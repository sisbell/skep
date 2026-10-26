//! EDITLINK's read-assembled successor (§4).
//!
//! It is the one request whose slots M10 builds itself, from content V-specs
//! resolved through M5 off a snapshot pinned *before* the write transaction,
//! or from content I-spans taken verbatim (W6 (a)). Recorded I-addresses are
//! permanent, so the source document's arrangement may move underneath with
//! no hazard, and the operation is still one M2 transaction.
//!
//! The whole successor is assembled here — all three slots, in the order the
//! client is promised, each held as it is built to M7's two per-slot budgets
//! ([`successor_link`]): the spans a slot keeps, [`MAX_SLOT_SPANS`], and the
//! run-list steps its resolution walks, [`MAX_SLOT_RESOLVE_STEPS`]. Building
//! the slots here rather than in M7 is what makes both M10's to charge for
//! this one request — M7's `editlink` receives a built `Link`, by which time
//! the walk has been paid — and charging them means stopping as the spans are
//! produced and before each walk is taken. Whether M10 also *answers* a
//! budget is the write door's to say: where the door judged the write, a
//! slot is refused as it crosses either; where the door deferred to the
//! store's own gate, the verdict is M7's, after that gate — save the two name
//! forms' span counts, an address-form type slot's and an I-span slot's, the
//! request's own, which are answered here either way.

use skep_address::{subtree_of, Nat, Span, Tumbler};
use skep_arrangement::{as_ordinal_vspan, M5State, VSpec};
use skep_links::{
    enc, Endset, Link, SlotArg, FROM, MAX_SLOT_RESOLVE_STEPS, MAX_SLOT_SPANS, TO, TYPE,
};
use skep_namespace::M3State;

use crate::reject::{FaultSite, RejectCode, Rejection};
use crate::request::{OpKind, SuccessorSpec};

/// The write door's verdict on a write's sources, `consult_write`'s answer.
///
/// It says what may speak before the store does. Defined here, where it is
/// read, because the module order lets the door name this module and not the
/// reverse; the door fills it, as M7's `Visibility` is filled by M10. Public
/// with [`successor_link`], for the one caller outside this crate that
/// composes the successor the dispatch will deposit: a write that reaches
/// the daemon's entry-frame composer has passed registration and ownership
/// on both homes, so it is one the door judges, and the composer passes
/// [`Judgment::Judged`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Judgment {
    /// The door ran past the deferral and every rule it owns passed.
    ///
    /// The caller may read every source, so a verdict their arrangements
    /// decide may speak here.
    Judged,
    /// The door judged nothing.
    ///
    /// The op takes no consult, or the destination's own gate would refuse,
    /// so nothing built from a source may speak ahead of the store.
    Unjudged,
}

/// Assembles EDITLINK's successor link from the request's [`SuccessorSpec`].
///
/// `judgment` is the write door's answer (`consult_write`). Where it is
/// [`Judgment::Unjudged`] — the destination's own gate would refuse, so the
/// store speaks first — the sources went unconsulted, and the build issues no
/// verdict their arrangements decide: a resolved slot's two budgets, whose
/// crossing turns on what a source holds, are left to M7's `editlink`, a slot
/// over either being left one span past the span budget, which that call
/// refuses after its home gate (`successor_slot`). Every other refusal here
/// is the request's own or the registry's, and answers alike whatever a
/// source holds.
///
/// `from` and `to` are content-resolved or content I-spans. An
/// address-denoting successor endpoint is refused here —
/// `IllFormedSuccessor`, naming the slot — the narrowing [`SuccessorSpec`]
/// states, and the wire's parse admits no `addrs` object on either, so over
/// the wire the form never reaches this build. An I-span slot is taken
/// verbatim (`ispan_slot`): no source, no resolve, nothing read of the
/// document its spans name, its shape M7's content clause by index — the
/// same answer whatever `judgment` says and whatever that document holds,
/// which is the read check's premise for this op.
///
/// Public for one caller beside the dispatch: the daemon's composer of an
/// `edit_link`'s entry frame (signed ops), which composes the successor's
/// slot rows from the link this function builds over the same base, under
/// the daemon's serialization lock ahead of the transaction — so the signed
/// rows and the stored successor agree by construction, and a request this
/// function refuses is passed through to the dispatch's own refusal of it.
///
/// # Errors
///
/// Refuses with `IllFormedSpec` for a spec whose span is not a content
/// V-span, `SourceNotRegistered` for a spec whose source the registry does
/// not know, `NotContentSubspace` for an I-span that is no content I-span,
/// `IllFormedSuccessor` for an address-form `from` or `to`, and
/// `SlotTooLarge` for a slot over a budget — a resolved slot only where the
/// door judged the write (above), the two name forms whatever it judged
/// (below).
///
/// **Precedence.** A successor may be wrong in several slots at once and
/// exactly one answer goes back, so the order decides it: the slots are built
/// `from`, then `to`, then `ty`, and the first that refuses is the only
/// refusal. Within a slot the first offending spec or span speaks (see
/// `successor_slot` and `ispan_slot`). Every refusal names its slot in
/// [`FaultSite`]'s `slot`, in M7's numbering ([`FROM`], [`TO`], [`TYPE`]) —
/// the numbering `Op::FollowLink`'s and `Op::Project`'s slot index is
/// already in — so the `index` beside it is read against a slot the client
/// can identify.
///
/// `TYPE` is the successor's one three-form slot (§4): address-denoting,
/// content-resolved or content I-spans, with M7 owning the slot-shape and
/// schema verdict inside `editlink`. Every form is held to
/// [`MAX_SLOT_SPANS`] where the slot is built — the `Resolve` form as
/// `successor_slot` says, the `Spans` form as `ispan_slot` says, and the
/// `Addrs` form here, whatever `judgment` says, and *before* the encoding
/// is: its count is the request's own, so refusing it discloses nothing, and
/// [`enc`] turns each name into a subtree span of two tumblers as deep as
/// the name — ~26–40× the bytes the name arrived in, ~16–20 KB a span at the
/// 256 components skepd's codec admits a tumbler — memory M7 would then
/// refuse anyway.
pub fn successor_link(
    m3: &M3State,
    m5: &M5State,
    successor: &SuccessorSpec,
    judgment: Judgment,
) -> Result<Link, Rejection> {
    let from = successor_end(m3, m5, FROM, &successor.from, judgment)?;
    let to = successor_end(m3, m5, TO, &successor.to, judgment)?;
    let ty = match &successor.ty {
        SlotArg::Addrs(addrs) => {
            if addrs.len() > MAX_SLOT_SPANS {
                return Err(slot_too_large(TYPE));
            }
            enc(addrs)
        }
        SlotArg::Resolve(specs) => successor_slot(m3, m5, TYPE, specs, judgment)?,
        SlotArg::Spans(spans) => ispan_slot(TYPE, spans)?,
    };
    Ok(Link::triple(from, to, ty))
}

/// Assembles one successor end, `from` or `to`, in the form it was given.
///
/// The `Resolve` form is `successor_slot`'s; the `Spans` form `ispan_slot`'s;
/// the address form is the narrowing [`SuccessorSpec`] states, refused
/// `IllFormedSuccessor` naming the slot — the code M7 answers a successor of
/// the wrong shape, since the shape is the request's own and no source
/// decides it.
fn successor_end(
    m3: &M3State,
    m5: &M5State,
    slot: usize,
    end: &SlotArg,
    judgment: Judgment,
) -> Result<Endset, Rejection> {
    match end {
        SlotArg::Resolve(specs) => successor_slot(m3, m5, slot, specs, judgment),
        SlotArg::Spans(spans) => ispan_slot(slot, spans),
        SlotArg::Addrs(_) => Err(Rejection::classified(
            OpKind::EditLink,
            RejectCode::IllFormedSuccessor,
            Some(FaultSite { slot: Some(slot), ..FaultSite::default() }),
        )),
    }
}

/// Assembles one successor slot from its content I-spans, verbatim.
///
/// The I-span form (W6 (a)) names its spans as the address form names its
/// addresses: no source, so nothing is resolved, consulted or read — not the
/// registration, the arrangement or a byte of the document the spans name —
/// and nothing here turns on `judgment`. Two checks, both arithmetic on the
/// request: each span is a content I-span by M7's one spelling of the shape
/// ([`SlotArg::ill_formed_span`], the content clause — a content-subspace
/// element start and an ordinal width of at least one), the first offending
/// span answering `NotContentSubspace` at its index, the code the read by
/// identity gives the same fault; and the slot is held to [`MAX_SLOT_SPANS`]
/// spans, `SlotTooLarge` naming the slot, the count being the request's own.
/// Then the spans are the slot: `Endset::from_spans` stores what it is given,
/// which is what M7's `Spans` slot deposits on a `make_link`, so an edit's
/// re-made end and a fresh link's end are one shape.
fn ispan_slot(slot: usize, spans: &[Span]) -> Result<Endset, Rejection> {
    if let Some(index) = SlotArg::ill_formed_span(spans) {
        return Err(at_spec(slot, index, RejectCode::NotContentSubspace));
    }
    if spans.len() > MAX_SLOT_SPANS {
        return Err(slot_too_large(slot));
    }
    Ok(Endset::from_spans(spans.iter().cloned()))
}

/// Assembles one successor slot from its content V-specs.
///
/// M5's resolution — `iter_resolve`, pulled a run at a time below, yielding
/// exactly `resolve`'s runs — is total, and answers ⟨⟩ four ways: a span
/// whose shape is not depth-2 ordinal-level; a document with no entry in M5's
/// arrangement map; a subspace outside {s_C, s_L}; and a well-formed spec
/// whose ordinal range holds nothing. A ⟨⟩ deposited into a slot is
/// indistinguishable from a slot the caller meant to leave empty, so the two
/// faults a client can act on are typed here, ahead of `resolve` — the first
/// two errors below.
///
/// The other two ⟨⟩ sources survive the guard and are deposited as an empty
/// slot: M5 arranges a document lazily, so a freshly created one is
/// registered and unarranged at once, and an in-range-looking ordinal may
/// simply hold nothing. That is deliberate — MAKELINK's `SlotArg::Resolve`
/// slots build from the same run list and deposit the same empty endset, and
/// an EDITLINK successor stricter than the MAKELINK it supersedes would be a
/// different operation.
///
/// The slot's spans are bounded at [`MAX_SLOT_SPANS`] — M7's per-slot budget,
/// named rather than respelled — and the count is taken *as the spans are
/// produced*, so an over-budget slot stops accumulating instead of being
/// built and then measured. A spec's expansion is not the request's size but
/// the source document's fragmentation (one run per contiguous I-segment), so
/// a short list of specs over a fragmented document names spans without
/// bound, and each is two tumblers as deep as the I-address it covers — order
/// half a kilobyte live at eight components, ~16–20 KB at the 256 components
/// skepd's codec admits, which M5's daughter chains let a registered member
/// reach. M7's `editlink` holds the finished slots to the same number, but
/// inside its transaction; counting here is what keeps the build's own peak
/// to one slot's worth of spans instead of every spec's, each spec's runs
/// being pulled one at a time off M5's lazy `iter_resolve` so the cap ends a
/// spec's walk where the slot crosses it — as M7 builds MAKELINK's `Resolve`
/// slots.
///
/// The slot's work is bounded at [`MAX_SLOT_RESOLVE_STEPS`] — M7's budget for
/// those same `Resolve` slots, named rather than respelled — because the span
/// count cannot bound it. A spec's walk to its opening ordinal passes every
/// run of its source that ends before it, whatever the spec keeps: all of them
/// for a span opening past the arranged end, which keeps nothing, so a slot of
/// such specs is empty to the span budget while its steps are the sources'
/// fragmentation times the caller's list length. Each walk is charged
/// *before* it is taken, at its source's whole run count — M5's
/// `content_run_count`, the walk's ceiling, read in one lookup without
/// walking — so the charge errs in the safe direction and a refusal precedes
/// the work it refuses. Where the build runs is why it is bounded: ahead of
/// the write's transaction, so outside M2's applier lock, but inside any
/// serialization a transport holds around `execute` — skepd holds its write
/// lock there — which every other writer waits through. What a spec costs
/// once the slot is over either budget is its two guards, a shape test and a
/// registry lookup, so the list length multiplies nothing a source decides.
///
/// Past the guard and under the budgets the tail is infallible:
/// `Run::iextent` is total (every `Run` has `width ≥ 1` and an element-level
/// `i_start`). An empty from/to is structurally fine; M7 gates the type slot.
///
/// # Errors
///
/// * `IllFormedSpec` — the span is not a content V-span ([`is_content_vspan`]
///   covers the shape and subspace cases together). Permanent: the request
///   itself is what is wrong.
/// * `SourceNotRegistered` — M3 does not know the source. This is M10's own
///   precondition, not a restatement of anything `resolve` checks: `resolve`
///   reads M5's arrangement map and never M3's registry. It is here
///   because it is the fault with a remedy — `Reorder`, telling a client that
///   arrived ahead of its own CREATENEWDOCUMENT to try again.
///
/// That precondition is read off the snapshot pinned before the write, which
/// is a different base from the one `editlink` commits against, and it holds
/// anyway because M3's registry only grows: every `M3Rec` variant is an
/// insert (a frontier advance, a node, a principal), so nothing a concurrent
/// transaction can commit unregisters a document. A source registered at
/// snapshot time is still registered at commit; one that becomes registered
/// inside the window is refused `SourceNotRegistered`/`Reorder`, which is
/// exactly the advice that race deserves. M7 cannot make the check itself —
/// `editlink` receives a built `Link`, by which point the source documents
/// are gone — so the check is M10's, and this is the right place for it.
///
/// **Who answers a budget.** It is `judgment`'s to say. Where the door judged
/// the write, the caller may read every source, so the third fault is typed
/// here: `SlotTooLarge` as the slot crosses either budget, which costs the
/// client nothing against M7's refusal of the same slot (the same code, the
/// same `Permanent` disposition — MAKELINK's `Resolve` slots answer both
/// budgets with it) and names the slot besides. Where the door deferred, a
/// refusal here would be decided by a source the caller was never shown — its
/// fragmentation, through either budget — ahead of the store's `not_owner`:
/// two private drafts differing in arrangement alone would draw two answers.
/// So an unjudged slot over either budget is left one span past the span
/// budget, which M7 refuses after its home gate: by the run that crosses the
/// span budget, or, crossing the work budget, by a constant fill
/// ([`unjudged_fill`]). The fill is never read — M7 counts a slot's spans
/// before any verdict reads one — so its size is pure cost, and it is the
/// smallest span there is whatever the crossing source. The store's gate
/// therefore speaks first; and where that gate passes after all — the window
/// between the snapshot this build reads and the write's commit — the slot is
/// refused for the budget it crossed rather than deposited short of what the
/// client asked, while a slot under both budgets is deposited there as built,
/// from sources the door never consulted (`consult_write`'s staleness). Past
/// the crossing the walk resolves no further spec while still judging each
/// one's shape and registration. Those faults are the request's own and the
/// registry's, so they must speak alike wherever an unconsulted source crossed
/// a budget ahead of them; a walk that ended at the crossing would let a later
/// spec's fault speak or not by where that happened.
///
/// **Precedence within the slot.** Several specs may be wrong and exactly one
/// answer goes back, so the order decides it: the specs are walked in order
/// and the first offending one speaks, with `IllFormedSpec` ahead of
/// `SourceNotRegistered` on that spec. `SlotTooLarge`, raised only where the
/// door judged the write, can arise only after every spec reached so far has
/// passed both, a spec's work being charged after its guards and before its
/// walk. Every refusal names the slot it is about in `site.slot`; the two
/// per-spec refusals also localize the offender in `site.index`, while
/// `SlotTooLarge` leaves `index` empty, being the slot's fault rather than one
/// spec's.
fn successor_slot(
    m3: &M3State,
    m5: &M5State,
    slot: usize,
    specs: &[VSpec],
    judgment: Judgment,
) -> Result<Endset, Rejection> {
    let mut spans = Vec::new();
    let mut steps: usize = 0;
    for (index, spec) in specs.iter().enumerate() {
        if !is_content_vspan(&spec.span) {
            return Err(at_spec(slot, index, RejectCode::IllFormedSpec));
        }
        if !m3.is_registered_document(&spec.source) {
            return Err(at_spec(slot, index, RejectCode::SourceNotRegistered));
        }
        // Past a budget only an unjudged build is still walking, and it
        // resolves nothing more.
        if spans.len() > MAX_SLOT_SPANS {
            continue;
        }
        // The work charge, ahead of the work: the walk's ceiling, read without
        // walking.
        steps = steps.saturating_add(m5.content_run_count(&spec.source));
        if steps > MAX_SLOT_RESOLVE_STEPS {
            match judgment {
                Judgment::Judged => return Err(slot_too_large(slot)),
                // One span past the span budget, in the constant fill M7 never
                // reads: it refuses the slot after its home gate, counting
                // before it reads.
                Judgment::Unjudged => {
                    spans.resize(MAX_SLOT_SPANS + 1, unjudged_fill());
                    continue;
                }
            }
        }
        for run in m5.iter_resolve(&spec.source, &spec.span) {
            if spans.len() == MAX_SLOT_SPANS {
                match judgment {
                    Judgment::Judged => return Err(slot_too_large(slot)),
                    // One span past the budget: M7 refuses it after its home
                    // gate.
                    Judgment::Unjudged => {
                        spans.push(run.iextent());
                        break;
                    }
                }
            }
            spans.push(run.iextent());
        }
    }
    Ok(Endset::from_spans(spans))
}

/// Returns the refusal for one offending spec, localized in two site fields.
///
/// They are the slot it was building, in M7's numbering, and the spec's
/// position within that slot — the same `site.index` M6 threads for a
/// malformed span in a multi-spec request, so a client reads one field for
/// both.
fn at_spec(slot: usize, index: usize, code: RejectCode) -> Rejection {
    Rejection::classified(
        OpKind::EditLink,
        code,
        Some(FaultSite { slot: Some(slot), index: Some(index), ..FaultSite::default() }),
    )
}

/// Returns the slot's own refusal, `SlotTooLarge`.
///
/// The slot is named, and `index` is left empty, since no one spec is at
/// fault.
fn slot_too_large(slot: usize) -> Rejection {
    Rejection::classified(
        OpKind::EditLink,
        RejectCode::SlotTooLarge,
        Some(FaultSite { slot: Some(slot), ..FaultSite::default() }),
    )
}

/// Returns the span an unjudged slot over the work budget is padded with.
///
/// It pads the slot to one past the span budget, and it is the smallest span
/// there is — one component in each tumbler, the subtree of `[1]` — whatever
/// the crossing source. M7 counts a slot's spans before any verdict reads
/// one, so the fill is never read and its size is pure cost, paid once for
/// every span it pads. It takes no argument because no address in hand
/// bounds a span's depth: M5 mints a daughter chain one component per shot,
/// as deep as a transport's codec lets a base be named, so a span derived
/// from the crossing source would be as deep as that.
///
/// # Panics
///
/// Panics if `Tumbler::new` refuses `[1]`, which it cannot: it refuses only
/// the empty sequence.
fn unjudged_fill() -> Span {
    // `Tumbler::new` refuses only the empty sequence.
    subtree_of(&Tumbler::new([Nat::from(1u32)]).expect("[1] is nonempty"))
}

/// Returns whether `span` passes the content-V well-formedness predicate.
///
/// That predicate is the span half of the one makelink applies to its own
/// `Resolve` specs, whose other half is the source's registration: a depth-2
/// V-position in the content subspace with an ordinal displacement —
/// `#start = 2 ∧ start₁ = s_C ∧ #width = 2 ∧ width₁ = 0`.
///
/// The shape is M5's one reading of it, `as_ordinal_vspan`, asked with its
/// content clause — the same question M7's own spec gate asks — so the
/// predicate has one spelling, M5's, and this successor cannot admit a span
/// the MAKELINK it supersedes would refuse. The reading is total, so a span
/// of any shape answers rather than faulting, which is what `execute`'s
/// Total contract needs.
fn is_content_vspan(span: &Span) -> bool {
    as_ordinal_vspan(span).is_some_and(|v| v.is_content())
}

// These run over genesis M3 and M5 state, with no kernel. The two that walk a
// real fragmented draft are in `operation/tests.rs`; the budgets as a client
// meets them, through the surface, are in `tests/it/successor.rs` and
// `tests/it/write_door.rs`.
#[cfg(test)]
mod tests {
    use skep_address::{validate, Address, Nat, Tumbler};

    use super::*;

    fn tum(comps: &[u32]) -> Tumbler {
        Tumbler::new(comps.iter().map(|&c| Nat::from(c))).expect("nonempty")
    }
    fn addr(comps: &[u32]) -> Address {
        validate(tum(comps)).unwrap_or_else(|_| panic!("T4-valid test address"))
    }
    fn span(start: &[u32], width: &[u32]) -> Span {
        Span::new(tum(start), tum(width)).unwrap_or_else(|_| panic!("well-formed test span"))
    }

    /// §4: the content-V guard answers for a span of any shape.
    ///
    /// The guard is depth-2, content-subspace (s_C), ordinal-level, and it
    /// answers deeper and shallower spans too.
    #[test]
    fn only_a_depth_two_ordinal_level_content_span_passes_the_guard() {
        assert!(is_content_vspan(&span(&[1, 1], &[0, 2])));
        assert!(!is_content_vspan(&span(&[2, 1], &[0, 1]))); // link subspace
        assert!(!is_content_vspan(&span(&[1, 1], &[1, 0]))); // not ordinal-level
        assert!(!is_content_vspan(&span(&[5], &[1]))); // shallower than depth 2
        assert!(!is_content_vspan(&span(&[1, 1, 1], &[0, 0, 1])));
    }

    /// §4: the two faults this guard owns are typed and told apart.
    ///
    /// An ill-formed span is Permanent, an unregistered source is Reorder,
    /// and neither reaches `resolve`, whose ⟨⟩ would otherwise be deposited
    /// as an empty slot. Each localizes the offending spec in `site.index`,
    /// and names the slot that index is read against. Neither turns on what a
    /// source holds, so each answers alike whether or not the door judged the
    /// write.
    #[test]
    fn the_two_faults_this_guard_owns_are_typed_before_resolve() {
        let m3 = M3State::genesis();
        let m5 = M5State::genesis();
        let doc = addr(&[1, 0, 1, 0, 1]);
        let ill_formed = || VSpec { source: doc.clone(), span: span(&[2, 1], &[0, 1]) };
        // Well formed, and genesis M3 has registered no document: the spec
        // would resolve to ⟨⟩, so it is refused instead.
        let unregistered = || VSpec { source: doc.clone(), span: span(&[1, 1], &[0, 1]) };

        for judgment in [Judgment::Judged, Judgment::Unjudged] {
            let rej = successor_slot(&m3, &m5, FROM, &[ill_formed()], judgment)
                .expect_err("link-subspace span");
            assert_eq!(rej.op, OpKind::EditLink);
            assert_eq!(rej.code, RejectCode::IllFormedSpec, "{judgment:?}");
            let site = rej.site.expect("localized");
            assert_eq!(site.slot, Some(FROM));
            assert_eq!(site.index, Some(0));

            let rej = successor_slot(&m3, &m5, TO, &[unregistered()], judgment)
                .expect_err("unregistered source");
            assert_eq!(rej.code, RejectCode::SourceNotRegistered, "{judgment:?}");
            assert_eq!(rej.disposition, crate::reject::Disposition::Reorder);
            let site = rej.site.expect("localized");
            assert_eq!(site.slot, Some(TO));
            assert_eq!(site.index, Some(0));

            // No specs is not a fault: an empty slot the caller asked for.
            let empty = successor_slot(&m3, &m5, FROM, &[], judgment).expect("empty is fine");
            assert!(empty.is_empty());
        }
    }

    /// §4: within a slot the first offending spec speaks, and names itself.
    ///
    /// `IllFormedSpec` speaks ahead of `SourceNotRegistered` on that spec —
    /// so a slot wrong in two places gets one answer, and the answer says
    /// which spec it is about.
    #[test]
    fn the_first_offending_spec_speaks_and_names_itself() {
        let m3 = M3State::genesis();
        let m5 = M5State::genesis();
        let doc = addr(&[1, 0, 1, 0, 1]);
        let ill_formed = || VSpec { source: doc.clone(), span: span(&[2, 1], &[0, 1]) };
        let unregistered = || VSpec { source: doc.clone(), span: span(&[1, 1], &[0, 1]) };

        // Both faults on one spec: the span is judged first.
        let rej = successor_slot(&m3, &m5, FROM, &[ill_formed()], Judgment::Judged)
            .expect_err("both faults");
        assert_eq!(rej.code, RejectCode::IllFormedSpec, "the span is judged before the source");

        // Two offending specs, the later one ill-formed: the earlier speaks,
        // and its index is what comes back.
        let rej = successor_slot(&m3, &m5, FROM, &[unregistered(), ill_formed()], Judgment::Judged)
            .expect_err("two offenders");
        assert_eq!(rej.code, RejectCode::SourceNotRegistered, "the first offender speaks");
        assert_eq!(rej.site.expect("localized").index, Some(0));
    }

    /// §4: the request-level precedence past its first position.
    ///
    /// It covers the type slot's other form too. `to` is built before `ty`,
    /// so a successor offending in both is answered about `to`; and a
    /// `Resolve`-form `ty` names `TYPE` — the one slot label no other
    /// per-spec refusal here reaches. A mislabeled slot sends a client to
    /// edit a field it sent correctly, on the engine's own word.
    #[test]
    fn the_to_slot_speaks_before_the_type_slot_and_each_names_itself() {
        let m3 = M3State::genesis();
        let m5 = M5State::genesis();
        let doc = addr(&[1, 0, 1, 0, 1]);
        let unregistered = || VSpec { source: doc.clone(), span: span(&[1, 1], &[0, 1]) };
        let ill_formed = || VSpec { source: doc.clone(), span: span(&[2, 1], &[0, 1]) };

        // `TO` and `TYPE` both offend, with different faults, so the answer
        // says which slot it is about twice over — by code and by slot.
        let both = SuccessorSpec {
            from: vec![].into(),
            to: vec![unregistered()].into(),
            ty: SlotArg::Resolve(vec![ill_formed()]),
        };
        let rej =
            successor_link(&m3, &m5, &both, Judgment::Judged).expect_err("two offending slots");
        assert_eq!(rej.code, RejectCode::SourceNotRegistered, "TO is built before TYPE");
        assert_eq!(rej.site.expect("localized").slot, Some(TO));

        // `TYPE` alone, in its `Resolve` form.
        let ty_only = SuccessorSpec {
            from: vec![].into(),
            to: vec![].into(),
            ty: SlotArg::Resolve(vec![ill_formed()]),
        };
        let rej = successor_link(&m3, &m5, &ty_only, Judgment::Judged)
            .expect_err("the type slot offends");
        assert_eq!(rej.code, RejectCode::IllFormedSpec);
        let site = rej.site.expect("localized");
        assert_eq!(site.slot, Some(TYPE), "a Resolve-form type slot names TYPE, not its neighbour");
        assert_eq!(site.index, Some(0));
    }

    /// §4: the type slot's `Addrs` form meets the `Resolve` form's span budget.
    ///
    /// It is held to it *before* `enc` expands each name into a subtree span
    /// as deep as the name — whether or not the door judged the write, since
    /// the count is the request's own. The site names the slot and no index:
    /// the slot is at fault, not one address in it.
    #[test]
    fn an_over_budget_address_denoting_type_slot_is_refused_before_encoding() {
        let m3 = M3State::genesis();
        let m5 = M5State::genesis();
        let doc = addr(&[1, 0, 1, 0, 1]);
        let with_type = |names: usize| SuccessorSpec {
            from: vec![].into(),
            to: vec![].into(),
            ty: SlotArg::Addrs(vec![doc.clone(); names]),
        };

        for judgment in [Judgment::Judged, Judgment::Unjudged] {
            let rej = successor_link(&m3, &m5, &with_type(MAX_SLOT_SPANS + 1), judgment)
                .expect_err("one address past the budget");
            assert_eq!(rej.op, OpKind::EditLink);
            assert_eq!(rej.code, RejectCode::SlotTooLarge, "{judgment:?}");
            assert_eq!(rej.disposition, crate::reject::Disposition::Permanent);
            let site = rej.site.expect("the slot is named");
            assert_eq!(site.slot, Some(TYPE));
            assert!(site.index.is_none(), "the slot is at fault, not one address in it");

            // At the budget it is an ordinary slot, and the whole successor
            // assembles: empty from/to are structurally fine (M7 gates the
            // type).
            let link = successor_link(&m3, &m5, &with_type(MAX_SLOT_SPANS), judgment)
                .expect("a slot at the budget is accepted");
            assert_eq!(link.type_slot().len(), MAX_SLOT_SPANS);
            assert!(link.from_slot().is_empty() && link.to_slot().is_empty());
        }
    }
}
