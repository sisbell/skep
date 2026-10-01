//! EDITLINK's read-assembled successor (§4): the one request whose slots M10
//! builds itself, from content V-specs resolved through M5 off a snapshot
//! pinned BEFORE the write transaction. Recorded I-addresses are permanent,
//! so the source document's arrangement may move underneath with no hazard,
//! and the operation is still one M2 transaction.
//!
//! The whole successor is assembled here — all three slots, in the order the
//! client is promised, each held as it is built to M7's two per-slot budgets
//! ([`successor_link`]): the spans a slot keeps, [`MAX_SLOT_SPANS`], and the
//! run-list steps its resolution walks, [`MAX_SLOT_RESOLVE_STEPS`]. Building
//! the slots here rather than in M7 is what makes both M10's to charge for
//! this one request — M7's `editlink` receives a built `Link`, by which time
//! the walk has been paid — and charging them means stopping as the spans are
//! produced and before each walk is taken. Whether M10 also ANSWERS a budget
//! is the write door's to say: where the door judged the write, a slot is
//! refused as it crosses either; where the door deferred to the store's own
//! gate, the verdict is M7's, after that gate.

use skep_address::{subtree_of, Span};
use skep_arrangement::{as_ordinal_vspan, M5State, VSpec};
use skep_links::{
    enc, Endset, Link, SlotArg, FROM, MAX_SLOT_RESOLVE_STEPS, MAX_SLOT_SPANS, TO, TYPE,
};
use skep_namespace::M3State;

use crate::op::{OpKind, SuccessorSpec};
use crate::reject::{FaultSite, RejectCode, Rejection};

/// Assemble EDITLINK's successor link from the request's [`SuccessorSpec`].
///
/// `judged` is the write door's answer (`consult_write`): whether it judged
/// this write's sources. Where it did not — the destination's own gate would
/// refuse, so the store speaks first — the sources went unconsulted, and the
/// build issues no verdict their arrangements decide: a resolved slot's two
/// budgets, whose crossing turns on what a source holds, are left to M7's
/// `editlink`, a slot over either being left one span past the span budget,
/// which that call refuses after its home gate ([`successor_slot`]). Every
/// other refusal here is the request's own or the registry's, and answers
/// alike whatever a source holds.
///
/// PRECEDENCE, since a successor may be wrong in several slots at once and
/// exactly one answer goes back: the slots are built `from`, then `to`, then
/// `ty`, and the first that refuses is the only refusal. Within a slot the
/// first offending spec speaks (see [`successor_slot`]). Every refusal
/// names its slot in [`FaultSite`]'s `slot`, in M7's numbering ([`FROM`],
/// [`TO`], [`TYPE`]) — the numbering `Op::FollowLink`'s and `Op::Project`'s
/// slot index is already in — so the `index` beside it is read against a slot
/// the client can identify.
///
/// TYPE is the successor's one two-form slot (§4): address-denoting or
/// content-resolved, with M7 owning the slot-shape and schema verdict inside
/// `editlink`. Both forms are held to [`MAX_SLOT_SPANS`] where the slot is
/// built — the `Resolve` form as [`successor_slot`] says, and the `Addrs`
/// form HERE, whatever `judged` says, and BEFORE the encoding is: its count
/// is the request's own, so refusing it discloses nothing, and [`enc`] turns
/// each ~19-byte name into a subtree span of two multi-component tumblers, a
/// ~26× amplification into memory M7 would then refuse anyway.
///
/// `from` and `to` are content-resolved only. An address-denoting successor
/// endpoint is not constructible through this surface — [`SuccessorSpec`]'s
/// types say so — so there is no form here for M7 to reject.
pub(crate) fn successor_link(
    m3: &M3State,
    m5: &M5State,
    successor: &SuccessorSpec,
    judged: bool,
) -> Result<Link, Rejection> {
    let from = successor_slot(m3, m5, FROM, &successor.from, judged)?;
    let to = successor_slot(m3, m5, TO, &successor.to, judged)?;
    let ty = match &successor.ty {
        SlotArg::Addrs(a) => {
            if a.len() > MAX_SLOT_SPANS {
                return Err(slot_too_large(TYPE));
            }
            enc(a)
        }
        SlotArg::Resolve(v) => successor_slot(m3, m5, TYPE, v, judged)?,
    };
    Ok(Link::triple(from, to, ty))
}

/// Assemble one successor slot from its content V-specs.
///
/// M5's resolution — `iter_resolve`, pulled a run at a time below, yielding
/// exactly `resolve`'s runs — is total, and answers ⟨⟩ four ways: a span
/// whose shape is not depth-2 ordinal-level; a document with no entry in M5's
/// arrangement map; a subspace outside {s_C, s_L}; and a well-formed spec
/// whose ordinal range holds nothing. A ⟨⟩ deposited into a slot is
/// indistinguishable from a slot the caller meant to leave empty, so the two
/// faults a client can act on are typed here, ahead of `resolve`:
///
/// * `IllFormedSpec` — the span is not a content V-span ([`is_content_vspan`]
///   covers the shape and subspace cases together). Permanent: the request
///   itself is what is wrong.
/// * `SourceNotRegistered` — M3 does not know the source. This is M10's own
///   precondition, not a restatement of anything `resolve` checks: `resolve`
///   consults M5's arrangement map and never M3's registry. It is here
///   because it is the fault with a remedy — `Reorder`, telling a client that
///   arrived ahead of its own CREATENEWDOCUMENT to try again.
///
/// That precondition is read off the snapshot pinned before the write, which
/// is a different base from the one `editlink` commits against, and it holds
/// anyway because M3's registry only GROWS: every `M3Rec` variant is an
/// insert (a frontier advance, a node, a principal), so nothing a concurrent
/// transaction can commit unregisters a document. A source registered at
/// snapshot time is still registered at commit; one that becomes registered
/// inside the window is refused `SourceNotRegistered`/`Reorder`, which is
/// exactly the advice that race deserves. M7 cannot make the check itself —
/// `editlink` receives a built `Link`, by which point the source documents
/// are gone — so this is the door, and it is the right one.
///
/// The other two ⟨⟩ sources survive the guard and are deposited as an empty
/// slot: M5 arranges a document lazily, so a freshly created one is
/// registered and unarranged at once, and an in-range-looking ordinal may
/// simply hold nothing. That is deliberate — MAKELINK's `SlotArg::Resolve`
/// slots build from the same run list and deposit the same empty endset, and
/// an EDITLINK successor stricter than the MAKELINK it supersedes would be a
/// different operation.
///
/// The slot's SPANS are bounded at [`MAX_SLOT_SPANS`] — M7's per-slot budget,
/// named rather than respelled — and the count is taken AS THE SPANS ARE
/// PRODUCED, so an over-budget slot stops accumulating instead of being built
/// and then measured. A spec's expansion is not the request's size but the
/// SOURCE document's fragmentation (one run per contiguous I-segment), so a
/// short list of specs over a fragmented document names spans without bound,
/// and each is two multi-component tumblers — order half a kilobyte live.
/// M7's `editlink` holds the finished slots to the same number, but inside
/// its transaction; counting here is what keeps the build's own peak to one
/// slot's worth of spans instead of every spec's, each spec's runs being
/// pulled one at a time off M5's lazy `iter_resolve` so the cap ends a spec's
/// walk where the slot crosses it — as M7 builds MAKELINK's `Resolve` slots.
///
/// The slot's WORK is bounded at [`MAX_SLOT_RESOLVE_STEPS`] — M7's budget for
/// those same `Resolve` slots, named rather than respelled — because the span
/// count cannot bound it. A spec's walk to its opening ordinal passes every
/// run of its source that ends before it, whatever the spec keeps: all of them
/// for a span opening past the arranged end, which keeps nothing, so a slot of
/// such specs is empty to the span budget while its steps are the sources'
/// fragmentation times the caller's list length. Each walk is charged BEFORE
/// it is taken, at its source's whole run count — M5's `content_run_count`,
/// the walk's ceiling, read in one lookup without walking — so the charge errs
/// in the safe direction and a refusal precedes the work it refuses. Where the
/// build runs is why it is bounded: ahead of the write's transaction, so
/// outside M2's applier lock, but inside any serialization a transport holds
/// around `execute` — skepd holds its write lock there — which every other
/// writer waits through. What a spec costs once the slot is over either budget
/// is its two guards, a shape test and a registry lookup, so the list length
/// multiplies nothing a source decides.
///
/// WHO ANSWERS A BUDGET is `judged`'s to say. Where the door judged the
/// write, the caller may read every source, so the third fault is typed here:
/// `SlotTooLarge` as the slot crosses either budget, which costs the client
/// nothing against M7's refusal of the same slot (the same code, the same
/// `Permanent` disposition — MAKELINK's `Resolve` slots answer both budgets
/// with it) and names the slot besides. Where the door deferred, a refusal
/// here would be decided by a source the caller was never shown — its
/// fragmentation, through either budget — ahead of the store's `not_owner`:
/// two private drafts differing in arrangement alone would draw two answers.
/// So an unjudged slot over either budget is left ONE span past the span
/// budget, which M7 refuses after its home gate: by the run that crosses the
/// span budget, or, crossing the work budget, by a fill of the crossing
/// source's subtree span. The fill is never read — M7 counts a slot's spans
/// before any verdict reads one — and is sized by an address the registry
/// minted rather than by the request. The store's gate therefore speaks first;
/// and where that gate passes after all — the window between the snapshot this
/// build reads and the write's commit — the slot is refused for the budget it
/// crossed rather than deposited short of what the client asked. Past the
/// crossing the walk resolves no further spec while still judging each one's
/// shape and registration. Those faults are the request's own and the
/// registry's, so they must speak alike wherever an unconsulted source crossed
/// a budget ahead of them; a walk that ended at the crossing would let a later
/// spec's fault speak or not by where that happened.
///
/// PRECEDENCE within the slot, since several specs may be wrong and exactly
/// one answer goes back: the specs are walked in order and the FIRST offending
/// one speaks, with `IllFormedSpec` ahead of `SourceNotRegistered` on that
/// spec. `SlotTooLarge`, raised only where the door judged the write, can
/// arise only after every spec reached so far has passed both, a spec's work
/// being charged after its guards and before its walk. Every refusal names the
/// slot it is about in `site.slot`; the two per-spec refusals also localize
/// the offender in `site.index`, while `SlotTooLarge` leaves `index` empty,
/// being the slot's fault rather than one spec's.
///
/// Past the guard and under the budgets the tail is infallible:
/// `Run::iextent` is total (every `Run` has `width ≥ 1` and an element-level
/// `i_start`). An empty from/to is structurally fine; M7 gates the type slot.
fn successor_slot(
    m3: &M3State,
    m5: &M5State,
    slot: usize,
    specs: &[VSpec],
    judged: bool,
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
        // The WORK charge, ahead of the work: the walk's ceiling, read without
        // walking.
        steps = steps.saturating_add(m5.content_run_count(&spec.source));
        if steps > MAX_SLOT_RESOLVE_STEPS {
            if judged {
                return Err(slot_too_large(slot));
            }
            // One span past the span budget, which M7 refuses after its home
            // gate, counting before it reads.
            spans.resize(MAX_SLOT_SPANS + 1, subtree_of(spec.source.tumbler()));
            continue;
        }
        for run in m5.iter_resolve(&spec.source, &spec.span) {
            if spans.len() == MAX_SLOT_SPANS {
                if judged {
                    return Err(slot_too_large(slot));
                }
                // One span past the budget: M7 refuses it after its home gate.
                spans.push(run.iextent());
                break;
            }
            spans.push(run.iextent());
        }
    }
    Ok(Endset::from_spans(spans))
}

/// The refusal for one offending spec, localized in two fields of the site —
/// the slot it was building, in M7's numbering, and the spec's position
/// within that slot, the same `site.index` M6 threads for a malformed span in
/// a multi-spec request, so a client reads one field for both.
fn at_spec(slot: usize, index: usize, code: RejectCode) -> Rejection {
    Rejection::classified(
        OpKind::EditLink,
        code,
        Some(FaultSite { slot: Some(slot), index: Some(index), ..FaultSite::default() }),
    )
}

/// The slot's own refusal — the slot is named, and `index` is left empty,
/// since no one spec is at fault.
fn slot_too_large(slot: usize) -> Rejection {
    Rejection::classified(
        OpKind::EditLink,
        RejectCode::SlotTooLarge,
        Some(FaultSite { slot: Some(slot), ..FaultSite::default() }),
    )
}

/// The content-V well-formedness predicate makelink applies to its own
/// `Resolve` specs: a depth-2 V-position in the content subspace with an
/// ordinal displacement — `#start = 2 ∧ start₁ = s_C ∧ #width = 2 ∧
/// width₁ = 0`.
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

    /// §4: the content-V guard — depth-2, content-subspace (s_C), ordinal-
    /// level — answering for a span of any shape, deeper and shallower
    /// included.
    #[test]
    fn only_a_depth_two_ordinal_level_content_span_passes_the_guard() {
        assert!(is_content_vspan(&span(&[1, 1], &[0, 2])));
        assert!(!is_content_vspan(&span(&[2, 1], &[0, 1]))); // link subspace
        assert!(!is_content_vspan(&span(&[1, 1], &[1, 0]))); // not ordinal-level
        assert!(!is_content_vspan(&span(&[5], &[1]))); // shallower than depth 2
        assert!(!is_content_vspan(&span(&[1, 1, 1], &[0, 0, 1])));
    }

    /// §4: the two faults this guard owns are typed and told apart — an
    /// ill-formed span is Permanent, an unregistered source is Reorder — and
    /// neither reaches `resolve`, whose ⟨⟩ would otherwise be deposited as an
    /// empty slot. Each localizes the offending spec in `site.index`, and
    /// names the slot that index is read against. Neither turns on what a
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

        for judged in [true, false] {
            let rej = successor_slot(&m3, &m5, FROM, &[ill_formed()], judged)
                .expect_err("link-subspace span");
            assert_eq!(rej.op, OpKind::EditLink);
            assert_eq!(rej.code, RejectCode::IllFormedSpec, "judged: {judged}");
            let site = rej.site.expect("localized");
            assert_eq!(site.slot, Some(FROM));
            assert_eq!(site.index, Some(0));

            let rej = successor_slot(&m3, &m5, TO, &[unregistered()], judged)
                .expect_err("unregistered source");
            assert_eq!(rej.code, RejectCode::SourceNotRegistered, "judged: {judged}");
            assert_eq!(rej.disposition, crate::reject::Disposition::Reorder);
            let site = rej.site.expect("localized");
            assert_eq!(site.slot, Some(TO));
            assert_eq!(site.index, Some(0));

            // No specs is not a fault: an empty slot the CALLER asked for.
            let empty = successor_slot(&m3, &m5, FROM, &[], judged).expect("empty is fine");
            assert!(empty.is_empty());
        }
    }

    /// §4: within a slot the FIRST offending spec speaks, and `IllFormedSpec`
    /// speaks ahead of `SourceNotRegistered` on that spec — so a slot wrong
    /// in two places gets one answer, and the answer says which spec it is
    /// about.
    #[test]
    fn the_first_offending_spec_speaks_and_names_itself() {
        let m3 = M3State::genesis();
        let m5 = M5State::genesis();
        let doc = addr(&[1, 0, 1, 0, 1]);
        let ill_formed = || VSpec { source: doc.clone(), span: span(&[2, 1], &[0, 1]) };
        let unregistered = || VSpec { source: doc.clone(), span: span(&[1, 1], &[0, 1]) };

        // Both faults on ONE spec: the span is judged first.
        let rej = successor_slot(&m3, &m5, FROM, &[ill_formed()], true).expect_err("both faults");
        assert_eq!(rej.code, RejectCode::IllFormedSpec, "the span is judged before the source");

        // Two offending specs, the later one ill-formed: the earlier speaks,
        // and its index is what comes back.
        let rej = successor_slot(&m3, &m5, FROM, &[unregistered(), ill_formed()], true)
            .expect_err("two offenders");
        assert_eq!(rej.code, RejectCode::SourceNotRegistered, "the first offender speaks");
        assert_eq!(rej.site.expect("localized").index, Some(0));
    }

    /// §4: the request-level precedence past its FIRST position, and the type
    /// slot's other form. `to` is built before `ty`, so a successor offending
    /// in both is answered about `to`; and a `Resolve`-form `ty` names TYPE —
    /// the one of the four slot labels no other case reaches. A mislabeled
    /// slot sends a client to edit a field it sent correctly, on the engine's
    /// own word.
    #[test]
    fn the_to_slot_speaks_before_the_type_slot_and_each_names_itself() {
        let m3 = M3State::genesis();
        let m5 = M5State::genesis();
        let doc = addr(&[1, 0, 1, 0, 1]);
        let unregistered = || VSpec { source: doc.clone(), span: span(&[1, 1], &[0, 1]) };
        let ill_formed = || VSpec { source: doc.clone(), span: span(&[2, 1], &[0, 1]) };

        // TO and TYPE both offend, with DIFFERENT faults, so the answer says
        // which slot it is about twice over — by code and by slot.
        let both = SuccessorSpec {
            from: vec![],
            to: vec![unregistered()],
            ty: SlotArg::Resolve(vec![ill_formed()]),
        };
        let rej = successor_link(&m3, &m5, &both, true).expect_err("two offending slots");
        assert_eq!(rej.code, RejectCode::SourceNotRegistered, "TO is built before TYPE");
        assert_eq!(rej.site.expect("localized").slot, Some(TO));

        // TYPE alone, in its `Resolve` form.
        let ty_only =
            SuccessorSpec { from: vec![], to: vec![], ty: SlotArg::Resolve(vec![ill_formed()]) };
        let rej = successor_link(&m3, &m5, &ty_only, true).expect_err("the type slot offends");
        assert_eq!(rej.code, RejectCode::IllFormedSpec);
        let site = rej.site.expect("localized");
        assert_eq!(site.slot, Some(TYPE), "a Resolve-form type slot names TYPE, not its neighbour");
        assert_eq!(site.index, Some(0));
    }

    /// §4: the type slot's `Addrs` form is held to the same budget its
    /// `Resolve` sibling is, and held to it BEFORE `enc` expands each ~19-byte
    /// name into a subtree span — whether or not the door judged the write,
    /// since the count is the request's own. The site names the slot and no
    /// index: the slot is at fault, not one address in it.
    #[test]
    fn an_over_budget_address_denoting_type_slot_is_refused_before_encoding() {
        let m3 = M3State::genesis();
        let m5 = M5State::genesis();
        let doc = addr(&[1, 0, 1, 0, 1]);
        let with_type = |names: usize| SuccessorSpec {
            from: vec![],
            to: vec![],
            ty: SlotArg::Addrs(vec![doc.clone(); names]),
        };

        for judged in [true, false] {
            let rej = successor_link(&m3, &m5, &with_type(MAX_SLOT_SPANS + 1), judged)
                .expect_err("one address past the budget");
            assert_eq!(rej.op, OpKind::EditLink);
            assert_eq!(rej.code, RejectCode::SlotTooLarge, "judged: {judged}");
            assert_eq!(rej.disposition, crate::reject::Disposition::Permanent);
            let site = rej.site.expect("the slot is named");
            assert_eq!(site.slot, Some(TYPE));
            assert!(site.index.is_none(), "the slot is at fault, not one address in it");

            // At the budget it is an ordinary slot, and the whole successor
            // assembles: empty from/to are structurally fine (M7 gates the type).
            let link = successor_link(&m3, &m5, &with_type(MAX_SLOT_SPANS), judged)
                .expect("a slot at the budget is accepted");
            assert_eq!(link.type_slot().len(), MAX_SLOT_SPANS);
            assert!(link.from_slot().is_empty() && link.to_slot().is_empty());
        }
    }
}
