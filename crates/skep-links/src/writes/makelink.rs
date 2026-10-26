//! MAKELINK (ASN-0120), the open surface, in its three slot forms.
//!
//! [`SlotArg`] is the slot argument; [`slot_endset`] the endset a slot builds
//! under both per-slot budgets; `stage_record` the record half both MAKELINK
//! forms stage; and [`LinkWriter::makelink`] and
//! [`LinkWriter::makelink_replacing`] the two forms — the one op family that
//! seats, so the one block bounded by `HasM5`.

use skep_address::{content_subspace, validate, Address, Span};
use skep_arrangement::{
    as_ordinal_vspan, stage_seat_link, Caller, HasM5, M5Rec, M5State, Run, SeatError, VSpec,
};
use skep_kernel::{Seq, Staging, TxnError};
use skep_namespace::{M3Rec, M3State};

use super::{emit_core, home_gate, replaces_class, replaces_type, Gate, LinkWriter, Visibility};
use crate::budget::{MAX_SLOT_RESOLVE_STEPS, MAX_SLOT_SPANS};
use crate::class::coverage_class;
use crate::endset::{enc, Endset, Link};
use crate::error::MakeLinkError;
use crate::registry::{registry, ShippedType};
use crate::state::{LinkRec, FROM, TO, TYPE};
use crate::LinkWorld;

/// One MAKELINK endset argument (ASN-0043 L4/L8/L9/L13).
///
/// It is content V-specs resolved against the txn base; address names
/// recorded verbatim as [`enc`]`(addrs)`, with no resolution, no occupancy
/// requirement, and nothing beyond the T4 validity `Address` already carries
/// (LM 4/44: type matching is by address, contents never examined; ghost
/// names are valid); or content I-spans recorded verbatim (W6 (a)), the
/// third form, which names its spans as the address form names its
/// addresses — no source, so nothing is consulted, resolved or required
/// registered or occupied — and is held to one shape by request arithmetic
/// alone ([`SlotArg::ill_formed_span`]). Per-slot one form — no mixing
/// within a slot in v1 (a mixed need resolves first via the read surface
/// and passes `Addrs` or `Spans`). Also M10's successor slots: the one
/// three-form enum serves both surfaces, the successor's `from` and `to`
/// taking the first and the third form.
///
/// Equality is structural over the form and its list — the relation a caller
/// comparing two requests wants: the same slot, asked for in the same form,
/// naming the same things in the same order, which is the order every arm
/// deposits in. It is not a claim about the endset either would become: a
/// `Resolve` slot's is a function of the txn base as well as the argument, so
/// two equal `Resolve` slots deposit different endsets against different
/// bases. Coverage identity is [`coverage_class`], one level down and after
/// resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlotArg {
    /// Content V-specs, resolved to I-extents inside makelink's transact.
    ///
    /// Each is wf-checked first.
    Resolve(Vec<VSpec>),
    /// Address names, deposited verbatim as the canonical `enc` endset.
    Addrs(Vec<Address>),
    /// Content I-spans, deposited verbatim (W6 (a); the wire's
    /// `{"spans": […]}`).
    ///
    /// Each span is one the read by identity names and a `Run`'s `iextent`
    /// is: its start a CONTENT-subspace element position, its width the
    /// ordinal displacement `0…0.n` with `n ≥ 1` — so level-uniform, and the
    /// shape a `Resolve` slot stores — checked by [`SlotArg::ill_formed_span`]
    /// on the request's own bytes. Nothing of the spans' document is read:
    /// not its registration, not its arrangement, not a byte — a ghost
    /// position past a frontier, or of a document no one minted, is a valid
    /// name here exactly as it is in the address form, which is what lets a
    /// writer name positions it cannot read without being told anything of
    /// them (the read check, `skepd`'s `ispan_slot` suite).
    Spans(Vec<Span>),
}

impl SlotArg {
    /// Returns the `Resolve` form's specs — the wf-check domain, and the
    /// sources a reader of the slot consults.
    ///
    /// `Addrs` names get no check beyond the T4 validity their type already
    /// carries (ReflexiveAddressing: any T4-valid name, occupied or ghost),
    /// and `Spans` names none beyond their shape; both answer the empty
    /// slice. Public for M10, whose door consults a slot's sources and whose
    /// entry-frame composer asks their readability, and which reads them off
    /// the one form that has any.
    pub fn specs(&self) -> &[VSpec] {
        match self {
            SlotArg::Resolve(specs) => specs,
            SlotArg::Addrs(_) | SlotArg::Spans(_) => &[],
        }
    }

    /// Returns the index of the first span that is no content I-span, if any.
    ///
    /// The I-span form's one shape — THE CONTENT CLAUSE (the wire-lane
    /// decision 5) — decided on the span's own bytes and no world read: a
    /// span is admitted iff it is the extent of a content run, M5's
    /// [`Run::new`] admitting its start (a T4-valid element position
    /// `doc·0·subspace·ordinal`) with its width's last component as the
    /// run's width (so `n ≥ 1`) and that run's `iextent` being the span
    /// itself (so the width is `0…0.n` at the start's own length, and the
    /// span level-uniform), and the start's subspace is the content
    /// subspace. The clause is what keeps the form off every address a
    /// classifier reads: a subspace-3 type address — a credential type's, a
    /// registry kind's, the `replaces` class — has a unit span of the same
    /// two-tumbler shape, and a slot spelling one here would reach the plain
    /// path and the fold as a deposit the credential and registry sequences
    /// never judged, since both classify the address form alone. The five
    /// reserved ghost tumblers are content positions and pass the clause;
    /// the two with a sole writer are caught by the fences below exactly as
    /// their address form is.
    ///
    /// Public for M10's successor build, which admits the form on an
    /// `edit_link`'s `from` and `to` through this same test — one spelling,
    /// so the two ops cannot drift. Answers the first offending span's
    /// index, the `site.index` its refusal names.
    pub fn ill_formed_span(spans: &[Span]) -> Option<usize> {
        spans.iter().position(|span| !is_content_ispan(span))
    }
}

/// The V-spec form, for a caller that holds specs alone.
///
/// The successor's `from` and `to` were V-specs by type before the I-span
/// form joined them (M10's `SuccessorSpec`); a caller building one from its
/// specs still writes the list and converts.
impl From<Vec<VSpec>> for SlotArg {
    fn from(specs: Vec<VSpec>) -> SlotArg {
        SlotArg::Resolve(specs)
    }
}

/// Returns whether `span` is a content I-span — [`SlotArg::ill_formed_span`]'s
/// per-span test.
///
/// `Run::new`'s admission plus the content clause, then the extent equality
/// that pins the width's shape; every step is arithmetic on the span.
fn is_content_ispan(span: &Span) -> bool {
    let Ok(start) = validate(span.start().clone()) else { return false };
    if start.subspace() != Some(&content_subspace()) {
        return false;
    }
    // The width's last component, `Tumbler::get` being 1-based.
    let width = span.width();
    let Some(count) = width.get(width.len()) else { return false };
    Run::new(start, count.clone()).is_ok_and(|run| run.iextent() == *span)
}

impl From<SeatError> for MakeLinkError {
    fn from(e: SeatError) -> Self {
        MakeLinkError::Seat(e)
    }
}

/// Returns whether one MAKELINK `Resolve` spec is well-formed (wf).
///
/// wf is a registered source, and a depth-2 content V-position with ordinal
/// displacement — `#start = 2 ∧ start₁ = s_C ∧ #width = 2 ∧ width₁ = 0`, the
/// deliberate depth-2 narrowing of ASN-0120's `#u_j ≥ 2` (Conflicts §12).
///
/// The span half is M5's one reading of the shape, `as_ordinal_vspan`, asked
/// with its content clause — so the narrowing has one spelling, M5's, and
/// this predicate adds only the registry half. A spec of any shape answers
/// rather than faulting, the reading being total.
fn is_wf_content_spec(m3: &M3State, spec: &VSpec) -> bool {
    m3.is_registered_document(&spec.source)
        && as_ordinal_vspan(&spec.span).is_some_and(|v| v.is_content())
}

/// Builds one MAKELINK slot's endset, read off the txn base.
///
/// It is `None` iff the slot is over either per-slot budget: more than
/// [`MAX_SLOT_SPANS`] spans in whichever form built it, or, for a `Resolve`
/// slot, specs commanding more than [`MAX_SLOT_RESOLVE_STEPS`] run-list
/// steps.
///
/// `Resolve`: ρ as content I-extents — readable, level-uniform spans (ML1
/// coverage-exactness by construction: the runs trace exactly allocated
/// content, cross-origin runs arrive un-coalesced). Both budgets are charged
/// as the slot is built, and each stops it: the spans as they are kept,
/// pulled a run at a time off M5's lazy `iter_resolve` so the span budget
/// ends the walk itself, and the work before each resolve, so a refusal
/// precedes the walk it refuses rather than following it. The two are
/// independent because a spec that keeps nothing still walks its whole source
/// (see [`MAX_SLOT_RESOLVE_STEPS`]); the span count alone would see such a
/// slot as empty.
///
/// `Addrs`: the canonical name encoding, deposited unresolved, one span per
/// name, counted before the encoding is built and commanding no walk.
///
/// `Spans`: the spans as given, counted and copied, reading no state at all
/// — the one path of the three that touches neither `m5` nor any document,
/// which is the read check's first premise (the content clause is
/// `stage_record`'s, ahead of this).
///
/// Public for one caller beside [`LinkWriter::makelink`]: the daemon's
/// composer of a MAKELINK's entry frame (signed ops), which composes each
/// slot's row from *the endset this transaction will deposit* — the same
/// function over the same base, under the daemon's serialization lock ahead
/// of the transaction — so the signed row and the stored endset agree by
/// construction, and charges the same two budgets there, passing a slot
/// over either through to this crate's own refusal of it (`SlotTooLarge`).
/// It reads the base and stages nothing: a caller that resolves through it
/// off a snapshot the transaction will not open on composes the base's
/// endset, not the transaction's.
pub fn slot_endset(m5: &M5State, arg: &SlotArg) -> Option<Endset> {
    match arg {
        SlotArg::Resolve(specs) => {
            let mut spans: Vec<Span> = Vec::new();
            let mut steps: usize = 0;
            for spec in specs {
                // The work charge, ahead of the work. `content_run_count` is
                // M5's one-map-lookup accessor, reading no run, published for
                // a caller that owns admission control over one of these
                // walks (COPY prices `MAX_COPY_RESOLVE_STEPS` against it), and
                // the content subspace is the right list to ask: on
                // makelink's own path, `is_wf_content_spec` ran over every
                // slot's specs before the first endset was built.
                steps = steps.saturating_add(m5.content_run_count(&spec.source));
                if steps > MAX_SLOT_RESOLVE_STEPS {
                    return None;
                }
                for run in m5.iter_resolve(&spec.source, &spec.span) {
                    if spans.len() == MAX_SLOT_SPANS {
                        return None;
                    }
                    spans.push(run.iextent());
                }
            }
            Some(Endset::from_spans(spans))
        }
        SlotArg::Addrs(addrs) => (addrs.len() <= MAX_SLOT_SPANS).then(|| enc(addrs)),
        SlotArg::Spans(spans) => {
            (spans.len() <= MAX_SLOT_SPANS).then(|| Endset::from_spans(spans.iter().cloned()))
        }
    }
}

/// Stages the record half of MAKELINK, in a transaction the caller opened.
///
/// That half is the home gate, the specs' well-formedness, the I-spans'
/// shape, the three slots' endsets under their budgets, the three
/// sole-writer fences, the deposit under the Open gate and its seat —
/// everything [`LinkWriter::makelink`] states — answering the record's
/// address. One body, which both MAKELINK forms stage:
/// [`LinkWriter::makelink`] alone, [`LinkWriter::makelink_replacing`]
/// followed by the record's `replaces` link.
///
/// # Errors
///
/// In the order its steps run: `HomeNotRegistered`, then `NotOwner`, for
/// `home`, asked of the base; `IllFormedSpec` for a spec of any slot;
/// `NotContentSpan` for the first I-span of any slot that is no content
/// I-span, slots in declared order; `SlotTooLarge` for the first slot over a
/// budget; `RetractionClass`, `SupersessionClass` or `ReplacesClass` for the
/// resolved type slot's class; `EmptyTypeResolution` from the Open gate on
/// an empty type slot; `Mint` where the mint fails; and `Seat` where the
/// seat step refuses.
fn stage_record<W>(
    stg: &mut Staging<W>,
    visibility: &Visibility<'_, W>,
    caller: Caller,
    home: &Address,
    from: &SlotArg,
    to: &SlotArg,
    ty: &SlotArg,
) -> Result<Address, MakeLinkError>
where
    W: LinkWorld + HasM5,
    W::Record: From<LinkRec> + From<M3Rec> + From<M5Rec>,
{
    let r_class = registry().shipped_class(ShippedType::Retraction);
    let sup_class = registry().shipped_class(ShippedType::Supersedes);
    let (e1, e2, e3) = {
        let base = stg.base();
        // P0 then ω on home, hoisted so both win over every spec/type
        // verdict.
        home_gate(base.m3(), caller, &[home])?;
        let mut specs = from.specs().iter().chain(to.specs()).chain(ty.specs());
        if !specs.all(|spec| is_wf_content_spec(base.m3(), spec)) {
            return Err(MakeLinkError::IllFormedSpec);
        }
        // The I-span form's shape — the content clause — by slot and index,
        // on the request's own bytes: the one check the form takes, and no
        // read of the spans' document stands beside it (the address form's
        // rule, which the read check holds this form to).
        for (slot, arg) in [(FROM, from), (TO, to), (TYPE, ty)] {
            if let SlotArg::Spans(spans) = arg {
                if let Some(index) = SlotArg::ill_formed_span(spans) {
                    return Err(MakeLinkError::NotContentSpan { slot, index });
                }
            }
        }
        let endset_of = |arg| slot_endset(base.m5(), arg).ok_or(MakeLinkError::SlotTooLarge);
        (endset_of(from)?, endset_of(to)?, endset_of(ty)?)
    };
    // The sole-writer fences. Total: a `Resolve` slot is level-uniform by
    // M5's construction, a `Spans` slot by the shape check above, and an
    // `Addrs` slot is address-denoting, which are the same grounds under
    // which the fold classifies this very value one step later. `⟨⟩`
    // classifies as the empty denoted antichain, which is none of the three
    // classes, so ML6 stays the deposit gate's check and no input can
    // satisfy both. A content extent wider than one position classes as an
    // extent, never as any of the three; a width-1 content I-span at a
    // reserved ghost tumbler IS that tumbler's unit span and classes as its
    // class, so the two fenced ghosts are refused here in this form as in
    // the address form.
    let e3_class = coverage_class(&e3);
    if e3_class == *r_class {
        return Err(MakeLinkError::RetractionClass); // K ≁ R
    }
    if e3_class == *sup_class {
        return Err(MakeLinkError::SupersessionClass); // Conflicts §10
    }
    if e3_class == *replaces_class() {
        return Err(MakeLinkError::ReplacesClass); // PUB-5.15, RES-309
    }
    let value = Link::triple(e1, e2, e3);
    // `minted`, because the seat below names this address: the Open gate
    // runs no dedup, so it cannot be an incumbent.
    let addr = emit_core(stg, visibility, caller, home, value, Gate::Open)?.minted();
    let seat = stage_seat_link(stg.working().m5(), home, &addr)?;
    stg.push(seat.into());
    Ok(addr)
}

impl<'k, W> LinkWriter<'k, W>
where
    W: LinkWorld + HasM5,
    W::Record: From<LinkRec> + From<M3Rec> + From<M5Rec>,
{
    /// MAKELINK (ASN-0120): deposits and seats a link built from three slots.
    ///
    /// It builds three endsets — a [`SlotArg::Resolve`] slot resolves its
    /// V-specs to content I-extents (M5 `iter_resolve` + `Run::iextent`, read
    /// off the txn base — the whole op linearizes at its commit, ASN-0134); a
    /// [`SlotArg::Addrs`] slot is `enc(addrs)`, the names verbatim (L8:
    /// matching is by address, contents never examined; ghost names valid,
    /// L9); a [`SlotArg::Spans`] slot is its content I-spans verbatim, each
    /// held to the content clause and nothing read of its document (W6 (a))
    /// — requires the type endset non-empty as given, mints a fresh
    /// home-scoped link, deposits the standard triple, then seats it in
    /// `home`'s link subspace (K.μ⁺_L, no R — J-LV). One M2 composite under
    /// `link_lock_key(home)` (the held lock and the advanced frontier are
    /// byte-identical — M3's contract). No shape gate, no idem dedup
    /// (distinct links always — ML0), no provenance.
    ///
    /// The three sole-writer fences listed under Errors below are the open
    /// surface's whole type discipline, and they are not optional —
    /// [`crate::LinkState::apply_link`]'s hint fold recognizes a deposit by
    /// its type slot's coverage class alone, so an `[R]`-classed link
    /// deposited through this surface would tombstone every address its `TO`
    /// slot denotes, and a `[K_sup]`-classed one would enter the supersession
    /// adjacency as a claim, both without any of the ownership, residence or
    /// schema checks `nullify`, `assert_sup` and `editlink` establish; and a
    /// `replaces`-classed one, landing at a record's next address, would name
    /// a state for a record whose signed bytes named none — the grant fold
    /// reads a record's `replaces` there ([`LinkWriter::makelink_replacing`]
    /// is that class's one writer).
    ///
    /// Returns `(link, seq)`: the address of the deposited link, which is
    /// also the one seated in `home`'s link subspace.
    ///
    /// # Errors
    ///
    /// Each refusal comes as `TxnError::Rejected`, in the order the steps
    /// run. `home` unregistered (`HomeNotRegistered`), then not the caller's
    /// (`NotOwner`), asked of the txn base. Every `Resolve` spec is
    /// wf-checked — a registered source, and a depth-2 content V-position with
    /// ordinal displacement — before any slot is built (`IllFormedSpec`);
    /// `Addrs` names get no wf step, T4 validity being the whole precondition
    /// and already carried by the `Address` type; every `Spans` span is held
    /// to the content clause, slots in declared order and the first
    /// offending span named (`NotContentSpan`). Every slot is then held, as
    /// [`slot_endset`] builds it, to [`MAX_SLOT_SPANS`] spans in any form
    /// and, for a `Resolve` slot, to [`MAX_SLOT_RESOLVE_STEPS`] run-list
    /// steps — both refused `SlotTooLarge`, both charged inside this
    /// transact, under the applier lock the whole engine writes through. The
    /// two constants say why the request that carried a slot bounds neither.
    /// The three sole-writer fences apply here as they do on the managed
    /// surface: a resolved type slot in the `[R]` class
    /// (`RetractionClass`), the `[K_sup]` class (`SupersessionClass`) or the
    /// `replaces` class (`ReplacesClass`,
    /// [`is_replaces_class`](crate::is_replaces_class)) is refused. An empty
    /// type endset is refused as given (ML6, so an empty `Addrs` list and an
    /// empty `Resolve` resolution are one rejection; the check belongs to the
    /// deposit gate every link passes, and its verdict arrives here as
    /// `EmptyTypeResolution`). Last come `Mint`, where the mint fails, and
    /// `Seat`, where the seat step refuses. The kernel's own failures —
    /// `Durability`, `Unencodable`, `OverBudget`, `Poisoned` — come back as
    /// `transact` returns them.
    pub fn makelink(
        &self,
        caller: Caller,
        home: &Address,
        from: SlotArg,
        to: SlotArg,
        ty: SlotArg,
    ) -> Result<(Address, Seq), TxnError<MakeLinkError>> {
        // No dedup section: the open surface takes no dedup check either
        // (ML0 — distinct links always), so `deposit_lock_set`'s question does
        // not arise and the home's alloc key is the whole set. The seam's one
        // line: the attested arm, which is `transact` where this writer
        // carries no attestation (signed ops).
        self.kernel.transact_attested(&[M3State::link_lock_key(home)], self.attest, |stg| {
            stage_record(stg, self.visibility, caller, home, &from, &to, &ty)
        })
    }

    /// MAKELINK with its `replaces` member: deposits a record and its link.
    ///
    /// One transaction (PUB-5.15 (iii), (iv); RES-308, RES-309, RES-310; the
    /// authority link type investigation §3 (A′)) deposits the record exactly
    /// as [`LinkWriter::makelink`] does — its slots, its three fences, its
    /// seat — and then its `replaces` link,
    /// `(enc([record]), enc([replaces]), enc([replaces_type()]))`: `from` the
    /// record, filled from the address this transaction minted the way
    /// `editlink` fills its claim's `new`; `to` the state the record replaces
    /// — at the grant, the revocation a re-share follows; typed the class.
    /// Both deposits take the Open gate — no dedup, so both are minted — and
    /// both are seated, the record and then its link, so a home that
    /// re-shares often keeps one run in its link subspace. Under one
    /// attestation: the commit marker this writer's attestation fills covers
    /// both, the entry frame having signed the body with the member
    /// (`skep_identity`'s `entry_body_make_link_replacing`).
    ///
    /// Where the pair lands is the grant fold's whole read of it: the two
    /// mints are consecutive in one home under one lock, so the link sits at
    /// the record's own next link address, and the fold reads a record's
    /// `replaces` there and nowhere else — a `replaces` link homed elsewhere,
    /// or deposited by any other act, names nothing to it. The fences keep
    /// every other act off the class
    /// ([`is_replaces_class`](crate::is_replaces_class)), so this is the one
    /// way such a link comes to sit there.
    ///
    /// Nothing about `replaces` is checked here: whether it names the key's
    /// current state is the fold's question and a fact of resolution, never
    /// of the write (PUB-5.15: "the second deposit lands and is
    /// acknowledged, and the fold decides") — a stale or foreign name is
    /// deposited, and the record it rides is honored for nothing.
    ///
    /// Returns `(record, seq)`: the record's address, which is the ack's
    /// (M10 answers `ack_addr` with it); the link's is the record's next,
    /// reachable by `read_link`.
    ///
    /// # Errors
    ///
    /// Each refusal comes as `TxnError::Rejected`: the record's are
    /// [`LinkWriter::makelink`]'s, in its order, and the `replaces` link adds
    /// its own `Mint` and `Seat`. The kernel's own failures — `Durability`,
    /// `Unencodable`, `OverBudget`, `Poisoned` — come back as `transact`
    /// returns them.
    pub fn makelink_replacing(
        &self,
        caller: Caller,
        home: &Address,
        from: SlotArg,
        to: SlotArg,
        ty: SlotArg,
        replaces: &Address,
    ) -> Result<(Address, Seq), TxnError<MakeLinkError>> {
        self.kernel.transact_attested(&[M3State::link_lock_key(home)], self.attest, |stg| {
            let record = stage_record(stg, self.visibility, caller, home, &from, &to, &ty)?;
            let pair = Link::triple(enc([&record]), enc([replaces]), enc([replaces_type()]));
            // `minted`: the Open gate runs no dedup, and the address this
            // mint takes is the record's next — the one the fold reads.
            let link = emit_core(stg, self.visibility, caller, home, pair, Gate::Open)?.minted();
            // Seated like the record: an unseated link leaves the home's
            // link subspace one run per re-share, and every later link write
            // into that home pays for the runs (as measured: 5.7 ms a commit
            // at 1,000 re-shares, flat at 0.2 ms seated).
            let seat = stage_seat_link(stg.working().m5(), home, &link)?;
            stg.push(seat.into());
            Ok(record)
        })
    }
}
