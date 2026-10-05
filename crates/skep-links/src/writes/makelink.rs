//! MAKELINK (ASN-0120), the open surface, in both forms: [`SlotArg`], the
//! slot argument; [`slot_endset`], the endset a slot builds under both
//! per-slot budgets; `stage_record`, the record half both forms stage; and
//! [`LinkWriter::makelink`] and [`LinkWriter::makelink_replacing`] — the one
//! op family that seats, so the one block bounded by `HasM5`.

use skep_address::{Address, Span};
use skep_arrangement::{
    as_ordinal_vspan, stage_seat_link, Caller, HasM5, M5Rec, M5State, SeatError, VSpec,
};
use skep_kernel::{Seq, Staging, TxnError};
use skep_namespace::{M3Rec, M3State};

use super::{emit_core, home_gate, replaces_class, replaces_type, Gate, LinkWriter, Visibility};
use crate::budget::{MAX_SLOT_RESOLVE_STEPS, MAX_SLOT_SPANS};
use crate::class::coverage_class;
use crate::endset::{enc, Endset, Link};
use crate::error::MakeLinkError;
use crate::registry::{registry, ShippedType};
use crate::state::LinkRec;
use crate::LinkWorld;

/// One MAKELINK endset argument (the 2026-08-16 address-denoting-endsets
/// amendment; ASN-0043 L4/L8/L9/L13): content V-specs resolved against the
/// txn base — the original form, semantics unchanged — or address NAMES
/// recorded verbatim as [`enc`]`(addrs)`, with no resolution, no occupancy
/// requirement, and nothing beyond the T4 validity `Address` already carries
/// (LM 4/44: type matching is by address, contents never examined; ghost
/// names are valid). Per-slot either/or — no mixing within a slot in v1 (a
/// mixed need resolves first via the read surface and passes `Addrs`). Also
/// M10's successor type slot: the one two-form enum serves both surfaces.
///
/// Equality is structural over the form and its list — the relation a caller
/// comparing two REQUESTS wants: the same slot, asked for in the same form,
/// naming the same things in the same order, which is the order both arms
/// deposit in. It is not a claim about the endset either would become: a
/// `Resolve` slot's is a function of the txn base as well as the argument, so
/// two equal `Resolve` slots deposit different endsets against different
/// bases. Coverage identity is [`coverage_class`], one level down and after
/// resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlotArg {
    /// Content V-specs, wf-checked and resolved to I-extents inside
    /// makelink's transact.
    Resolve(Vec<VSpec>),
    /// Address names, deposited verbatim as the canonical `enc` endset.
    Addrs(Vec<Address>),
}

impl SlotArg {
    /// The `Resolve` form's specs — the wf-check domain. `Addrs` names get
    /// no check beyond the T4 validity their type already carries
    /// (ReflexiveAddressing: any T4-valid name, occupied or ghost).
    fn specs(&self) -> &[VSpec] {
        match self {
            SlotArg::Resolve(specs) => specs,
            SlotArg::Addrs(_) => &[],
        }
    }
}

impl From<SeatError> for MakeLinkError {
    fn from(e: SeatError) -> Self {
        MakeLinkError::Seat(e)
    }
}

/// wf for one MAKELINK `Resolve` spec: a registered source, and a depth-2
/// content V-position with ordinal displacement — `#start = 2 ∧ start₁ = s_C
/// ∧ #width = 2 ∧ width₁ = 0`, the deliberate depth-2 narrowing of ASN-0120's
/// `#u_j ≥ 2` (Conflicts §12).
///
/// The span half is M5's one reading of the shape, `as_ordinal_vspan`, asked
/// with its content clause — so the narrowing has one spelling, M5's, and
/// this predicate adds only the registry half. A spec of any shape answers
/// rather than faulting, the reading being total.
fn is_wf_content_spec(m3: &M3State, spec: &VSpec) -> bool {
    m3.is_registered_document(&spec.source)
        && as_ordinal_vspan(&spec.span).is_some_and(|v| v.is_content())
}

/// One MAKELINK slot's endset, read off the txn base — `None` iff the slot
/// is over either per-slot budget: more than [`MAX_SLOT_SPANS`] spans in
/// whichever form built it, or, for a `Resolve` slot, specs commanding more
/// than [`MAX_SLOT_RESOLVE_STEPS`] run-list steps.
///
/// `Resolve`: ρ as content I-extents — readable, level-uniform spans (ML1
/// coverage-exactness by construction: the runs trace exactly allocated
/// content, cross-origin runs arrive un-coalesced). Both budgets are charged
/// as the slot is built, and each stops it: the spans as they are kept,
/// pulled a run at a time off M5's lazy `iter_resolve` so the span budget
/// ends the walk itself, and the work BEFORE each resolve, so a refusal
/// precedes the walk it refuses rather than following it. The two are
/// independent because a spec that keeps nothing still walks its whole source
/// (see [`MAX_SLOT_RESOLVE_STEPS`]); the span count alone would see such a
/// slot as empty.
///
/// `Addrs`: the canonical name encoding, deposited unresolved, one span per
/// name, counted before the encoding is built and commanding no walk.
///
/// PUBLIC for one caller beside [`LinkWriter::makelink`]: the daemon's
/// composer of a MAKELINK's entry frame (signed ops), which composes each
/// slot's row from THE ENDSET THIS TRANSACTION WILL DEPOSIT — the same
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
                // The WORK charge, ahead of the work. `content_run_count` is
                // M5's O(1) accessor, published for a caller that owns
                // admission control over one of these walks (COPY prices
                // `MAX_PLACED_RUNS` against it), and the content subspace is
                // the right list to ask: `is_wf_content_spec` ran over every
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
    }
}

/// THE RECORD HALF of MAKELINK, inside a transaction the caller opened: the
/// home gate, the specs' well-formedness, the three slots' endsets under
/// their budgets, the three sole-writer fences, the deposit under the Open
/// gate and its seat — everything [`LinkWriter::makelink`] states — answering
/// the record's address. ONE body, which both MAKELINK forms stage:
/// [`LinkWriter::makelink`] alone, [`LinkWriter::makelink_replacing`]
/// followed by the record's `replaces` link.
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
        let endset_of = |arg| slot_endset(base.m5(), arg).ok_or(MakeLinkError::SlotTooLarge);
        (endset_of(from)?, endset_of(to)?, endset_of(ty)?)
    };
    // The sole-writer fences. Total: a `Resolve` slot is level-uniform by
    // M5's construction and an `Addrs` slot is address-denoting, which are
    // the same two grounds under which the fold classifies this very value
    // one step later. `⟨⟩` classifies as the empty denoted antichain, which
    // is none of the three classes, so ML6 stays the deposit gate's check
    // and no input can satisfy both.
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
    /// MAKELINK (ASN-0120, as amended 2026-08-16): build three endsets — a
    /// [`SlotArg::Resolve`] slot resolves its V-specs to content I-extents
    /// (M5 `iter_resolve` + `Run::iextent`, read off the txn BASE — the whole op
    /// linearizes at its commit, ASN-0134); a [`SlotArg::Addrs`] slot is
    /// `enc(addrs)`, the NAMES verbatim (L8: matching is by address,
    /// contents never examined; ghost names valid, L9) — require the type
    /// endset non-empty AS GIVEN (ML6, so an empty `Addrs` list and an empty
    /// `Resolve` resolution are one rejection; the check belongs to the
    /// deposit gate every link passes, and its verdict arrives here as
    /// `EmptyTypeResolution`), mint a fresh home-scoped link, deposit the
    /// standard triple, then seat it in
    /// `home`'s link subspace (K.μ⁺_L, no R — J-LV). ONE M2 composite under
    /// `link_lock_key(home)` (the held lock and the advanced frontier are
    /// byte-identical — M3's contract). NO shape gate, NO idem dedup
    /// (distinct links always — ML0), NO provenance.
    ///
    /// Every `Resolve` spec is wf-checked — a registered source, and a depth-2
    /// content V-position with ordinal displacement — before any slot is
    /// built; `Addrs` names get no wf step, T4 validity being the whole
    /// precondition and already carried by the `Address` type. EVERY slot,
    /// in either form, is bounded at [`MAX_SLOT_SPANS`] spans
    /// (`SlotTooLarge`): a spec's expansion is the source document's
    /// fragmentation rather than the request's size, and a name's span costs
    /// order half a kilobyte live against ~19 wire bytes, so neither form's
    /// live cost is bounded by the request body that carried it. Every
    /// `Resolve` slot is additionally bounded at [`MAX_SLOT_RESOLVE_STEPS`]
    /// run-list steps (`SlotTooLarge` again): the resolution's WORK is not
    /// its result, a spec aimed past its source's arranged end keeping no
    /// span and walking all of it — and every step runs inside this
    /// transact, under the applier lock the whole engine writes through.
    ///
    /// The three SOLE-WRITER fences apply here as the first two do on the
    /// managed surface: a resolved type slot in the `[R]` class
    /// (`RetractionClass`), the `[K_sup]` class (`SupersessionClass`) or the
    /// `replaces` class (`ReplacesClass`, [`is_replaces_class`](crate::is_replaces_class))
    /// is refused.
    /// They are the open surface's whole type discipline, and they are not
    /// optional — [`crate::LinkState::apply_link`]'s hint fold recognizes a
    /// deposit by its type slot's coverage class alone, so an `[R]`-classed
    /// link deposited through this surface would tombstone every address its
    /// TO slot denotes, and a `[K_sup]`-classed one would enter the
    /// supersession adjacency as a claim, both without any of the ownership,
    /// residence or schema checks `nullify`, `assert_sup` and `editlink`
    /// establish; and a `replaces`-classed one, landing at a record's next
    /// address, would name a state for a record whose signed bytes named
    /// none — the grant fold reads a record's `replaces` there
    /// ([`LinkWriter::makelink_replacing`] is that class's one writer).
    ///
    /// RETURNS `(link, seq)`: the address of the deposited link, which is
    /// also the one seated in `home`'s link subspace.
    pub fn makelink(
        &self,
        caller: Caller,
        home: &Address,
        from: SlotArg,
        to: SlotArg,
        ty: SlotArg,
    ) -> Result<(Address, Seq), TxnError<MakeLinkError>> {
        // No dedup section: the open surface takes no dedup CHECK either
        // (ML0 — distinct links always), so `deposit_lock_set`'s question does
        // not arise and the home's alloc key is the whole set. The seam's one
        // line: the attested arm, which is `transact` where this writer
        // carries no attestation (signed ops).
        self.kernel.transact_attested(&[M3State::link_lock_key(home)], self.attest, |stg| {
            stage_record(stg, self.visibility, caller, home, &from, &to, &ty)
        })
    }

    /// MAKELINK WITH ITS `replaces` MEMBER (PUB-5.15 (iii), (iv); RES-308,
    /// RES-309, RES-310; the authority link type investigation §3 (A′)): ONE
    /// transaction deposits the RECORD exactly as [`LinkWriter::makelink`]
    /// does — its slots, its three fences, its seat — and then its `replaces`
    /// LINK, `(enc([record]), enc([replaces]), enc([replaces_type()]))`:
    /// `from` the record, filled from the address this transaction minted
    /// the way `editlink` fills its claim's `new`; `to` the state the record
    /// replaces — at the grant, the revocation a re-share follows; typed the
    /// class. Both deposits take the Open gate — no dedup, so both are
    /// minted — and BOTH are seated, the record and then its link, so a
    /// home that re-shares often keeps one run in its link subspace. Under
    /// ONE attestation: the
    /// commit marker this writer's attestation fills covers both, the entry
    /// frame having signed the body WITH the member (`skep_identity`'s
    /// `entry_body_make_link_replacing`).
    ///
    /// Where the pair lands is the grant fold's whole read of it: the two
    /// mints are consecutive in ONE home under ONE lock, so the link sits at
    /// the record's own NEXT link address, and the fold reads a record's
    /// `replaces` there and nowhere else — a `replaces` link homed elsewhere,
    /// or deposited by any other act, names nothing to it. The fences keep
    /// every other act off the class ([`is_replaces_class`](crate::is_replaces_class)), so
    /// this is the
    /// one way such a link comes to sit there.
    ///
    /// Nothing about `replaces` is checked here: whether it names the key's
    /// current state is the FOLD's question and a fact of resolution, never
    /// of the write (PUB-5.15: "the second deposit lands and is
    /// acknowledged, and the fold decides") — a stale or foreign name is
    /// deposited, and the record it rides is honored for nothing.
    ///
    /// RETURNS `(record, seq)`: the RECORD's address, which is the ack's
    /// (M10 answers `ack_addr` with it); the link's is the record's next,
    /// reachable by `read_link`.
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
            // into that home pays for the runs (lane A's measurement:
            // 5.7 ms a commit at 1,000 re-shares, flat at 0.2 ms seated).
            let seat = stage_seat_link(stg.working().m5(), home, &link)?;
            stg.push(seat.into());
            Ok(record)
        })
    }
}
