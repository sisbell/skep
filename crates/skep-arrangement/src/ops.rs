//! §B / §3–§7 — the editing & versioning surface: `Vstream`, one M2
//! `transact` per operation, every mutation under an M3 lock key for the
//! touched document's allocation domain (§Serialization key).
//!
//! A REJECTION LEAVES NO STATE CHANGE, and that is M2's guarantee rather than
//! an ordering these ops keep: `transact` returns `TxnError::Rejected(E)`
//! straight out of the closure phase, discarding the staging, drawing no
//! `Seq` and appending nothing. Four of the five ops do reject before staging
//! anything; INSERT cannot, since its per-value mint and content write are
//! staged as they are made and either may reject on a later value.
//! M10 surfaces the rejection as a typed one and acknowledges only after
//! commit.
//!
//! Ownership: the four edit ops take a [`Caller`] and open with
//! [`gate_write`] — the in-txn ω gate — on the document whose arrangement
//! they write (COPY: destination only; VERSION is ungated, non-owner
//! versioning being denial-as-fork, O10).
//!
//! WHICH ERROR WINS when several conditions fail at once is stated on each op
//! below, and this is the only statement of it: the error types name verdicts,
//! not precedence, and the integration suite pins what is written here.
//!
//! Per-op trait bounds: each impl block names exactly the slices its ops
//! read and the records they stage, so a minimal test world can drive
//! `delete`/`rearrange` with `HasM5 + HasM3` and `From<M5Rec>` alone.

use std::fmt;

use num_traits::{One, Zero};
use skep_address::{Address, Nat};
use skep_content::{stage_write, ContentWrite, HasContent, Val};
use skep_kernel::{Kernel, Seq, TxnError, WorldState};
use skep_namespace::{HasM3, M3Rec, M3State, PrincipalId};

use crate::auth::{gate_write, Caller};
use crate::error::{CopyError, DeleteError, InsertError, RearrangeError, VersionError};
use crate::run::Run;
use crate::runlist::extend_or_push_run;
use crate::state::M5Rec;
use crate::vspace::{as_ordinal_vspan, VPos, VSpec};
use crate::HasM5;

/// The most runs one COPY may place, and so the ceiling on what one request
/// can make M5 hold live while it decides whether to place anything at all.
///
/// The budget: a `Run` journals as an element `Address` and a width, about a
/// hundred bytes as bincode writes them, so M2's `MAX_TXN_BYTES` (64 MiB)
/// admits on the order of half a million of them and no more — past that the
/// transaction cannot commit whatever M5 does, and the work of building it
/// is spent for a refusal. `2^16` sits an order inside that ceiling, which
/// keeps the LIVE heap one COPY commands to the same order as the
/// transaction budget M2 already prices rather than several times it. The
/// arithmetic is checked against the real encoding rather than restated here
/// (`the_placement_budget_stays_inside_the_transaction_budget`).
///
/// IT BINDS WHAT ONE COPY PLACES AND HOLDS LIVE, and that is the whole of
/// what it binds. A copy needing more runs than this is split by the caller,
/// exactly as an over-budget transaction already is. Because the accumulator
/// is filled from a LAZY resolution, the cap also stops the walk: an
/// over-budget spec is refused at the cap rather than resolved in full and
/// measured afterwards.
///
/// WHAT IT DOES NOT BIND is the WORK of resolving, which is a separate
/// quantity with a separate owner. Each spec costs a prefix-sum walk of its
/// source's run-list to reach the span — `Θ(#runs(source))` for a span near
/// the end, however narrow the answer — and a request multiplies that by its
/// spec count. Neither factor has a ceiling here: `#runs(source)` has none in
/// v1 (Open decision #1) and grows with editing, and a spec count is bounded
/// only by M10's wire list cap. So admission control and concurrency for a
/// route carrying COPY are the CALLER's, as they are for the reads that state
/// their own cost, and a route that carries this op owes that number.
pub const MAX_PLACED_RUNS: usize = 1 << 16;

/// M5's transact-driving op handle over M2 (§B): a thin borrow of the
/// engine's kernel. The pure reads live on [`M5State`](crate::M5State)
/// (reached through [`HasM5`]); this type owns only the five editing/
/// versioning operations M10 (and, for `insert`, M9) dispatches.
pub struct Vstream<'k, W: WorldState> {
    kernel: &'k Kernel<W>,
}

impl<'k, W: WorldState> Vstream<'k, W> {
    /// The only constructor — M10 (and M9, for predicate-def `insert`) build
    /// a Vstream over the engine's kernel this way.
    pub fn new(kernel: &'k Kernel<W>) -> Vstream<'k, W> {
        Vstream { kernel }
    }
}

/// The handle's name and nothing else — it holds one kernel borrow, and a
/// world is not a thing to print into a diagnostic. Written out rather than
/// derived: a derive would bound the impl on `W: Debug`, and a world composed
/// of persistent store slices need not be, so the derived impl would apply to
/// no `W` that exists.
impl<W: WorldState> fmt::Debug for Vstream<'_, W> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Vstream")
    }
}

impl<W> Vstream<'_, W>
where
    W: WorldState + HasM5 + HasM3 + HasContent, // reads M3 (registration, mints) + M4 (write) + M5
    W::Record: From<M5Rec> + From<M3Rec> + From<ContentWrite>, // stages M3Rec + ContentWrite + M5Rec
{
    /// INSERT (ASN-0116; §3): mint n fresh content addresses (M3), write
    /// their bytes (M4), splice the run at `at` (content subspace), record
    /// provenance — one M2 composite under
    /// `M3State::content_lock_key(doc)`. Returns the inserted run's START
    /// address (the predicate-def identity for M9) and the commit `Seq`.
    ///
    /// Check order (which error wins): `DocNotRegistered` → `NotOwner` (the
    /// in-txn ω gate) → `EmptyContent` → `NotContentSubspace`
    /// (`at.subspace ≠ s_C`) → `OutOfBounds` (the arrangement does not admit
    /// `at.ordinal` as a placement boundary — Valid(First)InsertionPosition,
    /// so ordinal = 1 when n_C = 0). Then, PER VALUE in the order given,
    /// `Mint` (the content mint) → `Content` (the byte write), with the FIRST
    /// value to fail deciding.
    ///
    /// Only one of those last two is a verdict an honest request can earn.
    /// `Mint(MintError::Gate)` is M3's defence against a corrupted frontier;
    /// `Mint(MintError::HomeNotRegistered)` cannot arrive past the gate above
    /// and is M3's own boundary discharge; and `Content(AlreadyPresent)`
    /// cannot occur in production at all — M3 mints fresh and M5 writes once,
    /// which is the argument `stage_write` itself makes for keeping the guard.
    ///
    /// COST, AND WHO OWNS IT. This op admits any `values` length: there is no
    /// analogue of COPY's [`MAX_PLACED_RUNS`](crate::MAX_PLACED_RUNS) here,
    /// and none is owed, because the size of an INSERT is the size of the
    /// request that carries it rather than a source document's fragmentation
    /// multiplied by a spec count. What `n` values cost is `2n + 1` staged
    /// records — a mint and a content write apiece, plus one placement — and
    /// `n` content addresses that are allocated permanently, M5 having no
    /// reclamation path. M2's `MAX_TXN_BYTES` refuses the transaction past its
    /// own ceiling, but it refuses AFTER the mints and writes are staged, so
    /// a caller that wants the refusal to arrive before that work owes its own
    /// cap: M10's codec sets one on the wire route (`MAX_INSERT_VALUES`), and
    /// a route that carries this op without one owes the number.
    ///
    /// J0/J1★ by construction: mint + write + place + provenance ride one
    /// transaction; successive `mint_content` calls read `stg.working()`, so
    /// under the held lock they advance the same frontier → contiguous
    /// I-adjacent addresses → the placement accumulator coalesces them into
    /// exactly ONE placed run, whose start is the first address minted.
    /// The accumulator is asked rather than assumed: were the frontier ever
    /// to hand back a non-adjacent address, the placement would be a correct
    /// multi-run one, never a single run widened over addresses M3 never
    /// allocated and M4 never wrote.
    pub fn insert(
        &self,
        caller: Caller,
        doc: &Address,
        at: VPos,
        values: Vec<Val>,
    ) -> Result<(Address, Seq), TxnError<InsertError>> {
        let key = M3State::content_lock_key(doc);
        self.kernel.transact(&[key], |stg| {
            gate_write(
                stg.working().m3(),
                caller,
                doc,
                InsertError::DocNotRegistered,
                InsertError::NotOwner,
            )?;
            if values.is_empty() {
                return Err(InsertError::EmptyContent);
            }
            if !at.is_content() {
                return Err(InsertError::NotContentSubspace);
            }
            if !stg.working().m5().admits_content_boundary(doc, &at.ordinal) {
                return Err(InsertError::OutOfBounds);
            }
            let mut runs: Vec<Run> = Vec::new();
            for value in values {
                let (addr, m3rec) = stg.working().m3().mint_content(doc)?;
                stg.push(m3rec.into());
                let write = stage_write(stg.working().content(), &addr, value)?;
                stg.push(write.into());
                extend_or_push_run(
                    &mut runs,
                    Run {
                        i_start: addr,
                        width: Nat::one(),
                    },
                );
            }
            // The placement's start is the FIRST address minted: the
            // accumulator only ever widens a run rightwards or opens a new
            // one after it, so the first run's start is the first mint.
            let start = runs
                .first()
                .expect("EmptyContent guard ⇒ at least one value ⇒ at least one run")
                .i_start()
                .clone();
            stg.push(
                M5Rec::ContentPlace {
                    doc: doc.clone(),
                    at: at.ordinal,
                    runs,
                }
                .into(),
            );
            Ok(start)
        })
    }
}

impl<W> Vstream<'_, W>
where
    W: WorldState + HasM5 + HasM3 + HasContent, // reads M3 (registration) + M4 (`contains` gate) + M5
    W::Record: From<M5Rec>,                     // stages only M5Rec (no mint, no byte write)
{
    /// COPY (ASN-0118; §5): transclude existing content by reference —
    /// resolve `specs` against source arrangements off the composite's
    /// consistent base, splice into doc's content subspace at `at`, record
    /// provenance for the placed runs. Allocates NO content (CP1/CP2); the
    /// resolved addresses stay valid forever by content immutability (S0),
    /// so no source lock is needed.
    ///
    /// `specs` is borrowed: COPY reads each spec's source and span and keeps
    /// neither, so a caller that holds its spec list behind a reference is not
    /// made to clone it.
    ///
    /// Check order (which error wins). Destination first, as INSERT:
    /// `DocNotRegistered` → `NotOwner` (the ω gate on the DESTINATION only;
    /// source spans stay unrestricted, transclusion of anyone's content being
    /// the point of the medium) → `NotContentSubspace` → `OutOfBounds`. Then,
    /// per spec: `SourceNotRegistered`
    /// → `NotOrdinalVSpan` (the span fails
    /// [`is_ordinal_vspan`](crate::is_ordinal_vspan) — the one shape `resolve`
    /// folds on, so a span COPY rejects is exactly a span `resolve` would
    /// refuse to serve, Conflicts #7)
    /// → `SourceNotContentSubspace` (that span's subspace ≠ s_C)
    /// → `EmptySource` (ASN-0118
    /// enabled(COPY)) → per-run `DanglingSource` (`M4::contains` on the run
    /// start — S3★, Open decision #5 default) → `TooManyRuns`
    /// ([`MAX_PLACED_RUNS`](crate::MAX_PLACED_RUNS), measured after each run
    /// is accumulated; the resolution is pulled LAZILY, so an over-budget spec
    /// stops the source walk at the cap rather than being resolved in full and
    /// measured afterwards); finally `EmptyResult` when nothing survives
    /// clipping. Cross-origin runs never coalesce
    /// (the placement accumulator's I-adjacency guard), preserving the origin
    /// multiset (CP11).
    ///
    /// WHICH SPEC SPEAKS, when more than one is defective: the specs are
    /// examined in the order given and the FIRST spec to fail any of its
    /// guards decides, with the per-spec order above applying within that
    /// spec. So a mis-shaped span in an earlier spec outranks an unregistered
    /// source in a later one — the list is walked, not the guards.
    ///
    /// The two guards whose subject is not the request's shape but an
    /// invariant, stated so that widening what they gate obliges widening
    /// them:
    ///
    /// * `SourceNotContentSubspace` keeps LINK addresses out of content
    ///   V-positions. It is not a formality: `resolve` serves whichever
    ///   run-list the span's subspace numeral selects, so a link-subspace span
    ///   resolves against the source's LINK runs, and placing those here would
    ///   bind link addresses at content positions — links seated under an
    ///   origin that is not this document, which CL-OWN forbids and no read
    ///   downstream would report.
    /// * `DanglingSource` is S3★ on the content side, and it is checked on run
    ///   STARTS alone. Sound for the interior by induction: every address a
    ///   source arranges was itself admitted through this gate or written by
    ///   INSERT in the composite that placed it, so a present start implies a
    ///   present run. The induction is over the ways an address can enter an
    ///   arrangement — a new one obliges re-examining this check.
    pub fn copy(
        &self,
        caller: Caller,
        doc: &Address,
        at: VPos,
        specs: &[VSpec],
    ) -> Result<Seq, TxnError<CopyError>> {
        let key = M3State::content_lock_key(doc);
        self.kernel
            .transact(&[key], |stg| {
                let world = stg.working();
                gate_write(
                    world.m3(),
                    caller,
                    doc,
                    CopyError::DocNotRegistered,
                    CopyError::NotOwner,
                )?;
                if !at.is_content() {
                    return Err(CopyError::NotContentSubspace);
                }
                if !world.m5().admits_content_boundary(doc, &at.ordinal) {
                    return Err(CopyError::OutOfBounds);
                }
                let mut runs: Vec<Run> = Vec::new();
                for spec in specs {
                    if !world.m3().is_registered_document(&spec.source) {
                        return Err(CopyError::SourceNotRegistered);
                    }
                    let span = &spec.span;
                    let Some(vspan) = as_ordinal_vspan(span) else {
                        return Err(CopyError::NotOrdinalVSpan);
                    };
                    if !vspan.is_content() {
                        return Err(CopyError::SourceNotContentSubspace);
                    }
                    if world.m5().content_count(&spec.source).is_zero() {
                        return Err(CopyError::EmptySource);
                    }
                    // Resolved BEFORE staging ⇒ a self-copy sees the pre-edit
                    // arrangement. Resolved LAZILY, so what one spec makes
                    // this closure hold live is the accumulator (capped
                    // below) and not the source's whole run-list, whose size
                    // the request does not choose.
                    for run in world.m5().iter_resolve(&spec.source, span) {
                        if !world.content().contains(run.i_start().tumbler()) {
                            return Err(CopyError::DanglingSource);
                        }
                        extend_or_push_run(&mut runs, run);
                        // Measured where the run is produced, not after the
                        // whole spec list has been folded: the accumulator is
                        // what a request's spec count multiplies, and a
                        // refusal that arrives at the end has already been
                        // paid for. With the resolution pulled lazily, this
                        // return also ends the source walk, so an over-budget
                        // spec is not resolved past the cap.
                        if runs.len() > MAX_PLACED_RUNS {
                            return Err(CopyError::TooManyRuns);
                        }
                    }
                }
                // Every `Run` has `width ≥ 1` by standing invariant, so a
                // nonempty accumulator places at least one position: the net
                // placement is empty exactly when nothing survived clipping.
                if runs.is_empty() {
                    return Err(CopyError::EmptyResult);
                }
                stg.push(
                    M5Rec::ContentPlace {
                        doc: doc.clone(),
                        at: at.ordinal,
                        runs,
                    }
                    .into(),
                );
                Ok(())
            })
            .map(|((), seq)| seq)
    }
}

impl<W> Vstream<'_, W>
where
    W: WorldState + HasM5 + HasM3, // reads M3 registration + M5 only
    W::Record: From<M5Rec>,        // stages only M5Rec
{
    /// DELETE (ASN-0117; §4): remove content range `[p, p + width)` and
    /// close the gap (shift the suffix left). Content store and R untouched
    /// — NonDestruction is structural (M5 has no reclamation path); link
    /// survival is automatic (a text delete never touches the link
    /// run-list).
    ///
    /// Check order (which error wins): `DocNotRegistered` → `NotOwner` (the ω
    /// gate) → `NotContentSubspace` → `NotArranged` (`p.ordinal ∉ [1, n_C]`)
    /// → `OutOfBounds` (`ordinal + width − 1 > n_C`) → `EmptyWidth`
    /// (`width = 0`).
    ///
    /// THE FIRST TWO OF THOSE MAY NOT BE TRANSPOSED, and the reason is not
    /// only which verdict a caller reads: `NotArranged` also DISCHARGES the
    /// next check's precondition. `contains_content_range` tests the upper
    /// bound alone and means containment only for `p.ordinal ≥ 1`, which the
    /// arranged-position check has just established. Asked the other way
    /// round, a range opening at ordinal 0 would be admitted as contained.
    pub fn delete(
        &self,
        caller: Caller,
        doc: &Address,
        p: VPos,
        width: Nat,
    ) -> Result<Seq, TxnError<DeleteError>> {
        let key = M3State::content_lock_key(doc);
        self.kernel
            .transact(&[key], |stg| {
                gate_write(
                    stg.working().m3(),
                    caller,
                    doc,
                    DeleteError::DocNotRegistered,
                    DeleteError::NotOwner,
                )?;
                if !p.is_content() {
                    return Err(DeleteError::NotContentSubspace);
                }
                let m5 = stg.working().m5();
                if !m5.arranges_content_position(doc, &p.ordinal) {
                    return Err(DeleteError::NotArranged);
                }
                if !m5.contains_content_range(doc, &p.ordinal, &width) {
                    return Err(DeleteError::OutOfBounds);
                }
                if width.is_zero() {
                    return Err(DeleteError::EmptyWidth);
                }
                stg.push(
                    M5Rec::ContentRemove {
                        doc: doc.clone(),
                        from: p.ordinal,
                        width,
                    }
                    .into(),
                );
                Ok(())
            })
            .map(|((), seq)| seq)
    }

    /// REARRANGE (ASN-0119/0084; §6): pivot (3 cuts) / swap (4 cuts)
    /// transpose in the content subspace. Pure cut-determined, value-blind
    /// permutation — content, links, R untouched (a duplicate-I interval
    /// correctly yields π ≠ id with M' = M).
    ///
    /// THE RESULTING ORDER, which is what a caller relays. With THREE cuts the
    /// two adjacent regions `α = [c₀, c₁)` and `β = [c₁, c₂)` exchange in
    /// place, so the arranged content reads `α`'s positions where `β`'s stood
    /// and `β`'s where `α`'s stood. With FOUR, the outer regions
    /// `α = [c₀, c₁)` and `β = [c₂, c₃)` exchange around `μ = [c₁, c₂)`, which
    /// keeps its positions. Everything outside `[ord(c₀), ord(c_last))` is
    /// untouched, and the result is a permutation of the same run multiset:
    /// `content_count` is unchanged, no I-address enters or leaves the
    /// arrangement, and `deletions` therefore reports exactly what it did
    /// before (RA1/RA6).
    ///
    /// `cuts` is borrowed, as COPY's specs are, so the caller keeps the cut
    /// sequence it asked with — to report it beside a rejection, say. The
    /// record then clones the three or four ordinals out; against a
    /// transaction that will fsync, four small clones buy the caller its own
    /// value back.
    ///
    /// Check order (which error wins, per R-PRE): `DocNotRegistered` →
    /// `NotOwner` (the ω gate) → `BadCutCount` (3|4) →
    /// `NotAscending` (strict) → `NotContentSubspace` (every cut) →
    /// `OutOfBounds` (CS5 lower bound `1 ≤ ord(c₀)` and upper bound
    /// `ord(c_last) ≤ n_C + 1`) → `EmptyContentSubspace` (R-PRE(ii);
    /// defensive after the bounds — see [`RearrangeError`]). Strict ascent
    /// already forces every region width ≥ 1, so no per-region emptiness
    /// check is reachable.
    pub fn rearrange(
        &self,
        caller: Caller,
        doc: &Address,
        cuts: &[VPos],
    ) -> Result<Seq, TxnError<RearrangeError>> {
        let key = M3State::content_lock_key(doc);
        self.kernel
            .transact(&[key], |stg| {
                gate_write(
                    stg.working().m3(),
                    caller,
                    doc,
                    RearrangeError::DocNotRegistered,
                    RearrangeError::NotOwner,
                )?;
                if cuts.len() != 3 && cuts.len() != 4 {
                    return Err(RearrangeError::BadCutCount);
                }
                if !cuts.windows(2).all(|w| w[0].ordinal < w[1].ordinal) {
                    return Err(RearrangeError::NotAscending);
                }
                if cuts.iter().any(|c| !c.is_content()) {
                    return Err(RearrangeError::NotContentSubspace);
                }
                let m5 = stg.working().m5();
                // Strict ascent is established above, so asking the
                // arrangement about the first and last cut settles CS5 for
                // every cut between them.
                if !m5.admits_content_boundary(doc, &cuts[0].ordinal)
                    || !m5.admits_content_boundary(doc, &cuts[cuts.len() - 1].ordinal)
                {
                    return Err(RearrangeError::OutOfBounds);
                }
                if m5.content_count(doc).is_zero() {
                    return Err(RearrangeError::EmptyContentSubspace);
                }
                let cut_ordinals: Vec<Nat> = cuts.iter().map(|c| c.ordinal.clone()).collect();
                stg.push(
                    M5Rec::ContentReorder {
                        doc: doc.clone(),
                        cut_ordinals,
                    }
                    .into(),
                );
                Ok(())
            })
            .map(|((), seq)| seq)
    }
}

impl<W> Vstream<'_, W>
where
    W: WorldState + HasM5 + HasM3, // reads M3 (ω pre-read, registration, mints) + M5
    W::Record: From<M5Rec> + From<M3Rec>, // stages M3Rec + M5Rec
{
    /// CREATENEWVERSION (ASN-0123; §7): fork — mint a new identity (M3),
    /// install its content arrangement as a snapshot of `source`'s content
    /// subspace (the multiplicity-preserving V→I map share, V2), record
    /// provenance. Returns the new document address and the commit `Seq`.
    ///
    /// `ω(source)` is pre-read off a snapshot (stable for an existing
    /// document, per M3) to choose branch + lock key: an owned fork mints
    /// `mint_version(source)` under `version_lock_key(source)` (serializing
    /// forks of that source); a cross-owner fork requires the forker's prefix
    /// to be a registered ACCOUNT — M3's `is_registered_account`, which is the
    /// predicate `mint_document` itself gates on, so the P-tier rule has one
    /// spelling and asking it here surfaces `NodeTierCrossOwner` BEFORE any
    /// mint rather than obliquely as `Mint(NotAnAccount)` — and mints
    /// `mint_document(prefix)` under `document_lock_key(prefix)`. Source
    /// untouched (V3); the fork diverges copy-on-write (V11).
    ///
    /// ALL THREE PRE-TRANSACTION READS ARE OFF A SNAPSHOT, taken before the
    /// applier lock and so possibly stale by the time the transaction runs,
    /// and each is sound for its own reason. `ω(source)` is stable for an
    /// existing document (per M3), which is what makes the branch and the
    /// lock key safe to choose before the transaction opens. The two
    /// REGISTRATION reads — `is_registered_document(source)` and
    /// `is_registered_account(prefix)` — are sound because M3's registrations
    /// are MONOTONE: its record set allocates and registers and never
    /// withdraws, so a `true` here cannot go stale, and a `false` can only be
    /// a rejection a retry need not repeat. Any future M2 realization that
    /// widens what may land between a snapshot and its transaction must
    /// re-examine this, along with [`M5Rec::VersionSnapshot`]'s
    /// linearization-at-fold, which the same change already obliges.
    ///
    /// UNGATED, deliberately: this op takes no [`Caller`] and applies no ω
    /// check, because forking a document one may not write IS the remedy the
    /// medium offers for that denial (denial-as-fork, ASN-0042 O10). What
    /// bounds a cross-owner fork is the forker's own tier, not the source's
    /// ownership. `principal` is the forker's identity, not an authorization.
    ///
    /// Check order (which error wins): `SourceNotRegistered` first, so a fork
    /// aimed at an address naming no document discloses nothing about who owns
    /// it. Then the branch decides the rest — an OWNED fork has no further
    /// rejection of its own and can fail only at the mint (`Mint`); a
    /// CROSS-OWNER fork is `NotAPrincipal` (the id names no registered
    /// principal) → `NodeTierCrossOwner` → `Mint`.
    ///
    /// EMPTY SOURCE: a source whose content subspace is empty yields a fork
    /// that is registered and ABSENT from the arrangement map — the lazy
    /// absent-⇒-empty convention, with no redundant entry and no provenance
    /// (ASN-0123 V1). Every read answers for it as it does for any document
    /// M5 has not yet touched.
    ///
    /// COST, AND WHO OWNS IT. One request names one address, and the record
    /// it stages names two; what the fold then does is share the source's
    /// run-list (O(1), structural) and append `#runs(source)` freshly-built
    /// spans to R, permanently, R losing no member ever (P2). So the work and
    /// the state a request commands are set by the SOURCE's fragmentation and
    /// not by the request, and `#runs(source)` is itself grown by editing —
    /// a self-COPY doubles it, within `MAX_PLACED_RUNS` per request.
    ///
    /// M5 CAPS NONE OF IT, and no cap upstream reaches it: M2's
    /// `MAX_TXN_BYTES` prices the staged record, which is two addresses;
    /// M10's `MAX_INSERT_VALUES` prices values and `MAX_WIRE_LIST` prices
    /// lists, and this request carries neither. The asymmetry against COPY is
    /// deliberate to state and not to defend: COPY's R-append is bounded at
    /// [`MAX_PLACED_RUNS`](crate::MAX_PLACED_RUNS) per request and this one is
    /// unbounded, though the two append by the same mechanism and with the
    /// same permanence — a fork cannot be split by its caller the way an
    /// over-budget copy can, so a ceiling here would refuse
    /// `enabled(VERSION)` rather than shape a request. Replay re-does the
    /// expansion from the same two addresses ([`M5Rec::VersionSnapshot`]), so
    /// the bill is charged again at every `Kernel::open`. Admission control
    /// for a route carrying this op is therefore the CALLER's, and a route
    /// that carries it owes the number.
    pub fn version(
        &self,
        principal: PrincipalId,
        source: &Address,
    ) -> Result<(Address, Seq), TxnError<VersionError>> {
        enum Branch {
            Owned,
            Cross(Address),
        }
        let snap = self.kernel.snapshot();
        let m3 = snap.world().m3();
        if !m3.is_registered_document(source) {
            return Err(TxnError::Rejected(VersionError::SourceNotRegistered));
        }
        let (key, branch) = match m3.effective_owner(source) {
            Some(p) if p == principal => (M3State::version_lock_key(source), Branch::Owned),
            _ => {
                // Cross-owner fork.
                let prefix = m3
                    .principal_prefix(principal)
                    .cloned()
                    .ok_or_else(|| TxnError::Rejected(VersionError::NotAPrincipal))?;
                if !m3.is_registered_account(&prefix) {
                    return Err(TxnError::Rejected(VersionError::NodeTierCrossOwner));
                }
                (M3State::document_lock_key(&prefix), Branch::Cross(prefix))
            }
        };
        self.kernel.transact(&[key], |stg| {
            let (v, m3rec) = match &branch {
                Branch::Owned => stg.working().m3().mint_version(source),
                Branch::Cross(prefix) => stg.working().m3().mint_document(prefix),
            }?;
            stg.push(m3rec.into());
            stg.push(
                M5Rec::VersionSnapshot {
                    source: source.clone(),
                    new: v.clone(),
                }
                .into(),
            );
            Ok(v)
        })
    }
}

#[cfg(test)]
mod tests {
    //! The design's per-op-bound claim, verified literally: a MINIMAL test
    //! world — `HasM5 + HasM3`, `Record = M5Rec` (the identity `From`) —
    //! drives `delete` and `rearrange`; no content store, no `From<M3Rec>`.
    //!
    //! And COPY's content-side referential gate (S3★), which needs a world
    //! whose arrangement and content store can be seeded INDEPENDENTLY — a
    //! state no engine reaches, every arranged address there having been
    //! written by INSERT in the same composite.

    use serde::{Deserialize, Serialize};
    use skep_content::ContentStore;
    use skep_kernel::{CheckpointPolicy, Durability, Kernel, KernelConfig};
    use skep_namespace::M3State;

    use super::*;
    use crate::state::M5State;
    use crate::testutil::{ca, doc1, doc2, n, run, seeded_m3, vp, vspan};

    /// Unwrap an op's typed rejection (`TxnError::Rejected(E)` — surfaced
    /// verbatim, per M2's transact contract).
    fn rejected<T, E: fmt::Debug>(r: Result<T, TxnError<E>>) -> E {
        match r {
            Err(TxnError::Rejected(e)) => e,
            Err(other) => panic!("expected TxnError::Rejected, got {other:?}"),
            Ok(_) => panic!("expected TxnError::Rejected, got Ok"),
        }
    }

    #[derive(Clone, Serialize, Deserialize)]
    struct MiniWorld {
        m3: M3State,
        m5: M5State,
    }

    impl WorldState for MiniWorld {
        type Record = M5Rec;
        fn apply(&self, r: &M5Rec) -> MiniWorld {
            MiniWorld {
                m3: self.m3.clone(),
                m5: self.m5.apply_m5(r),
            }
        }
    }
    impl HasM3 for MiniWorld {
        fn m3(&self) -> &M3State {
            &self.m3
        }
    }
    impl HasM5 for MiniWorld {
        fn m5(&self) -> &M5State {
            &self.m5
        }
    }

    fn mini_kernel() -> Kernel<MiniWorld> {
        let m5 = M5State::genesis().apply_m5(&M5Rec::ContentPlace {
            doc: doc1(),
            at: n(1),
            runs: vec![run(&ca(1), 5)],
        });
        let cfg = KernelConfig {
            durability: Durability::InMemory,
            checkpoint: CheckpointPolicy::Manual,
        };
        Kernel::open(cfg, MiniWorld { m3: seeded_m3(), m5 }).expect("in-memory open")
    }

    #[test]
    fn the_handle_prints_without_its_world_being_printable() {
        // `MiniWorld` is not `Debug`, and the handle is — which is the whole
        // reason the impl is written out rather than derived.
        let k = mini_kernel();
        assert_eq!(format!("{:?}", Vstream::new(&k)), "Vstream");
    }

    /// A world carrying a content store beside the arrangement — the one
    /// slice `MiniWorld` deliberately lacks, kept a separate type so the
    /// per-op-bound claim `MiniWorld` witnesses stays witnessed.
    #[derive(Clone, Serialize, Deserialize)]
    struct GateWorld {
        m3: M3State,
        content: ContentStore,
        m5: M5State,
    }

    impl WorldState for GateWorld {
        type Record = M5Rec;
        fn apply(&self, r: &M5Rec) -> GateWorld {
            GateWorld {
                m3: self.m3.clone(),
                content: self.content.clone(),
                m5: self.m5.apply_m5(r),
            }
        }
    }
    impl HasM3 for GateWorld {
        fn m3(&self) -> &M3State {
            &self.m3
        }
    }
    impl HasContent for GateWorld {
        fn content(&self) -> &ContentStore {
            &self.content
        }
    }
    impl HasM5 for GateWorld {
        fn m5(&self) -> &M5State {
            &self.m5
        }
    }

    /// doc1 arranged as `run(ca(1), 3)`, with the content store holding the
    /// bytes of exactly `present`. The two halves of S3★ are set apart from
    /// each other, which is what lets one test say which of them COPY reads.
    fn gate_kernel(present: &[u32]) -> Kernel<GateWorld> {
        gate_kernel_arranging(vec![run(&ca(1), 3)], present)
    }

    /// The same world arranging the runs a caller chooses — for the tests
    /// whose subject is the source's RUN COUNT rather than its bytes.
    fn gate_kernel_arranging(runs: Vec<Run>, present: &[u32]) -> Kernel<GateWorld> {
        let m5 = M5State::genesis().apply_m5(&M5Rec::ContentPlace {
            doc: doc1(),
            at: n(1),
            runs,
        });
        let mut content = ContentStore::default();
        for &k in present {
            let cw = stage_write(&content, &ca(k), Val::new(&b"x"[..]))
                .expect("each seeded address is written once");
            content = content.apply_write(&cw);
        }
        let cfg = KernelConfig {
            durability: Durability::InMemory,
            checkpoint: CheckpointPolicy::Manual,
        };
        Kernel::open(
            cfg,
            GateWorld {
                m3: seeded_m3(),
                content,
                m5,
            },
        )
        .expect("in-memory open")
    }

    #[test]
    fn copy_rejects_a_source_run_whose_start_is_absent_from_the_content_store() {
        // §5/S3★: COPY asserts each resolved run start ∈ dom(C) before
        // placing it, so a transclusion cannot manufacture a reference to
        // bytes that were never written — a reference R would then keep
        // permanently (P2) and every later RETRIEVEV would fail to resolve.
        let p1 = Caller::Principal(PrincipalId(1));
        // `count` positions from doc1's first content ordinal.
        let from_doc1 = |count: u32| {
            vec![VSpec {
                source: doc1(),
                span: vspan(1, 1, count),
            }]
        };

        // Nothing written: the resolved run's start, ca(1), is absent.
        let k = gate_kernel(&[]);
        assert!(matches!(
            rejected(Vstream::new(&k).copy(p1, &doc2(), vp(1, 1), &from_doc1(2))),
            CopyError::DanglingSource
        ));

        // The identical COPY against a store that holds the bytes commits —
        // without this, the rejection above could be earned by anything.
        let k = gate_kernel(&[1, 2, 3]);
        Vstream::new(&k)
            .copy(p1, &doc2(), vp(1, 1), &from_doc1(2))
            .expect("a resolved run whose start is present is admitted");
        assert_eq!(k.snapshot().world().m5().content_count(&doc2()), n(2));

        // Open decision #5's default, pinned: the gate reads run STARTS and
        // relies on the source's own S3★ for the interior. ca(3) is absent,
        // yet the width-3 run starting at the present ca(1) is admitted —
        // widening the gate to every address of a run turns this red, which
        // is how such a change announces itself.
        let k = gate_kernel(&[1, 2]);
        Vstream::new(&k)
            .copy(p1, &doc2(), vp(1, 1), &from_doc1(3))
            .expect("the run start is present, so the run is admitted");
    }

    #[test]
    fn copy_refuses_a_placement_past_the_run_budget_before_building_it() {
        // §5: the runs one COPY places are bounded, and the bound binds the
        // ACCUMULATOR rather than the request — a spec list is a multiplier,
        // so a small request can name an unbounded placement. Here 65_537
        // single-position specs against a one-address source: each resolves
        // to `run(ca(1), 1)`, which is never I-adjacent to the run before it
        // (`shift(ca(1), 1) = ca(2)`), so every one of them pushes.
        let p1 = Caller::Principal(PrincipalId(1));
        let k = gate_kernel(&[1, 2, 3]);
        let one = VSpec {
            source: doc1(),
            span: vspan(1, 1, 1),
        };
        let over_budget_specs: Vec<VSpec> = std::iter::repeat_with(|| one.clone())
            .take(MAX_PLACED_RUNS + 1)
            .collect();
        assert!(matches!(
            rejected(Vstream::new(&k).copy(p1, &doc2(), vp(1, 1), &over_budget_specs)),
            CopyError::TooManyRuns
        ));
        // Nothing was placed: the refusal happens inside the closure, before
        // a record is staged, so the destination is untouched.
        assert_eq!(k.snapshot().world().m5().content_count(&doc2()), n(0));
        // And the cap refuses only what is past it — an ordinary copy still
        // commits, so the assertion above is not earned by refusing COPY.
        Vstream::new(&k)
            .copy(p1, &doc2(), vp(1, 1), &over_budget_specs[..3])
            .expect("a placement inside the budget commits");
        assert_eq!(k.snapshot().world().m5().content_count(&doc2()), n(3));
    }

    #[test]
    fn one_spec_over_a_fragmented_source_is_refused_at_the_cap_not_after_it() {
        // §5: a spec list is one multiplier of the source's fragmentation and
        // the SPAN is the other — a single spec over a heavily fragmented
        // source names as many runs as the source holds in range. The cap
        // therefore has to bind one spec, and because the resolution is pulled
        // lazily the refusal arrives AT the cap: the accumulator never holds
        // more than the budget, whatever the source's run count.
        let p1 = Caller::Principal(PrincipalId(1));
        // Non-adjacent starts (`shift(ca(2k), 1) = ca(2k + 1) ≠ ca(2k + 2)`),
        // so nothing coalesces and the source really holds this many runs.
        let over_budget_runs = MAX_PLACED_RUNS + 1;
        let present: Vec<u32> = (1..=over_budget_runs as u32).map(|k| 2 * k).collect();
        let runs: Vec<Run> = present.iter().map(|&k| run(&ca(k), 1)).collect();
        let k = gate_kernel_arranging(runs, &present);
        assert_eq!(
            k.snapshot().world().m5().content_runs(&doc1()).len(),
            over_budget_runs,
            "the source arranges one run per placed address"
        );
        // ONE spec, whose span covers the whole source.
        let whole = [VSpec {
            source: doc1(),
            span: vspan(1, 1, over_budget_runs as u32),
        }];
        assert!(matches!(
            rejected(Vstream::new(&k).copy(p1, &doc2(), vp(1, 1), &whole)),
            CopyError::TooManyRuns
        ));
        assert_eq!(k.snapshot().world().m5().content_count(&doc2()), n(0));
        // A span inside the budget over the same source still commits, so the
        // refusal above is about the count and not about the source.
        Vstream::new(&k)
            .copy(
                p1,
                &doc2(),
                vp(1, 1),
                &[VSpec {
                    source: doc1(),
                    span: vspan(1, 1, 4),
                }],
            )
            .expect("a span inside the budget commits");
        assert_eq!(k.snapshot().world().m5().content_count(&doc2()), n(4));
    }

    #[test]
    fn the_placement_budget_stays_inside_the_transaction_budget() {
        // MAX_PLACED_RUNS is a number with an argument behind it, and the
        // argument is about M2's encoding — so it is measured against that
        // encoding rather than remembered. A full placement must still be a
        // transaction M2 could accept: a cap above the journal's own ceiling
        // would be no cap at all, since the work would be done and then
        // refused downstream, which is the cost the cap exists to refuse.
        const SAMPLE: usize = 64;
        let runs: Vec<Run> = (1..=SAMPLE as u32).map(|k| run(&ca(2 * k), 1)).collect();
        let rec = M5Rec::ContentPlace {
            doc: doc1(),
            at: n(1),
            runs,
        };
        let per_run = bincode::serialize(&rec).expect("the record encodes").len() / SAMPLE;
        let full = MAX_PLACED_RUNS as u64 * per_run as u64;
        assert!(
            full < skep_kernel::MAX_TXN_BYTES,
            "a full placement encodes to ~{full} bytes, past M2's {}",
            skep_kernel::MAX_TXN_BYTES
        );
    }

    #[test]
    fn delete_and_rearrange_drive_a_minimal_world() {
        let k = mini_kernel();
        let vs = Vstream::new(&k);
        // The seeded owner of doc1 — the ω gate is exercised, not skipped.
        let p1 = Caller::Principal(PrincipalId(1));
        vs.delete(p1, &doc1(), vp(1, 2), n(1)).expect("delete commits");
        let seq = vs
            .rearrange(p1, &doc1(), &[vp(1, 1), vp(1, 2), vp(1, 3)])
            .expect("rearrange commits");
        let s = k.snapshot();
        assert_eq!(s.seq(), seq);
        let m5 = s.world().m5();
        // After deleting V2 (ca(2)): [ca1, ca3, ca4, ca5]; pivot at [1,2,3]
        // exchanges V1 and V2: [ca3, ca1, ca4, ca5].
        assert_eq!(m5.content_count(&doc1()), n(4));
        assert_eq!(m5.point(&doc1(), &vp(1, 1)), Some(ca(3)));
        assert_eq!(m5.point(&doc1(), &vp(1, 2)), Some(ca(1)));
        assert_eq!(m5.point(&doc1(), &vp(1, 3)), Some(ca(4)));
    }
}
