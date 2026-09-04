//! §B / §3–§7 — the editing & versioning surface: `Vstream`, one M2
//! `transact` per operation, every mutation under an M3 lock key for the
//! touched document's allocation domain (§Serialization key). Rejections are
//! validated before any record is staged, so a rejection leaves no state
//! change; M10 surfaces `TxnError::Rejected(E)` as typed rejections and
//! acknowledges only after commit.
//!
//! Ownership (as amended 2026-08-16): the four edit ops take a [`Caller`]
//! and require `caller.is_owner(m3, doc)` — the in-txn ω gate — on the
//! document whose arrangement they write (COPY: destination only; VERSION
//! untouched — non-owner versioning is denial-as-fork, O10, correct as
//! built).
//!
//! Per-op trait bounds: each impl block names exactly the slices its ops
//! read and the records they stage, so a minimal test world can drive
//! `delete`/`rearrange` with `HasM5 + HasM3` and `From<M5Rec>` alone.

use num_traits::Zero;
use skep_address::{content_subspace, zeros, Address, Nat};
use skep_content::{stage_write, ContentWrite, HasContent, Val};
use skep_kernel::{Kernel, Seq, TxnError, WorldState};
use skep_namespace::{HasM3, M3Rec, M3State, PrincipalId};

use crate::auth::Caller;
use crate::error::{CopyError, DeleteError, InsertError, RearrangeError, VersionError};
use crate::run::Run;
use crate::runlist::{extend_or_push_run, extend_run};
use crate::state::M5Rec;
use crate::vspace::{is_ordinal_vspan, VPos, VSpec};
use crate::HasM5;

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
    pub fn new(k: &'k Kernel<W>) -> Vstream<'k, W> {
        Vstream { kernel: k }
    }
}

impl<'k, W> Vstream<'k, W>
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
    /// in-txn ω gate — ownership ruling, as amended 2026-08-16) →
    /// `EmptyContent` → `NotContentSubspace` (`at.subspace ≠ s_C`) →
    /// `OutOfBounds` (the arrangement does not admit `at.ordinal` as a
    /// placement boundary — Valid(First)InsertionPosition, so ordinal = 1
    /// when n_C = 0).
    /// J0/J1★ by construction: mint + write + place + provenance ride one
    /// transaction; successive `mint_content` calls read `stg.working()`,
    /// so under the held lock they advance the same frontier → contiguous
    /// I-adjacent addresses → exactly ONE placed run ([`extend_run`] only
    /// ever widens it).
    pub fn insert(
        &self,
        caller: Caller,
        doc: &Address,
        at: VPos,
        values: Vec<Val>,
    ) -> Result<(Address, Seq), TxnError<InsertError>> {
        let key = M3State::content_lock_key(doc);
        self.kernel.transact(&[key], |stg| {
            if !stg.working().m3().is_registered_document(doc) {
                return Err(InsertError::DocNotRegistered);
            }
            if !caller.is_owner(stg.working().m3(), doc) {
                return Err(InsertError::NotOwner(doc.clone()));
            }
            if values.is_empty() {
                return Err(InsertError::EmptyContent);
            }
            if at.subspace != content_subspace() {
                return Err(InsertError::NotContentSubspace);
            }
            if !stg.working().m5().admits_content_boundary(doc, &at.ordinal) {
                return Err(InsertError::OutOfBounds);
            }
            let mut first: Option<Address> = None;
            let mut open: Option<Run> = None;
            for v in values {
                let (a, m3rec) = stg.working().m3().mint_content(doc)?;
                stg.push(m3rec.into());
                let cw = stage_write(stg.working().content(), &a, v)?;
                stg.push(cw.into());
                if first.is_none() {
                    first = Some(a.clone());
                }
                extend_run(&mut open, a);
            }
            let run = open.expect("EmptyContent guard ⇒ at least one value ⇒ a run opened");
            stg.push(
                M5Rec::ContentPlace {
                    doc: doc.clone(),
                    at: at.ordinal,
                    runs: vec![run],
                }
                .into(),
            );
            Ok(first.expect("at least one mint succeeded"))
        })
    }
}

impl<'k, W> Vstream<'k, W>
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
    /// Destination checks as INSERT (`DocNotRegistered` → `NotOwner` — the
    /// ω gate on the DESTINATION only; source spans stay unrestricted,
    /// transclusion of anyone's content being the point of the medium
    /// (ownership ruling, as amended 2026-08-16) — `NotContentSubspace` →
    /// `OutOfBounds`); per spec: `SourceNotRegistered`
    /// → `BadSpan` (fails [`is_ordinal_vspan`] — the one shape predicate,
    /// which `resolve` folds on, so a span COPY rejects is exactly a span
    /// `resolve` would refuse to serve, Conflicts #7)
    /// → `SourceNotContentSubspace`
    /// (`span.start().get(1) ≠ s_C`) → `EmptySource` (ASN-0118
    /// enabled(COPY)) → per-run `DanglingSource` (`M4::contains` on the run
    /// start — S3★, Open decision #5 default); finally `EmptyResult` when
    /// nothing survives clipping. Cross-origin runs never coalesce
    /// ([`extend_or_push_run`]'s I-adjacency guard), preserving the origin
    /// multiset (CP11).
    pub fn copy(
        &self,
        caller: Caller,
        doc: &Address,
        at: VPos,
        specs: Vec<VSpec>,
    ) -> Result<Seq, TxnError<CopyError>> {
        let key = M3State::content_lock_key(doc);
        self.kernel
            .transact(&[key], |stg| {
                let w = stg.working();
                if !w.m3().is_registered_document(doc) {
                    return Err(CopyError::DocNotRegistered);
                }
                if !caller.is_owner(w.m3(), doc) {
                    return Err(CopyError::NotOwner(doc.clone()));
                }
                if at.subspace != content_subspace() {
                    return Err(CopyError::NotContentSubspace);
                }
                if !w.m5().admits_content_boundary(doc, &at.ordinal) {
                    return Err(CopyError::OutOfBounds);
                }
                let mut runs: Vec<Run> = Vec::new();
                for spec in &specs {
                    if !w.m3().is_registered_document(&spec.source) {
                        return Err(CopyError::SourceNotRegistered);
                    }
                    let span = &spec.span;
                    if !is_ordinal_vspan(span) {
                        return Err(CopyError::BadSpan);
                    }
                    if span.start().get(1) != Some(&content_subspace()) {
                        return Err(CopyError::SourceNotContentSubspace);
                    }
                    if w.m5().content_count(&spec.source).is_zero() {
                        return Err(CopyError::EmptySource);
                    }
                    // Resolved BEFORE staging ⇒ a self-copy sees the pre-edit
                    // arrangement.
                    for r in w.m5().resolve(&spec.source, span) {
                        if !w.content().contains(r.i_start().tumbler()) {
                            return Err(CopyError::DanglingSource);
                        }
                        extend_or_push_run(&mut runs, r);
                    }
                }
                let total = runs.iter().fold(Nat::zero(), |acc, r| acc + r.width());
                if total.is_zero() {
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

impl<'k, W> Vstream<'k, W>
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
    /// Check order: `DocNotRegistered` → `NotOwner` (the ω gate —
    /// ownership ruling, as amended 2026-08-16) → `NotContentSubspace` →
    /// `NotArranged` (`p.ordinal ∉ [1, n_C]`) → `OutOfBounds`
    /// (`ordinal + width − 1 > n_C`) → `EmptyWidth` (`width = 0`).
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
                if !stg.working().m3().is_registered_document(doc) {
                    return Err(DeleteError::DocNotRegistered);
                }
                if !caller.is_owner(stg.working().m3(), doc) {
                    return Err(DeleteError::NotOwner(doc.clone()));
                }
                if p.subspace != content_subspace() {
                    return Err(DeleteError::NotContentSubspace);
                }
                let m5 = stg.working().m5();
                if !m5.content_position_arranged(doc, &p.ordinal) {
                    return Err(DeleteError::NotArranged);
                }
                if !m5.content_range_within(doc, &p.ordinal, &width) {
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
    /// Check order (R-PRE): `DocNotRegistered` → `NotOwner` (the ω gate —
    /// ownership ruling, as amended 2026-08-16) → `BadCutCount` (3|4) →
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
        cuts: Vec<VPos>,
    ) -> Result<Seq, TxnError<RearrangeError>> {
        let key = M3State::content_lock_key(doc);
        self.kernel
            .transact(&[key], |stg| {
                if !stg.working().m3().is_registered_document(doc) {
                    return Err(RearrangeError::DocNotRegistered);
                }
                if !caller.is_owner(stg.working().m3(), doc) {
                    return Err(RearrangeError::NotOwner(doc.clone()));
                }
                if cuts.len() != 3 && cuts.len() != 4 {
                    return Err(RearrangeError::BadCutCount);
                }
                if !cuts.windows(2).all(|w| w[0].ordinal < w[1].ordinal) {
                    return Err(RearrangeError::NotAscending);
                }
                if cuts.iter().any(|c| c.subspace != content_subspace()) {
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
                let ords: Vec<Nat> = cuts.into_iter().map(|c| c.ordinal).collect();
                stg.push(
                    M5Rec::ContentReorder {
                        doc: doc.clone(),
                        cuts: ords,
                    }
                    .into(),
                );
                Ok(())
            })
            .map(|((), seq)| seq)
    }
}

impl<'k, W> Vstream<'k, W>
where
    W: WorldState + HasM5 + HasM3, // reads M3 (ω pre-read, registration, mints) + M5
    W::Record: From<M5Rec> + From<M3Rec>, // stages M3Rec + M5Rec
{
    /// CREATENEWVERSION (ASN-0123; §7): fork — mint a new identity (M3),
    /// install its content arrangement as a snapshot of `d_src`'s content
    /// subspace (the multiplicity-preserving V→I map share, V2), record
    /// provenance. Returns the new document address and the commit `Seq`.
    ///
    /// `ω(d_src)` is pre-read off a snapshot (stable for an existing
    /// document, per M3) to choose branch + lock: an owned fork mints
    /// `mint_version(d_src)` under `version_lock_key(d_src)` (serializing
    /// forks of d_src); a cross-owner fork requires an ACCOUNT-tier forker
    /// (`zeros(pfx) == 1` — the P-tier gate, surfaced as
    /// `NodeTierCrossOwner` BEFORE any mint rather than obliquely as
    /// `Mint(NotAnAccount)`) and mints `mint_document(pfx)` under
    /// `document_lock_key(pfx)`. Source untouched (V3); the fork diverges
    /// copy-on-write (V11).
    pub fn version(
        &self,
        principal: PrincipalId,
        d_src: &Address,
    ) -> Result<(Address, Seq), TxnError<VersionError>> {
        enum Branch {
            Owned,
            Cross(Address),
        }
        let snap = self.kernel.snapshot();
        let m3 = snap.world().m3();
        if !m3.is_registered_document(d_src) {
            return Err(TxnError::Rejected(VersionError::SourceNotRegistered));
        }
        let (lock, branch) = match m3.effective_owner(d_src) {
            Some(p) if p == principal => (M3State::version_lock_key(d_src), Branch::Owned),
            _ => {
                // Cross-owner fork.
                let pfx = m3
                    .principal_prefix(principal)
                    .cloned()
                    .ok_or_else(|| TxnError::Rejected(VersionError::NotAPrincipal))?;
                if zeros(pfx.tumbler()) != 1 {
                    return Err(TxnError::Rejected(VersionError::NodeTierCrossOwner));
                }
                (M3State::document_lock_key(&pfx), Branch::Cross(pfx))
            }
        };
        self.kernel.transact(&[lock], |stg| {
            let (v, m3rec) = match &branch {
                Branch::Owned => stg.working().m3().mint_version(d_src),
                Branch::Cross(pfx) => stg.working().m3().mint_document(pfx),
            }?;
            stg.push(m3rec.into());
            stg.push(
                M5Rec::VersionSnapshot {
                    source: d_src.clone(),
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

    use serde::{Deserialize, Serialize};
    use skep_kernel::{CheckpointPolicy, Durability, Kernel, KernelConfig};
    use skep_namespace::M3State;

    use super::*;
    use crate::state::M5State;
    use crate::testutil::{ca, doc1, n, run, seeded_m3, vp};

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
    fn delete_and_rearrange_drive_a_minimal_world() {
        let k = mini_kernel();
        let vs = Vstream::new(&k);
        // The seeded owner of doc1 — the ω gate is exercised, not skipped.
        let p1 = Caller::Principal(PrincipalId(1));
        vs.delete(p1, &doc1(), vp(1, 2), n(1)).expect("delete commits");
        let seq = vs
            .rearrange(p1, &doc1(), vec![vp(1, 1), vp(1, 2), vp(1, 3)])
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
