//! STAGE, the staging act (B3-S10; §7): a private draft of a source, with
//! where it began recorded.
//!
//! One commit mints the draft in the caller's own account, shares the
//! source's reading surface into it as `version` shares, and records the
//! draft's base, the extent the copy took and its source in the slice's own
//! state — so the draft stands whole or not at all, and every reader of it
//! learns where its next publication lands from the board rather than from
//! a record the client wrote.

use skep_address::Address;
use skep_kernel::{Seq, TxnError, WorldState};
use skep_namespace::{HasM3, M3Rec, M3State, PrincipalId};

use super::{head_lock_key, Vstream};
use crate::chain::{published_target, reading_surface};
use crate::error::StageError;
use crate::state::{M5Rec, Merge};
use crate::HasM5;

impl<W> Vstream<'_, W>
where
    W: WorldState + HasM5 + HasM3, // reads M3 (registration, the mint) + M5 (the count, the base)
    W::Record: From<M5Rec> + From<M3Rec>, // stages M3Rec + M5Rec
{
    /// Stages a private draft of `from`, its base recorded (B3-S10).
    ///
    /// The staging act as one board operation: in one commit this mints a
    /// fresh private document in `principal`'s own account — as `fork` mints
    /// one, `mint_document(prefix, false)`, never a member of any chain —
    /// installs its content arrangement as a snapshot of the content
    /// subspace of `from`'s reading surface, exactly as
    /// [`version`](Vstream::version) does (the multiplicity-preserving V→I
    /// map share, V2; the source untouched, V3; the draft diverging
    /// copy-on-write, V11; the link subspace not shared), and records where
    /// the draft began ([`M5Rec::DraftBase`], folded into
    /// [`draft_base`](crate::M5State::draft_base)). Returns the draft's
    /// address and the commit `Seq`. A stop between the three leaves
    /// nothing: the mint, the snapshot and the record are one transaction.
    ///
    /// **Which surface is copied** is `from`'s reading surface
    /// ([`reading_surface`](crate::reading_surface)): a version member
    /// itself; a bare published document's trunk head, or the document
    /// itself while its chain is empty; a private draft itself. Read off the
    /// working state before the mint is staged, as `version` reads it. The
    /// snapshot's `source` is that surface, so
    /// [`fork_source`](crate::M5State::fork_source) answers it for the draft
    /// as it answers a `version`'s.
    ///
    /// **What is recorded**, by what the surface is:
    ///
    /// * a version member, or a bare published document (memberless, or
    ///   with members — its head) — `base` the surface itself and `extent`
    ///   the surface's whole content count at the commit, measured: what the
    ///   copy took, a memberless home's genesis atom counted where it is
    ///   there; `source` the surface;
    /// * a private draft of the caller's, or any draft the caller may read
    ///   — an ALTERNATIVE of it: `base` and `extent` that draft's own
    ///   recorded base and extent, inherited by identity, since the
    ///   alternative holds the draft's words; `source` the draft; and the
    ///   draft's merge marker, where it carries one, INHERITED with them
    ///   (the owner's ruling N3 and its precision P2) — the record carries
    ///   its content, and the fold stamps THIS commit's position as the
    ///   marker's `at`, the position the marker was put on the alternative,
    ///   so an undo of the alternative reads before its own mint and finds
    ///   nothing to take back. A draft the board holds no base for yields no
    ///   record: the alternative is a free-standing draft of its own,
    ///   whatever its source becomes.
    ///
    /// The base moves at every shot the draft renders: the shot's placing
    /// record names its rendering draft ([`M5Rec::ShotPlace`]), and the fold
    /// moves the draft's base to the member minted, clearing the marker
    /// (BASE★ on [`M5State`](crate::M5State)); and at every landing that
    /// names a base to record
    /// ([`set_arrangement`](Vstream::set_arrangement)), which sets or clears
    /// the marker with it. Nothing checks a shot's own `base` against the
    /// record: the request's base is the client's statement, as
    /// [`Base`](crate::Base) states it, whether or not the board holds one.
    ///
    /// **Always private.** The draft is minted private whatever `from`'s
    /// state, so it lands in no published world: it is never a publish-class
    /// act, carries no attestation — the transaction takes the plain arm,
    /// whatever handle this is called on, and leaves the marker's signature
    /// slot empty — and the version-chain refusals never read on it. It is
    /// the sibling draft those refusals point to (PUB-2.7, PUB-2.9).
    ///
    /// **Ungated, as `version` is**: no [`Caller`](crate::Caller) and no ω
    /// check — `from` may be any registered document, the caller's own or
    /// another's. What bounds the act is the caller's own tier: the draft is
    /// minted in the caller's account, which must be a registered account.
    ///
    /// **Precondition.** The caller has established that `principal` may
    /// read `from` (PUB-6.23's source gate). M5 knows no principal's read
    /// rights and takes no consult here, as it takes none for `version`: on
    /// the wire route M10's pre-dispatch consult discharges it (`withheld`);
    /// a caller driving this directly owes its own.
    ///
    /// **Locks.** `document_lock_key` of the caller's account, under which
    /// the draft is minted, and the source's head key (`head_lock_key`),
    /// since the snapshot takes the source's reading surface off that
    /// frontier — the keys `version`'s cross-owner arm takes.
    ///
    /// **Cost**: `version`'s, stated there — the share O(1), the R-append
    /// `#runs(reading_surface(from))` spans, permanent, re-paid at replay —
    /// plus one map lookup for the base and one for the count.
    ///
    /// # Errors
    ///
    /// Each refusal comes as `TxnError::Rejected`, in this order (which
    /// error wins): `SourceNotRegistered` first — off the pre-transaction M2
    /// snapshot, so a stage aimed at an address naming no document discloses
    /// nothing about it — then `NotAPrincipal` (the id names no registered
    /// principal), then `NodeTierCrossOwner` (the caller's prefix is no
    /// registered account), both off that snapshot and sound for the reasons
    /// `version` states of its own pre-transaction reads; then `Mint`,
    /// defensive, M3's frontier gate alone. The kernel's own failures —
    /// `OverBudget`, `Unencodable`, `Durability`, `Poisoned` — come back as
    /// `transact` returns them.
    pub fn stage(
        &self,
        principal: PrincipalId,
        from: &Address,
    ) -> Result<(Address, Seq), TxnError<StageError>> {
        // The three pre-transaction reads come off the M2 snapshot, which
        // lives in this block alone; each is sound for the reason `version`
        // states — registration is monotone, a principal's prefix is
        // value-stable.
        let prefix = {
            let snap = self.kernel.snapshot();
            let snapshot_m3 = snap.world().m3();
            if !snapshot_m3.is_registered_document(from) {
                return Err(TxnError::Rejected(StageError::SourceNotRegistered));
            }
            let prefix = snapshot_m3
                .principal_prefix(principal)
                .cloned()
                .ok_or_else(|| TxnError::Rejected(StageError::NotAPrincipal))?;
            if !snapshot_m3.is_registered_account(&prefix) {
                return Err(TxnError::Rejected(StageError::NodeTierCrossOwner));
            }
            prefix
        };
        let keys = [M3State::document_lock_key(&prefix), head_lock_key(from)];
        // The plain arm, whatever the handle carries: a stage is never
        // publish-class, so its marker's signature slot stays empty.
        self.kernel.transact(&keys, |stg| {
            let world = stg.working();
            let m3 = world.m3();
            // The surface shared, read before the mint is staged, as
            // `version` reads it.
            let surface = reading_surface(m3, from);
            // The base and the extent: the surface itself at its count where
            // it is published (a member, or the bare document), no marker;
            // else the source draft's own record, inherited — base, extent
            // and the marker's content, its position the fold's to stamp
            // (N3, P2) — or none.
            let recorded = if published_target(m3, &surface) {
                Some((surface.clone(), world.m5().content_count(&surface), None))
            } else {
                world.m5().draft_base(&surface).map(|standing| {
                    (
                        standing.base.clone(),
                        standing.extent.clone(),
                        standing.merge.as_ref().map(Merge::from),
                    )
                })
            };
            let (draft, m3rec) = m3.mint_document(&prefix, false)?;
            stg.push(m3rec.into());
            stg.push(M5Rec::VersionSnapshot { source: surface.clone(), new: draft.clone() }.into());
            if let Some((base, extent, merge)) = recorded {
                stg.push(
                    M5Rec::DraftBase { draft: draft.clone(), base, extent, source: surface, merge }
                        .into(),
                );
            }
            Ok(draft)
        })
    }
}
