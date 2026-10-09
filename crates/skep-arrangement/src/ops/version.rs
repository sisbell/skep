//! CREATENEWVERSION (ASN-0123; §7): the fork — a new identity sharing its
//! source's reading surface, on the owned arm or the cross-owner one.

use skep_address::Address;
use skep_kernel::{Seq, TxnError, WorldState};
use skep_namespace::{HasM3, M3Rec, M3State, PrincipalId};

use super::{head_lock_key, Vstream};
use crate::chain::{published_target, reading_surface};
use crate::error::VersionError;
use crate::state::M5Rec;
use crate::HasM5;

impl<W> Vstream<'_, W>
where
    W: WorldState + HasM5 + HasM3, // reads M3 (ω pre-read, registration, mints) + M5
    W::Record: From<M5Rec> + From<M3Rec>, // stages M3Rec + M5Rec
{
    /// CREATENEWVERSION (ASN-0123; §7): fork — mint a new identity (M3),
    /// install its content arrangement as a snapshot of the content subspace
    /// of `source`'s READING SURFACE (the arrangement `source`'s readers
    /// answer from, below) — the multiplicity-preserving V→I map share, V2 —
    /// and record provenance. Returns the new document address and the commit
    /// `Seq`.
    ///
    /// Whether `principal` owns `source` is asked of M3's authorization
    /// predicate — `is_effective_owner`, the ω rule the ownership gate asks
    /// through [`Caller::is_owner`](crate::Caller::is_owner), so ownership
    /// has one spelling here just as the P-tier rule below does — off an M2
    /// snapshot (stable for an existing document, per M3), to choose branch +
    /// lock key: an owned fork mints `mint_version(source, bit)` under
    /// `version_lock_key(source)` (serializing forks of that source); a
    /// cross-owner fork requires the
    /// forker's prefix to be a registered ACCOUNT — M3's
    /// `is_registered_account`, which is the predicate `mint_document` itself
    /// gates on, so the P-tier rule has one spelling and asking it here
    /// surfaces `NodeTierCrossOwner` BEFORE any mint rather than obliquely as
    /// `Mint(NotAnAccount)` — and mints `mint_document(prefix, bit)` under
    /// `document_lock_key(prefix)`. Either branch also holds the source's
    /// head key (`head_lock_key`, the trunk's `version_lock_key`), since the
    /// fork snapshots its source's reading surface (below). On the owned arm
    /// of a trunk the two keys are one, which M2 normalizes. Source untouched
    /// (V3); the fork diverges copy-on-write (V11).
    ///
    /// THE PUBLICATION BIT (PUB round 1): the new document's RESOLVED
    /// publication state, which THIS composite resolves off its own working
    /// state and passes down (PUB-8.17) — the mints apply no default of their
    /// own (PUB-8.18). `published` is the three-valued wire flag (PUB-8.16):
    /// `Some(b)` ⇒ `b`, and ABSENT (`None`) ⇒ INHERIT `published(source)`,
    /// on BOTH branches — a cross-owner fork into an EMPTY account inherits
    /// too, never the create path's born-published rule (lane 0's rider: the
    /// copy inherits; M3 applies no default). The source's state is read on
    /// the DOCUMENT a version member projects to ([`published_target`],
    /// PUB-2.15).
    ///
    /// THE TWO REFUSALS OF THE VERSION-CHAIN MODEL (PUB round 2, lane 3.1;
    /// owner ruling D2b), both EXACT OF THE OWN-SOURCE ARM (PUB-2.14) and
    /// evaluated inside the transaction off its working state, in PUB-6.36's
    /// one slot, after registration:
    ///
    /// * `PrivateSourceVersionless` (PUB-2.9) — the caller OWNS `source` and
    ///   its document is PRIVATE: private documents are versionless, whatever
    ///   the flag says (absent, `false` or `true` — one code; the FACE splits
    ///   on the flag the caller SENT, which is the daemon's to render).
    /// * `PrivateVersionOfPublished` (PUB-2.7) — the caller OWNS `source`,
    ///   its document is PUBLISHED, and the RESOLVED state is private, which
    ///   only an explicit `false` produces (absent inherits published and is
    ///   legal, PUB-2.8).
    ///
    /// The CROSS-OWNER branch is refused by NEITHER: it mints a fresh
    /// document in the caller's own account off the source default plus the
    /// flag, as round 1 built it — the entitled reader's private working copy
    /// of published material (an explicit `false`), the inherited copy (an
    /// absent flag), and the fork of another's draft all stand (PUB-2.18,
    /// PUB-2.21). Applying the refusals to that arm would forbid every
    /// private working copy of every published document to every principal,
    /// which PUB-2.14 forbids.
    ///
    /// UNGATED, deliberately: this op takes no [`Caller`](crate::Caller) and applies no ω
    /// check, because forking a document one may not write IS the remedy the
    /// medium offers for that denial (denial-as-fork, ASN-0042 O10). What
    /// bounds a cross-owner fork is the forker's own tier, not the source's
    /// ownership — nor the source's readability, which this op cannot judge.
    /// `principal` is the forker's identity, not an authorization.
    ///
    /// REQUIRES — the caller has established that `principal` may read
    /// `source` (PUB-6.23's source gate). M5 knows no principal's read rights
    /// and takes no consult for VERSION, so nothing here checks it: a caller
    /// that skips it lets the cross-owner arm fork a document its principal
    /// may not read into that principal's own account, where the read
    /// predicate's subtree clause makes the copy readable. On the wire route
    /// M10's pre-dispatch consult discharges it; a caller driving VERSION
    /// directly owes its own.
    ///
    /// Check order (which error wins): `SourceNotRegistered` first — off the
    /// pre-transaction M2 snapshot, so a fork aimed at an address naming no
    /// document discloses nothing about who owns it or whether it is
    /// published. Then the branch decides the rest. An OWNED fork:
    /// `PrivateSourceVersionless` → `PrivateVersionOfPublished` (both inside
    /// the transaction, off its working state) → `Mint`; the two refusals
    /// cannot both hold — the first needs the source's document private, the
    /// second published — so their order between themselves decides nothing.
    /// A CROSS-OWNER fork: `NotAPrincipal` (the id names no registered
    /// principal) → `NodeTierCrossOwner` (both off that M2 snapshot) → `Mint`,
    /// neither refusal reading on that arm (PUB-2.14). `Mint` is defensive on
    /// both arms: the source's registration and the forker's account-hood are
    /// established above and M3's registrations are monotone, which leaves
    /// only M3's frontier gate. The three refusals answered off that snapshot
    /// are answered off a state that may predate the transaction, so one that
    /// raced a registration need not recur on a retry.
    ///
    /// WHICH ARRANGEMENT IS SNAPSHOTTED (lane 3.2's head-float): the source's
    /// READING SURFACE ([`reading_surface`]) — a bare published source with
    /// members forks its trunk HEAD's arrangement, the one its readers answer
    /// from (PUB-2.49), never its own pre-chain arrangement, which a shot has
    /// superseded and which a trunk member built from it would have the bare
    /// address float back to. A version address forks its own member
    /// (PUB-2.50); a private or memberless source forks itself. The record's
    /// `source` is that surface, read off the working state — never off the
    /// M2 snapshot the branch and its lock key are chosen from, since a shot
    /// or an owned fork of the trunk can advance the frontier between the two
    /// — and read before the fork's own mint is staged, as
    /// [`trunk_head`](crate::trunk_head) requires: after it, an owned fork
    /// would be the head it asks about.
    ///
    /// EMPTY SURFACE: when the arrangement snapshotted arranges no content,
    /// the fork is registered and ABSENT from the arrangement map — the lazy
    /// absent-⇒-empty convention, with no redundant entry and no provenance
    /// (ASN-0123 V1) — and every read of its arrangement and of R answers for
    /// it as for any document M5 has not yet touched. The emptiness is the
    /// SURFACE's, not the address named's: a bare published source whose own
    /// pre-chain arrangement is empty forks its head's content, and one whose
    /// head is empty forks nothing, whatever its pre-chain arrangement holds.
    ///
    /// THE BIRTH EXTENT: a fork that is its trunk's BIRTH VERSION (PUB-2.34)
    /// — `D.1`, which the owned arm mints off a memberless published document
    /// — has its birth extent noted at the count it shares (BIRTH★, on
    /// [`M5State`](crate::M5State)), ZERO when the surface is empty. So for
    /// that fork [`birth_extent`](crate::M5State::birth_extent) answers a
    /// noted zero where a document M5 has not touched answers `None` — the one
    /// read that tells an empty birth version from an untouched document. No
    /// other fork notes an extent, and no fork carries
    /// [`shot_terms`](crate::M5State::shot_terms): no shot minted it.
    ///
    /// THE LINK SUBSPACE IS NOT SHARED: the fork's link subspace starts EMPTY,
    /// whatever the surface seats. ASN-0123 V2 shares the CONTENT map, and a
    /// link is arranged only in its home document (CL-OWN), so the source's
    /// seated links stay the source's; a link made on the source's content
    /// still reaches the fork through the content the two share, found at
    /// query time by link discovery rather than enumerated in the fork's own
    /// link subspace. That is a ruled divergence from the reference
    /// implementation, which copies the source's link subspace into the
    /// version (`conformance/adjudication/decisions.md`, ruling 15);
    /// link-subspace versioning is ASN-0123's open question OQ3. The shot's
    /// member starts with an empty link subspace for the same reason
    /// ([`publish`](Vstream::publish)).
    ///
    /// COST, AND WHO OWNS IT. One request names one address, and the record
    /// it stages names two; what the fold then does is share the surface's
    /// run-list (O(1), structural) and append `#runs(reading_surface(source))`
    /// freshly-built spans to R, permanently, R losing no member ever (P2). So
    /// the work and the state a request commands are set by the SURFACE's
    /// fragmentation and not by the request, and that count is itself grown
    /// by editing — a self-COPY of a draft doubles it, within
    /// `MAX_PLACED_RUNS` per request.
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
    /// that carries it owes the number:
    /// [`content_run_count`](crate::M5State::content_run_count) of the
    /// source's [`reading_surface`], which the arrangement answers without
    /// reading a run.
    ///
    /// THE ATTESTED ARM (signed ops): the transaction commits under the
    /// handle's attestation where it carries one — a `version` landing in
    /// the published world is a publish-class act, signed over the parent
    /// account the member or the fresh document is minted under, with an
    /// EMPTY body — and with the slot empty otherwise, the kernel's arm being
    /// `transact` itself under `None`.
    pub fn version(
        &self,
        principal: PrincipalId,
        source: &Address,
        published: Option<bool>,
    ) -> Result<(Address, Seq), TxnError<VersionError>> {
        enum Branch {
            Owned,
            CrossOwner(Address),
        }
        // The four pre-transaction reads, and nothing else, come off the M2
        // snapshot: it lives in this block alone, which yields the key and
        // the branch and ends before the transaction opens, so no read inside
        // the transaction can be taken off it. The snapshot may be stale by
        // the time the transaction runs, and each read is sound for its own
        // reason. The ownership read is stable for an existing document (per
        // M3), which is what makes the branch and the lock key safe to choose
        // here. The two REGISTRATION reads — `is_registered_document(source)`
        // and `is_registered_account(prefix)` — are sound because M3's
        // registrations are MONOTONE: its records allocate and register and
        // never withdraw, so a `true` cannot go stale and a `false` is a
        // rejection a retry need not repeat. The forker's PREFIX is
        // value-stable across snapshots (M3: prefixes are immutable and
        // principals persist), so a `Some` names the same account inside the
        // transaction and a `None` is a rejection a retry need not repeat. An
        // M2 realization that widens what may land between a snapshot and its
        // transaction must re-examine this, with `M5Rec::VersionSnapshot`'s
        // linearization-at-fold, which the same change already obliges.
        let (key, branch) = {
            let snap = self.kernel.snapshot();
            let snapshot_m3 = snap.world().m3();
            if !snapshot_m3.is_registered_document(source) {
                return Err(TxnError::Rejected(VersionError::SourceNotRegistered));
            }
            if snapshot_m3.is_effective_owner(principal, source) {
                (M3State::version_lock_key(source), Branch::Owned)
            } else {
                // Cross-owner fork.
                let prefix = snapshot_m3
                    .principal_prefix(principal)
                    .cloned()
                    .ok_or_else(|| TxnError::Rejected(VersionError::NotAPrincipal))?;
                if !snapshot_m3.is_registered_account(&prefix) {
                    return Err(TxnError::Rejected(VersionError::NodeTierCrossOwner));
                }
                (M3State::document_lock_key(&prefix), Branch::CrossOwner(prefix))
            }
        };
        let keys = [key, head_lock_key(source)];
        self.kernel.transact_attested(&keys, self.attest, |stg| {
            let m3 = stg.working().m3();
            // PUB-8.16/8.17: resolve the three-valued flag off this
            // composite's OWN working state — `Some(b)` ⇒ `b`, ABSENT ⇒
            // INHERIT `published(d_src)` — and pass the RESOLVED bit down as
            // the bit the record journals (PUB-7.10, PUB-8.18). `source` is a
            // registered document (the monotone pre-read above), so the
            // inherit read is inside `published_target`'s contract; it is
            // read on the DOCUMENT a version member projects to (PUB-2.15).
            let source_published = published_target(m3, source);
            let fork_published = published.unwrap_or(source_published);
            let (fork, m3rec) = match &branch {
                // PUB-6.36 slot 5, the own-source arm alone (PUB-2.14):
                // private documents are versionless (PUB-2.9), and a
                // published one admits no private member (PUB-2.7).
                Branch::Owned => {
                    if !source_published {
                        return Err(VersionError::PrivateSourceVersionless);
                    }
                    if !fork_published {
                        return Err(VersionError::PrivateVersionOfPublished);
                    }
                    m3.mint_version(source, fork_published)
                }
                Branch::CrossOwner(prefix) => m3.mint_document(prefix, fork_published),
            }?;
            // The arrangement shared is the source's reading surface — its
            // trunk head when it has one (head-float, PUB-2.49) — asked of
            // the working state before the fork's mint is staged below.
            let surface = reading_surface(m3, source);
            stg.push(m3rec.into());
            stg.push(
                M5Rec::VersionSnapshot {
                    source: surface,
                    new: fork.clone(),
                }
                .into(),
            );
            Ok(fork)
        })
    }
}
