//! skep-kernel — M2: Transaction, Journal & Concurrency Kernel.
//!
//! The engine's **generic transactional substrate**: every state change becomes
//! one atomic, totally-ordered step, durable and recoverable where journaled
//! (or a composite committed as one); committed state is served as consistent
//! snapshots; writers are serialized — while M2 knows nothing about what any
//! change *means*. It is a WAL + atomic-install + keyed-serialization +
//! snapshot kernel, dependency-inverted: M2 defines the fold
//! ([`WorldState::apply`]), the engine implements it, and M2 only calls down
//! through that trait.
//!
//! Spec traceability: doc-comments cite the labels they realize — ASN-0134's
//! atomic-step model (A0–A7), MIC clauses 1–7, verdict coordinates V0–V2, run
//! contiguity W2, SAFE(b)(iii) lost-acks — and ASN-0047's journaling/recovery
//! obligations — plus §-references into the M2 design (journal & WAL §1,
//! sequencer §2, transaction boundary §3, keyed sections §4, snapshots §5,
//! checkpoint §6, recovery §7, concurrency realizations §8).
//!
//! The v1 concurrency realization is the **single applier** (§8): one global
//! applier lock serializes every write, subsuming the [`LockKey`] seam, and the
//! one commit ordering, where journaled, is **durable-before-visible** (§1):
//! append records → append commit marker → one records+marker fsync → atomic
//! root install → return. The `transact`/`snapshot` signatures and the
//! `LockKey` seam are invariant across the deferred per-key/CAS realizations.
//!
//! ## Checkpoints, inline or deferred
//!
//! The §6 cadence is tested on commit under the applier lock, never by a
//! timer. Under its inline arms the crossing commit runs the checkpoint on
//! its own thread, the result reaching no caller but as the kernel's record
//! of the run ([`Kernel::last_inline_checkpoint`]); under
//! [`CheckpointPolicy::Deferred`] it sets the due flag instead
//! ([`Kernel::checkpoint_due`], lock-free) and the caller's own thread runs
//! [`Kernel::checkpoint`] — which clears the flag first, then runs — and
//! reads the result. A crossing that finds the flag already set runs the
//! checkpoint inline after all, the backstop: a caller that services no flag
//! gets a checkpoint at every second crossing and never an unbounded
//! window. [`CheckpointPolicy::EitherOf`] crosses when either of its two
//! policies does, whichever first — a commit count beside a byte bound, the
//! shape it exists for — and [`Kernel::set_cadence_bytes`] and
//! [`Kernel::set_cadence_commits`] move the bound and the count in a running
//! kernel — the two values of a [`KernelConfig`] that move after
//! [`Kernel::open`] reads it; [`CheckpointHeader::len`] is the figure a
//! caller sizes the byte bound by — the newest base's through
//! [`Kernel::newest_checkpoint`], or one base's by its seq through
//! [`Kernel::checkpoint_header`], the start point's after an open that
//! skipped a newer base. The fixed `checkpoint.tmp` is the kernel's to
//! remove: a failed write removes its own, best-effort, and [`Kernel::open`]
//! removes one a crash or a failed write left, reporting its size as
//! [`Kernel::stray_checkpoint_removed`].
//!
//! ## The journal's tail, at the open
//!
//! Every journaled open sorts the bytes after the last committed marker into
//! two classes (§7). A crash's tail — one interrupted append's bytes, at
//! most [`MAX_CRASH_TAIL_BYTES`], none of them acknowledged — is cut and
//! gone. Anything else is damage, and the write it holds may have been
//! acknowledged: an intact commit marker committing nothing, a CRC-intact
//! frame that does not decode, or no intact frame over more bytes than one
//! append leaves. The open refuses such a tail, the journal as it found it
//! ([`OpenError::Corruption`] carrying [`DamagedTail`]), until the
//! configuration accepts the cut by name ([`Durability::Fsync`]'s
//! `cut_damaged_tail`, one open's word): then every byte of the tail is kept
//! beside the journal first (`seg-<n>.wal.cut-<b>`, [`Recovery`]'s
//! `tail_cut_kept`), the tail is cut, and no position it claimed is handed
//! out again ([`Kernel::order_floor`]). Whether a journal stands in a
//! directory at all is [`journal_stands`]'s answer, the one a tool asks
//! before an open that would begin one.
//!
//! The kernel has no logging seam: it answers facts, and the caller above
//! says them. A journaled open reports what it found and did as [`Recovery`]
//! — the start point, the bases it passed over, the commits it replayed, the
//! tail it cut with where the cut began, the intact frames in it no torn
//! write leaves, the position an intact marker in it claimed and the files
//! its bytes were kept in, whether it began a journal where none stood, and
//! the corrupt runs below the start point it read and passed over; a landing
//! answers the journal bytes it reclaimed and the checkpoints it removed
//! through [`Kernel::last_reclaimed_bytes`] and
//! [`Kernel::last_removed_checkpoints`]; the checkpoints `transact` ran
//! inline on a committing thread are counted, and the last one recorded —
//! the commit that ran it, how long it held that commit's caller, how it
//! ended ([`Kernel::inline_checkpoints`], [`Kernel::last_inline_checkpoint`]);
//! and a checkpoint that failed after its base landed names which step
//! failed — the directory's fsync, retention or the journal's reclamation —
//! as [`CheckpointError::Landed`] carrying a [`LandedStep`]. **Retention
//! counts every base but those the open skipped**: the names an open passed
//! over are passed over by the count of bases to keep and removed as excess,
//! so the first landing after a skip keeps the base the open loaded from
//! beside the new one, where `retain_checkpoints` is two or more.
//!
//! The `test-hooks` feature compiles in the test seam (`hooks.rs`). It holds
//! the write-fault seam, under which a test makes the next checkpoint write —
//! before or past the rename that publishes it — or the next journal append,
//! barrier or repair fail with a named `io::ErrorKind` (`StorageFull` for the
//! full volume), or the next checkpoint write or journal append panic, each
//! arm firing once and disarming, armed through `Kernel`'s `#[doc(hidden)]`
//! doors `fail_the_next` and `panic_at_the_next`, with `armed_steps` reading
//! what stands; and the count of the bases this kernel's history reads have
//! loaded, read through the door `bases_loaded`. The open's tail keep hooks
//! the seam at its copy's fsync, which fires only under the cut's own unit
//! suite: an arm a door places there stands unfired. The seam is one
//! kernel's, never the process's, and a build without the feature carries
//! none of it: the write sites' hook before a [`Step`] is a no-op there.
//!
//! ## Boundary — deliberately not owned here
//!
//! * address, frontier, or coverage-class computation (M1/M3/M7 — keys and
//!   payloads are opaque; [`LockKey`] order is bytewise, never tumbler order);
//! * store permanence P0–P3/L12 and the J-couplings J0/J1★ (the stores enforce
//!   them at their composite boundaries *through* M2, never by it);
//! * record semantics — payloads are the engine's `W::Record`, folded blindly;
//! * the request lifecycle, dispatch, and acknowledgment-to-client (M10 — M2
//!   keeps only the commit-gate *mechanism*: return after install, and install
//!   after durability where journaled);
//! * derived hints — the stores own them; M2 journals only authoritative
//!   deltas (§1);
//! * multi-step (`m ≥ 2`) batch atomicity — M2 offers only the per-`transact`
//!   atomic unit (ASN-0134 A5: a multi-step batch's atomicity is the caller's,
//!   built above the substrate); a single-step (`m = 1`) fire *is* one atomic
//!   `transact`;
//! * durability *as a requirement* — not a MIC clause; [`Durability::InMemory`]
//!   is a faithful realization.
//!
//! ## Composition
//!
//! M2 sits below every store: it has no upstream module dependency, and the
//! central [`Space`] tag enum lives here precisely so no store picks a lock-key
//! space tag locally (cross-store uniqueness without a crate cycle — the engine
//! crate depends on every store and would cycle). The tags are all M2 can hold:
//! a `key(home, …) -> LockKey` constructor names M1's `Address`, and M2 carries
//! no edge to M1. So each store builds its own keys in these spaces through
//! [`LockKey::new`] — M3's `skep-namespace` public chain constructors
//! (`content_lock_key`, `link_lock_key`, `version_lock_key`,
//! `document_lock_key`) are the ones every other store's writes go through;
//! its account chain's key (`account_lock_key`) and its two registry keys
//! (`principals_lock_key`, `nodes_lock_key`) are private to M3, whose own ops
//! are the only ones that take them.
//!
//! ## Example
//!
//! ```no_run
//! use serde::{Deserialize, Serialize};
//! use skep_kernel::{
//!     BurnedSeqPolicy, CheckpointPolicy, Durability, Kernel, KernelConfig, SaltSource,
//!     WorldState,
//! };
//!
//! #[derive(Clone, Serialize, Deserialize)]
//! struct World { log: Vec<u64> }
//! #[derive(Clone, Serialize, Deserialize)]
//! struct Append(u64);
//! impl WorldState for World {
//!     type Record = Append;
//!     fn apply(&self, record: &Append) -> World {
//!         let mut w = self.clone();
//!         w.log.push(record.0);
//!         w
//!     }
//! }
//!
//! let cfg = KernelConfig {
//!     durability: Durability::Fsync {
//!         journal_path: "/var/lib/skep/journal".into(),
//!         retain_checkpoints: 2,
//!         burned_seq: BurnedSeqPolicy::Rollback,
//!         cut_damaged_tail: false,
//!     },
//!     checkpoint: CheckpointPolicy::EveryN(1024),
//!     salt: SaltSource::Os,
//! };
//! let kernel = Kernel::open(cfg, World { log: vec![] }).unwrap();
//! let (_, seq) = kernel
//!     .transact::<_, ()>(&[], |stg| {
//!         stg.push(Append(7));
//!         Ok(())
//!     })
//!     .unwrap();
//! assert_eq!(kernel.snapshot().seq(), seq);
//! ```

#![forbid(unsafe_code)]
#![deny(missing_docs)]

// The modules in dependency order: each names only modules above it, and the
// root's own `Seq`, `LockKey`, `WorldState`, `Step` and `Seam` — save
// `error`, which names `checkpoint`'s `refused_at_decode`. The rules that hold
// across them are in the workspace's ARCHITECTURE.md, §The kernel.

// `KernelConfig` and its knobs, each validating itself; `SaltSource` draws the
// chain's salt.
mod config;
// The four error vocabularies, one per operation, the refusal of a base's
// seed, and the stamp renderer both formats share.
mod error;
// The test seam — `test-hooks` builds only: the write-fault seam's state,
// its hook before a step, and the arming and the base-load count the
// kernel's doors delegate to.
#[cfg(feature = "test-hooks")]
mod hooks;
// The journal: its on-disk format and the crate's one codec, with the writer,
// the scan, the segment files, the chain link and the signature slot beneath
// it.
mod journal;
// Checkpoint files: header, body, listing and retention.
mod checkpoint;
// Base selection and the fold: the one derivation recovery and the history
// reads share.
mod replay;
// `Kernel` and its handles: recovery, the commit path and checkpointing, with
// the applier lock and the history reads beneath it.
mod kernel;

pub use checkpoint::{CheckpointHeader, CHECKPOINT_FORMAT};
pub use config::{BurnedSeqPolicy, CheckpointPolicy, Durability, KernelConfig, SaltSource};
pub use error::{
    CheckpointError, DamagedTail, DamagedTailTell, HistoryError, LandedStep, OpenError,
    RebuildError, TxnError,
};
pub use journal::{
    journal_stands, Attestation, AttestationError, JOURNAL_FORMAT, MAX_CRASH_TAIL_BYTES,
    MAX_SEGMENT_LEN, MAX_SIG_BYTES, MAX_TXN_BYTES,
};
pub use kernel::{InlineCheckpoint, Kernel, Recovery, Snapshot, Staging};
pub use replay::SkippedBase;

use std::fmt;

use serde::de::DeserializeOwned;
use serde::Serialize;

/// The engine's contract to M2, dependency-inverted.
///
/// The engine composes all store slices into one `World`, implements this
/// trait for it, and instantiates [`Kernel<World>`]. M2 never names the
/// concrete world — it only calls down through this trait (Engine Composition
/// Contract).
///
/// **Cost of `Clone`.** M2 clones `W` once per [`Kernel::transact`] that finds
/// the kernel unpoisoned, before the closure runs and therefore for rejected
/// and zero-step transactions too, and it does so while holding the applier
/// lock, so the clone is on the critical section every other writer in the
/// process waits behind. `Clone` must therefore be cheap: the design's
/// structurally-shared store slices are a requirement of this path, and a
/// slice that moves to an eagerly-copied collection makes every transaction
/// in the system — read-only ones included — `O(|world|)` under a global
/// lock, which M2 has no way to report.
///
/// **Drop obligation.** `W`'s destructor must not unwind, and M2 cannot check
/// this. What M2 does fix is *where* a world's destructor can run: never
/// after a root's install inside the commit region — [`Kernel::transact`]
/// holds the superseded root until the call returns, so the install releases
/// only a reference, and every unwind out of the commit region precedes the
/// install, as the region's repair assumes. So an unwinding destructor
/// surfaces wherever a world's *last* reference goes: out of a `transact`
/// whose transaction has committed and installed — the superseded root,
/// released as the call returns — so the caller receives a panic in place of
/// the `Ok` it was owed, the lost-ack case (§3); out of a `transact` that
/// installed nothing — a staged world discarded by `f`'s rejection, a
/// zero-step return, the `Seq` order's refusal or the journal's, or
/// [`Staging::push`] replacing it — with nothing committed and the kernel as
/// the answer it displaces would have left it, save where that answer is a
/// repair's failure: the §3 unwind guard runs the repair again, and only a
/// second failure halts the kernel, its frames possibly standing; out of
/// whichever read or [`Kernel::checkpoint`] releases the last reference to a
/// superseded root, a [`Snapshot`] most often; out of [`Kernel::open`],
/// [`Kernel::world_at`], [`Kernel::chain_at`], [`Kernel::attestation_at`] and
/// [`Kernel::boundaries_above`], whose base loads and folds drop worlds of
/// their own; and out of the kernel's own drop, which releases its reference
/// to the installed root and drops the genesis a journaled kernel keeps.
///
/// **Hostile-input obligation.** `W` is decoded from a checkpoint body, which
/// is bytes M2 does not trust: the header checksum proves they are the bytes
/// that were written, and nothing about whether decoding them is safe. So
/// this type's `Deserialize` must terminate and must not exhaust the stack on
/// any byte string. The same obligation binds [`Record`], and is written out
/// in full there. M2 cannot check this.
///
/// **Canonical-encoding obligation.** This type's `Serialize`, and
/// [`Record`]'s, must write *one* byte string per value, on every process and
/// every machine. M2's codec fixes every integer's width and every field's
/// place; the order a type's own `Serialize` visits the entries of a map or a
/// set is the type's, so an authoritative collection serializes in an order
/// that is a function of its contents — never a hash map's iteration order
/// under a per-process `RandomState`, which a derived hint may still hold
/// behind `#[serde(skip)]`. Two promises rest on it, and recovery on neither:
/// a checkpoint's `body_hash` names the world it embodies
/// ([`CheckpointHeader`]), so two checkpoints of one world at one coordinate
/// carry one body and a replica that derived that world can check a published
/// base by it; and one op sequence under one [`SaltSource::Seeded`] seed
/// writes one journal byte for byte, so two replicas of one history agree on
/// every chain link. Recovery reads back the very bytes it framed, so nothing
/// but a comparison across two processes notices a violation. M2 cannot check
/// this.
///
/// [`Record`]: WorldState::Record
pub trait WorldState: Clone + Serialize + DeserializeOwned + Send + Sync + 'static {
    /// The engine's central record enum.
    ///
    /// It is the union of every store's own record type. Opaque to M2:
    /// journaled as bytes, folded via [`apply`].
    ///
    /// **Round-trip obligation.** A record is journaled as bytes and replayed
    /// by decoding those bytes, so [`apply`] must have the same effect on the
    /// decoded record as on the one that was staged: this type's serde must
    /// round-trip everything [`apply`] reads. A `#[serde(skip)]`ped field, a
    /// `#[serde(default)]` whose default differs from what was written, or a
    /// `Serialize` that normalizes, each make replay fold a different record
    /// than the live commit folded — so the recovered world differs from the
    /// acknowledged one by exactly that difference, silently, and
    /// [`Kernel::world_at`] answers a world [`Kernel::snapshot`] never held.
    /// Nothing a record carries that [`apply`] does not read need survive the
    /// round trip. M2 cannot check this.
    ///
    /// **Hostile-input obligation.** M2 decodes this type from bytes it does
    /// not trust: a journal frame is validated by a CRC, which proves the
    /// bytes are the ones that were written and nothing about whether
    /// decoding them is safe. So this type's `Deserialize` must terminate and
    /// must not exhaust the stack on any byte string. Two shapes break that,
    /// and neither is caught here: a recursive type has no depth limit under
    /// this journal's codec, and a stack overflow aborts rather than unwinding
    /// — no error, no [`crate::OpenError::Corruption`], and [`Kernel::open`]
    /// does not return; and a sequence whose element consumes no bytes turns
    /// a length prefix into an unbounded loop. Bound recursion depth where a
    /// value is admitted, not where it is decoded — by then the bytes have
    /// already been accepted. M2 cannot check this.
    ///
    /// [`apply`]: WorldState::apply
    type Record: Serialize + DeserializeOwned + Send + Sync + 'static;

    /// Returns this world with `record` folded in: the one fold step.
    ///
    /// Deterministic, total and side-effect-free, it drives both live commit
    /// and replay (ASN-0134 A6: every journal prefix up to a committed marker
    /// is a canonical reachable state). Folds authoritative deltas and
    /// maintains every derived hint incrementally; a hint not folded here is
    /// stale after every live write and after replay ([`rebuild_derived`]
    /// runs only at load). Deterministic so replay reproduces committed state
    /// exactly — together with [`Record`]'s round-trip obligation, which is
    /// what makes the record replay hands this method the record that was
    /// staged. Not required to be idempotent — recovery applies each committed
    /// record exactly once (the checkpoint embodies `Seq ≤ S_load`, replay
    /// covers `S_load < Seq ≤ W`; §6/§7).
    ///
    /// **Where it runs.** Once per [`Staging::push`], inside the
    /// [`Kernel::transact`] closure and therefore on the applier lock's
    /// critical section, and once per replayed record at [`Kernel::open`] and
    /// [`Kernel::world_at`]. So it must be cheap for the reason `Clone` must
    /// be: a fold that copies the world builds one copy per record, and on
    /// the commit path it does so with every other writer in the process
    /// waiting.
    ///
    /// [`Record`]: WorldState::Record
    ///
    /// [`rebuild_derived`]: WorldState::rebuild_derived
    fn apply(&self, record: &Self::Record) -> Self;

    /// Seeds derived hints from authoritative state, or refuses the base.
    ///
    /// Runs once per base a derivation loads — at every journaled
    /// [`Kernel::open`] and at every history read that selects a base
    /// ([`Kernel::world_at`], [`Kernel::chain_at`], [`Kernel::attestation_at`],
    /// [`Kernel::boundaries_above`]; genesis's slot and the empty range select
    /// none), on each base it loads, a retained checkpoint or genesis, until
    /// one seeds — before replay, and never on a live commit, so it cannot
    /// keep any hint current by itself. It exists solely to reconstruct hints
    /// a checkpoint skip-serialized (`#[serde(skip)]`), and to say when it
    /// cannot. Not run under [`Durability::InMemory`], which does not load:
    /// that mode installs the caller's `genesis` value as the root exactly as
    /// given. Default `Ok(self)`; override iff hints are skipped or a slice can
    /// be absent.
    ///
    /// **Consistency obligation** (§7, seam contract 2): an override must seed
    /// exactly the hint state that folding every record with `Seq ≤ S` through
    /// [`apply`] would produce (`S` = the seq of the base selected — a
    /// retained checkpoint's, or `0` for genesis) — or refuse. Recovery and
    /// [`Kernel::world_at`] run `rebuild_derived` (seeding `Seq ≤ S`) then
    /// replay `Seq > S` through `apply`; if the seed disagrees with the
    /// `apply`-fold it stands in for, the recovered — or the historical —
    /// hint diverges from the live-maintained one and reads go wrong. A
    /// refusal is what an override answers where no seed it could compute
    /// would agree — a slice the base was written without, over records whose
    /// fold depends on a commit order the base does not hold — and it is the
    /// only honest answer there: a guessed seed is exactly the divergence this
    /// obligation forbids. M2 cannot check this.
    ///
    /// **What may be skipped** (§6/§7): a checkpoint is a serialized `W`
    /// standing in for the fold over `Seq ≤ S`, so only state this method can
    /// reconstruct may be `#[serde(skip)]`ped. Authoritative state must
    /// survive the serde round trip: [`Kernel::world_at`] promises the same
    /// world at a boundary whichever base carries it, and a skipped
    /// authoritative field makes a checkpoint-based derivation differ from a
    /// genesis-based one by exactly that field, silently. A world that skips
    /// nothing needs no override at all, which is why the default is
    /// `Ok(self)`. M2 cannot check this either.
    ///
    /// **Genesis obligation.** The `genesis` handed to [`Kernel::open`] must
    /// arrive with its derived hints already consistent with its own
    /// authoritative state, and must seed `Ok`, because
    /// [`Durability::InMemory`] installs it unseeded while a journaled
    /// `open()` seeds it through this method where it stands in. A world that
    /// relies on that seeding is right in one mode and wrong in the other,
    /// silently, and both modes answer the same coordinate — `Seq(0)` — with
    /// different hints; a genesis that refuses leaves a derivation that
    /// reaches it no base to stand in, answered as the exhausted chain it is.
    /// M2 cannot check this.
    ///
    /// # Errors
    ///
    /// **The refusal** (the AUTH spec's M2 seam delta, AUTH-2.85): an override
    /// that cannot seed from what the base carries answers [`RebuildError`],
    /// and the base is not a start point — `open` and every history read pass
    /// it over exactly as they pass over a checkpoint that does not decode,
    /// under the fallback chain: the next-older retained checkpoint, then
    /// genesis while the journal still reaches it, and
    /// [`OpenError::BadCheckpoint`] or [`HistoryError::Reclaimed`] only when
    /// the chain is exhausted, carrying the newest candidate's refusal as its
    /// `cause`, which is this one where that candidate refused its seed.
    /// Startup and the history reads run the same chain (AUTH-2.84), and a
    /// journaled `open` reports what it did — the start point and every base
    /// it passed over — as [`Recovery`], so the caller can say so. Retention
    /// counts none of the bases the open passed over — a refused one among
    /// them — among the bases it keeps, and the first landing removes them,
    /// save a name a later checkpoint wrote over; the reclaim floor is the
    /// oldest base kept ([`Kernel::checkpoint`]). The error is M2's own and
    /// slice-agnostic: it names the slice and nothing of what the slice means,
    /// since this kernel knows nothing about what any change means.
    ///
    /// [`apply`]: WorldState::apply
    fn rebuild_derived(self) -> Result<Self, RebuildError> {
        Ok(self)
    }
}

/// M2's per-record linearization coordinate (ASN-0134 A1/A2).
///
/// The assignment of a record's `Seq` under the applier lock is its
/// linearization point. Monotone always; gap-free under
/// [`BurnedSeqPolicy::Rollback`] (the default), monotone-only under
/// [`BurnedSeqPolicy::TolerateGap`] (§1/§3/Invariants). `Copy`, so
/// [`Snapshot::seq`]/[`Kernel::current_seq`] return it by value.
///
/// A refinement of ASN-0134's `𝔼`, not an identity (§2): non-`→_sh` records
/// also draw a `Seq`, and for a multi-record composite the externally
/// observable coordinate is the terminal `last_seq` returned by
/// [`Kernel::transact`], never an interior `Seq`. No caller derives `idx(σ)`
/// from it.
///
/// `Seq::default()` is `Seq(0)` — the genesis boundary, the coordinate before
/// anything is committed: what [`Kernel::open`] installs under
/// [`Durability::InMemory`], and what [`Kernel::world_at`] answers at.
#[derive(Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Seq(pub u64);

impl fmt::Display for Seq {
    /// Writes the bare coordinate.
    ///
    /// It is how every error message that names one spells it.
    ///
    /// # Errors
    ///
    /// The formatter's error, where the sink it writes to refuses the bytes.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Opaque serialization key (MIC clauses 2/5/7).
///
/// It is the documented serialization seam M3/M7 code against. M2 only
/// `Eq`/`Hash`/`Ord`-s the bytes (`Ord` is bytewise, not tumbler order). A
/// key is built by [`LockKey::new`] from a [`Space`] and the caller's own
/// bytes, so the 1-byte space tag every key carries is prefixed in one place
/// and distinct key spaces (e.g. `(home, subspace)` vs coverage-class) never
/// collide.
///
/// Under the v1 single applier the global applier lock subsumes the keys
/// (§4/§8) — they are the seam, not a live lock table — so the deferred
/// per-key realization slots in without changing any caller's call shape.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct LockKey(Vec<u8>);

impl LockKey {
    /// Returns a key in `space`, over the caller's own opaque bytes.
    ///
    /// The 1-byte tag is prefixed here, so no store can forget it or choose
    /// one locally — which is what makes the cross-store uniqueness [`Space`]
    /// promises structural rather than a convention each store re-keeps.
    pub fn new(space: Space, bytes: &[u8]) -> LockKey {
        let mut key = Vec::with_capacity(1 + bytes.len());
        key.push(space.tag());
        key.extend_from_slice(bytes);
        LockKey(key)
    }
}

/// The single central lock-key space-tag enum (§4, §Dependencies & seams).
///
/// It names only 1-byte constants — no store types — so it sits below every
/// store; were it in the engine crate (which depends on every store) each
/// store would need an edge to the engine: a compile-time crate cycle (Engine
/// Composition Contract). Tags are never chosen per-store, which is what
/// guarantees cross-store uniqueness: without it two stores could both pick
/// `0x01` and silently alias M3's `(home,subspace)` keys with M7's
/// coverage-class keys.
///
/// Dormant under the v1 single applier (the global lock subsumes all keys —
/// §4/§8); load-bearing under the deferred per-key realization.
#[non_exhaustive]
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Space {
    /// `(home, subspace)` namespace/frontier keys.
    ///
    /// The keys of entity allocation (M3), content writes (M4), placement
    /// (M5) and link allocation (M7), byte-equal by construction because every
    /// one of them is built by M3's `*_lock_key` constructors over one
    /// encoding, so they serialize against each other (MIC clause 2 / H0
    /// discipline).
    Namespace = 0x01,
    /// Coverage-class keys: M7's idem=⊤ dedup critical sections.
    ///
    /// MIC clause 7 / G2: read-decide-deposit is one action under this key.
    CoverageClass = 0x02,
    /// The principal registry: M3's single global `principals_lock_key`.
    ///
    /// It serializes delegation's id-freshness read; that race is
    /// cross-namespace, so it cannot ride on a namespace key.
    Principals = 0x03,
    /// The node registry: M3's single global `nodes_lock_key`.
    ///
    /// It keeps a concurrent duplicate `RegisterNode` a typed rejection
    /// rather than a silent coalesce.
    Nodes = 0x04,
}

impl Space {
    /// Returns the 1-byte tag this space's keys carry.
    ///
    /// [`LockKey::new`] writes it. Public so the assignment is inspectable —
    /// the uniqueness the enum exists for is a claim about these bytes.
    pub const fn tag(self) -> u8 {
        self as u8
    }
}

/// The steps of the kernel's write paths the test seam hooks before.
///
/// Under `test-hooks` (`hooks.rs`) an arm — a failure of a named
/// `io::ErrorKind`, or a panic — is placed before the step it names, after
/// every step before it has completed, so what each leaves is the step's
/// own card. Three are the checkpoint write's: its temp file's creation,
/// the temp file's fsync, and the directory's fsync after the rename that
/// publishes it. Three are the journal appender's: the append of a
/// transaction's frames, the barrier that commits them, and the truncation
/// that repairs a failed or unwound commit. One is the open's tail cut's:
/// the fsync of the copy it keeps of a tail that holds an intact frame no
/// torn write leaves. The rename itself — which a directory squatting on its
/// name already refuses, as one squatting on the temp file's name refuses
/// the creation — is no step. Named in every build, so each write site's
/// hook before a step is one call whether the seam is compiled in or not;
/// without the feature nothing reads it.
///
/// Deliberately not `#[non_exhaustive]`: the seam says of every step whether
/// it takes a panic arm (`hooks.rs`), and a suite outside this crate that
/// lists every step should fail its build when one is added rather than fall
/// into a wildcard.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Step {
    /// The checkpoint's temp file's creation, the world already serialized.
    ///
    /// An arm here leaves nothing on disk — the shape a panic in the world's
    /// own serializer has, which precedes the temp file's creation.
    CheckpointCreate,
    /// The temp file's fsync, its header and body written.
    ///
    /// A failure here lands no base and removes the temp file, best-effort,
    /// before it is answered; a panic leaves the temp file whole under the
    /// fixed name, for the next checkpoint write to write over, or the next
    /// open to remove and report ([`Kernel::stray_checkpoint_removed`]).
    CheckpointSync,
    /// The directory's fsync after the rename that publishes the checkpoint.
    ///
    /// The base is on disk, and a failure here answers
    /// [`CheckpointError::Landed`] over it, naming the step
    /// ([`LandedStep::DirectorySync`]), with retention and reclamation not
    /// run — the landed base that error's card says survives.
    CheckpointDirSync,
    /// The append of a transaction's frames to the active segment.
    ///
    /// It comes after the rotation and before a byte of the transaction is on
    /// disk: a failure here is repaired by the truncation and answers
    /// [`TxnError::Durability`]; a panic here is the unwind out of the commit
    /// region the §3 guard repairs.
    JournalAppend,
    /// The barrier, the one fsync of records and marker.
    ///
    /// The frames are appended and none of them durable: a failure here is
    /// repaired by the truncation and answers [`TxnError::Durability`], as the
    /// append's does.
    JournalBarrier,
    /// The truncation back to the pre-transaction mark.
    ///
    /// It repairs a failed append or barrier, or an unwind out of the commit
    /// region: a failure here is the repair's own, and poisons the kernel
    /// ([`TxnError::Poisoned`]).
    JournalRepair,
    /// The fsync of the copy the open's tail cut keeps.
    ///
    /// The tail holds an intact frame no torn write leaves
    /// ([`Recovery::tail_cut_kept`]); the copy's bytes are written and
    /// nothing is cut. A failure here removes the copy, best-effort, cuts
    /// nothing and fails the open with [`OpenError::Io`]. The step is hooked
    /// on the seam the open makes, which no door can arm before the open
    /// runs, so it fires only where the cut's own unit suite hands it a seam
    /// of its own; an arm a door places here stands unfired.
    TailKeep,
}

/// The write-fault seam as the write paths hold it.
///
/// Each write path calls its hook before a [`Step`]. Under `test-hooks` it is
/// the kernel's seam state behind an `Arc` (`hooks::Hooks`), so what the
/// kernel's doors arm its journal appender fires; the checkpoint write and
/// the open's tail cut take it by reference.
#[cfg(feature = "test-hooks")]
pub(crate) type Seam = std::sync::Arc<hooks::Hooks>;
/// The write-fault seam as the write paths hold it.
///
/// Each write path calls its hook before a [`Step`]. Without `test-hooks` it
/// is [`NoHooks`], whose hook is a no-op, so the write paths read the same in
/// either build.
#[cfg(not(feature = "test-hooks"))]
pub(crate) type Seam = NoHooks;

/// The seam of a build without `test-hooks`, which has nothing to arm.
///
/// Its hook before a step is nothing. Zero-sized, so the kernel and its
/// appender carry nothing of the seam.
#[cfg(not(feature = "test-hooks"))]
#[derive(Clone, Default)]
pub(crate) struct NoHooks;

#[cfg(not(feature = "test-hooks"))]
impl NoHooks {
    /// Runs the hook before a step, in a build without the seam: the step runs.
    ///
    /// # Errors
    ///
    /// None: the answer is `Ok(())` for every step.
    #[inline]
    pub(crate) fn before(&self, _step: Step) -> std::io::Result<()> {
        Ok(())
    }
}
