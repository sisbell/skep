//! # skep-kernel — M2: Transaction, Journal & Concurrency Kernel
//!
//! The engine's **generic transactional substrate**: every state change becomes
//! one atomic, totally-ordered, durable, recoverable step (or a composite
//! committed as one); committed state is served as consistent snapshots;
//! writers are serialized — while M2 knows nothing about what any change
//! *means*. It is a WAL + atomic-install + keyed-serialization + snapshot
//! kernel, dependency-inverted: M2 defines the fold ([`WorldState::apply`]),
//! the engine implements it, and M2 only calls down through that trait.
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
//! one commit ordering is **durable-before-visible** (§1): append records →
//! append commit marker → one records+marker fsync → atomic root install →
//! return. The `transact`/`snapshot` signatures and the `LockKey` seam are
//! invariant across the deferred per-key/CAS realizations.
//!
//! ## Boundary — deliberately NOT owned here
//!
//! * address, frontier, or coverage-class computation (M1/M3/M7 — keys and
//!   payloads are opaque; [`LockKey`] order is bytewise, never tumbler order);
//! * store permanence P0–P3/L12 and the J-couplings J0/J1★ (the stores enforce
//!   them at their composite boundaries *through* M2, never by it);
//! * record semantics — payloads are the engine's `W::Record`, folded blindly;
//! * the request lifecycle, dispatch, and acknowledgment-to-client (M10 — M2
//!   keeps only the commit-gate *mechanism*: return after durable install);
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
//! [`LockKey::new`] — M3's `skep-namespace` constructors (`content_lock_key`,
//! `link_lock_key`, `version_lock_key`, `document_lock_key`,
//! `principals_lock_key`, `nodes_lock_key`) are the ones every other store's
//! writes go through.
//!
//! ## Example
//!
//! ```no_run
//! use serde::{Deserialize, Serialize};
//! use skep_kernel::{
//!     BurnedSeqPolicy, CheckpointPolicy, Durability, Kernel, KernelConfig, WorldState,
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
//!     },
//!     checkpoint: CheckpointPolicy::EveryN(1024),
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

mod checkpoint;
mod config;
mod error;
mod journal;
mod kernel;
mod replay;

pub use config::{BurnedSeqPolicy, CheckpointPolicy, Durability, KernelConfig};
pub use error::{CheckpointError, HistoryError, OpenError, TxnError};
pub use journal::MAX_TXN_BYTES;
pub use kernel::{Kernel, Snapshot, Staging};

use std::fmt;

use serde::de::DeserializeOwned;
use serde::Serialize;

/// The engine's contract to M2 (dependency-inverted): the engine composes all
/// store slices into one `World`, implements this trait for it, and
/// instantiates [`Kernel<World>`]. M2 never names the concrete world — it only
/// calls down through this trait (Engine Composition Contract).
///
/// COST OF `Clone` — M2 clones `W` once per [`Kernel::transact`], BEFORE the
/// closure runs and therefore for rejected and zero-step transactions too, and
/// it does so while holding the applier lock, so the clone is on the critical
/// section every other writer in the process waits behind. `Clone` must
/// therefore be cheap: the design's structurally-shared store slices are a
/// requirement of this path, and a slice that moves to an eagerly-copied
/// collection makes every transaction in the system — read-only ones included
/// — `O(|world|)` under a global lock, which M2 has no way to report.
///
/// DROP OBLIGATION — `W`'s destructor MUST NOT unwind. M2 drops the previous
/// root inside the atomic install, so a panicking `Drop` unwinds from a point
/// the in-memory journal reports as a pre-install unwind — which would roll
/// the `Seq` order back below a root that is already installed, and
/// [`Kernel::current_seq`] would regress, which its own contract says it never
/// does. M2 cannot check this.
///
/// HOSTILE-INPUT OBLIGATION — `W` is decoded from a checkpoint body, which is
/// bytes M2 does not trust: the header checksum proves they are the bytes that
/// were written, and nothing about whether decoding them is safe. So this
/// type's `Deserialize` must terminate and must not exhaust the stack on any
/// byte string. The same obligation binds [`Record`], and is written out in
/// full there. M2 cannot check this.
///
/// [`Record`]: WorldState::Record
pub trait WorldState: Clone + Serialize + DeserializeOwned + Send + Sync + 'static {
    /// The engine's central record enum — the union of every store's own
    /// record type. Opaque to M2: journaled as bytes, folded via [`apply`].
    ///
    /// ROUND-TRIP OBLIGATION — a record is journaled as bytes and replayed by
    /// decoding those bytes, so [`apply`] must have the same effect on the
    /// decoded record as on the one that was staged: this type's serde must
    /// round-trip everything [`apply`] reads. A `#[serde(skip)]`ped field, a
    /// `#[serde(default)]` whose default differs from what was written, or a
    /// `Serialize` that normalizes, each make replay fold a DIFFERENT record
    /// than the live commit folded — so the recovered world differs from the
    /// acknowledged one by exactly that difference, silently, and
    /// [`Kernel::world_at`] answers a world [`Kernel::snapshot`] never held.
    /// Nothing a record carries that [`apply`] does not read need survive the
    /// round trip. M2 cannot check this.
    ///
    /// HOSTILE-INPUT OBLIGATION — M2 decodes this type from bytes it does not
    /// trust: a journal frame is validated by a CRC, which proves the bytes are
    /// the ones that were written and nothing about whether decoding them is
    /// safe. So this type's `Deserialize` must terminate and must not exhaust
    /// the stack on any byte string. Two shapes break that, and NEITHER is
    /// caught here: a recursive type has no depth limit under this journal's
    /// codec, and a stack overflow ABORTS rather than unwinding — no error, no
    /// [`crate::OpenError::Corruption`], and [`Kernel::open`] does not return;
    /// and a sequence whose element consumes no bytes turns a length prefix
    /// into an unbounded loop. Bound recursion depth where a value is
    /// ADMITTED, not where it is decoded — by then the bytes have already been
    /// accepted. M2 cannot check this.
    ///
    /// [`apply`]: WorldState::apply
    type Record: Serialize + DeserializeOwned + Send + Sync + 'static;

    /// The ONE deterministic, total, side-effect-free fold step — drives both
    /// live commit and replay (ASN-0134 A6: every journal prefix up to a
    /// committed marker is a canonical reachable state). Folds authoritative
    /// deltas AND maintains every derived hint incrementally; a hint NOT
    /// folded here is stale after every live write and after replay
    /// ([`rebuild_derived`] runs only at load). Deterministic so replay
    /// reproduces committed state exactly — together with [`Record`]'s
    /// round-trip obligation, which is what makes the record replay hands
    /// this method the record that was staged. NOT required to be idempotent
    /// — recovery applies each committed record exactly once (the checkpoint
    /// embodies `Seq ≤ S_load`, replay covers `S_load < Seq ≤ W`; §6/§7).
    ///
    /// WHERE IT RUNS — once per [`Staging::push`], inside the
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

    /// Seed derived hints from authoritative state. Runs ONCE per journaled
    /// load — on whichever base recovery selects, a retained checkpoint or
    /// genesis — BEFORE replay, and NEVER on a live commit, so it cannot keep
    /// any hint current by itself. It exists solely to reconstruct hints a
    /// checkpoint skip-serialized (`#[serde(skip)]`). NOT run under
    /// [`Durability::InMemory`], which does not load: that mode installs the
    /// caller's `genesis` value as the root exactly as given. Default
    /// identity; override iff hints are skipped.
    ///
    /// CONSISTENCY OBLIGATION (§7, seam contract 2): an override MUST seed
    /// exactly the hint state that folding every record with `Seq ≤ S` through
    /// [`apply`] would produce (`S` = the seq of the base selected — a
    /// retained checkpoint's, or `0` for genesis). Recovery runs
    /// `rebuild_derived` (seeding `Seq ≤ S`) THEN replays `Seq > S`
    /// through `apply`; if the seed disagrees with the `apply`-fold it stands
    /// in for, the recovered hint diverges from the live-maintained one and
    /// reads go wrong. M2 cannot check this.
    ///
    /// WHAT MAY BE SKIPPED (§6/§7): a checkpoint is a serialized `W` standing
    /// in for the fold over `Seq ≤ S`, so ONLY state this method can
    /// reconstruct may be `#[serde(skip)]`ped. Authoritative state must
    /// survive the serde round trip: [`Kernel::world_at`] promises the same
    /// world at a boundary whichever base carries it, and a skipped
    /// authoritative field makes a checkpoint-based derivation differ from a
    /// genesis-based one by exactly that field, silently. A world that skips
    /// nothing needs no override at all, which is why the default is identity.
    /// M2 cannot check this either.
    ///
    /// GENESIS OBLIGATION — the `genesis` handed to [`Kernel::open`] MUST
    /// arrive with its derived hints already consistent with its own
    /// authoritative state, because [`Durability::InMemory`] installs it
    /// unseeded while a journaled `open()` seeds it through this method. A
    /// world that relies on that seeding is right in one mode and wrong in the
    /// other, silently, and both modes answer the same coordinate — `Seq(0)` —
    /// with different hints. M2 cannot check this.
    ///
    /// [`apply`]: WorldState::apply
    fn rebuild_derived(self) -> Self {
        self
    }
}

/// M2's per-record linearization coordinate (ASN-0134 A1/A2 — the assignment
/// of a record's `Seq` under the applier lock is its linearization point).
/// Monotone always; gap-free under [`BurnedSeqPolicy::Rollback`] (the
/// default), monotone-only under [`BurnedSeqPolicy::TolerateGap`]
/// (§1/§3/Invariants). `Copy`, so [`Snapshot::seq`]/[`Kernel::current_seq`]
/// return it by value.
///
/// A REFINEMENT of ASN-0134's `𝔼`, not an identity (§2): non-`→_sh` records
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
    /// The bare coordinate, as every error message that names one spells it.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Opaque serialization key — the documented serialization seam M3/M7 code
/// against (MIC clauses 2/5/7). M2 only `Eq`/`Hash`/`Ord`-s the bytes (`Ord`
/// is bytewise, NOT tumbler order). A key is built by [`LockKey::new`] from a
/// [`Space`] and the caller's own bytes, so the 1-byte space tag every key
/// carries is prefixed in one place and distinct key spaces (e.g.
/// `(home, subspace)` vs coverage-class) never collide.
///
/// Under the v1 single applier the global applier lock subsumes the keys
/// (§4/§8) — they are the seam, not a live lock table — so the deferred
/// per-key realization slots in without changing any caller's call shape.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct LockKey(Vec<u8>);

impl LockKey {
    /// A key in `space`, over the caller's own opaque bytes. The 1-byte tag is
    /// prefixed HERE, so no store can forget it or choose one locally — which
    /// is what makes the cross-store uniqueness [`Space`] promises structural
    /// rather than a convention each store re-keeps.
    pub fn new(space: Space, bytes: &[u8]) -> LockKey {
        let mut key = Vec::with_capacity(1 + bytes.len());
        key.push(space.tag());
        key.extend_from_slice(bytes);
        LockKey(key)
    }
}

/// The SINGLE CENTRAL lock-key space-tag enum (§4, §Dependencies & seams;
/// Engine Composition Contract). It names only 1-byte constants — no store
/// types — so it sits BELOW every store; were it in the engine crate (which
/// depends on every store) each store would need an edge to the engine: a
/// compile-time crate cycle. Tags are never chosen per-store, which is what
/// guarantees CROSS-STORE uniqueness: without it two stores could both pick
/// `0x01` and silently alias M3's `(home,subspace)` keys with M7's
/// `class_key`s.
///
/// Dormant under the v1 single applier (the global lock subsumes all keys —
/// §4/§8); load-bearing under the deferred per-key realization.
#[non_exhaustive]
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Space {
    /// `(home, subspace)` namespace/frontier keys — entity allocation (M3),
    /// content writes (M4), placement (M5), link allocation (M7): byte-equal
    /// by construction because every one of them is built by M3's
    /// `*_lock_key` constructors over one encoding, so they serialize against
    /// each other (MIC clause 2 / H0 discipline).
    Namespace = 0x01,
    /// Coverage-class keys — M7's idem=⊤ dedup critical sections (MIC clause
    /// 7 / G2: read-decide-deposit is one action under this key).
    CoverageClass = 0x02,
    /// THE principal registry — M3's single global `principals_lock_key`,
    /// which serializes delegation's id-freshness read; that race is
    /// CROSS-namespace, so it cannot ride on a namespace key.
    Principals = 0x03,
    /// THE node registry — M3's single global `nodes_lock_key`, which keeps a
    /// concurrent duplicate `RegisterNode` a typed rejection rather than a
    /// silent coalesce.
    Nodes = 0x04,
}

impl Space {
    /// The 1-byte tag this space's keys carry, which [`LockKey::new`] writes.
    /// Public so the assignment is inspectable — the uniqueness the enum
    /// exists for is a claim about these bytes.
    pub const fn tag(self) -> u8 {
        self as u8
    }
}
