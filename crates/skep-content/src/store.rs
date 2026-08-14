//! §A/§B and the pure half of §C — the slice, the record, the fold, the two
//! point queries, and the composable write step.

use std::fmt;
use std::hash::BuildHasherDefault;

use rustc_hash::FxHasher;
use serde::{Deserialize, Serialize};
use skep_address::{Address, Tumbler};

#[cfg(feature = "content-addr-guard")]
use skep_address::{Level, Nat};

use crate::error::ContentError;
use crate::value::Val;

/// Fixed-seed deterministic build-hasher → reproducible checkpoint
/// serialization across runs (§Core data model: keys are trusted internal
/// tumblers, not adversarial input, so flooding-resistance buys nothing).
/// MUST be `BuildHasher + Default + Clone + Send + Sync + 'static`: the
/// first three so [`ContentStore`]'s `Default`/`Clone`/`Deserialize` derives
/// hold; the last three because `ContentStore` becomes a field of the
/// engine's `W`, and M2's `WorldState` bound requires
/// `Send + Sync + 'static` — a pick missing them surfaces as an opaque
/// compile error in `skep-engine`, far from the decision point. The
/// *specific* hasher is Open build decision #5; this alias is the one place
/// it is named — `BuildHasherDefault<FxHasher>` (rustc-hash), the design's
/// placeholder pick, taken as the default.
type FixedHasher = BuildHasherDefault<FxHasher>;

/// Content-subspace numeral — ASN-0093's SubspaceConventionAxiom fixes
/// `s_C = 1`, matching M1's documented `subspace()` convention (1 = text,
/// 2 = link). Defined HERE, M4-locally, cfg-gated with its only consumer
/// (Open build decision #4's routing guard): the feature is M4-local and off
/// by default, so a debug-only assertion warrants no shared-crate export,
/// and the axiom-pinned value cannot drift. `Nat` (`BigUint`) has no const
/// constructor, hence a lazy static, not a `const`. NOT the kernel-side
/// LockKey space-tag — different constant, different layer (§Dependencies &
/// seams).
#[cfg(feature = "content-addr-guard")]
pub(crate) static S_C_SUBSPACE: std::sync::LazyLock<Nat> =
    std::sync::LazyLock::new(|| Nat::from(1u32));

/// The one routing guard behind Open build decision #4, shared by its two
/// doors ([`stage_write`] and the standalone `write`): asserts
/// `level == Element ∧ subspace == s_C`. Debug-assert sub-choice (the
/// design's recommendation): fatal in debug builds, free in release.
#[cfg(feature = "content-addr-guard")]
pub(crate) fn debug_assert_content_address(addr: &Address, site: &str) {
    debug_assert!(
        addr.level() == Level::Element && addr.subspace() == Some(S_C_SUBSPACE.clone()),
        "content-addr-guard: {site}: not a content-subspace element address \
         (level == Element ∧ subspace == s_C = 1 required)"
    );
}

/// M4's authoritative folded slice: `dom(C) ↦ Val` — the only state M4 owns
/// (§A; §Core data model). The journal of [`ContentWrite`] records (held by
/// M2) is ground truth; this map is its fold, fully serialized in
/// checkpoints (no skip-serialize, so the engine's `rebuild_derived` is
/// identity for M4).
///
/// `im::HashMap`, not `OrdMap`: the entire query surface is point membership
/// and point value-at — nobody needs ordered iteration, range, or prefix
/// scans (the allocator's max-under-prefix reads M3's own frontier, never
/// M4 — Conflicts #3), so `Tumbler`'s `Ord` is deliberately unused; only
/// `Eq + Hash` is relied on. Persistent (`im`) for the commit path: each
/// `transact` produces a *new* `World` and outstanding snapshots pin old
/// ones — [`apply_write`](ContentStore::apply_write) is O(log₃₂ n) and
/// old/new maps share all untouched structure. The `Serialize`/`Deserialize`
/// derive requires the `im` crate built with its `serde` feature (an
/// M4-local dependency knob).
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct ContentStore {
    map: im::HashMap<Tumbler, Val, FixedHasher>,
}

impl ContentStore {
    /// The fold — pure, total, deterministic (M2's `apply` obligation; §A).
    /// Insert only: [`stage_write`] guarantees `r.addr ∉ dom(C)`, so this
    /// never overwrites a live value; the `debug_assert!` is a release-free
    /// second net behind that guard (the fold stays total/infallible in
    /// release). The engine's `World::apply` dispatches its
    /// `Record::Content` variant here — on live commit and on M2's replay
    /// alike. S0(a)/S1/C0 fall straight out: a record can only add, so
    /// `dom(C) ⊆ dom(C')`.
    pub fn apply_write(&self, r: &ContentWrite) -> ContentStore {
        debug_assert!(
            !self.map.contains_key(&r.addr),
            "S0(b): apply_write must not overwrite — stage_write guards this"
        );
        ContentStore {
            map: self.map.update(r.addr.clone(), r.val.clone()),
        }
    }

    /// S3 referential-integrity oracle: `a ∈ dom(C)` (ASN-0036 S3; §B).
    /// CONTENT-PRESENCE — not "allocated" (M3) and not "registered" (M3): a
    /// content address can be allocated yet content-absent (a ghost); this
    /// reports presence only. M5 calls this on the content side of
    /// placement.
    pub fn contains(&self, a: &Tumbler) -> bool {
        self.map.contains_key(a)
    }

    /// `C(a)`: the immutable value at `a`, else `None` (§B). The returned
    /// borrow lives THROUGH the pinning `Snapshot` — bind the snapshot
    /// first (`let s = k.snapshot(); s.world().content().value_at(a)`);
    /// chaining off the temporary won't compile. RETRIEVEV (M6, ASN-0115)
    /// and predicate-def read-back (M9) call this.
    ///
    /// `None` CONTRACT for those callers: under S3 plus single-snapshot
    /// consistency, an I-address obtained from a successful V→I resolve
    /// against the SAME `Snapshot` always yields `Some` — a `None` there is
    /// an internal invariant violation (report/halt), never a domain-level
    /// "not found"; do not invent a user-visible not-found semantics from
    /// it.
    pub fn value_at(&self, a: &Tumbler) -> Option<&Val> {
        self.map.get(a)
    }

    /// `|dom(C)|` — diagnostics only (§B).
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// `dom(C) = ∅` — diagnostics only (§B).
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

/// M4's sole authoritative journal delta (§A). Carries the FLAT [`Tumbler`]
/// (M1: the Tumbler is the storage/journal key; `Address` is the
/// past-the-door value).
///
/// CONSTRUCTOR-PRIVATE, READ-PUBLIC: the fields are private so
/// [`stage_write`] is the compiler-enforced sole constructor — no caller can
/// hand-build a record into the total fold and skip the AlreadyPresent
/// guard — while [`addr`](ContentWrite::addr)/[`val`](ContentWrite::val)
/// and the manual `Debug` give full read access (the S0(b) guard needs
/// constructor privacy only, not read privacy). Serde deserializes the
/// private fields for M2's replay (the derive expands at the definition
/// site); the engine only `From`-lifts and folds — it never constructs one
/// from scratch. This satisfies the composition-contract checklist's
/// "constructible by upstream producers, readable by downstream consumers"
/// item in full: the one sanctioned producer (`stage_write`) is public to
/// M5, serde replays at the definition site, and downstream consumers —
/// including engine-side journal-inspection/diagnostic tooling — read
/// records through the public accessors and `Debug`.
#[derive(Clone, Serialize, Deserialize)]
pub struct ContentWrite {
    addr: Tumbler,
    val: Val,
}

impl ContentWrite {
    /// The flat storage/journal key. Read-only; the sole constructor stays
    /// [`stage_write`].
    pub fn addr(&self) -> &Tumbler {
        &self.addr
    }

    /// The staged payload. Read-only; the sole constructor stays
    /// [`stage_write`].
    pub fn val(&self) -> &Val {
        &self.val
    }
}

/// Manual, not derived: renders the address by its components (via
/// [`Tumbler::len`]/[`Tumbler::get`]) and the value by BYTE LENGTH only —
/// [`Val`] deliberately carries no `Debug`, so blobs can never leak into
/// diagnostics (and a derive would therefore not compile). Shape:
/// `ContentWrite { addr: [c₁, …, c_#t], val: n bytes }`.
impl fmt::Debug for ContentWrite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ContentWrite {{ addr: [")?;
        for i in 1..=self.addr.len() {
            if i > 1 {
                f.write_str(", ")?;
            }
            write!(f, "{:?}", self.addr.get(i))?;
        }
        write!(f, "], val: {} bytes }}", self.val.len())
    }
}

/// PURE STEP — the storage half of K.α (§C; M2 contract 3). Reads off a
/// supplied working slice, returns the record, commits nothing. THIS is
/// M4's real export: M5's placement composite (and, via M5, M9's
/// predicate-def creation) calls it against `stg.working().content()` and
/// lifts the result with `stg.push(rec.into())`.
///
/// Enforces S0's no-overwrite — the *one* genuine guard M4 owns:
/// `Err(AlreadyPresent(addr.tumbler()))` if `addr ∈ dom(C)`. The fold is
/// total and cannot reject, and [`ContentWrite`]'s private fields make this
/// the compiler-enforced sole constructor of the record, so the guard has
/// no bypass. It never fires in correct operation (M3 mints fresh; M5
/// writes once) — it is the cheap correct-the-rare-case insurance over the
/// permascroll. Otherwise the address is TRUSTED: minted and validated
/// upstream (M3), T4-valid by M1's standing invariant.
///
/// With the `content-addr-guard` feature on (Open build decision #4), a
/// routing check (`level == Element ∧ subspace == s_C`) runs BEFORE the
/// overwrite check, so a mis-routed address is rejected on its own terms,
/// never masked by a coincidental occupancy; under the recommended
/// debug-assert sub-choice taken here it panics in debug builds and costs
/// nothing in release.
pub fn stage_write(
    c: &ContentStore,
    addr: &Address,
    val: Val,
) -> Result<ContentWrite, ContentError> {
    #[cfg(feature = "content-addr-guard")]
    debug_assert_content_address(addr, "stage_write");
    if c.contains(addr.tumbler()) {
        return Err(ContentError::AlreadyPresent(addr.tumbler().clone()));
    }
    Ok(ContentWrite {
        addr: addr.tumbler().clone(),
        val,
    })
}
