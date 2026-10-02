//! §A/§B and the pure half of §C — the slice, the record, the fold, the two
//! point queries, and the composable write step.

use std::fmt;
use std::hash::BuildHasherDefault;

use rustc_hash::FxHasher;
use serde::{Deserialize, Serialize};
use skep_address::{Address, Tumbler};

use crate::error::ContentError;
#[cfg(feature = "content-addr-guard")]
use crate::guard::debug_assert_content_address;
use crate::value::Val;

/// Fixed-seed deterministic build-hasher (§Core data model: keys are trusted
/// internal tumblers, not adversarial input, so flooding-resistance buys
/// nothing). Its stated purpose — reproducible checkpoint serialization
/// across runs — is discharged since 2026-09-23 by the sorting `Serialize`
/// below, which does not read iteration order at all; the alias stays for
/// its cost (a fixed hasher is cheaper than a randomized one) and for the
/// bounds. MUST be `BuildHasher + Default + Clone + Send + Sync + 'static`:
/// the first three so [`ContentStore`]'s `Default`/`Clone`/`Deserialize`
/// derives hold; the last three because `ContentStore` becomes a field of the
/// engine's `W`, and M2's `WorldState` bound requires
/// `Send + Sync + 'static` — a pick missing them surfaces as an opaque
/// compile error in `skep-engine`, far from the decision point. The
/// *specific* hasher is Open build decision #5; this alias is the one place
/// it is named — `BuildHasherDefault<FxHasher>` (rustc-hash), the design's
/// placeholder pick, taken as the default.
type FixedHasher = BuildHasherDefault<FxHasher>;

/// M4's authoritative folded slice: `dom(C) ↦ Val` — the only state M4 owns
/// (§A; §Core data model). The journal of [`ContentWrite`] records (held by
/// M2) is ground truth; this map is its fold, fully serialized in
/// checkpoints (no skip-serialize, so the engine's `rebuild_derived` is
/// identity for M4).
///
/// `im::HashMap`, not `OrdMap`: the query surface is point membership and
/// point value-at, plus ONE enumeration — [`ContentStore::iter`], the walk the
/// daemon's cell-index rebuild makes at open, which reads every entry once
/// and asks no order of them — and no QUERY needs ordered iteration, range,
/// or prefix scans (the allocator's max-under-prefix reads M3's own frontier,
/// never M4 — Conflicts #3), so only `Eq + Hash` is relied on for the READS;
/// the two whole-store readers, the checkpoint and the engine's world dump,
/// take their order from the sort in `Serialize` below.
/// Persistent (`im`) for the commit path: each `transact` produces a *new*
/// `World` and outstanding snapshots pin old ones —
/// [`apply_write`](ContentStore::apply_write) is O(log₃₂ n) and old/new maps
/// share all untouched structure. The `Deserialize` derive requires the `im`
/// crate built with its `serde` feature (set in the workspace's dependency
/// table); `Serialize` is written by hand, below, and is where `Tumbler`'s
/// `Ord` IS used: the checkpoint's bytes must be a function of the contents.
#[derive(Clone, Default, Deserialize)]
pub struct ContentStore {
    map: im::HashMap<Tumbler, Val, FixedHasher>,
}

/// CANONICAL SERIALIZATION (2026-09-23, QUEUE item 10 option (i)): the same
/// serde form the derive produced — a struct with the one field `map`, the
/// map as a map with its length — but its entries emitted in `Tumbler` order
/// rather than in the HAMT's iteration order, which is a function of the
/// hasher crate's version and the platform's word size (`BigUint` hashes its
/// digit vector, whose digit is `u32` on 32-bit and `u64` on 64-bit targets)
/// and not of the contents. So two writes of one store, on two processes or
/// two machines, yield one byte string, and M2's checkpoint header can commit
/// to its body by hash. `Deserialize` is untouched: bincode's map decode is
/// order-agnostic, and the HAMT is rebuilt from the entries whatever order
/// they arrive in. Cost: one O(n log n) sort of the entry set per checkpoint,
/// on top of the O(n) serialization the checkpoint already pays.
///
/// THE FORM IS A FORMAT, read by three collaborators, none with a compiler
/// edge back to this impl. M2's checkpoint hashes it (above), and decodes it
/// from bytes it does not trust — so the map's key and value types stay free
/// of recursion and of sequence elements that decode from zero bytes (M2's
/// hostile-input obligation on `WorldState`, which `Tumbler` and `Val` meet).
/// The engine's `World` lays these bytes down as one slice of its checkpoint
/// layout, so a change to them — a field added or removed, an entry encoded
/// differently — owes the engine's `WORLD_FORMAT` bump; the engine's pin
/// (`each_slice_serializes_the_fields_the_format_count_names`) sees only
/// the top-level field set, `map`, and a change beneath it owes the bump by
/// hand. And the engine's world dump renders the form as M4's authoritative
/// section, where the daemon's per-reader `/dump` keeps or drops each `map`
/// entry by its key's document; a field added here would reach every reader
/// class whole, which
/// `every_entry_at_each_level_of_the_tree_is_reduced_or_kept_by_name`
/// refuses until the engine's filter is given a disposition for it. This
/// crate's suite pins the bytes themselves
/// (`the_slice_serializes_as_its_map_alone_in_tumbler_order`), so a change
/// to them fails here first. A rename of `map` leaves the bytes alone and
/// unhooks the dump filter's path, which ends in that name; only the
/// engine's two pins, which name the field, see it.
impl Serialize for ContentStore {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut store = serializer.serialize_struct("ContentStore", 1)?;
        store.serialize_field("map", &InTumblerOrder(&self.map))?;
        store.end()
    }
}

/// The content map as a serde map in `Tumbler` order — the sorting half of
/// [`ContentStore`]'s `Serialize`, kept apart so the struct's own shape above
/// reads as the derive's.
struct InTumblerOrder<'a>(&'a im::HashMap<Tumbler, Val, FixedHasher>);

impl Serialize for InTumblerOrder<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut entries: Vec<(&Tumbler, &Val)> = self.0.iter().collect();
        entries.sort_unstable_by(|a, b| a.0.cmp(b.0));
        let mut map = serializer.serialize_map(Some(entries.len()))?;
        for (addr, val) in entries {
            map.serialize_entry(addr, val)?;
        }
        map.end()
    }
}

impl ContentStore {
    /// The fold — pure, total, deterministic (M2's `apply` obligation; §A).
    /// Insert only, and never an overwrite when `r` was staged against this
    /// very slice — the caller's half of S0(b), which [`stage_write`]
    /// states. The `debug_assert!` nets that half, and a record folded
    /// twice. In release it is compiled out and the fold stays total and
    /// infallible, so a record that broke the caller's half replaces the
    /// stored value: no type holds that half, and nothing here refuses it.
    /// The engine's `World::apply` dispatches its `Record::Content` variant
    /// here — on live commit and on M2's replay alike. S0(a)/S1/C0 fall
    /// straight out: a record can only add, so `dom(C) ⊆ dom(C')`.
    pub fn apply_write(&self, r: &ContentWrite) -> ContentStore {
        debug_assert!(
            !self.map.contains_key(&r.addr),
            "S0(b): this record's address is already stored in the slice it is folded \
             into — it was staged against another slice, or folded twice"
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
    /// chaining off the temporary won't compile. The design's readers are
    /// RETRIEVEV (M6, ASN-0115) and predicate-def read-back (M9); M5's
    /// publish shot and the daemon read it too.
    ///
    /// What a `None` MEANS depends on where `a` came from, which the caller
    /// knows and M4 does not; M4 promises only that a stored value is in
    /// every later slice (S0). An address an arrangement placed — read off a
    /// V→I resolve against the same `Snapshot` (S3★, kept on M5's write
    /// path) — and a registered predicate-def's start (M9's residence gate
    /// admitted it) always yield `Some`, so a `None` for either is an
    /// internal invariant violation to report or halt on, never a
    /// domain-level "not found". An address a request or an endset names
    /// verbatim carries no such promise — it may be unallocated, a ghost, or
    /// a link — and the caller holding it names its own refusal.
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

    /// THE ONE ENUMERATION of the slice: every `(address, value)` pair it
    /// holds, each exactly once, in the map's own order — a function of the
    /// hasher and the platform's word size, not of the contents (which is why
    /// the checkpoint's `Serialize` above sorts, and this does not). Its one
    /// consumer is the daemon's cell-index rebuild at open, which walks the
    /// world's whole content once over a pinned snapshot, reading every
    /// value's leading bytes and asking no order of them: a sort of the
    /// entry set would cost that walk more than the walk itself at the
    /// scale it exists for, and would buy a determinism no reader of the
    /// index can observe. Over a pinned snapshot the walk is immutable while
    /// commits proceed on later roots (the persistent map's structural
    /// sharing). Exact-size, as the map's own walk is. No range, no prefix
    /// and no ordered form is offered beside it; the reads stay point reads.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = (&Tumbler, &Val)> + '_ {
        self.map.iter()
    }
}

/// M4's sole authoritative journal delta (§A). Carries the FLAT [`Tumbler`]
/// (M1: the Tumbler is the storage/journal key; `Address` is the
/// past-the-door value).
///
/// CONSTRUCTOR-PRIVATE, READ-PUBLIC: the fields are private, so a record has
/// two doors, and no struct literal outside this file builds one.
/// [`stage_write`] stages one past S0(b)'s guard. Serde's `Deserialize` —
/// public, as M2's `Record: DeserializeOwned` bound requires, and able to set
/// the private fields because the derive expands at the definition site — is
/// M2's replay door, decoding records that guard admitted; nothing but review
/// keeps any other caller from decoding a record out of bytes of its own
/// making. Neither door makes a record fresh for the slice it is folded into;
/// [`stage_write`] says whose half that is. Read access is full —
/// [`addr`](ContentWrite::addr)/[`val`](ContentWrite::val) and the manual
/// `Debug`, which is what the engine's `Record: Debug` renders for this
/// variant. The engine only `From`-lifts and folds; it never constructs one.
/// That is the composition-contract checklist's "constructible by upstream
/// producers, readable by downstream consumers" item in full: the one
/// producer (`stage_write`) is public to M5, serde replays at the definition
/// site, and consumers read through the accessors and `Debug`.
#[derive(Clone, Serialize, Deserialize)]
pub struct ContentWrite {
    addr: Tumbler,
    val: Val,
}

impl ContentWrite {
    /// The flat storage/journal key. Read-only.
    pub fn addr(&self) -> &Tumbler {
        &self.addr
    }

    /// The staged payload. Read-only.
    pub fn val(&self) -> &Val {
        &self.val
    }
}

/// Manual, not derived: renders the address by walking its components and
/// the value by BYTE LENGTH only — [`Val`] deliberately carries no `Debug`,
/// so blobs can never leak into diagnostics (and a derive would therefore not
/// compile). Shape: `ContentWrite { addr: [c₁, …, c_#t], val: n bytes }`.
impl fmt::Debug for ContentWrite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ContentWrite {{ addr: [")?;
        for (i, c) in self.addr.iter().enumerate() {
            if i > 0 {
                f.write_str(", ")?;
            }
            write!(f, "{c:?}")?;
        }
        write!(f, "], val: {} bytes }}", self.val.len())
    }
}

/// PURE STEP — the storage half of K.α (§C; M2 contract 3). Reads the slice
/// it is handed and nothing else, returns the record, commits nothing. THIS
/// is M4's real export: M5's placement composite (and, via M5, M9's
/// predicate-def creation) calls it and lifts the result with
/// `stg.push(rec.into())`.
///
/// S0(b) — NO OVERWRITE — has two halves, one each side of this call. THIS
/// function's, the one genuine guard M4 owns:
/// `Err(AlreadyPresent(addr.tumbler()))` if `addr` is stored in `c`. The
/// CALLER's: `c` is the slice the record will be folded into —
/// `stg.working().content()`, read after every `push` — because against one
/// unchanged slice one address stages twice, and the fold, being total,
/// cannot refuse the second. [`ContentWrite`]'s private fields make this the
/// only way to stage a record (serde's `Deserialize` is M2's replay of
/// records already staged), so a record reaches the fold having passed this
/// guard. That it passed against the right slice is the caller's half: M5's
/// `allocate_for_placement` keeps it, no type holds it, and
/// [`ContentStore::apply_write`]'s `debug_assert!` nets it in debug builds.
/// The guard never fires in correct operation (M3 mints fresh; M5 writes
/// once) — it is the cheap correct-the-rare-case insurance over the
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
