//! §A/§B and the pure half of §C — the slice and its serialized form, the
//! record, the fold, the two point queries and the one enumeration, and the
//! composable write step.

use std::fmt;

use serde::{Deserialize, Serialize};
use skep_address::{Address, Tumbler};

use crate::error::ContentError;
use crate::routing::debug_assert_content_address_routing;
use crate::value::Val;

/// M4's authoritative folded slice: `dom(C) ↦ Val` — the only state M4 owns
/// (§A; §Core data model). The journal of [`ContentWrite`] records (held by
/// M2) is ground truth; this map is its fold, fully serialized in
/// checkpoints (no skip-serialize, so the engine's `rebuild_derived` is
/// identity for M4).
///
/// Two INVARIANTS hold of every key, each at a named gate:
///
/// * **T4-valid** (ASN-0093 StoreT4Validity, one premise of SD) — every key
///   is the tumbler of an `Address`. Gates: [`stage_write`], which takes an
///   `Address` on every build, so nothing a build journals or checkpoints
///   holds a key the decode door refuses; and the two decode paths, a
///   record's and a slice's, which re-enter M1's `Address` door (`validate`)
///   for each address, so a journal frame or a checkpoint body carrying any
///   other key is refused, never folded.
/// * **A content-subspace element address** (ASN-0093 C1 and L0 — M4's half
///   of SD, `dom(C) ∩ dom(L) = ∅`). Gate: [`stage_write`], whose caller owes
///   it — M3 mints only such addresses for content, and M5 hands only those
///   to this door — and whose routing assertion checks it in debug builds;
///   release trusts it and stages a violator as given. Both decode paths
///   take it on journal and checkpoint integrity: a release build can journal
///   what its stage door did not check, and a decode that refused it would
///   leave that build unable to replay its own journal.
///
/// Cheap to keep many of: `clone` is O(1), and
/// [`apply_write`](ContentStore::apply_write) returns a new slice in
/// O(log n), sharing all untouched structure with the old one, which stays
/// as it was — so a snapshot pinning an old `World` costs next to nothing.
/// Its serialized form is canonical, a function of the contents alone
/// (`in_tumbler_order` below, the field's emitting half, says who reads it).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContentStore {
    // A persistent ORDERED map — `im::OrdMap`, a B-tree keyed by `Tumbler`'s
    // `Ord` — not `im::HashMap`. The reads are point lookups and the writes
    // single inserts, O(log n) here against the HAMT's O(log₃₂ n), and no
    // query asks the order of it: no range or prefix scan is built on it
    // (the allocator's max-under-prefix reads M3's own frontier, never M4:
    // Conflicts #3), and `ContentStore::iter`, the one enumeration, promises
    // no order. What the order buys is the checkpoint: a whole-store reader
    // that needs every entry in `Tumbler` order at every cadence crossing
    // (the canonical bytes, `in_tumbler_order` below), which the ordered
    // map's walk gives for free where a hash map's would have to be collected
    // and sorted at every checkpoint. Its serde form is this crate's, never
    // `im`'s: `in_tumbler_order` emits it and `entry_by_entry` decodes it,
    // the two named in the attribute below.
    #[serde(serialize_with = "in_tumbler_order", deserialize_with = "entry_by_entry")]
    map: im::OrdMap<Tumbler, Val>,
}

/// The `map` field's serde form, emitted: a serde map with its length, its
/// entries in the map's own walk — `Tumbler` order, the map being ordered by
/// its key's `Ord` — so the bytes are a function of the contents alone, and
/// two writes of one store, on two processes or two machines, yield one byte
/// string that M2's checkpoint header can commit to by hash. Spelled by this
/// crate rather than left to `im`'s own impl, because the form is a FORMAT
/// (below) and what a dependency writes is its choice; the struct around the
/// field is the derive's, as every store slice's is, and the decoding half is
/// [`entry_by_entry`]. Cost: the O(n) walk the checkpoint already pays, and
/// no sort.
///
/// THE FORM IS A FORMAT, read by three collaborators, none with a compiler
/// edge back to this crate. M2's checkpoint hashes it (above), and decodes it
/// from bytes it does not trust — so the map's key and value types stay free
/// of recursion and of sequence elements that decode from zero bytes (M2's
/// hostile-input obligation on `WorldState`, which `Tumbler` and `Val` meet),
/// the map's own declared count is never trusted with a reservation, and a
/// body naming one address twice is refused, so the bytes a hash commits to
/// never leave a decoder a tie to break ([`entry_by_entry`]). The engine's
/// `World` lays these bytes down as one slice of its checkpoint layout, so a
/// change to them — a field added to or removed from [`ContentStore`], an
/// entry encoded differently — owes the engine's `WORLD_FORMAT` bump; the
/// engine's pin (`each_slice_serializes_the_fields_the_format_count_names`)
/// sees only the top-level field set, `map`, and a change beneath it owes the
/// bump by hand.
/// And the engine's world dump renders the form as M4's authoritative
/// section, where the daemon's per-reader `/dump` keeps or drops each `map`
/// entry by its key's document; a field added to [`ContentStore`] would reach
/// every reader class whole, which
/// `every_entry_at_each_level_of_the_tree_is_reduced_or_kept_by_name` refuses
/// until the engine's filter is given a disposition for it. This crate's
/// suite pins the bytes themselves
/// (`the_slice_serializes_as_its_map_alone_in_tumbler_order`), so a change to
/// them fails here first. The field's serialized name is the derive's, its
/// Rust name, which bincode never writes: a rename of `map` leaves the bytes
/// alone and unhooks the dump filter's path, which ends in that name; only
/// the engine's tests that name the field see it.
fn in_tumbler_order<S: serde::Serializer>(
    map: &im::OrdMap<Tumbler, Val>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.collect_map(map.iter())
}

/// The content map decoded one entry at a time — the decoding half of
/// [`ContentStore`]'s serde form, beside [`in_tumbler_order`]. `im`'s own map
/// visitor reserves room for the entry count the bytes declare before it has
/// read one entry, and a checkpoint body is bytes M2 does not trust: a count
/// they do not carry — a writer/reader skew reading another slice's bytes as
/// this length, or a crafted file — makes that reservation panic or abort the
/// process, where M2's load must refuse the base and fall back. Inserting each
/// entry as it arrives reserves nothing the bytes have not carried, so a short
/// body runs out of input and the decode refuses it; each key re-enters M1's
/// `Address` door (`validate`), so a body carrying a key no [`stage_write`]
/// could have staged is refused the same way ([`ContentStore`]'s key
/// invariants); it takes the entries in whatever order they arrive; and it
/// refuses a body naming one address twice. No build writes one — the encoder
/// walks a map whose keys are unique — and admitting one would mean choosing
/// which value stands: `OrdMap::insert` keeps the later, where the fold keeps
/// the one already stored (S0(b)). Refusing it leaves no tie to break, so
/// every body this decode admits names one state, whatever order its entries
/// take. Addresses are compared as decoded, and a component's digits decode
/// to one number however they are spelled, so two spellings of one address
/// are one address. The refusal names no address: a key can be as long as the
/// body that carries it, and M2 keeps a refused base's reason.
///
/// REFUSAL PRECEDENCE — several of these can hold of one body, and the first
/// fault in reading order speaks. Within an entry, the key is read first and
/// refused at M1's `Address` door, then the value, and only then is the key
/// checked against the entries before it; across entries, the earlier
/// entry's fault speaks; and a declared count the body does not carry is no
/// fault of its own — the body is refused where it runs out, after any fault
/// the entries before that point hold. So the reason M2 keeps for a refused
/// base names the earliest fault the body holds.
fn entry_by_entry<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<im::OrdMap<Tumbler, Val>, D::Error> {
    use serde::de::{Error, MapAccess, Visitor};

    struct MapVisitor;

    impl<'de> Visitor<'de> for MapVisitor {
        type Value = im::OrdMap<Tumbler, Val>;

        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a map from content address to value")
        }

        fn visit_map<A: MapAccess<'de>>(self, mut entries: A) -> Result<Self::Value, A::Error> {
            let mut map = im::OrdMap::new();
            while let Some((addr, val)) = entries.next_entry::<Address, Val>()? {
                if map.insert(Tumbler::from(addr), val).is_some() {
                    return Err(Error::custom("a content address named twice in one slice"));
                }
            }
            Ok(map)
        }
    }

    deserializer.deserialize_map(MapVisitor)
}

impl ContentStore {
    /// The fold — pure, deterministic, insert-only (§A), on live commit and
    /// on M2's replay alike (the engine's `World::apply` dispatches its
    /// `Record::Content` variant here). It returns a new slice and leaves the
    /// receiver as it was.
    ///
    /// TOTALITY DOMAIN (M2's total-apply obligation, stated here at the seam
    /// the engine wires): total — deterministic, side-effect-free, panic-free
    /// — over every record whose address is not stored in the receiver, which
    /// is every record [`stage_write`] admitted against this very slice,
    /// folded once. There the result is the receiver's contents with
    /// `r.addr ↦ r.val` added.
    ///
    /// Outside the domain — a record staged against another slice, or folded
    /// twice: a caller's bug, met live or on replaying the journal a release
    /// build wrote past it — a debug build fail-stops on the `debug_assert!`,
    /// and a release build returns a slice equal to the receiver: the STORED
    /// value wins and the record's write is lost. So no record overwrites the
    /// permascroll, inside the domain or out of it, on any build: S0(b), and
    /// with it S0(a)/S1/C0 — `dom(C) ⊆ dom(C')`, and every value in `C` is in
    /// `C'` unchanged.
    #[must_use = "apply_write returns the folded slice; it does not modify the receiver"]
    pub fn apply_write(&self, r: &ContentWrite) -> ContentStore {
        let already_stored = self.map.contains_key(&r.addr);
        debug_assert!(
            !already_stored,
            "S0(b): this record's address is already stored in the slice it is folded \
             into — it was staged against another slice, or folded twice"
        );
        if already_stored {
            // S0(b): the STORED value wins.
            return self.clone();
        }
        ContentStore {
            map: self.map.update(r.addr.clone(), r.val.clone()),
        }
    }

    /// S3 referential-integrity oracle — content-presence: is content STORED
    /// at `a`, `a ∈ dom(C)` (ASN-0036 S3; §B)? Not "allocated" (M3) and not
    /// "registered" (M3): an allocated address with nothing stored is a ghost
    /// element (ASN-0034 T8; ASN-0040 B3), and this answers `false` for it.
    /// M5 calls this on the content side of placement.
    pub fn contains(&self, a: &Tumbler) -> bool {
        self.map.contains_key(a)
    }

    /// `C(a)`: the immutable value at `a`, else `None` (§B). The returned
    /// borrow lives THROUGH the pinning `Snapshot` — bind the snapshot
    /// first (`let s = k.snapshot(); s.world().content().value_at(a)`);
    /// chaining off the temporary won't compile. The design's readers are
    /// RETRIEVEV (M6, ASN-0115) and predicate-def read-back (M9); any holder
    /// of a slice may ask it, and the paragraph below says what its answer
    /// means.
    ///
    /// What a `None` MEANS depends on where `a` came from, which the caller
    /// knows and M4 does not; M4 promises only that a stored value is in
    /// every later slice (S0) — of a world's `content()` as well as of the
    /// fold's own results, by [`HasContent`](crate::HasContent)'s implementor
    /// obligation. An address an arrangement placed — read off a V→I resolve
    /// against the same `Snapshot` (S3★, kept on M5's write path) — and a
    /// registered predicate-def's start (M9's residence gate admitted it)
    /// always yield `Some`, so a `None` for either is an internal invariant
    /// violation to report or halt on, never a domain-level "not found". An
    /// address a request or an endset names verbatim carries no such promise
    /// — it may be unallocated, a ghost element, or a link — and the caller
    /// holding it decides what that absence means to it: a refusal of its
    /// own, an absence it reports, or an address it passes over.
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
    /// holds, each exactly once — the whole of its promise. Exact-size, as
    /// the map's own walk is; `&ContentStore` yields the same [`Iter`], so a
    /// `for` loop over `&store` reads it too. Its ORDER is no part of the
    /// promise: the order the checkpoint's bytes need is the serializer's to
    /// keep (`in_tumbler_order` above, which walks the map itself), and a
    /// reader that wants an order sorts what it reads. Every address it
    /// yields is the tumbler of a T4-valid `Address` ([`ContentStore`]'s
    /// first key invariant, kept at every door), so validating one back into
    /// an `Address` cannot fail.
    ///
    /// A walk of the whole store, for whole-store work over a pinned
    /// snapshot such as the cell index's walk (`skep-media`); there it stays
    /// immutable while commits proceed on later roots (the persistent map's
    /// structural sharing). A request path asks the point reads; no range and
    /// no prefix read is offered beside this one.
    pub fn iter(&self) -> Iter<'_> {
        Iter(self.map.iter())
    }
}

/// Every `(address, value)` pair of one slice, each once — what
/// [`ContentStore::iter`] lends and what `&ContentStore` yields to a `for`
/// loop. Opaque, as M1's `Spans` and M5's `Runs` are, so the persistent map
/// behind the slice stays this crate's own choice.
///
/// Opacity hides the container, never what the walk promises: the exact
/// length is forwarded below. The reverse walk is withheld, though `im`'s map
/// iterator has one: the order is no part of the promise
/// ([`ContentStore::iter`]), and a walk from the far end would promise one.
/// `Clone` and the fused guarantee are absent because `im`'s map iterator
/// implements neither: a caller wanting two cursors asks the slice for two,
/// and one that polls past the end wraps the walk in `fuse()`.
#[must_use = "iterators are lazy and do nothing unless consumed"]
pub struct Iter<'a>(im::ordmap::Iter<'a, Tumbler, Val>);

impl<'a> Iterator for Iter<'a> {
    type Item = (&'a Tumbler, &'a Val);
    fn next(&mut self) -> Option<(&'a Tumbler, &'a Val)> {
        self.0.next()
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.0.size_hint()
    }
}

impl ExactSizeIterator for Iter<'_> {
    fn len(&self) -> usize {
        self.0.len()
    }
}

/// The cursor, not the entries: `im`'s map iterator is not `Debug`, so there
/// is no way to show what is left without spending it, and the slice it was
/// lent from is `Debug` already.
impl fmt::Debug for Iter<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Iter").finish_non_exhaustive()
    }
}

impl<'a> IntoIterator for &'a ContentStore {
    type Item = (&'a Tumbler, &'a Val);
    type IntoIter = Iter<'a>;
    fn into_iter(self) -> Iter<'a> {
        self.iter()
    }
}

/// M4's sole authoritative journal delta (§A). Carries the FLAT [`Tumbler`]
/// (M1: the flat tumbler is the storage/journal key form; an `Address` is a
/// tumbler admitted through M1's `Address` door, `validate`).
///
/// Its fields are private, so [`stage_write`] is its one producer; serde's
/// `Deserialize` — public, as M2's `Record: DeserializeOwned` bound requires —
/// is M2's replay of records already staged. That decode takes `addr`
/// through M1's `Address` door (`through_address`), so a replayed record's
/// key is T4-valid as a staged one's is ([`ContentStore`]'s key invariants).
/// It reads the address before the value, so a frame whose address and value
/// both fail is refused for its address, and that is the account M2's
/// `Corruption` carries for the frame. Read access is full:
/// [`addr`](ContentWrite::addr)/[`val`](ContentWrite::val), and its derived
/// `Debug`, which the engine's `Record: Debug` renders for this variant and
/// which shows the value as its length, never a byte. The engine only
/// `From`-lifts and folds a record; it never builds one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContentWrite {
    #[serde(deserialize_with = "through_address")]
    addr: Tumbler,
    val: Val,
}

impl ContentWrite {
    /// The flat storage/journal key — the tumbler of an `Address`, whether
    /// the record was staged or decoded. Read-only.
    pub fn addr(&self) -> &Tumbler {
        &self.addr
    }

    /// The value the record writes at [`addr`](ContentWrite::addr). Read-only.
    pub fn val(&self) -> &Val {
        &self.val
    }
}

/// A record's address decoded through M1's `Address` door — `validate`, so
/// T4, [`ContentStore`]'s first key invariant — and kept as its flat tumbler.
/// An `Address` journals as its bare tumbler, so this reads exactly the bytes
/// the record's `Serialize` writes, and refuses an address no [`stage_write`]
/// could have staged.
fn through_address<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Tumbler, D::Error> {
    Address::deserialize(deserializer).map(Tumbler::from)
}

/// PURE STEP — the storage half of K.α (§C; M2 contract 3). Reads the slice
/// it is handed and nothing else, returns the record, commits nothing. THIS
/// is M4's real export: M5's placement composite (and, via M5, M9's
/// predicate-def creation) calls it and lifts the result with
/// `stg.push(rec.into())`.
///
/// Refuses a second write at one address: `Err(AlreadyStored(addr.tumbler()))`
/// if `addr` is stored in `c`. M3 mints fresh and M5 writes once, so this
/// never fires in correct operation; when an upstream bug does hand it an
/// address already stored, the caller gets a typed rejection to refuse its
/// transaction with, instead of a write the fold would silently drop, leaving
/// the caller with an address that holds another write's value. It sees only
/// `c`, so hand it the slice the record will be folded into —
/// `stg.working().content()`, read after every `push`; staged against an
/// older slice, a second write at one address gets through and the fold keeps
/// the stored value (a debug build panics there). Otherwise the address is
/// TRUSTED: minted and validated upstream (M3), T4-valid by M1's standing
/// invariant.
///
/// In debug builds a routing assertion (`level == Element ∧ subspace ==
/// s_C`; Open build decision #4) runs BEFORE the already-stored check, so a
/// mis-routed address panics on its own terms — at the caller's line, this
/// function being `#[track_caller]` — never masked by a value that happens
/// to be stored there; release compiles it out. The routing is the caller's
/// to guarantee — M3's mint, M5's routing — and is [`ContentStore`]'s second
/// key invariant: a release build stages a mis-routed address as given.
#[track_caller]
pub fn stage_write(
    c: &ContentStore,
    addr: &Address,
    val: Val,
) -> Result<ContentWrite, ContentError> {
    debug_assert_content_address_routing(addr, "stage_write");
    if c.contains(addr.tumbler()) {
        return Err(ContentError::AlreadyStored(addr.tumbler().clone()));
    }
    Ok(ContentWrite {
        addr: addr.tumbler().clone(),
        val,
    })
}
