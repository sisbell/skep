//! M3's slice (§Core data model, §1): [`M3State`], genesis and the fold.
//!
//! The module holds [`M3State`] itself, and the `published` a non-document
//! record carries; the two registry caps; the fixed addresses genesis
//! builds — Σ₀'s bootstrap root and the system-account seed (PUB-6.65),
//! whose doc 1 (`ghost_home_document`) is `crate::ghost`'s — with genesis and
//! the fold (§D); and the frontier arithmetic the fold checks and the mints
//! draw on (§1). The records the fold consumes, and the identity type they
//! name, are `crate::record`'s; namespace keys are `crate::ns`'s, and the
//! ghost floor is `crate::ghost`'s.
//!
//! Beneath it, two children, each an `impl M3State` that sees this module's
//! private items the way a child does, so nothing here is widened for them:
//!
//! * [`mint`] — §A: the lock keys a transaction holds, the six mints, and
//!   the two peeks, each a mint without its record.
//! * [`query`] — §C: every other query but the opening slots, which `ns`
//!   builds — entity membership (§2), the two chain-end reads that read a
//!   frontier directly, the publication reads, the principal registry and
//!   the ω resolver (§5), and `prefix_contains`.
//!
//! The unit tests for the slice and both children are `state/tests.rs`.

// §A: the lock keys a transaction holds, the six mints, the two peeks.
mod mint;
// §C: every other query but the opening slots, which `ns` builds —
// membership, two chain-end reads, the publication reads, the principal
// registry and ω.
mod query;

pub use query::prefix_contains;

use std::sync::LazyLock;

use num_traits::Zero;
use serde::{Deserialize, Serialize};
use skep_address::{link_subspace, ordinal, validate, Address, GateViolation, Level, Nat, Tumbler};
use skep_kernel::Seq;

use crate::ghost::{ghost_floor, ghost_home_document};
use crate::ns::{is_content_or_link_slot, namespace_of, nth_in, NsKey};
use crate::record::{
    Allocation, M3Rec, Principal, PrincipalId, RangeAllocation, BOOTSTRAP_PRINCIPAL,
    SYSTEM_PRINCIPAL,
};

/// The `published` an `Allocate` carries outside the document tier.
///
/// There — an account, a content or link element — publication is not a
/// property of the address at all (PUB-1.68: one bit per document, and
/// nothing else carries one). [`M3State::apply_m3`] reads the bit only for a
/// Document-tier address, so this value is never consulted; it is named so
/// the three single non-document mints, and genesis's account record, say
/// what they stamp and why, and so a reader of a journal frame knows the
/// `false` on an account or element `Allocate` is an absence and not a
/// verdict.
const NO_PUBLICATION_STATE: bool = false;

/// M3's slice of the engine's `WorldState`, reached via [`crate::HasM3::m3`].
///
/// All persistent (`im`), so each commit yields a cheap structurally-shared
/// version — free MVCC snapshots for readers and free historical ω_Σ.
///
/// **The journal is the sole authority** (M2); these five structures are the
/// *recovered working representation*, folded by [`M3State::apply_m3`]. All
/// five are ordinary `Serialize`/`Deserialize` fields — **none** is
/// `#[serde(skip)]` — so they are restored verbatim from the loaded checkpoint
/// and then advanced by replaying the post-checkpoint `M3Rec`s. They are
/// authoritative working state, not derived hints, so M3 takes M2's **default
/// `rebuild_derived`** (identity): nothing to re-seed before replay.
///
/// Authoritative vs hint: `frontiers`/`nodes`/`principals`/`publication`/
/// `minted_at` are authoritative (the compressed allocation journal, the
/// per-document publication map beside it, and the commit position of every
/// document, member and link minted). The delegation forest, any
/// `address → owner` ω-cache, any `id → prefix` reverse index, and the
/// exception set over `publication` are *hints* — recomputable from the
/// authoritative fields alone — and are deliberately not stored here (Open
/// build decisions: defaults taken; the exception set is the engine's derived
/// membership index, PUB-7.5).
///
/// The `Serialize` impl targets bincode-class formats, M2's checkpoint
/// encoding: `frontiers` is keyed by a struct, which formats requiring string
/// keys (JSON among them) refuse. The bytes are canonical: every field is an
/// ordered collection, so two slices holding the same entries encode to one
/// byte string on any process and any machine — which is what lets M2's
/// checkpoint header commit to its body by hash. Field order is the
/// compatibility surface (bincode carries no names): a field is appended,
/// never inserted, so an older encoding decodes its prefix, and where the
/// slice ends the bytes it fails at the field it lacks rather than
/// mis-reading one field as another. In the engine's world more slices
/// follow this one, so there the field it lacks would read the next slice's
/// bytes, which the world's leading format stamp exists to prevent.
///
/// Equality is structural, and it is the meaning of the type: two slices are
/// equal iff their three registries, the publication map and the position map
/// hold the same entries. So a slice recovered from a checkpoint is comparable
/// to the one it was taken from — the whole claim recovery makes — without
/// going through a rendering. There is no [`Default`]: [`M3State::genesis`]
/// is not an empty value (it seeds `[1]` into `nodes` and Π), and an empty
/// one would be a world with no bootstrap principal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct M3State {
    /// The baptismal registry (ASN-0040 B), in B1+B2 compressed form.
    ///
    /// A namespace's entire realized set `{c₁..cₘ}` *is* the single count `m` —
    /// a gap is literally unrepresentable (B1 free). Covers every chain:
    /// accounts, documents, versions, content, links. Values are big-ints (B9
    /// unbounded). Mint and membership are *point* lookups on one namespace
    /// and namespaces are never iterated, so no read pays for order; the map
    /// is an `OrdMap` all the same, because the order is written: the
    /// checkpoint's bytes are a function of the contents, and a published head
    /// can name a checkpoint by hash, where an `im::HashMap`'s per-process
    /// `RandomState` would hash-order this slice of the checkpoint. The cost
    /// is O(log |namespaces|) tumbler comparisons per lookup instead of a
    /// hash.
    ///
    /// The count is the realized set for every namespace but the ghost content
    /// one, whose realized set is `{c_{floor+1}..cₘ}`: the format's one
    /// carve-out reserves the first [`GHOST_POSITIONS`] ordinals of that chain
    /// and is held as a compiled floor ([`ghost_floor`]), not as a gap in the
    /// count. So a reader enumerating a namespace's members from its count is
    /// right everywhere else and must start past the floor there — where the
    /// skipped ordinals are M7's reserved type addresses, never members.
    ///
    /// Not the entity registry E (ASN-0047): E is this map's below-element
    /// part together with `nodes`, which is the pair
    /// [`M3State::is_allocated`] dispatches over and
    /// [`M3State::entity_level`] then filters by tier.
    ///
    /// [`GHOST_POSITIONS`]: crate::GHOST_POSITIONS
    frontiers: im::OrdMap<NsKey, Nat>,

    /// The node registry.
    ///
    /// Node addresses (zeros = 0), externally minted (ASN-0047 NodeBaptism —
    /// provisioning mints node addresses outside the docuverse), so possibly
    /// non-contiguous → held explicitly, not frontier-encoded. M3 suppresses
    /// ASN-0040's `baptize(node, 1)` child-node capability (Conflicts §7):
    /// internal minting never yields a zeros = 0 address; ongoing admission is
    /// `register_node`, never ASN-0040 baptism. Σ₀ seeds `{[1]}`, and
    /// genesis's system-account seed admits the system node `[1.1]` beside it
    /// (PUB-6.65).
    ///
    /// What its members satisfy is `register_node`'s admission conditions, not
    /// an invariant this field carries: [`M3State::apply_m3`] states which
    /// they are, why the record door does not carry them, and what a violation
    /// costs on each of the three.
    nodes: im::OrdSet<Address>,

    /// The principal registry Π: ownership prefix ↦ opaque id.
    ///
    /// The prefix is the key and is filed nowhere else, so a principal cannot
    /// be seated at one prefix and claim another — [`M3State::effective_owner`]
    /// arbitrates by the key and [`M3State::principal_prefix`] answers with it,
    /// and the two read one value. Append-only with immutable prefixes
    /// (O12/O13), which the fold makes structural: it writes a seat only where
    /// none is held ([`M3State::apply_m3`]).
    ///
    /// Nothing in M3 bounds its size. O1a bounds a seat's tier, not how many
    /// seats there are: every account holder is ω of its own sub-account
    /// chain, so one holder can seat principals without limit, one durable
    /// delegation each; every ω call walks them all, and every by-id scan
    /// walks them until it meets the id it seeks (the private walk `omega`
    /// states the cost; [`crate::Namespace::delegate`] names whose bound the
    /// count is).
    ///
    /// Four standing properties, and they hold by three different means:
    ///
    /// * prefix-injectivity (O1b, by (v)) is structural, carried by the map's
    ///   own key;
    /// * id-injectivity (`delegate`'s `DuplicateId` gate, §6) is a producer
    ///   invariant, established at that one gate and never re-established by
    ///   [`M3State::apply_m3`] — it is what makes the by-id scan
    ///   single-valued;
    /// * the account-tier bound (O1a) is a producer invariant too, owned by
    ///   genesis (which seats π₀ at the node prefix `[1]`) and by `delegate`'s
    ///   hoisted `NotAccountTier` gate. On the journal path
    ///   `RegisterPrincipal`'s prefix door re-establishes it — stricter than
    ///   O1a, since every seat `delegate` stages is account-tier exactly — and
    ///   the record's payload keeps its fields private ([`crate::Principal`]),
    ///   so no holder rewrites a decoded prefix past that door. But a seat can
    ///   also arrive inside a whole [`M3State`], which decodes by bare derive
    ///   because genesis's own seat is node-tier. So ω re-checks it as well —
    ///   the private walk `omega` filters by tier — ω being the one reader
    ///   whose answer to a below-tier entry would be a pass.
    /// * the seat–allocation coupling — an account-tier prefix is seated iff
    ///   it is allocated, the seated ⇒ allocated half being ASN-0042's
    ///   PrefixBaptismCoupling — is a producer invariant like id-injectivity.
    ///   `delegate`, the account chain's sole allocator, stages an account's
    ///   `Allocate` and its `RegisterPrincipal` in one transaction (O17b), and
    ///   genesis folds its one account the same way; [`M3State::apply_m3`]
    ///   folds either record without the other and re-establishes neither
    ///   half ([`M3Rec::RegisterPrincipal`] states what its producer owes).
    ///   It is the property [`M3State::account_seat`] stands on to answer for
    ///   every registered document and account, and
    ///   [`M3State::effective_owner_prefix`] to answer a registered
    ///   document's own account, and what makes the owner-of-address read's
    ///   `prefix == a` an account's allocation test (AUTH-6.37).
    ///
    /// The only authoritative ownership state — the delegation forest is
    /// recomputable (NestingByDelegation) and never stored. An `OrdMap`
    /// because the top-down check needs a descendant *range* probe (§6 (iv))
    /// and ordering leaves the ω range-walk upgrade open — a change the one
    /// private `omega` walk absorbs once, serving all four of its readers
    /// (the id, the seat, the whole entry, and the authorization predicate
    /// stated in terms of the id).
    principals: im::OrdMap<Address, PrincipalId>,

    /// The publication map: the publication state of every registered document.
    ///
    /// It is what PUB §5.5 calls M3's document records, and the engine's one
    /// definition of `published(doc)` (PUB-kickoff D1; PUB-1.68: the substrate
    /// knows one bit per document, and PUB-1.70: never a second). Keyed by
    /// document address, versions included (a version is a registered
    /// Document); the value is the resolved bit its minting `Allocate`
    /// journaled (PUB-7.10), folded by [`M3State::apply_m3`] and written by
    /// nothing else: there is no publication transition (PUB-1.9, PUB-1.11) —
    /// the publish shot mints a new member born published rather than changing
    /// an entry — so an entry is written once, at mint, and stands forever.
    /// Authoritative working state like its three siblings — an ordinary serde
    /// field, restored from the checkpoint and advanced by replay, never
    /// `#[serde(skip)]` — and the engine's exception set (PUB-7.5) is a derived
    /// membership index over it (PUB-7.7), answerable off this map at the
    /// one-lookup cost [`M3State::published`] pays, and seeded by one walk of
    /// it, [`M3State::documents`].
    ///
    /// Declared after the three registries, and that is load-bearing where
    /// this slice ends the bytes: bincode encodes a struct as its fields in
    /// declaration order with no names, so there a pre-publication slice
    /// decodes its three older fields and then meets end-of-input where this
    /// one should begin — the decode failure PUB-7.8 demands, never a default
    /// and never everything-published. Inserted anywhere earlier, the same
    /// slice would read a sibling's bytes as this map. In the engine's world
    /// more slices follow this one, so there the checkpoint's format stamps
    /// refuse a pre-publication body before any slice is read. The position
    /// map below is appended after it, under the same rule.
    ///
    /// **The budget.** It is stated in the form [`MAX_NODE_COMPONENTS`] and
    /// [`MAX_PRINCIPAL_COMPONENTS`] state theirs: this is the one structure in
    /// M3 whose entry count tracks documents rather than namespaces. An entry
    /// is a full [`Address`] key, permanent (B0 — there is no deletion),
    /// ordered, and re-serialized into every checkpoint thereafter. Against
    /// the ω-gated request that buys it the charge is about one to one; against
    /// the account address a caller supplies — the document address is minted,
    /// not sent — it is the same ~32-bytes-per-component charge the node cap
    /// prices, and about a third of what a written document already pays in
    /// frontier keys, since its content, link and version chains open one
    /// full-tumbler key each. So a reader sizing a checkpoint from `frontiers`'
    /// compressed count adds one entry per document, and an empty document is
    /// not free. No cap: the count is the docuverse's, and bounding it would
    /// bound the product rather than refuse a resource.
    ///
    /// **Open decision.** The collection shape — the delta names none — is an
    /// `OrdMap`. The read is a point lookup either way — O(log |documents|)
    /// tumbler compares here — and what the ordered map buys is a checkpoint
    /// encoding and an iteration order that are functions of the contents: two
    /// boards with one history checkpoint this field to one byte string, and
    /// [`M3State::documents`], the walk the exception set's seed makes, yields
    /// them in address order. `nodes`, `principals` and `frontiers` pay that
    /// price for the same reason.
    publication: im::OrdMap<Address, bool>,

    /// The position map: the commit position of every document, member and
    /// link minted.
    ///
    /// It is the permanent order of arrival kept in the world, keyed by the
    /// address — a document (`create_new_document`, `fork`, a cross-owner
    /// `version`), a version member (an owned `version`'s mint and the publish
    /// shot's) or a link (every link deposit) — and valued by the position of
    /// the commit that minted it: the `Seq` [`M3State::apply_m3`] is handed
    /// for the `Allocate` that realizes the address, which M2 makes the
    /// transaction's own coordinate (its marker's `last_seq`, the one the
    /// acknowledgment, the change feed's row and a history read name — never
    /// an interior position of a composite), written once, at that record,
    /// and never moved (an address is never reused, so no later record names
    /// it). A content element is not entered — a run of bytes is minted per
    /// byte, and its position is the placement's — and neither is an account,
    /// whose seat the principal registry already dates by nothing: the map
    /// is for the addresses a reader asks the age of, which `doc_metadata`
    /// and `read_link` answer from it (`at`).
    ///
    /// Authoritative working state like its four siblings — an ordinary
    /// serde field, restored from the checkpoint and advanced by replay,
    /// never `#[serde(skip)]` — because the fact it keeps is a fact about
    /// the journal's order, which nothing in the world can rebuild once the
    /// journal below the reclaim floor is gone: the fork source's reason, in
    /// its shape (`skep-arrangement`'s `fork_sources`). It is the one map in
    /// the engine that keeps a position, and the fold alone writes it;
    /// `rebuild_derived` stays the identity. Genesis's two seeded documents
    /// are entered at `Seq(0)`, the coordinate the genesis state answers at.
    ///
    /// **The budget.** One full [`Address`] key and eight bytes per entry,
    /// one entry per document, member and link ever minted, ordered and
    /// re-serialized into every checkpoint — about 0.4 MB per 50,000 links
    /// beside the address keys the link slice already pays for every one of
    /// them; the `publication` map's one-entry-per-document charge, extended
    /// to members and links. No cap, for the reason that map has none: the
    /// count is the docuverse's. An `OrdMap` so the checkpoint's bytes are a
    /// function of the contents, as every sibling is.
    minted_at: im::OrdMap<Address, Seq>,
}

// ---------------------------------------------------------------------------
// The two registry caps.
// ---------------------------------------------------------------------------

/// The cap on a registered node address's component count.
///
/// It is enforced by [`crate::Namespace::register_node`]
/// ([`crate::RegisterNodeError::TooDeep`]; §7).
///
/// `nodes` is one of the two registries M3 cannot keep in frontier form (the
/// other is `principals` — [`MAX_PRINCIPAL_COMPONENTS`]): a namespace's
/// realized set is a single count, but node addresses originate outside the
/// docuverse (ASN-0047 NodeBaptism) and may be non-contiguous, so each is
/// stored whole, permanently (B0 — there is no deletion), and re-serialized
/// into every checkpoint thereafter; and because the set is ordered, a deep
/// or large-magnitude entry can lengthen a later `nodes` probe that compares
/// against it.
///
/// What the cap closes is the per-component fixed overhead: each component
/// occupies a `Vec<Nat>` element plus its own heap magnitude allocation — ~32
/// bytes resident — against ~2 bytes of dotted decimal to supply, so a small
/// component is a ~16× permanent, replicated charge. 32 leaves an order of
/// magnitude over any physical provisioning hierarchy (one component per
/// level of region/site/rack/host and the like) while capping that overhead
/// near a kilobyte per entry.
///
/// What it does not close is component magnitude, which M1 leaves unbounded
/// (T0(b)): `[1, 2^100000]` is two components and some twelve kilobytes of
/// entry. That is permanent and replicated like any entry, but it is not an
/// amplification — a K-byte magnitude costs ~2.4K bytes to supply, so wire
/// bytes exceed resident bytes. It is worth knowing that `register_node` is
/// the only path by which a caller's chosen component values enter the
/// permanent name space at all: every other address M3 mints is a registered
/// parent extended by separators, the subspace identifiers 1/2, and frontier
/// ordinals bounded by the mint count plus the chain's floor — so every
/// address under a node inherits that node's magnitudes. A magnitude bound,
/// if a deployment wants one, belongs where the codec parses a tumbler, not
/// here.
pub const MAX_NODE_COMPONENTS: usize = 32;

/// The cap on a principal prefix's component count.
///
/// It is enforced by [`crate::Namespace::delegate`]
/// ([`crate::DelegateError::TooDeep`]; §6).
///
/// `principals` is the second registry M3 cannot keep in frontier form: a
/// prefix is stored whole, permanently (O12 — there is no revocation),
/// re-serialized into every checkpoint, ordered (so a deep entry can lengthen
/// a later range probe that compares against it), and — unlike a `nodes`
/// entry — walked by every ω query in the system. Its component count is the
/// caller's, one per level of delegation nesting, and at ~32 bytes resident
/// against ~2 bytes of dotted decimal to supply it is the same ~16×
/// permanent, replicated charge [`MAX_NODE_COMPONENTS`] bounds for `nodes`.
///
/// The number: a prefix is `node_field ++ [0] ++ account_field` in M1's
/// accessors — its node field, then its user field (T4b's `U`) — the node
/// field already bounded by [`MAX_NODE_COMPONENTS`], and the user field
/// grows one component per delegation. 64 leaves 31 levels of nesting under
/// the deepest admissible node — an order of magnitude over any authority
/// hierarchy (operator → org → division → team → project is five) — and holds
/// one permanent entry near 2 KB, twice the node cap's ceiling for twice its
/// components. It also caps what an unauthenticated deep prefix can command
/// before `delegate` reaches its first gate, which is the half of the charge
/// no economics bound: the full-depth `parent` clone, the
/// nine-bytes-per-component lock key, and the transaction that takes the
/// account-chain and global-principals keys. Depth in the registry itself
/// costs one committed delegation per level, since P8 admits only a
/// registered parent — so a deep entry is bought, not smuggled, and what the
/// cap bounds there is what one entry charges every later ω walk.
///
/// Nothing re-checks it at the record door or in the fold, for the reason the
/// node cap is not re-checked either: that would refuse a record M3 itself
/// wrote before the cap existed, turning a resource charge into an
/// unreplayable journal.
pub const MAX_PRINCIPAL_COMPONENTS: usize = 64;

// ---------------------------------------------------------------------------
// §D Genesis: Σ₀'s bootstrap root, the system-account seed, and the fold.
// ---------------------------------------------------------------------------

/// Returns the bootstrap node root `[1]` (Σ₀).
///
/// It is the single definition genesis seeds from and `register_node`'s
/// lineage check probes against. `Nat` is a big-int and so cannot be
/// `const`, so the address is built once and borrowed thereafter.
pub(crate) fn bootstrap_root() -> &'static Address {
    static ROOT: LazyLock<Address> = LazyLock::new(|| {
        let root = Tumbler::new([Nat::from(1u32)]).expect("a one-component sequence is nonempty");
        validate(root).expect("the bootstrap root [1] is T4-valid")
    });
    &ROOT
}

/// Returns the system node `1.1` (PUB-6.65, RES-304).
///
/// It is a node under the bootstrap node `[1]`, the one the system account is
/// delegated under, registered by [`M3State::genesis`]. The seed lives under
/// *this* node's allocator, never under node `[1]`'s, so the seed leaves node
/// `[1]`'s own account frontier — the input the claim floor reads
/// (`next_account_prefix([1])`, PUB-6.52) — alone, and the honest claim
/// admits.
pub fn system_node() -> Address {
    let t = Tumbler::new([1u32, 1].into_iter().map(Nat::from))
        .expect("a two-component sequence is nonempty");
    validate(t).expect("the system node 1.1 is T4-valid by construction")
}

/// Returns the system account `1.1.0.1` (PUB-6.65, RES-304).
///
/// It is the commons account of the design, owned by [`SYSTEM_PRINCIPAL`] and
/// seeded by [`M3State::genesis`] with its doc 1 (the commons registry's
/// future home, which is [`ghost_home_document`]) and its doc 2 (the daemon's
/// head document `H`), both born published. Its account chain sits under
/// [`system_node`].
pub fn system_account() -> Address {
    let t = Tumbler::new([1u32, 1, 0, 1].into_iter().map(Nat::from))
        .expect("a four-component sequence is nonempty");
    validate(t).expect("the system account 1.1.0.1 is T4-valid by construction")
}

/// Returns the head document `H` = `1.1.0.1.0.2` (PUB-6.65, RES-304).
///
/// It is doc 2 of [`system_account`], the new-version-per-head document the
/// daemon writes. Seeded born published by [`M3State::genesis`]. This is the
/// one spelling of `H` the seed and the daemon's head writer share: the seed
/// registers the document it builds and the head writer writes the document
/// it builds, so the two cannot come apart.
pub fn head_document() -> Address {
    let t = Tumbler::new([1u32, 1, 0, 1, 0, 2].into_iter().map(Nat::from))
        .expect("a six-component sequence is nonempty");
    validate(t).expect("the head document 1.1.0.1.0.2 is T4-valid by construction")
}

/// Returns the time document `T` = `1.1.0.1.0.4`.
///
/// It is doc 4 of [`system_account`], the daemon's own document of hourly
/// `skep-time` records — each a published version member holding one record
/// that names a committed position and the daemon's clock at it — which a
/// reader of a minted address's age falls back on where the change feed's
/// line is gone (wire.md §The other endpoints, the time document). Not
/// seeded by [`M3State::genesis`]: the daemon's time writer mints it,
/// published, at its first record, after the staging draft doc 3 the head
/// writer and the registry seed share, so by the document chain's frontier
/// it lands here. One spelling for the writer and every reader, as
/// [`head_document`] is for `H`.
pub fn time_document() -> Address {
    let t = Tumbler::new([1u32, 1, 0, 1, 0, 4].into_iter().map(Nat::from))
        .expect("a six-component sequence is nonempty");
    validate(t).expect("the time document 1.1.0.1.0.4 is T4-valid by construction")
}

impl M3State {
    /// Returns Σ₀ + O14, plus the system account seed (PUB-6.65, RES-304).
    ///
    /// That is `nodes = {[1], [1.1]}`,
    /// `Π = { [1] → BOOTSTRAP_PRINCIPAL, [1.1.0.1] → SYSTEM_PRINCIPAL }`, the
    /// account chain `([1.1], 2)` at 1 and the document chain
    /// `([1.1.0.1], 2)` at 2, and both documents born published. `pub` — the
    /// engine seeds `Kernel::open(cfg, genesis-World)` with it; "load empty
    /// journal" and "fresh genesis" are the same code path (§7).
    /// Deterministic, per M2's byte-identical-genesis caller contract — and
    /// byte-identical across processes because every field is ordered (the
    /// frontier map included).
    ///
    /// **Two parts, built two ways.** The roots — node `[1]` and π₀ seated at
    /// it — are written directly: they are the state every record folds onto,
    /// and π₀'s node-tier seat is a shape no op stages and
    /// `RegisterPrincipal`'s prefix door refuses. The seed is folded: it is
    /// the five records M3's own ops stage for the same work —
    /// [`crate::Namespace::register_node`]'s admission of [`system_node`]
    /// `1.1`, [`crate::Namespace::delegate`]'s baptism and seat of
    /// [`system_account`] `1.1.0.1` for [`SYSTEM_PRINCIPAL`], and the
    /// allocations of the two documents
    /// [`crate::Namespace::create_new_document`] mints there, doc 1
    /// ([`ghost_home_document`], the commons registry's future home) and doc 2
    /// ([`head_document`] `H`), born published (PUB-1.25's
    /// genesis/commons-seeded row) — handed to [`M3State::apply_m3`] in that
    /// order. So the fold is the one writer of the frontier and publication
    /// maps: each chain reaches its count by the fold's own advance to each
    /// record's ordinal, each document's bit lands in the step that registers
    /// it, and the fold's contiguity check confirms, on every build, that the
    /// account and each document is the next member of its own chain. A
    /// document added to the seed is one more record.
    ///
    /// What the seed leaves alone: node `[1]`'s own account chain — the
    /// seeded account chain is `([1.1], 2)`, not `([1], 2)` — so
    /// `next_account_prefix([1])` answers `1.0.1`; and content — both
    /// documents are born empty, so the ghost content namespace has no
    /// frontier and its floor (`ghost_floor`, [`GHOST_POSITIONS`]) stands.
    /// It seeds no unpublished document and no link.
    ///
    /// [`GHOST_POSITIONS`]: crate::GHOST_POSITIONS
    pub fn genesis() -> M3State {
        let root = bootstrap_root();
        let roots = M3State {
            frontiers: im::OrdMap::new(),
            nodes: im::OrdSet::unit(root.clone()),
            principals: im::OrdMap::unit(root.clone(), BOOTSTRAP_PRINCIPAL),
            publication: im::OrdMap::new(),
            minted_at: im::OrdMap::new(),
        };
        let seed = [
            // `register_node`: the system node 1.1.
            M3Rec::RegisterNode {
                addr: system_node(),
            },
            // `delegate`: the system account 1.1.0.1, baptized and seated.
            M3Rec::Allocate(Allocation {
                addr: system_account(),
                published: NO_PUBLICATION_STATE,
            }),
            M3Rec::RegisterPrincipal(Principal {
                prefix: system_account(),
                id: SYSTEM_PRINCIPAL,
            }),
            // Two creates under it, both born published: doc 1, then doc 2 (H).
            M3Rec::Allocate(Allocation {
                addr: ghost_home_document(),
                published: true,
            }),
            M3Rec::Allocate(Allocation {
                addr: head_document(),
                published: true,
            }),
        ];
        // Folded at `Seq(0)`, the genesis coordinate: the two documents enter
        // the position map there, which is where a reader of the genesis
        // state finds them registered.
        seed.iter().fold(roots, |s, r| s.apply_m3(Seq(0), r))
    }

    /// Returns the slice with `r` folded in at position `at`: M3's fold.
    ///
    /// It is `pub`: the engine crate wires `World::apply`'s dispatch of the
    /// variant carrying an [`M3Rec`] to this, handing it the position of the
    /// commit the record belongs to (M2's `WorldState::apply`), which the
    /// fold keeps for every document, member and link an `Allocate` mints
    /// (the position map, `minted_at`): written once, at the record that
    /// mints the address, and read by [`M3State::minted_at`]. A position is a
    /// journal fact and never a clock (DOCTRINE D1), so the fold stays a pure
    /// function of the journal's content and order.
    ///
    /// **Totality domain.** M2's total-apply obligation, stated here at the
    /// seam the engine wires: total — deterministic, side-effect-free,
    /// panic-free — over every record whose `Allocate` address, or
    /// `AllocateRange` first address, both extends a parent and carries its
    /// namespace's effective frontier + 1 as its ordinal (effective =
    /// `max(frontier, floor)`; the floor is nonzero only for the ghost content
    /// namespace — `ghost_floor`). A mint's record is such a record wherever
    /// it is staged as [`M3Rec::Allocate`] requires — against the working
    /// state the mint read: a mint extends a registered parent and issues
    /// exactly `c_{m+1}` of that state, past the floor. That the parent is
    /// registered (P8) is the mints' gate and no part of this domain: an
    /// `Allocate` under an unregistered parent folds like any other, and that
    /// is the state [`M3State::has_documents`] and [`M3State::latest_version`]
    /// answer by their chains.
    ///
    /// The two conditions differ in kind, and each is checked where it can be.
    /// Extending a parent is a fact about one field, so it is carried at that
    /// field's door: the [`Address`] payloads carry T4-validity, `Allocate`'s
    /// address door (`parented_address`) and `AllocateRange`'s first-address
    /// door (`content_range_first`, which runs it) carry the parent, and a
    /// record arriving from disk or a peer that lacks either is refused at
    /// decode rather than folded into a panic. Contiguity is not decidable
    /// from one record — it is a claim about the frontier the record is about
    /// to advance — so no door can carry it, and the fold checks it instead,
    /// on every build: an `Allocate` or a range whose ordinal jumps, repeats
    /// or regresses its chain's next is outside the domain — corruption, or a
    /// caller's bug, a mint's record staged where [`M3Rec::Allocate`] forbids
    /// — and the fold fail-stops on it (`# Panics`) rather than register
    /// ordinals no mint issued (B1) or issue a live address again (B8). On the
    /// write path the fold runs at the record's push, in the transaction's
    /// closure phase, so the panic unwinds a transaction that has journaled
    /// nothing, drawn no position and poisoned nothing; at replay it halts the
    /// open, as the engine's `Engine::open` states for every structural fact a
    /// fold asserts. [`M3Rec`]'s seals keep the producer inside this crate in
    /// a build that compiles no test — the mints, the ops and genesis
    /// construct every record, and no other crate constructs one or edits the
    /// `Allocate` a mint returned, whose payload's fields are private — but not
    /// the stager: a composite in another crate places the record a mint
    /// returned, and contiguity rests on where it does ([`M3Rec::Allocate`]),
    /// which is why the fold is what checks it. A record decoded from bytes
    /// rather than constructed here carries the first condition through its
    /// door and meets the second at the fold; [`M3Rec`] states what else it
    /// owes.
    ///
    /// `Allocate`'s publication bit is folded for a document-tier address and
    /// read for no other (PUB-7.7's fold half, at M3's own allocation record:
    /// the publication map and the registration reach a reader in the one
    /// commit that carries that record, never a later step). The write is
    /// insert-if-absent, so the bit a document was minted with is the bit that
    /// stands (PUB-1.9), and not merely inside the totality domain: the
    /// contiguity check holds a record to the stored frontier, and a frontier
    /// regressed off a corrupted checkpoint makes a second record for a
    /// registered document contiguous, so the check cannot be what holds an
    /// immutability that record would otherwise overwrite. Membership of the
    /// publication map is a per-arm fact no door can carry — "this document
    /// already has a bit" is a claim about the map, which a decoder holding
    /// one frame cannot settle — so it is answered here, at one lookup, rather
    /// than refused at decode.
    ///
    /// `RegisterNode`'s admission conditions — node level, the
    /// [`MAX_NODE_COMPONENTS`] cap, and bootstrap lineage — belong to
    /// [`crate::Namespace::register_node`] and are not invariants of `nodes`.
    /// The fold neither re-establishes them nor could refuse, and the record
    /// door deliberately does not carry them either: a depth check at the door
    /// would refuse a record M3 itself wrote before the cap existed, turning a
    /// resource charge into an unreplayable journal. What a violation costs is
    /// bounded and never a pass — a non-node-level entry is unreachable, since
    /// [`M3State::is_allocated`] consults `nodes` only on the `Node` arm; an
    /// off-lineage node is inert, since no principal covers it and so
    /// `delegate` beneath it is refused `NotAncestor` at (i); and an over-cap
    /// entry is a permanent resource charge and nothing more.
    ///
    /// `RegisterPrincipal`'s tier is a fact about one field, so it rides at
    /// that field's door like `Allocate`'s parent: the prefix door
    /// (`account_tier_prefix`) admits an account-tier prefix and nothing else,
    /// which is what `delegate` stages and what ω's O1a filter cannot refuse
    /// on its own (node tier is a pass there, for π₀'s sake). A seat is
    /// written once, like a document's bit: a `RegisterPrincipal` naming a
    /// prefix already seated leaves the seated principal alone (O12/O13 —
    /// principals persist and prefixes are immutable; no op re-seats, since
    /// `delegate` seats only a fresh prefix). Whether a prefix is seated is a
    /// claim about the registry, which no door holding one frame can settle,
    /// so the fold answers it at one lookup, on every build. Two facts that
    /// arm does not check are its producer's, and [`M3Rec::RegisterPrincipal`]
    /// states both. The prefix's allocation is one: a seat folds whether or
    /// not its prefix is allocated, as an account's `Allocate` folds without a
    /// seat, so their coupling is the producer invariant `delegate` keeps by
    /// staging both in one transaction (O17b). Id-injectivity is the other,
    /// and leaving it unchecked is deliberate rather than missing: one id ↦ at
    /// most one principal is a producer invariant, owned by `delegate`'s
    /// `DuplicateId` gate alone. The fold could check it — an arm sees the
    /// whole slice — but Π is keyed by prefix, so the check is a Θ(|Π|) scan
    /// per replayed seat, making replay of N delegations Θ(N²); and it has no
    /// fail-safe direction, since skipping the seat would leave the account
    /// its transaction allocated unseated. What rests on it is
    /// [`M3State::principal_prefix`]'s single-valuedness, and through it
    /// every account an id is resolved to — `fork`'s account, `delegate`'s
    /// delegator, M5's cross-owner VERSION target and the daemon's session
    /// account among them: a `RegisterPrincipal` from any producer but
    /// `delegate` could seat a second principal on a live id and make each
    /// such answer arbitrary. `delegate` is its sole producer on the journal;
    /// genesis folds one more — `SYSTEM_PRINCIPAL`'s seat, onto roots where
    /// only π₀'s id is live — before any delegation can run, and from then on
    /// `delegate`'s `DuplicateId` gate refuses that id. A producer this crate
    /// adds owes both clauses; [`M3Rec`]'s seals keep every other crate from
    /// constructing one in a build that compiles no test, and a crate that
    /// decodes a seat from bytes it wrote owes both, unchecked.
    ///
    /// # Panics
    ///
    /// Panics where an `Allocate` address or an `AllocateRange` first address
    /// extends no parent: the `namespace_of` `expect`. Panics, on every build,
    /// where an `Allocate`'s ordinal, or a range's first ordinal, is not its
    /// chain's effective frontier + 1 — a jump, a repeat or a regression: the
    /// contiguity check, whose message names the record's address.
    #[must_use = "apply_m3 returns the folded slice; it does not modify the receiver"]
    pub fn apply_m3(&self, at: Seq, r: &M3Rec) -> M3State {
        let mut s = self.clone();
        match r {
            M3Rec::Allocate(Allocation { addr, published }) => {
                let key = namespace_of(addr).expect(
                    "≥ 2 components: Allocate's address door refuses a parentless address off the journal, and the totality domain asks it of an in-process producer",
                );
                let n = ordinal(addr.tumbler()).clone();
                // The totality domain's contiguity condition, held on every
                // build: an ordinal past the chain's next would register the
                // ordinals between as members no mint issued (B1); one at the
                // chain's frontier or below would issue a live address again
                // (B8), and below it set the frontier back (B0). Its floor term
                // matters at most once per journal: the ghost home document's
                // first content record, an Allocate or a range, carries
                // ordinal GHOST_POSITIONS + 1 over an absent frontier.
                let next = s.effective_frontier(&key) + 1u32;
                assert_eq!(
                    n, next,
                    "Allocate ordinal must equal its namespace's effective frontier + 1: {addr} is not its chain's next"
                );
                s.frontiers.insert(key, n);
                // Written once (PUB-1.9) on every build. The check above holds
                // a record to the stored frontier, and a frontier regressed off
                // a corrupted checkpoint makes a second record for a registered
                // document contiguous: this `contains_key` test holds the bit
                // there.
                if addr.level() == Level::Document && !s.publication.contains_key(addr) {
                    s.publication.insert(addr.clone(), *published);
                }
                // The position map (the `minted_at` field's card): a document
                // or a version member — Document-tier — and a link element;
                // written once, at the record that mints the address, on
                // every build, as the bit above is.
                if (addr.level() == Level::Document || is_link_slot(addr))
                    && !s.minted_at.contains_key(addr)
                {
                    s.minted_at.insert(addr.clone(), at);
                }
            }
            M3Rec::RegisterNode { addr } => {
                s.nodes.insert(addr.clone());
            }
            M3Rec::RegisterPrincipal(Principal { prefix, id }) => {
                // Written once (O12/O13): the first seat stands.
                if !s.principals.contains_key(prefix) {
                    s.principals.insert(prefix.clone(), *id);
                }
            }
            M3Rec::AllocateRange(RangeAllocation { first, count }) => {
                let key = namespace_of(first).expect(
                    "≥ 2 components: AllocateRange's first-address door refuses a parentless address off the journal, and the totality domain asks it of an in-process producer",
                );
                let n = ordinal(first.tumbler()).clone();
                // The same contiguity condition `Allocate` carries, on the
                // range's first ordinal and on every build; the frontier then
                // advances by the count in one record. No publication write: a
                // range is minted on a content chain only (the element tier).
                let next = s.effective_frontier(&key) + 1u32;
                assert_eq!(
                    n, next,
                    "a range's first ordinal must equal its namespace's effective frontier + 1: {first} is not its chain's next"
                );
                s.frontiers.insert(key, n + count - 1u32);
            }
        }
        s
    }
}

/// Returns whether `e` is an element of a link chain: `d·0·2·n`.
///
/// It is the position map's test for the one element family it enters —
/// [`is_content_or_link_slot`] narrowed to the link subspace — asked of the
/// address alone, as the fold must.
fn is_link_slot(e: &Address) -> bool {
    matches!(e.element_field(), Some([s, _]) if *s == link_subspace())
}

impl M3State {
    /// Returns the position the record that minted `a` committed at.
    ///
    /// It is the position map's entry (the `minted_at` field's card): `Some`
    /// for every document, version member and link minted by a build that
    /// keeps the map — genesis's two seeded documents at `Seq(0)` — and
    /// `None` for every other address: a content element, an account, a
    /// node, an address never minted, and one minted by a build that kept no
    /// map, which a checkpoint written without the field never carries. A
    /// point lookup, `O(log |entries|)`; the same at every position from the
    /// mint on, since an entry is written once and never moved. What a
    /// reader is served for it, and the time beside it, is the wire's
    /// (`doc_metadata`'s and `read_link`'s `at`, `time`, `time_from`).
    pub fn minted_at(&self, a: &Address) -> Option<Seq> {
        self.minted_at.get(a).copied()
    }
}

// ---------------------------------------------------------------------------
// §1 The frontier allocator (the heart).
// ---------------------------------------------------------------------------

impl M3State {
    /// Returns the effective frontier: `max(frontiers[key], ghost_floor(key))`.
    ///
    /// It is the frontier `next_in` mints past and the fold's contiguity check
    /// expects. For every namespace but the ghost content one the floor is 0
    /// and this is the stored frontier; for that one it starts the chain past
    /// the ghost region ([`ghost_floor`] carries the non-reissue argument). Not
    /// the membership bound — membership reads the stored frontier and
    /// excludes the floored ordinals, because a floor that counted as members
    /// would make the five ghost tumblers allocated without a mint. Given that
    /// exclusion the two bounds agree, so membership stays on the stored value,
    /// which it can borrow.
    fn effective_frontier(&self, key: &NsKey) -> Nat {
        self.frontiers
            .get(key)
            .cloned()
            .unwrap_or_else(Nat::zero)
            .max(ghost_floor(key))
    }

    /// Returns `next(B, p, g)` in closed form (§1).
    ///
    /// The chain `S(p, g)` is `cₙ = p ++ [0]^(g−1) ++ [n]`, so the next
    /// address is `c_{m+1}` — read the count, advance the trailing ordinal —
    /// which is [`nth_in`] at `m + 1`, where `m` is the
    /// [`M3State::effective_frontier`] (the stored count, floored past the
    /// ghost region for the one namespace that holds it). Pure function of
    /// `frontiers` (B2 determinism — the natural property-test oracle).
    ///
    /// `first_in`'s anchor precondition is stated in `crate::ns` beside the
    /// `validate` that consumes it, and the six mints — this function's only
    /// callers, the five single mints through `mint_on` and the range mint
    /// directly — each meet it by a gate that has already run: [`version_ns`]
    /// and [`document_ns`] clone their anchor from an [`Address`], as does
    /// [`account_ns`] behind [`M3State::mint_account`]'s registered-entity
    /// gate; and [`content_ns`]/[`link_ns`] sit behind
    /// `is_registered_document`, which makes `home` a Document, so
    /// `inc(home, 2)` lands inside T4.
    ///
    /// # Errors
    ///
    /// Fails with the [`GateViolation`] of M1's `checked_inc`, the TA5a gate ⇒
    /// B6(ii)/(iii). Routing every address this issues through that gate, via
    /// `first_in`, is the defensive guard: it cannot fire on a live path, nor
    /// on any frontier count, since `first_in` sees only the anchor — only on
    /// a key that fails `first_in`'s anchor precondition.
    ///
    /// # Panics
    ///
    /// Panics on an element that is no slot of a content or a link chain
    /// ([`is_content_or_link_slot`]). Every single mint's address and every
    /// range's first address is computed here, and a range's other addresses
    /// follow its first on one chain, so this is also where the element
    /// families are held to two: such an element is a panic naming the
    /// guarantee, never an address. The shape of what this issues follows from
    /// `key` alone and `key` from a mint's own constructor, so no state,
    /// corrupted or not, reaches the panic — only a third element family added
    /// to M3, which fails at its first mint rather than allocating the
    /// subspace-3 type names readers treat as never minted (AUTH-7.1 horn B;
    /// AUTH-3.70). It also panics, in `first_in`, on a key whose anchor is no
    /// valid address: that precondition's first half.
    ///
    /// [`version_ns`]: crate::ns::version_ns
    /// [`document_ns`]: crate::ns::document_ns
    /// [`account_ns`]: crate::ns::account_ns
    /// [`content_ns`]: crate::ns::content_ns
    /// [`link_ns`]: crate::ns::link_ns
    /// [`is_content_or_link_slot`]: crate::ns::is_content_or_link_slot
    fn next_in(&self, key: &NsKey) -> Result<Address, GateViolation> {
        let next = nth_in(key, &(self.effective_frontier(key) + 1u32))?;
        assert!(
            next.level() != Level::Element || is_content_or_link_slot(&next),
            "M3 mints elements on the content and link chains alone: {next} is on neither (AUTH-7.1 horn B — subspace 3 holds type names)"
        );
        Ok(next)
    }
}

#[cfg(test)]
mod tests;
