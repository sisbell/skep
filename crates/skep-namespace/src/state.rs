//! M3's slice (§Core data model, §1): [`M3State`] itself, and the
//! `published` a non-document record carries; the two registry caps; the
//! fixed addresses genesis builds — Σ₀'s bootstrap root and the
//! system-account seed (PUB-6.65) — with genesis and the fold (§D); and the
//! frontier arithmetic the fold checks and the mints draw on (§1). The
//! records the fold consumes, and the identity type they name, are
//! `crate::record`'s; namespace keys are `crate::ns`'s, and the ghost floor
//! is `crate::ghost`'s.
//!
//! Beneath it, two children, each an `impl M3State` that sees this module's
//! private items the way a child does, so nothing here is widened for them:
//!
//! * [`mint`] — §A: the lock keys a transaction holds, the five mints, and
//!   the two peeks, each a mint without its record.
//! * [`query`] — §C: every other query — entity membership (§2), the two
//!   chain-end reads that read a frontier directly, the publication reads,
//!   the principal registry and the ω resolver (§5), and `prefix_contains`.
//!
//! The unit tests for the slice and both children are `state/tests.rs`.

// §A: the lock keys a transaction holds, the five mints, the two peeks.
mod mint;
// §C: every other query — membership, two chain-end reads, the publication
// reads, the principal registry and ω.
mod query;

pub use query::prefix_contains;

use std::sync::LazyLock;

use num_traits::Zero;
use serde::{Deserialize, Serialize};
use skep_address::{ordinal, validate, Address, GateViolation, Level, Nat, Tumbler};

use crate::ghost::{ghost_floor, ghost_home_document};
use crate::ns::{namespace_of, nth_in, NsKey};
use crate::record::{M3Rec, PrincipalId, BOOTSTRAP_PRINCIPAL, SYSTEM_PRINCIPAL};

/// The `published` an `Allocate` carries OUTSIDE the document tier — an
/// account, a content or link element — where publication is not a property
/// of the address at all (PUB-1.68: one bit per DOCUMENT, and nothing else
/// carries one). [`M3State::apply_m3`] reads the bit only for a Document-tier
/// address, so this value is never consulted; it is named so the three
/// non-document mints, and genesis's account record, say what they stamp and
/// why, and so a reader of a journal frame knows the `false` on an account or
/// element `Allocate` is an absence and not a verdict.
const NO_PUBLICATION_STATE: bool = false;

/// M3's slice of the engine's `WorldState`, reached via [`crate::HasM3::m3`].
/// All persistent (`im`), so each commit yields a cheap structurally-shared
/// version — free MVCC snapshots for readers and free historical ω_Σ.
///
/// **The journal is the sole authority** (M2); these four structures are the
/// *recovered working representation*, folded by [`M3State::apply_m3`]. All
/// four are ordinary `Serialize`/`Deserialize` fields — **none** is
/// `#[serde(skip)]` — so they are restored verbatim from the loaded checkpoint
/// and then advanced by replaying the post-checkpoint `M3Rec`s. They are
/// authoritative working state, not derived hints, so M3 takes M2's **default
/// `rebuild_derived`** (identity): nothing to re-seed before replay.
///
/// Authoritative vs hint: `frontiers`/`nodes`/`principals`/`publication` are
/// authoritative (the compressed allocation journal, and the per-document
/// publication map beside it). The delegation forest, any
/// `address → owner` ω-cache, any `id → prefix` reverse index, and the
/// exception set over `publication` are *hints* — recomputable from the
/// authoritative fields alone — and are deliberately NOT stored here (Open
/// build decisions: defaults taken; the exception set is the engine's derived
/// membership index, PUB-7.5).
///
/// The `Serialize` impl targets bincode-class formats, M2's checkpoint
/// encoding: `frontiers` is keyed by a struct, which formats requiring string
/// keys (JSON among them) refuse. The bytes are CANONICAL (2026-09-23, QUEUE
/// item 10 option (i)): every field is an ordered collection, so two slices
/// holding the same entries encode to one byte string on any process and any
/// machine — which is what lets M2's checkpoint header commit to its body by
/// hash. Field ORDER is the compatibility surface (bincode carries no names):
/// a field is APPENDED, never inserted, so an older checkpoint decodes its
/// prefix and fails at the field it lacks rather than mis-reading one field
/// as another.
///
/// Equality is structural, and it is the meaning of the type: two slices are
/// equal iff their three registries and the publication map hold the same
/// entries. So a slice recovered from a checkpoint is comparable to the one
/// it was taken from — the whole claim recovery makes — without going through
/// a rendering. There is no [`Default`]: [`M3State::genesis`] is not an empty
/// value (it seeds `[1]` into `nodes` and Π), and an empty one would be a
/// world with no bootstrap principal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct M3State {
    /// THE baptismal registry (ASN-0040 B), in B1+B2 compressed form. A
    /// namespace's entire realized set `{c₁..cₘ}` IS the single count `m` — a
    /// gap is literally unrepresentable (B1 free). Covers every chain:
    /// accounts, documents, versions, content, links. Values are big-ints (B9
    /// unbounded). Mint and membership are *point* lookups on one namespace
    /// and namespaces are never iterated, so no READ pays for order; the
    /// map is an `OrdMap` all the same (2026-09-23, QUEUE item 10 option (i),
    /// in place of the `im::HashMap` whose per-process `RandomState` made
    /// this the one hash-ordered slice of the checkpoint), because the order
    /// is WRITTEN: the checkpoint's bytes are a function of the contents, and
    /// a published head can name a checkpoint by hash. The cost is a tumbler
    /// comparison per lookup instead of a hash.
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
    /// part TOGETHER WITH `nodes`, which is the pair
    /// [`M3State::is_allocated`] dispatches over and
    /// [`M3State::entity_level`] then filters by tier.
    ///
    /// [`GHOST_POSITIONS`]: crate::GHOST_POSITIONS
    frontiers: im::OrdMap<NsKey, Nat>,

    /// The node registry. Node addresses (zeros = 0), externally minted
    /// (ASN-0047 NodeBaptism — provisioning mints node addresses OUTSIDE the
    /// docuverse), so possibly non-contiguous → held explicitly, not
    /// frontier-encoded. M3 SUPPRESSES ASN-0040's `baptize(node, 1)`
    /// child-node capability (Conflicts §7): internal minting never yields a
    /// zeros = 0 address; ongoing admission is `register_node`, never
    /// ASN-0040 baptism. Σ₀ seeds `{[1]}`, and genesis's system-account seed
    /// admits the system node `[1.1]` beside it (PUB-6.65).
    ///
    /// What its members satisfy is `register_node`'s ADMISSION conditions, not
    /// an invariant this field carries: [`M3State::apply_m3`] states which
    /// they are, why no door can re-establish them, and what a violation costs
    /// on each of the three.
    nodes: im::OrdSet<Address>,

    /// Principal registry Π: ownership prefix ↦ opaque id. The prefix is the
    /// KEY and is filed nowhere else, so a principal cannot be seated at one
    /// prefix and claim another — [`M3State::effective_owner`] arbitrates by
    /// the key and [`M3State::principal_prefix`] answers with it, and the two
    /// read one value. Append-only with immutable prefixes (O12/O13), which
    /// the fold makes structural: it writes a seat only where none is held
    /// ([`M3State::apply_m3`]).
    ///
    /// Nothing in M3 bounds its SIZE. O1a bounds a seat's tier, not how many
    /// seats there are: every account holder is ω of its own sub-account
    /// chain, so one holder can seat principals without limit, one durable
    /// delegation each, and every ω call and every by-id scan walks them all
    /// (the private walk `omega` states the cost;
    /// [`crate::Namespace::delegate`] names whose bound the count is).
    ///
    /// Four standing properties, and they hold by three different means:
    ///
    /// * prefix-injectivity (O1b, by (v)) is STRUCTURAL, carried by the map's
    ///   own key;
    /// * id-injectivity (`delegate`'s `DuplicateId` gate, §6) is a PRODUCER
    ///   invariant, established at that one gate and never re-established by
    ///   [`M3State::apply_m3`] — it is what makes the by-id scan
    ///   single-valued;
    /// * the account-tier bound (O1a) is a PRODUCER invariant too, owned by
    ///   genesis (which seats π₀ at the node prefix `[1]`) and by `delegate`'s
    ///   hoisted `NotAccountTier` gate. On the journal path
    ///   `RegisterPrincipal`'s prefix door re-establishes it — stricter than
    ///   O1a, since every seat `delegate` stages is account-tier exactly — but
    ///   a seat can also arrive inside a whole [`M3State`], which decodes by
    ///   bare derive because genesis's own seat is node-tier. So ω re-checks
    ///   it as well — the private walk `omega` filters by tier — ω being the
    ///   one reader whose answer to a below-tier entry would be a PASS.
    /// * the seat–allocation coupling — an account-tier prefix is seated iff
    ///   it is allocated, the seated ⇒ allocated half being ASN-0042's
    ///   PrefixBaptismCoupling — is a PRODUCER invariant like id-injectivity.
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
    /// The ONLY authoritative ownership state — the delegation forest is
    /// recomputable (NestingByDelegation) and never stored. An `OrdMap`
    /// because the top-down check needs a descendant *range* probe (§6 (iv))
    /// and ordering leaves the ω range-walk upgrade open — a change the one
    /// private `omega` walk absorbs once, serving all four of its readers
    /// (the id, the seat, the whole entry, and the authorization predicate
    /// stated in terms of the id).
    principals: im::OrdMap<Address, PrincipalId>,

    /// The publication map: the publication state of every registered
    /// DOCUMENT — what PUB §5.5 calls M3's document records, and the engine's
    /// ONE definition of `published(doc)` (owner ruling D1, 2026-09-05;
    /// PUB-1.68: the substrate knows one bit per document, and PUB-1.70:
    /// never a second). Keyed by document address, versions included (a
    /// version is a registered Document); the value is the RESOLVED bit its
    /// minting `Allocate` journaled (PUB-7.10), folded by
    /// [`M3State::apply_m3`] and written by nothing else: there is no
    /// publication transition (PUB-1.9, PUB-1.11) — the publish shot mints a
    /// new member born published rather than changing an entry — so an entry
    /// is written once, at mint, and stands forever. AUTHORITATIVE working
    /// state like its three siblings — an ordinary serde field, restored from
    /// the checkpoint and advanced by replay, never `#[serde(skip)]` — and the
    /// engine's exception set (PUB-7.5) is a derived membership index OVER it
    /// (PUB-7.7), answerable off this map at the one-lookup cost
    /// [`M3State::published`] pays, and seeded by one walk of it,
    /// [`M3State::documents`].
    ///
    /// Declared LAST, and that is load-bearing: bincode encodes a struct as
    /// its fields in declaration order with no names, so a pre-publication
    /// checkpoint decodes its three older fields and then meets end-of-input
    /// where this one should begin — the decode FAILURE PUB-7.8 demands,
    /// never a default and never everything-published. Inserted anywhere
    /// earlier, the same checkpoint would read a sibling's bytes as this map.
    ///
    /// THE BUDGET, in the form [`MAX_NODE_COMPONENTS`] and
    /// [`MAX_PRINCIPAL_COMPONENTS`] state theirs: this is the first structure
    /// in M3 whose entry count tracks DOCUMENTS rather than namespaces. An
    /// entry is a full [`Address`] key, permanent (B0 — there is no deletion),
    /// ordered, and re-serialized into every checkpoint thereafter. Against
    /// the ω-gated request that buys it the charge is about one to one; against
    /// the ACCOUNT address a caller supplies — the document address is minted,
    /// not sent — it is the same ~32-bytes-per-component charge the node cap
    /// prices, and about a third of what a WRITTEN document already pays in
    /// frontier keys, since its content, link and version chains open one
    /// full-tumbler key each. So a reader sizing a checkpoint from `frontiers`'
    /// compressed count adds one entry per document, and an EMPTY document,
    /// free before this map existed, is no longer free. No cap: the count is
    /// the docuverse's, and bounding it would bound the product rather than
    /// refuse a resource.
    ///
    /// OPEN DECISION (collection shape — the delta names none): an `OrdMap`.
    /// The read is a point lookup either way — O(log |documents|) tumbler
    /// compares here — and what the ordered map buys is a checkpoint encoding
    /// and an iteration order that are functions of the contents: two boards
    /// with one history checkpoint this field to one byte string, and
    /// [`M3State::documents`], the walk the exception set's seed makes,
    /// yields them in address order. `nodes` and `principals` already pay
    /// that price for the same reason, and `frontiers` does since option (i).
    publication: im::OrdMap<Address, bool>,
}

// ---------------------------------------------------------------------------
// The two registry caps.
// ---------------------------------------------------------------------------

/// The cap on a registered node address's component COUNT, enforced by
/// [`crate::Namespace::register_node`]
/// ([`crate::RegisterNodeError::TooDeep`]; §7).
///
/// `nodes` is one of the two registries M3 cannot keep in frontier form (the
/// other is `principals` — [`MAX_PRINCIPAL_COMPONENTS`]): a namespace's
/// realized set is a single count, but node addresses originate outside the
/// docuverse (ASN-0047 NodeBaptism) and may be non-contiguous, so each is
/// stored WHOLE, permanently (B0 — there is no deletion), and re-serialized
/// into every checkpoint thereafter; and because the set is ordered, a deep
/// or large-magnitude entry lengthens every later `nodes` probe.
///
/// What the cap closes is the per-component FIXED overhead: each component
/// occupies a `Vec<Nat>` element plus its own heap magnitude allocation — ~32
/// bytes resident — against ~2 bytes of dotted decimal to supply, so a small
/// component is a ~16× permanent, replicated charge. 32 leaves an order of
/// magnitude over any physical provisioning hierarchy (one component per
/// level of region/site/rack/host and the like) while capping that overhead
/// near a kilobyte per entry.
///
/// What it does NOT close is component MAGNITUDE, which M1 leaves unbounded
/// (T0(b)): `[1, 2^100000]` is two components and megabytes of entry. That is
/// permanent and replicated like any entry, but it is not an amplification —
/// a K-byte magnitude costs ~2.4K bytes to supply, so wire bytes exceed
/// resident bytes. It is worth knowing that `register_node` is the ONLY path
/// by which a caller's chosen component VALUES enter the permanent name space
/// at all: every other address M3 mints is a registered parent extended by
/// separators, the subspace identifiers 1/2, and frontier ordinals bounded by
/// the mint count — so every address under a node inherits that node's
/// magnitudes. A magnitude bound, if a deployment wants one, belongs where
/// the codec parses a tumbler, not here.
pub const MAX_NODE_COMPONENTS: usize = 32;

/// The cap on a principal prefix's component COUNT, enforced by
/// [`crate::Namespace::delegate`] ([`crate::DelegateError::TooDeep`]; §6).
///
/// `principals` is the SECOND registry M3 cannot keep in frontier form: a
/// prefix is stored WHOLE, permanently (O12 — there is no revocation),
/// re-serialized into every checkpoint, ordered (so a deep entry lengthens
/// every later range probe), and — unlike a `nodes` entry — walked by every ω
/// query in the system. Its component count is the caller's, one per level of
/// delegation nesting, and at ~32 bytes resident against ~2 bytes of dotted
/// decimal to supply it is the same ~16× permanent, replicated charge
/// [`MAX_NODE_COMPONENTS`] bounds for `nodes`.
///
/// The number: a prefix is `node_field ++ [0] ++ account_field` in M1's
/// accessors — its node field, then its user field (T4b's `U`) — the node
/// field already bounded by [`MAX_NODE_COMPONENTS`], and the user field
/// grows one component per delegation. 64 leaves 31 levels of nesting under
/// the deepest admissible node — an order of magnitude over any authority
/// hierarchy (operator → org → division → team → project is five) — and holds
/// one permanent entry near 2 KB, twice the node cap's ceiling for twice its
/// components. It also caps what an UNAUTHENTICATED deep prefix can command
/// before `delegate` reaches its first gate, which is the half of the charge
/// no economics bound: the full-depth `parent` clone, the
/// nine-bytes-per-component lock key, and the transaction that takes the
/// account-chain and global-principals keys. Depth in the registry ITSELF
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

/// The bootstrap node root `[1]` (Σ₀) — the single definition genesis seeds
/// from and `register_node`'s lineage check probes against. `Nat` is a
/// big-int and so cannot be `const`, so the address is built once and
/// borrowed thereafter.
pub(crate) fn bootstrap_root() -> &'static Address {
    static ROOT: LazyLock<Address> = LazyLock::new(|| {
        let root = Tumbler::new([Nat::from(1u32)]).expect("a one-component sequence is nonempty");
        validate(root).expect("the bootstrap root [1] is T4-valid")
    });
    &ROOT
}

/// The SYSTEM NODE `1.1` (PUB-6.65, RES-304) — a node under the bootstrap
/// node `[1]`, the one the system account is delegated under, registered by
/// [`M3State::genesis`]. The seed lives under THIS node's allocator, never
/// under node `[1]`'s, so node `[1]`'s own account frontier — the input the
/// claim floor reads (`next_account_prefix([1])`, PUB-6.52) — stays exactly
/// what it was, and the honest claim admits as before.
pub fn system_node() -> Address {
    let t = Tumbler::new([1u32, 1].into_iter().map(Nat::from))
        .expect("a two-component sequence is nonempty");
    validate(t).expect("the system node 1.1 is T4-valid by construction")
}

/// The SYSTEM ACCOUNT `1.1.0.1` (PUB-6.65, RES-304) — the commons account of
/// the design, owned by [`SYSTEM_PRINCIPAL`] and seeded by [`M3State::genesis`]
/// with its doc 1 (the commons registry's future home, which IS
/// [`ghost_home_document`]) and its doc 2 (the daemon's head document `H`),
/// both born published. Its account chain sits under [`system_node`].
pub fn system_account() -> Address {
    let t = Tumbler::new([1u32, 1, 0, 1].into_iter().map(Nat::from))
        .expect("a four-component sequence is nonempty");
    validate(t).expect("the system account 1.1.0.1 is T4-valid by construction")
}

/// The head document `H` = `1.1.0.1.0.2` (PUB-6.65, RES-304) — doc 2 of
/// [`system_account`], the NEW-VERSION-PER-HEAD document the daemon writes.
/// Seeded born published by [`M3State::genesis`]. This is `H`'s one spelling:
/// the seed registers the document it builds and the daemon's head writer
/// writes the document it builds, so the two cannot come apart.
pub fn head_document() -> Address {
    let t = Tumbler::new([1u32, 1, 0, 1, 0, 2].into_iter().map(Nat::from))
        .expect("a six-component sequence is nonempty");
    validate(t).expect("the head document 1.1.0.1.0.2 is T4-valid by construction")
}

impl M3State {
    /// Σ₀ + O14, plus the SYSTEM ACCOUNT seed (PUB-6.65, RES-304): `nodes =
    /// {[1], [1.1]}`, `Π = { [1] → BOOTSTRAP_PRINCIPAL, [1.1.0.1] →
    /// SYSTEM_PRINCIPAL }`, the account chain `([1.1], 2)` at 1 and the
    /// document chain `([1.1.0.1], 2)` at 2, and both documents born published.
    /// `pub` — the engine seeds `Kernel::open(cfg, genesis-World)` with it;
    /// "load empty journal" and "fresh genesis" are the same code path (§7).
    /// Deterministic, per M2's byte-identical-genesis caller contract — and
    /// byte-identical ACROSS PROCESSES because every field is ordered (since
    /// option (i) the frontier map too).
    ///
    /// TWO PARTS, built two ways. The ROOTS — node `[1]` and π₀ seated at it —
    /// are written directly: they are the state every record folds onto, and
    /// π₀'s node-tier seat is a shape no op stages and `RegisterPrincipal`'s
    /// prefix door refuses. The SEED is folded: it is the five records
    /// M3's own ops stage for the same work —
    /// [`crate::Namespace::register_node`]'s admission of [`system_node`]
    /// `1.1`, [`crate::Namespace::delegate`]'s baptism and seat of
    /// [`system_account`] `1.1.0.1` for [`SYSTEM_PRINCIPAL`], and the
    /// allocations of the two documents
    /// [`crate::Namespace::create_new_document`] mints there, doc 1
    /// ([`ghost_home_document`], the commons registry's future home) and doc 2
    /// ([`head_document`] `H`), born PUBLISHED (PUB-1.25's
    /// genesis/commons-seeded row) — handed to [`M3State::apply_m3`] in that
    /// order. So the fold is the one writer of the frontier and publication
    /// maps: each chain reaches its count by the fold's own `+1`, each
    /// document's bit lands in the step that registers it, and the fold's
    /// contiguity check confirms, on every debug build, that the account and
    /// each document is the next member of its own chain. A document added to
    /// the seed is one more record.
    ///
    /// What the seed leaves alone: node `[1]`'s own account chain — the
    /// seeded account chain is `([1.1], 2)`, not `([1], 2)` — so
    /// `next_account_prefix([1])` answers `1.0.1`; and CONTENT — both
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
        };
        let seed = [
            // `register_node`: the system node 1.1.
            M3Rec::RegisterNode {
                addr: system_node(),
            },
            // `delegate`: the system account 1.1.0.1, baptized and seated.
            M3Rec::Allocate {
                addr: system_account(),
                published: NO_PUBLICATION_STATE,
            },
            M3Rec::RegisterPrincipal {
                prefix: system_account(),
                id: SYSTEM_PRINCIPAL,
            },
            // Two creates under it, both born published: doc 1, then doc 2 (H).
            M3Rec::Allocate {
                addr: ghost_home_document(),
                published: true,
            },
            M3Rec::Allocate {
                addr: head_document(),
                published: true,
            },
        ];
        seed.iter().fold(roots, |s, r| s.apply_m3(r))
    }

    /// M3's fold — `pub`: the engine crate wires `World::apply`'s dispatch of
    /// the variant carrying an [`M3Rec`] to this. TOTALITY DOMAIN (M2's
    /// total-apply obligation, stated here at the seam the engine wires):
    /// total — deterministic, side-effect-free, panic-free — over every record
    /// whose `Allocate` address BOTH extends a parent AND carries its
    /// namespace's effective frontier + 1 as its ordinal (effective =
    /// `max(frontier, floor)`; the floor is nonzero only for the ghost content
    /// namespace — `ghost_floor`). A mint's record is such a record wherever
    /// it is staged as [`M3Rec::Allocate`] requires — against the working
    /// state the mint read: a mint extends a REGISTERED parent and emits
    /// exactly `c_{m+1}` of that state, past the floor. That the parent is
    /// REGISTERED (P8) is the mints' gate and no part of this domain: an
    /// `Allocate` under an unregistered parent folds like any other, and that
    /// is the state [`M3State::has_documents`] and [`M3State::latest_version`]
    /// answer by their chains.
    ///
    /// The two conditions differ in kind, and only the first is owed to the
    /// journal. Extending a parent is a fact about one field, so it is carried
    /// at that field's door: the [`Address`] payloads carry T4-validity and
    /// `Allocate`'s address door (`parented_address`) carries the parent, and
    /// a record arriving from disk or a peer that lacks either is refused at
    /// decode rather than folded into a panic. Contiguity is NOT decidable
    /// from one record — it is a claim about the frontier the record is about
    /// to advance — so no door can carry it, and it stays a stated condition
    /// of the caller: an `Allocate` that regresses or jumps a frontier is
    /// outside the domain — corruption, or a caller's bug, a mint's record
    /// staged where [`M3Rec::Allocate`] forbids, rather than a live error
    /// path. A debug build fail-stops on the contiguity `debug_assert`; a
    /// release build folds the record as written, moving the frontier to its
    /// ordinal. What the fold trusts for both conditions is an IN-PROCESS
    /// producer, which builds the variant directly.
    ///
    /// `Allocate`'s publication bit is folded for a DOCUMENT-tier address and
    /// read for no other (PUB-7.7's fold half, at M3's own allocation record:
    /// the publication map and the registration reach a reader in the ONE
    /// commit that carries that record, never a later step). The write is
    /// INSERT-IF-ABSENT, so the bit a document was minted with is the bit that
    /// stands (PUB-1.9) on EVERY build, and not merely inside the totality
    /// domain: the contiguity check is a `debug_assert` and cannot be what
    /// holds an immutability a second record would otherwise overwrite in
    /// release. Registration-membership is the one per-arm fact no door can
    /// carry — "this address is already registered" is a claim about the
    /// registry, which a decoder holding one frame cannot settle — so it is
    /// answered here, at one lookup, rather than refused at decode.
    ///
    /// `RegisterNode`'s admission conditions — node level, the
    /// [`MAX_NODE_COMPONENTS`] cap, and bootstrap lineage — belong to
    /// [`crate::Namespace::register_node`] and are NOT invariants of `nodes`.
    /// The fold neither re-establishes them nor could refuse, and the record
    /// door deliberately does not carry them either: a depth check
    /// at the door would refuse a record M3 itself wrote before the cap
    /// existed, turning a resource charge into an unreplayable journal. What a
    /// violation costs is bounded and never a pass — a non-node-level entry is
    /// unreachable, since [`M3State::is_allocated`] consults `nodes` only on
    /// the `Node` arm; an off-lineage node is inert, since no principal covers
    /// it and so `delegate` beneath it is refused `NotAncestor` at (i); and an
    /// over-cap entry is a permanent resource charge and nothing more.
    ///
    /// `RegisterPrincipal`'s tier is a fact about one field, so it rides at
    /// that field's door like `Allocate`'s parent: the prefix door
    /// (`account_tier_prefix`) admits an account-tier prefix and nothing
    /// else, which is what `delegate` stages and what ω's
    /// O1a filter cannot refuse on its own (node tier is a pass there, for
    /// π₀'s sake). A seat is WRITTEN ONCE, like a document's bit: a
    /// `RegisterPrincipal` naming a prefix already seated leaves the seated
    /// principal alone (O12/O13 — principals persist and prefixes are
    /// immutable; no op re-seats, since `delegate` seats only a fresh
    /// prefix). Whether a prefix is seated is a claim about the registry,
    /// which no door holding one frame can settle, so the fold answers it at
    /// one lookup, on every build. Two facts that arm does NOT check are its
    /// producer's, and [`M3Rec::RegisterPrincipal`] states both. The prefix's
    /// allocation is one: a seat folds whether or not its prefix is
    /// allocated, as an account's `Allocate` folds without a seat, so their
    /// coupling is the producer invariant `delegate` keeps by staging both in
    /// one transaction (O17b). Id-injectivity is the other, and leaving it
    /// unchecked is deliberate rather than missing: one id ↦ at most one
    /// principal is a PRODUCER invariant, owned by `delegate`'s `DuplicateId`
    /// gate alone. The fold could check it — an arm sees the whole slice —
    /// but Π is keyed by prefix, so the check is a Θ(|Π|) scan per replayed
    /// seat, making replay of N delegations Θ(N²); and it has no fail-safe
    /// direction, since skipping the seat would leave the account its
    /// transaction allocated unseated. What rests on it is
    /// [`M3State::principal_prefix`]'s single-valuedness, and through it
    /// `fork`'s account and M5's cross-owner VERSION target: a
    /// `RegisterPrincipal` from any producer but `delegate` would seat a
    /// second principal on a live id and make all three arbitrary. `delegate`
    /// is its sole producer on the journal; genesis folds one more —
    /// `SYSTEM_PRINCIPAL`'s seat, onto roots where only π₀'s id is live —
    /// before any delegation can run, and from then on `delegate`'s
    /// `DuplicateId` gate refuses that id. Any other producer owes both
    /// clauses, and no type enforces them.
    #[must_use = "apply_m3 returns the folded slice; it does not modify the receiver"]
    pub fn apply_m3(&self, r: &M3Rec) -> M3State {
        let mut s = self.clone();
        match r {
            M3Rec::Allocate { addr, published } => {
                let key = namespace_of(addr).expect(
                    "≥ 2 components: Allocate's address door refuses a parentless address off the journal, and the totality domain asks it of an in-process producer",
                );
                let n = ordinal(addr.tumbler()).clone();
                // The totality domain's contiguity condition. Its floor term
                // matters once per journal: the ghost home document's first
                // content Allocate carries ordinal GHOST_POSITIONS + 1 over an
                // absent frontier.
                debug_assert_eq!(
                    n,
                    s.effective_frontier(&key) + 1u32,
                    "Allocate ordinal must equal its namespace's effective frontier + 1"
                );
                s.frontiers.insert(key, n);
                // Written once (PUB-1.9) on every build: this `contains_key`
                // test holds it in release, where the check above is absent.
                if addr.level() == Level::Document && !s.publication.contains_key(addr) {
                    s.publication.insert(addr.clone(), *published);
                }
            }
            M3Rec::RegisterNode { addr } => {
                s.nodes.insert(addr.clone());
            }
            M3Rec::RegisterPrincipal { prefix, id } => {
                // Written once (O12/O13): the first seat stands.
                if !s.principals.contains_key(prefix) {
                    s.principals.insert(prefix.clone(), *id);
                }
            }
        }
        s
    }
}

// ---------------------------------------------------------------------------
// §1 The frontier allocator (the heart).
// ---------------------------------------------------------------------------

impl M3State {
    /// The frontier `next_in` mints past and the fold's contiguity check
    /// expects: `max(frontiers[key], ghost_floor(key))`. For every namespace
    /// but the ghost content one the floor is 0 and this IS the stored
    /// frontier; for that one it starts the chain past the ghost region
    /// ([`ghost_floor`] carries the non-reissue argument). NOT the membership
    /// bound — membership reads the STORED frontier and excludes the floored
    /// ordinals, because a floor that counted as members would make the five
    /// ghost tumblers allocated without a mint. Given that exclusion the two
    /// bounds agree, so membership stays on the stored value, which it can
    /// borrow.
    fn effective_frontier(&self, key: &NsKey) -> Nat {
        self.frontiers
            .get(key)
            .cloned()
            .unwrap_or_else(Nat::zero)
            .max(ghost_floor(key))
    }

    /// `next(B, p, g)` in closed form (§1): the chain `S(p, g)` is
    /// `cₙ = p ++ [0]^(g−1) ++ [n]`, so the next address is
    /// `c_{m+1}` — read the count, advance the trailing ordinal — which is
    /// [`nth_in`] at `m + 1`, where `m` is the
    /// [`M3State::effective_frontier`] (the stored count, floored past the
    /// ghost region for the one namespace that holds it). Pure function of
    /// `frontiers` (B2 determinism — the natural property-test oracle). M1's
    /// `checked_inc` is the TA5a gate ⇒ B6(ii)/(iii); routing every emission
    /// through it, via `first_in`, is the defensive guard: it cannot fire on
    /// a live path, nor on any frontier COUNT, since `first_in` sees only the
    /// anchor — only on a key that fails `first_in`'s anchor precondition.
    ///
    /// That precondition is `first_in`'s, stated in `crate::ns` beside the
    /// `validate` that consumes it, and the five mints — this function's only
    /// callers, one per chain — each meet it by a gate that has already run:
    /// [`version_ns`] and [`document_ns`] clone their anchor from an
    /// [`Address`], as does [`account_ns`] behind
    /// [`M3State::mint_account`]'s registered-entity gate; and
    /// [`content_ns`]/[`link_ns`] sit behind `is_registered_document`, which
    /// makes `home` a Document, so `inc(home, 2)` lands inside T4.
    ///
    /// [`version_ns`]: crate::ns::version_ns
    /// [`document_ns`]: crate::ns::document_ns
    /// [`account_ns`]: crate::ns::account_ns
    /// [`content_ns`]: crate::ns::content_ns
    /// [`link_ns`]: crate::ns::link_ns
    fn next_in(&self, key: &NsKey) -> Result<Address, GateViolation> {
        nth_in(key, &(self.effective_frontier(key) + 1u32))
    }
}

#[cfg(test)]
mod tests;
