//! M3's slice (§Core data model, §1): the identity type and its two fixed
//! ids; the journal delta [`M3Rec`] and its at-rest door; [`M3State`] itself;
//! the two registry caps; Σ₀ — the fixed addresses genesis seeds — with
//! genesis and the fold (§D); and the frontier arithmetic the fold checks and
//! the mints draw on (§1). Namespace keys are `crate::ns`'s, and the ghost
//! floor is `crate::ghost`'s.
//!
//! Beneath it, two children, each an `impl M3State` that sees this module's
//! private items the way a child does, so nothing here is widened for them:
//!
//! * [`mint`] — §A: the lock keys a transaction holds, the five mints, and
//!   the account chain's peek.
//! * [`query`] — §C: entity membership (§2), the publication reads, the
//!   principal registry and the ω resolver (§5).
//!
//! The unit tests for the slice and both children are `state/tests.rs`.

// §A: the lock keys a transaction holds, the five mints, the account peek.
mod mint;
// §C: membership, the publication reads, the principal registry and ω.
mod query;

pub use query::prefix_contains;

use std::sync::LazyLock;

use num_traits::Zero;
use serde::{Deserialize, Serialize};
use skep_address::{ordinal, validate, Address, GateViolation, Level, Nat, Tumbler};

use crate::ghost::{ghost_floor, ghost_home_doc};
use crate::ns::{namespace_of, nth_in, NsKey};

/// Opaque external identity, supplied by M10/session. `delegate` enforces
/// id-injectivity ([`crate::DelegateError::DuplicateId`]) ⇒ one id ↦ one
/// principal, which keeps [`M3State::principal_prefix`] and the ω-auth gate
/// single-valued (§6).
///
/// The order is the underlying numeral's and carries no ownership meaning —
/// ownership is decided by prefix length, never by id (§5). It is here
/// because an id is a map key and a sort key: the `id → prefix` reverse index
/// [`M3State`] names as a recomputable hint wants a `BTreeMap`, whose
/// iteration order is deterministic where a hashed one's is the process's
/// hash seed, and no downstream crate can add the impl.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Serialize, Deserialize)]
pub struct PrincipalId(pub u64);

/// π₀'s fixed id (genesis Σ₀, O14); the ω-auth gate keys on it, so M10 binds
/// the bootstrap session to it. `delegate`'s id-freshness gate then prevents
/// any later principal from re-claiming id 0 (§7).
pub const BOOTSTRAP_PRINCIPAL: PrincipalId = PrincipalId(0);

/// The SYSTEM ACCOUNT's fixed principal (PUB-6.65, RES-304): the id genesis
/// seats at [`system_account`] `1.1.0.1`, the commons/system account the
/// board's own daemon writes the published head document into. Never `0` (that
/// is [`BOOTSTRAP_PRINCIPAL`]) and a reserved sentinel no client can seat: the
/// account holds no key and can never enrol one (AUTH-6.19's cell — a keyless
/// account answers empty lists), and [`crate::Namespace::delegate`]'s
/// id-freshness gate refuses this id `DuplicateId` because genesis has already
/// registered it (§6/§7). So no principal but the one genesis seats ever bears
/// it, and it can act only in-process, never over a session.
///
/// The VALUE is a conspicuous reserved sentinel — `9 × 10^15`, well below the
/// wire's `2^53 − 1` exact-integer cap (AUTH-5.20) yet far above any ordinary
/// delegation — so a client's attempt to re-seat it PARSES and reaches the
/// freshness gate, refused `duplicate_id` (the "not fresh" refusal PUB-6.65
/// names), rather than being turned away earlier as an unrepresentable number.
pub const SYSTEM_PRINCIPAL: PrincipalId = PrincipalId(9_000_000_000_000_000);

/// M3's journal deltas — lifted to `W::Record` via the engine's `From<M3Rec>`
/// impl (the write-side mirror of [`crate::HasM3`]) and folded by
/// [`M3State::apply_m3`]. Every address payload is an [`Address`], so
/// T4-validity is carried by the value: checked once where the record is
/// built, and re-checked on the way back off the journal by M1's validating
/// `Deserialize`. A record still journals as a bare, flat tumbler, exactly as
/// the data model prescribes. One `Allocate` variant suffices for every minted
/// address (entity, content, link) because the frontier map is uniform; the
/// level distinction is recovered at *query* time from the address's own
/// level.
///
/// Off the journal a record arrives through [`M3RecShadow`], which re-checks
/// the two standing facts T4-validity does not carry: an `Allocate` address
/// extends a parent, and a `RegisterPrincipal` prefix is account-tier — and
/// which carries the publication bit as a REQUIRED field (PUB-7.8).
///
/// A variant or field added HERE must be added to [`M3RecShadow`] too:
/// `Serialize` is derived from this enum and `Deserialize` runs through the
/// shadow, so a shadow missing the variant yields records that journal and
/// then never decode — a recovery failure that survives restart, from an edit
/// that looked local.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "M3RecShadow")]
pub enum M3Rec {
    /// A mint's COMMIT HALF: advance `frontiers[namespace_of(addr)]` (§1) —
    /// this record is the only thing that moves a frontier. The `(parent, g)`
    /// of an `Allocate` is exactly the `NsKey` of the `LockKey` the minting op
    /// held — frontier key and lock key are the same key.
    ///
    /// `published` is the RESOLVED publication state of a minted DOCUMENT
    /// (PUB-7.8, PUB-7.10, PUB-8.18): every document-minting record journals
    /// the bit its caller resolved — never the caller's three-valued flag, so
    /// replay reconstructs the world that committed and not a re-derivation
    /// from the op's arguments — and [`M3State::apply_m3`] folds it into the
    /// publication map for a Document-tier `addr` (a version is a document
    /// too). IMMUTABLE after mint: no op changes it, there is no publish op in
    /// either direction (PUB-1.9, PUB-1.68), and no LATER record changes it
    /// either — the fold writes the entry only where none is held, so a second
    /// `Allocate` naming a registered document leaves its bit alone. Outside the
    /// document tier — an account, a content or link element — publication is
    /// not a property of the address at all (PUB-1.68: one bit per DOCUMENT);
    /// those mints stamp `NO_PUBLICATION_STATE` (`false`) and the fold does
    /// not read it. NON-OPTIONAL by design: a record written without the
    /// field fails to decode at [`M3RecShadow`] rather than defaulting
    /// (PUB-7.8).
    Allocate { addr: Address, published: bool },
    /// External node admission (ASN-0047 NodeBaptism; §7).
    RegisterNode { addr: Address },
    /// Delegation's principal half (§6).
    RegisterPrincipal { prefix: Address, id: PrincipalId },
}

/// The `published` an `Allocate` carries OUTSIDE the document tier — an
/// account, a content or link element — where publication is not a property
/// of the address at all (PUB-1.68: one bit per DOCUMENT, and nothing else
/// carries one). [`M3State::apply_m3`] reads the bit only for a Document-tier
/// address, so this value is never consulted; it is named so the three
/// non-document mints, and genesis's account record, say what they stamp and
/// why, and so a reader of a journal frame knows the `false` on an account or
/// element `Allocate` is an absence and not a verdict.
const NO_PUBLICATION_STATE: bool = false;

/// The at-rest shadow of [`M3Rec`] — same variants in the same order, same
/// fields in the same order, so the journal and checkpoint encoding is the
/// enum's own — and the ONE door a record re-enters memory through.
///
/// It carries the standing fact [`M3State::apply_m3`]'s `namespace_of`
/// `expect` rests on, and which the [`Address`] type does NOT: a minted
/// address extends a parent. `[7]` is T4-valid, so M1's door passes it, and a
/// parentless `Allocate` reaching the fold would panic the applier — at
/// replay too, on every subsequent open. For a T4-valid address
/// `parent(a).is_some()` ⟺ `#a ≥ 2` (M1's `parent` is `None` only for a
/// single-component node), so the check is one length compare, and it turns a
/// permanent applier panic into M2's ordinary decode failure.
///
/// It carries the other per-record fact a seat needs, and the one whose
/// absence fails OPEN: a `RegisterPrincipal` prefix is account-tier.
/// `delegate` is its sole producer on the journal and its hoisted
/// `NotAccountTier` gate stages nothing else, so the door refuses nothing M3
/// has ever journaled — genesis's node-tier π₀ seat is world state, passed to
/// `Kernel::open`, not a record, and the one seat genesis folds,
/// `SYSTEM_PRINCIPAL`'s, is account-tier. The tier matters because ω's O1a
/// filter ADMITS node tier (it must, for π₀): a node-tier seat arriving on
/// the journal would make its carrier the effective owner of everything under
/// that node no deeper account principal covers — including the unallocated
/// subtree, so it could seat that node's first account, the operator seat
/// `register_node`'s postcondition leaves to whoever owns the covering
/// prefix. A below-tier seat is refused by every reader of Π already; this is
/// the shape that is not.
///
/// The door is therefore tighter than O1a, and deliberately: a STATE-level
/// door could not be, since genesis's seat is node-tier, so [`M3State`]'s
/// bare-derive checkpoint path keeps that exposure and
/// [`M3State::effective_owner`]'s tier filter is not removable. An op that
/// ever seats a principal at a node prefix changes this door first.
///
/// A per-record door carries per-record facts and no others. The standing
/// property `RegisterPrincipal` would want besides — id-injectivity across Π
/// — is not one: it is a claim about the principal registry the record is
/// about to enter, which no decoder holding a single frame can settle. That
/// invariant has one owner, `delegate`'s `DuplicateId` gate, and this door
/// does not share it.
///
/// The publication bit is a REQUIRED field here, exactly as on [`M3Rec`] —
/// no `Option`, no `#[serde(default)]` (PUB-7.8): a journal frame or a
/// checkpoint written before the bit existed ends where the bit should
/// begin, and the decoder's end-of-input there is the refusal. M2 treats a
/// decode failure as "replay from an older start point, else refuse to
/// serve" (PUB-7.9); what this door owes is that the failure HAPPENS, and
/// that no pre-publication record is ever read as private or as published
/// by a default it never carried (PUB-1.2: no grandfather clause).
#[derive(Deserialize)]
enum M3RecShadow {
    Allocate { addr: Address, published: bool },
    RegisterNode { addr: Address },
    RegisterPrincipal { prefix: Address, id: PrincipalId },
}

impl TryFrom<M3RecShadow> for M3Rec {
    type Error = &'static str;
    fn try_from(shadow: M3RecShadow) -> Result<M3Rec, &'static str> {
        match shadow {
            M3RecShadow::Allocate { addr, .. } if addr.tumbler().len() < 2 => {
                Err("an Allocate address extends a parent (≥ 2 components)")
            }
            M3RecShadow::Allocate { addr, published } => Ok(M3Rec::Allocate { addr, published }),
            M3RecShadow::RegisterNode { addr } => Ok(M3Rec::RegisterNode { addr }),
            M3RecShadow::RegisterPrincipal { prefix, .. } if prefix.level() != Level::Account => {
                Err("a RegisterPrincipal prefix is account-tier (delegate's O15(iii) gate)")
            }
            M3RecShadow::RegisterPrincipal { prefix, id } => {
                Ok(M3Rec::RegisterPrincipal { prefix, id })
            }
        }
    }
}

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
    /// admits the system sub-node `[1.1]` beside it (PUB-6.65).
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
    /// read one value. Small (node/account tier only, O1a). Append-only with
    /// immutable prefixes (O12/O13).
    ///
    /// Three standing properties, and they hold by three different means:
    ///
    /// * prefix-injectivity (O1b, by (v)) is STRUCTURAL, carried by the map's
    ///   own key;
    /// * id-injectivity (`delegate`'s `DuplicateId` gate, §6) is a PRODUCER
    ///   invariant, established at that one gate and never re-established by
    ///   [`M3State::apply_m3`] — it is what makes the by-id scan
    ///   single-valued;
    /// * the account-tier floor (O1a) is a PRODUCER invariant too, owned by
    ///   genesis (which seats π₀ at the node prefix `[1]`) and by `delegate`'s
    ///   hoisted `NotAccountTier` gate. On the journal path [`M3RecShadow`]
    ///   re-establishes it — stricter than O1a, since every seat `delegate`
    ///   stages is account-tier exactly — but a seat can also arrive inside a
    ///   whole [`M3State`], which decodes by bare derive because genesis's own
    ///   seat is node-tier. So [`M3State::effective_owner`] re-checks it as
    ///   well, ω being the one reader whose answer to a below-tier entry would
    ///   be a PASS; see the tier filter there.
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
    /// [`M3State::apply_m3`] and written by nothing else: there is no publish
    /// op and no transition (PUB-1.9, PUB-1.11), so an entry is written once,
    /// at mint, and stands forever. AUTHORITATIVE working state like its
    /// three siblings — an ordinary serde field, restored from the checkpoint
    /// and advanced by replay, never `#[serde(skip)]` — and the engine's
    /// exception set (PUB-7.5) is a derived membership index OVER it
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
/// [`crate::Namespace::register_node`] ([`crate::NodeError::TooDeep`]; §7).
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
/// occupies a `Vec<Nat>` slot plus its own heap magnitude allocation — ~32
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
/// resident bytes. It is worth knowing that `register_node` is the ONLY door
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
/// The number: a prefix is `node_field ++ [0] ++ account_field`, the node
/// field already bounded by [`MAX_NODE_COMPONENTS`], and the account field
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
// §D Σ₀ — the fixed addresses genesis seeds — and the fold.
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

/// The SYSTEM SUB-NODE `1.1` (PUB-6.65, RES-304) — the node the system
/// account is delegated under, registered by [`M3State::genesis`]. The seed
/// lives under THIS sub-node's allocator, never under node `[1]`'s, so node
/// `[1]`'s own account frontier — the input the claim floor reads
/// (`next_account_prefix([1])`, PUB-6.52) — stays exactly what it was, and the
/// honest claim admits as before.
pub fn system_node() -> Address {
    let t = Tumbler::new([1u32, 1].into_iter().map(Nat::from)).expect("a two-component sequence is nonempty");
    validate(t).expect("the system node 1.1 is T4-valid by construction")
}

/// The SYSTEM ACCOUNT `1.1.0.1` (PUB-6.65, RES-304) — the commons account of
/// the design, owned by [`SYSTEM_PRINCIPAL`] and seeded by [`M3State::genesis`]
/// with its doc 1 (the commons registry's future home, which IS
/// [`ghost_home_doc`]) and its doc 2 (the daemon's head document `H`), both
/// born published. Its account chain sits under [`system_node`].
pub fn system_account() -> Address {
    let t = Tumbler::new([1u32, 1, 0, 1].into_iter().map(Nat::from)).expect("a four-component sequence is nonempty");
    validate(t).expect("the system account 1.1.0.1 is T4-valid by construction")
}

/// The head document `H` = `1.1.0.1.0.2` (PUB-6.65, RES-304) — doc 2 of
/// [`system_account`], the NEW-VERSION-PER-HEAD document the daemon writes.
/// Seeded born published by [`M3State::genesis`]. This is `H`'s one spelling:
/// the seed registers the document it builds and the daemon's head writer
/// writes the document it builds, so the two cannot come apart.
pub fn head_document() -> Address {
    let t = Tumbler::new([1u32, 1, 0, 1, 0, 2].into_iter().map(Nat::from)).expect("a six-component sequence is nonempty");
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
    /// π₀'s node-tier seat is a shape no op stages and the record door
    /// (`M3RecShadow`) refuses. The SEED is folded: it is the five records
    /// M3's own ops stage for the same work —
    /// [`crate::Namespace::register_node`]'s admission of [`system_node`]
    /// `1.1`, [`crate::Namespace::delegate`]'s baptism and seat of
    /// [`system_account`] `1.1.0.1` for [`SYSTEM_PRINCIPAL`], and the
    /// allocations of the two documents
    /// [`crate::Namespace::create_new_document`] mints there, doc 1
    /// ([`ghost_home_doc`], the commons registry's future home) and doc 2
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
    /// frontier and its floor ([`ghost_floor`], [`GHOST_POSITIONS`]) stands.
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
            // `register_node`: the system sub-node 1.1.
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
                addr: ghost_home_doc(),
                published: true,
            },
            M3Rec::Allocate {
                addr: head_document(),
                published: true,
            },
        ];
        seed.iter().fold(roots, |s, r| s.apply_m3(r))
    }

    /// M3's fold — `pub`: the engine crate wires `World::apply`'s `Record::M3`
    /// dispatch to this. TOTALITY DOMAIN (M2's total-apply obligation, stated
    /// here at the seam the engine wires): total — deterministic,
    /// side-effect-free, panic-free — over every record whose `Allocate`
    /// address BOTH extends a parent AND carries its namespace's effective
    /// frontier + 1 as its ordinal (effective = `max(frontier, floor)`; the
    /// floor is nonzero only for the ghost content namespace —
    /// [`ghost_floor`]). Every mint's does: a mint extends a REGISTERED
    /// parent and emits exactly `c_{m+1}` past the floor.
    ///
    /// The two conditions differ in kind, and only the first is owed to the
    /// journal. Extending a parent is a per-record fact, so it is carried at
    /// the door: the [`Address`] payloads carry T4-validity and
    /// [`M3RecShadow`] carries the parent, and a record arriving from disk or
    /// a peer that lacks either is refused at decode rather than folded into a
    /// panic. Contiguity is NOT decidable from one record — it is a claim
    /// about the frontier the record is about to advance — so no door can
    /// carry it, and it stays a stated condition of the caller: an `Allocate`
    /// that regresses or jumps a frontier is outside the domain and fail-stops
    /// on the contiguity `debug_assert`, which is corruption rather than a
    /// live error path. What the fold trusts for both is an IN-PROCESS
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
    /// `RegisterPrincipal`'s tier is a per-record fact, so it rides at the
    /// door like `Allocate`'s parent: the record door admits an account-tier
    /// prefix and nothing else, which is what `delegate` stages and what ω's
    /// O1a filter cannot refuse on its own (node tier is a pass there, for
    /// π₀'s sake). Id-injectivity is the fact that arm has no gate for, and
    /// that is deliberate rather than missing: one id ↦ at most one
    /// principal is a PRODUCER invariant, owned by `delegate`'s
    /// `DuplicateId` gate alone; the fold neither re-checks nor re-establishes
    /// it, and could not, since the property is about the whole principal
    /// registry and a fold arm sees one record. What rests on it is
    /// [`M3State::principal_prefix`]'s single-valuedness, and through it
    /// `fork`'s account and M5's cross-owner VERSION target: a
    /// `RegisterPrincipal` from any producer but `delegate` would seat a
    /// second principal on a live id and make all three arbitrary. `delegate`
    /// is its sole producer on the journal; genesis folds one more —
    /// `SYSTEM_PRINCIPAL`'s seat, onto roots where only π₀'s id is live —
    /// before any delegation can run, and from then on `delegate`'s
    /// `DuplicateId` gate refuses that id. M2's journal is the boundary that
    /// keeps it so.
    pub fn apply_m3(&self, r: &M3Rec) -> M3State {
        let mut s = self.clone();
        // Adding a variant? `M3RecShadow` needs it as well — see `M3Rec`.
        match r {
            M3Rec::Allocate { addr, published } => {
                let key = namespace_of(addr)
                    .expect("≥ 2 components — every mint extends a registered parent");
                let n = ordinal(addr.tumbler()).clone();
                // Contiguity fail-stop: every record M3's own paths stage
                // mints exactly c_{m+1} past the floor, so at fold time the
                // ordinal is the effective frontier + 1 — a regressed or
                // jumped ordinal is OUTSIDE the totality domain, never
                // silently absorbed. The floor term matters exactly once per
                // journal: the ghost home doc's first content Allocate carries
                // ordinal GHOST_POSITIONS + 1 over an absent frontier.
                debug_assert_eq!(
                    n,
                    s.effective_frontier(&key) + 1u32,
                    "Allocate ordinal must equal its namespace's effective frontier + 1"
                );
                s.frontiers.insert(key, n);
                // The publication bit rides only a DOCUMENT's Allocate — a
                // version is a document — and lands in the same fold step as
                // the registration, so no reader's snapshot holds the one
                // without the other (PUB-7.7). On any other tier the field is
                // `NO_PUBLICATION_STATE`, an absence, and is not read.
                //
                // WRITTEN ONCE, and by this `get` rather than by the contiguity
                // check above: that check is a `debug_assert` and is absent in
                // release, so a second `Allocate` naming a registered document
                // would otherwise REPLACE its bit — a publication transition,
                // which PUB-1.9 says does not exist and which no record door
                // can refuse (whether an address is already registered is a
                // claim about the registry, not a per-record fact). Inside the
                // totality domain the entry is absent and this is the plain
                // insert; outside it, the bit a document was minted with is
                // the bit that stands.
                if addr.level() == Level::Document && s.publication.get(addr).is_none() {
                    s.publication.insert(addr.clone(), *published);
                }
            }
            M3Rec::RegisterNode { addr } => {
                s.nodes.insert(addr.clone());
            }
            M3Rec::RegisterPrincipal { prefix, id } => {
                s.principals.insert(prefix.clone(), *id);
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
    /// anchor — only on a key whose anchor the pairing below refuses.
    ///
    /// PRECONDITION — `key.parent` is T4-valid, and under
    /// `Generator::NextField` it is not Element-level (M1's TA5a admits
    /// `k = 2` only below that tier). The five mints are the only callers,
    /// one per chain, and each discharges it by a gate that has
    /// already run: [`version_ns`] and [`document_ns`] clone their anchor
    /// from an [`Address`], as does [`account_ns`] behind
    /// [`M3State::mint_account`]'s registered-entity gate; and
    /// [`content_ns`]/[`link_ns`] sit behind `is_registered_document`, which
    /// makes `home` a Document, so `inc(home, 2)` lands inside T4. Off a
    /// checkpoint the anchor arrives through `NsKeyShadow`, which
    /// re-establishes its T4 half where no caller can; the
    /// `Generator::NextField`/Element half is a pairing that no per-key door
    /// settles and none need, since it fails as a `GateViolation` here rather
    /// than a panic.
    ///
    /// [`M3State::content_lock_key`] and [`M3State::link_lock_key`] do NOT
    /// discharge it: handed an element they build an anchor outside T4. That
    /// costs nothing, because a lock key is never dereferenced — what those
    /// two owe is [`ns_lock_key`]'s injectivity, which holds for any anchor.
    ///
    /// [`version_ns`]: crate::ns::version_ns
    /// [`document_ns`]: crate::ns::document_ns
    /// [`account_ns`]: crate::ns::account_ns
    /// [`content_ns`]: crate::ns::content_ns
    /// [`link_ns`]: crate::ns::link_ns
    /// [`ns_lock_key`]: crate::ns::ns_lock_key
    fn next_in(&self, key: &NsKey) -> Result<Address, GateViolation> {
        nth_in(key, &(self.effective_frontier(key) + 1u32))
    }
}

#[cfg(test)]
mod tests;
