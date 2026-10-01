//! M3's slice and the code over it (§Core data model, §1–§5): the identity
//! type and its two fixed ids; the journal delta [`M3Rec`] and its at-rest
//! door; [`M3State`] itself; the two registry caps; Σ₀ — the fixed addresses
//! genesis seeds — with genesis and the fold (§D); the frontier allocator and
//! its lock keys (§1); the five mints (§A); and the reads — entity membership
//! (§2), the publication map, and the principal registry with the ω resolver
//! (§C/§5). Namespace keys are `crate::ns`'s, and the ghost floor is
//! `crate::ghost`'s.

use std::sync::LazyLock;

use num_traits::Zero;
use serde::{Deserialize, Serialize};
use skep_address::{is_prefix, ordinal, validate, Address, GateViolation, Level, Nat, Tumbler};
use skep_kernel::{LockKey, Space};

use crate::error::MintError;
use crate::ghost::{ghost_floor, ghost_home_doc};
use crate::ns::{
    account_ns, content_ns, document_ns, link_ns, namespace_of, ns_lock_key, nth_in, version_ns,
    NsKey,
};

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
/// account answers empty lists), and [`Namespace::delegate`]'s id-freshness
/// gate refuses this id `DuplicateId` because genesis has already registered it
/// (§6/§7). So no principal but the one genesis seats ever bears it, and it can
/// act only in-process, never over a session.
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
/// `delegate` is the sole producer and its hoisted `NotAccountTier` gate
/// stages nothing else, so the door refuses nothing M3 has ever journaled —
/// genesis's node-tier π₀ seat is world state, passed to `Kernel::open`, not
/// a record. The tier matters because ω's O1a filter ADMITS node tier (it
/// must, for π₀): a node-tier seat arriving on the journal would make its
/// carrier the effective owner of everything under that node no deeper
/// account principal covers — including the unallocated subtree, so it could
/// seat that node's first account, the operator seat `register_node`'s
/// postcondition leaves to whoever owns the covering prefix. A below-tier
/// seat is refused by every reader of Π already; this is the shape that is
/// not.
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
    /// ASN-0040 baptism. Seeded `{[1]}`.
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
    /// private `omega` walk absorbs once, serving all three of its projections
    /// (the id, the seat, and the authorization predicate stated in terms of
    /// the id).
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

/// The `published` an `Allocate` carries OUTSIDE the document tier — an
/// account, a content or link element — where publication is not a property
/// of the address at all (PUB-1.68: one bit per DOCUMENT, and nothing else
/// carries one). [`M3State::apply_m3`] reads the bit only for a Document-tier
/// address, so this value is never consulted; it is named so the three
/// non-document mints say what they stamp and why, and so a reader of a
/// journal frame knows the `false` on an account or element `Allocate` is an
/// absence and not a verdict.
const NO_PUBLICATION_STATE: bool = false;

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
    /// WHAT THE SEED CREATES, and what it deliberately does not. It registers
    /// SUB-NODE [`system_node`] `1.1`, seats [`SYSTEM_PRINCIPAL`] at
    /// [`system_account`] `1.1.0.1` under it, and registers that account's doc
    /// 1 ([`ghost_home_doc`], the commons registry's future home) and doc 2
    /// ([`head_document`] `H`), both PUBLISHED. It touches node `[1]`'s own
    /// account allocator NOWHERE — the seeded account chain is `([1.1], 2)`, not
    /// `([1], 2)` — so `next_account_prefix([1])` still answers `1.0.1` and the
    /// claim floor (PUB-6.35, `policy::claim_residue_refusal`) stays zero. It
    /// mints no CONTENT: both documents are born empty, so the ghost content
    /// namespace's frontier is untouched and its floor ([`ghost_floor`],
    /// [`GHOST_POSITIONS`]) stands — nothing exists at a ghost tumbler. Two
    /// PUBLISHED documents add nothing to the exception set (PUB-7.5 stores the
    /// UNPUBLISHED side) and no link exists, so every derived structure over
    /// this state is still empty and `Engine::check_hints` holds by
    /// construction — the corollary the engine's `genesis.rs` states, undisturbed.
    ///
    /// [`GHOST_POSITIONS`]: crate::GHOST_POSITIONS
    pub fn genesis() -> M3State {
        let root = bootstrap_root();
        let node = system_node(); // 1.1
        let account = system_account(); // 1.1.0.1
        let doc1 = ghost_home_doc(); // 1.1.0.1.0.1 — the commons registry's home
        let doc2 = head_document(); // 1.1.0.1.0.2 — the head document H

        // The two frontiers the seed advances, each the key its own mint would
        // have read (§1/§A): the account chain (1.1, 2) to c₁ = 1.1.0.1, and
        // the document chain (1.1.0.1, 2) to c₂ = 1.1.0.1.0.2 (doc 1 then doc 2,
        // M3's document chain being sequential).
        let mut frontiers = im::OrdMap::new();
        frontiers.insert(account_ns(&node), Nat::from(1u32));
        frontiers.insert(document_ns(&account), Nat::from(2u32));

        let mut nodes = im::OrdSet::unit(root.clone());
        nodes.insert(node);

        let mut principals = im::OrdMap::unit(root.clone(), BOOTSTRAP_PRINCIPAL);
        principals.insert(account, SYSTEM_PRINCIPAL);

        // The two documents' RESOLVED publication bits, exactly as their
        // minting Allocates would have journaled them (PUB-7.10): born
        // published (PUB-1.25's genesis/commons-seeded row).
        let mut publication = im::OrdMap::new();
        publication.insert(doc1, true);
        publication.insert(doc2, true);

        M3State {
            frontiers,
            nodes,
            principals,
            publication,
        }
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
    /// is that sole producer, and M2's journal is the boundary that keeps it
    /// so.
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
// §1 The frontier allocator (the heart) + §A lock-key constructors.
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
    fn next_in(&self, key: &NsKey) -> Result<Address, GateViolation> {
        nth_in(key, &(self.effective_frontier(key) + 1u32))
    }

    /// Content-chain `LockKey`: `(b_C(home), 1)` (§1/§3). Pairs with
    /// [`M3State::mint_content`]`(home)` — take it for `transact`'s `keys`
    /// BEFORE the closure; the mint inside READS this key's frontier, and the
    /// [`M3Rec`] you stage ADVANCES it. Never a coarser `(home_doc, g)` key:
    /// the three g = 1 chains under one document — content `(b_C(d), 1)`,
    /// link `(b_L(d), 1)`, version `(d, 1)` — get three DISTINCT locks
    /// (B7/B8).
    ///
    /// Total on every [`Address`], and the caller's one obligation is to pass
    /// the SAME `home` the paired mint receives. A `home` below the document
    /// tier yields a key whose anchor is outside T4 — harmless, since a lock
    /// key is only ever compared, and the paired mint refuses that `home`
    /// `HomeNotRegistered` a moment later.
    pub fn content_lock_key(home: &Address) -> LockKey {
        ns_lock_key(&content_ns(home))
    }

    /// Link-chain `LockKey`: `(b_L(home), 1)` (§1/§3). Pairs with
    /// [`M3State::mint_link`]`(home)` — take it BEFORE the closure; the mint
    /// inside READS this key's frontier, and the [`M3Rec`] you stage ADVANCES
    /// it. Same obligation and same latitude as
    /// [`M3State::content_lock_key`]: pass the mint's own `home`, and a
    /// wrong-tier one costs only the key's own T4-validity, which nothing
    /// reads.
    pub fn link_lock_key(home: &Address) -> LockKey {
        ns_lock_key(&link_ns(home))
    }

    /// Version-chain `LockKey`: `(source, 1)` — SEPARATE from the document
    /// chain below (ASN-0123 VD). Pairs with
    /// [`M3State::mint_version`]`(source, published)` — take it BEFORE the
    /// closure; the mint inside READS this key's frontier, and the [`M3Rec`]
    /// you stage ADVANCES it.
    ///
    /// Total on every [`Address`], and the anchor is the argument itself, so
    /// the key is T4-valid whatever tier arrives. What a wrong tier costs is
    /// not well-formedness but IDENTITY: `(A, 1)` under an account is the
    /// SUB-ACCOUNT chain's key, not a version chain's. Harmless, since a lock
    /// key is only ever compared and the paired mint refuses that `source`
    /// `SourceNotRegistered` a moment later — but the caller's one obligation
    /// is to pass the SAME `source` the mint receives.
    pub fn version_lock_key(source: &Address) -> LockKey {
        ns_lock_key(&version_ns(source))
    }

    /// Document-chain `LockKey`: `(account, 2)`. Pairs with
    /// [`M3State::mint_document`]`(account, published)` — take it BEFORE the
    /// closure; the mint inside READS this key's frontier, and the [`M3Rec`]
    /// you stage ADVANCES it.
    ///
    /// Same shape as [`M3State::version_lock_key`]: total on every
    /// [`Address`], T4-valid whatever tier arrives because the anchor is the
    /// argument itself, and a wrong tier names a DIFFERENT chain — `(N, 2)`
    /// under a node is the ACCOUNT chain's key. Harmless for the same reason,
    /// and the caller's one obligation is the same: pass the mint's own
    /// `account`, which it refuses `NotAnAccount` a moment later if it is
    /// not one.
    pub fn document_lock_key(account: &Address) -> LockKey {
        ns_lock_key(&document_ns(account))
    }

    /// Account-chain `LockKey`: `(parent, 2)` under a node, `(parent, 1)`
    /// under an account — the one family whose `g` the chain-family rule
    /// picks (Conflicts §8). Pairs with [`M3State::mint_account`]`(parent)`
    /// — take it BEFORE the closure; the mint inside READS this key's
    /// frontier, and the [`M3Rec`] you stage ADVANCES it. `pub(crate)` for
    /// the reason the mint is: `delegate` is the only caller and lives in
    /// this crate.
    pub(crate) fn account_lock_key(parent: &Address) -> LockKey {
        ns_lock_key(&account_ns(parent))
    }

    /// THE single global principal-registry key (NOT per-subtree — §8 / Open
    /// build decisions "Serialization granularity"). LOAD-BEARING in
    /// `delegate`: serializes its fresh-prefix top-down / next-form /
    /// authorization reads against concurrent same-namespace delegations AND
    /// its id-freshness read against concurrent same-id delegations — the id
    /// race is CROSS-namespace (same `new_id`, different `new_prefix`), which
    /// no per-namespace key can serialize. Held DEFENSIVELY by
    /// `create_new_document` (its ω read is stale-safe — ω of an *existing*
    /// account is stable, §6/§8). Redundant under M2 v1's global applier lock.
    /// `pub(crate)` because only this crate's ops take it: a store that took
    /// it as well would, under a per-key M2, serialize itself against every
    /// delegation in the docuverse.
    pub(crate) fn principals_lock_key() -> LockKey {
        LockKey::new(Space::Principals, &[])
    }

    /// THE single global node-registry key — one key for the whole registry,
    /// argument-free like [`M3State::principals_lock_key`] and plural for the
    /// same reason: two `register_node` calls for DIFFERENT nodes contend on
    /// it. Held by `register_node` so a concurrent duplicate `RegisterNode`
    /// surfaces `NotFresh` instead of silently coalescing. Node admission
    /// needs NO lock for SAFETY (idempotent `OrdSet` insert, monotone
    /// freshness); this only preserves the typed rejection under per-key
    /// concurrency. Redundant under v1's global lock, exactly like
    /// [`M3State::principals_lock_key`], and `pub(crate)` for the same reason:
    /// `register_node` is the only op that takes it.
    pub(crate) fn nodes_lock_key() -> LockKey {
        LockKey::new(Space::Nodes, &[])
    }
}

// ---------------------------------------------------------------------------
// §A The five pure mints — one per chain, covering the corpus's six
// families, since `mint_account` serves both account-tier families
// (`A_account(N)` under a node and the sub-account `(A, 1)` under an
// account, whose `g` the chain-family rule picks). So every address M3
// originates is minted here. Four are public and fold into M5/M7 composites
// (M2 contract 3); the fifth, `mint_account`, is `pub(crate)` because
// `delegate` is its only caller and lives in this crate.
//
// Each is a query: it reads WORKING state, checks one structural
// precondition, and hands back the next address on its chain together with
// the single `M3Rec` that realizes it. Advancing the frontier is the
// CALLER's half — hold the paired `*_lock_key` across the transaction and
// stage the returned record in it — and it is an obligation nothing here can
// enforce, because the record is delivered inside a tuple the caller has
// already destructured.
//
// The cost of dropping it is stated rather than guarded: a mint whose record
// is never staged leaves the frontier where it stood, so the next mint on
// that chain hands out the SAME address, and the fold's contiguity check
// cannot see it — the second `Allocate` is legitimately `m + 1`. So "an
// address is never reused" is M3's to keep GIVEN the caller's half; unmet,
// nothing in the system says so.
//
// So a mint is also the chain's PEEK: called without staging it answers the
// next address and moves nothing, which is what `next_account_prefix`
// publishes for the account chain and what the determinism assertions here
// ask of the other four.
// ---------------------------------------------------------------------------

impl M3State {
    /// The mint behind the five mints: the next address on the chain `key`
    /// names and the ONE [`M3Rec`] that realizes it, stamped `published` — a
    /// caller's RESOLVED bit on a document chain, [`NO_PUBLICATION_STATE`] on
    /// every other. The address and its record leave together, which is what
    /// makes the key a mint reads and the key its record advances one key
    /// (§A); each public mint is this behind its own structural gate.
    fn mint_on(&self, key: &NsKey, published: bool) -> Result<(Address, M3Rec), GateViolation> {
        let addr = self.next_in(key)?;
        Ok((addr.clone(), M3Rec::Allocate { addr, published }))
    }

    /// Next content address under `home`: namespace `(b_C(home), 1)`, element
    /// field `[s_C, m+1]` (§3). [M5: INSERT] Reads the caller's WORKING state
    /// (successive mints in one composite each see the prior mint); checks
    /// only the structural precondition P6/C2; to realize it, the caller holds
    /// [`M3State::content_lock_key`] and stages the returned [`M3Rec`].
    pub fn mint_content(&self, home: &Address) -> Result<(Address, M3Rec), MintError> {
        if !self.is_registered_document(home) {
            return Err(MintError::HomeNotRegistered); // P6/C2
        }
        self.mint_on(&content_ns(home), NO_PUBLICATION_STATE)
            .map_err(MintError::Gate)
    }

    /// Next link address under `home`: namespace `(b_L(home), 1)`, element
    /// field `[s_L, m+1]` (§3). [M7: MAKELINK] To realize it, the caller holds
    /// [`M3State::link_lock_key`]`(home)` and stages the returned [`M3Rec`].
    pub fn mint_link(&self, home: &Address) -> Result<(Address, M3Rec), MintError> {
        if !self.is_registered_document(home) {
            return Err(MintError::HomeNotRegistered); // L1a
        }
        self.mint_on(&link_ns(home), NO_PUBLICATION_STATE)
            .map_err(MintError::Gate)
    }

    /// Next version identity: namespace `(source, 1)` — the version chain,
    /// kept SEPARATE from the document chain (ASN-0123). [M5: owned
    /// CREATENEWVERSION] To realize it, the caller holds
    /// [`M3State::version_lock_key`]`(source)` and stages the returned
    /// [`M3Rec`].
    ///
    /// `published` is the RESOLVED bit the version is born with, stamped on
    /// the `Allocate` exactly as passed (PUB-8.18): the three-valued flag and
    /// its ABSENT ⇒ INHERIT `published(source)` rule are the CALLING
    /// composite's to resolve off its own working state (PUB-8.17), and this
    /// mint applies no default of its own — a version of a private source
    /// passed `true` is born published and passed `false` private, the
    /// composite's choice both times. The write-path refusals that bound
    /// that choice (PUB-2.7, PUB-2.9) are applied ahead of this mint by the
    /// composite that resolves the flag (owner ruling D2b), not by this mint.
    pub fn mint_version(
        &self,
        source: &Address,
        published: bool,
    ) -> Result<(Address, M3Rec), MintError> {
        if !self.is_registered_document(source) {
            // V-WF: registered Document (covers unregistered AND non-document).
            return Err(MintError::SourceNotRegistered);
        }
        self.mint_on(&version_ns(source), published)
            .map_err(MintError::Gate)
    }

    /// Next document identity under an account: namespace `(account, 2)`.
    /// [CREATENEWDOCUMENT; cross-owner VERSION; fork] To realize it, the
    /// caller holds [`M3State::document_lock_key`]`(account)` and stages the
    /// returned [`M3Rec`].
    ///
    /// `published` is the RESOLVED bit the document is born with, stamped on
    /// the `Allocate` exactly as passed (PUB-8.18) — never the caller's
    /// three-valued flag, and NEVER a default of this mint's own. In
    /// particular the empty-account rule (PUB-8.21: a flagless FIRST mint is
    /// born published) belongs to the CREATE path and lives in
    /// [`crate::Namespace::create_new_document`], which resolves it before
    /// calling here; a cross-owner `version` into an empty account passes
    /// whatever bit its composite resolved (PUB-8.17), and a `false` there
    /// mints private. Whether that first mint is REFUSED (PUB-8.20) is the
    /// daemon's door, not M3's (owner ruling D2c).
    pub fn mint_document(
        &self,
        account: &Address,
        published: bool,
    ) -> Result<(Address, M3Rec), MintError> {
        if !self.is_registered_account(account) {
            // P8/CND.pre (covers unregistered AND non-account).
            return Err(MintError::NotAnAccount);
        }
        self.mint_on(&document_ns(account), published)
            .map_err(MintError::Gate)
    }

    /// Next account identity under `parent`: namespace `(parent, 2)` under a
    /// node, `(parent, 1)` under an account — the sixth family (Conflicts §8),
    /// whose `g` the chain-family rule picks. [`crate::Namespace::delegate`]
    ///
    /// `None`, never a [`MintError`], unless `parent` is a REGISTERED node or
    /// account: `delegate` is the only caller, it is in this crate, and it
    /// already has a typed rejection for that one refusal — a fifth
    /// `MintError` leaf would put a permanently dead arm in M5's, M7's and
    /// M10's vocabularies for a mint none of them can reach.
    ///
    /// To realize it, the caller holds
    /// [`M3State::account_lock_key`]`(parent)` and stages the returned
    /// [`M3Rec`]; [`M3State::next_account_prefix`] is this without the record,
    /// which is the peek.
    pub(crate) fn mint_account(&self, parent: &Address) -> Option<(Address, M3Rec)> {
        if !matches!(self.entity_level(parent)?, Level::Node | Level::Account) {
            return None;
        }
        Some(
            self.mint_on(&account_ns(parent), NO_PUBLICATION_STATE)
                .expect("a registered node/account anchor with g ≤ 2 passes TA5a"),
        )
    }
}

// ---------------------------------------------------------------------------
// §C Queries (pure; read off any M2 Snapshot; write nothing) + §2 membership.
// ---------------------------------------------------------------------------

/// Containment test (O1): `prefix ≼ a` — pure, total, decidable from the two
/// addresses alone, consulting no registry state and needing no coordination.
/// It answers where an address SITS, not who may write it: authorization is
/// [`M3State::is_effective_owner`] (ω, longest match), because several
/// principals' prefixes contain the same address — §5.
pub fn prefix_contains(prefix: &Address, a: &Address) -> bool {
    is_prefix(prefix.tumbler(), a.tumbler())
}

impl M3State {
    /// Is `a` a member of its own chain? The §2 decision behind
    /// [`M3State::is_allocated`] (and so behind [`M3State::entity_level`]),
    /// settled by decomposing and comparing against the frontier.
    /// Membership-correctness invariant: for T4-valid `a`, `a` is *exactly*
    /// `c_{ordinal(a)}` of its decomposed `(parent, g)` namespace (ASN-0040
    /// `S(p, d)` canonical form; T4b unique-parse), so `a` is realized —
    /// `a ∈ {c_{floor+1}..cₘ}` — iff `floor < ordinal(a) ≤ m`, where the floor
    /// is 0 everywhere but the ghost content namespace — genuine chain
    /// membership with NO false positives, not an approximation. The code
    /// spells that interval, and both of its ends absorb their edge case:
    /// where the floor is zero the lower bound is free, because T4 forbids a
    /// trailing zero and `ordinal` reads the last component, so the
    /// [`Address`] type carries a positive ordinal; and an absent frontier is
    /// `m = 0`, which no positive ordinal is ≤. The ghost exclusion is
    /// permanent: the five ghost tumblers answer unallocated on every board
    /// forever ([`ghost_floor`] — nothing exists at a reserved type address),
    /// however far the chain past them has advanced.
    fn is_chain_member(&self, a: &Address) -> bool {
        let Some(key) = namespace_of(a) else {
            return false; // parentless only for a 1-component node — the callers' Node arm
        };
        let n = ordinal(a.tumbler()); // &Nat — compare BY REFERENCE (BigUint is not Copy)
        *n > ghost_floor(&key) && self.frontiers.get(&key).is_some_and(|m| n <= m)
    }

    /// `true` iff `a` exists in the name space — minted on a frontier in ANY
    /// namespace, content/link included, or, for a node, admitted by
    /// `register_node` (node addresses are never minted here — ASN-0047
    /// NodeBaptism originates them outside the docuverse). THE allocation
    /// oracle, which §2 assigns to M5's COPY for referential integrity. Ghost
    /// principle (B3): reflects *allocation*, never byte-presence — a
    /// registered-empty document is a valid, addressable ghost; content
    /// existence is M4's separate axis. E is append-only, so a `true` answer
    /// is permanent (B0/P1).
    pub fn is_allocated(&self, a: &Address) -> bool {
        match a.level() {
            Level::Node => self.nodes.contains(a),
            // The general decompose-and-compare over ALL non-node levels
            // (incl. Element): a content/link element [d.0.s.n] has parent
            // b_C(d)/b_L(d) at the SAME tier, so g = 1 and the key is its
            // TRUE content/link namespace.
            Level::Account | Level::Document | Level::Element => self.is_chain_member(a),
        }
    }

    /// `Some(level)` iff `a` is a registered *entity* (zeros ≤ 2); `None` for
    /// an element or an unregistered address. An entity is an allocated
    /// address below the element tier: content and link elements ARE allocated
    /// but are not in E, so ask [`M3State::is_allocated`] about those.
    /// [ASN-0047 E]
    pub fn entity_level(&self, a: &Address) -> Option<Level> {
        (a.level() != Level::Element && self.is_allocated(a)).then_some(a.level())
    }

    /// `entity_level(a) == Some(Document)` — the edit/home precondition seam
    /// for M5/M7, and the ⟨⟩-vs-fail bool for M6/M8.
    pub fn is_registered_document(&self, a: &Address) -> bool {
        self.entity_level(a) == Some(Level::Document)
    }

    /// `entity_level(a) == Some(Account)` — the account-hood precondition
    /// (P8/CND.pre): what [`M3State::mint_document`] gates on, what
    /// `create_new_document` and `fork` reach through it, and the
    /// account-hood test M10's credential fold and key-set read ask. NOT
    /// `delegate`'s parent gate, which is the account mint's own and
    /// admits a registered node OR account — a node parent being the ordinary
    /// case, since the first delegate under a node has one. The
    /// account twin of [`M3State::is_registered_document`], published for the
    /// same reason: the question is asked from outside M3, and spelling it as
    /// a comparison against an `Option<Level>` makes every caller import M1's
    /// tier enum and choose between `.is_some()` (any entity — what
    /// `register_node`'s freshness gate wants) and this.
    pub fn is_registered_account(&self, a: &Address) -> bool {
        self.entity_level(a) == Some(Level::Account)
    }

    /// Has `account` any documents — is its `(account, 2)` chain non-empty?
    /// AUTH-3.68's `has_documents(account)`, and the premise of the create
    /// path's empty-account rule (PUB-8.21). The chain's frontier IS its
    /// count (B1), so the chain is non-empty iff that frontier exists — one
    /// lookup on the key [`M3State::mint_document`] reads; a zero count,
    /// representable only off a corrupted checkpoint, is an empty chain, as
    /// [`M3State::latest_version`] reads it. `false` off the account tier,
    /// where no document chain is anchored — the tier gate is what makes the
    /// key the DOCUMENT chain's, since `(N, 2)` under a node is the account
    /// chain — and for an unregistered account, whose chain is empty. Asked
    /// by [`crate::Namespace::create_new_document`] under the held
    /// document-chain key and by the daemon's mint doors off a snapshot;
    /// answered here so that neither reassembles it.
    pub fn has_documents(&self, account: &Address) -> bool {
        account.level() == Level::Account
            && self
                .frontiers
                .get(&document_ns(account))
                .is_some_and(|m| !m.is_zero())
    }

    /// The LATEST member of `source`'s version chain `(source, 1)` — `c_m`
    /// for the chain's frontier `m`, spelled by the one chain-member helper
    /// (`nth_in`) at `m` — or `None` when the chain holds no member yet.
    /// [M5: the trunk head a bare document address floats to,
    /// PUB-2.49/PUB-2.53, and the head/older distinction the publish shot
    /// decides at commit, PUB-2.39] A pure frontier read off any snapshot:
    /// the chain is contiguous from 1 (B1) and never loses a member (B0), so
    /// a `Some` never regresses across snapshots — a later read answers the
    /// same member or a later one. The chain's other end, the slot it opens
    /// at, is [`first_version_address`].
    ///
    /// Total. `None` off the document tier, because no other tier anchors a
    /// version chain — the same key under an account is the sub-account chain
    /// (Conflicts §8), whose members are not versions of anything — and for
    /// a document-tier address whose chain has no member, registered or not.
    /// PUB-6.37's polarity — registration precedes every chain read — stays
    /// the caller's for the reason it is on [`M3State::published`]: an
    /// unregistered address is answered by the registration check, and a
    /// `None` here says only that the chain is empty.
    ///
    /// [`first_version_address`]: crate::first_version_address
    pub fn latest_version(&self, source: &Address) -> Option<Address> {
        if source.level() != Level::Document {
            return None;
        }
        let key = version_ns(source);
        let m = self.frontiers.get(&key).filter(|m| !m.is_zero())?;
        Some(nth_in(&key, m).expect("k = 1 passes TA5a on every anchor"))
    }

    /// `published(doc)` — THE engine's one definition of a document's
    /// publication state (owner ruling D1; PUB-1.68, PUB-7.8): the bit its
    /// minting `Allocate` journaled, read off the publication map at one
    /// point lookup — the record-lookup cost the PUB pack names for a build
    /// answering off M3's document records (§5.5), and the map the engine's
    /// derived exception set (PUB-7.5) is a membership index over. A version
    /// address answers its OWN member's bit; projecting a member to its
    /// document ahead of a gate (PUB-2.15) is the caller's address
    /// arithmetic, not this read's.
    ///
    /// CONTRACT — `doc` is a REGISTERED document: callers gate on
    /// [`M3State::is_registered_document`] first (PUB-6.37: registration
    /// precedes publication, and an unregistered address is answered by the
    /// registration check and by nothing here). On any slice M3's own fold
    /// produced, every registered document has an entry, because the
    /// allocation record that registers it carries the bit and the fold writes
    /// both in one step.
    ///
    /// `false` FOR A MISSING ENTRY is the fail-private direction (PUB-1.1),
    /// and it answers two different absences. An unregistered address has no
    /// allocation record, so what this returns for one is no answer at all —
    /// a caller that reads it has skipped the gate. A REGISTERED document with
    /// NO entry is the other, and it is not a caller's bug: it is reachable
    /// outside [`M3State::apply_m3`]'s totality domain — a jumped `Allocate`
    /// registers the ordinals it skipped — and is the case
    /// [`M3State::documents`] states has no remedy here. This read answers it
    /// PRIVATE. A derived index that stores the UNPUBLISHED side and answers
    /// by membership MISS inverts that, and should say so where it is built.
    ///
    /// IMMUTABLE: no M3 function changes a document's bit after its mint —
    /// there is no publish op, in either direction (PUB-1.9, PUB-1.68).
    pub fn published(&self, doc: &Address) -> bool {
        self.publication.get(doc).copied().unwrap_or(false)
    }

    /// Every registered DOCUMENT with its publication bit, in address order —
    /// the ENUMERATION of the publication map [`M3State::published`] reads
    /// one entry of. One entry per registered document, versions included, on
    /// any slice M3's own fold produced: the allocation record that registers
    /// a document carries its bit and [`M3State::apply_m3`] writes both in one
    /// step, and nothing else writes here. A checkpoint is bytes, so a reader
    /// that must not fail-stop on a corrupted one re-asks
    /// [`M3State::is_registered_document`] per entry, as the engine's seed
    /// does. The order is the `OrdMap`'s — a function of the contents, so two
    /// boards with one history enumerate alike, and the walk's back end is the
    /// address-greatest entry, which address order does not make the newest: a
    /// version of doc 1 sorts BETWEEN doc 1 and doc 2, whichever was minted
    /// first. Double-ended and exact-size, as a map walk is in std — `.rev()`
    /// and `.len()` are the hidden type's own, promised rather than hidden, so
    /// that end and the document count each cost one call and no walk.
    ///
    /// The fold-produced scope is load-bearing in one direction only. A
    /// checkpoint or a journal outside [`M3State::apply_m3`]'s totality domain
    /// can hold a registered document with NO entry — a jumped `Allocate`
    /// registers the ordinals it skipped — and that direction has no remedy
    /// here: the claim relates the frontier map to this one, which no
    /// per-entry door can settle, and checking it at load would mean expanding
    /// every document chain to its members, the Θ(documents) cost B1's
    /// compression exists to avoid. What a reader owes is the POLARITY.
    /// [`M3State::published`] answers `false` for a missing entry, which is
    /// fail-private; an index that stores the UNPUBLISHED side and answers by
    /// membership MISS inverts that, so a document this walk omits reads
    /// PUBLISHED there. A derived index built by ADDITION over this walk
    /// inherits the open direction and should say so where it is built.
    ///
    /// Published for the reader that cannot ask per address: a derived index
    /// over the bit (the engine's exception set, PUB-7.5 — PUB-7.7's seed
    /// half) and a rendering of the map. Both would otherwise rebuild this
    /// walk from the slice's serde form by a private field name, which no
    /// compiler edge protects.
    pub fn documents(
        &self,
    ) -> impl DoubleEndedIterator<Item = (&Address, bool)> + ExactSizeIterator + '_ {
        self.publication
            .iter()
            .map(|(doc, published)| (doc, *published))
    }

    /// ω's resolution step: the Π entry whose prefix is the LONGEST covering
    /// prefix of `a` (§5) — THE one walk. [`M3State::effective_owner`]
    /// projects the id, [`M3State::effective_owner_prefix`] the prefix,
    /// [`M3State::effective_owner_pair`] hands the entry back whole, and
    /// [`M3State::is_effective_owner`] compares; the cost promise and the O1a
    /// tier filter are stated on `effective_owner`, and the `principals`
    /// range-walk upgrade lands here once, serving all four.
    fn omega(&self, a: &Address) -> Option<(&Address, PrincipalId)> {
        self.principals
            .iter()
            .filter(|(p, _)| {
                matches!(p.level(), Level::Node | Level::Account) && prefix_contains(p, a)
            })
            .max_by_key(|(p, _)| p.tumbler().len())
            .map(|(p, id)| (p, *id))
    }

    /// ω(a): WHO owns `a` — the longest-prefix match over Π, answered as the
    /// owning id (§5; ASN-0042 O2/O3/O5). A pure prefix query — valid even
    /// when `a` is not (yet) allocated. One projection of the single Π walk
    /// [`M3State::effective_owner_prefix`] shares, and the authorization
    /// predicate [`M3State::is_effective_owner`] is stated in terms of this
    /// one.
    ///
    /// The walk is over Π, keeping the longest covering prefix — the reference
    /// form the design names — and NEVER over `a`'s own reconstructed
    /// prefixes. That is a cost decision, and it is load-bearing: `a` arrives
    /// from a caller, and T4 bounds its zero pattern but not its DEPTH, so a
    /// per-candidate walk would do work quadratic in a length the caller
    /// chooses (an account-tier `[1, 0, 1, 1, …]` has an admissible candidate
    /// at every length, and rebuilding each one clones its components), while
    /// `create_new_document` and `delegate` both evaluate ω in-closure under
    /// the held global `M3State::principals_lock_key`. Here the work is
    /// `Σ_{p ∈ Π} |p|` component comparisons and no allocation: to enlarge it
    /// an attacker must first commit durable, ω-gated, next-form-gated
    /// delegations, one journal record per principal. So a deep probe costs no
    /// more than a shallow one, and neither costs O(#allocated). The shape is
    /// per CALL, though, so a caller that takes one ω per entry of a walk pays
    /// the PRODUCT — a seed over [`M3State::documents`] costs Θ(entries · |Π|)
    /// at every load — and the `principals` range-walk upgrade is where that
    /// lands.
    ///
    /// The tier filter is O1a, and it is a refusal rather than an
    /// optimisation. O1a is a producer invariant (genesis plus `delegate`'s
    /// hoisted `NotAccountTier` gate), so a below-tier entry is unreachable
    /// through the ops and representable only in a corrupted checkpoint — and
    /// ω is the one reader whose answer to such an entry would be a PASS,
    /// which is why ω is the one reader that refuses it. The other two readers
    /// of Π need no filter: [`M3State::has_principal_strictly_under`] already
    /// answers a rejection when it sees one, and [`M3State::principal_prefix`]
    /// returns the registry's verbatim answer, which every mint that could
    /// receive such a prefix then refuses on its own tier gate. No tie is
    /// possible here: two prefixes of one address have different lengths, and
    /// Π is prefix-injective.
    ///
    /// For WHETHER a given id owns `a` — the authorization question — ask
    /// [`M3State::is_effective_owner`], which settles it without naming the
    /// owner.
    pub fn effective_owner(&self, a: &Address) -> Option<PrincipalId> {
        self.omega(a).map(|(_, id)| id)
    }

    /// ω(a) as the PREFIX rather than the id: the node or account address the
    /// effective owner is seated at (§5; ASN-0042 O2/O3). Same walk, same
    /// tier filter, same cost as [`M3State::effective_owner`] — this is its
    /// other projection, and it is published because the composition a caller
    /// would otherwise write, `principal_prefix(effective_owner(a))`, is two
    /// scans and is the same answer only while Π is id-injective, which is a
    /// PRODUCER invariant (`delegate`'s `DuplicateId` gate) that
    /// [`M3State::apply_m3`] neither re-checks nor could. Here the prefix IS
    /// the entry ω matched, so the two cannot come apart.
    pub fn effective_owner_prefix(&self, a: &Address) -> Option<&Address> {
        self.omega(a).map(|(prefix, _)| prefix)
    }

    /// ω(a) UNPROJECTED: the Π entry ω matched, as the PAIR — the node or
    /// account address the effective owner is seated at AND the principal
    /// seated there (§5; ASN-0042 O2/O3). Same walk, same tier filter, same
    /// cost as [`M3State::effective_owner`]: this is that ONE walk's whole
    /// answer, where the two projections beside it each keep half.
    ///
    /// OPTIONAL, and published for the one reader that needs both halves of
    /// ONE entry: the owner-of-address read (AUTH-6.37), whose allocation
    /// test is `prefix == a` and whose principal must be the one seated AT
    /// that prefix. Composing [`M3State::effective_owner_prefix`] with
    /// [`M3State::effective_owner`] answers the same pair off one snapshot,
    /// but walks Π TWICE, and that read's cost promise is the walk every
    /// ownership check already makes — one. No caller is REQUIRED to use it;
    /// it adds no state, no index and no fold fact, and `None` is exactly
    /// the projections' `None`: no registered node- or account-tier prefix
    /// contains `a`, so the two halves are absent TOGETHER by construction.
    pub fn effective_owner_pair(&self, a: &Address) -> Option<(&Address, PrincipalId)> {
        self.omega(a)
    }

    /// THE authorization predicate: is `id` the effective owner ω of `a`? An
    /// absent ω is not-owner, never a pass (§5; ASN-0042 O5).
    ///
    /// Every ω-gated op asks this rather than reassembling it from
    /// [`M3State::effective_owner`], and NEVER
    /// [`M3State::prefix_contains`] — the ownership-divergence trap: a node
    /// operator's prefix contains every delegated account, so containment is
    /// true for several principals at once, and only the longest match
    /// arbitrates. O2 exclusivity is then a theorem given prefix-injectivity,
    /// which delegation's freshness gate enforces; id-injectivity
    /// (`DuplicateId`) makes the id comparison equivalent to comparing the
    /// principals themselves.
    pub fn is_effective_owner(&self, id: PrincipalId, a: &Address) -> bool {
        self.effective_owner(a) == Some(id)
    }

    /// `pfx(id)` — the projection the id-centric ops (`fork`, `delegate`) and
    /// the M5→M3 cross-owner-VERSION seam need, since `principals` is keyed by
    /// PREFIX, not id: an O(|Π|) scan, not a point lookup (the §5 scan). The
    /// answer is the registry's own key, so the prefix a principal is seated
    /// at and the prefix it is reported at are one value. Π is account/node-
    /// tier only (O1a), hence small per node. SINGLE-VALUED because `delegate`
    /// enforces id-freshness (`DuplicateId`), so at most one principal carries
    /// any id (§5/§6). Value-stable across snapshots: prefixes are immutable
    /// (O13) and principals persist (O12) — so a caller that needs the prefix
    /// as a value says `.cloned()`, and one that only probes or forwards it
    /// pays nothing.
    pub fn principal_prefix(&self, id: PrincipalId) -> Option<&Address> {
        self.principals
            .iter()
            .find(|(_, pid)| **pid == id)
            .map(|(prefix, _)| prefix)
    }

    /// Peek the next delegable account-tier prefix under `parent` — the exact
    /// value `delegate` will demand as next-form (O17c), so a caller obtains a
    /// valid `new_prefix` instead of guess-and-retry on `NotNextForm`. It is
    /// [`M3State::mint_account`] without the record, so the value a caller
    /// peeks and the value the gate compares come off one chain by one code
    /// path. `g` follows `parent`'s level: a node ⇒ the `(parent, 2)` account
    /// chain; an account ⇒ the `(parent, 1)` sub-account chain (the sixth
    /// chain family ASN-0042 licenses — Conflicts §8). Both yield zeros = 1.
    /// Pure frontier read off any snapshot; `None` for two reasons, and both
    /// are monotone, so a `Some` answer never regresses: `parent` is not a
    /// REGISTERED node or account (E is append-only), or the slot it names
    /// would exceed [`MAX_PRINCIPAL_COMPONENTS`], which is a compiled
    /// constant. That second refusal is here so the peek and `delegate`'s
    /// `TooDeep` gate read one bound and no caller is handed a prefix the
    /// gate refuses. The returned prefix still faces `delegate`'s full
    /// in-closure gate — two racing peeks of the same value leave exactly one
    /// winner.
    pub fn next_account_prefix(&self, parent: &Address) -> Option<Address> {
        self.mint_account(parent)
            .map(|(addr, _)| addr)
            .filter(|addr| addr.tumbler().len() <= MAX_PRINCIPAL_COMPONENTS)
    }

    /// §6 (iv), concretely: because `principals` is an `OrdMap` under tumbler
    /// order and the extensions of `p` form a contiguous block (T5), a SINGLE
    /// probe settles top-down — take the first key ≥ `p`; a registered
    /// principal sits strictly under `p` iff that key is a strict extension.
    /// If it is not, none is (the block is empty). No full scan.
    ///
    /// PRECONDITION — `p ∉ Π`. The block of keys ≥ `p` opens with `p` itself
    /// when `p` is a principal, so the probe would answer `false` while a
    /// principal genuinely sits beneath it. `delegate` is the only caller and
    /// discharges this by the two gates PINNED ahead of (iv): if `p ∈ Π` then
    /// ω(`p`) is `p`'s own principal, so every strict-ancestor delegator is
    /// already refused `NotAuthorized` at (ii), and `p`'s own principal is
    /// already refused `NotAncestor` at (i). Reordering (i) or (ii) behind
    /// (iv) would not fail loudly, and what it costs is a wrong rejection CODE
    /// rather than the nesting invariant. A principal strictly under `p` — or
    /// `p` itself in Π — implies `p` is allocated: every account-tier address
    /// is minted by [`M3State::mint_account`], which refuses an unregistered
    /// anchor, and that chain of refusals runs back up to `p`. So (v)
    /// freshness independently refuses every input this probe's blind spot
    /// admits, and answers `NotFresh` where [`crate::DelegateError`]'s
    /// declaration promises `NotTopDown` — which M10's `RejectCode` mapping
    /// and the conformance allowlist read. On the live path the invariant has
    /// two gates; only the published precedence has one.
    pub(crate) fn has_principal_strictly_under(&self, p: &Address) -> bool {
        self.principals
            .range(p.clone()..)
            .next()
            .is_some_and(|(first, _)| prefix_contains(p, first) && first != p)
    }
}

#[cfg(test)]
mod tests;
