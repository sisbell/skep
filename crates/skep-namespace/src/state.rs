//! §Core data model, §1–§5 — M3's `WorldState` slice ([`M3State`]), its
//! journal deltas ([`M3Rec`]) and fold ([`M3State::apply_m3`]); the frontier
//! allocator (§1, the heart), entity membership (§2), the content/link
//! sub-allocators (§3), the admission gates (§4), and the principal registry
//! with the ω resolver (§5).

use num_traits::Zero;
use serde::{Deserialize, Serialize};
use skep_address::{
    checked_inc, inc, is_prefix, is_t4_valid, ordinal, parent, shift, validate, Address,
    GateViolation, Level, Nat, Tumbler,
};
use skep_kernel::{LockKey, Space};

use crate::error::MintError;

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

/// A namespace — ASN-0040's `(p, d)`: chain anchor `parent` + generator
/// [`Generator`]. THE frontier-map key, and (through the injective
/// [`ns_lock_key`] encoding) the lock key — one key type, one code path, so
/// the two can never drift (§1). Keying by `(parent, g)` keeps the document
/// chain `(A, 2)` and the version chain `(d, 1)` on SEPARATE frontiers by
/// construction (ASN-0123 VD — the entire fix for ASN-0103's
/// version/document collision, requiring no length filter).
///
/// `parent` is a bare `Tumbler` rather than an `Address` because the content
/// and link anchors are `inc(d, 2)` and `inc(b_C(d), 0)`, which M1 returns as
/// tumblers — so the anchor constructors carry no `validate` of their own and
/// [`M3State::next_in`] re-lifts the anchor at the one place it needs an
/// [`Address`].
///
/// What this type owes, and owes on EVERY `(Tumbler, Generator)` pair it can
/// be built from, is that [`ns_lock_key`] is injective — distinct namespaces,
/// distinct locks. That holds for any nonempty anchor whatever its shape, so
/// it is stated without a proviso and needs none.
///
/// A T4-valid anchor is NOT this type's invariant. It is a precondition of
/// [`M3State::next_in`], discharged there by the caller's own gate and stated
/// beside the `validate` that consumes it — which is why a key may exist that
/// no `next_in` path can reach, and why that costs nothing.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "NsKeyShadow")]
pub(crate) struct NsKey {
    parent: Tumbler,
    g: Generator,
}

/// The at-rest shadow of [`NsKey`] — same fields, same order, so the
/// checkpoint encoding is the struct's own — and the ONE door a frontier key
/// re-enters memory through.
///
/// It re-establishes the T4 HALF of [`M3State::next_in`]'s anchor
/// precondition — the half a decoder holding one key can settle — for keys
/// that arrive with no caller to establish it. In process, a `next_in` caller
/// establishes T4-validity through its own gate before it calls; a checkpoint
/// is bytes, and `Tumbler` admits any nonempty component sequence — `[1, 0]`
/// decodes and is not T4-valid — so a loaded key would otherwise be a panic
/// waiting for the first reader to dereference it. One T4 scan per key at
/// load, no allocation.
///
/// The other half — [`Generator::NextField`] paired with an Element-level
/// anchor — is not this door's, and needs no door: it is a property of the
/// PAIR, which a per-key check could settle but need not, because it fails
/// soft. `checked_inc` refuses `k = 2` at that tier, so `next_in` answers
/// `GateViolation` and the mint surfaces [`MintError::Gate`]; there is no
/// panic to prevent.
///
/// No key read out of `frontiers` reaches `next_in` today — all five mints
/// build a fresh key from a `*_ns` constructor, and loaded keys are only ever
/// hashed for lookup. So this door is defence for the first frontier-
/// enumerating or re-keying reader to appear, and that reader is why it is
/// here: M3 publishes no enumeration API, which is why the engine's
/// observation surface reads this slice through its serde bytes instead.
#[derive(Deserialize)]
struct NsKeyShadow {
    parent: Tumbler,
    g: Generator,
}

impl TryFrom<NsKeyShadow> for NsKey {
    type Error = &'static str;
    fn try_from(shadow: NsKeyShadow) -> Result<NsKey, &'static str> {
        if !is_t4_valid(&shadow.parent) {
            return Err("a namespace anchor is T4-valid (ASN-0040 (p, d))");
        }
        Ok(NsKey {
            parent: shadow.parent,
            g: shadow.g,
        })
    }
}

/// The chain generator — ASN-0040's `d`: [`Generator::SameField`] extends the
/// anchor's own field, [`Generator::NextField`] opens the next one. An enum
/// because `g ∈ {1, 2}` exhausts it: no third generator is representable, in
/// memory or off a checkpoint, so [`M3State::next_in`] can only hand M1's
/// `checked_inc` a `k` its TA5a gate admits by shape (`k ≥ 3` is refused
/// there, and is what M1 asks a minting producer never to derive from input).
/// What survives is the one refusal a precondition owns rather than the type:
/// `NextField` off an Element anchor, which every mint's registered-entity
/// gate already excludes. Encodes as its numeral, so the checkpointed
/// frontier key and [`ns_lock_key`]'s trailing byte read the same either way.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(into = "u8", try_from = "u8")]
pub(crate) enum Generator {
    SameField,
    NextField,
}

impl Generator {
    /// The `k` this generator denotes in M1's `inc(t, k)` — which field of the
    /// anchor the chain advances. A widening of the numeral, so it cannot
    /// disagree with what a checkpoint or a lock key carries.
    fn inc_k(self) -> usize {
        usize::from(u8::from(self))
    }
}

impl From<Generator> for u8 {
    /// The generator's numeral — ASN-0040's `d`, and the byte itself: what a
    /// checkpointed frontier key carries and what [`ns_lock_key`] pushes.
    /// [`Generator::try_from`] is its inverse.
    fn from(g: Generator) -> u8 {
        match g {
            Generator::SameField => 1,
            Generator::NextField => 2,
        }
    }
}

impl TryFrom<u8> for Generator {
    type Error = &'static str;
    fn try_from(numeral: u8) -> Result<Generator, &'static str> {
        match numeral {
            1 => Ok(Generator::SameField),
            2 => Ok(Generator::NextField),
            _ => Err("a namespace generator is 1 or 2 (ASN-0040 (p, d))"),
        }
    }
}

/// M3's journal deltas — lifted to `W::Record` via the engine's `From<M3Rec>`
/// impl (the write-side mirror of [`crate::HasM3`]) and folded by
/// [`M3State::apply_m3`]. Every payload is an [`Address`], so T4-validity is
/// carried by the value: checked once where the record is built, and re-checked
/// on the way back off the journal by M1's validating `Deserialize`. A record
/// still journals as a bare, flat tumbler, exactly as the data model
/// prescribes. One `Allocate` variant suffices for every minted address
/// (entity, content, link) because the frontier map is uniform; the level
/// distinction is recovered at *query* time from the address's own level.
///
/// Off the journal a record arrives through [`M3RecShadow`], which re-checks
/// the one standing fact T4-validity does not carry: an `Allocate` address
/// extends a parent.
///
/// A variant added HERE must be added to [`M3RecShadow`] too: `Serialize` is
/// derived from this enum and `Deserialize` runs through the shadow, so a
/// shadow missing the variant yields records that journal and then never
/// decode — a recovery failure that survives restart, from an edit that looked
/// local.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "M3RecShadow")]
pub enum M3Rec {
    /// A mint's COMMIT HALF: advance `frontiers[namespace_of(addr)]` (§1) —
    /// this record is the only thing that moves a frontier. The `(parent, g)`
    /// of an `Allocate` is exactly the `NsKey` of the `LockKey` the minting op
    /// held — frontier key and lock key are the same key.
    Allocate { addr: Address },
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
/// A per-record door carries per-record facts and no others. The standing
/// property `RegisterPrincipal` would want — id-injectivity across Π — is not
/// one: it is a claim about the principal registry the record is about to
/// enter, which no decoder holding a single frame can settle. That invariant
/// has one owner, `delegate`'s `DuplicateId` gate, and this door does not
/// share it.
#[derive(Deserialize)]
enum M3RecShadow {
    Allocate { addr: Address },
    RegisterNode { addr: Address },
    RegisterPrincipal { prefix: Address, id: PrincipalId },
}

impl TryFrom<M3RecShadow> for M3Rec {
    type Error = &'static str;
    fn try_from(shadow: M3RecShadow) -> Result<M3Rec, &'static str> {
        match shadow {
            M3RecShadow::Allocate { addr } if addr.tumbler().len() < 2 => {
                Err("an Allocate address extends a parent (≥ 2 components)")
            }
            M3RecShadow::Allocate { addr } => Ok(M3Rec::Allocate { addr }),
            M3RecShadow::RegisterNode { addr } => Ok(M3Rec::RegisterNode { addr }),
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
/// **The journal is the sole authority** (M2); these three structures are the
/// *recovered working representation*, folded by [`M3State::apply_m3`]. All
/// three are ordinary `Serialize`/`Deserialize` fields — **none** is
/// `#[serde(skip)]` — so they are restored verbatim from the loaded checkpoint
/// and then advanced by replaying the post-checkpoint `M3Rec`s. They are
/// authoritative working state, not derived hints, so M3 takes M2's **default
/// `rebuild_derived`** (identity): nothing to re-seed before replay.
///
/// Authoritative vs hint: `frontiers`/`nodes`/`principals` are authoritative
/// (the compressed allocation journal). The delegation forest, any
/// `address → owner` ω-cache, and any `id → prefix` reverse index are *hints*
/// — recomputable from `principals` alone — and are deliberately NOT stored
/// (Open build decisions: defaults taken).
///
/// The `Serialize` impl targets bincode-class formats, M2's checkpoint
/// encoding: `frontiers` is keyed by a struct, which formats requiring string
/// keys (JSON among them) refuse. Nor are the bytes stable across processes —
/// `im::HashMap` iterates in an order the process's hash seed picks — so a
/// caller wanting a byte-comparable rendering canonicalizes it (the engine's
/// observation surface transcodes for exactly this reason) rather than
/// hashing the encoding.
///
/// Equality is structural, and it is the meaning of the type: two slices are
/// equal iff their three registries hold the same entries, whatever order a
/// process's hash seed iterates them in. So a slice recovered from a
/// checkpoint is comparable to the one it was taken from — the whole claim
/// recovery makes — without going through a rendering. There is no
/// [`Default`]: [`M3State::genesis`] is not an empty value (it seeds `[1]`
/// into `nodes` and Π), and an empty one would be a world with no bootstrap
/// principal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct M3State {
    /// THE baptismal registry (ASN-0040 B), in B1+B2 compressed form. A
    /// namespace's entire realized set `{c₁..cₘ}` IS the single count `m` — a
    /// gap is literally unrepresentable (B1 free). Covers every chain:
    /// accounts, documents, versions, content, links. Values are big-ints (B9
    /// unbounded). A `HashMap` because mint and membership are *point* lookups
    /// on one namespace; namespaces are never iterated, so order is not paid
    /// for.
    ///
    /// Not the entity registry E (ASN-0047): E is this map's below-element
    /// part TOGETHER WITH `nodes`, which is the pair
    /// [`M3State::is_allocated`] dispatches over and
    /// [`M3State::entity_level`] then filters by tier.
    frontiers: im::HashMap<NsKey, Nat>,

    /// The node registry. Node addresses (zeros = 0), externally minted
    /// (ASN-0047 NodeBaptism — provisioning mints node addresses OUTSIDE the
    /// docuverse), so possibly non-contiguous → held explicitly, not
    /// frontier-encoded. M3 SUPPRESSES ASN-0040's `baptize(node, 1)`
    /// child-node capability (Conflicts §7): internal minting never yields a
    /// zeros = 0 address; ongoing admission is `register_node`, never
    /// ASN-0040 baptism. Seeded `{[1]}`.
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
    ///   genesis and by `delegate`'s hoisted `NotAccountTier` gate. Only
    ///   [`M3State::effective_owner`] re-checks it, because ω is the one
    ///   reader whose answer to a below-tier entry would be a PASS; see the
    ///   tier filter there.
    ///
    /// The ONLY authoritative ownership state — the delegation forest is
    /// recomputable (NestingByDelegation) and never stored. An `OrdMap`
    /// because the top-down check needs a descendant *range* probe (§6 (iv))
    /// and ordering leaves the ω range-walk upgrade open — a change
    /// [`M3State::effective_owner`] absorbs for the authorization predicate
    /// at the same time, since that predicate is stated in terms of it.
    principals: im::OrdMap<Address, PrincipalId>,
}

// ---------------------------------------------------------------------------
// Pure structural helpers (the house style for pure helpers: free functions).
// ---------------------------------------------------------------------------

/// The cap on a registered node address's component COUNT, enforced by
/// [`crate::Namespace::register_node`] ([`crate::NodeError::TooDeep`]; §7).
///
/// `nodes` is the one registry M3 cannot keep in frontier form: a namespace's
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

/// The bootstrap node root `[1]` (Σ₀) — the single definition genesis seeds
/// from and `register_node`'s lineage check probes against.
pub(crate) fn bootstrap_root() -> Address {
    let root = Tumbler::new([Nat::from(1u32)]).expect("a one-component sequence is nonempty");
    validate(root).expect("the bootstrap root [1] is T4-valid")
}

/// THE chain-family rule: the generator carrying an anchor at one tier to a
/// child at another — same tier extends the anchor's own field, a lower tier
/// opens the next one. Every `NsKey`'s `g` comes from here, and this is what
/// keeps the document chain `(A, 2)` and the version chain `(d, 1)` on
/// separate frontiers (ASN-0123 VD).
///
/// Both arguments are M1 [`Level`]s — the vocabulary the corpus states the
/// tiers in, and the answer an [`Address`] already carries, so the rule that
/// decides which frontier a mint lands on is never spelled in the encoding's
/// numerals.
fn generator(anchor: Level, child: Level) -> Generator {
    if anchor == child {
        Generator::SameField
    } else {
        Generator::NextField
    }
}

/// THE namespace derivation from the child side: the [`NsKey`] `a` sits in —
/// chain anchor `parent(a)`, generator [`generator`]. Pure M1, and total:
/// `None` EXACTLY for a parentless 1-component node (e.g. `[7]`), which is
/// T4-valid yet anchors no chain — M1's `parent` returns `None` there, and
/// that is the one input for which no namespace exists.
///
/// Every child-side reader of a frontier key routes through here —
/// membership for its chain range probe, the fold for its frontier advance —
/// so the key a staged `Allocate` advances is the key its mint read, by
/// construction (§1/§2). Anchor-side keys come from the `*_ns` family below,
/// one per chain, and both sides take their `g` from [`generator`] at the
/// same tier pair, which is what makes them one key. Callers that hold a
/// ≥ 2-component address by their own gate discharge the `None` case with an
/// `expect` that names that gate.
pub(crate) fn namespace_of(a: &Address) -> Option<NsKey> {
    let par = parent(a)?;
    let g = generator(par.level(), a.level());
    Some(NsKey {
        parent: par.tumbler().clone(),
        g,
    })
}

// The namespace helpers — the ONE code path each mint, each `*_lock_key` and
// the account peek reuse (§1/§3). The subspace identifier is the
// element-field's FIRST component, and M1 names both numerals:
// `content_subspace()` = 1, `link_subspace()` = 2. It is NEVER the `.0.`
// separator (the corpus-wide misread to guard against); `s_C ≠ s_L` is what
// makes content and link address spaces disjoint by construction (SD/L14,
// T7). The two element-field constructors reach those bases by M1 arithmetic
// rather than by naming a subspace: `inc(d, 2)` opens the element field at
// `s_C`, and `inc(b_C(d), 0)` steps it on to `s_L`.
//
// Each fixed family's `g` is what `generator` yields at that family's FIXED
// tier pair, noted beside each constructor, so the variants below and the
// chain-family rule cannot drift apart unnoticed.
/// `b_C(d) = inc(d, 2)` — the content sub-allocator's anchor, named because
/// [`link_ns`] is defined off it: `b_L(d) = inc(b_C(d), 0)` (§3).
fn content_base(home: &Address) -> Tumbler {
    inc(home.tumbler(), 2)
}
fn content_ns(home: &Address) -> NsKey {
    // b_C(d); Element → Element.
    NsKey {
        parent: content_base(home),
        g: Generator::SameField,
    }
}
fn link_ns(home: &Address) -> NsKey {
    // b_L(d) = inc(b_C(d), 0); Element → Element.
    NsKey {
        parent: inc(&content_base(home), 0),
        g: Generator::SameField,
    }
}
fn version_ns(source: &Address) -> NsKey {
    // (source, 1) — Document → Document, the ASN-0123 separate chain.
    NsKey {
        parent: source.tumbler().clone(),
        g: Generator::SameField,
    }
}
fn document_ns(account: &Address) -> NsKey {
    // (account, 2) — Account → Document.
    NsKey {
        parent: account.tumbler().clone(),
        g: Generator::NextField,
    }
}

/// `A_account(N)` and the sub-account family: the account chain under
/// `parent` — `(N, 2)` under a node, `(A, 1)` under an account (the sixth
/// family ASN-0042 licenses — Conflicts §8). The one family whose `g` is not
/// fixed: the target is account-tier by definition, so the chain-family rule
/// picks.
fn account_ns(parent: &Address) -> NsKey {
    NsKey {
        parent: parent.tumbler().clone(),
        g: generator(parent.level(), Level::Account),
    }
}

// The three key domains M3 serializes on — namespace frontiers, THE principal
// registry, THE node registry — must occupy disjoint byte spaces (§1/§8: an
// alias would under-serialize a namespace and REUSE an address, the one fatal
// error). Each takes its own tag from M2's central `Space` enum
// (`Space::Namespace` / `Space::Principals` / `Space::Nodes`), where every
// tag in the system is assigned, so the disjointness holds against the other
// stores' key spaces too and not merely against M3's own.

/// The injective, space-tagged `NsKey → LockKey` encoding (§1): tag byte,
/// 8-byte BE component count, each component length-delimited (8-byte BE
/// length + minimal BE magnitude bytes), then `g`. Injectivity is what
/// guarantees distinct namespaces map to distinct locks; both the
/// `*_lock_key` constructors and the frontier advance route through the SAME
/// `*_ns` helper and THIS encoding, so the held lock key and the staged
/// frontier key are the same bytes by one code path.
///
/// The two length fields are the width of the counts they carry —
/// `Tumbler::len` and a magnitude's byte length are both `usize`, and both
/// are written whole. A narrower field would make injectivity conditional on
/// no tumbler and no component exceeding it, and neither bound is one M3
/// imposes or could test: M1 leaves component count and magnitude alike
/// unbounded (T0). Injectivity is the property this key exists for, so it is
/// stated without a proviso.
pub(crate) fn ns_lock_key(key: &NsKey) -> LockKey {
    let mut bytes = Vec::new();
    bytes.extend((key.parent.len() as u64).to_be_bytes());
    for comp in &key.parent {
        let magnitude = comp.to_bytes_be();
        bytes.extend((magnitude.len() as u64).to_be_bytes());
        bytes.extend(magnitude);
    }
    bytes.push(u8::from(key.g));
    LockKey::new(Space::Namespace, &bytes)
}

/// Containment test (O1): `prefix ≼ a` — pure, total, decidable from the two
/// addresses alone, consulting no registry state and needing no coordination.
/// It answers where an address SITS, not who may write it: authorization is
/// [`M3State::is_effective_owner`] (ω, longest match), because several
/// principals' prefixes contain the same address — §5.
pub fn prefix_contains(prefix: &Address, a: &Address) -> bool {
    is_prefix(prefix.tumbler(), a.tumbler())
}

// ---------------------------------------------------------------------------
// §D Genesis and the fold.
// ---------------------------------------------------------------------------

impl M3State {
    /// Σ₀ + O14: `nodes = {[1]}`, `frontiers = {}`,
    /// `Π = { [1] → BOOTSTRAP_PRINCIPAL }`. `pub` — the engine seeds
    /// `Kernel::open(cfg, genesis-World)` with it; "load empty journal" and
    /// "fresh genesis" are the same code path (§7). Deterministic, per M2's
    /// byte-identical-genesis caller contract.
    pub fn genesis() -> M3State {
        let root = bootstrap_root();
        M3State {
            frontiers: im::HashMap::new(),
            nodes: im::OrdSet::unit(root.clone()),
            principals: im::OrdMap::unit(root, BOOTSTRAP_PRINCIPAL),
        }
    }

    /// M3's fold — `pub`: the engine crate wires `World::apply`'s `Record::M3`
    /// dispatch to this. TOTALITY DOMAIN (M2's total-apply obligation, stated
    /// here at the seam the engine wires): total — deterministic,
    /// side-effect-free, panic-free — over every record whose `Allocate`
    /// address has a parent, which every mint's does, since a mint extends a
    /// REGISTERED parent. Neither shape precondition is owed to the journal:
    /// the [`Address`] payloads carry T4-validity, and [`M3RecShadow`] carries
    /// the parent, so a record that arrives from disk or a peer is refused at
    /// decode rather than folded into a panic. What the fold still trusts is
    /// an IN-PROCESS producer, which builds the variant directly. An
    /// `Allocate` that regresses or jumps a frontier (ordinal ≠ count + 1) is
    /// outside the domain and fail-stops on the contiguity `debug_assert` —
    /// corruption, not a live error path.
    ///
    /// `RegisterPrincipal` is the one arm with no gate of its own, and that is
    /// deliberate rather than missing. Id-injectivity — one id ↦ at most one
    /// principal — is a PRODUCER invariant, owned by `delegate`'s
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
            M3Rec::Allocate { addr } => {
                let key = namespace_of(addr)
                    .expect("≥ 2 components — every mint extends a registered parent");
                let n = ordinal(addr.tumbler()).clone();
                // Contiguity fail-stop: every record M3's own paths stage
                // mints exactly c_{m+1}, so at fold time the ordinal is
                // frontier + 1 — a regressed or jumped ordinal is OUTSIDE the
                // totality domain, never silently absorbed.
                debug_assert_eq!(
                    n,
                    s.frontiers.get(&key).cloned().unwrap_or_else(Nat::zero) + 1u32,
                    "Allocate ordinal must equal its namespace frontier + 1"
                );
                s.frontiers.insert(key, n);
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
    /// `next(B, p, g)` in closed form (§1): the chain `S(p, g)` is
    /// `cₙ = p ++ [0]^(g−1) ++ [n]`, so the next address is
    /// `c_{m+1}` — read the count, advance the trailing ordinal. Pure function
    /// of `frontiers` (B2 determinism — the natural property-test oracle).
    /// M1's `checked_inc` is the TA5a gate ⇒ B6(ii)/(iii); routing every first
    /// emission through it is the defensive guard (it can only fire on a
    /// corrupted frontier).
    ///
    /// PRECONDITION — `key.parent` is T4-valid, and under
    /// [`Generator::NextField`] it is not Element-level (M1's TA5a admits
    /// `k = 2` only below that tier). The five mints are the only callers,
    /// one per chain, and each discharges it by a gate that has
    /// already run: [`version_ns`] and [`document_ns`] clone their anchor
    /// from an [`Address`], as does [`account_ns`] behind
    /// [`M3State::mint_account`]'s registered-entity gate; and
    /// [`content_ns`]/[`link_ns`] sit behind `is_registered_document`, which
    /// makes `home` a Document, so `inc(home, 2)` lands inside T4. Off a
    /// checkpoint the anchor arrives through [`NsKeyShadow`], which
    /// re-establishes its T4 half where no caller can; the
    /// [`Generator::NextField`]/Element half is a pairing that no per-key door
    /// settles and none need, since it fails as a `GateViolation` here rather
    /// than a panic.
    ///
    /// [`M3State::content_lock_key`] and [`M3State::link_lock_key`] do NOT
    /// discharge it: handed an element they build an anchor outside T4. That
    /// costs nothing, because a lock key is never dereferenced — what those
    /// two owe is [`ns_lock_key`]'s injectivity, which holds for any anchor.
    pub(crate) fn next_in(&self, key: &NsKey) -> Result<Address, GateViolation> {
        let m = self.frontiers.get(key).cloned().unwrap_or_else(Nat::zero);
        let anchor = validate(key.parent.clone()).expect(
            "next_in precondition: a T4-valid anchor — the caller's gate, or NsKeyShadow, established it",
        );
        let c1 = checked_inc(&anchor, key.g.inc_k())?; // c1 = inc(parent, g), trailing ordinal 1
        Ok(if m.is_zero() {
            c1 // first emission
        } else {
            // c_{m+1} = c1 with its trailing ordinal 1 → m+1. M1's `shift`
            // (ordinal-only, n = m ≥ 1) does exactly this and is SAFE here:
            // c1 is a FULL address carrying its ordinal in the last position,
            // not a bare doc·0·subspace base (the TA7a hazard). Re-`validate`
            // is total — c_{m+1} is the same namespace as the gated c1,
            // differing only in a positive ordinal.
            validate(shift(c1.tumbler(), &m))
                .expect("differs from gated c1 only in a positive ordinal")
        })
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
    /// [`M3State::mint_version`]`(source)` — take it BEFORE the closure; the
    /// mint inside READS this key's frontier, and the [`M3Rec`] you stage
    /// ADVANCES it.
    pub fn version_lock_key(source: &Address) -> LockKey {
        ns_lock_key(&version_ns(source))
    }

    /// Document-chain `LockKey`: `(account, 2)`. Pairs with
    /// [`M3State::mint_document`]`(account)` — take it BEFORE the closure; the
    /// mint inside READS this key's frontier, and the [`M3Rec`] you stage
    /// ADVANCES it.
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
    pub fn principals_lock_key() -> LockKey {
        LockKey::new(Space::Principals, &[])
    }

    /// Coarse node-registry key — held by `register_node` so a concurrent
    /// duplicate `RegisterNode` surfaces `NotFresh` instead of silently
    /// coalescing. Node admission needs NO lock for SAFETY (idempotent
    /// `OrdSet` insert, monotone freshness); this only preserves the typed
    /// rejection under per-key concurrency. Redundant under v1's global lock,
    /// exactly like [`M3State::principals_lock_key`].
    pub fn node_lock_key() -> LockKey {
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
// ---------------------------------------------------------------------------

impl M3State {
    /// Next content address under `home`: namespace `(b_C(home), 1)`, element
    /// field `[s_C, m+1]` (§3). [M5: INSERT] Reads the caller's WORKING state
    /// (successive mints in one composite each see the prior mint); checks
    /// only the structural precondition P6/C2; the caller holds
    /// [`M3State::content_lock_key`] and stages the returned [`M3Rec`].
    pub fn mint_content(&self, home: &Address) -> Result<(Address, M3Rec), MintError> {
        if !self.is_registered_document(home) {
            return Err(MintError::HomeNotRegistered); // P6/C2
        }
        let a = self.next_in(&content_ns(home)).map_err(MintError::Gate)?;
        Ok((a.clone(), M3Rec::Allocate { addr: a }))
    }

    /// Next link address under `home`: namespace `(b_L(home), 1)`, element
    /// field `[s_L, m+1]` (§3). [M7: MAKELINK] The caller holds
    /// [`M3State::link_lock_key`]`(home)` and stages the returned [`M3Rec`].
    pub fn mint_link(&self, home: &Address) -> Result<(Address, M3Rec), MintError> {
        if !self.is_registered_document(home) {
            return Err(MintError::HomeNotRegistered); // L1a
        }
        let a = self.next_in(&link_ns(home)).map_err(MintError::Gate)?;
        Ok((a.clone(), M3Rec::Allocate { addr: a }))
    }

    /// Next version identity: namespace `(source, 1)` — the version chain,
    /// kept SEPARATE from the document chain (ASN-0123). [M5: owned
    /// CREATENEWVERSION] The caller holds
    /// [`M3State::version_lock_key`]`(source)` and stages the returned
    /// [`M3Rec`].
    pub fn mint_version(&self, source: &Address) -> Result<(Address, M3Rec), MintError> {
        if !self.is_registered_document(source) {
            // V-WF: registered Document (covers unregistered AND non-document).
            return Err(MintError::SourceNotRegistered);
        }
        let a = self.next_in(&version_ns(source)).map_err(MintError::Gate)?;
        Ok((a.clone(), M3Rec::Allocate { addr: a }))
    }

    /// Next document identity under an account: namespace `(account, 2)`.
    /// [CREATENEWDOCUMENT; cross-owner VERSION; fork] The caller holds
    /// [`M3State::document_lock_key`]`(account)` and stages the returned
    /// [`M3Rec`].
    pub fn mint_document(&self, account: &Address) -> Result<(Address, M3Rec), MintError> {
        if self.entity_level(account) != Some(Level::Account) {
            // P8/CND.pre (covers unregistered AND non-account).
            return Err(MintError::NotAnAccount);
        }
        let a = self
            .next_in(&document_ns(account))
            .map_err(MintError::Gate)?;
        Ok((a.clone(), M3Rec::Allocate { addr: a }))
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
    /// The caller holds [`M3State::account_lock_key`]`(parent)` and stages
    /// the returned [`M3Rec`].
    pub(crate) fn mint_account(&self, parent: &Address) -> Option<(Address, M3Rec)> {
        if !matches!(self.entity_level(parent)?, Level::Node | Level::Account) {
            return None;
        }
        let a = self
            .next_in(&account_ns(parent))
            .expect("a registered node/account anchor with g ≤ 2 passes TA5a");
        Some((a.clone(), M3Rec::Allocate { addr: a }))
    }
}

// ---------------------------------------------------------------------------
// §C Queries (pure; read off any M2 Snapshot; write nothing) + §2 membership.
// ---------------------------------------------------------------------------

impl M3State {
    /// Is `a` a member of its own chain? The §2 decision behind
    /// [`M3State::is_allocated`] (and so behind [`M3State::entity_level`]),
    /// settled by decomposing and comparing against the frontier.
    /// Membership-correctness invariant: for T4-valid `a`, `a` is *exactly*
    /// `c_{ordinal(a)}` of its decomposed `(parent, g)` namespace (ASN-0040
    /// `S(p, d)` canonical form; T4b unique-parse), so `a ∈ {c₁..cₘ}` iff
    /// `1 ≤ ordinal(a) ≤ m` — genuine chain membership with NO false
    /// positives, not an approximation.
    fn is_chain_member(&self, a: &Address) -> bool {
        let Some(key) = namespace_of(a) else {
            return false; // parentless only for a 1-component node — the callers' Node arm
        };
        // An absent frontier is m = 0, which no positive ordinal is ≤, so the
        // missing key needs no branch of its own.
        let n = ordinal(a.tumbler()); // &Nat — compare BY REFERENCE (BigUint is not Copy)
        !n.is_zero() && self.frontiers.get(&key).is_some_and(|m| n <= m)
    }

    /// `true` iff `a` exists in the name space — minted on a frontier in ANY
    /// namespace, content/link included, or, for a node, admitted by
    /// `register_node` (node addresses are never minted here — ASN-0047
    /// NodeBaptism originates them outside the docuverse). The
    /// referential-integrity oracle M5's COPY depends on (§2). Ghost
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

    /// `entity_level(d) == Some(Document)` — the edit/home precondition seam
    /// for M5/M7, and the ⟨⟩-vs-fail bool for M6/M8.
    pub fn is_registered_document(&self, d: &Address) -> bool {
        self.entity_level(d) == Some(Level::Document)
    }

    /// ω(a): WHO owns `a` — the longest-prefix match over Π, answered as the
    /// owning id (§5; ASN-0042 O2/O3/O5). A pure prefix query — valid even
    /// when `a` is not (yet) allocated. THE one walk: the authorization
    /// predicate [`M3State::is_effective_owner`] is stated in terms of it, and
    /// the `principals` range-walk upgrade lands here once, serving both.
    ///
    /// The walk is over Π, keeping the longest covering prefix — the reference
    /// form the design names — and NEVER over `a`'s own reconstructed
    /// prefixes. That is a cost decision, and it is load-bearing: `a` arrives
    /// from a caller, and T4 bounds its zero pattern but not its DEPTH, so a
    /// per-candidate walk would do work quadratic in a length the caller
    /// chooses (an account-tier `[1, 0, 1, 1, …]` has an admissible candidate
    /// at every length, and rebuilding each one clones its components), while
    /// `create_new_document` and `delegate` both evaluate ω in-closure under
    /// the held global [`M3State::principals_lock_key`]. Here the work is
    /// `Σ_{p ∈ Π} |p|` component comparisons and no allocation: to enlarge it
    /// an attacker must first commit durable, ω-gated, next-form-gated
    /// delegations, one journal record per principal. So a deep probe costs no
    /// more than a shallow one, and neither costs O(#allocated).
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
        self.principals
            .iter()
            .filter(|(p, _)| {
                matches!(p.level(), Level::Node | Level::Account) && prefix_contains(p, a)
            })
            .max_by_key(|(p, _)| p.tumbler().len())
            .map(|(_, id)| *id)
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
    /// Pure frontier read off any snapshot; `None` unless `parent` is a
    /// REGISTERED node or account (the one monotone gate a peek can answer
    /// honestly — E is append-only, so a `Some` answer never regresses), which
    /// leaves `None` exactly one meaning. The returned prefix still faces
    /// `delegate`'s full in-closure gate — two racing peeks of the same value
    /// leave exactly one winner.
    pub fn next_account_prefix(&self, parent: &Address) -> Option<Address> {
        self.mint_account(parent).map(|(addr, _)| addr)
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
    /// (iv) would not fail loudly — it would let delegation seat a principal
    /// ABOVE an existing one, which is the nesting invariant (iv) exists to
    /// hold.
    pub(crate) fn has_principal_strictly_under(&self, p: &Address) -> bool {
        self.principals
            .range(p.clone()..)
            .next()
            .is_some_and(|(first, _)| prefix_contains(p, first) && first != p)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(comps: &[u32]) -> Tumbler {
        Tumbler::new(comps.iter().map(|&c| Nat::from(c))).expect("nonempty")
    }

    fn a(comps: &[u32]) -> Address {
        validate(t(comps)).expect("T4-valid")
    }

    /// §1: a frontier key re-enters memory through its own door. `next_in`
    /// re-`validate`s a loaded key's anchor with an `expect`, and `Tumbler`
    /// admits any nonempty component sequence — `[1, 0]` decodes and is not
    /// T4-valid — so without the door a checkpoint could seat a key that is
    /// a panic waiting for the first reader to dereference it. Refused while
    /// it is still bytes, at no cost to the encoding.
    #[test]
    fn a_frontier_key_re_enters_through_its_t4_door() {
        #[derive(Serialize)]
        struct RawKey {
            parent: Tumbler,
            g: u8,
        }

        let good = NsKey {
            parent: t(&[1, 0, 1]),
            g: Generator::NextField,
        };
        let bytes = bincode::serialize(&good).expect("serialize the key");
        assert_eq!(
            bincode::deserialize::<NsKey>(&bytes).expect("a well-formed key round-trips"),
            good
        );
        // The door changes nothing at rest: the key's bytes are still the
        // struct's own, anchor tumbler then generator numeral.
        assert_eq!(
            bytes,
            bincode::serialize(&RawKey {
                parent: t(&[1, 0, 1]),
                g: 2
            })
            .expect("serialize the raw shape"),
        );

        // Anchors no `*_ns` constructor could have produced: a trailing
        // separator and a doubled one, both nonempty tumblers, neither T4.
        for bogus in [vec![1u32, 0], vec![1, 0, 0, 1]] {
            let frame = bincode::serialize(&RawKey {
                parent: t(&bogus),
                g: 1,
            })
            .expect("serialize the raw shape");
            assert!(
                bincode::deserialize::<NsKey>(&frame).is_err(),
                "{bogus:?} decoded as a namespace anchor"
            );
        }
    }

    /// The generator IS ASN-0040's `d ∈ {1, 2}`: it is the numeral wherever
    /// bytes are written — the checkpointed frontier key and `ns_lock_key`'s
    /// trailing byte — and no third value survives the way back in, so the
    /// `k` `next_in` hands M1 is one its TA5a gate admits by shape.
    #[test]
    fn generator_is_its_numeral_and_admits_no_third_value() {
        for (g, n) in [(Generator::SameField, 1u8), (Generator::NextField, 2u8)] {
            assert_eq!(u8::from(g), n);
            assert_eq!(g.inc_k(), n as usize);
            assert_eq!(Generator::try_from(n), Ok(g));
            assert_eq!(
                bincode::serialize(&g).expect("serialize the generator"),
                bincode::serialize(&n).expect("serialize the numeral"),
            );
        }
        for bogus in [0u8, 3, 7, 255] {
            assert!(Generator::try_from(bogus).is_err());
            assert!(bincode::deserialize::<Generator>(&[bogus]).is_err());
        }
    }

    /// The chain-family rule at the tier pairs the `*_ns` family is built at:
    /// an anchor and child at the SAME tier extend the anchor's own field, a
    /// child one tier down opens the next one. This is what puts the document
    /// chain `(A, 2)` and the version chain `(d, 1)` on separate frontiers
    /// (ASN-0123 VD), so the two keys anchored at one account differ.
    #[test]
    fn the_chain_family_rule_separates_document_from_version() {
        assert_eq!(
            generator(Level::Element, Level::Element),
            Generator::SameField
        );
        assert_eq!(
            generator(Level::Document, Level::Document),
            Generator::SameField
        );
        assert_eq!(
            generator(Level::Account, Level::Document),
            Generator::NextField
        );
        assert_eq!(generator(Level::Node, Level::Account), Generator::NextField);
        assert_eq!(
            generator(Level::Account, Level::Account),
            Generator::SameField
        );

        // The fixed families carry what the rule yields, and the two chains
        // anchored at one account are distinct keys.
        let acct = validate(Tumbler::new([1u32, 0, 1].map(Nat::from)).expect("nonempty"))
            .expect("T4-valid account");
        assert_eq!(version_ns(&acct).g, Generator::SameField);
        assert_eq!(document_ns(&acct).g, Generator::NextField);
        assert_ne!(version_ns(&acct), document_ns(&acct));
        assert_eq!(account_ns(&acct).g, Generator::SameField);

        let doc = validate(Tumbler::new([1u32, 0, 1, 0, 1].map(Nat::from)).expect("nonempty"))
            .expect("T4-valid document");
        assert_eq!(content_ns(&doc).g, Generator::SameField);
        assert_eq!(link_ns(&doc).g, Generator::SameField);
        // The child-side derivation agrees with the anchor-side one: the
        // account peeked under a node sits in the very key `account_ns`
        // builds there.
        let node = validate(Tumbler::new([Nat::from(1u32)]).expect("nonempty")).expect("T4-valid");
        assert_eq!(account_ns(&node).g, Generator::NextField);
        assert_eq!(namespace_of(&acct), Some(account_ns(&node)));
    }

    /// §1/§8: for every chain family, the key derived from a MINTED address
    /// (the child side, which `apply_m3` uses to advance the frontier) is
    /// byte-identical to the key its caller locks and its mint reads (the
    /// anchor side). A divergence would under-serialize a namespace and
    /// REUSE an address. Checked at two ordinals per chain, because every
    /// member of a chain must derive the same key or the frontier forks.
    #[test]
    fn each_chains_minted_addresses_advance_the_key_their_mint_read() {
        let node = a(&[1]);
        let acct = a(&[1, 0, 1]);
        let doc = a(&[1, 0, 1, 0, 1]);
        for (family, anchor_key, members) in [
            (
                "content",
                content_ns(&doc),
                [a(&[1, 0, 1, 0, 1, 0, 1, 1]), a(&[1, 0, 1, 0, 1, 0, 1, 2])],
            ),
            (
                "link",
                link_ns(&doc),
                [a(&[1, 0, 1, 0, 1, 0, 2, 1]), a(&[1, 0, 1, 0, 1, 0, 2, 2])],
            ),
            (
                "version",
                version_ns(&doc),
                [a(&[1, 0, 1, 0, 1, 1]), a(&[1, 0, 1, 0, 1, 2])],
            ),
            (
                "document",
                document_ns(&acct),
                [a(&[1, 0, 1, 0, 1]), a(&[1, 0, 1, 0, 2])],
            ),
            (
                "account under a node",
                account_ns(&node),
                [a(&[1, 0, 1]), a(&[1, 0, 2])],
            ),
            (
                "sub-account under an account",
                account_ns(&acct),
                [a(&[1, 0, 1, 1]), a(&[1, 0, 1, 2])],
            ),
        ] {
            for member in &members {
                let child_key = namespace_of(member).expect("minted addresses have a parent");
                assert_eq!(
                    child_key, anchor_key,
                    "{family}: the fold's key for {member:?} is not the mint's key"
                );
                assert_eq!(
                    ns_lock_key(&child_key),
                    ns_lock_key(&anchor_key),
                    "{family}: lock bytes differ from frontier bytes for {member:?}"
                );
            }
        }
        // The key constructors are that same encoding, so a caller's key
        // and the frontier its mint reads are one value — the account
        // chain included, whose lock `delegate` takes and whose frontier
        // `mint_account` reads.
        assert_eq!(
            M3State::content_lock_key(&doc),
            ns_lock_key(&content_ns(&doc))
        );
        assert_eq!(M3State::link_lock_key(&doc), ns_lock_key(&link_ns(&doc)));
        assert_eq!(
            M3State::version_lock_key(&doc),
            ns_lock_key(&version_ns(&doc))
        );
        assert_eq!(
            M3State::document_lock_key(&acct),
            ns_lock_key(&document_ns(&acct))
        );
        assert_eq!(
            M3State::account_lock_key(&node),
            ns_lock_key(&account_ns(&node))
        );
        assert_eq!(
            M3State::account_lock_key(&acct),
            ns_lock_key(&account_ns(&acct))
        );
    }

    /// The `NsKey → LockKey` map is INJECTIVE (§1) — distinct namespaces,
    /// distinct locks — and functional. Over a family crossed with both
    /// generators, including the pair that makes the per-component length
    /// delimiter load-bearing: without it `[1, 256]` and `[257, 0]` encode
    /// alike.
    #[test]
    fn the_lock_key_encoding_is_injective_over_a_generated_family() {
        let parents: Vec<Tumbler> = [
            vec![1u32],
            vec![1, 1],
            vec![2],
            vec![1, 2],
            vec![1, 256],
            vec![257, 0],
            vec![1, 0, 1],
            vec![1, 0, 1, 1],
            vec![1, 0, 1, 0, 1],
            vec![1, 0, 1, 0, 1, 0, 1],
            vec![1, 0, 1, 0, 1, 0, 2],
            vec![1, 0, 1, 0, 1, 0, 1, 1],
        ]
        .into_iter()
        .map(|c| Tumbler::new(c.into_iter().map(Nat::from)).expect("nonempty"))
        .collect();
        let mut keys = Vec::new();
        for parent in &parents {
            for g in [Generator::SameField, Generator::NextField] {
                let key = NsKey {
                    parent: parent.clone(),
                    g,
                };
                let encoded = ns_lock_key(&key);
                // Functional: the same key encodes to the same bytes every
                // time.
                assert_eq!(ns_lock_key(&key), encoded);
                keys.push((key, encoded));
            }
        }
        for i in 0..keys.len() {
            for j in (i + 1)..keys.len() {
                assert_ne!(
                    keys[i].1, keys[j].1,
                    "distinct namespaces share a lock: {:?} and {:?}",
                    keys[i].0, keys[j].0
                );
            }
        }
    }

    /// What a key owes is injectivity, and it owes it on every anchor — a
    /// lock key is compared, never dereferenced. `content_ns`/`link_ns` on an
    /// element build `e ++ [0, 1]` and `e ++ [0, 2]`, four separators apiece
    /// and so outside T4, which is exactly the shape `next_in`'s precondition
    /// excludes and no mint can reach: both go through
    /// `is_registered_document`, which admits only a Document. The keys are
    /// still deterministic and still distinct, which is the whole of what
    /// [`M3State::content_lock_key`] and [`M3State::link_lock_key`] promise.
    #[test]
    fn a_lock_key_is_injective_even_on_an_anchor_no_mint_could_reach() {
        let element = a(&[1, 0, 1, 0, 1, 0, 1, 1]);
        assert_eq!(element.level(), Level::Element);

        let (content, link) = (content_ns(&element), link_ns(&element));
        assert!(!is_t4_valid(&content.parent), "the anchor is outside T4");
        assert!(!is_t4_valid(&link.parent), "the anchor is outside T4");

        // Deterministic, and the two subspaces stay apart — the properties
        // the public constructors exist to provide.
        assert_eq!(
            M3State::content_lock_key(&element),
            M3State::content_lock_key(&element)
        );
        assert_ne!(
            M3State::content_lock_key(&element),
            M3State::link_lock_key(&element)
        );
        // …and neither collides with the key of the document that homes it.
        let doc = a(&[1, 0, 1, 0, 1]);
        assert_ne!(
            M3State::content_lock_key(&element),
            M3State::content_lock_key(&doc)
        );
    }

    /// §6 (iv): the single probe answers "does a registered principal sit
    /// STRICTLY under `p`?" — checked over the shape family one probe can
    /// meet, because only ONE key is ever examined, so a wrong range bound or
    /// a dropped containment test still answers correctly at a chosen point.
    /// Π holds only the seats each row names, plus genesis's `[1]`, which is
    /// an ANCESTOR of `p` in every row and sorts before it — so no row's
    /// answer may come from it.
    ///
    /// The last two rows are the PRECONDITION `p ∉ Π` made executable: once
    /// `p` is itself a principal the block of keys ≥ `p` opens with `p`, so
    /// the probe answers false whether or not a principal sits beneath. That
    /// is why [`crate::Namespace::delegate`] PINS (i) and (ii) ahead of (iv),
    /// and a probe made correct for `p ∈ Π` makes the last row wrong and that
    /// pinning revisable — one edit, both consequences.
    #[test]
    fn the_top_down_probe_sees_strict_descendants_and_nothing_else() {
        let p = a(&[1, 0, 1]);
        for (shape, seats, expected) in [
            ("an empty subtree", vec![], false),
            ("a strict child", vec![vec![1, 0, 1, 1]], true),
            (
                "a deep strict descendant only",
                vec![vec![1, 0, 1, 1, 1]],
                true,
            ),
            (
                "a successor that is no descendant",
                vec![vec![1, 0, 2]],
                false,
            ),
            ("p itself, with nothing beneath", vec![vec![1, 0, 1]], false),
            (
                "p itself, with a child beneath — the precondition's blind spot",
                vec![vec![1, 0, 1], vec![1, 0, 1, 1]],
                false,
            ),
        ] {
            let state =
                seats
                    .iter()
                    .enumerate()
                    .fold(M3State::genesis(), |state, (nth, prefix)| {
                        state.apply_m3(&M3Rec::RegisterPrincipal {
                            prefix: a(prefix),
                            id: PrincipalId(nth as u64 + 1),
                        })
                    });
            assert_eq!(
                state.has_principal_strictly_under(&p),
                expected,
                "{shape}: the top-down probe disagrees"
            );
        }
    }

    /// The [`M3RecShadow`] door tests `#a ≥ 2`; [`M3State::apply_m3`]'s
    /// `expect` needs `parent(a).is_some()`. Two spellings of one fact, sound
    /// only while M1's `parent` is `None` at exactly one component — a
    /// property M3 asserts in prose and cannot enforce. Pinned here so a
    /// change in M1 reddens this suite instead of panicking the applier at
    /// every replay from then on.
    #[test]
    fn the_allocate_door_and_the_folds_expect_are_one_fact() {
        for comps in [
            vec![1u32],
            vec![7],
            vec![1, 1],
            vec![1, 7],
            vec![2, 3],
            vec![1, 0, 1],
            vec![1, 0, 1, 1],
            vec![1, 0, 1, 0, 1],
            vec![1, 0, 1, 0, 1, 1],
            vec![1, 0, 1, 0, 1, 0, 1],
            vec![1, 0, 1, 0, 1, 0, 2],
            vec![1, 0, 1, 0, 1, 0, 1, 1],
            vec![1, 0, 1, 0, 1, 0, 2, 9],
        ] {
            let addr = a(&comps);
            let door_admits = addr.tumbler().len() >= 2;
            assert_eq!(
                parent(&addr).is_some(),
                door_admits,
                "{comps:?}: the door's length test and M1's `parent` disagree"
            );
            assert_eq!(
                namespace_of(&addr).is_some(),
                door_admits,
                "{comps:?}: the fold's key derivation disagrees with the door"
            );
        }
    }
}
