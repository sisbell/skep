//! §Core data model, §1–§5 — M3's `WorldState` slice ([`M3State`]), its
//! journal deltas ([`M3Rec`]) and fold ([`M3State::apply_ns`]); the frontier
//! allocator (§1, the heart), entity membership (§2), the content/link
//! sub-allocators (§3), the admission gates (§4), and the principal registry
//! with the ω resolver (§5).

use num_traits::{One, Zero};
use serde::{Deserialize, Serialize};
use skep_address::{
    checked_inc, inc, is_prefix, ordinal, parent, shift, validate, zeros, Address, GateViolation,
    Level, Nat, Tumbler,
};
use skep_kernel::{LockKey, Space};

use crate::error::MintError;

/// Opaque external identity, supplied by M10/session. `delegate` enforces
/// id-injectivity ([`crate::DelegateError::DuplicateId`]) ⇒ one id ↦ one
/// principal, which keeps [`M3State::principal_by_id`]/[`M3State::principal_prefix`]
/// and the ω-auth gate single-valued (§6).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub struct PrincipalId(pub u64);

/// π₀'s fixed id (genesis Σ₀, O14); the ω-auth gate keys on it, so M10 binds
/// the bootstrap session to it. `delegate`'s id-freshness gate then prevents
/// any later principal from re-claiming id 0 (§7).
pub const BOOTSTRAP_PRINCIPAL: PrincipalId = PrincipalId(0);

/// A registered principal: opaque id plus ownership prefix — T4-valid,
/// `zeros ≤ 1` (account/node tier only, O1a).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Principal {
    pub id: PrincipalId,
    pub prefix: Address,
}

/// A namespace — ASN-0040's `(p, d)`: chain anchor `parent` + generator
/// `g ∈ {1, 2}`. THE frontier-map key, and (through the injective
/// [`ns_lock_key`] encoding) the lock key — one key type, one code path, so
/// the two can never drift (§1). Keying by `(parent, g)` keeps the document
/// chain `(A, 2)` and the version chain `(d, 1)` on SEPARATE frontiers by
/// construction (ASN-0123 VD — the entire fix for ASN-0103's
/// version/document collision, requiring no length filter).
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NsKey {
    parent: Tumbler,
    g: u8, // 1 | 2
}

/// M3's journal deltas — lifted to `W::Record` via the engine's `From<M3Rec>`
/// impl (the write-side mirror of [`crate::HasM3`]) and folded by
/// [`M3State::apply_ns`]. One `Allocate` variant suffices for every minted
/// address (entity, content, link) because the frontier map is uniform; the
/// level distinction is recovered at *query* time from `zeros`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum M3Rec {
    /// A mint: advance `frontiers[namespace_of(addr)]` (§1). The `(parent, g)`
    /// of an `Allocate` is exactly the `NsKey` of the `LockKey` the minting op
    /// held — frontier key and lock key are the same key.
    Allocate { addr: Tumbler },
    /// External node admission (ASN-0047 NodeBaptism; §7).
    RegisterNode { addr: Tumbler },
    /// Delegation's principal half (§6).
    RegisterPrincipal { prefix: Tumbler, id: PrincipalId },
}

/// M3's slice of the engine's `WorldState`, reached via [`crate::HasM3::m3`].
/// All persistent (`im`), so each commit yields a cheap structurally-shared
/// version — free MVCC snapshots for readers and free historical ω_Σ.
///
/// **The journal is the sole authority** (M2); these three structures are the
/// *recovered working representation*, folded by [`M3State::apply_ns`]. All
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
#[derive(Clone, Serialize, Deserialize)]
pub struct M3State {
    /// THE registry, in B1+B2 compressed form. A namespace's entire realized
    /// set `{c₁..cₘ}` IS the single count `m` — a gap is literally
    /// unrepresentable (B1 free). Covers every chain: accounts, documents,
    /// versions, content, links. Values are big-ints (B9 unbounded). A
    /// `HashMap` because mint and membership are *point* lookups on one
    /// namespace; namespaces are never iterated, so order is not paid for.
    frontiers: im::HashMap<NsKey, Nat>,

    /// Node addresses (zeros = 0). Externally minted (ASN-0047 NodeBaptism —
    /// provisioning mints node addresses OUTSIDE the docuverse), so possibly
    /// non-contiguous → held explicitly, not frontier-encoded. M3 SUPPRESSES
    /// ASN-0040's `baptize(node, 1)` child-node capability (Conflicts §7):
    /// internal minting never yields a zeros = 0 address; ongoing admission is
    /// `register_node`, never baptism. Seeded `{[1]}`.
    nodes: im::OrdSet<Tumbler>,

    /// Principal registry Π, keyed by ownership prefix. Small (node/account
    /// tier only, O1a). Append-only with immutable prefixes (O12/O13),
    /// prefix-injective (O1b, by (v)) AND id-injective (`delegate`'s
    /// DuplicateId gate, §6) — both the by-prefix key and the by-id scan are
    /// single-valued. The ONLY authoritative ownership state — the delegation
    /// forest is recomputable (NestingByDelegation) and never stored. An
    /// `OrdMap` because the top-down check needs a descendant *range* probe
    /// (§6 (iv)) and ordering leaves the ω range-walk upgrade open.
    principals: im::OrdMap<Tumbler, Principal>,
}

// ---------------------------------------------------------------------------
// Pure structural helpers (the house style for pure helpers: free functions).
// ---------------------------------------------------------------------------

/// The bootstrap node root `[1]` (Σ₀).
pub(crate) fn bootstrap_root() -> Tumbler {
    Tumbler::new([Nat::from(1u32)]).expect("a one-component sequence is nonempty")
}

/// THE namespace derivation: the [`NsKey`] `a` sits in — chain anchor
/// `parent(a)`, generator `g = 1` when `a` extends its parent's field (equal
/// `zeros`) and `g = 2` when it opens the next one. Pure M1, and total:
/// `None` EXACTLY for a parentless 1-component node (e.g. `[7]`), which is
/// T4-valid yet anchors no chain — M1's `parent` returns `None` there, and
/// that is the one input for which no namespace exists.
///
/// Every reader of a frontier key routes through here — `delegate` for BOTH
/// its next-form check and its held namespace `LockKey`, membership for its
/// chain range probe, the fold for its frontier advance — so the checked key,
/// the locked key, and the key a staged `Allocate` advances are one and the
/// same key by construction (§1/§2/§6). Callers that hold a ≥ 2-component
/// address by their own gate discharge the `None` case with an `expect` that
/// names that gate.
pub(crate) fn namespace_of(a: &Address) -> Option<NsKey> {
    let par = parent(a)?;
    let g = if zeros(a.tumbler()) == zeros(par.tumbler()) { 1 } else { 2 };
    Some(NsKey { parent: par.tumbler().clone(), g })
}

// The four namespace helpers — the ONE code path each mint and each
// `*_lock_key` reuses (§1/§3). The subspace identifier is the element-field's
// FIRST component (`s_C = 1`, `s_L = 2`), read via M1's `subspace()` — NOT the
// `.0.` separator (the corpus-wide misread to guard against); `s_C ≠ s_L` is
// what makes content and link address spaces disjoint by construction
// (SD/L14, T7).
fn content_ns(d: &Address) -> NsKey {
    NsKey { parent: inc(d.tumbler(), 2), g: 1 } // b_C(d) = inc(d, 2)
}
fn link_ns(d: &Address) -> NsKey {
    NsKey { parent: inc(&inc(d.tumbler(), 2), 0), g: 1 } // b_L(d) = inc(b_C(d), 0)
}
fn version_ns(s: &Address) -> NsKey {
    NsKey { parent: s.tumbler().clone(), g: 1 } // (source, 1) — ASN-0123 separate chain
}
fn document_ns(a: &Address) -> NsKey {
    NsKey { parent: a.tumbler().clone(), g: 2 } // (account, 2)
}

// The three key domains M3 serializes on — namespace frontiers, THE principal
// registry, THE node registry — must occupy disjoint byte spaces (§1/§8: an
// alias would under-serialize a namespace and REUSE an address, the one fatal
// error). Each takes its own tag from M2's central `Space` enum
// (`Space::Namespace` / `Space::Principals` / `Space::Nodes`), where every
// tag in the system is assigned, so the disjointness holds against the other
// stores' key spaces too and not merely against M3's own.

/// The injective, space-tagged `NsKey → LockKey` encoding (§1): tag byte,
/// 4-byte BE component count, each component length-delimited (4-byte BE
/// length + minimal BE magnitude bytes), then `g`. Injectivity is what
/// guarantees distinct namespaces map to distinct locks; both the
/// `*_lock_key` constructors and the frontier advance route through the SAME
/// `*_ns` helper and THIS encoding, so the held lock key and the staged
/// frontier key are the same bytes by one code path.
pub(crate) fn ns_lock_key(k: &NsKey) -> LockKey {
    let mut b = Vec::new();
    b.extend((k.parent.len() as u32).to_be_bytes());
    for comp in &k.parent {
        let c = comp.to_bytes_be();
        b.extend((c.len() as u32).to_be_bytes());
        b.extend(c);
    }
    b.push(k.g);
    LockKey::new(Space::Namespace, &b)
}

/// `a`'s T4-valid, `zeros ≤ 1` prefixes, LONGEST FIRST (O1a) — the ω
/// candidate walk (§5). FREE function — pure, consults no state. For each
/// prefix length from `#a` down to 1, reconstruct the prefix and keep it iff
/// T4-valid ∧ zeros ≤ 1: `validate` drops the trailing-separator lengths
/// (`N·0`, non-T4) and the zeros ≤ 1 filter caps the walk at the account
/// field — leaving exactly the account-tier (`N·0·U[..j]`) then node-tier
/// (`N[..i]`) prefixes. Every account-tier prefix is strictly longer than
/// every node-tier one, so descending length is globally longest-first;
/// ≤ `#a` (= depth) candidates, never O(#allocated).
fn principal_tier_prefixes(a: &Address) -> impl Iterator<Item = Tumbler> + '_ {
    (1..=a.tumbler().len()).rev().filter_map(move |plen| {
        let p = Tumbler::new(a.tumbler().iter().take(plen).cloned()).ok()?;
        validate(p)
            .ok()
            .filter(|ad| zeros(ad.tumbler()) <= 1)
            .map(|ad| ad.tumbler().clone())
    })
}

// ---------------------------------------------------------------------------
// §D Genesis and the fold.
// ---------------------------------------------------------------------------

impl M3State {
    /// Σ₀ + O14: `nodes = {[1]}`, `frontiers = {}`,
    /// `Π = { [1] → Principal{BOOTSTRAP_PRINCIPAL, [1]} }`. `pub` — the engine
    /// seeds `Kernel::open(cfg, genesis-World)` with it; "load empty journal"
    /// and "fresh genesis" are the same code path (§7). Deterministic, per
    /// M2's byte-identical-genesis caller contract.
    pub fn genesis() -> M3State {
        let root = bootstrap_root();
        let root_addr = validate(root.clone()).expect("the bootstrap root [1] is T4-valid");
        M3State {
            frontiers: im::HashMap::new(),
            nodes: im::OrdSet::unit(root.clone()),
            principals: im::OrdMap::unit(
                root,
                Principal { id: BOOTSTRAP_PRINCIPAL, prefix: root_addr },
            ),
        }
    }

    /// M3's fold — `pub`: the engine crate wires `World::apply`'s `Record::Ns`
    /// dispatch to this. TOTALITY DOMAIN (M2's total-apply obligation, stated
    /// here at the seam the engine wires): total — deterministic,
    /// side-effect-free, panic-free — over every record staged by M3's own
    /// paths, the only record source (every mint extends a REGISTERED parent,
    /// so an `Allocate` has ≥ 2 components; `delegate` tier-checks (iii)
    /// before staging, so a `RegisterPrincipal` prefix parses `N·0·U`). A
    /// hand-constructed malformed `M3Rec` (e.g. a 1-component `Allocate`) is
    /// OUTSIDE this domain and fail-stops on the expects by design — as does
    /// an `Allocate` that regresses or jumps a frontier (ordinal ≠ count + 1),
    /// on the contiguity `debug_assert` — corruption, not a live error path.
    pub fn apply_ns(&self, r: &M3Rec) -> M3State {
        let mut s = self.clone();
        match r {
            M3Rec::Allocate { addr } => {
                let ad = validate(addr.clone()).expect("a minted address is T4-valid");
                let key = namespace_of(&ad)
                    .expect("≥ 2 components — every mint extends a registered parent");
                let n = ordinal(addr).clone();
                // Contiguity fail-stop (the frontier mirror of the shape
                // expects): every record M3's own paths stage mints exactly
                // c_{m+1}, so at fold time the ordinal is frontier + 1 — a
                // regressed or jumped ordinal is OUTSIDE the totality domain,
                // never silently absorbed.
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
                let ad = validate(prefix.clone()).expect("a registered principal prefix is T4-valid");
                s.principals.insert(prefix.clone(), Principal { id: *id, prefix: ad });
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
    pub(crate) fn next_in(&self, key: &NsKey) -> Result<Address, GateViolation> {
        let m = self.frontiers.get(key).cloned().unwrap_or_else(Nat::zero);
        let anchor =
            validate(key.parent.clone()).expect("namespace parents are T4-valid by construction");
        let c1 = checked_inc(&anchor, key.g as usize)?; // c1 = inc(parent, g), trailing ordinal 1
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

    /// Namespace `LockKey` for `transact`'s `keys` arg — call BEFORE the
    /// closure; the mint advances the same key, byte-identically, because both
    /// route through the one `content_ns` + [`ns_lock_key`] path (§1). Never a
    /// coarser `(home_doc, g)` key: the three g = 1 chains under one document
    /// — content `(b_C(d), 1)`, link `(b_L(d), 1)`, version `(d, 1)` — get
    /// three DISTINCT locks (B7/B8).
    pub fn content_lock_key(home: &Address) -> LockKey {
        ns_lock_key(&content_ns(home))
    }

    /// Link-chain `LockKey`: `(b_L(home), 1)` (§1/§3).
    pub fn link_lock_key(home: &Address) -> LockKey {
        ns_lock_key(&link_ns(home))
    }

    /// Version-chain `LockKey`: `(source, 1)` — SEPARATE from the document
    /// chain below (ASN-0123 VD).
    pub fn version_lock_key(source: &Address) -> LockKey {
        ns_lock_key(&version_ns(source))
    }

    /// Document-chain `LockKey`: `(account, 2)`.
    pub fn document_lock_key(account: &Address) -> LockKey {
        ns_lock_key(&document_ns(account))
    }

    /// THE single global principal-registry key (NOT per-subtree — §8 / Open
    /// build decisions "Serialization granularity"). LOAD-BEARING in
    /// `delegate`: serializes its fresh-prefix top-down / next-form /
    /// authorization reads against concurrent same-namespace delegations AND
    /// its id-freshness read against concurrent same-id delegations — the id
    /// race is CROSS-namespace (same `new_id`, different `new_prefix`), so
    /// only a single global key serializes it. Held DEFENSIVELY by
    /// `create_new_document` (its ω read is stale-safe — ω of an *existing*
    /// account is stable, §6/§8). M5's cross-owner VERSION does NOT need it:
    /// it pre-reads the stable ω(d_src). Redundant under M2 v1's global
    /// applier lock.
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
// §A The four pure mints (folded into M5/M7 composites; M2 contract 3).
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
        Ok((a.clone(), M3Rec::Allocate { addr: a.tumbler().clone() }))
    }

    /// Next link address under `home`: namespace `(b_L(home), 1)`, element
    /// field `[s_L, m+1]` (§3). [M7: MAKELINK]
    pub fn mint_link(&self, home: &Address) -> Result<(Address, M3Rec), MintError> {
        if !self.is_registered_document(home) {
            return Err(MintError::HomeNotRegistered); // L1a
        }
        let a = self.next_in(&link_ns(home)).map_err(MintError::Gate)?;
        Ok((a.clone(), M3Rec::Allocate { addr: a.tumbler().clone() }))
    }

    /// Next version identity: namespace `(source, 1)` — the version chain,
    /// kept SEPARATE from the document chain (ASN-0123). [M5: owned
    /// CREATENEWVERSION]
    pub fn mint_version(&self, source: &Address) -> Result<(Address, M3Rec), MintError> {
        if self.entity_level(source) != Some(Level::Document) {
            // V-WF: registered Document (covers unregistered AND non-document).
            return Err(MintError::SourceNotRegistered);
        }
        let a = self.next_in(&version_ns(source)).map_err(MintError::Gate)?;
        Ok((a.clone(), M3Rec::Allocate { addr: a.tumbler().clone() }))
    }

    /// Next document identity under an account: namespace `(account, 2)`.
    /// [CREATENEWDOCUMENT; cross-owner VERSION; fork]
    pub fn mint_document(&self, account: &Address) -> Result<(Address, M3Rec), MintError> {
        if self.entity_level(account) != Some(Level::Account) {
            // P8/CND.pre (covers unregistered AND non-account).
            return Err(MintError::NotAnAccount);
        }
        let a = self.next_in(&document_ns(account)).map_err(MintError::Gate)?;
        Ok((a.clone(), M3Rec::Allocate { addr: a.tumbler().clone() }))
    }
}

// ---------------------------------------------------------------------------
// §C Queries (pure; read off any M2 Snapshot; write nothing) + §2 membership.
// ---------------------------------------------------------------------------

impl M3State {
    /// The §2 decompose-and-range check, shared by [`M3State::entity_level`]
    /// and [`M3State::is_allocated`]. Membership-correctness invariant: for
    /// T4-valid `a`, `a` is *exactly* `c_{ordinal(a)}` of its decomposed
    /// `(parent, g)` namespace (ASN-0040 `S(p, d)` canonical form; T4b
    /// unique-parse), so `a ∈ {c₁..cₘ}` iff `1 ≤ ordinal(a) ≤ m` — genuine
    /// chain membership with NO false positives, not an approximation.
    fn in_chain_range(&self, a: &Address) -> bool {
        let Some(key) = namespace_of(a) else {
            return false; // parentless only for a 1-component node — the callers' Node arm
        };
        let m = self.frontiers.get(&key).cloned().unwrap_or_else(Nat::zero);
        let n = ordinal(a.tumbler()); // &Nat — compare BY REFERENCE (BigUint is not Copy)
        n >= &Nat::one() && n <= &m
    }

    /// `true` iff `a` is minted in ANY namespace, content/link included (the
    /// referential-integrity oracle M5's COPY depends on — §2). Ghost
    /// principle (B3): reflects *minting*, never byte-presence — a
    /// registered-empty document is a valid, addressable ghost; content
    /// existence is M4's separate axis. E is append-only, so a `true` answer
    /// is permanent (B0/P1).
    pub fn is_allocated(&self, a: &Address) -> bool {
        match a.level() {
            Level::Node => self.nodes.contains(a.tumbler()),
            // The general decompose-and-compare over ALL non-node levels
            // (incl. Element): a content/link element [d.0.s.n] has parent
            // b_C(d)/b_L(d) at the SAME zeros, so g = 1 and the key is its
            // TRUE content/link namespace.
            Level::Account | Level::Document | Level::Element => self.in_chain_range(a),
        }
    }

    /// `Some(level)` iff `a` is a registered *entity* (zeros ≤ 2); `None` for
    /// an element (content/link are not entities — use
    /// [`M3State::is_allocated`]) or an unregistered address. [ASN-0047 E]
    pub fn entity_level(&self, a: &Address) -> Option<Level> {
        match a.level() {
            Level::Node => self.nodes.contains(a.tumbler()).then_some(Level::Node),
            Level::Account | Level::Document => self.in_chain_range(a).then_some(a.level()),
            Level::Element => None,
        }
    }

    /// `entity_level(d) == Some(Document)` — the edit/home precondition seam
    /// for M5/M7, and the ⟨⟩-vs-fail bool for M6/M8.
    pub fn is_registered_document(&self, d: &Address) -> bool {
        self.entity_level(d) == Some(Level::Document)
    }

    /// ω(a): the effective owner — longest-prefix match over Π (§5; ASN-0042
    /// O2/O3/O5). A pure prefix query — valid even when `a` is not (yet)
    /// allocated. The account-tier floor (O1a) makes it O(depth) point
    /// lookups, never O(#allocated). For the authorization question itself,
    /// ask [`M3State::is_effective_owner`]; this one is for callers that need
    /// the owning principal as a value.
    pub fn effective_owner(&self, a: &Address) -> Option<Principal> {
        principal_tier_prefixes(a).find_map(|p| self.principals.get(&p).cloned())
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
        principal_tier_prefixes(a)
            .find_map(|p| self.principals.get(&p))
            .is_some_and(|p| p.id == id)
    }

    /// Resolve a principal by its opaque id. O(|Π|) scan over
    /// `principals.values()` — Π is account/node-tier only (O1a), hence small
    /// per node. SINGLE-VALUED because `delegate` enforces id-freshness
    /// (DuplicateId), so at most one principal carries any id (§5/§6).
    pub fn principal_by_id(&self, id: PrincipalId) -> Option<Principal> {
        self.principals.values().find(|p| p.id == id).cloned()
    }

    /// `pfx(id)` — the projection the id-centric ops (`fork`, `delegate`) and
    /// the M5→M3 cross-owner-VERSION seam need, since `principals` is keyed by
    /// PREFIX, not id (NOT a point lookup — the §5 scan). Value-stable across
    /// snapshots: prefixes are immutable (O13) and principals persist (O12).
    pub fn principal_prefix(&self, id: PrincipalId) -> Option<Address> {
        self.principal_by_id(id).map(|p| p.prefix)
    }

    /// Peek the next delegable account-tier prefix under `parent` — the exact
    /// value `delegate` will demand as next-form (O17c), so a caller obtains a
    /// valid `new_prefix` instead of guess-and-retry on `NotNextForm`. `g`
    /// follows `parent`'s level: a node ⇒ the `(parent, 2)` account chain; an
    /// account ⇒ the `(parent, 1)` sub-account chain (the sixth chain family
    /// ASN-0042 licenses — Conflicts §8). Both yield zeros = 1. Pure frontier
    /// read off any snapshot; `None` unless `parent` is a REGISTERED node or
    /// account (the one monotone gate a peek can answer honestly — E is
    /// append-only, so a `Some` answer never regresses), which leaves `None`
    /// exactly one meaning. The returned prefix still faces `delegate`'s full
    /// in-closure gate — two racing peeks of the same value leave exactly one
    /// winner.
    pub fn next_account_prefix(&self, parent: &Address) -> Option<Address> {
        let g = match self.entity_level(parent)? {
            Level::Node => 2,
            Level::Account => 1,
            _ => return None,
        };
        let key = NsKey { parent: parent.tumbler().clone(), g };
        Some(
            self.next_in(&key)
                .expect("a registered node/account anchor with g ≤ 2 passes TA5a"),
        )
    }

    /// Containment test (O1): `prefix ≼ a` — pure, total, decidable from the
    /// two addresses alone, consulting no registry state and needing no
    /// coordination. It answers where an address SITS, not who may write it:
    /// authorization is [`M3State::is_effective_owner`] (ω, longest match),
    /// because several principals' prefixes contain the same address — §5.
    pub fn prefix_contains(prefix: &Address, a: &Address) -> bool {
        is_prefix(prefix.tumbler(), a.tumbler())
    }

    /// §6 (iv), concretely: because `principals` is an `OrdMap` under tumbler
    /// order and the extensions of `p` form a contiguous block (T5), a SINGLE
    /// probe settles top-down — take the first key ≥ `p`; a registered
    /// principal sits strictly under `p` iff that key is a strict extension.
    /// If it is not, none is (the block is empty). No full scan.
    pub(crate) fn has_principal_strictly_under(&self, p: &Tumbler) -> bool {
        self.principals
            .range(p.clone()..)
            .next()
            .is_some_and(|(k, _)| is_prefix(p, k) && k != p)
    }
}
