//! §A/§1 — the engine-plug slice: [`LinkState`] (the authoritative
//! append-only links map + the genesis type config + the recomputable
//! hints), the one journal delta [`LinkRec`], the pure fold
//! [`LinkState::apply_link`], and the load-time [`LinkState::rebuild_derived`].

use std::collections::BTreeSet;
use std::sync::Arc;

use im::{HashMap, OrdMap, OrdSet};
use serde::{Deserialize, Serialize};
use skep_address::{
    document_of, elem_addr, link_subspace, validate, Address, ElemPos, Nat, Tumbler,
};

use crate::dedup::DedupKey;
use crate::endset::{coverage_class, CoverageClass, Link};
use crate::registry::{Registration, RegistryError, ShippedType, TypeConfig, TypeRegistry};

/// The ONE authoritative delta. Every write — MAKELINK link, Emit_K tuple,
/// retraction tuple, supersession claim, editlink successor, pdef/pd_stable
/// classifier — is a deposit of an immutable link at a fresh address. There
/// is no update, no delete, no tombstone record (L12/R2/R3).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub enum LinkRec {
    Deposit { addr: Tumbler, value: Link },
}

/// One supersession edge out of `old`: the claimed successor and the
/// `[K_sup]` claim asserting it (ASN-0125's `new(e)` and `addr(e)`). It is
/// the CLAIM's activity that makes the edge operative (Df-SUCC), never the
/// endpoint's, which is why the claim address is carried rather than
/// discarded once the edge is built.
///
/// Two `Tumbler`s of different kinds, so they are named: `Ord` derives in
/// field order, making the set's iteration — and therefore `succs`' output
/// order — the claimed-successor order the walk reads.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct SupEdge {
    pub(crate) new: Tumbler,
    pub(crate) claim: Tumbler,
}

/// The recomputable hints — pure functions of `links` (+ `registry`),
/// maintained incrementally by [`LinkState::apply_link`] and re-seeded by
/// [`LinkState::rebuild_derived`]. The journal (via M2) is truth; lose any
/// hint and replay rebuilds it, never wrong.
#[derive(Debug, Clone, Default)]
pub(crate) struct Hints {
    /// Typed slices `L_K` (Observe / type-match, L8) — audit; active is
    /// derived at query time as `audit ∖ nullified`.
    pub(crate) type_slices: HashMap<CoverageClass, OrdSet<Tumbler>>,
    /// Resident retraction roots — the tombstone set (active = audit ∖ this).
    /// Monotone (R3/R6a). Membership is EXACT (`contains`), never
    /// prefix-closed: a root tombstones the one address it denotes and
    /// nothing beneath it. BH1's filter roots are the prefix-closed ones
    /// ([`crate::LinkState::is_filtered`]), and the two regimes must not be
    /// read across.
    pub(crate) nullified: OrdSet<Tumbler>,
    /// I0-class → addrs (audit; active-filtered at the check) — registered
    /// idem⊤ classes only (I1).
    pub(crate) dedup: HashMap<DedupKey, OrdSet<Tumbler>>,
    /// BH2 adjacency: `old` → its [`SupEdge`] set; `[K_sup]` only in v1 (§5).
    pub(crate) sup_fwd: HashMap<Tumbler, OrdSet<SupEdge>>,
    /// `f_d^Σ` — home document → its chain-frontier index, equal to M3's
    /// frontier by construction (Conflicts §7). The next emission lands at
    /// `chain_d(f_d^Σ)`, and BH4 age is measured back from it.
    pub(crate) home_frontier: HashMap<Tumbler, u64>,
}

/// M7's slice of the engine's `WorldState`, reached via
/// [`crate::HasLinks::links`].
///
/// The AUTHORITATIVE state is one map plus the genesis type config. Identity
/// is the key, never the value: the store is never content-addressed on the
/// endset (NonInjectivity L11b).
///
/// Four INVARIANTS hold of `links`, each at a named gate:
///
/// * **Freshness** — every deposit lands at a key not already present, which
///   is what makes the map append-only with immutable values and so makes
///   Permanence (L12/R2), append-only audit (R3), retraction stability (R6a)
///   and lock-free MVCC reads free. Gate: [`LinkState::apply_link`], the one
///   insertion point, discharged by M3's `mint_link`.
/// * **Arity exactly 3** — every stored value has three slots, so the
///   FROM/TO/TYPE accessors and the discovery primitives' slot indexes are
///   total (ASN-0086's `|Σ.L| = 3`); the [`Link`] type itself holds only the
///   L3 capacity floor of ≥ 3. Gate: `emit_core`'s backstop, ahead of the
///   mint.
/// * **Every slot level-uniform** — so [`coverage_class`] is total on every
///   stored slot, at deposit and at every replay. Gates: `emit`'s
///   address-denoting check on `ty` and `enc` on the rest; `editlink`'s
///   all-slot check on a caller-supplied successor; M5's `Run::iextent` by
///   construction for a resolved slot.
/// * **Every key T4-valid and element-level** — so `home(addr)` exists for
///   the frontier fold and every index key lifts to an `Address`. Gate: the
///   hint fold's two `expect`s, which fail-stop rather than fold a corrupt
///   address.
///
/// The deserialization path constructs a `LinkState` without passing those
/// gates: it establishes the L3 floor (through [`Link`]'s serde door) and
/// fail-stops on a non-T4 key at the rebuild fold, and takes the other two on
/// checkpoint integrity.
///
/// `registry` and `hints` are `#[serde(skip)]` RECOMPUTABLE state: on
/// deserialize serde seeds them with their `Default`s, placeholders
/// [`LinkState::rebuild_derived`] replaces BEFORE replay — load-bearing
/// because M2 recovers from the deserialized checkpoint whenever one exists,
/// so a skip-and-reseed-from-engine-genesis scheme would deserialize an
/// empty registry and silently mis-replay (§Core data model; that option is
/// rejected).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkState {
    /// ── AUTHORITATIVE ── append-only, immutable values.
    pub(crate) links: OrdMap<Tumbler, Link>,
    /// ── AUTHORITATIVE ── the genesis [`TypeConfig`]; `Arc` ⇒ O(1) per-fold
    /// clone (serde `rc`).
    pub(crate) config: Arc<TypeConfig>,
    /// ── RECOMPUTABLE ── lookup map; rebuilt from `config`.
    #[serde(skip)]
    pub(crate) registry: Arc<TypeRegistry>,
    /// ── RECOMPUTABLE ── rebuilt from `links`+`registry`.
    #[serde(skip)]
    pub(crate) hints: Hints,
}

impl LinkState {
    /// Validate the [`TypeConfig`] (`TypeRegistry::build`), seal it as
    /// authoritative genesis state, start from `links = ∅`. The engine builds
    /// the genesis slice here at assembly, propagating [`RegistryError`].
    /// (`TypeRegistry::build` is the same validation standalone; this is the
    /// normal entry.)
    pub fn genesis(config: TypeConfig) -> Result<LinkState, RegistryError> {
        let registry = TypeRegistry::build(&config)?;
        Ok(LinkState {
            links: OrdMap::new(),
            config: Arc::new(config),
            registry: Arc::new(registry),
            hints: Hints::default(),
        })
    }

    /// The pure/total/deterministic M2 fold (§1): insert `addr ↦ value` into
    /// `links` and fold EVERY hint incrementally, carrying the genesis
    /// `config` and its `registry` forward unchanged (Arc refcount bumps).
    /// Reads only `LinkState` + M1 arithmetic + the registry. Applied exactly
    /// once per committed record (M2 guarantees this — deliberately NOT coded
    /// idempotent).
    ///
    /// Totality domain, all three clauses owed by M3's `mint_link` and held
    /// by every record M7's own paths stage: `addr` is T4-valid, is
    /// element-level, and is FRESH (`addr ∉ dom(links)`) — the mint allocates
    /// on the home's link frontier and never re-issues, and M2 replays each
    /// committed record exactly once. A hand-built `addr` is OUTSIDE the
    /// domain and fail-stops — corruption, not a live error path (the M3
    /// fold's precedent).
    ///
    /// The first two clauses fail-stop on the hint fold's `expect`s. Freshness
    /// is asserted HERE because it is the one that would fail SILENTLY: the
    /// insert would replace an immutable value, leaving its address in the
    /// displaced value's type slice, double-counting the home frontier and
    /// voiding Permanence — none of it observable at the fold that admitted
    /// it.
    pub fn apply_link(&self, r: &LinkRec) -> LinkState {
        match r {
            LinkRec::Deposit { addr, value } => {
                let mut next = self.clone();
                let displaced = next.links.insert(addr.clone(), value.clone());
                assert!(
                    displaced.is_none(),
                    "apply_link: a Deposit must land at a fresh address (M3's mint never \
                     re-issues); replacing an immutable value voids Permanence (L12/R2)"
                );
                next.hints = fold_hints(&self.hints, &self.registry, addr, value);
                next
            }
        }
    }

    /// Runs once at load, BEFORE replay (M2's `rebuild_derived` slot): first
    /// reconstructs `registry = TypeRegistry::build(config)` from the
    /// deserialized authoritative config (an `expect` — that configuration
    /// passed validation at genesis, so the rebuild cannot fail), THEN
    /// recomputes every hint from `links` + the rebuilt registry in one pass.
    /// Required because both fields are `#[serde(skip)]` — M2's default
    /// identity would leave them empty, and replay's `apply_link` folds need
    /// the registry to recognize the `[R]`/`[K_sup]` classes.
    pub fn rebuild_derived(self) -> LinkState {
        let registry = Arc::new(TypeRegistry::build(&self.config).expect(
            "genesis type config re-validates: it passed TypeRegistry::build at genesis",
        ));
        let mut hints = Hints::default();
        for (addr, value) in self.links.iter() {
            hints = fold_hints(&hints, &registry, addr, value);
        }
        LinkState {
            links: self.links,
            config: self.config,
            registry,
            hints,
        }
    }

    /// Residence: `t ∈ dom(links)` (crate-internal; the public forms are
    /// `readlink`/`is_active`).
    pub(crate) fn resident(&self, t: &Tumbler) -> bool {
        self.links.contains_key(t)
    }

    /// Tombstoned: `t` is a retraction root. The one statement of the rule
    /// every active view applies — active = audit ∖ this — monotone
    /// (R3/R6a). EXACT membership, never a prefix test: a root tombstones
    /// the one address it denotes, so nothing beneath a nullified document
    /// or account is nullified by it. The public form is `is_nullified`.
    pub(crate) fn nullified(&self, t: &Tumbler) -> bool {
        self.hints.nullified.contains(t)
    }

    /// Df-DISC(ii): the `[K_sup]` claim schema — F and G each a unit-depth
    /// single denoted address, the two distinct, both resident. The one
    /// statement of the invariant every stored claim holds, and the whole
    /// reason `assert_sup`/`editlink` are the sole `[K_sup]` writers: the
    /// supersession adjacency, the walk family and M8's lineage reads all
    /// take it as fact, so what admits a claim states it here rather than
    /// inline at the gate that happens to be checking one.
    pub(crate) fn conforms_to_sup_schema(&self, value: &Link) -> bool {
        match (
            value.from_slot().single_denoted(),
            value.to_slot().single_denoted(),
        ) {
            (Some(f), Some(g)) => f != g && self.resident(f) && self.resident(g),
            _ => false,
        }
    }

    /// `f_d^Σ` — the home's chain-frontier hint, 0 for a home holding no
    /// links yet. The one reading of it: `next_link_address` mints at
    /// `1 + this`, BH4 `age` counts back from it.
    pub(crate) fn home_frontier(&self, home: &Address) -> u64 {
        self.hints
            .home_frontier
            .get(home.tumbler())
            .copied()
            .unwrap_or(0)
    }

    /// The registration of a coverage class, `None` for an unregistered one —
    /// the slice's delegate to its own registry, beside `shipped_class`, so a
    /// gate or a read asks the state it already holds rather than reaching
    /// through it for the lookup.
    pub(crate) fn registration(&self, class: &CoverageClass) -> Option<&Registration> {
        self.registry.registration(class)
    }

    /// The link an INDEX KEY names. Every key in `type_slices`/`dedup`/
    /// `sup_fwd`, and every key `stab` returns, is a key of `links` —
    /// [`fold_hints`] only ever indexes the address it is inserting — so
    /// absence is corruption rather than a miss, and fail-stops here instead
    /// of reading downstream as an empty answer. `readlink` is the fallible
    /// form, for an address a caller supplies.
    pub(crate) fn link_at(&self, t: &Tumbler) -> &Link {
        self.links
            .get(t)
            .expect("an index key names a resident link: the fold indexes only what it inserts")
    }

    /// The address `mint_link(home)` would mint next —
    /// `home · 0 · s_L · (1 + f_d^Σ)`, assembled off M7's own frontier and
    /// equal to M3's by construction (FrontierUnification; Conflicts §7 — no
    /// upward M3 read). An absent frontier gives ordinal 1, the first
    /// emission itself. `home` is a registered Document, which is what makes
    /// the assembly total (§4).
    pub(crate) fn next_link_address(&self, home: &Address) -> Address {
        let ordinal = 1 + self.home_frontier(home);
        elem_addr(ElemPos {
            doc: home.clone(),
            subspace: link_subspace(),
            ordinal: Nat::from(ordinal),
        })
        .expect("P0 discharged: home is a Document; s_L ≥ 1; ordinal ≥ 1 (§4)")
    }

    /// The active-view dedup incumbent of an I0 class (§3 step 2): the audit
    /// matches filtered by `∉ nullified`, T1-least first. Reading the ACTIVE
    /// view (I2) is what gives resurrection — a nullified tuple is invisible
    /// here, so re-emitting lands fresh.
    pub(crate) fn active_incumbent(&self, key: &DedupKey) -> Option<Address> {
        self.hints
            .dedup
            .get(key)?
            .iter()
            .find(|t| !self.nullified(t))
            .map(|t| validate(t.clone()).expect("stored link keys are T4-valid by M3's mint"))
    }

    /// The coverage class of a shipped reserved type (guard/recognition key).
    pub(crate) fn shipped_class(&self, ty: ShippedType) -> &CoverageClass {
        self.registry.shipped_class(ty)
    }
}

/// The incremental hint fold shared by [`LinkState::apply_link`] (per record)
/// and [`LinkState::rebuild_derived`] (whole-map pass) — one function so the
/// recovered hints are exactly the live-maintained ones (M2's consistency
/// obligation).
///
/// Class recognition and every write-path guard evaluate the SAME pure
/// [`coverage_class`] — the shipped classes this fold recognizes are that
/// function's own verdicts, fixed once at [`TypeRegistry::build`]. No second
/// classifier exists anywhere in M7 (class coherence, §Core data model).
pub(crate) fn fold_hints(
    hints: &Hints,
    registry: &TypeRegistry,
    addr: &Tumbler,
    value: &Link,
) -> Hints {
    let mut out = hints.clone();
    let class = coverage_class(value.type_slot());

    // type_slices — `L_K` per coverage class (L8).
    out.type_slices
        .entry(class.clone())
        .or_default()
        .insert(addr.clone());

    // nullified — the replay-critical [R] fold, pinned off the surface
    // discipline (§1): insert EVERY denoted to-root (zero roots ⇒ no insert,
    // several ⇒ all inserted; a non-unit-depth [R] to-span contributes no
    // root). Every v1 surface path yields exactly one root, but the fold
    // never invents behavior. A root tombstones the ONE address it denotes:
    // the set is read by exact membership, so inserting a document address
    // here would tombstone that document and no link under it.
    if class == *registry.shipped_class(ShippedType::Retraction) {
        for root in value.to_slot().addrs() {
            out.nullified.insert(root.clone());
        }
    }

    // dedup — registered idem⊤ classes only (§1); an unregistered or idem⊥
    // class skips the key entirely (no dedup check ever reads it). The one
    // degenerate exception — a MAKELINK deposit whose resolved class equals a
    // registered idem⊤ app class — folds an in-memory key here (possibly with
    // extent-classed from/to): harmless, it never reaches a LockKey
    // (Conflicts §1).
    if registry.registration(&class).is_some_and(|r| r.idem) {
        out.dedup
            .entry(DedupKey::of(value))
            .or_default()
            .insert(addr.clone());
    }

    // sup_fwd — one SupEdge out of each denoted old, for a [K_sup]-classed
    // tuple; both endpoints via addrs() (§5). DISTINCT endpoints, because the
    // schema admits repeats: Df-DISC(ii) demands one distinct denoted address
    // a side, so a slot may name it any number of times, and a repeated span
    // cannot add an edge — it can only multiply the work of adding one, at
    // every deposit AND at every replay. Deduplicating first makes the
    // schema-conformant case the 1 × 1 it is.
    if class == *registry.shipped_class(ShippedType::Supersedes) {
        let olds: BTreeSet<&Tumbler> = value.from_slot().addrs().collect();
        let news: BTreeSet<&Tumbler> = value.to_slot().addrs().collect();
        for old in olds {
            let edges = out.sup_fwd.entry(old.clone()).or_default();
            for new in &news {
                edges.insert(SupEdge {
                    new: (*new).clone(),
                    claim: addr.clone(),
                });
            }
        }
    }

    // home_frontier — keyed by home(addr) (Conflicts §7). The expects mark the
    // totality domain: every staged addr is M3-minted, T4-valid, element-level.
    let home = document_of(
        &validate(addr.clone()).expect("LinkRec addrs are M3-minted T4-valid link addresses"),
    )
    .expect("link addresses are element-level, so their home Document exists");
    *out.home_frontier.entry(home.tumbler().clone()).or_insert(0) += 1;

    out
}
