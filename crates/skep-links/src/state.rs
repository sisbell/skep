//! §A/§1 — the engine-plug slice: [`LinkState`] (the authoritative
//! append-only links map + the genesis type config + the recomputable
//! hints), the one journal delta [`LinkRec`], the pure fold
//! [`LinkState::apply_link`], and the load-time [`LinkState::rebuild_derived`].

use std::sync::Arc;

use im::{HashMap, OrdMap, OrdSet};
use serde::{Deserialize, Serialize};
use skep_address::{
    document_of, elem_addr, link_subspace, validate, Address, ElemPos, Nat, Tumbler,
};

use crate::dedup::DedupKey;
use crate::endset::{coverage_class, CoverageClass, Link};
use crate::registry::{RegistryError, ReservedAddrs, ShippedType, TypeDecl, TypeRegistry};

/// The ONE authoritative delta. Every write — MAKELINK link, Emit_K tuple,
/// retraction emitter, supersession claim, editlink successor, pdef/pd_stable
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
    /// Monotone (R3/R6a).
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
/// The AUTHORITATIVE state is one map plus the genesis type config: `links`
/// is append-only with immutable values (a `LinkRec::Deposit` only ever
/// inserts at a fresh key), which makes Permanence (L12/R2), append-only
/// audit (R3), retraction stability (R6a) and lock-free MVCC reads free.
/// Identity is the key, never the value: the store is never content-addressed
/// on the endset (NonInjectivity L11b).
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
    /// ── AUTHORITATIVE ── genesis type config; `Arc` ⇒ O(1) per-fold clone
    /// (serde `rc`).
    pub(crate) reserved: Arc<ReservedAddrs>,
    /// ── AUTHORITATIVE ── genesis type config; `Arc` ⇒ O(1) per-fold clone.
    pub(crate) decls: Arc<Vec<TypeDecl>>,
    /// ── RECOMPUTABLE ── lookup map; rebuilt from `reserved`+`decls`.
    #[serde(skip)]
    pub(crate) registry: Arc<TypeRegistry>,
    /// ── RECOMPUTABLE ── rebuilt from `links`+`registry`.
    #[serde(skip)]
    pub(crate) hints: Hints,
}

impl LinkState {
    /// Validate `decls` against `reserved` (`TypeRegistry::build`), seal BOTH
    /// as authoritative genesis config, start from `links = ∅`. The engine
    /// builds the genesis slice here at assembly, propagating
    /// [`RegistryError`]. (`TypeRegistry::build` is the same validation
    /// standalone; this is the normal entry.)
    pub fn genesis(reserved: ReservedAddrs, decls: Vec<TypeDecl>) -> Result<LinkState, RegistryError> {
        let registry = TypeRegistry::build(reserved.clone(), decls.clone())?;
        Ok(LinkState {
            links: OrdMap::new(),
            reserved: Arc::new(reserved),
            decls: Arc::new(decls),
            registry: Arc::new(registry),
            hints: Hints::default(),
        })
    }

    /// The pure/total/deterministic M2 fold (§1): insert `addr ↦ value` into
    /// `links` and fold EVERY hint incrementally, carrying the genesis config
    /// (`reserved`/`decls`/`registry`) forward unchanged (Arc refcount bumps).
    /// Reads only `LinkState` + M1 arithmetic + the registry. Applied exactly
    /// once per committed record (M2 guarantees this — deliberately NOT coded
    /// idempotent).
    ///
    /// Totality domain: `addr` is an M3-minted (T4-valid, element-level) link
    /// address — every record M7's own paths stage. A hand-built garbage
    /// `addr` is OUTSIDE the domain and fail-stops on the `expect`s —
    /// corruption, not a live error path (the M3 fold's precedent).
    pub fn apply_link(&self, r: &LinkRec) -> LinkState {
        match r {
            LinkRec::Deposit { addr, value } => {
                let mut next = self.clone();
                next.links.insert(addr.clone(), value.clone());
                next.hints = fold_hints(&self.hints, &self.registry, addr, value);
                next
            }
        }
    }

    /// Runs once at load, BEFORE replay (M2's `rebuild_derived` slot): first
    /// reconstructs `registry = TypeRegistry::build(reserved, decls)` from
    /// the deserialized authoritative config (an `expect` — the inputs passed
    /// validation at genesis, so the rebuild cannot fail), THEN recomputes
    /// every hint from `links` + the rebuilt registry in one pass. Required
    /// because both fields are `#[serde(skip)]` — M2's default identity would
    /// leave them empty, and replay's `apply_link` folds need the registry to
    /// recognize the `[R]`/`[K_sup]` classes.
    pub fn rebuild_derived(self) -> LinkState {
        let registry = Arc::new(
            TypeRegistry::build((*self.reserved).clone(), (*self.decls).clone())
                .expect("genesis type config re-validates: it passed TypeRegistry::build at genesis"),
        );
        let mut hints = Hints::default();
        for (addr, value) in self.links.iter() {
            hints = fold_hints(&hints, &registry, addr, value);
        }
        LinkState {
            links: self.links,
            reserved: self.reserved,
            decls: self.decls,
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
    /// (R3/R6a). The public form is `is_nullified`.
    pub(crate) fn nullified(&self, t: &Tumbler) -> bool {
        self.hints.nullified.contains(t)
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
        let ordinal = 1 + self
            .hints
            .home_frontier
            .get(home.tumbler())
            .copied()
            .unwrap_or(0);
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
    pub(crate) fn shipped_class(&self, t: ShippedType) -> &CoverageClass {
        self.registry.shipped_class(t)
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
pub(crate) fn fold_hints(h: &Hints, registry: &TypeRegistry, addr: &Tumbler, value: &Link) -> Hints {
    let mut out = h.clone();
    let k = coverage_class(value.type_slot());

    // type_slices — `L_K` per coverage class (L8).
    let mut slice = out.type_slices.get(&k).cloned().unwrap_or_default();
    slice.insert(addr.clone());
    out.type_slices.insert(k.clone(), slice);

    // nullified — the replay-critical [R] fold, pinned off the surface
    // discipline (§1): insert EVERY denoted to-root (zero roots ⇒ no insert,
    // several ⇒ all inserted; a non-unit-depth [R] to-span contributes no
    // root). Every v1 surface path yields exactly one root, but the fold
    // never invents behavior.
    if k == *registry.shipped_class(ShippedType::Retraction) {
        for root in value.to_slot().addrs() {
            out.nullified.insert(root.clone());
        }
    }

    // dedup — registered idem⊤ classes only (§1); an unregistered or idem⊥
    // class skips the key entirely (no dedup check ever reads it). The one
    // degenerate exception — a MAKELINK deposit whose resolved class equals a
    // registered idem⊤ app class — folds an in-memory key here (possibly with
    // Extents from/to): harmless, it never reaches a LockKey (Conflicts §1).
    if registry.registration(&k).is_some_and(|r| r.idem) {
        let key = DedupKey::of(value);
        let mut set = out.dedup.get(&key).cloned().unwrap_or_default();
        set.insert(addr.clone());
        out.dedup.insert(key, set);
    }

    // sup_fwd — one SupEdge out of each denoted old, for a [K_sup]-classed
    // tuple; both endpoints via addrs() (§5).
    if k == *registry.shipped_class(ShippedType::Supersedes) {
        for old in value.from_slot().addrs() {
            let mut edges = out.sup_fwd.get(old).cloned().unwrap_or_default();
            for new in value.to_slot().addrs() {
                edges.insert(SupEdge {
                    new: new.clone(),
                    claim: addr.clone(),
                });
            }
            out.sup_fwd.insert(old.clone(), edges);
        }
    }

    // home_frontier — keyed by home(addr) (Conflicts §7). The expects mark the
    // totality domain: every staged addr is M3-minted, T4-valid, element-level.
    let home = document_of(
        &validate(addr.clone()).expect("LinkRec addrs are M3-minted T4-valid link addresses"),
    )
    .expect("link addresses are element-level, so their home Document exists");
    let n = out.home_frontier.get(home.tumbler()).copied().unwrap_or(0);
    out.home_frontier.insert(home.tumbler().clone(), n + 1);

    out
}
