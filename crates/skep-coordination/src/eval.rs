//! §Internal 2 — the pure evaluator: a syntax-directed tree-walk threading
//! `(env, view, snap)`, reading ONLY M7 (`links()`) and M3 (`m3()`) — never
//! content or arrangement (PC4, structural-reads-only as a wiring
//! discipline). Every constituent read of one verdict comes off the single
//! pinned `Snapshot` the caller supplied (ASN-0134 clause 6, by
//! construction).
//!
//! The one audit seam: every audit read — `is_K@audit`, the audit core-atom
//! rebuilds (`members`/`targets_of`/`M_K`@audit, per V-AUD's own equations
//! over `observe(K, ⟨⟩, Audit)`), `L_K`, `L_dom`, and ever-registration —
//! passes `View::Audit` to `observe` and relies on M7 returning the audit
//! slice for it; no second audit-honoring method is assumed anywhere.
//!
//! The UV default-view rewrite is M9's (Conflicts §3): `members`/`targets_of`
//! at `default` drop elements filtered by the BH1 types OTHER than
//! `K_queried` — per-type via `is_k(J, ·)` (≡ BH1's `is_filtered_J`, D2) —
//! never M7's aggregate `is_filtered`; `succs`/`chain`/`sources_to`/`stale`
//! post-filter their returned collections; `tip`/`is_in_chain` walk
//! unfiltered.
//!
//! THE LOOK AT GUEST CLASS (PUB round 2, lane 4.1): every M7 read the
//! evaluator makes goes through [`GuestLinks`] — M7's read surface filtered
//! at link HOME by the coordinator's injected guest predicate — so a tuple
//! homed in a private draft can neither satisfy a rule's trigger nor seed its
//! domain, and a public fire never testifies to a draft's contents
//! (PUB-6.28). M7's `LinkState` reads stay class-free; the filter is the
//! delegator's, applied here.

use std::slice;

use im::OrdSet;
use skep_address::{document_of, is_prefix, validate, Address, Nat, Tumbler};
use skep_links::{
    coverage_class, registry, Behavior, CoverageClass, Endset, LinkState, NotBh4, Pattern, Shape,
    ShippedType, Tip, Tuple, View, Visibility,
};
use skep_namespace::M3State;

use crate::ast::{Atom, Dom, Lit, Prim, Term, TypeKey, TypeRef, VarId};
use crate::catalog::TypeCatalog;
use crate::value::{Env, Value};

/// Referent supplier for `evaluate_def`'s DAG-recursive driver — `eval`'s
/// walk plus the one `Ref` arm (§Internal 4/Conflicts §5). `None` for the
/// public `eval`/`decide`, whose ref-free precondition makes the arm a panic.
pub(crate) trait DefSource {
    fn resolve_def(&self, addr: &Address) -> Option<(Vec<(VarId, crate::value::Sort)>, crate::ast::ArcTerm)>;
}

/// THE TRIGGER'S LOOK AT GUEST CLASS (PUB round 2, lane 4.1): M7's read
/// surface as the evaluator sees it — one filtered view over `&LinkState`
/// that DROPS every tuple whose HOME document the coordinator's injected
/// guest predicate refuses. Every read the evaluator makes of the store goes
/// through this view, and through nothing else: `EvalCtx.links` IS this
/// view in every construction (`eval`/`decide`, the rule engine's domain
/// enumeration and trigger evaluation, the fire's own re-check, the
/// def-path denotation), so no draft-homed tuple can satisfy a rule's
/// trigger, seed its domain, or move a PL verdict.
///
/// WHY BY HOME (PUB-1.26, PUB-1.31, PUB-6.13): a link carries no publication
/// flag of its own — its publishedness is its HOME's — so a tuple is visible
/// at guest class iff `readable_guest(document_of(t.addr))`, its home
/// document being published. That is the same test M7's own value-keyed
/// gates apply at link-home identity (lane 3.3b) and the result-set row
/// applies to every link (PUB-6.13). The VIEW (`Active`/`Audit`) is
/// ORTHOGONAL to the class: an `AuditSlice` domain still shows the retracted
/// tuples of READABLE homes, and never a draft's tuples.
///
/// WHY HERE (PUB-6.28; the owner's placement ruling of 2026-09-06 — the
/// class is threaded from the caller): "a fire's verdict never turns on a
/// document rule 4 hides, and a fire commits byte-identically to a world
/// with no drafts". The verdict is the trigger's as much as the write's, so
/// the class lane 3.3 pinned on the action's home (`FireError::DraftBoundary`)
/// and lane 3.3b on the writer's gates is applied to the LOOK too — in M9,
/// the delegator that holds `guest`. M7 is told nothing.
///
/// COST (PUB-7.15's shape): one `document_of` (M1 arithmetic, no read) and
/// one predicate call per candidate tuple of the unfiltered read — a rule's
/// domain over a class of N tuples costs N home tests, proportional to the
/// unfiltered candidate set, as the read-side filters are. No per-home memo
/// is kept: the context is borrow-scoped to one verdict, the predicate the
/// engine injects is an exception-set membership miss (one hash), and the
/// evaluator carries no interior mutability.
///
/// THE READS, each answered over the visible slice exactly as M7's own
/// answers it over the whole: `is_k` and `observe` (the two reads the delta
/// names) and, listed as the delta asks, the rest the evaluator makes —
/// `members`, `targets_of` (D1/D3 over the visible slice); the BH2 walk
/// family `succs`/`chain`/`tip`/`is_in_chain` (rebuilt over the VISIBLE
/// active `[K_sup]` claims, so a draft-homed claim moves no walk); the BH3
/// family `sources_to`/`target_of`/`targets_keyed`; and BH4's `age`/`stale`
/// (dormant in this format, filtered the same way). Signatures mirror M7's so
/// the evaluator's call sites read as before.
pub(crate) struct GuestLinks<'a, W> {
    world: &'a W,
    state: &'a LinkState,
    guest: &'a Visibility<'a, W>,
}

impl<'a, W> GuestLinks<'a, W> {
    /// Over the world `w` of one pinned snapshot: its link slice, and the
    /// guest-class predicate the coordinator lends (a borrow of the one
    /// closure it holds — the same one every `LinkWriter` it builds runs at).
    pub(crate) fn new(world: &'a W, state: &'a LinkState, guest: &'a Visibility<'a, W>) -> GuestLinks<'a, W> {
        GuestLinks { world, state, guest }
    }

    /// The class test, at link-HOME identity — as M7's dedup gate applies it:
    /// `document_of(link)` is address arithmetic (no read), then the
    /// predicate on that home. A stored link key is element-level, so its
    /// home exists; an address with no document is answered `false`
    /// (fail-closed).
    fn home_readable(&self, link: &Address) -> bool {
        document_of(link).is_some_and(|home| (self.guest)(self.world, &home))
    }

    fn admits(&self, t: &Tuple) -> bool {
        self.home_readable(&t.addr)
    }

    /// M7's `observe` with the tuples of unreadable homes dropped — the ONE
    /// filtering primitive every other read here is built on (so the class
    /// test has one statement).
    pub(crate) fn observe(&self, ty: &Endset, pat: Pattern<'_>, view: View) -> Vec<Tuple> {
        let mut out = self.state.observe(ty, pat, view);
        out.retain(|t| self.admits(t));
        out
    }

    /// D2 over the visible active slice: some visible active type-`ty`
    /// tuple's F COVERS the probe. M7's own `is_k` does not expose the
    /// witnessing tuple, so the answer is the home-filtered `observe` at the
    /// same coverage pattern — the two are one predicate on the whole slice.
    pub(crate) fn is_k(&self, ty: &Endset, probe: &Tumbler) -> bool {
        !self
            .observe(ty, Pattern { from: slice::from_ref(probe), to: &[] }, View::Active)
            .is_empty()
    }

    /// D1 over the visible slice: `⋃ F.addrs()`, deduplicated, Tumbler order
    /// — M7's own equation, at `Active` or `Audit`. `Default` reads as
    /// `Active`: the UV rewrite is `EvalCtx`'s own per-type filter, which
    /// reads the active set and subtracts through this view's `is_k`, so no
    /// caller here ever asks this read for M7's aggregate subtraction.
    pub(crate) fn members(&self, ty: &Endset, view: View) -> Vec<Address> {
        let mut out: OrdSet<Tumbler> = OrdSet::new();
        for t in self.observe(ty, Pattern::default(), default_to_active(view)) {
            for m in t.from.addrs() {
                out.insert(m.clone());
            }
        }
        out.iter().map(lift).collect()
    }

    /// D3 over the visible slice: `⋃ G.addrs()` of the tuples whose F COVERS
    /// `x`, deduplicated, Tumbler order (M7's own coverage regime for this
    /// read). `Default` reads as `Active`, as for `members`.
    pub(crate) fn targets_of(&self, ty: &Endset, x: &Address, view: View) -> Vec<Address> {
        let mut out: OrdSet<Tumbler> = OrdSet::new();
        for t in self.observe(
            ty,
            Pattern { from: slice::from_ref(x.tumbler()), to: &[] },
            default_to_active(view),
        ) {
            for g in t.to.addrs() {
                out.insert(g.clone());
            }
        }
        out.iter().map(lift).collect()
    }

    // ───────────── BH2 — the walk over the VISIBLE operative claims ─────────────

    /// M7's v1 walk-serving scope, restated: the walk family serves the
    /// shipped `Supersedes` class and no other (the type checker admits BH2
    /// atoms only there — `UnservedWalkClass` otherwise).
    fn serves_walk(ty: &Endset) -> bool {
        coverage_class(ty) == coverage_class(registry().reserved_type(ShippedType::Supersedes))
    }

    /// The visible OPERATIVE claim set: the active `[K_sup]` tuples of
    /// readable homes. Edges run `old → new` by DENOTATION on both slots,
    /// exactly as M7's `sup_fwd` fold keys them; a claim is operative iff
    /// unnullified (Df-SUCC), which the active view gives.
    fn visible_claims(&self, ty: &Endset) -> Vec<Tuple> {
        self.observe(ty, Pattern::default(), View::Active)
    }

    /// `succ_o(x)` over the visible claims — deduplicated over `new`.
    fn succs_operative(claims: &[Tuple], x: &Tumbler) -> OrdSet<Tumbler> {
        claims
            .iter()
            .filter(|t| t.from.addrs().any(|old| old == x))
            .flat_map(|t| t.to.addrs().cloned())
            .collect()
    }

    /// The visited-set-bounded forward walk (M7's own halting rule): the
    /// traversed path from `x` (inclusive) and `Some(sink)` iff halted at a
    /// successor-free node — a branch or a cycle yields `None`.
    fn walk_sup(claims: &[Tuple], x: &Tumbler) -> (Vec<Tumbler>, Option<Tumbler>) {
        let mut path = vec![x.clone()];
        let mut visited = OrdSet::unit(x.clone());
        let mut node = x.clone();
        loop {
            let succs = Self::succs_operative(claims, &node);
            match succs.len() {
                0 => return (path, Some(node)),
                1 => {
                    let next = succs.iter().next().expect("len == 1").clone();
                    if visited.contains(&next) {
                        return (path, None); // cycle
                    }
                    visited.insert(next.clone());
                    path.push(next.clone());
                    node = next;
                }
                _ => return (path, None), // branch
            }
        }
    }

    /// BH2 forward step over the visible operative claims (Tumbler order);
    /// empty outside the served class.
    pub(crate) fn succs(&self, ty: &Endset, x: &Address) -> Vec<Address> {
        if !Self::serves_walk(ty) {
            return Vec::new();
        }
        let claims = self.visible_claims(ty);
        Self::succs_operative(&claims, x.tumbler()).iter().map(lift).collect()
    }

    /// BH2 chain over the visible operative claims; empty outside the served
    /// class.
    pub(crate) fn chain(&self, ty: &Endset, x: &Address) -> Vec<Address> {
        if !Self::serves_walk(ty) {
            return Vec::new();
        }
        let claims = self.visible_claims(ty);
        Self::walk_sup(&claims, x.tumbler()).0.iter().map(lift).collect()
    }

    /// BH2 head over the visible operative claims: `Sink(head)` at a
    /// successor-free node, `Indeterminate` at a branch or cycle — and
    /// outside the served class (no positive head is fabricated).
    pub(crate) fn tip(&self, ty: &Endset, x: &Address) -> Tip {
        if !Self::serves_walk(ty) {
            return Tip::Indeterminate;
        }
        let claims = self.visible_claims(ty);
        match Self::walk_sup(&claims, x.tumbler()).1 {
            Some(sink) => Tip::Sink(lift(&sink)),
            None => Tip::Indeterminate,
        }
    }

    /// BH2 chain membership: `target ∈ chain(ty, addr)` — walk-result
    /// membership, never a coverage test.
    pub(crate) fn is_in_chain(&self, ty: &Endset, addr: &Address, target: &Address) -> bool {
        self.chain(ty, addr).contains(target)
    }

    // ────────────────────────── BH3 — over the visible slice ──────────────────────────

    /// BH3 reverse: the F-denoted sources of the visible active type-`ty`
    /// tuples whose G COVERS `target`, deduplicated, Tumbler order.
    pub(crate) fn sources_to(&self, ty: &Endset, target: &Address) -> Vec<Address> {
        let mut out: OrdSet<Tumbler> = OrdSet::new();
        for t in self.observe(
            ty,
            Pattern { from: &[], to: slice::from_ref(target.tumbler()) },
            View::Active,
        ) {
            for f in t.from.addrs() {
                out.insert(f.clone());
            }
        }
        out.iter().map(lift).collect()
    }

    /// BH3 forward: ⊥ unless EXACTLY ONE visible active type-`ty` tuple
    /// denotes `source` in F with a single-address-denoting G.
    pub(crate) fn target_of(&self, ty: &Endset, source: &Address) -> Option<Address> {
        let mut survivor: Option<Tuple> = None;
        for t in self.observe(ty, Pattern::default(), View::Active) {
            if t.from.addrs().any(|f| f == source.tumbler()) {
                if survivor.is_some() {
                    return None; // several visible active matches ⇒ ⊥
                }
                survivor = Some(t);
            }
        }
        let survivor = survivor?;
        survivor.to.single_denoted().map(lift)
    }

    /// BH3 join: `target_of` across every BH3-registered Binary class of the
    /// format's registry (none in this format — `targets_keyed` is out of the
    /// vocabulary, and the type checker says so), keyed by coverage class.
    pub(crate) fn targets_keyed(&self, source: &Address) -> im::HashMap<CoverageClass, Address> {
        let reg = registry();
        let mut out = im::HashMap::new();
        for shipped in ShippedType::ALL {
            let ty = reg.reserved_type(shipped);
            let class = coverage_class(ty);
            let bh3 = reg.registration(&class).is_some_and(|r| {
                r.shape == Shape::Binary && r.behaviors.contains(&Behavior::ReverseLookup)
            });
            if bh3 {
                if let Some(target) = self.target_of(ty, source) {
                    out.insert(class, target);
                }
            }
        }
        out
    }

    // ────────────────────────── BH4 — over the visible slice ──────────────────────────

    /// BH4 age: M7's own for a link of a readable home, ⊥ otherwise (a
    /// draft-homed tuple has no age at guest class, as it has no residence).
    pub(crate) fn age(&self, a: &Address) -> Option<u64> {
        if !self.home_readable(a) {
            return None;
        }
        self.state.age(a)
    }

    /// BH4 stale set: M7's own (its `NotBh4` fence included), with the
    /// tuples of unreadable homes dropped; ascending address order kept.
    pub(crate) fn stale(&self, ty: &Endset, horizon: u64) -> Result<Vec<Address>, NotBh4> {
        let stale = self.state.stale(ty, horizon)?;
        Ok(stale.into_iter().filter(|a| self.home_readable(a)).collect())
    }
}

/// `Default → Active` for the view's slice reads (`Default` is the UV
/// rewrite's, which `EvalCtx` performs itself).
fn default_to_active(view: View) -> View {
    match view {
        View::Default => View::Active,
        other => other,
    }
}

/// One verdict's read context — all slices off one pinned snapshot, M7's
/// through the guest-class view (built only by `Coordinator::eval_ctx`).
pub(crate) struct EvalCtx<'a, W> {
    pub(crate) catalog: &'a TypeCatalog,
    pub(crate) links: GuestLinks<'a, W>,
    pub(crate) m3: &'a M3State,
    pub(crate) defs: Option<&'a dyn DefSource>,
}

/// A domain element: an address, or a whole tuple (`A_K`/`L_K`) — the
/// trigger/atom dispatch consumes the tuple; bookkeeping projects to
/// `t.addr` (R1 AddressInjectivity).
#[derive(Debug, Clone)]
pub(crate) enum Elem {
    Addr(Address),
    Tup(Tuple),
}

impl Elem {
    pub(crate) fn value(&self) -> Value {
        match self {
            Elem::Addr(a) => Value::Addr(a.clone()),
            Elem::Tup(t) => Value::Tuple(t.clone()),
        }
    }

    pub(crate) fn key_addr(&self) -> Address {
        match self {
            Elem::Addr(a) => a.clone(),
            Elem::Tup(t) => t.addr.clone(),
        }
    }
}

/// Set-element lift (Tumbler → Address) at the binding sites — M1 `validate`,
/// infallible on store-minted addresses (§Internal 2).
pub(crate) fn lift(t: &Tumbler) -> Address {
    validate(t.clone()).expect("PL set elements are store-minted, T4-valid addresses")
}

pub(crate) fn truthy(v: Value) -> bool {
    match v {
        Value::Bool(b) => b,
        other => unreachable!("well-typed Bool position held {other:?}"),
    }
}

fn as_addr(v: Value) -> Address {
    match v {
        Value::Addr(a) => a,
        other => unreachable!("well-typed Addr position held {other:?}"),
    }
}

fn as_set(v: Value) -> OrdSet<Tumbler> {
    match v {
        Value::AddrSet(s) => s,
        other => unreachable!("well-typed AddrSet position held {other:?}"),
    }
}

fn as_nat(v: Value) -> Nat {
    match v {
        Value::Nat(n) => n,
        other => unreachable!("well-typed Nat position held {other:?}"),
    }
}

fn concrete(tr: &TypeRef) -> &TypeKey {
    match tr {
        TypeRef::Concrete(k) => k,
        TypeRef::ClassVar(v) => {
            unreachable!("post-Reg-expansion invariant: the evaluator never sees ClassVar({v:?})")
        }
    }
}

impl<'a, W> EvalCtx<'a, W> {
    fn class_of(&self, k: &TypeKey) -> &CoverageClass {
        &self
            .catalog
            .get(k)
            .expect("checked Concrete TypeKeys are cataloged")
            .class
    }

    /// UV `K_queried` self-exclusion: `∃ J ∈ Φ, J ≠ K :: is_k(J, x)` — the
    /// per-type BH1 filter (D2), never M7's aggregate `is_filtered`.
    fn filtered_other(&self, k_class: &CoverageClass, x: &Tumbler) -> bool {
        self.catalog
            .bh1()
            .iter()
            .any(|(j_class, j_endset)| j_class != k_class && self.links.is_k(j_endset, x))
    }

    /// `members(K, v)` (D1 / V-AUD / UV): active from the view's `members`;
    /// audit REBUILT from `observe(K, ⟨⟩, Audit)` per V-AUD's own equations
    /// (⋃ F.addrs()); default = active minus the other-BH1-filtered elements.
    /// Every read is the guest-class view's (lane 4.1), so a draft-homed
    /// tuple contributes no member at any view.
    fn members_at(&self, k: &TypeKey, view: View) -> OrdSet<Tumbler> {
        match view {
            View::Active => self
                .links
                .members(&k.0, View::Active)
                .into_iter()
                .map(|a| a.tumbler().clone())
                .collect(),
            View::Audit => {
                let mut out = OrdSet::new();
                for t in self.links.observe(&k.0, Pattern::default(), View::Audit) {
                    for a in t.from.addrs() {
                        out.insert(a.clone());
                    }
                }
                out
            }
            View::Default => {
                let k_class = self.class_of(k).clone();
                self.members_at(k, View::Active)
                    .into_iter()
                    .filter(|x| !self.filtered_other(&k_class, x))
                    .collect()
            }
        }
    }

    /// `targets_of(K, x, v)` (D3 / V-AUD / UV) — audit membership by
    /// `x ∈ F.addrs()` (the AM exact denotation).
    fn targets_of_at(&self, k: &TypeKey, x: &Address, view: View) -> OrdSet<Tumbler> {
        match view {
            View::Active => self
                .links
                .targets_of(&k.0, x, View::Active)
                .into_iter()
                .map(|a| a.tumbler().clone())
                .collect(),
            View::Audit => {
                let mut out = OrdSet::new();
                for t in self.links.observe(&k.0, Pattern::default(), View::Audit) {
                    if t.from.addrs().any(|a| a == x.tumbler()) {
                        for g in t.to.addrs() {
                            out.insert(g.clone());
                        }
                    }
                }
                out
            }
            View::Default => {
                let k_class = self.class_of(k).clone();
                self.targets_of_at(k, x, View::Active)
                    .into_iter()
                    .filter(|g| !self.filtered_other(&k_class, g))
                    .collect()
            }
        }
    }

    /// `is_K(x)` per view — audit through the ONE `observe`-honors-`Audit`
    /// seam; active/default via `is_k` (never UV-filtered — UV); both the
    /// guest-class view's, so a draft-homed tuple witnesses nothing.
    fn is_k_at(&self, k: &TypeKey, x: &Address, view: View) -> bool {
        match view {
            View::Audit => !self
                .links
                .observe(
                    &k.0,
                    Pattern { from: slice::from_ref(x.tumbler()), to: &[] },
                    View::Audit,
                )
                .is_empty(),
            View::Active | View::Default => self.links.is_k(&k.0, x.tumbler()),
        }
    }

    /// Drop other-BH1-filtered elements from a returned collection — the UV
    /// rewrite for the non-core collections in a `default` term.
    fn uv_drop(&self, k: &TypeKey, view: View, set: OrdSet<Tumbler>) -> OrdSet<Tumbler> {
        if view != View::Default {
            return set;
        }
        let k_class = self.class_of(k).clone();
        set.into_iter().filter(|e| !self.filtered_other(&k_class, e)).collect()
    }
}

/// The denotation. Pure, total, terminating; panics only on precondition
/// violations (a `Ref` with no `DefSource`, a `ClassVar`, an ill-sorted
/// runtime value — all unreachable on checked input).
pub(crate) fn eval_term<W>(cx: &EvalCtx<'_, W>, env: &Env, view: View, t: &Term) -> Value {
    match t {
        Term::Var(v) => env
            .get(v)
            .unwrap_or_else(|| unreachable!("checked Var {v:?} is bound at eval time"))
            .clone(),
        Term::Lit(l) => match l {
            Lit::True => Value::Bool(true),
            Lit::False => Value::Bool(false),
            Lit::Nat(n) => Value::Nat(n.clone()),
            Lit::Addr(a) => Value::Addr(a.clone()),
            Lit::BotAddr => Value::OptAddr(None),
            Lit::BotNat => Value::OptNat(None),
        },
        Term::Atom(a) => eval_atom(cx, env, view, a),
        Term::Prim(p) => eval_prim(cx, env, view, p),
        Term::And(a, b) => {
            Value::Bool(truthy(eval_term(cx, env, view, a)) && truthy(eval_term(cx, env, view, b)))
        }
        Term::Or(a, b) => {
            Value::Bool(truthy(eval_term(cx, env, view, a)) || truthy(eval_term(cx, env, view, b)))
        }
        Term::Not(a) => Value::Bool(!truthy(eval_term(cx, env, view, a))),
        Term::Implies(a, b) => {
            Value::Bool(!truthy(eval_term(cx, env, view, a)) || truthy(eval_term(cx, env, view, b)))
        }
        Term::Iff(a, b) => {
            Value::Bool(truthy(eval_term(cx, env, view, a)) == truthy(eval_term(cx, env, view, b)))
        }
        // Short-circuit: ∀ stops at the first counterexample, ∃ at the first
        // witness (over the materialized slice — §Internal 2 tradeoff).
        Term::Forall { var, dom, body } => Value::Bool(enum_dom(cx, env, view, dom).into_iter().all(|e| {
            truthy(eval_term(cx, &env.bind(var.clone(), e.value()), view, body))
        })),
        Term::Exists { var, dom, body } => Value::Bool(enum_dom(cx, env, view, dom).into_iter().any(|e| {
            truthy(eval_term(cx, &env.bind(var.clone(), e.value()), view, body))
        })),
        Term::Let { var, bound, body } => {
            let b = eval_term(cx, env, view, bound);
            eval_term(cx, &env.bind(var.clone(), b), view, body)
        }
        Term::IfSome { opt, var, then_, else_ } => match eval_term(cx, env, view, opt) {
            Value::OptAddr(Some(a)) => eval_term(cx, &env.bind(var.clone(), Value::Addr(a)), view, then_),
            Value::OptNat(Some(n)) => eval_term(cx, &env.bind(var.clone(), Value::Nat(n)), view, then_),
            Value::OptAddr(None) | Value::OptNat(None) => eval_term(cx, env, view, else_),
            other => unreachable!("IfSome guard checked at an Opt sort, held {other:?}"),
        },
        // Set-semantics counting (PC2a): enum_dom deduplicates address
        // domains; tuple slices are distinct by address.
        Term::Count(d) => Value::Nat(Nat::from(enum_dom(cx, env, view, d).len() as u64)),
        Term::MaxT1(d) => {
            let best = enum_dom(cx, env, view, d)
                .into_iter()
                .map(|e| e.key_addr())
                .max_by(|a, b| a.tumbler().cmp(b.tumbler()));
            Value::OptAddr(best)
        }
        Term::MinT1(d) => {
            let best = enum_dom(cx, env, view, d)
                .into_iter()
                .map(|e| e.key_addr())
                .min_by(|a, b| a.tumbler().cmp(b.tumbler()));
            Value::OptAddr(best)
        }
        Term::BigUnion { dom, var, body } => {
            let mut out: OrdSet<Tumbler> = OrdSet::new();
            for e in enum_dom(cx, env, view, dom) {
                let s = as_set(eval_term(cx, &env.bind(var.clone(), e.value()), view, body));
                for t in s.iter() {
                    out.insert(t.clone());
                }
            }
            Value::AddrSet(out)
        }
        // QD-refl: the reflected ℘_fin(T) value is the domain's address
        // denotation at this snapshot.
        Term::Reflect(d) => {
            let mut out: OrdSet<Tumbler> = OrdSet::new();
            for e in enum_dom(cx, env, view, d) {
                out.insert(e.key_addr().tumbler().clone());
            }
            Value::AddrSet(out)
        }
        Term::Ref { addr, args } => {
            let Some(defs) = cx.defs else {
                panic!(
                    "eval precondition violated: ref-bearing term (a Ref node survives) — \
                     ref-bearing terms evaluate only through evaluate_def"
                );
            };
            let (params, body) = defs
                .resolve_def(addr)
                .expect("WT-ref: every referent of a checked body has a defined signature");
            let mut inner = Env::empty();
            for ((v, _), arg) in params.iter().zip(args.iter()) {
                let val = eval_term(cx, env, view, arg);
                inner = inner.bind(v.clone(), val);
            }
            eval_term(cx, &inner, view, &body)
        }
    }
}

fn eval_atom<W>(cx: &EvalCtx<'_, W>, env: &Env, view: View, a: &Atom) -> Value {
    let tup = |v: &VarId| -> Tuple {
        match env.get(v) {
            Some(Value::Tuple(t)) => t.clone(),
            other => unreachable!("checked Tup var {v:?} bound to a tuple, held {other:?}"),
        }
    };
    match a {
        Atom::IsK(tr, e) => {
            let k = concrete(tr);
            let x = as_addr(eval_term(cx, env, view, e));
            Value::Bool(cx.is_k_at(k, &x, view))
        }
        Atom::Members(tr) => Value::AddrSet(cx.members_at(concrete(tr), view)),
        Atom::TargetsOf(tr, e) => {
            let x = as_addr(eval_term(cx, env, view, e));
            Value::AddrSet(cx.targets_of_at(concrete(tr), &x, view))
        }
        // BH1: is_filtered_J ≡ is_k(J, ·) — D2, J's own active membership.
        Atom::IsFiltered(tr, e) => {
            let k = concrete(tr);
            let x = as_addr(eval_term(cx, env, view, e));
            Value::Bool(cx.links.is_k(&k.0, x.tumbler()))
        }
        Atom::Succs(tr, e) => {
            let k = concrete(tr);
            let x = as_addr(eval_term(cx, env, view, e));
            let set: OrdSet<Tumbler> =
                cx.links.succs(&k.0, &x).into_iter().map(|a| a.tumbler().clone()).collect();
            Value::AddrSet(cx.uv_drop(k, view, set))
        }
        Atom::Chain(tr, e) => {
            let k = concrete(tr);
            let x = as_addr(eval_term(cx, env, view, e));
            let chain = cx.links.chain(&k.0, &x);
            let seq: im::Vector<Address> = if view == View::Default {
                let k_class = cx.class_of(k).clone();
                chain
                    .into_iter()
                    .filter(|a| !cx.filtered_other(&k_class, a.tumbler()))
                    .collect()
            } else {
                chain.into_iter().collect()
            };
            Value::AddrSeq(seq)
        }
        // Verdict/traversal atoms are never UV-rewritten (UV): unfiltered
        // active walk.
        Atom::Tip(tr, e) => {
            let k = concrete(tr);
            let x = as_addr(eval_term(cx, env, view, e));
            Value::OptAddr(match cx.links.tip(&k.0, &x) {
                Tip::Sink(a) => Some(a),
                Tip::Indeterminate => None,
            })
        }
        Atom::IsInChain(tr, e1, e2) => {
            let k = concrete(tr);
            let x = as_addr(eval_term(cx, env, view, e1));
            let y = as_addr(eval_term(cx, env, view, e2));
            Value::Bool(cx.links.is_in_chain(&k.0, &x, &y))
        }
        Atom::SourcesTo(tr, e) => {
            let k = concrete(tr);
            let x = as_addr(eval_term(cx, env, view, e));
            let set: OrdSet<Tumbler> =
                cx.links.sources_to(&k.0, &x).into_iter().map(|a| a.tumbler().clone()).collect();
            Value::AddrSet(cx.uv_drop(k, view, set))
        }
        Atom::TargetOf(tr, e) => {
            let k = concrete(tr);
            let x = as_addr(eval_term(cx, env, view, e));
            Value::OptAddr(cx.links.target_of(&k.0, &x))
        }
        Atom::TargetsKeyed(e) => {
            let x = as_addr(eval_term(cx, env, view, e));
            Value::Map(cx.links.targets_keyed(&x))
        }
        // BH4 totalization (ASN-0129): age(a) = ⊥ exactly when `a` is not
        // the address of an ACTIVE K-tuple — a tuple-identity test, not
        // is_k's coverage-of-F membership.
        Atom::Age(tr, e) => {
            let k = concrete(tr);
            let a = as_addr(eval_term(cx, env, view, e));
            let active_k_tuple = cx
                .links
                .observe(&k.0, Pattern::default(), View::Active)
                .iter()
                .any(|t| t.addr == a);
            let age = if active_k_tuple {
                cx.links.age(&a).map(Nat::from)
            } else {
                None
            };
            Value::OptNat(age)
        }
        // Saturating Nat→u64 at the seam: a horizon ≥ 2^64 ⇒ stale = ∅ (all
        // non-stale) — never a wrapping truncation.
        Atom::Stale(tr, e) => {
            let k = concrete(tr);
            let h = as_nat(eval_term(cx, env, view, e));
            let h64 = u64::try_from(&h).unwrap_or(u64::MAX);
            let stale = cx
                .links
                .stale(&k.0, h64)
                .expect("type-check admits Stale only at a BH4-registered class");
            let set: OrdSet<Tumbler> = stale.into_iter().map(|a| a.tumbler().clone()).collect();
            Value::AddrSet(cx.uv_drop(k, view, set))
        }
        // V-DOC — M3 residence (a registered-but-arrangementless doc is a
        // valid residence; the eager/lazy split).
        Atom::IsDoc(e) => {
            let d = as_addr(eval_term(cx, env, view, e));
            Value::Bool(cx.m3.is_registered_document(&d))
        }
        Atom::TupAddr(v) => Value::Addr(tup(v).addr),
        Atom::TupAddrsF(v) => {
            Value::AddrSet(tup(v).from.addrs().cloned().collect())
        }
        Atom::TupAddrsG(v) => Value::AddrSet(tup(v).to.addrs().cloned().collect()),
        Atom::InCoverageF(e, v) => {
            let x = as_addr(eval_term(cx, env, view, e));
            Value::Bool(tup(v).from.covers(x.tumbler()))
        }
        Atom::InCoverageG(e, v) => {
            let x = as_addr(eval_term(cx, env, view, e));
            Value::Bool(tup(v).to.covers(x.tumbler()))
        }
    }
}

fn eval_prim<W>(cx: &EvalCtx<'_, W>, env: &Env, view: View, p: &Prim) -> Value {
    let ev = |t: &Term| eval_term(cx, env, view, t);
    match p {
        Prim::AddrEq(a, b) => Value::Bool(as_addr(ev(a)) == as_addr(ev(b))),
        Prim::Prefix(a, b) => {
            Value::Bool(is_prefix(as_addr(ev(a)).tumbler(), as_addr(ev(b)).tumbler()))
        }
        Prim::T1Lt(a, b) => Value::Bool(as_addr(ev(a)).tumbler() < as_addr(ev(b)).tumbler()),
        Prim::SetMem(x, s) => {
            Value::Bool(as_set(ev(s)).contains(as_addr(ev(x)).tumbler()))
        }
        Prim::SetEq(a, b) => Value::Bool(as_set(ev(a)) == as_set(ev(b))),
        Prim::IsEmpty(s) => Value::Bool(as_set(ev(s)).is_empty()),
        Prim::Elems(q) => match ev(q) {
            Value::AddrSeq(seq) => {
                Value::AddrSet(seq.iter().map(|a| a.tumbler().clone()).collect())
            }
            other => unreachable!("Elems checked at AddrSeq, held {other:?}"),
        },
        Prim::NatEq(a, b) => Value::Bool(as_nat(ev(a)) == as_nat(ev(b))),
        Prim::NatLe(a, b) => Value::Bool(as_nat(ev(a)) <= as_nat(ev(b))),
        Prim::NatAdd(a, b) => Value::Nat(as_nat(ev(a)) + as_nat(ev(b))),
        // ·[K] keys through the catalog's PRECOMPUTED class (never a runtime
        // coverage_class on user input); an absent key — non-BH3 K included —
        // denotes ⊥.
        Prim::MapGet(m, tr) => {
            let k = concrete(tr);
            let class = cx.class_of(k);
            match ev(m) {
                Value::Map(map) => Value::OptAddr(map.get(class).cloned()),
                other => unreachable!("MapGet checked at Map, held {other:?}"),
            }
        }
        Prim::Def(x) => Value::Bool(match ev(x) {
            Value::OptAddr(o) => o.is_some(),
            Value::OptNat(o) => o.is_some(),
            other => unreachable!("Def checked at an Opt sort, held {other:?}"),
        }),
    }
}

/// `[D]_snap` — finite by QD-fin. Address domains deduplicate (set
/// semantics); tuple slices are distinct by address. `Filter` composes over
/// the materialized base (§Internal 2).
pub(crate) fn enum_dom<W>(cx: &EvalCtx<'_, W>, env: &Env, view: View, d: &Dom) -> Vec<Elem> {
    match d {
        // M_K at the TERM view (view-parameterized domain).
        Dom::MembersDom(tr) => cx
            .members_at(concrete(tr), view)
            .iter()
            .map(|t| Elem::Addr(lift(t)))
            .collect(),
        Dom::ActiveSlice(tr) => cx
            .links
            .observe(&concrete(tr).0, Pattern::default(), View::Active)
            .into_iter()
            .map(Elem::Tup)
            .collect(),
        Dom::AuditSlice(tr) => cx
            .links
            .observe(&concrete(tr).0, Pattern::default(), View::Audit)
            .into_iter()
            .map(Elem::Tup)
            .collect(),
        // L_dom = ⋃_{K∈catalog} observe(K, ⟨⟩, Audit) ↦ t.addr — the
        // typed-relation sublayer only (open MAKELINK links excluded); never
        // M8's type_slice.
        Dom::LinkDom => {
            let mut out: OrdSet<Tumbler> = OrdSet::new();
            for k in cx.catalog.classes() {
                for t in cx.links.observe(&k.0, Pattern::default(), View::Audit) {
                    out.insert(t.addr.tumbler().clone());
                }
            }
            out.iter().map(|t| Elem::Addr(lift(t))).collect()
        }
        Dom::Reg => unreachable!("no Reg domain survives type_check's expansion/folding"),
        Dom::Filter { dom, var, pred } => enum_dom(cx, env, view, dom)
            .into_iter()
            .filter(|e| truthy(eval_term(cx, &env.bind(var.clone(), e.value()), view, pred)))
            .collect(),
        Dom::SetTerm(t) => {
            let s = as_set(eval_term(cx, env, view, t));
            s.iter().map(|t| Elem::Addr(lift(t))).collect()
        }
    }
}
