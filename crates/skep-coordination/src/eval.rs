//! §Internal 2 — the pure evaluator: a syntax-directed tree-walk over one
//! verdict's fixed context `(catalog, links, m3, view)` and its environment,
//! reading ONLY M7 (`links()`) and M3 (`m3()`) — never content or arrangement
//! (PC4, structural-reads-only as a wiring discipline). Every constituent
//! read of one verdict comes off the single pinned `Snapshot` the caller
//! supplied (ASN-0134 clause 6, by construction).
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
//! Every M7 read the evaluator makes goes through [`GuestLinks`] — M7's read
//! surface filtered at link HOME by the coordinator's injected guest
//! predicate (`guest.rs` states the doctrine) — so a tuple homed in a private
//! draft can neither satisfy a rule's trigger nor seed its domain, and a
//! public fire never testifies to a draft's contents (PUB-6.28).

use std::sync::Arc;

use im::OrdSet;
use skep_address::{is_prefix, validate, Address, Nat, Tumbler};
use skep_links::{CoverageClass, Pattern, Tip, Tuple, View};
use skep_namespace::M3State;

use crate::ast::{Atom, Dom, Lit, Prim, Term, TypeKey, VarId};
use crate::catalog::TypeCatalog;
use crate::check::TypedTerm;
use crate::guest::GuestLinks;
use crate::rule::Arg;
use crate::value::{Env, Value};

/// Referent supplier for the DAG-recursive drivers over ref-bearing bodies —
/// the denotation of a stored def (`eval_term`'s walk plus the one `Ref`
/// arm, §Internal 4/Conflicts §5) and the flat expansion the static analyses
/// run over. `None` for the public `eval`/`decide`, whose ref-free
/// precondition makes the arm a panic. A `Some` is the memo's own `Arc` —
/// the checked term of a defined referent, never a copy.
pub(crate) trait DefSource {
    fn resolve_def(&self, addr: &Address) -> Option<Arc<TypedTerm>>;
}

/// One verdict's read context — all slices off one pinned snapshot, M7's
/// through the guest-class view, at ONE term view (PC3: the view is fixed
/// for the life of a verdict, so it is context, not an argument). Built only
/// by `Coordinator::eval_ctx`.
pub(crate) struct EvalCtx<'a, W> {
    pub(crate) catalog: &'a TypeCatalog,
    pub(crate) links: GuestLinks<'a, W>,
    pub(crate) m3: &'a M3State,
    pub(crate) view: View,
    pub(crate) defs: Option<&'a dyn DefSource>,
}

/// Set-element lift (Tumbler → Address) at the binding sites — M1 `validate`,
/// infallible on what reaches it (§Internal 2). Every tumbler lifted here
/// is one of two things: the start of a unit-depth span in a stored slot
/// endset — `Endset::addrs()` yields no other, and M7's slot doors admit a
/// start only as an `Address` (`SlotArg::Addrs`, `emit`'s and `assert_sup`'s
/// endpoints) or as a `Run::i_start`, an `Address` by type — or an element
/// of a `Value::AddrSet`, which the evaluator builds from those and the two
/// caller-facing doors (`evaluate_def`, `eval`) check element by element.
pub(crate) fn lift(t: &Tumbler) -> Address {
    validate(t.clone()).expect("PL set elements are store-minted, T4-valid addresses")
}

pub(crate) fn as_bool(v: Value) -> bool {
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

/// The address element of an ADDRESS-VALUED domain — the three formers that
/// fold one (`MaxT1`, `MinT1`, `Reflect`) require `dom(Addr)` at the checker
/// (`want(Sort::Addr, cd.elem)`), so a tuple here is a checked-input
/// violation, as an ill-sorted `Value` is above.
fn addr_elem(e: Arg) -> Address {
    match e {
        Arg::Addr(a) => a,
        Arg::Tuple(t) => {
            unreachable!("an address-valued domain yielded the tuple {:?}", t.addr)
        }
    }
}

/// A V-TUP variable's tuple, borrowed from the environment — the checker
/// bound it at `Tup`, so the binding is a tuple.
fn tuple_var<'e>(env: &'e Env, v: &VarId) -> &'e Tuple {
    match env.get(v) {
        Some(Value::Tuple(t)) => t,
        other => unreachable!("checked Tup var {v:?} bound to a tuple, held {other:?}"),
    }
}

impl<'a, W> EvalCtx<'a, W> {
    /// UV `K_queried` self-exclusion: `∃ J ∈ Φ, J ≠ K :: is_k(J, x)` — the
    /// per-type BH1 filter (D2), fixed active, never M7's aggregate
    /// `is_filtered`. Takes the queried KEY, so the class lookup a UV rewrite
    /// needs is made here rather than at each of its four sites.
    fn filtered_other(&self, k: &TypeKey, x: &Tumbler) -> bool {
        let k_class = self.catalog.class_of(k);
        self.catalog.bh1().iter().any(|(j_class, j_endset)| {
            j_class != k_class && self.links.is_k(j_endset, x, View::Active)
        })
    }

    /// `members(K, v)` (D1 / V-AUD / UV): active and audit are the view's
    /// slice read at that view (⋃ F.addrs() over `observe(K, ⟨⟩, v)` —
    /// V-AUD's own equation is D1's over the audit slice); default = active
    /// minus the other-BH1-filtered elements. The `view` is explicit here
    /// because the `Default` arm re-enters at `Active`. Every read is the
    /// guest-class view's (lane 4.1), so a draft-homed tuple contributes no
    /// member at any view.
    fn members_at(&self, k: &TypeKey, view: View) -> OrdSet<Tumbler> {
        match view {
            View::Active | View::Audit => self
                .links
                .members(&k.0, view)
                .into_iter()
                .map(|a| a.tumbler().clone())
                .collect(),
            View::Default => self
                .members_at(k, View::Active)
                .into_iter()
                .filter(|x| !self.filtered_other(k, x))
                .collect(),
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
            View::Default => self
                .targets_of_at(k, x, View::Active)
                .into_iter()
                .filter(|g| !self.filtered_other(k, g))
                .collect(),
        }
    }

    /// `is_K(x)` per view — a verdict atom, so a `default` term reads it at
    /// the ACTIVE slice, never UV-filtered (UV). Both slices are the
    /// guest-class view's, so a draft-homed tuple witnesses nothing.
    fn is_k_at(&self, k: &TypeKey, x: &Address, view: View) -> bool {
        let slice = match view {
            View::Audit => View::Audit,
            View::Active | View::Default => View::Active,
        };
        self.links.is_k(&k.0, x.tumbler(), slice)
    }

    /// Drop other-BH1-filtered elements from a returned collection — the UV
    /// rewrite for the non-core collections in a `default` term.
    fn uv_drop(&self, k: &TypeKey, set: OrdSet<Tumbler>) -> OrdSet<Tumbler> {
        if self.view != View::Default {
            return set;
        }
        set.into_iter().filter(|e| !self.filtered_other(k, e)).collect()
    }

    /// BH3 join: `target_of` across the catalog's BH3-attached Binary
    /// classes — the same list the footprint analysis charges the atom with
    /// (none in this format; the type checker keeps the atom out of the
    /// vocabulary while that holds) — keyed by coverage class, each answered
    /// over the visible slice.
    fn targets_keyed(&self, source: &Address) -> im::HashMap<CoverageClass, Address> {
        let mut out = im::HashMap::new();
        for (class, endset) in self.catalog.bh3() {
            if let Some(target) = self.links.target_of(endset, source) {
                out.insert(class.clone(), target);
            }
        }
        out
    }
}

/// The denotation at the context's view. Pure, total, terminating; panics
/// only on precondition violations (a `Ref` with no `DefSource`, a
/// `ClassVar`, an ill-sorted runtime value — all unreachable on checked
/// input).
pub(crate) fn eval_term<W>(cx: &EvalCtx<'_, W>, env: &Env, t: &Term) -> Value {
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
        Term::Atom(a) => eval_atom(cx, env, a),
        Term::Prim(p) => eval_prim(cx, env, p),
        Term::And(a, b) => Value::Bool(as_bool(eval_term(cx, env, a)) && as_bool(eval_term(cx, env, b))),
        Term::Or(a, b) => Value::Bool(as_bool(eval_term(cx, env, a)) || as_bool(eval_term(cx, env, b))),
        Term::Not(a) => Value::Bool(!as_bool(eval_term(cx, env, a))),
        Term::Implies(a, b) => {
            Value::Bool(!as_bool(eval_term(cx, env, a)) || as_bool(eval_term(cx, env, b)))
        }
        Term::Iff(a, b) => Value::Bool(as_bool(eval_term(cx, env, a)) == as_bool(eval_term(cx, env, b))),
        // Short-circuit: ∀ stops at the first counterexample, ∃ at the first
        // witness (over the materialized slice — §Internal 2 tradeoff).
        Term::Forall { var, dom, body } => Value::Bool(
            enum_dom(cx, env, dom)
                .into_iter()
                .all(|e| as_bool(eval_term(cx, &env.bind(*var, Value::from(e)), body))),
        ),
        Term::Exists { var, dom, body } => Value::Bool(
            enum_dom(cx, env, dom)
                .into_iter()
                .any(|e| as_bool(eval_term(cx, &env.bind(*var, Value::from(e)), body))),
        ),
        Term::Let { var, bound, body } => {
            let b = eval_term(cx, env, bound);
            eval_term(cx, &env.bind(*var, b), body)
        }
        Term::IfSome { opt, var, then_, else_ } => match eval_term(cx, env, opt) {
            Value::OptAddr(Some(a)) => eval_term(cx, &env.bind(*var, Value::Addr(a)), then_),
            Value::OptNat(Some(n)) => eval_term(cx, &env.bind(*var, Value::Nat(n)), then_),
            Value::OptAddr(None) | Value::OptNat(None) => eval_term(cx, env, else_),
            other => unreachable!("IfSome guard checked at an Opt sort, held {other:?}"),
        },
        // Set-semantics counting (PC2a): enum_dom deduplicates address
        // domains; tuple slices are distinct by address.
        Term::Count(d) => Value::Nat(Nat::from(enum_dom(cx, env, d).len())),
        Term::MaxT1(d) => {
            let best = enum_dom(cx, env, d)
                .into_iter()
                .map(addr_elem)
                .max_by(|a, b| a.tumbler().cmp(b.tumbler()));
            Value::OptAddr(best)
        }
        Term::MinT1(d) => {
            let best = enum_dom(cx, env, d)
                .into_iter()
                .map(addr_elem)
                .min_by(|a, b| a.tumbler().cmp(b.tumbler()));
            Value::OptAddr(best)
        }
        Term::BigUnion { dom, var, body } => {
            let mut out: OrdSet<Tumbler> = OrdSet::new();
            for e in enum_dom(cx, env, dom) {
                let s = as_set(eval_term(cx, &env.bind(*var, Value::from(e)), body));
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
            for e in enum_dom(cx, env, d) {
                out.insert(addr_elem(e).tumbler().clone());
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
            let referent = defs
                .resolve_def(addr)
                .expect("WT-ref: every referent of a checked body has a defined signature");
            let inner: Env = referent
                .params()
                .iter()
                .map(|(v, _)| *v)
                .zip(args.iter().map(|arg| eval_term(cx, env, arg)))
                .collect();
            eval_term(cx, &inner, &referent.evaluable)
        }
    }
}

fn eval_atom<W>(cx: &EvalCtx<'_, W>, env: &Env, a: &Atom) -> Value {
    match a {
        Atom::IsK(tr, e) => {
            let k = tr.key();
            let x = as_addr(eval_term(cx, env, e));
            Value::Bool(cx.is_k_at(k, &x, cx.view))
        }
        Atom::Members(tr) => Value::AddrSet(cx.members_at(tr.key(), cx.view)),
        Atom::TargetsOf(tr, e) => {
            let x = as_addr(eval_term(cx, env, e));
            Value::AddrSet(cx.targets_of_at(tr.key(), &x, cx.view))
        }
        // BH1: is_filtered_J ≡ is_k(J, ·) — D2, J's own active membership,
        // fixed active at every term view.
        Atom::IsFiltered(tr, e) => {
            let k = tr.key();
            let x = as_addr(eval_term(cx, env, e));
            Value::Bool(cx.links.is_k(&k.0, x.tumbler(), View::Active))
        }
        Atom::Succs(tr, e) => {
            let k = tr.key();
            let x = as_addr(eval_term(cx, env, e));
            let set: OrdSet<Tumbler> =
                cx.links.succs(&k.0, &x).into_iter().map(|a| a.tumbler().clone()).collect();
            Value::AddrSet(cx.uv_drop(k, set))
        }
        Atom::Chain(tr, e) => {
            let k = tr.key();
            let x = as_addr(eval_term(cx, env, e));
            let chain = cx.links.chain(&k.0, &x);
            let seq: im::Vector<Address> = if cx.view == View::Default {
                chain.into_iter().filter(|a| !cx.filtered_other(k, a.tumbler())).collect()
            } else {
                chain.into_iter().collect()
            };
            Value::AddrSeq(seq)
        }
        // Verdict/traversal atoms are never UV-rewritten (UV): unfiltered
        // active walk.
        Atom::Tip(tr, e) => {
            let k = tr.key();
            let x = as_addr(eval_term(cx, env, e));
            Value::OptAddr(match cx.links.tip(&k.0, &x) {
                Tip::Sink(a) => Some(a),
                Tip::Indeterminate => None,
            })
        }
        Atom::IsInChain(tr, e1, e2) => {
            let k = tr.key();
            let x = as_addr(eval_term(cx, env, e1));
            let y = as_addr(eval_term(cx, env, e2));
            Value::Bool(cx.links.is_in_chain(&k.0, &x, &y))
        }
        Atom::SourcesTo(tr, e) => {
            let k = tr.key();
            let x = as_addr(eval_term(cx, env, e));
            let set: OrdSet<Tumbler> =
                cx.links.sources_to(&k.0, &x).into_iter().map(|a| a.tumbler().clone()).collect();
            Value::AddrSet(cx.uv_drop(k, set))
        }
        Atom::TargetOf(tr, e) => {
            let k = tr.key();
            let x = as_addr(eval_term(cx, env, e));
            Value::OptAddr(cx.links.target_of(&k.0, &x))
        }
        Atom::TargetsKeyed(e) => {
            let x = as_addr(eval_term(cx, env, e));
            Value::Map(cx.targets_keyed(&x))
        }
        // BH4 totalization (ASN-0129): age(a) = ⊥ exactly when `a` is not
        // the address of an ACTIVE K-tuple — a tuple-identity test, not
        // is_k's coverage-of-F membership.
        Atom::Age(tr, e) => {
            let k = tr.key();
            let a = as_addr(eval_term(cx, env, e));
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
            let k = tr.key();
            let h = as_nat(eval_term(cx, env, e));
            let h64 = u64::try_from(&h).unwrap_or(u64::MAX);
            let stale = cx
                .links
                .stale(&k.0, h64)
                .expect("type-check admits Stale only at a BH4-registered class");
            let set: OrdSet<Tumbler> = stale.into_iter().map(|a| a.tumbler().clone()).collect();
            Value::AddrSet(cx.uv_drop(k, set))
        }
        // V-DOC — M3 residence (a registered-but-arrangementless doc is a
        // valid residence; the eager/lazy split).
        Atom::IsDoc(e) => {
            let d = as_addr(eval_term(cx, env, e));
            Value::Bool(cx.m3.is_registered_document(&d))
        }
        Atom::TupAddr(v) => Value::Addr(tuple_var(env, v).addr.clone()),
        Atom::TupAddrsF(v) => Value::AddrSet(tuple_var(env, v).from.addrs().cloned().collect()),
        Atom::TupAddrsG(v) => Value::AddrSet(tuple_var(env, v).to.addrs().cloned().collect()),
        Atom::InCoverageF(e, v) => {
            let x = as_addr(eval_term(cx, env, e));
            Value::Bool(tuple_var(env, v).from.covers(x.tumbler()))
        }
        Atom::InCoverageG(e, v) => {
            let x = as_addr(eval_term(cx, env, e));
            Value::Bool(tuple_var(env, v).to.covers(x.tumbler()))
        }
    }
}

fn eval_prim<W>(cx: &EvalCtx<'_, W>, env: &Env, p: &Prim) -> Value {
    let ev = |t: &Term| eval_term(cx, env, t);
    match p {
        Prim::AddrEq(a, b) => Value::Bool(as_addr(ev(a)) == as_addr(ev(b))),
        Prim::Prefix(a, b) => {
            Value::Bool(is_prefix(as_addr(ev(a)).tumbler(), as_addr(ev(b)).tumbler()))
        }
        Prim::T1Lt(a, b) => Value::Bool(as_addr(ev(a)).tumbler() < as_addr(ev(b)).tumbler()),
        Prim::SetMem(x, s) => Value::Bool(as_set(ev(s)).contains(as_addr(ev(x)).tumbler())),
        Prim::SetEq(a, b) => Value::Bool(as_set(ev(a)) == as_set(ev(b))),
        Prim::IsEmpty(s) => Value::Bool(as_set(ev(s)).is_empty()),
        Prim::Elems(q) => match ev(q) {
            Value::AddrSeq(seq) => Value::AddrSet(seq.iter().map(|a| a.tumbler().clone()).collect()),
            other => unreachable!("Elems checked at AddrSeq, held {other:?}"),
        },
        Prim::NatEq(a, b) => Value::Bool(as_nat(ev(a)) == as_nat(ev(b))),
        Prim::NatLe(a, b) => Value::Bool(as_nat(ev(a)) <= as_nat(ev(b))),
        Prim::NatAdd(a, b) => Value::Nat(as_nat(ev(a)) + as_nat(ev(b))),
        // ·[K] keys through the catalog's PRECOMPUTED class (never a runtime
        // coverage_class on user input); an absent key — non-BH3 K included —
        // denotes ⊥.
        Prim::MapGet(m, tr) => {
            let k = tr.key();
            let class = cx.catalog.class_of(k);
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

/// `[D]_snap` at the context's view — finite by QD-fin. Address domains
/// deduplicate (set semantics); tuple slices are distinct by address.
/// `Filter` composes over the materialized base (§Internal 2). Each element
/// is an [`Arg`] — the shape a rule binds, and the one a quantifier binds
/// through `Value::from`.
pub(crate) fn enum_dom<W>(cx: &EvalCtx<'_, W>, env: &Env, d: &Dom) -> Vec<Arg> {
    match d {
        // M_K at the TERM view (view-parameterized domain).
        Dom::MembersDom(tr) => cx
            .members_at(tr.key(), cx.view)
            .iter()
            .map(|t| Arg::Addr(lift(t)))
            .collect(),
        Dom::ActiveSlice(tr) => cx
            .links
            .observe(&tr.key().0, Pattern::default(), View::Active)
            .into_iter()
            .map(Arg::Tuple)
            .collect(),
        Dom::AuditSlice(tr) => cx
            .links
            .observe(&tr.key().0, Pattern::default(), View::Audit)
            .into_iter()
            .map(Arg::Tuple)
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
            out.iter().map(|t| Arg::Addr(lift(t))).collect()
        }
        Dom::Reg => unreachable!("no Reg domain survives type_check's Reg-expansion/folding"),
        Dom::Filter { dom, var, pred } => enum_dom(cx, env, dom)
            .into_iter()
            .filter(|e| as_bool(eval_term(cx, &env.bind(*var, Value::from(e.clone())), pred)))
            .collect(),
        Dom::SetTerm(t) => {
            let s = as_set(eval_term(cx, env, t));
            s.iter().map(|t| Arg::Addr(lift(t))).collect()
        }
    }
}
