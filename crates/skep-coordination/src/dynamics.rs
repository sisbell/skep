//! §Internal 3 — the dynamics / stability analyzer: a second bottom-up pass
//! (after type-check, over a ref-free tree with `Reg` expanded and every
//! `TypeRef` concrete), parameterized by the term view (PC3), fusing the FP
//! footprint and the PD0 stability induction, plus the PR-VIEW
//! view-independence scan. Sound but incomplete: classification is by
//! spelling and errs toward "not certified" — never over-certifies.

use im::HashSet;
use skep_links::{CoverageClass, View};

use crate::ast::{Atom, Dom, Lit, Prim, Term, TypeKey, TypeRef};
use crate::catalog::TypeCatalog;

/// `classify`'s output — all static, sound-but-incomplete. `footprint`/
/// `stability`/`active_exceptions` are RELATIVE TO `classify`'s view argument
/// (PC3); `view_independent` alone is view-agnostic (the PR-VIEW scan).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dynamics {
    pub footprint: Footprint,
    pub stability: Stability,
    pub active_exceptions: ActiveExceptions,
    pub view_independent: bool,
}

/// The 4-point lattice: ST∩SF / ST / SF / neither (PD0).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stability {
    StSf,
    StOnly,
    SfOnly,
    Neither,
}

/// Read slices: per-type {active, audit} (an active read implies `L_R` —
/// retractions shrink it), the whole-audit flag (`L_dom`), the residence
/// domain (`is_doc`), and the BH4 home-frontier flag.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Footprint {
    pub(crate) audit: HashSet<CoverageClass>,
    pub(crate) active: HashSet<CoverageClass>,
    pub(crate) all_audit: bool,
    pub(crate) residence: bool,
    pub(crate) home_frontier: bool,
    pub(crate) targets_keyed: bool,
}

impl Footprint {
    pub(crate) fn is_empty(&self) -> bool {
        self.audit.is_empty()
            && self.active.is_empty()
            && !self.all_audit
            && !self.residence
            && !self.home_frontier
            && !self.targets_keyed
    }

    fn union(mut self, other: &Footprint) -> Footprint {
        for c in other.audit.iter() {
            self.audit.insert(c.clone());
        }
        for c in other.active.iter() {
            self.active.insert(c.clone());
        }
        self.all_audit |= other.all_audit;
        self.residence |= other.residence;
        self.home_frontier |= other.home_frontier;
        self.targets_keyed |= other.targets_keyed;
        self
    }
}

/// The three active-view exceptions, emitted explicitly ("name them or be
/// surprised").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActiveExceptions {
    /// (i) any R-deposit can shrink an active slice.
    pub retraction_shrinks: bool,
    /// (ii) BH4 moves with same-home deposits.
    pub bh4_home_frontier: bool,
    /// (iii) targets_keyed is cross-type.
    pub targets_keyed_cross_type: bool,
}

/// Per-node analysis: footprint, ⊤-stability (st), ⊥-stability (sf), and —
/// for set-valued nodes — membership in the grow-only closure. Step-constant
/// = empty footprint (PD0's "literal or already-bound address" proviso,
/// transcribed structurally).
pub(crate) struct Analysis {
    pub(crate) fp: Footprint,
    pub(crate) st: bool,
    pub(crate) sf: bool,
    pub(crate) grow: bool,
}

fn constant(fp: Footprint) -> Analysis {
    let c = fp.is_empty();
    Analysis { fp, st: c, sf: c, grow: c }
}

/// Slice footprint of a typed read at a view: audit reads `L_K`; active (and
/// default) reads the active slice (⊆ `L_K ∪ L_R`); default additionally
/// reads each BH1 type's active filter slice (the UV rewrite's footprint).
fn slice_fp(catalog: &TypeCatalog, k: &TypeKey, view: View) -> Footprint {
    let class = catalog
        .get(k)
        .expect("checked Concrete TypeKeys are cataloged")
        .class
        .clone();
    let mut fp = Footprint::default();
    match view {
        View::Audit => {
            fp.audit.insert(class);
        }
        View::Active => {
            fp.active.insert(class);
        }
        View::Default => {
            fp.active.insert(class);
            for (j, _) in catalog.bh1() {
                fp.active.insert(j.clone());
            }
        }
    }
    fp
}

/// A stability-threshold term: an ℕ literal, widened (ST⁺, `certify_stable`
/// only) to a bound ℕ parameter — the one PD0 widening (§Internal 3).
fn threshold_ok(t: &Term, widen: bool) -> bool {
    matches!(t, Term::Lit(Lit::Nat(_))) || (widen && matches!(t, Term::Var(_)))
}

/// The fused FP + PD0 pass. Precondition: `t` is ref-free with every
/// `TypeRef` concrete (the evaluable projection / a flat expansion).
pub(crate) fn analyze_term(catalog: &TypeCatalog, view: View, widen: bool, t: &Term) -> Analysis {
    let a1 = |x: &Term| analyze_term(catalog, view, widen, x);
    match t {
        // Γ-/binder-bound vars and literals: empty footprint ⇒ ST∩SF.
        Term::Var(_) | Term::Lit(_) => constant(Footprint::default()),
        Term::Atom(a) => analyze_atom(catalog, view, widen, a),
        Term::Prim(p) => analyze_prim(catalog, view, widen, p),
        Term::And(x, y) | Term::Or(x, y) => {
            let ax = a1(x);
            let ay = a1(y);
            let fp = ax.fp.union(&ay.fp);
            Analysis { st: ax.st && ay.st, sf: ax.sf && ay.sf, grow: fp.is_empty(), fp }
        }
        Term::Not(x) => {
            let ax = a1(x);
            Analysis { st: ax.sf, sf: ax.st, grow: ax.fp.is_empty(), fp: ax.fp }
        }
        // ⇒ combines SF⇒ST (PD0).
        Term::Implies(x, y) => {
            let ax = a1(x);
            let ay = a1(y);
            let fp = ax.fp.union(&ay.fp);
            Analysis { st: ax.sf && ay.st, sf: ax.st && ay.sf, grow: fp.is_empty(), fp }
        }
        Term::Iff(x, y) => {
            let ax = a1(x);
            let ay = a1(y);
            let fp = ax.fp.union(&ay.fp);
            let both = ax.st && ax.sf && ay.st && ay.sf;
            Analysis { st: both, sf: both, grow: fp.is_empty(), fp }
        }
        // Quantifiers per grow-only / step-constant domain (PD0): a
        // step-constant D strengthens both directions; a grow-only D gives
        // ∃/ST (a witness persists) and ∀/SF (a counterexample persists).
        Term::Forall { dom, body, .. } | Term::Exists { dom, body, .. } => {
            let (dfp, dgrow) = analyze_dom(catalog, view, widen, dom);
            let ab = a1(body);
            let step_const = dfp.is_empty();
            let (st, sf) = if step_const {
                (ab.st, ab.sf)
            } else if dgrow {
                match t {
                    Term::Forall { .. } => (false, ab.sf),
                    _ => (ab.st, false),
                }
            } else {
                (false, false)
            };
            let fp = dfp.union(&ab.fp);
            Analysis { st, sf, grow: fp.is_empty(), fp }
        }
        Term::Let { bound, body, .. } => {
            let ab = a1(bound);
            let ay = a1(body);
            let bound_const = ab.fp.is_empty();
            let fp = ab.fp.union(&ay.fp);
            Analysis {
                st: bound_const && ay.st,
                sf: bound_const && ay.sf,
                grow: bound_const && ay.grow,
                fp,
            }
        }
        // A state-reading guard leaves the node in Neither (its value free
        // to change across steps and flip the branch).
        Term::IfSome { opt, then_, else_, .. } => {
            let ao = a1(opt);
            let at = a1(then_);
            let ae = a1(else_);
            let guard_const = ao.fp.is_empty();
            let fp = ao.fp.union(&at.fp).union(&ae.fp);
            Analysis {
                st: guard_const && at.st && ae.st,
                sf: guard_const && at.sf && ae.sf,
                grow: fp.is_empty(),
                fp,
            }
        }
        Term::Count(d) | Term::MaxT1(d) | Term::MinT1(d) => {
            let (dfp, _) = analyze_dom(catalog, view, widen, d);
            constant(dfp)
        }
        // ⋃(D, f) with D grow-only and f step-constant per binding is
        // grow-only (the derived closure form).
        Term::BigUnion { dom, body, .. } => {
            let (dfp, dgrow) = analyze_dom(catalog, view, widen, dom);
            let ab = a1(body);
            let fp = dfp.union(&ab.fp);
            let grow = fp.is_empty() || (dgrow && ab.fp.is_empty());
            Analysis { st: fp.is_empty(), sf: fp.is_empty(), grow, fp }
        }
        // Reflect(D)'s footprint is D's; its value grows iff D does.
        Term::Reflect(d) => {
            let (dfp, dgrow) = analyze_dom(catalog, view, widen, d);
            let empty = dfp.is_empty();
            Analysis { grow: empty || dgrow, st: empty, sf: empty, fp: dfp }
        }
        Term::Ref { .. } => unreachable!(
            "classification precondition: ref-free input (classify inline triggers or a flattened expand)"
        ),
    }
}

fn analyze_atom(catalog: &TypeCatalog, view: View, widen: bool, a: &Atom) -> Analysis {
    let a1 = |x: &Term| analyze_term(catalog, view, widen, x);
    match a {
        // Audit is_K at a step-constant argument is ST (audit membership is
        // monotone); a state-reading argument lands in Neither.
        Atom::IsK(tr, e) => {
            let ae = a1(e);
            let st = view == View::Audit && ae.fp.is_empty();
            let fp = ae.fp.union(&slice_fp(catalog, key(tr), view));
            Analysis { st, sf: false, grow: false, fp }
        }
        // M_K in an audit-view term is a grow-only set value (V-AUD).
        Atom::Members(tr) => {
            let fp = slice_fp(catalog, key(tr), view);
            Analysis { grow: view == View::Audit, st: false, sf: false, fp }
        }
        Atom::TargetsOf(tr, e) => {
            let ae = a1(e);
            let grow = view == View::Audit && ae.fp.is_empty();
            let fp = ae.fp.union(&slice_fp(catalog, key(tr), view));
            Analysis { grow, st: false, sf: false, fp }
        }
        Atom::IsFiltered(tr, e) => {
            let ae = a1(e);
            let fp = ae.fp.union(&slice_fp(catalog, key(tr), View::Active));
            Analysis { st: false, sf: false, grow: false, fp }
        }
        // BH2/BH3 collections: active-slice reads — Neither; at a default
        // term the UV drop additionally reads the BH1 filter slices.
        Atom::Succs(tr, e) | Atom::Chain(tr, e) | Atom::SourcesTo(tr, e) => {
            let ae = a1(e);
            let fp = ae.fp.union(&slice_fp(catalog, key(tr), effective_collection_view(view)));
            Analysis { st: false, sf: false, grow: false, fp }
        }
        // Verdict/traversal atoms (tip/is_in_chain) and the single-target
        // projection are never UV-rewritten: fixed active.
        Atom::Tip(tr, e) | Atom::TargetOf(tr, e) => {
            let ae = a1(e);
            let fp = ae.fp.union(&slice_fp(catalog, key(tr), View::Active));
            Analysis { st: false, sf: false, grow: false, fp }
        }
        Atom::IsInChain(tr, x, y) => {
            let ax = a1(x);
            let ay = a1(y);
            let fp = ax.fp.union(&ay.fp).union(&slice_fp(catalog, key(tr), View::Active));
            Analysis { st: false, sf: false, grow: false, fp }
        }
        Atom::TargetsKeyed(e) => {
            let ae = a1(e);
            let mut fp = ae.fp;
            for c in catalog.bh3() {
                fp.active.insert(c.clone());
            }
            fp.targets_keyed = true;
            Analysis { st: false, sf: false, grow: false, fp }
        }
        // BH4: fixed active + the home-wide frontier; a default-term `stale`
        // collection additionally UV-drops (BH1 slices in its footprint).
        Atom::Age(tr, e) => {
            let ae = a1(e);
            let mut fp = ae.fp.union(&slice_fp(catalog, key(tr), View::Active));
            fp.home_frontier = true;
            Analysis { st: false, sf: false, grow: false, fp }
        }
        Atom::Stale(tr, e) => {
            let ae = a1(e);
            let mut fp = ae.fp.union(&slice_fp(catalog, key(tr), effective_collection_view(view)));
            fp.home_frontier = true;
            Analysis { st: false, sf: false, grow: false, fp }
        }
        // is_doc at a step-constant argument is ST (registration is
        // permanent).
        Atom::IsDoc(e) => {
            let ae = a1(e);
            let st = ae.fp.is_empty();
            let mut fp = ae.fp;
            fp.residence = true;
            Analysis { st, sf: false, grow: false, fp }
        }
        // V-TUP: state-independent.
        Atom::TupAddr(_) | Atom::TupAddrsF(_) | Atom::TupAddrsG(_) => constant(Footprint::default()),
        Atom::InCoverageF(e, _) | Atom::InCoverageG(e, _) => {
            let ae = a1(e);
            constant(ae.fp)
        }
    }
}

/// A default-view term's non-core collections additionally read the BH1
/// filter slices (the UV drop); active/audit read their named slice.
fn effective_collection_view(view: View) -> View {
    match view {
        View::Default => View::Default,
        _ => View::Active,
    }
}

fn key(tr: &TypeRef) -> &TypeKey {
    match tr {
        TypeRef::Concrete(k) => k,
        TypeRef::ClassVar(_) => unreachable!("post-expansion trees hold only Concrete TypeRefs"),
    }
}

fn analyze_prim(catalog: &TypeCatalog, view: View, widen: bool, p: &Prim) -> Analysis {
    let a1 = |x: &Term| analyze_term(catalog, view, widen, x);
    match p {
        // Grow-only membership at a step-constant probe is ST.
        Prim::SetMem(x, s) => {
            let ax = a1(x);
            let as_ = a1(s);
            let st_grow = ax.fp.is_empty() && as_.grow;
            let fp = ax.fp.union(&as_.fp);
            let empty = fp.is_empty();
            Analysis { st: empty || st_grow, sf: empty, grow: empty, fp }
        }
        // Emptiness of a grow-only set is SF.
        Prim::IsEmpty(s) => {
            let as_ = a1(s);
            let sf_grow = as_.grow;
            let empty = as_.fp.is_empty();
            Analysis { st: empty, sf: empty || sf_grow, grow: empty, fp: as_.fp }
        }
        // count(D) ≤ c ∈ SF and count(D) ≥ c ∈ ST over a grow-only D, with a
        // literal threshold (ST⁺ widens to a bound ℕ parameter);
        // count(D) = c is unclassified — Neither (PD0).
        Prim::NatLe(x, y) => {
            let ax = a1(x);
            let ay = a1(y);
            let mut st = false;
            let mut sf = false;
            if let Term::Count(d) = &**x {
                if threshold_ok(y, widen) {
                    let (_, g) = analyze_dom(catalog, view, widen, d);
                    sf |= g; // count(D) ≤ c: upper bound, false-stable
                }
            }
            if let Term::Count(d) = &**y {
                if threshold_ok(x, widen) {
                    let (_, g) = analyze_dom(catalog, view, widen, d);
                    st |= g; // c ≤ count(D): lower bound, true-stable
                }
            }
            let fp = ax.fp.union(&ay.fp);
            let empty = fp.is_empty();
            Analysis { st: st || empty, sf: sf || empty, grow: empty, fp }
        }
        Prim::AddrEq(x, y)
        | Prim::Prefix(x, y)
        | Prim::T1Lt(x, y)
        | Prim::SetEq(x, y)
        | Prim::NatEq(x, y)
        | Prim::NatAdd(x, y) => {
            let ax = a1(x);
            let ay = a1(y);
            constant(ax.fp.union(&ay.fp))
        }
        Prim::Elems(x) | Prim::Def(x) => constant(a1(x).fp),
        Prim::MapGet(m, _) => constant(a1(m).fp),
    }
}

/// Domain analysis: (footprint, grow-only). The grow-only closure (PD0):
/// `L_K`; `L_dom`; `M_K` in an audit-view term; `Filter{D, P}` with D
/// grow-only and P ∈ ST per binding; a step-constant domain; `SetTerm` of a
/// grow-only set-valued term.
pub(crate) fn analyze_dom(catalog: &TypeCatalog, view: View, widen: bool, d: &Dom) -> (Footprint, bool) {
    match d {
        Dom::MembersDom(tr) => {
            let fp = slice_fp(catalog, key(tr), view);
            (fp, view == View::Audit)
        }
        Dom::ActiveSlice(tr) => (slice_fp(catalog, key(tr), View::Active), false),
        Dom::AuditSlice(tr) => (slice_fp(catalog, key(tr), View::Audit), true),
        Dom::LinkDom => {
            let fp = Footprint { all_audit: true, ..Footprint::default() };
            (fp, true)
        }
        Dom::Reg => unreachable!("no Reg domain survives type_check's expansion/folding"),
        Dom::Filter { dom, pred, .. } => {
            let (dfp, dgrow) = analyze_dom(catalog, view, widen, dom);
            let ap = analyze_term(catalog, view, widen, pred);
            let grow = (dgrow && ap.st) || (dfp.is_empty() && ap.fp.is_empty());
            (dfp.union(&ap.fp), grow)
        }
        Dom::SetTerm(t) => {
            let at = analyze_term(catalog, view, widen, t);
            let grow = at.grow || at.fp.is_empty();
            (at.fp, grow)
        }
    }
}

// ─────────────────────── PR-VIEW view-independence ───────────────────────

/// The syntactic scan: no view-parameterized constituent (`is_K`/`members`/
/// `targets_of`/`M_K`) and no UV-rewritten collection atom (`succs`/`chain`/
/// `sources_to`/`stale`). The same answer at every view.
pub(crate) fn view_independent(t: &Term) -> bool {
    match t {
        Term::Var(_) | Term::Lit(_) => true,
        Term::Atom(a) => match a {
            Atom::IsK(..) | Atom::Members(_) | Atom::TargetsOf(..) => false,
            Atom::Succs(..) | Atom::Chain(..) | Atom::SourcesTo(..) | Atom::Stale(..) => false,
            Atom::IsFiltered(_, e)
            | Atom::Tip(_, e)
            | Atom::TargetOf(_, e)
            | Atom::TargetsKeyed(e)
            | Atom::Age(_, e)
            | Atom::IsDoc(e)
            | Atom::InCoverageF(e, _)
            | Atom::InCoverageG(e, _) => view_independent(e),
            Atom::IsInChain(_, x, y) => view_independent(x) && view_independent(y),
            Atom::TupAddr(_) | Atom::TupAddrsF(_) | Atom::TupAddrsG(_) => true,
        },
        Term::Prim(p) => match p {
            Prim::AddrEq(x, y)
            | Prim::Prefix(x, y)
            | Prim::T1Lt(x, y)
            | Prim::SetMem(x, y)
            | Prim::SetEq(x, y)
            | Prim::NatEq(x, y)
            | Prim::NatLe(x, y)
            | Prim::NatAdd(x, y) => view_independent(x) && view_independent(y),
            Prim::IsEmpty(x) | Prim::Elems(x) | Prim::Def(x) | Prim::MapGet(x, _) => view_independent(x),
        },
        Term::And(x, y) | Term::Or(x, y) | Term::Implies(x, y) | Term::Iff(x, y) => {
            view_independent(x) && view_independent(y)
        }
        Term::Not(x) => view_independent(x),
        Term::Forall { dom, body, .. } | Term::Exists { dom, body, .. } => {
            dom_view_independent(dom) && view_independent(body)
        }
        Term::Let { bound, body, .. } => view_independent(bound) && view_independent(body),
        Term::IfSome { opt, then_, else_, .. } => {
            view_independent(opt) && view_independent(then_) && view_independent(else_)
        }
        Term::Count(d) | Term::MaxT1(d) | Term::MinT1(d) | Term::Reflect(d) => dom_view_independent(d),
        Term::BigUnion { dom, body, .. } => dom_view_independent(dom) && view_independent(body),
        Term::Ref { args, .. } => args.iter().all(|a| view_independent(a)),
    }
}

fn dom_view_independent(d: &Dom) -> bool {
    match d {
        Dom::MembersDom(_) => false,
        Dom::ActiveSlice(_) | Dom::AuditSlice(_) | Dom::LinkDom | Dom::Reg => true,
        Dom::Filter { dom, pred, .. } => dom_view_independent(dom) && view_independent(pred),
        Dom::SetTerm(t) => view_independent(t),
    }
}

/// Assemble a `Dynamics` from one analysis pass at `view`.
pub(crate) fn classify_term(catalog: &TypeCatalog, view: View, t: &Term) -> Dynamics {
    let a = analyze_term(catalog, view, false, t);
    let stability = match (a.st, a.sf) {
        (true, true) => Stability::StSf,
        (true, false) => Stability::StOnly,
        (false, true) => Stability::SfOnly,
        (false, false) => Stability::Neither,
    };
    Dynamics {
        active_exceptions: ActiveExceptions {
            retraction_shrinks: !a.fp.active.is_empty(),
            bh4_home_frontier: a.fp.home_frontier,
            targets_keyed_cross_type: a.fp.targets_keyed,
        },
        stability,
        view_independent: view_independent(t),
        footprint: a.fp,
    }
}
