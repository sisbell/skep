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
use crate::walk::{visit_dom, visit_term, Visit};

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
/// domain (`is_doc`), the BH4 home-frontier flag, and the cross-type
/// `targets_keyed` join. Read through the accessors below; a caller that
/// wants to know what a term reads gets exactly the slices the analysis
/// recorded.
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
    /// The classes whose AUDIT slice (`L_K`) the term reads.
    pub fn audit_classes(&self) -> impl Iterator<Item = &CoverageClass> + '_ {
        self.audit.iter()
    }

    /// The classes whose ACTIVE slice the term reads (each ⊆ `L_K ∪ L_R`, so
    /// any retraction can shrink it — `ActiveExceptions::retraction_shrinks`).
    pub fn active_classes(&self) -> impl Iterator<Item = &CoverageClass> + '_ {
        self.active.iter()
    }

    /// The term reads the whole typed-relation audit sublayer (`L_dom`).
    pub fn reads_all_audit(&self) -> bool {
        self.all_audit
    }

    /// The term reads the residence domain (`is_doc`).
    pub fn reads_residence(&self) -> bool {
        self.residence
    }

    /// The term reads BH4's home-wide frontier (`age`/`stale`).
    pub fn reads_home_frontier(&self) -> bool {
        self.home_frontier
    }

    /// The term reads the cross-type `targets_keyed` join.
    pub fn reads_targets_keyed(&self) -> bool {
        self.targets_keyed
    }

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

/// A domain's analysis: its footprint and its membership in PD0's grow-only
/// closure — the two facts the quantifier, fold and `Filter` rules read of a
/// domain, and the certification lint's leg (c).
pub(crate) struct DomAnalysis {
    pub(crate) fp: Footprint,
    pub(crate) grow: bool,
}

fn constant(fp: Footprint) -> Analysis {
    let c = fp.is_empty();
    Analysis { fp, st: c, sf: c, grow: c }
}

/// A state read whose value is free to change across steps: Neither, and
/// outside the grow-only closure.
fn reads(fp: Footprint) -> Analysis {
    Analysis { fp, st: false, sf: false, grow: false }
}

/// A stability-threshold term: an ℕ literal, widened (ST⁺, `certify_stable`
/// only) to a bound ℕ parameter — the one PD0 widening (§Internal 3).
fn threshold_ok(t: &Term, widen: bool) -> bool {
    matches!(t, Term::Lit(Lit::Nat(_))) || (widen && matches!(t, Term::Var(_)))
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
        TypeRef::ClassVar(_) => unreachable!("post-Reg-expansion trees hold only Concrete TypeRefs"),
    }
}

/// One classification's fixed context: the catalog, the term view (PC3 —
/// binds the view-parameterized constituents), and the ST⁺ threshold
/// widening (certification only). The fused FP + PD0 pass runs over it.
/// Precondition on every input: ref-free, every `TypeRef` concrete (the
/// evaluable projection / a flat expansion).
pub(crate) struct Analyzer<'a> {
    pub(crate) catalog: &'a TypeCatalog,
    pub(crate) view: View,
    pub(crate) widen: bool,
}

impl Analyzer<'_> {
    /// Slice footprint of a typed read at a view: audit reads `L_K`; active
    /// (and default) reads the active slice (⊆ `L_K ∪ L_R`); default
    /// additionally reads each BH1 type's active filter slice (the UV
    /// rewrite's footprint).
    fn slice_fp(&self, k: &TypeKey, view: View) -> Footprint {
        let class = self
            .catalog
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
                for (j, _) in self.catalog.bh1() {
                    fp.active.insert(j.clone());
                }
            }
        }
        fp
    }

    /// The fused FP + PD0 pass over a term.
    pub(crate) fn term(&self, t: &Term) -> Analysis {
        match t {
            // Γ-/binder-bound vars and literals: empty footprint ⇒ ST∩SF.
            Term::Var(_) | Term::Lit(_) => constant(Footprint::default()),
            Term::Atom(a) => self.atom(a),
            Term::Prim(p) => self.prim(p),
            Term::And(x, y) | Term::Or(x, y) => {
                let ax = self.term(x);
                let ay = self.term(y);
                let fp = ax.fp.union(&ay.fp);
                Analysis { st: ax.st && ay.st, sf: ax.sf && ay.sf, grow: fp.is_empty(), fp }
            }
            Term::Not(x) => {
                let ax = self.term(x);
                Analysis { st: ax.sf, sf: ax.st, grow: ax.fp.is_empty(), fp: ax.fp }
            }
            // ⇒ combines SF⇒ST (PD0).
            Term::Implies(x, y) => {
                let ax = self.term(x);
                let ay = self.term(y);
                let fp = ax.fp.union(&ay.fp);
                Analysis { st: ax.sf && ay.st, sf: ax.st && ay.sf, grow: fp.is_empty(), fp }
            }
            Term::Iff(x, y) => {
                let ax = self.term(x);
                let ay = self.term(y);
                let fp = ax.fp.union(&ay.fp);
                let both = ax.st && ax.sf && ay.st && ay.sf;
                Analysis { st: both, sf: both, grow: fp.is_empty(), fp }
            }
            // Quantifiers per grow-only / step-constant domain (PD0): a
            // step-constant D strengthens both directions; a grow-only D gives
            // ∃/ST (a witness persists) and ∀/SF (a counterexample persists).
            Term::Forall { dom, body, .. } | Term::Exists { dom, body, .. } => {
                let ad = self.dom(dom);
                let ab = self.term(body);
                let step_const = ad.fp.is_empty();
                let (st, sf) = if step_const {
                    (ab.st, ab.sf)
                } else if ad.grow {
                    match t {
                        Term::Forall { .. } => (false, ab.sf),
                        _ => (ab.st, false),
                    }
                } else {
                    (false, false)
                };
                let fp = ad.fp.union(&ab.fp);
                Analysis { st, sf, grow: fp.is_empty(), fp }
            }
            Term::Let { bound, body, .. } => {
                let ab = self.term(bound);
                let ay = self.term(body);
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
                let ao = self.term(opt);
                let at = self.term(then_);
                let ae = self.term(else_);
                let guard_const = ao.fp.is_empty();
                let fp = ao.fp.union(&at.fp).union(&ae.fp);
                Analysis {
                    st: guard_const && at.st && ae.st,
                    sf: guard_const && at.sf && ae.sf,
                    grow: fp.is_empty(),
                    fp,
                }
            }
            Term::Count(d) | Term::MaxT1(d) | Term::MinT1(d) => constant(self.dom(d).fp),
            // ⋃(D, f) with D grow-only and f step-constant per binding is
            // grow-only (the derived closure form).
            Term::BigUnion { dom, body, .. } => {
                let ad = self.dom(dom);
                let ab = self.term(body);
                let fp = ad.fp.union(&ab.fp);
                let grow = fp.is_empty() || (ad.grow && ab.fp.is_empty());
                Analysis { st: fp.is_empty(), sf: fp.is_empty(), grow, fp }
            }
            // Reflect(D)'s footprint is D's; its value grows iff D does.
            Term::Reflect(d) => {
                let ad = self.dom(d);
                let empty = ad.fp.is_empty();
                Analysis { grow: empty || ad.grow, st: empty, sf: empty, fp: ad.fp }
            }
            Term::Ref { .. } => unreachable!(
                "classification precondition: ref-free input (an inline trigger's projection or a flat expansion)"
            ),
        }
    }

    fn atom(&self, a: &Atom) -> Analysis {
        let view = self.view;
        match a {
            // Audit is_K at a step-constant argument is ST (audit membership is
            // monotone); a state-reading argument lands in Neither.
            Atom::IsK(tr, e) => {
                let ae = self.term(e);
                let st = view == View::Audit && ae.fp.is_empty();
                let fp = ae.fp.union(&self.slice_fp(key(tr), view));
                Analysis { st, sf: false, grow: false, fp }
            }
            // M_K in an audit-view term is a grow-only set value (V-AUD).
            Atom::Members(tr) => {
                let fp = self.slice_fp(key(tr), view);
                Analysis { grow: view == View::Audit, st: false, sf: false, fp }
            }
            Atom::TargetsOf(tr, e) => {
                let ae = self.term(e);
                let grow = view == View::Audit && ae.fp.is_empty();
                let fp = ae.fp.union(&self.slice_fp(key(tr), view));
                Analysis { grow, st: false, sf: false, fp }
            }
            Atom::IsFiltered(tr, e) => {
                let ae = self.term(e);
                reads(ae.fp.union(&self.slice_fp(key(tr), View::Active)))
            }
            // BH2/BH3 collections: active-slice reads — Neither; at a default
            // term the UV drop additionally reads the BH1 filter slices.
            Atom::Succs(tr, e) | Atom::Chain(tr, e) | Atom::SourcesTo(tr, e) => {
                let ae = self.term(e);
                reads(ae.fp.union(&self.slice_fp(key(tr), effective_collection_view(view))))
            }
            // Verdict/traversal atoms (tip/is_in_chain) and the single-target
            // projection are never UV-rewritten: fixed active.
            Atom::Tip(tr, e) | Atom::TargetOf(tr, e) => {
                let ae = self.term(e);
                reads(ae.fp.union(&self.slice_fp(key(tr), View::Active)))
            }
            Atom::IsInChain(tr, x, y) => {
                let ax = self.term(x);
                let ay = self.term(y);
                reads(ax.fp.union(&ay.fp).union(&self.slice_fp(key(tr), View::Active)))
            }
            Atom::TargetsKeyed(e) => {
                let ae = self.term(e);
                let mut fp = ae.fp;
                for (c, _) in self.catalog.bh3() {
                    fp.active.insert(c.clone());
                }
                fp.targets_keyed = true;
                reads(fp)
            }
            // BH4: fixed active + the home-wide frontier; a default-term `stale`
            // collection additionally UV-drops (BH1 slices in its footprint).
            Atom::Age(tr, e) => {
                let ae = self.term(e);
                let mut fp = ae.fp.union(&self.slice_fp(key(tr), View::Active));
                fp.home_frontier = true;
                reads(fp)
            }
            Atom::Stale(tr, e) => {
                let ae = self.term(e);
                let mut fp = ae.fp.union(&self.slice_fp(key(tr), effective_collection_view(view)));
                fp.home_frontier = true;
                reads(fp)
            }
            // is_doc at a step-constant argument is ST (registration is
            // permanent).
            Atom::IsDoc(e) => {
                let ae = self.term(e);
                let st = ae.fp.is_empty();
                let mut fp = ae.fp;
                fp.residence = true;
                Analysis { st, sf: false, grow: false, fp }
            }
            // V-TUP: state-independent.
            Atom::TupAddr(_) | Atom::TupAddrsF(_) | Atom::TupAddrsG(_) => constant(Footprint::default()),
            Atom::InCoverageF(e, _) | Atom::InCoverageG(e, _) => {
                let ae = self.term(e);
                constant(ae.fp)
            }
        }
    }

    fn prim(&self, p: &Prim) -> Analysis {
        match p {
            // Grow-only membership at a step-constant probe is ST.
            Prim::SetMem(x, s) => {
                let ax = self.term(x);
                let as_ = self.term(s);
                let st_grow = ax.fp.is_empty() && as_.grow;
                let fp = ax.fp.union(&as_.fp);
                let empty = fp.is_empty();
                Analysis { st: empty || st_grow, sf: empty, grow: empty, fp }
            }
            // Emptiness of a grow-only set is SF.
            Prim::IsEmpty(s) => {
                let as_ = self.term(s);
                let sf_grow = as_.grow;
                let empty = as_.fp.is_empty();
                Analysis { st: empty, sf: empty || sf_grow, grow: empty, fp: as_.fp }
            }
            // count(D) ≤ c ∈ SF and count(D) ≥ c ∈ ST over a grow-only D, with a
            // literal threshold (ST⁺ widens to a bound ℕ parameter);
            // count(D) = c is unclassified — Neither (PD0).
            Prim::NatLe(x, y) => {
                let ax = self.term(x);
                let ay = self.term(y);
                let mut st = false;
                let mut sf = false;
                if let Term::Count(d) = &**x {
                    if threshold_ok(y, self.widen) {
                        sf |= self.dom(d).grow; // count(D) ≤ c: upper bound, false-stable
                    }
                }
                if let Term::Count(d) = &**y {
                    if threshold_ok(x, self.widen) {
                        st |= self.dom(d).grow; // c ≤ count(D): lower bound, true-stable
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
                let ax = self.term(x);
                let ay = self.term(y);
                constant(ax.fp.union(&ay.fp))
            }
            Prim::Elems(x) | Prim::Def(x) => constant(self.term(x).fp),
            Prim::MapGet(m, _) => constant(self.term(m).fp),
        }
    }

    /// Domain analysis: the footprint and grow-only membership. The grow-only
    /// closure (PD0): `L_K`; `L_dom`; `M_K` in an audit-view term;
    /// `Filter{D, P}` with D grow-only and P ∈ ST per binding; a
    /// step-constant domain; `SetTerm` of a grow-only set-valued term.
    pub(crate) fn dom(&self, d: &Dom) -> DomAnalysis {
        match d {
            Dom::MembersDom(tr) => DomAnalysis {
                fp: self.slice_fp(key(tr), self.view),
                grow: self.view == View::Audit,
            },
            Dom::ActiveSlice(tr) => {
                DomAnalysis { fp: self.slice_fp(key(tr), View::Active), grow: false }
            }
            Dom::AuditSlice(tr) => DomAnalysis { fp: self.slice_fp(key(tr), View::Audit), grow: true },
            Dom::LinkDom => {
                DomAnalysis { fp: Footprint { all_audit: true, ..Footprint::default() }, grow: true }
            }
            Dom::Reg => unreachable!("no Reg domain survives type_check's Reg-expansion/folding"),
            Dom::Filter { dom, pred, .. } => {
                let ad = self.dom(dom);
                let ap = self.term(pred);
                let grow = (ad.grow && ap.st) || (ad.fp.is_empty() && ap.fp.is_empty());
                DomAnalysis { fp: ad.fp.union(&ap.fp), grow }
            }
            Dom::SetTerm(t) => {
                let at = self.term(t);
                let grow = at.grow || at.fp.is_empty();
                DomAnalysis { fp: at.fp, grow }
            }
        }
    }
}

// ─────────────────────── PR-VIEW view-independence ───────────────────────

/// The syntactic scan: no view-parameterized constituent (`is_K`/`members`/
/// `targets_of`/`M_K`) and no UV-rewritten collection atom (`succs`/`chain`/
/// `sources_to`/`stale`). The same answer at every view. Precondition as the
/// `Analyzer`'s: ref-free input — a referent's body is the one part a `Ref`
/// node's own spelling cannot vouch for, so the scan runs over the flat
/// expansion, never around a `Ref`.
pub(crate) fn view_independent(t: &Term) -> bool {
    struct ViewScan {
        ok: bool,
    }
    impl Visit for ViewScan {
        fn term(&mut self, t: &Term) {
            if !self.ok {
                return;
            }
            match t {
                Term::Atom(
                    Atom::IsK(..)
                    | Atom::Members(_)
                    | Atom::TargetsOf(..)
                    | Atom::Succs(..)
                    | Atom::Chain(..)
                    | Atom::SourcesTo(..)
                    | Atom::Stale(..),
                ) => self.ok = false,
                Term::Ref { .. } => unreachable!(
                    "classification precondition: ref-free input (an inline trigger's projection or a flat expansion)"
                ),
                _ => visit_term(self, t),
            }
        }

        fn dom(&mut self, d: &Dom) {
            if !self.ok {
                return;
            }
            match d {
                Dom::MembersDom(_) => self.ok = false,
                _ => visit_dom(self, d),
            }
        }
    }
    let mut scan = ViewScan { ok: true };
    scan.term(t);
    scan.ok
}

/// Assemble a `Dynamics` from one analysis pass at `view`.
pub(crate) fn classify_term(catalog: &TypeCatalog, view: View, t: &Term) -> Dynamics {
    let a = Analyzer { catalog, view, widen: false }.term(t);
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
