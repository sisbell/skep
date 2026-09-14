//! §Internal 3 — the dynamics / stability analyzer: a second bottom-up pass
//! (after type-check, over a ref-free tree with `Reg` expanded and every
//! `TypeRef` concrete), parameterized by the term view (PC3), fusing the FP
//! footprint and the PD0 stability induction, plus the PR-VIEW
//! view-independence scan. Sound but incomplete: classification is by
//! spelling and errs toward "not certified" — never over-certifies.

use im::HashSet;
use skep_links::{CoverageClass, View};

use crate::ast::{Atom, Dom, Lit, Prim, Term, TypeKey, VarId};
use crate::catalog::TypeCatalog;
use crate::guest::Slice;
use crate::walk::{visit_dom, visit_term, Visit};

/// `classify`'s output — all static, sound-but-incomplete. `footprint`/
/// `stability`/`active_exceptions` are RELATIVE TO `classify`'s view argument
/// (PC3); `view_independent` alone is view-agnostic (the PR-VIEW scan).
///
/// `#[non_exhaustive]`: emitted, never constructed by a caller — the analyses
/// are a vocabulary that grows (as `CertifyError`'s static refusals do), and
/// a further report should be an addition rather than a broken build.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Dynamics {
    pub footprint: Footprint,
    pub stability: Stability,
    pub active_exceptions: ActiveExceptions,
    pub view_independent: bool,
}

/// The 4-point lattice: ST∩SF / ST / SF / neither (PD0). Deliberately NOT
/// `Ord`: `StOnly` and `SfOnly` are incomparable, so a derived total order
/// would compile, read meaningful, and contradict PD0.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Stability {
    StSf,
    StOnly,
    SfOnly,
    Neither,
}

/// Read slices: per-type {active, audit} (an active read implies `L_R` —
/// retractions shrink it), the whole-audit flag (`L_dom`), the residence
/// domain (`is_doc`), the BH4 home-frontier flag, and the cross-type
/// `targets_keyed` join. Read through the accessors below.
///
/// A SOUND OVER-APPROXIMATION: every slice the term may read is recorded,
/// and a recorded slice need not be read. One imprecision is deliberate —
/// `is_K` at the `default` view charges Φ's active slices, though UV never
/// rewrites a verdict atom — because every reader takes the footprint as a
/// superset. So a caller may use it to decide what MIGHT change a verdict,
/// never to assert that a dependency exists.
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

    /// Any active slice is read, so any R-deposit can shrink what the term
    /// reads (the first active-view exception, and the armer graph's
    /// retraction edge).
    pub fn retraction_shrinks(&self) -> bool {
        !self.active.is_empty()
    }

    /// THE ARMER GRAPH'S EDGE RULE (§8), whole: `emission` can change what a
    /// term with this footprint reads — because it lands in a class whose
    /// audit or active slice the term reads, because the term reads the whole
    /// audit sublayer, because the term reads BH4's home-wide frontier (which
    /// ANY same-home deposit moves), or because it is a RETRACTION and the
    /// term reads some active slice (every active slice shrinks under one).
    /// Asked of the footprint, which alone knows what a term reads, over an
    /// [`Emission`], which the rule engine builds because it alone knows what
    /// an action deposits.
    pub(crate) fn armed_by(&self, emission: &Emission) -> bool {
        let class = emission.class();
        self.all_audit
            || self.audit.contains(class)
            || self.active.contains(class)
            || self.home_frontier
            || (matches!(emission, Emission::Retraction(_)) && self.retraction_shrinks())
    }

    /// The term reads nothing, so its value cannot change across a state step
    /// — PD0's STEP-CONSTANT proviso ("a literal or an already-bound
    /// address"), transcribed structurally.
    pub(crate) fn is_step_constant(&self) -> bool {
        self.audit.is_empty()
            && self.active.is_empty()
            && !self.all_audit
            && !self.residence
            && !self.home_frontier
            && !self.targets_keyed
    }

    fn union(mut self, other: &Footprint) -> Footprint {
        self.audit.extend(other.audit.iter().cloned());
        self.active.extend(other.active.iter().cloned());
        self.all_audit |= other.all_audit;
        self.residence |= other.residence;
        self.home_frontier |= other.home_frontier;
        self.targets_keyed |= other.targets_keyed;
        self
    }
}

/// What a fire deposits, as the armer graph reads it (§8): the coverage class
/// of the tuple the action emits, and whether that emission is a RETRACTION —
/// which arms any active-reading trigger besides its own class, retractions
/// shrinking every active slice. Built by the rule engine, which alone knows
/// what an action emits; read by [`Footprint::armed_by`], which alone knows
/// what a term reads.
#[derive(Debug, Clone)]
pub(crate) enum Emission {
    Marker(CoverageClass),
    Retraction(CoverageClass),
}

impl Emission {
    /// The class the deposited tuple lands in, whichever kind it is.
    fn class(&self) -> &CoverageClass {
        match self {
            Emission::Marker(c) | Emission::Retraction(c) => c,
        }
    }
}

/// The three active-view exceptions, emitted explicitly ("name them or be
/// surprised"). `#[non_exhaustive]` for [`Dynamics`]'s reason: emitted, never
/// constructed by a caller, and a fourth exception named is an addition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct ActiveExceptions {
    /// (i) any R-deposit can shrink an active slice.
    pub retraction_shrinks: bool,
    /// (ii) BH4 moves with same-home deposits.
    pub bh4_home_frontier: bool,
    /// (iii) targets_keyed is cross-type.
    pub targets_keyed_cross_type: bool,
}

/// Per-node analysis: footprint, ⊤-stability (st), ⊥-stability (sf), and —
/// for set-valued nodes — membership in PD0's grow-only closure. PD0's other
/// closure property, step-constancy, is the footprint's own
/// ([`Footprint::is_step_constant`]) rather than a field here.
#[derive(Debug, Clone)]
pub(crate) struct Analysis {
    pub(crate) fp: Footprint,
    pub(crate) st: bool,
    pub(crate) sf: bool,
    pub(crate) grow_only: bool,
}

/// A domain's analysis: its footprint and its membership in PD0's grow-only
/// closure — the two facts the quantifier, fold and `Filter` rules read of a
/// domain, and the certification lint's leg (c).
#[derive(Debug, Clone)]
pub(crate) struct DomAnalysis {
    pub(crate) fp: Footprint,
    pub(crate) grow_only: bool,
}

/// A node whose value is fixed by its footprint: step-constant ⇒ ST∩SF and
/// grow-only vacuously; reading state ⇒ Neither and outside the closure.
fn step_constant(fp: Footprint) -> Analysis {
    let c = fp.is_step_constant();
    Analysis { fp, st: c, sf: c, grow_only: c }
}

/// A state read whose value is free to change across steps: Neither, and
/// outside the grow-only closure.
fn state_read(fp: Footprint) -> Analysis {
    Analysis { fp, st: false, sf: false, grow_only: false }
}

/// One classification's fixed context: the catalog, the term view (PC3 —
/// binds the view-parameterized constituents), and the ST⁺ threshold
/// widening. The fused FP + PD0 pass runs over it.
///
/// PRECONDITIONS on every input: ref-free, every `TypeRef` concrete, and
/// WITHIN [`crate::budget::MAX_DEPTH`] — this pass recurses once per node on
/// the caller's thread with no bound of its own, and takes that bound from
/// `TypedTerm::reach`, which the checker charges for the flat expansion as
/// well as for the checked tree. The two shapes that satisfy all three are a
/// checked term's evaluable projection and an `Expander` output.
///
/// The fields are private and [`Analyzer::new`] leaves `widen` false, so
/// [`st_plus`] — the one judgment PD0's widening belongs to — is the only
/// site that can set it, and no analysis outside this module can certify at
/// a strength `classify` would refuse.
pub(crate) struct Analyzer<'a> {
    catalog: &'a TypeCatalog,
    view: View,
    widen: bool,
}

impl<'a> Analyzer<'a> {
    /// The classification analyzer at `view`: PD0 without the ST⁺ threshold
    /// widening, which only [`st_plus`] applies.
    pub(crate) fn new(catalog: &'a TypeCatalog, view: View) -> Analyzer<'a> {
        Analyzer { catalog, view, widen: false }
    }

    /// A stability-threshold term: an ℕ literal, widened under ST⁺ to a bound
    /// ℕ parameter — the one PD0 widening (§Internal 3).
    fn threshold_ok(&self, t: &Term) -> bool {
        matches!(t, Term::Lit(Lit::Nat(_))) || (self.widen && matches!(t, Term::Var(_)))
    }

    /// The stored slice a read of class `k` touches: the audit slice is
    /// `L_K`; the active slice is ⊆ `L_K ∪ L_R`, so any retraction can shrink
    /// it. Which slice a term's VIEW reads is [`Slice::of`]'s statement, made
    /// once per arm below.
    fn slice_fp(&self, k: &TypeKey, slice: Slice) -> Footprint {
        let mut fp = Footprint::default();
        let read = match slice {
            Slice::Audit => &mut fp.audit,
            Slice::Active => &mut fp.active,
        };
        read.insert(self.catalog.class_of(k).clone());
        fp
    }

    /// The BH1 filter slices a `default`-view term's UV rewrite consults per
    /// element (`EvalCtx::filtered_other`, fixed active); empty at `active`
    /// and `audit`, where no rewrite runs. Unioned into exactly the reads the
    /// evaluator UV-rewrites, so which those are is one token per arm.
    ///
    /// The atom arms that union it are exactly [`moves_with_view`]'s list,
    /// which PR-VIEW's scan refuses — for a union of two reasons: the first
    /// three take `Slice::of(view)`, the rest are UV-rewritten collections,
    /// and `is_K` is both view-parameterized and charged here deliberately
    /// though UV never rewrites it. So a change to either list belongs in
    /// both.
    fn read_filter_fp(&self) -> Footprint {
        let mut fp = Footprint::default();
        if self.view == View::Default {
            for (j, _) in self.catalog.read_filter_classes() {
                fp.active.insert(j.clone());
            }
        }
        fp
    }

    /// The fused FP + PD0 pass over a term.
    pub(crate) fn term(&self, t: &Term) -> Analysis {
        match t {
            // Γ-/binder-bound vars and literals: empty footprint ⇒ ST∩SF.
            Term::Var(_) | Term::Lit(_) => step_constant(Footprint::default()),
            Term::Atom(a) => self.atom(a),
            Term::Prim(p) => self.prim(p),
            Term::And(x, y) | Term::Or(x, y) => {
                let ax = self.term(x);
                let ay = self.term(y);
                let fp = ax.fp.union(&ay.fp);
                Analysis { st: ax.st && ay.st, sf: ax.sf && ay.sf, grow_only: fp.is_step_constant(), fp }
            }
            Term::Not(x) => {
                let ax = self.term(x);
                Analysis { st: ax.sf, sf: ax.st, grow_only: ax.fp.is_step_constant(), fp: ax.fp }
            }
            // ⇒ combines SF⇒ST (PD0).
            Term::Implies(x, y) => {
                let ax = self.term(x);
                let ay = self.term(y);
                let fp = ax.fp.union(&ay.fp);
                Analysis { st: ax.sf && ay.st, sf: ax.st && ay.sf, grow_only: fp.is_step_constant(), fp }
            }
            Term::Iff(x, y) => {
                let ax = self.term(x);
                let ay = self.term(y);
                let fp = ax.fp.union(&ay.fp);
                let both = ax.st && ax.sf && ay.st && ay.sf;
                Analysis { st: both, sf: both, grow_only: fp.is_step_constant(), fp }
            }
            // Quantifiers per grow-only / step-constant domain (PD0): a
            // step-constant D strengthens both directions; a grow-only D gives
            // ∃/ST (a witness persists) and ∀/SF (a counterexample persists).
            Term::Forall { dom, body, .. } | Term::Exists { dom, body, .. } => {
                let universal = matches!(t, Term::Forall { .. });
                let ad = self.dom(dom);
                let ab = self.term(body);
                let step_const = ad.fp.is_step_constant();
                let (st, sf) = if step_const {
                    (ab.st, ab.sf)
                } else if ad.grow_only {
                    if universal {
                        (false, ab.sf)
                    } else {
                        (ab.st, false)
                    }
                } else {
                    (false, false)
                };
                let fp = ad.fp.union(&ab.fp);
                Analysis { st, sf, grow_only: fp.is_step_constant(), fp }
            }
            Term::Let { bound, body, .. } => {
                let ab = self.term(bound);
                let ay = self.term(body);
                let bound_const = ab.fp.is_step_constant();
                let fp = ab.fp.union(&ay.fp);
                Analysis {
                    st: bound_const && ay.st,
                    sf: bound_const && ay.sf,
                    grow_only: bound_const && ay.grow_only,
                    fp,
                }
            }
            // A state-reading guard leaves the node in Neither (its value free
            // to change across steps and flip the branch).
            Term::IfSome { opt, then_, else_, .. } => {
                let ao = self.term(opt);
                let at = self.term(then_);
                let ae = self.term(else_);
                let guard_const = ao.fp.is_step_constant();
                let fp = ao.fp.union(&at.fp).union(&ae.fp);
                Analysis {
                    st: guard_const && at.st && ae.st,
                    sf: guard_const && at.sf && ae.sf,
                    grow_only: fp.is_step_constant(),
                    fp,
                }
            }
            Term::Count(d) | Term::MaxT1(d) | Term::MinT1(d) => step_constant(self.dom(d).fp),
            // ⋃(D, f) with D grow-only and f step-constant per binding is
            // grow-only (the derived closure form).
            Term::BigUnion { dom, body, .. } => {
                let ad = self.dom(dom);
                let ab = self.term(body);
                let fp = ad.fp.union(&ab.fp);
                let grow_only = fp.is_step_constant() || (ad.grow_only && ab.fp.is_step_constant());
                Analysis { st: fp.is_step_constant(), sf: fp.is_step_constant(), grow_only, fp }
            }
            // Reflect(D)'s footprint is D's; its value grows iff D does.
            Term::Reflect(d) => {
                let ad = self.dom(d);
                let step_const = ad.fp.is_step_constant();
                Analysis {
                    grow_only: step_const || ad.grow_only,
                    st: step_const,
                    sf: step_const,
                    fp: ad.fp,
                }
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
            //
            // `is_K` is a verdict atom: UV never rewrites it (`EvalCtx::is_k_at`
            // reads the active slice at `default`), so the BH1 charge here is
            // deliberately CONSERVATIVE — the footprint is read only as a
            // superset (`armed_by`, step-constancy), and the armer graph's
            // Default self-loop case is pinned on it.
            Atom::IsK(tr, e) => {
                let ae = self.term(e);
                let st = view == View::Audit && ae.fp.is_step_constant();
                let fp = ae.fp.union(&self.slice_fp(tr.key(), Slice::of(view))).union(&self.read_filter_fp());
                Analysis { st, sf: false, grow_only: false, fp }
            }
            // M_K in an audit-view term is a grow-only set value (V-AUD).
            Atom::Members(tr) => {
                let fp = self.slice_fp(tr.key(), Slice::of(view)).union(&self.read_filter_fp());
                Analysis { grow_only: view == View::Audit, st: false, sf: false, fp }
            }
            Atom::TargetsOf(tr, e) => {
                let ae = self.term(e);
                let grow_only = view == View::Audit && ae.fp.is_step_constant();
                let fp = ae.fp.union(&self.slice_fp(tr.key(), Slice::of(view))).union(&self.read_filter_fp());
                Analysis { grow_only, st: false, sf: false, fp }
            }
            Atom::IsFiltered(tr, e) => {
                let ae = self.term(e);
                state_read(ae.fp.union(&self.slice_fp(tr.key(), Slice::Active)))
            }
            // BH2/BH3 collections: fixed-active reads — Neither — and the
            // evaluator UV-rewrites them, so a default term's footprint carries
            // the BH1 slices too.
            Atom::Succs(tr, e) | Atom::Chain(tr, e) | Atom::SourcesTo(tr, e) => {
                let ae = self.term(e);
                state_read(ae.fp.union(&self.slice_fp(tr.key(), Slice::Active)).union(&self.read_filter_fp()))
            }
            // Verdict/traversal atoms (tip/is_in_chain) and the single-target
            // projection are never UV-rewritten: fixed active.
            Atom::Tip(tr, e) | Atom::TargetOf(tr, e) => {
                let ae = self.term(e);
                state_read(ae.fp.union(&self.slice_fp(tr.key(), Slice::Active)))
            }
            Atom::IsInChain(tr, x, y) => {
                let ax = self.term(x);
                let ay = self.term(y);
                state_read(ax.fp.union(&ay.fp).union(&self.slice_fp(tr.key(), Slice::Active)))
            }
            Atom::TargetsKeyed(e) => {
                let ae = self.term(e);
                let mut fp = ae.fp;
                for (c, _) in self.catalog.reverse_lookup_classes() {
                    fp.active.insert(c.clone());
                }
                fp.targets_keyed = true;
                state_read(fp)
            }
            // BH4: fixed active + the home-wide frontier. `age` is a
            // projection the evaluator never UV-rewrites; the `stale`
            // collection it does.
            Atom::Age(tr, e) => {
                let ae = self.term(e);
                let mut fp = ae.fp.union(&self.slice_fp(tr.key(), Slice::Active));
                fp.home_frontier = true;
                state_read(fp)
            }
            Atom::Stale(tr, e) => {
                let ae = self.term(e);
                let mut fp =
                    ae.fp.union(&self.slice_fp(tr.key(), Slice::Active)).union(&self.read_filter_fp());
                fp.home_frontier = true;
                state_read(fp)
            }
            // is_doc at a step-constant argument is ST (registration is
            // permanent).
            Atom::IsDoc(e) => {
                let ae = self.term(e);
                let st = ae.fp.is_step_constant();
                let mut fp = ae.fp;
                fp.residence = true;
                Analysis { st, sf: false, grow_only: false, fp }
            }
            // V-TUP: state-independent.
            Atom::TupAddr(_) | Atom::TupAddrsF(_) | Atom::TupAddrsG(_) => step_constant(Footprint::default()),
            Atom::InCoverageF(e, _) | Atom::InCoverageG(e, _) => {
                let ae = self.term(e);
                step_constant(ae.fp)
            }
        }
    }

    fn prim(&self, p: &Prim) -> Analysis {
        match p {
            // Grow-only membership at a step-constant probe is ST.
            Prim::SetMem(x, s) => {
                let ax = self.term(x);
                let aset = self.term(s);
                let st_grow = ax.fp.is_step_constant() && aset.grow_only;
                let fp = ax.fp.union(&aset.fp);
                let step_const = fp.is_step_constant();
                Analysis { st: step_const || st_grow, sf: step_const, grow_only: step_const, fp }
            }
            // Emptiness of a grow-only set is SF.
            Prim::IsEmpty(s) => {
                let aset = self.term(s);
                let sf_grow = aset.grow_only;
                let step_const = aset.fp.is_step_constant();
                Analysis {
                    st: step_const,
                    sf: step_const || sf_grow,
                    grow_only: step_const,
                    fp: aset.fp,
                }
            }
            // count(D) ≤ c ∈ SF and count(D) ≥ c ∈ ST over a grow-only D, with a
            // literal threshold (ST⁺ widens to a bound ℕ parameter);
            // count(D) = c is unclassified — Neither (PD0). Each side's
            // `Count` domain is analyzed exactly once here — its own analysis
            // is `step_constant(dom.fp)`, and the grow-only fact rides along — so
            // a threshold nested inside its own domain's filter costs linear
            // work, not a doubling per level.
            Prim::NatLe(x, y) => {
                let side = |t: &Term, other: &Term| -> (Analysis, bool) {
                    match t {
                        Term::Count(d) => {
                            let ad = self.dom(d);
                            let bound = self.threshold_ok(other) && ad.grow_only;
                            (step_constant(ad.fp), bound)
                        }
                        _ => (self.term(t), false),
                    }
                };
                let (ax, sf) = side(x, y); // count(D) ≤ c: upper bound, false-stable
                let (ay, st) = side(y, x); // c ≤ count(D): lower bound, true-stable
                let fp = ax.fp.union(&ay.fp);
                let step_const = fp.is_step_constant();
                Analysis { st: st || step_const, sf: sf || step_const, grow_only: step_const, fp }
            }
            Prim::AddrEq(x, y)
            | Prim::Prefix(x, y)
            | Prim::T1Lt(x, y)
            | Prim::SetEq(x, y)
            | Prim::NatEq(x, y)
            | Prim::NatAdd(x, y) => {
                let ax = self.term(x);
                let ay = self.term(y);
                step_constant(ax.fp.union(&ay.fp))
            }
            Prim::Elems(x) | Prim::Def(x) => step_constant(self.term(x).fp),
            Prim::MapGet(m, _) => step_constant(self.term(m).fp),
        }
    }

    /// Domain analysis: the footprint and grow-only membership. The grow-only
    /// closure (PD0): `L_K`; `L_dom`; `M_K` in an audit-view term;
    /// `Filter{D, P}` with D grow-only and P ∈ ST per binding; a
    /// step-constant domain; `SetTerm` of a grow-only set-valued term.
    pub(crate) fn dom(&self, d: &Dom) -> DomAnalysis {
        match d {
            Dom::MembersDom(tr) => DomAnalysis {
                fp: self.slice_fp(tr.key(), Slice::of(self.view)).union(&self.read_filter_fp()),
                grow_only: self.view == View::Audit,
            },
            Dom::ActiveSlice(tr) => {
                DomAnalysis { fp: self.slice_fp(tr.key(), Slice::Active), grow_only: false }
            }
            Dom::AuditSlice(tr) => DomAnalysis { fp: self.slice_fp(tr.key(), Slice::Audit), grow_only: true },
            Dom::LinkDom => {
                DomAnalysis { fp: Footprint { all_audit: true, ..Footprint::default() }, grow_only: true }
            }
            Dom::Reg => unreachable!("no Reg domain survives type_check's Reg-expansion/folding"),
            Dom::Filter { dom, pred, .. } => {
                let ad = self.dom(dom);
                let ap = self.term(pred);
                let grow_only = (ad.grow_only && ap.st) || (ad.fp.is_step_constant() && ap.fp.is_step_constant());
                DomAnalysis { fp: ad.fp.union(&ap.fp), grow_only }
            }
            Dom::SetTerm(t) => {
                let at = self.term(t);
                let grow_only = at.grow_only || at.fp.is_step_constant();
                DomAnalysis { fp: at.fp, grow_only }
            }
        }
    }
}

// ─────────────────────── PR-VIEW view-independence ───────────────────────

/// The atoms whose denotation moves with the TERM VIEW, classified
/// EXHAUSTIVELY: the three view-parameterized constituents (`is_K`/`members`/
/// `targets_of` — D1–D3 and V-AUD read different slices, and `targets_of`
/// matches its source differently at `audit`) and the four collections the
/// evaluator UV-rewrites at `default` (`succs`/`chain`/`sources_to`/`stale`).
/// Every other atom reads a fixed slice, or no state at all, and answers the
/// same at every view — though its ARGUMENTS need not, so the caller walks on.
///
/// No `_` arm, deliberately. `certify_stable` stands behind this scan and a
/// `pd_stable` tuple is a permanent content-addressed claim, so an atom added
/// to `ast.rs` must be CLASSIFIED here rather than inherit the certifying
/// answer by default — and a conservative default would be no better, since it
/// would silently refuse a legitimate view-independent atom. These are also
/// exactly the arms [`Analyzer::read_filter_fp`] is unioned into, so a change
/// here belongs in both.
fn moves_with_view(a: &Atom) -> bool {
    match a {
        Atom::IsK(..)
        | Atom::Members(_)
        | Atom::TargetsOf(..)
        | Atom::Succs(..)
        | Atom::Chain(..)
        | Atom::SourcesTo(..)
        | Atom::Stale(..) => true,
        Atom::IsFiltered(..)
        | Atom::Tip(..)
        | Atom::IsInChain(..)
        | Atom::TargetOf(..)
        | Atom::TargetsKeyed(_)
        | Atom::Age(..)
        | Atom::IsDoc(_)
        | Atom::TupAddr(_)
        | Atom::TupAddrsF(_)
        | Atom::TupAddrsG(_)
        | Atom::InCoverageF(..)
        | Atom::InCoverageG(..) => false,
    }
}

/// The syntactic scan: no atom whose denotation [`moves_with_view`] and no
/// `M_K` domain (view-parameterized like the core atoms it reflects). The same
/// answer at every view. Preconditions as the [`Analyzer`]'s — the depth
/// bound included: this walk has none of its own. Ref-free, in particular,
/// because a referent's body is the one part a `Ref` node's own spelling
/// cannot vouch for, so the scan runs over the flat expansion, never around a
/// `Ref`.
pub(crate) fn view_independent(t: &Term) -> bool {
    struct ViewScan {
        independent: bool,
    }
    impl Visit for ViewScan {
        fn term(&mut self, t: &Term) {
            if !self.independent {
                return;
            }
            match t {
                Term::Atom(a) if moves_with_view(a) => self.independent = false,
                Term::Ref { .. } => unreachable!(
                    "classification precondition: ref-free input (an inline trigger's projection or a flat expansion)"
                ),
                _ => visit_term(self, t),
            }
        }

        /// `M_K` is the one view-parameterized domain; the rest name a fixed
        /// slice (`A_K`/`L_K`/`L_dom`), carry no state (`Reg`, folded away at
        /// type-check), or are closures whose children the walk reaches —
        /// enumerated rather than caught, for [`moves_with_view`]'s reason.
        fn dom(&mut self, d: &Dom) {
            if !self.independent {
                return;
            }
            match d {
                Dom::MembersDom(_) => self.independent = false,
                Dom::ActiveSlice(_)
                | Dom::AuditSlice(_)
                | Dom::LinkDom
                | Dom::Reg
                | Dom::Filter { .. }
                | Dom::SetTerm(_) => visit_dom(self, d),
            }
        }
    }
    let mut scan = ViewScan { independent: true };
    scan.term(t);
    scan.independent
}

// ───────────────────────────── ST⁺ ─────────────────────────────

/// ST⁺ — the certification-strength ⊤-stability judgment (§Internal 3): PD0
/// over a FLAT reference expansion (ST⁺ is not compositional over
/// references), with the aggregate threshold widened to a bound ℕ parameter
/// — the one PD0 widening, and the reason it is not `classify`'s. Judged at
/// a fixed view: `certify_stable` admits only view-independent expansions,
/// so the classification is view-invariant. Γ_D parameters read as bound
/// constants (a free `Var` has an empty footprint). Preconditions as the
/// [`Analyzer`]'s — the depth bound included: this walk has none of its own.
pub(crate) fn st_plus(catalog: &TypeCatalog, t: &Term) -> bool {
    Analyzer { catalog, view: View::Audit, widen: true }.term(t).st
}

// ───────────────────── the certified-Marker spelling ─────────────────────

/// The negated membership a certifiable Marker rule's trigger is spelled as:
/// `¬ is_K(x)` at `param`, yielding K — the witness the rule engine matches
/// its emitted class against (§8 leg b). `None` for every other spelling:
/// sound but incomplete, as the rest of this module is, and by spelling, so
/// an equivalent trigger written otherwise is simply not certified.
/// Preconditions as the [`Analyzer`]'s — the depth bound included: this walk
/// has none of its own.
pub(crate) fn negated_membership(t: &Term, param: VarId) -> Option<&TypeKey> {
    let Term::Not(inner) = t else { return None };
    match inner.as_ref() {
        Term::Atom(Atom::IsK(tr, arg)) => match arg.as_ref() {
            Term::Var(v) if *v == param => Some(tr.key()),
            _ => None,
        },
        Term::Ref { .. } => unreachable!(
            "classification precondition: ref-free input (an inline trigger's projection or a flat expansion)"
        ),
        _ => None,
    }
}

/// Assemble a `Dynamics` from one analysis pass at `view`.
pub(crate) fn classify_term(catalog: &TypeCatalog, view: View, t: &Term) -> Dynamics {
    let analysis = Analyzer::new(catalog, view).term(t);
    let stability = match (analysis.st, analysis.sf) {
        (true, true) => Stability::StSf,
        (true, false) => Stability::StOnly,
        (false, true) => Stability::SfOnly,
        (false, false) => Stability::Neither,
    };
    Dynamics {
        active_exceptions: ActiveExceptions {
            retraction_shrinks: analysis.fp.retraction_shrinks(),
            bh4_home_frontier: analysis.fp.reads_home_frontier(),
            targets_keyed_cross_type: analysis.fp.reads_targets_keyed(),
        },
        stability,
        view_independent: view_independent(t),
        footprint: analysis.fp,
    }
}
