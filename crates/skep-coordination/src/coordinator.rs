//! §Public interface — the one handle. All capability groups hang off
//! [`Coordinator<W>`] over the engine's `Arc<Kernel<W>>`. M9 contributes no
//! `WorldState` slice and no record variant — it is a pure orchestrator/
//! evaluator; everything it holds is a recomputable hint or an in-memory
//! working set (§Core data model).

use std::collections::HashSet;
use std::fmt;
use std::sync::Arc;

use skep_address::Address;
use skep_arrangement::Vstream;
use skep_kernel::{Kernel, Snapshot, WorldState};
use skep_links::{Endset, LinkWriter, ShippedType, TypeRegistry, View, Visibility};

use crate::ast::{Term, VarId};
use crate::catalog::TypeCatalog;
use crate::check::{Checker, Ctx, TriggerTerm, TypedTerm, Unresolved};
use crate::defs::parse_def;
use crate::dynamics::{classify_term, Dynamics};
use crate::error::TypeError;
use crate::eval::{eval_term, DefSource, EvalCtx};
use crate::guest::GuestLinks;
use crate::memo::{Breach, DefMemo, DefStatus};
use crate::rule::RuleId;
use crate::value::{holds_addresses, value_sort, Env, Signature, SignedTerm, Sort, Value};
use crate::CoordinationWorld;

/// The M5 `Vstream` factory the engine injects: a borrow-scoped op handle
/// minted off `&Kernel<W>` per call (driver construction is the engine's by
/// the composition contract, so M9 names `Vstream::new` nowhere; HRTB
/// because the handle borrows the kernel).
pub type VstreamFactory<W> = Box<dyn for<'k> Fn(&'k Kernel<W>) -> Vstream<'k, W> + Send + Sync>;

/// The M7 `LinkWriter` factory the engine injects: a writer over the kernel
/// AT A VISIBILITY CLASS (lane 3.3b). Called only by
/// [`Coordinator::link_writer`], which hands it the coordinator's `guest`
/// predicate, so the value-keyed gates of every fire and every def write run
/// at guest class.
pub type LinkWriterFactory<W> =
    Box<dyn for<'k> Fn(&'k Kernel<W>, &'k Visibility<'k, W>) -> LinkWriter<'k, W> + Send + Sync>;

/// One registered rule in the working set (§Internal 5): the checked
/// `TypedDom`, the checked trigger, the declared view, the action.
#[derive(Debug, Clone)]
pub(crate) struct CheckedRule {
    pub(crate) id: RuleId,
    pub(crate) dom: crate::check::TypedDom,
    /// The checked trigger: a one-parameter Bool `TypedTerm` — an `Inline`
    /// trigger's own, or the memo entry of a `Def` trigger's def, captured
    /// at registration. The body is immutable content, so the trigger reads
    /// only the snapshot it is evaluated on: no ordering between that
    /// snapshot and the def's registration is required, and a later
    /// retraction of the def changes nothing. Ref-bearing iff it came from a
    /// def; evaluation resolves referents through the memo, the static
    /// analyses through the flat expansion.
    pub(crate) trigger: Arc<TypedTerm>,
    pub(crate) view: View,
    pub(crate) action: crate::rule::FireAction,
}

/// M9's one public handle: PL (group A), predicate definitions (group B), and
/// the reactive rule engine (group C). Owns no authoritative state — the
/// `DefMemo` is an interior-mutable recomputable hint; the rule registry
/// and rotation cursor are the `&mut self` working set.
pub struct Coordinator<W: WorldState> {
    pub(crate) kernel: Arc<Kernel<W>>,
    pub(crate) catalog: TypeCatalog,
    pub(crate) memo: DefMemo,
    pub(crate) rules: Vec<CheckedRule>,
    pub(crate) next_rule_id: u64,
    pub(crate) cursor: usize,
    pub(crate) mk_vstream: VstreamFactory<W>,
    pub(crate) mk_link_writer: LinkWriterFactory<W>,
    /// The GUEST-class read predicate over a document address (PUB round 2,
    /// lane 3.3, §5), in M7's own `Visibility` shape: `true` iff the
    /// document is readable at guest class — the engine supplies
    /// `published(doc)`. A fire consults it, off the fire's own pinned
    /// snapshot, on the action's HOME and on the bound argument's document
    /// before any deposit, so a rule's effect never crosses the draft
    /// boundary in either direction (a marker on a draft's content, or a
    /// deposit into a draft home). And every `LinkWriter` M9 builds is built
    /// AT this class (lane 3.3b, PUB-6.28): the same closure is lent to
    /// `mk_link_writer`, so M7's idempotency and dedup lookups see only
    /// guest-readable incumbents and a fire commits byte-identically to a
    /// world with no drafts. M9 holds no publication state of its own — the
    /// predicate is injected like the factories.
    pub(crate) guest: Box<Visibility<'static, W>>,
}

/// The working set is what a driver reads back — the registered rule ids
/// and the rotation cursor. The kernel, the catalog projection, the memo and
/// the injected factories are elided (`finish_non_exhaustive`).
impl<W: WorldState> fmt::Debug for Coordinator<W> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Coordinator")
            .field("rules", &self.rules.iter().map(|r| r.id).collect::<Vec<_>>())
            .field("next_rule_id", &self.next_rule_id)
            .field("cursor", &self.cursor)
            .finish_non_exhaustive()
    }
}

impl<W: CoordinationWorld> Coordinator<W> {
    /// Engine-assembled construction. Receives the shared kernel; the ONE
    /// engine-built `Arc<TypeRegistry>` (NEVER rebuilt here — Conflicts §7),
    /// which M9 projects its static `TypeCatalog` from and then need not
    /// retain; and the two op-handle factories, [`VstreamFactory`] and
    /// [`LinkWriterFactory`] (the latter takes the VISIBILITY class beside
    /// the kernel — lane 3.3b: M9 lends it `guest` at every construction, a
    /// borrow of the one closure it holds).
    ///
    /// Infallible: the registry's population is the compiled shipped five
    /// (owner ruling, 2026-08-26), so the projection is a pure read of the
    /// injected registry and there is no twice-passed configuration whose
    /// drift a validate-once-or-fail step would catch.
    ///
    /// `guest` is the GUEST-class read predicate (lane 3.3 §5): the engine
    /// passes `World::readable_guest`; a fire refuses, before any deposit,
    /// an action whose home or bound argument's document it answers `false`
    /// for (`FireError::DraftBoundary`), and every write M9 makes runs its
    /// value-keyed gates at this class (PUB-6.28).
    pub fn new(
        kernel: Arc<Kernel<W>>,
        registry: Arc<TypeRegistry>,
        mk_vstream: VstreamFactory<W>,
        mk_link_writer: LinkWriterFactory<W>,
        guest: Box<Visibility<'static, W>>,
    ) -> Coordinator<W> {
        let catalog = TypeCatalog::project(&registry);
        Coordinator {
            kernel,
            catalog,
            memo: DefMemo::new(),
            rules: Vec::new(),
            next_rule_id: 1,
            cursor: 0,
            mk_vstream,
            mk_link_writer,
            guest,
        }
    }

    /// M9's own cached catalog accessor (no snapshot) — the `&Endset` every
    /// `emit(d, reserved_type(…), …)` / PL `TypeKey` construction reads.
    /// Distinct from M7's snapshot-bound `LinkState::reserved_type`, and
    /// byte-identical to it: the catalog is a projection of the same
    /// registry.
    pub fn reserved_type(&self, t: ShippedType) -> &Endset {
        self.catalog.reserved(t)
    }

    /// One verdict's read context over the world `w` of a pinned snapshot,
    /// at the term view `view`: the catalog, M3, and M7 THROUGH THE
    /// GUEST-CLASS VIEW (`GuestLinks`, PUB round 2, lane 4.1 — every tuple
    /// homed where the injected `guest` predicate answers `false` is dropped
    /// from every read). The ONE construction site in the crate:
    /// `eval`/`decide`, the rule engine's domain enumeration, trigger
    /// evaluation and scope test, the fire's own re-check, and
    /// `evaluate_def`'s denotation all build their context here, so no
    /// evaluator ever reads the link store class-free.
    pub(crate) fn eval_ctx<'a>(
        &'a self,
        w: &'a W,
        view: View,
        defs: Option<&'a dyn DefSource>,
    ) -> EvalCtx<'a, W> {
        EvalCtx {
            catalog: &self.catalog,
            links: GuestLinks::new(w, w.links(), &*self.guest),
            m3: w.m3(),
            view,
            defs,
        }
    }

    /// The M7 write handle, AT GUEST CLASS (lane 3.3b, PUB-6.28) — the write
    /// side's twin of [`Coordinator::eval_ctx`], and the ONE construction
    /// site: every `emit`/`nullify` M9 makes (`register_pred`, `supersede`,
    /// `certify_stable`, `retract_pred`, and a rule's fire) goes through a
    /// writer built here, so M7's idempotency and dedup lookups see only
    /// guest-readable incumbents and no write can be built class-free.
    pub(crate) fn link_writer(&self) -> LinkWriter<'_, W> {
        (self.mk_link_writer)(self.kernel.as_ref(), &*self.guest)
    }

    // ──────────────────── A. The predicate language ────────────────────

    /// Type-check `body` under the ordered parameter context `params` (Γ_D —
    /// ASN-0129 WT is a Γ-parameterized CHECKING judgment; empty for a closed
    /// term), expand `Reg`-quantifiers to concrete-class instances (V-IDX),
    /// and reject ill-typed / dangling-reference / unregistered-type /
    /// unbound-variable / non-Codomain-parameter terms. Γ_D is Codom-only: a
    /// `Tup`-sorted parameter is `TupParameter` — a stored def binds values,
    /// never a tuple (ASN-0130 SignedTerm) — and the one PL term that binds a
    /// tuple, a rule trigger, is checked by [`Coordinator::type_check_trigger`]
    /// into a type of its own. Every `Concrete` `TypeKey` must be a canonical
    /// catalog endset (the probe is `Endset`-equality, not coverage). The
    /// check is also the term's resource door: a body nested past the
    /// crate's one nesting cap, counted through its references, is
    /// `TooDeep`, and one whose `Reg`-expansion outgrows the node budget is
    /// `TooLarge` — each refused at the bound, not after it. Reads no
    /// structural state for a ref-free body; consults the immutable def memo
    /// for any `Ref`. Once `Ok`, valid at every reachable state (WT).
    ///
    /// WHICH REJECTION SPEAKS, when several hold: `TupParameter` (over Γ_D)
    /// first, then `DuplicateParameter` (a Γ_D name bound twice), then the
    /// first rejection the checker meets in a pre-order walk of the body —
    /// a node's type position and behavior guard before its children;
    /// children left to right, a binder's domain or bound term before its
    /// body; a `Ref`'s referent before its arguments, each argument checked
    /// before it is matched against its formal, so an arity mismatch (a
    /// `SortMismatch`) speaks at the first unmatched position; a `Reg`
    /// quantifier's instances in catalog order — with `TooDeep`/`TooLarge`
    /// at the node where the budget is spent.
    pub fn type_check(&self, params: Vec<(VarId, Sort)>, body: Term) -> Result<TypedTerm, TypeError> {
        if let Some((v, _)) = params.iter().find(|(_, s)| *s == Sort::Tup) {
            return Err(TypeError::TupParameter(*v));
        }
        self.check_signed(SignedTerm { params, body }, 0)
    }

    /// Type-check a RULE TRIGGER: `body` under the one parameter `param` (any
    /// sort, `Tup` included — a tuple-domained rule fires by binding a
    /// `Value::Tuple`, ASN-0133 ρ_R), Bool codomain (`SortMismatch`
    /// otherwise). The domain↔parameter sort reconciliation and the ref-free
    /// requirement are `register_rule`'s. Which rejection speaks: the
    /// checker's, in [`Coordinator::type_check`]'s walk order, before the
    /// Bool requirement.
    pub fn type_check_trigger(&self, param: (VarId, Sort), body: Term) -> Result<TriggerTerm, TypeError> {
        let t = self.check_signed(SignedTerm { params: vec![param], body }, 0)?;
        if t.result != Sort::Bool {
            return Err(TypeError::SortMismatch { expected: Sort::Bool, found: t.result });
        }
        Ok(TriggerTerm(Arc::new(t)))
    }

    /// The ONE checker invocation: WT + WT-ref over the signed term — its
    /// body under its Γ_D — into the checked-term shape, the body's root at
    /// nesting level `depth`: 0 at the top of a chain (the public checks,
    /// `register_pred`, a cold `signature`), and for a def derived through a
    /// `Ref` the level the checker charged that `Ref` for its referent, so
    /// the chain's total nesting is bounded by `MAX_DEPTH` however deep the
    /// derivation runs. Γ_D binds each name once (`DuplicateParameter`
    /// otherwise — the one gate, so a stored def with a repeated name is a
    /// breach and a supplied one a rejection). Referents resolve through the
    /// def memo at the level the checker asks for them: a referent with no
    /// defined signature is `DanglingReference`, and one whose derivation
    /// cannot complete at that level is `TooDeep` here, with the referent
    /// left unjudged.
    pub(crate) fn check_signed(&self, signed: SignedTerm, depth: u32) -> Result<TypedTerm, TypeError> {
        let mut seen: HashSet<VarId> = HashSet::with_capacity(signed.params.len());
        if let Some((v, _)) = signed.params.iter().find(|(v, _)| !seen.insert(*v)) {
            return Err(TypeError::DuplicateParameter(*v));
        }
        let resolve = |a: &Address, d: u32| self.resolve_def_at(a, d);
        let checker = Checker::new(&self.catalog, &resolve);
        let ctx: Ctx = signed.params.iter().copied().collect();
        let checked = checker.check_term(&ctx, &signed.body, depth)?;
        Ok(TypedTerm {
            signed,
            result: checked.sort,
            evaluable: checked.term,
            ref_free: checked.ref_free,
            reach: checked.deepest.saturating_sub(depth),
        })
    }

    /// Pure, total, terminating denotation at one view against one committed
    /// snapshot. PRECONDITIONS, all asserted at the door: `t.is_ref_free()`
    /// — a surviving `Ref` node is a precondition violation (PANICS, like
    /// `decide` on a non-Bool codomain); ref-bearing terms evaluate only
    /// through `evaluate_def`, keeping this denotation content-free — and
    /// `env` binds every Γ_D parameter at its sort, an `AddrSet` holding
    /// T4-valid addresses only (the evaluator lifts each set element to an
    /// `Address` at its binding sites). INFALLIBLE past the door; reads ONLY
    /// M7 + M3, all off `snap` (PC4 / ASN-0134 clause 6) — M7 through the
    /// GUEST-CLASS view (lane 4.1, PUB-6.28): a tuple homed in a document
    /// the injected `guest` predicate refuses is invisible to the verdict,
    /// exactly as it is to a fire's gates. The verdict is "as of
    /// `snap.seq()`" (M2 V1 retrospective).
    pub fn eval(&self, t: &TypedTerm, env: &Env, view: View, snap: &Snapshot<W>) -> Value {
        assert!(
            t.is_ref_free(),
            "eval precondition violated: ref-bearing TypedTerm — route through evaluate_def"
        );
        for (v, s) in t.params() {
            let bound = env.get(v);
            assert!(
                bound.is_some_and(|val| value_sort(val) == *s),
                "eval precondition violated: Γ_D parameter {v:?} unbound or mis-sorted in env (expected {s:?})"
            );
            assert!(
                bound.is_some_and(holds_addresses),
                "eval precondition violated: AddrSet parameter {v:?} holds a tumbler that is not a T4-valid address"
            );
        }
        let cx = self.eval_ctx(snap.world(), view, None);
        eval_term(&cx, env, t.evaluable.as_ref())
    }

    /// Convenience for Bool-codomain terms; panics if the codomain is not
    /// Bool, or on either of `eval`'s preconditions.
    pub fn decide(&self, t: &TypedTerm, env: &Env, view: View, snap: &Snapshot<W>) -> bool {
        assert!(
            t.result_sort() == Sort::Bool,
            "decide precondition violated: codomain is {:?}, not Bool",
            t.result_sort()
        );
        match self.eval(t, env, view, snap) {
            Value::Bool(b) => b,
            other => unreachable!("Bool-codomain term denoted {other:?}"),
        }
    }

    /// Static footprint + 4-point stability lattice + the three active-view
    /// exceptions + view-independence flag, computed RELATIVE TO `view` (PC3
    /// binds the view-parameterized constituents to it); `view_independent`
    /// alone is view-agnostic (the PR-VIEW scan). Sound-but-incomplete; never
    /// over-certifies. Reads no state. PRECONDITION: ref-free (panics
    /// otherwise); a stored def is certified through `certify_stable` and a
    /// trigger linted through `certify_rule`, each over its flat expansion.
    pub fn classify(&self, t: &TypedTerm, view: View) -> Dynamics {
        assert!(
            t.is_ref_free(),
            "classify precondition violated: ref-bearing TypedTerm — certify via certify_stable, \
             which classifies the flat reference expansion"
        );
        classify_term(&self.catalog, view, t.evaluable.as_ref())
    }

    // ───────────────── internal: the DefMemo (§Internal 4) ─────────────────

    /// Memo-or-derive at the top of a derivation chain — a status about the
    /// content alone: every start answers at level 0, where `register_pred`
    /// checked it (a nesting refusal there is the content's own, a breach).
    pub(crate) fn def_status(&self, start: &Address) -> DefStatus {
        self.def_status_at(start, 0).unwrap_or_else(|DerivedTooDeep| {
            unreachable!(
                "a derivation rooted at level 0 completes or poisons: derive_def freezes a \
                 nesting refusal there as the content's own breach"
            )
        })
    }

    /// Memo-or-derive with the derivation's root at nesting level `depth`:
    /// a memo hit answers at any level; a miss derives from immutable
    /// content at `depth`, and a derivation that cannot complete there is
    /// [`DerivedTooDeep`] — the asking term's refusal, filling nothing.
    fn def_status_at(&self, start: &Address, depth: u32) -> Result<DefStatus, DerivedTooDeep> {
        if let Some(hit) = self.memo.get(start) {
            return Ok(hit);
        }
        self.derive_def(start, depth)
    }

    /// The miss path: pin its OWN snapshot to check ever-registration (a
    /// never-registered start is never cached — a later registration must
    /// surface), then derive from immutable content with the body's root at
    /// `depth`, recursing through referents at the levels the checker
    /// charges them (well-founded by PR2; a breach cycle strictly deepens
    /// each round until the checker's nesting door refuses it).
    ///
    /// What is memoized is the CONTENT's verdict and nothing else: an
    /// ever-registered start whose content fails the parse, or fails WT on
    /// its own account, fills the memo poisoned — freeze-on-breach (PR-DISC,
    /// §Internal 4). A nesting refusal ABOVE level 0 is not the content's:
    /// every registered def was checked at level 0 and fits there, and every
    /// registered consumer's `Ref` charge (`TypedTerm::reach`) guarantees
    /// its referents fit where a cold derivation starts them — so a
    /// `TooDeep` at `depth > 0` is the referring term's, answered as
    /// [`DerivedTooDeep`] with the memo untouched, and the same term
    /// answers `TooDeep` on a warm memo and a cold one alike. At level 0 a
    /// `TooDeep` can only be a breach (content registered past the gate),
    /// and freezes.
    fn derive_def(&self, start: &Address, depth: u32) -> Result<DefStatus, DerivedTooDeep> {
        let snap = self.kernel.snapshot();
        let w = snap.world();
        if !self.ever_registered(w, start) {
            return Ok(DefStatus::NeverRegistered);
        }
        let verdict = match parse_def(w, start) {
            Err(_) => Err(Breach),
            Ok(signed) => match self.check_signed(signed, depth) {
                Ok(entry) => Ok(entry),
                Err(TypeError::TooDeep) if depth > 0 => return Err(DerivedTooDeep),
                Err(_) => Err(Breach),
            },
        };
        Ok(self.memo.fill(start, verdict))
    }

    /// The defined referent at `start`, its derivation (if the memo misses)
    /// rooted at nesting level `depth` — the resolver the checker consults
    /// for a `Ref`, which asks at the level it charged the reference for.
    /// No defined signature (never registered, or poisoned) is
    /// `Unresolved::Dangling`; a derivation that cannot complete at `depth`
    /// is `Unresolved::TooDeep`, the referent unjudged.
    pub(crate) fn resolve_def_at(&self, start: &Address, depth: u32) -> Result<Arc<TypedTerm>, Unresolved> {
        match self.def_status_at(start, depth) {
            Ok(DefStatus::Defined(e)) => Ok(e),
            Ok(DefStatus::Poisoned | DefStatus::NeverRegistered) => Err(Unresolved::Dangling),
            Err(DerivedTooDeep) => Err(Unresolved::TooDeep),
        }
    }

    /// `(Γ_D, C_D)` — defined-signature starts only; answered from the
    /// immutable DefMemo. A `Some` is permanent and cacheable forever
    /// (content immutable, ever-registration monotone); a never-registered
    /// `None` is transient and never memoized; an ever-registered-but-
    /// undisciplined start answers `None` via a PERMANENT poisoned entry
    /// (freeze-on-breach, §Internal 4). No snapshot parameter — the miss
    /// path pins its own. A query: the memo it may fill answers every later
    /// probe as this one was answered.
    pub fn signature(&self, start: &Address) -> Option<Signature> {
        self.resolve_def_at(start, 0).ok().map(|e| e.signature())
    }
}

/// A derivation asked for at a level where it cannot complete: the
/// referring term is too deep. A verdict about the asking depth, never
/// about the content — so never memoized. Unreachable at level 0, where
/// `derive_def` freezes a nesting refusal as the content's breach.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DerivedTooDeep;

/// The referent supplier for the DAG-recursive drivers (a def's denotation,
/// the flat expansion) — the content-read pass stays distinct from the
/// structural denotation, so the denotation remains reference-free
/// (Conflicts §5). Asked at level 0, so the one refusal is "no defined
/// signature".
impl<W: CoordinationWorld> DefSource for Coordinator<W> {
    fn resolve_def(&self, addr: &Address) -> Option<Arc<TypedTerm>> {
        self.resolve_def_at(addr, 0).ok()
    }
}
