//! The reactive rule engine (§C / §Internal 5–8) and its working set's shapes.
//!
//! It holds registration validation (the one shared path `certify_rule`
//! re-runs), Q0/Q7 quiescence detection, the peek/fire/step scheduler (weak
//! fairness lives in `step`'s rotation), the SF+Marker+grow-only lint, the
//! journal-recomputed divergence backstop, and the static armer-cycle
//! warning — with the checked shapes the working set holds (`CheckedRule`,
//! `TypedDom`), which only this module builds.

use std::slice::from_ref;

use skep_address::{document_of, Address};
use skep_kernel::{Seq, Snapshot, TxnError};
use skep_links::{Caller, EmitError, Endset, NullifyError, Pattern, ShippedType, View};

use crate::ast::{ArcDom, Dom, Term};
use crate::check::{TriggerTerm, TypedTerm};
use crate::coordinator::memo::DefStatus;
use crate::coordinator::Coordinator;
use crate::dynamics::{negated_membership, Analyzer, Emission, Footprint};
use crate::error::{FireError, RuleError};
use crate::eval::{as_bool, enum_dom, eval_term};
use crate::rule::{
    FireAction, FireOutcome, Occurrence, Rule, RuleCertification, RuleId, ScopeBody, StepOutcome,
    Trigger,
};
use crate::value::{Arg, Env, Sort, Value};
use crate::CoordinationWorld;

/// A rule domain that passed the checker and `validate_rule`'s ref gate.
///
/// It passed the checker's closed-domain judgment and `validate_rule`'s
/// `RefBearingDomain` gate: the `Dom` analogue of `TypedTerm`'s evaluable
/// projection — every `TypeRef` `Concrete`, no surviving `Reg` binder,
/// ref-free (so its enumeration needs no `DefSource`: `enum_rule_dom` builds
/// its context with none), and nested within `MAX_DEPTH` — the bound
/// `enum_dom` and `Analyzer::dom` rely on, having none of their own. A
/// [`Rule`]'s own `domain` is the raw submission; only this shape is ever
/// enumerated, and only this module builds one — `validate_rule`, the shared
/// doorkeeper both `register_rule` and `certify_rule` run — so the working
/// set holds no unchecked domain.
#[derive(Debug, Clone)]
struct TypedDom(ArcDom);

impl TypedDom {
    /// Returns the checked domain, for enumeration (`enum_dom`) and analysis.
    fn as_dom(&self) -> &Dom {
        &self.0
    }
}

/// One registered rule in the working set.
///
/// It holds the checked domain, the checked trigger, the declared view, the
/// action, the trigger's footprint — `footprint(T_ρ)`, the reads §8's armer
/// graph asks about, never the rule's writes — and the rule's place in
/// `step`'s rotation. Built only by `register_rule`; the id alone is read
/// outside this module, by the handle's `Debug`.
#[derive(Debug, Clone)]
pub(super) struct CheckedRule {
    pub(super) id: RuleId,
    domain: TypedDom,
    /// The checked trigger, from the rule's `Inline` term or its `Def`.
    ///
    /// It is an `Inline` trigger's own [`TriggerTerm`], or a `Def` trigger's
    /// def captured into one at registration (the memo's own `Arc`, no copy).
    /// The body is immutable content, so the trigger reads only the snapshot
    /// it is evaluated on: no ordering between that snapshot and the def's
    /// registration is required, and a later retraction of the def changes
    /// nothing. Ref-bearing only if it came from a def; evaluation resolves
    /// referents through the memo, the static analyses through the flat
    /// expansion.
    trigger: TriggerTerm,
    view: View,
    action: FireAction,
    /// FP over the *trigger*, `footprint(T_ρ)`, at the rule's declared view.
    ///
    /// It is the subject §8's edge rule names, computed once at registration
    /// from the same flat ref-free expansion the node budget admitted there
    /// (`RuleError::TriggerExpansionTooLarge`). What the rule *writes* is the
    /// action's, which the armer graph reads as an [`Emission`]. A pure
    /// function of immutable inputs — the captured trigger's content, the
    /// frozen catalog, the declared view — so recording it costs nothing in
    /// authority, and the armer graph reads §8's edge rule off it rather than
    /// re-expanding every trigger on every call.
    trigger_footprint: Footprint,
    /// The key of the occurrence this rule's last `step` turn picked.
    ///
    /// It is `None` before the rule's first turn: where the rule's own
    /// rotation resumes ([`Coordinator::step`], §7). Every domain enumerates
    /// in ascending key order — an address domain's set in T1 order, a tuple
    /// slice in M7's ascending tuple-address order (`observe`'s stated
    /// order), a filter in its base's — so "past it" is "greater".
    last_pick: Option<Address>,
}

/// What `validate_rule` decides once, for both of its callers.
///
/// That is the checked domain, the captured trigger, and the trigger's
/// *flat* ref-free expansion — the tree the termination lint and the armer
/// graph read. The expansion is built where the node budget admits it
/// (`RuleError::TriggerExpansionTooLarge`) and handed on, so no later pass
/// re-derives it or has to argue that it fits.
#[derive(Debug)]
struct Validated {
    domain: TypedDom,
    trigger: TriggerTerm,
    flat_expansion: Term,
}

impl<W: CoordinationWorld> Coordinator<W> {
    // ───────────────── registration & the shared validation ─────────────────

    /// Validates `rule` and adds it to the working set.
    ///
    /// Each failure is a typed [`RuleError`], never a late eval-time panic:
    /// the domain is checked *and* normalized through the same WT-domain +
    /// `Reg`-expansion pass as `type_check` and stored as a checked
    /// `TypedDom`; the trigger's parameter sort must equal the domain element
    /// sort (a `Tup` domain requires an `Inline` trigger — a `Def` signature
    /// is Codom-only) and a `Def` trigger's def must be a one-parameter Bool
    /// def; a Marker action's `ty` is a cataloged idem⊤ Unary type that is not
    /// a PredLayer class (PR-DISC's in-module guard). Enforces
    /// *well-formedness* only, not termination — apply your own
    /// uncertified-rule policy via [`Coordinator::certify_rule`].
    ///
    /// **Postcondition.** The rule is in the working set for the life of this
    /// `Coordinator` — the registry is append-only (nothing de-registers, and
    /// a `RuleId` is never reused), so every later `quiescent`,
    /// `quiescent_scoped`, `next_enabled`, `step`, `fire`, `fire_count` and
    /// `armer_cycles` includes it, and a rule is shed only with its
    /// coordinator.
    ///
    /// # Errors
    ///
    /// Which rejection speaks, when several hold — the domain, then the
    /// trigger, then the action: `IllFormedDomain` (in `type_check`'s walk
    /// order), `RefBearingDomain`; for an `Inline` trigger
    /// `RefBearingInlineTrigger`, `DomainTriggerSortMismatch`; for a `Def`
    /// trigger `UndefinedDefTrigger`, `BadTriggerArity`, `TriggerNotBoolean`,
    /// `DomainTriggerSortMismatch`, `TriggerExpansionTooLarge`; for a Marker
    /// action `BadMarkerType`, `NonIdemMarkerType`, `PredLayerMarkerType`.
    /// The same order in [`Coordinator::certify_rule`], which runs the same
    /// validation.
    pub fn register_rule(&mut self, rule: Rule) -> Result<RuleId, RuleError> {
        let Validated { domain, trigger, flat_expansion } = self.validate_rule(&rule)?;
        // `footprint(T_ρ)` at the declared view, from the same flat expansion
        // the budget just admitted: recorded on the rule, so §8's armer graph
        // reads it rather than re-deriving it per call
        // (`CheckedRule::trigger_footprint` states why that costs no
        // authority).
        let trigger_footprint = Analyzer::new(&self.catalog, rule.view).term(&flat_expansion).fp;
        let id = RuleId(self.next_rule_id);
        self.next_rule_id += 1;
        self.rules.push(CheckedRule {
            id,
            domain,
            trigger,
            view: rule.view,
            action: rule.action,
            trigger_footprint,
            last_pick: None,
        });
        Ok(id)
    }

    /// Lints `rule` for termination: the SF + Marker + grow-only lint (§8).
    ///
    /// **Input contract.** It takes the raw submission and re-runs
    /// `register_rule`'s normalization internally (the one shared validation
    /// path), then lints the checked artifacts. Callable pre-registration; a
    /// query — registers nothing. `CertifiedTerminating` = all three legs,
    /// under weak fairness + bounded input: (a) the trigger is SF, classified
    /// at the rule's *declared* view (a `Def` trigger over its flat, ref-free
    /// expansion); (b) the Marker witness-coverage match — the declared view
    /// is `audit` and the trigger's body is the canonical negated membership
    /// `¬ is_K(x)` at the trigger's own parameter, naming a class
    /// coverage-equal to `Marker.ty`; (c) the domain is grow-only. The lint
    /// reads no home: `CertifiedTerminating` presumes the action's fires
    /// commit, and a rule whose fires all fail never terminates — `step`
    /// states that hypothesis.
    ///
    /// Leg (b) is recognized *by spelling* (`dynamics::negated_membership`),
    /// so an equivalent trigger written otherwise is simply not certified,
    /// and a rule declared at `active` or `default` fails the leg whatever it
    /// spells; a `Nullify` rule fails it *by action*, whatever the trigger's
    /// stability (`Uncertified`, divergence-monitored).
    ///
    /// # Errors
    ///
    /// A malformed rule returns the same typed [`RuleError`] `register_rule`
    /// would, in the same order of precedence.
    pub fn certify_rule(&self, rule: &Rule) -> Result<RuleCertification, RuleError> {
        let Validated { domain, trigger, flat_expansion } = self.validate_rule(rule)?;
        // Leg (a): trigger ∈ SF at the declared view.
        let analyzer = Analyzer::new(&self.catalog, rule.view);
        let sf = analyzer.term(&flat_expansion).sf;
        // Leg (b): the Marker pattern — the emitted tuple's slot-coverage is
        // exactly the witness the trigger's negated membership names
        // (canonical: trigger ¬is_K(a) @ audit ⟺ Marker{_, K}). The spelling
        // is the analyzer's to recognize; the class comparison is the rule
        // engine's, which alone knows what the action emits.
        let marker = match &rule.action {
            FireAction::Marker { ty, .. } => {
                let param = trigger.param().0;
                rule.view == View::Audit
                    && negated_membership(&flat_expansion, param).is_some_and(|witness_ty| {
                        self.catalog.class_of(witness_ty) == self.catalog.class_of(ty)
                    })
            }
            FireAction::Nullify { .. } => false,
        };
        // Leg (c): grow-only domain.
        let grow_only = analyzer.dom(domain.as_dom()).grow_only;
        if sf && marker && grow_only {
            Ok(RuleCertification::CertifiedTerminating)
        } else {
            Ok(RuleCertification::Uncertified { sf, marker, grow_only })
        }
    }

    /// Runs the one shared validation path (§Internal 5) over `rule`.
    ///
    /// It covers domain → `TypedDom`, trigger checks, domain↔trigger sort
    /// reconciliation, Marker guards — and the trigger's flat expansion,
    /// built here where the budget admits it and handed on in [`Validated`].
    ///
    /// # Errors
    ///
    /// The rejections [`Coordinator::register_rule`] states, in its order.
    fn validate_rule(&self, rule: &Rule) -> Result<Validated, RuleError> {
        // Domain: checked + Reg-expanded (a body-level Reg is legitimate PL;
        // a bare Reg is `MisplacedReg`), closed (binds only its own
        // variables).
        let cd = self.check_closed_dom(&rule.domain).map_err(RuleError::IllFormedDomain)?;
        if !cd.is_ref_free() {
            return Err(RuleError::RefBearingDomain);
        }
        let elem_sort = cd.elem_sort();
        // Trigger: one-parameter Bool (a `TriggerTerm` is that by type; a
        // def is checked here and captured into one), sort-matched to the
        // element sort — and its flat ref-free expansion, which an `Inline`
        // trigger's evaluable projection already is (a shallow node copy: the
        // children are `Arc`s).
        let (trigger, flat_expansion) = match &rule.trigger {
            Trigger::Inline(t) => {
                if !t.is_ref_free() {
                    return Err(RuleError::RefBearingInlineTrigger);
                }
                let s = t.param().1;
                if s != elem_sort {
                    return Err(RuleError::DomainTriggerSortMismatch {
                        expected: elem_sort,
                        found: s,
                    });
                }
                (t.clone(), t.evaluable().clone())
            }
            Trigger::Def(addr) => {
                let DefStatus::Defined(def) = self.def_status(addr) else {
                    return Err(RuleError::UndefinedDefTrigger(addr.clone()));
                };
                if def.params().len() != 1 {
                    return Err(RuleError::BadTriggerArity);
                }
                if def.result_sort() != Sort::Bool {
                    return Err(RuleError::TriggerNotBoolean);
                }
                let s = def.params()[0].1;
                if s != elem_sort {
                    // A Def signature is Codom-only, so a Tup domain lands
                    // here — the remediation is an Inline trigger.
                    return Err(RuleError::DomainTriggerSortMismatch {
                        expected: elem_sort,
                        found: s,
                    });
                }
                // The expansion door: the flat tree the lint and the armer
                // graph read must fit the node budget, decided here — over
                // immutable referents, so decided once — and the tree itself
                // handed on, so no later pass re-derives it or has to argue
                // that it fits.
                let flat_expansion = self
                    .expand_def(&def)
                    .map_err(|_| RuleError::TriggerExpansionTooLarge)?;
                (TriggerTerm::new(def), flat_expansion)
            }
        };
        // Marker shape: cataloged Unary (BadMarkerType), idem⊤
        // (NonIdemMarkerType — the gap dedup-absorption and Q3/I1a lean on
        // it), non-PredLayer (PredLayerMarkerType — PR-DISC's in-module
        // route closed).
        if let FireAction::Marker { ty, .. } = &rule.action {
            let Some(entry) = self.catalog.get(ty) else {
                return Err(RuleError::BadMarkerType(ty.clone()));
            };
            if !entry.is_unary() {
                return Err(RuleError::BadMarkerType(ty.clone()));
            }
            if !entry.is_idem() {
                return Err(RuleError::NonIdemMarkerType(ty.clone()));
            }
            if self.catalog.is_pred_layer(&entry.class) {
                return Err(RuleError::PredLayerMarkerType(ty.clone()));
            }
        }
        Ok(Validated { domain: TypedDom(cd.into_dom()), trigger, flat_expansion })
    }

    // ─────────────────────── enumeration & triggers ───────────────────────

    /// Returns `[D_ρ]_snap`: the stored `TypedDom` enumerated off `snap`.
    ///
    /// It is evaluated at the *rule's* declared view (a `default`-view rule
    /// never fires on UV-hidden arguments); finite by QD-fin. Enumerated
    /// through the look at guest class (PUB-6.28): a tuple homed in a private
    /// draft seeds no domain — a rule whose only matching tuples are
    /// draft-homed has an empty visible domain and reports as a rule with no
    /// matching tuple does (`next_enabled` → `None`, `step` → `Quiescent`).
    fn enum_rule_dom(&self, rule: &CheckedRule, snap: &Snapshot<W>) -> Vec<Arg> {
        let cx = self.eval_ctx(snap.world(), rule.view, None);
        enum_dom(&cx, &Env::empty(), rule.domain.as_dom())
    }

    /// Returns `T_ρ(x, snap)` at the rule's view, `x` bound to `arg`.
    ///
    /// It is read through the look at guest class (PUB-6.28) — the captured
    /// trigger body with its one parameter bound to `arg`, referents (a `Def`
    /// trigger's) resolved through the memo — so a draft-homed tuple
    /// satisfies no trigger's pattern and a fire's verdict never turns on a
    /// document hidden from the guest class (PUB's model rule 4,
    /// PUB-1.13–1.16). Reads nothing but `snap`: the body is immutable content
    /// captured at registration, so any snapshot serves.
    fn trigger_true(&self, rule: &CheckedRule, arg: &Arg, snap: &Snapshot<W>) -> bool {
        let cx = self.eval_ctx(snap.world(), rule.view, Some(self));
        let env = Env::empty().bind(rule.trigger.param().0, Value::from(arg.clone()));
        as_bool(eval_term(&cx, &env, rule.trigger.evaluable()))
    }

    /// Returns the rule's first *enabled* occurrence at `snap`.
    ///
    /// Only the arguments `keep` admits count: `[D_ρ]` in enumeration order,
    /// the first whose trigger holds — the one statement of "enabled"
    /// (ASN-0133). The peek asks it (`next_enabled`/`quiescent`, and `step`
    /// through `next_pick`'s rotation), `quiescent_scoped` filters it by
    /// scope, and `fire` asks it again at its own snapshot, narrowed to one
    /// element — so the peek and the fire answer the same question, and
    /// `NoOp` means exactly "enabled at the peek, not at the fire". `keep` is
    /// asked first, so an argument it rejects costs no trigger evaluation.
    fn first_enabled(
        &self,
        rule: &CheckedRule,
        snap: &Snapshot<W>,
        keep: impl Fn(&Arg) -> bool,
    ) -> Option<Arg> {
        self.enum_rule_dom(rule, snap)
            .into_iter()
            .find(|arg| keep(arg) && self.trigger_true(rule, arg, snap))
    }

    /// Returns the rule's pick on its `step` turn.
    ///
    /// It is the agenda's rotation within one rule (§7): its first *enabled*
    /// argument past the one its last turn picked (`first_enabled`, narrowed
    /// to keys greater than `last_pick`), wrapping to its first enabled
    /// argument at or before that key when none lies past. So a rule's turns
    /// cycle through its own enabled occurrences, and
    /// one whose fire leaves it enabled — a `Failed`, or a `Deduped` under a
    /// trigger its action does not falsify — cannot hold its rule's later
    /// arguments back. `None` exactly when the rule has no enabled occurrence
    /// at `snap`: the wrap admits every argument the first scan does not, and
    /// both scans read `snap`.
    fn next_pick(&self, rule: &CheckedRule, snap: &Snapshot<W>) -> Option<Arg> {
        let past = |arg: &Arg| rule.last_pick.as_ref().is_none_or(|last| arg.key_addr() > last);
        self.first_enabled(rule, snap, past)
            .or_else(|| self.first_enabled(rule, snap, |arg| !past(arg)))
    }

    // ───────────────────────────── quiescence ─────────────────────────────

    /// Returns Q0 at *one* pinned snapshot: `⋀_{ρ∈R} ∀ x∈[D_ρ] :: ¬T_ρ(x)`.
    ///
    /// It short-circuits on the first enabled occurrence, each conjunct at its
    /// rule's declared view (the heterogeneous-registry detector — no
    /// single-view rewrite needed, one `Snapshot` giving the soundness). Q0
    /// *is* "no rule has an enabled occurrence at `snap`", which is
    /// [`Coordinator::next_enabled`]'s question, so the two answer from one
    /// traversal and cannot come apart.
    pub fn quiescent(&self, snap: &Snapshot<W>) -> bool {
        self.next_enabled(snap).is_none()
    }

    /// Returns Q7, scoped quiescence, at `snap` under `scope` and `body`.
    ///
    /// `scope` is a one-`Addr`-parameter Bool ref-free `TypedTerm`, checked
    /// as a precondition. The verdict is *exact* iff every scoped rule's
    /// domain element sort matches `body`'s required sort (`PerAddress`→Addr;
    /// the three tuple bodies→Tup); sort-incompatible rules are left
    /// *unscoped* (their full `[D_ρ]`) — a strict safe-direction
    /// over-approximation of remaining work, never false quiescence. Exact
    /// per-rule scoping is deferred (Open).
    ///
    /// `scope` is evaluated at `View::Active` against `snap`, each rule's
    /// domain at its own declared view. The scope's view is an open decision
    /// — the design leaves it unstated, the canonical scopes being state-free
    /// address tests — and `active`, the current structural state, is the
    /// conservative default taken here: a caller supplying a state-*reading*
    /// scope observes that choice, and a later settlement would change this
    /// verdict for such a scope.
    ///
    /// Enabledness is the one statement Q0 answers from too — the private
    /// `first_enabled`, behind [`Coordinator::quiescent`] and
    /// [`Coordinator::next_enabled`] — with the scope test as its argument
    /// filter, so a scoped verdict cannot come apart from an unscoped one on
    /// what "enabled" means.
    ///
    /// # Panics
    ///
    /// A violation of the precondition panics, like `decide`: a ref-bearing
    /// `scope`, one binding other than one parameter, a parameter not at
    /// `Addr`, or a codomain other than Bool, each asserted on its own.
    pub fn quiescent_scoped(&self, scope: &TypedTerm, body: ScopeBody, snap: &Snapshot<W>) -> bool {
        // Each conjunct of Q7's "a ref-free one-Addr-parameter Bool
        // TypedTerm" on its own, so a caller who trips one learns which —
        // arity before the parameter is indexed.
        assert!(
            scope.is_ref_free(),
            "quiescent_scoped precondition violated (Q7): the scope is ref-bearing"
        );
        assert!(
            scope.params().len() == 1,
            "quiescent_scoped precondition violated (Q7): the scope binds {} parameters, not 1",
            scope.params().len()
        );
        assert!(
            scope.params()[0].1 == Sort::Addr,
            "quiescent_scoped precondition violated (Q7): the scope's parameter is {:?}, not Addr",
            scope.params()[0].1
        );
        assert!(
            scope.result_sort() == Sort::Bool,
            "quiescent_scoped precondition violated (Q7): the scope's codomain is {:?}, not Bool",
            scope.result_sort()
        );
        let scope_param = scope.params()[0].0;
        // The open scope-view decision the doc states: `active`, the current
        // structural state, as the conservative default.
        let cx = self.eval_ctx(snap.world(), View::Active, None);
        let s_of = |y: Address| -> bool {
            let env = Env::empty().bind(scope_param, Value::Addr(y));
            as_bool(eval_term(&cx, &env, scope.evaluable()))
        };
        // A `None` — the body and the element's shape disagree — leaves the
        // rule unscoped: every one of its arguments counts.
        let counted = |arg: &Arg| body.in_scope(arg, &s_of).unwrap_or(true);
        !self
            .rules
            .iter()
            .any(|rule| self.first_enabled(rule, snap, counted).is_some())
    }

    // ───────────────────────────── the scheduler ─────────────────────────────

    /// Peeks an enabled occurrence `(ρ, x)` at `snap`: a pure candidate query.
    ///
    /// It answers the first rule in registration order with an enabled
    /// argument, and that rule's first enabled argument in its domain's
    /// enumeration order (Tumbler order for an address domain, M7's `observe`
    /// order for a tuple slice). It cannot advance `step`'s rotation, so it
    /// is not itself "fair" (weak fairness is a property of the `&mut self`
    /// `step` loop).
    pub fn next_enabled(&self, snap: &Snapshot<W>) -> Option<Occurrence> {
        self.rules.iter().find_map(|r| {
            self.first_enabled(r, snap, |_| true).map(|arg| Occurrence { rule: r.id, arg })
        })
    }

    /// Fires `(ρ, x)`: re-checks it at a fresh snapshot, then runs the action.
    ///
    /// The fire executor pins a fresh snapshot and asks again there whether
    /// `(ρ, x)` is *enabled* (`first_enabled`, the peek's own question,
    /// narrowed to `x`'s element), two cases answering `NoOp` — `x` out of
    /// `[D_ρ]` (ASN-0133's fire relation is defined only on domain members:
    /// the fairness "removed" discharge, which an `arg` of the other shape
    /// than the rule's domain yields meets by construction), or the trigger
    /// false (Q1, falsified in place); then it runs the action through M7's
    /// gated write path — one emit/nullify per fire, one M2 transaction
    /// (H-ATOM/H-FIN), home checked by M7 (H-HOME → `HomeNotRegistered`,
    /// never a silent skip).
    ///
    /// The membership+trigger check and the deposit are two transactions, and
    /// the outcome is decided by where the address M7 returns stands at
    /// *this* fire's snapshot (§Internal 5): resident there, it is an
    /// incumbent M7 deduped onto — `Deduped`, nothing committed, M7's base
    /// `Seq`; absent, it is `Fired`. Absent concurrency that is exact: a
    /// `Fired` is this fire's fresh deposit and its commit `Seq`. Under
    /// concurrency it errs one way — M7's `emit`/`nullify` report no hit or
    /// miss — so a witness another writer deposits after this fire's snapshot
    /// and before its emit is deduped onto and still reported `Fired`, its
    /// `effect` that writer's tuple and its `seq` M7's base `Seq`; a fresh
    /// deposit is never reported `Deduped`. The divergence count is
    /// recomputed from the store (`fire_count`), so it counts deposits, never
    /// these outcomes.
    ///
    /// **The look at guest class (PUB-6.28).** The domain re-check and the
    /// trigger read M7 through the look at guest class off this fire's own
    /// snapshot — the look `next_enabled`/`step` peeked through — so an
    /// argument whose only witnessing tuple is draft-homed is out of the
    /// visible domain and answers `NoOp` (the removed discharge), never
    /// `DraftBoundary`: the trigger never reaches the action.
    ///
    /// **Precondition.** `occurrence.rule` is a `RuleId` *this* `Coordinator`
    /// minted — ids are per-handle, see [`RuleId`]. An `Occurrence` comes from
    /// this coordinator's own `next_enabled`, or is aimed by hand at a known
    /// rule. An id that *collides* with one this handle minted names that rule
    /// instead and fires *its* action, which is why the id's provenance is the
    /// caller's obligation and not a check.
    ///
    /// # Errors
    ///
    /// Answer order, as built: `NoOp` (out of the visible domain, or trigger
    /// false) → `Err(DraftBoundary(doc))` (the action's home or the argument's
    /// document unreadable at guest class; when both fail, the home is the
    /// document named) → `Err(HomeNotRegistered)` → `Err(Emit | Nullify)`.
    ///
    /// # Panics
    ///
    /// An id naming no rule here is a precondition violation and panics, like
    /// `decide` (`fire_count`, a monitor, answers 0 for the same id — a count,
    /// not a fire).
    pub fn fire(&self, occurrence: &Occurrence) -> Result<FireOutcome, FireError> {
        let rule = self
            .rules
            .iter()
            .find(|r| r.id == occurrence.rule)
            .expect(
                "fire precondition: the RuleId was minted by this Coordinator (ids are per-handle)",
            );
        let snap = self.kernel.snapshot();
        // Enabledness at the fire's own snapshot is the peek's question —
        // `first_enabled` — narrowed to the occurrence's element by the domain
        // element's identity rule (`Arg::same_element`). What it yields is the
        // store's element, never the caller's, so the trigger and the action
        // see what the domain yielded.
        let is_occurrence = |elem: &Arg| elem.same_element(&occurrence.arg);
        let Some(arg) = self.first_enabled(rule, &snap, is_occurrence) else {
            return Ok(FireOutcome::NoOp);
        };
        let arg_addr = arg.key_addr();
        if let Some(doc) = self.draft_boundary(snap.world(), rule.action.home(), arg_addr) {
            return Err(FireError::DraftBoundary(doc));
        }
        // The writer at guest class (PUB-6.28): the fire's idempotency lookup
        // sees only guest-readable incumbents, so a guest-invisible incumbent
        // in a draft cannot absorb a fire as `Deduped`, and a fire commits
        // byte-identically to a world with no drafts. PUB-6.28's three
        // registration conditions are not built.
        let writer = self.link_writer();
        // Rule fires run as `Caller::System`, the in-process automation path:
        // M9 ⟂ M10 — a fire carries no wire principal, and its authority is
        // the rule set the operator registered, not a session. The two actions
        // differ in the write and in M7's error vocabulary, and in nothing
        // else: the gap accounting is one statement over whatever was
        // deposited.
        let deposited = match &rule.action {
            FireAction::Marker { home, ty } => {
                writer.emit(Caller::System, home, &ty.0, arg_addr, &[]).map_err(emit_refusal)
            }
            FireAction::Nullify { home } => {
                writer.nullify(Caller::System, home, arg_addr).map_err(nullify_refusal)
            }
        };
        deposited.map(|(effect, seq)| self.fired_or_deduped(&snap, effect, seq))
    }

    /// Returns the document a fire at guest class may not cross, or `None`.
    ///
    /// This is the *draft boundary*. Both the action's home and the bound
    /// argument's document must be readable at guest class off the fire's own
    /// snapshot, else the fire is refused *before* any deposit — as
    /// `FireError::DraftBoundary`, a `Failed` step through
    /// [`Coordinator::step`], never a silent skip; the home is asked first,
    /// so when both fail it is the document named. An argument with no
    /// document field is judged as itself — as is a document address bound
    /// as the argument. The predicate is therefore consulted on addresses no
    /// gate has established to be registered documents (the home, before
    /// M7's H-HOME), which is why `Coordinator::new` obliges the assembler
    /// to make it *total*.
    ///
    /// This is the boundary, one of the guest class's three applications:
    /// what a verdict sees is `Coordinator::eval_ctx`'s (the look), and what
    /// a deposit's own value-keyed gates see is `Coordinator::link_writer`'s.
    fn draft_boundary(&self, w: &W, home: &Address, arg_addr: &Address) -> Option<Address> {
        let arg_doc = document_of(arg_addr).unwrap_or_else(|| arg_addr.clone());
        for doc in [home, &arg_doc] {
            if !(self.guest)(w, doc) {
                return Some(doc.clone());
            }
        }
        None
    }

    /// Classifies a fire's deposit by where its address stands at `snap`.
    ///
    /// A returned incumbent resident at the fire snapshot is `Deduped`; a
    /// fresh deposit's address is newly minted and absent from it, `Fired`.
    /// The one miscount runs the safe way: a witness another writer deposited
    /// after the snapshot and M7 deduped onto is absent too, and is reported
    /// `Fired` ([`Coordinator::fire`] states it) — never a fresh deposit as
    /// `Deduped`. The divergence count reads the store, not this answer.
    ///
    /// Reads `LinkState` at no visibility class, as the def probes and the
    /// divergence monitor do (`coordinator/defs.rs` enumerates the regime):
    /// the writer runs at guest class, so a returned incumbent is
    /// guest-readable and a fresh mint is absent from this snapshot under
    /// either reading — the discrimination is the same at guest class or at
    /// none.
    fn fired_or_deduped(&self, snap: &Snapshot<W>, effect: Address, seq: Seq) -> FireOutcome {
        if snap.world().links().readlink(&effect).is_some() {
            FireOutcome::Deduped { effect, seq }
        } else {
            FireOutcome::Fired { effect, seq }
        }
    }

    /// Runs one turn of the pick+fire default driver at `snap`.
    ///
    /// The driver is replaceable — the scheduler/violation policy is handed
    /// upward, ASN-0133. It owns the rotation over the agenda (§7) —
    /// round-robin over the rules, and on each rule's turn its first enabled
    /// occurrence past the one that rule's last turn picked, wrapping
    /// (`next_pick`) — and weak fairness is a property of this loop. It is
    /// sufficient to reach and hold quiescence for an all-SF,
    /// extinction-disciplined registry over grow-only domains on bounded input
    /// (ASN-0133 Q6 regime (ii), Q5a): every trigger an SF spelling, and every
    /// rule's own fire falsifying its trigger at the argument it fired (X-DEF)
    /// — the Marker pattern `certify_rule` certifies (Q3). SF alone is not
    /// enough (Q5a): a rule whose fire does not falsify its own trigger — a ⊤
    /// trigger's Marker, say, whose every later turn at a fired argument is a
    /// `Deduped` — stays enabled there, so the registry never reaches
    /// `Quiescent`. Peeks at `snap`; the fire pins its own, so an occurrence
    /// enabled at `snap` and falsified since is `NoOp`, and `Quiescent` means
    /// no rule has an enabled occurrence at `snap`. A fire error surfaces as
    /// `Failed` (never swallowed) and the rotation moves *past* the failing
    /// occurrence — to the next rule now, and on its own rule's next turn to
    /// that rule's next enabled argument — so it starves neither another rule
    /// nor its own rule's later arguments (§7).
    ///
    /// **Caller's obligation**, and the hypothesis the reachability claim
    /// above rests on: re-pin between steps — `step(&kernel.snapshot())` per
    /// iteration, over the kernel this coordinator was built on. A `NoOp`
    /// makes *no* progress toward `quiescent(snap)`: the peek reads `snap` and
    /// only the fire reads the present, so an occurrence the fire itself
    /// falsified is still enabled *at* `snap`. A driver that pins once and
    /// loops on the stale snapshot therefore gets at most one fire per
    /// occurrence enabled at it and then `NoOp` forever, with
    /// `quiescent(&snap)` false forever — no concurrent writer needed, the
    /// rule's own deposit being what falsifies it.
    ///
    /// The claim has a *second* hypothesis: every fire the loop attempts
    /// commits or dedups. A `Failed` changes nothing — the occurrence stays
    /// enabled and comes round again — so a rule that fails every fire
    /// (`HomeNotRegistered`, or `DraftBoundary` on its home or on an
    /// argument's document) keeps the registry from `Quiescent` however it
    /// certifies, until the caller repairs it ([`StepOutcome::Failed`]).
    pub fn step(&mut self, snap: &Snapshot<W>) -> StepOutcome {
        let n = self.rules.len();
        if n == 0 {
            return StepOutcome::Quiescent;
        }
        for i in 0..n {
            let idx = (self.cursor + i) % n;
            let Some(arg) = self.next_pick(&self.rules[idx], snap) else {
                continue;
            };
            let id = self.rules[idx].id;
            self.cursor = (idx + 1) % n; // rotate past the rule, success or failure …
            // The outcome reports the bookkeeping key, not the bound value —
            // owned here, the argument itself moving into the occurrence.
            let arg_addr = arg.key_addr().clone();
            // … and, on the rule's next turn, past the occurrence (§7).
            self.rules[idx].last_pick = Some(arg_addr.clone());
            let occurrence = Occurrence { rule: id, arg };
            return match self.fire(&occurrence) {
                Ok(FireOutcome::Fired { effect, seq }) => {
                    StepOutcome::Fired { rule: id, arg: arg_addr, effect, seq }
                }
                Ok(FireOutcome::Deduped { effect, seq }) => {
                    StepOutcome::Deduped { rule: id, arg: arg_addr, effect, seq }
                }
                Ok(FireOutcome::NoOp) => StepOutcome::NoOp,
                Err(err) => StepOutcome::Failed { rule: id, arg: arg_addr, err },
            };
        }
        StepOutcome::Quiescent
    }

    // ─────────────────── divergence backstop & armer graph ───────────────────

    /// Returns the per-`(ρ, x)` fire count, recomputed from M7's audit slices.
    ///
    /// The slices are journal-recovered, and the count is taken under §8's
    /// attribution key — `(ty coverage-class, home, F = {x})` for Marker,
    /// `([R], retracting home, G = {x})` for Nullify. The key *collides*
    /// across rules sharing `(ty, home)` and with non-rule same-type writers,
    /// so the recompute *over*-counts only (never under-counts a genuine rule
    /// fire): count > 1 flags misbehavior for investigation — it does not
    /// certify it, and must never drive an automated kill. For a `Tup`-domain
    /// rule the key is the bound tuple's `t.addr`. A `RuleId` this handle did
    /// not mint counts 0 when it names no rule here, and counts the *local*
    /// rule's attribution key when it collides with one this handle minted —
    /// ids are per-handle ([`RuleId`]). The count is as of a snapshot pinned
    /// at the call, never a caller's.
    ///
    /// Reads `LinkState` at no visibility class, where every verdict reads
    /// through the look at guest class: the attribution key pins the home to
    /// the rule's own action home, and a fire into a home the guest class
    /// hides deposits nothing (`FireError::DraftBoundary`), so the look would
    /// drop no tuple of the rule's own fires — only another writer's at the
    /// key, homed where the guest class cannot see, which is part of the
    /// over-count above and is counted with the rest: an operator looking for
    /// a runaway wants every tuple the journal recovered.
    pub fn fire_count(&self, id: RuleId, x: &Address) -> u64 {
        let Some(rule) = self.rules.iter().find(|r| r.id == id) else {
            return 0;
        };
        let snap = self.kernel.snapshot();
        let links = snap.world().links();
        // "This slot denotes `a` and nothing else" — M7's own test, the one
        // `GuestLinks::target_of` applies, so the attribution key's exactness
        // is asked one way in both reads that ask it. It reads the slot as a
        // set, so a slot spelling `a` twice still keys on `{a}`: the
        // recompute over-counts, as its contract above says, and never
        // under-counts.
        let exact = |e: &Endset, a: &Address| -> bool { e.single_denoted() == Some(a.tumbler()) };
        match &rule.action {
            FireAction::Marker { home, ty } => links
                .observe(
                    &ty.0,
                    Pattern { from: from_ref(x.tumbler()), to: &[] },
                    View::Audit,
                )
                .iter()
                .filter(|t| {
                    exact(&t.from, x) && document_of(&t.addr).is_some_and(|d| d == *home)
                })
                .count() as u64,
            FireAction::Nullify { home } => links
                .observe(
                    self.catalog.reserved_type(ShippedType::Retraction),
                    Pattern {
                        from: from_ref(home.tumbler()),
                        to: from_ref(x.tumbler()),
                    },
                    View::Audit,
                )
                .iter()
                .filter(|t| exact(&t.from, home) && exact(&t.to, x))
                .count() as u64,
        }
    }

    /// Returns the static cyclic-coupling warning (§8): armer-graph cycles.
    ///
    /// The armer graph has an edge `ρ → ρ'` when ρ's emitted class lies in
    /// `footprint(T_ρ')` (a Nullify emission is `[R]`-classed and additionally
    /// arms any active-reading trigger — retraction shrinks active slices; a
    /// home-frontier footprint is armed by any deposit). Reads each trigger's
    /// footprint as recorded at registration, from the flat expansion
    /// admitted there. Returns the non-trivial strongly-connected components
    /// (a cycle of non-SF rules is a divergence risk; SF immunity breaks the
    /// cycle), each ascending by `RuleId`, the components ordered by their
    /// least member.
    pub fn armer_cycles(&self) -> Vec<Vec<RuleId>> {
        let n = self.rules.len();
        if n == 0 {
            return Vec::new();
        }
        // What each rule's fire deposits — the rule engine's knowledge, since
        // only it knows what an action emits; the edge rule itself is
        // `Footprint::armed_by`'s, which alone knows what a term reads, over
        // the footprint recorded at registration.
        let emitted: Vec<Emission> = self
            .rules
            .iter()
            .map(|r| match &r.action {
                FireAction::Marker { ty, .. } => Emission::Marker(self.catalog.class_of(ty).clone()),
                FireAction::Nullify { .. } => {
                    Emission::Retraction(self.catalog.retraction_class().clone())
                }
            })
            .collect();
        let edges: Vec<Vec<usize>> = (0..n)
            .map(|i| {
                (0..n)
                    .filter(|&j| self.rules[j].trigger_footprint.armed_by(&emitted[i]))
                    .collect()
            })
            .collect();
        tarjan_nontrivial_sccs(&edges)
            .into_iter()
            .map(|scc| scc.into_iter().map(|i| self.rules[i].id).collect())
            .collect()
    }
}

/// Returns M7's refusal of a Marker fire's emit in the fire's own vocabulary.
///
/// H-HOME is hoisted to [`FireError::HomeNotRegistered`] — never a silent
/// skip — and every other rejection carried whole.
fn emit_refusal(err: TxnError<EmitError>) -> FireError {
    match err {
        TxnError::Rejected(EmitError::HomeNotRegistered) => FireError::HomeNotRegistered,
        other => FireError::Emit(other),
    }
}

/// Returns M7's refusal of a Nullify fire in the fire's own vocabulary.
///
/// H-HOME is hoisted as [`emit_refusal`] hoists it.
fn nullify_refusal(err: TxnError<NullifyError>) -> FireError {
    match err {
        TxnError::Rejected(NullifyError::HomeNotRegistered) => FireError::HomeNotRegistered,
        other => FireError::Nullify(other),
    }
}

/// Returns the graph's strongly connected components that are cycles.
///
/// The components are found by Tarjan SCC, keeping those that are cycles
/// (size > 1, or a self-loop).
///
/// # Panics
///
/// Panics on an edge naming a node at or past `edges.len()`.
fn tarjan_nontrivial_sccs(edges: &[Vec<usize>]) -> Vec<Vec<usize>> {
    struct St<'a> {
        edges: &'a [Vec<usize>],
        index: Vec<Option<usize>>,
        low: Vec<usize>,
        on_stack: Vec<bool>,
        stack: Vec<usize>,
        next: usize,
        out: Vec<Vec<usize>>,
    }
    fn visit(s: &mut St<'_>, v: usize) {
        s.index[v] = Some(s.next);
        s.low[v] = s.next;
        s.next += 1;
        s.stack.push(v);
        s.on_stack[v] = true;
        // `edges` is a shared slice, so walking it borrows nothing of `s`.
        let edges = s.edges;
        for &w in &edges[v] {
            match s.index[w] {
                None => {
                    visit(s, w);
                    s.low[v] = s.low[v].min(s.low[w]);
                }
                Some(iw) => {
                    if s.on_stack[w] {
                        s.low[v] = s.low[v].min(iw);
                    }
                }
            }
        }
        if s.low[v] == s.index[v].expect("visited") {
            let mut scc = Vec::new();
            loop {
                let w = s.stack.pop().expect("stack nonempty in SCC pop");
                s.on_stack[w] = false;
                scc.push(w);
                if w == v {
                    break;
                }
            }
            scc.sort_unstable();
            let self_loop = scc.len() == 1 && s.edges[scc[0]].contains(&scc[0]);
            if scc.len() > 1 || self_loop {
                s.out.push(scc);
            }
        }
    }
    let n = edges.len();
    let mut st = St {
        edges,
        index: vec![None; n],
        low: vec![0; n],
        on_stack: vec![false; n],
        stack: Vec::new(),
        next: 0,
        out: Vec::new(),
    };
    for v in 0..n {
        if st.index[v].is_none() {
            visit(&mut st, v);
        }
    }
    st.out.sort();
    st.out
}
