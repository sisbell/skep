//! §C / §Internal 5–8 — the reactive rule engine: registration validation
//! (the one shared path `certify_rule` re-runs), Q0/Q7 quiescence detection,
//! the peek/fire/step scheduler (weak fairness lives in `step`'s rotation),
//! the SF+Marker+grow-only lint, the journal-recomputed divergence backstop,
//! and the static armer-cycle warning.

use std::slice::from_ref;
use std::sync::Arc;

use skep_address::{document_of, Address};
use skep_kernel::{Seq, Snapshot, TxnError};
use skep_links::{Caller, EmitError, Endset, NullifyError, Pattern, Shape, ShippedType, View};

use crate::ast::Term;
use crate::check::{Checker, Ctx, TypedTerm};
use crate::coordinator::Coordinator;
use crate::dynamics::{negated_membership, Analyzer, Emission};
use crate::error::{FireError, RuleError};
use crate::eval::{as_bool, enum_dom, eval_term};
use crate::memo::DefStatus;
use crate::rule::{
    CheckedRule, FireAction, FireOutcome, Occurrence, Rule, RuleCertification, RuleId, ScopeBody,
    StepOutcome, Trigger, TypedDom,
};
use crate::value::{lift, Arg, Env, Sort, Value};
use crate::CoordinationWorld;

/// What `validate_rule` decides once, for both of its callers: the checked
/// domain, the captured trigger, and the trigger's FLAT ref-free expansion —
/// the tree the termination lint and the armer graph read. The expansion is
/// built where the node budget admits it
/// (`RuleError::TriggerExpansionTooLarge`) and handed on, so no later pass
/// re-derives it or has to argue that it fits.
struct Validated {
    domain: TypedDom,
    trigger: Arc<TypedTerm>,
    flat_expansion: Term,
}

impl<W: CoordinationWorld> Coordinator<W> {
    // ─────────────────── registration & the shared validation ───────────────────

    /// Validate the rule and add it to the working set (each failure a typed
    /// [`RuleError`], never a late eval-time panic): the domain is checked
    /// AND normalized through the same WT-domain + `Reg`-expansion pass as
    /// `type_check` and stored as a checked `TypedDom`; the trigger's
    /// parameter sort must equal the domain element sort (a `Tup` domain
    /// requires an `Inline` trigger — a `Def` signature is Codom-only) and a
    /// `Def` trigger's def must be a one-parameter Bool def; a Marker
    /// action's `ty` is a cataloged idem⊤ Unary type that is not a PredLayer
    /// class (PR-DISC's in-module guard). Enforces WELL-FORMEDNESS only, not
    /// termination — apply your own uncertified-rule policy via
    /// [`Coordinator::certify_rule`].
    ///
    /// POSTCONDITION: the rule is in the working set for the life of this
    /// `Coordinator` — the registry is APPEND-ONLY (nothing de-registers, and
    /// a `RuleId` is never reused), so every later `quiescent`,
    /// `next_enabled`, `step`, `fire`, `fire_count` and `armer_cycles`
    /// includes it, and a rule is shed only with its coordinator.
    ///
    /// WHICH REJECTION SPEAKS, when several hold — the domain, then the
    /// trigger, then the action: `IllFormedDomain` (in `type_check`'s walk
    /// order), `RefBearingDomain`; for an `Inline` trigger
    /// `RefBearingInlineTrigger`, `DomainTriggerSortMismatch`; for a `Def`
    /// trigger `DanglingDefTrigger`, `BadTriggerArity`, `TriggerNotBoolean`,
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
        });
        Ok(id)
    }

    /// SF + Marker + grow-only lint (§8). INPUT CONTRACT: takes the RAW
    /// submission and RE-RUNS `register_rule`'s normalization internally (the
    /// one shared validation path), then lints the CHECKED artifacts; a
    /// malformed rule returns the same typed [`RuleError`] `register_rule`
    /// would, in the same order of precedence. Callable pre-registration;
    /// a query — registers nothing. `CertifiedTerminating` = all three legs,
    /// under weak fairness + bounded input: (a) the trigger is SF, classified
    /// at the rule's DECLARED view (a `Def` trigger over its flat, ref-free
    /// expansion); (b) the Marker witness-coverage match — the declared view
    /// is `audit` AND the trigger's body is the canonical negated membership
    /// `¬ is_K(x)` at the trigger's own parameter, naming a class
    /// coverage-equal to `Marker.ty`; (c) the domain is grow-only.
    ///
    /// Leg (b) is recognized BY SPELLING (`dynamics::negated_membership`), so
    /// an equivalent trigger written otherwise is simply not certified, and a
    /// rule declared at `active` or `default` fails the leg whatever it
    /// spells; a `Nullify` rule fails it BY ACTION, whatever the trigger's
    /// stability (`Uncertified`, divergence-monitored).
    pub fn certify_rule(&self, rule: &Rule) -> Result<RuleCertification, RuleError> {
        let Validated { domain, trigger, flat_expansion } = self.validate_rule(rule)?;
        // Leg (a): trigger ∈ SF at the declared view.
        let analyzer = Analyzer::new(&self.catalog, rule.view);
        let sf = analyzer.term(&flat_expansion).sf;
        // Leg (b): the Marker pattern — the emitted tuple's slot-coverage is
        // exactly the witness the trigger's negated membership names
        // (canonical: trigger ¬is_K(a) @ audit ⟺ Marker{_, K}). The spelling
        // is the analyzer's to recognize; the class comparison is this
        // engine's, which alone knows what the action emits.
        let marker = match &rule.action {
            FireAction::Marker { ty, .. } => {
                let param = trigger.params()[0].0;
                rule.view == View::Audit
                    && negated_membership(&flat_expansion, param).is_some_and(|witness| {
                        self.catalog.class_of(witness) == self.catalog.class_of(ty)
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

    /// The one shared validation path (§Internal 5): domain → `TypedDom`,
    /// trigger checks, domain↔trigger sort reconciliation, Marker guards —
    /// and the trigger's flat expansion, built here where the budget admits
    /// it and handed on in [`Validated`].
    fn validate_rule(&self, rule: &Rule) -> Result<Validated, RuleError> {
        // Domain: checked + Reg-expanded (a body-level Reg is legitimate PL;
        // a BARE Reg fails the sort check), closed (binds only its own
        // variables).
        let resolve = |start: &Address, depth: u32| self.resolve_def_at(start, depth);
        let checker = Checker::new(&self.catalog, &resolve);
        let cd = checker
            .check_dom(&Ctx::new(), &rule.domain, 0)
            .map_err(RuleError::IllFormedDomain)?;
        if !cd.ref_free {
            return Err(RuleError::RefBearingDomain);
        }
        let elem = cd.elem;
        // Trigger: one-parameter Bool (a `TriggerTerm` is that by type; a
        // def is checked here), sort-matched to the element sort — and its
        // FLAT ref-free expansion, which an `Inline` trigger's evaluable
        // projection already is (a shallow node copy: the children are
        // `Arc`s).
        let (trigger, flat_expansion) = match &rule.trigger {
            Trigger::Inline(t) => {
                if !t.is_ref_free() {
                    return Err(RuleError::RefBearingInlineTrigger);
                }
                let (_, s) = t.param();
                if *s != elem {
                    return Err(RuleError::DomainTriggerSortMismatch { expected: elem, found: *s });
                }
                let checked = Arc::clone(t.checked());
                let flat_expansion = checked.evaluable.as_ref().clone();
                (checked, flat_expansion)
            }
            Trigger::Def(addr) => {
                let DefStatus::Defined(def) = self.def_status(addr) else {
                    return Err(RuleError::DanglingDefTrigger(addr.clone()));
                };
                if def.params().len() != 1 {
                    return Err(RuleError::BadTriggerArity);
                }
                if def.result != Sort::Bool {
                    return Err(RuleError::TriggerNotBoolean);
                }
                let s = def.params()[0].1;
                if s != elem {
                    // A Def signature is Codom-only, so a Tup domain lands
                    // here — the remediation is an Inline trigger.
                    return Err(RuleError::DomainTriggerSortMismatch { expected: elem, found: s });
                }
                // The expansion door: the flat tree the lint and the armer
                // graph read must fit the node budget, decided here — over
                // immutable referents, so decided once — and the tree itself
                // handed on, so no later pass re-derives it or has to argue
                // that it fits.
                let flat_expansion = self
                    .expand_def(&def)
                    .map_err(|_| RuleError::TriggerExpansionTooLarge)?;
                (def, flat_expansion)
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
            if entry.registration.shape != Shape::Unary {
                return Err(RuleError::BadMarkerType(ty.clone()));
            }
            if !entry.registration.idem {
                return Err(RuleError::NonIdemMarkerType(ty.clone()));
            }
            if self.catalog.is_pred_layer(&entry.class) {
                return Err(RuleError::PredLayerMarkerType(ty.clone()));
            }
        }
        Ok(Validated { domain: TypedDom(cd.dom), trigger, flat_expansion })
    }

    // ─────────────────────── enumeration & triggers ───────────────────────

    /// `[D_ρ]_snap` — the stored `TypedDom` evaluated off the snapshot at the
    /// RULE's declared view (a `default`-view rule never fires on UV-hidden
    /// arguments); finite by QD-fin. Enumerated THROUGH THE GUEST-CLASS VIEW
    /// (lane 4.1, PUB-6.28): a tuple homed in a private draft seeds no
    /// domain — a rule whose only matching tuples are draft-homed has an
    /// EMPTY visible domain and reports as a rule with no matching tuple
    /// does today (`next_enabled` → `None`, `step` → `Quiescent`).
    fn enum_rule_dom(&self, rule: &CheckedRule, snap: &Snapshot<W>) -> Vec<Arg> {
        let cx = self.eval_ctx(snap.world(), rule.view, None);
        enum_dom(&cx, &Env::empty(), rule.domain.as_dom())
    }

    /// `T_ρ(x, snap)` at the rule's view, read THROUGH THE GUEST-CLASS VIEW
    /// (lane 4.1, PUB-6.28) — the captured trigger body with its one
    /// parameter bound to `elem`, referents (a `Def` trigger's) resolved
    /// through the memo — so a draft-homed tuple satisfies no trigger's
    /// pattern and a fire's verdict never turns on a document rule 4 hides.
    /// Reads nothing but `snap`: the body is immutable content captured at
    /// registration, so any snapshot serves.
    fn trigger_true(&self, rule: &CheckedRule, arg: &Arg, snap: &Snapshot<W>) -> bool {
        let cx = self.eval_ctx(snap.world(), rule.view, Some(self));
        let env = Env::empty().bind(rule.trigger.params()[0].0, Value::from(arg.clone()));
        as_bool(eval_term(&cx, &env, rule.trigger.evaluable.as_ref()))
    }

    /// The rule's first ENABLED occurrence at `snap` among the arguments
    /// `keep` admits: `[D_ρ]` in enumeration order, the first whose trigger
    /// holds — the ONE statement of "enabled" (ASN-0133), so `step`,
    /// `next_enabled`/`quiescent` and `quiescent_scoped` cannot come apart on
    /// it. `keep` is asked first, so an argument it rejects costs no trigger
    /// evaluation.
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

    // ───────────────────────────── quiescence ─────────────────────────────

    /// Q0: `⋀_{ρ∈R} ∀ x∈[D_ρ] :: ¬T_ρ(x)` at ONE pinned snapshot,
    /// short-circuiting on the first enabled occurrence; each conjunct at its
    /// rule's declared view (the heterogeneous-registry detector — no
    /// single-view rewrite needed, one `Snapshot` giving the soundness). Q0
    /// IS "no rule has an enabled occurrence at `snap`", which is
    /// [`Coordinator::next_enabled`]'s question, so the two answer from one
    /// traversal and cannot come apart.
    pub fn quiescent(&self, snap: &Snapshot<W>) -> bool {
        self.next_enabled(snap).is_none()
    }

    /// Q7 scoped quiescence. `scope`: a one-`Addr`-parameter Bool ref-free
    /// `TypedTerm`, checked as a PRECONDITION (a violation panics, like
    /// `decide`). The verdict is EXACT iff every scoped rule's domain element
    /// sort matches `body`'s required sort (`PerAddress`→Addr; the three
    /// tuple bodies→Tup); sort-incompatible rules are left UNSCOPED (their
    /// full `[D_ρ]`) — a strict safe-direction over-approximation of
    /// remaining work, never false quiescence. Exact per-rule scoping is
    /// deferred (Open).
    ///
    /// `scope` is evaluated at `View::Active` against `snap`, each rule's
    /// domain at its own declared view. The scope's view is an OPEN decision
    /// — the design leaves it unstated, the canonical scopes being state-free
    /// address tests — and `active`, the current structural state, is the
    /// conservative default taken here: a caller supplying a state-READING
    /// scope observes that choice, and a later settlement would change this
    /// verdict for such a scope.
    ///
    /// Enabledness is [`Coordinator::first_enabled`]'s, as Q0's is, with the
    /// scope test as its argument filter — so a scoped verdict cannot come
    /// apart from an unscoped one on what "enabled" means.
    pub fn quiescent_scoped(&self, scope: &TypedTerm, body: ScopeBody, snap: &Snapshot<W>) -> bool {
        assert!(
            scope.is_ref_free()
                && scope.params().len() == 1
                && scope.params()[0].1 == Sort::Addr
                && scope.result_sort() == Sort::Bool,
            "quiescent_scoped precondition violated (Q7): scope must be a ref-free \
             one-Addr-parameter Bool TypedTerm"
        );
        let scope_param = scope.params()[0].0;
        // The OPEN scope-view decision the doc states: `active`, the current
        // structural state, as the conservative default.
        let cx = self.eval_ctx(snap.world(), View::Active, None);
        let s_of = |y: &Address| -> bool {
            let env = Env::empty().bind(scope_param, Value::Addr(y.clone()));
            as_bool(eval_term(&cx, &env, scope.evaluable.as_ref()))
        };
        let scoped = |arg: &Arg| in_scope(body, arg, &s_of) != Some(false);
        !self
            .rules
            .iter()
            .any(|rule| self.first_enabled(rule, snap, scoped).is_some())
    }

    // ───────────────────────────── the scheduler ─────────────────────────────

    /// PEEK an enabled occurrence `(ρ, x)` at `snap` — a pure candidate query:
    /// the first rule in registration order with an enabled argument, and
    /// that rule's first enabled argument in its domain's enumeration order
    /// (Tumbler order for an address domain, M7's `observe` order for a
    /// tuple slice). It cannot advance the rotation cursor, so it is not
    /// itself "fair" (weak fairness is a property of the `&mut self` `step`
    /// loop).
    pub fn next_enabled(&self, snap: &Snapshot<W>) -> Option<Occurrence> {
        self.rules.iter().find_map(|r| {
            self.first_enabled(r, snap, |_| true).map(|arg| Occurrence { rule: r.id, arg })
        })
    }

    /// The fire executor: pin a fresh snapshot; re-check `x ∈ [D_ρ]` (out ⇒
    /// `NoOp` — ASN-0133's fire relation is defined only on domain members;
    /// the fairness "removed" discharge — an `arg` of the other shape than
    /// the rule's domain yields is out of it by construction, and answers
    /// `NoOp` like any other non-member); evaluate the trigger (false ⇒
    /// `NoOp` — Q1 falsified-in-place); then run the action through M7's
    /// gated write path — ONE emit/nullify per fire, one M2 transaction
    /// (H-ATOM/H-FIN), home checked by M7 (H-HOME → `HomeNotRegistered`,
    /// never a silent skip).
    ///
    /// The membership+trigger check and the deposit are TWO transactions; the
    /// gap accounting is exact (§Internal 5): an idem⊤ dedup hit (M7 returned
    /// an incumbent, committed nothing) reports `Deduped`; a fresh deposit
    /// reports `Fired` — discriminated by the fire-snapshot residence of the
    /// returned effect (an incumbent already existed in `snap`). Only `Fired`
    /// advances the divergence count.
    ///
    /// THE LOOK AT GUEST CLASS (lane 4.1, PUB-6.28): the domain re-check and
    /// the trigger read M7 through the guest-class view off this fire's own
    /// snapshot — the same view `next_enabled`/`step` peeked through — so an
    /// argument whose only witnessing tuple is draft-homed is OUT of the
    /// visible domain and answers `NoOp` (the removed discharge), never
    /// `DraftBoundary`: the trigger never reaches the action. Answer order,
    /// as built: `NoOp` (out of the visible domain, or trigger false) →
    /// `Err(DraftBoundary(doc))` (the action's home or the argument's
    /// document unreadable at guest class) → `Err(HomeNotRegistered)` →
    /// `Err(Emit | Nullify)`.
    ///
    /// PRECONDITION: `occurrence.rule` is a `RuleId` this `Coordinator`
    /// registered — an `Occurrence` comes from this coordinator's own
    /// `next_enabled`, or is aimed by hand at a known rule; an unregistered
    /// id is a precondition violation and PANICS, like `decide`
    /// (`fire_count`, a monitor, answers 0 for the same id — a count, not a
    /// fire).
    pub fn fire(&self, occurrence: &Occurrence) -> Result<FireOutcome, FireError> {
        let rule = self
            .rules
            .iter()
            .find(|r| r.id == occurrence.rule)
            .expect("fire precondition: the RuleId is registered with this Coordinator");
        let snap = self.kernel.snapshot();
        // Membership is the domain element's own identity rule
        // (`Arg::same_element`), and what it finds is the STORE's element —
        // never the caller's — so the trigger and the action see what the
        // domain yielded.
        let found = self
            .enum_rule_dom(rule, &snap)
            .into_iter()
            .find(|elem| elem.same_element(&occurrence.arg));
        let Some(arg) = found else {
            return Ok(FireOutcome::NoOp);
        };
        if !self.trigger_true(rule, &arg, &snap) {
            return Ok(FireOutcome::NoOp);
        }
        let a = arg.key_addr();
        // THE GUEST-CLASS FILTER (PUB round 2, lane 3.3, §5): a fire runs at
        // pinned GUEST class — its home and the bound argument's document
        // must both be readable at guest class off the fire's own snapshot,
        // else the fire is refused BEFORE any deposit, as a `Failed` step
        // (never a silent skip). The predicate is the engine's
        // (`World::readable_guest` = `published(doc)`, injected at assembly);
        // a document address bound as the argument is judged as itself.
        //
        // This filter refuses before any deposit; what the deposit's own
        // VALUE-KEYED gates see is governed one step below (lane 3.3b): the
        // writer is built at the same guest class, so a guest-invisible
        // incumbent in a draft cannot absorb a fire as `Deduped` (PUB-6.28).
        // PUB-6.28's three REGISTRATION conditions remain not built.
        {
            let w = snap.world();
            let arg_doc = document_of(a).unwrap_or_else(|| a.clone());
            for doc in [rule.action.home(), &arg_doc] {
                if !(self.guest)(w, doc) {
                    return Err(FireError::DraftBoundary(doc.clone()));
                }
            }
        }
        // The writer at GUEST class (lane 3.3b, PUB-6.28): the fire's
        // idempotency lookup sees only guest-readable incumbents, so a fire
        // commits byte-identically to a world with no drafts.
        let writer = self.link_writer();
        // Rule fires run as `Caller::System` (the ownership ruling's
        // automation path, 2026-08-16): M9 ⟂ M10 — a fire carries no wire
        // principal, and its authority is the operator's certified rule set,
        // not a session. The two actions differ in the write and in M7's
        // error vocabulary, and in nothing else: the gap accounting is one
        // statement over whatever was deposited.
        let deposited = match &rule.action {
            FireAction::Marker { home, ty } => {
                writer.emit(Caller::System, home, &ty.0, a, &[]).map_err(emit_refusal)
            }
            FireAction::Nullify { home } => {
                writer.nullify(Caller::System, home, a).map_err(nullify_refusal)
            }
        };
        deposited.map(|(effect, seq)| self.fired_or_deduped(&snap, effect, seq))
    }

    /// A returned incumbent was already resident at the fire snapshot; a
    /// fresh deposit's address is newly minted and absent from it. Safe
    /// direction under concurrency: at worst a gap-deposited witness is
    /// miscounted as a real fire — the monitor is only a backstop.
    fn fired_or_deduped(&self, snap: &Snapshot<W>, effect: Address, seq: Seq) -> FireOutcome {
        if snap.world().links().readlink(&effect).is_some() {
            FireOutcome::Deduped { effect, seq }
        } else {
            FireOutcome::Fired { effect, seq }
        }
    }

    /// The pick+fire default driver (replaceable — the scheduler/violation
    /// policy is handed upward, ASN-0133). Owns the round-robin rotation over
    /// rules — weak fairness is a property of this loop, sufficient to
    /// reach/hold quiescence for an all-SF, grow-only, bounded-input registry
    /// (Q5a/Q6). Peeks at `snap`; the fire pins its own, so an occurrence
    /// enabled at `snap` and falsified since is `NoOp`, and `Quiescent`
    /// means no rule has an enabled occurrence at `snap`. A fire error
    /// surfaces as `Failed` (never swallowed) and the cursor rotates PAST
    /// the failing occurrence, so it cannot starve the rest of the agenda
    /// (§7).
    pub fn step(&mut self, snap: &Snapshot<W>) -> StepOutcome {
        let n = self.rules.len();
        if n == 0 {
            return StepOutcome::Quiescent;
        }
        for i in 0..n {
            let idx = (self.cursor + i) % n;
            let (id, arg) = {
                let rule = &self.rules[idx];
                match self.first_enabled(rule, snap, |_| true) {
                    Some(arg) => (rule.id, arg),
                    None => continue,
                }
            };
            self.cursor = (idx + 1) % n; // rotate past, success or failure
            // The outcome reports the bookkeeping KEY, not the bound value —
            // owned here, the argument itself moving into the occurrence.
            let a = arg.key_addr().clone();
            let occurrence = Occurrence { rule: id, arg };
            return match self.fire(&occurrence) {
                Ok(FireOutcome::Fired { effect, seq }) => {
                    StepOutcome::Fired { rule: id, arg: a, effect, seq }
                }
                Ok(FireOutcome::Deduped { effect, seq }) => {
                    StepOutcome::Deduped { rule: id, arg: a, effect, seq }
                }
                Ok(FireOutcome::NoOp) => StepOutcome::NoOp,
                Err(err) => StepOutcome::Failed { rule: id, arg: a, err },
            };
        }
        StepOutcome::Quiescent
    }

    // ──────────────────── divergence backstop & armer graph ────────────────────

    /// Per-`(ρ, x)` fire count, recomputed from M7's journal-recovered audit
    /// slices under §8's attribution key — `(ty coverage-class, home,
    /// F = {x})` for Marker, `([R], retracting home, G = {x})` for Nullify.
    /// The key COLLIDES across rules sharing `(ty, home)` and with non-rule
    /// same-type writers, so the recompute OVER-counts only (never
    /// under-counts a genuine rule fire): count > 1 flags misbehavior for
    /// investigation — it does not certify it, and must never drive an
    /// automated kill. For a `Tup`-domain rule the key is the bound tuple's
    /// `t.addr`. An unregistered `RuleId` counts 0. The count is as of a
    /// snapshot pinned at the call — the one read in this group that takes
    /// no caller's snapshot.
    ///
    /// Reads `LinkState` CLASS-FREE, where every verdict reads through the
    /// guest-class view: the attribution key pins the home to the rule's own
    /// action home, and a fire into a home the guest class hides deposits
    /// nothing (`FireError::DraftBoundary`), so no count this recompute can
    /// produce would differ under the filtered view — while an operator
    /// looking for a runaway wants every tuple the journal recovered.
    pub fn fire_count(&self, rule: RuleId, x: &Address) -> u64 {
        let Some(r) = self.rules.iter().find(|r| r.id == rule) else {
            return 0;
        };
        let snap = self.kernel.snapshot();
        let links = snap.world().links();
        // "This slot denotes `a` and nothing else" — M7's own test, the one
        // `GuestLinks::target_of` applies, so the attribution key's exactness
        // is asked the same way everywhere. It reads the slot as a SET, so a
        // slot spelling `a` twice still keys on `{a}`: the recompute
        // over-counts, as its contract above says, and never under-counts.
        let exact = |e: &Endset, a: &Address| -> bool { e.single_denoted() == Some(a.tumbler()) };
        let homed = |link: &Address, home: &Address| -> bool {
            document_of(link).is_some_and(|o| o == *home)
        };
        match &r.action {
            FireAction::Marker { home, ty } => links
                .observe(
                    &ty.0,
                    Pattern { from: from_ref(x.tumbler()), to: &[] },
                    View::Audit,
                )
                .iter()
                .filter(|t| exact(&t.from, x) && homed(&t.addr, home))
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

    /// The static cyclic-coupling warning (§8): the armer graph has an edge
    /// `ρ → ρ'` when ρ's emitted class lies in `footprint(T_ρ')` (a Nullify
    /// emission is `[R]`-classed and additionally arms any active-reading
    /// trigger — retraction shrinks active slices; a home-frontier footprint
    /// is armed by any deposit). Reads each trigger's footprint as recorded at
    /// registration, from the flat expansion admitted there. Returns the
    /// non-trivial strongly-connected components (a cycle of non-SF rules is a
    /// divergence risk; SF immunity breaks the cycle), each ascending by
    /// `RuleId`, the components ordered by their least member.
    pub fn armer_cycles(&self) -> Vec<Vec<RuleId>> {
        let n = self.rules.len();
        if n == 0 {
            return Vec::new();
        }
        // What each rule's fire deposits — the engine's knowledge, since only
        // it knows what an action emits; the edge rule itself is
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

/// M7's refusal of a Marker fire's emit, in the fire's own vocabulary: H-HOME
/// hoisted to [`FireError::HomeNotRegistered`] — never a silent skip — and
/// every other rejection carried whole.
fn emit_refusal(err: TxnError<EmitError>) -> FireError {
    match err {
        TxnError::Rejected(EmitError::HomeNotRegistered) => FireError::HomeNotRegistered,
        other => FireError::Emit(other),
    }
}

/// M7's refusal of a Nullify fire, in the fire's own vocabulary — H-HOME
/// hoisted as [`emit_refusal`] hoists it.
fn nullify_refusal(err: TxnError<NullifyError>) -> FireError {
    match err {
        TxnError::Rejected(NullifyError::HomeNotRegistered) => FireError::HomeNotRegistered,
        other => FireError::Nullify(other),
    }
}

/// β_ρ^S(x) — the four canonical S-positive bodies (Q9): whether the bound
/// argument is in scope, or `None` when the body and the argument's shape
/// disagree (`PerAddress` goes with an address element, the three tuple
/// bodies with a tuple element). A `None` leaves the rule UNSCOPED — its
/// full `[D_ρ]` — a safe over-approximation of remaining work, never false
/// quiescence.
fn in_scope(body: ScopeBody, arg: &Arg, s_of: &dyn Fn(&Address) -> bool) -> Option<bool> {
    match (body, arg) {
        (ScopeBody::PerAddress, Arg::Addr(a)) => Some(s_of(a)),
        (ScopeBody::PerEmitter, Arg::Tuple(t)) => Some(s_of(&t.addr)),
        (ScopeBody::PerTarget, Arg::Tuple(t)) => Some(t.to.addrs().any(|y| s_of(&lift(y)))),
        (ScopeBody::PerSource, Arg::Tuple(t)) => Some(t.from.addrs().any(|y| s_of(&lift(y)))),
        _ => None,
    }
}

/// Tarjan SCC, keeping components that are cycles (size > 1, or a self-loop).
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
