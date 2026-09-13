//! §C / §Internal 5–8 — the reactive rule engine: registration validation
//! (the one shared path `certify_rule` re-runs), Q0/Q7 quiescence detection,
//! the peek/fire/step scheduler (weak fairness lives in `step`'s rotation),
//! the SF+Marker+grow-only lint, the journal-recomputed divergence backstop,
//! and the static armer-cycle warning.

use std::slice;
use std::sync::Arc;

use skep_address::{document_of, Address};
use skep_kernel::{Seq, Snapshot, TxnError};
use skep_links::{Caller, EmitError, Endset, NullifyError, Pattern, Shape, ShippedType, View};

use crate::ast::Term;
use crate::check::{Checker, Ctx, TypedTerm};
use crate::coordinator::Coordinator;
use crate::dynamics::{negated_membership, Analyzer, Footprint};
use crate::error::{FireError, RuleError};
use crate::eval::{as_bool, enum_dom, eval_term, lift};
use crate::memo::DefStatus;
use crate::rule::{
    Arg, CheckedRule, FireAction, FireOutcome, Occurrence, Rule, RuleCertification, RuleId,
    ScopeBody, StepOutcome, Trigger, TypedDom,
};
use crate::value::{Env, Sort, Value};
use crate::CoordinationWorld;

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
        let (dom, trigger) = self.validate_rule(&rule)?;
        let id = RuleId(self.next_rule_id);
        self.next_rule_id += 1;
        self.rules.push(CheckedRule { id, dom, trigger, view: rule.view, action: rule.action });
        Ok(id)
    }

    /// SF + Marker + grow-only lint (§8). INPUT CONTRACT: takes the RAW
    /// submission and RE-RUNS `register_rule`'s normalization internally (the
    /// one shared validation path), then lints the CHECKED artifacts; a
    /// malformed rule returns the same typed [`RuleError`] `register_rule`
    /// would, in the same order of precedence. Callable pre-registration;
    /// a query — registers nothing. `CertifiedTerminating` = SF trigger
    /// (classified at the rule's declared view; a `Def` trigger over its
    /// flat, ref-free expansion) + Marker witness-coverage match + grow-only
    /// domain, under weak fairness + bounded input; a `Nullify` rule always
    /// fails the marker leg (`Uncertified`, divergence-monitored).
    pub fn certify_rule(&self, rule: &Rule) -> Result<RuleCertification, RuleError> {
        let (dom, trigger) = self.validate_rule(rule)?;
        // Leg (a): trigger ∈ SF at the declared view.
        let flat = self.trigger_expansion(&trigger);
        let analyzer = Analyzer { catalog: &self.catalog, view: rule.view, widen: false };
        let sf = analyzer.term(&flat).sf;
        // Leg (b): the Marker pattern — the emitted tuple's slot-coverage is
        // exactly the witness the trigger's negated membership names
        // (canonical: trigger ¬is_K(a) @ audit ⟺ Marker{_, K}). The spelling
        // is the analyzer's to recognize; the class comparison is this
        // engine's, which alone knows what the action emits.
        let marker = match &rule.action {
            FireAction::Marker { ty, .. } => {
                rule.view == View::Audit
                    && negated_membership(&flat, trigger.params()[0].0).is_some_and(|witness| {
                        self.catalog.class_of(witness) == self.catalog.class_of(ty)
                    })
            }
            FireAction::Nullify { .. } => false,
        };
        // Leg (c): grow-only domain.
        let grow_only = analyzer.dom(dom.as_dom()).grow_only;
        if sf && marker && grow_only {
            Ok(RuleCertification::CertifiedTerminating)
        } else {
            Ok(RuleCertification::Uncertified { sf, marker, grow_only })
        }
    }

    /// A checked trigger as the static analyses read it: its flat, ref-free
    /// expansion — an `Inline` trigger's evaluable projection is already
    /// one; a `Def` trigger's is `expand_def`'s, which `validate_rule` ran
    /// against the same immutable referents and the same node budget before
    /// the trigger was captured, so it cannot exceed it here.
    fn trigger_expansion(&self, trigger: &TypedTerm) -> Term {
        if trigger.is_ref_free() {
            trigger.evaluable.as_ref().clone()
        } else {
            self.expand_def(trigger).expect(
                "a validated Def trigger expands within MAX_TERM_NODES — validate_rule checked it \
                 against the same immutable referents",
            )
        }
    }

    /// The one shared validation path (§Internal 5): domain → `TypedDom`,
    /// trigger checks, domain↔trigger sort reconciliation, Marker guards.
    fn validate_rule(&self, rule: &Rule) -> Result<(TypedDom, Arc<TypedTerm>), RuleError> {
        // Domain: checked + Reg-expanded (a body-level Reg is legitimate PL;
        // a BARE Reg fails the sort check), closed (binds only its own
        // variables).
        let resolve = |a: &Address, d: u32| self.resolve_def_at(a, d);
        let checker = Checker::new(&self.catalog, &resolve);
        let cd = checker
            .check_dom(&Ctx::new(), &rule.domain, 0)
            .map_err(RuleError::IllFormedDomain)?;
        if !cd.ref_free {
            return Err(RuleError::RefBearingDomain);
        }
        let elem = cd.elem;
        // Trigger: one-parameter Bool (a `TriggerTerm` is that by type; a
        // def is checked here), sort-matched to the element sort.
        let trigger = match &rule.trigger {
            Trigger::Inline(t) => {
                if !t.is_ref_free() {
                    return Err(RuleError::RefBearingInlineTrigger);
                }
                let (_, s) = t.param();
                if *s != elem {
                    return Err(RuleError::DomainTriggerSortMismatch { expected: elem, found: *s });
                }
                Arc::clone(t.checked())
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
                // immutable referents, so decided once — and never again.
                self.expand_def(&def).map_err(|_| RuleError::TriggerExpansionTooLarge)?;
                def
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
            if entry.reg.shape != Shape::Unary {
                return Err(RuleError::BadMarkerType(ty.clone()));
            }
            if !entry.reg.idem {
                return Err(RuleError::NonIdemMarkerType(ty.clone()));
            }
            if entry.class == self.catalog.pred_def_class || entry.class == self.catalog.pred_stable_class
            {
                return Err(RuleError::PredLayerMarkerType(ty.clone()));
            }
        }
        Ok((TypedDom(cd.dom), trigger))
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
        enum_dom(&cx, &Env::empty(), rule.dom.as_dom())
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

    fn first_enabled(&self, rule: &CheckedRule, snap: &Snapshot<W>) -> Option<Arg> {
        self.enum_rule_dom(rule, snap)
            .into_iter()
            .find(|e| self.trigger_true(rule, e, snap))
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
        // OPEN DECISION: the design leaves the scope predicate's evaluation
        // view unstated (the canonical scopes are state-free address tests);
        // Active — the current structural state — is taken as the
        // conservative default.
        let cx = self.eval_ctx(snap.world(), View::Active, None);
        let s_of = |y: &Address| -> bool {
            let env = Env::empty().bind(scope_param, Value::Addr(y.clone()));
            as_bool(eval_term(&cx, &env, scope.evaluable.as_ref()))
        };
        for rule in &self.rules {
            for e in self.enum_rule_dom(rule, snap) {
                if in_scope(body, &e, &s_of) == Some(false) {
                    continue;
                }
                if self.trigger_true(rule, &e, snap) {
                    return false;
                }
            }
        }
        true
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
            self.first_enabled(r, snap).map(|arg| Occurrence { rule: r.id, arg })
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
        let arg = {
            let elems = self.enum_rule_dom(rule, &snap);
            match &occurrence.arg {
                Arg::Addr(a) => elems.into_iter().find(|x| matches!(x, Arg::Addr(b) if b == a)),
                // Tuple membership keys on the tuple's address (R1
                // AddressInjectivity: an address hit is a value hit).
                Arg::Tuple(t) => {
                    elems.into_iter().find(|x| matches!(x, Arg::Tuple(u) if u.addr == t.addr))
                }
            }
        };
        let Some(arg) = arg else {
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
            let home = match &rule.action {
                FireAction::Marker { home, .. } | FireAction::Nullify { home } => home,
            };
            let arg_doc = document_of(&a).unwrap_or_else(|| a.clone());
            for d in [home, &arg_doc] {
                if !(self.guest)(w, d) {
                    return Err(FireError::DraftBoundary(d.clone()));
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
        // not a session.
        match &rule.action {
            FireAction::Marker { home, ty } => {
                match writer.emit(Caller::System, home, &ty.0, &a, &[]) {
                    Ok((effect, seq)) => Ok(self.fired_or_deduped(&snap, effect, seq)),
                    Err(TxnError::Rejected(EmitError::HomeNotRegistered)) => {
                        Err(FireError::HomeNotRegistered)
                    }
                    Err(err) => Err(FireError::Emit(err)),
                }
            }
            FireAction::Nullify { home } => match writer.nullify(Caller::System, home, &a) {
                Ok((effect, seq)) => Ok(self.fired_or_deduped(&snap, effect, seq)),
                Err(TxnError::Rejected(NullifyError::HomeNotRegistered)) => {
                    Err(FireError::HomeNotRegistered)
                }
                Err(err) => Err(FireError::Nullify(err)),
            },
        }
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
            let (id, enabled) = {
                let rule = &self.rules[idx];
                match self.first_enabled(rule, snap) {
                    Some(e) => (rule.id, e),
                    None => continue,
                }
            };
            self.cursor = (idx + 1) % n; // rotate past, success or failure
            let arg = enabled.key_addr();
            let occurrence = Occurrence { rule: id, arg: enabled };
            return match self.fire(&occurrence) {
                Ok(FireOutcome::Fired { effect, seq }) => {
                    StepOutcome::Fired { rule: id, arg, effect, seq }
                }
                Ok(FireOutcome::Deduped { effect, seq }) => {
                    StepOutcome::Deduped { rule: id, arg, effect, seq }
                }
                Ok(FireOutcome::NoOp) => StepOutcome::NoOp,
                Err(err) => StepOutcome::Failed { rule: id, arg, err },
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
        let exact = |e: &Endset, a: &Address| -> bool {
            let mut it = e.addrs();
            it.next() == Some(a.tumbler()) && it.next().is_none()
        };
        let homed = |link: &Address, home: &Address| -> bool {
            document_of(link).is_some_and(|o| o == *home)
        };
        match &r.action {
            FireAction::Marker { home, ty } => links
                .observe(
                    &ty.0,
                    Pattern { from: slice::from_ref(x.tumbler()), to: &[] },
                    View::Audit,
                )
                .iter()
                .filter(|t| exact(&t.from, x) && homed(&t.addr, home))
                .count() as u64,
            FireAction::Nullify { home } => links
                .observe(
                    self.catalog.reserved_type(ShippedType::Retraction),
                    Pattern {
                        from: slice::from_ref(home.tumbler()),
                        to: slice::from_ref(x.tumbler()),
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
    /// is armed by any deposit). Returns the non-trivial strongly-connected
    /// components (a cycle of non-SF rules is a divergence risk; SF immunity
    /// breaks the cycle), each ascending by `RuleId`, the components ordered
    /// by their least member.
    pub fn armer_cycles(&self) -> Vec<Vec<RuleId>> {
        let n = self.rules.len();
        if n == 0 {
            return Vec::new();
        }
        // Trigger footprints at each rule's declared view.
        let fps: Vec<Footprint> = self
            .rules
            .iter()
            .map(|r| {
                Analyzer { catalog: &self.catalog, view: r.view, widen: false }
                    .term(&self.trigger_expansion(&r.trigger))
                    .fp
            })
            .collect();
        let emitted: Vec<_> = self
            .rules
            .iter()
            .map(|r| match &r.action {
                FireAction::Marker { ty, .. } => self.catalog.class_of(ty).clone(),
                FireAction::Nullify { .. } => self.catalog.retraction_class.clone(),
            })
            .collect();
        let arms = |i: usize, j: usize| -> bool {
            let (fp, emitted) = (&fps[j], &emitted[i]);
            // The footprint answers for its own slices; the retraction edge is
            // this loop's, since only it knows which class an action emits.
            fp.armed_by(emitted)
                || (*emitted == self.catalog.retraction_class && fp.retraction_shrinks())
        };
        let edges: Vec<Vec<usize>> =
            (0..n).map(|i| (0..n).filter(|&j| arms(i, j)).collect()).collect();
        tarjan_nontrivial_sccs(&edges)
            .into_iter()
            .map(|scc| scc.into_iter().map(|i| self.rules[i].id).collect())
            .collect()
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
