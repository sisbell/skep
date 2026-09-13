//! §Internal 5 — the reactive-rule datatypes: the raw [`Rule`] submission,
//! trigger/action forms, the checked shapes the working set holds
//! ([`CheckedRule`], [`TypedDom`]), the occurrence, and the fire/step outcome
//! types. A rule's bound argument is a PL domain element, so it is
//! [`crate::value::Arg`] — `Occurrence` names it, this module does not
//! declare it.

use std::sync::Arc;

use skep_address::Address;
use skep_kernel::Seq;
use skep_links::View;

use crate::ast::{ArcDom, Dom, TypeKey};
use crate::check::{TriggerTerm, TypedTerm};
use crate::dynamics::Footprint;
use crate::error::FireError;
use crate::value::Arg;

/// One trigger→action rule. `domain` is the RAW submission — `register_rule`
/// checks + `Reg`-expands it into the internal checked `TypedDom` the working
/// set stores (§Internal 5). Comparable in every field, so a harness can pin
/// the submission it built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    pub domain: Dom,
    pub trigger: Trigger,
    pub view: View,
    pub action: FireAction,
}

/// The rule's trigger `T_ρ` — a one-parameter Bool predicate over the domain
/// element sort — as the submission gives it: inline, as a checked
/// `TriggerTerm`, or by the content start of a stored def.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Trigger {
    /// Built via `type_check_trigger` (may bind one `Tup`); MUST be ref-free
    /// (`register_rule` rejects otherwise — `RuleError::RefBearingInlineTrigger`).
    Inline(TriggerTerm),
    /// pdef-backed: the def's checked body is captured at `register_rule`,
    /// so the rule survives the def's later retraction and reads only the
    /// snapshot it is evaluated on. A `Def` signature is Codom-only — it
    /// cannot serve a `Tup` domain.
    Def(Address),
}

/// The single-deposit fire actions v1 ships (H-ATOM/H-FIN by one M7
/// transact).
///
/// `#[non_exhaustive]`: multi-deposit fires are deferred pending M7's
/// `stage_emit`, and arrive as a variant a driver's catch-all should absorb.
/// Construction is unaffected — both variants' fields are public.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FireAction {
    /// Canonical certifiable Marker: emit ONE Unary K-tuple covering the
    /// bound argument `a` at `home`, flipping audit `is_K(a)` false→true.
    /// `ty` must be a cataloged idem⊤ Unary type that is NOT a PredLayer
    /// class (`register_rule` rejects otherwise — PR-DISC).
    Marker { home: Address, ty: TypeKey },
    /// Single retraction: `nullify(home, a)` on the bound argument. NEVER
    /// certifiable: `certify_rule`'s Marker leg is false BY ACTION, whatever
    /// the trigger's stability (a ⊤ trigger is SF and the rule is still
    /// `Uncertified`) — admitted under the uncertified-rule policy with the
    /// divergence monitor as backstop. Documented contract: the domain must
    /// yield RESIDENT LINKS
    /// (tuple-domained, or `Addr`-over-`L_dom`); an `Addr`-over-`M_K` domain
    /// passes `register_rule` but every fire then trips
    /// `FireError::Nullify(Rejected(BadTarget))`.
    Nullify { home: Address },
}

impl FireAction {
    /// The document a fire of this action writes into — the one fact both
    /// variants share: checked against the guest class before any deposit
    /// (`FireError::DraftBoundary`), checked by M7 as the write's home
    /// (H-HOME → `FireError::HomeNotRegistered`), and the home half of the
    /// divergence monitor's attribution key (§8).
    pub fn home(&self) -> &Address {
        match self {
            FireAction::Marker { home, .. } | FireAction::Nullify { home } => home,
        }
    }
}

/// `quiescent_scoped`'s per-rule restriction form (Q7). All four use the
/// scope predicate `S` only positively, so Q9's global⟹scope inference holds
/// by construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeBody {
    PerEmitter,
    PerTarget,
    PerSource,
    PerAddress,
}

/// A registered rule's handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RuleId(pub(crate) u64);

/// A rule domain that passed `check_dom` — the `Dom` analogue of
/// `TypedTerm`'s evaluable projection: every `TypeRef` `Concrete`, no
/// surviving `Reg` binder. A [`Rule`]'s own `domain` is the raw submission;
/// only this shape is ever enumerated, and only `register_rule` can build
/// one, so the working set holds no unchecked domain.
#[derive(Debug, Clone)]
pub(crate) struct TypedDom(pub(crate) ArcDom);

impl TypedDom {
    /// The checked domain, for enumeration (`enum_dom`) and analysis.
    pub(crate) fn as_dom(&self) -> &Dom {
        &self.0
    }
}

/// One registered rule in the working set: the checked domain, the checked
/// trigger, the declared view, the action, and the trigger's footprint —
/// `footprint(T_ρ)`, the reads §8's armer graph asks about, never the rule's
/// writes.
#[derive(Debug, Clone)]
pub(crate) struct CheckedRule {
    pub(crate) id: RuleId,
    pub(crate) dom: TypedDom,
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
    pub(crate) action: FireAction,
    /// FP over the TRIGGER — `footprint(T_ρ)`, the subject §8's edge rule
    /// names — at the rule's DECLARED view, computed once at registration
    /// from the same flat ref-free expansion the node budget admitted there
    /// (`RuleError::TriggerExpansionTooLarge`). What the rule WRITES is the
    /// action's, carried separately as an [`crate::dynamics::Emission`]. A
    /// pure function of immutable inputs — the captured trigger's content,
    /// the frozen catalog, the declared view — so recording it costs nothing
    /// in authority, and the armer graph reads §8's edge rule off it rather
    /// than re-expanding every trigger on every call.
    pub(crate) trigger_footprint: Footprint,
}

/// An occurrence `(ρ, x)`: a rule and a candidate argument. Enabled only
/// relative to a snapshot — `next_enabled` peeks one that is; `fire`
/// re-checks on its own pin and answers `NoOp` if it no longer is. `arg` is
/// `Arg::Addr` for an `Addr`-domain rule, `Arg::Tuple` for a `Tup`-domain
/// rule (the trigger/atom dispatch consumes the whole tuple; only the
/// bookkeeping projects to the address).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Occurrence {
    pub rule: RuleId,
    pub arg: Arg,
}

/// One fire's outcome (§Internal 5, the two-transaction race exactly
/// accounted). Only `Fired` advances the divergence count — a `Deduped`
/// (idem⊤ dedup hit in the trigger-check↔commit gap: M7 committed NOTHING,
/// returned the incumbent) and a `NoOp` (argument out of `[D_ρ]` — removed —
/// or trigger false — falsified — at fire time, Q1) leave no journal record.
///
/// Deliberately exhaustive (no `#[non_exhaustive]`): the three outcomes are
/// closed by the quiescence theory — a fire either commits, is absorbed, or
/// finds nothing to do — and a driver's exhaustive match is what keeps its
/// accounting complete. `#[must_use]` on the type, for the same accounting:
/// a dropped outcome is a fire whose effect nothing recorded.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FireOutcome {
    NoOp,
    Fired { effect: Address, seq: Seq },
    Deduped { effect: Address, seq: Seq },
}

/// One `step`'s outcome. `Fired`/`Deduped` carry `FireOutcome`'s `effect`
/// (the deposited resp. incumbent tuple's address) through, so a driver can
/// reconcile the divergence monitor against the journal without re-deriving
/// the deposited tuple's address. `arg` is the bookkeeping KEY, never the
/// bound value: the bound address for an `Addr`-domain rule, a bound tuple's
/// `t.addr` for a `Tup`-domain one — which is what `fire_count(rule, &arg)`
/// keys on. A fire error surfaces as `Failed` — never a
/// silent swallow — with rotate-past rotation (§7): nothing committed; the
/// rule stays registered — the working set offers no de-registration — and
/// its occurrence enabled, re-attempted when the rotation returns to it;
/// repair (registering the home, publishing the document) is the caller's,
/// and a rule that cannot be repaired is shed only with its coordinator.
///
/// Deliberately exhaustive, as `FireOutcome` is: a step fires, dedups, fails,
/// finds its pick a no-op, or finds nothing enabled — the scheduler's whole
/// case split, which a driver's exhaustive match should carry. `#[must_use]`
/// on the type: a step's outcome is the driver's only record of what the fire
/// did, and a `Failed` dropped as a statement takes its `FireError` with it.
#[must_use]
#[derive(Debug)]
pub enum StepOutcome {
    Fired { rule: RuleId, arg: Address, effect: Address, seq: Seq },
    Deduped { rule: RuleId, arg: Address, effect: Address, seq: Seq },
    Failed { rule: RuleId, arg: Address, err: FireError },
    NoOp,
    Quiescent,
}

/// `certify_rule`'s verdict: SF trigger + Marker witness-coverage + grow-only
/// domain (+ bounded input, a workload hypothesis) ⇒ terminating under weak
/// fairness (Q5a/Q6); otherwise the failed legs are named. Sound but
/// incomplete — never over-certifies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleCertification {
    CertifiedTerminating,
    Uncertified { sf: bool, marker: bool, grow_only: bool },
}
