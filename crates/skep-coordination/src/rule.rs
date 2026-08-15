//! §Internal 5 — the reactive-rule datatypes: the raw [`Rule`] submission,
//! trigger/action forms, and the fire/step outcome types.

use skep_address::Address;
use skep_kernel::Seq;
use skep_links::View;

use crate::ast::{Dom, TypeKey};
use crate::check::TypedTerm;
use crate::error::FireError;
use crate::value::Value;

/// One trigger→action rule. `domain` is the RAW submission — `register_rule`
/// checks + `Reg`-expands it into the internal checked `TypedDom` the working
/// set stores (§Internal 5).
#[derive(Debug, Clone)]
pub struct Rule {
    pub domain: Dom,
    pub trigger: TriggerRef,
    pub view: View,
    pub action: FireAction,
}

/// The trigger: a one-parameter Bool predicate over the domain element sort.
#[derive(Debug, Clone)]
pub enum TriggerRef {
    /// Built via `type_check_trigger` (may bind one `Tup`); MUST be ref-free
    /// (`register_rule` rejects otherwise — `RuleError::RefBearingInlineTrigger`).
    Inline(TypedTerm),
    /// pdef-backed; evaluated via `evaluate_def`, so ref-bearing bodies
    /// survive de-registration (eval keys on ever-registration). A `Def`
    /// signature is Codom-only — it cannot serve a `Tup` domain.
    Def(Address),
}

/// The single-deposit fire actions v1 ships (H-ATOM/H-FIN by one M7
/// transact; multi-deposit fires are deferred pending M7's `stage_emit`).
#[derive(Debug, Clone)]
pub enum FireAction {
    /// Canonical certifiable Marker: emit ONE Unary K-tuple covering the
    /// bound argument `a` at `home`, flipping audit `is_K(a)` false→true.
    /// `ty` must be a cataloged idem⊤ Unary type that is NOT a PredLayer
    /// class (`register_rule` rejects otherwise — PR-DISC).
    Marker { home: Address, ty: TypeKey },
    /// Single retraction: `nullify(home, a)` on the bound argument. NOT
    /// SF-certifiable (active-state trigger) — always `Uncertified`, admitted
    /// under the uncertified-rule policy with the divergence monitor as
    /// backstop. Documented contract: the domain must yield RESIDENT LINKS
    /// (tuple-domained, or `Addr`-over-`L_dom`); an `Addr`-over-`M_K` domain
    /// passes `register_rule` but every fire then trips
    /// `FireError::Nullify(Rejected(BadTarget))`.
    Nullify { home: Address },
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

/// A peeked enabled occurrence `(ρ, x)`; `arg` is `Value::Addr` for an
/// `Addr`-domain rule, `Value::Tuple` for a `Tup`-domain rule (the trigger/
/// atom dispatch consumes the whole tuple; only the bookkeeping projects to
/// the address).
#[derive(Debug, Clone, PartialEq)]
pub struct Enabled {
    pub rule: RuleId,
    pub arg: Value,
}

/// One fire's outcome (§Internal 5, the two-transaction race exactly
/// accounted). Only `Fired` advances the divergence count — a `Deduped`
/// (idem⊤ dedup hit in the trigger-check↔commit gap: M7 committed NOTHING,
/// returned the incumbent) and a `NoOp` (argument out of `[D_ρ]` — removed —
/// or trigger false — falsified — at fire time, Q1) leave no journal record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FireOutcome {
    NoOp,
    Fired { effect: Address, seq: Seq },
    Deduped { effect: Address, seq: Seq },
}

/// One `step`'s outcome. `Fired`/`Deduped` carry `FireOutcome`'s `effect`
/// (the deposited resp. incumbent tuple's address) through, so a driver can
/// reconcile the divergence monitor against the journal without re-deriving
/// the deposited tuple's address. A fire error surfaces as `Failed` — never a
/// silent swallow — with rotate-past rotation (§7): nothing committed, the
/// occurrence stays enabled; deregister/repair is the caller's.
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
