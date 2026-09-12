//! §Internal 5 — the reactive-rule datatypes: the raw [`Rule`] submission,
//! trigger/action forms, the occurrence and its argument, and the fire/step
//! outcome types.

use skep_address::Address;
use skep_kernel::Seq;
use skep_links::{Tuple, View};

use crate::ast::{Dom, TypeKey};
use crate::check::TriggerTerm;
use crate::error::FireError;
use crate::value::Value;

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

/// A rule's bound argument — a domain element: an address (an `Addr`-domain
/// rule, `M_K`/`L_dom`/a set term) or a whole tuple (a `Tup`-domain rule,
/// `A_K`/`L_K`). The two shapes a rule can bind are the two this type has:
/// the trigger/atom dispatch consumes the whole value; bookkeeping projects
/// to the address (`t.addr` for a tuple — R1 AddressInjectivity).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Arg {
    Addr(Address),
    Tuple(Tuple),
}

impl Arg {
    /// The bookkeeping key: the address itself, or the tuple's `t.addr`.
    pub(crate) fn key_addr(&self) -> Address {
        match self {
            Arg::Addr(a) => a.clone(),
            Arg::Tuple(t) => t.addr.clone(),
        }
    }
}

/// The value a trigger's one parameter binds to.
impl From<Arg> for Value {
    fn from(a: Arg) -> Value {
        match a {
            Arg::Addr(a) => Value::Addr(a),
            Arg::Tuple(t) => Value::Tuple(t),
        }
    }
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
/// accounting complete.
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
///
/// Deliberately exhaustive, as `FireOutcome` is: a step fires, dedups, fails,
/// finds its pick a no-op, or finds nothing enabled — the scheduler's whole
/// case split, which a driver's exhaustive match should carry.
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
