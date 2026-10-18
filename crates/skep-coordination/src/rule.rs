//! The reactive rule engine's public vocabulary (§Internal 5).
//!
//! It holds the raw [`Rule`] submission, trigger/action forms, the
//! occurrence, the fire/step outcome types, and the scope bodies
//! `quiescent_scoped` restricts by, each saying what it reads. The checked
//! shapes the working set holds are the rule engine's own
//! (`coordinator/engine.rs`). A rule's bound argument is a PL domain element,
//! so it is [`crate::value::Arg`] — `Occurrence` names it, this module does
//! not declare it.

use skep_address::Address;
use skep_kernel::Seq;
use skep_links::View;

use crate::ast::{Dom, TypeKey};
use crate::check::TriggerTerm;
use crate::error::FireError;
use crate::value::{lift, Arg};

/// One trigger→action rule.
///
/// `domain` is the *raw* submission — `register_rule` checks +
/// `Reg`-expands it into the internal checked `TypedDom` the working set
/// stores (§Internal 5). Comparable in every field, so a harness can pin the
/// submission it built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    /// The domain `D_ρ`, as submitted.
    pub domain: Dom,
    /// The trigger `T_ρ`.
    pub trigger: Trigger,
    /// The term view the rule's domain and trigger are read at.
    pub view: View,
    /// What each fire of the rule deposits.
    pub action: FireAction,
}

/// The rule's trigger `T_ρ`, as the submission gives it.
///
/// It is a one-parameter Bool predicate over the domain element sort:
/// inline, as a checked `TriggerTerm`, or by the content start of a stored
/// def.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Trigger {
    /// A trigger built via `type_check_trigger`.
    ///
    /// Its one parameter may be `Tup`; it must be ref-free (`register_rule`
    /// rejects otherwise — `RuleError::RefBearingInlineTrigger`).
    Inline(TriggerTerm),
    /// A `pdef`-backed trigger, named by its def's content start.
    ///
    /// It is any def with a defined signature — ever-registered, a retracted
    /// one included, endorsement gating only a new *reference*
    /// (`register_pred`'s gate (iv)), never a trigger. Its checked body is
    /// captured at `register_rule`, so the rule survives the def's
    /// retraction, before or after, and reads only the snapshot it is
    /// evaluated on. A `Def` signature is Codom-only — it cannot serve a `Tup`
    /// domain.
    Def(Address),
}

/// The single-deposit fire actions v1 ships (H-ATOM/H-FIN by one M7 transact).
///
/// `#[non_exhaustive]`: multi-deposit fires are deferred pending M7's
/// `stage_emit`, and arrive as a variant a driver's catch-all should absorb.
/// Construction is unaffected — both variants' fields are public.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum FireAction {
    /// The canonical certifiable Marker: one Unary K-tuple emitted at `home`.
    ///
    /// The tuple covers the bound argument's address `a` (`Arg::key_addr` —
    /// a bound tuple's own `t.addr`), flipping audit `is_K(a)` false→true.
    /// `ty` must be a cataloged idem⊤ Unary type that is not a PredLayer
    /// class (`register_rule` rejects otherwise — PR-DISC).
    Marker { home: Address, ty: TypeKey },
    /// A single retraction: `nullify(home, a)`.
    ///
    /// `a` is the bound argument's address (a bound tuple's own `t.addr`).
    /// Never certifiable: `certify_rule`'s Marker leg is false *by action*,
    /// whatever the trigger's stability (a ⊤ trigger is SF and the rule is
    /// still `Uncertified`) — admitted under the uncertified-rule policy with
    /// the divergence monitor as backstop. Documented contract: the domain
    /// must yield resident links (tuple-domained, or `Addr`-over-`L_dom`); an
    /// `Addr`-over-`M_K` domain passes `register_rule`, but a fire whose
    /// member is no resident link (nor the address its own retraction would
    /// occupy) trips `FireError::Nullify(Rejected(BadTarget))`.
    Nullify { home: Address },
}

impl FireAction {
    /// Returns the document a fire of this action writes into.
    ///
    /// It is the one fact both variants share: checked against the guest
    /// class before any deposit (`FireError::DraftBoundary`), checked by M7
    /// as the write's home (H-HOME → `FireError::HomeNotRegistered`), and the
    /// home half of the divergence monitor's attribution key (§8).
    pub fn home(&self) -> &Address {
        match self {
            FireAction::Marker { home, .. } | FireAction::Nullify { home } => home,
        }
    }
}

/// `quiescent_scoped`'s per-rule restriction form (Q7).
///
/// It says which address of a rule's bound argument the scope predicate `S`
/// is asked about — Q9's β. A body reads one element shape: `PerAddress` an
/// address domain's element, the other three a tuple slice's; a rule whose
/// domain yields the other shape is left *unscoped*, every one of its
/// arguments counted — a safe over-approximation of remaining work, never
/// false quiescence. All four use `S` only positively, so Q9's global⟹scope
/// inference holds by construction. Deliberately not `Ord`: the four bodies
/// have no order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScopeBody {
    /// A tuple is in scope iff `S` holds of its own address, `t.addr`.
    ///
    /// That is `S(addr(x))`, a *link* address, never a document's, so a scope
    /// written `x = D` for a document `D` holds of no tuple; a scope by the
    /// emitting (home) document asks `D ≼ x`, which holds of the links homed
    /// in `D` and in every document whose address extends `D`'s (its
    /// versions).
    PerEmitter,
    /// A tuple is in scope iff `S` holds of any address its G slot denotes.
    ///
    /// That is `∃y ∈ addrs_G(x) :: S(y)`.
    PerTarget,
    /// A tuple is in scope iff `S` holds of any address its F slot denotes.
    ///
    /// That is `∃y ∈ addrs_F(x) :: S(y)`.
    PerSource,
    /// An address is in scope iff `S` holds of it — `S(x)`.
    PerAddress,
}

impl ScopeBody {
    /// Returns β_ρ^S(x): whether `arg` is in scope under this body.
    ///
    /// `None` when the body and the argument's shape disagree — which leaves
    /// the rule *unscoped*, its full `[D_ρ]` counted. `s` owns each address
    /// it is asked about — `quiescent_scoped`'s binds it into the scope's
    /// environment — so a slot's addresses are lifted straight into it.
    pub(crate) fn in_scope(self, arg: &Arg, s: &dyn Fn(Address) -> bool) -> Option<bool> {
        match (self, arg) {
            (ScopeBody::PerAddress, Arg::Addr(a)) => Some(s(a.clone())),
            (ScopeBody::PerEmitter, Arg::Tuple(t)) => Some(s(t.addr.clone())),
            (ScopeBody::PerTarget, Arg::Tuple(t)) => Some(t.to.addrs().any(|y| s(lift(y)))),
            (ScopeBody::PerSource, Arg::Tuple(t)) => Some(t.from.addrs().any(|y| s(lift(y)))),
            _ => None,
        }
    }
}

/// A registered rule's handle.
///
/// Ordered by registration: the registry is append-only and mints each id
/// from a counter it only increments, so `<` is "registered earlier" — which
/// is what makes `armer_cycles`' stated ordering checkable, and what lets a
/// driver key a `BTreeMap` of per-rule state in registration order.
///
/// Minted per-`Coordinator`, from that handle's own counter starting at 1, so
/// an id is meaningful only to the handle that minted it and two handles over
/// one kernel mint *colliding* ids. `<` therefore orders the rules of *one*
/// handle; an id carried to another either names no rule there — tripping
/// `fire`'s precondition — or names a *different* rule, which no check here
/// can detect. A driver holding several coordinators must keep their ids
/// apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RuleId(pub(crate) u64);

/// An occurrence `(ρ, x)`: a rule and a candidate argument.
///
/// Enabled only relative to a snapshot — `next_enabled` peeks one that is;
/// `fire` re-checks on its own pin and answers `NoOp` if it no longer is.
/// `arg` is `Arg::Addr` for an `Addr`-domain rule, `Arg::Tuple` for a
/// `Tup`-domain rule (the trigger and its atoms consume the whole tuple; what
/// the fire acts at, the document its draft boundary judges and the
/// bookkeeping all take its address, `Arg::key_addr`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Occurrence {
    /// The rule, by the id its handle minted.
    pub rule: RuleId,
    /// The candidate argument.
    pub arg: Arg,
}

/// One fire's outcome (§Internal 5).
///
/// It is decided by where the address M7 returns stands at the fire's own
/// snapshot — M7 reports no hit or miss of its own. `Deduped`: an idem⊤
/// dedup hit on an incumbent already resident there; M7 committed nothing
/// and answered its base `Seq`. `Fired`: an address absent there — this
/// fire's fresh deposit and its commit `Seq`, except under concurrency, where
/// M7 may have deduped onto a witness another writer deposited after the
/// fire's snapshot: still `Fired`, carrying that writer's tuple and M7's base
/// `Seq`, nothing committed by this fire. The miscount runs one way — a fresh
/// deposit is never `Deduped`. `NoOp` (argument out of `[D_ρ]` — removed — or
/// trigger false — falsified — at fire time, Q1): nothing written. The
/// divergence count is recomputed from the store (`fire_count`), never from
/// these outcomes.
///
/// Deliberately exhaustive (no `#[non_exhaustive]`): the three outcomes are
/// closed by the quiescence theory — a fire either commits, is absorbed, or
/// finds nothing to do, as its own snapshot can tell them apart — and a
/// driver's exhaustive match is what keeps its accounting complete.
/// `#[must_use]` on the type, for the same accounting: a dropped outcome is a
/// fire whose effect nothing recorded.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FireOutcome {
    /// Nothing written: out of `[D_ρ]`, or the trigger false, at fire time.
    NoOp,
    /// A deposit whose address was absent at the fire's snapshot.
    Fired { effect: Address, seq: Seq },
    /// A dedup hit on an incumbent resident at the fire's snapshot.
    Deduped { effect: Address, seq: Seq },
}

/// One `step`'s outcome.
///
/// `Fired`/`Deduped` carry `FireOutcome`'s `effect` and `seq` through with
/// `FireOutcome`'s meaning — `Fired`'s one-way concurrency exception included
/// — so a driver can reconcile against the journal without re-deriving the
/// deposited tuple's address. `arg` is the bookkeeping *key*, never the bound
/// value: the bound address for an `Addr`-domain rule, a bound tuple's
/// `t.addr` for a `Tup`-domain one — which is what `fire_count(rule, &arg)`
/// keys on. A fire error surfaces as `Failed` — never a silent swallow — with
/// rotate-past rotation (§7): nothing committed; the rule stays registered —
/// the working set offers no de-registration — and its occurrence enabled,
/// re-attempted when the rotation returns to it; repair (registering the
/// home, publishing the document) is the caller's, and a rule that cannot be
/// repaired is shed only with its coordinator.
///
/// `NoOp` means the pick was enabled at the peeked snapshot and not at the
/// fire's own: nothing committed, the rotation moved past it, and — the peek
/// being the caller's snapshot — no progress toward `quiescent` *at* that
/// snapshot. Re-pin per step ([`crate::Coordinator::step`] states the
/// obligation).
///
/// Deliberately exhaustive, as `FireOutcome` is: a step fires, dedups, fails,
/// finds its pick a no-op, or finds nothing enabled — the scheduler's whole
/// case split, which a driver's exhaustive match should carry. `#[must_use]`
/// on the type: a step's outcome is the driver's only record of what the fire
/// did, and a `Failed` dropped as a statement takes its `FireError` with it.
#[must_use]
#[derive(Debug)]
pub enum StepOutcome {
    /// The pick fired, with `FireOutcome::Fired`'s `effect` and `seq`.
    Fired { rule: RuleId, arg: Address, effect: Address, seq: Seq },
    /// The pick deduped, with `FireOutcome::Deduped`'s `effect` and `seq`.
    Deduped { rule: RuleId, arg: Address, effect: Address, seq: Seq },
    /// The pick's fire was refused, `err` saying why.
    Failed { rule: RuleId, arg: Address, err: FireError },
    /// The pick was enabled at the peek and not at the fire's own snapshot.
    NoOp,
    /// No rule has an enabled occurrence at the peeked snapshot.
    Quiescent,
}

/// `certify_rule`'s answer.
///
/// SF trigger + Marker witness-coverage — the extinction discipline Q5a
/// needs beside SF, by the Marker pattern (Q3) — + grow-only domain (+
/// bounded input, a workload hypothesis) ⇒ terminating under weak fairness
/// (Q5a/Q6); otherwise the failed legs are named. Sound but incomplete —
/// never over-certifies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RuleCertification {
    /// All three legs hold.
    CertifiedTerminating,
    /// Some leg fails; each field is that leg's verdict.
    Uncertified { sf: bool, marker: bool, grow_only: bool },
}
