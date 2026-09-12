//! # skep-coordination — M9: Predicate & Coordination Layer
//!
//! The substrate's **programmable, self-monitoring automation layer**. It
//! owns three things and nothing else:
//!
//! 1. **PL** — a closed, read-only, statically-typed predicate/query algebra
//!    (ASN-0129) composing M7's per-type atoms (Observe + BH1–BH4) into
//!    decidable Boolean/value verdicts over committed structural state;
//! 2. **predicate definitions as content** (ASN-0130) — PL terms persisted as
//!    immutable content-addressed artifacts, validated/registered/versioned/
//!    certified as `pdef`/`pd_stable` tuples;
//! 3. a **reactive rule engine with a quiescence theory** (ASN-0133) — a
//!    registry of trigger→action rules, an atomic fire executor, quiescence
//!    detection (Q0/Q7), a fair `step` scheduler, and the SF+Marker+grow-only
//!    termination lint with a journal-recomputable divergence backstop.
//!
//! The one thing it does well: turn committed structural substrate state into
//! decidable verdicts and bounded reactions, with **composition as the only
//! extension mechanism — never foreign read-path code** (PC6).
//!
//! ## The Lampson spine
//!
//! **M9 owns no authoritative state.** PL reads M7/M3 off one pinned M2
//! `Snapshot` per verdict; defs persist as M4 content plus M7 tuples; rule
//! *effects* are durable in M7's journal; everything M9 holds — the `DefMemo`
//! of immutable-once-defined signatures, the rule working set, the fire
//! counters — is a recomputable hint or an in-memory working set, rebuilt by
//! replay/re-query/re-registration. No journal, no `apply`, no slice, no
//! record variant.
//!
//! ## Boundary — deliberately NOT owned here
//!
//! * the content-region/arrangement query algebra — M8 (hard lateral
//!   boundary: **no M9→M8 edge**);
//! * the request lifecycle/dispatch/acknowledgment — M10 (parallel surface;
//!   fires reach M7's gated write path **directly, never through M10**);
//! * ordering/durability/recovery — M2;
//! * byte content, arrangement, link values, address minting, registry
//!   mutation — M4/M5/M7/M3 (M9 builds **no second `TypeRegistry`**: it
//!   projects the ONE engine-built instance into its frozen catalog at
//!   construction and consults nothing else for type knowledge after);
//! * ownership consultation — residence reduces to
//!   `is_registered_document`;
//! * the activation binding (who may register rules), bounded-input
//!   workloads, the scheduler/violation policy — handed upward: M9 supplies
//!   the mechanism, not the policy.
//!
//! ## Standing assembly obligations (not dischargeable here)
//!
//! * the injected `mk_vstream`/`mk_link_writer` factories presuppose the
//!   engine can construct a `Vstream` from `&Kernel<W>` and a `LinkWriter`
//!   from `&Kernel<W>` plus a visibility class — the injected `guest`
//!   predicate, lent at every construction (lane 3.3b);
//! * **PR-DISC**: no holder of M7's `emit` other than M9's
//!   `register_pred`/`certify_stable` may route a typed emit whose `ty` is
//!   `pdef`/`pd_stable` (M7's gate rejects only R-class; M9's own
//!   `register_rule` closes the in-module route via `PredLayerMarkerType`).

#![forbid(unsafe_code)]

mod ast;
mod catalog;
mod check;
mod codec;
mod coordinator;
mod defs;
mod dynamics;
mod engine;
mod error;
mod eval;
mod expand;
mod guest;
mod memo;
mod rule;
mod value;
mod walk;

use skep_arrangement::{HasM5, M5Rec};
use skep_content::{ContentWrite, HasContent};
use skep_kernel::WorldState;
use skep_links::{HasLinks, LinkRec};
use skep_namespace::{HasM3, M3Rec};

pub use ast::{
    ArcDom, ArcTerm, Atom, Dom, Lit, Prim, Term, TypeKey, TypeRef, VarId, EXPANSION_NAME_BASE,
};
pub use check::{TriggerTerm, TypedTerm};
pub use coordinator::{Coordinator, LinkWriterFactory, VstreamFactory};
pub use dynamics::{ActiveExceptions, Dynamics, Footprint, Stability};
pub use error::{
    CertifyError, DefineError, EvalError, FireError, RegisterError, RetractError,
    RuleError, TypeError,
};
pub use rule::{
    Arg, FireAction, FireOutcome, Occurrence, Rule, RuleCertification, RuleId, ScopeBody,
    StepOutcome, Trigger,
};
pub use value::{Env, Signature, Sort, Value};

// Foreign types in this surface, re-exported so a caller names everything a
// `Coordinator` signature carries from one crate: M1's address and numeral,
// M2's snapshot/position/transaction refusal, M5's insert refusal, and M7's
// view, walk head, shipped types, endset, coverage class, tuple, behavior,
// write refusals and visibility class. The assembly-time types (`Kernel`,
// `TypeRegistry`, `Vstream`, `LinkWriter`) stay the assembler's — it owns
// those crates already.
pub use skep_address::{Address, Nat};
pub use skep_arrangement::InsertError;
pub use skep_kernel::{Seq, Snapshot, TxnError};
pub use skep_links::{
    Behavior, CoverageClass, EmitError, Endset, NullifyError, ShippedType, Tip, Tuple, View,
    Visibility,
};

/// The world M9 is assembled over: every store it reads (M3, M4, M5, M7)
/// and every record it lifts through their ops (M9 drives no `transact`
/// itself — a def write rides M5's placement composite, every `pdef`/
/// `pd_stable`/fire deposit M7's gated `emit`/`nullify`). One name for the
/// bound set every `Coordinator` impl block states; a blanket impl, so any
/// world with the four stores and the four lifts is one.
pub trait CoordinationWorld:
    WorldState<Record: From<LinkRec> + From<M5Rec> + From<M3Rec> + From<ContentWrite>>
    + HasLinks
    + HasM3
    + HasContent
    + HasM5
{
}

impl<W> CoordinationWorld for W where
    W: WorldState<Record: From<LinkRec> + From<M5Rec> + From<M3Rec> + From<ContentWrite>>
        + HasLinks
        + HasM3
        + HasContent
        + HasM5
{
}

/// What this crate promises without saying, pinned so a private change
/// cannot revoke it silently: every value a driver carries out of a verdict
/// or a step — and every rejection, in its `Box<dyn Error + Send + Sync>`
/// crossing form — is `Send + Sync + 'static`. `Value`/`Env` keep the
/// promise through `im`'s `Arc`-backed collections, which this crate's
/// manifest names; a swap to the `Rc`-backed `im-rc` would revoke it with
/// nothing else failing to build. `Coordinator<W>` itself is pinned over a
/// concrete world in the suite, being generic here.
const _: fn() = || {
    fn owed<T: Send + Sync + 'static>() {}
    fn owed_error<T: std::error::Error + Send + Sync + 'static>() {}
    owed::<TypedTerm>();
    owed::<TriggerTerm>();
    owed::<Value>();
    owed::<Env>();
    owed::<Dynamics>();
    owed::<Occurrence>();
    owed::<Rule>();
    owed::<FireOutcome>();
    owed::<StepOutcome>();
    owed_error::<TypeError>();
    owed_error::<DefineError>();
    owed_error::<RegisterError>();
    owed_error::<EvalError>();
    owed_error::<CertifyError>();
    owed_error::<RetractError>();
    owed_error::<FireError>();
    owed_error::<RuleError>();
};
