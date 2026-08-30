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
//!   projects the ONE engine-built instance, validate-once-or-fail);
//! * ownership consultation — residence reduces to
//!   `is_registered_document`;
//! * the activation binding (who may register rules), bounded-input
//!   workloads, the scheduler/violation policy — handed upward: M9 supplies
//!   the mechanism, not the policy.
//!
//! ## Standing assembly obligations (not dischargeable here)
//!
//! * the injected `mk_vstream`/`mk_link_store` factories presuppose the
//!   engine can construct a `Vstream`/`LinkWriter` from `&Kernel<W>`;
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
mod rule;
mod value;

pub use ast::{
    ArcDom, ArcTerm, Atom, Dom, Lit, Prim, Term, TypeKey, TypeRef, VarId, EXPANSION_NAME_BASE,
};
pub use check::TypedTerm;
pub use coordinator::Coordinator;
pub use dynamics::{ActiveExceptions, Dynamics, Footprint, Stability};
pub use error::{
    CertifyError, DefineError, EvalError, FireError, RegisterError, RetractError,
    RuleError, TypeError,
};
pub use rule::{
    Enabled, FireAction, FireOutcome, Rule, RuleCertification, RuleId, ScopeBody, StepOutcome,
    TriggerRef,
};
pub use value::{Env, Signature, Sort, Value};
