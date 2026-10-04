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
//! of immutable-once-defined signatures, the rule working set — is a
//! recomputable hint or an in-memory working set, rebuilt by
//! replay/re-query/re-registration, and the fire counts it reports are
//! recomputed from M7's journal-recovered slices at every ask. No journal, no
//! `apply`, no slice, no record variant.
//!
//! Several QUERIES may fill that memo on a miss — `signature`, a
//! `type_check`/`type_check_trigger` over a `Ref`, `evaluate_def`,
//! `certify_stable`, a rule validation over a `Def` trigger. The first fill
//! of a start wins and nothing is ever evicted, so once a start is memoized
//! ONE handle answers every later probe of it as it answered the first (a
//! never-registered start is never memoized, its answer following the
//! registration; nor is an ever-registered start with nothing resident yet,
//! its answer following the content). On the disciplined domain (PR-DISC) an
//! entry is moreover a function of the def's immutable content plus M7's
//! monotone audit slice, so the fill is unobservable — every handle, warm or
//! cold, answers alike — and each of these stays a query. Under a breach the
//! design gives that up on purpose (freeze-on-breach, §Internal 4): a start
//! deposited past the gate before its referent was defined, and probed in
//! that window, stays POISONED on the probing handle while a handle that
//! first probes it later derives it defined; and a reference to breached
//! content may be refused one way warm and another cold. Every such
//! disagreement is between refusals, or a refusal and a defined answer —
//! never a wrong `Some`.
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
//!   predicate, lent at every construction (lane 3.3b) — and each must build
//!   over EXACTLY the kernel (and, for the writer, the visibility class) it
//!   is handed, with `guest` a pure function of the world it is passed: the
//!   one-pinned-snapshot verdict and the byte-identical commit rest on both.
//!   The factory types are `fn` pointers, so a factory holding a kernel or a
//!   class of its own does not compile; one naming a `static` instead, and
//!   an impure `guest`, nothing here can refuse. And `guest` must be TOTAL
//!   over every `&Address` M9 hands it, a fire consulting it on the action's
//!   HOME before M7's H-HOME gate has run and on the bound argument's
//!   document, falling back to the argument itself; `false` is the safe
//!   answer for an address it does not recognize, and a panic is not an
//!   answer ([`Coordinator::new`] states the whole of it);
//! * **PR-DISC**: no write but M9's own `register_pred`/`certify_stable` may
//!   grow the `pdef`/`pd_stable` slices (§Internal 4). M7 classes a deposit
//!   by its TYPE slot, whatever surface it arrives through, so the obligation
//!   covers a typed `emit`, the open surface's `makelink` and `editlink`'s
//!   successor alike — M7 itself fences only the `[R]`, `[K_sup]` and
//!   `replaces` classes. M9's `register_rule` closes the in-module route
//!   (`PredLayerMarkerType`). A breach degrades per start, as defined
//!   (`UndisciplinedDef`, freeze-on-breach), but `is_ever_pred`,
//!   `is_active_pred` and `is_certified_stable` read the classes: nothing in
//!   M9 can tell a breaching `pd_stable` tuple from a certificate. What
//!   bounds a breach is that those probes match a start by its COVERAGE
//!   CLASS — the F half of the I0 identity M7's dedup keys the two writes'
//!   deposits by, so one tuple names one start at most — so a forgery costs
//!   its writer one tuple per start, and one whose F covers starts from a
//!   document, an account or the node has that ancestor's class and forges
//!   none of them. PL's `is_K` over the two classes matches by coverage (D2),
//!   and a rule reading either class has no such bound.

#![forbid(unsafe_code)]

// The modules in dependency order: each names only modules above it and the
// root's own `CoordinationWorld`, test code included — `tests/it/tidy.rs`
// checks it. Section marks in the module docs (§Core data model, §Internal N,
// Conflicts §N) cite M9's module design, which lives in the design project
// (the workspace's ARCHITECTURE.md, "Where the reasons live").

// The PL term tree: `Term` and `Dom`, `VarId`'s reserved range, type keys.
mod ast;
// Sorts, values and domain elements; the signed term; the environment.
mod value;
// Test only: one signed term spelling every former — the codec's round trip
// and the walks' agreement are checked on it — and the unit tests' two
// builders, `v` (a variable below the watershed) and `a` (an address from its
// components).
#[cfg(test)]
mod fixture;
// The tree's child structure, stated once: `Rewrite` and `Visit`.
mod walk;
// The caps every walk over a term is charged against, and the one counter.
mod budget;
// The rejection vocabularies, one per operation.
mod error;
// The frozen projection of the engine's `TypeRegistry`.
mod catalog;
// M7's read surface at guest class: every read a verdict makes.
mod guest;
// WT: the type checker, the checked terms only it builds, and the two seams a
// referent is resolved through (`Resolver`, `DefSource`).
mod check;
// PR-ENC: a stored def's byte format — the run a checked def is stored as,
// and the door for untrusted bytes.
mod codec;
// The pure evaluator: one verdict's context and the denotation.
mod eval;
// Footprint, PD0 stability, PR-VIEW and ST⁺ — static, never over-certifying.
mod dynamics;
// PR3's flat reference expansion, the tree the analyses read.
mod expand;
// The rule engine's public vocabulary: rules, actions, occurrences, outcomes,
// and the scope bodies `quiescent_scoped` restricts by.
mod rule;
// The handle, `Coordinator`: construction, the guest-class surfaces and
// group A; its children are `defs` (group B) and `engine` (group C), the rest
// of its impl, and `memo`, the def-status cache it holds — all three inside
// the wall around its private state.
mod coordinator;

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
    CertifyError, DefineError, EvalError, FireError, RegisterError, RetractError, RuleError,
    SupersedeError, TypeError,
};
pub use rule::{
    FireAction, FireOutcome, Occurrence, Rule, RuleCertification, RuleId, ScopeBody, StepOutcome,
    Trigger,
};
pub use value::{Arg, Env, Signature, Sort, Value};

// Foreign types in this surface, re-exported so a caller names everything a
// `Coordinator` signature carries — and every payload a `Value` it builds
// carries — from one crate: M1's address, numeral and tumbler (what a
// `Tuple`'s endsets denote, `Endset::addrs()` yielding it), M2's
// snapshot/position/transaction refusal, M5's insert refusal, and M7's view,
// walk head, shipped types, endset, coverage class, tuple, behavior, write
// refusals and visibility class. The assembly-time types (`Kernel`,
// `TypeRegistry`, `Vstream`, `LinkWriter`) stay the assembler's — it owns
// those crates already.
pub use skep_address::{Address, Nat, Tumbler};
pub use skep_arrangement::InsertError;
pub use skep_kernel::{Seq, Snapshot, TxnError};
pub use skep_links::{
    Behavior, CoverageClass, EmitError, Endset, NullifyError, ShippedType, Tip, Tuple, View,
    Visibility,
};

/// `im`'s persistent collections are [`Value`]'s payload types, so this is a
/// PUBLIC dependency: the exact version the crate was built against is
/// nameable here — `skep_coordination::im::OrdSet` — rather than matched by
/// luck at a caller's own manifest, where a version skew would spell itself
/// `expected OrdSet<Address>, found OrdSet<Address>`. The `const _` below
/// pins what the choice of `im` (over the `Rc`-backed `im-rc`) promises.
pub use im;

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
    owed::<Arg>();
    owed::<Env>();
    owed::<Signature>();
    owed::<Dynamics>();
    owed::<Occurrence>();
    owed::<Rule>();
    owed::<FireOutcome>();
    owed::<StepOutcome>();
    owed_error::<TypeError>();
    owed_error::<DefineError>();
    owed_error::<SupersedeError>();
    owed_error::<RegisterError>();
    owed_error::<EvalError>();
    owed_error::<CertifyError>();
    owed_error::<RetractError>();
    owed_error::<FireError>();
    owed_error::<RuleError>();
};
