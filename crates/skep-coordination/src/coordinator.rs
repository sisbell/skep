//! §Public interface — the one handle. All capability groups hang off
//! [`Coordinator<W>`] over the engine's `Arc<Kernel<W>>`. M9 contributes no
//! `WorldState` slice and no record variant — it is a pure orchestrator/
//! evaluator; everything it holds is a recomputable hint or an in-memory
//! working set (§Core data model).
//!
//! The handle's impl is cut one file per capability group. This file holds
//! construction, the two guest-class surfaces (`eval_ctx`, `link_writer`),
//! the checker's two invocations, the calling convention both evaluators
//! bind Γ_D by (`bind_args`) and group A; its children `defs` (group B) and
//! `engine` (group C) are the rest of the impl, and `memo` is the def-status
//! cache the handle holds. Being children they share the private state this
//! module declares — no other module of the crate can reach it.

// The def-status memo the handle holds: permanence here, admission in `defs`.
mod memo;
// Group B: predicate definitions as content, and their resolution.
mod defs;
// Group C: the reactive rule engine and its working set's shapes.
mod engine;

use std::fmt;
use std::sync::Arc;

use skep_address::Address;
use skep_arrangement::Vstream;
use skep_kernel::{Kernel, Snapshot, WorldState};
use skep_links::{Endset, LinkWriter, ShippedType, TypeRegistry, View, Visibility};

use crate::ast::{Dom, Term, VarId};
use crate::catalog::TypeCatalog;
use crate::check::{CheckedDom, Checker, DefSource, TriggerTerm, TypedTerm};
use crate::dynamics::{classify_term, Dynamics};
use crate::error::{EvalError, TypeError};
use crate::eval::{eval_term, EvalCtx};
use crate::guest::GuestLinks;
use crate::value::{Env, SignedTerm, Sort, Value};
use crate::CoordinationWorld;

use engine::CheckedRule;
use memo::DefMemo;

/// The M5 `Vstream` factory the engine injects: a borrow-scoped op handle
/// minted off `&Kernel<W>` per call (driver construction is the engine's by
/// the composition contract, so M9 names `Vstream::new` nowhere;
/// higher-ranked because the handle borrows the kernel).
///
/// A plain `fn` pointer: a factory builds over the kernel it is handed and
/// over nothing it holds, and a `fn` pointer holds nothing — a capturing
/// closure does not coerce to one. A non-capturing closure written where the
/// type is expected coerces, the type supplying its higher-ranked signature,
/// and so does a fn item that declares its lifetime on itself. `Vstream::new`
/// takes its `'k` from its impl, so it does not coerce itself, and an
/// assembler wraps it in one or the other:
///
/// ```
/// use skep_arrangement::Vstream;
/// use skep_coordination::VstreamFactory;
/// use skep_kernel::WorldState;
///
/// fn factory<W: WorldState>() -> VstreamFactory<W> {
///     |kernel| Vstream::new(kernel)
/// }
/// ```
///
/// The same closure holding anything of its own is refused at compile time:
///
/// ```compile_fail,E0308
/// use std::sync::Arc;
///
/// use skep_arrangement::Vstream;
/// use skep_coordination::VstreamFactory;
/// use skep_kernel::WorldState;
///
/// fn factory<W: WorldState>(held: Arc<()>) -> VstreamFactory<W> {
///     move |kernel| {
///         let _held = &held;
///         Vstream::new(kernel)
///     }
/// }
/// ```
pub type VstreamFactory<W> = for<'k> fn(&'k Kernel<W>) -> Vstream<'k, W>;

/// The M7 `LinkWriter` factory the engine injects: a writer over the kernel
/// AT A VISIBILITY CLASS (lane 3.3b). Called only by
/// [`Coordinator::link_writer`], which hands it the coordinator's `guest`
/// predicate, so the value-keyed gates of every fire and every def write run
/// at guest class. A plain `fn` pointer, for [`VstreamFactory`]'s reason: it
/// can hold no kernel and no visibility class of its own.
pub type LinkWriterFactory<W> =
    for<'k> fn(&'k Kernel<W>, &'k Visibility<'k, W>) -> LinkWriter<'k, W>;

/// M9's one public handle: PL (group A), predicate definitions (group B), and
/// the reactive rule engine (group C). Owns no authoritative state — the
/// `DefMemo` is an interior-mutable recomputable hint; the rule registry
/// and rotation cursor are the `&mut self` working set.
pub struct Coordinator<W: WorldState> {
    kernel: Arc<Kernel<W>>,
    catalog: TypeCatalog,
    memo: DefMemo,
    rules: Vec<CheckedRule>,
    next_rule_id: u64,
    cursor: usize,
    mk_vstream: VstreamFactory<W>,
    mk_link_writer: LinkWriterFactory<W>,
    /// The GUEST-class read predicate over a document address (PUB round 2,
    /// lane 3.3, §5), in M7's own `Visibility` shape: `true` iff the
    /// document is readable at guest class, with no principal. It is applied
    /// THREE ways, each by one element:
    ///
    /// - THE LOOK (lane 4.1, PUB-6.28): every verdict's read context is built
    ///   over it ([`Coordinator::eval_ctx`] → `GuestLinks`), so a tuple homed
    ///   where it answers `false` seeds no domain, satisfies no trigger and
    ///   moves no PL verdict;
    /// - THE BOUNDARY (lane 3.3): a fire consults it, off its own pinned
    ///   snapshot, on the action's HOME and on the bound argument's document
    ///   before any deposit (`draft_boundary`), so a rule's effect never
    ///   crosses the draft boundary in either direction (a marker on a
    ///   draft's content, or a deposit into a draft home);
    /// - THE GATES (lane 3.3b, PUB-6.28): every `LinkWriter` M9 builds is
    ///   built AT this visibility class ([`Coordinator::link_writer`] lends
    ///   this closure to `mk_link_writer`), so M7's idempotency and dedup
    ///   lookups see only guest-readable incumbents and a fire commits
    ///   byte-identically to a world with no drafts.
    ///
    /// M9 holds no publication state of its own — the predicate is injected
    /// like the factories.
    guest: Box<Visibility<'static, W>>,
}

/// The working set is what a driver reads back — the registered rule ids
/// and the rotation cursor. The kernel, the catalog projection, the memo and
/// the injected factories are elided (`finish_non_exhaustive`).
impl<W: WorldState> fmt::Debug for Coordinator<W> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Coordinator")
            .field("rules", &self.rules.iter().map(|r| r.id).collect::<Vec<_>>())
            .field("next_rule_id", &self.next_rule_id)
            .field("cursor", &self.cursor)
            .finish_non_exhaustive()
    }
}

impl<W: CoordinationWorld> Coordinator<W> {
    /// Engine-assembled construction. Receives the shared kernel; the ONE
    /// engine-built `Arc<TypeRegistry>` (NEVER rebuilt here — Conflicts §7),
    /// which M9 projects its static `TypeCatalog` from and then need not
    /// retain; and the two op-handle factories, [`VstreamFactory`] and
    /// [`LinkWriterFactory`] (the latter takes the VISIBILITY class beside
    /// the kernel — lane 3.3b: M9 lends it `guest` at every construction, a
    /// borrow of the one closure it holds).
    ///
    /// Infallible: the projection is a pure read of the injected registry,
    /// whose population is the compiled shipped five (owner ruling,
    /// 2026-08-26).
    ///
    /// `guest` is the GUEST-class read predicate (lane 3.3 §5) — `true` iff a
    /// document is readable with no principal. Any `Fn` of M7's `Visibility`
    /// shape serves — a closure, or a predicate already boxed — and the
    /// handle boxes it to hold it. It decides three things, so an assembler
    /// choosing it chooses all three: what every PL verdict sees (lane 4.1 —
    /// a tuple homed where it answers `false` is invisible to `eval`,
    /// `evaluate_def` and every rule's domain and trigger); which fires are
    /// refused before any deposit (`FireError::DraftBoundary`, lane 3.3); and
    /// what M7's value-keyed gates see at every write M9 makes (PUB-6.28,
    /// lane 3.3b).
    ///
    /// OBLIGATIONS ON THE THREE INJECTED VALUES — half of one carried by the
    /// types, the rest owed by the assembler. The factories are `fn`
    /// pointers, so neither can hold a kernel or a visibility class of its
    /// own: a capturing closure does not coerce to one. What stays the
    /// assembler's: each factory builds its handle over EXACTLY the
    /// arguments it is handed — `mk_vstream` over the `&Kernel<W>` given,
    /// `mk_link_writer` over that kernel AND that `&Visibility` — rather than
    /// over a `static` it could still name; and `guest` is a pure function of
    /// `(world, doc)`, reading nothing outside the world it is passed. M9's
    /// one-pinned-snapshot verdicts and lane 3.3b's byte-identical commit
    /// rest on both: a predicate consulting state outside its world would
    /// give one verdict two visibility answers for one document, and a
    /// factory building over a kernel or a visibility class it was not handed
    /// would void the guarantee in silence.
    ///
    /// And `guest` must be TOTAL over every `&Address` M9 hands it, which is
    /// not only registered documents: a fire consults it on the action's HOME
    /// before M7's H-HOME gate has run — so on an address this crate has not
    /// established to be a registered document — and on `document_of` of the
    /// bound argument, falling back to the argument itself when it has no
    /// document field. It must ANSWER for any of those, never panic, and
    /// `false` is the safe answer for an address it does not recognize: the
    /// fire stops at the draft boundary (`FireError::DraftBoundary`) before
    /// any deposit. A `true` for a HOME no mint produced lets the fire reach
    /// M7, whose H-HOME refuses it (`FireError::HomeNotRegistered`). Which
    /// addresses an injected predicate reads as drafts is its assembler's to
    /// state; M9 states what it does with each answer.
    pub fn new(
        kernel: Arc<Kernel<W>>,
        registry: Arc<TypeRegistry>,
        mk_vstream: VstreamFactory<W>,
        mk_link_writer: LinkWriterFactory<W>,
        guest: impl Fn(&W, &Address) -> bool + Send + Sync + 'static,
    ) -> Coordinator<W> {
        let catalog = TypeCatalog::project(&registry);
        Coordinator {
            kernel,
            catalog,
            memo: DefMemo::new(),
            rules: Vec::new(),
            next_rule_id: 1,
            cursor: 0,
            mk_vstream,
            mk_link_writer,
            guest: Box::new(guest),
        }
    }

    /// M9's own cached catalog accessor (no snapshot) — the `&Endset` every
    /// `emit(home, reserved_type(…), …)` / PL `TypeKey` construction reads.
    /// Distinct from M7's snapshot-bound `LinkState::reserved_type`, and
    /// byte-identical to it: the catalog is a projection of the same
    /// registry.
    pub fn reserved_type(&self, ty: ShippedType) -> &Endset {
        self.catalog.reserved_type(ty)
    }

    /// One verdict's read context over the world `w` of a pinned snapshot,
    /// at the term view `view`: the catalog, M3, and M7 THROUGH THE LOOK AT
    /// GUEST CLASS (`GuestLinks`, PUB round 2, lane 4.1 — every tuple homed
    /// where the injected `guest` predicate answers `false` is dropped from
    /// every read). The ONE construction site in the crate: `eval`/`decide`,
    /// the rule engine's domain enumeration, trigger evaluation and scope
    /// test, the fire's own re-check, and `evaluate_def`'s denotation all
    /// build their context here, so every evaluator reads the link store at
    /// guest class.
    fn eval_ctx<'a>(
        &'a self,
        w: &'a W,
        view: View,
        defs: Option<&'a dyn DefSource>,
    ) -> EvalCtx<'a, W> {
        EvalCtx {
            catalog: &self.catalog,
            links: GuestLinks::new(w, &*self.guest),
            m3: w.m3(),
            view,
            defs,
        }
    }

    /// The M7 write handle, AT GUEST CLASS (lane 3.3b, PUB-6.28) — the write
    /// side's twin of [`Coordinator::eval_ctx`], and the ONE construction
    /// site: every `emit`/`nullify` M9 makes (`register_pred`, `supersede`,
    /// `certify_stable`, `retract_pred`, and a rule's fire) goes through a
    /// writer built here, so M7's idempotency and dedup lookups see only
    /// guest-readable incumbents and every writer M9 builds runs at guest
    /// class.
    fn link_writer(&self) -> LinkWriter<'_, W> {
        (self.mk_link_writer)(self.kernel.as_ref(), &*self.guest)
    }

    // ──────────────────── A. The predicate language ────────────────────

    /// Type-check `body` under the ordered parameter context `params` (Γ_D —
    /// ASN-0129 WT is a Γ-parameterized CHECKING judgment; empty for a closed
    /// term), expand `Reg`-quantifiers to concrete-class instances (V-IDX),
    /// and reject ill-typed / undefined-reference / uncataloged-type-key /
    /// unbound-variable / non-Codomain-parameter terms. Γ_D is Codom-only: a
    /// `Tup`-sorted parameter is `TupParameter` — a stored def's parameters
    /// are Codom-sorted, never `Tup` (ASN-0130 SignedTerm) — and the one PL
    /// term with a tuple parameter, a rule trigger, is checked by
    /// [`Coordinator::type_check_trigger`] into a type of its own. Every
    /// `Concrete` `TypeKey` must be a canonical catalog endset (the probe is
    /// `Endset`-equality, not coverage). The check is also the term's
    /// resource door: a body nested past the crate's one nesting cap,
    /// counted through its references, is `TooDeep`, and one whose
    /// `Reg`-expansion outgrows the node budget — counted per node AND per
    /// unit of payload, so a large literal under a `Reg` quantifier is
    /// charged for every instance it multiplies into — is `TooLarge`; each
    /// refused at the bound, not after it. Passing that door is not
    /// storability: the def codec meters a stored body by its own charges,
    /// and `define_predicate` refuses a checked term it would not read back
    /// (`DefineError::Unstorable`). Reads no structural state for a
    /// ref-free body; consults the def memo for any `Ref`, and on a MISS
    /// derives the referent from its immutable content, pinning its own
    /// snapshot — on the disciplined domain the answer is the same either way
    /// (the crate root states the breach exception, which runs only toward
    /// refusal). Once `Ok`, valid at every reachable state (WT).
    ///
    /// WHICH REJECTION SPEAKS, when several hold: `TupParameter` (over Γ_D)
    /// first, then `TooLarge` for a Γ_D longer than the budget (charged
    /// before anything is sized by its length), then `DuplicateParameter` (a
    /// Γ_D name bound twice), then the
    /// first rejection the checker meets in a pre-order walk of the body —
    /// a node's type position and behavior guard before its children;
    /// children left to right, a binder's domain or bound term before its
    /// body; a `Ref`'s referent — whether it resolves, then how deep a walk
    /// through it reaches — before its arguments, each argument checked
    /// before it is matched against its formal, so an arity mismatch
    /// (`ArgArityMismatch`) speaks at the first unmatched position; a `Reg`
    /// quantifier's instances in catalog order — with `TooDeep`/`TooLarge`
    /// at the node where the budget is spent.
    pub fn type_check(&self, params: Vec<(VarId, Sort)>, body: Term) -> Result<TypedTerm, TypeError> {
        if let Some((v, _)) = params.iter().find(|(_, s)| *s == Sort::Tup) {
            return Err(TypeError::TupParameter(*v));
        }
        self.check_signed(SignedTerm { params, body }, 0)
    }

    /// Type-check a RULE TRIGGER: `body` under the one parameter `param` (any
    /// sort, `Tup` included — a tuple-domained rule fires by binding a
    /// `Value::Tuple`, ASN-0133 ρ_R), Bool codomain (`SortMismatch`
    /// otherwise). The domain↔parameter sort reconciliation and the ref-free
    /// requirement are `register_rule`'s. Which rejection speaks: the
    /// checker's, in [`Coordinator::type_check`]'s walk order, before the
    /// Bool requirement.
    pub fn type_check_trigger(&self, param: (VarId, Sort), body: Term) -> Result<TriggerTerm, TypeError> {
        let t = self.check_signed(SignedTerm { params: vec![param], body }, 0)?;
        if t.result_sort() != Sort::Bool {
            return Err(TypeError::SortMismatch { expected: Sort::Bool, found: t.result_sort() });
        }
        Ok(TriggerTerm::new(Arc::new(t)))
    }

    /// The checker's invocation for a signed term — one of its two, wired
    /// alike (the other is [`Coordinator::check_closed_dom`]): the catalog
    /// and the def resolver handed to a fresh [`Checker`], whose judgment
    /// runs from nesting level `depth` — 0 at the top of a chain (the public
    /// checks, `register_pred`, a cold `signature`), and for a def derived
    /// through a `Ref` the level the checker asks for its referent at
    /// ([`crate::budget::referent_depth`]), so the chain's total nesting is
    /// bounded by `MAX_DEPTH` however deep the derivation runs. Referents
    /// resolve through the def memo at the level the checker asks for them:
    /// a referent whose signature is undefined is `UndefinedReference`, and
    /// one whose derivation cannot complete at that level is `TooDeep`, with
    /// the referent left unjudged.
    fn check_signed(&self, signed: SignedTerm, depth: u32) -> Result<TypedTerm, TypeError> {
        let resolve = |start: &Address, depth: u32| self.resolve_def_at(start, depth);
        Checker::new(&self.catalog, &resolve).check_signed(signed, depth)
    }

    /// A rule's domain through the checker's closed-domain judgment, wired as
    /// [`Coordinator::check_signed`] is: the catalog, and referents resolved
    /// through the def memo — a rule's domain must be ref-free, but its
    /// `Ref`s are checked and resolved before `validate_rule` refuses them.
    fn check_closed_dom(&self, dom: &Dom) -> Result<CheckedDom, TypeError> {
        let resolve = |start: &Address, depth: u32| self.resolve_def_at(start, depth);
        Checker::new(&self.catalog, &resolve).check_closed_dom(dom)
    }

    /// Pure, total, terminating denotation at one view against one committed
    /// snapshot. PRECONDITIONS, both asserted at the door: `t.is_ref_free()`
    /// — a surviving `Ref` node is a precondition violation (PANICS, like
    /// `decide` on a non-Bool codomain); ref-bearing terms evaluate only
    /// through `evaluate_def`, keeping this denotation content-free — and
    /// `args` bind positionally to Γ_D, one per parameter, each at its sort:
    /// the convention `evaluate_def` shares (`bind_args`), refused there as a
    /// value where this door panics. INFALLIBLE past the door;
    /// reads ONLY M7 + M3, all off `snap` (PC4 / ASN-0134 clause 6) — M7
    /// through the look at guest class (lane 4.1, PUB-6.28): a tuple homed in
    /// a document the injected `guest` predicate refuses is invisible to the
    /// verdict, exactly as it is to a fire's gates. The verdict is "as of
    /// `snap.seq()`" (M2 V1 retrospective).
    ///
    /// Each precondition has a PUBLIC discharge point, so a caller can check
    /// what it owes before it calls: [`TypedTerm::is_ref_free`] for the
    /// first, [`TypedTerm::params`] against [`Value::sort`] for the second.
    pub fn eval(&self, t: &TypedTerm, args: &[Value], view: View, snap: &Snapshot<W>) -> Value {
        assert!(
            t.is_ref_free(),
            "eval precondition violated: ref-bearing TypedTerm — route through evaluate_def"
        );
        let env = bind_args(t.params(), args).unwrap_or_else(|refused| {
            panic!(
                "eval precondition violated: {refused:?} — args bind positionally to Γ_D {:?}",
                t.params()
            )
        });
        let cx = self.eval_ctx(snap.world(), view, None);
        eval_term(&cx, &env, t.evaluable())
    }

    /// Convenience for Bool-codomain terms; panics if the codomain is not
    /// Bool, or on any of `eval`'s preconditions.
    pub fn decide(&self, t: &TypedTerm, args: &[Value], view: View, snap: &Snapshot<W>) -> bool {
        assert!(
            t.result_sort() == Sort::Bool,
            "decide precondition violated: codomain is {:?}, not Bool",
            t.result_sort()
        );
        match self.eval(t, args, view, snap) {
            Value::Bool(b) => b,
            other => unreachable!("Bool-codomain term denoted {other:?}"),
        }
    }

    /// Static footprint + 4-point stability lattice (for any codomain —
    /// [`Stability`](crate::dynamics::Stability) states what a non-`Bool`
    /// term's point means) + the three active-view exceptions +
    /// view-independence flag, computed RELATIVE TO `view` (PC3 binds the
    /// view-parameterized constituents to it); `view_independent` alone is
    /// view-agnostic (the PR-VIEW scan). Sound-but-incomplete; never
    /// over-certifies. Reads no state. PRECONDITION: ref-free (panics
    /// otherwise); a stored def is certified through `certify_stable` and a
    /// trigger linted through `certify_rule`, each over its flat expansion.
    pub fn classify(&self, t: &TypedTerm, view: View) -> Dynamics {
        assert!(
            t.is_ref_free(),
            "classify precondition violated: ref-bearing TypedTerm — certify via certify_stable, \
             which classifies the flat reference expansion"
        );
        classify_term(&self.catalog, view, t.evaluable())
    }
}

/// Γ_D's calling convention, stated once for both public evaluators: `args`
/// bind POSITIONALLY to `params` — one argument per parameter, each at its
/// parameter's sort. [`Coordinator::eval`] asserts it at its door;
/// [`Coordinator::evaluate_def`] answers a violation as a value, arity
/// before sort.
fn bind_args(params: &[(VarId, Sort)], args: &[Value]) -> Result<Env, EvalError> {
    if args.len() != params.len() {
        return Err(EvalError::ArgArityMismatch);
    }
    if args.iter().zip(params).any(|(arg, (_, s))| arg.sort() != *s) {
        return Err(EvalError::ArgSortMismatch);
    }
    Ok(params.iter().map(|(v, _)| *v).zip(args.iter().cloned()).collect())
}
