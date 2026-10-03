//! §Public interface — the one handle. All capability groups hang off
//! [`Coordinator<W>`] over the engine's `Arc<Kernel<W>>`. M9 contributes no
//! `WorldState` slice and no record variant — it is a pure orchestrator/
//! evaluator; everything it holds is a recomputable hint or an in-memory
//! working set (§Core data model).
//!
//! The handle's impl is cut one file per capability group. This file holds
//! construction, the two guest-class surfaces (`eval_ctx`, `link_writer`),
//! the checker's two invocations and group A; its children `defs` (group B)
//! and `engine` (group C) are the rest of the impl, and `memo` is the
//! def-status cache the handle holds. Being children they share the private
//! state this module declares — no other module of the crate can reach it.

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
use crate::error::TypeError;
use crate::eval::{eval_term, EvalCtx};
use crate::guest::GuestLinks;
use crate::value::{Env, SignedTerm, Sort, Value};
use crate::CoordinationWorld;

use engine::CheckedRule;
use memo::DefMemo;

/// The M5 `Vstream` factory the engine injects: a borrow-scoped op handle
/// minted off `&Kernel<W>` per call (driver construction is the engine's by
/// the composition contract, so M9 names `Vstream::new` nowhere; HRTB
/// because the handle borrows the kernel).
pub type VstreamFactory<W> = Box<dyn for<'k> Fn(&'k Kernel<W>) -> Vstream<'k, W> + Send + Sync>;

/// The M7 `LinkWriter` factory the engine injects: a writer over the kernel
/// AT A VISIBILITY CLASS (lane 3.3b). Called only by
/// [`Coordinator::link_writer`], which hands it the coordinator's `guest`
/// predicate, so the value-keyed gates of every fire and every def write run
/// at guest class.
pub type LinkWriterFactory<W> =
    Box<dyn for<'k> Fn(&'k Kernel<W>, &'k Visibility<'k, W>) -> LinkWriter<'k, W> + Send + Sync>;

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
    /// document is readable at guest class — the engine supplies
    /// `World::readable_guest`. It is applied THREE ways, each by one
    /// element:
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
    ///   built AT this class ([`Coordinator::link_writer`] lends this closure
    ///   to `mk_link_writer`), so M7's idempotency and dedup lookups see only
    ///   guest-readable incumbents and a fire commits byte-identically to a
    ///   world with no drafts.
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
    /// Infallible: the registry's population is the compiled shipped five
    /// (owner ruling, 2026-08-26), so the projection is a pure read of the
    /// injected registry and there is no twice-passed configuration whose
    /// drift a validate-once-or-fail step would catch.
    ///
    /// `guest` is the GUEST-class read predicate (lane 3.3 §5): the engine
    /// passes `World::readable_guest`. It decides three things, so an
    /// assembler choosing it chooses all three: what every PL verdict sees
    /// (lane 4.1 — a tuple homed where it answers `false` is invisible to
    /// `eval`, `evaluate_def` and every rule's domain and trigger); which
    /// fires are refused before any deposit (`FireError::DraftBoundary`, lane
    /// 3.3); and what M7's value-keyed gates see at every write M9 makes
    /// (PUB-6.28, lane 3.3b).
    ///
    /// OBLIGATIONS ON THE THREE INJECTED VALUES, owed by the assembler and
    /// uncheckable here: each factory must build its handle over EXACTLY the
    /// arguments it is handed — `mk_vstream` over the `&Kernel<W>` given,
    /// `mk_link_writer` over that kernel AND that `&Visibility` — never over
    /// a captured one; and `guest` must be a pure function of `(world, doc)`,
    /// reading nothing outside the world it is passed. M9's
    /// one-pinned-snapshot verdicts and lane 3.3b's byte-identical commit
    /// rest on both: a predicate consulting state outside its world would
    /// give one verdict two visibility answers for one document, and a
    /// factory capturing its own kernel or its own visibility class would
    /// type-check and void the guarantee in silence.
    ///
    /// And `guest` must be TOTAL over every `&Address` M9 hands it, which is
    /// not only registered documents: a fire consults it on the action's HOME
    /// before M7's H-HOME gate has run — so on an address this crate has not
    /// established to be a registered document — and on `document_of` of the
    /// bound argument, falling back to the argument itself when it has no
    /// document field. It must ANSWER for any of those, never panic, and
    /// `false` is the safe answer for an address it does not recognize. The
    /// engine's `World::readable_guest` is total by construction: it answers
    /// through the engine's `World::published`, which answers for any address
    /// — fail-open where M3's `published` is fail-private, an address no mint
    /// produced reading published. That is safe here as well: such an address
    /// is no draft, so no boundary is crossed, and as a home it is refused by
    /// M7's H-HOME.
    pub fn new(
        kernel: Arc<Kernel<W>>,
        registry: Arc<TypeRegistry>,
        mk_vstream: VstreamFactory<W>,
        mk_link_writer: LinkWriterFactory<W>,
        guest: Box<Visibility<'static, W>>,
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
            guest,
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
    /// at the term view `view`: the catalog, M3, and M7 THROUGH THE
    /// GUEST-CLASS VIEW (`GuestLinks`, PUB round 2, lane 4.1 — every tuple
    /// homed where the injected `guest` predicate answers `false` is dropped
    /// from every read). The ONE construction site in the crate:
    /// `eval`/`decide`, the rule engine's domain enumeration, trigger
    /// evaluation and scope test, the fire's own re-check, and
    /// `evaluate_def`'s denotation all build their context here, so no
    /// evaluator ever reads the link store class-free.
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
    /// guest-readable incumbents and no write can be built class-free.
    fn link_writer(&self) -> LinkWriter<'_, W> {
        (self.mk_link_writer)(self.kernel.as_ref(), &*self.guest)
    }

    // ──────────────────── A. The predicate language ────────────────────

    /// Type-check `body` under the ordered parameter context `params` (Γ_D —
    /// ASN-0129 WT is a Γ-parameterized CHECKING judgment; empty for a closed
    /// term), expand `Reg`-quantifiers to concrete-class instances (V-IDX),
    /// and reject ill-typed / dangling-reference / uncataloged-type-key /
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
    /// refused at the bound, not after it. Reads no structural state for a
    /// ref-free body; consults the def memo for any `Ref`, and on a MISS
    /// derives the referent from its immutable content, pinning its own
    /// snapshot — the answer is the same either way. Once `Ok`, valid at
    /// every reachable state (WT).
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
    /// before it is matched against its formal, so an arity mismatch (a
    /// `SortMismatch`) speaks at the first unmatched position; a `Reg`
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
        Ok(TriggerTerm::new(t))
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
    /// a referent with no defined signature is `DanglingReference`, and one
    /// whose derivation cannot complete at that level is `TooDeep`, with the
    /// referent left unjudged.
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
    /// snapshot. PRECONDITIONS, all asserted at the door: `t.is_ref_free()`
    /// — a surviving `Ref` node is a precondition violation (PANICS, like
    /// `decide` on a non-Bool codomain); ref-bearing terms evaluate only
    /// through `evaluate_def`, keeping this denotation content-free — and
    /// `env` binds every Γ_D parameter at its sort, an `AddrSet` holding
    /// T4-valid addresses only (the evaluator lifts each set element to an
    /// `Address` at its binding sites). INFALLIBLE past the door; reads ONLY
    /// M7 + M3, all off `snap` (PC4 / ASN-0134 clause 6) — M7 through the
    /// GUEST-CLASS view (lane 4.1, PUB-6.28): a tuple homed in a document
    /// the injected `guest` predicate refuses is invisible to the verdict,
    /// exactly as it is to a fire's gates. The verdict is "as of
    /// `snap.seq()`" (M2 V1 retrospective).
    ///
    /// Each precondition has a PUBLIC discharge point, so a caller can check
    /// what it owes before it calls: [`TypedTerm::is_ref_free`],
    /// [`TypedTerm::params`] against [`Value::sort`], and
    /// [`Value::holds_addresses`].
    pub fn eval(&self, t: &TypedTerm, env: &Env, view: View, snap: &Snapshot<W>) -> Value {
        assert!(
            t.is_ref_free(),
            "eval precondition violated: ref-bearing TypedTerm — route through evaluate_def"
        );
        for (v, s) in t.params() {
            let bound = env.get(v);
            assert!(
                bound.is_some_and(|val| val.sort() == *s),
                "eval precondition violated: Γ_D parameter {v:?} unbound or mis-sorted in env (expected {s:?})"
            );
            assert!(
                bound.is_some_and(Value::holds_addresses),
                "eval precondition violated: AddrSet parameter {v:?} holds a tumbler that is not a T4-valid address"
            );
        }
        let cx = self.eval_ctx(snap.world(), view, None);
        eval_term(&cx, env, t.evaluable())
    }

    /// Convenience for Bool-codomain terms; panics if the codomain is not
    /// Bool, or on any of `eval`'s preconditions.
    pub fn decide(&self, t: &TypedTerm, env: &Env, view: View, snap: &Snapshot<W>) -> bool {
        assert!(
            t.result_sort() == Sort::Bool,
            "decide precondition violated: codomain is {:?}, not Bool",
            t.result_sort()
        );
        match self.eval(t, env, view, snap) {
            Value::Bool(b) => b,
            other => unreachable!("Bool-codomain term denoted {other:?}"),
        }
    }

    /// Static footprint + 4-point stability lattice + the three active-view
    /// exceptions + view-independence flag, computed RELATIVE TO `view` (PC3
    /// binds the view-parameterized constituents to it); `view_independent`
    /// alone is view-agnostic (the PR-VIEW scan). Sound-but-incomplete; never
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
