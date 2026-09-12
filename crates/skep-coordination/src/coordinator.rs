//! §Public interface — the one handle. All capability groups hang off
//! [`Coordinator<W>`] over the engine's `Arc<Kernel<W>>`. M9 contributes no
//! `WorldState` slice and no record variant — it is a pure orchestrator/
//! evaluator; everything it holds is a recomputable hint or an in-memory
//! working set (§Core data model).

use std::sync::Arc;

use skep_address::Address;
use skep_arrangement::{HasM5, M5Rec, Vstream};
use skep_content::{ContentWrite, HasContent};
use skep_kernel::{Kernel, Snapshot, WorldState};
use skep_links::{
    Endset, HasLinks, LinkRec, LinkWriter, ShippedType, TypeRegistry, View, Visibility,
};
use skep_namespace::{HasM3, M3Rec};

use crate::ast::{Term, VarId};
use crate::catalog::TypeCatalog;
use crate::check::{Checker, Ctx, TriggerTerm, TypedTerm};
use crate::defs::parse_def;
use crate::dynamics::{classify_term, Dynamics};
use crate::error::TypeError;
use crate::eval::{eval_term, DefSource, EvalCtx};
use crate::guest::GuestLinks;
use crate::memo::{Breach, DefMemo, DefStatus};
use crate::rule::RuleId;
use crate::value::{value_sort, Env, Signature, Sort, Value};

/// One registered rule in the working set (§Internal 5): the checked
/// `TypedDom`, the checked trigger, the declared view, the action.
pub(crate) struct CheckedRule {
    pub(crate) id: RuleId,
    pub(crate) dom: crate::check::TypedDom,
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
    pub(crate) action: crate::rule::FireAction,
}

/// Breach-only recursion bound on the signature derivation: a legitimately
/// registered def's reference DAG is acyclic (PR2 — refs name strictly-earlier
/// defs), so this trips only on a PR-DISC-breach cycle, where returning
/// "no signature yet" makes the outer derivation fail WT and freeze the start
/// poisoned (§Internal 4). The depth is a property of the derivation CHAIN
/// and travels with it: each derivation resolves its referents one level
/// deeper than itself.
const MAX_SIG_DEPTH: u32 = 512;

/// M9's one public handle: PL (group A), predicate definitions (group B), and
/// the reactive rule engine (group C). Owns no authoritative state — the
/// `DefMemo` is an interior-mutable recomputable hint; the rule registry
/// and rotation cursor are the `&mut self` working set.
#[allow(clippy::type_complexity)] // the factory fields carry the interface's types verbatim
pub struct Coordinator<W: WorldState> {
    pub(crate) kernel: Arc<Kernel<W>>,
    pub(crate) catalog: TypeCatalog,
    pub(crate) memo: DefMemo,
    pub(crate) rules: Vec<CheckedRule>,
    pub(crate) next_rule: u64,
    pub(crate) cursor: usize,
    pub(crate) mk_vstream: Box<dyn for<'k> Fn(&'k Kernel<W>) -> Vstream<'k, W> + Send + Sync>,
    /// The M7 write-handle factory: a writer over the kernel AT A VISIBILITY
    /// CLASS (lane 3.3b). Called only by [`Coordinator::link_writer`], which
    /// hands it `guest`, so the value-keyed gates of every fire and every
    /// def write run at guest class.
    pub(crate) mk_link_store: Box<
        dyn for<'k> Fn(&'k Kernel<W>, &'k Visibility<'k, W>) -> LinkWriter<'k, W> + Send + Sync,
    >,
    /// The GUEST-class read predicate over a document address (PUB round 2,
    /// lane 3.3, §5): `true` iff the document is readable at guest class —
    /// the engine supplies `published(doc)`. A fire consults it, off the
    /// fire's own pinned snapshot, on the action's HOME and on the bound
    /// argument's document before any deposit, so a rule's effect never
    /// crosses the draft boundary in either direction (a marker on a draft's
    /// content, or a deposit into a draft home). And every `LinkWriter` M9
    /// builds is built AT this class (lane 3.3b, PUB-6.28): the same closure
    /// is lent to `mk_link_store`, so M7's idempotency and dedup lookups see
    /// only guest-readable incumbents and a fire commits byte-identically to
    /// a world with no drafts. M9 holds no publication state of its own —
    /// the predicate is injected like the factories.
    pub(crate) guest: Box<dyn Fn(&W, &Address) -> bool + Send + Sync>,
}

impl<W> Coordinator<W>
where
    W: WorldState + HasLinks + HasM3 + HasContent + HasM5,
    W::Record: From<LinkRec> + From<M5Rec> + From<M3Rec> + From<ContentWrite>,
{
    /// Engine-assembled construction. Receives the shared kernel; the ONE
    /// engine-built `Arc<TypeRegistry>` (NEVER rebuilt here — Conflicts §7),
    /// which M9 projects its static `TypeCatalog` from and then need not
    /// retain; and two op-handle factories minting a borrow-scoped
    /// `Vstream`/`LinkWriter` off `&Kernel<W>` per call (driver construction
    /// is the engine's by the composition contract, so M9 names neither
    /// `Vstream::new` nor `LinkWriter::new`; HRTB because each handle
    /// borrows the kernel). The `LinkWriter` factory takes the VISIBILITY
    /// class beside the kernel (lane 3.3b): M9 lends it `guest` at every
    /// construction, a borrow of the one closure it holds.
    ///
    /// Infallible: the registry's population is the compiled shipped five
    /// (owner ruling, 2026-08-26), so the projection is a pure read of the
    /// injected registry and there is no twice-passed configuration whose
    /// drift a validate-once-or-fail step would catch.
    ///
    /// `guest` is the GUEST-class read predicate (lane 3.3 §5): the engine
    /// passes `World::readable_guest`; a fire refuses, before any deposit,
    /// an action whose home or bound argument's document it answers `false`
    /// for (`FireError::DraftBoundary`), and every write M9 makes runs its
    /// value-keyed gates at this class (PUB-6.28).
    #[allow(clippy::type_complexity)] // the factory types are the interface's, verbatim
    pub fn new(
        kernel: Arc<Kernel<W>>,
        registry: Arc<TypeRegistry>,
        mk_vstream: Box<dyn for<'k> Fn(&'k Kernel<W>) -> Vstream<'k, W> + Send + Sync>,
        mk_link_store: Box<
            dyn for<'k> Fn(&'k Kernel<W>, &'k Visibility<'k, W>) -> LinkWriter<'k, W>
                + Send
                + Sync,
        >,
        guest: Box<dyn Fn(&W, &Address) -> bool + Send + Sync>,
    ) -> Coordinator<W> {
        let catalog = TypeCatalog::project(&registry);
        Coordinator {
            kernel,
            catalog,
            memo: DefMemo::new(),
            rules: Vec::new(),
            next_rule: 1,
            cursor: 0,
            mk_vstream,
            mk_link_store,
            guest,
        }
    }

    /// M9's own cached catalog accessor (no snapshot) — the `&Endset` every
    /// `emit(d, reserved_type(…), …)` / PL `TypeKey` construction reads.
    /// Distinct from M7's snapshot-bound `LinkState::reserved_type`, and
    /// byte-identical to it: the catalog is a projection of the same
    /// registry.
    pub fn reserved_type(&self, t: ShippedType) -> &Endset {
        self.catalog.reserved(t)
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
    pub(crate) fn eval_ctx<'a>(
        &'a self,
        w: &'a W,
        view: View,
        defs: Option<&'a dyn DefSource>,
    ) -> EvalCtx<'a, W> {
        EvalCtx {
            catalog: &self.catalog,
            links: GuestLinks::new(w, w.links(), &*self.guest),
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
    pub(crate) fn link_writer(&self) -> LinkWriter<'_, W> {
        (self.mk_link_store)(self.kernel.as_ref(), &*self.guest)
    }

    // ──────────────────── A. The predicate language ────────────────────

    /// Type-check `body` under the ordered parameter context `params` (Γ_D —
    /// ASN-0129 WT is a Γ-parameterized CHECKING judgment; empty for a closed
    /// term), expand `Reg`-quantifiers to concrete-class instances (V-IDX),
    /// and reject ill-typed / dangling-reference / unregistered-type /
    /// unbound-variable / non-Codomain-parameter terms. Γ_D is Codom-only: a
    /// `Tup`-sorted parameter is `TupParameter` — a stored def binds values,
    /// never a tuple (ASN-0130 SignedTerm) — and the one PL term that binds a
    /// tuple, a rule trigger, is checked by [`Coordinator::type_check_trigger`]
    /// into a type of its own. Every `Concrete` `TypeKey` must be a canonical
    /// catalog endset (the probe is `Endset`-equality, not coverage). Reads
    /// no structural state for a ref-free body; consults the immutable
    /// signature memo for any `Ref`. Once `Ok`, valid at every reachable
    /// state (WT).
    pub fn type_check(&self, params: Vec<(VarId, Sort)>, body: Term) -> Result<TypedTerm, TypeError> {
        if let Some((v, _)) = params.iter().find(|(_, s)| *s == Sort::Tup) {
            return Err(TypeError::TupParameter(v.clone()));
        }
        self.check_under(params, body, 0)
    }

    /// Type-check a RULE TRIGGER: `body` under the one parameter `param` (any
    /// sort, `Tup` included — a tuple-domained rule fires by binding a
    /// `Value::Tuple`, ASN-0133 ρ_R), Bool codomain (`SortMismatch`
    /// otherwise). The domain↔parameter sort reconciliation and the ref-free
    /// requirement are `register_rule`'s.
    pub fn type_check_trigger(&self, param: (VarId, Sort), body: Term) -> Result<TriggerTerm, TypeError> {
        let t = self.check_under(vec![param], body, 0)?;
        if t.result != Sort::Bool {
            return Err(TypeError::SortMismatch { expected: Sort::Bool, found: t.result });
        }
        Ok(TriggerTerm(t))
    }

    /// The ONE checker invocation: WT + WT-ref over `body` under Γ_D
    /// `params`, into the checked-term shape. Referents resolve through the
    /// signature memo at derivation depth `depth` — 0 at the top of a chain
    /// (the public checks, `register_pred`), one deeper per nested
    /// derivation (a chain that runs past `MAX_SIG_DEPTH` is a PR-DISC-breach
    /// cycle and reads as "no signature", failing WT here).
    pub(crate) fn check_under(
        &self,
        params: Vec<(VarId, Sort)>,
        body: Term,
        depth: u32,
    ) -> Result<TypedTerm, TypeError> {
        let resolve = |a: &Address| self.signature_at(a, depth);
        let checker = Checker { catalog: &self.catalog, resolve: &resolve };
        let ctx: Ctx = params.iter().cloned().collect();
        let checked = checker.check_term(&ctx, &body)?;
        Ok(TypedTerm {
            gamma: params,
            result: checked.sort,
            source: body,
            evaluable: checked.term,
            ref_free: checked.ref_free,
        })
    }

    /// Pure, total, terminating denotation at one view against one committed
    /// snapshot. PRECONDITIONS, both asserted at the door: `t.is_ref_free()`
    /// — a surviving `Ref` node is a precondition violation (PANICS, like
    /// `decide` on a non-Bool codomain); ref-bearing terms evaluate only
    /// through `evaluate_def`, keeping this denotation content-free — and
    /// `env` binds every Γ_D parameter at its sort. INFALLIBLE past the door;
    /// reads ONLY M7 + M3, all off `snap` (PC4 / ASN-0134 clause 6) — M7
    /// through the GUEST-CLASS view (lane 4.1, PUB-6.28): a tuple homed in a
    /// document the injected `guest` predicate refuses is invisible to the
    /// verdict, exactly as it is to a fire's gates. The verdict is "as of
    /// `snap.seq()`" (M2 V1 retrospective).
    pub fn eval(&self, t: &TypedTerm, env: &Env, view: View, snap: &Snapshot<W>) -> Value {
        assert!(
            t.is_ref_free(),
            "eval precondition violated: ref-bearing TypedTerm — route through evaluate_def"
        );
        for (v, s) in &t.gamma {
            assert!(
                env.get(v).is_some_and(|val| value_sort(val) == *s),
                "eval precondition violated: Γ_D parameter {v:?} unbound or mis-sorted in env (expected {s:?})"
            );
        }
        let cx = self.eval_ctx(snap.world(), view, None);
        eval_term(&cx, env, t.evaluable.as_ref())
    }

    /// Convenience for Bool-codomain terms; panics if the codomain is not
    /// Bool, or on either of `eval`'s preconditions.
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
             which flattens the reference expansion"
        );
        classify_term(&self.catalog, view, t.evaluable.as_ref())
    }

    // ───────────────── internal: the DefMemo (§Internal 4) ─────────────────

    /// Memo-or-derive at the top of a derivation chain.
    pub(crate) fn def_status(&self, start: &Address) -> DefStatus {
        self.def_status_at(start, 0)
    }

    /// Memo-or-derive as the `depth`-th nested derivation: a memo hit answers
    /// at any depth; past the breach-only bound the answer is "no signature"
    /// (never memoized — the outer derivation freezes poisoned, not this
    /// one); otherwise derive from immutable content.
    fn def_status_at(&self, start: &Address, depth: u32) -> DefStatus {
        if let Some(hit) = self.memo.get(start) {
            return hit;
        }
        if depth >= MAX_SIG_DEPTH {
            return DefStatus::Unregistered;
        }
        self.derive_def(start, depth)
    }

    /// The miss path: pin its OWN snapshot to check ever-registration (a
    /// never-registered start is never cached — a later registration must
    /// surface), then derive from immutable content, recursing through
    /// referent signatures one level deeper (well-founded by PR2). An
    /// ever-registered start whose content fails the parse or WT fills the
    /// memo poisoned — freeze-on-breach (PR-DISC, §Internal 4).
    fn derive_def(&self, start: &Address, depth: u32) -> DefStatus {
        let snap = self.kernel.snapshot();
        let w = snap.world();
        if !self.ever_registered(w, start) {
            return DefStatus::Unregistered;
        }
        let verdict = parse_def(w, start)
            .map_err(|_| Breach)
            .and_then(|(params, body)| self.check_under(params, body, depth + 1).map_err(|_| Breach));
        self.memo.fill(start, verdict)
    }

    /// `(Γ_D, C_D)` at derivation depth `depth` — the resolver the checker
    /// consults for a `Ref`.
    fn signature_at(&self, start: &Address, depth: u32) -> Option<Signature> {
        match self.def_status_at(start, depth) {
            DefStatus::Defined(e) => Some(e.signature()),
            _ => None,
        }
    }

    /// `(Γ_D, C_D)` — defined-signature starts only; answered from the
    /// immutable DefMemo. A `Some` is permanent and cacheable forever
    /// (content immutable, ever-registration monotone); a never-registered
    /// `None` is transient and never memoized; an ever-registered-but-
    /// undisciplined start answers `None` via a PERMANENT poisoned entry
    /// (freeze-on-breach, §Internal 4). No snapshot parameter — the miss
    /// path pins its own.
    pub fn signature(&self, start: &Address) -> Option<Signature> {
        self.signature_at(start, 0)
    }
}

/// The referent supplier for the DAG-recursive drivers (a def's denotation,
/// the flat expansion) — the content-read pass stays distinct from the
/// structural denotation, so the denotation remains reference-free
/// (Conflicts §5).
impl<W> DefSource for Coordinator<W>
where
    W: WorldState + HasLinks + HasM3 + HasContent + HasM5,
    W::Record: From<LinkRec> + From<M5Rec> + From<M3Rec> + From<ContentWrite>,
{
    fn resolve_def(&self, addr: &Address) -> Option<Arc<TypedTerm>> {
        match self.def_status(addr) {
            DefStatus::Defined(e) => Some(e),
            _ => None,
        }
    }
}
