//! §Public interface — the one handle. All capability groups hang off
//! [`Coordinator<W>`] over the engine's `Arc<Kernel<W>>`. M9 contributes no
//! `WorldState` slice and no record variant — it is a pure orchestrator/
//! evaluator; everything it holds is a recomputable hint or an in-memory
//! working set (§Core data model).

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use skep_address::{Address, Tumbler};
use skep_arrangement::{HasM5, M5Rec, Vstream};
use skep_content::{ContentWrite, HasContent};
use skep_kernel::{Kernel, Snapshot, WorldState};
use skep_links::{
    Endset, HasLinks, LinkRec, LinkStore, ReservedAddrs, ShippedType, TypeDecl, TypeRegistry, View,
};
use skep_namespace::{HasM3, M3Rec};

use crate::ast::{Term, VarId};
use crate::catalog::TypeCatalog;
use crate::check::{Checker, Ctx, TypedTerm};
use crate::codec;
use crate::dynamics::{classify_term, Dynamics};
use crate::error::{CatalogError, TypeError};
use crate::eval::{eval_term, DefSource, EvalCtx};
use crate::rule::RuleId;
use crate::value::{Env, Signature, Sort, Value};

/// A derived, immutable-once-defined def hint: the checked signature and the
/// `Reg`-expanded evaluable body (§Core data model, DefMemo).
pub(crate) struct DefEntry {
    pub(crate) sig: Signature,
    pub(crate) expanded: crate::ast::ArcTerm,
}

/// A memo cell: `Defined` and `Poisoned` are both PERMANENT (content
/// immutable, ever-registration monotone; freeze-on-breach for the poison —
/// §Internal 4). A never-registered start is never cached.
pub(crate) enum MemoEntry {
    Defined(Arc<DefEntry>),
    Poisoned,
}

/// A def-status answer, distinguishing CVALID (0)'s two `None` causes.
pub(crate) enum DefStatus {
    Defined(Arc<DefEntry>),
    Poisoned,
    Unregistered,
}

/// One registered rule in the working set (§Internal 5): the checked
/// `TypedDom`, the validated trigger, the declared view, the action.
pub(crate) struct CheckedRule {
    pub(crate) id: RuleId,
    pub(crate) dom: crate::check::TypedDom,
    pub(crate) trigger: CheckedTrigger,
    pub(crate) view: View,
    pub(crate) action: crate::rule::FireAction,
}

pub(crate) enum CheckedTrigger {
    Inline { param: VarId, term: TypedTerm },
    Def { addr: Address },
}

/// Breach-only recursion bound on the signature derivation: a legitimately
/// registered def's reference DAG is acyclic (PR2 — refs name strictly-earlier
/// defs), so this trips only on a PR-DISC-breach cycle, where returning
/// "no signature yet" makes the outer derivation fail WT and freeze the start
/// poisoned (§Internal 4).
const MAX_SIG_DEPTH: u32 = 512;

std::thread_local! {
    static SIG_DEPTH: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

/// M9's one public handle: PL (group A), predicate definitions (group B), and
/// the reactive rule engine (group C). Owns no authoritative state — the
/// `DefMemo` is an interior-mutable recomputable hint (a `RwLock`, never a
/// `RefCell`: the `&self` signature/define paths of a shared `Coordinator`
/// need `Sync`); the rule registry and rotation cursor are the `&mut self`
/// working set.
#[allow(clippy::type_complexity)] // the factory fields carry the interface's types verbatim
pub struct Coordinator<W: WorldState> {
    pub(crate) kernel: Arc<Kernel<W>>,
    pub(crate) catalog: TypeCatalog,
    pub(crate) memo: RwLock<HashMap<Tumbler, MemoEntry>>,
    pub(crate) rules: Vec<CheckedRule>,
    pub(crate) next_rule: u64,
    pub(crate) cursor: usize,
    pub(crate) mk_vstream: Box<dyn for<'k> Fn(&'k Kernel<W>) -> Vstream<'k, W> + Send + Sync>,
    pub(crate) mk_link_store: Box<dyn for<'k> Fn(&'k Kernel<W>) -> LinkStore<'k, W> + Send + Sync>,
}

impl<W> Coordinator<W>
where
    W: WorldState + HasLinks + HasM3 + HasContent + HasM5,
    W::Record: From<LinkRec> + From<M5Rec> + From<M3Rec> + From<ContentWrite>,
{
    /// Engine-assembled construction. Receives the shared kernel; the ONE
    /// engine-built `Arc<TypeRegistry>` behind the genesis-sealed config
    /// (NEVER rebuilt here — Conflicts §7), which M9 projects its static
    /// `TypeCatalog` from and then need not retain; the `(reserved, decls)`
    /// pair naming the app type-key endsets and the five `ShippedType`
    /// endsets for that projection; and two op-handle factories minting a
    /// borrow-scoped `Vstream`/`LinkStore` off `&Kernel<W>` per call (the
    /// engine — the one crate that can name those constructors — supplies
    /// them; HRTB because each handle borrows the kernel).
    ///
    /// The catalog projection is VALIDATE-ONCE-OR-FAIL (mirroring genesis):
    /// each `enc(&[reserved.X])` must be coverage-equal to the injected
    /// registry's own `reserved(X)` and each decls key must hold a
    /// registration in that registry — a miss fails construction with
    /// [`CatalogError`], so residual drift of the twice-passed pair is caught
    /// at assembly, never as a spurious `UnregisteredType` at type-check.
    #[allow(clippy::type_complexity)] // the factory types are the interface's, verbatim
    pub fn new(
        kernel: Arc<Kernel<W>>,
        registry: Arc<TypeRegistry>,
        reserved: ReservedAddrs,
        decls: Vec<TypeDecl>,
        mk_vstream: Box<dyn for<'k> Fn(&'k Kernel<W>) -> Vstream<'k, W> + Send + Sync>,
        mk_link_store: Box<dyn for<'k> Fn(&'k Kernel<W>) -> LinkStore<'k, W> + Send + Sync>,
    ) -> Result<Coordinator<W>, CatalogError> {
        let catalog = TypeCatalog::project(&registry, &reserved, &decls)?;
        Ok(Coordinator {
            kernel,
            catalog,
            memo: RwLock::new(HashMap::new()),
            rules: Vec::new(),
            next_rule: 1,
            cursor: 0,
            mk_vstream,
            mk_link_store,
        })
    }

    /// M9's own cached catalog accessor (no snapshot) — the `&Endset` every
    /// `emit(d, reserved_type(…), …)` / PL `TypeKey` construction reads.
    /// Distinct from M7's snapshot-bound `LinkState::reserved_type`;
    /// coverage-equal to it by the construction-time validation.
    pub fn reserved_type(&self, t: ShippedType) -> &Endset {
        self.catalog.reserved(t)
    }

    // ──────────────────── A. The predicate language ────────────────────

    /// Type-check `body` under the ordered parameter context `params` (Γ_D —
    /// ASN-0129 WT is a Γ-parameterized CHECKING judgment; empty for a closed
    /// term), expand `Reg`-quantifiers to concrete-class instances (V-IDX),
    /// and reject ill-typed / dangling-reference / unregistered-type /
    /// unbound-variable / non-Codomain-parameter terms. This is the DEF-PATH
    /// check: a `Tup`-sorted Γ_D parameter is `TupParameter` — a stored def
    /// binds values, never a tuple (ASN-0130 SignedTerm); a rule trigger uses
    /// [`Coordinator::type_check_trigger`]. Every `Concrete` `TypeKey` must
    /// be a canonical catalog endset (the probe is `Endset`-equality, not
    /// coverage). Reads no structural state for a ref-free body; consults the
    /// immutable signature memo for any `Ref`. Once `Ok`, valid at every
    /// reachable state (WT).
    pub fn type_check(&self, params: Vec<(VarId, Sort)>, body: Term) -> Result<TypedTerm, TypeError> {
        if let Some((v, _)) = params.iter().find(|(_, s)| *s == Sort::Tup) {
            return Err(TypeError::TupParameter(v.clone()));
        }
        self.check_under(params, body)
    }

    /// As [`Coordinator::type_check`], but for a RULE TRIGGER — the only PL
    /// term that may bind a tuple: admits a SINGLE `Tup`-sorted parameter (a
    /// tuple-domained rule fires by binding a `Value::Tuple`, ASN-0133 ρ_R);
    /// every other parameter stays Codom-only. One-parameter-Bool is still a
    /// `register_rule` check, not enforced here.
    pub fn type_check_trigger(&self, params: Vec<(VarId, Sort)>, body: Term) -> Result<TypedTerm, TypeError> {
        let mut tups = params.iter().filter(|(_, s)| *s == Sort::Tup);
        let _first = tups.next();
        if let Some((v, _)) = tups.next() {
            return Err(TypeError::TupParameter(v.clone()));
        }
        self.check_under(params, body)
    }

    fn check_under(&self, params: Vec<(VarId, Sort)>, body: Term) -> Result<TypedTerm, TypeError> {
        let resolve = |a: &Address| self.signature(a);
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
    /// snapshot. PRECONDITION: `t.is_ref_free()` — a surviving `Ref` node is
    /// a precondition violation (PANICS, like `decide` on a non-Bool
    /// codomain); ref-bearing terms evaluate only through `evaluate_def`,
    /// keeping this denotation content-free. INFALLIBLE on a ref-free
    /// `TypedTerm`; reads ONLY M7 + M3, all off `snap` (PC4 / ASN-0134
    /// clause 6). The verdict is "as of `snap.seq()`" (M2 V1 retrospective).
    pub fn eval(&self, t: &TypedTerm, env: &Env, view: View, snap: &Snapshot<W>) -> Value {
        assert!(
            t.is_ref_free(),
            "eval precondition violated: ref-bearing TypedTerm — route through evaluate_def"
        );
        let w = snap.world();
        let cx = EvalCtx { catalog: &self.catalog, links: w.links(), m3: w.m3(), defs: None };
        eval_term(&cx, env, view, t.evaluable.as_ref())
    }

    /// Convenience for Bool-codomain terms; panics if the codomain is not
    /// Bool or `t` is ref-bearing.
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
    /// otherwise — callers classify inline triggers or a flattened expand).
    pub fn classify(&self, t: &TypedTerm, view: View) -> Dynamics {
        assert!(
            t.is_ref_free(),
            "classify precondition violated: ref-bearing TypedTerm — certify via certify_stable, \
             which flattens the reference expansion"
        );
        classify_term(&self.catalog, view, t.evaluable.as_ref())
    }

    // ───────────────── internal: the DefMemo (§Internal 4) ─────────────────

    /// Memo-or-derive: `Some`-or-permanent-poisoned only; a never-registered
    /// start is never cached (a later registration must surface). The
    /// miss-path pins its OWN snapshot to check ever-registration
    /// (`is_K(pdef, start)@audit` through the one `observe`-honors-`Audit`
    /// seam), then derives from immutable content, recursing through referent
    /// signatures (well-founded by PR2). Concurrent fills race only to write
    /// the same value.
    pub(crate) fn def_status(&self, start: &Address) -> DefStatus {
        {
            let memo = self.memo.read().expect("DefMemo lock");
            if let Some(e) = memo.get(start.tumbler()) {
                return match e {
                    MemoEntry::Defined(d) => DefStatus::Defined(Arc::clone(d)),
                    MemoEntry::Poisoned => DefStatus::Poisoned,
                };
            }
        }

        let depth = SIG_DEPTH.with(|d| {
            let v = d.get();
            d.set(v + 1);
            v
        });
        let status = if depth >= MAX_SIG_DEPTH {
            // Breach-only cycle bound: answer "no signature" without
            // memoizing; the outer derivation fails WT and freezes poisoned.
            DefStatus::Unregistered
        } else {
            self.derive_def(start)
        };
        SIG_DEPTH.with(|d| d.set(d.get() - 1));
        status
    }

    fn derive_def(&self, start: &Address) -> DefStatus {
        let snap = self.kernel.snapshot();
        let w = snap.world();
        let pdef = self.catalog.reserved(ShippedType::PredDef);
        let ever = !w
            .links()
            .observe(pdef, std::slice::from_ref(start.tumbler()), &[], View::Audit)
            .is_empty();
        if !ever {
            return DefStatus::Unregistered; // transient — never memoized
        }
        let derived: Result<DefEntry, ()> = (|| {
            let val = w.content().value_at(start.tumbler()).ok_or(())?;
            let (params, body) = codec::decode(val.as_bytes()).map_err(|_| ())?;
            let resolve = |a: &Address| self.signature(a);
            let checker = Checker { catalog: &self.catalog, resolve: &resolve };
            let ctx: Ctx = params.iter().cloned().collect();
            let checked = checker.check_term(&ctx, &body).map_err(|_| ())?;
            Ok(DefEntry {
                sig: Signature { params, result: checked.sort },
                expanded: checked.term,
            })
        })();
        let mut memo = self.memo.write().expect("DefMemo lock");
        let entry = memo.entry(start.tumbler().clone()).or_insert_with(|| match derived {
            Ok(e) => MemoEntry::Defined(Arc::new(e)),
            // Ever-registered but unparseable/ill-typed: the permanent
            // poisoned entry — freeze-on-breach (PR-DISC, §Internal 4).
            Err(()) => MemoEntry::Poisoned,
        });
        match entry {
            MemoEntry::Defined(d) => DefStatus::Defined(Arc::clone(d)),
            MemoEntry::Poisoned => DefStatus::Poisoned,
        }
    }

    /// Memoize a freshly-derived entry from the `register_pred` validation
    /// path (immutable-once-defined; racing fills write the same value).
    pub(crate) fn memo_defined(&self, start: &Address, entry: DefEntry) {
        let mut memo = self.memo.write().expect("DefMemo lock");
        memo.entry(start.tumbler().clone())
            .or_insert_with(|| MemoEntry::Defined(Arc::new(entry)));
    }
}

/// `evaluate_def`'s DAG-recursive driver resolves referents here — the
/// content-read pass stays distinct from the structural denotation, so the
/// denotation remains reference-free (Conflicts §5).
impl<W> DefSource for Coordinator<W>
where
    W: WorldState + HasLinks + HasM3 + HasContent + HasM5,
    W::Record: From<LinkRec> + From<M5Rec> + From<M3Rec> + From<ContentWrite>,
{
    fn resolve_def(&self, addr: &Address) -> Option<(Vec<(VarId, Sort)>, crate::ast::ArcTerm)> {
        match self.def_status(addr) {
            DefStatus::Defined(e) => Some((e.sig.params.clone(), e.expanded.clone())),
            _ => None,
        }
    }
}
