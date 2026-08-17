//! §B / §Internal 4 — predicate definitions as content (self-hosting
//! persistence): store + register (gate-first, idem dedup at M7), resolution/
//! signature/expansion hints, versioning over the shipped `supersedes` class,
//! ST⁺ certification, and de-registration. M9 drives no `transact` — every
//! write rides M5's placement composite or M7's gated `emit`/`nullify`.

use std::slice;
use std::sync::Arc;

use skep_address::{Address, Nat};
use skep_arrangement::{HasM5, M5Rec, VPos};
use skep_content::{ContentWrite, HasContent, Val};
use skep_kernel::{Seq, Snapshot, WorldState};
use skep_links::{Caller, HasLinks, LinkRec, ShippedType, Tip, View};
use skep_namespace::{HasM3, M3Rec};

use crate::ast::{collect_ref_addrs, Term, VarId};
use crate::check::{Checker, Ctx, TypedTerm};
use crate::codec;
use crate::coordinator::{Coordinator, DefEntry, DefStatus};
use crate::dynamics::{analyze_term, view_independent};
use crate::error::{CertifyError, DefineError, EvalError, RegisterError, RetractError};
use crate::eval::{eval_term, EvalCtx};
use crate::value::{value_sort, Env, Signature, Sort, Value};

/// `s_C` = 1 — the content-subspace numeral (ASN-0047 convention; the
/// workspace precedent keeps the axiom-pinned numeral crate-local).
fn s_c() -> Nat {
    Nat::from(1u32)
}

impl<W> Coordinator<W>
where
    W: WorldState + HasLinks + HasM3 + HasContent + HasM5,
    W::Record: From<LinkRec> + From<M5Rec> + From<M3Rec> + From<ContentWrite>,
{
    /// Encode `term`'s COMPACT pre-`Reg`-expansion body (with its Γ_D) to one
    /// content `Val` (n = 1 — Conflicts §2), write it through M5's placement
    /// composite (mint + write + place + R, atomically — J0/J1★), then
    /// validate + register the `pdef`. Returns the def IDENTITY (content
    /// start address) and the `pdef` EMIT's commit `Seq` — NOT the insert's.
    ///
    /// Rejects a `Tup`-sorted Γ_D parameter UP FRONT, before any insert
    /// (`DefineError::TupParameter` — stored-def params are Codom-only,
    /// ASN-0130 SignedTerm). Under concurrency: a concurrent INSERT lands the
    /// def mid-document (harmless — identity is the returned start); a
    /// concurrent DELETE yields a retryable `Insert(Rejected(OutOfBounds))` —
    /// benign, recompute and re-insert (item 6; the design's `BadPosition`,
    /// split by the as-built M5); a `register_pred`-stage failure leaves
    /// harmless orphan content a later `register_pred(d, start)` adopts.
    pub fn define_predicate(&self, d: &Address, term: TypedTerm) -> Result<(Address, Seq), DefineError> {
        self.define_core(d, &term)
    }

    /// The shared define-style path (`define_predicate` + `supersede`'s
    /// successor registration).
    fn define_core(&self, d: &Address, term: &TypedTerm) -> Result<(Address, Seq), DefineError> {
        if let Some((v, _)) = term.params().iter().find(|(_, s)| *s == Sort::Tup) {
            return Err(DefineError::TupParameter(v.clone()));
        }
        // The codec's own Tup refusal backstops the check above (one shared
        // rejection surface — §Invariants).
        let blob = codec::encode(term.params(), term.source_body()).map_err(DefineError::TupParameter)?;
        // Insert position off a snapshot read; M5's insert re-validates
        // against committed state (benign TOCTOU — item 6).
        let n_c = self.kernel.snapshot().world().m5().content_count(d);
        let at = VPos { subspace: s_c(), ordinal: n_c + Nat::from(1u32) };
        let vs = (self.mk_vstream)(self.kernel.as_ref());
        // M9's writes run as `Caller::System` (the ownership ruling's
        // automation path, 2026-08-16): the coordination layer holds no wire
        // principal — M9 ⟂ M10 by architecture.
        let (start, _insert_seq) = vs.insert(Caller::System, d, at, vec![Val::new(blob)])?;
        let (_pdef_tuple, seq) = self.register_pred(d, &start)?;
        Ok((start, seq))
    }

    /// Validate (parse → Γ_D + body, WT + WT-ref, ever-registration of refs,
    /// endorsement, home-residence) the run already at `start` against ONE
    /// pinned snapshot σ, then emit the `pdef` tuple via M7 (a second
    /// transaction — sound because evaluation keys on ever-registration,
    /// never endorsement currency; §Internal 4 two-transaction soundness).
    /// Gate-first; idem⊤ dedup at M7 gives ≤1 active `pdef` per start (PR0).
    pub fn register_pred(&self, d: &Address, start: &Address) -> Result<(Address, Seq), RegisterError> {
        let snap = self.kernel.snapshot();
        let w = snap.world();
        // (0/i/ii) one Val, residence + extent + fully consumed.
        let val = w
            .content()
            .value_at(start.tumbler())
            .ok_or(RegisterError::NotResident)?;
        let (params, body) = codec::decode(val.as_bytes()).map_err(|_| RegisterError::ParseFailed)?;
        // (iii) every referent ever-registered at σ — is_K(pdef, r)@audit,
        // through the one observe-honors-Audit seam.
        let pdef = self.catalog.reserved(ShippedType::PredDef).clone();
        let mut refs = Vec::new();
        collect_ref_addrs(&body, &mut refs);
        for r in &refs {
            let ever = !w
                .links()
                .observe(&pdef, slice::from_ref(r.tumbler()), &[], View::Audit)
                .is_empty();
            if !ever {
                return Err(RegisterError::ReferentNotEverRegistered(r.clone()));
            }
        }
        // (iii) WT + WT-ref. Sigs via the resolver (memo-missing signature
        // calls pin their own snapshots — sound: the σ ever-gate ran first,
        // ever-registration is monotone, signature facts are
        // content-intrinsic).
        let resolve = |a: &Address| self.signature(a);
        let checker = Checker { catalog: &self.catalog, resolve: &resolve };
        let ctx: Ctx = params.iter().cloned().collect();
        let checked = checker.check_term(&ctx, &body).map_err(RegisterError::IllTyped)?;
        // (iv) endorsement: every referent ACTIVELY registered at σ.
        for r in &refs {
            if !w.links().is_k(&pdef, r.tumbler()) {
                return Err(RegisterError::ReferentNotActive(r.clone()));
            }
        }
        // (P0) home residence.
        if !w.m3().is_registered_document(d) {
            return Err(RegisterError::HomeNotRegistered);
        }
        // Valid ⇒ emit(d, [pdef], start, &[]) — Unary, |F| = 1; idem⊤ dedups
        // to ≤1 active pdef per start.
        let ls = (self.mk_link_store)(self.kernel.as_ref());
        let (tuple, seq) = ls.emit(Caller::System, d, &pdef, start, &[])?;
        // Memoize the freshly-derived hint (immutable-once-defined).
        self.memo_defined(start, DefEntry {
            sig: Signature { params, result: checked.sort },
            expanded: checked.term,
        });
        Ok((tuple, seq))
    }

    /// resolve + expand + denote. PRECONDITION: `start` EVER-registered (not
    /// active) against the caller's `snap` — else `NotEverRegistered`; an
    /// ever-registered start whose immutable content fails the PR-ENC
    /// parse/WT (a PR-DISC breach) is `UndisciplinedDef`. `args` bind
    /// positionally to Γ_D (= `signature(start).params`). Pure pin to `snap`;
    /// the denotation is DAG-recursive (`eval`'s walk + the one `Ref` arm),
    /// never a materialized flat term (Conflicts §5).
    pub fn evaluate_def(
        &self,
        start: &Address,
        args: &[Value],
        view: View,
        snap: &Snapshot<W>,
    ) -> Result<Value, EvalError> {
        let pdef = self.catalog.reserved(ShippedType::PredDef);
        let ever = !snap
            .world()
            .links()
            .observe(pdef, slice::from_ref(start.tumbler()), &[], View::Audit)
            .is_empty();
        if !ever {
            return Err(EvalError::NotEverRegistered);
        }
        let entry = match self.def_status(start) {
            DefStatus::Defined(e) => e,
            DefStatus::Poisoned => return Err(EvalError::UndisciplinedDef),
            // Ever at the caller's snap but not at the memo's own fresh pin
            // cannot happen (ever-registration is monotone); defensive.
            DefStatus::Unregistered => return Err(EvalError::NotEverRegistered),
        };
        if args.len() != entry.sig.params.len() {
            return Err(EvalError::ArgArityMismatch);
        }
        let mut env = Env::empty();
        for (arg, (v, s)) in args.iter().zip(entry.sig.params.iter()) {
            if value_sort(arg) != *s {
                return Err(EvalError::ArgSortMismatch);
            }
            env = env.bind(v.clone(), arg.clone());
        }
        let w = snap.world();
        let cx = EvalCtx { catalog: &self.catalog, links: w.links(), m3: w.m3(), defs: Some(self) };
        Ok(eval_term(&cx, &env, view, entry.expanded.as_ref()))
    }

    /// `(Γ_D, C_D)` — defined-signature starts only; answered from the
    /// immutable DefMemo. A `Some` is permanent and cacheable forever
    /// (content immutable, ever-registration monotone); a never-registered
    /// `None` is transient and never memoized; an ever-registered-but-
    /// undisciplined start answers `None` via a PERMANENT poisoned entry
    /// (freeze-on-breach, §Internal 4). No snapshot parameter — the miss
    /// path pins its own.
    pub fn signature(&self, start: &Address) -> Option<Signature> {
        match self.def_status(start) {
            DefStatus::Defined(e) => Some(e.sig.clone()),
            _ => None,
        }
    }

    /// `is_K(pdef, start)@active`.
    pub fn is_active_pred(&self, start: &Address, snap: &Snapshot<W>) -> bool {
        snap.world()
            .links()
            .is_k(self.catalog.reserved(ShippedType::PredDef), start.tumbler())
    }

    /// `is_K(pdef, start)@audit` — through the one observe-honors-Audit seam.
    pub fn is_ever_pred(&self, start: &Address, snap: &Snapshot<W>) -> bool {
        !snap
            .world()
            .links()
            .observe(
                self.catalog.reserved(ShippedType::PredDef),
                slice::from_ref(start.tumbler()),
                &[],
                View::Audit,
            )
            .is_empty()
    }

    /// Register `new_term` (define-style, sharing the up-front
    /// `TupParameter` rejection) and record old→new via the shipped
    /// `supersedes` class with CONTENT-ADDRESS endpoints — `emit`, NOT
    /// M7::assert_sup (which requires resident links; def starts are content
    /// addresses — Conflicts §4). Gates `old_start` UP FRONT, before any
    /// transaction: it must be EVER-registered (superseding a retracted def
    /// is legitimate lineage — PR4) — else `OldStartNotEverRegistered`.
    ///
    /// THREE non-atomic transactions, NO idempotency key — a lost-ack retry
    /// re-inserts a fresh successor and branches the lineage
    /// (`current_version` → `Indeterminate`); retry-dedup is the DRIVING
    /// coordination caller's (not M10's — this reaches M5/M7 directly).
    /// Returns the successor's identity (its content start) and the
    /// `supersedes` EMIT's commit `Seq` — the third transaction's.
    pub fn supersede(
        &self,
        d: &Address,
        old_start: &Address,
        new_term: TypedTerm,
    ) -> Result<(Address, Seq), DefineError> {
        if let Some((v, _)) = new_term.params().iter().find(|(_, s)| *s == Sort::Tup) {
            return Err(DefineError::TupParameter(v.clone()));
        }
        let snap = self.kernel.snapshot();
        if !self.is_ever_pred(old_start, &snap) {
            return Err(DefineError::OldStartNotEverRegistered(old_start.clone()));
        }
        let (new_start, _pdef_seq) = self.define_core(d, &new_term)?;
        let sup = self.catalog.reserved(ShippedType::Supersedes).clone();
        let ls = (self.mk_link_store)(self.kernel.as_ref());
        let (_claim, seq) =
            ls.emit(Caller::System, d, &sup, old_start, slice::from_ref(&new_start))?;
        Ok((new_start, seq))
    }

    /// The lineage head: `tip(reserved_type(Supersedes), start)` —
    /// `Sink(head)` for a linear lineage, `Indeterminate` at a branch/cycle.
    /// The reference DAG is acyclic by registration order, so no cycle check
    /// is added here (PR4).
    pub fn current_version(&self, start: &Address, snap: &Snapshot<W>) -> Tip {
        snap.world()
            .links()
            .tip(self.catalog.reserved(ShippedType::Supersedes), start)
    }

    /// CVALID(0..iii): defined signature (its two `None` causes surfaced
    /// distinctly), Boolean sort, actively registered, view-independent
    /// expansion, ST⁺ — then emit `pd_stable`. ST⁺ runs PD0 over the FLAT
    /// reference expansion (ST⁺ is not compositional — §Internal 3), with the
    /// aggregate threshold widened to a bound ℕ parameter, at a fixed view
    /// (view-independence makes the classification view-invariant).
    pub fn certify_stable(&self, d: &Address, start: &Address) -> Result<(Address, Seq), CertifyError> {
        let snap = self.kernel.snapshot();
        let entry = match self.def_status(start) {
            DefStatus::Defined(e) => e,
            DefStatus::Poisoned => return Err(CertifyError::UndisciplinedDef),
            DefStatus::Unregistered => return Err(CertifyError::NotEverRegistered),
        };
        if entry.sig.result != Sort::Bool {
            return Err(CertifyError::NotBoolean);
        }
        if !self.is_active_pred(start, &snap) {
            return Err(CertifyError::NotActive);
        }
        let flat = self.flatten_entry(&entry);
        if !view_independent(&flat) {
            return Err(CertifyError::ViewDependent);
        }
        // Γ_D parameters read as bound constants (free Vars have empty
        // footprint); ⊤-stability is the `st` leg.
        let a = analyze_term(&self.catalog, View::Audit, true, &flat);
        if !a.st {
            return Err(CertifyError::NotStable);
        }
        let ls = (self.mk_link_store)(self.kernel.as_ref());
        let (tuple, seq) =
            ls.emit(Caller::System, d, self.catalog.reserved(ShippedType::PredStable), start, &[])?;
        Ok((tuple, seq))
    }

    /// `is_K(pd_stable, start)@active`.
    pub fn is_certified_stable(&self, start: &Address, snap: &Snapshot<W>) -> bool {
        snap.world()
            .links()
            .is_k(self.catalog.reserved(ShippedType::PredStable), start.tumbler())
    }

    /// De-register: M7::nullify on the active `pdef` tuple, found via
    /// `.first().ok_or(NotActive)` (never `[0]` — item 8). Content untouched;
    /// audit retains it; re-registration after nullify deposits afresh (the
    /// idem class is empty again). Does NOT cascade to referents.
    pub fn retract_pred(&self, d: &Address, start: &Address) -> Result<(Address, Seq), RetractError> {
        let target = {
            let snap = self.kernel.snapshot();
            snap.world()
                .links()
                .observe(
                    self.catalog.reserved(ShippedType::PredDef),
                    slice::from_ref(start.tumbler()),
                    &[],
                    View::Active,
                )
                .first()
                .ok_or(RetractError::NotActive)?
                .addr
                .clone()
        };
        let ls = (self.mk_link_store)(self.kernel.as_ref());
        let (r, seq) = ls.nullify(Caller::System, d, &target)?;
        Ok((r, seq))
    }

    // ─────────────── internal: flat reference expansion (PR3) ───────────────

    /// The flat `expand(start)` for certification: reference nodes processed
    /// bottom-up (arguments before the node), fresh names drawn from the
    /// reserved `VarId ≥ EXPANSION_NAME_BASE` supply by one content-
    /// deterministic counter per top-level expand — at each reference node
    /// the referent's parameters first (signature order), then its binders
    /// depth-first left-to-right — so the expansion is deterministic and its
    /// names are disjoint from every host binder by construction (PR3/PR3a).
    /// Realized as Let-bindings of the (expanded) arguments over the
    /// α-renamed referent body.
    pub(crate) fn flatten_entry(&self, entry: &DefEntry) -> Term {
        let mut counter: u32 = 0;
        self.flatten_refs(entry.expanded.as_ref(), &mut counter)
    }

    fn mint(counter: &mut u32) -> VarId {
        let v = crate::ast::EXPANSION_NAME_BASE
            .checked_add(*counter)
            .expect("expansion-name supply exhausted");
        *counter += 1;
        VarId(v)
    }

    fn flatten_refs(&self, t: &Term, counter: &mut u32) -> Term {
        use crate::ast::{Atom, Prim};
        use std::sync::Arc as A;
        let f = |x: &crate::ast::ArcTerm, c: &mut u32| -> crate::ast::ArcTerm {
            A::new(self.flatten_refs(x, c))
        };
        match t {
            Term::Ref { addr, args } => {
                // Bottom-up: the arguments first, left to right.
                let flat_args: Vec<Term> =
                    args.iter().map(|a| self.flatten_refs(a, counter)).collect();
                let (params, body) = match self.def_status(addr) {
                    DefStatus::Defined(e) => (e.sig.params.clone(), e.expanded.clone()),
                    _ => unreachable!("WT-ref: a checked body's referent has a defined signature"),
                };
                // The node: fresh names for the referent's parameters first,
                // in signature order …
                let fresh: Vec<VarId> = params.iter().map(|_| Self::mint(counter)).collect();
                // … then its (recursively flattened) body's binders,
                // depth-first left-to-right.
                let inner_flat = self.flatten_refs(&body, counter);
                let mut map: im::HashMap<VarId, VarId> = im::HashMap::new();
                for ((p, _), fr) in params.iter().zip(fresh.iter()) {
                    map.insert(p.clone(), fr.clone());
                }
                let renamed = rename(&inner_flat, &map, counter);
                let mut out = renamed;
                for (fr, arg) in fresh.into_iter().zip(flat_args).rev() {
                    out = Term::Let { var: fr, bound: A::new(arg), body: A::new(out) };
                }
                out
            }
            Term::Var(_) | Term::Lit(_) => t.clone(),
            Term::Atom(a) => Term::Atom(match a {
                Atom::IsK(tr, e) => Atom::IsK(tr.clone(), f(e, counter)),
                Atom::Members(tr) => Atom::Members(tr.clone()),
                Atom::TargetsOf(tr, e) => Atom::TargetsOf(tr.clone(), f(e, counter)),
                Atom::IsFiltered(tr, e) => Atom::IsFiltered(tr.clone(), f(e, counter)),
                Atom::Succs(tr, e) => Atom::Succs(tr.clone(), f(e, counter)),
                Atom::Chain(tr, e) => Atom::Chain(tr.clone(), f(e, counter)),
                Atom::Tip(tr, e) => Atom::Tip(tr.clone(), f(e, counter)),
                Atom::IsInChain(tr, x, y) => {
                    Atom::IsInChain(tr.clone(), f(x, counter), f(y, counter))
                }
                Atom::SourcesTo(tr, e) => Atom::SourcesTo(tr.clone(), f(e, counter)),
                Atom::TargetOf(tr, e) => Atom::TargetOf(tr.clone(), f(e, counter)),
                Atom::TargetsKeyed(e) => Atom::TargetsKeyed(f(e, counter)),
                Atom::Age(tr, e) => Atom::Age(tr.clone(), f(e, counter)),
                Atom::Stale(tr, e) => Atom::Stale(tr.clone(), f(e, counter)),
                Atom::IsDoc(e) => Atom::IsDoc(f(e, counter)),
                Atom::TupAddr(v) => Atom::TupAddr(v.clone()),
                Atom::TupAddrsF(v) => Atom::TupAddrsF(v.clone()),
                Atom::TupAddrsG(v) => Atom::TupAddrsG(v.clone()),
                Atom::InCoverageF(e, v) => Atom::InCoverageF(f(e, counter), v.clone()),
                Atom::InCoverageG(e, v) => Atom::InCoverageG(f(e, counter), v.clone()),
            }),
            Term::Prim(p) => Term::Prim(match p {
                Prim::AddrEq(x, y) => Prim::AddrEq(f(x, counter), f(y, counter)),
                Prim::Prefix(x, y) => Prim::Prefix(f(x, counter), f(y, counter)),
                Prim::T1Lt(x, y) => Prim::T1Lt(f(x, counter), f(y, counter)),
                Prim::SetMem(x, y) => Prim::SetMem(f(x, counter), f(y, counter)),
                Prim::SetEq(x, y) => Prim::SetEq(f(x, counter), f(y, counter)),
                Prim::IsEmpty(x) => Prim::IsEmpty(f(x, counter)),
                Prim::Elems(x) => Prim::Elems(f(x, counter)),
                Prim::NatEq(x, y) => Prim::NatEq(f(x, counter), f(y, counter)),
                Prim::NatLe(x, y) => Prim::NatLe(f(x, counter), f(y, counter)),
                Prim::NatAdd(x, y) => Prim::NatAdd(f(x, counter), f(y, counter)),
                Prim::MapGet(m, tr) => Prim::MapGet(f(m, counter), tr.clone()),
                Prim::Def(x) => Prim::Def(f(x, counter)),
            }),
            Term::And(x, y) => Term::And(f(x, counter), f(y, counter)),
            Term::Or(x, y) => Term::Or(f(x, counter), f(y, counter)),
            Term::Not(x) => Term::Not(f(x, counter)),
            Term::Implies(x, y) => Term::Implies(f(x, counter), f(y, counter)),
            Term::Iff(x, y) => Term::Iff(f(x, counter), f(y, counter)),
            Term::Forall { var, dom, body } => Term::Forall {
                var: var.clone(),
                dom: A::new(self.flatten_dom(dom, counter)),
                body: f(body, counter),
            },
            Term::Exists { var, dom, body } => Term::Exists {
                var: var.clone(),
                dom: A::new(self.flatten_dom(dom, counter)),
                body: f(body, counter),
            },
            Term::Let { var, bound, body } => Term::Let {
                var: var.clone(),
                bound: f(bound, counter),
                body: f(body, counter),
            },
            Term::IfSome { opt, var, then_, else_ } => Term::IfSome {
                opt: f(opt, counter),
                var: var.clone(),
                then_: f(then_, counter),
                else_: f(else_, counter),
            },
            Term::Count(d) => Term::Count(A::new(self.flatten_dom(d, counter))),
            Term::MaxT1(d) => Term::MaxT1(A::new(self.flatten_dom(d, counter))),
            Term::MinT1(d) => Term::MinT1(A::new(self.flatten_dom(d, counter))),
            Term::BigUnion { dom, var, body } => Term::BigUnion {
                dom: A::new(self.flatten_dom(dom, counter)),
                var: var.clone(),
                body: f(body, counter),
            },
            Term::Reflect(d) => Term::Reflect(A::new(self.flatten_dom(d, counter))),
        }
    }

    fn flatten_dom(&self, d: &crate::ast::Dom, counter: &mut u32) -> crate::ast::Dom {
        use crate::ast::Dom;
        match d {
            Dom::MembersDom(_) | Dom::ActiveSlice(_) | Dom::AuditSlice(_) | Dom::LinkDom | Dom::Reg => {
                d.clone()
            }
            Dom::Filter { dom, var, pred } => Dom::Filter {
                dom: Arc::new(self.flatten_dom(dom, counter)),
                var: var.clone(),
                pred: Arc::new(self.flatten_refs(pred, counter)),
            },
            Dom::SetTerm(t) => Dom::SetTerm(Arc::new(self.flatten_refs(t, counter))),
        }
    }
}

/// α-rename an (already flat, ref-free) referent body: substitute the given
/// map on free occurrences, and give every internal binder a fresh reserved
/// name, depth-first left-to-right (PR3's binding-site renaming).
fn rename(t: &Term, map: &im::HashMap<VarId, VarId>, counter: &mut u32) -> Term {
    use crate::ast::{Atom, Prim};
    use std::sync::Arc as A;
    let fresh = |c: &mut u32| -> VarId {
        let v = crate::ast::EXPANSION_NAME_BASE
            .checked_add(*c)
            .expect("expansion-name supply exhausted");
        *c += 1;
        VarId(v)
    };
    let rv = |v: &VarId, m: &im::HashMap<VarId, VarId>| m.get(v).cloned().unwrap_or_else(|| v.clone());
    let r = |x: &crate::ast::ArcTerm, m: &im::HashMap<VarId, VarId>, c: &mut u32| -> crate::ast::ArcTerm {
        A::new(rename(x, m, c))
    };
    fn rename_dom(
        d: &crate::ast::Dom,
        map: &im::HashMap<VarId, VarId>,
        counter: &mut u32,
    ) -> crate::ast::Dom {
        use crate::ast::Dom;
        match d {
            Dom::MembersDom(_) | Dom::ActiveSlice(_) | Dom::AuditSlice(_) | Dom::LinkDom | Dom::Reg => {
                d.clone()
            }
            Dom::Filter { dom, var, pred } => {
                let base = rename_dom(dom, map, counter);
                let v2 = {
                    let v = crate::ast::EXPANSION_NAME_BASE
                        .checked_add(*counter)
                        .expect("expansion-name supply exhausted");
                    *counter += 1;
                    VarId(v)
                };
                let m2 = map.update(var.clone(), v2.clone());
                Dom::Filter {
                    dom: std::sync::Arc::new(base),
                    var: v2,
                    pred: std::sync::Arc::new(rename(pred, &m2, counter)),
                }
            }
            Dom::SetTerm(t) => Dom::SetTerm(std::sync::Arc::new(rename(t, map, counter))),
        }
    }
    match t {
        Term::Var(v) => Term::Var(rv(v, map)),
        Term::Lit(_) => t.clone(),
        Term::Atom(a) => Term::Atom(match a {
            Atom::IsK(tr, e) => Atom::IsK(tr.clone(), r(e, map, counter)),
            Atom::Members(tr) => Atom::Members(tr.clone()),
            Atom::TargetsOf(tr, e) => Atom::TargetsOf(tr.clone(), r(e, map, counter)),
            Atom::IsFiltered(tr, e) => Atom::IsFiltered(tr.clone(), r(e, map, counter)),
            Atom::Succs(tr, e) => Atom::Succs(tr.clone(), r(e, map, counter)),
            Atom::Chain(tr, e) => Atom::Chain(tr.clone(), r(e, map, counter)),
            Atom::Tip(tr, e) => Atom::Tip(tr.clone(), r(e, map, counter)),
            Atom::IsInChain(tr, x, y) => {
                Atom::IsInChain(tr.clone(), r(x, map, counter), r(y, map, counter))
            }
            Atom::SourcesTo(tr, e) => Atom::SourcesTo(tr.clone(), r(e, map, counter)),
            Atom::TargetOf(tr, e) => Atom::TargetOf(tr.clone(), r(e, map, counter)),
            Atom::TargetsKeyed(e) => Atom::TargetsKeyed(r(e, map, counter)),
            Atom::Age(tr, e) => Atom::Age(tr.clone(), r(e, map, counter)),
            Atom::Stale(tr, e) => Atom::Stale(tr.clone(), r(e, map, counter)),
            Atom::IsDoc(e) => Atom::IsDoc(r(e, map, counter)),
            Atom::TupAddr(v) => Atom::TupAddr(rv(v, map)),
            Atom::TupAddrsF(v) => Atom::TupAddrsF(rv(v, map)),
            Atom::TupAddrsG(v) => Atom::TupAddrsG(rv(v, map)),
            Atom::InCoverageF(e, v) => Atom::InCoverageF(r(e, map, counter), rv(v, map)),
            Atom::InCoverageG(e, v) => Atom::InCoverageG(r(e, map, counter), rv(v, map)),
        }),
        Term::Prim(p) => Term::Prim(match p {
            Prim::AddrEq(x, y) => Prim::AddrEq(r(x, map, counter), r(y, map, counter)),
            Prim::Prefix(x, y) => Prim::Prefix(r(x, map, counter), r(y, map, counter)),
            Prim::T1Lt(x, y) => Prim::T1Lt(r(x, map, counter), r(y, map, counter)),
            Prim::SetMem(x, y) => Prim::SetMem(r(x, map, counter), r(y, map, counter)),
            Prim::SetEq(x, y) => Prim::SetEq(r(x, map, counter), r(y, map, counter)),
            Prim::IsEmpty(x) => Prim::IsEmpty(r(x, map, counter)),
            Prim::Elems(x) => Prim::Elems(r(x, map, counter)),
            Prim::NatEq(x, y) => Prim::NatEq(r(x, map, counter), r(y, map, counter)),
            Prim::NatLe(x, y) => Prim::NatLe(r(x, map, counter), r(y, map, counter)),
            Prim::NatAdd(x, y) => Prim::NatAdd(r(x, map, counter), r(y, map, counter)),
            Prim::MapGet(m, tr) => Prim::MapGet(r(m, map, counter), tr.clone()),
            Prim::Def(x) => Prim::Def(r(x, map, counter)),
        }),
        Term::And(x, y) => Term::And(r(x, map, counter), r(y, map, counter)),
        Term::Or(x, y) => Term::Or(r(x, map, counter), r(y, map, counter)),
        Term::Not(x) => Term::Not(r(x, map, counter)),
        Term::Implies(x, y) => Term::Implies(r(x, map, counter), r(y, map, counter)),
        Term::Iff(x, y) => Term::Iff(r(x, map, counter), r(y, map, counter)),
        Term::Forall { var, dom, body } => {
            let d2 = rename_dom(dom, map, counter);
            let v2 = fresh(counter);
            let m2 = map.update(var.clone(), v2.clone());
            Term::Forall { var: v2, dom: A::new(d2), body: A::new(rename(body, &m2, counter)) }
        }
        Term::Exists { var, dom, body } => {
            let d2 = rename_dom(dom, map, counter);
            let v2 = fresh(counter);
            let m2 = map.update(var.clone(), v2.clone());
            Term::Exists { var: v2, dom: A::new(d2), body: A::new(rename(body, &m2, counter)) }
        }
        Term::Let { var, bound, body } => {
            let b2 = rename(bound, map, counter);
            let v2 = fresh(counter);
            let m2 = map.update(var.clone(), v2.clone());
            Term::Let { var: v2, bound: A::new(b2), body: A::new(rename(body, &m2, counter)) }
        }
        Term::IfSome { opt, var, then_, else_ } => {
            let o2 = rename(opt, map, counter);
            let v2 = fresh(counter);
            let m2 = map.update(var.clone(), v2.clone());
            Term::IfSome {
                opt: A::new(o2),
                var: v2,
                then_: A::new(rename(then_, &m2, counter)),
                else_: A::new(rename(else_, map, counter)),
            }
        }
        Term::Count(d) => Term::Count(A::new(rename_dom(d, map, counter))),
        Term::MaxT1(d) => Term::MaxT1(A::new(rename_dom(d, map, counter))),
        Term::MinT1(d) => Term::MinT1(A::new(rename_dom(d, map, counter))),
        Term::BigUnion { dom, var, body } => {
            let d2 = rename_dom(dom, map, counter);
            let v2 = fresh(counter);
            let m2 = map.update(var.clone(), v2.clone());
            Term::BigUnion { dom: A::new(d2), var: v2, body: A::new(rename(body, &m2, counter)) }
        }
        Term::Reflect(d) => Term::Reflect(A::new(rename_dom(d, map, counter))),
        Term::Ref { .. } => unreachable!("rename runs on flattened (ref-free) bodies"),
    }
}
