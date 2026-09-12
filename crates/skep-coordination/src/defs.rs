//! §B / §Internal 4 — predicate definitions as content (self-hosting
//! persistence): store + register (gate-first, idem dedup at M7), resolution/
//! signature/expansion hints, versioning over the shipped `supersedes` class,
//! ST⁺ certification, and de-registration. M9 drives no `transact` — every
//! write rides M5's placement composite or M7's gated `emit`/`nullify`.

use std::slice;

use skep_address::{content_subspace, Address, Nat};
use skep_arrangement::{Deposit, HasM5, M5Rec, VPos};
use skep_content::{ContentWrite, HasContent, Val};
use skep_kernel::{Seq, Snapshot, WorldState};
use skep_links::{Caller, HasLinks, LinkRec, Pattern, ShippedType, Tip, View};
use skep_namespace::{HasM3, M3Rec};

use crate::ast::{collect_ref_addrs, Term, VarId};
use crate::check::TypedTerm;
use crate::codec;
use crate::coordinator::Coordinator;
use crate::dynamics::{view_independent, Analyzer};
use crate::error::{CertifyError, DefineError, EvalError, RegisterError, RetractError};
use crate::eval::eval_term;
use crate::expand::Flattener;
use crate::memo::DefStatus;
use crate::value::{value_sort, Env, Sort, Value};

/// Why a stored def could not be read back as a signed term: no `Val` at the
/// start, or bytes the PR-ENC codec rejects.
pub(crate) enum ParseFail {
    NotResident,
    Malformed,
}

/// Read the run at `start` back as its signed term `(Γ_D, body)` — the one
/// content read M9 makes (M4 `value_at`), off the world of a pinned
/// snapshot. The parse consumes exactly the run (the codec's envelope
/// check), so a resident, well-formed def is exactly what was encoded.
pub(crate) fn parse_def<W: HasContent>(
    w: &W,
    start: &Address,
) -> Result<(Vec<(VarId, Sort)>, Term), ParseFail> {
    let val = w.content().value_at(start.tumbler()).ok_or(ParseFail::NotResident)?;
    codec::decode(val.as_bytes()).map_err(|_| ParseFail::Malformed)
}

impl<W> Coordinator<W>
where
    W: WorldState + HasLinks + HasM3 + HasContent + HasM5,
    W::Record: From<LinkRec> + From<M5Rec> + From<M3Rec> + From<ContentWrite>,
{
    /// `is_K(pdef, start)@audit` off the world `w` of a pinned snapshot —
    /// through the one `observe`-honors-`Audit` seam, and CLASS-FREE by
    /// design: a def's registration is not a trigger read, so the guest-class
    /// view the evaluator looks through does not apply, and a def registered
    /// into a draft home is ever-registered as it was. Every ever-registration
    /// question in the crate asks it here (the memo's derivation gate, the
    /// referent gate of `register_pred`, `evaluate_def`, `is_ever_pred`).
    pub(crate) fn ever_registered(&self, w: &W, start: &Address) -> bool {
        !w.links()
            .observe(
                self.catalog.reserved(ShippedType::PredDef),
                Pattern { from: slice::from_ref(start.tumbler()), to: &[] },
                View::Audit,
            )
            .is_empty()
    }

    /// Encode `term`'s COMPACT pre-`Reg`-expansion body (with its Γ_D) to one
    /// content `Val` (n = 1 — Conflicts §2), write it through M5's placement
    /// composite (mint + write + place + R, atomically — J0/J1★), then
    /// validate + register the `pdef`. Returns the def IDENTITY (content
    /// start address) and the `pdef` EMIT's commit `Seq` — NOT the insert's.
    ///
    /// The stored-def parameters are Codom-only (ASN-0130 SignedTerm), and
    /// that is the `TypedTerm` type's guarantee, not a check made here: every
    /// `TypedTerm` came through `type_check`, and a trigger — the one checked
    /// term that binds a tuple — is a `TriggerTerm`, which this signature
    /// cannot receive. The codec's own `Tup` refusal (it has no tag for the
    /// sort) is therefore unreachable from this path. Under concurrency: a
    /// concurrent INSERT lands the def mid-document (harmless — identity is
    /// the returned start); a concurrent DELETE yields a retryable
    /// `Insert(Rejected(OutOfBounds))` — benign, recompute and re-insert
    /// (item 6; the design's `BadPosition`, split by the as-built M5); a
    /// `register_pred`-stage failure leaves harmless orphan content a later
    /// `register_pred(d, start)` adopts.
    pub fn define_predicate(&self, d: &Address, term: TypedTerm) -> Result<(Address, Seq), DefineError> {
        let blob = codec::encode(term.params(), term.source_body())
            .expect("type_check admits no Tup parameter, and TypedTerm has no other public constructor");
        // Insert position off a snapshot read; M5's insert re-validates
        // against committed state (benign TOCTOU — item 6).
        let n_c = self.kernel.snapshot().world().m5().content_count(d);
        let at = VPos { subspace: content_subspace(), ordinal: n_c + Nat::from(1u32) };
        let vs = (self.mk_vstream)(self.kernel.as_ref());
        // M9's writes run as `Caller::System` (the ownership ruling's
        // automation path, 2026-08-16): the coordination layer holds no wire
        // principal — M9 ⟂ M10 by architecture. A def write is no deposit
        // (the declaration is a credential-class client's, PUB-2.59), and
        // `System` is not exempt from the in-place refusal (PUB-6.28): a def
        // into a PUBLISHED document surfaces as
        // `Insert(Rejected(PublishedTarget))`.
        let (start, _insert_seq) =
            vs.insert(Caller::System, d, at, vec![Val::new(blob)], Deposit::Undeclared)?;
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
        let (params, body) = parse_def(w, start).map_err(|e| match e {
            ParseFail::NotResident => RegisterError::NotResident,
            ParseFail::Malformed => RegisterError::ParseFailed,
        })?;
        // (iii) every referent ever-registered at σ.
        let mut refs = Vec::new();
        collect_ref_addrs(&body, &mut refs);
        if let Some(r) = refs.iter().find(|r| !self.ever_registered(w, r)) {
            return Err(RegisterError::ReferentNotEverRegistered(r.clone()));
        }
        // (iii) WT + WT-ref. Sigs via the resolver (memo-missing signature
        // calls pin their own snapshots — sound: the σ ever-gate ran first,
        // ever-registration is monotone, signature facts are
        // content-intrinsic).
        let entry = self.check_under(params, body, 0).map_err(RegisterError::IllTyped)?;
        // (iv) endorsement: every referent ACTIVELY registered at σ.
        let pdef = self.catalog.reserved(ShippedType::PredDef);
        if let Some(r) = refs.iter().find(|r| !w.links().is_k(pdef, r.tumbler())) {
            return Err(RegisterError::ReferentNotActive(r.clone()));
        }
        // (P0) home residence.
        if !w.m3().is_registered_document(d) {
            return Err(RegisterError::HomeNotRegistered);
        }
        // Valid ⇒ emit(d, [pdef], start, &[]) — Unary, |F| = 1; idem⊤ dedups
        // to ≤1 active pdef per start WITHIN THE GUEST CLASS the System path
        // writes at (lane 3.3b, PUB-6.28): a pdef tuple homed in a document
        // unreadable at guest class is invisible to the dedup and a second is
        // minted beside it.
        let (tuple, seq) = self.link_writer().emit(Caller::System, d, pdef, start, &[])?;
        // Memoize the freshly-derived hint (immutable-once-defined).
        self.memo.fill(start, Ok(entry));
        Ok((tuple, seq))
    }

    /// resolve + expand + denote. PRECONDITION: `start` EVER-registered (not
    /// active) against the caller's `snap` — else `NotEverRegistered`; an
    /// ever-registered start whose immutable content fails the PR-ENC
    /// parse/WT (a PR-DISC breach) is `UndisciplinedDef`. `args` bind
    /// positionally to Γ_D (= `signature(start).params`). Pure pin to `snap`;
    /// the denotation is DAG-recursive (`eval`'s walk + the one `Ref` arm),
    /// never a materialized flat term (Conflicts §5). The denotation reads
    /// M7 through the GUEST-CLASS view (lane 4.1) — the same view an `Inline`
    /// trigger reads — while the ever-registration probe stays class-free
    /// (`ever_registered`).
    pub fn evaluate_def(
        &self,
        start: &Address,
        args: &[Value],
        view: View,
        snap: &Snapshot<W>,
    ) -> Result<Value, EvalError> {
        if !self.ever_registered(snap.world(), start) {
            return Err(EvalError::NotEverRegistered);
        }
        let entry = match self.def_status(start) {
            DefStatus::Defined(e) => e,
            DefStatus::Poisoned => return Err(EvalError::UndisciplinedDef),
            // Ever at the caller's snap but not at the memo's own fresh pin
            // cannot happen (ever-registration is monotone); defensive.
            DefStatus::Unregistered => return Err(EvalError::NotEverRegistered),
        };
        if args.len() != entry.gamma.len() {
            return Err(EvalError::ArgArityMismatch);
        }
        let mut env = Env::empty();
        for (arg, (v, s)) in args.iter().zip(entry.gamma.iter()) {
            if value_sort(arg) != *s {
                return Err(EvalError::ArgSortMismatch);
            }
            env = env.bind(v.clone(), arg.clone());
        }
        let cx = self.eval_ctx(snap.world(), view, Some(self));
        Ok(eval_term(&cx, &env, entry.evaluable.as_ref()))
    }

    /// `is_K(pdef, start)@active`.
    pub fn is_active_pred(&self, start: &Address, snap: &Snapshot<W>) -> bool {
        snap.world()
            .links()
            .is_k(self.catalog.reserved(ShippedType::PredDef), start.tumbler())
    }

    /// `is_K(pdef, start)@audit` — through the one observe-honors-Audit seam.
    pub fn is_ever_pred(&self, start: &Address, snap: &Snapshot<W>) -> bool {
        self.ever_registered(snap.world(), start)
    }

    /// Register `new_term` (through `define_predicate`) and record old→new
    /// via the shipped `supersedes` class with CONTENT-ADDRESS endpoints —
    /// `emit`, NOT M7::assert_sup (which requires resident links; def starts
    /// are content addresses — Conflicts §4). Gates `old_start` UP FRONT,
    /// before any transaction: it must be EVER-registered (superseding a
    /// retracted def is legitimate lineage — PR4) — else
    /// `OldStartNotEverRegistered`.
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
        let snap = self.kernel.snapshot();
        if !self.is_ever_pred(old_start, &snap) {
            return Err(DefineError::OldStartNotEverRegistered(old_start.clone()));
        }
        let (new_start, _pdef_seq) = self.define_predicate(d, new_term)?;
        let sup = self.catalog.reserved(ShippedType::Supersedes);
        let (_claim, seq) =
            self.link_writer().emit(Caller::System, d, sup, old_start, slice::from_ref(&new_start))?;
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
        if entry.result != Sort::Bool {
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
        let a = Analyzer { catalog: &self.catalog, view: View::Audit, widen: true }.term(&flat);
        if !a.st {
            return Err(CertifyError::NotStable);
        }
        let (tuple, seq) = self.link_writer().emit(
            Caller::System,
            d,
            self.catalog.reserved(ShippedType::PredStable),
            start,
            &[],
        )?;
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
                    Pattern { from: slice::from_ref(start.tumbler()), to: &[] },
                    View::Active,
                )
                .first()
                .ok_or(RetractError::NotActive)?
                .addr
                .clone()
        };
        let (r, seq) = self.link_writer().nullify(Caller::System, d, &target)?;
        Ok((r, seq))
    }

    /// The flat `expand(start)` of a checked (memo-held) def — one
    /// `Flattener` per top-level expansion, so the fresh-name sequence is
    /// deterministic in the content alone (PR3).
    pub(crate) fn flatten_entry(&self, entry: &TypedTerm) -> Term {
        Flattener::new(self).flatten(entry.evaluable.as_ref())
    }
}
