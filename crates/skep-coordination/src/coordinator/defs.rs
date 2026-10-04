//! §B / §Internal 4 — predicate definitions as content (self-hosting
//! persistence): store + register (gate-first, idem dedup at M7), the
//! registration probes, a stored def's denotation, versioning over the
//! shipped `supersedes` class, ST⁺ certification over the flat expansion,
//! and de-registration — and the resolution every group reaches a referent
//! through: the memo-or-derive ladder, and the content read and
//! ever-registration gate it rests on. M9 drives no `transact` — every write
//! rides M5's placement composite or M7's gated `emit`/`nullify`.
//!
//! THE DEF LAYER READS CLASS-FREE, where the evaluator does not (lane 4.1):
//! a def's registration is not a trigger read, so the two registration
//! probes every gate and query asks — `ever_registered` and
//! `actively_registered` — and `is_certified_stable`, `current_version` and
//! `retract_pred`'s target probe all read M7's `LinkState` directly, and a
//! def registered into a draft home is ever-registered as it was — signed,
//! resolvable and evaluable — while the guest-class view the evaluator looks
//! through hides its `pdef` tuple from `is_K`. Two class-free reads sit
//! outside this module and complete the list: the divergence monitor's
//! (`coordinator/engine.rs::fire_count`), whose attribution key pins the home
//! to the rule's own action home; and a fire's gap discrimination
//! (`coordinator/engine.rs::fired_or_deduped`), which probes residence of the
//! address M7 just returned — the writer runs at guest class, so a returned
//! incumbent is guest-readable and a fresh mint is absent from the fire
//! snapshot under either reading, and the discrimination is the same
//! filtered or not. Every read inside a VERDICT — this module's
//! `evaluate_def` included — goes through `Coordinator::eval_ctx`'s
//! guest-class view.
//!
//! THE DEF LAYER MATCHES A START BY ITS COVERAGE CLASS, where PL's `is_K`
//! matches by coverage (D2): `register_pred` and `certify_stable` deposit
//! `enc({start})`, and M7's idem dedup absorbs either deposit into any active
//! tuple of the same I0 identity (ASN-0128 I0) — so a def's registration and
//! its certificate are the tuples whose F has `start`'s class, and every
//! probe of them — the two registration probes, `is_certified_stable` and
//! `retract_pred`'s target — asks `tuple_naming`. A tuple whose F merely
//! COVERS an address names nothing there. On the disciplined domain that
//! refuses only wrong answers: no def start lies under another, a content
//! address being minted one ordinal deep (M3's element field `[s_C, n]`),
//! and an address under a def's start holds no def. Under a breach (PR-DISC)
//! it is what bounds a forgery to one start per tuple — a tuple has one
//! class, and so names one start at most: one tuple at an ancestor — a
//! document, an account, the node — has that ancestor's class, where matched
//! by coverage it would register, endorse and certify every start beneath it.

use std::collections::HashSet;
use std::slice::from_ref;
use std::sync::Arc;

use skep_address::{Address, Tumbler};
use skep_arrangement::{Deposit, VPos};
use skep_content::{ContentStore, Val};
use skep_kernel::{Seq, Snapshot};
use skep_links::{coverage_class, enc, Caller, Pattern, ShippedType, Tip, Tuple, View};

use crate::ast::Term;
use crate::check::{DefSource, TypedTerm, Unresolved};
use crate::codec;
use crate::coordinator::memo::{ContentBreach, DefStatus};
use crate::coordinator::{bind_args, Coordinator};
use crate::dynamics::{st_plus, view_independent};
use crate::error::{
    CertifyError, DefineError, EvalError, RegisterError, RetractError, SupersedeError, TypeError,
};
use crate::eval::eval_term;
use crate::expand::{Expander, ExpansionTooLarge};
use crate::value::{Signature, SignedTerm, Sort, Value};
use crate::walk::{visit_term, Visit};
use crate::CoordinationWorld;

/// Why a stored def could not be read back as a signed term: no `Val` at the
/// start, or bytes the PR-ENC codec rejects. The two say different things
/// about the start: refused bytes are a fact about immutable content, and
/// nothing resident is not — a run may yet be minted there — so the memo
/// keeps the first and never the second (`Coordinator::derive_def`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParseFail {
    NotResident,
    Malformed,
}

/// Read the run at `start` back as its signed term `(Γ_D, body)` — the one
/// content read M9 makes (M4 `value_at`), which the parameter states: the
/// content store of a pinned snapshot's world, never the world. The parse
/// consumes exactly the run (the codec's envelope check), so a resident,
/// well-formed def is exactly what was encoded.
fn parse_def(content: &ContentStore, start: &Address) -> Result<SignedTerm, ParseFail> {
    let val = content.value_at(start.tumbler()).ok_or(ParseFail::NotResident)?;
    codec::decode(val.as_bytes()).map_err(|_| ParseFail::Malformed)
}

/// The direct referents of `t` — the DISTINCT addresses its `Ref` nodes name
/// (recursively, including inside domain bodies), in first-occurrence
/// pre-order: what `register_pred`'s (iii)/(iv) checks range over
/// (§Internal 4).
///
/// Distinct, because each of those checks is an M7 slice scan and the node
/// budget admits a body spelling tens of thousands of `Ref` nodes at ONE
/// address; first-occurrence order, because the gates name the referent they
/// refuse on and the design's walk order reaches it first.
fn direct_referents(t: &Term) -> Vec<Address> {
    struct DirectReferents {
        out: Vec<Address>,
        seen: HashSet<Tumbler>,
    }
    impl Visit for DirectReferents {
        fn term(&mut self, t: &Term) {
            if let Term::Ref { addr, .. } = t {
                if self.seen.insert(addr.tumbler().clone()) {
                    self.out.push(addr.clone());
                }
            }
            visit_term(self, t);
        }
    }
    let mut referents = DirectReferents { out: Vec::new(), seen: HashSet::new() };
    referents.term(t);
    referents.out
}

impl<W: CoordinationWorld> Coordinator<W> {
    /// The `ty` tuple at `view` that NAMES `start`: one whose F has `start`'s
    /// coverage class, `coverage_class(enc({start}))` — the F half of the I0
    /// identity M7's idem dedup keys `register_pred`'s and `certify_stable`'s
    /// own deposits by (ASN-0128 I0), so a tuple that absorbs either deposit
    /// is one this finds — the T1-least if several, off the world `w` of a
    /// pinned snapshot and CLASS-FREE, as every def probe is. The one place
    /// the def layer matches a start, and by class (the module doc states
    /// why): M7's `observe` matches F by COVERAGE, a sound pre-filter — an F
    /// of `start`'s class denotes `start`, and a denoted address is the start
    /// of a unit-depth span, which covers it — and the scan keeps that class.
    /// An F covering `start` from an ancestor has the ancestor's class and
    /// names nothing there; one spelling `start` beside addresses under it has
    /// `start`'s class and names it, as M7's dedup counts it. Total:
    /// `enc({start})` is address-denoting, and M7's fold classified every
    /// stored F of these two idem⊤ classes when it indexed the tuple's dedup
    /// key, so `coverage_class` meets no endset here it cannot answer.
    fn tuple_naming(&self, w: &W, ty: ShippedType, start: &Address, view: View) -> Option<Tuple> {
        let named = coverage_class(&enc(from_ref(start)));
        w.links()
            .observe(
                self.catalog.reserved_type(ty),
                Pattern { from: from_ref(start.tumbler()), to: &[] },
                view,
            )
            .into_iter()
            .find(|t| coverage_class(&t.from) == named)
    }

    /// Some `pdef` tuple, active or retracted, names `start` — the
    /// ever-registration probe, [`Coordinator::tuple_naming`] at `Audit` (the
    /// one `observe`-honors-`Audit` seam) off the world `w` of a pinned
    /// snapshot, and CLASS-FREE by design: a def's registration is not a
    /// trigger read, so the guest-class view the evaluator looks through does
    /// not apply, and a def registered into a draft home is ever-registered as
    /// it was. Every ever-registration question in the crate asks it here (the
    /// memo's derivation gate, the referent gate of `register_pred`,
    /// `evaluate_def`, `is_ever_pred`).
    fn ever_registered(&self, w: &W, start: &Address) -> bool {
        self.tuple_naming(w, ShippedType::PredDef, start, View::Audit).is_some()
    }

    /// An ACTIVE `pdef` tuple names `start` — the endorsement probe, the
    /// active twin of [`Coordinator::ever_registered`]:
    /// [`Coordinator::tuple_naming`] at `Active`, off the world `w` of a
    /// pinned snapshot, and CLASS-FREE for the ever-probe's reason —
    /// endorsement is a registration question, not a trigger read. Every
    /// actively-registered question in the crate asks it here
    /// (`register_pred`'s endorsement gate, `is_active_pred`, and through it
    /// `certify_stable`'s leg).
    fn actively_registered(&self, w: &W, start: &Address) -> bool {
        self.tuple_naming(w, ShippedType::PredDef, start, View::Active).is_some()
    }

    // ───────────── resolution: the DefMemo's memo-or-derive (§Internal 4) ─────────────

    /// Memo-or-derive at the top of a derivation chain — a status about the
    /// content alone: every start answers at level 0, where `register_pred`
    /// checked it (a nesting refusal there is the content's own, a breach).
    pub(super) fn def_status(&self, start: &Address) -> DefStatus {
        self.def_status_at(start, 0).unwrap_or_else(|DerivedTooDeep| {
            unreachable!(
                "a derivation rooted at level 0 completes or poisons: derive_def freezes a \
                 nesting refusal there as the content's own breach"
            )
        })
    }

    /// Memo-or-derive with the derivation's root at nesting level `depth`:
    /// a memo hit answers at any level; a miss derives from immutable
    /// content at `depth`, and a derivation that cannot complete there is
    /// [`DerivedTooDeep`] — the asking term's refusal, filling nothing.
    fn def_status_at(&self, start: &Address, depth: u32) -> Result<DefStatus, DerivedTooDeep> {
        if let Some(hit) = self.memo.get(start) {
            return Ok(hit);
        }
        self.derive_def(start, depth)
    }

    /// The miss path: pin its OWN snapshot to check ever-registration (a
    /// never-registered start is never cached — a later registration must
    /// surface), then derive from immutable content with the body's root at
    /// `depth`, recursing through referents at the levels the checker asks
    /// for them at (`budget::referent_depth`; well-founded by PR2; a breach
    /// cycle strictly deepens each round until the checker's nesting door
    /// refuses it).
    ///
    /// What is memoized is a status of the CONTENT, never of the asking
    /// term: an ever-registered start whose RESIDENT content fails the
    /// parse, or fails WT on its own account, fills the memo poisoned —
    /// freeze-on-breach (PR-DISC, §Internal 4), a deliberate policy and not
    /// an immutability consequence: an `UndefinedReference` — to a referent
    /// not yet defined — could heal on that referent's definition, and the
    /// freeze declines to re-check (safe — the start merely stays
    /// signature-less, never a wrong `Some`; the crate root states what that
    /// costs across handles). An ever-registered start with NOTHING resident
    /// is a breach too — a `pdef` naming no def — but no fact about content:
    /// a run may yet be minted there, so it answers `Undisciplined` and fills
    /// nothing, as a never-registered start does, and a `pdef` deposited past
    /// the gate at a home's next content address cannot freeze the def its
    /// owner defines there. A nesting refusal ABOVE level 0 is not the
    /// content's: every def `register_pred` admits was checked at level 0 and
    /// fits there, and every such consumer's `Ref` charge
    /// (`TypedTerm::reach`) guarantees its referents fit where a cold
    /// derivation starts them — so a `TooDeep` at `depth > 0` is the
    /// referring term's, answered as [`DerivedTooDeep`] with the memo
    /// untouched, and on the disciplined domain the same term answers
    /// `TooDeep` on a warm memo and a cold one alike. At level 0 a `TooDeep`
    /// can only be a breach (content registered past the gate), and freezes.
    fn derive_def(&self, start: &Address, depth: u32) -> Result<DefStatus, DerivedTooDeep> {
        let snap = self.kernel.snapshot();
        let w = snap.world();
        if !self.ever_registered(w, start) {
            return Ok(DefStatus::NeverRegistered);
        }
        let derived = match parse_def(w.content(), start) {
            // Nothing resident at `start` is no fact about its content: a run
            // may yet be minted there. Undisciplined — a `pdef` naming no def
            // is a breach — but no `ContentBreach`, so never memoized:
            // `NeverRegistered`'s reason.
            Err(ParseFail::NotResident) => return Ok(DefStatus::Undisciplined),
            Err(ParseFail::Malformed) => Err(ContentBreach),
            Ok(signed) => match self.check_signed(signed, depth) {
                Ok(def) => Ok(def),
                Err(TypeError::TooDeep) if depth > 0 => return Err(DerivedTooDeep),
                Err(_) => Err(ContentBreach),
            },
        };
        Ok(self.memo.fill(start, derived))
    }

    /// The defined referent at `start`, its derivation (if the memo misses)
    /// rooted at nesting level `depth` — the resolver the checker consults
    /// for a `Ref`, which asks at `budget::referent_depth` of the reference's
    /// own level. An undefined signature (never registered, or undisciplined)
    /// is `Unresolved::Undefined`; a derivation that cannot complete at
    /// `depth` is `Unresolved::TooDeep`, the referent unjudged.
    pub(super) fn resolve_def_at(
        &self,
        start: &Address,
        depth: u32,
    ) -> Result<Arc<TypedTerm>, Unresolved> {
        match self.def_status_at(start, depth) {
            Ok(DefStatus::Defined(def)) => Ok(def),
            Ok(DefStatus::Undisciplined | DefStatus::NeverRegistered) => Err(Unresolved::Undefined),
            Err(DerivedTooDeep) => Err(Unresolved::TooDeep),
        }
    }

    // ─────────────────── B. predicate definitions as content ───────────────────

    /// Store `term`'s COMPACT pre-`Reg`-expansion body (with its Γ_D) as one
    /// content `Val` — the codec's stored run of it (`codec::stored_run`;
    /// n = 1 — Conflicts §2) — written through M5's placement composite
    /// (mint + write + place + R, atomically — J0/J1★), then validate +
    /// register the `pdef`. Returns the def IDENTITY (content start address)
    /// and the `pdef` EMIT's commit `Seq` — NOT the insert's.
    ///
    /// The stored-def parameters are Codom-only (ASN-0130 SignedTerm), and no
    /// check is made here: a caller's only route to a `TypedTerm` is
    /// `type_check`, which refuses a `Tup` in Γ_D, and the one checked term
    /// whose parameter may be a tuple is a `TriggerTerm`, no accessor of which
    /// returns its `TypedTerm`. The codec's own `Tup` refusal (it has no tag
    /// for the sort) is therefore unreachable, in this crate or out of it —
    /// the codec states why where it relies on it.
    ///
    /// A CHECKED term is not thereby storable, and that is the one refusal
    /// made BEFORE any transaction: `Unstorable`, when the codec has no stored
    /// run for the term ([`DefineError::Unstorable`] says how a checked term
    /// gets there). The refusals speak in this order:
    /// `Unstorable`; then the content insert's (`Insert(..)` — M5's door on
    /// `home`, below, among them — nothing committed); then `register_pred`'s
    /// gates over the run just committed (`Register(..)`), the content
    /// staying.
    ///
    /// `home` must be a registered document that is NOT a published TARGET
    /// (M5's `published_target`: the publication bit of `trunk_of(home)` —
    /// `home` with its version components stripped, so a chain's every member
    /// answers its trunk's bit). An unregistered `home` is M5's door,
    /// `Insert(Rejected(DocNotRegistered))`, before any content lands; a
    /// published target is `Insert(Rejected(PublishedTarget))` at the same
    /// door and for EVERY position, this insert being `Deposit::Undeclared` —
    /// M5 admits into a published target only a declared deposit at a fresh
    /// append position, and `Caller::System` is exempt from ω and from
    /// nothing else (PUB-6.28). A def's home is therefore a draft: a caller
    /// that means to publish the document holding its predicates defines into
    /// it first.
    ///
    /// Of `register_pred`'s refusals, a term checked on the disciplined
    /// domain meets only two after the insert has committed:
    /// `ReferentNotActive` — with no concurrency at all when it references a
    /// def retracted before the call (`type_check` keys on ever-registration,
    /// gate (iv) on endorsement; `retract_pred` states it), or when one is
    /// retracted in the gap — and M7's own refusal of the emit (`Emit`).
    /// Either way the content stays, orphan, and a later
    /// `register_pred(home, start)` adopts it once the cause is gone.
    ///
    /// Under concurrency: a concurrent INSERT lands the def mid-document
    /// (harmless — identity is the returned start); a concurrent DELETE
    /// yields a retryable `Insert(Rejected(OutOfBounds))` — benign, recompute
    /// and re-insert. Borrows the term: the stored def is re-derived from its
    /// own bytes by `register_pred`, so nothing of the caller's value is
    /// kept, and the caller goes on evaluating or classifying it.
    pub fn define_predicate(
        &self,
        home: &Address,
        term: &TypedTerm,
    ) -> Result<(Address, Seq), DefineError> {
        // The one refusal decided before any transaction (§Internal 4): a term
        // the codec has no stored run for is one `register_pred` would refuse
        // `ParseFailed` whatever the store holds, so storing it would commit an
        // orphan no registration adopts.
        let bytes = codec::stored_run(term).map_err(|codec::Unstorable| DefineError::Unstorable)?;
        // Insert position off a snapshot read; M5's insert re-validates
        // against committed state (a benign TOCTOU).
        let content_count = self.kernel.snapshot().world().m5().content_count(home);
        let at = VPos::content(content_count + 1u32);
        let vstream = (self.mk_vstream)(self.kernel.as_ref());
        // M9's writes run as `Caller::System` (the ownership ruling's
        // automation path, 2026-08-16): the coordination layer holds no wire
        // principal — M9 ⟂ M10 by architecture. A def write is no deposit:
        // the declaration is a credential-class client's (PUB-2.59), so this
        // insert is `Undeclared` — the door the published-target requirement
        // above is stated against.
        let (start, _insert_seq) =
            vstream.insert(Caller::System, home, at, vec![Val::new(bytes)], Deposit::Undeclared)?;
        let (_pdef_tuple, seq) = self.register_pred(home, &start)?;
        Ok((start, seq))
    }

    /// Validate the run already at `start` against ONE pinned snapshot σ,
    /// then emit the `pdef` tuple via M7 (a second transaction — sound
    /// because evaluation keys on ever-registration, never endorsement
    /// currency; §Internal 4 two-transaction soundness). Gate-first, and the
    /// gates speak in this order: no content `Val` at `start`
    /// (`NotResident`); bytes the PR-ENC codec refuses (`ParseFailed`); a
    /// referent not ever-registered at σ (`ReferentNotEverRegistered`, ahead
    /// of WT-ref, so a stored reference to nothing is a gate refusal, not an
    /// `IllTyped(UndefinedReference)`); WT + WT-ref over the signed term
    /// (`IllTyped`); a referent ever- but not actively registered at σ
    /// (`ReferentNotActive` — endorsement); `home` not a registered document
    /// (`HomeNotRegistered`, P0); M7's own refusal of the emit (`Emit`).
    /// Where several referents fail one of the two referent gates, the
    /// address carried is the FIRST in first-occurrence pre-order
    /// (`direct_referents`), which is the referent the design's walk order
    /// reaches first.
    ///
    /// RETURNS `(tuple, seq)`: the active `pdef` tuple's address — the
    /// fresh deposit's, or on an idem⊤ dedup hit the incumbent's, with M7's
    /// base `Seq` and nothing committed — so ≤1 active `pdef` per start
    /// within the guest class (PR0).
    ///
    /// POSTCONDITION: the memo holds `start` defined, so `signature(start)`
    /// answers — UNLESS a probe already froze `start` POISONED, which takes a
    /// PR-DISC breach and which this call does not lift: the memo's first
    /// fill wins and never yields (§Internal 4). The one shape is a
    /// breach-registered start probed while a referent's signature was still
    /// undefined — the referent not yet registered, or registered with
    /// nothing resident yet — `UndefinedReference` being the single WT
    /// rejection not fixed by the immutable content; the freeze stands, this
    /// call still returns `Ok`, and `signature(start)` keeps answering `None`.
    /// A start probed while nothing was resident at it is no such shape: that
    /// answer is never memoized (`derive_def`). Through this gate the one
    /// shape cannot arise: (iii) puts every referent's ever-registration
    /// ahead of the check, and PR2 registers the DAG bottom-up.
    pub fn register_pred(
        &self,
        home: &Address,
        start: &Address,
    ) -> Result<(Address, Seq), RegisterError> {
        let snap = self.kernel.snapshot();
        let w = snap.world();
        // (0/i/ii) one Val, residence + extent + fully consumed.
        let signed = parse_def(w.content(), start).map_err(|e| match e {
            ParseFail::NotResident => RegisterError::NotResident,
            ParseFail::Malformed => RegisterError::ParseFailed,
        })?;
        // (iii) every referent ever-registered at σ.
        let referents = direct_referents(&signed.body);
        if let Some(referent) = referents.iter().find(|referent| !self.ever_registered(w, referent))
        {
            return Err(RegisterError::ReferentNotEverRegistered(referent.clone()));
        }
        // (iii) WT + WT-ref. Sigs via the resolver (memo-missing signature
        // calls pin their own snapshots — sound: the σ ever-gate ran first,
        // ever-registration is monotone, signature facts are
        // content-intrinsic).
        let def = self.check_signed(signed, 0).map_err(RegisterError::IllTyped)?;
        // (iv) endorsement: every referent ACTIVELY registered at σ.
        if let Some(referent) =
            referents.iter().find(|referent| !self.actively_registered(w, referent))
        {
            return Err(RegisterError::ReferentNotActive(referent.clone()));
        }
        // (P0) home residence.
        if !w.m3().is_registered_document(home) {
            return Err(RegisterError::HomeNotRegistered);
        }
        // Valid ⇒ emit(home, [pdef], start, &[]) — Unary, |F| = 1; idem⊤ dedups
        // to ≤1 active pdef per start WITHIN THE GUEST CLASS the System path
        // writes at (lane 3.3b, PUB-6.28): a pdef tuple homed in a document
        // unreadable at guest class is invisible to the dedup and a second is
        // minted beside it.
        let pdef = self.catalog.reserved_type(ShippedType::PredDef);
        let (tuple, seq) = self.link_writer().emit(Caller::System, home, pdef, start, &[])?;
        // The memo's second admission site, under `derive_def`'s rule: the
        // start is ever-registered now, and `def` is the content's own status,
        // checked at level 0.
        self.memo.fill(start, Ok(def));
        Ok((tuple, seq))
    }

    /// resolve + expand + denote. Refuses, in this order: a start not
    /// EVER-registered (active or not) at the caller's `snap`
    /// (`NotEverRegistered`); an ever-registered start whose content is
    /// absent or fails the PR-ENC parse/WT — a PR-DISC breach
    /// (`UndisciplinedDef`); an argument count differing from Γ_D's
    /// (`ArgArityMismatch`); an argument at the wrong sort (`ArgSortMismatch`).
    /// `args` bind positionally to Γ_D (= `signature(start).params`). The
    /// denotation is DAG-recursive (`eval`'s walk + the one `Ref` arm), never
    /// a materialized flat term (Conflicts §5), and reads M7 through the
    /// GUEST-CLASS view (lane 4.1) — the same view an `Inline` trigger reads —
    /// while the ever-registration probe stays class-free (`ever_registered`).
    ///
    /// A pure pin to `snap` for the DENOTATION: every structural read it
    /// makes is `snap`'s. The def's RESOLUTION is the memo's, which on a miss
    /// pins its own later snapshot (`derive_def`); the answer is the same
    /// either way, by `register_pred`'s argument — the ever-gate above ran at
    /// `snap`, ever-registration is monotone, and signature facts are
    /// content-intrinsic, so a def ever-registered at `snap` has its whole
    /// referent DAG ever-registered there too (PR2, gate (iii)).
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
        let def = match self.def_status(start) {
            DefStatus::Defined(def) => def,
            DefStatus::Undisciplined => return Err(EvalError::UndisciplinedDef),
            // Unreachable: ever at the caller's snap and not at the memo's
            // own fresh pin cannot happen, ever-registration being monotone.
            // Answered rather than asserted, so the query stays total.
            DefStatus::NeverRegistered => return Err(EvalError::NotEverRegistered),
        };
        let env = bind_args(def.params(), args)?;
        let cx = self.eval_ctx(snap.world(), view, Some(self));
        Ok(eval_term(&cx, &env, def.evaluable()))
    }

    /// `(Γ_D, C_D)` — defined-signature starts only; answered from the
    /// immutable DefMemo. A `Some` is permanent and cacheable forever
    /// (content immutable, ever-registration monotone); a never-registered
    /// `None` is transient and never memoized, and so is that of an
    /// ever-registered start with nothing resident yet; an ever-registered
    /// start whose resident content is undisciplined answers `None` via a
    /// PERMANENT poisoned entry (freeze-on-breach, §Internal 4). No snapshot
    /// parameter — the miss path pins its own. A query: the memo it may fill
    /// answers every later probe on THIS handle as this one was answered, and
    /// every handle alike on the disciplined domain (the crate root states the
    /// breach exception).
    pub fn signature(&self, start: &Address) -> Option<Signature> {
        self.resolve_def_at(start, 0).ok().map(|def| def.signature())
    }

    /// An active `pdef` tuple names `start` — matched by `start`'s coverage
    /// class, never by covering it, and class-free (`actively_registered`).
    pub fn is_active_pred(&self, start: &Address, snap: &Snapshot<W>) -> bool {
        self.actively_registered(snap.world(), start)
    }

    /// A `pdef` tuple, active or retracted, names `start` — matched by
    /// `start`'s coverage class, never by covering it, and class-free
    /// (`ever_registered`).
    pub fn is_ever_pred(&self, start: &Address, snap: &Snapshot<W>) -> bool {
        self.ever_registered(snap.world(), start)
    }

    /// Register `new_term` (through `define_predicate`) and record old→new
    /// via the shipped `supersedes` class with CONTENT-ADDRESS endpoints —
    /// `emit`, NOT M7::assert_sup (which requires resident links; def starts
    /// are content addresses — Conflicts §4). Gates `old_start` UP FRONT,
    /// before any transaction: it must be EVER-registered (superseding a
    /// retracted def is legitimate lineage — PR4) — else
    /// `OldStartNotEverRegistered`. The successor's content is written
    /// through `define_predicate`, so `home` carries that operation's whole
    /// requirement — a registered document that is not a published target —
    /// and every one of its refusals arrives here as `SupersedeError::Define`.
    ///
    /// THREE non-atomic transactions, NO idempotency key — a lost-ack retry
    /// re-inserts a fresh successor and branches the lineage
    /// (`current_version` → `Indeterminate`); retry-dedup is the DRIVING
    /// coordination caller's (not M10's — this reaches M5/M7 directly).
    /// Returns the successor's identity (its content start) and the
    /// `supersedes` EMIT's commit `Seq` — the third transaction's.
    ///
    /// AS BUILT the third never commits: M7 fences every `[K_sup]`-typed
    /// `emit` pre-transact (`EmitError::SupersessionClass` — `assert_sup` and
    /// `editlink` being that class's sole writers), so a call that passes the
    /// gate commits the successor and its `pdef` (transactions 1–2) and
    /// answers `Err(Lineage(Rejected(SupersessionClass)))` — every time, until
    /// M7 admits content-endpoint def lineage. A retry registers another
    /// successor; the tripwire
    /// `supersede_gates_up_front_and_trips_m7_s_supersession_fence` flips when
    /// M7 changes.
    pub fn supersede(
        &self,
        home: &Address,
        old_start: &Address,
        new_term: &TypedTerm,
    ) -> Result<(Address, Seq), SupersedeError> {
        let snap = self.kernel.snapshot();
        if !self.is_ever_pred(old_start, &snap) {
            return Err(SupersedeError::OldStartNotEverRegistered(old_start.clone()));
        }
        let (new_start, _pdef_seq) = self.define_predicate(home, new_term)?;
        let sup = self.catalog.reserved_type(ShippedType::Supersedes);
        let (_claim, seq) = self
            .link_writer()
            .emit(Caller::System, home, sup, old_start, from_ref(&new_start))
            .map_err(SupersedeError::Lineage)?;
        Ok((new_start, seq))
    }

    /// The lineage head: `tip(reserved_type(Supersedes), start)` —
    /// `Sink(head)` for a linear lineage, `Indeterminate` at a branch or a
    /// cycle. The `supersedes` lineage is not constrained to be acyclic (it
    /// is a claim graph, not PR4's reference DAG): the walk halts on its own
    /// visited set, and `Indeterminate` is the contract for both shapes.
    pub fn current_version(&self, start: &Address, snap: &Snapshot<W>) -> Tip {
        snap.world()
            .links()
            .tip(self.catalog.reserved_type(ShippedType::Supersedes), start)
    }

    /// CVALID(0..iii), the refusals speaking in this order: defined signature
    /// (its two `None` causes surfaced distinctly — `NotEverRegistered`,
    /// `UndisciplinedDef`), Boolean sort (`NotBoolean`), actively registered
    /// (`NotActive`), an expansion within the node budget
    /// (`ExpansionTooLarge`), view-independent expansion (`ViewDependent`),
    /// ST⁺ (`StabilityUnproven` — unknown, never unstable) — then emit
    /// `pd_stable` at `home`, which must be a registered document: after
    /// every static leg, an unregistered `home` is M7's door,
    /// `Emit(Rejected(HomeNotRegistered))`. ST⁺ runs PD0 over the FLAT
    /// reference expansion (ST⁺ is not compositional — §Internal 3), with the
    /// aggregate threshold widened to a bound ℕ parameter, at a fixed view
    /// (view-independence makes the classification view-invariant).
    ///
    /// THE LEGS READ THREE STATES, and the operation is not atomic over
    /// them: (0) resolves through the memo, which on a miss pins its own
    /// snapshot (`derive_def`) — content-intrinsic on the disciplined domain,
    /// so the pin cannot change the answer there (the crate root states the
    /// breach exception); (ii) reads the `snap` this call pins; the deposit
    /// is a THIRD transaction after both. A def retracted in the gap is still
    /// certified — the accepted state `retract_pred` states from its side,
    /// the certificate being about the immutable content — and a def
    /// registered between `snap` and the memo's pin answers `NotActive`,
    /// which a retry resolves.
    ///
    /// RETURNS `(tuple, seq)`: the active `pd_stable` tuple's address — the
    /// fresh deposit's, or, where the guest class can see an incumbent, the
    /// incumbent's, with M7's base `Seq` and nothing committed: ≤1 active
    /// `pd_stable` per start WITHIN THE GUEST CLASS, as `register_pred`
    /// states for `pdef`. An incumbent homed where the guest predicate
    /// refuses — a draft, under the engine's predicate — is invisible to the
    /// writer's dedup (lane 3.3b), so re-certifying into such a home mints a
    /// second certificate and commits.
    pub fn certify_stable(
        &self,
        home: &Address,
        start: &Address,
    ) -> Result<(Address, Seq), CertifyError> {
        let snap = self.kernel.snapshot();
        let def = match self.def_status(start) {
            DefStatus::Defined(def) => def,
            DefStatus::Undisciplined => return Err(CertifyError::UndisciplinedDef),
            DefStatus::NeverRegistered => return Err(CertifyError::NotEverRegistered),
        };
        if def.result_sort() != Sort::Bool {
            return Err(CertifyError::NotBoolean);
        }
        if !self.is_active_pred(start, &snap) {
            return Err(CertifyError::NotActive);
        }
        let flat_expansion = self.expand_def(&def).map_err(|_| CertifyError::ExpansionTooLarge)?;
        if !view_independent(&flat_expansion) {
            return Err(CertifyError::ViewDependent);
        }
        if !st_plus(&self.catalog, &flat_expansion) {
            return Err(CertifyError::StabilityUnproven);
        }
        let (tuple, seq) = self.link_writer().emit(
            Caller::System,
            home,
            self.catalog.reserved_type(ShippedType::PredStable),
            start,
            &[],
        )?;
        Ok((tuple, seq))
    }

    /// An active `pd_stable` tuple names `start` — `tuple_naming`, matched by
    /// `start`'s coverage class, and class-free, as the def probes are. `true`
    /// is a CERTIFICATE (CVALID passed by `certify_stable`, over the immutable
    /// content) only under PR-DISC: a `pd_stable` tuple naming `start` that
    /// any other write deposited reads `true` here as well, and nothing in M9
    /// re-validates it — though one whose F merely covers `start`, from an
    /// ancestor, certifies nothing (the crate root states the obligation and
    /// the surfaces it covers).
    pub fn is_certified_stable(&self, start: &Address, snap: &Snapshot<W>) -> bool {
        self.tuple_naming(snap.world(), ShippedType::PredStable, start, View::Active).is_some()
    }

    /// De-register: M7::nullify, from the retracting `home`, on ONE active
    /// `pdef` tuple naming `start` — the T1-least, as `tuple_naming` returns
    /// it, `NotActive` when there is none; a `pdef` whose F merely covers
    /// `start` is never taken for the def's own. One tuple per call: beside a
    /// second active `pdef` naming the same start (a twin homed where the
    /// guest class could not see it when the first was minted),
    /// `is_active_pred` stays true until each is retracted. `home` must be a
    /// registered document — `Nullify(Rejected(HomeNotRegistered))`
    /// otherwise, after the `NotActive` probe. Content untouched; audit
    /// retains it; re-registration after nullify deposits afresh (the idem
    /// class is empty again).
    ///
    /// Does NOT cascade (ASN-0130: "existing referencing definitions, and
    /// evaluations of them, survive untouched"). A def that references `start`
    /// keeps its signature and goes on evaluating: its reference now dangles
    /// but stays live (ASN-0130 OQ3). `start`'s endorsement is withdrawn, so
    /// `register_pred` refuses a NEW reference to it as `ReferentNotActive`.
    /// The defs `start` references are untouched, and so is the `pd_stable`
    /// certificate: `is_certified_stable` stays true for a retracted def (the
    /// certificate is about the immutable content), while `certify_stable` on
    /// that def now refuses `NotActive`.
    ///
    /// RETURNS `(retraction, seq)`: the address of the `[R]` tuple itself —
    /// never the `pdef`'s — or, on a dedup hit, the incumbent retraction's,
    /// with M7's base `Seq`.
    pub fn retract_pred(
        &self,
        home: &Address,
        start: &Address,
    ) -> Result<(Address, Seq), RetractError> {
        let target = {
            let snap = self.kernel.snapshot();
            self.tuple_naming(snap.world(), ShippedType::PredDef, start, View::Active)
                .ok_or(RetractError::NotActive)?
                .addr
        };
        let (retraction, seq) = self.link_writer().nullify(Caller::System, home, &target)?;
        Ok((retraction, seq))
    }

    /// The flat `expand(start)` of a checked def, given the checked def the
    /// memo holds — one `Expander` per top-level expansion, so the fresh-name
    /// sequence is deterministic in the content alone (PR3) — or
    /// `ExpansionTooLarge` when the reference DAG's unfolding outgrows the
    /// node budget.
    pub(super) fn expand_def(&self, def: &TypedTerm) -> Result<Term, ExpansionTooLarge> {
        Expander::new(self).expand(def.evaluable())
    }
}

/// A derivation asked for at a level where it cannot complete: the
/// referring term is too deep. The asking term's refusal, never the
/// content's — so never memoized. Unreachable at level 0, where `derive_def`
/// freezes a nesting refusal as the content's breach.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DerivedTooDeep;

/// The referent supplier for the DAG-recursive drivers (a def's denotation,
/// the flat expansion) — the content-read pass stays distinct from the
/// structural denotation, so the denotation remains reference-free
/// (Conflicts §5). Asked at level 0, so the one refusal is "no defined
/// signature".
impl<W: CoordinationWorld> DefSource for Coordinator<W> {
    fn resolve_def(&self, addr: &Address) -> Option<Arc<TypedTerm>> {
        self.resolve_def_at(addr, 0).ok()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use skep_address::Address;

    use super::direct_referents;
    use crate::ast::{Dom, Term};
    use crate::fixture::{a, v};

    /// [`direct_referents`] names each referent ONCE, in first-occurrence
    /// order: `register_pred` runs an M7 slice scan per referent, and the node
    /// budget admits a body spelling tens of thousands of `Ref` nodes at one
    /// address; the order is what lets its gates name the referent the
    /// design's walk order reaches first.
    #[test]
    fn each_direct_referent_appears_once_in_first_occurrence_order() {
        let (p, q) = (a(&[1, 0, 1, 0, 1, 0, 1, 1]), a(&[1, 0, 1, 0, 1, 0, 1, 2]));
        let at = |t: Term| Arc::new(t);
        let r = |x: &Address| Term::Ref { addr: x.clone(), args: vec![] };
        // q first, then p, then q again — inside a domain body, so the walk's
        // reach over `Dom` is covered too.
        let body = Term::And(
            at(r(&q)),
            at(Term::Exists {
                var: v(1),
                dom: Arc::new(Dom::Filter {
                    dom: Arc::new(Dom::LinkDom),
                    var: v(2),
                    pred: at(r(&p)),
                }),
                body: at(r(&q)),
            }),
        );
        assert_eq!(direct_referents(&body), vec![q, p]);
    }
}
