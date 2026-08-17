//! §C/§D — the transact-driving write surface: [`LinkStore`] (the kernel
//! handle + construction-time registry cache), the shared single choke point
//! [`emit_core`] with its two-disciplines gate (§2), the M2 keyed dedup
//! sections (§3), and the five public ops.
//!
//! Concurrency belongs to the kernel: nothing here locks, threads, or caches
//! beyond the genesis-immutable registry `Arc` the design mandates.

use std::slice;
use std::sync::Arc;

use skep_address::{elem_addr, validate, Address, ElemPos, Nat};
use skep_arrangement::{stage_seat_link, HasM5, M5Rec, SeatError, VSpec};
use skep_kernel::{Kernel, LockKey, Seq, Space, Staging, TxnError, WorldState};
use skep_namespace::{HasM3, M3Rec, M3State, MintError};

use crate::endset::{
    coverage_class, enc, is_address_denoting, single_denoted, CoverageClass, DedupKey, Endset, Link,
};
use crate::error::{
    AssertSupError, EditLinkError, EmitError, MakeLinkError, NullifyError, RetractStaleError,
};
use crate::registry::{Behavior, Shape, ShippedType, TypeRegistry};
use crate::state::{LinkRec, LinkState};
use crate::{s_c, s_l, HasLinks};

/// The transact-driving handle: `&'k Kernel<W>` plus a construction-time
/// `Arc<TypeRegistry>` cache of the genesis-immutable registry (§C) — the
/// registration/reserved-class reads §3's pre-transact steps consult. Sound
/// because the registry is sealed at genesis and never drifts (P1/P2, R1/R2):
/// the cache can never go stale, and it agrees with what `emit_core` consults
/// inside the txn.
pub struct LinkStore<'k, W: WorldState> {
    kernel: &'k Kernel<W>,
    registry: Arc<TypeRegistry>,
}

/// One MAKELINK endset argument (the 2026-08-16 address-denoting-endsets
/// amendment; ASN-0043 L4/L8/L9/L13): content V-specs resolved against the
/// txn base — the original form, semantics unchanged — or address NAMES
/// recorded verbatim as [`enc`]`(addrs)`, with no resolution, no occupancy
/// requirement, and nothing beyond the T4 validity `Address` already carries
/// (LM 4/44: type matching is by address, contents never examined; ghost
/// names are valid). Per-slot either/or — no mixing within a slot in v1 (a
/// mixed need resolves first via the read surface and passes `Addrs`). Also
/// M10's successor type slot: the one two-form enum serves both surfaces.
pub enum SlotArg {
    /// Content V-specs, wf-checked and resolved to I-extents inside
    /// makelink's transact.
    Resolve(Vec<VSpec>),
    /// Address names, deposited verbatim as the canonical `enc` endset.
    Addrs(Vec<Address>),
}

impl SlotArg {
    /// The `Resolve` form's specs — the wf-check domain. `Addrs` names get
    /// no check beyond the T4 validity their type already carries
    /// (ReflexiveAddressing: any T4-valid name, occupied or ghost).
    fn specs(&self) -> &[VSpec] {
        match self {
            SlotArg::Resolve(specs) => specs,
            SlotArg::Addrs(_) => &[],
        }
    }
}

impl<'k, W> LinkStore<'k, W>
where
    W: WorldState + HasLinks,
{
    /// Construct the store handle: takes ONE `kernel.snapshot()` and clones
    /// the `Arc<TypeRegistry>` off `snapshot.world().links()` — a refcount
    /// bump of the slice's rebuilt registry (§C).
    pub fn new(kernel: &'k Kernel<W>) -> LinkStore<'k, W> {
        let snap = kernel.snapshot();
        let registry = Arc::clone(&snap.world().links().registry);
        LinkStore { kernel, registry }
    }
}

/// Admission DISCIPLINE selector — never the value (effect-identity: the gate
/// adds preconditions only and never alters `value`, ASN-0126 π).
enum Gate {
    /// MAKELINK / editlink successor: `e₃ ≠ ∅` only.
    Open,
    /// Emit_K / assert_sup / editlink claim: registered ∧ shape-conformant ∧
    /// K ≁ R; idem⊤ ⇒ active-view dedup check.
    Managed,
    /// Nullify: the genesis-fixed `[R]` Binary discipline, idem⊤.
    Retraction,
}

/// `emit_core`'s internal error; each public op maps it through the `From`
/// impls below (§2 error mapping). `HomeNotRegistered` originates at the
/// hoisted home check alone — the hoist makes `home` known-registered before
/// the mint, so `mint_link`'s own `HomeNotRegistered` branch is unreachable
/// and every other `MintError` rides `Mint`.
#[derive(Debug)]
enum EmitCoreError {
    HomeNotRegistered,
    NotRegistered,
    ShapeViolation,
    RetractionClass,
    EmptyType,
    Mint(MintError),
}

impl From<MintError> for EmitCoreError {
    fn from(e: MintError) -> Self {
        EmitCoreError::Mint(e)
    }
}

// §2 error mapping — the `_ => unreachable!()` arms are the paths the design
// proves cannot fire (each op's gate discipline makes them dead).

impl From<EmitCoreError> for MakeLinkError {
    // Open: only EmptyType/HomeNotRegistered/Mint reachable.
    fn from(e: EmitCoreError) -> Self {
        match e {
            EmitCoreError::EmptyType => MakeLinkError::EmptyTypeResolution,
            EmitCoreError::HomeNotRegistered => MakeLinkError::HomeNotRegistered,
            EmitCoreError::Mint(m) => MakeLinkError::Mint(m),
            _ => unreachable!("Open gate raises no Managed/Retraction rejection"),
        }
    }
}

impl From<SeatError> for MakeLinkError {
    fn from(e: SeatError) -> Self {
        MakeLinkError::Seat(e)
    }
}

impl From<EmitCoreError> for EmitError {
    // Managed: EmptyType unreachable (e₃ = ty is non-empty by T_admissible —
    // an empty ty lands NotRegistered at the gate instead).
    fn from(e: EmitCoreError) -> Self {
        match e {
            EmitCoreError::HomeNotRegistered => EmitError::HomeNotRegistered,
            EmitCoreError::NotRegistered => EmitError::NotRegistered,
            EmitCoreError::ShapeViolation => EmitError::ShapeViolation,
            EmitCoreError::RetractionClass => EmitError::RetractionClass,
            EmitCoreError::Mint(m) => EmitError::Mint(m),
            EmitCoreError::EmptyType => unreachable!("managed e₃ = ty ∈ T_admissible"),
        }
    }
}

impl From<EmitCoreError> for NullifyError {
    // Retraction: gate variants defensive (the [R] type is genesis-fixed
    // Binary; P-tgt is checked in nullify itself).
    fn from(e: EmitCoreError) -> Self {
        match e {
            EmitCoreError::HomeNotRegistered => NullifyError::HomeNotRegistered,
            EmitCoreError::Mint(m) => NullifyError::Mint(m),
            _ => unreachable!("[R] type is genesis-fixed Binary; P-tgt checked in nullify"),
        }
    }
}

impl From<EmitCoreError> for AssertSupError {
    // Managed/K_sup: the registry-fixed class makes the gate variants
    // unreachable.
    fn from(e: EmitCoreError) -> Self {
        match e {
            EmitCoreError::HomeNotRegistered => AssertSupError::HomeNotRegistered,
            EmitCoreError::Mint(m) => AssertSupError::Mint(m),
            _ => unreachable!(
                "K_sup registry-fixed Binary/idem⊤; endpoints/irreflexivity pre-checked in assert_sup"
            ),
        }
    }
}

impl From<EmitCoreError> for EditLinkError {
    // successor (Open): EmptyType → IllFormedSuccessor; claim (Managed/K_sup).
    fn from(e: EmitCoreError) -> Self {
        match e {
            EmitCoreError::EmptyType => EditLinkError::IllFormedSuccessor,
            EmitCoreError::HomeNotRegistered => EditLinkError::HomeNotRegistered,
            EmitCoreError::Mint(m) => EditLinkError::Mint(m),
            _ => unreachable!("editlink pre-checks DC/arity/residence; K_sup claim registry-fixed"),
        }
    }
}

/// §7 error mapping: lift a constituent `nullify` transact error into the
/// batch op's space — a typed rejection rides `RetractStaleError::Nullify`;
/// kernel-level failures pass through unchanged.
fn lift_nullify(e: TxnError<NullifyError>) -> TxnError<RetractStaleError> {
    match e {
        TxnError::Rejected(n) => TxnError::Rejected(n.into()),
        TxnError::Durability(io) => TxnError::Durability(io),
        TxnError::Poisoned => TxnError::Poisoned,
    }
}

/// Sh-conf (P3): SPAN COUNTS against the registered shape — never inferring
/// shape from the tuple (a `(1,0)` tuple conforms under Unary AND Multi).
/// All shapes require `|F| = 1`; Unary `|G| = 0`, Binary `|G| = 1`, Multi
/// `|G|` finite.
fn sh_conf(shape: Shape, f: usize, g: usize) -> bool {
    f == 1
        && match shape {
            Shape::Unary => g == 0,
            Shape::Binary => g == 1,
            Shape::Multi => true,
        }
}

/// The in-txn active-view dedup CHECK (§3 step 2): recompute the `DedupKey`
/// from `value` (identical to the public op's, by construction), look up the
/// audit matches, filter by `∉ nullified`, return the T1-least active
/// incumbent. Reading the ACTIVE view (I2) is what gives resurrection: a
/// nullified tuple is invisible here, so re-emitting lands fresh.
fn dedup_hit(links: &LinkState, value: &Link) -> Option<Address> {
    let key = DedupKey {
        ty: coverage_class(value.type_slot()),
        from: coverage_class(value.from_slot()),
        to: coverage_class(value.to_slot()),
    };
    let matches = links.hints.dedup.get(&key)?;
    matches
        .iter()
        .find(|t| !links.hints.nullified.contains(*t))
        .map(|t| validate(t.clone()).expect("stored link keys are T4-valid by M3's mint"))
}

/// Serialize an idem⊤ `DedupKey` into M2's opaque `LockKey`: the
/// `Space::CoverageClass` tag byte, then the three classes as
/// length-prefixed minimal antichains. Same I0-class ⇒ same bytes ⇒ M2
/// serializes the check-and-deposit (I1a/I4); different class ⇒ no
/// contention. Partitioned BY CLASS, never by home (§3).
fn dedup_lock_key(key: &DedupKey) -> LockKey {
    fn push_class(buf: &mut Vec<u8>, class: &CoverageClass) {
        match class {
            CoverageClass::Addrs(set) => {
                buf.extend_from_slice(&(set.len() as u64).to_be_bytes());
                for t in set.iter() {
                    buf.extend_from_slice(&(t.len() as u64).to_be_bytes());
                    for i in 1..=t.len() {
                        let comp = t.get(i).to_bytes_be();
                        buf.extend_from_slice(&(comp.len() as u64).to_be_bytes());
                        buf.extend_from_slice(&comp);
                    }
                }
            }
            CoverageClass::Extents(_) => unreachable!(
                "no Extents class is ever serialized into a LockKey: every idem⊤ dedup key is \
                 validated address-denoting before the lock is built (§Core data model)"
            ),
        }
    }
    let mut bytes = vec![Space::CoverageClass.tag()];
    push_class(&mut bytes, &key.ty);
    push_class(&mut bytes, &key.from);
    push_class(&mut bytes, &key.to);
    LockKey(bytes)
}

/// The single choke point both write surfaces share (§2), run INSIDE one
/// `transact`. Bounds are `HasLinks + HasM3` only — it has NO seat step (the
/// seat is staged by MAKELINK itself, the lone `HasM5` caller, after this
/// returns). Any dedup LOCK was acquired by the public op before the transact
/// (§3 step 1); this does the hoisted home check and the in-txn dedup CHECK.
///
/// The hoisted home check (Conflicts §8, a deliberate divergence from
/// ASN-0128 I1's miss-only read) runs ahead of EVERY gate/dedup
/// short-circuit, so an unregistered-home emit is rejected on every path —
/// miss AND hit; callers cannot observe the branch, which is what makes the
/// contract portable.
fn emit_core<W>(
    stg: &mut Staging<W>,
    home: &Address,
    value: Link,
    gate: Gate,
) -> Result<Address, EmitCoreError>
where
    W: WorldState + HasLinks + HasM3,
    W::Record: From<LinkRec> + From<M3Rec>,
{
    // STORE-INVARIANT BACKSTOP (§2): every caller builds arity 3
    // (MAKELINK/Emit_K/assert_sup/claim; editlink pre-checks), so this never
    // trips — but it guarantees type_class / the 3-slot spanfilade /
    // ASN-0086's |Σ.L| = 3 hold locally.
    assert_eq!(value.arity(), 3, "emit_core: the store holds only arity-3 links");
    if !stg.working().m3().is_registered_document(home) {
        return Err(EmitCoreError::HomeNotRegistered);
    }
    match gate {
        Gate::Open => {
            if value.type_slot().is_empty() {
                return Err(EmitCoreError::EmptyType); // L3 at the write boundary
            }
        }
        Gate::Managed => {
            let links = stg.working().links();
            // Total: the type slot is level-uniform by upstream validation
            // (emit's ty is address-denoting; the claim's type is reserved).
            let k = coverage_class(value.type_slot());
            let Some(reg) = links.registry.registration(&k) else {
                return Err(EmitCoreError::NotRegistered); // (i)
            };
            if k == links.shipped_class(ShippedType::Retraction) {
                return Err(EmitCoreError::RetractionClass); // K ≁ R
            }
            if !sh_conf(reg.shape, value.from_slot().len(), value.to_slot().len()) {
                return Err(EmitCoreError::ShapeViolation); // (ii)
            }
            if reg.idem {
                if let Some(incumbent) = dedup_hit(links, &value) {
                    return Ok(incumbent); // zero-step: stage NOTHING
                }
            }
        }
        Gate::Retraction => {
            let links = stg.working().links();
            let rclass = links.shipped_class(ShippedType::Retraction);
            let reg = links
                .registry
                .registration(&rclass)
                .expect("the [R] registration is genesis-fixed (defensive)");
            assert_eq!(reg.shape, Shape::Binary, "the [R] shape is genesis-fixed Binary (defensive)");
            if !sh_conf(Shape::Binary, value.from_slot().len(), value.to_slot().len()) {
                return Err(EmitCoreError::ShapeViolation); // |F| = |G| = 1
            }
            if let Some(incumbent) = dedup_hit(links, &value) {
                return Ok(incumbent); // idem⊤ zero-step
            }
        }
    }
    // K.λ via M3 (home already known-registered, so mint's own
    // HomeNotRegistered branch is unreachable; other MintError → Mint).
    let (addr, m3rec) = stg.working().m3().mint_link(home)?;
    stg.push(m3rec.into());
    stg.push(
        LinkRec::Emit {
            addr: addr.tumbler().clone(),
            value,
        }
        .into(),
    );
    Ok(addr)
}

impl<'k, W> LinkStore<'k, W>
where
    W: WorldState + HasLinks + HasM3 + HasM5,
    W::Record: From<LinkRec> + From<M3Rec> + From<M5Rec>,
{
    /// MAKELINK (ASN-0120, as amended 2026-08-16): build three endsets — a
    /// [`SlotArg::Resolve`] slot resolves its V-specs to content I-extents
    /// (M5 `resolve` + `Run::iextent`, read off the txn BASE — the whole op
    /// linearizes at its commit, ASN-0134); a [`SlotArg::Addrs`] slot is
    /// `enc(addrs)`, the NAMES verbatim (L8: matching is by address,
    /// contents never examined; ghost names valid, L9) — require the type
    /// endset non-empty AS GIVEN (ML6: an empty `Addrs` list and an empty
    /// `Resolve` resolution both land in the one `⟨⟩` check), mint a fresh
    /// home-scoped link, deposit the standard triple, then seat it in
    /// `home`'s link subspace (K.μ⁺_L, no R — J-LV). ONE M2 composite under
    /// `link_lock_key(home)` (the held lock and the advanced frontier are
    /// byte-identical — M3's contract). NO shape gate, NO idem dedup
    /// (distinct links always — ML0), NO provenance.
    ///
    /// wf is CONCRETE component tests on each `Resolve` spec (registered
    /// source; `#start = 2 ∧ start₁ = s_C ∧ #width = 2 ∧ width₁ = 0`) — the
    /// V-position's subspace is the start's FIRST component, NOT M1's
    /// `Address::subspace()` (which needs zeros = 3 and would reject every
    /// depth-2 spec); the length checks precede the `get(1)` indexing. A
    /// deliberate depth-2 narrowing of ASN-0120's `#u_j ≥ 2` (Conflicts
    /// §12). `Addrs` slots get no wf step: T4 validity is the whole
    /// precondition, already carried by the `Address` type.
    pub fn makelink(
        &self,
        home: &Address,
        from: SlotArg,
        to: SlotArg,
        ty: SlotArg,
    ) -> Result<(Address, Seq), TxnError<MakeLinkError>> {
        self.kernel
            .transact(&[M3State::link_lock_key(home)], |stg| {
                let (e1, e2, e3) = {
                    let base = stg.base();
                    if !base.m3().is_registered_document(home) {
                        return Err(MakeLinkError::HomeNotRegistered);
                    }
                    for spec in
                        from.specs().iter().chain(to.specs().iter()).chain(ty.specs().iter())
                    {
                        let wf = base.m3().is_registered_document(&spec.source)
                            && spec.span.start().len() == 2
                            && *spec.span.start().get(1) == s_c()
                            && spec.span.width().len() == 2
                            && spec.span.width().get(1).bits() == 0;
                        if !wf {
                            return Err(MakeLinkError::IllFormedSpec);
                        }
                    }
                    // Resolve: ρ as content I-extents — readable,
                    // level-uniform spans (ML1 coverage-exactness by
                    // construction: the runs trace exactly allocated content,
                    // cross-origin runs arrive un-coalesced). Addrs: the
                    // canonical name encoding, deposited unresolved.
                    let build = |slot: &SlotArg| -> Endset {
                        match slot {
                            SlotArg::Resolve(specs) => {
                                Endset::from_spans(specs.iter().flat_map(|sp| {
                                    base.m5()
                                        .resolve(&sp.source, &sp.span)
                                        .into_iter()
                                        .map(|r| r.iextent())
                                }))
                            }
                            SlotArg::Addrs(addrs) => enc(addrs),
                        }
                    };
                    (build(&from), build(&to), build(&ty))
                };
                if e3.is_empty() {
                    return Err(MakeLinkError::EmptyTypeResolution); // ML6, as-given
                }
                let value = Link::new([e1, e2, e3]).expect("the standard triple has arity 3");
                let addr = emit_core(stg, home, value, Gate::Open)?;
                let seat = stage_seat_link(stg.working().m5(), home, &addr)?;
                stg.push(seat.into());
                Ok(addr)
            })
    }
}

impl<'k, W> LinkStore<'k, W>
where
    W: WorldState + HasLinks + HasM3,
    W::Record: From<LinkRec> + From<M3Rec>,
{
    /// Emit_K (ASN-0086/0126/0128): gated typed-relation emission —
    /// `value = Link[enc({from}), enc(to), ty]` (`|F| = 1` forced, `to`
    /// cardinality shape-checked, `ty` stored verbatim as e₃). Does NOT
    /// seat. idem⊤ ⇒ dedup against the ACTIVE view; a hit returns the
    /// incumbent with the base `Seq` and commits NOTHING.
    ///
    /// PRE-TRANSACT rejections (no transaction opened — §3): `ty` not
    /// address-denoting (`NonAddressDenotingType`, before ANY class
    /// computation, keeping `coverage_class` on the safe `Addrs` path) and
    /// `ty ~ [K_sup]` (`SupersessionClass` — assert_sup/editlink are the
    /// sole `[K_sup]`-writers, the parallel of the `[R]` fence; Conflicts
    /// §10). The lock set is `[dedup_key, link_lock_key(home)]` for a
    /// registered idem⊤ `ty`, else `[link_lock_key(home)]` — the
    /// registration read comes from the construction-time cache, race-free
    /// because the registry is genesis-immutable (§3 step 1).
    pub fn emit(
        &self,
        home: &Address,
        ty: &Endset,
        from: &Address,
        to: &[Address],
    ) -> Result<(Address, Seq), TxnError<EmitError>> {
        if !is_address_denoting(ty) {
            return Err(TxnError::Rejected(EmitError::NonAddressDenotingType));
        }
        let k = coverage_class(ty);
        if k == coverage_class(self.registry.reserved(ShippedType::Supersedes)) {
            return Err(TxnError::Rejected(EmitError::SupersessionClass));
        }
        let idem = self.registry.registration(&k).is_some_and(|r| r.idem);
        let mut keys: Vec<LockKey> = Vec::with_capacity(2);
        if idem {
            let dk = DedupKey {
                ty: k,
                from: coverage_class(&enc(slice::from_ref(from))),
                to: coverage_class(&enc(to)),
            };
            keys.push(dedup_lock_key(&dk));
        }
        keys.push(M3State::link_lock_key(home));
        self.kernel.transact(&keys, |stg| {
            let value = Link::new([enc(slice::from_ref(from)), enc(to), ty.clone()])
                .expect("the managed triple has arity 3");
            let addr = emit_core(stg, home, value, Gate::Managed)?;
            Ok(addr)
        })
    }

    /// Nullify_Binary (ASN-0128): the SOLE retraction path — an `[R]` tuple
    /// with canonical from-fill `enc({home})` and unit-depth to-span
    /// `enc({target})`, idem⊤ (re-retracting the same target from the same
    /// home dedups). P-tgt is a REJECTING precondition against the txn base:
    /// `target` is a resident link OR this call's own fresh emitter —
    /// computed in O(1) off M7's own `home_count` as
    /// `elem_addr(home · 0 · s_L · (1 + home_count[home]))`, equal to
    /// `mint_link(home)`'s output by construction (FrontierUnification,
    /// Conflicts §7) — so sterilization is unreachable through this surface
    /// (DR). Lock set `[dedup_key, link_lock_key(home)]`.
    pub fn nullify(
        &self,
        home: &Address,
        target: &Address,
    ) -> Result<(Address, Seq), TxnError<NullifyError>> {
        let rty = self.registry.reserved(ShippedType::Retraction).clone();
        let dk = DedupKey {
            ty: coverage_class(&rty),
            from: coverage_class(&enc(slice::from_ref(home))),
            to: coverage_class(&enc(slice::from_ref(target))),
        };
        let keys = [dedup_lock_key(&dk), M3State::link_lock_key(home)];
        self.kernel.transact(&keys, |stg| {
            {
                let base = stg.base();
                if !base.m3().is_registered_document(home) {
                    return Err(NullifyError::HomeNotRegistered); // P0
                }
                if !base.links().resident(target.tumbler()) {
                    let next = base.links().next_home_ordinal(home);
                    let self_emitter = elem_addr(&ElemPos {
                        doc: home.clone(),
                        subspace: s_l(),
                        ordinal: Nat::from(next),
                    })
                    .expect("P0 discharged: home is a Document; s_L ≥ 1; ordinal ≥ 1 (§4)");
                    if *target != self_emitter {
                        return Err(NullifyError::BadTarget); // P-tgt
                    }
                }
            }
            let value = Link::new([
                enc(slice::from_ref(home)),
                enc(slice::from_ref(target)),
                rty.clone(),
            ])
            .expect("the retraction triple has arity 3");
            let addr = emit_core(stg, home, value, Gate::Retraction)?;
            Ok(addr)
        })
    }

    /// assert_sup (ASN-0125/0128): emit "old is superseded by new" —
    /// `F = enc({old})`, `G = enc({new})`, type `[K_sup]` (slot convention
    /// per Conflicts §2: F holds the OLD/superseded link; edges run
    /// old → new). Idem⊤ keyed on `([K_sup], {old}, {new})` — home excluded,
    /// so a duplicate `(old, new)` even from a different home dedups to the
    /// first claim (Conflicts §9). Requires `home` registered, both
    /// endpoints resident, `old ≠ new` (Df-DISC(ii)); checked in that order.
    pub fn assert_sup(
        &self,
        home: &Address,
        old: &Address,
        new: &Address,
    ) -> Result<(Address, Seq), TxnError<AssertSupError>> {
        let sup = self.registry.reserved(ShippedType::Supersedes).clone();
        let dk = DedupKey {
            ty: coverage_class(&sup),
            from: coverage_class(&enc(slice::from_ref(old))),
            to: coverage_class(&enc(slice::from_ref(new))),
        };
        let keys = [dedup_lock_key(&dk), M3State::link_lock_key(home)];
        self.kernel.transact(&keys, |stg| {
            {
                let base = stg.base();
                if !base.m3().is_registered_document(home) {
                    return Err(AssertSupError::HomeNotRegistered); // P0
                }
                if !base.links().resident(old.tumbler()) || !base.links().resident(new.tumbler()) {
                    return Err(AssertSupError::EndpointNotResident);
                }
                if old == new {
                    return Err(AssertSupError::SelfSupersession); // irreflexive
                }
            }
            let value = Link::new([
                enc(slice::from_ref(old)),
                enc(slice::from_ref(new)),
                sup.clone(),
            ])
            .expect("the claim triple has arity 3");
            let addr = emit_core(stg, home, value, Gate::Managed)?;
            Ok(addr)
        })
    }

    /// editlink (ASN-0125 EDITop): ONE composite over the two home alloc
    /// keys — deduped before the transact (`d_s == d_a` collapses `[k, k]`
    /// to `[k]`; M2's `transact(keys)` makes no duplicate-key promise) —
    /// inlining two `emit_core` calls (the public `assert_sup` CANNOT be
    /// called: M2 is non-reentrant). Allocates the fresh successor (value
    /// supplied — M10 builds it via M5 `resolve` + `Run::iextent` +
    /// `Endset::from_spans`/`enc` + `Link::new`, off any prior snapshot —
    /// ML8/EL0), then asserts it supersedes `original`. Successor born
    /// UNSEATED; both writes commit atomically (EL7); `original` untouched
    /// (L12).
    ///
    /// Rejects (against the txn base): unregistered `d_s`/`d_a`;
    /// non-resident `original`; a successor of arity ≠ 3 (Conflicts §11),
    /// empty type slot, or non-level-uniform type slot (`IllFormedSuccessor`
    /// — the last keeps the DC-guard `coverage_class` total); DC — a
    /// retraction-typed successor, or a `[K_sup]`-typed one without the
    /// Df-DISC(ii) schema (unit-depth single-addr F/G, resident endpoints,
    /// irreflexive) (`DcViolation`). The claim's dedup check is a guaranteed
    /// miss (its key carries the fresh successor), so no claim dedup lock is
    /// taken (§3).
    pub fn editlink(
        &self,
        original: &Address,
        successor: Link,
        d_s: &Address,
        d_a: &Address,
    ) -> Result<(Address, Address, Seq), TxnError<EditLinkError>> {
        let mut keys = vec![M3State::link_lock_key(d_s)];
        let k_a = M3State::link_lock_key(d_a);
        if k_a != keys[0] {
            keys.push(k_a);
        }
        let sup = self.registry.reserved(ShippedType::Supersedes).clone();
        let sup_class = coverage_class(&sup);
        let r_class = coverage_class(self.registry.reserved(ShippedType::Retraction));
        let ((succ, claim), seq) = self.kernel.transact(&keys, |stg| {
            {
                let base = stg.base();
                if !base.m3().is_registered_document(d_s) || !base.m3().is_registered_document(d_a)
                {
                    return Err(EditLinkError::HomeNotRegistered);
                }
                if !base.links().resident(original.tumbler()) {
                    return Err(EditLinkError::OriginalNotResident);
                }
                let well_formed = successor.arity() == 3
                    && !successor.type_slot().is_empty()
                    && successor.type_slot().spans().all(|s| s.is_level_uniform());
                if !well_formed {
                    return Err(EditLinkError::IllFormedSuccessor);
                }
                // DC guard — total: the type slot was just checked
                // level-uniform.
                let sc = coverage_class(successor.type_slot());
                if sc == r_class {
                    return Err(EditLinkError::DcViolation);
                }
                if sc == sup_class {
                    let schema_ok = match (
                        single_denoted(successor.from_slot()),
                        single_denoted(successor.to_slot()),
                    ) {
                        (Some(f), Some(g)) => {
                            f != g && base.links().resident(f) && base.links().resident(g)
                        }
                        _ => false,
                    };
                    if !schema_ok {
                        return Err(EditLinkError::DcViolation);
                    }
                }
            }
            let succ = emit_core(stg, d_s, successor, Gate::Open)?;
            let claim_value = Link::new([
                enc(slice::from_ref(original)),
                enc(slice::from_ref(&succ)),
                sup.clone(),
            ])
            .expect("the claim triple has arity 3");
            let claim = emit_core(stg, d_a, claim_value, Gate::Managed)?;
            Ok((succ, claim))
        })?;
        Ok((succ, claim, seq))
    }

    /// BH4 batch tooling (§7): nullify every stale tuple of `ty` (age >
    /// `horizon` over the type-`ty` active slice), the stale set snapshotted
    /// at entry. Served only where declared: a `ty` not registered with BH4
    /// (Age) is rejected PRE-TRANSACT as
    /// `TxnError::Rejected(RetractStaleError::NotBh4)` — no transaction
    /// opened, the same channel as `emit`'s pre-transact rejections — so the
    /// batch nullifier can never be aimed at an idem⊤ class (e.g.
    /// mass-nullifying old `[K_sup]` claims); v1 ships no BH4 type, so every
    /// call rejects until an app registers one. NOT atomic — a sequence of
    /// `nullify` transacts, each failure lifted through
    /// `RetractStaleError::Nullify`; on the first `TxnError` it returns
    /// `Err`, leaving earlier nullifies committed and durable (append-only,
    /// no rollback) — a re-run with the same `d_retr` is safe
    /// (already-nullified targets from this `d_retr` dedup; the recomputed
    /// stale set excludes them).
    pub fn retract_stale(
        &self,
        d_retr: &Address,
        ty: &Endset,
        horizon: u64,
    ) -> Result<Vec<(Address, Seq)>, TxnError<RetractStaleError>> {
        let bh4 = self
            .registry
            .registration(&coverage_class(ty))
            .is_some_and(|r| r.behaviors.contains(&Behavior::Age));
        if !bh4 {
            return Err(TxnError::Rejected(RetractStaleError::NotBh4)); // §7
        }
        let stale: Vec<Address> = {
            let snap = self.kernel.snapshot();
            let world = snap.world();
            world.links().stale(ty, horizon).expect(
                "BH4 registration checked pre-transact against the same genesis-immutable registry",
            )
        };
        let mut out = Vec::with_capacity(stale.len());
        for target in &stale {
            out.push(self.nullify(d_retr, target).map_err(lift_nullify)?);
        }
        Ok(out)
    }
}
