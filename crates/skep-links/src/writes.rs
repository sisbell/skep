//! §C/§D — the transact-driving write surface: [`LinkWriter`] (the kernel
//! handle + construction-time registry cache), the shared single choke point
//! [`emit_core`] with its two-disciplines gate (§2), the M2 keyed dedup
//! sections (§3), and the five public ops.
//!
//! Concurrency belongs to the kernel: nothing here locks, threads, or caches
//! beyond the genesis-immutable registry `Arc` the design mandates.
//!
//! Ownership (as amended 2026-08-16): every op that deposits into a home
//! document's link subspace takes a [`Caller`] and requires
//! `caller.is_owner(m3, home)` — the in-txn ω gate, enforced at
//! [`emit_core`] (hit AND miss) with per-op hoists pinning error order;
//! `nullify` additionally requires owning the TARGET link (self-retraction
//! only in v1).

use std::fmt;
use std::sync::Arc;

use skep_address::{content_subspace, Address};
use skep_arrangement::{stage_seat_link, Caller, HasM5, M5Rec, M5State, SeatError, VSpec};
use skep_kernel::{Kernel, LockKey, Seq, Staging, TxnError, WorldState};
use skep_namespace::{M3Rec, M3State, MintError};

use crate::dedup::DedupKey;
use crate::endset::{coverage_class, enc, is_address_denoting, single_denoted, Endset, Link};
use crate::error::{
    AssertSupError, EditLinkError, EmitError, MakeLinkError, NotBh4, NullifyError,
    RetractStaleError,
};
use crate::registry::{Shape, ShippedType, TypeRegistry};
use crate::state::LinkRec;
use crate::{HasLinks, LinkWorld};

/// M7's single writer of link values — the transact-driving handle: `&'k
/// Kernel<W>` plus a construction-time `Arc<TypeRegistry>` cache of the
/// genesis-immutable registry (§C), which the registration/reserved-class
/// reads of §3's pre-transact steps consult. Sound because the registry is
/// sealed at genesis and never drifts (P1/P2, R1/R2): the cache can never go
/// stale, and it agrees with what `emit_core` consults inside the txn.
///
/// The handle holds no links. `Σ.L` — the append-only store itself — is
/// [`crate::LinkState`]'s map, reached through [`crate::HasLinks`] and read
/// by `readlink`; this type is the write half, the counterpart to M8's
/// `LinkQuery`.
pub struct LinkWriter<'k, W: WorldState> {
    kernel: &'k Kernel<W>,
    registry: Arc<TypeRegistry>,
}

/// The handle prints as itself: `Kernel` is deliberately opaque and the
/// registry is genesis config, so neither is worth rendering — and asking for
/// no `W: Debug` keeps this type from being the reason a consumer's own
/// derive fails.
impl<W: WorldState> fmt::Debug for LinkWriter<'_, W> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LinkWriter").finish_non_exhaustive()
    }
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
#[derive(Debug, Clone)]
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

impl<'k, W> LinkWriter<'k, W>
where
    W: WorldState + HasLinks,
{
    /// Construct the writer handle: takes ONE `kernel.snapshot()` and clones
    /// the `Arc<TypeRegistry>` off `snapshot.world().links()` — a refcount
    /// bump of the slice's rebuilt registry (§C).
    pub fn new(kernel: &'k Kernel<W>) -> LinkWriter<'k, W> {
        let snap = kernel.snapshot();
        let registry = Arc::clone(&snap.world().links().registry);
        LinkWriter { kernel, registry }
    }
}

/// Admission DISCIPLINE selector — never the value (effect-identity: the gate
/// adds preconditions only and never alters `value`, ASN-0126 π).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Gate {
    /// MAKELINK / editlink successor: `e₃ ≠ ∅` only.
    Open,
    /// Emit_K / assert_sup / editlink claim: registered ∧ shape-conformant ∧
    /// K ≁ R; idem⊤ ⇒ active-view dedup check.
    Managed,
    /// Nullify: the Managed discipline with the `[R]` class ADMITTED rather
    /// than refused — the one clause that separates the two.
    Retraction,
}

/// `emit_core`'s internal error; each public op maps it through the `From`
/// impls below (§2 error mapping). `HomeNotRegistered` originates at the
/// hoisted home check alone — the hoist makes `home` known-registered before
/// the mint, so `mint_link`'s own `HomeNotRegistered` branch is unreachable
/// and every other `MintError` rides `Mint`. `NotOwner` is the ω backstop
/// (as amended 2026-08-16): every deposit passes this one choke point, so
/// no caller path can reach the mint without the ownership check having
/// run — the per-op hoists exist only to pin each op's error ORDER.
#[derive(Debug)]
enum EmitCoreError {
    HomeNotRegistered,
    NotOwner(Address),
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

// §2 error mapping. Every impl enumerates all seven variants: the dead ones
// are the paths the design proves cannot fire under that op's gate
// discipline, and naming them is what makes a new `EmitCoreError` variant a
// compile error at all five sites instead of a panic at one.

impl From<EmitCoreError> for MakeLinkError {
    // Open: only EmptyType/HomeNotRegistered/NotOwner/Mint reachable.
    fn from(e: EmitCoreError) -> Self {
        match e {
            EmitCoreError::EmptyType => MakeLinkError::EmptyTypeResolution,
            EmitCoreError::HomeNotRegistered => MakeLinkError::HomeNotRegistered,
            EmitCoreError::NotOwner(a) => MakeLinkError::NotOwner(a),
            EmitCoreError::Mint(m) => MakeLinkError::Mint(m),
            EmitCoreError::NotRegistered
            | EmitCoreError::ShapeViolation
            | EmitCoreError::RetractionClass => {
                unreachable!("Open gate raises no Managed/Retraction rejection")
            }
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
            EmitCoreError::NotOwner(a) => EmitError::NotOwner(a),
            EmitCoreError::NotRegistered => EmitError::NotRegistered,
            EmitCoreError::ShapeViolation => EmitError::ShapeViolation,
            EmitCoreError::RetractionClass => EmitError::RetractionClass,
            EmitCoreError::Mint(m) => EmitError::Mint(m),
            EmitCoreError::EmptyType => unreachable!("managed e₃ = ty ∈ T_admissible"),
        }
    }
}

impl From<EmitCoreError> for NullifyError {
    // Retraction: the shared discipline's verdicts are all dead here — the
    // `[R]` class is genesis-registered (never NotRegistered) and Binary
    // against a tuple nullify builds at |F| = |G| = 1 (never ShapeViolation),
    // and K ≁ R refuses `[R]` under Managed alone. P-tgt is nullify's own.
    fn from(e: EmitCoreError) -> Self {
        match e {
            EmitCoreError::HomeNotRegistered => NullifyError::HomeNotRegistered,
            EmitCoreError::NotOwner(a) => NullifyError::NotOwner(a),
            EmitCoreError::Mint(m) => NullifyError::Mint(m),
            EmitCoreError::NotRegistered
            | EmitCoreError::ShapeViolation
            | EmitCoreError::RetractionClass
            | EmitCoreError::EmptyType => {
                unreachable!("[R] is genesis-registered Binary and admitted under Retraction")
            }
        }
    }
}

impl From<EmitCoreError> for AssertSupError {
    // Managed/K_sup: the registry-fixed class makes the gate variants
    // unreachable.
    fn from(e: EmitCoreError) -> Self {
        match e {
            EmitCoreError::HomeNotRegistered => AssertSupError::HomeNotRegistered,
            EmitCoreError::NotOwner(a) => AssertSupError::NotOwner(a),
            EmitCoreError::Mint(m) => AssertSupError::Mint(m),
            EmitCoreError::NotRegistered
            | EmitCoreError::ShapeViolation
            | EmitCoreError::RetractionClass
            | EmitCoreError::EmptyType => unreachable!(
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
            EmitCoreError::NotOwner(a) => EditLinkError::NotOwner(a),
            EmitCoreError::Mint(m) => EditLinkError::Mint(m),
            EmitCoreError::NotRegistered
            | EmitCoreError::ShapeViolation
            | EmitCoreError::RetractionClass => {
                unreachable!("editlink pre-checks DC/arity/residence; K_sup claim registry-fixed")
            }
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
        TxnError::Unencodable(io) => TxnError::Unencodable(io),
        TxnError::OverBudget { bytes } => TxnError::OverBudget { bytes },
        TxnError::Poisoned => TxnError::Poisoned,
    }
}

/// Sh-conf (P3): the value's SPAN COUNTS against the registered shape — never
/// inferring shape from the tuple (a `(1,0)` tuple conforms under Unary AND
/// Multi). All shapes require `|F| = 1`; Unary `|G| = 0`, Binary `|G| = 1`,
/// Multi `|G|` finite. Reads `|F|` and `|G|` off the link itself, so the two
/// counts cannot arrive in the wrong order.
fn sh_conf(shape: Shape, value: &Link) -> bool {
    value.from_slot().len() == 1
        && match shape {
            Shape::Unary => value.to_slot().is_empty(),
            Shape::Binary => value.to_slot().len() == 1,
            Shape::Multi => true,
        }
}

/// The doorkeeper's verdict on a deposit's home documents, in the vocabulary
/// every op translates from (the `From` impls below).
enum HomeFault {
    NotRegistered,
    NotOwner(Address),
}

/// The two questions asked of every home a deposit writes into: registered
/// (P0), then owned (ω, exact account match). ALL registrations are checked
/// before ANY ownership, so an op depositing into two homes reports an
/// unregistered second home ahead of an unowned first — the order `editlink`
/// pins. The payload names the home that failed ownership; M10 threads it
/// into the rejection's fault site.
///
/// This is the hoist that pins each op's error ORDER ahead of its own
/// verdicts. The gate that actually admits a deposit is [`emit_core`], which
/// asks the same two questions of every value that reaches the mint.
fn home_gate(m3: &M3State, caller: Caller, homes: &[&Address]) -> Result<(), HomeFault> {
    for &home in homes {
        if !m3.is_registered_document(home) {
            return Err(HomeFault::NotRegistered);
        }
    }
    for &home in homes {
        if !caller.is_owner(m3, home) {
            return Err(HomeFault::NotOwner(home.clone()));
        }
    }
    Ok(())
}

impl From<HomeFault> for MakeLinkError {
    fn from(e: HomeFault) -> Self {
        match e {
            HomeFault::NotRegistered => MakeLinkError::HomeNotRegistered,
            HomeFault::NotOwner(a) => MakeLinkError::NotOwner(a),
        }
    }
}

impl From<HomeFault> for NullifyError {
    fn from(e: HomeFault) -> Self {
        match e {
            HomeFault::NotRegistered => NullifyError::HomeNotRegistered,
            HomeFault::NotOwner(a) => NullifyError::NotOwner(a),
        }
    }
}

impl From<HomeFault> for AssertSupError {
    fn from(e: HomeFault) -> Self {
        match e {
            HomeFault::NotRegistered => AssertSupError::HomeNotRegistered,
            HomeFault::NotOwner(a) => AssertSupError::NotOwner(a),
        }
    }
}

impl From<HomeFault> for EditLinkError {
    fn from(e: HomeFault) -> Self {
        match e {
            HomeFault::NotRegistered => EditLinkError::HomeNotRegistered,
            HomeFault::NotOwner(a) => EditLinkError::NotOwner(a),
        }
    }
}

/// The single choke point both write surfaces share (§2), run INSIDE one
/// `transact`. Bounds are [`crate::LinkWorld`] with no `HasM5`, so it has NO
/// seat step — the seat is staged by MAKELINK itself, the lone `HasM5`
/// caller, after this returns. Any dedup LOCK was acquired by the public op
/// before the transact (§3 step 1); this does the hoisted home check and the
/// in-txn dedup CHECK.
///
/// The hoisted home check (Conflicts §8, a deliberate divergence from
/// ASN-0128 I1's miss-only read) runs ahead of EVERY gate/dedup
/// short-circuit, so an unregistered-home emit is rejected on every path —
/// miss AND hit; callers cannot observe the branch, which is what makes the
/// contract portable. The ω check (as amended 2026-08-16) rides directly
/// behind it under the same discipline: a non-owner deposit is rejected on
/// hit AND miss, and because every deposit passes THIS choke point, no
/// caller can reach the mint ungated.
fn emit_core<W>(
    stg: &mut Staging<W>,
    caller: Caller,
    home: &Address,
    value: Link,
    gate: Gate,
) -> Result<Address, EmitCoreError>
where
    W: LinkWorld,
    W::Record: From<LinkRec> + From<M3Rec>,
{
    // STORE-INVARIANT BACKSTOP (§2): every caller builds arity 3
    // (MAKELINK/Emit_K/assert_sup/claim; editlink pre-checks), so this never
    // trips — but it guarantees type_slices, the FROM/TO/TYPE slots the
    // discovery primitives index, and ASN-0086's |Σ.L| = 3 hold locally.
    assert_eq!(value.arity(), 3, "emit_core: the store holds only arity-3 links");
    if !stg.working().m3().is_registered_document(home) {
        return Err(EmitCoreError::HomeNotRegistered);
    }
    if !caller.is_owner(stg.working().m3(), home) {
        return Err(EmitCoreError::NotOwner(home.clone()));
    }
    match gate {
        Gate::Open => {
            if value.type_slot().is_empty() {
                return Err(EmitCoreError::EmptyType); // L3 at the write boundary
            }
        }
        // ONE discipline, derived from the value's own class: registered,
        // shape-conformant per the REGISTERED shape, idem⊤ ⇒ active-view
        // dedup. `[R]` reaches it as an ordinary registered class — the
        // genesis registration supplies Binary and idem⊤, so nullify's
        // discipline is read from the registry rather than restated here,
        // and the two can never disagree.
        Gate::Managed | Gate::Retraction => {
            let links = stg.working().links();
            // Total: the type slot is level-uniform by upstream validation
            // (emit's ty is address-denoting; the claim's and the retraction
            // emitter's types are the genesis-fixed reserved endsets).
            let class = coverage_class(value.type_slot());
            let Some(reg) = links.registry.registration(&class) else {
                return Err(EmitCoreError::NotRegistered); // (i)
            };
            if gate == Gate::Managed && class == *links.shipped_class(ShippedType::Retraction) {
                return Err(EmitCoreError::RetractionClass); // K ≁ R
            }
            if !sh_conf(reg.shape, &value) {
                return Err(EmitCoreError::ShapeViolation); // (ii)
            }
            if reg.idem {
                if let Some(incumbent) = links.active_incumbent(&DedupKey::of(&value)) {
                    return Ok(incumbent); // zero-step: stage NOTHING
                }
            }
        }
    }
    // K.λ via M3 (home already known-registered, so mint's own
    // HomeNotRegistered branch is unreachable; other MintError → Mint).
    let (addr, m3rec) = stg.working().m3().mint_link(home)?;
    stg.push(m3rec.into());
    stg.push(
        LinkRec::Deposit {
            addr: addr.tumbler().clone(),
            value,
        }
        .into(),
    );
    Ok(addr)
}

/// wf for one MAKELINK `Resolve` spec: a registered source, and a depth-2
/// content V-position with ordinal displacement — `#start = 2 ∧ start₁ = s_C
/// ∧ #width = 2 ∧ width₁ = 0`, the deliberate depth-2 narrowing of ASN-0120's
/// `#u_j ≥ 2` (Conflicts §12).
///
/// The V-position's subspace is the start's FIRST component, NOT M1's
/// `Address::subspace()` (which needs zeros = 3 and would reject every depth-2
/// spec). Every component read is fallible, so a spec of any shape answers
/// rather than faulting, and the length tests state the depth this narrowing
/// wants rather than guarding the reads.
fn is_wf_content_spec(m3: &M3State, spec: &VSpec) -> bool {
    m3.is_registered_document(&spec.source)
        && spec.span.start().len() == 2
        && spec.span.start().get(1) == Some(&content_subspace())
        && spec.span.width().len() == 2
        && spec.span.width().get(1).is_some_and(|w| w.bits() == 0)
}

/// One MAKELINK slot's endset, read off the txn base. `Resolve`: ρ as content
/// I-extents — readable, level-uniform spans (ML1 coverage-exactness by
/// construction: the runs trace exactly allocated content, cross-origin runs
/// arrive un-coalesced). `Addrs`: the canonical name encoding, deposited
/// unresolved.
fn slot_endset(m5: &M5State, slot: &SlotArg) -> Endset {
    match slot {
        SlotArg::Resolve(specs) => specs
            .iter()
            .flat_map(|spec| {
                m5.resolve(&spec.source, &spec.span)
                    .into_iter()
                    .map(|run| run.iextent())
            })
            .collect(),
        SlotArg::Addrs(addrs) => enc(addrs),
    }
}

impl<'k, W> LinkWriter<'k, W>
where
    W: LinkWorld + HasM5,
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
    /// Every `Resolve` spec is wf-checked ([`is_wf_content_spec`]) before any
    /// slot is built. `Addrs` slots get no wf step: T4 validity is the whole
    /// precondition, already carried by the `Address` type.
    ///
    /// The two SOLE-WRITER fences apply here as they do on the managed
    /// surface: a resolved type slot in the `[R]` class
    /// (`RetractionClass`) or the `[K_sup]` class (`SupersessionClass`) is
    /// refused. They are the open surface's whole type discipline, and they
    /// are not optional — [`crate::LinkState::apply_link`]'s hint fold
    /// recognizes a deposit by its type slot's coverage class alone, so an
    /// `[R]`-classed link deposited through this surface would tombstone
    /// every address its TO slot denotes, and a `[K_sup]`-classed one would
    /// enter the supersession adjacency as a claim, both without any of the
    /// ownership, residence or schema checks `nullify`, `assert_sup` and
    /// `editlink` establish.
    pub fn makelink(
        &self,
        caller: Caller,
        home: &Address,
        from: SlotArg,
        to: SlotArg,
        ty: SlotArg,
    ) -> Result<(Address, Seq), TxnError<MakeLinkError>> {
        let r_class = self.registry.shipped_class(ShippedType::Retraction);
        let sup_class = self.registry.shipped_class(ShippedType::Supersedes);
        self.kernel
            .transact(&[M3State::link_lock_key(home)], |stg| {
                let (e1, e2, e3) = {
                    let base = stg.base();
                    // P0 then ω on home, hoisted so both win over every
                    // spec/type verdict.
                    home_gate(base.m3(), caller, &[home])?;
                    let specs = from.specs().iter().chain(to.specs()).chain(ty.specs());
                    if !specs
                        .into_iter()
                        .all(|spec| is_wf_content_spec(base.m3(), spec))
                    {
                        return Err(MakeLinkError::IllFormedSpec);
                    }
                    (
                        slot_endset(base.m5(), &from),
                        slot_endset(base.m5(), &to),
                        slot_endset(base.m5(), &ty),
                    )
                };
                if e3.is_empty() {
                    return Err(MakeLinkError::EmptyTypeResolution); // ML6, as-given
                }
                // The sole-writer fences. Total: a `Resolve` slot is
                // level-uniform by M5's construction and an `Addrs` slot is
                // address-denoting, which are the same two grounds under
                // which the fold classifies this very value one step later.
                let e3_class = coverage_class(&e3);
                if e3_class == *r_class {
                    return Err(MakeLinkError::RetractionClass); // K ≁ R
                }
                if e3_class == *sup_class {
                    return Err(MakeLinkError::SupersessionClass); // Conflicts §10
                }
                let value = Link::triple(e1, e2, e3);
                let addr = emit_core(stg, caller, home, value, Gate::Open)?;
                let seat = stage_seat_link(stg.working().m5(), home, &addr)?;
                stg.push(seat.into());
                Ok(addr)
            })
    }
}

impl<'k, W> LinkWriter<'k, W>
where
    W: LinkWorld,
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
        caller: Caller,
        home: &Address,
        ty: &Endset,
        from: &Address,
        to: &[Address],
    ) -> Result<(Address, Seq), TxnError<EmitError>> {
        if !is_address_denoting(ty) {
            return Err(TxnError::Rejected(EmitError::NonAddressDenotingType));
        }
        let class = coverage_class(ty);
        if class == *self.registry.shipped_class(ShippedType::Supersedes) {
            return Err(TxnError::Rejected(EmitError::SupersessionClass));
        }
        let idem = self.registry.registration(&class).is_some_and(|r| r.idem);
        let value = Link::triple(enc([from]), enc(to), ty.clone());
        let mut keys: Vec<LockKey> = Vec::with_capacity(2);
        if idem {
            keys.push(DedupKey::of(&value).lock_key());
        }
        keys.push(M3State::link_lock_key(home));
        self.kernel.transact(&keys, |stg| {
            let addr = emit_core(stg, caller, home, value, Gate::Managed)?;
            Ok(addr)
        })
    }

    /// Nullify_Binary (ASN-0128): the SOLE retraction path — an `[R]` tuple
    /// with canonical from-fill `enc({home})` and unit-depth to-span
    /// `enc({target})`, idem⊤ (re-retracting the same target from the same
    /// home dedups). P-tgt is a REJECTING precondition against the txn base:
    /// `target` is a resident link OR this call's own fresh emitter — the
    /// address the slice reports `mint_link(home)` would mint next, an O(1)
    /// read equal to that mint by construction (FrontierUnification,
    /// Conflicts §7) — so sterilization is unreachable through this surface
    /// (DR). Lock set `[dedup_key, link_lock_key(home)]`.
    ///
    /// Ownership (as amended 2026-08-16): the caller must own `home` AND the
    /// TARGET link — ω applied to the link's own address, which resolves to
    /// the account of the link's home document. Self-retraction only; the
    /// broader moderation question (territorial retraction, viewer-side
    /// filtering) is an explicitly deferred scope decision (wire.md). Both
    /// checks precede P-tgt, so the auth verdict never depends on residence
    /// timing. The self-emitter case passes by arithmetic: the fresh
    /// emitter's account IS home's account.
    pub fn nullify(
        &self,
        caller: Caller,
        home: &Address,
        target: &Address,
    ) -> Result<(Address, Seq), TxnError<NullifyError>> {
        let retraction = self.registry.reserved_type(ShippedType::Retraction).clone();
        let value = Link::triple(enc([home]), enc([target]), retraction);
        let keys = [DedupKey::of(&value).lock_key(), M3State::link_lock_key(home)];
        self.kernel.transact(&keys, |stg| {
            {
                let base = stg.base();
                home_gate(base.m3(), caller, &[home])?; // P0 then ω on home
                if !caller.is_owner(base.m3(), target) {
                    return Err(NullifyError::NotOwner(target.clone())); // v1 target policy
                }
                if !base.links().resident(target.tumbler())
                    && *target != base.links().next_link_address(home)
                {
                    return Err(NullifyError::BadTarget); // P-tgt
                }
            }
            let addr = emit_core(stg, caller, home, value, Gate::Retraction)?;
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
        caller: Caller,
        home: &Address,
        old: &Address,
        new: &Address,
    ) -> Result<(Address, Seq), TxnError<AssertSupError>> {
        let sup = self.registry.reserved_type(ShippedType::Supersedes).clone();
        let value = Link::triple(enc([old]), enc([new]), sup);
        let keys = [DedupKey::of(&value).lock_key(), M3State::link_lock_key(home)];
        self.kernel.transact(&keys, |stg| {
            {
                let base = stg.base();
                // P0 then ω on home, before the endpoint verdicts.
                home_gate(base.m3(), caller, &[home])?;
                if !base.links().resident(old.tumbler()) || !base.links().resident(new.tumbler()) {
                    return Err(AssertSupError::EndpointNotResident);
                }
                if old == new {
                    return Err(AssertSupError::SelfSupersession); // irreflexive
                }
            }
            let addr = emit_core(stg, caller, home, value, Gate::Managed)?;
            Ok(addr)
        })
    }

    /// editlink (ASN-0125 EDITop): ONE composite over the two home alloc
    /// keys — deduped before the transact (`d_s == d_a` collapses `[k, k]`
    /// to `[k]`; M2's `transact(keys)` makes no duplicate-key promise) —
    /// inlining two `emit_core` calls (the public `assert_sup` CANNOT be
    /// called: M2 is non-reentrant). Allocates the fresh successor (value
    /// supplied — M10 builds it via M5 `resolve` + `Run::iextent` +
    /// `Endset::from_spans`/`enc` + `Link::triple`, off any prior snapshot —
    /// ML8/EL0), then asserts it supersedes `original`. Successor born
    /// UNSEATED; both writes commit atomically (EL7); `original` untouched
    /// (L12).
    ///
    /// Rejects (against the txn base): unregistered `d_s`/`d_a`;
    /// non-resident `original`; a successor of arity ≠ 3 (Conflicts §11),
    /// empty type slot, or a non-level-uniform span in any slot
    /// (`IllFormedSuccessor` — the last keeps `coverage_class` total for
    /// both the DC guard and the fold's dedup key); DC — a
    /// retraction-typed successor, or a `[K_sup]`-typed one without the
    /// Df-DISC(ii) schema (unit-depth single-addr F/G, resident endpoints,
    /// irreflexive) (`DcViolation`). The claim's dedup check is a guaranteed
    /// miss (its key carries the fresh successor), so no claim dedup lock is
    /// taken (§3).
    pub fn editlink(
        &self,
        caller: Caller,
        original: &Address,
        successor: Link,
        d_s: &Address,
        d_a: &Address,
    ) -> Result<(Address, Address, Seq), TxnError<EditLinkError>> {
        let mut keys = vec![M3State::link_lock_key(d_s)];
        let d_a_key = M3State::link_lock_key(d_a);
        if d_a_key != keys[0] {
            keys.push(d_a_key);
        }
        let sup = self.registry.reserved_type(ShippedType::Supersedes).clone();
        let sup_class = self.registry.shipped_class(ShippedType::Supersedes);
        let r_class = self.registry.shipped_class(ShippedType::Retraction);
        let ((succ, claim), seq) = self.kernel.transact(&keys, |stg| {
            {
                let base = stg.base();
                // P0 on both homes, then ω on both: the successor deposits
                // into d_s, the claim into d_a — the rejection carries the
                // home that failed.
                home_gate(base.m3(), caller, &[d_s, d_a])?;
                if !base.links().resident(original.tumbler()) {
                    return Err(EditLinkError::OriginalNotResident);
                }
                // Level-uniformity is required of EVERY slot, not just the
                // one the DC guard classifies: a deposit of a registered
                // idem⊤ class folds a dedup key over all three slots
                // ([`crate::LinkState::apply_link`]), and `coverage_class`
                // aborts on a non-level-uniform span. Checking only the type
                // slot would leave a caller-supplied F or G reaching that
                // abort from inside the transact.
                let well_formed = successor.arity() == 3
                    && !successor.type_slot().is_empty()
                    && (1..=successor.arity()).all(|i| {
                        successor
                            .slot(i)
                            .is_some_and(|e| e.spans().all(|s| s.is_level_uniform()))
                    });
                if !well_formed {
                    return Err(EditLinkError::IllFormedSuccessor);
                }
                // DC guard — total: every slot was just checked
                // level-uniform.
                let successor_class = coverage_class(successor.type_slot());
                if successor_class == *r_class {
                    return Err(EditLinkError::DcViolation);
                }
                if successor_class == *sup_class {
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
            let succ = emit_core(stg, caller, d_s, successor, Gate::Open)?;
            let claim_value = Link::triple(enc([original]), enc([&succ]), sup.clone());
            let claim = emit_core(stg, caller, d_a, claim_value, Gate::Managed)?;
            Ok((succ, claim))
        })?;
        Ok((succ, claim, seq))
    }

    /// BH4 batch tooling (§7): nullify every stale tuple of `ty` (age >
    /// `horizon` over the type-`ty` active slice), the stale set snapshotted
    /// at entry. Served only where declared, and the snapshot read that
    /// builds the batch is what declares it: `stale`'s own `NotBh4` refusal
    /// lifts into `TxnError::Rejected(RetractStaleError::NotBh4)` —
    /// PRE-TRANSACT, no transaction opened, the same channel as `emit`'s
    /// pre-transact rejections — so the batch nullifier can never be aimed
    /// at an idem⊤ class (e.g. mass-nullifying old `[K_sup]` claims); v1
    /// ships no BH4 type, so every call rejects until an app registers one.
    /// NOT atomic — a sequence of
    /// `nullify` transacts, each failure lifted through
    /// `RetractStaleError::Nullify`; on the first `TxnError` it returns
    /// `Err`, leaving earlier nullifies committed and durable (append-only,
    /// no rollback) — a re-run with the same `d_retr` is safe
    /// (already-nullified targets from this `d_retr` dedup; the recomputed
    /// stale set excludes them).
    pub fn retract_stale(
        &self,
        caller: Caller,
        d_retr: &Address,
        ty: &Endset,
        horizon: u64,
    ) -> Result<Vec<(Address, Seq)>, TxnError<RetractStaleError>> {
        let stale: Vec<Address> = {
            let snap = self.kernel.snapshot();
            let world = snap.world();
            world
                .links()
                .stale(ty, horizon)
                .map_err(|NotBh4| TxnError::Rejected(RetractStaleError::NotBh4))? // §7
        };
        let mut out = Vec::with_capacity(stale.len());
        for target in &stale {
            out.push(self.nullify(caller, d_retr, target).map_err(lift_nullify)?);
        }
        Ok(out)
    }
}
