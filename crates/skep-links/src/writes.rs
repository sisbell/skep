//! §C/§D — the transact-driving write surface: [`LinkWriter`] (the kernel
//! handle), the shared single choke point [`emit_core`] with its
//! two-disciplines gate (§2), the M2 keyed dedup sections (§3), and the six
//! public ops (five deposits plus the BH4 batch).
//!
//! Concurrency belongs to the kernel: nothing here locks, threads, or caches.
//! The type registry every gate reads is the module's compiled format
//! constant, so no handle carries one.
//!
//! Ownership (as amended 2026-08-16): every op that deposits into a home
//! document's link subspace takes a [`Caller`] and requires
//! `caller.is_owner(m3, home)` — the in-txn ω gate, enforced at
//! [`emit_core`] (hit AND miss) with per-op hoists pinning error order;
//! `nullify` additionally requires owning the TARGET link (self-retraction
//! only in v1).

use std::fmt;

use skep_address::{content_subspace, Address, Span};
use skep_arrangement::{stage_seat_link, Caller, HasM5, M5Rec, M5State, SeatError, VSpec};
use skep_kernel::{Kernel, LockKey, Seq, Staging, TxnError, WorldState};
use skep_namespace::{M3Rec, M3State, MintError};

use crate::dedup::DedupKey;
use crate::endset::{coverage_class, enc, Endset, Link};
use crate::error::{
    AssertSupError, EditLinkError, EmitError, MakeLinkError, NotBh4, NullifyError,
    RetractStaleError,
};
use crate::registry::{registry, sh_conf, ShippedType};
use crate::state::LinkRec;
use crate::LinkWorld;

/// M7's single writer of link values — the transact-driving handle, and
/// nothing but `&'k Kernel<W>`. The registration and reserved-class reads of
/// §3's pre-transact steps go to the module's format registry
/// ([`registry`]), a compiled constant: there is no per-handle copy to keep,
/// so the question of whether a cache agrees with what `emit_core` consults
/// inside the txn does not arise.
///
/// The handle holds no links either. `Σ.L` — the append-only store itself — is
/// [`crate::LinkState`]'s map, reached through [`crate::HasLinks`] and read
/// by `readlink`; this type is the write half, the counterpart to M8's
/// `LinkQuery`.
pub struct LinkWriter<'k, W: WorldState> {
    kernel: &'k Kernel<W>,
}

/// The handle prints as itself: `Kernel` is deliberately opaque, so it is not
/// worth rendering — and asking for no `W: Debug` keeps this type from being
/// the reason a consumer's own derive fails.
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
    W: WorldState,
{
    /// Construct the writer handle: it holds the borrow and nothing else —
    /// no snapshot, no state, exactly as `Namespace::new` and `Vstream::new`
    /// do (§C).
    pub fn new(kernel: &'k Kernel<W>) -> LinkWriter<'k, W> {
        LinkWriter { kernel }
    }
}

/// The WHOLE M2 lock set a deposit needs: the I0 section iff the value's
/// class is a REGISTERED idem⊤ one — the same predicate [`emit_core`]
/// evaluates on `reg.idem`, so the section is taken exactly when the check
/// reads one — then the home's alloc key, always. A caller hands the
/// result to `transact` entire and adds nothing.
///
/// One derivation of the dedup DECISION, beside [`DedupKey::of`]'s one
/// derivation of the key, so "the section M2 serializes is the section the
/// check reads" covers taking a section at all and not merely which bytes
/// it carries.
///
/// A free function beside the gate it mirrors, taking no handle, because the
/// set is a function of the VALUE and its home: the class comes from the
/// module's format registry and the keys from M3's spelling, so there is no
/// world to read and no kernel to hold.
///
/// The two ops that deliberately take NO dedup section say so at their own
/// key sets: MAKELINK, whose open surface faces no dedup check (ML0), and
/// `editlink`'s claim, whose check is a guaranteed miss. Costs `emit` a
/// second classification of its `ty` — one ascending pass over a type
/// slot's denoted addresses, on a path that already pays one.
fn deposit_lock_set(value: &Link, home: &Address) -> Vec<LockKey> {
    let mut keys: Vec<LockKey> = Vec::with_capacity(2);
    let class = coverage_class(value.type_slot());
    if registry().registration(&class).is_some_and(|r| r.idem) {
        keys.push(DedupKey::of(value).lock_key());
    }
    keys.push(M3State::link_lock_key(home));
    keys
}

/// Admission DISCIPLINE selector — never the value (effect-identity: the gate
/// adds preconditions only and never alters `value`, ASN-0126 π).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Gate {
    /// MAKELINK / editlink successor: `e₃ ≠ ∅` only — and the ONE statement
    /// of it. Neither open-surface caller repeats the test; each states the
    /// obligation in its contract and reads the verdict back through its own
    /// `From<EmitCoreError>` (§2), so no deposited link can carry an empty
    /// type slot however it arrived. Runs NO dedup, so this gate always
    /// answers [`Deposited::Fresh`]: it is what MAKELINK's seat step rests on.
    Open,
    /// Emit_K / assert_sup / editlink claim: registered ∧ shape-conformant ∧
    /// K ≁ R; idem⊤ ⇒ active-view dedup check.
    Managed,
    /// Nullify: the Managed discipline with the `[R]` class ADMITTED rather
    /// than refused — the one clause that separates the two.
    Retraction,
}

/// What [`emit_core`] did — two words, because the choke point has two
/// outcomes and an `Address` alone names both.
enum Deposited {
    /// Freshly minted: the M3 allocation and the `LinkRec` are staged.
    Fresh(Address),
    /// The active incumbent of an idem⊤ class: NOTHING staged.
    Incumbent(Address),
}

impl Deposited {
    /// The address, whichever outcome — for a caller that stages nothing
    /// downstream naming it, and reports it as "the address of the tuple of
    /// this identity" (`emit`, `nullify`, `assert_sup`).
    fn address(self) -> Address {
        match self {
            Deposited::Fresh(addr) | Deposited::Incumbent(addr) => addr,
        }
    }

    /// The address of a link THIS call minted — what a caller staging a seat
    /// for it, or handing it back as freshly its own, is relying on. Stating
    /// the reliance here is what keeps it from being an argument in a
    /// doc-comment: MAKELINK takes [`Gate::Open`], which runs no dedup, and
    /// `editlink`'s claim keys its I0 on a successor minted moments earlier in
    /// the same transaction, so neither can meet an incumbent.
    fn minted(self) -> Address {
        match self {
            Deposited::Fresh(addr) => addr,
            Deposited::Incumbent(_) => unreachable!(
                "emit_core returns an incumbent only under Managed/Retraction on an idem⊤ \
                 class; this caller took the Open gate or keys its I0 on an address minted \
                 in this same transaction"
            ),
        }
    }
}

/// What an edit deposited (ASN-0125 EDITop): the fresh successor, and the
/// `[K_sup]` claim asserting it supersedes the original. Two same-typed
/// addresses, NAMED — the pair is permanently distinguishable only by which
/// home's link chain each landed on, the successor in `d_s` and the claim in
/// `d_a`, so a positional pair would carry that distinction in a convention
/// rather than in the value. M10 puts the two on the wire under these same
/// names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Edit {
    /// The fresh successor, deposited in `d_s`.
    pub successor: Address,
    /// The `[K_sup]` claim that `original` is superseded by `successor`,
    /// deposited in `d_a`.
    pub claim: Address,
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
    // Open: only EmptyType/HomeNotRegistered/NotOwner/Mint reachable, and
    // EmptyType is ML6 arriving from the gate that owns it.
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
    // `[R]` class is shipped-registered (never NotRegistered) and Binary
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
                unreachable!("[R] is shipped-registered Binary and admitted under Retraction")
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
    // successor (Open): EmptyType → IllFormedSuccessor, the empty-type-slot
    // cause arriving from the gate that owns it; claim (Managed/K_sup).
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
///
/// The two ask them of DIFFERENT states — every caller here reads the txn
/// BASE, `emit_core` reads the WORKING world — and cannot disagree: the only
/// records a composite stages between them are M3 element allocations and
/// link deposits, and neither changes a document's registration or its
/// effective owner. `editlink` is where the gap is real (its second
/// `emit_core` runs after the first has staged both), which is why the
/// agreement is an argument rather than an observation.
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
///
/// Both questions are asked of the WORKING world, where the per-op hoist
/// asked them of the txn base. The two verdicts agree because the only
/// records a composite stages in between are M3 element allocations and link
/// deposits, neither of which touches document registration or ω — so the
/// hoist pins the error order without the backstop being able to contradict
/// it.
///
/// RETURN CONTRACT: [`Deposited`], which distinguishes a freshly minted
/// address (two records staged) from an idem⊤ INCUMBENT (nothing staged). A
/// caller that stages anything downstream naming the address takes
/// [`Deposited::minted`], which states that reliance where it is relied on.
fn emit_core<W>(
    stg: &mut Staging<W>,
    caller: Caller,
    home: &Address,
    value: Link,
    gate: Gate,
) -> Result<Deposited, EmitCoreError>
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
        // shipped registration supplies Binary and idem⊤, so nullify's
        // discipline is read from the registry rather than restated here,
        // and the two can never disagree.
        Gate::Managed | Gate::Retraction => {
            // Total: the type slot is level-uniform by upstream validation
            // (emit's ty is address-denoting; the claim's and the retraction
            // tuple's types are the format-fixed reserved endsets).
            let class = coverage_class(value.type_slot());
            let Some(reg) = registry().registration(&class) else {
                return Err(EmitCoreError::NotRegistered); // (i)
            };
            if gate == Gate::Managed && class == *registry().shipped_class(ShippedType::Retraction)
            {
                return Err(EmitCoreError::RetractionClass); // K ≁ R
            }
            if !sh_conf(reg.shape, &value) {
                return Err(EmitCoreError::ShapeViolation); // (ii)
            }
            if reg.idem {
                // The one question this gate asks of the WORLD rather than of
                // the format: the three reads above are the module's compiled
                // registry, and only this one is per-store state.
                let links = stg.working().links();
                if let Some(incumbent) = links.active_incumbent(&DedupKey::of(&value)) {
                    return Ok(Deposited::Incumbent(incumbent)); // zero-step
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
    Ok(Deposited::Fresh(addr))
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

/// The most spans ONE slot may carry — the budget every caller-shaped slot
/// is held to, whichever form built it: MAKELINK's [`SlotArg::Resolve`] and
/// [`SlotArg::Addrs`] slots ([`MakeLinkError::SlotTooLarge`]), an `editlink`
/// successor's slots ([`EditLinkError::SlotTooLarge`]), and BOTH of
/// [`emit`](LinkWriter::emit)'s caller-sized slots — `to` and `ty`
/// ([`EmitError::SlotTooLarge`]).
///
/// Both slot forms amplify, and differently. A `Resolve` slot's span count is
/// not the request's size at all: `resolve` yields one run per contiguous
/// I-segment, so one ~80-byte spec expands to as many spans as the SOURCE
/// document happens to be fragmented, a slot's specs sum those, and the
/// result is stored VERBATIM (ML1 coverage-exactness forbids coalescing it
/// away). An address-named slot's span COUNT is linear in the request, but
/// its BYTES are not: a dotted address is ~19 wire bytes and the span it
/// becomes is `subtree_of` over it — two 8-component `BigUint` tumblers,
/// order half a kilobyte live — so a slot bounded only by the request body
/// would name hundreds of thousands of spans.
///
/// The budget is per-slot live memory and per-slot permanent store.
/// `MAX_TXN_BYTES` bounds neither: it is charged against the ENCODED
/// transaction after the closure returns, and the encoded form of a span is a
/// small fraction of the live one. At order half a kilobyte per element-level
/// span this bound is ~2 MB a slot and ~6 MB across a three-slot MAKELINK:
/// the order of the request body a caller is allowed to send in the first
/// place. MAKELINK's three slots are additionally built and held under M2's
/// applier lock; `emit` builds its value before the transact, and an
/// `editlink` successor is built entirely by its caller. It is not a bound on
/// `resolve`'s own per-spec run vector, which is M5's allocation and one
/// source document's fragmentation.
pub const MAX_SLOT_SPANS: usize = 4096;

/// One MAKELINK slot's endset, read off the txn base — `None` iff the slot
/// carries more than [`MAX_SLOT_SPANS`] spans, in either form. `Resolve`: ρ
/// as content I-extents — readable, level-uniform spans (ML1
/// coverage-exactness by construction: the runs trace exactly allocated
/// content, cross-origin runs arrive un-coalesced), counted as they are
/// produced, so an over-budget slot stops accumulating instead of being built
/// and then measured. `Addrs`: the canonical name encoding, deposited
/// unresolved, one span per name, counted before the encoding is built.
fn slot_endset(m5: &M5State, arg: &SlotArg) -> Option<Endset> {
    match arg {
        SlotArg::Resolve(specs) => {
            let mut spans: Vec<Span> = Vec::new();
            for spec in specs {
                for run in m5.resolve(&spec.source, &spec.span) {
                    if spans.len() == MAX_SLOT_SPANS {
                        return None;
                    }
                    spans.push(run.iextent());
                }
            }
            Some(Endset::from_spans(spans))
        }
        SlotArg::Addrs(addrs) => (addrs.len() <= MAX_SLOT_SPANS).then(|| enc(addrs)),
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
    /// endset non-empty AS GIVEN (ML6, so an empty `Addrs` list and an empty
    /// `Resolve` resolution are one rejection; the check belongs to the
    /// deposit gate every link passes, and its verdict arrives here as
    /// `EmptyTypeResolution`), mint a fresh home-scoped link, deposit the
    /// standard triple, then seat it in
    /// `home`'s link subspace (K.μ⁺_L, no R — J-LV). ONE M2 composite under
    /// `link_lock_key(home)` (the held lock and the advanced frontier are
    /// byte-identical — M3's contract). NO shape gate, NO idem dedup
    /// (distinct links always — ML0), NO provenance.
    ///
    /// Every `Resolve` spec is wf-checked — a registered source, and a depth-2
    /// content V-position with ordinal displacement — before any slot is
    /// built; `Addrs` names get no wf step, T4 validity being the whole
    /// precondition and already carried by the `Address` type. EVERY slot,
    /// in either form, is bounded at [`MAX_SLOT_SPANS`] spans
    /// (`SlotTooLarge`): a spec's expansion is the source document's
    /// fragmentation rather than the request's size, and a name's span costs
    /// order half a kilobyte live against ~19 wire bytes, so neither form's
    /// live cost is bounded by the request body that carried it.
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
    ///
    /// RETURNS `(link, seq)`: the address of the deposited link, which is
    /// also the one seated in `home`'s link subspace.
    pub fn makelink(
        &self,
        caller: Caller,
        home: &Address,
        from: SlotArg,
        to: SlotArg,
        ty: SlotArg,
    ) -> Result<(Address, Seq), TxnError<MakeLinkError>> {
        let r_class = registry().shipped_class(ShippedType::Retraction);
        let sup_class = registry().shipped_class(ShippedType::Supersedes);
        // No dedup section: the open surface takes no dedup CHECK either
        // (ML0 — distinct links always), so `deposit_lock_set`'s question does
        // not arise and the home's alloc key is the whole set.
        self.kernel
            .transact(&[M3State::link_lock_key(home)], |stg| {
                let (e1, e2, e3) = {
                    let base = stg.base();
                    // P0 then ω on home, hoisted so both win over every
                    // spec/type verdict.
                    home_gate(base.m3(), caller, &[home])?;
                    let mut specs = from.specs().iter().chain(to.specs()).chain(ty.specs());
                    if !specs.all(|spec| is_wf_content_spec(base.m3(), spec)) {
                        return Err(MakeLinkError::IllFormedSpec);
                    }
                    let endset_of =
                        |arg| slot_endset(base.m5(), arg).ok_or(MakeLinkError::SlotTooLarge);
                    (endset_of(&from)?, endset_of(&to)?, endset_of(&ty)?)
                };
                // The sole-writer fences. Total: a `Resolve` slot is
                // level-uniform by M5's construction and an `Addrs` slot is
                // address-denoting, which are the same two grounds under
                // which the fold classifies this very value one step later.
                // `⟨⟩` classifies as the empty denoted antichain, which is
                // neither shipped class, so ML6 stays the deposit gate's
                // check and no input can satisfy both.
                let e3_class = coverage_class(&e3);
                if e3_class == *r_class {
                    return Err(MakeLinkError::RetractionClass); // K ≁ R
                }
                if e3_class == *sup_class {
                    return Err(MakeLinkError::SupersessionClass); // Conflicts §10
                }
                let value = Link::triple(e1, e2, e3);
                // `minted`, because the seat below names this address: the
                // Open gate runs no dedup, so it cannot be an incumbent.
                let addr = emit_core(stg, caller, home, value, Gate::Open)?.minted();
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
    /// `value = Link[enc({from}), enc(to), ty]` (`|F| = 1` forced, `to`'s
    /// SPAN COUNT shape-checked, `ty` stored verbatim as e₃). Does NOT
    /// seat. idem⊤ ⇒ dedup against the ACTIVE view; a hit returns the
    /// incumbent with the base `Seq` and commits NOTHING.
    ///
    /// The shape gate counts spans, not distinct addresses: `enc(to)` yields
    /// one span per element, so `to = [x, x]` carries `|G| = 2` here and is
    /// refused under Binary, where ASN-0126's set-valued `|G|` admits it
    /// ([`Shape`](crate::Shape)).
    ///
    /// WHAT A HIT RETURNS: the T1-LEAST ACTIVE tuple of the I0 class, which
    /// is the class's incumbent and not a tuple this call admitted. The gate
    /// runs over the value this call BUILT; the incumbent may have been
    /// deposited through the open surface, which applies neither the shape
    /// gate nor a dedup check ([`Shape`](crate::Shape),
    /// [`Registration`](crate::Registration)) — so a caller that reads the
    /// returned address back may find a link its own emission would have been
    /// refused for, and one of several active tuples of that identity.
    ///
    /// PRE-TRANSACT rejections (no transaction opened — §3), in firing order:
    /// `ty` not address-denoting (`NonAddressDenotingType`, before ANY class
    /// computation, keeping `coverage_class` on the safe denoted path); `ty ~
    /// [K_sup]` (`SupersessionClass` — assert_sup/editlink are the sole
    /// `[K_sup]`-writers, the parallel of the `[R]` fence; Conflicts §10);
    /// and either caller-sized slot past [`MAX_SLOT_SPANS`] spans —
    /// `to`'s addresses or `ty`'s own spans (`SlotTooLarge`, the same
    /// per-slot budget MAKELINK's slots carry). Ahead of `ShapeViolation`,
    /// which an over-budget `to` also satisfies under every shape but Multi,
    /// and which no `ty` can reach: the shape gate never reads e₃'s count.
    /// The lock set is `[dedup_key, link_lock_key(home)]` for a
    /// registered idem⊤ `ty`, else `[link_lock_key(home)]` — the
    /// registration read goes to the module's format registry, race-free
    /// because that registry is a compiled constant (§3 step 1).
    ///
    /// RETURNS `(tuple, seq)`: the address of the deposited tuple, or — on a
    /// dedup hit — the incumbent's, with the base `Seq`.
    pub fn emit(
        &self,
        caller: Caller,
        home: &Address,
        ty: &Endset,
        from: &Address,
        to: &[Address],
    ) -> Result<(Address, Seq), TxnError<EmitError>> {
        if !ty.is_address_denoting() {
            return Err(TxnError::Rejected(EmitError::NonAddressDenotingType));
        }
        let class = coverage_class(ty);
        if class == *registry().shipped_class(ShippedType::Supersedes) {
            return Err(TxnError::Rejected(EmitError::SupersessionClass));
        }
        // The two managed slots a caller sizes: `enc({from})` is one span,
        // and `to` and `ty` are the caller's. `ty` is stored VERBATIM as e₃
        // and its class collapses repeats, so a registered class is no bound
        // on the slot that carries it. Ahead of the shape gate, which reads
        // neither count — it admits any finite `|G|` under Multi and never
        // looks at e₃ at all.
        if to.len() > MAX_SLOT_SPANS || ty.len() > MAX_SLOT_SPANS {
            return Err(TxnError::Rejected(EmitError::SlotTooLarge));
        }
        let value = Link::triple(enc([from]), enc(to), ty.clone());
        let keys = deposit_lock_set(&value, home);
        self.kernel.transact(&keys, |stg| {
            Ok(emit_core(stg, caller, home, value, Gate::Managed)?.address())
        })
    }

    /// Nullify_Binary (ASN-0128): the SOLE retraction path — an `[R]` tuple
    /// with canonical from-fill `enc({home})` and unit-depth to-span
    /// `enc({target})`, idem⊤ (re-retracting the same target from the same
    /// home dedups). P-tgt is a REJECTING precondition against the txn base:
    /// `target` is a resident link OR the address this call's own retraction
    /// tuple would occupy (`a_emit`) — the address the slice reports
    /// `mint_link(home)` would mint next, an O(1) read equal to that mint by
    /// construction (FrontierUnification, Conflicts §7) — so sterilization is
    /// unreachable through this surface (DR). Lock set `[dedup_key,
    /// link_lock_key(home)]`.
    ///
    /// Ownership (as amended 2026-08-16): the caller must own `home` AND the
    /// TARGET link — ω applied to the link's own address, which resolves to
    /// the account of the link's home document. Self-retraction only; the
    /// broader moderation question (territorial retraction, viewer-side
    /// filtering) is an explicitly deferred scope decision (wire.md). Both
    /// checks precede P-tgt, so the auth verdict never depends on residence
    /// timing, and `home` is checked BEFORE the target — the address
    /// `NotOwner` carries is `home`'s when a caller owns neither. The
    /// self-target case passes by arithmetic: `a_emit`'s account IS home's
    /// account.
    ///
    /// POSTCONDITION, on a fresh deposit and on a dedup hit alike:
    /// `is_nullified(target)` holds, and `target` is gone from every
    /// `View::Active` slice and every `stale` set — and, where `target` is
    /// itself a `[K_sup]` claim, from every operative `succ_o` edge — while
    /// `readlink` and the `Audit` view keep it (R3).
    ///
    /// A nullified ENDPOINT leaves its edges operative: Df-SUCC reads the
    /// CLAIM's activity and never the endpoint's, so the walk family still
    /// names a nullified successor and `current` still discloses it as a
    /// sink, carrying its own activity (EL14e). Suppressing an endpoint from
    /// the supersession graph means retracting the claims that name it.
    ///
    /// IRREVOCABLE. The tombstone set is monotone (R3/R6a) and the hint fold
    /// re-derives it from the `[R]` link at every replay, whether or not that
    /// link is itself nullified — so retracting a retraction restores
    /// nothing. This is where the module's two suppression mechanisms part
    /// company, and a caller chooses between them here: the BH1 `Retired`
    /// filter reads the ACTIVE retired slice, so retiring is undoable by
    /// nullifying the retirement; nullifying is not undoable by anything.
    ///
    /// RETURNS `(retraction, seq)`: the address of the `[R]` tuple itself —
    /// never `target` — or, on a dedup hit, the incumbent retraction's, with
    /// the base `Seq`. (The born-nullified case is where the two coincide:
    /// there `target` IS the address this tuple occupies.)
    pub fn nullify(
        &self,
        caller: Caller,
        home: &Address,
        target: &Address,
    ) -> Result<(Address, Seq), TxnError<NullifyError>> {
        let retraction = registry().reserved_type(ShippedType::Retraction).clone();
        let value = Link::triple(enc([home]), enc([target]), retraction);
        let keys = deposit_lock_set(&value, home);
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
            Ok(emit_core(stg, caller, home, value, Gate::Retraction)?.address())
        })
    }

    /// assert_sup (ASN-0125/0128): emit "old is superseded by new" —
    /// `F = enc({old})`, `G = enc({new})`, type `[K_sup]` (slot convention
    /// per Conflicts §2: F holds the OLD/superseded link; edges run
    /// old → new). Idem⊤ keyed on `([K_sup], {old}, {new})` — home excluded,
    /// so a duplicate `(old, new)` even from a different home dedups to the
    /// first claim (Conflicts §9). Requires `home` registered, both
    /// endpoints resident, `old ≠ new` (Df-DISC(ii)); checked in that order.
    ///
    /// RETURNS `(claim, seq)`: the address of the `[K_sup]` claim — never an
    /// endpoint — or, on a dedup hit, the incumbent claim's, with the base
    /// `Seq`.
    ///
    /// OWNERSHIP is required on `home` and on NOTHING ELSE: the caller need
    /// not own `old` or `new`, so a claim may be asserted over links owned by
    /// others, and the walk family and M8's lineage reads then report it as
    /// fact. Retracting it needs ω on the CLAIM, whose home is the asserter's
    /// — so the endpoints' owner cannot retract a foreign claim about their
    /// own links. The wider question this belongs to (moderation, viewer-side
    /// filtering) is the deferred scope decision `nullify` names.
    pub fn assert_sup(
        &self,
        caller: Caller,
        home: &Address,
        old: &Address,
        new: &Address,
    ) -> Result<(Address, Seq), TxnError<AssertSupError>> {
        let sup = registry().reserved_type(ShippedType::Supersedes).clone();
        let value = Link::triple(enc([old]), enc([new]), sup);
        let keys = deposit_lock_set(&value, home);
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
            Ok(emit_core(stg, caller, home, value, Gate::Managed)?.address())
        })
    }

    /// editlink (ASN-0125 EDITop): ONE composite over the two home alloc
    /// keys — sorted and deduped before the transact, so the pair reaches M2
    /// in a canonical order rather than the caller's, and `d_s == d_a`
    /// collapses `[k, k]` to `[k]` (M2's `transact(keys)` promises nothing
    /// about order or duplicates, and this is the only op handing it two keys
    /// of one space) — inlining two `emit_core` calls (the public
    /// `assert_sup` CANNOT be called: M2 is non-reentrant). Allocates the
    /// fresh successor (value supplied — M10 builds it via M5 `resolve` +
    /// `Run::iextent` + `Endset::from_spans`/`enc` + `Link::triple`, off any
    /// prior snapshot — ML8/EL0), then asserts it supersedes `original`.
    /// Successor born UNSEATED; both writes commit atomically (EL7);
    /// `original` untouched (L12).
    ///
    /// RETURNS `(edit, seq)`, where [`Edit`] carries the successor's address
    /// and the claim's each under its own name — the successor deposited in
    /// `d_s`, the claim in `d_a` — so the two cannot trade places at a call.
    ///
    /// OWNERSHIP is required on `d_s` and `d_a` and on NOTHING ELSE: the
    /// caller need not own `original`, so an edit may claim to supersede a
    /// link owned by another account, exactly as `assert_sup` may. What the
    /// operation deposits lands in the caller's own homes; what it asserts
    /// about `original` is retractable only by ω on the claim, which is
    /// `d_a`'s.
    ///
    /// Rejects (against the txn base): unregistered `d_s`/`d_a`;
    /// non-resident `original`; a successor slot past [`MAX_SLOT_SPANS`]
    /// spans (`SlotTooLarge` — the slots are the caller's, resolve-built, so
    /// their span count is a source document's fragmentation rather than the
    /// request's size, and every per-span step after this one runs inside the
    /// transact); a successor of arity ≠ 3 (Conflicts §11),
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
    ) -> Result<(Edit, Seq), TxnError<EditLinkError>> {
        // The one op that hands M2 two keys of ONE space, so the one whose
        // relative order would otherwise be the caller's: two concurrent
        // edits over the same pair of homes, named in opposite orders, would
        // present them in opposite orders. Emitted in M2's own bytewise
        // order, so the pair is the same set in the same sequence however it
        // was written, whatever the applier does with it. `dedup` behind the
        // sort subsumes `d_s == d_a` (M2 promises nothing about duplicates).
        //
        // No dedup section, so `deposit_lock_set` is not the shape here: the
        // successor takes the Open gate, which runs no dedup check, and the
        // claim's check is a guaranteed miss (its I0 carries a successor
        // minted inside this transaction).
        let mut keys = vec![M3State::link_lock_key(d_s), M3State::link_lock_key(d_a)];
        keys.sort();
        keys.dedup();
        let sup = registry().reserved_type(ShippedType::Supersedes).clone();
        let sup_class = registry().shipped_class(ShippedType::Supersedes);
        let r_class = registry().shipped_class(ShippedType::Retraction);
        self.kernel.transact(&keys, |stg| {
            {
                let base = stg.base();
                // P0 on both homes, then ω on both: the successor deposits
                // into d_s, the claim into d_a — the rejection carries the
                // home that failed.
                home_gate(base.m3(), caller, &[d_s, d_a])?;
                if !base.links().resident(original.tumbler()) {
                    return Err(EditLinkError::OriginalNotResident);
                }
                // The successor's span budget, ahead of every per-span
                // verdict: the level-uniformity walk below, the DC guard's
                // `coverage_class`, and the fold's dedup key over ALL THREE
                // slots are each linear in this count, and all three run
                // inside the transact under M2's applier lock. The slots are
                // built by the CALLER — M10 resolves V-specs into them — so
                // the count is the SOURCE document's fragmentation rather
                // than the request's size, which is the same expansion
                // MAKELINK's `Resolve` slots are bounded against.
                if successor.slots().any(|e| e.len() > MAX_SLOT_SPANS) {
                    return Err(EditLinkError::SlotTooLarge);
                }
                // Level-uniformity is required of EVERY slot, not just the
                // one the DC guard classifies: a deposit of a registered
                // idem⊤ class folds a dedup key over all three slots
                // ([`crate::LinkState::apply_link`]), and `coverage_class`
                // aborts on a non-level-uniform span. Checking only the type
                // slot would leave a caller-supplied F or G reaching that
                // abort from inside the transact.
                //
                // `e₃ ≠ ∅` is NOT restated here: it is the deposit gate's
                // check, and `⟨⟩` classifies as the empty denoted antichain —
                // neither shipped class — so it passes the DC guard untouched
                // and comes back from the gate as `IllFormedSuccessor`.
                let well_formed =
                    successor.arity() == 3 && successor.slots().all(Endset::is_level_uniform);
                if !well_formed {
                    return Err(EditLinkError::IllFormedSuccessor);
                }
                // DC guard — total: every slot was just checked
                // level-uniform.
                let successor_class = coverage_class(successor.type_slot());
                if successor_class == *r_class {
                    return Err(EditLinkError::DcViolation);
                }
                if successor_class == *sup_class
                    && !base.links().conforms_to_sup_schema(&successor)
                {
                    return Err(EditLinkError::DcViolation);
                }
            }
            // Both `minted`: this op reports each address as one it deposited,
            // and the claim's own I0 carries `successor`, minted a line above
            // in this same transaction, so no incumbent of that class exists.
            let successor = emit_core(stg, caller, d_s, successor, Gate::Open)?.minted();
            let claim_value = Link::triple(enc([original]), enc([&successor]), sup);
            let claim = emit_core(stg, caller, d_a, claim_value, Gate::Managed)?.minted();
            Ok(Edit { successor, claim })
        })
    }

    /// BH4 batch tooling (§7): nullify every stale tuple of `ty` (age >
    /// `horizon` over the type-`ty` active slice), the stale set snapshotted
    /// at entry. Served only where declared, and the snapshot read that
    /// builds the batch is what declares it: `stale`'s own `NotBh4` refusal
    /// lifts into `TxnError::Rejected(RetractStaleError::NotBh4)` —
    /// PRE-TRANSACT, no transaction opened, the same channel as `emit`'s
    /// pre-transact rejections — so the batch nullifier can never be aimed
    /// at an idem⊤ class (e.g. mass-nullifying old `[K_sup]` claims). In THIS
    /// format that fence covers every input: the registry's population is the
    /// shipped five, all of them idem⊤ and none declaring BH4, so no `ty` a
    /// caller can name is served and this op cannot succeed. Kept as the one
    /// statement of the rule rather than specialized to the population, as
    /// `reverse_lookup_classes` is. NOT atomic — a sequence of
    /// `nullify` transacts, each failure lifted through
    /// `RetractStaleError::Nullify`; on the first `TxnError` it returns
    /// `Err`, leaving earlier nullifies committed and durable (append-only,
    /// no rollback) — a re-run with the same `d_retr` is safe
    /// (already-nullified targets from this `d_retr` dedup; the recomputed
    /// stale set excludes them).
    ///
    /// COMPLETABLE ONLY BY AN OWNER OF EVERY STALE TUPLE. The batch comes
    /// from `stale`, which reads the WHOLE active type-`ty` slice — across
    /// homes and across accounts, `d_retr` scoping only where the retractions
    /// land — while each constituent `nullify` demands ω on its target (v1
    /// self-retraction). So a foreign-owned stale tuple halts the batch at
    /// the same point on every re-run: safe, and not progressive past it.
    /// Nullifying what one owns is the caller's business, done by aiming
    /// `nullify` directly.
    ///
    /// "The same point on every re-run" is a property rather than a hope
    /// because the batch is issued in [`stale`](crate::LinkState::stale)'s
    /// order, which that read publishes as ascending by address. Results come
    /// back in it, one `(retraction address, seq)` per nullified target.
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
