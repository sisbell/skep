//! §C/§D — the transact-driving write surface: [`LinkWriter`] (the kernel
//! handle), the shared single choke point [`emit_core`] with its
//! two-disciplines gate (§2), the M2 keyed dedup sections (§3), and the seven
//! public ops (six deposits — MAKELINK in its two forms — plus the BH4
//! batch), with the `replaces` class ([`replaces_type`]) whose one writer is
//! the second MAKELINK.
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
//!
//! Visibility (PUB round 2, lane 3.3b; PUB-6.25–6.27): the value-keyed gates
//! — `emit`'s idempotency lookup and `assert_sup`'s dedup, both the one
//! incumbent question [`emit_core`] asks of the world — run over the type
//! class FILTERED by the caller's [`Visibility`] predicate at link-HOME
//! identity, inside the write transaction. The predicate is THREADED FROM THE
//! CALLER at construction ([`LinkWriter::new`]): M7 fetches nothing from the
//! engine and learns nothing about principals.
//!
//! Layout: this file is the handle and what its ops share — the visibility
//! class, the deposit gate [`emit_core`] with its two disciplines and its §2
//! error tables, the home doorkeeper, the dedup lock set and the `replaces`
//! class. Each op family is a child module holding one `impl LinkWriter`
//! block — `writes/makelink.rs`, `writes/emit.rs`, `writes/nullify.rs` and
//! `writes/supersession.rs` — and sees this file's private items and none of
//! its siblings'. Each block's bounds name the slices its ops read and the
//! records they stage: MAKELINK's alone adds `HasM5`, MAKELINK being the one
//! op that seats.

use std::fmt;
use std::sync::LazyLock;

use skep_address::{validate, Address, Nat, Tumbler};
use skep_arrangement::Caller;
use skep_kernel::{Attestation, Kernel, LockKey, Staging, WorldState};
use skep_namespace::{M3Rec, M3State, MintError};

use crate::class::{coverage_class, CoverageClass};
use crate::dedup::DedupKey;
use crate::endset::{enc, Endset, Link};
use crate::error::{AssertSupError, EditLinkError, EmitError, MakeLinkError, NullifyError};
use crate::registry::{registry, sh_conf, ShippedType};
use crate::state::LinkRec;
use crate::LinkWorld;

// MAKELINK in both forms: the slot argument, the endset a slot builds under
// both budgets, the record half — the one op family that seats.
mod makelink;
// Emit_K, the managed surface's gated emission.
mod emit;
// Nullify, the sole retraction path, and the BH4 batch built on it.
mod nullify;
// The `[K_sup]` writers, `assert_sup` and `editlink`, and the pair an edit
// deposits.
mod supersession;

pub use makelink::{slot_endset, SlotArg};
pub use supersession::Edit;

/// The caller's VISIBILITY CLASS (PUB round 2, lane 3.3b; PUB-6.25): `true`
/// iff the caller a [`LinkWriter`] writes for may READ the document `doc` of
/// the world `w` — the read predicate `readable(doc, principal)` of PUB-1.31,
/// closed over the caller by whoever holds the caller: M10 over the
/// session's principal, M9 over the engine-injected GUEST class
/// (PUB-6.28), an engine-direct caller over its own. M7 names no principal
/// and no publication state; it applies the closure at link-HOME identity to
/// decide which incumbents a value-keyed gate may SEE.
///
/// CALLER'S OBLIGATION: the closure is a PURE, DETERMINISTIC function of
/// `(world, doc)` — the same answer for the same pair, no interior state.
/// The published determinism of the value-keyed gates rests on it and on
/// nothing else: [`emit`](LinkWriter::emit)'s "deterministic given the
/// visibility class" and [`assert_sup`](LinkWriter::assert_sup)'s
/// earliest-readable incumbent are the T1-least of the incumbent set THIS
/// predicate admits, so
/// a stateful predicate makes two value-identical writes disagree, silently.
/// `Fn` does not forbid interior mutability, and no check in this crate can
/// stand in for the obligation — it is the caller's, stated here and
/// enforced nowhere.
///
/// A second property is a CONDITION, not an obligation: a read predicate
/// admits the homes its caller ω-owns (an owner reads its own documents),
/// and that is the step `emit_core`'s claim that `nullify`'s dedup is
/// vacuous borrows. A predicate blind to the home the caller writes to —
/// the GUEST class over a private draft — costs `nullify` a fresh
/// retraction tuple where a hit would have been zero-step, and costs its
/// postcondition nothing: the target is tombstoned either way. The engine's
/// predicates are pure, and a principal's visibility class admits its own
/// homes.
///
/// The world handed in is the TRANSACTION's working world (`stg.working()`),
/// never a snapshot pinned before the transaction: the incumbent set is the
/// staged world's, and so is each home's publication state. The one
/// question this predicate answers is asked of a REGISTERED home — every
/// incumbent's home is a document a deposit landed in — so the registered-
/// only evaluation PUB-6.37 pins holds at every consult.
///
/// The same shape the coordinator holds its guest predicate in
/// (`Box<dyn Fn(&W, &Address) -> bool + Send + Sync>`), BORROWED: a writer is
/// built per operation and lends the very closure its caller holds, so the
/// pass-through is a borrow with no adapter, and a closure may capture the
/// request it serves (`'a` is that borrow, not `'static`).
pub type Visibility<'a, W> = dyn Fn(&W, &Address) -> bool + Send + Sync + 'a;

/// M7's single writer of link values — the transact-driving handle: the
/// kernel it deposits through and the caller's [`Visibility`] class, both
/// borrowed for the handle's lifetime. The registration and reserved-class
/// reads of §3's pre-transact steps go to the module's format registry
/// ([`registry`]), a compiled constant: there is no per-handle copy to keep,
/// so the question of whether a cache agrees with what `emit_core` consults
/// inside the txn does not arise.
///
/// The handle holds no links either. `Σ.L` — the append-only store itself —
/// is [`crate::LinkState`]'s map, reached through [`crate::HasLinks`], and
/// the store's reads are `LinkState`'s own, at no visibility class:
/// `readlink` and the rest of its read surface. This type is the write half,
/// run at the caller's visibility class; the reads that run at a reader's
/// visibility class are composed over `LinkState` outside this crate — M8's
/// `*_on` reads, each naming its reader, and M9's guest-class look.
///
/// A `LinkWriter` with NO visibility class does not exist: every
/// construction names the visibility class its writes run at
/// ([`LinkWriter::new`]), and
/// the value-keyed gates read the store through it, at the one choke point
/// every deposit passes (`emit_core`).
pub struct LinkWriter<'k, W: WorldState> {
    kernel: &'k Kernel<W>,
    visibility: &'k Visibility<'k, W>,
    /// THE ATTESTATION this handle's link writes commit under (signed ops):
    /// handed to the kernel's `transact_attested` arm at the one transaction
    /// each of the five publish-class link writes opens — `makelink` in both
    /// forms, `emit`, `nullify`, `assert_sup`, `editlink` — filling THAT
    /// commit marker's signature slot; `None` — the plain handle — leaves it
    /// empty. A borrow, held beside the visibility class for the one call
    /// this handle serves: a handle serves exactly one call, which is exactly
    /// one transaction, so one admitted value fills one slot. The BH4 batch
    /// (`retract_stale`) drives `nullify` once per target and would fill
    /// each of its commits under one value, which no caller does: it is
    /// reached by no dispatched write and served under no shipped
    /// registration, and the handles that could reach it are plain.
    attest: Option<&'k Attestation>,
}

/// The handle prints as itself: `Kernel` is deliberately opaque, so it is not
/// worth rendering — and asking for no `W: Debug` keeps this type from being
/// the reason a consumer's own derive fails.
impl<W: WorldState> fmt::Debug for LinkWriter<'_, W> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LinkWriter").finish_non_exhaustive()
    }
}

impl<'k, W> LinkWriter<'k, W>
where
    W: WorldState,
{
    /// Construct the writer handle: it holds the two borrows and nothing
    /// else — no snapshot, no state — exactly as `Namespace::new` and
    /// `Vstream::new` hold theirs (§C), plus the caller's [`Visibility`]
    /// class, which is a REQUIRED constructor parameter rather than a
    /// builder step so that a writer whose gates run at no stated
    /// visibility class cannot be built at all (lane 3.3b §2).
    pub fn new(kernel: &'k Kernel<W>, visibility: &'k Visibility<'k, W>) -> LinkWriter<'k, W> {
        LinkWriter::attested(kernel, visibility, None)
    }

    /// THE ATTESTED CONSTRUCTOR (signed ops; the confirmed placement): a
    /// writer whose link writes commit under `attest`. Its callers are the
    /// slot's producer set — M10's dispatch, with a value the daemon's check
    /// admitted — and nothing else; `None` is [`LinkWriter::new`].
    pub fn attested(
        kernel: &'k Kernel<W>,
        visibility: &'k Visibility<'k, W>,
        attest: Option<&'k Attestation>,
    ) -> LinkWriter<'k, W> {
        LinkWriter { kernel, visibility, attest }
    }
}

/// The WHOLE M2 lock set a deposit needs: the I0 section iff the value's
/// class is a REGISTERED idem⊤ one — the registry's `is_idempotent`, the
/// one statement of that predicate, which the hint fold applies to decide
/// what it indexes and `emit_core` reads as the `idem` flag of the
/// registration it already holds, so the section is taken exactly when the
/// check reads one — then the home's alloc key, always. A caller hands the
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
///
/// The I0 lock format serializes DENOTED classes only, so taking a section
/// carries a second precondition beside the registered-idem⊤ one: ALL THREE
/// slots address-denoting. The registration test does not imply it — it reads
/// the type slot alone, and a registered idem⊤ class holds extent-classed F
/// and G whenever the open surface deposits into it — so the full condition
/// is asserted here, at the decision, naming the format constraint that
/// requires it. Every op that takes a section meets it by construction: `emit`
/// validates `ty` and builds F and G through `enc`, and `nullify` and
/// `assert_sup` build all three that way.
fn deposit_lock_set(value: &Link, home: &Address) -> Vec<LockKey> {
    let mut keys: Vec<LockKey> = Vec::with_capacity(2);
    let class = coverage_class(value.type_slot());
    if registry().is_idempotent(&class) {
        assert!(
            value.slots().all(Endset::is_address_denoting),
            "an I0 lock section serializes denoted classes only: a section may be taken \
             only for a value whose every slot is address-denoting (§3)"
        );
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

/// The doorkeeper's verdict on a deposit's home documents, in the vocabulary
/// every op translates from (the `From` impls below) — and the one
/// [`EmitCoreError`] carries as its own, so the choke point's verdict on a
/// home IS the hoist's, translated once.
#[derive(Debug)]
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
/// Asked of every deposit by the gate that admits it, [`emit_core`], of the
/// WORKING world — so no caller path reaches the mint ungated — and asked
/// EARLIER, of the txn BASE, by each op that has in-transaction verdicts of
/// its own to order behind them (`emit` has none, and asks only through the
/// gate). The two askings cannot disagree: the only records a composite
/// stages between them are M3 element allocations and link deposits, and
/// neither changes a document's registration or its effective owner.
/// `editlink` is where the gap is real (its second `emit_core` runs after
/// the first has staged both), which is why the agreement is an argument
/// rather than an observation.
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

impl From<HomeFault> for EmitError {
    fn from(e: HomeFault) -> Self {
        match e {
            HomeFault::NotRegistered => EmitError::HomeNotRegistered,
            HomeFault::NotOwner(a) => EmitError::NotOwner(a),
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

/// `emit_core`'s internal error; each public op maps it through the `From`
/// impls below (§2 error mapping). `Home` carries the doorkeeper's verdict,
/// asked of the WORKING world through [`home_gate`] — the same two questions
/// an op's hoist asks of the base — so `mint_link`'s own `HomeNotRegistered`
/// branch is unreachable and every other `MintError` rides `Mint`. It is the
/// ω backstop (as amended 2026-08-16): every deposit passes this one choke
/// point, so no caller path can reach the mint without the ownership check
/// having run — the per-op hoists exist only to pin each op's error ORDER.
#[derive(Debug)]
enum EmitCoreError {
    Home(HomeFault),
    NotRegistered,
    ShapeViolation,
    RetractionClass,
    EmptyType,
    Mint(MintError),
}

impl From<HomeFault> for EmitCoreError {
    fn from(e: HomeFault) -> Self {
        EmitCoreError::Home(e)
    }
}

impl From<MintError> for EmitCoreError {
    fn from(e: MintError) -> Self {
        EmitCoreError::Mint(e)
    }
}

// §2 error mapping. Every impl enumerates all six variants: the dead ones
// are the paths the design proves cannot fire under that op's gate
// discipline, and naming them is what makes a new `EmitCoreError` variant a
// compile error at all five sites instead of a panic at one. `Home` is
// translated by the doorkeeper's own `From` impls above, so the verdict on a
// home is spelled once per op whichever check — hoist or backstop — raised it.

impl From<EmitCoreError> for MakeLinkError {
    // Open: only EmptyType/Home/Mint reachable, and EmptyType is ML6 arriving
    // from the gate that owns it.
    fn from(e: EmitCoreError) -> Self {
        match e {
            EmitCoreError::EmptyType => MakeLinkError::EmptyTypeResolution,
            EmitCoreError::Home(f) => f.into(),
            EmitCoreError::Mint(m) => MakeLinkError::Mint(m),
            EmitCoreError::NotRegistered
            | EmitCoreError::ShapeViolation
            | EmitCoreError::RetractionClass => {
                unreachable!("Open gate raises no Managed/Retraction rejection")
            }
        }
    }
}

impl From<EmitCoreError> for EmitError {
    // Managed: EmptyType unreachable (e₃ = ty is non-empty by T_admissible —
    // an empty ty lands NotRegistered at the gate instead).
    fn from(e: EmitCoreError) -> Self {
        match e {
            EmitCoreError::Home(f) => f.into(),
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
            EmitCoreError::Home(f) => f.into(),
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
            EmitCoreError::Home(f) => f.into(),
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
            EmitCoreError::Home(f) => f.into(),
            EmitCoreError::Mint(m) => EditLinkError::Mint(m),
            EmitCoreError::NotRegistered
            | EmitCoreError::ShapeViolation
            | EmitCoreError::RetractionClass => {
                unreachable!("editlink pre-checks DC/arity/residence; K_sup claim registry-fixed")
            }
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
/// THE DEDUP CHECK RUNS AT THE CALLER'S VISIBILITY CLASS (lane 3.3b;
/// PUB-6.25): the one question this gate asks of the world — the active
/// incumbent of the value's I0 class — is answered over that I0 class
/// FILTERED by `visibility` at link-HOME identity, against the WORKING
/// world. An incumbent homed in a document the caller cannot read is
/// invisible here, and the write proceeds exactly as in a world without it:
/// a fresh mint, never an ack naming an address inside a draft's link
/// subspace. The consequences are pinned (PUB-6.26): value-identical tuples
/// MAY coexist across the visibility boundary, and a hit is the EARLIEST
/// incumbent the caller's visibility class can read. The dedup LOCK is
/// unchanged — the I0 section serializes same-I0-class deposits whatever
/// visibility class their callers read at — so two callers of different
/// visibility classes racing on one value are serialized and each sees, or
/// does not see, the other's deposit per its own visibility class.
///
/// The filter reaches every caller of this gate uniformly. For `nullify`
/// (`Gate::Retraction`) it is vacuous under every read predicate: a
/// retraction tuple's I0 carries its own home in F, its sole writer deposits
/// it into that home, the caller ω-owns that home, and an owner reads its
/// own documents — the condition [`Visibility`] states, and the one whose
/// absence costs `nullify` a fresh retraction tuple rather than its
/// postcondition. For `editlink`'s claim it is vacuous under ANY predicate
/// (PUB-6.27): the claim's I0 carries a successor minted in this same
/// transaction, so the lookup is a guaranteed miss and no incumbent — at
/// any visibility class — can exist for it. Neither op threads a filter of
/// its own.
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
/// Both questions are asked through [`home_gate`] — the one statement of
/// them — of the WORKING world, where the per-op hoist asked them of the txn
/// base. The two verdicts agree because the only records a composite stages
/// in between are M3 element allocations and link deposits, neither of which
/// touches document registration or ω — so the hoist pins the error order
/// without the backstop being able to contradict it.
///
/// RETURN CONTRACT: [`Deposited`], which distinguishes a freshly minted
/// address (two records staged) from an idem⊤ INCUMBENT (nothing staged). A
/// caller that stages anything downstream naming the address takes
/// [`Deposited::minted`], which states that reliance where it is relied on.
fn emit_core<W>(
    stg: &mut Staging<W>,
    visibility: &Visibility<'_, W>,
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
    home_gate(stg.working().m3(), caller, &[home])?; // P0 then ω, of the working world
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
            // `is_idempotent`, read as the flag of the registration already in
            // hand: the same predicate that took the I0 section before the
            // transact and that keys the hint fold after it.
            if reg.idem {
                // The one question this gate asks of the WORLD rather than of
                // the format: the three reads above are the module's compiled
                // registry, and only this one is per-store state. Asked at
                // the caller's visibility class (PUB-6.25): the predicate is
                // evaluated over the WORKING world — the world this
                // transaction is writing — at each candidate's home.
                let world = stg.working();
                if let Some(incumbent) = world
                    .links()
                    .active_incumbent(&DedupKey::of(&value), |candidate_home| {
                        visibility(world, candidate_home)
                    })
                {
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

// ── the `replaces` class — the authority successor (PUB-5.15) ─────────────

/// THE `replaces` TYPE — the commons VALUE `1.1.0.1.0.1.0.3.12`, the core
/// vocabulary's vacant ordinal (the board's (rep-N) RULED, owner 2026-09-29:
/// "tke 3.12"; PUB-5.15 as RES-310 pins it): the type of the AUTHORITY
/// SUCCESSOR, the link a record's own transaction deposits beside it to name
/// the state that record REPLACES — `from` the record, `to` the record
/// replaced (PUB-5.15 (iii), (iv); the authority link type investigation's
/// §3 (A′)). A value, never a registration: [`TypeRegistry`](crate::TypeRegistry)
/// is untouched, as it is by every commons type, and no sixth shipped class
/// exists.
///
/// M7's OWN spelling, where its two readers here can read it — the class
/// the sole-writer fences compare against (`replaces_class`, below) and the
/// one write that mints the class ([`LinkWriter::makelink_replacing`]) — M7
/// sitting below the engine, whose commons ledger pins the same address
/// again (`skep_engine::types::t_replaces`) and whose ledger test holds the
/// two spellings EQUAL. Held, not built per call: the fences ask on every
/// MAKELINK, `emit` and `editlink`.
pub fn replaces_type() -> &'static Address {
    static ADDR: LazyLock<Address> = LazyLock::new(|| {
        validate(
            Tumbler::new([1u32, 1, 0, 1, 0, 1, 0, 3, 12].into_iter().map(Nat::from))
                .expect("the commons type components are nonempty"),
        )
        .expect("a subspace-3 element of the ghost document is T4-valid by construction")
    });
    &ADDR
}

/// The `replaces` class's coverage class — what the three fences compare a
/// type slot's own class to, exactly as the `[R]` and `[K_sup]` fences
/// compare theirs to [`crate::TypeRegistry::shipped_class`]'s answer.
fn replaces_class() -> &'static CoverageClass {
    static CLASS: LazyLock<CoverageClass> =
        LazyLock::new(|| coverage_class(&enc([replaces_type()])));
    &CLASS
}

/// Whether the type slot `ty` lands in the `replaces` class — the class's
/// sole-writer fence (PUB-5.15, RES-309/310) as a TOTAL predicate, for a
/// caller holding an endset whose shape it has not checked: the daemon asks
/// it of a request ahead of the transaction, so the wire's code
/// (`replaces_not_standalone`) and the store's refusal fall on the same
/// slots. Every write that takes a caller's type slot refuses exactly the
/// slots this answers `true` for — MAKELINK in both forms
/// ([`MakeLinkError::ReplacesClass`]), `emit` ([`EmitError::ReplacesClass`])
/// and an `editlink` successor ([`EditLinkError::DcViolation`]) — each
/// comparing the class it already holds with the same class, inside its own
/// checked region.
///
/// Coverage-class EQUALITY, the `[K_sup]` fence's rule: a slot naming the
/// type, alone or beside its own subtypes, is the class; a slot naming a
/// subtype alone, or the type beside another class, is not — and the grant
/// fold, which reads a `replaces` link by its type slot denoting EXACTLY
/// this address, reads no slot this fence admits.
///
/// Total over every endset: only an ADDRESS-DENOTING slot can name the type
/// (a `Resolve` slot resolves to content, never to a ghost address), so any
/// other answers `false` before a class is computed — which is also what
/// keeps [`coverage_class`]'s level-uniformity precondition off a
/// caller-built slot.
pub fn is_replaces_class(ty: &Endset) -> bool {
    ty.is_address_denoting() && coverage_class(ty) == *replaces_class()
}
