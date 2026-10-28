//! The transact-driving write surface (§C/§D): its handle, gate and ops.
//!
//! [`LinkWriter`] is the kernel handle and [`emit_core`] the shared single
//! choke point, with its two-disciplines gate (§2); beside them sit the M2
//! keyed dedup sections (§3) and the eight public ops (six deposits —
//! MAKELINK in its two forms — the publication, and the BH4 batch), with
//! the `replaces` class ([`replaces_type`]) whose one writer is the second
//! MAKELINK, and the correspondence class ([`correspondence_type`]) whose
//! one writer is the publication ([`LinkWriter::publication`]) — the publish
//! shot's own record mint, in the shot's transaction.
//!
//! Concurrency belongs to the kernel: nothing here locks, threads, or caches
//! world state. The type registry every gate reads is the module's compiled
//! format constant, so no handle carries one.
//!
//! Ownership: every op that deposits into a home document's link subspace
//! takes a [`Caller`] and requires `caller.is_owner(m3, home)` — the in-txn ω
//! gate, enforced at [`emit_core`] (hit and miss) with per-op hoists pinning
//! error order; `nullify` additionally requires owning the target link
//! (self-retraction only in v1).
//!
//! Visibility (PUB-6.25–6.27): the value-keyed gates — `emit`'s idempotency
//! lookup and `assert_sup`'s dedup, both the one incumbent question
//! [`emit_core`] asks of the world — run over the type class filtered by the
//! caller's [`Visibility`] predicate at link-home identity, inside the write
//! transaction. The predicate is threaded from the caller at construction
//! ([`LinkWriter::new`]): M7 fetches nothing from the engine and learns
//! nothing about principals.
//!
//! Layout: this file is the handle and what its ops share — the visibility
//! class, the deposit gate [`emit_core`] with its two disciplines and its §2
//! error tables, the home doorkeeper, the dedup lock set and the two
//! sole-writer commons classes, `replaces` and the correspondence. Each op
//! family is a child module — `writes/makelink.rs`,
//! `writes/emit.rs`, `writes/nullify.rs`, `writes/supersession.rs` and
//! `writes/publication.rs` —
//! holding one `impl LinkWriter` block and the public function that builds
//! what its ops deposit ([`slot_endset`], [`emit_tuple`],
//! [`retraction_tuple`], [`supersession_claim`]) or stages it
//! ([`stage_publication`], [`stage_correspondence`]); each sees this file's
//! private items and none of its siblings'. Each block's bounds name the
//! slices its ops read and the records they stage: MAKELINK's adds
//! `HasM5`, MAKELINK seating what it deposits, and the publication's is
//! M5's own shot bound beside `HasLinks`, the publication staging the shot.

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
// Emit_K, the managed surface's gated emission, and `emit_tuple`, the tuple
// it deposits.
mod emit;
// Nullify, the sole retraction path, with `retraction_tuple`, the tuple it
// deposits, and the BH4 batch built on it.
mod nullify;
// The `[K_sup]` writers, `assert_sup` and `editlink`, with
// `supersession_claim`, the claim both deposit, and the pair an edit
// deposits.
mod supersession;
// The publication: the publish shot staged with its correspondence records
// in one transaction — `stage_publication`, the composite as a staging
// function, `stage_correspondence`, one record's deposit and seat, and the
// public op over the union of the keys.
mod publication;

pub use emit::emit_tuple;
pub use makelink::{slot_endset, SlotArg};
pub use nullify::retraction_tuple;
pub use publication::{
    canonical_member_spans, edition_type, member_end, member_image, names_read_with,
    plan_deposits, price_publication_reads, read_with_in, read_with_type, request_image,
    resolve_end, stage_correspondence, stage_publication, DepositPlan, EndArg, LinkEntry,
    MemberEnd, MemberSpan, NamedAddress, PlannedClaim, PlannedDeposit, PlannedEnd, PlannedHome,
    PublishDeposits, PublishTarget, ReadPrice, CLAIM_BYTES, COPY_BYTES,
    CORRESPONDENCE_RECORD_BYTES, EDITION_CLAIM_BYTES, EDITION_MINT_BYTES, KEPT_PLACE_BYTES,
    MAXIMAL_PUBLICATION_BYTES, PLACED_RUN_BYTES, READ_WITH_BYTES, REINSERTED_VALUE_BYTES,
    RETRACTION_BYTES, SHOT_BYTES,
};
pub use supersession::{supersession_claim, Edit};

/// The caller's visibility class (PUB-6.25): its read predicate on documents.
///
/// It answers `true` iff the caller a [`LinkWriter`] writes for may read the
/// document `doc` of the world `w` — the read predicate
/// `readable(doc, principal)` of PUB-1.31, closed over the caller by whoever
/// holds the caller: M10 over the session's principal, M9 over the
/// engine-injected guest class (PUB-6.28), an engine-direct caller over its
/// own. M7 names no principal and no publication state; it applies the
/// closure at link-home identity to decide which incumbents a value-keyed
/// gate may see.
///
/// **Caller's obligation.** The closure is a pure, deterministic function of
/// `(world, doc)` — the same answer for the same pair, no interior state.
/// The published determinism of the value-keyed gates rests on it and on
/// nothing else: [`emit`](LinkWriter::emit)'s "deterministic given the
/// visibility class" and [`assert_sup`](LinkWriter::assert_sup)'s
/// earliest-readable incumbent are the T1-least of the incumbent set this
/// predicate admits, so a stateful predicate makes two value-identical writes
/// disagree, silently. `Fn` does not forbid interior mutability, and no check
/// in this crate can stand in for the obligation — it is the caller's, stated
/// here and enforced nowhere.
///
/// A second property is a condition, not an obligation: a read predicate
/// admits the homes its caller ω-owns (an owner reads its own documents),
/// and that is the step `emit_core`'s claim that `nullify`'s dedup is
/// vacuous borrows. A predicate blind to the home the caller writes to —
/// the guest class over a private draft — costs `nullify` a fresh
/// retraction tuple where a hit would have been zero-step, and costs its
/// postcondition nothing: the target is tombstoned either way. The engine's
/// predicates are pure, and a principal's visibility class admits its own
/// homes.
///
/// The world handed in is the transaction's working world (`stg.working()`),
/// never a snapshot pinned before the transaction: the incumbent set is the
/// staged world's, and so is each home's publication state. The one
/// question this predicate answers is asked of a registered home — every
/// incumbent's home is a document a deposit landed in — so the
/// registered-only evaluation PUB-6.37 pins holds at every consult.
///
/// The same shape the coordinator holds its guest predicate in
/// (`Box<dyn Fn(&W, &Address) -> bool + Send + Sync>`), borrowed: a writer is
/// built per operation and lends the very closure its caller holds, so the
/// pass-through is a borrow with no adapter, and a closure may capture the
/// request it serves (`'a` is that borrow, not `'static`).
pub type Visibility<'a, W> = dyn Fn(&W, &Address) -> bool + Send + Sync + 'a;

/// M7's single writer of link values — the transact-driving handle.
///
/// It holds the kernel it deposits through, the caller's [`Visibility`] class
/// and, where it carries one, the attestation its link writes commit under —
/// each borrowed for the handle's lifetime. The registration and
/// reserved-class reads of §3's pre-transact steps go to the module's format
/// registry ([`registry`]) — the compiled constant `emit_core` reads inside
/// the transaction, so the two reads cannot disagree.
///
/// The handle holds no links either. `Σ.L` — the append-only store itself —
/// is [`crate::LinkState`]'s map, reached through [`crate::HasLinks`], and
/// the store's reads are `LinkState`'s own, at no visibility class:
/// `readlink` and the rest of its read surface. This type is the write half,
/// run at the caller's visibility class; the reads that run at a reader's
/// visibility class are composed over `LinkState` outside this crate — M8's
/// `*_on` reads, each naming its reader, and M9's guest-class look.
///
/// A `LinkWriter` with no visibility class does not exist: every
/// construction names the visibility class its writes run at
/// ([`LinkWriter::new`]), and the value-keyed gates read the store through
/// it, at the one choke point every deposit passes (`emit_core`).
pub struct LinkWriter<'k, W: WorldState> {
    kernel: &'k Kernel<W>,
    visibility: &'k Visibility<'k, W>,
    /// The attestation this handle's link writes commit under (signed ops).
    ///
    /// It is handed to the kernel's `transact_attested` arm at the one
    /// transaction each of the five publish-class link writes opens —
    /// `makelink` in both forms, `emit`, `nullify`, `assert_sup`, `editlink` —
    /// filling that commit marker's signature slot; `None` — the plain
    /// handle — leaves it empty. A borrow, held beside the visibility class
    /// for the one call this handle serves: a handle serves exactly one call
    /// (its caller's obligation, since the write methods take `&self`), which
    /// is exactly one transaction, so one admitted value fills one slot. The
    /// BH4 batch (`retract_stale`) drives `nullify` once per target and would
    /// fill each of its commits under one value, which no caller does: it is
    /// reached by no dispatched write and served under no shipped
    /// registration, and the handles that could reach it are plain.
    attest: Option<&'k Attestation>,
}

/// Prints the handle as itself.
///
/// `Kernel`'s own `Debug` deliberately leaves out the world it holds, so it is
/// not worth rendering — and asking for no `W: Debug` keeps this type from
/// being the reason a consumer's own derive fails.
impl<W: WorldState> fmt::Debug for LinkWriter<'_, W> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LinkWriter").finish_non_exhaustive()
    }
}

impl<'k, W> LinkWriter<'k, W>
where
    W: WorldState,
{
    /// Constructs the writer handle.
    ///
    /// It holds the kernel borrow, no attestation and nothing else — no
    /// snapshot, no state — exactly as `Namespace::new` and `Vstream::new`
    /// hold theirs (§C), plus the caller's [`Visibility`] class, which is a
    /// required constructor parameter rather than a builder step so that a
    /// writer whose gates run at no stated visibility class cannot be built
    /// at all.
    pub fn new(kernel: &'k Kernel<W>, visibility: &'k Visibility<'k, W>) -> LinkWriter<'k, W> {
        LinkWriter::attested(kernel, visibility, None)
    }

    /// Constructs the attested writer (signed ops).
    ///
    /// Its link writes commit under `attest`. Its callers are the slot's
    /// producer set — M10's dispatch, with a value the daemon's check
    /// admitted — and nothing else; `None` is [`LinkWriter::new`].
    pub fn attested(
        kernel: &'k Kernel<W>,
        visibility: &'k Visibility<'k, W>,
        attest: Option<&'k Attestation>,
    ) -> LinkWriter<'k, W> {
        LinkWriter { kernel, visibility, attest }
    }
}

/// Returns the whole M2 lock set a deposit of `value` into `home` needs.
///
/// That is the I0 section iff the value's class is a registered idem⊤ one —
/// the registry's `is_idempotent`, the one statement of that predicate,
/// which the hint fold applies to decide what it indexes and `emit_core`
/// reads as the `idem` flag of the registration it already holds, so the
/// section is taken exactly when the check reads one — then the home's alloc
/// key, always. A caller hands the result to `transact` entire and adds
/// nothing.
///
/// One derivation of the dedup decision, beside [`DedupKey::of`]'s one
/// derivation of the key, so "the section M2 serializes is the section the
/// check reads" covers taking a section at all and not merely which bytes
/// it carries.
///
/// A free function beside the gate it mirrors, taking no handle, because the
/// set is a function of the value and its home: the class comes from
/// [`coverage_class`] and its idem⊤ flag from the module's format registry,
/// the I0 key from `DedupKey::of` and the alloc key from M3's spelling, so
/// there is no world to read and no kernel to hold.
///
/// The two ops that deliberately take no dedup section say so at their own
/// key sets: MAKELINK, whose open surface faces no dedup check (ML0), and
/// `editlink`'s claim, whose check is a guaranteed miss. Costs `emit` a
/// second classification of its `ty` — one ascending pass over a type
/// slot's denoted addresses, on a path that already pays one.
///
/// # Panics
///
/// Panics if the type slot is not level-uniform ([`coverage_class`]'s
/// precondition), or if the class is registered idem⊤ and a slot is not
/// address-denoting. The I0 lock format serializes denoted classes only, so
/// taking a section carries a second precondition beside the registered-idem⊤
/// one: all three slots address-denoting. The registration test does not
/// imply it — it reads the type slot alone, and a registered idem⊤ class
/// holds extent-classed F and G wherever the open surface deposits them into
/// it — so the full condition is asserted here, at the decision, naming the
/// format constraint that requires it. Every op that takes a section meets it
/// by construction: `emit` validates `ty` and [`emit_tuple`] builds F and G
/// through `enc`, and [`retraction_tuple`] and [`supersession_claim`] build
/// all three that way.
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

/// The admission discipline selector — never the value.
///
/// Effect-identity: the gate adds preconditions only and never alters
/// `value` (ASN-0126 π).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Gate {
    /// MAKELINK / editlink successor: `e₃ ≠ ∅` only.
    ///
    /// It is the one statement of `e₃ ≠ ∅`. Neither open-surface caller
    /// repeats the test; each states the obligation in its contract and reads
    /// the verdict back through its own `From<EmitCoreError>` (§2), so no
    /// deposited link can carry an empty type slot however it arrived. Runs
    /// no dedup, so this gate always answers [`Deposited::Fresh`]: it is what
    /// MAKELINK's seat step rests on.
    Open,
    /// The Managed discipline: registered ∧ shape-conformant ∧ K ≁ R.
    ///
    /// Emit_K, assert_sup and the editlink claim take it; idem⊤ ⇒ active-view
    /// dedup check.
    Managed,
    /// Nullify: the Managed discipline with the `[R]` class admitted.
    ///
    /// It admits that class rather than refusing it — the one clause that
    /// separates the two.
    Retraction,
}

/// What [`emit_core`] did, in two words.
///
/// Two, because the choke point has two outcomes and an `Address` alone
/// names both.
enum Deposited {
    /// Freshly minted: the M3 allocation and the `LinkRec` are staged.
    Fresh(Address),
    /// The active incumbent of an idem⊤ class: nothing staged.
    Incumbent(Address),
}

impl Deposited {
    /// Returns the address, whichever outcome.
    ///
    /// It is for a caller that stages nothing downstream naming it, and
    /// reports it as "the address of the tuple of this identity" (`emit`,
    /// `nullify`, `assert_sup`).
    fn address(self) -> Address {
        match self {
            Deposited::Fresh(addr) | Deposited::Incumbent(addr) => addr,
        }
    }

    /// Returns the address of a link this call minted.
    ///
    /// It is what a caller staging a seat for it, or handing it back as
    /// freshly its own, is relying on. Stating the reliance here is what keeps
    /// it from being an argument in a doc-comment: MAKELINK takes
    /// [`Gate::Open`], which runs no dedup, and `editlink`'s claim keys its I0
    /// on a successor minted moments earlier in the same transaction, so
    /// neither can meet an incumbent.
    ///
    /// # Panics
    ///
    /// Panics on [`Deposited::Incumbent`].
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

/// The doorkeeper's verdict on a deposit's home documents.
///
/// It is in the vocabulary every op translates from (the `From` impls
/// below), and the one [`EmitCoreError`] carries as its own, so the choke
/// point's verdict on a home is the hoist's, translated once.
#[derive(Debug)]
enum HomeFault {
    NotRegistered,
    NotOwner(Address),
}

/// Checks every home a deposit writes into: registered (P0), then owned (ω).
///
/// Asked of every deposit by the gate that admits it, [`emit_core`], of the
/// working world — so no caller path reaches the mint ungated — and asked
/// earlier, of the txn base, by each op that has in-transaction verdicts of
/// its own to order behind them (`emit` has none, and asks only through the
/// gate). The two askings cannot disagree: the only records a composite
/// stages between them are M3 element allocations, link deposits and M5
/// link seats, and none changes a document's registration or its effective
/// owner. `editlink` and `makelink_replacing` are where the gap is real
/// (each one's second `emit_core` runs after the first has staged both its
/// records — and, in `makelink_replacing`, the record's seat), which is why
/// the agreement is an argument rather than an observation.
///
/// # Errors
///
/// `NotRegistered` for an unregistered home, then `NotOwner` for a home the
/// caller does not own (ω, exact account match). All registrations are
/// checked before any ownership, so an op depositing into two homes reports
/// an unregistered second home ahead of an unowned first — the order
/// `editlink` pins. The payload names the home that failed ownership; M10
/// threads it into the rejection's fault site.
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

/// `emit_core`'s internal error, mapped by each public op (§2 error mapping).
///
/// Each public op maps it through the `From` impls below. `Home` carries the
/// doorkeeper's verdict, asked of the working world through [`home_gate`] —
/// the same two questions an op's hoist asks of the base — so `mint_link`'s
/// own `HomeNotRegistered` branch is unreachable and every other `MintError`
/// rides `Mint`. It is the ω backstop: every deposit passes this one choke
/// point, so no caller path can reach the mint without the ownership check
/// having run — the per-op hoists exist only to pin each op's error order.
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

/// Gates one deposit — the single choke point both write surfaces share (§2).
///
/// It runs inside one `transact`. Bounds are [`crate::LinkWorld`] with no
/// `HasM5`, so it has no seat step — the seat is staged by MAKELINK itself,
/// the lone `HasM5` caller, after this returns. Any dedup lock is in the key
/// set the public op hands the transact (§3 step 1); this does the hoisted
/// home check and the in-txn dedup check.
///
/// **The dedup check runs at the caller's visibility class.** The one
/// question its discipline asks of the world (PUB-6.25) — the active
/// incumbent of the value's I0 class — is answered over that I0 class
/// filtered by `visibility` at link-home identity, against the working
/// world. An incumbent homed in a document the caller cannot read is
/// invisible here, and the write proceeds exactly as in a world without it:
/// a fresh mint, never an ack naming an address inside a draft's link
/// subspace. The consequences are pinned (PUB-6.26): value-identical tuples
/// may coexist across the visibility boundary, and a hit is the earliest
/// incumbent the caller's visibility class can read. The dedup lock is
/// unfiltered — the I0 section serializes same-I0-class deposits whatever
/// visibility class their callers read at — so two callers of different
/// visibility classes racing on one value are serialized and each sees, or
/// does not see, the other's deposit per its own visibility class.
///
/// The filter reaches every caller of this gate uniformly. For `nullify`
/// (`Gate::Retraction`) it is vacuous under every read predicate that admits
/// the homes its caller ω-owns: a retraction tuple's I0 carries its own home
/// in F, its sole writer deposits it into that home, the caller ω-owns that
/// home, and an owner reads its own documents — the condition [`Visibility`]
/// states, and the one whose absence costs `nullify` a fresh retraction
/// tuple rather than its postcondition. For `editlink`'s claim it is vacuous
/// under any predicate (PUB-6.27): the claim's I0 carries a successor minted
/// in this same transaction, so the lookup is a guaranteed miss and no
/// incumbent — at any visibility class — can exist for it. Neither op
/// threads a filter of its own.
///
/// **Return contract.** A [`Deposited`], which distinguishes a freshly
/// minted address (two records staged) from an idem⊤ incumbent (nothing
/// staged). A caller that stages anything downstream naming the address
/// takes [`Deposited::minted`], which states that reliance where it is
/// relied on.
///
/// # Errors
///
/// In the order the checks run. The hoisted home check (Conflicts §8, a
/// deliberate divergence from ASN-0128 I1's miss-only read) runs ahead of
/// every gate/dedup short-circuit, so an unregistered-home emit is rejected
/// on every path — miss and hit; callers cannot observe the branch, which is
/// what makes the contract portable. The ω check rides directly behind it
/// under the same discipline: a non-owner deposit is rejected on hit and
/// miss, and because every deposit passes this choke point, no caller can
/// reach the mint ungated. Both questions are asked through [`home_gate`],
/// of the working world, and its verdict rides `Home`; why that verdict and
/// the per-op hoist's, asked of the base, cannot disagree is stated there.
/// Then the selected gate: `Gate::Open` refuses an empty type slot
/// (`EmptyType`); `Gate::Managed` and `Gate::Retraction` refuse an
/// unregistered class (`NotRegistered`), then, under `Gate::Managed` alone,
/// the `[R]` class (`RetractionClass`), then a value off its registered
/// shape (`ShapeViolation`). Last comes `Mint`, where the mint fails.
///
/// # Panics
///
/// Panics if `value`'s arity is not 3 — a store-invariant backstop no caller
/// trips — or if a slot the deposit classifies is not level-uniform, where
/// [`coverage_class`] aborts: the type slot always, and all three under a
/// registered idem⊤ class.
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
    // Store-invariant backstop (§2): every caller builds arity 3
    // (MAKELINK/Emit_K/Nullify/assert_sup/claim; editlink pre-checks), so
    // this never trips — but it guarantees type_slices, the `FROM`/`TO`/`TYPE`
    // slots the discovery primitives index, and ASN-0086's |Σ.L| = 3 hold
    // locally.
    assert_eq!(value.arity(), 3, "emit_core: the store holds only arity-3 links");
    home_gate(stg.working().m3(), caller, &[home])?; // P0 then ω, of the working world
    match gate {
        Gate::Open => {
            if value.type_slot().is_empty() {
                return Err(EmitCoreError::EmptyType); // L3 at the write boundary
            }
        }
        // One discipline, derived from the value's own class: registered,
        // shape-conformant per the registered shape, idem⊤ ⇒ active-view
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
                // The one question this gate asks of the world rather than of
                // the format: the three reads above are the module's compiled
                // registry, and only this one is per-store state. Asked at
                // the caller's visibility class (PUB-6.25): the predicate is
                // evaluated over the working world — the world this
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
    //
    // THE PIN (the link-sets design §5.7; lane S3): within one transaction a
    // home's link addresses RISE in minting order. The mint is M3's frontier
    // read over the working world — `next_link_address`'s ordinal is one
    // past the home's frontier, which every deposit staged ahead of this
    // one has already moved — so the composite that deposits several links
    // in one home (a publication's copies, retractions and read-withs, in
    // the plan's order) mints them at ascending addresses, and a reader
    // that sorts a home's links by address reads them in the order the
    // signed entry lists them; `tests/it/publication.rs` pins it
    // (`a_homes_link_addresses_rise_in_the_plans_order_within_one_commit`).
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

/// Returns the `replaces` type — the commons value `1.1.0.1.0.1.0.3.12`.
///
/// It is the core vocabulary's vacant ordinal (PUB-5.15, as RES-310 pins
/// it): the type of the authority successor, the link a record's own
/// transaction deposits beside it to name the state that record replaces —
/// `from` the record, `to` the record replaced (PUB-5.15 (iii), (iv); the
/// authority link type investigation's §3 (A′)). A value, never a
/// registration: [`TypeRegistry`](crate::TypeRegistry) is untouched, as it
/// is by every commons type, and no sixth shipped class exists.
///
/// M7's own spelling, where its two readers here can read it — the class
/// the sole-writer fences compare against (`replaces_class`, below) and the
/// one write that mints the class ([`LinkWriter::makelink_replacing`]) — M7
/// sitting below the engine, whose commons ledger pins the same address
/// again (`skep_engine::types::t_replaces`) and whose ledger test holds the
/// two spellings equal. Held, not built per call, as the class built from
/// it is: the fences ask that class on every MAKELINK, `emit` and
/// `editlink`, and the one write that mints the class reads this address
/// on every call.
///
/// # Panics
///
/// Panics if `1.1.0.1.0.1.0.3.12` is not a nonempty T4-valid address, which
/// can only happen if the constant itself is edited.
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

/// Returns the `replaces` class's coverage class.
///
/// It is what the three fences compare a type slot's own class to, exactly
/// as the `[R]` and `[K_sup]` fences compare theirs to
/// [`crate::TypeRegistry::shipped_class`]'s answer.
fn replaces_class() -> &'static CoverageClass {
    static CLASS: LazyLock<CoverageClass> =
        LazyLock::new(|| coverage_class(&enc([replaces_type()])));
    &CLASS
}

/// Returns whether the type slot `ty` lands in the `replaces` class.
///
/// It is the class's sole-writer fence (PUB-5.15, RES-309/310) as a total
/// predicate, for a caller holding an endset whose shape it has not checked:
/// the daemon asks it of a request ahead of the transaction, so the wire's
/// code (`replaces_not_standalone`) and the store's refusal fall on the same
/// slots. Every write that takes a caller's type slot refuses exactly the
/// slots this answers `true` for — MAKELINK in both forms
/// ([`MakeLinkError::ReplacesClass`]), `emit` ([`EmitError::ReplacesClass`])
/// and an `editlink` successor ([`EditLinkError::DcViolation`]) — each
/// comparing the class it already holds with the same class, inside its own
/// checked region.
///
/// Coverage-class equality, the `[K_sup]` fence's rule: a slot naming the
/// type, alone or beside its own subtypes, is the class; a slot naming a
/// subtype alone, or the type beside another class, is not — and the grant
/// fold, which reads a `replaces` link by its type slot denoting exactly
/// this address, reads no slot this fence admits.
///
/// Total over every endset: only an address-denoting slot can name the type
/// (a `Resolve` slot resolves to content, never to a ghost address), so any
/// other answers `false` before a class is computed — which is also what
/// keeps [`coverage_class`]'s level-uniformity precondition off a
/// caller-built slot.
pub fn is_replaces_class(ty: &Endset) -> bool {
    ty.is_address_denoting() && coverage_class(ty) == *replaces_class()
}

// ── the correspondence class — the publish shot's own record (link-sets §5.7)

/// Returns the correspondence record's type — the commons value
/// `1.1.0.1.0.1.0.3.102.1`.
///
/// It is the subtype row under Nelson's counterpart `3.102` the commons
/// seeding round pinned (2026-10-27): the type of the record a publish shot
/// mints for each run of draft identity it re-minted into the member —
/// `from` the run's draft-native span, `to` the member's span it became,
/// both of one width, homed in the draft (the link-sets design §5.5, §5.7).
/// A value, never a registration, as [`replaces_type`] is.
///
/// M7's own spelling, where its two readers here can read it — the class
/// the sole-writer fences compare against (`correspondence_class`, below)
/// and the one write that mints the class, the publication's record
/// ([`stage_correspondence`]) — M7 sitting below the engine, whose commons
/// ledger pins the same address again (`skep_engine::types::t_correspondence`)
/// and whose ledger test holds the two spellings equal. The class HAS ONE
/// WRITER, the shot's own record mint in the shot's transaction
/// ([`LinkWriter::publication`]); every door that takes a caller's type slot
/// refuses it. Held, not built per call, as the class built from it is.
///
/// # Panics
///
/// Panics if `1.1.0.1.0.1.0.3.102.1` is not a nonempty T4-valid address,
/// which can only happen if the constant itself is edited.
pub fn correspondence_type() -> &'static Address {
    static ADDR: LazyLock<Address> = LazyLock::new(|| {
        validate(
            Tumbler::new([1u32, 1, 0, 1, 0, 1, 0, 3, 102, 1].into_iter().map(Nat::from))
                .expect("the commons type components are nonempty"),
        )
        .expect("a subspace-3 element of the ghost document is T4-valid by construction")
    });
    &ADDR
}

/// Returns the correspondence class's coverage class.
///
/// It is what the three fences compare a type slot's own class to, exactly
/// as they compare it to [`replaces_class`]'s answer.
fn correspondence_class() -> &'static CoverageClass {
    static CLASS: LazyLock<CoverageClass> =
        LazyLock::new(|| coverage_class(&enc([correspondence_type()])));
    &CLASS
}

/// Returns whether the type slot `ty` lands in the correspondence class.
///
/// It is the class's sole-writer fence (the link-sets design §5.7: "the
/// CLASS HAS ONE WRITER and is refused elsewhere by coverage-class
/// equality") as a total predicate, [`is_replaces_class`]'s twin: the
/// daemon asks it of a request ahead of the transaction, so the wire's code
/// (`correspondence_not_standalone`) and the store's refusal fall on the
/// same slots. Every write that takes a caller's type slot refuses exactly
/// the slots this answers `true` for — MAKELINK in both forms
/// ([`MakeLinkError::CorrespondenceClass`]), `emit`
/// ([`EmitError::CorrespondenceClass`]) and an `editlink` successor
/// ([`EditLinkError::DcViolation`]). The publication's twin fence asks it of
/// each stored record it stabs, the exact test that keeps a link typed the
/// parent `counterpart` from passing for a record.
///
/// Coverage-class equality, the `[K_sup]` fence's rule: a slot naming the
/// type, alone or beside its own subtypes, is the class; a slot naming the
/// parent `counterpart` `3.102` — alone or beside this subtype, which the
/// parent then covers — is not, and stays the ordinary type a picker lists.
///
/// Total over every endset, as [`is_replaces_class`] is: only an
/// address-denoting slot can name the type, so any other answers `false`
/// before a class is computed.
pub fn is_correspondence_class(ty: &Endset) -> bool {
    ty.is_address_denoting() && coverage_class(ty) == *correspondence_class()
}
