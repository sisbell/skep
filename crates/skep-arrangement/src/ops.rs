//! The editing & versioning operations (§B / §3–§7).
//!
//! They are `Vstream`, one M2 `transact` per operation, every mutation under
//! an M3 lock key for the touched document's allocation domain
//! (§Serialization key).
//!
//! **A rejection leaves no state change.** For a refusal answered inside a
//! transaction that is M2's guarantee rather than an ordering these ops keep:
//! `transact` returns `TxnError::Rejected(E)` straight out of the closure
//! phase, discarding the staging, drawing no `Seq` and appending nothing.
//! Five of the seven ops do reject before staging anything; INSERT and the
//! publish shot cannot, since each stages a mint and a content record per
//! fresh atom or maximal run of single-byte values as it goes
//! ([`allocate_for_placement`] and [`allocate_stretch_for_placement`], J0's
//! two steps) and may reject after them — on a later value, and for the shot
//! on its run budget or its own version mint as well. VERSION's three
//! pre-transaction refusals (`SourceNotRegistered`, `NotAPrincipal`,
//! `NodeTierCrossOwner`) are answered off an M2 snapshot before any
//! transaction opens, and so reach M2 not at all. M10 surfaces the rejection
//! as a typed one and acknowledges only after commit.
//!
//! **Ownership.** Six ops take a [`Caller`](crate::Caller) and open with
//! [`gate_write`](crate::ownership::gate_write) — the in-txn ownership gate,
//! registration then the ω gate — on the address the caller names: the five
//! edits and the shot (COPY and REINSTATE: their destination only; VERSION
//! is ungated, non-owner versioning being denial-as-fork, O10). The address
//! named is not always the arrangement written. A declared deposit into a
//! published chain that has a head lands on that head
//! ([`deposit_surface`](crate::deposit_surface)) rather than in the named
//! address's arrangement, and a shot writes only the member it mints; both
//! are members of the named document's chain, minted under it, so the owner
//! the gate checked is theirs too.
//!
//! **Publication** (PUB-kickoff D2b): the version-chain model's refusals,
//! each stated with its op's check order, are evaluated inside that op's own
//! transaction on an address its own check has already found registered
//! (PUB-6.37), and are enforced here whatever runs ahead of the store. Their
//! one reading of the publication bit is
//! [`published_target`](crate::published_target), whose own card says why it
//! is public.
//!
//! **Which error wins** when several conditions fail at once is stated on
//! each op, in its own file below, and this is the only statement of it: the
//! error types name verdicts, not precedence, and the integration suite pins
//! what is written here.
//!
//! **Layout.** This file is the handle and what its operations share — the
//! three budgets, J0's two allocation steps ([`allocate_for_placement`] for an
//! atom, [`allocate_stretch_for_placement`] for a run of single-byte values)
//! and the head key ([`head_lock_key`]). Each operation is a child module
//! holding one `impl` block — `ops/insert.rs`, `ops/publish.rs`,
//! `ops/copy.rs`, `ops/reinstate.rs`, `ops/delete.rs`, `ops/rearrange.rs`,
//! `ops/version.rs` — and sees this file's private items and none of its
//! siblings'. `ops/publish.rs` holds as well the shot's admission, the checks
//! `publish` opens with, offered as a pure query ([`shot_admission`]); and
//! three of the modules hold their op's body as a function over a
//! caller-opened staging — [`stage_publish`], [`stage_reinstate_at`],
//! [`stage_delete_at`] — the public op a wrapper that opens the transaction,
//! so a caller can stage the three under one commit; `ops/publish.rs` names
//! the shot's bound as one trait ([`PublishWorld`]) and the pairing its
//! staging returns ([`MintedRun`], [`Pairing`]), for such a caller. Each
//! block's trait bounds name the slices its op reads and the records it
//! stages — `version`'s names `HasM5` as well, which its op does not read —
//! so a minimal test world can drive `delete`/`rearrange` with
//! `HasM5 + HasM3` and `From<M5Rec>` alone, and answer the shot's admission
//! with those two slices too.
//!
//! Unit tests sit with what they test: `ops/tests.rs` tests this file — the
//! handle, J0's atom step, the placement and re-insert budgets against M2's
//! own accounting — and the bound claim above on `delete`, `rearrange` and the
//! shot's admission; `ops/copy/tests.rs`, `ops/reinstate/tests.rs` and
//! `ops/publish/tests.rs` hold the three ops' own claims — COPY's walk budget
//! and REINSTATE's every-address probe among them — which need a world no
//! engine reaches.

use std::fmt;
use std::sync::Arc;

use num_traits::One;
use skep_address::{Address, Nat};
use skep_content::{
    stage_stretch, stage_write, ContentError, ContentStretch, ContentWrite, HasContent, Val,
};
use skep_kernel::{Attestation, Kernel, LockKey, Staging, WorldState};
use skep_namespace::{HasM3, M3Rec, M3State, MintError};

use crate::chain::trunk_of;
use crate::run::Run;
use crate::run_list::extend_or_push_run;

// COPY (ASN-0118): transclusion by reference, allocating nothing.
mod copy;
// DELETE (ASN-0117): a content range removed and the gap closed.
mod delete;
// INSERT (ASN-0116): fresh content placed, and the declared deposit.
mod insert;
// PUBLISH, the shot (PUB-2.33), and its admission.
mod publish;
// REARRANGE (ASN-0119/0084): the pivot and the swap.
mod rearrange;
// REINSTATE (the replacement act): the write by identity — client-named
// I-runs placed at a position, allocating nothing.
mod reinstate;
// CREATENEWVERSION (ASN-0123): the fork.
mod version;

pub use delete::stage_delete_at;
pub use publish::{
    mint_admission, shot_admission, stage_publish, MintedRun, Pairing, PublishWorld,
};
pub use reinstate::stage_reinstate_at;

/// The most runs one COPY, one REINSTATE, or one publish shot may place.
///
/// It is the ceiling on what one request can make M5 hold live while it
/// decides whether to place anything at all.
///
/// **The budget**: a `Run` journals as an element `Address` and a width —
/// about a hundred bytes as bincode writes them at the shallowest content
/// address, eight components, and about twelve more for each further
/// component — so at that depth M2's `MAX_TXN_BYTES` (64 MiB) admits on the
/// order of half a million of them and no more: past that the transaction
/// cannot commit whatever M5 does, and the work of building it is spent for a
/// refusal. There `2^16` sits an order inside the ceiling, which keeps the
/// live heap one placing request commands to the same order as the
/// transaction budget M2 already prices rather than several times it. The
/// argument is the shallow address's: a run's journal bytes and its resident
/// address both grow with the address's component count — an account prefix
/// up to M3's `MAX_PRINCIPAL_COMPONENTS`, then the version components of the
/// nested members beneath it — so from about eighty-five components on a
/// placement of the cap's runs does not fit M2's ceiling, and one under the
/// cap can be built whole and then refused `OverBudget`. The cap bounds the
/// runs one request commands; it does not promise that every placement under
/// it commits, and a route that wants depth priced ahead of the work owes
/// that number. The arithmetic, the shallow case and the crossing alike, is
/// checked against the real encoding rather than restated here
/// (`the_placement_budget_stays_inside_the_transaction_budget`).
///
/// **It binds what one COPY, one REINSTATE or one shot places and holds
/// live**, and that is the whole of what it binds. Each accumulator is
/// measured as each run is accumulated, and what feeds them is pulled a run
/// at a time — COPY's lazy resolution of each spec, REINSTATE's walk of the
/// client's list, the shot's walk of its base's carried tail — so the cap
/// also stops the walk: an over-budget request is refused at the cap rather
/// than built in full and measured afterwards. For a shot, what it places is
/// its whole placement — the client's runs and the base's carried tail
/// together, counted in runs — and never the shot term
/// [`placed`](crate::ShotTerms::placed), which counts the client's positions
/// alone.
///
/// **The remedy differs between the edits and the shot.** A copy or a
/// reinstate needing more runs than this is split by the caller, exactly as
/// an over-budget transaction already is. A shot cannot be split: the member
/// it produces is born whole, from the whole arrangement the client rendered
/// plus the base's carried deposits. For a shot the refusal is therefore a
/// ceiling on the run count of the member one shot produces — the client's
/// runs as the accumulator coalesces them, plus the base's deposit runs — and
/// a retry of the same arrangement is refused the same way.
///
/// **What it does not bind** is the work of resolving: each COPY spec's
/// prefix-sum walk of its source's run-list to reach the span,
/// `Θ(#runs(source))` for a span near the end however narrow the answer.
/// COPY's has a ceiling of its own, [`MAX_COPY_RESOLVE_STEPS`]; the shot's
/// per-run work is stated on [`Vstream::publish`].
pub const MAX_PLACED_RUNS: usize = 1 << 16;

/// The most values one publish shot may re-insert.
///
/// They are the fresh identities it mints for its draft-native runs
/// (PUB-2.40), each through one of J0's two steps — and so this is the
/// ceiling on what one shot makes M5 stage before M2 has priced any of it.
///
/// **Why a count of its own.** M2 judges a transaction's size only once the
/// closure has returned, and until then every staged value is live heap: a
/// mint record and a content record per atom or run of single-byte values,
/// each carrying an address, and the working world's new content entry. How
/// many values a shot re-inserts is
/// [`Shot::reinserted_values`](crate::Shot::reinserted_values), the distinct
/// positions its draft-native runs name — each draft identity is minted once
/// per shot, a later occurrence placed by reference — and that count is the
/// request's to choose: a run may name any stored I-extent of the draft,
/// while [`MAX_PLACED_RUNS`] does not see it, the fresh addresses being
/// I-adjacent and so coalescing into one run. Without this count a request
/// of a kilobyte stages the whole stored content its runs reach, before any
/// refusal can arrive. The count is request arithmetic, taken before any
/// address is probed, so it bounds the existence walk over the draft-native
/// runs as well.
///
/// **The budget**, measured at the worst case that holds: every re-inserted
/// value an atom — a `Piece::Value` of two bytes or more, which stages two
/// records apiece, a mint and a content write, where a run of single-byte
/// values re-inserts as one range mint and one stretch however wide it is
/// (the re-insert coalesces consecutive bytes, so a draft typed byte by byte
/// costs a few records, never two per value). M2 charges each record its
/// encoded bytes plus forty of framing — about 290 journal bytes for a
/// two-byte atom at the shallowest content address, so M2's `MAX_TXN_BYTES`
/// (64 MiB) carries some 230,000 of them and no more. `2^17` is the largest
/// power of two inside that ceiling, so a re-insert at the cap is a
/// transaction M2 accepts (`the_reinsert_budget_is_a_transaction_m2_accepts`
/// measures it against M2's own accounting, atom by atom), and the live heap
/// one shot commands stays on the order of the budget M2 already prices, as
/// [`MAX_PLACED_RUNS`] keeps it for a placement's runs at that depth. The
/// heap does not grow with a value's length — a re-inserted atom's bytes are
/// shared with the stored value they are read from, never copied, and a
/// byte-run is copied into an owned buffer and from it into its stretch, one
/// copy kept — but it grows with the address's depth, every staged record and
/// the working world's new entry holding the fresh address whole; and the
/// journal grows with both: a longer value, or a deeper document's addresses,
/// makes every record longer, so there the ceiling holds fewer values and a
/// re-insert under the cap can still meet M2's own refusal. The cap bounds
/// the values a shot commands; it does not promise that every staging under
/// it commits, nor that its heap stays on M2's order past the shallowest
/// address.
///
/// A shot cannot be split to meet it, any more than it can
/// [`MAX_PLACED_RUNS`]: the member it produces is born whole, and a retry of
/// the same shot is refused the same way. An arrangement whose draft-native
/// positions pass it reaches publication across successive shots instead:
/// what one shot re-inserts joins the document's own I-space, which the next
/// shot places by reference, so each shot re-inserts only what is still the
/// draft's. Each of those shots is a member in its own right: born
/// published, the head its readers float to until the next lands, answering
/// its own address forever — so this remedy publishes every interim
/// arrangement as a version of the edition. It is also the only remedy for a
/// shot M2 refuses `OverBudget`: for an act that cannot be split, M2's "split
/// the transaction" means this and nothing else.
pub const MAX_REINSERTED_VALUES: usize = 1 << 17;

/// The most run-list steps one COPY's specs may command.
///
/// That is the work its resolution does, which [`MAX_PLACED_RUNS`] does not
/// bound, since what a spec keeps does not bound what it walks. Resolving a
/// span walks every run left of its opening ordinal, one `Nat` addition and
/// comparison apiece ([`iter_resolve`](crate::M5State::iter_resolve) states
/// it), so a spec aimed at its source's end — or past it, keeping nothing —
/// costs the source's whole run count however narrow its answer, and a
/// request's spec list multiplies that. Every step runs inside COPY's
/// transaction, under M2's applier lock, where it stalls every writer in the
/// engine and not the caller alone.
///
/// Charged as M7 charges a MAKELINK slot's specs (its
/// `MAX_SLOT_RESOLVE_STEPS`): each spec at its source's whole run count
/// ([`content_run_count`](crate::M5State::content_run_count), one map lookup
/// reading no run), summed over the specs in order and refused
/// `TooManyRuns` where the sum crosses, ahead of that spec's walk. The worst
/// case rather than the steps taken, and the one ceiling that holds whatever
/// backs the run-list: a span's reach bounds today's walk too
/// ([`iter_resolve`](crate::M5State::iter_resolve)'s card), but only
/// today's, so it is not charged — and the bound is conservative in the one
/// safe direction: a narrow early span over a fragmented source is refused
/// for work it would not have done.
///
/// `2^20` steps: at order 50 ns a step, ~50 ms of applier-lock hold, the
/// order of a three-slot MAKELINK's walks (three slots of `2^18` steps). It
/// admits the wire's 4096 specs over a 256-run source, or one spec over a
/// source of a million runs; a copy past it is split by its caller, as one
/// past [`MAX_PLACED_RUNS`] is.
pub const MAX_COPY_RESOLVE_STEPS: usize = 1 << 20;

/// M5's transact-driving op handle over M2 (§B).
///
/// It is a thin borrow of the engine's kernel and, on an attested handle, of
/// an attestation. The pure reads live on [`M5State`](crate::M5State)
/// (reached through [`HasM5`](crate::HasM5)); this type owns only the seven
/// editing/versioning operations — INSERT, DELETE, COPY, REINSTATE,
/// REARRANGE, VERSION and the publish shot — that M10 (and, for `insert`, M9)
/// dispatches.
///
/// **The edition is append-only** (PUB-2.43) — the invariant the shot's
/// carried tail rests on ([`Vstream::publish`]), kept by these operations and
/// by no fold. A document's publication bit is fixed at its mint (M3), and
/// every content arrangement of a published document's chain starts as the
/// transaction that mints its document or member leaves it — empty from M3's
/// create path, a shot's placement, a version's snapshot — and afterwards
/// changes only by a declared deposit at `n_C + 1` of the arrangement
/// [`deposit_surface`](crate::deposit_surface) names. So at any moment
/// exactly one arrangement per published chain can grow — the trunk head, or
/// the document's own while it has no member — and no position of any is
/// removed, moved, or inserted before. Its gates: `insert`'s published-target
/// refusal, cleared at that one position alone; the same refusal on `copy`,
/// `reinstate`, `delete` and `rearrange`; `publish` and `version` writing
/// only the arrangement of the document or member they mint; and the
/// `LinkSeat` fold touching the link run-list alone. An operation that writes
/// a content arrangement joins this list or breaks the shot.
/// [`M5State::apply_m5`](crate::M5State::apply_m5) does not check it, so a
/// record staged past these ops ([`M5Rec`](crate::M5Rec)'s seals say how)
/// can break it, and a replayed journal holds it as far as M2's integrity
/// does.
pub struct Vstream<'k, W: WorldState> {
    kernel: &'k Kernel<W>,
    /// The attestation the handle's three checked-set ops commit under.
    ///
    /// They are `insert`, `publish` and `version` (signed ops) — the three
    /// ops of this handle in the checked set, the op kinds the daemon's
    /// write-path check reaches (skep-core's `in_checked_set`): the value is
    /// handed to the kernel's `transact_attested` arm at the one transaction
    /// each opens, filling that commit marker's signature slot; `None` — the
    /// plain handle every other constructor site builds — leaves the slot
    /// empty. A borrow, so the handle stays `Copy` and the value cannot
    /// outlive the caller that owns it; how many commits it signs is the
    /// producer's to hold, as [`Vstream::attested`] states. The handle's four
    /// other writes — `delete`, `copy`, `reinstate`, `rearrange` — lie outside
    /// the checked set and take the plain arm whatever this field holds: the
    /// store refuses each into a published document (`PublishedTarget`), so
    /// no entry of their kind exists for a frame to cover. Link seating is no
    /// write of this handle: `stage_seat_link` is a step of M7's MAKELINK,
    /// whose own handle carries that op's attestation.
    attest: Option<&'k Attestation>,
}

impl<'k, W: WorldState> Vstream<'k, W> {
    /// Builds the plain handle: its commits leave the signature slot empty.
    ///
    /// M10 builds a Vstream over the engine's kernel this way through
    /// `Stores::vstream` — its write dispatch builds its handles with
    /// [`Vstream::attested`] instead — and so does the factory the engine
    /// hands M9 for predicate-def `insert`.
    pub fn new(kernel: &'k Kernel<W>) -> Vstream<'k, W> {
        Vstream::attested(kernel, None)
    }

    /// Builds a handle whose three checked-set ops commit under `attest`.
    ///
    /// They are `insert`, `publish` and `version` (signed ops; the
    /// attestation rides the handle). Its callers are the slot's producer set
    /// — M10's dispatch, with a value the daemon's check admitted — and
    /// nothing else; `None` is [`Vstream::new`].
    ///
    /// **Precondition.** One call per attested handle is the producer's
    /// obligation, and the type does not hold it. An attestation signs one
    /// entry body, while every `insert`, `publish` and `version` the handle
    /// makes — or a copy of it, the handle being `Copy` — commits under the
    /// one value it carries, so a second commit under it carries a signature
    /// over a body not its own, which no verifier of that entry can verify.
    /// M10's `dispatch_write` builds one handle per call, for the one write
    /// the daemon's check admitted the value for.
    pub fn attested(kernel: &'k Kernel<W>, attest: Option<&'k Attestation>) -> Vstream<'k, W> {
        Vstream { kernel, attest }
    }
}

/// Prints the handle's arm alone: whether it carries an attestation.
///
/// That is the one fact about it that changes what its commits write,
/// `insert`, `publish` and `version` filling their marker's signature slot
/// under one — with `..` for the kernel borrow, a world being no thing to
/// print into a diagnostic, and never the attestation's bytes, a blob as wide
/// as M2's `MAX_SIG_BYTES`. Written out rather than derived: a derive would
/// bound the impl on `W: Debug`, and a world composed of persistent store
/// slices need not be, so the derived impl would apply to no `W` that exists.
impl<W: WorldState> fmt::Debug for Vstream<'_, W> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Vstream")
            .field("attested", &self.attest.is_some())
            .finish_non_exhaustive()
    }
}

/// Copies the handle, which is two borrows.
///
/// They are the kernel and, on an attested handle, the attestation — so a
/// copy of the handle is a copy of two references. Written out, as `Debug`
/// is: the derives would bound the impls on `W: Clone` / `W: Copy`, and no
/// `WorldState` is `Copy` — the choice M6's `Query` makes for the same
/// reason.
impl<W: WorldState> Clone for Vstream<'_, W> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<W: WorldState> Copy for Vstream<'_, W> {}

/// Mints, writes and stages one atom, accumulating its address into `runs`.
///
/// It is J0 at the composite boundary (content-allocation ⇒ placement) for an
/// atom: it mints one fresh content address under `home`'s I-space (M3),
/// writes `value` there (M4), stages both records, and accumulates the
/// address into the placement `runs`. The step INSERT and the publish shot's
/// re-insert share for every value that is not one byte long — an atom of two
/// bytes or more, or an empty value; a run of single-byte values goes through
/// [`allocate_stretch_for_placement`], its twin — so the coupling has one
/// enforcement site per record kind: what is allocated here rides the
/// transaction the caller's placement record rides, and so cannot commit
/// unplaced.
///
/// Successive calls read `stg.working()`, and under the content key both
/// callers hold for `home` (`M3State::content_lock_key`) they advance one
/// frontier and hand back I-adjacent addresses, which the accumulator
/// coalesces — a range mint advances it by its count, so the next step's
/// address starts at the range's reach and coalesces the same way. The
/// accumulator is asked rather than assumed: were the frontier ever to hand
/// back a non-adjacent address — a batched or striped allocator in M3 — the
/// placement would be a correct multi-run one, never a single run widened
/// over addresses M3 never allocated and M4 never wrote.
///
/// What the ops state of their mints rests on M3 and not on this step:
/// INSERT's one run, and the shot's fresh identity landing at the end of its
/// trunk's content chain (each stated on its op), hold because M3's content
/// chain issues each mint at the next ordinal (`M3State::mint_content`,
/// `M3State::mint_content_range`). This step assumes nothing of it, so a
/// placement stays correct where those statements would need revising — and
/// revising them is owed to their readers, skep-media's cell index among
/// them.
///
/// # Errors
///
/// `E` from the `MintError` where the mint is refused, then from the
/// `ContentError` where the write is: the mint precedes the write, which is
/// the `Mint` → `Content` order each of the two ops states for a value.
fn allocate_for_placement<W, E>(
    stg: &mut Staging<W>,
    home: &Address,
    value: Val,
    runs: &mut Vec<Run>,
) -> Result<(), E>
where
    W: WorldState + HasM3 + HasContent,
    W::Record: From<M3Rec> + From<ContentWrite>,
    E: From<MintError> + From<ContentError>,
{
    let (addr, m3rec) = stg.working().m3().mint_content(home)?;
    stg.push(m3rec.into());
    let write = stage_write(stg.working().content(), addr.clone(), value)?;
    stg.push(write.into());
    extend_or_push_run(
        runs,
        Run {
            i_start: addr,
            width: Nat::one(),
        },
    );
    Ok(())
}

/// Mints, writes and stages a run of single-byte values as one stretch.
///
/// It is J0 at the composite boundary for a run of single-byte values — the
/// twin of [`allocate_for_placement`]: it mints a range of `bytes.len()`
/// fresh content addresses under `home`'s I-space in one record (M3's
/// `mint_content_range`), writes the bytes there as one stretch (M4's
/// `stage_stretch`, the value at `first ⊕ k` being `bytes[k]`), stages both
/// records, and accumulates the range into the placement `runs` as one run.
/// INSERT's coalescing walk and the shot's re-insert call it per maximal
/// byte-run.
///
/// **One number, two records.** The range's `count` and the stretch's length
/// are one number by construction — both come off `bytes.len()` here, the
/// one site that stages the pair — and no decode door and no fold sees both
/// records at once: a stretch longer than its mint would store bytes past the
/// chain's frontier, so the chain's next mint would hand out an address M4
/// refuses `AlreadyStored`, and every later insert into the document would
/// fail for good. So the pair is checked where it is discharged, by the
/// `debug_assert_eq!` after the two pushes; the engine's fold holds the
/// stretch to the chain's frontier again at every fold, live and on replay.
/// Nothing checks them in release, where a `debug_assert` is nothing.
///
/// # Errors
///
/// `E` from the `MintError` where the range mint is refused, then from the
/// `ContentError` where the stretch is: the mint precedes the write, as the
/// atom's step keeps it.
///
/// # Panics
///
/// Panics in a debug build where the range minted and the stretch staged
/// carry two different counts.
fn allocate_stretch_for_placement<W, E>(
    stg: &mut Staging<W>,
    home: &Address,
    bytes: Arc<[u8]>,
    runs: &mut Vec<Run>,
) -> Result<(), E>
where
    W: WorldState + HasM3 + HasContent,
    W::Record: From<M3Rec> + From<ContentStretch>,
    E: From<MintError> + From<ContentError>,
{
    let width = Nat::from(bytes.len());
    let (first, m3rec) = stg.working().m3().mint_content_range(home, &width)?;
    // The count the record carries, read before the record is pushed, for
    // the check below; `M3Rec` is `#[non_exhaustive]`, so the other arms are
    // spelled by a wildcard a range mint never takes.
    let minted = match &m3rec {
        M3Rec::AllocateRange(range) => Some(range.count().clone()),
        _ => None,
    };
    stg.push(m3rec.into());
    let stretch = stage_stretch(stg.working().content(), first.clone(), bytes)?;
    let written = Nat::from(stretch.len());
    stg.push(stretch.into());
    debug_assert_eq!(
        minted.as_ref(),
        Some(&written),
        "a range mint and its stretch carry one number"
    );
    extend_or_push_run(
        runs,
        Run {
            i_start: first,
            width,
        },
    );
    Ok(())
}

/// Returns the key a published chain's head serializes under.
///
/// It guards two things: which member heads the chain (the frontier
/// [`trunk_head`](crate::trunk_head) reads and a trunk member's mint
/// advances), and the arrangement every declared deposit into the chain lands
/// in ([`deposit_surface`](crate::deposit_surface) — the head member's, or
/// the document's own while the chain has no member and so no head). No key
/// of M5's own: the trunk's `version_lock_key`, taken by arithmetic on the
/// address named, so a transaction holds it before it knows where the head
/// is.
///
/// Every transaction that advances that frontier or lands content in that
/// arrangement holds it — a declared deposit, which lands there and reads the
/// frontier to find where; an owned `version` of the trunk, which advances
/// the frontier; the shot, which reads it to judge its base and advances it
/// unless the member it mints is the base's daughter, carrying its base's
/// tail as it does — and so does every `version`, whose snapshot takes its
/// source's reading surface off that frontier. An operation that advances a
/// published chain's frontier, lands content in the arrangement its declared
/// deposits land in, or reads the frontier to find the head, joins this list.
/// COPY is not on it: its source spans are read at the address named, so it
/// never asks the frontier where the head is; nor is REINSTATE, which reads
/// no origin's arrangement and of its own only the content count its bounds
/// check asks.
///
/// Public for the caller that opens a transaction of its own over
/// [`stage_publish`]: the shot's keys are this, `content_lock_key` of the
/// document the shot names projects to, and the base's own `version_lock_key`
/// where the base is a member — and a caller composing several stagings under
/// one transaction supplies the union of their keys, this among them.
pub fn head_lock_key(doc: &Address) -> LockKey {
    M3State::version_lock_key(&trunk_of(doc))
}

#[cfg(test)]
mod tests;
