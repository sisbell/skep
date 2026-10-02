//! §B / §3–§7 — the editing & versioning surface: `Vstream`, one M2
//! `transact` per operation, every mutation under an M3 lock key for the
//! touched document's allocation domain (§Serialization key).
//!
//! A REJECTION LEAVES NO STATE CHANGE. For a refusal answered inside a
//! transaction that is M2's guarantee rather than an ordering these ops keep:
//! `transact` returns `TxnError::Rejected(E)` straight out of the closure
//! phase, discarding the staging, drawing no `Seq` and appending nothing.
//! Four of the six ops do reject before staging anything; INSERT and the
//! publish shot cannot, since each stages a mint and a content write per
//! fresh value as it goes ([`allocate_for_placement`], J0's one step) and may
//! reject after them — on a later value, and for the shot on its run budget
//! or its own version mint as well. VERSION's three pre-transaction refusals
//! (`SourceNotRegistered`, `NotAPrincipal`, `NodeTierCrossOwner`) are
//! answered off an M2 snapshot before any transaction opens, and so reach M2
//! not at all. M10 surfaces the rejection as a typed one and acknowledges
//! only after commit.
//!
//! Ownership: five ops take a [`Caller`](crate::Caller) and open with
//! [`gate_write`](crate::ownership::gate_write) — the in-txn ω gate — on the
//! address the caller NAMES: the four edits and the shot (COPY: its
//! destination only; VERSION is ungated, non-owner versioning being
//! denial-as-fork, O10). The address named is not always the arrangement
//! written. A DECLARED DEPOSIT into a published chain that has a head lands
//! on that head ([`deposit_surface`](crate::deposit_surface)) rather than in
//! the named address's arrangement, and a shot writes only the member it
//! mints; both are members of the named document's chain, minted under it,
//! so the owner the gate checked is theirs too.
//!
//! Publication (PUB round 2, lane 3.1; owner ruling D2b): the version-chain
//! model's refusals, each stated with its op's check order, are evaluated
//! inside that op's own transaction on an address its own check has already
//! found registered (PUB-6.37), and are enforced here whatever runs ahead of
//! the store. Their one reading of the publication bit is
//! [`published_target`](crate::published_target), whose own card says why it
//! is public.
//!
//! WHICH ERROR WINS when several conditions fail at once is stated on each op,
//! in its own file below, and this is the only statement of it: the error
//! types name verdicts, not precedence, and the integration suite pins what is
//! written here.
//!
//! Layout: this file is the handle and what its operations share — the two
//! budgets, J0's allocation step ([`allocate_for_placement`]) and the head
//! key ([`head_lock_key`]). Each operation is a child module holding one
//! `impl` block — `ops/insert.rs`, `ops/publish.rs`, `ops/copy.rs`,
//! `ops/delete.rs`, `ops/rearrange.rs`, `ops/version.rs` — and sees this
//! file's private items and none of its siblings'. Each block's trait bounds
//! name exactly the slices its op reads and the records it stages, so a
//! minimal test world can drive `delete`/`rearrange` with `HasM5 + HasM3`
//! and `From<M5Rec>` alone.
//!
//! Unit tests sit with what they test: `ops/tests.rs` tests this file — the
//! handle, J0's step, the two budgets — and the bound claim above on `delete`
//! and `rearrange`; `ops/copy/tests.rs` and `ops/publish/tests.rs` hold the
//! two ops' own claims, which need a world no engine reaches.

use std::fmt;

use num_traits::One;
use skep_address::{Address, Nat};
use skep_content::{stage_write, ContentError, ContentWrite, HasContent, Val};
use skep_kernel::{Attestation, Kernel, LockKey, Staging, WorldState};
use skep_namespace::{HasM3, M3Rec, M3State, MintError};

use crate::chain::trunk_of;
use crate::run::Run;
use crate::runlist::extend_or_push_run;

mod copy;
mod delete;
mod insert;
mod publish;
mod rearrange;
mod version;

/// The most runs one COPY, or one publish shot, may place — and so the
/// ceiling on what one request can make M5 hold live while it decides
/// whether to place anything at all.
///
/// The budget: a `Run` journals as an element `Address` and a width, about a
/// hundred bytes as bincode writes them, so M2's `MAX_TXN_BYTES` (64 MiB)
/// admits on the order of half a million of them and no more — past that the
/// transaction cannot commit whatever M5 does, and the work of building it
/// is spent for a refusal. `2^16` sits an order inside that ceiling, which
/// keeps the LIVE heap one placing request commands to the same order as the
/// transaction budget M2 already prices rather than several times it. The
/// arithmetic is checked against the real encoding rather than restated here
/// (`the_placement_budget_stays_inside_the_transaction_budget`).
///
/// IT BINDS WHAT ONE COPY OR ONE SHOT PLACES AND HOLDS LIVE, and that is the
/// whole of what it binds. Both accumulators are measured as each run is
/// accumulated, and what feeds them is pulled a run at a time — COPY's LAZY
/// resolution of each spec, the shot's walk of its base's carried tail — so
/// the cap also stops the walk: an over-budget request is refused at the cap
/// rather than built in full and measured afterwards.
///
/// THE REMEDY DIFFERS BETWEEN THE TWO. A copy needing more runs than this is
/// split by the caller, exactly as an over-budget transaction already is. A
/// shot CANNOT be split: the member it produces is born whole, from the
/// whole arrangement the client rendered plus the base's carried deposits.
/// For a shot the refusal is therefore a ceiling on the run count of the
/// member one shot produces — the client's runs as the accumulator coalesces
/// them, plus the base's deposit runs — and a retry of the same arrangement
/// is refused the same way.
///
/// WHAT IT DOES NOT BIND is the WORK of resolving, which is a separate
/// quantity with a separate owner. Each COPY spec costs a prefix-sum walk of
/// its source's run-list to reach the span — `Θ(#runs(source))` for a span
/// near the end, however narrow the answer — and a request multiplies that
/// by its spec count. Neither factor has a ceiling here: `#runs(source)` has
/// none in v1 (Open decision #1) and grows with editing, and a spec count is
/// bounded only by M10's wire list cap. So admission control and concurrency
/// for a route carrying COPY are the CALLER's, as they are for the reads that
/// state their own cost, and a route that carries this op owes that number —
/// per spec, [`content_run_count`](crate::M5State::content_run_count) of its
/// source, which the arrangement answers without reading a run. The shot's
/// own per-run work is stated on [`Vstream::publish`].
pub const MAX_PLACED_RUNS: usize = 1 << 16;

/// The most values one publish shot may RE-INSERT — the fresh identities it
/// mints for its draft-native runs (PUB-2.40), each through J0's one step —
/// and so the ceiling on what one shot makes M5 stage before M2 has priced
/// any of it.
///
/// WHY A COUNT OF ITS OWN. M2 judges a transaction's size only once the
/// closure has returned, and until then every staged value is live heap: a
/// mint record and a content write, each carrying an address, and the
/// working world's new content entry. How many values a shot re-inserts is
/// [`Shot::reinserted_values`](crate::Shot::reinserted_values), its
/// draft-native runs' widths summed, and that sum is the REQUEST's to choose
/// — a run may name any stored I-extent of the draft, as often as the wire's
/// run list allows — while [`MAX_PLACED_RUNS`] does not see it, the fresh
/// addresses being I-adjacent and so coalescing into one run. Without
/// this count a request of a kilobyte stages the draft's stored content as
/// many times over as its run list repeats it, before any refusal can arrive.
/// The count is request arithmetic, taken before any address is probed, so
/// it bounds the existence walk over the draft-native runs as well.
///
/// The budget: a re-inserted value stages two records, and M2 charges each
/// its encoded bytes plus forty of framing — about 290 journal bytes for a
/// one-byte value at the shallowest content address, so M2's `MAX_TXN_BYTES`
/// (64 MiB) carries some 230,000 of them and no more. `2^17` is the largest
/// power of two inside that ceiling, so a re-insert at the cap is a
/// transaction M2 accepts (`the_reinsert_budget_is_a_transaction_m2_accepts`
/// measures it against M2's own accounting), and the live heap one shot
/// commands stays on the order of the budget M2 already prices, as
/// [`MAX_PLACED_RUNS`] keeps it for a placement's runs. That heap is the
/// count's alone — a re-inserted value's bytes are shared with the stored
/// value they are read from, never copied — but the journal is not: a longer
/// value, or a deeper document's addresses, makes every record longer, so
/// there the ceiling holds fewer values and a re-insert under the cap can
/// still meet M2's own refusal. The cap bounds the staging a shot commands;
/// it does not promise that every staging under it commits.
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

/// M5's transact-driving op handle over M2 (§B): a thin borrow of the
/// engine's kernel. The pure reads live on [`M5State`](crate::M5State)
/// (reached through [`HasM5`](crate::HasM5)); this type owns only the six editing/
/// versioning operations — INSERT, DELETE, COPY, REARRANGE, VERSION and the
/// publish SHOT — that M10 (and, for `insert`, M9) dispatches.
///
/// THE EDITION IS APPEND-ONLY (PUB-2.43) — the invariant the shot's carried
/// tail rests on ([`Vstream::publish`]), kept by this surface and by no fold.
/// A document's publication bit is fixed at its mint (M3), and every content
/// arrangement of a published document's chain starts as the transaction
/// that mints its document or member leaves it — empty from M3's create
/// path, a shot's placement, a version's snapshot — and afterwards changes
/// only by a DECLARED deposit at `n_C + 1` of the arrangement
/// [`deposit_surface`](crate::deposit_surface) names. So at any moment
/// exactly one arrangement per published chain can grow — the trunk head, or
/// the document's own while it has no member — and no position of any is
/// removed, moved, or inserted before. Its gates: `insert`'s published-target
/// refusal, cleared at that one position alone; the same refusal on `copy`,
/// `delete` and `rearrange`; `publish` and `version` writing only the
/// arrangement of the document or member they mint; and the `LinkSeat` fold
/// touching the link run-list alone. An operation that writes a content
/// arrangement joins this list or breaks the shot.
/// [`M5State::apply_m5`](crate::M5State::apply_m5) does not check it, so a
/// record staged past these ops ([`M5Rec`](crate::M5Rec)'s seals say how)
/// can break it, and a replayed journal holds it as far as M2's integrity
/// does.
pub struct Vstream<'k, W: WorldState> {
    kernel: &'k Kernel<W>,
    /// THE ATTESTATION this handle's publish-class-capable calls commit under
    /// (signed ops): handed to the kernel's `transact_attested` arm at the one
    /// transaction `insert` and `publish` each open, filling THAT commit
    /// marker's signature slot; `None` — the plain handle every other
    /// constructor site builds — leaves the slot empty. A BORROW, so the
    /// handle stays `Copy` and the value cannot outlive the caller that owns
    /// it for the one call this handle serves. The other writes of this
    /// surface (`delete`, `copy`, `rearrange`, `version`, the seat op) take
    /// the plain arm whatever this field holds: outside the seam build's
    /// slice, a handle built with a value fills no slot through them.
    attest: Option<&'k Attestation>,
}

impl<'k, W: WorldState> Vstream<'k, W> {
    /// The plain constructor — M10 (and M9, for predicate-def `insert`) build
    /// a Vstream over the engine's kernel this way; its transactions commit
    /// with the signature slot EMPTY.
    pub fn new(kernel: &'k Kernel<W>) -> Vstream<'k, W> {
        Vstream::attested(kernel, None)
    }

    /// THE ATTESTED CONSTRUCTOR (signed ops; the confirmed placement): a
    /// handle whose `insert` and `publish` commit under `attest`. Its callers
    /// are the slot's producer set — M10's dispatch, with a value the
    /// daemon's check admitted — and nothing else; `None` is [`Vstream::new`].
    pub fn attested(kernel: &'k Kernel<W>, attest: Option<&'k Attestation>) -> Vstream<'k, W> {
        Vstream { kernel, attest }
    }
}

/// The handle's name and nothing else — it holds one kernel borrow, and a
/// world is not a thing to print into a diagnostic. Written out rather than
/// derived: a derive would bound the impl on `W: Debug`, and a world composed
/// of persistent store slices need not be, so the derived impl would apply to
/// no `W` that exists.
impl<W: WorldState> fmt::Debug for Vstream<'_, W> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Vstream")
    }
}

/// One kernel borrow, so a copy of the handle is a copy of a reference.
/// Written out, as `Debug` is: the derives would bound the impls on
/// `W: Clone` / `W: Copy`, and no `WorldState` is `Copy` — the choice M6's
/// `Query` makes for the same reason.
impl<W: WorldState> Clone for Vstream<'_, W> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<W: WorldState> Copy for Vstream<'_, W> {}

/// J0 at the composite boundary (content-allocation ⇒ placement): mint one
/// fresh content address under `home`'s I-space (M3), write `value` there
/// (M4), stage both records, and accumulate the address into the placement
/// `runs`. The ONE step INSERT and the publish shot's re-insert share, so
/// the coupling has one enforcement site: what is allocated here rides the
/// transaction the caller's placement record rides, and so cannot commit
/// unplaced. The mint precedes the write, which is the `Mint` → `Content`
/// order each of the two ops states for a value.
///
/// Successive calls read `stg.working()`, and under the content key both
/// callers hold for `home` (`M3State::content_lock_key`) they advance ONE
/// frontier and hand back I-adjacent addresses, which the accumulator
/// coalesces. The accumulator is ASKED rather than assumed: were the
/// frontier ever to hand back a non-adjacent address — a batched or striped
/// allocator in M3 — the placement would be a correct multi-run one, never a
/// single run widened over addresses M3 never allocated and M4 never wrote.
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
    let write = stage_write(stg.working().content(), &addr, value)?;
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

/// The key a published chain's HEAD serializes under, guarding two things:
/// which member heads the chain (the frontier [`trunk_head`](crate::trunk_head)
/// reads and a trunk member's mint advances), and the arrangement every
/// declared deposit into the chain lands in
/// ([`deposit_surface`](crate::deposit_surface) — the head member's, or the
/// document's own while the chain has no member and so no head). No key of
/// M5's own: the trunk's `version_lock_key`, taken by arithmetic on the
/// address named, so a transaction holds it before it knows where the head
/// is.
///
/// Every transaction that ADVANCES that frontier or LANDS content in that
/// arrangement holds it — a declared deposit, which lands there and reads the
/// frontier to find where; the shot and an owned `version` of the trunk,
/// which advance the frontier (the shot carrying its base's tail as it does)
/// — and so does every `version`, whose snapshot takes its source's reading
/// surface off that frontier. An operation that advances a published chain's
/// frontier, lands content in the arrangement its declared deposits land in,
/// or reads the frontier to find the head, joins this list. COPY is not on
/// it: its source spans are read at the address named, so it never asks the
/// frontier where the head is.
fn head_lock_key(doc: &Address) -> LockKey {
    M3State::version_lock_key(&trunk_of(doc))
}

#[cfg(test)]
mod tests;
