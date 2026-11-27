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
//! Six of the nine ops do reject before staging anything; INSERT, the
//! publish shot and the edit cannot, since each stages a mint and a content
//! record per fresh atom or maximal run of single-byte values as it goes
//! ([`allocate_for_placement`] and [`allocate_stretch_for_placement`], J0's
//! two steps) and may reject after them — on a later value, and for the shot
//! on its run budget or its own version mint as well; the edit judges
//! everything else of its request ahead of its first record, so past it only
//! its mints' own two verdicts remain. VERSION's
//! and STAGE's three pre-transaction refusals (`SourceNotRegistered`,
//! `NotAPrincipal`, `NodeTierCrossOwner`) are answered off an M2 snapshot
//! before any transaction opens, and so reach M2 not at all. M10 surfaces
//! the rejection as a typed one and acknowledges only after commit.
//!
//! **Ownership.** Seven ops take a [`Caller`](crate::Caller) and open with
//! [`gate_write`](crate::ownership::gate_write) — the in-txn ownership gate,
//! registration then the ω gate — on the address the caller names: the five
//! edits, EDIT and the shot (COPY, REINSTATE and EDIT:
//! their destination only; VERSION and STAGE are ungated, non-owner
//! versioning being denial-as-fork, O10, and a staging draft landing in the
//! caller's own account). The address named is not always the arrangement
//! written. A declared deposit into a published chain that has a head lands
//! on that head ([`deposit_surface`](crate::deposit_surface)) rather than in
//! the named address's arrangement, and a shot writes only the member it
//! mints; both are members of the named document's chain, minted under it,
//! so the owner the gate checked is theirs too. The substitution's staging
//! body ([`stage_substitute`]) opens with the same gate, on the draft it
//! changes.
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
//! four budgets, J0's two allocation steps ([`allocate_for_placement`] for an
//! atom, [`allocate_stretch_for_placement`] for a run of single-byte values)
//! and the coalescing walk over them that INSERT and the edit share
//! ([`allocate_values_for_placement`]), the head key ([`head_lock_key`]),
//! and the state an edit was typed against ([`AsOf`]) with the one check the
//! five in-place edits and the edit key on it ([`arrangement_moved`]). Each
//! operation is a child module holding one `impl` block — `ops/insert.rs`,
//! `ops/publish.rs`, `ops/copy.rs`, `ops/reinstate.rs`, `ops/delete.rs`,
//! `ops/rearrange.rs`, `ops/version.rs`, `ops/stage.rs`, `ops/edit.rs` —
//! and sees this file's private items and none of its siblings', the edit
//! excepted: it asks a landing's three terms of `ops/set_arrangement.rs`,
//! which holds their judgment and their record and no operation.
//! `ops/substitute.rs` holds no operation either: it is one staging body,
//! [`stage_substitute`], the identity-checked substitution a publication
//! stages for each draft it re-windows at its kept places.
//! `ops/publish.rs` holds as well the shot's admission, the checks
//! `publish` opens with, offered as a pure query ([`shot_admission`]), and
//! the count of the units its re-insert comes to
//! ([`Shot::reinserted_units`](crate::Shot::reinserted_units)), a read of
//! the draft's stored pieces under the one bound [`ReinsertWorld`]; and
//! three of the modules hold their op's body as a function over a
//! caller-opened staging — [`stage_publish`], [`stage_reinstate_at`],
//! [`stage_delete_at`] — the public op a wrapper that opens the transaction,
//! so a caller can stage the three under one commit; `ops/publish.rs` names
//! the shot's bound as one trait ([`PublishWorld`]) and the pairing its
//! staging returns ([`MintedRun`], [`Pairing`]), for such a caller. Each
//! block's trait bounds name the slices its op reads and the
//! records it stages — `version`'s names `HasM5` as well, which its op does
//! not read — so a minimal test world can drive `delete`/`rearrange` with
//! `HasM5 + HasM3` and `From<M5Rec>` alone, and answer the shot's admission
//! with those two slices too.
//!
//! Unit tests sit with what they test: `ops/tests.rs` tests this file — the
//! handle, J0's atom step, the placement budget and the re-insert's two
//! against M2's own accounting and the signed body's rows — and the bound
//! claim above on `delete`, `rearrange` and the
//! shot's admission; `ops/copy/tests.rs`, `ops/reinstate/tests.rs`,
//! `ops/publish/tests.rs`, `ops/edit/tests.rs` and
//! `ops/set_arrangement/tests.rs` hold the four ops' own claims — COPY's
//! walk budget, REINSTATE's every-address probe, the edit's lock hold by a
//! count and the refusal order of the landing's terms among them — and
//! `ops/substitute/tests.rs` the substitution's — one pass against a
//! replacement made one piece at a time, the entry that answers, its one
//! walk by a count — which need a world no engine reaches.

use std::fmt;
use std::sync::Arc;

use num_traits::One;
use skep_address::{Address, Nat};
use skep_content::{
    stage_stretch, stage_write, ContentError, ContentStretch, ContentWrite, HasContent, Val,
};
use skep_kernel::{Attestation, Kernel, LockKey, Seq, Staging, WorldState};
use skep_namespace::{HasM3, M3Rec, M3State, MintError};

use crate::chain::trunk_of;
use crate::run::Run;
use crate::run_list::extend_or_push_run;
use crate::state::M5State;

// COPY (ASN-0118): transclusion by reference, allocating nothing.
mod copy;
// DELETE (ASN-0117): a content range removed and the gap closed.
mod delete;
// EDIT: a list of positional changes to one draft in one commit, staged as
// one record — values minted or runs placed by identity.
mod edit;
// INSERT (ASN-0116): fresh content placed, and the declared deposit.
mod insert;
// PUBLISH, the shot (PUB-2.33), and its admission.
mod publish;
// REARRANGE (ASN-0119/0084): the pivot and the swap.
mod rearrange;
// REINSTATE (the replacement act): the write by identity — client-named
// I-runs placed at a position, allocating nothing.
mod reinstate;
// The landing's terms (the landing lane; skep #764): the head, the base and
// the merge an edit carries where it lands a merge, judged and recorded.
mod set_arrangement;
// STAGE (B3-S10): the staging act — a private draft of a source, its base
// recorded.
mod stage;
// SUBSTITUTE: the identity-checked substitution — the runs a draft arranges
// at each place of a list replaced by the runs given for them, in one walk
// and one record; a staging body, no operation.
mod substitute;
// CREATENEWVERSION (ASN-0123): the fork.
mod version;

pub use delete::stage_delete_at;
pub use edit::{Change, Edit, Edited, Placed};
pub use publish::{
    mint_admission, shot_admission, stage_publish, MintedRun, Pairing, PublishWorld,
    ReinsertWorld, ReinsertedUnits, UnitParts, UnitTally,
};
pub use reinstate::stage_reinstate_at;
pub use set_arrangement::SetMerge;
pub use substitute::{stage_substitute, Replacement, Substitution};

/// The most runs one COPY, one REINSTATE, one EDIT or one publish shot may
/// place.
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
/// **It binds what one COPY, one REINSTATE, one EDIT or one shot places and
/// holds live**, and that is the whole of what it binds. Each accumulator is
/// measured as each run is accumulated, and what feeds them is pulled a run
/// at a time — COPY's lazy resolution of each spec, REINSTATE's and the
/// edit's walks of the client's list, an edit's count taken over all its
/// changes with each change's minted values one run, the shot's walk of its
/// own runs — so the cap
/// also stops the walk: an over-budget request is refused at the cap rather
/// than built in full and measured afterwards. For a shot, what it places is
/// its placement — the client's runs as the store places them, each
/// stretch's accumulated apart, counted in runs — and never the shot term
/// [`placed`](crate::ShotTerms::placed), which counts positions. No run of
/// the shot's base is in it: the member is built from the base's own list
/// when the placing record is folded, so the positions of the base no
/// stretch names — its carried tail among them — are read there and held by
/// no accumulator here.
///
/// **The remedy differs between the edits and the shot.** A copy or a
/// reinstate needing more runs than this is split by the caller, exactly as
/// an over-budget transaction already is. A shot cannot be split: its member
/// is born in one commit. For a shot the refusal is a ceiling on the runs
/// ONE SHOT PLACES — the client's runs as each stretch's accumulator
/// coalesces them — and a retry of the same runs is refused the same way.
/// It is no ceiling on a member's run count: a shot that names its change
/// places the change's runs and mints its base's list with them spliced in,
/// so a member of more runs than this is reached by shots each inside it,
/// and only a shot that sends its whole arrangement holds its member — the
/// carried tail apart — to this number.
///
/// **A transport's door holds the request's own list to this number.** A
/// codec that bounds every request array by a span budget reads that budget
/// onto a list of runs by reuse, which the span budget's argument does not
/// cover; this card's does — a placed run is a run held live and about a
/// hundred bytes of the transaction, priced here at `2^16`. So the wire's
/// door takes this constant for a shot's `runs` and for the runs of an
/// edit's changes together (skepd's `MAX_WIRE_RUNS`), judged on the request
/// before a run is parsed, and the store judges the placement as it
/// accumulates: one number at two places, the second seeing what the first
/// cannot — a draft-native run re-inserted in pieces is more than one.
///
/// **What it does not bind** is the work of resolving: each COPY spec's
/// prefix-sum walk of its source's run-list to reach the span,
/// `Θ(#runs(source))` for a span near the end however narrow the answer.
/// COPY's has a ceiling of its own, [`MAX_COPY_RESOLVE_STEPS`]; the shot's
/// per-run work is stated on [`Vstream::publish`]. Nor does it bind the
/// runs a substitution puts in ([`stage_substitute`]): they are pieces its
/// caller built before the call, so no accumulator here grows with them.
pub const MAX_PLACED_RUNS: usize = 1 << 16;

/// The most distinct positions one publish shot may re-insert.
///
/// They are the positions its draft-native runs name
/// ([`Shot::reinserted_values`](crate::Shot::reinserted_values)) — each
/// draft identity is minted once per shot as fresh identity (PUB-2.40), a
/// later occurrence placed by reference — and so this is the ceiling on the
/// stored pieces one shot makes its readers walk before anything has priced
/// them.
///
/// **Why a count of its own.** The positions are the request's to choose: a
/// run may name any stored I-extent of the draft, while [`MAX_PLACED_RUNS`]
/// does not see it, the fresh addresses being I-adjacent and so coalescing
/// into one run. Without this count a request of a kilobyte commands a walk
/// of the whole stored content its runs reach, before any refusal can
/// arrive. The count is request arithmetic, taken before any address is
/// probed, so it bounds every walk of the draft-native runs' stored pieces:
/// the count of the shot's units
/// ([`Shot::reinserted_units`](crate::Shot::reinserted_units)), which is
/// the shot's existence walk over those runs, the walk the entry frame's
/// composer makes of them and the media door's reading of them. It is no
/// bound on the records the shot stages — a megabyte of typed text is one
/// unit where it lies in one run — which is [`MAX_REINSERTED_UNITS`]'s to
/// bind.
///
/// **The budget** is the signed body's. A shot's entry frame spells every
/// value the shot re-inserts by its bytes behind a four-byte length
/// (skep-identity's `PublishBody`), so a value of one byte costs the body
/// five, and the frame routes hold a body to 8 MiB (skep-core's
/// `MAX_REQUEST_BODY`): 8 MiB ÷ 5 = 1,677,721 one-byte values and no more.
/// `2^20` is the largest power of two inside that, chosen as
/// [`MAX_REINSERTED_UNITS`] is chosen inside the transaction's ceiling
/// (`the_reinsert_budget_is_a_transaction_m2_accepts` holds the number to
/// the body's rows). A shot at the cap is reachable at the mint form, or
/// over a document whose own placed words are few: at the document form the
/// body spells the document's own runs by value too.
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
/// shot past [`MAX_REINSERTED_UNITS`], and for one M2 refuses `OverBudget`:
/// for an act that cannot be split, M2's "split the transaction" means this
/// and nothing else.
pub const MAX_REINSERTED_VALUES: usize = 1 << 20;

/// The most units one publish shot may re-insert.
///
/// A unit is what the re-insert stages as one pair of records, a mint and a
/// content write, through one of J0's two steps: an atom — a `Piece::Value`
/// of two bytes or more, or an empty one — or a maximal run of single-byte
/// values inside one unminted portion of a draft-native run, however wide
/// it is. [`Shot::reinserted_units`](crate::Shot::reinserted_units) counts
/// them, split exactly as the staging splits them, and so this is the
/// ceiling on what one shot makes M5 stage before M2 has priced any of it.
///
/// **Why a count of its own**, beside [`MAX_REINSERTED_VALUES`]. M2 judges a
/// transaction's size only once the closure has returned, and until then
/// every staged record is live heap: a mint record and a content record a
/// unit, each carrying an address, and the working world's new content
/// entry. The positions do not tell the records — a run of single-byte
/// values re-inserts as one range mint and one stretch however wide it is
/// (the re-insert coalesces consecutive bytes, so a draft typed byte by
/// byte costs a few records, never two per value), where every atom costs
/// two — so the records are counted as what they are. The count reads the
/// draft's stored pieces, which tell an atom from a byte: it is asked after
/// the positions' arithmetic, which bounds its walk, and before the first
/// record is staged.
///
/// **The budget**, measured at the worst case that holds: every unit an
/// atom. M2 charges each record its encoded bytes plus forty of framing —
/// about 290 journal bytes for a two-byte atom at the shallowest content
/// address, so M2's `MAX_TXN_BYTES` (64 MiB) carries some 230,000 of them
/// and no more. `2^17` is the largest power of two inside that ceiling, so a
/// re-insert at the cap is a transaction M2 accepts
/// (`the_reinsert_budget_is_a_transaction_m2_accepts` measures it against
/// M2's own accounting, atom by atom), and the live heap one shot commands
/// stays on the order of the budget M2 already prices, as
/// [`MAX_PLACED_RUNS`] keeps it for a placement's runs at that depth. The
/// heap does not grow with an atom's length — a re-inserted atom's bytes are
/// shared with the stored value they are read from, never copied — and a
/// byte-run is copied into an owned buffer and from it into its stretch, one
/// copy kept, the runs' bytes together bounded by
/// [`MAX_REINSERTED_VALUES`]; but it grows with the address's depth, every
/// staged record and the working world's new entry holding the fresh address
/// whole; and the journal grows with both: a longer value, or a deeper
/// document's addresses, makes every record longer, so there the ceiling
/// holds fewer units and a re-insert under the cap can still meet M2's own
/// refusal. The cap bounds the units a shot commands; it does not promise
/// that every staging under it commits, nor that its heap stays on M2's
/// order past the shallowest address.
///
/// A shot cannot be split to meet it: the remedy is
/// [`MAX_REINSERTED_VALUES`]'s, successive shots.
pub const MAX_REINSERTED_UNITS: usize = 1 << 17;

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

/// The document state an edit was typed against (skep #442).
///
/// It is the value the five in-place edits take beside their positions —
/// [`insert`](Vstream::insert), [`delete`](Vstream::delete),
/// [`copy`](Vstream::copy), [`reinstate`](Vstream::reinstate),
/// [`rearrange`](Vstream::rearrange) — and
/// [`edit`](Vstream::edit) beside its changes, and the
/// one question the write path asks of [`M5State::arranged_at`]: whether the
/// document's arrangement has changed since the state the edit's positions
/// are true of. A frame's positions are true of one state of the document;
/// typed against an older one, they land a little off and nothing says so
/// — and a whole arrangement composed against an older state would wipe
/// what was written since. Two arms, as
/// [`Deposit`](crate::Deposit) has two: an edit is typed against a state or
/// it is not, so a match on it is exhaustive and the unchecked arm is spelled
/// where it is used. No `Default` and no `From<Seq>`: a position becomes this
/// value with the arm written out, where a reader sees which it is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AsOf {
    /// The position of the state the edit was typed against.
    ///
    /// It is the wire's `as_of`: the `as_of` of the read the edit's text came
    /// from, raised by the `at` of each of the writer's own acks on the
    /// document — one coordinate with a read's `as_of` and a write's `at`,
    /// the position in the committed log. The edit is refused
    /// `ArrangementMoved` where the document's arrangement last changed at a
    /// position past it (the ops' shared `arrangement_moved`), behind the
    /// published-target
    /// refusal and ahead of every shape check, so a stale edit meets its own
    /// code and never `OutOfBounds`; typed at or past that change, or on a
    /// document never arranged, it lands exactly as an unchecked one.
    Typed(Seq),
    /// No state named: the edit is judged on its positions alone.
    ///
    /// Two writers pass it, each with a reason the check could not improve
    /// on: the daemon's head writer and the rule engine's definer, in-process
    /// writers under their own serial lock that nothing races. The
    /// publication's re-window of a draft at its kept places takes no value
    /// of this type at all: its body ([`stage_substitute`]), staged inside
    /// the shot's own commit, checks by identity — refused `KeptPlaceMoved`
    /// — which this check would only duplicate, and refuse where the
    /// identity check does not.
    Unchecked,
}

/// M5's transact-driving op handle over M2 (§B).
///
/// It is a thin borrow of the engine's kernel and, on an attested handle, of
/// an attestation. The pure reads live on [`M5State`]
/// (reached through [`HasM5`](crate::HasM5)); this type owns only the nine
/// editing/versioning operations — INSERT, DELETE, COPY, REINSTATE,
/// REARRANGE, EDIT, VERSION, STAGE and the publish shot — that
/// M10 (and, for `insert`, M9) dispatches.
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
/// `reinstate`, `delete`, `rearrange` and `edit`, and on the substitution's
/// staging body ([`stage_substitute`]); `publish` and `version` writing
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
    /// producer's to hold, as [`Vstream::attested`] states. The handle's six
    /// other writes — `delete`, `copy`, `reinstate`, `rearrange`,
    /// `edit`, `stage` — lie outside the checked set and take the
    /// plain arm whatever this field holds: the store refuses each of the
    /// five edits into a published document (`PublishedTarget`), and a stage
    /// mints private, so no entry of their kind exists for a frame to cover.
    /// Link seating is no
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

/// Mints, writes and stages `values` in order, accumulating them into `runs`.
///
/// It is the coalescing walk INSERT and the edit share, J0's two steps
/// driven over a list of values: every one-byte value joins a pending
/// byte-run, and the run is flushed as one stretch
/// ([`allocate_stretch_for_placement`]) at the next atom and at the end; an
/// atom — a value of two bytes or more, or an empty one — stages its own
/// pair ([`allocate_for_placement`]). Every one-byte value the codec hands
/// in is a per-byte value (the wire canonicalizes a one-byte atom to its
/// per-byte form), so one code path stores every per-byte value one way, a
/// run of one included.
///
/// The values are minted one after another under the content key the caller
/// holds for `home`, so they take consecutive addresses of `home`'s content
/// chain in the order given — the k-th value at the first address plus `k`
/// — and `runs` gains one run for them, whose start is the first address
/// minted. That rests on M3's frontier, as [`allocate_for_placement`]
/// states: the accumulator is asked, never assumed, so a frontier that
/// handed back a non-adjacent address would leave several runs and a
/// correct placement.
///
/// What it stages is `2 × (maximal single-byte runs + atoms)` records — a
/// mint and a content record a run or an atom — so text of any length is two
/// records, whatever the caller then splits the minted run among.
///
/// # Errors
///
/// Per maximal run of single-byte values or atom in the order given, `E`
/// from the `MintError` then from the `ContentError`, the first to fail
/// deciding (the two steps' own order).
fn allocate_values_for_placement<W, E>(
    stg: &mut Staging<W>,
    home: &Address,
    values: impl IntoIterator<Item = Val>,
    runs: &mut Vec<Run>,
) -> Result<(), E>
where
    W: WorldState + HasM3 + HasContent,
    W::Record: From<M3Rec> + From<ContentWrite> + From<ContentStretch>,
    E: From<MintError> + From<ContentError>,
{
    let mut pending: Vec<u8> = Vec::new();
    for value in values {
        if let [byte] = value.as_bytes() {
            pending.push(*byte);
            continue;
        }
        if !pending.is_empty() {
            let run = Arc::from(std::mem::take(&mut pending));
            allocate_stretch_for_placement::<_, E>(stg, home, run, runs)?;
        }
        allocate_for_placement::<_, E>(stg, home, value, runs)?;
    }
    if !pending.is_empty() {
        allocate_stretch_for_placement::<_, E>(stg, home, Arc::from(pending), runs)?;
    }
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
/// check asks; nor is EDIT, which reads the frontier to tell a
/// head that moved and writes nothing of the chain.
///
/// Public for the caller that opens a transaction of its own over
/// [`stage_publish`]: the shot's keys are this, `content_lock_key` of the
/// document the shot names projects to, and the base's own `version_lock_key`
/// where the base is a member, or the first member's where the base is the
/// bare document — and a caller composing several stagings under one
/// transaction supplies the union of their keys, this among them.
pub fn head_lock_key(doc: &Address) -> LockKey {
    M3State::version_lock_key(&trunk_of(doc))
}

/// Returns a stale edit's two positions — the state it was typed against
/// and the document's current one — or `None` where it may land.
///
/// It is the one check the five in-place edits and the edit share
/// (skep #442), asked of the transaction's working state after the
/// published-target refusal and before the first shape check: one lookup of
/// [`M5State::arranged_at`] for
/// `doc` — the arrangement the edit lands in, which for a declared deposit
/// is the surface the deposit lands in rather than the address named — and
/// one comparison. Refused exactly where the typed position is BELOW the
/// position the document's arrangement last changed at: a typed state at or
/// past that change passes, a document never arranged passes, and the
/// unchecked arm passes without the lookup. Reads no run and makes no read
/// of its own beyond the working state every other check reads, so an edit
/// typed against the current state costs what it cost before the check.
///
/// The two positions come back in the order the refusal names them: the
/// typed state first, then the current one, each op's `ArrangementMoved`
/// carrying them as `as_of` and `current`.
fn arrangement_moved(m5: &M5State, doc: &Address, as_of: AsOf) -> Option<(Seq, Seq)> {
    let AsOf::Typed(typed) = as_of else { return None };
    match m5.arranged_at(doc) {
        Some(current) if typed < current => Some((typed, current)),
        _ => None,
    }
}

#[cfg(test)]
mod tests;
