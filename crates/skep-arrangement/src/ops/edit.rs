//! EDIT: a list of positional changes to one draft, made in one commit and
//! staged as one record.
//!
//! Each change removes a width of content at a position and puts something
//! in its place: values, minted as INSERT mints them, or runs, placed by
//! identity as REINSTATE places them. All of them land or none does, typed
//! against one state of the draft. It is one composition — the checks, the
//! staging, the record — under the two names the wire sends it by: `edit`,
//! whose changes mint, and `set_arrangement`, whose changes place runs and
//! which a merge's landing into a draft, its undo, a withdrawal and a
//! restore are sent as, the request's head, base and merge beside the
//! changes (`ops/set_arrangement.rs` judges and records those three).

use std::fmt;

use num_traits::{One, Zero};
use skep_address::{Address, Nat};
use skep_content::{ContentStretch, ContentWrite, HasContent, Val};
use skep_kernel::{Seq, Staging, TxnError, WorldState};
use skep_namespace::{HasM3, M3Rec, M3State};

use super::set_arrangement::{base_record, judge, SetMerge, Terms};
use super::{allocate_values_for_placement, arrangement_moved, AsOf, Vstream, MAX_PLACED_RUNS};
use crate::chain::{published_target, trunk_of};
use crate::error::EditError;
use crate::ownership::{gate_write, Caller};
use crate::run::Run;
use crate::run_list::{extend_or_push_run, Splice};
use crate::shot::{run_origin_document, Base, ShotRun};
use crate::state::M5Rec;
use crate::vspace::VPos;
use crate::HasM5;

/// One edit request: the changes to a draft, and a landing's three terms.
///
/// `changes` are positional changes in the coordinates of ONE state of the
/// draft — the state the call is typed against ([`AsOf`]) — ascending and
/// apart: each change's `at` at or past the reach, `at + width`, of the
/// change before it, so no change moves a position another names. Two
/// changes may touch, the second beginning where the first's removal ends,
/// and two placements may name one position, the earlier's content then
/// standing before the later's. An EMPTY list is admitted only beside a
/// `base` or a `merge`: a landing whose words already stand records its
/// base and its marker and changes no position.
///
/// `head` is the head a merge was composed on with its content count AS
/// READ at the compose (the owner's ruling R5 and its precision P1) —
/// present on a merge's landing, absent on an undo and on a plain edit.
/// `base` is the base to record (R6): a landing sends the head pair, an
/// undo the old base, a plain edit none; where present the draft must have
/// a recorded base to move. `merge` is the marker's sides — the sides
/// merged, by address, possibly empty — and, where the request puts a
/// marker back, its position ([`SetMerge`]), present only beside `head`,
/// which is the marker's own head; the marker is recorded where `base` is
/// recorded, and nowhere else (N3: the marker travels with the base). The
/// members a landing composes are the client's statement, as the shot's
/// `base` is: the store checks the head and the base against the draft's
/// chain, as registered members of it, each extent against its member's
/// current count, and nothing against the changes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Edit {
    /// The changes, ascending and apart in the typed state's coordinates.
    pub changes: Vec<Change>,
    /// The head the merge was composed on, at the extent read; `None` on an
    /// undo and a plain edit.
    pub head: Option<Base>,
    /// The base to record, with its extent; `None` moves no record.
    pub base: Option<Base>,
    /// The marker's sides and position, present only beside `head`.
    ///
    /// `None` records no marker and, where `base` is present, clears one.
    pub merge: Option<SetMerge>,
}

impl Edit {
    /// Returns the runs the changes place by identity, in the changes'
    /// order.
    ///
    /// They are what a door ahead of the store consults the origins of
    /// (PUB-6.23): none for a request whose every change mints.
    pub fn runs(&self) -> impl Iterator<Item = &ShotRun> + '_ {
        self.changes.iter().flat_map(|change| match &change.placed {
            Placed::Runs(runs) => runs.as_slice(),
            Placed::Values(_) => &[],
        })
    }

    /// Returns the values the changes mint, in the order they are minted.
    ///
    /// The k-th stands at the first address the call mints plus `k`
    /// ([`Edited::minted`]): none for a request whose every change places
    /// runs.
    pub fn values(&self) -> impl Iterator<Item = &Val> + '_ {
        self.changes.iter().flat_map(|change| match &change.placed {
            Placed::Values(values) => values.as_slice(),
            Placed::Runs(_) => &[],
        })
    }
}

/// One positional change of an [`Edit`]: what it removes, and what it puts
/// where that stood.
///
/// `width` content positions are removed from `at` on, and `placed` is put
/// in their place: a removal alone where `placed` holds nothing, a placement
/// before `at` alone where `width` is zero — the append boundary `n_C + 1`
/// among the positions it admits — and a replacement where it is neither. A
/// change that removes nothing and places nothing is refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Change {
    /// The content position of the first value removed, or the one the
    /// placed content stands before where none is.
    pub at: VPos,
    /// How many content positions are removed from `at` on.
    pub width: Nat,
    /// What is put where the removed positions stood.
    pub placed: Placed,
}

/// What a [`Change`] puts in place of what it removes.
///
/// Two arms, since content enters an arrangement two ways: minted, or
/// placed by identity. The wire's `edit` frame carries the first in every
/// change and its `set_arrangement` frame the second; the op takes either
/// in any change.
#[derive(Clone, PartialEq, Eq)]
pub enum Placed {
    /// Fresh values, minted under the draft's own content chain (J0).
    ///
    /// They are INSERT's values, in its write forms: a one-byte value a
    /// position of text, any other an atom at one position.
    Values(Vec<Val>),
    /// Content I-runs placed by identity, allocating nothing.
    ///
    /// They are REINSTATE's runs, each beside the document it states minted
    /// it ([`ShotRun`]), placed as given whether or not any arrangement
    /// holds them now.
    Runs(Vec<ShotRun>),
}

/// Prints values as their count, and runs as they are.
///
/// A change of text carries a value a byte, so a derive would list one
/// entry a byte; the count is `Vec::len`, which reads no value. No content
/// byte renders either way, M4's `Val` redacting its own.
impl fmt::Debug for Placed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Placed::Values(values) => {
                f.debug_tuple("Values").field(&format_args!("{} values", values.len())).finish()
            }
            Placed::Runs(runs) => f.debug_tuple("Runs").field(runs).finish(),
        }
    }
}

/// What an edit answered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Edited {
    /// The commit position.
    pub at: Seq,
    /// The first address the call minted, `None` where it minted none.
    ///
    /// The values of every change are minted in the request's order under
    /// one content-chain frontier, so a change's first value stands at this
    /// address plus the values of the changes before it.
    pub minted: Option<Address>,
    /// The trunk's current head, where the request named a head that is no
    /// longer it.
    pub head_moved: Option<Address>,
}

impl<W> Vstream<'_, W>
where
    W: WorldState + HasM5 + HasM3 + HasContent, // reads M3 (registration, mints) + M4 (the probe, the writes) + M5
    W::Record: From<M5Rec> + From<M3Rec> + From<ContentWrite> + From<ContentStretch>, // stages M3Rec + ContentWrite/ContentStretch + M5Rec
{
    /// Makes `request`'s changes to `doc`'s content arrangement in one
    /// commit.
    ///
    /// In ONE transaction every change's removed positions go and its
    /// content stands in their place, so the draft holds every change or
    /// what it held, never a state between; and, where the request names a
    /// base to record, the draft's recorded base moves to it in the same
    /// commit (R4), carrying the request's merge as the marker the draft
    /// now carries, or none (R2, N3; `ops/set_arrangement.rs`).
    ///
    /// **One record.** The values of every change are minted first, in the
    /// request's order, by the walk INSERT mints with: a maximal run of
    /// single-byte values is one range mint and one stretch, and it runs on
    /// across the changes, so a call of text is two records however many
    /// changes it holds, each change's bytes a part of the one stretch; an
    /// atom is its own mint and write. Then the whole list of changes is
    /// staged as ONE [`M5Rec::ContentEdit`], which the fold splices into the
    /// draft's run-list in one walk, appending a provenance span for every
    /// run placed (J1★), and which moves the draft's arranged-at position
    /// whatever it holds. The base record, where there is one, follows it.
    /// So a call that mints stages `2 × (maximal single-byte runs + atoms) +
    /// 1` records, one more with a base, and one that mints nothing one or
    /// two. M2 folds each at its push and, where the call staged more than
    /// one, once more at the seal: the draft's run-list is rebuilt by this
    /// record alone, so once or twice a call, never once a change.
    ///
    /// **The published target** (PUB-2.11). An edit is an in-place edit and
    /// carries no deposit form: where the document `doc` projects to
    /// (PUB-2.15) is published it is refused `PublishedTarget`, whatever it
    /// places. The one insert a published document admits stays INSERT's.
    ///
    /// **The runs' origins.** A run of any registered document's I-space
    /// may be placed, under the precondition
    /// [`reinstate`](Vstream::reinstate) states on its origins'
    /// readability: M5 takes no consult, and M10's door discharges it per
    /// distinct origin, the destination's own excepted.
    ///
    /// **Cost, and who owns it.** Under M2's applier lock the call reads
    /// the draft's content count once, off its list's root with no run
    /// read, and judges every change against that count and the reach of
    /// the change before it by arithmetic. Each run placed by identity is
    /// probed at every address, as REINSTATE probes. `steps` is charged one
    /// for every change judged and one for every run placed: the call's own
    /// walks read no run of the draft's list. The fold's splice, twice a
    /// call, reads the list at its changes' cuts alone
    /// (`RunList::spliced`), so what the call holds the lock for follows
    /// its changes and not the draft's run count. This op admits any number
    /// of
    /// changes and any number of values, as INSERT admits any values: M2's
    /// `MAX_TXN_BYTES` refuses the transaction past its own ceiling, after
    /// the staging, so a route that wants the refusal ahead of that work
    /// owes its own caps — skep-core's codec sets them on the wire route —
    /// and [`MAX_PLACED_RUNS`] binds the runs one call places, measured as
    /// they are accumulated.
    ///
    /// **Locks.** `content_lock_key(doc)` alone: the mints advance `doc`'s
    /// own content chain, no origin is locked, and the chain's head key is
    /// not taken — the head is read for the tell, never written.
    ///
    /// # Errors
    ///
    /// Each refusal comes as `TxnError::Rejected`, in this order (which
    /// error wins), every one but the last two ahead of the first record
    /// staged: `DocNotRegistered` → `NotOwner` → `PublishedTarget` →
    /// `ArrangementMoved` (the destination's own four, as the in-place
    /// edits judge them) → the landing's terms, in the order
    /// `ops/set_arrangement.rs` states: the head's `SourceNotRegistered`,
    /// `BaseNotInChain` and `BaseExtentTooLarge`, `ForkBaseMoved`, then the
    /// base's `NoBaseToRecord`, `SourceNotRegistered`, `BaseNotInChain` and
    /// `BaseExtentTooLarge`, then `MarkerNotRestorable` → `EmptyResult`
    /// naming no change (the request holds no change and names neither a
    /// base nor a merge) → per change, in the order given, the first
    /// defective change deciding and each verdict naming it:
    /// `NotContentSubspace` → `NotAscending` (its `at` below the reach of
    /// the change before it) → where it removes, `NotArranged`
    /// (`at.ordinal ∉ [1, n_C]`) → `OutOfBounds` (`at + width − 1 > n_C`);
    /// where it removes nothing, `OutOfBounds` (`at.ordinal ∉ [1, n_C + 1]`)
    /// → `EmptyResult` (it places nothing either) → per change and per run
    /// it places by identity, in the order given: `BadRun` →
    /// `SourceNotRegistered` → `DanglingSource` → `TooManyRuns`
    /// ([`MAX_PLACED_RUNS`], counted over the call's placed runs, a change's
    /// minted values one run) → then, per maximal run of single-byte values
    /// or atom across the changes in order, `Mint` → `Content`, neither one
    /// an honest request can earn on a correct store, as INSERT states. The
    /// kernel's own failures — `OverBudget`, `Unencodable`, `Durability`,
    /// `Poisoned` — come back as `transact` returns them.
    pub fn edit(
        &self,
        caller: Caller,
        doc: &Address,
        request: Edit,
        as_of: AsOf,
    ) -> Result<Edited, TxnError<EditError>> {
        self.edit_stepped(caller, doc, request, as_of, &mut |_| {})
    }

    /// Makes [`edit`](Vstream::edit), its walks counted.
    ///
    /// `steps` is charged as `edit` states. It is the op's one body: the
    /// public form hands it a count that compiles away.
    ///
    /// # Errors
    ///
    /// `edit`'s.
    pub(crate) fn edit_stepped(
        &self,
        caller: Caller,
        doc: &Address,
        request: Edit,
        as_of: AsOf,
        steps: &mut impl FnMut(u64),
    ) -> Result<Edited, TxnError<EditError>> {
        let key = M3State::content_lock_key(doc);
        self.kernel
            .transact(&[key], |stg| stage_edit(stg, caller, doc, request, as_of, steps))
            .map(|((minted, head_moved), at)| Edited { at, minted, head_moved })
    }
}

/// Stages `edit`'s body into the transaction.
///
/// It is [`Vstream::edit`]'s closure: every check in the order the op
/// states, off the transaction's working world and ahead of the first
/// record staged, then the mints, the one [`M5Rec::ContentEdit`] and the
/// base record. Returns the first address minted, where the call minted
/// any, and the trunk's current head where the request's head is not it.
///
/// # Errors
///
/// `edit`'s refusals, in the order it states.
fn stage_edit<W>(
    stg: &mut Staging<W>,
    caller: Caller,
    doc: &Address,
    request: Edit,
    as_of: AsOf,
    steps: &mut impl FnMut(u64),
) -> Result<(Option<Address>, Option<Address>), EditError>
where
    W: WorldState + HasM5 + HasM3 + HasContent,
    W::Record: From<M5Rec> + From<M3Rec> + From<ContentWrite> + From<ContentStretch>,
{
    let Edit { changes, head, base, merge } = request;
    let terms = Terms { head: head.as_ref(), base: base.as_ref(), merge: merge.as_ref() };
    // Every judgment off one reading of the working world, ahead of the
    // first record staged: the gates, the terms, each change's shape and
    // each run placed by identity.
    let (judged, placed) = {
        let world = stg.working();
        let (m3, m5) = (world.m3(), world.m5());
        gate_write(m3, caller, doc, EditError::DocNotRegistered, EditError::NotOwner)?;
        // PUB-6.36 slot 5: the in-place advance refusal (PUB-2.11).
        if published_target(m3, doc) {
            return Err(EditError::PublishedTarget);
        }
        // The stale-edit refusal (skep #442), ahead of every shape check.
        if let Some((as_of, current)) = arrangement_moved(m5, doc, as_of) {
            return Err(EditError::ArrangementMoved { as_of, current });
        }
        let judged = judge(m3, m5, doc, terms)?;
        if changes.is_empty() && base.is_none() && merge.is_none() {
            return Err(EditError::EmptyResult { change: None });
        }
        // n_C, read once a call off the list's root: every change is judged
        // against it and the reach of the change before it, by arithmetic.
        let count = m5.content_count(doc);
        judge_shapes(&changes, &count, steps)?;
        // The runs placed by identity, each judged as REINSTATE judges it
        // and accumulated within its change; a change that mints holds one
        // run of the placement, counted here and carved below.
        let content = world.content();
        let mut placed: Vec<Option<Vec<Run>>> = Vec::with_capacity(changes.len());
        let mut runs_placed = 0usize;
        for (k, change) in changes.iter().enumerate() {
            let runs = match &change.placed {
                Placed::Values(values) => {
                    runs_placed += usize::from(!values.is_empty());
                    None
                }
                Placed::Runs(runs) => {
                    let mut accumulated: Vec<Run> = Vec::new();
                    for ShotRun { origin, run } in runs {
                        steps(1);
                        // The shape, settled from the run's own start and
                        // checked against the client's statement: address
                        // arithmetic, disclosing nothing.
                        let origin_doc =
                            run_origin_document(run).ok_or(EditError::BadRun { change: k })?;
                        if origin_doc != trunk_of(origin) {
                            return Err(EditError::BadRun { change: k });
                        }
                        if !m3.is_registered_document(&origin_doc) {
                            return Err(EditError::SourceNotRegistered { change: Some(k) });
                        }
                        // Existence (S3★) at every address: the run is the
                        // client's I-extent and no arrangement's.
                        if !content.pieces(run.i_start().tumbler(), run.width()).covered() {
                            return Err(EditError::DanglingSource { change: k });
                        }
                        extend_or_push_run(&mut accumulated, run.clone());
                        if runs_placed + accumulated.len() > MAX_PLACED_RUNS {
                            return Err(EditError::TooManyRuns);
                        }
                    }
                    runs_placed += accumulated.len();
                    Some(accumulated)
                }
            };
            if runs_placed > MAX_PLACED_RUNS {
                return Err(EditError::TooManyRuns);
            }
            placed.push(runs);
        }
        (judged, placed)
    };
    let head_moved = judged.head_moved.clone();
    // The mints, every change's values in the request's order under the one
    // frontier: the walk INSERT mints with, a run of text running on across
    // the changes. What comes back is the run the values stand at, which
    // each minting change takes its own part of, in order.
    let (mut sites, mut widths, mut values) = (Vec::with_capacity(changes.len()), Vec::new(), Vec::new());
    for (change, runs) in changes.into_iter().zip(placed) {
        let Change { at, width, placed } = change;
        let runs = match (placed, runs) {
            (Placed::Values(own), _) => {
                widths.push(Nat::from(own.len()));
                values.extend(own);
                None
            }
            (Placed::Runs(_), runs) => runs,
        };
        sites.push((at.ordinal, width, runs));
    }
    let mut minted: Vec<Run> = Vec::new();
    allocate_values_for_placement::<_, EditError>(stg, doc, values, &mut minted)?;
    let first = minted.first().map(|run| run.i_start().clone());
    let mut minted = Minted::of(minted);
    let mut widths = widths.into_iter();
    let changes: Vec<Splice> = sites
        .into_iter()
        .map(|(at, width, runs)| {
            let runs = runs.unwrap_or_else(|| {
                let own = minted.take(&widths.next().unwrap_or_default());
                steps(own.len() as u64);
                own
            });
            Splice { at, width, runs }
        })
        .collect();
    stg.push(M5Rec::ContentEdit { doc: doc.clone(), changes }.into());
    // The record, where a base is to be recorded: the base told, the source
    // kept, and the marker put back as it stood, or the request's merge
    // beside its head to be stamped, or none (N3; skep #870).
    if let Some(record) = base_record(doc, terms, judged) {
        stg.push(record.into());
    }
    Ok((first, head_moved))
}

/// Judges every change's shape against `count`, the draft's content count.
///
/// One pass over the changes, each against the count and the reach of the
/// change before it, by arithmetic alone: no run is read. `steps` is charged
/// one for each change judged.
///
/// # Errors
///
/// For the first defective change, naming it, in this order:
/// `NotContentSubspace`; `NotAscending` where its `at` is below the reach of
/// the change before it; where it removes, `NotArranged` (`at ∉ [1, n_C]`)
/// then `OutOfBounds` (`at + width − 1 > n_C`); where it removes nothing,
/// `OutOfBounds` (`at ∉ [1, n_C + 1]`) then `EmptyResult` where it places
/// nothing either.
fn judge_shapes(
    changes: &[Change],
    count: &Nat,
    steps: &mut impl FnMut(u64),
) -> Result<(), EditError> {
    let boundary = count + Nat::one();
    // The reach of the change before: none yet, so the first is judged by
    // its bounds alone.
    let mut reach = Nat::zero();
    for (k, change) in changes.iter().enumerate() {
        steps(1);
        let Change { at, width, placed } = change;
        if !at.is_content() {
            return Err(EditError::NotContentSubspace { change: k });
        }
        if at.ordinal < reach {
            return Err(EditError::NotAscending { change: k });
        }
        let end = &at.ordinal + width;
        if width.is_zero() {
            if at.ordinal.is_zero() || at.ordinal > boundary {
                return Err(EditError::OutOfBounds { change: k });
            }
            let nothing = match placed {
                Placed::Values(values) => values.is_empty(),
                Placed::Runs(runs) => runs.is_empty(),
            };
            if nothing {
                return Err(EditError::EmptyResult { change: Some(k) });
            }
        } else {
            if at.ordinal.is_zero() || at.ordinal > *count {
                return Err(EditError::NotArranged { change: k });
            }
            if end > boundary {
                return Err(EditError::OutOfBounds { change: k });
            }
        }
        reach = end;
    }
    Ok(())
}

/// The run of addresses a call minted, taken a change's part at a time.
///
/// The call's values are minted in one walk, in the request's order, and
/// stand at consecutive addresses: one run where M3's frontier hands them
/// back adjacent, several where it does not (`allocate_for_placement`
/// states why the accumulator is asked). Each minting change takes the next
/// `width` positions of them, in order.
struct Minted {
    /// The minted runs, in mint order.
    runs: Vec<Run>,
    /// The index of the run the next part is taken from.
    run: usize,
    /// How many positions of that run are taken already.
    taken: Nat,
}

impl Minted {
    /// Returns the minted runs with nothing of them taken.
    fn of(runs: Vec<Run>) -> Minted {
        Minted { runs, run: 0, taken: Nat::zero() }
    }

    /// Takes the next `width` positions, as the runs that hold them.
    ///
    /// One run where they lie in one minted run, which is every change of a
    /// call the frontier minted adjacent; nothing for a width of zero. A
    /// width past what is left takes what is left: the widths are the
    /// values' own counts, so it is none on the op's path.
    fn take(&mut self, width: &Nat) -> Vec<Run> {
        let (mut own, mut owed) = (Vec::new(), width.clone());
        while !owed.is_zero() {
            let Some(run) = self.runs.get(self.run) else { break };
            let left = run.width() - &self.taken;
            let part = std::cmp::min(owed.clone(), left.clone());
            // At least one position: `owed` is not zero, and neither is
            // `left`, a run wholly taken being stepped past below.
            let piece = Run { i_start: run.addr_at(&self.taken), width: part.clone() };
            extend_or_push_run(&mut own, piece);
            owed -= &part;
            if part == left {
                self.run += 1;
                self.taken = Nat::zero();
            } else {
                self.taken += part;
            }
        }
        own
    }
}

#[cfg(test)]
mod tests;
