//! SUBSTITUTE: the identity-checked substitution — at each place of a list,
//! the runs a draft arranges replaced by the runs given for them, checked
//! on one cursor of the draft's run-list and staged as one record.
//!
//! It is a staging body and no operation: a composite stages it under its
//! own transaction. The publication stages it once for each draft it
//! re-windows at its kept places (the link-sets design §5.7 (viii)): the
//! draft's own words at each place replaced by the published identity they
//! became.

use std::collections::BTreeMap;

use skep_address::{Address, Nat};
use skep_content::HasContent;
use skep_kernel::{Staging, WorldState};
use skep_namespace::HasM3;

use crate::chain::published_target;
use crate::error::SubstituteError;
use crate::ownership::{gate_write, Caller};
use crate::run::Run;
use crate::run_list::Splice;
use crate::shot::run_origin_document;
use crate::state::M5Rec;
use crate::vspace::VPos;
use crate::HasM5;

/// One place of a substitution: where it opens, and its pieces.
///
/// `pieces` are the place's runs in V-order, each a run the draft must
/// arrange there beside the run that takes its place ([`Replacement`]): the
/// place is the positions from `at` on, as many as the pieces' `from` runs
/// are wide together. `None` is an entry its caller found no pieces for,
/// which the body refuses [`Unrecorded`](SubstituteError::Unrecorded) in
/// its turn.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Substitution {
    /// The entry's name in its caller's own list: what a refusal of the
    /// entry carries, and nothing the body reads.
    pub index: usize,
    /// The position the place opens at.
    pub at: VPos,
    /// The place's pieces, in V-order; `None` where the caller holds none.
    pub pieces: Option<Vec<Replacement>>,
}

/// One piece of a [`Substitution`]: a run the draft must arrange, and the
/// run put where it stood.
///
/// The publication's pieces pair a run with one of its own width — a
/// draft's words and the published identity they became — so no position of
/// the draft moves. The body does not ask it: a `to` wider or narrower than
/// its `from` moves the positions after its place by the difference, the
/// places being positions of the draft as it stood before any of them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Replacement {
    /// The run the draft must arrange at the piece's offset into the place.
    pub from: Run,
    /// The run placed there by identity in its stead.
    pub to: Run,
}

/// Stages the substitution of `entries` into `doc`'s content arrangement:
/// every place checked by identity, then every place's runs replaced, in
/// one record.
///
/// For each entry the draft must arrange exactly its pieces' `from` runs,
/// in their order and nothing else, over the positions its place opens at —
/// by membership at the place alone, so a draft that arranges the identity
/// twice is changed at the named place and left standing at the other, and
/// whatever the run boundaries are on either side
/// (`RunList::arranges_each`). Where every entry holds, each place's
/// positions are replaced by its pieces' `to` runs, placed by identity and
/// allocating nothing, as REINSTATE places a run.
///
/// **The gate first.** `doc`'s registration, its owner and the
/// published-target refusal (PUB-2.11: a substitution is an in-place edit
/// and has no deposit form) are judged ahead of every entry, so a published
/// `doc` answers `PublishedTarget` whatever its entries hold.
///
/// **Which entry answers.** Each entry's verdict is the first check it
/// fails, in the order [`SubstituteError`] states them, and the body
/// answers the verdict of the EARLIEST entry in the order given that fails
/// one — never the first failing place the check meets, which is the lowest
/// by position. An entry whose place overlaps the place of an entry before
/// it in that order is `Moved`: were the places replaced one at a time, the
/// later would find the earlier's runs standing where it expects its own.
/// That holds for every entry whose `from` runs are none of an earlier
/// overlapping entry's `to` runs — which is every piece the publication
/// hands in but one: where a draft's words were published into a document
/// that was then named as a draft and published itself, an entry by the
/// first record and a later one by the second, at one place, would chain if
/// made one at a time, and are refused here.
///
/// **One cursor.** The entries are ordered by place and each place is
/// compared on one cursor of the draft's run-list, which descends to the
/// place and never moves back (`RunList::arranges_each`): no run of the
/// draft left of the first place, between two places or past the last is
/// read.
///
/// **One record.** The places are staged as ONE [`M5Rec::ContentEdit`], a
/// change a place, its runs the pieces' `to` runs — ONE RUN A PIECE, never
/// coalesced here. The fold splices every change in one pass, coalescing
/// the run-list alone, and appends a provenance span for each run the
/// record carries (J1★), so R↾doc gains a span a piece whether or not two
/// pieces' runs are I-adjacent, and the draft's arranged-at position moves
/// once (MOVED★). The spans are appended in the record's order, which is by
/// place and not the order the entries are given in; R's reads answer alike
/// under either ([`deletions`](crate::M5State::deletions) normalizes what
/// it reads, [`docs_ever_containing`](crate::M5State::docs_ever_containing)
/// asks whether any span overlaps,
/// [`recorded_span_count`](crate::M5State::recorded_span_count) counts). An
/// empty `entries` stages nothing.
///
/// **Cost, and who owns it.** Under M2's applier lock: `steps` is charged
/// one for every entry judged, then the check's own — one for every place,
/// every piece, every node of the list's tree it opens and every run of the
/// list it reads — then one for every piece probed: at most
/// `#entries × (2 × (height + 1) + 21) + 4 × #pieces`, `height` the
/// height of the draft's tree, whatever the draft holds. The draft's run
/// count does not enter it. Ordering the entries by place is
/// `O(#entries log #entries)` comparisons of positions, reading no run.
/// Each `to` run is probed at every address, as REINSTATE probes. The
/// record's fold reads the list at its places' cuts alone, at the push, and
/// M2 folds it again at the seal where the transaction staged more than
/// this record. The body counts nothing against
/// [`MAX_PLACED_RUNS`](crate::MAX_PLACED_RUNS): the pieces are its
/// caller's, built before the call, and M2's `MAX_TXN_BYTES` refuses the
/// transaction past its own ceiling; a route that wants the refusal ahead
/// of the work owes its own bound, as the publication's price is.
///
/// **Precondition.** The caller has established that the principal it
/// writes for may read the document each `to` run was minted under, as
/// [`reinstate`](crate::Vstream::reinstate) states it: M5 takes no consult.
///
/// It reads the transaction's working world, `stg.working()`, so a `to`
/// run minted earlier in the same staging is covered and the arrangement is
/// as the records staged so far left it. It opens no transaction and takes
/// no lock: the key is the caller's, `content_lock_key(doc)`.
///
/// # Errors
///
/// As the bare [`SubstituteError`] the caller's transaction answers as
/// `TxnError::Rejected`, every one ahead of the record, so an `Err` stages
/// nothing: `DocNotRegistered` → `NotOwner` → `PublishedTarget`; then the
/// verdict of the earliest entry in the order given that fails a check —
/// `NotContentSubspace` → `Unrecorded` → `Moved` (no piece, an overlap with
/// an earlier entry's place, or the draft not arranging the `from` runs
/// there) → per `to` run in order `BadRun` → `SourceNotRegistered` →
/// `DanglingSource`.
///
/// [`M5State::iter_resolve`]: crate::M5State::iter_resolve
pub fn stage_substitute<W>(
    stg: &mut Staging<W>,
    caller: Caller,
    doc: &Address,
    entries: &[Substitution],
    steps: &mut impl FnMut(u64),
) -> Result<(), SubstituteError>
where
    W: WorldState + HasM5 + HasM3 + HasContent,
    W::Record: From<M5Rec>,
{
    let changes: Vec<Splice> = {
        let world = stg.working();
        let (m3, m5, content) = (world.m3(), world.m5(), world.content());
        gate_write(m3, caller, doc, SubstituteError::DocNotRegistered, SubstituteError::NotOwner)?;
        // PUB-6.36 slot 5: the in-place advance refusal (PUB-2.11), ahead
        // of every entry.
        if published_target(m3, doc) {
            return Err(SubstituteError::PublishedTarget);
        }
        // The entries in the order given, up to the first that fails a
        // check no run is read for: its place outside the content subspace,
        // no pieces, or a place overlapping an earlier entry's. The ones
        // before it are kept by the ordinal each opens at — its reach and
        // its pieces beside it — so they are apart, and ordered by place.
        let mut refused: Option<SubstituteError> = None;
        let mut kept: BTreeMap<&Nat, (Nat, &[Replacement])> = BTreeMap::new();
        for entry in entries {
            steps(1);
            let index = entry.index;
            if !entry.at.is_content() {
                refused = Some(SubstituteError::NotContentSubspace { index });
                break;
            }
            let Some(pieces) = entry.pieces.as_deref() else {
                refused = Some(SubstituteError::Unrecorded { index });
                break;
            };
            let at = &entry.at.ordinal;
            let reach = at + pieces.iter().map(|piece| piece.from.width()).sum::<Nat>();
            // Apart from every entry kept so far: the one opening at or
            // before it ends at or before it, and the next opens at or past
            // its reach. No piece is no place.
            let apart = !pieces.is_empty()
                && kept.range::<Nat, _>(..=at).next_back().is_none_or(|(_, (before, _))| before <= at)
                && kept.range::<Nat, _>(at..).next().is_none_or(|(after, _)| **after >= reach);
            if !apart {
                refused = Some(SubstituteError::Moved { index });
                break;
            }
            kept.insert(at, (reach, pieces));
        }
        // The check by identity, every kept place on one cursor of the list.
        let held = m5.content_list(doc).arranges_each(
            kept.iter().map(|(at, (_, pieces))| (*at, pieces.iter().map(|piece| &piece.from))),
            steps,
        );
        let moved: Vec<&Nat> =
            kept.keys().zip(&held).filter(|(_, held)| !**held).map(|(at, _)| *at).collect();
        // The entries in the order given again, up to the first the check
        // found moved: each run put in judged as REINSTATE judges a run.
        for entry in &entries[..kept.len()] {
            let index = entry.index;
            if moved.binary_search(&&entry.at.ordinal).is_ok() {
                return Err(SubstituteError::Moved { index });
            }
            for piece in entry.pieces.iter().flatten() {
                steps(1);
                let origin =
                    run_origin_document(&piece.to).ok_or(SubstituteError::BadRun { index })?;
                if !m3.is_registered_document(&origin) {
                    return Err(SubstituteError::SourceNotRegistered { index });
                }
                // Existence (S3★) at every address, as REINSTATE probes.
                if !content.pieces(piece.to.i_start().tumbler(), piece.to.width()).covered() {
                    return Err(SubstituteError::DanglingSource { index });
                }
            }
        }
        if let Some(refused) = refused {
            return Err(refused);
        }
        // One change a place, ascending and apart; one run a piece.
        kept.into_iter()
            .map(|(at, (reach, pieces))| Splice {
                at: at.clone(),
                width: &reach - at,
                runs: pieces.iter().map(|piece| piece.to.clone()).collect(),
            })
            .collect()
    };
    if !changes.is_empty() {
        stg.push(M5Rec::ContentEdit { doc: doc.clone(), changes }.into());
    }
    Ok(())
}

#[cfg(test)]
mod tests;
