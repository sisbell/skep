//! THE STRAY PLACES (the link-sets design §5.7, "AND THE STRAY PLACES WITH
//! THEM"): a kept place beside a run of the document's own identity — a run
//! the client re-composed by reference to a correspondence record's `to`
//! where the draft still arranges that record's `from`, left there by an
//! act the editor's mapping does not reach, a second device's undo made
//! before it learned the records, an agent's raw `reinstate` — and the
//! record read that turns the run back into the draft words it stands for,
//! piece by piece, for the re-window to check and replace.
//!
//! [`record_pieces`] is the read: the correspondence records homed in the
//! draft whose stored `to` overlaps the run's I-span — one stab of the TO
//! slot within the draft's home, the twin fence's read turned around — each
//! kept by the stored type slot's exact test, each cut to the overlap and
//! mapped onto the same piece of its `from` (the two slots are of one
//! width, so an offset into one is the offset into the other), the pieces
//! in the run's order. They must tile the run whole: a gap, or no record
//! at all, re-windows nothing and refuses the publication with the entry
//! (`StrayPlaceUnrecorded`). The arithmetic over the slots is
//! [`pieces_of`], a pure function over span pairs, so the tiling rule is
//! held without a world.

use std::cmp::{max, min};

use skep_address::{ordinal, shift, validate, Address, Nat, Span, Tumbler};
use skep_arrangement::Run;

use super::{correspondence_type, is_correspondence_class};
use crate::endset::enc;
use crate::state::{View, TO, TYPE};
use crate::LinkWorld;

/// One piece of a stray run: the draft words a record names (`from`) and
/// the published identity the entry carries for them (`to`), of one width.
///
/// The re-window checks the draft arranges `from` at the piece's offset from
/// the kept place and replaces it there by `to` — the shape of a
/// draft-native entry's pairing piece, read off a record instead of minted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Piece {
    /// The draft-native words, at the draft's own addresses.
    pub from: Run,
    /// The published identity they became, at the edition's addresses.
    pub to: Run,
}

/// Returns the pieces of `run`, a run of the document's own identity, as the
/// correspondence records homed in `draft` name them — in `run`'s order,
/// tiling it whole — or `None` where the records do not cover it.
///
/// One stab of `draft`'s TO slot by `run`'s I-span, on the active view,
/// each hit kept by the stored type slot's exact test
/// ([`is_correspondence_class`]: a link typed the parent `counterpart` is
/// an ordinary link and no record) and read as its two slots; the
/// arithmetic is [`pieces_of`]'s. Costs `O(log n)` plus the hits, the
/// records of `draft` overlapping the run — never the draft's history.
pub(super) fn record_pieces<W: LinkWorld>(world: &W, draft: &Address, run: &Run) -> Option<Vec<Piece>> {
    let links = world.links();
    let ty = enc([correspondence_type()]);
    let span = run.iextent();
    let records: Vec<(&Span, &Span)> = links
        .match_links_in(draft, (TO, [&span]), &[(TYPE, &ty)], View::Active)
        .iter()
        .filter_map(|hit| links.readlink(hit))
        .filter(|record| is_correspondence_class(record.type_slot()))
        .filter_map(|record| Some((one_span(record.from_slot())?, one_span(record.to_slot())?)))
        .collect();
    pieces_of(run, records)
}

/// Returns the one span of a record's slot, or `None` for a slot that is
/// not exactly one span — which no record the publication wrote carries.
fn one_span(slot: &crate::endset::Endset) -> Option<&Span> {
    let mut spans = slot.spans();
    let span = spans.next()?;
    spans.next().is_none().then_some(span)
}

/// Returns the pieces of `run` the record slots `records` — each a `(from,
/// to)` pair of one width — cut it into, in `run`'s order, where they tile it
/// whole; `None` otherwise.
///
/// A record counts where its `to` lies on `run`'s content chain and
/// overlaps `run`'s extent; the overlap is the piece's `to`, and the same
/// offsets into the record's `from` are the piece's `from`. The pieces are
/// ordered by their start within the run and must open at the run's start,
/// each at the previous one's reach, the last reaching the run's reach: a
/// gap, an overlap between two records, a record whose two slots differ in
/// width, or no record at all answers `None`. Pure arithmetic over the
/// spans and the run; reads nothing.
pub(super) fn pieces_of<'s>(run: &Run, records: impl IntoIterator<Item = (&'s Span, &'s Span)>) -> Option<Vec<Piece>> {
    let start = run.i_start().tumbler();
    let lo = ordinal(start).clone();
    let hi = &lo + run.width();
    let mut pieces: Vec<(Nat, Piece)> = Vec::new();
    for (from, to) in records {
        if !same_chain(to.start(), start) {
            continue;
        }
        let (to_lo, to_hi) = (ordinal(to.start()).clone(), ordinal(&to.reach()).clone());
        let from_width = ordinal(&from.reach()) - ordinal(from.start());
        if from_width != &to_hi - &to_lo {
            continue; // not a record's shape: the two slots are of one width
        }
        let (piece_lo, piece_hi) = (max(lo.clone(), to_lo.clone()), min(hi.clone(), to_hi));
        if piece_lo >= piece_hi {
            continue;
        }
        let (offset, width) = (&piece_lo - &to_lo, &piece_hi - &piece_lo);
        let piece = Piece {
            from: Run::new(validate(shift(from.start(), &offset)).ok()?, width.clone()).ok()?,
            to: Run::new(validate(shift(to.start(), &offset)).ok()?, width).ok()?,
        };
        pieces.push((piece_lo, piece));
    }
    pieces.sort_by(|a, b| a.0.cmp(&b.0));
    let mut next = lo;
    for (at, piece) in &pieces {
        if *at != next {
            return None;
        }
        next = at + piece.to.width();
    }
    (next == hi).then(|| pieces.into_iter().map(|(_, piece)| piece).collect())
}

/// Returns whether two tumblers lie on one content chain: one length, and
/// every component but the last equal.
fn same_chain(a: &Tumbler, b: &Tumbler) -> bool {
    a.len() == b.len() && a.iter().zip(b.iter()).take(a.len() - 1).all(|(x, y)| x == y)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(comps: &[u32]) -> Tumbler {
        Tumbler::new(comps.iter().map(|&c| Nat::from(c))).expect("nonempty")
    }

    /// The edition's content element `k`.
    fn pca(k: u32) -> Address {
        validate(t(&[1, 0, 1, 0, 3, 0, 1, k])).expect("valid")
    }

    /// The draft's content element `k`.
    fn ca(k: u32) -> Address {
        validate(t(&[1, 0, 1, 0, 1, 0, 1, k])).expect("valid")
    }

    fn run(start: &Address, width: u32) -> Run {
        Run::new(start.clone(), Nat::from(width)).expect("a run")
    }

    /// A record's two slots: `from` the draft's `width` positions from
    /// `from_k`, `to` the edition's from `to_k`.
    fn record(from_k: u32, to_k: u32, width: u32) -> (Span, Span) {
        (run(&ca(from_k), width).iextent(), run(&pca(to_k), width).iextent())
    }

    fn pieces(run: &Run, records: &[(Span, Span)]) -> Option<Vec<(Run, Run)>> {
        pieces_of(run, records.iter().map(|(f, t)| (f, t))).map(|ps| ps.into_iter().map(|p| (p.from, p.to)).collect())
    }

    /// THE TILING: a run inside one record is one piece at the record's
    /// offset; a run across two adjoining records is two pieces in the
    /// run's order, whichever order the records come in; a run equal to a
    /// record is the record.
    #[test]
    fn a_run_is_cut_into_the_records_pieces_in_its_order() {
        let (bc, de) = (record(2, 1, 2), record(4, 3, 2));
        assert_eq!(pieces(&run(&pca(1), 2), &[bc.clone()]), Some(vec![(run(&ca(2), 2), run(&pca(1), 2))]), "the record whole");
        assert_eq!(pieces(&run(&pca(2), 1), &[bc.clone()]), Some(vec![(run(&ca(3), 1), run(&pca(2), 1))]), "a piece at offset 1");
        let across = Some(vec![(run(&ca(2), 2), run(&pca(1), 2)), (run(&ca(4), 2), run(&pca(3), 2))]);
        assert_eq!(pieces(&run(&pca(1), 4), &[bc.clone(), de.clone()]), across, "across two records");
        assert_eq!(pieces(&run(&pca(1), 4), &[de.clone(), bc.clone()]), across, "in the run's order, not the records'");
        assert_eq!(pieces(&run(&pca(2), 2), &[de, bc]), Some(vec![(run(&ca(3), 1), run(&pca(2), 1)), (run(&ca(4), 1), run(&pca(3), 1))]), "a piece of each");
    }

    /// NOT COVERED WHOLE: no record, a gap between records, a run reaching
    /// past the records, two records overlapping on the run, a record on
    /// another chain, and a record whose slots differ in width each answer
    /// `None`.
    #[test]
    fn a_run_the_records_do_not_tile_whole_has_no_pieces() {
        let (bc, de) = (record(2, 1, 2), record(4, 3, 2));
        let (gapped, past) = (record(5, 4, 1), record(2, 1, 1));
        assert_eq!(pieces(&run(&pca(1), 2), &[]), None, "no record");
        assert_eq!(pieces(&run(&pca(1), 4), &[bc.clone(), gapped]), None, "a gap at pca(3)");
        assert_eq!(pieces(&run(&pca(1), 5), &[bc.clone(), de.clone()]), None, "reaching past the records");
        assert_eq!(pieces(&run(&pca(1), 2), &[bc.clone(), past]), None, "two records over one position");
        let elsewhere = (run(&ca(2), 2).iextent(), run(&validate(t(&[1, 0, 1, 0, 4, 0, 1, 1])).expect("valid"), 2).iextent());
        assert_eq!(pieces(&run(&pca(1), 2), &[elsewhere]), None, "another chain's identity");
        let skewed = (run(&ca(2), 3).iextent(), run(&pca(1), 2).iextent());
        assert_eq!(pieces(&run(&pca(1), 2), &[skewed]), None, "slots of two widths");
    }
}
