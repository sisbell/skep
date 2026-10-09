//! The UNION of a run set's I-extents ([`RunUnion`]): every address some run
//! of the set holds, merged within each content chain in TUMBLER order, so
//! that whether the set holds every address of a run is one search. The
//! run-list (`runlist.rs`) orders runs by V-position; the two share no private
//! item, and this module's privacy is what makes [`RunUnion::of`] the union's
//! one constructor.

use skep_address::{ordinal, Tumbler};

use crate::run::Run;

/// Do `a` and `b` lie in ONE content chain — their starts equal in every
/// component but the ordinal, the `doc·0·subspace` both share (each a full
/// element position, [`Run::admits_start`](crate::Run::admits_start))? Two
/// runs share an address only within one content chain. And among run starts
/// one content chain's positions lie together in the tumbler order: a start
/// strictly between two positions of a content chain either is of that
/// content chain or extends its `doc·0·subspace` by two components or more —
/// an element field of three or more, which no run admits — while a start
/// differing earlier compares alike with every position of it. What
/// [`RunUnion`] merges within and searches by.
fn same_content_chain(a: &Run, b: &Run) -> bool {
    let (s, t) = (a.i_start.tumbler(), b.i_start.tumbler());
    s.len() == t.len()
        && s.iter()
            .zip(t.iter())
            .take(s.len() - 1)
            .all(|(x, y)| x == y)
}

/// The UNION of a run set's I-extents — every address some run of the set
/// holds — MERGED: within each content chain, runs that overlap or abut are
/// joined into one piece, so the pieces are disjoint, hold each address once,
/// lie in tumbler order, and no two of one content chain abut. BUILT ONLY by
/// [`RunUnion::of`], which is what lets [`covers`](RunUnion::covers) answer
/// by a binary search: the order it searches is the type's invariant, not a
/// promise its caller keeps.
///
/// BORROWED: a piece names the run that opens it and the run that reaches
/// furthest, two pointers apiece, so the union of a document's runs costs a
/// pointer per run beside the run-list it is asked of rather than a clone of
/// it — whose size stored state, and not the asking request, sets.
///
/// The publish shot asks it twice. Its existence walk (S3★) probes the union
/// of the supplied runs, each address once, so a request naming one stored
/// I-extent many times pays for it once. Its carried-run test (PUB-6.24)
/// merges the base's runs once per admission and asks each supplied run of
/// the union by one search, so a request of many carried runs pays the base's
/// run count once and not once a run.
pub(crate) struct RunUnion<'r>(Vec<UnionPiece<'r>>);

/// One piece of a [`RunUnion`]: the addresses `[first.i_start,
/// furthest.reach())` of one content chain — `first` the run that opens the
/// piece, `furthest` the one of its runs reaching furthest, both of that
/// content chain, so the piece is one contiguous ordinal range. Named fields,
/// both being runs: a positional pair would put them within swapping distance.
struct UnionPiece<'r> {
    first: &'r Run,
    furthest: &'r Run,
}

impl<'r> RunUnion<'r> {
    /// The union of `runs`' I-extents: sorted by start, then each run joined
    /// to the piece before it when it is of that piece's content chain and
    /// opens at or before the piece's reach — overlapping or abutting it — and
    /// opening a piece of its own otherwise. Sorting is what lets one pass
    /// join: one content chain's runs lie together among the starts
    /// ([`same_content_chain`]) and come in ordinal order within it, so a run
    /// joining no piece before it opens past every address that piece holds.
    /// `O(n log n)` comparisons for `n` runs, and a pointer per run.
    pub(crate) fn of(runs: impl IntoIterator<Item = &'r Run>) -> RunUnion<'r> {
        let mut sorted: Vec<&'r Run> = runs.into_iter().collect();
        sorted.sort_unstable_by(|a, b| a.i_start.tumbler().cmp(b.i_start.tumbler()));
        let mut pieces: Vec<UnionPiece<'r>> = Vec::with_capacity(sorted.len());
        // The last piece's reach, kept beside it rather than derived again for
        // every run asked whether it joins.
        let mut last_reach: Option<Tumbler> = None;
        for run in sorted {
            let run_reach = run.reach();
            if let (Some(piece), Some(piece_reach)) = (pieces.last_mut(), last_reach.as_mut()) {
                if same_content_chain(piece.first, run) && *run.i_start.tumbler() <= *piece_reach {
                    if run_reach > *piece_reach {
                        piece.furthest = run;
                        *piece_reach = run_reach;
                    }
                    continue;
                }
            }
            pieces.push(UnionPiece {
                first: run,
                furthest: run,
            });
            last_reach = Some(run_reach);
        }
        RunUnion(pieces)
    }

    /// Does the union hold EVERY address of `run`? One binary search, the
    /// pieces being sorted by start and disjoint: the only piece that can hold
    /// `run`'s start is the last one opening at or before it, which is of
    /// `run`'s content chain whenever any piece of it opens there
    /// ([`same_content_chain`]); and no two pieces of a content chain abut, so
    /// `run` is held whole exactly when that piece is of its content chain and
    /// reaches as far.
    ///
    /// A piece of ANOTHER content chain holds no address of `run`. Within one
    /// length, content chains are disjoint by their prefixes. Across lengths,
    /// a shorter address lies outside a longer piece's I-extent — it is
    /// compared within the longer's leading components, where both ends of
    /// that extent agree, so it falls below both or above both — and a longer
    /// address inside a shorter piece's would follow that piece's subspace
    /// with two components or more, an element field no run admits. So neither
    /// the run's width nor any piece's is searched: `O(log #pieces)`
    /// comparisons and one reach, however wide the run. Transclusion
    /// multiplicity costs nothing — the union holds a doubly arranged address
    /// once.
    pub(crate) fn covers(&self, run: &Run) -> bool {
        let at = self
            .0
            .partition_point(|piece| piece.first.i_start.tumbler() <= run.i_start.tumbler());
        self.0[..at].last().is_some_and(|piece| {
            same_content_chain(piece.first, run) && run.reach() <= piece.reach()
        })
    }

    /// The union's pieces as owned runs, in tumbler order — every address the
    /// set holds, in exactly one of them. What the shot's existence walk
    /// probes.
    pub(crate) fn runs(&self) -> impl Iterator<Item = Run> + '_ {
        self.0.iter().map(UnionPiece::to_run)
    }
}

impl UnionPiece<'_> {
    /// One I-step past the piece's last address: its furthest run's reach.
    fn reach(&self) -> Tumbler {
        self.furthest.reach()
    }

    /// The piece as an owned run — `first`'s start, widened to the piece's
    /// reach. A PROPAGATING mint, as
    /// [`Run::admits_start`](crate::Run::admits_start) lists them: the start
    /// is a run's own, so a full element position; and the width is the
    /// ordinal distance to a reach of the same content chain at or past
    /// `first`'s own, so at least `first`'s width — positive, and the
    /// subtraction cannot underflow.
    fn to_run(&self) -> Run {
        Run {
            i_start: self.first.i_start.clone(),
            width: ordinal(&self.reach()) - ordinal(self.first.i_start.tumbler()),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use skep_address::Address;

    use super::*;
    use crate::testutil::{ca, pca, run, vca};

    #[test]
    fn a_run_union_denotes_exactly_the_runs_addresses_each_once_in_tumbler_order() {
        // S3★/PUB-6.24: the union a run set's I-extents name, merged within each
        // content chain — EXACTLY the runs' addresses, none dropped, which the
        // shot's existence walk and its re-insert's `.expect` stand on, and each
        // in one merged run, which is what lets the walk pay a stored position
        // once however often a request names it. Repeats, nesting, overlap,
        // abutment and a gap in one content chain; a second content chain of
        // the SAME length, kept apart by its prefix alone; a third of another
        // length — listed out of order, so the sort is what brings each content
        // chain's runs together.
        let family = vec![
            run(&ca(3), 2),
            run(&ca(1), 2),
            run(&ca(3), 2),
            run(&ca(2), 5),
            run(&ca(9), 1),
            run(&ca(8), 1),
            run(&pca(3), 1),
            run(&pca(1), 1),
            run(&vca(1), 3),
            run(&vca(2), 1),
        ];
        let union = RunUnion::of(&family);
        let merged: Vec<Run> = union.runs().collect();
        assert_eq!(
            merged,
            vec![
                run(&ca(1), 6),
                run(&ca(8), 2),
                run(&vca(1), 3),
                run(&pca(1), 1),
                run(&pca(3), 1)
            ]
        );
        let named: BTreeSet<Address> = family.iter().flat_map(Run::addrs).collect();
        let denoted: Vec<Address> = merged.iter().flat_map(Run::addrs).collect();
        assert_eq!(denoted.len(), named.len(), "no address in two merged runs");
        assert_eq!(denoted.into_iter().collect::<BTreeSet<_>>(), named);
        // And whole-run membership is its search, against the address-by-address
        // oracle, from every start and width across the three content chains
        // and their gaps — the same-length content chains being where the
        // prefix, and not the length, has to keep the search apart.
        let mut checked = 0usize;
        for start in (1..=10u32).flat_map(|k| [ca(k), pca(k), vca(k)]) {
            for width in 1..=7u32 {
                let probe = run(&start, width);
                let held = probe.addrs().all(|address| named.contains(&address));
                assert_eq!(union.covers(&probe), held, "{start:?} × {width}");
                checked += 1;
            }
        }
        assert_eq!(checked, 210);
        assert_eq!(
            RunUnion::of(std::iter::empty::<&Run>()).runs().count(),
            0,
            "an empty union"
        );
        assert!(!RunUnion::of(std::iter::empty::<&Run>()).covers(&run(&ca(1), 1)));
    }
}
