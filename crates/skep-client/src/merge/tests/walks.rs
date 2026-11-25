//! The landing's replaced stretches, held to their answers and their cost.
//!
//! `replaced_stretches` answers from a union of the merged list's I-extents
//! per origin, and this suite holds it to two things.
//!
//! Its answers are a scan's: [`replaced_stretches_by_scan`] reads every run
//! of the merged list for each held run, and the two are compared on the
//! landing suite's cases, on each way the merged list's runs can lie over a
//! held run, on merges of many small changes and on generated lists.
//!
//! Its work is bounded by count, never by a clock. The walk charges one
//! step for every run it reads, every comparison of a sort or a search and
//! every piece it walks; [`within`] fails the moment the count passes a
//! budget; and the budget is [`bound`], at 65,536 runs a side, where the
//! scan reads 4.3 × 10⁹ pairs of runs. So a walk that reads the merged list
//! through for each held run, or all of one origin's runs, fails in the
//! first few hundred held runs.

use super::*;
use crate::merge::land::replaced_stretches;

/// The runs a side at the count the suite bounds the walk at.
const RUNS: usize = 1 << 16;

/// Returns the steps a walk may take: the suite's bound.
///
/// For lists of `n` and `m` runs and `out` stretches answered it is
/// `8 · (n + m) · ⌈log₂(n + m + 2)⌉ + out`.
fn bound(n: usize, m: usize, out: usize) -> u64 {
    let runs = (n + m) as u64;
    8 * runs * u64::from((runs + 2).next_power_of_two().trailing_zeros()) + out as u64
}

/// Returns a count of steps that fails the moment it passes `budget`.
///
/// The steps counted are kept in `count`.
fn within(budget: u64, count: &mut u64) -> impl FnMut(u64) + '_ {
    move |steps| {
        *count += steps;
        assert!(*count <= budget, "the walk passed its budget of {budget} steps");
    }
}

/// The same answer by a scan: for each held run, every run of `m` read.
///
/// It is what `replaced_stretches` is held equal to, plain enough to be
/// read as right, and it costs the product of the two lists.
fn replaced_stretches_by_scan(held: &[Run], m: &[Run]) -> Vec<Replaced> {
    let mut out: Vec<Replaced> = Vec::new();
    let mut ordinal = 1u64;
    for run in held {
        let mut carried: Vec<(u64, u64)> = m
            .iter()
            .filter(|r| r.origin == run.origin)
            .map(|r| (r.i_start.max(run.i_start), r.reach().min(run.reach())))
            .filter(|(lo, hi)| lo < hi)
            .collect();
        carried.sort_unstable();
        let mut cursor = run.i_start;
        let mut gaps: Vec<(u64, u64)> = Vec::new();
        for (lo, hi) in carried {
            if lo > cursor {
                gaps.push((cursor, lo));
            }
            cursor = cursor.max(hi);
        }
        if cursor < run.reach() {
            gaps.push((cursor, run.reach()));
        }
        for (lo, hi) in gaps {
            let at = ordinal + (lo - run.i_start);
            match out.last_mut() {
                Some(last) if last.ordinal + last.width == at => last.width += hi - lo,
                _ => out.push(Replaced {
                    ordinal: at,
                    width: hi - lo,
                    origin: run.origin.clone(),
                    i_start: lo,
                }),
            }
        }
        ordinal += run.width;
    }
    out
}

/// A merge of many small changes, as the walk meets it.
///
/// The base is runs of `D`, each four wide, their starts five apart so no
/// two coalesce, and every `step`-th of them is changed for a fresh run of
/// `Z`, four wide at a start no other takes. `held` is the side's runs, `m`
/// the composed list, both built directly, and `replaced` the stretches of
/// `held` that `m` carries none of.
struct Changes {
    held: Vec<Run>,
    m: Vec<Run>,
    replaced: Vec<Replaced>,
}

/// Returns a merge of `r` runs a side whose sides change runs by turns.
///
/// `held` is the side that changes the first, the third and so on, in which
/// the other side's changed runs still stand. `m` is the base with each
/// changed run replaced by its side's fresh run, `r` runs. So `m` carries
/// all of `held` but each base run the other side changed, whole.
fn changed_by_turns(r: usize, step: usize) -> Changes {
    let (base, fresh) = (d(), z());
    let run = |i: usize| Run::new(base.clone(), 1 + 5 * i as u64, 4);
    let (mut held, mut m): (Vec<Run>, Vec<Run>) =
        ((0..r).map(run).collect(), (0..r).map(run).collect());
    let mut replaced = Vec::new();
    for (nth, i) in (step - 1..r).step_by(step).enumerate() {
        m[i] = Run::new(fresh.clone(), 1 + 5 * nth as u64, 4);
        if nth % 2 == 0 {
            held[i] = m[i].clone();
        } else {
            replaced.push(Replaced {
                ordinal: 1 + 4 * i as u64,
                width: 4,
                origin: base.clone(),
                i_start: 1 + 5 * i as u64,
            });
        }
    }
    Changes { held, m, replaced }
}

/// Returns a merge of `r` runs a side whose sides change the same runs.
///
/// Each side puts a fresh run of its own there, and `m` holds both, the
/// held side's first: `r` runs and one more a changed run. So `m` carries
/// all of `held`.
fn changed_by_both(r: usize, step: usize) -> Changes {
    let (base, fresh) = (d(), z());
    let (mut held, mut m) = (Vec::with_capacity(r), Vec::with_capacity(r + r / step));
    let mut taken = 0u64;
    for i in 0..r {
        if (i + 1) % step == 0 {
            let (ours, theirs) = (1 + 5 * taken, 6 + 5 * taken);
            held.push(Run::new(fresh.clone(), ours, 4));
            m.extend([Run::new(fresh.clone(), ours, 4), Run::new(fresh.clone(), theirs, 4)]);
            taken += 2;
        } else {
            held.push(Run::new(base.clone(), 1 + 5 * i as u64, 4));
            m.push(Run::new(base.clone(), 1 + 5 * i as u64, 4));
        }
    }
    Changes { held, m, replaced: Vec::new() }
}

/// Returns words a draft holds many times, over a merged list that abuts.
///
/// `m` is `r` runs of `D`, each four wide and each opening where another
/// ends, laid last first so no two would coalesce. `held` is `r` runs of
/// `D` too, each as wide as `under` of `m`'s runs and lying over that many,
/// so the held runs overlap one another, and `m` carries every one whole.
/// Joined where they abut, `m`'s runs are one piece, and a held run walks
/// that piece and no more.
fn held_over_abutting_runs(r: usize, under: usize) -> Changes {
    let base = d();
    let m = (0..r).rev().map(|i| Run::new(base.clone(), 1 + 4 * i as u64, 4)).collect();
    let held = (0..r)
        .map(|j| Run::new(base.clone(), 1 + 4 * (j % (r - under)) as u64, 4 * under as u64))
        .collect();
    Changes { held, m, replaced: Vec::new() }
}

/// Returns the merges the suite reads at `r` runs a side, each named.
///
/// One run in a hundred and every second run are changed by turns, and one
/// in ten by both sides.
fn merges_of(r: usize) -> [(&'static str, Changes); 3] {
    [
        ("one run in a hundred changed, by turns", changed_by_turns(r, 100)),
        ("every second run changed, by turns", changed_by_turns(r, 2)),
        ("one run in ten changed by both sides", changed_by_both(r, 10)),
    ]
}

/// Checks the walk's step bound at 65,536 runs a side.
///
/// Every base run is of one origin, so grouping the merged list by origin
/// leaves a held run all but the whole list to read: only a search of that
/// origin's pieces keeps the walk inside [`bound`], and [`within`] fails it
/// at the first step past. The last cell holds each held run over 1,024 of
/// the merged list's runs, which abut: only their join into one piece keeps
/// a held run from walking them all. The floor holds the count itself: a
/// walk that charged nothing would pass any bound, and this one charges at
/// least one step a run of either list.
#[test]
fn replaced_stretches_stays_within_its_step_bound_at_65536_runs_a_side() {
    let abutting =
        ("words held many times over runs that abut", held_over_abutting_runs(RUNS, 1_024));
    for (what, merge) in merges_of(RUNS).into_iter().chain([abutting]) {
        let (n, m) = (merge.held.len(), merge.m.len());
        let budget = bound(n, m, merge.replaced.len());
        let mut count = 0;
        let out = replaced_stretches(&merge.held, &merge.m, &mut within(budget, &mut count));
        assert_eq!(out.len(), merge.replaced.len(), "{what}");
        assert!(count >= (n + m) as u64, "{what}: {count} steps charged for {n} and {m} runs");
    }
}

/// Checks what a landing replaces at 65,536 runs a side.
///
/// Where the sides change runs by turns it is each base run the other side
/// changed, four positions apiece, in order; where both change the same
/// runs and the merged list holds both, it is nothing. The walk is counted
/// here too, so one that reads the lists' product fails by its count and
/// not after minutes.
#[test]
fn at_65536_runs_a_side_what_is_replaced_is_each_run_the_other_side_changed() {
    for (what, merge) in merges_of(RUNS) {
        let budget = bound(merge.held.len(), merge.m.len(), merge.replaced.len());
        let mut count = 0;
        let out = replaced_stretches(&merge.held, &merge.m, &mut within(budget, &mut count));
        assert_eq!(out, merge.replaced, "{what}");
    }
    let [(_, hundredth), (_, second), (_, both)] = merges_of(RUNS);
    assert_eq!(
        (hundredth.replaced.len(), second.replaced.len(), both.replaced.len()),
        (327, 16_384, 0),
        "the stretches each merge replaces"
    );
    assert_eq!(
        (both.held.len(), both.m.len()),
        (RUNS, RUNS + 6_553),
        "both sides' runs in the list"
    );
}

/// Checks the walk against the scan on each way runs overlap.
///
/// The cells are the landing suite's cases, over that suite's documents
/// (its `D` is `Z` here), then each way `m`'s runs lie over a held run.
#[test]
fn replaced_stretches_answers_as_the_scan_does_on_each_way_runs_overlap() {
    let of = |document: &str| {
        let origin = addr(document);
        move |i, w| Run::new(origin.clone(), i, w)
    };
    let (z, s, l, x) = (of("1.0.1.0.64"), of("1.0.1.0.66"), of("1.0.1.0.72"), of("1.0.1.0.73"));
    let m = vec![z(1, 4), s(1, 3), z(5, 7)];
    let cells: Vec<(&str, Vec<Run>, Vec<Run>)> = vec![
        // The landing suite's cases.
        ("two stretches", vec![l(1, 3), z(1, 4), l(4, 2), z(5, 7), s(1, 3)], m.clone()),
        ("one stretch across the boundary", vec![l(1, 2), x(5, 3)], m.clone()),
        ("the run's middle", vec![z(1, 11)], vec![z(1, 4), z(8, 4)]),
        ("carried whole", vec![z(1, 11)], vec![z(1, 11)]),
        ("an empty draft", vec![], m.clone()),
        // Each way `m`'s runs lie over a held run.
        ("an empty merged list", vec![rd(1, 4), z(1, 2)], vec![]),
        ("both empty", vec![], vec![]),
        ("the run's start alone carried", vec![rd(1, 10)], vec![rd(1, 4)]),
        ("the run's end alone carried", vec![rd(1, 10)], vec![rd(7, 4)]),
        ("carried runs that overlap", vec![rd(1, 10)], vec![rd(2, 3), rd(4, 3)]),
        ("carried runs that abut", vec![rd(1, 10)], vec![rd(5, 3), rd(2, 3)]),
        ("a carried run inside another", vec![rd(1, 10)], vec![rd(2, 8), rd(4, 2)]),
        ("a carried run held twice", vec![rd(1, 10)], vec![rd(3, 2), rd(3, 2)]),
        (
            "one held run under several carried runs",
            vec![rd(3, 6)],
            vec![rd(1, 4), rd(5, 2), rd(7, 5)],
        ),
        ("carried runs past both ends", vec![rd(5, 3)], vec![rd(1, 20)]),
        (
            "carried runs that touch the run and hold none of it",
            vec![rd(5, 3)],
            vec![rd(1, 4), rd(8, 4)],
        ),
        ("words carried at another place", vec![z(1, 3), rd(1, 4)], vec![rd(1, 4), z(1, 3)]),
        ("runs one position wide", vec![rd(1, 1), rd(2, 1), rd(3, 1)], vec![rd(2, 1)]),
        ("a carried position inside a run", vec![rd(1, 5)], vec![rd(3, 1)]),
        ("stretches meeting across runs of two origins", vec![rd(1, 2), z(5, 3), rd(9, 1)], vec![]),
        (
            "a stretch ending at a boundary and one opening past it",
            vec![rd(1, 4), z(1, 4)],
            vec![rd(1, 2), z(1, 2)],
        ),
        (
            "a stretch across a boundary, carried either side",
            vec![rd(1, 4), z(1, 4)],
            vec![rd(1, 2), z(3, 2)],
        ),
        ("the same origin twice in the draft", vec![rd(1, 4), z(1, 2), rd(1, 4)], vec![rd(2, 2)]),
        ("a run of no width in the merged list", vec![rd(1, 4)], vec![rd(2, 0), rd(3, 1)]),
        ("a run of no width in the draft", vec![rd(1, 2), rd(9, 0), rd(3, 2)], vec![rd(2, 2)]),
        ("another origin's runs alone", vec![rd(1, 4)], vec![z(1, 4), rt(1, 4)]),
    ];
    for (what, held, m) in cells {
        assert_eq!(
            replaced_stretches(&held, &m, &mut |_| {}),
            replaced_stretches_by_scan(&held, &m),
            "{what}"
        );
    }
}

/// Checks the walk against the scan on merges of many small changes.
///
/// At 4,096 runs a side the scan's answer is also what each merge is built
/// to replace, which is what the cells at 65,536 runs a side, past the
/// scan's reach, are held to.
#[test]
fn replaced_stretches_answers_as_the_scan_does_on_merges_of_many_small_changes() {
    let merges = merges_of(4_096).into_iter().chain([
        ("one run in ten changed, by turns", changed_by_turns(4_096, 10)),
        ("words held many times over runs that abut", held_over_abutting_runs(1_024, 256)),
    ]);
    for (what, merge) in merges {
        let scanned = replaced_stretches_by_scan(&merge.held, &merge.m);
        assert_eq!(replaced_stretches(&merge.held, &merge.m, &mut |_| {}), scanned, "{what}");
        assert_eq!(scanned, merge.replaced, "{what}: what the merge is built to replace");
    }
}

/// The same numbers every run: a xorshift generator, seeded.
struct Seeded(u64);

impl Seeded {
    /// Returns the next number below `n`.
    fn below(&mut self, n: u64) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0 % n
    }

    /// Returns `count` runs of the first `origins` documents.
    ///
    /// Each opens in the first 24 ordinals and is at most six wide.
    fn runs(&mut self, count: u64, origins: u64) -> Vec<Run> {
        let documents = [d(), z(), t(), f()];
        (0..count)
            .map(|_| {
                Run::new(
                    documents[self.below(origins) as usize].clone(),
                    1 + self.below(24),
                    1 + self.below(6),
                )
            })
            .collect()
    }
}

/// Checks the walk against the scan on generated lists.
///
/// Each list holds up to twelve runs of one to four origins, opening within
/// 24 ordinals and one to six wide, so the merged list's runs overlap, abut
/// and nest, one held run lies under several of them, and words are carried
/// at another place. The counts hold the set to the kinds it is read for:
/// an empty list on either side, a stretch across a boundary between runs
/// of two origins, and a held run answered in more than one stretch.
#[test]
fn replaced_stretches_answers_as_the_scan_does_on_generated_lists() {
    let mut seeded = Seeded(0x9e37_79b9_7f4a_7c15);
    let (mut no_held, mut no_m, mut across, mut several) = (0, 0, 0, 0);
    for round in 0..4_000 {
        let origins = 1 + seeded.below(4);
        let (held, m) = (seeded.below(13), seeded.below(13));
        let (held, m) = (seeded.runs(held, origins), seeded.runs(m, origins));
        let scanned = replaced_stretches_by_scan(&held, &m);
        assert_eq!(
            replaced_stretches(&held, &m, &mut |_| {}),
            scanned,
            "round {round}: {held:?} under {m:?}"
        );
        no_held += usize::from(held.is_empty());
        no_m += usize::from(m.is_empty());
        // Each held run's first ordinal, and the one past the last run's.
        let mut opens = vec![1u64];
        opens.extend(held.iter().scan(1, |at, run| {
            *at += run.width;
            Some(*at)
        }));
        let inside = |s: &Replaced, k: usize| opens[k] <= s.ordinal && s.ordinal < opens[k + 1];
        across += usize::from((1..held.len()).any(|k| {
            held[k - 1].origin != held[k].origin
                && scanned.iter().any(|s| s.ordinal < opens[k] && opens[k] < s.ordinal + s.width)
        }));
        several += usize::from(
            (0..held.len()).any(|k| scanned.iter().filter(|s| inside(s, k)).count() > 1),
        );
    }
    assert!(no_held > 0 && no_m > 0, "{no_held} empty drafts and {no_m} empty merged lists");
    assert!(across > 100, "{across} rounds with a stretch across runs of two origins");
    assert!(several > 100, "{several} rounds with a held run answered in several stretches");
}
