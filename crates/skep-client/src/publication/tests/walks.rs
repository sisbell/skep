//! The placement's walks, held to their answers and their cost.
//!
//! `place_runs` finds each held run's places by a search of its chain's runs
//! in the image, and reads which copy of its run a held run is off one map
//! of the selection. This suite holds it, and `place_again` over it, to two
//! things.
//!
//! Its answers are a scan's: [`by_scan`] keeps the placement reading the
//! image through for each held run and the selection through for each run's
//! copies, and the two are compared through `place_selection` and through
//! `place_again`, under each answer a first read can give a run, on the kept
//! places' cells, on the shapes the cost is bounded on and on generated
//! images.
//!
//! Its work is bounded by count, never by a clock. The walk charges one step
//! for every run it reads, every comparison of a sort or a search and every
//! node of an index; [`within`] fails the moment the count passes a budget;
//! and the budget is [`bound`], at 65,536 runs, where the scans read
//! 4.3 × 10⁹ pairs of runs. So a placement that reads the image, a chain's
//! runs or the selection through for each held run fails before a tenth of
//! them are placed.

use super::*;
use crate::publication::enumerate::{place_again, place_runs};

/// The runs at the count the suite bounds the walks at.
const RUNS: usize = 1 << 16;

/// Returns the steps a placement may take: the suite's bound.
///
/// For `n` held runs over `m` image runs and `out` placements answered it
/// is `8 · (n + m) · ⌈log₂(n + m + 2)⌉ + out`.
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

/// The same placements by scans.
///
/// `arranged_in` reads the image through for each held run, in both passes
/// and again over the first image, and `place_runs` reads the selection
/// through for each run's copies. They are what the placement is held equal
/// to, plain enough to be read as right, and each costs the product of the
/// lists it reads.
mod by_scan {
    use crate::board::answers::IRun;
    use crate::publication::enumerate::{widest_first, Enumeration, Placement, TakenPlaces};
    use crate::publication::Run;

    /// Returns where `image` arranges `run`, by a read of the whole image.
    ///
    /// It answers each piece of the run as its V-ordinal, first I-ordinal
    /// and width, and the V-ordinals it stands whole at, both in V-order.
    pub(super) fn arranged_in(image: &[IRun], run: &Run) -> (Vec<(u64, u64, u64)>, Vec<u64>) {
        let chain = run.chain();
        let mut pieces: Vec<(u64, u64, u64)> = Vec::new();
        let mut wholes: Vec<u64> = Vec::new();
        for r in image.iter().filter(|r| r.prefix == chain) {
            let (lo, hi) = (run.i_start.max(r.first), run.reach().min(r.first + r.width));
            if lo < hi {
                pieces.push((r.ordinal + (lo - r.first), lo, hi - lo));
                if lo == run.i_start && hi == run.reach() {
                    wholes.push(r.ordinal + (lo - r.first));
                }
            }
        }
        (pieces, wholes)
    }

    /// Places the held runs in the image, each at one place.
    pub(super) fn place_selection(image: &[IRun], selection: &[Run]) -> Vec<Placement> {
        place_runs(image, selection, |_, _| 1)
    }

    /// Places the held runs as a later read does, over `first`.
    pub(super) fn place_again(image: &[IRun], selection: &[Run], first: &Enumeration, grows: bool) -> Vec<Placement> {
        place_runs(image, selection, |k, standing| match first.placed.get(k) {
            Some(Placement::Places(held)) if !grows => held.len(),
            Some(Placement::Places(_)) => usize::MAX,
            _ if grows && standing > arranged_in(&first.image, &selection[k]).1.len() => usize::MAX,
            _ => 1,
        })
    }

    /// Places each held run, then lets a run take further whole places.
    ///
    /// `most` answers how many places a run may stand at.
    fn place_runs(image: &[IRun], selection: &[Run], most: impl Fn(usize, usize) -> usize) -> Vec<Placement> {
        let mut taken = TakenPlaces::default();
        let mut out = vec![Placement::Absent; selection.len()];
        let order = widest_first(selection);
        for &k in &order {
            let run = &selection[k];
            let (pieces, wholes) = arranged_in(image, run);
            let occurrence = selection[..k].iter().filter(|s| *s == run).count();
            out[k] = match wholes.iter().copied().find(|&at| taken.take(at, run.width)).or_else(|| wholes.get(occurrence).copied()) {
                Some(ordinal) => Placement::Whole { ordinal },
                None if pieces.is_empty() => Placement::Absent,
                None => Placement::Split(pieces),
            };
        }
        for &k in &order {
            let run = &selection[k];
            let Placement::Whole { ordinal } = out[k] else { continue };
            if selection[k + 1..].contains(run) {
                continue;
            }
            let (_, wholes) = arranged_in(image, run);
            let limit = most(k, wholes.len());
            let mut places = vec![ordinal];
            for at in wholes {
                if places.len() >= limit {
                    break;
                }
                if taken.take(at, run.width) {
                    places.push(at);
                }
            }
            if places.len() > 1 {
                places.sort_unstable();
                out[k] = Placement::Places(places);
            }
        }
        out
    }
}

/// An image, a selection of its runs, and where each held run stands.
struct Shape {
    image: Vec<IRun>,
    selection: Vec<Run>,
    placed: Vec<Placement>,
}

/// Returns `n` disjoint runs of one chain, every one of them held.
///
/// Each is four wide. The `i`-th opens at `D·(1 + 5i)`, so no two coalesce,
/// and stands at V-ordinal `1 + 4i`, where the selection's `i`-th run
/// stands whole.
fn disjoint(n: usize) -> Shape {
    let (origin, chain) = (a(D), format!("{D}.0.1"));
    let at = |i: usize| (1 + 5 * i as u64, 1 + 4 * i as u64);
    Shape {
        image: (0..n).map(|i| IRun { prefix: chain.clone(), first: at(i).0, width: 4, ordinal: at(i).1 }).collect(),
        selection: (0..n).map(|i| Run::new(origin.clone(), at(i).0, 4)).collect(),
        placed: (0..n).map(|i| Placement::Whole { ordinal: at(i).1 }).collect(),
    }
}

/// Returns `n` such runs, each arranged twice and held twice.
///
/// The image holds the `n` runs and then the `n` again, and so does the
/// selection: a run's first held copy stands at its first place and its
/// second at its second.
fn held_twice(n: usize) -> Shape {
    let once = disjoint(n);
    let again = |r: &IRun| IRun { ordinal: r.ordinal + 4 * n as u64, ..r.clone() };
    Shape {
        image: once.image.iter().cloned().chain(once.image.iter().map(again)).collect(),
        selection: [once.selection.clone(), once.selection].concat(),
        placed: (0..2 * n).map(|k| Placement::Whole { ordinal: 1 + 4 * k as u64 }).collect(),
    }
}

/// Returns `n` held runs inside one run that encloses them all.
///
/// The image holds one run over all `4n` positions of a chain, then `n`
/// disjoint runs four wide inside it, and the selection holds the `n`.
/// The enclosing run stands at V-ordinal 1 and the `i`-th small run after
/// it, at `4n + 1 + 4i`. Each held run stands whole at two places, inside
/// the enclosing run and at its own, and takes the first in V-order,
/// `1 + 4i`.
fn enclosed(n: usize) -> Shape {
    let (origin, chain) = (a(D), format!("{D}.0.1"));
    let all = 4 * n as u64;
    let small = |i: usize| IRun { prefix: chain.clone(), first: 1 + 4 * i as u64, width: 4, ordinal: all + 1 + 4 * i as u64 };
    Shape {
        image: std::iter::once(IRun { prefix: chain.clone(), first: 1, width: all, ordinal: 1 }).chain((0..n).map(small)).collect(),
        selection: (0..n).map(|i| Run::new(origin.clone(), 1 + 4 * i as u64, 4)).collect(),
        placed: (0..n).map(|i| Placement::Whole { ordinal: 1 + 4 * i as u64 }).collect(),
    }
}

/// Returns an earlier read of a publication, for a later placement.
///
/// It holds `image` and `placed`, the two fields a later placement reads,
/// and nothing else.
fn read_before(image: Vec<IRun>, placed: Vec<Placement>) -> Enumeration {
    Enumeration {
        extent: 0,
        image,
        also: Vec::new(),
        base: None,
        placed,
        merge_atoms: Vec::new(),
        windows: Vec::new(),
        twins: Vec::new(),
        answers: BTreeMap::new(),
        left_out: BTreeSet::new(),
        selection: Vec::new(),
        received: Vec::new(),
        region: Vec::new(),
        candidates: Vec::new(),
        records: Vec::new(),
        homes: Vec::new(),
        frames: Vec::new(),
        as_of: 0,
    }
}

// ── THE COST, by count ───────────────────────────────────────────────────

/// Checks the step bound placing 65,536 disjoint runs of one chain.
///
/// One chain holds every run, so grouping the image by chain leaves a held
/// run the whole image to read, and every held run is distinct, so counting
/// a run's copies by reading the selection reads all of it: only a search of
/// the chain and a map of the selection keep the walk inside [`bound`], and
/// [`within`] fails it at the first step past. The floor holds the count
/// itself: a walk that charged nothing would pass any bound, and this one
/// charges at least one step a run of either list.
#[test]
fn placing_65536_disjoint_runs_of_one_chain_stays_within_the_step_bound() {
    let shape = disjoint(RUNS);
    let (n, m) = (shape.selection.len(), shape.image.len());
    let (budget, mut count) = (bound(n, m, n), 0);
    let placed = place_runs(&shape.image, &shape.selection, |_, _, _| 1, &mut within(budget, &mut count));
    assert_eq!(placed, shape.placed);
    assert!(count >= (n + m) as u64, "{count} steps charged for {n} held runs and {m} image runs");
}

/// Checks the step bound placing 65,536 runs again over a first read.
///
/// The first read placed every run whole, as `place_selection` places it,
/// and the re-read lets a run take more places than its image shows, so
/// every held run asks the first image how many places it shows: that image
/// is searched as the draft's is, and the bound counts both. The first
/// placement is counted too, so no walk here runs unbounded.
#[test]
fn placing_65536_runs_again_over_a_first_read_of_as_many_stays_within_the_step_bound() {
    let shape = disjoint(RUNS);
    let (budget, mut count) = (bound(shape.selection.len(), shape.image.len(), shape.selection.len()), 0);
    let once = place_runs(&shape.image, &shape.selection, |_, _, _| 1, &mut within(budget, &mut count));
    assert_eq!(once, shape.placed, "the first read places every run whole");
    let first = read_before(shape.image.clone(), once);
    let (n, m) = (shape.selection.len(), shape.image.len() + first.image.len());
    let (budget, mut count) = (bound(n, m, n), 0);
    let placed = place_again(&shape.image, &shape.selection, &first, true, &mut within(budget, &mut count));
    assert_eq!(placed, shape.placed);
    assert!(count >= (n + m) as u64, "{count} steps charged for {n} held runs and {m} image runs");
}

/// Checks the step bound placing 4,096 runs each held twice.
///
/// Each is arranged twice too. Every held run has a copy, so which copy it
/// is and whether a later one is held are read for each of them.
#[test]
fn placing_4096_runs_each_held_twice_stays_within_the_step_bound() {
    let shape = held_twice(4_096);
    let (n, m) = (shape.selection.len(), shape.image.len());
    let (budget, mut count) = (bound(n, m, n), 0);
    let placed = place_runs(&shape.image, &shape.selection, |_, _, _| 1, &mut within(budget, &mut count));
    assert_eq!(placed, shape.placed);
    assert!(count >= (n + m) as u64, "{count} steps charged for {n} held runs and {m} image runs");
}

/// Checks the step bound placing 65,536 runs inside one enclosing run.
///
/// The enclosing run opens no later than any other and reaches furthest,
/// so the running maximum of the reaches passes every held run's start all
/// along the chain: a search that walked back while it does would read
/// every run opening before the held one. Only passing over the runs that
/// end before the held run's start keeps the walk inside [`bound`].
#[test]
fn placing_65536_runs_inside_one_enclosing_run_stays_within_the_step_bound() {
    let shape = enclosed(RUNS);
    let (n, m) = (shape.selection.len(), shape.image.len());
    let (budget, mut count) = (bound(n, m, n), 0);
    let placed = place_runs(&shape.image, &shape.selection, |_, _, _| 1, &mut within(budget, &mut count));
    assert_eq!(placed, shape.placed);
    assert!(count >= (n + m) as u64, "{count} steps charged for {n} held runs and {m} image runs");
}

// ── THE ANSWERS, against the scan ────────────────────────────────────────

/// Returns the cells the search and the scan are compared on.
///
/// Each is an image and a selection. The first eleven are the cells of
/// `no_held_run_takes_a_whole_place_another_held_run_took`, the kept
/// places' test. The rest are the ones an index by first ordinal could part
/// from the image's order on: a run standing whole inside one that opens
/// before it and stands after it, or inside two with a run between that
/// ends before it, runs held three times, image runs that overlap, an image
/// whose ordinals do not ascend, several chains, and runs and lists holding
/// nothing.
fn cells() -> Vec<(&'static str, Vec<IRun>, Vec<Run>)> {
    let at_20 = image_run(D, 1, 10, 20);
    let nested_at_30 = image_run(D, 5, 6, 30);
    vec![
        ("the enclosing run first", vec![at_20.clone(), nested_at_30.clone()], vec![run(D, 1, 10), run(D, 5, 6)]),
        ("the enclosing run second", vec![at_20.clone(), nested_at_30.clone()], vec![run(D, 5, 6), run(D, 1, 10)]),
        ("a nested run either side of the enclosing one", vec![image_run(D, 5, 6, 20), image_run(D, 1, 10, 26), image_run(D, 5, 6, 36)], vec![run(D, 5, 6), run(D, 1, 10), run(D, 5, 6)]),
        ("nested at the enclosing run's start", vec![at_20.clone(), image_run(D, 1, 4, 30)], vec![run(D, 1, 10), run(D, 1, 4)]),
        ("a chain of three", vec![image_run(D, 1, 12, 10), image_run(D, 3, 6, 50), image_run(D, 4, 2, 100)], vec![run(D, 4, 2), run(D, 3, 6), run(D, 1, 12)]),
        ("every whole place inside another's: the one its occurrence names", vec![at_20.clone()], vec![run(D, 1, 10), run(D, 5, 6)]),
        ("a copy held twice, arranged twice", vec![at_20.clone(), image_run(D, 1, 10, 30)], vec![run(D, 1, 10), run(D, 1, 10)]),
        ("a copy held twice, arranged once: the second in pieces", vec![at_20.clone()], vec![run(D, 1, 10), run(D, 1, 10)]),
        ("runs no other overlaps", vec![image_run(E, 1, 19, 1), at_20.clone(), image_run(O, 1, 5, 30)], vec![run(E, 1, 19), run(D, 1, 10), run(O, 1, 5)]),
        ("a run in pieces takes no whole place", vec![image_run(D, 1, 6, 30), image_run(D, 7, 4, 50), image_run(D, 2, 2, 70)], vec![run(D, 1, 10), run(D, 2, 2)]),
        ("a run the image does not hold", vec![at_20.clone()], vec![run(D, 20, 2)]),
        ("whole inside a run that opens before it and stands after it", vec![image_run(D, 5, 6, 20), image_run(D, 1, 10, 26)], vec![run(D, 5, 6)]),
        ("whole at its own run, standing after one that opens after it", vec![image_run(D, 5, 6, 20), image_run(D, 1, 10, 26)], vec![run(D, 1, 10), run(D, 6, 2)]),
        ("whole at three places, the last to open standing first", vec![image_run(D, 4, 4, 1), image_run(D, 2, 8, 5), image_run(D, 1, 12, 13)], vec![run(D, 4, 4)]),
        ("whole inside two runs, a run that ends before it opening after both", vec![image_run(D, 1, 20, 1), image_run(D, 2, 2, 21), image_run(D, 1, 20, 23), image_run(D, 10, 2, 43)], vec![run(D, 10, 2)]),
        ("held three times, arranged three times", vec![at_20.clone(), image_run(D, 1, 10, 30), image_run(D, 1, 10, 40)], vec![run(D, 1, 10), run(D, 1, 10), run(D, 1, 10)]),
        ("held three times, arranged twice", vec![at_20.clone(), image_run(D, 1, 10, 30)], vec![run(D, 1, 10), run(D, 1, 10), run(D, 1, 10)]),
        ("held three times inside one run that holds it once", vec![at_20.clone()], vec![run(D, 3, 2), run(D, 1, 10), run(D, 3, 2), run(D, 3, 2)]),
        ("held twice, each whole place inside another's: the second names none", vec![at_20.clone()], vec![run(D, 1, 10), run(D, 5, 6), run(D, 5, 6)]),
        ("image runs that overlap", vec![image_run(D, 1, 6, 1), image_run(D, 4, 6, 7), image_run(D, 8, 6, 13)], vec![run(D, 4, 3), run(D, 1, 13), run(D, 8, 2), run(D, 5, 5)]),
        ("an image whose ordinals do not ascend", vec![image_run(D, 1, 10, 40), image_run(D, 1, 10, 20), image_run(D, 3, 4, 30)], vec![run(D, 3, 4), run(D, 1, 10), run(D, 1, 10)]),
        ("the same words on two chains", vec![image_run(E, 1, 10, 1), image_run(D, 1, 10, 11), image_run(E, 1, 10, 21)], vec![run(D, 1, 10), run(E, 1, 10), run(E, 2, 3), run(O, 1, 10)]),
        ("a held run of no width", vec![at_20.clone()], vec![run(D, 3, 0), run(D, 1, 10)]),
        ("an image run of no width", vec![image_run(D, 3, 0, 5), at_20.clone()], vec![run(D, 1, 10), run(D, 3, 1)]),
        ("an empty image", vec![], vec![run(D, 1, 10)]),
        ("an empty selection", vec![at_20], vec![]),
    ]
}

/// Returns the first reads a later placement is compared over, each named.
///
/// The later placement is of `selection` over `image`. Between them and
/// the two values of `grows` the first reads reach every answer a first
/// read gives a run: carried at several places, at the panel's re-open and
/// at the re-read; whole at more places than the first image shows, at as
/// many, and at fewer; and not placed at all.
fn first_reads(image: &[IRun], selection: &[Run]) -> Vec<(&'static str, Enumeration)> {
    let half = &image[..image.len() / 2];
    let several = |places: u64| vec![Placement::Places((1..=places).collect()); selection.len()];
    vec![
        ("the same image", read_before(image.to_vec(), by_scan::place_selection(image, selection))),
        ("the image's first half", read_before(half.to_vec(), by_scan::place_selection(half, selection))),
        ("an image holding nothing", read_before(Vec::new(), by_scan::place_selection(&[], selection))),
        ("every run carried at two places", read_before(image.to_vec(), several(2))),
        ("every run carried at three places", read_before(half.to_vec(), several(3))),
        ("no run placed", read_before(image.to_vec(), Vec::new())),
    ]
}

/// Checks the search against the scan on one image and selection.
///
/// It places through `place_selection`, and through `place_again` over each
/// of [`first_reads`] at both values of `grows`.
fn placed_as_the_scan_places(what: &str, image: &[IRun], selection: &[Run]) {
    assert_eq!(place_selection(image, selection), by_scan::place_selection(image, selection), "{what}");
    for (which, first) in first_reads(image, selection) {
        for grows in [false, true] {
            let scanned = by_scan::place_again(image, selection, &first, grows);
            assert_eq!(place_again(image, selection, &first, grows, &mut |_| {}), scanned, "{what}, again over {which}, grows {grows}");
        }
    }
}

/// Checks the search against the scan on the kept places' cells.
///
/// The cells an index by first ordinal could part from the image's order
/// on are read with them ([`cells`]).
#[test]
fn the_search_places_as_the_scan_does_on_the_kept_places_cells() {
    for (what, image, selection) in cells() {
        placed_as_the_scan_places(what, &image, &selection);
    }
}

/// Checks what a run whole at three places takes after each first read.
///
/// The search and the scan are each held to the answer.
/// A run the first read carried at two takes two at the panel's re-open and
/// every place at the re-read; a run it placed whole takes every place at
/// the re-read where it stands at more than the first image shows, and one
/// where it stands at as many, or at the panel's re-open.
#[test]
fn a_run_whole_at_three_places_takes_what_each_answer_of_a_first_read_allows() {
    let image = vec![image_run(D, 1, 10, 20), image_run(D, 1, 10, 30), image_run(D, 1, 10, 40)];
    let selection = vec![run(D, 1, 10)];
    let whole = vec![Placement::Whole { ordinal: 20 }];
    let at = |places: &[u64]| vec![Placement::Places(places.to_vec())];
    let cells = [
        ("carried at two, the panel's re-open", read_before(image.clone(), at(&[20, 30])), false, at(&[20, 30])),
        ("carried at two, the re-read", read_before(image.clone(), at(&[20, 30])), true, at(&[20, 30, 40])),
        ("whole at more places than the first image shows, the re-read", read_before(image[..1].to_vec(), whole.clone()), true, at(&[20, 30, 40])),
        ("whole at as many as the first image shows, the re-read", read_before(image.clone(), whole.clone()), true, whole.clone()),
        ("whole at more places than the first image shows, the panel's re-open", read_before(image[..1].to_vec(), whole.clone()), false, whole.clone()),
    ];
    for (what, first, grows, want) in cells {
        assert_eq!(place_again(&image, &selection, &first, grows, &mut |_| {}), want, "{what}");
        assert_eq!(by_scan::place_again(&image, &selection, &first, grows), want, "{what}, by scan");
    }
}

/// Checks the search against the scan on the shapes the cost is bounded on.
///
/// At 4,096 held runs the scan's answer is also where each shape says its
/// runs stand, which is what the cells at 65,536 runs, past the scan's
/// reach, are held to.
#[test]
fn the_search_places_as_the_scan_does_on_the_bounded_shapes_at_4096_runs() {
    let shapes = [("disjoint runs of one chain", disjoint(4_096)), ("runs each held twice", held_twice(2_048)), ("runs inside one enclosing run", enclosed(4_096))];
    for (what, shape) in shapes {
        let scanned = by_scan::place_selection(&shape.image, &shape.selection);
        assert_eq!(place_selection(&shape.image, &shape.selection), scanned, "{what}");
        assert_eq!(scanned, shape.placed, "{what}: where the shape says its runs stand");
    }
    let shape = disjoint(4_096);
    let first = read_before(shape.image.clone(), shape.placed.clone());
    let scanned = by_scan::place_again(&shape.image, &shape.selection, &first, true);
    assert_eq!(place_again(&shape.image, &shape.selection, &first, true, &mut |_| {}), scanned, "disjoint runs placed again");
    assert_eq!(scanned, shape.placed, "disjoint runs placed again: where the shape says its runs stand");
}

/// The three documents the generated images arrange words of.
const CHAINS: [&str; 3] = [D, E, O];

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

    /// Returns one of `list`'s items.
    fn one_of<'l, T>(&mut self, list: &'l [T]) -> &'l T {
        &list[self.below(list.len() as u64) as usize]
    }

    /// Returns an image of up to twelve runs of the first `chains` documents.
    ///
    /// Each opens within 24 ordinals and is up to eight wide, so runs of one
    /// chain overlap, nest and repeat.
    /// Its runs lie end to end from V-ordinal 1, as a draft's image does,
    /// or, one image in four, at ordinals in no order.
    fn image(&mut self, chains: u64) -> Vec<IRun> {
        let scattered = self.below(4) == 0;
        let mut next = 1;
        (0..self.below(13))
            .map(|_| {
                let (doc, first, width) = (CHAINS[self.below(chains) as usize], 1 + self.below(24), 1 + self.below(8));
                let ordinal = if scattered { 1 + self.below(200) } else { next };
                next += width;
                image_run(doc, first, width, ordinal)
            })
            .collect()
    }

    /// Returns a selection of up to eight runs over `image`.
    ///
    /// Each is an image run's words, which stand whole there; a part of an
    /// image run's, nested in it; a run held already, so held twice or
    /// three times; or a run of its own, in pieces, across several image
    /// runs or absent. A run and the one enclosing it come in either order.
    fn selection(&mut self, image: &[IRun], chains: u64) -> Vec<Run> {
        let mut held: Vec<Run> = Vec::new();
        for _ in 0..self.below(9) {
            let kind = self.below(4);
            let next = if kind == 0 && !held.is_empty() {
                self.one_of(&held).clone()
            } else if kind < 3 && !image.is_empty() {
                let r = self.one_of(image);
                let origin = a(r.prefix.strip_suffix(".0.1").expect("a content chain"));
                let from = if kind == 1 { 0 } else { self.below(r.width) };
                let width = if kind == 1 { r.width } else { 1 + self.below(r.width - from) };
                Run::new(origin, r.first + from, width)
            } else {
                run(CHAINS[self.below(chains) as usize], 1 + self.below(24), 1 + self.below(10))
            };
            held.push(next);
        }
        held
    }

    /// Returns a first read for a later placement.
    ///
    /// The later placement is of `selection` over `image`. The first read's
    /// image is the same one, a head of it or another; it places a head
    /// of the selection, each run whole, at up to three places, in pieces
    /// or absent, whatever its own image holds: the later placement reads a
    /// first placement's kind and count alone.
    fn first_read(&mut self, image: &[IRun], selection: &[Run], chains: u64) -> Enumeration {
        let before = match self.below(3) {
            0 => image.to_vec(),
            1 => image[..self.below(image.len() as u64 + 1) as usize].to_vec(),
            _ => self.image(chains),
        };
        let placed = (0..self.below(selection.len() as u64 + 1))
            .map(|_| match self.below(4) {
                0 => Placement::Places((1..=1 + self.below(3)).collect()),
                1 => Placement::Split(vec![(1, 1, 1)]),
                2 => Placement::Absent,
                _ => Placement::Whole { ordinal: 1 },
            })
            .collect();
        read_before(before, placed)
    }
}

/// Checks that the search places as the scan does on generated images.
///
/// Each image holds up to twelve runs of one to three chains that overlap,
/// nest and repeat, and each selection up to eight runs that stand whole,
/// in pieces or nowhere, some held twice and three times. Each is placed
/// through `place_selection` and, over a generated first read, through
/// `place_again` at both values of `grows`. The counts hold the set to the
/// kinds it is read for: each kind of placement, a run carried at several
/// places under each value of `grows`, a run held three times, and a run
/// whose whole places stand in another order than they open in.
#[test]
fn the_search_places_as_the_scan_does_on_generated_images() {
    let mut seeded = Seeded(0x9e37_79b9_7f4a_7c15);
    let (mut whole, mut split, mut absent, mut thrice, mut out_of_order) = (0, 0, 0, 0, 0);
    let mut several = [0, 0];
    for round in 0..4_000 {
        let chains = 1 + seeded.below(3);
        let image = seeded.image(chains);
        let selection = seeded.selection(&image, chains);
        let scanned = by_scan::place_selection(&image, &selection);
        assert_eq!(place_selection(&image, &selection), scanned, "round {round}: {selection:?} over {image:?}");
        let first = seeded.first_read(&image, &selection, chains);
        for grows in [false, true] {
            let scanned = by_scan::place_again(&image, &selection, &first, grows);
            let searched = place_again(&image, &selection, &first, grows, &mut |_| {});
            assert_eq!(searched, scanned, "round {round}, grows {grows}: {selection:?} over {image:?}, first {:?} over {:?}", first.placed, first.image);
            several[usize::from(grows)] += usize::from(scanned.iter().any(|p| matches!(p, Placement::Places(_))));
        }
        whole += usize::from(scanned.iter().any(|p| matches!(p, Placement::Whole { .. })));
        split += usize::from(scanned.iter().any(|p| matches!(p, Placement::Split(_))));
        absent += usize::from(scanned.contains(&Placement::Absent));
        thrice += usize::from(selection.iter().any(|run| selection.iter().filter(|held| *held == run).count() > 2));
        // A held run's whole places come in the image's order; where the
        // runs holding them open in another order, an index by first
        // ordinal meets them in another order than it must answer them in.
        out_of_order += usize::from(selection.iter().any(|run| {
            let opens: Vec<u64> = image.iter().filter(|r| !by_scan::arranged_in(std::slice::from_ref(*r), run).1.is_empty()).map(|r| r.first).collect();
            opens.windows(2).any(|pair| pair[0] > pair[1])
        }));
    }
    assert!(whole > 1_000 && split > 1_000 && absent > 1_000, "{whole} rounds with a run whole, {split} in pieces, {absent} absent");
    assert!(several[0] > 20 && several[1] > 100, "{several:?} rounds with a run at several places, by grows");
    assert!(thrice > 100, "{thrice} rounds with a run held three times");
    assert!(out_of_order > 100, "{out_of_order} rounds with whole places standing in another order than they open in");
}
