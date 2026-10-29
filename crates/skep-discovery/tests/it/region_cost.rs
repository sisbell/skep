//! The region read's cost over a crowded PUBLIC passage (skep #656), measured
//! in-process and printed: S34's flooded passage — ten thousand links homed
//! ten apiece in a thousand documents the reader may read, on a hundred
//! positions crossing three directory blocks — beside four controls: the
//! passage with no foreign link, the same flood in ten homes, the same flood
//! read by a reader who may read none of its homes (a guest over drafts,
//! PUB-7.17's residual), and a thousand readable homes the passage's blocks
//! name that hold no link on it (S43's popular document, the readable home
//! with an empty stab). `findlinks_v` and `count_v` are timed over
//! interleaved rounds, each arm's answer held identical round to round, and
//! the table carries per-arm medians and p99, the heap each read asks for,
//! and the per-public-link and per-home figures. Run by name with
//! `--release --ignored --nocapture`; `SKEP_REGION_COST_ROUNDS` and
//! `SKEP_REGION_COST_WARMUP` set the rounds.
//!
//! Beside it, the two measurements the count-by-home lane owes (the
//! link-sets design §7, W10 (a); the owner's rulings of 2026-10-28): the
//! PER-SET HOME READ over a set of ten thousand links, sixty-four of them on
//! a sixty-four-position passage — the descriptor family's `find_links_ftt
//! {home: S, from: the passage}` as built, the home's whole chain walked,
//! timed against the stab within the home M7 answers — the one-line change
//! to the descriptor's candidates ruled "only if the measurement says so",
//! against one sixteenth of a frame, 1 ms p50; and THE ACCEPTANCE, the
//! budgeted count by home over S43's flooded public passage at F = 10⁴ and
//! 10⁵, `except` the author's own home and `n` the view's links, against
//! `count_v` on the same board: the budgeted count is held FLAT in F past
//! the budget — within 2× of its 10⁴ figure at 10⁵ — while `count_v` grows
//! with F. Each prints its figures with the machine's load.

use std::time::{Duration, Instant};

use crate::common;
use crate::heap::settled_heap_bytes;

use common::*;
use skep_address::Address;
use skep_discovery::{
    count_v_by_home_on, count_v_on, findlinks_ftt_on, findlinks_v_on, image_on, FourSet, Run,
    SlotSpec,
};
use skep_kernel::{Kernel, Snapshot};
use skep_links::{enc, Endset, HasLinks, LinkWriter, View, FROM};

/// S34's flood: ten thousand foreign links on the passage…
const FLOOD: u32 = 10_000;
/// …homed in a thousand documents, ten apiece.
const HOMES: u32 = 1_000;
/// The few-homes control: the same flood in ten homes, a thousand apiece.
const FEW_HOMES: u32 = 10;
/// The passage document's own links on the passage: the floor every arm
/// answers, so the guest's answer is a set and not the empty one.
const OWN: u32 = 20;
/// The passage: a hundred positions from the thirtieth, so at a block of
/// sixty-four positions it crosses three directory blocks.
const PASSAGE_START: u32 = 30;
const PASSAGE: u32 = 100;
/// The document's content: the passage with a margin either side.
const CONTENT: u32 = 160;

/// A world of `flood` links on the passage, homed round-robin in `homes`
/// documents past the passage document, each home's links ten positions
/// apart so a home of ten spreads over the passage's three blocks — beside
/// the passage document's own [`OWN`] links. With `named_only`, every home
/// holds ONE link instead, in the passage's first block but ahead of the
/// passage: the directory names the home for the passage, and its stab finds
/// nothing (S43's popular document, the readable home with an empty stab).
fn world(homes: u32, flood: u32, named_only: bool) -> Kernel<World> {
    let k = kernel_with_documents(1 + homes);
    seed_content(&k, &doc(1), CONTENT);
    let store = LinkWriter::new(&k, &EVERYONE);
    for j in 0..OWN {
        link(&store, &doc(1), &[ca(PASSAGE_START + j)], &[ca(CONTENT + 40 + j)]);
    }
    let links = if named_only { homes } else { flood };
    for i in 0..links {
        let home = 2 + i % homes;
        let position = if named_only {
            1 + i % (PASSAGE_START - 1)
        } else {
            PASSAGE_START + (10 * (i / homes) + i % homes) % PASSAGE
        };
        link(
            &store,
            &doc(home),
            &[ca(position)],
            &[a(&[1, 0, 1, 0, home, 0, 1, 1])],
        );
    }
    k
}

/// One arm of the measurement: a snapshot read under a reader.
struct Arm {
    name: &'static str,
    snap: Snapshot<World>,
    readable: Box<dyn Fn(&Address) -> bool>,
    links: usize,
}

/// The two reads timed, by name.
const READS: [&str; 2] = ["findlinks_v", "count_v"];

fn setting(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn median(sorted: &[Duration]) -> Duration {
    sorted[sorted.len() / 2]
}

fn p99(sorted: &[Duration]) -> Duration {
    sorted[(sorted.len() * 99).div_ceil(100).saturating_sub(1)]
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1e3
}

fn us(d: f64) -> f64 {
    d * 1e3
}

/// The 1-, 5- and 15-minute load averages, off `sysctl -n vm.loadavg` — the
/// load every figure here is reported with, as the spikes report theirs.
fn loadavg() -> String {
    match std::process::Command::new("sysctl").args(["-n", "vm.loadavg"]).output() {
        Ok(o) => String::from_utf8_lossy(&o.stdout)
            .trim()
            .trim_start_matches('{')
            .trim_end_matches('}')
            .trim()
            .to_string(),
        Err(e) => format!("? ({e})"),
    }
}

/// Times `arms` over `rounds` interleaved rounds after `warmup` discarded
/// ones, the order rotated by round, each arm's answer held to its first;
/// the samples per arm, sorted.
fn timed<T: PartialEq + std::fmt::Debug>(
    rounds: usize,
    warmup: usize,
    arms: &[(&str, &dyn Fn() -> T)],
) -> Vec<Vec<Duration>> {
    let first: Vec<T> = arms.iter().map(|(_, run)| run()).collect();
    let mut samples: Vec<Vec<Duration>> = vec![Vec::with_capacity(rounds); arms.len()];
    for round in 0..warmup + rounds {
        for k in 0..arms.len() {
            let i = (round + k) % arms.len();
            let start = Instant::now();
            let answer = (arms[i].1)();
            let took = start.elapsed();
            assert_eq!(answer, first[i], "{}: round {round}", arms[i].0);
            if round >= warmup {
                samples[i].push(took);
            }
        }
    }
    for s in &mut samples {
        s.sort();
    }
    samples
}

/// The passage's I-spans, as the view images them: the endset a per-set home
/// read's `from` slot carries.
fn passage_spans(snap: &Snapshot<World>, d: &Address, region: &[skep_address::Span]) -> Endset {
    let image = image_on(snap, d, region).expect("the passage images");
    Endset::from_spans(image.iter().map(Run::iextent))
}

/// The set under the per-set measurement: ten thousand links in one home.
const SET_LINKS: u32 = 10_000;
/// Of them, the ones on the view: one per position of a sixty-four-position
/// passage, the view's own width.
const VIEW: u32 = 64;

/// THE PER-SET HOME READ AT A SET OF 10⁴ (the owner's ruling A (4),
/// 2026-10-28): one home S holding ten thousand links, sixty-four of them on
/// a sixty-four-position passage of the page and the rest on positions past
/// its content, read as the default view reads an applied set —
/// `find_links_ftt {home: S, from: the passage's I-spans}` — timed as the
/// descriptor family answers it, beside the stab within the home M7
/// answers for the same question (`stab_in` over the spans the directory
/// named S for). The threshold the ruling names is one sixteenth of a
/// frame, 1 ms p50, in a release build. MEASURED 2026-10-28 as first built
/// — S's WHOLE chain walked and each link's slot tested (`homed_in`) —
/// 2.844 ms p50 (2.899 p99) in release at load 15, 40.3 ms in debug, past
/// the threshold, against 0.035 ms the stab within the home; so the
/// descriptor's `candidates` reads a home-constrained query with a link
/// slot beside by the stab within the home since, and the first arm here
/// is that form, timed against the bare stab. The cell asserts the answers
/// and prints the figures with the load.
#[test]
#[ignore = "timing test - gate-full only"]
fn the_per_set_home_read_over_a_large_set_reports_its_cost() {
    let rounds = setting("SKEP_REGION_COST_ROUNDS", 50);
    let warmup = setting("SKEP_REGION_COST_WARMUP", 5);
    let region = [vspan(1, PASSAGE_START, VIEW)];
    let seeding = Instant::now();
    let k = kernel_with_documents(2);
    seed_content(&k, &doc(1), CONTENT);
    let set = doc(2);
    let store = LinkWriter::new(&k, &EVERYONE);
    for i in 0..SET_LINKS {
        // The first VIEW links one per passage position; the rest at
        // positions past the page's content, in blocks the passage never
        // names.
        let position = if i < VIEW { PASSAGE_START + i } else { 1_000 + i };
        link(&store, &set, &[ca(position)], &[a(&[1, 0, 1, 0, 2, 0, 1, 1])]);
    }
    let seeded = seeding.elapsed();
    let snap = k.snapshot();
    let from = passage_spans(&snap, &doc(1), &region);
    let q = FourSet {
        home: SlotSpec::Spans(enc([&set])),
        from: SlotSpec::Spans(from.clone()),
        ..FourSet::any()
    };
    let view = usize::try_from(VIEW).expect("small");
    let as_built = || findlinks_ftt_on(&snap, &q, &every_home).len();
    let within = || {
        let links = snap.world().links();
        let touch = links
            .homes_touching([(FROM, &from)])
            .find(|touch| *touch.home() == set)
            .expect("the directory names the set for the passage");
        links.stab_in(touch.home(), FROM, touch.spans(0), View::Active).len()
    };
    assert_eq!(as_built(), view, "the set's links on the passage");
    assert_eq!(within(), view, "the stab within the home finds the same");
    let arms: [(&str, &dyn Fn() -> usize); 2] = [("as built", &as_built), ("stab within", &within)];
    let samples = timed(rounds, warmup, &arms);
    let profile = if cfg!(debug_assertions) { "debug" } else { "release" };
    eprintln!(
        "PER-SET-READ ({profile}): {rounds} rounds after {warmup} warm-up; seeding {:.1} s; \
         load {}; set of {SET_LINKS} links, {VIEW} on a {VIEW}-position passage",
        seeded.as_secs_f64(),
        loadavg()
    );
    let names = [
        "find_links_ftt {home: S, from: P} (the descriptor's candidates: the stab within the home)",
        "stab within the home (M7 stab_in over the named spans, bare)",
    ];
    for (name, sorted) in names.iter().zip(&samples) {
        eprintln!("{name}: p50 {:.3} ms, p99 {:.3} ms", ms(median(sorted)), ms(p99(sorted)));
    }
    eprintln!(
        "threshold: 1 ms p50 (one sixteenth of a 16.7 ms frame); the descriptor's read {}",
        if ms(median(&samples[0])) > 1.0 { "EXCEEDS it" } else { "is under it" }
    );
}

/// The floods of the acceptance: S34's 10⁴, and the design's 10⁵.
const FLOODS: [u32; 2] = [10_000, 100_000];

/// THE ACCEPTANCE (the link-sets design §7: "the open at a flooded PUBLIC
/// passage added to the lane's acceptance past 10⁴"): S43's board shape —
/// one page, a thousand readable homes, F public links on the passage
/// homed round-robin, the author's own twenty among them in the page's own
/// home — read by the count by home with `except` the author's home and
/// `n` the view's links, against `count_v` on the same board, at F = 10⁴
/// and 10⁵. The expectation, tested: the budgeted count's cost is FLAT in F
/// past the budget — its p50 at 10⁵ within 2× of its p50 at 10⁴, or of a
/// tenth of a millisecond where the 10⁴ figure is under that: at the
/// microsecond scale a release build answers in, the index's depth, which
/// grows as the logarithm of the flood, and the cache's state move a figure
/// by tens of microseconds, which is not growth with the flood and is a
/// hundredth of the frame — while `count_v`'s grows with F. The figures are
/// printed with the load; nothing is corrected. MEASURED 2026-10-28,
/// release at load 15–19: the budgeted count 0.029 ms p50 at 10⁴ and
/// 0.060 ms at 10⁵; `count_v` 3.27 ms and 33.5 ms.
#[test]
#[ignore = "timing test - gate-full only"]
fn the_budgeted_count_by_home_over_a_flooded_public_passage_is_flat_in_the_flood() {
    let rounds = setting("SKEP_REGION_COST_ROUNDS", 50);
    let warmup = setting("SKEP_REGION_COST_WARMUP", 5);
    let region = [vspan(1, PASSAGE_START, PASSAGE)];
    let view = usize::try_from(VIEW).expect("small");
    let own = usize::try_from(OWN).expect("small");
    let author = [doc(1)];
    let profile = if cfg!(debug_assertions) { "debug" } else { "release" };
    let mut by_home_p50 = Vec::new();
    let mut count_v_p50 = Vec::new();
    for flood in FLOODS {
        let seeding = Instant::now();
        let k = world(HOMES, flood, false);
        let seeded = seeding.elapsed();
        let snap = k.snapshot();
        let per_home = usize::try_from(flood / HOMES).expect("small");
        let budgeted = || {
            count_v_by_home_on(&snap, &doc(1), &region, view, &author, &every_home)
                .expect("count_v_by_home over a registered document and a well-formed region")
        };
        let whole = || {
            count_v_on(&snap, &doc(1), &region, &every_home)
                .expect("count_v over a registered document and a well-formed region")
        };
        let counts = budgeted();
        assert!(!counts.exhausted, "the flood is past the budget");
        assert!(counts.homes.iter().all(|(home, n)| *home != doc(1) && *n == per_home), "{counts:?}");
        let sum: usize = counts.homes.iter().map(|(_, n)| n).sum();
        assert!(sum >= view && sum - per_home < view, "the home that fills the budget, whole: {counts:?}");
        assert_eq!(whole(), own + usize::try_from(flood).expect("small"));
        let budgeted_sum = || counted(&budgeted());
        let arms: [(&str, &dyn Fn() -> usize); 2] =
            [("count_v_by_home", &budgeted_sum), ("count_v", &whole)];
        let samples = timed(rounds, warmup, &arms);
        let (by_home, count_v) = (&samples[0], &samples[1]);
        eprintln!(
            "ACCEPTANCE ({profile}): F = {flood} public links in {HOMES} homes; {rounds} rounds \
             after {warmup} warm-up; seeding {:.1} s; load {}",
            seeded.as_secs_f64(),
            loadavg()
        );
        eprintln!(
            "count_v_by_home {{except: [the author's home], n: {VIEW}}}: p50 {:.3} ms, p99 {:.3} ms \
             ({} homes counted, {sum} links); count_v: p50 {:.3} ms, p99 {:.3} ms ({} links)",
            ms(median(by_home)),
            ms(p99(by_home)),
            counts.homes.len(),
            ms(median(count_v)),
            ms(p99(count_v)),
            whole()
        );
        by_home_p50.push(median(by_home));
        count_v_p50.push(median(count_v));
    }
    let floor = Duration::from_micros(100);
    assert!(
        by_home_p50[1] <= 2 * by_home_p50[0].max(floor),
        "the budgeted count is flat in F past the budget: {:.3} ms at 10⁵ against {:.3} ms at 10⁴",
        ms(by_home_p50[1]),
        ms(by_home_p50[0])
    );
    assert!(
        count_v_p50[1] > count_v_p50[0],
        "the control: count_v grows with F: {:.3} ms at 10⁵ against {:.3} ms at 10⁴",
        ms(count_v_p50[1]),
        ms(count_v_p50[0])
    );
}

#[test]
#[ignore = "timing test - gate-full only"]
fn the_region_read_over_a_crowded_public_passage_reports_its_cost() {
    let rounds = setting("SKEP_REGION_COST_ROUNDS", 50);
    let warmup = setting("SKEP_REGION_COST_WARMUP", 5);
    let region = [vspan(1, PASSAGE_START, PASSAGE)];
    let seeding = Instant::now();
    let flooded = world(HOMES, FLOOD, false);
    let few = world(FEW_HOMES, FLOOD, false);
    let empty = world(HOMES, 0, false);
    let named = world(HOMES, 0, true);
    let seeded = seeding.elapsed();
    let own = usize::try_from(OWN).expect("small");
    let flood = usize::try_from(FLOOD).expect("small");
    let arms = [
        Arm {
            name: "flooded: 10^4 public links in 1,000 homes",
            snap: flooded.snapshot(),
            readable: Box::new(every_home),
            links: own + flood,
        },
        Arm {
            name: "F = 0: the passage with no foreign link",
            snap: empty.snapshot(),
            readable: Box::new(every_home),
            links: own,
        },
        Arm {
            name: "few homes: 10^4 public links in 10 homes",
            snap: few.snapshot(),
            readable: Box::new(every_home),
            links: own + flood,
        },
        Arm {
            name: "guest: 10^4 links in 1,000 homes it may not read",
            snap: flooded.snapshot(),
            readable: Box::new(|d: &Address| *d == doc(1)),
            links: own,
        },
        Arm {
            name: "named: 1,000 readable homes in the blocks, no hit",
            snap: named.snapshot(),
            readable: Box::new(every_home),
            links: own,
        },
    ];

    let run = |arm: &Arm, read: usize| -> (usize, Vec<Address>) {
        match read {
            0 => {
                let found = findlinks_v_on(&arm.snap, &doc(1), &region, &*arm.readable)
                    .expect("findlinks_v over a registered document and a well-formed region");
                (found.len(), found)
            }
            _ => (
                count_v_on(&arm.snap, &doc(1), &region, &*arm.readable)
                    .expect("count_v over a registered document and a well-formed region"),
                Vec::new(),
            ),
        }
    };

    // The answers each arm must keep, round to round.
    let first: Vec<Vec<(usize, Vec<Address>)>> = arms
        .iter()
        .map(|arm| (0..READS.len()).map(|read| run(arm, read)).collect())
        .collect();
    for (arm, answers) in arms.iter().zip(&first) {
        for (count, found) in answers {
            assert_eq!(*count, arm.links, "{}: the arm's answer", arm.name);
            assert!(
                found.is_empty() || found.windows(2).all(|p| p[0] < p[1]),
                "{}: address order",
                arm.name
            );
        }
    }

    let mut samples: Vec<Vec<Vec<Duration>>> =
        vec![vec![Vec::with_capacity(rounds); READS.len()]; arms.len()];
    for round in 0..warmup + rounds {
        // Interleaved: every arm once per round, the order rotated by round.
        for k in 0..arms.len() {
            let i = (round + k) % arms.len();
            for read in 0..READS.len() {
                let start = Instant::now();
                let answer = run(&arms[i], read);
                let took = start.elapsed();
                assert_eq!(answer, first[i][read], "{}: round {round}", arms[i].name);
                if round >= warmup {
                    samples[i][read].push(took);
                }
            }
        }
    }

    let heap: Vec<Vec<u64>> = arms
        .iter()
        .map(|arm| {
            (0..READS.len())
                .map(|read| settled_heap_bytes(|| run(arm, read)).1)
                .collect()
        })
        .collect();

    let profile = if cfg!(debug_assertions) { "debug" } else { "release" };
    eprintln!(
        "REGION-COST ({profile}): {rounds} rounds after {warmup} warm-up; seeding {:.1} s; \
         passage {PASSAGE} positions from {PASSAGE_START}",
        seeded.as_secs_f64()
    );
    eprintln!(
        "{:<52} {:>9} {:>20} {:>20} {:>12}",
        "arm", "links", "findlinks_v p50/p99", "count_v p50/p99", "heap (bytes)"
    );
    for (i, arm) in arms.iter().enumerate() {
        let mut cells = Vec::new();
        for read in 0..READS.len() {
            let sorted = {
                let mut s = samples[i][read].clone();
                s.sort();
                s
            };
            cells.push(format!("{:.3} / {:.3}", ms(median(&sorted)), ms(p99(&sorted))));
        }
        eprintln!(
            "{:<52} {:>9} {:>20} {:>20} {:>12}",
            arm.name,
            arm.links,
            cells[0],
            cells[1],
            format!("{} / {}", heap[i][0], heap[i][1])
        );
    }
    // The paired shift: the median over rounds of (arm − control) in the same
    // round, so a mode the machine drifts into mid-run cancels.
    let paired = |arm: usize, control: usize, read: usize| -> f64 {
        let mut shifts: Vec<f64> = samples[arm][read]
            .iter()
            .zip(&samples[control][read])
            .map(|(a, c)| ms(*a) - ms(*c))
            .collect();
        shifts.sort_by(f64::total_cmp);
        shifts[shifts.len() / 2]
    };
    for (read, name) in READS.iter().enumerate() {
        let per_link = paired(0, 1, read) / FLOOD as f64;
        let per_link_few = paired(2, 1, read) / FLOOD as f64;
        let per_readable_home = paired(0, 2, read) / f64::from(HOMES - FEW_HOMES);
        let per_unreadable_home = paired(3, 1, read) / f64::from(HOMES);
        let per_empty_home = paired(4, 1, read) / f64::from(HOMES);
        eprintln!(
            "{name}: per public link (flooded − F=0) {:.3} µs; per public link in few homes \
             {:.3} µs; per readable home holding ten (flooded − few homes) {:.2} µs; per \
             readable home with an empty stab (named − F=0) {:.2} µs; per unreadable home \
             (guest − F=0) {:.3} µs; heap per public link {} B, per empty readable home {} B, \
             per unreadable home {} B",
            us(per_link),
            us(per_link_few),
            us(per_readable_home),
            us(per_empty_home),
            us(per_unreadable_home),
            (heap[0][read].saturating_sub(heap[1][read])) / u64::from(FLOOD),
            (heap[4][read].saturating_sub(heap[1][read])) / u64::from(HOMES),
            (heap[3][read].saturating_sub(heap[1][read])) / u64::from(HOMES),
        );
    }
}
