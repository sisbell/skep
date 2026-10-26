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

use std::time::{Duration, Instant};

use crate::common;
use crate::heap::settled_heap_bytes;

use common::*;
use skep_address::Address;
use skep_discovery::{count_v_on, findlinks_v_on};
use skep_kernel::{Kernel, Snapshot};
use skep_links::LinkWriter;

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
