use skep_address::subtree_of;

use super::*;

fn tumbler(comps: impl IntoIterator<Item = Nat>) -> Tumbler {
    Tumbler::new(comps).expect("test tumblers are nonempty")
}

/// Returns the axis every run below sits on, `[1, 0, 1]` — a content
/// axis, its last two components `0 · s_C`, so its blocks are
/// `2^BLOCK_BITS` wide — plus `tail`.
fn on_axis(tail: &[&Nat]) -> Tumbler {
    let axis = [1u32, 0, 1].map(Nat::from);
    tumbler(axis.into_iter().chain(tail.iter().map(|&c| c.clone())))
}

/// The one home every run below is filed under.
fn home() -> Home {
    Arc::new(tumbler([1u32, 0, 1, 0, 1].map(Nat::from)))
}

/// Returns the walk a query of the one span `query` opens over `index`,
/// through the directory alone: every directory range the span opens,
/// merged as a read merges them.
fn walk<'q>(index: &'q SlotIndex, query: &'q Span) -> Touching<'q> {
    let mut streams = Vec::new();
    index.streams(query, 0, 0, &mut streams);
    streams.extend(index.residue_stream(0));
    Touching::open(vec![vec![query]], streams)
}

/// Returns the candidate homes a query of the one span `query` opens, in
/// the walk's order.
fn candidates(index: &SlotIndex, query: &Span) -> Vec<Address> {
    walk(index, query).map(Touch::into_home).collect()
}

/// Returns whether a stab of `index` with the one span `query` answers,
/// asked as a read asks: of the homes the directory names, and then of each
/// one's filings at the parts of the stab whose ranges named it — so a
/// directory that misses a home the stab would hit, or names it at too few
/// parts, answers `false` here.
fn found(index: &SlotIndex, query: &Span) -> bool {
    let mut answered = false;
    for touch in walk(index, query) {
        for (span, parts) in touch.named_at(0) {
            index.stab_in_parts(touch.held(), span, parts, &mut |_| answered = true);
        }
    }
    answered
}

/// Returns the parts each candidate home of a query of the one span `query`
/// is named at, in the walk's order.
fn parts(index: &SlotIndex, query: &Span) -> Vec<Parts> {
    walk(index, query)
        .map(|touch| {
            let named: Vec<(&Span, Parts)> = touch.named_at(0).collect();
            assert_eq!(named.len(), 1, "a one-span query names its one span");
            named[0].1
        })
        .collect()
}

#[test]
fn a_sibling_run_is_found_at_exactly_the_points_it_contains() {
    // Every run [x, y) with x < y ≤ 70, filed alone, against every point
    // c < 72: at the point's own subtree, which the run starts in or
    // contains, and beneath it, where only the containing half can see
    // it. Runs reach level 7 and cross every power of two up to 64, and
    // every block boundary of the directory. The second grid straddles
    // 2^64, where the coordinates take two digits and a run crossing 2^64
    // files at level 65. A point is asked of the parts of the stab the
    // walk named its home at, so a range that stands for the wrong part
    // misses the points that part alone finds.
    let link = Arc::new(tumbler([Nat::from(9u32)]));
    let beneath_tail = Nat::from(5u32);
    for (offset, size) in [
        (Nat::from(0u32), 70u32),
        ((Nat::from(1u32) << 64u32) - 12u32, 24),
    ] {
        let probes: Vec<(Nat, Span, Span)> = (0..size + 2)
            .map(|c| {
                let point = &offset + c;
                let at = subtree_of(&on_axis(&[&point]));
                let beneath = subtree_of(&on_axis(&[&point, &beneath_tail]));
                (point, at, beneath)
            })
            .collect();
        for x in 0..size {
            for y in x + 1..=size {
                let (first, end) = (&offset + x, &offset + y);
                let run = Span::from_endpoints(on_axis(&[&first]), &on_axis(&[&end]))
                    .expect("x < y at one length");
                let mut index = SlotIndex::default();
                index.file(&home(), &link, 0, &run);
                for (point, at, beneath) in &probes {
                    let inside = first <= *point && *point < end;
                    assert_eq!(found(&index, at), inside, "[{first}, {end}) at {point}");
                    assert_eq!(
                        found(&index, beneath),
                        inside,
                        "[{first}, {end}) beneath {point}"
                    );
                }
            }
        }
    }
}

#[test]
fn the_directory_names_a_home_once_however_many_ranges_reach_it() {
    // A home with runs in two blocks of one axis and at a deeper axis,
    // beside a second home with one run: a query spanning both blocks
    // and the deeper axis names each home once, in address order, with
    // every span of the query; a query touching neither home's blocks
    // names nothing without stabbing anything.
    let (h1, h2) = (
        home(),
        Arc::new(tumbler([1u32, 0, 1, 0, 2].map(Nat::from))),
    );
    let link = Arc::new(tumbler([Nat::from(9u32)]));
    let mut index = SlotIndex::default();
    let unit = |c: u32| subtree_of(&on_axis(&[&Nat::from(c)]));
    index.file(&h1, &link, 0, &unit(3));
    index.file(&h1, &link, 1, &unit(200));
    index.file(&h1, &link, 2, &subtree_of(&on_axis(&[&Nat::from(5u32), &Nat::from(1u32)])));
    index.file(&h2, &link, 0, &unit(70));
    let whole = Span::from_endpoints(on_axis(&[&Nat::from(0u32)]), &on_axis(&[&Nat::from(300u32)]))
        .expect("a run");
    assert_eq!(
        candidates(&index, &whole),
        vec![lift_home(&h1), lift_home(&h2)]
    );
    let elsewhere = Span::from_endpoints(
        on_axis(&[&Nat::from(1000u32)]),
        &on_axis(&[&Nat::from(2000u32)]),
    )
    .expect("a run");
    assert!(candidates(&index, &elsewhere).is_empty());
    // The block grain shows in what a short query names: one home has
    // a run in the block of 70, the other has none there.
    assert_eq!(candidates(&index, &unit(71)), vec![lift_home(&h2)]);
    assert!(!found(&index, &unit(71)), "named by the block, missed by the stab");
    // On a link axis — `[1, 0, 2]`, the link subspace — the grain is one
    // coordinate: a run at link 70 is no candidate for a query at link
    // 71, so a probe at a link no claim names costs no home.
    let on_link_axis = |c: u32| {
        subtree_of(&tumbler([1u32, 0, 2, c].map(Nat::from)))
    };
    let mut links = SlotIndex::default();
    links.file(&h2, &link, 0, &on_link_axis(70));
    assert_eq!(candidates(&links, &on_link_axis(70)), vec![lift_home(&h2)]);
    assert!(candidates(&links, &on_link_axis(71)).is_empty());
}

#[test]
fn the_walk_names_each_span_at_the_parts_whose_ranges_reached_its_home() {
    // Each range of the directory stands for one part of the stab, and a
    // span carries the parts of the ranges that named its home: the block a
    // run starts in names the home at the starting half, the node a run
    // containing the query's start is filed at names it at the containing
    // half, the two together name it at both, and the residue range names
    // a home holding a span tested whole at the residue test, beside the
    // parts the span's own ranges name it at. A stab at the parts named runs
    // no other: at the starting half alone, a run only the containing half
    // finds is not found.
    let link = Arc::new(tumbler([Nat::from(9u32)]));
    let unit = |c: u32| subtree_of(&on_axis(&[&Nat::from(c)]));
    // A run at 70, in the block of 71: the block names the home for 71, and
    // no node does — a width-1 run is filed at level 0, which the probe set
    // skips on the query start's own axis.
    let mut index = SlotIndex::default();
    index.file(&home(), &link, 0, &unit(70));
    assert_eq!(parts(&index, &unit(71)), [Parts::STARTING]);
    assert!(!found(&index, &unit(71)), "named by the block, missed by the stab");
    // A run from 1 to 70, filed at level 7: its node names the home for 69,
    // and no block 69's coordinates cross holds a start.
    let run = Span::from_endpoints(on_axis(&[&Nat::from(1u32)]), &on_axis(&[&Nat::from(70u32)]))
        .expect("1 < 70 at one length");
    let mut index = SlotIndex::default();
    index.file(&home(), &link, 0, &run);
    assert_eq!(parts(&index, &unit(69)), [Parts::CONTAINING]);
    assert!(found(&index, &unit(69)), "the containing half finds it");
    let mut hits = 0;
    index.stab_in_parts(&home(), &unit(69), Parts::STARTING, &mut |_| hits += 1);
    assert_eq!(hits, 0, "the starting half alone runs no containing probe");
    // Beside it a run at 69, in 69's own block: the home is named by both
    // ranges, at both halves.
    index.file(&home(), &link, 1, &unit(69));
    assert_eq!(
        parts(&index, &unit(69)),
        [Parts::STARTING.with(Parts::CONTAINING)]
    );
    // A span that is no sibling run: the residue range names its home for
    // every query, at the residue test.
    let n = |c: u32| Nat::from(c);
    let residue = Span::new(tumbler([1, 0, 1, 5].map(n)), tumbler([0, 0, 1, 3].map(n)))
        .expect("T12 admits it");
    let mut index = SlotIndex::default();
    index.file(&home(), &link, 0, &residue);
    let at_start = subtree_of(&tumbler([1, 0, 1, 5].map(n)));
    assert_eq!(parts(&index, &at_start), [Parts::RESIDUE]);
    assert!(found(&index, &at_start), "the residue test finds it");
    // Beside it a run at 3, short of the residue span's start: the residue
    // range names the home for the whole query and the block names it for
    // the span, so the span is asked at both, and the starting half finds
    // the run the residue test misses.
    index.file(&home(), &link, 1, &unit(3));
    assert_eq!(
        parts(&index, &unit(3)),
        [Parts::RESIDUE.with(Parts::STARTING)]
    );
    assert!(found(&index, &unit(3)), "the starting half finds the run");
}

#[test]
fn the_spans_the_write_paths_store_are_sibling_runs() {
    // `enc`'s unit-depth spans at every depth, a one-component one
    // included, and an extent M5's `Run::iextent` builds.
    for comps in [&[1u32][..], &[1, 0, 1], &[1, 0, 1, 0, 1, 0, 2, 7]] {
        let t = tumbler(comps.iter().map(|&c| Nat::from(c)));
        assert!(SiblingRun::of(&subtree_of(&t)).is_some(), "{t}");
    }
    let extent =
        Span::from_endpoints(on_axis(&[&Nat::from(3u32)]), &on_axis(&[&Nat::from(9u32)]))
            .expect("an extent");
    let run = SiblingRun::of(&extent).expect("an extent is a sibling run");
    assert_eq!((run.first, run.end), (Nat::from(3u32), Nat::from(9u32)));
}

#[test]
fn a_span_that_is_no_sibling_run_is_tested_whole() {
    // `[1,0,1,5] + [0,0,1,3]` reaches `[1,0,2,3]`: its width is nonzero
    // ahead of its last component, so it is no sibling run, and neither is
    // a span whose width is longer than its start. Its home is a candidate
    // for every query, and the span is tested against each.
    let n = |c: u32| Nat::from(c);
    let span = Span::new(tumbler([1, 0, 1, 5].map(n)), tumbler([0, 0, 1, 3].map(n)))
        .expect("T12 admits it");
    let skew =
        Span::new(tumbler([5, 3].map(n)), tumbler([0, 2, 7].map(n))).expect("T12 admits it");
    assert!(SiblingRun::of(&span).is_none());
    assert!(SiblingRun::of(&skew).is_none());
    let link = Arc::new(tumbler([n(9)]));
    let mut index = SlotIndex::default();
    index.file(&home(), &link, 0, &span);
    let at = |comps: &[u32]| {
        let probe = subtree_of(&tumbler(comps.iter().map(|&c| n(c))));
        assert_eq!(candidates(&index, &probe), vec![lift_home(&home())]);
        found(&index, &probe)
    };
    assert!(at(&[1, 0, 1, 5]), "at its start");
    assert!(at(&[1, 0, 1, 9]), "past its start, on its start's axis");
    assert!(at(&[1, 0, 2, 2]), "on the next axis, short of its reach");
    assert!(!at(&[1, 0, 1, 4]), "abutting its start");
    assert!(!at(&[1, 0, 2, 3]), "abutting its reach");
    assert!(!at(&[1, 0, 1, 4, 7]), "beneath a tumbler short of it");
}
