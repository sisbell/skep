//! §2 — windowed enumeration: the stateless key-cut both families page by,
//! its clamp, the cursor that survives its link's departure, and what a page
//! costs, counted: its links and the homes it passes.

use crate::common;
use crate::heap::settled_heap_bytes;

use common::*;
use skep_arrangement::Vstream;
use skep_discovery::{
    find_links_v_history_on, findlinks_v_on, window_ftt_on, window_v_on, FourSet, LinkRow,
    SlotSpec,
};
use skep_kernel::Kernel;
use skep_links::{enc, HasLinks, LinkWriter};
use skep_namespace::HasM3;

/// §2 — the key-cut pages, and its cursor survives its link's departure from
/// the matched set by either of the two roads the corpus keeps apart
/// (ASN-0132): ORPHANING, where the link loses its content mapping and stays
/// active — ASN-0108's view-loss, the case W8 names — and RETRACTION, where
/// it is nullified. Resume is a cut past the cursor and never a lookup of
/// it, so neither road can fault it; each departed cursor sits between live
/// links, so a resume that restarted from the top when its cursor was gone
/// would answer wide and fail.
#[test]
fn window_v_pages_by_key_cut_and_survives_orphaning() {
    let k = kernel();
    seed_content(&k, &doc1(), 2); // V 1..2 → ca(1..2)
    let store = LinkWriter::new(&k, &EVERYONE);
    let reads = Reads(&k);
    link(&store, &doc1(), &[ca(1)], &[ca(101)]); // la(1): position 1
    link(&store, &doc1(), &[ca(2)], &[ca(102)]); // la(2): position 2 alone
    link(&store, &doc1(), &[ca(1)], &[ca(103)]); // la(3): position 1
    link(&store, &doc1(), &[ca(1)], &[ca(104)]); // la(4): position 1
    let region = [vspan(1, 1, 2)];

    // Ascending address order; next = ≺-max of the batch; full batch ⇒ not
    // exhausted.
    let w1 = reads.window_v(&doc1(), &region, None, 2).expect("window");
    assert_eq!(w1.batch, vec![la(1), la(2)]);
    assert_eq!(w1.next, Some(la(2)));
    assert!(!w1.exhausted);
    // Resume strictly past the cursor; short batch ⇒ exhausted (W9).
    let w2 = reads.window_v(&doc1(), &region, w1.next, 3).expect("window");
    assert_eq!(w2.batch, vec![la(3), la(4)]);
    assert_eq!(w2.next, Some(la(4)));
    assert!(w2.exhausted);
    // Past the end: empty batch, cursor unchanged, still exhausted.
    let w3 = reads.window_v(&doc1(), &region, w2.next, 2).expect("window");
    assert_eq!(w3.batch, vec![]);
    assert_eq!(w3.next, Some(la(4)));
    assert!(w3.exhausted);

    // n = 0 is clamped to 1 (total API) — never a false non-terminal.
    let w0 = reads.window_v(&doc1(), &region, None, 0).expect("window");
    assert_eq!(w0.batch, vec![la(1)]);
    assert!(!w0.exhausted);

    // Cursor survives ORPHANING (W8): la(2)'s only witness in doc1 leaves the
    // arrangement, so la(2) leaves the matched set by view-loss while it
    // stays active — and the key-cut resume needs no lookup of it.
    Vstream::new(&k)
        .delete(SYS, &doc1(), vp(1, 2), n(1))
        .expect("delete succeeds");
    assert!(
        k.snapshot().world().links().is_active(&la(2)),
        "orphaned, not retracted"
    );
    assert_eq!(
        reads.findlinks_v(&doc1(), &region),
        Ok(vec![la(1), la(3), la(4)])
    );
    let w4 = reads.window_v(&doc1(), &region, Some(la(2)), 5).expect("window");
    assert_eq!(w4.batch, vec![la(3), la(4)]);
    assert!(w4.exhausted);

    // And survives RETRACTION, the other road: la(3) is nullified and leaves
    // the set with its content mapping intact, and the resume past it needs
    // no lookup of it either.
    store.nullify(SYS, &doc2(), &la(3)).expect("nullify succeeds");
    let w5 = reads.window_v(&doc1(), &region, Some(la(3)), 5).expect("window");
    assert_eq!(w5.batch, vec![la(4)]);
    assert!(w5.exhausted);
}

/// §2 — W8 on the descriptor family, whose one road out of a set is
/// retraction (CN-MONO). The departed cursor sits between live links, so a
/// resume that looked it up and restarted from the top when it was gone would
/// answer wide.
#[test]
fn window_ftt_resumes_past_a_cursor_whose_link_was_retracted() {
    let k = kernel();
    seed_content(&k, &doc1(), 1);
    let store = LinkWriter::new(&k, &EVERYONE);
    let reads = Reads(&k);
    for to in [ca(101), ca(102), ca(103)] {
        link(&store, &doc1(), &[ca(1)], &[to]); // la(1..=3)
    }
    // Homed here, so the retraction tuple (homed in doc2) stays out of the set.
    let homed_here = FourSet {
        home: SlotSpec::Spans(enc(&[doc1()])),
        ..FourSet::any()
    };
    let w1 = reads.window_ftt(&homed_here, None, 2);
    assert_eq!(w1.batch, vec![la(1), la(2)]);
    store.nullify(SYS, &doc2(), &la(2)).expect("nullify succeeds");
    assert_eq!(
        reads.findlinks_ftt(&homed_here),
        vec![la(1), la(3)],
        "la(2) has left the set"
    );
    let w2 = reads.window_ftt(&homed_here, w1.next, 5);
    assert_eq!(w2.batch, vec![la(3)]);
    assert!(w2.exhausted);
}

/// §2 — EVERY `Address` is a legal cursor, including one naming a link the
/// state being read never minted: a cursor paged off the head and replayed
/// against an earlier position (`POST /op-at` runs a window frame as of one)
/// names exactly that. Resume is a cut past it, never a lookup of it, so it
/// resumes where it would have — and a cursor naming no link at all cuts by
/// the same order.
#[test]
fn a_window_resumes_past_a_cursor_its_state_never_minted() {
    let k = kernel();
    seed_content(&k, &doc1(), 1);
    let store = LinkWriter::new(&k, &EVERYONE);
    let first = link(&store, &doc1(), &[ca(1)], &[ca(101)]); // la(1)
    let theirs = link(&store, &doc2(), &[ca(1)], &[ca(102)]); // la2(1): after every doc1 link
    let earlier = k.snapshot();
    let later = link(&store, &doc1(), &[ca(1)], &[ca(103)]); // la(2), minted after `earlier`
    assert!(
        earlier.world().links().readlink(&later).is_none(),
        "the cursor names nothing at `earlier`"
    );
    let region = [vspan(1, 1, 1)];

    let head_page =
        window_v_on(&k.snapshot(), &doc1(), &region, None, 2, &every_home).expect("window");
    assert_eq!(head_page.batch, vec![first, later]);
    let resumed = window_v_on(&earlier, &doc1(), &region, head_page.next.clone(), 5, &every_home)
        .expect("any Address is a legal cursor");
    assert_eq!(resumed.batch, vec![theirs.clone()]);
    assert!(resumed.exhausted);
    assert_eq!(
        window_ftt_on(&earlier, &FourSet::any(), head_page.next, 5, &every_home).batch,
        vec![theirs.clone()]
    );
    // A cursor that is no link at all cuts the same way: doc2's own address
    // sorts after every doc1 link and before every doc2 one.
    assert_eq!(
        window_ftt_on(&earlier, &FourSet::any(), Some(doc2()), 5, &every_home).batch,
        vec![theirs]
    );
}

/// §2 — what a PASS returns under concurrent writes: a link that begins to
/// match mid-pass is returned only if it sorts past the cursor. Link
/// addresses grow within a home and not across homes, so a link minted in
/// doc1 after the pass has moved on to doc2's links is never seen by it —
/// the blind spot `Window` states, and the one W4/W5 do not cover, since
/// they speak of links that match throughout.
#[test]
fn a_pass_misses_a_link_minted_behind_its_cursor() {
    let k = kernel();
    seed_content(&k, &doc1(), 1);
    let store = LinkWriter::new(&k, &EVERYONE);
    let reads = Reads(&k);
    let first = link(&store, &doc1(), &[ca(1)], &[ca(101)]); // la(1)
    let theirs = link(&store, &doc2(), &[ca(1)], &[ca(102)]); // la2(1)
    let page = reads.window_ftt(&FourSet::any(), None, 2);
    assert_eq!(page.batch, vec![first, theirs.clone()]);
    assert!(!page.exhausted);

    let behind = link(&store, &doc1(), &[ca(1)], &[ca(103)]); // la(2)
    assert!(behind < theirs, "minted after the page, sorted behind its cursor");
    let rest = reads.window_ftt(&FourSet::any(), page.next, 2);
    assert!(rest.batch.is_empty() && rest.exhausted, "the pass ends: {rest:?}");
    assert!(
        reads.findlinks_ftt(&FourSet::any()).contains(&behind),
        "it exists when the pass ends"
    );
}

/// §2 — A WINDOW PAYS FOR ITS PAGE AND THE HOMES IT PASSES, counted (D5 of the
/// home-index record): a passage of readable links homed ten apiece in many
/// documents, read by a window of ten from the start, costs the heap beside a
/// thousand homes that it costs beside a hundred — the first home fills the
/// page, and the homes past it are never asked, never stabbed, and their
/// directory entries never stepped — in both families. `findlinks_v`, which
/// takes the whole passage, is the control and grows with the homes.
#[test]
fn a_window_pays_for_its_page_and_the_homes_it_passes() {
    let world_of = |homes: u32| {
        let k = kernel_with_documents(1 + homes);
        seed_content(&k, &doc1(), 1);
        let store = LinkWriter::new(&k, &EVERYONE);
        for h in 0..homes {
            for i in 0..10 {
                link(&store, &doc(2 + h), &[ca(1)], &[ca(100 + i)]);
            }
        }
        k
    };
    let (fewer, more) = (world_of(100), world_of(1_000));
    let region = [vspan(1, 1, 1)];
    let from_the_position = FourSet {
        from: SlotSpec::Spans(enc(&[ca(1)])),
        ..FourSet::any()
    };
    let heap_of = |k: &Kernel<World>, read: &dyn Fn(&Kernel<World>) -> usize| settled_heap_bytes(|| read(k)).1;
    let page_v = |k: &Kernel<World>| {
        let page = window_v_on(&k.snapshot(), &doc1(), &region, None, 10, &every_home).expect("window_v");
        assert_eq!(page.batch, (1..=10).map(|i| a(&[1, 0, 1, 0, 2, 0, 2, i])).collect::<Vec<_>>());
        assert!(!page.exhausted);
        page.batch.len()
    };
    let page_ftt = |k: &Kernel<World>| {
        let page = window_ftt_on(&k.snapshot(), &from_the_position, None, 10, &every_home);
        assert_eq!(page.batch.len(), 10);
        page.batch.len()
    };
    for (what, read) in [("window_v", &page_v as &dyn Fn(&Kernel<World>) -> usize), ("window_ftt", &page_ftt)] {
        assert_eq!(
            heap_of(&more, read),
            heap_of(&fewer, read),
            "{what}: a page of ten costs the first home, whatever lies past it"
        );
    }
    let whole = |k: &Kernel<World>| findlinks_v_on(&k.snapshot(), &doc1(), &region, &every_home).expect("findlinks_v").len();
    assert_eq!(whole(&more), 10_000);
    assert!(heap_of(&more, &whole) > heap_of(&fewer, &whole), "the control: the whole passage pays for every home");
}

/// §2 — THE COUNT BY HOME IS THE FOURTH READ-OUT OF THE ONE SELECTION INDEX
/// (the link-sets design §7, W10 (a)), stated over a passage whose links lie
/// in four homes — one touching at two slots, one retracted, one home named
/// by the passage's block with no hit — under every budget from the clamp
/// at 0 through one past the set: with no budget and nothing excepted the
/// rows are `findlinks_v`'s answer grouped by home, so `Σ = count_v`; with
/// `except` naming homes the rows lose exactly those homes and the sum
/// drops by exactly the links homed there, an excepted home with no hit
/// changing nothing; and under a budget `n` the rows are a prefix of the
/// full rows, `exhausted` false iff the sum reached `max(n, 1)`, the home
/// that filled it counted whole and nothing past it, `n = 0` clamped to 1.
#[test]
fn the_count_by_home_is_the_fourth_read_out_of_the_selection_index() {
    let k = kernel_with_documents(5);
    seed_content(&k, &doc1(), 3);
    let store = LinkWriter::new(&k, &EVERYONE);
    // doc1: two links on position 1.
    link(&store, &doc1(), &[ca(1)], &[ca(101)]);
    link(&store, &doc1(), &[ca(1)], &[ca(102)]);
    // doc2: three links — one touching at FROM and TO both, counted once.
    link(&store, &doc2(), &[ca(2)], &[ca(3)]);
    link(&store, &doc2(), &[ca(103)], &[ca(1)]);
    link(&store, &doc2(), &[ca(3)], &[ca(104)]);
    // doc3: one link; doc4: a link in the passage's block, off the passage;
    // doc5: two links, one retracted.
    link(&store, &doc(3), &[ca(2)], &[ca(105)]);
    link(&store, &doc(4), &[ca(50)], &[ca(106)]);
    link(&store, &doc(5), &[ca(1)], &[ca(107)]);
    let gone = link(&store, &doc(5), &[ca(3)], &[ca(108)]);
    store.nullify(SYS, &doc(5), &gone).expect("nullify succeeds");
    let reads = Reads(&k);
    let region = [vspan(1, 1, 3)];

    let all = reads.findlinks_v(&doc1(), &region).expect("findlinks_v");
    assert_eq!(all.len(), 7, "the seven live links on the passage: {all:?}");
    let full = by_home(&all);
    assert_eq!(full, vec![(doc1(), 2), (doc2(), 3), (doc(3), 1), (doc(5), 1)]);

    // No budget, nothing excepted: the enumeration grouped by home.
    let counts = reads.count_v_by_home(&doc1(), &region, usize::MAX, &[]).expect("count_v_by_home");
    assert_eq!(counts.homes, full);
    assert!(counts.exhausted);
    assert_eq!(counted(&counts), reads.count_v(&doc1(), &region).expect("count_v"));

    // Excepted homes: their rows go, the sum drops by their links, and a
    // home with no hit on the passage is passed to no effect.
    let without_doc2 = reads.count_v_by_home(&doc1(), &region, usize::MAX, &[doc2()]).expect("count_v_by_home");
    assert_eq!(without_doc2.homes, vec![(doc1(), 2), (doc(3), 1), (doc(5), 1)]);
    assert_eq!(counted(&without_doc2), all.len() - 3);
    assert!(without_doc2.exhausted);
    let excepted = [doc(4), doc2(), doc(5)];
    let fewer = reads.count_v_by_home(&doc1(), &region, usize::MAX, &excepted).expect("count_v_by_home");
    assert_eq!(fewer.homes, vec![(doc1(), 2), (doc(3), 1)]);
    assert_eq!(counted(&fewer), all.len() - 4, "the links homed in the excepted homes");
    let every = [doc1(), doc2(), doc(3), doc(5)];
    let none = reads.count_v_by_home(&doc1(), &region, 1, &every).expect("count_v_by_home");
    assert_eq!(none.homes, vec![], "every home excepted: no row");
    assert!(none.exhausted, "…and the walk ended under its budget");

    // Every budget from the clamp through one past the set.
    for n in 0..=all.len() + 1 {
        let budgeted = reads.count_v_by_home(&doc1(), &region, n, &[]).expect("count_v_by_home");
        let clamped = n.max(1);
        let sum = counted(&budgeted);
        assert!(
            full.starts_with(&budgeted.homes),
            "n = {n}: the rows are a prefix of the full rows: {budgeted:?}"
        );
        assert_eq!(budgeted.exhausted, sum < clamped, "n = {n}: exhausted iff the sum is under the budget");
        if budgeted.exhausted {
            assert_eq!(budgeted.homes, full, "n = {n}: under the budget, every home");
        } else {
            let last = budgeted.homes.last().map_or(0, |(_, c)| *c);
            assert!(sum - last < clamped, "n = {n}: the home that fills the budget is the last, counted whole");
        }
    }
    let clamp = reads.count_v_by_home(&doc1(), &region, 0, &[]).expect("count_v_by_home");
    assert_eq!(clamp.homes, vec![(doc1(), 2)], "n = 0 is clamped to 1: the first home");
    assert!(!clamp.exhausted);
}

/// §2 — THE RETRACTED-LINKS READ IS WINDOWED OVER THE AUDIT SELECTION, its
/// law its own (the link-sets design §7, lane 7; the survey's C1 — never a
/// read-out of `sel`, so the one-index law below is not extended to it):
/// over five regions and every batch size from the clamp at 0 through one
/// past the set, a pass drains `sel_audit` — `findlinks_v`'s answer with
/// the retracted link beside it, in address order — every page held to what
/// a window promises; the retracted link is a ROW of the pass, carrying the
/// retraction's position where `window_v` skips it; and a cursor naming the
/// retracted link resumes at the row past it, in both reads, by the same
/// key-cut. `n = 0` is clamped to 1.
#[test]
fn the_retracted_links_read_is_windowed_over_the_audit_selection() {
    let k = kernel();
    seed_content(&k, &doc1(), 3);
    let store = LinkWriter::new(&k, &EVERYONE);
    let reads = Reads(&k);
    for (from, to) in [
        (ca(1), ca(101)),
        (ca(2), ca(3)),
        (ca(3), ca(101)),
        (ca(1), ca(2)),
    ] {
        link(&store, &doc1(), &[from], &[to]);
    }
    // One link reaching position 2, retracted from doc2 — a row of the audit
    // answer and nothing of the active one.
    let retracted = link(&store, &doc1(), &[ca(2)], &[ca(102)]);
    assert_eq!(retracted, la(5));
    let (_, retracted_at) = store.nullify(SYS, &doc2(), &retracted).expect("nullify succeeds");
    let snap = k.snapshot();

    for region in [
        vec![],
        vec![vspan(1, 1, 1)],
        vec![vspan(1, 2, 1)],
        vec![vspan(1, 1, 3)],
        vec![vspan(1, 1, 1), vspan(1, 3, 1)],
    ] {
        let active = reads.findlinks_v(&doc1(), &region).expect("findlinks_v");
        let mut audit = active.clone();
        // The retracted link is on the audit answer exactly where position 2
        // is in the region.
        let reaches_two = region.iter().any(|s| *s == vspan(1, 2, 1) || *s == vspan(1, 1, 3));
        if reaches_two {
            audit.push(retracted.clone());
            audit.sort();
        }
        let whole = reads.find_links_v_history(&doc1(), &region, None, 64).expect("find_links_v_history");
        assert_eq!(rows_window(&whole).batch, audit, "sel_audit for {region:?}");
        assert_eq!(active_rows(&whole), active, "the active rows are findlinks_v's for {region:?}");
        for row in &whole.links {
            assert!(row.at.is_some(), "every row carries its position: {row:?}");
            assert_eq!(
                row.retracted_at,
                (row.a == retracted).then_some(retracted_at),
                "the retracted row carries its retraction's position, the rest none: {row:?}"
            );
        }
        for n in 0..=audit.len() + 1 {
            let drained = drain_window(n, audit.len() + 1, |cur| {
                rows_window(&reads.find_links_v_history(&doc1(), &region, cur, n).expect("find_links_v_history"))
            });
            assert_eq!(drained, audit, "a pass drains sel_audit for {region:?} at n = {n}");
        }
    }

    // The cursor past the retracted link: a ROW here, so a window of one from
    // the start over positions 1..3 ends on it and the next page is empty and
    // exhausted; `window_v`, which never lists it, resumes past it all the
    // same — the same key-cut, two selections.
    let region = [vspan(1, 1, 3)];
    let last = find_links_v_history_on(&snap, &doc1(), &region, Some(la(4)), 1, &every_home).expect("rows");
    assert_eq!(
        last.links,
        vec![LinkRow { a: retracted.clone(), at: Some(snap.world().m3().minted_at(&retracted).expect("minted")), retracted_at: Some(retracted_at) }]
    );
    assert!(!last.exhausted && last.next == Some(retracted.clone()));
    let past = find_links_v_history_on(&snap, &doc1(), &region, last.next, 1, &every_home).expect("rows");
    assert!(past.links.is_empty() && past.exhausted && past.next == Some(retracted.clone()));
    assert_eq!(reads.window_v(&doc1(), &region, Some(la(4)), 1).expect("window").batch, vec![]);
    assert_eq!(reads.window_v(&doc1(), &region, Some(la(3)), 1).expect("window").batch, vec![la(4)]);
    assert_eq!(rows_window(&reads.find_links_v_history(&doc1(), &region, Some(la(3)), 1).expect("rows")).batch, vec![la(4)]);
    let clamped = reads.find_links_v_history(&doc1(), &region, None, 0).expect("rows");
    assert_eq!((rows_window(&clamped).batch, clamped.exhausted), (vec![la(1)], false), "n = 0 is clamped to 1");
}

/// §2 — one selection index, read out three ways: `count_v`, `findlinks_v`
/// and `window_v` at EVERY batch size answer off the same
/// `findlinks_V ∩ addressable`, so they cannot disagree about which links
/// touch a region (W4/W5 — no continuously-matching link duplicated or
/// skipped). The descriptor family states this over five descriptors; the
/// region family is entitled to the law rather than to one hand-picked
/// pagination, so this walks five regions × every batch size from the clamp
/// at 0 through one past the set, holding every page to what a returned
/// window promises.
#[test]
fn region_count_enumeration_and_window_read_out_one_selection_index() {
    let k = kernel();
    seed_content(&k, &doc1(), 3);
    let store = LinkWriter::new(&k, &EVERYONE);
    let reads = Reads(&k);
    // Varied slot reach, so the regions below select different subsets …
    for (from, to) in [
        (ca(1), ca(101)),
        (ca(2), ca(3)),
        (ca(3), ca(101)),
        (ca(1), ca(2)),
    ] {
        link(&store, &doc1(), &[from], &[to]);
    }
    // … and one retracted link reaching position 2, which no read-out may
    // surface.
    let retracted = link(&store, &doc1(), &[ca(2)], &[ca(102)]);
    store.nullify(SYS, &doc2(), &retracted).expect("nullify succeeds");

    // The law is not vacuous: the wide region selects all four live links and
    // none of the retracted one.
    assert_eq!(
        reads.findlinks_v(&doc1(), &[vspan(1, 1, 3)]),
        Ok(vec![la(1), la(2), la(3), la(4)])
    );

    for region in [
        vec![],
        vec![vspan(1, 1, 1)],
        vec![vspan(1, 2, 1)],
        vec![vspan(1, 1, 3)],
        vec![vspan(1, 1, 1), vspan(1, 3, 1)],
    ] {
        let enumerated = reads.findlinks_v(&doc1(), &region).expect("findlinks_v");
        assert!(
            !enumerated.contains(&retracted),
            "a nullified link never surfaces: {region:?}"
        );
        assert_eq!(
            reads.count_v(&doc1(), &region),
            Ok(enumerated.len()),
            "count = |enum| for {region:?}"
        );
        // The fourth read-out: with no budget and nothing excepted, the
        // count by home is the enumeration grouped by home, and its rows sum
        // to the count.
        let counts = reads.count_v_by_home(&doc1(), &region, usize::MAX, &[]).expect("count_v_by_home");
        assert_eq!(counts.homes, by_home(&enumerated), "Σ count_v_by_home = count_v for {region:?}");
        assert_eq!(counted(&counts), enumerated.len());
        assert!(counts.exhausted, "no budget: every home reached");

        // n = 0 is the clamp (W9); n = |enumerated| is the equal case, where
        // the batch exactly drains the set and one further call is owed to
        // report exhaustion. Every clamped batch admits at least one link, so
        // a drain of `len` links owes at most `len + 1` pages.
        for n in 0..=enumerated.len() + 1 {
            let drained = drain_window(n, enumerated.len() + 1, |cur| {
                reads.window_v(&doc1(), &region, cur, n).expect("window")
            });
            assert_eq!(
                drained, enumerated,
                "the window drains sel for {region:?} at n = {n}"
            );
        }
    }
}
