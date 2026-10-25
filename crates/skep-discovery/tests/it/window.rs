//! §2 — windowed enumeration: the stateless key-cut both families page by,
//! its clamp, the cursor that survives its link's departure, and what a page
//! costs, counted: its links and the homes it passes.

use crate::common;
use crate::heap::settled_heap_bytes;

use common::*;
use skep_arrangement::Vstream;
use skep_discovery::{findlinks_v_on, window_ftt_on, window_v_on, FourSet, SlotSpec};
use skep_kernel::Kernel;
use skep_links::{enc, HasLinks, LinkWriter};

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
