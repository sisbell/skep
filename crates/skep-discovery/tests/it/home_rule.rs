//! The home rule (PUB-6.13), the reader argument every link read takes:
//! each read drops exactly the links homed where its reader may not read,
//! asks its predicate only of homes, once per distinct home, ahead of the
//! home's links — and, counted, pays nothing for the links of a home it may
//! not read.

use crate::common;
use crate::heap::settled_heap_bytes;

use common::*;
use skep_address::{document_of, Address};
use skep_discovery::{
    addressably_discoverable_from_on, count_ftt_on, count_v_on, delete_orphans_on,
    findlinks_ftt_on, findlinks_v_on, in_claims_on, out_claims_on, project_on, retrieve_endsets_on,
    window_ftt_on, window_v_on, FourSet, QueryError, SlotSpec, SupClaim, FROM, MAX_ANSWER_SPANS,
    TO,
};
use skep_kernel::Kernel;
use skep_links::{enc, LinkWriter, View};

/// Every result-set read drops EXACTLY the links homed where the reader may
/// not read, and counts and pages what survives (PUB-6.13, PUB-6.14,
/// PUB-6.19) — asked of each read against the same read under a reader
/// admitting every home, never against a hand-written answer. The fixture
/// homes links in both documents, every one touching doc1's content, so each
/// read-out has something to drop and something to keep. The mistake the law
/// exists for is a site that asks the home rule's question of the LINK
/// instead of its home: a link address is no draft, so it reads as published
/// and the rule admits every link — and that one read then keeps doc2's
/// links.
///
/// Two readers, because the windows page in address order and doc1's links
/// all sort ahead of doc2's. The first may read everything but doc2, so
/// every link it refuses sorts AFTER every link it keeps. The second may read
/// everything but doc1, so its refused links sort FIRST. A window that
/// stopped at the first page the rule emptied would still hand the first
/// reader every survivor, and loses all of them for the second. Every page is
/// held to the window's postconditions, so a refused link counted against `n`
/// (PUB-6.14) shows as a short page claiming more to come.
#[test]
fn every_result_set_read_drops_exactly_the_links_homed_where_the_reader_may_not_read() {
    let k = kernel();
    seed_content(&k, &doc1(), 3);
    let store = LinkWriter::new(&k, &EVERYONE);
    // doc1's: position 1; positions 2 and 3; position 3 alone.
    let m0 = link(&store, &doc1(), &[ca(1)], &[ca(101)]);
    let m1 = link(&store, &doc1(), &[ca(2)], &[ca(3)]);
    let m2 = link(&store, &doc1(), &[ca(3)], &[ca(104)]);
    // doc2's: position 1 under an endset no doc1 link carries, and position 3
    // alone under the FROM value m2 carries too.
    let t0 = link(&store, &doc2(), &[ca(1), ca(102)], &[ca(105)]);
    let t1 = link(&store, &doc2(), &[ca(3)], &[ca(103)]);
    // One supersession claim homed in each document, both with old = m0.
    let (kept, _) = store.assert_sup(SYS, &doc1(), &m0, &m1).expect("assert_sup succeeds");
    let (dropped, _) = store.assert_sup(SYS, &doc2(), &m0, &t0).expect("assert_sup succeeds");

    let snap = k.snapshot();
    let cannot_read_doc2 = |d: &Address| *d != doc2();
    let homed_outside_doc2 = |links: Vec<Address>| -> Vec<Address> {
        links
            .into_iter()
            .filter(|a| document_of(a) != Some(doc2()))
            .collect()
    };

    // The descriptor family over the unit descriptor: every link in the store.
    let q = FourSet::any();
    let all = findlinks_ftt_on(&snap, &q, &every_home);
    assert!(all.contains(&t0) && all.contains(&dropped), "doc2's links are in the store");
    let seen = findlinks_ftt_on(&snap, &q, &cannot_read_doc2);
    assert_eq!(seen, homed_outside_doc2(all), "findlinks_ftt");
    assert_eq!(count_ftt_on(&snap, &q, &cannot_read_doc2), seen.len(), "count_ftt");
    assert_eq!(
        drain_window(1, seen.len() + 1, |cur| {
            window_ftt_on(&snap, &q, cur, 1, &cannot_read_doc2)
        }),
        seen,
        "window_ftt"
    );

    // The region family over doc1's whole content.
    let region = [vspan(1, 1, 3)];
    let all = findlinks_v_on(&snap, &doc1(), &region, &every_home).expect("findlinks_v");
    assert!(all.contains(&t0) && all.contains(&t1), "doc2's links touch the region");
    let seen = findlinks_v_on(&snap, &doc1(), &region, &cannot_read_doc2).expect("findlinks_v");
    assert_eq!(seen, homed_outside_doc2(all), "findlinks_v");
    assert_eq!(
        count_v_on(&snap, &doc1(), &region, &cannot_read_doc2),
        Ok(seen.len()),
        "count_v"
    );
    assert_eq!(
        drain_window(1, seen.len() + 1, |cur| {
            window_v_on(&snap, &doc1(), &region, cur, 1, &cannot_read_doc2).expect("window_v")
        }),
        seen,
        "window_v"
    );

    // The second reader refuses doc1, whose links sort FIRST, so both windows
    // open on pages the rule empties. (It reads doc1's region though it may
    // not read doc1: the named document's own readability is the caller's
    // consult, never M8's.)
    let cannot_read_doc1 = |d: &Address| *d != doc1();
    let seen = findlinks_ftt_on(&snap, &q, &cannot_read_doc1);
    assert_eq!(
        seen,
        vec![t0.clone(), t1.clone(), dropped.clone()],
        "doc2's links survive"
    );
    assert_eq!(
        drain_window(1, seen.len() + 1, |cur| {
            window_ftt_on(&snap, &q, cur, 1, &cannot_read_doc1)
        }),
        seen,
        "window_ftt, refused links first"
    );
    let seen = findlinks_v_on(&snap, &doc1(), &region, &cannot_read_doc1).expect("findlinks_v");
    assert_eq!(seen, vec![t0.clone(), t1.clone()]);
    assert_eq!(
        drain_window(1, seen.len() + 1, |cur| {
            window_v_on(&snap, &doc1(), &region, cur, 1, &cannot_read_doc1).expect("window_v")
        }),
        seen,
        "window_v, refused links first"
    );

    // RETRIEVEENDSETS withholds identity, so what it drops is PAIRS: t0's own
    // pair goes, and the one t1 shares with m2 stays, since m2 still carries
    // it.
    let all_pairs =
        retrieve_endsets_on(&snap, &doc1(), &region, &every_home).expect("retrieve_endsets");
    assert_eq!(all_pairs.len(), 5);
    assert!(all_pairs.contains(&(FROM, enc(&[ca(1), ca(102)]))), "t0's own pair");
    assert_eq!(
        retrieve_endsets_on(&snap, &doc1(), &region, &cannot_read_doc2),
        Ok(vec![
            (FROM, enc(&[ca(1)])),
            (FROM, enc(&[ca(2)])),
            (FROM, enc(&[ca(3)])),
            (TO, enc(&[ca(3)])),
        ])
    );

    // The delete-orphan preview of position 3: m2 and t1 lose their last
    // witness, and only m2 is reported — the home rule reads the orphan set
    // after it is computed, so it never changes which links are orphaned.
    let orphaned = delete_orphans_on(&snap, &doc1(), &vp(1, 3), &n(1), &every_home)
        .expect("preview")
        .orphaned;
    assert_eq!(orphaned, vec![m2, t1]);
    assert_eq!(
        delete_orphans_on(&snap, &doc1(), &vp(1, 3), &n(1), &cannot_read_doc2)
            .map(|r| r.orphaned),
        Ok(homed_outside_doc2(orphaned))
    );

    // The lineage pair: the doc2-homed claim goes, from both probes.
    let all = claims_of(in_claims_on(&snap, &m0, View::Active, &every_home));
    assert_eq!(all, vec![kept.clone(), dropped.clone()]);
    assert_eq!(
        claims_of(in_claims_on(&snap, &m0, View::Active, &cannot_read_doc2)),
        homed_outside_doc2(all)
    );
    for new in [&m1, &t0] {
        let all = claims_of(out_claims_on(&snap, new, View::Active, &every_home));
        assert_eq!(all.len(), 1, "one claim names {new:?} as new");
        assert_eq!(
            claims_of(out_claims_on(&snap, new, View::Active, &cannot_read_doc2)),
            homed_outside_doc2(all),
            "out_claims({new:?})"
        );
    }
}

/// The home rule's contract with its predicate, over every read that takes
/// one: asked only of a candidate HOME, once per distinct home for a read's
/// life (PUB-7.15's memo, PUB-7.16, PUB-7.18), in home order, AHEAD of that
/// home's links and of every slot test — a window asks no further than it
/// walks, of its cursor's own home and the homes past it up to the one that
/// fills its `n`, and of none behind the cursor — the lineage pair of each
/// claim's home past its other filters, and the pointwise pair of `a`'s home
/// alone, never of a named `d`. Under the pure predicates every other test
/// passes, a read that asked a link, asked once per slot, asked once per
/// link of a home, asked the named document, or asked of the homes behind a
/// cursor answers exactly as the right one does; a predicate that records
/// what it is asked is where each shows.
///
/// Each link here touches the region through FROM and TO both, which is what
/// separates one ask per home from one ask per `(home, slot)`; doc1 holds two
/// of the three links, which is what separates one ask per home from one per
/// link; and `d` is itself a home, so a preview that consulted its `d` shows
/// as a repeated ask rather than as a different address.
#[test]
fn the_home_rule_asks_its_predicate_once_per_candidate_and_only_of_homes() {
    let k = kernel();
    seed_content(&k, &doc1(), 1);
    let store = LinkWriter::new(&k, &EVERYONE);
    for home in [doc1(), doc1(), doc2()] {
        link(&store, &home, &[ca(1)], &[ca(1)]); // la(1), la(2), la2(1)
    }
    let snap = k.snapshot();
    let asked = Asked::default();
    let recorder = asked.recorder();
    let homes = vec![doc1(), doc2()];
    let region = [vspan(1, 1, 1)];

    // The three links' two homes, each once, in home order — never a home
    // per link, never a home per slot.
    let found = findlinks_v_on(&snap, &doc1(), &region, &recorder).expect("findlinks_v");
    assert_eq!(found.len(), 3);
    assert_eq!(asked.take(), homes);
    let found = findlinks_ftt_on(&snap, &FourSet::any(), &recorder);
    assert_eq!(found.len(), 3);
    assert_eq!(asked.take(), homes);
    // The counts ask exactly what their enumerations ask.
    assert_eq!(count_v_on(&snap, &doc1(), &region, &recorder), Ok(3));
    assert_eq!(asked.take(), homes);
    assert_eq!(count_ftt_on(&snap, &FourSet::any(), &recorder), 3);
    assert_eq!(asked.take(), homes);
    // A window of one asks of the one home that fills it, and stops.
    assert_eq!(
        window_ftt_on(&snap, &FourSet::any(), None, 1, &recorder).batch,
        vec![la(1)]
    );
    assert_eq!(asked.take(), vec![doc1()]);
    assert_eq!(
        window_v_on(&snap, &doc1(), &region, None, 1, &recorder)
            .expect("window_v")
            .batch,
        vec![la(1)]
    );
    assert_eq!(asked.take(), vec![doc1()]);
    // … a window RESUMED past a cursor asks of the cursor's own home — cut
    // past the cursor, which here leaves it nothing — and of the homes past
    // it that it reaches …
    assert_eq!(
        window_ftt_on(&snap, &FourSet::any(), Some(la(2)), 1, &recorder).batch,
        vec![la2(1)]
    );
    assert_eq!(asked.take(), homes);
    assert_eq!(
        window_v_on(&snap, &doc1(), &region, Some(la(2)), 1, &recorder)
            .expect("window_v")
            .batch,
        vec![la2(1)]
    );
    assert_eq!(asked.take(), homes);
    // … and of none BEHIND the cursor: resumed in doc2, doc1 is passed
    // unasked, in both families.
    assert_eq!(
        window_ftt_on(&snap, &FourSet::any(), Some(doc2()), 1, &recorder).batch,
        vec![la2(1)]
    );
    assert_eq!(asked.take(), vec![doc2()]);
    assert_eq!(
        window_v_on(&snap, &doc1(), &region, Some(doc2()), 1, &recorder)
            .expect("window_v")
            .batch,
        vec![la2(1)]
    );
    assert_eq!(asked.take(), vec![doc2()]);
    // RETRIEVEENDSETS asks of each HOME, ONCE, before any of its links' slots
    // are read: each link reaches the region through FROM and TO, so a rule
    // asked per (link, slot) asks twice for each link.
    assert_eq!(
        retrieve_endsets_on(&snap, &doc1(), &region, &recorder),
        Ok(vec![(FROM, enc(&[ca(1)])), (TO, enc(&[ca(1)]))])
    );
    assert_eq!(asked.take(), homes);
    // The preview asks about the homes of the links touching the deleted
    // range and never about the `d` it is asked at — which is doc1 here, so a
    // consult of `d` would show as doc1 twice.
    let report = delete_orphans_on(&snap, &doc1(), &vp(1, 1), &n(1), &recorder).expect("preview");
    assert_eq!(report.orphaned.len(), 3);
    assert_eq!(asked.take(), homes);
    // "Past its OTHER filters": under a home-bound descriptor only the
    // residing candidate's home is asked, in the enumeration, the count and
    // the window's lazy key-cut alike.
    let homed_in_doc2 = FourSet {
        home: SlotSpec::Spans(enc(&[doc2()])),
        ..FourSet::any()
    };
    assert_eq!(findlinks_ftt_on(&snap, &homed_in_doc2, &recorder), vec![la2(1)]);
    assert_eq!(asked.take(), vec![doc2()]);
    assert_eq!(count_ftt_on(&snap, &homed_in_doc2, &recorder), 1);
    assert_eq!(asked.take(), vec![doc2()]);
    assert_eq!(
        window_ftt_on(&snap, &homed_in_doc2, None, 5, &recorder).batch,
        vec![la2(1)]
    );
    assert_eq!(asked.take(), vec![doc2()]);
    // Where the HOME SLOT drives, the rule is asked once per distinct home
    // under it, in home order, ahead of that home's links (PUB-7.18): doc1
    // holds two of the three links and is asked once, in the enumeration and
    // the count alike; the window of one asks of doc1 alone, which fills it.
    let under_the_account = FourSet {
        home: SlotSpec::Spans(enc(&[a(&[1, 0, 1])])),
        ..FourSet::any()
    };
    assert_eq!(findlinks_ftt_on(&snap, &under_the_account, &recorder), found);
    assert_eq!(asked.take(), homes);
    assert_eq!(count_ftt_on(&snap, &under_the_account, &recorder), 3);
    assert_eq!(asked.take(), homes);
    assert_eq!(
        window_ftt_on(&snap, &under_the_account, None, 1, &recorder).batch,
        vec![la(1)]
    );
    assert_eq!(asked.take(), vec![doc1()]);
    // …and AHEAD of the link-slot tests: a home none of whose links meets the
    // FROM constraint is asked all the same, once, before its links are
    // tested, so an unreadable home's links are never read at all.
    let under_the_account_from_elsewhere = FourSet {
        home: SlotSpec::Spans(enc(&[a(&[1, 0, 1])])),
        from: SlotSpec::Spans(enc(&[ca(2)])),
        ..FourSet::any()
    };
    assert_eq!(
        findlinks_ftt_on(&snap, &under_the_account_from_elsewhere, &recorder),
        vec![]
    );
    assert_eq!(asked.take(), homes);
    // Where a LINK SLOT drives, the candidate homes its directory names are
    // asked, once each, ahead of their links — a home with a link at the
    // position though none meets the other constraint included.
    let from_the_position_typed_otherwise = FourSet {
        from: SlotSpec::Spans(enc(&[ca(1)])),
        ty: SlotSpec::Spans(enc(&[rel2()])),
        ..FourSet::any()
    };
    assert_eq!(
        findlinks_ftt_on(&snap, &from_the_position_typed_otherwise, &recorder),
        vec![]
    );
    assert_eq!(asked.take(), vec![], "a type no link carries names no home");
    let from_the_position = FourSet {
        from: SlotSpec::Spans(enc(&[ca(1)])),
        to: SlotSpec::Spans(enc(&[ca(1)])),
        ..FourSet::any()
    };
    assert_eq!(findlinks_ftt_on(&snap, &from_the_position, &recorder), found);
    assert_eq!(asked.take(), homes);
    // The lineage pair asks of each claim's home, at the claim's identity.
    let (claim, _) = store.assert_sup(SYS, &doc2(), &la(1), &la(2)).expect("assert_sup succeeds");
    let snap = k.snapshot();
    assert_eq!(claims_of(in_claims_on(&snap, &la(1), View::Active, &recorder)), vec![claim]);
    assert_eq!(asked.take(), vec![doc2()]);
    // The pointwise pair asks `a`'s home once, and of a homeless `a` nothing.
    project_on(&snap, &la2(1), FROM, &doc1(), &recorder).expect("project");
    assert_eq!(asked.take(), vec![doc2()]);
    assert_eq!(
        addressably_discoverable_from_on(&snap, &a(&[1, 0, 1]), &doc1(), &recorder),
        Err(QueryError::NotALink)
    );
    assert_eq!(asked.take(), vec![]);
}

/// §6 — the preview asks the home rule (PUB-6.13) of the homes the link
/// store names for the DELETED range, once each, ahead of their links — and
/// never of a home named for the retained content alone, which the delete
/// leaves witnessed whatever it holds (PUB-7.15, PUB-7.16). The once-per-home
/// law's fixture orphans every link it holds, where a home touching only the
/// retained side cannot show; here one home's link survives at the retained
/// position beside a deleted one and is asked, as the deleted side names it,
/// and a third home links a retained position in another block of the
/// content axis alone and is never asked. Neither is `d`, which is the
/// orphan's home here and would show as a repeat. The store names homes at
/// block grain — a home linking a retained position in the deleted
/// position's own block of sixty-four is named and asked all the same, the
/// residual PUB-7.18 accepts — which is why the third home links far away.
#[test]
fn the_preview_asks_its_predicate_only_of_the_links_it_orphans() {
    let k = kernel();
    seed_content(&k, &doc1(), 70);
    let store = LinkWriter::new(&k, &EVERYONE);
    let orphan = link(&store, &doc1(), &[ca(1)], &[ca(101)]); // la(1): position 1 alone
    link(&store, &doc2(), &[ca(1)], &[ca(2)]); // la2(1): deleted position 1, witnessed at position 2 too
    link(&store, &pdoc(), &[ca(70)], &[ca(102)]); // retained position 70 alone, in the next block
    let snap = k.snapshot();
    let asked = Asked::default();
    let recorder = asked.recorder();
    let report = delete_orphans_on(&snap, &doc1(), &vp(1, 1), &n(1), &recorder).expect("preview");
    assert_eq!(report.orphaned, vec![orphan]);
    assert_eq!(
        asked.take(),
        vec![doc1(), doc2()],
        "the homes named for the deleted position, once each — the home linking a retained position alone is never asked"
    );
}

/// A world of `flood` links FROM doc1's position 1, homed round-robin in
/// `homes` documents past doc2, beside two of doc1's own on the same position
/// and one of doc2's on position 70 alone — another block of the content
/// axis, so the passage's directory never names doc2 — the fixture the home
/// rule's cost laws read at two floods and two home counts.
fn flooded_homes(flood: u32, homes: u32) -> Kernel<World> {
    let k = kernel_with_documents(2 + homes);
    seed_content(&k, &doc1(), 2);
    let store = LinkWriter::new(&k, &EVERYONE);
    link(&store, &doc1(), &[ca(1)], &[ca(101)]);
    link(&store, &doc1(), &[ca(1)], &[ca(102)]);
    link(&store, &doc2(), &[ca(70)], &[ca(103)]); // off the passage, in another block
    for i in 0..flood {
        link(&store, &doc(3 + i % homes), &[ca(1)], &[ca(1_000 + i)]);
    }
    k
}

/// The heap bytes a read of `k`'s current state asks for, on its second run.
fn heap_of<T>(k: &Kernel<World>, read: impl Fn(&Kernel<World>) -> T) -> u64 {
    settled_heap_bytes(|| read(k)).1
}

/// A read of a kernel's current state answering a count, as the cost laws
/// compare them.
type Counted<'a> = dyn Fn(&Kernel<World>) -> usize + 'a;

/// THE WORK MOVES, counted (PUB-7.18 at the region family; S36 (a)): a region
/// read over a passage holding a flood of links homed where the reader may
/// not read asks of those homes once each and reads none of their links. A
/// thousand flooding links in ten homes cost the reader's `findlinks_v`,
/// `count_v` and `window_v` the heap a hundred do — the homes are the same
/// ten, and the links in them are never visited — and the same thousand in
/// ONE home cost what a hundred in one do: one home test. The reader of every
/// home is the control and pays for every hit. A home whose links lie off
/// the passage is never asked, so the homes asked are the passage's
/// candidates and not the board's.
#[test]
fn a_region_read_pays_for_the_homes_the_reader_may_not_read_and_none_of_their_links() {
    let region = [vspan(1, 1, 1)];
    let only_doc1 = |d: &Address| *d == doc1();
    let reads: [(&str, &Counted<'_>); 3] = [
        ("findlinks_v", &|k| {
            findlinks_v_on(&k.snapshot(), &doc1(), &region, &only_doc1).expect("findlinks_v").len()
        }),
        ("count_v", &|k| count_v_on(&k.snapshot(), &doc1(), &region, &only_doc1).expect("count_v")),
        ("window_v", &|k| {
            window_v_on(&k.snapshot(), &doc1(), &region, None, 5, &only_doc1).expect("window_v").batch.len()
        }),
    ];
    for homes in [1, 10] {
        let (fewer, more) = (flooded_homes(100, homes), flooded_homes(1_000, homes));
        for k in [&fewer, &more] {
            assert_eq!(
                findlinks_v_on(&k.snapshot(), &doc1(), &region, &only_doc1),
                Ok(vec![la(1), la(2)]),
                "doc1's two, whatever the flood"
            );
            // The homes asked: doc1 and the flood's, once each, in home order
            // — never doc2, whose link lies off the passage and outside its
            // block.
            let asked = Asked::default();
            let recorder = asked.recording(only_doc1);
            findlinks_v_on(&k.snapshot(), &doc1(), &region, &recorder).expect("findlinks_v");
            let expected: Vec<Address> = std::iter::once(doc1()).chain((0..homes).map(|i| doc(3 + i))).collect();
            assert_eq!(asked.take(), expected, "once per home the passage names");
        }
        for (what, read) in reads {
            assert_eq!(
                heap_of(&more, read),
                heap_of(&fewer, read),
                "{what} beside {homes} unreadable home(s): the flood's links cost nothing"
            );
        }
    }
    // The control: the reader of every home pays for every hit.
    let (fewer, more) = (flooded_homes(100, 10), flooded_homes(1_000, 10));
    let everyone = |k: &Kernel<World>| findlinks_v_on(&k.snapshot(), &doc1(), &region, &every_home).expect("findlinks_v").len();
    assert_eq!(everyone(&more), 1_002);
    assert!(heap_of(&more, everyone) > heap_of(&fewer, everyone), "the control pays for the flood");
}

/// §4 — PUB-6.15: filtered at link HOME, UNFILTERED at origin. The home rule
/// decides which links contribute a pair and never reaches into a surviving
/// link's endset. The result-set law cannot see this: every link its readers
/// keep names only addresses under one document, where an endset clipped to
/// the reader is unchanged. Here a doc1-homed link names doc2's content too.
#[test]
fn retrieve_endsets_filters_at_the_links_home_and_ships_its_endset_whole_at_origin() {
    let k = kernel();
    seed_content(&k, &doc1(), 1);
    let store = LinkWriter::new(&k, &EVERYONE);
    link(&store, &doc1(), &[ca(1), ca2(1)], &[ca(101)]); // homed in doc1, naming doc2 too
    link(&store, &doc2(), &[ca(1)], &[ca(102)]); // homed in doc2
    let snap = k.snapshot();
    let region = [vspan(1, 1, 1)];
    assert_eq!(
        retrieve_endsets_on(&snap, &doc1(), &region, &every_home),
        Ok(vec![(FROM, enc(&[ca(1)])), (FROM, enc(&[ca(1), ca2(1)]))])
    );
    let cannot_read_doc2 = |d: &Address| *d != doc2();
    assert_eq!(
        retrieve_endsets_on(&snap, &doc1(), &region, &cannot_read_doc2),
        Ok(vec![(FROM, enc(&[ca(1), ca2(1)]))]),
        "the doc2-homed link's pair goes; the doc1-homed link's endset ships whole"
    );
}

/// §4 — the span budget prices the READER's own answer, not the store's: a
/// link the home rule refuses contributes no pair and no spans (PUB-6.15), so
/// a region whose whole answer is one span past the budget is still answered
/// to a reader that cannot see the link carrying that span. A budget summed
/// over the candidates instead would refuse a sixty-four-pair answer — and
/// the refusal would tell that reader that links they may not see exist, on a
/// verdict `QueryError` says they cannot reshape their way past. Every other
/// budget test runs under the total predicate and every other home-rule test
/// runs far under the budget, so neither can see this.
#[test]
fn retrieve_endsets_prices_its_span_budget_over_the_readers_own_answer() {
    const SPANS: u32 = 1024;
    let at_budget = MAX_ANSWER_SPANS / SPANS as usize; // 64 whole endsets
    let k = kernel();
    seed_content(&k, &doc1(), 1);
    let store = LinkWriter::new(&k, &EVERYONE);
    for i in 0..at_budget as u32 {
        link(&store, &doc1(), &wide_from(i, SPANS), &[ca(101)]);
    }
    // One span more, homed where the second reader may not read.
    link(&store, &doc2(), &[ca(1)], &[ca(101)]);
    let snap = k.snapshot();
    let region = [vspan(1, 1, 1)];

    assert_eq!(
        retrieve_endsets_on(&snap, &doc1(), &region, &every_home),
        Err(QueryError::EndsetsTooLarge),
        "the whole answer is one span past the budget"
    );
    let cannot_read_doc2 = |d: &Address| *d != doc2();
    let pairs = retrieve_endsets_on(&snap, &doc1(), &region, &cannot_read_doc2)
        .expect("this reader's own answer is AT the budget, not past it");
    assert_eq!(pairs.len(), at_budget);
    assert!(pairs
        .iter()
        .all(|(i, e)| *i == FROM && e.len() == SPANS as usize));
}

/// §7 — the home rule is asked of the CLAIM's own address, and a surviving
/// claim's endpoints read out as recorded, whatever the reader may read. The
/// result-set law's claims each share a home with their `new`, so a read that
/// asked `new`'s home would answer exactly as the right one there; here the
/// two part. One probe key, `theirs`, is homed where the reader may not read:
/// the key is a filter value (PUB-6.12), so the claims naming it are listed
/// under the same result-set filter, while the pointwise pair reads the same
/// address as absent (PUB-6.6).
#[test]
fn the_lineage_pair_asks_the_home_rule_of_the_claim_and_reads_its_endpoints_as_recorded() {
    let k = kernel();
    seed_content(&k, &doc1(), 1);
    let store = LinkWriter::new(&k, &EVERYONE);
    let e1 = link(&store, &doc1(), &[ca(1)], &[ca(101)]);
    let e2 = link(&store, &doc1(), &[ca(1)], &[ca(102)]);
    let theirs = link(&store, &doc2(), &[ca(1)], &[ca(103)]);
    // Homed in doc1, naming a doc2 link as new …
    let (kept, _) = store
        .assert_sup(SYS, &doc1(), &e1, &theirs)
        .expect("assert_sup succeeds");
    // … and homed in doc2, naming only doc1 links.
    let (dropped, _) = store
        .assert_sup(SYS, &doc2(), &e1, &e2)
        .expect("assert_sup succeeds");
    let snap = k.snapshot();
    assert_eq!(
        claims_of(in_claims_on(&snap, &e1, View::Active, &every_home)),
        vec![kept.clone(), dropped.clone()]
    );
    assert_eq!(
        claims_of(out_claims_on(&snap, &e2, View::Active, &every_home)),
        vec![dropped]
    );

    let cannot_read_doc2 = |d: &Address| *d != doc2();
    // The KEY is a filter value (PUB-6.12), never consulted: `theirs` is homed
    // in doc2, which this reader may not read, and the claim naming it —
    // homed in doc1 — is listed all the same. As an ARGUMENT, the same address
    // is absent (PUB-6.6): discoverable from doc1 in truth, `NotALink` to this
    // reader — exactly as an address no link occupies, never `false`.
    assert_eq!(
        claims_of(out_claims_on(&snap, &theirs, View::Active, &cannot_read_doc2)),
        vec![kept.clone()]
    );
    assert_eq!(
        addressably_discoverable_from_on(&snap, &theirs, &doc1(), &every_home),
        Ok(true)
    );
    assert_eq!(
        addressably_discoverable_from_on(&snap, &theirs, &doc1(), &cannot_read_doc2),
        Err(QueryError::NotALink)
    );
    assert_eq!(
        in_claims_on(&snap, &e1, View::Active, &cannot_read_doc2),
        vec![SupClaim {
            claim: kept,
            old: e1,
            new: theirs,
            home: doc1(),
            active: true,
        }]
    );
    assert_eq!(
        out_claims_on(&snap, &e2, View::Active, &cannot_read_doc2),
        vec![]
    );
}
