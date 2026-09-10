//! The home rule (PUB-6.13), the reader argument every link read takes:
//! each read drops exactly the links homed where its reader may not read,
//! and asks its predicate only of homes, once per candidate.

use crate::common;

use std::cell::RefCell;

use common::*;
use skep_address::{document_of, Address};
use skep_discovery::{
    addressably_discoverable_from_on, count_ftt_on, count_v_on, delete_orphans_on,
    findlinks_ftt_on, findlinks_v_on, in_claims_on, out_claims_on, project_on, retrieve_endsets_on,
    window_ftt_on, window_v_on, FourSet, QueryError, SupClaim, FROM, TO,
};
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
    let survivors = |links: Vec<Address>| -> Vec<Address> {
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
    assert_eq!(seen, survivors(all), "findlinks_ftt");
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
    assert_eq!(seen, survivors(all), "findlinks_v");
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
    let every_pair =
        retrieve_endsets_on(&snap, &doc1(), &region, &every_home).expect("retrieve_endsets");
    assert_eq!(every_pair.len(), 5);
    assert!(every_pair.contains(&(FROM, enc(&[ca(1), ca(102)]))), "t0's own pair");
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
        Ok(survivors(orphaned))
    );

    // The lineage pair: the doc2-homed claim goes, from both probes.
    let claims_of =
        |found: Vec<SupClaim>| -> Vec<Address> { found.into_iter().map(|c| c.claim).collect() };
    let all = claims_of(in_claims_on(&snap, &m0, View::Active, &every_home));
    assert_eq!(all, vec![kept.clone(), dropped.clone()]);
    assert_eq!(
        claims_of(in_claims_on(&snap, &m0, View::Active, &cannot_read_doc2)),
        survivors(all)
    );
    for new in [&m1, &t0] {
        let all = claims_of(out_claims_on(&snap, new, View::Active, &every_home));
        assert_eq!(all.len(), 1, "one claim names {new:?} as new");
        assert_eq!(
            claims_of(out_claims_on(&snap, new, View::Active, &cannot_read_doc2)),
            survivors(all),
            "out_claims({new:?})"
        );
    }
}

/// The home rule's contract with its predicate: asked only of a candidate's
/// HOME, at most once per candidate (PUB-7.15, PUB-7.16) — a window asks no
/// further than it walks — and of the pointwise pair's `a` alone, never of a
/// named `d`. Under the pure predicates every other test passes, a read that
/// asked a link, asked twice, or asked the named document answers exactly as
/// the right one does; a predicate that records what it is asked is where
/// each shows.
#[test]
fn the_home_rule_asks_its_predicate_once_per_candidate_and_only_of_homes() {
    let k = kernel();
    seed_content(&k, &doc1(), 1);
    let store = LinkWriter::new(&k, &EVERYONE);
    for home in [doc1(), doc1(), doc2()] {
        link(&store, &home, &[ca(1)], &[ca(101)]); // la(1), la(2), la2(1)
    }
    let snap = k.snapshot();
    let asked: RefCell<Vec<Address>> = RefCell::new(Vec::new());
    let recorder = |d: &Address| {
        asked.borrow_mut().push(d.clone());
        true
    };
    let homes_of = |links: &[Address]| -> Vec<Address> {
        links
            .iter()
            .map(|l| document_of(l).expect("a link has a home"))
            .collect()
    };
    let sorted = |mut v: Vec<Address>| {
        v.sort();
        v
    };

    let found = findlinks_v_on(&snap, &doc1(), &[vspan(1, 1, 1)], &recorder)
        .expect("findlinks_v");
    assert_eq!(found.len(), 3);
    assert_eq!(sorted(asked.take()), sorted(homes_of(&found)));
    let found = findlinks_ftt_on(&snap, &FourSet::any(), &recorder);
    assert_eq!(found.len(), 3);
    assert_eq!(sorted(asked.take()), sorted(homes_of(&found)));
    // A window of one asks of the one candidate it admits, and stops.
    assert_eq!(
        window_ftt_on(&snap, &FourSet::any(), None, 1, &recorder).batch,
        vec![la(1)]
    );
    assert_eq!(asked.take(), vec![doc1()]);
    // The pointwise pair asks `a`'s home once, and of a homeless `a` nothing.
    assert!(project_on(&snap, &la2(1), FROM, &doc1(), &recorder).is_ok());
    assert_eq!(asked.take(), vec![doc2()]);
    assert_eq!(
        addressably_discoverable_from_on(&snap, &a(&[1, 0, 1]), &doc1(), &recorder),
        Err(QueryError::NotALink)
    );
    assert_eq!(asked.take(), vec![]);
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
    let (refused, _) = store
        .assert_sup(SYS, &doc2(), &e1, &e2)
        .expect("assert_sup succeeds");
    let snap = k.snapshot();
    let claims_of =
        |found: Vec<SupClaim>| -> Vec<Address> { found.into_iter().map(|c| c.claim).collect() };
    assert_eq!(
        claims_of(in_claims_on(&snap, &e1, View::Active, &every_home)),
        vec![kept.clone(), refused.clone()]
    );
    assert_eq!(
        claims_of(out_claims_on(&snap, &e2, View::Active, &every_home)),
        vec![refused]
    );

    let cannot_read_doc2 = |d: &Address| *d != doc2();
    // The KEY is a filter value (PUB-6.12), never consulted: `theirs` is homed
    // in doc2, which this reader may not read, and the claim naming it —
    // homed in doc1 — is listed all the same. As an ARGUMENT, the same address
    // is absent (PUB-6.6): discoverable from doc1 in truth, `false` to this
    // reader.
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
        Ok(false)
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
