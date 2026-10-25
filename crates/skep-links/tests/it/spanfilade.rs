//! The spanfilade over a real kernel (InMemory): `stab` answers from the
//! coverage index exactly what a scan of the store under `classify_spans`
//! would — over every slot, view and query of a world holding every span
//! shape a deposit path stores, live and after a checkpoint rebuild — and so
//! does the stab a reader composes over the homes it may read, against the
//! same scan filtered by each link's home; and a stab pays nothing for the
//! links it cannot match.

use std::collections::HashSet;

use crate::common;
use crate::heap::settled_heap_bytes;

use common::*;
use im::OrdSet;
use skep_address::{classify_spans, document_of, subtree_of, Address, Span, SpanRel, Tumbler};
use skep_kernel::{Kernel, WorldState};
use skep_links::{enc, Endset, HasLinks, Link, View, FROM};

#[test]
fn stab_does_not_pay_for_the_links_it_cannot_match() {
    // A stab costs its probes and its hits, so a query that matches nothing
    // costs the same over a thousand links as over a hundred: the probes are
    // the same in both, where a walk of the store allocates for every link it
    // tests.
    let world_of = |n: u32| {
        let k = kernel();
        {
            let w = writer(&k);
            for i in 1..=n {
                open_deposit(&w, &[ca(i)], &[], &[unregistered_ta(1)]);
            }
        }
        k
    };
    let (fewer, more) = (world_of(100), world_of(1_000));
    let query = enc(&[ca(5_000)]);
    let heap_of = |k: &Kernel<World>| {
        let snap = k.snapshot();
        let (hits, bytes) =
            settled_heap_bytes(|| snap.world().links().stab(FROM, &query, View::Active));
        assert!(hits.is_empty(), "nothing stored overlaps the query");
        bytes
    };
    assert_eq!(
        heap_of(&more),
        heap_of(&fewer),
        "a link the stab cannot match costs it nothing"
    );
}

#[test]
fn stab_answers_exactly_what_a_scan_of_the_store_would() {
    // The oracle walks every link and asks `classify_spans` of every pair of
    // a query span and a stored span — the relation the index splits into
    // its two halves and its residue — so an index that lost a span, filed
    // one at the wrong node, probed a level too few, or kept a home out of
    // its directory answers differently somewhere in the pool. The reader's
    // stab — the candidate homes, those the reader may read stabbed over the
    // spans that named them, concatenated — is held to the same scan
    // filtered by each link's home: the reader may read everything but doc2,
    // which homes a third of the store.
    let k = kernel();
    let nullified = assorted(&k);
    let snap = k.snapshot();
    let live = snap.world().links();
    let bytes = bincode::serialize(snap.world()).expect("world serializes");
    let decoded: World = bincode::deserialize(&bytes).expect("world deserializes");
    let rebuilt = WorldState::rebuild_derived(decoded).expect("this world's seed never refuses");
    let back = rebuilt.links();

    let every: Vec<(Address, Link)> = live
        .match_links(&[], View::Audit)
        .into_iter()
        .map(|addr| {
            let link = live
                .readlink(&addr)
                .expect("a store key names a resident link")
                .clone();
            (addr, link)
        })
        .collect();
    assert_eq!(
        back.match_links(&[], View::Audit).len(),
        every.len(),
        "one store, decoded"
    );
    let cannot_read_doc2 = |home: &Address| *home != doc2();
    let homed_outside_doc2 =
        |hits: &OrdSet<Address>| -> Vec<Address> { hits.iter().filter(|a| document_of(a) != Some(doc2())).cloned().collect() };
    let pool = pool(&every);
    let (mut answered, mut nullified_found, mut dropped) = (0, false, 0);
    for slot in 0..=4 {
        for query in &pool {
            let audit = scanned(&every, slot, query);
            let active: OrdSet<Address> = audit
                .iter()
                .filter(|addr| !live.is_nullified(addr))
                .cloned()
                .collect();
            answered += usize::from(!audit.is_empty());
            nullified_found |= audit.contains(&nullified);
            dropped += audit.len() - homed_outside_doc2(&audit).len();
            for (label, links) in [("live", live), ("rebuilt", back)] {
                let at = |view| format!("{label}, slot {slot}, {view:?}, {query:?}");
                assert_eq!(
                    links.stab(slot, query, View::Audit),
                    audit,
                    "{}",
                    at(View::Audit)
                );
                assert_eq!(
                    links.stab(slot, query, View::Active),
                    active,
                    "{}",
                    at(View::Active)
                );
                assert_eq!(
                    links.stab(slot, query, View::Default),
                    active,
                    "{}",
                    at(View::Default)
                );
                for (view, scan) in [(View::Audit, &audit), (View::Active, &active)] {
                    assert_eq!(
                        under_reader(links, slot, query, view, &cannot_read_doc2),
                        homed_outside_doc2(scan),
                        "the reader's stab: {}",
                        at(view)
                    );
                }
            }
        }
    }
    // ...and the agreement is not vacuous: most queries meet some link, the
    // nullified one is found and then left out of the active answers, and
    // the reader's filter drops something.
    assert!(
        answered > pool.len(),
        "{answered} answered queries over {} in the pool",
        pool.len()
    );
    assert!(nullified_found, "a query reaches the nullified link");
    assert!(dropped > pool.len(), "{dropped} links dropped by the reader over the pool");
}

/// The directory's block grain, measured and REPORTED: at a document of ten
/// thousand linking homes — each with one link at its own position — read
/// over a short passage of ten positions, and at an ordinary passage — a
/// hundred homes with ten links apiece at distinct positions inside a passage
/// of a hundred, and a thousand notes of one home over forty positions, S36's
/// shape — the candidate homes the directory names against the links the
/// read answers. A figure for the record, printed; the grain is
/// `spanfilade.rs`'s constant, and this test is run at each grain tried.
#[test]
#[ignore = "timing test - gate-full only"]
fn the_directory_at_its_block_grain_reports_its_candidates_against_its_hits() {
    let report = |label: &str, k: &Kernel<World>, query: &Endset| {
        let snap = k.snapshot();
        let links = snap.world().links();
        let candidates = links.homes_touching([(FROM, query)]).count();
        let hits = links.stab(FROM, query, View::Active).len();
        eprintln!("B-MEASURE {label}: candidates {candidates}, links visited {hits}");
    };
    // (A) the popular document: home i links FROM position i.
    const HOMES: u32 = 10_000;
    let popular = kernel_with_documents(HOMES);
    for i in 1..=HOMES {
        deposit_in(&popular, &doc(i), &[ca(i)], &[], &unregistered_ta(1));
    }
    report(
        "popular document, ten positions",
        &popular,
        &Endset::from_spans([iext(5_001, 5_011)]),
    );
    report(
        "popular document, one position",
        &popular,
        &enc(&[ca(5_005)]),
    );
    report(
        "popular document, a thousand positions",
        &popular,
        &Endset::from_spans([iext(5_001, 6_001)]),
    );
    // (B) the ordinary passage: a hundred homes, ten links apiece, at
    // positions h..h+9 of a passage of a hundred and nine.
    let ordinary = kernel_with_documents(100);
    for h in 1..=100 {
        for j in 0..10 {
            deposit_in(&ordinary, &doc(h), &[ca(h + j)], &[], &unregistered_ta(1));
        }
    }
    report(
        "ordinary passage, whole",
        &ordinary,
        &Endset::from_spans([iext(1, 110)]),
    );
    report(
        "ordinary passage, ten positions",
        &ordinary,
        &Endset::from_spans([iext(50, 60)]),
    );
    // (B') one home's thousand notes over forty positions, S36 (a)'s shape,
    // beside the two floor links of another home.
    let notes = kernel_with_documents(2);
    deposit_in(&notes, &doc(1), &[ca(1)], &[], &unregistered_ta(1));
    deposit_in(&notes, &doc(1), &[ca(20)], &[], &unregistered_ta(1));
    for i in 0..1_000 {
        deposit_in(&notes, &doc(2), &[ca(1 + i % 40)], &[], &unregistered_ta(1));
    }
    report(
        "a thousand notes of one home over forty positions",
        &notes,
        &Endset::from_spans([iext(1, 41)]),
    );
}

/// The stab a reader composes: the candidate homes of `query` at `slot`,
/// each the reader may read stabbed over the spans that named it, their
/// shares concatenated in home order — which the law in `discovery.rs` holds
/// to be address order.
fn under_reader(
    links: &skep_links::LinkState,
    slot: usize,
    query: &Endset,
    view: View,
    readable: &dyn Fn(&Address) -> bool,
) -> Vec<Address> {
    let mut found = Vec::new();
    for touch in links.homes_touching([(slot, query)]) {
        if readable(touch.home()) {
            found.extend(links.stab_in(touch.home(), slot, touch.spans(0), view));
        }
    }
    found
}

/// Fills `k`'s store with every span shape and returns the link it nullifies.
///
/// The shapes are those a deposit path stores. Every slot holds more spans
/// than one `im` B-tree leaf holds (64 keys), so each set the index keeps
/// spans several leaves. A third of the element-level links are homed in
/// doc2, the home the reader's law may not read.
fn assorted(k: &Kernel<World>) -> Address {
    let w = writer(k);
    // Element-level unit spans: one link per element, a type apiece — every
    // third one homed in doc2.
    let elements: Vec<Address> = (1..=70)
        .map(|i| {
            if i % 3 == 0 {
                deposit_in(k, &doc2(), &[ca(i)], &[ca(2 * i), la(i)], &unregistered_ta(i))
            } else {
                open_deposit(&w, &[ca(i)], &[ca(2 * i), la(i)], &[unregistered_ta(i)])
            }
        })
        .collect();
    // Unit spans at every other level, nested and repeated: node, account,
    // document, subspace and link addresses, a document beside its own
    // element, and an address named twice.
    open_deposit(&w, &[a(&[1])], &[a(&[1, 0, 1])], &[doc1()]);
    open_deposit(&w, &[doc1(), ca(3)], &[doc2(), doc2()], &[sib_doc()]);
    open_deposit(&w, &[la(2)], &[a(&[1, 0, 2])], &[a(&[1, 0, 1, 0, 1, 0, 1])]);
    // Extents, through `editlink`'s successor, whose slots are its caller's.
    let runs =
        |pairs: &[(u32, u32)]| Endset::from_spans(pairs.iter().map(|&(lo, hi)| iext(lo, hi)));
    let edit = |from: Endset, to: Endset, ty: u32| {
        let successor = Link::triple(from, to, unregistered_ty(100 + ty));
        w.editlink(P1, &elements[0], successor, &doc1(), &doc1())
            .expect("a level-uniform successor");
    };
    // Widths 1 to 9, and runs crossing 64.
    edit(
        runs(&[(10, 11), (12, 14), (15, 18)]),
        runs(&[(20, 24), (25, 30), (31, 37)]),
        1,
    );
    edit(
        runs(&[(40, 47), (48, 56), (57, 66)]),
        runs(&[(63, 66), (60, 70)]),
        2,
    );
    // Nested, abutting, separated and repeated.
    edit(runs(&[(1, 9), (2, 4)]), runs(&[(1, 3), (3, 5)]), 3);
    edit(runs(&[(1, 3), (7, 9)]), runs(&[(2, 4), (2, 4)]), 4);
    // Empty slots.
    edit(Endset::empty(), runs(&[(5, 6)]), 5);
    edit(runs(&[(6, 8)]), Endset::empty(), 6);
    // A run on an axis beneath an element, and runs on short axes: the
    // one-component axis under every address a fixture names.
    let between = |lo: &[u32], hi: &[u32]| Span::from_endpoints(t(lo), &t(hi)).expect("lo < hi");
    let beneath = between(
        &[1, 0, 1, 0, 1, 0, 1, 3, 0, 1, 4],
        &[1, 0, 1, 0, 1, 0, 1, 3, 0, 1, 9],
    );
    edit(
        Endset::from_spans([beneath]),
        Endset::from_spans([between(&[1, 2], &[1, 6]), between(&[1], &[3])]),
        7,
    );
    // The residue: a width nonzero ahead of its last component, from ca(5)
    // through the first link elements of doc1.
    let residue =
        Span::new(ca(5).tumbler().clone(), t(&[0, 0, 0, 0, 0, 0, 1, 3])).expect("T12 admits it");
    edit(Endset::from_spans([residue]), enc(&[ca(9)]), 8);
    w.nullify(P1, &doc1(), &elements[3]).expect("retract one");
    elements[3].clone()
}

/// Returns the query pool the agreement test asks every slot and view.
///
/// It is every stored span alone, the subtree of every prefix of every
/// stored start, every extent of doc1's first twelve elements, the
/// off-contract witness, two mixed-length spans, and each neighbouring pair
/// of those as one two-span query.
fn pool(every: &[(Address, Link)]) -> Vec<Endset> {
    let mut candidates: Vec<Endset> = Vec::new();
    for (_, link) in every {
        for span in link.slots().flat_map(Endset::spans) {
            candidates.push(Endset::from_spans([span.clone()]));
            let comps: Vec<_> = span.start().iter().cloned().collect();
            for depth in 1..=comps.len() {
                let prefix = Tumbler::new(comps[..depth].iter().cloned()).expect("nonempty");
                candidates.push(Endset::from_spans([subtree_of(&prefix)]));
            }
        }
    }
    for lo in 1..12 {
        for hi in lo + 1..=12 {
            candidates.push(Endset::from_spans([iext(lo, hi)]));
        }
    }
    candidates.push(skew());
    // A width longer than its start, and one whose reach is shorter than it.
    let deeper = Span::new(ca(3).tumbler().clone(), t(&[0, 0, 0, 0, 0, 0, 0, 4, 2])).expect("T12");
    let shorter = Span::new(ca(60).tumbler().clone(), t(&[0, 0, 0, 0, 0, 0, 1])).expect("T12");
    candidates.push(Endset::from_spans([deeper]));
    candidates.push(Endset::from_spans([shorter]));
    let mut seen: HashSet<Endset> = HashSet::new();
    let singles: Vec<Endset> = candidates
        .into_iter()
        .filter(|q| seen.insert(q.clone()))
        .collect();
    let pairs: Vec<Endset> = singles
        .windows(2)
        .map(|pair| pair[0].spans().chain(pair[1].spans()).cloned().collect())
        .collect();
    singles
        .into_iter()
        .chain(pairs.into_iter().filter(|q| seen.insert(q.clone())))
        .collect()
}

/// Returns the links of `every` whose `slot` some span of `query` overlaps.
///
/// It asks `classify_spans` of every pair of a query span and a stored span.
fn scanned(every: &[(Address, Link)], slot: usize, query: &Endset) -> OrdSet<Address> {
    every
        .iter()
        .filter(|(_, link)| {
            link.slot(slot).is_some_and(|stored| {
                query.spans().any(|q| {
                    stored.spans().any(|s| {
                        matches!(
                            classify_spans(q, s),
                            SpanRel::ProperOverlap | SpanRel::Containment | SpanRel::Equal
                        )
                    })
                })
            })
        })
        .map(|(addr, _)| addr.clone())
        .collect()
}
