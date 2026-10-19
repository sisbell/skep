//! The spanfilade over a real kernel (InMemory): `stab` answers from the
//! coverage index exactly what a scan of the store under `classify_spans`
//! would — over every slot, view and query of a world holding every span
//! shape a deposit path stores, live and after a checkpoint rebuild — and a
//! stab pays nothing for the links it cannot match.

use std::collections::HashSet;

use crate::common;
use crate::heap::settled_heap_bytes;

use common::*;
use im::OrdSet;
use skep_address::{classify_spans, subtree_of, Address, Span, SpanRel, Tumbler};
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
    // one at the wrong node or probed a level too few answers differently
    // somewhere in the pool.
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
    let pool = pool(&every);
    let (mut answered, mut nullified_found) = (0, false);
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
            }
        }
    }
    // ...and the agreement is not vacuous: most queries meet some link, and
    // the nullified one is found and then left out of the active answers.
    assert!(
        answered > pool.len(),
        "{answered} answered queries over {} in the pool",
        pool.len()
    );
    assert!(nullified_found, "a query reaches the nullified link");
}

/// Fills `k`'s store with every span shape and returns the link it nullifies.
///
/// The shapes are those a deposit path stores. Every slot holds more spans
/// than one `im` B-tree leaf holds (64 keys), so each set the index keeps
/// spans several leaves.
fn assorted(k: &Kernel<World>) -> Address {
    let w = writer(k);
    // Element-level unit spans: one link per element, a type apiece.
    let elements: Vec<Address> = (1..=70)
        .map(|i| open_deposit(&w, &[ca(i)], &[ca(2 * i), la(i)], &[unregistered_ta(i)]))
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
