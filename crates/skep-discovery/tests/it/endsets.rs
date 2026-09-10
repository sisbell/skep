//! §4 — RETRIEVEENDSETS: identity withheld, endsets whole, a total pinned
//! order, and the span budget that prices what the answer carries.

use crate::common;

use common::*;
use skep_discovery::{QueryError, FROM, MAX_ENDSET_SPANS, TO, TYPE};
use skep_links::{enc, Endset, LinkWriter, SlotArg, MAX_SLOT_SPANS};

#[test]
fn retrieve_endsets_withholds_identity_and_ships_whole_endsets_in_pinned_order() {
    let k = kernel();
    seed_content(&k, &doc1(), 3);
    let store = LinkWriter::new(&k, &EVERYONE);
    let reads = Reads(&k);
    // Two distinct links with VALUE-IDENTICAL from-endsets (dedup collapse),
    // plus one makelink whose from spans all three positions.
    link(&store, &doc1(), &[ca(1)], &[ca(101)]);
    link(&store, &doc1(), &[ca(1)], &[ca(102)]);
    store
        .makelink(
            SYS,
            &doc1(),
            SlotArg::Resolve(vec![spec(&doc1(), 1, 1, 3)]),
            SlotArg::Resolve(vec![spec(&doc1(), 1, 3, 1)]),
            SlotArg::Resolve(vec![spec(&doc1(), 1, 1, 1)]),
        )
        .expect("makelink succeeds");
    let whole = Endset::from_spans([run(&ca(1), 3).iextent()]);

    // A query touching only position 2 surfaces the WHOLE stored endset,
    // never a clip (RE-CLIP/RE-WHOLE); abutting endsets (the two `link`
    // fixtures' enc({ca1}) at position 1, the resolved makelink's TO at 3 and
    // TYPE at 1) are Adjacent to the image — not matches.
    assert_eq!(
        reads.retrieve_endsets(&doc1(), &[vspan(1, 2, 1)]),
        Ok(vec![(FROM, whole.clone())])
    );

    // The wide query: identity withheld — the two `link` fixtures collapse to
    // ONE (FROM, enc({ca1})) pair (RE-UNIT) — and the output order is pinned:
    // slot, then lexicographic span-sequence.
    assert_eq!(
        reads.retrieve_endsets(&doc1(), &[vspan(1, 1, 3)]),
        Ok(vec![
            (FROM, enc(&[ca(1)])),
            (FROM, whole),
            (TO, Endset::from_spans([run(&ca(3), 1).iextent()])),
            (TYPE, Endset::from_spans([run(&ca(1), 1).iextent()])),
        ])
    );
}

/// §4 — the pinned order is TOTAL: fourteen FROM endsets that tie on every
/// key but one — eight sharing their one span's start and differing in its
/// width, six sharing their first span and differing in the second — come
/// back in one order, twice, whatever order the throwaway hash set held them
/// in. `enc(&[ca(1)])` and the width-1 run's extent are one span (both are
/// `ca(1)` to the next position at its length), so the width-1 endset is a
/// strict prefix of every two-span one, and each of those sorts ahead of
/// every wider single span.
#[test]
fn retrieve_endsets_orders_pairs_that_tie_on_every_key_but_the_last() {
    let k = kernel();
    seed_content(&k, &doc1(), 8); // one run: V 1..8 → ca(1..8)
    let store = LinkWriter::new(&k, &EVERYONE);
    let reads = Reads(&k);
    for w in 1..=8 {
        store
            .makelink(
                SYS,
                &doc1(),
                SlotArg::Resolve(vec![spec(&doc1(), 1, 1, w)]),
                SlotArg::Addrs(vec![ca(101)]),
                SlotArg::Addrs(vec![rel()]),
            )
            .expect("makelink succeeds");
    }
    for j in 3..=8 {
        link(&store, &doc1(), &[ca(1), ca(j)], &[ca(101)]);
    }
    let one = |w: u32| (FROM, Endset::from_spans([run(&ca(1), w).iextent()]));
    let two = |j: u32| (FROM, enc(&[ca(1), ca(j)]));
    let expected: Vec<(usize, Endset)> = std::iter::once(one(1))
        .chain((3..=8).map(two))
        .chain((2..=8).map(one))
        .collect();
    for _ in 0..2 {
        assert_eq!(
            reads.retrieve_endsets(&doc1(), &[vspan(1, 1, 1)]),
            Ok(expected.clone())
        );
    }
}

/// §4 — the answer's span budget, at its boundary. The amplification it
/// prices is the one no request-shaped cap reaches: a two-hundred-byte query
/// naming ONE position, answered with every whole endset touching it, each of
/// which M7 admits at `MAX_SLOT_SPANS` on deposit. Sixty-four such endsets is
/// the budget exactly, and one span more — a sixty-fifth link naming position
/// 1 alone — is refused rather than dropped: RE-UNIT licenses withholding a
/// link's IDENTITY, never its endset.
#[test]
fn retrieve_endsets_refuses_an_answer_past_the_span_budget() {
    const SPANS: u32 = 1024;
    let at_budget = MAX_ENDSET_SPANS / SPANS as usize; // 64 whole endsets

    let k = kernel();
    seed_content(&k, &doc1(), 1);
    let store = LinkWriter::new(&k, &EVERYONE);
    let reads = Reads(&k);
    let region = [vspan(1, 1, 1)];
    assert!(SPANS as usize <= MAX_SLOT_SPANS, "each slot is in M7's budget");
    for i in 0..at_budget as u32 {
        link(&store, &doc1(), &wide_from(i, SPANS), &[ca(101)]);
    }

    // At the budget: one pair per link, each endset WHOLE, none clipped.
    let pairs = reads.retrieve_endsets(&doc1(), &region).expect("at budget");
    assert_eq!(pairs.len(), at_budget);
    assert!(pairs.iter().all(|(i, e)| *i == FROM && e.len() == SPANS as usize));

    // One span more, and the answer is refused rather than shortened.
    link(&store, &doc1(), &[ca(1)], &[ca(101)]);
    assert_eq!(
        reads.retrieve_endsets(&doc1(), &region),
        Err(QueryError::EndsetsTooLarge)
    );
    // The region family's other read-outs carry no such budget: they enumerate
    // ADDRESSES, whose size is the link count and not the endsets'.
    assert_eq!(reads.count_v(&doc1(), &region), Ok(at_budget + 1));
}

/// §4 — the span budget prices what the answer CARRIES: links sharing one
/// wide endset are one pair and one charge. A per-link charge would refuse
/// this answer, which is a single pair — the collapse RE-UNIT licenses,
/// refused for being collapsed.
#[test]
fn retrieve_endsets_prices_the_collapsed_answer_not_the_links_behind_it() {
    const SPANS: u32 = 1024;
    let links = MAX_ENDSET_SPANS / SPANS as usize + 1; // one more than a per-link charge admits
    let k = kernel();
    seed_content(&k, &doc1(), 1);
    let store = LinkWriter::new(&k, &EVERYONE);
    let reads = Reads(&k);
    let shared = wide_from(0, SPANS);
    for i in 0..links as u32 {
        link(&store, &doc1(), &shared, &[ca(101 + i)]);
    }
    let region = [vspan(1, 1, 1)];
    assert_eq!(
        reads.count_v(&doc1(), &region),
        Ok(links),
        "every link touches the region"
    );
    assert_eq!(
        reads.retrieve_endsets(&doc1(), &region),
        Ok(vec![(FROM, enc(&shared))])
    );
}

/// §4 — the answer budget is not M7's slot budget: two links each carrying
/// the most spans M7 admits in one slot are answered whole. That is the case
/// the constant's own doc gives for `2^16` over `2^12`, and a symbolic
/// boundary test cannot see it.
#[test]
fn retrieve_endsets_answers_a_region_two_maximal_endsets_touch() {
    let k = kernel();
    seed_content(&k, &doc1(), 1);
    let store = LinkWriter::new(&k, &EVERYONE);
    let reads = Reads(&k);
    for i in 0..2 {
        link(&store, &doc1(), &wide_from(i, MAX_SLOT_SPANS as u32), &[ca(101)]);
    }
    let pairs = reads
        .retrieve_endsets(&doc1(), &[vspan(1, 1, 1)])
        .expect("inside the answer budget");
    assert_eq!(pairs.len(), 2);
    assert!(pairs
        .iter()
        .all(|(i, e)| *i == FROM && e.len() == MAX_SLOT_SPANS));
}
