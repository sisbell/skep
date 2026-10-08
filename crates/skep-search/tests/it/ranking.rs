//! §3.3's RANKING VECTORS (§8.3): "a long unit of many completions against
//! a short unit holding the word, its order now fixed by the pinned idf, the
//! first keystroke's prefix union scoring near zero and never below, and a
//! tie set ordered by address, member, span"; THE PAIR's MERGED STATISTICS,
//! the published member's units counted ONCE (ITEM 4's cut); and
//! DETERMINISM — the same pair and query give the same hits in the same
//! order twice, and the order never depends on insertion.

use skep_search::rank;
use skep_search::{
    Answer, Class, Index, Item, Kind, Pair, Query, QueryOpts, Statistics, Unit, UnitKey,
};

use crate::{addr, doc, draft, text_unit};

fn ask(pair: Pair<'_>, text: &str) -> Answer {
    Index::query(pair, &Query::parse(text), &QueryOpts::default())
}

/// §8.3: a long unit of many completions against a short unit holding the
/// word — under the pinned idf, positive at every df, the short unit ranks
/// first and both score above zero. The expansion is ONE COMBINED TERM over
/// the union, so the long unit gains nothing by holding many completions,
/// and length normalization decides.
#[test]
fn a_short_unit_holding_the_word_outranks_a_long_unit_of_many_completions() {
    let filler = "word ".repeat(400);
    let long =
        format!("{filler}transclusion transclusions transclusive transclusivity transclusionist");
    let mut index = Index::new(Class::Guest);
    index.index(text_unit(Class::Guest, 1, long.as_bytes())).expect("admitted");
    index.index(text_unit(Class::Guest, 2, b"transclusion here")).expect("admitted");
    let answer = ask(Pair::guest(&index), "transclusi");
    assert_eq!(answer.hits.len(), 2);
    assert_eq!(answer.hits[0].doc, doc(2), "the short unit first");
    assert_eq!(answer.hits[1].doc, doc(1));
    assert!(answer.hits[0].score > answer.hits[1].score);
    assert!(answer.hits[1].score > 0.0, "never below zero, though every unit holds the union");
    assert_eq!(answer.hits[1].occurrences, 5, "the five completions summed as one term's tf");
}

/// §8.3: the first keystroke's prefix union — a one-letter prefix every unit
/// completes — scores near zero and never below, by the pinned idf's form
/// (about 0.5/N at df = N); under Robertson–Spärck Jones it would be
/// negative and the order inverted.
#[test]
fn the_first_keystrokes_prefix_union_scores_near_zero_and_never_below() {
    let mut index = Index::new(Class::Guest);
    let texts =
        ["the", "to the", "that this", "then", "there the", "trunk", "tie", "two", "ten", "tax"];
    for (i, text) in texts.iter().enumerate() {
        index.index(text_unit(Class::Guest, i as u32 + 1, text.as_bytes())).expect("admitted");
    }
    let answer = ask(Pair::guest(&index), "t");
    assert_eq!(answer.total, 10, "every unit completes `t`");
    let idf = rank::idf(10, 10);
    assert!(idf > 0.0 && idf < 0.05, "ln(1 + 0.5/10.5) = {idf}");
    for hit in &answer.hits {
        assert!(hit.score > 0.0, "{hit:?}");
        assert!(hit.score < idf * (rank::K1 + 1.0) + 1e-9, "bounded by idf · (k₁ + 1): {hit:?}");
    }
    assert!(!answer.more_terms, "ten short units: far under the bound");
}

/// §3.3, §8.3: a tie set is ordered by document address, then member, then
/// span start — whatever order the units entered in.
#[test]
fn a_tie_set_is_ordered_by_address_then_member_then_span() {
    let mut published = Index::new(Class::Guest);
    for n in [3u32, 1, 2] {
        published.index(text_unit(Class::Guest, n, b"alpha beta")).expect("admitted");
    }
    let ties = ask(Pair::guest(&published), "alpha");
    assert_eq!(
        ties.hits.iter().map(|h| h.doc.clone()).collect::<Vec<_>>(),
        [doc(1), doc(2), doc(3)]
    );
    assert!(ties.hits.windows(2).all(|w| w[0].score == w[1].score), "one score, one tie set");

    // The same document in both members — a case ITEM 4's cut leaves to the
    // embedder, but the order is stated: the member breaks the tie.
    let mut published = Index::new(Class::Guest);
    let later = Unit::new(
        UnitKey::new(doc(5)),
        Some(addr(&[1, 0, 1, 0, 5, 2])),
        Kind::Edition,
        Class::Guest,
        1,
        vec![Item::Text { start: 1, bytes: b"alpha".to_vec() }],
    )
    .expect("one extent");
    published.index(later).expect("admitted");
    let mut supplement = Index::new(Class::Principal(3));
    let earlier = Unit::new(
        UnitKey::new(doc(5)),
        Some(addr(&[1, 0, 1, 0, 5, 1])),
        Kind::Edition,
        Class::Principal(3),
        1,
        vec![Item::Text { start: 1, bytes: b"alpha".to_vec() }],
    )
    .expect("one extent");
    supplement.index(earlier).expect("admitted");
    let pair = Pair::session(&published, &supplement, &[], &[]);
    let answer = ask(pair, "alpha");
    assert_eq!(answer.hits.len(), 2);
    assert_eq!(answer.hits[0].member, Some(addr(&[1, 0, 1, 0, 5, 1])), "the lesser member first");
    assert_eq!(answer.hits[1].member, Some(addr(&[1, 0, 1, 0, 5, 2])));
    assert_eq!(answer.hits[0].score, answer.hits[1].score);
}

/// §3.3 THE PAIR SCORES AS ONE CORPUS over its MERGED STATISTICS — N the
/// units of both, df the sum, avgdl over both — the published member's units
/// counted ONCE: a hit's score over the pair is BM25 by hand with N = 3 + 1,
/// and differs from the guest form's over the published index alone.
#[test]
fn the_pair_scores_over_merged_statistics_counting_the_published_member_once() {
    let mut published = Index::new(Class::Guest);
    published.index(text_unit(Class::Guest, 1, b"alpha beta gamma delta")).expect("admitted");
    published.index(text_unit(Class::Guest, 2, b"beta gamma")).expect("admitted");
    published.index(text_unit(Class::Guest, 3, b"gamma delta epsilon")).expect("admitted");
    let mut supplement = Index::new(Class::Principal(7));
    supplement
        .index(draft(Class::Principal(7), &addr(&[1, 0, 7, 0, 1]), b"alpha zeta"))
        .expect("admitted");
    let pair = Pair::session(&published, &supplement, &[], &[]);

    let stats = Statistics::merged(pair.indexes());
    assert_eq!(stats, Statistics { units: 4, tokens: 11, avgdl: 11.0 / 4.0 });
    let answer = ask(pair, "alpha ");
    assert_eq!(answer.hits.len(), 2, "one edition, one draft, one ranking");
    let edition = answer.hits.iter().find(|h| h.doc == doc(1)).expect("the edition");
    let by_hand = rank::term_score(rank::idf(4, 2), 1, 4, 11.0 / 4.0);
    assert!((edition.score - by_hand).abs() < 1e-12, "N = 4, df = 2, dl = 4, avgdl = 11/4");
    let twice = rank::term_score(rank::idf(7, 3), 1, 4, 20.0 / 7.0);
    assert!(
        (edition.score - twice).abs() > 1e-6,
        "the published member counted again would move it"
    );
    let guest = ask(Pair::guest(&published), "alpha ");
    let alone = rank::term_score(rank::idf(3, 1), 1, 4, 9.0 / 3.0);
    assert!((guest.hits[0].score - alone).abs() < 1e-12, "the guest form: N = 3, df = 1");
    assert!(guest.hits[0].score != edition.score, "the pair's statistics are merged");
}

/// §3.3 DETERMINISM: the same pair and query give the same hits in the same
/// order twice.
#[test]
fn the_same_pair_and_query_answer_the_same_order_twice() {
    let mut published = Index::new(Class::Guest);
    for (n, text) in
        [(4u32, "alpha beta"), (2, "alpha"), (9, "alpha beta gamma alpha"), (1, "beta alpha")]
    {
        published.index(text_unit(Class::Guest, n, text.as_bytes())).expect("admitted");
    }
    let mut supplement = Index::new(Class::Principal(2));
    supplement
        .index(draft(Class::Principal(2), &addr(&[1, 0, 2, 0, 3]), b"alpha beta"))
        .expect("admitted");
    let pair = Pair::session(&published, &supplement, &[], &[]);
    let first = ask(pair, "alpha beta");
    let second = ask(pair, "alpha beta");
    assert_eq!(first, second);
    assert_eq!(first.total, 4);
    assert!(first.hits.windows(2).all(|w| rank::order(&w[0], &w[1]).is_le()), "in §3.3's order");
}
