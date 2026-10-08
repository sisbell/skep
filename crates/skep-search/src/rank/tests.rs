use super::*;
use crate::hit::{Span, Standing};
use crate::unit::{Class, Item, Kind, Unit, UnitKey};
use skep_address::{validate, Address, Nat, Tumbler};

fn addr(comps: &[u32]) -> Address {
    let t = Tumbler::new(comps.iter().map(|&c| Nat::from(c))).expect("nonempty");
    validate(t).expect("a T4-valid address")
}

fn hit(doc: &[u32], member: Option<&[u32]>, start: u64, score: f64) -> Hit {
    Hit {
        doc: addr(doc),
        member: member.map(addr),
        as_of: 1,
        span: Span { start, width: 1 },
        score,
        snippet: None,
        kind: Kind::Edition,
        standing: Standing::Public,
        occurrences: 1,
        matched: Vec::new(),
    }
}

/// §3.3 THE PINNED idf, as written: `ln(1 + (N − df + 0.5)/(df + 0.5))`,
/// positive at every df, about 0.5/N at df = N, and never below zero.
#[test]
fn the_idf_is_lucenes_form_positive_at_every_df() {
    assert!((idf(10, 1) - (1.0f64 + 9.5 / 1.5).ln()).abs() < 1e-12);
    assert!((idf(10, 10) - (1.0f64 + 0.5 / 10.5).ln()).abs() < 1e-12);
    assert!(idf(10, 10) > 0.0 && idf(10, 10) < 0.05, "near zero, never below");
    assert!(idf(1, 1) > 0.0);
    for n in [1usize, 2, 7, 10_000] {
        for df in 0..=n.min(50) {
            assert!(idf(n, df) > 0.0, "N = {n}, df = {df}");
        }
        assert!(idf(n, n) > 0.0);
        assert!(idf(n, n) < idf(n, 1.min(n)) || n == 1);
    }
    assert!(idf(10, 1) > idf(10, 5) && idf(10, 5) > idf(10, 10), "rarer is heavier");
}

/// §3.3 the term score, as written, with k₁ = 1.2 and b = 0.75; zero at
/// tf = 0; a shorter unit scores higher at equal tf; a higher tf scores
/// higher and saturates.
#[test]
fn the_term_score_is_bm25s_with_the_pinned_parameters() {
    assert_eq!((K1, B), (1.2, 0.75));
    let by_hand = |idf: f64, tf: f64, dl: f64, avgdl: f64| {
        idf * tf * (K1 + 1.0) / (tf + K1 * (1.0 - B + B * dl / avgdl))
    };
    assert!((term_score(2.0, 3, 20, 10.0) - by_hand(2.0, 3.0, 20.0, 10.0)).abs() < 1e-12);
    assert_eq!(term_score(2.0, 0, 20, 10.0), 0.0);
    assert!(term_score(2.0, 1, 5, 10.0) > term_score(2.0, 1, 50, 10.0), "length normalization");
    assert!(term_score(2.0, 2, 10, 10.0) > term_score(2.0, 1, 10, 10.0));
    assert!(term_score(2.0, 100, 10, 10.0) < 2.0 * (K1 + 1.0), "saturates below idf · (k₁ + 1)");
    assert!(
        (term_score(2.0, 1, 10, 0.0) - by_hand(2.0, 1.0, 10.0, 10.0)).abs() < 1e-12,
        "an empty average is one"
    );
}

/// §3.3 THE PAIR's MERGED STATISTICS: N the units of both, the tokens of
/// both, the average over both — each index counted once.
#[test]
fn the_statistics_merge_the_pair_counting_each_member_once() {
    let unit = |class: Class, n: u32, text: &str| {
        Unit::new(
            UnitKey::new(addr(&[1, 0, 1, 0, n])),
            None,
            Kind::Edition,
            class,
            1,
            vec![Item::Text { start: 1, bytes: text.as_bytes().to_vec() }],
        )
        .expect("one extent")
    };
    let mut published = Index::new(Class::Guest);
    published.index(unit(Class::Guest, 1, "a b c d")).expect("admitted");
    published.index(unit(Class::Guest, 2, "e f")).expect("admitted");
    let mut supplement = Index::new(Class::Principal(3));
    supplement.index(unit(Class::Principal(3), 7, "g h i")).expect("admitted");
    assert_eq!(Statistics::merged([&published]), Statistics { units: 2, tokens: 6, avgdl: 3.0 });
    assert_eq!(
        Statistics::merged([&published, &supplement]),
        Statistics { units: 3, tokens: 9, avgdl: 3.0 }
    );
    assert_eq!(Statistics::merged([]), Statistics { units: 0, tokens: 0, avgdl: 0.0 });
}

/// §3.3 THE ORDER: the score descending, then the document address, the
/// member and the span start ascending.
#[test]
fn the_order_is_score_then_address_member_and_span() {
    let a = hit(&[1, 0, 1, 0, 1], None, 5, 2.0);
    let b = hit(&[1, 0, 1, 0, 2], None, 5, 2.0);
    let c = hit(&[1, 0, 1, 0, 2], Some(&[1, 0, 1, 0, 2, 1]), 5, 2.0);
    let d = hit(&[1, 0, 1, 0, 2], Some(&[1, 0, 1, 0, 2, 1]), 9, 2.0);
    let e = hit(&[1, 0, 1, 0, 1], None, 5, 3.0);
    let mut hits = vec![d.clone(), c.clone(), b.clone(), a.clone(), e.clone()];
    hits.sort_by(order);
    assert_eq!(hits, [e, a, b, c, d]);
    assert_eq!(
        order(&hit(&[1, 0, 1, 0, 1], None, 5, 2.0), &hit(&[1, 0, 1, 0, 1], None, 5, 2.0)),
        Ordering::Equal
    );
}
