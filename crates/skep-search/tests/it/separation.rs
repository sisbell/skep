//! §2.1 THE CLASS SEPARATION BY CONSTRUCTION (§8.3): "an index built from
//! guest-class deliveries and one built from a principal's differ exactly by
//! the supplement, a query over one pair returns no term only another
//! principal's drafts hold" — the investigation §4.10 item 15's vector set,
//! cut by this lane: class separation (row 9: "a search in principal A's
//! session returns no term that only principal B's drafts hold, by
//! construction and by test"), the guest build against the principal build
//! (row 10: "an index built as the guest and one built as a principal differ
//! exactly by the supplement"). The separation is STRUCTURAL (§5.2 D7): the
//! guest pair holds the published index alone, a session's pair that index
//! and its own principal's supplement, and no filter decides it.

use std::collections::BTreeSet;

use skep_address::Address;
use skep_search::{Answer, Class, Index, Pair, Query, QueryOpts, Standing};

use crate::{addr, draft, text_unit};

fn ask(pair: Pair<'_>, text: &str) -> Answer {
    Index::query(pair, &Query::parse(text), &QueryOpts::default())
}

fn docs(answer: &Answer) -> BTreeSet<Address> {
    answer.hits.iter().map(|h| h.doc.clone()).collect()
}

/// The board: its published documents, read token-free at guest class; and
/// two principals' drafts, each read under its own session.
struct Board {
    published: Index,
    a: Index,
    b: Index,
}

fn board() -> Board {
    let mut published = Index::new(Class::Guest);
    published
        .index(text_unit(Class::Guest, 1, b"the published charter of the board"))
        .expect("admitted");
    published
        .index(text_unit(Class::Guest, 2, b"a second edition about transclusion"))
        .expect("admitted");
    let class_a = Class::Principal(1);
    let mut a = Index::new(class_a);
    a.index(draft(class_a, &addr(&[1, 0, 1, 0, 7]), b"alice drafts about transclusion"))
        .expect("admitted");
    a.index(draft(class_a, &addr(&[1, 0, 1, 0, 8]), b"alice's secret alpenglow"))
        .expect("admitted");
    let class_b = Class::Principal(2);
    let mut b = Index::new(class_b);
    b.index(draft(class_b, &addr(&[1, 0, 2, 0, 3]), b"bob drafts the charter again"))
        .expect("admitted");
    b.index(draft(class_b, &addr(&[1, 0, 2, 0, 4]), b"bob's secret zymurgy")).expect("admitted");
    Board { published, a, b }
}

/// Row 10: an index built as the guest and one built as a principal differ
/// exactly by the supplement — for every term, the principal's pair answers
/// the guest's documents and the supplement's own, and nothing else; the
/// published index is one and the same value in both pairs.
#[test]
fn the_guest_build_and_the_principal_build_differ_exactly_by_the_supplement() {
    let board = board();
    let guest = Pair::guest(&board.published);
    let alice = Pair::session(&board.published, &board.a, &[], &[]);
    let alone = Pair::guest(&board.a);
    let terms: BTreeSet<&str> = board.published.terms().chain(board.a.terms()).collect();
    assert!(terms.contains("alpenglow") && terms.contains("charter"));
    for term in terms {
        let query = format!("{term} ");
        let from_guest = docs(&ask(guest, &query));
        let from_supplement = docs(&ask(alone, &query));
        let from_alice = docs(&ask(alice, &query));
        assert_eq!(
            from_alice,
            from_guest.union(&from_supplement).cloned().collect::<BTreeSet<_>>(),
            "`{term}`: the pair's answer is the guest's plus the supplement's"
        );
        assert!(from_guest.is_subset(&from_alice), "`{term}`: nothing of the guest's is lost");
    }
    assert_eq!(
        board.published.terms().collect::<Vec<_>>(),
        Pair::guest(&board.published).published.terms().collect::<Vec<_>>(),
        "one published index, shared"
    );
}

/// §2.1, row 9: a query over the guest pair returns no term only a
/// principal's drafts hold; the principal's pair returns them
/// `YoursToRead`; and a search in principal A's session returns no term
/// that only principal B's drafts hold, by construction.
#[test]
fn a_query_over_one_pair_returns_no_term_only_another_principals_drafts_hold() {
    let board = board();
    let guest = Pair::guest(&board.published);
    let alice = Pair::session(&board.published, &board.a, &[], &[]);
    let bob = Pair::session(&board.published, &board.b, &[], &[]);

    // Terms only Alice's drafts hold.
    for term in ["alice ", "alpenglow ", "secret alpenglow "] {
        assert_eq!(
            ask(guest, term),
            Answer::default(),
            "`{term}` reaches the guest face not at all"
        );
        assert_eq!(ask(bob, term), Answer::default(), "`{term}` reaches Bob's session not at all");
        let hers = ask(alice, term);
        assert!(!hers.hits.is_empty(), "`{term}` answers in Alice's own session");
        assert!(hers.hits.iter().all(|h| h.standing == Standing::YoursToRead), "{term}");
    }
    // Terms only Bob's drafts hold.
    for term in ["bob ", "zymurgy "] {
        assert_eq!(ask(guest, term), Answer::default());
        assert_eq!(ask(alice, term), Answer::default());
        assert!(!ask(bob, term).hits.is_empty());
    }
    // A term both the board and a draft hold: the guest face sees the
    // published unit alone; each session sees the published unit and its
    // own draft, never the other's.
    let published_charter = docs(&ask(guest, "charter "));
    assert_eq!(published_charter, BTreeSet::from([addr(&[1, 0, 1, 0, 1])]));
    assert_eq!(docs(&ask(alice, "charter ")), published_charter, "Alice holds no charter draft");
    let bobs = docs(&ask(bob, "charter "));
    assert_eq!(bobs.len(), 2);
    assert!(bobs.contains(&addr(&[1, 0, 2, 0, 3])) && bobs.is_superset(&published_charter));
    let transclusion = ask(alice, "transclusion ");
    assert_eq!(transclusion.hits.len(), 2);
    let standings: BTreeSet<String> =
        transclusion.hits.iter().map(|h| format!("{:?}", h.standing)).collect();
    assert_eq!(standings, BTreeSet::from(["Public".to_string(), "YoursToRead".to_string()]));
    // The fuzzy correction's dictionary is the pair's: a typo of a term only
    // Bob's drafts hold corrects to nothing in Alice's session (fact 4).
    assert_eq!(ask(alice, "zymurgi "), Answer::default());
    assert!(!ask(bob, "zymurgi ").hits.is_empty());
    assert_eq!(ask(guest, "zymurgi "), Answer::default());
}
