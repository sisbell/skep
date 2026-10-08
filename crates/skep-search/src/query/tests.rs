use super::*;
use crate::hit::Standing;
use crate::unit::{Class, GapKind, Kind, UnitKey};
use skep_address::{validate, Address, Nat, Tumbler};

fn addr(comps: &[u32]) -> Address {
    let t = Tumbler::new(comps.iter().map(|&c| Nat::from(c))).expect("nonempty");
    validate(t).expect("a T4-valid address")
}

/// The document `1.0.1.0.n`.
fn doc(n: u32) -> Address {
    addr(&[1, 0, 1, 0, n])
}

fn unit_of(class: Class, n: u32, items: Vec<Item>) -> Unit {
    Unit::new(UnitKey::new(doc(n)), None, Kind::Edition, class, 1, items).expect("one extent")
}

fn unit(class: Class, n: u32, text: &str) -> Unit {
    unit_of(class, n, vec![Item::Text { start: 1, bytes: text.as_bytes().to_vec() }])
}

/// A published index of `texts`, the documents numbered from 1 in order.
fn published(texts: &[&str]) -> Index {
    let mut index = Index::new(Class::Guest);
    for (i, text) in texts.iter().enumerate() {
        index.index(unit(Class::Guest, i as u32 + 1, text)).expect("admitted");
    }
    index
}

fn ask(index: &Index, text: &str) -> Answer {
    Index::query(Pair::guest(index), &Query::parse(text), &QueryOpts::default())
}

fn ask_under(index: &Index, text: &str, bounds: Bounds) -> Answer {
    evaluate(&Pair::guest(index), &Query::parse(text), &QueryOpts::default(), bounds)
}

/// The hits' documents in the answer's order.
fn docs(answer: &Answer) -> Vec<Address> {
    answer.hits.iter().map(|h| h.doc.clone()).collect()
}

fn w(typed: &str, term: &str) -> Word {
    Word { typed: typed.to_string(), term: term.to_string() }
}

fn plain(term: &str) -> Word {
    w(term, term)
}

/// §3.2 THE ONE GRAMMAR: each form from its string — the trailing prefix
/// unless whitespace ends the string, the quoted phrase, the unclosed quote,
/// the split chunk's implicit phrase and its phrase-prefix at the end, a
/// quoted single word a word, the fold over the query, and what cuts to
/// nothing.
#[test]
fn the_grammar_cuts_each_of_the_forms() {
    assert_eq!(
        Query::parse("alpha beta").forms(),
        &[Form::Word(plain("alpha")), Form::Prefix(plain("beta"))]
    );
    assert_eq!(
        Query::parse("alpha beta ").forms(),
        &[Form::Word(plain("alpha")), Form::Word(plain("beta"))],
        "whitespace at the end completes the last word"
    );
    assert_eq!(
        Query::parse("\"the publish shot\"").forms(),
        &[Form::Phrase(vec![plain("the"), plain("publish"), plain("shot")])]
    );
    assert_eq!(
        Query::parse("\"the publish s").forms(),
        &[Form::PhrasePrefix { fixed: vec![plain("the"), plain("publish")], prefix: plain("s") }],
        "an unclosed quote is a phrase-prefix"
    );
    assert_eq!(
        Query::parse("\"the publish ").forms(),
        &[Form::Phrase(vec![plain("the"), plain("publish")])],
        "an unclosed quote whose last word is complete is a phrase"
    );
    assert_eq!(
        Query::parse("PUB-5.115").forms(),
        &[Form::PhrasePrefix { fixed: vec![w("PUB", "pub")], prefix: plain("5.115") }],
        "a split chunk at the string's end is a phrase-prefix"
    );
    assert_eq!(
        Query::parse("PUB-5.115 ").forms(),
        &[Form::Phrase(vec![w("PUB", "pub"), plain("5.115")])],
        "a split chunk is an implicit phrase"
    );
    assert_eq!(
        Query::parse("東京都").forms(),
        &[Form::PhrasePrefix { fixed: vec![plain("東"), plain("京")], prefix: plain("都") }]
    );
    assert_eq!(Query::parse("\"shot\"").forms(), &[Form::Word(plain("shot"))]);
    assert_eq!(
        Query::parse("\"shot\" x").forms(),
        &[Form::Word(plain("shot")), Form::Prefix(plain("x"))]
    );
    assert_eq!(
        Query::parse("x \"a b\" y").forms(),
        &[
            Form::Word(plain("x")),
            Form::Phrase(vec![plain("a"), plain("b")]),
            Form::Prefix(plain("y"))
        ]
    );
    assert_eq!(Query::parse("\"s").forms(), &[Form::Prefix(plain("s"))]);
    assert_eq!(
        Query::parse("Émile").forms(),
        &[Form::Prefix(w("Émile", "emile"))],
        "the query is folded as the text was; `typed` keeps the spelling"
    );
    for empty in ["", "   ", "... !!", "\"", "\"\"", "\" \""] {
        assert!(Query::parse(empty).is_empty(), "{empty:?} holds no form");
    }
}

/// §3.2 A WORD and A PREFIX: a complete word finds the units holding its
/// term; the trailing word finds every completion, the shorter unit first.
#[test]
fn a_word_finds_its_units_and_a_prefix_its_completions() {
    let index =
        published(&["the publish shot lands on the trunk", "the publish should wait", "alpha"]);
    let answer = ask(&index, "publish ");
    assert_eq!(docs(&answer), [doc(2), doc(1)], "the shorter unit first");
    assert_eq!(answer.total, 2);
    assert!(
        !answer.truncated
            && !answer.more_terms
            && !answer.fuzzy_bounded
            && !answer.positions_bounded
    );
    assert_eq!(docs(&ask(&index, "sh")), [doc(2), doc(1)], "`shot` and `should`");
    assert_eq!(docs(&ask(&index, "sho")), [doc(2), doc(1)]);
    assert_eq!(docs(&ask(&index, "shot")), [doc(1)]);
    assert!(ask(&index, "shots").hits.is_empty());
    assert_eq!(docs(&ask(&index, "trunk")), [doc(1)]);
    assert_eq!(ask(&index, "alpha").hits[0].occurrences, 1);
}

/// §3.2 A PHRASE matches adjacent ordinals in one unit, in order, and never
/// across a `Gap`.
#[test]
fn a_phrase_matches_adjacent_ordinals_and_never_across_a_gap() {
    let mut index = published(&["the publish shot lands", "shot the publish"]);
    let split = unit_of(
        Class::Guest,
        3,
        vec![
            Item::Text { start: 1, bytes: b"the publish".to_vec() },
            Item::Gap { start: 12, width: 1, kind: GapKind::Atom },
            Item::Text { start: 13, bytes: b"shot".to_vec() },
        ],
    );
    index.index(split).expect("admitted");
    assert_eq!(docs(&ask(&index, "\"publish shot\"")), [doc(1)]);
    assert_eq!(docs(&ask(&index, "\"the publish\"")), [doc(2), doc(3), doc(1)]);
    assert!(ask(&index, "\"shot publish\"").hits.is_empty(), "order matters");
    assert!(ask(&index, "\"publish shot the\"").hits.is_empty());
    let hit = &ask(&index, "\"publish shot\"").hits[0];
    assert_eq!(hit.span, Span { start: 5, width: 12 }, "`publish shot` at V-ordinals 5..17");
    assert_eq!(hit.occurrences, 1);
}

/// §3.2 A PHRASE-PREFIX expands over the terms that follow the fixed words:
/// `"the publish s` finds `shot`, and a unit where nothing follows the fixed
/// phrase — or a `Gap` does — answers no hit.
#[test]
fn a_phrase_prefix_takes_the_terms_after_the_fixed_words() {
    let mut index = published(&[
        "the publish shot lands",
        "the publish should wait; see the state",
        "the publish",
        "see should state the",
    ]);
    index
        .index(unit_of(
            Class::Guest,
            5,
            vec![
                Item::Text { start: 1, bytes: b"the publish".to_vec() },
                Item::Gap { start: 12, width: 3, kind: GapKind::Atom },
                Item::Text { start: 15, bytes: b"shot".to_vec() },
            ],
        ))
        .expect("admitted");
    let answer = ask(&index, "\"the publish s");
    assert_eq!(docs(&answer), [doc(1), doc(2)]);
    assert_eq!(answer.hits[0].span, Span { start: 1, width: 16 }, "`the publish shot`");
    assert_eq!(answer.hits[1].span, Span { start: 1, width: 18 }, "`the publish should`");
    assert!(!answer.more_terms);
    assert_eq!(ask(&index, "\"the publish sh").hits.len(), 2, "`shot` and `should`");
    assert_eq!(docs(&ask(&index, "\"the publish shot")), [doc(1)]);
    assert!(
        ask(&index, "\"the publish w").hits.is_empty(),
        "nothing after the fixed words starts so"
    );
}

/// §3.2 A SPLIT CHUNK is an implicit phrase: `PUB-5.115` finds the unit that
/// holds it and not `AUTH-5.115` beside `PUB-1.2`; `5.115` alone finds
/// both.
#[test]
fn a_split_chunk_is_an_implicit_phrase() {
    let index = published(&["PUB-5.115 holds the rule", "AUTH-5.115 beside PUB-1.2"]);
    assert_eq!(docs(&ask(&index, "PUB-5.115")), [doc(1)], "the phrase-prefix at the end");
    assert_eq!(docs(&ask(&index, "PUB-5.115 ")), [doc(1)], "the implicit phrase");
    assert_eq!(docs(&ask(&index, "PUB-5.1")), [doc(1)], "mid-typing, a phrase-prefix over `5.1*`");
    assert_eq!(docs(&ask(&index, "PUB-1")), [doc(2)]);
    assert_eq!(ask(&index, "5.115").hits.len(), 2, "`5.115` alone also finds it");
}

/// §3.2 SEVERAL BARE WORDS are a conjunction: every form present, the span
/// the tightest window holding one occurrence of each.
#[test]
fn a_conjunction_needs_every_form_and_spans_the_tightest_window() {
    let index = published(&["alpha beta gamma", "gamma x x x alpha y gamma", "alpha only"]);
    let answer = ask(&index, "alpha gamma ");
    assert_eq!(docs(&answer), [doc(1), doc(2)]);
    assert_eq!(answer.hits[0].span, Span { start: 1, width: 16 });
    assert_eq!(
        answer.hits[1].span,
        Span { start: 13, width: 13 },
        "`alpha y gamma`, not the wider window"
    );
    assert_eq!(answer.hits[1].occurrences, 3, "alpha once, gamma twice");
    assert!(ask(&index, "alpha delta ").hits.is_empty());
}

/// §3.2 D15 THE FUZZY WORD: one edit of each kind — an insertion, a
/// deletion, a substitution, an adjacent transposition — finds the term,
/// counted in characters, and `matched` says so; a four-letter word and an
/// exact term are NOT expanded; the trailing prefix is not fuzzy.
#[test]
fn a_fuzzy_word_is_found_within_one_edit_and_the_hit_says_so() {
    let index = published(&["transclusion is the link's other face", "привет мир"]);
    for typo in ["transclusin ", "transcluusion ", "transclusiom ", "transclusoin "] {
        let answer = ask(&index, typo);
        assert_eq!(docs(&answer), [doc(1)], "{typo:?}");
        assert_eq!(
            answer.hits[0].matched,
            [Matched { word: typo.trim().to_string(), term: "transclusion".to_string() }]
        );
        assert!(!answer.fuzzy_bounded && !answer.more_terms);
    }
    let answer = ask(&index, "привeт ");
    assert_eq!(docs(&answer), [doc(2)], "a Cyrillic substitution is one edit, not two bytes'");
    assert_eq!(answer.hits[0].matched[0].term, "привет");
    assert!(ask(&index, "lnik ").hits.is_empty(), "four letters: not expanded");
    assert!(ask(&index, "transclusin").hits.is_empty(), "the trailing prefix is not fuzzy");
    let exact = ask(&index, "face ");
    assert_eq!(docs(&exact), [doc(1)]);
    assert!(exact.hits[0].matched.is_empty(), "a word that is a term takes no expansion");
    let inside = ask(&index, "\"transclusoin is\"");
    assert_eq!(docs(&inside), [doc(1)], "inside a phrase a fuzzy word matches at its ordinal");
    assert_eq!(inside.hits[0].matched[0].term, "transclusion");
    assert_eq!(inside.hits[0].span, Span { start: 1, width: 15 });
}

/// §3.2 THE FUZZY WORDS BOUND IS A FLAG: at most three complete words are
/// expanded, the three nearest the string's end; a fourth is matched as
/// typed — which no term is — and the answer says so by `fuzzy_bounded`,
/// never silently.
#[test]
fn a_fourth_fuzzy_word_is_left_as_typed_and_the_answer_says_so() {
    let index = published(&["alphas bravos charls deltas"]);
    let three = ask(&index, "bravoz charlz deltaz ");
    assert_eq!(docs(&three), [doc(1)]);
    assert_eq!(three.hits[0].matched.len(), 3);
    assert!(!three.fuzzy_bounded);
    let four = ask(&index, "alphaz bravoz charlz deltaz ");
    assert!(four.hits.is_empty(), "`alphaz`, the farthest from the end, is matched as typed");
    assert!(four.fuzzy_bounded);
    assert_eq!(four.total, 0);
    let three_of_four = ask(&index, "alphas bravoz charlz deltaz ");
    assert_eq!(docs(&three_of_four), [doc(1)], "an exact term spends no budget");
    assert!(!three_of_four.fuzzy_bounded);
}

/// §3.2 THE EXPANSION's BOUND IS A FLAG: the completions are taken by
/// document frequency descending until the next would pass the bound, the
/// prefix's own term first and always, and `more_terms` is set exactly when
/// the bound is met — a cut without the flag fails here.
#[test]
fn the_expansion_is_bounded_in_entries_and_more_terms_says_so() {
    let index = published(&["alpha alpha alpha alphabet", "alphabet alpine", "alpine"]);
    let wide = ask_under(&index, "alp", Bounds { expansion: 100, positions: 100 });
    assert_eq!(wide.total, 3);
    assert!(!wide.more_terms);
    // By df: `alphabet` (2) and `alpine` (2) before `alpha` (1); equal
    // frequencies in the dictionary's order. `alphabet` costs 2 entries,
    // `alpine` 2, `alpha` 3.
    let cut = ask_under(&index, "alp", Bounds { expansion: 4, positions: 100 });
    assert!(cut.more_terms, "the bound met");
    assert_eq!(cut.total, 3, "`alphabet` and `alpine` reach every unit");
    let tight = ask_under(&index, "alp", Bounds { expansion: 2, positions: 100 });
    assert!(tight.more_terms);
    assert_eq!(docs(&tight), [doc(2), doc(1)], "`alphabet` alone");
    // The own term is assured its place past the bound.
    let own = ask_under(&index, "alpha", Bounds { expansion: 1, positions: 100 });
    assert_eq!(docs(&own), [doc(1)]);
    assert_eq!(own.hits[0].occurrences, 3, "`alpha` three times, `alphabet` not taken");
    assert!(own.more_terms);
    let unbounded = ask_under(&index, "alpha", Bounds { expansion: 100, positions: 100 });
    assert_eq!(docs(&unbounded), [doc(1), doc(2)]);
    assert!(!unbounded.more_terms);
}

/// §3.2 THE POSITIONS BOUND IS A FLAG: the walk stops where the next merge
/// would pass it, the units reached are answered ranked,
/// `positions_bounded` is set, `total` is a lower bound and `truncated` says
/// the list was cut — never a silent stop.
#[test]
fn the_evaluation_is_bounded_in_positions_and_positions_bounded_says_so() {
    let index = published(&["alpha", "alpha alpha alpha", "alpha"]);
    let whole = ask_under(&index, "alpha ", Bounds { expansion: 100, positions: 5 });
    assert_eq!(whole.total, 3);
    assert!(!whole.positions_bounded && !whole.truncated);
    let stopped = ask_under(&index, "alpha ", Bounds { expansion: 100, positions: 2 });
    assert_eq!(docs(&stopped), [doc(1)], "the unit reached before the stop");
    assert_eq!(stopped.total, 1, "a lower bound");
    assert!(stopped.positions_bounded);
    assert!(stopped.truncated);
    // A conjunction stopped inside its second form keeps the units checked
    // against both, in the rarest word's postings order.
    let index = published(&["alpha beta", "alpha beta beta beta", "alpha beta", "gamma"]);
    let checked = ask_under(&index, "alpha beta ", Bounds { expansion: 100, positions: 5 });
    assert_eq!(
        docs(&checked),
        [doc(1)],
        "alpha's three entries, then beta at unit 1; unit 2's three would pass"
    );
    assert!(checked.positions_bounded);
}

/// §3.2 the list's bounds: `offset` and `limit` cut the list and
/// `truncated` says whether more units match than the list holds.
#[test]
fn offset_and_limit_cut_the_list_and_truncated_says_so() {
    let index = published(&["alpha", "alpha", "alpha"]);
    let query = Query::parse("alpha");
    let pair = Pair::guest(&index);
    let two = Index::query(pair, &query, &QueryOpts { offset: 0, limit: 2 });
    assert_eq!((two.hits.len(), two.total, two.truncated), (2, 3, true));
    let rest = Index::query(pair, &query, &QueryOpts { offset: 2, limit: 2 });
    assert_eq!((rest.hits.len(), rest.total, rest.truncated), (1, 3, false));
    assert_eq!(docs(&rest), [doc(3)]);
    let past = Index::query(pair, &query, &QueryOpts { offset: 5, limit: 2 });
    assert_eq!((past.hits.len(), past.total, past.truncated), (0, 3, false));
    let none = Index::query(pair, &query, &QueryOpts { offset: 0, limit: 0 });
    assert_eq!((none.hits.len(), none.total, none.truncated), (0, 3, true));
}

/// §3.3 DETERMINISM: the same pair and query give the same hits in the same
/// order twice, and a tie set is ordered by address whatever order the units
/// entered in.
#[test]
fn the_answer_is_the_same_twice_and_ties_fall_by_address_not_insertion() {
    let mut index = Index::new(Class::Guest);
    for n in [3u32, 1, 2] {
        index.index(unit(Class::Guest, n, "alpha beta")).expect("admitted");
    }
    let first = ask(&index, "alpha");
    let second = ask(&index, "alpha");
    assert_eq!(first, second);
    assert_eq!(docs(&first), [doc(1), doc(2), doc(3)]);
    assert!(first.hits.windows(2).all(|w| w[0].score == w[1].score), "a tie set");
}

/// An empty query, an empty pair and a word no unit holds each answer no
/// hit and no flag.
#[test]
fn nothing_answers_nothing() {
    let index = published(&["alpha"]);
    assert_eq!(ask(&index, ""), Answer::default());
    assert_eq!(ask(&index, "  \"  "), Answer::default());
    assert_eq!(ask(&index, "beta"), Answer::default());
    assert_eq!(ask(&Index::new(Class::Guest), "alpha"), Answer::default());
}

/// §3.1 the hit's members from the unit: the member, `as_of`, the kind, the
/// standing of the published member's edition.
#[test]
fn a_hit_carries_its_units_member_position_kind_and_standing() {
    let mut index = Index::new(Class::Guest);
    let member = addr(&[1, 0, 1, 0, 4, 2]);
    let u = Unit::new(
        UnitKey::new(doc(4)),
        Some(member.clone()),
        Kind::Edition,
        Class::Guest,
        77,
        vec![Item::Text { start: 100, bytes: b"a shot".to_vec() }],
    )
    .expect("one extent");
    index.index(u).expect("admitted");
    let hit = &ask(&index, "shot").hits[0];
    assert_eq!(hit.doc, doc(4));
    assert_eq!(hit.member, Some(member));
    assert_eq!(hit.as_of, 77);
    assert_eq!(hit.kind, Kind::Edition);
    assert_eq!(hit.standing, Standing::Public);
    assert_eq!(hit.span, Span { start: 102, width: 4 }, "the extent starts at 100");
    assert!(hit.snippet.is_some());
}

/// ONE EDIT, counted in characters.
#[test]
fn one_edit_apart_counts_characters() {
    assert!(!one_edit_apart("abc", "abc"), "equal strings are no edit apart");
    assert!(one_edit_apart("abc", "abd"), "a substitution");
    assert!(one_edit_apart("abc", "acb"), "an adjacent transposition");
    assert!(one_edit_apart("abc", "ab"), "a deletion");
    assert!(one_edit_apart("ab", "abc"), "an insertion");
    assert!(one_edit_apart("abc", "xabc"));
    assert!(!one_edit_apart("abc", "xyz"));
    assert!(!one_edit_apart("abcd", "dcba"));
    assert!(!one_edit_apart("abc", "abcde"));
    assert!(!one_edit_apart("abc", "cba"));
    assert!(one_edit_apart("привет", "привeт"), "one Cyrillic letter for a Latin one");
    assert!(one_edit_apart("привет", "приевт"));
    assert!(!one_edit_apart("привет", "прив"));
}
