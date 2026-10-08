//! §3.2's FORMS at the public surface, §7.2's TWO GRAMMAR CASES with their
//! byte ranges — "`PUB-5.115` typed bare finds the unit that holds it and not
//! `AUTH-5.115` beside `PUB-1.2`; `東京都` typed bare finds the run. Each with
//! its byte ranges, so the span test (fact 11) rides the same vectors: the
//! token's bytes in the item ARE the V-ordinals it claims" — §8.3's query
//! items: the phrase and the phrase-prefix finding `shot`, the implicit
//! phrase, the conjunctive window, the fuzzy word's cases; and EVERY BOUND
//! IS A FLAG at the REAL constants: the expansion's bound, the positions
//! bound stopping a common phrase-prefix with the reached units ranked, the
//! fuzzy words bound.

use skep_search::{
    Answer, Class, Index, Matched, Pair, Query, QueryOpts, Span, Unit, EXPANSION_BOUND_ENTRIES,
    FUZZY_MIN_CHARS, FUZZY_WORDS, POSITIONS_BOUND, PREFIX_MIN_CHARS,
};

use crate::{doc, text_unit};

fn published(texts: &[&str]) -> Index {
    let mut index = Index::new(Class::Guest);
    for (i, text) in texts.iter().enumerate() {
        index.index(text_unit(Class::Guest, i as u32 + 1, text.as_bytes())).expect("admitted");
    }
    index
}

fn ask(index: &Index, text: &str) -> Answer {
    Index::query(Pair::guest(index), &Query::parse(text), &QueryOpts::default())
}

fn docs(answer: &Answer) -> Vec<u32> {
    answer
        .hits
        .iter()
        .map(|h| (1..=9).find(|&n| h.doc == doc(n)).expect("a numbered document"))
        .collect()
}

/// §7.2, the first grammar case: `PUB-5.115` typed bare — a split chunk at
/// the string's end, a phrase-prefix over `5.115*` after `pub` — finds the
/// unit that holds it and not `AUTH-5.115` beside `PUB-1.2`; the span is the
/// rule id's own nine bytes at the V-ordinals it claims (fact 11).
#[test]
fn pub_5_115_typed_bare_finds_the_unit_that_holds_it_and_not_auth_5_115_beside_pub_1_2() {
    let index =
        published(&["PUB-5.115 holds the rule", "AUTH-5.115 beside PUB-1.2", "see PUB-5.115 here"]);
    let bare = ask(&index, "PUB-5.115");
    assert_eq!(docs(&bare), [3, 1], "the shorter unit first; never unit 2");
    assert_eq!(bare.hits[1].span, Span { start: 1, width: 9 }, "`PUB-5.115` at V-ordinals 1..10");
    assert_eq!(bare.hits[0].span, Span { start: 5, width: 9 }, "after `see `");
    let phrase = ask(&index, "PUB-5.115 ");
    assert_eq!(docs(&phrase), [3, 1], "complete, an implicit phrase");
    assert_eq!(phrase.hits[1].span, Span { start: 1, width: 9 });
    assert_eq!(docs(&ask(&index, "AUTH-5.115")), [2]);
    assert_eq!(docs(&ask(&index, "PUB-1.2")), [2]);
    assert_eq!(ask(&index, "5.115").hits.len(), 3, "`5.115` alone also finds it");
}

/// §7.2, the second grammar case: `東京都` typed bare — an unspaced run the
/// tokenizer cuts to three one-character tokens, a phrase-prefix over `都*`
/// after `東京` — finds the run and not its characters elsewhere; the span is
/// the run's nine bytes (fact 11).
#[test]
fn tokyo_typed_bare_finds_the_run_with_its_byte_range() {
    let index = published(&["東京都", "京都 と 東", "the 東京都 office", "東京大阪"]);
    let answer = ask(&index, "東京都");
    assert_eq!(docs(&answer), [1, 3]);
    assert_eq!(answer.hits[0].span, Span { start: 1, width: 9 }, "three characters, nine bytes");
    assert_eq!(answer.hits[1].span, Span { start: 5, width: 9 });
    assert_eq!(
        docs(&ask(&index, "東京")),
        [1, 4, 3],
        "`東京` is a prefix over `京*` after `東`, the shorter first"
    );
    assert!(ask(&index, "都京").hits.is_empty(), "the characters in another order");
}

/// §8.3: phrase and phrase-prefix — `"the publish s` finding `shot` by the
/// terms after the fixed phrase's occurrences, the commonest `s` word
/// elsewhere notwithstanding.
#[test]
fn the_phrase_prefix_finds_shot_after_the_fixed_words() {
    let index = published(&[
        "the publish shot lands on the trunk",
        "see see see state state should should should",
        "the publish",
    ]);
    let answer = ask(&index, "\"the publish s");
    assert_eq!(docs(&answer), [1]);
    assert_eq!(answer.hits[0].span, Span { start: 1, width: 16 }, "`the publish shot`");
    assert!(!answer.more_terms, "`shot` is the one term after the fixed words");
    assert_eq!(docs(&ask(&index, "\"the publish shot\"")), [1]);
    assert!(ask(&index, "\"publish the\"").hits.is_empty());
}

/// §8.3: the implicit phrase and the conjunctive window — `search-free`
/// finds the hyphenated word and not the words apart; two bare words find a
/// unit holding both, the span the tightest window holding one of each.
#[test]
fn the_implicit_phrase_and_the_conjunctive_window() {
    let index = published(&[
        "a search-free substrate",
        "free search for all",
        "search then much later free",
    ]);
    assert_eq!(docs(&ask(&index, "search-free ")), [1]);
    assert_eq!(docs(&ask(&index, "search-fr")), [1], "the split chunk mid-typing");
    let both = ask(&index, "free search ");
    assert_eq!(both.total, 3, "the conjunction holds all three");
    let third = both.hits.iter().find(|h| h.doc == doc(3)).expect("unit 3");
    assert_eq!(third.span, Span { start: 1, width: 27 }, "from `search` through `free`");
    let first = both.hits.iter().find(|h| h.doc == doc(1)).expect("unit 1");
    assert_eq!(first.span, Span { start: 3, width: 11 }, "`search-free` itself");
}

/// §8.3's fuzzy cases: one edit of each kind found, counted in characters; a
/// four-letter word and an exact term NOT expanded; the trailing prefix not
/// expanded; `matched` filled; a fourth complete word left as typed with
/// `fuzzy_bounded` set.
#[test]
fn the_fuzzy_word_cases() {
    assert_eq!((FUZZY_WORDS, FUZZY_MIN_CHARS, PREFIX_MIN_CHARS), (3, 5, 1));
    let index =
        published(&["transclusion links the passage to its origin", "alphas bravos charls deltas"]);
    for (typo, kind) in [
        ("transclusin ", "a deletion"),
        ("transcluusion ", "an insertion"),
        ("transclusiom ", "a substitution"),
        ("transclusoin ", "an adjacent transposition"),
    ] {
        let answer = ask(&index, typo);
        assert_eq!(docs(&answer), [1], "{kind}");
        assert_eq!(
            answer.hits[0].matched,
            [Matched { word: typo.trim().to_string(), term: "transclusion".to_string() }],
            "{kind}: `matched` filled"
        );
        assert!(!answer.fuzzy_bounded);
    }
    assert!(ask(&index, "lnks ").hits.is_empty(), "four letters: not expanded");
    assert!(ask(&index, "transclusin").hits.is_empty(), "the trailing prefix: not expanded");
    let exact = ask(&index, "passage ");
    assert_eq!(docs(&exact), [1]);
    assert!(exact.hits[0].matched.is_empty(), "an exact term takes no expansion");
    let three = ask(&index, "bravoz charlz deltaz ");
    assert_eq!(docs(&three), [2]);
    assert_eq!(three.hits[0].matched.len(), 3);
    assert!(!three.fuzzy_bounded);
    let four = ask(&index, "alphaz bravoz charlz deltaz ");
    assert!(four.hits.is_empty(), "the fourth, farthest from the end, is matched as typed");
    assert!(four.fuzzy_bounded, "and the answer says so");
}

/// §3.2 THE EXPANSION's BOUND at the real constant: a prefix whose
/// completions' entries pass `EXPANSION_BOUND_ENTRIES` takes them by
/// document frequency descending until the next would pass, and
/// `more_terms` says so.
#[test]
fn the_expansion_bound_is_met_at_the_real_constant_and_flagged() {
    assert_eq!(EXPANSION_BOUND_ENTRIES, 1 << 16);
    let half = (EXPANSION_BOUND_ENTRIES / 2 + 1) as usize;
    let text = "aa ab ".repeat(half);
    let index = published(&[&text, "aa"]);
    let answer = ask(&index, "a");
    assert!(answer.more_terms, "`aa` (df 2) taken at {half} entries; `ab` would pass the bound");
    assert_eq!(docs(&answer), [1, 2], "the long unit's tf saturates near idf · (k₁ + 1)");
    assert_eq!(answer.hits[0].occurrences, half, "`aa` alone, not `ab`");
    let under = published(&["aa ab ab ac"]);
    assert!(!ask(&under, "a").more_terms, "under the bound, no flag");
}

/// §3.2, §8.3 THE POSITIONS BOUND at the real constant: a common
/// phrase-prefix — `"of the d` over a unit holding the phrase forty thousand
/// times — stops the keystroke's evaluation where the next merge would pass
/// `POSITIONS_BOUND`, the units reached first ranked and answered,
/// `positions_bounded` set, `total` a lower bound and `truncated` true.
#[test]
fn a_common_phrase_prefix_is_stopped_at_the_positions_bound_with_the_reached_units_ranked() {
    assert_eq!(POSITIONS_BOUND, 1 << 16);
    let repeats = 40_000usize;
    let common = "of the dog ".repeat(repeats);
    let index = published(&["of the dog", &common]);
    let answer = ask(&index, "\"of the d");
    assert_eq!(docs(&answer), [1], "the unit reached before the stop");
    assert_eq!(answer.hits[0].span, Span { start: 1, width: 10 }, "`of the dog`");
    assert!(answer.positions_bounded, "the flag");
    assert!(answer.truncated);
    assert_eq!(answer.total, 1, "a lower bound");
    let rare = ask(&index, "\"of the dog\" ");
    assert!(rare.positions_bounded, "the fixed phrase alone passes the bound too");
    let small = published(&["of the dog", "of the dog of the cat"]);
    let whole = ask(&small, "\"of the d");
    assert_eq!(whole.total, 2);
    assert!(!whole.positions_bounded && !whole.truncated);
}

/// The empty query, a string of no words and a word no unit holds each
/// answer nothing, with no flag.
#[test]
fn an_empty_or_unmatched_query_answers_nothing() {
    let index = published(&["alpha"]);
    for text in ["", "   ", "\"\"", "...", "beta"] {
        assert_eq!(ask(&index, text), Answer::default(), "{text:?}");
    }
    let unit: Unit = text_unit(Class::Guest, 1, b"alpha");
    assert_eq!(unit.positions(), 5);
}
