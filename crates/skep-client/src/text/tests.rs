//! The finder's unit suite.
//!
//! It holds the changes of whole texts to values the prototype's finder
//! gave, the match to `difflib`'s own examples, the cut into lines and
//! words, the bound at both levels, the join at its threshold, and the
//! trim.

use super::*;

/// Returns the change removing `old` and inserting `new`, by their bytes.
fn change(old: Range<usize>, new: Range<usize>) -> Change {
    Change { old, new }
}

/// Returns the changes of `old` into `new`, each law of the list held.
///
/// The changes ascend and lie apart in both texts, each holds a byte and
/// ends on character boundaries, and making them in `old` gives `new`.
fn changes(old: &str, new: &str) -> Vec<Change> {
    let changes = minimal_changes(old, new);
    let (mut made, mut at_old, mut at_new) = (String::new(), 0, 0);
    for (k, change) in changes.iter().enumerate() {
        assert!(!change.old.is_empty() || !change.new.is_empty(), "{old:?} → {new:?}: a change of no byte: {change:?}");
        assert!(at_old <= change.old.start && at_new <= change.new.start, "{old:?} → {new:?}: out of order: {changes:?}");
        assert!(k == 0 || at_old < change.old.start, "{old:?} → {new:?}: two changes touch: {changes:?}");
        for (text, range) in [(old, &change.old), (new, &change.new)] {
            assert!(text.is_char_boundary(range.start) && text.is_char_boundary(range.end), "{old:?} → {new:?}: a character split: {change:?}");
        }
        assert_eq!(&old[at_old..change.old.start], &new[at_new..change.new.start], "{old:?} → {new:?}: what stands between is the same text");
        made.push_str(&old[at_old..change.old.start]);
        made.push_str(&new[change.new.clone()]);
        (at_old, at_new) = (change.old.end, change.new.end);
    }
    made.push_str(&old[at_old..]);
    assert_eq!(made, new, "{old:?}: the changes make the new text: {changes:?}");
    changes
}

/// Returns `text`'s characters, a sequence the match is made over.
fn letters(text: &str) -> Vec<char> {
    text.chars().collect()
}

// ── whole texts, against the prototype ──────────────────────────────────

/// Code with a line moved is two changes, the lines between kept.
///
/// The line is put in where it now stands and taken out where it stood, and
/// the four lines between the two places are in neither change (the mutant
/// that makes the pair as one change re-types them).
#[test]
fn code_with_a_moved_line_is_the_line_put_in_and_the_line_taken_out() {
    let old = "fn total(items: &[Item]) -> u64 {\n    let mut sum = 0;\n    for item in items {\n        sum += item.price;\n    }\n    log(sum);\n    sum\n}\n";
    let new = "fn total(items: &[Item]) -> u64 {\n    log(items.len());\n    let mut sum = 0;\n    for item in items {\n        sum += item.price;\n    }\n    sum\n}\n";
    assert_eq!(changes(old, new), [change(34..34, 34..56), change(112..126, 134..134)]);
    assert_eq!((&new[34..56], &old[112..126]), ("    log(items.len());\n", "    log(sum);\n"));
}

/// An identifier renamed where it repeats is one change at each place.
#[test]
fn a_renamed_identifier_repeated_is_one_change_at_each_place() {
    let old = "let count = items.len();\nif count > limit {\n    return Err(TooMany(count));\n}\nprintln!(\"{count} items\");\n";
    let new = old.replace("count", "total");
    assert_eq!(changes(old, &new), [change(4..9, 4..9), change(28..33, 28..33), change(67..72, 67..72), change(89..94, 89..94)]);
}

/// Prose changed in two sentences is two changes, the sentence between kept.
#[test]
fn prose_changed_in_two_sentences_keeps_the_sentence_between() {
    let old = "The quick brown fox jumps over the lazy dog, and the dog does not mind at all.\nA second sentence stands here unchanged, long enough to be kept as it is.\nThe end comes quickly.\n";
    let new =
        "The quick red fox jumps over the lazy dog, and the dog does not mind at all.\nA second sentence stands here unchanged, long enough to be kept as it is.\nThe end comes slowly, in time.\n";
    assert_eq!(changes(old, new), [change(10..15, 10..13), change(167..174, 165..180)]);
    assert_eq!((&old[10..15], &new[10..13], &old[167..174], &new[165..180]), ("brown", "red", "quickly", "slowly, in time"));
}

/// Lines are matched first, then the words of the lines that changed.
///
/// A line standing in both texts is unchanged though lines around it went
/// in or out, and a changed line gives up only its changed words: two words
/// far apart in one line are two changes.
#[test]
fn lines_are_matched_first_then_the_words_of_the_lines_that_changed() {
    let old = "a = 1\nkeep this line as it is\nb = 2\ntail stays here too\n";
    let new = "a = 10\nkeep this line as it is\nb = 20\ntail stays here too\n";
    assert_eq!(changes(old, new), [change(5..5, 5..6), change(35..35, 36..37)], "each cut to the one byte added");
    let old = "def a():\n    return 1\n\n\ndef b():\n    return 2\n\n\ndef c():\n    return 3\n";
    let new = "import os\n\n\ndef a():\n    return 1\n\n\ndef c():\n    return os.EX_OK\n";
    assert_eq!(changes(old, new), [change(0..0, 0..12), change(24..48, 36..36), change(68..69, 56..64)], "lines put in, lines taken out, a word changed");
    let old = "| `mark` | sets a point a later diff shows the changes from | `git commit` |\n";
    let new = "| `mark {name}` | sets a point a later diff shows the changes from | `git tag` |\n";
    assert_eq!(changes(old, new), [change(7..7, 7..14), change(67..73, 74..77)], "two words of one line");
}

/// A stretch under the threshold is written again with its neighbours.
///
/// Seven characters that are no whitespace between two changes join them,
/// and eight are kept, however much whitespace stands among them; a blank
/// line between two changed lines joins them, and a brace with the line
/// after it does not (the mutants that keep every stretch, or count
/// whitespace, split the first of each pair or join the second).
#[test]
fn a_stretch_under_the_threshold_is_written_again_with_its_neighbours() {
    assert_eq!(changes("aa 1234567 bb", "cc 1234567 dd"), [change(0..13, 0..13)], "seven: one change");
    assert_eq!(changes("aa 12345678 bb", "cc 12345678 dd"), [change(0..2, 0..2), change(12..14, 12..14)], "eight: two");
    assert_eq!(changes("aa 1 2 3 4 5 6 7 bb", "cc 1 2 3 4 5 6 7 dd"), [change(0..19, 0..19)], "seven among whitespace");
    assert_eq!(changes("aa 1 2 3 4 5 6 7 8 bb", "cc 1 2 3 4 5 6 7 8 dd"), [change(0..2, 0..2), change(19..21, 19..21)], "eight among whitespace");
    assert_eq!(changes("x = foo(a) + bar(b)\n", "x = foo2(a) + bar2(b)\n"), [change(7..16, 7..18)], "`(a) + bar` holds seven");
    assert_eq!(changes("a = 1\n\nb = 2\n", "a = 10\n\nb = 20\n"), [change(5..12, 5..14)], "a blank line between");
    assert_eq!(changes("if a {\n    x();\n}\nif b {\n    y();\n}\n", "if a {\n    x(1);\n}\nif b {\n    y(2);\n}\n"), [change(13..13, 13..14), change(31..31, 32..33)]);
    assert_eq!(MIN_KEPT_BETWEEN, 8);
}

/// An addition, a deletion and the same text twice.
#[test]
fn an_addition_a_deletion_and_the_same_text() {
    assert_eq!(changes("", "new"), [change(0..0, 0..3)]);
    assert_eq!(changes("gone", ""), [change(0..4, 0..0)]);
    assert!(changes("same", "same").is_empty() && changes("", "").is_empty());
    assert_eq!(changes("first line stays\nsecond", "first line stays\nsecond line grew"), [change(23..23, 23..33)], "a last line with no line break");
}

/// A change at a text's start and one at its end are each found.
#[test]
fn a_change_at_a_texts_start_and_one_at_its_end() {
    assert_eq!(changes("alpha beta gamma delta epsilon zeta\n", "ALPHA beta gamma delta epsilon ZETA\n"), [change(0..5, 0..5), change(31..35, 31..35)]);
    assert_eq!(changes("beta gamma delta\n", "alpha beta gamma delta\n"), [change(0..0, 0..6)]);
    assert_eq!(changes("beta gamma delta", "beta gamma delta epsilon"), [change(16..16, 16..24)]);
}

/// A carriage return is whitespace within its line.
///
/// Lines are cut after `\n` alone, so a line's `\r` is its last word's
/// neighbour and never a change of its own.
#[test]
fn a_carriage_return_is_whitespace_within_its_line() {
    let old = "one\r\ntwo\r\nthree is long enough\r\nfour\r\n";
    let new = "one\r\n2\r\nthree is long enough\r\nFOUR\r\n";
    assert_eq!(changes(old, new), [change(5..8, 5..6), change(32..36, 30..34)]);
    assert_eq!(Pieces::lines(old).pieces, ["one\r\n", "two\r\n", "three is long enough\r\n", "four\r\n"]);
}

/// A character past ASCII is never split between kept bytes and new ones.
///
/// Two characters that share a byte are replaced whole, a character the
/// two texts share beside a change stands, and a word of such characters is
/// one word.
#[test]
fn a_multibyte_character_is_never_split() {
    assert_eq!(changes("é", "è"), [change(0..2, 0..2)], "C3 A9 / C3 A8: replaced whole");
    assert_eq!(changes("naïve café\n", "naïve thé\n"), [change(7..10, 7..9)], "the é they share stands");
    assert_eq!(changes("日本語 のテキスト は ここ に あります。\n", "日本誤 のテキスト は そこ に あります。\n"), [change(6..33, 6..33)]);
}

// ── the cut ─────────────────────────────────────────────────────────────

/// A text is cut into its lines, and into its words.
///
/// A line ends after its `\n`; a word is a run of word characters, a run of
/// whitespace or one other character, a `_` and a letter past ASCII among
/// the word characters; and each cut's pieces are the text, in order.
#[test]
fn a_text_is_cut_into_its_lines_and_into_its_words() {
    assert_eq!(Pieces::lines("a\n\nb").pieces, ["a\n", "\n", "b"]);
    assert_eq!(Pieces::lines("a\n").pieces, ["a\n"]);
    assert!(Pieces::lines("").pieces.is_empty() && Pieces::words("").pieces.is_empty());
    assert_eq!(Pieces::words("let x_1 = f(naïve,  \tb);\n").pieces, ["let", " ", "x_1", " ", "=", " ", "f", "(", "naïve", ",", "  \t", "b", ")", ";", "\n"]);
    assert_eq!(Pieces::words("=>!!").pieces, ["=", ">", "!", "!"], "each other character is a word of its own");
    assert_eq!(Pieces::words("日本語。 é_").pieces, ["日本語", "。", " ", "é_"]);
    let cut = Pieces::words("ab  cd");
    assert_eq!((cut.bytes(&(0..1)), cut.bytes(&(1..3)), cut.bytes(&(3..3))), (0..2, 2..6, 6..6));
}

// ── the match ───────────────────────────────────────────────────────────

/// The match is `difflib`'s, held to its own documented examples.
///
/// `qabxcd` into `abycdf` is a deletion, a replacement and an insertion
/// around the two blocks the texts share; the longest block of ` abcd` in
/// `abcd abcd` is the whole of it at the second place; and of several
/// longest blocks the earliest in the first sequence is taken, then the
/// earliest in the second (the mutants that take a later block answer
/// another place).
#[test]
fn the_match_is_difflibs_held_to_its_documented_examples() {
    assert_eq!(unmatched(&letters("qabxcd"), &letters("abycdf")), [(0..1, 0..0), (3..4, 2..3), (6..6, 5..6)]);
    assert_eq!(matching_blocks(&letters(" abcd"), &letters("abcd abcd")), [(0, 4, 5)]);
    assert_eq!(matching_blocks(&letters("abxab"), &letters("ab")), [(0, 0, 2)], "the earliest in the first sequence");
    assert_eq!(matching_blocks(&letters("ab"), &letters("abxab")), [(0, 0, 2)], "then the earliest in the second");
    assert_eq!(matching_blocks(&letters("abcxabcd"), &letters("abcd")), [(4, 0, 4)], "the longest, wherever it stands");
    assert_eq!(matching_blocks(&letters("abcd"), &letters("bcda")), [(1, 0, 3)], "what stands before the block in one and after it in the other is not matched");
    assert!(unmatched(&letters("abc"), &letters("abc")).is_empty() && unmatched(&letters(""), &letters("")).is_empty());
    assert_eq!(unmatched(&letters(""), &letters("ab")), [(0..0, 0..2)]);
    assert_eq!(unmatched(&letters("ab"), &letters("")), [(0..2, 0..0)]);
    assert_eq!(unmatched(&letters("ab"), &letters("cd")), [(0..2, 0..2)]);
}

/// A block is found again on either side of the longest, to no depth.
///
/// A sequence whose every element stands alone between two that differ is
/// as many blocks as elements, found one stretch after another with no
/// recursion; the scratch rows are left as they were found, so each stretch
/// is matched as the first was (the mutants that leave a row's lengths
/// standing for the next stretch, or for the row after next, find a block
/// where the two sequences differ).
#[test]
fn a_block_is_found_again_on_either_side_of_the_longest() {
    let a: Vec<u32> = (0..200).collect();
    let b: Vec<u32> = (0..200).map(|n| if n % 2 == 0 { n } else { n + 10_000 }).collect();
    assert_eq!(matching_blocks(&a, &b), (0..100).map(|k| (2 * k, 2 * k, 1)).collect::<Vec<_>>());
    assert_eq!(unmatched(&a, &b), (0..100).map(|k| (2 * k + 1..2 * k + 2, 2 * k + 1..2 * k + 2)).collect::<Vec<_>>());
    assert_eq!(matching_blocks(&letters("xyxyxyxy"), &letters("yxyx")), [(1, 0, 4)]);
    assert_eq!(matching_blocks(&letters("abXcdYab"), &letters("abcdab")), [(0, 0, 2), (3, 2, 2), (6, 4, 2)], "one block found, then one on either side of it");
    assert_eq!(matching_blocks(&letters("AAAAyz"), &letters("AAAAzy")), [(0, 0, 4), (4, 5, 1)], "the stretch after a block is matched from clean rows: `Ay` is no block");
    assert_eq!(matching_blocks(&letters("x?yz"), &letters("xz")), [(0, 0, 1), (3, 1, 1)], "a row reads the row before it alone: `yz` is no block");
}

// ── the bound ───────────────────────────────────────────────────────────

/// Two sequences are matched at the bound and are one run past it.
///
/// A hundred elements against ten thousand multiply to the bound and are
/// matched; a hundred and one against 9,901 multiply to one more, and are
/// one run however much they share (the mutants that never match, match
/// past the bound, or bound at one less answer otherwise).
#[test]
fn two_sequences_are_matched_at_the_bound_and_one_run_past_it() {
    assert_eq!(MAX_MATCH_PRODUCT, 1_000_000);
    let long: Vec<u32> = (0..10_000).collect();
    assert_eq!(100 * long.len(), MAX_MATCH_PRODUCT);
    assert_eq!(unmatched(&long[..100], &long), [(100..100, 100..10_000)], "at the bound: the hundred they share stand");
    assert_eq!(101 * 9_901, MAX_MATCH_PRODUCT + 1);
    assert_eq!(unmatched(&long[..101], &long[..9_901]), [(0..101, 0..9_901)], "one past it: one run");
}

/// Lines past the bound still meet the match by words.
///
/// Half a million blank lines between two changed lines put the pair past
/// the bound by lines; its words are few, so the two changes are found and
/// the word between them stands.
#[test]
fn lines_past_the_bound_still_meet_the_match_by_words() {
    let blank = "\n".repeat(500_000);
    let old = format!("alpha\n{blank}a_long_enough_word omega\n");
    let new = "ALPHA\na_long_enough_word OMEGA\n";
    assert!(Pieces::lines(&old).pieces.len() * Pieces::lines(new).pieces.len() > MAX_MATCH_PRODUCT);
    let end = old.len();
    assert_eq!(changes(&old, new), [change(0..end - 26, 0..5), change(end - 6..end - 1, 25..30)]);
    assert_eq!((&old[end - 6..end - 1], &new[25..30], &old[end - 26..end - 6]), ("omega", "OMEGA", "\na_long_enough_word "));
}

/// A changed line is matched by words at the bound and is one change past it.
///
/// A line of five hundred words is a thousand pieces, so against its like
/// it stands at the bound: its first word and its last are two changes. A
/// line of five hundred and one is past it, and is one change from the
/// first byte that differs to the last.
#[test]
fn a_changed_line_is_matched_by_words_at_the_bound_and_one_change_past_it() {
    let line = |words: usize, first: &str, last: &str| {
        let mut all: Vec<String> = (0..words).map(|n| format!("w{n}")).collect();
        (all[0], all[words - 1]) = (first.to_string(), last.to_string());
        all.join(" ") + "\n"
    };
    let (old, new) = (line(500, "first", "last"), line(500, "FIRST", "LAST"));
    assert_eq!(Pieces::words(&old).pieces.len() * Pieces::words(&new).pieces.len(), MAX_MATCH_PRODUCT);
    let end = old.len();
    assert_eq!(changes(&old, &new), [change(0..5, 0..5), change(end - 5..end - 1, end - 5..end - 1)]);
    let (old, new) = (line(501, "first", "last"), line(501, "FIRST", "LAST"));
    assert!(Pieces::words(&old).pieces.len() * Pieces::words(&new).pieces.len() > MAX_MATCH_PRODUCT);
    let end = old.len();
    assert_eq!(changes(&old, &new), [change(0..end - 1, 0..end - 1)]);
}

// ── the trim ────────────────────────────────────────────────────────────

/// The trim counts what two texts share at either end.
///
/// The start is taken first, and the end from what is left of each, so the
/// two never overlap.
#[test]
fn the_trim_counts_what_two_texts_share_at_either_end() {
    assert_eq!(shared("    let total = add(left, right);\n", "    let total = sub(left, right);\n"), (16, 15));
    assert_eq!(shared("abcabc", "abc"), (3, 0), "the start is taken first, and the end from what is left");
    assert_eq!(shared("abc", "abcabc"), (3, 0));
    assert_eq!(shared("axa", "aa"), (1, 1));
    assert_eq!(shared("", "abc"), (0, 0));
    assert_eq!(shared("abc", "abc"), (3, 0));
    assert_eq!(shared("add", "sub"), (0, 0), "nothing shared");
    assert_eq!(trimmed("a foo b", "a food b", change(2..5, 2..6)), Some(change(5..5, 5..6)), "a change is cut to what differs");
    assert_eq!(trimmed("xabcx", "yabcy", change(1..4, 1..4)), None, "and one the trim leaves nothing of is no change");
}

/// The trim never splits a character between kept bytes and new ones.
///
/// Two characters that share their first bytes, or their last, are replaced
/// whole: the shared start is cut back to a character boundary and the
/// shared end forward to one, in each text (the mutant that trims by bytes
/// keeps half of `é` and inserts half of `è`).
#[test]
fn the_trim_never_splits_a_character() {
    for (old, new, lead, tail) in [
        ("é", "è", 0, 0),     // C3 A9 / C3 A8: the first byte shared
        ("é", "ĩ", 0, 0),     // C3 A9 / C4 A9: the last byte shared
        ("a€b", "a₭b", 1, 1), // E2 82 AC / E2 82 AD: two bytes shared
        ("😀", "😁", 0, 0),   // F0 9F 98 80 / F0 9F 98 81: three shared
        ("x😀", "y😀", 0, 4), // a whole character shared at the end
        ("né", "nè", 1, 0),
        ("éa", "ĩa", 0, 1),
        ("日本語", "日本誤", 6, 0), // E8 AA 9E / E8 AA A4: the last differs in its third byte
    ] {
        assert_eq!(shared(old, new), (lead, tail), "{old:?} → {new:?}");
        for text in [old, new] {
            assert!(text.is_char_boundary(lead) && text.is_char_boundary(text.len() - tail), "{old:?} → {new:?}: a boundary of each text");
        }
    }
}
