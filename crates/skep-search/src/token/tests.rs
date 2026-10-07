use super::*;
use crate::unit::{Class, GapKind, Kind, UnitKey};
use skep_address::{validate, Nat, Tumbler};

fn key() -> UnitKey {
    let t = Tumbler::new([1u32, 0, 1, 0, 1].map(Nat::from)).expect("nonempty");
    UnitKey::new(validate(t).expect("a T4-valid address"))
}

fn unit(items: Vec<Item>) -> Unit {
    Unit::new(key(), None, Kind::Edition, Class::Guest, 1, items).expect("one extent")
}

fn text(start: u64, bytes: &[u8]) -> Item {
    Item::Text { start, bytes: bytes.to_vec() }
}

/// `(term, ordinal, offset, len)` per token, the shape every assertion reads.
fn cut(items: Vec<Item>) -> Vec<(String, u32, u64, u32)> {
    tokenize(&unit(items)).into_iter().map(|t| (t.term, t.ordinal, t.offset, t.len)).collect()
}

fn tok(term: &str, ordinal: u32, offset: u64, len: u32) -> (String, u32, u64, u32) {
    (term.to_string(), ordinal, offset, len)
}

/// §1.3: the two tables are one Unicode version — the segmenter's and the
/// decomposition's — and the revision names it.
#[test]
fn the_two_tables_share_one_unicode_version_which_the_revision_names() {
    let (a, b, c) = unicode_normalization::UNICODE_VERSION;
    assert_eq!(
        (u64::from(a), u64::from(b), u64::from(c)),
        unicode_segmentation::UNICODE_VERSION,
        "unicode-normalization's tables must be the segmenter's Unicode version"
    );
    assert_eq!(REVISION.unicode, unicode_segmentation::UNICODE_VERSION);
    assert_eq!(REVISION.rule, 1);
    assert_eq!(REVISION.to_string(), "1/17.0.0");
}

/// §2.3: the fold's reach — accents go, letters stay, the shapes with no mark
/// to drop stay as they are.
#[test]
fn the_fold_drops_accents_and_keeps_every_letter() {
    assert_eq!(fold("résumé"), "resume");
    assert_eq!(fold("Émile"), "emile");
    assert_eq!(fold("E\u{301}mile"), "emile", "the decomposed spelling folds the same");
    assert_eq!(fold("İstanbul"), "istanbul", "decomposed, the dot dropped, then lowercased");
    for unchanged in ["ß", "ø", "ł", "ı", "æ", "ﬁ"] {
        assert_eq!(fold(unchanged), unchanged, "{unchanged} has no mark to drop");
    }
    assert_eq!(fold("ＰＤＦ"), "ｐｄｆ", "a compatibility form stays one");
    assert_ne!(fold("कु"), fold("क्"), "the vowel sign and the virama are letters");
    assert_eq!(fold("ก\u{E34}"), "ก\u{E34}", "a Thai vowel stays");
}

/// §2.3's residue, each named: U+034F lies inside the first block and is
/// dropped; the Mongolian free variation selectors are kept while the vowel
/// separator goes with the Cf set; the Hangul fillers stay.
#[test]
fn the_folds_residue_falls_as_the_design_names_it() {
    assert_eq!(fold("a\u{034F}b"), "ab", "the combining grapheme joiner is inside U+0300–U+036F");
    assert_eq!(fold("\u{1820}\u{180B}"), "\u{1820}\u{180B}", "an FVS is kept");
    assert_eq!(
        fold("\u{1820}\u{180E}\u{1821}"),
        "\u{1820}\u{1821}",
        "the vowel separator is a format control"
    );
    assert_eq!(fold("\u{3164}"), "\u{3164}", "the Hangul filler is Lo");
    assert_eq!(fold("1\u{FE0F}\u{20E3}"), "1", "the selector and the enclosing keycap go");
}

/// The second fold: the three apostrophe variants become U+0027.
#[test]
fn the_apostrophe_variants_fold_to_the_ascii_apostrophe() {
    assert_eq!(fold("person's"), "person's");
    assert_eq!(fold("person\u{2019}s"), "person's");
    assert_eq!(fold("person\u{2018}s"), "person's");
    assert_eq!(fold("person\u{FF07}s"), "person's");
}

/// The third fold: the invisible format controls go, one of each kind named
/// by §2.3, and the token's range is unchanged by it (asserted on the token
/// below).
#[test]
fn the_format_controls_are_dropped() {
    assert_eq!(fold("trans\u{AD}clusion"), "transclusion");
    assert_eq!(fold("a\u{200E}b\u{200F}c\u{061C}d"), "abcd", "the bidi marks");
    assert_eq!(fold("a\u{202A}b\u{2066}c\u{2069}d"), "abcd", "embeddings and isolates");
    assert_eq!(fold("a\u{200C}b\u{200D}c"), "abc", "ZWNJ and ZWJ");
    assert_eq!(fold("a\u{2060}b\u{FEFF}c"), "abc", "the word joiner and the BOM");
    assert_eq!(fold("a\u{E0001}\u{E0041}b"), "ab", "the tags");
}

/// §2.3: the ordinal and the range across a `Gap` and a `hex` stretch — the
/// range from the unit's start, the gap counted at its width, the invalid
/// byte at its own ordinal, each break advancing the ordinal by one.
#[test]
fn ranges_run_from_the_units_start_across_a_gap_and_a_hex_stretch() {
    let items = vec![
        text(1, b"alpha beta"),
        Item::Gap { start: 11, width: 5, kind: GapKind::Atom },
        text(16, b"gam\xFFma delta"),
    ];
    assert_eq!(
        cut(items),
        vec![
            tok("alpha", 0, 0, 5),
            tok("beta", 1, 6, 4),
            // the gap took ordinal 2
            tok("gam", 3, 15, 3),
            // the invalid byte took ordinal 4
            tok("ma", 5, 19, 2),
            tok("delta", 6, 22, 5),
        ]
    );
}

/// A gap advances the ordinal by ONE whatever its width (§2.1), so the
/// tokens either side are never adjacent and a phrase never crosses it.
#[test]
fn a_gap_advances_the_ordinal_by_one_whatever_its_width() {
    let wide = vec![
        text(1, b"a"),
        Item::Gap { start: 2, width: 1_000, kind: GapKind::Unknown },
        text(1_002, b"b"),
    ];
    assert_eq!(cut(wide), vec![tok("a", 0, 0, 1), tok("b", 2, 1_001, 1)]);
}

/// A kept segment whose fold holds nothing alphanumeric — a stray harakat,
/// which the segmenter attaches to the space before it (WB4) and counts as
/// alphabetic, and which the fold drops, leaving the space — cuts no token
/// and takes no ordinal: `b` follows `a` at ordinal 1.
#[test]
fn a_segment_that_folds_to_nothing_alphanumeric_is_no_token() {
    assert_eq!(
        cut(vec![text(1, "a \u{064E} b".as_bytes())]),
        vec![tok("a", 0, 0, 1), tok("b", 1, 5, 1)]
    );
    assert_eq!(cut(vec![text(1, "\u{064E}".as_bytes())]), vec![], "a mark alone");
}

/// The extent's start is wherever the first item begins: offsets are from
/// it, not from ordinal 1.
#[test]
fn offsets_are_counted_from_the_extents_own_start() {
    assert_eq!(cut(vec![text(500, b"x y")]), vec![tok("x", 0, 0, 1), tok("y", 1, 2, 1)]);
}
