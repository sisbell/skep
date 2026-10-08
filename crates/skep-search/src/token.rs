//! The tokenizer (`search.md` §2.3, D14's half; sx-D16 as sr-E1 scopes it
//! and ITEM 3 amended it; the apostrophe fold; the format-control fold):
//! UAX #29 WORD BOUNDARIES — `unicode-segmentation`'s word iterator over
//! each text item, keeping the segments that hold an alphanumeric character
//! and dropping whitespace and punctuation segments — then FOLDED: each
//! segment decomposed (NFD, by `unicode-normalization`) and its COMBINING
//! DIACRITICAL MARKS dropped — the blocks U+0300–U+036F, U+1AB0–U+1AFF,
//! U+1DC0–U+1DFF, U+20D0–U+20FF and U+FE20–U+FE2F, the OPTIONAL POINTING of
//! Arabic (U+064B–U+065F, U+0670) and Hebrew (U+0591–U+05BD, U+05BF,
//! U+05C1–U+05C2, U+05C4–U+05C5, U+05C7), and the VARIATION SELECTORS
//! U+FE00–U+FE0F and U+E0100–U+E01EF — so `É` is `E`, `ï` is `i`, `ñ` is
//! `n` and `كَتَبَ` is `كتب`, while a mark that is a LETTER of its script
//! (Devanagari's virama and vowel signs, Thai's vowels and tone marks, every
//! Mn outside those ranges) stays: a mark its script writes OPTIONALLY is
//! dropped, a mark that is a letter of its script stays — then each
//! APOSTROPHE VARIANT inside a segment, U+2018, U+2019 and U+FF07, folded to
//! U+0027, a second fold — then every code point inside a segment that is
//! BOTH Default_Ignorable_Code_Point AND of general category Cf, the
//! invisible FORMAT CONTROLS, DROPPED, a third fold — then LOWERCASED by
//! `str::to_lowercase`. The SAME rule runs over the query — [`segments`] is
//! the rule over one stretch, and `Query::parse` cuts the query string with
//! it — so a person without accents on their keyboard finds `Émile` by
//! `emile` as an EXACT hit.
//!
//! What the folding does NOT do, stated (§2.3): `ß`, `ø`, `ł` and the
//! Turkish dotless `ı` have no combining mark to drop and stay; a ligature
//! stays a ligature, and so does every COMPATIBILITY form — NFD decomposes
//! canonically, never by compatibility — so fullwidth `ＰＤＦ` is the term
//! `ｐｄｆ`; the MONGOLIAN FREE VARIATION SELECTORS U+180B–U+180D and U+180F,
//! Mn outside every range dropped, are KEPT, while the Mongolian vowel
//! separator U+180E, a format control, goes with the Cf set; the Hangul
//! fillers, Lo, stay; `10,000` and `10000` are two terms, the joiner kept
//! inside the token; an identifier's INTERIOR is found by no query but the
//! whole token's prefix; no stemming and no stop words (R9b's search is
//! LEXICAL). The third fold's trades: the legacy Malayalam chillu and its
//! dead-consonant homograph become one term, and the Persian spellings with
//! and without the ZWNJ become one term.
//!
//! EACH TOKEN KEEPS ITS RANGE FROM THE UNIT's START (§2.3): its first byte's
//! V-ordinal offset from the extent's start — every `Gap` counted at its
//! width and a `hex` stretch's bytes at their own ordinals — and its length
//! in bytes, the range of the UNFOLDED segment, since folding changes a
//! token's spelling and never its place. The tokenizer runs per text item,
//! token ordinals run in sequence across the unit, and a `Gap` advances the
//! ordinal by one — as does each invalid byte of a `hex` run — so a phrase
//! never crosses an atom, a hex run or a withheld hole, each a real break in
//! the text the person reads (§2.1, §2.2). The postings store the range
//! beside the ordinal (`index`), so a span is read off them byte-exact with
//! no re-tokenizing at result time. The two hand range lists below are tied
//! to [`REVISION`]'s Unicode version, as §2.3 requires, since neither crate
//! exposes the properties they encode. §7.2's twenty-two cases are
//! `tests/it/cases.rs`, each with its byte range.

use std::fmt;

use unicode_normalization::UnicodeNormalization;
use unicode_segmentation::UnicodeSegmentation;

use crate::unit::{Item, Unit};

/// The tokenizer's REVISION (`search.md` §2.3, §5.1): the rule's version —
/// this module's rule, bumped when a boundary rule or a fold changes — and
/// the Unicode version of its two tables, the segmenter's and the
/// decomposition's, which the unit suite holds equal. The index records it
/// (`Index::revision`) and the file names it (lane SR-2): a file cut under an
/// older revision is MIGRATED by re-indexing its stored text, a newer one
/// FACED, never searched under this one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Revision {
    /// The rule's version: 1, this module as it stands.
    pub rule: u32,
    /// The Unicode version of the two tables, as
    /// `unicode_segmentation::UNICODE_VERSION` states it.
    pub unicode: (u64, u64, u64),
}

/// The running crate's tokenizer revision.
pub const REVISION: Revision = Revision { rule: 1, unicode: unicode_segmentation::UNICODE_VERSION };

impl fmt::Display for Revision {
    /// `<rule>/<major>.<minor>.<update>` — `1/17.0.0`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (major, minor, update) = self.unicode;
        write!(f, "{}/{major}.{minor}.{update}", self.rule)
    }
}

/// One token the tokenizer cut (§2.3): its TERM — the segment folded and
/// lowercased, what the dictionary holds — its ORDINAL in the unit's token
/// sequence, and its RANGE from the unit's start: the first byte's V-ordinal
/// offset from the extent's start and its length in bytes, the UNFOLDED
/// segment's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Token {
    /// The folded, lowercased term.
    pub term: String,
    /// The ordinal in the unit's sequence; a gap and an invalid byte each
    /// take one.
    pub ordinal: u32,
    /// The first byte's V-ordinal offset from the unit's start.
    pub offset: u64,
    /// The segment's length in bytes, unfolded.
    pub len: u32,
}

/// sr-E1's DROPPED MARKS, as ITEM 3 amended them: the five combining
/// diacritical blocks, the optional pointing of Arabic and Hebrew, and the
/// two variation-selector blocks. A mark outside these ranges is a LETTER of
/// its script and stays.
const DROPPED_MARKS: &[(char, char)] = &[
    ('\u{0300}', '\u{036F}'), // Combining Diacritical Marks (U+034F lies inside it)
    ('\u{0591}', '\u{05BD}'), // Hebrew pointing
    ('\u{05BF}', '\u{05BF}'),
    ('\u{05C1}', '\u{05C2}'),
    ('\u{05C4}', '\u{05C5}'),
    ('\u{05C7}', '\u{05C7}'),
    ('\u{064B}', '\u{065F}'), // Arabic harakat
    ('\u{0670}', '\u{0670}'),
    ('\u{1AB0}', '\u{1AFF}'),   // Combining Diacritical Marks Extended
    ('\u{1DC0}', '\u{1DFF}'),   // Combining Diacritical Marks Supplement
    ('\u{20D0}', '\u{20FF}'), // Combining Diacritical Marks for Symbols — the enclosing keycap among them
    ('\u{FE00}', '\u{FE0F}'), // Variation Selectors
    ('\u{FE20}', '\u{FE2F}'), // Combining Half Marks
    ('\u{E0100}', '\u{E01EF}'), // Variation Selectors Supplement
];

/// The THIRD FOLD's set: every code point both Default_Ignorable_Code_Point
/// and of general category Cf at Unicode 17.0 — a hand list, since neither
/// crate exposes the property; twelve ranges, tied to the revision's Unicode
/// version. What the property lists beyond them is not Cf and not dropped
/// here: the Mongolian free variation selectors and the Khmer inherent
/// vowels (Mn, kept as letters), the Hangul fillers (Lo), the reserved
/// ranges (Cn), U+034F (Mn, inside the marks above).
const DROPPED_FORMAT: &[(char, char)] = &[
    ('\u{00AD}', '\u{00AD}'),   // soft hyphen
    ('\u{061C}', '\u{061C}'),   // Arabic letter mark
    ('\u{180E}', '\u{180E}'),   // Mongolian vowel separator
    ('\u{200B}', '\u{200F}'),   // ZWSP, ZWNJ, ZWJ, LRM, RLM
    ('\u{202A}', '\u{202E}'),   // the embeddings and overrides
    ('\u{2060}', '\u{2064}'),   // word joiner, the invisible operators
    ('\u{2066}', '\u{206F}'),   // the isolates, the deprecated format characters
    ('\u{FEFF}', '\u{FEFF}'),   // the BOM
    ('\u{1BCA0}', '\u{1BCA3}'), // shorthand format controls
    ('\u{1D173}', '\u{1D17A}'), // musical symbol format controls
    ('\u{E0001}', '\u{E0001}'), // language tag
    ('\u{E0020}', '\u{E007F}'), // tags
];

fn within(c: char, ranges: &[(char, char)]) -> bool {
    ranges.iter().any(|&(lo, hi)| lo <= c && c <= hi)
}

/// Whether the fold drops `c`: a mark sr-E1 scopes or a format control of
/// the third fold.
fn dropped(c: char) -> bool {
    within(c, DROPPED_MARKS) || within(c, DROPPED_FORMAT)
}

/// The apostrophe fold: U+2018, U+2019 and U+FF07 to U+0027, the mapping
/// Lucene's ASCIIFoldingFilter applies; every other code point itself.
fn apostrophe(c: char) -> char {
    match c {
        '\u{2018}' | '\u{2019}' | '\u{FF07}' => '\'',
        c => c,
    }
}

/// THE FOLD (§2.3), the one rule the index and the query share: the segment
/// decomposed by NFD, the marks sr-E1 scopes and the invisible format
/// controls dropped, the apostrophe variants folded to U+0027, then the
/// whole lowercased by `str::to_lowercase`. `Émile`, `Emile` and `emile`
/// fold alike; `person’s` folds to `person's`; `trans­clusion` loses its soft
/// hyphen; `कु` and `क्` stay apart. A segment of optional marks alone folds
/// to nothing alphanumeric, and [`tokenize`] cuts no token for it.
pub fn fold(segment: &str) -> String {
    let mut folded = String::with_capacity(segment.len());
    for c in segment.nfd() {
        if dropped(c) {
            continue;
        }
        folded.push(apostrophe(c));
    }
    folded.to_lowercase()
}

/// One segment the rule keeps (§2.3), cut from a stretch of text with no
/// unit around it: its TERM — the segment folded and lowercased — and its
/// range in the stretch, the byte offset of its first byte and its length,
/// the UNFOLDED segment's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    /// The folded, lowercased term.
    pub term: String,
    /// The byte offset of the segment's first byte in the stretch.
    pub offset: usize,
    /// The segment's length in bytes, unfolded.
    pub len: usize,
}

/// THE RULE over one stretch of valid UTF-8 (§2.3; §3.2: "The SAME rule runs
/// over the query"): the stretch's UAX #29 word segments in order, each
/// folded by [`fold`], and kept only where its FOLDED term holds an
/// alphanumeric character — a whitespace or punctuation segment is dropped,
/// and so is a segment of optional marks alone, which the segmenter attaches
/// to the space before it (WB4) and the fold empties. Three callers and no
/// other cutting: [`tokenize`] runs it over every valid stretch of every
/// text item, placing each segment at its ordinal and its range from the
/// unit's start; the query grammar (`Query::parse`) runs it over the query
/// string, so a query word is the term the text's word is; and a
/// phrase-prefix's candidate cut runs it over the stored text at a fixed
/// occurrence's end, "one token cut there" (§3.2).
pub fn segments(text: &str) -> impl Iterator<Item = Segment> + '_ {
    text.unicode_word_indices().filter_map(|(offset, segment)| {
        let term = fold(segment);
        term.chars().any(char::is_alphanumeric).then(|| Segment {
            term,
            offset,
            len: segment.len(),
        })
    })
}

/// The unit's tokens in order (§2.3): per text item, the valid UTF-8
/// stretches cut by [`segments`] — UAX #29 word boundaries, each segment
/// holding an alphanumeric character folded to its term — and placed at
/// their range from the unit's start; the ordinal advanced by one across
/// every `Gap` and every invalid byte, so no phrase crosses either. A
/// segment whose FOLDED term holds no alphanumeric character is no token and
/// takes no ordinal: the segmenter attaches a stray optional mark to the
/// space before it (UAX #29's WB4) and counts the mark as alphabetic, and
/// the fold then drops it, leaving the whitespace segment the rule drops.
/// Built against no index, under no lock (§5.6): `Index::prepare` calls this
/// and nothing else does the cutting.
pub fn tokenize(unit: &Unit) -> Vec<Token> {
    let mut tokens = Vec::new();
    let mut ordinal: u32 = 0;
    for item in unit.items() {
        match item {
            Item::Gap { .. } => ordinal = next(ordinal, 1),
            Item::Text { start, bytes } => {
                let base = start - unit.start();
                let mut at = 0usize;
                for chunk in bytes.utf8_chunks() {
                    let valid = chunk.valid();
                    for segment in segments(valid) {
                        tokens.push(Token {
                            term: segment.term,
                            ordinal,
                            offset: base + (at + segment.offset) as u64,
                            len: u32::try_from(segment.len)
                                .expect("a word segment past 4 GiB is beyond the ceiling's reach"),
                        });
                        ordinal = next(ordinal, 1);
                    }
                    at += valid.len();
                    let invalid = chunk.invalid().len();
                    ordinal = next(ordinal, invalid);
                    at += invalid;
                }
            }
        }
    }
    tokens
}

/// The ordinal after `steps` more tokens or breaks; the count is bounded by
/// the unit's positions, which the ceiling (§7.4) keeps far below `u32`.
fn next(ordinal: u32, steps: usize) -> u32 {
    u32::try_from(steps)
        .ok()
        .and_then(|s| ordinal.checked_add(s))
        .expect("a unit's token count is bounded by its positions, far below u32")
}

#[cfg(test)]
mod tests;
