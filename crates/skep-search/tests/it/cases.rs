//! §7.2's TWENTY-TWO CASES, asserted (`search.md` §2.3's consequences for the
//! project's own text; §7.1's M3): each test is one case in §7.2's own
//! words, asserting the tokens the tokenizer cuts AND each token's byte
//! range — its offset from the unit's start and its length, the unfolded
//! segment's — so the span test (§0 fact 11) rides the same vectors: the
//! token's bytes in the item ARE the V-ordinals it claims. The two GRAMMAR
//! cases of §7.2 (`PUB-5.115` typed bare; `東京都` typed bare) are the
//! query's and lane SR-3's. Every unit here is one text item at ordinal 1,
//! read at guest class.

use skep_search::{tokenize, Class};

use crate::text_unit;

/// `(term, ordinal, offset, len)` per token.
type Cut = (String, u32, u64, u32);

fn cut_bytes(bytes: &[u8]) -> Vec<Cut> {
    tokenize(&text_unit(Class::Guest, 1, bytes))
        .into_iter()
        .map(|t| (t.term, t.ordinal, t.offset, t.len))
        .collect()
}

fn cut(text: &str) -> Vec<Cut> {
    cut_bytes(text.as_bytes())
}

fn tok(term: &str, ordinal: u32, offset: u64, len: u32) -> Cut {
    (term.to_string(), ordinal, offset, len)
}

/// 1. `1.0.1.0.1` → one token: UAX #29 keeps digits joined across `.`, so an
/// address is found as typed.
#[test]
fn a_dotted_address_stays_one_token() {
    assert_eq!(cut("1.0.1.0.1"), vec![tok("1.0.1.0.1", 0, 0, 9)]);
}

/// 2. `PUB-5.115` → `pub`, `5.115`: a hyphen is no MidLetter, and the two
/// tokens are adjacent.
#[test]
fn a_rule_id_is_two_adjacent_tokens_pub_and_its_number() {
    assert_eq!(cut("PUB-5.115"), vec![tok("pub", 0, 0, 3), tok("5.115", 1, 4, 5)]);
}

/// 3. `` `retrieve_v` `` → `retrieve_v`: the backticks are punctuation and
/// drop; `_` is ExtendNumLet and joins letters.
#[test]
fn a_backticked_identifier_is_one_token_without_its_backticks() {
    assert_eq!(cut("`retrieve_v`"), vec![tok("retrieve_v", 0, 1, 10)]);
}

/// 4. `search-free` → `search`, `free`: every hyphenated word splits.
#[test]
fn a_hyphenated_word_is_two_tokens() {
    assert_eq!(cut("search-free"), vec![tok("search", 0, 0, 6), tok("free", 1, 7, 4)]);
}

/// 5. `person's` and `person’s` → one token each, ONE TERM: the ASCII
/// apostrophe is Single_Quote and U+2019 is MidNumLet, both join letters,
/// and the apostrophe fold makes the two spellings one term — over eight
/// bytes and ten.
#[test]
fn the_two_possessives_are_one_token_each_and_one_term() {
    let ascii = cut("person's");
    let typographic = cut("person\u{2019}s");
    assert_eq!(ascii, vec![tok("person's", 0, 0, 8)]);
    assert_eq!(typographic, vec![tok("person's", 0, 0, 10)]);
    assert_eq!(ascii[0].0, typographic[0].0, "one term");
}

/// 6. `scope:content` → one token: `:` is MidLetter between letters, UAX
/// #29's known oddity, asserted rather than discovered.
#[test]
fn a_colon_joined_pair_is_one_token() {
    assert_eq!(cut("scope:content"), vec![tok("scope:content", 0, 0, 13)]);
}

/// 7. `10,000` → one token: a MidNum between numerics; `10` finds it as a
/// prefix.
#[test]
fn a_thousands_separated_number_is_one_token() {
    assert_eq!(cut("10,000"), vec![tok("10,000", 0, 0, 6)]);
}

/// 8. `Émile` → `emile`, folded then lowercased; the byte range the six
/// bytes of a precomposed `Émile`, `c3 89 6d 69 6c 65`, or the seven of a
/// decomposed one.
#[test]
fn emile_folds_to_emile_over_six_bytes_precomposed_and_seven_decomposed() {
    let precomposed = "\u{C9}mile";
    assert_eq!(precomposed.as_bytes(), [0xc3, 0x89, 0x6d, 0x69, 0x6c, 0x65]);
    assert_eq!(cut(precomposed), vec![tok("emile", 0, 0, 6)]);
    let decomposed = "E\u{301}mile";
    assert_eq!(decomposed.len(), 7);
    assert_eq!(cut(decomposed), vec![tok("emile", 0, 0, 7)]);
    assert_eq!(cut("Emile"), vec![tok("emile", 0, 0, 5)], "`Emile` and `emile` find it alike");
}

/// 9. `https://acme.skep.host/l/abc` → `https`, `acme.skep.host`, `l`,
/// `abc`: the host one token, dots between letters being MidNumLet.
#[test]
fn a_url_is_its_scheme_its_host_and_its_path_segments() {
    assert_eq!(
        cut("https://acme.skep.host/l/abc"),
        vec![
            tok("https", 0, 0, 5),
            tok("acme.skep.host", 1, 8, 14),
            tok("l", 2, 23, 1),
            tok("abc", 3, 25, 3)
        ]
    );
}

/// 10. A run of three Han characters → three one-character tokens, adjacent,
/// so the three-character phrase finds the run.
#[test]
fn three_han_characters_are_three_adjacent_one_character_tokens() {
    assert_eq!(cut("東京都"), vec![tok("東", 0, 0, 3), tok("京", 1, 3, 3), tok("都", 2, 6, 3)]);
}

/// 11. `कु` and `क्` → one token each, TWO TERMS: the vowel sign and the
/// virama are letters of their script, not dropped (sr-E1).
#[test]
fn a_devanagari_vowel_sign_and_virama_are_letters_two_terms() {
    let ku = cut("कु");
    let k_virama = cut("क्");
    assert_eq!(ku, vec![tok("क\u{941}", 0, 0, 6)]);
    assert_eq!(k_virama, vec![tok("क\u{94D}", 0, 0, 6)]);
    assert_ne!(ku[0].0, k_virama[0].0, "two terms");
}

/// 12. `كَتَبَ` → one token, the term `كتب`: the harakat dropped, sr-E1's
/// ranges; the range the twelve bytes of the pointed spelling.
#[test]
fn arabic_harakat_are_dropped() {
    let pointed = "ك\u{64E}ت\u{64E}ب\u{64E}";
    assert_eq!(pointed.len(), 12);
    assert_eq!(cut(pointed), vec![tok("كتب", 0, 0, 12)]);
    assert_eq!(cut("كتب"), vec![tok("كتب", 0, 0, 6)], "the unpointed query is the same term");
}

/// 13. A run holding ONE invalid byte → the valid stretches either side as
/// text at their own V-ordinals, the byte a token break that advances the
/// ordinal.
#[test]
fn one_invalid_byte_breaks_the_run_into_two_stretches_at_their_own_ordinals() {
    assert_eq!(cut_bytes(b"abc\xFFdef"), vec![tok("abc", 0, 0, 3), tok("def", 2, 4, 3)]);
    assert_eq!(
        cut_bytes(b"one two\xFF three"),
        vec![tok("one", 0, 0, 3), tok("two", 1, 4, 3), tok("three", 3, 9, 5)],
        "a phrase never crosses the byte: `two` and `three` are not adjacent"
    );
}

/// 14. `HybridSigner` → one token, the term `hybridsigner`, which `signer`
/// finds not: an identifier's interior.
#[test]
fn an_identifier_is_one_lowercased_term_its_interior_unfound() {
    let cut = cut("HybridSigner");
    assert_eq!(cut, vec![tok("hybridsigner", 0, 0, 12)]);
    assert!(!cut[0].0.starts_with("signer"), "the whole token's prefix is the one way in");
}

/// 15. Fullwidth `ＰＤＦ` → the term `ｐｄｆ`, which `pdf` finds not: a
/// compatibility form, which NFD never decomposes.
#[test]
fn fullwidth_pdf_stays_a_compatibility_form() {
    let cut = cut("ＰＤＦ");
    assert_eq!(cut, vec![tok("ｐｄｆ", 0, 0, 9)]);
    assert_ne!(cut[0].0, "pdf");
    assert!(!cut[0].0.starts_with("pdf"));
}

/// 16. `trans­clusion` → the term `transclusion`: the soft hyphen dropped,
/// §2.3's third fold, the range the fourteen bytes of the typeset spelling.
#[test]
fn a_soft_hyphen_is_dropped_from_its_word() {
    let typeset = "trans\u{AD}clusion";
    assert_eq!(typeset.len(), 14);
    assert_eq!(cut(typeset), vec![tok("transclusion", 0, 0, 14)]);
}

/// 17. A KEYCAP `1` + U+FE0F + U+20E3 → the term `1`: the variation selector
/// dropped with sr-E1's amended list, the enclosing keycap with its range.
#[test]
fn a_keycap_folds_to_its_digit() {
    let keycap = "1\u{FE0F}\u{20E3}";
    assert_eq!(keycap.len(), 7);
    assert_eq!(cut(keycap), vec![tok("1", 0, 0, 7)]);
}

/// 18. An SVS-written CJK compatibility ideograph beside its compatibility
/// form → ONE term, the unified base: NFD and the selector's drop agreeing.
#[test]
fn a_compatibility_ideograph_and_its_svs_form_are_one_term() {
    let compatibility = cut("\u{FA10}");
    let svs = cut("\u{585A}\u{FE00}");
    assert_eq!(compatibility, vec![tok("塚", 0, 0, 3)]);
    assert_eq!(svs, vec![tok("塚", 0, 0, 6)]);
    assert_eq!(compatibility[0].0, svs[0].0, "one term, the unified base");
}

/// 19. `ශ්‍රී` with and without its ZWJ → ONE term.
#[test]
fn sinhala_sri_with_and_without_its_zwj_is_one_term() {
    let with = cut("ශ\u{DCA}\u{200D}ර\u{DD3}");
    let without = cut("ශ\u{DCA}ර\u{DD3}");
    assert_eq!(with, vec![tok("ශ\u{DCA}ර\u{DD3}", 0, 0, 15)]);
    assert_eq!(without, vec![tok("ශ\u{DCA}ර\u{DD3}", 0, 0, 12)]);
    assert_eq!(with[0].0, without[0].0, "one term");
}

/// 20. `می‌خواهم` with and without its ZWNJ → ONE term: the Persian trade.
#[test]
fn persian_with_and_without_its_zwnj_is_one_term() {
    let with = cut("می\u{200C}خواهم");
    let without = cut("میخواهم");
    assert_eq!(with, vec![tok("میخواهم", 0, 0, 17)]);
    assert_eq!(without, vec![tok("میخواهم", 0, 0, 14)]);
    assert_eq!(with[0].0, without[0].0, "one term");
}

/// 21. A ZWSP U+200B between two Thai runs → two tokens, the ZWSP inside
/// neither: the segmenter breaks there, so the fold never sees it.
#[test]
fn a_zwsp_between_two_thai_runs_leaves_two_tokens_holding_neither() {
    assert_eq!(
        cut("ก\u{E34}\u{200B}ข\u{E35}"),
        vec![tok("ก\u{E34}", 0, 0, 6), tok("ข\u{E35}", 1, 9, 6)]
    );
}

/// 22. A Mongolian word carrying an FVS → one token holding the selector,
/// which the unmarked query finds as a prefix alone: kept, §2.3's residue.
#[test]
fn a_mongolian_word_keeps_its_free_variation_selector_found_as_a_prefix_alone() {
    let marked = cut("\u{1820}\u{180B}");
    assert_eq!(marked, vec![tok("\u{1820}\u{180B}", 0, 0, 6)]);
    let unmarked = cut("\u{1820}");
    assert_eq!(unmarked, vec![tok("\u{1820}", 0, 0, 3)]);
    assert_ne!(marked[0].0, unmarked[0].0, "not the same term");
    assert!(marked[0].0.starts_with(&unmarked[0].0), "found as a prefix alone");
}
