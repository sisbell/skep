//! T9 — THE CODE's ALPHABET, at every byte, and its value,
//! `InviteCode::parse`, admitting exactly the codes the alphabet does, its
//! `Debug` showing none of it. (The invite file that keeps a code is
//! `invites`' suite; the link a code rides, `pages`'.)

use super::*;

/// THE CODE's ALPHABET: a space, `&`, `/`, the empty code and one byte past
/// [`MAX_CODE_BYTES`] are outside it; a document's address, every
/// unreserved character and a code at the bound are inside — and
/// [`InviteCode::parse`], the value's one door, admits exactly the codes the
/// alphabet does, keeping each as given, its `Debug` showing none of it.
#[test]
fn a_code_is_1_to_128_unreserved_characters_and_parse_admits_just_those() {
    let long = "x".repeat(MAX_CODE_BYTES + 1);
    for bad in ["has space", "a&b", "a/b", "", long.as_str()] {
        assert!(!code_ok(bad), "{bad:?}");
        assert!(InviteCode::parse(bad).is_none(), "{bad:?}");
    }
    let longest = "x".repeat(MAX_CODE_BYTES);
    for good in ["abc", "1.1.0.1.0.3", "A-z_0.9~", longest.as_str()] {
        assert!(code_ok(good), "{good:?}");
        assert_eq!(InviteCode::parse(good).as_ref().map(InviteCode::as_str), Some(good));
    }
    assert_eq!(format!("{:?}", InviteCode::parse("secretcode").expect("a code")), "InviteCode(…)");
}

/// THE CODE's ALPHABET AT EVERY BYTE: `a`, one character, `a` is a code iff
/// the character is a letter, a digit, `-`, `.`, `_` or `~` — the URL's
/// unreserved characters, each riding the invite link as it is — and
/// refused for every other: `+`, which the link would carry as a space, `%`,
/// which opens an escape, `#`, which ends the query, and `&`, `=`, a space,
/// a control character and every character past ASCII.
#[test]
fn every_character_but_the_unreserved_is_out_of_the_alphabet() {
    for b in 0..=255u8 {
        let code = format!("a{}a", char::from(b));
        let unreserved = b.is_ascii_alphanumeric() || b"-._~".contains(&b);
        assert_eq!(code_ok(&code), unreserved, "{b:#04x}");
        assert_eq!(InviteCode::parse(&code).is_some(), unreserved, "{b:#04x}");
    }
}
