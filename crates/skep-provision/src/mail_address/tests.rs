//! T10 — THE ADDRESS RULE: ASCII alone, at every character past it; each
//! special and each bidi control refused alone; its words for a refusal to
//! name; and its value, `MailAddress::parse`, admitting exactly the
//! addresses the rule does, its `Debug` showing none of it. (The files that
//! keep an address are `signups`' and `invites`' suites; the flags that take
//! one, `args`'.)

use super::*;

/// The address rule: one `@` with a side each way, at most 254 bytes, no
/// control character and no whitespace, none of RFC 5322's specials but `@`
/// and `.` — a second recipient, a group, a route, a quoted or a commented
/// form — and ASCII alone — no bidi control, no letter of another script in
/// a Latin one's shape, nothing drawn as nothing — and
/// [`MailAddress::parse`], its one door, admits exactly the addresses the
/// rule does, keeping each as given, its `Debug` showing none of it.
#[test]
fn an_address_is_ascii_with_one_at_a_side_each_way_and_no_space_control_or_special() {
    for ok in ["a@b", "person@example.com", "first.last+tag@sub.example.org", "o'brien_x-y@example.org"] {
        assert!(address_ok(ok), "{ok}");
        assert_eq!(MailAddress::parse(ok).as_ref().map(MailAddress::as_str), Some(ok));
    }
    let long = format!("{}@b", "a".repeat(MAX_ADDRESS_BYTES - 2));
    assert!(address_ok(&long));
    assert!(MailAddress::parse(&long).is_some());
    for bad in [
        "",
        "ab",
        "@b",
        "a@",
        "a@b@c",
        "a b@c",
        "a@b\n",
        "a\t@b",
        "a@b\r",
        "\u{a0}a@b",
        "me@x.example,root",
        "g:me@x.example;",
        "\"me\"@x.example",
        "me@[192.0.2.1]",
        "(c)me@x.example",
        "<me@x.example>",
        "me\\@x.example",
        "me@x.example\u{202E}",
        "\u{430}lice@x.example",
        "a\u{200B}@x.example",
        "a@x.example\u{FEFF}",
        "a\u{AD}b@x.example",
        "a@x\u{E0041}.example",
        "\u{E9}@x.example",
    ] {
        assert!(!address_ok(bad), "{bad:?}");
        assert!(MailAddress::parse(bad).is_none(), "{bad:?}");
    }
    assert!(!address_ok(&format!("{long}c")), "255 bytes");
    assert!(MailAddress::parse(&format!("{long}c")).is_none(), "255 bytes");
    assert_eq!(format!("{:?}", MailAddress::parse("person@example.com").expect("an address")), "MailAddress(…)");
}

/// THE RULE's REFUSALS ONE CHARACTER AT A TIME: `a<c>a@x.example` is no
/// address for each of RFC 5322's specials but `@` and `.`, and for each
/// bidi control `render_inert` disarms — the format characters no control
/// test catches, refused with every character past ASCII; and the
/// punctuation a mailbox carries — `.`, `+`, `-`, `_`, `'` — stays inside
/// the rule.
#[test]
fn each_special_and_each_bidi_control_alone_is_refused() {
    let bidi = (0x202A..=0x202E).chain(0x2066..=0x2069).chain([0x200E, 0x200F, 0x061C]).map(|code| char::from_u32(code).expect("a scalar value"));
    for c in "()<>[]:;\\,\"".chars().chain(bidi) {
        let address = format!("a{c}a@x.example");
        assert!(!address_ok(&address), "{c:?}");
        assert!(MailAddress::parse(&address).is_none(), "{c:?}");
    }
    for c in ['.', '+', '-', '_', '\''] {
        assert!(address_ok(&format!("a{c}a@x.example")), "{c:?}");
    }
}

/// ASCII ALONE, AT EVERY CHARACTER PAST IT: `a<c>a@x.example` is no address
/// for each character of the Basic Multilingual Plane past ASCII — a letter
/// of another script in a Latin one's shape, a zero-width character, a soft
/// hyphen, a bidi control among them — and for one in every 256 of the
/// planes beyond, a tag character and the last scalar value beside them:
/// each refused by the rule and at its one door.
#[test]
fn every_character_past_ascii_is_refused() {
    let beyond = (0x1_0000..=0x10_FFFF).step_by(0x100).chain([0xE_0041, 0x10_FFFF]);
    for c in (0x80..=0xFFFF).chain(beyond).filter_map(char::from_u32) {
        let address = format!("a{c}a@x.example");
        assert!(!address_ok(&address), "{:#x}", u32::from(c));
        assert!(MailAddress::parse(&address).is_none(), "{:#x}", u32::from(c));
    }
}

/// THE RULE IN WORDS names what the rule refuses: every one of RFC 5322's
/// specials but `@` and `.` — this suite's own list, never the rule's — the
/// byte bound and ASCII alone, in the sentence a refusal shows the operator.
#[test]
fn the_rules_words_name_its_bound_and_every_special() {
    let words = address_rule();
    for c in "()<>[]:;\\,\"".chars() {
        assert!(words.contains(&format!(" {c} ")) || words.ends_with(&format!(" {c}")), "{c:?}: {words}");
    }
    assert!(words.contains(&format!("at most {MAX_ADDRESS_BYTES} bytes")), "{words}");
    assert_eq!(words, "one @ with a side each way, at most 254 bytes, ASCII alone, no space, no control character, none of ( ) < > [ ] : ; \\ , \"");
}
