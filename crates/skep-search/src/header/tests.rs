//! The header line's fence (`search.md` §5.1; PATTERNS P35, P38): the
//! canonical bytes of both kinds, byte-exact against a literal;
//! `parse(encode(h)) == h` and `encode(parse(b)) == b`; `v` read FIRST; every
//! re-spelling DAMAGED — a test that fails if the parser admits whitespace
//! or another member order; an unknown member refused by name.

use super::*;
use crate::token::REVISION;

const HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

const PUBLISHED: &[u8] = b"{\"type\":\"skep-index\",\"v\":1,\"board\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\",\"kind\":\"published\",\"floor\":null,\"tokenizer\":\"1/17.0.0\",\"body\":0}\n";

const SUPPLEMENT: &[u8] = b"{\"type\":\"skep-index\",\"v\":1,\"board\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\",\"kind\":\"supplement\",\"principal\":7,\"floor\":2048,\"tokenizer\":\"1/17.0.0\",\"body\":1234}\n";

fn board() -> Chain {
    Chain::parse(HEX).expect("64 lowercase hex")
}

fn header(floor: Option<u64>) -> Header {
    Header { board: board(), floor, ranges: Vec::new(), head: None }
}

fn published(body: u64) -> Parsed {
    Parsed { board: board(), class: Class::Guest, floor: None, tokenizer: REVISION, body }
}

/// A re-spelling of `PUBLISHED`: `from` replaced by `to`, once.
fn respelled(from: &str, to: &str) -> Vec<u8> {
    let line = std::str::from_utf8(PUBLISHED).expect("ASCII");
    assert!(line.contains(from), "the case must be a change: {from}");
    line.replacen(from, to, 1).into_bytes()
}

/// §5.1: the canonical bytes of a published and a supplement header, in the
/// key file's conventions — members in one order, no whitespace outside
/// strings, lowercase hex, a `v`, `principal` beside `kind` on a supplement's
/// alone, one `\n` after the brace. The tokenizer literal is the running
/// revision's own spelling, pinned by `token`'s suite.
#[test]
fn the_canonical_bytes_of_a_published_and_a_supplement_header() {
    assert_eq!(REVISION.to_string(), "1/17.0.0");
    assert_eq!(encode(&header(None), Class::Guest, REVISION, 0), PUBLISHED);
    assert_eq!(encode(&header(Some(2048)), Class::Principal(7), REVISION, 1234), SUPPLEMENT);
}

/// §5.1 ONE SPELLING (P35): `parse(encode(h)) == h` for every header, and
/// `encode(parse(b)) == b` for every admitted `b`.
#[test]
fn parse_of_encode_is_identity_and_encode_of_parse_is_the_bytes() {
    let headers = [
        published(0),
        published(u64::MAX),
        Parsed { floor: Some(0), ..published(1) },
        Parsed { class: Class::Principal(u64::MAX), floor: Some(u64::MAX), ..published(9) },
        Parsed {
            board: Chain::from_bytes([0xFF; 32]),
            class: Class::Principal(0),
            tokenizer: Revision { rule: 30, unicode: (18, 1, 2) },
            ..published(77)
        },
    ];
    for h in headers {
        assert_eq!(parse(&h.encode()), Ok(h.clone()), "{h:?}");
    }
    for bytes in [PUBLISHED, SUPPLEMENT] {
        let parsed = parse(bytes).expect("the canonical bytes are admitted");
        assert_eq!(parsed.encode(), bytes);
    }
    let supplement = parse(SUPPLEMENT).expect("admitted");
    assert_eq!(supplement.class, Class::Principal(7));
    assert_eq!(supplement.floor, Some(2048));
    assert_eq!(supplement.body, 1234);
    assert_eq!(supplement.tokenizer, REVISION);
}

/// §5.1 `v` FIRST (P38): a `v` above 1 is NewerVersion whatever stands after
/// it — garbage, a member this crate does not know, no newline, a `type`
/// that is not an index's — and never Damaged; a `v` of 0, a non-canonical
/// `v` and no `v` are Damaged, since no skep wrote them.
#[test]
fn v_is_read_first_a_v_above_1_with_anything_after_it_is_newer_version() {
    let newer = |line: &[u8], v: u64| {
        assert_eq!(
            parse(line),
            Err(HeaderError::NewerVersion { v }),
            "{}",
            String::from_utf8_lossy(line)
        );
    };
    newer(b"{\"type\":\"skep-index\",\"v\":2,\"board\":\"not hex", 2);
    newer(b"{\"type\":\"skep-index\",\"v\":2,\"custody\":\"keychain\",\"board\":\"x\"}\n", 2);
    newer(b"{\"type\":\"skep-index\",\"v\":2}\r\n", 2);
    newer(b"{\"type\":\"skep-key\",\"v\":3}\n", 3);
    newer(b"{\"v\":7}", 7);
    newer(b"{\"type\":\"skep-index\",\"v\":99999999999999999999999999}\n", u64::MAX);
    let damaged = |line: &[u8]| {
        assert!(
            matches!(parse(line), Err(HeaderError::Damaged { .. })),
            "{}",
            String::from_utf8_lossy(line)
        );
    };
    damaged(&respelled("\"v\":1", "\"v\":0"));
    damaged(&respelled("\"v\":1", "\"v\":01"));
    damaged(&respelled("\"v\":1", "\"v\":\"1\""));
    damaged(&respelled(",\"v\":1", ""));
    damaged(b"{\"board\":\"\\\"v\\\":2\"}\n");
    damaged(b"");
    damaged(b"\n");
}

/// §5.1 ONE SPELLING: a re-spelled line is DAMAGED — whitespace, another
/// member order, uppercase hex, a CRLF, a missing or doubled newline, a
/// second spelling of a number, a re-spelled kind or type, a member twice, a
/// member missing, `principal` where it does not belong, an escape, bytes
/// after the line. The member-order case stands on the canonical compare
/// alone: relax it and this test fails.
#[test]
fn a_re_spelled_line_is_damaged() {
    let cases: [(&str, &str); 22] = [
        ("\"v\":1,", "\"v\":1, "),
        ("\"v\":1,", "\"v\": 1,"),
        ("{\"type\":\"skep-index\",\"v\":1,", "{\"v\":1,\"type\":\"skep-index\","),
        ("\"floor\":null,\"tokenizer\":\"1/17.0.0\"", "\"tokenizer\":\"1/17.0.0\",\"floor\":null"),
        ("0123456789abcdef0123", "0123456789ABCDEF0123"),
        (
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
        ),
        ("}\n", "}\r\n"),
        ("}\n", "}"),
        ("}\n", "}\n\n"),
        ("\"floor\":null", "\"floor\":1.0"),
        ("\"floor\":null", "\"floor\":+1"),
        ("\"floor\":null", "\"floor\":01"),
        ("\"floor\":null", "\"floor\":-1"),
        ("\"floor\":null", "\"floor\":NULL"),
        ("\"body\":0", "\"body\":00"),
        ("\"tokenizer\":\"1/17.0.0\"", "\"tokenizer\":\"01/17.0.0\""),
        ("\"tokenizer\":\"1/17.0.0\"", "\"tokenizer\":\"1/17.0\""),
        ("\"kind\":\"published\"", "\"kind\":\"Published\""),
        ("\"kind\":\"published\"", "\"kind\":\"published\",\"principal\":3"),
        ("\"kind\":\"published\"", "\"kind\":\"supplement\""),
        ("\"type\":\"skep-index\"", "\"type\":\"skep-key\""),
        ("\"floor\":null,", "\"floor\":null,\"floor\":null,"),
    ];
    for (from, to) in cases {
        let line = respelled(from, to);
        assert!(
            matches!(parse(&line), Err(HeaderError::Damaged { .. })),
            "{from} -> {to}: {:?}",
            parse(&line)
        );
    }
    let escaped = respelled("0123456789abcdef0123", "0123456789abcdef012\\u");
    assert!(matches!(parse(&escaped), Err(HeaderError::Damaged { .. })), "an escape");
    let mut trailing = PUBLISHED.to_vec();
    trailing.extend_from_slice(b"{}");
    assert!(matches!(parse(&trailing), Err(HeaderError::Damaged { .. })));
}

/// §5.1: an unknown member at the file's own `v` is refused by name — last,
/// first, or among the others — and never admitted half.
#[test]
fn an_unknown_member_is_refused_by_name() {
    let unknown = |name: &str| HeaderError::UnknownMember { name: name.to_string() };
    assert_eq!(
        parse(&respelled("\"body\":0}", "\"body\":0,\"custody\":\"keychain\"}")),
        Err(unknown("custody"))
    );
    assert_eq!(parse(&respelled("{\"type\"", "{\"units\":3,\"type\"")), Err(unknown("units")));
    assert_eq!(
        parse(&respelled("\"floor\":null,", "\"floor\":null,\"held\":{\"a\":1},")),
        Err(unknown("held"))
    );
}

/// The chain's one spelling: 64 lowercase hex in, the same out; anything
/// else is no chain.
#[test]
fn the_chain_is_64_lowercase_hex_and_round_trips() {
    let chain = board();
    assert_eq!(chain.to_string(), HEX);
    assert_eq!(format!("{chain:?}"), format!("Chain({HEX})"));
    assert_eq!(Chain::from_bytes(*chain.as_bytes()), chain);
    assert_eq!(chain.as_bytes()[0], 0x01);
    assert_eq!(chain.as_bytes()[31], 0xEF);
    assert_eq!(Chain::parse(&HEX.to_uppercase()), None, "uppercase");
    assert_eq!(Chain::parse(&HEX[..63]), None, "63 digits");
    assert_eq!(Chain::parse(&format!("{HEX}0")), None, "65 digits");
    assert_eq!(Chain::parse(&HEX.replace('0', "g")), None, "not hex");
    assert_eq!(Chain::parse(""), None);
    assert_eq!(Chain::from_bytes([0xFF; 32]).to_string(), "ff".repeat(32));
}

/// The refusals render the fact each disposition names.
#[test]
fn the_refusals_display_their_facts() {
    assert_eq!(
        HeaderError::NewerVersion { v: 2 }.to_string(),
        "this index was written by a newer skep than this one (v 2)"
    );
    assert_eq!(
        HeaderError::UnknownMember { name: "custody".to_string() }.to_string(),
        "the header names a member this skep does not know: `custody`"
    );
    assert_eq!(
        HeaderError::Damaged { what: "no `v` member" }.to_string(),
        "the header line is damaged: no `v` member"
    );
}
