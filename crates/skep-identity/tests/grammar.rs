//! The line grammar and parse-fault precedence — the I2 corpus's
//! tokenization and parse-precedence vectors (AUTH-2.96), over
//! AUTH-2.6–2.19 and the payload-type rules AUTH-1.23–1.28.

mod common;

use common::{fp, key};
use skep_identity::{
    encode_enroll, encode_retire, parse_enroll, parse_retire, Enrollment, Fingerprint, LabelError,
    PayloadError, PublicKey, ALG_ED25519,
};

fn hex(i: u8) -> String {
    key(i).to_hex()
}

#[track_caller]
fn err_enroll(bytes: &[u8]) -> PayloadError {
    match parse_enroll(bytes) {
        Err(e) => e,
        Ok(_) => panic!("expected an enroll parse fault"),
    }
}

#[track_caller]
fn err_retire(bytes: &[u8]) -> PayloadError {
    match parse_retire(bytes) {
        Err(e) => e,
        Ok(_) => panic!("expected a retire parse fault"),
    }
}

#[track_caller]
fn ok_enroll(bytes: &[u8]) -> Vec<Enrollment> {
    match parse_enroll(bytes) {
        Ok(v) => v,
        Err(e) => panic!("expected a clean enroll parse, got {}", e.token()),
    }
}

#[track_caller]
fn ok_retire(bytes: &[u8]) -> Vec<Fingerprint> {
    match parse_retire(bytes) {
        Ok(v) => v,
        Err(e) => panic!("expected a clean retire parse, got {}", e.token()),
    }
}

// ------------------------------------------------------------ tokenization

/// Corpus: a CRLF record — header ⇒ `bad_header`; a CRLF fingerprint line ⇒
/// `bad_line` (AUTH-2.6: `\r` is an ordinary payload byte).
#[test]
fn crlf_is_ordinary_payload_byte() {
    let crlf_enroll = format!("skep-enroll v1\r\ned25519 {}\r\n", hex(1));
    assert_eq!(err_enroll(crlf_enroll.as_bytes()), PayloadError::BadHeader);

    let crlf_fp_line = format!("skep-retire v1\n{}\r\n", fp(1).to_hex());
    assert_eq!(err_retire(crlf_fp_line.as_bytes()), PayloadError::BadLine(2));
}

/// Corpus: header with a trailing space; a leading blank line — `bad_header`
/// (AUTH-2.7: line 1, literally, byte-exact).
#[test]
fn header_is_byte_exact() {
    let trailing = format!("skep-enroll v1 \ned25519 {}\n", hex(1));
    assert_eq!(err_enroll(trailing.as_bytes()), PayloadError::BadHeader);

    let leading_blank = format!("\nskep-enroll v1\ned25519 {}\n", hex(1));
    assert_eq!(err_enroll(leading_blank.as_bytes()), PayloadError::BadHeader);

    assert_eq!(err_enroll(b""), PayloadError::BadHeader);
    assert_eq!(err_retire(b"skep-enroll v1\n"), PayloadError::BadHeader);
}

/// Corpus: a whitespace-only line — `bad_line` naming it (AUTH-2.7; a blank
/// line is zero-length and ignored, a whitespace-only line is not blank).
#[test]
fn whitespace_only_line_is_bad_line_naming_it() {
    let record = format!("skep-enroll v1\ned25519 {}\n \n", hex(1));
    assert_eq!(err_enroll(record.as_bytes()), PayloadError::BadLine(3));
}

/// Corpus: enroll key line ending in the separator (empty remainder) —
/// `bad_line` (AUTH-2.10: the test is the REMAINDER, never the last byte).
#[test]
fn empty_label_remainder_is_bad_line() {
    let record = format!("skep-enroll v1\ned25519 {} \n", hex(1));
    assert_eq!(err_enroll(record.as_bytes()), PayloadError::BadLine(2));
}

/// Corpus: `ed25519 <hex> my phone ` — honored; label verbatim with its
/// trailing 0x20 (AUTH-1.24, AUTH-2.10).
#[test]
fn label_keeps_trailing_space_verbatim() {
    let record = format!("skep-enroll v1\ned25519 {} my phone \n", hex(1));
    let parsed = ok_enroll(record.as_bytes());
    assert_eq!(parsed.len(), 1);
    assert_eq!(parsed[0].label(), Some("my phone "));
    assert!(!parsed[0].anchor);
}

/// Corpus: retirement lines `<64hex> ` and `<64hex> note` — `bad_line` ⇒
/// whole record inert on both (AUTH-2.14: no label, no trailing separator).
#[test]
fn retire_line_admits_nothing_after_the_fingerprint() {
    let trailing = format!("skep-retire v1\n{} \n", fp(1).to_hex());
    assert_eq!(err_retire(trailing.as_bytes()), PayloadError::BadLine(2));

    let with_note = format!("skep-retire v1\n{} note\n", fp(1).to_hex());
    assert_eq!(err_retire(with_note.as_bytes()), PayloadError::BadLine(2));
}

/// Corpus: `ED25519 <hex>` · `ANCHOR ed25519 <hex>` · `SIG <alg> <hex>` ·
/// `P256 <hex>` — `bad_line` naming the line on each (AUTH-2.9: keyword
/// tokens match as bytes, lowercase; case-insensitivity is the hex tokens'
/// alone).
#[test]
fn uppercase_keywords_are_bad_line() {
    for line in [
        format!("ED25519 {}", hex(1)),
        format!("ANCHOR ed25519 {}", hex(1)),
        format!("SIG ed25519 {}", hex(1)),
        format!("P256 {}", hex(1)),
    ] {
        let record = format!("skep-enroll v1\n{line}\n");
        assert_eq!(err_enroll(record.as_bytes()), PayloadError::BadLine(2));
    }
}

/// Corpus: `ed25519  <hex>` (doubled 0x20) · `ed25519\t<hex>` (tab) ·
/// `anchor  ed25519 <hex>` — `bad_line` on each (AUTH-2.8: no collapsing; a
/// doubled separator yields an empty token; a tab is an ordinary byte
/// INSIDE a token).
#[test]
fn separator_is_exactly_one_space() {
    for line in [
        format!("ed25519  {}", hex(1)),
        format!("ed25519\t{}", hex(1)),
        format!("anchor  ed25519 {}", hex(1)),
    ] {
        let record = format!("skep-enroll v1\n{line}\n");
        assert_eq!(err_enroll(record.as_bytes()), PayloadError::BadLine(2));
    }
}

/// Corpus: a `sig` line with garbage — skipped, whatever follows
/// (AUTH-2.13, permanent per AUTH-2.94), on BOTH kinds (AUTH-2.14).
#[test]
fn sig_lines_are_skipped_with_garbage() {
    let record = format!("skep-enroll v1\nsig !! not remotely parseable !!\ned25519 {}\n", hex(1));
    assert_eq!(ok_enroll(record.as_bytes()).len(), 1);

    let record = format!("skep-retire v1\nsig\n{}\n", fp(1).to_hex());
    assert_eq!(ok_retire(record.as_bytes()).len(), 1);
}

/// Corpus: a key line whose first token is an alg the build does not carry
/// (`mldsa44 <hex>`; `p256 <hex>` before its coordinated upgrade) —
/// `bad_line` ⇒ whole record inert (AUTH-2.12, AUTH-2.91).
#[test]
fn uncarried_alg_token_is_bad_line() {
    for alg in ["mldsa44", "p256"] {
        let record = format!("skep-enroll v1\n{alg} {}\n", hex(1));
        assert_eq!(err_enroll(record.as_bytes()), PayloadError::BadLine(2));
    }
}

/// Corpus: `anchor ed25519 <hex>` beside `ed25519 <hex> anchor` — honored
/// with `anchor: true` / honored, label `anchor`, NO flag (AUTH-2.11: the
/// anchor flag is the LEADING token and never a trailing one).
#[test]
fn anchor_is_the_leading_token_only() {
    let leading = format!("skep-enroll v1\nanchor ed25519 {}\n", hex(1));
    let parsed = ok_enroll(leading.as_bytes());
    assert!(parsed[0].anchor);
    assert_eq!(parsed[0].label(), None);

    let trailing = format!("skep-enroll v1\ned25519 {} anchor\n", hex(1));
    let parsed = ok_enroll(trailing.as_bytes());
    assert!(!parsed[0].anchor);
    assert_eq!(parsed[0].label(), Some("anchor"));
}

/// Corpus: `anchor` alone; `anchor anchor ed25519 …` — `bad_line`
/// (AUTH-2.11; `anchor sig …` is the same refusal).
#[test]
fn malformed_anchor_lines_are_bad_line() {
    for line in [
        "anchor".to_owned(),
        format!("anchor anchor ed25519 {}", hex(1)),
        format!("anchor sig ed25519 {}", hex(1)),
    ] {
        let record = format!("skep-enroll v1\n{line}\n");
        assert_eq!(err_enroll(record.as_bytes()), PayloadError::BadLine(2));
    }
}

/// Corpus: an uppercase-hex key line; an uppercase-hex fingerprint line —
/// parse exactly as their lowercase forms (AUTH-2.17).
#[test]
fn hex_tokens_are_case_insensitive() {
    let lower = format!("skep-enroll v1\ned25519 {}\n", hex(7));
    let upper = format!("skep-enroll v1\ned25519 {}\n", hex(7).to_uppercase());
    assert_eq!(ok_enroll(lower.as_bytes()), ok_enroll(upper.as_bytes()));

    let lower = format!("skep-retire v1\n{}\n", fp(7).to_hex());
    let upper = format!("skep-retire v1\n{}\n", fp(7).to_hex().to_uppercase());
    assert_eq!(ok_retire(lower.as_bytes()), ok_retire(upper.as_bytes()));
}

/// A blank line after line 1 is ignored but still counts for numbering
/// (AUTH-2.7, AUTH-1.27: 1-based, the header line 1).
#[test]
fn blank_lines_are_ignored_and_numbering_is_positional() {
    let record = format!("skep-enroll v1\n\ned25519 {}\n", hex(1));
    assert_eq!(ok_enroll(record.as_bytes()).len(), 1);

    let record = "skep-enroll v1\n\nnot a line\n";
    assert_eq!(err_enroll(record.as_bytes()), PayloadError::BadLine(3));
}

/// A duplicate under EITHER flag is the same duplicate — compared as PARSED
/// bytes, whatever the flag (AUTH-2.15).
#[test]
fn duplicate_across_flags_is_duplicate_key() {
    let record = format!(
        "skep-enroll v1\ned25519 {}\nanchor ed25519 {}\n",
        hex(3),
        hex(3)
    );
    assert_eq!(err_enroll(record.as_bytes()), PayloadError::DuplicateKey(3));
}

// ------------------------------------------------------- parse precedence

/// Corpus: a retirement listing one fingerprint twice, the second in
/// uppercase — `duplicate_key` naming the repeating line (AUTH-2.15).
#[test]
fn retire_duplicate_names_the_repeating_line() {
    let record = format!(
        "skep-retire v1\n{}\n{}\n",
        fp(2).to_hex(),
        fp(2).to_hex().to_uppercase()
    );
    assert_eq!(err_retire(record.as_bytes()), PayloadError::DuplicateKey(3));
}

/// Corpus: a header-only retirement — `empty`, never `nothing_changed`
/// (AUTH-2.16, `sig` lines included).
#[test]
fn header_only_record_is_empty() {
    assert_eq!(err_retire(b"skep-retire v1\n"), PayloadError::Empty);
    assert_eq!(err_retire(b"skep-retire v1"), PayloadError::Empty);
    assert_eq!(err_retire(b"skep-retire v1\nsig only sig lines\n"), PayloadError::Empty);
    assert_eq!(err_enroll(b"skep-enroll v1\nsig x\n\n"), PayloadError::Empty);
}

/// Corpus: uppercase keyword at line 2 + repeated fingerprint at line 4 —
/// `bad_line:2`, never `duplicate_key:4` (AUTH-2.19 item 3: first failing
/// line wins).
#[test]
fn first_failing_line_wins() {
    let record = format!(
        "skep-enroll v1\nED25519 {}\ned25519 {}\ned25519 {}\n",
        hex(1),
        hex(2),
        hex(2)
    );
    assert_eq!(err_enroll(record.as_bytes()), PayloadError::BadLine(2));
}

/// Corpus: `skep-enroll v1\n \n` — `bad_line:2`, never `empty` (AUTH-2.19
/// item 4: `Empty` is evaluated only after a clean scan).
#[test]
fn empty_is_evaluated_only_after_a_clean_scan() {
    assert_eq!(err_enroll(b"skep-enroll v1\n \n"), PayloadError::BadLine(2));
}

/// AUTH-2.19 item 1 — UTF-8 before everything.
#[test]
fn not_utf8_precedes_the_header_check() {
    assert_eq!(err_enroll(&[0xff, 0xfe, 0xfd]), PayloadError::NotUtf8);
    assert_eq!(err_retire(&[0xc3, 0x28]), PayloadError::NotUtf8);
}

// ------------------------------------------------------- encode / domain

/// AUTH-2.18/AUTH-2.17 — the emission form, pinned: lowercase hex, leading
/// `anchor`, one space before the verbatim label, `\n`-terminated lines.
#[test]
fn encode_emits_the_pinned_line_forms() {
    let record = encode_enroll(&[
        Enrollment::new(key(1), true, Some("desk key".to_owned())).unwrap(),
        Enrollment::new(key(2), false, None).unwrap(),
    ]);
    let want = format!(
        "skep-enroll v1\nanchor ed25519 {} desk key\ned25519 {}\n",
        hex(1),
        hex(2)
    );
    assert_eq!(record, want.into_bytes());

    let record = encode_retire(&[fp(1)]);
    let want = format!("skep-retire v1\n{}\n", fp(1).to_hex());
    assert_eq!(record, want.into_bytes());
}

/// `parse(encode(x)) == x` on hand-picked domain corners (the full-domain
/// proptest is I1's, in `props.rs`): trailing-0x20 label, `anchor` as a
/// label, an interior-space label, a label starting with a space.
#[test]
fn round_trip_domain_corners() {
    let corners = vec![
        Enrollment::new(key(1), true, Some("my phone ".to_owned())).unwrap(),
        Enrollment::new(key(2), false, Some("anchor".to_owned())).unwrap(),
        Enrollment::new(key(3), false, Some("two words here".to_owned())).unwrap(),
        Enrollment::new(key(4), true, Some(" leading space".to_owned())).unwrap(),
        Enrollment::new(key(5), false, None).unwrap(),
    ];
    let parsed = ok_enroll(&encode_enroll(&corners));
    assert_eq!(parsed, corners);

    let fps = vec![fp(1), fp(2), fp(3)];
    let parsed = ok_retire(&encode_retire(&fps));
    assert_eq!(parsed, fps);
}

/// AUTH-1.25 — `Enrollment::new` is the only constructor: `Some("")` maps
/// to `None`; a label containing `\n` is `Err(LabelError::Newline)`.
#[test]
fn enrollment_constructor_polices_the_label_domain() {
    let e = Enrollment::new(key(1), false, Some(String::new())).unwrap();
    assert_eq!(e.label(), None);

    assert!(matches!(
        Enrollment::new(key(1), false, Some("two\nlines".to_owned())),
        Err(LabelError::Newline)
    ));
}

/// AUTH-1.28 — `PayloadError::token()`: the one authority, all eight rows.
#[test]
fn payload_error_token_map() {
    assert_eq!(PayloadError::TooLarge.token(), "too_large");
    assert_eq!(PayloadError::ForeignContent.token(), "foreign_content");
    assert_eq!(PayloadError::MissingValue.token(), "missing_value");
    assert_eq!(PayloadError::NotUtf8.token(), "not_utf8");
    assert_eq!(PayloadError::BadHeader.token(), "bad_header");
    assert_eq!(PayloadError::Empty.token(), "empty");
    assert_eq!(PayloadError::BadLine(7).token(), "bad_line:7");
    assert_eq!(PayloadError::DuplicateKey(12).token(), "duplicate_key:12");
}

/// AUTH-1.2/AUTH-1.3/AUTH-1.4 — `PublicKey::parse` is syntax-only and
/// case-insensitive; `to_hex` is lowercase; `alg`/`raw` read the table row.
#[test]
fn public_key_surface() {
    let k = key(0xab);
    assert_eq!(k.alg(), "ed25519");
    assert_eq!(k.raw().len(), 32);
    let h = k.to_hex();
    assert_eq!(h.len(), 64);
    assert_eq!(h, h.to_lowercase());

    // Case-insensitive parse; syntax-only (0xff…ff is no curve point and is
    // admitted anyway — AUTH-1.4 never decodes the point).
    assert_eq!(PublicKey::parse("ed25519", &h.to_uppercase()).unwrap(), k);
    assert!(PublicKey::parse("ed25519", &"ff".repeat(32)).is_ok());

    use skep_identity::KeyParseError;
    assert!(matches!(PublicKey::parse("rsa", &h), Err(KeyParseError::UnknownAlg)));
    assert!(matches!(PublicKey::parse("ed25519", "zz"), Err(KeyParseError::BadHex)));
    assert!(matches!(
        PublicKey::parse("ed25519", &h[..63]),
        Err(KeyParseError::BadHex) // 63 chars: odd length cannot decode
    ));
    assert!(matches!(
        PublicKey::parse("ed25519", &h[..62]),
        Err(KeyParseError::BadLength)
    ));

    // `parse` takes two `&str` in a row, so a caller CAN swap them — and the
    // swap is loud, on either argument's own check: a hex string is in no
    // ALGS row, and `ed25519` is seven characters, an odd length no hex
    // decode admits. Nothing silently parses the wrong way round, which is
    // why AUTH-1.4's table lookup can stay inside this function rather than
    // being lifted into the caller's types.
    assert!(matches!(
        PublicKey::parse(&h, ALG_ED25519),
        Err(KeyParseError::UnknownAlg)
    ));
    assert!(matches!(
        PublicKey::parse(ALG_ED25519, ALG_ED25519),
        Err(KeyParseError::BadHex)
    ));
}

/// AUTH-1.9 — `Fingerprint::to_hex`/`parse_hex`: 64 lowercase out; exactly
/// 64 hex in, case-insensitively; `None` for anything else.
#[test]
fn fingerprint_hex_surface() {
    let f = fp(9);
    let h = f.to_hex();
    assert_eq!(h.len(), 64);
    assert_eq!(h, h.to_lowercase());
    assert_eq!(Fingerprint::parse_hex(&h).unwrap(), f);
    assert_eq!(Fingerprint::parse_hex(&h.to_uppercase()).unwrap(), f);
    assert!(Fingerprint::parse_hex(&h[..62]).is_none());
    assert!(Fingerprint::parse_hex(&format!("{h}00")).is_none());
    assert!(Fingerprint::parse_hex(&format!("g{}", &h[1..])).is_none());
}
