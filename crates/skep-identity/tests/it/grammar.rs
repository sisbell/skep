//! The JSON record schemas and the parse-fault precedence — the I2
//! canonical-profile corpus (AUTH-2.96 §2.1), over AUTH-2.128–2.130 and the
//! payload-type rules AUTH-1.23–1.28. Every malformation below is measured
//! against ONE canonical record; each answers the pinned token or is admitted.

use crate::common;

use common::{fp, key};
use skep_identity::{
    encode_enroll, encode_retire, parse_enroll, parse_retire, Enrollment, Fingerprint, LabelError,
    PayloadError, PublicKey, ALG_ED25519,
};

fn key_hex(i: u8) -> String {
    key(i).to_hex()
}

fn fp_hex(i: u8) -> String {
    fp(i).to_hex()
}

/// The one canonical enrollment record — one device key, no label — every
/// malformation below mutates.
fn canonical_enroll_record() -> String {
    encode_enroll(&[Enrollment::new(key(1), false, None).expect("label-free")])
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

// ------------------------------------------------- the canonical profile

/// The canonical record is admitted — both kinds (AUTH-2.128–2.130).
#[test]
fn a_canonical_record_is_admitted() {
    assert_eq!(
        ok_enroll(canonical_enroll_record().as_bytes()),
        vec![Enrollment::new(key(1), false, None).unwrap()]
    );
    assert_eq!(ok_retire(encode_retire(&[fp(1)]).as_bytes()), vec![fp(1)]);
}

/// §2.1 row 1 — a body carrying the member `keys` TWICE is `bad_record` (never
/// the LAST value, never the first, never a parser's choice): serde takes one,
/// the canonical re-encode carries one, the byte-identity compare differs.
#[test]
fn a_duplicate_member_is_bad_record() {
    let record = format!(
        r#"{{"type":"skep-enroll","keys":[{{"alg":"ed25519","key":"{h}","anchor":false}}],"keys":[{{"alg":"ed25519","key":"{h}","anchor":true}}]}}"#,
        h = key_hex(1)
    );
    assert_eq!(err_enroll(record.as_bytes()), PayloadError::BadRecord);
}

/// §2.1 row 2 — ANY byte after the closing brace is `bad_record` (AUTH-2.130
/// clause 5).
#[test]
fn any_byte_after_the_closing_brace_is_bad_record() {
    for suffix in ["\n", " ", "x", "\t", "}"] {
        let record = format!("{}{suffix}", canonical_enroll_record());
        assert_eq!(
            err_enroll(record.as_bytes()),
            PayloadError::BadRecord,
            "suffix {suffix:?}"
        );
    }
}

/// §2.1 row 3 — a leading UTF-8 BOM is `bad_record`.
#[test]
fn a_leading_bom_is_bad_record() {
    let record = format!("\u{feff}{}", canonical_enroll_record());
    assert_eq!(err_enroll(record.as_bytes()), PayloadError::BadRecord);
}

/// §2.1 row 4 — insignificant whitespace is `bad_record` (AUTH-2.130 clause 2):
/// a space after a `:` or a `,`, and a `\r`/`\n` outside a string (a CRLF or
/// pretty-printed body).
#[test]
fn insignificant_whitespace_is_bad_record() {
    let h = key_hex(1);
    let after_colon =
        format!(r#"{{"type": "skep-enroll","keys":[{{"alg":"ed25519","key":"{h}","anchor":false}}]}}"#);
    assert_eq!(err_enroll(after_colon.as_bytes()), PayloadError::BadRecord);

    let after_comma =
        format!(r#"{{"type":"skep-enroll", "keys":[{{"alg":"ed25519","key":"{h}","anchor":false}}]}}"#);
    assert_eq!(err_enroll(after_comma.as_bytes()), PayloadError::BadRecord);

    let crlf = format!(
        "{{\r\n\"type\":\"skep-enroll\",\"keys\":[{{\"alg\":\"ed25519\",\"key\":\"{h}\",\"anchor\":false}}]}}"
    );
    assert_eq!(err_enroll(crlf.as_bytes()), PayloadError::BadRecord);
}

/// §2.1 row 5 — a non-shortest escape (`A` where the value is `A`), an
/// escaped `/`, and a `\u` escape for a character above U+001F are each
/// `bad_record` (AUTH-2.130 clause 3: escape NOTHING else). The backslash is
/// built at runtime so no source escape is decoded before the JSON sees it.
///
/// The last two are the near-misses of the table's POSITIVE half: `\u0009`
/// where the canonical form is `\t`, and `\u001F` where it is `\u001f` — each
/// admitted the moment the encoder adopts that spelling, which is what
/// [`the_canonical_escape_table_is_pinned_as_bytes`] watches from the emission
/// side.
#[test]
fn non_canonical_escapes_are_bad_record() {
    let h = key_hex(1);
    let bs = char::from(92); // a backslash
    for body in ["u0041", "/", "u00e9", "u0009", "u001F"] {
        let record = format!(
            r#"{{"type":"skep-enroll","keys":[{{"alg":"ed25519","key":"{h}","anchor":false,"label":"{bs}{body}"}}]}}"#
        );
        assert_eq!(err_enroll(record.as_bytes()), PayloadError::BadRecord, "escape {bs}{body}");
    }
}

/// §2.1 row 6 — `"\ud800"` (legal JSON text, no Unicode scalar) is
/// `bad_record` on every implementation, never accept-on-one.
#[test]
fn a_lone_surrogate_is_bad_record() {
    let record = format!(
        r#"{{"type":"skep-enroll","keys":[{{"alg":"ed25519","key":"{}","anchor":false,"label":"{}ud800"}}]}}"#,
        key_hex(1),
        char::from(92)
    );
    assert_eq!(err_enroll(record.as_bytes()), PayloadError::BadRecord);
}

/// §2.1 row 7 — reordered members are `bad_record`: `keys` before `type`, `sig`
/// not last, an entry's `anchor` before its `key` (AUTH-2.130 clause 1).
#[test]
fn reordered_members_are_bad_record() {
    let h = key_hex(1);
    let keys_first =
        format!(r#"{{"keys":[{{"alg":"ed25519","key":"{h}","anchor":false}}],"type":"skep-enroll"}}"#);
    assert_eq!(err_enroll(keys_first.as_bytes()), PayloadError::BadRecord);

    let sig_not_last =
        format!(r#"{{"type":"skep-enroll","sig":"00","keys":[{{"alg":"ed25519","key":"{h}","anchor":false}}]}}"#);
    assert_eq!(err_enroll(sig_not_last.as_bytes()), PayloadError::BadRecord);

    let anchor_first =
        format!(r#"{{"type":"skep-enroll","keys":[{{"alg":"ed25519","anchor":false,"key":"{h}"}}]}}"#);
    assert_eq!(err_enroll(anchor_first.as_bytes()), PayloadError::BadRecord);
}

/// §2.1 row 8 — an uppercase-hex `key` or `fingerprints` entry is `bad_record`:
/// the PARSE is case-insensitive (AUTH-2.17) but the BODY is not the canonical
/// encoding (AUTH-2.130 clause 4).
#[test]
fn uppercase_hex_is_bad_record() {
    // A key whose hex carries letters (0xab ⇒ "abab…"), so uppercasing differs.
    let up = key_hex(0xab).to_uppercase();
    let enroll = format!(r#"{{"type":"skep-enroll","keys":[{{"alg":"ed25519","key":"{up}","anchor":false}}]}}"#);
    assert_eq!(err_enroll(enroll.as_bytes()), PayloadError::BadRecord);

    let up = fp_hex(1).to_uppercase();
    let retire = format!(r#"{{"type":"skep-retire","fingerprints":["{up}"]}}"#);
    assert_eq!(err_retire(retire.as_bytes()), PayloadError::BadRecord);
}

/// §2.1 rows 9–11 — a label outside the AUTH-1.24 domain is `bad_record`,
/// never Honored with `label: None`: `""`, a `\n`, and `null` — and row 11's
/// class clause, a `label` member carrying an absent value in ANY OTHER
/// spelling: `false`, `0`, `[]`, `{}`. The member is a STRING or it is not
/// there (AUTH-2.128); no falsy value reads as "no label".
#[test]
fn a_label_outside_the_domain_is_bad_record() {
    let h = key_hex(1);
    for label in [
        r#""label":"""#,
        r#""label":"a\nb""#,
        r#""label":null"#,
        r#""label":false"#,
        r#""label":0"#,
        r#""label":[]"#,
        r#""label":{}"#,
    ] {
        let record =
            format!(r#"{{"type":"skep-enroll","keys":[{{"alg":"ed25519","key":"{h}","anchor":false,{label}}}]}}"#);
        assert_eq!(err_enroll(record.as_bytes()), PayloadError::BadRecord, "{label}");
    }
}

/// §2.1 row 12 — `"label":"my phone "` (ends in 0x20) is Honored, the label
/// verbatim with its trailing 0x20 (AUTH-1.24).
#[test]
fn a_trailing_space_label_is_admitted_verbatim() {
    let record = format!(
        r#"{{"type":"skep-enroll","keys":[{{"alg":"ed25519","key":"{}","anchor":false,"label":"my phone "}}]}}"#,
        key_hex(1)
    );
    let parsed = ok_enroll(record.as_bytes());
    assert_eq!(parsed.len(), 1);
    assert_eq!(parsed[0].label(), Some("my phone "));
    assert!(!parsed[0].anchor);
}

/// §2.1 row 13 — an extra member on the record, and on a key entry, are each
/// `bad_record` (AUTH-2.128 "No other member").
#[test]
fn an_extra_member_is_bad_record() {
    let h = key_hex(1);
    let on_record =
        format!(r#"{{"type":"skep-enroll","keys":[{{"alg":"ed25519","key":"{h}","anchor":false}}],"extra":1}}"#);
    assert_eq!(err_enroll(on_record.as_bytes()), PayloadError::BadRecord);

    let on_entry =
        format!(r#"{{"type":"skep-enroll","keys":[{{"alg":"ed25519","key":"{h}","anchor":false,"extra":1}}]}}"#);
    assert_eq!(err_enroll(on_entry.as_bytes()), PayloadError::BadRecord);
}

/// §2.1 row 14 — `"anchor"` absent from a key entry is `bad_record` (the flag
/// is REQUIRED, one spelling per value — AUTH-2.128).
#[test]
fn a_missing_anchor_is_bad_record() {
    let record = format!(r#"{{"type":"skep-enroll","keys":[{{"alg":"ed25519","key":"{}"}}]}}"#, key_hex(1));
    assert_eq!(err_enroll(record.as_bytes()), PayloadError::BadRecord);
}

/// §2.1 row 15 — a `type` disagreeing with the link's kind (`skep-retire` in an
/// enroll-typed link), any other string, and a missing `type` are each
/// `bad_record` (the parse is keyed to the kind, AUTH-2.128).
#[test]
fn a_wrong_or_missing_type_is_bad_record() {
    let h = key_hex(1);
    let disagree =
        format!(r#"{{"type":"skep-retire","keys":[{{"alg":"ed25519","key":"{h}","anchor":false}}]}}"#);
    assert_eq!(err_enroll(disagree.as_bytes()), PayloadError::BadRecord);

    let other =
        format!(r#"{{"type":"skep-enrol","keys":[{{"alg":"ed25519","key":"{h}","anchor":false}}]}}"#);
    assert_eq!(err_enroll(other.as_bytes()), PayloadError::BadRecord);

    let missing = format!(r#"{{"keys":[{{"alg":"ed25519","key":"{h}","anchor":false}}]}}"#);
    assert_eq!(err_enroll(missing.as_bytes()), PayloadError::BadRecord);
}

/// §2.1 row 16 — a `sig` member carrying garbage is SKIPPED, and the same
/// record with no `sig` folds to the identical table: the `sig`-bearing body is
/// ADMITTED (AUTH-2.130's sentence ranges over the record value, `sig`
/// included), never `bad_record` (AUTH-2.13, AUTH-2.94).
#[test]
fn a_sig_member_is_skipped_and_the_table_is_identical() {
    let h = key_hex(1);
    let without = format!(r#"{{"type":"skep-enroll","keys":[{{"alg":"ed25519","key":"{h}","anchor":false}}]}}"#);
    let with = format!(
        r#"{{"type":"skep-enroll","keys":[{{"alg":"ed25519","key":"{h}","anchor":false}}],"sig":"deadbeef not a real signature"}}"#
    );
    assert_eq!(
        ok_enroll(with.as_bytes()),
        ok_enroll(without.as_bytes()),
        "the sig member is skipped; the entries are identical"
    );

    let with_r = format!(r#"{{"type":"skep-retire","fingerprints":["{}"],"sig":"garbage"}}"#, fp_hex(1));
    assert_eq!(ok_retire(with_r.as_bytes()), vec![fp(1)]);
}

/// AUTH-2.130 clause 3 on the `sig` member — the second string the encoder
/// escapes, and the one no other vector gives a character the escape table
/// decides. Every other `sig` in the suite is escape-free: the literals in the
/// vectors above, and the I1 generator's printable-ASCII class minus `"` and
/// `\`, which cannot draw a control character at all. So emitting `sig` raw
/// between quotes refuses every signature carrying a `"`, a `\` or a control
/// character — permanently, as `bad_record`, with the whole suite green.
///
/// `\n` is reachable ONLY here: AUTH-1.24 bars it from a label, so
/// [`the_canonical_escape_table_is_pinned_as_bytes`] cannot exercise that arm
/// of the table from the emission side at all. Spelling U+000A as the `\u00xx`
/// fallback instead inverts both `\n` rows below — the canonical body refused,
/// the non-canonical one admitted — turning over a frozen protocol pin (I2,
/// AUTH-2.90) in silence.
#[test]
fn a_sig_is_admitted_only_in_its_canonical_escaping() {
    let base = canonical_enroll_record();
    let splice = |sig_text: &str| format!("{},\"sig\":\"{sig_text}\"}}", &base[..base.len() - 1]);
    // As on `non_canonical_escapes_are_bad_record`: the backslash is built at
    // runtime, so no source escape is decoded before the JSON sees it.
    let bs = char::from(92);

    // A sig holding every character the table decides differently — a newline
    // among them — beside U+0020 and the three that must never be escaped.
    let canonical_sig = format!("{bs}u0000{bs}b{bs}t{bs}n{bs}f{bs}r{bs}u001f {bs}\"{bs}{bs}/é~");
    assert_eq!(
        ok_enroll(splice(&canonical_sig).as_bytes()),
        ok_enroll(base.as_bytes()),
        "a canonically escaped sig is admitted, and ignored"
    );

    // The near-misses, each one backslash away from a canonical spelling: a
    // `u00xx` where the table gives a two-character form, uppercase escape hex,
    // an escape for a character that takes none, an escaped `/`.
    for body in [
        "u000a", // the canonical form is the two-character newline escape
        "u0009", // …the tab escape
        "u0008", // …the backspace escape
        "u001F", // the canonical escape hex is LOWERCASE
        "u0041", // `A` is emitted raw
        "/",     // `/` is never escaped
    ] {
        assert_eq!(
            err_enroll(splice(&format!("{bs}{body}")).as_bytes()),
            PayloadError::BadRecord,
            "sig escape {bs}{body}"
        );
    }
}

/// §2.1 row 17 — an unadmitted alg (`mldsa44`, `p256`, `ED25519`) and a `key`
/// of the wrong hex length are each `bad_record` ⇒ whole record inert
/// (AUTH-2.9, AUTH-2.91).
#[test]
fn an_unadmitted_alg_or_wrong_hex_length_is_bad_record() {
    let h = key_hex(1);
    for alg in ["mldsa44", "p256", "ED25519"] {
        let record =
            format!(r#"{{"type":"skep-enroll","keys":[{{"alg":"{alg}","key":"{h}","anchor":false}}]}}"#);
        assert_eq!(err_enroll(record.as_bytes()), PayloadError::BadRecord, "alg {alg}");
    }
    let short = &h[..62];
    let record = format!(r#"{{"type":"skep-enroll","keys":[{{"alg":"ed25519","key":"{short}","anchor":false}}]}}"#);
    assert_eq!(err_enroll(record.as_bytes()), PayloadError::BadRecord);
}

/// §2.1 row 18 — the anchor FLAG and a label of the word `anchor` are distinct:
/// `anchor:true` Honored with the flag; `anchor:false, label:"anchor"` Honored
/// with NO flag (AUTH-1.26, AUTH-2.128).
#[test]
fn the_anchor_flag_and_a_label_anchor_are_distinct() {
    let record = encode_enroll(&[
        Enrollment::new(key(1), true, None).unwrap(),
        Enrollment::new(key(2), false, Some("anchor".to_owned())).unwrap(),
    ]);
    let parsed = ok_enroll(record.as_bytes());
    assert_eq!(parsed.len(), 2);
    assert!(parsed[0].anchor);
    assert_eq!(parsed[0].label(), None);
    assert!(!parsed[1].anchor);
    assert_eq!(parsed[1].label(), Some("anchor"));
}

/// §2.1 row 19 — a duplicate ENTRY names the 1-based repeating ENTRY index,
/// never a line number (AUTH-2.15, AUTH-1.27): entry 2 repeats entry 1's key
/// (under the opposite flag — the same parsed key), and a retirement listing
/// one fingerprint twice.
#[test]
fn a_duplicate_entry_names_the_repeating_entry_index() {
    let h = key_hex(3);
    let record = format!(
        r#"{{"type":"skep-enroll","keys":[{{"alg":"ed25519","key":"{h}","anchor":false}},{{"alg":"ed25519","key":"{h}","anchor":true}}]}}"#
    );
    assert_eq!(err_enroll(record.as_bytes()), PayloadError::DuplicateKey(2));

    let f = fp_hex(2);
    let record = format!(r#"{{"type":"skep-retire","fingerprints":["{f}","{f}"]}}"#);
    assert_eq!(err_retire(record.as_bytes()), PayloadError::DuplicateKey(2));
}

/// §2.1 row 20 — an empty `keys` or `fingerprints` array is `empty`, never
/// `nothing_changed` (AUTH-2.16).
#[test]
fn an_empty_array_is_empty() {
    assert_eq!(err_enroll(br#"{"type":"skep-enroll","keys":[]}"#), PayloadError::Empty);
    assert_eq!(err_retire(br#"{"type":"skep-retire","fingerprints":[]}"#), PayloadError::Empty);
}

/// §2.1 row 21 — an unadmitted alg at entry 1 beside a duplicate at entry 3 is
/// `bad_record`, never `duplicate_key:3` (AUTH-2.19 item 2 precedes item 3).
#[test]
fn an_unadmitted_alg_precedes_a_later_duplicate() {
    let record = format!(
        r#"{{"type":"skep-enroll","keys":[{{"alg":"mldsa44","key":"{h1}","anchor":false}},{{"alg":"ed25519","key":"{h2}","anchor":false}},{{"alg":"ed25519","key":"{h2}","anchor":false}}]}}"#,
        h1 = key_hex(1),
        h2 = key_hex(2)
    );
    assert_eq!(err_enroll(record.as_bytes()), PayloadError::BadRecord);
}

/// AUTH-2.19 item 2 before item 3 at the CANONICAL half — the cell
/// [`PayloadError::DuplicateKey`]'s own card names: a body that is both
/// non-canonical and duplicate-bearing answers `bad_record`, never
/// `duplicate_key`. Row 21 puts an unadmitted ALG ahead of the duplicate, which
/// fails inside the ENTRY LOOP and so reads the same under either ordering;
/// every entry of every body below parses cleanly and only the byte-identity
/// compare refuses them. Moving the duplicate scan above that compare answers
/// `duplicate_key:2` for all three rows and leaves the rest of the suite green.
#[test]
fn a_non_canonical_body_that_also_repeats_an_entry_is_bad_record() {
    // Insignificant whitespace after a `:`, two entries carrying one key.
    let h = key_hex(3);
    let spaced = format!(
        r#"{{"type": "skep-enroll","keys":[{{"alg":"ed25519","key":"{h}","anchor":false}},{{"alg":"ed25519","key":"{h}","anchor":true}}]}}"#
    );
    assert_eq!(err_enroll(spaced.as_bytes()), PayloadError::BadRecord);

    // Uppercase hex, which the PARSE admits (AUTH-2.17), so both entries really
    // do carry one key and the duplicate is real — the compare decides first.
    let up = key_hex(0xab).to_uppercase();
    let uppercase = format!(
        r#"{{"type":"skep-enroll","keys":[{{"alg":"ed25519","key":"{up}","anchor":false}},{{"alg":"ed25519","key":"{up}","anchor":true}}]}}"#
    );
    assert_eq!(err_enroll(uppercase.as_bytes()), PayloadError::BadRecord);

    // The retirement kind keeps the same precedence.
    let f = fp_hex(1).to_uppercase();
    let retire = format!(r#"{{"type":"skep-retire","fingerprints":["{f}","{f}"]}}"#);
    assert_eq!(err_retire(retire.as_bytes()), PayloadError::BadRecord);
}

/// §2.1 row 22 — `{"type":"skep-enroll","keys":[]}` carrying a fourth member is
/// `bad_record`, never `empty` (AUTH-2.19 item 2 precedes item 4).
#[test]
fn an_empty_keys_array_with_an_extra_member_is_bad_record() {
    assert_eq!(
        err_enroll(br#"{"type":"skep-enroll","keys":[],"extra":1}"#),
        PayloadError::BadRecord
    );
}

/// AUTH-2.19 item 1 — UTF-8 before the schema check, on both kinds.
#[test]
fn not_utf8_precedes_the_schema_check() {
    assert_eq!(err_enroll(&[0xff, 0xfe, 0xfd]), PayloadError::NotUtf8);
    assert_eq!(err_retire(&[0xc3, 0x28]), PayloadError::NotUtf8);
}

/// AUTH-2.130 — a body that is not JSON at all is `bad_record`, the retired
/// LINE FORM included (RES-98: the line grammar is retired).
#[test]
fn a_non_json_body_is_bad_record() {
    assert_eq!(err_enroll(b"nonsense"), PayloadError::BadRecord);
    let line_form = format!("skep-enroll v1\ned25519 {}\n", key_hex(1));
    assert_eq!(err_enroll(line_form.as_bytes()), PayloadError::BadRecord);
    assert_eq!(err_retire(b"{not json"), PayloadError::BadRecord);
}

/// AUTH-2.129 — the retirement schema's own checks: `fingerprints` an array of
/// 64-hex strings, no other member.
#[test]
fn the_retirement_schema_is_enforced() {
    assert_eq!(
        err_retire(br#"{"type":"skep-retire","fingerprints":"x"}"#),
        PayloadError::BadRecord
    );
    let short = fp_hex(1)[..62].to_owned();
    assert_eq!(
        err_retire(format!(r#"{{"type":"skep-retire","fingerprints":["{short}"]}}"#).as_bytes()),
        PayloadError::BadRecord
    );
    assert_eq!(
        err_retire(br#"{"type":"skep-retire","fingerprints":[1]}"#),
        PayloadError::BadRecord
    );
    assert_eq!(
        err_retire(br#"{"type":"skep-retire","fingerprints":[],"extra":1}"#),
        PayloadError::BadRecord
    );
}

// ------------------------------------------------------- encode / domain

/// AUTH-2.18/AUTH-2.130 — the emission form, pinned: schema order, no
/// whitespace, lowercase hex, the label escaped canonically, no `sig`.
#[test]
fn encode_emits_the_canonical_forms() {
    let record = encode_enroll(&[
        Enrollment::new(key(1), true, Some("desk key".to_owned())).unwrap(),
        Enrollment::new(key(2), false, None).unwrap(),
    ]);
    let want = format!(
        r#"{{"type":"skep-enroll","keys":[{{"alg":"ed25519","key":"{}","anchor":true,"label":"desk key"}},{{"alg":"ed25519","key":"{}","anchor":false}}]}}"#,
        key_hex(1),
        key_hex(2)
    );
    assert_eq!(record, want);

    let record = encode_retire(&[fp(1)]);
    let want = format!(r#"{{"type":"skep-retire","fingerprints":["{}"]}}"#, fp_hex(1));
    assert_eq!(record, want);
}

/// AUTH-2.130 clause 3 — the canonical escape table as BYTES, the whole of it:
/// `"` and `\` escaped, the C0 controls JSON gives a two-character form take it
/// (`\b \f \r \t`; `\n` is outside the AUTH-1.24 label domain), every other C0
/// control takes `\u00xx` with LOWERCASE hex, and U+0020 and above is emitted
/// raw — never `/`, never a non-ASCII character.
///
/// Every other escape vector compares the encoder against ITSELF: the admission
/// rule re-encodes with the same function, and a JSON `\u` escape decodes
/// case-insensitively. So an encoder emitting `\u0009` for a tab, or `\u001F`
/// for U+001F, round-trips cleanly and is admitted while an origin and a mirror
/// disagree forever about which bodies are canonical — and therefore about the
/// key table. `round_trip_domain_corners` and I1 alike stay green under both,
/// and I1's `.+` labels DO reach the escape table — reaching a corner is not
/// the same as being able to judge it, and only a byte compare judges it. This
/// is the one assertion that reads the emitted bytes.
#[test]
fn the_canonical_escape_table_is_pinned_as_bytes() {
    // Every character the table decides differently, plus the boundaries on
    // either side of the C0 range: the four two-character forms a label can
    // carry, `\u00xx` controls below, between and above them, the first raw
    // character (U+0020), and the three that must never be escaped.
    let label = "\u{0}\u{1}\u{7}\u{8}\u{9}\u{b}\u{c}\u{d}\u{e}\u{1f}\u{20}\"\\/é~";
    let record = encode_enroll(&[Enrollment::new(key(1), false, Some(label.to_owned()))
        .expect("the AUTH-1.24 domain admits every character here")]);
    let want = format!(
        r#"{{"type":"skep-enroll","keys":[{{"alg":"ed25519","key":"{}","anchor":false,"label":"\u0000\u0001\u0007\b\t\u000b\f\r\u000e\u001f \"\\/é~"}}]}}"#,
        key_hex(1)
    );
    assert_eq!(record, want);

    // …and those bytes are a RECORD, admitted with the label verbatim: the
    // emission form pinned above is the one the parser reads back.
    let parsed = ok_enroll(want.as_bytes());
    assert_eq!(parsed[0].label(), Some(label));
}

/// `parse(encode(x)) == x` on hand-picked domain corners, the escaper included
/// (the full-domain proptest is I1's, in `props.rs`): a trailing-0x20 label,
/// `anchor` as a label, an interior-space label, a leading-space label, and a
/// label carrying `"`, `\` and a tab — each escaped canonically and decoded
/// back.
#[test]
fn round_trip_domain_corners() {
    let corners = vec![
        Enrollment::new(key(1), true, Some("my phone ".to_owned())).unwrap(),
        Enrollment::new(key(2), false, Some("anchor".to_owned())).unwrap(),
        Enrollment::new(key(3), false, Some("two words here".to_owned())).unwrap(),
        Enrollment::new(key(4), true, Some(" leading space".to_owned())).unwrap(),
        Enrollment::new(key(5), false, Some("quote \" backslash \\ tab\tend".to_owned())).unwrap(),
        Enrollment::new(key(6), false, None).unwrap(),
    ];
    let parsed = ok_enroll(encode_enroll(&corners).as_bytes());
    assert_eq!(parsed, corners);

    let fps = vec![fp(1), fp(2), fp(3)];
    let parsed = ok_retire(encode_retire(&fps).as_bytes());
    assert_eq!(parsed, fps);
}

/// AUTH-1.25 — `Enrollment::new` is the only constructor: `Some("")` maps
/// to `None`; a label containing `\n` is `Err(LabelError::Newline)`.
#[test]
fn enrollment_constructor_polices_the_label_domain() {
    let e = Enrollment::new(key(1), false, Some(String::new())).unwrap();
    assert_eq!(e.label(), None);

    assert_eq!(
        Enrollment::new(key(1), false, Some("two\nlines".to_owned())),
        Err(LabelError::Newline)
    );
}

/// AUTH-1.28 — `PayloadError::token()`: the one authority, all seven rows,
/// `bad_record` in and the line-grammar tokens out (RES-98).
#[test]
fn every_payload_error_variant_has_its_pinned_token() {
    assert_eq!(PayloadError::TooLarge.token(), "too_large");
    assert_eq!(PayloadError::ForeignContent.token(), "foreign_content");
    assert_eq!(PayloadError::MissingValue.token(), "missing_value");
    assert_eq!(PayloadError::NotUtf8.token(), "not_utf8");
    assert_eq!(PayloadError::BadRecord.token(), "bad_record");
    assert_eq!(PayloadError::Empty.token(), "empty");
    assert_eq!(PayloadError::DuplicateKey(12).token(), "duplicate_key:12");
}

/// AUTH-1.2/AUTH-1.3/AUTH-1.4 — `PublicKey::parse` is syntax-only and
/// case-insensitive; `to_hex` is lowercase; `alg`/`raw` read the table row.
#[test]
fn public_key_surface() {
    let k = key(0xab);
    assert_eq!(k.alg(), "ed25519");
    assert_eq!(k.raw().len(), 32);
    let key_hex = k.to_hex();
    assert_eq!(key_hex.len(), 64);
    assert_eq!(key_hex, key_hex.to_lowercase());

    assert_eq!(
        PublicKey::parse("ed25519", &key_hex.to_uppercase()).unwrap(),
        k
    );
    assert!(PublicKey::parse("ed25519", &"ff".repeat(32)).is_ok());

    use skep_identity::KeyParseError;
    assert_eq!(PublicKey::parse("rsa", &key_hex), Err(KeyParseError::UnknownAlg));
    assert_eq!(PublicKey::parse("ed25519", "zz"), Err(KeyParseError::BadHex));
    assert_eq!(
        PublicKey::parse("ed25519", &key_hex[..63]),
        Err(KeyParseError::BadHex)
    );
    assert_eq!(PublicKey::parse("ed25519", &key_hex[..62]), Err(KeyParseError::BadLength));

    assert_eq!(PublicKey::parse(&key_hex, ALG_ED25519), Err(KeyParseError::UnknownAlg));
    assert_eq!(PublicKey::parse(ALG_ED25519, ALG_ED25519), Err(KeyParseError::BadHex));
}

/// AUTH-1.9 — `Fingerprint::to_hex`/`parse_hex`: 64 lowercase out; exactly
/// 64 hex in, case-insensitively; `None` for anything else.
#[test]
fn fingerprint_hex_round_trips_and_admits_exactly_64_chars() {
    let f = fp(9);
    let fp_hex = f.to_hex();
    assert_eq!(fp_hex.len(), 64);
    assert_eq!(fp_hex, fp_hex.to_lowercase());
    assert_eq!(Fingerprint::parse_hex(&fp_hex).unwrap(), f);
    assert_eq!(Fingerprint::parse_hex(&fp_hex.to_uppercase()).unwrap(), f);
    assert!(Fingerprint::parse_hex(&fp_hex[..62]).is_none());
    assert!(Fingerprint::parse_hex(&format!("{fp_hex}00")).is_none());
    assert!(Fingerprint::parse_hex(&format!("g{}", &fp_hex[1..])).is_none());
}
