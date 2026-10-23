use skep_identity::Enrollment;

use super::*;

/// AUTH-5.1 — eight groups of eight, four to a line.
#[test]
fn the_grouping_is_eight_by_eight_four_to_a_line() {
    let hex64 = "0123456789abcdef".repeat(4);
    let grouped = group_hex(&hex64);
    let lines: Vec<&str> = grouped.lines().collect();
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[0], "01234567 89abcdef 01234567 89abcdef");
    assert_eq!(lines[1], lines[0]);
}

/// AUTH-5.2 — control and bidi characters render as code points.
#[test]
fn a_label_renders_inert() {
    assert_eq!(render_inert("ok name"), "ok name");
    assert_eq!(render_inert("a\u{202E}b\u{07}"), "a<U+202E>b<U+0007>");
}

/// AUTH-5.2, the whole set.
///
/// Every C0 control, DEL and every bidi control renders as its code point
/// — 45 characters — and a neighbour at one end or both of each range
/// renders as itself.
#[test]
fn every_control_and_bidi_control_renders_as_its_code_point() {
    let inert: Vec<char> = (0x00..=0x1f)
        .chain([0x7f, 0x061c, 0x200e, 0x200f])
        .chain(0x202a..=0x202e)
        .chain(0x2066..=0x2069)
        .map(|c| char::from_u32(c).expect("a scalar value"))
        .collect();
    assert_eq!(inert.len(), 45);
    for c in &inert {
        assert_eq!(render_inert(&c.to_string()), format!("<U+{:04X}>", *c as u32), "{:04X}", *c as u32);
    }
    for c in [' ', '~', '\u{061b}', '\u{061d}', '\u{200d}', '\u{2010}', '\u{202f}', '\u{2065}', '\u{206a}'] {
        assert_eq!(render_inert(&c.to_string()), c.to_string(), "{:04X} renders as itself", c as u32);
    }
    let all: String = inert.iter().collect();
    assert!(render_inert(&all).bytes().all(|b| b.is_ascii_graphic()), "{}", render_inert(&all));
}

/// AUTH-1.24/1.25 at the box.
///
/// 128 bytes are admitted, 129 refused with the byte count named
/// (AUTH-2.96's vector row), a newline refused, the empty label faced
/// (AUTH-5.42).
#[test]
fn the_label_domain_is_tested_at_the_box() {
    assert!(Label::new(&"a".repeat(128)).is_ok());
    assert_eq!(Label::new(&"a".repeat(129)).unwrap_err(), LabelFault::TooLong { bytes: 129 });
    assert_eq!(Label::new("two\nlines").unwrap_err(), LabelFault::Newline);
    assert_eq!(Label::new("").unwrap_err(), LabelFault::Empty);
    assert!(Label::new("my phone ").is_ok(), "a trailing space is in the domain");
    assert_eq!(Label::new("Paper A / 2026").unwrap().slug(), "paper-a-2026");
    // Bytes, not characters: 43 three-byte characters are 129 bytes.
    assert_eq!(Label::new(&"€".repeat(43)).unwrap_err(), LabelFault::TooLong { bytes: 129 });
    let fault: &dyn std::error::Error = &LabelFault::Empty;
    assert!(fault.to_string().contains("a name is required"));
}

/// One byline domain, the box's and the record's (AUTH-1.24, AUTH-1.25).
///
/// Every text the box admits `Enrollment::new` keeps as it is, and every
/// text the box refuses — save the empty one, which the record maps to
/// none — `Enrollment::new` refuses too, over labels of 0 to 135 bytes
/// of one- to four-byte characters, a line break at the start, the
/// middle, the end or none. The walks' `expect`s on a label the box
/// admitted stand on this.
#[test]
fn the_box_and_the_record_hold_one_label_domain() {
    let key = KeyFile::new(Seed::new([11u8; 32]), false, None, None).public;
    for ch in ['a', 'é', '€', '𝄞'] {
        for lead in ["", "a", "aa", "aaa"] {
            for k in 0..=131 / ch.len_utf8() {
                let body = format!("{lead}{}", ch.to_string().repeat(k));
                let middle = body.len() / 2;
                let middle = (0..=middle).rev().find(|i| body.is_char_boundary(*i)).unwrap_or(0);
                for text in [body.clone(), format!("\n{body}"), format!("{body}\n"), format!("{}\n{}", &body[..middle], &body[middle..])] {
                    let record = Enrollment::new(key.clone(), false, Some(text.clone()));
                    assert_eq!(Label::new(&text).is_ok(), !text.is_empty() && record.is_ok(), "{} bytes: {text:?}", text.len());
                    if Label::new(&text).is_ok() {
                        assert_eq!(record.unwrap().label(), Some(text.as_str()));
                    }
                }
            }
        }
    }
}

/// §9 item 35's typed prefix, one rule.
///
/// It is at least one R42 group, a prefix of the fingerprint, read
/// trimmed and in either case — and a short group padded with spaces is
/// no group.
#[test]
fn a_typed_prefix_is_one_r42_group_or_more_in_either_case() {
    let fp = KeyFile::new(Seed::new([8u8; 32]), true, None, None).fingerprint;
    let hex = fp.to_hex();
    assert!(typed_prefix_matches(&hex[..8], &fp) && typed_prefix_matches(&hex, &fp));
    assert!(typed_prefix_matches(&format!("  {}\n", hex[..16].to_ascii_uppercase()), &fp));
    assert!(!typed_prefix_matches(&hex[..7], &fp), "under one group");
    assert!(!typed_prefix_matches(&format!("       {}", &hex[..1]), &fp), "padding is no group");
    let other = if hex.starts_with('0') { "1" } else { "0" };
    assert!(!typed_prefix_matches(&format!("{other}{}", &hex[1..8]), &fp), "another key's group");
}

/// A seed is born in its zeroing value, and the sheet hides it.
///
/// It is drawn fresh, or decoded from its 64 hex in either case — any
/// other text is no seed; and the sheet prints every field but the seed.
#[test]
fn a_seed_is_drawn_or_decoded_into_its_value_and_the_sheet_hides_it() {
    assert_ne!(Seed::fresh().bytes(), Seed::fresh().bytes());
    assert_eq!(Seed::from_hex(&"AB".repeat(32)).map(|s| *s.bytes()), Some([0xab; 32]));
    assert!(Seed::from_hex(&"ab".repeat(31)).is_none() && Seed::from_hex(&"zz".repeat(32)).is_none());
    let file = KeyFile::new(Seed::new([4u8; 32]), true, Some(Label::new("paper").unwrap()), None);
    let printed = format!("{:?}", file.sheet());
    assert!(printed.contains(&file.fingerprint.to_hex()) && printed.contains("seed_grouped: …"), "{printed}");
    assert!(!printed.contains(&file.seed_hex()[..8]), "the seed never prints: {printed}");
}

/// §3.2 — one spelling written, a standard parser reading it back.
///
/// Whitespace and member order are admitted, the refusals the store's
/// own.
#[test]
fn the_key_file_round_trips_and_refuses_by_state() {
    let facts = Facts { account: "1.0.1".into(), principal: 1, origin: Origin::parse("http://127.0.0.1:8642").unwrap() };
    let file = KeyFile::new(Seed::new([3u8; 32]), true, Some(Label::new("paper-a").unwrap()), Some(&facts));
    let json = file.to_json();
    assert!(json.starts_with("{\"type\":\"skep-key\",\"v\":1,\"anchor\":true,\"alg\":\"mldsa65-ed25519\",\"seed\":\""));
    assert!(json.ends_with("\"origin\":\"http://127.0.0.1:8642\"}\n"));
    assert!(!json.contains(' '));
    let again = KeyFile::parse(json.as_bytes()).unwrap();
    assert_eq!(again.fingerprint, file.fingerprint);
    assert_eq!(again.label.as_deref(), Some("paper-a"));
    assert_eq!(again.principal, Some(1));
    // An editor-touched file still opens: whitespace, CRLF, member order.
    let v: Value = serde_json::from_str(&json).unwrap();
    let pretty = serde_json::to_string_pretty(&v).unwrap().replace('\n', "\r\n");
    assert_eq!(KeyFile::parse(pretty.as_bytes()).unwrap().fingerprint, file.fingerprint);
    // The refusals.
    assert_eq!(KeyFile::parse(b"not json").unwrap_err(), KeyFileError::NotKeyFile);
    assert_eq!(KeyFile::parse(br#"{"type":"skep-enroll"}"#).unwrap_err(), KeyFileError::NotKeyFile);
    let mut newer = v.clone();
    newer["v"] = Value::from(2);
    assert_eq!(KeyFile::parse(newer.to_string().as_bytes()).unwrap_err(), KeyFileError::Newer { v: 2 });
    let mut extra = v.clone();
    extra["custody"] = Value::from("x");
    assert_eq!(KeyFile::parse(extra.to_string().as_bytes()).unwrap_err(), KeyFileError::Schema { member: "custody".into() });
    // The file's `label` member is held to the box's own domain test.
    for bad in [String::new(), "two\nlines".into(), "a".repeat(129)] {
        let mut bad_label = v.clone();
        bad_label["label"] = Value::from(bad);
        assert_eq!(KeyFile::parse(bad_label.to_string().as_bytes()).unwrap_err(), KeyFileError::Schema { member: "label".into() });
    }
    let mut bad_seed = v.clone();
    bad_seed["seed"] = Value::from("00".repeat(32));
    assert_eq!(KeyFile::parse(bad_seed.to_string().as_bytes()).unwrap_err(), KeyFileError::Disagrees);
    // AUTH-5.39's other half: the seed and the public key agree, and the
    // `fingerprint` member names another key.
    let mut other_fingerprint = v.clone();
    other_fingerprint["fingerprint"] = Value::from(KeyFile::new(Seed::new([9u8; 32]), true, None, None).fingerprint.to_hex());
    assert_eq!(KeyFile::parse(other_fingerprint.to_string().as_bytes()).unwrap_err(), KeyFileError::Disagrees);
    let mut wrong_type = v.clone();
    wrong_type["anchor"] = Value::from("yes");
    assert_eq!(KeyFile::parse(wrong_type.to_string().as_bytes()).unwrap_err(), KeyFileError::Schema { member: "anchor".into() });
}

/// The seed and the sheet's text of it wipe themselves on drop.
///
/// AUTH-5.54 step 3's drop is owed as a wipe (`client.md` §3.4, §4.2 step
/// 5): each type's `ZeroizeOnDrop` is read off this build, each type read
/// off the field that holds it, and a plain `String` — the key file's text
/// of the seed — reads as the one that does not wipe. The sheet shows the
/// text AUTH-5.1's grouping spells, born at its final size so no growth
/// leaves a copy, and `SheetFields::lines` lends it, copying none of it.
#[test]
fn the_seed_and_the_sheets_text_of_it_wipe_on_drop() {
    use std::marker::PhantomData;
    use zeroize::ZeroizeOnDrop;
    /// `Probe::<T>::WIPES` is `true` exactly where `T: ZeroizeOnDrop`.
    ///
    /// The inherent const, which path resolution prefers, exists only then,
    /// and the trait's `false` answers everywhere else.
    struct Probe<T>(PhantomData<T>);
    trait Unwiped {
        const WIPES: bool = false;
    }
    impl<T> Unwiped for Probe<T> {}
    impl<T: ZeroizeOnDrop> Probe<T> {
        const WIPES: bool = true;
    }
    // Each type the probes ask about, read off the field that holds it: a
    // field typed otherwise fails to compile here.
    let counting = KeyFile::new(Seed::new(std::array::from_fn(|i| i as u8)), true, None, None);
    let sheet = counting.sheet();
    let _: &Seed = &counting.seed;
    let _: &SeedText = &sheet.seed_grouped;
    let _: String = counting.seed_hex();
    assert_eq!(
        [Probe::<Seed>::WIPES, Probe::<SeedText>::WIPES, Probe::<String>::WIPES],
        [true, true, false],
        "the seed and the sheet's text of it wipe on drop; the key file's plain `String` does not"
    );
    assert_eq!(sheet.seed_grouped.as_str(), "00010203 04050607 08090a0b 0c0d0e0f\n10111213 14151617 18191a1b 1c1d1e1f");
    assert_eq!(format!("{:?}", sheet.seed_grouped), "SeedText(…)", "the text prints as none of itself");
    for bytes in [[0u8; 32], [0xff; 32], std::array::from_fn(|i| i as u8)] {
        let file = KeyFile::new(Seed::new(bytes), true, None, None);
        let sheet = file.sheet();
        let text = &sheet.seed_grouped.0;
        assert_eq!(text.as_str(), group_hex(&file.seed_hex()), "the grouping AUTH-5.1 spells");
        assert_eq!((text.len(), text.capacity()), (SEED_TEXT_LEN, SEED_TEXT_LEN), "born at its final size, never grown");
        let (_, row) = sheet.lines().into_iter().find(|(name, _)| *name == "seed").expect("the seed's row");
        assert!(matches!(row, Cow::Borrowed(s) if std::ptr::eq(s.as_ptr(), text.as_ptr())), "the row lends the field's own text");
    }
}
