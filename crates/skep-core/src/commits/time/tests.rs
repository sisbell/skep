//! The time record's schema and the lines, as pure values.

use super::*;
use skep_address::Tumbler;

fn a(comps: &[u32]) -> Address {
    validate(Tumbler::new(comps.iter().map(|&c| Nat::from(c))).expect("nonempty")).expect("T4")
}

/// The record renders in schema order — `type`, `position`, `time`, no
/// whitespace — and reads back as itself; a body of another type, or one
/// short a member, reads as no record.
#[test]
fn a_time_record_renders_in_schema_order_and_reads_back_as_itself() {
    let record = TimeRecord { position: 351, time: 1_786_838_400_047 };
    let bytes = record.to_bytes();
    assert_eq!(
        String::from_utf8(bytes.clone()).expect("utf-8"),
        r#"{"type":"skep-time","position":351,"time":1786838400047}"#
    );
    assert_eq!(TimeRecord::parse(&bytes), Some(record));
    assert_eq!(TimeRecord::parse(br#"{"type":"skep-head","position":1,"time":2}"#), None);
    assert_eq!(TimeRecord::parse(br#"{"type":"skep-time","position":1}"#), None);
    assert_eq!(TimeRecord::parse(b"not json"), None);
}

/// The two lines render the ruled words.
#[test]
fn the_time_writers_lines_render_the_ruled_words() {
    let line =
        TimeRefusedLine { position: 400, act: "publish", cause: "durability: the volume is full" };
    assert_eq!(
        line.to_string(),
        "time writer: the time record at position 400 was refused at its publish (durability: the \
         volume is full); no record written this cycle"
    );
    let minted = a(&[1, 1, 0, 1, 0, 5]);
    let expected = time_document();
    let line = DocumentMintedElsewhere { minted: &minted, expected: &expected };
    assert_eq!(
        line.to_string(),
        "time writer: the time document minted at 1.1.0.1.0.5, not at 1.1.0.1.0.4 — another writer \
         minted under the system account; the records go on in the document it minted"
    );
}

/// The time document is doc 4 of the system account, beside `H` at doc 2 and
/// the staging draft at doc 3.
#[test]
fn the_time_document_is_doc_4_of_the_system_account() {
    assert_eq!(time_document(), a(&[1, 1, 0, 1, 0, 4]));
    assert_eq!(time_document().to_string(), "1.1.0.1.0.4");
}
