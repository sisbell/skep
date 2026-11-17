//! The line read over the wire (wire.md §Content & provenance reads,
//! `line_numbers`): the board answers which line a position lies on, where a
//! line starts and how many lines a document holds, in numbers, moving no
//! text.
//!
//! What is asserted is the wire: the numbers of a draft as its owner reads
//! it, live and — through `/op-at` — as the draft stood at a past position;
//! `null` in the place of a line that names none; the refusals, each a
//! classified rejection naming the op, the two position faults by
//! `site.index`; an over-long list refused at the parse; and, over a
//! published member that windows a draft, the numbers a guest counts — no
//! line break of the run it may not read, and `masked` on every number that
//! run lies at or before — beside the owner's.

use crate::common;

use common::*;
use serde_json::{json, Value};

/// The read of `doc` asking `positions` and `lines`, as the wire spells it.
fn frame(doc: &str, positions: &[u64], lines: &[u64]) -> String {
    let positions: Vec<String> =
        positions.iter().map(|at| format!(r#"{{"ordinal":"{at}","subspace":"1"}}"#)).collect();
    let lines: Vec<String> = lines.iter().map(|line| format!(r#""{line}""#)).collect();
    format!(
        r#"{{"doc":"{doc}","lines":[{}],"op":"line_numbers","positions":[{}]}}"#,
        lines.join(","),
        positions.join(",")
    )
}

/// One answered position: its line and its flag.
fn line(number: u64, masked: bool) -> Value {
    json!({"line": number.to_string(), "masked": masked})
}

/// One answered line: the position it starts at and its flag.
fn start(at: u64, masked: bool) -> Value {
    json!({"masked": masked, "start": {"ordinal": at.to_string(), "subspace": "1"}})
}

/// The line count and its flag.
fn count(n: u64, masked: bool) -> Value {
    json!({"masked": masked, "n": n.to_string()})
}

/// The three members of a `line_numbers` answer.
fn numbers(v: &Value) -> (Value, Value, Value) {
    let r = expect_resp(v, "line_numbers");
    (r["positions"].clone(), r["lines"].clone(), r["count"].clone())
}

/// The draft is numbered as it stands, and as it stood at a past position.
///
/// A draft holding `a`, a line break and `b` is two lines to its owner;
/// after a line break is inserted at its head it is three, and `/op-at` at
/// the earlier position still answers the two — the numbers of the document
/// as it stood, stamped with that position. A guest is refused the draft,
/// `withheld`, live and in history alike.
#[test]
fn the_line_read_numbers_a_draft_live_and_as_it_stood_at_a_past_position() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let draft = draft_with(port, &owner, "a\\nb");
    let ask = frame(&draft, &[1, 3, 4], &[1, 2, 3, 0]);

    let then = op(port, Some(&owner), &ask);
    let before = (
        json!([line(1, false), line(2, false), line(2, false)]),
        json!([start(1, false), start(3, false), Value::Null, Value::Null]),
        count(2, false),
    );
    assert_eq!(numbers(&then), before, "`a\\nb` is two lines, its end on the second: {then}");
    let at = then["as_of"].as_u64().expect("a read names its position");

    expect_resp(&insert_text(port, &owner, &draft, 1, "\\n"), "ack_addr");
    let now = op(port, Some(&owner), &ask);
    assert_eq!(
        numbers(&now),
        (
            json!([line(1, false), line(2, false), line(3, false)]),
            json!([start(1, false), start(2, false), start(4, false), Value::Null]),
            count(3, false),
        ),
        "a line break at the head makes three lines: {now}"
    );

    let past = op_at_ok(port, Some(&owner), at, &ask);
    assert_eq!(numbers(&past), before, "at the earlier position, the draft as it stood: {past}");
    assert_eq!(past["as_of"].as_u64(), Some(at), "stamped with the position it is of: {past}");
    let head = op_at_ok(port, Some(&owner), head_position(port), &ask);
    assert_eq!(numbers(&head), numbers(&now), "and at the head, the live answer: {head}");

    assert_withheld(&op(port, None, &ask), &draft);
    assert_withheld(&op_at_ok(port, None, at, &ask), &draft);
    sd.shutdown();
}

/// Each refusal is a classified rejection that names the op.
///
/// An unregistered document is `doc_not_registered`; a position outside the
/// content subspace is `not_content_subspace` and one at ordinal 0 or more
/// than one past the end is `range_not_present`, each naming its place in
/// the request's list, the first faulty one speaking; a line faults
/// nothing; and a list past the wire-list cap is refused at the parse.
#[test]
fn the_line_read_refuses_a_position_by_its_index_and_an_over_long_list_at_the_parse() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let draft = draft_with(port, &owner, "a\\nb");
    let rejected = |frame: &str| {
        let v = op(port, Some(&owner), frame);
        let rej = expect_resp(&v, "rejected");
        assert_eq!(rej["op"].as_str(), Some("line_numbers"), "{v}");
        (rej["code"].as_str().expect("a code").to_string(), rej["site"]["index"].as_u64())
    };

    let unregistered = nth_document(CLAIMANT_ACCOUNT, 99);
    assert_eq!(
        rejected(&frame(&unregistered, &[1], &[1])),
        ("doc_not_registered".to_string(), None)
    );
    // One past the end is the last position admitted; two past is refused.
    assert_eq!(
        numbers(&op(port, Some(&owner), &frame(&draft, &[4], &[]))).0,
        json!([line(2, false)])
    );
    assert_eq!(rejected(&frame(&draft, &[4, 5], &[])), ("range_not_present".to_string(), Some(1)));
    assert_eq!(rejected(&frame(&draft, &[0], &[])), ("range_not_present".to_string(), Some(0)));
    let in_links = format!(
        r#"{{"doc":"{draft}","op":"line_numbers","positions":[{{"ordinal":"1","subspace":"1"}},{{"ordinal":"1","subspace":"2"}},{{"ordinal":"9","subspace":"1"}}]}}"#
    );
    assert_eq!(
        rejected(&in_links),
        ("not_content_subspace".to_string(), Some(1)),
        "the first fault speaks"
    );
    // A line that names none is an answer, however far past the count.
    let far = format!(
        r#"{{"doc":"{draft}","lines":["0","3","340282366920938463463374607431768211456"],"op":"line_numbers"}}"#
    );
    assert_eq!(numbers(&op(port, Some(&owner), &far)).1, json!([null, null, null]));

    let over = frame(&draft, &[], &vec![1; 4097]);
    let v = op(port, Some(&owner), &over);
    let rej = expect_resp(&v, "rejected");
    assert_eq!(
        (rej["code"].as_str(), rej["op"].as_str()),
        (Some("malformed"), Some("unparseable")),
        "{v}"
    );
    assert!(
        rej["detail"].as_str().is_some_and(|d| d.contains("lines") && d.contains("wire cap")),
        "{v}"
    );
    sd.shutdown();
}

/// A guest counts no line break of a run it may not read.
///
/// The edition's member is the edition's own `x`, line break, `y`, line
/// break, then three positions of a private draft holding `s`, a line break
/// and `t`. The owner reads four lines. The guest is served the same seven
/// positions with the draft's run withheld, and counts three: the run's line
/// break is counted nowhere, the numbers at or past the run are flagged, and
/// the ones before it are not. The bare edition answers as its head does.
#[test]
fn a_guest_counts_no_line_break_of_a_run_withheld_from_it_and_each_number_past_it_is_masked() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let edition = edition_with(port, &signed, "x\\ny\\n");
    let draft = draft_with(port, &owner, "s\\nt");
    let runs =
        [run(&edition, &format!("{edition}.0.1.1"), 4), run(&draft, &format!("{draft}.0.1.1"), 3)];
    let member = shot(port, &signed, &edition, None, None, &runs);
    assert_eq!(
        delivery(port, None, &member, 1, 7),
        json!([{"content": "x\ny\n"}, withheld_item(&draft, 3)])
    );

    for doc in [&member, &edition] {
        let ask = frame(doc, &[4, 5, 7, 8], &[2, 3, 4]);
        let mine = op(port, Some(&owner), &ask);
        assert_eq!(
            numbers(&mine),
            (
                json!([line(2, false), line(3, false), line(4, false), line(4, false)]),
                json!([start(3, false), start(5, false), start(7, false)]),
                count(4, false),
            ),
            "the owner reads both origins of {doc}: {mine}"
        );
        let theirs = op(port, None, &ask);
        assert_eq!(
            numbers(&theirs),
            (
                // Position 4 is the line break before the withheld run; 5 is
                // the run's first position, on the line the run starts on.
                json!([line(2, false), line(3, true), line(3, true), line(3, true)]),
                json!([start(3, false), start(5, true), Value::Null]),
                count(3, true),
            ),
            "the guest counts no line break of the withheld run of {doc}: {theirs}"
        );
    }
    sd.shutdown();
}
