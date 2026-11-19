//! The unit suite of `text.mark`.
//!
//! It holds the member, the read and the three writes against a scripted
//! board (the text suite's `Script`) — each frame as the wire spells it and
//! each typed against the write before it — and what every write that does
//! not land leaves and answers. The row itself, its door, and the mark a
//! real board keeps — its content by identity, its link, the base and the
//! source it does not record — run against the daemon in
//! `shell/tests/text.rs`.

use skep_client::halt::Refused;
use skep_client::DialError;

use super::super::tests::{held_answer, lines, settling, Script, DOC};
use super::*;
use crate::refusal::Name;

/// The account every scripted mark is minted in.
const ACCOUNT: &str = "1.0.1";

/// The document the scripted mint answers.
const MARK: &str = "1.0.1.0.65";

/// The link the scripted `make_link` answers.
const LINK: &str = "1.0.1.0.65.0.2.1";

/// The commits the scripted mint, copy and link land at.
const MINTED_AT: u64 = 41;
const COPIED_AT: u64 = 44;
const LINKED_AT: u64 = 47;

/// The extent read of a draft holding `positions` content positions.
fn extent(positions: u64) -> Result<Value, Refusal> {
    let set = if positions == 0 { json!([]) } else { json!([{"start": "1.1", "width": format!("0.{positions}")}]) };
    Ok(json!({"resp": "span_set", "as_of": 40, "set": set}))
}

/// The mint's ack.
fn minted() -> Result<Value, Refusal> {
    Ok(json!({"resp": "ack_addr", "addr": MARK, "at": MINTED_AT}))
}

/// The copy's ack.
fn copied() -> Result<Value, Refusal> {
    Ok(json!({"resp": "ack", "at": COPIED_AT}))
}

/// The link's ack.
fn linked() -> Result<Value, Refusal> {
    Ok(json!({"resp": "ack_addr", "addr": LINK, "at": LINKED_AT}))
}

/// The frames a mark of a draft that holds content sends, in order.
fn frames_of_a_mark() -> Vec<Value> {
    vec![
        frames::span_set(DOC),
        frames::create_document(ACCOUNT, false, None),
        frames::copy(MARK, 1, &[(DOC, 1, u64::MAX)], MINTED_AT, None),
        frames::make_link_spec(MARK, &[(MARK, 1, u64::MAX)], &[DOC], frames::T_MARKS, None),
    ]
}

/// Returns the call's outcome over a board answering `answers`.
///
/// The calls made are beside it.
fn run(answers: Vec<Result<Value, Refusal>>) -> (Result<Answer, Refusal>, Vec<Value>) {
    let script = Script::of(answers);
    let args = json!({"doc": DOC});
    let outcome = Asked::read(&args).and_then(|asked| mark(&script, &asked, ACCOUNT));
    (outcome, script.sent_past(0))
}

/// A board's verdict on a write, as the shell carries one back.
fn verdict(op: &str, code: &str) -> Refusal {
    Refusal::Board(Refused { status: 200, code: code.into(), detail: None, op: Some(op.into()), body: json!({"resp": "rejected", "op": op, "code": code, "disposition": "permanent"}) })
}

/// A mark is a mint, a copy and a link, each typed against the one before.
///
/// The draft's extent is read; a private document is minted in the
/// session's account; the draft's whole content is copied into it at its
/// first position, one source span from the first content position on,
/// typed against the mint's commit; and one link typed `marks` is homed in
/// the mark, its `from` the mark's whole content in the V-spec form — the
/// span the copy named — and its `to` the draft by address. The answer
/// names the mark, the link and the link's commit (the mutants that write
/// the `from` in the address form, type the copy against the read, or mint
/// the mark published send another frame).
#[test]
fn a_mark_is_a_mint_a_copy_and_a_link_each_typed_against_the_one_before() {
    let (answer, sent) = run(vec![extent(12), minted(), copied(), linked()]);
    assert_eq!(sent, frames_of_a_mark());
    assert_eq!(sent[1], json!({"op": "create_new_document", "account": ACCOUNT, "published": false}), "private, in the session's account");
    assert_eq!(sent[2]["specs"], json!([{"source": DOC, "span": {"start": "1.1", "width": format!("0.{}", u64::MAX)}}]), "one span over the whole content, the board's to clip");
    assert_eq!((sent[2]["as_of"].as_u64(), &sent[2]["at"]), (Some(MINTED_AT), &json!({"subspace": "1", "ordinal": "1"})));
    let link = &sent[3];
    assert_eq!(link["from"], json!([{"source": MARK, "span": {"start": "1.1", "width": format!("0.{}", u64::MAX)}}]), "the mark's content, never its name");
    assert_eq!((&link["to"], &link["ty"], link["home"].as_str()), (&json!({"addrs": [DOC]}), &json!({"addrs": ["1.1.0.1.0.1.0.3.25"]}), Some(MARK)));
    let answer = answer.expect("an answer");
    assert!(!answer.is_error);
    let answer = answer.into_value();
    crate::shapes::assert_declared("TextMarked", &answer);
    assert_eq!(answer, json!({"outcome": "marked", "doc": DOC, "mark": MARK, "link": LINK, "at": LINKED_AT}));
}

/// The mark of an empty draft makes no copy, and its link's `from` is empty.
#[test]
fn the_mark_of_an_empty_draft_makes_no_copy_and_an_empty_from() {
    let (answer, sent) = run(vec![extent(0), minted(), linked()]);
    assert_eq!(sent, [frames::span_set(DOC), frames::create_document(ACCOUNT, false, None), frames::make_link_spec(MARK, &[], &[DOC], frames::T_MARKS, None)]);
    assert_eq!(sent[2]["from"], json!([]), "the empty list");
    assert_eq!(answer.expect("an answer").into_value(), json!({"outcome": "marked", "doc": DOC, "mark": MARK, "link": LINK, "at": LINKED_AT}));
}

/// A refusal the read or the mint decides leaves nothing written.
///
/// A draft the session may not read, and one the board does not register,
/// refuse the call at its read, no document minted; the mint's refusal is
/// the call's, nothing copied or linked; and an answer to either that this
/// shell does not read is an error naming the op, never taken for an empty
/// draft or a mark (the mutant that mints first leaves an empty document
/// for every draft it may not read).
#[test]
fn a_refusal_the_read_or_the_mint_decides_leaves_nothing_written() {
    for code in ["withheld", "doc_not_registered"] {
        let (answer, sent) = run(vec![Err(verdict("retrieve_doc_v_span_set", code))]);
        assert_eq!((answer, sent), (Err(verdict("retrieve_doc_v_span_set", code)), vec![frames::span_set(DOC)]), "{code}: nothing minted");
    }
    let home_first = || {
        Refusal::Board(Refused {
            status: 200,
            code: "credential_refused".into(),
            detail: Some("mint_home_first".into()),
            op: Some("create_new_document".into()),
            body: json!({"resp": "rejected", "code": "credential_refused", "detail": "mint_home_first"}),
        })
    };
    let (answer, sent) = run(vec![extent(12), Err(home_first())]);
    assert_eq!(sent.len(), 2, "the read and the mint");
    assert_eq!(answer.as_ref().map_err(Refusal::name), Err("mint_home_first"));
    let (answer, sent) = run(vec![Ok(json!({"resp": "delivery", "items": []}))]);
    assert_eq!(sent.len(), 1);
    assert_eq!(answer.expect("an answer").into_value(), json!({"outcome": "refused", "cause": "unread", "doc": DOC, "op": "retrieve_doc_v_span_set", "error": true}));
    let (answer, sent) = run(vec![extent(12), Ok(json!({"resp": "ack", "at": MINTED_AT}))]);
    assert_eq!(sent.len(), 2, "no copy into a document the mint did not name");
    assert_eq!(answer.expect("an answer").into_value(), json!({"outcome": "refused", "cause": "unread", "doc": DOC, "op": "create_new_document", "error": true}));
    assert_eq!(Asked::read(&json!({"doc": "1..2"})).unwrap_err().to_value()["what"], "doc");
    assert_eq!(Asked::read(&json!({})).unwrap_err().to_value()["what"], "doc");
}

/// A copy that does not land names the empty mark the mint left.
///
/// The copy is a burst, and its line is settled as `text.replace` settles
/// one. Dropped with the board's verdict, the call answers `refused` with
/// the verdict, as data, naming the mark; dropped with none, an error with
/// the hold's cause, naming it too; and no link is sent after either. A
/// drop that finds the copy landed goes on to the link. A line the shell
/// will not drop is answered `held`, an error naming the line, the mark and
/// the write, nothing sent after it. And the `op` row's own refusal of the
/// copy is an error naming the mark (the mutants that leave the line queued,
/// link a mark nothing was copied into, or drop the mark from the answer
/// answer otherwise).
#[test]
fn a_copy_that_does_not_land_names_the_empty_mark_the_mint_left() {
    let copy = frames_of_a_mark().remove(2);
    let withheld = json!({"resp": "rejected", "op": "copy", "code": "withheld", "disposition": "reorder", "site": {"addr": DOC}});
    let (answer, sent) = run(vec![extent(12), minted(), held_answer(3, "refused"), lines(3, "refused", withheld.clone()), Ok(json!({}))]);
    assert_eq!(sent[2..], [vec![copy.clone()], settling(3)].concat()[..], "the copy, then its line read and dropped; no link");
    let answer = answer.expect("an answer");
    crate::shapes::assert_declared("TextRefused", &answer.value);
    assert_eq!(answer, Answer { value: json!({"outcome": "refused", "cause": "withheld", "doc": DOC, "mark": MARK, "refusal": withheld}), is_error: false });

    let (answer, sent) = run(vec![extent(12), minted(), held_answer(5, "unreachable"), lines(5, "unreachable", Value::Null), Ok(json!({}))]);
    assert_eq!(sent.len(), 5);
    assert_eq!(answer.expect("an answer").into_value(), json!({"outcome": "refused", "cause": "unreachable", "doc": DOC, "mark": MARK, "error": true}), "no verdict: an error, the mark named");

    let gone = || Err(Refusal::shell(Name::NO_SUCH_HELD, json!({"held": 6})));
    for found in [Ok(json!({"kept": true})), gone()] {
        let (answer, sent) = run(vec![extent(12), minted(), held_answer(6, "unreachable"), lines(6, "unreachable", Value::Null), found, linked()]);
        assert_eq!(sent.last(), frames_of_a_mark().last(), "the copy landed: the link is written");
        assert_eq!(answer.expect("an answer").into_value(), json!({"outcome": "marked", "doc": DOC, "mark": MARK, "link": LINK, "at": LINKED_AT}));
    }

    let unread = || Err(Refusal::shell(Name::LANDING_UNREAD, json!({"held": 8, "why": "unanswered"})));
    let (answer, sent) = run(vec![extent(12), minted(), held_answer(8, "unreachable"), lines(8, "unreachable", Value::Null), unread()]);
    assert_eq!(sent.len(), 5, "nothing sent after a line that may land");
    let answer = answer.expect("an answer");
    assert!(answer.is_error);
    let answer = answer.into_value();
    crate::shapes::assert_declared("TextMarkHeld", &answer);
    assert_eq!(answer, json!({"outcome": "held", "doc": DOC, "mark": MARK, "held": 8, "cause": "unreachable", "write": "copy", "error": true}));

    let full = || Refusal::shell(Name::HELD_FULL, json!({"lines": 16384}));
    let (answer, sent) = run(vec![extent(12), minted(), Err(full())]);
    assert_eq!(sent.len(), 3);
    let answer = answer.expect("an answer").into_value();
    crate::shapes::assert_declared("TextRefused", &answer);
    assert_eq!(answer, json!({"outcome": "refused", "cause": "held_full", "doc": DOC, "mark": MARK, "refusal": full().to_value(), "error": true}));
}

/// A link refused or lost answers `partial`, and is not sent again.
///
/// The mint and the copy landed: a link the board refuses, a mark of more
/// runs than a slot takes among the refusals, one whose answer is lost and
/// one answered in a form this shell does not read each answer `partial`, an
/// error naming the mark, which stands with no link, the copy's commit, the
/// cause and the refusal; the link frame is sent once. For a draft read
/// empty the commit is the mint's, and where the copy's own answer was lost
/// it is absent (the mutants that send the link again, or answer a mark
/// with no link as marked, answer otherwise).
#[test]
fn a_link_refused_or_lost_answers_partial_and_is_not_sent_again() {
    let too_large = || verdict("make_link", "slot_too_large");
    let lost = || Refusal::Unreachable(DialError::Timeout("no answer".into()));
    for refusal in [too_large(), lost()] {
        let (answer, sent) = run(vec![extent(12), minted(), copied(), Err(refusal.clone())]);
        assert_eq!(sent, frames_of_a_mark(), "the link sent once");
        let answer = answer.expect("an answer");
        assert!(answer.is_error);
        let answer = answer.into_value();
        crate::shapes::assert_declared("TextMarkPartial", &answer);
        assert_eq!(answer, json!({"outcome": "partial", "doc": DOC, "mark": MARK, "at": COPIED_AT, "cause": refusal.name(), "refusal": refusal.to_value(), "error": true}));
    }
    let (answer, sent) = run(vec![extent(12), minted(), copied(), Ok(json!({"resp": "ack", "at": LINKED_AT}))]);
    assert_eq!(sent.len(), 4);
    let answer = answer.expect("an answer").into_value();
    crate::shapes::assert_declared("TextMarkPartial", &answer);
    assert_eq!(answer, json!({"outcome": "partial", "doc": DOC, "mark": MARK, "at": COPIED_AT, "cause": "unread", "op": "make_link", "error": true}), "an ack that names no link is no link");
    let (answer, _) = run(vec![extent(0), minted(), Err(too_large())]);
    assert_eq!(answer.expect("an answer").value["at"], MINTED_AT, "an empty draft: the mint is the last write that landed");
    let (answer, _) = run(vec![extent(12), minted(), held_answer(6, "unreachable"), lines(6, "unreachable", Value::Null), Ok(json!({"kept": true})), Err(too_large())]);
    let answer = answer.expect("an answer").into_value();
    crate::shapes::assert_declared("TextMarkPartial", &answer);
    assert_eq!(answer.get("at"), None, "the copy's own answer was lost: its commit unnamed");
}
