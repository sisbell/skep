use std::collections::BTreeSet;

use skep_client::halt::{Face, Refused};
use skep_shell::Name;

use super::*;

/// Checks `tools/call` params: a string `name` and optional arguments.
///
/// `arguments` is absent, null (both the empty object) or an object taken
/// whole — anything else refused.
#[test]
fn tools_call_params_are_a_string_name_and_object_or_absent_arguments() {
    let (name, args) = call_params(Some(json!({"name": "fork"}))).expect("argument-less call");
    assert_eq!(name, "fork");
    assert!(args.is_empty());
    let p = json!({"name": "fork", "arguments": null});
    assert!(call_params(Some(p)).expect("null arguments").1.is_empty());
    let p = json!({"name": "insert", "arguments": {"doc": "1.0.1.0.1", "values": ["x"]}});
    let (name, args) = call_params(Some(p)).expect("a call with arguments");
    assert_eq!(name, "insert");
    assert_eq!(Value::Object(args), json!({"doc": "1.0.1.0.1", "values": ["x"]}), "whole");
    assert!(call_params(None).is_err());
    assert!(call_params(Some(json!({"name": 7}))).is_err());
    assert!(call_params(Some(json!({"name": "fork", "arguments": 3}))).is_err());
}

/// Checks that the scan finds each lone surrogate escape, as serde_json does.
///
/// Each row is a text and the offsets found in it. A high or a low alone,
/// in either case of hex, at a string's end, before a pair, before another
/// escape, the two halves reversed and one behind an escaped backslash
/// are lone; a pair, a `u` behind an escaped backslash, another character's
/// escape and text with no escape are not. serde_json refuses a string
/// exactly where one was found, and reads it with U+FFFD's escape over
/// each. A cut escape and a trailing backslash, in no JSON, are scanned to
/// nothing found.
#[test]
fn the_scan_finds_each_lone_surrogate_escape_and_no_other() {
    let strings: [(&str, &[usize]); 14] = [
        (r#""\ud800""#, &[1]),
        (r#""\udc00""#, &[1]),
        (r#""a\uD83Db""#, &[2]),
        (r#""a\uDfFf""#, &[2]),
        (r#""\ud800\ud83d\ude00""#, &[1]),
        (r#""\ude00\ud83d""#, &[1, 7]),
        (r#""\ud800\u0041""#, &[1]),
        (r#""\ud800\n""#, &[1]),
        (r#""\\\ud800""#, &[3]),
        (r#""\ud83d\ude00""#, &[]),
        (r#""\uD83D\uDE00\ud83d\ude00""#, &[]),
        (r#""\\ud800""#, &[]),
        (r#""plain \u00e9 text\n""#, &[]),
        (r#""plain text""#, &[]),
    ];
    for (text, found) in strings {
        assert_eq!(lone_surrogates(text.as_bytes()), found, "{text}");
        assert_eq!(serde_json::from_str::<Value>(text).is_err(), !found.is_empty(), "serde_json refuses {text} where one is lone");
        let mut mended = text.as_bytes().to_vec();
        found.iter().for_each(|&at| mended[at + 2..at + 6].copy_from_slice(b"FFFD"));
        assert!(serde_json::from_slice::<Value>(&mended).is_ok(), "{text} reads with a stand-in at each");
    }
    for cut in [r#""\ud8"#, r#""\ud80g""#, "\"\\", "\\"] {
        assert!(lone_surrogates(cut.as_bytes()).is_empty(), "{cut}");
    }
}

/// Checks what a line holding a lone surrogate escape reads as.
///
/// A request reads whole, U+FFFD where the escape stood, as a notification
/// and JSON that is no object do. An id that holds one is not read — a
/// string, an array's member, a key beside keys that spell the stand-ins
/// — and an id holding its sender's own U+FFFD is, the escape elsewhere.
/// A line with nothing lone, one no stand-in makes parse, and one whose id
/// holds every private-use character, leaving no second stand-in, read as
/// nothing.
#[test]
fn a_line_holding_a_lone_surrogate_escape_reads_with_a_stand_in_but_for_its_id() {
    let read = |line: &str| read_mended(&mut line.as_bytes().to_vec());
    let request = read(r#"{"id":7,"method":"tools/call","params":{"name":"replace_text","arguments":{"old":"a\ud800b","new":"\uDC00 \ud83d"}}}"#);
    assert_eq!(request, Some(json!({"id": 7, "method": "tools/call", "params": {"name": "replace_text", "arguments": {"old": "a\u{FFFD}b", "new": "\u{FFFD} \u{FFFD}"}}})));
    assert_eq!(read(r#"{"method":"x\uDC00"}"#), Some(json!({"method": "x\u{FFFD}"})));
    assert_eq!(read(r#"["\ud800"]"#), Some(json!(["\u{FFFD}"])));
    let own = read(r#"{"id":{"a\ufffd":["\uFFFD"]},"method":"ping","params":["\udc00"]}"#).expect("an id holding its sender's own U+FFFD");
    assert_eq!(own["id"], json!({"a\u{FFFD}": ["\u{FFFD}"]}));
    for unread in [
        r#"{"id":"a\ud800","method":"ping"}"#,
        r#"{"id":[1,"a\ud800"],"method":"ping"}"#,
        r#"{"id":{"\ud800":0,"\ufffd":1,"\ue000":2},"method":"ping"}"#,
        r#"{"id":7,"method":"ping","params":["\ud83d\ude00"]}"#,
        r#"{"id":7,"method":"ping","params":["\ud800"]"#,
        r#"{"id":7,"method":"ping","params":["\ud800",1e999]}"#,
    ] {
        assert_eq!(read(unread), None, "{unread}");
    }
    let every_private: String = ('\u{E000}'..='\u{F8FF}').collect();
    assert_eq!(read(&format!(r#"{{"id":"{every_private}","method":"ping","params":["\ud800"]}}"#)), None, "no stand-in the id does not hold");
}

/// Checks that an answer and the board's verdict are data.
///
/// It is *a refusal as a result*. An answer is the text whole; the board's
/// verdict rides as the refusal's whole value — its body verbatim under
/// `body`, every member skep-shell declares for it beside it and no other
/// — `isError` false; a halt, the block, the unreachable board and the
/// shell's own refusals are `isError` true with the refusal's value as the
/// text, a halt's face as its three words and never the path it names
/// (SP-15: no path in a tool result; the mutant that marks every refusal
/// `isError` loses "the board's verdict is data"; the one that marks none
/// loses `unreachable`).
#[test]
fn an_answer_and_the_boards_verdict_are_data_and_every_other_refusal_is_an_error() {
    let read = |v: &Value| -> (bool, Value) {
        assert_eq!(v["content"].as_array().map(Vec::len), Some(1));
        let text = v["content"][0]["text"].as_str().expect("a text block");
        (v["isError"].as_bool().expect("isError"), serde_json::from_str(text).expect("JSON text"))
    };
    let answer = json!({"resp": "ack_addr", "addr": "1.0.1.0.64", "at": 7});
    let (is_error, value) = read(&tool_result(Ok(answer.clone())));
    assert!(!is_error);
    assert_eq!(value, answer, "the shell's answer, whole");
    let verdict = json!({"code": "doc_not_registered", "disposition": "reorder", "op": "retrieve_v", "resp": "rejected"});
    let detail = Some("the frame names no registered document".to_string());
    let refused = Refusal::Board(Refused { status: 200, code: "doc_not_registered".into(), detail, op: Some("retrieve_v".into()), body: verdict.clone() });
    let expected = refused.to_value();
    let (is_error, value) = read(&tool_result(Err(refused)));
    assert!(!is_error, "the board's verdict is data");
    assert_eq!((value["kind"].as_str(), value["name"].as_str(), value["status"].as_u64()), (Some("refused"), Some("doc_not_registered"), Some(200)));
    assert_eq!(value["body"], verdict, "the verdict's body verbatim");
    assert_eq!(value, expected, "the board's verdict rides as the refusal's whole value");
    let declared: BTreeSet<&str> = skep_shell::shapes::shape("RefusedByBoard").expect("skep-shell declares the board's refusal").fields.iter().map(|field| field.name).collect();
    let members: BTreeSet<&str> = value.as_object().expect("the refusal is an object").keys().map(String::as_str).collect();
    assert_eq!(members, declared, "every member skep-shell declares, and no other");
    let face = Face { state: "s".into(), cause: "c".into(), act: "a".into(), path: None };
    for other in [
        Refusal::named(Name::NO_KEY, face.clone()),
        Refusal::named(Name::STORE_UNREADABLE, Face { path: Some("/a/store/keys/x.key".into()), ..face.clone() }),
        Refusal::halt(face),
        Refusal::Blocked(skep_client::Blocked { record: "1.0.1.0.69.1".into(), named_by: "http://x".into(), ground: None }),
        Refusal::Unreachable(skep_client::DialError::Connect("refused".into())),
        Refusal::shell(Name::SESSION_ENDED, json!({"session": "s-1"})),
        Refusal::malformed("since"),
    ] {
        let expected = other.to_value();
        let (is_error, value) = read(&tool_result(Err(other)));
        assert!(is_error, "{expected}");
        assert_eq!(value, expected, "the refusal's value is the text");
        assert!(!value.to_string().contains("/a/store"), "a face's path reaches no tool result: {value}");
    }
}

/// Checks that the text edit's error member is its `isError`, and is taken
/// off.
///
/// The shell's `text.replace` answer with the error member is `isError`
/// true, its text the answer less the member, exactly as an agent was
/// always answered; one without it is `isError` false and its text whole;
/// a member of another value marks no error; and a refusal of the call goes
/// by *a refusal as a result*, the board's verdict data and the shell's own
/// `isError` (the mutants that strip the member and mark nothing, mark the
/// error and leave the member in the text, or read every edit as an error).
#[test]
fn the_edits_error_member_is_its_is_error_and_is_taken_off() {
    let read = |v: &Value| -> (bool, Value) {
        let text = v["content"][0]["text"].as_str().expect("a text block");
        (v["isError"].as_bool().expect("isError"), serde_json::from_str(text).expect("JSON text"))
    };
    let held = json!({"outcome": "held", "doc": "1.0.1.0.64", "held": 8, "cause": "unreachable", "write": "insert"});
    let mut marked = held.clone();
    marked[EDIT_ERROR] = json!(true);
    assert_eq!(read(&edit_result(Ok(marked))), (true, held.clone()), "an error, the member taken off");
    let replaced = json!({"outcome": "replaced", "doc": "1.0.1.0.64", "ordinal": "7", "removed": "1", "inserted": "1", "addr": "1.0.1.0.64.0.1.80", "at": 45});
    assert_eq!(read(&edit_result(Ok(replaced.clone()))), (false, replaced), "data, whole");
    let mut unmarked = held.clone();
    unmarked[EDIT_ERROR] = json!("yes");
    assert_eq!(read(&edit_result(Ok(unmarked))), (false, held), "a member of another value marks no error");
    let verdict = Refusal::Board(Refused { status: 200, code: "not_owner".into(), detail: None, op: Some("doc_metadata".into()), body: json!({"resp": "rejected", "code": "not_owner"}) });
    assert_eq!(edit_result(Err(verdict.clone())), tool_result(Err(verdict)), "the board's verdict on a read, as every tool's");
    let ended = Refusal::shell(Name::SESSION_ENDED, json!({"session": "s-1"}));
    assert_eq!(read(&edit_result(Err(ended.clone()))), (true, ended.to_value()), "the shell's own refusal of the call");
}

/// Checks that the builders move what they wrap into the two specs' shapes.
///
/// Each equals what `json!` builds from the same members: a JSON-RPC
/// response and error (JSON-RPC 2.0 §5), and a tool result of one text
/// block, `isError` as given (MCP 2025-06-18, Tools).
#[test]
fn the_builders_move_what_they_wrap_into_the_shapes_the_specs_name() {
    assert_eq!(rpc_result(json!(7), json!({"tools": []})), json!({"jsonrpc": "2.0", "id": 7, "result": {"tools": []}}));
    assert_eq!(rpc_error(json!("x"), ErrorCode::InvalidParams, "no"), json!({"jsonrpc": "2.0", "id": "x", "error": {"code": -32602, "message": "no"}}));
    assert_eq!(text_result("t".into(), IsError::Yes), json!({"content": [{"type": "text", "text": "t"}], "isError": true}));
    assert_eq!(text_result("t".into(), IsError::No), json!({"content": [{"type": "text", "text": "t"}], "isError": false}));
}

/// Checks a slow call's line: its tool, request, wait, hold and answer.
///
/// The line names the tool, the request's id as given — a long one cut at
/// 64 characters — how long the request waited behind earlier calls, how
/// long the call held the loop, and the answer: a tool result, one
/// `isError`, or the -32602; no argument rides it. A call that waited and
/// was quick is said with its wait as surely as one that held the loop.
#[test]
fn a_slow_call_is_said_by_its_tool_request_wait_hold_and_answer() {
    let held = Duration::from_millis(10_240);
    let answered = slow_call_line("fetch", &json!(7), Duration::ZERO, held, &Ok(text_result("x".into(), IsError::No)));
    assert_eq!(answered, "the `fetch` call of request 7 waited 0.0 s behind earlier calls and held the loop 10.2 s: answered");
    let is_error = slow_call_line("create_new_document", &json!("call-1"), Duration::ZERO, held, &Ok(text_result("x".into(), IsError::Yes)));
    assert_eq!(is_error, "the `create_new_document` call of request \"call-1\" waited 0.0 s behind earlier calls and held the loop 10.2 s: answered isError");
    let long = json!("x".repeat(100));
    let refused = slow_call_line("search", &long, Duration::ZERO, held, &Err("search's opts take 'limit', 'offset'; got 'reindex'".into()));
    assert_eq!(refused, format!("the `search` call of request \"{}… waited 0.0 s behind earlier calls and held the loop 10.2 s: refused -32602", "x".repeat(63)));
    let queued = slow_call_line("boards", &json!(9), Duration::from_millis(58_300), Duration::from_micros(40), &Ok(text_result("x".into(), IsError::No)));
    assert_eq!(queued, "the `boards` call of request 9 waited 58.3 s behind earlier calls and held the loop 0.0 s: answered");
}

/// Checks that what the loop served is counted by the answers written.
///
/// Every answer counts; a tool result counts as one, `isError` or not, and
/// a JSON-RPC error as one; the loop's time on each adds up as its busy
/// time, and the longest a line waited before the loop took it is kept,
/// whichever line it was; the figures are said over the time served.
#[test]
fn what_the_loop_served_is_counted_by_the_answers_written() {
    let mut served = Served::default();
    let replies = [
        rpc_result(json!(1), json!({"protocolVersion": "2025-06-18"})),
        rpc_result(json!(2), text_result("x".into(), IsError::No)),
        rpc_result(json!(3), text_result("x".into(), IsError::Yes)),
        rpc_error(json!(4), ErrorCode::InvalidParams, "no"),
        rpc_error(Value::Null, ErrorCode::ParseError, "parse error"),
    ];
    // Waits and times that neither rise nor fall, so the longest wait is
    // neither the last nor a sum, and the busy time no single line's.
    let (waits, busy) = ([100, 400, 0, 300, 200], [300, 200, 500, 100, 400]);
    for ((reply, waited), busy) in replies.iter().zip(waits).zip(busy) {
        served.count(reply, Duration::from_millis(waited), Duration::from_millis(busy));
    }
    assert_eq!(
        served.said(Duration::from_millis(2_000)),
        "5 answers written in 2.0 s of serving, the loop busy 1.5 s of it: 2 tool results, 1 of them isError, and 2 JSON-RPC errors; no request waited longer than 0.4 s behind earlier calls"
    );
}
