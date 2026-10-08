//! THE BRIDGE CALL against the daemon (`client.md` §4e.5; `search.md` §3.4):
//! "NO RECORD OF A SEARCH" and "PURE LOCAL" — a search dials nothing and no
//! request body carries the query's words; `query_too_long` at 1,025 bytes
//! echoing none of it; and THE JUMP's one read, `compare`, whose `rho1` is
//! the BAND the page composes and never the hit's span, landed by the rule.

use skep_client::board::{frames, Answer};
use skep_client::search::{landing_of, Landing, QueryTooLong, SearchOpts, Who, QUERY_BOUND};

use super::Fixture;
use crate::common::traced_board;

/// §4e.5: "NO RECORD OF A SEARCH … no query text, hit or jump target is
/// written into any log, refusal detail …"; "PURE LOCAL: no board read on
/// the call's path". The jump: `rho1` "the BAND the LEAP's viewport will
/// show at `member` around the hit's span … never a range cut to the span",
/// and the landing over the answered pairs.
#[test]
fn the_query_crosses_nothing_but_the_answer_and_the_jump_names_the_band_not_the_span() {
    let fx = Fixture::claimed();
    let signed = fx.signed(&fx.board);
    let (doc, member) = fx.published(&signed, "one two three CORMORANT five six seven eight nine ten");
    signed.close().unwrap();
    let (traced, traces) = traced_board(fx.board.dialed().clone());
    let consumer = fx.consumer(&traced);
    consumer.poll().unwrap();
    traces.lock().unwrap().clear();
    let answer = consumer.search(Who::Guest, "cormorant", &SearchOpts::default()).unwrap();
    assert_eq!(answer.hits.len(), 1);
    let hit = &answer.hits[0];
    assert_eq!((hit.doc.clone(), hit.member.clone()), (doc.clone(), Some(member.clone())));
    assert!(traces.lock().unwrap().is_empty(), "the call dials nothing");
    let long = "q".repeat(QUERY_BOUND + 1);
    let refused = consumer.search(Who::Guest, &long, &SearchOpts::default()).expect_err("too long");
    assert_eq!(refused, QueryTooLong { bound: QUERY_BOUND, length: QUERY_BOUND + 1 });
    assert!(!refused.to_string().contains("qq"));
    assert!(traces.lock().unwrap().is_empty());
    // THE JUMP: the page composes the band — the member's whole extent
    // here — and the shell reads `compare` against the head, the hit's span
    // never named.
    let extent = "one two three CORMORANT five six seven eight nine ten".len() as u64;
    let band = frames::region(&member.to_string(), 1, extent);
    let head = frames::region(&doc.to_string(), 1, extent);
    let Answer::Document(v) = traced.op(None, &frames::compare(&[band], &[head])).unwrap() else { panic!("closed") };
    let landing = landing_of(&v, hit.span).unwrap_or_else(|| panic!("no landing: {v}"));
    assert_eq!(landing, Landing::Carried { at: hit.span.start }, "the head is the member: carried whole at the same position");
    let traces = traces.lock().unwrap();
    assert_eq!(traces.len(), 1, "one `compare` read: {:?}", traces.iter().map(|t| &t.line).collect::<Vec<_>>());
    let body = String::from_utf8_lossy(&traces[0].body);
    assert!(!body.contains("cormorant") && !body.contains("CORMORANT"), "no request body carries the query's words: {body}");
    let span_spelled = format!("\"start\":\"1.{}\",\"width\":\"0.{}\"", hit.span.start, hit.span.width);
    assert!(!body.contains(&span_spelled), "the body names the band, never the hit's span: {body}");
}
