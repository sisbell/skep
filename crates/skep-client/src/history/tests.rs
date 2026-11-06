//! The restore's unit suite: THE MAPPING's arithmetic over hand-built
//! records, and THE READS AND THE ONE WRITE over the crate's fake board —
//! the frames in order, the position pre-check that reads nothing at a
//! position, the published document refused at the one read, the write
//! byte-checked.

use std::sync::Arc;

use serde_json::{json, Value};
use skep_address::Address;

use super::{covered, mapped, past, restore, Restored};
use crate::address::parse_address;
use crate::board::fake::{self, Fake};
use crate::board::frames::{self, T_CORRESPONDENCE};
use crate::board::Token;
use crate::dial::Request;
use crate::merge::{Refusal, Run};
use crate::publication::{ISpan, Record};

const TOKEN: &str = "9f3a6c21d4b8e07a5c1b2d4e6f708192";
/// The person's account; `S` their draft, `E` the trunk its words were
/// published into, `Z` another account's document a run windows.
const ACCOUNT: &str = "1.0.1";
const S: &str = "1.0.1.0.4";
const E: &str = "1.0.1.0.2";
const Z: &str = "1.0.2.0.3";

fn a(text: &str) -> Address {
    parse_address(text).expect("an address")
}

fn run(doc: &str, s: u64, w: u64) -> Run {
    Run::new(a(doc), s, w)
}

fn span(doc: &str, first: u64, width: u64) -> ISpan {
    ISpan { chain: format!("{doc}.0.1"), first, width }
}

/// A record homed in `home`, its link the `k`-th of the home.
fn record(home: &str, k: u64, from: ISpan, to: ISpan) -> Record {
    Record { link: a(&format!("{home}.0.2.{k}")), home: a(home), from, to, at: Some(15) }
}

fn token() -> Token {
    Token::parse(TOKEN).expect("a token")
}

/// A `doc_metadata` answer for `S` at position 20: a private draft of the
/// person's, no marker.
fn metadata(published: bool) -> Value {
    json!({"resp": "doc_metadata", "as_of": 20, "doc": S, "published": published, "owner": ACCOUNT, "merge": null})
}

// ── the mapping ──────────────────────────────────────────────────────────

/// A run a record covers whole comes back as the published span, its origin
/// the trunk; one covered at its head, its tail or its middle is split into
/// the mapped piece and the pieces kept as read.
#[test]
fn a_covered_run_is_mapped_whole_or_split_at_the_records_edges() {
    let state = vec![run(S, 1, 11)];
    let whole = [record(S, 1, span(S, 1, 11), span(E, 20, 11))];
    assert_eq!(mapped(&state, &whole), vec![run(E, 20, 11)]);
    assert_eq!(covered(&state, &whole), 11);
    let head = [record(S, 1, span(S, 1, 4), span(E, 20, 4))];
    assert_eq!(mapped(&state, &head), vec![run(E, 20, 4), run(S, 5, 7)]);
    assert_eq!(covered(&state, &head), 4);
    let tail = [record(S, 1, span(S, 8, 4), span(E, 30, 4))];
    assert_eq!(mapped(&state, &tail), vec![run(S, 1, 7), run(E, 30, 4)]);
    let middle = [record(S, 1, span(S, 4, 3), span(E, 40, 3))];
    assert_eq!(mapped(&state, &middle), vec![run(S, 1, 3), run(E, 40, 3), run(S, 7, 5)]);
    assert_eq!(covered(&state, &middle), 3);
}

/// Two adjoining records whose published spans are I-adjacent map to one
/// run; two whose spans lie apart map to two, in the state's order.
#[test]
fn adjoining_records_merge_where_their_published_spans_adjoin() {
    let state = vec![run(S, 1, 11)];
    let adjoining = [record(S, 1, span(S, 1, 5), span(E, 20, 5)), record(S, 2, span(S, 6, 6), span(E, 25, 6))];
    assert_eq!(mapped(&state, &adjoining), vec![run(E, 20, 11)]);
    assert_eq!(covered(&state, &adjoining), 11);
    let apart = [record(S, 1, span(S, 1, 5), span(E, 20, 5)), record(S, 2, span(S, 6, 6), span(E, 40, 6))];
    assert_eq!(mapped(&state, &apart), vec![run(E, 20, 5), run(E, 40, 6)]);
}

/// A run of an origin no record names passes through unchanged, in its
/// place; a record on another chain touches nothing; no records is the
/// state itself.
#[test]
fn runs_no_record_names_pass_through_in_order() {
    let state = vec![run(Z, 1, 5), run(S, 1, 3), run(S, 20, 3)];
    let records = [record(S, 1, span(S, 1, 3), span(E, 7, 3)), record(E, 2, span(E, 1, 50), span(E, 60, 50))];
    assert_eq!(mapped(&state, &records), vec![run(Z, 1, 5), run(E, 7, 3), run(S, 20, 3)]);
    assert_eq!(covered(&state, &records), 3);
    assert_eq!(mapped(&state, &[]), state);
    assert_eq!(covered(&state, &[]), 0);
}

// ── the reads and the one write ──────────────────────────────────────────

/// The fake board: `S` at position 20 holding fourteen positions in two
/// runs as of 12, one record in `S` naming its first eleven as `E`'s
/// twentieth on, a hit in another account's home, a hit of another type,
/// and the write acknowledged at 21.
fn scripted() -> Arc<Fake> {
    Fake::new(|req: &Request| {
        let f = fake::frame(req);
        match (req.path.as_str(), f["op"].as_str().unwrap_or("?")) {
            ("/op", "doc_metadata") => fake::json(200, metadata(false)),
            ("/op-at", "retrieve_doc_v_span_set") => fake::json(200, json!({"resp": "span_set", "as_of": 12, "set": [{"start": "1.1", "width": "0.14"}]})),
            ("/op-at", "image") => fake::json(200, json!({"resp": "runs", "as_of": 12, "runs": [{"i_start": format!("{S}.0.1.1"), "width": "11"}, {"i_start": format!("{S}.0.1.20"), "width": "3"}]})),
            ("/op", "find_links_ftt") => fake::json(200, json!({"resp": "addrs", "as_of": 20, "addrs": [format!("{S}.0.2.1"), format!("{Z}.0.2.9"), format!("{S}.0.2.2")]})),
            ("/op", "read_link") => {
                let ty = if f["a"] == format!("{S}.0.2.1") { frames::unit_span(T_CORRESPONDENCE) } else { frames::unit_span("1.1.0.1.0.1.0.3.13") };
                fake::json(200, json!({"resp": "link_value", "as_of": 20, "at": 15, "link": {"slots": [[frames::i_span(&format!("{S}.0.1.1"), 11)], [frames::i_span(&format!("{E}.0.1.20"), 11)], ty]}}))
            }
            ("/op", "set_arrangement") => fake::json(200, json!({"resp": "ack", "at": 21})),
            other => panic!("the restore sent a frame the fake does not answer: {other:?}"),
        }
    })
}

/// The frames the fake served, each as the board read it: an `/op-at`
/// body's inner frame beside its position, an `/op` frame whole.
fn served(fake: &Fake) -> Vec<(String, Option<u64>, Value)> {
    fake.sent
        .lock()
        .unwrap()
        .iter()
        .map(|(_, req)| {
            let body: Value = serde_json::from_slice(&req.body).unwrap_or(Value::Null);
            (req.path.clone(), body["at"].as_u64().filter(|_| req.path == "/op-at"), fake::frame(req))
        })
        .collect()
}

/// THE READS IN ORDER — the metadata at the head, the extent and the image
/// as of `at`, the records at the head (one query, home-constrained, over
/// the state's spans; the other account's hit never read; the hit of
/// another type read and dropped) — the state, the mapped runs and the
/// count; then THE ONE WRITE: the mapped runs, `as_of` the first read's
/// position, no head, no base, no merge, the id naming the draft and the two
/// positions.
#[test]
fn the_reads_run_in_order_and_the_one_write_sends_the_mapped_state() {
    let fake = scripted();
    let board = fake::board(&fake);
    let p = past(&board, &token(), ACCOUNT, &a(S), 12).expect("the past read");
    assert_eq!(p.state, vec![run(S, 1, 11), run(S, 20, 3)]);
    assert_eq!(p.sent, vec![run(E, 20, 11), run(S, 20, 3)], "the first eleven come back as E's words, the trunk their origin");
    assert_eq!((p.at, p.as_of, p.records.len(), p.covered(), p.extent(), p.marker.is_none()), (12, 20, 1, 11, 14, true));
    assert_eq!(fake.log(), ["POST /op doc_metadata", "POST /op-at retrieve_doc_v_span_set", "POST /op-at image", "POST /op find_links_ftt", "POST /op read_link", "POST /op read_link"]);
    let reads = served(&fake);
    assert_eq!(reads.iter().filter_map(|(_, at, _)| *at).collect::<Vec<_>>(), [12, 12], "the state read as of `at`, nothing else at a position");
    let query = &reads[3].2["q"];
    assert_eq!(query["home"], frames::unit_span(S));
    assert_eq!(query["from"], json!([frames::i_span(&format!("{S}.0.1.1"), 11), frames::i_span(&format!("{S}.0.1.20"), 3)]));
    assert_eq!((query["to"].as_str(), query["ty"].clone()), (Some("any"), frames::unit_span(T_CORRESPONDENCE)));
    assert_eq!(reads[4].2["a"], format!("{S}.0.2.1"));
    assert_eq!(reads[5].2["a"], format!("{S}.0.2.2"), "the other account's hit is judged off its address and never read");
    let restored = restore(&board, &token(), &p).expect("restored");
    assert_eq!(restored, Restored { draft: a(S), at: 12, position: 21 });
    let (path, at, write) = served(&fake).pop().expect("the write");
    assert_eq!((path.as_str(), at), ("/op", None));
    let runs = [frames::shot_run(E, &format!("{E}.0.1.20"), 11), frames::shot_run(S, &format!("{S}.0.1.20"), 3)];
    assert_eq!(write, json!({"op": "set_arrangement", "doc": S, "as_of": 20, "runs": runs, "id": format!("restore:{S}:12:20.arrangement")}), "no head, no base, no merge");
}

/// A position at or past the draft's own is refused before any read at a
/// position: the one `doc_metadata` read, nothing on `/op-at`, nothing
/// sent.
#[test]
fn a_position_at_or_past_the_drafts_own_is_refused_before_any_read_at_a_position() {
    let fake = Fake::new(|req: &Request| {
        assert_eq!(req.path, "/op", "a read at a position: {}", req.path);
        assert_eq!(fake::frame(req)["op"], "doc_metadata", "another read: {}", fake::frame(req));
        fake::json(200, metadata(false))
    });
    let board = fake::board(&fake);
    for at in [20, 21, 1_000] {
        assert_eq!(past(&board, &token(), ACCOUNT, &a(S), at), Err(Refusal::NotPast { draft: a(S), at, current: 20 }));
    }
    assert_eq!(fake.log().len(), 3, "one read each");
    let said = Refusal::NotPast { draft: a(S), at: 20, current: 20 }.to_string();
    assert!(said.contains("position 20") && said.contains("nothing was read or sent"), "{said}");
}

/// A published document is refused at the one read, nothing else read.
#[test]
fn a_published_document_is_refused_at_the_one_read() {
    let fake = Fake::new(|_: &Request| fake::json(200, metadata(true)));
    let board = fake::board(&fake);
    assert_eq!(past(&board, &token(), ACCOUNT, &a(S), 3), Err(Refusal::Published { doc: a(S) }));
    assert_eq!(fake.log(), ["POST /op doc_metadata"]);
}
