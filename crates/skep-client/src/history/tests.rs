//! The restore's unit suite: the core runs' mapping and `covered` over
//! hand-built records, the mapping of images at their own spelling, and THE
//! READS AND THE ONE WRITE over the crate's fake board — the frames in
//! order, the position pre-check that reads nothing at a position, the
//! published document refused at the one read, the write byte-checked, a
//! member's own words written under the member's chain, the cap counted on
//! the runs the write sends, a record mapping past the range faced, and the
//! session's end at each of them typed. Beside them, the one records' read
//! over several images, the diff's.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use serde_json::{json, Value};
use skep_address::Address;

use super::{covered, mapped, mapped_image, past, records, restore, Restored};
use crate::address::parse_address;
use crate::board::answers::MAX_IMAGE_RUNS;
use crate::board::fake::{self, Fake};
use crate::board::frames::{self, T_CORRESPONDENCE};
use crate::board::{whole_image, Image, Token};
use crate::dial::{Request, Response};
use crate::halt::Halt;
use crate::merge::reads::OnEnd;
use crate::merge::{Refusal, Run, SHOT_RUN_CAP};
use crate::publication::{ISpan, Record};

const TOKEN: &str = "9f3a6c21d4b8e07a5c1b2d4e6f708192";
/// The person's account; `S` their draft, `E` the trunk its words were
/// published into, `Z` another account's document a run windows.
const ACCOUNT: &str = "1.0.1";
const S: &str = "1.0.1.0.66";
const E: &str = "1.0.1.0.64";
const Z: &str = "1.0.2.0.65";

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

// ── the mapping of images ────────────────────────────────────────────────

/// A member of `E`'s chain, whose own words a deposit naming it mints under
/// its chain, `M.0.1`.
const M: &str = "1.0.1.0.64.1";

/// Returns an `image` answer as of 12 holding `runs`, each an I-address
/// prefix, a first ordinal and a width, in V order.
fn runs_at(runs: &[(&str, u64, u64)]) -> Value {
    let runs: Vec<Value> = runs.iter().map(|(prefix, first, width)| json!({"i_start": format!("{prefix}.{first}"), "width": width.to_string()})).collect();
    json!({"resp": "runs", "as_of": 12, "runs": runs})
}

/// Returns the image of `runs`, as [`runs_at`] takes them, decoded as a
/// board's answer is.
fn image(runs: &[(&str, u64, u64)]) -> Image {
    whole_image(&runs_at(runs)).expect("an image")
}

/// A draft run a record covers in part comes back as the trunk's span where
/// the record covers it and as its own words around it; a window no record
/// names, and a run minted under a member's chain, keep their own prefixes —
/// the member's never spelled as its trunk's, as the merge's runs spell it;
/// the ordinals are tiled again from 1, the extent unchanged (the mutants
/// that map through the merge's runs, keep the old ordinals, or drop a run
/// answer another image).
#[test]
fn an_image_is_mapped_at_its_own_spelling_and_tiled_again_from_one() {
    let (s, z, e, m) = (format!("{S}.0.1"), format!("{Z}.0.1"), format!("{E}.0.1"), format!("{M}.0.1"));
    let before = image(&[(&s, 1, 10), (&z, 1, 4), (&m, 7, 3)]);
    let records = [record(S, 1, span(S, 3, 5), span(E, 20, 5))];
    let after = mapped_image(&before, &records).expect("mapped");
    assert_eq!(after, image(&[(&s, 1, 2), (&e, 20, 5), (&s, 8, 3), (&z, 1, 4), (&m, 7, 3)]));
    assert_eq!(after.runs().iter().map(|run| run.ordinal).collect::<Vec<_>>(), [1, 3, 8, 11, 15], "tiled again from 1");
    assert_eq!((after.extent(), before.extent()), (17, 17), "the extent unchanged");
    assert_eq!(after.runs()[4].prefix, m, "the member's own chain, never its trunk's");
}

/// Two mapped pieces I-adjacent on one chain are one run, and so are a
/// mapped piece and a run of the trunk's words beside it; an image no record
/// touches comes back equal (a board answers I-adjacent runs joined).
#[test]
fn mapped_pieces_adjacent_on_one_chain_are_one_run_and_an_untouched_image_is_itself() {
    let (s, z, e) = (format!("{S}.0.1"), format!("{Z}.0.1"), format!("{E}.0.1"));
    let adjoining = [record(S, 1, span(S, 1, 4), span(E, 20, 4)), record(S, 2, span(S, 5, 6), span(E, 24, 6))];
    assert_eq!(mapped_image(&image(&[(&s, 1, 10)]), &adjoining), Ok(image(&[(&e, 20, 10)])));
    let beside = image(&[(&s, 1, 4), (&e, 24, 6)]);
    assert_eq!(mapped_image(&beside, &adjoining[..1]), Ok(image(&[(&e, 20, 10)])), "the re-minted words and the trunk's beside them");
    let untouched = image(&[(&z, 1, 5), (&s, 1, 3), (&e, 40, 2)]);
    assert_eq!(mapped_image(&untouched, &[]), Ok(untouched.clone()));
    assert_eq!(mapped_image(&untouched, &[record(S, 1, span(S, 50, 4), span(E, 7, 4))]), Ok(untouched.clone()), "a record of positions it does not hold");
    assert_eq!(mapped_image(&Image::default(), &adjoining), Ok(Image::default()));
}

/// A record mapping words past the largest ordinal is the board's fault,
/// faced, never a panic or a wrapped sum: at the piece's first I-address,
/// and at its last.
#[test]
fn a_record_mapping_past_the_largest_ordinal_is_faced_and_maps_nothing() {
    let s = format!("{S}.0.1");
    let faced = |answer: Result<Image, Halt>| matches!(answer, Err(Halt::Halt(face)) if face.state.contains("past the largest ordinal") && face.act.contains("board fault"));
    let first = [record(S, 1, span(S, 1, 10), span(E, u64::MAX, 10))];
    assert!(faced(mapped_image(&image(&[(&s, 5, 1)]), &first)), "the offset past the range");
    let last = [record(S, 1, span(S, 1, 10), span(E, u64::MAX - 3, 10))];
    assert!(faced(mapped_image(&image(&[(&s, 1, 10)]), &last)), "the piece's last I-address past the range");
    assert!(mapped_image(&image(&[(&s, 1, 4)]), &last).is_ok(), "within the range, mapped");
}

/// THE RECORDS OF SEVERAL IMAGES, one read: the owned origin's spans of both
/// images in one four-set query, a span two images hold asked once, the
/// other account's hit never read, a record kept once; the death signal at
/// the query and at a link's read is the typed session end (the mutants that
/// read per image, or keep a span twice, ask another query).
#[test]
fn the_records_of_several_images_are_read_at_once_each_span_asked_once() {
    let (s, z) = (format!("{S}.0.1"), format!("{Z}.0.1"));
    let (mark, draft) = (image(&[(&s, 1, 11), (&z, 1, 4)]), image(&[(&s, 1, 11), (&s, 20, 3)]));
    let fake = scripted();
    let found = records(&fake::board(&fake), &token(), ACCOUNT, &[&mark, &draft]).expect("the records");
    assert_eq!(found, vec![record(S, 1, span(S, 1, 11), span(E, 20, 11))]);
    assert_eq!(fake.log(), ["POST /op find_links_ftt", "POST /op read_link", "POST /op read_link"], "one query, each owned hit read once");
    let reads = served(&fake);
    assert_eq!(reads[0].2["q"]["home"], frames::unit_span(S));
    assert_eq!(reads[0].2["q"]["from"], json!([frames::i_span(&format!("{s}.1"), 11), frames::i_span(&format!("{s}.20"), 3)]), "each span once");
    assert_eq!(records(&fake::board(&Fake::unread()), &token(), ACCOUNT, &[&image(&[(&z, 1, 4)]), &Image::default()]), Ok(Vec::new()), "no origin of the person's: nothing read");
    for n in 1..=2 {
        let dying = dying_at(n);
        let answer = records(&fake::board(&dying), &token(), ACCOUNT, &[&mark, &draft]);
        assert!(matches!(&answer, Err(Refusal::SessionEnded(Halt::Halt(face))) if face.act == OnEnd::Rerun.act()), "the death at read {n}: {answer:?}");
    }
}

// ── the reads and the one write ──────────────────────────────────────────

/// The fake board: `S` at position 20 holding fourteen positions in two
/// runs as of 12, one record in `S` naming its first eleven as `E`'s
/// twentieth on, a hit in another account's home, a hit of another type,
/// and the write acknowledged at 21.
fn scripted() -> Arc<Fake> {
    Fake::new(answer)
}

/// The fake board of [`scripted`], the session dying before its `n`-th
/// request is answered: that answer carries the death signal.
fn dying_at(n: usize) -> Arc<Fake> {
    let served = AtomicUsize::new(0);
    Fake::new(move |req: &Request| if served.fetch_add(1, Ordering::SeqCst) + 1 == n { fake::closed() } else { answer(req) })
}

/// The answer of [`scripted`]'s board to one request.
fn answer(req: &Request) -> Response {
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
}

/// Returns the fake board of a draft `S` whose state as of 12 holds
/// `extent` positions.
///
/// `region(from, width)` is the `image` answer of a region of the state,
/// `hits` the records' query's addresses and `link` every record's read;
/// the write is acknowledged at 21.
fn holding(extent: u64, region: impl Fn(u64, u64) -> Value + Send + Sync + 'static, hits: Vec<String>, link: Value) -> Arc<Fake> {
    Fake::new(move |req: &Request| {
        let f = fake::frame(req);
        // The region's first ordinal, `1.from`, and its width, `0.width`.
        let part = |key: &str, lead: &str| f["region"][0][key].as_str().and_then(|s| s.strip_prefix(lead)?.parse::<u64>().ok());
        match (req.path.as_str(), f["op"].as_str().unwrap_or("?")) {
            ("/op", "doc_metadata") => fake::json(200, metadata(false)),
            ("/op-at", "retrieve_doc_v_span_set") => fake::json(200, json!({"resp": "span_set", "as_of": 12, "set": [{"start": "1.1", "width": format!("0.{extent}")}]})),
            ("/op-at", "image") => fake::json(200, region(part("start", "1.").expect("a region"), part("width", "0.").expect("a width"))),
            ("/op", "find_links_ftt") => fake::json(200, json!({"resp": "addrs", "as_of": 20, "addrs": hits})),
            ("/op", "read_link") => fake::json(200, link.clone()),
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
/// another type read and dropped) — the state, the written image and its
/// core runs, and the count; then THE ONE WRITE: the written runs, `as_of`
/// the first read's position, no head, no base, no merge, the id naming the
/// draft and the two positions.
#[test]
fn the_reads_run_in_order_and_the_one_write_sends_the_mapped_state() {
    let fake = scripted();
    let board = fake::board(&fake);
    let p = past(&board, &token(), ACCOUNT, &a(S), 12).expect("the past read");
    assert_eq!(p.state, vec![run(S, 1, 11), run(S, 20, 3)]);
    assert_eq!(p.written, image(&[(&format!("{E}.0.1"), 20, 11), (&format!("{S}.0.1"), 20, 3)]), "the image the write sends, mapped");
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

/// A member's own words are written under the member's chain.
///
/// A deposit naming `M` is minted under `M`'s chain, and a draft staged
/// from `M` holds it I-adjacent to the trunk's words: the core's runs join
/// the two as one run of `E`, and the write sends each run as itself, its
/// `origin` the document that minted it (the mutants that spell the write
/// from the core's runs, map through them, or state the trunk as the
/// member's origin send another frame).
#[test]
fn a_members_own_words_are_written_under_the_members_chain() {
    let (e, m) = (format!("{E}.0.1"), format!("{M}.0.1"));
    let held = runs_at(&[(&e, 1, 2), (&m, 3, 1)]);
    let fake = holding(3, move |_, _| held.clone(), Vec::new(), Value::Null);
    let board = fake::board(&fake);
    let p = past(&board, &token(), ACCOUNT, &a(S), 12).expect("the past read");
    assert_eq!((p.state.clone(), p.sent.clone()), (vec![run(E, 1, 3)], vec![run(E, 1, 3)]), "the premise: the core's runs spell the member's word as the trunk's");
    assert_eq!(p.written, image(&[(&e, 1, 2), (&m, 3, 1)]), "each run on the chain that minted it");
    restore(&board, &token(), &p).expect("restored");
    let (_, _, write) = served(&fake).pop().expect("the write");
    assert_eq!(write["runs"], json!([frames::shot_run(E, &format!("{e}.1"), 2), frames::shot_run(M, &format!("{m}.3"), 1)]));
}

/// A state is refused at the cap counted on the runs its write would send.
///
/// The trunk's words and a member's alternate I-adjacent, one core run of
/// `E` and 4,097 written runs, read in halves past the board's run budget:
/// [`Refusal::OverCap`] with the written count, nothing sent (the mutant
/// that counts the core's runs answers the state).
#[test]
fn a_state_whose_written_runs_pass_the_cap_is_refused_however_few_its_core_runs() {
    let (e, m) = (format!("{E}.0.1"), format!("{M}.0.1"));
    let region = move |from: u64, width: u64| {
        if width as usize > MAX_IMAGE_RUNS {
            return json!({"resp": "rejected", "code": "image_too_large", "disposition": "permanent", "op": "image"});
        }
        let runs: Vec<(&str, u64, u64)> = (from..from + width).map(|p| (if p % 2 == 1 { e.as_str() } else { m.as_str() }, p, 1)).collect();
        runs_at(&runs)
    };
    let fake = holding(SHOT_RUN_CAP as u64 + 1, region, Vec::new(), Value::Null);
    assert_eq!(past(&fake::board(&fake), &token(), ACCOUNT, &a(S), 12), Err(Refusal::OverCap { runs: SHOT_RUN_CAP + 1, cap: SHOT_RUN_CAP }));
    let reads = ["POST /op doc_metadata", "POST /op-at retrieve_doc_v_span_set", "POST /op-at image", "POST /op-at image", "POST /op-at image", "POST /op find_links_ftt"];
    assert_eq!(fake.log(), reads, "the image read in halves past the budget; nothing sent");
}

/// A board's record mapping the state past the largest ordinal is faced.
///
/// It is the board's fault, faced at the read before any core run is mapped
/// through the record, never a panic or a wrapped sum (SP-19; the mutant
/// that maps the core's runs first panics).
#[test]
fn a_record_mapping_the_state_past_the_range_is_faced_at_the_read() {
    let s = format!("{S}.0.1");
    let held = runs_at(&[(&s, 5, 3)]);
    let to = frames::i_span(&format!("{E}.0.1.{}", u64::MAX - 2), 11);
    let link = json!({"resp": "link_value", "as_of": 20, "at": 15, "link": {"slots": [[frames::i_span(&format!("{s}.1"), 11)], [to], frames::unit_span(T_CORRESPONDENCE)]}});
    let fake = holding(3, move |_, _| held.clone(), vec![format!("{S}.0.2.1")], link);
    let answer = past(&fake::board(&fake), &token(), ACCOUNT, &a(S), 12);
    assert!(
        matches!(&answer, Err(Refusal::Halt(Halt::Halt(face))) if face.state.contains("past the largest ordinal") && face.act.contains("board fault") && face.act.contains("written")),
        "{answer:?}"
    );
    assert_eq!(fake.log().last().map(String::as_str), Some("POST /op read_link"), "nothing read or sent past the record");
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

/// THE SESSION'S END (skep #812): the death signal at each of the reads —
/// the metadata at the head, the extent and the image at the position, the
/// records' find and its two link reads — and at the one write is
/// `Refusal::SessionEnded`, nothing asked past it, its face naming the
/// session's end and saying to run this again: nothing was restored.
#[test]
fn a_death_at_any_read_or_at_the_write_is_the_typed_session_end() {
    let ended = |answer: &Result<(), Refusal>| matches!(answer, Err(Refusal::SessionEnded(Halt::Halt(face))) if face.state.starts_with("the session ended while") && face.act == OnEnd::Rerun.act());
    let reads = scripted();
    past(&fake::board(&reads), &token(), ACCOUNT, &a(S), 12).expect("the past read");
    assert_eq!(reads.log().len(), 6, "the premise: six reads");
    for n in 1..=6 {
        let fake = dying_at(n);
        let answer = past(&fake::board(&fake), &token(), ACCOUNT, &a(S), 12).map(drop);
        assert!(ended(&answer), "the death at read {n}, {}: {answer:?}", fake.log()[n - 1]);
        assert_eq!(fake.log().len(), n, "nothing asked past it");
    }
    let fake = dying_at(7);
    let board = fake::board(&fake);
    let p = past(&board, &token(), ACCOUNT, &a(S), 12).expect("the past read");
    let answer = restore(&board, &token(), &p).map(drop);
    assert!(ended(&answer), "the death at the write: {answer:?}");
    assert_eq!(fake.log().last().map(String::as_str), Some("POST /op set_arrangement"));
}
