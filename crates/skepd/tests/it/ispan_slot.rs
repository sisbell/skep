//! THE READ CHECK of the I-span slot form (the link-sets ruling W6 (a) —
//! "a, and include the read check"; the wire-lane record §4 and §7): writing
//! a link whose end is I-SPANS the writer cannot read REVEALS NOTHING of
//! them — no answer, refusal, timing or stored byte tells the writer about
//! the content at those positions or their residence. The argument is the
//! address form's — "an address is not secret and needs no read to write"
//! — carried over to a run of addresses, and it holds channel by channel
//! because the form is built as §3.2 states: no registration or occupancy
//! check of the spans' document, every validation arithmetic on the
//! request's own bytes, and nothing consulted or resolved for a `Spans`
//! slot by the door or the entry composer.
//!
//! THE BOARD: `spawn` (claimed), the writer W the claimant — its SIGNED
//! session for its published doc 1, its BARE session for its private draft
//! `D`. The documents X whose positions W names (the record's four cases):
//! (i) a stranger's PRIVATE draft, its first positions occupied by the
//! stranger's text; (ii) a ghost run past that draft's frontier; (iii) a
//! document no one registered, under an account no one delegated; (iv) W's
//! own draft `D`. For each X, W writes one `make_link` and one `edit_link`
//! successor in the I-span form into `D` (bare) and into doc 1 (signed, the
//! `attest` composed here from the request's spans alone, as the daemon's
//! composer composes it), and the suite asserts:
//!
//! * the acks are byte-identical across (i)–(iv) save the acked address and
//!   position — the two values the write mints;
//! * `read_link` and `follow_link` of the written link answer the spans AS
//!   GIVEN, a function of the request alone — the same bytes across the
//!   four once each case's own start is put back;
//! * the same malformed shapes answer the same refusal bytes across the
//!   four — the content clause (`not_content_subspace` by slot and index),
//!   the zero width and the cap (unparseable) — so no refusal turns on what
//!   X holds;
//! * a read W then makes of X — `project` of its own link into X,
//!   `retrieve_i` over the span, `image` of X — answers `withheld` naming X
//!   for (i) and (ii) exactly as any read of X does, `doc_not_registered`
//!   for (iii), and the link changes neither.
//!
//! The COUNTING cell — the store's `Spans` path reads nothing, measured in
//! heap bytes against the bare copy of the request's spans, in the
//! home-index suites' allocation-counting form — lives beside the store it
//! measures, in `skep-links`' `tests/it/makelink.rs`
//! (`building_an_ispan_slot_costs_exactly_the_endset_it_stores_whatever_the_world_holds`
//! and its whole-write sibling): the daemon runs out of process here, so no
//! allocator of this binary's sees its work. The TIMING cell below compares
//! the four cases' write latencies and REPORTS them, asserting nothing: the
//! one residue the record names is the hint fold's filing of the spans on
//! X's axis, a count of homes already filing there, inside a journaled
//! commit's milliseconds.
//!
//! What the form DOES disclose is the writer's own, outside this check: a
//! public link naming X's I-span tells every reader of the home that X exists
//! and where in X's I-space the end lies — the disclosure the address form
//! already makes (PUB-6.15), by the writer's hand.

use std::time::{Duration, Instant};

use crate::common;

use common::*;
use serde_json::{json, Value};
use skep_address::{validate, Address, Nat, Span, Tumbler};
use skep_identity::{
    entry_body_edit_link, entry_body_make_link, entry_frame, unit_span, DocTerm, EntrySlot,
    LinkSlots, ALG_MLDSA65_ED25519,
};
use skep_signature::HybridSigner;

/// The stranger's text, whose positions W names and cannot read.
const SECRET: &str = "a stranger's private words, never read by the writer";
/// W's own words in its draft `D`.
const OWN: &str = "the writer's own words";
/// The width every I-span of the matrix carries.
const WIDTH: u64 = 3;
/// An account no one delegated: its documents' positions are names no mint
/// issued (case (iii)).
const NOBODYS_DOC: &str = "1.0.77.0.1";

/// The address an I-span starts at: `doc`'s content position `ordinal`.
fn content_pos(doc: &str, ordinal: u64) -> String {
    format!("{doc}.0.1.{ordinal}")
}

/// The I-span form's slot, one span of `WIDTH` positions from `start`.
fn spans_slot(start: &str) -> String {
    spans_slot_with(start, WIDTH)
}

fn spans_slot_with(start: &str, width: u64) -> String {
    format!(r#"{{"spans":[{{"start":"{start}","width":"{width}"}}]}}"#)
}

/// The stored shape of [`spans_slot`]: the span's start and its ordinal
/// width at the start's own depth, as `read_link` serves a slot.
fn stored_span(start: &str, width: u64) -> Value {
    let zeros = "0.".repeat(start.split('.').count() - 1);
    json!({"start": start, "width": format!("{zeros}{width}")})
}

/// A dotted address as the identity crate's `Address`.
fn addr(s: &str) -> Address {
    let t = Tumbler::new(s.split('.').map(|c| Nat::from(c.parse::<u64>().expect("a component"))))
        .expect("nonempty");
    validate(t).expect("a T4-valid address")
}

/// A slot of a frame as the daemon's composer stores it: an `addrs` slot's
/// unit spans, a `spans` slot's spans — each the span of `width` positions
/// from `start`, built by the same arithmetic the codec's parse applies and
/// no address check, so a malformed span composes exactly as the store
/// will hold it ahead of refusing it. `None` for the one shape no span
/// holds, a zero width, which the daemon refuses at the parse ahead of any
/// composition of its own.
fn composed_slot(slot: &Value) -> Option<Vec<Span>> {
    if let Some(spans) = slot.get("spans") {
        spans
            .as_array()
            .expect("spans")
            .iter()
            .map(|s| {
                let start = addr(s["start"].as_str().expect("start")).tumbler().clone();
                let width: u64 = s["width"].as_str().expect("width").parse().expect("a count");
                let zeros = (1..start.len()).map(|_| Nat::from(0u32));
                let width = Tumbler::new(zeros.chain([Nat::from(width)])).expect("nonempty");
                Span::new(start, width).ok()
            })
            .collect()
    } else {
        Some(
            slot["addrs"]
                .as_array()
                .expect("addrs")
                .iter()
                .map(|a| unit_span(&addr(a.as_str().expect("an address"))))
                .collect(),
        )
    }
}

/// `frame` with its `attest` composed and signed by `token`'s key — the
/// test signer's seed — over the request's own members: the slot rows from
/// the slots AS GIVEN (an I-span slot resolves nothing), the home, the board
/// term. The harness's own composer resolves V-spec slots through `image`
/// and knows no `spans` slot, so this suite composes the frame itself, which
/// is also the point: a client signs an I-span slot with no read of the
/// document it names. A frame no slot row composes for — a zero width — is
/// sent as written: the daemon refuses it at the parse, ahead of the check.
fn attested(port: u16, token: &str, frame: &str) -> String {
    let (principal, seed) = signer_of(token).expect("a session the test signer keys");
    let mut v: Value = serde_json::from_str(frame).expect("a JSON frame");
    let board = board_term(port).expect("H.1 stands on a claimed board");
    let account = addr(&account_of(port, token, principal).expect("the signer's account"));
    let slots = |from: &Value, to: &Value, ty: &Value| -> Option<(Vec<Span>, Vec<Span>, Vec<Span>)> {
        Some((composed_slot(from)?, composed_slot(to)?, composed_slot(ty)?))
    };
    let bytes = match v["op"].as_str() {
        Some("make_link") => {
            let Some((from, to, ty)) = slots(&v["from"], &v["to"], &v["ty"]) else {
                return frame.to_string();
            };
            let body = entry_body_make_link(LinkSlots {
                from: EntrySlot(&from),
                to: EntrySlot(&to),
                ty: EntrySlot(&ty),
            });
            let home = addr(v["home"].as_str().expect("home"));
            entry_frame(ALG_MLDSA65_ED25519, board, &account, DocTerm::One(&home), &body)
        }
        Some("edit_link") => {
            let successor = &v["successor"];
            let Some((from, to, ty)) = slots(&successor["from"], &successor["to"], &successor["ty"])
            else {
                return frame.to_string();
            };
            let body = entry_body_edit_link(
                LinkSlots { from: EntrySlot(&from), to: EntrySlot(&to), ty: EntrySlot(&ty) },
                &unit_span(&addr(v["original"].as_str().expect("original"))),
            );
            let (d_s, d_a) =
                (addr(v["d_s"].as_str().expect("d_s")), addr(v["d_a"].as_str().expect("d_a")));
            entry_frame(ALG_MLDSA65_ED25519, board, &account, DocTerm::Pair { d_s: &d_s, d_a: &d_a }, &body)
        }
        other => panic!("no entry frame for {other:?}"),
    };
    let signer = HybridSigner::from_seed(FIXTURE_TAG, &seed).expect("tag 1");
    v["attest"] = attest_member(&signer.sign(&bytes));
    v.to_string()
}

/// One write as this suite sends it: a bare session's frame as written, a
/// signed session's with its `attest` composed here. The raw reply bytes.
fn post(port: u16, token: &str, frame: &str) -> Vec<u8> {
    let frame = if signer_of(token).is_some() { attested(port, token, frame) } else { frame.to_string() };
    let (st, body) = http(port, "POST", "/op", Some(token), frame.as_bytes());
    assert_eq!(st, 200, "op transport failed: {}", String::from_utf8_lossy(&body));
    body
}

/// A reply with the members the write mints removed: what must be
/// byte-identical across the four cases.
fn save_minted(body: &[u8]) -> Value {
    let mut v = json(body);
    if let Some(m) = v.as_object_mut() {
        for minted in ["addr", "at", "successor", "claim"] {
            m.remove(minted);
        }
    }
    v
}

/// A rejection with its `op` removed: the bytes two reads of one document
/// share.
fn save_op(body: &[u8]) -> Value {
    let mut v = json(body);
    if let Some(m) = v.as_object_mut() {
        m.remove("op");
    }
    v
}

/// The four documents, as the record's cases name them.
struct Cases {
    /// (i) the stranger's private draft, its first positions occupied.
    stranger_draft: String,
    /// The stranger's own session, which reads what W cannot.
    stranger_session: String,
    /// The I-span starts, in case order: (i) occupied, (ii) past the
    /// frontier, (iii) unregistered, (iv) W's own.
    starts: [String; 4],
    /// Each case's document, for the reads W then makes.
    docs: [String; 4],
}

const LABELS: [&str; 4] = [
    "(i) a stranger's private draft, occupied positions",
    "(ii) a ghost past that draft's frontier",
    "(iii) a document no one registered",
    "(iv) the writer's own draft",
];

/// The board: W's draft `D`, the stranger's draft X with its text, the four
/// starts.
fn cases(port: u16, bare: &str) -> (String, Cases) {
    let d = draft_with(port, bare, OWN);
    let stranger = seat_stranger(port, 977);
    let x = create_doc(port, &stranger.session, &stranger.account);
    expect_resp(&insert_text(port, &stranger.session, &x, 1, SECRET), "ack_addr");
    assert_eq!(text_of(port, Some(&stranger.session), &x, 1, SECRET.len() as u64), SECRET);
    assert_withheld(&op(port, Some(bare), &image_frame(&x, 1, 1)), &x);
    let frontier = SECRET.len() as u64 + 1;
    let starts = [
        content_pos(&x, 1),
        content_pos(&x, frontier + 4),
        content_pos(NOBODYS_DOC, 1),
        content_pos(&d, 1),
    ];
    let docs = [x.clone(), x.clone(), NOBODYS_DOC.to_string(), d.clone()];
    (d, Cases { stranger_draft: x, stranger_session: stranger.session, starts, docs })
}

/// The feed rows since `since` that a client wrote — the head writer's own
/// `system` rows left out, since a refused write takes the head writer's
/// turn and may land a head record of the board's own.
fn client_rows_since(port: u16, token: &str, since: u64) -> Vec<Value> {
    let (st, body) = http(port, "GET", &format!("/changes?since={since}"), Some(token), b"");
    assert_eq!(st, 200, "/changes: {}", String::from_utf8_lossy(&body));
    json(&body)["changes"]
        .as_array()
        .expect("changes")
        .iter()
        .filter(|row| row["key"].as_str() != Some("system"))
        .cloned()
        .collect()
}

/// THE ACKS AND THE STORED LINK, channel by channel, into W's draft and
/// into W's published home: a `make_link` and an `edit_link` successor in
/// the I-span form over each of the four cases answer byte-identical acks
/// save the minted address and position; `read_link` and `follow_link`
/// serve the spans as given; and the written link changes no read of X —
/// `project` into X, `retrieve_i` over the span and `image` of X answer the
/// same `withheld` naming X ((i), (ii)) or `doc_not_registered` ((iii)) that
/// any read of X answers, and (iv), W's own, answers.
#[test]
fn an_ispan_end_over_positions_the_writer_cannot_read_answers_as_over_its_own() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let bare = open_session(port, CLAIMANT_PRINCIPAL);
    let (d, cases) = cases(port, &bare);

    for (home, token, label) in [(d.as_str(), bare.as_str(), "the draft"), (CLAIMANT_DOC1, signed.as_str(), "the published home")] {
        let mut make_acks = Vec::new();
        let mut edit_acks = Vec::new();
        let mut links = Vec::new();
        for (k, start) in cases.starts.iter().enumerate() {
            // The make_link: the I-span FROM, an empty TO, a ghost type.
            let frame = link_frame(home, &spans_slot(start), r#"{"addrs":[]}"#, &ghost_ty(home, 10 + k as u64));
            let body = post(port, token, &frame);
            let v = json(&body);
            let link = acked_addr(&v);
            make_acks.push(save_minted(&body));
            // The stored link, as given — slots, then the coverage.
            let value = read_link(port, Some(token), &link);
            assert_eq!(
                value["slots"],
                json!([[stored_span(start, WIDTH)], [], [stored_span(&format!("{home}.0.3.6.{}", 10 + k), 1)]]),
                "{label} {}: read_link answers the spans as given",
                LABELS[k]
            );
            let follow = op(port, Some(token), &format!(r#"{{"op":"follow_link","a":"{link}","slot":1}}"#));
            assert_eq!(
                expect_resp(&follow, "follow")["result"]["ok"],
                json!([stored_span(start, WIDTH)]),
                "{label} {}: follow_link answers the coverage as given",
                LABELS[k]
            );
            // The edit_link: the successor's FROM the same I-span, its TO
            // an empty I-span slot.
            let edit = format!(
                r#"{{"op":"edit_link","original":"{link}","d_s":"{home}","d_a":"{home}","successor":{{"from":{},"to":{{"spans":[]}},"ty":{}}}}}"#,
                spans_slot(start),
                ghost_ty(home, 20 + k as u64)
            );
            let body = post(port, token, &edit);
            let v = json(&body);
            let successor = expect_resp(&v, "ack_edit")["successor"].as_str().expect("successor").to_string();
            edit_acks.push(save_minted(&body));
            assert_eq!(
                read_link(port, Some(token), &successor)["slots"][0],
                json!([stored_span(start, WIDTH)]),
                "{label} {}: the successor's I-span end as given",
                LABELS[k]
            );
            links.push(link);
        }
        for k in 1..4 {
            assert_eq!(make_acks[k], make_acks[0], "{label}: the make_link acks differ between {} and {}", LABELS[0], LABELS[k]);
            assert_eq!(edit_acks[k], edit_acks[0], "{label}: the edit_link acks differ between {} and {}", LABELS[0], LABELS[k]);
        }
        assert_eq!(make_acks[0], json!({"resp": "ack_addr"}), "an ack is the address and the position, nothing else");
        assert_eq!(edit_acks[0], json!({"resp": "ack_edit"}));

        // The reads W then makes of X: its own link projected into X, the
        // span by identity, X's image — one answer per X, the link changing
        // none of it.
        for (k, (link, x)) in links.iter().zip(&cases.docs).enumerate() {
            let project = format!(r#"{{"op":"project","a":"{link}","slot":1,"d":"{x}"}}"#);
            let retrieve = format!(r#"{{"op":"retrieve_i","spans":[{{"start":"{}","width":"{WIDTH}"}}]}}"#, cases.starts[k]);
            let image = image_frame(x, 1, 1);
            let answers: Vec<Vec<u8>> = [project, retrieve, image]
                .iter()
                .map(|f| http(port, "POST", "/op", Some(token), f.as_bytes()).1)
                .collect();
            match k {
                0 | 1 => {
                    assert_withheld(&json(&answers[0]), x);
                    for a in &answers[1..] {
                        assert_eq!(save_op(a), save_op(&answers[0]), "{label} {}: every read of X is one withheld", LABELS[k]);
                    }
                }
                2 => {
                    // Registration is public (§The read predicate): the two
                    // document reads answer the store's own
                    // `doc_not_registered`, and the read by identity delivers
                    // `null` at positions no one minted — exactly what they
                    // answer with no link written.
                    for a in [&answers[0], &answers[2]] {
                        let v = json(a);
                        assert_eq!(expect_resp(&v, "rejected")["code"].as_str(), Some("doc_not_registered"), "{label} {}: {v}", LABELS[k]);
                    }
                    let delivery = json(&answers[1]);
                    let items = expect_resp(&delivery, "i_delivery")["items"].as_array().expect("items").clone();
                    assert_eq!(items.len(), WIDTH as usize, "{label} {}: {delivery}", LABELS[k]);
                    assert!(items.iter().all(|i| i["value"].is_null()), "{label} {}: nothing minted, nothing delivered: {delivery}", LABELS[k]);
                }
                _ => {
                    let v = json(&answers[0]);
                    assert_eq!(v["resp"].as_str(), Some("span_set"), "{label} {}: W's own document projects: {v}", LABELS[k]);
                    let v = json(&answers[1]);
                    assert_eq!(v["resp"].as_str(), Some("i_delivery"), "{label} {}: {v}", LABELS[k]);
                    assert_eq!(json(&answers[2])["resp"].as_str(), Some("runs"));
                }
            }
        }
    }
    // The stranger's text stands untouched by every write above, readable to
    // the stranger and still withheld from W: the links named positions and
    // moved nothing.
    let x = &cases.stranger_draft;
    assert_eq!(text_of(port, Some(&cases.stranger_session), x, 1, SECRET.len() as u64), SECRET);
    assert_withheld(&op(port, Some(&bare), &image_frame(x, 1, 1)), x);
    assert_withheld(&op(port, Some(&signed), &image_frame(x, 1, 1)), x);
    sd.shutdown();
}

/// THE REFUSALS: the same malformed I-span shapes answer the same bytes over
/// each of the four documents — the content clause by slot and index
/// (`not_content_subspace`: a start at the document's own address, at its
/// account, in its link subspace), the zero width and the list past the cap
/// (unparseable, `malformed`) — into the draft and into the published home
/// alike; and the credential route refuses an I-span `from` on a
/// credential-typed deposit `resolved_from` as it refuses a V-spec one.
/// Nothing commits.
#[test]
fn a_malformed_ispan_answers_the_same_bytes_whatever_document_it_names() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let bare = open_session(port, CLAIMANT_PRINCIPAL);
    let (d, cases) = cases(port, &bare);
    let before = head_position(port);

    // Per case, the malformed shapes: each a function of X's address, so
    // the bytes are compared after X is put back as a placeholder.
    let shapes = |doc: &str, start: &str| -> Vec<(&'static str, String)> {
        vec![
            ("a start at the document's own address", spans_slot(doc)),
            ("a start at the account", spans_slot(&doc.rsplit_once(".0.").map(|(a, _)| a.to_string()).expect("an account"))),
            ("a start in the link subspace", spans_slot(&format!("{doc}.0.2.1"))),
            ("a zero width", spans_slot_with(start, 0)),
            ("a list past the cap", format!(r#"{{"spans":[{}]}}"#, vec![format!(r#"{{"start":"{start}","width":"1"}}"#); 4097].join(","))),
        ]
    };
    for (home, token, label) in [(d.as_str(), bare.as_str(), "the draft"), (CLAIMANT_DOC1, signed.as_str(), "the published home")] {
        let mut per_case: Vec<Vec<(&str, Value)>> = Vec::new();
        for (k, (start, doc)) in cases.starts.iter().zip(&cases.docs).enumerate() {
            let mut answers = Vec::new();
            for (what, slot) in shapes(doc, start) {
                // In the FROM slot of a make_link, and in the TO slot of an
                // edit_link's successor: `site.slot` names each.
                let make = link_frame(home, &slot, r#"{"addrs":[]}"#, &ghost_ty(home, 1));
                let v = json(&post(port, token, &make));
                let rej = expect_resp(&v, "rejected");
                match what {
                    "a zero width" | "a list past the cap" => {
                        assert_eq!(rej["code"].as_str(), Some("malformed"), "{label} {} {what}: {v}", LABELS[k]);
                    }
                    _ => {
                        assert_eq!(rej["code"].as_str(), Some("not_content_subspace"), "{label} {} {what}: {v}", LABELS[k]);
                        assert_eq!(rej["disposition"].as_str(), Some("permanent"), "{v}");
                        assert_eq!((rej["site"]["slot"].as_u64(), rej["site"]["index"].as_u64()), (Some(1), Some(0)), "the FROM slot, its first span: {v}");
                    }
                }
                answers.push((what, v));
            }
            per_case.push(answers);
        }
        for k in 1..4 {
            assert_eq!(per_case[k], per_case[0], "{label}: the refusals differ between {} and {}", LABELS[0], LABELS[k]);
        }
        // The successor's slot is named too: the TO slot's second span.
        let original = acked_addr(&json(&post(port, token, &link_frame(home, r#"{"addrs":[]}"#, r#"{"addrs":[]}"#, &ghost_ty(home, 2)))));
        let mut successor_answers = Vec::new();
        for (k, start) in cases.starts.iter().enumerate() {
            let edit = format!(
                r#"{{"op":"edit_link","original":"{original}","d_s":"{home}","d_a":"{home}","successor":{{"from":{{"spans":[]}},"to":{{"spans":[{{"start":"{start}","width":"1"}},{{"start":"{}","width":"1"}}]}},"ty":{}}}}}"#,
                cases.docs[k],
                ghost_ty(home, 3)
            );
            let v = json(&post(port, token, &edit));
            let rej = expect_resp(&v, "rejected");
            assert_eq!(rej["code"].as_str(), Some("not_content_subspace"), "{label} {}: {v}", LABELS[k]);
            assert_eq!((rej["site"]["slot"].as_u64(), rej["site"]["index"].as_u64()), (Some(2), Some(1)), "the TO slot, its second span: {v}");
            successor_answers.push(v);
        }
        for k in 1..4 {
            assert_eq!(successor_answers[k], successor_answers[0], "{label}: the successor's refusals differ between {} and {}", LABELS[0], LABELS[k]);
        }
    }
    // Only the two originals landed: the client's rows since `before` are
    // their two `make_link`s and nothing else — a refusal commits nothing,
    // whatever the head writer lands on the turns the refusals hand it.
    let rows = client_rows_since(port, &signed, before);
    assert_eq!(
        rows.iter().map(|r| r["op"].as_str().unwrap_or("?")).collect::<Vec<_>>(),
        ["make_link", "make_link"],
        "every refusal commits nothing: {rows:?}"
    );

    // The credential route: an I-span `from` on a credential-typed deposit
    // is `resolved_from`, as a V-spec `from` is — the form never reaches the
    // record grade. `signed_atom`'s own deposit shape is the control the
    // credential suites hold; here the slot form alone changes.
    for start in &cases.starts {
        let frame = link_frame(CLAIMANT_DOC1, &spans_slot(start), &addrs_slot(&[CLAIMANT_ACCOUNT]), &addrs_slot(&[T_ENROLL]));
        let v = op_as_written(port, Some(&signed), &frame);
        assert_eq!(verdict(&v), "credential_refused:resolved_from", "{v}");
    }
    sd.shutdown();
}

/// THE TIMING CELL (the record's §4 (4), UNVERIFIED 4): the latency of a
/// `make_link` in the I-span form into W's draft, compared across the four
/// documents the spans name. REPORTED, never asserted: the record names
/// one residue — the hint fold's filing of the spans on X's content axis,
/// a count of homes already filing in that block, the class PUB-7.18
/// accepts at reads — and it sits inside a journaled commit's fsync. The
/// figures are printed per case as median and 95th percentile over
/// `ROUNDS` writes each, interleaved across the cases so a drift of the
/// board touches each alike.
#[test]
#[ignore = "timing test - gate-full only"]
fn the_latency_of_an_ispan_write_is_reported_across_the_four_documents() {
    const ROUNDS: usize = 24;
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let bare = open_session(port, CLAIMANT_PRINCIPAL);
    let (d, cases) = cases(port, &bare);
    let mut samples: [Vec<Duration>; 4] = Default::default();
    for round in 0..ROUNDS {
        for (k, start) in cases.starts.iter().enumerate() {
            let frame = link_frame(&d, &spans_slot(start), r#"{"addrs":[]}"#, &ghost_ty(&d, 100 + (round * 4 + k) as u64));
            let began = Instant::now();
            let body = post(port, &bare, &frame);
            let took = began.elapsed();
            acked_addr(&json(&body));
            samples[k].push(took);
        }
    }
    for (k, label) in LABELS.iter().enumerate() {
        let mut s = samples[k].clone();
        s.sort();
        let median = s[s.len() / 2];
        let p95 = s[(s.len() * 95 / 100).min(s.len() - 1)];
        println!(
            "ispan_slot timing: {label}: median {:.3} ms, p95 {:.3} ms over {} writes",
            median.as_secs_f64() * 1e3,
            p95.as_secs_f64() * 1e3,
            s.len()
        );
    }
    sd.shutdown();
}
