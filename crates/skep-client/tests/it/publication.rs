//! THE PUBLICATION COMPOSITION against the real daemon (the link-sets design
//! §5.1–§5.8; the client lane's brief 1): a claimed permissive board seeded
//! as `merge.rs` seeds one — `E` a published edition with its first version,
//! `D` a staging draft arranging `E`'s words by reference, ten new words of
//! its own and a window onto `O`, the person's own unpublished origin; links
//! in THREE homes of the person's on the selection's words (the draft's own
//! set, the notes `N`, the public set `S`), one in a second public set `S2`,
//! one of a sub-account's on the same words, a whole-work link in `N` on
//! the draft `D` itself — the address form FROM `D`, one unit subtree span
//! at its address, TO a span of `Z` — a held removal of a published mark, a
//! read-with standing between `E` and `S`.
//!
//! THE FIRST GATE: the composition's enumeration over the whole draft EQUALS
//! the daemon's own filter — skepd's `accept_originals.rs` `offered`, ported
//! here over raw frames — the same addresses in the same grouping by home,
//! the whole-work link on `D` in neither side's list (the stored-endset
//! test, the design's §5.1, applied by both); a red here is a library red.
//! Then the panel's rows and the count, the
//! price, the re-read, THE ONE REQUEST's bytes against the daemon's
//! acceptance — the acknowledgment with the member, the copies present in
//! each home, the claim in the original's home, the read-with written, the
//! retraction standing, the kept place re-windowing the draft — the cut
//! connection with the records read after it, `already_published` on a
//! re-send read as the acknowledgment, `kept_place_moved` after a move
//! with its re-statement, and a second publication off the member the first
//! made, offering nothing the first accepted on the words it re-minted —
//! nor where the draft shows those words as its own again.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write as _;

use serde_json::{json, Value};
use skep_address::{Address, Nat, Span, Tumbler};
use skep_client::address::{document_of, parse_address};
use skep_client::board::frames::{self, T_HELD_REMOVAL, T_READ_WITH};
use skep_client::board::{acked_addr, Answer, Board, ChangesAnswer, ChangesQuery, Scope, Token, T_RETRACTION};
use skep_client::ceremony::handshake::{handshake, Session, Site};
use skep_client::publication::{self, build, count, enumerate, landed, panel, reread, send, AckVia, AlsoPlaces, Base, Built, Confirmed, Destination, Inputs, OriginAnswer, PartKey, Publisher, Refusal, RowKind, Run, Sent, Switches, Verdict};
use skep_client::sign::{sig_hex, Signer};
use skep_identity::{entry_body_empty, entry_body_make_link, entry_body_publish, entry_frame, unit_span, ContentFreeOp, DocTerm, EntryBody, EntrySlot, LinkSlots, ShotSegmentPiece};
use skep_signature::HybridSigner;

use crate::common::{bare, board, claim, insert_text, keygen, mint, spawn, wire_delegate, wire_session};

const ACCOUNT: &str = "1.0.1";
const PRINCIPAL: u64 = 1;
/// A sub-account delegated under the claimant's, whose link on the same
/// words is never the person's.
const SUB_ACCOUNT: &str = "1.0.1.2";
const SUB: u64 = 2;
const T_STRONG: &str = "1.1.0.1.0.1.0.3.23.2";
const T_HEADING: &str = "1.1.0.1.0.1.0.3.20";
const T_CITATION: &str = "1.1.0.1.0.1.0.3.13";
const T_MARK: &str = "1.1.0.1.0.1.0.3.23.4";
const P: &str = "the quick brown fox";
const W: &str = " new words";
const Q: &str = "quote";

fn addr(text: &str) -> Address {
    parse_address(text).expect("an address")
}

fn run(doc: &str, s: u64, w: u64) -> Run {
    Run::new(addr(doc), s, w)
}

/// A content I-span of `doc`'s chain, `w` wide from ordinal `s`.
fn content_span(doc: &str, s: u64, w: u64) -> Span {
    let comps: Vec<Nat> = doc.split('.').map(|c| Nat::from(c.parse::<u64>().unwrap())).chain([Nat::from(0u32), Nat::from(1u32), Nat::from(s)]).collect();
    let depth = comps.len();
    let start = Tumbler::new(comps).unwrap();
    let width = Tumbler::new(std::iter::repeat_n(Nat::from(0u32), depth - 1).chain([Nat::from(w)])).unwrap();
    Span::new(start, width).unwrap()
}

/// The `attest` member over `body` for a write whose `doc` row is `doc`.
fn attest(board: &Board, signer: &HybridSigner, doc: &Address, body: &EntryBody) -> Value {
    let term = board.board_term().expect("the term").expect("H.1 stands");
    let alg = Signer::public_key(signer).alg();
    let frame = entry_frame(alg, term, &addr(ACCOUNT), DocTerm::One(doc), body);
    json!({"alg": alg, "sig": sig_hex(&Signer::sign(signer, &frame))})
}

fn acked(answer: Result<Answer, skep_client::Halt>) -> Value {
    match answer.expect("the exchange") {
        Answer::Document(v) => {
            assert!(matches!(v["resp"].as_str(), Some("ack" | "ack_addr")), "the board refused: {v}");
            v
        }
        Answer::Closed => panic!("the session was closed"),
    }
}

fn read(board: &Board, token: &Token, frame: &Value) -> Value {
    let Answer::Document(v) = board.op(Some(token), frame).expect("the read") else { panic!("closed") };
    assert_ne!(v["resp"].as_str(), Some("rejected"), "{v}");
    v
}

fn image(board: &Board, token: &Token, doc: &str, from: u64, width: u64) -> Vec<(String, u64)> {
    let v = read(board, token, &frames::image(doc, from, width));
    v["runs"].as_array().unwrap().iter().map(|r| (r["i_start"].as_str().unwrap().to_string(), r["width"].as_str().unwrap().parse().unwrap())).collect()
}

fn published_document(board: &Board, session: &Session<'_>, signer: &HybridSigner) -> String {
    let account = addr(ACCOUNT);
    let mut frame = json!({"op": "create_new_document", "account": ACCOUNT, "published": true});
    frame["attest"] = attest(board, signer, &account, &entry_body_empty(ContentFreeOp::CreateNewDocument));
    acked_addr(&acked(session.op(&frame))).expect("a minted address").to_string()
}

/// One end of a `make_link`: the address form, or a V-spec over `doc`'s
/// positions with the stored span the signer composes for it.
enum End<'a> {
    Addrs(Vec<&'a str>),
    Spec { doc: &'a str, from: u64, width: u64, stored: Span },
}

impl End<'_> {
    fn wire(&self) -> Value {
        match self {
            End::Addrs(list) => json!({"addrs": list}),
            End::Spec { doc, from, width, .. } => json!([{"source": doc, "span": {"start": format!("1.{from}"), "width": format!("0.{width}")}}]),
        }
    }

    fn spans(&self) -> Vec<Span> {
        match self {
            End::Addrs(list) => list.iter().map(|a| unit_span(&addr(a))).collect(),
            End::Spec { stored, .. } => vec![stored.clone()],
        }
    }
}

/// A V-spec end over `doc`'s positions `from ..`, whose stored span is
/// `chain`'s I-span `first ..` — the identity the positions resolve to.
fn spec<'a>(doc: &'a str, from: u64, width: u64, chain: &str, first: u64) -> End<'a> {
    End::Spec { doc, from, width, stored: content_span(chain, first, width) }
}

/// A link homed in `home`, signed where the home is published.
#[allow(clippy::too_many_arguments)] // the fixture's one link maker: the board, the two sessions, the hand, the home and its slots
fn make_link(board: &Board, session: &Session<'_>, bare_token: &Token, signer: &HybridSigner, home: &str, published: bool, from: End<'_>, to: End<'_>, ty: &str) -> String {
    let mut frame = json!({"op": "make_link", "home": home, "from": from.wire(), "to": to.wire(), "ty": {"addrs": [ty]}});
    if published {
        let (from_spans, to_spans, ty_spans) = (from.spans(), to.spans(), vec![unit_span(&addr(ty))]);
        let body = entry_body_make_link(LinkSlots { from: EntrySlot(&from_spans), to: EntrySlot(&to_spans), ty: EntrySlot(&ty_spans) });
        frame["attest"] = attest(board, signer, &addr(home), &body);
        acked_addr(&acked(session.op(&frame))).expect("the link").to_string()
    } else {
        acked_addr(&acked(board.op(Some(bare_token), &frame))).expect("the link").to_string()
    }
}

/// THE FIRST SHOT of `doc`: a staging draft holding `text`, re-inserted as
/// the birth version, attested.
fn first_shot(board: &Board, session: &Session<'_>, signer: &HybridSigner, bare_token: &Token, doc: &str, text: &str) -> String {
    let d = mint(board, bare_token, ACCOUNT, false);
    insert_text(board, bare_token, &d, 1, text);
    let im = image(board, bare_token, &d, 1, text.len() as u64);
    assert_eq!(im.len(), 1);
    let runs = [frames::shot_run(&d, &im[0].0, im[0].1)];
    let pieces: Vec<[u8; 1]> = text.bytes().map(|b| [b]).collect();
    let body = entry_body_publish(pieces.iter().map(|b| ShotSegmentPiece::Value(b)), None);
    let mut frame = frames::publication(&frames::PublishFrame { doc: Some(doc), draft: Some(&d), runs: &runs, ..frames::PublishFrame::default() });
    frame["attest"] = attest(board, signer, &addr(doc), &body);
    acked_addr(&acked(session.op(&frame))).expect("the member").to_string()
}

/// `copy` of `source`'s positions `from ..` into `doc` at `at`: a window.
fn copy(board: &Board, token: &Token, doc: &str, at: u64, source: &str, from: u64, width: u64) {
    let as_of = crate::common::typed_at(board, token, doc);
    let frame = json!({"op": "copy", "doc": doc, "at": {"subspace": "1", "ordinal": at.to_string()}, "specs": [{"source": source, "span": {"start": format!("1.{from}"), "width": format!("0.{width}")}}], "as_of": as_of});
    acked(board.op(Some(token), &frame));
}

/// The seeded board.
struct Seeded {
    e: String,
    e1: String,
    s: String,
    s2: String,
    d: String,
    n: String,
    o: String,
    z: String,
    mark_d: String,
    heading_d: String,
    cite_d: String,
    l1_n: String,
    whole_n: String,
    k_s: String,
    k2_s2: String,
    mpub: String,
    held: String,
    orig_d: String,
    sub_link: String,
}

/// Seeds the fixture (the module doc).
fn seed(board: &Board, session: &Session<'_>, signer: &HybridSigner, bare_token: &Token, anchors: &std::path::Path) -> Seeded {
    let e = published_document(board, session, signer);
    let e1 = first_shot(board, session, signer, bare_token, &e, P);
    assert_eq!(e1, format!("{e}.1"));
    assert_eq!(image(board, bare_token, &e1, 1, 19), vec![(format!("{e}.0.1.1"), 19)], "E's one identity");
    let s = published_document(board, session, signer);
    let s2 = published_document(board, session, signer);
    let n = mint(board, bare_token, ACCOUNT, false);
    insert_text(board, bare_token, &n, 1, "notes here");
    let z = mint(board, bare_token, ACCOUNT, false);
    insert_text(board, bare_token, &z, 1, "zed");
    let o = mint(board, bare_token, ACCOUNT, false);
    insert_text(board, bare_token, &o, 1, Q);
    let d = mint(board, bare_token, ACCOUNT, false);
    copy(board, bare_token, &d, 1, &e1, 1, 19);
    insert_text(board, bare_token, &d, 20, W);
    copy(board, bare_token, &d, 30, &o, 1, 5);
    assert_eq!(image(board, bare_token, &d, 1, 34), vec![(format!("{e}.0.1.1"), 19), (format!("{d}.0.1.1"), 10), (format!("{o}.0.1.1"), 5)], "the draft: kept words, new words, the window");
    // The draft's own set: a bold on the new words, a heading over them, a
    // citation from the new words to Z.
    let mark_d = make_link(board, session, bare_token, signer, &d, false, End::Addrs(vec![]), spec(&d, 21, 3, &d, 2), T_STRONG);
    let heading_d = make_link(board, session, bare_token, signer, &d, false, End::Addrs(vec![]), spec(&d, 20, 10, &d, 1), T_HEADING);
    let cite_d = make_link(board, session, bare_token, signer, &d, false, spec(&d, 25, 5, &d, 6), spec(&z, 1, 3, &z, 1), T_CITATION);
    // The notes: a citation from E's kept words to the note, and THE
    // WHOLE-WORK LINK on the draft itself — the address form FROM `D`, one
    // unit subtree span at its address, TO a span of Z — the corner's link
    // (the link-sets design §5.1), which no publication offers.
    let l1_n = make_link(board, session, bare_token, signer, &n, false, spec(&e1, 5, 5, &e, 5), spec(&n, 1, 5, &n, 1), T_CITATION);
    let whole_n = make_link(board, session, bare_token, signer, &n, false, End::Addrs(vec![&d]), spec(&z, 1, 3, &z, 1), T_CITATION);
    // The public sets: a citation in S, a highlight in S2, and E read with S.
    let k_s = make_link(board, session, bare_token, signer, &s, true, spec(&e1, 1, 3, &e, 1), End::Addrs(vec![]), T_CITATION);
    let k2_s2 = make_link(board, session, bare_token, signer, &s2, true, spec(&e1, 1, 3, &e, 1), End::Addrs(vec![]), T_MARK);
    make_link(board, session, bare_token, signer, &s, true, End::Addrs(vec![&e]), End::Addrs(vec![&s]), T_READ_WITH);
    // The edition's own published mark, and the held removal of it in D;
    // the mark's PRIVATE ORIGINAL in D, of the same shape, claimed onto the
    // mark as an accept claims it — folded under its copy, offered nowhere,
    // and ended with the copy by the rider.
    let mpub = make_link(board, session, bare_token, signer, &e1, true, End::Addrs(vec![]), spec(&e1, 5, 5, &e, 5), T_STRONG);
    let held = make_link(board, session, bare_token, signer, &d, false, End::Addrs(vec![]), End::Addrs(vec![&mpub]), T_HELD_REMOVAL);
    let orig_d = make_link(board, session, bare_token, signer, &d, false, End::Addrs(vec![]), spec(&e1, 5, 5, &e, 5), T_STRONG);
    acked(board.op(Some(bare_token), &frames::assert_sup(&d, &orig_d, &mpub, None, None)));
    // A sub-account's link on the same words: never the person's.
    let as_owner = wire_session(board, PRINCIPAL, signer);
    wire_delegate(board, &as_owner, SUB_ACCOUNT, SUB).expect("delegated");
    board.session_close(&as_owner).unwrap();
    let sub = bare(board, SUB);
    assert_eq!(mint(board, &sub, SUB_ACCOUNT, false), format!("{SUB_ACCOUNT}.0.1"));
    let sub_draft = mint(board, &sub, SUB_ACCOUNT, false);
    let sub_frame = json!({"op": "make_link", "home": sub_draft, "from": spec(&e1, 1, 3, &e, 1).wire(), "to": {"addrs": []}, "ty": {"addrs": [T_CITATION]}});
    let sub_link = acked_addr(&acked(board.op(Some(&sub), &sub_frame))).unwrap().to_string();
    let _ = anchors;
    Seeded { e, e1, s, s2, d, n, o, z, mark_d, heading_d, cite_d, l1_n, whole_n, k_s, k2_s2, mpub, held, orig_d, sub_link }
}

/// THE ORACLE, ported from skepd's `accept_originals.rs`: `find_links_v` over
/// the selection; each address read for its home and kept where the home is
/// a private document of the claimant's; each kept link read once and kept
/// as a candidate only where a stored end touches the selection through a
/// content span — THE STORED-ENDSET TEST (the design's §5.1), in the
/// daemon's suite's words: a whole-work end, a unit subtree span at a
/// document's address, expands to that address alone, never a position the
/// selection holds, so a link reaching the selection through one alone has
/// nothing on it and is no candidate; one `in_claims {y, view: active}`
/// per candidate; each claim's `new` read for its home and its two ends,
/// as the plan's `covers_all` reads a successor; the
/// candidate dropped where some successor is homed in a published document
/// of the claimant's AND covers the candidate's positions on the selection
/// that `base` — the member the request's `base` names, over its positions
/// 1..`base_extent` — does not hold (key (iii) as E4 2.1 re-says it) — the
/// keys as the daemon's suite reads them (its liveness key, struck by
/// sweep 5 S1, left out: nothing here is retracted). Grouped by home, in the
/// order the homes answer.
fn offered_oracle(board: &Board, token: &Token, doc: &str, from: u64, width: u64, base: (&str, u64)) -> Vec<(String, Vec<String>)> {
    let expand = |start: &str, w: u64| -> Vec<String> {
        let (prefix, first) = start.rsplit_once('.').unwrap();
        let first: u64 = first.parse().unwrap();
        (first..first + w).map(|k| format!("{prefix}.{k}")).collect()
    };
    let selection: BTreeSet<String> = image(board, token, doc, from, width).iter().flat_map(|(s, w)| expand(s, *w)).collect();
    let held: BTreeSet<String> = image(board, token, base.0, 1, base.1).iter().flat_map(|(s, w)| expand(s, *w)).collect();
    let slot_addresses = |slot: &Value| -> BTreeSet<String> {
        slot.as_array().unwrap().iter().flat_map(|s| {
            let start = s["start"].as_str().unwrap();
            let w: u64 = s["width"].as_str().unwrap().rsplit('.').next().unwrap().parse().unwrap();
            expand(start, w)
        }).collect()
    };
    let owner_and_state = |d: &str| -> (String, bool) {
        let m = read(board, token, &frames::doc_metadata(d));
        (m["owner"].as_str().unwrap().to_string(), m["published"].as_bool().unwrap())
    };
    let home_of = |link: &str| link[..link.rfind(".0.2.").unwrap()].to_string();
    let links = read(board, token, &frames::find_links_v(doc, &[(from, width)]));
    let mut out: Vec<(String, Vec<String>)> = Vec::new();
    for link in links["addrs"].as_array().unwrap().iter().filter_map(Value::as_str) {
        let home = home_of(link);
        let (owner, published) = owner_and_state(&home);
        if owner != ACCOUNT || published {
            continue;
        }
        let value = read(board, token, &frames::read_link(link));
        let slots = &value["link"]["slots"];
        if slots[2][0]["start"].as_str() == Some(frames::T_CORRESPONDENCE) {
            continue;
        }
        let mut ends = slot_addresses(&slots[0]);
        ends.extend(slot_addresses(&slots[1]));
        let on_selection: BTreeSet<String> = ends.intersection(&selection).cloned().collect();
        // THE STORED-ENDSET TEST: nothing on the selection through a content
        // span, no candidate.
        if on_selection.is_empty() {
            continue;
        }
        let claims = read(board, token, &frames::in_claims(link));
        let dropped = claims["claims"].as_array().unwrap().iter().any(|row| {
            let new = row["new"].as_str().unwrap();
            let (new_owner, new_published) = owner_and_state(&home_of(new));
            let successor = read(board, token, &frames::read_link(new));
            let mut ends = slot_addresses(&successor["link"]["slots"][0]);
            ends.extend(slot_addresses(&successor["link"]["slots"][1]));
            new_owner == ACCOUNT && new_published && !on_selection.is_empty() && on_selection.difference(&held).all(|a| ends.contains(a))
        });
        if dropped {
            continue;
        }
        match out.iter_mut().find(|(h, _)| *h == home) {
            Some((_, links)) => links.push(link.to_string()),
            None => out.push((home, vec![link.to_string()])),
        }
    }
    out
}

fn inputs(seeded: &Seeded) -> Inputs {
    Inputs {
        doc: Some(addr(&seeded.e)),
        mint: None,
        claim: false,
        base: Some((addr(&seeded.e1), 19)),
        draft: addr(&seeded.d),
        also: vec![],
        selection: vec![run(&seeded.e, 1, 19), run(&seeded.d, 1, 10), run(&seeded.o, 1, 5)],
        notes: vec![addr(&seeded.n)],
        readable_drafts: vec![addr(&seeded.d), addr(&seeded.n)],
        published: vec![addr(&seeded.e), addr(&seeded.s), addr(&seeded.s2)],
        supersede: vec![],
        merge_landing: false,
    }
}

/// The switches: the draft's own set into the member, the notes into `S2`;
/// the window onto `O`, one part no record names, kept private.
fn confirmed(seeded: &Seeded) -> Confirmed {
    let mut switches = Switches::default();
    switches.on.insert(addr(&seeded.d));
    switches.on.insert(addr(&seeded.n));
    switches.destinations.insert(addr(&seeded.n), Destination::Set(addr(&seeded.s2)));
    let mut answers = BTreeMap::new();
    answers.insert(PartKey { run: 2, part: 0 }, OriginAnswer::KeepPrivate);
    Confirmed { switches, answers, left_out: BTreeSet::new() }
}

/// Sends one `POST /op` under `token` and DROPS the connection without
/// reading its answer: the frame is on the daemon's socket whole, its client
/// gone (wire.md §Transport: a frame received is applied).
fn send_and_drop(port: u16, token: &Token, frame: &Value) {
    let body = frame.to_string();
    let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect");
    let head = format!("POST /op HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\nContent-Length: {}\r\nSkepd-Session: {}\r\nContent-Type: application/json\r\n\r\n", body.len(), token.as_str());
    stream.write_all(head.as_bytes()).unwrap();
    stream.write_all(body.as_bytes()).unwrap();
    stream.flush().unwrap();
}

/// THE WHOLE COMPOSITION on the daemon: THE FIRST GATE — the enumeration
/// equals the daemon's own filter over the same spans, the sub-account's
/// link dropped off its address — the panel's rows in order with the
/// read-with state and the job list, the count, the price admitting, the
/// re-read finding nothing moved, THE ONE REQUEST acknowledged: the member,
/// the copies in the member and in `S2` (the notes' destination) at the
/// commit's position, the claim in the notes, the held mark retracted, the
/// read-with `E` → `S2` written and `E` → `S` not written twice, the draft
/// re-windowed onto the member's identity at its kept place, the window onto
/// `O` kept by reference; then `already_published` on a re-send under a
/// fresh `id` read as the acknowledgment by the landed test.
#[test]
fn the_composition_enumerates_as_the_daemon_filters_and_its_one_request_lands() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(&dir.path().join("board"), true);
    let board = board(sd.port());
    let store = skep_client::store::FileStore::open(dir.path().join("store"));
    let fp = keygen(&store, "notebook");
    claim(&board, &store, &dir.path().join("anchors"));
    let device = store.load(&store.key_path(&fp)).expect("the device key").signer();
    let session = handshake(&board, Scope::Content, &device, PRINCIPAL, Site::Session).expect("a content session");
    let token = session.token().clone();
    let bare_token = bare(&board, PRINCIPAL);
    let seeded = seed(&board, &session, &device, &bare_token, &dir.path().join("anchors"));
    let Seeded { e, e1, s, s2, d, n, o, .. } = &seeded;
    let p = Publisher { board: &board, token: &token, account: ACCOUNT, signer: &device };
    let inputs = inputs(&seeded);

    // THE FIRST GATE.
    let before = board.health().unwrap().log_position();
    let en = enumerate(&p, &inputs).expect("enumerated");
    let oracle = offered_oracle(&board, &token, d, 1, 34, (e1, 19));
    let by_home = |groups: Vec<(String, Vec<String>)>| -> BTreeMap<String, Vec<String>> { groups.into_iter().collect() };
    let private: Vec<(String, Vec<String>)> = en.offered_by_home().into_iter().filter(|(h, _)| h.to_string() != *s && h.to_string() != *s2).map(|(h, links)| (h.to_string(), links.iter().map(ToString::to_string).collect())).collect();
    // THE STORED-ENDSET TEST, met on the wire: the region read answers the
    // whole-work link on `D` through `D`'s unit span, and NEITHER side offers
    // it — the composition by its test, the oracle by its own.
    let region = read(&board, &token, &frames::find_links_v(d, &[(1, 34)]));
    assert!(region["addrs"].as_array().unwrap().iter().any(|a| a.as_str() == Some(seeded.whole_n.as_str())), "the region read answers the whole-work link on D: {region}");
    let listed = |groups: &[(String, Vec<String>)]| -> Vec<String> { groups.iter().flat_map(|(_, links)| links.iter().cloned()).collect() };
    assert!(!listed(&private).contains(&seeded.whole_n), "the composition offers no whole-work link: {private:?}");
    assert!(!listed(&oracle).contains(&seeded.whole_n), "and neither does the daemon's own filter: {oracle:?}");
    assert_eq!(by_home(private), by_home(oracle.clone()), "the composition's private homes, as the daemon's own filter offers them");
    assert_eq!(by_home(oracle), BTreeMap::from([(d.clone(), vec![seeded.mark_d.clone(), seeded.heading_d.clone(), seeded.cite_d.clone()]), (n.clone(), vec![seeded.l1_n.clone()])]));
    let public: Vec<(String, Vec<String>)> = en.offered_by_home().into_iter().filter(|(h, _)| h.to_string() == *s || h.to_string() == *s2).map(|(h, links)| (h.to_string(), links.iter().map(ToString::to_string).collect())).collect();
    assert_eq!(public, vec![(s.clone(), vec![seeded.k_s.clone()]), (s2.clone(), vec![seeded.k2_s2.clone()])]);
    let all: Vec<String> = en.candidates.iter().map(|c| c.link.to_string()).collect();
    assert!(!all.contains(&seeded.sub_link) && !all.contains(&seeded.held) && !all.contains(&seeded.mpub) && !all.contains(&seeded.whole_n), "{all:?}");
    assert_eq!(en.placed.len(), 3);
    assert_eq!(en.region, vec![(1, 34)]);
    assert_eq!(board.health().unwrap().log_position(), before, "the enumeration writes nothing");
    let frames_sent: usize = en.frames.iter().map(|(_, n)| n).sum();
    assert!(frames_sent >= 10, "{:?}", en.frames);

    // THE PANEL AND THE COUNT.
    let pn = panel(&p, &inputs, &en).expect("the panel");
    let kinds: Vec<(String, RowKind)> = pn.rows.iter().map(|r| (r.home.to_string(), r.kind.clone())).collect();
    assert_eq!(kinds, [(d.clone(), RowKind::Own), (n.clone(), RowKind::Notes), (s.clone(), RowKind::Public { read_with: true }), (s2.clone(), RowKind::Public { read_with: false })]);
    assert_eq!(pn.rows[0].label, format!("{P}{W}{Q}").into_bytes(), "the draft's first line is its arranged text");
    assert_eq!(pn.rows[1].label, b"notes here".to_vec());
    assert_eq!(pn.rows[0].links.iter().map(|i| en.candidates[*i].link.to_string()).collect::<Vec<_>>(), vec![seeded.cite_d.clone()]);
    assert_eq!(pn.rows[0].line.p, 1, "the citation's far end is private");
    assert_eq!(pn.formatting.marks.iter().map(|i| en.candidates[*i].link.to_string()).collect::<Vec<_>>(), vec![seeded.mark_d.clone(), seeded.heading_d.clone()]);
    let jobs: Vec<String> = pn.formatting.job_list().iter().map(|r| r.mark.to_string()).collect();
    assert_eq!(jobs, vec![seeded.mpub.clone()]);
    assert_eq!(pn.read_with, BTreeMap::from([(addr(s), true), (addr(s2), false)]));
    // The one window: the run onto `O`, the person's own unpublished origin,
    // one part no record names (no record of a draft the person reads names
    // its words).
    assert_eq!(en.windows.len(), 1, "{:?}", en.windows);
    let window = &en.windows[0];
    assert_eq!((window.run, window.origin.to_string(), window.owner.as_str(), window.i_start, window.width), (2, o.clone(), ACCOUNT, 1, 5));
    assert_eq!(window.parts.iter().map(|part| (part.span.first, part.span.width, part.ordinal, part.named())).collect::<Vec<_>>(), vec![(1, 5, 30, false)]);
    let c = count(&pn, &confirmed(&seeded).switches, &inputs);
    assert_eq!((c.l, c.n, c.r, c.e, c.claim, c.read_with.clone()), (3, 2, 1, 0, false, vec![addr(s2)]));

    // THE RE-READ, THE REQUEST, THE PRICE.
    let rr = reread(&p, &inputs, &en, &pn).expect("re-read");
    assert_eq!(rr.restatement, None);
    let Built::Request(mut request) = build(&p, &inputs, &rr.enumeration, &rr.panel, &confirmed(&seeded)).expect("built") else { panic!("inert") };
    assert!(request.price.admits(), "{:?}", request.price);
    assert_eq!(request.runs, vec![run(e, 1, 19), run(d, 1, 10), run(o, 1, 5)]);
    assert_eq!(request.places, vec![None, Some(20), None]);
    assert_eq!(request.retract, vec![addr(&seeded.mpub)]);
    assert_eq!(request.originals.iter().map(|o| (o.old.to_string(), o.rest.clone(), o.marks.clone())).collect::<Vec<_>>(), vec![(seeded.orig_d.clone(), vec![], vec![addr(&seeded.mpub)])], "the rider: the held mark's original, found from the copy, every word covered");
    assert_eq!(request.read_with, vec![addr(s2)]);
    assert_eq!(request.entries.len(), 4, "the line's two marks, the citation, the note");
    let frame = request.frame(None);
    assert_eq!(frame["originals"], json!([{"old": seeded.orig_d}]), "the rider on the wire, no rest");
    assert_eq!(frame["links"][0]["to"], json!({"member": [{"ordinal": "21", "width": "3"}]}), "the bold's end in the member-position form, canonical");
    assert_eq!(frame["links"][3]["home"].as_str(), Some(s2.as_str()));
    assert_eq!(frame["links"][3]["from"], json!({"spans": [{"start": format!("{e}.0.1.5"), "width": "5"}]}), "the note's kept-word end by reference, the width a natural");

    // THE CUT CONNECTION FIRST: the frame sent, the connection dropped before
    // the answer, the records read — the publication stands, ONE version,
    // and the same request under the same id answers the memo.
    let term = board.board_term().unwrap().unwrap();
    let alg = Signer::public_key(&device).alg();
    let bytes = entry_frame(alg, term, &addr(ACCOUNT), DocTerm::One(request.term()), &request.body());
    let signed = request.frame(Some(json!({"alg": alg, "sig": sig_hex(&Signer::sign(&device, &bytes))})));
    send_and_drop(sd.port(), &token, &signed);
    std::thread::sleep(std::time::Duration::from_millis(400));
    let verdict = landed(&p, &inputs, &request, Base::Records).expect("the landed test");
    let Verdict::Passed(ack) = verdict else { panic!("{verdict:?}") };
    assert_eq!((ack.member.to_string(), ack.via), (format!("{e}.2"), AckVia::Records), "a received frame is applied whatever its connection");
    let sent = send(&p, &inputs, &mut request).expect("sent");
    let Sent::Acknowledged(again) = sent else { panic!("{sent:?}") };
    assert_eq!((again.member, again.at, again.via), (ack.member.clone(), ack.at, AckVia::Answer), "the memo answers the same id");
    let member = ack.member.to_string();
    let registered = |doc: &str| -> bool {
        let Answer::Document(v) = board.op(Some(&token), &frames::doc_metadata(doc)).unwrap() else { panic!("closed") };
        v["resp"].as_str() == Some("doc_metadata")
    };
    assert!(!registered(&format!("{e}.3")), "no third member: one version");
    assert!(!registered(&format!("{e}.1.1")), "no daughter");

    // WHAT THE ONE COMMIT HOLDS.
    assert_eq!(image(&board, &token, &member, 1, 34), vec![(format!("{e}.0.1.1"), 29), (format!("{o}.0.1.1"), 5)], "the new words minted under E after the kept words; the window by reference");
    assert_eq!(image(&board, &bare_token, d, 1, 34), vec![(format!("{e}.0.1.1"), 29), (format!("{o}.0.1.1"), 5)], "the draft re-windowed at its kept place");
    let link_at = |a: &str| read(&board, &token, &frames::read_link(a));
    let copy1 = link_at(&format!("{member}.0.2.1"));
    assert_eq!(copy1["link"]["slots"][1], json!([{"start": format!("{e}.0.1.21"), "width": "0.0.0.0.0.0.0.3"}]), "the bold's copy on the fresh identity: {copy1}");
    assert_eq!(copy1["at"].as_u64(), Some(ack.at));
    let copy3 = link_at(&format!("{member}.0.2.3"));
    assert_eq!(copy3["link"]["slots"][1], json!([{"start": format!("{}.0.1.1", seeded.z), "width": "0.0.0.0.0.0.0.3"}]), "the citation's far end verbatim: {copy3}");
    let claims = read(&board, &token, &frames::in_claims(&seeded.l1_n));
    assert_eq!(claims["claims"].as_array().map(Vec::len), Some(1), "the note's claim at its home: {claims}");
    assert_eq!(claims["claims"][0]["home"].as_str(), Some(n.as_str()));
    assert_eq!(document_of(claims["claims"][0]["new"].as_str().unwrap()).as_deref(), Some(s2.as_str()), "the copy in S2");
    let retracted = read(&board, &token, &frames::find_links_ftt(T_RETRACTION, &seeded.mpub));
    assert_eq!(retracted["addrs"].as_array().map(Vec::len), Some(1), "the held mark retracted: {retracted}");
    let ended = read(&board, &token, &frames::find_links_ftt(T_RETRACTION, &seeded.orig_d));
    assert_eq!(ended["addrs"].as_array().map(Vec::len), Some(1), "the mark's original ended with it, by the rider: {ended}");
    assert_eq!(ended["addrs"][0].as_str().and_then(document_of).as_deref(), Some(d.as_str()), "its retraction homed in the draft: {ended}");
    let rw2 = read(&board, &token, &frames::find_links_four(frames::Slot::Any, frames::Slot::Spans(&frames::unit_span(e).as_array().unwrap().clone()), frames::Slot::Spans(&frames::unit_span(s2).as_array().unwrap().clone()), frames::Slot::Spans(&frames::unit_span(T_READ_WITH).as_array().unwrap().clone())));
    assert_eq!(rw2["addrs"].as_array().map(Vec::len), Some(1), "E read with S2 now: {rw2}");
    let rw1 = read(&board, &token, &frames::find_links_four(frames::Slot::Any, frames::Slot::Spans(&frames::unit_span(e).as_array().unwrap().clone()), frames::Slot::Spans(&frames::unit_span(s).as_array().unwrap().clone()), frames::Slot::Spans(&frames::unit_span(T_READ_WITH).as_array().unwrap().clone())));
    assert_eq!(rw1["addrs"].as_array().map(Vec::len), Some(1), "E read with S once, not twice: {rw1}");
    let records = read(&board, &token, &frames::find_links_four(frames::Slot::Spans(&frames::unit_span(d).as_array().unwrap().clone()), frames::Slot::Any, frames::Slot::Any, frames::Slot::Spans(&frames::unit_span(frames::T_CORRESPONDENCE).as_array().unwrap().clone())));
    assert_eq!(records["addrs"].as_array().map(Vec::len), Some(1), "one record for the one minted run: {records}");

    // THE TWIN ON A RE-SEND under a fresh id: the fence refuses, the landed
    // test passes at the member it names, the refusal is the acknowledgment.
    request.id = publication::fresh_id();
    let twin = send(&p, &inputs, &mut request).expect("sent");
    assert!(matches!(&twin, Sent::Acknowledged(a) if a.via == AckVia::Twin && a.member.to_string() == member), "{twin:?}");
    session.close().expect("close");
}

/// THE REST AND THE CONTROL on the daemon (the link-sets design §5.7 (vi′);
/// §2, a cut copy's rest): a heading in `D` over `E`'s words 10–16 whose
/// copy in `E.1` covers 10–14, its held removal in `D` and its accept claim;
/// a citation's copy in `E.1` with a held removal and an accept claim onto a
/// citation in `N`. The selection publishes `E`'s words 1–12 and the draft's
/// own, so the heading's rest, 15–16, is outside it and the heading is
/// offered nowhere. The composition names the heading's original with its
/// rest as one I-span and composes NO entry for the citation's; the one
/// request lands; after it the heading and its copy are retracted, `D`
/// holds a fresh heading over exactly 15–16 — the mark's address below the
/// retraction's — and the citation's original stands.
#[test]
fn a_cut_copys_rest_keeps_a_fresh_mark_and_a_citations_original_stands() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(&dir.path().join("board"), true);
    let board = board(sd.port());
    let store = skep_client::store::FileStore::open(dir.path().join("store"));
    let fp = keygen(&store, "notebook");
    claim(&board, &store, &dir.path().join("anchors"));
    let device = store.load(&store.key_path(&fp)).expect("the device key").signer();
    let session = handshake(&board, Scope::Content, &device, PRINCIPAL, Site::Session).expect("a content session");
    let token = session.token().clone();
    let bare_token = bare(&board, PRINCIPAL);
    let seeded = seed(&board, &session, &device, &bare_token, &dir.path().join("anchors"));
    let Seeded { e, e1, d, n, .. } = &seeded;
    // The heading and its cut copy; the citation and its copy.
    let heading = make_link(&board, &session, &bare_token, &device, d, false, End::Addrs(vec![]), spec(e1, 10, 7, e, 10), T_HEADING);
    let hpub = make_link(&board, &session, &bare_token, &device, e1, true, End::Addrs(vec![]), spec(e1, 10, 5, e, 10), T_HEADING);
    make_link(&board, &session, &bare_token, &device, d, false, End::Addrs(vec![]), End::Addrs(vec![&hpub]), T_HELD_REMOVAL);
    acked(board.op(Some(&bare_token), &frames::assert_sup(d, &heading, &hpub, None, None)));
    let cite_n = make_link(&board, &session, &bare_token, &device, n, false, spec(e1, 1, 3, e, 1), spec(n, 1, 2, n, 1), T_CITATION);
    let cpub = make_link(&board, &session, &bare_token, &device, e1, true, spec(e1, 1, 3, e, 1), spec(n, 1, 2, n, 1), T_CITATION);
    make_link(&board, &session, &bare_token, &device, d, false, End::Addrs(vec![]), End::Addrs(vec![&cpub]), T_HELD_REMOVAL);
    acked(board.op(Some(&bare_token), &frames::assert_sup(n, &cite_n, &cpub, None, None)));
    let p = Publisher { board: &board, token: &token, account: ACCOUNT, signer: &device };
    let mut inputs = inputs(&seeded);
    inputs.selection = vec![run(e, 1, 12), run(d, 1, 10), run(&seeded.o, 1, 5)];
    let en = enumerate(&p, &inputs).expect("enumerated");
    assert!(!en.candidates.iter().any(|c| c.offered() && c.link.to_string() == heading), "the heading is folded under its copy on the selection's words: offered nowhere");
    let pn = panel(&p, &inputs, &en).expect("the panel");
    let jobs: Vec<String> = pn.formatting.job_list().iter().map(|r| r.mark.to_string()).collect();
    assert_eq!(jobs.len(), 3, "mpub, hpub and cpub: {jobs:?}");
    let original_of = |mark: &str| pn.formatting.removals.iter().find(|r| r.mark.to_string() == mark).unwrap().original.clone();
    assert_eq!(original_of(&hpub).map(|o| (o.link.to_string(), o.rest)), Some((heading.clone(), vec![skep_client::publication::ISpan { chain: format!("{e}.0.1"), first: 15, width: 2 }])), "the heading's rest: the words its copy left out");
    assert_eq!(original_of(&cpub), None, "a citation's held removal composes no original");
    let rr = reread(&p, &inputs, &en, &pn).expect("re-read");
    let Built::Request(mut request) = build(&p, &inputs, &rr.enumeration, &rr.panel, &confirmed(&seeded)).expect("built") else { panic!("inert") };
    assert_eq!(request.originals.len(), 2, "the strong mark's and the heading's: {:?}", request.originals);
    let sent = send(&p, &inputs, &mut request).expect("sent");
    let Sent::Acknowledged(ack) = sent else { panic!("{sent:?}") };
    let retractions = |link: &str| read(&board, &token, &frames::find_links_ftt(T_RETRACTION, link))["addrs"].as_array().map(Vec::len).unwrap_or(0);
    assert_eq!((retractions(&hpub), retractions(&heading), retractions(&cpub), retractions(&cite_n)), (1, 1, 1, 0), "the heading ended with its copy; the citation's original stands");
    let fresh = read(&board, &token, &frames::find_links_four(frames::Slot::Spans(&frames::unit_span(d).as_array().unwrap().clone()), frames::Slot::Any, frames::Slot::Spans(&[frames::i_span(&format!("{e}.0.1.15"), 2)]), frames::Slot::Spans(&frames::unit_span(T_HEADING).as_array().unwrap().clone())));
    let marks: Vec<&str> = fresh["addrs"].as_array().unwrap().iter().filter_map(Value::as_str).filter(|a| *a != heading).collect();
    assert_eq!(marks.len(), 1, "one fresh heading in D over the rest: {fresh}");
    let value = read(&board, &token, &frames::read_link(marks[0]));
    assert_eq!(value["link"]["slots"][1], json!([{"start": format!("{e}.0.1.15"), "width": "0.0.0.0.0.0.0.2"}]), "over exactly the rest: {value}");
    assert_eq!(value["at"].as_u64(), Some(ack.at), "written in the one commit");
    let ended = read(&board, &token, &frames::find_links_ftt(T_RETRACTION, &heading));
    assert!(ended["addrs"][0].as_str().unwrap() > marks[0], "the fresh mark's address below the retraction's: {ended}");
    session.close().expect("close");
}

/// Checks against the daemon that a retype stands in its original's place.
///
/// The note `l1_n` retyped to `mark` by `edit_link` (proposal 23; B3-S12) —
/// its successor homed in the notes beside it, the original left standing,
/// the claim in the notes — is offered in its original's place, the notes'
/// group the successor alone; the successor retracted at its home, the
/// original is offered again, the claim still active and its `new` no
/// candidate.
#[test]
fn a_link_retyped_before_the_shot_is_offered_in_its_originals_place_until_the_retype_is_retracted() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(&dir.path().join("board"), true);
    let board = board(sd.port());
    let store = skep_client::store::FileStore::open(dir.path().join("store"));
    let fp = keygen(&store, "notebook");
    claim(&board, &store, &dir.path().join("anchors"));
    let device = store.load(&store.key_path(&fp)).expect("the device key").signer();
    let session = handshake(&board, Scope::Content, &device, PRINCIPAL, Site::Session).expect("a content session");
    let token = session.token().clone();
    let bare_token = bare(&board, PRINCIPAL);
    let seeded = seed(&board, &session, &device, &bare_token, &dir.path().join("anchors"));
    let Seeded { e, e1, n, l1_n, .. } = &seeded;
    let edit = json!({"op": "edit_link", "d_s": n, "d_a": n, "original": l1_n, "successor": {"from": spec(e1, 5, 5, e, 5).wire(), "to": spec(n, 1, 5, n, 1).wire(), "ty": {"addrs": [T_MARK]}}});
    let Answer::Document(edited) = board.op(Some(&bare_token), &edit).expect("the edit") else { panic!("closed") };
    assert_eq!(edited["resp"].as_str(), Some("ack_edit"), "{edited}");
    let retyped = edited["successor"].as_str().expect("the successor").to_string();
    let p = Publisher { board: &board, token: &token, account: ACCOUNT, signer: &device };
    let inputs = inputs(&seeded);
    let in_notes = |en: &publication::Enumeration| -> Vec<String> {
        en.offered_by_home().into_iter().filter(|(h, _)| h.to_string() == *n).flat_map(|(_, links)| links.iter().map(ToString::to_string).collect::<Vec<_>>()).collect()
    };
    let en = enumerate(&p, &inputs).expect("enumerated");
    assert_eq!(in_notes(&en), vec![retyped.clone()], "the retype offered, its original not");
    // The retype retracted at its home: the claim stands, its `new` no
    // candidate, and the original is offered again.
    acked(board.op(Some(&bare_token), &json!({"op": "nullify", "home": n, "target": retyped})));
    let en = enumerate(&p, &inputs).expect("enumerated");
    assert_eq!(in_notes(&en), vec![l1_n.clone()], "the original offered again");
    let original = en.candidates.iter().find(|c| c.link.to_string() == *l1_n).expect("the original a candidate");
    assert_eq!(original.successors.iter().map(|s| (s.new.to_string(), s.candidate)).collect::<Vec<_>>(), vec![(retyped, false)], "the claim read active, naming a successor no longer a candidate");
    session.close().expect("close");
}

/// Checks against the daemon that a second publication offers nothing the
/// first accepted on the words it re-minted.
///
/// The seeded draft publishes as the first test's request does, landing
/// `E.2` and re-windowing `D` onto the member's identity; a word is typed
/// into `D` and the whole draft published again off the base the board
/// moved to `E.2`. The draft's bold, heading and citation, which the region
/// read no longer reaches, come back by the read-through, and each one's
/// copy in `E.2` covers its ends read through `D`'s record (§5.1), so none
/// is offered: the private groups are empty, as the daemon's own filter
/// over the region finds them, the formatting line holds nothing, and the
/// request, carrying no entry, lands `E.3` with no copy in it.
#[test]
fn a_second_publication_offers_nothing_the_first_accepted_on_the_words_it_re_minted() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(&dir.path().join("board"), true);
    let board = board(sd.port());
    let store = skep_client::store::FileStore::open(dir.path().join("store"));
    let fp = keygen(&store, "notebook");
    claim(&board, &store, &dir.path().join("anchors"));
    let device = store.load(&store.key_path(&fp)).expect("the device key").signer();
    let session = handshake(&board, Scope::Content, &device, PRINCIPAL, Site::Session).expect("a content session");
    let token = session.token().clone();
    let bare_token = bare(&board, PRINCIPAL);
    let seeded = seed(&board, &session, &device, &bare_token, &dir.path().join("anchors"));
    let Seeded { e, s, s2, d, o, .. } = &seeded;
    let p = Publisher { board: &board, token: &token, account: ACCOUNT, signer: &device };
    let first = inputs(&seeded);
    let en = enumerate(&p, &first).expect("enumerated");
    let pn = panel(&p, &first, &en).expect("the panel");
    let Built::Request(mut request) = build(&p, &first, &en, &pn, &confirmed(&seeded)).expect("built") else { panic!("inert") };
    let Sent::Acknowledged(ack) = send(&p, &first, &mut request).expect("sent") else { panic!("refused") };
    let e2 = format!("{e}.2");
    assert_eq!(ack.member.to_string(), e2);
    // A word typed into the re-windowed draft, then the whole draft again.
    insert_text(&board, &bare_token, d, 30, "!");
    let typed = vec![(format!("{e}.0.1.1"), 29), (format!("{d}.0.1.11"), 1), (format!("{o}.0.1.1"), 5)];
    assert_eq!(image(&board, &bare_token, d, 1, 35), typed, "the premise: the member's words, the new one, the window");
    assert_eq!(publication::draft_base(&p, &addr(e), &addr(d)), Ok(publication::base::Base::Recorded { base: addr(&e2), copied: 34 }), "the board moved D's base to E.2");
    let second = Inputs { base: Some((addr(&e2), 34)), selection: vec![run(e, 1, 29), run(d, 11, 1), run(o, 1, 5)], ..inputs(&seeded) };
    let en = enumerate(&p, &second).expect("enumerated");
    for link in [&seeded.mark_d, &seeded.heading_d, &seeded.cite_d] {
        let c = en.candidates.iter().find(|c| c.link.to_string() == *link).unwrap_or_else(|| panic!("{link} is a candidate"));
        assert!(matches!(c.via, publication::Via::ReadThrough(_)), "{link}: reached by the read-through: {:?}", c.via);
        let keys: Vec<(bool, bool, bool)> = c.successors.iter().map(|s| (s.published_home, s.covers, s.candidate)).collect();
        assert_eq!(keys, vec![(true, true, false)], "{link}: its copy in E.2 covers its ends read through D's record");
        assert!(!c.offered(), "{link}");
    }
    let private: Vec<(String, Vec<String>)> =
        en.offered_by_home().into_iter().filter(|(h, _)| h.to_string() != *s && h.to_string() != *s2).map(|(h, links)| (h.to_string(), links.iter().map(ToString::to_string).collect())).collect();
    assert_eq!(private, Vec::<(String, Vec<String>)>::new(), "nothing private the first publication accepted is offered");
    assert_eq!(private, offered_oracle(&board, &token, d, 1, 35, (&e2, 34)), "as the daemon's own filter over the region offers it");
    let pn = panel(&p, &second, &en).expect("the panel");
    assert!(pn.formatting.marks.is_empty(), "no mark on the line");
    let Built::Request(mut request) = build(&p, &second, &en, &pn, &confirmed(&seeded)).expect("built") else { panic!("inert") };
    assert!(request.entries.is_empty(), "{:?}", request.entries);
    let sent = send(&p, &second, &mut request).expect("sent");
    let Sent::Acknowledged(ack) = sent else { panic!("{sent:?}") };
    let e3 = format!("{e}.3");
    assert_eq!(ack.member.to_string(), e3);
    assert!(read(&board, &token, &frames::read_link(&format!("{e3}.0.2.1")))["link"].is_null(), "no copy in E.3");
    session.close().expect("close");
}

/// Checks against the daemon that a cut copy's original is offered once,
/// where its rest arrives, and that the board agrees before and after.
///
/// A note on the draft's new words 3..8 is published at version 2 with only
/// 1..5 selected, its copy in `E.2` cut to the words that version
/// re-minted. Version 3 publishes the rest as new words: the note is offered
/// again — the save — and left off. At version 4 its base `E.3` holds every
/// word of it, read through the draft's records, so the panel offers it no
/// more (E4 2.1), and an entry pushing it again — the write a switch turned
/// on for an unrelated link would make — is refused `old_refused`,
/// `superseded`, by the board, which reads the same base ahead of its lock.
#[test]
fn the_panel_and_the_board_agree_on_a_cut_copys_original_before_and_after_its_rest_arrives() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(&dir.path().join("board"), true);
    let board = board(sd.port());
    let store = skep_client::store::FileStore::open(dir.path().join("store"));
    let fp = keygen(&store, "notebook");
    claim(&board, &store, &dir.path().join("anchors"));
    let device = store.load(&store.key_path(&fp)).expect("the device key").signer();
    let session = handshake(&board, Scope::Content, &device, PRINCIPAL, Site::Session).expect("a content session");
    let token = session.token().clone();
    let bare_token = bare(&board, PRINCIPAL);
    let seeded = seed(&board, &session, &device, &bare_token, &dir.path().join("anchors"));
    let Seeded { e, d, n, o, .. } = &seeded;
    let p = Publisher { board: &board, token: &token, account: ACCOUNT, signer: &device };
    // The note on the draft's new words 3..8, its positions 22..27.
    let cut_n = make_link(&board, &session, &bare_token, &device, n, false, spec(d, 22, 6, d, 3), spec(n, 1, 2, n, 1), T_CITATION);
    let answered = |notes: bool| -> Confirmed {
        let mut switches = Switches::default();
        if notes {
            switches.on.insert(addr(n));
        }
        Confirmed { switches, answers: BTreeMap::from([(PartKey { run: 2, part: 0 }, OriginAnswer::KeepPrivate)]), left_out: BTreeSet::new() }
    };
    let publish = |inputs: &Inputs, confirmed: &Confirmed| -> String {
        let en = enumerate(&p, inputs).expect("enumerated");
        let pn = panel(&p, inputs, &en).expect("the panel");
        let Built::Request(mut request) = build(&p, inputs, &en, &pn, confirmed).expect("built") else { panic!("inert") };
        let sent = send(&p, inputs, &mut request).expect("sent");
        let Sent::Acknowledged(ack) = sent else { panic!("{sent:?}") };
        ack.member.to_string()
    };
    let recorded = || -> (Address, u64) {
        match publication::draft_base(&p, &addr(e), &addr(d)).expect("the base") {
            publication::base::Base::Recorded { base, copied } => (base, copied),
            other => panic!("{other:?}"),
        }
    };
    // Version 2: the draft's 1..5 alone, the note into the member — its copy
    // cut to the new words 3..5.
    let v2 = Inputs { selection: vec![run(e, 1, 19), run(d, 1, 5), run(o, 1, 5)], ..inputs(&seeded) };
    assert_eq!(publish(&v2, &answered(true)), format!("{e}.2"));
    // Version 3: the rest arrives as new words, and the note is offered
    // again; the person leaves it off.
    assert_eq!(image(&board, &bare_token, d, 1, 34), vec![(format!("{e}.0.1.1"), 24), (format!("{d}.0.1.6"), 5), (format!("{o}.0.1.1"), 5)], "the premise: 1..5 re-minted, 6..10 the draft's own");
    let v3 = Inputs { base: Some(recorded()), selection: vec![run(e, 1, 24), run(d, 6, 5), run(o, 1, 5)], ..inputs(&seeded) };
    let en = enumerate(&p, &v3).expect("enumerated");
    let c = en.candidates.iter().find(|c| c.link.to_string() == cut_n).expect("the note is a candidate");
    let keys: Vec<(bool, bool, bool)> = c.successors.iter().map(|s| (s.published_home, s.covers, s.candidate)).collect();
    assert_eq!((keys, c.offered(), c.unchanged), (vec![(true, false, false)], true, false), "the save: its rest arrives at this version");
    assert_eq!(publish(&v3, &answered(false)), format!("{e}.3"));
    // Version 4: a word typed; the base holds every word of the note.
    insert_text(&board, &bare_token, d, 30, "!");
    assert_eq!(image(&board, &bare_token, d, 1, 35), vec![(format!("{e}.0.1.1"), 29), (format!("{d}.0.1.11"), 1), (format!("{o}.0.1.1"), 5)], "the premise");
    let v4 = Inputs { base: Some(recorded()), selection: vec![run(e, 1, 29), run(d, 11, 1), run(o, 1, 5)], ..inputs(&seeded) };
    assert_eq!(v4.base, Some((addr(&format!("{e}.3")), 34)));
    let en = enumerate(&p, &v4).expect("enumerated");
    let c = en.candidates.iter().find(|c| c.link.to_string() == cut_n).expect("read through the draft's records");
    let keys: Vec<(bool, bool, bool)> = c.successors.iter().map(|s| (s.published_home, s.covers, s.candidate)).collect();
    assert_eq!((keys, c.offered(), c.unchanged), (vec![(true, true, false)], false, true), "the base holds every word of it: offered no more, and unchanged");
    let pn = panel(&p, &v4, &en).expect("the panel");
    let Built::Request(mut request) = build(&p, &v4, &en, &pn, &answered(true)).expect("built") else { panic!("inert") };
    assert!(request.entries.iter().all(|entry| entry.old != Some(addr(&cut_n))), "{:?}", request.entries);
    let candidate = en.candidates.iter().position(|c| c.link.to_string() == cut_n).expect("a candidate");
    let span = |doc: &str, first: u64, width: u64| publication::End::Spans(vec![publication::ISpan { chain: format!("{doc}.0.1"), first, width }]);
    request.entries.push(publication::Entry { home: publication::EntryHome::Member, from: span(e, 22, 6), to: span(n, 1, 2), ty: publication::End::Addrs(vec![T_CITATION.to_string()]), old: Some(addr(&cut_n)), candidate });
    let before = board.health().unwrap().log_position();
    let sent = send(&p, &v4, &mut request).expect("sent");
    assert!(matches!(&sent, Sent::Refused(Refusal::Lineage { original, cause: publication::LineageCause::Superseded, .. }) if *original == addr(&cut_n)), "the board refuses the re-offer the panel no longer makes: {sent:?}");
    assert_eq!(board.health().unwrap().log_position(), before, "nothing committed");
    session.close().expect("close");
}

/// Checks against the daemon that a draft's stray words offer nothing.
///
/// The seeded draft publishes as the first test's request does, landing
/// `E.2` and re-windowing `D` onto the member's identity; then an agent's
/// raw `reinstate` lays `D`'s own ten words back beside `E`'s and a
/// `delete` takes `E`'s out, so `D` shows its own words again beside the
/// record naming them as `E`'s 20..29 (the link-sets design §5.1). The
/// enumeration reads that record as a twin: the bold, the heading and the
/// citation read through it onto the words their copies in `E.2` cover,
/// and none is offered; the request re-composes the run by reference with
/// its kept place, carries no entry, and the board takes it, landing `E.3`
/// and re-windowing `D` onto `E`'s words.
#[test]
fn a_draft_showing_its_published_words_as_its_own_again_offers_nothing_and_lands() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(&dir.path().join("board"), true);
    let board = board(sd.port());
    let store = skep_client::store::FileStore::open(dir.path().join("store"));
    let fp = keygen(&store, "notebook");
    claim(&board, &store, &dir.path().join("anchors"));
    let device = store.load(&store.key_path(&fp)).expect("the device key").signer();
    let session = handshake(&board, Scope::Content, &device, PRINCIPAL, Site::Session).expect("a content session");
    let token = session.token().clone();
    let bare_token = bare(&board, PRINCIPAL);
    let seeded = seed(&board, &session, &device, &bare_token, &dir.path().join("anchors"));
    let Seeded { e, d, o, .. } = &seeded;
    let p = Publisher { board: &board, token: &token, account: ACCOUNT, signer: &device };
    let first = inputs(&seeded);
    let en = enumerate(&p, &first).expect("enumerated");
    let pn = panel(&p, &first, &en).expect("the panel");
    let Built::Request(mut request) = build(&p, &first, &en, &pn, &confirmed(&seeded)).expect("built") else { panic!("inert") };
    let Sent::Acknowledged(ack) = send(&p, &first, &mut request).expect("sent") else { panic!("refused") };
    let e2 = format!("{e}.2");
    assert_eq!(ack.member.to_string(), e2);
    // An agent's raw reinstate of D's own words at V 30, then E's 20..29
    // deleted from in front of them.
    let as_of = crate::common::typed_at(&board, &bare_token, d);
    acked(board.op(Some(&bare_token), &frames::reinstate(d, 30, &[frames::shot_run(d, &format!("{d}.0.1.1"), 10)], as_of, None)));
    let as_of = crate::common::typed_at(&board, &bare_token, d);
    acked(board.op(Some(&bare_token), &json!({"op": "delete", "doc": d, "p": {"subspace": "1", "ordinal": "20"}, "width": "10", "as_of": as_of})));
    assert_eq!(image(&board, &bare_token, d, 1, 34), vec![(format!("{e}.0.1.1"), 19), (format!("{d}.0.1.1"), 10), (format!("{o}.0.1.1"), 5)], "the premise: D shows its own words again");
    let second = Inputs { base: Some((addr(&e2), 34)), ..inputs(&seeded) };
    let en = enumerate(&p, &second).expect("enumerated");
    assert_eq!(en.twins.iter().map(|r| (r.home.to_string(), r.from.first, r.from.width, r.to.first)).collect::<Vec<_>>(), vec![(d.clone(), 1, 10, 20)], "the record naming D's words as E's 20..29");
    for link in [&seeded.mark_d, &seeded.heading_d, &seeded.cite_d] {
        let c = en.candidates.iter().find(|c| c.link.to_string() == *link).unwrap_or_else(|| panic!("{link} is a candidate"));
        let keys: Vec<(bool, bool, bool)> = c.successors.iter().map(|s| (s.published_home, s.covers, s.candidate)).collect();
        assert_eq!(keys, vec![(true, true, false)], "{link}: its copy in E.2 covers its ends read through the twin");
        assert!(!c.offered(), "{link}");
    }
    let pn = panel(&p, &second, &en).expect("the panel");
    assert!(pn.formatting.marks.is_empty(), "no mark on the line");
    let Built::Request(mut request) = build(&p, &second, &en, &pn, &confirmed(&seeded)).expect("built") else { panic!("inert") };
    assert_eq!(request.runs, vec![run(e, 1, 19), run(e, 20, 10), run(o, 1, 5)], "D's words by reference to E's");
    assert_eq!(request.places, vec![None, Some(20), None], "with their kept place");
    assert!(request.entries.is_empty(), "{:?}", request.entries);
    let sent = send(&p, &second, &mut request).expect("sent");
    let Sent::Acknowledged(ack) = sent else { panic!("{sent:?}") };
    assert_eq!(ack.member.to_string(), format!("{e}.3"));
    assert_eq!(image(&board, &bare_token, d, 1, 34), vec![(format!("{e}.0.1.1"), 29), (format!("{o}.0.1.1"), 5)], "D re-windowed onto E's words at the kept place");
    session.close().expect("close");
}

/// Checks against the daemon that the board takes the request each answer
/// composes (B3-S11 P2 (i)).
///
/// Version 2 keeps the window onto `O` private and publishes a note on `O`'s
/// 2..3 into `S2`, its copy there on `O`'s own identity. `O` is then
/// published at the mint form, its record naming those words as the new
/// edition's. At the next version the window is one part the record names:
/// keep-private is no answer there and the request is inert naming the
/// part; leaving it out lands a version holding nothing of `O` and no entry
/// on its words; and the counterpart, taken at the version after, offers
/// the note again on the edition's words, which its copy never covered, and
/// the board takes it, the window re-composed by reference with its kept
/// place.
#[test]
fn the_board_accepts_the_request_each_answer_composes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(&dir.path().join("board"), true);
    let board = board(sd.port());
    let store = skep_client::store::FileStore::open(dir.path().join("store"));
    let fp = keygen(&store, "notebook");
    claim(&board, &store, &dir.path().join("anchors"));
    let device = store.load(&store.key_path(&fp)).expect("the device key").signer();
    let session = handshake(&board, Scope::Content, &device, PRINCIPAL, Site::Session).expect("a content session");
    let token = session.token().clone();
    let bare_token = bare(&board, PRINCIPAL);
    let seeded = seed(&board, &session, &device, &bare_token, &dir.path().join("anchors"));
    let Seeded { e, s, s2, d, n, o, .. } = &seeded;
    let note_o = make_link(&board, &session, &bare_token, &device, n, false, spec(d, 31, 2, o, 2), spec(n, 1, 2, n, 1), T_CITATION);
    let p = Publisher { board: &board, token: &token, account: ACCOUNT, signer: &device };
    let names = |request: &publication::Request, link: &str| request.entries.iter().any(|entry| entry.old.as_ref().map(ToString::to_string).as_deref() == Some(link));
    // Version 2: the window kept private, the note into S2 on O's own words.
    let first = inputs(&seeded);
    let en = enumerate(&p, &first).expect("enumerated");
    let pn = panel(&p, &first, &en).expect("the panel");
    let Built::Request(mut request) = build(&p, &first, &en, &pn, &confirmed(&seeded)).expect("built") else { panic!("inert") };
    assert!(names(&request, &note_o), "the note offered on the placeholder's words: {:?}", request.entries);
    let Sent::Acknowledged(ack) = send(&p, &first, &mut request).expect("sent") else { panic!("refused") };
    assert_eq!(ack.member.to_string(), format!("{e}.2"));
    // O published at the mint form: its words the new edition's, its record
    // in O.
    let origin = Inputs { doc: None, mint: Some(addr(ACCOUNT)), claim: false, base: None, draft: addr(o), also: vec![], selection: vec![run(o, 1, 5)], notes: vec![], readable_drafts: vec![addr(o)], published: vec![addr(e), addr(s), addr(s2)], supersede: vec![], merge_landing: false };
    let oe = enumerate(&p, &origin).expect("O enumerated");
    let opn = panel(&p, &origin, &oe).expect("O's panel");
    let Built::Request(mut request) = build(&p, &origin, &oe, &opn, &Confirmed::default()).expect("built") else { panic!("inert") };
    let Sent::Acknowledged(published) = send(&p, &origin, &mut request).expect("sent") else { panic!("refused") };
    let edition = published.edition.expect("an edition minted").to_string();
    // Each next version: the draft as it stands — the member's words and the
    // window — off the base the board records.
    let version = || -> Inputs {
        let base = match publication::draft_base(&p, &addr(e), &addr(d)).expect("the base") {
            publication::base::Base::Recorded { base, copied } => (base, copied),
            other => panic!("{other:?}"),
        };
        assert_eq!(image(&board, &bare_token, d, 1, 34), vec![(format!("{e}.0.1.1"), 29), (format!("{o}.0.1.1"), 5)], "the premise: the member's words and the window");
        Inputs { base: Some(base), selection: vec![run(e, 1, 29), run(o, 1, 5)], readable_drafts: vec![addr(d), addr(n), addr(o)], ..inputs(&seeded) }
    };
    let key = PartKey { run: 1, part: 0 };
    let answered = |answer: OriginAnswer| -> Confirmed { Confirmed { answers: BTreeMap::from([(key, answer)]), ..confirmed(&seeded) } };
    let third = version();
    let en = enumerate(&p, &third).expect("enumerated");
    let parts = &en.windows[0].parts;
    assert_eq!((en.windows[0].run, parts.len(), parts[0].named()), (1, 1, true), "{parts:?}");
    assert_eq!(parts[0].counterpart().and_then(|c| c.document()).as_deref(), Some(edition.as_str()), "O's words are the edition's now");
    let pn = panel(&p, &third, &en).expect("the panel");
    let Built::Inert(publication::Inert::Unanswered(owed)) = build(&p, &third, &en, &pn, &answered(OriginAnswer::KeepPrivate)).expect("built") else { panic!("no owed answer") };
    assert_eq!(owed.iter().map(|o| (o.part, o.named)).collect::<Vec<_>>(), vec![(key, true)], "no placeholder over published words");
    let Built::Request(mut left) = build(&p, &third, &en, &pn, &answered(OriginAnswer::Drop)).expect("built") else { panic!("inert") };
    assert_eq!(left.runs, vec![run(e, 1, 29)], "the part left out");
    assert!(!names(&left, &note_o), "no entry on the words left out: {:?}", left.entries);
    let sent = send(&p, &third, &mut left).expect("sent");
    let Sent::Acknowledged(ack) = sent else { panic!("{sent:?}") };
    assert_eq!(ack.member.to_string(), format!("{e}.3"));
    // The counterpart: the note on the edition's words, which its copy in S2
    // never covered.
    let fourth = version();
    let en = enumerate(&p, &fourth).expect("enumerated");
    let pn = panel(&p, &fourth, &en).expect("the panel");
    let taken = answered(OriginAnswer::Counterpart);
    let composed = taken.compose(&fourth, &en);
    assert!(composed.candidates.iter().any(|c| c.link.to_string() == note_o && c.offered()), "offered again on the published words");
    let Built::Request(mut request) = build(&p, &fourth, &en, &pn, &taken).expect("built") else { panic!("inert") };
    let entry = request.entries.iter().find(|entry| entry.old.as_ref().map(ToString::to_string).as_deref() == Some(note_o.as_str())).expect("the note's entry");
    assert!(matches!(&entry.from, publication::End::Spans(spans) if spans.iter().all(|span| span.chain == format!("{edition}.0.1"))), "on the edition's words: {:?}", entry.from);
    assert_eq!(request.places, vec![None, Some(30)], "the window's kept place beside its counterpart");
    let sent = send(&p, &fourth, &mut request).expect("sent");
    let Sent::Acknowledged(ack) = sent else { panic!("{sent:?}") };
    assert_eq!(ack.member.to_string(), format!("{e}.4"));
    session.close().expect("close");
}

/// Checks against the daemon that a far-end original arrives with its words.
///
/// A note from `E`'s 5..9 to the draft's new words 3..4 is published by a
/// shot that leaves the draft's words out, so its copy in `S2` holds the
/// draft's addresses verbatim. The shot that publishes the draft's words
/// reads them as new words, which that copy never covers (§5.2's ⟨d⟩), so
/// the note is offered, its `to` at the member's positions, and the board
/// takes it beside the copy: the new copy in `S2` lies on `E`'s fresh words.
#[test]
fn a_far_end_original_is_offered_and_lands_at_the_shot_that_publishes_its_words() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(&dir.path().join("board"), true);
    let board = board(sd.port());
    let store = skep_client::store::FileStore::open(dir.path().join("store"));
    let fp = keygen(&store, "notebook");
    claim(&board, &store, &dir.path().join("anchors"));
    let device = store.load(&store.key_path(&fp)).expect("the device key").signer();
    let session = handshake(&board, Scope::Content, &device, PRINCIPAL, Site::Session).expect("a content session");
    let token = session.token().clone();
    let bare_token = bare(&board, PRINCIPAL);
    let seeded = seed(&board, &session, &device, &bare_token, &dir.path().join("anchors"));
    let Seeded { e, e1, s2, d, n, o, .. } = &seeded;
    let note = make_link(&board, &session, &bare_token, &device, n, false, spec(e1, 5, 5, e, 5), spec(d, 22, 2, d, 3), T_CITATION);
    let p = Publisher { board: &board, token: &token, account: ACCOUNT, signer: &device };
    let claims = |link: &str| read(&board, &token, &frames::in_claims(link))["claims"].as_array().cloned().unwrap_or_default();
    let to_of = |claim: &Value| read(&board, &token, &frames::read_link(claim["new"].as_str().unwrap()))["link"]["slots"][1].clone();
    // The draft's words left out: the window, now the second run, kept
    // private.
    let first = Inputs { selection: vec![run(e, 1, 19), run(o, 1, 5)], ..inputs(&seeded) };
    let mut windowed = confirmed(&seeded);
    windowed.answers = BTreeMap::from([(PartKey { run: 1, part: 0 }, OriginAnswer::KeepPrivate)]);
    let en = enumerate(&p, &first).expect("enumerated");
    let pn = panel(&p, &first, &en).expect("the panel");
    let Built::Request(mut request) = build(&p, &first, &en, &pn, &windowed).expect("built") else { panic!("inert") };
    let Sent::Acknowledged(ack) = send(&p, &first, &mut request).expect("sent") else { panic!("refused") };
    let e2 = format!("{e}.2");
    assert_eq!(ack.member.to_string(), e2);
    let accepted = claims(&note);
    assert_eq!(accepted.len(), 1, "the note accepted: {accepted:?}");
    assert_eq!(to_of(&accepted[0]), json!([{"start": format!("{d}.0.1.3"), "width": "0.0.0.0.0.0.0.2"}]), "its copy holds the draft's 3..4 verbatim");
    assert_eq!(publication::draft_base(&p, &addr(e), &addr(d)), Ok(publication::base::Base::Recorded { base: addr(&e2), copied: 24 }), "the board moved D's base to E.2");
    // The shot that publishes the draft's words, off that base.
    let second = Inputs { base: Some((addr(&e2), 24)), ..inputs(&seeded) };
    let en = enumerate(&p, &second).expect("enumerated");
    let c = en.candidates.iter().find(|c| c.link.to_string() == note).expect("the note a candidate");
    let keys: Vec<(bool, bool, bool)> = c.successors.iter().map(|s| (s.published_home, s.covers, s.candidate)).collect();
    assert_eq!((keys, c.offered()), (vec![(true, false, true)], true), "its copy in S2 never covers the new words: offered");
    let pn = panel(&p, &second, &en).expect("the panel");
    let Built::Request(mut request) = build(&p, &second, &en, &pn, &confirmed(&seeded)).expect("built") else { panic!("inert") };
    let entry = request.entries.iter().find(|entry| en.candidates[entry.candidate].link.to_string() == note).expect("the note's entry");
    assert_eq!(entry.to, publication::End::Member(vec![(22, 2)]), "the far end on the new words, after the kept words' nineteen");
    let Sent::Acknowledged(ack) = send(&p, &second, &mut request).expect("sent") else { panic!("refused") };
    assert_eq!(ack.member.to_string(), format!("{e}.3"));
    let accepted = claims(&note);
    assert_eq!(accepted.len(), 2, "a second claim beside the first: {accepted:?}");
    let fresh: Vec<&Value> = accepted.iter().filter(|claim| to_of(claim) == json!([{"start": format!("{e}.0.1.22"), "width": "0.0.0.0.0.0.0.2"}])).collect();
    assert_eq!(fresh.len(), 1, "one copy on E's fresh words 22..23: {accepted:?}");
    assert_eq!(document_of(fresh[0]["new"].as_str().unwrap()).as_deref(), Some(s2.as_str()), "in S2, the notes' destination");
    session.close().expect("close");
}

/// Checks against the daemon that the re-read counts no deleted word.
///
/// The far-end note of the test above is offered over the draft's new
/// words 3..4, which are deleted after the panel. The re-read states the
/// draft's run split and reads the note over what the draft still arranges
/// (PUB-3.108): its copy in `S2` covers the end it keeps, so it is
/// superseded, and the request confirmed again carries no entry for it and
/// lands, where its entry, the `to` the deleted words as stored, is refused
/// `superseded`.
#[test]
fn a_word_deleted_since_the_panel_drops_its_original_and_the_request_confirmed_again_lands() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(&dir.path().join("board"), true);
    let board = board(sd.port());
    let store = skep_client::store::FileStore::open(dir.path().join("store"));
    let fp = keygen(&store, "notebook");
    claim(&board, &store, &dir.path().join("anchors"));
    let device = store.load(&store.key_path(&fp)).expect("the device key").signer();
    let session = handshake(&board, Scope::Content, &device, PRINCIPAL, Site::Session).expect("a content session");
    let token = session.token().clone();
    let bare_token = bare(&board, PRINCIPAL);
    let seeded = seed(&board, &session, &device, &bare_token, &dir.path().join("anchors"));
    let Seeded { e, e1, d, n, o, .. } = &seeded;
    let note = make_link(&board, &session, &bare_token, &device, n, false, spec(e1, 5, 5, e, 5), spec(d, 22, 2, d, 3), T_CITATION);
    let p = Publisher { board: &board, token: &token, account: ACCOUNT, signer: &device };
    let claims = |link: &str| read(&board, &token, &frames::in_claims(link))["claims"].as_array().map_or(0, Vec::len);
    // The note accepted by a shot that leaves the draft's words out.
    let first = Inputs { selection: vec![run(e, 1, 19), run(o, 1, 5)], ..inputs(&seeded) };
    let mut windowed = confirmed(&seeded);
    windowed.answers = BTreeMap::from([(PartKey { run: 1, part: 0 }, OriginAnswer::KeepPrivate)]);
    let en = enumerate(&p, &first).expect("enumerated");
    let pn = panel(&p, &first, &en).expect("the panel");
    let Built::Request(mut request) = build(&p, &first, &en, &pn, &windowed).expect("built") else { panic!("inert") };
    let Sent::Acknowledged(_) = send(&p, &first, &mut request).expect("sent") else { panic!("refused") };
    assert_eq!(claims(&note), 1, "the premise: the note accepted, its copy in S2");
    // The panel over the whole draft offers it; then its 3..4 are deleted.
    let second = Inputs { base: Some((addr(&format!("{e}.2")), 24)), ..inputs(&seeded) };
    let en = enumerate(&p, &second).expect("enumerated");
    let pn = panel(&p, &second, &en).expect("the panel");
    assert!(en.candidates.iter().any(|c| c.link.to_string() == note && c.offered()), "the premise: offered over the new words");
    let as_of = crate::common::typed_at(&board, &bare_token, d);
    acked(board.op(Some(&bare_token), &json!({"op": "delete", "doc": d, "p": {"subspace": "1", "ordinal": "22"}, "width": "2", "as_of": as_of})));
    let rr = reread(&p, &second, &en, &pn).expect("re-read");
    let r = rr.restatement.expect("the draft moved");
    assert_eq!(r.selection, vec![(1, publication::Placement::Split(vec![(20, 1, 2), (22, 5, 6)])), (2, publication::Placement::Whole { ordinal: 28 })]);
    assert_eq!(r.superseded, vec![addr(&note)], "its copy in S2 covers the end it keeps");
    // Confirmed again over what is left.
    let again = reread(&p, &second, &rr.enumeration, &rr.panel).expect("re-read");
    assert_eq!(again.restatement, None);
    let Built::Request(mut request) = build(&p, &second, &again.enumeration, &again.panel, &confirmed(&seeded)).expect("built") else { panic!("inert") };
    assert!(request.entries.iter().all(|entry| again.enumeration.candidates[entry.candidate].link.to_string() != note), "no entry for the note: {:?}", request.entries);
    let sent = send(&p, &second, &mut request).expect("sent");
    assert!(matches!(&sent, Sent::Acknowledged(ack) if ack.member.to_string() == format!("{e}.3")), "{sent:?}");
    assert_eq!(claims(&note), 1, "no copy made over the deleted words");
    session.close().expect("close");
}

/// A MOVED PLACE: a second draft whose words are swapped after the request
/// was built is refused `kept_place_moved` naming the entry, with the race's
/// key off the feed; the re-read then re-states the selection's new places
/// and nothing else, and the request built over it lands.
#[test]
fn a_moved_place_is_refused_with_its_entry_and_the_reread_restates_the_selection() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(&dir.path().join("board"), true);
    let board = board(sd.port());
    let store = skep_client::store::FileStore::open(dir.path().join("store"));
    let fp = keygen(&store, "notebook");
    claim(&board, &store, &dir.path().join("anchors"));
    let device = store.load(&store.key_path(&fp)).expect("the device key").signer();
    let session = handshake(&board, Scope::Content, &device, PRINCIPAL, Site::Session).expect("a content session");
    let token = session.token().clone();
    let bare_token = bare(&board, PRINCIPAL);
    let e = published_document(&board, &session, &device);
    let e1 = first_shot(&board, &session, &device, &bare_token, &e, P);
    let d = mint(&board, &bare_token, ACCOUNT, false);
    insert_text(&board, &bare_token, &d, 1, "xyz");
    let y = format!("{d}.0.1.2");
    let p = Publisher { board: &board, token: &token, account: ACCOUNT, signer: &device };
    let inputs = Inputs { doc: Some(addr(&e)), mint: None, claim: false, base: Some((addr(&e1), 19)), draft: addr(&d), also: vec![], selection: vec![run(&d, 2, 2)], notes: vec![], readable_drafts: vec![addr(&d)], published: vec![addr(&e)], supersede: vec![], merge_landing: false };
    let en = enumerate(&p, &inputs).unwrap();
    assert_eq!(en.placed, vec![publication::Placement::Whole { ordinal: 2 }]);
    let pn = panel(&p, &inputs, &en).unwrap();
    let Built::Request(mut request) = build(&p, &inputs, &en, &pn, &Confirmed::default()).unwrap() else { panic!("inert") };
    assert_eq!(request.places, vec![Some(2)]);
    // The move: `y` and `x` swapped after the place was read.
    let as_of = crate::common::typed_at(&board, &bare_token, &d);
    acked(board.op(Some(&bare_token), &json!({"op": "rearrange", "doc": d, "cuts": [{"subspace": "1", "ordinal": "1"}, {"subspace": "1", "ordinal": "2"}, {"subspace": "1", "ordinal": "3"}], "as_of": as_of})));
    let sent = send(&p, &inputs, &mut request).expect("sent");
    let Sent::Refused(Refusal::KeptPlaceMoved { index, draft, race }) = sent else { panic!("{sent:?}") };
    assert_eq!((index, draft), (0, addr(&d)), "the entry, and the rendering draft the board names");
    let race = race.expect("the race's key off the feed");
    assert_eq!(race.key.as_deref(), Some("bare"), "the move was the bare session's own write: {race:?}");
    // The re-read: "y z" now stands as two pieces around the moved "x" — a
    // split run, re-stated, and sent as its pieces in the draft's order,
    // each with its own kept place.
    let rr = reread(&p, &inputs, &en, &pn).unwrap();
    let r = rr.restatement.expect("the selection moved");
    assert_eq!(r.selection, vec![(0, publication::Placement::Split(vec![(1, 2, 1), (3, 3, 1)]))]);
    assert!(r.left.is_empty() && r.came.is_empty() && r.removals_undone.is_empty());
    let Built::Request(mut again) = build(&p, &inputs, &rr.enumeration, &rr.panel, &Confirmed::default()).unwrap() else { panic!("inert") };
    assert_eq!(again.runs, vec![run(&d, 2, 1), run(&d, 3, 1)]);
    assert_eq!(again.places, vec![Some(1), Some(3)]);
    assert_ne!(again.id, request.id, "a re-composed request takes a fresh id");
    let landed = send(&p, &inputs, &mut again).unwrap();
    assert!(matches!(&landed, Sent::Acknowledged(a) if a.member.to_string() == format!("{e}.2")), "{landed:?}");
    assert_eq!(image(&board, &bare_token, &d, 1, 3), vec![(format!("{e}.0.1.20"), 1), (format!("{d}.0.1.1"), 1), (format!("{e}.0.1.21"), 1)], "each piece re-windowed at its own place: {y}");
    session.close().unwrap();
}

/// COST (stated, not bounded): the enumeration and the panel over a
/// selection with N links in the person's three homes — the draft's own
/// set, the notes and a public set — p50 of 20 runs, the frame count
/// beside; N = 1,000 here, 10,000 under `SKEP_COST_LARGE=1`. Run in release
/// for the figures the report states.
#[test]
#[ignore = "cost figures: run by hand in release"]
fn cost_of_the_enumeration_and_the_panel_over_many_links() {
    let large = std::env::var("SKEP_COST_LARGE").is_ok();
    let n_links: u64 = if large { 10_000 } else { 1_000 };
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(&dir.path().join("board"), true);
    let board = board(sd.port());
    let store = skep_client::store::FileStore::open(dir.path().join("store"));
    let fp = keygen(&store, "notebook");
    claim(&board, &store, &dir.path().join("anchors"));
    let device = store.load(&store.key_path(&fp)).expect("the device key").signer();
    let session = handshake(&board, Scope::Content, &device, PRINCIPAL, Site::Session).expect("a content session");
    let token = session.token().clone();
    let bare_token = bare(&board, PRINCIPAL);
    let text: String = "abcdefghij".repeat(100);
    let e = published_document(&board, &session, &device);
    let e1 = first_shot(&board, &session, &device, &bare_token, &e, &text);
    let s = published_document(&board, &session, &device);
    let n = mint(&board, &bare_token, ACCOUNT, false);
    insert_text(&board, &bare_token, &n, 1, "notes");
    let d = mint(&board, &bare_token, ACCOUNT, false);
    copy(&board, &bare_token, &d, 1, &e1, 1, 1000);
    insert_text(&board, &bare_token, &d, 1001, " new");
    let per_home = n_links / 3;
    for k in 0..per_home {
        let at = 1 + (k % 990);
        make_link(&board, &session, &bare_token, &device, &d, false, End::Addrs(vec![]), spec(&d, at, 3, &e, at), T_STRONG);
        make_link(&board, &session, &bare_token, &device, &n, false, spec(&e1, at, 2, &e, at), End::Addrs(vec![]), T_CITATION);
        make_link(&board, &session, &bare_token, &device, &s, true, spec(&e1, at, 2, &e, at), End::Addrs(vec![]), T_CITATION);
    }
    let p = Publisher { board: &board, token: &token, account: ACCOUNT, signer: &device };
    let inputs = Inputs { doc: Some(addr(&e)), mint: None, claim: false, base: Some((addr(&e1), 1000)), draft: addr(&d), also: vec![], selection: vec![run(&e, 1, 1000), run(&d, 1, 4)], notes: vec![addr(&n)], readable_drafts: vec![addr(&d), addr(&n)], published: vec![addr(&e), addr(&s)], supersede: vec![], merge_landing: false };
    let mut enumerate_ms = Vec::new();
    let mut panel_ms = Vec::new();
    let mut reread_ms = Vec::new();
    let mut frames = (0usize, 0usize);
    for _ in 0..20 {
        let t = std::time::Instant::now();
        let en = enumerate(&p, &inputs).unwrap();
        enumerate_ms.push(t.elapsed().as_secs_f64() * 1000.0);
        let t = std::time::Instant::now();
        let pn = panel(&p, &inputs, &en).unwrap();
        panel_ms.push(t.elapsed().as_secs_f64() * 1000.0);
        let t = std::time::Instant::now();
        let _ = reread(&p, &inputs, &en, &pn).unwrap();
        reread_ms.push(t.elapsed().as_secs_f64() * 1000.0);
        frames = (en.frames.iter().map(|(_, k)| k).sum(), pn.frames.iter().map(|(_, k)| k).sum());
        assert_eq!(en.offered().len() as u64, per_home * 3);
    }
    let p50 = |v: &mut Vec<f64>| {
        v.sort_by(|a, b| a.partial_cmp(b).unwrap());
        v[v.len() / 2]
    };
    println!("COST links={n_links} enumerate p50 {:.1} ms ({} frames) panel p50 {:.1} ms ({} frames) reread p50 {:.1} ms", p50(&mut enumerate_ms), frames.0, p50(&mut panel_ms), frames.1, p50(&mut reread_ms));
    session.close().unwrap();
}

/// THE FAMILY against the daemon (the Nelson way, B3-S10): `A`, an
/// alternative of `D`'s holding `E`'s words and `D`'s own ten by identity
/// (two copies) and six words of its own, publishes with `also: [D]` — the
/// panel lists no window for `D`'s words and counts its one inherited
/// passage; the request carries `also`, `A`'s kept place for every run of
/// a named draft's identity and `D`'s own place for its run in
/// `also_places`, off `D`'s image; the acknowledgment names `E.2`,
/// whose text is `A`'s whole; the records are read back in BOTH drafts,
/// `D`'s for its ten words and `A`'s for its six, each `to` the member's
/// fresh identity; the feed row names the member, `A` and `D`; and BOTH
/// drafts are re-windowed in the one commit (skep #739) — `D`'s image at
/// its ten words the member's identity, no counterpart left in it.
#[test]
fn a_family_publication_re_mints_two_drafts_words_and_homes_a_record_in_each() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(&dir.path().join("board"), true);
    let board = board(sd.port());
    let store = skep_client::store::FileStore::open(dir.path().join("store"));
    let fp = keygen(&store, "notebook");
    claim(&board, &store, &dir.path().join("anchors"));
    let device = store.load(&store.key_path(&fp)).expect("the device key").signer();
    let session = handshake(&board, Scope::Content, &device, PRINCIPAL, Site::Session).expect("a content session");
    let token = session.token().clone();
    let bare_token = bare(&board, PRINCIPAL);
    let seeded = seed(&board, &session, &device, &bare_token, &dir.path().join("anchors"));
    let Seeded { e, e1, d, n, .. } = &seeded;
    // A: E's words and D's own ten by identity, then six of its own.
    let a_draft = mint(&board, &bare_token, ACCOUNT, false);
    copy(&board, &bare_token, &a_draft, 1, e1, 1, 19);
    copy(&board, &bare_token, &a_draft, 20, d, 20, 10);
    insert_text(&board, &bare_token, &a_draft, 30, " extra");
    assert_eq!(image(&board, &bare_token, &a_draft, 1, 35), vec![(format!("{e}.0.1.1"), 19), (format!("{d}.0.1.1"), 10), (format!("{a_draft}.0.1.1"), 6)], "the premise: A holds E's identity, D's by identity, and its own");
    let p = Publisher { board: &board, token: &token, account: ACCOUNT, signer: &device };
    let inputs = Inputs {
        draft: addr(&a_draft),
        also: vec![addr(d)],
        selection: vec![run(e, 1, 19), run(d, 1, 10), run(&a_draft, 1, 6)],
        readable_drafts: vec![addr(&a_draft), addr(d), addr(n)],
        ..inputs(&seeded)
    };
    let en = enumerate(&p, &inputs).expect("enumerated");
    let pn = panel(&p, &inputs, &en).expect("the panel");
    assert_eq!(en.windows, vec![], "D's run is re-minted, not windowed");
    assert_eq!(pn.inherited, vec![publication::Inherited { draft: addr(d), passages: 1 }]);
    let Built::Request(mut request) = build(&p, &inputs, &en, &pn, &Confirmed::default()).expect("built") else { panic!("inert") };
    assert_eq!(request.also, vec![addr(d)]);
    assert_eq!(request.places, vec![None, Some(20), Some(30)], "the rendering draft's kept place for every run of a named draft's identity: D's ten at 20, its own six at 30");
    assert_eq!(request.also_places, vec![AlsoPlaces { draft: addr(d), places: vec![None, Some(20), None] }], "D's own place for its run, off D's image");
    assert!(request.price.admits(), "{:?}", request.price);
    let Sent::Acknowledged(ack) = send(&p, &inputs, &mut request).expect("sent") else { panic!("refused") };
    let e2 = format!("{e}.2");
    assert_eq!((ack.member.to_string(), ack.via), (e2.clone(), AckVia::Answer));
    let text = read(&board, &token, &frames::retrieve_v(&e2, 1, 35));
    assert_eq!(text["items"][0]["content"], format!("{P}{W} extra"), "A's whole text as E's own words");
    assert_eq!(image(&board, &token, &e2, 1, 35), vec![(format!("{e}.0.1.1"), 35)], "fresh identity for every re-minted run, I-adjacent to E's own");
    // The records, one in each draft.
    let unit = |a: &str| frames::unit_span(a).as_array().cloned().unwrap_or_default();
    let records = |home: &str| -> Vec<Vec<(String, String)>> {
        let hits = read(&board, &token, &frames::find_links_four(frames::Slot::Spans(&unit(home)), frames::Slot::Any, frames::Slot::Any, frames::Slot::Spans(&unit(frames::T_CORRESPONDENCE))));
        hits["addrs"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| {
                let link = read(&board, &token, &frames::read_link(a.as_str().unwrap()));
                let slot = |k: usize| (link["link"]["slots"][k][0]["start"].as_str().unwrap().to_string(), link["link"]["slots"][k][0]["width"].as_str().unwrap().to_string());
                vec![slot(0), slot(1)]
            })
            .collect()
    };
    assert_eq!(records(d), vec![vec![(format!("{d}.0.1.1"), "0.0.0.0.0.0.0.10".to_string()), (format!("{e}.0.1.20"), "0.0.0.0.0.0.0.10".to_string())]], "D's record, homed in D, `to` the member's fresh identity");
    assert_eq!(records(&a_draft), vec![vec![(format!("{a_draft}.0.1.1"), "0.0.0.0.0.0.0.6".to_string()), (format!("{e}.0.1.30"), "0.0.0.0.0.0.0.6".to_string())]], "A's record, homed in A");
    let page = board.changes(Some(&token), &ChangesQuery { since: ack.at - 1, under: Some(e), drafts: false, limit: Some(1) }).expect("the feed");
    let ChangesAnswer::Page(page) = page else { panic!("a page") };
    assert_eq!(page.changes[0]["docs"], json!([e2, a_draft, d]), "the member, the rendering draft, then the draft `also` named: {:?}", page.changes);
    assert_eq!(image(&board, &bare_token, d, 20, 10), vec![(format!("{e}.0.1.20"), 10)], "D re-windowed in the one commit at its own place: its ten words the member's identity, no counterpart left");
    assert_eq!(image(&board, &bare_token, &a_draft, 1, 35), vec![(format!("{e}.0.1.1"), 35)], "A re-windowed whole, D's run among its own");
    sd.shutdown();
}

/// A MOVED `also` DRAFT against the daemon (skep #739): `A` publishes with
/// `also: [D]`; after the request is built, `D` swaps its own ten words
/// about — the bare session's write — and the board refuses
/// `kept_place_moved` naming the entry AND `D` (`site.addr`), the race's
/// key read under `D`, the bare session's own; the re-read re-states
/// nothing (`A` still arranges `D`'s run whole, and `D`'s move is no
/// difference of the rendering draft's); the request built over it carries
/// `None` for `D`'s run in its list — `D` is sure of no place — and no
/// `also_places` at all, and lands `E.2`: `A` re-windowed whole, `D` LEFT AS
/// IT STANDS with its record homed in it, healed at its own next shot; the
/// row names `D` after `A` for that record.
#[test]
fn a_moved_also_draft_is_refused_naming_it_and_left_as_it_stands_once_its_place_is_dropped() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(&dir.path().join("board"), true);
    let board = board(sd.port());
    let store = skep_client::store::FileStore::open(dir.path().join("store"));
    let fp = keygen(&store, "notebook");
    claim(&board, &store, &dir.path().join("anchors"));
    let device = store.load(&store.key_path(&fp)).expect("the device key").signer();
    let session = handshake(&board, Scope::Content, &device, PRINCIPAL, Site::Session).expect("a content session");
    let token = session.token().clone();
    let bare_token = bare(&board, PRINCIPAL);
    let seeded = seed(&board, &session, &device, &bare_token, &dir.path().join("anchors"));
    let Seeded { e, e1, d, n, .. } = &seeded;
    let a_draft = mint(&board, &bare_token, ACCOUNT, false);
    copy(&board, &bare_token, &a_draft, 1, e1, 1, 19);
    copy(&board, &bare_token, &a_draft, 20, d, 20, 10);
    insert_text(&board, &bare_token, &a_draft, 30, " extra");
    let p = Publisher { board: &board, token: &token, account: ACCOUNT, signer: &device };
    let inputs = Inputs { draft: addr(&a_draft), also: vec![addr(d)], selection: vec![run(e, 1, 19), run(d, 1, 10), run(&a_draft, 1, 6)], readable_drafts: vec![addr(&a_draft), addr(d), addr(n)], ..inputs(&seeded) };
    let en = enumerate(&p, &inputs).expect("enumerated");
    let pn = panel(&p, &inputs, &en).expect("the panel");
    let Built::Request(mut request) = build(&p, &inputs, &en, &pn, &Confirmed::default()).expect("built") else { panic!("inert") };
    assert_eq!(request.also_places, vec![AlsoPlaces { draft: addr(d), places: vec![None, Some(20), None] }]);
    // D's move after the place was read: its first five own words and its
    // last five swapped.
    let as_of = crate::common::typed_at(&board, &bare_token, d);
    acked(board.op(Some(&bare_token), &json!({"op": "rearrange", "doc": d, "cuts": [{"subspace": "1", "ordinal": "20"}, {"subspace": "1", "ordinal": "25"}, {"subspace": "1", "ordinal": "30"}], "as_of": as_of})));
    let sent = send(&p, &inputs, &mut request).expect("sent");
    let Sent::Refused(Refusal::KeptPlaceMoved { index, draft, race }) = sent else { panic!("{sent:?}") };
    assert_eq!((index, &draft), (1, &addr(d)), "the entry of D's run, and D named");
    assert_eq!(race.expect("the race's key off the feed under D").key.as_deref(), Some("bare"), "read under D: the bare session's own write");
    assert_eq!(image(&board, &bare_token, &a_draft, 20, 10), vec![(format!("{d}.0.1.1"), 10)], "nothing committed: A as it was");
    let rr = reread(&p, &inputs, &en, &pn).expect("re-read");
    assert_eq!(rr.restatement, None, "A's placements stand; D's move is none of the rendering draft's");
    let Built::Request(mut again) = build(&p, &inputs, &rr.enumeration, &rr.panel, &Confirmed::default()).expect("built") else { panic!("inert") };
    assert_eq!(again.places, vec![None, Some(20), Some(30)]);
    assert_eq!(again.also_places, vec![AlsoPlaces { draft: addr(d), places: vec![None; 3] }], "D no longer arranges its run whole: no place for it");
    assert!(again.frame(None).get("also_places").is_none(), "an all-None entry is not sent");
    let Sent::Acknowledged(ack) = send(&p, &inputs, &mut again).expect("sent") else { panic!("refused") };
    let e2 = format!("{e}.2");
    assert_eq!((ack.member.to_string(), ack.via), (e2.clone(), AckVia::Answer));
    assert_eq!(image(&board, &token, &e2, 1, 35), vec![(format!("{e}.0.1.1"), 35)], "the member: fresh identity for every re-minted run");
    assert_eq!(image(&board, &bare_token, &a_draft, 1, 35), vec![(format!("{e}.0.1.1"), 35)], "A re-windowed whole");
    assert_eq!(image(&board, &bare_token, d, 20, 10), vec![(format!("{d}.0.1.6"), 5), (format!("{d}.0.1.1"), 5)], "D left as it stands: its own words, swapped, a counterpart through its record");
    let page = board.changes(Some(&token), &ChangesQuery { since: ack.at - 1, under: Some(e), drafts: false, limit: Some(1) }).expect("the feed");
    let ChangesAnswer::Page(page) = page else { panic!("a page") };
    assert_eq!(page.changes[0]["docs"], json!([e2, a_draft, d]), "the member, the rendering draft, then D for the record homed in it: {:?}", page.changes);
    sd.shutdown();
}

/// Checks that a base under a trunk member stands behind against the daemon.
///
/// `B` and `C` are staged from the memberless `X` (skep #807; PUB-2.37,
/// PUB-2.53), each with words of its own. `B`'s shot births `X.1`; `C`'s,
/// its base still the bare document, lands `X.1.1`, version 1's daughter,
/// and the board moves `C`'s recorded base there at the daughter's whole
/// count. That base stands `Behind`, `X.2` absent, and `C`'s next shot,
/// words of its own added, lands `X.1.1.1`, the base's own daughter, as its
/// standing told: no trunk member `X.2` is minted and the edition still
/// reads version 1. The landed walk from that base finds the member the
/// shot made.
#[test]
fn a_base_under_a_trunk_member_stands_behind_and_its_next_shot_lands_its_daughter() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(&dir.path().join("board"), true);
    let board = board(sd.port());
    let store = skep_client::store::FileStore::open(dir.path().join("store"));
    let fp = keygen(&store, "notebook");
    claim(&board, &store, &dir.path().join("anchors"));
    let device = store.load(&store.key_path(&fp)).expect("the device key").signer();
    let session = handshake(&board, Scope::Content, &device, PRINCIPAL, Site::Session).expect("a content session");
    let token = session.token().clone();
    let bare_token = bare(&board, PRINCIPAL);
    let x = published_document(&board, &session, &device);
    let staged = |text: &str| -> String {
        let d = acked_addr(&acked(board.op(Some(&bare_token), &frames::stage(&x, None)))).expect("the staged draft").to_string();
        insert_text(&board, &bare_token, &d, 1, text);
        d
    };
    let (b, c) = (staged("ab"), staged("wxyz"));
    let p = Publisher { board: &board, token: &token, account: ACCOUNT, signer: &device };
    // One shot of the draft's first `width` positions off `base`: its
    // inputs, its request and the acknowledgment.
    let shot = |draft: &str, base: (Address, u64), width: u64| -> (Inputs, publication::Request, publication::Ack) {
        let selection = image(&board, &bare_token, draft, 1, width)
            .into_iter()
            .map(|(start, w)| {
                let (origin, ordinal) = start.rsplit_once(".0.1.").expect("a content I-address");
                run(origin, ordinal.parse().expect("an ordinal"), w)
            })
            .collect();
        let inputs = Inputs { doc: Some(addr(&x)), mint: None, claim: false, base: Some(base), draft: addr(draft), also: vec![], selection, notes: vec![], readable_drafts: vec![addr(draft)], published: vec![addr(&x)], supersede: vec![], merge_landing: false };
        let en = enumerate(&p, &inputs).expect("enumerated");
        let pn = panel(&p, &inputs, &en).expect("the panel");
        let Built::Request(mut request) = build(&p, &inputs, &en, &pn, &Confirmed::default()).expect("built") else { panic!("inert") };
        let sent = send(&p, &inputs, &mut request).expect("sent");
        let Sent::Acknowledged(ack) = sent else { panic!("{sent:?}") };
        (inputs, *request, ack)
    };
    let (x1, x11, x111, x2) = (format!("{x}.1"), format!("{x}.1.1"), format!("{x}.1.1.1"), format!("{x}.2"));
    assert_eq!(shot(&b, (addr(&x), 0), 2).2.member.to_string(), x1, "the birth version");
    assert_eq!(shot(&c, (addr(&x), 0), 4).2.member.to_string(), x11, "beside version 1, as its daughter");
    let moved = publication::draft_base(&p, &addr(&x), &addr(&c));
    assert_eq!(moved, Ok(publication::base::Base::Recorded { base: addr(&x11), copied: 4 }), "the board moved C's base to the daughter it made");
    assert_eq!(publication::standing(&p, &addr(&x), &addr(&x11)), Ok(publication::Standing::Behind), "a daughter is never the head, X.2 absent");
    insert_text(&board, &bare_token, &c, 5, " now");
    let (inputs, request, ack) = shot(&c, (addr(&x11), 4), 8);
    assert_eq!(ack.member.to_string(), x111, "the base's own daughter, as its standing told");
    let Answer::Document(probe) = board.op(Some(&token), &frames::doc_metadata(&x2)).expect("the read") else { panic!("closed") };
    assert_eq!(probe["code"].as_str(), Some("doc_not_registered"), "no trunk member X.2 minted: {probe}");
    assert_eq!(read(&board, &token, &frames::retrieve_v(&x, 1, 2))["items"][0]["content"], "ab", "the edition still reads version 1: a daughter moves no head");
    assert_eq!(read(&board, &token, &frames::retrieve_v(&x111, 1, 8))["items"][0]["content"], "wxyz now", "C's whole text in its daughter's daughter");
    let verdict = landed(&p, &inputs, &request, Base::Walk).expect("the landed test");
    assert!(matches!(&verdict, Verdict::Passed(found) if found.member.to_string() == x111 && found.via == AckVia::Walk), "the walk from the daughter finds the member the shot made: {verdict:?}");
    session.close().expect("close");
}

/// The ground the nested-run suites arrange on: an edition `E` holding `P`
/// at `E.1` and a staging draft arranging its words, then `W`, the draft's
/// ten new words, at 20. Answers `E`, `E.1` and the draft.
fn nesting_ground(board: &Board, session: &Session<'_>, signer: &HybridSigner, bare_token: &Token) -> (String, String, String) {
    let e = published_document(board, session, signer);
    let e1 = first_shot(board, session, signer, bare_token, &e, P);
    let d = mint(board, bare_token, ACCOUNT, false);
    copy(board, bare_token, &d, 1, &e1, 1, 19);
    insert_text(board, bare_token, &d, 20, W);
    (e, e1, d)
}

/// The inputs publishing `selection` from the draft `d` off `E.1`.
fn nesting_inputs(e: &str, e1: &str, d: &str, selection: Vec<Run>) -> Inputs {
    Inputs { doc: Some(addr(e)), mint: None, claim: false, base: Some((addr(e1), 19)), draft: addr(d), also: vec![], selection, notes: vec![], readable_drafts: vec![addr(d)], published: vec![addr(e)], supersede: vec![], merge_landing: false }
}

/// Builds the publication of `inputs` through the panel and the re-read,
/// which finds nothing moved.
fn confirmed_request(p: &Publisher<'_>, inputs: &Inputs) -> Box<publication::Request> {
    let en = enumerate(p, inputs).expect("enumerated");
    let pn = panel(p, inputs, &en).expect("the panel");
    let rr = reread(p, inputs, &en, &pn).expect("re-read");
    assert_eq!(rr.restatement, None, "nothing moved since the panel");
    let Built::Request(request) = build(p, inputs, &rr.enumeration, &rr.panel, &Confirmed::default()).expect("built") else { panic!("inert") };
    request
}

/// Sends `request` and answers its acknowledgment.
fn acknowledged(p: &Publisher<'_>, inputs: &Inputs, request: &mut publication::Request) -> publication::Ack {
    let sent = send(p, inputs, request).expect("sent");
    let Sent::Acknowledged(ack) = sent else { panic!("{sent:?}") };
    ack
}

/// The text `doc` reads over its first `width` positions.
fn text_of(board: &Board, token: &Token, doc: &str, width: u64) -> String {
    read(board, token, &frames::retrieve_v(doc, 1, width))["items"].as_array().expect("items").iter().filter_map(|item| item["content"].as_str()).collect()
}

/// `delete` of `width` positions of `doc` from ordinal `at`.
fn delete(board: &Board, token: &Token, doc: &str, at: u64, width: u64) {
    let as_of = crate::common::typed_at(board, token, doc);
    acked(board.op(Some(token), &json!({"op": "delete", "doc": doc, "p": {"subspace": "1", "ordinal": at.to_string()}, "width": width.to_string(), "as_of": as_of})));
}

/// Checks against the daemon that a held run nested in another takes a
/// place of its own and lands.
///
/// In each cell the draft arranges `E`'s words, `W` and a held run nested
/// in `W`, and the nested run takes the place the enclosing run leaves it,
/// whichever comes first in the selection: the board acknowledges, the
/// member holds every run and the draft is re-windowed onto the member's
/// identity at every place. The first cell's request, handed the nested
/// run's whole place inside the enclosing run's, is refused
/// `kept_place_moved` at that later entry, as `docs/wire.md` says of two
/// overlapping places in one list.
#[test]
fn a_nested_held_run_takes_its_own_place_and_lands() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(&dir.path().join("board"), true);
    let board = board(sd.port());
    let store = skep_client::store::FileStore::open(dir.path().join("store"));
    let fp = keygen(&store, "notebook");
    claim(&board, &store, &dir.path().join("anchors"));
    let device = store.load(&store.key_path(&fp)).expect("the device key").signer();
    let session = handshake(&board, Scope::Content, &device, PRINCIPAL, Site::Session).expect("a content session");
    let token = session.token().clone();
    let bare_token = bare(&board, PRINCIPAL);
    let p = Publisher { board: &board, token: &token, account: ACCOUNT, signer: &device };
    let ground = || nesting_ground(&board, &session, &device, &bare_token);

    // `D` 1..10 at 20, `D` 5..10 at 30.
    let (e, e1, d) = ground();
    copy(&board, &bare_token, &d, 30, &d, 24, 6);
    assert_eq!(image(&board, &bare_token, &d, 1, 35), vec![(format!("{e}.0.1.1"), 19), (format!("{d}.0.1.1"), 10), (format!("{d}.0.1.5"), 6)], "the premise");
    let inputs = nesting_inputs(&e, &e1, &d, vec![run(&e, 1, 19), run(&d, 1, 10), run(&d, 5, 6)]);
    let mut request = confirmed_request(&p, &inputs);
    assert_eq!(request.places, vec![None, Some(20), Some(30)]);
    let mut inside = request.clone();
    inside.places[2] = Some(24);
    inside.id = publication::fresh_id();
    let refused = send(&p, &inputs, &mut inside).expect("sent");
    assert!(matches!(&refused, Sent::Refused(Refusal::KeptPlaceMoved { index: 2, draft, .. }) if *draft == addr(&d)), "the later of two overlapping places: {refused:?}");
    let ack = acknowledged(&p, &inputs, &mut request);
    assert_eq!(ack.member.to_string(), format!("{e}.2"));
    let words = vec![(format!("{e}.0.1.1"), 29), (format!("{e}.0.1.24"), 6)];
    assert_eq!(image(&board, &token, &ack.member.to_string(), 1, 35), words, "the member holds both runs on the one fresh identity");
    assert_eq!(image(&board, &bare_token, &d, 1, 35), words, "the draft re-windowed at both places");
    assert_eq!(text_of(&board, &token, &ack.member.to_string(), 35), format!("{P}{W}{}", &W[4..]));

    // `D` 5..10 at 20, `D` 1..10 at 26, `D` 5..10 at 36: the enclosing run
    // between two copies, each copy clear of it.
    let (e, e1, d) = ground();
    copy(&board, &bare_token, &d, 20, &d, 24, 6);
    copy(&board, &bare_token, &d, 36, &d, 30, 6);
    assert_eq!(image(&board, &bare_token, &d, 1, 41), vec![(format!("{e}.0.1.1"), 19), (format!("{d}.0.1.5"), 6), (format!("{d}.0.1.1"), 10), (format!("{d}.0.1.5"), 6)], "the premise");
    let inputs = nesting_inputs(&e, &e1, &d, vec![run(&e, 1, 19), run(&d, 5, 6), run(&d, 1, 10), run(&d, 5, 6)]);
    let mut request = confirmed_request(&p, &inputs);
    assert_eq!(request.places, vec![None, Some(20), Some(26), Some(36)]);
    let ack = acknowledged(&p, &inputs, &mut request);
    assert_eq!(ack.member.to_string(), format!("{e}.2"));
    let words = vec![(format!("{e}.0.1.1"), 29), (format!("{e}.0.1.20"), 6), (format!("{e}.0.1.20"), 6)];
    assert_eq!(image(&board, &token, &ack.member.to_string(), 1, 41), words, "the member holds all three runs");
    assert_eq!(image(&board, &bare_token, &d, 1, 41), words, "the draft re-windowed at every place");
    assert_eq!(text_of(&board, &token, &ack.member.to_string(), 41), format!("{P}{}{W}{}", &W[4..], &W[4..]));

    // `D` 1..10 at 20, `D` 1..4 at 30: nested at the enclosing run's start.
    let (e, e1, d) = ground();
    copy(&board, &bare_token, &d, 30, &d, 20, 4);
    let inputs = nesting_inputs(&e, &e1, &d, vec![run(&e, 1, 19), run(&d, 1, 10), run(&d, 1, 4)]);
    let mut request = confirmed_request(&p, &inputs);
    assert_eq!(request.places, vec![None, Some(20), Some(30)]);
    let ack = acknowledged(&p, &inputs, &mut request);
    assert_eq!(ack.member.to_string(), format!("{e}.2"));
    let words = vec![(format!("{e}.0.1.1"), 29), (format!("{e}.0.1.20"), 4)];
    assert_eq!(image(&board, &token, &ack.member.to_string(), 1, 33), words, "the member holds both runs");
    assert_eq!(image(&board, &bare_token, &d, 1, 33), words, "the draft re-windowed at both places");
    assert_eq!(text_of(&board, &token, &ack.member.to_string(), 33), format!("{P}{W}{}", &W[..4]));

    // `D` 1..10 at 20, `D` 5..10 at 30, the nested run first in the selection.
    let (e, e1, d) = ground();
    copy(&board, &bare_token, &d, 30, &d, 24, 6);
    let inputs = nesting_inputs(&e, &e1, &d, vec![run(&e, 1, 19), run(&d, 5, 6), run(&d, 1, 10)]);
    let mut request = confirmed_request(&p, &inputs);
    assert_eq!(request.places, vec![None, Some(30), Some(20)], "the nested run clear of the enclosing one, whichever comes first");
    let ack = acknowledged(&p, &inputs, &mut request);
    assert_eq!(ack.member.to_string(), format!("{e}.2"));
    assert_eq!(image(&board, &token, &ack.member.to_string(), 1, 35), vec![(format!("{e}.0.1.1"), 29), (format!("{e}.0.1.20"), 6)], "the member holds both runs");
    assert_eq!(image(&board, &bare_token, &d, 1, 35), vec![(format!("{e}.0.1.1"), 19), (format!("{e}.0.1.26"), 4), (format!("{e}.0.1.20"), 6), (format!("{e}.0.1.20"), 6)], "the draft re-windowed at both places, reading as it did");
    assert_eq!(text_of(&board, &bare_token, &d, 35), format!("{P}{W}{}", &W[4..]));
    session.close().expect("close");
}

/// Checks against the daemon that a nested run with no place of its own
/// lands, covered by the run enclosing it.
///
/// The draft arranges the nested run only inside the run enclosing it, so
/// the request names no place for it. The board acknowledges, the member
/// holds both runs and the draft is re-windowed at the one place, the
/// enclosing run's re-window covering the nested run's words.
#[test]
fn a_nested_run_with_no_place_of_its_own_is_covered_by_the_run_enclosing_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(&dir.path().join("board"), true);
    let board = board(sd.port());
    let store = skep_client::store::FileStore::open(dir.path().join("store"));
    let fp = keygen(&store, "notebook");
    claim(&board, &store, &dir.path().join("anchors"));
    let device = store.load(&store.key_path(&fp)).expect("the device key").signer();
    let session = handshake(&board, Scope::Content, &device, PRINCIPAL, Site::Session).expect("a content session");
    let token = session.token().clone();
    let bare_token = bare(&board, PRINCIPAL);
    let p = Publisher { board: &board, token: &token, account: ACCOUNT, signer: &device };
    let (e, e1, d) = nesting_ground(&board, &session, &device, &bare_token);
    let inputs = nesting_inputs(&e, &e1, &d, vec![run(&e, 1, 19), run(&d, 1, 10), run(&d, 5, 6)]);
    let mut request = confirmed_request(&p, &inputs);
    assert_eq!(request.places, vec![None, Some(20), None], "the enclosing run keeps its place, the nested run takes none");
    let ack = acknowledged(&p, &inputs, &mut request);
    assert_eq!(ack.member.to_string(), format!("{e}.2"));
    assert_eq!(image(&board, &token, &ack.member.to_string(), 1, 35), vec![(format!("{e}.0.1.1"), 29), (format!("{e}.0.1.24"), 6)], "the member holds both runs");
    assert_eq!(image(&board, &bare_token, &d, 1, 29), vec![(format!("{e}.0.1.1"), 29)], "the draft re-windowed at the one place");
    assert_eq!(text_of(&board, &token, &ack.member.to_string(), 35), format!("{P}{W}{}", &W[4..]));
    session.close().expect("close");
}

/// Checks against the daemon that an `also` draft's kept places keep to the
/// same rule.
///
/// `A` renders the publication with `also: [D]`, arranging `D`'s ten words
/// by identity at 20 and its 5..10 again at 30. Where `D` arranges them the
/// same way, each draft's list places the nested run at 30; where `D`
/// arranges only the ten, `D`'s list names no place for it. The board
/// acknowledges each and re-windows every named draft at its own places.
#[test]
fn an_also_drafts_nested_runs_take_their_own_places() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(&dir.path().join("board"), true);
    let board = board(sd.port());
    let store = skep_client::store::FileStore::open(dir.path().join("store"));
    let fp = keygen(&store, "notebook");
    claim(&board, &store, &dir.path().join("anchors"));
    let device = store.load(&store.key_path(&fp)).expect("the device key").signer();
    let session = handshake(&board, Scope::Content, &device, PRINCIPAL, Site::Session).expect("a content session");
    let token = session.token().clone();
    let bare_token = bare(&board, PRINCIPAL);
    let p = Publisher { board: &board, token: &token, account: ACCOUNT, signer: &device };
    for (what, nested_in_d, d_places, d_after) in [("D arranges the nested run too", true, vec![None, Some(20), Some(30)], 35), ("D arranges the ten alone", false, vec![None, Some(20), None], 29)] {
        let (e, e1, d) = nesting_ground(&board, &session, &device, &bare_token);
        if nested_in_d {
            copy(&board, &bare_token, &d, 30, &d, 24, 6);
        }
        let rendering = mint(&board, &bare_token, ACCOUNT, false);
        copy(&board, &bare_token, &rendering, 1, &e1, 1, 19);
        copy(&board, &bare_token, &rendering, 20, &d, 20, 10);
        copy(&board, &bare_token, &rendering, 30, &d, 24, 6);
        assert_eq!(image(&board, &bare_token, &rendering, 1, 35), vec![(format!("{e}.0.1.1"), 19), (format!("{d}.0.1.1"), 10), (format!("{d}.0.1.5"), 6)], "{what}: the premise");
        let held = vec![run(&e, 1, 19), run(&d, 1, 10), run(&d, 5, 6)];
        let inputs = Inputs { draft: addr(&rendering), also: vec![addr(&d)], readable_drafts: vec![addr(&rendering), addr(&d)], ..nesting_inputs(&e, &e1, &d, held) };
        let mut request = confirmed_request(&p, &inputs);
        assert_eq!(request.places, vec![None, Some(20), Some(30)], "{what}: the rendering draft's list");
        assert_eq!(request.also_places, vec![AlsoPlaces { draft: addr(&d), places: d_places }], "{what}: D's own list, off D's image");
        let ack = acknowledged(&p, &inputs, &mut request);
        assert_eq!(ack.member.to_string(), format!("{e}.2"), "{what}");
        let words = vec![(format!("{e}.0.1.1"), 29), (format!("{e}.0.1.24"), 6)];
        assert_eq!(image(&board, &token, &ack.member.to_string(), 1, 35), words, "{what}: the member");
        assert_eq!(image(&board, &bare_token, &rendering, 1, 35), words, "{what}: the rendering draft re-windowed at both places");
        let d_words = if d_after == 35 { words } else { vec![(format!("{e}.0.1.1"), 29)] };
        assert_eq!(image(&board, &bare_token, &d, 1, d_after), d_words, "{what}: D re-windowed at its own places");
    }
    session.close().expect("close");
}

/// Checks against the daemon that a piece of a split run takes no place
/// inside another held run's.
///
/// The draft arranges `D` 1..10 at 20 and `D` 5..12 at 30, and `D`'s 11..12
/// are deleted after the panel. The re-read states the run as its two
/// pieces, one inside the enclosing run's place; the request places the
/// piece standing at a place of its own and names none for the other, and
/// the board acknowledges it.
#[test]
fn a_split_run_takes_no_place_inside_another_held_runs() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(&dir.path().join("board"), true);
    let board = board(sd.port());
    let store = skep_client::store::FileStore::open(dir.path().join("store"));
    let fp = keygen(&store, "notebook");
    claim(&board, &store, &dir.path().join("anchors"));
    let device = store.load(&store.key_path(&fp)).expect("the device key").signer();
    let session = handshake(&board, Scope::Content, &device, PRINCIPAL, Site::Session).expect("a content session");
    let token = session.token().clone();
    let bare_token = bare(&board, PRINCIPAL);
    let p = Publisher { board: &board, token: &token, account: ACCOUNT, signer: &device };
    let e = published_document(&board, &session, &device);
    let e1 = first_shot(&board, &session, &device, &bare_token, &e, P);
    let d = mint(&board, &bare_token, ACCOUNT, false);
    copy(&board, &bare_token, &d, 1, &e1, 1, 19);
    insert_text(&board, &bare_token, &d, 20, "abcdefghijkl");
    copy(&board, &bare_token, &d, 32, &d, 24, 8);
    delete(&board, &bare_token, &d, 30, 2);
    assert_eq!(image(&board, &bare_token, &d, 1, 37), vec![(format!("{e}.0.1.1"), 19), (format!("{d}.0.1.1"), 10), (format!("{d}.0.1.5"), 8)], "the premise");
    let inputs = nesting_inputs(&e, &e1, &d, vec![run(&e, 1, 19), run(&d, 1, 10), run(&d, 5, 8)]);
    let en = enumerate(&p, &inputs).expect("enumerated");
    let pn = panel(&p, &inputs, &en).expect("the panel");
    delete(&board, &bare_token, &d, 36, 2);
    let rr = reread(&p, &inputs, &en, &pn).expect("re-read");
    let restated = rr.restatement.expect("the run moved");
    assert_eq!(restated.selection, vec![(2, publication::Placement::Split(vec![(24, 5, 6), (30, 5, 6)]))], "its two pieces, the first inside the enclosing run's place");
    let again = reread(&p, &inputs, &rr.enumeration, &rr.panel).expect("re-read");
    assert_eq!(again.restatement, None);
    let Built::Request(mut request) = build(&p, &inputs, &again.enumeration, &again.panel, &Confirmed::default()).expect("built") else { panic!("inert") };
    assert_eq!(request.runs, vec![run(&e, 1, 19), run(&d, 1, 10), run(&d, 5, 6), run(&d, 5, 6)]);
    assert_eq!(request.places, vec![None, Some(20), None, Some(30)], "no place inside the enclosing run's");
    let ack = acknowledged(&p, &inputs, &mut request);
    assert_eq!(ack.member.to_string(), format!("{e}.2"));
    assert_eq!(image(&board, &token, &ack.member.to_string(), 1, 41), vec![(format!("{e}.0.1.1"), 29), (format!("{e}.0.1.24"), 6), (format!("{e}.0.1.24"), 6)], "the member holds every piece");
    assert_eq!(image(&board, &bare_token, &d, 1, 35), vec![(format!("{e}.0.1.1"), 29), (format!("{e}.0.1.24"), 6)], "the draft re-windowed at both places");
    session.close().expect("close");
}
