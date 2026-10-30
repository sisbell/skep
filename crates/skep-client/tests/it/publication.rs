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
//! re-send read as the acknowledgment, and `kept_place_moved` after a move
//! with its re-statement.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write as _;

use serde_json::{json, Value};
use skep_address::{Address, Nat, Span, Tumbler};
use skep_client::address::{document_of, parse_address};
use skep_client::board::frames::{self, T_HELD_REMOVAL, T_READ_WITH};
use skep_client::board::{acked_addr, Answer, Board, ChangesAnswer, ChangesQuery, Scope, Token, T_RETRACTION};
use skep_client::ceremony::handshake::{handshake, Session, Site};
use skep_client::publication::{self, build, count, enumerate, landed, panel, reread, send, AckVia, Base, Built, Confirmed, Destination, Inputs, OriginAnswer, Publisher, Refusal, RowKind, Run, Sent, Switches, Verdict};
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
    let frame = json!({"op": "copy", "doc": doc, "at": {"subspace": "1", "ordinal": at.to_string()}, "specs": [{"source": source, "span": {"start": format!("1.{from}"), "width": format!("0.{width}")}}]});
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
    // The edition's own published mark, and the held removal of it in D.
    let mpub = make_link(board, session, bare_token, signer, &e1, true, End::Addrs(vec![]), spec(&e1, 5, 5, &e, 5), T_STRONG);
    let held = make_link(board, session, bare_token, signer, &d, false, End::Addrs(vec![]), End::Addrs(vec![&mpub]), T_HELD_REMOVAL);
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
    Seeded { e, e1, s, s2, d, n, o, z, mark_d, heading_d, cite_d, l1_n, whole_n, k_s, k2_s2, mpub, held, sub_link }
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
/// per candidate; each claim's `new` read for its home and its FROM; the
/// candidate dropped where some successor is homed in a published document
/// of the claimant's AND covers the candidate's positions on the selection —
/// the keys as the daemon's suite reads them (its liveness key, struck by
/// sweep 5 S1, left out: nothing here is retracted). Grouped by home, in the
/// order the homes answer.
fn offered_oracle(board: &Board, token: &Token, doc: &str, from: u64, width: u64) -> Vec<(String, Vec<String>)> {
    let expand = |start: &str, w: u64| -> Vec<String> {
        let (prefix, first) = start.rsplit_once('.').unwrap();
        let first: u64 = first.parse().unwrap();
        (first..first + w).map(|k| format!("{prefix}.{k}")).collect()
    };
    let selection: BTreeSet<String> = image(board, token, doc, from, width).iter().flat_map(|(s, w)| expand(s, *w)).collect();
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
            let from_end = slot_addresses(&read(board, token, &frames::read_link(new))["link"]["slots"][0]);
            new_owner == ACCOUNT && new_published && !on_selection.is_empty() && on_selection.is_subset(&from_end)
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
    }
}

/// The switches: the draft's own set into the member, the notes into `S2`;
/// the window onto `O` kept private.
fn confirmed(seeded: &Seeded) -> Confirmed {
    let mut switches = Switches::default();
    switches.on.insert(addr(&seeded.d));
    switches.on.insert(addr(&seeded.n));
    switches.destinations.insert(addr(&seeded.n), Destination::Set(addr(&seeded.s2)));
    let mut answers = BTreeMap::new();
    answers.insert(2, OriginAnswer::KeepPrivate);
    Confirmed { switches, answers }
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
    let oracle = offered_oracle(&board, &token, d, 1, 34);
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
    // with no counterpart (no record of a draft the person reads names it).
    assert_eq!(pn.windows.len(), 1, "{:?}", pn.windows);
    assert_eq!((pn.windows[0].run, pn.windows[0].origin.to_string(), pn.windows[0].owner.as_str(), pn.windows[0].i_start, pn.windows[0].width, pn.windows[0].counterpart.is_none()), (2, o.clone(), ACCOUNT, 1, 5, true));
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
    assert_eq!(request.read_with, vec![addr(s2)]);
    assert_eq!(request.entries.len(), 4, "the line's two marks, the citation, the note");
    let frame = request.frame(None);
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
    let _ = e1;
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
    let inputs = Inputs { doc: Some(addr(&e)), mint: None, claim: false, base: Some((addr(&e1), 19)), draft: addr(&d), also: vec![], selection: vec![run(&d, 2, 2)], notes: vec![], readable_drafts: vec![addr(&d)], published: vec![addr(&e)] };
    let en = enumerate(&p, &inputs).unwrap();
    assert_eq!(en.placed, vec![publication::Placement::Whole { ordinal: 2 }]);
    let pn = panel(&p, &inputs, &en).unwrap();
    let Built::Request(mut request) = build(&p, &inputs, &en, &pn, &Confirmed::default()).unwrap() else { panic!("inert") };
    assert_eq!(request.places, vec![Some(2)]);
    // The move: `y` and `x` swapped after the place was read.
    acked(board.op(Some(&bare_token), &json!({"op": "rearrange", "doc": d, "cuts": [{"subspace": "1", "ordinal": "1"}, {"subspace": "1", "ordinal": "2"}, {"subspace": "1", "ordinal": "3"}]})));
    let sent = send(&p, &inputs, &mut request).expect("sent");
    let Sent::Refused(Refusal::KeptPlaceMoved { index, race }) = sent else { panic!("{sent:?}") };
    assert_eq!(index, 0);
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
    let inputs = Inputs { doc: Some(addr(&e)), mint: None, claim: false, base: Some((addr(&e1), 1000)), draft: addr(&d), also: vec![], selection: vec![run(&e, 1, 1000), run(&d, 1, 4)], notes: vec![addr(&n)], readable_drafts: vec![addr(&d), addr(&n)], published: vec![addr(&e), addr(&s)] };
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
/// passage; the request carries `also`; the acknowledgment names `E.2`,
/// whose text is `A`'s whole; and the records are read back in BOTH drafts,
/// `D`'s for its ten words and `A`'s for its six, each `to` the member's
/// fresh identity; the feed row names the member, `A` and `D`.
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
    assert_eq!(pn.windows, vec![], "D's run is re-minted, not windowed");
    assert_eq!(pn.inherited, vec![publication::Inherited { draft: addr(d), passages: 1 }]);
    let Built::Request(mut request) = build(&p, &inputs, &en, &pn, &Confirmed::default()).expect("built") else { panic!("inert") };
    assert_eq!(request.also, vec![addr(d)]);
    assert_eq!(request.places, vec![None, None, Some(30)], "a kept place for the rendering draft's run alone");
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
    assert_eq!(image(&board, &bare_token, d, 20, 10), vec![(format!("{d}.0.1.1"), 10)], "D is not re-windowed: its words stay its own, a counterpart through its record");
    sd.shutdown();
}
