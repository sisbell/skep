use std::cell::{Cell, RefCell};
use std::rc::Rc;

use skep_address::Address;
use skep_identity::PublicKey;
use skep_signature::{HybridSigner, TAG_MLDSA65_ED25519};

use super::*;
use crate::http::{dial_http, Method, Transport, TransportError};
use crate::parse_address;

fn a(s: &str) -> Address {
    parse_address(s).unwrap()
}

fn key(seed: u8) -> PublicKey {
    HybridSigner::from_seed(TAG_MLDSA65_ED25519, &[seed; 32]).expect("tag 1").public_key().clone()
}

/// The hint every board here is opened under: one origin, no board behind
/// it, and a genesis fingerprint no realm check below ever reaches.
fn hint() -> RootHint {
    let genesis = Fingerprint::parse_hex(&"ab".repeat(32)).unwrap();
    RootHint::new(vec![Origin::parse("http://127.0.0.1:1").unwrap()], genesis, None).unwrap()
}

/// A mirror over `board` under `dir`, at no root: every read a pull, a fold
/// or a fetch makes, the board alone answers.
fn over(board: impl Transport + 'static, dir: &Path) -> Mirror {
    Mirror::fresh(&hint(), None, Some(Board::new(Box::new(board))), dir)
}

/// A 200 answer of `v`.
fn answer(v: Value) -> Result<(u16, Vec<u8>), TransportError> {
    Ok((200, v.to_string().into_bytes()))
}

/// A span over one address as `read_link` answers a slot.
fn span(start: &str) -> Value {
    json!({ "start": start, "width": "0.1" })
}

/// A `key_set` answer: `k` alone, the table as of `as_of`.
fn table(k: &PublicKey, as_of: u64) -> Value {
    json!({ "resp": "key_set", "as_of": as_of, "enrolled": [{ "alg": k.alg(), "key": k.to_hex(), "anchor": true }] })
}

/// The feed a [`Scripted`] board serves: at 5 a link of no type, at 6 an
/// enroll naming `1.0.2` — and no claim.
fn scripted_rows() -> [Value; 2] {
    [
        json!({ "at": 5, "op": "make_link", "link": "1.0.2.0.1.0.2.1", "docs": ["1.0.2.0.1"] }),
        json!({ "at": 6, "op": "make_link", "link": "1.0.2.0.1.0.2.2", "docs": ["1.0.2.0.1"] }),
    ]
}

/// A BOARD THE SUITE HOLDS FIXED: the two link rows of [`scripted_rows`] on
/// its feed, the enroll's `read_link` refused `refusals` times; `1.0.2`'s
/// live table answers as of 6, its table as of any earlier position is
/// `before`.
struct Scripted {
    refusals: Cell<u32>,
    asked: RefCell<Vec<String>>,
    live: PublicKey,
    before: PublicKey,
}

impl Transport for Scripted {
    fn exchange(&self, method: Method, path: &str, body: &[u8]) -> Result<(u16, Vec<u8>), TransportError> {
        self.asked.borrow_mut().push(format!("{method} {path}"));
        if let Some(since) = path.strip_prefix("/changes?since=") {
            let since: u64 = since.parse().expect("a position");
            let rows: Vec<Value> = scripted_rows().into_iter().filter(|r| position(r) > Some(since)).collect();
            let last = rows.last().and_then(position).unwrap_or(since);
            return answer(json!({ "changes": rows, "last": last, "more": false }));
        }
        if path == "/health" {
            return answer(json!({ "log_position": 6, "chain_head": "07".repeat(32) }));
        }
        let request: Value = serde_json::from_slice(body).expect("a JSON body");
        let (frame, at) = if path == "/op-at" { (&request["frame"], request["at"].as_u64()) } else { (&request, None) };
        match (frame["op"].as_str(), frame["a"].as_str(), at) {
            (Some("read_link"), Some("1.0.2.0.1.0.2.1"), None) => {
                answer(json!({ "resp": "link", "link": { "slots": [[span("1.0.2.0.1.0.1.1")], [], []] } }))
            }
            (Some("read_link"), Some("1.0.2.0.1.0.2.2"), None) if self.refusals.get() > 0 => {
                self.refusals.set(self.refusals.get() - 1);
                Ok((503, b"unavailable".to_vec()))
            }
            (Some("read_link"), Some("1.0.2.0.1.0.2.2"), None) => answer(json!({ "resp": "link", "link": { "slots": [
                [span("1.0.2.0.1.0.1.2")], [span("1.0.2")], [span("1.1.0.1.0.1.0.3.1")],
            ] } })),
            (Some("key_set"), None, None) => answer(table(&self.live, 6)),
            (Some("key_set"), None, Some(at)) => answer(table(&self.before, at)),
            _ => panic!("a read this board does not answer: {path} {request}"),
        }
    }
}

/// A SYNC THAT FAILED IS TAKEN UP WHERE IT STOPPED (REG-3.10): the two
/// rows the failed sync held are folded by the next, which asks the
/// board only past the copy's frontier and holds each row once; and
/// between the two, the credential pass having stopped short of the act
/// at 6, the live table answered as of 6 proves nothing of the table at
/// the head — it is read as of the head — while once the act is read it
/// does.
#[test]
fn a_sync_that_failed_is_taken_up_where_it_stopped() {
    let dir = tempfile::tempdir().expect("tempdir");
    let board = Rc::new(Scripted { refusals: Cell::new(1), asked: RefCell::new(Vec::new()), live: key(3), before: key(4) });
    let mut mirror = over(board.clone(), dir.path());
    let keys = |m: &mut Mirror| -> Vec<PublicKey> {
        m.current_keys(&a("1.0.2")).expect("read").expect("a table").into_iter().map(|e| e.key).collect()
    };
    assert!(matches!(mirror.sync(), Err(MirrorError::Board(BoardError::Status { status: 503, .. }))));
    assert_eq!((mirror.rows.len(), mirror.head), (2, 0), "held, and not folded");
    assert_eq!((mirror.held_through(), mirror.acts_through()), (6, 5));
    assert_eq!(keys(&mut mirror), [key(4)], "the act at 6 unread: the table as of the head, off /op-at");
    assert_eq!(mirror.sync(), Ok(2), "the two held rows folded, each once");
    assert_eq!((mirror.rows.len(), mirror.head, mirror.acts_through()), (2, 6, 6));
    let pulls: Vec<String> = board.asked.borrow().iter().filter(|r| r.contains("/changes")).cloned().collect();
    assert_eq!(pulls, ["GET /changes?since=0", "GET /changes?since=6"], "the second pull past the copy's frontier");
    assert_eq!(keys(&mut mirror), [key(3)], "the act read: the live table is the table at the head");
}

/// AN UNCLAIMED BOARD RESOLVES NOTHING: a feed that holds no claim through
/// the source's head opens no base, fresh or held — [`MirrorError::NoClaim`],
/// the realm never compared — and a base refused before its first line
/// writes nothing: no feed copy where none was, a held one byte for byte,
/// and a stray cache the directory held left as it was found.
#[test]
fn a_feed_with_no_claim_opens_no_base_and_writes_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let board = Rc::new(Scripted { refusals: Cell::new(0), asked: RefCell::new(Vec::new()), live: key(3), before: key(4) });
    let dial = |_: &Origin| -> Result<Box<dyn Transport>, TransportError> { Ok(Box::new(board.clone())) };
    let read = |name: &str| fs::read_to_string(dir.path().join(name)).expect("a file of the directory");
    let stray = json!({ "link": { "at": 1, "address": "1.0.9.0.1.0.2.1", "home": "1.0.9.0.1", "ty": null, "from": [], "to": [] } });
    let cache = format!("{stray}\n");
    fs::write(dir.path().join(FETCH_CACHE), &cache).expect("a stray cache");
    assert_eq!(Mirror::open(&hint(), dir.path(), &dial).unwrap_err(), MirrorError::NoClaim, "a fresh base");
    assert!(!dir.path().join(FEED_COPY).exists(), "no feed copy where none was");
    assert_eq!(read(FETCH_CACHE), cache, "the stray cache as it was found");
    let header = json!({ "skep-resolve": FEED_FORMAT, "realm": hint().realm().genesis.to_hex(), "root": null });
    let rows = scripted_rows().into_iter().map(|row| json!({ "row": row }));
    let held: String = std::iter::once(header).chain(rows).map(|line| format!("{line}\n")).collect();
    fs::write(dir.path().join(FEED_COPY), &held).expect("a held copy of the same feed");
    assert_eq!(Mirror::open(&hint(), dir.path(), &dial).unwrap_err(), MirrorError::NoClaim, "a held copy");
    assert_eq!(read(FEED_COPY), held, "the held copy byte for byte");
    assert_eq!(read(FETCH_CACHE), cache, "and the cache");
}

/// A BOARD THAT HAS RECLAIMED POSITION 6 (REG-3.15's floor): `1.0.2`'s live
/// table is `key(3)` as of 9, past what the mirrors below hold; `/op-at` at
/// 6 answers `history_reclaimed`, naming `floor` where one is given, and at
/// any other position `key(4)` as of it — every position asked recorded.
struct Reclaimed {
    floor: Option<u64>,
    asked: RefCell<Vec<u64>>,
}

impl Transport for Reclaimed {
    fn exchange(&self, method: Method, path: &str, body: &[u8]) -> Result<(u16, Vec<u8>), TransportError> {
        let request: Value = serde_json::from_slice(body).expect("a JSON body");
        match (method, path) {
            (Method::Post, "/op") if request["op"] == "key_set" => answer(table(&key(3), 9)),
            (Method::Post, "/op-at") if request["frame"]["op"] == "key_set" => {
                let at = request["at"].as_u64().expect("a position");
                self.asked.borrow_mut().push(at);
                if at != 6 {
                    return answer(table(&key(4), at));
                }
                let mut refusal = json!({ "error": "history_reclaimed" });
                if let Some(floor) = self.floor {
                    refusal["floor"] = json!(floor);
                }
                Ok((410, refusal.to_string().into_bytes()))
            }
            _ => panic!("a read this board does not answer: {method} {path} {request}"),
        }
    }
}

/// THE RECLAIM FLOOR (REG-3.15; the table as of the position): where the
/// board has reclaimed a record's position, the table is read at the floor
/// only where the floor lies inside the acts the mirror knows and no act of
/// the account lies in `(position, floor]` — an act at the floor itself
/// between, an act at the position not; a floor the board does not name is
/// the mirror's own frontier; elsewhere the table as of the position is gone
/// with the journal, UNDETERMINABLE HERE, and counted. The live table, as of
/// a position past what the mirror knows, is never the answer.
#[test]
fn a_reclaimed_position_is_read_at_the_floor_only_where_no_act_lies_between() {
    /// One read of `1.0.2`'s table as of 6: the account's acts and the floor
    /// the board names, against the table read, the positions `/op-at` was
    /// asked, and the reads counted at the floor and undeterminable.
    struct Case {
        acts: &'static [u64],
        floor: Option<u64>,
        opening: Option<Vec<PublicKey>>,
        asked: &'static [u64],
        counted: (u64, u64),
    }
    let dir = tempfile::tempdir().expect("tempdir");
    let cases = [
        Case { acts: &[5], floor: Some(7), opening: Some(vec![key(4)]), asked: &[6, 7], counted: (1, 0) },
        Case { acts: &[5, 7], floor: Some(7), opening: None, asked: &[6], counted: (0, 1) },
        Case { acts: &[5, 6], floor: Some(7), opening: Some(vec![key(4)]), asked: &[6, 7], counted: (1, 0) },
        Case { acts: &[5], floor: Some(9), opening: None, asked: &[6], counted: (0, 1) },
        Case { acts: &[5], floor: None, opening: Some(vec![key(4)]), asked: &[6, 8], counted: (1, 0) },
    ];
    for Case { acts, floor, opening, asked, counted } in cases {
        let board = Rc::new(Reclaimed { floor, asked: RefCell::new(Vec::new()) });
        let mut mirror = over(board.clone(), dir.path());
        // The acts are known through 8: one row held, the credential pass
        // through it.
        mirror.rows = vec![json!({ "at": 8, "op": "publish", "docs": [] })];
        mirror.scanned = 1;
        mirror.epochs.insert(a("1.0.2"), acts.to_vec());
        let case = format!("acts {acts:?}, floor {floor:?}");
        let read = mirror.keys_opening(&a("1.0.2"), 6).expect("read");
        assert_eq!(read.map(|keys| keys.into_iter().map(|e| e.key).collect::<Vec<_>>()), opening, "{case}");
        assert_eq!(*board.asked.borrow(), asked, "{case}");
        assert_eq!((mirror.stats.reads_at_floor, mirror.stats.reclaimed_undeterminable), counted, "{case}");
    }
}

/// A BOARD WHOSE FIRST PAGE PASSES THE BYTE BUDGET (wire.md §The change
/// feed, Paging): `since=0` asked with no limit is refused `400
/// malformed_changes` naming `fits` 0, and served a row a page at `limit=1`
/// — a `publish` at 5, then one at 6 — every request recorded; any other
/// page is refused, naming no `fits`.
struct Paged {
    asked: RefCell<Vec<String>>,
}

impl Transport for Paged {
    fn exchange(&self, method: Method, path: &str, _: &[u8]) -> Result<(u16, Vec<u8>), TransportError> {
        self.asked.borrow_mut().push(format!("{method} {path}"));
        let page = |at: u64, member: &str, more: bool| {
            answer(json!({ "changes": [{ "at": at, "op": "publish", "docs": [member] }], "last": at, "more": more }))
        };
        let refused = |v: Value| Ok((400, v.to_string().into_bytes()));
        match path {
            "/changes?since=0" => refused(json!({ "error": "malformed_changes", "budget": 2_097_152, "fits": 0 })),
            "/changes?since=0&limit=1" => page(5, "1.0.2.0.1.1", true),
            "/changes?since=5&limit=1" | "/changes?since=5" => page(6, "1.0.2.0.1.2", false),
            "/health" => answer(json!({ "log_position": 6, "chain_head": "07".repeat(32) })),
            _ => refused(json!({ "error": "malformed_changes" })),
        }
    }
}

/// THE PAGE BYTE BUDGET (wire.md §The change feed, Paging): a page refused
/// past its budget is asked again at the limit the feed names — never at
/// `limit=0`, which the wire refuses, where the feed names `fits` 0 — by the
/// pull and by the resume's check alike, and the rows it serves are held and
/// folded as any page's are.
#[test]
fn a_page_past_the_byte_budget_is_re_asked_at_the_limit_the_feed_names() {
    let dir = tempfile::tempdir().expect("tempdir");
    let board = Rc::new(Paged { asked: RefCell::new(Vec::new()) });
    let mut mirror = over(board.clone(), dir.path());
    let first_two = || board.asked.borrow().iter().take(2).cloned().collect::<Vec<_>>();
    let re_asked = ["GET /changes?since=0", "GET /changes?since=0&limit=1"];
    assert_eq!(mirror.sync(), Ok(2), "both rows held and folded");
    assert_eq!(first_two(), re_asked, "the pull");
    assert_eq!(mirror.chain_members_of(&a("1.0.2.0.1")), [a("1.0.2.0.1.1"), a("1.0.2.0.1.2")]);
    board.asked.borrow_mut().clear();
    let rows = mirror.rows.clone();
    assert_eq!(mirror.check_against_source(&rows, &[]), Ok(()), "the source answers every held row");
    assert_eq!(first_two(), re_asked, "the resume's check");
}

/// A BOARD WHOSE HOME `1.0.2.0.1` ARRANGES `…0.1.2` NOWHERE AT ITS HEAD: the
/// head arranges `…0.1.9` alone and the home's chain has no member; as of
/// position 7 the home arranged `…0.1.9` then `…0.1.2` where `places`, and
/// is refused otherwise. Any other read — a value read at the head, or one
/// at another V-ordinal or another position — is no read this board
/// answers.
struct Unarranged {
    places: bool,
}

impl Transport for Unarranged {
    fn exchange(&self, method: Method, path: &str, body: &[u8]) -> Result<(u16, Vec<u8>), TransportError> {
        let request: Value = serde_json::from_slice(body).expect("a JSON body");
        let (frame, at) = if path == "/op-at" { (&request["frame"], request["at"].as_u64()) } else { (&request, None) };
        let doc = frame["doc"].as_str().or(frame["d"].as_str()).or(frame["specs"][0]["doc"].as_str());
        let runs = |starts: &[&str]| {
            json!({ "resp": "runs", "runs": starts.iter().map(|s| json!({ "i_start": s, "width": "1" })).collect::<Vec<_>>() })
        };
        let set = |width: &str| json!({ "resp": "span_set", "set": [{ "start": "1.1", "width": width }] });
        let refused = json!({ "resp": "rejected", "op": frame["op"], "code": "doc_not_registered" });
        let at_ordinal_2 = frame["specs"][0]["span"]["start"] == "1.2";
        assert_eq!(method, Method::Post, "{path}");
        match (frame["op"].as_str(), doc, at) {
            (Some("image"), Some("1.0.2.0.1"), None) => answer(runs(&["1.0.2.0.1.0.1.9"])),
            (Some("retrieve_doc_v_span_set"), Some("1.0.2.0.1"), None) => answer(set("0.1")),
            (Some("retrieve_doc_v_span_set"), Some(_), None) => answer(refused),
            (Some("retrieve_doc_v_span_set"), Some("1.0.2.0.1"), Some(7)) if self.places => answer(set("0.2")),
            (Some("retrieve_doc_v_span_set"), Some("1.0.2.0.1"), Some(7)) => answer(refused),
            (Some("image"), Some("1.0.2.0.1"), Some(7)) => answer(runs(&["1.0.2.0.1.0.1.9", "1.0.2.0.1.0.1.2"])),
            (Some("retrieve_v"), Some("1.0.2.0.1"), Some(7)) if at_ordinal_2 => {
                answer(json!({ "resp": "delivery", "items": [{ "atom": "the bytes as of 7" }] }))
            }
            _ => panic!("a read this board does not answer: {path} {request}"),
        }
    }
}

/// THE POSITION READ (REG-3.26), the last recourse: an atom its home's head
/// does not arrange and no version of the home holds is read as of its
/// link's position through `/op-at` — the extent, the image, the value at
/// the V-ordinal that image places it — kept, and counted; where the home
/// as of that position arranges nothing either, there are no bytes.
#[test]
fn an_atom_no_version_holds_is_read_as_of_its_links_position() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (home, atom) = (a("1.0.2.0.1"), a("1.0.2.0.1.0.1.2"));
    let mut mirror = over(Unarranged { places: true }, dir.path());
    assert_eq!(mirror.fetch_atom(7, &home, &atom), Ok(Some("the bytes as of 7".to_string())));
    assert_eq!(mirror.stats.chain_walk.position_reads, 1);
    assert_eq!(mirror.fetched.atoms.get(&atom).map(String::as_str), Some("the bytes as of 7"), "kept");
    let mut mirror = over(Unarranged { places: false }, dir.path());
    assert_eq!(mirror.fetch_atom(7, &home, &atom), Ok(None), "the home as of 7 arranges nothing");
    assert_eq!(mirror.stats.chain_walk.position_reads, 0);
}

/// NO ROOT ANSWERED: every origin the hint names is named beside its own
/// error, in the hint's order — an `https` origin a transport this build
/// does not hold, an `http` one whose board is down — so a caller tells
/// the two apart by type and never by text; and nothing is written. The
/// board that is down listens at port 1, which no ephemeral bind is ever
/// handed — a port freed by a dropped listener can be the next bind's, and
/// answer.
#[test]
fn every_origin_tried_is_named_beside_its_own_error() {
    let dir = tempfile::tempdir().expect("tempdir");
    let https = Origin::parse("https://registry.example").unwrap();
    let down = Origin::parse("http://127.0.0.1:1").unwrap();
    let genesis = Fingerprint::parse_hex(&"ab".repeat(32)).unwrap();
    let hint = RootHint::new(vec![https.clone(), down.clone()], genesis, None).unwrap();
    let refused = Mirror::open(&hint, dir.path(), &dial_http).unwrap_err();
    assert!(refused.to_string().starts_with("no root answered: https://registry.example: no transport held for https origins, http://"), "{refused}");
    let tried = match refused {
        MirrorError::Unreachable { tried } => tried,
        other => panic!("no root answers: {other:?}"),
    };
    assert_eq!(tried[0], (https, BoardError::Transport(TransportError::NotHeld("https".into()))));
    assert_eq!(tried[1].0, down);
    assert!(matches!(tried[1].1, BoardError::Transport(TransportError::Connect(_))), "{:?}", tried[1].1);
    assert_eq!(tried.len(), 2);
    assert!(!dir.path().join(FEED_COPY).exists(), "nothing written");
}
