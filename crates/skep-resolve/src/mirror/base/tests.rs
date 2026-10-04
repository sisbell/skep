use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::rc::Rc;

use skep_address::Address;
use skep_identity::PublicKey;
use skep_registry::{commons_type, t_endpoint, MAX_REGISTRY_RECORD_BYTES};
use skep_signature::{HybridSigner, TAG_MLDSA65_ED25519};

use super::*;
use crate::board::unit_span_json;
use crate::http::{dial_http, Method, Transport, TransportError};
use crate::mirror::StoredLink;
use crate::parse_address;
use crate::state::{EndpointRecord, Judged, Verdict};

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
                [span("1.0.2.0.1.0.1.2")], [span("1.0.2")], [unit_span_json(&commons_type(&[1]))],
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

/// A link's slots as `read_link` serves them: its `from` atom, its `to` as
/// named, its type's unit span.
fn slots(from: &str, to: &[&str], ty: &Address) -> Value {
    json!([[span(from)], to.iter().map(|t| span(t)).collect::<Vec<_>>(), [unit_span_json(ty)]])
}

/// A CLAIMED BOARD THE SUITE HOLDS FIXED: a `make_link` row per `(at, link,
/// home, slots)` on its feed, each link served with its slots; an account's
/// table from a position on per `history` — the latest at or below the
/// position asked, as of it on `/op-at` and as of the feed's head live.
/// Every request recorded.
struct Claimed {
    rows: Vec<Value>,
    links: BTreeMap<String, Value>,
    history: Vec<(&'static str, u64, Vec<PublicKey>)>,
    asked: RefCell<Vec<String>>,
}

fn claimed(links: Vec<(u64, &str, &str, Value)>, history: Vec<(&'static str, u64, Vec<PublicKey>)>) -> Rc<Claimed> {
    let rows = links.iter().map(|(at, link, home, _)| json!({ "at": at, "op": "make_link", "link": link, "docs": [home] })).collect();
    let links = links.into_iter().map(|(_, link, _, slots)| (link.to_string(), slots)).collect();
    Rc::new(Claimed { rows, links, history, asked: RefCell::new(Vec::new()) })
}

impl Transport for Claimed {
    fn exchange(&self, method: Method, path: &str, body: &[u8]) -> Result<(u16, Vec<u8>), TransportError> {
        self.asked.borrow_mut().push(format!("{method} {path}"));
        let head = self.rows.last().and_then(position).unwrap_or(0);
        if let Some(since) = path.strip_prefix("/changes?since=") {
            let since: u64 = since.parse().expect("a position");
            let rows: Vec<&Value> = self.rows.iter().filter(|r| position(r) > Some(since)).collect();
            let last = rows.last().and_then(|r| position(r)).unwrap_or(since);
            return answer(json!({ "changes": rows, "last": last, "more": false }));
        }
        if path == "/health" {
            return answer(json!({ "log_position": head, "chain_head": "07".repeat(32) }));
        }
        let request: Value = serde_json::from_slice(body).expect("a JSON body");
        let (frame, at) = if path == "/op-at" { (&request["frame"], request["at"].as_u64()) } else { (&request, None) };
        match frame["op"].as_str() {
            Some("read_link") => {
                let slots = self.links.get(frame["a"].as_str().expect("a link")).expect("a link this board holds");
                answer(json!({ "resp": "link", "link": { "slots": slots } }))
            }
            Some("key_set") => {
                let as_of = at.unwrap_or(head);
                let account = frame["account"].as_str().expect("an account");
                let held = self.history.iter().rev().find(|(acct, from, _)| *acct == account && *from <= as_of);
                let enrolled: Vec<Value> = held.map(|(_, _, keys)| keys.as_slice()).unwrap_or_default().iter()
                    .map(|k| json!({ "alg": k.alg(), "key": k.to_hex(), "anchor": true }))
                    .collect();
                answer(json!({ "resp": "key_set", "as_of": as_of, "enrolled": enrolled }))
            }
            _ => panic!("a read this board does not answer: {path} {request}"),
        }
    }
}

/// The genesis fingerprint of the set holding `key(seed)` alone.
fn genesis_of(seed: u8) -> Fingerprint {
    RealmId::genesis_fingerprint(&[Fingerprint::of(&key(seed))])
}

/// A hint naming `genesis`, at an origin [`claimed_dial`] answers.
fn hint_of(genesis: Fingerprint) -> RootHint {
    RootHint::new(vec![Origin::parse("http://127.0.0.1:1").unwrap()], genesis, None).unwrap()
}

/// A dial that answers every origin with `board`.
fn claimed_dial(board: &Rc<Claimed>) -> impl Fn(&Origin) -> Result<Box<dyn Transport>, TransportError> {
    let board = board.clone();
    move |_: &Origin| -> Result<Box<dyn Transport>, TransportError> { Ok(Box::new(board.clone())) }
}

/// A copy held under `dir` — its header naming `genesis`, `board`'s rows —
/// and a fetch cache of `cache`'s lines: both files as written.
fn hold(dir: &Path, genesis: Fingerprint, board: &Claimed, cache: &[Value]) -> (String, String) {
    let header = json!({ "skep-resolve": FEED_FORMAT, "realm": genesis.to_hex(), "root": null });
    let rows = board.rows.iter().map(|row| json!({ "row": row }));
    let feed: String = std::iter::once(header).chain(rows).map(|line| format!("{line}\n")).collect();
    let cache: String = cache.iter().map(|line| format!("{line}\n")).collect();
    fs::write(dir.join(FEED_COPY), &feed).expect("the feed copy");
    fs::write(dir.join(FETCH_CACHE), &cache).expect("the fetch cache");
    (feed, cache)
}

/// The board of the claim cells below: at 1 `1.0.1`'s genesis enroll, at 2
/// its claim, at 3 `1.0.2`'s genesis enroll, each in its own doc 1; and,
/// with `rotated`, `1.0.1` enrolling a second key at 4 and retiring its
/// genesis key at 5 — `1.0.1`'s genesis set `key(1)`, `1.0.2`'s `key(2)`.
fn claim_board(rotated: bool) -> Rc<Claimed> {
    let (enroll, retire, claim) = (commons_type(&[1]), commons_type(&[2]), commons_type(&[3]));
    let mut links = vec![
        (1, "1.0.1.0.1.0.2.1", "1.0.1.0.1", slots("1.0.1.0.1.0.1.1", &["1.0.1"], &enroll)),
        (2, "1.0.1.0.1.0.2.2", "1.0.1.0.1", slots("1.0.1", &[], &claim)),
        (3, "1.0.2.0.1.0.2.1", "1.0.2.0.1", slots("1.0.2.0.1.0.1.1", &["1.0.2"], &enroll)),
    ];
    let mut history = vec![("1.0.1", 1, vec![key(1)]), ("1.0.2", 3, vec![key(2)])];
    if rotated {
        links.push((4, "1.0.1.0.1.0.2.3", "1.0.1.0.1", slots("1.0.1.0.1.0.1.2", &["1.0.1"], &enroll)));
        links.push((5, "1.0.1.0.1.0.2.4", "1.0.1.0.1", slots("1.0.1.0.1.0.1.3", &["1.0.1"], &retire)));
        history.extend([("1.0.1", 4, vec![key(1), key(2)]), ("1.0.1", 5, vec![key(2)])]);
    }
    claimed(links, history)
}

/// THE CLAIMANT IS THE BOARD'S WORD (REG-3.42): a held copy whose fetch
/// cache names another claimant at the claim's link — `1.0.2`, whose genesis
/// set the copy's header names, so a realm compared for it would pass — is
/// refused at the claim, the realm compared for the claimant the board's
/// own link names; and nothing is written.
#[test]
fn a_cache_naming_another_claimant_is_refused_at_the_claim() {
    let dir = tempfile::tempdir().expect("tempdir");
    let board = claim_board(false);
    let claim = StoredLink {
        at: 2,
        address: a("1.0.1.0.1.0.2.2"),
        home: a("1.0.1.0.1"),
        ty: Some(commons_type(&[3])),
        from: vec![a("1.0.2")],
        to: Vec::new(),
    };
    let forged = Fetched::default().keep_link(claim).expect("a line");
    let held = hold(dir.path(), genesis_of(2), &board, &[forged]);
    let refused = Mirror::open(&hint_of(genesis_of(2)), dir.path(), &claimed_dial(&board)).unwrap_err();
    assert_eq!(refused, MirrorError::Refused(Refusal::RealmMismatch { expected: genesis_of(2), found: genesis_of(1) }));
    let read = |name: &str| fs::read_to_string(dir.path().join(name)).expect("a file of the copy");
    assert_eq!((read(FEED_COPY), read(FETCH_CACHE)), held, "nothing written");
}

/// THE GENESIS ACT IS THE BOARD'S WORD (REG-3.42; REG-3.39: the genesis set,
/// never the living one): a held copy whose fetch cache types neither
/// `1.0.1`'s genesis enroll nor its later one — so the first act of the
/// claimant it holds is the retire at 5, after which the claimant's living
/// set is the one the copy's header names — is refused at the claim, the
/// genesis set read at the genesis act the board answered; and nothing is
/// written.
#[test]
fn a_cache_hiding_the_genesis_act_is_refused_at_the_claim() {
    let dir = tempfile::tempdir().expect("tempdir");
    let board = claim_board(true);
    let untyped = |at: u64, link: &str| StoredLink { at, address: a(link), home: a("1.0.1.0.1"), ty: None, from: Vec::new(), to: Vec::new() };
    let mut kept = Fetched::default();
    let hidden = [kept.keep_link(untyped(1, "1.0.1.0.1.0.2.1")), kept.keep_link(untyped(4, "1.0.1.0.1.0.2.3"))].map(|l| l.expect("a line"));
    let held = hold(dir.path(), genesis_of(2), &board, &hidden);
    let refused = Mirror::open(&hint_of(genesis_of(2)), dir.path(), &claimed_dial(&board)).unwrap_err();
    assert_eq!(refused, MirrorError::Refused(Refusal::RealmMismatch { expected: genesis_of(2), found: genesis_of(1) }));
    let read = |name: &str| fs::read_to_string(dir.path().join(name)).expect("a file of the copy");
    assert_eq!((read(FEED_COPY), read(FETCH_CACHE)), held, "nothing written");
}

/// ONE CLAIM (AUTH-2.68: a board admits one, a second `already_claimed`): a
/// claim row past the one the realm was compared for — `1.0.2`'s, in its own
/// doc 1 — moves nothing: the claim stays the board's first, its claimant
/// the binding home, online and in the copy rebuilt offline alike.
#[test]
fn a_claim_past_the_one_compared_moves_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (enroll, claim) = (commons_type(&[1]), commons_type(&[3]));
    let board = claimed(
        vec![
            (1, "1.0.1.0.1.0.2.1", "1.0.1.0.1", slots("1.0.1.0.1.0.1.1", &["1.0.1"], &enroll)),
            (2, "1.0.1.0.1.0.2.2", "1.0.1.0.1", slots("1.0.1", &[], &claim)),
            (4, "1.0.2.0.1.0.2.2", "1.0.2.0.1", slots("1.0.2", &[], &claim)),
        ],
        vec![("1.0.1", 1, vec![key(1)])],
    );
    let hint = hint_of(genesis_of(1));
    let mirror = Mirror::open(&hint, dir.path(), &claimed_dial(&board)).expect("opened");
    assert_eq!(mirror.claim(), Some((2, &a("1.0.1"))), "the board's first claim");
    drop(mirror);
    let offline = Mirror::rebuild_offline(&hint, dir.path()).expect("rebuilt");
    assert_eq!(offline.claim(), Some((2, &a("1.0.1"))), "and the copy's");
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
        mirror.credential_acts.insert(a("1.0.2"), acts.to_vec());
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

/// AN OFFLINE REBUILD HOLDS THE COPY TO THE FEED'S OWN ORDER (wire.md §The
/// change feed, Paging), which no source check holds it to there: a copy
/// whose rows re-serve a position, re-order two, or name none is refused,
/// never folded out of order; rows that rise are rebuilt, the head the last.
#[test]
fn an_offline_rebuild_refuses_rows_that_do_not_rise() {
    let dir = tempfile::tempdir().expect("tempdir");
    let copy = |ats: &[Option<u64>]| {
        let header = json!({ "skep-resolve": FEED_FORMAT, "realm": hint().realm().genesis.to_hex(), "root": null });
        let rows = ats.iter().map(|at| {
            let mut row = json!({ "op": "publish", "docs": [] });
            if let Some(at) = at {
                row["at"] = json!(at);
            }
            json!({ "row": row })
        });
        let feed: String = std::iter::once(header).chain(rows).map(|line| format!("{line}\n")).collect();
        fs::write(dir.path().join(FEED_COPY), feed).expect("the feed copy");
        Mirror::rebuild_offline(&hint(), dir.path())
    };
    for (ats, case) in [
        (&[Some(5), Some(5)][..], "a position re-served"),
        (&[Some(6), Some(5)][..], "two rows re-ordered"),
        (&[Some(5), None][..], "a row naming none"),
    ] {
        assert!(matches!(copy(ats), Err(MirrorError::Copy(_))), "{case}");
    }
    assert_eq!(copy(&[Some(5), Some(6)]).map(|mirror| mirror.head()), Ok(6), "rows that rise");
}

/// THE ROOT BEFORE THE COPY: where no origin answers and the directory holds
/// a copy that does not read, the open is refused for the root — the root is
/// dialed before the copy is read — and the copy is left as it was found.
#[test]
fn no_root_answering_speaks_before_a_copy_that_does_not_read() {
    let dir = tempfile::tempdir().expect("tempdir");
    let unstamped = format!("{}\n", json!({ "realm": hint().realm().genesis.to_hex() }));
    fs::write(dir.path().join(FEED_COPY), &unstamped).expect("a copy of no format");
    let down = |_: &Origin| -> Result<Box<dyn Transport>, TransportError> { Err(TransportError::Connect("down".into())) };
    assert!(matches!(Mirror::open(&hint(), dir.path(), &down), Err(MirrorError::Unreachable { .. })));
    assert_eq!(fs::read_to_string(dir.path().join(FEED_COPY)).expect("the copy"), unstamped, "as it was found");
}

/// A BOARD WHERE A FORGED RETRACTION STANDS: an account's own link in its
/// own doc 1, typed `1.1.0.1.0.1.0.1` — a prefix of the retraction class's
/// address, another class `make_link` admits — and naming the node, so it
/// overlaps every link of the retraction's type and target a query asks
/// for, and such a query answers it. The board's active view, asked for
/// the deposit by its home, its type and its atom, answers `active`. Every
/// query asked is kept.
struct ActiveView {
    active: Value,
    asked: RefCell<Vec<Value>>,
}

impl Transport for ActiveView {
    fn exchange(&self, method: Method, path: &str, body: &[u8]) -> Result<(u16, Vec<u8>), TransportError> {
        assert_eq!((method, path), (Method::Post, "/op"));
        let frame: Value = serde_json::from_slice(body).expect("a frame");
        assert_eq!(frame["op"], "find_links_ftt", "a read this board does not answer: {frame}");
        self.asked.borrow_mut().push(frame["q"].clone());
        if frame["q"]["ty"][0]["start"] == "1.1.0.1.0.1.0.1.5" {
            return answer(json!({ "resp": "addrs", "addrs": ["1.0.9.0.1.0.2.1"] }));
        }
        answer(self.active.clone())
    }
}

/// A RETRACTION IS THE BOARD'S OWN READING (REG-1.11): a deposit leaves the
/// active view where the board's active links of its home, its type and its
/// atom answer it no longer — the org's own `nullify` — and never where a
/// link of the retraction's type is found, which any account's link of
/// another class overlaps; a refusal takes nothing off the view. A deposit
/// found off the view is kept at the `nullify`'s row, a standing one never.
#[test]
fn a_link_of_another_class_takes_no_deposit_off_the_view() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (deposit, home, atom) = (a("1.0.2.0.1.0.2.1"), a("1.0.2.0.1"), a("1.0.2.0.1.0.1.1"));
    let stored = StoredLink { at: 7, address: deposit.clone(), home: home.clone(), ty: Some(t_endpoint().clone()), from: vec![atom.clone()], to: Vec::new() };
    let asked = |active: Value| {
        let board = Rc::new(ActiveView { active, asked: RefCell::new(Vec::new()) });
        let mut mirror = over(board.clone(), dir.path());
        mirror.fetched.keep_link(stored.clone());
        let retracted = mirror.retracted(8, &deposit, &home).expect("answered");
        let queries = board.asked.borrow().clone();
        (retracted, queries, mirror.fetched.retracted)
    };
    let (retracted, queries, kept) = asked(json!({ "resp": "addrs", "addrs": [deposit.to_string()] }));
    assert!(!retracted, "the forged link takes nothing off the view");
    let active = json!({ "home": [unit_span_json(&home)], "from": [unit_span_json(&atom)], "to": "any", "ty": [unit_span_json(t_endpoint())] });
    assert_eq!(queries, [active], "the active view asked, never the retraction's type");
    assert!(kept.is_empty(), "a standing deposit is kept as no retraction");
    let (retracted, _, kept) = asked(json!({ "resp": "addrs", "addrs": [] }));
    assert!(retracted, "the org's own nullify: off the view");
    assert_eq!(kept.get(&8), Some(&vec![deposit.clone()]), "kept at the nullify's row");
    let refused = json!({ "resp": "rejected", "op": "find_links_ftt", "code": "unparseable" });
    assert!(!asked(refused).0, "a refusal takes nothing off the view");
}

/// A BOARD WHOSE ACTIVE VIEW HOLDS EVERY DEPOSIT of `1.0.2.0.1`.
struct AllStanding;

impl Transport for AllStanding {
    fn exchange(&self, _: Method, _: &str, _: &[u8]) -> Result<(u16, Vec<u8>), TransportError> {
        answer(json!({ "resp": "addrs", "addrs": ["1.0.2.0.1.0.2.1", "1.0.2.0.1.0.2.2", "1.0.2.0.1.0.2.3"] }))
    }
}

/// A STANDING DEPOSIT IS ASKED ONCE A PASS: every row a pass folds was
/// held before it asks, so the active view's answer stands for the pass —
/// three `nullify` rows naming a home of three standing deposits ask three
/// times, never nine — and a later pass, its rows past the answer, asks
/// afresh. The deposits are ones the gate passes: SIGNED, each of an origin.
#[test]
fn each_standing_deposit_is_asked_once_a_pass() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut mirror = over(AllStanding, dir.path());
    let home = a("1.0.2.0.1");
    let deposit = |n: u64| a(&format!("1.0.2.0.1.0.2.{n}"));
    let signed = Verdict::Signed(Fingerprint::parse_hex(&"ab".repeat(32)).unwrap());
    for n in 1..=3 {
        let atom = a(&format!("1.0.2.0.1.0.1.{n}"));
        mirror.fetched.keep_link(StoredLink { at: n, address: deposit(n), home: home.clone(), ty: Some(t_endpoint().clone()), from: vec![atom], to: Vec::new() });
        let origins = vec![format!("https://{n}.example")];
        let record = EndpointRecord { origins, replaces: (n > 1).then(|| deposit(n - 1)), honored: false, nullified: false };
        let judged = Judged { position: n, link: deposit(n), home: home.clone(), record, verdict: signed.clone() };
        assert!(mirror.index.fold_endpoint(judged), "deposit {n} honored");
    }
    mirror.rows = (10..13).map(|at| json!({ "at": at, "op": "nullify", "docs": ["1.0.2.0.1"] })).collect();
    mirror.fold_pending().expect("folded");
    assert_eq!(mirror.stats().reads.find_links, 3, "each standing deposit asked once, never once a row");
    assert_eq!(mirror.index.current_endpoint(&home).map(|d| d.link.clone()), Some(deposit(3)), "every deposit stands");
    mirror.rows.push(json!({ "at": 13, "op": "nullify", "docs": ["1.0.2.0.1"] }));
    mirror.fold_pending().expect("folded");
    assert_eq!(mirror.stats().reads.find_links, 6, "a later pass asks afresh");
}

/// A BOARD THAT RE-SERVES A ROW: the page past `since=0` holds the row at 5
/// and announces more, and so does every page after it — every request
/// recorded, a request past the tenth a panic, so a pull that would page
/// forever fails.
struct Repeating {
    asked: RefCell<Vec<String>>,
}

impl Transport for Repeating {
    fn exchange(&self, method: Method, path: &str, _: &[u8]) -> Result<(u16, Vec<u8>), TransportError> {
        self.asked.borrow_mut().push(format!("{method} {path}"));
        assert!(self.asked.borrow().len() <= 10, "a pull that pages forever: {path}");
        let row = json!({ "at": 5, "op": "publish", "docs": ["1.0.2.0.1.1"] });
        answer(json!({ "changes": [row], "last": 5, "more": true }))
    }
}

/// A PAGE THAT SERVES A ROW AGAIN IS REFUSED (wire.md §The change feed,
/// Paging): the row the first page served is held once, and the page past
/// it that serves it again is refused — never held, never asked again.
#[test]
fn a_page_that_serves_a_row_again_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let board = Rc::new(Repeating { asked: RefCell::new(Vec::new()) });
    let mut mirror = over(board.clone(), dir.path());
    assert!(matches!(mirror.sync(), Err(MirrorError::Board(BoardError::Malformed(_)))));
    assert_eq!(mirror.rows.len(), 1, "the row held once");
    assert_eq!(*board.asked.borrow(), ["GET /changes?since=0", "GET /changes?since=5"], "never asked a third time");
}

/// A BOARD THAT REFUSES EVERY PAGE past its byte budget, naming `fits` 0
/// each time — every request recorded, a request past the tenth a panic.
struct Refusing {
    asked: RefCell<Vec<String>>,
}

impl Transport for Refusing {
    fn exchange(&self, method: Method, path: &str, _: &[u8]) -> Result<(u16, Vec<u8>), TransportError> {
        self.asked.borrow_mut().push(format!("{method} {path}"));
        assert!(self.asked.borrow().len() <= 10, "a feed re-asked forever: {path}");
        Ok((400, json!({ "error": "malformed_changes", "budget": 2_097_152, "fits": 0 }).to_string().into_bytes()))
    }
}

/// A FEED THAT REFUSES THE LIMIT IT NAMED IS REFUSED: a page refused past
/// the byte budget is re-asked once, at the limit the feed names, and
/// refused again it is malformed — by the pull and by the resume's check
/// alike, neither asking a third time.
#[test]
fn a_feed_that_refuses_the_limit_it_named_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let board = Rc::new(Refusing { asked: RefCell::new(Vec::new()) });
    let mut mirror = over(board.clone(), dir.path());
    let re_asked_once = ["GET /changes?since=0", "GET /changes?since=0&limit=1"];
    assert!(matches!(mirror.sync(), Err(MirrorError::Board(BoardError::Malformed(_)))), "the pull");
    assert_eq!(*board.asked.borrow(), re_asked_once);
    board.asked.borrow_mut().clear();
    assert!(matches!(mirror.check_against_source(&[], &[]), Err(MirrorError::Board(BoardError::Malformed(_)))), "the resume's check");
    assert_eq!(*board.asked.borrow(), re_asked_once);
}

/// A BOARD WHOSE LINK `1.0.2.0.1.0.2.7` IS OF A TYPE THE FOLD DOES NOT
/// READ: its type slot two spans, its `from` three thousand atoms.
struct Untyped;

impl Transport for Untyped {
    fn exchange(&self, _: Method, _: &str, body: &[u8]) -> Result<(u16, Vec<u8>), TransportError> {
        let frame: Value = serde_json::from_slice(body).expect("a frame");
        assert_eq!((frame["op"].as_str(), frame["a"].as_str()), (Some("read_link"), Some("1.0.2.0.1.0.2.7")));
        let from: Vec<Value> = (1..=3_000).map(|n| span(&format!("1.0.2.0.1.0.1.{n}"))).collect();
        let ty = [unit_span_json(t_endpoint()), unit_span_json(&commons_type(&[1]))];
        answer(json!({ "resp": "link", "link": { "slots": [from, [span("1.0.2")], ty] } }))
    }
}

/// A LINK OF NO TYPE THE FOLD READS is held with no slots: none of its
/// spans is parsed, and its cache line holds its type as none and nothing
/// of its `from` or its `to`.
#[test]
fn a_link_of_no_type_the_fold_reads_is_held_with_no_slots() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut mirror = over(Untyped, dir.path());
    let stored = mirror.read_link(5, &a("1.0.2.0.1.0.2.7"), &a("1.0.2.0.1")).expect("answered").expect("a link stands");
    assert_eq!((stored.ty, stored.from.len(), stored.to.len()), (None, 0, 0));
    let line = json!({ "link": { "at": 5, "address": "1.0.2.0.1.0.2.7", "home": "1.0.2.0.1", "ty": null, "from": [], "to": [] } });
    assert_eq!(mirror.pending_cache, [line], "its cache line holds no slot");
}

/// A BOARD WHOSE HOME `1.0.2.0.1` ARRANGES ITS ATOM `…0.1.1` AT THE HEAD,
/// the bytes there `len` long.
struct Lengthy {
    len: usize,
}

impl Transport for Lengthy {
    fn exchange(&self, _: Method, _: &str, body: &[u8]) -> Result<(u16, Vec<u8>), TransportError> {
        let frame: Value = serde_json::from_slice(body).expect("a frame");
        match frame["op"].as_str() {
            Some("image") => answer(json!({ "resp": "runs", "runs": [{ "i_start": "1.0.2.0.1.0.1.1", "width": "1" }] })),
            Some("retrieve_v") => answer(json!({ "resp": "delivery", "items": [{ "atom": "x".repeat(self.len) }] })),
            _ => panic!("a read this board does not answer: {frame}"),
        }
    }
}

/// BYTES PAST ANY RECORD ARE NEVER HELD: an atom longer than the largest
/// record the canonical rule admits is handed to the parse, which refuses
/// it, and kept neither in the cache nor in its file; a record's own bytes,
/// at that length, are kept.
#[test]
fn bytes_past_any_record_are_handed_to_the_parse_and_never_held() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (home, atom) = (a("1.0.2.0.1"), a("1.0.2.0.1.0.1.1"));
    let mut mirror = over(Lengthy { len: MAX_REGISTRY_RECORD_BYTES + 1 }, dir.path());
    let bytes = mirror.fetch_atom(5, &home, &atom).expect("read").expect("the bytes");
    assert_eq!(bytes.len(), MAX_REGISTRY_RECORD_BYTES + 1, "handed to the parse");
    assert!(mirror.fetched.atoms.is_empty() && mirror.pending_cache.is_empty(), "never held");
    let mut mirror = over(Lengthy { len: MAX_REGISTRY_RECORD_BYTES }, dir.path());
    mirror.fetch_atom(5, &home, &atom).expect("read").expect("the bytes");
    assert_eq!((mirror.fetched.atoms.len(), mirror.pending_cache.len()), (1, 1), "a record's bytes, held");
}
