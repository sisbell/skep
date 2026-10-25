use std::cell::RefCell;
use std::rc::Rc;

use skep_address::Address;
use skep_identity::{Fingerprint, PublicKey};
use skep_registry::{commons_type, t_binding};

use super::*;
use crate::http::{dial_http, Method, Transport, TransportError};
use crate::mirror::testing::{
    answer, binding_text, enroll_text, hint, hint_of, key, over, over_hint, realm_of, retire_text, signer, KeySetArm,
    Script,
};
use crate::mirror::{Fetched, StoredLink};
use crate::parse_address;
use crate::state::Verdict;

fn a(s: &str) -> Address {
    parse_address(s).unwrap()
}

/// The registrar `1.0.1`'s doc 1 and the org `1.0.2`'s.
fn homes() -> (Address, Address) {
    (a("1.0.1.0.1"), a("1.0.2.0.1"))
}

/// The genesis fingerprint of the set holding `key(seed)` alone.
fn genesis_of(seed: u8) -> Fingerprint {
    realm_of(&[&key(seed)])
}

/// A dial that answers every origin with `board`.
fn dial_of(board: &Rc<impl Transport + 'static>) -> impl Fn(&Origin) -> Result<Box<dyn Transport>, TransportError> {
    let board = board.clone();
    move |_: &Origin| -> Result<Box<dyn Transport>, TransportError> { Ok(Box::new(board.clone())) }
}

/// A copy held under `dir` — its header naming `genesis`, `rows` — and a
/// fetch cache of `cache`'s lines: both files as written.
fn hold(dir: &Path, genesis: Fingerprint, rows: &[Value], cache: &[Value]) -> (String, String) {
    let header = json!({ "skep-resolve": FEED_FORMAT, "realm": genesis.to_hex(), "root": null });
    let rows = rows.iter().map(|row| json!({ "row": row }));
    let feed: String = std::iter::once(header).chain(rows).map(|line| format!("{line}\n")).collect();
    let cache: String = cache.iter().map(|line| format!("{line}\n")).collect();
    fs::write(dir.join(FEED_COPY), &feed).expect("the feed copy");
    fs::write(dir.join(FETCH_CACHE), &cache).expect("the fetch cache");
    (feed, cache)
}

/// The claimant's fingerprints as the walk hands them, sorted by hex.
fn fingerprints(keys: Option<Vec<skep_identity::Enrolled>>) -> Option<Vec<Fingerprint>> {
    keys.map(|keys| {
        let mut v: Vec<Fingerprint> = keys.iter().map(|e| Fingerprint::of(&e.key)).collect();
        v.sort_by_key(Fingerprint::to_hex);
        v
    })
}

fn sorted(keys: &[&PublicKey]) -> Vec<Fingerprint> {
    let mut v: Vec<Fingerprint> = keys.iter().map(|k| Fingerprint::of(k)).collect();
    v.sort_by_key(Fingerprint::to_hex);
    v
}

/// A SYNC THAT FAILED IS TAKEN UP WHERE IT STOPPED (REG-3.10): the two rows
/// the failed sync held are folded by the next, which asks the board only
/// past the copy's frontier and holds each row once; and between the two,
/// the credential pass having stopped short of the enroll at 4, the walk
/// answers the table as of the head — the key it enrolls not yet in it —
/// while once the act is read it is, and the binding that key signed stands.
#[test]
fn a_sync_that_failed_is_taken_up_where_it_stopped() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (registry, _) = homes();
    let (registrar, second) = (signer(1), signer(2));
    let claimant = a("1.0.1");
    let mut script = Script::new();
    script.deposit(&registry, &commons_type(&[1]), &[claimant.clone()], &enroll_text(None, &registry, &claimant, &[(registrar.public_key(), true)]));
    script.claim(&claimant);
    script.deposit(&registry, t_binding(), &[a("1.0.2")], &binding_text(&registrar, &registry, &[a("1.0.2")], &a("1.5")));
    let board = Rc::new(script.board(KeySetArm::Refused));
    let mut mirror = over_hint(board.clone(), dir.path(), &hint_of(genesis_of(1)));
    assert_eq!(mirror.sync(), Ok(3), "the first sync folds the three rows");
    let enroll = board.deposit(&registry, &commons_type(&[1]), &[claimant.clone()], &enroll_text(Some(&registrar), &registry, &claimant, &[(second.public_key(), false)]));
    board.deposit(&registry, t_binding(), &[a("1.0.3")], &binding_text(&second, &registry, &[a("1.0.3")], &a("1.6")));
    board.refuse_link_once(&enroll);
    assert!(matches!(mirror.sync(), Err(MirrorError::Board(BoardError::Status { status: 503, .. }))));
    assert_eq!((mirror.rows.len(), mirror.head), (5, 3), "held, and not folded");
    assert_eq!(mirror.held_through(), 5);
    assert_eq!(fingerprints(mirror.current_keys(&claimant).expect("read")), Some(sorted(&[registrar.public_key()])), "the act at 4 unread: the table as of the head");
    assert_eq!(mirror.sync(), Ok(2), "the two held rows folded, each once");
    assert_eq!((mirror.rows.len(), mirror.head), (5, 5));
    let pulls: Vec<String> = board.asked.borrow().iter().filter(|r| r.contains("/changes")).cloned().collect();
    assert_eq!(pulls, ["GET /changes?since=0", "GET /changes?since=3", "GET /changes?since=5"], "each pull past the copy's frontier");
    assert_eq!(fingerprints(mirror.current_keys(&claimant).expect("read")), Some(sorted(&[registrar.public_key(), second.public_key()])), "the act read: the key is in the table at the head");
    let standing = mirror.index().standing(&a("1.6")).expect("the binding the second key signed");
    assert_eq!(standing.current.verdict, Verdict::Signed(Fingerprint::of(second.public_key())));
}

/// AN UNCLAIMED BOARD RESOLVES NOTHING: a feed that holds no claim through
/// the source's head opens no base, fresh or held — [`MirrorError::NoClaim`],
/// the realm never compared — and a base refused before its first line
/// writes nothing: no feed copy where none was, a held one byte for byte,
/// and a stray cache the directory held left as it was found.
#[test]
fn a_feed_with_no_claim_opens_no_base_and_writes_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (_, own) = homes();
    let mut script = Script::new();
    script.deposit(&own, &a("1.1.0.1.0.1.0.7.1"), &[], "not a record the fold reads");
    script.deposit(&own, &commons_type(&[1]), &[a("1.0.2")], &enroll_text(None, &own, &a("1.0.2"), &[(&key(3), true)]));
    let rows = script.rows();
    let board = Rc::new(script.board(KeySetArm::Refused));
    let dial = dial_of(&board);
    let read = |name: &str| fs::read_to_string(dir.path().join(name)).expect("a file of the directory");
    let stray = json!({ "link": { "at": 1, "address": "1.0.9.0.1.0.2.1", "home": "1.0.9.0.1", "ty": null, "from": [], "to": [] } });
    let cache = format!("{stray}\n");
    fs::write(dir.path().join(FETCH_CACHE), &cache).expect("a stray cache");
    assert_eq!(Mirror::open(&hint(), dir.path(), &dial).unwrap_err(), MirrorError::NoClaim, "a fresh base");
    assert!(!dir.path().join(FEED_COPY).exists(), "no feed copy where none was");
    assert_eq!(read(FETCH_CACHE), cache, "the stray cache as it was found");
    let header = json!({ "skep-resolve": FEED_FORMAT, "realm": hint().realm().genesis.to_hex(), "root": null });
    let held: String = std::iter::once(header).chain(rows.into_iter().map(|row| json!({ "row": row }))).map(|line| format!("{line}\n")).collect();
    fs::write(dir.path().join(FEED_COPY), &held).expect("a held copy of the same feed");
    assert_eq!(Mirror::open(&hint(), dir.path(), &dial).unwrap_err(), MirrorError::NoClaim, "a held copy");
    assert_eq!(read(FEED_COPY), held, "the held copy byte for byte");
    assert_eq!(read(FETCH_CACHE), cache, "and the cache");
}

/// The board of the claim cells below: at 1 `1.0.1`'s genesis enroll of
/// `key(1)`, at 2 its claim, at 3 `1.0.2`'s genesis — a hire into the
/// claimant's doc 1, the claimant's hand — and, with `rotated`, `1.0.1`
/// enrolling `key(2)` at 4 and retiring its genesis key at 5 by the new
/// key's hand; `1.0.1`'s genesis set `key(1)`, `1.0.2`'s `key(2)`.
fn claim_board(rotated: bool) -> (Script, Vec<Address>) {
    let (registry, _) = homes();
    let (one, two) = (signer(1), signer(2));
    let claimant = a("1.0.1");
    let mut script = Script::new();
    let mut links = vec![
        script.deposit(&registry, &commons_type(&[1]), &[claimant.clone()], &enroll_text(None, &registry, &claimant, &[(one.public_key(), true)])),
        script.claim(&claimant),
        script.deposit(&registry, &commons_type(&[1]), &[a("1.0.2")], &enroll_text(Some(&one), &registry, &a("1.0.2"), &[(two.public_key(), true)])),
    ];
    if rotated {
        links.push(script.deposit(&registry, &commons_type(&[1]), &[claimant.clone()], &enroll_text(Some(&one), &registry, &claimant, &[(two.public_key(), true)])));
        links.push(script.deposit(&registry, &commons_type(&[2]), &[claimant.clone()], &retire_text(&two, &registry, &claimant, &[Fingerprint::of(one.public_key())])));
    }
    (script, links)
}

/// THE CLAIMANT IS THE BOARD'S WORD (REG-3.42): a held copy whose fetch
/// cache names another claimant at the claim's link — `1.0.2`, whose genesis
/// set the copy's header names, so a realm compared for it would pass — is
/// refused at the claim, the realm compared for the claimant the board's
/// own link names; and nothing is written.
#[test]
fn a_cache_naming_another_claimant_is_refused_at_the_claim() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (script, links) = claim_board(false);
    let rows = script.rows();
    let board = Rc::new(script.board(KeySetArm::Refused));
    let claim = StoredLink {
        at: 2,
        address: links[1].clone(),
        home: a("1.0.1.0.1"),
        ty: Some(commons_type(&[3])),
        from: vec![a("1.0.2")],
        to: Vec::new(),
    };
    let forged = Fetched::default().keep_link(claim).expect("a line");
    let held = hold(dir.path(), genesis_of(2), &rows, &[forged]);
    let refused = Mirror::open(&hint_of(genesis_of(2)), dir.path(), &dial_of(&board)).unwrap_err();
    assert_eq!(refused, MirrorError::Refused(Refusal::RealmMismatch { expected: genesis_of(2), found: genesis_of(1) }));
    let read = |name: &str| fs::read_to_string(dir.path().join(name)).expect("a file of the copy");
    assert_eq!((read(FEED_COPY), read(FETCH_CACHE)), held, "nothing written");
}

/// THE GENESIS RECORD IS THE BOARD'S WORD (REG-3.42; REG-3.39: the genesis
/// set, never the living one): a held copy whose fetch cache types neither
/// `1.0.1`'s genesis enroll nor its later one, and holds in the claimant's
/// genesis atom's place a record enrolling `key(2)` — the set the copy's
/// header names — is refused at the claim all the same, the claimant's
/// links and its genesis record read off the board; and nothing is written.
#[test]
fn a_cache_hiding_the_genesis_act_is_refused_at_the_claim() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (script, links) = claim_board(true);
    let rows = script.rows();
    let board = Rc::new(script.board(KeySetArm::Refused));
    let untyped = |at: u64, link: &Address| StoredLink { at, address: link.clone(), home: a("1.0.1.0.1"), ty: None, from: Vec::new(), to: Vec::new() };
    let mut kept = Fetched::default();
    let forged_genesis = enroll_text(None, &a("1.0.1.0.1"), &a("1.0.1"), &[(&key(2), true)]);
    let hidden = [
        kept.keep_link(untyped(1, &links[0])),
        kept.keep_link(untyped(4, &links[3])),
        kept.keep_atom(a("1.0.1.0.1.0.1.1"), forged_genesis),
    ]
    .map(|l| l.expect("a line"));
    let held = hold(dir.path(), genesis_of(2), &rows, &hidden);
    let refused = Mirror::open(&hint_of(genesis_of(2)), dir.path(), &dial_of(&board)).unwrap_err();
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
    let (mut script, _) = claim_board(false);
    script.claim(&a("1.0.2"));
    let board = Rc::new(script.board(KeySetArm::Refused));
    let hint = hint_of(genesis_of(1));
    let mirror = Mirror::open(&hint, dir.path(), &dial_of(&board)).expect("opened");
    assert_eq!(mirror.claim(), Some((2, &a("1.0.1"))), "the board's first claim");
    drop(mirror);
    let offline = Mirror::rebuild_offline(&hint, dir.path()).expect("rebuilt");
    assert_eq!(offline.claim(), Some((2, &a("1.0.1"))), "and the copy's");
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
