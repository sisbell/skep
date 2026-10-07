use std::cell::RefCell;
use std::rc::Rc;

use serde_json::json;
use skep_identity::{entry_body_record, entry_frame, DocTerm, RecordRows};
use skep_registry::{encode, Binding};
use skep_signature::{HybridSigner, TAG_MLDSA65_ED25519};

use super::*;
use crate::board::unit_span_json;
use crate::http::{Method, Transport, TransportError};
use crate::mirror::testing::{answer, hint, over, span};

fn a(s: &str) -> Address {
    parse_address(s).unwrap()
}

/// The board term every record below is signed under.
const TERM: BoardTerm = BoardTerm { log_position: 1, chain: [7; 32] };

/// A binding of `prefix` naming `to`, deposited in `home` and signed by
/// `signer` over the record frame the home's account composes under
/// [`TERM`].
fn signed_binding(signer: &HybridSigner, home: &Address, prefix: &Address, to: &[Address]) -> String {
    let body = Body::Binding(Binding { prefix: prefix.clone(), replaces: None });
    let sigless = encode(&body, None);
    let rows = RecordRows {
        ty: t_binding(),
        to,
        replaces: None,
        lineage_fork_point: None,
        sigless_canonical_record: sigless.as_bytes(),
    };
    let account = account_of_document(home).expect("a doc 1's account");
    let frame = entry_frame(signer.public_key().alg(), TERM, &account, DocTerm::One(home), &entry_body_record(rows));
    encode(&body, Some(&signer.sign(&frame).iter().map(|b| format!("{b:02x}")).collect::<String>()))
}

/// A stored link at `at`, homed in `home`, typed `ty`, from `from` to `to`.
fn stored(at: u64, address: &str, home: &Address, ty: &Address, from: &str, to: &[Address]) -> StoredLink {
    StoredLink { at, address: a(address), home: home.clone(), ty: Some(ty.clone()), from: vec![a(from)], to: to.to_vec() }
}

/// `signer`'s table, the one key it holds, as `account`'s before any act.
fn table(account: &str, signer: &HybridSigner) -> KeysAsOf {
    KeysAsOf { account: a(account), epoch: Epoch(0), at: 0, enrolled: vec![Enrolled { key: signer.public_key().clone(), anchor: true }] }
}

/// A copy under `dir` — its header naming [`hint`]'s genesis fingerprint, a
/// `make_link` row at each `(at, link, home)` — and a fetch cache of
/// `lines`, rebuilt offline.
fn rebuilt(dir: &Path, rows: &[(u64, &str, &Address)], lines: &[Value]) -> Mirror {
    let header = json!({ "skep-resolve": FEED_FORMAT, "realm": hint().realm().genesis.to_hex(), "root": null });
    let rows: Vec<Value> = rows
        .iter()
        .map(|(at, link, home)| json!({ "row": { "at": at, "op": "make_link", "link": link, "docs": [home.to_string()] } }))
        .collect();
    let feed: String = std::iter::once(&header).chain(&rows).map(|line| format!("{line}\n")).collect();
    fs::write(dir.join(FEED_COPY), feed).expect("the feed copy");
    fs::write(dir.join(FETCH_CACHE), lines.iter().map(|line| format!("{line}\n")).collect::<String>()).expect("the cache");
    Mirror::rebuild_offline(&hint(), dir).expect("rebuilt")
}

/// THE BINDING-WRITING ACCOUNT (R5 (g); REG-2.8, REG-2.6): a binding-typed
/// record an org deposits in its own doc 1 — signed by the org's own key, so
/// the board's home check and the verify would both pass it — binds nothing:
/// it is counted apart, never judged, and its prefix has no standing; the
/// registrar's own binding, deposited the same way in the claimant's doc 1,
/// is SIGNED and stands. The copy is rebuilt offline, every fetch served
/// from a cache written by `Fetched`.
#[test]
fn a_binding_typed_record_outside_the_claimants_doc_one_binds_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let registrar = HybridSigner::from_seed(TAG_MLDSA65_ED25519, &[1; 32]).expect("tag 1");
    let org = HybridSigner::from_seed(TAG_MLDSA65_ED25519, &[2; 32]).expect("tag 1");
    let bound = [a("1.0.2")];
    let (registry, own) = (a("1.0.1.0.1"), a("1.0.2.0.1"));
    let mut kept = Fetched::default();
    let lines: Vec<Value> = [
        kept.keep_link(stored(1, "1.0.1.0.1.0.2.1", &registry, &commons_type(&[3]), "1.0.1", &[])),
        kept.keep_link(stored(2, "1.0.2.0.1.0.2.1", &own, t_binding(), "1.0.2.0.1.0.1.1", &bound)),
        kept.keep_link(stored(3, "1.0.1.0.1.0.2.2", &registry, t_binding(), "1.0.1.0.1.0.1.1", &bound)),
        kept.keep_atom(a("1.0.2.0.1.0.1.1"), signed_binding(&org, &own, &a("1.9"), &bound)),
        kept.keep_atom(a("1.0.1.0.1.0.1.1"), signed_binding(&registrar, &registry, &a("1.8"), &bound)),
        kept.keep_board(TERM, &"07".repeat(32)),
        kept.keep_keys(table("1.0.1", &registrar)),
        kept.keep_keys(table("1.0.2", &org)),
    ]
    .into_iter()
    .map(|line| line.expect("a value not held writes its line"))
    .collect();
    let rows = [(1, "1.0.1.0.1.0.2.1", &registry), (2, "1.0.2.0.1.0.2.1", &own), (3, "1.0.1.0.1.0.2.2", &registry)];
    let mirror = rebuilt(dir.path(), &rows, &lines);
    let verdict = mirror.index().standing(&a("1.8")).map(|s| s.current.verdict);
    assert_eq!(verdict, Some(Verdict::Signed(Fingerprint::of(registrar.public_key()))), "the registrar's binding stands");
    assert_eq!(mirror.index().standing(&a("1.9")), None, "the org's binding-typed record binds nothing");
    assert_eq!(mirror.stats().binding_typed_outside_home, 1, "counted apart");
    assert!(mirror.index().suppressed().is_empty(), "and never judged: {:?}", mirror.index().suppressed());
}

/// A RECORD'S POSITION AND HOME ARE ITS ROW'S (R5 (g); REG-1.10): a cache
/// line naming the registrar's binding link at another position and in an
/// org's doc 1, its atom the org's own signed binding, binds nothing — the
/// record is judged where its row puts it, in the claimant's doc 1 under the
/// registrar's table, and is UNSIGNED there, kept out at the row's position;
/// never where the line puts it, SIGNED by the org's key.
#[test]
fn a_records_position_and_home_are_its_rows_never_a_cache_lines() {
    let dir = tempfile::tempdir().expect("tempdir");
    let registrar = HybridSigner::from_seed(TAG_MLDSA65_ED25519, &[1; 32]).expect("tag 1");
    let org = HybridSigner::from_seed(TAG_MLDSA65_ED25519, &[2; 32]).expect("tag 1");
    let bound = [a("1.0.2")];
    let (registry, own) = (a("1.0.1.0.1"), a("1.0.2.0.1"));
    let mut kept = Fetched::default();
    let lines: Vec<Value> = [
        kept.keep_link(stored(1, "1.0.1.0.1.0.2.1", &registry, &commons_type(&[3]), "1.0.1", &[])),
        kept.keep_link(stored(7, "1.0.1.0.1.0.2.2", &own, t_binding(), "1.0.2.0.1.0.1.1", &bound)),
        kept.keep_atom(a("1.0.2.0.1.0.1.1"), signed_binding(&org, &own, &a("1.9"), &bound)),
        kept.keep_board(TERM, &"07".repeat(32)),
        kept.keep_keys(table("1.0.1", &registrar)),
        kept.keep_keys(table("1.0.2", &org)),
    ]
    .into_iter()
    .map(|line| line.expect("a value not held writes its line"))
    .collect();
    let rows = [(1, "1.0.1.0.1.0.2.1", &registry), (2, "1.0.1.0.1.0.2.2", &registry)];
    let mirror = rebuilt(dir.path(), &rows, &lines);
    assert_eq!(mirror.index().standing(&a("1.9")), None, "the org's record binds nothing");
    let kept_out: Vec<(u64, Cause)> = mirror.index().suppressed().iter().map(|s| (s.position, s.cause.clone())).collect();
    assert_eq!(kept_out, [(2, Cause::Verdict(Verdict::Unsigned))], "judged at the row's position, in the row's home");
}

/// AN ADDRESS PAST A MACHINE WORD IS AN ADDRESS (wire.md §Value encodings:
/// a component is one decimal natural, of any size), and what the canonical
/// rule admits is not judged again: the registrar's binding of a prefix one
/// component of which passes `u64`, its binding naming an account one
/// component of which does — the stored link's target read whole, so the
/// frame the verify rebuilds is the one the registrar signed — and its
/// binding of a prefix past the wire's digit cap, which a record's own cap
/// bounds instead, each stand SIGNED, and nothing is suppressed.
#[test]
fn a_record_naming_an_address_past_a_machine_word_stands_signed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let registrar = HybridSigner::from_seed(TAG_MLDSA65_ED25519, &[1; 32]).expect("tag 1");
    let registry = a("1.0.1.0.1");
    let (word, wide_account) = (a("1.18446744073709551616"), a("1.0.18446744073709551616"));
    // Past the wire's digit cap, so built from its components: `a` reads
    // what a board serves, and no board serves it.
    let past_the_wire = skep_address::validate(
        Tumbler::new([Nat::from(1u8), "9".repeat(4097).parse().expect("a natural")]).expect("a tumbler"),
    )
    .expect("an address");
    let (to_org, to_wide) = ([a("1.0.2")], [wide_account.clone()]);
    let mut kept = Fetched::default();
    let lines: Vec<Value> = [
        kept.keep_link(stored(1, "1.0.1.0.1.0.2.1", &registry, &commons_type(&[3]), "1.0.1", &[])),
        kept.keep_link(stored(2, "1.0.1.0.1.0.2.2", &registry, t_binding(), "1.0.1.0.1.0.1.1", &to_org)),
        kept.keep_link(stored(3, "1.0.1.0.1.0.2.3", &registry, t_binding(), "1.0.1.0.1.0.1.2", &to_wide)),
        kept.keep_link(stored(4, "1.0.1.0.1.0.2.4", &registry, t_binding(), "1.0.1.0.1.0.1.3", &to_org)),
        kept.keep_atom(a("1.0.1.0.1.0.1.1"), signed_binding(&registrar, &registry, &word, &to_org)),
        kept.keep_atom(a("1.0.1.0.1.0.1.2"), signed_binding(&registrar, &registry, &a("1.8"), &to_wide)),
        kept.keep_atom(a("1.0.1.0.1.0.1.3"), signed_binding(&registrar, &registry, &past_the_wire, &to_org)),
        kept.keep_board(TERM, &"07".repeat(32)),
        kept.keep_keys(table("1.0.1", &registrar)),
    ]
    .into_iter()
    .map(|line| line.expect("a value not held writes its line"))
    .collect();
    let rows = [
        (1, "1.0.1.0.1.0.2.1", &registry),
        (2, "1.0.1.0.1.0.2.2", &registry),
        (3, "1.0.1.0.1.0.2.3", &registry),
        (4, "1.0.1.0.1.0.2.4", &registry),
    ];
    let mirror = rebuilt(dir.path(), &rows, &lines);
    assert!(mirror.index().suppressed().is_empty(), "{:?}", mirror.index().suppressed());
    let signed = Verdict::Signed(Fingerprint::of(registrar.public_key()));
    let past_a_word = mirror.index().standing(&word).expect("a prefix past a machine word");
    assert_eq!(past_a_word.current.verdict, signed);
    let naming = mirror.index().standing(&a("1.8")).expect("a binding naming an account past a machine word");
    assert_eq!((naming.current.verdict, naming.current.record.account), (signed.clone(), Some(wide_account)));
    let past_the_cap = mirror.index().standing(&past_the_wire).expect("a prefix past the wire's cap");
    assert_eq!(past_the_cap.current.verdict, signed);
}

/// The address arithmetic the fold rests on: a doc 1's account.
#[test]
fn the_homes_account_is_read_by_arithmetic() {
    assert_eq!(account_of_document(&a("1.0.1.0.1")), Some(a("1.0.1")));
    assert_eq!(account_of_document(&a("1.0.2.3.0.1")), Some(a("1.0.2.3")));
    assert_eq!(account_of_document(&a("1.0.1.0.1.2")), Some(a("1.0.1")), "a member's account");
    assert_eq!(account_of_document(&a("1.0.1.0.1.0.1.4")), Some(a("1.0.1")), "an element's");
    assert_eq!(account_of_document(&a("1.0.1")), None);
}

/// A link row is an unattested `make_link` with a link and a home — the
/// row a record deposit and a credential deposit alike commit; an
/// attested one and one naming no document are no link row, nothing the
/// fold takes. A `nullify` is read as the documents it names, and a
/// `publish` as the members it names.
#[test]
fn a_link_row_is_an_unattested_make_link() {
    let row = json!({ "at": 7, "op": "make_link", "link": "1.0.2.0.1.0.2.1", "docs": ["not an address", "1.0.2.0.1"] });
    let link = Row::Link { at: 7, link: a("1.0.2.0.1.0.2.1"), home: a("1.0.2.0.1") };
    assert_eq!(Row::of(&row), link, "the home is the first document that is an address");
    let mut attested = row.clone();
    attested["attest"] = json!({});
    assert_eq!(Row::of(&attested), Row::Other);
    assert_eq!(Row::of(&json!({ "at": 7, "op": "make_link", "link": "1.0.2.0.1.0.2.1", "docs": [] })), Row::Other);
    let nullify = json!({ "at": 8, "op": "nullify", "link": "1.0.2.0.1.0.2.1", "docs": ["1.0.2.0.1"] });
    assert_eq!(Row::of(&nullify), Row::Nullify { at: 8, docs: vec![a("1.0.2.0.1")] });
    let publish = json!({ "at": 9, "op": "publish", "docs": ["1.0.2.0.1.1"] });
    assert_eq!(Row::of(&publish), Row::Chain { members: vec![a("1.0.2.0.1.1")] });
}

/// A LINE CUT SHORT IS NEVER RUN INTO, AND HOLDS NOTHING: a held cache a
/// crash left mid-line is appended to on a line of its own, every byte of
/// it counted; and the cache's reader takes every line that reads and passes
/// over the one that does not, refusing nothing — the fold fetches afresh
/// what it held.
#[test]
fn a_line_cut_short_is_never_run_into_and_holds_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join(FETCH_CACHE);
    let cut = r#"{"atom":{"addr"#;
    fs::write(&path, cut).expect("a cache a crash cut short");
    let mut lines = Lines::held(path.clone());
    let claim = json!({ "claim": { "at": 3, "claimant": "1.0.1" } });
    lines.append(&claim).expect("appended");
    let held = fs::read_to_string(&path).expect("the cache");
    assert_eq!(held, format!("{cut}\n{claim}\n"), "the cut line ended, the next on its own");
    assert_eq!(lines.bytes, held.len() as u64, "every byte counted");
    let header = json!({ "skep-resolve": FEED_FORMAT, "realm": hint().realm().genesis.to_hex(), "root": null });
    fs::write(dir.path().join(FEED_COPY), format!("{header}\n")).expect("the feed copy");
    let mirror = Mirror::rebuild_offline(&hint(), dir.path()).expect("a line that does not read refuses nothing");
    assert_eq!(mirror.fetched.claim, Some((3, a("1.0.1"))), "the line after it reads");
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
