//! THE REGISTRAR's CONSOLE against the real daemon (REG-4.78 to REG-4.131):
//! `ceremony::console` and `ceremony::policy` over an ENFORCING board its
//! registrar claimed. The door's policy is set with the policy command's
//! library half at well-known document 5; an account beneath the
//! registrar's stands as the intake home and writes each request from its
//! own doc 1 under its own key, as a scribe will; and the console answers.
//!
//! The cells: the queue holds admitted homes' requests alone, by the policy
//! version at each request's own position; the row guard; the framing
//! re-check and the refused answer it writes; the approval's order and its
//! resume from a stop after each write; the read-back loop under a lost
//! race; next-form off the bindings alone; whose key every record is signed
//! under; the approved answer's home and members; the unattended hand under
//! each policy; the denial; the three derived lists; the policy's four acts;
//! and a door with no policy.

use std::io::Read;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use serde_json::Value;
use skep_client::address::doc_1_of;
use skep_client::board::{frames, Answer, Board, Scope, Token};
use skep_client::ceremony::console::{approve, auto_round, deny, read_queue, unattended_withheld, Console, Door, Hand, Outcome, Queue, State, Verdict};
use skep_client::ceremony::handshake::{handshake, Site};
use skep_client::ceremony::policy::{check_policy, read_policy, set_policy, NoPolicy, MAX_POLICY_BYTES};
use skep_client::ceremony::registration::{registration_request, RegistrationOptions};
use skep_client::ceremony::registry_record::{binding_history, registration_at, stored_link, Atoms};
use skep_client::dial::{DialError, Dialer, Headers, PlainHttp, Request, RequestHead, Response, StreamedResponse};
use skep_client::person::scripted::{Script, Scripted};
use skep_client::sign::{sig_hex, signer_from_seed, RecordFrame, Signer};
use skep_client::store::FileStore;
use skep_client::{Halt, Origin};
use skep_identity::{encode_enroll, AdmissionFrame, Enrollment, Fingerprint};
use skep_registry::{
    encode_policy, encode_registration, Admission, AdmissionPolicy, BoardCarriesOn, Denied, Digits, Disposition, Fault, Fresh, Hex64, HexDigits, Refused, RegistrationBody, RegistrationKind,
};
use skep_signature::HybridSigner;

use crate::common::{board, claim, entry_of, key_file, keyed_sub_account, keygen, origin_of, spawn, wire_binding, wire_delegate, wire_enroll, wire_home, wire_policy_version, wire_registration, wire_session};

const T_REQUEST_FRESH: &str = "1.1.0.1.0.1.0.3.54.1.1";
const T_REQUEST_BOARD_CARRIES_ON: &str = "1.1.0.1.0.1.0.3.54.1.2";
const T_APPROVAL: &str = "1.1.0.1.0.1.0.3.54.4";
const T_BINDING: &str = "1.1.0.1.0.1.0.3.55";
const T_ENROLL: &str = "1.1.0.1.0.1.0.3.1";
const T_REPLY_APPROVED: &str = "1.1.0.1.0.1.0.3.54.2.1";
const T_REPLY_REFUSED: &str = "1.1.0.1.0.1.0.3.54.2.2";
const T_REPLY_DENIED: &str = "1.1.0.1.0.1.0.3.54.2.3";

/// What a probe does with one frame.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Act {
    /// Sends it on.
    Pass,
    /// Sends it on and loses the answer: the write commits, its ack does not
    /// arrive.
    Lose,
    /// Fails before it is sent.
    Drop,
}

type Rule = Box<dyn FnMut(&Value) -> Act + Send>;
type Rewrite = Box<dyn FnMut(&Value, &mut Value) + Send>;

/// THE PROBE: a dialer that logs every frame as `op type`, loses or drops
/// the frame its rule picks, and rewrites an answer where a test stands in
/// for a board that answers otherwise.
struct Probe {
    inner: PlainHttp,
    log: Arc<Mutex<Vec<String>>>,
    rule: Arc<Mutex<Option<Rule>>>,
    rewrite: Arc<Mutex<Option<Rewrite>>>,
}

impl Dialer for Probe {
    fn exchange(&self, origin: &Origin, req: &Request) -> Result<Response, DialError> {
        let frame = if req.path == "/op" { serde_json::from_slice::<Value>(&req.body).ok() } else { None };
        let mut act = Act::Pass;
        if let Some(frame) = &frame {
            let ty = frame["deposit"].as_str().or_else(|| frame["ty"]["addrs"][0].as_str()).unwrap_or("");
            self.log.lock().unwrap().push(format!("{} {ty}", frame["op"].as_str().unwrap_or("?")).trim().to_string());
            // The rule is taken out while it runs, so it may dial for itself.
            let taken = self.rule.lock().unwrap().take();
            if let Some(mut rule) = taken {
                act = rule(frame);
                if act == Act::Pass {
                    self.rule.lock().unwrap().get_or_insert(rule);
                }
            }
        }
        if act == Act::Drop {
            return Err(DialError::Io("the probe dropped the request".into()));
        }
        let mut response = self.inner.exchange(origin, req)?;
        if act == Act::Lose {
            return Err(DialError::Io("the probe lost the answer".into()));
        }
        if let (Some(frame), Some(rewrite)) = (&frame, self.rewrite.lock().unwrap().as_mut()) {
            if let Ok(mut answer) = serde_json::from_slice::<Value>(&response.body) {
                rewrite(frame, &mut answer);
                response.body = answer.to_string().into_bytes();
            }
        }
        Ok(response)
    }

    fn stream(&self, origin: &Origin, head: &RequestHead, body: &mut dyn Read, on_interim: &mut dyn FnMut(&Headers)) -> Result<StreamedResponse, DialError> {
        self.inner.stream(origin, head, body, on_interim)
    }
}

/// A board over a probe, with the probe's three handles.
struct Probed {
    board: Board,
    log: Arc<Mutex<Vec<String>>>,
    rule: Arc<Mutex<Option<Rule>>>,
    rewrite: Arc<Mutex<Option<Rewrite>>>,
}

fn probed(port: u16) -> Probed {
    let (log, rule, rewrite) = (Arc::new(Mutex::new(Vec::new())), Arc::new(Mutex::new(None)), Arc::new(Mutex::new(None)));
    let board = Board::new(origin_of(port), Probe { inner: PlainHttp::new(), log: log.clone(), rule: rule.clone(), rewrite: rewrite.clone() });
    Probed { board, log, rule, rewrite }
}

impl Probed {
    /// The frames that write, as logged, since the log was last cleared.
    fn writes(&self) -> Vec<String> {
        let writes = ["delegate", "insert", "make_link", "create_new_document", "create_well_known_document", "stage", "publish"];
        self.log.lock().unwrap().iter().filter(|line| writes.iter().any(|op| line.split(' ').next() == Some(*op))).cloned().collect()
    }

    fn clear(&self) {
        self.log.lock().unwrap().clear();
    }

    /// Arms a rule that acts once: at the first frame `at` picks.
    fn once(&self, act: Act, at: impl Fn(&Value) -> bool + Send + 'static) {
        *self.rule.lock().unwrap() = Some(Box::new(move |frame| if at(frame) { act } else { Act::Pass }));
    }
}

/// An account with a home of its own: an intake home, or a stranger's.
struct Home {
    account: String,
    home: String,
    principal: u64,
    signer: HybridSigner,
}

/// An ENFORCING board its registrar claimed, the registrar's store and
/// device key, and the door read off the board.
struct Rig {
    dir: tempfile::TempDir,
    sd: skepd::Skepd,
    board: Board,
    store: FileStore,
    fp: Fingerprint,
    device: HybridSigner,
    anchors: PathBuf,
    door: Door,
    dialer: Arc<dyn Dialer>,
}

fn rig() -> Rig {
    let dir = tempfile::tempdir().unwrap();
    let sd = spawn(&dir.path().join("board"), false);
    let store = FileStore::open(dir.path().join("registrar"));
    let fp = keygen(&store, "registrar laptop");
    let anchors = dir.path().join("anchors");
    let board = board(sd.port());
    claim(&board, &store, &anchors);
    let dialer: Arc<dyn Dialer> = Arc::new(PlainHttp::new());
    let door = Door::read(&board, dialer.clone()).expect("the door");
    Rig { device: key_file(&store, &fp).signer(), dir, sd, board, store, fp, anchors, door, dialer }
}

impl Rig {
    /// The `n`-th account beneath the registrar's, keyed and with its home
    /// minted from its own signed session.
    fn home(&self, n: u64) -> Home {
        let (principal, signer) = (7000 + n, signer_from_seed(&[60 + n as u8; 32]));
        let account = keyed_sub_account(&self.board, &self.anchors, &self.device, n, principal, &signer, "an account beneath the registrar's");
        let token = wire_session(&self.board, principal, &signer);
        let home = wire_home(&self.board, &token, &signer, &account).expect("the home");
        self.board.session_close(&token).unwrap();
        Home { account, home, principal, signer }
    }

    /// `body` written as a request of the row `ty` from `home`'s own doc 1
    /// under its own key: the link's address.
    fn request(&self, home: &Home, ty: &str, body: &str) -> String {
        let token = wire_session(&self.board, home.principal, &home.signer);
        let link = wire_registration(&self.board, &token, &home.signer, &home.home, ty, &[&self.door.account], body).unwrap_or_else(|refused| panic!("the request's deposit: {refused}"));
        self.board.session_close(&token).unwrap();
        link
    }

    /// The door's policy set to `text` with the policy command's library
    /// half: the version it stands as.
    fn policy(&self, text: &str) -> String {
        let session = handshake(&self.board, Scope::Content, &self.device, 1, Site::Console).expect("the registrar's session");
        let set = set_policy(&self.board, &session, &self.device, text.as_bytes()).unwrap_or_else(|h| panic!("set-policy: {h}"));
        session.close().unwrap();
        set.version
    }

    /// A console over `board`: the registrar's own key and store.
    fn console<'a>(&'a self, board: &'a Board, hand: Hand) -> Console<'a> {
        Console { board, store: &self.store, signer: &self.device, principal: 1, hand, dialer: self.dialer.clone() }
    }

    fn queue(&self) -> Queue {
        read_queue(&self.board, None, &self.door).expect("the queue")
    }

    /// The registrar's own signed session's token, for another console's
    /// writes.
    fn registrar_token(&self) -> Token {
        wire_session(&self.board, 1, &self.device)
    }

    fn head(&self) -> u64 {
        self.board.health().unwrap().log_position()
    }

    fn next_account(&self) -> String {
        self.board.next_account_prefix("1").unwrap().expect("a next account")
    }

    /// The registration record at `link`, parsed under its row.
    fn record(&self, link: &str) -> (RegistrationBody, String, Vec<String>) {
        let entry = registration_at(&self.board, None, &mut Atoms::new(&self.board, None), link).expect("the read").unwrap_or_else(|| panic!("no registration record at {link}"));
        let record = entry.record.unwrap_or_else(|refusal| panic!("{link}: {refusal}"));
        let to = entry.stored.value.to.iter().map(|span| span.start.clone()).collect();
        (record.body, record.sig.expect("a signed record"), to)
    }
}

/// An open door approved by an officer, admitting `intake`, with two grounds.
fn policy_text(admission: Admission, approval: &str, intake: &[&str]) -> String {
    let digits = |s: &str| Digits::new(s).unwrap();
    encode_policy(&AdmissionPolicy {
        admission,
        approval: approval.into(),
        intake: intake.iter().map(|a| skep_client::address::parse_address(a).expect("an address")).collect(),
        intake_rate: digits("60"),
        intake_window: digits("3600"),
        intake_per_device: digits("3"),
        collection_interval: digits("1209600"),
        stale_request_interval: digits("2592000"),
        transcription_interval: digits("3600"),
        contact: "registrar@registry.example".into(),
        sponsors: None,
        grounds: vec!["No machine-rate sponsoring.".into(), "One registration a board.".into()],
    })
}

/// An applicant's keys, from seeds: its device key and two pairs.
struct Applicant {
    device: HybridSigner,
    node: [HybridSigner; 2],
    root: [HybridSigner; 2],
}

fn applicant(n: u8) -> Applicant {
    let key = |k: u8| signer_from_seed(&[n.wrapping_mul(8).wrapping_add(k); 32]);
    Applicant { device: key(1), node: [key(2), key(3)], root: [key(4), key(5)] }
}

/// A pair's two anchor-flagged entries, then `device`, device-flagged.
fn enrolment(pair: &[HybridSigner; 2], device: &HybridSigner, name: &str) -> Vec<Enrollment> {
    let entry = |signer: &HybridSigner, anchor: bool, label: String| Enrollment::new(Signer::public_key(signer).clone(), anchor, Some(label)).expect("a label");
    vec![entry(&pair[0], true, format!("{name} sheet a")), entry(&pair[1], true, format!("{name} sheet b")), entry(device, false, "applicant laptop".into())]
}

/// A request's body, framed for `door` under `fresh` and signed by `signer`:
/// fresh where `board` is given, board-carries-on where it is not.
fn request_body(door: &str, fresh: &str, node: &[Enrollment], board: Option<&[Enrollment]>, signer: &HybridSigner) -> String {
    let kind = if board.is_some() { RegistrationKind::Fresh } else { RegistrationKind::BoardCarriesOn };
    let shape = kind.row().ordinal_path();
    let (node, board) = (encode_enroll(node), board.map(encode_enroll));
    let frame = AdmissionFrame { door, fresh, shape: &shape, node: &node, board: board.as_deref() };
    let signature = HexDigits::new(sig_hex(&Signer::sign(signer, &frame.to_bytes()))).expect("hex");
    let (fresh, signed_by) = (Hex64::new(fresh).expect("64 hex"), Hex64::new(Signer::fingerprint(signer).to_hex()).expect("64 hex"));
    let door = door.to_string();
    let body = match board {
        Some(board) => RegistrationBody::Fresh(Fresh { door, fresh, shape, node, board, signer: signed_by, signature }),
        None => RegistrationBody::BoardCarriesOn(BoardCarriesOn { door, fresh, shape, node, signer: signed_by, signature }),
    };
    encode_registration(&body, None)
}

/// A freshness value: one byte, thirty-two times.
fn fresh(byte: u8) -> String {
    format!("{byte:02x}").repeat(32)
}

/// A well-formed fresh request of applicant `n` for this door.
fn good_request(rig: &Rig, n: u8) -> String {
    let a = applicant(n);
    request_body(&rig.door.id.to_string(), &fresh(n), &enrolment(&a.node, &a.device, "node"), Some(&enrolment(&a.root, &a.device, "org root")), &a.device)
}

/// An officer who confirms every act.
fn officer() -> Scripted {
    Scripted::new(vec![Script::Confirm(true), Script::Confirm(true), Script::Confirm(true), Script::Confirm(true)])
}

fn approved(outcome: Outcome) -> skep_client::ceremony::console::Approval {
    match outcome {
        Outcome::Approved(approval) => approval,
        other => panic!("not approved: {other:?}"),
    }
}

fn refused(outcome: Outcome) -> skep_client::ceremony::console::Refusal {
    match outcome {
        Outcome::Refused(refusal) => refusal,
        other => panic!("not refused: {other:?}"),
    }
}

fn yielded(outcome: Outcome) -> skep_client::ceremony::console::Yielded {
    match outcome {
        Outcome::Yielded(left) => left,
        other => panic!("not yielded: {other:?}"),
    }
}

fn halted<T: std::fmt::Debug>(result: Result<T, Halt>) -> String {
    result.expect_err("a halt").to_string()
}

/// FENCE 1 (T-R7(s); REG-4.78; D-1) — THE QUEUE HOLDS REQUESTS FROM
/// ADMITTED HOMES ALONE, BY THE POLICY VERSION AT EACH REQUEST's OWN
/// POSITION. Under a first version naming one intake home, a request on
/// that home is listed, and a request-typed record on a stranger's home is
/// never parsed: not listed, and `approve` at its address names no request
/// and writes nothing. A second version adds the stranger's home: the
/// stranger's EARLIER request is still not admitted, and one it writes
/// after is. A third version drops the first home: its earlier request
/// stays on the queue, and one it writes after is not admitted.
#[test]
fn the_queue_holds_requests_from_admitted_homes_alone_by_the_version_at_their_own_position() {
    let rig = rig();
    let (intake, stranger) = (rig.home(2), rig.home(3));
    let v1 = rig.policy(&policy_text(Admission::Open, "officer", &[&intake.account]));
    assert_eq!(v1, format!("{}.0.5.1", rig.door.account), "the door's first policy version, at well-known document 5");
    let listed = rig.request(&intake, T_REQUEST_FRESH, &good_request(&rig, 1));
    let unadmitted = rig.request(&stranger, T_REQUEST_FRESH, &good_request(&rig, 2));
    let links = |queue: &Queue| queue.threads.iter().map(|thread| thread.request.link.clone()).collect::<Vec<_>>();
    assert_eq!(links(&rig.queue()), [listed.as_str()], "the stranger's record is not on the queue");

    // Not answered either: its address names no request, and nothing is written.
    let before = rig.head();
    let refusal = halted(approve(&rig.console(&rig.board, Hand::Officer), &mut officer(), &unadmitted));
    assert!(refusal.contains("names no request at this door"), "{refusal}");
    assert_eq!(rig.head(), before, "nothing was written");

    // A home a LATER version names does not admit an earlier request.
    let v2 = rig.policy(&policy_text(Admission::Open, "officer", &[&intake.account, &stranger.account]));
    assert_eq!(v2, format!("{}.0.5.2", rig.door.account));
    let later = rig.request(&stranger, T_REQUEST_FRESH, &good_request(&rig, 3));
    assert_eq!(links(&rig.queue()), [listed.clone(), later.clone()], "the stranger's earlier request stays unadmitted; its later one is admitted");

    // A home a later version drops keeps its earlier requests.
    rig.policy(&policy_text(Admission::Open, "officer", &[&stranger.account]));
    let after_the_drop = rig.request(&intake, T_REQUEST_FRESH, &good_request(&rig, 4));
    let queue = rig.queue();
    assert_eq!(links(&queue), [listed, later], "the dropped home's earlier request is read still, its later one is not admitted");
    assert!(queue.thread(&after_the_drop).is_none() && queue.thread(&unadmitted).is_none());
    assert!(queue.threads.iter().all(|thread| thread.request.verdict == Verdict::Passes && thread.state == State::Waiting));
    assert!(queue.passed_over.is_empty(), "{:?}", queue.passed_over);
    rig.sd.shutdown();
}

/// FENCE 2 (the decision item 5; REG-4.78) — THE ROW GUARD: a request whose
/// link is typed another row than its signed `shape` names is passed over
/// before its body is parsed. The daemon refuses such a link at its write,
/// so the cell stands in for a board that did not: a probe answers the
/// request's `read_link` with its type slot moved to the other request row.
/// The record is not on the queue, the console says why, and it names the
/// guard and never the parse.
#[test]
fn a_request_whose_link_is_typed_another_row_than_its_shape_names_is_passed_over_before_its_parse() {
    let rig = rig();
    let intake = rig.home(2);
    rig.policy(&policy_text(Admission::Open, "officer", &[&intake.account]));
    let link = rig.request(&intake, T_REQUEST_FRESH, &good_request(&rig, 1));
    assert_eq!(rig.queue().threads.len(), 1, "the premise: as the board holds it, the request is on the queue");

    let probe = probed(rig.sd.port());
    let moved = link.clone();
    *probe.rewrite.lock().unwrap() = Some(Box::new(move |frame, answer| {
        if frame["op"] == "read_link" && frame["a"] == moved.as_str() {
            answer["link"]["slots"][2][0]["start"] = Value::String(T_REQUEST_BOARD_CARRIES_ON.into());
        }
    }));
    let queue = read_queue(&probe.board, None, &rig.door).expect("the queue");
    assert!(queue.threads.is_empty(), "the record is no request");
    let [passed] = queue.passed_over.as_slice() else { panic!("one record passed over: {:?}", queue.passed_over) };
    assert_eq!(passed.link, link);
    assert_eq!(passed.why, "its link is typed the row 3.54.1.2 and its signed `shape` names `3.54.1.1`", "the row guard's own words, ahead of the parse");
    rig.sd.shutdown();
}

/// FENCE 3 (R7 (a); REG-4.84, REG-4.85, REG-4.95 step 2) — THE FRAMING IS
/// RE-CHECKED AT THE APPROVAL, and each failure is the REFUSED answer and
/// nothing else: a request signed over another door is `not-this-door`; one
/// whose freshness value an earlier request at this door carried is
/// `freshness-spent`; one whose `signer` no enrolment names, and one whose
/// `signer` the node enrolment alone names, are `enrolment-not-honored`.
/// Each refusal stands in the door account's own doc 1 with the request's
/// link as its `to`, and no `delegate`, no genesis and no binding is
/// written for it.
#[test]
fn a_failed_re_check_writes_the_refused_answer_and_no_delegate_no_genesis_no_binding() {
    let rig = rig();
    let intake = rig.home(2);
    rig.policy(&policy_text(Admission::Open, "officer", &[&intake.account]));
    let door = rig.door.id.to_string();
    let other_door = format!("realm:{} door:1.1.0.1", "9f".repeat(32));
    let (a, b, c, d, e) = (applicant(1), applicant(2), applicant(3), applicant(4), applicant(5));
    let both = |x: &Applicant| (enrolment(&x.node, &x.device, "node"), enrolment(&x.root, &x.device, "org root"));

    // Signed over another door: every member in its form, the signature
    // verifying over its own frame.
    let (node, root) = both(&a);
    let elsewhere = rig.request(&intake, T_REQUEST_FRESH, &request_body(&other_door, &fresh(1), &node, Some(&root), &a.device));
    // An earlier request at this door, then one carrying its freshness value.
    let (node, root) = both(&b);
    let first = rig.request(&intake, T_REQUEST_FRESH, &request_body(&door, &fresh(7), &node, Some(&root), &b.device));
    let (node, root) = both(&c);
    let spent = rig.request(&intake, T_REQUEST_FRESH, &request_body(&door, &fresh(7), &node, Some(&root), &c.device));
    // A signer no enrolment names: signed by a key outside the request.
    let (node, root) = both(&d);
    let stray = rig.request(&intake, T_REQUEST_FRESH, &request_body(&door, &fresh(8), &node, Some(&root), &e.device));
    // A signer the node enrolment alone names: the board root's enrolment
    // carries another device key.
    let root_under_another_device = enrolment(&d.root, &e.device, "org root");
    let half = rig.request(&intake, T_REQUEST_FRESH, &request_body(&door, &fresh(9), &node, Some(&root_under_another_device), &d.device));

    let queue = rig.queue();
    let verdict = |link: &str| queue.thread(link).unwrap_or_else(|| panic!("{link} is on the queue")).request.verdict.clone();
    assert_eq!(verdict(&first), Verdict::Passes, "the first request under a freshness value passes");
    let fault = |link: &str| match verdict(link) {
        Verdict::Fails { fault, .. } => fault,
        Verdict::Passes => panic!("{link} passes"),
    };
    let expected = [(&elsewhere, Fault::NotThisDoor), (&spent, Fault::FreshnessSpent), (&stray, Fault::EnrolmentNotHonored), (&half, Fault::EnrolmentNotHonored)];
    for (link, expected) in expected {
        assert_eq!(fault(link), expected, "{link}");
    }

    let frontier = rig.next_account();
    let console = rig.console(&rig.board, Hand::Officer);
    for (link, expected) in expected {
        let refusal = refused(approve(&console, &mut Scripted::new(vec![]), link).unwrap_or_else(|h| panic!("{link}: {h}")));
        assert_eq!((refusal.request.as_str(), refusal.fault), (link.as_str(), expected));
        let (body, _, to) = rig.record(&refusal.answer);
        assert_eq!(body, RegistrationBody::Refused(skep_registry::Refused { fault: expected }), "the fault its one member");
        assert_eq!(to, [link.as_str()], "to the request's link");
        assert!(refusal.answer.starts_with(&format!("{}.0.2.", rig.door.home)), "homed in the door account's own doc 1");
        let again = halted(approve(&console, &mut Scripted::new(vec![]), link));
        assert!(again.contains("is already refused"), "a request is answered once: {again}");
    }
    assert_eq!(rig.next_account(), frontier, "no account was delegated");
    assert!(binding_history(&rig.board, None, &rig.door.home).unwrap().is_empty(), "no binding was written");
    let queue = rig.queue();
    assert_eq!(queue.waiting().map(|thread| thread.request.link.clone()).collect::<Vec<_>>(), [first], "the one request that passes still waits");
    assert_eq!(queue.closed().count(), 4, "the four refused are closed");
    rig.sd.shutdown();
}

/// REG-4.78 — THE SHAPE IS CHECKED BEFORE THE BYTES. A request whose node
/// enrolment names four keys, written on an admitted home, is never parsed:
/// it stands on the queue failing `enrolment-not-honored` with no member of
/// it read — no door, no enrolment, no key — and the approval's hand
/// answers it refused, writing no `delegate`, no genesis and no binding. An
/// officer denies such a request by typing the act's own word, there being
/// no key of it this console read.
#[test]
fn a_request_past_the_shape_is_never_parsed_and_is_refused() {
    let rig = rig();
    let intake = rig.home(2);
    rig.policy(&policy_text(Admission::Open, "officer", &[&intake.account]));
    let over = |n: u8| {
        let a = applicant(n);
        let mut node = enrolment(&a.node, &a.device, "node");
        node.push(Enrollment::new(Signer::public_key(&applicant(n + 40).device).clone(), false, Some("a fourth key".into())).expect("a label"));
        rig.request(&intake, T_REQUEST_FRESH, &request_body(&rig.door.id.to_string(), &fresh(n), &node, Some(&enrolment(&a.root, &a.device, "org root")), &a.device))
    };
    let (first, second) = (over(1), over(2));
    let queue = rig.queue();
    for link in [&first, &second] {
        let request = &queue.thread(link).unwrap_or_else(|| panic!("{link} stands on the queue")).request;
        assert_eq!(request.verdict, Verdict::Fails { fault: Fault::EnrolmentNotHonored, why: "an enrolment names more than 3 keys".into() });
        assert!(request.door.is_empty() && request.node.is_empty() && request.signer.is_empty() && request.keys.is_empty() && request.thread_key.is_empty(), "no member of it was read: {request:?}");
    }
    let frontier = rig.next_account();
    let console = rig.console(&rig.board, Hand::Officer);
    let refusal = refused(approve(&console, &mut Scripted::new(vec![]), &first).unwrap_or_else(|h| panic!("{h}")));
    assert_eq!((refusal.fault, refusal.why.as_str()), (Fault::EnrolmentNotHonored, "an enrolment names more than 3 keys"));
    let (body, _, to) = rig.record(&refusal.answer);
    assert_eq!((body, to), (RegistrationBody::Refused(Refused { fault: Fault::EnrolmentNotHonored }), vec![first.clone()]));
    assert_eq!(rig.next_account(), frontier, "no account was delegated");
    assert!(binding_history(&rig.board, None, &rig.door.home).unwrap().is_empty(), "no binding was written");

    let mut person = officer();
    let denial = deny(&console, &mut person, &second, 1).unwrap_or_else(|h| panic!("{h}"));
    assert!(person.transcript.join("\n").contains("to deny it, type `deny`; or `no`"), "the row is the act's own word: {}", person.transcript.join("\n"));
    assert_eq!(rig.queue().thread(&second).unwrap().answers[0].link, denial.answer);
    rig.sd.shutdown();
}

/// One place an approval is stopped: what it is, and the frame it is at.
type Stop = (&'static str, fn(&Value) -> bool);

/// What stands on the board for one approved request, read back whole.
struct Stood {
    accounts: Vec<String>,
    approvals: Vec<String>,
    bindings: usize,
    answers: usize,
}

fn stood(rig: &Rig, request: &str) -> Stood {
    let enrolls = skep_client::ceremony::registry_record::links_homed(&rig.board, None, &rig.door.home, T_ENROLL).unwrap();
    let mut accounts = Vec::new();
    for link in enrolls {
        let to = stored_link(&rig.board, None, &link).unwrap().unwrap().value.to.iter().map(|span| span.start.clone()).collect::<Vec<_>>();
        if to != [rig.door.account.clone()] {
            accounts.extend(to.into_iter().filter(|account| !account.starts_with(&format!("{}.", rig.door.account))));
        }
    }
    let approvals = skep_client::ceremony::registry_record::links_homed(&rig.board, None, &rig.door.home, T_APPROVAL).unwrap();
    let queue = rig.queue();
    let thread = queue.thread(request).expect("the request");
    Stood { accounts, approvals, bindings: binding_history(&rig.board, None, &rig.door.home).unwrap().len(), answers: thread.answers.len() }
}

/// FENCE 4 (R8 (a), (m); REG-4.109, REG-4.123 step 1; REG-4.86) — THE MINT
/// IS THE `delegate` AND THE GENESIS WITH THE APPROVAL LINK, AHEAD OF THE
/// BINDING, AND A STOPPED APPROVAL RESUMES BY READING. A whole approval
/// writes, in this order: the `delegate`, the genesis — the request's `node`
/// enrolment, verbatim — its link, the approval link, the binding and its
/// link, the approved answer and its link. Then four approvals are each
/// stopped once — the `delegate`'s ack lost, the genesis's, the approval
/// link's, the binding's — and run again: each resumes by reading and ends
/// with one account, one genesis, one approval link, one binding and one
/// answer, the store's persist-first line standing before the `delegate`
/// answered.
#[test]
fn the_mint_is_ordered_ahead_of_the_binding_and_a_stopped_approval_resumes_by_reading() {
    let rig = rig();
    let intake = rig.home(2);
    rig.policy(&policy_text(Admission::Open, "officer", &[&intake.account]));
    let probe = probed(rig.sd.port());
    let console = rig.console(&probe.board, Hand::Officer);

    // The whole act, in order.
    let whole = rig.request(&intake, T_REQUEST_FRESH, &good_request(&rig, 1));
    let frontier = rig.next_account();
    probe.clear();
    let done = approved(approve(&console, &mut officer(), &whole).unwrap_or_else(|h| panic!("{h}")));
    assert_eq!(
        probe.writes(),
        [
            "delegate".to_string(),
            format!("insert {T_ENROLL}"),
            format!("make_link {T_ENROLL}"),
            format!("make_link {T_APPROVAL}"),
            format!("insert {T_BINDING}"),
            format!("make_link {T_BINDING}"),
            format!("insert {T_REPLY_APPROVED}"),
            format!("make_link {T_REPLY_APPROVED}"),
        ],
        "the delegate and the genesis with the approval link, then the binding, then the reply"
    );
    assert_eq!(done.node_address, frontier, "the board's next top-level account");
    // The genesis is the request's node enrolment, verbatim.
    let a = applicant(1);
    let node = encode_enroll(&enrolment(&a.node, &a.device, "node"));
    let genesis = stored_link(&rig.board, None, &done.genesis).unwrap().expect("the genesis link");
    let atom = genesis.value.from[0].start.clone();
    let written = Atoms::new(&rig.board, None).read(&rig.door.home, &atom).unwrap().expect("the genesis record");
    let record: Value = serde_json::from_slice(&written).unwrap();
    let mut sigless = record.clone();
    sigless.as_object_mut().unwrap().remove("sig");
    assert!(record["sig"].is_string() && String::from_utf8(written.clone()).unwrap().starts_with(&node[..node.len() - 1]), "the request's `node` bytes, then the console's sig");
    assert_eq!(sigless, serde_json::from_str::<Value>(&node).unwrap());

    // Stopped once at each write, then run again.
    let stops: [Stop; 4] = [
        ("the delegate's ack lost", |frame| frame["op"] == "delegate"),
        ("the genesis's ack lost", |frame| frame["op"] == "make_link" && frame["ty"]["addrs"][0] == T_ENROLL),
        ("the approval link's ack lost", |frame| frame["op"] == "make_link" && frame["ty"]["addrs"][0] == T_APPROVAL),
        ("the binding's ack lost", |frame| frame["op"] == "make_link" && frame["ty"]["addrs"][0] == T_BINDING),
    ];
    let mut expected_accounts = vec![done.node_address.clone()];
    for (n, (what, at)) in stops.into_iter().enumerate() {
        let request = rig.request(&intake, T_REQUEST_FRESH, &good_request(&rig, 10 + n as u8));
        let frontier = rig.next_account();
        let lines_before = rig.store.all_bindings().unwrap().len();
        probe.once(Act::Lose, at);
        let stopped = halted(approve(&console, &mut officer(), &request));
        assert!(probe.rule.lock().unwrap().is_none(), "{what}: the probe fired ({stopped})");
        // The `new_id` is on disk before the `delegate` is sent.
        assert_eq!(rig.store.all_bindings().unwrap().len(), lines_before + 1, "{what}: the persist-first line stands");
        assert_ne!(rig.next_account(), frontier, "{what}: the delegate committed");
        let after_the_stop = rig.next_account();

        probe.clear();
        let resumed = approved(approve(&console, &mut officer(), &request).unwrap_or_else(|h| panic!("{what}: the resume halted: {h}")));
        assert_eq!(resumed.node_address, frontier, "{what}: the account the stopped run delegated");
        assert_eq!(rig.next_account(), after_the_stop, "{what}: no second account was delegated");
        assert!(!probe.writes().iter().any(|line| line == "delegate"), "{what}: {:?}", probe.writes());
        expected_accounts.push(resumed.node_address.clone());
        let stands = stood(&rig, &request);
        assert_eq!(stands.accounts, expected_accounts, "{what}: one genesis an account");
        assert_eq!((stands.approvals.len(), stands.bindings, stands.answers), (n + 2, n + 2, 1), "{what}: one approval link, one binding, one answer a request");
        let again = halted(approve(&console, &mut officer(), &request));
        assert!(again.contains("is already approved"), "{what}: {again}");
    }
    rig.sd.shutdown();
}

/// FENCE 5 (R2 (c); REG-2.16) — BIND, THEN READ BACK, UNTIL THE READ-BACK
/// FINDS THE ACCOUNT MINTED AT THE PREFIX BOUND. Another console binds the
/// prefix this one derived, to another account, between this console's read
/// of the bindings and its own binding's write. Both bindings commit; the
/// read-back finds the other account at `1.2`; this console takes the next
/// prefix, binds it and reads it back, and its answer names `1.3` — the
/// prefix that resolves to the account it minted.
#[test]
fn a_binding_that_loses_its_race_is_read_back_and_the_next_prefix_bound() {
    let rig = rig();
    let intake = rig.home(2);
    let rival_account = rig.home(3).account;
    rig.policy(&policy_text(Admission::Open, "officer", &[&intake.account]));
    let request = rig.request(&intake, T_REQUEST_FRESH, &good_request(&rig, 1));
    let probe = probed(rig.sd.port());
    // The other console: its binding of `1.2` lands just ahead of this one's.
    let (port, store, fp, home) = (rig.sd.port(), rig.dir.path().join("registrar"), rig.fp, rig.door.home.clone());
    let mut raced = false;
    *probe.rule.lock().unwrap() = Some(Box::new(move |frame| {
        if !raced && frame["op"] == "insert" && frame["deposit"] == T_BINDING {
            raced = true;
            let (board, device) = (board(port), key_file(&FileStore::open(&store), &fp).signer());
            let token = wire_session(&board, 1, &device);
            wire_binding(&board, &token, &device, &home, "1.2", Some(&rival_account), None).expect("the other console's binding");
            board.session_close(&token).unwrap();
        }
        Act::Pass
    }));
    let done = approved(approve(&rig.console(&probe.board, Hand::Officer), &mut officer(), &request).unwrap_or_else(|h| panic!("{h}")));
    assert_eq!(done.prefix, "1.3", "the prefix the read-back found the minted account at");
    let history = binding_history(&rig.board, None, &rig.door.home).unwrap();
    let standing: Vec<(&str, Option<&str>, bool)> = history.iter().map(|binding| (binding.prefix.as_str(), binding.account.as_deref(), binding.honored)).collect();
    assert_eq!(standing.len(), 3, "{standing:?}");
    assert!(standing[0].0 == "1.2" && standing[0].2 && standing[0].1 != Some(done.node_address.as_str()), "the other console's binding stood first: {standing:?}");
    assert_eq!(standing[1], ("1.2", Some(done.node_address.as_str()), false), "this console's first binding is inert");
    assert_eq!(standing[2], ("1.3", Some(done.node_address.as_str()), true));
    let (body, _, _) = rig.record(&done.answer);
    let RegistrationBody::Approved(answer) = body else { panic!("an approved answer") };
    assert_eq!(answer.prefix.to_string(), "1.3", "the answer names the FINAL prefix, never the derived one");
    rig.sd.shutdown();
}

/// REG-4.86, REG-4.95 step 4 — TWO CONSOLES AT ONE REQUEST: THE FIRST
/// GENESIS BY JOURNAL ORDER IS THE REGISTRATION. Another console of the
/// registrar's keys an account of its own for the request between this
/// console's read of the genesis registry and its own genesis's write, and
/// both commit. This console writes its approval link, binds `1.2` and reads
/// it back as its own; the same pass reads the genesis registry again and
/// finds the other console's genesis ahead of its own. It sends no answer,
/// retires the binding it wrote — a binding of `1.2` to nobody, naming it —
/// and answers that it left the request. Run again, the approval resumes at
/// the account whose genesis stood first, mints nothing, binds the next
/// prefix — `1.2`, named once, is never named again — and answers: the
/// thread holds one answer.
#[test]
fn two_consoles_at_one_request_the_later_genesis_sends_no_answer_and_retires_its_binding() {
    let rig = rig();
    let intake = rig.home(2);
    rig.policy(&policy_text(Admission::Open, "officer", &[&intake.account]));
    let request = rig.request(&intake, T_REQUEST_FRESH, &good_request(&rig, 1));
    let probe = probed(rig.sd.port());
    // The other console: its account and its genesis land just ahead of
    // this console's own genesis.
    let (port, store, fp, home) = (rig.sd.port(), rig.dir.path().join("registrar"), rig.fp, rig.door.home.clone());
    let a = applicant(1);
    let node = enrolment(&a.node, &a.device, "node");
    let rival = Arc::new(Mutex::new(None::<String>));
    let (seen, mut raced) = (rival.clone(), false);
    *probe.rule.lock().unwrap() = Some(Box::new(move |frame| {
        if !raced && frame["op"] == "insert" && frame["deposit"] == T_ENROLL {
            raced = true;
            let (board, device) = (board(port), key_file(&FileStore::open(&store), &fp).signer());
            let zero = wire_session(&board, 0, &device);
            let account = board.next_account_prefix("1").unwrap().expect("a next account");
            wire_delegate(&board, &zero, &account, 880_101).expect("the other console's delegate");
            board.session_close(&zero).unwrap();
            let token = wire_session(&board, 1, &device);
            wire_enroll(&board, &token, &device, &home, &account, &node).expect("the other console's genesis");
            board.session_close(&token).unwrap();
            *seen.lock().unwrap() = Some(account);
        }
        Act::Pass
    }));
    let console = rig.console(&probe.board, Hand::Officer);
    let mut person = officer();
    let left = yielded(approve(&console, &mut person, &request).unwrap_or_else(|h| panic!("{h}")));
    let rival = rival.lock().unwrap().clone().expect("the probe fired");
    assert_eq!((left.request.as_str(), left.account.as_deref(), left.answer.as_deref()), (request.as_str(), Some(rival.as_str()), None), "{left:?}");
    assert!(person.transcript.join("\n").contains("is LEFT to the other console, and no answer is sent"), "{}", person.transcript.join("\n"));
    let retired = left.retired.expect("the binding this run wrote is retired");
    // What stands: this console's `1.2`, bound and retired, and no answer.
    let history = binding_history(&rig.board, None, &rig.door.home).unwrap();
    assert_eq!(history.len(), 2, "{history:?}");
    assert!(history[0].prefix == "1.2" && history[0].honored && history[0].account.is_some() && history[0].account.as_deref() != Some(rival.as_str()), "this console bound its own account: {history:?}");
    assert_eq!(
        (history[1].link.as_str(), history[1].prefix.as_str(), history[1].account.as_deref(), history[1].replaces.as_deref(), history[1].honored),
        (retired.as_str(), "1.2", None, Some(history[0].link.as_str()), true),
        "and retired it, by a binding to nobody that names it"
    );
    let queue = rig.queue();
    let thread = queue.thread(&request).unwrap();
    assert!(thread.answers.is_empty() && thread.state == State::Waiting, "no answer was sent: {thread:?}");
    let before = stood(&rig, &request);
    assert_eq!((before.accounts.len(), before.approvals.len()), (2, 1), "two accounts keyed for one request, and this console's approval link");

    // Run again: the registration is the first genesis's account.
    probe.clear();
    let done = approved(approve(&console, &mut officer(), &request).unwrap_or_else(|h| panic!("{h}")));
    assert_eq!((done.node_address.as_str(), done.prefix.as_str()), (rival.as_str(), "1.3"), "the first genesis's account, at a prefix never named before");
    assert!(!probe.writes().iter().any(|line| line == "delegate" || *line == format!("insert {T_ENROLL}")), "nothing is minted again: {:?}", probe.writes());
    let after = stood(&rig, &request);
    assert_eq!((after.accounts.len(), after.approvals.len(), after.bindings, after.answers), (2, 2, 3, 1), "one request, one answer");
    let (body, _, _) = rig.record(&done.answer);
    let RegistrationBody::Approved(answer) = body else { panic!("an approved answer") };
    assert_eq!((answer.node_address.to_string(), answer.prefix.to_string()), (rival, "1.3".to_string()));
    rig.sd.shutdown();
}

/// REG-4.86 ("one request has one reply"); REG-1.43 — AN ANSWER ANOTHER
/// CONSOLE WROTE WHILE THIS ONE RAN IS READ BEFORE THIS ONE's. While this
/// console's approval stands between its binding and its reply, another
/// console denies the request: this one reads the thread again, sends no
/// second answer, and retires the binding it wrote, so a denied request
/// holds no prefix. And while a denial waits on its confirmation another
/// console refuses the request: the denial reads the thread again before it
/// writes, halts naming the answer that stands, and writes nothing.
#[test]
fn an_answer_written_while_a_console_runs_is_read_before_its_own_and_no_second_is_sent() {
    let rig = rig();
    let intake = rig.home(2);
    let version = rig.policy(&policy_text(Admission::Open, "officer", &[&intake.account]));
    let probe = probed(rig.sd.port());
    let console = rig.console(&probe.board, Hand::Officer);
    // Another console's answer to `request`, of the row `ty`, written when
    // this console sends the first frame `at` picks.
    let other_answers = |request: &str, ty: &'static str, body: String, at: fn(&Value) -> bool| {
        let (port, store, fp, home, request) = (rig.sd.port(), rig.dir.path().join("registrar"), rig.fp, rig.door.home.clone(), request.to_string());
        let written = Arc::new(Mutex::new(None::<String>));
        let (seen, mut raced) = (written.clone(), false);
        *probe.rule.lock().unwrap() = Some(Box::new(move |frame| {
            if !raced && at(frame) {
                raced = true;
                let (board, device) = (board(port), key_file(&FileStore::open(&store), &fp).signer());
                let token = wire_session(&board, 1, &device);
                let link = wire_registration(&board, &token, &device, &home, ty, &[&request], &body).expect("the other console's answer");
                board.session_close(&token).unwrap();
                *seen.lock().unwrap() = Some(link);
            }
            Act::Pass
        }));
        written
    };

    // An approval, denied by another console between its binding and its reply.
    let first = rig.request(&intake, T_REQUEST_FRESH, &good_request(&rig, 1));
    let denied = encode_registration(&RegistrationBody::Denied(Denied { policy: skep_client::address::parse_address(&version).unwrap(), clause: Digits::new("1").unwrap() }), None);
    let theirs = other_answers(&first, T_REPLY_DENIED, denied, |frame| frame["op"] == "make_link" && frame["ty"]["addrs"][0] == T_BINDING);
    let left = yielded(approve(&console, &mut officer(), &first).unwrap_or_else(|h| panic!("{h}")));
    let theirs = theirs.lock().unwrap().clone().expect("the probe fired");
    assert_eq!((left.account.as_deref(), left.answer.as_deref()), (None, Some(theirs.as_str())), "{left:?}");
    let history = binding_history(&rig.board, None, &rig.door.home).unwrap();
    assert_eq!(history.iter().map(|b| (b.prefix.as_str(), b.account.is_some(), b.honored)).collect::<Vec<_>>(), [("1.2", true, true), ("1.2", false, true)], "the binding this run wrote is retired");
    assert_eq!(left.retired.as_deref(), Some(history[1].link.as_str()));
    let queue = rig.queue();
    let thread = queue.thread(&first).unwrap();
    assert_eq!((thread.answers.len(), thread.answers[0].link.as_str(), thread.state), (1, theirs.as_str(), State::Closed), "one answer: the other console's");

    // A denial, refused by another console while it waited.
    let second = rig.request(&intake, T_REQUEST_FRESH, &good_request(&rig, 2));
    let refused_body = encode_registration(&RegistrationBody::Refused(Refused { fault: Fault::NotThisDoor }), None);
    let theirs = other_answers(&second, T_REPLY_REFUSED, refused_body, |frame| frame["op"] == "key_set");
    let halt = halted(deny(&console, &mut officer(), &second, 1));
    let theirs = theirs.lock().unwrap().clone().expect("the probe fired at the denial's own session");
    assert!(halt.contains("was answered while this denial waited, and is not denied") && halt.contains(&theirs), "{halt}");
    let queue = rig.queue();
    let thread = queue.thread(&second).unwrap();
    assert_eq!((thread.answers.len(), thread.answers[0].link.as_str()), (1, theirs.as_str()), "one answer: the other console's");
    rig.sd.shutdown();
}

/// FENCE 6 (R2 (e); REG-2.3) — NEXT-FORM READS THE BINDINGS AND NOTHING
/// ELSE, AND A PREFIX NAMED ONCE IS NEVER NAMED AGAIN. The board holds a
/// held prefix, `1.2`; a retired one, `1.3`, bound and then bound to
/// nobody; and `1.5`, named by a binding the walk never honored. It also
/// holds accounts delegated and abandoned, which no binding names. The next
/// approval binds `1.6`: past every prefix a binding has ever named, held,
/// retired or inert, and unmoved by the delegations.
#[test]
fn next_form_reads_the_bindings_alone_and_names_no_prefix_twice() {
    let rig = rig();
    let intake = rig.home(2);
    let (held, retired) = (rig.home(3).account, rig.home(4).account);
    rig.policy(&policy_text(Admission::Open, "officer", &[&intake.account]));
    let token = rig.registrar_token();
    let bind = |prefix: &str, account: Option<&str>, replaces: Option<&str>| wire_binding(&rig.board, &token, &rig.device, &rig.door.home, prefix, account, replaces).expect("a binding");
    bind("1.2", Some(&held), None);
    let allocated = bind("1.3", Some(&retired), None);
    bind("1.3", None, Some(&allocated));
    // A first record of `1.5` naming a state where none has stood: inert.
    bind("1.5", Some(&held), Some(&allocated));
    // Two accounts delegated and abandoned: no key, no binding.
    let zero = wire_session(&rig.board, 0, &rig.device);
    for id in [880_001u64, 880_002] {
        let address = rig.next_account();
        wire_delegate(&rig.board, &zero, &address, id).expect("an abandoned delegate");
    }
    rig.board.session_close(&zero).unwrap();
    rig.board.session_close(&token).unwrap();

    let request = rig.request(&intake, T_REQUEST_FRESH, &good_request(&rig, 1));
    let frontier = rig.next_account();
    let done = approved(approve(&rig.console(&rig.board, Hand::Officer), &mut officer(), &request).unwrap_or_else(|h| panic!("{h}")));
    assert_eq!(done.prefix, "1.6", "past the held 1.2, the retired 1.3 and the inert 1.5");
    assert_eq!(done.node_address, frontier, "the account is the board's next; the prefix is the bindings' next");
    let history = binding_history(&rig.board, None, &rig.door.home).unwrap();
    assert_eq!(history.iter().map(|b| (b.prefix.as_str(), b.honored)).collect::<Vec<_>>(), [("1.2", true), ("1.3", true), ("1.3", true), ("1.5", false), ("1.6", true)]);
    rig.sd.shutdown();
}

/// Whether `sig` verifies under `key` over the record frame of a deposit of
/// `sigless` homed in `home`, typed `ty` and naming `to`.
fn signed_by(rig: &Rig, key: &HybridSigner, home: &str, ty: &str, to: &[&str], sigless: &str, sig: &str) -> bool {
    let term = rig.board.board_term().unwrap().expect("H.1");
    let frame = RecordFrame { alg: Signer::public_key(key).alg(), board: term, home_account: &rig.door.account, home, ty, to, sigless: sigless.as_bytes() }.compose().expect("a frame");
    let blob: Vec<u8> = (0..sig.len()).step_by(2).map(|i| u8::from_str_radix(&sig[i..i + 2], 16).expect("hex")).collect();
    skep_signature::verify(Signer::tag(key), Signer::public_key(key), &frame, &blob).is_ok()
}

/// FENCES 7 and 8 (T-R8(s); R8 (a); REG-4.108; R7 (h); REG-4.79; Q1; P-15;
/// P-19; RES-273) — WHAT AN APPROVAL LEAVES, AND UNDER WHOSE KEY. The
/// approved answer stands in the binding-writing account's own doc 1 with
/// the request's link as its `to`. At the root it carries the node account's
/// pair alone — no board members, no `door_origin` — the collection interval
/// copied from the policy version standing at the approval, the disposition
/// `retirement`, and that version's address. The approval link runs from the
/// genesis to the request, typed `3.54.4`, in that same doc 1. The binding
/// and the answer each carry a `sig` that verifies under the registrar's own
/// key and under no agent's; and a console under an agent's key — a key of
/// another account's set — writes nothing.
#[test]
fn an_approval_leaves_the_node_accounts_pair_alone_in_the_registrars_own_doc_1_under_the_registrars_key() {
    let rig = rig();
    let intake = rig.home(2);
    let version = rig.policy(&policy_text(Admission::Open, "officer", &[&intake.account]));
    let request = rig.request(&intake, T_REQUEST_FRESH, &good_request(&rig, 1));

    // An agent's key answers nothing: it opens no session as the door's
    // account, and a console under its own account is not the door's.
    let agent_store = FileStore::open(rig.dir.path().join("agent"));
    let before = rig.head();
    let as_the_registrar = Console { board: &rig.board, store: &agent_store, signer: &intake.signer, principal: 1, hand: Hand::Officer, dialer: rig.dialer.clone() };
    let refusal = halted(approve(&as_the_registrar, &mut officer(), &request));
    assert!(refusal.contains("this console's key is not enrolled at"), "{refusal}");
    let as_itself = Console { principal: intake.principal, ..as_the_registrar };
    let refusal = halted(approve(&as_itself, &mut officer(), &request));
    assert!(refusal.contains("does not write this board's bindings"), "{refusal}");
    assert_eq!(rig.head(), before, "an agent's key wrote nothing");

    let mut person = officer();
    let done = approved(approve(&rig.console(&rig.board, Hand::Officer), &mut person, &request).unwrap_or_else(|h| panic!("{h}\n{}", person.transcript.join("\n"))));
    assert!(person.said("CONSENT confirm"), "the officer was asked once: {:?}", person.transcript);

    // The approved answer: its home, its `to`, its members.
    assert!(done.answer.starts_with(&format!("{}.0.2.", rig.door.home)), "the answer is homed in the door account's own doc 1: {}", done.answer);
    let (body, sig, to) = rig.record(&done.answer);
    assert_eq!(to, [request.as_str()], "to the request's link, one address");
    let RegistrationBody::Approved(answer) = &body else { panic!("an approved answer: {body:?}") };
    assert_eq!((answer.prefix.to_string(), answer.node_address.to_string(), answer.node_principal.get()), (done.prefix.clone(), done.node_address.clone(), done.node_principal));
    assert_eq!(done.prefix, "1.2", "the first prefix a root door allocates");
    assert_eq!(rig.board.principal_prefix(done.node_principal).unwrap().as_deref(), Some(done.node_address.as_str()), "the principal the board seats at the account");
    assert!(answer.board.is_none() && answer.door_origin.is_none(), "at the root, the node account's pair alone");
    assert_eq!(answer.collection_interval.as_str(), "1209600", "copied from the policy version at the approval");
    assert_eq!(answer.disposition, Disposition::Retirement);
    assert_eq!(answer.policy.to_string(), version, "the version address the two were read off");

    // The approval link: from the genesis to the request, in that doc 1.
    assert!(done.approval.starts_with(&format!("{}.0.2.", rig.door.home)));
    let approval = stored_link(&rig.board, None, &done.approval).unwrap().expect("the approval link");
    let starts = |slot: &[skep_client::board::LinkSpan]| slot.iter().map(|span| span.start.clone()).collect::<Vec<_>>();
    assert_eq!((starts(&approval.value.from), starts(&approval.value.to), starts(&approval.value.ty)), (vec![done.genesis.clone()], vec![request.clone()], vec![T_APPROVAL.to_string()]));
    let genesis = stored_link(&rig.board, None, &done.genesis).unwrap().expect("the genesis link");
    assert_eq!(starts(&genesis.value.to), [done.node_address.as_str()], "the genesis names the node account");
    let (approval_at, binding_at) = (approval.value.at.unwrap(), stored_link(&rig.board, None, &done.binding).unwrap().unwrap().value.at.unwrap());
    assert!(genesis.value.at.unwrap() < approval_at && approval_at < binding_at, "the approval link is written with the genesis, ahead of the binding");

    // Each record's `sig`: the registrar's own key, and no agent's.
    let sigless = encode_registration(&body, None);
    assert!(signed_by(&rig, &rig.device, &rig.door.home, T_REPLY_APPROVED, &[&request], &sigless, &sig), "the answer is signed under the registrar's key");
    assert!(!signed_by(&rig, &intake.signer, &rig.door.home, T_REPLY_APPROVED, &[&request], &sigless, &sig), "and under no agent's");
    let binding = stored_link(&rig.board, None, &done.binding).unwrap().unwrap();
    let bytes = Atoms::new(&rig.board, None).read(&rig.door.home, &binding.value.from[0].start).unwrap().expect("the binding's atom");
    let record = skep_registry::parse(skep_registry::BodyKind::Binding, &bytes).expect("a binding");
    assert!(signed_by(&rig, &rig.device, &rig.door.home, T_BINDING, &[&done.node_address], &record.canonical_sigless(), record.sig.as_deref().unwrap()), "the binding is signed under the registrar's key");
    assert!(!signed_by(&rig, &intake.signer, &rig.door.home, T_BINDING, &[&done.node_address], &record.canonical_sigless(), record.sig.as_deref().unwrap()));
    rig.sd.shutdown();
}

/// A second device key enrolled in the registrar's own set, non-anchor: the
/// labeled registrar device key, in a store of its own.
fn labeled_key(rig: &Rig) -> (FileStore, HybridSigner) {
    let store = FileStore::open(rig.dir.path().join("console"));
    let fp = keygen(&store, "registry console");
    let file = key_file(&store, &fp);
    let token = rig.registrar_token();
    wire_enroll(&rig.board, &token, &rig.device, &rig.door.home, &rig.door.account, &[entry_of(&file, "registry console")]).expect("the console's key enrolled");
    rig.board.session_close(&token).unwrap();
    (store, file.signer())
}

/// FENCE 9 (U2; R8 (b); T-R12(s); D-2; REG-4.108) — THE UNATTENDED HAND
/// ACTS ONLY UNDER OPEN ADMISSION NAMING `auto`. Under a policy naming the
/// officer, and under `auto` at a door that is not open, which fails closed
/// to the officer, a pass of the unattended console writes nothing — no
/// approval, and no refusal of a request that fails the re-check — and says
/// why. Under open admission naming `auto` it approves the request that
/// passes and refuses the one that fails, each under the labeled key, whose
/// `sig` verifies under that key and not under the officer's.
#[test]
fn the_unattended_hand_approves_only_under_open_admission_naming_auto() {
    let rig = rig();
    let intake = rig.home(2);
    let (store, labeled) = labeled_key(&rig);
    let console = Console { board: &rig.board, store: &store, signer: &labeled, principal: 1, hand: Hand::Unattended, dialer: rig.dialer.clone() };
    rig.policy(&policy_text(Admission::Open, "officer", &[&intake.account]));
    let passing = rig.request(&intake, T_REQUEST_FRESH, &good_request(&rig, 1));
    let a = applicant(2);
    let failing = rig.request(&intake, T_REQUEST_FRESH, &request_body(&rig.door.id.to_string(), &fresh(1), &enrolment(&a.node, &a.device, "node"), Some(&enrolment(&a.root, &a.device, "org root")), &a.device));
    let never = || false;

    let withheld = [
        (policy_text(Admission::Open, "officer", &[&intake.account]), "is `open` admission approved by `officer`"),
        (policy_text(Admission::NVouches(Digits::new("2").unwrap()), "auto", &[&intake.account]), "is `n-vouches` admission approved by `auto`"),
        (policy_text(Admission::InvitationOnly, "auto", &[&intake.account]), "is `invitation-only` admission approved by `auto`"),
        (policy_text(Admission::Open, "steward", &[&intake.account]), "names no approval hand this console knows"),
    ];
    for (n, (text, why)) in withheld.iter().enumerate() {
        if n > 0 {
            rig.policy(text);
        }
        let before = rig.head();
        let round = auto_round(&console, &mut Scripted::new(vec![]), &never).expect("a pass");
        let said = round.withheld.as_deref().unwrap_or_else(|| panic!("the hand is withheld under {text}"));
        assert!(said.contains(why), "{said}");
        assert!(round.acts.is_empty() && round.waiting == 2 && rig.head() == before, "nothing was written, the failing request's refusal among it");
        assert_eq!(unattended_withheld(&rig.queue()).as_deref(), Some(said));
        // The act itself refuses as the pass does.
        let refusal = halted(approve(&console, &mut Scripted::new(vec![]), &passing));
        assert!(refusal.contains("does not open the unattended hand") || refusal.contains("approves at an open door alone") || refusal.contains("opens no approval"), "{refusal}");
        assert_eq!(rig.head(), before);
    }

    rig.policy(&policy_text(Admission::Open, "auto", &[&intake.account]));
    assert_eq!(unattended_withheld(&rig.queue()), None);
    let mut person = Scripted::new(vec![]);
    let round = auto_round(&console, &mut person, &never).unwrap_or_else(|h| panic!("{h}\n{}", person.transcript.join("\n")));
    assert!(round.withheld.is_none() && !round.stopped && round.waiting == 0, "{round:?}");
    let [Outcome::Approved(approval), Outcome::Refused(refusal)] = round.acts.as_slice() else { panic!("an approval, then a refusal: {:?}", round.acts) };
    assert_eq!((approval.request.as_str(), refusal.request.as_str(), refusal.fault), (passing.as_str(), failing.as_str(), Fault::FreshnessSpent));
    assert!(!person.transcript.iter().any(|line| line.starts_with("CONSENT")), "the unattended hand is asked nothing: {:?}", person.transcript);
    for (answer, ty, request) in [(&approval.answer, T_REPLY_APPROVED, &passing), (&refusal.answer, T_REPLY_REFUSED, &failing)] {
        let (body, sig, _) = rig.record(answer);
        let sigless = encode_registration(&body, None);
        assert!(signed_by(&rig, &labeled, &rig.door.home, ty, &[request], &sigless, &sig), "{answer}: signed under the labeled key");
        assert!(!signed_by(&rig, &rig.device, &rig.door.home, ty, &[request], &sigless, &sig), "{answer}: told from an officer's by its key");
    }
    // A stop asked between acts ends the pass with nothing begun.
    let third = rig.request(&intake, T_REQUEST_FRESH, &good_request(&rig, 3));
    let before = rig.head();
    let round = auto_round(&console, &mut Scripted::new(vec![]), &|| true).expect("a pass");
    assert!(round.stopped && round.acts.is_empty() && round.waiting == 1 && rig.head() == before, "{round:?}");
    assert_eq!(rig.queue().waiting().map(|t| t.request.link.clone()).collect::<Vec<_>>(), [third]);
    rig.sd.shutdown();
}

/// FENCE 11 (U7; REG-4.99) — THE DENIAL CITES A CLAUSE OF THE POLICY
/// VERSION STANDING, BY ITS POSITION FROM 1. `deny` under clause 2 writes
/// the denied answer in the door account's own doc 1: `policy` the address
/// of the version standing at the denial — the second, not the one the
/// request was written under — and `clause` `"2"`, the second ground. A
/// clause past the list, and clause 0, are refused before any write; a
/// denial works at a door that is not open, where `approve` is refused
/// naming the mode; and the unattended hand never denies.
#[test]
fn a_denial_cites_the_clause_by_its_position_in_the_version_standing() {
    let rig = rig();
    let intake = rig.home(2);
    rig.policy(&policy_text(Admission::Open, "officer", &[&intake.account]));
    let request = rig.request(&intake, T_REQUEST_FRESH, &good_request(&rig, 1));
    let second = rig.request(&intake, T_REQUEST_FRESH, &good_request(&rig, 2));
    let standing = rig.policy(&policy_text(Admission::InvitationOnly, "officer", &[&intake.account]));
    assert_eq!(standing, format!("{}.0.5.2", rig.door.account));
    let console = rig.console(&rig.board, Hand::Officer);

    let before = rig.head();
    for clause in [0, 3, 40] {
        let refusal = halted(deny(&console, &mut officer(), &request, clause));
        assert!(refusal.contains(&format!("the policy standing has no clause {clause}")) && refusal.contains("states 2 grounds"), "{refusal}");
    }
    let unattended = Console { hand: Hand::Unattended, ..rig.console(&rig.board, Hand::Officer) };
    let refusal = halted(deny(&unattended, &mut officer(), &request, 2));
    assert!(refusal.contains("a denial is an officer's alone"), "{refusal}");
    let refusal = halted(approve(&console, &mut officer(), &request));
    assert!(refusal.contains("this door's admission is `invitation-only`, and `skep approve` approves at an open door alone"), "{refusal}");
    let declined = halted(deny(&console, &mut Scripted::new(vec![Script::Confirm(false)]), &request, 2));
    assert!(declined.contains("the request was not denied: the confirmation was declined"), "{declined}");
    assert_eq!(rig.head(), before, "no refusal wrote");

    let mut person = officer();
    let denial = deny(&console, &mut person, &request, 2).unwrap_or_else(|h| panic!("{h}"));
    assert!(person.said("One registration a board."), "the clause's words are said before the answer: {:?}", person.transcript);
    assert_eq!((denial.policy.as_str(), denial.clause, denial.ground.as_str()), (standing.as_str(), 2, "One registration a board."));
    let (body, sig, to) = rig.record(&denial.answer);
    let RegistrationBody::Denied(denied) = &body else { panic!("a denied answer: {body:?}") };
    assert_eq!((denied.policy.to_string(), denied.clause.as_str()), (standing.clone(), "2"), "the version standing at the denial, and the position from 1");
    assert_eq!(to, [request.as_str()]);
    assert!(denial.answer.starts_with(&format!("{}.0.2.", rig.door.home)));
    assert!(signed_by(&rig, &rig.device, &rig.door.home, T_REPLY_DENIED, &[&request], &encode_registration(&body, None), &sig));
    let again = halted(deny(&console, &mut officer(), &request, 1));
    assert!(again.contains("is already denied"), "{again}");
    let queue = rig.queue();
    assert_eq!((queue.thread(&request).unwrap().state, queue.thread(&second).unwrap().state), (State::Closed, State::Waiting));
    rig.sd.shutdown();
}

/// FENCE 12 (U6; REG-4.123 step 5) — THE THREE LISTS, READ FROM THE BOARD
/// ALONE: a request with no answer waits; an approved request whose node
/// account has no doc 1 is approved and not collected; and a refused
/// request, a denied one and an approved one whose node account has minted
/// its doc 1 — its first signed session's first act — are closed. The read
/// is a guest's and holds no state of its own: a second console with an
/// empty store reads the same lists.
#[test]
fn a_waiting_an_uncollected_and_a_closed_request_each_stand_in_their_own_list() {
    let rig = rig();
    let intake = rig.home(2);
    rig.policy(&policy_text(Admission::Open, "officer", &[&intake.account]));
    let door = rig.door.id.to_string();
    let console = rig.console(&rig.board, Hand::Officer);
    let waiting = rig.request(&intake, T_REQUEST_FRESH, &good_request(&rig, 1));
    let uncollected = rig.request(&intake, T_REQUEST_FRESH, &good_request(&rig, 2));
    let collected_request = rig.request(&intake, T_REQUEST_BOARD_CARRIES_ON, &{
        let a = applicant(3);
        request_body(&door, &fresh(3), &enrolment(&a.node, &a.device, "node"), None, &a.device)
    });
    let refused_request = rig.request(&intake, T_REQUEST_FRESH, &good_request(&rig, 1));
    let denied_request = rig.request(&intake, T_REQUEST_FRESH, &good_request(&rig, 5));

    approved(approve(&console, &mut officer(), &uncollected).unwrap_or_else(|h| panic!("{h}")));
    let collected = approved(approve(&console, &mut officer(), &collected_request).unwrap_or_else(|h| panic!("{h}")));
    assert_eq!(refused(approve(&console, &mut officer(), &refused_request).unwrap()).fault, Fault::FreshnessSpent);
    deny(&console, &mut officer(), &denied_request, 1).unwrap_or_else(|h| panic!("{h}"));
    // The org's first signed session mints its node account's doc 1.
    let org = applicant(3);
    let token = wire_session(&rig.board, collected.node_principal, &org.device);
    assert_eq!(wire_home(&rig.board, &token, &org.device, &collected.node_address).expect("the node account's doc 1"), doc_1_of(&collected.node_address));
    rig.board.session_close(&token).unwrap();

    let queue = read_queue(&board(rig.sd.port()), None, &Door::read(&rig.board, rig.dialer.clone()).unwrap()).expect("a guest's read");
    let links = |threads: Vec<&skep_client::ceremony::console::Thread>| threads.into_iter().map(|thread| thread.request.link.clone()).collect::<Vec<_>>();
    assert_eq!(links(queue.waiting().collect()), [waiting.as_str()]);
    assert_eq!(links(queue.approved_and_not_collected().collect()), [uncollected.as_str()]);
    assert_eq!(links(queue.closed().collect()), [collected_request.clone(), refused_request, denied_request]);
    let thread = queue.thread(&collected_request).unwrap();
    assert_eq!((thread.request.kind, thread.request.keys.len()), (RegistrationKind::BoardCarriesOn, 3), "the node pair and the device key");
    let fresh = queue.thread(&waiting).unwrap();
    assert_eq!(fresh.request.keys.iter().map(|key| (key.named.as_str(), key.label.as_str())).collect::<Vec<_>>(), [
        ("org root pair, sheet a", "org root sheet a"),
        ("org root pair, sheet b", "org root sheet b"),
        ("node pair, sheet a", "node sheet a"),
        ("node pair, sheet b", "node sheet b"),
        ("device key", "applicant laptop"),
    ]);
    assert_eq!(fresh.request.thread_key.len(), 5, "every key's fingerprint, the device key's once");
    assert!(fresh.request.time.is_some(), "the board dates the request");
    rig.sd.shutdown();
}

/// A REQUEST AS `skep register` COMPOSES IT PASSES THE CONSOLE's CHECK
/// (REG-4.67, REG-4.95 step 2): the applicant's own composition, framed for
/// the door as the console reads it off the board, written by the intake
/// home and approved; the same bytes written a second time are the same
/// payload replayed, and are refused `freshness-spent`.
#[test]
fn a_request_the_applicants_composition_made_is_approved_and_its_replay_refused() {
    let rig = rig();
    let intake = rig.home(2);
    rig.policy(&policy_text(Admission::Open, "officer", &[&intake.account]));
    let (store, sheets) = (FileStore::open(rig.dir.path().join("applicant")), rig.dir.path().join("sheets"));
    let options = RegistrationOptions {
        door: rig.door.id.to_string(),
        board_carries_on: false,
        key_file: None,
        label: None,
        anchor_labels: vec![],
        anchor_out: (0..4).map(|i| sheets.join(i.to_string())).collect(),
        paper: false,
        host_name: "testhost".into(),
        date: "2026-11-16".into(),
    };
    let mut applicant = Scripted::new(["laptop", "root a", "root b", "node a", "node b"].map(|label| Script::Label(label.into())).to_vec());
    let composed = registration_request(&mut applicant, &store, &options).unwrap_or_else(|h| panic!("{h}\n{}", applicant.transcript.join("\n")));
    let request = rig.request(&intake, T_REQUEST_FRESH, &composed.body);
    let replay = rig.request(&intake, T_REQUEST_FRESH, &composed.body);
    let queue = rig.queue();
    let thread = queue.thread(&request).expect("the request");
    assert_eq!(thread.request.verdict, Verdict::Passes, "the applicant's composition passes the console's check");
    assert_eq!(thread.request.thread_key, composed.thread_key, "the thread's key is the one the applicant was told");
    assert_eq!(thread.request.keys.iter().map(|key| key.fingerprint).collect::<Vec<_>>(), composed.keys.iter().map(|key| key.fingerprint).collect::<Vec<_>>());
    let console = rig.console(&rig.board, Hand::Officer);
    let done = approved(approve(&console, &mut officer(), &request).unwrap_or_else(|h| panic!("{h}")));
    assert_eq!(refused(approve(&console, &mut officer(), &replay).unwrap()).fault, Fault::FreshnessSpent);
    // The account opens under the device key the applicant's store holds.
    let device = key_file(&store, &composed.device.fingerprint).signer();
    let session = handshake(&rig.board, Scope::Content, &device, done.node_principal, Site::Session).expect("the org's first signed session");
    assert_eq!(session.account(), done.node_address);
    session.close().unwrap();
    rig.sd.shutdown();
}

/// The text of the version at `member`, as a guest reads it: its per-byte
/// items alone.
fn text_read(board: &Board, member: &str) -> Vec<Value> {
    let Answer::Document(v) = board.op(None, &frames::span_set(member)).unwrap() else { panic!("closed") };
    let extent: u64 = v["set"][0]["width"].as_str().and_then(|w| w.rsplit('.').next()).and_then(|n| n.parse().ok()).unwrap_or(0);
    let Answer::Document(v) = board.op(None, &frames::retrieve_v(member, 1, extent)).unwrap() else { panic!("closed") };
    v["items"].as_array().cloned().unwrap_or_default()
}

/// FENCE 17 (call 1 item 3; WELL-KNOWN CALL 5) — THE POLICY's FOUR ACTS. A
/// file past 16 KiB and a file the shared parser refuses are refused before
/// any write: document 5 is not created. The first policy creates document
/// 5 and publishes `.0.5.1`; the next, on the same session, publishes
/// `.0.5.2` and creates nothing; the same file again publishes nothing and
/// says so. Each version's content, read by a guest, is the file's bytes as
/// text — per-byte words, never one composite value — and holds nothing of
/// the version before it.
#[test]
fn set_policy_creates_document_5_once_and_publishes_each_file_as_the_next_version_as_text() {
    let rig = rig();
    let document = format!("{}.0.5", rig.door.account);
    let session = handshake(&rig.board, Scope::Content, &rig.device, 1, Site::Console).expect("the registrar's session");
    let absent = |board: &Board| matches!(board.op(None, &frames::doc_metadata(&document)).unwrap(), Answer::Document(v) if v["code"] == "doc_not_registered");

    // Refused before any write.
    let before = rig.head();
    let good = policy_text(Admission::Open, "officer", &["1.0.1.2"]);
    let mut long = skep_registry::parse_policy(good.as_bytes()).unwrap();
    long.contact = "x".repeat(MAX_POLICY_BYTES);
    for (bad, why) in [
        (encode_policy(&long), "past the cap of 16384"),
        (format!("{good}\n"), "the file is no admission policy: not_canonical"),
        (good.replace("\"open\"", "\"closed\""), "the file is no admission policy: unknown_value:admission"),
        (String::new(), "the file is no admission policy: not_json"),
    ] {
        let refusal = halted(set_policy(&rig.board, &session, &rig.device, bad.as_bytes()));
        assert!(refusal.contains(why) && refusal.contains("nothing was written"), "{refusal}");
        assert_eq!(halted(check_policy(bad.as_bytes())), refusal, "the file is judged by the same check");
    }
    assert!(rig.head() == before && absent(&rig.board), "document 5 is not created by a refused file");

    // The first policy and the next, on ONE session.
    let first = set_policy(&rig.board, &session, &rig.device, good.as_bytes()).unwrap_or_else(|h| panic!("{h}"));
    assert_eq!((first.document.as_str(), first.created, first.version.clone(), first.published), (document.as_str(), true, format!("{document}.1"), true));
    let next_text = policy_text(Admission::Open, "auto", &["1.0.1.2", "1.0.1.3"]);
    let next = set_policy(&rig.board, &session, &rig.device, next_text.as_bytes()).unwrap_or_else(|h| panic!("{h}"));
    assert_eq!((next.created, next.version.clone(), next.published), (false, format!("{document}.2"), true), "the next version, nothing created again");
    let before = rig.head();
    let same = set_policy(&rig.board, &session, &rig.device, next_text.as_bytes()).unwrap_or_else(|h| panic!("{h}"));
    assert_eq!((same.created, same.version.clone(), same.published, same.at), (false, format!("{document}.2"), false, None), "the standing version already holds the file");
    assert_eq!(rig.head(), before, "and nothing was published");
    session.close().unwrap();

    // What a guest reads: text, the file's bytes, and nothing of the old.
    for (member, text) in [(&first.version, &good), (&next.version, &next_text)] {
        let items = text_read(&rig.board, member);
        assert!(!items.is_empty() && items.iter().all(|item| item.get("content").is_some() || item.get("hex").is_some()), "{member}: per-byte text, never a composite value: {items:?}");
        let read: String = items.iter().filter_map(|item| item["content"].as_str()).collect();
        assert_eq!(&read, text, "{member}: the file's bytes");
    }
    let chain = read_policy(&rig.board, None, &rig.door.account).expect("the chain");
    assert_eq!(chain.versions.iter().map(|v| (v.address.clone(), v.text.clone().map(String::from_utf8))).collect::<Vec<_>>(), [(first.version, Some(Ok(good))), (next.version.clone(), Some(Ok(next_text)))]);
    assert_eq!(chain.standing().unwrap().version.address, next.version);
    assert!(chain.versions[0].at < chain.versions[1].at);
    assert!(matches!(chain.standing_at(chain.versions[0].at - 1), Err(NoPolicy::NotYet { .. })), "no version stood before the first was published");
    assert_eq!(chain.standing_at(chain.versions[1].at - 1).unwrap().version.address, chain.versions[0].address, "the version standing at a position is the latest at or below it");
    rig.sd.shutdown();
}

/// FENCE 18 (call 1 item 2; WELL-KNOWN CALL 4) — A DOOR WITH NO POLICY IS
/// SHUT, THREE WAYS ALIKE: document 5 absent; created and holding no
/// version; and a standing version that does not parse — after a version
/// that did, and whether its words are text the parser refuses or one
/// composite value that is no text at all. In each the queue is empty
/// though a request stands on the home the earlier version named, `approve`
/// and `deny` and a pass of the unattended hand refuse or do nothing before
/// any write, and each says the door has no policy. And a request written
/// while no policy stood is not admitted once one does.
#[test]
fn a_door_with_no_policy_admits_no_request_and_answers_none() {
    let rig = rig();
    let intake = rig.home(2);
    let document = format!("{}.0.5", rig.door.account);
    let unattended = Console { hand: Hand::Unattended, ..rig.console(&rig.board, Hand::Officer) };
    let shut = |request: &str, why: &str| {
        let queue = rig.queue();
        assert!(queue.threads.is_empty() && queue.passed_over.is_empty(), "{why}: no home is admitted, nothing is parsed");
        let said = queue.policy.standing().expect_err("no policy").to_string();
        assert!(said.contains(why), "{said}");
        let before = rig.head();
        let console = rig.console(&rig.board, Hand::Officer);
        for refusal in [halted(approve(&console, &mut officer(), request)), halted(deny(&console, &mut officer(), request, 1)), halted(approve(&unattended, &mut Scripted::new(vec![]), request))] {
            assert!(refusal.contains(why) && refusal.contains("is shut"), "{why}: {refusal}");
        }
        let round = auto_round(&unattended, &mut Scripted::new(vec![]), &|| false).expect("a pass");
        assert!(round.acts.is_empty() && round.withheld.as_deref().is_some_and(|said| said.contains(why)), "{why}: {round:?}");
        assert_eq!(rig.head(), before, "{why}: nothing was written");
    };

    // Absent.
    let early = rig.request(&intake, T_REQUEST_FRESH, &good_request(&rig, 1));
    shut(&early, &format!("its policy document {document} has not been created"));

    // Created, holding no version.
    let session = handshake(&rig.board, Scope::Content, &rig.device, 1, Site::Console).unwrap();
    skep_client::ceremony::create_well_known_document(&rig.board, &session, &rig.door.account, 5, &rig.device, "empty-5").expect("document 5");
    session.close().unwrap();
    shut(&early, &format!("its policy document {document} is created and holds no version"));

    // A policy stands: the request written before it is not admitted, and
    // one written after is.
    rig.policy(&policy_text(Admission::Open, "officer", &[&intake.account]));
    let admitted = rig.request(&intake, T_REQUEST_FRESH, &good_request(&rig, 2));
    assert_eq!(rig.queue().threads.iter().map(|t| t.request.link.clone()).collect::<Vec<_>>(), [admitted.as_str()], "no policy stood at the earlier request's position");

    // A standing version that does not parse: the door is shut, though the
    // version before it parsed.
    let token = rig.registrar_token();
    let unparsable = wire_policy_version(&rig.board, &token, &rig.device, &rig.door.account, "{\"type\":\"admission-policy\"}\n", false).expect("an unparsable version");
    assert_eq!(unparsable, format!("{document}.2"));
    shut(&admitted, &format!("the version standing, {unparsable}, does not read as an admission policy (missing_member:admission)"));

    // A version whose words are one composite value holds no text.
    let atom = wire_policy_version(&rig.board, &token, &rig.device, &rig.door.account, &policy_text(Admission::Open, "officer", &[&intake.account]), true).expect("a version of one atom");
    rig.board.session_close(&token).unwrap();
    shut(&admitted, &format!("the version standing, {atom}, does not read as an admission policy (it holds a value that is no text)"));

    // The door re-opens at the next version that parses; the requests
    // written while it was shut stay unadmitted.
    let while_shut = rig.request(&intake, T_REQUEST_FRESH, &good_request(&rig, 3));
    rig.policy(&policy_text(Admission::Open, "officer", &[&intake.account]));
    let queue = rig.queue();
    assert_eq!(queue.threads.iter().map(|t| t.request.link.clone()).collect::<Vec<_>>(), [admitted]);
    assert!(queue.thread(&while_shut).is_none() && queue.thread(&early).is_none());
    rig.sd.shutdown();
}
