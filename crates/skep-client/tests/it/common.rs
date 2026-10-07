//! The fixture: a daemon in-process on an ephemeral port (skepd's own
//! spawn pattern — the port reserved through the slow open, the rebind race
//! retried), a `Board` over the one dialer, a recording dialer for the tests
//! that pin WHAT WAS DIALED AND IN WHAT ORDER, a redirecting one for a board
//! dialed at a served origin, and the scripts the claim walk's person
//! answers.

#![allow(dead_code)]

use std::io::{ErrorKind, Read};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::Value;
use skep_client::board::Board;
use skep_client::ceremony::claim::{self, ClaimOutcome, Claimed, NotebookOptions};
use skep_client::dial::{DialError, Dialer, Headers, PlainHttp, Request, RequestHead, Response, StreamedResponse};
use skep_client::person::scripted::{Script, Scripted};
use skep_client::sheet::Label;
use skep_client::store::{FileStore, KeyStore};
use skep_client::Origin;
use skep_identity::Fingerprint;
use skepd::{serve, AuthOptions, Daemon, Skepd, DEFAULT_WORKERS};

/// Spawn a daemon over `dir` with ONE configured origin — its own loopback
/// port — and `local_trust` as given: `false` flips the board into ENFORCING
/// at the claim, `true` into CLAIMED-PERMISSIVE.
pub fn spawn(dir: &Path, local_trust: bool) -> Skepd {
    const ATTEMPTS: usize = 12;
    for _ in 0..ATTEMPTS {
        let reserved = TcpListener::bind(("127.0.0.1", 0)).expect("reserve an ephemeral port");
        let port = reserved.local_addr().expect("reserved local addr").port();
        let origin = skepd::Origin::parse(&format!("http://127.0.0.1:{port}")).expect("a canonical loopback origin");
        let mut opts = AuthOptions::default();
        opts.local_trust = local_trust;
        opts.configured = vec![origin];
        let daemon = match Daemon::open_with(dir, opts) {
            Ok(d) => d,
            Err(e) => {
                let mut source: Option<&(dyn std::error::Error + 'static)> = Some(&e);
                let mut lock_race = false;
                while let Some(err) = source {
                    if let Some(io) = err.downcast_ref::<std::io::Error>() {
                        lock_race = io.kind() == ErrorKind::WouldBlock;
                        break;
                    }
                    source = err.source();
                }
                if lock_race {
                    drop(reserved);
                    std::thread::sleep(Duration::from_millis(25));
                    continue;
                }
                panic!("daemon open at {}: {e}", dir.display());
            }
        };
        drop(reserved);
        match serve(daemon, port, DEFAULT_WORKERS) {
            Ok(sd) => {
                let deadline = Instant::now() + Duration::from_secs(60);
                while !sd.daemon().index_is_ready() {
                    assert!(Instant::now() < deadline, "the cell index's walk did not complete within 60 s");
                    std::thread::sleep(Duration::from_millis(5));
                }
                return sd;
            }
            Err(e) if e.kind() == ErrorKind::AddrInUse => continue,
            Err(e) => panic!("bind the reserved port: {e}"),
        }
    }
    panic!("spawn: lost the rebind race {ATTEMPTS} times running")
}

/// The daemon's own origin.
pub fn origin_of(port: u16) -> Origin {
    Origin::parse(&format!("http://127.0.0.1:{port}")).expect("canonical")
}

/// A board over the plain dialer.
pub fn board(port: u16) -> Board {
    Board::new(origin_of(port), PlainHttp::new())
}

/// THE RECORDING DIALER: every exchange logged as `METHOD path[ op]`, the
/// frame's `op` member appended for a `/op`, so a test can pin the ORDER of
/// what was dialed — the pre-check's reads AHEAD of the `/challenge`.
pub struct Recording {
    inner: PlainHttp,
    pub log: Arc<Mutex<Vec<String>>>,
}

impl Dialer for Recording {
    fn exchange(&self, origin: &Origin, req: &Request) -> Result<Response, DialError> {
        let mut line = format!("{} {}", req.method.as_str(), req.path);
        if req.path == "/op" || req.path == "/op-at" {
            if let Ok(v) = serde_json::from_slice::<Value>(&req.body) {
                let op = v["op"].as_str().or_else(|| v["frame"]["op"].as_str()).unwrap_or("?");
                line.push(' ');
                line.push_str(op);
            }
        }
        self.log.lock().expect("log").push(line);
        self.inner.exchange(origin, req)
    }

    fn stream(&self, origin: &Origin, head: &RequestHead, body: &mut dyn Read, on_interim: &mut dyn FnMut(&Headers)) -> Result<StreamedResponse, DialError> {
        self.log.lock().expect("log").push(format!("{} {} (stream)", head.method.as_str(), head.path));
        self.inner.stream(origin, head, body, on_interim)
    }
}

/// A board over the recording dialer, and its log.
pub fn recording_board(origin: Origin) -> (Board, Arc<Mutex<Vec<String>>>) {
    let log = Arc::new(Mutex::new(Vec::new()));
    let board = Board::new(origin, Recording { inner: PlainHttp::new(), log: log.clone() });
    (board, log)
}

/// THE REDIRECT: every request, in both forms, carried to the daemon at `to`
/// through the plain arm, whatever origin the board dials — so a board
/// dialed at a SERVED origin reads the in-process daemon, and a walk meets
/// the served cell of the A4 table.
pub struct Redirect {
    to: Origin,
    inner: PlainHttp,
}

impl Redirect {
    pub fn to(to: Origin) -> Redirect {
        Redirect { to, inner: PlainHttp::new() }
    }
}

impl Dialer for Redirect {
    fn exchange(&self, _origin: &Origin, req: &Request) -> Result<Response, DialError> {
        self.inner.exchange(&self.to, req)
    }

    fn stream(&self, _origin: &Origin, head: &RequestHead, body: &mut dyn Read, on_interim: &mut dyn FnMut(&Headers)) -> Result<StreamedResponse, DialError> {
        self.inner.stream(&self.to, head, body, on_interim)
    }
}

/// One DEVICE key generated into `store` under `label`.
pub fn keygen(store: &FileStore, label: &str) -> Fingerprint {
    store.generate(Some(Label::new(label).expect("a label in the domain"))).expect("generate").0
}

/// The notebook walk's options: the two anchor destinations under
/// `anchors`, no paper, the display name given so no question is asked.
pub fn opts(anchors: &Path) -> NotebookOptions {
    NotebookOptions {
        principal: None,
        display_name: Some("a display name".into()),
        anchor_out: vec![anchors.join("a"), anchors.join("b")],
        paper: false,
        host_name: "testhost".into(),
        date: "2026-10-04".into(),
    }
}

/// The script a plain claim's person needs: the two anchor boxes, answered
/// with their per-run defaults.
pub fn claim_script() -> Vec<Script> {
    vec![Script::LabelDefault, Script::LabelDefault]
}

/// The notebook walk run to its OURS end.
pub fn claim(board: &Board, store: &FileStore, anchors: &Path) -> (Claimed, Scripted) {
    let mut person = Scripted::new(claim_script());
    let outcome = claim::notebook(board, store, &mut person, &opts(anchors)).unwrap_or_else(|h| panic!("the claim halted: {h}\n{}", person.transcript.join("\n")));
    match outcome {
        ClaimOutcome::Ours(done) => (done, person),
        ClaimOutcome::Stranger { claimant } => panic!("a stranger's board: {claimant}"),
    }
}

/// The key files written under `dir`, by name.
pub fn files_in(dir: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(dir).map(|rd| rd.filter_map(Result::ok).map(|e| e.path()).collect()).unwrap_or_default();
    v.sort();
    v
}

// ── THE WIRE TRANSCRIPT, re-driven: another hand's acts ──────────────────
//
// A "thief" or "another hand" in a test is the daemon's own helper's shape
// (`open_signed_session_as`, `hire`, the retire helpers of skepd's suite) run
// from the test over the board's raw frames — never a client ceremony.

use skep_client::board::{acked_addr, frames, Answer, KeySetAnswer, Opened, Scope, SessionBody, Token, T_ENROLL, T_RETIRE};
use skep_client::ceremony::deposit::next_content_ordinal;
use skep_client::person::{Abandoned, Confirmation, Consent, Destination, HandedPath, Import, Imported, KeptOrPlaced, LabelBox, Person, Public, Question, Retype, Retyped, Secret, Sheet, Statement};
use skep_client::sheet::KeyFile;
use skep_client::sign::{session_payload, sig_hex, signer_from_seed, RecordFrame, Signer};
use skep_identity::{canonical_record, Enrollment, RecordEntry};
use skep_signature::HybridSigner;

/// A FULL signed session under `signer` for `principal`, as skepd's
/// `open_signed_session_as` opens one: the challenge, the v1 bytes signed,
/// the body posted.
pub fn wire_session(board: &Board, principal: u64, signer: &HybridSigner) -> Token {
    let challenge = board.challenge(principal).expect("challenge");
    let payload = session_payload(board.signed(), &challenge.nonce, principal, Scope::Full);
    let sig = sig_hex(&HybridSigner::sign(signer, &payload));
    match board.session_open(SessionBody::Signed { principal, nonce: &challenge.nonce, sig_hex: &sig, scope: Scope::Full }).expect("session") {
        Opened::Token(t) => t,
        other => panic!("the wire session answered {other:?}"),
    }
}

/// A credential record SIGNED at the record grade by `hand` (skepd's
/// `signed_atom`), inserted DECLARED at `home`'s next free content ordinal
/// and linked to `subject` under `ty` — the daemon's `hire` shape. Answers
/// the link's address, or the refusal's token.
fn wire_deposit<T: RecordEntry>(board: &Board, token: &Token, hand: &HybridSigner, home: &str, subject: &str, ty: &str, entries: &[T]) -> Result<String, String> {
    let term = board.board_term().expect("term").expect("H.1");
    let home_account = board.effective_owner(home).expect("owner").expect("owned").prefix;
    let sigless = canonical_record(entries, None);
    let alg = HybridSigner::public_key(hand).alg();
    let frame = RecordFrame { alg, board: term, home_account: &home_account, home, ty, to: &[subject], sigless: sigless.as_bytes() }.compose().expect("frame");
    let text = canonical_record(entries, Some(&sig_hex(&HybridSigner::sign(hand, &frame))));
    let ordinal = next_content_ordinal(board, Some(token), home).expect("ordinal");
    let Answer::Document(v) = board.op(Some(token), &frames::insert_atom(home, ordinal, &text, ty, None)).expect("insert") else { return Err("closed".into()) };
    let Some(atom) = acked_addr(&v).map(str::to_string) else { return Err(v.to_string()) };
    let Answer::Document(v) = board.op(Some(token), &frames::make_link(home, &[&atom], &[subject], ty, None)).expect("link") else { return Err("closed".into()) };
    acked_addr(&v).map(str::to_string).ok_or_else(|| v.to_string())
}

/// Another hand ENROLLS `entries` at `subject`, homed in `home`.
pub fn wire_enroll(board: &Board, token: &Token, hand: &HybridSigner, home: &str, subject: &str, entries: &[Enrollment]) -> Result<String, String> {
    wire_deposit(board, token, hand, home, subject, T_ENROLL, entries)
}

/// Another hand RETIRES `fps` at `subject`, homed in `home`.
pub fn wire_retire(board: &Board, token: &Token, hand: &HybridSigner, home: &str, subject: &str, fps: &[Fingerprint]) -> Result<String, String> {
    wire_deposit(board, token, hand, home, subject, T_RETIRE, fps)
}

/// A `delegate` from `token`'s session.
pub fn wire_delegate(board: &Board, token: &Token, new_prefix: &str, new_id: u64) -> Result<String, String> {
    let Answer::Document(v) = board.op(Some(token), &frames::delegate(new_prefix, new_id, None)).expect("delegate") else { return Err("closed".into()) };
    acked_addr(&v).map(str::to_string).ok_or_else(|| v.to_string())
}

/// The set at `1.0.1` filled to the enrolled-set cap (16) from `token`'s
/// session under `hand`: fresh device keys, one record each.
pub fn fill_to_the_cap(board: &Board, token: &Token, hand: &HybridSigner) {
    let KeySetAnswer::Set(set) = board.key_set("1.0.1").expect("key_set") else { panic!("1.0.1 is no account") };
    for k in 20..20 + (16 - set.enrolled.len() as u8) {
        let filler = Enrollment::new(HybridSigner::public_key(&signer_from_seed(&[k; 32])).clone(), false, Some(format!("filler {k}"))).expect("a label");
        wire_enroll(board, token, hand, "1.0.1.0.1", "1.0.1", &[filler]).expect("a filler");
    }
}

/// Whether `token` is dead: a write under it answers `unauthenticated` with
/// the death signal.
pub fn token_dead(board: &Board, token: &Token) -> bool {
    matches!(board.op(Some(token), &frames::span_set("1.0.1.0.1")), Ok(Answer::Closed))
}

/// A device-key entry for a store key.
pub fn entry_of(file: &KeyFile, label: &str) -> Enrollment {
    Enrollment::new(file.public.clone(), false, Some(label.into())).expect("a label in the domain")
}

/// The store's one key file.
pub fn key_file(store: &FileStore, fp: &Fingerprint) -> KeyFile {
    store.load(&store.key_path(fp)).expect("the key file")
}

/// The anchor file under `anchors/<which>`, parsed.
pub fn anchor_file(anchors: &Path, which: &str) -> (PathBuf, KeyFile) {
    let files = files_in(&anchors.join(which));
    assert_eq!(files.len(), 1, "one anchor file under {which}");
    let file = KeyFile::parse(&std::fs::read(&files[0]).unwrap()).expect("an anchor file");
    (files[0].clone(), file)
}

/// THE HOOKED PERSON: the scripted person with a hand that acts at a moment
/// — `on_confirm` fires with the confirmation's index before it is answered,
/// `on_say` with every statement's rule and text — so a test can plant a
/// key between a walk's rounds, or pull a file from under its read-back.
pub struct Hooked {
    pub inner: Scripted,
    pub confirms: usize,
    pub on_confirm: Box<dyn FnMut(usize, &str)>,
    pub on_say: Box<dyn FnMut(&str, &str)>,
}

impl Hooked {
    pub fn new(script: Vec<Script>) -> Hooked {
        Hooked { inner: Scripted::new(script), confirms: 0, on_confirm: Box::new(|_, _| {}), on_say: Box::new(|_, _| {}) }
    }
}

impl Person for Hooked {
    fn say(&mut self, m: Public<Statement>) {
        (self.on_say)(m.0.rule, &m.0.text);
        self.inner.say(m);
    }
    fn label(&mut self, m: Public<LabelBox>) -> Result<String, Abandoned> {
        self.inner.label(m)
    }
    fn ask(&mut self, m: Public<Question>) -> Result<String, Abandoned> {
        self.inner.ask(m)
    }
    fn yes_no(&mut self, m: Public<Question>) -> Result<bool, Abandoned> {
        self.inner.yes_no(m)
    }
    fn sheet(&mut self, m: Secret<Sheet>) -> Result<(), Abandoned> {
        self.inner.sheet(m)
    }
    fn dismiss(&mut self) {
        self.inner.dismiss()
    }
    fn retype(&mut self, m: Secret<Retype>) -> Result<Retyped, Abandoned> {
        self.inner.retype(m)
    }
    fn destination(&mut self, m: Secret<Destination>) -> Result<PathBuf, Abandoned> {
        self.inner.destination(m)
    }
    fn confirm_typed(&mut self, m: Consent<Confirmation>) -> Result<String, Abandoned> {
        let i = self.confirms;
        self.confirms += 1;
        (self.on_confirm)(i, &m.0.text);
        self.inner.confirm_typed(m)
    }
    fn import(&mut self, m: Secret<Import>) -> Result<Imported, Abandoned> {
        self.inner.import(m)
    }
    fn kept_or_placed(&mut self, m: Secret<HandedPath>) -> Result<KeptOrPlaced, Abandoned> {
        self.inner.kept_or_placed(m)
    }
}

/// `Signer::fingerprint` on a hybrid signer, disambiguated.
pub fn fp_of(signer: &HybridSigner) -> Fingerprint {
    Signer::fingerprint(signer)
}
