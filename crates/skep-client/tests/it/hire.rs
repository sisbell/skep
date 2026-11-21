//! `hire` (AUTH-5.58, the owner's side; AUTH RES-211): on an ENFORCING board
//! an owner hires an agent beneath the space for their agents — the standing
//! statements ahead of the `delegate`, the custody pair or its decline, the
//! paste's tests and the comparison, the owner's own three-entry (or
//! one-entry) genesis in the agent space's doc 1, the agent's doc 1 minted
//! under the custody anchor, and only then its principal — and every state
//! resumes by reading. Beside the walk: the agent's own key opens its
//! sessions and the owner's keys open none; a rotation at the agent reserves
//! no agent space beneath it; and the stop, `recover`'s agent arm with a
//! custody sheet, at an account a hire made.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use serde_json::Value;
use skep_client::address::{doc_1_of, document_of, first_child, mailbox_of};
use skep_client::board::{Board, KeySetAnswer, Scope};
use skep_client::ceremony::claim::{hosted, HostedOutcome};
use skep_client::ceremony::first_session::document_present;
use skep_client::ceremony::handshake::{handshake, Site};
use skep_client::ceremony::hire::{hire, HireOptions, Hired};
use skep_client::ceremony::recover::{recover, RecoverOptions};
use skep_client::ceremony::rotate::{rotate, RotateOptions};
use skep_client::derive::records::{credential_records, Hand};
use skep_client::derive::{hirer_of, principal_of};
use skep_client::dial::{DialError, Dialer, Headers, PlainHttp, Request, RequestHead, Response, StreamedResponse};
use skep_client::person::scripted::{Script, Scripted};
use skep_client::person::KeptOrPlaced;
use skep_client::sheet::{KeyFile, Label, Seed};
use skep_client::store::{Binding, FileStore, KeyStore};
use skep_client::{Halt, Origin};
use skep_identity::{encode_enroll, Enrollment, Fingerprint};
use skep_signature::HybridSigner;

use crate::common::{anchor_file, board, claim, entry_of, files_in, fp_of, key_file, keygen, keyed_sub_account, origin_of, recording_board, spawn, wire_delegate, wire_enroll, wire_home, wire_retire, wire_session, Hooked};

/// The owner's account on every rig, its agent space and its first agent.
const OWNER: &str = "1.0.1";
const SPACE: &str = "1.0.1.1";
const FIRST: &str = "1.0.1.1.1";
const SECOND: &str = "1.0.1.1.2";

/// An ENFORCING board its owner claimed: the owner's store, their device
/// key and their own anchor pair — and, by the claim's tail, the space for
/// their agents reserved at `1.0.1.1`.
struct Rig {
    dir: tempfile::TempDir,
    sd: skepd::Skepd,
    owner: FileStore,
    owner_fp: Fingerprint,
    anchors: PathBuf,
}

fn rig() -> Rig {
    let dir = tempfile::tempdir().unwrap();
    let sd = spawn(&dir.path().join("board"), false);
    let owner = FileStore::open(dir.path().join("owner"));
    let owner_fp = keygen(&owner, "owner laptop");
    let anchors = dir.path().join("anchors");
    claim(&board(sd.port()), &owner, &anchors);
    Rig { dir, sd, owner, owner_fp, anchors }
}

impl Rig {
    fn board(&self) -> Board {
        board(self.sd.port())
    }

    /// The directory the custody pair of hire `n` is exported under.
    fn custody(&self, n: usize) -> PathBuf {
        self.dir.path().join(format!("custody-{n}"))
    }

    /// An agent's host: a store of its own, one working key under `label`,
    /// and the record `skep keygen --payload` prints for it.
    fn agent(&self, name: &str, label: &str) -> Agent {
        let store = FileStore::open(self.dir.path().join(name));
        let fp = keygen(&store, label);
        let payload = encode_enroll(&[entry_of(&key_file(&store, &fp), label)]);
        Agent { store, fp, payload }
    }

    fn head(&self) -> u64 {
        self.board().health().unwrap().log_position()
    }
}

struct Agent {
    store: FileStore,
    fp: Fingerprint,
    payload: String,
}

impl Agent {
    fn signer(&self) -> HybridSigner {
        key_file(&self.store, &self.fp).signer()
    }
}

fn options(payload: &str, custody: &Path) -> HireOptions {
    HireOptions {
        principal: 1,
        payload: format!("{payload}\n").into_bytes(),
        anchorless: false,
        replaces: None,
        anchor_out: vec![custody.join("a"), custody.join("b")],
        paper: false,
        host_name: "testhost".into(),
        date: "2026-11-15".into(),
    }
}

/// The anchored arm's script: the pair's two label boxes at their per-run
/// defaults, then the comparison's first group.
fn anchored() -> Vec<Script> {
    vec![Script::LabelDefault, Script::LabelDefault, Script::Confirm(true)]
}

/// One anchored hire run to its end over `board`.
fn hired(board: &Board, rig: &Rig, agent: &Agent, n: usize) -> (Hired, Scripted) {
    let mut person = Scripted::new(anchored());
    let done = hire(board, &rig.owner, &mut person, &options(&agent.payload, &rig.custody(n))).unwrap_or_else(|h| panic!("the hire halted: {h}\n{}", person.transcript.join("\n")));
    (done, person)
}

fn set_of(board: &Board, account: &str) -> skep_client::KeySet {
    match board.key_set(account).unwrap() {
        KeySetAnswer::Set(set) => set,
        KeySetAnswer::NotAnAccount => skep_client::KeySet::default(),
    }
}

/// Every statement a walk said: its rule, its text, and the count of
/// requests dialed when it was said.
type Said = Arc<Mutex<Vec<(String, String, usize)>>>;

/// Every `/op` a dialer carried: the op, and the session token it rode.
type Ops = Arc<Mutex<Vec<(String, Option<String>)>>>;

/// A person whose every statement is kept with the count of requests
/// dialed when it was said, so a test places a statement against a write.
fn placing(script: Vec<Script>, log: &Arc<Mutex<Vec<String>>>) -> (Hooked, Said) {
    let said: Said = Arc::new(Mutex::new(Vec::new()));
    let (keep, dialed) = (said.clone(), log.clone());
    let mut person = Hooked::new(script);
    person.on_say = Box::new(move |rule, text| keep.lock().unwrap().push((rule.to_string(), text.to_string(), dialed.lock().unwrap().len())));
    (person, said)
}

/// A dialer whose `n`-th `/challenge` fails as a refused connection: the
/// run stops there, as a killed one does, everything before it written.
struct DiesAt {
    inner: PlainHttp,
    challenges: AtomicUsize,
    at: usize,
}

impl Dialer for DiesAt {
    fn exchange(&self, origin: &Origin, req: &Request) -> Result<Response, DialError> {
        if req.path.starts_with("/challenge") && self.challenges.fetch_add(1, Ordering::SeqCst) + 1 == self.at {
            return Err(DialError::Connect("the run was killed here".into()));
        }
        self.inner.exchange(origin, req)
    }

    fn stream(&self, origin: &Origin, head: &RequestHead, body: &mut dyn Read, on_interim: &mut dyn FnMut(&Headers)) -> Result<StreamedResponse, DialError> {
        self.inner.stream(origin, head, body, on_interim)
    }
}

/// A dialer that keeps, for every `/op` it carries, the op and the session
/// token it rode under.
struct Tokens {
    inner: PlainHttp,
    seen: Ops,
}

impl Dialer for Tokens {
    fn exchange(&self, origin: &Origin, req: &Request) -> Result<Response, DialError> {
        if req.path == "/op" {
            let op = serde_json::from_slice::<Value>(&req.body).ok().and_then(|v| v["op"].as_str().map(str::to_string)).unwrap_or_default();
            let token = req.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case("Skepd-Session")).map(|(_, v)| v.clone());
            self.seen.lock().unwrap().push((op, token));
        }
        self.inner.exchange(origin, req)
    }

    fn stream(&self, origin: &Origin, head: &RequestHead, body: &mut dyn Read, on_interim: &mut dyn FnMut(&Headers)) -> Result<StreamedResponse, DialError> {
        self.inner.stream(origin, head, body, on_interim)
    }
}

/// FENCE 1 (AUTH-5.58; AUTH RES-211; AUTH-5.62; AUTH-5.91): an anchored hire
/// at an owner's account on an ENFORCING board. The agent's account stands
/// at `X.1.n`; its set is exactly three entries, the agent's key and the
/// pair; the pair's two sheets stand at the owner's venue under the labels
/// their boxes fixed, each carrying the AGENT's address and principal; and a
/// read of the agent space's doc 1 names the agent — the genesis link's `to`
/// the agent's address, the label carried — with nothing written for it.
#[test]
fn an_anchored_hire_seats_the_agent_beneath_the_agent_space_under_three_entries() {
    let rig = rig();
    let board = rig.board();
    let agent = rig.agent("scribe-host", "scribe");
    let (done, person) = hired(&board, &rig, &agent, 1);
    let t = person.transcript.join("\n");
    assert!(!board.health().unwrap().local_trust(), "an ENFORCING board");
    assert_eq!((done.facts.account.as_str(), done.agent_space.as_str(), done.key), (FIRST, SPACE, agent.fp));
    assert_eq!(principal_of(&board, FIRST).unwrap(), Some(done.facts.principal), "the agent's seat, under the hire's own id");
    assert_eq!(hirer_of(&board, FIRST).unwrap().as_deref(), Some(OWNER), "told a hire's by its address");
    assert!(!done.anchorless && !done.already && done.minted_home && done.label.as_deref() == Some("scribe"), "{done:?}");
    // Exactly three entries: the agent's key and the pair.
    let set = set_of(&board, FIRST);
    assert_eq!((set.enrolled.len(), set.retired.len()), (3, 0), "{set:?}");
    assert!(set.enrolled(&agent.fp).is_some_and(|e| !e.anchor), "the working key, device-flagged");
    assert_eq!(set.enrolled.iter().filter(|e| e.anchor).count(), 2, "the custody pair");
    assert!(set.enrolled(&rig.owner_fp).is_none(), "the owner's own key is in no agent's set (AUTH-5.62)");
    // The two sheets at the owner's venue, with their labels and the
    // agent's facts (AUTH-5.38).
    assert_eq!(done.anchors.len(), 2);
    for (which, artifact) in ["a", "b"].iter().zip(&done.anchors) {
        let (path, sheet) = anchor_file(&rig.custody(1), which);
        assert_eq!(artifact.file.as_deref(), Some(path.as_path()));
        assert!(sheet.anchor && set.enrolled(&sheet.fingerprint).is_some_and(|e| e.anchor), "sheet {which} is an enrolled anchor of the agent");
        assert_eq!(sheet.label.as_deref(), Some(artifact.label.as_str()));
        assert!(artifact.label.as_str().starts_with("testhost-2026-11-15-") && artifact.label.as_str().ends_with(which), "the box's per-run default: {}", artifact.label);
        assert_eq!((sheet.account.as_deref(), sheet.principal, sheet.origin.as_ref()), (Some(FIRST), Some(done.facts.principal), Some(board.dialed())));
        assert!(!rig.owner.contains_path(&path), "never under the owner's key store");
    }
    assert_eq!(files_in(&rig.custody(1)).len(), 2, "one directory per sheet");
    assert!(person.said("PUBLIC label [name anchor a]") && person.said("sits beside every OTHER agent's sheets forever"), "the pair's boxes, in the hire's copy:\n{t}");
    assert!(person.said("[AUTH-5.44 (hire)]: keep both anchor files — they are the only way to open a session as this agent (1.0.1.1.1)"), "the moment's own line:\n{t}");
    // AUTH-5.91's read: the agent space's doc 1 names the agent.
    let records = credential_records(&board, FIRST, &[]).unwrap();
    let genesis = records.genesis().expect("the hire's record");
    assert_eq!((genesis.home.as_str(), genesis.home_account.as_str(), genesis.subject.as_str()), (doc_1_of(SPACE).as_str(), SPACE, FIRST));
    assert_eq!(document_of(&genesis.link).as_deref(), Some(doc_1_of(SPACE).as_str()), "the link is homed in the agent space's doc 1");
    assert_eq!(records.label_of(&agent.fp).as_deref(), Some("scribe"), "the label carried");
    assert_eq!(records.records.len(), 1, "one record names the agent, and nothing is written for the roster");
    assert!(person.said("It is the row a roster reads — nothing more is written for it (AUTH-5.91)"), "{t}");
}

/// Checks that a hired agent's account holds its mailbox.
///
/// The hire mints the agent's doc 1 from the custody anchor's session, and
/// the board creates the agent's mailbox in that home's own commit (the
/// mailbox design §3), with no step of the walk's: a guest is answered
/// `withheld` at the agent's `.0.2`.
#[test]
fn hire_agent_account_holds_its_mailbox() {
    let rig = rig();
    let board = rig.board();
    let agent = rig.agent("scribe-host", "scribe");
    let (done, _) = hired(&board, &rig, &agent, 1);
    assert!(done.minted_home, "the premise: the hire minted the agent's home");
    let v = board.guest(&skep_client::board::frames::doc_metadata(&mailbox_of(FIRST))).expect("a guest's read");
    assert_eq!(v["code"].as_str(), Some("withheld"), "the agent's mailbox stands, private: {v}");
}

/// FENCE 5 (AUTH RES-211, the composition): the committed genesis is the
/// owner's own composition, never the arriving bytes — the bytes differ, the
/// payload's entry stands in it member for member, and it is signed by the
/// owner's hand. FENCE 13b (AUTH-5.58; AUTH-5.10; AUTH-3.34): it is written
/// in the agent space's doc 1 from the session step 2's `delegate` rode, and
/// from another session the board answers `not_owner`.
#[test]
fn the_genesis_is_the_owners_composition_written_from_the_delegates_session() {
    let rig = rig();
    let seen: Ops = Arc::new(Mutex::new(Vec::new()));
    let tapped = Board::new(origin_of(rig.sd.port()), Tokens { inner: PlainHttp::new(), seen: seen.clone() });
    let agent = rig.agent("scribe-host", "scribe");
    let (done, _) = hired(&tapped, &rig, &agent, 1);
    let board = rig.board();
    let genesis = credential_records(&board, FIRST, &[(rig.owner_fp, key_file(&rig.owner, &rig.owner_fp).public.clone())]).unwrap().genesis().cloned().expect("the genesis");
    // The bytes differ; the entries match member for member.
    assert_ne!(genesis.sigless, agent.payload, "never the arriving bytes committed");
    assert!(!String::from_utf8_lossy(&genesis.bytes).contains(&agent.payload), "nor inside them");
    let arrived = skep_identity::parse_enroll(agent.payload.as_bytes()).unwrap();
    assert_eq!(arrived.len(), 1);
    assert_eq!(genesis.enrolled.len(), 3, "the owner's three entries");
    assert_eq!(genesis.enrolled.iter().filter(|e| **e == arrived[0]).count(), 1, "the payload's entry, re-emitted member for member: alg, key, flag and label");
    let pair: Vec<&Enrollment> = genesis.enrolled.iter().filter(|e| e.anchor).collect();
    assert_eq!(pair.iter().map(|e| e.label().map(str::to_string)).collect::<Vec<_>>(), done.anchors.iter().map(|a| Some(a.label.as_str().to_string())).collect::<Vec<_>>(), "each anchor under the label its box fixed");
    assert_eq!(pair.iter().map(|e| Fingerprint::of(&e.key)).collect::<Vec<_>>(), done.anchors.iter().map(|a| a.fingerprint).collect::<Vec<_>>());
    assert!(genesis.sig.is_some(), "signed where a record is signed");
    assert_eq!(genesis.hand, Hand::Key(rig.owner_fp), "by the OWNER's hand");
    // FENCE 13b: one session carries the delegate, the insert and the link.
    let seen = seen.lock().unwrap().clone();
    let token_of = |op: &str| -> Vec<Option<String>> { seen.iter().filter(|(o, _)| o == op).map(|(_, t)| t.clone()).collect() };
    let delegate = token_of("delegate");
    assert_eq!(delegate.len(), 1, "one delegate: {seen:?}");
    assert!(delegate[0].is_some(), "under a session");
    assert_eq!(token_of("insert"), delegate, "the genesis's insert rides step 2's session");
    assert_eq!(token_of("make_link"), delegate, "and so does its link");
    // …and from another session the board answers `not_owner`: the owner's
    // own session as X, over a second prefix a session as the space delegated.
    let device = key_file(&rig.owner, &rig.owner_fp).signer();
    let as_space = wire_session(&board, principal_of(&board, SPACE).unwrap().unwrap(), &device);
    wire_delegate(&board, &as_space, SECOND, 880_002).expect("a second prefix beneath the agent space");
    board.session_close(&as_space).unwrap();
    let as_owner = wire_session(&board, 1, &device);
    let other = rig.agent("other-host", "other");
    let refused = wire_enroll(&board, &as_owner, &device, &doc_1_of(SPACE), SECOND, &[entry_of(&key_file(&other.store, &other.fp), "other")]).expect_err("not the space's session");
    assert!(refused.contains("not_owner"), "{refused}");
    assert!(set_of(&board, SECOND).is_empty(), "and seeds nothing");
}

/// FENCE 10 (AUTH-5.58 steps 5–7; AUTH-5.61): after an anchored hire the
/// agent's doc 1 stands published, minted before the walk said the
/// principal; and a re-run reads it, writes nothing and mints nothing.
#[test]
fn the_agents_doc_one_is_minted_before_the_principal_and_a_re_run_mints_nothing() {
    let rig = rig();
    let (board, log) = recording_board(origin_of(rig.sd.port()));
    let agent = rig.agent("scribe-host", "scribe");
    let (mut person, said) = placing(anchored(), &log);
    let done = hire(&board, &rig.owner, &mut person, &options(&agent.payload, &rig.custody(1))).unwrap_or_else(|h| panic!("{h}\n{}", person.inner.transcript.join("\n")));
    assert_eq!(document_present(&board, &doc_1_of(FIRST)), Ok(true), "the agent's home stands PUBLISHED");
    let lines = log.lock().unwrap().clone();
    let mint = lines.iter().position(|l| l == "POST /op create_new_document").expect("the doc-1 mint");
    let link = lines.iter().position(|l| l == "POST /op make_link").expect("the genesis's link");
    let said = said.lock().unwrap().clone();
    let principal_said = said.iter().find(|(rule, _, _)| rule == "AUTH-5.58 step 6").expect("step 6");
    assert!(principal_said.1.contains(&format!("the agent's principal is {}", done.facts.principal)), "{}", principal_said.1);
    assert!(link < mint && mint < principal_said.2, "genesis, then the mint, and only then the principal: link {link}, mint {mint}, said at {}", principal_said.2);
    assert!(!said.iter().any(|(rule, text, at)| rule != "AUTH-5.58 step 6" && *at <= mint && text.contains(&done.facts.principal.to_string())), "no statement names the principal ahead of the mint");
    let closes = lines.iter().filter(|l| *l == "POST /session/close").count();
    assert_eq!(closes, 2, "the agent space's session and the custody anchor's, both closed: {lines:?}");
    // A re-run with the same record: read, nothing written, nothing minted.
    let before = rig.head();
    log.lock().unwrap().clear();
    let mut again = Scripted::new(vec![]);
    let re = hire(&board, &rig.owner, &mut again, &options(&agent.payload, &rig.custody(2))).unwrap_or_else(|h| panic!("{h}\n{}", again.transcript.join("\n")));
    assert_eq!((re.facts.clone(), re.already, re.minted_home, re.anchors.len()), (done.facts.clone(), true, false, 0));
    assert_eq!(rig.head(), before, "nothing written");
    let lines = log.lock().unwrap().clone();
    assert!(!lines.iter().any(|l| ["POST /op create_new_document", "POST /op delegate", "POST /op insert", "POST /op make_link", "POST /session"].contains(&l.as_str())), "no write and no session: {lines:?}");
    assert!(again.said("this hire already stands") && !again.said("CONSENT confirm"), "{}", again.transcript.join("\n"));
    assert!(!rig.custody(2).exists(), "and no second pair is made");
    assert_eq!(board.next_account_prefix(SPACE).unwrap().as_deref(), Some(SECOND), "one agent beneath the space");
}

/// PUB-5.72's clauses as AUTH-5.78 renders them, in a second spelling: the
/// walk's copy is held to these words, never to its own constant.
const COPY: [(&str, &str); 7] = [
    ("AUTH-5.78", "this agent can read every draft of yours under you — every revision, removed text included, back to this board's floor — and unlike a share, this cannot be revoked: the account stays under you permanently. The agent can publish its own documents, which may quote what it reads. Quotes stay linked to your originals. Nothing but this rule stops it from restating what it reads in its own words — and whatever it publishes is public forever."),
    ("AUTH-5.78 (repetition)", "it can do this repeatedly, at machine rate, for as long as the account stands, and the series shows how your draft was shaped and how much of it existed over that time"),
    ("AUTH-5.78 (reach)", "it does not have to publish anything to do this: it can keep its own copy of what it reads private and share that copy with every account on this board, and only it can withdraw that share"),
    ("AUTH-5.78 (onward tier)", "it can create further accounts beneath itself, permanently and under your prefix, keyed to whoever it chooses; each gets a permanent public home document here and its enrollment is a permanent public record here; whoever it keys reads every draft of yours this agent reads, and you cannot remove them"),
    ("AUTH-5.78 (onward tier, publish)", "whoever it keys can also PUBLISH under your prefix: what they publish is permanent public history here, counted under your account and shown as published by them, a delegate under you — and no rail setting of yours reaches those mints; you see them after the fact, in the supervision feed"),
    ("AUTH-5.78 (onward tier, disclosure)", "whoever it keys can do with your drafts everything this agent can: publish forks of them, keep private copies shared with every account on this board, and re-create their links on a public page — each disclosing how your draft is laid out, repeatedly, for as long as the account stands — and nothing of yours takes any of it back."),
    ("AUTH-5.78 (standing machinery)", "this agent can leave standing machinery on this board — rules it registers that keep writing at other people's documents after its keys are gone, publicly and permanently — and nothing of yours stops it."),
];

/// FENCE 12a (AUTH-5.58 step 2; AUTH-5.44; AUTH-5.78–5.80): before the
/// `delegate` the walk states AUTH-5.78's clauses verbatim, AUTH-5.79's
/// mapping, AUTH-5.80's two statements — at a notebook, the notebook's
/// reader class — the disavowal clause and AUTH-5.44's hire line; and none
/// of step 2's statements is said once the `delegate` is sent. AUTH-5.44's
/// line is said once more where its rule places it, by the backup moment
/// over the sheets it exported.
#[test]
fn the_standing_statements_are_all_said_before_the_delegate_and_none_after() {
    let rig = rig();
    let (board, log) = recording_board(origin_of(rig.sd.port()));
    let agent = rig.agent("scribe-host", "scribe");
    let (mut person, said) = placing(anchored(), &log);
    hire(&board, &rig.owner, &mut person, &options(&agent.payload, &rig.custody(1))).unwrap_or_else(|h| panic!("{h}\n{}", person.inner.transcript.join("\n")));
    let lines = log.lock().unwrap().clone();
    let delegate = lines.iter().position(|l| l == "POST /op delegate").expect("the hire's delegate");
    assert_eq!(lines.iter().filter(|l| *l == "POST /op delegate").count(), 1, "the space stood reserved: one delegate, the agent's");
    let said = said.lock().unwrap().clone();
    let before = |rule: &str| said.iter().filter(|(r, _, at)| r == rule && *at <= delegate).map(|(_, text, _)| text.clone()).collect::<Vec<_>>();
    let after = |rule: &str| said.iter().filter(|(r, _, at)| r == rule && *at > delegate).count();
    for (rule, clause) in COPY {
        assert_eq!(before(rule), vec![clause.to_string()], "{rule}, verbatim, once, ahead of the delegate");
        assert_eq!(after(rule), 0, "{rule} after the delegate");
    }
    let mapping = before("AUTH-5.79").concat();
    assert!(mapping.contains("\"the rail can stop this where you set it\"") && mapping.contains("\"only this sentence stops this, ever\""), "the mapping's two ruled phrases: {mapping}");
    assert!(mapping.contains("The two MINT forms") && mapping.contains("The two MINT-FREE forms") && mapping.contains("reachable by NO rail setting"), "{mapping}");
    let home = before("AUTH-5.80 (home)").concat();
    assert!(home.contains("\"this agent's home document is public from birth, and every edit it makes there — including what it later removes — is public history.\""), "{home}");
    let record = before("AUTH-5.80 (record)").concat();
    assert!(record.contains("\"hiring this agent writes a permanent record in the home document of the space for this account's agents — its name and its keys — and that record stands there forever, whether or not this agent ever writes anything.\""), "{record}");
    for scoped in [&home, &record] {
        assert!(scoped.contains("at this notebook the reader class is this machine") && !scoped.contains("its mirrors"), "the notebook's reader class at the notebook: {scoped}");
    }
    let disavowal = before("AUTH-5.58 step 2 (disavowal)").concat();
    assert!(disavowal.contains("written and signed by YOUR key") && disavowal.contains("reads as DISAVOWED") && disavowal.contains("a disavowal un-hires nothing"), "{disavowal}");
    for rule in ["AUTH-5.79", "AUTH-5.80 (home)", "AUTH-5.80 (record)", "AUTH-5.58 step 2 (disavowal)"] {
        assert_eq!((before(rule).len(), after(rule)), (1, 0), "{rule}: once, ahead of the delegate");
    }
    let keep = before("AUTH-5.44 (hire)").concat();
    assert!(keep.contains("keep both sheets — they are the only way to open a session as this agent") && keep.contains("UNBACKED BY DESIGN") && keep.contains("SECOND COPY OF THIS AGENT'S IDENTITY"), "{keep}");
    assert!(!keep.contains("read its drafts"), "the owner reads an agent's drafts by the rule (AUTH-5.62 (iv)): {keep}");
    // Its second site is the moment's own, over the exported pair: after
    // the export's write, ahead of the genesis.
    let moments: Vec<&(String, String, usize)> = said.iter().filter(|(r, _, at)| r == "AUTH-5.44 (hire)" && *at > delegate).collect();
    let insert = lines.iter().position(|l| l == "POST /op insert").expect("the genesis's insert");
    assert_eq!(moments.len(), 1, "the backup moment's keep-the-papers line");
    assert!(moments[0].1.starts_with("keep both anchor files") && moments[0].2 <= insert, "said ahead of the genesis: {:?}", moments[0]);
    // The order of the walk's writes: the delegate, the genesis, the mint.
    let mint = lines.iter().position(|l| l == "POST /op create_new_document").unwrap();
    assert!(delegate < insert && insert < mint, "{lines:?}");
}

/// FENCE 2 (AUTH-5.58 step 3; AUTH RES-211; AUTH-5.62; AUTH-5.78;
/// AUTH-5.61): `--anchorless`. The genesis holds the agent's one entry and
/// nothing else; at the choice — after the `delegate`, ahead of the typed
/// answer — the walk stated AUTH-5.62's ruled sentence, its costs (i)–(iii)
/// each naming loss beside compromise, (iv) supervision, the shipping
/// venue's clause, and AUTH-5.78's copy a second time; no pair is made and
/// no doc 1 is minted.
#[test]
fn an_anchorless_hire_states_its_costs_at_the_choice_and_writes_the_one_key_alone() {
    let rig = rig();
    let (board, log) = recording_board(origin_of(rig.sd.port()));
    let agent = rig.agent("scribe-host", "scribe");
    let (mut person, said) = placing(vec![Script::Confirm(true), Script::Confirm(true)], &log);
    let opts = HireOptions { anchorless: true, anchor_out: vec![], ..options(&agent.payload, &rig.custody(1)) };
    let done = hire(&board, &rig.owner, &mut person, &opts).unwrap_or_else(|h| panic!("{h}\n{}", person.inner.transcript.join("\n")));
    let t = person.inner.transcript.join("\n");
    assert!(done.anchorless && done.anchors.is_empty() && !done.minted_home && !done.already, "{done:?}");
    let set = set_of(&board, FIRST);
    assert_eq!((set.enrolled.len(), set.has_anchor()), (1, false), "the one entry and nothing else: {set:?}");
    assert!(set.enrolled(&agent.fp).is_some());
    let genesis = credential_records(&board, FIRST, &[]).unwrap().genesis().cloned().unwrap();
    assert_eq!(genesis.enrolled, skep_identity::parse_enroll(agent.payload.as_bytes()).unwrap(), "that entry, member for member");
    assert_eq!(genesis.hand, Hand::Key(rig.owner_fp), "composed and signed by the owner all the same");
    assert_eq!(document_present(&board, &doc_1_of(FIRST)), Ok(false), "no doc 1 is minted: the agent's own first session owes it (AUTH-5.61)");
    let lines = log.lock().unwrap().clone();
    assert!(!lines.iter().any(|l| l == "POST /op create_new_document"), "{lines:?}");
    assert!(!rig.custody(1).exists(), "no pair, no moment");
    assert!(!person.inner.said("PUBLIC label") && !person.inner.said("[AUTH-5.44 (hire)]"), "no box and no keep-the-papers line on this arm:\n{t}");
    // The choice's statements, each after the delegate and ahead of the
    // typed answer.
    let delegate = lines.iter().position(|l| l == "POST /op delegate").unwrap();
    let insert = lines.iter().position(|l| l == "POST /op insert").unwrap();
    let said = said.lock().unwrap().clone();
    let at_the_choice = |rule: &str| said.iter().filter(|(r, _, at)| r == rule && *at > delegate && *at <= insert).map(|(_, text, _)| text.clone()).collect::<Vec<_>>().concat();
    let sentence = at_the_choice("AUTH-5.62");
    assert!(sentence.contains("WHAT ONLY AN ANCHOR SESSION COULD DO HERE AND WHAT A DEVICE KEY ALONE CAN DO AFTER"), "the ruled sentence: {sentence}");
    assert!(sentence.contains("to stop it by retiring its working key") && sentence.contains("the working key alone does everything this account can do"), "both halves answered: {sentence}");
    for cost in ["AUTH-5.62 (i)", "AUTH-5.62 (ii)", "AUTH-5.62 (iii)"] {
        let text = at_the_choice(cost);
        assert!(text.contains("COMPROMISE") && text.contains("LOSS"), "{cost} names loss beside compromise: {text}");
    }
    assert!(at_the_choice("AUTH-5.62 (iv)").contains("SUPERVISION — a statement, not a cost"), "{}", at_the_choice("AUTH-5.62 (iv)"));
    let venue = at_the_choice("AUTH-5.62 (venue)");
    assert!(venue.contains("on a notebook the agent's host is YOUR machine") && venue.contains("counterweight a compromise of the working key and never the machine's"), "the shipping venue's clause: {venue}");
    for (rule, clause) in COPY {
        assert_eq!(at_the_choice(rule), clause, "{rule} a second time, at the choice");
        assert_eq!(said.iter().filter(|(r, _, _)| r == rule).count(), 2, "{rule}: once ahead of the delegate, once at the choice");
    }
    let choice = person.inner.transcript.iter().position(|l| l.contains("CONSENT confirm: CONFIRM THE ANCHORLESS HIRE")).expect("the typed answer");
    let last_cost = person.inner.transcript.iter().rposition(|l| l.contains("[AUTH-5.78 (standing machinery)]")).unwrap();
    assert!(last_cost < choice, "every statement ahead of the answer:\n{t}");
    assert!(person.inner.said("[AUTH-5.61]: ANCHORLESS: no session as this agent can be opened from here"), "{t}");
    // Declined at the choice: no genesis, and the prefix stands.
    let other = rig.agent("other-host", "other");
    let mut person = Scripted::new(vec![Script::Confirm(false)]);
    let opts = HireOptions { anchorless: true, anchor_out: vec![], ..options(&other.payload, &rig.custody(2)) };
    let halt = hire(&board, &rig.owner, &mut person, &opts).expect_err("declined");
    assert!(halt.to_string().contains("the anchorless choice was not confirmed") && halt.to_string().contains("no genesis was written"), "{halt}");
    assert!(set_of(&board, SECOND).is_empty() && principal_of(&board, SECOND).unwrap().is_some(), "the prefix stands, keyless");
}

/// The halt of a hire refused at step 4: nothing of the genesis written, the
/// prefix standing delegated and keyless — step 2's recoverable state.
fn refused_before_the_genesis(rig: &Rig, payload: &str, script: Vec<Script>, n: usize) -> (Halt, Scripted) {
    let board = rig.board();
    let mut person = Scripted::new(script);
    let halt = hire(&board, &rig.owner, &mut person, &options(payload, &rig.custody(n))).expect_err("refused");
    assert!(principal_of(&board, FIRST).unwrap().is_some(), "the agent's prefix stands: {halt}");
    assert!(set_of(&board, FIRST).is_empty(), "no genesis is written: {halt}");
    assert!(halt.to_string().contains("no genesis was written") && halt.to_string().contains("resumes at this same address"), "the refusal says what the delegate left: {halt}");
    assert_eq!(board.next_account_prefix(SPACE).unwrap().as_deref(), Some(SECOND), "one prefix");
    (halt, person)
}

/// FENCE 3 (AUTH RES-211, the count): a payload of two device-flagged
/// entries is refused before the consent, and no genesis is written.
#[test]
fn a_payload_of_two_device_entries_is_refused_before_the_consent() {
    let rig = rig();
    let (one, two) = (rig.agent("host-one", "scribe"), rig.agent("host-two", "scribe two"));
    let payload = encode_enroll(&[entry_of(&key_file(&one.store, &one.fp), "scribe"), entry_of(&key_file(&two.store, &two.fp), "scribe two")]);
    let (halt, person) = refused_before_the_genesis(&rig, &payload, vec![Script::LabelDefault, Script::LabelDefault], 1);
    assert!(halt.to_string().contains("the payload carries 2 device-flagged entries, and a hire takes EXACTLY ONE"), "{halt}");
    assert!(!person.said("CONSENT confirm"), "refused ahead of the consent:\n{}", person.transcript.join("\n"));
}

/// FENCE 9 (AUTH-5.58 step 4, the flag): a payload of one device entry and
/// one anchor-flagged entry — which the count alone passes — is refused at
/// the hire by the flag test's own face.
#[test]
fn a_payload_carrying_an_anchor_flagged_entry_is_refused_by_the_flag_test() {
    let rig = rig();
    let agent = rig.agent("scribe-host", "scribe");
    let planted = KeyFile::new(Seed::fresh(), true, Some(Label::new("a sheet of the agent's own").unwrap()), None);
    let payload = encode_enroll(&[entry_of(&key_file(&agent.store, &agent.fp), "scribe"), Enrollment::new(planted.public.clone(), true, Some("a sheet of the agent's own".into())).unwrap()]);
    let (halt, person) = refused_before_the_genesis(&rig, &payload, vec![Script::LabelDefault, Script::LabelDefault], 1);
    let text = halt.to_string();
    assert!(text.contains(&format!("the payload carries an ANCHOR-flagged entry ({}) and a hire takes the agent's one working key alone", planted.fingerprint)), "the flag test's own face: {text}");
    assert!(text.contains("an agent account's anchors are the OWNER'S OWN custody pair") && !text.contains("device-flagged entries"), "{text}");
    assert!(!person.said("CONSENT confirm"), "{}", person.transcript.join("\n"));
}

/// FENCE 12 (AUTH-5.58 step 4; AUTH-5.42): a payload whose entry carries no
/// label is refused and never committed.
#[test]
fn an_empty_payload_label_is_refused_and_never_committed() {
    let rig = rig();
    let agent = rig.agent("scribe-host", "scribe");
    let payload = encode_enroll(&[Enrollment::new(key_file(&agent.store, &agent.fp).public.clone(), false, None).unwrap()]);
    let (halt, person) = refused_before_the_genesis(&rig, &payload, vec![Script::LabelDefault, Script::LabelDefault], 1);
    assert!(halt.to_string().contains(&format!("the payload's key {} carries NO label, and a hire never commits an empty byline", agent.fp)), "{halt}");
    assert!(!person.said("CONSENT confirm"), "{}", person.transcript.join("\n"));
    // An empty label at a pair's box is faced there too, and asked again.
    let mut person = Scripted::new(vec![Script::Label(String::new()), Script::LabelDefault, Script::LabelDefault, Script::Confirm(true)]);
    let done = hire(&rig.board(), &rig.owner, &mut person, &options(&agent.payload, &rig.custody(2))).unwrap_or_else(|h| panic!("{h}\n{}", person.transcript.join("\n")));
    assert!(person.said("[AUTH-1.24]: that name is refused at the box"), "{}", person.transcript.join("\n"));
    assert_eq!(done.facts.account, FIRST, "and the refused run's prefix is the one resumed");
    assert!(done.anchors.iter().all(|a| !a.label.as_str().is_empty()));
}

/// FENCE 4 (AUTH-5.58 step 4; AUTH-5.32): a mistyped first group refuses
/// before the genesis, the prefix standing; the right group proceeds. FENCE
/// 13 (AUTH-5.19/5.20; AUTH-5.58 step 2's resume): the run that proceeds
/// resumes the same `X.1.n` under the persisted `new_id` and seats no
/// second.
#[test]
fn a_mistyped_group_refuses_before_the_genesis_and_the_re_run_resumes_the_same_prefix() {
    let rig = rig();
    let board = rig.board();
    let agent = rig.agent("scribe-host", "scribe");
    let wrong = if agent.fp.to_hex().starts_with("00000000") { "11111111" } else { "00000000" };
    let script = vec![Script::LabelDefault, Script::LabelDefault, Script::Typed(wrong.into()), Script::Typed(wrong.into()), Script::Typed(wrong.into())];
    let (halt, person) = refused_before_the_genesis(&rig, &agent.payload, script, 1);
    let t = person.transcript.join("\n");
    assert!(halt.to_string().contains("the comparison was declined"), "{halt}");
    assert!(halt.to_string().contains("The two custody sheets this run exported name that account and open nothing"), "the dead pair named: {halt}");
    assert_eq!(person.transcript.iter().filter(|l| l.starts_with("CONSENT confirm")).count(), 3, "{t}");
    assert!(person.said("label: scribe — this label is PUBLIC, PERMANENT and UNCORRECTABLE") && person.said(&agent.fp.to_hex()), "the label and the fingerprint shown:\n{t}");
    assert!(person.said("have the record recomposed under the intended label"), "the wrong-label act:\n{t}");
    let persisted = rig.owner.persisted_new_id(board.dialed(), FIRST).unwrap().expect("the new_id persisted before the frame");
    assert_eq!(principal_of(&board, FIRST).unwrap(), Some(persisted));
    // The right group: the same prefix, resumed by reading; no second.
    let mut person = Scripted::new(anchored());
    let done = hire(&board, &rig.owner, &mut person, &options(&agent.payload, &rig.custody(2))).unwrap_or_else(|h| panic!("{h}\n{}", person.transcript.join("\n")));
    assert_eq!((done.facts.account.as_str(), done.facts.principal), (FIRST, persisted), "the same X.1.n, under the persisted id");
    assert!(person.said("[AUTH-5.58 step 7]: resuming at 1.0.1.1.1"), "{}", person.transcript.join("\n"));
    assert_eq!(board.next_account_prefix(SPACE).unwrap().as_deref(), Some(SECOND), "no second prefix was seated");
    assert_eq!(principal_of(&board, SECOND).unwrap(), None);
    let set = set_of(&board, FIRST);
    assert_eq!(set.enrolled.len(), 3);
    let (_, live) = anchor_file(&rig.custody(2), "a");
    let (_, dead) = anchor_file(&rig.custody(1), "a");
    assert!(set.enrolled(&live.fingerprint).is_some() && set.enrolled(&dead.fingerprint).is_none(), "the fresh pair is enrolled, the refused run's is not");
}

/// FENCE 13, the two kills around the `delegate` (AUTH-5.19; AUTH-5.20). A
/// run killed AFTER it — the `delegate` committed, nothing else — is resumed
/// at the same address. A run killed BEFORE it — the `new_id` persisted, the
/// frame never sent — sends that same id.
#[test]
fn a_run_killed_around_the_delegate_resumes_under_the_persisted_new_id() {
    // Killed after: the person leaves at the pair's first box.
    let rig = rig();
    let board = rig.board();
    let agent = rig.agent("scribe-host", "scribe");
    let mut person = Scripted::new(vec![]);
    let halt = hire(&board, &rig.owner, &mut person, &options(&agent.payload, &rig.custody(1))).expect_err("left at the box");
    assert!(halt.to_string().contains("the hire stops before its first key record"), "{halt}");
    let persisted = rig.owner.persisted_new_id(board.dialed(), FIRST).unwrap().expect("persisted before the frame");
    assert_eq!((principal_of(&board, FIRST).unwrap(), set_of(&board, FIRST).is_empty()), (Some(persisted), true));
    let (done, _) = hired(&board, &rig, &agent, 2);
    assert_eq!((done.facts.account.as_str(), done.facts.principal), (FIRST, persisted));
    assert_eq!(board.next_account_prefix(SPACE).unwrap().as_deref(), Some(SECOND), "no second prefix");
    // A second agent lands beside it, at the next child.
    let next = rig.agent("second-host", "second scribe");
    let (second, _) = hired(&board, &rig, &next, 3);
    assert_eq!(second.facts.account, SECOND);
    assert_ne!(second.facts.principal, persisted);

    // Killed before: the line stands in the store and no frame went out.
    let rig = self::rig();
    let board = rig.board();
    let agent = rig.agent("scribe-host", "scribe");
    rig.owner.bind(&Binding::Enrollment { origin: board.dialed().clone(), principal: 4_242_424_242, account: FIRST.into(), fingerprint: rig.owner_fp }).unwrap();
    assert_eq!(principal_of(&board, FIRST).unwrap(), None, "never delegated");
    let (done, _) = hired(&board, &rig, &agent, 1);
    assert_eq!((done.facts.account.as_str(), done.facts.principal), (FIRST, 4_242_424_242), "the same new_id, sent again (AUTH-5.19)");
}

/// FENCE 13a (the owner's ruling, 2026-11-15): an anchored run killed after
/// the genesis and before the mint. The re-run stops, writes nothing,
/// answers no principal, and names the unminted doc 1 and the custody
/// anchor the mint needs; it re-imports no sheet.
#[test]
fn a_run_killed_between_the_genesis_and_the_mint_stops_the_re_run() {
    let rig = rig();
    let agent = rig.agent("scribe-host", "scribe");
    // The second challenge is the custody anchor's session: the run dies there.
    let dying = Board::new(origin_of(rig.sd.port()), DiesAt { inner: PlainHttp::new(), challenges: AtomicUsize::new(0), at: 2 });
    let mut person = Scripted::new(anchored());
    let killed = hire(&dying, &rig.owner, &mut person, &options(&agent.payload, &rig.custody(1))).expect_err("killed at step 5");
    assert_eq!(killed.exit_code(), 4, "the kill is a transport fault: {killed}");
    let board = rig.board();
    let principal = principal_of(&board, FIRST).unwrap().expect("delegated");
    assert_eq!(set_of(&board, FIRST).enrolled.len(), 3, "the genesis stands");
    assert_eq!(document_present(&board, &doc_1_of(FIRST)), Ok(false), "and the agent's doc 1 does not");
    assert!(!person.said("[AUTH-5.58 step 6]"), "no principal was said");
    // The re-run: the stop.
    let (recording, log) = recording_board(origin_of(rig.sd.port()));
    let before = rig.head();
    let mut person = Scripted::new(vec![]);
    let stop = hire(&recording, &rig.owner, &mut person, &options(&agent.payload, &rig.custody(2))).expect_err("the stop");
    let text = stop.to_string();
    assert_eq!(stop.exit_code(), 3, "{text}");
    assert!(text.contains("the hire of 1.0.1.1.1 stopped between its first key record and its doc-1 mint, and this run writes nothing"), "{text}");
    assert!(text.contains("1.0.1.1.1.0.1 is NOT yet minted") && text.contains("opened by a CUSTODY ANCHOR from its sheet"), "the unminted doc 1 and the anchor it needs: {text}");
    assert!(text.contains("this command never re-imports a sheet on its own") && text.contains("no principal is answered here"), "{text}");
    assert!(!text.contains(&principal.to_string()), "the principal is named nowhere in the stop: {text}");
    assert_eq!(rig.head(), before, "nothing written");
    let lines = log.lock().unwrap().clone();
    assert!(!lines.iter().any(|l| l.starts_with("GET /challenge") || l == "POST /session"), "no session opened: {lines:?}");
    assert!(person.transcript.iter().all(|l| !l.starts_with("SECRET")) && !person.said("[AUTH-5.58 step 6]"), "no import asked and no principal said:\n{}", person.transcript.join("\n"));
    assert_eq!(document_present(&board, &doc_1_of(FIRST)), Ok(false));
    assert!(!rig.custody(2).exists(), "and no second pair is made");
}

/// FENCE 11 (AUTH-5.58 step 4, the re-hire test): at `--replaces`, a payload
/// key standing in the predecessor's `enrolled` list — the loss arm, a host
/// rebuilt from the same image — is refused, and so is one standing in its
/// `retired` list; no genesis is written in either. A fresh key is hired,
/// its boxes naming the predecessor's labels, and a matching label refused
/// by nothing.
#[test]
fn a_re_hire_refuses_a_key_that_stands_in_the_predecessors_set() {
    let rig = rig();
    let board = rig.board();
    let old = rig.agent("old-host", "scribe");
    let (first, _) = hired(&board, &rig, &old, 1);
    let replacing = |payload: &str, n: usize| HireOptions { replaces: Some(FIRST.into()), ..options(payload, &rig.custody(n)) };
    let refused = |n: usize, list: &str| {
        let mut person = Scripted::new(vec![Script::LabelDefault, Script::LabelDefault]);
        let halt = hire(&board, &rig.owner, &mut person, &replacing(&old.payload, n)).expect_err("no fresh key");
        let text = halt.to_string();
        assert!(text.contains(&format!("the payload's key {} is NOT A FRESH KEY: it stands {list} at 1.0.1.1.1, the account this hire replaces", old.fp)), "{text}");
        assert!(text.contains("no genesis was written"), "{text}");
        assert!(set_of(&board, SECOND).is_empty(), "no genesis is written at the successor");
        assert!(!person.said("CONSENT confirm"), "refused ahead of the consent:\n{}", person.transcript.join("\n"));
        person
    };
    // The loss arm: the predecessor's working key still ENROLLED there.
    let person = refused(2, "enrolled");
    assert!(person.said("[AUTH-5.58 step 3 (re-hire)]: RE-HIRE: this hire REPLACES 1.0.1.1.1"), "{}", person.transcript.join("\n"));
    let labels: Vec<String> = first.anchors.iter().map(|a| format!("`{}`", a.label)).chain(["`scribe`".to_string()]).collect();
    assert!(person.said(&format!("This hire REPLACES 1.0.1.1.1, whose sheets and key carry {}", labels.join(", "))), "the boxes show the predecessor's labels:\n{}", person.transcript.join("\n"));
    assert!(principal_of(&board, SECOND).unwrap().is_some(), "the successor's prefix stands");
    // The owner stops the predecessor: its key now stands RETIRED there.
    let (_, sheet) = anchor_file(&rig.custody(1), "a");
    let custody = sheet.signer();
    let as_agent = wire_session(&board, first.facts.principal, &custody);
    wire_retire(&board, &as_agent, &custody, &doc_1_of(FIRST), FIRST, &[old.fp]).expect("the stop");
    board.session_close(&as_agent).unwrap();
    assert!(set_of(&board, FIRST).retired(&old.fp).is_some());
    refused(3, "retired");
    // A fresh key under the SAME label: hired, at the prefix the refused
    // runs left, and nothing refuses the matching name.
    let fresh = rig.agent("new-host", "scribe");
    let mut person = Scripted::new(anchored());
    let done = hire(&board, &rig.owner, &mut person, &replacing(&fresh.payload, 4)).unwrap_or_else(|h| panic!("{h}\n{}", person.transcript.join("\n")));
    assert_eq!((done.facts.account.as_str(), done.key, done.label.as_deref()), (SECOND, fresh.fp, Some("scribe")));
    assert_eq!(board.next_account_prefix(SPACE).unwrap().as_deref(), Some("1.0.1.1.3"), "one successor, resumed at the refused runs' prefix");
    assert!(person.said("where the label below reads like one of them, answer `no`"), "{}", person.transcript.join("\n"));
    // `--replaces` names an agent of this space, or the walk halts unread.
    let mut person = Scripted::new(vec![]);
    let halt = hire(&board, &rig.owner, &mut person, &HireOptions { replaces: Some("1.0.1.2".into()), ..options(&fresh.payload, &rig.custody(5)) }).expect_err("no agent of this space");
    assert!(halt.to_string().contains("1.0.1.2 is no agent of yours"), "{halt}");
}

/// FENCE 6 (AUTH-5.65; the 2026-10-19 rulings — a pin): the agent's first
/// signed session opens under its own key, and the owner's own keys — the
/// device key that hired it, the owner's own anchors — open nothing of it.
/// And an agent's account hires nobody: an agent holds no agent space.
#[test]
fn the_agent_signs_in_under_its_own_key_and_the_owners_keys_open_nothing_of_it() {
    let rig = rig();
    let board = rig.board();
    let agent = rig.agent("scribe-host", "scribe");
    let (done, _) = hired(&board, &rig, &agent, 1);
    let principal = done.facts.principal;
    let session = handshake(&board, Scope::Content, &agent.signer(), principal, Site::Session).expect("the agent's own key");
    assert_eq!((session.account(), session.fingerprint()), (FIRST, agent.fp));
    session.close().unwrap();
    let owner_device = key_file(&rig.owner, &rig.owner_fp).signer();
    let (_, own_anchor) = anchor_file(&rig.anchors, "a");
    for (whose, key) in [("the owner's device key", owner_device), ("the owner's own anchor", own_anchor.signer())] {
        let refused = handshake(&board, Scope::Content, &key, principal, Site::Session).expect_err(whose);
        assert!(refused.to_string().contains(&format!("{} is in neither list of the set at 1.0.1.1.1", fp_of(&key))), "{whose}: {refused}");
    }
    // The custody sheet is the owner's one way to act as the agent.
    let (_, sheet) = anchor_file(&rig.custody(1), "b");
    handshake(&board, Scope::Content, &sheet.signer(), principal, Site::Recover).expect("a custody anchor opens the agent's account").close().unwrap();
    // An agent's account hires nobody.
    let worker = rig.agent("worker-host", "worker");
    let mut person = Scripted::new(vec![]);
    let halt = hire(&board, &agent.store, &mut person, &HireOptions { principal, ..options(&worker.payload, &rig.custody(2)) }).expect_err("an agent's account");
    assert!(halt.to_string().contains("1.0.1.1.1 is itself a hired agent's account, and an agent holds no agent space"), "{halt}");
    assert_eq!(principal_of(&board, &first_child(FIRST)).unwrap(), None, "and nothing was delegated beneath it");
}

/// FENCE 7 (AUTH-5.87): a rotation at a hired agent — the agent's own
/// device-grade act, run through `first_session` as every rotation is —
/// reserves no agent space beneath it: its first child stays unseated, and
/// no home is minted there.
#[test]
fn a_rotation_at_a_hired_agent_reserves_no_agent_space_beneath_it() {
    let rig = rig();
    let board = rig.board();
    let agent = rig.agent("scribe-host", "scribe");
    let (done, _) = hired(&board, &rig, &agent, 1);
    let (recording, log) = recording_board(origin_of(rig.sd.port()));
    let mut person = Scripted::new(vec![Script::Confirm(true)]);
    let opts = RotateOptions { principal: done.facts.principal, label: Some("scribe".into()), payload: None };
    let rotated = rotate(&recording, &agent.store, &mut person, &opts).unwrap_or_else(|h| panic!("{h}\n{}", person.transcript.join("\n")));
    assert_eq!((rotated.facts.account.as_str(), rotated.old), (FIRST, agent.fp));
    let set = set_of(&board, FIRST);
    assert!(set.retired(&agent.fp).is_some() && set.enrolled(&rotated.new).is_some_and(|e| !e.anchor), "the rotation ran whole: {set:?}");
    assert_eq!(set.enrolled.iter().filter(|e| e.anchor).count(), 2, "the custody pair stands");
    let worker = first_child(FIRST);
    assert_eq!(principal_of(&board, &worker).unwrap(), None, "the agent's first child stays unseated");
    assert_eq!(document_present(&board, &doc_1_of(&worker)), Ok(false), "and no home is minted there");
    assert_eq!(board.next_account_prefix(FIRST).unwrap().as_deref(), Some(worker.as_str()), "its first worker's address is still the next one");
    let lines = log.lock().unwrap().clone();
    assert!(!lines.iter().any(|l| l == "POST /op delegate" || l == "POST /op create_new_document"), "no delegate and no mint: {lines:?}");
    assert!(rig_store_holds_no_line_beneath(&agent.store, &board, FIRST), "and no persist-first line for a child of the agent");
}

/// Whether `store` holds no binding line for a child of `account`.
fn rig_store_holds_no_line_beneath(store: &FileStore, board: &Board, account: &str) -> bool {
    store.all_bindings().unwrap().iter().all(|b| !matches!(b, Binding::Enrollment { origin, account: a, .. } if origin == board.dialed() && a.starts_with(&format!("{account}."))))
}

/// FENCE 8 (AUTH-5.64; the scribe analysis §1.3 — a pin): the stop at an
/// account a hire made. `recover`'s agent arm, run from the hirer's own
/// store — which holds a device key bound at the hirer's own principal on
/// this board — with a custody sheet the hire exported, retires the agent's
/// working key and enrolls none; the retirement homes in the doc 1 the
/// hire's step 5 minted.
#[test]
fn the_stop_at_a_hired_account_retires_the_working_key_and_enrolls_none() {
    let rig = rig();
    let board = rig.board();
    let agent = rig.agent("scribe-host", "scribe");
    let (done, _) = hired(&board, &rig, &agent, 1);
    assert_eq!(rig.owner.enrollment_for(board.dialed(), 1).unwrap().map(|(_, fp)| fp), Some(rig.owner_fp), "the hirer's own binding on this board");
    let (sheet, _) = anchor_file(&rig.custody(1), "a");
    let opts = RecoverOptions { principal: done.facts.principal, anchor: Some(sheet.clone()), lost: vec![], stolen: Some(false), anchor_lost: false, anchor_out: vec![], paper: false, host_name: "testhost".into(), date: "2026-11-15".into() };
    let script = vec![Script::YesNo(false), Script::KeptOrPlaced(KeptOrPlaced::Kept), Script::YesNo(true), Script::YesNo(true), Script::Confirm(true)];
    let mut person = Scripted::new(script);
    let stopped = recover(&board, &rig.owner, &mut person, &opts).unwrap_or_else(|h| panic!("{h}\n{}", person.transcript.join("\n")));
    let t = person.transcript.join("\n");
    assert!(stopped.containment && stopped.enrolled.is_empty(), "{stopped:?}");
    assert_eq!(stopped.retired, vec![agent.fp]);
    assert!(person.said("THE ENROLLMENT IS REFUSED") && person.said("RETIRE THE NON-ANCHOR SET AND ENROLL NOTHING"), "{t}");
    let set = set_of(&board, FIRST);
    assert_eq!((set.enrolled.len(), set.enrolled.iter().all(|e| e.anchor)), (2, true), "the pair alone stands enrolled: {set:?}");
    assert!(set.retired(&agent.fp).is_some());
    assert!(set.enrolled(&rig.owner_fp).is_none() && set.retired(&rig.owner_fp).is_none(), "the hirer's key never enters the agent's set");
    let retirement = credential_records(&board, FIRST, &[]).unwrap().retirement_of(&agent.fp).cloned().expect("the retirement");
    assert_eq!(retirement.home, doc_1_of(FIRST), "homed in the doc 1 the hire minted");
    assert!(sheet.is_file(), "the kept sheet is retained");
    assert_eq!(principal_of(&board, &first_child(FIRST)).unwrap(), None, "nothing reserved beneath the agent");
    assert!(rig.owner.enrollment_for(board.dialed(), done.facts.principal).unwrap().is_some_and(|(_, fp)| fp == rig.owner_fp), "the store's line for the agent is the hire's persist-first line alone");
    // The stopped agent's key opens nothing.
    assert!(handshake(&board, Scope::Content, &agent.signer(), done.facts.principal, Site::Session).is_err());
}

/// H0's preconditions (AUTH-5.87). An owner whose agent space is not yet
/// reserved — a hosted customer's account, whose cascade runs no setup act —
/// has it reserved first, the account's own setup act in its pinned order,
/// and the agent then lands beneath it. An account whose first sub-account
/// holds a set of its own has no agent space, permanently, and the walk
/// stops before any write.
#[test]
fn the_agent_space_is_reserved_first_where_owed_and_a_seeded_one_closes_the_door() {
    // A hosted customer's account: a device key and an anchor pair, no
    // agent space.
    let dir = tempfile::tempdir().unwrap();
    let sd = spawn(&dir.path().join("board"), false);
    let board = board(sd.port());
    let owner = FileStore::open(dir.path().join("owner"));
    let owner_fp = keygen(&owner, "owner laptop");
    let (a, b) = (KeyFile::new(Seed::fresh(), true, Some(Label::new("a").unwrap()), None), KeyFile::new(Seed::fresh(), true, Some(Label::new("b").unwrap()), None));
    let payload = encode_enroll(&[
        Enrollment::new(a.public.clone(), true, Some("a".into())).unwrap(),
        Enrollment::new(b.public.clone(), true, Some("b".into())).unwrap(),
        entry_of(&key_file(&owner, &owner_fp), "owner laptop"),
    ]);
    let HostedOutcome::Claimed(_) = hosted(&board, payload.as_bytes(), 1).unwrap() else { panic!("the hosted claim") };
    assert_eq!(principal_of(&board, SPACE).unwrap(), None, "no agent space yet");
    let agent_store = FileStore::open(dir.path().join("agent"));
    let agent_fp = keygen(&agent_store, "scribe");
    let record = encode_enroll(&[entry_of(&key_file(&agent_store, &agent_fp), "scribe")]);
    let mut person = Scripted::new(anchored());
    let done = hire(&board, &owner, &mut person, &options(&record, &dir.path().join("custody"))).unwrap_or_else(|h| panic!("{h}\n{}", person.transcript.join("\n")));
    let t = person.transcript.join("\n");
    assert!(person.said("[AUTH-5.87]: the space for your agents is not yet reserved at 1.0.1"), "{t}");
    let at = |needle: &str| person.transcript.iter().position(|l| l.contains(needle)).unwrap_or_else(|| panic!("{needle} missing:\n{t}"));
    assert!(at("[AUTH-5.78 (standing machinery)]") < at("[AUTH-5.87]"), "the standing statements ahead of every write, the setup act's among them:\n{t}");
    assert!(principal_of(&board, SPACE).unwrap().is_some() && document_present(&board, &doc_1_of(SPACE)) == Ok(true), "the space and its home, reserved");
    assert_eq!((done.facts.account.as_str(), set_of(&board, FIRST).enrolled.len()), (FIRST, 3));

    // A handed-off account whose first sub-account holds a set of its own:
    // no agent space stands there, permanently. (A claimant's own first
    // sub-account is never seedable, so the cell is a recipient's.)
    let rig = rig();
    let board = rig.board();
    let recipient = FileStore::open(rig.dir.path().join("recipient"));
    let recipient_fp = keygen(&recipient, "recipient");
    let theirs = key_file(&recipient, &recipient_fp).signer();
    let account = keyed_sub_account(&board, &rig.anchors, &key_file(&rig.owner, &rig.owner_fp).signer(), 2, 770_002, &theirs, "recipient");
    let first = first_child(&account);
    let as_recipient = wire_session(&board, 770_002, &theirs);
    wire_home(&board, &as_recipient, &theirs, &account).expect("the recipient's home");
    wire_delegate(&board, &as_recipient, &first, 770_021).expect("their first sub-account");
    let stranger = rig.agent("stranger", "stranger");
    wire_enroll(&board, &as_recipient, &theirs, &doc_1_of(&account), &first, &[entry_of(&key_file(&stranger.store, &stranger.fp), "stranger")]).expect("the first sub-account handed away");
    board.session_close(&as_recipient).unwrap();
    let before = rig.head();
    let agent = rig.agent("scribe-host", "scribe");
    let mut person = Scripted::new(vec![]);
    let halt = hire(&board, &recipient, &mut person, &HireOptions { principal: 770_002, ..options(&agent.payload, &rig.custody(1)) }).expect_err("no agent space");
    assert!(halt.to_string().contains("no agent space stands at 1.0.1.2: 1.0.1.2.1 holds a key set of its own") && halt.to_string().contains("closed for good"), "{halt}");
    assert_eq!(rig.head(), before, "nothing written");
    assert!(person.transcript.is_empty(), "and nothing said: the halt stands alone");
    assert_eq!(board.next_account_prefix(&first).unwrap().as_deref(), Some("1.0.1.2.1.1"), "and nothing delegated beneath it");
}
