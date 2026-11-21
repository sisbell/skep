//! The nineteenth command through the binary (`skep deposit`; REG-1.9).
//!
//! Every board here is ENFORCING: local trust off and the claim ahead of
//! the first write, so no bare session binds and each write below rode a
//! signed session ([`Registry::open`] asserts the mode).
//!
//! **The node account** comes from the suite's own hands, as the daemon's
//! registry suite makes one, since no console mints one yet: principal 0's
//! signed session delegates the next top-level prefix; the registrar's
//! session writes the account's genesis into the registrar's own doc 1,
//! verbatim from the record `skep keygen --payload` printed in the node
//! account's own store. That store's one device key is the node account's
//! key; no other party holds it.
//!
//! **The reader** is a verifying mirror of the board
//! (`skep_resolve::Mirror`), opened from the board's own root hint: every
//! registry record judged under its home's key set as of its own position,
//! and folded by the registry's currency rule (REG-1.10). An endpoint is
//! current where that mirror's index answers it current.
//!
//! **The cells.** The pin first: the real `skep bind` at a node account
//! mints its doc 1 from its own first signed session (REG-1.51). Then the
//! command: at an account whose doc 1 is missing it mints the home
//! published and deposits the endpoint, which the mirror reads current and
//! signed by the store's own key; a key of no set of that account deposits
//! nothing. A later deposit names the one it replaces and becomes current,
//! past an inert record and past a nullified one, and nothing is erased.
//! And each refusal, by name.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde_json::{json, Value};
use skep_address::Address;
use skep_client::board::{frames, Answer, Board, ChangesAnswer, ChangesQuery, Opened, Scope, SessionBody, T_RETRACTION};
use skep_client::ceremony::claim::{self, ClaimOutcome, NotebookOptions};
use skep_client::ceremony::deposit::{deposit, Deposit, DepositKind};
use skep_client::ceremony::first_session::document_present;
use skep_client::ceremony::handshake::{handshake, Site};
use skep_client::ceremony::registry_record::{deposit_endpoint_naming, endpoint_history, latest_stood, EndpointDeposit};
use skep_client::derive::Mode;
use skep_client::dial::PlainHttp;
use skep_client::person::scripted::{Script, Scripted};
use skep_client::resolve::{mirror_dial, mirror_dialer, root_hint, EndpointRecord, Judged, Verdict};
use skep_client::sheet::Label;
use skep_client::sign::{session_payload, sig_hex, Signer};
use skep_client::store::{FileStore, KeySelector, KeyStore};
use skep_client::Origin;
use skep_identity::{entry_body_nullify, entry_frame, unit_span, DocTerm, EntrySlot, Fingerprint, LinkSlots};
use skep_resolve::Mirror;
use skepd::Skepd;

use crate::common::{origin, s, skep, spawn, tree, Run};

/// The registrar's principal and its doc 1: the board's claimant.
const REGISTRAR: u64 = 1;
const REGISTRAR_HOME: &str = "1.0.1.0.1";

/// A claimed, ENFORCING board: the registry's, and its registrar's store.
struct Registry {
    dir: tempfile::TempDir,
    _daemon: Skepd,
    origin: String,
    board: Board,
}

/// A node account on the registry's board, and the store holding its key.
struct Node {
    account: String,
    home: String,
    principal: u64,
    store: PathBuf,
}

impl Registry {
    /// Starts a board with local trust off and claims it through the library.
    ///
    /// The notebook walk is a person door the binary refuses without a
    /// terminal, so the claim is the library's, as `ceremonies.rs` makes
    /// its. The mode is asserted: a cell on a board left permissive fails.
    fn open() -> Registry {
        let dir = tempfile::tempdir().expect("a directory");
        let daemon = spawn(&dir.path().join("board"), false);
        let origin = origin(daemon.port());
        let board = Board::new(Origin::parse(&origin).expect("an origin"), PlainHttp::new());
        let store = FileStore::open(dir.path().join("registrar"));
        store.generate(Some(Label::new("registrar").unwrap())).expect("the registrar's key");
        let mut person = Scripted::new(vec![Script::LabelDefault, Script::LabelDefault]);
        let anchors = dir.path().join("anchors");
        let opts = NotebookOptions { principal: Some(REGISTRAR), display_name: Some("a registry".into()), anchor_out: vec![anchors.join("a"), anchors.join("b")], paper: false, host_name: "testhost".into(), date: "2026-11-15".into() };
        let ClaimOutcome::Ours(_) = claim::notebook(&board, &store, &mut person, &opts).unwrap_or_else(|h| panic!("{h}\n{}", person.transcript.join("\n"))) else { panic!("a stranger's board") };
        assert_eq!(Mode::of(&board.health().expect("health")), Mode::Enforcing, "the board is ENFORCING ahead of every cell");
        Registry { dir, _daemon: daemon, origin, board }
    }

    fn registrar_store(&self) -> PathBuf {
        self.dir.path().join("registrar")
    }

    /// Makes a node account by the suite's own hands, keyed and never bound.
    ///
    /// `name` names its store's directory. The key is generated by the
    /// binary in that store; principal 0's signed session, which the
    /// registrar's key opens, delegates the next top-level prefix under
    /// `principal`; and the registrar's own session writes the genesis into
    /// its doc 1, the printed record verbatim.
    fn node_account(&self, name: &str, principal: u64) -> Node {
        let store = self.dir.path().join(name);
        let r = skep(&["keygen", "--label", name, "--payload", "--dir", s(&store)], &[], None);
        assert_eq!(r.code, 0, "{r:?}");
        let payload = r.lines()[0].to_string();
        let board = &self.board;
        let signer = FileStore::open(self.registrar_store()).signer(&KeySelector::Board { origin: board.dialed(), principal: Some(REGISTRAR) }).expect("the registrar's key");
        let challenge = board.challenge(0).expect("a challenge for principal 0");
        let sig = sig_hex(&signer.sign(&session_payload(board.signed(), &challenge.nonce, 0, Scope::Full)));
        let Opened::Token(zero) = board.session_open(SessionBody::Signed { principal: 0, nonce: &challenge.nonce, sig_hex: &sig, scope: Scope::Full }).expect("principal 0's session") else { panic!("principal 0's signed session was refused") };
        let account = board.next_account_prefix("1").expect("the frontier").expect("a free prefix");
        let Answer::Document(v) = board.op(Some(&zero), &frames::delegate(&account, principal, None)).expect("the delegate") else { panic!("closed") };
        assert_eq!(v["resp"].as_str(), Some("ack_addr"), "{v}");
        board.session_close(&zero).expect("close");
        let console = handshake(board, Scope::Full, &*signer, REGISTRAR, Site::Session).unwrap_or_else(|h| panic!("the registrar's session: {h}"));
        let genesis = Deposit { home: REGISTRAR_HOME, subject: &account, kind: DepositKind::EnrollVerbatim(payload), hand: Some(&*signer), id: &format!("genesis.{account}") };
        deposit(board, console.token(), &genesis).unwrap_or_else(|h| panic!("the genesis: {h}"));
        console.close().expect("close");
        Node { home: format!("{account}.0.1"), account, principal, store }
    }

    /// Runs `skep deposit` at `node` naming `origins`, with `extra` flags.
    fn deposit(&self, node: &Node, origins: &[&str], extra: &[&str]) -> Run {
        let mut args = vec!["deposit", "--board", &self.origin, "--dir", s(&node.store), "--account", &node.account];
        for origin in origins {
            args.extend(["--origin", origin]);
        }
        args.extend_from_slice(extra);
        skep(&args, &[], None)
    }

    /// Returns `node`'s endpoint deposits as a verifying mirror holds them.
    ///
    /// The mirror is opened afresh from the board's own root hint and read
    /// to the board's head: every deposit in the home, in journal order,
    /// and the one current. A record the mirror's gate kept out fails the
    /// read: every deposit here is signed.
    fn mirrored(&self, node: &Node) -> (Vec<Judged<EndpointRecord>>, Option<Judged<EndpointRecord>>) {
        let (hint, _) = root_hint(Arc::new(mirror_dialer()), self.board.dialed(), &[], None).unwrap_or_else(|h| panic!("the root hint: {h}"));
        let dir = tempfile::tempdir().expect("a directory");
        let mirror = Mirror::open(&hint, dir.path(), &mirror_dial()).unwrap_or_else(|e| panic!("the mirror: {e:?}"));
        assert!(mirror.index().suppressed().is_empty(), "the mirror's gate kept a record out: {:?}", mirror.index().suppressed());
        let home = address(&node.home);
        (mirror.index().endpoints(&home).to_vec(), mirror.index().current_endpoint(&home).cloned())
    }

    /// Returns the fingerprint of the one device key `store` holds.
    fn key_of(store: &Path) -> Fingerprint {
        let keys = FileStore::open(store).device_keys().expect("the store lists");
        let [key] = keys.as_slice() else { panic!("one device key: {keys:?}") };
        key.fingerprint
    }

    /// Returns the home's `doc_metadata`, read as a guest.
    fn metadata(&self, home: &str) -> Value {
        self.board.guest(&frames::doc_metadata(home)).expect("the metadata read")
    }

    fn head(&self) -> u64 {
        self.board.health().expect("health").log_position()
    }

    /// Opens `node`'s own content session, by its store's key.
    fn session_of<'b>(&'b self, node: &Node) -> (skep_client::ceremony::handshake::Session<'b>, Box<dyn Signer>) {
        let signer = FileStore::open(&node.store).signer(&KeySelector::Board { origin: self.board.dialed(), principal: Some(node.principal) }).expect("the node account's key");
        let session = handshake(&self.board, Scope::Content, &*signer, node.principal, Site::Session).unwrap_or_else(|h| panic!("the node account's session: {h}"));
        (session, signer)
    }
}

fn address(text: &str) -> Address {
    skep_resolve::parse_address(text).unwrap_or_else(|| panic!("{text} is an address"))
}

/// Returns the link a run of `skep deposit` printed, and the one it named.
///
/// The run passed: stdout is `endpoint <link>`, and under it `replaces
/// <link>` where the deposit names one, and nothing else.
fn deposited(r: &Run) -> (String, Option<String>) {
    assert_eq!(r.code, 0, "{r:?}");
    let lines = r.lines();
    let link = lines[0].strip_prefix("endpoint ").unwrap_or_else(|| panic!("`endpoint <link>`: {r:?}")).to_string();
    let replaces = lines.get(1).map(|line| line.strip_prefix("replaces ").unwrap_or_else(|| panic!("`replaces <link>`: {r:?}")).to_string());
    assert!(lines.len() <= 2, "two lines at most: {r:?}");
    (link, replaces)
}

/// Checks a refusal: its exit code and the words it is named by on stderr.
///
/// Its stdout holds nothing.
fn refused(r: &Run, code: i32, named: &str) {
    assert_eq!(r.code, code, "{r:?}");
    assert!(r.err.contains(named), "named {named:?}: {}", r.err);
    assert_eq!(r.out, "", "a refusal prints nothing on stdout: {r:?}");
}

/// A pin: the real `skep bind` at a node account runs its first signed session.
///
/// Nothing here is new: the cell holds `skep bind`, as built, to REG-1.51
/// at a node account on an ENFORCING board. The account's genesis is homed
/// in its minter's doc 1, so its own space is empty and its doc 1
/// unregistered; `bind`, answered `alone` — another hand wrote the first
/// set around this key alone — compares that genesis whole and then runs
/// the account's first signed session, which mints its doc 1, born
/// published and owned by the account, under an entry signature and never
/// a bare session. The binding line lands, so the store's lookup answers
/// the key with no `--principal`; a second `bind` finds nothing owed.
///
/// `skep deposit` then resumes at the deposit: the home stands published,
/// so nothing is minted, and the mirror reads the endpoint current.
#[test]
fn pin_the_real_skep_bind_at_a_node_account_mints_its_doc_1_from_its_own_first_signed_session() {
    let registry = Registry::open();
    let node = registry.node_account("node", 931);
    assert_eq!(document_present(&registry.board, &node.home), Ok(false), "the account's own space is empty at its first signed session");
    let before = registry.head();
    let bind = ["bind", "--board", &registry.origin, "--dir", s(&node.store), "--account", &node.account, "--principal", "931"];
    let r = skep(&bind, &[], Some(b"alone\n"));
    assert_eq!(r.code, 0, "{r:?}");
    assert_eq!(r.lines()[..3], [format!("account {}", node.account), "principal 931".to_string(), format!("origin {}", registry.origin)]);
    assert!(r.err.contains(&format!("the home {} is minted", node.home)), "{}", r.err);
    let metadata = registry.metadata(&node.home);
    assert_eq!((metadata["published"].as_bool(), metadata["owner"].as_str()), (Some(true), Some(node.account.as_str())), "born published, the account's own: {metadata}");
    let ChangesAnswer::Page(page) = registry.board.changes(None, &ChangesQuery { since: before, ..ChangesQuery::default() }).expect("the feed") else { panic!("a page") };
    let mint = page.changes.iter().find(|row| row["op"] == "create_new_document" && row["docs"].as_array().is_some_and(|docs| docs.contains(&json!(node.home)))).unwrap_or_else(|| panic!("the mint's row: {:?}", page.changes));
    assert!(mint.get("attest").is_some() && mint.get("key").is_none(), "the mint rode the account's own signed session: {mint}");
    let bound = std::fs::read_to_string(node.store.join("bindings")).expect("the bindings file");
    assert!(bound.lines().any(|line| line == format!("{} 931 {} {}", registry.origin, node.account, Registry::key_of(&node.store))), "the binding line: {bound}");
    let again = skep(&bind, &[], Some(b"alone\n"));
    assert_eq!(again.code, 0, "{again:?}");
    assert!(again.err.contains("nothing is owed at this account's first signed session"), "{}", again.err);

    // The deposit resumes: the home stands published, and nothing is minted.
    let r = registry.deposit(&node, &["https://acme.example"], &[]);
    let (link, replaces) = deposited(&r);
    assert!(replaces.is_none() && !r.err.contains("is minted"), "the home was read published, and the run resumed at the deposit: {}", r.err);
    let (all, current) = registry.mirrored(&node);
    assert_eq!(all.len(), 1);
    assert_eq!(current.map(|e| e.link.to_string()), Some(link));
}

/// Checks that `skep deposit` mints a missing home and deposits the endpoint.
///
/// The node account was never bound, so its doc 1 is unregistered and the
/// command's own mint is what makes it: the account's first signed session
/// mints its doc 1 published (REG-1.51, REG-1.52), then deposits the
/// endpoint (REG-1.9) — `--principal` omitted, the board's own seat at
/// `--account` standing in, and the key the store's one device key. The
/// run prints the deposit's address.
///
/// A verifying mirror of the board then reads that deposit current: the
/// origins in the order given, naming none, honored — and SIGNED, its `sig`
/// verified under the node account's own set as of the deposit's position,
/// by the key the node account's store holds and by no key of the registry's
/// (REG-4.120; REG-1.86 (e)). The client's own read of the home agrees.
///
/// The key is the store's own, and no other signs: a key that stands in no
/// set of the account — here the registry's own key, named by `--key` —
/// halts at the key's face before any session, and a principal that is not
/// the account's is refused; each writes nothing.
#[test]
fn deposit_mints_the_missing_home_published_and_a_verifying_mirror_reads_the_endpoint_current() {
    let registry = Registry::open();
    let node = registry.node_account("node", 931);
    assert_eq!(registry.metadata(&node.home)["code"].as_str(), Some("doc_not_registered"), "no home yet");
    let r = registry.deposit(&node, &["https://acme.example", "https://acme.example.net"], &[]);
    let (link, replaces) = deposited(&r);
    assert_eq!((link.as_str(), replaces), (format!("{}.0.2.1", node.home).as_str(), None), "the home's first link, naming none");
    assert!(r.err.contains(&format!("the home {} is minted, born published", node.home)), "{}", r.err);
    assert!(r.err.contains(&format!("acting as principal 931 at account {} with key {}", node.account, Registry::key_of(&node.store))), "{}", r.err);
    let metadata = registry.metadata(&node.home);
    assert_eq!((metadata["published"].as_bool(), metadata["owner"].as_str()), (Some(true), Some(node.account.as_str())), "{metadata}");

    let (all, current) = registry.mirrored(&node);
    let current = current.expect("the mirror reads an endpoint current");
    assert_eq!(all, std::slice::from_ref(&current), "the one deposit");
    assert_eq!(current.link.to_string(), link);
    assert_eq!(current.record, EndpointRecord { origins: vec!["https://acme.example".into(), "https://acme.example.net".into()], replaces: None, honored: true, nullified: false });
    assert_eq!(current.verdict, Verdict::Signed(Registry::key_of(&node.store)), "signed by the key the node account's store holds");
    assert_ne!(Registry::key_of(&node.store), Registry::key_of(&registry.registrar_store()), "and by no key of the registry's");
    let history = endpoint_history(&registry.board, None, &node.home).expect("the client's read, as a guest");
    assert_eq!(latest_stood(&history).map(|record| (record.link.as_str(), record.origins.len())), Some((link.as_str(), 2)));

    // A key of no set of the account, and a principal not its own.
    let (head, store) = (registry.head(), tree(&node.store));
    let registrar_key = FileStore::open(registry.registrar_store()).device_keys().expect("the registrar's store")[0].path.clone();
    let r = registry.deposit(&node, &["https://host.example"], &["--key", s(&registrar_key)]);
    refused(&r, 3, &format!("skep: this account's records do not list this key: {} is in neither list of the set at {}", Registry::key_of(&registry.registrar_store()), node.account));
    let r = registry.deposit(&node, &["https://host.example"], &["--principal", "1"]);
    refused(&r, 3, &format!("skep: principal 1 is not the principal seated at {}", node.account));
    assert_eq!((registry.head(), tree(&node.store)), (head, store), "neither wrote to the board or to the store");
    assert_eq!(registry.mirrored(&node).1.map(|e| e.link.to_string()), Some(link), "and the endpoint stands as it was");
}

/// Checks that a node account holds its mailbox after its first deposit.
///
/// The first `skep deposit` at a node account mints its missing home, and
/// the board creates the account's mailbox in that home's own commit (the
/// mailbox design §3), with no step of the binary's: before the deposit a
/// guest is answered `doc_not_registered` at the account's `.0.2`, as at
/// its `.0.1`; after it, `withheld`.
#[test]
fn deposit_node_account_holds_its_mailbox() {
    let registry = Registry::open();
    let node = registry.node_account("node", 932);
    let mailbox = skep_client::address::mailbox_of(&node.account);
    assert_eq!(registry.metadata(&mailbox)["code"].as_str(), Some("doc_not_registered"), "no home yet, and no mailbox");
    deposited(&registry.deposit(&node, &["https://acme.example"], &[]));
    assert_eq!(registry.metadata(&mailbox)["code"].as_str(), Some("withheld"), "the mailbox stands beside the home the deposit minted");
}

/// Checks that a later deposit names the one it replaces and erases nothing.
///
/// A second `skep deposit` names the first in `replaces` and becomes
/// current (REG-1.10); the first stays in the home, read as replaced.
///
/// What it names is the latest deposit that stood, read on the audit view,
/// and never merely the latest or the active one. A record naming none
/// where one stands — written here by the suite's own hand through the
/// library, as the node account — commits, and the mirror holds it inert;
/// the next `skep deposit` names the deposit before it, the latest that
/// stood, and is honored. Then the account's own `nullify` takes the
/// current deposit off the active view, the one before it standing current
/// again (REG-1.11); the next `skep deposit` names the nullified one — the
/// latest that stood — and is honored, where one naming the active answer
/// would be inert.
///
/// Nothing is erased: every deposit made stands in the home, in order.
#[test]
fn a_later_deposit_names_the_one_it_replaces_and_nothing_is_erased() {
    let registry = Registry::open();
    let node = registry.node_account("node", 931);
    let (first, _) = deposited(&registry.deposit(&node, &["https://acme.example"], &[]));
    let r = registry.deposit(&node, &["https://acme.example.net"], &[]);
    let (second, replaces) = deposited(&r);
    assert_eq!(replaces.as_deref(), Some(first.as_str()), "the later deposit names the first: {r:?}");
    assert!(r.err.contains(&format!("it names {first} as the deposit it replaces, which stays in the home")), "{}", r.err);
    let (all, current) = registry.mirrored(&node);
    assert_eq!(all.iter().map(|e| (e.link.to_string(), e.record.honored)).collect::<Vec<_>>(), [(first.clone(), true), (second.clone(), true)]);
    assert_eq!(all[0].record.origins, ["https://acme.example"], "the first stands in the home as it was written");
    assert_eq!(current.map(|e| (e.link.to_string(), e.record.replaces.map(|a| a.to_string()))), Some((second.clone(), Some(first.clone()))));

    // One naming none where one stands: committed, and inert at the reader.
    let (session, signer) = registry.session_of(&node);
    let origins = ["https://inert.example".to_string()];
    let inert = deposit_endpoint_naming(&registry.board, session.token(), &EndpointDeposit { home: &node.home, origins: &origins, hand: &*signer, id: "inert" }, None).unwrap_or_else(|h| panic!("{h}"));
    let (all, current) = registry.mirrored(&node);
    assert_eq!(all.last().map(|e| (e.link.to_string(), e.record.honored, e.verdict.admits())), Some((inert.link.clone(), false, true)), "signed, and inert");
    assert_eq!(current.map(|e| e.link.to_string()), Some(second.clone()), "the deposit before it stands current");
    let (fourth, replaces) = deposited(&registry.deposit(&node, &["https://acme.example.org"], &[]));
    assert_eq!(replaces.as_deref(), Some(second.as_str()), "the latest that stood, past the inert record");
    assert_eq!(registry.mirrored(&node).1.map(|e| e.link.to_string()), Some(fourth.clone()));

    // The account's own nullify: off the active view, and still what the
    // next deposit names.
    let (home, target) = (address(&node.home), address(&fourth));
    let (from, to, ty) = ([unit_span(&home)], [unit_span(&target)], [unit_span(&address(T_RETRACTION))]);
    let body = entry_body_nullify(LinkSlots { from: EntrySlot(&from), to: EntrySlot(&to), ty: EntrySlot(&ty) });
    let term = registry.board.board_term().expect("the term's read").expect("H.1 stands on a claimed board");
    let alg = signer.public_key().alg();
    let attest = json!({"alg": alg, "sig": sig_hex(&signer.sign(&entry_frame(alg, term, &address(&node.account), DocTerm::One(&home), &body)))});
    let Answer::Document(v) = session.op(&json!({"op": "nullify", "home": node.home, "target": fourth, "attest": attest})).expect("the nullify") else { panic!("closed") };
    assert_eq!(v["resp"].as_str(), Some("ack_addr"), "the account's own nullify of its endpoint lands: {v}");
    session.close().expect("close");
    assert_eq!(registry.mirrored(&node).1.map(|e| e.link.to_string()), Some(second.clone()), "the one before it stands current again");
    let (fifth, replaces) = deposited(&registry.deposit(&node, &["https://acme.example.com"], &[]));
    assert_eq!(replaces.as_deref(), Some(fourth.as_str()), "the nullified deposit is the latest that stood");
    let (all, current) = registry.mirrored(&node);
    assert_eq!(current.map(|e| e.link.to_string()), Some(fifth.clone()), "and the deposit naming it is honored");

    // Nothing is erased: every deposit stands in the home, in order.
    let stands: Vec<(String, bool, bool)> = all.iter().map(|e| (e.link.to_string(), e.record.honored, e.record.nullified)).collect();
    assert_eq!(stands, [(first, true, false), (second, true, false), (inert.link, false, false), (fourth, true, true), (fifth, true, false)]);
}

/// Checks each refusal of `skep deposit`: a named line, and nothing printed.
///
/// A line that names no account or no origin, or names one that does not
/// read, a second `--account` and a flag of another command's are exit 2,
/// before any socket opens — each names a board at a dead port, which a
/// run that dialed would meet as exit 4, and a store that is absent after.
/// A board that does not answer is exit 4. An address the board seats no
/// account at is a halt naming it, exit 3, and writes nothing.
#[test]
fn deposit_refuses_by_name_and_prints_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let absent = dir.path().join("no-store");
    let dead = "http://127.0.0.1:1";
    let rows: [(&[&str], &str); 8] = [
        (&["--origin", "https://acme.example"], "--account <address> is required: the node account the endpoint is deposited at"),
        (&["--account", "1.0.x", "--origin", "https://acme.example"], "--account: '1.0.x' is not an address (the wire's dotted spelling)"),
        (&["--account", "1.0.2"], "--origin <origin> is required: the origin your board answers at"),
        (&["--account", "1.0.2", "--origin", "acme.example"], "--origin: 'acme.example' is "),
        (&["--account", "1.0.2", "--origin", "https://acme.example", "--origin", "HTTPS://ACME.example/"], "--origin: 'HTTPS://ACME.example/' is "),
        (&["--account", "1.0.2", "--account", "1.0.3", "--origin", "https://acme.example"], "`--account` is given at most once at `deposit`"),
        (&["--account", "1.0.2", "--origin", "https://acme.example", "--also", "https://acme.example.net"], "`--also` is not a flag of `deposit`"),
        (&["--account", "1.0.2", "--origin", "https://acme.example", "--principal", "7x"], "--principal: '7x' is not a principal"),
    ];
    for (flags, named) in rows {
        let args: Vec<&str> = ["deposit", "--board", dead, "--dir", s(&absent)].into_iter().chain(flags.iter().copied()).collect();
        refused(&skep(&args, &[], None), 2, named);
    }
    assert!(!absent.exists(), "a line that does not read makes no directory");
    let r = skep(&["deposit", "--board", dead, "--dir", s(&absent), "--account", "1.0.2", "--origin", "https://acme.example"], &[], None);
    refused(&r, 4, "skep: transport: connect: ");

    let registry = Registry::open();
    let head = registry.head();
    let r = skep(&["deposit", "--board", &registry.origin, "--dir", s(&absent), "--account", "1.0.9", "--origin", "https://acme.example"], &[], None);
    refused(&r, 3, "skep: 1.0.9 is not an account on this board");
    assert!(r.err.contains("\n  act: check --account, and that --board (or SKEP_BOARD) names the board the account is on"), "a halt's face: {}", r.err);
    assert_eq!(registry.head(), head, "nothing was written");
}
