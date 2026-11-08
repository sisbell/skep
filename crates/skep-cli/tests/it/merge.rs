//! THE FOURTEENTH COMMAND through the binary (the merge record's §6, "The
//! CLI and the agent adapter"; `client.md` §2.1's thirteen stand beside
//! it): THE USAGE FORMS refused before any socket opens, exit 2 — no
//! `--doc`, two sides, `--base` outside `--draft`, `--publish` with
//! `--into`, `--new` with either, a malformed `--resolve`, no `--kind` and
//! no `SKEP_MERGE_KIND`, a value that is no address — while `--draft`
//! without `--base` is a whole form and the variable stands in for the
//! flag; THE WHOLE WALK on the real daemon —
//! a document seeded with a base version, a head and a daughter as the
//! library's own daemon walk seeds them, the merge composed and printed as
//! one JSON document with nothing else on stdout, then `--publish` landing
//! the next version whose image is the report's runs and whose record is
//! found from the daughter, the same `--publish` again landing nothing
//! twice with the prior named, a gap both sides added at reported
//! unsettled with its default and then `--resolve`d the other way round as
//! the AGENT's choice (the runner has no terminal), a resolution naming no
//! gap reported as not applied, `--into` landing the merged list in a
//! draft in one write with the newer version told, and `--new` staging a
//! fresh draft from the head and landing there, the base and the merge
//! recorded, a re-run reporting the standing landing and staging nothing;
//! A MOVED HEAD — the head moved before `--publish`, the shot claiming the
//! daughter superseded refused whole by the board, exit 1 with the head to
//! run again on and nothing published, and the re-run with `--retries 1`
//! landing on the new head with the count in its record and its claim
//! marking the daughter; and `--fork` ADMITTED — a
//! second account's fork of a published version merged from the source the
//! board serves for it and published — while a fork of the bare document,
//! taken before its first version, is refused with its own reason, exit 1,
//! nothing on stdout; and `--draft` WITHOUT `--base` — a draft `stage`
//! minted off the base version merged over the base the board records for
//! it, a `--base` that agrees taken, and one the board's record does not
//! derive refused by name, exit 1, nothing on stdout; and A STRANGER's
//! documents — a second top-level account's private draft and fork — each
//! `withheld` refusal saying beside the document what the run did, and the
//! draft named as the journal refused before the shot, exit 3, nothing
//! published; and A PUBLISHED JOURNAL — the trunk and the account's doc 1 —
//! said by the composition's talk before any landing flag is acted on, and
//! refused `published_target` in the command's words at `--publish`,
//! `--new` and `--undo`, exit 1, nothing written; and THE RECORD KEPT
//! PRIVATE — each record's link homed in the journal beside its atom, none
//! in doc 1, none a guest or a stranger finds; and THE NEWEST RECORD by
//! when its link was minted — an undo recorded in an older journal leaving
//! the key open, so `--new` stages a draft of its own.

use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use skep_address::Address;
use skep_client::address::parse_address;
use skep_client::board::{
    acked_addr, acked_at, frames, Answer, Board, ChangesAnswer, ChangesQuery, Opened, Scope,
    SessionBody, Token,
};
use skep_client::ceremony::claim::{self, ClaimOutcome, NotebookOptions};
use skep_client::ceremony::handshake::{handshake, Session, Site};
use skep_client::dial::PlainHttp;
use skep_client::person::scripted::{Script, Scripted};
use skep_client::sheet::Label;
use skep_client::sign::{sig_hex, Signer};
use skep_client::store::{FileStore, KeyStore};
use skep_client::Origin;
use skep_identity::{
    entry_body_empty, entry_body_publish, entry_frame, ContentFreeOp, DocTerm, EntryBody,
    Fingerprint, ShotBase, ShotSegmentPiece,
};
use skep_signature::HybridSigner;
use skepd::Skepd;

use crate::common::{origin, s, skep, spawn, Run};

/// The claimant's account and principal on a notebook.
const ACCOUNT: &str = "1.0.1";
const PRINCIPAL: u64 = 1;

/// THE FORKER: principal 2 at a sub-account delegated under the claimant's,
/// so the claimant — its ancestor — may read the forker's drafts (PUB-1.33).
/// `1.0.1.2`: the claim ceremony seats `1.0.1.1`.
const FORKER_ACCOUNT: &str = "1.0.1.2";
const FORKER: u64 = 2;

/// A port nothing listens at: a run that reaches it is exit 4, so a usage
/// refusal judged ahead of it is seen to open no socket.
const DEAD: &str = "http://127.0.0.1:1";

pub(crate) fn addr(text: &str) -> Address {
    parse_address(text).expect("an address")
}

/// A claimed board through the LIBRARY, as `ceremonies.rs` claims its (the
/// notebook arm is a person door the binary refuses without a terminal):
/// the store holds the device key, whose fingerprint is answered.
fn claim_board(board_origin: &str, store: &Path, anchors: &Path) -> Fingerprint {
    let board = Board::new(Origin::parse(board_origin).unwrap(), PlainHttp::new());
    let store = FileStore::open(store);
    let fp = store.generate(Some(Label::new("notebook").unwrap())).unwrap().0;
    let mut person = Scripted::new(vec![Script::LabelDefault, Script::LabelDefault]);
    let opts = NotebookOptions { principal: None, display_name: Some("a name".into()), anchor_out: vec![anchors.join("a"), anchors.join("b")], paper: false, host_name: "testhost".into(), date: "2026-10-15".into() };
    let ClaimOutcome::Ours(_) = claim::notebook(&board, &store, &mut person, &opts).unwrap_or_else(|h| panic!("{h}\n{}", person.transcript.join("\n"))) else { panic!("a stranger's board") };
    fp
}

/// One run of the binary's stdout read whole as ONE JSON document: exit 0,
/// one line, nothing beside it.
pub(crate) fn report(r: &Run) -> Value {
    assert_eq!(r.code, 0, "{r:?}");
    assert_eq!(r.out.lines().count(), 1, "one JSON document on one line, nothing else on stdout: {}", r.out);
    serde_json::from_str(&r.out).unwrap_or_else(|e| panic!("stdout is one JSON document: {e}\n{}", r.out))
}

/// The report's `runs` as `(i_start, width)`, the spelling `image` answers.
fn runs_of(report: &Value) -> Vec<(String, String)> {
    report["runs"].as_array().expect("runs").iter().map(|r| (r["i_start"].as_str().unwrap().to_string(), r["width"].as_str().unwrap().to_string())).collect()
}

/// One run of a shot as the test stages it: the document's own positions by
/// reference, or a staging draft's fresh text.
enum Staged<'a> {
    /// `text.len()` positions of the document's own I-space from ordinal
    /// `from`, whose bytes are `text`.
    Own { from: u64, text: &'a str },
    /// A draft minted and filled with `text`, re-inserted by the shot.
    Fresh { text: &'a str },
}

/// A claimed PERMISSIVE board (bare sessions mint the staging drafts), its
/// store, the device key's signer, a bare token, and the facts the shots
/// sign with — the restore suite's rig too (`restore.rs`).
pub(crate) struct Rig {
    _daemon: Skepd,
    pub(crate) origin: String,
    pub(crate) store: PathBuf,
    pub(crate) board: Board,
    pub(crate) device: HybridSigner,
    pub(crate) bare: Token,
}

impl Rig {
    pub(crate) fn new(dir: &Path) -> Rig {
        let daemon = spawn(&dir.join("board"), true);
        let origin = origin(daemon.port());
        let store = dir.join("store");
        let fp = claim_board(&origin, &store, &dir.join("anchors"));
        let board = Board::new(Origin::parse(&origin).unwrap(), PlainHttp::new());
        let file_store = FileStore::open(&store);
        let device = file_store.load(&file_store.key_path(&fp)).expect("the device key").signer();
        let bare = match board.session_open(SessionBody::Bare { principal: PRINCIPAL }).expect("a bare session") {
            Opened::Token(t) => t,
            other => panic!("the bare bind answered {other:?}"),
        };
        Rig { _daemon: daemon, origin, store, board, device, bare }
    }

    /// A content session under the device key, the seeding shots' hand.
    pub(crate) fn session(&self) -> Session<'_> {
        handshake(&self.board, Scope::Content, &self.device, PRINCIPAL, Site::Session).expect("a content session")
    }

    /// `skep merge --board … --dir …` with `extra`; `--principal` omitted,
    /// the store's one binding standing in for it.
    fn merge(&self, extra: &[&str]) -> Run {
        let mut args = vec!["merge", "--board", &self.origin, "--dir", s(&self.store)];
        args.extend_from_slice(extra);
        skep(&args, &[], None)
    }

    /// The `attest` member over `body` for a write whose `doc` row is `doc`,
    /// signed by the device key — the one composer, `entry_frame`.
    fn attest(&self, doc: &Address, body: &EntryBody) -> Value {
        let term = self.board.board_term().expect("the board term read").expect("H.1 stands on a claimed board");
        let alg = Signer::public_key(&self.device).alg();
        let frame = entry_frame(alg, term, &addr(ACCOUNT), DocTerm::One(doc), body);
        json!({"alg": alg, "sig": sig_hex(&Signer::sign(&self.device, &frame))})
    }

    /// A read's document under `token`, never a rejection.
    pub(crate) fn read(&self, token: &Token, frame: &Value) -> Value {
        let Answer::Document(v) = self.board.op(Some(token), frame).expect("the read") else { panic!("closed") };
        assert_ne!(v["resp"].as_str(), Some("rejected"), "{v}");
        v
    }

    /// An acked write's document.
    pub(crate) fn acked(answer: Result<Answer, skep_client::Halt>) -> Value {
        match answer.expect("the exchange") {
            Answer::Document(v) => {
                assert!(matches!(v["resp"].as_str(), Some("ack" | "ack_addr")), "the board refused: {v}");
                v
            }
            Answer::Closed => panic!("the session was closed"),
        }
    }

    /// `image` over content ordinals `1 ..= width` of `doc`, as `(i_start,
    /// width)`.
    pub(crate) fn image(&self, token: &Token, doc: &Address, width: u64) -> Vec<(String, String)> {
        let v = self.read(token, &frames::image(&doc.to_string(), 1, width));
        v["runs"].as_array().expect("runs").iter().map(|r| (r["i_start"].as_str().unwrap().to_string(), r["width"].as_str().unwrap().to_string())).collect()
    }

    /// A private draft minted into the account from the bare session.
    pub(crate) fn draft(&self) -> Address {
        let v = Rig::acked(self.board.op(Some(&self.bare), &json!({"op": "create_new_document", "account": ACCOUNT})));
        addr(acked_addr(&v).expect("a minted address"))
    }

    /// A private draft STAGED from `from` by the bare session — the board's
    /// `stage`, which copies `from` by identity and records the draft's base
    /// (wire.md §Namespace).
    fn stage(&self, from: &Address) -> Address {
        let v = Rig::acked(self.board.op(Some(&self.bare), &frames::stage(&from.to_string(), None)));
        addr(acked_addr(&v).expect("the staged draft's address"))
    }

    /// The forker's bare session: its account delegated from the claimant's
    /// full-scope session first.
    fn forker(&self) -> Token {
        let full = handshake(&self.board, Scope::Full, &self.device, PRINCIPAL, Site::Session)
            .expect("a full session");
        let v = Rig::acked(full.op(&frames::delegate(FORKER_ACCOUNT, FORKER, None)));
        assert_eq!(acked_addr(&v), Some(FORKER_ACCOUNT), "the forker's account: {v}");
        full.close().expect("closed");
        let token = match self.board.session_open(SessionBody::Bare { principal: FORKER }).expect("a bare session") {
            Opened::Token(t) => t,
            other => panic!("the bare bind answered {other:?}"),
        };
        // Its home first: a mint into an account without one is `mint_home_first`.
        let v = Rig::acked(self.board.op(Some(&token), &json!({"op": "create_new_document", "account": FORKER_ACCOUNT})));
        assert_eq!(acked_addr(&v), Some(format!("{FORKER_ACCOUNT}.0.1").as_str()), "the forker's home: {v}");
        token
    }

    /// A STRANGER: a second top-level account delegated as the dev seed
    /// delegates one — the node's bare session delegating the next prefix
    /// under `1` to a free principal — answered with its prefix and its bare
    /// session, which has minted its home. The claimant may read none of its
    /// documents, nor it the claimant's: an account's subtree runs above and
    /// beneath it, never beside it (wire.md §The read predicate).
    fn stranger_account(&self) -> (String, Token) {
        let bare = |principal: u64| match self.board.session_open(SessionBody::Bare { principal }).expect("a bare session") {
            Opened::Token(t) => t,
            other => panic!("principal {principal}'s bare bind answered {other:?}"),
        };
        let prefix = self.board.next_account_prefix("1").expect("the read").expect("a top-level prefix");
        let mut principal = FORKER + 1;
        while self.board.principal_prefix(principal).expect("the read").is_some() {
            principal += 1;
        }
        let v = Rig::acked(self.board.op(Some(&bare(0)), &frames::delegate(&prefix, principal, None)));
        assert_eq!(acked_addr(&v), Some(prefix.as_str()), "the stranger's account: {v}");
        let token = bare(principal);
        let home = Rig::acked(self.board.op(Some(&token), &json!({"op": "create_new_document", "account": prefix})));
        assert_eq!(acked_addr(&home), Some(format!("{prefix}.0.1").as_str()), "the stranger's home first");
        (prefix, token)
    }

    /// A STRANGER's private draft and private fork of `source`, minted by
    /// its bare session ([`Rig::stranger_account`]).
    fn stranger(&self, source: &Address) -> (Address, Address) {
        let (prefix, token) = self.stranger_account();
        let draft = addr(acked_addr(&Rig::acked(self.board.op(Some(&token), &json!({"op": "create_new_document", "account": prefix})))).expect("a minted address"));
        (draft, self.fork(&token, source))
    }

    /// A private cross-owner fork of `source` by `forker`: the fresh document
    /// of the forker's account, born sharing `source`.
    fn fork(&self, forker: &Token, source: &Address) -> Address {
        let frame = json!({"op": "version", "d_src": source.to_string(), "published": false});
        addr(acked_addr(&Rig::acked(self.board.op(Some(forker), &frame))).expect("the fork's address"))
    }

    /// A published document minted into the account from `session`, attested.
    fn document(&self, session: &Session<'_>) -> Address {
        let account = addr(ACCOUNT);
        let mut frame = json!({"op": "create_new_document", "account": ACCOUNT, "published": true});
        frame["attest"] = self.attest(&account, &entry_body_empty(ContentFreeOp::CreateNewDocument));
        addr(acked_addr(&Rig::acked(session.op(&frame))).expect("a minted address"))
    }

    /// THE SHOT by hand, as the library's daemon walk composes it: `staged`
    /// in V-order, each own run by reference and each fresh run through a
    /// staging draft, the body the values one per position with the base
    /// group, attested; the member minted.
    fn shot(&self, session: &Session<'_>, doc: &Address, base: Option<(&Address, u64)>, staged: &[Staged<'_>]) -> Address {
        let mut runs = Vec::new();
        let mut values: Vec<u8> = Vec::new();
        let mut draft: Option<Address> = None;
        for stage in staged {
            match stage {
                Staged::Own { from, text } => {
                    runs.push(frames::shot_run(&doc.to_string(), &format!("{doc}.0.1.{from}"), text.len() as u64));
                    values.extend_from_slice(text.as_bytes());
                }
                Staged::Fresh { text } => {
                    let d = self.draft();
                    let as_of = self.board.health().unwrap().log_position();
                    let insert = json!({"op": "insert", "doc": d.to_string(), "at": {"subspace": "1", "ordinal": "1"}, "values": [text], "as_of": as_of});
                    acked_at(&Rig::acked(self.board.op(Some(&self.bare), &insert))).expect("the insert's position");
                    let image = self.image(&self.bare, &d, text.len() as u64);
                    assert_eq!(image.len(), 1, "one burst at one caret is one run: {image:?}");
                    runs.push(frames::shot_run(&d.to_string(), &image[0].0, image[0].1.parse().unwrap()));
                    values.extend_from_slice(text.as_bytes());
                    assert!(draft.is_none(), "one staging draft a shot");
                    draft = Some(d);
                }
            }
        }
        let pieces: Vec<[u8; 1]> = values.iter().map(|b| [*b]).collect();
        let body = entry_body_publish(pieces.iter().map(|b| ShotSegmentPiece::Value(b)), base.map(|(member, extent)| ShotBase { member, extent }));
        let base_text = base.map(|(m, e)| (m.to_string(), e));
        let draft_text = draft.as_ref().map(ToString::to_string);
        let doc_text = doc.to_string();
        let mut frame = frames::publication(&frames::PublishFrame { doc: Some(&doc_text), base: base_text.as_ref().map(|(m, e)| (m.as_str(), *e)), draft: draft_text.as_deref(), runs: &runs, ..frames::PublishFrame::default() });
        frame["attest"] = self.attest(doc, &body);
        addr(acked_addr(&Rig::acked(session.op(&frame))).expect("the member's address"))
    }

    /// THE RACE SHAPE over a fresh document (the merge record's §9): the base
    /// `D.1` "the cat sat", the head `D.2` adding "big " at `D·4|D·5` (fresh
    /// at `D·12`), and the daughter `D.1.1` removing " sat" — answered as
    /// `(D, base, head, daughter)`.
    fn race(&self, session: &Session<'_>) -> (Address, Address, Address, Address) {
        let d = self.document(session);
        let base = self.shot(session, &d, None, &[Staged::Fresh { text: "the cat sat" }]);
        assert_eq!(base.to_string(), format!("{d}.1"), "the birth version");
        let head = self.shot(session, &d, Some((&base, 11)), &[Staged::Own { from: 1, text: "the " }, Staged::Fresh { text: "big " }, Staged::Own { from: 5, text: "cat sat" }]);
        assert_eq!(head.to_string(), format!("{d}.2"), "the trunk's next member");
        let daughter = self.shot(session, &d, Some((&base, 11)), &[Staged::Own { from: 1, text: "the cat" }]);
        assert_eq!(daughter.to_string(), format!("{d}.1.1"), "a base the trunk has moved past yields the base's own DAUGHTER");
        (d, base, head, daughter)
    }

    /// The `publish` rows under `doc` on the feed, from its floor.
    fn publishes_under(&self, token: &Token, doc: &Address) -> usize {
        let under = doc.to_string();
        let (mut since, mut count) = (0u64, 0usize);
        loop {
            let query = ChangesQuery { since, under: Some(&under), drafts: false, limit: None };
            match self.board.changes(Some(token), &query).expect("the feed") {
                ChangesAnswer::Page(page) => {
                    count += page.changes.iter().filter(|row| row["op"].as_str() == Some("publish")).count();
                    if !page.more {
                        return count;
                    }
                    since = page.last;
                }
                other => panic!("the feed answered {other:?}"),
            }
        }
    }
}

/// THE USAGE FORMS are judged whole before any socket opens (§2.3's exit 2;
/// the fence): each refusal names what is wrong with the help beneath it,
/// stdout empty, against a dead port — `--draft` without `--base` is a
/// whole form, the base the board's to serve, and reaches the dead board —
/// and `SKEP_MERGE_KIND` stands in for `--kind`, so that line is no usage
/// refusal and reaches the dead board.
#[test]
fn the_usage_forms_are_refused_before_any_socket() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("store");
    let (doc, alt, draft, base, kind) = ("1.0.1.0.2", "1.0.1.0.2.1.1", "1.0.1.0.4", "1.0.1.0.2.1", "1.0.1.0.3");
    let refused = |extra: &[&str], words: &str| {
        let mut args = vec!["merge", "--board", DEAD, "--dir", s(&store)];
        args.extend_from_slice(extra);
        let r = skep(&args, &[], None);
        assert_eq!(r.code, 2, "{extra:?}: {r:?}");
        assert!(r.err.contains(words), "{extra:?}: {}", r.err);
        assert!(r.err.contains("\n\nusage: skep <command> [flags]\n"), "the help beneath the refusal: {}", r.err);
        assert!(r.out.is_empty(), "{extra:?}: {}", r.out);
    };
    refused(&["--alternative", alt, "--kind", kind], "--doc <D> is required");
    refused(&["--doc", doc, "--kind", kind], "one side is required: --alternative <D.k.m>, --draft <S> [--base <D.k>], or --fork <F>");
    refused(&["--doc", doc, "--alternative", alt, "--draft", draft, "--base", base, "--kind", kind], "`--alternative` and `--draft` belong to two forms of `merge`: give one");
    refused(&["--doc", doc, "--alternative", alt, "--fork", draft, "--kind", kind], "`--alternative` and `--fork` belong to two forms of `merge`: give one");
    refused(&["--doc", doc, "--alternative", alt, "--base", base, "--kind", kind], "`--base` belongs to `merge --draft` and is refused without `--draft`");
    refused(&["--doc", doc, "--alternative", alt, "--kind", kind, "--publish", "--into", draft], "`--publish` and `--into` belong to two forms of `merge`: give one");
    refused(&["--doc", doc, "--alternative", alt, "--kind", kind, "--publish", "--new"], "`--publish` and `--new` belong to two forms of `merge`: give one");
    refused(&["--doc", doc, "--alternative", alt, "--kind", kind, "--into", draft, "--new"], "`--into` and `--new` belong to two forms of `merge`: give one");
    refused(&["--doc", doc, "--alternative", alt, "--kind", kind, "--resolve", "1=frob"], "--resolve: '1=frob' is not <gap>=<choice>");
    refused(&["--doc", doc, "--alternative", alt, "--kind", kind, "--resolve", "both"], "--resolve: 'both' is not <gap>=<choice>");
    refused(&["--doc", doc, "--alternative", alt, "--kind", kind, "--resolve", "0=omit"], "--resolve: '0=omit' is not <gap>=<choice>");
    refused(&["--doc", doc, "--alternative", alt, "--kind", kind, "--resolve", "1=order:"], "--resolve: '1=order:' is not <gap>=<choice>");
    refused(&["--doc", doc, "--alternative", alt, "--kind", kind, "--resolve", "1=after:x"], "--resolve: '1=after:x' is not <gap>=<choice>");
    refused(&["--doc", doc, "--alternative", alt], "--kind <address> (or SKEP_MERGE_KIND) is required");
    refused(&["--doc", "not-an-address", "--alternative", alt, "--kind", kind], "--doc: 'not-an-address' is not an address");
    refused(&["--doc", doc, "--alternative", alt, "--kind", kind, "--retries", "x"], "--retries: 'x' is not a count");
    // THE TWO TAKE-BACKS (skep #783): each apart from the other, from every
    // side, `--doc`, `--head`, and the three landings; `--base` outside
    // `--draft` is refused as before; each needs `--kind` and an address.
    refused(&["--undo", draft, "--withdraw", draft, "--kind", kind], "`--undo` and `--withdraw` belong to two forms of `merge`: give one");
    for (flag, other) in [("--undo", "--doc"), ("--undo", "--alternative"), ("--undo", "--draft"), ("--undo", "--fork"), ("--undo", "--head"), ("--undo", "--into"), ("--withdraw", "--doc"), ("--withdraw", "--alternative"), ("--withdraw", "--draft"), ("--withdraw", "--fork"), ("--withdraw", "--head"), ("--withdraw", "--into")] {
        refused(&[flag, draft, other, alt, "--kind", kind], &format!("`{flag}` and `{other}` belong to two forms of `merge`: give one"));
    }
    for (flag, landing) in [("--undo", "--publish"), ("--undo", "--new"), ("--withdraw", "--publish"), ("--withdraw", "--new")] {
        refused(&[flag, draft, landing, "--kind", kind], &format!("`{flag}` and `{landing}` belong to two forms of `merge`: give one"));
    }
    refused(&["--undo", draft, "--base", base, "--kind", kind], "`--base` belongs to `merge --draft` and is refused without `--draft`");
    refused(&["--withdraw", draft, "--base", base, "--kind", kind], "`--base` belongs to `merge --draft` and is refused without `--draft`");
    refused(&["--undo", draft], "--kind <address> (or SKEP_MERGE_KIND) is required");
    refused(&["--withdraw", draft], "--kind <address> (or SKEP_MERGE_KIND) is required");
    refused(&["--undo", "not-an-address", "--kind", kind], "--undo: 'not-an-address' is not an address");
    refused(&["--withdraw", "not-an-address", "--kind", kind], "--withdraw: 'not-an-address' is not an address");
    // Every whole form reaches the dead board — `--draft` with and without
    // `--base`, the base being the board's to serve, each landing alone,
    // and each take-back with `--kind` alone or with `--journal`.
    for form in [&["--doc", doc, "--alternative", alt, "--kind", kind][..], &["--doc", doc, "--draft", draft, "--base", base, "--kind", kind], &["--doc", doc, "--draft", draft, "--kind", kind], &["--doc", doc, "--fork", draft, "--kind", kind], &["--doc", doc, "--alternative", alt, "--kind", kind, "--new"], &["--doc", doc, "--alternative", alt, "--kind", kind, "--into", draft], &["--undo", draft, "--kind", kind], &["--withdraw", draft, "--kind", kind], &["--undo", draft, "--kind", kind, "--journal", kind]] {
        let mut args = vec!["merge", "--board", DEAD, "--dir", s(&store), "--principal", "1"];
        args.extend_from_slice(form);
        let r = skep(&args, &[], None);
        assert_eq!(r.code, 4, "a whole form reaches the dead board: {form:?}: {r:?}");
    }
    let r = skep(&["merge", "--board", DEAD, "--dir", s(&store), "--principal", "1", "--doc", doc, "--alternative", alt], &[("SKEP_MERGE_KIND", kind)], None);
    assert_eq!(r.code, 4, "the variable stands in for the flag, and the run reaches the dead board: {r:?}");
    assert!(!store.exists(), "nothing written");
}

/// THE WHOLE WALK: composed and printed, published once with its record,
/// published again without landing twice, a gap both sides added at
/// resolved as the agent's choice, a resolution naming no gap not applied,
/// and the merged list landed in a draft.
#[test]
fn the_whole_walk_composes_prints_publishes_once_and_resolves_a_gap_as_the_agent() {
    let dir = tempfile::tempdir().unwrap();
    let rig = Rig::new(dir.path());
    let session = rig.session();
    let token = session.token().clone();
    let kind = rig.draft();
    let kind_s = kind.to_string();
    let (d, base, head, daughter) = rig.race(&session);
    let (d_s, daughter_s, head_s) = (d.to_string(), daughter.to_string(), head.to_string());
    let position = || rig.board.health().unwrap().log_position();

    // COMPOSE AND PRINT, no landing flag: the head off the feed walk, the
    // report one JSON document, nothing written.
    let before = position();
    let r = rig.merge(&["--doc", &d_s, "--alternative", &daughter_s, "--kind", &kind_s]);
    let v = report(&r);
    assert_eq!(v["doc"].as_str(), Some(d_s.as_str()));
    assert_eq!(v["head"].as_str(), Some(head_s.as_str()), "the head off the feed walk");
    assert_eq!(v["base"].as_str(), Some(base.to_string().as_str()), "the base derived along the anchor chains");
    assert_eq!(runs_of(&v), vec![(format!("{d}.0.1.1"), "4".into()), (format!("{d}.0.1.12"), "4".into()), (format!("{d}.0.1.5"), "3".into())], "the big cat");
    assert_eq!(v["runs"][1]["side"], json!(0), "the head's fresh run carries its side");
    assert_eq!(v["runs"][1]["family"], json!("own"));
    assert_eq!(v["gaps"], json!([]), "different material on each side: no gap");
    assert_eq!(v["counts"], json!({"a": 3, "b": 1, "m": 3}));
    assert_eq!((v["over_cap"].as_bool(), v["cap"].as_u64()), (Some(false), Some(4096)));
    assert!(v["prior"].is_null() && v["landed"].is_null(), "{v}");
    assert_eq!(v["record"]["type"].as_str(), Some("merge"));
    assert!(v["record"]["landed"].is_null(), "the record unlanded: {}", v["record"]);
    assert_eq!(v["sides"], json!([{"at": head_s, "role": "head"}, {"at": daughter_s, "role": "alternative"}]));
    assert_eq!(position(), before, "composing writes nothing");
    assert!(r.err.contains(&format!("merging the alternative {daughter} with {head}, the head of {d}, at {}", rig.origin)), "the entry line: {}", r.err);
    assert!(r.err.contains(&format!("composed over the base {base}: 3 runs from the head's 3 and the side's 1, 0 gaps")), "{}", r.err);
    assert!(!r.err.contains("need a choice") && !r.err.contains("needs a choice"), "{}", r.err);

    // PUBLISH: the next version, whose image is the report's runs; the
    // record found from the daughter by the link of the kind.
    let r = rig.merge(&["--doc", &d_s, "--alternative", &daughter_s, "--kind", &kind_s, "--publish"]);
    let v = report(&r);
    let member = v["landed"]["member"].as_str().expect("the member").to_string();
    assert_eq!(member, format!("{d}.3"), "the trunk's next member");
    assert_eq!(v["landed"]["retries"], json!(0));
    let claims = v["landed"]["claims"].as_array().expect("the shot's claims").clone();
    assert_eq!(claims.len(), 1, "the shot's own claim marking the daughter superseded: {}", v["landed"]);
    assert!(claims[0].as_str().is_some_and(|c| c.starts_with(&format!("{d}.0.2."))), "homed in the trunk: {}", claims[0]);
    assert_eq!(rig.read(&token, &frames::in_claims(&daughter_s))["claims"][0]["new"].as_str(), Some(member.as_str()), "in_claims at the daughter answers the member");
    assert!(r.err.contains("the claim marking the side superseded by it: 1"), "{}", r.err);
    let link = v["landed"]["record"].as_str().expect("the record's link").to_string();
    assert!(v["landed"]["position"].as_u64().is_some_and(|p| p > before), "{}", v["landed"]);
    assert_eq!(rig.image(&token, &addr(&member), 11), runs_of(&v), "the member's image over its placed positions is M");
    let found = rig.read(&token, &frames::find_links_ftt(&kind_s, &daughter_s));
    assert_eq!(found["addrs"], json!([link]), "the record is found FROM the daughter by the kind");
    assert!(r.err.contains(&format!("published {member} at position")), "{}", r.err);
    assert!(r.err.contains(&format!("the record's link is {link}")), "{}", r.err);

    // THE SAME PUBLISH AGAIN, the head named (the feed's head is now the
    // merge): the prior record named, the same landing read back, nothing
    // landed twice.
    let before = position();
    let publishes = rig.publishes_under(&token, &d);
    let r = rig.merge(&["--doc", &d_s, "--alternative", &daughter_s, "--kind", &kind_s, "--head", &head_s, "--publish"]);
    let v = report(&r);
    assert_eq!(v["landed"]["member"].as_str(), Some(member.as_str()));
    assert_eq!(v["landed"]["record"].as_str(), Some(link.as_str()));
    assert_eq!(v["prior"]["link"].as_str(), Some(link.as_str()), "the standing record: {}", v["prior"]);
    assert_eq!(v["prior"]["landed"]["member"].as_str(), Some(member.as_str()));
    assert_eq!(v["prior"]["key"]["sides"], json!([daughter_s, head_s]), "the key's sides in address order");
    assert_eq!(v["record"]["replaces"].as_str(), Some(link.as_str()), "a later record names what it replaces");
    assert_eq!(position(), before, "nothing landed twice");
    assert_eq!(rig.publishes_under(&token, &d), publishes, "no second publish");

    // --INTO a draft, against the head the merge was composed from: the
    // merged list landed by identity IN ONE WRITE, the draft's image M, the
    // report without an edit count; the draft is baseless, so nothing is
    // recorded on it (N4); the trunk's head is the merge, so the newer
    // version is told.
    let into = rig.draft();
    let r = rig.merge(&["--doc", &d_s, "--alternative", &daughter_s, "--kind", &kind_s, "--head", &head_s, "--into", &into.to_string()]);
    let v = report(&r);
    assert_eq!(v["landed"]["draft"].as_str(), Some(into.to_string().as_str()));
    assert!(v["landed"].get("ops").is_none(), "no edit count: the landing is one write: {}", v["landed"]);
    assert!(v["landed"]["position"].as_u64().is_some_and(|p| p > before), "the write's position: {}", v["landed"]);
    assert!(v["landed"]["record"].as_str().is_some());
    assert_eq!(v["landed"]["fresh"], json!(false));
    assert_eq!(v["landed"]["head_moved"].as_str(), Some(member.as_str()), "composed on {head}, the trunk's head is the merge: told: {}", v["landed"]);
    assert_eq!(rig.image(&token, &into, 11), runs_of(&v), "the draft holds M");
    let meta = rig.read(&token, &frames::doc_metadata(&into.to_string()));
    assert!(meta["base"].is_null() && meta["merge"].is_null(), "a baseless draft: no base, no marker: {meta}");
    assert!(r.err.contains(&format!("landed in the draft {into} at position")), "{}", r.err);
    assert!(!r.err.contains("fresh draft"), "{}", r.err);
    assert!(r.err.contains(&format!("a newer version of {d} was published since this merge was composed: {member}")), "{}", r.err);
    assert!(r.err.contains(&format!("merge again to include {member}")), "{}", r.err);

    // A GAP BOTH SIDES ADDED AT (§9's case (b)): the head "big " and the
    // daughter "fat " at `D·4|D·5` — an `order` gap, unsettled, the commit
    // order its default; one place needs a choice.
    let d2 = rig.document(&session);
    let base2 = rig.shot(&session, &d2, None, &[Staged::Fresh { text: "the cat sat" }]);
    let head2 = rig.shot(&session, &d2, Some((&base2, 11)), &[Staged::Own { from: 1, text: "the " }, Staged::Fresh { text: "big " }, Staged::Own { from: 5, text: "cat sat" }]);
    let daughter2 = rig.shot(&session, &d2, Some((&base2, 11)), &[Staged::Own { from: 1, text: "the " }, Staged::Fresh { text: "fat " }, Staged::Own { from: 5, text: "cat sat" }]);
    assert_eq!((head2.to_string(), daughter2.to_string()), (format!("{d2}.2"), format!("{d2}.1.1")));
    let (d2_s, daughter2_s) = (d2.to_string(), daughter2.to_string());
    let r = rig.merge(&["--doc", &d2_s, "--alternative", &daughter2_s, "--kind", &kind_s]);
    let v = report(&r);
    assert_eq!(runs_of(&v), vec![(format!("{d2}.0.1.1"), "4".into()), (format!("{d2}.0.1.12"), "8".into()), (format!("{d2}.0.1.5"), "7".into())], "the big fat cat sat: the two fresh runs coalesce");
    let gaps = v["gaps"].as_array().expect("gaps");
    assert_eq!(gaps.len(), 1, "{gaps:?}");
    let gap = &gaps[0];
    assert_eq!((gap["id"].as_u64(), gap["kind"].as_str(), gap["settled"].as_bool()), (Some(1), Some("order"), Some(false)));
    assert!(gap["resolved_by"].is_null(), "{gap}");
    assert_eq!(gap["placed"], json!([0, 1]), "the commit order, the head's group first");
    assert_eq!(gap["default"].as_str(), Some("order:0,1"), "the default in --resolve's spelling");
    assert_eq!((gap["after"].as_str(), gap["before"].as_str()), (Some(format!("{d2}.0.1.4").as_str()), Some(format!("{d2}.0.1.5").as_str())));
    assert_eq!(gap["runs"].as_array().map(Vec::len), Some(2));
    assert!(r.err.contains("1 place needs a choice: gap 1 (order, default order:0,1)"), "{}", r.err);
    assert!(r.err.contains("--resolve <gap>=<choice>"), "{}", r.err);

    // RESOLVED the other way round and published: the merger is the AGENT
    // under the runner, where stdin and stderr are no terminal.
    let r = rig.merge(&["--doc", &d2_s, "--alternative", &daughter2_s, "--kind", &kind_s, "--resolve", "1=order:1,0", "--publish"]);
    let v = report(&r);
    let expected = vec![(format!("{d2}.0.1.1"), "4".into()), (format!("{d2}.0.1.16"), "4".into()), (format!("{d2}.0.1.12"), "4".into()), (format!("{d2}.0.1.5"), "7".into())];
    assert_eq!(runs_of(&v), expected, "the fat big cat sat");
    assert_eq!(v["counts"], json!({"a": 3, "b": 3, "m": 4}));
    let gap = &v["gaps"][0];
    assert_eq!((gap["placed"].clone(), gap["settled"].as_bool(), gap["resolved_by"].as_str()), (json!([1, 0]), Some(true), Some("agent")));
    assert_eq!(gap["default"].as_str(), Some("order:1,0"), "the placement as this run composed it");
    assert_eq!(v["record"]["gaps"][0]["resolved_by"].as_str(), Some("agent"), "the record keeps who the merger was");
    assert_eq!(v["ignored"], json!([]));
    let member2 = v["landed"]["member"].as_str().expect("the member");
    assert_eq!(member2, format!("{d2}.3"));
    assert_eq!(rig.image(&token, &addr(member2), 19), expected, "the member holds the resolved order");
    assert!(!r.err.contains("need a choice") && !r.err.contains("needs a choice"), "resolved, no place needs a choice: {}", r.err);

    // A RESOLUTION NAMING NO GAP is reported and not applied.
    let r = rig.merge(&["--doc", &d2_s, "--alternative", &daughter2_s, "--kind", &kind_s, "--head", &head2.to_string(), "--resolve", "9=both"]);
    let v = report(&r);
    assert_eq!(v["ignored"], json!([9]));
    assert!(r.err.contains("not applied: the resolution of gap 9"), "{}", r.err);
    assert_eq!(v["prior"]["landed"]["member"].as_str(), Some(member2), "the prior for the key stands");

    // --NEW: a fresh draft staged from the head the merge composed on and
    // the merged list landed in it in one write — the base re-recorded on
    // that head, the merge marked beside it with the daughter as its side,
    // the newer version (the merge published above) told. The key's
    // standing record names a member landing, so a draft is staged.
    let (head2_s, member2_s) = (head2.to_string(), member2.to_string());
    let r = rig.merge(&["--doc", &d2_s, "--alternative", &daughter2_s, "--kind", &kind_s, "--head", &head2_s, "--new"]);
    let v = report(&r);
    let fresh = addr(v["landed"]["draft"].as_str().expect("the fresh draft"));
    assert_eq!(v["landed"]["fresh"], json!(true), "{}", v["landed"]);
    assert!(v["landed"].get("ops").is_none());
    let at = v["landed"]["position"].as_u64().expect("the write's position");
    assert_eq!(v["landed"]["head_moved"].as_str(), Some(member2_s.as_str()), "the newer version told: {}", v["landed"]);
    assert!(v["landed"]["record"].as_str().is_some());
    assert_eq!(rig.image(&token, &fresh, 19), runs_of(&v), "the fresh draft holds M");
    let meta = rig.read(&token, &frames::doc_metadata(&fresh.to_string()));
    assert_eq!((meta["base"].as_str(), meta["base_copied"].as_str(), meta["source"].as_str()), (Some(head2_s.as_str()), Some("15"), Some(head2_s.as_str())), "staged from the head, the base re-recorded on it: {meta}");
    assert_eq!(meta["merge"], json!({"at": at, "head": head2_s, "head_copied": "15", "sides": [daughter2_s]}), "the merge recorded: {meta}");
    assert!(r.err.contains(&format!("landed in the draft {fresh} at position {at}, a fresh draft staged from {head2}")), "{}", r.err);
    assert!(r.err.contains(&format!("a newer version of {d2} was published since this merge was composed: {member2}")), "{}", r.err);
    // Run again: the standing record for the key names the landing, which
    // is reported — nothing staged, nothing written.
    let before = position();
    let r = rig.merge(&["--doc", &d2_s, "--alternative", &daughter2_s, "--kind", &kind_s, "--head", &head2_s, "--new"]);
    let v = report(&r);
    assert_eq!(v["landed"]["draft"].as_str(), Some(fresh.to_string().as_str()), "the standing landing: {}", v["landed"]);
    assert_eq!((v["landed"]["fresh"].clone(), v["landed"]["position"].as_u64(), v["landed"]["head_moved"].is_null()), (json!(false), Some(at), true), "{}", v["landed"]);
    assert_eq!(position(), before, "nothing staged, nothing written");
    assert!(r.err.contains(&format!("landed in the draft {fresh} at position {at};")), "{}", r.err);
    assert!(!r.err.contains("fresh draft"), "{}", r.err);
    session.close().expect("close");
}

/// A MOVED HEAD IS REFUSED, NEVER RETRIED (decision 17; the merge bridge
/// lane, skep #806): the head moves between the composition and
/// `--publish`; the shot, claiming the daughter superseded, is refused whole
/// by the board — exit 1 under `supersede_refused`, the words saying the
/// head moved, that nothing was published and to run again against the new
/// head — nothing on stdout, no publish in the feed, no claim at the
/// daughter; and the re-run with `--retries 1` lands on the new head with
/// the count in its record and its claim marking the daughter.
#[test]
fn a_moved_head_is_refused_with_the_head_to_run_again_on_and_never_retried() {
    let dir = tempfile::tempdir().unwrap();
    let rig = Rig::new(dir.path());
    let session = rig.session();
    let token = session.token().clone();
    let kind = rig.draft().to_string();
    let (d, _base, head, daughter) = rig.race(&session);
    let (d_s, daughter_s, head_s) = (d.to_string(), daughter.to_string(), head.to_string());
    // Composed and printed against the head as it stands.
    let v = report(&rig.merge(&["--doc", &d_s, "--alternative", &daughter_s, "--kind", &kind]));
    assert_eq!(v["head"].as_str(), Some(head_s.as_str()));
    assert!(v["landed"].is_null());
    // THE HEAD MOVES: a third shot off it, "new " before "big " — "the new
    // big cat sat", the fresh word at `D·16`.
    let third = rig.shot(&session, &d, Some((&head, 15)), &[Staged::Own { from: 1, text: "the " }, Staged::Fresh { text: "new " }, Staged::Own { from: 12, text: "big " }, Staged::Own { from: 5, text: "cat sat" }]);
    assert_eq!(third.to_string(), format!("{d}.3"));
    assert_eq!(rig.image(&token, &third, 19), vec![(format!("{d}.0.1.1"), "4".into()), (format!("{d}.0.1.16"), "4".into()), (format!("{d}.0.1.12"), "4".into()), (format!("{d}.0.1.5"), "7".into())]);
    let publishes = rig.publishes_under(&token, &d);
    let before = rig.board.health().unwrap().log_position();
    // --PUBLISH against the head the merge was composed from: refused whole.
    let r = rig.merge(&["--doc", &d_s, "--alternative", &daughter_s, "--kind", &kind, "--head", &head_s, "--publish"]);
    assert_eq!(r.code, 1, "{r:?}");
    assert!(r.out.is_empty(), "nothing on stdout: {}", r.out);
    assert!(r.err.contains(&format!("the board refused: supersede_refused:the head moved under the merge: the trunk's head is now {d}.3, so the shot would have landed as a daughter")), "{}", r.err);
    assert!(r.err.contains("nothing was published"), "{}", r.err);
    assert!(r.err.contains(&format!("run this again with --head {d}.3, or with no --head to take the feed's, to merge against it")), "{}", r.err);
    assert_eq!(rig.publishes_under(&token, &d), publishes, "no publish from the command");
    assert_eq!(rig.board.health().unwrap().log_position(), before, "nothing committed");
    assert_eq!(rig.read(&token, &frames::in_claims(&daughter_s))["claims"], json!([]), "no claim at the daughter");
    assert_eq!(rig.read(&token, &frames::find_links_ftt(&kind, &daughter_s))["addrs"], json!([]), "no record");
    // THE RE-RUN, as the talk asks: against the new head with --retries 1,
    // the count kept in the record, the claim marking the daughter.
    let r = rig.merge(&["--doc", &d_s, "--alternative", &daughter_s, "--kind", &kind, "--retries", "1", "--publish"]);
    let v = report(&r);
    assert_eq!(v["head"].as_str(), Some(format!("{d}.3").as_str()), "the new head off the feed");
    assert_eq!(v["landed"]["member"].as_str(), Some(format!("{d}.4").as_str()));
    assert_eq!(v["landed"]["retries"], json!(1));
    assert_eq!(v["record"]["retries"], json!(1), "the contention number, kept in the record");
    assert_eq!(v["landed"]["claims"].as_array().map(Vec::len), Some(1), "{}", v["landed"]);
    assert_eq!(rig.read(&token, &frames::in_claims(&daughter_s))["claims"][0]["new"].as_str(), Some(format!("{d}.4").as_str()), "the daughter superseded by the merge");
    assert_eq!(runs_of(&v), vec![(format!("{d}.0.1.1"), "4".into()), (format!("{d}.0.1.16"), "4".into()), (format!("{d}.0.1.12"), "4".into()), (format!("{d}.0.1.5"), "3".into())], "the new big cat");
    assert_eq!(v["gaps"], json!([]), "the head's two words between surviving anchors that stand together: no gap");
    assert_eq!(rig.image(&token, &addr(&format!("{d}.4")), 15), runs_of(&v));
    assert_eq!(rig.publishes_under(&token, &d), publishes + 1);
    session.close().expect("close");
}

/// `--fork` IS ADMITTED (the fork-source design record's arm A; the merge
/// record's case (j)): the forker's account, delegated under the claimant's,
/// forks the base version `D.1` privately and removes " sat"; the command
/// reads the fork's served source off the board, composes "the big cat" over
/// the base `D.1` — never named — with the fork's role `fork`, and
/// `--publish` lands the trunk's next member with its record found from the
/// fork. A fork of the BARE document, taken before its first version, is
/// refused with its own reason, exit 1, nothing on stdout, nothing written.
#[test]
fn a_fork_of_a_published_version_is_merged_from_its_served_source() {
    let dir = tempfile::tempdir().unwrap();
    let rig = Rig::new(dir.path());
    let session = rig.session();
    let token = session.token().clone();
    let kind = rig.draft().to_string();
    let d = rig.document(&session);
    let base = rig.shot(&session, &d, None, &[Staged::Fresh { text: "the cat sat" }]);
    let head = rig.shot(&session, &d, Some((&base, 11)), &[Staged::Own { from: 1, text: "the " }, Staged::Fresh { text: "big " }, Staged::Own { from: 5, text: "cat sat" }]);
    let forker = rig.forker();
    let fork = rig.fork(&forker, &base);
    let forked_at = rig.board.health().unwrap().log_position();
    Rig::acked(rig.board.op(Some(&forker), &frames::delete(&fork.to_string(), 8, 4, forked_at, None)));
    let meta = rig.read(&token, &frames::doc_metadata(&fork.to_string()));
    assert_eq!(meta["source"].as_str(), Some(base.to_string().as_str()), "the premise — the board serves the fork's source: {meta}");
    let (d_s, fork_s, head_s) = (d.to_string(), fork.to_string(), head.to_string());

    // COMPOSE AND PRINT: the base off the served source, never named.
    let before = rig.board.health().unwrap().log_position();
    let r = rig.merge(&["--doc", &d_s, "--fork", &fork_s, "--kind", &kind]);
    let v = report(&r);
    assert_eq!(v["head"].as_str(), Some(head_s.as_str()), "the head off the feed walk");
    assert_eq!(v["base"].as_str(), Some(base.to_string().as_str()), "the fork's served source");
    assert_eq!(runs_of(&v), vec![(format!("{d}.0.1.1"), "4".into()), (format!("{d}.0.1.12"), "4".into()), (format!("{d}.0.1.5"), "3".into())], "the big cat");
    assert_eq!(v["sides"], json!([{"at": head_s, "role": "head"}, {"at": fork_s, "role": "fork"}]));
    assert_eq!(v["gaps"], json!([]));
    assert!(v["landed"].is_null(), "{v}");
    assert_eq!(rig.board.health().unwrap().log_position(), before, "composing writes nothing");
    assert!(r.err.contains(&format!("merging the fork {fork} with {head}, the head of {d}")), "{}", r.err);
    assert!(r.err.contains(&format!("composed over the base {base}: 3 runs from the head's 3 and the side's 1, 0 gaps")), "{}", r.err);

    // PUBLISHED: the trunk's next member holds M; the record is found FROM
    // the fork by the kind.
    let r = rig.merge(&["--doc", &d_s, "--fork", &fork_s, "--kind", &kind, "--publish"]);
    let v = report(&r);
    let member = v["landed"]["member"].as_str().expect("the member").to_string();
    assert_eq!(member, format!("{d}.3"), "the trunk's next member");
    assert_eq!(rig.image(&token, &addr(&member), 11), runs_of(&v), "the member's image over its placed positions is M");
    let link = v["landed"]["record"].as_str().expect("the record's link").to_string();
    assert_eq!(rig.read(&token, &frames::find_links_ftt(&kind, &fork_s))["addrs"], json!([link]), "the record is found FROM the fork");
    assert!(r.err.contains(&format!("published {member} at position")), "{}", r.err);

    // A FORK OF THE BARE DOCUMENT — a second document, forked before its
    // first version — is refused with its own reason once the document has
    // a head to merge with.
    let d2 = rig.document(&session);
    let bare_fork = rig.fork(&forker, &d2);
    let base2 = rig.shot(&session, &d2, None, &[Staged::Fresh { text: "the cat sat" }]);
    let before = rig.board.health().unwrap().log_position();
    let r = rig.merge(&["--doc", &d2.to_string(), "--fork", &bare_fork.to_string(), "--kind", &kind]);
    assert_eq!(r.code, 1, "{r:?}");
    assert!(r.out.is_empty(), "nothing on stdout: {}", r.out);
    assert!(r.err.contains(&format!("the board refused: bare_source:the fork {bare_fork} was taken from {d2} itself, before it had a version (a bare source)")), "{}", r.err);
    assert!(r.err.contains(&format!("merging the fork {bare_fork} with {base2}, the head of {d2}")), "the entry line, the head off the feed: {}", r.err);
    assert_eq!(rig.board.health().unwrap().log_position(), before, "nothing written");
    session.close().expect("close");
}

/// `--draft` WITHOUT `--base` (skep #743): the draft `stage` minted off the
/// base version `D.1`, "!!!" typed at its end; the command composes it with
/// the head over the base the board records for the draft — nothing named,
/// the talk naming the draft alone — and prints "the big cat sat!!!" with
/// the draft's fresh run as its own family, nothing written. `--base` naming
/// the recorded base is taken, and said in the talk; `--base` naming the
/// head is refused by name, exit 1, nothing on stdout, nothing written.
#[test]
fn a_draft_is_merged_over_the_base_the_board_records_and_a_disagreeing_base_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let rig = Rig::new(dir.path());
    let session = rig.session();
    let token = session.token().clone();
    let kind = rig.draft().to_string();
    let (d, base, head, _daughter) = rig.race(&session);
    // THE STAGED DRAFT off the base, "!!!" typed at its end, typed against
    // the board's head as the shots type their fresh text.
    let staged = rig.stage(&base);
    let as_of = rig.board.health().unwrap().log_position();
    Rig::acked(rig.board.op(Some(&rig.bare), &json!({"op": "insert", "doc": staged.to_string(), "at": {"subspace": "1", "ordinal": "12"}, "values": ["!!!"], "as_of": as_of})));
    let meta = rig.read(&token, &frames::doc_metadata(&staged.to_string()));
    assert_eq!(meta["base"].as_str(), Some(base.to_string().as_str()), "the premise — the board records the draft's base: {meta}");
    let (d_s, staged_s, base_s, head_s) = (d.to_string(), staged.to_string(), base.to_string(), head.to_string());
    let expected = vec![(format!("{d}.0.1.1"), "4".into()), (format!("{d}.0.1.12"), "4".into()), (format!("{d}.0.1.5"), "7".into()), (format!("{staged}.0.1.1"), "3".into())];

    // COMPOSE with no --base: the base off the board, the head off the feed.
    let before = rig.board.health().unwrap().log_position();
    let r = rig.merge(&["--doc", &d_s, "--draft", &staged_s, "--kind", &kind]);
    let v = report(&r);
    assert_eq!(v["head"].as_str(), Some(head_s.as_str()), "the head off the feed walk");
    assert_eq!(v["base"].as_str(), Some(base_s.as_str()), "the base the board records for the draft, never named");
    assert_eq!(runs_of(&v), expected, "the big cat sat!!!");
    assert_eq!((v["runs"][3]["family"].clone(), v["runs"][3]["side"].clone()), (json!("draft"), json!(1)), "the draft's fresh run, its own family");
    assert_eq!(v["sides"][1]["role"], json!("draft"));
    assert_eq!(v["sides"][1]["at"]["draft"], json!(staged_s), "{}", v["sides"]);
    assert_eq!(v["sides"][1]["at"]["position"], json!(before), "the position the draft was read at, carried in the record's side (skep #453): {}", v["sides"]);
    assert_eq!(v["counts"], json!({"a": 3, "b": 2, "m": 4}));
    assert_eq!(v["gaps"], json!([]), "different material on each side: no gap");
    assert!(v["landed"].is_null(), "{v}");
    assert_eq!(rig.board.health().unwrap().log_position(), before, "composing writes nothing");
    assert!(r.err.contains(&format!("merging the draft {staged} with {head}, the head of {d}, at {}", rig.origin)), "the entry line names the draft alone: {}", r.err);
    assert!(!r.err.contains("staged from"), "no base named, none claimed: {}", r.err);
    assert!(r.err.contains(&format!("composed over the base {base}: 4 runs from the head's 3 and the side's 2, 0 gaps")), "{}", r.err);

    // --BASE naming the recorded base is taken, and the talk says it.
    let r = rig.merge(&["--doc", &d_s, "--draft", &staged_s, "--base", &base_s, "--kind", &kind]);
    let v = report(&r);
    assert_eq!(v["base"].as_str(), Some(base_s.as_str()));
    assert_eq!(runs_of(&v), expected);
    assert!(r.err.contains(&format!("merging the draft {staged} (staged from {base}) with {head}")), "{}", r.err);

    // --BASE naming the head is refused by name: exit 1, nothing on stdout,
    // nothing written.
    let r = rig.merge(&["--doc", &d_s, "--draft", &staged_s, "--base", &head_s, "--kind", &kind]);
    assert_eq!(r.code, 1, "{r:?}");
    assert!(r.out.is_empty(), "nothing on stdout: {}", r.out);
    assert!(r.err.contains(&format!("the board refused: draft_base_disagrees:the base {head} was named for the draft {staged}, whose recorded base (doc_metadata's base) derives the base {base}")), "{}", r.err);
    assert_eq!(rig.board.health().unwrap().log_position(), before, "nothing written");
    session.close().expect("close");
}

/// THE TWO TAKE-BACKS on the real daemon (skep #783). A merge landed in the
/// staged draft `S` by `--into S`; then `--undo S` puts `S` back as it
/// stood — its words C, its base `D.1` at eleven, the marker gone — in one
/// write, the report one JSON document naming the act, the draft, the
/// position, the replacing record, the case and the base restored, the talk
/// saying so in plain words; a second `--undo` is nothing to undo, the
/// merge already taken back, exit 1, nothing on stdout, nothing written. A
/// merge landed in a second draft `T` is taken out by `--withdraw T`: its
/// words stay M, its base stays `D.2` at fifteen, the marker is gone, the
/// report and the talk say so; a second `--withdraw` finds no merge, exit 1,
/// nothing written.
#[test]
fn the_two_take_backs_walk_on_the_real_daemon() {
    let dir = tempfile::tempdir().unwrap();
    let rig = Rig::new(dir.path());
    let session = rig.session();
    let token = session.token().clone();
    let kind = rig.draft();
    let kind_s = kind.to_string();
    let (d, base, head, _daughter) = rig.race(&session);
    let position = || rig.board.health().unwrap().log_position();
    let typed_insert = |doc: &Address, ordinal: u64, text: &str| {
        let as_of = position();
        Rig::acked(rig.board.op(Some(&rig.bare), &json!({"op": "insert", "doc": doc.to_string(), "at": {"subspace": "1", "ordinal": ordinal.to_string()}, "values": [text], "as_of": as_of})));
    };
    let (d_s, base_s, head_s) = (d.to_string(), base.to_string(), head.to_string());

    // THE UNDO. `S` off the base with "!!!" typed, the merge landed in it.
    let s = rig.stage(&base);
    typed_insert(&s, 12, "!!!");
    let s_s = s.to_string();
    let c = rig.image(&token, &s, 14);
    assert_eq!(c, vec![(format!("{d}.0.1.1"), "11".into()), (format!("{s}.0.1.1"), "3".into())], "C");
    let r = rig.merge(&["--doc", &d_s, "--draft", &s_s, "--into", &s_s, "--kind", &kind_s]);
    let v = report(&r);
    let m = runs_of(&v);
    let at = v["landed"]["position"].as_u64().expect("the landing's position");
    let link = v["landed"]["record"].as_str().expect("the record's link").to_string();
    assert_eq!(rig.image(&token, &s, 18), m, "the premise: S holds M");
    let meta = rig.read(&token, &frames::doc_metadata(&s_s));
    assert_eq!((meta["base"].as_str(), meta["base_copied"].as_str(), meta["merge"]["at"].as_u64()), (Some(head_s.as_str()), Some("15"), Some(at)), "the premise: the base on the head, the marker at the landing: {meta}");
    let r = rig.merge(&["--undo", &s_s, "--kind", &kind_s]);
    let v = report(&r);
    let undone_at = v["position"].as_u64().expect("the write's position");
    assert!(undone_at > at, "{v}");
    let replacing = v["record"].as_str().expect("the replacing record's link").to_string();
    assert_ne!(replacing, link);
    assert_eq!(v, json!({"act": "undo", "draft": s_s, "position": undone_at, "record": replacing, "case": "marker", "restored": {"at": base_s, "extent": "11"}}), "the report");
    assert_eq!(rig.image(&token, &s, 14), c, "C again");
    let meta = rig.read(&token, &frames::doc_metadata(&s_s));
    assert_eq!((meta["base"].as_str(), meta["base_copied"].as_str(), meta["merge"].is_null()), (Some(base_s.as_str()), Some("11"), true), "the base restored, the marker cleared: {meta}");
    assert!(r.err.contains(&format!("taking the merge back out of {s} at {}", rig.origin)), "the entry line: {}", r.err);
    assert!(r.err.contains(&format!("took the merge back out of {s} at position {undone_at}: the draft is back to how it stood before the merge, its base is {base} at 11 positions again, and the merge is taken out; the record's link is {replacing}")), "{}", r.err);
    // Again: nothing to undo, nothing written.
    let before = position();
    let r = rig.merge(&["--undo", &s_s, "--kind", &kind_s]);
    assert_eq!(r.code, 1, "{r:?}");
    assert!(r.out.is_empty(), "nothing on stdout: {}", r.out);
    assert!(r.err.contains(&format!("the board refused: nothing_to_undo:nothing to undo: the merge in {s} was already taken back")), "{}", r.err);
    assert_eq!(position(), before, "nothing written");

    // THE WITHDRAWAL. `T` off the base with "???" typed, the merge landed
    // in it.
    let t = rig.stage(&base);
    typed_insert(&t, 12, "???");
    let t_s = t.to_string();
    let r = rig.merge(&["--doc", &d_s, "--draft", &t_s, "--into", &t_s, "--kind", &kind_s]);
    let v = report(&r);
    let m_t = runs_of(&v);
    let at_t = v["landed"]["position"].as_u64().expect("the landing's position");
    let link_t = v["landed"]["record"].as_str().expect("the record's link").to_string();
    let r = rig.merge(&["--withdraw", &t_s, "--kind", &kind_s]);
    let v = report(&r);
    let withdrawn_at = v["position"].as_u64().expect("the write's position");
    assert!(withdrawn_at > at_t, "{v}");
    let replacing_t = v["record"].as_str().expect("the replacing record's link").to_string();
    assert_ne!(replacing_t, link_t);
    assert_eq!(v, json!({"act": "withdraw", "draft": t_s, "position": withdrawn_at, "record": replacing_t, "case": "marker"}), "the report");
    assert_eq!(rig.image(&token, &t, 18), m_t, "the words stay");
    let meta = rig.read(&token, &frames::doc_metadata(&t_s));
    assert_eq!((meta["base"].as_str(), meta["base_copied"].as_str(), meta["merge"].is_null()), (Some(head_s.as_str()), Some("15"), true), "the base unchanged, the marker cleared: {meta}");
    assert!(r.err.contains(&format!("taking the merge out of {t} at {}", rig.origin)), "the entry line: {}", r.err);
    assert!(r.err.contains(&format!("took the merge out of {t} at position {withdrawn_at}: the words stay as they are, and the draft's next version is an ordinary one; the record's link is {replacing_t}")), "{}", r.err);
    // Again: no merge, nothing written.
    let before = position();
    let r = rig.merge(&["--withdraw", &t_s, "--kind", &kind_s]);
    assert_eq!(r.code, 1, "{r:?}");
    assert!(r.out.is_empty(), "nothing on stdout: {}", r.out);
    assert!(r.err.contains(&format!("the board refused: no_merge:{t} carries no merge: nothing to undo, nothing to take out")), "{}", r.err);
    assert_eq!(position(), before, "nothing written");
    session.close().expect("close");
}

/// A MERGE'S RECORD AND ITS LINK STAY PRIVATE (skep #893; the merge
/// record's §4, "Its home"): at `--publish`, `--new` and `--undo` each
/// record's link is homed in the journal its atom lies in — a private draft
/// of the claimant's, never its doc 1, each run finding the one journal the
/// first minted by the account's links of the kind — so no link of the kind
/// stands in doc 1, and neither a guest nor a stranger's session finds a
/// record from the daughter or the draft, while the claimant's own find
/// from the daughter answers all three; the same `--publish` again names
/// the same record, nothing written.
#[test]
fn a_merges_record_and_its_link_stay_in_the_private_journal() {
    let dir = tempfile::tempdir().unwrap();
    let rig = Rig::new(dir.path());
    let session = rig.session();
    let token = session.token().clone();
    let kind_s = rig.draft().to_string();
    let (d, _, head, daughter) = rig.race(&session);
    let (d_s, daughter_s, head_s) = (d.to_string(), daughter.to_string(), head.to_string());
    let position = || rig.board.health().unwrap().log_position();
    let r = rig.merge(&["--doc", &d_s, "--alternative", &daughter_s, "--kind", &kind_s, "--publish"]);
    let published = report(&r)["landed"]["record"].as_str().expect("the shot's record").to_string();
    let before = position();
    let r = rig.merge(&["--doc", &d_s, "--alternative", &daughter_s, "--kind", &kind_s, "--head", &head_s, "--publish"]);
    assert_eq!(report(&r)["landed"]["record"].as_str(), Some(published.as_str()), "the same record");
    assert_eq!(position(), before, "nothing written twice");
    let r = rig.merge(&["--doc", &d_s, "--alternative", &daughter_s, "--kind", &kind_s, "--head", &head_s, "--new"]);
    let v = report(&r);
    let fresh = v["landed"]["draft"].as_str().expect("the fresh draft").to_string();
    let staged = v["landed"]["record"].as_str().expect("the draft landing's record").to_string();
    let r = rig.merge(&["--undo", &fresh, "--kind", &kind_s]);
    let undone = report(&r)["record"].as_str().expect("the undo's record").to_string();
    let homes: Vec<String> = [&published, &staged, &undone].iter().map(|l| skep_client::address::document_of(l).expect("a link's home")).collect();
    assert!(homes.iter().all(|h| *h == homes[0]), "each run found the account's one journal by its links of the kind, minting none after the first: {homes:?}");
    for link in [&published, &staged, &undone] {
        let home = skep_client::address::document_of(link).expect("a link's home");
        assert_ne!(home, format!("{ACCOUNT}.0.1"), "never doc 1: {link}");
        let atom = rig.read(&token, &frames::read_link(link))["link"]["slots"][0][0]["start"].as_str().expect("the atom").to_string();
        assert_eq!(skep_client::address::document_of(&atom).as_deref(), Some(home.as_str()), "homed in the journal its atom lies in: {link}");
        let meta = rig.read(&token, &frames::doc_metadata(&home));
        assert_eq!((meta["published"].as_bool(), meta["owner"].as_str()), (Some(false), Some(ACCOUNT)), "a private draft of the claimant's: {meta}");
    }
    let doc_1 = rig.read(&token, &frames::find_links_ftt_home(&kind_s, &format!("{ACCOUNT}.0.1")));
    assert_eq!(doc_1["addrs"], json!([]), "no link of the kind in doc 1: {doc_1}");
    let (_, stranger) = rig.stranger_account();
    for target in [&daughter_s, &fresh] {
        let find = frames::find_links_ftt(&kind_s, target);
        assert_eq!(rig.board.guest(&find).expect("the guest's read")["addrs"], json!([]), "a guest finds no record from {target}");
        assert_eq!(rig.read(&stranger, &find)["addrs"], json!([]), "a stranger finds no record from {target}");
    }
    let mut own: Vec<String> = rig.read(&token, &frames::find_links_ftt(&kind_s, &daughter_s))["addrs"].as_array().expect("addrs").iter().map(|a| a.as_str().unwrap().to_string()).collect();
    own.sort();
    let mut all = vec![published, staged, undone];
    all.sort();
    assert_eq!(own, all, "the claimant finds every record from the daughter");
    session.close().expect("close");
}

/// THE NEWEST RECORD IS THE ONE WHOSE LINK WAS MINTED LAST (skep #893; the
/// merge record's §4, "Its currency"): `--new` lands in `F`, its record in
/// the account's own journal; `--undo F --journal J0` records the undo in
/// `J0`, a private draft minted before that journal and so at the lower
/// address; and `--new` again finds the undo's record the newest — the
/// report's `prior` — so it stages a fresh draft of its own and lands
/// there, `F` left as the undo put it.
#[test]
fn a_take_back_recorded_in_an_older_journal_leaves_the_key_open() {
    let dir = tempfile::tempdir().unwrap();
    let rig = Rig::new(dir.path());
    let session = rig.session();
    let token = session.token().clone();
    let kind_s = rig.draft().to_string();
    let j0 = rig.draft();
    let (d, _, _, daughter) = rig.race(&session);
    let (d_s, daughter_s) = (d.to_string(), daughter.to_string());
    let r = rig.merge(&["--doc", &d_s, "--alternative", &daughter_s, "--kind", &kind_s, "--new"]);
    let v = report(&r);
    let f = v["landed"]["draft"].as_str().expect("F").to_string();
    let first = v["landed"]["record"].as_str().expect("the landing's record").to_string();
    let journal = addr(&skep_client::address::document_of(&first).expect("the account's journal"));
    let last = |a: &Address| a.to_string().rsplit('.').next().unwrap().parse::<u64>().unwrap();
    assert!(last(&j0) < last(&journal), "the premise: J0 {j0} lies below the account's journal {journal}");
    let r = rig.merge(&["--undo", &f, "--kind", &kind_s, "--journal", &j0.to_string()]);
    let undone = report(&r)["record"].as_str().expect("the undo's record").to_string();
    assert_eq!(skep_client::address::document_of(&undone), Some(j0.to_string()), "the undo recorded in J0");
    let f_words = rig.image(&token, &addr(&f), 15);
    assert_eq!(f_words.iter().map(|(_, w)| w.parse::<u64>().unwrap()).sum::<u64>(), 15, "the premise: F back to the head's words, \"the big cat sat\"");
    let r = rig.merge(&["--doc", &d_s, "--alternative", &daughter_s, "--kind", &kind_s, "--new"]);
    let v = report(&r);
    assert_eq!(v["prior"]["link"].as_str(), Some(undone.as_str()), "the undo's record, the newest: {}", v["prior"]);
    assert_eq!(v["landed"]["fresh"], json!(true), "{}", v["landed"]);
    let landed_in = v["landed"]["draft"].as_str().expect("the draft");
    assert_ne!(landed_in, f, "a draft of its own: {}", v["landed"]);
    assert_eq!(rig.image(&token, &addr(landed_in), 11), runs_of(&v), "the fresh draft holds M");
    assert_eq!(rig.image(&token, &addr(&f), 15), f_words, "F as the undo put it");
    session.close().expect("close");
}

/// A stranger's documents are refused, saying what the run did.
///
/// They are a second top-level account's private draft `X` and its private
/// fork `F` of `D.1`, which the claimant may not read. Each `withheld`
/// refusal names the document, and the talk says beside it what the run
/// did, exit 1, nothing on stdout, nothing written: `--fork F` composed
/// nothing; `--into X` composed the merge and merged nothing; `--undo X`
/// took nothing back; `--withdraw X` took nothing out. `X` named as the
/// journal is checked before the shot: `--publish` halts, exit 3, naming
/// the journal and the check it fails, nothing published; the same
/// `--publish` naming no journal lands the next version with its record,
/// and naming `X` again answers that landing, nothing written.
#[test]
fn a_strangers_document_is_refused_with_what_the_run_did_and_as_the_journal_before_any_write() {
    let dir = tempfile::tempdir().unwrap();
    let rig = Rig::new(dir.path());
    let session = rig.session();
    let token = session.token().clone();
    let kind = rig.draft().to_string();
    let (d, base, head, daughter) = rig.race(&session);
    let (d_s, daughter_s, head_s) = (d.to_string(), daughter.to_string(), head.to_string());
    let position = || rig.board.health().unwrap().log_position();
    let (x, f) = rig.stranger(&base);
    let x_s = x.to_string();
    let refused = |extra: &[&str], said: &str| {
        let before = position();
        let r = rig.merge(extra);
        assert_eq!(r.code, 1, "{extra:?}: {r:?}");
        assert!(r.out.is_empty(), "{extra:?}: nothing on stdout: {}", r.out);
        assert!(r.err.contains(&format!("the board refused: withheld:{said}")), "{extra:?}: {}", r.err);
        assert_eq!(position(), before, "{extra:?}: nothing written");
        r
    };
    refused(&["--doc", &d_s, "--fork", &f.to_string(), "--kind", &kind], &format!("{f} is not readable to this reader (withheld); nothing was composed"));
    let r = refused(&["--doc", &d_s, "--alternative", &daughter_s, "--into", &x_s, "--kind", &kind], &format!("{x} is not readable to this reader (withheld); the merge was composed, and nothing was merged"));
    assert!(r.err.contains(&format!("composed over the base {base}")), "the composition said before the landing's refusal: {}", r.err);
    refused(&["--undo", &x_s, "--kind", &kind], &format!("{x} is not readable to this reader (withheld); nothing was taken back"));
    refused(&["--withdraw", &x_s, "--kind", &kind], &format!("{x} is not readable to this reader (withheld); nothing was taken out"));

    // The journal, checked before the shot: the stranger's draft refused,
    // nothing published.
    let member = format!("{d}.3");
    let publishes = rig.publishes_under(&token, &d);
    let before = position();
    let r = rig.merge(&["--doc", &d_s, "--alternative", &daughter_s, "--publish", "--journal", &x_s, "--kind", &kind]);
    assert_eq!(r.code, 3, "{r:?}");
    assert!(r.out.is_empty(), "no report: {}", r.out);
    assert!(r.err.contains(&format!("the journal {x} is not readable to this merger (withheld), so the merge cannot land")), "{}", r.err);
    assert!(r.err.contains("act: name as the journal a draft this account owns, or none for the account's own; nothing was written"), "{}", r.err);
    assert!(!r.err.contains("nothing was composed") && !r.err.contains("fault in this library"), "{}", r.err);
    assert_eq!(position(), before, "nothing written");
    assert_eq!(rig.publishes_under(&token, &d), publishes, "nothing published");
    // Naming no journal, the next version lands with its record; naming the
    // stranger's draft again, the standing landing is answered, nothing
    // written and no journal checked by the landing.
    let r = rig.merge(&["--doc", &d_s, "--alternative", &daughter_s, "--head", &head_s, "--publish", "--kind", &kind]);
    let v = report(&r);
    assert_eq!(v["landed"]["member"].as_str(), Some(member.as_str()), "the next version: {}", v["landed"]);
    let link = v["landed"]["record"].as_str().expect("the record's link").to_string();
    assert_eq!(rig.read(&token, &frames::find_links_ftt(&kind, &daughter_s))["addrs"], json!([link]), "the record found from the daughter");
    assert_eq!(rig.publishes_under(&token, &d), publishes + 1, "one version published");
    let before = position();
    let r = rig.merge(&["--doc", &d_s, "--alternative", &daughter_s, "--head", &head_s, "--publish", "--journal", &x_s, "--kind", &kind]);
    let v = report(&r);
    assert_eq!((v["landed"]["member"].as_str(), v["landed"]["record"].as_str()), (Some(member.as_str()), Some(link.as_str())), "the standing landing: {}", v["landed"]);
    assert_eq!(position(), before, "nothing written twice");
    session.close().expect("close");
}

/// A published journal is refused in the command's words, before any write.
///
/// `D`, the published trunk, and the account's doc 1, born published, are
/// each named as the journal. With no landing flag the composition's talk
/// says the fact after its own line and the report is printed, exit 0; with
/// `--publish` and with `--new` the talk says it, then the board's refusal
/// `published_target` in the command's words, exit 1, nothing on stdout,
/// nothing written and nothing published — never the library's own fault.
/// `--undo` of a merge `--new` landed is refused the same naming `D`,
/// nothing taken back.
#[test]
fn a_published_journal_is_refused_in_the_commands_words_before_any_write() {
    let dir = tempfile::tempdir().unwrap();
    let rig = Rig::new(dir.path());
    let session = rig.session();
    let token = session.token().clone();
    let kind = rig.draft().to_string();
    let (d, base, head, daughter) = rig.race(&session);
    let (d_s, daughter_s, head_s) = (d.to_string(), daughter.to_string(), head.to_string());
    let doc1 = format!("{ACCOUNT}.0.1");
    let position = || rig.board.health().unwrap().log_position();
    let refusal = |journal: &str, undone: &str| {
        format!("the board refused: published_target:{journal} is published, and a merge record is kept only in a private document — {undone} and nothing was written. Name a private document of yours with --journal, or leave --journal out to use your private journal.")
    };
    for journal in [d_s.as_str(), doc1.as_str()] {
        let clause = format!("{journal} is published, and a merge record is kept only in a private document — landing this merge there is refused");
        let before = position();
        let r = rig.merge(&["--doc", &d_s, "--alternative", &daughter_s, "--head", &head_s, "--journal", journal, "--kind", &kind]);
        report(&r);
        let composed = r.err.find(&format!("composed over the base {base}")).unwrap_or_else(|| panic!("the composition said: {}", r.err));
        let said = r.err.find(&clause).unwrap_or_else(|| panic!("{journal}: the fact said before any landing: {}", r.err));
        assert!(composed < said, "{journal}: after the composition's line: {}", r.err);
        assert_eq!(position(), before, "{journal}: nothing written");
        for landing in ["--publish", "--new"] {
            let (before, publishes) = (position(), rig.publishes_under(&token, &d));
            let r = rig.merge(&["--doc", &d_s, "--alternative", &daughter_s, "--head", &head_s, landing, "--journal", journal, "--kind", &kind]);
            assert_eq!(r.code, 1, "{journal} {landing}: {r:?}");
            assert!(r.out.is_empty(), "{journal} {landing}: no report: {}", r.out);
            let said = r.err.find(&clause).unwrap_or_else(|| panic!("{journal} {landing}: the fact said: {}", r.err));
            let refused = r.err.find(&refusal(journal, "nothing was merged")).unwrap_or_else(|| panic!("{journal} {landing}: the refusal in the command's words: {}", r.err));
            assert!(said < refused, "{journal} {landing}: the fact, then the refusal: {}", r.err);
            assert!(!r.err.contains("fault in this library"), "{journal} {landing}: {}", r.err);
            assert_eq!(position(), before, "{journal} {landing}: nothing written");
            assert_eq!(rig.publishes_under(&token, &d), publishes, "{journal} {landing}: nothing published");
        }
    }
    // A take-back names a published journal: refused before its one write.
    let v = report(&rig.merge(&["--doc", &d_s, "--alternative", &daughter_s, "--head", &head_s, "--new", "--kind", &kind]));
    let draft = v["landed"]["draft"].as_str().expect("the fresh draft").to_string();
    let before = position();
    let r = rig.merge(&["--undo", &draft, "--journal", &d_s, "--kind", &kind]);
    assert_eq!(r.code, 1, "{r:?}");
    assert!(r.out.is_empty(), "no report: {}", r.out);
    assert!(r.err.contains(&refusal(&d_s, "nothing was taken back")), "{}", r.err);
    assert_eq!(position(), before, "nothing taken back, nothing written");
    session.close().expect("close");
}
