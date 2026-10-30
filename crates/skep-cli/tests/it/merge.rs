//! THE FOURTEENTH COMMAND through the binary (the merge record's §6, "The
//! CLI and the agent adapter"; `client.md` §2.1's thirteen stand beside
//! it): THE USAGE FORMS refused before any socket opens, exit 2 — no
//! `--doc`, two sides, `--draft` without `--base`, `--base` outside
//! `--draft`, `--publish` with `--into`, a malformed `--resolve`, no
//! `--kind` and no `SKEP_MERGE_KIND`, a value that is no address — while
//! the variable stands in for the flag; THE WHOLE WALK on the real daemon —
//! a document seeded with a base version, a head and a daughter as the
//! library's own daemon walk seeds them, the merge composed and printed as
//! one JSON document with nothing else on stdout, then `--publish` landing
//! the next version whose image is the report's runs and whose record is
//! found from the daughter, the same `--publish` again landing nothing
//! twice with the prior named, a gap both sides added at reported
//! unsettled with its default and then `--resolve`d the other way round as
//! the AGENT's choice (the runner has no terminal), a resolution naming no
//! gap reported as not applied, and `--into` landing the merged list in a
//! draft; A DAUGHTER — the head moved before `--publish`, the shot landing
//! as the head's daughter, reported with the re-run line and never retried,
//! one `publish` in the feed, and the re-run with `--retries 1` landing on
//! the new head with the count in its record; and `--fork` ADMITTED — a
//! second account's fork of a published version merged from the source the
//! board serves for it and published — while a fork of the bare document,
//! taken before its first version, is refused with its own reason, exit 1,
//! nothing on stdout.

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

fn addr(text: &str) -> Address {
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
fn report(r: &Run) -> Value {
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
/// sign with.
struct Rig {
    _daemon: Skepd,
    origin: String,
    store: PathBuf,
    board: Board,
    device: HybridSigner,
    bare: Token,
}

impl Rig {
    fn new(dir: &Path) -> Rig {
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
    fn session(&self) -> Session<'_> {
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
    fn read(&self, token: &Token, frame: &Value) -> Value {
        let Answer::Document(v) = self.board.op(Some(token), frame).expect("the read") else { panic!("closed") };
        assert_ne!(v["resp"].as_str(), Some("rejected"), "{v}");
        v
    }

    /// An acked write's document.
    fn acked(answer: Result<Answer, skep_client::Halt>) -> Value {
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
    fn image(&self, token: &Token, doc: &Address, width: u64) -> Vec<(String, String)> {
        let v = self.read(token, &frames::image(&doc.to_string(), 1, width));
        v["runs"].as_array().expect("runs").iter().map(|r| (r["i_start"].as_str().unwrap().to_string(), r["width"].as_str().unwrap().to_string())).collect()
    }

    /// A private draft minted into the account from the bare session.
    fn draft(&self) -> Address {
        let v = Rig::acked(self.board.op(Some(&self.bare), &json!({"op": "create_new_document", "account": ACCOUNT})));
        addr(acked_addr(&v).expect("a minted address"))
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
                    let insert = json!({"op": "insert", "doc": d.to_string(), "at": {"subspace": "1", "ordinal": "1"}, "values": [text]});
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
/// stdout empty, against a dead port — and `SKEP_MERGE_KIND` stands in for
/// `--kind`, so that line is no usage refusal and reaches the dead board.
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
    refused(&["--doc", doc, "--kind", kind], "one side is required: --alternative <D.k.m>, --draft <S> --base <D.k>, or --fork <F>");
    refused(&["--doc", doc, "--alternative", alt, "--draft", draft, "--base", base, "--kind", kind], "`--alternative` and `--draft` belong to two forms of `merge`: give one");
    refused(&["--doc", doc, "--alternative", alt, "--fork", draft, "--kind", kind], "`--alternative` and `--fork` belong to two forms of `merge`: give one");
    refused(&["--doc", doc, "--draft", draft, "--kind", kind], "--base <D.k> is required with --draft <S>");
    refused(&["--doc", doc, "--alternative", alt, "--base", base, "--kind", kind], "`--base` belongs to `merge --draft` and is refused without `--draft`");
    refused(&["--doc", doc, "--alternative", alt, "--kind", kind, "--publish", "--into", draft], "`--publish` and `--into` belong to two forms of `merge`: give one");
    refused(&["--doc", doc, "--alternative", alt, "--kind", kind, "--resolve", "1=frob"], "--resolve: '1=frob' is not <gap>=<choice>");
    refused(&["--doc", doc, "--alternative", alt, "--kind", kind, "--resolve", "both"], "--resolve: 'both' is not <gap>=<choice>");
    refused(&["--doc", doc, "--alternative", alt, "--kind", kind, "--resolve", "0=omit"], "--resolve: '0=omit' is not <gap>=<choice>");
    refused(&["--doc", doc, "--alternative", alt, "--kind", kind, "--resolve", "1=order:"], "--resolve: '1=order:' is not <gap>=<choice>");
    refused(&["--doc", doc, "--alternative", alt, "--kind", kind, "--resolve", "1=after:x"], "--resolve: '1=after:x' is not <gap>=<choice>");
    refused(&["--doc", doc, "--alternative", alt], "--kind <address> (or SKEP_MERGE_KIND) is required");
    refused(&["--doc", "not-an-address", "--alternative", alt, "--kind", kind], "--doc: 'not-an-address' is not an address");
    refused(&["--doc", doc, "--alternative", alt, "--kind", kind, "--retries", "x"], "--retries: 'x' is not a count");
    for form in [&["--doc", doc, "--alternative", alt, "--kind", kind][..], &["--doc", doc, "--draft", draft, "--base", base, "--kind", kind], &["--doc", doc, "--fork", draft, "--kind", kind]] {
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
    assert_eq!(v["landed"]["claims"], json!([]), "this wire admits no claim over version members");
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
    // merged list landed by identity, the draft's image M.
    let into = rig.draft();
    let r = rig.merge(&["--doc", &d_s, "--alternative", &daughter_s, "--kind", &kind_s, "--head", &head_s, "--into", &into.to_string()]);
    let v = report(&r);
    assert_eq!(v["landed"]["draft"].as_str(), Some(into.to_string().as_str()));
    assert!(v["landed"]["ops"].as_u64().is_some_and(|n| n >= 1), "{}", v["landed"]);
    assert!(v["landed"]["record"].as_str().is_some());
    assert_eq!(rig.image(&token, &into, 11), runs_of(&v), "the draft holds M");
    assert!(r.err.contains(&format!("landed in the draft {into} in")), "{}", r.err);

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
    session.close().expect("close");
}

/// A DAUGHTER IS REPORTED, NEVER RETRIED (decision 17; the fence): the head
/// moves between the composition and `--publish`, the shot lands as the
/// head's daughter, the report names it with the retry count, the talk says
/// to run again with `--retries 1`, the feed holds ONE publish from the
/// command — and the re-run with `--retries 1` lands on the new head with
/// the count in its record.
#[test]
fn a_daughter_is_reported_with_its_retry_count_and_never_retried() {
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
    // --PUBLISH against the head the merge was composed from.
    let r = rig.merge(&["--doc", &d_s, "--alternative", &daughter_s, "--kind", &kind, "--head", &head_s, "--publish"]);
    let v = report(&r);
    let landed = &v["landed"];
    assert_eq!(landed["daughter"].as_str(), Some(format!("{d}.2.1").as_str()), "the head's daughter: {landed}");
    assert!(landed.get("member").is_none() && landed.get("record").is_none(), "no member, no record: {landed}");
    assert_eq!(landed["retries"], json!(0));
    assert!(landed["position"].as_u64().is_some());
    assert_eq!(rig.image(&token, &addr(&format!("{d}.2.1")), 11), runs_of(&v), "the daughter holds M");
    assert!(r.err.contains(&format!("the head of {d} moved under the merge: the shot landed as the daughter {d}.2.1 at position")), "{}", r.err);
    assert!(r.err.contains("Nothing is retried here — run this again with --retries 1"), "{}", r.err);
    assert_eq!(rig.publishes_under(&token, &d), publishes + 1, "ONE publish from the command, never a second");
    assert_eq!(rig.read(&token, &frames::find_links_ftt(&kind, &daughter_s))["addrs"], json!([]), "no record for a daughter landing");
    // THE RE-RUN, as the talk asks: against the new head with --retries 1,
    // the count kept in the record.
    let r = rig.merge(&["--doc", &d_s, "--alternative", &daughter_s, "--kind", &kind, "--retries", "1", "--publish"]);
    let v = report(&r);
    assert_eq!(v["head"].as_str(), Some(format!("{d}.3").as_str()), "the new head off the feed");
    assert_eq!(v["landed"]["member"].as_str(), Some(format!("{d}.4").as_str()));
    assert_eq!(v["landed"]["retries"], json!(1));
    assert_eq!(v["record"]["retries"], json!(1), "the contention number, kept in the record");
    assert_eq!(runs_of(&v), vec![(format!("{d}.0.1.1"), "4".into()), (format!("{d}.0.1.16"), "4".into()), (format!("{d}.0.1.12"), "4".into()), (format!("{d}.0.1.5"), "3".into())], "the new big cat");
    assert_eq!(v["gaps"], json!([]), "the head's two words between surviving anchors that stand together: no gap");
    assert_eq!(rig.image(&token, &addr(&format!("{d}.4")), 15), runs_of(&v));
    assert_eq!(rig.publishes_under(&token, &d), publishes + 2);
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
    Rig::acked(rig.board.op(Some(&forker), &frames::delete(&fork.to_string(), 8, 4, None)));
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
