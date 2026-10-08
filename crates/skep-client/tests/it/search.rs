//! THE SEARCH HALF against the real daemon (`client.md` §4e; `search.md` §4,
//! §5): the suites below drive `skep_client::search` over a board spawned
//! in-process — a claimed board in CLAIMED-PERMISSIVE mode, so the claimant's
//! bare session mints and fills the drafts the index reads back, the
//! claimant's device key opens the signed sessions the supplement takes, and
//! the publish class's attested shot gives the published index TEXT — read
//! back by the consumer as the shell reads it. `consumer` — the class fence
//! (§4 (i)–(iii)), the events stream; `resume` — `history_reclaimed` reached
//! on the daemon through its checkpoint seam; `directory` — the orphan test
//! read off the board and the forget; `bridge` — the query crossing nothing,
//! the places at the call's class, the jump's band. The fixture is this
//! module's.

mod bridge;
mod consumer;
mod directory;
mod resume;

use std::path::PathBuf;

use serde_json::{json, Value};
use skep_address::Address;
use skep_client::address::parse_address;
use skep_client::board::{acked_addr, frames, Answer, Board, Scope, Token};
use skep_client::ceremony::handshake::{handshake, Session, Site};
use skep_client::search::{Consumer, SearchDir, SessionRef};
use skep_client::sign::{sig_hex, Signer};
use skep_client::store::FileStore;
use skep_identity::{entry_body_empty, entry_body_publish, entry_frame, ContentFreeOp, DocTerm, EntryBody, Fingerprint, ShotBase, ShotSegmentPiece};
use skep_signature::HybridSigner;
use skepd::Skepd;
use tempfile::TempDir;

use crate::common::{bare, board, claim, insert_text, keygen, mint, spawn};

/// The claimant's account on a notebook.
pub const CLAIMANT: &str = "1.0.1";

/// A claimed permissive board with the claimant's store, key and anchors,
/// and a data directory for the search half.
pub struct Fixture {
    /// Declared first, so the daemon stops before the directory below goes.
    pub sd: Skepd,
    pub board: Board,
    pub store: FileStore,
    pub fp: Fingerprint,
    pub anchors: PathBuf,
    pub data: PathBuf,
    /// The temp directory everything above lives in, removed with the value
    /// after the daemon has stopped.
    _tmp: TempDir,
}

impl Fixture {
    /// Spawned, keyed and claimed; the search directory under `data`.
    pub fn claimed() -> Fixture {
        let tmp = tempfile::tempdir().expect("tempdir");
        let sd = spawn(&tmp.path().join("board"), true);
        let board = board(sd.port());
        let store = FileStore::open(tmp.path().join("store"));
        let fp = keygen(&store, "notebook");
        let anchors = tmp.path().join("anchors");
        claim(&board, &store, &anchors);
        let data = tmp.path().join("data");
        Fixture { sd, board, store, fp, anchors, data, _tmp: tmp }
    }

    /// The claimant's device key.
    pub fn device(&self) -> HybridSigner {
        self.store.load(&self.store.key_path(&self.fp)).expect("the device key").signer()
    }

    /// A FULL signed session as the claimant over `board`.
    pub fn signed<'b>(&self, board: &'b Board) -> Session<'b> {
        handshake(board, Scope::Full, &self.device(), 1, Site::Session).expect("the signed session")
    }

    /// The search directory under the data directory.
    pub fn dir(&self) -> SearchDir {
        SearchDir::new(&self.data)
    }

    /// A consumer over `board`.
    pub fn consumer<'b>(&self, board: &'b Board) -> Consumer<'b> {
        Consumer::open(board, self.dir()).expect("opens")
    }

    /// The claimant's bare session — the drafts' writer on a permissive
    /// board.
    pub fn bare(&self) -> Token {
        bare(&self.board, 1)
    }

    /// A draft under `account` filled with `text`, from `token`'s session.
    pub fn draft(&self, token: &Token, account: &str, text: &str) -> Address {
        let doc = mint(&self.board, token, account, false);
        insert_text(&self.board, token, &doc, 1, text);
        parse_address(&doc).expect("an address")
    }

    /// A PUBLISHED EDITION holding `text` (wire.md §Arrangement, `publish`;
    /// §The publish shot; signed ops): a published document minted from the
    /// claimant's signed session with its attest, the text written per-byte
    /// into a STAGING DRAFT, and the shot naming that `draft`, so its runs
    /// are "re-inserted as fresh identity under `doc`'s own I-space" — guest
    /// readable, where a window onto the draft would be withheld — the shot
    /// attested over its entry frame, the body's pieces the copied values one
    /// per position. Answers the document and its first member, `D.1`.
    pub fn published(&self, signed: &Session<'_>, text: &str) -> (Address, Address) {
        let signer = self.device();
        let account = parse_address(CLAIMANT).expect("an address");
        let mut frame = json!({"op": "create_new_document", "account": CLAIMANT, "published": true});
        frame["attest"] = attest(&self.board, &signer, &account, &account, &entry_body_empty(ContentFreeOp::CreateNewDocument));
        let doc = parse_address(acked_addr(&document(signed.op(&frame))).expect("a minted address")).expect("an address");
        let token = self.bare();
        let draft = self.draft(&token, CLAIMANT, text);
        let runs = image_runs(&self.board, &token, &draft, 1, text.len() as u64);
        let bytes: Vec<[u8; 1]> = text.bytes().map(|b| [b]).collect();
        let body = entry_body_publish(bytes.iter().map(|b| ShotSegmentPiece::Value(b)), None::<ShotBase<'_>>);
        let mut frame = json!({
            "op": "publish",
            "doc": doc.to_string(),
            "draft": draft.to_string(),
            "runs": runs.iter().map(|(start, width)| {
                let start = start.to_string();
                json!({"origin": origin_of(&start), "i_start": start, "width": width.to_string()})
            }).collect::<Vec<_>>(),
        });
        frame["attest"] = attest(&self.board, &signer, &account, &doc, &body);
        let member = parse_address(acked_addr(&document(signed.op(&frame))).expect("the member's address")).expect("an address");
        (doc, member)
    }

    /// A keyed sub-account's HOME minted from its own signed session with its
    /// attest — the account's first mint is its doc 1, born published, so
    /// the mint is publish-class and takes the entry signature; a later
    /// flagless mint is a private draft and takes none.
    pub fn home(&self, session: &Session<'_>, signer: &HybridSigner, account: &str) -> Address {
        let account_addr = parse_address(account).expect("an address");
        let mut frame = json!({"op": "create_new_document", "account": account});
        frame["attest"] = attest(&self.board, signer, &account_addr, &account_addr, &entry_body_empty(ContentFreeOp::CreateNewDocument));
        parse_address(acked_addr(&document(session.op(&frame))).expect("the home's address")).expect("an address")
    }
}

/// The `attest` member over `body` for a write whose `doc` row is `doc` —
/// the account itself for a mint — under `account`: the entry frame under
/// `H.1`'s pair, the account and the row, signed by the device key
/// (skep-identity's `entry_frame`).
fn attest(board: &Board, signer: &HybridSigner, account: &Address, doc: &Address, body: &EntryBody) -> Value {
    let term = board.board_term().expect("the board term read").expect("H.1 stands on a claimed board");
    let frame = entry_frame(Signer::public_key(signer).alg(), term, account, DocTerm::One(doc), body);
    json!({"alg": Signer::public_key(signer).alg(), "sig": sig_hex(&Signer::sign(signer, &frame))})
}

/// The response document of an exchange that must not have met the death
/// signal, and must have been acked.
fn document(answer: Result<Answer, skep_client::Halt>) -> Value {
    match answer.expect("the exchange") {
        Answer::Document(v) => {
            assert!(matches!(v["resp"].as_str(), Some("ack" | "ack_addr")), "the board refused the attested write: {v}");
            v
        }
        Answer::Closed => panic!("the session was closed"),
    }
}

/// `image` over content ordinals `from ..` of `doc`: the V→I runs as
/// `(i_start, width)`.
fn image_runs(board: &Board, token: &Token, doc: &Address, from: u64, width: u64) -> Vec<(Address, u64)> {
    let Answer::Document(v) = board.op(Some(token), &frames::image(&doc.to_string(), from, width)).expect("image") else { panic!("closed") };
    assert_eq!(v["resp"].as_str(), Some("runs"), "{v}");
    v["runs"]
        .as_array()
        .expect("runs")
        .iter()
        .map(|r| (parse_address(r["i_start"].as_str().expect("i_start")).expect("an address"), r["width"].as_str().expect("width").parse().expect("a count")))
        .collect()
}

/// The document a content I-address was minted under: the prefix before its
/// last `.0.1.`.
fn origin_of(i_addr: &str) -> String {
    let at = i_addr.rfind(".0.1.").unwrap_or_else(|| panic!("{i_addr} is not a content I-address"));
    i_addr[..at].to_string()
}

/// The three facts the search half takes of a session.
pub fn session_ref<'a>(session: &'a Session<'_>) -> SessionRef<'a> {
    SessionRef { token: session.token(), principal: session.principal(), account: session.account() }
}
