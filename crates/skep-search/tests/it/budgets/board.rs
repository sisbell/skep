//! THE DEV BOARD (`search.md` §7.3): the corpus "written to a DEV BOARD
//! through the ordinary `insert` path, one document per cut, the text
//! per-byte, and read back through `retrieve_v` so the index is fed exactly
//! as the shell feeds it — the harness OUTSIDE the `xanadu-spec` root". The
//! daemon runs IN-PROCESS on an ephemeral port over a `tempfile` directory
//! under the system temp dir, claimed as skep-client's suite claims its
//! boards (the notebook walk with the scripted person), and every document
//! goes through the wire the shell's own library dials: `create_new_document`
//! as a private draft of the claimant's, `insert` of the text PER-BYTE (the
//! `str` write form, or `{"hex"}` for bytes that are not UTF-8 — one
//! single-byte value per byte either way; wire.md §Value encodings), then
//! `retrieve_v` over the document's whole content extent, in PARTS where the
//! extent passes `MAX_DELIVERY_ITEMS` (§2.1's parts rule), each delivery's
//! items turned into the crate's typed [`Item`]s — a `content` or `hex` item
//! a `Text`, an atom, a withheld run or an unknown kind a `Gap` at its width
//! — and the parts JOINED by [`Unit::new`]. The documents are DRAFTS read
//! under the claimant's session, so the units carry the claimant's class and
//! `Kind::Draft`, member the draft's own address — the supplement's feed
//! (`client.md` §4e.2: the `drafts=true` page's documents "are read with the
//! SESSION's token at the principal's class into `principal-<n>.index`"); a
//! published document on a CLAIMED board takes its text by the attested
//! `publish` shot alone, the daemon suite's signer and not a crate's, and the
//! engine does not differ by class.
//!
//! THE CACHE: feeding 10⁴ documents through the daemon costs minutes, and
//! nextest runs every test in its own process, so the units a feed delivered
//! are written — as delivered, byte for byte — to one file per tier under the
//! system temp dir, keyed by the pin, the cut rule and the tier, with the
//! board's own timings beside them; a later test loads them instead of
//! spawning a board, and the board itself is gone with its temp directory.
//! Every unit the index takes still came back through `retrieve_v` over the
//! wire, once, and [`DevBoard::feed`] asserted the round trip byte-exact when
//! it did. (A fed board is never REOPENED: the daemon's open of a board
//! holding thousands of commits rebuilds its attest store by replaying
//! history, which ran past ten minutes in a release build — the daemon's
//! restart path, not this crate's, and reported as met.)
//!
//! The rows that need a LIVE board spawn a fresh claimed one: the save path's
//! `/chain?at` beside `/op-at` readers feeds it the 10³ cut first, so the
//! chain read verifies a journal of some eight million records; M4's 1 MB
//! document is read from one in parts; M6's `compare` against MEMBERS, which
//! the publish class alone mints — on a claimed board an attested write from
//! a signed session, so the board keeps the claimant's device key, opens the
//! FULL session the client's own handshake opens, and signs each shot's
//! entry frame as the daemon composes it (`publish_windows`), the runs
//! windows onto a draft's I-space so the signed body is the windows alone.

// A fixture module: the rows take what they need of this surface, and a
// helper no row calls yet is no fault — skep-client's own fixture takes the
// same allowance.
#![allow(dead_code)]

use std::io::{ErrorKind, Read, Write};
use std::net::TcpListener;
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use skep_address::{validate, Address, Nat, Tumbler};
use skep_client::board::{
    acked_addr, acked_at, frames, Answer, AtAnswer, Board, Opened, Scope, SessionBody, Token,
};
use skep_client::ceremony::claim::{self, ClaimOutcome, NotebookOptions};
use skep_client::ceremony::handshake::{handshake, Session, Site};
use skep_client::dial::{PlainHttp, Request};
use skep_client::person::scripted::{Script, Scripted};
use skep_client::sheet::Label;
use skep_client::sign::{sig_hex, Signer};
use skep_client::store::{FileStore, KeyStore};
use skep_identity::{
    entry_body_empty, entry_body_publish, entry_frame, ContentFreeOp, DocTerm, EntryBody, ShotBase,
    ShotSegmentPiece,
};
use skep_search::{Chain, ChainAt, Class, GapKind, Item, Kind, Unit, UnitKey};
use skepd::{serve, AuthOptions, Daemon, Skepd, DEFAULT_WORKERS};
use tempfile::TempDir;

use super::corpus::{Document, CUT_RULE, PIN};

/// `MAX_DELIVERY_ITEMS`, the delivery budget one `retrieve_v` is bounded by
/// (`crates/skep-retrieval/src/budget.rs`, `1 << 17`): a document past it is
/// read in parts (§2.1). The number alone is mirrored here, as the index
/// suite mirrors it.
pub const MAX_DELIVERY_ITEMS: u64 = 1 << 17;

/// The most bytes one `insert` frame carries: 128 KiB, one delivery part's
/// worth. One transaction is bounded by the kernel's `MAX_TXN_BYTES`, 64 MiB,
/// and a per-byte value costs the journal 67 bytes and more — a 1 MiB chunk
/// encoded to 70,364,921 bytes and was refused `txn_over_budget`, and one
/// records-tier document's 512 KiB chunk to the same — where eight 128 KiB
/// chunks of a 1 MiB text landed in 1.6–2.0 s each; a longer document is
/// inserted in consecutive frames at consecutive ordinals. A chunk the board
/// still refuses is recorded ([`Fed::refused`]) and its document enters the
/// index directly, named in the report.
pub const INSERT_CHUNK: usize = 1 << 17;

/// The cache's format tag.
const CACHE_MAGIC: &[u8] = b"skep-search-budgets-units-1\n";

/// A board address parsed to the vocabulary's own type.
pub fn parse_addr(text: &str) -> Address {
    let comps = text.split('.').map(|c| Nat::from(c.parse::<u64>().expect("a decimal component")));
    validate(Tumbler::new(comps).expect("a nonempty tumbler")).expect("a T4-valid address")
}

/// Lowercase hex of `bytes`.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The bytes of lowercase or uppercase hex.
pub fn unhex(text: &str) -> Vec<u8> {
    (0..text.len() / 2)
        .map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).expect("hex"))
        .collect()
}

/// The document a content I-address was minted under: the prefix before its
/// last `.0.1.`.
pub fn origin_of(i_addr: &str) -> String {
    let at = i_addr.rfind(".0.1.").unwrap_or_else(|| panic!("{i_addr} is not a content I-address"));
    i_addr[..at].to_string()
}

/// The live daemon, the board over the client's dialer, and the session the
/// documents are written and read under.
pub struct DevBoard {
    /// The daemon — declared first, so it stops before the directory below
    /// is removed (fields drop in declaration order).
    pub sd: Skepd,
    pub board: Board,
    pub token: Token,
    /// The account the documents are minted under.
    pub account: String,
    /// The principal whose session reads them — the class of the units.
    pub principal: u64,
    /// The claimant's device key, for the publish class's signed session
    /// and the `attest` an edition's mint and a shot carry on a claimed
    /// board.
    signer: Option<Box<dyn Signer>>,
    /// The `tempfile` directory the board's data, the key store and the
    /// anchors live in — under the system temp dir, removed with the value,
    /// after the daemon above has stopped.
    pub root: PathBuf,
    _tmp: TempDir,
}

/// What one feed measured, beside the units it delivered.
#[derive(Debug, Clone)]
pub struct Fed {
    pub units: Vec<Unit>,
    /// The documents' names, one per unit in order — a tier file's path, or
    /// `cut-NNNNN`.
    pub names: Vec<String>,
    /// The `create_new_document` round trips, summed.
    pub mint_time: Duration,
    /// The `insert` round trips, summed — the board's time apart from the index's.
    pub insert_time: Duration,
    /// The `retrieve_doc_v_span_set` and `retrieve_v` round trips, summed.
    pub read_time: Duration,
    /// The `retrieve_v` frames made.
    pub reads: u64,
    /// The documents read in more than one part.
    pub in_parts: u64,
    /// The principal whose session read the units, and its account.
    pub principal: u64,
    pub account: String,
    /// The documents the board REFUSED to hold — a chunk's `insert` answered
    /// a rejection, its code and detail here beside the document's name —
    /// whose units entered the index directly from the corpus's bytes.
    pub refused: Vec<(String, String)>,
    /// Whether the units came from the cache, fed by an earlier test.
    pub cached: bool,
}

impl Fed {
    /// The bytes of text over the units.
    pub fn bytes(&self) -> u64 {
        self.units.iter().map(Unit::bytes).sum()
    }
}

fn spawn_daemon(dir: &Path) -> Skepd {
    const ATTEMPTS: usize = 12;
    for _ in 0..ATTEMPTS {
        let reserved = TcpListener::bind(("127.0.0.1", 0)).expect("reserve an ephemeral port");
        let port = reserved.local_addr().expect("reserved local addr").port();
        let origin = skepd::Origin::parse(&format!("http://127.0.0.1:{port}"))
            .expect("a canonical loopback origin");
        let mut opts = AuthOptions::default();
        opts.local_trust = true;
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
                    assert!(
                        Instant::now() < deadline,
                        "the cell index's walk did not complete within 60 s"
                    );
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

fn board_at(port: u16) -> Board {
    let origin =
        skep_client::Origin::parse(&format!("http://127.0.0.1:{port}")).expect("canonical");
    Board::new(origin, PlainHttp::new())
}

fn bare(board: &Board, principal: u64) -> Token {
    match board.session_open(SessionBody::Bare { principal }).expect("bare session") {
        Opened::Token(t) => t,
        other => panic!("the bare bind answered {other:?}"),
    }
}

impl DevBoard {
    /// A CLAIMED dev board under a fresh temp directory, as the suites claim
    /// theirs: the notebook walk run over the wire with the scripted person,
    /// the device key generated into a store under the directory, the two
    /// anchors written beside it; then a bare session as the claimant, under
    /// which the documents are written and read.
    pub fn spawn() -> DevBoard {
        let tmp = tempfile::tempdir().expect("a temp dir under the system temp dir");
        let root = tmp.path().to_path_buf();
        let sd = spawn_daemon(&root.join("board"));
        let board = board_at(sd.port());
        let store = FileStore::open(root.join("store"));
        store
            .generate(Some(Label::new("notebook").expect("a label in the domain")))
            .expect("the device key generated");
        let anchors = root.join("anchors");
        let opts = NotebookOptions {
            principal: None,
            display_name: Some("the budgets suite".into()),
            anchor_out: vec![anchors.join("a"), anchors.join("b")],
            paper: false,
            host_name: "budgets".into(),
            date: "2026-10-07".into(),
        };
        let mut person = Scripted::new(vec![Script::LabelDefault, Script::LabelDefault]);
        let outcome = claim::notebook(&board, &store, &mut person, &opts)
            .unwrap_or_else(|h| panic!("the claim halted: {h}\n{}", person.transcript.join("\n")));
        let done = match outcome {
            ClaimOutcome::Ours(done) => done,
            ClaimOutcome::Stranger { claimant } => panic!("a stranger's board: {claimant}"),
        };
        let token = bare(&board, done.principal);
        let device = store.load(&store.key_path(&done.fingerprint)).expect("the device key file");
        let signer: Box<dyn Signer> = Box::new(device.signer());
        DevBoard {
            sd,
            board,
            token,
            account: done.account,
            principal: done.principal,
            signer: Some(signer),
            root,
            _tmp: tmp,
        }
    }

    /// A FULL signed session under the claimant's device key — the publish
    /// class's door on a claimed board (wire.md §Sessions; the client's own
    /// handshake).
    pub fn signed(&self) -> Session<'_> {
        let signer = self.signer.as_ref().expect("a claimed board has its device key");
        handshake(&self.board, Scope::Full, signer.as_ref(), self.principal, Site::Session)
            .expect("the signed session")
    }

    /// The `attest` member over `body` for a write whose `doc` row is `doc`:
    /// the entry frame under `H.1`'s pair, the account and the row, signed by
    /// the device key (wire.md §Arrangement; skep-identity's `entry_frame`).
    fn attest(&self, doc: &Address, body: &EntryBody) -> Value {
        let signer = self.signer.as_ref().expect("the device key");
        let term = self
            .board
            .board_term()
            .expect("the board term read")
            .expect("H.1 stands on a claimed board");
        let account = parse_addr(&self.account);
        let frame = entry_frame(signer.public_key().alg(), term, &account, DocTerm::One(doc), body);
        json!({"alg": signer.public_key().alg(), "sig": sig_hex(&signer.sign(&frame))})
    }

    fn acked_signed(signed: &Session<'_>, frame: &Value) -> Value {
        let v = Self::document_of(signed.op(frame));
        assert!(
            matches!(v["resp"].as_str(), Some("ack" | "ack_addr")),
            "the board refused the attested {}: {v}",
            frame["op"]
        );
        v
    }

    /// An EDITION: `create_new_document` born published into the account,
    /// attested over the empty body, from the signed session.
    pub fn create_edition(&self, signed: &Session<'_>) -> Address {
        let account = parse_addr(&self.account);
        let mut frame =
            json!({"op": "create_new_document", "account": self.account, "published": true});
        frame["attest"] =
            self.attest(&account, &entry_body_empty(ContentFreeOp::CreateNewDocument));
        let v = Self::acked_signed(signed, &frame);
        parse_addr(acked_addr(&v).expect("a minted address"))
    }

    /// THE SHOT, attested: the next member of `doc`'s chain whose arrangement
    /// is `runs`, each a WINDOW onto another document's I-space — `(i_start,
    /// width)`, its origin the document that minted the address — so the
    /// signed body is the windows alone; `base` the member staged from with
    /// its extent, or none for the birth version. The member's address.
    pub fn publish_windows(
        &self,
        signed: &Session<'_>,
        doc: &Address,
        base: Option<(&Address, u64)>,
        runs: &[(Address, u64)],
    ) -> Address {
        let pieces = runs.iter().map(|(start, width)| ShotSegmentPiece::Window {
            start,
            width: NonZeroU64::new(*width).expect("a run has width"),
        });
        let body =
            entry_body_publish(pieces, base.map(|(member, extent)| ShotBase { member, extent }));
        let mut frame = json!({
            "op": "publish",
            "doc": doc.to_string(),
            "runs": runs
                .iter()
                .map(|(start, width)| {
                    let start = start.to_string();
                    json!({"origin": origin_of(&start), "i_start": start, "width": width.to_string()})
                })
                .collect::<Vec<_>>(),
        });
        if let Some((member, extent)) = base {
            frame["base"] = Value::String(member.to_string());
            frame["base_extent"] = Value::String(extent.to_string());
        }
        frame["attest"] = self.attest(doc, &body);
        let v = Self::acked_signed(signed, &frame);
        parse_addr(acked_addr(&v).expect("the member's address"))
    }

    pub fn port(&self) -> u16 {
        self.sd.port()
    }

    fn document_of(answer: Result<Answer, skep_client::Halt>) -> Value {
        match answer.expect("the exchange") {
            Answer::Document(v) => v,
            Answer::Closed => panic!("the session was closed"),
        }
    }

    /// One frame under the session; the response document.
    pub fn op(&self, frame: &Value) -> Value {
        Self::document_of(self.board.op(Some(&self.token), frame))
    }

    /// One frame under the session that must be acked; the ack.
    fn acked(&self, frame: &Value) -> Value {
        let v = self.op(frame);
        assert!(
            matches!(v["resp"].as_str(), Some("ack" | "ack_addr")),
            "the board refused {}: {v}",
            frame["op"]
        );
        v
    }

    /// `create_new_document` into the account — flagless, a private draft
    /// (the home at the account's first mint); `Some(true)` a published
    /// document, admitted from a bare session below the claim alone.
    pub fn create(&self, published: Option<bool>) -> Address {
        let mut frame = json!({"op": "create_new_document", "account": self.account});
        if let Some(flag) = published {
            frame["published"] = Value::Bool(flag);
        }
        let v = self.acked(&frame);
        parse_addr(acked_addr(&v).expect("a minted address"))
    }

    /// `insert` of `bytes` PER-BYTE at content ordinal `ordinal` of `doc` —
    /// the `str` form where the bytes are UTF-8, else `{"hex"}` — in frames of
    /// at most [`INSERT_CHUNK`] bytes at consecutive ordinals. The last ack's
    /// position, or the board's refusal — its `code: detail` — at the first
    /// chunk refused.
    pub fn try_insert(&self, doc: &Address, ordinal: u64, bytes: &[u8]) -> Result<u64, String> {
        let mut at = 0;
        let mut from = 0usize;
        let mut ordinal = ordinal;
        while from < bytes.len() {
            let mut end = (from + INSERT_CHUNK).min(bytes.len());
            let value = match std::str::from_utf8(bytes) {
                Ok(text) => {
                    while !text.is_char_boundary(end) {
                        end -= 1;
                    }
                    Value::String(text[from..end].to_string())
                }
                Err(_) => json!({"hex": hex(&bytes[from..end])}),
            };
            let frame = json!({
                "op": "insert",
                "doc": doc.to_string(),
                "at": {"subspace": "1", "ordinal": ordinal.to_string()},
                "values": [value],
            });
            let v = self.op(&frame);
            if v["resp"].as_str() != Some("ack_addr") {
                return Err(format!(
                    "{}: {}",
                    v["code"].as_str().unwrap_or("?"),
                    v["detail"].as_str().unwrap_or("")
                ));
            }
            at = acked_at(&v).expect("an ack carries at");
            ordinal += (end - from) as u64;
            from = end;
        }
        Ok(at)
    }

    /// [`DevBoard::try_insert`], a refusal a fault.
    pub fn insert(&self, doc: &Address, ordinal: u64, bytes: &[u8]) -> u64 {
        self.try_insert(doc, ordinal, bytes)
            .unwrap_or_else(|refusal| panic!("the board refused the insert into {doc}: {refusal}"))
    }

    /// `copy`: `width` positions of `source` from content ordinal `from`
    /// transcluded into `doc` at content ordinal `at` — shared identity, one
    /// run of the destination's arrangement per call. The ack's position.
    pub fn copy(&self, doc: &Address, at: u64, source: &Address, from: u64, width: u64) -> u64 {
        let frame = json!({
            "op": "copy",
            "doc": doc.to_string(),
            "at": {"subspace": "1", "ordinal": at.to_string()},
            "specs": [{"source": source.to_string(), "span": {"start": format!("1.{from}"), "width": format!("0.{width}")}}],
        });
        let v = self.acked(&frame);
        acked_at(&v).expect("an ack carries at")
    }

    /// The content extent of `doc`: `retrieve_doc_v_span_set`'s `1.1` span
    /// width, zero where it holds no content.
    pub fn extent(&self, doc: &Address) -> u64 {
        let v = self.op(&frames::span_set(&doc.to_string()));
        assert_eq!(v["resp"].as_str(), Some("span_set"), "{v}");
        v["set"]
            .as_array()
            .expect("a set")
            .iter()
            .find(|s| s["start"].as_str() == Some("1.1"))
            .map(|s| {
                s["width"]
                    .as_str()
                    .expect("a width")
                    .strip_prefix("0.")
                    .expect("a depth-2 width")
                    .parse()
                    .expect("a count")
            })
            .unwrap_or(0)
    }

    /// One `retrieve_v` over content ordinals `from ..` of `doc`, `width` of
    /// them: the delivery's items as the crate's typed items from `from`, and
    /// the delivery's `as_of`.
    pub fn retrieve(&self, doc: &Address, from: u64, width: u64) -> (Vec<Item>, u64) {
        let v = self.op(&frames::retrieve_v(&doc.to_string(), from, width));
        assert_eq!(v["resp"].as_str(), Some("delivery"), "retrieve_v {doc} {from}+{width}: {v}");
        let as_of = v["as_of"].as_u64().expect("as_of");
        let mut start = from;
        let mut items = Vec::new();
        for item in v["items"].as_array().expect("items") {
            let typed = if let Some(text) = item["content"].as_str() {
                Item::Text { start, bytes: text.as_bytes().to_vec() }
            } else if let Some(h) = item["hex"].as_str() {
                Item::Text { start, bytes: unhex(h) }
            } else if item.get("atom").is_some() || item.get("atom_hex").is_some() {
                Item::Gap { start, width: 1, kind: GapKind::Atom }
            } else if let Some(w) = item.get("withheld") {
                let width: u64 = w["width"].as_str().expect("a width").parse().expect("a count");
                let origin = parse_addr(w["origin"].as_str().expect("an origin"));
                Item::Gap { start, width, kind: GapKind::Withheld { origin } }
            } else {
                let width = item["width"].as_str().and_then(|w| w.parse().ok()).unwrap_or(1);
                Item::Gap { start, width, kind: GapKind::Unknown }
            };
            start += typed.width();
            items.push(typed);
        }
        (items, as_of)
    }

    /// THE UNIT of `doc` as the shell reads it (§2.1): `retrieve_v` over the
    /// whole content extent, in consecutive parts of at most
    /// `MAX_DELIVERY_ITEMS` positions where it holds more, the parts joined
    /// by `Unit::new`, `as_of` the last part's. Answers the unit and the
    /// parts read.
    pub fn read_unit(&self, doc: &Address, kind: Kind, member: Option<Address>) -> (Unit, u64) {
        let extent = self.extent(doc);
        let mut items = Vec::new();
        let mut as_of = 0;
        let mut parts = 0;
        let mut from = 1;
        while from <= extent {
            let width = MAX_DELIVERY_ITEMS.min(extent - from + 1);
            let (part, at) = self.retrieve(doc, from, width);
            items.extend(part);
            as_of = at;
            parts += 1;
            from += width;
        }
        let class = Class::Principal(self.principal);
        let unit = Unit::new(UnitKey::new(doc.clone()), member, kind, class, as_of, items)
            .expect("the parts are one contiguous extent");
        (unit, parts)
    }

    /// THE FEED: every document minted as a draft, its text inserted
    /// per-byte, then read back over the wire into one unit each — the round
    /// trip ASSERTED byte-exact (§7.3's fence) — the board's times kept apart.
    pub fn feed(&self, docs: &[Document]) -> Fed {
        let mut mint_time = Duration::ZERO;
        let mut insert_time = Duration::ZERO;
        let mut addresses = Vec::with_capacity(docs.len());
        let mut refused: Vec<(String, String)> = Vec::new();
        for doc in docs {
            let t = Instant::now();
            let address = self.create(None);
            mint_time += t.elapsed();
            let t = Instant::now();
            let landed = self.try_insert(&address, 1, &doc.bytes);
            insert_time += t.elapsed();
            if let Err(refusal) = landed {
                refused.push((doc.name.clone(), refusal));
            }
            addresses.push(address);
        }
        let mut units = Vec::with_capacity(docs.len());
        let mut read_time = Duration::ZERO;
        let mut reads = 0;
        let mut in_parts = 0;
        let class = Class::Principal(self.principal);
        for (doc, address) in docs.iter().zip(&addresses) {
            if refused.iter().any(|(name, _)| *name == doc.name) {
                // The board refused this document: its unit enters directly,
                // in the shape the board's units take.
                let item = Item::Text { start: 1, bytes: doc.bytes.clone() };
                let unit = Unit::new(
                    UnitKey::new(address.clone()),
                    Some(address.clone()),
                    Kind::Draft,
                    class,
                    0,
                    vec![item],
                )
                .expect("one item");
                units.push(unit);
                continue;
            }
            let t = Instant::now();
            let (unit, parts) = self.read_unit(address, Kind::Draft, Some(address.clone()));
            read_time += t.elapsed();
            reads += parts;
            if parts > 1 {
                in_parts += 1;
            }
            let delivered: Vec<u8> = unit
                .items()
                .iter()
                .filter_map(|i| match i {
                    Item::Text { bytes, .. } => Some(bytes.as_slice()),
                    Item::Gap { .. } => None,
                })
                .flatten()
                .copied()
                .collect();
            assert!(
                delivered == doc.bytes,
                "§7.3: the unit read back for `{}` is not the document's bytes ({} against {})",
                doc.name,
                delivered.len(),
                doc.bytes.len()
            );
            units.push(unit);
        }
        Fed {
            units,
            names: docs.iter().map(|d| d.name.clone()).collect(),
            mint_time,
            insert_time,
            read_time,
            reads,
            in_parts,
            principal: self.principal,
            account: self.account.clone(),
            refused,
            cached: false,
        }
    }

    /// `/health`'s `(log_position, chain_head)` pair.
    pub fn health_pair(&self) -> ChainAt {
        let health = self.board.health().expect("health");
        let chain = Chain::parse(health.body["chain_head"].as_str().expect("chain_head"))
            .expect("64 lowercase hex");
        ChainAt { position: health.log_position(), chain }
    }

    /// `H.1`'s chain — the board's key (§5.2) — where the board has one.
    pub fn board_chain(&self) -> Option<Chain> {
        self.board.board_term().expect("the board term read").map(|t| Chain::from_bytes(t.chain))
    }

    /// `GET /chain?at=<at>`: the status, the chain where answered, and the
    /// round trip's time — the time the read held a reconstruction permit.
    pub fn chain_at(&self, at: u64) -> (u16, Option<Chain>, Duration) {
        let t = Instant::now();
        let resp =
            self.board.exchange(&Request::get(format!("/chain?at={at}"))).expect("the exchange");
        let took = t.elapsed();
        let chain = (resp.status == 200)
            .then(|| serde_json::from_slice::<Value>(&resp.body).ok())
            .flatten()
            .and_then(|v| v["chain"].as_str().and_then(Chain::parse));
        (resp.status, chain, took)
    }

    /// The journal's RECLAIM FLOOR — the oldest position `/chain?at` still
    /// answers — read off `/chain?at=0`'s `410 history_reclaimed` body; `0`
    /// where genesis is still retained.
    pub fn reclaim_floor(&self) -> u64 {
        let resp = self.board.exchange(&Request::get("/chain?at=0")).expect("the exchange");
        if resp.status == 200 {
            return 0;
        }
        assert_eq!(resp.status, 410, "/chain?at=0: {}", String::from_utf8_lossy(&resp.body));
        serde_json::from_slice::<Value>(&resp.body)
            .ok()
            .and_then(|v| v["floor"].as_u64())
            .unwrap_or(0)
    }

    /// `POST /op-at`: `retrieve_v` over content ordinals `from ..` of `doc`
    /// as of `at`, under the session.
    pub fn op_at_retrieve(&self, at: u64, doc: &Address, from: u64, width: u64) -> AtAnswer {
        self.board
            .op_at(Some(&self.token), at, &frames::retrieve_v(&doc.to_string(), from, width))
            .expect("the exchange")
    }

    /// `image` over content ordinals `from ..` of `doc`: the V→I runs as
    /// `(i_start, width)`, and the round trip's time.
    pub fn image(&self, doc: &Address, from: u64, width: u64) -> (Vec<(String, u64)>, Duration) {
        let t = Instant::now();
        let v = self.op(&frames::image(&doc.to_string(), from, width));
        let took = t.elapsed();
        assert_eq!(v["resp"].as_str(), Some("runs"), "image {doc} {from}+{width}: {v}");
        let runs = v["runs"]
            .as_array()
            .expect("runs")
            .iter()
            .map(|r| {
                (
                    r["i_start"].as_str().expect("i_start").to_string(),
                    r["width"].as_str().expect("width").parse().expect("a count"),
                )
            })
            .collect();
        (runs, took)
    }

    /// `compare` between `rho1` — `(doc, from, width)` — and `rho2`: the
    /// response document (the pairs, or a refusal) and the round trip's time.
    pub fn compare(
        &self,
        rho1: (&Address, u64, u64),
        rho2: (&Address, u64, u64),
    ) -> (Value, Duration) {
        let region = |(doc, from, width): (&Address, u64, u64)| json!({"doc": doc.to_string(), "spans": [{"start": format!("1.{from}"), "width": format!("0.{width}")}]});
        let frame = json!({"op": "compare", "rho1": [region(rho1)], "rho2": [region(rho2)]});
        let t = Instant::now();
        let v = self.op(&frame);
        (v, t.elapsed())
    }
}

// ── THE CACHE ─────────────────────────────────────────────────────────────

/// The cache directory under the system temp dir.
pub fn cache_dir() -> PathBuf {
    std::env::temp_dir().join("skep-search-budgets")
}

/// The cache file of one tier.
fn cache_path(tier: &str) -> PathBuf {
    cache_dir().join(format!("{PIN}-{CUT_RULE}-{tier}.units"))
}

fn put_u64(out: &mut Vec<u8>, n: u64) {
    out.extend_from_slice(&n.to_le_bytes());
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    put_u64(out, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    fn u64(&mut self) -> u64 {
        let n = u64::from_le_bytes(self.bytes[self.at..self.at + 8].try_into().expect("8 bytes"));
        self.at += 8;
        n
    }

    fn u8(&mut self) -> u8 {
        let b = self.bytes[self.at];
        self.at += 1;
        b
    }

    fn bytes(&mut self) -> &'a [u8] {
        let len = self.u64() as usize;
        let out = &self.bytes[self.at..self.at + len];
        self.at += len;
        out
    }

    fn str(&mut self) -> &'a str {
        std::str::from_utf8(self.bytes()).expect("UTF-8 in the cache")
    }
}

fn encode(fed: &Fed) -> Vec<u8> {
    let mut out = CACHE_MAGIC.to_vec();
    put_u64(&mut out, fed.mint_time.as_nanos() as u64);
    put_u64(&mut out, fed.insert_time.as_nanos() as u64);
    put_u64(&mut out, fed.read_time.as_nanos() as u64);
    put_u64(&mut out, fed.reads);
    put_u64(&mut out, fed.in_parts);
    put_u64(&mut out, fed.principal);
    put_bytes(&mut out, fed.account.as_bytes());
    put_u64(&mut out, fed.units.len() as u64);
    for (unit, name) in fed.units.iter().zip(&fed.names) {
        put_bytes(&mut out, name.as_bytes());
        put_bytes(&mut out, unit.key().doc().to_string().as_bytes());
        match unit.member() {
            Some(m) => {
                out.push(1);
                put_bytes(&mut out, m.to_string().as_bytes());
            }
            None => out.push(0),
        }
        out.push(match unit.kind() {
            Kind::Edition => 0,
            Kind::Draft => 1,
        });
        match unit.class() {
            Class::Guest => {
                out.push(0);
                put_u64(&mut out, 0);
            }
            Class::Principal(n) => {
                out.push(1);
                put_u64(&mut out, n);
            }
        }
        put_u64(&mut out, unit.as_of());
        put_u64(&mut out, unit.items().len() as u64);
        for item in unit.items() {
            match item {
                Item::Text { start, bytes } => {
                    out.push(0);
                    put_u64(&mut out, *start);
                    put_bytes(&mut out, bytes);
                }
                Item::Gap { start, width, kind } => {
                    match kind {
                        GapKind::Atom => out.push(1),
                        GapKind::Withheld { .. } => out.push(2),
                        GapKind::Unknown => out.push(3),
                    }
                    put_u64(&mut out, *start);
                    put_u64(&mut out, *width);
                    if let GapKind::Withheld { origin } = kind {
                        put_bytes(&mut out, origin.to_string().as_bytes());
                    }
                }
            }
        }
    }
    // The refused documents, appended: a cache without the section holds none.
    put_u64(&mut out, fed.refused.len() as u64);
    for (name, refusal) in &fed.refused {
        put_bytes(&mut out, name.as_bytes());
        put_bytes(&mut out, refusal.as_bytes());
    }
    out
}

fn decode(bytes: &[u8]) -> Option<Fed> {
    if !bytes.starts_with(CACHE_MAGIC) {
        return None;
    }
    let mut c = Cursor { bytes, at: CACHE_MAGIC.len() };
    let mint_time = Duration::from_nanos(c.u64());
    let insert_time = Duration::from_nanos(c.u64());
    let read_time = Duration::from_nanos(c.u64());
    let reads = c.u64();
    let in_parts = c.u64();
    let principal = c.u64();
    let account = c.str().to_string();
    let count = c.u64() as usize;
    let mut units = Vec::with_capacity(count);
    let mut names = Vec::with_capacity(count);
    for _ in 0..count {
        names.push(c.str().to_string());
        let doc = parse_addr(c.str());
        let member = (c.u8() == 1).then(|| parse_addr(c.str()));
        let kind = if c.u8() == 0 { Kind::Edition } else { Kind::Draft };
        let class = {
            let tag = c.u8();
            let n = c.u64();
            if tag == 0 {
                Class::Guest
            } else {
                Class::Principal(n)
            }
        };
        let as_of = c.u64();
        let items = c.u64() as usize;
        let mut typed = Vec::with_capacity(items);
        for _ in 0..items {
            let tag = c.u8();
            let start = c.u64();
            typed.push(match tag {
                0 => Item::Text { start, bytes: c.bytes().to_vec() },
                1 => Item::Gap { start, width: c.u64(), kind: GapKind::Atom },
                2 => {
                    let width = c.u64();
                    let origin = parse_addr(c.str());
                    Item::Gap { start, width, kind: GapKind::Withheld { origin } }
                }
                _ => Item::Gap { start, width: c.u64(), kind: GapKind::Unknown },
            });
        }
        units.push(
            Unit::new(UnitKey::new(doc), member, kind, class, as_of, typed).expect("one extent"),
        );
    }
    let mut refused = Vec::new();
    if c.at < bytes.len() {
        for _ in 0..c.u64() {
            let name = c.str().to_string();
            let refusal = c.str().to_string();
            refused.push((name, refusal));
        }
    }
    Some(Fed {
        units,
        names,
        mint_time,
        insert_time,
        read_time,
        reads,
        in_parts,
        principal,
        account,
        refused,
        cached: true,
    })
}

/// Forget a tier's cache, so the next [`fed`] feeds anew.
pub fn forget(tier: &str) {
    let _ = std::fs::remove_file(cache_path(tier));
}

/// The units of `tier`: from the cache where an earlier test fed them, else
/// fed now through a fresh dev board — `docs` built only then — and cached.
pub fn fed(tier: &str, docs: impl FnOnce() -> Vec<Document>) -> Fed {
    let path = cache_path(tier);
    if let Ok(bytes) = std::fs::read(&path) {
        if let Some(fed) = decode(&bytes) {
            return fed;
        }
    }
    let docs = docs();
    std::fs::create_dir_all(cache_dir()).expect("the cache dir");
    let board = DevBoard::spawn();
    let fed = board.feed(&docs);
    drop(board);
    let tmp = path.with_extension("tmp");
    std::fs::File::create(&tmp)
        .and_then(|mut f| f.write_all(&encode(&fed)))
        .and_then(|()| std::fs::rename(&tmp, &path))
        .expect("the cache written");
    fed
}

/// The cache's whole contents re-read: the fence that the codec is exact.
pub fn roundtrip(fed: &Fed) -> Fed {
    let mut bytes = Vec::new();
    bytes.extend(encode(fed));
    let mut back = Vec::new();
    (&bytes[..]).read_to_end(&mut back).expect("read");
    decode(&back).expect("the cache decodes")
}
