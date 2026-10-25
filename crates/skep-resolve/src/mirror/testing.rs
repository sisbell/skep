//! What the mirror's tests share: the hint they are scoped to, a key, a
//! mirror over a board a test holds fixed, and A SCRIPTED BOARD — a feed of
//! deposits a test writes row by row ([`Script`]), served with the stored
//! links, the record atoms and the `H.1` term a mirror fetches, every record
//! signed at the record grade by the hand the test names, as the daemon's
//! own composer frames it — so the suite can plant what a conforming daemon
//! refuses (REG-5.9's operator) and withhold what a transport may.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde_json::{json, Value};
use skep_address::Address;
use skep_identity::{canonical_record, BoardTerm, Enrollment, Fingerprint, PublicKey, RecordFrame, RecordRows};
use skep_registry::{commons_type, encode, t_binding, t_endpoint, Binding, Body, Endpoint, Origins};
use skep_signature::{HybridSigner, TAG_MLDSA65_ED25519};

use super::{account_of_document, Mirror};
use crate::board::{unit_span_json, Board};
use crate::hint::{RealmId, RootHint};
use crate::http::{Method, Transport, TransportError};
use crate::origin::Origin;
use crate::parse_address;

/// The tag-1 hybrid signer whose seed is the byte `seed`, thirty-two times.
pub(super) fn signer(seed: u8) -> HybridSigner {
    HybridSigner::from_seed(TAG_MLDSA65_ED25519, &[seed; 32]).expect("tag 1")
}

/// The tag-1 hybrid key whose seed is the byte `seed`, thirty-two times.
pub(super) fn key(seed: u8) -> PublicKey {
    signer(seed).public_key().clone()
}

/// The hint every mirror below is opened or rebuilt under: one origin, at a
/// port no board answers, and the genesis fingerprint `ab`×32 the copies the
/// tests write name.
pub(super) fn hint() -> RootHint {
    hint_of(Fingerprint::parse_hex(&"ab".repeat(32)).unwrap())
}

/// A hint at an origin no board answers, naming `genesis`.
pub(super) fn hint_of(genesis: Fingerprint) -> RootHint {
    RootHint::new(vec![Origin::parse("http://127.0.0.1:1").unwrap()], genesis, None).unwrap()
}

/// The realm a board whose claimant's genesis set is `keys` belongs to
/// (REG-3.39).
pub(super) fn realm_of(keys: &[&PublicKey]) -> Fingerprint {
    RealmId::genesis_fingerprint(&keys.iter().map(|k| Fingerprint::of(k)).collect::<Vec<_>>())
}

/// A mirror over `board` under `dir`, at no root: every read a pull, a fold
/// or a fetch makes, the board alone answers.
pub(super) fn over(board: impl Transport + 'static, dir: &Path) -> Mirror {
    over_hint(board, dir, &hint())
}

/// [`over`] under `hint`, whose realm a scripted board's claimant must match.
pub(super) fn over_hint(board: impl Transport + 'static, dir: &Path, hint: &RootHint) -> Mirror {
    Mirror::fresh(hint, None, Some(Board::new(Box::new(board))), dir)
}

/// A 200 answer of `v`.
pub(super) fn answer(v: Value) -> Result<(u16, Vec<u8>), TransportError> {
    Ok((200, v.to_string().into_bytes()))
}

/// A span over one address as `read_link` answers a slot.
pub(super) fn span(start: &str) -> Value {
    json!({ "start": start, "width": "0.1" })
}

/// The board term every scripted record is signed under: `H.1`'s pair.
pub(super) const TERM: BoardTerm = BoardTerm { log_position: 1, chain: [7; 32] };

/// `H.1`'s address, the member whose first atom carries the board term.
const HEAD_MEMBER_1: &str = "1.1.0.1.0.2.1";

fn a(s: &str) -> Address {
    parse_address(s).unwrap_or_else(|| panic!("{s} is an address"))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A record text SIGNED at the record grade by `hand` for a deposit in
/// `home` typed `ty` naming `to`: the frame the daemon composes — `H.1`'s
/// pair, the home's account by address arithmetic, the home, the type, the
/// target, the sig-less canonical body — under the hand's own token.
pub(super) fn sign(hand: &HybridSigner, home: &Address, ty: &Address, to: &[Address], sigless: &str) -> String {
    let home_account = account_of_document(home).expect("a doc 1's account");
    let frame = RecordFrame {
        board: TERM,
        home_account: &home_account,
        home,
        rows: RecordRows { ty, to, replaces: None, lineage_fork_point: None, sigless_canonical_record: sigless.as_bytes() },
    };
    hex(&hand.sign(&frame.to_bytes(hand.public_key().alg())))
}

/// An enroll record of `keys`, each under its anchor flag, for a deposit in
/// `home` naming `to` — signed by `hand` where one is given, sig-less where
/// none is (a pre-claim genesis, or an operator's plant).
pub(super) fn enroll_text(hand: Option<&HybridSigner>, home: &Address, to: &Address, keys: &[(&PublicKey, bool)]) -> String {
    let entries: Vec<Enrollment> = keys.iter().map(|(k, anchor)| Enrollment::new((*k).clone(), *anchor, None).expect("no label")).collect();
    let sigless = canonical_record(&entries, None);
    let sig = hand.map(|h| sign(h, home, &commons_type(&[1]), std::slice::from_ref(to), &sigless));
    canonical_record(&entries, sig.as_deref())
}

/// A retire record of `fps`, signed by `hand`, for a deposit in `home`
/// naming `to`.
pub(super) fn retire_text(hand: &HybridSigner, home: &Address, to: &Address, fps: &[Fingerprint]) -> String {
    let sigless = canonical_record(fps, None);
    let sig = sign(hand, home, &commons_type(&[2]), std::slice::from_ref(to), &sigless);
    canonical_record(fps, Some(&sig))
}

/// A binding of `prefix`, signed by `hand`, for a deposit in `home` naming
/// `to` — the account bound, or none at a retirement.
pub(super) fn binding_text(hand: &HybridSigner, home: &Address, to: &[Address], prefix: &Address) -> String {
    let body = Body::Binding(Binding { prefix: prefix.clone(), replaces: None });
    let sig = sign(hand, home, t_binding(), to, &encode(&body, None));
    encode(&body, Some(&sig))
}

/// An endpoint of `origins`, signed by `hand`, for a deposit in `home`.
pub(super) fn endpoint_text(hand: &HybridSigner, home: &Address, origins: &[&str]) -> String {
    let origins = Origins::new(origins.iter().map(|o| o.to_string()).collect()).expect("one origin or more");
    let body = Body::Endpoint(Endpoint { origins, replaces: None });
    let sig = sign(hand, home, t_endpoint(), &[], &encode(&body, None));
    encode(&body, Some(&sig))
}

/// How a scripted board answers `key_set`, on `/op` and `/op-at` alike: as a
/// read it does not answer — a panic naming it, so a mirror that asks fails
/// its test — or served the keys given, every one an anchor: the FOLD's table
/// as the board's operator has it, planted key included (REG-5.9).
pub(super) enum KeySetArm {
    Refused,
    Served(Vec<PublicKey>),
}

/// A feed of deposits a test writes, row by row, with what a mirror fetches
/// of each: the stored link's slots, the record atom at the home's next
/// content ordinal, the row at the next position.
pub(super) struct Script {
    rows: Vec<Value>,
    links: BTreeMap<String, Value>,
    atoms: BTreeMap<String, String>,
    ordinals: BTreeMap<String, u64>,
    link_ordinals: BTreeMap<String, u64>,
    position: u64,
}

impl Script {
    /// An empty feed: the first row lands at position 1.
    pub(super) fn new() -> Script {
        Script { rows: Vec::new(), links: BTreeMap::new(), atoms: BTreeMap::new(), ordinals: BTreeMap::new(), link_ordinals: BTreeMap::new(), position: 0 }
    }

    /// `text` deposited as the next atom of `home` and linked, typed `ty`, to
    /// `to` at the next position: the link's address.
    pub(super) fn deposit(&mut self, home: &Address, ty: &Address, to: &[Address], text: &str) -> Address {
        let ordinal = bump(&mut self.ordinals, home);
        let atom = format!("{home}.0.1.{ordinal}");
        self.atoms.insert(atom.clone(), text.to_string());
        self.link(home, deposit_slots(&atom, to, ty))
    }

    /// A claim link in the claimant's own doc 1 (AUTH-2.48): `from` the
    /// claimant, `to` empty, no atom.
    pub(super) fn claim(&mut self, claimant: &Address) -> Address {
        let home = a(&format!("{claimant}.0.1"));
        let slots = json!([[span(&claimant.to_string())], [], [unit_span_json(&commons_type(&[3]))]]);
        self.link(&home, slots)
    }

    /// A link of `slots` at `home`'s next link ordinal, its row at the next
    /// position.
    fn link(&mut self, home: &Address, slots: Value) -> Address {
        let k = bump(&mut self.link_ordinals, home);
        let link = format!("{home}.0.2.{k}");
        self.links.insert(link.clone(), slots);
        self.position += 1;
        self.rows.push(json!({ "at": self.position, "op": "make_link", "link": link, "docs": [home.to_string()] }));
        a(&link)
    }

    /// The feed's rows so far, as the board serves them.
    pub(super) fn rows(&self) -> Vec<Value> {
        self.rows.clone()
    }

    /// The board that serves this feed, `key_set` answered by `key_set`.
    pub(super) fn board(self, key_set: KeySetArm) -> ScriptedBoard {
        ScriptedBoard {
            rows: RefCell::new(self.rows),
            links: RefCell::new(self.links),
            atoms: RefCell::new(self.atoms),
            ordinals: RefCell::new(self.ordinals),
            link_ordinals: RefCell::new(self.link_ordinals),
            position: RefCell::new(self.position),
            withheld: RefCell::new(BTreeSet::new()),
            refuse_once: RefCell::new(BTreeSet::new()),
            key_set,
            asked: RefCell::new(Vec::new()),
        }
    }
}

/// `home`'s next ordinal in `of`, from 1.
fn bump(of: &mut BTreeMap<String, u64>, home: &Address) -> u64 {
    let n = of.entry(home.to_string()).or_insert(0);
    *n += 1;
    *n
}

/// A deposit link's slots as `read_link` serves them: its atom, its targets,
/// its type's unit span.
fn deposit_slots(atom: &str, to: &[Address], ty: &Address) -> Value {
    json!([[span(atom)], to.iter().map(|t| span(&t.to_string())).collect::<Vec<_>>(), [unit_span_json(ty)]])
}

/// A board holding a [`Script`]'s feed, every read a mirror makes answered
/// off it as the wire spells it: the pages, `/health`, `/chain`, `read_link`,
/// `retrieve_v` — `H.1`'s atom the board term — the span set, `image`, and
/// `key_set` by its arm; a read it does not hold is a panic naming it. Every
/// request is kept under `asked`, as `METHOD path op`.
pub(super) struct ScriptedBoard {
    rows: RefCell<Vec<Value>>,
    links: RefCell<BTreeMap<String, Value>>,
    atoms: RefCell<BTreeMap<String, String>>,
    ordinals: RefCell<BTreeMap<String, u64>>,
    link_ordinals: RefCell<BTreeMap<String, u64>>,
    position: RefCell<u64>,
    /// Atoms the board will not serve: `retrieve_v` refuses them at the head
    /// and as of any position, though the home's image places them.
    withheld: RefCell<BTreeSet<String>>,
    /// Links whose next `read_link` is refused `503`, once each.
    refuse_once: RefCell<BTreeSet<String>>,
    key_set: KeySetArm,
    pub(super) asked: RefCell<Vec<String>>,
}

impl ScriptedBoard {
    /// The board will not serve the atom at `address`.
    pub(super) fn withhold(&self, address: &Address) {
        self.withheld.borrow_mut().insert(address.to_string());
    }

    /// The next `read_link` of `link` is refused `503`.
    pub(super) fn refuse_link_once(&self, link: &Address) {
        self.refuse_once.borrow_mut().insert(link.to_string());
    }

    /// A further deposit on the live board, after a mirror has read it: the
    /// link's address, its row at the next position.
    pub(super) fn deposit(&self, home: &Address, ty: &Address, to: &[Address], text: &str) -> Address {
        let ordinal = bump(&mut self.ordinals.borrow_mut(), home);
        let atom = format!("{home}.0.1.{ordinal}");
        self.atoms.borrow_mut().insert(atom.clone(), text.to_string());
        let k = bump(&mut self.link_ordinals.borrow_mut(), home);
        let link = format!("{home}.0.2.{k}");
        self.links.borrow_mut().insert(link.clone(), deposit_slots(&atom, to, ty));
        let at = {
            let mut p = self.position.borrow_mut();
            *p += 1;
            *p
        };
        self.rows.borrow_mut().push(json!({ "at": at, "op": "make_link", "link": link, "docs": [home.to_string()] }));
        a(&link)
    }

    /// The content atoms of `doc`, by ordinal, where it holds any.
    fn extent_of(&self, doc: &str) -> Option<u64> {
        self.ordinals.borrow().get(doc).copied()
    }

    fn served(&self, frame: &Value) -> Value {
        let op = frame["op"].as_str().unwrap_or("");
        match op {
            "read_link" => {
                let link = frame["a"].as_str().expect("a link");
                match self.links.borrow().get(link) {
                    Some(slots) => json!({ "resp": "link", "link": { "slots": slots } }),
                    None => json!({ "resp": "link", "link": null }),
                }
            }
            "retrieve_v" => {
                let spec = &frame["specs"][0];
                let doc = spec["doc"].as_str().expect("a doc");
                let ordinal = spec["span"]["start"].as_str().and_then(|s| s.strip_prefix("1.")).and_then(|n| n.parse::<u64>().ok()).expect("an ordinal");
                if doc == HEAD_MEMBER_1 && ordinal == 1 {
                    let term = json!({ "position": TERM.log_position, "chain": hex(&TERM.chain) }).to_string();
                    return json!({ "resp": "delivery", "items": [{ "atom": term }] });
                }
                let address = format!("{doc}.0.1.{ordinal}");
                match self.atoms.borrow().get(&address) {
                    Some(text) if !self.withheld.borrow().contains(&address) => json!({ "resp": "delivery", "items": [{ "atom": text }] }),
                    _ => json!({ "resp": "rejected", "op": "retrieve_v", "code": "out_of_range" }),
                }
            }
            "retrieve_doc_v_span_set" => {
                let doc = frame["doc"].as_str().expect("a doc");
                match self.extent_of(doc) {
                    Some(extent) => json!({ "resp": "span_set", "set": [{ "start": "1.1", "width": format!("0.{extent}") }] }),
                    None => json!({ "resp": "rejected", "op": "retrieve_doc_v_span_set", "code": "doc_not_registered" }),
                }
            }
            "image" => {
                let doc = frame["d"].as_str().expect("a doc");
                let region = &frame["region"][0];
                let from = region["start"].as_str().and_then(|s| s.strip_prefix("1.")).and_then(|n| n.parse::<u64>().ok()).expect("a start");
                let width = region["width"].as_str().and_then(|s| s.strip_prefix("0.")).and_then(|n| n.parse::<u64>().ok()).expect("a width");
                let extent = self.extent_of(doc).unwrap_or(0);
                let runs: Vec<Value> = (from..from + width)
                    .filter(|n| *n >= 1 && *n <= extent)
                    .map(|n| json!({ "i_start": format!("{doc}.0.1.{n}"), "width": "1" }))
                    .collect();
                json!({ "resp": "runs", "runs": runs })
            }
            "key_set" => match &self.key_set {
                KeySetArm::Refused => panic!("the board was asked key_set, a read this reader never makes: {frame}"),
                KeySetArm::Served(keys) => {
                    let enrolled: Vec<Value> = keys.iter().map(|k| json!({ "alg": k.alg(), "key": k.to_hex(), "anchor": true })).collect();
                    json!({ "resp": "key_set", "as_of": *self.position.borrow(), "enrolled": enrolled })
                }
            },
            _ => panic!("a read this board does not answer: {frame}"),
        }
    }
}

impl Transport for ScriptedBoard {
    fn exchange(&self, method: Method, path: &str, body: &[u8]) -> Result<(u16, Vec<u8>), TransportError> {
        let head = *self.position.borrow();
        if let Some(query) = path.strip_prefix("/changes?since=") {
            self.asked.borrow_mut().push(format!("{method} {path}"));
            let since: u64 = query.split('&').next().unwrap_or("").parse().expect("a position");
            let rows: Vec<Value> = self.rows.borrow().iter().filter(|r| r["at"].as_u64() > Some(since)).cloned().collect();
            let last = rows.last().and_then(|r| r["at"].as_u64()).unwrap_or(since);
            return answer(json!({ "changes": rows, "last": last, "more": false }));
        }
        if path == "/health" {
            self.asked.borrow_mut().push(format!("{method} {path}"));
            return answer(json!({ "log_position": head, "chain_head": hex(&TERM.chain) }));
        }
        if let Some(at) = path.strip_prefix("/chain?at=") {
            self.asked.borrow_mut().push(format!("{method} {path}"));
            return answer(json!({ "at": at.parse::<u64>().expect("a position"), "chain": hex(&TERM.chain) }));
        }
        let request: Value = serde_json::from_slice(body).expect("a JSON body");
        let frame = if path == "/op-at" { request["frame"].clone() } else { request.clone() };
        self.asked.borrow_mut().push(format!("{method} {path} {}", frame["op"].as_str().unwrap_or("")));
        if frame["op"].as_str() == Some("read_link") {
            let link = frame["a"].as_str().expect("a link").to_string();
            if self.refuse_once.borrow_mut().remove(&link) {
                return Ok((503, b"unavailable".to_vec()));
            }
        }
        answer(self.served(&frame))
    }
}
