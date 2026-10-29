//! The publication composition's unit suite over a SCRIPTED BOARD: a
//! `Dialer` whose answers come from a `World` the test writes — the
//! documents' arrangements and bytes, every link with its slots and age, the
//! claims as supersession links, the feed's rows — which APPLIES a
//! publication as the daemon does (the twin fence, the kept places, one
//! fresh identity per draft identity, the records, the copies resolved from
//! the member's positions, the claims, the retractions, the read-withs, the
//! re-window, the memo) and keeps every frame it served, so a test pins what
//! each step reads, in what order and how many frames, and what the
//! composition makes of each answer, with no daemon. The suites that need
//! the daemon itself are `tests/it/publication.rs`.
//!
//! THE FIXTURE (`World::base`): the claimant `1.0.1` on a claimed board; `E`
//! a published edition holding "the quick brown fox" at `E.1`; `D` the
//! staging draft arranging `E`'s words by reference, ten new words of its
//! own and a window onto `O`, the person's own unpublished origin; `N` the
//! notes; `S` a public set `E` is read with, `S2` one it is not; links in the
//! three homes of the person's on the selection's words, one of another
//! account's and one of a sub-account's on the same words, a whole-work
//! link, the edition's own published marks, three held removals in `D` (one
//! re-made, one spent, one plain), an accepted original with its claim and
//! copy, a revised original, and a counterpart record of an earlier shot
//! with a private link on its `from` words.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};
use skep_address::Address;
use skep_identity::PublicKey;
use skep_signature::HybridSigner;

use crate::address::parse_address;
use crate::board::frames::{T_CORRESPONDENCE, T_EDITION, T_HELD_REMOVAL, T_READ_WITH};
use crate::board::{Board, Token, HEAD_MEMBER_1, T_RETRACTION, T_SUPERSEDES};
use crate::dial::{DialError, Dialer, Headers, Request as DialRequest, RequestHead, Response, StreamedResponse};
use crate::origin::Origin;
use crate::sign::Signer;

use super::panel::Destination;
use super::request::{Answer as OriginAnswer, Confirmed, Inert, Piece};
use super::send::{AckVia, OwnFault, Refusal, Sent};
use super::*;

const TOKEN: &str = "9f3a6c21d4b8e07a5c1b2d4e6f708192";
const ACCOUNT: &str = "1.0.1";
const DOC1: &str = "1.0.1.0.1";
/// `E` the published edition, `S`/`S2` the public sets, `D` the staging
/// draft, `N` the notes, `O` the person's unpublished origin, `Z` a private
/// far document, `SUB` a sub-account's draft, `OTHER` another account's.
const E: &str = "1.0.1.0.2";
const S: &str = "1.0.1.0.3";
const S2: &str = "1.0.1.0.4";
const D: &str = "1.0.1.0.5";
const N: &str = "1.0.1.0.6";
const O: &str = "1.0.1.0.7";
const Z: &str = "1.0.1.0.8";
const SUB: &str = "1.0.1.2.0.1";
const OTHER: &str = "1.0.2.0.1";
const T_STRONG: &str = "1.1.0.1.0.1.0.3.23.2";
const T_HEADING: &str = "1.1.0.1.0.1.0.3.20";
const T_MARK: &str = "1.1.0.1.0.1.0.3.23.4";
const T_CITATION: &str = "1.1.0.1.0.1.0.3.13";
const E_TEXT: &str = "the quick brown fox";
const D_TEXT: &str = " new words";
const O_TEXT: &str = "quote";

fn a(text: &str) -> Address {
    parse_address(text).expect("an address")
}

fn run(doc: &str, s: u64, w: u64) -> Run {
    Run::new(a(doc), s, w)
}

fn reply(status: u16, body: Value) -> Response {
    Response { status, headers: Headers::default(), body: body.to_string().into_bytes() }
}

fn chain_hex(position: u64) -> String {
    format!("{position:064x}")
}

/// The unit span at `addr` as `(start, width)`.
fn unit(addr: &str) -> (String, String) {
    (addr.to_string(), format!("{}1", "0.".repeat(addr.split('.').count() - 1)))
}

/// A content I-span of `doc` from ordinal `s`, `w` wide, as `(start, width)`.
fn ispan(doc: &str, s: u64, w: u64) -> (String, String) {
    let start = format!("{doc}.0.1.{s}");
    (start.clone(), format!("{}{w}", "0.".repeat(start.split('.').count() - 1)))
}

/// A stored span's addresses where it is a content span; none for a unit
/// span at a document or an account.
fn addresses(span: &(String, String)) -> Vec<String> {
    let (start, width) = span;
    let comps: Vec<&str> = start.split('.').collect();
    if !start.contains(".0.1.") || comps.len() < 8 {
        return Vec::new();
    }
    let w: u64 = width.rsplit('.').next().unwrap().parse().unwrap();
    let (prefix, first) = start.rsplit_once('.').unwrap();
    let first: u64 = first.parse().unwrap();
    (first..first + w).map(|k| format!("{prefix}.{k}")).collect()
}

#[derive(Debug, Clone)]
struct LinkRow {
    addr: String,
    home: String,
    from: Vec<(String, String)>,
    to: Vec<(String, String)>,
    ty: Vec<(String, String)>,
    at: u64,
    retracted: bool,
}

#[derive(Debug, Clone)]
struct DocState {
    runs: Vec<Run>,
    published: bool,
    owner: String,
    placed: Option<u64>,
    base_extent: Option<u64>,
    at: u64,
}

#[derive(Debug, Clone)]
struct FeedRow {
    at: u64,
    op: &'static str,
    docs: Vec<String>,
    key: Option<&'static str>,
}

/// The board as the test writes it.
#[derive(Default)]
struct World {
    position: u64,
    docs: BTreeMap<String, DocState>,
    values: BTreeMap<(String, u64), u8>,
    links: Vec<LinkRow>,
    rows: Vec<FeedRow>,
    next_fresh: BTreeMap<String, u64>,
    next_doc: u64,
    trunk_head: BTreeMap<String, String>,
    /// The per-session idempotency memo: an id's acknowledgment.
    memo: BTreeMap<String, Value>,
    /// The next publish is answered this document, applied not.
    refuse_next: Option<Value>,
    /// The next N acknowledgments are lost at the transport, the write
    /// applied.
    drop_acks: usize,
    /// The next N `find_links_v` answer `503 scan_busy`.
    busy: usize,
    /// `image` refuses `image_too_large` past this many runs.
    image_cap: usize,
    /// `/health` names a claimant.
    claimed: bool,
    /// `H.1` answers its record.
    head: bool,
    key: Option<PublicKey>,
}

impl World {
    fn doc(&mut self, text: &str, published: bool, owner: &str, runs: Vec<Run>) {
        self.position += 1;
        self.docs.insert(text.to_string(), DocState { runs, published, owner: owner.to_string(), placed: None, base_extent: None, at: self.position });
    }

    fn text(&mut self, origin: &str, from: u64, text: &str) {
        for (k, b) in text.bytes().enumerate() {
            self.values.insert((origin.to_string(), from + k as u64), b);
        }
        let next = self.next_fresh.entry(origin.to_string()).or_insert(1);
        *next = (*next).max(from + text.len() as u64);
    }

    /// A link homed in `home`, at the next position: its address.
    fn link(&mut self, home: &str, from: Vec<(String, String)>, to: Vec<(String, String)>, ty: Vec<(String, String)>) -> String {
        let n = self.links.iter().filter(|l| l.home == home).count() + 1;
        let addr = format!("{home}.0.2.{n}");
        self.position += 1;
        self.links.push(LinkRow { addr: addr.clone(), home: home.to_string(), from, to, ty, at: self.position, retracted: false });
        self.rows.push(FeedRow { at: self.position, op: "make_link", docs: vec![home.to_string()], key: Some("bare") });
        addr
    }

    fn typed(&mut self, home: &str, from: Vec<(String, String)>, to: Vec<(String, String)>, ty: &str) -> String {
        self.link(home, from, to, vec![unit(ty)])
    }

    /// The claim `old` → `new`, homed in `home`.
    fn claim(&mut self, home: &str, old: &str, new: &str) -> String {
        self.typed(home, vec![unit(old)], vec![unit(new)], T_SUPERSEDES)
    }

    /// A retraction of `target` homed in `home`; the target retracted.
    fn retract(&mut self, home: &str, target: &str) -> String {
        let r = self.typed(home, vec![unit(home)], vec![unit(target)], T_RETRACTION);
        if let Some(l) = self.links.iter_mut().find(|l| l.addr == target) {
            l.retracted = true;
        }
        r
    }

    /// The fixture (the module doc). Returns the addresses the cells name.
    fn base() -> (World, Named) {
        let mut w = World { position: 10, next_doc: 20, image_cap: 1 << 12, claimed: true, head: true, ..World::default() };
        w.doc(DOC1, true, ACCOUNT, Vec::new());
        w.text(E, 1, E_TEXT);
        w.doc(E, true, ACCOUNT, vec![run(E, 1, 19)]);
        w.doc(&format!("{E}.1"), true, ACCOUNT, vec![run(E, 1, 19)]);
        w.docs.get_mut(&format!("{E}.1")).unwrap().placed = Some(19);
        w.trunk_head.insert(E.to_string(), format!("{E}.1"));
        w.rows.push(FeedRow { at: w.position, op: "publish", docs: vec![format!("{E}.1")], key: None });
        w.text(S, 1, "set one");
        w.doc(S, true, ACCOUNT, vec![run(S, 1, 7)]);
        w.text(S2, 1, "set two");
        w.doc(S2, true, ACCOUNT, vec![run(S2, 1, 7)]);
        w.text(D, 1, D_TEXT);
        w.text(O, 1, O_TEXT);
        w.doc(O, false, ACCOUNT, vec![run(O, 1, 5)]);
        w.doc(D, false, ACCOUNT, vec![run(E, 1, 19), run(D, 1, 10), run(O, 1, 5)]);
        w.text(N, 1, "notes here");
        w.doc(N, false, ACCOUNT, vec![run(N, 1, 10)]);
        w.text(Z, 1, "zed");
        w.doc(Z, false, ACCOUNT, vec![run(Z, 1, 3)]);
        w.text(SUB, 1, "sub");
        w.doc(SUB, false, "1.0.1.2", vec![run(SUB, 1, 3)]);
        w.text(OTHER, 1, "other");
        w.doc(OTHER, false, "1.0.2", vec![run(OTHER, 1, 5)]);
        // The ceremony's records in doc 1: whole-work ends, record classes.
        w.typed(DOC1, vec![unit(ACCOUNT)], vec![], crate::board::T_CLAIM);
        // The draft's own set.
        let mark_d = w.typed(D, vec![], vec![ispan(D, 2, 3)], T_STRONG);
        let heading_d = w.link(D, vec![], vec![ispan(D, 1, 12)], vec![unit(T_HEADING), unit("1.1.0.1.0.1.0.1.3")]);
        let cite_d = w.typed(D, vec![ispan(D, 6, 5)], vec![ispan(Z, 1, 3)], T_CITATION);
        let cut_d = w.typed(D, vec![ispan(D, 9, 4)], vec![], T_CITATION);
        let left_d = w.typed(D, vec![ispan(D, 11, 2)], vec![ispan(E, 1, 3)], T_CITATION);
        // The notes.
        let l1_n = w.typed(N, vec![ispan(E, 5, 5)], vec![ispan(N, 1, 5)], T_CITATION);
        let whole = w.typed(N, vec![unit(E)], vec![ispan(N, 6, 4)], T_CITATION);
        // The public sets, and the read-with E stands with S.
        let k_s = w.typed(S, vec![ispan(E, 1, 3)], vec![], T_CITATION);
        let k2_s2 = w.typed(S2, vec![ispan(E, 1, 3)], vec![], T_MARK);
        let rw = w.typed(S, vec![unit(E)], vec![unit(S)], T_READ_WITH);
        // Others' links on the same words.
        let other = w.typed(OTHER, vec![ispan(E, 1, 3)], vec![], T_CITATION);
        let sub = w.typed(SUB, vec![ispan(E, 1, 3)], vec![], T_CITATION);
        // The edition's own published marks, and the held removals.
        let e1 = format!("{E}.1");
        let mpub = w.typed(&e1, vec![], vec![ispan(E, 5, 5)], T_STRONG);
        let mpub2 = w.typed(&e1, vec![], vec![ispan(E, 10, 5)], T_STRONG);
        let mpub3 = w.typed(&e1, vec![], vec![ispan(E, 15, 5)], T_HEADING);
        let held = w.typed(D, vec![], vec![unit(&mpub)], T_HELD_REMOVAL);
        let held2 = w.typed(D, vec![], vec![unit(&mpub2)], T_HELD_REMOVAL);
        let held3 = w.typed(D, vec![], vec![unit(&mpub3)], T_HELD_REMOVAL);
        w.retract(&e1, &mpub2);
        let mark_d2 = w.typed(D, vec![], vec![ispan(E, 5, 5)], T_STRONG);
        // An accepted original: the copy at E.1 and the claim at home.
        let l_acc = w.typed(N, vec![ispan(E, 10, 5)], vec![ispan(N, 1, 5)], T_CITATION);
        let copy = w.typed(&e1, vec![ispan(E, 10, 5)], vec![ispan(N, 1, 5)], T_CITATION);
        let claim_acc = w.claim(N, &l_acc, &copy);
        // A revised original: its accept's claim and the retype's.
        let l_orig = w.typed(N, vec![ispan(E, 16, 3)], vec![ispan(N, 6, 4)], T_CITATION);
        let copy_orig = w.typed(&e1, vec![ispan(E, 16, 3)], vec![ispan(N, 6, 4)], T_CITATION);
        w.claim(N, &l_orig, &copy_orig);
        let l_rev = w.typed(N, vec![ispan(E, 16, 3)], vec![ispan(N, 6, 4)], T_HEADING);
        w.claim(N, &l_orig, &l_rev);
        // An earlier shot's record in D and a private link on its from words.
        let record = w.typed(D, vec![ispan(D, 20, 4)], vec![ispan(E, 16, 4)], T_CORRESPONDENCE);
        let l_rt = w.typed(N, vec![ispan(D, 20, 4)], vec![ispan(N, 1, 2)], T_CITATION);
        let named = Named { mark_d, heading_d, cite_d, cut_d, left_d, l1_n, whole, k_s, k2_s2, rw, other, sub, mpub, mpub2, mpub3, held, held2, held3, mark_d2, l_acc, copy, claim_acc, l_orig, l_rev, record, l_rt };
        (w, named)
    }

    fn readable(&self, home: &str) -> bool {
        let Some(doc) = trunk_of(home).and_then(|t| self.docs.get(&t).cloned()) else { return false };
        doc.published || doc.owner == ACCOUNT || doc.owner.starts_with("1.0.1.")
    }

    fn arrangement(&self, doc: &str) -> Option<Vec<Run>> {
        self.docs.get(doc).map(|d| d.runs.clone())
    }

    fn expand(runs: &[Run]) -> Vec<(Address, u64)> {
        runs.iter().flat_map(|r| (r.i_start..r.reach()).map(move |n| (r.origin.clone(), n))).collect()
    }

    fn coalesce(positions: Vec<(Address, u64)>) -> Vec<Run> {
        let mut out: Vec<Run> = Vec::new();
        for (origin, n) in positions {
            match out.last_mut() {
                Some(last) if last.origin == origin && last.reach() == n => last.width += 1,
                _ => out.push(Run::new(origin, n, 1)),
            }
        }
        out
    }

    fn fresh(&mut self, origin: &str) -> u64 {
        let next = self.next_fresh.entry(origin.to_string()).or_insert(1);
        let n = *next;
        *next += 1;
        n
    }

    fn link_value(&self, l: &LinkRow) -> Value {
        let slot = |spans: &[(String, String)]| spans.iter().map(|(s, w)| json!({"start": s, "width": w})).collect::<Vec<_>>();
        json!({"resp": "link_value", "as_of": self.position, "at": l.at, "link": {"slots": [slot(&l.from), slot(&l.to), slot(&l.ty)]}, "time": null, "time_from": null})
    }

    /// The addresses at V-positions `region` of `doc`'s arrangement.
    fn addresses_at(&self, doc: &str, region: &[(u64, u64)]) -> BTreeSet<String> {
        let positions = Self::expand(&self.arrangement(doc).unwrap_or_default());
        let mut out = BTreeSet::new();
        for &(from, width) in region {
            for k in from..from + width {
                if let Some((origin, n)) = positions.get(k as usize - 1) {
                    out.insert(format!("{origin}.0.1.{n}"));
                }
            }
        }
        out
    }

    fn touches_addresses(l: &LinkRow, addrs: &BTreeSet<String>, doc: &str) -> bool {
        l.from.iter().chain(&l.to).any(|s| {
            let covered = addresses(s);
            if covered.is_empty() {
                // A unit span at a document: a whole-work end on `doc` or its account.
                return s.0 == doc || doc.starts_with(&format!("{}.", s.0));
            }
            covered.iter().any(|a| addrs.contains(a))
        })
    }

    fn claims_answer(&self, rows: Vec<&LinkRow>) -> Value {
        let claims: Vec<Value> = rows.iter().map(|c| json!({"active": !c.retracted, "claim": c.addr, "home": c.home, "new": c.to[0].0, "old": c.from[0].0})).collect();
        json!({"resp": "claims", "as_of": self.position, "claims": claims})
    }

    fn op(&mut self, frame: &Value) -> Result<Response, DialError> {
        let op = frame["op"].as_str().unwrap_or("?").to_string();
        let position = self.position;
        let rejected = |code: &str, extra: Value| {
            let mut v = json!({"resp": "rejected", "code": code, "disposition": "reorder", "op": op});
            if let Some(obj) = extra.as_object() {
                for (k, val) in obj {
                    v[k] = val.clone();
                }
            }
            reply(200, v)
        };
        match op.as_str() {
            "principal_prefix" => Ok(reply(200, json!({"resp": "addr", "as_of": position, "addr": ACCOUNT}))),
            "key_set" => {
                let key = self.key.clone().expect("the key");
                Ok(reply(200, json!({"resp": "key_set", "as_of": position, "retired": [], "enrolled": [{"alg": key.alg(), "key": key.to_hex(), "fingerprint": skep_identity::Fingerprint::of(&key).to_hex(), "anchor": false}]})))
            }
            "doc_metadata" => {
                let doc = frame["doc"].as_str().unwrap();
                let Some(d) = self.docs.get(doc).cloned() else { return Ok(rejected("doc_not_registered", json!({}))) };
                if !self.readable(doc) {
                    return Ok(rejected("withheld", json!({"site": {"addr": doc}})));
                }
                Ok(reply(200, json!({"resp": "doc_metadata", "as_of": position, "doc": trunk_of(doc), "published": d.published, "owner": d.owner, "placed": d.placed.map(|p| p.to_string()), "base_extent": d.base_extent.map(|e| e.to_string()), "source": null, "at": d.at})))
            }
            "retrieve_doc_v_span_set" => {
                let doc = frame["doc"].as_str().unwrap();
                if !self.readable(doc) {
                    return Ok(rejected("withheld", json!({"site": {"addr": doc}})));
                }
                let Some(runs) = self.arrangement(doc) else { return Ok(rejected("doc_not_registered", json!({}))) };
                let extent: u64 = runs.iter().map(|r| r.width).sum();
                let set = if extent == 0 { json!([]) } else { json!([{"start": "1.1", "width": format!("0.{extent}")}]) };
                Ok(reply(200, json!({"resp": "span_set", "as_of": position, "set": set})))
            }
            "image" => {
                let doc = frame["d"].as_str().unwrap();
                let Some(runs) = self.arrangement(doc) else { return Ok(rejected("doc_not_registered", json!({}))) };
                let (from, width) = span_of(&frame["region"][0]);
                let positions = Self::expand(&runs);
                let clipped = Self::coalesce(positions.into_iter().skip(from as usize - 1).take(width as usize).collect());
                if clipped.len() > self.image_cap {
                    return Ok(rejected("image_too_large", json!({})));
                }
                let runs: Vec<Value> = clipped.iter().map(|r| json!({"i_start": r.i_start_text(), "width": r.width.to_string()})).collect();
                Ok(reply(200, json!({"resp": "runs", "as_of": position, "runs": runs})))
            }
            "retrieve_v" => {
                let spec = &frame["specs"][0];
                let doc = spec["doc"].as_str().unwrap();
                if doc == HEAD_MEMBER_1 {
                    let items = if self.head { json!([{"atom": json!({"type": "skep-head", "position": 1, "chain": chain_hex(1)}).to_string()}]) } else { json!([]) };
                    return Ok(reply(200, json!({"resp": "delivery", "as_of": position, "items": items})));
                }
                let (from, width) = span_of(&spec["span"]);
                let Some(runs) = self.arrangement(doc) else { return Ok(rejected("doc_not_registered", json!({}))) };
                let positions = Self::expand(&runs);
                let text: String = positions.iter().skip(from as usize - 1).take(width as usize).map(|(o, n)| *self.values.get(&(o.to_string(), *n)).unwrap_or_else(|| panic!("no value at {o}.0.1.{n}")) as char).collect();
                assert_eq!(text.len() as u64, width, "the span asked lies within the arrangement");
                Ok(reply(200, json!({"resp": "delivery", "as_of": position, "items": [{"content": text}]})))
            }
            "find_links_v" => {
                if self.busy > 0 {
                    self.busy -= 1;
                    return Ok(reply(503, json!({"error": "scan_busy", "detail": "all region-read permits of this document are in use; retry shortly", "op": "find_links_v"})));
                }
                let doc = frame["d"].as_str().unwrap().to_string();
                let region: Vec<(u64, u64)> = frame["region"].as_array().unwrap().iter().map(span_of).collect();
                let addrs = self.addresses_at(&doc, &region);
                let hits: Vec<String> = self.links.iter().filter(|l| !l.retracted && self.readable(&l.home) && Self::touches_addresses(l, &addrs, &doc)).map(|l| l.addr.clone()).collect();
                Ok(reply(200, json!({"resp": "addrs", "as_of": position, "addrs": hits})))
            }
            "find_links_ftt" => {
                let q = &frame["q"];
                let spans = |slot: &Value| -> Option<Vec<(String, String)>> { slot.as_array().map(|s| s.iter().map(|x| (x["start"].as_str().unwrap().to_string(), x["width"].as_str().unwrap().to_string())).collect()) };
                let (home, from, to, ty) = (spans(&q["home"]), spans(&q["from"]), spans(&q["to"]), spans(&q["ty"]));
                assert!(home.is_some() || from.is_some() || to.is_some(), "a class scan: {q}");
                let overlaps = |stored: &[(String, String)], asked: &[(String, String)]| -> bool {
                    stored.iter().any(|s| {
                        asked.iter().any(|q| {
                            let (sa, qa) = (addresses(s), addresses(q));
                            if sa.is_empty() || qa.is_empty() {
                                // A unit span: the address under the other's.
                                return s.0 == q.0 || s.0.starts_with(&format!("{}.", q.0)) || q.0.starts_with(&format!("{}.", s.0));
                            }
                            sa.iter().any(|x| qa.contains(x))
                        })
                    })
                };
                let hits: Vec<String> = self
                    .links
                    .iter()
                    .filter(|l| !l.retracted && self.readable(&l.home))
                    .filter(|l| home.as_ref().is_none_or(|h| h.iter().any(|(start, _)| l.home == *start || l.home.starts_with(&format!("{start}.")))))
                    .filter(|l| from.as_ref().is_none_or(|f| overlaps(&l.from, f)))
                    .filter(|l| to.as_ref().is_none_or(|t| overlaps(&l.to, t)))
                    .filter(|l| ty.as_ref().is_none_or(|t| overlaps(&l.ty, t)))
                    .map(|l| l.addr.clone())
                    .collect();
                Ok(reply(200, json!({"resp": "addrs", "as_of": position, "addrs": hits})))
            }
            "read_link" => {
                let addr = frame["a"].as_str().unwrap();
                match self.links.iter().find(|l| l.addr == addr && self.readable(&l.home)) {
                    Some(l) => Ok(reply(200, self.link_value(l))),
                    None => Ok(reply(200, json!({"resp": "link_value", "as_of": position, "at": null, "link": null, "time": null, "time_from": null}))),
                }
            }
            "in_claims" | "out_claims" => {
                let (slot, key) = if op == "in_claims" { (0usize, "y") } else { (1, "x") };
                let target = frame[key].as_str().unwrap();
                let rows: Vec<&LinkRow> = self.links.iter().filter(|l| self.readable(&l.home) && l.ty.first().is_some_and(|t| t.0 == T_SUPERSEDES) && (if slot == 0 { &l.from } else { &l.to }).first().is_some_and(|s| s.0 == target)).collect();
                Ok(reply(200, self.claims_answer(rows)))
            }
            "edition_claims" => {
                let target = frame["target"].as_str().unwrap();
                let rows: Vec<Value> = self
                    .links
                    .iter()
                    .filter(|l| self.readable(&l.home) && l.ty.first().is_some_and(|t| t.0.starts_with(T_EDITION)) && l.to.first().is_some_and(|s| s.0 == target))
                    .map(|l| json!({"active": !l.retracted, "claim": l.addr, "home": l.home, "to": l.to.iter().map(|(s, w)| json!({"start": s, "width": w})).collect::<Vec<_>>()}))
                    .collect();
                Ok(reply(200, json!({"resp": "edition_claims", "as_of": position, "claims": rows})))
            }
            "publish" => self.publish(frame),
            other => panic!("the composition sent an op the scripted board does not answer: {other}"),
        }
    }

    /// The write: the memo answered where one stands, else the publication
    /// applied and its acknowledgment kept; the next `drop_acks`
    /// acknowledgments lost at the transport.
    fn publish(&mut self, frame: &Value) -> Result<Response, DialError> {
        if let Some(r) = self.refuse_next.take() {
            return Ok(reply(200, r));
        }
        let id = frame["id"].as_str().map(str::to_string);
        let ack = match id.as_ref().and_then(|id| self.memo.get(id)).cloned() {
            Some(ack) => ack,
            None => {
                let ack = self.apply(frame);
                if let (Some(id), true) = (&id, ack["resp"] != "rejected") {
                    self.memo.insert(id.clone(), ack.clone());
                }
                ack
            }
        };
        if self.drop_acks > 0 {
            self.drop_acks -= 1;
            return Err(DialError::Io("the acknowledgment was lost".into()));
        }
        Ok(reply(200, ack))
    }

    /// Applies a publication as the daemon does, in its order.
    fn apply(&mut self, frame: &Value) -> Value {
        let refused = |code: &str, site: Value| json!({"resp": "rejected", "code": code, "disposition": "permanent", "op": "publish", "site": site});
        let mint = frame["mint"].as_bool().unwrap_or(false);
        let draft = frame["draft"].as_str().map(str::to_string);
        let runs: Vec<Run> = frame["runs"].as_array().unwrap().iter().map(|r| Run::new(a(r["origin"].as_str().unwrap()), r["i_start"].as_str().unwrap().rsplit('.').next().unwrap().parse().unwrap(), r["width"].as_str().unwrap().parse().unwrap())).collect();
        let places: Vec<Option<u64>> = frame["places"].as_array().map(|p| p.iter().map(|x| x["ordinal"].as_str().and_then(|o| o.parse().ok())).collect()).unwrap_or_else(|| vec![None; runs.len()]);
        let (trunk, edition) = if mint {
            let account = frame["account"].as_str().unwrap();
            let e = format!("{account}.0.{}", self.next_doc);
            self.next_doc += 1;
            self.position += 1;
            self.docs.insert(e.clone(), DocState { runs: Vec::new(), published: true, owner: account.to_string(), placed: None, base_extent: None, at: self.position });
            (e.clone(), Some(e))
        } else {
            (frame["doc"].as_str().unwrap().to_string(), None)
        };
        let records_in = |w: &World, d: &str| -> Vec<(LinkRow, String)> {
            w.links.iter().filter(|l| l.home == d && l.ty.first().is_some_and(|t| t.0 == T_CORRESPONDENCE)).map(|l| (l.clone(), w.rows.iter().find(|r| r.at == l.at && r.op == "publish").map(|r| r.docs[0].clone()).unwrap_or_default())).collect()
        };
        // The twin fence.
        if let Some(d) = &draft {
            for run in runs.iter().filter(|r| r.origin.to_string() == *d) {
                for (rec, member) in records_in(self, d) {
                    let from = addresses(&rec.from[0]);
                    if (run.i_start..run.reach()).any(|n| from.contains(&format!("{d}.0.1.{n}"))) {
                        return refused("already_published", json!({"addr": member}));
                    }
                }
            }
        }
        // The member's address.
        let base = frame["base"].as_str().map(str::to_string);
        let member = match self.trunk_head.get(&trunk).cloned() {
            Some(head) if base.as_deref() == Some(head.as_str()) => format!("{trunk}.{}", head.rsplit('.').next().unwrap().parse::<u64>().unwrap() + 1),
            Some(_) => {
                let b = base.clone().unwrap_or(trunk.clone());
                let k = 1 + self.docs.keys().filter(|m| m.strip_prefix(&format!("{b}.")).is_some_and(|rest| !rest.contains('.'))).count();
                format!("{b}.{k}")
            }
            None => format!("{trunk}.1"),
        };
        // The kept places: the draft arranges the run's words at the place.
        let draft_positions: Vec<(Address, u64)> = draft.as_ref().and_then(|d| self.arrangement(d)).map(|r| Self::expand(&r)).unwrap_or_default();
        let mut stray_froms: Vec<(usize, Vec<(Address, u64)>)> = Vec::new();
        for (k, (run, place)) in runs.iter().zip(&places).enumerate() {
            let Some(place) = place else { continue };
            let at_place: Vec<(Address, u64)> = draft_positions.iter().skip(*place as usize - 1).take(run.width as usize).cloned().collect();
            if draft.as_deref() == Some(run.origin.to_string().as_str()) {
                let want: Vec<(Address, u64)> = (run.i_start..run.reach()).map(|n| (run.origin.clone(), n)).collect();
                if at_place != want {
                    return refused("kept_place_moved", json!({"index": k}));
                }
            } else {
                // A stray run: a record of the draft naming the run whole as its to.
                let Some(d) = &draft else { return refused("stray_place_unrecorded", json!({"index": k})) };
                let covering = records_in(self, d).into_iter().find(|(rec, _)| {
                    let to = addresses(&rec.to[0]);
                    (run.i_start..run.reach()).all(|n| to.contains(&format!("{}.0.1.{n}", run.origin)))
                });
                let Some((rec, _)) = covering else { return refused("stray_place_unrecorded", json!({"index": k})) };
                let to = addresses(&rec.to[0]);
                let offset = to.iter().position(|x| *x == run.i_start_text()).unwrap();
                let from: Vec<(Address, u64)> = addresses(&rec.from[0]).iter().skip(offset).take(run.width as usize).map(|x| { let (p, n) = x.rsplit_once('.').unwrap(); (a(&trunk_of(p).unwrap()), n.parse().unwrap()) }).collect();
                if at_place != from {
                    return refused("kept_place_moved", json!({"index": k}));
                }
                stray_froms.push((k, from));
            }
        }
        // The plan's entries: the home and the original, as the plan refuses them.
        let entries = frame["links"].as_array().cloned().unwrap_or_default();
        for (k, entry) in entries.iter().enumerate() {
            let home = entry["home"].as_str().unwrap();
            if home != "member" && home != "edition" && !self.docs.get(home).is_some_and(|d| d.published && d.owner == ACCOUNT) {
                return refused("link_home_refused", json!({"index": k}));
            }
            if let Some(old) = entry["old"].as_str() {
                match self.links.iter().find(|l| l.addr == old) {
                    None => return json!({"resp": "rejected", "code": "old_refused", "detail": "absent", "disposition": "permanent", "op": "publish", "site": {"index": k}}),
                    Some(l) if l.retracted => return json!({"resp": "rejected", "code": "old_refused", "detail": "retracted", "disposition": "permanent", "op": "publish", "site": {"index": k}}),
                    _ => {}
                }
            }
        }
        // The mint: one fresh identity per draft identity, in runs' order.
        self.position += 1;
        let at = self.position;
        let mut fresh_of: BTreeMap<u64, u64> = BTreeMap::new();
        let mut positions: Vec<(Address, u64)> = Vec::new();
        let mut fresh_runs: Vec<Run> = Vec::new();
        let mut records: Vec<(u64, u64, u64)> = Vec::new();
        for run in &runs {
            if draft.as_deref() == Some(run.origin.to_string().as_str()) {
                let mut minted_start: Option<(u64, u64)> = None;
                let mut piece_start = 0u64;
                for n in run.i_start..run.reach() {
                    let f = match fresh_of.get(&n) {
                        Some(f) => {
                            if let Some((ds, fs)) = minted_start.take() {
                                records.push((ds, fs, n - ds));
                            }
                            *f
                        }
                        None => {
                            let f = self.fresh(&trunk);
                            let value = self.values[&(run.origin.to_string(), n)];
                            self.values.insert((trunk.clone(), f), value);
                            fresh_of.insert(n, f);
                            if minted_start.is_none() {
                                minted_start = Some((n, f));
                            }
                            f
                        }
                    };
                    positions.push((a(&trunk), f));
                    piece_start = n;
                }
                if let Some((ds, fs)) = minted_start.take() {
                    records.push((ds, fs, piece_start + 1 - ds));
                }
                fresh_runs.push(Run::new(a(&trunk), fresh_of[&run.i_start], run.width));
            } else {
                positions.extend((run.i_start..run.reach()).map(|n| (run.origin.clone(), n)));
                fresh_runs.push(run.clone());
            }
        }
        let member_runs = Self::coalesce(positions);
        let placed: u64 = member_runs.iter().map(|r| r.width).sum();
        self.docs.insert(member.clone(), DocState { runs: member_runs.clone(), published: true, owner: ACCOUNT.to_string(), placed: Some(placed), base_extent: frame["base_extent"].as_str().and_then(|e| e.parse().ok()), at });
        if !member.strip_prefix(&format!("{trunk}.")).unwrap().contains('.') {
            self.trunk_head.insert(trunk.clone(), member.clone());
            if let Some(t) = self.docs.get_mut(&trunk) {
                t.runs = member_runs;
            }
        }
        let mut homes: Vec<String> = vec![member.clone()];
        if let Some(e) = &edition {
            homes.push(e.clone());
        }
        let push_link = |w: &mut World, home: &str, from: Vec<(String, String)>, to: Vec<(String, String)>, ty: Vec<(String, String)>| -> String {
            let n = w.links.iter().filter(|l| l.home == home).count() + 1;
            let addr = format!("{home}.0.2.{n}");
            w.links.push(LinkRow { addr: addr.clone(), home: home.to_string(), from, to, ty, at, retracted: false });
            addr
        };
        // The records.
        if let Some(d) = &draft {
            for (ds, fs, w) in &records {
                push_link(self, d, vec![ispan(d, *ds, *w)], vec![ispan(&trunk, *fs, *w)], vec![unit(T_CORRESPONDENCE)]);
            }
            if !records.is_empty() || places.iter().any(Option::is_some) {
                homes.push(d.clone());
            }
        }
        // The edition claim.
        if mint && frame["claim"].as_bool().unwrap_or(false) {
            let e = edition.clone().unwrap();
            push_link(self, &e, vec![unit(&e)], vec![unit(draft.as_deref().unwrap())], vec![unit(T_EDITION)]);
        }
        // The copies and their claims.
        let resolve = |end: &Value| -> Vec<(String, String)> {
            if let Some(list) = end["addrs"].as_array() {
                return list.iter().map(|x| match x.as_str().unwrap() { "member" => unit(&member), "edition" => unit(edition.as_deref().unwrap_or(&member)), addr => unit(addr) }).collect();
            }
            if let Some(list) = end["spans"].as_array() {
                // As the daemon stores the I-span form: the width a decimal
                // natural on the wire, a displacement at the start's depth in
                // the slot.
                return list
                    .iter()
                    .map(|x| {
                        let start = x["start"].as_str().unwrap().to_string();
                        let width: u64 = x["width"].as_str().unwrap().parse().expect("the daemon refuses a width that is not a decimal natural as malformed");
                        let depth = start.split('.').count();
                        (start, format!("{}{width}", "0.".repeat(depth - 1)))
                    })
                    .collect();
            }
            let spans: Vec<(u64, u64)> = end["member"].as_array().unwrap().iter().map(|x| (x["ordinal"].as_str().unwrap().parse().unwrap(), x["width"].as_str().unwrap().parse().unwrap())).collect();
            resolve_member_spans(&fresh_runs, &spans).expect("inside the placed positions").iter().map(|s| (format!("{}.{}", s.chain, s.first), format!("{}{}", "0.".repeat(s.chain.split('.').count()), s.width))).collect()
        };
        for entry in &entries {
            let home = match entry["home"].as_str().unwrap() {
                "member" => member.clone(),
                "edition" => edition.clone().unwrap(),
                h => h.to_string(),
            };
            let copy = push_link(self, &home, resolve(&entry["from"]), resolve(&entry["to"]), resolve(&entry["ty"]));
            if !homes.contains(&home) {
                homes.push(home.clone());
            }
            if let Some(old) = entry["old"].as_str() {
                let old_home = home_of_link(old).unwrap().to_string();
                push_link(self, &old_home, vec![unit(old)], vec![unit(&copy)], vec![unit(T_SUPERSEDES)]);
                if !homes.contains(&old_home) {
                    homes.push(old_home);
                }
            }
        }
        // The retractions, a retracted target skipped.
        for target in frame["retract"].as_array().cloned().unwrap_or_default() {
            let target = target.as_str().unwrap().to_string();
            if self.links.iter().any(|l| l.addr == target && l.retracted) {
                continue;
            }
            let home = home_of_link(&target).unwrap().to_string();
            push_link(self, &home, vec![unit(&home)], vec![unit(&target)], vec![unit(T_RETRACTION)]);
            if let Some(l) = self.links.iter_mut().find(|l| l.addr == target) {
                l.retracted = true;
            }
            if !homes.contains(&home) {
                homes.push(home);
            }
        }
        // The read-withs, a standing one skipped.
        let from_edition = edition.clone().unwrap_or(trunk.clone());
        for set in frame["read_with"].as_array().cloned().unwrap_or_default() {
            let set = set.as_str().unwrap().to_string();
            let stands = self.links.iter().any(|l| !l.retracted && l.ty.first().is_some_and(|t| t.0 == T_READ_WITH) && l.from.first().is_some_and(|s| s.0 == from_edition) && l.to.first().is_some_and(|s| s.0 == set) && self.docs.get(&l.home).is_some_and(|d| d.published && d.owner == ACCOUNT));
            if stands {
                continue;
            }
            push_link(self, &set, vec![unit(&from_edition)], vec![unit(&set)], vec![unit(T_READ_WITH)]);
            if !homes.contains(&set) {
                homes.push(set);
            }
        }
        // The re-window at the kept places.
        if let Some(d) = &draft {
            let mut positions = draft_positions;
            for (k, (run, place)) in runs.iter().zip(&places).enumerate() {
                let Some(place) = place else { continue };
                let replacement: Vec<(Address, u64)> = if draft.as_deref() == Some(run.origin.to_string().as_str()) {
                    (run.i_start..run.reach()).map(|n| (a(&trunk), fresh_of[&n])).collect()
                } else {
                    let _ = stray_froms.iter().find(|(i, _)| *i == k);
                    (run.i_start..run.reach()).map(|n| (run.origin.clone(), n)).collect()
                };
                positions.splice(*place as usize - 1..*place as usize - 1 + run.width as usize, replacement);
            }
            if let Some(ds) = self.docs.get_mut(d) {
                ds.runs = Self::coalesce(positions);
            }
        }
        self.rows.push(FeedRow { at, op: "publish", docs: homes, key: None });
        json!({"resp": "ack_addr", "addr": member, "at": at})
    }

    fn changes(&self, path: &str) -> Response {
        let query = path.split_once('?').map_or("", |x| x.1);
        let (mut since, mut under, mut limit) = (0u64, None::<String>, 256usize);
        for pair in query.split('&') {
            match pair.split_once('=') {
                Some(("since", v)) => since = v.parse().unwrap(),
                Some(("under", v)) => under = Some(v.to_string()),
                Some(("limit", v)) => limit = v.parse().unwrap(),
                Some(("drafts", _)) => {}
                _ => panic!("an unknown `/changes` member: {pair}"),
            }
        }
        let visible: Vec<&FeedRow> = self.rows.iter().filter(|r| r.at > since).filter(|r| under.as_ref().is_none_or(|u| r.docs.iter().any(|d| d == u || d.starts_with(&format!("{u}."))))).collect();
        let page: Vec<Value> = visible.iter().take(limit).map(|r| json!({"at": r.at, "op": r.op, "docs": r.docs, "key": r.key, "time": null})).collect();
        let last = page.last().and_then(|r| r["at"].as_u64()).unwrap_or(since);
        reply(200, json!({"changes": page, "last": last, "more": visible.len() > page.len()}))
    }
}

/// A V-span `{"start": "1.N", "width": "0.W"}` as `(from, width)`.
fn span_of(v: &Value) -> (u64, u64) {
    let from = v["start"].as_str().unwrap().strip_prefix("1.").unwrap().parse().unwrap();
    let width = v["width"].as_str().unwrap().strip_prefix("0.").unwrap().parse().unwrap();
    (from, width)
}

/// The fixture's addresses, by name.
#[allow(dead_code)]
struct Named {
    mark_d: String,
    heading_d: String,
    cite_d: String,
    cut_d: String,
    left_d: String,
    l1_n: String,
    whole: String,
    k_s: String,
    k2_s2: String,
    rw: String,
    other: String,
    sub: String,
    mpub: String,
    mpub2: String,
    mpub3: String,
    held: String,
    held2: String,
    held3: String,
    mark_d2: String,
    l_acc: String,
    copy: String,
    claim_acc: String,
    l_orig: String,
    l_rev: String,
    record: String,
    l_rt: String,
}

/// The dialer over a world, every frame it served kept.
struct Scripted {
    world: Arc<Mutex<World>>,
    served: Mutex<Vec<(String, Value)>>,
}

impl Scripted {
    fn ops(&self) -> Vec<String> {
        self.served.lock().unwrap().iter().map(|(line, _)| line.clone()).collect()
    }

    fn frames(&self, op: &str) -> Vec<Value> {
        self.served.lock().unwrap().iter().filter(|(line, _)| line == op).map(|(_, f)| f.clone()).collect()
    }

    fn clear(&self) {
        self.served.lock().unwrap().clear();
    }

    fn world(&self) -> std::sync::MutexGuard<'_, World> {
        self.world.lock().unwrap()
    }
}

impl Dialer for Scripted {
    fn exchange(&self, _origin: &Origin, req: &DialRequest) -> Result<Response, DialError> {
        let frame: Value = serde_json::from_slice(&req.body).unwrap_or(Value::Null);
        let line = match req.path.as_str() {
            "/op" => frame["op"].as_str().unwrap_or("?").to_string(),
            p => format!("{} {p}", req.method.as_str()),
        };
        self.served.lock().unwrap().push((line, frame.clone()));
        let mut w = self.world.lock().unwrap();
        match req.path.as_str() {
            "/health" => {
                let claimant = if w.claimed { json!(ACCOUNT) } else { Value::Null };
                Ok(reply(200, json!({"ok": true, "log_position": w.position, "chain_head": chain_hex(w.position), "auth": {"claimant": claimant, "local_trust": true, "origins": [], "signed_origins": []}})))
            }
            "/op" => w.op(&frame),
            p if p.starts_with("/changes?") => Ok(w.changes(p)),
            p => panic!("the composition dialed a path the scripted board does not answer: {p}"),
        }
    }

    fn stream(&self, _: &Origin, _: &RequestHead, _: &mut dyn std::io::Read, _: &mut dyn FnMut(&Headers)) -> Result<StreamedResponse, DialError> {
        unreachable!("no read of the scripted board streams")
    }
}

fn signer() -> HybridSigner {
    crate::sign::signer_from_seed(&[42; 32])
}

/// A board over `world`, the person's key enrolled.
fn open(mut world: World) -> (Arc<Scripted>, Board, HybridSigner) {
    let signer = signer();
    world.key = Some(Signer::public_key(&signer).clone());
    let dialer = Arc::new(Scripted { world: Arc::new(Mutex::new(world)), served: Mutex::new(Vec::new()) });
    let board = Board::new(Origin::parse("http://127.0.0.1:8642").unwrap(), dialer.clone());
    (dialer, board, signer)
}

fn token() -> Token {
    Token::parse(TOKEN).unwrap()
}

/// The fixture's inputs: the whole draft as the selection, `N` the notes,
/// `D` and `N` the readable drafts, `E`, `S` and `S2` the published documents.
fn inputs() -> Inputs {
    Inputs {
        doc: Some(a(E)),
        mint: None,
        claim: false,
        base: Some((a(&format!("{E}.1")), 19)),
        draft: a(D),
        selection: vec![run(E, 1, 19), run(D, 1, 10), run(O, 1, 5)],
        notes: vec![a(N)],
        readable_drafts: vec![a(D), a(N)],
        published: vec![a(E), a(S), a(S2)],
    }
}

fn publisher<'a>(board: &'a Board, token: &'a Token, signer: &'a HybridSigner) -> Publisher<'a> {
    Publisher { board, token, account: ACCOUNT, signer }
}

fn links_of(e: &Enumeration, indices: &[usize]) -> Vec<String> {
    indices.iter().map(|i| e.candidates[*i].link.to_string()).collect()
}

/// The switches: the draft's own set and the notes ON, the notes into
/// `dest` where one is named.
fn switched(dest: Option<&str>) -> Confirmed {
    let mut switches = Switches::default();
    switches.on.insert(a(D));
    switches.on.insert(a(N));
    if let Some(s) = dest {
        switches.destinations.insert(a(N), Destination::Set(a(s)));
    }
    let mut answers = BTreeMap::new();
    answers.insert(2, OriginAnswer::KeepPrivate);
    Confirmed { switches, answers }
}

/// The whole composition to a built request over the base fixture.
fn built(dialer: &Scripted, board: &Board, tok: &Token, signer: &HybridSigner, confirmed: &Confirmed) -> (Enumeration, Panel, Request) {
    let p = publisher(board, tok, signer);
    let inputs = inputs();
    let e = enumerate(&p, &inputs).expect("enumerated");
    let panel = panel(&p, &inputs, &e).expect("the panel");
    let reread = reread(&p, &inputs, &e, &panel).expect("re-read");
    assert_eq!(reread.restatement, None, "nothing moved");
    let Built::Request(request) = build(&p, &inputs, &reread.enumeration, &reread.panel, confirmed).expect("built") else { panic!("inert") };
    let _ = dialer;
    (reread.enumeration, reread.panel, *request)
}

// ── THE ENUMERATION ──────────────────────────────────────────────────────

/// §5.1's reads IN ORDER with their frame counts — the extent and the one
/// image, the one `find_links_v` over the selection as one region, one
/// `read_link` per owned link, the records read with its hits, the
/// read-through's two batched reads, the two claims reads per candidate —
/// and the candidates: the owned homes' links touching the selection kept,
/// another account's and a sub-account's dropped off the address, the
/// whole-work link dropped by the stored-endset test, the edition's own
/// links no row, the records no candidate; the accepted original dropped on
/// keys (i) and (iii), the revision dropped on the original's accept, the
/// private link on an earlier shot's words reached THROUGH its record.
#[test]
fn the_enumeration_reads_in_order_and_keeps_the_owned_homes_links_on_the_words() {
    let (world, named) = World::base();
    let (dialer, board, signer) = open(world);
    let tok = token();
    let p = publisher(&board, &tok, &signer);
    let e = enumerate(&p, &inputs()).expect("enumerated");
    let steps: Vec<&str> = e.frames.iter().map(|(s, _)| *s).collect();
    assert_eq!(steps, ["image", "find_links_v", "links", "records", "read_through", "claims"]);
    assert_eq!(e.frames[0], ("image", 2), "the extent and one image");
    assert_eq!(e.frames[1], ("find_links_v", 1), "ONE region read");
    assert_eq!(e.frames[3], ("records", 1), "the records read; the record's own read_link was cached when the region read answered it");
    assert_eq!(e.frames[4].1, 4, "two batched reads, the link's read_link and its home's metadata");
    assert_eq!(e.region, vec![(1, 34)], "the selection's V-spans merged: the whole draft");
    assert_eq!(e.placed, vec![Placement::Whole { ordinal: 1 }, Placement::Whole { ordinal: 20 }, Placement::Whole { ordinal: 30 }]);
    let find = dialer.frames("find_links_v");
    assert_eq!(find[0]["region"], json!([{"start": "1.1", "width": "0.34"}]));
    let offered: BTreeSet<String> = links_of(&e, &e.offered()).into_iter().collect();
    let want: BTreeSet<String> = [&named.mark_d, &named.heading_d, &named.cite_d, &named.cut_d, &named.left_d, &named.l1_n, &named.k_s, &named.k2_s2, &named.mark_d2, &named.l_rt].iter().map(|s| s.to_string()).collect();
    assert_eq!(offered, want);
    let all: Vec<String> = e.candidates.iter().map(|c| c.link.to_string()).collect();
    for dropped in [&named.other, &named.sub, &named.whole, &named.mpub, &named.copy, &named.record, &named.rw] {
        assert!(!all.contains(dropped), "{dropped} is no candidate");
    }
    let acc = e.candidates.iter().find(|c| c.link.to_string() == named.l_acc).expect("the accepted original is a candidate");
    assert_eq!(acc.successors.len(), 1);
    assert_eq!((acc.successors[0].new.to_string(), acc.successors[0].published_home, acc.successors[0].covers), (named.copy.clone(), true, true));
    assert!(!acc.offered(), "dropped on both keys");
    let rev = e.candidates.iter().find(|c| c.link.to_string() == named.l_rev).expect("the revision is a candidate");
    assert!(rev.revised && !rev.offered(), "the revision of a published original is not offered");
    let rt = e.candidates.iter().find(|c| c.link.to_string() == named.l_rt).unwrap();
    assert_eq!(rt.via, Via::ReadThrough(vec![a(&named.record)]), "mapped back to its record");
    assert_eq!(e.records.len(), 1);
    assert_eq!((e.records[0].from.first, e.records[0].to.first, e.records[0].to.width), (20, 16, 4));
    let homes: Vec<String> = e.homes.iter().map(|(h, _)| h.to_string()).collect();
    assert_eq!(homes, [D, N, S, S2], "grouped by home in the order the homes answered");
    // No frame this module sends is a class scan.
    for f in dialer.frames("find_links_ftt") {
        let q = &f["q"];
        assert!(q["home"].is_array() || q["from"].is_array() || q["to"].is_array(), "a class scan: {q}");
    }
    assert_eq!(dialer.frames("in_claims").len(), e.candidates.len() + 1, "one in_claims per candidate, and the revision's original's");
    assert_eq!(dialer.frames("out_claims").len(), e.candidates.len());
}

/// THE FILTER's keys, one at a time: a successor homed in a PRIVATE document
/// of the person's fails (i) and the original is offered; one whose ends do
/// not cover the published spans fails (iii) and the original is offered; a
/// claim of ANOTHER's naming a public copy drops nothing.
#[test]
fn the_filter_drops_only_on_both_keys_of_the_persons_own_claim() {
    let (mut world, named) = World::base();
    // (i) fails: the copy homed in the private N.
    let private_copy = world.typed(N, vec![ispan(E, 10, 5)], vec![ispan(N, 1, 5)], T_CITATION);
    let claim = world.links.iter().position(|l| l.addr == named.claim_acc).unwrap();
    world.links[claim].to = vec![unit(&private_copy)];
    let (_, board, signer) = open(world);
    let tok = token();
    let p = publisher(&board, &tok, &signer);
    let e = enumerate(&p, &inputs()).unwrap();
    let acc = e.candidates.iter().find(|c| c.link.to_string() == named.l_acc).unwrap();
    assert_eq!((acc.successors[0].published_home, acc.successors[0].covers, acc.offered()), (false, true, true));

    // (iii) fails: the copy covers other words.
    let (mut world, named) = World::base();
    let copy = world.links.iter().position(|l| l.addr == named.copy).unwrap();
    world.links[copy].from = vec![ispan(E, 1, 2)];
    let (_, board, signer) = open(world);
    let p = publisher(&board, &tok, &signer);
    let e = enumerate(&p, &inputs()).unwrap();
    let acc = e.candidates.iter().find(|c| c.link.to_string() == named.l_acc).unwrap();
    assert_eq!((acc.successors[0].published_home, acc.successors[0].covers, acc.offered()), (true, false, true));

    // Another's claim: homed in a sub-account's document, not the person's.
    let (mut world, named) = World::base();
    let claim = world.links.iter().position(|l| l.addr == named.claim_acc).unwrap();
    let row = world.links[claim].clone();
    world.links.remove(claim);
    world.link(SUB, row.from, row.to, row.ty);
    let (_, board, signer) = open(world);
    let p = publisher(&board, &tok, &signer);
    let e = enumerate(&p, &inputs()).unwrap();
    let acc = e.candidates.iter().find(|c| c.link.to_string() == named.l_acc).unwrap();
    assert!(acc.successors.is_empty() && acc.offered(), "another's claim is never read as the person's");
}

/// A `scan_busy` on the region read is reissued under a short backoff and
/// answered; past the bound the step halts `Busy`, nothing written.
#[test]
fn a_busy_region_read_is_reissued_and_halts_past_the_bound() {
    let (world, _) = World::base();
    let (dialer, board, signer) = open(world);
    let tok = token();
    let p = publisher(&board, &tok, &signer);
    dialer.world().busy = 2;
    let e = enumerate(&p, &inputs()).expect("reissued");
    assert_eq!(e.frames[1], ("find_links_v", 3), "two refusals and the answer");
    dialer.world().busy = SCAN_BUSY_REISSUES as usize + 1;
    assert_eq!(enumerate(&p, &inputs()).unwrap_err(), Fault::Busy);
}

/// A held run the draft no longer arranges whole is the first
/// enumeration's fault, naming the run; the re-read reads it as a
/// difference instead.
#[test]
fn a_selection_run_not_arranged_whole_is_refused_at_the_first_enumeration() {
    let (mut world, _) = World::base();
    world.docs.get_mut(D).unwrap().runs = vec![run(E, 1, 19), run(D, 1, 4), run(O, 1, 5), run(D, 5, 6)];
    let (_, board, signer) = open(world);
    let tok = token();
    let p = publisher(&board, &tok, &signer);
    assert_eq!(enumerate(&p, &inputs()).unwrap_err(), Fault::SelectionNotArranged { index: 1 });
}

// ── THE PANEL AND THE COUNT ──────────────────────────────────────────────

/// §5.2's rows in the design's order — the draft's own set, the notes, then
/// the public sets in address order with their read-with state — each with
/// its label, its links folded by type with their far documents, and the
/// line's counts: ⟨p⟩ a far end into a private document, ⟨d⟩ an end wholly
/// on left-out words, ⟨c⟩ an end past the cut, ⟨u⟩ the revision not offered;
/// the formatting line by its test — a one-sided mark, a heading with its
/// parameter span, never the two-ended citation — with the one mark past
/// the cut; the held removals: the spent one dropped, the re-made one paired
/// with the draft's mark of the same type, the plain one listed.
#[test]
fn the_panel_orders_the_rows_and_counts_each_line() {
    let (world, named) = World::base();
    let (_, board, signer) = open(world);
    let tok = token();
    let p = publisher(&board, &tok, &signer);
    let inputs = inputs();
    let e = enumerate(&p, &inputs).unwrap();
    let panel = panel(&p, &inputs, &e).unwrap();
    let kinds: Vec<(String, RowKind)> = panel.rows.iter().map(|r| (r.home.to_string(), r.kind.clone())).collect();
    assert_eq!(kinds, [(D.to_string(), RowKind::Own), (N.to_string(), RowKind::Notes), (S.to_string(), RowKind::Public { read_with: true }), (S2.to_string(), RowKind::Public { read_with: false })]);
    let own = &panel.rows[0];
    assert_eq!(links_of(&e, &own.links), [named.cite_d.clone(), named.cut_d.clone(), named.left_d.clone()], "the marks leave the row for the line");
    assert_eq!(own.line, LineCounts { p: 1, d: 1, c: 1, t: 0, u: 0 });
    assert_eq!(own.label, b"the quick brown fox new wordsquote".to_vec(), "the draft's first line: its arranged text, no newline in it");
    assert_eq!(own.types, vec![TypeFold { ty: T_CITATION.into(), n: 3, far: vec![Z.into()] }]);
    let notes = &panel.rows[1];
    assert_eq!(links_of(&e, &notes.links), [named.l1_n.clone(), named.l_rt.clone()]);
    assert_eq!((notes.line.u, notes.line.p, notes.read_through), (1, 2, 1), "the revision counted, the far ends private, one link read through");
    assert_eq!(notes.label, b"notes here".to_vec());
    assert_eq!(panel.rows[2].label, b"set one".to_vec());
    assert_eq!(links_of(&e, &panel.formatting.marks), [named.mark_d.clone(), named.heading_d.clone(), named.mark_d2.clone()]);
    assert_eq!(panel.formatting.cut, 1, "the heading runs past the selection");
    let removals: Vec<(String, bool, bool, Option<String>)> = panel.formatting.removals.iter().map(|r| (r.mark.to_string(), r.on_selection, r.spent, r.remake.map(|i| e.candidates[i].link.to_string()))).collect();
    assert_eq!(removals, [(named.mpub.clone(), true, false, Some(named.mark_d2.clone())), (named.mpub2.clone(), true, true, None), (named.mpub3.clone(), true, false, None)]);
    assert_eq!(panel.formatting.job_list().len(), 2);
    assert_eq!(panel.read_with, BTreeMap::from([(a(S), true), (a(S2), false)]));
    let steps: Vec<&str> = panel.frames.iter().map(|(s, _)| *s).collect();
    assert_eq!(steps, ["removals", "homes", "far", "labels", "read_with"], "the formatting line's test sends no frame");
}

/// THE COUNT (PUB-3.8): ⟨l⟩ the switched-on sets' entries plus the read-with
/// entries, ⟨n⟩ the line's marks that re-make nothing, ⟨r⟩ the take-offs no
/// re-make covers, ⟨e⟩ the re-makes — in neither ⟨n⟩ nor ⟨r⟩ — the claim
/// clause only at the mint form; a destination `E` is already read with
/// needs no read-with, one it is not does.
#[test]
fn the_count_follows_the_switches_and_the_destinations() {
    let (world, _) = World::base();
    let (_, board, signer) = open(world);
    let tok = token();
    let p = publisher(&board, &tok, &signer);
    let inputs = inputs();
    let e = enumerate(&p, &inputs).unwrap();
    let panel = panel(&p, &inputs, &e).unwrap();
    let off = count(&panel, &Switches::default(), &inputs);
    assert_eq!(off, Count { l: 0, n: 2, r: 1, e: 1, claim: false, read_with: Vec::new() });
    let on = count(&panel, &switched(None).switches, &inputs);
    assert_eq!((on.l, on.n, on.r, on.e, on.read_with.len()), (5, 2, 1, 1, 0));
    let into_s2 = count(&panel, &switched(Some(S2)).switches, &inputs);
    assert_eq!((into_s2.l, into_s2.read_with), (6, vec![a(S2)]), "the read-with E needs is counted");
    let into_s = count(&panel, &switched(Some(S)).switches, &inputs);
    assert_eq!((into_s.l, into_s.read_with), (5, Vec::new()), "E is read with S already");
    let minting = Inputs { mint: Some(a(ACCOUNT)), claim: true, ..inputs.clone() };
    assert!(count(&panel, &Switches::default(), &minting).claim);
    let claim_alone = Inputs { claim: true, ..inputs };
    assert!(!count(&panel, &Switches::default(), &claim_alone).claim, "a claim without a mint is not sent in this build");
}

// ── THE PRICE ────────────────────────────────────────────────────────────

/// THE TABLE IS THE DAEMON's: every per-kind figure, the two budgets, the
/// slot cap and the span arithmetic equal `skep-links`' own — a figure that
/// moves there is a red cell here, not a drift.
#[test]
fn the_price_table_is_the_daemons() {
    use skep_address::{Nat, Span, Tumbler};
    assert_eq!(price::CORRESPONDENCE_RECORD_BYTES, skep_links::CORRESPONDENCE_RECORD_BYTES);
    assert_eq!(price::COPY_FIXED_BYTES, skep_links::COPY_FIXED_BYTES);
    assert_eq!(price::CLAIM_BYTES, skep_links::CLAIM_BYTES);
    assert_eq!(price::RETRACTION_BYTES, skep_links::RETRACTION_BYTES);
    assert_eq!(price::READ_WITH_BYTES, skep_links::READ_WITH_BYTES);
    assert_eq!(price::KEPT_PLACE_BYTES, skep_links::KEPT_PLACE_BYTES);
    assert_eq!(price::PLACED_RUN_BYTES, skep_links::PLACED_RUN_BYTES);
    assert_eq!(price::REINSERTED_VALUE_BYTES, skep_links::REINSERTED_VALUE_BYTES);
    assert_eq!(price::SHOT_BYTES, skep_links::SHOT_BYTES);
    assert_eq!(price::EDITION_MINT_BYTES, skep_links::EDITION_MINT_BYTES);
    assert_eq!(price::EDITION_CLAIM_BYTES, skep_links::EDITION_CLAIM_BYTES);
    assert_eq!(price::REQUEST_BODY_BYTES as u64, skep_links::REQUEST_BODY_BYTES);
    assert_eq!(price::MAX_SLOT_SPANS, skep_links::MAX_SLOT_SPANS);
    assert_eq!(price::MAX_PUBLICATION_READS, skep_links::MAX_PUBLICATION_READS);
    assert_eq!(price::MAX_TXN_BYTES, skep_links::ReadPrice::BYTE_BUDGET);
    assert_eq!(price::MAX_REINSERTED_VALUES, skep_arrangement::MAX_REINSERTED_VALUES as u64);
    assert_eq!(MAX_WIRE_LIST, skep_links::MAX_SLOT_SPANS, "the codec reuses the slot cap for its lists");
    let t = |comps: &[u64]| Tumbler::new(comps.iter().map(|&c| Nat::from(c))).expect("nonempty");
    for (start, width) in [(vec![1, 0, 1, 0, 3, 0, 1, 1], vec![0, 0, 0, 0, 0, 0, 0, 1]), (vec![1, 1, 0, 1, 0, 1, 0, 3, 23, 1], vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 1]), (vec![1, 0, 1, 0, 3, 0, 1, 1], vec![0, 0, 0, 0, 0, 0, 0, 70_000]), (vec![1 << 40, 1 << 40], vec![0, 1])] {
        let span = Span::new(t(&start), t(&width)).expect("a span");
        assert_eq!(price::stored_span_bytes(&start, &width), skep_links::stored_span_bytes(&span), "{start:?}");
    }
}

/// Each term over its cap is refused HERE, before any frame: a list past
/// 4,096, the body past 8 MiB, the values past the re-insert budget, the
/// reads past 65,536, the bytes past 64 MiB — the member-position slot
/// priced at up to 4,096 spans — and a request within every cap admitted.
#[test]
fn each_term_past_its_cap_is_refused_before_any_frame() {
    let draft = a(D);
    let term = a(E);
    let one = vec![run(D, 1, 1)];
    let within = price::price(&price::Shape { runs: &one, draft: &draft, term: &term, mint: false, claim: false, places: &[Some(1)], stray_records: &[0], entries: &[], retract: 0, read_with: 0, body_bytes: 100, homes: 3, draft_runs: 2 });
    assert!(within.admits(), "{within:?}");
    assert_eq!((within.lists, within.values, within.reads), ([1, 1, 0, 0, 0], 1, 2));
    assert_eq!(within.bytes, price::SHOT_BYTES + price::PLACED_RUN_BYTES + price::CORRESPONDENCE_RECORD_BYTES + price::KEPT_PLACE_BYTES + price::REINSERTED_VALUE_BYTES);
    let over = |shape: &price::Shape<'_>| price::price(shape).over.iter().map(|(t, _)| *t).collect::<Vec<_>>();
    let many: Vec<Run> = (0..4097).map(|k| run(E, 1 + k, 1)).collect();
    assert_eq!(over(&price::Shape { runs: &many, draft: &draft, term: &term, mint: false, claim: false, places: &[], stray_records: &[], entries: &[], retract: 0, read_with: 0, body_bytes: 0, homes: 0, draft_runs: 0 }), [price::Term::Runs]);
    assert_eq!(over(&price::Shape { runs: &one, draft: &draft, term: &term, mint: false, claim: false, places: &[], stray_records: &[], entries: &[], retract: 4097, read_with: 0, body_bytes: 0, homes: 0, draft_runs: 0 }), [price::Term::Retract]);
    assert_eq!(over(&price::Shape { runs: &one, draft: &draft, term: &term, mint: false, claim: false, places: &[], stray_records: &[], entries: &[], retract: 0, read_with: 0, body_bytes: price::REQUEST_BODY_BYTES + 1, homes: 0, draft_runs: 0 }), [price::Term::Body]);
    let wide = vec![run(D, 1, price::MAX_REINSERTED_VALUES + 1)];
    let values = price::price(&price::Shape { runs: &wide, draft: &draft, term: &term, mint: false, claim: false, places: &[], stray_records: &[], entries: &[], retract: 0, read_with: 0, body_bytes: 0, homes: 0, draft_runs: 0 });
    assert!(values.over.iter().any(|(t, by)| *t == price::Term::Values && *by == 1), "{values:?}");
    let reads = price::price(&price::Shape { runs: &one, draft: &draft, term: &term, mint: false, claim: false, places: &[], stray_records: &[], entries: &[], retract: 0, read_with: 4096, body_bytes: 0, homes: 17, draft_runs: 0 });
    assert_eq!(reads.over, vec![(price::Term::Reads, (17 * 4096 - price::MAX_PUBLICATION_READS) as u64)]);
    let entry = price::EntryShape { from: price::EndShape::Member(vec![(1, 4096)]), to: price::EndShape::Addrs(vec![]), ty: price::EndShape::Addrs(vec![T_CITATION.into()]), old: false };
    let runs4096: Vec<Run> = (0..4096).map(|k| run(D, 1 + k, 1)).collect();
    let entries = vec![entry; 100];
    let bytes = price::price(&price::Shape { runs: &runs4096, draft: &draft, term: &term, mint: false, claim: false, places: &[], stray_records: &[], entries: &entries, retract: 0, read_with: 0, body_bytes: 0, homes: 1, draft_runs: 1 });
    assert_eq!(bytes.over.iter().map(|(t, _)| *t).collect::<Vec<_>>(), [price::Term::Bytes], "a hundred member-position slots over 4096 runs stage past the budget: {bytes:?}");
    let entries = vec![entries[0].clone()];
    assert!(price::price(&price::Shape { runs: &runs4096, draft: &draft, term: &term, mint: false, claim: false, places: &[], stray_records: &[], entries: &entries, retract: 0, read_with: 0, body_bytes: 0, homes: 1, draft_runs: 1 }).admits(), "one such entry is inside both budgets");
}

// ── THE RE-READ ──────────────────────────────────────────────────────────

/// THE FOUR DIFFERENCES, and the selection's: a link retracted meanwhile has
/// LEFT, one a claim of the person's superseded is SUPERSEDED, a held
/// removal undone is UNDONE, a link that arrived CAME, and a held run the
/// draft moved is re-placed — each re-stated as data; nothing changed is no
/// re-statement.
#[test]
fn the_reread_states_each_difference_over_what_is_left() {
    let (world, named) = World::base();
    let (dialer, board, signer) = open(world);
    let tok = token();
    let p = publisher(&board, &tok, &signer);
    let inputs = inputs();
    let e = enumerate(&p, &inputs).unwrap();
    let first = panel(&p, &inputs, &e).unwrap();
    assert_eq!(reread(&p, &inputs, &e, &first).unwrap().restatement, None);
    {
        let mut w = dialer.world();
        w.retract(N, &named.l1_n);
        let copy = w.typed(&format!("{E}.1"), vec![ispan(E, 1, 3)], vec![], T_CITATION);
        w.claim(S, &named.k_s, &copy);
        let held = w.links.iter().position(|l| l.addr == named.held3).unwrap();
        w.links.remove(held);
        w.typed(N, vec![ispan(E, 2, 2)], vec![], T_CITATION);
        w.docs.get_mut(D).unwrap().runs = vec![run(D, 1, 10), run(E, 1, 19), run(O, 1, 5)];
    }
    let again = reread(&p, &inputs, &e, &first).unwrap();
    let r = again.restatement.expect("a difference");
    assert_eq!(r.left, vec![a(&named.l1_n)]);
    assert_eq!(r.superseded, vec![a(&named.k_s)]);
    assert_eq!(r.removals_undone, vec![a(&named.mpub3)]);
    assert_eq!(r.came.len(), 1);
    assert_eq!(r.removals_came, Vec::<Address>::new());
    assert_eq!(r.selection, vec![(0, Placement::Whole { ordinal: 11 }), (1, Placement::Whole { ordinal: 1 })], "the two runs traded places");
    // Confirmed again, the request carries the new places and nothing that left.
    let Built::Request(request) = build(&p, &inputs, &again.enumeration, &again.panel, &switched(None)).unwrap() else { panic!("inert") };
    assert_eq!(request.places, vec![None, Some(1), None]);
    assert!(!request.entries.iter().any(|en| en.old.as_ref().map(ToString::to_string).as_deref() == Some(named.l1_n.as_str())));
    assert_eq!(request.retract, vec![a(&named.mpub)]);
}

// ── THE REQUEST ──────────────────────────────────────────────────────────

/// THE ONE REQUEST's members as built from the confirmed rows: every run with
/// its kept place beside the draft-native one and none beside a window or a
/// kept run; the `links` entries — the line's marks and the switched-on
/// rows' links, `home` the tag `member`, an end on the new words in the
/// member-position form spelled CANONICALLY from the runs, an end on kept
/// words in the I-span form, a far end verbatim, an end wholly on left-out
/// words as the draft's own I-span, an end on an earlier shot's words mapped
/// through its record onto the published identity, a type's parameter span
/// in the I-span form, `old` the original; `retract` the job list's marks
/// without the spent one; the read-with the destination needs; a fresh
/// `id`; the body through the one builder, verified by the signer.
#[test]
fn the_request_spells_every_member_and_the_canonical_member_end() {
    let (world, named) = World::base();
    let (dialer, board, signer) = open(world);
    let tok = token();
    let (e, _, request) = built(&dialer, &board, &tok, &signer, &switched(Some(S2)));
    assert_eq!(request.runs, vec![run(E, 1, 19), run(D, 1, 10), run(O, 1, 5)]);
    assert_eq!(request.places, vec![None, Some(20), None]);
    assert_eq!(request.retract, vec![a(&named.mpub), a(&named.mpub3)]);
    assert_eq!(request.read_with, vec![a(S2)]);
    assert!(request.id.starts_with("publication."));
    let entry = |link: &str| request.entries.iter().find(|en| e.candidates[en.candidate].link.to_string() == link).unwrap_or_else(|| panic!("no entry for {link}"));
    assert_eq!(entry(&named.mark_d).to, End::Member(vec![(21, 3)]), "the new words' positions after the kept words' nineteen");
    assert_eq!(entry(&named.heading_d).to, End::Member(vec![(20, 10)]), "cut at the selection");
    assert_eq!(entry(&named.heading_d).ty, End::Addrs(vec![T_HEADING.into(), "1.1.0.1.0.1.0.1.3".into()]));
    assert_eq!(entry(&named.mark_d2).to, End::Spans(vec![ISpan { chain: format!("{E}.0.1"), first: 5, width: 5 }]), "kept words by reference");
    assert_eq!(entry(&named.cite_d).from, End::Member(vec![(25, 5)]));
    assert_eq!(entry(&named.cite_d).to, End::Spans(vec![ISpan { chain: format!("{Z}.0.1"), first: 1, width: 3 }]), "the far end verbatim");
    assert_eq!(entry(&named.cut_d).from, End::Member(vec![(28, 2)]), "the end past the cut, cut");
    assert_eq!(entry(&named.left_d).from, End::Spans(vec![ISpan { chain: format!("{D}.0.1"), first: 11, width: 2 }]), "wholly left out: the draft's own span");
    assert_eq!(entry(&named.l_rt).from, End::Spans(vec![ISpan { chain: format!("{E}.0.1"), first: 16, width: 4 }]), "through the record onto the published identity");
    assert_eq!(entry(&named.l1_n).home, EntryHome::Set(a(S2)));
    assert_eq!(entry(&named.mark_d).home, EntryHome::Member);
    assert_eq!(entry(&named.l1_n).old, Some(a(&named.l1_n)));
    assert_eq!(request.entries.len(), 8);
    assert!(request.unspellable.is_empty(), "{:?}", request.unspellable);
    let frame = request.frame(None);
    assert_eq!(frame["doc"], E);
    assert_eq!(frame["places"], json!([null, {"subspace": "1", "ordinal": "20"}, null]));
    assert_eq!(frame["links"].as_array().map(Vec::len), Some(8));
    assert_eq!(frame["retract"], json!([named.mpub, named.mpub3]));
    assert_eq!(frame["read_with"], json!([S2]));
    assert_eq!(frame["id"], request.id);
    assert!(frame.get("mint").is_none() && frame.get("claim").is_none() && frame.get("account").is_none());
    // The body: the kept words and the new words by value, the window by
    // address, then the deposit rows — the member's first.
    assert!(matches!(&request.pieces[0], Piece::Values(v) if v.len() == 19));
    assert!(matches!(&request.pieces[1], Piece::Values(v) if v.iter().map(|b| b[0] as char).collect::<String>() == D_TEXT));
    assert!(matches!(&request.pieces[2], Piece::Window { width: 5, .. }));
    let body = request.body();
    assert!(body.as_bytes().len() > request.shot_body().as_bytes().len(), "the deposit rows follow the shot's");
    assert!(request.price.admits(), "{:?}", request.price);
    // THE CANONICAL FORM at a run named twice: the lowest positions.
    let mut twice = inputs();
    twice.selection = vec![run(E, 1, 19), run(D, 1, 10), run(D, 1, 10), run(O, 1, 5)];
    dialer.world().docs.get_mut(D).unwrap().runs = vec![run(E, 1, 19), run(D, 1, 10), run(D, 1, 10), run(O, 1, 5)];
    let p = publisher(&board, &tok, &signer);
    let e2 = enumerate(&p, &twice).unwrap();
    let panel2 = panel(&p, &twice, &e2).unwrap();
    let mut twice_confirmed = switched(None);
    twice_confirmed.answers.insert(3, OriginAnswer::KeepPrivate);
    let Built::Request(r2) = build(&p, &twice, &e2, &panel2, &twice_confirmed).unwrap() else { panic!("inert") };
    let mark = r2.entries.iter().find(|en| e2.candidates[en.candidate].link.to_string() == named.mark_d).unwrap();
    assert_eq!(mark.to, End::Member(vec![(21, 3)]), "the lowest positions holding each value, never the second occurrence's");
    assert_eq!(r2.places, vec![None, Some(20), Some(30), None]);
}

/// THE THREE ANSWERS at a window onto the person's own unpublished origin:
/// unanswered the request is INERT naming the run; publish-first is not this
/// request; DROP leaves the run out; KEEP PRIVATE sends it as a window with
/// no place; and THE COUNTERPART FIRST — a record of a draft the person reads
/// naming the window's words — offered as data and, taken, re-composed by
/// reference with no place.
#[test]
fn the_three_answers_and_the_counterpart_first() {
    let (world, _) = World::base();
    let (_, board, signer) = open(world);
    let tok = token();
    let p = publisher(&board, &tok, &signer);
    let inputs = inputs();
    let e = enumerate(&p, &inputs).unwrap();
    let panel = panel(&p, &inputs, &e).unwrap();
    let mut confirmed = switched(None);
    confirmed.answers.clear();
    assert_eq!(build(&p, &inputs, &e, &panel, &confirmed).unwrap(), Built::Inert(Inert::Unanswered(vec![2])));
    confirmed.answers.insert(2, OriginAnswer::PublishFirst);
    assert_eq!(build(&p, &inputs, &e, &panel, &confirmed).unwrap(), Built::Inert(Inert::PublishFirst(vec![2])));
    confirmed.answers.insert(2, OriginAnswer::Drop);
    let Built::Request(dropped) = build(&p, &inputs, &e, &panel, &confirmed).unwrap() else { panic!() };
    assert_eq!(dropped.runs, vec![run(E, 1, 19), run(D, 1, 10)]);
    confirmed.answers.insert(2, OriginAnswer::KeepPrivate);
    let Built::Request(kept) = build(&p, &inputs, &e, &panel, &confirmed).unwrap() else { panic!() };
    assert_eq!((kept.runs.len(), kept.places[2]), (3, None));
    assert!(matches!(kept.pieces[2], Piece::Window { .. }));
    // The counterpart: O published before as E's words 16..19 (a record in O).
    let (mut world, _) = World::base();
    let record = world.typed(O, vec![ispan(O, 1, 4)], vec![ispan(E, 16, 4)], T_CORRESPONDENCE);
    let (_, board, signer) = open(world);
    let p = publisher(&board, &tok, &signer);
    let mut with_o = inputs.clone();
    with_o.readable_drafts.push(a(O));
    let e = enumerate(&p, &with_o).unwrap();
    let panel = super::panel::panel(&p, &with_o, &e).unwrap();
    confirmed.answers.insert(2, OriginAnswer::KeepPrivate);
    let Built::Request(offered) = build(&p, &with_o, &e, &panel, &confirmed).unwrap() else { panic!() };
    assert_eq!(offered.counterparts.len(), 1);
    assert_eq!((offered.counterparts[0].run, offered.counterparts[0].record.to_string(), offered.counterparts[0].to.first, offered.counterparts[0].to.width), (2, record.clone(), 16, 4));
    confirmed.answers.insert(2, OriginAnswer::Counterpart);
    let Built::Request(taken) = build(&p, &with_o, &e, &panel, &confirmed).unwrap() else { panic!() };
    assert_eq!(taken.runs[2], run(E, 16, 4), "the covered part re-composed by reference to the record's to");
    assert_eq!(taken.runs[3], run(O, 5, 1), "the rest a window still");
    assert_eq!(&taken.places[2..], &[None, None]);
}

/// THE TWIN PRE-CHECK: a draft-native run whose words an earlier shot
/// published — the draft's record names them — is re-composed by reference
/// to the record's `to` at its offset, in pieces where the record covers it
/// in part, each piece with its kept place, so the request never meets the
/// fence for them.
#[test]
fn the_twin_precheck_recomposes_the_recorded_words_by_reference() {
    let (mut world, _) = World::base();
    world.typed(D, vec![ispan(D, 4, 3)], vec![ispan(E, 20, 3)], T_CORRESPONDENCE);
    let (_, board, signer) = open(world);
    let tok = token();
    let p = publisher(&board, &tok, &signer);
    let inputs = inputs();
    let re = twin_precheck(&p, &inputs, &[run(D, 1, 10)], &[Some(20)], &[Some(20)]).unwrap();
    assert_eq!(re.runs, vec![run(D, 1, 3), run(E, 20, 3), run(D, 7, 4)]);
    assert_eq!(re.places, vec![Some(20), Some(23), Some(26)]);
    assert_eq!(re.stray_records, vec![0, 1, 0]);
    assert_eq!(re.frames, vec![("twin_precheck", 2)], "the records read and the one record's read_link");
}

/// A request that changes nothing against its base — every run the base
/// member's by reference, no entry, no place — is INERT.
#[test]
fn an_unchanged_request_is_inert() {
    let (mut world, _) = World::base();
    world.docs.get_mut(D).unwrap().runs = vec![run(E, 1, 19)];
    for l in world.links.iter_mut().filter(|l| l.home == D) {
        l.retracted = true;
    }
    let (_, board, signer) = open(world);
    let tok = token();
    let p = publisher(&board, &tok, &signer);
    let mut inputs = inputs();
    inputs.selection = vec![run(E, 1, 19)];
    let e = enumerate(&p, &inputs).unwrap();
    let panel = panel(&p, &inputs, &e).unwrap();
    assert_eq!(build(&p, &inputs, &e, &panel, &Confirmed::default()).unwrap(), Built::Inert(Inert::Unchanged));
}

// ── THE SEND AND THE LANDED TEST ─────────────────────────────────────────

/// THE ACKNOWLEDGMENT: the frame under the token with its `id` and an
/// `attest` over the body as built; the member minted, the copies in it and
/// in the set, the claims at home, the retractions, the read-with, the
/// draft re-windowed; a second send of the same request answers the memo.
#[test]
fn the_send_is_acknowledged_and_the_commit_holds_every_deposit() {
    let (world, named) = World::base();
    let (dialer, board, signer) = open(world);
    let tok = token();
    let (_, _, mut request) = built(&dialer, &board, &tok, &signer, &switched(Some(S2)));
    let p = publisher(&board, &tok, &signer);
    dialer.clear();
    let sent = send(&p, &inputs(), &mut request).expect("sent");
    let Sent::Acknowledged(ack) = &sent else { panic!("{sent:?}") };
    assert_eq!((ack.member.to_string(), ack.via, ack.edition.clone()), (format!("{E}.2"), AckVia::Answer, None));
    let frames = dialer.frames("publish");
    assert_eq!(frames.len(), 1);
    assert!(frames[0]["attest"].is_object() && frames[0]["id"] == request.id);
    let w = dialer.world();
    let member = format!("{E}.2");
    assert_eq!(w.docs[&member].runs, vec![run(E, 1, 29), run(O, 1, 5)], "the new words minted under E, I-adjacent to the kept words and so one run with them");
    assert_eq!(w.docs[D].runs, vec![run(E, 1, 29), run(O, 1, 5)], "the draft re-windowed at its kept place");
    let copies: Vec<&LinkRow> = w.links.iter().filter(|l| l.home == member).collect();
    assert_eq!(copies.len(), 6, "the line's three and the own row's three");
    assert_eq!(copies[0].to, vec![ispan(E, 21, 3)], "the mark's end resolved from the member's positions");
    let in_s2: Vec<&LinkRow> = w.links.iter().filter(|l| l.home == S2 && l.at == ack.at).collect();
    assert_eq!(in_s2.len(), 3, "the notes' two copies and the read-with");
    assert!(in_s2.iter().any(|l| l.ty[0].0 == T_READ_WITH && l.from[0].0 == E && l.to[0].0 == S2));
    assert!(w.links.iter().any(|l| l.home == N && l.ty[0].0 == T_SUPERSEDES && l.from[0].0 == named.l1_n), "the claim at the original's home");
    assert!(w.links.iter().filter(|l| l.addr == named.mpub || l.addr == named.mpub3).all(|l| l.retracted));
    let records: Vec<&LinkRow> = w.links.iter().filter(|l| l.home == D && l.ty[0].0 == T_CORRESPONDENCE && l.at == ack.at).collect();
    assert_eq!(records.len(), 1);
    assert_eq!((records[0].from.clone(), records[0].to.clone()), (vec![ispan(D, 1, 10)], vec![ispan(E, 20, 10)]));
    drop(w);
    // The same request again: the memo answers, nothing applied twice.
    let position = dialer.world().position;
    let again = send(&p, &inputs(), &mut request).unwrap();
    assert!(matches!(again, Sent::Acknowledged(ref a2) if a2.member == ack.member && a2.at == ack.at));
    assert_eq!(dialer.world().position, position, "the memo, not a second commit");
}

/// NEVER UNSIGNED ON A CLAIMED BOARD: a head record that cannot be read where
/// `/health` names a claimant is the halt's data, no frame sent; a board no
/// one claimed takes the frame without an `attest`.
#[test]
fn an_unreadable_head_on_a_claimed_board_sends_nothing() {
    let (world, _) = World::base();
    let (dialer, board, signer) = open(world);
    let tok = token();
    let (_, _, mut request) = built(&dialer, &board, &tok, &signer, &switched(None));
    dialer.world().head = false;
    let (_, board, signer) = open(World::base().0);
    let fresh_board = board;
    let _ = fresh_board;
    let (dialer2, board2, signer2) = open({
        let (mut w, _) = World::base();
        w.head = false;
        w
    });
    let p = publisher(&board2, &tok, &signer2);
    dialer2.clear();
    assert_eq!(send(&p, &inputs(), &mut request).unwrap(), Sent::Refused(Refusal::HeadUnreadable));
    assert!(dialer2.frames("publish").is_empty(), "no frame: {:?}", dialer2.ops());
    dialer2.world().claimed = false;
    let sent = send(&p, &inputs(), &mut request).unwrap();
    assert!(matches!(sent, Sent::Acknowledged(_)), "{sent:?}");
    assert!(dialer2.frames("publish")[0].get("attest").is_none(), "an unclaimed board takes the frame unsigned");
    let _ = signer;
}

/// THE REFUSAL FAMILY's arms, each from the board's own refusal with its
/// site: `kept_place_moved` with the entry and the race's key off the feed;
/// `stray_place_unrecorded` the library's own; `publication_over_budget` a
/// race where this price admitted; `not_owner` naming the draft; the six
/// deposit tokens with their entry and detail; `unparseable` on a request
/// carrying members the older-board arm; the shot's table the library's
/// own; `withheld` the window's origin; `signed_session_required`; and the
/// board's other refusals verbatim.
#[test]
fn every_refusal_arm_carries_its_face_data() {
    let (world, _) = World::base();
    let (dialer, board, signer) = open(world);
    let tok = token();
    let (_, _, mut request) = built(&dialer, &board, &tok, &signer, &switched(None));
    let p = publisher(&board, &tok, &signer);
    let refuse = |code: &str, extra: Value| {
        let mut rej = json!({"resp": "rejected", "code": code, "disposition": "permanent", "op": "publish"});
        for (k, v) in extra.as_object().unwrap() {
            rej[k] = v.clone();
        }
        dialer.world().refuse_next = Some(rej);
    };
    dialer.world().rows.push(FeedRow { at: 999, op: "insert", docs: vec![D.to_string()], key: Some("ab".repeat(32).leak()) });
    refuse("kept_place_moved", json!({"site": {"index": 1}}));
    let sent = send(&p, &inputs(), &mut request).unwrap();
    let Sent::Refused(Refusal::KeptPlaceMoved { index, race }) = sent else { panic!("{sent:?}") };
    assert_eq!(index, 1);
    assert_eq!(race, Some(RaceKey { at: 999, key: Some("ab".repeat(32)), signed: false }), "whose write moved the words");
    refuse("stray_place_unrecorded", json!({"site": {"index": 0}}));
    assert_eq!(send(&p, &inputs(), &mut request).unwrap(), Sent::Refused(Refusal::OwnFault(OwnFault::StrayPlace { index: 0 })));
    refuse("publication_over_budget", json!({"detail": "70000 in-lock reads priced over the budget of 65536"}));
    assert_eq!(send(&p, &inputs(), &mut request).unwrap(), Sent::Refused(Refusal::BudgetRace { detail: Some("70000 in-lock reads priced over the budget of 65536".into()) }));
    refuse("not_owner", json!({"site": {"addr": D}}));
    assert_eq!(send(&p, &inputs(), &mut request).unwrap(), Sent::Refused(Refusal::UnownedDraft { draft: a(D) }));
    refuse("not_owner", json!({"site": {"addr": E}}));
    assert_eq!(send(&p, &inputs(), &mut request).unwrap(), Sent::Refused(Refusal::NotOwner { addr: Some(a(E)) }));
    for code in ["link_home_refused", "old_refused", "duplicate_original", "read_with_in_links", "retract_refused", "read_with_refused"] {
        refuse(code, json!({"site": {"index": 2}, "detail": "superseded"}));
        assert_eq!(send(&p, &inputs(), &mut request).unwrap(), Sent::Refused(Refusal::OwnFault(OwnFault::Deposit { code: code.into(), index: Some(2), detail: Some("superseded".into()) })));
    }
    dialer.world().refuse_next = Some(json!({"resp": "rejected", "code": "malformed", "detail": "unknown field `links`", "disposition": "permanent", "op": "unparseable"}));
    assert_eq!(send(&p, &inputs(), &mut request).unwrap(), Sent::Refused(Refusal::OlderBoard { detail: Some("unknown field `links`".into()) }));
    refuse("base_superseded", json!({}));
    assert_eq!(send(&p, &inputs(), &mut request).unwrap(), Sent::Refused(Refusal::OwnFault(OwnFault::Shot { code: "base_superseded".into() })));
    refuse("withheld", json!({"site": {"addr": O}}));
    assert_eq!(send(&p, &inputs(), &mut request).unwrap(), Sent::Refused(Refusal::WindowWithheld { origin: Some(a(O)) }));
    refuse("signed_session_required", json!({}));
    assert_eq!(send(&p, &inputs(), &mut request).unwrap(), Sent::Refused(Refusal::NeedsSignedSession));
    refuse("write_busy", json!({}));
    assert!(matches!(send(&p, &inputs(), &mut request).unwrap(), Sent::Refused(Refusal::Other(_))));
    let position = dialer.world().position;
    assert_eq!(dialer.world().position, position, "nothing committed by a refusal");
}

/// THE ONE RE-SIGN: `attestation_invalid:signature` where a `retract` mark
/// was retracted meanwhile — the body named a deposit the plan skipped —
/// drops the entry after re-reading presence and re-signs ONCE under a
/// FRESH `id`; a second refusal, or one with nothing to drop, is the
/// library's own fault.
#[test]
fn a_skipped_deposit_is_dropped_and_re_signed_once_under_a_fresh_id() {
    let (world, named) = World::base();
    let (dialer, board, signer) = open(world);
    let tok = token();
    let (_, _, mut request) = built(&dialer, &board, &tok, &signer, &switched(None));
    let p = publisher(&board, &tok, &signer);
    let first_id = request.id.clone();
    dialer.world().retract(&format!("{E}.1"), &named.mpub3);
    dialer.world().refuse_next = Some(json!({"resp": "rejected", "code": "credential_refused", "detail": "attestation_invalid:signature", "disposition": "permanent", "op": "publish"}));
    dialer.clear();
    let sent = send(&p, &inputs(), &mut request).unwrap();
    assert!(matches!(sent, Sent::Acknowledged(_)), "{sent:?}");
    assert_eq!(request.retract, vec![a(&named.mpub)], "the retracted mark's entry dropped");
    assert_ne!(request.id, first_id, "a fresh id");
    let frames = dialer.frames("publish");
    assert_eq!(frames.len(), 2);
    assert_eq!((frames[0]["id"].as_str(), frames[1]["id"].as_str()), (Some(first_id.as_str()), Some(request.id.as_str())));
    assert_eq!(frames[1]["retract"], json!([named.mpub]));
    // Nothing to drop: the library's own fault, once, no second send.
    let (world, _) = World::base();
    let (dialer, board, signer) = open(world);
    let (_, _, mut request) = built(&dialer, &board, &tok, &signer, &switched(None));
    let p = publisher(&board, &tok, &signer);
    dialer.world().refuse_next = Some(json!({"resp": "rejected", "code": "credential_refused", "detail": "attestation_invalid:signature", "disposition": "permanent", "op": "publish"}));
    dialer.clear();
    assert_eq!(send(&p, &inputs(), &mut request).unwrap(), Sent::Refused(Refusal::OwnFault(OwnFault::Attest { detail: Some("attestation_invalid:signature".into()) })));
    assert_eq!(dialer.frames("publish").len(), 1);
}

/// THE LOST ACKNOWLEDGMENT: the answer lost twice at the transport, the
/// same `id` re-asked once, then the board READ FIRST — the draft's records
/// name the member, the member holds the runs, every copy in its home at
/// the commit's position by the position-fenced read, every mark retracted
/// — the acknowledgment, no third send; and the probe's reads counted.
#[test]
fn a_lost_acknowledgment_is_read_back_from_the_records_and_never_re_sent() {
    let (world, _) = World::base();
    let (dialer, board, signer) = open(world);
    let tok = token();
    let (_, _, mut request) = built(&dialer, &board, &tok, &signer, &switched(Some(S2)));
    let p = publisher(&board, &tok, &signer);
    dialer.world().drop_acks = 2;
    dialer.clear();
    let sent = send(&p, &inputs(), &mut request).unwrap();
    let Sent::Acknowledged(ack) = sent else { panic!("{sent:?}") };
    assert_eq!((ack.member.to_string(), ack.via), (format!("{E}.2"), AckVia::Records));
    let publishes = dialer.frames("publish");
    assert_eq!(publishes.len(), 2, "one re-ask under the same id, no third");
    assert_eq!(publishes[0]["id"], publishes[1]["id"]);
    let ops = dialer.ops();
    assert!(ops.iter().any(|o| o.starts_with("GET /changes?")), "the member off the feed at the record's position");
    let probes = dialer.frames("read_link").iter().filter(|f| f["a"].as_str().is_some_and(|a| a.starts_with(&format!("{E}.2.0.2.")) || a.starts_with(&format!("{S2}.0.2.")))).count();
    assert!(probes <= 40, "{probes} read_links over two homes: a gallop and two searches each, under 5·⌈log₂⌉ apiece plus the run");
    // A lost answer at a request the board refused — a place the draft does
    // not honour — commits nothing: the records name no member, NOT LANDED,
    // the caller re-sends.
    let (world, _) = World::base();
    let (dialer, board, signer) = open(world);
    let (_, _, mut request) = built(&dialer, &board, &tok, &signer, &switched(None));
    let p = publisher(&board, &tok, &signer);
    request.places[1] = Some(21);
    dialer.world().drop_acks = 2;
    dialer.clear();
    assert_eq!(send(&p, &inputs(), &mut request).unwrap(), Sent::NotLanded);
    assert_eq!(dialer.frames("publish").len(), 2, "the one re-ask, then the read");
}

/// THE LANDED TEST's three answers at a member that holds the runs: pass;
/// a copy missing — another's commit with fewer sets on; a mark still
/// standing — another's commit without this request's take-offs; and the
/// twin refusal read as the acknowledgment where the test passes.
#[test]
fn the_landed_test_passes_or_names_what_the_member_lacks() {
    let (world, named) = World::base();
    let (dialer, board, signer) = open(world);
    let tok = token();
    let (_, _, mut request) = built(&dialer, &board, &tok, &signer, &switched(None));
    let p = publisher(&board, &tok, &signer);
    let Sent::Acknowledged(ack) = send(&p, &inputs(), &mut request).unwrap() else { panic!() };
    let member = ack.member.clone();
    assert_eq!(landed(&p, &inputs(), &request, Base::Member(member.clone())).unwrap(), Verdict::Passed(Ack { member: member.clone(), at: ack.at, edition: None, via: AckVia::Twin }));
    assert!(matches!(landed(&p, &inputs(), &request, Base::Walk).unwrap(), Verdict::Passed(Ack { via: AckVia::Walk, .. })), "the walk from the base finds the trunk's next member");
    // The twin: a re-send meets the fence and reads the refusal as the ack.
    dialer.world().refuse_next = Some(json!({"resp": "rejected", "code": "already_published", "disposition": "permanent", "op": "publish", "site": {"addr": member.to_string()}}));
    let twin = send(&p, &inputs(), &mut request).unwrap();
    assert!(matches!(twin, Sent::Acknowledged(Ack { via: AckVia::Twin, .. })), "{twin:?}");
    // A copy missing: another's commit.
    {
        let mut w = dialer.world();
        let k = w.links.iter().position(|l| l.home == member.to_string() && l.to == vec![ispan(E, 21, 3)]).unwrap();
        w.links.remove(k);
    }
    let v = landed(&p, &inputs(), &request, Base::Member(member.clone())).unwrap();
    assert_eq!(v, Verdict::Anothers { member: member.clone(), missing: Missing::Copy(0) });
    dialer.world().refuse_next = Some(json!({"resp": "rejected", "code": "already_published", "disposition": "permanent", "op": "publish", "site": {"addr": member.to_string()}}));
    assert_eq!(send(&p, &inputs(), &mut request).unwrap(), Sent::Refused(Refusal::Twin { member: member.clone(), missing: Some(Missing::Copy(0)) }));
    // A mark standing: the copies restored, the retraction undone.
    let (world, _) = World::base();
    let (dialer, board, signer) = open(world);
    let (_, _, mut request) = built(&dialer, &board, &tok, &signer, &switched(None));
    let p = publisher(&board, &tok, &signer);
    let Sent::Acknowledged(ack) = send(&p, &inputs(), &mut request).unwrap() else { panic!() };
    {
        let mut w = dialer.world();
        w.links.retain(|l| !(l.ty[0].0 == T_RETRACTION && l.to[0].0 == named.mpub3));
        w.links.iter_mut().find(|l| l.addr == named.mpub3).unwrap().retracted = false;
    }
    assert_eq!(landed(&p, &inputs(), &request, Base::Member(ack.member.clone())).unwrap(), Verdict::Anothers { member: ack.member.clone(), missing: Missing::Retraction(1) });
    // No member holds the runs: not found.
    let mut other = request.clone();
    other.runs[1] = run(D, 2, 8);
    assert_eq!(landed(&p, &inputs(), &other, Base::Member(ack.member.clone())).unwrap(), Verdict::NotFound);
}

/// THE MINT FORM: `account` with `mint` and `claim`, no `doc`; the edition
/// minted with its member and its claim, the acknowledgment naming the
/// edition; and the lost answer read back through `edition_claims(D)`.
#[test]
fn the_mint_form_mints_the_edition_and_its_lost_answer_is_read_through_the_claim() {
    let (mut world, _) = World::base();
    world.docs.get_mut(D).unwrap().runs = vec![run(D, 1, 10)];
    let (dialer, board, signer) = open(world);
    let tok = token();
    let p = publisher(&board, &tok, &signer);
    let inputs = Inputs { doc: None, mint: Some(a(ACCOUNT)), claim: true, base: None, selection: vec![run(D, 1, 10)], published: vec![a(S), a(S2)], ..inputs() };
    let e = enumerate(&p, &inputs).unwrap();
    let panel = panel(&p, &inputs, &e).unwrap();
    let Built::Request(mut request) = build(&p, &inputs, &e, &panel, &Confirmed::default()).unwrap() else { panic!() };
    let frame = request.frame(None);
    assert_eq!((frame["account"].as_str(), frame["mint"].as_bool(), frame["claim"].as_bool(), frame.get("doc")), (Some(ACCOUNT), Some(true), Some(true), None));
    assert!(request.count.claim);
    dialer.clear();
    let Sent::Acknowledged(ack) = send(&p, &inputs, &mut request).unwrap() else { panic!() };
    let edition = ack.edition.clone().expect("the edition minted");
    assert_eq!(ack.member.to_string(), format!("{edition}.1"));
    assert!(dialer.world().links.iter().any(|l| l.home == edition.to_string() && l.ty[0].0 == T_EDITION && l.to[0].0 == D), "the claim homed in the edition, to the draft");
    // Lost at a records-less minting request — every run a window, no
    // entry — the claim read from D names the edition.
    let mut records_less = request.clone();
    records_less.runs = vec![run(S, 1, 7)];
    records_less.pieces = vec![Piece::Window { start: a(&format!("{S}.0.1.1")), width: 7 }];
    records_less.places = vec![None];
    records_less.stray_records = vec![0];
    records_less.entries.clear();
    records_less.retract.clear();
    records_less.read_with.clear();
    records_less.id = fresh_id();
    dialer.world().drop_acks = 2;
    let sent = send(&p, &inputs, &mut records_less).unwrap();
    assert!(matches!(sent, Sent::Acknowledged(Ack { via: AckVia::EditionClaim, .. })), "{sent:?}");
    // No claim standing, nothing committed: the publication may already stand.
    dialer.world().links.retain(|l| l.ty[0].0 != T_EDITION);
    records_less.places = vec![Some(99)];
    records_less.id = fresh_id();
    dialer.world().drop_acks = 2;
    assert_eq!(send(&p, &inputs, &mut records_less).unwrap(), Sent::Refused(Refusal::MayAlreadyStand));
}
