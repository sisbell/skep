//! The publication composition's unit suite over a SCRIPTED BOARD: a
//! `Dialer` whose answers come from a `World` the test writes — the
//! documents' arrangements and bytes, every link with its slots and age, the
//! claims as supersession links, the feed's rows, the drafts' recorded bases
//! — which APPLIES a publication as the daemon does (a frame with no
//! `attest` refused at a claimed board serving `H.1`, the twin fence, the
//! kept places, an `old` refused `superseded` where a public successor an
//! active claim of the person's names covers the entry's published spans —
//! the claim naming `old` itself only where no member-position end lies on
//! the shot's new words — one fresh identity per draft identity, the
//! records, the copies resolved from the member's positions, the claims,
//! the retractions, the read-withs, the re-window, the base's move, the
//! memo) and keeps every frame it served, so a test pins what each step
//! reads, in what order and how many frames, and what the composition makes
//! of each answer, with no daemon. The suites that need the daemon itself
//! are `tests/it/publication.rs`.
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
use skep_address::{Address, Span};
use skep_identity::{entry_body_publication, entry_frame, unit_span, DepositHome, DepositKind, DepositRow, DepositSlot, DocTerm, PublicKey, SlotElement};
use skep_signature::HybridSigner;

use crate::address::parse_address;
use crate::board::answers::LinkSpan;
use crate::board::frames::{T_CORRESPONDENCE, T_EDITION, T_HELD_REMOVAL, T_READ_WITH};
use crate::board::{Board, Token, HEAD_MEMBER_1, T_RETRACTION, T_SUPERSEDES};
use crate::dial::{DialError, Dialer, Headers, Request as DialRequest, RequestHead, Response, StreamedResponse};
use crate::origin::Origin;
use crate::sign::Signer;

use super::base::Base as DraftBase;
use super::enumerate::RecordWalk;
use super::panel::Destination;
use super::request::{Answer as OriginAnswer, Confirmed, Inert, OwnedRow, Piece};
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
const T_EMPHASIS: &str = "1.1.0.1.0.1.0.3.23.1";
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
    /// The surface a `stage` copied into it — `doc_metadata`'s `source`.
    source: Option<String>,
    /// The draft base the board records — `doc_metadata`'s `base`, and
    /// beside it `base_copied`, each answered as it stands.
    base: Option<String>,
    base_copied: Option<u64>,
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
    /// The positions holding a composite value, an atom, in place of a byte.
    atoms: BTreeMap<(String, u64), String>,
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
    /// The next N `doc_metadata` answer `503 history_busy`.
    history_busy: usize,
    /// `image` refuses `image_too_large` past this many runs.
    image_cap: usize,
    /// `/health` names a claimant.
    claimed: bool,
    /// `H.1` answers its record.
    head: bool,
    /// `H.1` answers a record that stands and cannot be read.
    damaged_head: bool,
    /// A claim lands before the next publish is judged: from then on
    /// `/health` names a claimant and `H.1` answers its record.
    claim_at_publish: bool,
    key: Option<PublicKey>,
}

impl World {
    fn doc(&mut self, text: &str, published: bool, owner: &str, runs: Vec<Run>) {
        self.position += 1;
        self.docs.insert(text.to_string(), DocState { runs, published, owner: owner.to_string(), placed: None, base_extent: None, source: None, base: None, base_copied: None, at: self.position });
    }

    fn text(&mut self, origin: &str, from: u64, text: &str) {
        for (k, b) in text.bytes().enumerate() {
            self.values.insert((origin.to_string(), from + k as u64), b);
        }
        let next = self.next_fresh.entry(origin.to_string()).or_insert(1);
        *next = (*next).max(from + text.len() as u64);
    }

    /// An atom at `origin`'s ordinal `n`: one composite value.
    fn atom(&mut self, origin: &str, n: u64, atom: &str) {
        self.atoms.insert((origin.to_string(), n), atom.to_string());
        let next = self.next_fresh.entry(origin.to_string()).or_insert(1);
        *next = (*next).max(n + 1);
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

    /// Records `draft` as staged from `from`, as the board's `stage` does
    /// (wire.md §Namespace): `from`'s reading surface — a trunk's head where
    /// it has members — the draft's source; a published surface its base,
    /// at its whole count; a draft's own recorded base inherited, and none
    /// where it holds none. The draft's arrangement is the cell's.
    fn stage(&mut self, draft: &str, from: &str) {
        let surface = self.trunk_head.get(from).cloned().unwrap_or_else(|| from.to_string());
        let source = self.docs[&surface].clone();
        let (base, copied) = if source.published { (Some(surface.clone()), Some(source.runs.iter().map(|r| r.width).sum())) } else { (source.base, source.base_copied) };
        let d = self.docs.get_mut(draft).expect("the draft");
        d.source = Some(surface);
        d.base = base;
        d.base_copied = copied;
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

    /// The active supersession claims homed in a document the person owns
    /// exactly, each kept where `keep` holds.
    fn own_claims<'w>(&'w self, keep: impl Fn(&LinkRow) -> bool + 'w) -> impl Iterator<Item = &'w LinkRow> + 'w {
        let owned = |home: &str| trunk_of(home).and_then(|t| self.docs.get(&t)).is_some_and(|d| d.owner == ACCOUNT);
        self.links.iter().filter(move |l| !l.retracted && l.ty.first().is_some_and(|t| t.0 == T_SUPERSEDES) && owned(&l.home) && keep(l))
    }

    /// The content spans of a `links` entry's two ends on published
    /// identity, as the plan's `published_spans` reads them: the I-span form
    /// as given and the member-position form resolved through the request's
    /// runs, every span of a named draft's own words left out.
    fn published_spans(entry: &Value, runs: &[Run], named: &[String]) -> Vec<ISpan> {
        let mut out = Vec::new();
        for end in [&entry["from"], &entry["to"]] {
            let spans: Vec<ISpan> = if let Some(list) = end["spans"].as_array() {
                list.iter()
                    .map(|x| {
                        let (chain, first) = x["start"].as_str().unwrap().rsplit_once('.').unwrap();
                        ISpan { chain: chain.to_string(), first: first.parse().unwrap(), width: x["width"].as_str().unwrap().parse().unwrap() }
                    })
                    .collect()
            } else {
                Self::member_end(end, runs).unwrap_or_default()
            };
            out.extend(spans.into_iter().filter(|s| !s.document().is_some_and(|d| named.contains(&d))));
        }
        out
    }

    /// Returns the I-spans a member-position end resolves to through `runs`.
    ///
    /// It resolves the end as the plan's `member_end` does; an end of
    /// another form answers `None`.
    fn member_end(end: &Value, runs: &[Run]) -> Option<Vec<ISpan>> {
        let spans: Vec<(u64, u64)> = end["member"].as_array()?.iter().map(|x| (x["ordinal"].as_str().unwrap().parse().unwrap(), x["width"].as_str().unwrap().parse().unwrap())).collect();
        Some(resolve_member_spans(runs, &spans).expect("inside the placed positions"))
    }

    /// Returns whether a `links` entry's member-position end holds new words.
    ///
    /// Some span the end resolves to through the request's runs lies on a
    /// named draft's own words, as the plan's `holds_new_words` reads it. An
    /// I-span end on those words names the draft's own identity, a far end
    /// on words the shot leaves out, and holds none.
    fn holds_new_words(entry: &Value, runs: &[Run], named: &[String]) -> bool {
        [&entry["from"], &entry["to"]].into_iter().filter_map(|end| Self::member_end(end, runs)).flatten().any(|s| s.document().is_some_and(|d| named.contains(&d)))
    }

    /// Whether an active claim of the person's names `old` and a successor
    /// homed in a published document of theirs whose ends hold each of
    /// `spans` within one of their spans — the plan's
    /// `superseded_by_own_claim`, no liveness of the successor asked; never
    /// where `spans` is empty.
    fn superseded_by_own_claim(&self, old: &str, spans: &[ISpan]) -> bool {
        if spans.is_empty() {
            return false;
        }
        self.own_claims(|c| c.from.first().is_some_and(|s| s.0 == old)).any(|claim| {
            let new = &claim.to[0].0;
            let public = home_of_link(new).and_then(|h| self.docs.get(h)).is_some_and(|d| d.published && d.owner == ACCOUNT);
            let Some(successor) = self.links.iter().find(|l| l.addr == *new) else { return false };
            let ends: Vec<ISpan> = successor.from.iter().chain(&successor.to).filter_map(|(start, width)| ISpan::of(&LinkSpan { start: start.clone(), width: width.clone() })).collect();
            public && spans.iter().all(|s| ends.iter().any(|e| e.chain == s.chain && e.first <= s.first && s.reach() <= e.reach()))
        })
    }

    /// The originals `y` revises: the `old` of each active claim of the
    /// person's naming `y` as its `new` — the plan's `originals_of`.
    fn originals_of(&self, y: &str) -> Vec<String> {
        self.own_claims(|c| c.to.first().is_some_and(|s| s.0 == y)).map(|c| c.from[0].0.clone()).collect()
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
                if self.history_busy > 0 {
                    self.history_busy -= 1;
                    return Ok(reply(503, json!({"error": "history_busy", "detail": "the reconstruction pool is full; retry shortly", "op": "doc_metadata"})));
                }
                let doc = frame["doc"].as_str().unwrap();
                let Some(d) = self.docs.get(doc).cloned() else { return Ok(rejected("doc_not_registered", json!({}))) };
                if !self.readable(doc) {
                    return Ok(rejected("withheld", json!({"site": {"addr": doc}})));
                }
                Ok(reply(200, json!({"resp": "doc_metadata", "as_of": position, "doc": trunk_of(doc), "published": d.published, "owner": d.owner, "placed": d.placed.map(|p| p.to_string()), "base_extent": d.base_extent.map(|e| e.to_string()), "source": d.source, "base": d.base, "base_copied": d.base_copied.map(|c| c.to_string()), "at": d.at})))
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
                    let items = if self.damaged_head {
                        json!([{"atom": "not a head record"}])
                    } else if self.head {
                        json!([{"atom": json!({"type": "skep-head", "position": 1, "chain": chain_hex(1)}).to_string()}])
                    } else {
                        json!([])
                    };
                    return Ok(reply(200, json!({"resp": "delivery", "as_of": position, "items": items})));
                }
                let (from, width) = span_of(&spec["span"]);
                let Some(runs) = self.arrangement(doc) else { return Ok(rejected("doc_not_registered", json!({}))) };
                let positions = Self::expand(&runs);
                // A run of bytes is one `content` item, an atom an item of
                // its own (wire.md §Value encodings).
                let (mut items, mut text, mut covered) = (Vec::new(), String::new(), 0u64);
                for (o, n) in positions.iter().skip(from as usize - 1).take(width as usize) {
                    covered += 1;
                    match self.atoms.get(&(o.to_string(), *n)) {
                        Some(atom) => {
                            if !text.is_empty() {
                                items.push(json!({"content": std::mem::take(&mut text)}));
                            }
                            items.push(json!({"atom": atom}));
                        }
                        None => text.push(*self.values.get(&(o.to_string(), *n)).unwrap_or_else(|| panic!("no value at {o}.0.1.{n}")) as char),
                    }
                }
                if !text.is_empty() {
                    items.push(json!({"content": text}));
                }
                assert_eq!(covered, width, "the span asked lies within the arrangement");
                Ok(reply(200, json!({"resp": "delivery", "as_of": position, "items": items})))
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

    /// The write: a frame with no `attest` refused where a claimed board
    /// serves `H.1`, else the memo answered where one stands, else the
    /// publication applied and its acknowledgment kept; the next `drop_acks`
    /// acknowledgments lost at the transport.
    fn publish(&mut self, frame: &Value) -> Result<Response, DialError> {
        if std::mem::take(&mut self.claim_at_publish) {
            self.claimed = true;
            self.head = true;
        }
        // The board's check, before its transaction: applied not, memoized
        // not (wire.md §Credential refusals, a reorder).
        if self.claimed && self.head && frame.get("attest").is_none() {
            return Ok(reply(200, json!({"resp": "rejected", "code": "credential_refused", "detail": "attestation_required", "disposition": "reorder", "op": "publish"})));
        }
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
        // The family: the rendering draft, then the drafts `also` names.
        let also: Vec<String> = frame["also"].as_array().map(|l| l.iter().map(|x| x.as_str().unwrap().to_string()).collect()).unwrap_or_default();
        let named: Vec<String> = draft.iter().cloned().chain(also.iter().cloned()).collect();
        let runs: Vec<Run> = frame["runs"].as_array().unwrap().iter().map(|r| Run::new(a(r["origin"].as_str().unwrap()), r["i_start"].as_str().unwrap().rsplit('.').next().unwrap().parse().unwrap(), r["width"].as_str().unwrap().parse().unwrap())).collect();
        let places: Vec<Option<u64>> = frame["places"].as_array().map(|p| p.iter().map(|x| x["ordinal"].as_str().and_then(|o| o.parse().ok())).collect()).unwrap_or_else(|| vec![None; runs.len()]);
        // Each `also` draft's own kept places (the wire's `also_places`): one
        // entry per draft `also` names, its list parallel to the runs, a
        // shorter list padded with `None` — the codec's shape, a stranger's
        // fault there this board's own bug.
        let also_places: Vec<(String, Vec<Option<u64>>)> = frame["also_places"]
            .as_array()
            .map(|entries| {
                entries
                    .iter()
                    .map(|entry| {
                        let d = entry["draft"].as_str().unwrap().to_string();
                        assert!(also.contains(&d), "the composition sent an also_places entry for a draft `also` does not name: {d}");
                        let mut list: Vec<Option<u64>> = entry["places"].as_array().unwrap().iter().map(|x| x["ordinal"].as_str().and_then(|o| o.parse().ok())).collect();
                        assert!(list.len() <= runs.len(), "the composition sent an also_places list longer than runs");
                        list.resize(runs.len(), None);
                        (d, list)
                    })
                    .collect()
            })
            .unwrap_or_default();
        let (trunk, edition) = if mint {
            let account = frame["account"].as_str().unwrap();
            let e = format!("{account}.0.{}", self.next_doc);
            self.next_doc += 1;
            self.position += 1;
            self.docs.insert(e.clone(), DocState { runs: Vec::new(), published: true, owner: account.to_string(), placed: None, base_extent: None, source: None, base: None, base_copied: None, at: self.position });
            (e.clone(), Some(e))
        } else {
            (frame["doc"].as_str().unwrap().to_string(), None)
        };
        let records_in = |w: &World, d: &str| -> Vec<(LinkRow, String)> {
            w.links.iter().filter(|l| l.home == d && l.ty.first().is_some_and(|t| t.0 == T_CORRESPONDENCE)).map(|l| (l.clone(), w.rows.iter().find(|r| r.at == l.at && r.op == "publish").map(|r| r.docs[0].clone()).unwrap_or_default())).collect()
        };
        // ω per named draft, in the request's order; then the twin fence per
        // named draft: each draft's own records for the runs of its identity.
        for d in &named {
            if self.docs.get(d).is_some_and(|doc| doc.owner != ACCOUNT) {
                return refused("not_owner", json!({"addr": d}));
            }
        }
        for d in &named {
            for run in runs.iter().filter(|r| r.origin.to_string() == *d) {
                for (rec, member) in records_in(self, d) {
                    let from = addresses(&rec.from[0]);
                    if (run.i_start..run.reach()).any(|n| from.contains(&format!("{d}.0.1.{n}"))) {
                        return refused("already_published", json!({"addr": member}));
                    }
                }
            }
        }
        // The member's address: the trunk's next member off the head, a
        // daughter off any other member, and off the bare document — a
        // draft begun before any version — the FIRST member's daughter once
        // a member stands; the birth shape, no base, is refused then.
        let base = frame["base"].as_str().map(str::to_string);
        let member = match self.trunk_head.get(&trunk).cloned() {
            Some(head) if base.as_deref() == Some(head.as_str()) => format!("{trunk}.{}", head.rsplit('.').next().unwrap().parse::<u64>().unwrap() + 1),
            Some(_) => {
                let Some(b) = base.clone() else { return refused("base_superseded", json!({})) };
                let b = if b == trunk { format!("{trunk}.1") } else { b };
                let k = 1 + self.docs.keys().filter(|m| m.strip_prefix(&format!("{b}.")).is_some_and(|rest| !rest.contains('.'))).count();
                format!("{b}.{k}")
            }
            None => format!("{trunk}.1"),
        };
        // The kept places, per list — the rendering draft's `places`, then
        // each `also` draft's entry in `also`'s order: the draft arranges
        // the run's words at the place, by identity — in the rendering
        // draft's list a run of ANY named draft's identity, in an `also`
        // draft's its own alone — or, at a stray run, the from-words of a
        // correspondence record the caller may read, wherever homed, naming
        // the run whole as its to; a refusal names the entry and the draft.
        if draft.is_none() {
            if let Some(k) = places.iter().position(Option::is_some) {
                return refused("stray_place_unrecorded", json!({"index": k}));
            }
        }
        let mut lists: Vec<(String, Vec<Option<u64>>)> = draft.iter().map(|d| (d.clone(), places.clone())).collect();
        lists.extend(also_places.iter().cloned());
        let mut stray_froms: Vec<(String, usize, Vec<(Address, u64)>)> = Vec::new();
        for (d, list) in &lists {
            let positions: Vec<(Address, u64)> = self.arrangement(d).map(|r| Self::expand(&r)).unwrap_or_default();
            for (k, (run, place)) in runs.iter().zip(list).enumerate() {
                let Some(place) = place else { continue };
                let at_place: Vec<(Address, u64)> = positions.iter().skip(*place as usize - 1).take(run.width as usize).cloned().collect();
                let origin = run.origin.to_string();
                let own = if draft.as_deref() == Some(d.as_str()) { named.contains(&origin) } else { origin == *d };
                if own {
                    let want: Vec<(Address, u64)> = (run.i_start..run.reach()).map(|n| (run.origin.clone(), n)).collect();
                    if at_place != want {
                        return refused("kept_place_moved", json!({"index": k, "addr": d}));
                    }
                } else if named.contains(&origin) {
                    panic!("the composition sent a place in {d}'s list beside a run of another named draft's identity, {origin}, which the codec refuses malformed");
                } else {
                    let covering = self
                        .links
                        .iter()
                        .filter(|l| !l.retracted && self.readable(&l.home) && l.ty.first().is_some_and(|t| t.0 == T_CORRESPONDENCE))
                        .find(|rec| {
                            let to = addresses(&rec.to[0]);
                            (run.i_start..run.reach()).all(|n| to.contains(&format!("{}.0.1.{n}", run.origin)))
                        })
                        .cloned();
                    let Some(rec) = covering else { return refused("stray_place_unrecorded", json!({"index": k, "addr": d})) };
                    let to = addresses(&rec.to[0]);
                    let offset = to.iter().position(|x| *x == run.i_start_text()).unwrap();
                    let from: Vec<(Address, u64)> = addresses(&rec.from[0]).iter().skip(offset).take(run.width as usize).map(|x| { let (p, n) = x.rsplit_once('.').unwrap(); (a(&trunk_of(p).unwrap()), n.parse().unwrap()) }).collect();
                    if at_place != from {
                        return refused("kept_place_moved", json!({"index": k, "addr": d}));
                    }
                    stray_froms.push((d.clone(), k, from));
                }
            }
        }
        // The claim's precondition at the document form (skep #692): the
        // edition holds no member yet, else refused naming the edition.
        let claims = frame["claim"].as_bool().unwrap_or(false);
        if claims && !mint && self.trunk_head.contains_key(&trunk) {
            return json!({"resp": "rejected", "code": "claim_refused", "detail": "member_stands", "disposition": "permanent", "op": "publish", "site": {"addr": trunk}});
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
                // Superseded, as the plan's `check_old` judges it: the
                // entry's published spans covered by a public successor an
                // active claim of the person's names from `old`, where no
                // member-position end lies on the shot's new words, or from
                // an original `old` itself revises, whatever new words the
                // entry holds.
                let spans = Self::published_spans(entry, &runs, &named);
                let new_words = Self::holds_new_words(entry, &runs, &named);
                if (!new_words && self.superseded_by_own_claim(old, &spans)) || self.originals_of(old).iter().any(|o| self.superseded_by_own_claim(o, &spans)) {
                    return json!({"resp": "rejected", "code": "old_refused", "detail": "superseded", "disposition": "permanent", "op": "publish", "site": {"index": k}});
                }
            }
        }
        // THE VALIDATION's (6), the daughters (the merge bridge lane): the
        // list stands only beside a shot landing on the trunk — refused whole
        // `head_moved` naming the head where the base is not it — then each
        // entry a registered member of `doc`'s chain, not the base, named
        // once; one an ACTIVE claim of the caller's own already names, homed
        // in any document of theirs and whatever its `new`, is skipped below.
        let supersede: Vec<String> = frame["supersede"].as_array().map(|l| l.iter().map(|x| x.as_str().unwrap().to_string()).collect()).unwrap_or_default();
        let supersede_refused = |detail: &str, site: Value| json!({"resp": "rejected", "code": "supersede_refused", "detail": detail, "disposition": "permanent", "op": "publish", "site": site});
        if !supersede.is_empty() {
            if let Some(head) = self.trunk_head.get(&trunk) {
                if base.as_deref() != Some(head.as_str()) {
                    return supersede_refused("head_moved", json!({"index": 0, "addr": head}));
                }
            }
            let mut seen: BTreeSet<&str> = BTreeSet::new();
            for (k, daughter) in supersede.iter().enumerate() {
                let in_chain = !mint && daughter.strip_prefix(&format!("{trunk}.")).is_some_and(|rest| !rest.is_empty()) && self.docs.contains_key(daughter);
                if !in_chain {
                    return supersede_refused("not_member", json!({"index": k}));
                }
                if base.as_deref() == Some(daughter.as_str()) {
                    return supersede_refused("base", json!({"index": k}));
                }
                if !seen.insert(daughter) {
                    return supersede_refused("duplicate", json!({"index": k}));
                }
            }
        }
        // The mint: one fresh identity per draft identity, in runs' order.
        self.position += 1;
        let at = self.position;
        // Keyed by the draft and the position: the drafts' chains are
        // distinct, so one draft's ordinal is no other's.
        let mut fresh_of: BTreeMap<(String, u64), u64> = BTreeMap::new();
        let mut positions: Vec<(Address, u64)> = Vec::new();
        let mut fresh_runs: Vec<Run> = Vec::new();
        // Each record: the draft it is homed in, its draft start, its fresh
        // start, its width.
        let mut records: Vec<(String, u64, u64, u64)> = Vec::new();
        for run in &runs {
            let origin = run.origin.to_string();
            if named.contains(&origin) {
                let mut minted_start: Option<(u64, u64)> = None;
                let mut piece_start = 0u64;
                for n in run.i_start..run.reach() {
                    let f = match fresh_of.get(&(origin.clone(), n)) {
                        Some(f) => {
                            if let Some((ds, fs)) = minted_start.take() {
                                records.push((origin.clone(), ds, fs, n - ds));
                            }
                            *f
                        }
                        None => {
                            let f = self.fresh(&trunk);
                            match self.atoms.get(&(origin.clone(), n)).cloned() {
                                Some(atom) => drop(self.atoms.insert((trunk.clone(), f), atom)),
                                None => {
                                    let value = self.values[&(origin.clone(), n)];
                                    self.values.insert((trunk.clone(), f), value);
                                }
                            }
                            fresh_of.insert((origin.clone(), n), f);
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
                    records.push((origin.clone(), ds, fs, piece_start + 1 - ds));
                }
                fresh_runs.push(Run::new(a(&trunk), fresh_of[&(origin.clone(), run.i_start)], run.width));
            } else {
                positions.extend((run.i_start..run.reach()).map(|n| (run.origin.clone(), n)));
                fresh_runs.push(run.clone());
            }
        }
        let member_runs = Self::coalesce(positions);
        let placed: u64 = member_runs.iter().map(|r| r.width).sum();
        self.docs.insert(member.clone(), DocState { runs: member_runs.clone(), published: true, owner: ACCOUNT.to_string(), placed: Some(placed), base_extent: frame["base_extent"].as_str().and_then(|e| e.parse().ok()), source: None, base: None, base_copied: None, at });
        // The rendering draft's base moves to the member, at its whole
        // count, its source kept (wire.md §Namespace, THE BASE MOVES): a
        // draft with none, its first publication's member.
        if let Some(d) = draft.as_ref().and_then(|d| self.docs.get_mut(d)) {
            d.base = Some(member.clone());
            d.base_copied = Some(placed);
        }
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
        // The records, each homed in the draft whose identity the piece was;
        // the row names the rendering draft always, whether or not the
        // commit wrote it, then each `also` draft where a record landed in
        // it or its list re-windows it, in the request's order.
        for (home, ds, fs, w) in &records {
            push_link(self, home, vec![ispan(home, *ds, *w)], vec![ispan(&trunk, *fs, *w)], vec![unit(T_CORRESPONDENCE)]);
        }
        if let Some(d) = &draft {
            homes.push(d.clone());
        }
        for other in &also {
            if records.iter().any(|(home, ..)| home == other) || also_places.iter().any(|(d, list)| d == other && list.iter().any(Option::is_some)) {
                homes.push(other.clone());
            }
        }
        // The edition claim: homed in the edition minted, or in the trunk
        // `doc` names — then a home the deposits touched.
        if claims {
            let e = edition.clone().unwrap_or_else(|| trunk.clone());
            push_link(self, &e, vec![unit(&e)], vec![unit(draft.as_deref().unwrap())], vec![unit(T_EDITION)]);
            if edition.is_none() && !homes.contains(&e) {
                homes.push(e);
            }
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
        // The private rider (the link-sets design §5.7 (vi′)): each original
        // the request names ended at its own home — over a rest, a fresh mark
        // of the original's type first, the rest's spans in the end the
        // original holds them in — an original already retracted skipped;
        // the home joins the row.
        for entry in frame["originals"].as_array().cloned().unwrap_or_default() {
            let old = entry["old"].as_str().unwrap().to_string();
            let Some(original) = self.links.iter().find(|l| l.addr == old).cloned() else { continue };
            if original.retracted {
                continue;
            }
            let home = home_of_link(&old).unwrap().to_string();
            let rest: Vec<(String, String)> = entry["rest"]
                .as_array()
                .map(|list| {
                    list.iter()
                        .map(|x| {
                            let start = x["start"].as_str().unwrap().to_string();
                            let width: u64 = x["width"].as_str().unwrap().parse().unwrap();
                            let depth = start.split('.').count();
                            (start, format!("{}{width}", "0.".repeat(depth - 1)))
                        })
                        .collect()
                })
                .unwrap_or_default();
            if !rest.is_empty() {
                let within = |end: &[(String, String)], span: &(String, String)| {
                    let positions = addresses(span);
                    end.iter().any(|e| positions.iter().all(|p| addresses(e).contains(p)))
                };
                let (from, to): (Vec<_>, Vec<_>) = rest.iter().cloned().partition(|span| within(&original.from, span));
                assert!(to.iter().all(|span| within(&original.to, span)), "a rest span outside the original: the plan refuses it");
                push_link(self, &home, from, to, original.ty.clone());
            }
            push_link(self, &home, vec![unit(&home)], vec![unit(&old)], vec![unit(T_RETRACTION)]);
            if let Some(l) = self.links.iter_mut().find(|l| l.addr == old) {
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
        // The supersession claims, one per daughter in the trunk — `old` the
        // daughter, `new` the member this commit minted — a daughter an
        // active claim of the caller's own already names skipped, the entry
        // committing nothing.
        for daughter in &supersede {
            let claimed = self.links.iter().any(|l| !l.retracted && l.ty.first().is_some_and(|t| t.0 == T_SUPERSEDES) && l.from.first().is_some_and(|s| s.0 == *daughter) && trunk_of(&l.home).is_some_and(|t| self.docs.get(&t).is_some_and(|d| d.owner == ACCOUNT)));
            if claimed {
                continue;
            }
            push_link(self, &trunk, vec![unit(daughter)], vec![unit(&member)], vec![unit(T_SUPERSEDES)]);
            if !homes.contains(&trunk) {
                homes.push(trunk.clone());
            }
        }
        // The re-window at the kept places, last: the rendering draft at
        // `places`, then each `also` draft at its own entry, in `also`'s
        // order — a run of a named draft's identity replaced by the fresh
        // identity it became, a stray by the published identity its record
        // names, each at the place its list carries.
        for (d, list) in &lists {
            let mut positions: Vec<(Address, u64)> = self.arrangement(d).map(|r| Self::expand(&r)).unwrap_or_default();
            for (k, (run, place)) in runs.iter().zip(list).enumerate() {
                let Some(place) = place else { continue };
                let origin = run.origin.to_string();
                let replacement: Vec<(Address, u64)> = if named.contains(&origin) {
                    (run.i_start..run.reach()).map(|n| (a(&trunk), fresh_of[&(origin.clone(), n)])).collect()
                } else {
                    let _ = stray_froms.iter().find(|(home, i, _)| home == d && *i == k);
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
        also: vec![],
        selection: vec![run(E, 1, 19), run(D, 1, 10), run(O, 1, 5)],
        notes: vec![a(N)],
        readable_drafts: vec![a(D), a(N)],
        published: vec![a(E), a(S), a(S2)],
        supersede: vec![],
    }
}

fn publisher<'a>(board: &'a Board, token: &'a Token, signer: &'a HybridSigner) -> Publisher<'a> {
    Publisher { board, token, account: ACCOUNT, signer }
}

fn links_of(e: &Enumeration, indices: &[usize]) -> Vec<String> {
    indices.iter().map(|i| e.candidates[*i].link.to_string()).collect()
}

/// Returns the candidate at `link`.
///
/// # Panics
///
/// Where `link` is no candidate of `e`.
fn candidate_at<'e>(e: &'e Enumeration, link: &str) -> &'e Candidate {
    e.candidates.iter().find(|c| c.link.to_string() == link).unwrap_or_else(|| panic!("{link} is no candidate"))
}

/// Returns the keys read for `c`'s one successor: (i), (iii) and candidacy.
///
/// # Panics
///
/// Where `c` has no successor, or more than one.
fn keys_of(c: &Candidate) -> (bool, bool, bool) {
    let [s] = c.successors.as_slice() else { panic!("{}: {} successors, not one", c.link, c.successors.len()) };
    (s.published_home, s.covers, s.candidate)
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
/// image, the atoms of the draft's own run (no merge record among them), the
/// one `find_links_v` over the selection as one region, one
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
    assert_eq!(steps, ["image", "merge_records", "find_links_v", "links", "records", "read_through", "claims"]);
    assert_eq!(e.frames[0], ("image", 2), "the extent and one image");
    assert_eq!(e.frames[1], ("merge_records", 1), "the atoms of the draft's own run, one read; the edition's words and the window's none");
    assert_eq!(e.frames[2], ("find_links_v", 1), "ONE region read");
    assert_eq!(e.frames[4], ("records", 1), "the records read; the record's own read_link was cached when the region read answered it");
    assert_eq!(e.frames[5].1, 4, "two batched reads, the link's read_link and its home's metadata");
    assert_eq!((e.merge_atoms.clone(), e.selection.clone()), (vec![vec![], vec![], vec![]], inputs().selection), "no merge record: the selection as published is the held one");
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
    assert_eq!((acc.successors[0].new.to_string(), keys_of(acc)), (named.copy.clone(), (true, true, false)), "the copy at `E.1` is no candidate");
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

/// Checks THE FILTER's public arm one key at a time.
///
/// A successor homed in a PRIVATE document of the person's fails (i) and,
/// retracted since, is no candidate, though its value is still read and
/// covers, so the original is offered; one whose ends do not cover the
/// published spans fails (iii) and the original is offered; a claim of
/// ANOTHER's naming a public copy drops nothing.
#[test]
fn the_filter_drops_only_on_both_keys_of_the_persons_own_claim() {
    let (mut world, named) = World::base();
    // (i) fails: the copy homed in the private N, retracted since.
    let private_copy = world.typed(N, vec![ispan(E, 10, 5)], vec![ispan(N, 1, 5)], T_CITATION);
    world.retract(N, &private_copy);
    let claim = world.links.iter().position(|l| l.addr == named.claim_acc).unwrap();
    world.links[claim].to = vec![unit(&private_copy)];
    let (_, board, signer) = open(world);
    let tok = token();
    let p = publisher(&board, &tok, &signer);
    let e = enumerate(&p, &inputs()).unwrap();
    let acc = candidate_at(&e, &named.l_acc);
    assert_eq!((keys_of(acc), acc.offered()), ((false, true, false), true));

    // (iii) fails: the copy covers other words.
    let (mut world, named) = World::base();
    let copy = world.links.iter().position(|l| l.addr == named.copy).unwrap();
    world.links[copy].from = vec![ispan(E, 1, 2)];
    let (_, board, signer) = open(world);
    let p = publisher(&board, &tok, &signer);
    let e = enumerate(&p, &inputs()).unwrap();
    let acc = candidate_at(&e, &named.l_acc);
    assert_eq!((keys_of(acc), acc.offered()), ((true, false, false), true));

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

/// Checks that a retype is offered in its original's place until retracted.
///
/// THE FILTER's other arm (proposal 23) at a retype made in the draft
/// before the shot (B3-S12): the successor, the same ends typed `mark`
/// beside its original in the notes, is a candidate, so the original is not
/// offered and the successor stands in the notes' row in its place; the
/// successor retracted, it is no candidate, and the original is offered
/// again.
#[test]
fn a_retyped_link_is_offered_in_its_originals_place_until_the_retype_is_retracted() {
    let (mut world, named) = World::base();
    let retyped = world.typed(N, vec![ispan(E, 5, 5)], vec![ispan(N, 1, 5)], T_MARK);
    world.claim(N, &named.l1_n, &retyped);
    let (dialer, board, signer) = open(world);
    let tok = token();
    let p = publisher(&board, &tok, &signer);
    let e = enumerate(&p, &inputs()).unwrap();
    assert_eq!(keys_of(candidate_at(&e, &named.l1_n)), (false, true, true), "private, covering, a candidate");
    let offered = links_of(&e, &e.offered());
    assert!(offered.contains(&retyped) && !offered.contains(&named.l1_n), "the retype offered, not its original: {offered:?}");
    let pn = panel(&p, &inputs(), &e).unwrap();
    assert_eq!((pn.rows[1].home.to_string(), links_of(&e, &pn.rows[1].links)), (N.to_string(), vec![retyped.clone(), named.l_rt.clone()]), "the notes' row: the retype in its original's place");
    dialer.world().retract(N, &retyped);
    let e = enumerate(&p, &inputs()).unwrap();
    assert!(!e.candidates.iter().any(|c| c.link.to_string() == retyped), "a retracted successor is no candidate");
    let l1_n = candidate_at(&e, &named.l1_n);
    assert_eq!((keys_of(l1_n), l1_n.offered()), ((false, true, false), true), "offered again");
}

/// Checks that a link moved into another set leaves its row for the new one.
///
/// The note moved into the person's private `Z` (§2) leaves the notes' row,
/// and its successor stands in `Z`'s.
#[test]
fn a_link_moved_into_another_set_leaves_its_old_row_for_its_new_one() {
    let (mut world, named) = World::base();
    let moved = world.typed(Z, vec![ispan(E, 5, 5)], vec![ispan(N, 1, 5)], T_CITATION);
    world.claim(N, &named.l1_n, &moved);
    let (_, board, signer) = open(world);
    let tok = token();
    let p = publisher(&board, &tok, &signer);
    let e = enumerate(&p, &inputs()).unwrap();
    assert_eq!(keys_of(candidate_at(&e, &named.l1_n)), (false, true, true));
    let pn = panel(&p, &inputs(), &e).unwrap();
    let row = |home: &str| pn.rows.iter().find(|r| r.home.to_string() == home).unwrap_or_else(|| panic!("no row for {home}"));
    assert_eq!(links_of(&e, &row(N).links), vec![named.l_rt.clone()], "the original gone from its home's row");
    assert_eq!((row(Z).kind.clone(), links_of(&e, &row(Z).links)), (RowKind::Private, vec![moved]), "the successor in its new home's");
}

/// Checks that an end moved before the shot drops the original.
///
/// Widened over the original's words, or moved off part of them (B3-S12),
/// the successor is offered and the original is not: coverage is no key of
/// this arm. On kept words the successor covers or not as its ends lie; on
/// the draft's new words, which no successor covers, it covers nothing even
/// widened, and the original is dropped all the same.
#[test]
fn an_end_moved_before_the_shot_drops_the_original_whether_or_not_its_successor_covers() {
    let tok = token();
    let (_, named) = World::base();
    let cells = [
        ("widened over kept words", &named.l1_n, N, ispan(E, 4, 7), ispan(N, 1, 5), true),
        ("moved off part of kept words", &named.l1_n, N, ispan(E, 7, 5), ispan(N, 1, 5), false),
        ("widened over new words", &named.cite_d, D, ispan(D, 4, 7), ispan(Z, 1, 3), false),
    ];
    for (what, original, home, from, to, covers) in cells {
        let (mut world, _) = World::base();
        let moved = world.typed(home, vec![from], vec![to], T_CITATION);
        world.claim(home, original, &moved);
        let (_, board, signer) = open(world);
        let p = publisher(&board, &tok, &signer);
        let e = enumerate(&p, &inputs()).unwrap();
        assert_eq!(keys_of(candidate_at(&e, original)), (false, covers, true), "{what}");
        let offered = links_of(&e, &e.offered());
        assert!(offered.contains(&moved) && !offered.contains(original), "{what}: the successor offered, not its original: {offered:?}");
    }
}

/// Checks that a selection reaching only the original's words offers it.
///
/// The selection holds the original's words, `E`'s 5..9, and not its
/// successor's, moved onto `E`'s 15..17: the successor touches nothing
/// selected and is no candidate, and the original is offered.
#[test]
fn a_selection_reaching_only_the_originals_words_offers_the_original() {
    let (mut world, named) = World::base();
    let moved = world.typed(N, vec![ispan(E, 15, 3)], vec![ispan(N, 1, 5)], T_CITATION);
    world.claim(N, &named.l1_n, &moved);
    let (_, board, signer) = open(world);
    let tok = token();
    let p = publisher(&board, &tok, &signer);
    let e = enumerate(&p, &Inputs { selection: vec![run(E, 5, 5)], ..inputs() }).unwrap();
    assert!(!e.candidates.iter().any(|c| c.link.to_string() == moved), "the successor touches nothing selected");
    let l1_n = candidate_at(&e, &named.l1_n);
    assert_eq!((keys_of(l1_n), l1_n.offered()), ((false, false, false), true), "the original offered");
}

/// Checks that an original drops where its successor was dropped in turn.
///
/// A successor a covering copy has superseded — the retype accepted at
/// `E.1` — is still a candidate, dropped itself by the public arm, and so
/// drops its own original by the other: neither is offered.
#[test]
fn an_original_drops_where_its_successor_is_a_candidate_dropped_in_turn() {
    let (mut world, named) = World::base();
    let retyped = world.typed(N, vec![ispan(E, 5, 5)], vec![ispan(N, 1, 5)], T_MARK);
    world.claim(N, &named.l1_n, &retyped);
    let copy = world.typed(&format!("{E}.1"), vec![ispan(E, 5, 5)], vec![ispan(N, 1, 5)], T_MARK);
    world.claim(N, &retyped, &copy);
    let (_, board, signer) = open(world);
    let tok = token();
    let p = publisher(&board, &tok, &signer);
    let e = enumerate(&p, &inputs()).unwrap();
    let successor = candidate_at(&e, &retyped);
    assert_eq!((keys_of(successor), successor.offered()), ((true, true, false), false), "the retype dropped by its covering copy");
    let original = candidate_at(&e, &named.l1_n);
    assert_eq!((keys_of(original), original.offered()), ((false, true, true), false), "the original dropped by its successor's candidacy");
}

/// Checks that a cut copy in a public set leaves its original offered.
///
/// An original on an earlier shot's words and on new words beside them, its
/// copy in the public set `S` cut at the earlier selection — over `E`'s
/// words the record names — is offered again at the shot that publishes the
/// rest (W4): the copy touches the selection and is a candidate, but a
/// public successor drops its original only where it covers. Its entry
/// holds the new words in the member-position form, and the board takes it
/// beside the cut copy: the member homes the copy re-made over the whole
/// run, and the original holds a second claim.
#[test]
fn a_cut_copy_in_a_public_set_is_a_candidate_and_leaves_its_original_offered() {
    let (mut world, _) = World::base();
    // D's words 24..27, new beside the record's 20..23, which `E`'s 16..19
    // published.
    world.text(D, 24, "more");
    world.docs.get_mut(D).unwrap().runs.push(run(D, 24, 4));
    let original = world.typed(N, vec![ispan(D, 20, 8)], vec![ispan(N, 1, 2)], T_CITATION);
    let cut = world.typed(S, vec![ispan(E, 16, 4)], vec![ispan(N, 1, 2)], T_CITATION);
    world.claim(N, &original, &cut);
    let (dialer, board, signer) = open(world);
    let tok = token();
    let p = publisher(&board, &tok, &signer);
    let rest = Inputs { selection: vec![run(E, 1, 19), run(D, 1, 10), run(O, 1, 5), run(D, 24, 4)], ..inputs() };
    let e = enumerate(&p, &rest).unwrap();
    let in_s: Vec<String> = e.homes.iter().filter(|(h, _)| h.to_string() == S).flat_map(|(_, indices)| links_of(&e, indices)).collect();
    assert!(in_s.contains(&cut), "the cut copy a candidate in S: {in_s:?}");
    let c = candidate_at(&e, &original);
    assert_eq!((keys_of(c), c.offered()), ((true, false, true), true), "public and cut: offered, though its copy is a candidate");
    let pn = panel(&p, &rest, &e).unwrap();
    let Built::Request(mut request) = build(&p, &rest, &e, &pn, &switched(None)).unwrap() else { panic!("inert") };
    let entry = request.entries.iter().find(|en| e.candidates[en.candidate].link.to_string() == original).expect("the original's entry");
    assert_eq!(entry.from, End::Member(vec![(16, 4), (35, 4)]), "the record's words and the new words beside them, at the member's positions");
    let Sent::Acknowledged(ack) = send(&p, &rest, &mut request).unwrap() else { panic!("refused") };
    let w = dialer.world();
    let (member, whole_run) = (ack.member.to_string(), vec![ispan(E, 16, 4), ispan(E, 30, 4)]);
    assert!(w.links.iter().any(|l| l.home == member && l.from == whole_run && l.to == vec![ispan(N, 1, 2)]), "the copy re-made over the whole run, the new words on their fresh identity");
    let claims = w.links.iter().filter(|l| !l.retracted && l.ty[0].0 == T_SUPERSEDES && l.from[0].0 == original).count();
    assert_eq!(claims, 2, "the cut copy's claim and the re-made copy's");
}

/// Checks the walk through the records piece by piece.
///
/// The draft's 3..10, over records naming its 5..7 and its 9, is read in
/// five pieces, each record's words mapped onto its `to` at their offset
/// and the rest as stored. A span on a chain no named draft owns is walked
/// for a candidate the read-through reached and read as stored for one the
/// region read reached.
#[test]
fn the_walk_maps_each_piece_a_record_covers_and_reads_the_rest_as_stored() {
    let span = |doc: &str, first: u64, width: u64| ISpan { chain: format!("{doc}.0.1"), first, width };
    let record = |home: &str, n: u64, from: ISpan, to: ISpan| Record { link: a(&format!("{home}.0.2.{n}")), home: a(home), from, to, at: None };
    let records = [record(D, 90, span(D, 5, 3), span(E, 30, 3)), record(D, 91, span(D, 9, 1), span(E, 40, 1)), record(O, 90, span(O, 1, 4), span(E, 5, 4))];
    let inputs = inputs();
    let walk = RecordWalk::new(&inputs, &records);
    let read = |s: ISpan, via: Via| walk.pieces(&s, &via).into_iter().map(|p| (p.span, p.mapped)).collect::<Vec<_>>();
    assert_eq!(read(span(D, 3, 8), Via::Region), vec![(span(D, 3, 2), false), (span(E, 30, 3), true), (span(D, 8, 1), false), (span(E, 40, 1), true), (span(D, 10, 1), false)]);
    assert_eq!(read(span(D, 6, 1), Via::Region), vec![(span(E, 31, 1), true)], "a piece inside a record, at its offset");
    assert_eq!(read(span(O, 2, 4), Via::Region), vec![(span(O, 2, 4), false)], "another chain, reached by the region read: as stored");
    assert_eq!(read(span(O, 2, 4), Via::ReadThrough(vec![])), vec![(span(E, 6, 3), true), (span(O, 5, 1), false)], "reached by the read-through: walked");
}

/// Checks that an accepted link the read-through reaches stays dropped.
///
/// `l_rt`, on the draft's words an earlier shot published as `E`'s 16..19,
/// accepted with its copy at `E.1` over those words: the read-through
/// reaches it, key (iii) reads its ends through the record as `E`'s words,
/// the copy covers them, and it is offered at no later publication (§5.1).
#[test]
fn an_accepted_link_the_read_through_reaches_is_dropped_by_its_copy_over_the_published_words() {
    let (mut world, named) = World::base();
    let copy = world.typed(&format!("{E}.1"), vec![ispan(E, 16, 4)], vec![ispan(N, 1, 2)], T_CITATION);
    world.claim(N, &named.l_rt, &copy);
    let (_, board, signer) = open(world);
    let tok = token();
    let p = publisher(&board, &tok, &signer);
    let e = enumerate(&p, &inputs()).unwrap();
    let l_rt = candidate_at(&e, &named.l_rt);
    assert_eq!(l_rt.via, Via::ReadThrough(vec![a(&named.record)]), "reached through its record");
    assert_eq!((keys_of(l_rt), l_rt.offered()), ((true, true, false), false), "its copy covers its ends read through the record");
    let pn = panel(&p, &inputs(), &e).unwrap();
    assert_eq!((pn.rows[1].home.to_string(), links_of(&e, &pn.rows[1].links)), (N.to_string(), vec![named.l1_n.clone()]), "the notes' row without it");
}

/// Checks that an end on words published since its copy is offered again.
///
/// A note from `E`'s 5..9 to the draft's 21..22, accepted while 21..22 were
/// left out, so its copy at `E.1` holds them verbatim; the draft's 20..23
/// published since as `E`'s 16..19. The region read reaches the note, its
/// `to` reads through the record as `E`'s 17..18, words its copy never
/// covered, so it is offered again (§5.1), its entry spelled on `E`'s words,
/// and the board takes it.
#[test]
fn an_end_on_words_published_since_its_copy_is_offered_again_over_them() {
    let (mut world, _) = World::base();
    let note = world.typed(N, vec![ispan(E, 5, 5)], vec![ispan(D, 21, 2)], T_CITATION);
    let copy = world.typed(&format!("{E}.1"), vec![ispan(E, 5, 5)], vec![ispan(D, 21, 2)], T_CITATION);
    world.claim(N, &note, &copy);
    let (dialer, board, signer) = open(world);
    let tok = token();
    let p = publisher(&board, &tok, &signer);
    let first = enumerate(&p, &inputs()).unwrap();
    let c = candidate_at(&first, &note);
    assert_eq!(c.via, Via::Region);
    assert_eq!((keys_of(c), c.offered()), ((true, false, false), true), "its copy covers E's 5..9, not the 17..18 its `to` reads as");
    let (e, _, mut request) = built(&dialer, &board, &tok, &signer, &switched(None));
    let entry = request.entries.iter().find(|en| e.candidates[en.candidate].link.to_string() == note).expect("the note's entry");
    let on_e = |first: u64, width: u64| End::Spans(vec![ISpan { chain: format!("{E}.0.1"), first, width }]);
    assert_eq!((entry.from.clone(), entry.to.clone()), (on_e(5, 5), on_e(17, 2)), "both ends on E's words");
    let sent = send(&p, &inputs(), &mut request).unwrap();
    assert!(matches!(sent, Sent::Acknowledged(_)), "no successor covers it on E's words: {sent:?}");
}

/// Checks that a far-end original is offered when its words are published.
///
/// A note from `E`'s 5..9 to the draft's 3..4, accepted while 3..4 were
/// left out, so its copy at `E.1` holds the draft's addresses verbatim
/// (§5.2's ⟨d⟩). The shot that publishes the draft's words reads 3..4 as
/// new words, which that copy never covers, so the note is offered, its
/// `to` spelled at the member's positions, and the board takes it. At the
/// next shot those words are the member's, the new copy covers them, and
/// the note is offered no more.
#[test]
fn a_far_end_original_is_offered_at_the_publication_that_publishes_its_words() {
    let (mut world, _) = World::base();
    let note = world.typed(N, vec![ispan(E, 5, 5)], vec![ispan(D, 3, 2)], T_CITATION);
    let copy = world.typed(&format!("{E}.1"), vec![ispan(E, 5, 5)], vec![ispan(D, 3, 2)], T_CITATION);
    world.claim(N, &note, &copy);
    let (dialer, board, signer) = open(world);
    let tok = token();
    let p = publisher(&board, &tok, &signer);
    let first = enumerate(&p, &inputs()).unwrap();
    let c = candidate_at(&first, &note);
    assert_eq!((keys_of(c), c.offered()), ((true, false, false), true), "its copy holds the draft's 3..4, which this shot publishes as new");
    let (e, _, mut request) = built(&dialer, &board, &tok, &signer, &switched(None));
    let entry = request.entries.iter().find(|en| e.candidates[en.candidate].link.to_string() == note).expect("the note's entry");
    let on_e = End::Spans(vec![ISpan { chain: format!("{E}.0.1"), first: 5, width: 5 }]);
    assert_eq!((entry.from.clone(), entry.to.clone()), (on_e, End::Member(vec![(22, 2)])), "the far end on the new words, after the kept words' nineteen");
    let Sent::Acknowledged(ack) = send(&p, &inputs(), &mut request).unwrap() else { panic!("refused") };
    let e2 = format!("{E}.2");
    assert_eq!(ack.member.to_string(), e2);
    {
        let mut w = dialer.world();
        assert!(w.links.iter().any(|l| l.home == e2 && l.from == vec![ispan(E, 5, 5)] && l.to == vec![ispan(E, 22, 2)]), "the copy in the member, its far end on the fresh identity");
        let claims = w.links.iter().filter(|l| !l.retracted && l.ty[0].0 == T_SUPERSEDES && l.from[0].0 == note).count();
        assert_eq!(claims, 2, "the first copy's claim and the new copy's");
        // A word typed into the re-windowed draft, for the next shot.
        w.text(D, 30, "!");
        w.docs.get_mut(D).unwrap().runs = vec![run(E, 1, 29), run(D, 30, 1), run(O, 1, 5)];
    }
    let again = Inputs { base: Some((a(&e2), 34)), selection: vec![run(E, 1, 29), run(D, 30, 1), run(O, 1, 5)], ..inputs() };
    let e = enumerate(&p, &again).unwrap();
    let c = candidate_at(&e, &note);
    let keys: Vec<(bool, bool, bool)> = c.successors.iter().map(|s| (s.published_home, s.covers, s.candidate)).collect();
    assert_eq!((keys, c.offered()), (vec![(true, false, false), (true, true, false)], false), "the new copy covers E's 22..23, the words the draft's 3..4 became");
}

/// Checks that the formatting line takes a retype in its original's place.
///
/// A bold of the draft's own set retyped to emphasis before the shot stands
/// on the line in its original's place, and the one request carries one
/// entry for those words, the retype's: the line has no switch, so an
/// original left on it would be published beside its retype unasked.
#[test]
fn the_formatting_line_takes_a_retyped_mark_in_place_of_its_original() {
    let (mut world, named) = World::base();
    let retyped = world.typed(D, vec![], vec![ispan(D, 2, 3)], T_EMPHASIS);
    world.claim(D, &named.mark_d, &retyped);
    let (dialer, board, signer) = open(world);
    let tok = token();
    let (e, pn, request) = built(&dialer, &board, &tok, &signer, &switched(None));
    assert_eq!(links_of(&e, &pn.formatting.marks), [named.heading_d.clone(), named.mark_d2.clone(), retyped.clone()], "the retype on the line, its original not");
    let on_the_words: Vec<String> = request.entries.iter().filter(|en| en.to == End::Member(vec![(21, 3)])).map(|en| e.candidates[en.candidate].link.to_string()).collect();
    assert_eq!(on_the_words, [retyped], "one entry for the retyped words: the retype's");
}

/// A `scan_busy` on the region read is reissued under a short backoff and
/// answered; past the bound the step halts `Busy`, nothing written. A
/// `history_busy` on a read is reissued at the same door under the same
/// bound — the panel's metadata read here — and halts `Busy` past it.
#[test]
fn a_busy_region_read_is_reissued_and_halts_past_the_bound() {
    let (world, _) = World::base();
    let (dialer, board, signer) = open(world);
    let tok = token();
    let p = publisher(&board, &tok, &signer);
    dialer.world().busy = 2;
    let e = enumerate(&p, &inputs()).expect("reissued");
    assert_eq!(e.frames[2], ("find_links_v", 3), "two refusals and the answer");
    dialer.world().busy = SCAN_BUSY_REISSUES as usize + 1;
    assert_eq!(enumerate(&p, &inputs()).unwrap_err(), Fault::Busy);
    // `history_busy` at the same door: the panel's first metadata read
    // refused twice, then answered; past the bound, `Busy`.
    dialer.world().busy = 0;
    let e = enumerate(&p, &inputs()).expect("enumerated");
    dialer.world().history_busy = 2;
    dialer.clear();
    let pn = panel(&p, &inputs(), &e).expect("the panel, its busy read reissued");
    assert!(!pn.rows.is_empty());
    let metadata_frames = dialer.frames("doc_metadata");
    assert!(metadata_frames.len() >= 3 && metadata_frames[0]["doc"] == metadata_frames[1]["doc"] && metadata_frames[1]["doc"] == metadata_frames[2]["doc"], "the one read reissued twice: {metadata_frames:?}");
    dialer.world().history_busy = SCAN_BUSY_REISSUES as usize + 1;
    assert_eq!(panel(&p, &inputs(), &e).unwrap_err(), Fault::Busy, "past the bound, as scan_busy");
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
    assert_eq!((notes.line, notes.read_through), (LineCounts { p: 2, d: 0, c: 0, t: 0, u: 1 }, 1), "the revision counted, the far ends private, one link read through on its record's words");
    assert_eq!(notes.label, b"notes here".to_vec());
    assert_eq!(panel.rows[2].label, b"set one".to_vec());
    assert_eq!(links_of(&e, &panel.formatting.marks), [named.mark_d.clone(), named.heading_d.clone(), named.mark_d2.clone()]);
    assert_eq!(panel.formatting.cut, 1, "the heading runs past the selection");
    let removals: Vec<(String, bool, bool, Option<String>)> = panel.formatting.removals.iter().map(|r| (r.mark.to_string(), r.on_selection, r.spent, r.remake.map(|i| e.candidates[i].link.to_string()))).collect();
    assert_eq!(removals, [(named.mpub.clone(), true, false, Some(named.mark_d2.clone())), (named.mpub2.clone(), true, true, None), (named.mpub3.clone(), true, false, None)]);
    assert_eq!(panel.formatting.job_list().len(), 2);
    assert_eq!(panel.read_with, BTreeMap::from([(a(S), true), (a(S2), false)]));
    let steps: Vec<&str> = panel.frames.iter().map(|(s, _)| *s).collect();
    assert_eq!(steps, ["removals", "homes", "far", "labels", "read_with", "windows"], "the formatting line's test sends no frame; the windows read last");
}

/// Checks that an end over words before a record reads both.
///
/// A note in `N` from the draft's 18..23, whose 20..23 the record names as
/// `E`'s 16..19 and whose 18..19 stay the draft's own, left out: its end
/// runs past the selection's cut, ⟨c⟩, and lies wholly on no left-out words,
/// so no ⟨d⟩; and its entry spells `E`'s 16..19 once, the words before the
/// record read and cut.
#[test]
fn an_end_over_words_before_a_record_runs_past_the_cut_and_spells_the_records_words_once() {
    let (mut world, named) = World::base();
    let ahead = world.typed(N, vec![ispan(D, 18, 6)], vec![ispan(N, 3, 2)], T_CITATION);
    let (dialer, board, signer) = open(world);
    let tok = token();
    let (e, pn, request) = built(&dialer, &board, &tok, &signer, &switched(None));
    let notes = &pn.rows[1];
    assert_eq!(links_of(&e, &notes.links), [named.l1_n.clone(), named.l_rt.clone(), ahead.clone()]);
    assert_eq!(notes.line, LineCounts { p: 3, d: 0, c: 1, t: 0, u: 1 }, "past the cut, never wholly on left-out words");
    let entry = request.entries.iter().find(|en| e.candidates[en.candidate].link.to_string() == ahead).expect("its entry");
    assert_eq!(entry.from, End::Spans(vec![ISpan { chain: format!("{E}.0.1"), first: 16, width: 4 }]), "the record's words once, the words before it cut");
}

/// Checks that the formatting line reads its marks through the records.
///
/// Two marks of the draft's own set on its 20..23, which an earlier shot
/// published as `E`'s 16..19, both reached by the read-through: a bold over
/// 20..25 runs past the selection's cut once 20..23 read as `E`'s words,
/// and a heading over 20..23 re-makes the published heading over `E`'s
/// 15..19, whose held removal the line lists.
#[test]
fn the_formatting_line_reads_its_marks_through_the_records() {
    let (mut world, named) = World::base();
    let bold = world.typed(D, vec![], vec![ispan(D, 20, 6)], T_STRONG);
    let heading = world.typed(D, vec![], vec![ispan(D, 20, 4)], T_HEADING);
    let (_, board, signer) = open(world);
    let tok = token();
    let p = publisher(&board, &tok, &signer);
    let e = enumerate(&p, &inputs()).unwrap();
    let pn = panel(&p, &inputs(), &e).unwrap();
    assert_eq!(links_of(&e, &pn.formatting.marks), [named.mark_d.clone(), named.heading_d.clone(), named.mark_d2.clone(), bold, heading.clone()], "both on the line");
    assert_eq!(pn.formatting.cut, 2, "the heading over the draft's own words and the bold run past the cut");
    let remade: Vec<(String, Option<String>)> = pn.formatting.removals.iter().map(|r| (r.mark.to_string(), r.remake.map(|i| e.candidates[i].link.to_string()))).collect();
    assert_eq!(remade, [(named.mpub.clone(), Some(named.mark_d2.clone())), (named.mpub2.clone(), None), (named.mpub3.clone(), Some(heading))], "the published heading re-made on E's words");
}

/// THE COUNT (PUB-3.8): ⟨l⟩ the switched-on sets' entries plus the read-with
/// entries, ⟨n⟩ the line's marks that re-make nothing, ⟨r⟩ the take-offs no
/// re-make covers, ⟨e⟩ the re-makes — in neither ⟨n⟩ nor ⟨r⟩ — the claim
/// clause where the caller asks the claim, at either form (skep #692); a
/// destination `E` is already read with needs no read-with, one it is not
/// does.
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
    assert_eq!(off, Count { l: 0, n: 2, r: 1, e: 1, claim: false, read_with: Vec::new(), supersede: Vec::new() });
    let on = count(&panel, &switched(None).switches, &inputs);
    assert_eq!((on.l, on.n, on.r, on.e, on.read_with.len()), (5, 2, 1, 1, 0));
    let into_s2 = count(&panel, &switched(Some(S2)).switches, &inputs);
    assert_eq!((into_s2.l, into_s2.read_with), (6, vec![a(S2)]), "the read-with E needs is counted");
    let into_s = count(&panel, &switched(Some(S)).switches, &inputs);
    assert_eq!((into_s.l, into_s.read_with), (5, Vec::new()), "E is read with S already");
    let minting = Inputs { mint: Some(a(ACCOUNT)), claim: true, ..inputs.clone() };
    assert!(count(&panel, &Switches::default(), &minting).claim);
    let claim_alone = Inputs { claim: true, ..inputs };
    assert!(count(&panel, &Switches::default(), &claim_alone).claim, "the claim rides at the document form too; whether the edition holds a member is the board's to refuse");
}

/// THE CLAIM AT THE DOCUMENT FORM (skep #692): asked at the document form,
/// `claim: true` rides the frame beside `doc` with no `mint`; the claim row
/// leads the trunk's own group in the signed body — homed by ADDRESS,
/// `from` the edition's unit span, `to` the draft, behind the member's
/// group and ahead of every other row of the trunk's — the price adds the
/// claim's bytes; and the builder asks nothing of the edition's members:
/// the board refuses `claim_refused` where one stands, which the send maps
/// to its arm naming the edition, and a board whose `E` holds no member
/// lands the claim homed in `E`, `to` `D`.
#[test]
fn the_document_form_sends_the_claim_homed_in_the_trunk_and_maps_its_refusal() {
    let (world, _) = World::base();
    let (dialer, board, signer) = open(world);
    let tok = token();
    let p = publisher(&board, &tok, &signer);
    let asked = Inputs { claim: true, ..inputs() };
    let e = enumerate(&p, &asked).unwrap();
    let panel = panel(&p, &asked, &e).unwrap();
    let Built::Request(mut request) = build(&p, &asked, &e, &panel, &switched(None)).unwrap() else { panic!() };
    let frame = request.frame(None);
    assert_eq!((frame["doc"].as_str(), frame["claim"].as_bool(), frame.get("mint"), frame.get("account")), (Some(E), Some(true), None, None));
    assert!(request.count.claim);
    let rows = request.rows();
    let borrowed: Vec<_> = rows.iter().map(OwnedRow::borrow).collect();
    let trunk = a(E);
    let first_in_e = borrowed.iter().position(|r| r.home == DepositHome::Address(&trunk)).expect("the trunk's group");
    assert!(borrowed[..first_in_e].iter().all(|r| r.home == DepositHome::Member), "the member's group ahead of the trunk's: {first_in_e}");
    let (edition_ty, edition, draft) = (unit_span(&a(T_EDITION)), unit_span(&trunk), unit_span(&a(D)));
    let claim_row = &borrowed[first_in_e];
    assert_eq!(claim_row.kind, DepositKind::EditionClaim, "the claim first in the trunk's group");
    assert_eq!(claim_row.ty, DepositSlot::Stored(vec![SlotElement::Span(&edition_ty)]));
    assert_eq!(claim_row.from, DepositSlot::Stored(vec![SlotElement::Span(&edition)]), "from the edition's unit span, never the tag");
    assert_eq!(claim_row.to, DepositSlot::Stored(vec![SlotElement::Span(&draft)]));
    assert!(borrowed[first_in_e + 1..].iter().all(|r| r.kind != DepositKind::EditionClaim), "one claim row");
    let mut plain = request.clone();
    plain.claim = false;
    assert_eq!(request.priced(3, 2, &[]).bytes - plain.priced(3, 2, &[]).bytes, price::EDITION_CLAIM_BYTES, "the claim's bytes at the document form");
    assert!(request.body().as_bytes().len() > plain.body().as_bytes().len(), "the row is in the signed body");
    // The board: `E` holds `E.1`, so the claim is refused naming `E`.
    dialer.clear();
    assert_eq!(send(&p, &asked, &mut request).unwrap(), Sent::Refused(Refusal::ClaimRefused { edition: Some(a(E)) }));
    assert_eq!(dialer.frames("publish").len(), 1, "sent once, refused, no re-ask");
    // An edition holding no member yet takes it: the birth shape into `E`
    // with the claim, the claim homed in `E`, `to` `D`.
    let (mut world, _) = World::base();
    world.trunk_head.remove(E);
    world.docs.remove(&format!("{E}.1"));
    let (dialer2, board2, signer2) = open(world);
    let p2 = publisher(&board2, &tok, &signer2);
    let birth = Inputs { claim: true, base: None, ..inputs() };
    let e2 = enumerate(&p2, &birth).unwrap();
    let panel2 = super::panel::panel(&p2, &birth, &e2).unwrap();
    let Built::Request(mut request2) = build(&p2, &birth, &e2, &panel2, &switched(None)).unwrap() else { panic!() };
    let Sent::Acknowledged(ack) = send(&p2, &birth, &mut request2).unwrap() else { panic!() };
    assert_eq!((ack.member.to_string(), ack.claim), (format!("{E}.1"), true), "the acknowledgment echoes the request's claim");
    assert!(dialer2.world().links.iter().any(|l| l.home == E && l.ty[0].0 == T_EDITION && l.to[0].0 == D), "the claim homed in the edition named, to the draft");
}

// ── THE DAUGHTERS (the merge bridge lane) ────────────────────────────────

/// Two daughters of `E`'s chain, `E.1.1` and `E.1.2`, each a published
/// member in the fixture.
fn with_daughters(world: &mut World) -> (String, String) {
    let (e11, e12) = (format!("{E}.1.1"), format!("{E}.1.2"));
    world.doc(&e11, true, ACCOUNT, vec![run(E, 1, 7)]);
    world.doc(&e12, true, ACCOUNT, vec![run(E, 1, 3)]);
    (e11, e12)
}

/// A supersession claim's group as the daemon's verifier spells it from its
/// plan (`skep-core`'s `deposit_rows`): the trunk by address, the kind, the
/// supersedes class's unit span, `from` the daughter's unit span, `to` the
/// tag `member`.
fn claim_group<'a>(trunk: &'a Address, sup_ty: &'a Span, daughter: &'a Span) -> DepositRow<'a> {
    DepositRow { home: DepositHome::Address(trunk), kind: DepositKind::Supersede, ty: DepositSlot::Stored(vec![SlotElement::Span(sup_ty)]), from: DepositSlot::Stored(vec![SlotElement::Span(daughter)]), to: DepositSlot::Stored(vec![SlotElement::Member]) }
}

/// THE DAUGHTERS RIDE THE FRAME AND SIGN AS THE BOARD COMPOSES THEM: one
/// daughter and two — the frame's `supersede` the list as named, the
/// request's list and the count's clause the same, and the body
/// BYTE-CHECKED against the one builder over the request's other rows and
/// one group per daughter spelled as the daemon's verifier spells it, last
/// in the trunk's group in declared order; the send acknowledged with the
/// daughters that rode, the commit holding one claim per daughter in the
/// trunk, `old` the daughter and `new` the member. A request naming none is
/// today's frame and body: no `supersede` member, no group.
#[test]
fn the_daughters_ride_the_frame_and_sign_as_the_board_composes_them() {
    for n in [1usize, 2] {
        let (mut world, _) = World::base();
        let (e11, e12) = with_daughters(&mut world);
        let daughters: Vec<Address> = [a(&e11), a(&e12)][..n].to_vec();
        let (dialer, board, signer) = open(world);
        let tok = token();
        let p = publisher(&board, &tok, &signer);
        let asked = Inputs { supersede: daughters.clone(), ..inputs() };
        let e = enumerate(&p, &asked).unwrap();
        let panel = panel(&p, &asked, &e).unwrap();
        let Built::Request(mut request) = build(&p, &asked, &e, &panel, &switched(None)).unwrap() else { panic!("{n}") };
        let named: Vec<String> = daughters.iter().map(ToString::to_string).collect();
        assert_eq!(request.frame(None)["supersede"], json!(named), "{n}: the frame's list as named");
        assert_eq!((&request.supersede, &request.count.supersede), (&daughters, &daughters), "{n}: the request's list and the count's clause");
        // The body: the member's rows, one group per daughter — the trunk's
        // group, which holds nothing else here — then every later home's.
        let trunk = a(E);
        let sup_ty = unit_span(&a(T_SUPERSEDES));
        let units: Vec<Span> = daughters.iter().map(unit_span).collect();
        let rows = request.rows();
        let borrowed: Vec<DepositRow<'_>> = rows.iter().map(OwnedRow::borrow).collect();
        let members: Vec<DepositRow<'_>> = borrowed.iter().filter(|r| r.home == DepositHome::Member).cloned().collect();
        let after: Vec<DepositRow<'_>> = borrowed.iter().filter(|r| matches!(&r.home, DepositHome::Address(h) if **h > trunk)).cloned().collect();
        assert_eq!(members.len() + after.len() + n, borrowed.len(), "{n}: the trunk's group is the claims' alone");
        let expected: Vec<DepositRow<'_>> = members.into_iter().chain(units.iter().map(|u| claim_group(&trunk, &sup_ty, u))).chain(after).collect();
        assert_eq!(request.body().as_bytes(), entry_body_publication(request.shot_body(), &expected).as_bytes(), "{n}: the body the board composes, byte for byte");
        // The send: acknowledged with the daughters that rode, one claim per
        // daughter deposited in the trunk.
        dialer.clear();
        let Sent::Acknowledged(ack) = send(&p, &asked, &mut request).unwrap() else { panic!("{n}") };
        assert_eq!((ack.member.to_string(), ack.supersede.clone()), (format!("{E}.2"), daughters.clone()));
        let w = dialer.world();
        let claims: Vec<(String, String)> = w.links.iter().filter(|l| l.home == E && l.ty[0].0 == T_SUPERSEDES).map(|l| (l.from[0].0.clone(), l.to[0].0.clone())).collect();
        assert_eq!(claims, named.iter().map(|d| (d.clone(), format!("{E}.2"))).collect::<Vec<_>>(), "{n}: one claim per daughter, old the daughter and new the member");
    }
    // No daughter: today's frame and body.
    let (world, _) = World::base();
    let (dialer, board, signer) = open(world);
    let tok = token();
    let (_, _, request) = built(&dialer, &board, &tok, &signer, &switched(None));
    assert!(request.frame(None).get("supersede").is_none(), "no member where none is named");
    assert!(request.rows().iter().all(|r| r.borrow().kind != DepositKind::Supersede), "no group");
    assert!(request.count.supersede.is_empty() && request.supersede.is_empty());
}

/// THE SKIP, read before signing as the board's plan decides it (wire.md
/// §The publish shot and head-float, the deposits): a daughter an ACTIVE
/// claim of the person's own already names — homed in a draft of theirs,
/// its `new` a side version — is dropped from the request's list and its
/// signed groups together, so the frame and the body agree with the board's
/// composition; another account's claim and a retracted one drop nothing;
/// the count carries the daughters as asked and the acknowledgment those
/// that rode, the board depositing no claim for the one skipped; one
/// `in_claims` per daughter at the build. And THE ONE RE-SIGN: an own claim
/// landed between the build and the send is re-read at
/// `attestation_invalid:signature`, the daughter dropped and the request
/// re-signed once under a fresh id.
#[test]
fn an_own_claim_already_naming_a_daughter_drops_its_group_and_its_entry_together() {
    let (mut world, _) = World::base();
    let (e11, e12) = with_daughters(&mut world);
    let e13 = format!("{E}.1.3");
    world.doc(&e13, true, ACCOUNT, vec![run(E, 1, 5)]);
    world.claim(N, &e11, &format!("{E}.1.1.1"));
    world.claim(OTHER, &e12, &format!("{E}.2"));
    let retracted = world.claim(S, &e13, &format!("{E}.2"));
    world.retract(S, &retracted);
    let (dialer, board, signer) = open(world);
    let tok = token();
    let p = publisher(&board, &tok, &signer);
    let asked = Inputs { supersede: vec![a(&e11), a(&e12), a(&e13)], ..inputs() };
    let e = enumerate(&p, &asked).unwrap();
    let panel = panel(&p, &asked, &e).unwrap();
    dialer.clear();
    let Built::Request(mut request) = build(&p, &asked, &e, &panel, &switched(None)).unwrap() else { panic!() };
    let reads: Vec<String> = dialer.frames("in_claims").iter().filter_map(|f| f["y"].as_str().map(str::to_string)).filter(|y| [&e11, &e12, &e13].contains(&y)).collect();
    assert_eq!(reads, vec![e11.clone(), e12.clone(), e13.clone()], "one in_claims per daughter, in order");
    assert_eq!(request.supersede, vec![a(&e12), a(&e13)], "the own-claimed daughter dropped; another's claim and a retracted one drop nothing");
    assert_eq!(request.frame(None)["supersede"], json!([e12, e13]), "the frame's list agrees");
    assert_eq!(request.rows().iter().filter(|r| r.borrow().kind == DepositKind::Supersede).count(), 2, "and the groups");
    assert_eq!(request.count.supersede, asked.supersede, "the count's clause carries the daughters as asked");
    dialer.clear();
    let Sent::Acknowledged(ack) = send(&p, &asked, &mut request).unwrap() else { panic!() };
    assert_eq!(ack.supersede, vec![a(&e12), a(&e13)], "what rode");
    assert_eq!(dialer.frames("publish").len(), 1, "signed once: the body named no skipped daughter");
    let froms: Vec<String> = dialer.world().links.iter().filter(|l| l.home == E && l.ty[0].0 == T_SUPERSEDES).map(|l| l.from[0].0.clone()).collect();
    assert_eq!(froms, vec![e12.clone(), e13.clone()], "no claim for the skipped daughter");
    // THE RE-SIGN: an own claim lands after the build and before the send.
    let (mut world, _) = World::base();
    let (e11, e12) = with_daughters(&mut world);
    let (dialer, board, signer) = open(world);
    let p = publisher(&board, &tok, &signer);
    let asked = Inputs { supersede: vec![a(&e11), a(&e12)], ..inputs() };
    let e = enumerate(&p, &asked).unwrap();
    let panel = super::panel::panel(&p, &asked, &e).unwrap();
    let Built::Request(mut request) = build(&p, &asked, &e, &panel, &switched(None)).unwrap() else { panic!() };
    let first_id = request.id.clone();
    dialer.world().claim(D, &e11, &format!("{E}.1.1.1"));
    dialer.world().refuse_next = Some(json!({"resp": "rejected", "code": "credential_refused", "detail": "attestation_invalid:signature", "disposition": "permanent", "op": "publish"}));
    dialer.clear();
    let Sent::Acknowledged(ack) = send(&p, &asked, &mut request).unwrap() else { panic!() };
    assert_eq!((request.supersede.clone(), ack.supersede.clone()), (vec![a(&e12)], vec![a(&e12)]), "the daughter claimed meanwhile dropped");
    assert_ne!(request.id, first_id, "a fresh id");
    let frames = dialer.frames("publish");
    assert_eq!(frames.len(), 2, "re-signed once");
    assert_eq!((frames[0]["supersede"].clone(), frames[1]["supersede"].clone()), (json!([e11, e12]), json!([e12])));
}

/// `supersede_refused` REACHES THE CALLER TYPED, never as this library's
/// fault and nothing re-sent: `head_moved` with entry 0 and the trunk's head
/// `site.addr` names — the board's own judgement too, a shot off a base the
/// trunk moved past refused whole with no claim deposited and nothing
/// committed — `not_member`, `base` and `duplicate` with their entry, and a
/// detail this client does not know the board's refusal verbatim.
#[test]
fn each_supersede_refusal_is_typed_and_head_moved_carries_the_head() {
    let (mut world, _) = World::base();
    let (e11, _) = with_daughters(&mut world);
    let (dialer, board, signer) = open(world);
    let tok = token();
    let p = publisher(&board, &tok, &signer);
    let asked = Inputs { supersede: vec![a(&e11)], ..inputs() };
    let e = enumerate(&p, &asked).unwrap();
    let panel = panel(&p, &asked, &e).unwrap();
    let Built::Request(mut request) = build(&p, &asked, &e, &panel, &switched(None)).unwrap() else { panic!() };
    let refuse = |detail: &str, site: Value| {
        dialer.world().refuse_next = Some(json!({"resp": "rejected", "code": "supersede_refused", "detail": detail, "disposition": "permanent", "op": "publish", "site": site}));
        dialer.clear();
    };
    let e2 = a(&format!("{E}.2"));
    refuse("head_moved", json!({"index": 0, "addr": e2.to_string()}));
    assert_eq!(send(&p, &asked, &mut request).unwrap(), Sent::Refused(Refusal::SupersedeRefused { index: 0, cause: SupersedeCause::HeadMoved { head: Some(e2.clone()) } }));
    assert_eq!(dialer.frames("publish").len(), 1, "nothing re-sent");
    for (detail, cause) in [("not_member", SupersedeCause::NotMember), ("base", SupersedeCause::Base), ("duplicate", SupersedeCause::Duplicate)] {
        refuse(detail, json!({"index": 1}));
        assert_eq!(send(&p, &asked, &mut request).unwrap(), Sent::Refused(Refusal::SupersedeRefused { index: 1, cause }), "{detail}");
    }
    refuse("later_cause", json!({"index": 0}));
    assert!(matches!(send(&p, &asked, &mut request).unwrap(), Sent::Refused(Refusal::Other(Halt::Refused(r))) if r.code == "supersede_refused"), "an unknown detail verbatim");
    // The board's own judgement: a sibling's shot moves the head to `E.2`
    // after the build, and the shot off `E.1` is refused whole.
    {
        let mut w = dialer.world();
        w.doc(&e2.to_string(), true, ACCOUNT, vec![run(E, 1, 19)]);
        w.trunk_head.insert(E.to_string(), e2.to_string());
    }
    let position = dialer.world().position;
    dialer.clear();
    assert_eq!(send(&p, &asked, &mut request).unwrap(), Sent::Refused(Refusal::SupersedeRefused { index: 0, cause: SupersedeCause::HeadMoved { head: Some(e2.clone()) } }));
    let w = dialer.world();
    assert_eq!(w.position, position, "nothing committed");
    assert!(!w.links.iter().any(|l| l.ty[0].0 == T_SUPERSEDES && l.from[0].0 == e11), "no claim at the daughter");
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
    let shape = price::Shape { runs: &one, drafts: std::slice::from_ref(&draft), draft: None, term: &term, mint: false, claim: false, places: &[Some(1)], also_places: &[], also_runs: &[], stray_records: &[0], entries: &[], retract: 0, originals: &[], read_with: 0, body_bytes: 100, homes: 3, draft_runs: 2 };
    let within = price::price(&shape);
    assert!(within.admits(), "{within:?}");
    assert_eq!((within.lists, within.values, within.reads), ([1, 1, 0, 0, 0, 0], 1, 2));
    assert_eq!(within.bytes, price::SHOT_BYTES + price::PLACED_RUN_BYTES + price::CORRESPONDENCE_RECORD_BYTES + price::KEPT_PLACE_BYTES + price::REINSERTED_VALUE_BYTES);
    // Naming the rendering draft stores its address in the placing record's
    // own slot: the daemon's term, `stored_tumbler_bytes` of it.
    let named = price::price(&price::Shape { draft: Some(&draft), ..shape });
    let comps: Vec<u64> = D.split('.').map(|c| c.parse().expect("a component")).collect();
    assert_eq!(named.bytes, within.bytes + price::stored_tumbler_bytes(&comps), "{named:?}");
    let over = |shape: &price::Shape<'_>| price::price(shape).over.iter().map(|(t, _)| *t).collect::<Vec<_>>();
    let many: Vec<Run> = (0..4097).map(|k| run(E, 1 + k, 1)).collect();
    assert_eq!(over(&price::Shape { runs: &many, drafts: std::slice::from_ref(&draft), draft: None, term: &term, mint: false, claim: false, places: &[], also_places: &[], also_runs: &[], stray_records: &[], entries: &[], retract: 0, originals: &[], read_with: 0, body_bytes: 0, homes: 0, draft_runs: 0 }), [price::Term::Runs]);
    assert_eq!(over(&price::Shape { runs: &one, drafts: std::slice::from_ref(&draft), draft: None, term: &term, mint: false, claim: false, places: &[], also_places: &[], also_runs: &[], stray_records: &[], entries: &[], retract: 4097, originals: &[], read_with: 0, body_bytes: 0, homes: 0, draft_runs: 0 }), [price::Term::Retract]);
    assert_eq!(over(&price::Shape { runs: &one, drafts: std::slice::from_ref(&draft), draft: None, term: &term, mint: false, claim: false, places: &[], also_places: &[], also_runs: &[], stray_records: &[], entries: &[], retract: 0, originals: &[], read_with: 0, body_bytes: price::REQUEST_BODY_BYTES + 1, homes: 0, draft_runs: 0 }), [price::Term::Body]);
    let wide = vec![run(D, 1, price::MAX_REINSERTED_VALUES + 1)];
    let values = price::price(&price::Shape { runs: &wide, drafts: std::slice::from_ref(&draft), draft: None, term: &term, mint: false, claim: false, places: &[], also_places: &[], also_runs: &[], stray_records: &[], entries: &[], retract: 0, originals: &[], read_with: 0, body_bytes: 0, homes: 0, draft_runs: 0 });
    assert!(values.over.iter().any(|(t, by)| *t == price::Term::Values && *by == 1), "{values:?}");
    let reads = price::price(&price::Shape { runs: &one, drafts: std::slice::from_ref(&draft), draft: None, term: &term, mint: false, claim: false, places: &[], also_places: &[], also_runs: &[], stray_records: &[], entries: &[], retract: 0, originals: &[], read_with: 4096, body_bytes: 0, homes: 17, draft_runs: 0 });
    assert_eq!(reads.over, vec![(price::Term::Reads, (17 * 4096 - price::MAX_PUBLICATION_READS) as u64)]);
    let entry = price::EntryShape { from: price::EndShape::Member(vec![(1, 4096)]), to: price::EndShape::Addrs(vec![]), ty: price::EndShape::Addrs(vec![T_CITATION.into()]), old: false };
    let runs4096: Vec<Run> = (0..4096).map(|k| run(D, 1 + k, 1)).collect();
    let entries = vec![entry; 100];
    let bytes = price::price(&price::Shape { runs: &runs4096, drafts: std::slice::from_ref(&draft), draft: None, term: &term, mint: false, claim: false, places: &[], also_places: &[], also_runs: &[], stray_records: &[], entries: &entries, retract: 0, originals: &[], read_with: 0, body_bytes: 0, homes: 1, draft_runs: 1 });
    assert_eq!(bytes.over.iter().map(|(t, _)| *t).collect::<Vec<_>>(), [price::Term::Bytes], "a hundred member-position slots over 4096 runs stage past the budget: {bytes:?}");
    let entries = vec![entries[0].clone()];
    assert!(price::price(&price::Shape { runs: &runs4096, drafts: std::slice::from_ref(&draft), draft: None, term: &term, mint: false, claim: false, places: &[], also_places: &[], also_runs: &[], stray_records: &[], entries: &entries, retract: 0, originals: &[], read_with: 0, body_bytes: 0, homes: 1, draft_runs: 1 }).admits(), "one such entry is inside both budgets");
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

/// Checks that a word deleted since the panel counts nowhere at the re-read.
///
/// The draft's 3..4 are deleted after the panel. The re-read states the run
/// split and reads every test over what the draft still arranges of the
/// selection (PUB-3.108): the note whose `to` lay on those words is covered
/// by its copy over its kept end and is superseded, the link whose content
/// end lay there alone has left, and the formatting line's cut and the
/// notes' ⟨d⟩ count the words as left out. Confirmed again, the request
/// carries neither link and the board takes it, where the note's entry, its
/// `to` the deleted words as stored, is refused `superseded`.
#[test]
fn a_word_deleted_since_the_panel_counts_nowhere_at_the_reread() {
    let (mut world, _) = World::base();
    let note = world.typed(N, vec![ispan(E, 5, 5)], vec![ispan(D, 3, 2)], T_CITATION);
    let copy = world.typed(&format!("{E}.1"), vec![ispan(E, 5, 5)], vec![ispan(D, 3, 2)], T_CITATION);
    world.claim(N, &note, &copy);
    let far = world.typed(N, vec![ispan(E, 1, 3)], vec![ispan(D, 3, 2)], T_CITATION);
    let whole_d = world.typed(N, vec![unit(D)], vec![ispan(D, 3, 2)], T_CITATION);
    let (dialer, board, signer) = open(world);
    let tok = token();
    let p = publisher(&board, &tok, &signer);
    let inputs = inputs();
    let e = enumerate(&p, &inputs).unwrap();
    let first = panel(&p, &inputs, &e).unwrap();
    assert!([&note, &far, &whole_d].iter().all(|l| candidate_at(&e, l).offered()), "the premise: all three offered over the draft's 3..4");
    assert_eq!(first.formatting.cut, 1, "the premise: the heading alone runs past the cut");
    dialer.world().docs.get_mut(D).unwrap().runs = vec![run(E, 1, 19), run(D, 1, 2), run(D, 5, 6), run(O, 1, 5)];
    let again = reread(&p, &inputs, &e, &first).unwrap();
    let r = again.restatement.clone().expect("a difference");
    assert_eq!(r.selection, vec![(1, Placement::Split(vec![(20, 1, 2), (22, 5, 6)])), (2, Placement::Whole { ordinal: 28 })]);
    assert_eq!(again.enumeration.selection, vec![run(E, 1, 19), run(D, 1, 2), run(D, 5, 6), run(O, 1, 5)], "the selection as published: what the draft still arranges");
    let c = candidate_at(&again.enumeration, &note);
    assert_eq!((keys_of(c), c.offered()), ((true, true, false), false), "its copy covers the end it keeps");
    assert_eq!((r.superseded, r.left, r.came), (vec![a(&note)], vec![a(&whole_d)], vec![]));
    assert_eq!(again.panel.formatting.cut, 2, "the bold over 2..4 runs past the cut now");
    let notes = again.panel.rows.iter().find(|row| row.home == a(N)).expect("the notes' row");
    assert_eq!(notes.line.d, 1, "the far link's end lies wholly on words left out");
    // Confirmed again over what is left: nothing moves, and the board takes it.
    let settled = reread(&p, &inputs, &again.enumeration, &again.panel).unwrap();
    assert_eq!(settled.restatement, None);
    let Built::Request(mut request) = build(&p, &inputs, &settled.enumeration, &settled.panel, &switched(None)).unwrap() else { panic!("inert") };
    let entry_of = |link: &str| request.entries.iter().find(|en| settled.enumeration.candidates[en.candidate].link.to_string() == link);
    assert!(entry_of(&note).is_none() && entry_of(&whole_d).is_none(), "{:?}", request.entries);
    assert_eq!(entry_of(&far).expect("the far link's entry").to, End::Spans(vec![ISpan { chain: format!("{D}.0.1"), first: 3, width: 2 }]), "wholly left out: the draft's own span");
    let sent = send(&p, &inputs, &mut request).unwrap();
    assert!(matches!(sent, Sent::Acknowledged(_)), "{sent:?}");
    let claims = dialer.world().links.iter().filter(|l| !l.retracted && l.ty[0].0 == T_SUPERSEDES && l.from[0].0 == note).count();
    assert_eq!(claims, 1, "the note's one copy, none made over the deleted words");
}

/// Checks that a record of words deleted since the panel reaches no link.
///
/// `E`'s 16..19, the words an earlier shot's record in `D` names as its
/// `to`, are deleted from the draft after the panel. The re-read holds no
/// record, so the private link on the record's `from` is reached no more
/// and has left (PUB-3.108); confirmed again, the member homes no copy over
/// words it does not hold.
#[test]
fn a_record_of_deleted_words_reaches_no_link_at_the_reread() {
    let (world, named) = World::base();
    let (dialer, board, signer) = open(world);
    let tok = token();
    let p = publisher(&board, &tok, &signer);
    let inputs = inputs();
    let e = enumerate(&p, &inputs).unwrap();
    let first = panel(&p, &inputs, &e).unwrap();
    assert!(candidate_at(&e, &named.l_rt).offered(), "the premise: reached through the record");
    dialer.world().docs.get_mut(D).unwrap().runs = vec![run(E, 1, 15), run(D, 1, 10), run(O, 1, 5)];
    let again = reread(&p, &inputs, &e, &first).unwrap();
    let r = again.restatement.clone().expect("a difference");
    assert_eq!(r.selection, vec![(0, Placement::Split(vec![(1, 1, 15)])), (1, Placement::Whole { ordinal: 16 }), (2, Placement::Whole { ordinal: 26 })]);
    assert!(again.enumeration.records.is_empty(), "no record's `to` lies on what the draft still arranges: {:?}", again.enumeration.records);
    assert_eq!((r.left, r.superseded, r.came), (vec![a(&named.l_rt)], vec![], vec![]));
    let notes = again.panel.rows.iter().find(|row| row.home == a(N)).expect("the notes' row");
    assert_eq!((links_of(&again.enumeration, &notes.links), notes.read_through), (vec![named.l1_n.clone()], 0));
    let settled = reread(&p, &inputs, &again.enumeration, &again.panel).unwrap();
    assert_eq!(settled.restatement, None);
    let Built::Request(mut request) = build(&p, &inputs, &settled.enumeration, &settled.panel, &switched(None)).unwrap() else { panic!("inert") };
    assert_eq!(request.runs, vec![run(E, 1, 15), run(D, 1, 10), run(O, 1, 5)]);
    let Sent::Acknowledged(ack) = send(&p, &inputs, &mut request).unwrap() else { panic!("refused") };
    let member = ack.member.to_string();
    assert!(!dialer.world().links.iter().any(|l| l.home == member && l.from == vec![ispan(E, 16, 4)]), "no copy over E's 16..19, which the member does not hold");
}

/// Checks that a window deleted since the panel is owed no answer.
///
/// The window onto `O` is deleted from the draft after the panel and never
/// answered. The re-read states it absent, and the request confirmed again
/// carries the rest and is sent: a run the draft no longer arranges is
/// asked nothing, and an answer given for it holds nothing back
/// (PUB-3.108).
#[test]
fn a_window_deleted_since_the_panel_owes_no_answer() {
    let (world, _) = World::base();
    let (dialer, board, signer) = open(world);
    let tok = token();
    let p = publisher(&board, &tok, &signer);
    let inputs = inputs();
    let e = enumerate(&p, &inputs).unwrap();
    let first = panel(&p, &inputs, &e).unwrap();
    dialer.world().docs.get_mut(D).unwrap().runs = vec![run(E, 1, 19), run(D, 1, 10)];
    let again = reread(&p, &inputs, &e, &first).unwrap();
    assert_eq!(again.restatement.expect("a difference").selection, vec![(2, Placement::Absent)]);
    let mut confirmed = switched(None);
    confirmed.answers.insert(2, OriginAnswer::PublishFirst);
    let Built::Request(_) = build(&p, &inputs, &again.enumeration, &again.panel, &confirmed).unwrap() else { panic!("inert at an answer for a deleted run") };
    confirmed.answers.clear();
    let Built::Request(mut request) = build(&p, &inputs, &again.enumeration, &again.panel, &confirmed).unwrap() else { panic!("inert") };
    assert_eq!((request.runs.clone(), request.places.clone()), (vec![run(E, 1, 19), run(D, 1, 10)], vec![None, Some(20)]));
    let sent = send(&p, &inputs, &mut request).unwrap();
    assert!(matches!(sent, Sent::Acknowledged(_)), "{sent:?}");
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
/// reference WITH the covered piece's kept place, the rest a window with
/// none.
#[test]
fn the_three_answers_and_the_counterpart_first() {
    let (world, _) = World::base();
    let (_, board, signer) = open(world);
    let tok = token();
    let p = publisher(&board, &tok, &signer);
    let inputs = inputs();
    let e = enumerate(&p, &inputs).unwrap();
    let panel = panel(&p, &inputs, &e).unwrap();
    // THE WINDOWS are the panel's: the one run onto `O`, the person's own
    // unpublished origin, its owner and where in `O` it was written, no
    // counterpart (no record of a draft the person reads names its words).
    assert_eq!(panel.windows.len(), 1, "{:?}", panel.windows);
    assert_eq!((panel.windows[0].run, panel.windows[0].origin.to_string(), panel.windows[0].owner.as_str(), panel.windows[0].i_start, panel.windows[0].width), (2, O.to_string(), ACCOUNT, 1, 5));
    assert_eq!(panel.windows[0].counterpart, None);
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
    // It is read at the PANEL — the windows step, one four-set over the record
    // class homed in O — and the request takes it as given: no read of O at
    // the build.
    let (mut world, _) = World::base();
    let record = world.typed(O, vec![ispan(O, 1, 4)], vec![ispan(E, 16, 4)], T_CORRESPONDENCE);
    let (dialer, board, signer) = open(world);
    let p = publisher(&board, &tok, &signer);
    let mut with_o = inputs.clone();
    with_o.readable_drafts.push(a(O));
    let e = enumerate(&p, &with_o).unwrap();
    let panel = super::panel::panel(&p, &with_o, &e).unwrap();
    let counterpart = panel.windows[0].counterpart.as_ref().expect("the counterpart offered at the panel");
    assert_eq!((counterpart.run, counterpart.record.to_string(), counterpart.to.first, counterpart.to.width), (2, record.clone(), 16, 4));
    assert!(panel.frames.iter().any(|(step, _)| *step == "windows"), "the windows are a step of the panel: {:?}", panel.frames);
    let reads_o = |frames: &[Value]| frames.iter().filter(|f| f["q"]["home"][0]["start"].as_str() == Some(O)).count();
    assert_eq!(reads_o(&dialer.frames("find_links_ftt")), 1, "one four-set homed in O at the panel");
    dialer.clear();
    confirmed.answers.insert(2, OriginAnswer::KeepPrivate);
    let Built::Request(offered) = build(&p, &with_o, &e, &panel, &confirmed).unwrap() else { panic!() };
    assert_eq!(reads_o(&dialer.frames("find_links_ftt")), 0, "the build reads no counterpart of its own: {:?}", dialer.ops());
    assert!(dialer.frames("doc_metadata").iter().all(|f| f["doc"].as_str() != Some(O)), "nor O's state: {:?}", dialer.ops());
    assert_eq!(offered.counterparts.len(), 1);
    assert_eq!((offered.counterparts[0].run, offered.counterparts[0].record.to_string(), offered.counterparts[0].to.first, offered.counterparts[0].to.width), (2, record.clone(), 16, 4));
    confirmed.answers.insert(2, OriginAnswer::Counterpart);
    let Built::Request(taken) = build(&p, &with_o, &e, &panel, &confirmed).unwrap() else { panic!() };
    assert_eq!(taken.runs[2], run(E, 16, 4), "the covered part re-composed by reference to the record's to");
    assert_eq!(taken.runs[3], run(O, 5, 1), "the rest a window still");
    assert_eq!(&taken.places[2..], &[Some(30), None], "the covered piece with its kept place, the rendering draft's own position of it; the window with none");
    assert_eq!(&taken.stray_records[2..], &[1, 0], "the covered piece counts the one record the commit reads for it");
}

/// THE COUNTERPART's KEPT PLACE (the link-sets design §5.5: "its KEPT
/// PLACE sent beside it as a stray's is"): the covered piece of a window
/// re-composed by reference to a record's `to` carries the rendering
/// draft's own V-position of it — in THIS document, where the record's `to`
/// is `E`'s identity, and in ANOTHER, where an earlier shot published the
/// origin's words into `F` — the uncovered remainder a window with none;
/// the pre-check passes the piece through with its place and counts its
/// one record, the price charges the kept place beside the run; the request
/// is not inert for it; and the scripted board, reading the record wherever
/// homed, re-windows `D` there onto the published identity, `E`'s or `F`'s.
#[test]
fn the_counterpart_arm_sends_the_covered_pieces_place_in_this_document_or_another_and_the_precheck_counts_its_record() {
    const F: &str = "1.0.1.0.10";
    // The record's `to`: E's 5..8 (the fixture's earlier record in D names
    // E's 16..19 already), or F's 16..19.
    for (what, to_doc, to_first, published_into_f) in [("into this document", E, 5u64, false), ("into another document", F, 16u64, true)] {
        let (mut world, _) = World::base();
        if published_into_f {
            world.text(F, 1, "another document one");
            world.doc(F, true, ACCOUNT, vec![run(F, 1, 20)]);
        }
        // O's `quot` published before as `to_doc`'s words: the record in O.
        let record = world.typed(O, vec![ispan(O, 1, 4)], vec![ispan(to_doc, to_first, 4)], T_CORRESPONDENCE);
        let (dialer, board, signer) = open(world);
        let tok = token();
        let p = publisher(&board, &tok, &signer);
        let mut inputs = inputs();
        inputs.readable_drafts.push(a(O));
        let e = enumerate(&p, &inputs).unwrap();
        let panel = super::panel::panel(&p, &inputs, &e).unwrap();
        let counterpart = panel.windows[0].counterpart.as_ref().expect("the counterpart offered at the panel");
        assert_eq!((counterpart.record.to_string(), counterpart.to.document().as_deref(), counterpart.to.first), (record.clone(), Some(to_doc), to_first), "{what}");
        let mut confirmed = switched(None);
        confirmed.answers.insert(2, OriginAnswer::Counterpart);
        let Built::Request(mut taken) = build(&p, &inputs, &e, &panel, &confirmed).unwrap() else { panic!("{what}: inert") };
        assert_eq!(taken.runs, vec![run(E, 1, 19), run(D, 1, 10), run(to_doc, to_first, 4), run(O, 5, 1)], "{what}: the covered part by reference to the record's to, the rest a window");
        assert_eq!(taken.places, vec![None, Some(20), Some(30), None], "{what}: the covered piece's place is D's own position of it; the window has none");
        assert_eq!(taken.stray_records, vec![0, 0, 1, 0], "{what}: the one record the commit reads for the piece");
        assert!(matches!(taken.pieces[2], Piece::Values(_)) == !published_into_f, "{what}: E's own identity reads through the draft, F's is a window by address");
        // The price charges the piece's kept place per record it counts.
        let mut unplaced = (*taken).clone();
        (unplaced.places[2], unplaced.stray_records[2]) = (None, 0);
        let mut twice = (*taken).clone();
        twice.stray_records[2] = 2;
        assert_eq!(taken.priced(0, 0, &[]).bytes, unplaced.priced(0, 0, &[]).bytes + super::price::KEPT_PLACE_BYTES, "{what}: the kept place beside the piece, at its one record");
        assert_eq!(twice.priced(0, 0, &[]).bytes, taken.priced(0, 0, &[]).bytes + super::price::KEPT_PLACE_BYTES, "{what}: per record");
        assert!(taken.price.admits(), "{what}: {:?}", taken.price);
        // Sent: the board finds the record in O by its `to`, checks D
        // arranges O's words at 30, and re-windows D there.
        dialer.clear();
        let Sent::Acknowledged(ack) = send(&p, &inputs, &mut taken).unwrap() else { panic!("{what}: refused") };
        assert_eq!((ack.member.to_string(), ack.via), (format!("{E}.2"), AckVia::Answer), "{what}");
        let w = dialer.world();
        assert_eq!(w.docs[D].runs, vec![run(E, 1, 29), run(to_doc, to_first, 4), run(O, 5, 1)], "{what}: D re-windowed onto the published identity where O's words stood, its own fresh words I-adjacent to E's");
        assert_eq!(w.docs[&format!("{E}.2")].runs, vec![run(E, 1, 29), run(to_doc, to_first, 4), run(O, 5, 1)], "{what}: the member holds the published words by reference");
        let row = w.rows.iter().find(|r| r.at == ack.at).expect("the publish row");
        assert_eq!(row.docs[..2], [format!("{E}.2"), D.to_string()], "{what}: the member, then the re-windowed draft");
    }
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
    let re = twin_precheck(&p, &inputs, &[run(D, 1, 10)], &[Some(20)], &[Some(20)], &[]).unwrap();
    assert_eq!(re.runs, vec![run(D, 1, 3), run(E, 20, 3), run(D, 7, 4)]);
    assert_eq!(re.places, vec![Some(20), Some(23), Some(26)]);
    assert_eq!(re.also_places, vec![], "no `also` draft, no list");
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

/// Checks that an end reached through another draft's record is spelled on
/// the words that record published.
///
/// `O`'s words published before as `E`'s 5..8, the record in `O`, and a
/// note on them accepted while the draft windowed `O`, so its copy at `E.1`
/// holds `O`'s identity; the draft windows `O` no longer. The read-through
/// reaches the note through `O`'s record, of a draft the request does not
/// name, and its end is read and spelled through that record as `E`'s 5..8,
/// words its copy never covered, so the board takes it.
#[test]
fn an_end_reached_through_another_drafts_record_is_spelled_on_the_words_it_published() {
    let (mut world, _) = World::base();
    world.docs.get_mut(D).unwrap().runs = vec![run(E, 1, 19), run(D, 1, 10)];
    let record = world.typed(O, vec![ispan(O, 1, 4)], vec![ispan(E, 5, 4)], T_CORRESPONDENCE);
    let note = world.typed(N, vec![ispan(O, 1, 4)], vec![ispan(N, 6, 2)], T_CITATION);
    let copy = world.typed(&format!("{E}.1"), vec![ispan(O, 1, 4)], vec![ispan(N, 6, 2)], T_CITATION);
    world.claim(N, &note, &copy);
    let (_, board, signer) = open(world);
    let tok = token();
    let p = publisher(&board, &tok, &signer);
    let unwindowed = Inputs { selection: vec![run(E, 1, 19), run(D, 1, 10)], ..inputs() };
    let e = enumerate(&p, &unwindowed).unwrap();
    let c = candidate_at(&e, &note);
    assert_eq!(c.via, Via::ReadThrough(vec![a(&record)]));
    assert_eq!((keys_of(c), c.offered()), ((true, false, false), true), "its copy holds O's words, not E's 5..8");
    let pn = panel(&p, &unwindowed, &e).unwrap();
    let Built::Request(mut request) = build(&p, &unwindowed, &e, &pn, &switched(None)).unwrap() else { panic!("inert") };
    let entry = request.entries.iter().find(|en| e.candidates[en.candidate].link.to_string() == note).expect("the note's entry");
    assert_eq!(entry.from, End::Spans(vec![ISpan { chain: format!("{E}.0.1"), first: 5, width: 4 }]), "spelled through O's record");
    let sent = send(&p, &unwindowed, &mut request).unwrap();
    assert!(matches!(sent, Sent::Acknowledged(_)), "no successor covers it on E's words: {sent:?}");
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
    assert_eq!((ack.member.to_string(), ack.via, ack.edition.clone(), ack.claim), (format!("{E}.2"), AckVia::Answer, None, false));
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

/// Checks that the scripted board refuses an entry its own copy covers.
///
/// `l_rt` accepted with its copy at `E.1` over `E`'s 16..19: an entry
/// carrying it again over those words is refused `old_refused`,
/// `superseded`, naming the entry, as the plan's `check_old` refuses it,
/// and nothing is committed.
#[test]
fn the_board_refuses_an_entry_re_offering_an_original_its_copy_covers() {
    let (mut world, named) = World::base();
    let copy = world.typed(&format!("{E}.1"), vec![ispan(E, 16, 4)], vec![ispan(N, 1, 2)], T_CITATION);
    world.claim(N, &named.l_rt, &copy);
    let (dialer, board, signer) = open(world);
    let tok = token();
    let p = publisher(&board, &tok, &signer);
    let (e, _, mut request) = built(&dialer, &board, &tok, &signer, &switched(None));
    let candidate = e.candidates.iter().position(|c| c.link.to_string() == named.l_rt).expect("a candidate");
    let span = |doc: &str, first: u64, width: u64| End::Spans(vec![ISpan { chain: format!("{doc}.0.1"), first, width }]);
    request.entries.push(Entry { home: EntryHome::Member, from: span(E, 16, 4), to: span(N, 1, 2), ty: End::Addrs(vec![T_CITATION.into()]), old: Some(a(&named.l_rt)), candidate });
    let index = request.entries.len() as u64 - 1;
    let position = dialer.world().position;
    assert_eq!(send(&p, &inputs(), &mut request).unwrap(), Sent::Refused(Refusal::OwnFault(OwnFault::Deposit { code: "old_refused".into(), index: Some(index), detail: Some("superseded".into()) })));
    assert_eq!(dialer.world().position, position, "nothing committed");
}

/// Checks that the scripted board exempts new words as narrowly as the plan.
///
/// Two entries beside covering copies are still refused `old_refused`,
/// `superseded`, as the plan's `check_old` refuses them. A far-end note
/// whose copy holds the draft's 3..4 verbatim, its `to` spelled as that
/// I-span, holds no new words: the end names the draft's own identity. The
/// revision `l_rev`, its end at the member's positions over the new words
/// beside its own, is judged by its original's accepted copy whatever new
/// words it holds.
#[test]
fn the_board_exempts_only_a_member_position_end_on_new_words_and_only_the_claim_naming_old() {
    let tok = token();
    let span = |doc: &str, first: u64, width: u64| End::Spans(vec![ISpan { chain: format!("{doc}.0.1"), first, width }]);
    let refused = |index: usize| Sent::Refused(Refusal::OwnFault(OwnFault::Deposit { code: "old_refused".into(), index: Some(index as u64), detail: Some("superseded".into()) }));
    // The far-end note, spelled on the draft's own identity.
    let (mut world, _) = World::base();
    let note = world.typed(N, vec![ispan(E, 5, 5)], vec![ispan(D, 3, 2)], T_CITATION);
    let copy = world.typed(&format!("{E}.1"), vec![ispan(E, 5, 5)], vec![ispan(D, 3, 2)], T_CITATION);
    world.claim(N, &note, &copy);
    let (dialer, board, signer) = open(world);
    let p = publisher(&board, &tok, &signer);
    let (e, _, mut request) = built(&dialer, &board, &tok, &signer, &switched(None));
    let candidate = e.candidates.iter().position(|c| c.link.to_string() == note).expect("a candidate");
    request.entries.retain(|en| en.old != Some(a(&note)));
    request.entries.push(Entry { home: EntryHome::Member, from: span(E, 5, 5), to: span(D, 3, 2), ty: End::Addrs(vec![T_CITATION.into()]), old: Some(a(&note)), candidate });
    let (index, position) = (request.entries.len() - 1, dialer.world().position);
    assert_eq!(send(&p, &inputs(), &mut request).unwrap(), refused(index), "an I-span end on the draft's words");
    assert_eq!(dialer.world().position, position, "nothing committed");
    // The revision, beside the draft's new words 1..2 at positions 20..21.
    let (world, named) = World::base();
    let (dialer, board, signer) = open(world);
    let p = publisher(&board, &tok, &signer);
    let (e, _, mut request) = built(&dialer, &board, &tok, &signer, &switched(None));
    let candidate = e.candidates.iter().position(|c| c.link.to_string() == named.l_rev).expect("a candidate");
    let beside_new_words = End::Member(vec![(16, 3), (20, 2)]);
    request.entries.push(Entry { home: EntryHome::Member, from: beside_new_words, to: span(N, 6, 4), ty: End::Addrs(vec![T_HEADING.into()]), old: Some(a(&named.l_rev)), candidate });
    let (index, position) = (request.entries.len() - 1, dialer.world().position);
    assert_eq!(send(&p, &inputs(), &mut request).unwrap(), refused(index), "a revision beside new words");
    assert_eq!(dialer.world().position, position, "nothing committed");
}

/// Checks that a second publication offers nothing the first accepted.
///
/// The draft publishes its whole selection, its own words re-minted as
/// `E`'s 20..29 and the draft re-windowed onto them; a word typed, it
/// publishes again off the member the first one made. Every link the first
/// one accepted on the draft's own words — the bold, the heading, the
/// citations and the note on an earlier shot's words — comes back by the
/// read-through, and its copy covers its ends read through the records, so
/// none is offered, the request carries no entry, and the board takes it.
#[test]
fn a_second_publication_offers_nothing_the_first_accepted_and_lands() {
    let (world, named) = World::base();
    let (dialer, board, signer) = open(world);
    let tok = token();
    let p = publisher(&board, &tok, &signer);
    let (_, _, mut first) = built(&dialer, &board, &tok, &signer, &switched(None));
    let Sent::Acknowledged(ack) = send(&p, &inputs(), &mut first).unwrap() else { panic!("refused") };
    let e2 = format!("{E}.2");
    assert_eq!(ack.member.to_string(), e2);
    {
        let mut w = dialer.world();
        assert_eq!(w.docs[D].runs, vec![run(E, 1, 29), run(O, 1, 5)], "the premise: the draft re-windowed onto the member's words");
        w.text(D, 30, "!");
        w.docs.get_mut(D).unwrap().runs = vec![run(E, 1, 29), run(D, 30, 1), run(O, 1, 5)];
    }
    let again = Inputs { base: Some((a(&e2), 34)), selection: vec![run(E, 1, 29), run(D, 30, 1), run(O, 1, 5)], ..inputs() };
    let e = enumerate(&p, &again).unwrap();
    for link in [&named.mark_d, &named.heading_d, &named.cite_d, &named.cut_d, &named.l_rt] {
        let c = candidate_at(&e, link);
        assert!(matches!(c.via, Via::ReadThrough(_)), "{link}: reached by the read-through");
        assert_eq!((keys_of(c), c.offered()), ((true, true, false), false), "{link}: its copy covers its ends read through the records");
    }
    let private: Vec<String> = e.offered_by_home().into_iter().filter(|(h, _)| ![S, S2].contains(&h.to_string().as_str())).flat_map(|(_, links)| links.into_iter().map(|l| l.to_string())).collect();
    assert!(private.is_empty(), "nothing private the first publication accepted is offered: {private:?}");
    let pn = panel(&p, &again, &e).unwrap();
    assert!(pn.formatting.marks.is_empty(), "no mark on the line: {:?}", links_of(&e, &pn.formatting.marks));
    let Built::Request(mut request) = build(&p, &again, &e, &pn, &switched(None)).unwrap() else { panic!("inert") };
    assert!(request.entries.is_empty(), "{:?}", request.entries);
    let sent = send(&p, &again, &mut request).unwrap();
    assert!(matches!(&sent, Sent::Acknowledged(ack) if ack.member.to_string() == format!("{E}.3")), "{sent:?}");
}

/// Checks that a claimed board serving no head record sends nothing.
///
/// Where `H.1` serves no record and `/health` names a claimant, the send is
/// refused `Refusal::HeadUnreadable`, no frame sent; a board no one claimed
/// takes the frame without an `attest`.
#[test]
fn a_claimed_board_serving_no_head_record_sends_nothing() {
    let (dialer, board, signer) = open({
        let (mut w, _) = World::base();
        w.head = false;
        w
    });
    let tok = token();
    let (_, _, mut request) = built(&dialer, &board, &tok, &signer, &switched(None));
    let p = publisher(&board, &tok, &signer);
    dialer.clear();
    assert_eq!(send(&p, &inputs(), &mut request).unwrap(), Sent::Refused(Refusal::HeadUnreadable));
    assert!(dialer.frames("publish").is_empty(), "no frame: {:?}", dialer.ops());
    dialer.world().claimed = false;
    let sent = send(&p, &inputs(), &mut request).unwrap();
    assert!(matches!(sent, Sent::Acknowledged(_)), "{sent:?}");
    assert!(dialer.frames("publish")[0].get("attest").is_none(), "an unclaimed board takes the frame unsigned");
}

/// Checks that the board's own `attestation_invalid:board_unavailable` is
/// the head arm, signed or not.
///
/// The frame signed over a record the board's own build does not read, or
/// sent unsigned to a board a claim reached after the send's read, its first
/// head refused, meets the board's state, never this library's frame: the
/// refusal is answered `Refusal::HeadUnreadable`, never `OwnFault::Attest`,
/// and the frame is never re-sent.
#[test]
fn the_boards_own_board_unavailable_is_head_unreadable_signed_or_not() {
    let tok = token();
    let unavailable = json!({"resp": "rejected", "code": "credential_refused", "detail": "attestation_invalid:board_unavailable", "disposition": "reorder", "op": "publish"});
    for claimed in [true, false] {
        let (dialer, board, signer) = open({
            let (mut w, _) = World::base();
            w.claimed = claimed;
            w.head = claimed;
            w
        });
        let (_, _, mut request) = built(&dialer, &board, &tok, &signer, &switched(None));
        let p = publisher(&board, &tok, &signer);
        dialer.clear();
        dialer.world().refuse_next = Some(unavailable.clone());
        assert_eq!(send(&p, &inputs(), &mut request).unwrap(), Sent::Refused(Refusal::HeadUnreadable), "claimed {claimed}");
        let frames = dialer.frames("publish");
        assert_eq!(frames.len(), 1, "claimed {claimed}: one frame, never re-sent: {:?}", dialer.ops());
        match (claimed, frames[0].get("attest")) {
            (true, Some(attest)) => assert!(attest["sig"].is_string(), "signed over `H.1`'s pair: {attest}"),
            (false, None) => {}
            (_, attest) => panic!("claimed {claimed}: the frame's attest {attest:?}"),
        }
    }
}

/// Checks that a claim landing past the send's head read is met by one
/// signed send under a fresh `id`.
///
/// The send reads a board no one has claimed and sends the frame unsigned; a
/// claim lands, its head written, before the frame's turn, and the board
/// refuses the frame `attestation_required` before its transaction. The
/// head is read again and the same request sent once more, signed over the
/// pair now read, under a fresh `id`, and acknowledged: one publication
/// committed. That send's answer is a signed frame's — `attestation_required`
/// again the library's own fault and `signed_session_required` its own arm,
/// never a third send — and where the head read again serves none, the
/// board's refusal of the unsigned frame answers `Refusal::HeadUnreadable`,
/// nothing sent after it.
#[test]
fn a_claim_past_the_head_read_is_re_sent_once_signed_under_a_fresh_id() {
    let tok = token();
    let unclaimed = |claim_at_publish: bool| {
        open({
            let (mut w, _) = World::base();
            w.claimed = false;
            w.head = false;
            w.claim_at_publish = claim_at_publish;
            w
        })
    };
    let rejected = |code: &str, detail: Option<&str>| {
        let mut rej = json!({"resp": "rejected", "code": code, "disposition": "reorder", "op": "publish"});
        if let Some(d) = detail {
            rej["detail"] = json!(d);
        }
        rej
    };
    let (dialer, board, signer) = unclaimed(true);
    let (_, _, mut request) = built(&dialer, &board, &tok, &signer, &switched(None));
    let p = publisher(&board, &tok, &signer);
    let first_id = request.id.clone();
    let committed = dialer.world().rows.iter().filter(|r| r.op == "publish").count();
    dialer.clear();
    let sent = send(&p, &inputs(), &mut request).unwrap();
    let Sent::Acknowledged(ack) = &sent else { panic!("{sent:?}") };
    assert_eq!((ack.member.to_string(), ack.via), (format!("{E}.2"), AckVia::Answer));
    let frames = dialer.frames("publish");
    assert_eq!(frames.len(), 2, "one signed send after the unsigned one: {:?}", dialer.ops());
    assert!(frames[0].get("attest").is_none(), "the first went unsigned: {}", frames[0]);
    assert_ne!(request.id, first_id, "a fresh id");
    assert_eq!((frames[0]["id"].as_str(), frames[1]["id"].as_str()), (Some(first_id.as_str()), Some(request.id.as_str())));
    let mut resent = frames[1].clone();
    let attest = resent.as_object_mut().unwrap().remove("attest").expect("the second send signed");
    resent["id"] = frames[0]["id"].clone();
    assert_eq!(resent, frames[0], "the same request, signed");
    let term = board.board_term().unwrap().expect("the pair read after the claim");
    let alg = Signer::public_key(&signer).alg();
    assert_eq!(attest["alg"].as_str(), Some(alg));
    let expected = entry_frame(alg, term, &a(ACCOUNT), DocTerm::One(request.term()), &request.body());
    let sig = crate::hex::decode(attest["sig"].as_str().unwrap()).unwrap();
    assert_eq!(skep_signature::verify(Signer::tag(&signer), Signer::public_key(&signer), &expected, &sig), Ok(()), "signed over the pair read after the claim");
    let heads = dialer.frames("retrieve_v").iter().filter(|f| f["specs"][0]["doc"] == HEAD_MEMBER_1).count();
    assert_eq!(heads, 2, "`H.1` read before the frame and again after the claim");
    let w = dialer.world();
    assert_eq!(w.rows.iter().filter(|r| r.op == "publish").count(), committed + 1, "one publication committed");
    assert!(w.docs.contains_key(&format!("{E}.2")) && !w.docs.contains_key(&format!("{E}.3")), "nothing applied twice");
    drop(w);
    // The signed send's answer is a signed frame's, and never sent again.
    let answers = [
        (rejected("credential_refused", Some("attestation_required")), Sent::Refused(Refusal::OwnFault(OwnFault::Attest { detail: Some("attestation_required".into()) }))),
        (rejected("signed_session_required", None), Sent::Refused(Refusal::NeedsSignedSession)),
    ];
    for (refusal, answer) in answers {
        let (dialer, board, signer) = unclaimed(true);
        let (_, _, mut request) = built(&dialer, &board, &tok, &signer, &switched(None));
        let p = publisher(&board, &tok, &signer);
        let rows = dialer.world().rows.len();
        dialer.world().refuse_next = Some(refusal.clone());
        dialer.clear();
        assert_eq!(send(&p, &inputs(), &mut request).unwrap(), answer, "{refusal}");
        let frames = dialer.frames("publish");
        assert_eq!(frames.len(), 2, "{refusal}: never a third send: {:?}", dialer.ops());
        assert!(frames[0].get("attest").is_none() && frames[1]["attest"]["sig"].is_string(), "{refusal}: unsigned, then signed");
        assert_eq!(dialer.world().rows.len(), rows, "{refusal}: nothing committed");
    }
    // The board refuses the unsigned frame so, and the head read again
    // serves no record to sign over: the head arm, one frame.
    let (dialer, board, signer) = unclaimed(false);
    let (_, _, mut request) = built(&dialer, &board, &tok, &signer, &switched(None));
    let p = publisher(&board, &tok, &signer);
    dialer.world().refuse_next = Some(rejected("credential_refused", Some("attestation_required")));
    dialer.clear();
    assert_eq!(send(&p, &inputs(), &mut request).unwrap(), Sent::Refused(Refusal::HeadUnreadable));
    assert_eq!(dialer.frames("publish").len(), 1, "nothing sent after the second read: {:?}", dialer.ops());
}

/// Checks that a head record that stands and cannot be read sends nothing.
///
/// The read halts naming why (SP-14), on a claimed board and on one no one
/// claimed alike, and no frame leaves: a damaged record is never read as no
/// record (the mutant that reads it as none sends the frame unsigned where no
/// one claimed the board).
#[test]
fn a_damaged_head_record_sends_nothing_claimed_or_not() {
    let tok = token();
    for claimed in [true, false] {
        let (dialer, board, signer) = open({
            let (mut w, _) = World::base();
            w.claimed = claimed;
            w.damaged_head = true;
            w
        });
        let (_, _, mut request) = built(&dialer, &board, &tok, &signer, &switched(None));
        let p = publisher(&board, &tok, &signer);
        dialer.clear();
        match send(&p, &inputs(), &mut request) {
            Err(Fault::Halt(Halt::Halt(face))) => assert!(face.state.contains("`H.1`") && face.cause.contains("no JSON"), "claimed {claimed}: {face}"),
            other => panic!("claimed {claimed}: {other:?}"),
        }
        assert!(dialer.frames("publish").is_empty(), "claimed {claimed}: no frame: {:?}", dialer.ops());
    }
}

/// THE REFUSAL FAMILY's arms, each from the board's own refusal with its
/// site: `kept_place_moved` with the entry, the draft `site.addr` names
/// and the race's key off the feed under it — the rendering draft where an
/// older board names none; `stray_place_unrecorded` the library's own,
/// naming the draft alike; `publication_over_budget` a
/// race where this price admitted; `not_owner` naming the draft;
/// `claim_refused` naming the edition; the six
/// deposit tokens with their entry and detail; `unparseable` on a request
/// carrying members the older-board arm; `base_superseded` its own arm
/// naming the trunk's first member, out of the shot's table, whose other
/// codes are the library's own; an `attestation_*` token but the
/// signature's and `board_unavailable` the library's own too,
/// `attestation_required` at the signed frame among them and never sent
/// again; `withheld`
/// the window's origin; `signed_session_required`; and the board's other
/// refusals verbatim.
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
    refuse("kept_place_moved", json!({"site": {"index": 1, "addr": D}}));
    let sent = send(&p, &inputs(), &mut request).unwrap();
    let Sent::Refused(Refusal::KeptPlaceMoved { index, draft, race }) = sent else { panic!("{sent:?}") };
    assert_eq!((index, draft), (1, a(D)), "the entry and the draft the board names");
    assert_eq!(race, Some(RaceKey { at: 999, key: Some("ab".repeat(32)), signed: false }), "whose write moved the words");
    refuse("kept_place_moved", json!({"site": {"index": 1}}));
    assert!(matches!(send(&p, &inputs(), &mut request).unwrap(), Sent::Refused(Refusal::KeptPlaceMoved { draft, .. }) if draft == a(D)), "an older board naming no draft: the rendering draft");
    refuse("stray_place_unrecorded", json!({"site": {"index": 0, "addr": D}}));
    assert_eq!(send(&p, &inputs(), &mut request).unwrap(), Sent::Refused(Refusal::OwnFault(OwnFault::StrayPlace { index: 0, draft: a(D) })));
    refuse("publication_over_budget", json!({"detail": "70000 in-lock reads priced over the budget of 65536"}));
    assert_eq!(send(&p, &inputs(), &mut request).unwrap(), Sent::Refused(Refusal::BudgetRace { detail: Some("70000 in-lock reads priced over the budget of 65536".into()) }));
    refuse("not_owner", json!({"site": {"addr": D}}));
    assert_eq!(send(&p, &inputs(), &mut request).unwrap(), Sent::Refused(Refusal::UnownedDraft { draft: a(D) }));
    refuse("not_owner", json!({"site": {"addr": E}}));
    assert_eq!(send(&p, &inputs(), &mut request).unwrap(), Sent::Refused(Refusal::NotOwner { addr: Some(a(E)) }));
    refuse("claim_refused", json!({"site": {"addr": E}, "detail": "member_stands"}));
    assert_eq!(send(&p, &inputs(), &mut request).unwrap(), Sent::Refused(Refusal::ClaimRefused { edition: Some(a(E)) }));
    for code in ["link_home_refused", "old_refused", "duplicate_original", "read_with_in_links", "retract_refused", "read_with_refused"] {
        refuse(code, json!({"site": {"index": 2}, "detail": "superseded"}));
        assert_eq!(send(&p, &inputs(), &mut request).unwrap(), Sent::Refused(Refusal::OwnFault(OwnFault::Deposit { code: code.into(), index: Some(2), detail: Some("superseded".into()) })));
    }
    dialer.world().refuse_next = Some(json!({"resp": "rejected", "code": "malformed", "detail": "unknown field `links`", "disposition": "permanent", "op": "unparseable"}));
    assert_eq!(send(&p, &inputs(), &mut request).unwrap(), Sent::Refused(Refusal::OlderBoard { detail: Some("unknown field `links`".into()) }));
    refuse("base_superseded", json!({}));
    assert_eq!(send(&p, &inputs(), &mut request).unwrap(), Sent::Refused(Refusal::BaseSuperseded { first: a(&format!("{E}.1")) }), "its own arm, never the library's fault");
    refuse("base_not_in_chain", json!({}));
    assert_eq!(send(&p, &inputs(), &mut request).unwrap(), Sent::Refused(Refusal::OwnFault(OwnFault::Shot { code: "base_not_in_chain".into() })));
    refuse("credential_refused", json!({"detail": "attestation_invalid:malformed"}));
    assert_eq!(send(&p, &inputs(), &mut request).unwrap(), Sent::Refused(Refusal::OwnFault(OwnFault::Attest { detail: Some("attestation_invalid:malformed".into()) })), "the library's own");
    let sent_before = dialer.frames("publish").len();
    refuse("credential_refused", json!({"detail": "attestation_required"}));
    assert_eq!(send(&p, &inputs(), &mut request).unwrap(), Sent::Refused(Refusal::OwnFault(OwnFault::Attest { detail: Some("attestation_required".into()) })), "signed: the library's own");
    assert_eq!(dialer.frames("publish").len(), sent_before + 1, "a signed frame is never sent again for it");
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
    assert_eq!(landed(&p, &inputs(), &request, Base::Member(member.clone())).unwrap(), Verdict::Passed(Ack { member: member.clone(), at: ack.at, edition: None, via: AckVia::Twin, claim: false, supersede: vec![] }));
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
    assert_eq!((ack.member.to_string(), ack.claim), (format!("{edition}.1"), true), "the member, and the claim echoed");
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

// ── THE FAMILY (the Nelson way) ──────────────────────────────────────────

/// `A`, an alternative of `D`'s: a private draft of the person's holding
/// five words of its own, which `D` arranges by identity beside its own.
const A: &str = "1.0.1.0.9";
const A_TEXT: &str = " also";

/// The base fixture with `A` beside `D`: `D` arranges `E`'s words, its own
/// ten, `A`'s five by identity and the window onto `O`.
fn family_world() -> (World, Named) {
    let (mut w, named) = World::base();
    w.text(A, 1, A_TEXT);
    w.doc(A, false, ACCOUNT, vec![run(A, 1, 5)]);
    w.docs.get_mut(D).unwrap().runs = vec![run(E, 1, 19), run(D, 1, 10), run(A, 1, 5), run(O, 1, 5)];
    (w, named)
}

/// The family's inputs: `D` the rendering draft, `A` named `also`, the whole
/// of `D` the selection.
fn family_inputs() -> Inputs {
    Inputs { also: vec![a(A)], selection: vec![run(E, 1, 19), run(D, 1, 10), run(A, 1, 5), run(O, 1, 5)], readable_drafts: vec![a(D), a(N), a(A)], ..inputs() }
}

/// The family's confirmation: every row OFF, the window onto `O` (the fourth
/// run) kept private.
fn family_confirmed() -> Confirmed {
    let mut confirmed = Confirmed::default();
    confirmed.answers.insert(3, OriginAnswer::KeepPrivate);
    confirmed
}

/// THE FAMILY PUBLICATION: the panel excludes `A`'s run from the windows and
/// counts its passages as `inherited`; the request carries `also`, the
/// rendering draft's kept place for EVERY run of a named draft's identity —
/// its own ten and `A`'s five — and `A`'s own place for its run in
/// `also_places`, read off `A`'s image (skep #739), `A`'s run signed by
/// value, and the price counts both drafts' positions and, in its reads,
/// `A`'s run count where its list places it; the twin pre-check reads `A`'s
/// records too; the acknowledgment names `E.2`, the records are homed each
/// in its draft — `D`'s for its ten words, `A`'s for its five — the feed
/// row names the member, `D`, then `A`, and BOTH drafts are re-windowed in
/// the one commit: `D` at every named run, `A` at its own.
#[test]
fn a_family_publication_re_mints_the_also_drafts_words_counts_its_passages_and_homes_its_record_in_it() {
    let (world, _) = family_world();
    let (dialer, board, signer) = open(world);
    let tok = token();
    let p = publisher(&board, &tok, &signer);
    let inputs = family_inputs();
    let e = enumerate(&p, &inputs).unwrap();
    let panel = panel(&p, &inputs, &e).unwrap();
    assert_eq!(panel.windows.iter().map(|w| w.run).collect::<Vec<_>>(), vec![3], "O alone is a window: A's run is re-minted, not windowed");
    assert_eq!(panel.inherited, vec![Inherited { draft: a(A), passages: 1 }]);
    let scattered = Inputs { selection: vec![run(A, 1, 2), run(A, 3, 3), run(D, 1, 10), run(A, 1, 5)], ..inputs.clone() };
    assert_eq!(inherited(&scattered.also, &scattered.selection), vec![Inherited { draft: a(A), passages: 2 }], "consecutive runs of one origin count once");
    assert!(inherited(&self::inputs().also, &self::inputs().selection).is_empty(), "no `also`, no count");
    dialer.clear();
    let Built::Request(mut request) = build(&p, &inputs, &e, &panel, &family_confirmed()).unwrap() else { panic!("inert") };
    assert!(
        dialer.frames("find_links_ftt").iter().any(|f| f["q"]["home"][0]["start"].as_str() == Some(A) && !f["q"]["from"].is_null()),
        "the twin pre-check reads A's records for the run of its identity: {:?}",
        dialer.ops()
    );
    assert_eq!(request.also, vec![a(A)]);
    assert_eq!(request.runs, vec![run(E, 1, 19), run(D, 1, 10), run(A, 1, 5), run(O, 1, 5)]);
    assert_eq!(request.places, vec![None, Some(20), Some(30), None], "the rendering draft's kept place for every run of a named draft's identity — its own and A's — none for the trunk's words or the window");
    assert_eq!(request.also_places, vec![AlsoPlaces { draft: a(A), places: vec![None, None, Some(1), None] }], "A's own place for its run, off A's image; none at every other run");
    assert!(matches!(&request.pieces[2], Piece::Values(v) if v.len() == 5), "A's run signed by value: {:?}", request.pieces[2]);
    let frame = request.frame(None);
    assert_eq!(frame["also"], json!([A]), "the frame carries `also`");
    assert_eq!(frame["also_places"], json!([{"draft": A, "places": [null, null, {"subspace": "1", "ordinal": "1"}, null]}]), "and A's entry, in also's order");
    assert_eq!(request.price.values, 15, "both drafts' distinct positions");
    let mut unplaced = (*request).clone();
    unplaced.also_places[0].places = vec![None; 4];
    assert_eq!(request.priced(0, 4, &[1]).reads, unplaced.priced(0, 4, &[1]).reads + 4, "A's one run enters the reads' draft term where its list places it, once per run of the request");
    dialer.clear();
    let Sent::Acknowledged(ack) = send(&p, &inputs, &mut request).unwrap() else { panic!("refused") };
    assert_eq!((ack.member.to_string(), ack.via), (format!("{E}.2"), AckVia::Answer));
    let w = dialer.world();
    let records = |home: &str| w.links.iter().filter(|l| l.home == home && l.ty[0].0 == T_CORRESPONDENCE).map(|l| (l.from[0].clone(), l.to[0].clone())).collect::<Vec<_>>();
    assert_eq!(records(D).len(), 2, "D's earlier record, and the one this shot homed in D for its ten words");
    assert!(records(D).contains(&(ispan(D, 1, 10), ispan(E, 20, 10))), "{:?}", records(D));
    assert_eq!(records(A), vec![(ispan(A, 1, 5), ispan(E, 30, 5))], "A's record homed in A, `to` the member's fresh identity");
    let row = w.rows.iter().find(|r| r.at == ack.at).expect("the publish row");
    assert_eq!(row.docs[..3], [format!("{E}.2"), D.to_string(), A.to_string()], "the member, the rendering draft, then the also draft");
    assert_eq!(w.docs[D].runs, vec![run(E, 1, 34), run(O, 1, 5)], "D re-windowed at every named draft's run — its own ten and A's five — onto the fresh identity, I-adjacent to E's");
    assert_eq!(w.docs[A].runs, vec![run(E, 30, 5)], "A re-windowed at its own place in the same commit: its words the member's identity, no counterpart left");
}

/// Checks that a passage deleted since the panel is counted in no statement.
///
/// `A`'s run is deleted from `D` after the panel. The re-read states it
/// absent, and the statement's count reads what the draft still arranges of
/// the selection: no passage first written in `A` publishes (PUB-3.108).
#[test]
fn a_passage_deleted_since_the_panel_is_counted_in_no_statement() {
    let (world, _) = family_world();
    let (dialer, board, signer) = open(world);
    let tok = token();
    let p = publisher(&board, &tok, &signer);
    let inputs = family_inputs();
    let e = enumerate(&p, &inputs).unwrap();
    let first = panel(&p, &inputs, &e).unwrap();
    assert_eq!(first.inherited, vec![Inherited { draft: a(A), passages: 1 }], "the premise");
    dialer.world().docs.get_mut(D).unwrap().runs = vec![run(E, 1, 19), run(D, 1, 10), run(O, 1, 5)];
    let again = reread(&p, &inputs, &e, &first).unwrap();
    assert_eq!(again.restatement.expect("a difference").selection, vec![(2, Placement::Absent), (3, Placement::Whole { ordinal: 30 })]);
    assert_eq!(again.panel.inherited, vec![Inherited { draft: a(A), passages: 0 }]);
}

/// THE TWIN PRE-CHECK over the family: a run of `A`'s identity that a record
/// of `A` already names is re-composed by reference to the record's `to`, in
/// pieces where the record covers it in part, EVERY named draft's kept
/// place carried beside each piece at its offset — the rendering draft's in
/// `places`, `A`'s own in its `also_places` entry, the recorded piece's a
/// stray place each draft is re-windowed at through the record (skep #739)
/// — and the records are read per draft, `D`'s then `A`'s.
#[test]
fn the_twin_precheck_re_composes_an_also_drafts_recorded_words_by_reference() {
    let (mut world, _) = family_world();
    world.typed(A, vec![ispan(A, 2, 2)], vec![ispan(E, 40, 2)], T_CORRESPONDENCE);
    let (dialer, board, signer) = open(world);
    let tok = token();
    let p = publisher(&board, &tok, &signer);
    let a_list = [AlsoPlaces { draft: a(A), places: vec![None, Some(1)] }];
    let re = twin_precheck(&p, &family_inputs(), &[run(D, 1, 10), run(A, 1, 5)], &[Some(20), Some(30)], &[Some(20), Some(30)], &a_list).unwrap();
    assert_eq!(re.runs, vec![run(D, 1, 10), run(A, 1, 1), run(E, 40, 2), run(A, 4, 2)]);
    assert_eq!(re.places, vec![Some(20), Some(30), Some(31), Some(33)], "the rendering draft's place beside every piece of A's run, at the piece's offset");
    assert_eq!(re.also_places, vec![AlsoPlaces { draft: a(A), places: vec![None, Some(1), Some(2), Some(4)] }], "A's own place beside each piece of its run at the piece's offset, the recorded piece's a stray place");
    assert_eq!(re.draft_places, vec![Some(20), Some(30), Some(31), Some(33)]);
    assert_eq!(re.stray_records, vec![0, 0, 1, 0]);
    let homes: Vec<String> = dialer.frames("find_links_ftt").iter().filter_map(|f| f["q"]["home"][0]["start"].as_str().map(str::to_string)).collect();
    assert_eq!(homes, vec![D.to_string(), A.to_string()], "D's records read first, then A's");
    assert_eq!(re.frames, vec![("twin_precheck", 3)], "the two records reads and the one record's read_link");
}

/// A LOST ACKNOWLEDGMENT of a family publication is read back through the
/// records: the rendering draft's first where it re-inserted a run, each
/// `also` draft's for the runs of its own identity after it — and `A`'s
/// alone where the rendering draft re-inserted nothing.
#[test]
fn a_lost_family_acknowledgment_is_read_back_through_the_rendering_drafts_records_then_the_also_drafts() {
    let (world, _) = family_world();
    let (dialer, board, signer) = open(world);
    let tok = token();
    let p = publisher(&board, &tok, &signer);
    let inputs = family_inputs();
    let e = enumerate(&p, &inputs).unwrap();
    let panel = panel(&p, &inputs, &e).unwrap();
    let Built::Request(mut request) = build(&p, &inputs, &e, &panel, &family_confirmed()).unwrap() else { panic!("inert") };
    dialer.world().drop_acks = 2;
    dialer.clear();
    let Sent::Acknowledged(ack) = send(&p, &inputs, &mut request).unwrap() else { panic!("not landed") };
    assert_eq!((ack.member.to_string(), ack.via), (format!("{E}.2"), AckVia::Records));
    let homes: Vec<String> = dialer.frames("find_links_ftt").iter().filter_map(|f| f["q"]["home"][0]["start"].as_str().map(str::to_string)).collect();
    assert_eq!(homes.first().map(String::as_str), Some(D), "the rendering draft's records first: {homes:?}");
    // `A`'s run alone: the rendering draft re-inserts nothing, so its records
    // are not read and `A`'s name the member.
    let (world, _) = family_world();
    let (dialer, board, signer) = open(world);
    let p = publisher(&board, &tok, &signer);
    let only_a = Inputs { selection: vec![run(E, 1, 19), run(A, 1, 5)], ..family_inputs() };
    let e = enumerate(&p, &only_a).unwrap();
    let pn = self::panel(&p, &only_a, &e).unwrap();
    let Built::Request(mut request) = build(&p, &only_a, &e, &pn, &Confirmed::default()).unwrap() else { panic!("inert") };
    assert_eq!(request.runs, vec![run(E, 1, 19), run(A, 1, 5)]);
    dialer.world().drop_acks = 2;
    dialer.clear();
    let Sent::Acknowledged(ack) = send(&p, &only_a, &mut request).unwrap() else { panic!("not landed") };
    assert_eq!(ack.via, AckVia::Records);
    let homes: Vec<String> = dialer.frames("find_links_ftt").iter().filter_map(|f| f["q"]["home"][0]["start"].as_str().map(str::to_string)).collect();
    assert_eq!(homes, vec![A.to_string()], "A's records alone: {homes:?}");
}

/// `not_owner` naming a draft `also` names is the unowned-draft arm, as it
/// is for the rendering draft — the board's own ω per home: `A` a
/// sub-account's draft the person reads but does not own, imaged for its
/// places and refused at the write. A draft `also` names the person cannot
/// read at all is the enumeration's own fault — it is imaged for its kept
/// places as the rendering draft is — ahead of any frame.
#[test]
fn an_unowned_also_draft_is_the_unowned_draft_arm() {
    let (mut world, _) = family_world();
    world.docs.get_mut(A).unwrap().owner = "1.0.1.2".to_string();
    let (dialer, board, signer) = open(world);
    let tok = token();
    let p = publisher(&board, &tok, &signer);
    let inputs = family_inputs();
    let e = enumerate(&p, &inputs).unwrap();
    let panel = panel(&p, &inputs, &e).unwrap();
    let Built::Request(mut request) = build(&p, &inputs, &e, &panel, &family_confirmed()).unwrap() else { panic!("inert") };
    let before = dialer.world().position;
    assert_eq!(send(&p, &inputs, &mut request).unwrap(), Sent::Refused(Refusal::UnownedDraft { draft: a(A) }));
    assert_eq!(dialer.world().position, before, "nothing committed");
    let (mut world, _) = family_world();
    world.docs.get_mut(A).unwrap().owner = "1.0.2".to_string();
    let (dialer, board, signer) = open(world);
    let p = publisher(&board, &tok, &signer);
    assert_eq!(enumerate(&p, &inputs).unwrap_err(), Fault::Unreadable(a(A)), "an also draft withheld from the reader: the image read's fault");
    assert!(dialer.frames("publish").is_empty(), "no frame");
}

/// AN `also` DRAFT MOVED SINCE THE PANEL (skep #739): `A` re-arranges its
/// five words after the panel's reads, so at the re-read its image no
/// longer arranges its run whole — its `also_places` entry carries `None`
/// at that run (a place the client is not sure of is never guessed) and,
/// all `None`, is not sent; the re-read re-states nothing, the rendering
/// draft's placements being the diff's and `D` still arranging `A`'s run
/// whole; the request is sent and lands — `D` re-windowed at `A`'s run as
/// at its own, `A` LEFT AS IT STANDS, its words its own and a counterpart
/// through the record the shot homed in it, healed at its own next shot —
/// and the row names `A` for that record.
#[test]
fn an_also_draft_that_moved_its_run_since_the_panel_takes_no_place_and_is_left_as_it_stands() {
    let (world, _) = family_world();
    let (dialer, board, signer) = open(world);
    let tok = token();
    let p = publisher(&board, &tok, &signer);
    let inputs = family_inputs();
    let e = enumerate(&p, &inputs).unwrap();
    assert_eq!(e.also.len(), 1);
    assert_eq!((e.also[0].draft.to_string(), e.also[0].extent, e.also[0].image.len()), (A.to_string(), 5, 1), "A imaged whole at the panel");
    let panel = panel(&p, &inputs, &e).unwrap();
    // A's words swapped about: its last two, then its first three.
    dialer.world().docs.get_mut(A).unwrap().runs = vec![run(A, 4, 2), run(A, 1, 3)];
    let rr = reread(&p, &inputs, &e, &panel).unwrap();
    assert_eq!(rr.restatement, None, "the rendering draft's placements are the diff's; A's move is no difference");
    assert_eq!(rr.enumeration.also[0].image, vec![IRun { prefix: format!("{A}.0.1"), first: 4, width: 2, ordinal: 1 }, IRun { prefix: format!("{A}.0.1"), first: 1, width: 3, ordinal: 3 }], "A's image read again at the re-read");
    let Built::Request(mut request) = build(&p, &inputs, &rr.enumeration, &rr.panel, &family_confirmed()).unwrap() else { panic!("inert") };
    assert_eq!(request.places, vec![None, Some(20), Some(30), None], "D's places as before, A's run among them");
    assert_eq!(request.also_places, vec![AlsoPlaces { draft: a(A), places: vec![None; 4] }], "no place A is sure of: None at its run");
    assert!(request.frame(None).get("also_places").is_none(), "an all-None entry is not sent");
    dialer.clear();
    let Sent::Acknowledged(ack) = send(&p, &inputs, &mut request).unwrap() else { panic!("refused") };
    let frames = dialer.frames("publish");
    assert!(frames[0].get("also_places").is_none() && frames[0]["places"].is_array(), "{}", frames[0]);
    let w = dialer.world();
    assert_eq!(w.docs[D].runs, vec![run(E, 1, 34), run(O, 1, 5)], "D re-windowed at A's run as at its own");
    assert_eq!(w.docs[A].runs, vec![run(A, 4, 2), run(A, 1, 3)], "A left as it stands");
    assert!(w.links.iter().any(|l| l.home == A && l.ty[0].0 == T_CORRESPONDENCE && l.at == ack.at), "A's record homed in A all the same");
    let row = w.rows.iter().find(|r| r.at == ack.at).expect("the publish row");
    assert_eq!(row.docs[..3], [format!("{E}.2"), D.to_string(), A.to_string()], "A named for the record homed in it");
}

/// THE READS' DRAFT TERM IS THE BOARD's (`price_publication_reads` since
/// skep #739): the content run count of every draft a list places, summed
/// — the rendering draft where `places` carries a place, each `also` draft
/// where its `also_places` entry does — times the request's runs, and NONE
/// for a draft no list places. A family request placing the rendering
/// draft and one of two `also` drafts prices `(D's runs + A's runs) ×
/// runs`, the unplaced `B` adding nothing; one placing no draft has no
/// draft term; one placing `A` alone reads `A` alone. `also_places` is no
/// sixth list — bounded by `runs`, it needs no cap of its own — and the
/// staged bytes count a kept place per LIST that places a run (the
/// board's `placed_in`).
#[test]
fn the_reads_draft_term_sums_every_draft_a_list_places_as_the_boards_does() {
    const B: &str = "1.0.1.0.11";
    let (d, a_draft, b, term) = (a(D), a(A), a(B), a(E));
    let drafts = vec![d.clone(), a_draft.clone(), b.clone()];
    let runs = vec![run(D, 1, 10), run(A, 1, 5), run(B, 1, 7)];
    let also = |a_places: Vec<Option<u64>>, b_places: Vec<Option<u64>>| vec![AlsoPlaces { draft: a_draft.clone(), places: a_places }, AlsoPlaces { draft: b.clone(), places: b_places }];
    let none: [Option<u64>; 3] = [None; 3];
    let no_also = also(vec![None; 3], vec![None; 3]);
    let base = price::Shape { runs: &runs, drafts: &drafts, draft: Some(&d), term: &term, mint: false, claim: false, places: &none, also_places: &no_also, also_runs: &[1, 9], stray_records: &[0, 0, 0], entries: &[], retract: 0, originals: &[], read_with: 0, body_bytes: 0, homes: 3, draft_runs: 4 };
    assert_eq!(price::price(&base).reads, 0, "no list places a draft: no draft is read");
    let placed = [Some(20), Some(30), None];
    let family = also(vec![None, Some(1), None], vec![None; 3]);
    let priced = price::price(&price::Shape { places: &placed, also_places: &family, ..base.clone() });
    assert_eq!(priced.reads, (4 + 1) * 3, "D's four runs and A's one, once per run of the request; B, unplaced, adds none");
    assert_eq!(priced.lists, [3, 2, 0, 0, 0, 0], "places counts its two entries; also_places is no list of the price, the rider its sixth");
    let also_alone = price::price(&price::Shape { also_places: &family, ..base.clone() });
    assert_eq!(also_alone.reads, 3, "an also draft's re-window alone reads that draft");
    let b_too = also(vec![None, Some(1), None], vec![None, None, Some(4)]);
    assert_eq!(price::price(&price::Shape { places: &placed, also_places: &b_too, ..base.clone() }).reads, (4 + 1 + 9) * 3, "every draft a list places");
    let in_places_alone = price::price(&price::Shape { places: &placed, ..base.clone() });
    assert_eq!(priced.bytes, in_places_alone.bytes + price::KEPT_PLACE_BYTES, "A's run placed by two lists stages a kept place per list, one piece each");
}

/// `kept_place_moved` NAMING AN `also` DRAFT: `site.addr` is the draft that
/// no longer honours the place, and the race's key is read off the feed
/// under THAT draft — the newest row under `A`, not `D`'s — so the face
/// names whose write moved `A`'s run; naming `D`, the newest row under `D`;
/// `stray_place_unrecorded` names the draft alike.
#[test]
fn a_kept_place_moved_in_an_also_draft_names_it_and_reads_the_race_under_it() {
    let (world, _) = family_world();
    let (dialer, board, signer) = open(world);
    let tok = token();
    let p = publisher(&board, &tok, &signer);
    let inputs = family_inputs();
    let e = enumerate(&p, &inputs).unwrap();
    let panel = panel(&p, &inputs, &e).unwrap();
    let Built::Request(mut request) = build(&p, &inputs, &e, &panel, &family_confirmed()).unwrap() else { panic!("inert") };
    let refuse = |code: &str, site: Value| {
        dialer.world().refuse_next = Some(json!({"resp": "rejected", "code": code, "disposition": "permanent", "op": "publish", "site": site}));
    };
    dialer.world().rows.push(FeedRow { at: 998, op: "insert", docs: vec![D.to_string()], key: Some("cd".repeat(32).leak()) });
    dialer.world().rows.push(FeedRow { at: 999, op: "rearrange", docs: vec![A.to_string()], key: Some("ab".repeat(32).leak()) });
    refuse("kept_place_moved", json!({"index": 2, "addr": A}));
    let sent = send(&p, &inputs, &mut request).unwrap();
    assert_eq!(sent, Sent::Refused(Refusal::KeptPlaceMoved { index: 2, draft: a(A), race: Some(RaceKey { at: 999, key: Some("ab".repeat(32)), signed: false }) }), "A named, the race A's newest row");
    refuse("kept_place_moved", json!({"index": 1, "addr": D}));
    assert_eq!(send(&p, &inputs, &mut request).unwrap(), Sent::Refused(Refusal::KeptPlaceMoved { index: 1, draft: a(D), race: Some(RaceKey { at: 998, key: Some("cd".repeat(32)), signed: false }) }), "D named, the race D's newest row");
    refuse("stray_place_unrecorded", json!({"index": 2, "addr": A}));
    assert_eq!(send(&p, &inputs, &mut request).unwrap(), Sent::Refused(Refusal::OwnFault(OwnFault::StrayPlace { index: 2, draft: a(A) })));
    let before = dialer.world().position;
    assert_eq!(dialer.world().position, before, "nothing committed by a refusal");
}

// ── THE MERGE RECORDS (kept private) ─────────────────────────────────────

/// `J`, a merge journal of the person's, though no list names it one: a
/// private draft holding words of its own around two merge records' atoms,
/// and an atom of another kind last — "ab", a record, "cd", a record, a
/// note — at ordinals 1 to 7, each record's link homed in `J` beside it, as
/// the merge library writes it.
const J: &str = "1.0.1.0.11";

/// The merge record kind the journal's links are typed: the account's doc
/// 1, as the shell names it.
const MERGE_KIND: &str = "1.0.1.0.1";

/// A merge record's atom, the JSON the merge library appends to a journal.
fn record_atom(retries: u64) -> String {
    json!({"type": MERGE_RECORD_TYPE, "v": 1, "rules": "merge-rules-1", "doc": E, "base": format!("{E}.1"), "sides": [], "landed": null, "claims": [], "runs": [], "retries": retries, "gaps": [], "values": {}, "replaces": null, "by": "skep-client"}).to_string()
}

/// The base fixture with `J` beside `D`.
fn journal_world() -> World {
    let (mut w, _) = World::base();
    w.text(J, 1, "ab");
    w.atom(J, 3, &record_atom(0));
    w.text(J, 4, "cd");
    w.atom(J, 6, &record_atom(1));
    w.atom(J, 7, &json!({"type": "note", "text": "kept"}).to_string());
    w.doc(J, false, ACCOUNT, vec![run(J, 1, 7)]);
    for n in [3, 6] {
        w.typed(J, vec![ispan(J, n, 1)], vec![unit(&format!("{E}.1"))], MERGE_KIND);
    }
    w
}

/// `J` published as its own draft at the mint form, the whole of it held.
fn journal_inputs(selection: Vec<Run>) -> Inputs {
    Inputs { doc: None, mint: Some(a(ACCOUNT)), claim: true, base: None, draft: a(J), selection, notes: vec![], readable_drafts: vec![a(J)], published: vec![a(S), a(S2)], ..inputs() }
}

/// A MERGE RECORD IS NEVER PUBLISHED: `J` published at the mint form, the
/// whole of it held. The enumeration reads `J`'s atoms through their places,
/// one step after the image, and cuts the selection around the two records
/// — the note kept, a test of the atom and never a list of journals — the
/// region going by the cut; the panel counts the two under `J`; the request
/// carries no run and no kept place for either; the records' links, homed
/// in `J` from the atoms cut, are offered as no candidate; and after the
/// commit the member holds the words and the note alone, while `J` still
/// arranges both records by their own identity at their places, never
/// re-windowed there, and still homes both links.
#[test]
fn a_merge_record_is_never_published_and_its_journal_keeps_it_arranged() {
    let (dialer, board, signer) = open(journal_world());
    let tok = token();
    let p = publisher(&board, &tok, &signer);
    let inputs = journal_inputs(vec![run(J, 1, 7)]);
    let record_links: Vec<String> = dialer.world().links.iter().filter(|l| l.home == J).map(|l| l.addr.clone()).collect();
    assert_eq!(record_links, [format!("{J}.0.2.1"), format!("{J}.0.2.2")], "the premise: the records' links");
    let e = enumerate(&p, &inputs).unwrap();
    assert!(e.candidates.iter().all(|c| !record_links.contains(&c.link.to_string())), "no record's link a candidate: {:?}", e.candidates);
    let steps: Vec<&str> = e.frames.iter().map(|(s, _)| *s).collect();
    assert_eq!(&steps[..2], ["image", "merge_records"], "the atoms read after the image: {steps:?}");
    assert_eq!(e.merge_atoms, vec![vec![3, 6]], "the two records, never the note");
    assert_eq!(e.selection, vec![run(J, 1, 2), run(J, 4, 2), run(J, 7, 1)], "the selection as published");
    assert_eq!(e.region, vec![(1, 2), (4, 2), (7, 1)]);
    assert_eq!(e.pieces(0, &inputs.selection[0]), vec![(run(J, 1, 2), 1), (run(J, 4, 2), 4), (run(J, 7, 1), 7)]);
    let panel = panel(&p, &inputs, &e).unwrap();
    assert_eq!(panel.merge_records, vec![MergeRecords { draft: a(J), n: 2 }]);
    let Built::Request(mut request) = build(&p, &inputs, &e, &panel, &Confirmed::default()).unwrap() else { panic!("inert") };
    assert_eq!(request.runs, vec![run(J, 1, 2), run(J, 4, 2), run(J, 7, 1)], "no run of a record");
    assert_eq!(request.places, vec![Some(1), Some(4), Some(7)], "no kept place for one");
    let Sent::Acknowledged(ack) = send(&p, &inputs, &mut request).unwrap() else { panic!("sent") };
    let w = dialer.world();
    assert_eq!(w.docs[&ack.member.to_string()].runs.iter().map(|r| r.width).sum::<u64>(), 5, "the member holds the words and the note alone");
    let minted: Vec<&String> = w.atoms.iter().filter(|((doc, _), _)| doc != J).map(|(_, atom)| atom).collect();
    assert!(!minted.is_empty() && minted.iter().all(|atom| !is_merge_record(atom.as_bytes())), "the note re-minted, no record: {minted:?}");
    let positions = World::expand(&w.docs[J].runs);
    assert_eq!((positions[2].clone(), positions[5].clone()), ((a(J), 3), (a(J), 6)), "J arranges both records by their own identity at their places");
    assert!(positions.iter().enumerate().filter(|(k, _)| ![2, 5].contains(k)).all(|(_, (origin, _))| origin.to_string() != J), "the rest re-windowed onto the member's words: {positions:?}");
    let homed: Vec<&str> = w.links.iter().filter(|l| l.ty == [unit(MERGE_KIND)]).map(|l| l.home.as_str()).collect();
    assert_eq!(homed, [J, J], "the records' links homed in J alone, none re-homed in the member");
}

/// A SELECTION OF MERGE RECORDS ALONE IS REFUSED: every position held is a
/// record — `J`'s two, held as two runs — so the enumeration answers
/// `OnlyMergeRecords` naming the rendering draft after the atoms' read,
/// nothing further read and nothing sent.
#[test]
fn a_selection_of_merge_records_alone_is_refused_before_any_link_is_read() {
    let mut world = journal_world();
    world.docs.get_mut(J).unwrap().runs = vec![run(J, 3, 1), run(J, 6, 1)];
    let (dialer, board, signer) = open(world);
    let tok = token();
    let p = publisher(&board, &tok, &signer);
    let inputs = journal_inputs(vec![run(J, 3, 1), run(J, 6, 1)]);
    assert_eq!(enumerate(&p, &inputs).unwrap_err(), Fault::OnlyMergeRecords { draft: a(J) });
    assert!(dialer.frames("find_links_v").is_empty() && dialer.frames("publish").is_empty(), "nothing read past the atoms, nothing sent: {:?}", dialer.ops());
    assert_eq!(Fault::OnlyMergeRecords { draft: a(J) }.to_string(), format!("{J} holds only merge records, and they stay private — there is nothing in it to publish"));
}

/// Checks that the re-read refuses what is left where it is merge records.
///
/// `J`'s words are deleted after the panel, its two records left. What the
/// draft still arranges of the selection is merge records alone, so the
/// re-read answers `OnlyMergeRecords`, as the first enumeration does, and
/// no request of an empty member is ever built over it (PUB-3.108; the
/// merge record's decision 7).
#[test]
fn a_reread_over_merge_records_alone_is_refused() {
    let (dialer, board, signer) = open(journal_world());
    let tok = token();
    let p = publisher(&board, &tok, &signer);
    let inputs = journal_inputs(vec![run(J, 1, 7)]);
    let e = enumerate(&p, &inputs).unwrap();
    let first = panel(&p, &inputs, &e).unwrap();
    dialer.world().docs.get_mut(J).unwrap().runs = vec![run(J, 3, 1), run(J, 6, 1)];
    dialer.clear();
    assert_eq!(reread(&p, &inputs, &e, &first).unwrap_err(), Fault::OnlyMergeRecords { draft: a(J) });
    assert!(dialer.frames("find_links_v").is_empty() && dialer.frames("publish").is_empty(), "nothing read past the atoms, nothing sent: {:?}", dialer.ops());
}

/// A merge record of a draft `also` names is left out of both lists: `D`
/// arranges its own ten words and `J`'s seven positions by identity, `J`
/// named `also`. The records are cut out of `J`'s held run and counted
/// under `J`, its words one passage, and neither the rendering draft's
/// places nor `J`'s own list carries one.
#[test]
fn a_merge_record_of_an_also_draft_is_left_out_of_both_lists() {
    let mut world = journal_world();
    world.docs.get_mut(D).unwrap().runs = vec![run(D, 1, 10), run(J, 1, 7)];
    let (_, board, signer) = open(world);
    let tok = token();
    let p = publisher(&board, &tok, &signer);
    let inputs = Inputs { also: vec![a(J)], selection: vec![run(D, 1, 10), run(J, 1, 7)], readable_drafts: vec![a(D), a(N), a(J)], ..inputs() };
    let e = enumerate(&p, &inputs).unwrap();
    assert_eq!(e.merge_atoms, vec![vec![], vec![3, 6]]);
    let panel = panel(&p, &inputs, &e).unwrap();
    assert_eq!(panel.merge_records, vec![MergeRecords { draft: a(J), n: 2 }]);
    assert_eq!(panel.inherited, vec![Inherited { draft: a(J), passages: 1 }], "J's words one passage, the records cut from it");
    let Built::Request(request) = build(&p, &inputs, &e, &panel, &Confirmed::default()).unwrap() else { panic!("inert") };
    assert_eq!(request.runs, vec![run(D, 1, 10), run(J, 1, 2), run(J, 4, 2), run(J, 7, 1)]);
    assert_eq!(request.places, vec![Some(1), Some(11), Some(14), Some(17)], "the rendering draft's places: none at a record");
    assert_eq!(request.also_places, vec![AlsoPlaces { draft: a(J), places: vec![None, Some(1), Some(4), Some(7)] }], "J's own list: none at a record");
}

// ── THE DRAFT'S BASE ─────────────────────────────────────────────────────

/// `X` a memberless edition of the person's.
const X: &str = "1.0.1.0.30";

/// What `draft_base` answers.
type BaseRead = Result<DraftBase, Fault>;

/// The answer naming `base` as recorded, at the count `copied`.
fn recorded(base: &str, copied: u64) -> BaseRead {
    Ok(DraftBase::Recorded { base: a(base), copied })
}

/// The answer naming no base in the chain, and why.
fn unrecorded(why: Unrecorded) -> BaseRead {
    Ok(DraftBase::Unrecorded(why))
}

/// `draft_base` over `world`, `doc` and `draft`.
fn base_of(world: World, doc: &str, draft: &str) -> (Arc<Scripted>, BaseRead) {
    let (dialer, board, signer) = open(world);
    let tok = token();
    let p = publisher(&board, &tok, &signer);
    let base = draft_base(&p, &a(doc), &a(draft));
    (dialer, base)
}

/// THE BASE IS THE BOARD'S RECORD (B3-S10): a draft staged from `E.1`
/// answers the base its `stage` recorded and the count the copy took, off
/// ONE read of the draft after the trunk's — no feed, no link and no extent
/// read; staged from the memberless edition, the bare document at the count
/// it held, nothing. A trunk the board holds no record of is that fault,
/// ahead of the draft's.
#[test]
fn a_staged_drafts_base_is_the_boards_record_read_once() {
    let (mut world, _) = World::base();
    let e1 = format!("{E}.1");
    world.stage(D, &e1);
    let (dialer, base) = base_of(world, E, D);
    assert_eq!(base, recorded(&e1, 19), "the recorded base and the count the copy took");
    assert_eq!(dialer.ops(), ["doc_metadata", "doc_metadata"], "two reads: no feed, no link, no extent");
    let asked: Vec<Value> = dialer.frames("doc_metadata").iter().map(|f| f["doc"].clone()).collect();
    assert_eq!(asked, [json!(E), json!(D)], "the trunk, then the draft");
    // The memberless edition: the bare document is its own base.
    let (mut world, _) = World::base();
    world.doc(X, true, ACCOUNT, Vec::new());
    let d2 = "1.0.1.0.31";
    world.doc(d2, false, ACCOUNT, vec![run(d2, 1, 3)]);
    world.stage(d2, X);
    assert_eq!(base_of(world, X, d2).1, recorded(X, 0), "doc itself while the chain is empty");
    // A trunk the board holds no record of is that fault, ahead of the rest.
    let (mut world, _) = World::base();
    world.stage(D, &e1);
    assert_eq!(base_of(world, "1.0.1.0.40", D).1, Err(Fault::NoSuchDocument(a("1.0.1.0.40"))));
}

/// NO RECORD, NO BASE — AND WHY: a draft the board records no base for is
/// unrecorded with the reason its one answer gives, never the trunk's head:
/// `D` as the fixture holds it, never staged, naming no source, is
/// `NoRecord`, and so is a draft whose source lies in `E`'s own chain with
/// no base beside it; an alternative staged from `D`, which inherits none
/// and names `D` its source, is `FreeStanding`. A base the board names
/// without its count is an answer the client cannot read, never no base
/// (SP-14).
#[test]
fn a_draft_the_board_records_no_base_for_is_unrecorded_with_its_reason() {
    let (world, _) = World::base();
    let (dialer, none) = base_of(world, E, D);
    assert_eq!(none, unrecorded(Unrecorded::NoRecord), "no record: no base, never the head");
    assert_eq!(dialer.ops(), ["doc_metadata", "doc_metadata"], "the draft read once, nothing after it");
    let (mut world, _) = World::base();
    world.docs.get_mut(D).unwrap().source = Some(format!("{E}.1"));
    assert_eq!(base_of(world, E, D).1, unrecorded(Unrecorded::NoRecord), "a source in E's own chain and no base: never staged");
    let (mut world, _) = World::base();
    let alternative = "1.0.1.0.31";
    world.doc(alternative, false, ACCOUNT, vec![run(D, 1, 10)]);
    world.stage(alternative, D);
    assert_eq!(base_of(world, E, alternative).1, unrecorded(Unrecorded::FreeStanding), "an alternative of an unrecorded draft stands free");
    let (mut world, _) = World::base();
    world.docs.get_mut(D).unwrap().base = Some(format!("{E}.1"));
    let unread = base_of(world, E, D).1;
    assert!(matches!(unread, Err(Fault::Shape { ref op, .. }) if op == "doc_metadata"), "a base without its count: {unread:?}");
}

/// A BASE IN ANOTHER CHAIN IS NONE OF THIS ONE: a draft staged from the
/// public set `S` answers `S` asked of `S`'s chain and `OtherChain` asked of
/// `E`'s, and so does one staged from a document whose address only begins
/// with `E`'s text — never a member of `E`'s chain.
#[test]
fn a_recorded_base_outside_the_docs_chain_is_another_chains() {
    let (mut world, _) = World::base();
    world.stage(D, S);
    assert_eq!(base_of(world, E, D).1, unrecorded(Unrecorded::OtherChain), "S is no version of E");
    let (mut world, _) = World::base();
    world.stage(D, S);
    assert_eq!(base_of(world, S, D).1, recorded(S, 7), "S's own chain: the bare document at its count");
    let (mut world, _) = World::base();
    let near = format!("{E}1");
    world.doc(&near, true, ACCOUNT, Vec::new());
    world.stage(D, &near);
    assert_eq!(base_of(world, E, D).1, unrecorded(Unrecorded::OtherChain), "{near} is no member of {E}'s chain");
}

/// THE BASE MOVES WITH EACH PUBLICATION (B3-S10): `D` staged from `E.1`
/// reads the base the fixture's request carries, publishes `E.2` off it,
/// and read again stands on `E.2` at the member's whole count — the board's
/// move read, never the source its stage copied, which stays `E.1`. A draft
/// with no base whose first publication mints its edition stands on that
/// edition's first member.
#[test]
fn a_drafts_base_moves_to_the_member_each_publication_makes() {
    let (mut world, _) = World::base();
    let e1 = format!("{E}.1");
    world.stage(D, &e1);
    let (dialer, board, signer) = open(world);
    let tok = token();
    let p = publisher(&board, &tok, &signer);
    let (base, copied) = inputs().base.expect("the fixture's base");
    assert_eq!(draft_base(&p, &a(E), &a(D)), Ok(DraftBase::Recorded { base, copied }), "the stage's record is the request's base");
    let (_, _, mut request) = built(&dialer, &board, &tok, &signer, &switched(Some(S2)));
    let Sent::Acknowledged(ack) = send(&p, &inputs(), &mut request).unwrap() else { panic!("acknowledged") };
    let e2 = format!("{E}.2");
    assert_eq!(ack.member.to_string(), e2);
    let whole: u64 = dialer.world().docs[&e2].runs.iter().map(|r| r.width).sum();
    assert_eq!(draft_base(&p, &a(E), &a(D)), recorded(&e2, whole), "the member the publication made, at its whole count");
    assert_eq!(dialer.world().docs[D].source.as_deref(), Some(e1.as_str()), "the source the stage copied stays");
    // The mint form: a draft with no base stands on its edition's first member.
    let (mut world, _) = World::base();
    world.docs.get_mut(D).unwrap().runs = vec![run(D, 1, 10)];
    let (_, board, signer) = open(world);
    let p = publisher(&board, &tok, &signer);
    let minting = Inputs { doc: None, mint: Some(a(ACCOUNT)), base: None, selection: vec![run(D, 1, 10)], published: vec![a(S), a(S2)], ..inputs() };
    let e = enumerate(&p, &minting).unwrap();
    let panel = panel(&p, &minting, &e).unwrap();
    let Built::Request(mut request) = build(&p, &minting, &e, &panel, &Confirmed::default()).unwrap() else { panic!("inert") };
    let Sent::Acknowledged(ack) = send(&p, &minting, &mut request).unwrap() else { panic!("acknowledged") };
    let edition = ack.edition.clone().expect("the edition minted");
    assert_eq!(draft_base(&p, &edition, &a(D)), Ok(DraftBase::Recorded { base: ack.member.clone(), copied: 10 }), "its first publication's member");
}

// ── THE BASE's STANDING AND THE FAMILY LEFT BEHIND ───────────────────────

/// Checks that a trunk base's standing is typed off one probe (D4 (a)+(b′)).
///
/// The probe is `doc_metadata` of the trunk member after the base, and no
/// `/changes` read: a draft staged from the head `E.1` stands `AtHead`,
/// `E.2` absent; once a later publication lands `E.2` it stands `Behind`; a
/// draft staged from the memberless `X` stands `First`, its probe `X.1`, and
/// once `X.1` stands `SupersededFirst` naming it. A probe refused otherwise
/// is that fault, never the member's absence (SP-14).
#[test]
fn each_standing_is_typed_off_one_probe_of_the_next_trunk_member() {
    let (e1, e2) = (format!("{E}.1"), format!("{E}.2"));
    let (mut world, _) = World::base();
    world.stage(D, &e1);
    let (dialer, board, signer) = open(world);
    let tok = token();
    let p = publisher(&board, &tok, &signer);
    let probed = |dialer: &Arc<Scripted>| -> Vec<Value> { dialer.frames("doc_metadata").iter().map(|f| f["doc"].clone()).collect() };
    assert_eq!(standing(&p, &a(E), &a(&e1)), Ok(Standing::AtHead), "E.2 is not registered: E.1 is the head");
    assert_eq!((dialer.ops(), probed(&dialer)), (vec!["doc_metadata".to_string()], vec![json!(e2)]), "ONE probe, the trunk member after the base's, and no feed read");
    let (_, _, mut request) = built(&dialer, &board, &tok, &signer, &switched(Some(S2)));
    let Sent::Acknowledged(ack) = send(&p, &inputs(), &mut request).unwrap() else { panic!("acknowledged") };
    assert_eq!(ack.member.to_string(), e2, "a later publication lands E.2");
    dialer.clear();
    assert_eq!(standing(&p, &a(E), &a(&e1)), Ok(Standing::Behind), "a trunk member follows E.1");
    assert_eq!((dialer.ops(), probed(&dialer)), (vec!["doc_metadata".to_string()], vec![json!(e2)]));
    // The bare document: the first while its chain is empty, superseded
    // once its first member stands.
    let (mut world, _) = World::base();
    world.doc(X, true, ACCOUNT, Vec::new());
    let (dialer, board, signer) = open(world);
    let p = publisher(&board, &tok, &signer);
    let x1 = format!("{X}.1");
    assert_eq!(standing(&p, &a(X), &a(X)), Ok(Standing::First), "X's chain is empty");
    assert_eq!(probed(&dialer), [json!(x1)], "the bare document's probe is its first member");
    dialer.world().doc(&x1, true, ACCOUNT, Vec::new());
    assert_eq!(standing(&p, &a(X), &a(X)), Ok(Standing::SupersededFirst { first: a(&x1) }), "version 1 published since");
    assert!(dialer.ops().iter().all(|op| op == "doc_metadata"), "no feed read: {:?}", dialer.ops());
    dialer.world().history_busy = SCAN_BUSY_REISSUES as usize + 1;
    assert_eq!(standing(&p, &a(X), &a(X)), Err(Fault::Busy), "a refused probe is that fault, never an absent member");
}

/// THE LANDED WALK FROM THE BARE DOCUMENT (B3-S10's draft begun before
/// version 1): two drafts are staged from the memberless `X`, each holding
/// `X`'s three positions by reference and words of its own. The first's
/// shot births `X.1`, and its landed test from the walk finds it there — the
/// chain was empty at the send, the shot made its first member. The second's
/// base is still the bare document, so its shot lands as `X.1`'s DAUGHTER,
/// `X.1.1`, and its landed test from the walk finds it: the first member
/// probed and passed over (it holds the first draft's words, not the
/// second's), then the first member's daughters in order — never `X.2`, the
/// trunk's second member, which no bare-based shot mints.
#[test]
fn the_landed_walk_from_a_bare_base_finds_the_first_member_then_its_daughters_and_never_the_second_member() {
    let (first_draft, second_draft) = ("1.0.1.0.37", "1.0.1.0.38");
    let (x1, x11, x2) = (format!("{X}.1"), format!("{X}.1.1"), format!("{X}.2"));
    let (mut world, _) = World::base();
    world.text(X, 1, "xyz");
    world.doc(X, true, ACCOUNT, vec![run(X, 1, 3)]);
    world.text(first_draft, 1, "ab");
    world.doc(first_draft, false, ACCOUNT, vec![run(X, 1, 3), run(first_draft, 1, 2)]);
    world.text(second_draft, 1, "wxyz");
    world.doc(second_draft, false, ACCOUNT, vec![run(X, 1, 3), run(second_draft, 1, 4)]);
    for d in [first_draft, second_draft] {
        world.stage(d, X);
    }
    let (dialer, board, signer) = open(world);
    let tok = token();
    let p = publisher(&board, &tok, &signer);
    let bare = |draft: &str, selection: Vec<Run>| Inputs { doc: Some(a(X)), base: Some((a(X), 3)), draft: a(draft), also: Vec::new(), selection, notes: Vec::new(), readable_drafts: vec![a(draft)], published: vec![a(X)], ..inputs() };
    let request_of = |inputs: &Inputs| -> Request {
        let e = enumerate(&p, inputs).expect("enumerated");
        let panel = panel(&p, inputs, &e).expect("the panel");
        let Built::Request(request) = build(&p, inputs, &e, &panel, &Confirmed::default()).expect("built") else { panic!("inert") };
        *request
    };
    // The chain empty at the send: the shot births `X.1`, and the walk
    // finds it at the first member.
    let first = bare(first_draft, vec![run(X, 1, 3), run(first_draft, 1, 2)]);
    let mut request = request_of(&first);
    let Sent::Acknowledged(ack) = send(&p, &first, &mut request).unwrap() else { panic!("acknowledged") };
    assert_eq!(ack.member.to_string(), x1, "the birth version");
    dialer.clear();
    assert!(matches!(landed(&p, &first, &request, Base::Walk).unwrap(), Verdict::Passed(Ack { ref member, via: AckVia::Walk, .. }) if member.to_string() == x1), "the walk from the bare document finds the first member the shot made");
    // The chain opened since: the second draft's shot lands as `X.1`'s
    // daughter, and the walk passes over `X.1` to find it there.
    let second = bare(second_draft, vec![run(X, 1, 3), run(second_draft, 1, 4)]);
    let mut request = request_of(&second);
    let Sent::Acknowledged(ack) = send(&p, &second, &mut request).unwrap() else { panic!("acknowledged") };
    assert_eq!(ack.member.to_string(), x11, "beside version 1, as its daughter");
    dialer.clear();
    let verdict = landed(&p, &second, &request, Base::Walk).unwrap();
    assert!(matches!(verdict, Verdict::Passed(Ack { ref member, via: AckVia::Walk, .. }) if member.to_string() == x11), "the walk finds the daughter: {verdict:?}");
    let probed: Vec<String> = dialer.frames("doc_metadata").iter().filter_map(|f| f["doc"].as_str().map(str::to_string)).collect();
    assert_eq!(probed.first(), Some(&x1), "the first member first: {probed:?}");
    assert!(probed.len() > 1 && probed[1..].iter().all(|d| *d == x11), "then its first daughter, and nothing else: {probed:?}");
    assert!(dialer.frames("image").iter().all(|f| f["d"].as_str() != Some(x2.as_str())) && !probed.contains(&x2), "never the trunk's second member");
    // Nothing of the second draft's landed: the walk ends at the first
    // absent daughter, `X.1.2`, not found.
    let mut other = request.clone();
    other.runs[1] = run(second_draft, 2, 3);
    assert_eq!(landed(&p, &second, &other, Base::Walk).unwrap(), Verdict::NotFound);
}

/// Checks that a base under a trunk member stands behind off its address.
///
/// Two drafts are staged from the memberless `X` (skep #807; PUB-2.37,
/// PUB-2.53). The first's shot births `X.1`; the second's lands `X.1.1`,
/// version 1's daughter, and the board moves the second draft's recorded
/// base there, `X.2` absent. That base stands `Behind` with no frame sent,
/// never `AtHead` off a probe of `X.2`, and so does a deeper base,
/// `X.1.1.1`. The draft's next shot, a word of its own added, lands
/// `X.1.1.1`, the base's own daughter, as its standing told, and mints no
/// `X.2`; the landed walk from that base finds it among the base's
/// daughters, the trunk's next member never read. Once a trunk member `X.2`
/// stands, the base still stands `Behind` off its address alone.
#[test]
fn a_base_under_a_trunk_member_stands_behind_off_its_address_and_its_shot_lands_its_daughter() {
    let (first_draft, second_draft) = ("1.0.1.0.37", "1.0.1.0.38");
    let (x1, x11, x111, x2) = (format!("{X}.1"), format!("{X}.1.1"), format!("{X}.1.1.1"), format!("{X}.2"));
    let (mut world, _) = World::base();
    world.text(X, 1, "xyz");
    world.doc(X, true, ACCOUNT, vec![run(X, 1, 3)]);
    world.text(first_draft, 1, "ab");
    world.doc(first_draft, false, ACCOUNT, vec![run(X, 1, 3), run(first_draft, 1, 2)]);
    world.text(second_draft, 1, "wxyz");
    world.doc(second_draft, false, ACCOUNT, vec![run(X, 1, 3), run(second_draft, 1, 4)]);
    for d in [first_draft, second_draft] {
        world.stage(d, X);
    }
    let (dialer, board, signer) = open(world);
    let tok = token();
    let p = publisher(&board, &tok, &signer);
    // One shot of the whole draft off `base`: its inputs, its request and
    // the acknowledgment.
    let shot = |draft: &str, base: (Address, u64)| -> (Inputs, Request, Ack) {
        let selection = dialer.world().docs[draft].runs.clone();
        let inputs = Inputs { doc: Some(a(X)), base: Some(base), draft: a(draft), also: Vec::new(), selection, notes: Vec::new(), readable_drafts: vec![a(draft)], published: vec![a(X)], ..inputs() };
        let e = enumerate(&p, &inputs).expect("enumerated");
        let panel = panel(&p, &inputs, &e).expect("the panel");
        let Built::Request(mut request) = build(&p, &inputs, &e, &panel, &Confirmed::default()).expect("built") else { panic!("inert") };
        let Sent::Acknowledged(ack) = send(&p, &inputs, &mut request).expect("sent") else { panic!("acknowledged") };
        (inputs, *request, ack)
    };
    assert_eq!(shot(first_draft, (a(X), 3)).2.member.to_string(), x1, "the birth version");
    assert_eq!(shot(second_draft, (a(X), 3)).2.member.to_string(), x11, "beside version 1, as its daughter");
    assert_eq!(draft_base(&p, &a(X), &a(second_draft)), recorded(&x11, 7), "the board moved the second draft's base to the daughter it made");
    dialer.clear();
    assert_eq!(standing(&p, &a(X), &a(&x11)), Ok(Standing::Behind), "a daughter is never the head, X.2 absent or not");
    assert_eq!(standing(&p, &a(X), &a(&x111)), Ok(Standing::Behind), "nor is a member under a daughter");
    assert!(dialer.ops().is_empty(), "typed off the address, no frame sent: {:?}", dialer.ops());
    // The next shot off the daughter: a word of the draft's own added.
    {
        let mut w = dialer.world();
        w.text(second_draft, 5, "!");
        w.docs.get_mut(second_draft).unwrap().runs.push(run(second_draft, 5, 1));
    }
    let (third, request, ack) = shot(second_draft, (a(&x11), 7));
    assert_eq!(ack.member.to_string(), x111, "the base's own daughter, as its standing told");
    assert!(!dialer.world().docs.contains_key(&x2), "no trunk member X.2 minted");
    assert_eq!(dialer.world().trunk_head.get(X), Some(&x1), "the head did not move");
    dialer.clear();
    let verdict = landed(&p, &third, &request, Base::Walk).unwrap();
    assert!(matches!(verdict, Verdict::Passed(Ack { ref member, via: AckVia::Walk, .. }) if member.to_string() == x111), "the walk finds the base's daughter: {verdict:?}");
    let probed: Vec<String> = dialer.frames("doc_metadata").iter().filter_map(|f| f["doc"].as_str().map(str::to_string)).collect();
    assert_eq!(probed.first(), Some(&x111), "the base's first daughter first: {probed:?}");
    assert!(!probed.contains(&x2) && dialer.frames("image").iter().all(|f| f["d"].as_str() != Some(x2.as_str())), "never the trunk's next member: {probed:?}");
    // A later trunk member standing moves nothing: still behind, unread.
    dialer.world().doc(&x2, true, ACCOUNT, Vec::new());
    dialer.clear();
    assert_eq!(standing(&p, &a(X), &a(&x11)), Ok(Standing::Behind), "a daughter, and X.2 stands");
    assert!(dialer.ops().is_empty(), "no frame sent: {:?}", dialer.ops());
}

/// THE FAMILY LEFT BEHIND (skep #744): every draft `also` names, in its
/// order, then — where the publication becomes the head — every other
/// draft of the person's own list whose recorded base is the rendering
/// draft's, in the list's order, off one `doc_metadata` each: at `E.1`,
/// `AtHead`, `Q` staged from `E.1` is left behind, `N` with no base and `R`
/// on another chain's base are not, `G` the board does not hold is passed
/// over, and the rendering draft and `A`, which `also` names, are never
/// read; at `Behind` the publication lands a daughter and `also` alone is
/// answered, nothing read; at the bare document, `First`, a draft staged
/// from it is left behind; at the mint form nothing is. A read refused
/// otherwise is that fault.
#[test]
fn the_family_left_behind_is_also_then_the_drafts_on_this_base_where_the_publication_heads() {
    let e1 = format!("{E}.1");
    let (q, r, g) = ("1.0.1.0.32", "1.0.1.0.33", "1.0.1.0.34");
    let (mut world, _) = family_world();
    world.stage(D, &e1);
    world.stage(A, &e1);
    world.doc(q, false, ACCOUNT, vec![run(E, 1, 19)]);
    world.stage(q, &e1);
    world.doc(r, false, ACCOUNT, vec![run(S, 1, 7)]);
    world.stage(r, S);
    let (dialer, board, signer) = open(world);
    let tok = token();
    let p = publisher(&board, &tok, &signer);
    let inputs = family_inputs();
    let own = [a(D), a(N), a(q), a(A), a(r), a(g)];
    assert_eq!(left_behind(&p, &inputs, &Standing::AtHead, &own), Ok(vec![a(A), a(q)]), "`also` first, then the drafts on E.1 in the list's order");
    let asked: Vec<Value> = dialer.frames("doc_metadata").iter().map(|f| f["doc"].clone()).collect();
    assert_eq!(asked, [json!(N), json!(q), json!(r), json!(g)], "one read per other draft, never the rendering draft's or one `also` names");
    assert_eq!(dialer.ops().len(), 4, "the reads alone: {:?}", dialer.ops());
    dialer.clear();
    assert_eq!(left_behind(&p, &inputs, &Standing::Behind, &own), Ok(vec![a(A)]), "the head does not move: `also` alone");
    assert!(dialer.ops().is_empty(), "nothing read at Behind: {:?}", dialer.ops());
    let minting = Inputs { doc: None, mint: Some(a(ACCOUNT)), base: None, ..family_inputs() };
    assert_eq!(left_behind(&p, &minting, &Standing::AtHead, &own), Ok(Vec::new()), "the mint form has no base to leave a draft on");
    assert_eq!(left_behind(&p, &inputs, &Standing::AtHead, &[a(OTHER)]), Err(Fault::Unreadable(a(OTHER))), "a refused read is that fault, never a draft passed over");
    // The bare document: its first member leaves the drafts staged from it.
    let (first, second) = ("1.0.1.0.35", "1.0.1.0.36");
    let (mut world, _) = World::base();
    world.doc(X, true, ACCOUNT, Vec::new());
    for d in [first, second] {
        world.doc(d, false, ACCOUNT, vec![run(d, 1, 3)]);
        world.stage(d, X);
    }
    let (_, board, signer) = open(world);
    let p = publisher(&board, &tok, &signer);
    let bare = Inputs { doc: Some(a(X)), base: Some((a(X), 0)), draft: a(first), also: Vec::new(), ..inputs };
    assert_eq!(left_behind(&p, &bare, &Standing::First, &[a(first), a(second)]), Ok(vec![a(second)]), "the first version leaves the bare document's other drafts behind");
}

// ── THE PRIVATE RIDER (the link-sets design §5.7 (vi′); skep #894) ───────

/// THE RIDER COMPOSED FROM THE COPY: a held removal's mark of the formatting
/// types with an accept claim in the draft — `orig` the claim's `old`, the
/// mark its `new` — composes one `originals` entry, `old` the original, no
/// rest (the copy covers every word), paired with the mark; the frame
/// carries `originals: [{"old": …}]` and no `rest`; the price counts the
/// rider's list and its retraction; a citation's held removal with the same
/// claim shape composes NO entry — notes, citations and typed links keep
/// their originals — and the mark of another type is no removal's original;
/// the send is acknowledged and the world ends the original at its home,
/// retracted beside the copy, the citation's original standing.
#[test]
fn a_held_removals_original_rides_the_rider_and_ends_with_its_copy() {
    let (mut world, named) = World::base();
    let e1 = format!("{E}.1");
    // The strong mark's original in D, claimed onto `mpub`; a citation's
    // held removal with its original in N, claimed onto its copy.
    let orig = world.typed(D, vec![], vec![ispan(E, 5, 5)], T_STRONG);
    world.claim(D, &orig, &named.mpub);
    let cpub = world.typed(&e1, vec![ispan(E, 1, 3)], vec![ispan(N, 1, 2)], T_CITATION);
    world.typed(D, vec![], vec![unit(&cpub)], T_HELD_REMOVAL);
    let orig_c = world.typed(N, vec![ispan(E, 1, 3)], vec![ispan(N, 1, 2)], T_CITATION);
    world.claim(N, &orig_c, &cpub);
    let (dialer, board, signer) = open(world);
    let tok = token();
    let (_, panel, mut request) = built(&dialer, &board, &tok, &signer, &switched(None));
    let removal = |mark: &str| panel.formatting.removals.iter().find(|r| r.mark.to_string() == mark).unwrap_or_else(|| panic!("{mark}'s removal"));
    assert_eq!(removal(&named.mpub).original.as_ref().map(|o| (o.link.to_string(), o.rest.clone())), Some((orig.clone(), vec![])), "the strong mark's original, every word covered");
    assert_eq!(removal(&cpub).original, None, "a citation's held removal composes no original");
    assert_eq!(removal(&named.mpub3).original, None, "a mark with no accept claim has no original");
    assert_eq!(request.retract.len(), 3, "mpub, cpub and mpub3: {:?}", request.retract);
    assert_eq!(request.originals.len(), 1);
    assert_eq!((request.originals[0].old.to_string(), request.originals[0].rest.clone(), request.originals[0].marks.clone()), (orig.clone(), vec![], vec![a(&named.mpub)]));
    assert_eq!(request.originals[0].ty, vec![LinkSpan { start: T_STRONG.to_string(), width: "0.0.0.0.0.0.0.0.0.1".to_string() }], "the original's stored type, for the price");
    let frame = request.frame(None);
    assert_eq!(frame["originals"], json!([{"old": orig}]), "the rider, no rest spelled");
    assert_eq!(request.price.lists[5], 1, "the rider's list counted");
    let p = publisher(&board, &tok, &signer);
    let sent = send(&p, &inputs(), &mut request).unwrap();
    assert!(matches!(sent, Sent::Acknowledged(_)), "{sent:?}");
    let w = dialer.world();
    assert!(w.links.iter().find(|l| l.addr == orig).unwrap().retracted, "the original ended at its home");
    assert!(w.links.iter().any(|l| l.home == D && l.ty[0].0 == T_RETRACTION && l.to[0].0 == orig), "its retraction tuple in D");
    assert!(w.links.iter().find(|l| l.addr == named.mpub).unwrap().retracted, "the copy retracted beside it");
    assert!(!w.links.iter().find(|l| l.addr == orig_c).unwrap().retracted, "the citation's original stands");
}

/// THE REST, COMPUTED BY IDENTITY: an original over `E`'s words 10–15 whose
/// copy covers 10–14 composes its rest, 15, as one I-span; one over a
/// record's draft words `D` 20–23 whose copy lies on the published words the
/// record maps them to, `E` 16–17, composes its rest on the DRAFT's chain,
/// `D` 22–23, through the record; the frame spells each rest in the I-span
/// form; the price carries the fresh marks; and the world writes each fresh
/// mark of the original's type over exactly the rest, in the end the
/// original holds it in, ahead of the original's retraction. The selection
/// — `E`'s words 1–12 and 16–17, the draft's own and the window — holds
/// the copies' words and leaves the rests' out, so each original is folded
/// under its copy on the selection and offered nowhere.
#[test]
fn a_cut_copys_rest_is_composed_by_identity_through_the_records_and_kept_by_a_fresh_mark() {
    let (mut world, _named) = World::base();
    let e1 = format!("{E}.1");
    let heading = world.typed(D, vec![], vec![ispan(E, 10, 6)], T_HEADING);
    let hpub = world.typed(&e1, vec![], vec![ispan(E, 10, 5)], T_HEADING);
    world.typed(D, vec![], vec![unit(&hpub)], T_HELD_REMOVAL);
    world.claim(D, &heading, &hpub);
    // On the record's draft words (D 20–23 → E 16–19): the original on D's
    // chain, its copy on E's.
    let emph = world.typed(N, vec![], vec![ispan(D, 20, 4)], T_EMPHASIS);
    let epub = world.typed(&e1, vec![], vec![ispan(E, 16, 2)], T_EMPHASIS);
    world.typed(D, vec![], vec![unit(&epub)], T_HELD_REMOVAL);
    world.claim(N, &emph, &epub);
    let (dialer, board, signer) = open(world);
    let tok = token();
    let p = publisher(&board, &tok, &signer);
    // The selection publishes E's words 1–12 and 16–17 and the draft's own:
    // the copies' words, the rests left out.
    let mut inputs = inputs();
    inputs.selection = vec![run(E, 1, 12), run(E, 16, 2), run(D, 1, 10), run(O, 1, 5)];
    let e = enumerate(&p, &inputs).expect("enumerated");
    let panel = panel(&p, &inputs, &e).expect("the panel");
    // The window onto `O` is the selection's fourth run here.
    let mut confirmed = switched(None);
    confirmed.answers = BTreeMap::from([(3, OriginAnswer::KeepPrivate)]);
    let built = build(&p, &inputs, &e, &panel, &confirmed).expect("built");
    let Built::Request(mut request) = built else { panic!("{built:?}") };
    let entry = |old: &str| request.originals.iter().find(|o| o.old.to_string() == old).unwrap_or_else(|| panic!("{old}'s entry: {:?}", request.originals));
    assert_eq!(entry(&heading).rest, vec![ISpan { chain: format!("{E}.0.1"), first: 15, width: 1 }], "the word the copy left out");
    assert_eq!(entry(&emph).rest, vec![ISpan { chain: format!("{D}.0.1"), first: 22, width: 2 }], "on the draft's chain, through the record");
    let frame = request.frame(None);
    let originals = frame["originals"].as_array().unwrap();
    let spelled = |old: &str| originals.iter().find(|o| o["old"] == old).unwrap()["rest"].clone();
    assert_eq!(spelled(&heading), json!([{"start": format!("{E}.0.1.15"), "width": "1"}]));
    assert_eq!(spelled(&emph), json!([{"start": format!("{D}.0.1.22"), "width": "2"}]));
    let without = Request { originals: Vec::new(), ..(*request).clone() }.priced(0, 0, &[]);
    assert!(request.priced(0, 0, &[]).bytes > without.bytes + 2 * price::RETRACTION_BYTES, "the fresh marks priced beside the retractions");
    let sent = send(&p, &inputs, &mut request).unwrap();
    assert!(matches!(sent, Sent::Acknowledged(_)), "{sent:?}");
    let w = dialer.world();
    let fresh = |home: &str, ty: &str, span: (String, String)| w.links.iter().any(|l| l.home == home && !l.retracted && l.ty[0].0 == ty && l.from.is_empty() && l.to == vec![span.clone()]);
    assert!(fresh(D, T_HEADING, ispan(E, 15, 1)), "the heading's rest keeps a fresh heading in D");
    assert!(fresh(N, T_EMPHASIS, ispan(D, 22, 2)), "the emphasis's rest keeps a fresh emphasis in N, on the draft's words");
    for (original, home, ty, rest) in [(&heading, D, T_HEADING, ispan(E, 15, 1)), (&emph, N, T_EMPHASIS, ispan(D, 22, 2))] {
        assert!(w.links.iter().find(|l| l.addr == *original).unwrap().retracted, "{original} ended");
        let mark = w.links.iter().position(|l| l.home == home && l.ty[0].0 == ty && l.to == vec![rest.clone()]).unwrap();
        let retraction = w.links.iter().position(|l| l.home == home && l.ty[0].0 == T_RETRACTION && l.to.first().is_some_and(|s| s.0 == *original)).unwrap();
        assert!(mark < retraction, "{original}: the fresh mark ahead of the retraction");
    }
}

/// THE ONE RE-SIGN DROPS THE ORIGINAL WITH ITS COPY: `mpub3`'s original
/// rides the rider paired with `mpub3`; `mpub3` retracted meanwhile — a
/// skipped `retract` entry — the board's `attestation_invalid:signature`
/// makes the one re-sign drop the entry AND the original paired with it, so
/// the second frame carries neither and the publication is acknowledged;
/// an original paired with two marks rides while either does.
#[test]
fn a_skipped_copys_original_is_dropped_with_it_at_the_one_re_sign() {
    let (mut world, named) = World::base();
    let orig3 = world.typed(D, vec![], vec![ispan(E, 15, 5)], T_HEADING);
    world.claim(D, &orig3, &named.mpub3);
    let (dialer, board, signer) = open(world);
    let tok = token();
    let (_, _, mut request) = built(&dialer, &board, &tok, &signer, &switched(None));
    assert_eq!(request.originals.iter().map(|o| (o.old.to_string(), o.marks.clone())).collect::<Vec<_>>(), vec![(orig3.clone(), vec![a(&named.mpub3)])]);
    let p = publisher(&board, &tok, &signer);
    dialer.world().retract(&format!("{E}.1"), &named.mpub3);
    dialer.world().refuse_next = Some(json!({"resp": "rejected", "code": "credential_refused", "detail": "attestation_invalid:signature", "disposition": "permanent", "op": "publish"}));
    dialer.clear();
    let sent = send(&p, &inputs(), &mut request).unwrap();
    assert!(matches!(sent, Sent::Acknowledged(_)), "{sent:?}");
    assert_eq!(request.retract, vec![a(&named.mpub)], "the retracted mark's entry dropped");
    assert!(request.originals.is_empty(), "and its original with it");
    let frames = dialer.frames("publish");
    assert_eq!(frames.len(), 2);
    assert_eq!(frames[0]["originals"], json!([{"old": orig3}]), "the first frame carried the rider");
    assert!(frames[1].get("originals").is_none(), "the second carries neither the entry nor the original: {}", frames[1]);
    assert!(!dialer.world().links.iter().find(|l| l.addr == orig3).unwrap().retracted, "the original stands: the other device's take-off is where it ends");
    // Paired with two marks: dropped only with the last.
    let mut two = Request { originals: vec![OriginalEntry { old: a(&orig3), rest: vec![], ty: vec![], marks: vec![a(&named.mpub), a(&named.mpub3)] }], ..request.clone() };
    two.retract = vec![a(&named.mpub), a(&named.mpub3)];
    two.without(&[1], &[], &[]);
    assert_eq!(two.originals.len(), 1, "one mark still rides");
    two.without(&[0], &[], &[]);
    assert!(two.originals.is_empty(), "none does");
}
