//! The scripted board, and the ground the area suites below stand on.
//!
//! `World` is the board as a test writes it — each document's arrangement
//! and values, the links, the claims, the feed — and `Scripted` the
//! `Dialer` that answers from it, keeping every frame it served, so a test
//! pins what the module reads and writes, in what order, and what it makes
//! of each answer, with no daemon. Beside them stand the names the areas
//! share: the documents and the account the tests run over, the sign-in,
//! the race's inputs, the draft landing's world, inputs and landing, the
//! landing into `S` and the record it appends, a correspondence record
//! planted in `S`, and a record filed in a journal. Each area's own helpers
//! stand in its file.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};
use skep_address::Address;
use skep_identity::{
    entry_body_publication, entry_body_publish, entry_frame, unit_span, DepositHome,
    DepositKind, DepositRow, DepositSlot, DocTerm, Fingerprint, PublicKey, ShotBase,
    ShotSegmentPiece, SlotElement,
};
use skep_febe::MAX_REQ_ID_BYTES;
use skep_signature::HybridSigner;

use super::{handshake, Session, Site};
use crate::address::parse_address;
use crate::board::{
    acked_addr, acked_at, frames, guest_closed, Answer, AtAnswer, Board, Scope, HEAD_MEMBER_1,
    T_SUPERSEDES,
};
use crate::dial::{
    DialError, Dialer, Headers, Request, RequestHead, Response, StreamedResponse,
};
use crate::halt::Halt;
use crate::merge::land::Stem;
use crate::merge::reads::{session_ended, OnEnd, MAX_SIDES};
use crate::merge::*;
use crate::origin::Origin;
use crate::publication::OriginAnswer;
use crate::sign::Signer;

mod compose;
mod fences;
mod journals;
mod land;
mod land_again;
mod land_begun;
mod land_refusals;
mod records;
mod session_end;
mod undo;
mod windows;
mod withdraw;

const TOKEN: &str = "9f3a6c21d4b8e07a5c1b2d4e6f708192";
/// The merger's account and its doc 1.
const ACCOUNT: &str = "1.0.1";
const DOC1: &str = "1.0.1.0.1";
/// `D`, the published document merged; `Z` another published document;
/// `S` the merger's staging draft; `K` the document standing as the
/// record kind; `F` a fork in another account, `OTHER_DOC1` that
/// account's doc 1.
const D: &str = "1.0.1.0.64";
const Z: &str = "1.0.1.0.65";
const S: &str = "1.0.1.0.66";
const K: &str = "1.0.1.0.71";
const F: &str = "1.0.2.0.69";
const OTHER_DOC1: &str = "1.0.2.0.1";
/// `O`, an unpublished draft of the merger's own; `E` another published
/// document of theirs, in which a record may name `O`'s words.
const O: &str = "1.0.1.0.67";
const E: &str = "1.0.1.0.68";

fn a(text: &str) -> Address {
    parse_address(text).expect("an address")
}

/// O's correspondence record, naming `width` of its words from `first`
/// as published at `E`'s ordinal 3, and the feed row of its commit,
/// `E.2`'s `publish` at `at`.
fn o_record(first: u64, width: u64, at: u64) -> (LinkRow, FeedRow) {
    let link = LinkRow {
        addr: format!("{O}.0.2.1"),
        home: O.to_string(),
        from: vec![format!("{O}.0.1.{first}")],
        to: vec![format!("{E}.0.1.3")],
        ty: crate::board::frames::T_CORRESPONDENCE.to_string(),
        width,
        at: Some(at),
    };
    (link, FeedRow { at, op: "publish", docs: vec![format!("{E}.2")], terms: None })
}

/// `(doc, s, w)`.
fn run(doc: &str, s: u64, w: u64) -> Run {
    Run::new(a(doc), s, w)
}

fn i_addr(origin: &Address, ordinal: u64) -> String {
    format!("{origin}.0.1.{ordinal}")
}

fn reply(status: u16, body: Value) -> Response {
    Response { status, headers: Headers::default(), body: body.to_string().into_bytes() }
}

fn chain_hex(position: u64) -> String {
    format!("{position:064x}")
}

/// A V-span `{"start": "1.N", "width": "0.W"}` as `(from, width)`.
fn span(v: &Value) -> (u64, u64) {
    let from = v["start"].as_str().unwrap().strip_prefix("1.").unwrap().parse().unwrap();
    let width = v["width"].as_str().unwrap().strip_prefix("0.").unwrap().parse().unwrap();
    (from, width)
}

/// The runs clipped to V-positions `from .. from + width`, each with the
/// V-ordinal it begins at.
fn clip(runs: &[Run], from: u64, width: u64) -> Vec<(u64, Run)> {
    let end = from + width;
    let mut out = Vec::new();
    let mut v = 1u64;
    for r in runs {
        let (lo, hi) = (v.max(from), (v + r.width).min(end));
        if lo < hi {
            out.push((lo, Run::new(r.origin.clone(), r.i_start + (lo - v), hi - lo)));
        }
        v += r.width;
    }
    out
}

fn expand(runs: &[Run]) -> Vec<(Address, u64)> {
    runs.iter()
        .flat_map(|r| (r.i_start..r.reach()).map(move |n| (r.origin.clone(), n)))
        .collect()
}

fn coalesce(positions: Vec<(Address, u64)>) -> Vec<Run> {
    let mut out: Vec<Run> = Vec::new();
    for (origin, n) in positions {
        if let Some(last) = out.last_mut() {
            if last.origin == origin && last.reach() == n {
                last.width += 1;
                continue;
            }
        }
        out.push(Run::new(origin, n, 1));
    }
    out
}

/// One position's value as the world holds it.
///
/// A `Ref` is a link position's, delivered `{"ref": …}`: no value a
/// content read spells, which a cell plants to meet a board fault.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Val {
    Byte(u8),
    Atom(String),
    Ref(String),
}

/// The merge marker a draft carries (wire.md §The response envelope,
/// `doc_metadata`'s `merge`).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Marker {
    sides: Vec<String>,
    head: String,
    head_copied: u64,
    at: u64,
}

/// One document as the world holds it.
#[derive(Debug, Clone, Default)]
struct DocState {
    runs: Vec<Run>,
    published: bool,
    owner: String,
    placed: Option<u64>,
    base_extent: Option<u64>,
    /// The base the shot that minted the member was made against, as the
    /// board recorded it — its `doc_metadata` `shot_base` (wire.md §The
    /// response envelope); `None` in the birth shape and where no shot
    /// minted the document.
    shot_base: Option<String>,
    /// The source a `version` minted the document sharing, or a `stage`
    /// copied into it — its `doc_metadata` `source`; `None` where
    /// neither did.
    source: Option<String>,
    /// The base the board records for a staged draft as of each
    /// position it changed at, with the extent the copy took of it — its
    /// `doc_metadata` `base` and `base_copied`, recorded by `stage`,
    /// moved by each `publish` naming the draft as its rendering `draft`
    /// (wire.md §Namespace, `stage`) and by each `set_arrangement`
    /// naming a base to record, served as of `at` on `/op-at`; empty
    /// where the board records none.
    staged: BTreeMap<u64, (String, u64)>,
    /// The merge marker beside the base as of each position it changed
    /// at — set or cleared by a `set_arrangement` naming a base, cleared
    /// by the `publish` that moves the base, inherited at a `stage` of a
    /// marked draft (wire.md §The response envelope, `doc_metadata`'s
    /// `merge`); `None` at a position is no marker.
    markers: BTreeMap<u64, Option<Marker>>,
    /// The markers the board stamped on the draft, in stamp order.
    ///
    /// They are those since a `publish` last moved its base — a
    /// landing's, a `stage`'s inherited one —
    /// which a `set_arrangement` naming `merge.at` may put back (wire.md
    /// §Arrangement, `merge`; skep #870).
    stamped: Vec<Marker>,
    /// The arrangement as of each position it changed at, for `/op-at`.
    history: BTreeMap<u64, Vec<Run>>,
}

#[derive(Debug, Clone)]
struct LinkRow {
    addr: String,
    home: String,
    from: Vec<String>,
    to: Vec<String>,
    ty: String,
    /// The positions each `from` and `to` span holds: one for every
    /// link the merge writes, a correspondence record's width for one
    /// a cell plants.
    width: u64,
    /// The position of the commit that minted the link, as `read_link`
    /// answers it: a `make_link`'s own, none for a row a cell plants
    /// unless the cell names one.
    at: Option<u64>,
}

#[derive(Debug, Clone)]
struct ClaimRow {
    claim: String,
    home: String,
    old: String,
    new: String,
}

#[derive(Debug, Clone)]
struct FeedRow {
    at: u64,
    op: &'static str,
    docs: Vec<String>,
    /// A `set_arrangement` row's two terms — the base it recorded and
    /// the request's merge beside its head, whether or not a marker was
    /// recorded, each `null` where none rides (wire.md §The change
    /// feed); `None` on every other op's row, which carries neither
    /// member.
    terms: Option<(Option<String>, Option<Value>)>,
}

/// What lands in the world as a refused write is answered.
type OnRefused = Box<dyn FnOnce(&mut World) + Send>;

/// The board as the test writes it.
#[derive(Default)]
struct World {
    position: u64,
    docs: BTreeMap<String, DocState>,
    values: BTreeMap<(String, u64), Val>,
    links: Vec<LinkRow>,
    claims: Vec<ClaimRow>,
    rows: Vec<FeedRow>,
    /// Each origin's next fresh content ordinal.
    next_fresh: BTreeMap<String, u64>,
    /// The next document ordinal a mint takes.
    next_doc: u64,
    /// Each trunk's head member.
    trunk_head: BTreeMap<String, String>,
    /// The per-session idempotency memo: an id's acknowledgment.
    memo: BTreeMap<String, Value>,
    /// `image` refuses `image_too_large` past this many runs.
    image_cap: usize,
    /// `retrieve_v` refuses `too_many_items` past this width.
    delivery_cap: u64,
    /// `compare` refuses `too_many_blocks` past this many blocks an
    /// operand.
    compare_cap: usize,
    /// The next N acknowledgments are lost at the transport, the write
    /// applied.
    drop_acks: usize,
    /// `/op-at` answers `history_busy` this many times first.
    busy: usize,
    /// A `find_links_ftt` whose `home` names an account — the merge
    /// journal's find, a class scan — is refused `503 scan_busy` this
    /// many times first (wire.md §Link discovery reads).
    scan_busy: usize,
    /// `/op-at` answers `history_reclaimed` below this position, where
    /// one is set: the journal reclaimed there.
    floor: Option<u64>,
    /// Numbers inside one multi-record commit, each `not_a_position`.
    ///
    /// `/op-at` answers each with `nearest` the greatest number below it
    /// that is none of them (wire.md §Reading history); a number past
    /// `position` answers `beyond_head`.
    inside_commits: BTreeSet<u64>,
    /// Another hand's edit landing in the middle of a walk: before the
    /// N-th frame the dialer serves is answered, the document's
    /// arrangement becomes these runs, one commit.
    interleave: Option<(usize, String, Vec<Run>)>,
    /// The journal reclaimed in the middle of a walk.
    ///
    /// Before the N-th frame the dialer serves is answered, `floor`
    /// becomes this position.
    reclaim: Option<(usize, u64)>,
    /// A grant withdrawn in the middle of a walk.
    ///
    /// Before the N-th frame the dialer serves is answered, this
    /// document joins `withheld`.
    withhold: Option<(usize, String)>,
    /// A record landing in the middle of a walk: before the `find_links_ftt`
    /// of this count (the 2nd is the shot's re-read of a window's
    /// records) is answered, this link and this feed row stand.
    link_before: Option<(usize, LinkRow, FeedRow)>,
    /// Every shot lands as its base's daughter: the head moved.
    head_moved: bool,
    /// Documents this reader may not read.
    ///
    /// A read naming one is refused `withheld`; a `retrieve_v` of a
    /// readable document delivers each run whose origin is one as a
    /// `withheld` item at its own position (wire.md §Value encodings),
    /// the one predicate asked of both (wire.md §The read predicate).
    withheld: BTreeSet<String>,
    /// `/health` names the merger's account the board's claimant.
    claimed: bool,
    /// `H.1` answers its record.
    head: bool,
    /// A claim landing before the first `/op` frame of this op is
    /// answered: from then on the board is claimed and serves `H.1`.
    claim_before: Option<&'static str>,
    /// The next write carrying an `attest` is answered this document,
    /// applied not.
    refuse_signed: Option<Value>,
    /// What lands as that refusal is answered: the board's state moved
    /// under the refused write.
    on_refused: Option<OnRefused>,
    /// The next write of this op is lost at the transport before it is
    /// applied: nothing committed and no acknowledgment.
    lose_before: Option<&'static str>,
    /// The merger's enrolled key.
    key: Option<PublicKey>,
    /// The session dies before the N-th frame the dialer serves is
    /// answered: that answer carries the death signal (wire.md
    /// §Sessions) whatever the request presented — a token-free one's
    /// the board's or the transport's fault — and so does every later
    /// one presenting a token, nothing of either applied.
    die_at: Option<usize>,
    /// Each trunk's own arrangement from before its first version, where
    /// a cell plants one (PUB-2.66): what `image` and a `compare` region
    /// with `own` read of it, and its `own_count`. A trunk with a head
    /// and none planted holds none, as most published documents do.
    pre_chain: BTreeMap<String, Vec<Run>>,
    /// `doc_metadata` serves no `own_count`: an older board.
    no_own_count: bool,
}

impl World {
    /// A claimed permissive board with the merger's doc 1 and `K`, the
    /// kind's document, serving its head record.
    fn new() -> World {
        let mut w = World {
            position: 10,
            image_cap: 1 << 12,
            delivery_cap: 1 << 17,
            compare_cap: 1 << 12,
            next_doc: 72,
            claimed: true,
            head: true,
            ..World::default()
        };
        w.doc(DOC1, true, ACCOUNT, Vec::new());
        w.doc(K, false, ACCOUNT, Vec::new());
        w.doc(OTHER_DOC1, true, "1.0.2", Vec::new());
        w
    }

    fn doc(&mut self, text: &str, published: bool, owner: &str, runs: Vec<Run>) {
        let mut history = BTreeMap::new();
        history.insert(0, runs.clone());
        self.docs.insert(
            text.to_string(),
            DocState {
                runs,
                published,
                owner: owner.to_string(),
                placed: None,
                base_extent: None,
                shot_base: None,
                source: None,
                staged: BTreeMap::new(),
                markers: BTreeMap::new(),
                stamped: Vec::new(),
                history,
            },
        );
    }

    /// Another hand's edit: `doc`'s arrangement becomes `runs`, one
    /// commit at the next position.
    fn change(&mut self, doc: &str, runs: Vec<Run>) -> u64 {
        let at = self.commit("delete", vec![doc.to_string()]);
        let d = self.docs.get_mut(doc).expect("a document of the world");
        d.runs = runs.clone();
        d.history.insert(at, runs);
        at
    }

    /// The draft's recorded base and marker as they stand.
    fn standing(&self, doc: &str) -> (Option<(String, u64)>, Option<Marker>) {
        let d = self.docs.get(doc).expect("a document of the world");
        (
            d.staged.values().next_back().cloned(),
            d.markers.values().next_back().cloned().flatten(),
        )
    }

    /// Records `text`, a draft of the world, as STAGED from `base` with
    /// `copied` positions taken of it — its `doc_metadata` `base`,
    /// `base_copied` and `source`, as the board's `stage` records them
    /// (wire.md §Namespace), standing from the world's first position.
    /// The draft's arrangement is the cell's.
    fn staged(&mut self, text: &str, base: &str, copied: u64) {
        let d = self.docs.get_mut(text).expect("a draft of the world");
        d.staged.insert(0, (base.to_string(), copied));
        d.source = Some(base.to_string());
    }

    /// A member of a chain with its shot terms, its `shot_base` the base
    /// the minting rule names (`skep-arrangement`'s `shot_admission`):
    /// none for `D.1` (the birth shape), `D.k−1` for a later trunk
    /// member `D.k`, the address parent for a daughter. It is its
    /// trunk's owner's, the merger's where the world holds no trunk.
    fn member(&mut self, text: &str, runs: Vec<Run>, base_extent: Option<u64>) {
        let placed = runs.iter().map(|r| r.width).sum();
        let trunk = crate::address::document_of(text).expect("a member's trunk");
        let versions: Vec<u64> =
            text[trunk.len() + 1..].split('.').map(|c| c.parse().unwrap()).collect();
        let shot_base = match versions[..] {
            [1] => None,
            [k] => Some(format!("{trunk}.{}", k - 1)),
            _ => Some(text[..text.rfind('.').unwrap()].to_string()),
        };
        let owner = self.docs.get(&trunk).map_or_else(|| ACCOUNT.to_string(), |d| d.owner.clone());
        self.doc(text, true, &owner, runs);
        let d = self.docs.get_mut(text).unwrap();
        d.placed = Some(placed);
        d.base_extent = base_extent;
        d.shot_base = shot_base;
        self.position += 1;
        self.rows.push(FeedRow {
            at: self.position,
            op: "publish",
            docs: vec![text.to_string()],
            terms: None,
        });
    }

    /// Records `text`, a member under the trunk's first member, as
    /// published from the BARE trunk once that member stood — its
    /// `shot_base` the trunk (wire.md §The response envelope: "a draft
    /// begun from the memberless document `D` and published once `D.1`
    /// stands lands as `D.1`'s daughter `D.1.k`, and its `shot_base` is
    /// `D`").
    fn bare_based(&mut self, text: &str) {
        let trunk = crate::address::document_of(text).expect("a member's trunk");
        self.docs.get_mut(text).expect("a member of the world").shot_base = Some(trunk);
    }

    /// A cross-owner FORK: a private document of `owner`'s account that a
    /// `version` minted off `source` — the member or bare document it
    /// was born sharing, its `doc_metadata` `source` — arranged as
    /// `runs` since, with its `version` row on the feed.
    fn fork(&mut self, text: &str, owner: &str, source: &str, runs: Vec<Run>) {
        self.doc(text, false, owner, runs);
        self.docs.get_mut(text).unwrap().source = Some(source.to_string());
        self.position += 1;
        self.rows.push(FeedRow {
            at: self.position,
            op: "version",
            docs: vec![text.to_string()],
            terms: None,
        });
    }

    /// `text`'s bytes as the values of `origin`'s positions from `from`.
    fn text(&mut self, origin: &str, from: u64, text: &str) {
        for (k, b) in text.bytes().enumerate() {
            self.values.insert((origin.to_string(), from + k as u64), Val::Byte(b));
        }
        let next = self.next_fresh.entry(origin.to_string()).or_insert(1);
        *next = (*next).max(from + text.len() as u64);
    }

    /// The race shape of the record's §9: the base `D.1` "the cat sat",
    /// the head `D.2` adding "big " at `D·4|D·5` (fresh `D·12–15`), the
    /// daughter `D.1.1` removing " sat".
    fn race() -> World {
        let mut w = World::new();
        w.text(D, 1, "the cat sat");
        w.text(D, 12, "big ");
        let head = vec![run(D, 1, 4), run(D, 12, 4), run(D, 5, 7)];
        w.doc(D, true, ACCOUNT, head.clone());
        w.member(&format!("{D}.1"), vec![run(D, 1, 11)], None);
        w.member(&format!("{D}.2"), head, Some(11));
        w.member(&format!("{D}.1.1"), vec![run(D, 1, 7)], Some(11));
        w.trunk_head.insert(D.to_string(), format!("{D}.2"));
        w
    }

    /// THE WINDOW SHAPE: the race's shape, the head `D.2` holding
    /// "hello" windowed from `O`, an unpublished draft of the merger's —
    /// a window a reader of the head meets as a placeholder — and `E`,
    /// another published document, with "xxhello world".
    fn windowed() -> World {
        let mut w = World::new();
        w.text(D, 1, "the cat sat");
        w.text(O, 1, "hello");
        w.text(E, 1, "xxhello world");
        w.doc(O, false, ACCOUNT, vec![run(O, 1, 5)]);
        w.doc(E, true, ACCOUNT, vec![run(E, 1, 13)]);
        let head = vec![run(D, 1, 4), run(O, 1, 5), run(D, 5, 7)];
        w.doc(D, true, ACCOUNT, head.clone());
        w.member(&format!("{D}.1"), vec![run(D, 1, 11)], None);
        w.member(&format!("{D}.2"), head, Some(11));
        w.member(&format!("{D}.1.1"), vec![run(D, 1, 7)], Some(11));
        w.trunk_head.insert(D.to_string(), format!("{D}.2"));
        w
    }

    /// Plants O's record naming `width` of its words from `first` as
    /// published at `E`'s ordinal 3, minted at `at` — the publish row
    /// of `E.2` — and returns the link.
    fn record_of_o(&mut self, first: u64, width: u64, at: u64) -> String {
        let (link, row) = o_record(first, width, at);
        let addr = link.addr.clone();
        self.links.push(link);
        self.rows.push(row);
        addr
    }

    /// Shape (2) with a window: the head `D.2` `[(D,1,4),(Z,1,5),(D,5,7)]`
    /// — "hello" windowed from `Z` — and the staging draft `S`, staged
    /// from the base `D.1` (its recorded base) with "!!!" typed at its
    /// end.
    fn window_and_draft() -> World {
        let mut w = World::new();
        w.text(D, 1, "the cat sat");
        w.text(Z, 1, "hello");
        w.text(S, 1, "!!!");
        w.doc(Z, true, ACCOUNT, vec![run(Z, 1, 5)]);
        let head = vec![run(D, 1, 4), run(Z, 1, 5), run(D, 5, 7)];
        w.doc(D, true, ACCOUNT, head.clone());
        w.member(&format!("{D}.1"), vec![run(D, 1, 11)], None);
        w.member(&format!("{D}.2"), head, Some(11));
        w.trunk_head.insert(D.to_string(), format!("{D}.2"));
        w.doc(S, false, ACCOUNT, vec![run(D, 1, 11), run(S, 1, 3)]);
        w.staged(S, &format!("{D}.1"), 11);
        w.position += 1;
        let at = w.position;
        w.docs.get_mut(S).unwrap().history.insert(at, vec![run(D, 1, 11), run(S, 1, 3)]);
        w
    }

    /// THE SHAPE BEGUN BEFORE VERSION 1 (skep #1113): `D` published and
    /// empty; its first version `D.1` "the fox", the head `D.2` adding
    /// " jumps"; the daughter `D.1.1` "the cat" — a draft staged from
    /// the empty `D` and published once `D.1` stood, so recorded against
    /// `D` while its address says `D.1` — and the ordinary daughter
    /// `D.2.1` "the fox runs", recorded against `D.2`. Over `D`'s own
    /// arrangement, empty, the head's text and the cat are both
    /// additions at the one spot.
    fn begun_before_version_1() -> World {
        let mut w = World::new();
        w.text(D, 1, "the fox jumps");
        w.text(D, 20, "the cat");
        w.text(D, 30, " runs");
        let head = vec![run(D, 1, 13)];
        w.doc(D, true, ACCOUNT, head.clone());
        w.member(&format!("{D}.1"), vec![run(D, 1, 7)], None);
        w.member(&format!("{D}.2"), head, Some(7));
        w.member(&format!("{D}.1.1"), vec![run(D, 20, 7)], Some(0));
        w.bare_based(&format!("{D}.1.1"));
        w.member(&format!("{D}.2.1"), vec![run(D, 1, 7), run(D, 30, 5)], Some(13));
        w.trunk_head.insert(D.to_string(), format!("{D}.2"));
        w
    }

    fn arrangement(&self, doc: &str, at: Option<u64>) -> Option<Vec<Run>> {
        let d = self.docs.get(doc)?;
        Some(match at {
            None => d.runs.clone(),
            Some(at) => {
                d.history.range(..=at).next_back().map(|(_, r)| r.clone()).unwrap_or_default()
            }
        })
    }

    /// `doc`'s own arrangement as of `at`, never floated (wire.md §The
    /// publish shot and head-float; PUB-2.66): what `image` and a
    /// `compare` region carrying `own` read, and what `own_count`
    /// counts — a trunk's planted pre-chain arrangement, none for a
    /// trunk with a head and none planted, else the arrangement itself.
    fn own_arrangement(&self, doc: &str, at: Option<u64>) -> Option<Vec<Run>> {
        if !self.docs.contains_key(doc) {
            return None;
        }
        match self.pre_chain.get(doc) {
            Some(runs) => Some(runs.clone()),
            None if self.trunk_head.contains_key(doc) => Some(Vec::new()),
            None => self.arrangement(doc, at),
        }
    }

    fn fresh(&mut self, origin: &str) -> u64 {
        let next = self.next_fresh.entry(origin.to_string()).or_insert(1);
        let n = *next;
        *next += 1;
        n
    }

    fn commit(&mut self, op: &'static str, docs: Vec<String>) -> u64 {
        self.position += 1;
        self.rows.push(FeedRow { at: self.position, op, docs, terms: None });
        self.position
    }

    /// One commit of `records` records: the position advances by each,
    /// the numbers inside the commit answer `not_a_position` on `/op-at`
    /// (wire.md §Reading history), and the row's `at` is the commit's
    /// last — the ack's.
    fn commit_records(&mut self, op: &'static str, docs: Vec<String>, records: u64) -> u64 {
        let first = self.position + 1;
        self.position += records;
        self.inside_commits.extend(first..self.position);
        self.rows.push(FeedRow { at: self.position, op, docs, terms: None });
        self.position
    }

    /// The delivery items over clipped runs: adjacent bytes one
    /// `content` item, an atom and a reference each its own, and a run
    /// whose origin this reader may not read one `withheld` item of its
    /// width at its own position, never coalesced with a neighbour
    /// (wire.md §Value encodings).
    fn items(&self, clipped: &[(u64, Run)]) -> Vec<Value> {
        fn flush(out: &mut Vec<Value>, text: &mut String) {
            if !text.is_empty() {
                out.push(json!({"content": std::mem::take(text)}));
            }
        }
        let mut out = Vec::new();
        let mut text = String::new();
        for (_, r) in clipped {
            let origin = r.origin.to_string();
            if self.withheld.contains(&origin) {
                flush(&mut out, &mut text);
                out.push(json!({"withheld": {"origin": origin, "width": r.width.to_string()}}));
                continue;
            }
            for n in r.i_start..r.reach() {
                match self
                    .values
                    .get(&(origin.clone(), n))
                    .unwrap_or_else(|| panic!("no value at {}", i_addr(&r.origin, n)))
                {
                    Val::Byte(b) => text.push(*b as char),
                    Val::Atom(s) => {
                        flush(&mut out, &mut text);
                        out.push(json!({"atom": s}));
                    }
                    Val::Ref(link) => {
                        flush(&mut out, &mut text);
                        out.push(json!({"ref": link}));
                    }
                }
            }
        }
        flush(&mut out, &mut text);
        out
    }

    fn health(&self) -> Value {
        let origin = "http://127.0.0.1:8642";
        let claimant = if self.claimed { json!(ACCOUNT) } else { Value::Null };
        json!({"ok": true, "log_position": self.position, "chain_head": chain_hex(self.position), "auth": {"claimant": claimant, "local_trust": true, "origins": [origin], "signed_origins": [origin]}})
    }

    /// Answers a `/changes` page: the rows past `since`, narrowed to
    /// `under` and, with `drafts=true`, to the rows naming a draft (the
    /// supplement's page, wire.md §The change feed); a
    /// `set_arrangement` row carries its two terms.
    fn changes(&self, path: &str) -> Response {
        let query = path.splitn(2, '?').nth(1).unwrap_or("");
        let (mut since, mut under, mut limit, mut drafts) = (0u64, None::<String>, 256usize, false);
        for pair in query.split('&') {
            match pair.split_once('=') {
                Some(("since", v)) => since = v.parse().unwrap(),
                Some(("under", v)) => under = Some(v.to_string()),
                Some(("limit", v)) => limit = v.parse().unwrap(),
                Some(("drafts", v)) => drafts = v == "true",
                _ => panic!("an unknown `/changes` member: {pair}"),
            }
        }
        let visible: Vec<&FeedRow> = self
            .rows
            .iter()
            .filter(|r| r.at > since)
            .filter(|r| {
                under.as_ref().is_none_or(|u| {
                    r.docs.iter().any(|d| d == u || d.starts_with(&format!("{u}.")))
                })
            })
            .filter(|r| !drafts || r.docs.iter().any(|d| self.docs.get(d).is_some_and(|x| !x.published)))
            .collect();
        let page: Vec<Value> = visible
            .iter()
            .take(limit)
            .map(|r| {
                let mut row = json!({"at": r.at, "op": r.op, "docs": r.docs, "key": "bare", "time": null});
                if let Some((base, merge)) = &r.terms {
                    row["base"] = base.clone().map_or(Value::Null, Value::from);
                    row["merge"] = merge.clone().unwrap_or(Value::Null);
                }
                row
            })
            .collect();
        let last = page.last().and_then(|r| r["at"].as_u64()).unwrap_or(since);
        reply(200, json!({"changes": page, "last": last, "more": visible.len() > page.len()}))
    }

    fn op(&mut self, frame: &Value, at: Option<u64>) -> Result<Response, DialError> {
        let op = frame["op"].as_str().unwrap_or("?").to_string();
        // Every answer names where it sits: `at` on `/op-at`, the head
        // on `/op` (wire.md §Reading history).
        let position = at.unwrap_or(self.position);
        let rejected = |code: &str| {
            reply(
                200,
                json!({"resp": "rejected", "code": code, "disposition": "reorder", "op": op}),
            )
        };
        // A document argument this reader may not read: `withheld`,
        // `site.addr` the document (wire.md §The read predicate).
        let masked = |doc: &str| {
            reply(
                200,
                json!({"resp": "rejected", "code": "withheld", "disposition": "reorder", "op": op, "site": {"addr": doc}}),
            )
        };
        // An id past the wire's cap is refused at parse, as skepd's codec
        // refuses it: `malformed` under `unparseable`, nothing applied.
        if let Some(id) = frame["id"].as_str().filter(|id| id.len() > MAX_REQ_ID_BYTES) {
            return Ok(reply(
                200,
                json!({"resp": "rejected", "code": "malformed", "detail": format!("id is {} bytes, past the {MAX_REQ_ID_BYTES}-byte wire cap", id.len()), "disposition": "permanent", "op": "unparseable"}),
            ));
        }
        match op.as_str() {
            "principal_prefix" => Ok(reply(200, json!({"resp": "addr", "as_of": position, "addr": ACCOUNT}))),
            "key_set" => {
                let key = self.key.clone().expect("the merger's key");
                Ok(reply(200, json!({"resp": "key_set", "as_of": position, "retired": [], "enrolled": [{"alg": key.alg(), "key": key.to_hex(), "fingerprint": Fingerprint::of(&key).to_hex(), "anchor": false}]})))
            }
            "doc_metadata" => {
                let doc = frame["doc"].as_str().unwrap();
                if self.withheld.contains(doc) {
                    return Ok(masked(doc));
                }
                let Some(d) = self.docs.get(doc) else { return Ok(rejected("doc_not_registered")) };
                // A document minted after `position` did not exist then
                // (wire.md §Reading history: "that position's own
                // `doc_not_registered`").
                if d.history.keys().next().is_some_and(|minted| *minted > position) {
                    return Ok(rejected("doc_not_registered"));
                }
                // The recorded base and the marker as they stood at
                // `position`, and the document's age, the position the
                // world minted it at.
                let staged = d.staged.range(..=position).next_back().map(|(_, s)| s);
                let marker = d.markers.range(..=position).next_back().and_then(|(_, m)| m.clone());
                let merge = marker.map(|m| json!({"sides": m.sides, "head": m.head, "head_copied": m.head_copied.to_string(), "at": m.at}));
                // The position its arrangement last changed at as of
                // `position`, `null` for one the world never arranged
                // since it planted it at its start (wire.md §The
                // response envelope, `arranged_at`).
                let arranged_at = d.history.range(..=position).next_back().map(|(at, _)| *at).filter(|at| *at > 0);
                let mut answer = json!({"resp": "doc_metadata", "as_of": position, "doc": doc, "published": d.published, "owner": d.owner, "placed": d.placed.map(|p| p.to_string()), "base_extent": d.base_extent.map(|e| e.to_string()), "shot_base": d.shot_base, "source": d.source, "base": staged.map(|(b, _)| b.clone()), "base_copied": staged.map(|(_, c)| c.to_string()), "merge": merge, "at": d.history.keys().next(), "arranged_at": arranged_at});
                // The address named's own content count, never floated —
                // absent on an older board.
                if !self.no_own_count {
                    let own = self.own_arrangement(doc, Some(position)).unwrap_or_default();
                    answer["own_count"] = json!(own.iter().map(|r| r.width).sum::<u64>().to_string());
                }
                Ok(reply(200, answer))
            }
            "retrieve_doc_v_span_set" => {
                let doc = frame["doc"].as_str().unwrap();
                if self.withheld.contains(doc) {
                    return Ok(masked(doc));
                }
                let Some(runs) = self.arrangement(doc, at) else { return Ok(rejected("doc_not_registered")) };
                let extent: u64 = runs.iter().map(|r| r.width).sum();
                let set = if extent == 0 { json!([]) } else { json!([{"start": "1.1", "width": format!("0.{extent}")}]) };
                Ok(reply(200, json!({"resp": "span_set", "as_of": position, "set": set})))
            }
            "image" => {
                let doc = frame["d"].as_str().unwrap();
                if self.withheld.contains(doc) {
                    return Ok(masked(doc));
                }
                let (from, width) = span(&frame["region"][0]);
                let runs = if frame["own"] == true { self.own_arrangement(doc, at) } else { self.arrangement(doc, at) };
                let Some(runs) = runs else { return Ok(rejected("doc_not_registered")) };
                let clipped = clip(&runs, from, width);
                if clipped.len() > self.image_cap {
                    return Ok(rejected("image_too_large"));
                }
                let runs: Vec<Value> = clipped.iter().map(|(_, r)| json!({"i_start": i_addr(&r.origin, r.i_start), "width": r.width.to_string()})).collect();
                Ok(reply(200, json!({"resp": "runs", "as_of": position, "runs": runs})))
            }
            "retrieve_v" => {
                let spec = &frame["specs"][0];
                let doc = spec["doc"].as_str().unwrap();
                if doc == HEAD_MEMBER_1 {
                    let record = json!({"type": "skep-head", "position": 1, "chain": chain_hex(1)}).to_string();
                    let items = if self.head { json!([{"atom": record}]) } else { json!([]) };
                    return Ok(reply(200, json!({"resp": "delivery", "as_of": position, "items": items})));
                }
                if self.withheld.contains(doc) {
                    return Ok(masked(doc));
                }
                let (from, width) = span(&spec["span"]);
                if width > self.delivery_cap {
                    return Ok(rejected("too_many_items"));
                }
                let Some(runs) = self.arrangement(doc, at) else { return Ok(rejected("doc_not_registered")) };
                let items = self.items(&clip(&runs, from, width));
                Ok(reply(200, json!({"resp": "delivery", "as_of": position, "items": items})))
            }
            "compare" => {
                // Every region's document consulted in declaration
                // order, ρ₁'s before ρ₂'s, before the read runs.
                let regions = frame["rho1"].as_array().unwrap().iter().chain(frame["rho2"].as_array().unwrap());
                if let Some(doc) = regions.filter_map(|r| r["doc"].as_str()).find(|d| self.withheld.contains(*d)) {
                    return Ok(masked(doc));
                }
                let operand = |rho: &Value| -> Result<Vec<(String, Vec<(u64, Run)>)>, Response> {
                    let mut out = Vec::new();
                    let mut blocks = 0;
                    for region in rho.as_array().unwrap() {
                        let doc = region["doc"].as_str().unwrap();
                        let (from, width) = span(&region["spans"][0]);
                        let runs = if region["own"] == true { self.own_arrangement(doc, at) } else { self.arrangement(doc, at) };
                        let Some(runs) = runs else { return Err(rejected("doc_not_registered")) };
                        let clipped = clip(&runs, from, width);
                        blocks += clipped.len();
                        out.push((doc.to_string(), clipped));
                    }
                    if blocks > self.compare_cap {
                        return Err(rejected("too_many_blocks"));
                    }
                    Ok(out)
                };
                let rho1 = match operand(&frame["rho1"]) {
                    Ok(r) => r,
                    Err(r) => return Ok(r),
                };
                let rho2 = match operand(&frame["rho2"]) {
                    Ok(r) => r,
                    Err(r) => return Ok(r),
                };
                let mut pairs = Vec::new();
                for (d1, runs1) in &rho1 {
                    for (d2, runs2) in &rho2 {
                        for (v1, r1) in runs1 {
                            for (v2, r2) in runs2 {
                                if r1.origin != r2.origin {
                                    continue;
                                }
                                let (lo, hi) = (r1.i_start.max(r2.i_start), r1.reach().min(r2.reach()));
                                if lo < hi {
                                    pairs.push(json!({"d1": d1, "d2": d2, "u1": {"subspace": "1", "ordinal": (v1 + (lo - r1.i_start)).to_string()}, "u2": {"subspace": "1", "ordinal": (v2 + (lo - r2.i_start)).to_string()}, "width": (hi - lo).to_string()}));
                                }
                            }
                        }
                    }
                }
                Ok(reply(200, json!({"resp": "compare", "as_of": position, "pairs": pairs})))
            }
            "find_links_ftt" => {
                let q = &frame["q"];
                let start = |slot: &Value| slot.as_array().and_then(|s| s.first()).and_then(|s| s["start"].as_str()).map(str::to_string);
                let (ty, to, home, from) = (start(&q["ty"]), start(&q["to"]), start(&q["home"]), start(&q["from"]));
                assert!(to.is_some() || home.is_some() || from.is_some(), "a class scan: {q}");
                // A `home` naming an account walks every home under it, a
                // class scan under the board's permits; one naming a
                // document reads the homes of its subtree.
                let account_home = home.as_ref().is_some_and(|h| crate::address::document_of(h).as_deref() != Some(h.as_str()));
                if account_home && self.scan_busy > 0 {
                    self.scan_busy -= 1;
                    return Ok(reply(503, json!({"error": "scan_busy", "detail": "all class-scan permits are in use; retry shortly", "op": "find_links_ftt"})));
                }
                let under = |l: &LinkRow, h: &str| l.home == h || l.home.starts_with(&format!("{h}."));
                let addrs: Vec<&str> = self
                    .links
                    .iter()
                    .filter(|l| ty.as_ref().is_none_or(|t| &l.ty == t) && to.as_ref().is_none_or(|t| l.to.contains(t)) && home.as_ref().is_none_or(|h| under(l, h)) && from.as_ref().is_none_or(|f| l.from.contains(f)))
                    .map(|l| l.addr.as_str())
                    .collect();
                Ok(reply(200, json!({"resp": "addrs", "as_of": position, "addrs": addrs})))
            }
            "read_link" => {
                let addr = frame["a"].as_str().unwrap();
                let Some(l) = self.links.iter().find(|l| l.addr == addr) else {
                    return Ok(reply(200, json!({"resp": "link_value", "as_of": position, "link": null})));
                };
                let span = |addr: &str, width: u64| json!({"start": addr, "width": format!("{}{width}", "0.".repeat(addr.split('.').count() - 1))});
                let slot = |addrs: &[String]| addrs.iter().map(|x| span(x, l.width)).collect::<Vec<_>>();
                Ok(reply(200, json!({"resp": "link_value", "as_of": position, "at": l.at, "link": {"slots": [slot(&l.from), slot(&l.to), vec![span(&l.ty, 1)]]}})))
            }
            "in_claims" => {
                let y = frame["y"].as_str().unwrap();
                let claims: Vec<Value> = self.claims.iter().filter(|c| c.old == y).map(|c| json!({"active": true, "claim": c.claim, "home": c.home, "new": c.new, "old": c.old})).collect();
                Ok(reply(200, json!({"resp": "claims", "as_of": position, "claims": claims})))
            }
            "assert_sup" => panic!("the merge files no `assert_sup` on this wire, whose endpoints are links: {frame}"),
            "publish" | "insert" | "make_link" | "create_new_document" | "delete" | "reinstate" | "stage" | "set_arrangement" => {
                assert!(at.is_none(), "a write on `/op-at` is `write_at_history`: {frame}");
                self.write(frame)
            }
            other => panic!("the merge sent an op the scripted board does not answer: {other}"),
        }
    }

    /// A write: the id's memo answered where one stands, else the board's
    /// check — a publish-class write carrying no `attest` refused on a
    /// claimed board serving `H.1`, the next signed write refused where
    /// `refuse_signed` holds — else the write applied and its
    /// acknowledgment kept; the next `drop_acks` acknowledgments lost at
    /// the transport.
    fn write(&mut self, frame: &Value) -> Result<Response, DialError> {
        if self.lose_before.is_some_and(|op| frame["op"] == op) {
            self.lose_before = None;
            return Err(DialError::Io("the write was lost".into()));
        }
        let id = frame["id"].as_str().map(str::to_string);
        let ack = match id.as_ref().and_then(|id| self.memo.get(id)).cloned() {
            Some(ack) => ack,
            None => {
                // Before the transaction, applied not and memoized not
                // (wire.md §Credential refusals, a reorder): a `publish`,
                // or a link homed in a published document.
                let op = frame["op"].as_str().unwrap_or("?");
                let published_home = frame["home"]
                    .as_str()
                    .is_some_and(|h| self.docs.get(h).is_some_and(|d| d.published));
                let publish_class = op == "publish" || (op == "make_link" && published_home);
                if self.claimed && self.head && publish_class && frame.get("attest").is_none() {
                    return Ok(reply(
                        200,
                        json!({"resp": "rejected", "code": "credential_refused", "detail": "attestation_required", "disposition": "reorder", "op": op}),
                    ));
                }
                if frame.get("attest").is_some() {
                    if let Some(rejection) = self.refuse_signed.take() {
                        if let Some(then) = self.on_refused.take() {
                            then(self);
                        }
                        return Ok(reply(200, rejection));
                    }
                }
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

    fn apply(&mut self, frame: &Value) -> Value {
        let op = frame["op"].as_str().unwrap();
        match op {
            "create_new_document" => {
                let account = frame["account"].as_str().unwrap().to_string();
                let published = frame["published"].as_bool().unwrap_or(false);
                let addr = format!("{account}.0.{}", self.next_doc);
                self.next_doc += 1;
                self.doc(&addr, published, &account, Vec::new());
                let at = self.commit("create_new_document", vec![addr.clone()]);
                json!({"resp": "ack_addr", "addr": addr, "at": at})
            }
            "insert" => {
                let doc = frame["doc"].as_str().unwrap().to_string();
                assert!(
                    frame.get("deposit").is_none(),
                    "a journal append is a PLAIN insert: {frame}"
                );
                // The store's judgment, nothing applied: registration,
                // then the owner, then the version chain (wire.md
                // §Identity, §The version-chain refusals).
                let Some(d) = self.docs.get(&doc) else {
                    return permanent("insert", "doc_not_registered", Value::Null);
                };
                if d.owner != ACCOUNT {
                    return permanent("insert", "not_owner", json!({"addr": doc}));
                }
                if d.published {
                    return permanent("insert", "published_target", Value::Null);
                }
                let ordinal: u64 = frame["at"]["ordinal"].as_str().unwrap().parse().unwrap();
                let atom = frame["values"][0]["atom"].as_str().expect("one atom").to_string();
                let n = self.fresh(&doc);
                self.values.insert((doc.clone(), n), Val::Atom(atom));
                let d = self.docs.get(&doc).expect("a registered draft");
                let mut positions = expand(&d.runs);
                assert!(
                    ordinal >= 1 && ordinal as usize <= positions.len() + 1,
                    "out of bounds: {ordinal}"
                );
                positions.insert(ordinal as usize - 1, (a(&doc), n));
                let runs = coalesce(positions);
                let at = self.commit("insert", vec![doc.clone()]);
                let d = self.docs.get_mut(&doc).unwrap();
                d.runs = runs.clone();
                d.history.insert(at, runs);
                json!({"resp": "ack_addr", "addr": i_addr(&a(&doc), n), "at": at})
            }
            "make_link" => {
                let home = frame["home"].as_str().unwrap().to_string();
                let addrs = |slot: &Value| {
                    slot["addrs"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|x| x.as_str().unwrap().to_string())
                        .collect::<Vec<_>>()
                };
                let n = self.links.iter().filter(|l| l.home == home).count() + 1;
                let addr = format!("{home}.0.2.{n}");
                let (from, to, ty) = (
                    addrs(&frame["from"]),
                    addrs(&frame["to"]),
                    addrs(&frame["ty"])[0].clone(),
                );
                let at = self.commit("make_link", vec![home.clone()]);
                self.links.push(LinkRow {
                    addr: addr.clone(),
                    home,
                    from,
                    to,
                    ty,
                    width: 1,
                    at: Some(at),
                });
                json!({"resp": "ack_addr", "addr": addr, "at": at})
            }
            "publish" => {
                let doc = frame["doc"].as_str().unwrap().to_string();
                let base = frame["base"].as_str().unwrap().to_string();
                let base_extent: u64 = frame["base_extent"].as_str().unwrap().parse().unwrap();
                let draft = frame["draft"].as_str().map(str::to_string);
                let mut positions = Vec::new();
                for r in frame["runs"].as_array().unwrap() {
                    let origin = r["origin"].as_str().unwrap().to_string();
                    let i_start: u64 = r["i_start"]
                        .as_str()
                        .unwrap()
                        .rsplit('.')
                        .next()
                        .unwrap()
                        .parse()
                        .unwrap();
                    let width: u64 = r["width"].as_str().unwrap().parse().unwrap();
                    for k in 0..width {
                        if draft.as_deref() == Some(origin.as_str()) {
                            let n = self.fresh(&doc);
                            let v = self
                                .values
                                .get(&(origin.clone(), i_start + k))
                                .expect("the draft's value")
                                .clone();
                            self.values.insert((doc.clone(), n), v);
                            positions.push((a(&doc), n));
                        } else {
                            positions.push((a(&origin), i_start + k));
                        }
                    }
                }
                let runs = coalesce(positions);
                let placed: u64 = runs.iter().map(|r| r.width).sum();
                let head = self.trunk_head.get(&doc).cloned().expect("a chain");
                // THE VALIDATION's (6), the merge bridge lane: a shot
                // naming daughters lands on the trunk or not at all —
                // refused whole `head_moved` naming the head where it
                // would mint the base's daughter, nothing committed.
                let supersede: Vec<String> = frame["supersede"]
                    .as_array()
                    .map(|l| l.iter().map(|x| x.as_str().unwrap().to_string()).collect())
                    .unwrap_or_default();
                if !supersede.is_empty() && (self.head_moved || base != head) {
                    return json!({"resp": "rejected", "code": "supersede_refused", "detail": "head_moved", "disposition": "permanent", "op": "publish", "site": {"index": 0, "addr": head}});
                }
                let member = if self.head_moved || base != head {
                    let k = 1 + self
                        .docs
                        .keys()
                        .filter(|m| {
                            m.strip_prefix(&format!("{base}."))
                                .is_some_and(|rest| !rest.contains('.'))
                        })
                        .count();
                    format!("{base}.{k}")
                } else {
                    let n: u64 = head.rsplit('.').next().unwrap().parse().unwrap();
                    format!("{doc}.{}", n + 1)
                };
                self.doc(&member, true, ACCOUNT, runs.clone());
                let d = self.docs.get_mut(&member).unwrap();
                d.placed = Some(placed);
                d.base_extent = Some(base_extent);
                d.shot_base = Some(base.clone());
                if !member.strip_prefix(&format!("{doc}.")).unwrap().contains('.') {
                    self.trunk_head.insert(doc.clone(), member.clone());
                    self.docs.get_mut(&doc).unwrap().runs = runs;
                }
                // The row names the minted member first, then the
                // rendering draft, then every other home the deposits
                // touched (wire.md §The change feed, `docs`).
                let mut docs: Vec<String> =
                    std::iter::once(member.clone()).chain(draft.clone()).collect();
                // Each daughter's claim deposited in the trunk — `old`
                // the daughter, `new` the member this commit minted — one
                // an active claim of the merger's own already names
                // skipped, whatever its `new`.
                for daughter in &supersede {
                    let own = self
                        .claims
                        .iter()
                        .any(|c| c.old == *daughter && c.home.starts_with(&format!("{ACCOUNT}.0.")));
                    if own {
                        continue;
                    }
                    let n = self.links.iter().filter(|l| l.home == doc).count()
                        + self.claims.iter().filter(|c| c.home == doc).count()
                        + 1;
                    self.claims.push(ClaimRow {
                        claim: format!("{doc}.0.2.{n}"),
                        home: doc.clone(),
                        old: daughter.clone(),
                        new: member.clone(),
                    });
                    if !docs.contains(&doc) {
                        docs.push(doc.clone());
                    }
                }
                let at = self.commit("publish", docs);
                // THE BASE MOVES at the shot's position: the rendering
                // draft's recorded base becomes the member the shot
                // minted, `base_copied` its whole count, and the marker
                // is cleared — the merge is the member's now (wire.md
                // §Namespace, `stage`); a read as of an earlier position
                // answers the base that stood. A shot setting
                // `keep_base` moves neither (§Arrangement, `publish`).
                let moves = frame["keep_base"].as_bool() != Some(true);
                if let Some(s) = draft.as_ref().filter(|_| moves).and_then(|s| self.docs.get_mut(s)) {
                    s.staged.insert(at, (member.clone(), placed));
                    s.markers.insert(at, None);
                    s.stamped.clear();
                }
                json!({"resp": "ack_addr", "addr": member, "at": at})
            }
            "stage" => {
                // THE STAGING ACT (wire.md §Namespace, `stage`): a private
                // draft of the account holding `from` by identity, its
                // base the surface copied at its count — or a draft's
                // own base and marker inherited, the marker's `at` this
                // stage's position — in one commit.
                let from = frame["from"].as_str().unwrap().to_string();
                let Some(src) = self.docs.get(&from).cloned() else {
                    return permanent("stage", "source_not_registered", Value::Null);
                };
                let addr = format!("{ACCOUNT}.0.{}", self.next_doc);
                self.next_doc += 1;
                let extent: u64 = src.runs.iter().map(|r| r.width).sum();
                self.doc(&addr, false, ACCOUNT, src.runs.clone());
                // ONE COMMIT of three records (the skepd suite's
                // `an_alternative_inherits_the_marker_at_the_stages_position_and_the_shot_clears_it`),
                // so the number below the ack's `at` lies inside it.
                let at = self.commit_records("stage", vec![addr.clone()], 3);
                let d = self.docs.get_mut(&addr).unwrap();
                d.source = Some(from.clone());
                d.history = BTreeMap::from([(at, src.runs.clone())]);
                if src.published {
                    d.staged.insert(at, (from, extent));
                } else {
                    if let Some(s) = src.staged.values().next_back() {
                        d.staged.insert(at, s.clone());
                    }
                    if let Some(Some(m)) = src.markers.values().next_back() {
                        d.markers.insert(at, Some(Marker { at, ..m.clone() }));
                        d.stamped = vec![Marker { at, ..m.clone() }];
                    }
                }
                json!({"resp": "ack_addr", "addr": addr, "at": at})
            }
            "set_arrangement" => self.set_arrangement(frame),
            "delete" | "reinstate" => {
                let doc = frame["doc"].as_str().unwrap().to_string();
                let d = self.docs.get(&doc).expect("a registered draft");
                assert!(!d.published, "`{op}` into a published document is `published_target`");
                let mut positions = expand(&d.runs);
                if op == "delete" {
                    let p: usize = frame["p"]["ordinal"].as_str().unwrap().parse().unwrap();
                    let width: usize = frame["width"].as_str().unwrap().parse().unwrap();
                    positions.drain(p - 1..p - 1 + width);
                } else {
                    let at: usize = frame["at"]["ordinal"].as_str().unwrap().parse().unwrap();
                    let mut placed = Vec::new();
                    for r in frame["runs"].as_array().unwrap() {
                        let origin = a(r["origin"].as_str().unwrap());
                        let i_start: u64 = r["i_start"]
                            .as_str()
                            .unwrap()
                            .rsplit('.')
                            .next()
                            .unwrap()
                            .parse()
                            .unwrap();
                        let width: u64 = r["width"].as_str().unwrap().parse().unwrap();
                        placed.extend((i_start..i_start + width).map(|n| (origin.clone(), n)));
                    }
                    assert!(
                        placed.iter().all(|p| !positions.contains(p)),
                        "a position placed twice"
                    );
                    positions.splice(at - 1..at - 1, placed);
                }
                let runs = coalesce(positions);
                let at = self.commit(
                    if op == "delete" { "delete" } else { "reinstate" },
                    vec![doc.clone()],
                );
                let d = self.docs.get_mut(&doc).unwrap();
                d.runs = runs.clone();
                d.history.insert(at, runs);
                json!({"resp": "ack", "at": at})
            }
            other => panic!("no write named {other}"),
        }
    }

    /// Answers `set_arrangement` as the store judges it.
    ///
    /// The order is wire.md §Arrangement's and
    /// `crates/skep-arrangement/src/ops/set_arrangement.rs`'s: the
    /// destination's own four refusals; the head's registration on
    /// every draft, then its chain and its extent where the draft has a
    /// chain — its recorded base's, else its fork source's; the fork
    /// gate; the base's `no_base_to_record`, then its registration, its
    /// chain and its extent; then each run's origin registered and a
    /// value at every address it names, a `merge.at` naming no marker
    /// the board stamped on the draft refused `marker_not_restorable`
    /// after the base's checks and ahead of the runs'. The whole
    /// arrangement is replaced in one commit, the base re-recorded and
    /// the marker set — stamped at the commit, or put back with the
    /// position named — or cleared where a base is named, the row
    /// carrying the request's merge whatever the base, and `head_moved`
    /// rides the ack where the trunk has moved past the head named.
    ///
    /// It judges no `bad_run` or `too_many_runs`: the landing spells
    /// each run's start from its own origin and refuses a list past
    /// `SHOT_RUN_CAP` before any frame. The door's answers — `malformed`,
    /// `withheld` — are no judgment of it either: a test that needs one
    /// plants it in `memo` under the frame's id.
    fn set_arrangement(&mut self, frame: &Value) -> Value {
        let reject = |code: &str, site: Value| permanent("set_arrangement", code, site);
        let doc = frame["doc"].as_str().unwrap().to_string();
        let Some(d) = self.docs.get(&doc).cloned() else { return reject("doc_not_registered", Value::Null) };
        if d.owner != ACCOUNT {
            return reject("not_owner", json!({"addr": doc}));
        }
        if d.published {
            return reject("published_target", Value::Null);
        }
        // The typed state: `as_of` REQUIRED, refused below the position
        // the arrangement last changed at, with nothing written.
        let as_of = frame["as_of"].as_u64().expect("`as_of` is REQUIRED on `set_arrangement`");
        let current = d.history.keys().next_back().copied().unwrap_or(0);
        if as_of < current {
            return reject("arrangement_moved", json!({"as_of": as_of, "current": current}));
        }
        let pair = |v: &Value| -> Option<(String, u64)> {
            v.as_object().map(|p| (p["at"].as_str().expect("a pair's `at`").to_string(), p["extent"].as_str().expect("a pair's `extent`, a decimal string").parse().unwrap()))
        };
        let (head, base) = (pair(&frame["head"]), pair(&frame["base"]));
        let standing = d.staged.values().next_back().cloned();
        let trunk = |member: &str| crate::address::document_of(member).unwrap_or_else(|| member.to_string());
        // The fork (P5): no recorded base, and a source that is a
        // published surface.
        let fork_source = match (&standing, &d.source) {
            (None, Some(src)) if self.docs.get(src).is_some_and(|s| s.published) => Some(src.clone()),
            _ => None,
        };
        let chain = standing.as_ref().map(|(b, _)| trunk(b)).or_else(|| fork_source.as_ref().map(|s| trunk(s)));
        // A pair as the store judges it (`judge_pair`,
        // `judge_registration`): its registration first, on every draft;
        // then, on a draft with a chain, its address against the chain
        // and its extent against its own count.
        let judge = |p: &(String, u64), chain: Option<&String>| -> Option<&'static str> {
            let Some(member) = self.docs.get(&p.0) else {
                return Some("source_not_registered");
            };
            let chain = chain?;
            if trunk(&p.0) != *chain && p.0 != *chain {
                return Some("base_not_in_chain");
            }
            let count: u64 = member.runs.iter().map(|r| r.width).sum();
            (p.1 > count).then_some("base_extent_too_large")
        };
        if let Some(h) = &head {
            if let Some(code) = judge(h, chain.as_ref()) {
                return reject(code, Value::Null);
            }
            if let Some(src) = &fork_source {
                if *src != h.0 {
                    return reject("fork_base_moved", json!({"addr": src}));
                }
            }
        }
        if let Some(b) = &base {
            let Some((sb, _)) = &standing else { return reject("no_base_to_record", Value::Null) };
            if let Some(code) = judge(b, Some(&trunk(sb))) {
                return reject(code, Value::Null);
            }
        }
        // The request's merge beside its head, with the position of a
        // marker put back where it names one.
        let merge = match (&head, frame["merge"].as_object()) {
            (Some((h, e)), Some(m)) => Some((m["sides"].as_array().expect("`merge.sides`").iter().map(|s| s.as_str().unwrap().to_string()).collect::<Vec<_>>(), h.clone(), *e, m.get("at").and_then(Value::as_u64))),
            _ => None,
        };
        if let Some((sides, head, head_copied, Some(put_back))) = &merge {
            let marker = Marker { sides: sides.clone(), head: head.clone(), head_copied: *head_copied, at: *put_back };
            if base.is_none() || !d.stamped.contains(&marker) {
                return reject("marker_not_restorable", Value::Null);
            }
        }
        let mut positions = Vec::new();
        for r in frame["runs"].as_array().expect("`runs`, a list") {
            let origin = r["origin"].as_str().unwrap().to_string();
            if !self.docs.contains_key(&origin) {
                return reject("source_not_registered", Value::Null);
            }
            let i_start: u64 = r["i_start"].as_str().unwrap().rsplit('.').next().unwrap().parse().unwrap();
            let width: u64 = r["width"].as_str().unwrap().parse().unwrap();
            for k in 0..width {
                if !self.values.contains_key(&(origin.clone(), i_start + k)) {
                    return reject("dangling_source", Value::Null);
                }
                positions.push((a(&origin), i_start + k));
            }
        }
        // The tell (R5): the trunk's current head where it is not the
        // one named.
        let head_moved = head.as_ref().and_then(|(h, _)| self.trunk_head.get(&trunk(h)).filter(|cur| **cur != *h).cloned());
        let runs = coalesce(positions);
        // ONE COMMIT of two records — the removal and the placement —
        // and a third where a base is recorded (the skepd suite's
        // `a_landing_sets_the_arrangement_records_the_base_and_the_marker_in_one_commit`),
        // so the number below the ack's `at` lies inside it.
        let recorded = base.as_ref().filter(|_| standing.is_some()).cloned();
        let at = self.commit_records("set_arrangement", vec![doc.clone()], if recorded.is_some() { 3 } else { 2 });
        let d = self.docs.get_mut(&doc).unwrap();
        d.runs = runs.clone();
        d.history.insert(at, runs);
        // The marker where a base is recorded — stamped at this commit,
        // or put back with the position named — and the row's term
        // whatever the base.
        if let Some(b) = &recorded {
            d.staged.insert(at, b.clone());
            let marker = merge.clone().map(|(sides, head, head_copied, put_back)| Marker { sides, head, head_copied, at: put_back.unwrap_or(at) });
            if let Some(m) = marker.as_ref().filter(|m| m.at == at) {
                d.stamped.push(m.clone());
            }
            d.markers.insert(at, marker);
        }
        // The row's two terms: the base recorded, and the request's merge.
        let row = self.rows.last_mut().expect("the commit's row");
        let term = |(sides, head, _, put_back): (Vec<String>, String, u64, Option<u64>)| {
            let mut term = json!({"sides": sides, "head": head});
            if let Some(put_back) = put_back {
                term["at"] = json!(put_back);
            }
            term
        };
        row.terms = Some((recorded.map(|(b, _)| b), merge.map(term)));
        let mut ack = json!({"resp": "ack", "at": at});
        if let Some(h) = head_moved {
            ack["head_moved"] = json!(h);
        }
        ack
    }
}

/// A permanent rejection of `op` carrying `code` and `site`.
fn permanent(op: &str, code: &str, site: Value) -> Value {
    let mut rej = json!({"resp": "rejected", "code": code, "disposition": "permanent", "op": op});
    if !site.is_null() {
        rej["site"] = site;
    }
    rej
}

/// The dialer over a world, every frame it served kept.
struct Scripted {
    world: Arc<Mutex<World>>,
    served: Mutex<Vec<(String, Value)>>,
    /// Whether each request served presented a token, in the order
    /// `served` keeps.
    presented: Mutex<Vec<bool>>,
}

impl Scripted {
    /// Every request served since the last clear, the handshake's
    /// included: its line as `served` keeps it, beside whether it
    /// presented a token.
    fn requests(&self) -> Vec<(String, bool)> {
        let served = self.served.lock().unwrap();
        let presented = self.presented.lock().unwrap();
        served.iter().map(|(line, _)| line.clone()).zip(presented.iter().copied()).collect()
    }

    /// The ops served, in order — `op` for `/op`, `at:op` for `/op-at`,
    /// the path for anything else — the handshake's own lines dropped.
    fn ops(&self) -> Vec<String> {
        self.served
            .lock()
            .unwrap()
            .iter()
            .map(|(line, _)| line.clone())
            .filter(|l| {
                !l.starts_with("GET /health")
                    && !l.starts_with("GET /challenge")
                    && !l.starts_with("POST /session")
                    && l != "principal_prefix"
                    && l != "key_set"
            })
            .collect()
    }

    /// The ops served as [`Scripted::ops`] lists them, each `/op-at`
    /// read by its inner op's name — the order of the reads whatever
    /// position each was made at.
    fn names(&self) -> Vec<String> {
        self.ops().into_iter().map(|o| o.strip_prefix("at:").map_or(o.clone(), str::to_string)).collect()
    }

    /// The frames of one op, in order — an `/op-at` read's inner frame.
    fn frames(&self, op: &str) -> Vec<Value> {
        let at_line = format!("at:{op}");
        self.served
            .lock()
            .unwrap()
            .iter()
            .filter_map(|(line, f)| {
                if line == op {
                    Some(f.clone())
                } else if *line == at_line {
                    Some(f["frame"].clone())
                } else {
                    None
                }
            })
            .collect()
    }

    /// The positions the `/op-at` reads of one op were asked as of, in
    /// order — a read answered `history_busy` counted with its position.
    fn positions(&self, op: &str) -> Vec<u64> {
        let at_line = format!("at:{op}");
        self.served
            .lock()
            .unwrap()
            .iter()
            .filter(|(line, _)| *line == at_line)
            .map(|(_, f)| f["at"].as_u64().expect("an `/op-at` body names its position"))
            .collect()
    }

    fn clear(&self) {
        self.served.lock().unwrap().clear();
        self.presented.lock().unwrap().clear();
    }

    /// The 1-based place of the first `op` among every request served
    /// since the last clear — the N a `World::interleave` names to land
    /// an edit before that frame is answered.
    fn served_index(&self, op: &str) -> usize {
        self.served
            .lock()
            .unwrap()
            .iter()
            .position(|(line, _)| line == op)
            .map(|i| i + 1)
            .unwrap_or_else(|| panic!("no `{op}` was served: {:?}", self.ops()))
    }

    fn world(&self) -> std::sync::MutexGuard<'_, World> {
        self.world.lock().unwrap()
    }
}

impl Dialer for Scripted {
    fn exchange(&self, _origin: &Origin, req: &Request) -> Result<Response, DialError> {
        let frame: Value = serde_json::from_slice(&req.body).unwrap_or(Value::Null);
        // The body kept whole: an `/op-at` read's `at` beside its frame.
        let (line, body) = match req.path.as_str() {
            "/op" => (frame["op"].as_str().unwrap_or("?").to_string(), frame.clone()),
            "/op-at" => {
                (format!("at:{}", frame["frame"]["op"].as_str().unwrap_or("?")), frame.clone())
            }
            p => (format!("{} {p}", req.method.as_str()), Value::Null),
        };
        let presented =
            req.headers.iter().any(|(k, _)| k.eq_ignore_ascii_case("Skepd-Session"));
        let served = {
            let mut served = self.served.lock().unwrap();
            served.push((line, body));
            self.presented.lock().unwrap().push(presented);
            served.len()
        };
        let mut w = self.world.lock().unwrap();
        // The session dies before this frame is answered.
        if w.die_at.is_some_and(|n| n == served || (n < served && presented)) {
            return Ok(crate::board::fake::closed());
        }
        // Another hand's edit lands before this frame is answered.
        if w.interleave.as_ref().is_some_and(|(n, _, _)| *n == served) {
            let (_, doc, runs) = w.interleave.take().unwrap();
            w.change(&doc, runs);
        }
        // The journal reclaimed before this frame is answered.
        if w.reclaim.is_some_and(|(n, _)| n == served) {
            let (_, floor) = w.reclaim.take().unwrap();
            w.floor = Some(floor);
        }
        // A grant withdrawn before this frame is answered.
        if w.withhold.as_ref().is_some_and(|(n, _)| *n == served) {
            let (_, doc) = w.withhold.take().unwrap();
            w.withheld.insert(doc);
        }
        // A record landing before the find that reads it.
        if frame["op"] == "find_links_ftt" {
            let finds = self.served.lock().unwrap().iter().filter(|(l, _)| l == "find_links_ftt").count();
            if w.link_before.as_ref().is_some_and(|(n, ..)| *n == finds) {
                let (_, link, row) = w.link_before.take().unwrap();
                w.links.push(link);
                w.rows.push(row);
            }
        }
        // A claim landing before this frame is answered, its head written.
        if req.path == "/op" && w.claim_before.is_some_and(|op| frame["op"] == op) {
            w.claim_before = None;
            w.claimed = true;
            w.head = true;
        }
        match req.path.as_str() {
            "/health" => Ok(reply(200, w.health())),
            "/op" => w.op(&frame, None),
            "/op-at" => {
                if w.busy > 0 {
                    w.busy -= 1;
                    return Ok(reply(503, json!({"error": "history_busy"})));
                }
                let at = frame["at"].as_u64();
                // A number past the committed head, or inside one commit.
                if let Some(at) = at {
                    if at > w.position {
                        return Ok(reply(
                            400,
                            json!({"error": "beyond_head", "head": w.position}),
                        ));
                    }
                    if w.inside_commits.contains(&at) {
                        let nearest = (0..at).rev().find(|n| !w.inside_commits.contains(n));
                        return Ok(reply(
                            400,
                            json!({"error": "not_a_position", "nearest": nearest}),
                        ));
                    }
                }
                if let (Some(floor), Some(at)) = (w.floor, at) {
                    if at < floor {
                        return Ok(reply(410, json!({"error": "history_reclaimed", "floor": floor})));
                    }
                }
                w.op(&frame["frame"], at)
            }
            "/session" => Ok(reply(200, json!({"session": TOKEN}))),
            "/session/close" => {
                Ok(Response { status: 204, headers: Headers::default(), body: Vec::new() })
            }
            p if p.starts_with("/challenge") => Ok(reply(
                200,
                json!({"nonce": "ab".repeat(32), "principal": 1, "ttl_ms": 60000}),
            )),
            p if p.starts_with("/changes?") => Ok(w.changes(p)),
            p => panic!("the merge dialed a path the scripted board does not answer: {p}"),
        }
    }

    fn stream(
        &self,
        _: &Origin,
        _: &RequestHead,
        _: &mut dyn std::io::Read,
        _: &mut dyn FnMut(&Headers),
    ) -> Result<StreamedResponse, DialError> {
        unreachable!("no read of the scripted board streams")
    }
}

fn signer() -> HybridSigner {
    crate::sign::signer_from_seed(&[42; 32])
}

/// A board over `world`, the merger's key enrolled.
fn open(mut world: World) -> (Arc<Scripted>, Board, HybridSigner) {
    let signer = signer();
    world.key = Some(Signer::public_key(&signer).clone());
    let dialer = Arc::new(Scripted {
        world: Arc::new(Mutex::new(world)),
        served: Mutex::new(Vec::new()),
        presented: Mutex::new(Vec::new()),
    });
    let board = Board::new(Origin::parse("http://127.0.0.1:8642").unwrap(), dialer.clone());
    (dialer, board, signer)
}

/// The merger's content-scoped session, through the one handshake.
fn sign_in<'b>(board: &'b Board, signer: &HybridSigner) -> Session<'b> {
    handshake(board, Scope::Content, signer, 1, Site::Session).expect("the session opens")
}

fn token() -> crate::board::Token {
    crate::board::Token::parse(TOKEN).unwrap()
}

/// Makes the board too busy for the merge journal's next find: its first
/// send and each of its bounded reissues refused `scan_busy`, so the
/// record step meets the find unanswered (the `journal` module's doc).
fn too_busy_for_the_find(w: &mut World) {
    w.scan_busy = crate::publication::SCAN_BUSY_REISSUES as usize + 1;
}

/// The race shape's inputs: the head `D.2`, the daughter `D.1.1`, the
/// base derived.
fn race_inputs() -> Inputs {
    Inputs {
        doc: a(D),
        head: a(&format!("{D}.2")),
        base: None,
        sides: vec![Side::Member(a(&format!("{D}.1.1")))],
        options: Options::default(),
        kind: a(K),
    }
}

fn m_runs(merged: &Merged) -> Vec<Run> {
    merged.composed.runs.iter().map(|p| p.run.clone()).collect()
}

/// The merger's facts off the session it opened, with its hand.
fn merger<'s>(session: &'s Session<'_>, signer: &'s HybridSigner) -> Merger<'s> {
    Merger { token: session.token(), account: session.account(), signer }
}

fn shot<'s>(session: &'s Session<'_>, signer: &'s HybridSigner) -> Landing<'s> {
    Landing::Shot { merger: merger(session, signer), draft: None, answers: Answers::default(), journal: None }
}

/// The id of one frame of a landing write: the [`Stem`] over `text`, the
/// text naming the write (the `land` module's doc), then the frame.
fn landing_id(text: &str, frame: &str) -> String {
    Stem::of(text).id(frame)
}

/// The draft landing's world: shape (2) — the head `D.2` "the big cat
/// sat" (the race shape's head, "big " fresh at `D·12`) and the staging
/// draft `S`, staged from the base `D.1` with "!!!" typed at its end.
fn draft_landing_world() -> World {
    let mut w = World::window_and_draft();
    w.text(D, 12, "big ");
    let head = vec![run(D, 1, 4), run(D, 12, 4), run(D, 5, 7)];
    for doc in [D.to_string(), format!("{D}.2")] {
        let d = w.docs.get_mut(&doc).unwrap();
        d.runs = head.clone();
        // The head as it stood from the start: every read is made at a
        // position, through the history.
        d.history = BTreeMap::from([(0, head.clone())]);
    }
    w
}

/// The draft side's inputs: `S` read at the composition's position.
fn draft_inputs() -> Inputs {
    Inputs {
        sides: vec![Side::Draft { at: a(S), position: None }],
        base: Some(a(&format!("{D}.1"))),
        ..race_inputs()
    }
}

/// M of the draft landing's world: "the big cat sat!!!".
fn draft_m() -> Vec<Run> {
    vec![run(D, 1, 4), run(D, 12, 4), run(D, 5, 7), run(S, 1, 3)]
}

/// A draft landing into `into`, or into a fresh draft where `None`.
fn draft_landing<'s>(session: &'s Session<'_>, signer: &'s HybridSigner, into: Option<Address>) -> Landing<'s> {
    Landing::Draft { merger: merger(session, signer), into, journal: None }
}

/// Returns `landed` as a call that finds it standing answers it.
///
/// A draft landing found standing is the one staged with nothing staged
/// now, `staged` false; every other landing is answered as it is.
fn as_found(landed: &Landed) -> Landed {
    let mut found = landed.clone();
    if let Landed::Draft { staged, .. } = &mut found {
        *staged = false;
    }
    found
}

/// M's runs as a `set_arrangement` frame spells them.
fn frame_runs(m: &[Run]) -> Value {
    Value::Array(m.iter().map(|r| json!({"origin": r.origin.to_string(), "i_start": i_addr(&r.origin, r.i_start), "width": r.width.to_string()})).collect())
}

/// Lands M into `S` as the draft landing does — the base re-recorded on
/// `D.2` at fifteen, the marker beside it, the record written — and
/// answers the composition with the landing.
fn landed_in_s(board: &Board, session: &Session<'_>, signer: &HybridSigner) -> (Merged, Landed) {
    let merged = compose(board, Some(session.token()), &draft_inputs()).expect("composed");
    let landed = land(board, &merged, draft_landing(session, signer, Some(a(S)))).expect("landed");
    (merged, landed)
}

/// A draft landing's position and its record's link.
fn landing_of(landed: &Landed) -> (u64, Address) {
    let Landed::Draft { position, record, .. } = landed else { panic!("{landed:?}") };
    (*position, record.clone())
}

/// C, the draft landing's `S` before the landing: the base's text by
/// identity and "!!!" after it.
fn draft_c() -> Vec<Run> {
    vec![run(D, 1, 11), run(S, 1, 3)]
}

/// Runs as a `set_arrangement` frame built by hand spells them.
fn shot_runs(m: &[Run]) -> Vec<Value> {
    m.iter().map(|r| frames::shot_run(&r.origin.to_string(), &i_addr(&r.origin, r.i_start), r.width)).collect()
}

/// The record a take-back appended, read off the one `insert` served.
fn appended_record(dialer: &Scripted) -> Value {
    let inserts = dialer.frames("insert");
    assert_eq!(inserts.len(), 1, "one record appended: {:?}", dialer.ops());
    serde_json::from_str(inserts[0]["values"][0]["atom"].as_str().expect("the atom")).expect("a record")
}

/// Plants a correspondence record of the merger's homed in `S`: `from`
/// `S·from`, `to` the trunk's `D·to`, `width` positions each.
fn plant_record(w: &mut World, from: u64, to: u64, width: u64) -> String {
    let addr = format!("{S}.0.2.{}", 90 + w.links.len());
    w.links.push(LinkRow {
        addr: addr.clone(),
        home: S.into(),
        from: vec![i_addr(&a(S), from)],
        to: vec![i_addr(&a(D), to)],
        ty: frames::T_CORRESPONDENCE.into(),
        width,
        at: None,
    });
    addr
}

/// A record with its atom in `journal` and its link homed there beside
/// it, to `to`, typed `K`, minted at `at` — none, a link the board
/// serves no position for, where the cell names none.
///
/// The journal is a private draft of the account its address lies in,
/// registered where the world holds none at that address.
fn file(w: &mut World, journal: &str, record: &Record, to: &[&str], at: Option<u64>) -> String {
    let n = w.fresh(journal);
    w.values.insert((journal.to_string(), n), Val::Atom(record.to_value().to_string()));
    let owner = crate::address::account_of(journal).expect("a journal's account");
    let d = w.docs.entry(journal.to_string()).or_insert_with(|| DocState {
        published: false,
        owner,
        ..DocState::default()
    });
    d.runs.push(run(journal, n, 1));
    let k = w.links.iter().filter(|l| l.home == journal).count() + 1;
    let addr = format!("{journal}.0.2.{k}");
    w.links.push(LinkRow {
        addr: addr.clone(),
        home: journal.into(),
        from: vec![i_addr(&a(journal), n)],
        to: to.iter().map(|t| t.to_string()).collect(),
        ty: K.into(),
        width: 1,
        at,
    });
    addr
}
