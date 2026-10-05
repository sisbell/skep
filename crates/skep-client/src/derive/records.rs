//! THE ONE ADMITTED READ (`client.md` §1.1; RULED, owner 2026-09-22 "i"; §9
//! items 44, 50): an account's credential RECORDS over its two residence
//! addresses — AUTH-5.68's discovery per AUTH-2.113, `find_links_ftt` over
//! the enroll and retire types naming the account, per record `read_link`
//! at the address it answered, a CONTENT READ bounded to the credential
//! atoms that discovery returned (`retrieve_v` at the atom's position, the
//! I→V inversion over `image`, AUTH-2.114), the BISECTION over `/op-at` for
//! each record's position (≤ log₂(head) reads, AUTH-5.68), and THE HAND: at
//! a record carrying its own `sig` — every record above the claim — the key
//! that VERIFIES it over the `record` frame, this store's own keys first,
//! then a trial over the set that opens the home's account AS OF THE
//! RECORD's BASE (AUTH-2.94; P12), the anchors alone at an anchor-grade act;
//! at a record with no `sig` — the ceremony's own genesis — `/changes.key`
//! at that position. BELOW THE RETENTION FLOOR a position-addressed read
//! answers `history_reclaimed` — an ANSWER, never an exit (§2.3) — and the
//! order is derived POSITION-FREE, genesis-first (AUTH-2.100) plus
//! link-address order (AUTH-5.69); the position and the hand are then not
//! derivable and the face asserts neither (§9 item 50). The label a
//! fingerprint carries is the one on the record that FIRST enrolled it
//! (AUTH-5.69).
//!
//! `H.1`'s pair is the record frame's `board` term and every entry frame's
//! (cs6-2), read once per board by [`Board::board_term`].

use std::collections::HashMap;
use std::thread;
use std::time::Duration;

use serde_json::Value;
use skep_address::{validate, Address, Nat, Tumbler};
use skep_identity::{
    canonical_record, entry_body_record, entry_frame, parse_record_value, BoardTerm, DocTerm, Enrollment,
    Fingerprint, PublicKey, RecordRows,
};

use crate::board::{frames, Answer, AtAnswer, Board, ChangeKey, KeySet, KeySetAnswer, T_CLAIM, T_ENROLL, T_RETIRE};
use crate::halt::Halt;

/// A credential record's kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Enroll,
    Retire,
}

/// THE HAND that wrote a record, as this read names it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Hand {
    /// A key: the one that verifies the record's own `sig`, or the one
    /// `/changes.key` testifies at an unsigned row.
    Key(Fingerprint),
    /// An unsigned row's bare-session testimony — the ceremony's genesis.
    Bare,
    /// The board's own daemon.
    System,
    /// A `sig` NO candidate verifies — an operator's hand past the check
    /// (AUTH-4.54), or a record carried from another home or board: "signed
    /// by no key of this account's set", inert to the filter.
    NoKeyVerifies,
    /// Not readable here, and the face asserts none: below the retention
    /// floor, a lost testimony, no `H.1`.
    Unreadable(String),
}

/// One credential record, as read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub kind: Kind,
    /// The deposit's link address.
    pub link: String,
    /// The home — a doc 1 (AUTH-2.127).
    pub home: String,
    /// The home's account (ω over the home).
    pub home_account: String,
    /// The subject — the link's `to`, the account the read was made for.
    pub subject: String,
    /// The record atom's I-address.
    pub atom: String,
    /// The record's own bytes, as the atom holds them.
    pub bytes: Vec<u8>,
    /// The SIG-LESS canonical record (AUTH-4.58: the record's identity).
    pub sigless: String,
    /// The `sig` member, where the record carries one.
    pub sig: Option<String>,
    /// An enrollment's entries.
    pub enrolled: Vec<Enrollment>,
    /// A retirement's fingerprints.
    pub retired: Vec<Fingerprint>,
    /// The commit position, where it is above the floor.
    pub position: Option<u64>,
    /// The base — the greatest committed position below `position`.
    pub base: Option<u64>,
    /// The hand.
    pub hand: Hand,
    /// Whether the act is ANCHOR-GRADE: an anchor-flagged enrollment, a
    /// retirement naming an anchor (the `anchor_session_required` cases).
    pub anchor_grade: bool,
}

/// The read's answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Records {
    pub account: String,
    /// Genesis-first, then by position where known, then link-address order.
    pub records: Vec<Record>,
    /// The committed head the read was made at.
    pub head: u64,
    /// The retention floor, where a position-addressed read met it.
    pub floor: Option<u64>,
    /// THE ATTESTATION BOUNDARY — the board's CLAIM ENTRY, read as the
    /// position of the claim link `find_links` answers (SIGNED-OPS §5.5 as
    /// RULED); `None` while unclaimed, or below the floor (UNDETERMINABLE).
    pub claim_entry: Option<u64>,
    /// Whether the board is claimed at all.
    pub claimed: bool,
}

impl Records {
    /// The GENESIS record — the first of the read (AUTH-2.100: genesis at
    /// most once).
    pub fn genesis(&self) -> Option<&Record> {
        self.records.iter().find(|r| r.kind == Kind::Enroll)
    }

    /// AUTH-5.69 — the label carried by the record that FIRST enrolled
    /// `fp`; every later mention is informational.
    pub fn label_of(&self, fp: &Fingerprint) -> Option<String> {
        self.records.iter().filter(|r| r.kind == Kind::Enroll).find_map(|r| {
            r.enrolled.iter().find(|e| Fingerprint::of(&e.key) == *fp).map(|e| e.label().unwrap_or("").to_string())
        })
    }

    /// The retirement record naming `fp`, where one stands.
    pub fn retirement_of(&self, fp: &Fingerprint) -> Option<&Record> {
        self.records.iter().find(|r| r.kind == Kind::Retire && r.retired.contains(fp))
    }
}

/// One entry the person HOLDS — the payload this device composed, or an
/// anchor file's public members — for THE WHOLE-SET COMPARE (`client.md`
/// §2.2 `verify`; AUTH-4.58's detection; P25): fingerprint and anchor flag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Held {
    pub fingerprint: Fingerprint,
    pub anchor: bool,
    pub label: Option<String>,
}

/// One difference between the GENESIS RECORD and what the person holds —
/// a key added, a key missing, a flag flipped: HALT in AUTH-5.53's terms,
/// this account is NOT yours to keep as it stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Difference {
    /// In the genesis and not held.
    Added { fingerprint: Fingerprint, anchor: bool, label: Option<String> },
    /// Held and not in the genesis.
    Missing { fingerprint: Fingerprint, anchor: bool, label: Option<String> },
    /// Held and present, the anchor flag flipped.
    FlagFlipped { fingerprint: Fingerprint, held_anchor: bool, genesis_anchor: bool },
}

/// THE WHOLE-SET COMPARE's answer: the differences, and the current set's
/// FURTHER entries listed as LATER acts for the person to recognise (P27),
/// never as differences.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WholeSet {
    pub differences: Vec<Difference>,
    pub later: Vec<Held>,
}

/// THE WHOLE-SET COMPARE: the genesis record — the first of the admitted
/// read, its bytes readable position-free below the floor — entry for entry,
/// fingerprint AND anchor flag, against `held`; the current enrolled set's
/// further entries as later acts. `None` where the account has no genesis
/// record to compare against.
pub fn compare_whole_set(records: &Records, current: &KeySet, held: &[Held]) -> Option<WholeSet> {
    let genesis = records.genesis()?;
    let mut differences = Vec::new();
    let genesis_entries: Vec<Held> = genesis
        .enrolled
        .iter()
        .map(|e| Held { fingerprint: Fingerprint::of(&e.key), anchor: e.anchor, label: e.label().map(str::to_string) })
        .collect();
    for g in &genesis_entries {
        match held.iter().find(|h| h.fingerprint == g.fingerprint) {
            None => differences.push(Difference::Added { fingerprint: g.fingerprint, anchor: g.anchor, label: g.label.clone() }),
            Some(h) if h.anchor != g.anchor => {
                differences.push(Difference::FlagFlipped { fingerprint: g.fingerprint, held_anchor: h.anchor, genesis_anchor: g.anchor })
            }
            Some(_) => {}
        }
    }
    for h in held {
        if !genesis_entries.iter().any(|g| g.fingerprint == h.fingerprint) {
            differences.push(Difference::Missing { fingerprint: h.fingerprint, anchor: h.anchor, label: h.label.clone() });
        }
    }
    let later: Vec<Held> = current
        .enrolled
        .iter()
        .filter(|e| !genesis_entries.iter().any(|g| g.fingerprint == e.fingerprint))
        .map(|e| Held { fingerprint: e.fingerprint, anchor: e.anchor, label: records.label_of(&e.fingerprint).filter(|l| !l.is_empty()) })
        .collect();
    Some(WholeSet { differences, later })
}

/// Parse an address in its dotted-decimal spelling.
pub fn parse_address(s: &str) -> Option<Address> {
    let comps: Option<Vec<Nat>> = s.split('.').map(|c| c.parse::<u64>().ok().map(Nat::from)).collect();
    validate(Tumbler::new(comps?).ok()?).ok()
}

/// The document an element or link address lies in: the components through
/// the one after the SECOND `0` separator.
pub fn document_of(addr: &str) -> Option<String> {
    let comps: Vec<&str> = addr.split('.').collect();
    let mut zeros = comps.iter().enumerate().filter(|(_, c)| **c == "0").map(|(i, _)| i);
    let (_first, second) = (zeros.next()?, zeros.next()?);
    (second + 1 < comps.len()).then(|| comps[..=second + 1].join("."))
}

/// THE RECORD FRAME a credential record's `sig` is made over (the record
/// grade; wire.md §The claim ceremony and credentials): `framed("skep-entry-v1",
/// [alg, board, account, doc, "record", body])` — `alg` the signing key's
/// token, `board` `H.1`'s pair, `account` the HOME's account, `doc` the home,
/// the body the five rows over the sig-less canonical record. Composed by
/// `skep_identity::entry_frame`, spelled by nobody here.
pub fn record_frame(alg: &str, board: BoardTerm, home_account: &str, home: &str, ty: &str, to: &[&str], sigless: &[u8]) -> Option<Vec<u8>> {
    let account = parse_address(home_account)?;
    let home = parse_address(home)?;
    let ty = parse_address(ty)?;
    let to: Vec<Address> = to.iter().map(|a| parse_address(a)).collect::<Option<_>>()?;
    let body = entry_body_record(RecordRows { ty: &ty, to: &to, replaces: None, lineage_fork_point: None, sigless_canonical_record: sigless });
    Some(entry_frame(alg, board, &account, DocTerm::One(&home), &body))
}

/// THE TRIAL: the first candidate under whose own row both halves of `blob`
/// verify over `frame` (AUTH-4.32's rule, as `skep_signature::verify` holds
/// it) — the frame re-composed per candidate since `alg` names the signing
/// key's token.
pub fn trial<'a>(
    board: BoardTerm,
    home_account: &str,
    home: &str,
    ty: &str,
    to: &[&str],
    sigless: &[u8],
    blob: &[u8],
    candidates: impl IntoIterator<Item = (&'a Fingerprint, &'a PublicKey)>,
) -> Option<Fingerprint> {
    for (fp, key) in candidates {
        let row = key.sig_alg_row();
        let Some(frame) = record_frame(row.token, board, home_account, home, ty, to, sigless) else { return None };
        if skep_signature::verify(row.tag, key, &frame, blob).is_ok() {
            return Some(*fp);
        }
    }
    None
}

/// One `/op-at` probe of a link's presence.
enum Probe {
    Present,
    Absent,
    Reclaimed { floor: Option<u64> },
    NotAPosition { nearest: Option<u64> },
}

fn probe(board: &Board, at: u64, frame: &Value, link: &str) -> Result<Probe, Halt> {
    for attempt in 0..8 {
        match board.op_at(None, at, frame)? {
            AtAnswer::Document(v) => {
                let present = v["addrs"].as_array().is_some_and(|a| a.iter().any(|x| x.as_str() == Some(link)));
                return Ok(if present { Probe::Present } else { Probe::Absent });
            }
            AtAnswer::HistoryReclaimed { floor } => return Ok(Probe::Reclaimed { floor }),
            AtAnswer::NotAPosition { nearest } => return Ok(Probe::NotAPosition { nearest }),
            AtAnswer::BeyondHead { .. } => return Ok(Probe::Absent),
            AtAnswer::Closed => return Ok(Probe::Absent),
            AtAnswer::Busy => thread::sleep(Duration::from_millis(20 * (attempt + 1))),
        }
    }
    Err(Halt::face(
        "the board's history reads stayed busy",
        "`/op-at` answered `history_busy` eight times running: every reconstruction permit is in use",
        "retry shortly; a historical read is bounded by the board's reconstruction pool",
    ))
}

/// THE BISECTION (AUTH-5.68): the least position at which `find_links_ftt`
/// returns the link, or `None` below the floor; the floor met, if any.
fn position_of(board: &Board, frame: &Value, link: &str, head: u64) -> Result<(Option<u64>, Option<u64>), Halt> {
    // The lowest readable position first: a 410 names the floor.
    let mut floor: Option<u64> = None;
    let mut lo: u64 = 0; // absent, or unreadable, here
    match probe(board, 0, frame, link)? {
        Probe::Reclaimed { floor: f } => {
            let f = f.unwrap_or(1);
            floor = Some(f);
            match probe(board, f, frame, link)? {
                Probe::Present => return Ok((None, floor)),
                Probe::Reclaimed { .. } => return Ok((None, floor)),
                _ => lo = f,
            }
        }
        Probe::Present => return Ok((Some(0), None)),
        _ => {}
    }
    let mut hi = head;
    match probe(board, hi, frame, link)? {
        Probe::Present => {}
        Probe::NotAPosition { nearest: Some(n) } => hi = n,
        _ => return Ok((None, floor)),
    }
    while hi > lo + 1 {
        let mid = lo + (hi - lo) / 2;
        match probe(board, mid, frame, link)? {
            Probe::Present => hi = mid,
            Probe::Absent => lo = mid,
            Probe::Reclaimed { floor: f } => {
                floor = floor.or(f);
                lo = mid;
            }
            Probe::NotAPosition { nearest } => match nearest {
                Some(n) if n > lo => match probe(board, n, frame, link)? {
                    Probe::Present => hi = n,
                    _ => lo = mid,
                },
                _ => lo = mid,
            },
        }
    }
    Ok((Some(hi), floor))
}

/// The base of a record at `position`: the greatest committed position
/// below it.
fn base_of(board: &Board, position: u64) -> Result<Option<u64>, Halt> {
    if position == 0 {
        return Ok(None);
    }
    let frame = frames::span_set(crate::board::HEAD_DOCUMENT);
    for attempt in 0..8 {
        return match board.op_at(None, position - 1, &frame)? {
            AtAnswer::Document(_) => Ok(Some(position - 1)),
            AtAnswer::NotAPosition { nearest } => Ok(nearest),
            AtAnswer::Busy => {
                thread::sleep(Duration::from_millis(20 * (attempt + 1)));
                continue;
            }
            _ => Ok(None),
        };
    }
    Ok(None)
}

/// The set that opens `account` AS OF `at`: `key_set` at the account and,
/// while empty, at each account above it (AUTH-4.30 (i)), at that position.
fn set_opening_at(board: &Board, account: &str, at: u64) -> Result<Option<KeySet>, Halt> {
    let mut acc = account.to_string();
    loop {
        match board.key_set_at(&acc, at)? {
            Some(KeySetAnswer::Set(set)) if !set.is_empty() => return Ok(Some(set)),
            Some(KeySetAnswer::Set(_)) => match super::parent_account(&acc) {
                Some(p) => acc = p,
                None => return Ok(Some(KeySet::default())),
            },
            _ => return Ok(None),
        }
    }
}

/// A home's I→V inversion (AUTH-2.114): every content I-address of the
/// document, keyed to its V-ordinal, off `retrieve_doc_v_span_set` and
/// `image`.
fn inversion(board: &Board, home: &str) -> Result<HashMap<String, u64>, Halt> {
    let mut map = HashMap::new();
    let Answer::Document(set) = board.op(None, &frames::span_set(home))? else { return Ok(map) };
    let extent: u64 = set["set"]
        .as_array()
        .and_then(|s| s.iter().find(|x| x["start"].as_str() == Some("1.1")))
        .and_then(|s| s["width"].as_str()?.rsplit('.').next()?.parse().ok())
        .unwrap_or(0);
    if extent == 0 {
        return Ok(map);
    }
    let Answer::Document(image) = board.op(None, &frames::image(home, 1, extent))? else { return Ok(map) };
    let mut ordinal: u64 = 1;
    for run in image["runs"].as_array().into_iter().flatten() {
        let (Some(start), Some(width)) = (run["i_start"].as_str(), run["width"].as_str().and_then(|w| w.parse::<u64>().ok())) else { continue };
        let Some((prefix, last)) = start.rsplit_once('.') else { continue };
        let Ok(first) = last.parse::<u64>() else { continue };
        for k in 0..width {
            map.insert(format!("{prefix}.{}", first + k), ordinal);
            ordinal += 1;
        }
    }
    Ok(map)
}

/// The record atom's bytes at `atom` in `home`, through the inversion.
fn atom_bytes(board: &Board, home: &str, inv: &HashMap<String, u64>, atom: &str) -> Result<Option<Vec<u8>>, Halt> {
    let Some(ordinal) = inv.get(atom) else { return Ok(None) };
    let Answer::Document(v) = board.op(None, &frames::retrieve_v(home, *ordinal, 1))? else { return Ok(None) };
    let Some(item) = v["items"].as_array().and_then(|i| i.first()) else { return Ok(None) };
    if let Some(text) = item["atom"].as_str() {
        return Ok(Some(text.as_bytes().to_vec()));
    }
    if let Some(hex) = item["atom_hex"].as_str() {
        return Ok(crate::hex::decode(hex));
    }
    Ok(None)
}

/// The deposit's link addresses of `ty` naming `account`, in address order.
fn links_of(board: &Board, ty: &str, account: &str) -> Result<Vec<String>, Halt> {
    let Answer::Document(v) = board.op(None, &frames::find_links_ftt(ty, account))? else { return Ok(Vec::new()) };
    let mut links: Vec<String> =
        v["addrs"].as_array().into_iter().flatten().filter_map(|a| a.as_str().map(str::to_string)).collect();
    links.sort_by(address_order);
    Ok(links)
}

/// Address order over dotted-decimal spellings: component by component.
fn address_order(a: &String, b: &String) -> std::cmp::Ordering {
    let ca: Vec<u128> = a.split('.').filter_map(|c| c.parse().ok()).collect();
    let cb: Vec<u128> = b.split('.').filter_map(|c| c.parse().ok()).collect();
    ca.cmp(&cb)
}

/// THE READ, once per walk: the account's credential records with their
/// positions and hands. `own` is this store's own keys, tried first at a
/// signed record's hand.
pub fn credential_records(board: &Board, account: &str, own: &[(Fingerprint, PublicKey)]) -> Result<Records, Halt> {
    let health = board.health()?;
    let head = health.log_position();
    let claimed = health.claimant().is_some();
    let term = board.board_term()?;
    let mut floor: Option<u64> = None;

    // The attestation boundary: the claim link's position.
    let mut claim_entry = None;
    if claimed {
        if let Some(claimant) = health.claimant() {
            let frame = frames::find_links_ftt_from(T_CLAIM, claimant);
            if let Answer::Document(v) = board.op(None, &frame)? {
                if let Some(link) = v["addrs"].as_array().and_then(|a| a.first()).and_then(Value::as_str) {
                    let (pos, f) = position_of(board, &frame, link, head)?;
                    claim_entry = pos;
                    floor = floor.or(f);
                }
            }
        }
    }

    let mut inversions: HashMap<String, HashMap<String, u64>> = HashMap::new();
    let mut owners: HashMap<String, String> = HashMap::new();
    let mut records = Vec::new();
    for (kind, ty) in [(Kind::Enroll, T_ENROLL), (Kind::Retire, T_RETIRE)] {
        for link in links_of(board, ty, account)? {
            let Some(home) = document_of(&link) else { continue };
            let Answer::Document(lv) = board.op(None, &frames::read_link(&link))? else { continue };
            // The four-set query matches by span OVERLAP, so a link naming an
            // account ABOVE this one (its subtree covering this address)
            // answers too: the record is this account's only where the link's
            // own `to` names it (AUTH-2.113's residence read is per subject).
            let to = lv["link"]["slots"].as_array().and_then(|s| s.get(1)).and_then(Value::as_array).and_then(|t| t.first()).and_then(|span| span["start"].as_str());
            if to != Some(account) {
                continue;
            }
            let Some(atom) = lv["link"]["slots"].as_array().and_then(|s| s.first()).and_then(|from| from.as_array()).and_then(|f| f.first()).and_then(|span| span["start"].as_str()) else { continue };
            if !inversions.contains_key(&home) {
                inversions.insert(home.clone(), inversion(board, &home)?);
            }
            let Some(bytes) = atom_bytes(board, &home, &inversions[&home], atom)? else { continue };
            let home_account = match owners.get(&home) {
                Some(a) => a.clone(),
                None => {
                    let a = board.effective_owner(&home)?.map(|o| o.prefix).unwrap_or_default();
                    owners.insert(home.clone(), a.clone());
                    a
                }
            };
            let (enrolled, retired, sig, sigless, anchor_grade) = match kind {
                Kind::Enroll => match parse_record_value::<Enrollment>(&bytes) {
                    Ok(v) => {
                        let grade = v.entries.iter().any(|e| e.anchor);
                        (v.entries.clone(), Vec::new(), v.sig.clone(), canonical_record(&v.entries, None), grade)
                    }
                    Err(_) => continue,
                },
                Kind::Retire => match parse_record_value::<Fingerprint>(&bytes) {
                    Ok(v) => (Vec::new(), v.entries.clone(), v.sig.clone(), canonical_record(&v.entries, None), false),
                    Err(_) => continue,
                },
            };
            let frame = frames::find_links_ftt(ty, account);
            let (position, f) = position_of(board, &frame, &link, head)?;
            floor = floor.or(f);
            let base = match position {
                Some(p) => base_of(board, p)?,
                None => None,
            };
            // A retirement is anchor-grade where it names an anchor of the
            // set as of its base (the `anchor_session_required` cases).
            let anchor_grade = match (kind, base) {
                (Kind::Retire, Some(b)) => match set_opening_at(board, &home_account, b)? {
                    Some(set) => retired.iter().any(|fp| set.enrolled(fp).is_some_and(|e| e.anchor)),
                    None => false,
                },
                _ => anchor_grade,
            };
            let mut record = Record {
                kind,
                link: link.clone(),
                home: home.clone(),
                home_account: home_account.clone(),
                subject: account.to_string(),
                atom: atom.to_string(),
                bytes,
                sigless,
                sig,
                enrolled,
                retired,
                position,
                base,
                hand: Hand::Unreadable("not yet read".into()),
                anchor_grade,
            };
            record.hand = hand_of(board, &record, term, own, base)?;
            records.push(record);
        }
    }

    // Genesis-first, then by position, then link-address order (AUTH-5.69's
    // position-free arm): the genesis is the enrollment homed in the genesis
    // registry's doc 1 — another account's, or the own doc 1's lowest link.
    records.sort_by(|a, b| {
        let genesis = |r: &Record| (r.kind == Kind::Enroll && r.home_account != account) as u8;
        genesis(b).cmp(&genesis(a)).then_with(|| match (a.position, b.position) {
            (Some(x), Some(y)) => x.cmp(&y),
            (Some(_), None) => std::cmp::Ordering::Greater,
            (None, Some(_)) => std::cmp::Ordering::Less,
            (None, None) => address_order(&a.home, &b.home).then_with(|| address_order(&a.link, &b.link)),
        })
    });
    Ok(Records { account: account.to_string(), records, head, floor, claim_entry, claimed })
}

/// THE HAND of one record: a signed record's by the trial, an unsigned one's
/// by `/changes.key` at its position; unreadable where the inputs are not.
fn hand_of(board: &Board, record: &Record, term: Option<BoardTerm>, own: &[(Fingerprint, PublicKey)], base: Option<u64>) -> Result<Hand, Halt> {
    let ty = match record.kind {
        Kind::Enroll => T_ENROLL,
        Kind::Retire => T_RETIRE,
    };
    let to = [record.subject.as_str()];
    match &record.sig {
        Some(sig_hex) => {
            let Some(term) = term else { return Ok(Hand::Unreadable("the board has no H.1, so no record frame can be composed".into())) };
            let Some(blob) = crate::hex::decode(sig_hex) else { return Ok(Hand::NoKeyVerifies) };
            // This store's own keys first.
            if let Some(fp) = trial(term, &record.home_account, &record.home, ty, &to, record.sigless.as_bytes(), &blob, own.iter().map(|(f, k)| (f, k))) {
                return Ok(Hand::Key(fp));
            }
            let Some(base) = base else { return Ok(Hand::Unreadable("below the retention floor: the record's base is not readable at this board".into())) };
            let Some(set) = set_opening_at(board, &record.home_account, base)? else {
                return Ok(Hand::Unreadable("the set as of the record's base is not readable at this board".into()));
            };
            let candidates: Vec<(&Fingerprint, &PublicKey)> =
                set.enrolled.iter().filter(|e| !record.anchor_grade || e.anchor).map(|e| (&e.fingerprint, &e.key)).collect();
            Ok(match trial(term, &record.home_account, &record.home, ty, &to, record.sigless.as_bytes(), &blob, candidates) {
                Some(fp) => Hand::Key(fp),
                None => Hand::NoKeyVerifies,
            })
        }
        None => match record.position {
            None => Ok(Hand::Unreadable("below the retention floor: the position does not answer, and the hand with it".into())),
            Some(p) => Ok(match board.changes_key(None, p)? {
                ChangeKey::Key(fp) => Hand::Key(fp),
                ChangeKey::Bare => Hand::Bare,
                ChangeKey::System => Hand::System,
                ChangeKey::Lost => Hand::Unreadable("the row's testimony was lost (`key: null`)".into()),
                ChangeKey::Signed => Hand::Unreadable("the row carries no testimony and the record no `sig`".into()),
                ChangeKey::NoEntry => Hand::Unreadable("no feed row at the record's position".into()),
                ChangeKey::HistoryReclaimed { .. } => Hand::Unreadable("below the feed's floor".into()),
            }),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_document_of_a_link_or_element_address() {
        assert_eq!(document_of("1.0.1.0.1.0.2.3"), Some("1.0.1.0.1".into()));
        assert_eq!(document_of("1.0.1.0.1.0.1.1"), Some("1.0.1.0.1".into()));
        assert_eq!(document_of("1.0.1.1.0.1.0.2.1"), Some("1.0.1.1.0.1".into()));
        assert_eq!(document_of("1.0.1"), None);
    }

    #[test]
    fn addresses_order_by_component() {
        let mut v = vec!["1.0.1.0.1.0.2.10".to_string(), "1.0.1.0.1.0.2.2".to_string()];
        v.sort_by(address_order);
        assert_eq!(v, ["1.0.1.0.1.0.2.2", "1.0.1.0.1.0.2.10"]);
    }
}
