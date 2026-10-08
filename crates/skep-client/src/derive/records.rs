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
//! (cs6-2), read once per board by [`Board::board_term`]; the frame itself is
//! [`RecordFrame`]'s, the bytes the writing hand signed.

use std::collections::HashMap;
use std::thread;
use std::time::Duration;

use serde_json::Value;
use skep_identity::{parse_record_value, BoardTerm, Enrollment, Fingerprint, PublicKey};

use crate::address::{document_of, parent_account};
use crate::board::{answers, frames, AtAnswer, Board, ChangeKey, KeySet, KeySetAnswer, T_CLAIM, T_ENROLL, T_RETIRE};
use crate::halt::Halt;
use crate::sign::RecordFrame;

/// A credential record's kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Enroll,
    Retire,
}

impl Kind {
    /// The record class's type address — the deposit's declaration, its
    /// link's type and the record frame's `ty` row alike (AUTH-5.4;
    /// PUB-2.63).
    pub fn type_address(self) -> &'static str {
        match self {
            Kind::Enroll => T_ENROLL,
            Kind::Retire => T_RETIRE,
        }
    }
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

    /// The record that FIRST enrolled `fp` (AUTH-5.69), where one stands —
    /// the one whose label the key carries, and whose link a supersession
    /// trail names as its `old` (AUTH-5.59 step 2).
    pub fn enrollment_of(&self, fp: &Fingerprint) -> Option<&Record> {
        self.records.iter().find(|r| r.kind == Kind::Enroll && r.enrolled.iter().any(|e| Fingerprint::of(&e.key) == *fp))
    }

    /// AUTH-5.69 — the label carried by the record that FIRST enrolled
    /// `fp`, `None` where that record carried none (a label is never empty,
    /// AUTH-1.24); every later mention is informational.
    pub fn label_of(&self, fp: &Fingerprint) -> Option<String> {
        self.enrollment_of(fp)?.enrolled.iter().find(|e| Fingerprint::of(&e.key) == *fp)?.label().map(str::to_string)
    }

    /// The retirement record naming `fp`, where one stands.
    pub fn retirement_of(&self, fp: &Fingerprint) -> Option<&Record> {
        self.records.iter().find(|r| r.kind == Kind::Retire && r.retired.contains(fp))
    }

    /// The label of a hand, where the hand is a key this account's records
    /// first enrolled (AUTH-5.69).
    pub fn label_of_hand(&self, hand: &Hand) -> Option<String> {
        match hand {
            Hand::Key(fp) => self.label_of(fp),
            _ => None,
        }
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
        .map(|e| Held { fingerprint: e.fingerprint, anchor: e.anchor, label: records.label_of(&e.fingerprint) })
        .collect();
    Some(WholeSet { differences, later })
}

impl Record {
    /// THE TRIAL: the first candidate under whose own row both halves of
    /// `blob` verify over this record's `record` frame (AUTH-4.32's rule, as
    /// `skep_signature::verify` holds it) — the frame composed from the
    /// record's own home, home account, kind, subject and sig-less body, and
    /// re-composed per candidate since `alg` names the signing key's token.
    pub fn signed_by<'a>(&self, term: BoardTerm, blob: &[u8], candidates: impl IntoIterator<Item = (&'a Fingerprint, &'a PublicKey)>) -> Option<Fingerprint> {
        let to = [self.subject.as_str()];
        for (fp, key) in candidates {
            let row = key.sig_alg_row();
            let frame = RecordFrame {
                alg: row.token,
                board: term,
                home_account: &self.home_account,
                home: &self.home,
                ty: self.kind.type_address(),
                to: &to,
                sigless: self.sigless.as_bytes(),
            }
            .compose()?;
            if skep_signature::verify(row.tag, key, &frame, blob).is_ok() {
                return Some(*fp);
            }
        }
        None
    }
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
                let present = answers::addrs(&v).contains(&link);
                return Ok(if present { Probe::Present } else { Probe::Absent });
            }
            AtAnswer::HistoryReclaimed { floor } => return Ok(Probe::Reclaimed { floor }),
            AtAnswer::NotAPosition { nearest } => return Ok(Probe::NotAPosition { nearest }),
            AtAnswer::BeyondHead { .. } => return Ok(Probe::Absent),
            AtAnswer::Closed => unreachable!("a token-free `op_at` halts on the death signal and never answers it"),
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
            Some(KeySetAnswer::Set(_)) => match parent_account(&acc) {
                Some(p) => acc = p,
                None => return Ok(Some(KeySet::default())),
            },
            _ => return Ok(None),
        }
    }
}

/// A home's I→V inversion (AUTH-2.114): every content I-address of the
/// document, keyed to its V-ordinal, off `retrieve_doc_v_span_set` and
/// `image` — empty where the I-map does not read whole, so the home's
/// records read as unreadable and never as another position's bytes.
fn inversion(board: &Board, home: &str) -> Result<HashMap<String, u64>, Halt> {
    let extent = answers::content_extent(&board.guest(&frames::span_set(home))?);
    if extent == 0 {
        return Ok(HashMap::new());
    }
    let image = board.guest(&frames::image(home, 1, extent))?;
    Ok(answers::i_map(&image).unwrap_or_default().into_iter().collect())
}

/// The record atom's bytes at `atom` in `home`, through the inversion.
fn atom_bytes(board: &Board, home: &str, inv: &HashMap<String, u64>, atom: &str) -> Result<Option<Vec<u8>>, Halt> {
    let Some(ordinal) = inv.get(atom) else { return Ok(None) };
    Ok(answers::first_atom(&board.guest(&frames::retrieve_v(home, *ordinal, 1))?))
}

/// The deposit's link addresses of `ty` naming `account`, in address order.
fn links_of(board: &Board, ty: &str, account: &str) -> Result<Vec<String>, Halt> {
    let v = board.guest(&frames::find_links_ftt(ty, account))?;
    let mut links: Vec<String> = answers::addrs(&v).into_iter().map(str::to_string).collect();
    links.sort_by_cached_key(|l| components(l));
    Ok(links)
}

/// A dotted-decimal spelling's components — the key address order sorts
/// by, component by component.
fn components(address: &str) -> Vec<u128> {
    address.split('.').filter_map(|c| c.parse().ok()).collect()
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
            let v = board.guest(&frame)?;
            if let Some(link) = answers::addrs(&v).first().copied() {
                let (pos, f) = position_of(board, &frame, link, head)?;
                claim_entry = pos;
                floor = floor.or(f);
            }
        }
    }

    let mut inversions: HashMap<String, HashMap<String, u64>> = HashMap::new();
    let mut owners: HashMap<String, String> = HashMap::new();
    let mut records = Vec::new();
    for kind in [Kind::Enroll, Kind::Retire] {
        let ty = kind.type_address();
        for link in links_of(board, ty, account)? {
            let Some(home) = document_of(&link) else { continue };
            let lv = board.guest(&frames::read_link(&link))?;
            // The four-set query matches by span OVERLAP, so a link naming an
            // account ABOVE this one (its subtree covering this address)
            // answers too: the record is this account's only where the link's
            // own `to` names it (AUTH-2.113's residence read is per subject).
            if answers::link_to(&lv) != Some(account) {
                continue;
            }
            let Some(atom) = answers::link_from(&lv) else { continue };
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
                        let sigless = v.sigless_canonical_record();
                        (v.entries, Vec::new(), v.sig, sigless, grade)
                    }
                    Err(_) => continue,
                },
                Kind::Retire => match parse_record_value::<Fingerprint>(&bytes) {
                    Ok(v) => {
                        let sigless = v.sigless_canonical_record();
                        (Vec::new(), v.entries, v.sig, sigless, false)
                    }
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
            (None, None) => components(&a.home).cmp(&components(&b.home)).then_with(|| components(&a.link).cmp(&components(&b.link))),
        })
    });
    Ok(Records { account: account.to_string(), records, head, floor, claim_entry, claimed })
}

/// THE HAND of one record: a signed record's by the trial, an unsigned one's
/// by `/changes.key` at its position; unreadable where the inputs are not.
fn hand_of(board: &Board, record: &Record, term: Option<BoardTerm>, own: &[(Fingerprint, PublicKey)], base: Option<u64>) -> Result<Hand, Halt> {
    match &record.sig {
        Some(sig_hex) => {
            let Some(term) = term else { return Ok(Hand::Unreadable("the board has no H.1, so no record frame can be composed".into())) };
            let Some(blob) = crate::hex::decode(sig_hex) else { return Ok(Hand::NoKeyVerifies) };
            // This store's own keys first.
            if let Some(fp) = record.signed_by(term, &blob, own.iter().map(|(f, k)| (f, k))) {
                return Ok(Hand::Key(fp));
            }
            let Some(base) = base else { return Ok(Hand::Unreadable("below the retention floor: the record's base is not readable at this board".into())) };
            let Some(set) = set_opening_at(board, &record.home_account, base)? else {
                return Ok(Hand::Unreadable("the set as of the record's base is not readable at this board".into()));
            };
            let candidates = set.enrolled.iter().filter(|e| !record.anchor_grade || e.anchor).map(|e| (&e.fingerprint, &e.key));
            Ok(match record.signed_by(term, &blob, candidates) {
                Some(fp) => Hand::Key(fp),
                None => Hand::NoKeyVerifies,
            })
        }
        None => match record.position {
            None => Ok(Hand::Unreadable("below the retention floor: the position does not answer, and the hand with it".into())),
            Some(p) => Ok(match board.changes_key(p)? {
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
    use std::sync::Arc;

    use serde_json::json;
    use skep_identity::canonical_record;
    use skep_signature::HybridSigner;

    use super::*;
    use crate::board::fake::{self, Fake};

    const LINK: &str = "1.0.1.0.1.0.2.7";

    /// A board's history over the committed positions `committed`, the
    /// genesis at 0 beside them, its retention floor at `floor`, a link
    /// committed at `p`: `/op-at` answers as the wire does — `410
    /// history_reclaimed` below the floor, `400 not_a_position` naming the
    /// nearest position under a gap, and otherwise the discovery, holding
    /// the link from `p` on.
    fn history(committed: Vec<u64>, floor: Option<u64>, p: u64) -> Arc<Fake> {
        Fake::new(move |req| {
            assert_eq!(req.path, "/op-at", "the bisection reads history alone");
            let at = serde_json::from_slice::<Value>(&req.body).unwrap()["at"].as_u64().unwrap();
            if floor.is_some_and(|f| at < f) {
                return fake::json(410, json!({"error": "history_reclaimed", "floor": floor}));
            }
            if at == 0 || committed.contains(&at) {
                let addrs: Vec<&str> = if at >= p { vec![LINK] } else { Vec::new() };
                return fake::json(200, json!({"addrs": addrs, "as_of": at, "resp": "addrs"}));
            }
            let nearest = committed.iter().copied().filter(|c| *c <= at).max().unwrap_or(0);
            fake::json(400, json!({"error": "not_a_position", "nearest": nearest}))
        })
    }

    /// THE BISECTION (AUTH-5.68) as a law over generated histories — every
    /// gapless history to 20 positions and two with gaps, every position the
    /// link commits at, every retention floor or none: the answer is the
    /// LEAST position at which the discovery returns the link where that lies
    /// above the floor, and NONE where it lies at or below it — an answer,
    /// never an exit, and no position asserted (§9 item 50) — in at most
    /// 2·⌈log₂ head⌉ + 3 reads.
    #[test]
    fn the_bisection_finds_the_least_position_and_asserts_none_below_the_floor() {
        let mut histories: Vec<Vec<u64>> = (1..=20).map(|head| (1..=head).collect()).collect();
        histories.push(vec![1, 4, 5, 9, 12]);
        histories.push(vec![2, 3, 7, 8, 15, 16]);
        let frame = frames::find_links_ftt(T_ENROLL, "1.0.1");
        let mut cases = 0;
        for committed in histories {
            let head = *committed.last().unwrap();
            let bound = 2 * u64::from(head.next_power_of_two().trailing_zeros()) + 3;
            for &p in &committed {
                for floor in std::iter::once(None).chain(committed.iter().copied().map(Some)) {
                    let fake = history(committed.clone(), floor, p);
                    let found = position_of(&fake::board(&fake), &frame, LINK, head).expect("an answer, never an exit");
                    let expected = match floor {
                        Some(f) if p <= f => (None, Some(f)),
                        _ => (Some(p), floor),
                    };
                    assert_eq!(found, expected, "{committed:?}, the link at {p}, the floor at {floor:?}");
                    let reads = fake.sent.lock().unwrap().len() as u64;
                    assert!(reads <= bound, "{reads} reads past {bound}: {committed:?}, the link at {p}, the floor at {floor:?}");
                    cases += 1;
                }
            }
        }
        assert!(cases > 3000, "the family holds {cases} cases");
    }

    /// Below the retention floor neither a record's position nor its hand is
    /// derivable, and the read ASSERTS NEITHER (§9 item 50), reading neither
    /// the feed nor the set to try: an unsigned record read position-free,
    /// and a signed one whose base is unreadable and which no key of this
    /// store verifies, each answer `Unreadable`.
    #[test]
    fn below_the_floor_no_hand_is_asserted_and_no_read_is_made() {
        let board = fake::board(&Fake::unread());
        let key = |b: u8| HybridSigner::public_key(&crate::sign::signer_from_seed(&[b; 32])).clone();
        let own = [(Fingerprint::of(&key(4)), key(4))];
        let term = Some(BoardTerm { log_position: 12, chain: [7; 32] });
        let unsigned = enrollment("1.0.1.0.1.0.2.1", vec![Enrollment::new(key(1), true, Some("paper".into())).unwrap()]);
        let mut signed = enrollment("1.0.1.0.1.0.2.2", vec![Enrollment::new(key(2), false, Some("phone".into())).unwrap()]);
        signed.sig = Some("ab".repeat(64));
        for record in [unsigned, signed] {
            let hand = hand_of(&board, &record, term, &own, None).expect("no read, so no fault");
            assert!(matches!(hand, Hand::Unreadable(_)), "{}: {hand:?}", record.link);
        }
    }

    #[test]
    fn addresses_order_by_component() {
        let mut v = vec!["1.0.1.0.1.0.2.10".to_string(), "1.0.1.0.1.0.2.2".to_string()];
        v.sort_by_cached_key(|a| components(a));
        assert_eq!(v, ["1.0.1.0.1.0.2.2", "1.0.1.0.1.0.2.10"]);
    }

    /// An enrollment record of `entries` at `link`.
    fn enrollment(link: &str, entries: Vec<Enrollment>) -> Record {
        let sigless = canonical_record(&entries, None);
        Record {
            kind: Kind::Enroll,
            link: link.into(),
            home: "1.0.1.0.1".into(),
            home_account: "1.0.1".into(),
            subject: "1.0.1".into(),
            atom: format!("{link}.1"),
            bytes: sigless.clone().into_bytes(),
            sigless,
            sig: None,
            enrolled: entries,
            retired: Vec::new(),
            position: None,
            base: None,
            hand: Hand::Bare,
            anchor_grade: false,
        }
    }

    /// AUTH-5.69 — a key's label is the one on the record that FIRST enrolled
    /// it, and `None` — never an empty string — where that record carried
    /// none, whatever a later record names it.
    #[test]
    fn a_label_is_the_first_enrolling_records_and_none_where_it_carried_none() {
        let key = |b: u8| HybridSigner::public_key(&crate::sign::signer_from_seed(&[b; 32])).clone();
        let (labelled, bare) = (key(1), key(2));
        let records = Records {
            account: "1.0.1".into(),
            records: vec![
                enrollment("1.0.1.0.1.0.2.1", vec![Enrollment::new(labelled.clone(), true, Some("paper".into())).unwrap(), Enrollment::new(bare.clone(), false, None).unwrap()]),
                enrollment("1.0.1.0.1.0.2.2", vec![Enrollment::new(bare.clone(), false, Some("named later".into())).unwrap()]),
            ],
            head: 9,
            floor: None,
            claim_entry: None,
            claimed: false,
        };
        assert_eq!(records.label_of(&Fingerprint::of(&labelled)).as_deref(), Some("paper"));
        assert_eq!(records.enrollment_of(&Fingerprint::of(&bare)).map(|r| r.link.as_str()), Some("1.0.1.0.1.0.2.1"), "the record that FIRST enrolled it");
        assert!(records.enrollment_of(&Fingerprint::of(&key(3))).is_none());
        assert_eq!(records.label_of(&Fingerprint::of(&bare)), None);
        assert_eq!(records.label_of_hand(&Hand::Key(Fingerprint::of(&bare))), None);
        assert_eq!(records.label_of(&Fingerprint::of(&key(3))), None, "a key no record enrolled");
    }
}
