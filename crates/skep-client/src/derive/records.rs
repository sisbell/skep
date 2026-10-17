//! The one admitted read (`client.md` §1.1; §9 items 44, 50).
//!
//! It reads an account's credential records over its two residence
//! addresses — AUTH-5.68's discovery per AUTH-2.113, `find_links_ftt` over
//! the enroll and retire types naming the account, per record `read_link`
//! at the address it answered, a content read bounded to the credential
//! atoms that discovery returned (`retrieve_v` at the atom's position, the
//! I→V inversion over `image`, AUTH-2.114), the bisection over `/op-at` for
//! each record's position (at most 2·⌈log₂ head⌉ + 3 probes, AUTH-5.68), and
//! the hand: at a record carrying its own `sig` — every record above the
//! claim — the key that verifies it over the `record` frame, this store's
//! own keys first, then a trial over the set that opens the home's account
//! as of the record's base (AUTH-2.94; P12), the anchors alone at an
//! anchor-grade act; at a record with no `sig` — the ceremony's own genesis
//! — `/changes.key` at that position. Below the retention floor a
//! position-addressed read answers `history_reclaimed` — an answer, never an
//! exit (§2.3) — and the order is derived position-free, genesis-first
//! (AUTH-2.100) plus link-address order (AUTH-5.69); the position and the
//! hand are then not derivable and the face asserts neither (§9 item 50).
//! The label a fingerprint carries is the one on the record that first
//! enrolled it (AUTH-5.69).
//!
//! `H.1`'s pair is the record frame's `board` term and every entry frame's,
//! read once per board by [`Board::board_term`]; the frame itself is
//! [`RecordFrame`]'s, the bytes the writing hand signed.

use std::collections::HashMap;
use std::thread;
use std::time::Duration;

use serde_json::Value;
use skep_identity::{parse_record_value, BoardTerm, Enrollment, Fingerprint, HybridBlob, PublicKey};

use crate::address::{document_of, parent_account, within_principal_depth};
use crate::board::answers::IRun;
use crate::board::{answers, frames, guest_closed, AtAnswer, Board, ChangeKey, KeySet, KeySetAnswer, T_CLAIM, T_ENROLL, T_RETIRE};
use crate::halt::Halt;
use crate::sign::RecordFrame;

#[cfg(test)]
mod tests;

/// A credential record's kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// An enrollment record.
    Enroll,
    /// A retirement record.
    Retire,
}

impl Kind {
    /// Returns the record class's type address.
    ///
    /// It is the deposit's declaration, its link's type and the record
    /// frame's `ty` row alike (AUTH-5.4; PUB-2.63).
    pub fn type_address(self) -> &'static str {
        match self {
            Kind::Enroll => T_ENROLL,
            Kind::Retire => T_RETIRE,
        }
    }
}

/// The hand that wrote a record, as this read names it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Hand {
    /// A key: the one that verifies the record's own `sig`.
    ///
    /// At an unsigned row, it is the one `/changes.key` testifies.
    Key(Fingerprint),
    /// An unsigned row's bare-session testimony — the ceremony's genesis.
    Bare,
    /// The board's own daemon.
    System,
    /// A `sig` no candidate verifies.
    ///
    /// It is an operator's hand past the check (AUTH-4.54), or a record
    /// carried from another home or board: "signed by no key of this
    /// account's set", inert to the filter.
    NoKeyVerifies,
    /// Not readable here, and the face asserts none.
    ///
    /// Below the retention floor, a lost testimony, no `H.1`.
    Unreadable(String),
}

/// One credential record, as read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// The record's kind.
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
    /// The sig-less canonical record (AUTH-4.58: the record's identity).
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
    /// Whether the act is anchor-grade.
    ///
    /// It is an anchor-flagged enrollment, a retirement naming an anchor (the
    /// `anchor_session_required` cases).
    pub anchor_grade: bool,
}

/// The read's answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Records {
    /// The account the read was made for.
    pub account: String,
    /// The records, genesis-first.
    ///
    /// The records whose position is not known follow in link-address order,
    /// then the rest by position.
    pub records: Vec<Record>,
    /// The committed head the read was made at.
    pub head: u64,
    /// The retention floor, where a position-addressed read met it.
    pub floor: Option<u64>,
    /// The attestation boundary — the board's claim entry.
    ///
    /// It is read as the position of the claim link `find_links` answers
    /// (signed-ops §5.5); `None` while unclaimed, or below the floor
    /// (undeterminable).
    pub claim_entry: Option<u64>,
    /// Whether the board is claimed at all.
    pub claimed: bool,
}

impl Records {
    /// Returns the genesis record — the first enrollment of the read.
    ///
    /// AUTH-2.100: genesis at most once.
    pub fn genesis(&self) -> Option<&Record> {
        self.records.iter().find(|r| r.kind == Kind::Enroll)
    }

    /// Returns the record that first enrolled `fp`, where one stands.
    ///
    /// It is the one (AUTH-5.69) whose label the key carries, and whose link
    /// a supersession trail names as its `old` (AUTH-5.59 step 2).
    pub fn enrollment_of(&self, fp: &Fingerprint) -> Option<&Record> {
        self.records.iter().find(|r| r.kind == Kind::Enroll && r.enrolled.iter().any(|e| Fingerprint::of(&e.key) == *fp))
    }

    /// Returns the label carried by the record that first enrolled `fp`.
    ///
    /// AUTH-5.69: `None` where that record carried none (a label is never
    /// empty, AUTH-1.24); every later mention is informational.
    pub fn label_of(&self, fp: &Fingerprint) -> Option<String> {
        self.enrollment_of(fp)?.enrolled.iter().find(|e| Fingerprint::of(&e.key) == *fp)?.label().map(str::to_string)
    }

    /// Returns the retirement record naming `fp`, where one stands.
    pub fn retirement_of(&self, fp: &Fingerprint) -> Option<&Record> {
        self.records.iter().find(|r| r.kind == Kind::Retire && r.retired.contains(fp))
    }

    /// Returns the label of a hand, where the hand is a key.
    ///
    /// It is the key's label as this account's records first enrolled it
    /// (AUTH-5.69).
    pub fn label_of_hand(&self, hand: &Hand) -> Option<String> {
        match hand {
            Hand::Key(fp) => self.label_of(fp),
            _ => None,
        }
    }
}

/// One entry the person holds, for the whole-set compare.
///
/// It is the payload this device composed, or an anchor file's public
/// members (`client.md` §2.2 `verify`; AUTH-4.58's detection; P25):
/// fingerprint and anchor flag, and the label where it carries one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Held {
    /// The entry's fingerprint.
    pub fingerprint: Fingerprint,
    /// The entry's anchor flag.
    pub anchor: bool,
    /// The entry's label, where it carries one.
    pub label: Option<String>,
}

/// One difference between the genesis record and what the person holds.
///
/// It is a key added, a key missing, a flag flipped: halt in AUTH-5.53's
/// terms, this account is *not* yours to keep as it stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Difference {
    /// In the genesis and not held.
    Added { fingerprint: Fingerprint, anchor: bool, label: Option<String> },
    /// Held and not in the genesis.
    Missing { fingerprint: Fingerprint, anchor: bool, label: Option<String> },
    /// Held and present, the anchor flag flipped.
    FlagFlipped { fingerprint: Fingerprint, held_anchor: bool, genesis_anchor: bool },
}

/// The whole-set compare's answer.
///
/// It holds the differences, and the current set's further entries listed
/// as later acts for the person to recognise (P27), never as differences.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WholeSet {
    /// The differences between the genesis record and what is held.
    pub differences: Vec<Difference>,
    /// The current set's further entries, as later acts.
    pub later: Vec<Held>,
}

/// Runs the whole-set compare: the genesis record against `held`.
///
/// The genesis record — the first enrollment of the admitted read, its
/// bytes readable position-free below the floor — is compared entry for
/// entry, fingerprint and anchor flag; the current enrolled set's further
/// entries are the later acts. `None` where the account has no genesis
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
    /// Returns the first candidate whose own row verifies `blob` — the trial.
    ///
    /// Both halves of `blob` verify over this record's `record` frame under
    /// that row (AUTH-4.32's rule, as `skep_signature::verify` holds it) —
    /// the frame composed from the record's own home, home account, kind,
    /// subject and sig-less body, and re-composed per candidate since `alg`
    /// names the signing key's token.
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
            // A token-free `op_at` halts on the death signal itself; the arm
            // answers the same halt rather than trust that it never comes.
            AtAnswer::Closed => return Err(guest_closed()),
            AtAnswer::Busy => thread::sleep(Duration::from_millis(20 * (attempt + 1))),
        }
    }
    Err(Halt::face(
        "the board's history reads stayed busy",
        "`/op-at` answered `history_busy` eight times running: every reconstruction permit is in use",
        "retry shortly; a historical read is bounded by the board's reconstruction pool",
    ))
}

/// Returns the least position at which `find_links_ftt` returns the link.
///
/// It is the bisection (AUTH-5.68): `None` below the floor, with the floor
/// met, if any. A `nearest` the board answers — the greatest position at or
/// below the one sent (wire.md §Reading history) — is taken only inside the
/// range it was asked of, `(lo, mid]` in the loop and `(lo, head]` at the
/// head, so every step halves the open range whatever the board answers and
/// the read ends in at most 2·⌈log₂ head⌉ + 3 probes.
///
/// # Errors
///
/// The probes' halts — the reads' errors, the death signal, and history
/// reads that stay busy.
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
        Probe::NotAPosition { nearest: Some(n) } if n > lo && n <= head => hi = n,
        _ => return Ok((None, floor)),
    }
    // A floor at or past the head the board answered for: no position above
    // it to bisect.
    if lo >= hi {
        return Ok((None, floor));
    }
    while hi - lo > 1 {
        let mid = lo + (hi - lo) / 2;
        match probe(board, mid, frame, link)? {
            Probe::Present => hi = mid,
            Probe::Absent => lo = mid,
            Probe::Reclaimed { floor: f } => {
                floor = floor.or(f);
                lo = mid;
            }
            Probe::NotAPosition { nearest } => match nearest {
                Some(n) if n > lo && n <= mid => match probe(board, n, frame, link)? {
                    Probe::Present => hi = n,
                    _ => lo = mid,
                },
                _ => lo = mid,
            },
        }
    }
    Ok((Some(hi), floor))
}

/// Returns the base of a record at `position`.
///
/// It is the greatest committed position below it.
///
/// # Errors
///
/// [`Board::op_at`]'s errors.
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

/// Returns the set that opens `account` as of `at`.
///
/// It reads `key_set` at the account and, while empty, at each account
/// above it (AUTH-4.30 (i)), at that position. The account is ω's prefix as
/// the board named it; one deeper than the namespace delegates is
/// unreadable here, never climbed.
///
/// # Errors
///
/// [`Board::key_set_at`]'s errors.
fn set_opening_at(board: &Board, account: &str, at: u64) -> Result<Option<KeySet>, Halt> {
    if !within_principal_depth(account) {
        return Ok(None);
    }
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

/// Returns a home's I→V inversion (AUTH-2.114).
///
/// It is the runs its content I-addresses are arranged in, off
/// `retrieve_doc_v_span_set` and `image` — at most the run budget's,
/// whatever widths the board names — and none where the I-map does not read
/// whole, so the home's records read as unreadable and never as another
/// position's bytes.
///
/// # Errors
///
/// [`Board::guest`]'s errors.
fn inversion(board: &Board, home: &str) -> Result<Vec<IRun>, Halt> {
    let extent = answers::content_extent(&board.guest(&frames::span_set(home))?);
    if extent == 0 {
        return Ok(Vec::new());
    }
    let image = board.guest(&frames::image(home, 1, extent))?;
    Ok(answers::i_runs(&image, extent).unwrap_or_default())
}

/// Returns the record atom's bytes at `atom` in `home`, through the inversion.
///
/// # Errors
///
/// [`Board::guest`]'s errors.
fn atom_bytes(board: &Board, home: &str, runs: &[IRun], atom: &str) -> Result<Option<Vec<u8>>, Halt> {
    let Some(ordinal) = answers::ordinal_of(runs, atom) else { return Ok(None) };
    Ok(answers::first_atom(&board.guest(&frames::retrieve_v(home, ordinal, 1))?))
}

/// Returns the deposits' links of `ty` whose `to` overlaps `account`'s span.
///
/// They come as addresses, in address order. The four-set query matches by
/// span overlap, so a link naming an account above `account` or beneath it
/// answers too, and the caller keeps the ones whose own `to` names it.
///
/// # Errors
///
/// [`Board::guest`]'s errors.
fn links_of(board: &Board, ty: &str, account: &str) -> Result<Vec<String>, Halt> {
    let v = board.guest(&frames::find_links_ftt(ty, account))?;
    let mut links: Vec<String> = answers::addrs(&v).into_iter().map(str::to_string).collect();
    links.sort_by_cached_key(|l| components(l));
    Ok(links)
}

/// Returns a dotted-decimal spelling's components.
///
/// They are the key address order sorts by, component by component.
fn components(address: &str) -> Vec<u128> {
    address.split('.').filter_map(|c| c.parse().ok()).collect()
}

/// Reads the account's credential records, with their positions and hands.
///
/// Each call makes the whole read: R0 makes it once and holds it for the
/// walk, and a walk reads it again where its own writes moved the records.
/// `own` is this store's own keys, tried first at a signed record's hand.
///
/// # Errors
///
/// Any of its reads' errors; the bisection's probes halt on the death
/// signal and on history reads that stay busy.
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

    let mut inversions: HashMap<String, Vec<IRun>> = HashMap::new();
    let mut owners: HashMap<String, String> = HashMap::new();
    let mut records = Vec::new();
    for kind in [Kind::Enroll, Kind::Retire] {
        let ty = kind.type_address();
        for link in links_of(board, ty, account)? {
            let Some(home) = document_of(&link) else { continue };
            let lv = board.guest(&frames::read_link(&link))?;
            // The four-set query matches by span overlap, so a link naming an
            // account above this one (its subtree covering this address)
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

    // Genesis-first, then the records with no position in link-address order
    // (AUTH-5.69's position-free arm), then by position: the genesis is the
    // enrollment homed in the genesis registry's doc 1 — another account's,
    // or the own doc 1's lowest link.
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

/// Returns the hand of one record.
///
/// A signed record's comes by the trial, an unsigned one's by
/// `/changes.key` at its position; unreadable where the inputs are not.
///
/// # Errors
///
/// The set read's errors, and the `/changes` read's.
fn hand_of(board: &Board, record: &Record, term: Option<BoardTerm>, own: &[(Fingerprint, PublicKey)], base: Option<u64>) -> Result<Hand, Halt> {
    match &record.sig {
        Some(sig_hex) => {
            let Some(term) = term else { return Ok(Hand::Unreadable("the board has no H.1, so no record frame can be composed".into())) };
            let Some(blob) = HybridBlob::parse_hex(sig_hex) else { return Ok(Hand::NoKeyVerifies) };
            // This store's own keys first.
            if let Some(fp) = record.signed_by(term, blob.as_bytes(), own.iter().map(|(f, k)| (f, k))) {
                return Ok(Hand::Key(fp));
            }
            let Some(base) = base else { return Ok(Hand::Unreadable("below the retention floor: the record's base is not readable at this board".into())) };
            let Some(set) = set_opening_at(board, &record.home_account, base)? else {
                return Ok(Hand::Unreadable("the set as of the record's base is not readable at this board".into()));
            };
            let candidates = set.enrolled.iter().filter(|e| !record.anchor_grade || e.anchor).map(|e| (&e.fingerprint, &e.key));
            Ok(match record.signed_by(term, blob.as_bytes(), candidates) {
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
