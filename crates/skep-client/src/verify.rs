//! The reader's verifier (`client.md` §1.1's `verify` row).
//!
//! It checks a committed signature against the key set as of the entry's
//! base (AUTH-2.94; P12 — never the head, at which every entry signed by a
//! key since retired would read as forged) — and that set is the
//! signature-filtered one, never the fold's (D14): the fold honours an
//! enrollment whatever its `sig` holds (AUTH-2.13), so `key_set` over
//! `/op-at` fixes a position and never this input's members.
//!
//! **The table.** It is `skep_identity`'s [`FilteredTable`], the one table
//! every verifying reader keeps beside the fold (REG-3.39; the signed-ops
//! design record §4.5's table paragraph), built here over the admitted read
//! ([`filtered_table`]): each credential record, with its home, its home's
//! account, its subject and its position as the read answered them, handed
//! to the table in the read's order, and the signature check handed in as
//! this crate's — `skep_signature::verify`, both halves. The table's rules
//! are the table's: a record admitted only where its own `sig` verifies over
//! its `record` frame under the set that opens its home's account as the
//! table stood at *that* record's base, at the act's grade read off the
//! table itself; one record alone host-trusted, the board claimant's own
//! genesis at or below the claim (AUTH-4.55 (3); AUTH-4.58), so the
//! claimant is an input beside the read; every record the fold refuses out
//! whatever its `sig` says. The attestation boundary is an input beside the
//! set — the board's claim entry — so [`Verdict::BeforeAttestation`] is told
//! from [`Verdict::Unsigned`]. A missing input is a verdict and never a
//! fallback: where the caller cannot derive it, the entry reads
//! [`Verdict::Undeterminable`] here, never judged against the served
//! `key_set`. Below the retention floor the records are still read,
//! position-free, and the table builds in record order; what the floor
//! loses is the entry and its base, and [`Verdict::Undeterminable`] here is
//! that entry's verdict.
//!
//! **A pure function of its caller's reads.** The entry, the frame its
//! caller composed through `skep_identity::entry_frame`, the table, `H.1`'s
//! pair and the bounds in; the verdict out. The arithmetic is
//! `skep_signature::verify`'s; nothing here reads a board. The session
//! verify is the daemon's, in `skep_core::auth` (AUTH-2.2).

use skep_address::Address;
use skep_identity::{BoardTerm, FilteredTable, Fingerprint, SigAlgRow};

use crate::address::parse_address;
use crate::derive::records::Records;

#[cfg(test)]
mod tests;

/// Returns the signature-filtered key table over the admitted read.
///
/// It is the shared table ([`FilteredTable`]) built under the board's claim
/// — `records`' claim entry and `claimant`, the account `/health` names as
/// the board's — so the claimant's own genesis at or below the claim is
/// host-trusted and no other record is (AUTH-4.55 (3)); with either absent
/// the table is built under no claim and trusts nothing, every record judged
/// by its `sig`. Each record is handed to the table in the read's order —
/// genesis-first, position order where positions are known, link-address
/// order below the floor (AUTH-5.69) — with `board`, `H.1`'s pair, as the
/// record frame's term, and this crate's signature check. A record whose
/// board-served addresses do not parse cannot be framed: it is a gap in its
/// account's table from its position on, never a record admitted or passed
/// over in silence.
pub fn filtered_table(records: &Records, claimant: Option<&str>, board: Option<BoardTerm>) -> FilteredTable {
    let claim = match (records.claim_entry, claimant.and_then(parse_address)) {
        (Some(at), Some(claimant)) => Some((at, claimant)),
        _ => None,
    };
    let mut table = FilteredTable::new(claim);
    for r in &records.records {
        match r.addresses() {
            Some(addresses) => {
                table.admit(&r.as_credential(&addresses), board, |tag, key, message, blob| skep_signature::verify(tag, key, message, blob).is_ok());
            }
            None => {
                if let Some(subject) = parse_address(&r.subject) {
                    table.missing(&subject, r.position.unwrap_or(0));
                }
            }
        }
    }
    table
}

/// One committed entry under trial.
///
/// It holds its position, the frame its caller composed from the stored
/// entry (`skep_identity::entry_frame` over the op's own body builder), and
/// its `attest` as the feed served it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry<'a> {
    /// The entry's position.
    pub position: u64,
    /// The frame its caller composed from the stored entry.
    pub frame: &'a [u8],
    /// `(alg token, blob)` where the row carried an `attest`.
    ///
    /// It is `None` where the row carried none.
    pub attest: Option<(&'a str, &'a [u8])>,
}

/// The five verdicts' shape (the signed-ops record §3.5).
///
/// It holds the three a reader of one entry reaches and the one a missing
/// input forces. Non-exhaustive: the record's shape names more verdicts
/// than a reader of one entry meets.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Verdict {
    /// The entry's `attest` verifies under a member of the filtered set.
    ///
    /// The set is the one as of the entry's base.
    Signed(Fingerprint),
    /// Above the claim, no `attest`, or one no member verifies.
    Unsigned,
    /// At or below the attestation boundary — the claim entry.
    BeforeAttestation,
    /// A missing input — never judged against the served `key_set`.
    ///
    /// It is no boundary derivable, the entry below the floor, the records
    /// unfetchable, or the set that opens the account undeterminable at the
    /// entry's base.
    Undeterminable(&'static str),
}

/// The two positions a verdict is judged at beside the table.
///
/// Each is `None` where the caller could not derive it — named, so neither
/// can stand in the other's place: the attestation boundary, the board's
/// claim entry (signed-ops §5.5), at or below which an entry reads
/// [`Verdict::BeforeAttestation`], its absence [`Verdict::Undeterminable`]
/// here and never a fallback; and the retention floor, below which an entry
/// and its base are lost.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Bounds {
    /// The board's claim entry.
    pub boundary: Option<u64>,
    /// The retention floor, where a position-addressed read met it.
    pub floor: Option<u64>,
}

/// The bounds the admitted read derived: its claim entry and its floor.
impl From<&Records> for Bounds {
    fn from(records: &Records) -> Bounds {
        Bounds { boundary: records.claim_entry, floor: records.floor }
    }
}

/// Returns the verdict of `entry` under `table`, at `bounds`.
///
/// The set the `attest` is judged under is the one that opens `account` —
/// the account the entry's frame names, AUTH-4.30 (i)'s walk — as of the
/// entry's base (P12): [`FilteredTable::opening_at`], `None` where a table
/// on the walk is undeterminable there, which is the entry's verdict too.
pub fn verdict(entry: &Entry<'_>, table: &FilteredTable, account: &Address, bounds: Bounds) -> Verdict {
    let Some(boundary) = bounds.boundary else { return Verdict::Undeterminable("the attestation boundary could not be derived here") };
    if entry.position <= boundary {
        return Verdict::BeforeAttestation;
    }
    if bounds.floor.is_some_and(|f| entry.position < f) {
        return Verdict::Undeterminable("the entry lies below this board's retention floor");
    }
    let Some((alg, blob)) = entry.attest else { return Verdict::Unsigned };
    let Some(row) = SigAlgRow::of_token(alg) else { return Verdict::Unsigned };
    let Some(set) = table.opening_at(account, entry.position) else {
        return Verdict::Undeterminable("the set that opens the account as of the entry's base is not determinable here");
    };
    for e in &set {
        if e.key.alg() != alg {
            continue;
        }
        if skep_signature::verify(row.tag, &e.key, entry.frame, blob).is_ok() {
            return Verdict::Signed(Fingerprint::of(&e.key));
        }
    }
    Verdict::Unsigned
}
