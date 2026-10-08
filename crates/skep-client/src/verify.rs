//! THE READER'S VERIFIER (`client.md` §1.1's `verify` row; cp-1, owner-ruled
//! 2026-10-04): a COMMITTED signature checked against the key set AS OF THE
//! ENTRY's BASE (AUTH-2.94; P12 — never the head, at which every entry
//! signed by a key since retired would read as forged) — and that set is
//! THE SIGNATURE-FILTERED ONE, NEVER THE FOLD's (D14): the fold honours an
//! enrollment whatever its `sig` holds (AUTH-2.13), so `key_set` over `/op-at`
//! fixes a position and never this input's members.
//!
//! THE FILTER, derived from the account's credential records and their
//! `sig`s: a record is ADMITTED only where its own `sig` verifies over its
//! `record` frame under the filtered set as of THAT record's base, at the
//! act's GRADE — an anchor of that set where the act is anchor-grade, any
//! enrolled key of it otherwise; the PRE-CLAIM genesis is admitted unsigned
//! and HOST-TRUSTED (AUTH-4.55 (3); AUTH-4.58); a record whose `sig` fails is
//! inert to this table. THE ATTESTATION BOUNDARY is an input beside the set
//! — the board's CLAIM ENTRY — so BEFORE-ATTESTATION is told from UNSIGNED.
//! A MISSING INPUT IS A VERDICT AND NEVER A FALLBACK: where the caller
//! cannot derive it, the entry reads UNDETERMINABLE HERE, never judged
//! against the served `key_set`. Below the retention floor the records are
//! still read, position-free, and the filter builds in RECORD ORDER; what
//! the floor loses is the ENTRY and its base, and UNDETERMINABLE HERE is
//! that entry's verdict.
//!
//! A PURE FUNCTION OF ITS CALLER's READS: the entry, the frame its caller
//! composed through `skep_identity::entry_frame`, the table, `H.1`'s pair in;
//! the verdict out. The arithmetic is `skep_signature::verify`'s; nothing
//! here reads a board. The SESSION verify is `skepd`'s (AUTH-2.2).

use skep_identity::{BoardTerm, Fingerprint, HybridBlob, PublicKey, SigAlgRow};

use crate::derive::records::{Kind, Records};

#[cfg(test)]
mod tests;

/// One admission of the FILTERED table: a key, from the record that admitted
/// it, until the record that retired it — positions where known.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Admission {
    pub fingerprint: Fingerprint,
    pub key: PublicKey,
    pub anchor: bool,
    /// The label the admitting record carried (AUTH-5.69).
    pub label: Option<String>,
    /// The admitting record's position; `None` position-free.
    pub since: Option<u64>,
    /// Where the admission's lifecycle stands.
    pub until: Until,
}

/// Where an admission's lifecycle stands — one lifecycle per fingerprint
/// and set (I4, AUTH-2.98).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Until {
    /// No admitted retirement names it: it stands enrolled.
    Enrolled,
    /// Retired by an admitted record at this position.
    RetiredAt(u64),
    /// Retired by an admitted record read position-free, below the
    /// retention floor: no base reads it as enrolled.
    RetiredPositionFree,
}

/// One record the filter refused, and why — inert to the table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inert {
    /// The record's link address.
    pub link: String,
    pub why: String,
}

/// THE FILTERED TABLE and the records it left inert.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FilteredTable {
    pub admissions: Vec<Admission>,
    /// The records the filter refused.
    pub inert: Vec<Inert>,
}

impl FilteredTable {
    /// THE FILTER over `records` (genesis-first, record order): the genesis
    /// host-trusted; every later record admitted iff its `sig` verifies under
    /// the table as it stands at that record's base, at the act's grade.
    pub fn build(records: &Records, board: Option<BoardTerm>) -> FilteredTable {
        let mut table = FilteredTable::default();
        let mut genesis_seen = false;
        for r in &records.records {
            if r.kind == Kind::Enroll && !genesis_seen {
                genesis_seen = true;
                // AUTH-4.55 (3): the pre-claim genesis, host-trusted.
                for e in &r.enrolled {
                    table.admissions.push(Admission {
                        fingerprint: Fingerprint::of(&e.key),
                        key: e.key.clone(),
                        anchor: e.anchor,
                        label: e.label().map(str::to_string),
                        since: r.position,
                        until: Until::Enrolled,
                    });
                }
                continue;
            }
            let inert = |why: &str| Inert { link: r.link.clone(), why: why.to_string() };
            let Some(sig) = &r.sig else {
                table.inert.push(inert("no `sig` above the claim"));
                continue;
            };
            let Some(board) = board else {
                table.inert.push(inert("no H.1: the record frame cannot be composed"));
                continue;
            };
            let Some(blob) = HybridBlob::parse_hex(sig) else {
                table.inert.push(inert("the `sig` is no hybrid blob's hex"));
                continue;
            };
            // The table as it stands at this record's base — record order
            // being position order where positions are known.
            let candidates = table
                .admissions
                .iter()
                .filter(|a| a.until == Until::Enrolled && (!r.anchor_grade || a.anchor))
                .map(|a| (&a.fingerprint, &a.key));
            match r.signed_by(board, blob.as_bytes(), candidates) {
                None => table.inert.push(inert("signed by no key of this account's filtered set")),
                Some(_) => match r.kind {
                    Kind::Enroll => {
                        for e in &r.enrolled {
                            let fp = Fingerprint::of(&e.key);
                            if table.admissions.iter().any(|a| a.fingerprint == fp) {
                                continue; // I4: a fingerprint has one lifecycle per set.
                            }
                            table.admissions.push(Admission {
                                fingerprint: fp,
                                key: e.key.clone(),
                                anchor: e.anchor,
                                label: e.label().map(str::to_string),
                                since: r.position,
                                until: Until::Enrolled,
                            });
                        }
                    }
                    Kind::Retire => {
                        for fp in &r.retired {
                            if let Some(a) = table.admissions.iter_mut().find(|a| a.fingerprint == *fp && a.until == Until::Enrolled) {
                                a.until = r.position.map_or(Until::RetiredPositionFree, Until::RetiredAt);
                            }
                        }
                    }
                },
            }
        }
        table
    }

    /// The admissions ENROLLED as of the base of an entry at `position`
    /// (P12): admitted at a position below it (or position-free), not yet
    /// retired at one below it.
    pub fn as_of(&self, position: u64) -> impl Iterator<Item = &Admission> + '_ {
        self.admissions.iter().filter(move |a| a.since.is_none_or(|s| s < position)).filter(move |a| match a.until {
            Until::Enrolled => true,
            Until::RetiredAt(r) => r >= position,
            Until::RetiredPositionFree => false,
        })
    }

    /// The table's CURRENT members — every admission not retired.
    pub fn current(&self) -> impl Iterator<Item = &Admission> + '_ {
        self.admissions.iter().filter(|a| a.until == Until::Enrolled)
    }
}

/// One committed ENTRY under trial: its position, the frame its caller
/// composed from the stored entry (`skep_identity::entry_frame` over the
/// op's own body builder), and its `attest` as the feed served it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry<'a> {
    pub position: u64,
    pub frame: &'a [u8],
    /// `(alg token, blob)` where the row carried an `attest`; `None` where it
    /// carried none.
    pub attest: Option<(&'a str, &'a [u8])>,
}

/// The five verdicts' shape (the signed-ops record §3.5), the three a reader
/// of one entry reaches and the one a missing input forces. Non-exhaustive:
/// the record's shape names more verdicts than a reader of one entry meets.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Verdict {
    /// The entry's `attest` verifies under a member of the filtered set as
    /// of its base.
    Signed(Fingerprint),
    /// Above the claim, no `attest`, or one no member verifies.
    Unsigned,
    /// At or below the attestation boundary — the claim entry.
    BeforeAttestation,
    /// A missing input: no boundary derivable, the entry below the floor,
    /// the records unfetchable — never judged against the served `key_set`.
    Undeterminable(&'static str),
}

/// The two positions a verdict is judged at beside the table, each `None`
/// where the caller could not derive it — named, so neither can stand in the
/// other's place: THE ATTESTATION BOUNDARY, the board's claim entry
/// (SIGNED-OPS §5.5 as RULED), at or below which an entry reads BEFORE
/// ATTESTATION, its absence UNDETERMINABLE HERE and never a fallback; and
/// the RETENTION FLOOR, below which an entry and its base are lost.
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

/// THE VERDICT of `entry` under `table`, at `bounds`.
pub fn verdict(entry: &Entry<'_>, table: &FilteredTable, bounds: Bounds) -> Verdict {
    let Some(boundary) = bounds.boundary else { return Verdict::Undeterminable("the attestation boundary could not be derived here") };
    if entry.position <= boundary {
        return Verdict::BeforeAttestation;
    }
    if bounds.floor.is_some_and(|f| entry.position < f) {
        return Verdict::Undeterminable("the entry lies below this board's retention floor");
    }
    let Some((alg, blob)) = entry.attest else { return Verdict::Unsigned };
    let Some(row) = SigAlgRow::of_token(alg) else { return Verdict::Unsigned };
    for a in table.as_of(entry.position) {
        if a.key.alg() != alg {
            continue;
        }
        if skep_signature::verify(row.tag, &a.key, entry.frame, blob).is_ok() {
            return Verdict::Signed(a.fingerprint);
        }
    }
    Verdict::Unsigned
}
