//! THE SEEDING CHECK — the three arms the seeding hand runs at every board's
//! genesis over the registry's rows and every other commons row the build
//! holds, refusing to seed on a fault (REG-1.28 to REG-1.32; R9 (c)):
//!
//! 1. DISJOINTNESS, at the SUBTREE grain (REG-1.30): no registry row's
//!    subtree contains a foreign row and none is contained by one — a row
//!    AT a foreign row's address included, each containing the other. The
//!    domain is the PARENT's, every commons row the registry does not
//!    itself allocate (REG-1.31): the credential ordinals are the instance
//!    the arm was minted on and never its bound, and the sharpest
//!    non-credential case is a foreign row placed inside the policy link's
//!    kind — the mail type's, were an allocation to put it there. The
//!    registry's own subtype rows nest under their kinds by design, and
//!    under their parent rows where a subtype is one, and are no collision.
//! 2. COMPLETENESS (REG-1.29): every kind and every subtype the kinds' home
//!    names (REG-1.14, REG-1.15) has a row — a subtype's row being a row at
//!    a prefix UNDER the row it stands directly beneath (REG-1.20): its own
//!    kind's, or its PARENT ROW's where it is a row under a row, the arm
//!    recursing as REG-1.18's test does and a parent row owing its own row
//!    like any other; a list missing one refuses, so a missing row never
//!    surfaces at that subtype's first deposit.
//! 3. THE COUNT (REG-1.25): the kind rows against the registry range's
//!    ordinals, `3.54`–`3.59` as the list stands — no more kind rows than
//!    the range has ordinals, each a bare ordinal inside the range, no two
//!    at one ordinal. The kinds are counted off the list and against no
//!    written number.
//!
//! The order the arms run in, the refusal that speaks where several hold and
//! what the hand owes on one are [`seeding_check`]'s contract, stated there.

use std::fmt;

use skep_address::{is_prefix, Address};

use crate::rows::{registry_range_ordinal, Kind, Row, RowOf, Subtype, REGISTRY_RANGE};

/// The seeding check's refusal, naming its arm.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SeedingRefusal {
    /// The disjointness arm: a registry row and a foreign row whose
    /// subtrees meet.
    Disjointness { registry: Address, foreign: Address },
    /// The completeness arm: the row the list does not hold — a kind's own,
    /// or a subtype's under the row it stands directly beneath, the kind its
    /// subtype names or its parent row ([`RowOf::above`]).
    Completeness { missing: RowOf },
    /// The count arm: more kind rows than the registry range's ordinals, or
    /// — with `row` named — a kind row that is no bare ordinal inside the
    /// registry range, or a second kind row at an ordinal already taken.
    Count { kind_row_count: usize, row: Option<Address> },
}

impl SeedingRefusal {
    /// The arm's name — what a caller matching the refusal reads, and the
    /// head the operator's sentence (its `Display`) opens on, so the two name
    /// one arm.
    pub fn arm(&self) -> &'static str {
        match self {
            SeedingRefusal::Disjointness { .. } => "disjointness",
            SeedingRefusal::Completeness { .. } => "completeness",
            SeedingRefusal::Count { .. } => "count",
        }
    }
}

impl fmt::Display for SeedingRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: ", self.arm())?;
        match self {
            SeedingRefusal::Disjointness { registry, foreign } => write!(
                f,
                "the registry row {registry} and the foreign commons row {foreign} meet at the subtree grain"
            ),
            SeedingRefusal::Completeness { missing } => match missing.above() {
                None => write!(f, "{} has no row", missing.name()),
                Some(above) => write!(f, "{} has no row under {}", missing.name(), above.name()),
            },
            SeedingRefusal::Count { kind_row_count, row: None } => write!(
                f,
                "{kind_row_count} kind rows against the registry range's {} ordinals 3.{}-3.{}",
                REGISTRY_RANGE.count(),
                REGISTRY_RANGE.start(),
                REGISTRY_RANGE.end()
            ),
            SeedingRefusal::Count { kind_row_count, row: Some(row) } => write!(
                f,
                "of {kind_row_count} kind rows, {row} is no bare ordinal of the registry range 3.{}-3.{} left to it",
                REGISTRY_RANGE.start(),
                REGISTRY_RANGE.end()
            ),
        }
    }
}

impl std::error::Error for SeedingRefusal {}

/// THE CHECK: `rows`, the registry's rows as a list — [`crate::rows()`] on a
/// shipped build, a list a suite builds to prove an arm — against `foreign`,
/// every other commons row the hand can see; a pure query over the two
/// lists, writing nothing. `Ok` is a genesis that may complete. `Err` names
/// the first arm to fire, and on it THE HAND OWES a genesis that does not
/// complete: nothing written — no claim, no session and no board record
/// (REG-1.32).
///
/// WHICH REFUSAL SPEAKS where several hold — the one sentence the operator
/// repairs the image from (REG-1.33): the arms in their order — DISJOINTNESS
/// (REG-1.30), then COMPLETENESS (REG-1.29), then THE COUNT (REG-1.25), the
/// first to fire speaking — and within an arm its first fault in this order.
/// DISJOINTNESS names the first entry of `foreign`, in its own order, that
/// meets any row — at the subtree grain, either address a prefix of the
/// other, an entry AT a row's address included — with the first row of
/// `rows` it meets. COMPLETENESS names the first kind of [`Kind::ALL`] with
/// no row of its own, and only where every kind has one, the first subtype
/// of [`Subtype::ALL`] with no row of its own strictly under the row it
/// stands directly beneath ([`RowOf::above`]) — its kind's, or its parent
/// row's — the FIRST row that kind or that parent has in `rows`; a parent
/// stands ahead of the rows beneath it in `Subtype::ALL`, so a parent row
/// missing or misplaced speaks ahead of any row under it. THE COUNT names an
/// excess of kind rows over the registry range's ordinals, `3.54`–`3.59`,
/// ahead of any one row, then the first kind row of `rows` that is no bare
/// ordinal of that range — no address [`crate::commons_type`] spells from
/// one of its ordinals alone — or stands at one an earlier kind row took.
///
/// WHAT THE HAND OWES IN `foreign`: REG-1.31's domain, every address in it
/// read as foreign. A registry row spelled a second time — the insert door's
/// deposit class spells the binding and the endpoint again — is the hand's
/// to set apart, by equality ([`row_at`](crate::row_at)), and it sets apart
/// nothing else: another allocator's row AT a registry row's address is a
/// collision the disjointness arm names (REG-1.30), so a list of other
/// allocators' rows is handed over whole, never filtered against the table.
pub fn seeding_check<'a>(
    rows: &[Row],
    foreign: impl IntoIterator<Item = &'a Address>,
) -> Result<(), SeedingRefusal> {
    // 1 — DISJOINTNESS, both directions, at the subtree grain.
    for f in foreign {
        for r in rows {
            let (a, b) = (r.address.tumbler(), f.tumbler());
            if is_prefix(a, b) || is_prefix(b, a) {
                return Err(SeedingRefusal::Disjointness {
                    registry: r.address.clone(),
                    foreign: f.clone(),
                });
            }
        }
    }
    // 2 — COMPLETENESS: every kind's own row, then every subtype's row at a
    // prefix under the row it stands directly beneath — its kind's, or its
    // parent row's (REG-1.29: the arm recurses to a row under a parent row).
    let row_of = |of: RowOf| rows.iter().find(|r| r.of == of);
    for &kind in Kind::ALL {
        if row_of(RowOf::Kind(kind)).is_none() {
            return Err(SeedingRefusal::Completeness { missing: RowOf::Kind(kind) });
        }
    }
    for &subtype in Subtype::ALL {
        let of = RowOf::Subtype(subtype);
        let above = of.above().expect("a subtype row stands beneath a row");
        // Every kind's row stands, checked above, and a parent row is listed
        // ahead of the rows beneath it; a list that held neither is short
        // the row above, which is then the one named.
        let Some(above_row) = row_of(above) else {
            return Err(SeedingRefusal::Completeness { missing: above });
        };
        let present = rows.iter().any(|r| {
            r.of == of
                && r.address != above_row.address
                && is_prefix(above_row.address.tumbler(), r.address.tumbler())
        });
        if !present {
            return Err(SeedingRefusal::Completeness { missing: of });
        }
    }
    // 3 — THE COUNT: the kind rows against the registry range's ordinals.
    let kind_rows: Vec<&Row> = rows.iter().filter(|r| matches!(r.of, RowOf::Kind(_))).collect();
    if kind_rows.len() > REGISTRY_RANGE.count() {
        return Err(SeedingRefusal::Count { kind_row_count: kind_rows.len(), row: None });
    }
    let mut taken: Vec<u32> = Vec::new();
    for r in &kind_rows {
        match registry_range_ordinal(&r.address) {
            Some(ordinal) if !taken.contains(&ordinal) => taken.push(ordinal),
            _ => {
                return Err(SeedingRefusal::Count {
                    kind_row_count: kind_rows.len(),
                    row: Some(r.address.clone()),
                })
            }
        }
    }
    Ok(())
}
