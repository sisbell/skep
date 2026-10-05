//! THE SEEDING CHECK — the three arms the seeding hand runs at every board's
//! genesis over the registry's rows and every other commons row the build
//! holds, refusing to seed on a fault (REG-1.28 to REG-1.32; R9 (c)):
//!
//! 1. DISJOINTNESS, at the SUBTREE grain (REG-1.30): no registry row's
//!    subtree contains a foreign row and none is contained by one — a row
//!    AT a foreign row's address included, each containing the other. The
//!    domain is the PARENT's, every commons row the registry does not
//!    itself allocate (REG-1.31): the credential ordinals are the instance
//!    the arm was minted on and never its bound, and the sharpest case is a
//!    foreign type placed inside the policy link's kind. The registry's own
//!    subtype rows nest under their kinds by design and are no collision.
//! 2. COMPLETENESS (REG-1.29): every kind and every subtype the kinds' home
//!    names (REG-1.14, REG-1.15) has a row — a subtype's row being a row at
//!    a prefix UNDER its own kind's row (REG-1.20); a list missing one
//!    refuses, so a missing row never surfaces at that subtype's first
//!    deposit.
//! 3. THE COUNT (REG-1.25): the kind rows against the registry range's five
//!    ordinals `3.55`–`3.59` — at most five, each a bare ordinal inside the
//!    range, no two at one ordinal.
//!
//! The arms run in that order and the first to fire names the refusal; a
//! refusal is a genesis that does not complete — the hand that runs the
//! check writes nothing on `Err`.

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
    /// or a subtype's under the kind its subtype names.
    Completeness { missing: RowOf },
    /// The count arm: more kind rows than the registry range's ordinals, or
    /// — with `row` named — a kind row that is no bare ordinal inside the
    /// registry range, or a second kind row at an ordinal already taken.
    Count { kind_row_count: usize, row: Option<Address> },
}

impl SeedingRefusal {
    /// The arm's name.
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
        match self {
            SeedingRefusal::Disjointness { registry, foreign } => write!(
                f,
                "disjointness: the registry row {registry} and the foreign commons row {foreign} meet at the subtree grain"
            ),
            SeedingRefusal::Completeness { missing: RowOf::Kind(kind) } => {
                write!(f, "completeness: {} has no row", kind.name())
            }
            SeedingRefusal::Completeness { missing: RowOf::Subtype(subtype) } => write!(
                f,
                "completeness: {} has no row under {}",
                subtype.name(),
                subtype.kind().name()
            ),
            SeedingRefusal::Count { kind_row_count, row: None } => write!(
                f,
                "count: {kind_row_count} kind rows against the registry range's {} ordinals 3.{}-3.{}",
                REGISTRY_RANGE.count(),
                REGISTRY_RANGE.start(),
                REGISTRY_RANGE.end()
            ),
            SeedingRefusal::Count { kind_row_count, row: Some(row) } => write!(
                f,
                "count: of {kind_row_count} kind rows, {row} is no bare ordinal of the registry range 3.{}-3.{} left to it",
                REGISTRY_RANGE.start(),
                REGISTRY_RANGE.end()
            ),
        }
    }
}

impl std::error::Error for SeedingRefusal {}

/// THE CHECK: `rows`, the registry's rows as a list — [`crate::rows()`] on a
/// shipped build, a list a suite builds to prove an arm — against `foreign`,
/// every other commons row the hand can see. `Ok` is a genesis that may
/// complete; `Err` names the first arm to fire.
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
    // prefix under its kind's.
    let row_of = |of: RowOf| rows.iter().find(|r| r.of == of);
    for kind in Kind::ALL {
        if row_of(RowOf::Kind(kind)).is_none() {
            return Err(SeedingRefusal::Completeness { missing: RowOf::Kind(kind) });
        }
    }
    for subtype in Subtype::ALL {
        let kind_row =
            row_of(RowOf::Kind(subtype.kind())).expect("every kind's row stands, checked above");
        let present = rows.iter().any(|r| {
            r.of == RowOf::Subtype(subtype)
                && r.address != kind_row.address
                && is_prefix(kind_row.address.tumbler(), r.address.tumbler())
        });
        if !present {
            return Err(SeedingRefusal::Completeness { missing: RowOf::Subtype(subtype) });
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
