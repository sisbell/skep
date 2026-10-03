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
//! 3. THE COUNT (REG-1.25): the kind rows against the reserve's five
//!    ordinals `3.55`–`3.59` — at most five, each a bare ordinal inside the
//!    reserve, no two at one ordinal.
//!
//! The arms run in that order and the first to fire names the refusal; a
//! refusal is a genesis that does not complete — the hand that runs the
//! check writes nothing on `Err`.

use std::fmt;

use skep_address::{is_prefix, Address};

use crate::rows::{Kind, Row, Subtype, COMMONS_TYPE_PREFIX, RESERVE};

/// The seeding check's refusal, naming its arm.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SeedingRefusal {
    /// The disjointness arm: a registry row and a foreign row whose
    /// subtrees meet.
    Disjointness { registry: Address, foreign: Address },
    /// The completeness arm: a kind (`subtype` none) or a subtype row the
    /// list does not hold.
    Completeness { kind: Kind, subtype: Option<Subtype> },
    /// The count arm: more kind rows than the reserve's ordinals, or — with
    /// `row` named — a kind row that is no bare ordinal inside the reserve,
    /// or a second kind row at an ordinal already taken.
    Count { kind_rows: usize, row: Option<Address> },
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
                "disjointness: the registry row {} and the commons row {} meet at the subtree grain",
                registry.tumbler(),
                foreign.tumbler()
            ),
            SeedingRefusal::Completeness { kind, subtype: None } => {
                write!(f, "completeness: {} has no row", kind.name())
            }
            SeedingRefusal::Completeness { kind, subtype: Some(subtype) } => write!(
                f,
                "completeness: {} has no row under {}",
                subtype.name(),
                kind.name()
            ),
            SeedingRefusal::Count { kind_rows, row: None } => write!(
                f,
                "count: {kind_rows} kind rows against the reserve's {} ordinals 3.{}-3.{}",
                RESERVE.count(),
                RESERVE.start(),
                RESERVE.end()
            ),
            SeedingRefusal::Count { kind_rows, row: Some(row) } => write!(
                f,
                "count: of {kind_rows} kind rows, {} is no bare ordinal of the reserve 3.{}-3.{} left to it",
                row.tumbler(),
                RESERVE.start(),
                RESERVE.end()
            ),
        }
    }
}

impl std::error::Error for SeedingRefusal {}

/// THE CHECK: `rows`, the registry's rows as a list — [`crate::rows`] on a
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
    let kind_row = |kind: Kind| rows.iter().find(|r| r.kind == kind && r.subtype.is_none());
    for kind in Kind::ALL {
        if kind_row(kind).is_none() {
            return Err(SeedingRefusal::Completeness { kind, subtype: None });
        }
    }
    for subtype in Subtype::ALL {
        let kind = subtype.kind();
        let under = kind_row(kind).expect("every kind's row stands, checked above");
        let present = rows.iter().any(|r| {
            r.kind == kind
                && r.subtype == Some(subtype)
                && r.address != under.address
                && is_prefix(under.address.tumbler(), r.address.tumbler())
        });
        if !present {
            return Err(SeedingRefusal::Completeness { kind, subtype: Some(subtype) });
        }
    }
    // 3 — THE COUNT: the kind rows against the reserve's ordinals.
    let kind_rows: Vec<&Row> = rows.iter().filter(|r| r.subtype.is_none()).collect();
    if kind_rows.len() > RESERVE.count() {
        return Err(SeedingRefusal::Count { kind_rows: kind_rows.len(), row: None });
    }
    let mut taken: Vec<u32> = Vec::new();
    for r in &kind_rows {
        match reserve_ordinal(&r.address) {
            Some(ordinal) if !taken.contains(&ordinal) => taken.push(ordinal),
            _ => {
                return Err(SeedingRefusal::Count {
                    kind_rows: kind_rows.len(),
                    row: Some(r.address.clone()),
                })
            }
        }
    }
    Ok(())
}

/// The reserve ordinal a kind's row sits at — `a` is the commons type
/// prefix then ONE ordinal inside [`RESERVE`] — else `None`.
fn reserve_ordinal(a: &Address) -> Option<u32> {
    let spelled = a.tumbler().to_string();
    let prefix: Vec<String> = COMMONS_TYPE_PREFIX.iter().map(u32::to_string).collect();
    let tail = spelled.strip_prefix(&format!("{}.", prefix.join(".")))?;
    let ordinal: u32 = tail.parse().ok()?;
    RESERVE.contains(&ordinal).then_some(ordinal)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rows::{commons_type, rows};

    /// The shipped rows pass against nothing foreign and against the rows
    /// the map lists as the build's; every arm of the check is proved on a
    /// list a suite builds, in the crate's integration suite.
    #[test]
    fn the_shipped_rows_pass() {
        assert_eq!(seeding_check(rows(), std::iter::empty()), Ok(()));
        let foreign: Vec<Address> = [1, 2, 3, 12, 14, 22, 42, 60, 61, 89, 90, 91]
            .iter()
            .map(|&o| commons_type(&[o]))
            .collect();
        assert_eq!(seeding_check(rows(), &foreign), Ok(()));
    }

    #[test]
    fn the_reserve_ordinal_is_read_off_a_bare_row_inside_the_reserve_alone() {
        assert_eq!(reserve_ordinal(&commons_type(&[55])), Some(55));
        assert_eq!(reserve_ordinal(&commons_type(&[59])), Some(59));
        assert_eq!(reserve_ordinal(&commons_type(&[54])), None);
        assert_eq!(reserve_ordinal(&commons_type(&[60])), None);
        assert_eq!(reserve_ordinal(&commons_type(&[57, 1])), None);
    }
}
