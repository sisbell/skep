//! THE TWELVE ROWS — the registry's kinds and subtype rows at the addresses
//! commons-map pins (REG-1.14, REG-1.15, REG-1.26; the map's table "THE
//! REGISTRY'S TWELVE ROWS"), spelled ONCE as one table and read through
//! held pins, as the engine's commons ledger holds its own.
//!
//! Five KINDS on the reserve's five ordinals `3.55`–`3.59` (REG-1.24,
//! REG-1.25) and seven SUBTYPE rows nested under their kinds by prefix
//! (REG-1.20; L10: hierarchy is prefix), each subtype its own wire type at
//! the type slot (REG-1.21). THE BARE ORDINAL IS A TEST, NOT A PER-KIND
//! ANSWER (REG-1.18): a kind that reads ONE way — the binding, the endpoint,
//! `successor-of` — carries its deposits on its own ordinal and owes no
//! subtype row; a kind that reads MORE than one way — the takedown record
//! (two readings), the policy link (five) — carries NONE on its bare
//! ordinal, every reading a row at a prefix under it. The map's "Deposits"
//! column is [`Row::deposits`].
//!
//! THE ORDER (the map): the first three kinds in REG-1.14's order at `3.55`,
//! `3.56`, `3.57`; `successor-of`, REG-1.14's fourth kind, at `3.59` where
//! the build already had it; the policy link, its fifth, at `3.58`, the
//! ordinal the cut home-link kind freed. The subtype ordinals follow
//! REG-1.15's row order.
//!
//! Every address is the ghost home document's subspace-3 element —
//! `1.1.0.1.0.1 · 0 · 3 · <ordinals>`, the commons' type home, where
//! nothing is ever minted — spelled here from [`COMMONS_TYPE_PREFIX`] and
//! nowhere else in this crate. The engine's ledger reads these pins, and
//! the daemon's write-path classes read them through it. Two spellings in
//! shipped code stand outside this table, each held equal to its pin by the
//! suite that can see both: the ledger's own `successor-of`, held equal to
//! [`t_successor_of`] by the ledger's tests, and the insert door's deposit
//! class (`skep-arrangement`'s `DEPOSIT_CLASS_ORDINALS`), whose `55` and
//! `56` the daemon's suite (`skepd/tests/it/deposit_class.rs`) holds equal
//! to [`t_binding`] and [`t_endpoint`].

use std::ops::RangeInclusive;
use std::sync::LazyLock;

use skep_address::{validate, Address, Nat, Tumbler};

/// The five KINDS (REG-1.14), in the home's order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    /// The BINDING — the registration record itself: prefix → account.
    Binding,
    /// The ENDPOINT — the org's own endpoint deposit (REG-1.9).
    Endpoint,
    /// The TAKEDOWN RECORD — the operator's serving-layer instrument, with
    /// its LIFTED subtype.
    TakedownRecord,
    /// `successor-of` — the succession claim, at the fork's seat alone.
    SuccessorOf,
    /// The POLICY LINK — the link naming the published policy document,
    /// with the four records that ride under it as subtypes.
    PolicyLink,
}

impl Kind {
    /// Every kind, in the home's order — the completeness arm's list.
    pub const ALL: [Kind; 5] =
        [Kind::Binding, Kind::Endpoint, Kind::TakedownRecord, Kind::SuccessorOf, Kind::PolicyLink];

    /// The kind's name as the rules spell it.
    pub fn name(self) -> &'static str {
        match self {
            Kind::Binding => "the binding",
            Kind::Endpoint => "the endpoint",
            Kind::TakedownRecord => "the takedown record",
            Kind::SuccessorOf => "successor-of",
            Kind::PolicyLink => "the policy link",
        }
    }
}

/// The seven SUBTYPE rows (REG-1.15), in the home's row order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Subtype {
    /// The takedown record's own BASE reading.
    TakedownBase,
    /// LIFTED — the takedown record's reversal.
    TakedownLifted,
    /// The policy link's OWN reading.
    PolicyLinkOwn,
    /// The DISAVOWAL — the one type of it, an author's in their own doc 1
    /// or an officer's at the policy home.
    Disavowal,
    /// An expulsion's GROUND RECORD.
    ExpulsionGround,
    /// A succession's GROUND RECORD.
    SuccessionGround,
    /// The ORG-CHOSEN SUCCESSION POLICY.
    SuccessionPolicy,
}

impl Subtype {
    /// Every subtype row, in the home's order — the completeness arm's list.
    pub const ALL: [Subtype; 7] = [
        Subtype::TakedownBase,
        Subtype::TakedownLifted,
        Subtype::PolicyLinkOwn,
        Subtype::Disavowal,
        Subtype::ExpulsionGround,
        Subtype::SuccessionGround,
        Subtype::SuccessionPolicy,
    ];

    /// The kind this subtype row nests under (REG-1.20).
    pub fn kind(self) -> Kind {
        match self {
            Subtype::TakedownBase | Subtype::TakedownLifted => Kind::TakedownRecord,
            Subtype::PolicyLinkOwn
            | Subtype::Disavowal
            | Subtype::ExpulsionGround
            | Subtype::SuccessionGround
            | Subtype::SuccessionPolicy => Kind::PolicyLink,
        }
    }

    /// The row's name as the rules spell it.
    pub fn name(self) -> &'static str {
        match self {
            Subtype::TakedownBase => "the takedown record's base reading",
            Subtype::TakedownLifted => "lifted",
            Subtype::PolicyLinkOwn => "the policy link's own reading",
            Subtype::Disavowal => "the disavowal",
            Subtype::ExpulsionGround => "an expulsion's ground record",
            Subtype::SuccessionGround => "a succession's ground record",
            Subtype::SuccessionPolicy => "the org-chosen succession policy",
        }
    }
}

/// One of the twelve rows: a kind's own row (`subtype` none) or a subtype
/// row under its kind. The fields are public and the type is `Clone` so a
/// suite can build a list that differs from [`rows`] by one row and hand it
/// to the seeding check ([`crate::seeding_check`]), whose refusals are proved
/// on such lists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    /// The kind the row belongs to — its own, or its subtype's.
    pub kind: Kind,
    /// `Some` for a subtype row, `None` for a kind's own row.
    pub subtype: Option<Subtype>,
    /// The row's address: the ghost home document's subspace-3 element.
    pub address: Address,
    /// The map's "Deposits" column: whether a deposit rides THIS address
    /// (REG-1.18) — every subtype row and the three one-reading kinds yes,
    /// the two bare ordinals of the kinds that read more than one way NONE.
    pub deposits: bool,
    /// The `type` member's string where the row's record carries a body
    /// (REG-1.86 (a)); none at the three link-alone rows (lifted, the policy
    /// link's own reading, `successor-of`), which carry no body at all.
    pub type_value: Option<&'static str>,
}

/// The commons' type subspace of the ghost home document, `1.1.0.1.0.1 · 0
/// · 3` — the eight components ahead of a row's ordinals, spelled once.
pub(crate) const COMMONS_TYPE_PREFIX: [u32; 8] = [1, 1, 0, 1, 0, 1, 0, 3];

/// The reserve's five ordinals the kinds take, `3.55`–`3.59` as the ledger
/// stands (REG-1.24, REG-1.25): the count arm's bound.
pub(crate) const RESERVE: RangeInclusive<u32> = 55..=59;

/// A commons type address: the commons' type subspace `1.1.0.1.0.1.0.3`
/// then `ordinals` — one for a kind's row, the kind's then the subtype's for
/// a subtype row.
///
/// PANICS on an empty `ordinals` or on a zero among them: a row is an
/// element at a positive ordinal, and the table below spells none other.
/// Public for the readers that name a commons type the table does not hold:
/// `skep-resolve`, which builds with it the credential types `3.1`–`3.3`
/// its mirror's fold tells a stored link's kind by, and the suites that
/// spell a row at an ordinal off the table to prove the seeding check's
/// arms.
pub fn commons_type(ordinals: &[u32]) -> Address {
    assert!(!ordinals.is_empty(), "a commons row names at least one ordinal");
    let comps = COMMONS_TYPE_PREFIX.iter().chain(ordinals).map(|&c| Nat::from(c));
    let tumbler = Tumbler::new(comps).expect("the components are nonempty");
    validate(tumbler).expect("a subspace-3 element at positive ordinals is T4-valid")
}

/// The table's spelling of one row — what [`rows`] builds a [`Row`] from.
struct Spelling {
    kind: Kind,
    subtype: Option<Subtype>,
    ordinals: &'static [u32],
    deposits: bool,
    type_value: Option<&'static str>,
}

/// THE TABLE, in the map's order: five kinds, each followed by its subtype
/// rows where it has any.
const SPELLINGS: [Spelling; 12] = [
    Spelling {
        kind: Kind::Binding,
        subtype: None,
        ordinals: &[55],
        deposits: true,
        type_value: Some("binding"),
    },
    Spelling {
        kind: Kind::Endpoint,
        subtype: None,
        ordinals: &[56],
        deposits: true,
        type_value: Some("endpoint"),
    },
    Spelling {
        kind: Kind::TakedownRecord,
        subtype: None,
        ordinals: &[57],
        deposits: false,
        type_value: None,
    },
    Spelling {
        kind: Kind::TakedownRecord,
        subtype: Some(Subtype::TakedownBase),
        ordinals: &[57, 1],
        deposits: true,
        type_value: Some("takedown"),
    },
    Spelling {
        kind: Kind::TakedownRecord,
        subtype: Some(Subtype::TakedownLifted),
        ordinals: &[57, 2],
        deposits: true,
        type_value: None,
    },
    Spelling {
        kind: Kind::PolicyLink,
        subtype: None,
        ordinals: &[58],
        deposits: false,
        type_value: None,
    },
    Spelling {
        kind: Kind::PolicyLink,
        subtype: Some(Subtype::PolicyLinkOwn),
        ordinals: &[58, 1],
        deposits: true,
        type_value: None,
    },
    Spelling {
        kind: Kind::PolicyLink,
        subtype: Some(Subtype::Disavowal),
        ordinals: &[58, 2],
        deposits: true,
        type_value: Some("disavowal"),
    },
    Spelling {
        kind: Kind::PolicyLink,
        subtype: Some(Subtype::ExpulsionGround),
        ordinals: &[58, 3],
        deposits: true,
        type_value: Some("expulsion-ground"),
    },
    Spelling {
        kind: Kind::PolicyLink,
        subtype: Some(Subtype::SuccessionGround),
        ordinals: &[58, 4],
        deposits: true,
        type_value: Some("succession-ground"),
    },
    Spelling {
        kind: Kind::PolicyLink,
        subtype: Some(Subtype::SuccessionPolicy),
        ordinals: &[58, 5],
        deposits: true,
        type_value: Some("succession-policy"),
    },
    Spelling {
        kind: Kind::SuccessorOf,
        subtype: None,
        ordinals: &[59],
        deposits: true,
        type_value: None,
    },
];

/// THE TWELVE ROWS, held once: built from the table at the first read, so a
/// reader hands back a borrow of one process-wide value and a pin is never
/// rebuilt per consult.
pub fn rows() -> &'static [Row; 12] {
    static ROWS: LazyLock<[Row; 12]> = LazyLock::new(|| {
        SPELLINGS.each_ref().map(|s| Row {
            kind: s.kind,
            subtype: s.subtype,
            address: commons_type(s.ordinals),
            deposits: s.deposits,
            type_value: s.type_value,
        })
    });
    &ROWS
}

/// The row of a kind (`subtype` none) or of a subtype row under it.
pub fn row(kind: Kind, subtype: Option<Subtype>) -> &'static Row {
    rows()
        .iter()
        .find(|r| r.kind == kind && r.subtype == subtype)
        .expect("the table holds every kind and every subtype row")
}

/// The row at index `i` of the table — the readers below, each a held pin.
fn pin(i: usize) -> &'static Address {
    &rows()[i].address
}

/// The BINDING — `1.1.0.1.0.1.0.3.55`; deposits ride the bare ordinal.
pub fn t_binding() -> &'static Address {
    pin(0)
}

/// The ENDPOINT — `1.1.0.1.0.1.0.3.56`; deposits ride the bare ordinal, and
/// no subtype row stands under it (the org row retired).
pub fn t_endpoint() -> &'static Address {
    pin(1)
}

/// The TAKEDOWN RECORD's kind — `1.1.0.1.0.1.0.3.57`; no deposit on the bare
/// ordinal (two readings).
pub fn t_takedown() -> &'static Address {
    pin(2)
}

/// The takedown record's BASE reading — `1.1.0.1.0.1.0.3.57.1`.
pub fn t_takedown_base() -> &'static Address {
    pin(3)
}

/// LIFTED — `1.1.0.1.0.1.0.3.57.2`; link-alone.
pub fn t_takedown_lifted() -> &'static Address {
    pin(4)
}

/// The POLICY LINK's kind — `1.1.0.1.0.1.0.3.58`; no deposit on the bare
/// ordinal (five readings).
pub fn t_policy_link() -> &'static Address {
    pin(5)
}

/// The policy link's OWN reading — `1.1.0.1.0.1.0.3.58.1`; link-alone.
pub fn t_policy_link_own() -> &'static Address {
    pin(6)
}

/// The DISAVOWAL — `1.1.0.1.0.1.0.3.58.2`.
pub fn t_disavowal() -> &'static Address {
    pin(7)
}

/// An expulsion's GROUND RECORD — `1.1.0.1.0.1.0.3.58.3`.
pub fn t_expulsion_ground() -> &'static Address {
    pin(8)
}

/// A succession's GROUND RECORD — `1.1.0.1.0.1.0.3.58.4`.
pub fn t_succession_ground() -> &'static Address {
    pin(9)
}

/// The ORG-CHOSEN SUCCESSION POLICY — `1.1.0.1.0.1.0.3.58.5`.
pub fn t_succession_policy() -> &'static Address {
    pin(10)
}

/// `successor-of` — `1.1.0.1.0.1.0.3.59`; link-alone, the engine's own pin
/// held equal to this one.
pub fn t_successor_of() -> &'static Address {
    pin(11)
}

#[cfg(test)]
mod tests {
    use skep_address::is_prefix;

    use super::*;

    /// Every row's address is the ghost home document's subspace-3 element
    /// at the ordinals the map pins, spelled as a client spells it.
    #[test]
    fn the_twelve_rows_sit_at_the_maps_addresses() {
        let spelled: Vec<String> = rows().iter().map(|r| r.address.tumbler().to_string()).collect();
        assert_eq!(
            spelled,
            [
                "1.1.0.1.0.1.0.3.55",
                "1.1.0.1.0.1.0.3.56",
                "1.1.0.1.0.1.0.3.57",
                "1.1.0.1.0.1.0.3.57.1",
                "1.1.0.1.0.1.0.3.57.2",
                "1.1.0.1.0.1.0.3.58",
                "1.1.0.1.0.1.0.3.58.1",
                "1.1.0.1.0.1.0.3.58.2",
                "1.1.0.1.0.1.0.3.58.3",
                "1.1.0.1.0.1.0.3.58.4",
                "1.1.0.1.0.1.0.3.58.5",
                "1.1.0.1.0.1.0.3.59",
            ]
        );
    }

    /// The readers are the table's rows, one apiece and held: two reads
    /// hand back the same address, not two equal ones.
    #[test]
    fn every_reader_is_one_held_row() {
        let readers: [fn() -> &'static Address; 12] = [
            t_binding,
            t_endpoint,
            t_takedown,
            t_takedown_base,
            t_takedown_lifted,
            t_policy_link,
            t_policy_link_own,
            t_disavowal,
            t_expulsion_ground,
            t_succession_ground,
            t_succession_policy,
            t_successor_of,
        ];
        for (read, row) in readers.iter().zip(rows()) {
            assert!(std::ptr::eq(read(), &row.address), "{}", row.address.tumbler());
            assert!(std::ptr::eq(read(), read()), "{}: rebuilt per read", row.address.tumbler());
        }
    }

    /// REG-1.18's test, as the map's "Deposits" column records it: the three
    /// one-reading kinds and every subtype row carry deposits; the two bare
    /// ordinals of the kinds that read more than one way carry none.
    #[test]
    fn the_bare_ordinal_carries_deposits_exactly_where_the_kind_reads_one_way() {
        for r in rows() {
            let bare_of_a_many_reading_kind =
                matches!((r.kind, r.subtype), (Kind::TakedownRecord | Kind::PolicyLink, None));
            assert_eq!(r.deposits, !bare_of_a_many_reading_kind, "{:?} {:?}", r.kind, r.subtype);
        }
    }

    /// Each subtype row is a PREFIX under its own kind's row (REG-1.20) and
    /// under no other; the kind rows are pairwise prefix-free.
    #[test]
    fn every_subtype_row_nests_under_its_own_kind_alone() {
        let kinds: Vec<&Row> = rows().iter().filter(|r| r.subtype.is_none()).collect();
        for (i, a) in kinds.iter().enumerate() {
            for b in &kinds[i + 1..] {
                assert!(
                    !is_prefix(a.address.tumbler(), b.address.tumbler())
                        && !is_prefix(b.address.tumbler(), a.address.tumbler())
                );
            }
        }
        for r in rows().iter().filter(|r| r.subtype.is_some()) {
            for k in &kinds {
                let nested = is_prefix(k.address.tumbler(), r.address.tumbler());
                assert_eq!(nested, k.kind == r.kind, "{:?} under {:?}", r.subtype, k.kind);
            }
            assert_eq!(r.subtype.map(Subtype::kind), Some(r.kind));
        }
    }

    /// The `type` strings are the rules' names lowercased and hyphenated
    /// (REG-1.86 (a)), present at every body-bearing row and at none of the
    /// three link-alone rows.
    #[test]
    fn the_type_strings_stand_at_the_body_bearing_rows_alone() {
        let typed: Vec<(Option<Subtype>, Option<&str>)> =
            rows().iter().map(|r| (r.subtype, r.type_value)).collect();
        assert_eq!(
            typed,
            [
                (None, Some("binding")),
                (None, Some("endpoint")),
                (None, None),
                (Some(Subtype::TakedownBase), Some("takedown")),
                (Some(Subtype::TakedownLifted), None),
                (None, None),
                (Some(Subtype::PolicyLinkOwn), None),
                (Some(Subtype::Disavowal), Some("disavowal")),
                (Some(Subtype::ExpulsionGround), Some("expulsion-ground")),
                (Some(Subtype::SuccessionGround), Some("succession-ground")),
                (Some(Subtype::SuccessionPolicy), Some("succession-policy")),
                (None, None),
            ]
        );
    }

    /// The count arm's bound: the reserve's five ordinals (REG-1.25).
    #[test]
    fn the_reserve_is_the_five_ordinals_the_kinds_take() {
        assert_eq!(RESERVE, 55..=59);
    }

    #[test]
    fn row_answers_each_kind_and_subtype() {
        assert_eq!(&row(Kind::Binding, None).address, t_binding());
        assert_eq!(&row(Kind::PolicyLink, Some(Subtype::Disavowal)).address, t_disavowal());
        assert_eq!(row(Kind::SuccessorOf, None).type_value, None);
    }
}
