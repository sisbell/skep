//! THE TWELVE ROWS — the registry's kinds and subtype rows at the addresses
//! commons-map pins (REG-1.14, REG-1.15, REG-1.26; the map's table "THE
//! REGISTRY'S TWELVE ROWS"), spelled ONCE as one table and read through
//! held pins, as the engine's commons ledger holds its own.
//!
//! Five KINDS on the registry range's five ordinals `3.55`–`3.59` (REG-1.23
//! to REG-1.25) and seven SUBTYPE rows nested under their kinds by prefix
//! (REG-1.20; L10: hierarchy is prefix), each subtype its own wire type at
//! the type slot (REG-1.21). THE BARE ORDINAL IS A TEST, NOT A PER-KIND
//! ANSWER (REG-1.18): a kind that reads ONE way — the binding, the endpoint,
//! `successor-of` — carries its deposits on its own ordinal and owes no
//! subtype row; a kind that reads MORE than one way — the takedown record
//! (two readings), the policy link (five) — carries NONE on its bare
//! ordinal, every reading a row at a prefix under it. The map's "Deposits"
//! column is that test, computed off the subtype rows' kinds and never
//! stored ([`Row::carries_deposits`]), so a kind given a second reading
//! (REG-1.19) moves its column by the test alone.
//!
//! THE ORDER (the map): the first three kinds in REG-1.14's order at `3.55`,
//! `3.56`, `3.57`; `successor-of`, REG-1.14's fourth kind, at `3.59` where
//! the build already had it; the policy link, its fifth, at `3.58`, the
//! ordinal the cut home-link kind freed. The subtype ordinals follow
//! REG-1.15's row order.
//!
//! Every address is the ghost home document's subspace-3 element —
//! `1.1.0.1.0.1 · 0 · 3 · <ordinals>`, the commons' type subspace, where
//! nothing is ever minted — spelled here from [`COMMONS_TYPE_PREFIX`], read
//! back here ([`registry_range_ordinal`]), and nowhere else in this crate.
//! The engine's ledger reads these pins, and the daemon's write-path classes
//! read them through it. Two spellings in shipped code stand outside this
//! table, each held equal to its pin by the suite that can see both: the
//! ledger's own `successor-of`, held equal to [`t_successor_of`] by the
//! ledger's tests, and the insert door's deposit class
//! (`skep-arrangement`'s `DEPOSIT_CLASS_ORDINALS`), whose `55` and `56` the
//! daemon's suite (`skepd/tests/it/deposit_class.rs`) holds equal to
//! [`t_binding`] and [`t_endpoint`].

use std::ops::RangeInclusive;
use std::sync::LazyLock;

use skep_address::{validate, Address, Nat, Tumbler};

/// The five KINDS (REG-1.14), in the order its table lists them.
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
    /// Every kind, in REG-1.14's order — the completeness arm's list.
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

    /// The kind's own row in the table ([`rows()`]), held.
    pub fn row(self) -> &'static Row {
        rows().iter().find(|r| r.of == RowOf::Kind(self)).expect("the table holds every kind's row")
    }
}

/// The seven SUBTYPE rows (REG-1.15), in the order its table lists them.
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
    /// Every subtype row, in REG-1.15's row order — the completeness arm's
    /// list.
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

    /// The subtype's row in the table ([`rows()`]), held — nested under its
    /// kind's ([`Subtype::kind`]), which the subtype names, so no caller
    /// names the kind beside it.
    pub fn row(self) -> &'static Row {
        rows()
            .iter()
            .find(|r| r.of == RowOf::Subtype(self))
            .expect("the table holds every subtype row")
    }
}

/// What a row is the row OF: a kind, whose own row sits at its bare
/// ordinal, or a subtype, whose row nests under the row of the kind it
/// names (REG-1.20). A subtype row's kind is read off its subtype
/// ([`RowOf::kind`]), so a row whose kind and subtype disagree is no value
/// of this type. The inverse of [`Kind::row`] and [`Subtype::row`]:
/// `kind.row().of == RowOf::Kind(kind)`, and `subtype.row().of ==
/// RowOf::Subtype(subtype)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RowOf {
    /// A kind's own row, at its bare ordinal.
    Kind(Kind),
    /// A subtype row, under its kind's.
    Subtype(Subtype),
}

impl RowOf {
    /// The kind the row belongs to — its own, or the one its subtype nests
    /// under ([`Subtype::kind`]).
    pub fn kind(self) -> Kind {
        match self {
            RowOf::Kind(kind) => kind,
            RowOf::Subtype(subtype) => subtype.kind(),
        }
    }

    /// The subtype, for a subtype row; `None` for a kind's own row.
    pub fn subtype(self) -> Option<Subtype> {
        match self {
            RowOf::Kind(_) => None,
            RowOf::Subtype(subtype) => Some(subtype),
        }
    }
}

/// One of the twelve rows: the row of a kind or of a subtype, as [`RowOf`]
/// names it. The fields are public and the type is `Clone` so a suite can
/// build a list that differs from [`rows`] by one row and hand it to the
/// seeding check ([`crate::seeding_check`]), whose refusals are proved on
/// such lists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    /// What the row is the row of: a kind, or a subtype under its kind.
    pub of: RowOf,
    /// The row's address: the ghost home document's subspace-3 element.
    pub address: Address,
    /// The `type` member's string where the row's record carries a body
    /// (REG-1.86 (a)) — the seven body-bearing rows. None at the other five:
    /// the three link-alone rows (lifted, the policy link's own reading,
    /// `successor-of`), which carry no body at all, and the bare ordinals of
    /// the takedown record and the policy link, which carry no deposit
    /// (REG-1.18). The binding's and the endpoint's are the strings
    /// [`crate::encode`] writes and [`crate::parse`] holds a body to.
    pub type_value: Option<&'static str>,
}

impl Row {
    /// The map's "Deposits" column: whether a deposit rides THIS address —
    /// REG-1.18's test, which every reader of a kind's deposits reads. Every
    /// subtype row carries deposits; a kind's own row carries them exactly
    /// where no subtype row nests under the kind, a kind that reads ONE way,
    /// and none where its readings are rows under it. Computed off
    /// [`Subtype::ALL`] and [`Subtype::kind`] and never stored, so a kind
    /// given a SECOND reading (REG-1.19) carries none on its bare ordinal by
    /// the test itself once its subtype joins `Subtype::ALL`, as the
    /// completeness arm requires of every subtype row.
    pub fn carries_deposits(&self) -> bool {
        match self.of {
            RowOf::Subtype(_) => true,
            RowOf::Kind(kind) => !Subtype::ALL.iter().any(|s| s.kind() == kind),
        }
    }
}

/// The commons' type subspace of the ghost home document, `1.1.0.1.0.1 · 0
/// · 3` — the eight components ahead of a row's ordinals, spelled once.
const COMMONS_TYPE_PREFIX: [u32; 8] = [1, 1, 0, 1, 0, 1, 0, 3];

/// THE REGISTRY RANGE — the five ordinals `3.55`–`3.59` the kinds take as
/// commons-map's allocation ledger stands (REG-1.23, REG-1.24): the count
/// arm's bound (REG-1.25). Not the reserve commons-map names, `3.51`–`3.59`:
/// the reserve's name is no range (REG-1.23; REG-1.37 (b)), and its
/// `3.51`–`3.54` stay unallocated, no ordinal of this one (REG-1.24).
pub(crate) const REGISTRY_RANGE: RangeInclusive<u32> = 55..=59;

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

/// The ordinal of the registry range whose [`commons_type`] `a` IS — a bare
/// ordinal inside [`REGISTRY_RANGE`], where a kind's row sits — else `None`:
/// what the seeding check's count arm holds each kind row to.
pub(crate) fn registry_range_ordinal(a: &Address) -> Option<u32> {
    let mut range = REGISTRY_RANGE;
    range.find(|&ordinal| *a == commons_type(&[ordinal]))
}

/// The table's spelling of one row — what [`rows`] builds a [`Row`] from.
struct Spelling {
    of: RowOf,
    ordinals: &'static [u32],
    type_value: Option<&'static str>,
}

/// THE TABLE, in the map's order: five kinds, each followed by its subtype
/// rows where it has any.
const SPELLINGS: [Spelling; 12] = [
    Spelling { of: RowOf::Kind(Kind::Binding), ordinals: &[55], type_value: Some("binding") },
    Spelling { of: RowOf::Kind(Kind::Endpoint), ordinals: &[56], type_value: Some("endpoint") },
    Spelling { of: RowOf::Kind(Kind::TakedownRecord), ordinals: &[57], type_value: None },
    Spelling {
        of: RowOf::Subtype(Subtype::TakedownBase),
        ordinals: &[57, 1],
        type_value: Some("takedown"),
    },
    Spelling { of: RowOf::Subtype(Subtype::TakedownLifted), ordinals: &[57, 2], type_value: None },
    Spelling { of: RowOf::Kind(Kind::PolicyLink), ordinals: &[58], type_value: None },
    Spelling { of: RowOf::Subtype(Subtype::PolicyLinkOwn), ordinals: &[58, 1], type_value: None },
    Spelling {
        of: RowOf::Subtype(Subtype::Disavowal),
        ordinals: &[58, 2],
        type_value: Some("disavowal"),
    },
    Spelling {
        of: RowOf::Subtype(Subtype::ExpulsionGround),
        ordinals: &[58, 3],
        type_value: Some("expulsion-ground"),
    },
    Spelling {
        of: RowOf::Subtype(Subtype::SuccessionGround),
        ordinals: &[58, 4],
        type_value: Some("succession-ground"),
    },
    Spelling {
        of: RowOf::Subtype(Subtype::SuccessionPolicy),
        ordinals: &[58, 5],
        type_value: Some("succession-policy"),
    },
    Spelling { of: RowOf::Kind(Kind::SuccessorOf), ordinals: &[59], type_value: None },
];

/// THE TWELVE ROWS, held once: built from the table at the first read, so a
/// reader hands back a borrow of one process-wide value and a pin is never
/// rebuilt per consult.
pub fn rows() -> &'static [Row; 12] {
    static ROWS: LazyLock<[Row; 12]> = LazyLock::new(|| {
        SPELLINGS.each_ref().map(|s| Row {
            of: s.of,
            address: commons_type(s.ordinals),
            type_value: s.type_value,
        })
    });
    &ROWS
}

/// The row whose address IS `a`, else `None` — by EQUALITY, never by
/// prefix: an address beneath a row or above one is no row of the table.
/// The difference is load-bearing where a reader sets the registry's rows
/// apart from the commons' others — the seeding check's domain (REG-1.31) —
/// since a foreign row placed under a kind is what the disjointness arm
/// exists to catch (REG-1.30), and a prefix test would set it aside unseen.
pub fn row_at(a: &Address) -> Option<&'static Row> {
    rows().iter().find(|r| r.address == *a)
}

/// The BINDING — `1.1.0.1.0.1.0.3.55`; deposits ride the bare ordinal.
pub fn t_binding() -> &'static Address {
    &Kind::Binding.row().address
}

/// The ENDPOINT — `1.1.0.1.0.1.0.3.56`; deposits ride the bare ordinal, and
/// no subtype row stands under it (the org row retired).
pub fn t_endpoint() -> &'static Address {
    &Kind::Endpoint.row().address
}

/// The TAKEDOWN RECORD's kind — `1.1.0.1.0.1.0.3.57`; no deposit on the bare
/// ordinal (two readings).
pub fn t_takedown_record() -> &'static Address {
    &Kind::TakedownRecord.row().address
}

/// The takedown record's BASE reading — `1.1.0.1.0.1.0.3.57.1`.
pub fn t_takedown_base() -> &'static Address {
    &Subtype::TakedownBase.row().address
}

/// LIFTED — `1.1.0.1.0.1.0.3.57.2`; link-alone.
pub fn t_takedown_lifted() -> &'static Address {
    &Subtype::TakedownLifted.row().address
}

/// The POLICY LINK's kind — `1.1.0.1.0.1.0.3.58`; no deposit on the bare
/// ordinal (five readings).
pub fn t_policy_link() -> &'static Address {
    &Kind::PolicyLink.row().address
}

/// The policy link's OWN reading — `1.1.0.1.0.1.0.3.58.1`; link-alone.
pub fn t_policy_link_own() -> &'static Address {
    &Subtype::PolicyLinkOwn.row().address
}

/// The DISAVOWAL — `1.1.0.1.0.1.0.3.58.2`.
pub fn t_disavowal() -> &'static Address {
    &Subtype::Disavowal.row().address
}

/// An expulsion's GROUND RECORD — `1.1.0.1.0.1.0.3.58.3`.
pub fn t_expulsion_ground() -> &'static Address {
    &Subtype::ExpulsionGround.row().address
}

/// A succession's GROUND RECORD — `1.1.0.1.0.1.0.3.58.4`.
pub fn t_succession_ground() -> &'static Address {
    &Subtype::SuccessionGround.row().address
}

/// The ORG-CHOSEN SUCCESSION POLICY — `1.1.0.1.0.1.0.3.58.5`.
pub fn t_succession_policy() -> &'static Address {
    &Subtype::SuccessionPolicy.row().address
}

/// `successor-of` — `1.1.0.1.0.1.0.3.59`; link-alone, the engine's own pin
/// held equal to this one.
pub fn t_successor_of() -> &'static Address {
    &Kind::SuccessorOf.row().address
}

#[cfg(test)]
mod tests {
    use skep_address::is_prefix;

    use super::*;

    /// Every row's address is the ghost home document's subspace-3 element
    /// at the ordinals the map pins, spelled as a client spells it.
    #[test]
    fn the_twelve_rows_sit_at_the_maps_addresses() {
        let spelled: Vec<String> = rows().iter().map(|r| r.address.to_string()).collect();
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
            t_takedown_record,
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
            assert!(std::ptr::eq(read(), &row.address), "{}", row.address);
            assert!(std::ptr::eq(read(), read()), "{}: rebuilt per read", row.address);
        }
    }

    /// REG-1.18's test, as the map's "Deposits" column records it: the three
    /// one-reading kinds and every subtype row carry deposits; the two bare
    /// ordinals of the kinds that read more than one way carry none.
    #[test]
    fn the_bare_ordinal_carries_deposits_exactly_where_the_kind_reads_one_way() {
        for r in rows() {
            let bare_of_a_many_reading_kind =
                matches!(r.of, RowOf::Kind(Kind::TakedownRecord | Kind::PolicyLink));
            assert_eq!(r.carries_deposits(), !bare_of_a_many_reading_kind, "{:?}", r.of);
        }
    }

    /// REG-1.18's test read off the table's ADDRESSES: a row carries
    /// deposits exactly where no other row nests under it — so the column
    /// computed off the subtypes' kinds agrees with the readings the table
    /// places under each kind.
    #[test]
    fn a_row_carries_deposits_exactly_where_no_reading_nests_under_it() {
        for r in rows() {
            let nested = rows().iter().any(|s| {
                s.address != r.address && is_prefix(r.address.tumbler(), s.address.tumbler())
            });
            assert_eq!(r.carries_deposits(), !nested, "{}", r.address);
        }
    }

    /// Every row nests under its own kind's row alone: a subtype row is a
    /// PREFIX under its own kind's row (REG-1.20) and under no other kind's,
    /// and a kind's own row is that row itself, under no other kind's — the
    /// kind rows are pairwise prefix-free.
    #[test]
    fn every_row_nests_under_its_own_kinds_row_alone() {
        let kind_rows: Vec<&Row> =
            rows().iter().filter(|r| matches!(r.of, RowOf::Kind(_))).collect();
        for (i, a) in kind_rows.iter().enumerate() {
            for b in &kind_rows[i + 1..] {
                assert!(
                    !is_prefix(a.address.tumbler(), b.address.tumbler())
                        && !is_prefix(b.address.tumbler(), a.address.tumbler())
                );
            }
        }
        for r in rows().iter().filter(|r| matches!(r.of, RowOf::Subtype(_))) {
            for k in &kind_rows {
                let nested = is_prefix(k.address.tumbler(), r.address.tumbler());
                assert_eq!(nested, k.of.kind() == r.of.kind(), "{:?} under {:?}", r.of, k.of);
            }
        }
    }

    /// The `type` strings are the rules' names lowercased and hyphenated
    /// (REG-1.86 (a)), present at the seven body-bearing rows and at none of
    /// the other five: the three link-alone rows and the two bare ordinals
    /// that carry no deposit (REG-1.18).
    #[test]
    fn the_type_strings_stand_at_the_body_bearing_rows_alone() {
        let typed: Vec<(Option<Subtype>, Option<&str>)> =
            rows().iter().map(|r| (r.of.subtype(), r.type_value)).collect();
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

    /// The count arm's bound: the registry range's five ordinals (REG-1.25),
    /// never the reserve's name (REG-1.24).
    #[test]
    fn the_registry_range_is_the_five_ordinals_the_kinds_take() {
        assert_eq!(REGISTRY_RANGE, 55..=59);
    }

    /// A bare ordinal of the registry range in the commons type subspace
    /// answers itself; `3.54` — inside the reserve commons-map names and
    /// outside the registry range (REG-1.24) — an ordinal past the range, a
    /// row beneath a kind, a deeper address ending in a range ordinal and
    /// that ordinal in another subspace of the ghost home document answer
    /// none.
    #[test]
    fn the_registry_range_ordinal_is_read_off_a_bare_row_inside_the_range_alone() {
        assert_eq!(registry_range_ordinal(&commons_type(&[55])), Some(55));
        assert_eq!(registry_range_ordinal(&commons_type(&[59])), Some(59));
        assert_eq!(registry_range_ordinal(&commons_type(&[54])), None);
        assert_eq!(registry_range_ordinal(&commons_type(&[60])), None);
        assert_eq!(registry_range_ordinal(&commons_type(&[57, 1])), None);
        assert_eq!(registry_range_ordinal(&commons_type(&[55, 55])), None);
        let subspace_1 = [1u32, 1, 0, 1, 0, 1, 0, 1, 55].map(Nat::from);
        let subspace_1 = validate(Tumbler::new(subspace_1).expect("nonempty")).expect("T4-valid");
        assert_eq!(registry_range_ordinal(&subspace_1), None);
    }

    /// Each kind and each subtype names its own row of the table, held: a
    /// kind its bare row, a subtype the row under the kind it names — and
    /// the row's [`RowOf`] reads back the kind and the subtype it is of.
    #[test]
    fn each_kind_and_subtype_names_its_own_row() {
        for kind in Kind::ALL {
            let r = kind.row();
            assert_eq!((r.of, r.of.kind(), r.of.subtype()), (RowOf::Kind(kind), kind, None));
            assert!(std::ptr::eq(r, kind.row()), "{kind:?}");
        }
        for subtype in Subtype::ALL {
            let r = subtype.row();
            let of = (r.of, r.of.kind(), r.of.subtype());
            assert_eq!(of, (RowOf::Subtype(subtype), subtype.kind(), Some(subtype)));
            assert!(std::ptr::eq(r, subtype.row()), "{subtype:?}");
        }
        assert_eq!(&Kind::Binding.row().address, t_binding());
        assert_eq!(&Subtype::Disavowal.row().address, t_disavowal());
        assert_eq!(Kind::SuccessorOf.row().type_value, None);
    }

    /// The row AT an address is answered by equality: every row's own
    /// address answers that row, held; an address beneath a row, the
    /// subspace above every row and a foreign row answer none.
    #[test]
    fn row_at_answers_a_rows_own_address_alone() {
        for r in rows() {
            let found = row_at(&r.address);
            assert!(found.is_some_and(|f| std::ptr::eq(f, r)), "{}", r.address);
        }
        let subspace = Tumbler::new(COMMONS_TYPE_PREFIX.map(Nat::from)).expect("nonempty");
        let subspace = validate(subspace).expect("T4-valid");
        let beneath = [commons_type(&[58, 6]), commons_type(&[57, 1, 1])];
        for a in beneath.into_iter().chain([subspace, commons_type(&[12])]) {
            assert_eq!(row_at(&a), None, "{a}");
        }
    }
}
