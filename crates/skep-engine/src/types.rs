//! The COMMONS type addresses the engine and the daemon key on as VALUES —
//! never as registered M7 types, so `TypeRegistry` is untouched by every one
//! of them. Each is the ghost document's subspace-3 element `ordinal` —
//! `1.1.0.1.0.1 · 0 · 3 · ordinal`, the core vocabulary's home
//! (`commons-map.md`), where the AUTH round's credential types
//! (`3.{1,2,3}`, the daemon's own constants) already sit.
//!
//! Two consumers: the engine's own derived indexes ([`t_grant`] for the grant
//! fold, [`t_edition`] for the audit-view edition-claim lookup), and the
//! daemon's write-path type-recognition input (PUB round 2, lane 3.5 §1;
//! owner ruling D3, 2026-09-05) — the class addresses a `nullify` is refused
//! at (PUB-6.30's grant, PUB-6.64's audit-view members), pinned here beside
//! the two the engine reads so ONE ledger names them all. Every pin below
//! cites its commons row and its confirmation (the owner, 2026-09-07); a pin
//! is never silently renumbered — a change is a confirmed row there and a
//! dated line here.
//!
//! A pin is HELD, not manufactured per call: each reader below hands back a
//! borrow of one process-wide value, so the ledger is one instance and not
//! one construction per consult. That matters where the consults are: the
//! grant fold reads [`t_grant`] on every folded link record — once per deposit
//! on the live path and once per link record through a whole replay — and a
//! rebuilt pin is nine big-integer allocations, a vector and a T4 walk. The
//! addresses are compiled format constants, so there is nothing per-call for
//! them to depend on.

use std::sync::LazyLock;

use skep_address::{validate, Address, Nat, Tumbler};

/// A commons type address: the ghost document's subspace-3 element `ordinal`.
/// Called once per pin, at that pin's first read.
fn commons_type(ordinal: u32) -> Address {
    validate(
        Tumbler::new([1u32, 1, 0, 1, 0, 1, 0, 3, ordinal].into_iter().map(Nat::from))
            .expect("the commons type components are nonempty"),
    )
    .expect("a subspace-3 element of the ghost document is T4-valid by construction")
}

/// The GRANTS class type address — `1.1.0.1.0.1.0.3.90`.
///
/// COMMONS DECISION 5 — commons-map.md: "GRANTS/commerce | grant, price,
/// receipt-citation | 3.90–3.99 (decision 5)": the first address of the
/// Commerce range. CONFIRMED by the owner 2026-09-07 (owed since lane 3.3:
/// the ledger bounds the range and left the exact address to seeding). The
/// grant fold keys on it by denotation equality; the write path recognizes
/// it (and its subtypes by prefix) as PUB-6.30's grant-typed class.
pub fn t_grant() -> &'static Address {
    static ADDR: LazyLock<Address> = LazyLock::new(|| commons_type(90));
    &ADDR
}

/// The EDITION-CLAIM class type address (R20) — `1.1.0.1.0.1.0.3.14`,
/// read by the audit-view lookup (`crate::editions`).
///
/// CONFIRMED by the owner 2026-09-07. commons-seeding.md's row `3.14 |
/// edition` carries the descriptive subtypes `.1 abridged .2 expanded .3
/// translated .4 revised .5 annotated` beneath it (note 3: "a descriptive
/// edition relation is `edition.*`"); commons-map.md places the core
/// vocabulary at `3.1–3.21` with `edition` listed. Class membership is by
/// PREFIX: a type slot denoting
/// `3.14.k` is a subtype's member and counts — the lookup names the CLASS,
/// not one address. NOT a write-path refusal class: the claim is read under
/// the ACTIVE view (PUB-6.32), so its owner's `nullify` is admitted.
pub fn t_edition() -> &'static Address {
    static ADDR: LazyLock<Address> = LazyLock::new(|| commons_type(14));
    &ADDR
}

/// The succession pair's `successor-of` claim type — `1.1.0.1.0.1.0.3.59`
/// (PUB-7.63; PUB-6.64's member).
///
/// commons-map.md: "Succession | successor-of | 3.59 (registry reserve; the
/// supersession CLAIM stays the managed ⟦supersedes⟧ class, not commons)";
/// commons-seeding.md's reserved-range table lists `3.59` as CLAIMED. Not
/// provisional.
pub fn t_successor_of() -> &'static Address {
    static ADDR: LazyLock<Address> = LazyLock::new(|| commons_type(59));
    &ADDR
}

/// The succession pair's delegator ENDORSEMENT type — the `endorse` type,
/// `1.1.0.1.0.1.0.3.42` (PUB-7.63; PUB-6.64's member).
///
/// commons-seeding.md's seeded vocabulary: "3.42 | endorse | + .1 expertise
/// .2 trust .3 collaboration" (the social range 3.40–3.45); commons-map.md:
/// "endorse already 3.42". Not provisional. Its subtypes are members by
/// prefix (L10).
pub fn t_delegator_endorsement() -> &'static Address {
    static ADDR: LazyLock<Address> = LazyLock::new(|| commons_type(42));
    &ADDR
}

/// The CONSUMPTION MARKER type — `1.1.0.1.0.1.0.3.91`, CONFIRMED by the
/// owner 2026-09-07 (PUB-4.12, PUB-4.17; PUB-6.64's member).
///
/// commons-map.md's PUB consumption row: "3.90–3.99
/// beside the GRANTS/commerce claim — the pair's other half … exact address
/// at seeding" — ONE number (the marker's two values `offer_accepted` /
/// `offer_declined` are client-interpreted VALUES in the FROM slot, LM 4/53,
/// never subtypes). Pinned at the range's second address, beside the grant.
pub fn t_consumption_marker() -> &'static Address {
    static ADDR: LazyLock<Address> = LazyLock::new(|| commons_type(91));
    &ADDR
}

/// The JOURNAL DESIGNATION type — `1.1.0.1.0.1.0.3.22`, CONFIRMED by the
/// owner 2026-09-07 (PUB-4.3, PUB-4.12; PUB-6.64's member).
///
/// commons-map.md's PUB journal self-designation row:
/// "3.22–3.29 structural extension (designation is structure — what a
/// document IS — not commerce; the placement lean). ONE number, exact
/// address at seeding; the reserve is 8 wide and decisions 0/6 may also land
/// here". Pinned at the reserve's first address.
pub fn t_journal_designation() -> &'static Address {
    static ADDR: LazyLock<Address> = LazyLock::new(|| commons_type(22));
    &ADDR
}

/// The RAIL RECORD type — `1.1.0.1.0.1.0.3.60`, CONFIRMED by the owner
/// 2026-09-07 (PUB-5.76; PUB-6.64's member, inheriting on PUB-6.30's
/// ground).
///
/// commons-map.md's PUB rail record row (owner 2026-09-06): "3.60 (agentic
/// tier) — PROVISIONAL, exact at seeding; hire-side governance of an
/// agent".
pub fn t_rail_record() -> &'static Address {
    static ADDR: LazyLock<Address> = LazyLock::new(|| commons_type(60));
    &ADDR
}

/// The steward's CLASSIFICATION link type — `1.1.0.1.0.1.0.3.61`, CONFIRMED
/// by the owner 2026-09-07 (PUB-5.43; PUB-6.64's member where the link's
/// own home is published, RES-207).
///
/// commons-map.md's PUB steward classification link row (owner 2026-09-06):
/// "3.61 (agentic tier) — PROVISIONAL, exact at seeding; the
/// review/resolution layer the tier is reserved for".
pub fn t_steward_classification() -> &'static Address {
    static ADDR: LazyLock<Address> = LazyLock::new(|| commons_type(61));
    &ADDR
}

#[cfg(test)]
mod tests {
    use skep_address::is_prefix;

    use super::*;

    /// The eight pins are pairwise distinct and — since the write path
    /// recognizes a class's SUBTYPES by prefix — pairwise prefix-free: a pin
    /// under another's prefix would make one class swallow the other.
    #[test]
    fn the_commons_pins_are_pairwise_prefix_free() {
        let pins = [
            t_grant(),
            t_edition(),
            t_successor_of(),
            t_delegator_endorsement(),
            t_consumption_marker(),
            t_journal_designation(),
            t_rail_record(),
            t_steward_classification(),
        ];
        for (i, a) in pins.iter().enumerate() {
            for b in &pins[i + 1..] {
                assert!(
                    !is_prefix(a.tumbler(), b.tumbler()) && !is_prefix(b.tumbler(), a.tumbler()),
                    "{} and {} are prefix-related",
                    a.tumbler(),
                    b.tumbler()
                );
            }
        }
    }

    /// Every pin sits in the ghost document's subspace 3, where nothing is
    /// ever minted (the credential types' own unreachability argument,
    /// AUTH-3.70), so no content resolution can ever equal one.
    #[test]
    fn every_pin_is_a_ghost_subspace_3_element() {
        for (pin, ordinal) in [
            (t_grant(), 90u32),
            (t_edition(), 14),
            (t_successor_of(), 59),
            (t_delegator_endorsement(), 42),
            (t_consumption_marker(), 91),
            (t_journal_designation(), 22),
            (t_rail_record(), 60),
            (t_steward_classification(), 61),
        ] {
            assert_eq!(pin.tumbler().to_string(), format!("1.1.0.1.0.1.0.3.{ordinal}"));
        }
    }

    /// A pin is ONE value, held: two reads hand back the same address, not
    /// two equal ones. The ledger's readers are on hot paths — the grant fold
    /// consults [`t_grant`] per folded link record, live and through replay —
    /// so a reader that rebuilt its address per call would be paying nine
    /// big-integer allocations and a T4 walk for a compiled constant.
    #[test]
    fn every_pin_is_one_held_value_rather_than_a_construction_per_read() {
        for (first, again) in [
            (t_grant(), t_grant()),
            (t_edition(), t_edition()),
            (t_successor_of(), t_successor_of()),
            (t_delegator_endorsement(), t_delegator_endorsement()),
            (t_consumption_marker(), t_consumption_marker()),
            (t_journal_designation(), t_journal_designation()),
            (t_rail_record(), t_rail_record()),
            (t_steward_classification(), t_steward_classification()),
        ] {
            assert!(
                std::ptr::eq(first, again),
                "{} is rebuilt per read, not held",
                first.tumbler()
            );
        }
    }
}
