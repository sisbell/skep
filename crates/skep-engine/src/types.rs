//! The COMMONS type addresses the engine and the daemon key on as VALUES —
//! never as registered M7 types, so `TypeRegistry` is untouched by every one
//! of them. Each is the ghost document's subspace-3 element `ordinal` —
//! `1.1.0.1.0.1 · 0 · 3 · ordinal`, the core vocabulary's home
//! (`commons-map.md`), where the AUTH round's credential types
//! (`3.{1,2,3}`, the daemon's own constants) already sit.
//!
//! NOT PINNED HERE, and where they are: the credential types. The engine
//! keys on none of them, so they take no reader below. ENROLL `3.1` and
//! RETIRE `3.2` are spelled twice, each where its consumer can read it — the
//! daemon's `T_ENROLL` / `T_RETIRE` for the credential fold, and M5's
//! [`deposit_class_types`](skep_arrangement::deposit_class_types), the set
//! the insert door tests a deposit declaration's class type against
//! (PUB-2.11; RES-249, RES-261), M5 sitting below this crate and the daemon
//! alike. The daemon's suite pins the two spellings EQUAL; the ledger's tests
//! below hold M5's set prefix-free against every pin, so a pin that joins
//! cannot land on, above or beneath a deposit-class type unnoticed.
//!
//! Two consumers: the engine's own derived indexes ([`t_grant`] and
//! [`t_replaces`] for the grant fold, [`t_edition`] for the audit-view
//! edition-claim lookup), and the daemon's write-path type-recognition input
//! (PUB round 2, lane 3.5 §1; owner ruling D3, 2026-09-05) — the class
//! addresses a `nullify` is refused at (PUB-6.30's grant, PUB-6.64's
//! audit-view members), pinned here beside the ones the engine reads so ONE
//! ledger names them all. Every pin below cites its commons row and its
//! confirmation (the owner, 2026-09-07, and for [`t_replaces`] 2026-09-29); a
//! pin is never silently renumbered — a change is a confirmed row there and a
//! dated line here.
//!
//! ONE PIN IS SPELLED TWICE, by the same rule as the credential types:
//! [`t_replaces`], the authority successor's type, has a writer BELOW this
//! crate — M7's sole-writer fences and the one MAKELINK that mints it — so M7
//! holds its own spelling where those can read it
//! ([`skep_links::replaces_type`]), and the ledger's tests hold the two
//! EQUAL.
//!
//! THE REGISTRY'S TWELVE ROWS (REG-1.14, REG-1.15; commons-map's table of
//! them) are `skep-registry`'s table, read through readers here —
//! [`t_binding`] … [`t_succession_policy`] — so ONE ledger names every
//! commons pin the engine or the daemon keys on; [`t_successor_of`] stays
//! the engine's own pin, the registry's fourth kind, and the tests hold it
//! EQUAL to the crate's row. The daemon's deposit class spells the binding
//! and the endpoint a second time, M5 sitting below this crate, and the
//! daemon's suite holds those EQUAL as it holds the credential pair. The
//! registry's subtype rows NEST under their kinds by prefix (REG-1.20) —
//! the one prefix relation the ledger's guarantee below admits, by design:
//! a consumer recognizing a kind's subtypes by prefix reads a subtype row as
//! its kind's member, which is what REG-1.21 wants of it.
//!
//! A pin is HELD, not manufactured per call: each reader below hands back a
//! borrow of one process-wide value, so the ledger is one instance and not
//! one construction per consult. That matters where the consults are: the
//! grant fold reads [`t_grant`] on every folded link record — at least once
//! per deposit on the live path and per link record through a whole replay —
//! and a rebuilt pin is nine big-integer allocations, a vector and a T4 walk.
//! The addresses are compiled format constants, so there is nothing per-call
//! for them to depend on.
//!
//! GUARANTEE the ledger maintains, and the reason a pin is a decision about
//! ALL of them: the pins are pairwise DISTINCT and pairwise PREFIX-FREE —
//! but for a registry subtype row under its own kind's row, the nesting the
//! registry designs. A consumer that recognizes a class's subtypes by prefix
//! — the daemon's write path does, at every pin it refuses a `nullify` at —
//! relies on it, so a pin sitting under another's prefix makes one class
//! swallow the other and silently widens or narrows a refusal nobody chose.
//! The tests below hold it off ONE list of the pins, which is where a
//! twenty-first joins: nothing else here can notice a pin that reaches a
//! consumer without joining the guarantee.

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
/// PREFIX (L10): a subtype is its class's member, so a type slot denoting
/// `3.14.k` counts — the lookup names the CLASS, not one address. NOT a
/// write-path refusal class: the claim is read under the ACTIVE view
/// (PUB-6.32), so its owner's `nullify` is admitted.
pub fn t_edition() -> &'static Address {
    static ADDR: LazyLock<Address> = LazyLock::new(|| commons_type(14));
    &ADDR
}

/// The succession pair's `successor-of` claim type — `1.1.0.1.0.1.0.3.59`
/// (PUB-7.63; PUB-6.64's member) — and the registry's fourth kind, the
/// succession claim at the fork's seat (REG-1.14), pinned where the build
/// had it: commons-map's table of the registry's twelve rows reads `3.59`
/// as this pin, and the ledger's tests hold it EQUAL to `skep-registry`'s
/// own row ([`skep_registry::t_successor_of`]).
///
/// commons-map.md: "Succession | successor-of | 3.59"; commons-seeding.md's
/// reserved-range table lists `3.59` as CLAIMED. Not provisional.
pub fn t_successor_of() -> &'static Address {
    static ADDR: LazyLock<Address> = LazyLock::new(|| commons_type(59));
    &ADDR
}

// ── the registry's rows (REG-1.14, REG-1.15), `skep-registry`'s table ────

/// The BINDING — `1.1.0.1.0.1.0.3.55`: the registration record, prefix →
/// account, deposits riding the bare ordinal (REG-1.18). The daemon's
/// deposit class holds it (REG-1.37 as the record grade's join re-reads it),
/// its write path refuses a `nullify` at it (REG-1.44, REG-1.46), and the
/// record grade verifies its record's `sig` under the set that opens its
/// home (REG-1.86 (e)).
pub fn t_binding() -> &'static Address {
    skep_registry::t_binding()
}

/// The ENDPOINT — `1.1.0.1.0.1.0.3.56`: the org's own endpoint deposit
/// (REG-1.9), deposits riding the bare ordinal, no subtype row. The daemon's
/// deposit class holds it; its `nullify` is ADMITTED — the endpoint is read
/// on the active view, its org's own retraction effective (REG-1.11,
/// REG-1.46).
pub fn t_endpoint() -> &'static Address {
    skep_registry::t_endpoint()
}

/// The TAKEDOWN RECORD's kind — `1.1.0.1.0.1.0.3.57`: no deposit on the bare
/// ordinal (two readings, REG-1.18); the write path refuses a `nullify` at
/// it and, by prefix, at both rows under it (REG-1.44).
pub fn t_takedown() -> &'static Address {
    skep_registry::t_takedown()
}

/// The takedown record's BASE reading — `1.1.0.1.0.1.0.3.57.1`.
pub fn t_takedown_base() -> &'static Address {
    skep_registry::t_takedown_base()
}

/// LIFTED — `1.1.0.1.0.1.0.3.57.2`, the takedown record's reversal, a
/// link-alone row.
pub fn t_takedown_lifted() -> &'static Address {
    skep_registry::t_takedown_lifted()
}

/// The POLICY LINK's kind — `1.1.0.1.0.1.0.3.58`: no deposit on the bare
/// ordinal (five readings, REG-1.18); the write path refuses a `nullify` at
/// it and, by prefix, at the five rows under it (REG-1.44).
pub fn t_policy_link() -> &'static Address {
    skep_registry::t_policy_link()
}

/// The policy link's OWN reading — `1.1.0.1.0.1.0.3.58.1`, a link-alone row.
pub fn t_policy_link_own() -> &'static Address {
    skep_registry::t_policy_link_own()
}

/// The DISAVOWAL — `1.1.0.1.0.1.0.3.58.2`, the one type of it.
pub fn t_disavowal() -> &'static Address {
    skep_registry::t_disavowal()
}

/// An expulsion's GROUND RECORD — `1.1.0.1.0.1.0.3.58.3`.
pub fn t_expulsion_ground() -> &'static Address {
    skep_registry::t_expulsion_ground()
}

/// A succession's GROUND RECORD — `1.1.0.1.0.1.0.3.58.4`.
pub fn t_succession_ground() -> &'static Address {
    skep_registry::t_succession_ground()
}

/// The ORG-CHOSEN SUCCESSION POLICY — `1.1.0.1.0.1.0.3.58.5`.
pub fn t_succession_policy() -> &'static Address {
    skep_registry::t_succession_policy()
}

/// Every pin of this ledger that is NO registry row, in the ledger's order
/// — the grant, the edition claim, endorse, the consumption marker, the
/// journal designation, the rail record, the steward's classification and
/// `replaces`: the parent's domain as the engine sees it (REG-1.31), which
/// the seeding check compares the registry's rows against at every genesis
/// (REG-1.30, REG-1.32). The daemon widens it by the credential constants,
/// spelled nowhere below the daemon. The ledger's tests hold this list to be
/// exactly the pins outside the registry's table.
pub fn pins_outside_the_registry() -> [&'static Address; 8] {
    [
        t_grant(),
        t_edition(),
        t_endorse(),
        t_consumption_marker(),
        t_journal_designation(),
        t_rail_record(),
        t_steward_classification(),
        t_replaces(),
    ]
}

/// The ENDORSE class type address — `1.1.0.1.0.1.0.3.42`, the succession
/// pair's endorsement half (PUB-7.63; PUB-6.64's member).
///
/// commons-seeding.md's seeded vocabulary: "3.42 | endorse | + .1 expertise
/// .2 trust .3 collaboration" (the social range 3.40–3.45); commons-map.md:
/// "endorse already 3.42". Not provisional.
///
/// The CLASS, and no narrower: the address denotes every endorsement, and
/// its three subtypes are members by prefix (L10). So the write path's
/// refusal at this pin withholds a `nullify` from all of them and not from a
/// delegator's alone — which is what the succession pair happens to read it
/// for, not what it names.
pub fn t_endorse() -> &'static Address {
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

/// The `replaces` type — `1.1.0.1.0.1.0.3.12`, the AUTHORITY SUCCESSOR
/// (PUB-5.15 (iii), (iv); PUB-6.64's member as RES-308 lists it), RULED by the
/// owner 2026-09-29 (the board's "(rep-N) RULED": "tke 3.12"; PUB RES-310
/// pins it at PUB-5.15).
///
/// A CORE-VOCABULARY number (the owner's au-Q (6): "a core-vocabulary number,
/// not a sixth shipped class"): the vacant ordinal in the core range `3.1–3.21`
/// commons-map.md places, `commentary`'s catalog number reused knowingly — the
/// commons map's and the seeding table's rows are owed by the next spec pass.
/// The grant fold reads a record's `replaces` off the link of this type its
/// own transaction deposited, by denotation EQUALITY as it reads [`t_grant`];
/// the daemon's write path recognizes it (and its subtypes by prefix) as
/// PUB-6.64's `replaces` class, so its `nullify` is refused.
pub fn t_replaces() -> &'static Address {
    static ADDR: LazyLock<Address> = LazyLock::new(|| commons_type(12));
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

    /// One pin's READER — the accessor half of a [`PINS`] row, and the word
    /// the module doc uses for it.
    type Reader = fn() -> &'static Address;

    /// THE LEDGER as the tests walk it: each pin's reader, with the commons
    /// ordinals its own doc cites — one for a kind's row, the kind's then
    /// the subtype's for a registry subtype row. ONE list, because a pin's
    /// obligations are the ledger's rather than that pin's — three hand-kept
    /// lists would be three places to be forgotten, and a pin absent from
    /// all of them reaches the daemon's refusal set with nothing here
    /// failing. So this is the single gate a twenty-first pin passes
    /// through, and each test below is one question asked of every row.
    const PINS: [(Reader, &str); 20] = [
        (t_grant, "90"),
        (t_edition, "14"),
        (t_successor_of, "59"),
        (t_endorse, "42"),
        (t_consumption_marker, "91"),
        (t_journal_designation, "22"),
        (t_rail_record, "60"),
        (t_steward_classification, "61"),
        (t_replaces, "12"),
        (t_binding, "55"),
        (t_endpoint, "56"),
        (t_takedown, "57"),
        (t_takedown_base, "57.1"),
        (t_takedown_lifted, "57.2"),
        (t_policy_link, "58"),
        (t_policy_link_own, "58.1"),
        (t_disavowal, "58.2"),
        (t_expulsion_ground, "58.3"),
        (t_succession_ground, "58.4"),
        (t_succession_policy, "58.5"),
    ];

    /// Whether `a` is a registry row — one of `skep-registry`'s twelve.
    fn is_registry_row(a: &Address) -> bool {
        skep_registry::rows().iter().any(|r| r.address == *a)
    }

    /// The pairs the registry's own nesting admits (REG-1.20): each subtype
    /// row under its own kind's row, and nothing else.
    fn nested_pairs() -> Vec<(&'static Address, &'static Address)> {
        skep_registry::rows()
            .iter()
            .filter_map(|r| {
                let subtype = r.subtype?;
                Some((&skep_registry::row(subtype.kind(), None).address, &r.address))
            })
            .collect()
    }

    /// The ledger's GUARANTEE (the module doc's): the pins are pairwise
    /// distinct and — since a consumer recognizes a class's SUBTYPES by
    /// prefix — pairwise prefix-free, so no class swallows another; the ONE
    /// prefix relation admitted is a registry subtype row under its own
    /// kind's row, the nesting the registry designs (REG-1.20) — so every
    /// registry row stays prefix-free against every pin outside the
    /// registry's table, and the kinds against each other.
    #[test]
    fn the_commons_pins_are_pairwise_prefix_free_but_for_the_registrys_own_nesting() {
        let pins: Vec<&'static Address> = PINS.into_iter().map(|(read, _)| read()).collect();
        let nested = nested_pairs();
        assert_eq!(nested.len(), 7, "seven subtype rows nest under their kinds");
        for (i, a) in pins.iter().enumerate() {
            for b in &pins[i + 1..] {
                assert_ne!(a, b, "{} is pinned twice", a.tumbler());
                if is_prefix(a.tumbler(), b.tumbler()) || is_prefix(b.tumbler(), a.tumbler()) {
                    assert!(
                        nested.contains(&(a, b)) || nested.contains(&(b, a)),
                        "{} and {} are prefix-related and no registry kind/subtype pair",
                        a.tumbler(),
                        b.tumbler()
                    );
                }
            }
        }
    }

    /// The deposit class's types — M5's set: the credential types ENROLL
    /// and RETIRE (the module doc's pointer), and the registry's binding and
    /// endpoint, spelled a second time — are each EITHER exactly one of the
    /// two registry rows the set spells again (held equal to the pin, member
    /// for member, by the daemon's suite too) OR prefix-free against every
    /// pin: none IS another pin, which would make a typed-link class with no
    /// atom (the grant, the edition claim, `successor-of`) a member the
    /// insert door admits a declared deposit under (PUB-2.11, RES-261), and
    /// none sits above or beneath one, which would make the daemon's
    /// prefix-recognizing write path read a credential as that pin's class
    /// or subtype. Walked off the same ONE list, so a twenty-first pin meets
    /// the set where it joins.
    #[test]
    fn the_deposit_class_types_are_prefix_free_against_every_pin_but_the_two_rows_they_spell_again() {
        let spelled_again: Vec<&Address> = skep_arrangement::deposit_class_types()
            .iter()
            .filter(|ty| is_registry_row(ty))
            .collect();
        assert_eq!(spelled_again, [t_binding(), t_endpoint()], "the set's registry members, exactly");
        for ty in skep_arrangement::deposit_class_types() {
            if is_registry_row(ty) {
                continue;
            }
            for (read, _) in PINS {
                let pin = read();
                assert!(
                    !is_prefix(ty.tumbler(), pin.tumbler()) && !is_prefix(pin.tumbler(), ty.tumbler()),
                    "the deposit-class type {} and the pin {} are prefix-related",
                    ty.tumbler(),
                    pin.tumbler()
                );
            }
        }
    }

    /// Every pin sits in the ghost document's subspace 3, where nothing is
    /// ever minted (the credential types' own unreachability argument,
    /// AUTH-3.70), so no content resolution can ever equal one — and at the
    /// ordinals its own doc cites, so a silent renumbering fails here.
    #[test]
    fn every_pin_is_a_ghost_subspace_3_element() {
        for (read, ordinals) in PINS {
            assert_eq!(read().tumbler().to_string(), format!("1.1.0.1.0.1.0.3.{ordinals}"));
        }
    }

    /// THE REGISTRY'S ROWS ARE THE CRATE'S TABLE (the module doc): the
    /// eleven readers hand back the crate's own held rows, `t_successor_of`
    /// — the engine's own pin, the registry's fourth kind — EQUALS the
    /// crate's `3.59`, and the pins outside the registry are exactly the
    /// ledger's rows the crate's table does not hold.
    #[test]
    fn the_registry_rows_are_the_crates_table_and_successor_of_is_held_equal() {
        for r in skep_registry::rows() {
            let held = PINS.iter().find(|(read, _)| *read() == r.address);
            assert!(held.is_some(), "{} is a registry row and no pin", r.address.tumbler());
        }
        assert_eq!(t_successor_of(), skep_registry::t_successor_of());
        assert!(std::ptr::eq(t_binding(), skep_registry::t_binding()), "one held row, not a copy");
        let outside: Vec<&Address> =
            PINS.into_iter().map(|(read, _)| read()).filter(|a| !is_registry_row(a)).collect();
        assert_eq!(outside, pins_outside_the_registry());
    }

    /// THE PIN SPELLED TWICE (the module doc): [`t_replaces`] and M7's own
    /// spelling, which its sole-writer fences and its one writer read, are
    /// one address — so the class the fold reads a grant's `replaces` by is
    /// the class M7 fences and mints, and a renumbering of either fails here.
    #[test]
    fn the_replaces_pin_is_the_address_m7_fences_and_mints() {
        assert_eq!(t_replaces(), skep_links::replaces_type());
        assert!(skep_links::is_replaces_class(&skep_links::enc([t_replaces()])));
    }

    /// A pin is ONE value, held: two reads hand back the same address, not
    /// two equal ones. The ledger's readers are on hot paths — the grant fold
    /// consults [`t_grant`] per folded link record, live and through replay —
    /// so a reader that rebuilt its address per call would be paying nine
    /// big-integer allocations and a T4 walk for a compiled constant.
    #[test]
    fn every_pin_is_one_held_value_rather_than_a_construction_per_read() {
        for (read, _) in PINS {
            assert!(
                std::ptr::eq(read(), read()),
                "{} is rebuilt per read, not held",
                read().tumbler()
            );
        }
    }
}
