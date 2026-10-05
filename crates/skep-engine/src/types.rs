//! The COMMONS type addresses the engine and the daemon key on as VALUES —
//! never as registered M7 types, so `TypeRegistry` is untouched by every one
//! of them. Each is the ghost document's subspace-3 element `ordinal` —
//! `1.1.0.1.0.1 · 0 · 3 · ordinal`, the core vocabulary's home
//! (`commons-map.md`), where the AUTH round's credential types
//! (`3.{1,2,3}`) sit first.
//!
//! THE CREDENTIAL TYPES are pinned here too, since the World seats the
//! identity fold (AUTH-2.79): ENROLL `3.1`, RETIRE `3.2` and CLAIM `3.3`
//! ([`t_enroll`], [`t_retire`], [`t_claim`]), and the ONE `TypeAddrs` built
//! over them, [`IDENTITY_TYPES`], which the fold hook and the daemon's
//! classifiers all read. ENROLL and RETIRE are spelled twice — here, and in
//! M5's [`deposit_class_types`](skep_arrangement::deposit_class_types), the
//! set the insert door tests a deposit declaration's class type against
//! (PUB-2.11; RES-249, RES-261), M5 sitting below this crate — and the
//! ledger's tests hold M5's set to be exactly the pins it spells again, member
//! for member, and prefix-free against every other, so a pin that joins
//! cannot land on, above or beneath a deposit-class type unnoticed.
//!
//! Three consumers: the engine's own folds ([`IDENTITY_TYPES`] for the
//! identity slice; [`t_grant`] and [`t_replaces`] for the grant fold,
//! [`t_edition`] for the audit-view edition-claim lookup), and the daemon's
//! write-path type-recognition input
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
//! The tests (`types/tests.rs`) hold it off ONE list of the pins, which is
//! where the next pin joins: nothing else here can notice a pin that reaches
//! a consumer without joining the guarantee.

use std::sync::LazyLock;

use skep_address::{validate, Address, Nat, Tumbler};
use skep_identity::TypeAddrs;

/// A commons type address: the ghost document's subspace-3 element `ordinal`.
/// Called once per pin, at that pin's first read.
fn commons_type(ordinal: u32) -> Address {
    validate(
        Tumbler::new([1u32, 1, 0, 1, 0, 1, 0, 3, ordinal].into_iter().map(Nat::from))
            .expect("the commons type components are nonempty"),
    )
    .expect("a subspace-3 element of the ghost document is T4-valid by construction")
}

// ── the credential types (AUTH-2.79; AUTH-7.1 horn B) ───────────────────────

/// The ENROLLMENT record's type — `1.1.0.1.0.1.0.3.1`: subspace 3 of the
/// ghost document, ordinal 1 (AUTH-7.1 horn B's allocation, the
/// commons-seeding table's first core row). M5's deposit class spells it a
/// second time, as the type a record atom is DECLARED under at its insert
/// (PUB-2.63), and the ledger's tests hold the two EQUAL.
///
/// Why subspace 3 discharges AUTH-3.70's unreachability obligation with no
/// store edit: content V-spec RESOLUTION only ever yields I-spans in the
/// CONTENT subspace (subspace 1) of real documents — M3's content mints are
/// the resolution's whole codomain — and no M3 door mints into any document's
/// subspace 3 at all, so these names are never allocated and no resolved span
/// can equal their subtree spans. The daemon's `deposits_credential_link`
/// therefore answers false for every `Resolve` type slot without resolving
/// anything, which is exactly AUTH-2.61's lock-free classifier.
pub fn t_enroll() -> &'static Address {
    static ADDR: LazyLock<Address> = LazyLock::new(|| commons_type(1));
    &ADDR
}

/// The RETIREMENT record's type — `1.1.0.1.0.1.0.3.2`, M5's deposit class's
/// second member, held EQUAL below.
pub fn t_retire() -> &'static Address {
    static ADDR: LazyLock<Address> = LazyLock::new(|| commons_type(2));
    &ADDR
}

/// The BOARD CLAIM's type — `1.1.0.1.0.1.0.3.3`. A claim deposits no atom
/// (AUTH-2.48), so M5's set does not hold it.
pub fn t_claim() -> &'static Address {
    static ADDR: LazyLock<Address> = LazyLock::new(|| commons_type(3));
    &ADDR
}

/// THE ONE `TypeAddrs` (AUTH-2.79) — an I2 frozen constant (AUTH-2.90),
/// constructed once per build from the three pins above via
/// [`TypeAddrs::new`], which precomputes the three subtree spans the fold's
/// `kind_of` compares a type slot against (AUTH-2.21). Every classifier
/// reads THIS instance — the World's fold hook, the daemon's lock-free op
/// classifier, its precheck and its write-path type-recognition input — so
/// none can disagree about what a credential is. `TypeAddrs::new` asserts the
/// three pairwise distinct, once, here.
pub static IDENTITY_TYPES: LazyLock<TypeAddrs> =
    LazyLock::new(|| TypeAddrs::new(t_enroll().clone(), t_retire().clone(), t_claim().clone()));

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
    skep_registry::t_takedown_record()
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

/// Every CLASS pin of this ledger that is NO registry row, in the ledger's
/// order — the grant, the edition claim, endorse, the consumption marker, the
/// journal designation, the rail record, the steward's classification and
/// `replaces`: the parent's domain as the engine sees it (REG-1.31), which
/// the seeding check compares the registry's rows against at every genesis
/// (REG-1.30, REG-1.32). The three credential types stand beside this list
/// rather than in it — they are the fold's kinds, not a class the engine's
/// indexes or the write path's refusals read — and the daemon widens the
/// domain by them ([`t_enroll`], [`t_retire`], [`t_claim`]) and by M5's
/// deposit-class spellings. The ledger's tests hold this list to be exactly
/// the pins outside the registry's table but those three.
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
mod tests;
