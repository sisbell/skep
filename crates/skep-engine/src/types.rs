//! The commons type addresses the engine and the daemon key on as values.
//!
//! They are never keyed on as registered M7 types, so `TypeRegistry` is
//! untouched by every one of them. Each is an element of the ghost document's
//! subspace 3 —
//! `1.1.0.1.0.1 · 0 · 3 · ordinal`, or one component deeper for a registry
//! subtype row — the core vocabulary's home (`commons-map.md`), where the
//! credential types (`3.{1,2,3}`) sit first.
//!
//! The credential types are pinned here too, since the World seats the
//! identity fold (AUTH-2.79): enroll `3.1`, retire `3.2` and claim `3.3`
//! ([`t_enroll`], [`t_retire`], [`t_claim`]), and the one `TypeAddrs` built
//! over them, [`IDENTITY_TYPES`], which the fold hook and the daemon's
//! classifiers all read. Enroll and retire are spelled twice — here, and in
//! M5's [`deposit_class_types`](skep_arrangement::deposit_class_types), the
//! set the insert door tests a deposit declaration's class type against
//! (PUB-2.11; RES-249, RES-261), M5 sitting below this crate — and the
//! ledger's tests hold M5's set to be exactly the pins it spells again,
//! member for member, and prefix-free against every other, so a pin that
//! joins cannot land on, above or beneath a deposit-class type unnoticed.
//!
//! The consumers are the engine's own reads ([`IDENTITY_TYPES`] for the
//! identity slice; [`t_grant`] and [`t_replaces`] for the grant fold,
//! [`t_edition`] for the audit-view edition-claim lookup), the daemon's
//! credential classifiers, registry sequence and seeding check, and its
//! write-path type-recognition input (PUB-kickoff D3) — the class addresses
//! a `nullify` is refused at (PUB-6.30's grant, PUB-6.64's audit-view
//! members), pinned here beside the ones the engine reads so one ledger names
//! them all. Every class pin below cites its commons row and its
//! confirmation; a pin is never silently renumbered — a change is a
//! confirmed row there and a changed line here.
//!
//! **Two pins are spelled twice.** [`t_replaces`], the authority
//! successor's type, by the same rule as the credential types: it has a
//! writer below this crate — M7's sole-writer fences and the one MAKELINK
//! that mints it — so M7 holds its own spelling where those can read it
//! ([`skep_links::replaces_type`]), and the ledger's tests hold the two
//! equal. And [`t_correspondence`], the publish shot's record class, whose
//! sole-writer fences M7 holds the same way
//! ([`skep_links::correspondence_type`]) ahead of the one writer the shot's
//! lane will build; the ledger's tests hold that pair equal too.
//!
//! The link-sets rows the commons seeding round pinned (2026-10-27) join as
//! three pins — [`t_read_with`], [`t_correspondence`], [`t_held_removal`] —
//! the daemon's write path reading the correspondence as PUB-6.64's member
//! and the client's constants keying on all three; the registry's subtype
//! rows and the correspondence are the ledger's two-ordinal pins, the
//! correspondence built by `commons_subtype` as `commons_type` builds a
//! type's.
//!
//! The registry's twelve rows (REG-1.14, REG-1.15; commons-map's table of
//! them) are `skep-registry`'s table, read through readers here —
//! [`t_binding`] … [`t_succession_policy`] — so one ledger names every
//! commons pin the engine or the daemon keys on; [`t_successor_of`] stays
//! the engine's own pin, the registry's fourth kind, and the tests hold it
//! equal to the crate's row. The insert door's deposit class spells the
//! binding and the endpoint a second time, M5 sitting below this crate, and
//! the daemon's suite holds those equal as it holds the credential pair. The
//! registry's subtype rows nest under their kinds by prefix (REG-1.20) — the
//! one prefix relation the ledger's guarantee below admits, by design: a
//! consumer recognizing a kind's subtypes by prefix reads a subtype row as
//! its kind's member, which is what REG-1.21 wants of it.
//!
//! A pin is held, not manufactured per call: each reader below hands back a
//! borrow of one process-wide value, so the ledger is one instance and not
//! one construction per consult. That matters where the consults are: the
//! grant fold reads [`t_grant`] on every folded link record — at least once
//! per deposit on the live path and per link record through a whole replay —
//! and a rebuilt pin is nine big integers in a vector and a T4 walk. The
//! addresses are compiled format constants, so there is nothing per-call
//! for them to depend on.
//!
//! **The guarantee.** The ledger maintains it, and it is the reason a pin is
//! a decision about all of them: the pins are pairwise distinct and pairwise
//! prefix-free — but for a registry subtype row under its own kind's row,
//! the nesting the registry designs. A consumer that recognizes a class's
//! subtypes by prefix — the daemon's write path does, at every pin it
//! refuses a `nullify` at — relies on it, so a pin sitting under another's
//! prefix makes one class swallow the other and silently widens or narrows a
//! refusal nobody chose. The tests (`types/tests.rs`) hold it off one list of
//! the pins, which is where the next pin joins: nothing else here can notice
//! a pin that reaches a consumer without joining the guarantee.

use std::sync::LazyLock;

use skep_address::{validate, Address, Nat, Tumbler};
use skep_identity::TypeAddrs;

/// Returns the commons type address at `ordinal`.
///
/// It is the ghost document's subspace-3 element `ordinal`. Called once per
/// pin, at that pin's first read.
///
/// # Panics
///
/// Panics where the components are empty or not T4-valid, which a subspace-3
/// element of the ghost document never is.
fn commons_type(ordinal: u32) -> Address {
    validate(
        Tumbler::new([1u32, 1, 0, 1, 0, 1, 0, 3, ordinal].into_iter().map(Nat::from))
            .expect("the commons type components are nonempty"),
    )
    .expect("a subspace-3 element of the ghost document is T4-valid by construction")
}

/// Returns the commons subtype address at `path` — a type's ordinal then
/// its subtype's, `[102, 1]` for `3.102.1`.
///
/// It is `commons_type`'s twin for the two-ordinal rows the registry builds
/// its subtype rows from (`skep_registry::commons_type` takes the same
/// path), one component deeper under the ghost document's subspace 3.
/// Called once per pin, at that pin's first read.
///
/// # Panics
///
/// Panics where the components are empty or not T4-valid, which a subspace-3
/// element of the ghost document never is.
fn commons_subtype(path: &[u32]) -> Address {
    validate(
        Tumbler::new(
            [1u32, 1, 0, 1, 0, 1, 0, 3].into_iter().chain(path.iter().copied()).map(Nat::from),
        )
        .expect("the commons type components are nonempty"),
    )
    .expect("a subspace-3 element of the ghost document is T4-valid by construction")
}

// ── the credential types (AUTH-2.79; AUTH-7.1 horn B) ───────────────────────

/// Returns the enrollment record's type: `1.1.0.1.0.1.0.3.1`.
///
/// It is subspace 3 of the ghost document, ordinal 1 (AUTH-7.1 horn B's
/// allocation, the commons-seeding table's first core row). M5's deposit
/// class spells it a second time, as the type a record atom is declared
/// under at its insert (PUB-2.63), and the ledger's tests hold the two equal.
///
/// Why subspace 3 discharges AUTH-3.70's unreachability obligation with no
/// store edit: content V-spec resolution only ever yields I-spans in the
/// content subspace (subspace 1) of real documents — M3's content mints are
/// the resolution's whole codomain — and no M3 door mints into any document's
/// subspace 3 at all, so these names are never allocated and no resolved span
/// can equal their subtree spans. The daemon's `deposits_credential_link`
/// therefore answers false for every `Resolve` type slot without resolving
/// anything, which is exactly AUTH-2.61's lock-free classifier.
pub fn t_enroll() -> &'static Address {
    static ADDR: LazyLock<Address> = LazyLock::new(|| commons_type(1));
    &ADDR
}

/// Returns the retirement record's type: `1.1.0.1.0.1.0.3.2`.
///
/// It is M5's deposit class's second member, held equal below.
pub fn t_retire() -> &'static Address {
    static ADDR: LazyLock<Address> = LazyLock::new(|| commons_type(2));
    &ADDR
}

/// Returns the board claim's type: `1.1.0.1.0.1.0.3.3`.
///
/// A claim deposits no atom (AUTH-2.48), so M5's set does not hold it.
pub fn t_claim() -> &'static Address {
    static ADDR: LazyLock<Address> = LazyLock::new(|| commons_type(3));
    &ADDR
}

/// The one `TypeAddrs` (AUTH-2.79): an I2 frozen constant (AUTH-2.90).
///
/// It is constructed once per process, at its first read, from the three
/// pins above via [`TypeAddrs::new`], which precomputes the three subtree
/// spans the fold's `kind_of` compares a type slot against (AUTH-2.21).
/// Every classifier reads this instance — the World's fold hook, the
/// daemon's lock-free op classifier and its precheck — and the daemon's
/// write-path type-recognition input holds a clone of it, so none can
/// disagree about what a credential is. `TypeAddrs::new` asserts the three
/// pairwise distinct, once, here.
pub static IDENTITY_TYPES: LazyLock<TypeAddrs> =
    LazyLock::new(|| TypeAddrs::new(t_enroll().clone(), t_retire().clone(), t_claim().clone()));

/// Returns the grants class type address: `1.1.0.1.0.1.0.3.90`.
///
/// Commons decision 5 — commons-map.md: "grants/commerce | grant, price,
/// receipt-citation | 3.90–3.99 (decision 5)": the first address of the
/// commerce range. Confirmed, the ledger bounding the range and leaving the
/// exact address to seeding. The grant fold keys on it by denotation
/// equality; the write path recognizes it (and its subtypes by prefix) as
/// PUB-6.30's grant-typed class.
pub fn t_grant() -> &'static Address {
    static ADDR: LazyLock<Address> = LazyLock::new(|| commons_type(90));
    &ADDR
}

/// Returns the edition-claim class type address (R20): `1.1.0.1.0.1.0.3.14`.
///
/// It is read by the audit-view lookup (`crate::editions`).
///
/// Confirmed. commons-seeding.md's row `3.14 | edition` carries the
/// descriptive subtypes `.1 abridged .2 expanded .3 translated .4 revised .5
/// annotated` beneath it (note 3: "a descriptive edition relation is
/// `edition.*`"); commons-map.md places the core vocabulary at `3.1–3.21`
/// with `edition` listed. Class membership is by prefix (L10): a subtype is
/// its class's member, so a type slot denoting `3.14.k` counts — the lookup
/// names the class, not one address. Not a write-path refusal class: a face
/// reads the claim under the active view (PUB-6.32), so its owner's
/// `nullify` is admitted.
pub fn t_edition() -> &'static Address {
    static ADDR: LazyLock<Address> = LazyLock::new(|| commons_type(14));
    &ADDR
}

/// Returns the succession pair's `successor-of` claim type.
///
/// It is `1.1.0.1.0.1.0.3.59` (PUB-7.63; PUB-6.64's member), and the
/// registry's fourth kind, the succession claim at the fork's seat
/// (REG-1.14), pinned where the build has it: commons-map's table of the
/// registry's twelve rows reads `3.59` as this pin, and the ledger's tests
/// hold it equal to `skep-registry`'s own row
/// ([`skep_registry::t_successor_of`]).
///
/// commons-map.md: "Succession | successor-of | 3.59"; commons-seeding.md's
/// reserved-range table lists `3.59` as claimed. Not provisional.
pub fn t_successor_of() -> &'static Address {
    static ADDR: LazyLock<Address> = LazyLock::new(|| commons_type(59));
    &ADDR
}

// ── the registry's rows (REG-1.14, REG-1.15), `skep-registry`'s table ────

/// Returns the binding: `1.1.0.1.0.1.0.3.55`.
///
/// It is the registration record, prefix → account, deposits riding the bare
/// ordinal (REG-1.18). The insert door's deposit class holds it (REG-1.37 as
/// the record grade's join re-reads it), the daemon's write path refuses a
/// `nullify` at it (REG-1.44, REG-1.46), and the record grade verifies its
/// record's `sig` under the set that opens its home (REG-1.86 (e)).
pub fn t_binding() -> &'static Address {
    skep_registry::t_binding()
}

/// Returns the endpoint: `1.1.0.1.0.1.0.3.56`.
///
/// It is the org's own endpoint deposit (REG-1.9), deposits riding the bare
/// ordinal, no subtype row. The insert door's deposit class holds it; its
/// `nullify` is admitted — the endpoint is read on the active view, its org's
/// own retraction effective (REG-1.11, REG-1.46).
pub fn t_endpoint() -> &'static Address {
    skep_registry::t_endpoint()
}

/// Returns the takedown record's kind: `1.1.0.1.0.1.0.3.57`.
///
/// No deposit rides the bare ordinal (two readings, REG-1.18); the write path
/// refuses a `nullify` at it and, by prefix, at both rows under it
/// (REG-1.44).
pub fn t_takedown() -> &'static Address {
    skep_registry::t_takedown_record()
}

/// Returns the takedown record's base reading: `1.1.0.1.0.1.0.3.57.1`.
pub fn t_takedown_base() -> &'static Address {
    skep_registry::t_takedown_base()
}

/// Returns lifted, the takedown record's reversal: `1.1.0.1.0.1.0.3.57.2`.
///
/// It is a link-alone row.
pub fn t_takedown_lifted() -> &'static Address {
    skep_registry::t_takedown_lifted()
}

/// Returns the policy link's kind: `1.1.0.1.0.1.0.3.58`.
///
/// No deposit rides the bare ordinal (five readings, REG-1.18); the write
/// path refuses a `nullify` at it and, by prefix, at the five rows under it
/// (REG-1.44).
pub fn t_policy_link() -> &'static Address {
    skep_registry::t_policy_link()
}

/// Returns the policy link's own reading: `1.1.0.1.0.1.0.3.58.1`.
///
/// It is a link-alone row.
pub fn t_policy_link_own() -> &'static Address {
    skep_registry::t_policy_link_own()
}

/// Returns the disavowal, the one type of it: `1.1.0.1.0.1.0.3.58.2`.
pub fn t_disavowal() -> &'static Address {
    skep_registry::t_disavowal()
}

/// Returns an expulsion's ground record: `1.1.0.1.0.1.0.3.58.3`.
pub fn t_expulsion_ground() -> &'static Address {
    skep_registry::t_expulsion_ground()
}

/// Returns a succession's ground record: `1.1.0.1.0.1.0.3.58.4`.
pub fn t_succession_ground() -> &'static Address {
    skep_registry::t_succession_ground()
}

/// Returns the org-chosen succession policy: `1.1.0.1.0.1.0.3.58.5`.
pub fn t_succession_policy() -> &'static Address {
    skep_registry::t_succession_policy()
}

/// Returns every class pin of this ledger that is no registry row, in order.
///
/// The order is the ledger's — the grant, the edition claim, endorse, the
/// consumption marker, the journal designation, the rail record, the
/// steward's classification, `replaces`, then the link-sets rows: read-with,
/// the correspondence and the held removal — and the list is the parent's
/// domain as the engine sees it (REG-1.31), which the seeding check compares
/// the registry's rows against at every genesis (REG-1.30, REG-1.32). The
/// three credential types stand beside this list rather than in it — they
/// are the fold's kinds, which no engine index reads and which the write
/// path's refusals read through a clone of [`IDENTITY_TYPES`] rather than as
/// class pins — and the daemon widens the domain by them ([`t_enroll`],
/// [`t_retire`], [`t_claim`]) and by M5's deposit-class spellings. The
/// ledger's tests hold this list to be exactly the pins outside the
/// registry's table but those three.
pub fn pins_outside_the_registry() -> [&'static Address; 11] {
    [
        t_grant(),
        t_edition(),
        t_endorse(),
        t_consumption_marker(),
        t_journal_designation(),
        t_rail_record(),
        t_steward_classification(),
        t_replaces(),
        t_read_with(),
        t_correspondence(),
        t_held_removal(),
    ]
}

/// Returns the endorse class type address: `1.1.0.1.0.1.0.3.42`.
///
/// It is the succession pair's endorsement half (PUB-7.63; PUB-6.64's
/// member).
///
/// commons-seeding.md's seeded vocabulary: "3.42 | endorse | + .1 expertise
/// .2 trust .3 collaboration" (the social range 3.40–3.45); commons-map.md:
/// "endorse already 3.42". Not provisional.
///
/// The class, and no narrower: the address denotes every endorsement, and
/// its three subtypes are members by prefix (L10). So the write path's
/// refusal at this pin withholds a `nullify` from all of them and not from a
/// delegator's alone — which is what the succession pair happens to read it
/// for, not what it names.
pub fn t_endorse() -> &'static Address {
    static ADDR: LazyLock<Address> = LazyLock::new(|| commons_type(42));
    &ADDR
}

/// Returns the consumption marker type: `1.1.0.1.0.1.0.3.91`.
///
/// It is confirmed (PUB-4.12, PUB-4.17; PUB-6.64's member).
///
/// commons-map.md's PUB consumption row: "3.90–3.99
/// beside the grants/commerce claim — the pair's other half … exact address
/// at seeding" — one number (the marker's two values `offer_accepted` /
/// `offer_declined` are client-interpreted values in the `FROM` slot, LM
/// 4/53, never subtypes). Pinned at the range's second address, beside the
/// grant.
pub fn t_consumption_marker() -> &'static Address {
    static ADDR: LazyLock<Address> = LazyLock::new(|| commons_type(91));
    &ADDR
}

/// Returns the journal designation type: `1.1.0.1.0.1.0.3.22`.
///
/// It is confirmed (PUB-4.3, PUB-4.12; PUB-6.64's member).
///
/// commons-map.md's PUB journal self-designation row:
/// "3.22–3.29 structural extension (designation is structure — what a
/// document is — not commerce; the placement lean). One number, exact
/// address at seeding; the reserve is 8 wide and decisions 0/6 may also land
/// here". Pinned at the reserve's first address.
pub fn t_journal_designation() -> &'static Address {
    static ADDR: LazyLock<Address> = LazyLock::new(|| commons_type(22));
    &ADDR
}

/// Returns the rail record type: `1.1.0.1.0.1.0.3.60`.
///
/// It is confirmed (PUB-5.76; PUB-6.64's member, inheriting on PUB-6.30's
/// ground).
///
/// commons-map.md's PUB rail record row: "3.60 (agentic tier) — confirmed …,
/// exact at seeding; hire-side governance of an agent".
pub fn t_rail_record() -> &'static Address {
    static ADDR: LazyLock<Address> = LazyLock::new(|| commons_type(60));
    &ADDR
}

/// Returns the `replaces` type, the authority successor.
///
/// It is `1.1.0.1.0.1.0.3.12` (PUB-5.15 (iii), (iv); PUB-6.64's member as
/// RES-308 lists it), confirmed: PUB RES-310 pins it at PUB-5.15.
///
/// A core-vocabulary number, not a sixth shipped class: the vacant ordinal in
/// the core range `3.1–3.21` commons-map.md places, `commentary`'s catalog
/// number reused knowingly — the commons map's and the seeding table's rows
/// for it are owed. The grant fold reads a record's `replaces` off the link
/// of this type its own transaction deposited, by denotation equality as it
/// reads [`t_grant`]; the daemon's write path recognizes it (and its
/// subtypes by prefix) as PUB-6.64's `replaces` class, so its `nullify` is
/// refused.
pub fn t_replaces() -> &'static Address {
    static ADDR: LazyLock<Address> = LazyLock::new(|| commons_type(12));
    &ADDR
}

/// Returns the steward's classification link type: `1.1.0.1.0.1.0.3.61`.
///
/// It is confirmed (PUB-5.43; PUB-6.64's member where the link's own home is
/// published, RES-207).
///
/// commons-map.md's PUB steward classification link row: "3.61 (agentic
/// tier) — confirmed …, exact at seeding; the review/resolution layer the
/// tier is reserved for".
pub fn t_steward_classification() -> &'static Address {
    static ADDR: LazyLock<Address> = LazyLock::new(|| commons_type(61));
    &ADDR
}

// ── the link-sets rows (the commons seeding round, pinned 2026-10-27) ──────

/// Returns the read-with type: `1.1.0.1.0.1.0.3.71`.
///
/// commons-map.md's link-sets row: "`3.71` | READ-WITH, name `read-with` —
/// 'read this version with that set': 'a link, no new op' (D7) … 'a
/// reader's instruction and nothing the daemon checks'" — the presentation
/// tier's second ordinal, beside `3.70` layout. Pinned 2026-10-27 (the
/// owner: "pin as proposed"). No daemon index reads it and no refusal keys
/// on it: the client's constant, pinned here so one ledger names every
/// commons address the build spells.
pub fn t_read_with() -> &'static Address {
    static ADDR: LazyLock<Address> = LazyLock::new(|| commons_type(71));
    &ADDR
}

/// Returns the correspondence record's type: `1.1.0.1.0.1.0.3.102.1`.
///
/// commons-map.md's link-sets row: "`3.102.1` | THE CORRESPONDENCE RECORD,
/// name `correspondence` — 'a counterpart subtype no picker lists and no
/// user act writes' (C2 (a)), 'MINTED BY THE `publish` SHOT in its own
/// transaction' … 'the CLASS HAS ONE WRITER and is refused elsewhere by
/// coverage-class equality … `nullify` is REFUSED on it — an `AuditClass`
/// arm, PUB-6.64's member'". The first subtype under Nelson's counterpart
/// `3.102`, pinned 2026-10-27, so a pin of two ordinals — the ledger's one
/// two-ordinal pin outside the registry's own nesting, prefix-related to no
/// other pin (`3.102` itself is no pin). The daemon's write path refuses a
/// `nullify` at it (PUB-6.64's class), and M7 spells it a second time for
/// its sole-writer fences ([`skep_links::correspondence_type`]), the ledger's
/// tests holding the two equal; the one writer, the shot's own record mint,
/// is the publish lane's and not yet built.
pub fn t_correspondence() -> &'static Address {
    static ADDR: LazyLock<Address> = LazyLock::new(|| commons_subtype(&[102, 1]));
    &ADDR
}

/// Returns the held removal's type: `1.1.0.1.0.1.0.3.24`.
///
/// commons-map.md's link-sets row: "`3.24` | THE HELD-REMOVAL RECORD, name
/// `held-removal` (W2) — 'a second record subtype, `from` none, `to` a
/// published mark by address, written at the chord and retractable as its
/// undo'" — a type of its own in the structural reserve (the owner,
/// 2026-10-27: "pin as proposed, held removal at 3.24"). Written by the
/// chord through `make_link` and retracted by `nullify` as the chord's undo,
/// so no refusal keys on it; the client's constant, pinned here as
/// [`t_read_with`] is.
pub fn t_held_removal() -> &'static Address {
    static ADDR: LazyLock<Address> = LazyLock::new(|| commons_type(24));
    &ADDR
}

#[cfg(test)]
mod tests;
