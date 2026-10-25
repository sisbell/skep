//! The audit-view edition-claim lookup (PUB-8.46).
//!
//! It is the engine's composition of M7's audit reads over the R20
//! edition-claim class, answering M10's `PublicationWorld::edition_claims`.
//! That seam's impl is `crate::world`'s, beside the World's other role
//! impls, because the same trait asks for the grant fold's any-principal
//! index too.
//!
//! An edition claim is an ordinary link (deposited through MAKELINK's open
//! surface, address-form slots) whose type slot denotes the edition class —
//! [`t_edition`] itself or a descriptive subtype beneath it, by prefix — and
//! whose `to` slot carries the target the edition claims: the whole document
//! or a version of it, as the depositor writes it. What the lookup tests of
//! that slot is wider, and is M7's own regime rather than this module's; the
//! next section states it. It is homed in the edition, so the claim's home
//! is what a row carries, and it is over that home that the client's
//! PUB-3.19 admission test runs (one `doc_metadata` read of it: published,
//! owned by the claimant, its content imaging over the target's birth
//! version). The engine pre-applies none of that test — PUB-3.19 places it
//! on the client — and adds no semantics of its own past the per-hit checks
//! below: the type address is a pinned value and every read below is M7's.
//!
//! ## The lookup
//!
//! A type-range lookup over the class's subtree, narrowed by a `to`-range
//! lookup — the target's subtree, M1's `subtree_of` span — both through
//! `match_links` under `View::Audit` (M7's public reads alone: `match_links`,
//! then `readlink`, `succs` and `is_active` per hit). Which range drives the
//! stab is M7's choice, by its one rule for a conjunction: the constraint
//! naming the fewer candidate homes — the editions holding claims of the
//! class against the homes of every link whose `to` touches the target,
//! edition claim or not, from every hand — found by a bounded walk of its
//! index's directory, never of links; the class is handed first, so a tie
//! falls to it. So the lookup pays for the class where the class is the
//! smaller side, and never for more than the smaller of the two. An AND is
//! order-free: the choice moves work, never a row.
//!
//! The `to` test is M7's overlap regime and not denotation, which is what
//! makes a document name every claim on it or on any version of it, and a
//! version member name those on it and those on its document (coverage
//! containment) — and, by the same containment, every target name the claims
//! on its account and on its node, so one claim naming a node is a row of
//! every answer beneath it. The difference between the two readings is a
//! row: a `to` slot that is a non-unit span across the target's subtree
//! denotes no address under it and is still an answer here. The type slot is
//! judged the other way, over every denoted address, so the two range
//! lookups above narrow to two different tests below and not to one test
//! twice.
//!
//! Three per-hit checks then hold:
//!
//! * **A member** of the class — the type slot address-denoting and
//!   non-empty, every denoted address under [`t_edition`] by prefix. A slot
//!   that merely overlaps the class range (a non-unit span across it) is no
//!   member.
//! * **Unsuperseded** — no operative ⟦supersedes⟧ successor (`succs` over
//!   the shipped class): D4's supersedability is the designed path for R20
//!   (PUB-6.32), so a claim a later `assert_sup` retired leaves the answer.
//! * **Retracted or not** — `is_active` is stated on the row, never applied
//!   (PUB-8.46's "whether or not retracted"): the audit view lists a
//!   nullified claim with `active: false`, where an active-view result set
//!   omits it.
//!
//! Unfiltered by principal, by design: the world answers the class and M10
//! applies the home rule (PUB-6.13) per row off the same snapshot, so the
//! result-set filter is written once, at the front door, for this read as
//! for every other — a draft edition's claim is in the class here and
//! invisible to a stranger there.

use skep_address::{document_of, is_prefix, subtree_of, Address};
use skep_febe::EditionClaim;
use skep_links::{Endset, ShippedType, View, TO, TYPE};

use crate::types::t_edition;
use crate::world::World;

impl World {
    /// Returns every unsuperseded edition claim on `target`'s subtree.
    ///
    /// That is every claim of the class whose `to` slot overlaps `target`'s
    /// subtree — retracted or not — in link-address order (M7's `OrdSet`),
    /// each row the claim's own address, its home (the edition), its `to`
    /// endset as deposited and its active-view membership. The class,
    /// unfiltered; the caller applies the home rule (see the module docs). No
    /// test of a claim's home runs here — not its publication state, not its
    /// issuer — so this answer is not the grant fold's kind of admitted set.
    ///
    /// Total over every `target` — no input can refuse it, and an empty
    /// answer is the answer for a target nothing claims.
    ///
    /// **Cost.** Per call and uncached, it comes in four terms — the first
    /// the board's whatever `target` names, the second the caller's and every
    /// depositor's together, the last two the store's — so this figure is not
    /// read off the request:
    ///
    /// * The probe: `match_links` picks the constraint with the fewer
    ///   candidate homes — the class's, off M7's typed slices, against the
    ///   `to` range's, off its coverage index's directory, walked in lockstep
    ///   until one runs out — and answers it by one `stab`, home by home: a
    ///   step per candidate home and, per home, a probe logarithmic in the
    ///   store and a step per link whose slot overlaps the range — the type
    ///   slot the class, its subtypes' included — then narrows what that
    ///   finds by the other range, one overlap test per span of each link it
    ///   found, retracted links included, each slot up to
    ///   `skep_links::MAX_SLOT_SPANS` spans. So a call pays for the edition
    ///   class — every claim of it on the board, whatever target each names,
    ///   which is the depositors' choice board-wide — wherever the class is
    ///   homed in fewer documents than link into the target, and never for
    ///   the store's size
    ///   (`the_lookup_pays_for_the_class_and_not_for_the_links_the_target_draws`).
    /// * The rows. The `to` range is `target`'s whole subtree and `target`'s
    ///   level is unrestricted here, so which of the class's claims survive
    ///   the narrowing is the caller's: a version member keeps the claims on
    ///   itself, a document those on it and its versions, an account those on
    ///   every document under it and a node those on every account under that
    ///   — one address of a few components asking after every edition claim
    ///   in the store. Nothing below narrows by level, because the containment
    ///   regime that makes a document name its versions' claims is the same
    ///   arithmetic at every tier. The account- and node-tier breadths are a
    ///   direct caller's alone: M10's `PublicationWorld` seam asks only after
    ///   its own registration check, so through it `target` is one registered
    ///   document. That bounds the caller's share of the rows and nothing
    ///   more: overlap admits every claim whose `to` names an ancestor of
    ///   `target` too, so one address-form deposit naming a node is a row of
    ///   every lookup beneath it, and how many rows a registered document
    ///   draws is the depositors' choice, board-wide
    ///   (`a_claim_naming_an_ancestor_of_the_target_is_a_row_of_its_lookup`).
    /// * Per hit, one `readlink`, one `in_edition_class` walk, one `succs` over
    ///   the shipped supersession class, one `document_of` and one
    ///   `is_active`. That walk tests every address the type slot denotes and
    ///   short-circuits only on a non-member, so a slot filled with subtypes of
    ///   the class runs to completion and keeps its row; its bound is
    ///   `skep_links::MAX_SLOT_SPANS`, which is a slot's bound and not a
    ///   request's.
    /// * A surviving row carries the `to` endset as deposited, so the size of
    ///   the answer is the depositor's choice too — a row matched on one
    ///   address may carry a slot of `MAX_SLOT_SPANS` spans.
    ///
    /// Like every read on this world, it gates neither admission nor
    /// concurrency, and nothing here is memoized.
    ///
    /// # Panics
    ///
    /// Panics on a store that breaks M7's own postconditions: a `match_links`
    /// key that is not resident, or a link address with no document,
    /// fail-stops here, as M7 fail-stops on the same two facts itself —
    /// residency at `LinkState::link_at`, the document inside its hint fold.
    /// That is a store invariant violated, never a caller's argument, and it
    /// is why the two arms below are `expect`s.
    pub fn edition_claims(&self, target: &Address) -> Vec<EditionClaim> {
        let links = &self.links;
        let edition_class = t_edition();
        let to_range = Endset::from_spans([subtree_of(target.tumbler())]);
        let type_range = Endset::from_spans([subtree_of(edition_class.tumbler())]);
        let supersedes = links.reserved_type(ShippedType::Supersedes);
        // M7 drives from whichever range names fewer homes; the class is
        // handed first so that a tie falls to it, as the module docs state.
        links
            .match_links(&[(TYPE, &type_range), (TO, &to_range)], View::Audit)
            .into_iter()
            .filter_map(|claim| {
                // Residency is M7's stated postcondition on `match_links` —
                // every address it returns is a key of `links` — so absence
                // is corruption of the store rather than a claim to leave
                // out, and M7 fail-stops on it itself (`LinkState::link_at`).
                // Dropping the row instead would shorten the class by a claim
                // with nothing about the answer looking wrong.
                let link = links
                    .readlink(&claim)
                    .expect("a match_links key names a resident link (M7's postcondition)");
                if !in_edition_class(link.type_slot(), edition_class) {
                    return None; // overlaps the class range without denoting a member
                }
                if !links.succs(supersedes, &claim).is_empty() {
                    return None; // superseded through the managed class (D4)
                }
                // A link address is element-level, so it has a document —
                // M7's own hint fold asserts the same of every stored link
                // key, and this read is entitled to the same fact.
                let home = document_of(&claim)
                    .expect("a link address is element-level, so its home document exists");
                Some(EditionClaim {
                    home,
                    to: link.to_slot().clone(),
                    active: links.is_active(&claim),
                    claim,
                })
            })
            .collect()
    }
}

/// Returns whether `type_slot` makes its link a member of the edition class.
///
/// Membership is by prefix: the type slot denotes addresses (every span
/// unit-depth, at least one), each under the edition class — `3.14` itself
/// or a descriptive subtype `3.14.k` (commons-seeding.md's row). The first
/// clause is what refuses a slot spanning the class range without denoting
/// an address, over which the last would hold vacuously
/// (`a_type_slot_spanning_the_class_range_without_denoting_is_no_member`).
///
/// Membership and not admission, which in this crate is the grant fold's I4
/// test over a record's home (`crate::grants`). Nothing about a claim's home,
/// its issuer or its publication state is asked here or anywhere in this
/// module: PUB-3.19 places that test on the client, and the home rule is
/// M10's.
fn in_edition_class(type_slot: &Endset, edition_class: &Address) -> bool {
    type_slot.is_address_denoting()
        && !type_slot.is_empty()
        && type_slot.addrs().all(|t| is_prefix(edition_class.tumbler(), t))
}
