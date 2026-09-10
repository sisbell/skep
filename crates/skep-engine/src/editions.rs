//! The audit-view EDITION-CLAIM lookup (PUB-8.46; PUB round 2, lane 3.4 §2)
//! — the engine's composition of M7's audit reads over the R20 edition-claim
//! class, answering M10's `ReadableWorld::edition_claims`.
//!
//! An edition claim is an ORDINARY link (deposited through MAKELINK's open
//! surface, address-form slots) whose type slot denotes the edition class —
//! [`t_edition`] itself or a descriptive subtype beneath it, by PREFIX — and
//! whose `to` slot denotes the target the edition claims: the whole document
//! or a version of it. It is homed in the EDITION, so the claim's home is what
//! a row carries, and it is over that home that the client's PUB-3.19
//! admission test runs (one `doc_metadata` read of it: published, owned by
//! the claimant, its content imaging over the target's birth version). The
//! engine pre-applies NONE of that test — PUB-3.19 places it on the client —
//! and adds no semantics of its own: the type address is a pinned VALUE and
//! every read below is M7's.
//!
//! ## The lookup
//!
//! A `to`-RANGE lookup — the target's subtree, M1's `subtree_of` span, so a
//! document names every claim denoting it or any version of it, and a version
//! member names those denoting it and those denoting its document (coverage
//! CONTAINMENT, M7's own overlap regime) — AND a type-range lookup over the
//! class's subtree, both through `match_links` under `View::Audit` (the reads
//! the fence asked for: `match_links`, then `readlink`, `succs` and
//! `is_active` per hit; NO new M7 read). Three per-hit checks then hold:
//!
//! * ADMITTED to the class — the type slot address-denoting and non-empty,
//!   every denoted address under [`t_edition`] by prefix. A slot that merely
//!   OVERLAPS the class range (a non-unit span across it) is no member.
//! * UNSUPERSEDED — no operative ⟦supersedes⟧ successor (`succs` over the
//!   shipped class): D4's supersedability is the designed path for R20
//!   (PUB-6.32), so a claim a later `assert_sup` retired leaves the answer.
//! * RETRACTED OR NOT — `is_active` is STATED on the row, never applied
//!   (PUB-8.46's "whether or not retracted"): the audit view lists a nullified
//!   claim with `active: false`, where an active-view result set omits it.
//!
//! UNFILTERED by principal, by design: the world answers the CLASS and M10
//! applies the home rule (PUB-6.13) per row off the same snapshot, so the
//! result-set filter is written once, at the front door, for this read as for
//! every other — a draft edition's claim is in the class here and invisible
//! to a stranger there.

use skep_address::{document_of, is_prefix, subtree_of, Address};
use skep_febe::EditionClaim;
use skep_links::{Endset, ShippedType, View, TO, TYPE};

use crate::types::t_edition;
use crate::world::World;

impl World {
    /// Every admitted, unsuperseded edition claim whose `to` slot overlaps
    /// `target`'s subtree — retracted or not — in link-address order (M7's
    /// `OrdSet`), each row its home (the edition), its `to` endset as
    /// deposited and its active-view membership. The class, unfiltered; the
    /// caller applies the home rule (see the module docs).
    ///
    /// COST, per call, uncached, in three terms — and the caller chooses the
    /// first while the STORE chooses the other two, so this figure is not
    /// read off the request:
    ///
    /// * The `to` RANGE is `target`'s whole subtree and `target`'s LEVEL is
    ///   unrestricted here, so the breadth is the caller's: a version member
    ///   ranges over itself, a document over its versions, an ACCOUNT over
    ///   every document under it and a NODE over every account under that —
    ///   one address of a few components asking after every edition claim in
    ///   the store. Nothing below narrows by level, because the containment
    ///   regime that makes a document name its versions' claims is the same
    ///   arithmetic at every tier.
    /// * `match_links` under the two constraints, then per HIT one `readlink`,
    ///   one `admitted` walk, one `succs` over the shipped supersession
    ///   class and one `document_of`. `admitted` tests EVERY address the
    ///   type slot denotes and short-circuits only on a non-member, so a slot
    ///   filled with subtypes of the class runs to completion and keeps its
    ///   row; its bound is `skep_links::MAX_SLOT_SPANS`, which is a slot's
    ///   bound and not a request's.
    /// * A surviving row carries the `to` endset AS DEPOSITED, so the size of
    ///   the ANSWER is the depositor's choice too — a row matched on one
    ///   address may carry a slot of `MAX_SLOT_SPANS` spans.
    ///
    /// Like every read on this world, it gates neither admission nor
    /// concurrency, and nothing here is memoized.
    pub fn edition_claims(&self, target: &Address) -> Vec<EditionClaim> {
        let links = &self.links;
        let edition_class = t_edition();
        let to_range = Endset::from_spans([subtree_of(target.tumbler())]);
        let class_range = Endset::from_spans([subtree_of(edition_class.tumbler())]);
        let supersedes = links.reserved_type(ShippedType::Supersedes);
        links
            .match_links(&[(TO, &to_range), (TYPE, &class_range)], View::Audit)
            .into_iter()
            .filter_map(|claim| {
                // A `match_links` key is resident by construction.
                let link = links.readlink(&claim)?;
                if !admitted(link.type_slot(), edition_class) {
                    return None; // overlaps the class range without denoting a member
                }
                if !links.succs(supersedes, &claim).is_empty() {
                    return None; // superseded through the managed class (D4)
                }
                // A link address is element-level, so it has a document.
                let home = document_of(&claim)?;
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

/// Class ADMISSION by prefix: the type slot denotes addresses (every span
/// unit-depth, at least one), each under the edition class — `3.14` itself or
/// a descriptive subtype `3.14.k` (commons-seeding.md's row).
fn admitted(ty: &Endset, edition_class: &Address) -> bool {
    ty.is_address_denoting()
        && !ty.is_empty()
        && ty.addrs().all(|t| is_prefix(edition_class.tumbler(), t))
}
