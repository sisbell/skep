//! The reads M10 COMPOSES rather than forwards — the three publication reads
//! whose answer no single store computes (PUB round 2, lane 3.4; PUB-8.47) —
//! and the one card for what they need that no store computes for them:
//!
//! * [`Op::DocMetadata`] assembles M3's publication bit, owner and version
//!   chain with M5's frozen birth extent — [`require_registered_document`] is
//!   its refusal and [`birth_version`] its chain read;
//! * [`Op::EditionClaims`] takes the world's edition-claim class and keeps
//!   the rows whose home the caller reads — [`require_registered_document`]
//!   is the refusal that bounds it;
//! * [`Op::UniversalGrants`] takes the grant fold's live universal index and
//!   narrows it by M3's ω — [`covered_universal_grants`] is the narrowing.
//!
//! The dispatch arms stay in `dispatch_read`, beside the one snapshot and the
//! one read predicate every read answers from, and each says there what it
//! assembles. What sits here are pure functions of M3's and M5's state and of
//! values: no front door, no session, no predicate.
//!
//! Each asks its owners' reads rather than respelling them — M3's registry
//! and ω walk, M5's chain and birth memo — with ONE exception, and it is the
//! one rule M10 performs on another component's behalf anywhere (the crate
//! doc names it beside M10's boundary): the fold-filter RE-DERIVES the grant
//! fold's issuer test (`grant_exists`'s compare) as a projection over rows.
//! It sits here because the world hands its universal index raw
//! ([`PublicationWorld::universal_grants`]), so the narrowing a client's
//! answer needs falls to the front door.
//!
//! [`Op::DocMetadata`]: crate::Op::DocMetadata
//! [`Op::EditionClaims`]: crate::Op::EditionClaims
//! [`Op::UniversalGrants`]: crate::Op::UniversalGrants
//! [`PublicationWorld::universal_grants`]: crate::PublicationWorld::universal_grants

use std::collections::{BTreeMap, BTreeSet};

use skep_address::Address;
use skep_arrangement::{trunk_head, M5State};
use skep_namespace::{first_version_address, prefix_contains, M3State};

use crate::op::OpKind;
use crate::reject::{rejection, RejectCode, Rejection};
use crate::response::{BirthVersion, UniversalGrant};
use crate::UniversalIndexRow;

/// The registration refusal M10 ORIGINATES, for the two composed reads that
/// take a document ([`Op::DocMetadata`], [`Op::EditionClaims`]; the third,
/// [`Op::UniversalGrants`], takes no argument at all). Every other read's
/// `*NotRegistered` is its store's, raised where the store meets the address;
/// these two reach no single store that could raise one, so the check is this
/// door's and is named as such.
///
/// It is not bookkeeping — each of the two would answer something worse
/// without it. It is what BOUNDS the edition-claim seam: the world narrows
/// its `to` range by no level, so an account-tier target would ask after
/// every document under it and a node-tier one after the store, and
/// requiring document tier is what confines the lookup to one document's
/// claims. And it is what keeps the doc-metadata read from FABRICATING a
/// row for an address no mint produced — ω answers by longest prefix for any
/// address under a registered account, and the rest of that row would be a
/// plausible `false` and `None`, indistinguishable from a real private
/// unarranged document.
///
/// [`Op::DocMetadata`]: crate::Op::DocMetadata
/// [`Op::EditionClaims`]: crate::Op::EditionClaims
/// [`Op::UniversalGrants`]: crate::Op::UniversalGrants
pub(crate) fn require_registered_document(
    m3: &M3State,
    kind: OpKind,
    doc: &Address,
) -> Result<(), Rejection> {
    if m3.is_registered_document(doc) {
        Ok(())
    } else {
        Err(rejection(kind, RejectCode::DocNotRegistered))
    }
}

/// The BIRTH VERSION of a trunk document — `D.1`, the slot its version chain
/// opens at, with the BIRTH CONTENT of what occupies it (PUB-8.12; PUB-3.19 as
/// RES-276 reads it). `None` while the chain has no member, which is why the
/// two halves travel as one [`BirthVersion`]: no extent is read for a
/// document with no member, so the field is absent rather than zero.
///
/// The extent is the content `D.1` was BORN with — the leading runs of its
/// arrangement at its mint — and NOT its arranged content count: while `D.1`
/// is the head a declared deposit appends to its arrangement (PUB-2.66), and
/// the count follows every one. The owner's ruling D2 (2026-09-17) FREEZES
/// what is served, so no reader subtracts a remainder: a one-member edition
/// that took a deposit still answers the extent its claim was written over
/// (PUB-3.10), and so stays in the selection domain (RES-276) and passes the
/// fill's edition side (RES-284, RES-286's claimed half).
///
/// All three reads are their owner's own, asked rather than respelled: M5's
/// [`trunk_head`] for whether the chain has a member, M3's
/// [`first_version_address`] for where it opens — the chain's anchor and
/// opening ordinal being M3's alone — and M5's
/// [`birth_extent`](M5State::birth_extent) for the frozen extent, which M5's
/// fold notes at the mint; that fold states the one state it cannot tell.
///
/// PRECONDITION: `trunk` is DOCUMENT-tier. The one call site discharges it in
/// two steps: [`require_registered_document`] establishes the tier, and
/// [`trunk_of`](skep_arrangement::trunk_of) preserves it — it never makes a
/// document of anything else. It is stated on the parameter because that is
/// where a caller can see what it owes, and the `expect` is what ENFORCES it:
/// [`first_version_address`] is registry-free and answers `None` for every
/// tier but a document's, so a violation panics rather than fabricating the
/// address of a chain no tier but a document's anchors.
///
/// The guard above stands in front of that panic, so no call reaches it:
/// [`trunk_head`] delegates to M3's `latest_version`, which returns `None`
/// for any tier but a document's BEFORE it consults a frontier — so an
/// ACCOUNT, whose same namespace key is the sub-account chain, returns at
/// the `?` rather than reaching the mint.
pub(crate) fn birth_version(m3: &M3State, m5: &M5State, trunk: &Address) -> Option<BirthVersion> {
    trunk_head(m3, trunk)?;
    let addr = first_version_address(trunk)
        .expect("`trunk` is document-tier, the one tier that anchors a version chain");
    let extent = m5.birth_extent(&addr);
    Some(BirthVersion { addr, extent })
}

/// THE FOLD-FILTER of the any-principal discovery read (PUB-8.47): the
/// world's [`UniversalIndexRow`]s — the STORED rows of the grant fold's live
/// universal index — narrowed to the [`UniversalGrant`]s a client is served.
/// It realizes the compare [`Op::UniversalGrants`] states (RES-231, RES-264,
/// RES-273, RES-298), one branch per arm and each branch labelled with its
/// arm: ω of the stored prefix — M3's
/// [`effective_owner_prefix`](M3State::effective_owner_prefix), longest-match,
/// the walk the fold's own owner memo is taken by at the mint — against each
/// issuer of the row.
///
/// Rows GROUP by the served prefix — two stored rows can narrow to one — and
/// come back in prefix order, the issuers of a row in address order without a
/// repeat, so the ruled shape stands: one row per content prefix with the
/// issuers who granted it. That every served row carries exactly ONE issuer,
/// and that the issuer ω-owns the prefix beside it, rests on the obligation
/// [`UniversalIndexRow`] states — every issuer a registered seat — which this
/// takes as given and does not check: the wider arm serves the issuer's own
/// account, and only a seat is its own ω. No read class and no index
/// (PUB-3.48): the compare is M3's own walk, ONE per stored row off the
/// snapshot the arm holds, so the cost is the index's own size (PUB-7.45)
/// times that walk. The two widenings RES-298 declines are declined here
/// too: the wider arm never serves the stored prefix, and the exact arm is
/// ω's compare, never an "or contains" test.
///
/// [`Op::UniversalGrants`]: crate::Op::UniversalGrants
pub(crate) fn covered_universal_grants(
    m3: &M3State,
    stored: Vec<UniversalIndexRow>,
) -> Vec<UniversalGrant> {
    let mut served: BTreeMap<Address, BTreeSet<Address>> = BTreeMap::new();
    for UniversalIndexRow { content_prefix, issuers } in stored {
        let owner = m3.effective_owner_prefix(&content_prefix);
        for issuer in issuers {
            let covered = if owner == Some(&issuer) {
                content_prefix.clone() // ω answers the issuer for the stored prefix: unchanged
            } else if prefix_contains(&content_prefix, &issuer) && content_prefix != issuer {
                issuer.clone() // wider than the issuer's account: the account
            } else {
                continue; // ω answers another seat, or none: no row
            };
            served.entry(covered).or_default().insert(issuer);
        }
    }
    served
        .into_iter()
        .map(|(prefix, issuers)| UniversalGrant { prefix, issuers: issuers.into_iter().collect() })
        .collect()
}
