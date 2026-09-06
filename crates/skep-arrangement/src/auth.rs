//! The write-surface ownership gate (as amended 2026-08-16, ownership
//! ruling): ONE caller identity type and ONE predicate, shared by M5's edit
//! ops and (by re-export) M7's link-deposit ops, so "who may write into this
//! document's space" has a single definition everywhere — and, beside it,
//! the version-chain model's publication reads (PUB round 2, lane 3.1; owner
//! ruling D2b, 2026-09-05): the ONE projection of a version member to its
//! document ([`trunk_of`], PUB-2.15) and the published-target test the three
//! write-path refusals key on ([`published_target`], PUB-2.11).
//!
//! The predicate is M3's ω ([`M3State::effective_owner`] — the longest
//! registered account/node-tier prefix), compared by principal id: the
//! caller's account must be EXACTLY the document's account. Exactness is
//! load-bearing in both directions (ASN-0042 exclusive delegation, O2/O3/O8
//! — the deliberate fix of green's `tumbleraccounteq`): a parent account
//! does not own a sub-delegated account's documents, and a sub-account does
//! not own its parent's. Never bare prefix containment
//! (`skep_namespace::prefix_contains`, the documented ownership-divergence
//! trap).

use skep_address::{parent, Address};
use skep_namespace::{M3State, PrincipalId};

/// The write-op caller identity, evaluated inside the store's transaction
/// (the same discipline as the existing ω sites).
///
/// `Principal` is a FEBE-attributed write: M10 resolves the session's
/// principal and the store checks it owns the written document. `System` is
/// the in-process automation path — M9's rule fires and def writes reach
/// the gated write surface directly with no wire principal (M10 ⟂ M9, by
/// architecture); the ownership check does not apply. The transport never
/// constructs `System`.
///
/// `System` is exempt from ω and from NOTHING ELSE: the version-chain
/// model's in-place refusal (PUB-2.11) reads the same for it — a rule fire
/// never crosses the draft boundary and never advances a published
/// arrangement in place (PUB-6.28), so an automation write into a published
/// target is refused exactly as a principal's is.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Caller {
    /// A session-attributed principal — ω-checked against each written
    /// document.
    Principal(PrincipalId),
    /// The engine-internal automation path (M9); exempt from ω by
    /// architecture, not by omission — and exempt from the publication
    /// refusals by neither.
    System,
}

impl Caller {
    /// Is this caller the effective owner of `doc`? The ONE ownership
    /// predicate of the write surface, and it does not compute ω itself: it
    /// asks M3, whose `is_effective_owner` IS the rule (exact account match
    /// by principal id — delegation's id-injectivity makes id equality
    /// equivalent to prefix equality, and no registered owning prefix is
    /// not-owner, never a pass). One spelling of the rule, in the module
    /// that owns the registry it reads.
    pub fn is_owner(&self, m3: &M3State, doc: &Address) -> bool {
        match self {
            Caller::System => true,
            Caller::Principal(p) => m3.is_effective_owner(*p, doc),
        }
    }
}

/// The front door every edit op opens: `doc` must be a registered document,
/// and `caller` must be its effective owner.
///
/// THE ORDER IS DECIDED HERE — registration first, so a write aimed at an
/// unregistered document never reports `NotOwner` and never discloses an
/// ownership verdict about an address that names nothing. The verdicts stay
/// with the caller: each op passes its own two constructors, so its error
/// contract remains readable at its own call site.
///
/// What this door establishes is also what [`published_target`] REQUIRES
/// (PUB-6.37): every caller of that read has passed through here first, so
/// the publication bit is read on registered addresses alone and an
/// unregistered target answers the registration refusal, never a
/// publication code.
pub(crate) fn gate_write<E>(
    m3: &M3State,
    caller: Caller,
    doc: &Address,
    not_registered: E,
    not_owner: impl FnOnce(Address) -> E,
) -> Result<(), E> {
    if !m3.is_registered_document(doc) {
        return Err(not_registered);
    }
    if !caller.is_owner(m3, doc) {
        return Err(not_owner(doc.clone()));
    }
    Ok(())
}

/// PUB-2.15 — the DOCUMENT a version member projects to: the version
/// components stripped off the document field, one M1 `parent` peel at a
/// time, so `A·0·d·v·w` answers `A·0·d` and a document answers itself. Pure
/// address arithmetic (PUB-2.16 — "the M1 step on the nested form"), no
/// read; total on every address (a field of one component peels nothing),
/// and terminating because each peel shortens the field by one.
///
/// THE ONE PROJECTION HELPER. It was born as the daemon's own private
/// `trunk_of` beside its publish gate; the write-path refusals need the same
/// projection one crate below the engine, where the daemon's copy cannot be
/// reached, so it lives HERE — the lowest crate the refusals and the gate
/// share — and the daemon imports it. Two spellings of one projection would
/// be the drift the routed item (PUB-8.2) exists to close, so no second is
/// written. M1's `document_of` is NOT this projection: it answers the FULL
/// document field, version components included, so a member answers itself
/// there.
///
/// Every publication read of the write surface goes through it: the four
/// in-place refusals via [`published_target`], and `version`'s two
/// (PUB-2.7, PUB-2.9) on its source — so a version member is refused, or
/// admitted, as its DOCUMENT is, whatever its own journaled bit says.
pub fn trunk_of(a: &Address) -> Address {
    let mut trunk = a.clone();
    while trunk.document_field().is_some_and(|field| field.len() > 1) {
        trunk = parent(&trunk)
            .expect("a document field of two or more components peels to one shorter");
    }
    trunk
}

/// PUB-2.11's input: is the DOCUMENT `doc` projects to (PUB-2.15) published?
/// M3's one publication bit ([`M3State::published`], the record its minting
/// `Allocate` journaled), read after [`trunk_of`] — never the member's own
/// bit, which PUB-8.17's inheritance makes agree with its document's today
/// and which the projection keeps from ever deciding a refusal.
///
/// CONTRACT — `doc` is a REGISTERED document (PUB-6.37): the read is
/// answered for registered addresses alone, and every caller reaches it
/// through [`gate_write`], which has just established that. A version
/// member's trunk is registered whenever the member is (a member is minted
/// under a registered source, recursively), so the projected read is inside
/// M3's contract too.
pub(crate) fn published_target(m3: &M3State, doc: &Address) -> bool {
    m3.published(&trunk_of(doc))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::a;

    /// PUB-2.15's projection is address arithmetic and total: a version
    /// member answers its document, a document answers itself, a member of
    /// a member peels to the same document — and off the document tier the
    /// arithmetic changes nothing (an account has no document field; an
    /// element's field is its document's own).
    #[test]
    fn a_version_member_projects_to_its_document() {
        let doc = a(&[1, 0, 1, 0, 1]);
        assert_eq!(trunk_of(&doc), doc, "a document is its own trunk");
        assert_eq!(trunk_of(&a(&[1, 0, 1, 0, 1, 1])), doc, "a version");
        assert_eq!(trunk_of(&a(&[1, 0, 1, 0, 1, 1, 2])), doc, "a version of a version");
        let acct = a(&[1, 0, 1]);
        assert_eq!(trunk_of(&acct), acct);
        let element = a(&[1, 0, 1, 0, 1, 0, 1, 1]);
        assert_eq!(trunk_of(&element), element);
    }
}
