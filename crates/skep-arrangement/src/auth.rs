//! The write-surface ownership gate (as amended 2026-08-16, ownership
//! ruling): ONE caller identity type and ONE predicate, shared by M5's edit
//! ops and (by re-export) M7's link-deposit ops, so "who may write into this
//! document's space" has a single definition everywhere — and the one front
//! door that asks it, [`gate_write`], registration first.
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

use skep_address::Address;
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
/// never advances a published arrangement in place (PUB-6.28), so an
/// automation write into a published target is refused exactly as a
/// principal's is. PUB-6.28's other clause — a rule fire never crosses the
/// draft boundary — is NOT kept here:
/// [`Vstream::publish`](crate::Vstream::publish) asks its caller nothing
/// beyond `gate_write`, which `System` passes, so the clause holds for the
/// shot only because M9 composes `insert` alone.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
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
    ///
    /// `System` answers `true` — it is exempt from ω, as the type states — so
    /// what this decides is whether the caller passes the ω gate, which is
    /// the question every caller asks it.
    pub fn is_owner(&self, m3: &M3State, doc: &Address) -> bool {
        match self {
            Caller::System => true,
            Caller::Principal(p) => m3.is_effective_owner(*p, doc),
        }
    }
}

/// The front door every edit op and the publish shot open: `doc` must be a
/// registered document, and `caller` must be its effective owner.
///
/// THE ORDER IS DECIDED HERE — registration first, so a write aimed at an
/// unregistered document never reports `NotOwner` and never discloses an
/// ownership verdict about an address that names nothing. The verdicts stay
/// with the caller: each op passes its own two constructors, so its error
/// contract remains readable at its own call site.
///
/// The registration this door establishes is also what the version-chain
/// reads REQUIRE of the ops that open here ([`published_target`](crate::published_target)
/// and the reads beside it, PUB-6.37): each of them asks those reads only
/// after this door, so the publication bit is read on registered addresses
/// alone and an unregistered target answers the registration refusal, never
/// a publication code.
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
