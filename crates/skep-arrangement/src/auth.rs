//! The write-surface ownership gate (as amended 2026-08-16, ownership
//! ruling): ONE caller identity type and ONE predicate, shared by M5's edit
//! ops and (by re-export) M7's link-deposit ops, so "who may write into this
//! document's space" has a single definition everywhere.
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
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Caller {
    /// A session-attributed principal — ω-checked against each written
    /// document.
    Principal(PrincipalId),
    /// The engine-internal automation path (M9); exempt by architecture,
    /// not by omission.
    System,
}

impl Caller {
    /// Is this caller the effective owner of `a`? The ONE ownership
    /// predicate of the write surface, and it does not compute ω itself: it
    /// asks M3, whose `is_effective_owner` IS the rule (exact account match
    /// by principal id — delegation's id-injectivity makes id equality
    /// equivalent to prefix equality, and no registered owning prefix is
    /// not-owner, never a pass). One spelling of the rule, in the module
    /// that owns the registry it reads.
    pub fn is_owner(&self, m3: &M3State, a: &Address) -> bool {
        match self {
            Caller::System => true,
            Caller::Principal(p) => m3.is_effective_owner(*p, a),
        }
    }
}
