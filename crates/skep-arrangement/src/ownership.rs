//! THE OWNERSHIP GATE (as amended 2026-08-16, the ownership ruling): a gated
//! write's registration, then its ω gate — ONE caller identity type and ONE
//! ownership predicate, shared by M5's writes and (by re-export) M7's
//! link-deposit ops, so the ω half of "who may write into this document's
//! space" has one definition everywhere — and the whole gate, registration
//! then ω, has one too: answered as one boolean
//! ([`Caller::passes_ownership_gate`]) for a door ahead of the store, and as
//! the ordered verdict by [`gate_write`].
//!
//! The predicate is M3's [`M3State::is_effective_owner`] — ω, the longest
//! registered account/node-tier prefix, compared by principal id: the
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
/// M5's gated writes directly with no wire principal (M10 ⟂ M9, by
/// architecture); the ω gate does not apply. The transport never
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
    /// predicate of M5's writes, and it does not compute ω itself: it
    /// asks M3, whose `is_effective_owner` IS the rule (exact account match
    /// by principal id — delegation's id-injectivity makes id equality
    /// equivalent to prefix equality, and no registered owning prefix is
    /// not-owner, never a pass). One spelling of the rule, in the module
    /// that owns the registry it reads.
    ///
    /// `System` answers `true` — it is exempt from ω, as the type states — so
    /// what this decides is whether the caller passes the ω gate, which is
    /// the question every caller asks it.
    ///
    /// ω answers ANY address, registered or not, by its longest registered
    /// prefix, so this says "owner" of an address under the caller's own
    /// account that names no document. Whether a write would pass the
    /// ownership gate is [`passes_ownership_gate`](Caller::passes_ownership_gate)'s
    /// question, which asks registration first.
    pub fn is_owner(&self, m3: &M3State, doc: &Address) -> bool {
        match self {
            Caller::System => true,
            Caller::Principal(p) => m3.is_effective_owner(*p, doc),
        }
    }

    /// Does this caller pass the OWNERSHIP GATE for `doc` — is `doc` a
    /// REGISTERED document and this caller its effective owner
    /// ([`is_owner`](Caller::is_owner))? The two questions `gate_write` asks,
    /// in its order, answered as one, for a door AHEAD of the store that
    /// defers to the store wherever the store's own first slot would refuse
    /// (PUB-6.36 slot 1, PUB-6.37) and so needs the answer and not the
    /// verdict: M10's write door, skep-media's media door and the daemon's
    /// producers ask it. `System` passes wherever `doc` is registered.
    pub fn passes_ownership_gate(&self, m3: &M3State, doc: &Address) -> bool {
        m3.is_registered_document(doc) && self.is_owner(m3, doc)
    }
}

/// THE OWNERSHIP GATE every edit op and the publish shot open: `doc` must be
/// a registered document, and `caller` must be its effective owner.
///
/// THE ORDER IS DECIDED HERE — registration first, so a write aimed at an
/// unregistered document never reports `NotOwner` and never discloses an
/// ownership verdict about an address that names nothing. The verdicts stay
/// with the caller: each op passes its own two constructors, so its error
/// contract remains readable at its own call site. Its boolean, for a door
/// that defers rather than refuses, is [`Caller::passes_ownership_gate`] —
/// the same two questions, and
/// `the_ownership_gates_boolean_is_its_ordered_verdict_answered_as_one`
/// holds the two to one answer over every kind of caller and address.
///
/// The registration this gate establishes is also what the version-chain
/// reads ask first of the ops that open here (PUB-6.37):
/// [`published_target`](crate::published_target) and the two surfaces built
/// on it REQUIRE it, M3 answering the publication bit for registered
/// addresses alone, and the frontier reads beside them, total, leave that
/// polarity to their caller. Each op asks those reads only after this gate,
/// so the publication bit is read on registered addresses alone and an
/// unregistered target answers the registration refusal, never a publication
/// code.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{a, ca, doc1, doc2, pdoc, seeded_m3};

    #[test]
    fn the_ownership_gates_boolean_is_its_ordered_verdict_answered_as_one() {
        // `passes_ownership_gate` is `gate_write`'s two questions as one answer,
        // for a door that defers rather than refuses — so over every kind of
        // caller and every tier of address it passes exactly where the gate
        // does. The family holds each owner's documents, an address under
        // P1's account that names no document — which ω ALONE says P1 owns,
        // so the registration half is asked and not assumed — an account and
        // an element.
        let m3 = seeded_m3();
        let nameless = a(&[1, 0, 1, 0, 9]);
        let p1 = Caller::Principal(PrincipalId(1));
        assert!(
            p1.is_owner(&m3, &nameless),
            "the premise: ω answers by prefix"
        );
        let callers = [
            p1,
            Caller::Principal(PrincipalId(2)),
            Caller::Principal(PrincipalId(99)),
            Caller::System,
        ];
        let addresses = [doc1(), doc2(), pdoc(), nameless, a(&[1, 0, 2]), ca(1)];
        let mut passed = 0usize;
        for caller in callers {
            for doc in &addresses {
                let verdict = gate_write(&m3, caller, doc, (), |_| ()).is_ok();
                assert_eq!(
                    caller.passes_ownership_gate(&m3, doc),
                    verdict,
                    "{caller:?} at {doc:?}"
                );
                passed += usize::from(verdict);
            }
        }
        // P1, and System, at each of P1's three documents; no one elsewhere.
        assert_eq!(passed, 6);
    }
}
