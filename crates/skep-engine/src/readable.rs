//! THE READ PREDICATE (PUB-1.31, PUB round 2, lane 3.3 §1) — the one
//! function every read surface in the system answers through, and the
//! visibility class every write is gated at.
//!
//! `readable(doc, principal) = published(doc) ∨ subtree ∨ grant_exists(doc,
//! principal)`: three clauses over three owners, composed here and nowhere
//! else. The published clause is the exception set's (`crate::publication`),
//! the subtree clause is M3's ω answer memoized in that same set, and the
//! grant clause is the grant fold's (`crate::grants`). No clause is decided
//! here — this module states their composition, their short-circuit order and
//! the projection every one of them shares (`trunk_of`: a version member reads
//! as its document, PUB-2.15).
//!
//! Two derived readings sit beside it, because both are the same predicate
//! closed over a caller rather than a second rule: [`World::readable_guest`]
//! is `readable(None, ·)`, the class M9's fires and every unauthenticated read
//! run at; [`World::visible_to`] is the `Caller`-to-class mapping a
//! `LinkWriter` is built with, which is the engine's to state because M7 takes
//! a closure and names no principal.
//!
//! The `skep_febe::ReadableWorld` impl below is the seam M10's generic front
//! door reaches all of this through: M10 names no `World`, so it asks the
//! trait, off its own read snapshot, and applies the home rule (PUB-6.13) per
//! result row itself. The inherent methods are the real ones.

use skep_address::Address;
use skep_arrangement::{trunk_of, Caller};
use skep_namespace::{prefix_contains, PrincipalId};

use crate::world::World;

impl World {
    /// THE read predicate (PUB-1.31): `readable(doc, principal) =
    /// published(doc) ∨ principal ∈ owner_subtree(doc) ∨ grant_exists(doc,
    /// principal)` — one function, three clauses, short-circuiting.
    ///
    /// `principal` is `None` for the GUEST (PUB-1.31 with no principal: the
    /// subtree clause has no account to hold, and the grant clause — the
    /// ANY-PRINCIPAL form included, PUB-5.8, PUB-5.9 — reaches principals
    /// alone, PUB-5.109): a guest sees a document iff it is published, so
    /// [`World::readable_guest`] is `readable(None, ·)`. Every clause
    /// projects a version member to its document first (`trunk_of`, M5,
    /// PUB-2.15): `1.0.1.0.1.2` reads exactly as `1.0.1.0.1`.
    ///
    /// * PUBLISHED (PUB-1.31's first clause) — an exception-set MISS on the
    ///   projected document. Fail-open (PUB-7.5): an UNREGISTERED address is
    ///   absent from the set and so answers readable here, which is why every
    ///   doc-argument consult defers an unregistered document to its store's
    ///   own `*NotRegistered` (a withheld answer is only ever a REGISTERED
    ///   private document — PUB-6.12).
    /// * SUBTREE (PUB-5.9, PUB-5.13-adjacent) — `owner_account(doc) ⊑
    ///   account(principal)`, ONE prefix compare DOWNWARD only, off the
    ///   exception set's MINT-TIME owner (never a nearest-account walk). A
    ///   node-tier principal (principal 0, seated at a node) has a prefix
    ///   shorter than any account, so the compare excludes it; org members are
    ///   SIBLINGS, so neither reads the other's drafts. Both of those hold
    ///   because the LEFT operand is an ACCOUNT: a node-tier owner would
    ///   contain every account beneath it and admit each of their principals
    ///   here. The exception set asserts that tier where it memoizes the
    ///   owner (`crate::publication`), so this clause is a bare prefix
    ///   compare rather than a compare plus a tier gate.
    /// * GRANT (PUB-5.8, PUB-5.19) — the grant fold, grantee PRINCIPAL-EXACT,
    ///   coverage containment ∩ issuer = doc's ω owner. A principal M3 holds
    ///   no SEAT for is not thereby the guest: the subtree clause has no
    ///   account to compare and the principal-exact index has no key to
    ///   probe, so both fall through, but the ANY-PRINCIPAL grants still
    ///   reach it — being a principal at all is that tier's whole membership
    ///   test (PUB-5.8), and an unseated one is still not `None`.
    ///
    /// COST, per call, uncached, in two walks — and the CALLER chooses the
    /// first while the STORE chooses the second, so this figure is not one
    /// number:
    ///
    /// * The PROJECTION runs ahead of every clause, so `doc` pays it before
    ///   anything here can refuse it — an address M3 never registered
    ///   included, which the published clause then answers `true` two lines
    ///   later. `trunk_of` peels one component per iteration and each peel
    ///   COPIES the whole remaining address, M1's `parent` rebuilding its
    ///   prefix and re-walking T4 to mint it, so the work is the argument's
    ///   own document-field length TIMES its component count. A component is
    ///   a `Nat` besides, so a copy is an allocation apiece rather than a
    ///   word. Nothing in this crate bounds either count: `Address` carries
    ///   no depth limit, and this predicate is answered once per doc-argument
    ///   of every read a front door admits, so what bounds the term in the
    ///   live system is the CALLER's — the daemon's wire cap on a tumbler's
    ///   components, whose budget is written where that number is.
    /// * The GRANT clause then walks the projected document's ancestors,
    ///   `parent` again per level, with one probe of the principal-exact
    ///   index and one of the ANY-PRINCIPAL index at each. That walk is over
    ///   a document the exception set HOLDS — it is reached only past a set
    ///   hit — so its length is a registered document's depth, which is the
    ///   store's history rather than the request's.
    ///
    /// Nothing is memoized, and this gates neither admission nor
    /// concurrency.
    pub fn readable(&self, principal: Option<PrincipalId>, doc: &Address) -> bool {
        let trunk = trunk_of(doc);
        // Published clause — a published document (or member) is readable by
        // all, and an unregistered one is fail-open here (PUB-7.5).
        if self.published(&trunk) {
            return true;
        }
        // A REGISTERED private draft from here: the exception set holds its
        // mint-time owner. `None` cannot arise (published above covers the
        // unregistered case), but is answered fail-closed. Borrowed, as every
        // clause below wants it: nothing here outlives the slice it sits in.
        let Some(owner) = self.owner_account(&trunk) else {
            return false;
        };
        // The guest sees only published documents (no subtree, no grant).
        let Some(id) = principal else {
            return false;
        };
        // The principal's own account — M3's seat for it, which the two
        // clauses below read differently: as an account to compare against
        // the owner's, and as the grantee to probe the fold with.
        let account = self.namespace.principal_prefix(id);
        // Subtree clause — downward only.
        if let Some(account) = account {
            if prefix_contains(owner, account) {
                return true;
            }
        }
        // Grant clause — the fold, grantee exact (`None` account ⟹ only the
        // ANY-PRINCIPAL grants can match, which the fold probes regardless).
        self.grants.grant_exists(owner, account, &trunk)
    }

    /// The GUEST predicate (PUB-1.31 with no principal; a grant opens nothing
    /// to it, the ANY-PRINCIPAL form included — PUB-5.8, PUB-5.9, PUB-5.109):
    /// `readable(None, ·)` — published alone. M9's fires read at this class
    /// (§5), and every unauthenticated read answers through it.
    pub fn readable_guest(&self, doc: &Address) -> bool {
        self.readable(None, doc)
    }

    /// THE VISIBILITY CLASS A CALLER WRITES AT (PUB round 2, lane 3.3b): the
    /// predicate a `LinkWriter` is built with when `caller` deposits, so
    /// M7's value-keyed gates — `emit`'s idempotency, `assert_sup`'s dedup —
    /// see exactly the incumbents that caller could read (PUB-6.25). A
    /// principal writes at its own class, [`World::readable`] over
    /// `Some(principal)`; the System path — M9's fires and def writes, the
    /// one caller with no session — writes at GUEST class,
    /// [`World::readable_guest`] (PUB-6.28). This mapping is the engine's to
    /// state: M7 takes a closure and names no principal, and M10 closes its
    /// own over the session's principal. Every other caller — the harnesses,
    /// this crate's tests, and [`crate::Engine::coordinator`] building M9's
    /// System-class writers — threads it through here.
    pub fn visible_to(
        caller: Caller,
    ) -> impl Fn(&World, &Address) -> bool + Copy + Send + Sync + 'static {
        move |world: &World, doc: &Address| match caller {
            Caller::Principal(p) => world.readable(Some(p), doc),
            Caller::System => world.readable_guest(doc),
        }
    }
}

/// The read predicate as M10's capability (lane 3.3, §1): M10 is generic over
/// its world and names no `World`, so it reaches the engine's derived
/// predicate — published ∨ subtree ∨ grant ([`World::readable`]) — through this
/// one accessor, off its own read snapshot. The inherent method is the real
/// one; this is the seam the generic front door calls.
impl skep_febe::ReadableWorld for World {
    fn readable(&self, principal: Option<PrincipalId>, doc: &Address) -> bool {
        World::readable(self, principal, doc)
    }

    /// The audit-view edition-claim lookup (PUB-8.46; lane 3.4, §2) —
    /// [`World::edition_claims`], the engine's composition of M7's audit
    /// reads over the pinned edition class (`crate::editions`); M10 applies
    /// the home rule per row, off its own snapshot.
    ///
    /// The `to` test this implementation applies is M7's OVERLAP regime
    /// against `target`'s subtree, which is WIDER than denotation: a claim
    /// whose `to` slot is a non-unit span across the subtree denotes no
    /// address in it and is still a row. That width is the containment the
    /// lookup is for — it is what makes a document name its versions' claims
    /// — and it is the same arithmetic at every tier, so a caller sizing this
    /// answer reads `World::edition_claims`'s cost and not the word
    /// "denotes". The type slot is the other way: class MEMBERSHIP there is
    /// over every DENOTED address, so a slot that merely overlaps the class
    /// range is refused. Membership is the whole of what a row is tested for
    /// — no home, issuer or publication test runs on this side of the seam.
    fn edition_claims(&self, target: &Address) -> Vec<skep_febe::EditionClaim> {
        World::edition_claims(self, target)
    }
}
