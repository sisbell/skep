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
//! The predicate has ONE body, [`ReaderClass::readable`]: the predicate closed
//! over one principal and one world. [`World::readable`] asks it through a
//! fresh reader class per call, and a caller that consults it once per ROW —
//! a result-set filter, a filtered dump, a feed page — binds one reader class
//! with [`World::reader_class`], so the reader's seat in M3's principal
//! registry is looked up once rather than once per row.
//!
//! Two derived readings sit beside it, because both are the same predicate
//! closed over a caller rather than a second rule: [`World::readable_guest`]
//! is `readable(None, ·)`, the class M9's fires and every unauthenticated read
//! run at; [`World::visible_to`] is the `Caller`-to-class mapping a
//! `LinkWriter` is built with, which is the engine's to state because M7 takes
//! a closure and names no principal.
//!
//! The `skep_febe::ReadableWorld` impl below is the seam M10's generic front
//! door reaches the predicate through: M10 names no `World`, so it asks the
//! trait, off its own read snapshot, and closes the answer over a caller
//! itself. The inherent methods are the real ones.

use std::sync::OnceLock;

use skep_address::{Address, Level};
use skep_arrangement::{trunk_of, Caller};
use skep_namespace::{prefix_contains, PrincipalId};

use crate::world::World;

/// ONE READER'S CLASS over ONE world: the read predicate closed over one
/// principal (`None` is the guest), with that principal's SEAT — the account
/// M3's `principal_prefix` answers for it — looked up at most once for the
/// class's life.
///
/// M3 answers a seat by scanning its principal registry, and the seat is the
/// same for every document one reader asks about, so a caller that consults
/// the predicate per row binds one class and pays that scan once rather than
/// once per draft-homed row. What the class holds is the SEAT and never a
/// verdict: every document is still judged by its own owner and its own
/// grants, which `one_reader_class_answers_each_document_by_its_own_owner`
/// holds.
///
/// The seat is resolved LAZILY, by the first question that reaches the
/// subtree clause — a published document and every guest question answer
/// before it — so [`World::readable`], which binds a fresh class per call,
/// costs a published document no scan at all
/// (`a_reader_class_resolves_its_seat_only_where_a_draft_needs_it`).
///
/// The fields are private: the seat is M3's answer for this class's own
/// principal and never a caller's, so a class whose seat and principal
/// disagree is not constructible. `OnceLock` rather than `OnceCell`, so the
/// class is `Sync` and a closure borrowing it is `Send + Sync` — the bound
/// M10's readers take a threaded predicate under.
#[derive(Debug)]
pub struct ReaderClass<'w> {
    world: &'w World,
    principal: Option<PrincipalId>,
    seat: OnceLock<Option<&'w Address>>,
}

/// The `Send + Sync` [`ReaderClass`] promises, pinned where a field that
/// revoked it would fail to compile.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<ReaderClass<'static>>();
};

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
    ///   projected document. Fail-open (PUB-7.5), in two cases. An address
    ///   whose TRUNK M3 never registered is absent from the set and so
    ///   answers readable here — [`World::published`]'s postcondition — which
    ///   is why every doc-argument consult defers an unregistered document to
    ///   its store's own `*NotRegistered` (M10's `ReadableWorld`
    ///   postcondition, PUB-6.12 — met for every unregistered address but the
    ///   one shape this bullet ends on). A REGISTERED document M3's
    ///   publication map holds no entry for — reachable only off a slice
    ///   outside M3's fold's totality domain — is absent too, and answers
    ///   readable to every class where M3 answers it private; no registration
    ///   check closes that one, since the document is registered
    ///   (`crate::publication` states the open direction). The miss is asked
    ///   of the trunk and never of `doc`, so the one unregistered address this
    ///   clause does NOT open is one shaped as a version member of a
    ///   registered draft: it reads as that draft, and is withheld wherever
    ///   the draft is
    ///   (`a_version_member_shaped_address_under_a_draft_reads_as_the_draft`).
    /// * SUBTREE (PUB-1.32 as amended, PUB RES-215; PUB-7.2) — BOTH WAYS:
    ///   `owner_account(doc) ⊑ account(principal) ∨ account(principal) ⊑
    ///   owner_account(doc)`, TWO prefix compares off the exception set's
    ///   MINT-TIME owner, the second run only where the first fails — never
    ///   a subtree enumeration, never a nearest-account walk. The first
    ///   admits a principal at or BENEATH the owner (the owner's delegates,
    ///   transitively); the second a principal at or ABOVE it (the owner's
    ///   parent account and every account above that), so a parent account
    ///   reads its sub-accounts' drafts as a sub-account reads its parent's.
    ///   That is a READ and never ω: ownership stays exact-match, and a
    ///   parent account owns none of a sub-account's documents. Org members
    ///   are SIBLINGS — neither prefix contains the other — so neither reads
    ///   the other's drafts. Each compare's LEFT operand must be an ACCOUNT,
    ///   and the two sides discharge that differently. The OWNER's tier is
    ///   asserted where the exception set memoizes it (`crate::publication`):
    ///   a node-tier owner would contain every account beneath it and admit
    ///   each of their principals. The PRINCIPAL's is tested HERE, ahead of
    ///   the second compare, because its seat is M3's registry answer
    ///   verbatim and nothing asserts it: THE NODE-TIER PRINCIPAL 0 IS
    ///   EXCLUDED BY NAME (PUB-1.32). Principal 0 is seated at a node — `[1]`,
    ///   M3's genesis seat — and a node prefix contains every account beneath
    ///   it, so the bare second compare would admit it to every draft on the
    ///   board. Under the first compare alone its exclusion was a consequence
    ///   of the direction (a node prefix is shorter than any account's), and
    ///   that does not survive the second. So a seat that is no ACCOUNT —
    ///   principal 0's, or a sub-node's — is no account's ancestor for this
    ///   clause: the node reads no draft by subtree, by grant alone
    ///   (`the_subtree_clause_runs_both_ways`,
    ///   `the_node_tier_principal_reads_no_draft_by_subtree`).
    /// * GRANT (PUB-5.8, PUB-5.19) — the grant fold, grantee PRINCIPAL-EXACT,
    ///   coverage containment ∩ issuer = doc's ω owner. A principal M3 holds
    ///   no SEAT for is not thereby the guest: the subtree clause has no
    ///   account to compare and the principal-exact index has no key to
    ///   probe, so both fall through, but the ANY-PRINCIPAL grants still
    ///   reach it — being a principal at all is that tier's whole membership
    ///   test (PUB-5.8), and an unseated one is still not `None`.
    ///
    /// COST, per call, uncached, in three terms — and the CALLER chooses the
    /// first while the STORE chooses the other two, so this figure is not one
    /// number:
    ///
    /// * The PROJECTION runs ahead of every clause, so `doc` pays it before
    ///   anything here can refuse it — an address M3 never registered
    ///   included, which the published clause then answers `true` two lines
    ///   later. `trunk_of` cuts a version member back to its trunk in one
    ///   truncation (M5), copying the kept prefix once and validating it
    ///   once, so the work is linear in the argument's component count. A
    ///   component is a `Nat` besides, so a copy is an allocation apiece
    ///   rather than a word. Nothing in this crate bounds that count:
    ///   `Address` carries no depth limit, and this predicate is answered
    ///   once per doc-argument of every read a front door admits, so what
    ///   bounds the term in the live system is the CALLER's — the daemon's
    ///   wire cap on a tumbler's components, whose budget is written where
    ///   that number is.
    /// * The SEAT: past the draft hit, a bound principal's account is M3's
    ///   `principal_prefix`, a scan of the principal registry in address
    ///   order — O(|Π|), up to the reader's own entry, and the WHOLE registry
    ///   for a principal M3 seats nowhere. Π gains an entry for every
    ///   principal M3 seats and loses none, so the term grows with the
    ///   store's history, and it dominates wherever a caller consults per
    ///   row: this method binds a fresh [`ReaderClass`] per call and so pays
    ///   the scan once per draft-homed CALL, where a caller holding one class
    ///   from [`World::reader_class`] pays it once per CLASS.
    /// * The GRANT clause then walks the projected document's ancestors,
    ///   `parent` again per level, with one probe of the principal-exact
    ///   index and one of the ANY-PRINCIPAL index at each. That walk is over
    ///   a document the exception set HOLDS — it is reached only past a set
    ///   hit — so its length is a registered document's depth, which is the
    ///   store's history rather than the request's.
    ///
    /// Nothing is memoized across calls, and this gates neither admission nor
    /// concurrency.
    pub fn readable(&self, principal: Option<PrincipalId>, doc: &Address) -> bool {
        self.reader_class(principal).readable(doc)
    }

    /// The read predicate bound to ONE principal over THIS world, as a
    /// [`ReaderClass`] a caller consults once per row: the same predicate
    /// [`World::readable`] answers, with the principal's seat looked up once
    /// for the class rather than once per draft-homed call. `None` is the
    /// guest.
    ///
    /// The class borrows this world, so it answers about this world alone and
    /// cannot outlive it: one class per reader per snapshot, and none for a
    /// write, whose store hands its gate the working world on every consult
    /// ([`World::visible_to`]).
    pub fn reader_class(&self, principal: Option<PrincipalId>) -> ReaderClass<'_> {
        ReaderClass { world: self, principal, seat: OnceLock::new() }
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
    ///
    /// A write's class binds no [`ReaderClass`], and cannot: M7's value-keyed
    /// gates and M5's publish shot hand this closure their WORKING world on
    /// every consult, and that is not the world a class would have borrowed.
    /// So at a PRINCIPAL's class each consult on a draft-homed candidate — per
    /// dedup candidate in M7, per distinct origin document in M5 — pays
    /// [`World::readable`]'s seat scan afresh, inside the store's transaction
    /// and under M2's applier lock, where every waiting writer pays it too.
    ///
    /// PURE and TOTAL, and both are obligations other crates place on this
    /// closure without being able to check them. PURE: it captures one `Copy`
    /// `Caller` and reads nothing but the world handed to it, and the reader
    /// class it binds per consult dies with the consult. That discharges M7's
    /// CALLER'S OBLIGATION on a `Visibility` — a pure, deterministic function
    /// of `(world, doc)`, on which `emit`'s and `assert_sup`'s published
    /// determinism rests — and M9's purity obligation on the guest predicate
    /// [`crate::Engine::coordinator`] injects. TOTAL: it answers every address
    /// of every tier without panicking, as [`World::readable`] does.
    pub fn visible_to(
        caller: Caller,
    ) -> impl Fn(&World, &Address) -> bool + Copy + Send + Sync + 'static {
        move |world: &World, doc: &Address| match caller {
            Caller::Principal(p) => world.readable(Some(p), doc),
            Caller::System => world.readable_guest(doc),
        }
    }
}

impl<'w> ReaderClass<'w> {
    /// The read predicate at this reader class — its ONE body. Its clauses,
    /// its projection and its cost are stated on [`World::readable`], which
    /// asks this through a fresh class per call; a seat an earlier question
    /// resolved is reused here, and nothing else is.
    pub fn readable(&self, doc: &Address) -> bool {
        let world = self.world;
        let trunk = trunk_of(doc);
        // Published clause — a published document (or member) is readable by
        // all, and an address the set never held reads readable here:
        // `World::published`'s postcondition, which M10's `ReadableWorld`
        // obligation rests on (PUB-6.12). No registration check belongs ahead
        // of it.
        if world.published(&trunk) {
            return true;
        }
        // A REGISTERED private draft from here: `published` answered `false`,
        // so `trunk` is a key of the very map `owner_account` reads, in a
        // world that cannot change between the two lines. The `else` exists
        // because the type demands one, and answers fail-closed. Borrowed, as
        // every clause below wants it: nothing here outlives the slice it
        // sits in.
        let Some(owner) = world.owner_account(&trunk) else {
            return false;
        };
        // The guest sees only published documents (no subtree, no grant).
        let Some(id) = self.principal else {
            return false;
        };
        // The principal's own account — M3's seat for it, looked up by the
        // first question that reaches here and reused by every later one —
        // which the two clauses below read differently: as an account to
        // compare against the owner's, and as the grantee to probe the fold
        // with.
        let account = *self.seat.get_or_init(|| world.namespace.principal_prefix(id));
        // Subtree clause — both ways (PUB-1.32 as amended, PUB RES-215): the
        // owner's prefix containing the principal's, or the principal's
        // containing the owner's, the second compare run only where the
        // first fails — and only for a seat at the ACCOUNT tier. Principal 0
        // is seated at a node, which contains every account beneath it, so
        // it is excluded by name here: a node-tier seat is no account's
        // ancestor for this clause.
        if account.is_some_and(|account| {
            prefix_contains(owner, account)
                || (account.level() == Level::Account && prefix_contains(account, owner))
        }) {
            return true;
        }
        // Grant clause — the fold, grantee exact (`None` account ⟹ only the
        // ANY-PRINCIPAL grants can match, which the fold probes regardless).
        world.grants.grant_exists(owner, account, &trunk)
    }
}

/// The read predicate as M10's capability (lane 3.3, §1): M10 is generic over
/// its world and names no `World`, so it reaches the engine's derived
/// predicate — published ∨ subtree ∨ grant ([`World::readable`]) — through this
/// one accessor, off its own read snapshot. The inherent method is the real
/// one; this is the seam the generic front door calls.
///
/// M10's trait places a POSTCONDITION on this impl: TOTAL over every address,
/// and an UNREGISTERED one answers READABLE, so a read arm's own
/// `*NotRegistered` speaks and a WITHHELD answer names only a registered
/// private document (PUB-6.12). M10's door is built on it: its doc-argument
/// consult walks a request's named documents before any registration check,
/// and answers WITHHELD naming the first one this refuses. The inherent
/// predicate meets it at every tier
/// (`an_address_no_mint_produced_reads_readable_at_every_class_and_tier`)
/// for every unregistered address but ONE shape: an address shaped as a
/// version member of a REGISTERED DRAFT, which the projection reads as that
/// draft (PUB-2.15) and so withholds wherever the draft is withheld
/// (`a_version_member_shaped_address_under_a_draft_reads_as_the_draft`). On
/// state the stores' ops produce, that is the projection's only observable
/// effect — a registered version member carries its trunk's bit — so the
/// departure is exactly that wide. It is recorded here, where M10 reads, and
/// not endorsed: which of PUB-2.15 and PUB-6.12 governs is PUB's to say.
impl skep_febe::ReadableWorld for World {
    fn readable(&self, principal: Option<PrincipalId>, doc: &Address) -> bool {
        World::readable(self, principal, doc)
    }
}

#[cfg(test)]
mod tests {
    use crate::testkit::{delegated_account, mem_engine, USER};

    /// The seat is looked up LAZILY and at most once: the guest and a
    /// published document answer before any scan of the principal registry,
    /// and the first draft a bound principal asks about resolves it to M3's
    /// own answer, which every later question reuses. Laziness is what lets
    /// [`World::readable`] bind a fresh class per call and still cost a
    /// published document no scan; a class that looked its seat up at
    /// construction would charge one to every call on every published row.
    #[test]
    fn a_reader_class_resolves_its_seat_only_where_a_draft_needs_it() {
        let engine = mem_engine();
        let acct = delegated_account(&engine, USER);
        let (home, _) =
            engine.namespace().create_new_document(USER, &acct, None).expect("the home mint");
        let (draft, _) = engine
            .namespace()
            .create_new_document(USER, &acct, None)
            .expect("a later mint, private");
        let snap = engine.kernel().snapshot();
        let world = snap.world();

        let guest = world.reader_class(None);
        assert!(!guest.readable(&draft), "the guest reads no draft");
        assert!(guest.seat.get().is_none(), "…and has no seat to look up");

        let owner = world.reader_class(Some(USER));
        assert!(owner.readable(&home), "the first flagless mint is published");
        assert!(owner.seat.get().is_none(), "a published document answers before the scan");
        assert!(owner.readable(&draft), "the owner reads its draft by the subtree clause");
        assert_eq!(owner.seat.get(), Some(&Some(&acct)), "the draft looked up M3's own seat");
    }
}
