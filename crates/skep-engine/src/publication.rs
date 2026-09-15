//! The exception set — the engine's DERIVED membership index over M3's
//! publication bit (PUB-7.5; owner ruling D1, 2026-09-05: ONE publication
//! definition), and the two halves of the hint discipline it takes
//! (PUB-7.7): SEEDED by `WorldState::rebuild_derived` at load, FOLDED by
//! `WorldState::apply` on every document-minting record.
//!
//! The set stores the UNPUBLISHED side — a hash-keyed map draft document →
//! OWNER ACCOUNT, the owner fixed at mint — so `published(doc)` is a
//! membership MISS: one address hash, no walk (PUB-7.1). That polarity is
//! what makes an EMPTY set read as everything-published (PUB-7.5's fail-open
//! sign), and the set carries no witness of its own against that state: a
//! [`crate::World`] decoded from bytes has an empty set until the rebuild has
//! run over it (`World`'s invariant note), and a document never registered is
//! absent for the same reason a published one is — which is why every caller
//! checks registration FIRST (PUB-6.37) and why M3's bit, not this index, is
//! the authority (PUB-7.8's load check guards the bit; this set guards
//! nothing).
//!
//! That registration check closes the open direction for an UNREGISTERED
//! address and for nothing else, and the set inherits a second case it cannot
//! reach: a REGISTERED document M3's walk never enumerates. The set is built
//! by ADDITION over `M3State::documents`, which yields every registered
//! document on any slice M3's own fold produced — and a slice outside that
//! fold's totality domain can hold a registered document with NO publication
//! entry (a jumped `Allocate` registers the ordinals it skipped). M3 answers
//! such a document PRIVATE. This set never holds it, so it reads PUBLISHED
//! here, and a registration check ahead of the call passes, because the
//! document IS registered. `M3State::documents` assigns exactly this
//! statement to an index built over its walk, which is why it stands here.
//! Nothing in this crate detects the shape — detecting it at load means
//! expanding every document chain to its members, the Θ(documents) cost M3's
//! compressed frontiers exist to avoid — and
//! `a_registered_document_with_no_publication_entry_reads_published_to_the_set`
//! pins the direction so that it cannot move unnoticed; it does not endorse
//! it.
//!
//! The engine adds no semantics here. The bit is M3's (`M3State::published`,
//! written by the one record that registers the document, PUB-7.10); the
//! owner is M3's ω answer for the document at the fold; what this module owns
//! is the INDEX — construction and observation — and the one shape decision
//! the PUB pack leaves to the build (§5.5 row 3: a build MAY answer the bool
//! off M3's document records; this build takes the set the spec names, and
//! the standing subtraction candidate PUB-7.69 records is noted in the round's
//! report).

use skep_address::{Address, Level};
use skep_namespace::{M3Rec, M3State};

use crate::world::World;

/// The exception set's type: draft document → its owner account (PUB-7.5).
/// Hash-keyed, as the spec states — a membership probe is one address hash —
/// and an `im` structure, so `World::clone` on the commit path (M2 clones a
/// world per `transact`) is one more root clone. The default `RandomState`
/// hasher makes the iteration order instance-specific; every enumeration
/// that reaches bytes (the world dump's hint) sorts, and nothing else
/// enumerates it.
pub(crate) type Drafts = im::HashMap<Address, Address>;

/// One entry of the exception set, as [`World::drafts`] enumerates it: a
/// DRAFT document, and the ACCOUNT that owned it at its mint — the same memo
/// [`World::owner_account`] answers with.
///
/// A named row rather than a pair, for the reason [`crate::UniversalGrant`]
/// is one: both halves are addresses, so a consumer that read them the other
/// way round would still compile, and would go on to ask whether an ACCOUNT
/// is a draft. That is always no, so every entry would read as one the commit
/// just minted, and nothing about the answer would look wrong. The field
/// names are what make the swap fail to compile instead.
///
/// Rows order by document, so sorting them gives the set in address order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Draft<'a> {
    /// The draft document — a member of the set, so `published` is false for
    /// it (PUB-7.5).
    pub document: &'a Address,
    /// Its owner account, fixed at the mint and never re-derived by a walk.
    pub owner_account: &'a Address,
}

impl World {
    /// `published(doc)` — THE daemon-side publication read (owner ruling D1):
    /// `doc ∉ exception_set`, a membership miss, and nothing else. Takes the
    /// DOCUMENT: a version member's own bit is what its own `Allocate`
    /// journaled (M3 stamps the inherited bit, PUB-8.17), and a caller that
    /// wants the member's document's state projects to it first (PUB-2.15) —
    /// the daemon's publish gate does.
    ///
    /// CONTRACT — `doc` is a REGISTERED document (PUB-6.37): an unregistered
    /// address is absent from the set exactly as a published document is, so
    /// this answers `true` for it — the fail-open direction — and the
    /// registration check stands AHEAD of every call, at the caller. M3's own
    /// `published` reads the bit at one map lookup and answers `false` there.
    ///
    /// On every slice M3's own fold produced, the two agree on every
    /// registered document, because the seed and the fold below both answer
    /// off M3's publication map. They part in TWO places, and the caller's
    /// registration check closes only one. An UNREGISTERED address — outside
    /// the contract — reads published here and private at M3, and the check
    /// refuses it first. A REGISTERED document M3's publication map holds NO
    /// entry for — inside the contract, and reachable only off a slice outside
    /// M3's fold's totality domain — reads PUBLISHED here and PRIVATE at M3,
    /// and the check passes it: that is the open direction this set inherits
    /// from [`M3State::documents`], stated in the module doc.
    pub fn published(&self, doc: &Address) -> bool {
        is_published(&self.drafts, doc)
    }

    /// The owner account the set fixed for `doc` at its mint — `Some` iff
    /// `doc` is a DRAFT in the set (PUB-7.2's memo, PUB-7.6's per-item
    /// consumers), `None` for a published or an unregistered document. The
    /// account is M3's ω of the document, read once at the fold and never
    /// re-derived by a nearest-account walk per call.
    pub fn owner_account(&self, doc: &Address) -> Option<&Address> {
        self.drafts.get(doc)
    }

    /// Every draft in the set with its owner account, as [`Draft`] rows, in NO
    /// particular order (the map is hash-keyed; sort the rows, which order by
    /// document, before comparing or rendering them). The enumeration is for
    /// readers that need the whole set — the world dump's `publication.drafts`
    /// hint, and the daemon's change feed, which walks it for the drafts a
    /// commit minted or rearranged — where the read predicate's own consumers
    /// are point reads ([`World::published`], [`World::owner_account`]).
    pub fn drafts(&self) -> impl Iterator<Item = Draft<'_>> + '_ {
        self.drafts.iter().map(|(document, owner_account)| Draft { document, owner_account })
    }
}

/// `published(doc)` off the set alone: the POLARITY, in the one place that
/// holds it. The set stores the UNPUBLISHED side, so a published document is
/// a membership MISS — one address hash, no walk (PUB-7.1, PUB-7.5).
/// [`World::published`] is the public face and `crate::grants`' admission
/// test is the other reader, so a build that answered the bool off M3's
/// document records instead (PUB-7.69, the standing subtraction candidate)
/// changes this function and nothing else.
pub(crate) fn is_published(drafts: &Drafts, doc: &Address) -> bool {
    !drafts.contains_key(doc)
}

/// THE RULE, asked of ONE address: is `doc` a draft of M3's, and whose? An
/// entry `(doc, owner account)` iff M3 registers `doc` as a DOCUMENT and its
/// bit is `false`; `None` for a published document, for an account or element
/// address (outside the publication axis, PUB-1.68), and for an address M3
/// never registered.
///
/// Both halves of the hint discipline are this one call — [`fold`] asks it of
/// the address a record just minted, [`seed`] of every document
/// `M3State::documents` enumerates — so the two agree because they are ONE
/// rule rather than two that happen to match. Both read M3 through M3's own
/// accessors: `is_registered_document`, and `published` for the bit.
/// `M3State::documents` is the ENUMERATION, never a second reading of the bit
/// — which is why the seed asks its ADDRESSES rather than trusting the bit it
/// yields beside them, and why the registration test guards the load path
/// exactly as it guards the commit path. That guard is what keeps
/// [`owner_account_of`]'s fail-stop off an unregistered address, on the one
/// path whose input was just deserialized.
fn draft_entry(namespace: &M3State, doc: &Address) -> Option<(Address, Address)> {
    if !namespace.is_registered_document(doc) || namespace.published(doc) {
        return None;
    }
    Some((doc.clone(), owner_account_of(namespace, doc)))
}

/// The FOLD half (PUB-7.7): the set after `rec` has been folded into M3,
/// given `prev`, the set before it. `namespace` is M3's slice AFTER
/// `apply_m3(rec)`, so [`draft_entry`]'s questions are M3's own answers about
/// the record M3 just folded: a document-tier `Allocate` carrying `published:
/// false` joins the set, one carrying `true` does not, and an account or
/// element `Allocate` touches nothing. `RegisterNode`/`RegisterPrincipal`
/// mint no document, so they take the early return.
///
/// The fold asks about the ONE address a record names. A jumped `Allocate` —
/// outside M3's fold's totality domain — registers the ordinals it skipped as
/// well, and nobody here asks about those, so the fold shares the seed's
/// blind spot: a skipped document is registered, holds no publication entry,
/// and never joins the set (the module doc's open direction).
///
/// This runs INSIDE `World::apply`, so the membership and the registration
/// land in the ONE commit that carries the record (PUB-7.7 as RES-209 states
/// it): a reader's head snapshot holds both or neither.
pub(crate) fn fold(prev: &Drafts, namespace: &M3State, rec: &M3Rec) -> Drafts {
    let M3Rec::Allocate { addr, .. } = rec else {
        return prev.clone();
    };
    match draft_entry(namespace, addr) {
        Some((doc, owner)) => prev.update(doc, owner),
        None => prev.clone(),
    }
}

/// The SEED half (PUB-7.7): the set a from-scratch walk of M3's publication
/// map yields — [`draft_entry`] asked of every document
/// `M3State::documents` enumerates. Runs at load, before replay, and never on
/// a live commit; the fold carries the set forward across everything above
/// the base. The two halves agree because they are one rule under two
/// enumerations, and `Engine::check_hints` is the standing check that the
/// enumerations reach the same documents.
///
/// The ADDRESSES alone are the enumeration, and it is complete over every
/// slice M3's own fold produced: M3 writes a publication entry and the
/// registration in one fold step, and only for a document-tier mint, so there
/// the map's entries are exactly the registered documents. The bit the
/// walk yields beside each address is not read here — it comes back through
/// M3's own `published`, which is what makes this walk and the fold ONE rule
/// rather than two that happen to agree.
///
/// A decoded slice need not be fold-produced, and the rule's registration
/// re-ask guards exactly one of the two ways it can differ: an entry for an
/// address M3 does not register is skipped rather than fail-stopped on. The
/// other is outside the walk altogether. A registered document with NO entry
/// is never enumerated, so the rule is never asked of it — asked, it would
/// answer DRAFT — and the set never holds it: the open direction the module
/// doc states.
///
/// SEED COST, per load and per `Engine::world_at` reconstruction: one walk of
/// M3's publication map — `M3State::documents`, the store's own
/// enumeration of its registered documents — then, per document, M3's own
/// registration and bit lookups, and one ω resolution per draft.
pub(crate) fn seed(namespace: &M3State) -> Drafts {
    namespace
        .documents()
        .filter_map(|(doc, _)| draft_entry(namespace, doc))
        .collect()
}

/// The owner account of a registered document — M3's ω, which for a
/// document is the account it was minted under: every account M3 registers
/// is seated with a principal in the same transaction (`delegate`), and no
/// account-tier prefix longer than a document's own account can cover it.
///
/// TWO facts about the answer are asserted here, in every build, and neither
/// is decoration: this value is the left operand of [`crate::World::readable`]'s
/// subtree compare and the issuer the grant fold's coverage clause matches
/// on, so a wrong one is an authorization answer rather than a wrong log line.
///
/// * ITS EXISTENCE, the fail-CLOSED direction. `mint_document` refuses an
///   unregistered account and every registered account is a principal, so a
///   registered document ω answers nobody for is a world no M3 op produced —
///   corruption, answered as M3's own fold answers its structural facts, not
///   a live error path.
/// * ITS TIER, the fail-OPEN one, which is why it is checked in release and
///   not in debug alone. M3's ω keeps the LONGEST covering Node-or-Account
///   prefix, so a document whose own account were somehow absent from Π
///   would memoize the NODE above it instead — and a node prefix contains
///   every account beneath it, so `prefix_contains` would then admit every
///   principal seated anywhere under that node to the draft. Nothing
///   downstream can notice: the compare succeeds and the read is granted.
///
/// The invariant behind both is M3's, discharged by construction — a
/// document mints only under a registered account, and `delegate` seats a
/// principal at every account it registers. So this is the ONE deliberate
/// discharge point for it, at the boundary where a store fact becomes the
/// engine's memo, and not a second gate on a caller's obligation.
fn owner_account_of(namespace: &M3State, doc: &Address) -> Address {
    let owner = namespace
        .effective_owner_prefix(doc)
        .cloned()
        .unwrap_or_else(|| panic!("registered document {doc} has no effective owner"));
    assert_eq!(
        owner.level(),
        Level::Account,
        "the effective owner of registered document {doc} is not the account it was minted \
         under: a node-tier memo admits every principal seated under that node to the draft"
    );
    owner
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;
    use skep_namespace::HasM3;

    use crate::canon::{to_tree, SerdeTree, TreeDe};
    use crate::testkit::{delegated_account, mem_engine, USER};

    use super::*;

    /// M3's slice holding one account under the genesis node and one DRAFT
    /// document in it, driven through the real drivers, with the two
    /// addresses.
    fn account_with_a_draft() -> (M3State, Address, Address) {
        let engine = mem_engine();
        let acct = delegated_account(&engine, USER);
        let (doc, _) = engine
            .namespace()
            .create_new_document(USER, &acct, Some(false))
            .expect("an explicit-false mint is a draft");
        let namespace = engine.kernel().snapshot().world().m3().clone();
        (namespace, acct, doc)
    }

    /// `namespace` with the entry keyed by `key` struck from its serde map
    /// field `field`. A whole `M3State` decodes by bare derive, and M3's own
    /// docs name both strikes this suite makes as shapes a slice can arrive
    /// in: a SEAT struck from Π (`principals`: "a seat can also arrive inside
    /// a whole `M3State`, which decodes by bare derive"), and a registered
    /// document's entry struck from the PUBLICATION map (`documents`: a
    /// checkpoint "can hold a registered document with NO entry"). Built
    /// through the slice's serde form (`crate::canon`) and back through M3's
    /// own door, so nothing here reaches a private layout: the coupling is to
    /// the field NAME, and the panic below is what stands in for a compiler
    /// edge to it.
    fn with_entry_struck(namespace: &M3State, field: &str, key: &Address) -> M3State {
        let struck = to_tree(key).to_string();
        let mut tree = to_tree(namespace);
        let SerdeTree::Map(fields) = &mut tree else {
            panic!("M3State serializes as a struct — a map of its fields");
        };
        let map = fields
            .iter_mut()
            .find_map(|(name, value)| match name {
                SerdeTree::Str(s) if s.as_str() == field => Some(value),
                _ => None,
            })
            .unwrap_or_else(|| panic!("M3State serializes a `{field}` field"));
        let SerdeTree::Map(entries) = map else {
            panic!("M3's `{field}` serializes as a map keyed by address");
        };
        let before = entries.len();
        entries.retain(|(entry_key, _)| entry_key.to_string() != struck);
        assert_eq!(
            before - entries.len(),
            1,
            "the `{field}` entry keyed {key} must have been there to strike"
        );
        M3State::deserialize(TreeDe(&tree)).expect("M3's own types re-admit what they wrote")
    }

    /// The seed over a well-formed slice: the draft, memoized against the
    /// ACCOUNT it was minted under. The premise the two corruptions below are
    /// read against — without it, a test that panics or reads a document
    /// published proves only that something went wrong.
    #[test]
    fn the_seed_memoizes_a_draft_s_own_account() {
        let (namespace, acct, doc) = account_with_a_draft();
        let drafts = seed(&namespace);
        assert_eq!(drafts.get(&doc), Some(&acct));
        assert_eq!(acct.level(), Level::Account);
        assert!(!is_published(&drafts, &doc));
    }

    /// The TIER assertion, over the one shape that reaches it: a slice where
    /// the document's own account has no seat, so ω answers with the longest
    /// remaining covering one — the genesis NODE above it.
    ///
    /// Memoizing that node prefix is the fail-OPEN direction, and nothing
    /// downstream could notice. [`crate::World::readable`]'s subtree clause is
    /// a bare `prefix_contains` against this memo, and a node prefix contains
    /// every account beneath it, so every seated principal in the docuverse
    /// would read this draft and each read would look like an ordinary pass.
    /// So the tier is refused here, in every build, rather than asserted in
    /// debug and trusted in release.
    #[test]
    #[should_panic(expected = "is not the account it was minted under")]
    fn a_node_tier_owner_is_refused_rather_than_memoized() {
        let (namespace, acct, doc) = account_with_a_draft();
        let corrupt = with_entry_struck(&namespace, "principals", &acct);
        // The fixture must still reach the owner lookup: the document is
        // registered and its bit is still `false`, so `draft_entry` does not
        // return before it…
        assert!(corrupt.is_registered_document(&doc), "the mint's registration is untouched");
        assert!(!corrupt.published(&doc), "the mint's bit is untouched");
        // …and ω must now answer ABOVE the account tier, or this test would
        // pass for some other reason.
        assert_eq!(
            corrupt.effective_owner_prefix(&doc).map(Address::level),
            Some(Level::Node),
            "the struck seat must leave ω answering the node above the account"
        );
        let _ = seed(&corrupt);
    }

    /// The OPEN DIRECTION the set inherits from its enumeration, over the one
    /// shape that reaches it: a REGISTERED document whose publication entry is
    /// gone. M3 answers it private and its walk no longer yields it, so the
    /// seed never asks the rule of it, and the set reads it PUBLISHED — past a
    /// registration check, since the document IS registered. The rule itself,
    /// asked of the document directly, answers DRAFT, which is what locates
    /// the gap: in the ENUMERATION, not in the rule.
    ///
    /// Pinned so the direction cannot change unnoticed, not endorsed. The
    /// shape lies outside M3's fold's totality domain — a jumped `Allocate`
    /// is its live route, and M3's debug contiguity check refuses one — so it
    /// is built through M3's serde door, the checkpoint route, rather than
    /// through an op.
    #[test]
    fn a_registered_document_with_no_publication_entry_reads_published_to_the_set() {
        let (namespace, _acct, doc) = account_with_a_draft();
        let corrupt = with_entry_struck(&namespace, "publication", &doc);
        assert!(corrupt.is_registered_document(&doc), "the registration is untouched");
        assert!(
            corrupt.documents().all(|(document, _)| document != &doc),
            "M3's walk no longer yields the document"
        );
        assert!(!corrupt.published(&doc), "M3 answers the missing entry PRIVATE");
        assert!(draft_entry(&corrupt, &doc).is_some(), "the rule, asked of it, answers DRAFT");
        assert!(
            is_published(&seed(&corrupt), &doc),
            "the set, whose seed never asks the rule of it, reads it PUBLISHED"
        );
    }
}
