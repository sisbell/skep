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
//! absent for the same reason a published one is — which is why a caller
//! acting on the answer as a document's PUBLICATION STATE checks registration
//! first (PUB-6.37), why the read predicate relies on exactly that absence
//! (an address no mint produced reads READABLE, PUB-6.12), and why M3's bit,
//! not this index, is the authority (PUB-7.8's load check guards the bit;
//! this set guards nothing).
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
//! owner is M3's too — the seat at the document's own account, read at the
//! fold through `M3State::account_seat`, which is ω's answer for every
//! document M3's ops register; what this module owns is the INDEX —
//! construction and observation — and the one shape decision the PUB pack
//! leaves to the build (§5.5 row 3: a build MAY answer the bool off M3's
//! document records; this build takes the set the spec names, and the
//! standing subtraction candidate PUB-7.69 records is noted in the round's
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
/// A named row rather than a pair, for the reason
/// [`crate::UniversalGrantIndexRow`] is one: both halves are addresses, so a
/// consumer that read them the other way round would still compile, and would
/// go on to ask whether an ACCOUNT is a draft. That is always no, so every
/// entry would read as one the commit just minted, and nothing about the
/// answer would look wrong. The field names are what make the swap fail to
/// compile instead.
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
    /// CONTRACT — TOTAL: this answers for every address, and an address the
    /// set never held answers `true`. For a REGISTERED document that is its
    /// publication state. For every other address — a document no mint
    /// produced, an account, a node, an element — `true` is a POSTCONDITION,
    /// not an accident of the polarity: [`World::readable`]'s published clause
    /// asks this of addresses no gate has registered, and through it meets
    /// M10's `ReadableWorld` obligation (an unregistered address reads
    /// READABLE, so a read arm's own `*NotRegistered` speaks, PUB-6.12) and
    /// M9's obligation that its guest predicate be total.
    ///
    /// So the REGISTRATION requirement (PUB-6.37) binds exactly the callers
    /// that act on this answer as a document's PUBLICATION STATE, and each
    /// discharges it ahead of its call: the daemon's publish gate and AUTH
    /// fold by a registration test their own order places ahead of the read,
    /// and this crate's grant admission by M7's `HomeNotRegistered` gate,
    /// which registered every home it reads. The read predicate owes none and
    /// must not acquire one —
    /// `an_address_no_mint_produced_reads_readable_at_every_reader_class_and_tier`
    /// fails if it does. M3's own `published` reads the bit at one map lookup
    /// and answers `false` for an unregistered address (fail-private).
    ///
    /// On every slice M3's own fold produced, the two agree on every
    /// registered document, because the seed and the fold below both answer
    /// off M3's publication map. They part in TWO places, and a
    /// publication-state caller's registration check closes only one. An
    /// UNREGISTERED address reads published here by the postcondition above
    /// and private at M3, and that caller refuses it first. A REGISTERED
    /// document M3's publication map holds NO entry for — reachable only off a
    /// slice outside M3's fold's totality domain — reads PUBLISHED here and
    /// PRIVATE at M3, and the check passes it, since the document IS
    /// registered: that is the open direction this set inherits from
    /// [`M3State::documents`], stated in the module doc.
    pub fn published(&self, doc: &Address) -> bool {
        is_published(&self.drafts, doc)
    }

    /// The owner account the set fixed for `doc` at its mint — `Some` iff
    /// `doc` is a DRAFT in the set (PUB-7.2's memo, PUB-7.6's per-item
    /// consumers), `None` for a published or an unregistered document. The
    /// account is M3's ω of the document — the seat at its own account, read
    /// once at the fold through `M3State::account_seat` — and is never
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
/// test is the other reader. A build that answered the bool off M3's document
/// records instead (PUB-7.69, the standing subtraction candidate) replaces
/// this function's body and must keep its POSTCONDITION — `true` for every
/// address M3 does not register as a document, which [`World::published`]
/// states and the read predicate is built on. `M3State::published` by itself
/// answers `false` there, and would turn M10's front door into one that
/// answers WITHHELD naming addresses no mint produced.
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
/// address M3 does not register is skipped — neither fail-stopped on nor,
/// where an account above the address answers ω, memoized as a draft that
/// `World::published` would then answer `false` for
/// (`the_seed_skips_an_entry_for_an_address_the_registry_never_held`). The
/// other is outside the walk altogether. A registered document with NO entry
/// is never enumerated, so the rule is never asked of it — asked, it would
/// answer DRAFT — and the set never holds it: the open direction the module
/// doc states.
///
/// SEED COST, per load and per `Engine::world_at` reconstruction: one walk of
/// M3's publication map — `M3State::documents`, the store's own enumeration
/// of its registered documents — then, per document, M3's own registration and
/// bit lookups, and per DRAFT one owner lookup through [`owner_account_of`]:
/// M3's `account_seat`, ONE point lookup in the principal registry. So the
/// seed is one walk plus, per document, at most three logarithmic lookups,
/// and never the product of drafts and |Π| that one ω walk per draft would
/// cost — a product whatever serves historical reads would pay per
/// reconstruction it admits, both factors grown by one committed write
/// apiece.
pub(crate) fn seed(namespace: &M3State) -> Drafts {
    namespace
        .documents()
        .filter_map(|(doc, _)| draft_entry(namespace, doc))
        .collect()
}

/// The owner account of a registered document — the seat at the account it
/// was minted under, read through M3's `account_seat`: ONE point lookup in
/// the principal registry, never ω's walk of all of it. On every state M3's
/// ops produce that seat IS ω's answer — every account M3 registers is seated
/// with a principal in the same transaction (`delegate`), and no account-tier
/// prefix longer than a document's own account can cover it — and on any
/// other the lookup answers nobody where ω would climb.
///
/// TWO facts about the answer are asserted here, in every build, and neither
/// is decoration: this value is the left operand of the subtree clause's FIRST
/// compare (`in_owner_subtree` in `crate::readable`) and the issuer the grant
/// fold's coverage clause matches on, so a wrong one is an authorization
/// answer rather than a wrong log line.
///
/// * ITS EXISTENCE, the fail-CLOSED direction. `mint_document` refuses an
///   unregistered account and every registered account is seated, so a
///   registered document whose own account holds no seat is a world no M3 op
///   produced — corruption, answered as M3's own fold answers its structural
///   facts, not a live error path. ω would answer such a document from
///   ABOVE: the node, whose prefix contains every account beneath it, or an
///   ancestor ACCOUNT, which passes any tier check while containing every
///   principal seated under that ancestor, the owner's siblings included.
///   Memoized, either would admit them all to the draft through
///   `prefix_contains`, and nothing downstream could notice: the compare
///   succeeds and the read is granted. So the lookup asks the document's own
///   account and nothing ω climbs to, and its `None` is refused here.
/// * ITS TIER, the fail-OPEN one, which is why it is checked in release and
///   not in debug alone: `account_seat` looks up an account-tier key by
///   construction, and this is this crate's check on that postcondition — a
///   node-tier memo would admit every principal seated anywhere under that
///   node to the draft.
///
/// The invariant behind both is M3's, discharged by construction — a
/// document mints only under a registered account, and `delegate` seats a
/// principal at every account it registers. So this is the ONE deliberate
/// discharge point for it, at the boundary where a store fact becomes the
/// engine's memo, and not a second gate on a caller's obligation.
fn owner_account_of(namespace: &M3State, doc: &Address) -> Address {
    let (owner, _) = namespace.account_seat(doc).unwrap_or_else(|| {
        panic!("registered document {doc} has no owner account: its own account holds no seat")
    });
    assert_eq!(
        owner.level(),
        Level::Account,
        "the owner of registered document {doc} is not the account it was minted under: a \
         node-tier memo admits every principal seated under that node to the draft"
    );
    owner.clone()
}

#[cfg(test)]
mod tests;
