//! The exception set: the engine's derived index over M3's publication bit.
//!
//! It is a membership index (PUB-7.5; PUB-kickoff D1: one publication
//! definition), and it takes both halves of the hint discipline (PUB-7.7):
//! seeded by `WorldState::rebuild_derived` at load, folded by
//! `WorldState::apply` on every document-minting record.
//!
//! The set stores the unpublished side — a hash-keyed map draft document →
//! owner account, the owner fixed at mint — so `published(doc)` is a
//! membership miss: one address hash, no walk (PUB-7.1). That polarity is
//! what makes an empty set read as everything-published (PUB-7.5's fail-open
//! sign), and the set carries no witness of its own against that state: a
//! [`crate::World`] decoded from bytes has an empty set until the rebuild has
//! run over it (`World`'s invariant note), and a document never registered is
//! absent for the same reason a published one is — which is why a caller
//! acting on the answer as a document's publication state checks
//! registration first (PUB-6.37), why the read predicate relies on exactly
//! that absence (an address no mint produced reads readable, PUB-6.12), and
//! why M3's bit, not this index, is the authority (PUB-7.8's load check
//! guards the bit; this set guards nothing).
//!
//! That registration check closes the open direction for an unregistered
//! address and for nothing else, and the set inherits a second case it cannot
//! reach: a registered document M3's walk never enumerates. The set is built
//! by addition over `M3State::documents`, which yields every registered
//! document on any slice M3's own fold produced — and a slice outside that
//! fold's totality domain can hold a registered document with no publication
//! entry (a jumped `Allocate` registers the ordinals it skipped). M3 answers
//! such a document private. This set never holds it, so it reads published
//! here, and a registration check ahead of the call passes, because the
//! document *is* registered. `M3State::documents` assigns exactly this
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
//! owner is M3's too — the seat at the document's own account, read by the
//! fold and the seed through `M3State::account_seat`, which is ω's answer for
//! every document M3's ops register; what this module owns is the index —
//! construction and observation — and the one shape decision the PUB pack
//! leaves to the build (§5.5 row 3: a build may answer the bool off M3's
//! document records; this build takes the set the spec names, and PUB-7.69
//! records the standing subtraction candidate).

use skep_address::{Address, Level};
use skep_namespace::{M3Rec, M3State};

use crate::world::World;

/// The exception set's type: draft document → its owner account (PUB-7.5).
///
/// Hash-keyed, as the spec states — a membership probe is one address hash —
/// and an `im` structure, so `World::clone` on the commit path (M2 clones a
/// world per `transact`) is one more root clone. The default `RandomState`
/// hasher makes the iteration order instance-specific, so every enumeration
/// sorts what it takes before any order reaches bytes: the world dump's
/// hint, and the daemon's change feed.
pub(crate) type Drafts = im::HashMap<Address, Address>;

/// One entry of the exception set, as [`World::drafts`] enumerates it.
///
/// It is a draft document, and the account that owned it at its mint — the
/// same memo [`World::owner_account`] answers with.
///
/// A named row rather than a pair, for the reason
/// [`crate::UniversalGrantIndexRow`] is one: both halves are addresses, so a
/// consumer that read them the other way round would still compile, and would
/// go on to ask whether an account is a draft. That is always no, so every
/// entry would read as one the commit just minted, and nothing about the
/// answer would look wrong. The field names are what make the swap fail to
/// compile instead.
///
/// Rows order by document, so sorting them gives the set in address order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Draft<'a> {
    /// The draft document: a member of the set (PUB-7.5).
    ///
    /// So `published` is false for it.
    pub document: &'a Address,
    /// Its owner account, fixed at the mint and never re-derived by a walk.
    pub owner_account: &'a Address,
}

impl World {
    /// Returns `published(doc)`: whether the exception set misses `doc`.
    ///
    /// It is the daemon-side publication read (PUB-kickoff D1):
    /// `doc ∉ exception_set`, a membership miss, and nothing else. It takes
    /// the document: a version member's own bit is what its own `Allocate`
    /// journaled (M3 stamps the inherited bit, PUB-8.17), and a caller that
    /// wants the member's document's state projects to it first (PUB-2.15) —
    /// the daemon's publish gate does.
    ///
    /// **Contract — total.** This answers for every address, and an address
    /// the set never held answers `true`. For a registered document that is
    /// its publication state. For every other address — a document no mint
    /// produced, an account, a node, an element — `true` is a postcondition,
    /// not an accident of the polarity: [`World::readable`]'s published clause
    /// asks this of addresses no gate has registered, and through it meets
    /// M10's `ReadableWorld` obligation (an unregistered address reads
    /// readable, so a read arm's own `*NotRegistered` speaks, PUB-6.12) and
    /// M9's obligation that its guest predicate be total.
    ///
    /// So the registration requirement (PUB-6.37) binds exactly the callers
    /// that act on this answer as a document's publication state, and each
    /// discharges it ahead of its call: the daemon's publish gate and AUTH
    /// fold by a registration test their own order places ahead of the read,
    /// and this crate's grant admission by M7's `HomeNotRegistered` gate,
    /// which refused every link whose home was not registered, so every home
    /// the admission reads is. The read predicate owes none and must not
    /// acquire one —
    /// `an_address_no_mint_produced_reads_readable_at_every_reader_class_and_tier`
    /// fails if it does. M3's own `published` reads the bit at one map lookup
    /// and answers `false` for an unregistered address (fail-private).
    ///
    /// On every slice M3's own fold produced, the two agree on every
    /// registered document, because the seed and the fold below both answer
    /// off M3's publication map. They part in two places, and a
    /// publication-state caller's registration check closes only one. An
    /// unregistered address reads published here by the postcondition above
    /// and private at M3, and that caller refuses it first. A registered
    /// document M3's publication map holds no entry for — reachable only off a
    /// slice outside M3's fold's totality domain — reads published here and
    /// private at M3, and the check passes it, since the document *is*
    /// registered: that is the open direction this set inherits from
    /// [`M3State::documents`], stated in the module doc.
    pub fn published(&self, doc: &Address) -> bool {
        is_published(&self.drafts, doc)
    }

    /// Returns the owner account the set fixed for `doc` at its mint.
    ///
    /// It is `Some` iff `doc` is a draft in the set (PUB-7.2's memo, PUB-7.6's
    /// per-item consumers), `None` for a published or an unregistered
    /// document. The account is M3's ω of the document — the seat at its own
    /// account, read once, by the fold or the seed, through
    /// `M3State::account_seat` — and is never re-derived by a nearest-account
    /// walk per call.
    pub fn owner_account(&self, doc: &Address) -> Option<&Address> {
        self.drafts.get(doc)
    }

    /// Returns the set's drafts with their owner accounts, as [`Draft`] rows.
    ///
    /// They come in no particular order (the map is hash-keyed; sort the
    /// rows, which order by document, before comparing or rendering them).
    /// The enumeration is for readers that need the whole set — the world
    /// dump's `publication.drafts` hint, and the daemon's change feed, which
    /// walks it for the drafts a commit minted or rearranged — where the read
    /// predicate's own consumers are point reads ([`World::published`],
    /// [`World::owner_account`]).
    pub fn drafts(&self) -> impl Iterator<Item = Draft<'_>> + '_ {
        self.drafts.iter().map(|(document, owner_account)| Draft { document, owner_account })
    }
}

/// Returns `published(doc)` off the set alone: the polarity, in one place.
///
/// This is the one place that holds it. The set stores the unpublished side,
/// so a published document is a membership miss — one address hash, no walk
/// (PUB-7.1, PUB-7.5). [`World::published`] is the public face and
/// `crate::grants`' admission test is the other reader. A build that answered
/// the bool off M3's document records instead (PUB-7.69, the standing
/// subtraction candidate) replaces this function's body and must keep its
/// postcondition — `true` for every address M3 does not register as a
/// document, which [`World::published`] states and the read predicate is
/// built on. `M3State::published` by itself answers `false` there, and would
/// turn M10's front door into one that answers `withheld` naming addresses no
/// mint produced.
pub(crate) fn is_published(drafts: &Drafts, doc: &Address) -> bool {
    !drafts.contains_key(doc)
}

/// Returns `doc`'s entry if it is a draft: the rule, asked of one address.
///
/// The question is whether `doc` is a draft of M3's, and whose. An entry
/// `(doc, owner account)` iff M3 registers `doc` as a document and its bit is
/// `false`; `None` for a published document, for an account or element
/// address (outside the publication axis, PUB-1.68), and for an address M3
/// never registered.
///
/// Both halves of the hint discipline are this one call — [`fold`] asks it of
/// the address a record just minted, [`seed`] of every document
/// `M3State::documents` enumerates — so the two agree because they are one
/// rule rather than two that happen to match. Both read M3 through M3's own
/// accessors: `is_registered_document`, and `published` for the bit.
/// `M3State::documents` is the enumeration, never a second reading of the bit
/// — which is why the seed asks its addresses rather than trusting the bit it
/// yields beside them, and why the registration test guards the load path
/// exactly as it guards the commit path. That guard is what keeps
/// [`owner_account_of`]'s fail-stop off an unregistered address, on the one
/// path whose input was just deserialized.
///
/// # Panics
///
/// Panics where `doc` is a registered draft whose own account holds no seat,
/// or a seat that is not account-tier: [`owner_account_of`]'s fail-stop.
fn draft_entry(namespace: &M3State, doc: &Address) -> Option<(Address, Address)> {
    if !namespace.is_registered_document(doc) || namespace.published(doc) {
        return None;
    }
    Some((doc.clone(), owner_account_of(namespace, doc)))
}

/// Returns the fold half (PUB-7.7): the set after `rec` is folded into M3.
///
/// `prev` is the set before it. `namespace` is M3's slice after
/// `apply_m3(rec)`, so [`draft_entry`]'s questions are M3's own answers about
/// the record M3 just folded: a document-tier `Allocate` carrying `published:
/// false` joins the set, one carrying `true` does not, and an account or
/// element `Allocate` touches nothing. `RegisterNode`, `RegisterPrincipal`
/// and `AllocateRange` — a content range — mint no document, so they take
/// the early return.
///
/// The fold asks about the one address a record names. A jumped `Allocate` —
/// outside M3's fold's totality domain — registers the ordinals it skipped as
/// well, and nobody here asks about those, so the fold shares the seed's
/// blind spot: a skipped document is registered, holds no publication entry,
/// and never joins the set (the module doc's open direction).
///
/// This runs inside `World::apply`, so the membership and the registration
/// land in the one commit that carries the record (PUB-7.7 as RES-209 states
/// it): a reader's head snapshot holds both or neither.
///
/// # Panics
///
/// Panics where the record mints a draft whose own account holds no seat, or
/// a seat that is not account-tier: [`owner_account_of`]'s fail-stop.
pub(crate) fn fold(prev: &Drafts, namespace: &M3State, rec: &M3Rec) -> Drafts {
    let M3Rec::Allocate(allocation) = rec else {
        return prev.clone();
    };
    match draft_entry(namespace, allocation.addr()) {
        Some((doc, owner)) => prev.update(doc, owner),
        None => prev.clone(),
    }
}

/// Returns the seed half (PUB-7.7): the set a from-scratch walk yields.
///
/// The walk is of M3's publication map: [`draft_entry`] asked of every
/// document `M3State::documents` enumerates. Runs at load, before replay, and
/// never on a live commit; the fold carries the set forward across everything
/// above the base. The two halves agree because they are one rule under two
/// enumerations, and `Engine::check_hints` is the standing check that the
/// enumerations reach the same documents.
///
/// The addresses alone are the enumeration, and it is complete over every
/// slice M3's own fold produced: M3 writes a publication entry and the
/// registration in one fold step, and only for a document-tier mint, so there
/// the map's entries are exactly the registered documents. The bit the
/// walk yields beside each address is not read here — it comes back through
/// M3's own `published`, which is what makes this walk and the fold one rule
/// rather than two that happen to agree.
///
/// A decoded slice need not be fold-produced, and the rule's registration
/// re-ask guards exactly one of the two ways it can differ: an entry for an
/// address M3 does not register is skipped — neither fail-stopped on nor,
/// where an account above the address answers ω, memoized as a draft that
/// `World::published` would then answer `false` for
/// (`the_seed_skips_an_entry_for_an_address_the_registry_never_held`). The
/// other is outside the walk altogether. A registered document with no entry
/// is never enumerated, so the rule is never asked of it — asked, it would
/// answer draft — and the set never holds it: the open direction the module
/// doc states.
///
/// **Seed cost.** It is paid per load and per `Engine::world_at`
/// reconstruction: one walk of M3's publication map — `M3State::documents`,
/// the store's own enumeration of its registered documents — then, per
/// document, M3's own registration and bit lookups, and per draft one owner
/// lookup through [`owner_account_of`]: M3's `account_seat`, one point lookup
/// in the principal registry. So the seed is one walk plus, per document, at
/// most three logarithmic lookups, and never the product of drafts and |Π|
/// that one ω walk per draft would cost — a product whatever serves
/// historical reads would pay per reconstruction it admits, both factors
/// grown by one committed write apiece.
///
/// # Panics
///
/// Panics where a registered draft's own account holds no seat, or a seat
/// that is not account-tier: [`owner_account_of`]'s fail-stop, reachable
/// only off a decoded slice the store's ops did not produce.
pub(crate) fn seed(namespace: &M3State) -> Drafts {
    namespace
        .documents()
        .filter_map(|(doc, _)| draft_entry(namespace, doc))
        .collect()
}

/// Returns the owner account of a registered document: its own account's seat.
///
/// That is the seat at the account it was minted under, read through M3's
/// `account_seat`: one point lookup in the principal registry, never ω's walk
/// of all of it. On every state M3's ops produce that seat *is* ω's answer —
/// every account M3 registers is seated with a principal in the same
/// transaction (`delegate`), and no account-tier prefix longer than a
/// document's own account can cover it — and on any other the lookup answers
/// nobody where ω would climb.
///
/// # Panics
///
/// Panics, in every build, where either of two facts about the answer fails,
/// and neither check is decoration: this value is the left operand of the
/// subtree clause's first compare (`in_owner_subtree` in `crate::readable`)
/// and the issuer the grant fold's coverage clause matches on, so a wrong one
/// is an authorization answer rather than a wrong log line.
///
/// * **Its existence**, the fail-closed direction. `mint_document` refuses an
///   unregistered account and every registered account is seated, so a
///   registered document whose own account holds no seat is a world no M3 op
///   produced — corruption, answered as M3's own fold answers its structural
///   facts, not a live error path. ω would answer such a document from
///   above: the node, whose prefix contains every account beneath it, or an
///   ancestor account, which passes any tier check while containing every
///   principal seated under that ancestor, the owner's siblings included.
///   Memoized, either would admit them all to the draft through
///   `prefix_contains`, and nothing downstream could notice: the compare
///   succeeds and the read is granted. So the lookup asks the document's own
///   account and nothing ω climbs to, and its `None` is refused here.
/// * **Its tier**, the fail-open one, which is why it is checked in release and
///   not in debug alone: `account_seat` looks up an account-tier key by
///   construction, and this is this crate's check on that postcondition — a
///   node-tier memo would admit every principal seated anywhere under that
///   node to the draft.
///
/// The invariant behind both is M3's, discharged by construction — a
/// document mints only under a registered account, and `delegate` seats a
/// principal at every account it registers. So this is the one deliberate
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
