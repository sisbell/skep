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
//! The engine adds no semantics here. The bit is M3's (`M3State::published`,
//! written by the one record that registers the document, PUB-7.10); the
//! owner is M3's ω answer for the document at the fold; what this module owns
//! is the INDEX — construction and observation — and the one shape decision
//! the PUB pack leaves to the build (§5.5 row 3: a build MAY answer the bool
//! off M3's document records; this build takes the set the spec names, and
//! the standing subtraction candidate PUB-7.69 records is noted in the round's
//! report).
//!
//! SEED COST, per load and per `Engine::world_at` reconstruction: one
//! canonical transcode of M3's WHOLE slice — a tree node per serialized
//! element of the frontier map, the node set, the principal registry and the
//! publication map — then, per KEY of that map, M3's own registration and bit
//! lookups, and one ω resolution per draft. M3 publishes no enumeration over
//! its publication map, and this crate may not add one, so the map is read
//! through the slice's own serde form (`crate::canon`) — the same seam the
//! world dump already reads M3 through, and one whose coupling is to a field
//! NAME and the map's own types rather than to any private layout. A
//! `publication` enumeration on M3 would replace the whole transcode with one
//! walk; that is a store-side change and is reported.

use serde::Deserialize;
use skep_address::{Address, Level};
use skep_namespace::{M3Rec, M3State};

use crate::canon::{to_tree, SerdeTree, TreeDe};
use crate::world::World;

/// The exception set's type: draft document → its owner account (PUB-7.5).
/// Hash-keyed, as the spec states — a membership probe is one address hash —
/// and an `im` structure, so `World::clone` on the commit path (M2 clones a
/// world per `transact`) is one more root clone. The default `RandomState`
/// hasher makes the iteration order instance-specific; every enumeration
/// that reaches bytes (the world dump's hint) sorts, and nothing else
/// enumerates it.
pub(crate) type Drafts = im::HashMap<Address, Address>;

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
    /// `published` reads the bit at one map lookup and answers `false` there;
    /// the two agree on every registered document by construction (the seed
    /// and the fold below are both driven by M3's record) and differ only
    /// outside the contract.
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

    /// Every draft in the set with its owner account, in NO particular order
    /// (the map is hash-keyed; sort before comparing or rendering). The
    /// harnesses' enumeration; the spec's own consumers of the set are point
    /// reads.
    pub fn drafts(&self) -> impl Iterator<Item = (&Address, &Address)> + '_ {
        self.drafts.iter()
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
/// the address a record just minted, [`seed`] of every key of M3's
/// publication map — so the two agree because they are ONE rule rather than
/// two that happen to match. Both read M3 through M3's own accessors:
/// `is_registered_document`, and `published` for the bit. The map
/// [`publication_map`] transcodes is the ENUMERATION M3 does not publish,
/// never a second reading of the bit — which is why the seed asks its KEYS
/// rather than trusting its values, and why the registration test guards the
/// load path exactly as it guards the commit path. That guard is what keeps
/// [`owner_account_of`]'s fail-stop off an unregistered address, on the one
/// path whose input was just deserialized.
fn draft_entry(namespace: &M3State, doc: &Address) -> Option<(Address, Address)> {
    if !namespace.is_registered_document(doc) || namespace.published(doc) {
        return None;
    }
    Some((doc.clone(), owner_account_of(namespace, doc)))
}

/// The FOLD half (PUB-7.7): the set after `rec` has been folded into M3,
/// given the set before it. `namespace` is M3's slice AFTER `apply_m3(rec)`,
/// so [`draft_entry`]'s questions are M3's own answers about the record M3
/// just folded: a document-tier `Allocate` carrying `published: false` joins
/// the set, one carrying `true` does not, and an account or element
/// `Allocate` touches nothing. `RegisterNode`/`RegisterPrincipal` mint no
/// document, so they take the early return.
///
/// This runs INSIDE `World::apply`, so the membership and the registration
/// land in the ONE commit that carries the record (PUB-7.7 as RES-209 states
/// it): a reader's head snapshot holds both or neither.
pub(crate) fn fold(drafts: &Drafts, namespace: &M3State, rec: &M3Rec) -> Drafts {
    let M3Rec::Allocate { addr, .. } = rec else {
        return drafts.clone();
    };
    match draft_entry(namespace, addr) {
        Some((doc, owner)) => drafts.update(doc, owner),
        None => drafts.clone(),
    }
}

/// The SEED half (PUB-7.7): the set a from-scratch walk of M3's publication
/// map yields — [`draft_entry`] asked of every key. Runs at load, before
/// replay, and never on a live commit; the fold carries the set forward
/// across everything above the base. The two halves agree because they are
/// one rule under two enumerations, and `Engine::check_hints` is the standing
/// check that the enumerations reach the same documents.
pub(crate) fn seed(namespace: &M3State) -> Drafts {
    publication_map(namespace).keys().filter_map(|doc| draft_entry(namespace, doc)).collect()
}

/// The owner account of a registered document — M3's ω, which for a
/// document is the account it was minted under: every account M3 registers
/// is seated with a principal in the same transaction (`delegate`), and no
/// account-tier prefix longer than a document's own account can cover it.
///
/// Fail-stop on a document with no owner: `mint_document` refuses an
/// unregistered account and every registered account is a principal, so a
/// registered document ω answers nobody for is a world no M3 op produced —
/// corruption, answered as M3's own fold answers its structural facts, not a
/// live error path. The tier assertion is the same statement from the other
/// side.
fn owner_account_of(namespace: &M3State, doc: &Address) -> Address {
    let owner = namespace
        .effective_owner_prefix(doc)
        .cloned()
        .unwrap_or_else(|| panic!("registered document {doc} has no effective owner"));
    debug_assert_eq!(
        owner.level(),
        Level::Account,
        "a registered document's effective owner is the account it was minted under"
    );
    owner
}

/// M3's publication map, read through the slice's own serde form: transcode
/// the slice, take the `publication` field by NAME, and let the map re-enter
/// through its own types' doors (`Address` through M1's validating
/// deserialize). Both `expect`s name facts about THIS workspace's M3 — the
/// field exists under that name (lane 2.1's), and what its own `Serialize`
/// wrote its own `Deserialize` admits — and a change to either lands here,
/// at load, loudly.
///
/// The name is the coupling, and it is a PRIVATE one: `publication` is M3's
/// own struct field and no accessor publishes it, so a store author renaming
/// a field they never exported has no compiler edge to this call. The
/// `expect` is what stands in for one, which is why it fires at load rather
/// than resolving to an empty map.
///
/// Crate-visible for the world dump's PUBLICATION section (lane 3.4 §3),
/// which renders the AUTHORITATIVE slice this seed reads — the same read, so
/// the section and the seed cannot disagree about what M3 holds.
pub(crate) fn publication_map(namespace: &M3State) -> im::OrdMap<Address, bool> {
    let tree = to_tree(namespace);
    let SerdeTree::Map(fields) = &tree else {
        panic!("M3State serializes as a struct — a map of its fields");
    };
    let publication = fields
        .iter()
        .find_map(|(name, value)| match name {
            SerdeTree::Str(s) if s.as_str() == "publication" => Some(value),
            _ => None,
        })
        .expect("M3State serializes a `publication` field — the map the exception set indexes");
    im::OrdMap::<Address, bool>::deserialize(TreeDe(publication))
        .expect("M3's publication map re-enters through its own types, from what those types wrote")
}
