//! The GRANT FOLD — the engine's second derived index (PUB round 2, lane 3.3,
//! §1), beside the exception set (`crate::publication`): a DERIVED index over
//! the link store that answers `grant_exists(doc, principal)` — the third
//! clause of the read predicate [`crate::World::readable`] (PUB-1.31), which
//! composes it with the other two in `crate::readable`.
//!
//! Like the exception set it takes both halves of the hint discipline
//! (PUB-7.7): SEEDED by `WorldState::rebuild_derived` at load, FOLDED by
//! `WorldState::apply` on every link deposit — but over the LINK slice rather
//! than M3's, and with NO checkpoint slice of its own (`#[serde(skip)]`). The
//! failure sign is the exception set's read the other way (PUB-7.68): an empty
//! fold means an EMPTY LINK MAP, since every grant is a deposited link.
//!
//! ## What a grant is
//!
//! A grant is an ORDINARY link (deposited through MAKELINK's open surface),
//! recognized by the fold — never by M7's `TypeRegistry` — as a VALUE. Each
//! slot is read for EXACTLY ONE denoted address, or for none where the form
//! admits none:
//!
//! * the TYPE slot denotes ONE address, and that address IS [`t_grant`] — the
//!   GRANTS class (COMMONS DECISION 5) — by equality, never by prefix;
//! * the `from` slot denotes ONE address, which M1 admits and which stands on
//!   the LADDER (PUB-5.10): the CONTENT-PREFIX shared, a DOCUMENT or an
//!   ACCOUNT — read off the address, never assumed of it ([`on_the_ladder`]);
//! * the `to` slot is EMPTY for the ANY-PRINCIPAL form (PUB-5.8), or denotes
//!   ONE address M1 admits: the GRANTEE, a principal's account.
//!
//! A slot denoting SEVERAL addresses, or none where one is required, makes the
//! record MALFORMED, and a malformed record grants to nobody ([`classify`]).
//! That is the fail-closed direction and it is the whole of what the word
//! "one" carries above: a fold reaching for a slot's FIRST denoted address
//! would grant on the strength of records this one refuses.
//!
//! ## Which of the two kinds a record is (PUB-5.15)
//!
//! A grant and the record that revokes it share ONE type, ONE home and ONE
//! shape, so the fold tells them apart — a FOUR-WAY test, decided on the
//! `from` slot, on the class's own population of that home IN DEPOSIT ORDER
//! (RES-226), and at the fourth on the state the record's `replaces` names
//! (RES-308), and total over every field it reads (RES-258):
//!
//! 1. a `from` that does not denote exactly ONE address is of NEITHER KIND;
//! 2. a `from` naming an EARLIER admitted record of the class from this same
//!    home is that record's REVOCATION where it names a grant, and of NEITHER
//!    KIND where what it names is a revocation or is itself of neither kind.
//!    A grant ALREADY withdrawn is named to no effect: the revocation is the
//!    first one, and a second is honored for nothing;
//! 3. every OTHER record is a GRANT where its `from` stands on the ladder
//!    (RES-252) and its `to` denotes one address or is empty (RES-238), and
//!    of NEITHER KIND otherwise;
//! 4. a record the third outcome calls a GRANT is HONORED only where the
//!    state its `replaces` names — the revocation it follows, or the EMPTY
//!    state where it names none — is its KEY's CURRENT state, and is
//!    otherwise of NEITHER KIND ([`Grants::decide`]).
//!
//! [`classify`] answers the first three off the record's own slots; the
//! fourth is asked of the grant it answers, because what a grant's
//! `replaces` names is not in its slots: THE PAIR. A share that follows a
//! withdrawal is deposited with a `replaces` LINK — `from` the grant, `to` the
//! revocation it follows, typed [`t_replaces`] — in the grant's own
//! transaction, so the link lands at the grant's own NEXT link address, one
//! deposit after it ([`skep_links::LinkWriter::makelink_replacing`], the
//! class's one writer). The fold reads a grant's `replaces` there and nowhere
//! else: a `replaces` link homed elsewhere, or at any other address, names
//! nothing to it (residence, PUB-5.17), and a grant with no link there names
//! the EMPTY state. The fold meets a grant before its pair, so it decides the
//! grant at the grant's own turn under the EMPTY state and decides it again
//! when the pair lands ([`Grants::take_pair`]) — within the one transaction,
//! so no reader ever sees the first answer where a second followed it.
//!
//! THE KEY is the index's own — (issuer, content-prefix, grantee), PUB-5.22 —
//! and its POPULATION ([`Grants::populations`]) is every record of the class
//! that moved that key's honored state: each grant honored for it, live or
//! since withdrawn, and each revocation that withdrew one. It is read on the
//! AUDIT view, as the whole fold is (PUB-6.31), so a withdrawn grant and the
//! revocation that withdrew it still count as records that stood. The key's
//! CURRENT state is the latest of them — the grant that stands, or the
//! revocation that withdrew it — and the EMPTY state where there is none. So a
//! grant naming no `replaces` is honored only over an empty population, and
//! one naming a revocation only where that revocation is the latest; every
//! other would-be grant is of NEITHER KIND — the first share REPLAYED after
//! its revocation, a re-share replayed after a later one, the duplicate of a
//! grant that stands, the second of two re-shares naming one revocation. The
//! record a replay copies, signature and all, lands and is acknowledged, and
//! grants nothing: honoring is a fact of resolution and never of the write.
//!
//! A record of NEITHER KIND enters no index and moves no honored state, a
//! malformed record among them: [`Kind::Neither`] is the fold's one arm for
//! such a record, and a would-be grant the fourth outcome refuses is not
//! admitted; either joins the earlier-record set and nothing else.
//! The set outcome (2) is decided on holds EVERY earlier admitted record, and
//! never the operative set alone, which a revoked grant has left: read off that
//! set, a record naming a withdrawn grant or a revocation names nothing the
//! fold knows and goes on to the grant arm, where the ladder alone stands
//! between it and a fresh grant over a LINK ADDRESS — universal where its `to`
//! is empty, which a blind retry of a revoke is. Two promises rest on this
//! test, each on the outcome that states it and neither on what the addresses
//! happen to make true: A RECORD THAT WITHDRAWS A SHARE NEVER BECOMES ONE, and
//! A WITHDRAWAL, ONCE HONORED, IS LIFTED BY NOTHING. The fourth outcome keeps
//! both: it reads a would-be GRANT alone, so no revocation reaches it, and a
//! re-share it honors is a FRESH grant naming the withdrawal as the state it
//! follows — the grant withdrawn is never re-admitted.
//!
//! ## Admission (I4, PUB-5.19)
//!
//! A grant record counts only as ADMITTED:
//!
//! * homed in a document its author ω-owns — the issuer's own doc 1
//!   ([`first_document_address`]`(issuer) == home`);
//! * PUBLISHED — grants are born published, so the home is a published
//!   document (an exception-set MISS);
//! * UNREVOKED — no later admitted record from that same home names it;
//! * NAMING THE CURRENT STATE — the state its `replaces` names is its key's
//!   current state at its own position (outcome (iv), RES-308).
//!
//! Revocation is by the class's own REVOCATION record (PUB-5.13), and the fold
//! reads it from the GRANTS class alone: a later admitted `t_grant` record
//! whose `from` names an EARLIER admitted grant's own link address revokes it
//! (issuer alone — same home ⟹ same ω owner). A deposited `assert_sup` claim
//! is lineage display, never a fold input, and so is `edit_link`'s: its
//! successor carries no `replaces` link, so over a key with a record standing
//! it names a state that is not current and is of NEITHER KIND (PUB-4.15).
//!
//! ## The query indexes
//!
//! `grant_exists(doc, p)` walks up from doc through its ancestor prefixes,
//! probing p's prefix-keyed set and the ANY-PRINCIPAL set at each. Coverage is
//! CONTAINMENT (a granted prefix that is an ancestor of doc) ∩ the grant's
//! issuer being doc's ω owner. The grantee side is PRINCIPAL-EXACT.
//!
//! Coverage's issuer half is applied AT THE PROBE and never at indexing, so
//! the indexes hold the prefixes admitted grants NAME, whoever owns what lies
//! under them, and the two public enumerations over them
//! ([`World::universal_grants`], [`World::issuers_for`]) hand out that STORED
//! population — a superset of what the grants cover.
//!
//! ## The shared-entry shortfall, closed by the fourth outcome
//!
//! What the indexes hold is ENTRIES, not grants: one (issuer, content-prefix,
//! grantee) triple apiece ([`GrantIndexEntry`]), a set member with no count.
//! An admitted grant adds its entry and a revocation removes the entry of the
//! grant it names. Until outcome (iv) the class admitted two operative grants
//! sharing one entry — an issuer granting one prefix to one grantee twice —
//! and revoking EITHER took the entry both contributed, leaving the other
//! operative and in no index: THE SHARED-ENTRY SHORTFALL, recorded here as a
//! departure PUB had not decided. An entry IS a key, and the fourth outcome
//! honors no grant over a key whose population holds one standing: the
//! duplicate names the EMPTY state, or a revocation, and the key's current
//! state is the grant. So no key ever has two operative grants, no two
//! operative grants share an entry, and everything read off the indexes
//! answers the operative set exactly — every prefix an unrevoked grant names
//! (`a_duplicate_of_a_standing_grant_shares_no_index_entry`,
//! `a_duplicate_any_principal_grant_shares_no_universal_entry`). The indexes
//! still hold no count; none is needed, because nothing the fold admits can
//! add an entry twice. The reads that named the shortfall now answer without
//! it, and it is named here so that a search for the old name finds why.

use std::collections::BTreeMap;

use im::{HashMap, HashSet, OrdMap, OrdSet};
use skep_address::{checked_inc, document_of, parent, validate, Address, Level};
use skep_arrangement::trunk_of;
use skep_links::{Link, LinkRec, LinkState, View};
use skep_namespace::{first_document_address, M3State};

use crate::publication::{is_published, Drafts};
use crate::types::{t_grant, t_replaces};
use crate::world::World;

/// One STORED row of the fold's ANY-PRINCIPAL index, as the LIVE ANY-PRINCIPAL
/// set ([`World::universal_grants`]) enumerates it: a content-prefix as the
/// index keys it, and the issuers whose ANY-PRINCIPAL index ENTRIES name it —
/// one operative grant behind each entry (the module doc's fourth outcome).
/// The pair opens only those documents under the prefix whose ω owner is the
/// issuer, and none at all where it owns none.
///
/// An INDEX ROW, and never an answer: the borrowed twin of M10's
/// `skep_febe::UniversalIndexRow`, the row
/// `PublicationWorld::universal_grant_index` answers in, which the engine's
/// impl of that seam builds from this one field for field. What M10 SERVES is
/// its other row, `skep_febe::UniversalGrant` — a COVERED prefix, built only
/// by narrowing these (RES-231/264/273/298) — so a row of this type is no
/// entitlement by itself and never a displayable answer (RES-258, PUB-5.21).
///
/// A named row rather than a pair, because the two grant enumerations are
/// TRANSPOSES of each other and every half of both is an account or a
/// document address: `(content_prefix, issuers)` here, `(issuer,
/// content_prefixes)` in [`IssuerGrantIndexRow`]. Read one as the other and
/// the types still agree, so nothing refuses — a lookup keyed by the wrong
/// half finds nothing, and the term it was for goes unserved with no sign of
/// it. The field names are what make that mistake fail to compile instead.
///
/// A row BORROWS the world it was read from, as a map's own views do: the
/// read copies no address, and a caller that keeps a row past that world
/// clones what it keeps. Rows order by content-prefix, which no two rows of
/// one read share, so that order is the one the read hands them back in.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct UniversalGrantIndexRow<'a> {
    /// The content-prefix the grants name (a document or an account address).
    pub content_prefix: &'a Address,
    /// The issuers whose index entries name it, in address order.
    pub issuers: Vec<&'a Address>,
}

/// One STORED row of the fold's PRINCIPAL-EXACT index, inverted for one
/// grantee as the GRANTEE-INDEXED read ([`World::issuers_for`]) hands it back:
/// an issuer, and the union of the content-prefixes its index ENTRIES for the
/// queried grantee name, one operative grant behind each. They open, as a
/// [`UniversalGrantIndexRow`]'s do, only the documents under
/// them whose ω owner is the issuer, so this is an INDEX ROW too and never an
/// answer. [`UniversalGrantIndexRow`] is the transpose, and says why both are
/// named and what a row borrows. Rows order by issuer, which no two rows of
/// one read share, so that order is the one the read hands them back in.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct IssuerGrantIndexRow<'a> {
    /// The issuing account — a draft-stream key for the grantee.
    pub issuer: &'a Address,
    /// The prefixes that issuer's index entries for the grantee name, in
    /// address order.
    pub content_prefixes: Vec<&'a Address>,
}

impl World {
    /// THE LIVE ANY-PRINCIPAL SET, enumerable (PUB-7.22; lane 3.6 §3): every
    /// content-prefix an admitted, unrevoked ANY-PRINCIPAL grant NAMES, with
    /// the issuers whose grants name it — in prefix (tumbler) order, each
    /// issuer list in address order. An
    /// INDEX SHAPE, never per-session state: the fold's universal index as rows
    /// borrowed from this world, enumerated once per request off one head
    /// snapshot by the feed's universal term (a K-way merge of these prefixes'
    /// own position-index lists, K = this list's length). Revocation is
    /// immediate here — a revoking record withdraws its grant's entry from the
    /// index at the commit that carries it — so a derivation off this read
    /// never serves withdrawn material (PUB-7.23). Reads the fold's query
    /// index, adds no fold state, and is `readable`'s own universal probe
    /// turned inside out: a document is universally granted iff one of its
    /// ancestor prefixes is listed here with its ω owner among the issuers.
    ///
    /// The rows are STORED, and a SUPERSET of entitlement. Admission (I4)
    /// tests a record's HOME and never what its prefix covers, and the
    /// issuer half of coverage is applied at the probe (`grant_exists`), not
    /// at indexing — so an account's grant over another account's document is
    /// a row here that opens nothing
    /// (`an_any_principal_grant_from_a_non_owner_opens_nothing` holds one). A
    /// row is therefore no entitlement, and never a displayable answer
    /// (PUB-5.21). M10's any-principal discovery read narrows each row to
    /// what its issuer ω-owns (RES-231/264/273/298) before it serves one, and
    /// the daemon's feed uses the prefixes alone, as key ranges under its
    /// per-entry mask.
    ///
    /// The rows are index ENTRIES, not grants, and they answer the first
    /// sentence exactly: the fold honors at most one grant per (issuer,
    /// prefix, grantee) key at a time (PUB-5.15 (iv)), so no two operative
    /// grants share an entry, and the shared-entry shortfall `crate::grants`
    /// once recorded here cannot arise
    /// (`a_duplicate_any_principal_grant_shares_no_universal_entry`).
    ///
    /// COST, per call, uncached, and linear in the WHOLE universal index —
    /// this read takes no argument, so there is nothing in the request to
    /// read the figure off. One vector of borrows per prefix, and no address
    /// cloned. The index's size is the DEPOSITORS' choice: every admitted
    /// ANY-PRINCIPAL grant any account issues adds an entry, so this grows
    /// with the store. Nothing is memoized, so a caller polling per request
    /// re-pays per request, and it gates neither admission nor concurrency.
    pub fn universal_grants(&self) -> Vec<UniversalGrantIndexRow<'_>> {
        self.grants.universal()
    }

    /// THE GRANTEE-INDEXED READ (PUB-7.28; lane 3.6 §3): for `grantee` — a
    /// principal's account address — its ISSUERS, each with the UNION of the
    /// content-prefixes that issuer's admitted grants to it NAME, in issuer
    /// order, each prefix list in address order. The discovery term a feed
    /// poll re-pays: grants SELECT
    /// issuer streams (PUB-7.25), so a holder of N grants from M issuers merges
    /// M streams, each under one containment test against the union this read
    /// hands back. Reads the fold's principal-exact index — `grantee` alone,
    /// never its subtree (PUB-5.5) — and adds no fold state. The ANY-PRINCIPAL
    /// grants are NOT here; they are [`World::universal_grants`], the tier's
    /// own read.
    ///
    /// The rows are STORED pairs, a SUPERSET of entitlement for the reason
    /// [`World::universal_grants`] gives: an issuer's grant over a prefix whose
    /// documents it does not ω-own is a row here that opens nothing
    /// (`a_sub_account_s_grant_opens_none_of_its_parent_s_drafts` holds one).
    /// A row selects a stream to look in and grants nothing by itself; what
    /// the feed serves out of that stream is decided by its per-entry mask,
    /// the read predicate.
    ///
    /// They are index ENTRIES too, one operative grant behind each: a second
    /// grant from one issuer naming one prefix for `grantee` is of neither
    /// kind while the first stands (PUB-5.15 (iv)), so revoking the first
    /// takes the prefix out of the row with no survivor left unlisted
    /// (`a_duplicate_of_a_standing_grant_shares_no_index_entry`).
    ///
    /// COST, per call, uncached: one hash probe of the principal-exact index,
    /// then a walk of THAT grantee's whole row to invert it — one insert per
    /// (prefix, issuer) pair into an ordered map of borrows, so a logarithmic
    /// factor, and no address cloned. The row's size is neither the caller's
    /// choice nor the grantee's: any account may grant to any other, so the
    /// ISSUERS decide how much work a poll on this grantee's behalf does.
    /// Nothing is memoized, and it gates neither admission nor concurrency.
    pub fn issuers_for(&self, grantee: &Address) -> Vec<IssuerGrantIndexRow<'_>> {
        self.grants.issuers_for(grantee)
    }
}

// The GRANTS class type address the fold keys on — `crate::types::t_grant`
// (`1.1.0.1.0.1.0.3.90`, COMMONS DECISION 5): pinned in `types.rs` beside
// every other commons address the engine and the daemon read as a VALUE.

/// One admitted grant record — enough to answer queries, to withdraw its
/// index entry when a later record revokes it, and to name the state it
/// replaced. The fields are crate-visible for the world dump's `grants`
/// section (lane 3.4 §3), which renders the fold's operative set through
/// `Grants::operative_records` and destructures each record whole — so a
/// field added here is a field that section must render, or the faithfulness
/// check stops speaking for the whole record.
///
/// Held for a WOULD-BE grant too, between its own turn and its pair's
/// ([`Unpaired`]), which is where `replaces` is filled in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct GrantRecord {
    /// The grant link's home document (the issuer's doc 1).
    pub(crate) home: Address,
    /// The issuer — ω of `home`, the account whose grant this is.
    pub(crate) issuer: Address,
    /// The content-prefix shared (a document or an account address).
    pub(crate) content_prefix: Address,
    /// The grantee's account, or `None` for the ANY-PRINCIPAL form.
    pub(crate) grantee: Option<Address>,
    /// The state the grant's `replaces` names (PUB-5.15 (iv)): the `to` of
    /// the `replaces` link its own transaction deposited — the revocation a
    /// re-share follows — or `None`, the EMPTY state, where it deposited none
    /// (a first share). For an operative grant, the state that was its key's
    /// current one when it was honored.
    pub(crate) replaces: Option<Address>,
}

/// WHICH query index a grant belongs in, and where in it: the `grantee`
/// selects the index (`None` ⟹ the ANY-PRINCIPAL one), the `content_prefix`
/// keys it, and the `issuer` is the member its set holds. The three fields
/// [`Grants::admit`] and [`Grants::withdraw`] project a record onto, named,
/// so that the two index steps and their argument agree about what is being
/// indexed.
///
/// A VALUE, and that is the distinction it draws against the record it comes
/// from. A [`GrantRecord`] has an IDENTITY — the grant link's own address,
/// which the operative set keys it by — while an index entry is defined
/// entirely by these three fields, the grant's KEY ([`GrantKey`] is the owned
/// form): two admitted grants that agree on them would be ONE entry, and the
/// indexes hold no count of how many named it. That was the root of the
/// module doc's shared-entry shortfall, and the fourth outcome is what keeps
/// two operative grants off one key.
struct GrantIndexEntry<'a> {
    issuer: &'a Address,
    content_prefix: &'a Address,
    grantee: Option<&'a Address>,
}

impl GrantRecord {
    /// The query-index entry this record contributes.
    fn index_entry(&self) -> GrantIndexEntry<'_> {
        GrantIndexEntry {
            issuer: &self.issuer,
            content_prefix: &self.content_prefix,
            grantee: self.grantee.as_ref(),
        }
    }

    /// The KEY this record belongs to — its index entry, owned.
    fn key(&self) -> GrantKey {
        GrantKey {
            issuer: self.issuer.clone(),
            content_prefix: self.content_prefix.clone(),
            grantee: self.grantee.clone(),
        }
    }
}

/// A grant's KEY (PUB-5.15 (iv), PUB-5.22): the ISSUER, the CONTENT-PREFIX and
/// the GRANTEE — `None` for ANY-PRINCIPAL — the three fields an index entry
/// is ([`GrantIndexEntry`] is the borrowed form), owned so that a key's
/// population can be kept under it. Writers of different keys never meet: the
/// fourth outcome reads one key's population and no other's. Every record of
/// one key is homed in ONE document — the issuer's doc 1, the one home
/// admission takes for that issuer — so within a key, address order IS
/// deposit order.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) struct GrantKey {
    issuer: Address,
    content_prefix: Address,
    grantee: Option<Address>,
}

/// What one member of a key's POPULATION did to the key's honored state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Member {
    /// A grant HONORED for the key — standing, or since withdrawn.
    Grant,
    /// A revocation that WITHDREW the key's grant — the one state a re-share
    /// can name.
    Revocation,
}

/// A WOULD-BE GRANT whose pair has not been read: the record the fold met
/// last in its home that the third outcome called a grant, with its
/// [`GrantRecord`] as its own turn decided it — `replaces` the EMPTY state,
/// since nothing had named another yet. [`Grants::take_pair`] decides it again
/// where the next link of that home names it; any other next link leaves it
/// unpaired for good. One per HOME, so a record's window is its own home's
/// next address and nothing else.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Unpaired {
    /// The would-be grant's own link address.
    record: Address,
    /// The record as its own turn read it.
    grant: GrantRecord,
}

/// The grant fold: the operative grant set, the two query indexes it is
/// projected into, the earlier-record set, each key's population and each
/// home's unpaired would-be grant. All `im` persistent structures, so
/// `World::clone` on the commit path is one more root clone. `#[serde(skip)]`
/// at the World: derived, never checkpointed (the module docs' hint
/// discipline).
///
/// The classification asks the fold two questions, and asks both through
/// methods: whether a `from` names an earlier record of its home
/// ([`Grants::holds_earlier`]), and whether that record is an operative grant
/// ([`Grants::is_operative`]). How the earlier-record set and the operative
/// set relate is this type's to keep, on both sides: no caller reads either
/// structure to answer those questions, and every record the fold takes goes
/// through [`Grants::take_admitted`], the fold's one caller of the three
/// transitions below, so every operative grant is in the earlier-record set.
///
/// The operative set, its two indexes and the key populations must agree,
/// and [`Grants::admit`], [`Grants::withdraw`] and [`Grants::unadmit`] are the
/// only three transitions that move any of them — each doing the record edit,
/// the index edit and the population edit as ONE step. So the projection this
/// type's fields describe is performed here rather than at a caller, and a
/// fold arm that moved the set without its index, or without its key's
/// population, would have to be written past those three rather than beside
/// them. The earlier-record set stands apart from that agreement:
/// [`Grants::keep_earlier`] is its one transition, it only ever gains, none of
/// the other three touches it, and [`Grants::take_admitted`] takes it for
/// every admitted record, after that record's effect. So does the unpaired
/// map, whose one writer is [`Grants::take_admitted`] and whose one reader is
/// [`Grants::take_pair`].
#[derive(Clone, Debug, Default)]
pub(crate) struct Grants {
    /// THE OPERATIVE SET: the admitted, unrevoked grant records, keyed by the
    /// grant link's OWN address — so a revoking record removes exactly the
    /// RECORD it names. What leaves the query indexes with that record is its
    /// [`GrantIndexEntry`], which is a value and which a second record can
    /// name too.
    operative_records: HashMap<Address, GrantRecord>,
    /// THE EARLIER-RECORD SET (PUB-5.15, RES-226): the link address of EVERY
    /// admitted record of the class, whatever [`classify`] made of it — a
    /// grant live or since withdrawn, a revocation, a record of neither kind
    /// — and never pruned. It is what `operative_records` cannot be:
    /// [`Grants::withdraw`] takes a revoked grant OUT of that map, so a later
    /// record naming the withdrawn grant, or naming the revocation, finds
    /// nothing there, and a test decided on that map alone reads such a
    /// record as a fresh grant.
    ///
    /// A record joins AFTER its own classification
    /// ([`Grants::take_admitted`]), so at any record's turn the members from
    /// its home are exactly the records that home deposited EARLIER — the
    /// deposit order the test is stable under. One set for every home: a link
    /// address names its own home ([`document_of`]), so
    /// [`Grants::holds_earlier`] asks the same-home question of the address
    /// and keeps no per-home structure.
    ///
    /// FOLD STATE like the rest, journaled nowhere and re-derived by [`seed`]
    /// off the same walk. It grows by one address per admitted record of the
    /// class and never shrinks — a revocation ADDS a record — so its size is
    /// the depositors', as the class's own is.
    earlier_records: HashSet<Address>,
    /// THE PER-KEY POPULATION (PUB-5.15 (iv); RES-308/309 — the authority
    /// link type investigation's STOP-2): per [`GrantKey`], every admitted
    /// record of the class that moved that key's honored state, by its link
    /// address — each grant honored for the key, standing or since
    /// WITHDRAWN, and each revocation that withdrew one. Read on the AUDIT
    /// view, as the whole fold is: [`Grants::withdraw`] takes a grant out of
    /// the operative set and LEAVES it here, beside the revocation it adds,
    /// so a withdrawn grant still counts as a record that stood — which is
    /// what keeps a replayed first share off an empty-looking key. Two
    /// records of the class name a key and are not members, and neither
    /// could be read as the key's state: a revocation naming a grant already
    /// withdrawn (honored for nothing) and a would-be grant the fourth
    /// outcome refused.
    ///
    /// The members of one key share one home, so the map's ADDRESS order is
    /// their DEPOSIT order, and the key's CURRENT state is its last member —
    /// [`Grants::current_state`]. No key holds an empty map: the one
    /// transition that removes a member ([`Grants::unadmit`]) drops the key
    /// with its last.
    ///
    /// Fold state like the rest, re-derived by [`seed`]. It grows by one
    /// entry per honored grant and one per revocation ever made — the
    /// withdrawn grants it keeps are what PUB-7.67's "one entry per
    /// revocation ever made" counts — and never shrinks on the fold's own
    /// path.
    populations: HashMap<GrantKey, OrdMap<Address, Member>>,
    /// THE UNPAIRED WOULD-BE GRANT of each HOME ([`Unpaired`]): the record
    /// the fold met last in that home that the third outcome called a grant,
    /// until the next link of its home names it as its pair. What lets the
    /// fold decide a grant at its own turn and again at its pair's without a
    /// read of the link store, which the fold is not handed: at the pair's
    /// turn this holds the record's key and its first verdict. At most one
    /// entry per home, replaced by that home's next would-be grant and
    /// removed when its pair is read — so what stands at any snapshot is,
    /// per home, the last would-be grant whose pair was never read, which is
    /// what [`seed`] re-derives.
    unpaired: HashMap<Address, Unpaired>,
    /// The PRINCIPAL-EXACT index: grantee account → its granted
    /// content-prefixes → the issuers who granted them.
    by_grantee: HashMap<Address, OrdMap<Address, OrdSet<Address>>>,
    /// The ANY-PRINCIPAL index (PUB-5.8): content-prefix → issuers, granted to
    /// every principal.
    universal: OrdMap<Address, OrdSet<Address>>,
}

// ── the map-of-sets edits both indexes are made of ──
//
// `universal` is an `OrdMap<Address, OrdSet<Address>>` and every value of
// `by_grantee` is another one, so the fold's index maintenance is ONE shape
// throughout: [`Grants::index_add`] and [`Grants::index_remove`] each SELECT
// the index a [`GrantIndexEntry`] belongs in and hand it here. The decision
// at those sites is which index; the bookkeeping is here.
//
// That ONE shape is why the two below are spelled concretely rather than over
// a key and a member type: every map they edit keys a content-prefix to the
// issuers who granted it, and a signature that admitted a second pairing
// would be claiming a generality the fold has no use for.

/// `map[key] ∪= {member}`, adding the key where it is absent.
fn set_insert(map: &mut OrdMap<Address, OrdSet<Address>>, key: &Address, member: Address) {
    match map.get_mut(key) {
        Some(members) => {
            members.insert(member);
        }
        None => {
            map.insert(key.clone(), OrdSet::unit(member));
        }
    }
}

/// `map[key] −= {member}`, DROPPING the key where its set empties — so no
/// index ever holds an empty set, and an empty map means "nothing granted"
/// rather than "nothing granted, or one revocation ago".
fn set_remove(map: &mut OrdMap<Address, OrdSet<Address>>, key: &Address, member: &Address) {
    let Some(members) = map.get_mut(key) else {
        return;
    };
    members.remove(member);
    if members.is_empty() {
        map.remove(key);
    }
}

impl Grants {
    /// An empty fold — genesis, and the decoded-world starting point before
    /// the rebuild runs.
    pub(crate) fn new() -> Grants {
        Grants::default()
    }

    /// The operative set — every admitted, unrevoked grant record with the
    /// grant link's own address — in the map's hash order (the world dump's
    /// `grants` section renders it, and the dump's rendering sorts a map's
    /// entries). The operative set's one enumeration, where
    /// [`Grants::universal`] and [`Grants::issuers_for`] enumerate the query
    /// indexes; the predicate's consumers are the point probes below.
    /// Compiled with the `dump` feature alone, which holds its one caller.
    #[cfg(feature = "dump")]
    pub(crate) fn operative_records(&self) -> impl Iterator<Item = (&Address, &GrantRecord)> + '_ {
        self.operative_records.iter()
    }

    /// `grant_exists(doc, p)` (PUB-1.31's third clause): does some index ENTRY
    /// cover `doc` for principal-account `grantee`, issued by doc's ω owner? An
    /// entry and not a grant, and one operative grant stands behind each (the
    /// module doc's fourth outcome). Coverage = CONTAINMENT (a granted prefix ⊑ doc)
    /// ∩ the grant's issuer is `owner`. One probe of the principal-exact index
    /// (when there is a grantee) and one of the ANY-PRINCIPAL index at each
    /// ancestor, `doc` itself included.
    ///
    /// `owner` is doc's mint-time ω owner (the exception set's memo), and the
    /// coverage's issuer clause is exactly `issuers.contains(owner)`: a grant
    /// issued by anyone but doc's owner cannot make doc readable, so X cannot
    /// "grant" access to Y's document.
    pub(crate) fn grant_exists(
        &self,
        owner: &Address,
        grantee: Option<&Address>,
        doc: &Address,
    ) -> bool {
        // A grant of `prefix` that `owner` issued, in either index — the
        // principal-exact one first.
        let covers = |prefix: &Address| {
            grantee
                .and_then(|grantee| self.by_grantee.get(grantee))
                .and_then(|prefixes| prefixes.get(prefix))
                .is_some_and(|issuers| issuers.contains(owner))
                || self.universal.get(prefix).is_some_and(|issuers| issuers.contains(owner))
        };
        covers(doc) || std::iter::successors(parent(doc), parent).any(|ancestor| covers(&ancestor))
    }

    /// The ANY-PRINCIPAL index as rows borrowed from it, in the `OrdMap`'s key
    /// order — tumbler order — each issuer list in the `OrdSet`'s address
    /// order. [`World::universal_grants`] is the public face.
    pub(crate) fn universal(&self) -> Vec<UniversalGrantIndexRow<'_>> {
        self.universal
            .iter()
            .map(|(content_prefix, issuers)| UniversalGrantIndexRow {
                content_prefix,
                issuers: issuers.iter().collect(),
            })
            .collect()
    }

    /// The principal-exact index for one grantee, INVERTED over borrows:
    /// `by_grantee` keys prefix → issuers (the shape `grant_exists`'s O(depth)
    /// probe wants); the feed wants issuer → the union of that issuer's
    /// prefixes (the shape its per-issuer stream test wants). The issuers come
    /// out in the ordered map's key order, and each issuer's prefixes in
    /// address order and without a repeat: the walk visits the prefixes in
    /// key order, and an issuer sits at most once in any prefix's set.
    /// [`World::issuers_for`] is the public face.
    pub(crate) fn issuers_for(&self, grantee: &Address) -> Vec<IssuerGrantIndexRow<'_>> {
        let mut by_issuer: BTreeMap<&Address, Vec<&Address>> = BTreeMap::new();
        if let Some(prefixes) = self.by_grantee.get(grantee) {
            for (prefix, issuers) in prefixes.iter() {
                for issuer in issuers.iter() {
                    by_issuer.entry(issuer).or_default().push(prefix);
                }
            }
        }
        by_issuer
            .into_iter()
            .map(|(issuer, content_prefixes)| IssuerGrantIndexRow { issuer, content_prefixes })
            .collect()
    }

    /// The fold's step over ONE ADMITTED record of the class, deposited at
    /// `addr` in `home` by `issuer` — [`admitted_issuer`]'s answer. The record
    /// is classified against the fold as it stands and its kind takes effect:
    /// a would-be GRANT is decided by the fourth outcome under the EMPTY state
    /// ([`Grants::decide`]) — its pair, if it has one, is the NEXT deposit of
    /// its home — and held as its home's unpaired would-be grant; a REVOCATION
    /// withdraws the grant it names; and a record of NEITHER kind moves
    /// nothing honored. Then, whatever its kind, it is kept as an earlier
    /// record, so a later record of its home naming it is answered by
    /// PUB-5.15's second outcome.
    ///
    /// ONE step, because the classification rests on two orders inside it.
    /// The record is classified BEFORE it joins the earlier-record set, so it
    /// never names itself as an earlier record. And it joins that set in the
    /// same step as its effect, so every grant this makes operative is in the
    /// set — without which a later record naming it would pass the
    /// earlier-record test by, meet the ladder, and revoke nothing
    /// (`the_earlier_record_set_keeps_what_the_operative_set_lets_go` holds a
    /// fresh grant in both at once).
    fn take_admitted(&mut self, addr: Address, home: Address, issuer: Address, value: &Link) {
        let kind = classify(self, &home, value);
        match kind {
            Kind::Grant { content_prefix, grantee } => {
                let grant = GrantRecord {
                    home: home.clone(),
                    issuer,
                    content_prefix,
                    grantee,
                    replaces: None,
                };
                self.decide(addr.clone(), grant.clone());
                self.unpaired.insert(home, Unpaired { record: addr.clone(), grant });
            }
            Kind::Revoke { revoked } => self.withdraw(&revoked, addr.clone()),
            Kind::Neither => {}
        }
        self.keep_earlier(addr);
    }

    /// THE PAIR's step — the `replaces` link deposited at `addr`, whose value
    /// is `value` (typed [`t_replaces`]): where it sits at its home's
    /// unpaired would-be grant's NEXT link address and its `from` denotes
    /// exactly that record, it is that record's pair (PUB-5.15: "the `to` of
    /// the `replaces` link homed with that grant whose `from` is that grant,
    /// deposited in the grant's own transaction"), and the record is DECIDED
    /// AGAIN on the state the pair names: its first verdict, taken under the
    /// EMPTY state, is taken back ([`Grants::unadmit`]) and the fourth outcome
    /// asked anew ([`Grants::decide`]). Any other `replaces` link names
    /// nothing to the fold — homed elsewhere, at another address, naming
    /// another record — and moves nothing.
    ///
    /// EXACT, because nothing of the record's key moved between the two
    /// turns: the pair is the record's home's next deposit, and every record
    /// of a key is homed in that one home. So taking the first verdict back
    /// restores the key to what it was at the record's own position, which is
    /// where PUB-5.15 asks the question.
    ///
    /// The state named is the pair's `to`: the EMPTY state where the slot is
    /// empty, the one address it denotes otherwise — and NONE the fold can
    /// read where it denotes several, or one M1 refuses, which leaves the
    /// record of NEITHER KIND (RES-258's totality over every field the test
    /// reads). The one writer of the class deposits neither, and a record's
    /// first verdict never outlives a pair that names nothing it can read.
    fn take_pair(&mut self, addr: &Address, value: &Link) {
        let home = document_of(addr)
            .expect("a link address is element-level, so its home document exists");
        let Some(unpaired) = self.unpaired.get(&home) else {
            return;
        };
        let names_the_record =
            value.from_slot().single_denoted() == Some(unpaired.record.tumbler());
        let at_its_next_address = checked_inc(&unpaired.record, 0).is_ok_and(|next| next == *addr);
        if !(names_the_record && at_its_next_address) {
            return;
        }
        let Unpaired { record, mut grant } =
            self.unpaired.remove(&home).expect("the entry was read a line above");
        self.unadmit(&record);
        let named = if value.to_slot().is_empty() {
            None
        } else {
            let Some(named) =
                value.to_slot().single_denoted().and_then(|t| validate(t.clone()).ok())
            else {
                return; // a `to` naming no one state: the record is of neither kind
            };
            Some(named)
        };
        grant.replaces = named;
        self.decide(record, grant);
    }

    /// OUTCOME (iv), taken (PUB-5.15; RES-308): ADMIT the would-be `grant`
    /// deposited at `addr` where the state its `replaces` names is its key's
    /// CURRENT state ([`Grants::names_the_current_state`]); otherwise it is of
    /// NEITHER KIND and nothing moves. The one door to [`Grants::admit`].
    fn decide(&mut self, addr: Address, grant: GrantRecord) {
        if self.names_the_current_state(&grant.key(), grant.replaces.as_ref()) {
            self.admit(addr, grant);
        }
    }

    /// OUTCOME (iv)'s question: is the state `replaces` names — `None` the
    /// EMPTY state — `key`'s CURRENT state? The EMPTY state is current where
    /// the key's population is empty; a named state is current where it is
    /// the population's latest member and that member is a REVOCATION — the
    /// one state a re-share follows. So a grant naming the grant that stands
    /// is refused as surely as one naming a revocation a later record has
    /// passed: two operative grants of one key is the state this outcome
    /// exists to keep out. Of two re-shares naming one revocation the FIRST
    /// counts — the lowest-addressed, its home being their deposit order —
    /// since once it is honored the revocation is no longer the latest.
    fn names_the_current_state(&self, key: &GrantKey, replaces: Option<&Address>) -> bool {
        match (replaces, self.current_state(key)) {
            (None, None) => true,
            (Some(named), Some((latest, Member::Revocation))) => named == latest,
            _ => false,
        }
    }

    /// `key`'s CURRENT state: its population's latest member — the grant that
    /// stands, or the revocation that withdrew the last one — or `None`, the
    /// EMPTY state, where the population is empty.
    fn current_state(&self, key: &GrantKey) -> Option<(&Address, Member)> {
        self.populations.get(key).and_then(OrdMap::get_max).map(|(addr, member)| (addr, *member))
    }

    /// ADMIT `grant`, deposited at link address `addr`: it joins the operative
    /// set under its own address, its [`GrantIndexEntry`] joins the query
    /// index that entry names, and it joins its key's population as a
    /// [`Member::Grant`]. One transition, so the set, its projection and the
    /// population cannot part. [`Grants::decide`] is its one caller, for a
    /// would-be grant the fourth outcome honors.
    fn admit(&mut self, addr: Address, grant: GrantRecord) {
        self.index_add(grant.index_entry());
        self.populations.entry(grant.key()).or_default().insert(addr.clone(), Member::Grant);
        self.operative_records.insert(addr, grant);
    }

    /// WITHDRAW the grant deposited at `addr`, by the revocation deposited at
    /// `by`: it leaves the operative set, its [`GrantIndexEntry`] leaves the
    /// query index it was added to — and it STAYS in its key's population,
    /// which `by` joins as the key's new current state, a
    /// [`Member::Revocation`]. One transition, and one lookup, since the
    /// removal hands the record back. Naming no operative grant is a no-op:
    /// a revocation honored for nothing joins no population.
    ///
    /// The indexes are SETS and hold no count, so an entry is withdrawn by the
    /// first record that names it; the fourth outcome is what makes that
    /// exact, no second operative grant ever sharing the entry.
    fn withdraw(&mut self, addr: &Address, by: Address) {
        if let Some(grant) = self.operative_records.remove(addr) {
            self.index_remove(grant.index_entry());
            self.populations.entry(grant.key()).or_default().insert(by, Member::Revocation);
        }
    }

    /// TAKE BACK the admission of the grant deposited at `addr` — the
    /// verdict its own turn gave it under the EMPTY state, where its pair
    /// names another ([`Grants::take_pair`]): it leaves the operative set, its
    /// index entry and its key's population, the key dropped with its last
    /// member, so the fold stands as it did before the record. A no-op where
    /// that turn admitted nothing. Exact only there, one deposit after the
    /// record: an admission under the EMPTY state found the key's population
    /// empty, so the record was its only member and its entry's only grant.
    fn unadmit(&mut self, addr: &Address) {
        let Some(grant) = self.operative_records.remove(addr) else {
            return;
        };
        self.index_remove(grant.index_entry());
        let key = grant.key();
        if let Some(population) = self.populations.get_mut(&key) {
            population.remove(addr);
            if population.is_empty() {
                self.populations.remove(&key);
            }
        }
    }

    /// KEEP the admitted record deposited at `addr` as an EARLIER one to every
    /// record that follows it — the earlier-record set's one transition, taken
    /// for every admitted record of the class whatever its kind, and undone by
    /// nothing: a withdrawn grant stays a member, which is the point of it.
    fn keep_earlier(&mut self, addr: Address) {
        self.earlier_records.insert(addr);
    }

    /// Whether `addr` is the link address of an EARLIER admitted record of the
    /// class homed in `home` — the set PUB-5.15's second outcome decides on.
    /// EARLIER is the set's own invariant (a record joins after its turn), and
    /// SAME HOME is read off the address: a record is homed in the document
    /// its link address lies in, which is how [`fold_one`] derives every
    /// record's home. Same home ⟹ same ω owner is the whole of the issuer
    /// restriction (PUB-5.13), so a record naming ANOTHER home's member is
    /// not answered here. The probe runs first, so an address that names no
    /// record — nearly every `from` there is — costs no arithmetic at all.
    fn holds_earlier(&self, addr: &Address, home: &Address) -> bool {
        self.earlier_records.contains(addr) && document_of(addr).as_ref() == Some(home)
    }

    /// Whether `addr` is the link address of an OPERATIVE grant — admitted
    /// and not withdrawn — which is the one earlier record a later record of
    /// its home REVOKES (PUB-5.15). [`Grants::take_admitted`] keeps every
    /// record it takes as an earlier one, so every such grant is in the
    /// earlier-record set as well, and a withdrawal is what parts the two
    /// answers: the grant leaves the operative set and stays in the
    /// earlier-record set. So of a record that set holds, this is the question
    /// that tells a revocation from a record of neither kind.
    fn is_operative(&self, addr: &Address) -> bool {
        self.operative_records.contains_key(addr)
    }

    /// [`Grants::admit`]'s index step: add `entry` to the query index its
    /// grantee names — the PRINCIPAL-EXACT one keyed by the grantee, or the
    /// ANY-PRINCIPAL one.
    fn index_add(&mut self, entry: GrantIndexEntry<'_>) {
        let index = match entry.grantee {
            Some(grantee) => self.by_grantee.entry(grantee.clone()).or_default(),
            None => &mut self.universal,
        };
        set_insert(index, entry.content_prefix, entry.issuer.clone());
    }

    /// [`Grants::withdraw`]'s index step: take `entry` out of the index it was
    /// added to, dropping a grantee whose last entry this was — so
    /// `by_grantee` holds no empty prefix map, as `set_remove` leaves no empty
    /// issuer set.
    fn index_remove(&mut self, entry: GrantIndexEntry<'_>) {
        let Some(grantee) = entry.grantee else {
            set_remove(&mut self.universal, entry.content_prefix, entry.issuer);
            return;
        };
        let Some(prefixes) = self.by_grantee.get_mut(grantee) else {
            return;
        };
        set_remove(prefixes, entry.content_prefix, entry.issuer);
        if prefixes.is_empty() {
            self.by_grantee.remove(grantee);
        }
    }
}

/// The classification of one admitted `t_grant` record, off its `from` slot.
///
/// The removing arm is [`Kind::Revoke`], and the word is load-bearing: the
/// act it names reads the GRANTS class alone (a later admitted `t_grant`
/// record naming an earlier one), while `supersede` in this crate names the
/// ⟦supersedes⟧ CLASS — the claims `crate::dump`'s filter walks and the fold
/// must never take an input from. Revocation is by the class's own record
/// (PUB-5.13), and lineage is the `supersedes` claim, and that is exactly why
/// the two need two words here.
enum Kind {
    /// A WOULD-BE grant of `content_prefix` — a document or an account — to
    /// `grantee` (`None` = ANY-PRINCIPAL): what the third outcome calls a
    /// GRANT, and what the fourth then honors or leaves of neither kind
    /// ([`Grants::decide`]).
    Grant { content_prefix: Address, grantee: Option<Address> },
    /// A revocation naming an EARLIER admitted grant's link address, the grant
    /// still operative. Decided off the `from` slot ALONE, so this arm's `to`
    /// slot is never read and carries no meaning: a revoking record revokes
    /// whatever its `to` holds.
    Revoke { revoked: Address },
    /// A record of NEITHER KIND (PUB-5.15) — the one fail-closed arm, whatever
    /// put the record there, and three things do. It may be MALFORMED: a
    /// `from` denoting no address, several, or one M1 refuses, or, on the
    /// fresh-grant arm, a `to` denoting more than one. It may be well formed
    /// and name a SPENT record: a `from` naming an earlier record of this home
    /// that is no operative grant — a grant already withdrawn, which is what a
    /// blind retry of a revoke names, a revocation, or a record itself of
    /// neither kind. Or its `from` may stand on neither rung of the ladder.
    /// The fold enters it in no index and moves no honored state by it — it
    /// joins the earlier-record set and nothing else — so it grants to nobody
    /// and lifts nothing, whichever of the three put it here.
    Neither,
}

/// Whether a link value is typed `class` — denotation equality on the type
/// slot. The fold keys on its two commons types, [`t_grant`] and
/// [`t_replaces`], as VALUES, never through M7's registry.
fn is_typed(value: &Link, class: &Address) -> bool {
    value.type_slot().single_denoted() == Some(class.tumbler())
}

/// Admission (I4), asked of a record's home: the ISSUER (ω of `home`) where
/// the home is that issuer's OWN doc 1 and PUBLISHED, else `None`. A QUERY,
/// which is why it is named for its answer — [`Grants::take_admitted`] is the
/// step that acts on it.
///
/// `home` is a registered document (a deposit lands in no unregistered home,
/// M7's HomeNotRegistered gate). `published(home)` is the exception-set miss —
/// `home ∉ drafts` — and so it inherits the set's open direction
/// (`crate::publication`): a registered home M3's publication map holds no
/// entry for reads published here where M3 answers it private, and a grant
/// homed there admits.
fn admitted_issuer(namespace: &M3State, drafts: &Drafts, home: &Address) -> Option<Address> {
    // Published: an exception-set miss (grants are born published). The
    // polarity is `crate::publication`'s to hold, not this module's.
    if !is_published(drafts, home) {
        return None;
    }
    // The issuer — ω of the home, read as the seat at the home's own account
    // by one lookup. Where that account holds no seat, ω answers a node, an
    // ancestor account or nobody, and none of them has the home as its doc 1,
    // so the two reads refuse alike.
    let (issuer, _) = namespace.account_seat(home)?;
    // The home is the issuer's own doc 1.
    if first_document_address(issuer).as_ref() != Some(home) {
        return None;
    }
    Some(issuer.clone())
}

/// PUB-5.10's LADDER, read off the address alone: whether `from` is a DOCUMENT
/// or an ACCOUNT, the two rungs a grant's coverage is written over (PUB-5.22)
/// and the only two [`Grants::grant_exists`] can answer for. M1 arithmetic and
/// M5's projection, no read: the rung is asked of the address a depositor
/// wrote, registered or not, so it answers alike at the deposit and at every
/// later seed.
///
/// A VERSION MEMBER is a document-LEVEL address and stands on neither rung.
/// The read predicate projects every document to its TRUNK before the grant
/// clause walks up from it (`crate::readable`, PUB-2.15), so no walk ever
/// probes a member's own address: a grant there covers nothing, and indexed it
/// is a row that names a share nobody holds — universal where its `to` is
/// empty, which is the record RES-252 keeps off the board-wide face. The
/// document rung is therefore the address that IS its own trunk, asked through
/// [`trunk_of`], PUB-8.2's one spelling of that projection.
///
/// A NODE stands on neither (PUB-5.10: its ω owner holds no document), and it
/// is the one such address the grant clause's walk DOES reach — every
/// document's ancestors end at its node. Indexed, a node-rung record would
/// open every document its issuer owns, a reach no rung of the ladder has; so
/// for this address the test closes a door rather than an empty row. An
/// ELEMENT stands on neither: a link address that names no earlier record of
/// this home, or a content position, contains no document (PUB-5.9).
fn on_the_ladder(from: &Address) -> bool {
    match from.level() {
        Level::Account => true,
        Level::Document => trunk_of(from) == *from,
        Level::Node | Level::Element => false,
    }
}

/// Classify one admitted `t_grant` record — PUB-5.15's test, its first three
/// outcomes in its own order (the module docs state it whole): a `from` that
/// does not denote exactly one address is of NEITHER KIND; a `from` naming an
/// EARLIER admitted record of this home is a REVOCATION where that record is
/// an operative grant and of NEITHER KIND where it is anything else; every
/// other record is a would-be GRANT where its `from` stands on the ladder and
/// its `to` is the grantee (empty ⟹ ANY-PRINCIPAL), and of NEITHER KIND
/// otherwise.
///
/// The FOURTH outcome is asked of the would-be grant this answers, by
/// [`Grants::decide`]: what it reads — the state the grant's `replaces`
/// names — is not in the record's slots but in its PAIR, which lands one
/// deposit later, so it is decided at the record's own turn under the EMPTY
/// state and again at the pair's ([`Grants::take_pair`]). Nothing here reads
/// it, and so no outcome above moves with it: a record the first three call
/// a revocation, or of neither kind, is that whatever a `replaces` link beside
/// it names.
///
/// PRECEDENCE, which is part of the rule rather than an accident of the order
/// the lines happen to sit in: the EARLIER-RECORD test speaks first, and it is
/// answered before the ladder is consulted and before the `to` slot is read at
/// all. Ahead of the LADDER, because a revoking record's `from` is by
/// construction a link address, of neither rung — a ladder test that ran first
/// would turn every revocation into a record of neither kind, and nothing
/// would ever be withdrawn (RES-252: the second outcome decides every `from`
/// naming an earlier record before the third is reached). Ahead of the `to`
/// slot, so a revoking record's `to` goes unexamined and cannot make it
/// malformed, whatever it holds — where the same `to` on a FRESH grant would.
/// Parsing `to` ahead of that test would turn a revocation into a silent
/// no-op, leaving open what its issuer revoked.
///
/// The earlier-record test and the ladder OVERLAP, and neither is the other's
/// stand-in. Every record of the class sits at a link address, so a `from`
/// the second outcome sends to NEITHER KIND is one the ladder would have
/// refused too. That is arithmetic accident and not shape, which is PUB-5.15's
/// own ground for stating a test: the promise that a withdrawal is lifted by
/// nothing is held by the set it is stated over, and stays held under a
/// ladder that one day gains a rung.
///
/// Every slot this DOES read is read for exactly one denoted address: the
/// type slot at [`is_typed`] before this is called, `from` always, and
/// `to` on the fresh-grant arm alone. A slot denoting several, or a `from`
/// denoting none or one M1 refuses, is malformed and so of [`Kind::Neither`]
/// — the fail-closed direction, since a record naming two grantees grants to
/// neither.
fn classify(prev: &Grants, home: &Address, value: &Link) -> Kind {
    let Some(from) = value.from_slot().single_denoted() else {
        return Kind::Neither; // `from` must denote exactly one address
    };
    let Ok(from) = validate(from.clone()) else {
        return Kind::Neither;
    };
    // A `from` naming an EARLIER admitted record of THIS home is decided HERE
    // and by nothing below — ahead of the ladder and of the `to` slot, which
    // the precedence above makes part of the rule rather than a property of
    // this line's position. An operative grant is REVOKED. Anything else the
    // earlier-record set holds — a grant already withdrawn, a revocation, a
    // record of neither kind — is named to no effect, and the record naming
    // it NEVER reaches the fresh-grant arm: that fall-through is what made a
    // retried revoke a grant over a link address.
    if prev.holds_earlier(&from, home) {
        if prev.is_operative(&from) {
            return Kind::Revoke { revoked: from };
        }
        return Kind::Neither;
    }
    // Otherwise a fresh grant, and only over a prefix a grant can cover.
    if !on_the_ladder(&from) {
        return Kind::Neither; // neither a document nor an account
    }
    // `to` empty ⟹ ANY-PRINCIPAL, exactly one address ⟹ the grantee, anything
    // else ⟹ malformed.
    let grantee = if value.to_slot().is_empty() {
        None
    } else {
        let Some(grantee) = value.to_slot().single_denoted() else {
            return Kind::Neither; // a multi-address `to` is malformed
        };
        let Ok(grantee) = validate(grantee.clone()) else {
            return Kind::Neither;
        };
        Some(grantee)
    };
    Kind::Grant { content_prefix: from, grantee }
}

/// The shared fold core: the grant fold after the link `(addr, value)` has
/// been applied to the store. Both [`fold`] (per journal record) and [`seed`]
/// (the whole-map load pass) drive this ONE path, and [`Grants::take_pair`]
/// beside it, so the seed reproduces the fold. Only a `t_grant` deposit that
/// ADMITS moves the fold here; a `replaces` link moves it through the pair's
/// step.
///
/// The accumulator arrives OWNED because that is what both callers have: the
/// seed threads its own across the walk, and the fold gives a clone of the
/// world's. The two paths that move nothing hand it straight back, so a link
/// deposit that is no admitted record of the class — which is nearly all of
/// them — costs no copy at all; an admitted one is taken by
/// [`Grants::take_admitted`], whatever its kind.
///
/// The link address arrives owned for the same reason — each caller owns the
/// address it hands over and drops it on return — and because the fold KEEPS
/// it: every admitted record joins the earlier-record set under its own
/// address, so a revocation or a record of neither kind is kept without a
/// copy, and only a GRANT, which the operative set keys under that address
/// too, costs one. [`fold`] builds that address only for a deposit whose type
/// slot names the class, so every other deposit pays neither the copy nor the
/// T4 walk.
fn fold_one(
    prev: Grants,
    namespace: &M3State,
    drafts: &Drafts,
    addr: Address,
    value: &Link,
) -> Grants {
    if !is_typed(value, t_grant()) {
        return prev;
    }
    // A link address is ELEMENT-LEVEL, so it has a home document — M7's own
    // hint fold asserts exactly this of every stored link key, so a record
    // that failed it is a store already corrupt. Skipping it instead would
    // lose a grant or a revocation on one path and not the other, and the two
    // halves would part at the next restart with nothing looking wrong.
    let home = document_of(&addr)
        .expect("a link address is element-level, so its home document exists");
    let Some(issuer) = admitted_issuer(namespace, drafts, &home) else {
        return prev; // unadmitted: neither grant nor revocation
    };
    let mut next = prev;
    next.take_admitted(addr, home, issuer, value);
    next
}

/// The FOLD half (PUB-7.7): the grant fold after `rec` has been applied to the
/// link store. `rec` is the journal record just folded; `namespace`/`drafts`
/// are the world's slices as of this commit (a link deposit changes neither,
/// so both are the authoritative state a query would read).
///
/// ONLY A DEPOSIT moves the fold, and that is a premise [`seed`] rests on
/// rather than a convenience. `LinkRec` is `#[non_exhaustive]`, so the
/// `let … else` return absorbs every variant M7 has not written yet — and the
/// two halves read a link's slots from different places: this one from the
/// value the journal record carries, the seed from `readlink` at the end of
/// history. Those are the same value because M7's model has no update and no
/// delete: every write is a deposit of an immutable link at a fresh address,
/// and `editlink` deposits a successor rather than touching its original. A
/// journal record that changed a resident link's slots would split the
/// halves, and it would have to be answered here.
///
/// TWO TYPES move it: a `t_grant` record, through [`fold_one`], and a
/// [`t_replaces`] link, through [`Grants::take_pair`] — the second only while
/// some home holds an unpaired would-be grant for it to be the pair of.
pub(crate) fn fold(prev: &Grants, namespace: &M3State, drafts: &Drafts, rec: &LinkRec) -> Grants {
    let LinkRec::Deposit { addr, value, .. } = rec else {
        return prev.clone();
    };
    // Nearly every deposit is no record of the class and no pair, and its
    // type slot says so in one read apiece. The owned address below exists
    // only for the two steps to read and KEEP, so it is built for those two
    // types alone; `fold_one` asks the grant type again, which is what keeps
    // it the ONE path the seed drives too.
    let grant = is_typed(value, t_grant());
    let pair = !grant && is_typed(value, t_replaces()) && !prev.unpaired.is_empty();
    if !grant && !pair {
        return prev.clone();
    }
    // T4 VALIDITY is M7's own totality domain for a staged link address, and
    // `World::apply` has already run `LinkState::apply_link` over this very
    // journal record, whose hint fold asserts it — so by the time this line
    // runs the question is settled, twice over. Answering it a third time by
    // returning the previous fold would silently drop a grant the store did
    // accept.
    let link_addr = validate(addr.clone())
        .expect("a staged link address is T4-valid (M7's fold asserted it a moment ago)");
    if grant {
        return fold_one(prev.clone(), namespace, drafts, link_addr, value);
    }
    let mut next = prev.clone();
    next.take_pair(&link_addr, value);
    next
}

/// The SEED half (PUB-7.7): the grant fold a from-scratch walk of the GRANTS
/// class yields. Runs at load, before replay; the fold carries it forward.
///
/// PRECONDITIONS, owed by the caller and uncheckable here, each the far side
/// of an edge `World::rebuild_derived` states with the test that watches it:
/// `links` has been through `LinkState::rebuild_derived` — over unrebuilt
/// links the class reads empty and the seed admits nothing — and `drafts` is
/// the exception set seeded from this same `namespace` — an empty set reads
/// every home published and admits a draft-homed grant the fold refused.
/// `World::rebuild_derived`, the one caller, discharges both by its order.
///
/// The enumeration is the EXISTING M7 read `LinkState::type_slice` over
/// `enc([t_grant])` under `View::Audit` (every deposit ever, in address
/// order), plus `readlink` per address — NO new store read is added (the fence
/// asked which read the seed uses; this is it). Within one home, addresses are
/// ordinal-ordered = deposit-ordered, so a revocation is always processed
/// after the grant it names, the earlier-record set holds at each record's
/// turn exactly the records of its home the fold's held, and the seed
/// reproduces the fold. ACROSS homes the walk's order is not the deposits',
/// and the classification cannot tell: the set is asked of one home at a time
/// ([`Grants::holds_earlier`]), a key's population is one home's, and the
/// unpaired map is per home, so another home's records, early or late, answer
/// nothing.
///
/// THE PAIR, read where the live fold met it: after each record, a second
/// `readlink` at the record's own NEXT link address, and where a
/// [`t_replaces`] link sits there, the pair's step — so the seed takes the
/// record's two turns in the order its transaction put them. The live fold
/// meets that link as its home's next deposit, and the seed reads the one
/// address that deposit took, so the two halves decide on one link.
///
/// `type_slice` carries a stated PRECONDITION on its class — address-denoting
/// or `iextent`-built, else it panics naming it — discharged where the class
/// is built, on this function's first line: `enc` spans each address's own
/// subtree, so an `enc` over the validated [`t_grant`] pin denotes exactly
/// that address, by construction rather than by a check.
///
/// The AUDIT view is REQUIRED, not merely available. Revocation is by
/// supersession (PUB-5.13) and [`fold`] has no nullification arm, so a grant
/// whose link a later `nullify` retracted is still in the live fold and still
/// opens what it granted. An active-view seed would drop exactly those, and
/// the two halves would part at the next restart.
///
/// The halves also read the world at different TIMES: [`fold`] is handed M3
/// and the exception set as of the deposit's own commit, this walk as of the
/// end of history. [`admitted_issuer`]'s three questions answer alike at
/// both, each for its own reason. The BIT: M3 writes it once, at the journal
/// record that registers the document, and the exception set only ever GAINS
/// entries — so a home published when its grant landed is published still,
/// and a draft-homed one was unadmitted at both readings. The OWNER: the seat
/// at the home's own account, which M3 writes in the transaction that
/// allocates that account — before any document in it exists — and never
/// replaces (O12/O13), so no later delegation moves it. The DOC-1 test is
/// `first_document_address`, a pure function of the issuer and of no state at
/// all. A store change that made any of the three time-varying splits the
/// halves, and `Engine::check_hints` is where that shows.
///
/// SEED COST, per load and per `Engine::world_at` reconstruction, and sized
/// by the grants class rather than by anything a caller names: one
/// `type_slice` over that class under the audit view, then per member two
/// `readlink`s — the member's own and its next address's, where a pair would
/// sit — and one [`fold_one`]. Every grant-typed member whose home is
/// PUBLISHED — admitted or not, since the doc-1 test follows it — pays
/// [`admitted_issuer`]'s owner lookup: M3's `account_seat`, ONE point lookup
/// in the principal registry, and never ω's walk of all of it, which would
/// make the seed the product of the class and |Π|. A member whose home
/// admits then joins the earlier-record set — one insert of its own link
/// address, whatever its kind; one that is a would-be GRANT replaces its
/// home's unpaired entry and, where the fourth outcome honors it, adds
/// [`Grants::admit`]'s three — one into the operative map, one into an
/// ordered index whose key is a content-prefix and whose member is an issuer,
/// one into its key's population, whose key clones the three addresses — and
/// one that is a REVOCATION adds one population insert beside its withdrawal;
/// every address a DEPOSITOR chose and none bounded by this crate. A pair,
/// where one sits, re-decides its record once. The ladder test ahead of that
/// arm copies the `from` it is asked of once ([`trunk_of`]), linear in a
/// component count the depositor chose too. So the figure is the store's,
/// grown by every grant-typed link any account has ever deposited — and, by
/// a logarithm, by every principal M3 has ever seated — and never shrunk: a
/// revocation adds a record to the class rather than removing one, and a
/// `nullify` leaves the claim in the audit view this walk must read.
/// `crate::publication::seed` states the exception set's own figure, and
/// both run inside `WorldState::rebuild_derived` — the term M2's
/// `Kernel::world_at` names in its cost and cannot size itself.
pub(crate) fn seed(namespace: &M3State, links: &LinkState, drafts: &Drafts) -> Grants {
    let ty = skep_links::enc([t_grant()]);
    let mut grants = Grants::new();
    for addr in links.type_slice(&ty, View::Audit) {
        // RESIDENCY is M7's stated postcondition on `type_slice`, and M7
        // fail-stops on it itself (`LinkState::link_at`). Skipping the entry
        // instead would drop a grant — or, worse, a REVOCATION — from the
        // seed alone, so the recovered fold would open at the next restart
        // what the live fold had closed.
        let value = links
            .readlink(&addr)
            .expect("a type_slice key names a resident link (M7's postcondition)");
        // The record's next link address — where its own transaction put its
        // pair, if it has one. `inc` at the last component keeps T4 for every
        // address (TA5a admits k = 0 always).
        let next = checked_inc(&addr, 0).expect("inc at the last component preserves T4");
        grants = fold_one(grants, namespace, drafts, addr, value);
        if let Some(pair) = links.readlink(&next).filter(|pair| is_typed(pair, t_replaces())) {
            grants.take_pair(&next, pair);
        }
    }
    grants
}

#[cfg(test)]
mod tests;
