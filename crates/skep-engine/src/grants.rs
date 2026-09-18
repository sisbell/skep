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
//! shape, so [`classify`] tells them apart — a THREE-WAY test, decided on the
//! `from` slot and on the class's own population of that home IN DEPOSIT
//! ORDER (RES-226), and total over every field it reads (RES-258):
//!
//! 1. a `from` that does not denote exactly ONE address is of NEITHER KIND;
//! 2. a `from` naming an EARLIER admitted record of the class from this same
//!    home is that record's REVOCATION where it names a grant, and of NEITHER
//!    KIND where what it names is a revocation or is itself of neither kind.
//!    A grant ALREADY withdrawn is named to no effect: the revocation is the
//!    first one, and a second is honored for nothing;
//! 3. every OTHER record is a GRANT where its `from` stands on the ladder
//!    (RES-252) and its `to` denotes one address or is empty (RES-238), and
//!    of NEITHER KIND otherwise.
//!
//! A record of NEITHER KIND enters no index and moves no honored state — the
//! malformed arm above, which is the fold's one arm for a record it ignores.
//! The key in (2) is EVERY earlier admitted record and never the operative
//! set alone, which a revoked grant has left: read off that set, a record
//! naming a withdrawn grant or a revocation names nothing the fold knows and
//! goes on to the grant arm, where the ladder alone stands between it and a
//! fresh grant over a LINK ADDRESS — universal where its `to` is empty, which
//! a blind retry of a revoke is. Two promises rest on this test, each on the
//! outcome that states it and neither on what the addresses happen to make
//! true: A RECORD THAT WITHDRAWS A SHARE NEVER BECOMES ONE, and A WITHDRAWAL,
//! ONCE HONORED, IS LIFTED BY NOTHING.
//!
//! ## Admission (I4, PUB-5.19)
//!
//! A grant record counts only as ADMITTED:
//!
//! * homed in a document its author ω-owns — the issuer's own doc 1
//!   ([`first_document_address`]`(issuer) == home`);
//! * PUBLISHED — grants are born published, so the home is a published
//!   document (an exception-set MISS);
//! * UNREVOKED — no later admitted record from that same home names it.
//!
//! Revocation is by SUPERSESSION (PUB-5.13), and the fold reads it from the
//! GRANTS class alone: a later admitted `t_grant` record whose `from` names an
//! EARLIER admitted grant's own link address revokes it (issuer alone —
//! same home ⟹ same ω owner). A deposited `assert_sup` claim is lineage
//! display, never a fold input.
//!
//! ## The query indexes
//!
//! `grant_exists(doc, p)` walks up from doc through its ancestor prefixes,
//! probing p's prefix-keyed set and the ANY-PRINCIPAL set at each. Coverage is
//! CONTAINMENT (a granted prefix that is an ancestor of doc) ∩ the grant's
//! issuer being doc's ω owner. The grantee side is PRINCIPAL-EXACT.

use std::collections::BTreeMap;

use im::{HashMap, HashSet, OrdMap, OrdSet};
use skep_address::{document_of, parent, validate, Address, Level};
use skep_arrangement::trunk_of;
use skep_links::{Link, LinkRec, LinkState, View};
use skep_namespace::{first_document_address, M3State};

use crate::publication::{is_published, Drafts};
use crate::types::t_grant;
use crate::world::World;

/// One row of the LIVE ANY-PRINCIPAL set ([`World::universal_grants`]): a
/// content-prefix, and the issuers who have granted it to every principal.
///
/// A named row rather than a pair, because the two grant enumerations are
/// TRANSPOSES of each other and every half of both is an account or a
/// document address: `(content_prefix, issuers)` here, `(issuer,
/// content_prefixes)` in [`IssuerGrant`]. Read one as the other and the types
/// still agree, so nothing refuses — a lookup keyed by the wrong half finds
/// nothing, and the term it was for goes unserved with no sign of it. The
/// field names are what make that mistake fail to compile instead.
///
/// A row BORROWS the world it was read from, as a map's own views do: the
/// read copies no address, and a caller that keeps a row past that world
/// clones what it keeps. Rows order by content-prefix, which no two rows of
/// one read share, so that order is the one the read hands them back in.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct UniversalGrant<'a> {
    /// The content-prefix granted (a document or an account address).
    pub content_prefix: &'a Address,
    /// The issuers who granted it, in address order.
    pub issuers: Vec<&'a Address>,
}

/// One row of the GRANTEE-INDEXED read ([`World::issuers_for`]): an issuer,
/// and the union of the content-prefixes that issuer has granted the queried
/// grantee. [`UniversalGrant`] is the transpose, and says why both are named
/// and what a row borrows. Rows order by issuer, which no two rows of one read
/// share, so that order is the one the read hands them back in.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct IssuerGrant<'a> {
    /// The issuing account — a draft-stream key for the grantee.
    pub issuer: &'a Address,
    /// The prefixes that issuer has granted the grantee, in address order.
    pub content_prefixes: Vec<&'a Address>,
}

impl World {
    /// THE LIVE ANY-PRINCIPAL SET, enumerable (PUB-7.22; lane 3.6 §3): every
    /// content-prefix currently covered by an admitted, unrevoked
    /// ANY-PRINCIPAL grant, with the issuers that granted it — in prefix
    /// (tumbler) order, each issuer list in address order. An INDEX SHAPE,
    /// never per-session state: the fold's universal index as rows borrowed
    /// from this world, enumerated once per request off one head snapshot by
    /// the feed's universal term (a K-way merge of these prefixes' own
    /// position-index lists, K = this list's length). Revocation is immediate
    /// here — a revoking record withdraws its grant's entry from the index at
    /// the commit that carries it — so a derivation off this read never serves
    /// withdrawn material (PUB-7.23). Reads the fold's query index, adds no
    /// fold state, and is `readable`'s own universal probe turned inside out:
    /// a document is universally granted iff one of its ancestor prefixes is
    /// listed here with its ω owner among the issuers.
    ///
    /// COST, per call, uncached, and linear in the WHOLE universal index —
    /// this read takes no argument, so there is nothing in the request to
    /// read the figure off. One vector of borrows per prefix, and no address
    /// cloned. The index's size is the DEPOSITORS' choice: every admitted
    /// ANY-PRINCIPAL grant any account issues adds an entry, so this grows
    /// with the store. Nothing is memoized, so a caller polling per request
    /// re-pays per request, and it gates neither admission nor concurrency.
    pub fn universal_grants(&self) -> Vec<UniversalGrant<'_>> {
        self.grants.universal()
    }

    /// THE GRANTEE-INDEXED READ (PUB-7.28; lane 3.6 §3): for `grantee` — a
    /// principal's account address — its ISSUERS, each with the UNION of the
    /// content-prefixes that issuer has granted it, in issuer order, each
    /// prefix list in address order. The discovery term a feed poll re-pays:
    /// grants SELECT issuer streams (PUB-7.25), so a holder of N grants from M
    /// issuers merges M streams, each under one containment test against the
    /// union this read hands back. Reads the fold's principal-exact index —
    /// `grantee` alone, never its subtree (PUB-5.5) — and adds no fold state.
    /// The ANY-PRINCIPAL grants are NOT here; they are
    /// [`World::universal_grants`], the tier's own read.
    ///
    /// COST, per call, uncached: one hash probe of the principal-exact index,
    /// then a walk of THAT grantee's whole row to invert it — one insert per
    /// (prefix, issuer) pair into an ordered map of borrows, so a logarithmic
    /// factor, and no address cloned. The row's size is neither the caller's
    /// choice nor the grantee's: any account may grant to any other, so the
    /// ISSUERS decide how much work a poll on this grantee's behalf does.
    /// Nothing is memoized, and it gates neither admission nor concurrency.
    pub fn issuers_for(&self, grantee: &Address) -> Vec<IssuerGrant<'_>> {
        self.grants.issuers_for(grantee)
    }
}

// The GRANTS class type address the fold keys on — `crate::types::t_grant`
// (`1.1.0.1.0.1.0.3.90`, COMMONS DECISION 5): pinned in `types.rs` beside
// every other commons address the engine and the daemon read as a VALUE.

/// One admitted grant record — enough to answer queries and to withdraw its
/// index entry when a later record revokes it. The fields are crate-visible
/// for the world dump's grant section (lane 3.4 §3), which renders the fold's
/// operative set through [`Grants::records`] and destructures each record
/// whole — so a field added here is a field that section must render, or the
/// faithfulness check stops speaking for the whole record.
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
/// entirely by these three fields: two admitted grants that agree on them are
/// ONE entry, and the indexes hold no count of how many named it.
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
}

/// The grant fold: the operative grant set, the two query indexes it is
/// projected into, and the earlier-record key the classification reads. All
/// `im` persistent structures, so `World::clone` on the commit path is one
/// more root clone. `#[serde(skip)]` at the World: derived, never
/// checkpointed (the module docs' hint discipline).
///
/// The set and its two indexes must agree, and [`Grants::admit`] and
/// [`Grants::withdraw`] are the only two transitions that move any of the
/// three — each doing the record edit and the index edit as ONE step. So the
/// projection this type's fields describe is performed here rather than at a
/// caller, and a fold arm that moved the set without its index would have to
/// be written past those two rather than beside them. The earlier-record key
/// stands apart from that agreement: [`Grants::keep_earlier`] is its one
/// transition, it only ever gains, and neither of the other two touches it.
#[derive(Clone, Debug, Default)]
pub(crate) struct Grants {
    /// Admitted, unrevoked grants, keyed by the grant link's OWN address —
    /// so a revoking record removes exactly the RECORD it names. What leaves
    /// the query indexes with that record is its [`GrantIndexEntry`], which
    /// is a value and which a second record can name too.
    records: HashMap<Address, GrantRecord>,
    /// THE EARLIER-RECORD KEY (PUB-5.15, RES-226): the link address of EVERY
    /// admitted record of the class, whatever [`classify`] made of it — a
    /// grant live or since withdrawn, a revocation, a record of neither kind
    /// — and never pruned. It is what `records` cannot be: [`Grants::withdraw`]
    /// takes a revoked grant OUT of that map, so a later record naming the
    /// withdrawn grant, or naming the revocation, finds nothing there, and a
    /// test keyed on it alone reads such a record as a fresh grant.
    ///
    /// A record joins AFTER its own classification ([`fold_one`]), so at any
    /// record's turn the members from its home are exactly the records that
    /// home deposited EARLIER — the deposit order the test is stable under.
    /// One set for every home: a link address names its own home
    /// ([`document_of`]), so [`Grants::holds_earlier`] asks the same-home
    /// question of the address and keeps no per-home structure.
    ///
    /// FOLD STATE like the rest, journaled nowhere and re-derived by [`seed`]
    /// off the same walk. It grows by one address per admitted record of the
    /// class and never shrinks — a revocation ADDS a record — so its size is
    /// the depositors', as the class's own is.
    earlier: HashSet<Address>,
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

    /// The operative set — every admitted, unrevoked grant with the grant
    /// link's own address — in the map's hash order (the world dump's grant
    /// section renders it, and the dump's rendering sorts a map's entries).
    /// The fold's one enumeration; the predicate's consumers are the point
    /// probes above.
    pub(crate) fn records(&self) -> impl Iterator<Item = (&Address, &GrantRecord)> + '_ {
        self.records.iter()
    }

    /// `grant_exists(doc, p)` (PUB-1.32's third clause): does some admitted
    /// grant cover `doc` for principal-account `grantee`, issued by doc's ω
    /// owner? Coverage = CONTAINMENT (a granted prefix ⊑ doc) ∩ the grant's
    /// issuer is `owner`. One probe of the principal-exact index (when there
    /// is a grantee) and one of the ANY-PRINCIPAL index at each ancestor,
    /// `doc` itself included.
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
    pub(crate) fn universal(&self) -> Vec<UniversalGrant<'_>> {
        self.universal
            .iter()
            .map(|(content_prefix, issuers)| UniversalGrant {
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
    pub(crate) fn issuers_for(&self, grantee: &Address) -> Vec<IssuerGrant<'_>> {
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
            .map(|(issuer, content_prefixes)| IssuerGrant { issuer, content_prefixes })
            .collect()
    }

    /// ADMIT `grant`, deposited at link address `addr`: it joins the operative
    /// set under its own address and its [`GrantIndexEntry`] joins the query
    /// index that entry names. One transition, so the set and its projection
    /// cannot part. [`admitted_issuer`] is the test this acts on.
    fn admit(&mut self, addr: Address, grant: GrantRecord) {
        self.index_add(grant.index_entry());
        self.records.insert(addr, grant);
    }

    /// WITHDRAW the grant deposited at `addr`: it leaves the operative set and
    /// its [`GrantIndexEntry`] leaves the query index it was added to. One
    /// transition, and one lookup, since the removal hands the record back.
    /// Naming no admitted grant is a no-op.
    ///
    /// The indexes are SETS and hold no count, so an entry is withdrawn by the
    /// first record that names it: where two admitted grants share an entry —
    /// one issuer, one content-prefix, one grantee — withdrawing either takes
    /// the entry both contributed, while the other record stays in the
    /// operative set the dump's grant section renders.
    fn withdraw(&mut self, addr: &Address) {
        if let Some(grant) = self.records.remove(addr) {
            self.index_remove(grant.index_entry());
        }
    }

    /// KEEP the admitted record deposited at `addr` as an EARLIER one to every
    /// record that follows it — the earlier-record key's one transition, taken
    /// for every admitted record of the class whatever its kind, and undone by
    /// nothing: a withdrawn grant stays a member, which is the point of it.
    fn keep_earlier(&mut self, addr: Address) {
        self.earlier.insert(addr);
    }

    /// Whether `addr` is the link address of an EARLIER admitted record of the
    /// class homed in `home` — the key PUB-5.15's second outcome decides on.
    /// EARLIER is the set's own invariant (a record joins after its turn), and
    /// SAME HOME is read off the address: a record is homed in the document
    /// its link address lies in, which is how [`fold_one`] derives every
    /// record's home. Same home ⟹ same ω owner is the whole of the issuer
    /// restriction (PUB-5.13), so a record naming ANOTHER home's member is
    /// not answered here. The probe runs first, so an address that names no
    /// record — nearly every `from` there is — costs no arithmetic at all.
    fn holds_earlier(&self, addr: &Address, home: &Address) -> bool {
        self.earlier.contains(addr) && document_of(addr).as_ref() == Some(home)
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
/// must never take an input from. Revocation is by supersession (PUB-5.13),
/// and that is exactly why the two need two words here.
enum Kind {
    /// A fresh grant of `content_prefix` — a document or an account — to
    /// `grantee` (`None` = ANY-PRINCIPAL).
    Grant { content_prefix: Address, grantee: Option<Address> },
    /// A revocation naming an EARLIER admitted grant's link address, the grant
    /// still operative. Decided off the `from` slot ALONE, so this arm's `to`
    /// slot is never read and carries no meaning: a revoking record revokes
    /// whatever its `to` holds.
    Revoke { revoked: Address },
    /// A record of NEITHER KIND (PUB-5.15) — the one fail-closed arm, whatever
    /// put the record there: a `from` denoting no address, several, or one M1
    /// refuses; a `from` naming an earlier record of this home that is no
    /// operative grant — a grant already withdrawn, a revocation, or a record
    /// itself of neither kind; a `from` standing on neither rung of the
    /// ladder; or, on the fresh-grant arm, a `to` denoting more than one. The
    /// fold enters it in no index and moves no honored state by it, so a
    /// malformed grant grants to nobody and a malformed revocation lifts
    /// nothing.
    Malformed,
}

/// Whether a link value is a `t_grant`-typed record — denotation equality on
/// the type slot (the fold keys on `t_grant` as a VALUE, never through M7's
/// registry).
fn is_grant_typed(value: &Link, grants_class: &Address) -> bool {
    value.type_slot().single_denoted() == Some(grants_class.tumbler())
}

/// Admission (I4), asked of a record's home: the ISSUER (ω of `home`) where
/// the home is that issuer's OWN doc 1 and PUBLISHED, else `None`. A QUERY,
/// which is why it is named for its answer — [`Grants::admit`] is the
/// transition that acts on it.
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
    // The issuer — ω of the home, an account.
    let issuer = namespace.effective_owner_prefix(home)?.clone();
    // The home is the issuer's own doc 1.
    if first_document_address(&issuer).as_ref() != Some(home) {
        return None;
    }
    Some(issuer)
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

/// Classify one admitted `t_grant` record — PUB-5.15's three-way test, in its
/// own order (the module docs state it whole): a `from` that does not denote
/// exactly one address is of NEITHER KIND; a `from` naming an EARLIER admitted
/// record of this home is a REVOCATION where that record is an operative
/// grant and of NEITHER KIND where it is anything else; every other record is
/// a fresh GRANT where its `from` stands on the ladder and its `to` is the
/// grantee (empty ⟹ ANY-PRINCIPAL), and of NEITHER KIND otherwise.
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
/// nothing is held by the key it is stated over, and stays held under a
/// ladder that one day gains a rung.
///
/// Every slot this DOES read is read for exactly one denoted address: the
/// type slot at [`is_grant_typed`] before this is called, `from` always, and
/// `to` on the fresh-grant arm alone. A slot denoting several, or a `from`
/// denoting none or one M1 refuses, is [`Kind::Malformed`] — the fail-closed
/// direction, since a record naming two grantees grants to neither.
fn classify(prev: &Grants, home: &Address, value: &Link) -> Kind {
    let Some(from) = value.from_slot().single_denoted() else {
        return Kind::Malformed; // `from` must denote exactly one address
    };
    let Ok(from) = validate(from.clone()) else {
        return Kind::Malformed;
    };
    // A `from` naming an EARLIER admitted record of THIS home is decided HERE
    // and by nothing below — ahead of the ladder and of the `to` slot, which
    // the precedence above makes part of the rule rather than a property of
    // this line's position. An operative grant is REVOKED. Anything else the
    // key holds — a grant already withdrawn, a revocation, a record of neither
    // kind — is named to no effect, and the record naming it NEVER reaches the
    // fresh-grant arm: that fall-through is what made a retried revoke a grant
    // over a link address.
    if prev.holds_earlier(&from, home) {
        if prev.records.contains_key(&from) {
            return Kind::Revoke { revoked: from };
        }
        return Kind::Malformed;
    }
    // Otherwise a fresh grant, and only over a prefix a grant can cover.
    if !on_the_ladder(&from) {
        return Kind::Malformed; // neither a document nor an account
    }
    // `to` empty ⟹ ANY-PRINCIPAL, exactly one address ⟹ the grantee, anything
    // else ⟹ malformed.
    let grantee = if value.to_slot().is_empty() {
        None
    } else {
        let Some(grantee) = value.to_slot().single_denoted() else {
            return Kind::Malformed; // a multi-address `to` is malformed
        };
        let Ok(grantee) = validate(grantee.clone()) else {
            return Kind::Malformed;
        };
        Some(grantee)
    };
    Kind::Grant { content_prefix: from, grantee }
}

/// The shared fold core: the grant fold after the link `(addr, value)` has
/// been applied to the store. Both [`fold`] (per journal record) and [`seed`]
/// (the whole-map load pass) drive this ONE path, so the seed reproduces the
/// fold. Only a `t_grant` deposit that ADMITS moves the fold.
///
/// The accumulator arrives OWNED because that is what both callers have: the
/// seed threads its own across the walk, and the fold gives a clone of the
/// world's. The two paths that move nothing hand it straight back, so a link
/// deposit that is no admitted record of the class — which is nearly all of
/// them — costs no copy at all. [`classify`] reads it before the move, since
/// a revocation is recognized by the operative set it is about to leave, and
/// an earlier record by the key this one has not yet joined.
///
/// EVERY admitted record of the class moves the fold by one step at least:
/// whatever its kind, it joins the earlier-record key — after its own
/// classification, so a record naming its own address names no earlier one. A
/// record of NEITHER KIND moves that key and nothing else, which is what lets
/// the next record naming IT be answered as PUB-5.15's second outcome states.
fn fold_one(
    prev: Grants,
    namespace: &M3State,
    drafts: &Drafts,
    addr: &Address,
    value: &Link,
) -> Grants {
    if !is_grant_typed(value, t_grant()) {
        return prev;
    }
    // A link address is ELEMENT-LEVEL, so it has a home document — M7's own
    // hint fold asserts exactly this of every stored link key, so a record
    // that failed it is a store already corrupt. Skipping it instead would
    // lose a grant or a revocation on one path and not the other, and the two
    // halves would part at the next restart with nothing looking wrong.
    let home = document_of(addr)
        .expect("a link address is element-level, so its home document exists");
    let Some(issuer) = admitted_issuer(namespace, drafts, &home) else {
        return prev; // unadmitted: neither grant nor revocation
    };
    let kind = classify(&prev, &home, value);
    let mut next = prev;
    match kind {
        Kind::Grant { content_prefix, grantee } => {
            next.admit(addr.clone(), GrantRecord { home, issuer, content_prefix, grantee });
        }
        Kind::Revoke { revoked } => next.withdraw(&revoked),
        Kind::Malformed => {}
    }
    next.keep_earlier(addr.clone());
    next
}

/// The FOLD half (PUB-7.7): the grant fold after `rec` has been applied to the
/// link store. `rec` is the record just folded; `namespace`/`drafts` are the
/// world's slices as of this commit (a link deposit changes neither, so both
/// are the authoritative state a query would read).
///
/// ONLY A DEPOSIT moves the fold, and that is a premise [`seed`] rests on
/// rather than a convenience. `LinkRec` is `#[non_exhaustive]`, so the early
/// return absorbs every variant M7 has not written yet — and the two halves
/// read a link's slots from different places: this one from the value the
/// record carries, the seed from `readlink` at the end of history. Those are
/// the same value because M7's model has no update and no delete: every write
/// is a deposit of an immutable link at a fresh address, and `editlink`
/// deposits a successor rather than touching its original. A record that
/// changed a resident link's slots would split the halves, and it would have
/// to be answered here.
pub(crate) fn fold(prev: &Grants, namespace: &M3State, drafts: &Drafts, rec: &LinkRec) -> Grants {
    let LinkRec::Deposit { addr, value, .. } = rec else {
        return prev.clone();
    };
    // T4 VALIDITY is M7's own totality domain for a staged link address, and
    // `World::apply` has already run `LinkState::apply_link` over this very
    // record, whose hint fold asserts it — so by the time this line runs the
    // question is settled, twice over. Answering it a third time by returning
    // the previous fold would silently drop a grant the store did accept.
    let link_addr = validate(addr.clone())
        .expect("a staged link address is T4-valid (M7's fold asserted it a moment ago)");
    fold_one(prev.clone(), namespace, drafts, &link_addr, value)
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
/// after the grant it names, the earlier-record key holds at each record's
/// turn exactly the records of its home the fold's held, and the seed
/// reproduces the fold. ACROSS homes the walk's order is not the deposits',
/// and the classification cannot tell: the key is asked of one home at a time
/// ([`Grants::holds_earlier`]), so another home's members, early or late,
/// answer nothing.
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
/// both, each for its own reason. The BIT: M3 writes it once, at the record
/// that registers the document, and the exception set only ever GAINS
/// entries — so a home published when its grant landed is published still,
/// and a draft-homed one was unadmitted at both readings. The OWNER: no
/// account-tier prefix longer than a document's own account can cover it
/// (`crate::publication`'s `owner_account_of` states M3's half of that), so
/// no later delegation moves ω of a home. The DOC-1 test is
/// `first_document_address`, a pure function of the issuer and of no state at
/// all. A store change that made any of the three time-varying splits the
/// halves, and `Engine::check_hints` is where that shows.
///
/// SEED COST, per load and per `Engine::world_at` reconstruction, and the
/// PRODUCT of the grants class and M3's principal registry rather than
/// anything a caller names: one `type_slice` over that class under the audit
/// view, then per member one `readlink` and one [`fold_one`]. Every
/// grant-typed member whose home is PUBLISHED — admitted or not, since the
/// doc-1 test follows it — pays [`admitted_issuer`]'s ω resolution, M3's walk
/// of the WHOLE principal registry, so the seed is Θ(members · |Π|) wherever
/// the members are published-homed, which a depositor's own doc 1 is. A
/// member whose home admits then joins the earlier-record key — one insert of
/// its own link address, whatever its kind — and one that is a GRANT adds
/// [`Grants::admit`]'s two besides — one into the operative map, one into an
/// ordered index whose key is a content-prefix and whose member is an issuer,
/// both addresses a DEPOSITOR chose and neither bounded by this crate. The
/// ladder test ahead of that arm copies the `from` it is asked of once
/// ([`trunk_of`]), linear in a component count the depositor chose too. So
/// the figure is the store's, grown by every grant-typed link any account has
/// ever deposited and by every principal M3 has ever seated, and never
/// shrunk: a revocation adds a record to the class rather than removing one,
/// and a `nullify` leaves the claim in the audit view this walk must read.
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
        grants = fold_one(grants, namespace, drafts, &addr, value);
    }
    grants
}

#[cfg(test)]
mod tests {
    use skep_arrangement::Caller;
    use skep_links::SlotArg;

    use crate::testkit::{addr, delegated_account, element, mem_engine, USER};
    use crate::Engine;

    use super::*;

    /// [`USER`]'s account with its published doc 1 — the one home its records
    /// of the class admit from — and a later private draft: `(home, draft)`.
    fn a_home_and_a_draft(engine: &Engine) -> (Address, Address) {
        let acct = delegated_account(engine, USER);
        let (home, _) =
            engine.namespace().create_new_document(USER, &acct, None).expect("the home mint");
        let (draft, _) = engine
            .namespace()
            .create_new_document(USER, &acct, None)
            .expect("a later mint, private");
        (home, draft)
    }

    /// Deposit a record of the class in `home`, as [`USER`], with `from` its
    /// one `from` address and an EMPTY `to`. Returns the record's address.
    fn record(engine: &Engine, home: &Address, from: &Address) -> Address {
        let caller = Caller::Principal(USER);
        engine
            .linkstore(&World::visible_to(caller))
            .makelink(
                caller,
                home,
                SlotArg::Addrs(vec![from.clone()]),
                SlotArg::Addrs(vec![]),
                SlotArg::Addrs(vec![t_grant().clone()]),
            )
            .expect("the record deposits into the issuer's own doc 1")
            .0
    }

    /// THE EARLIER-RECORD KEY, held on its own. Every record the key sends to
    /// NEITHER KIND sits at a link address, which the ladder refuses as well,
    /// so no answer of the predicate can tell a fold that kept the key from
    /// one that leaned on the ladder — and the promise the key carries must
    /// not rest on that overlap ([`classify`]). So the key is asked directly:
    /// it keeps the grant the operative set let go, the revocation, and a
    /// record of neither kind; it answers for their own home alone; and the
    /// seed rebuilds it whole, since nothing journals it.
    #[test]
    fn the_earlier_record_key_keeps_what_the_operative_set_lets_go() {
        let engine = mem_engine();
        let (home, draft) = a_home_and_a_draft(&engine);
        let grant = record(&engine, &home, &draft);
        let revocation = record(&engine, &home, &grant);
        let neither = record(&engine, &home, &addr(&[1])); // the node stands on neither rung

        let snap = engine.kernel().snapshot();
        let world = snap.world();
        assert!(
            world.grants.records.is_empty(),
            "the premise: the operative set has let the revoked grant go, and held nothing else"
        );
        let members = [
            ("the withdrawn grant", &grant),
            ("the revocation", &revocation),
            ("the record of neither kind", &neither),
        ];
        for (what, member) in members {
            assert!(world.grants.holds_earlier(member, &home), "{what} is an earlier record");
            assert!(!world.grants.holds_earlier(member, &draft), "{what}: of its own home alone");
        }
        assert!(
            !world.grants.holds_earlier(&element(&home, 2, 99), &home),
            "an address of this home that no record occupies is no member"
        );
        let seeded = seed(&world.namespace, &world.links, &world.drafts);
        assert_eq!(seeded.earlier, world.grants.earlier, "the seed rebuilds the key the fold kept");
        assert_eq!(seeded.earlier.len(), members.len(), "…one member per admitted record");
    }

    /// …and [`classify`] CONSULTS the key AHEAD of the ladder, which no state
    /// the store can reach will show: every record of the class sits at a link
    /// address, and the ladder refuses those on its own. So the key here is
    /// SYNTHETIC — it holds a DOCUMENT address, as though a record of the
    /// class sat on a rung — which is the one shape where the two tests part.
    /// The ladder admits that `from`; the earlier-record test, speaking first,
    /// sends the record naming it to NEITHER KIND. A classification that
    /// dropped the consultation, or ran it after the ladder's arm, answers a
    /// fresh grant here. That is the precedence PUB-5.15's second promise
    /// rests on, pinned where a ladder that gained a rung would otherwise be
    /// the first thing to test it.
    #[test]
    fn the_earlier_record_test_speaks_before_the_ladder() {
        let engine = mem_engine();
        let (home, _) = a_home_and_a_draft(&engine);
        let naming_the_home = record(&engine, &home, &home);
        let snap = engine.kernel().snapshot();
        let link = snap.world().links.readlink(&naming_the_home).expect("the record is resident");

        assert!(
            matches!(classify(&Grants::new(), &home, link), Kind::Grant { .. }),
            "the premise: asked alone, the ladder admits a `from` at a document"
        );
        let mut keyed = Grants::new();
        keyed.keep_earlier(home.clone());
        assert!(keyed.holds_earlier(&home, &home), "the synthetic member answers for its own home");
        assert!(
            matches!(classify(&keyed, &home, link), Kind::Malformed),
            "a `from` naming an earlier record that is no operative grant reached the grant arm"
        );
    }
}
