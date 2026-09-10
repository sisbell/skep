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
//! recognized by the fold — never by M7's `TypeRegistry` — as a VALUE:
//!
//! * type slot denotes [`t_grant`] — the GRANTS class (COMMONS DECISION 5);
//! * `from` slot denotes the CONTENT-PREFIX shared (a document or an account);
//! * `to` slot denotes the GRANTEE (a principal's account), or is EMPTY for
//!   the ANY-PRINCIPAL form (PUB-5.8).
//!
//! ## Admission (I4, PUB-5.19)
//!
//! A grant record counts only as ADMITTED:
//!
//! * homed in a document its author ω-owns — the issuer's own doc 1
//!   ([`first_document_address`]`(issuer) == home`);
//! * PUBLISHED — grants are born published, so the home is a published
//!   document (an exception-set MISS);
//! * UNSUPERSEDED — no later admitted record from that same home names it.
//!
//! Revocation is by SUPERSESSION (PUB-5.13), and the fold reads it from the
//! GRANTS class alone: a later admitted `t_grant` record whose `from` names an
//! EARLIER admitted grant's own link address supersedes it (issuer alone —
//! same home ⟹ same ω owner). A deposited `assert_sup` claim is lineage
//! display, never a fold input.
//!
//! ## The query indexes
//!
//! `grant_exists(doc, p)` tests doc's O(depth) ancestor prefixes in p's
//! prefix-keyed set, plus one probe of the ANY-PRINCIPAL set. Coverage is
//! CONTAINMENT (a granted prefix that is an ancestor of doc) ∩ the grant's
//! issuer being doc's ω owner. The grantee side is PRINCIPAL-EXACT.

use im::{HashMap, OrdMap, OrdSet};
use skep_address::{document_of, parent, validate, Address};
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UniversalGrant {
    /// The content-prefix granted (a document or an account address).
    pub content_prefix: Address,
    /// The issuers who granted it, in address order.
    pub issuers: Vec<Address>,
}

/// One row of the GRANTEE-INDEXED read ([`World::issuers_for`]): an issuer,
/// and the union of the content-prefixes that issuer has granted the queried
/// grantee. [`UniversalGrant`] is the transpose, and says why both are named.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssuerGrant {
    /// The issuing account — a draft-stream key for the grantee.
    pub issuer: Address,
    /// The prefixes that issuer has granted the grantee, in address order.
    pub content_prefixes: Vec<Address>,
}

impl World {
    /// THE LIVE ANY-PRINCIPAL SET, enumerable (PUB-7.22; lane 3.6 §3): every
    /// content-prefix currently covered by an admitted, unsuperseded
    /// ANY-PRINCIPAL grant, with the issuers that granted it — in prefix
    /// (tumbler) order, each issuer list in address order. An INDEX SHAPE,
    /// never per-session state: the fold's universal index rendered as owned
    /// values, enumerated once per request off one head snapshot by the feed's
    /// universal term (a K-way merge of these prefixes' own position-index
    /// lists, K = this list's length). Revocation is immediate here — a
    /// revoking record withdraws its grant's entry from the index at the
    /// commit that carries it — so a derivation off this read never serves
    /// withdrawn material (PUB-7.23). Reads the fold's query index, adds no
    /// fold state, and is `readable`'s own universal probe turned inside out:
    /// a document is universally granted iff one of its ancestor prefixes is
    /// listed here with its ω owner among the issuers.
    ///
    /// COST, per call, uncached, and linear in the WHOLE universal index —
    /// this read takes no argument, so there is nothing in the request to
    /// read the figure off. One address clone per (prefix, issuer) pair, and
    /// an address clone is a vector plus an allocation per component. The
    /// index's size is the DEPOSITORS' choice: every admitted ANY-PRINCIPAL
    /// grant any account issues adds an entry, so this grows with the store.
    /// Nothing is memoized, so a caller polling per request re-pays per
    /// request, and it gates neither admission nor concurrency.
    pub fn universal_grants(&self) -> Vec<UniversalGrant> {
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
    /// then a walk of THAT grantee's whole row to invert it — one address
    /// clone per (prefix, issuer) pair on the way in and one on the way out,
    /// through an ordered map, so a logarithmic factor with them. The row's
    /// size is neither the caller's choice nor the grantee's: any account may
    /// grant to any other, so the ISSUERS decide how much work a poll on this
    /// grantee's behalf does. Nothing is memoized, and it gates neither
    /// admission nor concurrency.
    pub fn issuers_for(&self, grantee: &Address) -> Vec<IssuerGrant> {
        self.grants.issuers_for(grantee)
    }
}

// The GRANTS class type address the fold keys on — `crate::types::t_grant`
// (`1.1.0.1.0.1.0.3.90`, COMMONS DECISION 5): pinned in `types.rs` beside
// every other commons address the engine and the daemon read as a VALUE.

/// One admitted grant record — enough to answer queries and to withdraw its
/// index entry when a later record revokes it. The fields are crate-visible
/// for the world dump's grant section (lane 3.4 §3), which renders the fold's
/// operative set through [`Grants::records`].
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

/// The grant fold: the operative grant set, plus the two query indexes it is
/// projected into. All `im` persistent structures, so `World::clone` on the
/// commit path is one more root clone. `#[serde(skip)]` at the World: derived,
/// never checkpointed (the module docs' hint discipline).
///
/// The three structures must agree, and [`Grants::admit`] and
/// [`Grants::withdraw`] are the only two transitions that move any of them —
/// each doing the record edit and the index edit as ONE step. So the
/// projection this type's fields describe is performed here rather than at a
/// caller, and a fold arm that moved the set without its index would have to
/// be written past those two rather than beside them.
#[derive(Clone, Debug, Default)]
pub(crate) struct Grants {
    /// Admitted, unsuperseded grants, keyed by the grant link's OWN address —
    /// so a revoking record removes exactly the RECORD it names. What leaves
    /// the query indexes with that record is its [`GrantIndexEntry`], which
    /// is a value and which a second record can name too.
    records: HashMap<Address, GrantRecord>,
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
// the index a [`GrantIndexEntry`] belongs in and hand it here, and
// [`Grants::issuers_for`]'s inversion builds a third map of that same shape.
// The decision at those sites is which index; the bookkeeping is here.
//
// That ONE shape is why the two below are spelled concretely rather than over
// a key and a member type: every map they edit is a map of addresses to sets
// of addresses, and a signature that admitted a second pairing would be
// claiming a generality the fold has no use for. What the two sides MEAN
// differs by index — prefix to issuers one way, issuer to prefixes the other
// — and no type could carry that, which is what the named [`UniversalGrant`]
// and [`IssuerGrant`] rows exist to say at the surface.

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

    /// The operative set — every admitted, unsuperseded grant with the grant
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
    /// issuer is `owner`. O(depth) ancestor probes, plus one universal probe.
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
        let mut anc: Option<Address> = Some(doc.clone());
        while let Some(a) = anc {
            if let Some(g) = grantee {
                if self
                    .by_grantee
                    .get(g)
                    .and_then(|prefixes| prefixes.get(&a))
                    .is_some_and(|issuers| issuers.contains(owner))
                {
                    return true;
                }
            }
            if self.universal.get(&a).is_some_and(|issuers| issuers.contains(owner)) {
                return true;
            }
            anc = parent(&a);
        }
        false
    }

    /// The ANY-PRINCIPAL index as owned rows, in the `OrdMap`'s key order —
    /// tumbler order — each issuer list in address order.
    /// [`World::universal_grants`] is the public face.
    pub(crate) fn universal(&self) -> Vec<UniversalGrant> {
        self.universal
            .iter()
            .map(|(prefix, issuers)| UniversalGrant {
                content_prefix: prefix.clone(),
                issuers: issuers.iter().cloned().collect(),
            })
            .collect()
    }

    /// The principal-exact index for one grantee, INVERTED: `by_grantee` keys
    /// prefix → issuers (the shape `grant_exists`'s O(depth) probe wants);
    /// the feed wants issuer → the union of that issuer's prefixes (the shape
    /// its per-issuer stream test wants). Both orders are the `OrdMap`s' —
    /// deterministic. [`World::issuers_for`] is the public face.
    pub(crate) fn issuers_for(&self, grantee: &Address) -> Vec<IssuerGrant> {
        let mut by_issuer: OrdMap<Address, OrdSet<Address>> = OrdMap::new();
        if let Some(prefixes) = self.by_grantee.get(grantee) {
            for (prefix, issuers) in prefixes.iter() {
                for issuer in issuers.iter() {
                    set_insert(&mut by_issuer, issuer, prefix.clone());
                }
            }
        }
        by_issuer
            .iter()
            .map(|(issuer, covered)| IssuerGrant {
                issuer: issuer.clone(),
                content_prefixes: covered.iter().cloned().collect(),
            })
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

    /// [`Grants::admit`]'s index step: add `entry` to the query index its
    /// grantee names — the PRINCIPAL-EXACT one keyed by the grantee, or the
    /// ANY-PRINCIPAL one.
    fn index_add(&mut self, entry: GrantIndexEntry<'_>) {
        let index = match entry.grantee {
            Some(g) => self.by_grantee.entry(g.clone()).or_default(),
            None => &mut self.universal,
        };
        set_insert(index, entry.content_prefix, entry.issuer.clone());
    }

    /// [`Grants::withdraw`]'s index step: take `entry` out of the index it was
    /// added to, dropping a grantee whose last entry this was — so
    /// `by_grantee` holds no empty prefix map, as `set_remove` leaves no empty
    /// issuer set.
    fn index_remove(&mut self, entry: GrantIndexEntry<'_>) {
        let Some(g) = entry.grantee else {
            set_remove(&mut self.universal, entry.content_prefix, entry.issuer);
            return;
        };
        let Some(prefixes) = self.by_grantee.get_mut(g) else {
            return;
        };
        set_remove(prefixes, entry.content_prefix, entry.issuer);
        if prefixes.is_empty() {
            self.by_grantee.remove(g);
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
    /// A fresh grant of `content_prefix` to `grantee` (`None` = ANY-PRINCIPAL).
    Grant { content_prefix: Address, grantee: Option<Address> },
    /// A revocation naming an EARLIER admitted grant's link address.
    Revoke { old: Address },
    /// Not a well-formed grant (a malformed slot); the fold ignores it.
    Ignore,
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
/// `home ∉ drafts`.
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

/// Classify one admitted `t_grant` record off its `from` slot: a `from`
/// naming an earlier admitted grant (same home) is a REVOCATION; otherwise a
/// fresh grant whose `to` is the grantee (empty ⟹ ANY-PRINCIPAL). A malformed
/// slot is ignored.
fn classify(prev: &Grants, home: &Address, value: &Link) -> Kind {
    let Some(from) = value.from_slot().single_denoted() else {
        return Kind::Ignore; // `from` must denote exactly one address
    };
    let Ok(from) = validate(from.clone()) else {
        return Kind::Ignore;
    };
    // A `from` naming an admitted grant of THIS home is a revocation.
    if prev.records.get(&from).is_some_and(|r| &r.home == home) {
        return Kind::Revoke { old: from };
    }
    // Otherwise a fresh grant: `to` empty ⟹ ANY-PRINCIPAL, exactly one address
    // ⟹ the grantee, anything else ⟹ malformed.
    let grantee = if value.to_slot().is_empty() {
        None
    } else {
        match value.to_slot().single_denoted() {
            Some(g) => match validate(g.clone()) {
                Ok(g) => Some(g),
                Err(_) => return Kind::Ignore,
            },
            None => return Kind::Ignore, // a multi-address `to` is malformed
        }
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
/// world's. The three paths that move nothing hand it straight back, so a
/// link deposit that is not an admitted grant — which is nearly all of them —
/// costs no copy at all. [`classify`] reads it before the move, since a
/// revocation is recognized by the operative set it is about to leave.
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
        Kind::Revoke { old } => next.withdraw(&old),
        Kind::Ignore => {}
    }
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
/// The enumeration is the EXISTING M7 read `LinkState::type_slice` over
/// `enc([t_grant])` under `View::Audit` (every deposit ever, in address
/// order), plus `readlink` per address — NO new store read is added (the fence
/// asked which read the seed uses; this is it). Within one home, addresses are
/// ordinal-ordered = deposit-ordered, so a revocation is always processed
/// after the grant it names, and the seed reproduces the fold.
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
/// SEED COST, per load and per `Engine::world_at` reconstruction, and linear
/// in the GRANTS CLASS rather than in anything a caller names: one
/// `type_slice` over that class under the audit view, then per member one
/// `readlink` and one [`fold_one`]. A member that ADMITS pays
/// [`admitted_issuer`]'s three M3 reads on top, and then [`Grants::admit`]'s
/// two inserts — one into the operative map, one into an ordered index whose
/// key is a content-prefix and whose member is an issuer, both addresses a
/// DEPOSITOR chose and neither bounded by this crate. So the figure is the
/// store's, grown by every grant any account has ever issued and never
/// shrunk: a revocation adds a record to the class rather than removing one,
/// and a `nullify` leaves the claim in the audit view this walk must read.
/// `crate::publication`'s seed states the exception set's own figure, and
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
