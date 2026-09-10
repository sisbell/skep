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

impl World {
    /// THE LIVE ANY-PRINCIPAL SET, enumerable (PUB-7.22; lane 3.6 §3): every
    /// content-prefix currently covered by an admitted, unsuperseded
    /// ANY-PRINCIPAL grant, with the issuers that granted it — in prefix
    /// (tumbler) order, each issuer list in address order. An INDEX SHAPE,
    /// never per-session state: the fold's universal index rendered as owned
    /// values, enumerated once per request off one head snapshot by the feed's
    /// universal term (a K-way merge of these prefixes' own position-index
    /// lists, K = this list's length). Revocation is immediate here — a
    /// superseding record removes its grant from the index at the commit that
    /// carries it — so a derivation off this read never serves withdrawn
    /// material (PUB-7.23). Reads the fold's query index, adds no fold state,
    /// and is `readable`'s own universal probe turned inside out: a document
    /// is universally granted iff one of its ancestor prefixes is listed here
    /// with its ω owner among the issuers.
    pub fn universal_grants(&self) -> Vec<(Address, Vec<Address>)> {
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
    pub fn issuers_for(&self, grantee: &Address) -> Vec<(Address, Vec<Address>)> {
        self.grants.issuers_for(grantee)
    }
}

// The GRANTS class type address the fold keys on — `crate::types::t_grant`
// (`1.1.0.1.0.1.0.3.90`, COMMONS DECISION 5): pinned in `types.rs` beside
// every other commons address the engine and the daemon read as a VALUE.

/// One admitted, unsuperseded grant record — enough to answer queries and to
/// remove it from the query indexes when a later record supersedes it. The
/// fields are crate-visible for the world dump's grant section (lane 3.4
/// §3), which renders the fold's operative set through [`Grants::records`].
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

/// The grant fold: the operative grant set, plus the two query indexes it is
/// projected into. All `im` persistent structures, so `World::clone` on the
/// commit path is one more root clone. `#[serde(skip)]` at the World: derived,
/// never checkpointed (the module docs' hint discipline).
#[derive(Clone, Debug, Default)]
pub(crate) struct Grants {
    /// Admitted, unsuperseded grants, keyed by the grant link's OWN address —
    /// so a superseding record removes exactly the grant it names.
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
// `by_grantee` is another one, so the fold's index maintenance is four edits
// of a single shape — [`Grants::index_add`]'s two arms and
// [`Grants::index_remove`]'s two — and [`Grants::issuers_for`]'s inversion is
// a fifth. The decision each of those sites makes is WHICH index a record
// belongs in; the bookkeeping is here.

/// `map[key] ∪= {member}`, adding the key where it is absent.
fn set_insert<K: Ord + Clone, V: Ord + Clone>(
    map: &OrdMap<K, OrdSet<V>>,
    key: &K,
    member: V,
) -> OrdMap<K, OrdSet<V>> {
    let mut members = map.get(key).cloned().unwrap_or_default();
    members.insert(member);
    map.update(key.clone(), members)
}

/// `map[key] −= {member}`, DROPPING the key where its set empties — so no
/// index ever holds an empty set, and an empty map means "nothing granted"
/// rather than "nothing granted, or one revocation ago".
fn set_remove<K: Ord + Clone, V: Ord + Clone>(
    map: &OrdMap<K, OrdSet<V>>,
    key: &K,
    member: &V,
) -> OrdMap<K, OrdSet<V>> {
    let Some(members) = map.get(key) else {
        return map.clone();
    };
    let members = members.without(member);
    if members.is_empty() {
        map.without(key)
    } else {
        map.update(key.clone(), members)
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
    /// section renders it, and `render` sorts). The fold's one enumeration;
    /// the predicate's consumers are the point probes above.
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

    /// The ANY-PRINCIPAL index as owned values: `(content prefix, issuers)`
    /// in the `OrdMap`'s key order — tumbler order — each issuer set in
    /// address order. [`World::universal_grants`] is the public face.
    pub(crate) fn universal(&self) -> Vec<(Address, Vec<Address>)> {
        self.universal
            .iter()
            .map(|(prefix, issuers)| (prefix.clone(), issuers.iter().cloned().collect()))
            .collect()
    }

    /// The principal-exact index for one grantee, INVERTED: `by_grantee` keys
    /// prefix → issuers (the shape `grant_exists`'s O(depth) probe wants);
    /// the feed wants issuer → the union of that issuer's prefixes (the shape
    /// its per-issuer stream test wants). Both orders are the `OrdMap`s' —
    /// deterministic. [`World::issuers_for`] is the public face.
    pub(crate) fn issuers_for(&self, grantee: &Address) -> Vec<(Address, Vec<Address>)> {
        let mut by_issuer: OrdMap<Address, OrdSet<Address>> = OrdMap::new();
        if let Some(prefixes) = self.by_grantee.get(grantee) {
            for (prefix, issuers) in prefixes.iter() {
                for issuer in issuers.iter() {
                    by_issuer = set_insert(&by_issuer, issuer, prefix.clone());
                }
            }
        }
        by_issuer
            .iter()
            .map(|(issuer, covered)| (issuer.clone(), covered.iter().cloned().collect()))
            .collect()
    }

    /// Add an admitted grant to the query index its grantee names: the
    /// PRINCIPAL-EXACT one keyed by the grantee, or the ANY-PRINCIPAL one.
    fn index_add(&mut self, rec: &GrantRecord) {
        match &rec.grantee {
            Some(g) => {
                let prefixes = self.by_grantee.get(g).cloned().unwrap_or_default();
                let prefixes = set_insert(&prefixes, &rec.content_prefix, rec.issuer.clone());
                self.by_grantee.insert(g.clone(), prefixes);
            }
            None => {
                self.universal =
                    set_insert(&self.universal, &rec.content_prefix, rec.issuer.clone());
            }
        }
    }

    /// Remove a superseded grant from the index it was added to, dropping a
    /// grantee whose last grant this was — so `by_grantee` holds no empty
    /// prefix map, as `set_remove` leaves no empty issuer set.
    fn index_remove(&mut self, rec: &GrantRecord) {
        match &rec.grantee {
            Some(g) => {
                if let Some(prefixes) = self.by_grantee.get(g).cloned() {
                    let prefixes = set_remove(&prefixes, &rec.content_prefix, &rec.issuer);
                    if prefixes.is_empty() {
                        self.by_grantee.remove(g);
                    } else {
                        self.by_grantee.insert(g.clone(), prefixes);
                    }
                }
            }
            None => {
                self.universal = set_remove(&self.universal, &rec.content_prefix, &rec.issuer);
            }
        }
    }
}

/// The classification of one admitted `t_grant` record, off its `from` slot.
enum Kind {
    /// A fresh grant of `content_prefix` to `grantee` (`None` = ANY-PRINCIPAL).
    Grant { content_prefix: Address, grantee: Option<Address> },
    /// A revocation naming an EARLIER admitted grant's link address.
    Supersede { old: Address },
    /// Not a well-formed grant (a malformed slot); the fold ignores it.
    Ignore,
}

/// Whether a link value is a `t_grant`-typed record — denotation equality on
/// the type slot (the fold keys on `t_grant` as a VALUE, never through M7's
/// registry).
fn is_grant_typed(value: &Link, t_grant: &Address) -> bool {
    value.type_slot().single_denoted() == Some(t_grant.tumbler())
}

/// Admission (I4): the grant's home must be the issuer's OWN doc 1, PUBLISHED.
/// Returns the issuer (ω of home) when admitted, else `None`.
///
/// `home` is a registered document (a deposit lands in no unregistered home,
/// M7's HomeNotRegistered gate). `published(home)` is the exception-set miss —
/// `home ∉ drafts`.
fn admit(m3: &M3State, drafts: &Drafts, home: &Address) -> Option<Address> {
    // Published: an exception-set miss (grants are born published). The
    // polarity is `crate::publication`'s to hold, not this module's.
    if !is_published(drafts, home) {
        return None;
    }
    // The issuer — ω of the home, an account.
    let issuer = m3.effective_owner_prefix(home)?.clone();
    // The home is the issuer's own doc 1.
    if first_document_address(&issuer) != Some(home.clone()) {
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
        return Kind::Supersede { old: from };
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
fn fold_one(prev: &Grants, m3: &M3State, drafts: &Drafts, addr: &Address, value: &Link) -> Grants {
    if !is_grant_typed(value, t_grant()) {
        return prev.clone();
    }
    let Some(home) = document_of(addr) else {
        return prev.clone();
    };
    let Some(issuer) = admit(m3, drafts, &home) else {
        return prev.clone(); // unadmitted: neither grant nor revocation
    };
    let mut next = prev.clone();
    match classify(prev, &home, value) {
        Kind::Grant { content_prefix, grantee } => {
            let record = GrantRecord { home, issuer, content_prefix, grantee };
            next.index_add(&record);
            next.records.insert(addr.clone(), record);
        }
        Kind::Supersede { old } => {
            if let Some(record) = next.records.get(&old).cloned() {
                next.index_remove(&record);
                next.records.remove(&old);
            }
        }
        Kind::Ignore => {}
    }
    next
}

/// The FOLD half (PUB-7.7): the grant fold after `rec` has been applied to the
/// link store. `rec` is the record just folded; `m3`/`drafts` are the world's
/// slices as of this commit (a link deposit changes neither, so both are the
/// authoritative state a query would read).
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
pub(crate) fn fold(prev: &Grants, m3: &M3State, drafts: &Drafts, rec: &LinkRec) -> Grants {
    let LinkRec::Deposit { addr, value, .. } = rec else {
        return prev.clone();
    };
    let Ok(link_addr) = validate(addr.clone()) else {
        return prev.clone();
    };
    fold_one(prev, m3, drafts, &link_addr, value)
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
/// end of history. [`admit`]'s three questions answer alike at both, each for
/// its own reason. The BIT: M3 writes it once, at the record that registers
/// the document, and the exception set only ever GAINS entries — so a home
/// published when its grant landed is published still, and a draft-homed one
/// was unadmitted at both readings. The OWNER: no account-tier prefix longer
/// than a document's own account can cover it (`crate::publication`'s
/// `owner_account_of` states M3's half of that), so no later delegation moves
/// ω of a home. The DOC-1 test is `first_document_address`, a pure function of
/// the issuer and of no state at all. A store change that made any of the
/// three time-varying splits the halves, and `Engine::check_hints` is where
/// that shows.
pub(crate) fn seed(m3: &M3State, links: &LinkState, drafts: &Drafts) -> Grants {
    let ty = skep_links::enc([t_grant()]);
    let mut grants = Grants::new();
    for addr in links.type_slice(&ty, View::Audit) {
        let Some(value) = links.readlink(&addr).cloned() else {
            continue; // type-slice keys are resident by construction
        };
        grants = fold_one(&grants, m3, drafts, &addr, &value);
    }
    grants
}
