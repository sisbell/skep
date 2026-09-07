//! The GRANT FOLD — the engine's second derived index (PUB round 2, lane 3.3,
//! §1), beside the exception set (`crate::publication`): a DERIVED index over
//! the link store that answers `grant_exists(doc, principal)` — the third
//! clause of the read predicate [`crate::World::readable`] (PUB-1.31).
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
use skep_arrangement::{trunk_of, Caller};
use skep_links::{Link, LinkRec, LinkState, View};
use skep_namespace::{first_document_address, prefix_contains, M3State, PrincipalId};

use crate::publication::Drafts;
use crate::types::t_grant;
use crate::world::World;

impl World {
    /// THE read predicate (PUB-1.31): `readable(doc, principal) =
    /// published(doc) ∨ principal ∈ owner_subtree(doc) ∨ grant_exists(doc,
    /// principal)` — one function, three clauses, short-circuiting.
    ///
    /// `principal` is `None` for the GUEST (PUB-5.5): a guest sees a document
    /// iff it is published, so [`World::readable_guest`] is `readable(None,
    /// ·)`. Every clause projects a version member to its document first
    /// (`trunk_of`, M5, PUB-2.15): `1.0.1.0.1.2` reads exactly as
    /// `1.0.1.0.1`.
    ///
    /// * PUBLISHED (PUB-5.5) — an exception-set MISS on the projected
    ///   document. Fail-open (PUB-7.5): an UNREGISTERED address is absent from
    ///   the set and so answers readable here, which is why every doc-argument
    ///   consult defers an unregistered document to its store's own
    ///   `*NotRegistered` (a withheld answer is only ever a REGISTERED private
    ///   document — PUB-6.12).
    /// * SUBTREE (PUB-5.9, PUB-5.13-adjacent) — `owner_account(doc) ⊑
    ///   account(principal)`, ONE prefix compare DOWNWARD only, off the
    ///   exception set's MINT-TIME owner (never a nearest-account walk). A
    ///   node-tier principal (principal 0, seated at a node) has a prefix
    ///   shorter than any account, so the compare excludes it; org members are
    ///   SIBLINGS, so neither reads the other's drafts.
    /// * GRANT (PUB-5.8, PUB-5.19) — the grant fold, grantee PRINCIPAL-EXACT,
    ///   coverage containment ∩ issuer = doc's ω owner.
    pub fn readable(&self, principal: Option<PrincipalId>, doc: &Address) -> bool {
        let trunk = trunk_of(doc);
        // Published clause — a published document (or member) is readable by
        // all, and an unregistered one is fail-open here (PUB-7.5).
        if self.published(&trunk) {
            return true;
        }
        // A REGISTERED private draft from here: the exception set holds its
        // mint-time owner. `None` cannot arise (published above covers the
        // unregistered case), but is answered fail-closed.
        let Some(owner) = self.owner_account(&trunk).cloned() else {
            return false;
        };
        // The guest sees only published documents (no subtree, no grant).
        let Some(id) = principal else {
            return false;
        };
        let pa = self.namespace.principal_prefix(id).cloned();
        // Subtree clause — downward only.
        if let Some(pa) = &pa {
            if prefix_contains(&owner, pa) {
                return true;
            }
        }
        // Grant clause — the fold, grantee exact (`None` account ⟹ only the
        // ANY-PRINCIPAL grants can match, which the fold probes regardless).
        self.grants.grant_exists(&owner, pa.as_ref(), &trunk)
    }

    /// The GUEST predicate (PUB-5.5): `readable(None, ·)` — published alone.
    /// M9's fires read at this class (§5), and every unauthenticated read
    /// answers through it.
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
    /// state: M7 takes a closure and names no principal, M10 closes its own
    /// over the session's principal, and [`crate::Engine::coordinator`]
    /// hands M9 the guest half of it directly. Engine-direct callers — the
    /// harnesses and this crate's tests — thread it through here.
    pub fn visible_to(
        caller: Caller,
    ) -> impl Fn(&World, &Address) -> bool + Copy + Send + Sync + 'static {
        move |world: &World, doc: &Address| match caller {
            Caller::Principal(p) => world.readable(Some(p), doc),
            Caller::System => world.readable_guest(doc),
        }
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

    /// Add an admitted grant to the query indexes.
    fn index_add(&mut self, rec: &GrantRecord) {
        match &rec.grantee {
            Some(g) => {
                let mut prefixes = self.by_grantee.get(g).cloned().unwrap_or_default();
                let mut issuers =
                    prefixes.get(&rec.content_prefix).cloned().unwrap_or_default();
                issuers.insert(rec.issuer.clone());
                prefixes.insert(rec.content_prefix.clone(), issuers);
                self.by_grantee.insert(g.clone(), prefixes);
            }
            None => {
                let mut issuers =
                    self.universal.get(&rec.content_prefix).cloned().unwrap_or_default();
                issuers.insert(rec.issuer.clone());
                self.universal.insert(rec.content_prefix.clone(), issuers);
            }
        }
    }

    /// Remove a superseded grant from the query indexes, dropping empty sets.
    fn index_remove(&mut self, rec: &GrantRecord) {
        match &rec.grantee {
            Some(g) => {
                if let Some(mut prefixes) = self.by_grantee.get(g).cloned() {
                    if let Some(issuers) = prefixes.get(&rec.content_prefix).cloned() {
                        let issuers = issuers.without(&rec.issuer);
                        if issuers.is_empty() {
                            prefixes.remove(&rec.content_prefix);
                        } else {
                            prefixes.insert(rec.content_prefix.clone(), issuers);
                        }
                    }
                    if prefixes.is_empty() {
                        self.by_grantee.remove(g);
                    } else {
                        self.by_grantee.insert(g.clone(), prefixes);
                    }
                }
            }
            None => {
                if let Some(issuers) = self.universal.get(&rec.content_prefix).cloned() {
                    let issuers = issuers.without(&rec.issuer);
                    if issuers.is_empty() {
                        self.universal.remove(&rec.content_prefix);
                    } else {
                        self.universal.insert(rec.content_prefix.clone(), issuers);
                    }
                }
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
    // Published: an exception-set miss (grants are born published).
    if drafts.contains_key(home) {
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
    let t_grant = t_grant();
    if !is_grant_typed(value, &t_grant) {
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
pub(crate) fn seed(m3: &M3State, links: &LinkState, drafts: &Drafts) -> Grants {
    let t_grant = t_grant();
    let ty = skep_links::enc([&t_grant]);
    let mut grants = Grants::new();
    for addr in links.type_slice(&ty, View::Audit) {
        let Some(value) = links.readlink(&addr).cloned() else {
            continue; // type-slice keys are resident by construction
        };
        grants = fold_one(&grants, m3, drafts, &addr, &value);
    }
    grants
}
