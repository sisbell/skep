//! §C, beneath [`M3State`]: the queries — pure reads off any M2 snapshot,
//! writing nothing — all but the two peeks, which call a mint and so live in
//! `mint`. Entity membership (§2), the two chain-end reads that read a
//! frontier directly (`has_documents`, `latest_version`), the publication
//! map's point read and its walk, the principal registry's reads, its walk
//! and the ω resolver (§5), and [`prefix_contains`], which answers where an
//! address sits and never who may write it. An `impl M3State` child of
//! `state`: it reads the slice's private fields the way a child does, and
//! keeps the one chain-membership decision (`is_chain_member`) and the one ω
//! walk (`omega`) private to itself, so every other reader goes through a
//! method that states its contract.

use std::ops::Bound::{Excluded, Unbounded};

use num_traits::Zero;
use skep_address::{is_prefix, ordinal, validate, Address, Level, Tumbler};

use super::M3State;
use crate::ghost::ghost_floor;
use crate::ns::{document_ns, namespace_of, nth_in, version_ns};
use crate::record::PrincipalId;

// ---------------------------------------------------------------------------
// §C Queries (pure; read off any M2 Snapshot; write nothing) + §2 membership.
// ---------------------------------------------------------------------------

/// Containment test (O1): `prefix ≼ a` — pure, total, decidable from the two
/// addresses alone, consulting no registry state and needing no coordination.
/// It answers where an address SITS, not who may write it: authorization is
/// [`M3State::is_effective_owner`] (ω, longest match), because several
/// principals' prefixes contain the same address — §5.
pub fn prefix_contains(prefix: &Address, a: &Address) -> bool {
    is_prefix(prefix.tumbler(), a.tumbler())
}

impl M3State {
    /// Is `a` a member of its own chain? The §2 decision behind
    /// [`M3State::is_allocated`] (and so behind [`M3State::entity_level`]),
    /// settled by decomposing and comparing against the frontier.
    /// Membership-correctness invariant: for T4-valid `a`, `a` is *exactly*
    /// `c_{ordinal(a)}` of its decomposed `(parent, g)` namespace (ASN-0040
    /// `S(p, d)` canonical form; T4b unique-parse), so `a` is realized —
    /// `a ∈ {c_{floor+1}..cₘ}` — iff `floor < ordinal(a) ≤ m`, where the floor
    /// is 0 everywhere but the ghost content namespace — genuine chain
    /// membership with NO false positives, not an approximation. The code
    /// spells that interval, and both of its ends absorb their edge case:
    /// where the floor is zero the lower bound is free, because T4 forbids a
    /// trailing zero and `ordinal` reads the last component, so the
    /// [`Address`] type carries a positive ordinal; and an absent frontier is
    /// `m = 0`, which no positive ordinal is ≤. The ghost exclusion is
    /// permanent: the five ghost tumblers answer unallocated on every board
    /// forever ([`ghost_floor`] — nothing exists at a reserved type address),
    /// however far the chain past them has advanced.
    fn is_chain_member(&self, a: &Address) -> bool {
        let Some(key) = namespace_of(a) else {
            return false; // parentless only for a 1-component node — the callers' Node arm
        };
        let n = ordinal(a.tumbler()); // &Nat — compare BY REFERENCE (BigUint is not Copy)
        *n > ghost_floor(&key) && self.frontiers.get(&key).is_some_and(|m| n <= m)
    }

    /// `true` iff `a` exists in the name space — minted on a frontier in ANY
    /// namespace, content/link included, or, for a node, held in the node
    /// registry: Σ₀'s root `[1]`, the system node genesis's seed admits, and
    /// every node `register_node` admitted (node addresses are never minted
    /// here — ASN-0047 NodeBaptism originates them outside the docuverse).
    /// THE allocation oracle (§2). Ghost principle (B3): reflects
    /// *allocation*, never byte-presence — a registered-empty document is a
    /// valid, addressable ghost; content existence is M4's separate axis, and
    /// a check that content exists asks M4, never this read. E is
    /// append-only, so a `true` answer is permanent (B0/P1) on any slice
    /// whose every record fell inside [`M3State::apply_m3`]'s totality domain
    /// — as each mint's record does when staged where [`M3Rec::Allocate`]
    /// says.
    ///
    /// [`M3Rec::Allocate`]: crate::M3Rec::Allocate
    pub fn is_allocated(&self, a: &Address) -> bool {
        match a.level() {
            Level::Node => self.nodes.contains(a),
            // The general decompose-and-compare over ALL non-node levels
            // (incl. Element): a content/link element [d.0.s.n] has parent
            // b_C(d)/b_L(d) at the SAME tier, so g = 1 and the key is its
            // TRUE content/link namespace.
            Level::Account | Level::Document | Level::Element => self.is_chain_member(a),
        }
    }

    /// `Some(level)` iff `a` is a registered *entity* (zeros ≤ 2); `None` for
    /// an element or an unregistered address. An entity is an allocated
    /// address below the element tier: content and link elements ARE allocated
    /// but are not in E, so ask [`M3State::is_allocated`] about those.
    /// [ASN-0047 E]
    pub fn entity_level(&self, a: &Address) -> Option<Level> {
        (a.level() != Level::Element && self.is_allocated(a)).then_some(a.level())
    }

    /// `entity_level(a) == Some(Document)` — the edit/home precondition seam
    /// for M5/M7, and the ⟨⟩-vs-fail bool for M6/M8.
    pub fn is_registered_document(&self, a: &Address) -> bool {
        self.entity_level(a) == Some(Level::Document)
    }

    /// `entity_level(a) == Some(Account)` — the account-hood precondition
    /// (P8/CND.pre): what [`M3State::mint_document`] gates on, what
    /// `create_new_document` and `fork` reach through it, and the
    /// account-hood test the credential fold (AUTH-2.33) and the key-set read
    /// (AUTH-6.19) ask. NOT `delegate`'s parent gate, which is the account
    /// mint's own and admits a registered node OR account — a node parent
    /// being the ordinary case, since the first delegate under a node has
    /// one. The account twin of [`M3State::is_registered_document`], published
    /// for the same reason: the question is asked from outside M3, and
    /// spelling it as a comparison against an `Option<Level>` makes every
    /// caller import M1's tier enum and choose between `.is_some()` (any
    /// entity — what `register_node`'s freshness gate wants) and this.
    pub fn is_registered_account(&self, a: &Address) -> bool {
        self.entity_level(a) == Some(Level::Account)
    }

    /// Has `account` any documents — is its `(account, 2)` chain non-empty?
    /// AUTH-3.68's `has_documents(account)`, and the premise of the create
    /// path's empty-account rule (PUB-8.21). The chain's frontier IS its
    /// count (B1), so the chain is non-empty iff that frontier exists — one
    /// lookup on the key [`M3State::mint_document`] reads; a zero count,
    /// representable only off a corrupted checkpoint, is an empty chain, as
    /// [`M3State::latest_version`] reads it. `false` off the account tier,
    /// where no document chain is anchored — the tier gate is what makes the
    /// key the DOCUMENT chain's, since `(N, 2)` under a node is the account
    /// chain — and, on every state M3's own ops produce, for an unregistered
    /// account, whose chain is empty because `mint_document` refuses one
    /// (P8). It reads the CHAIN and not the registry, like `latest_version`:
    /// P8 is a producer invariant the fold does not re-check, so off it — a
    /// document folded under an account no op registered — this answers the
    /// chain, and whether the account is registered stays the caller's
    /// question ([`M3State::is_registered_account`]). Asked by
    /// [`crate::Namespace::create_new_document`] under the held
    /// document-chain key and by the daemon's mint doors off a snapshot;
    /// answered here so that neither reassembles it.
    pub fn has_documents(&self, account: &Address) -> bool {
        account.level() == Level::Account
            && self
                .frontiers
                .get(&document_ns(account))
                .is_some_and(|m| !m.is_zero())
    }

    /// The LATEST member of `source`'s version chain `(source, 1)` — `c_m`
    /// for the chain's frontier `m`, spelled by the one chain-member helper
    /// (`nth_in`) at `m` — or `None` when the chain holds no member yet.
    /// [M5: the trunk head a bare document address floats to,
    /// PUB-2.49/PUB-2.53, and the head/older distinction the publish shot
    /// decides at commit, PUB-2.39] A pure frontier read off any snapshot:
    /// the chain is contiguous from 1 (B1) and never loses a member (B0), so
    /// a `Some` never regresses across snapshots — a later read answers the
    /// same member or a later one. The chain's other end, the slot it opens
    /// at, is [`first_version_address`].
    ///
    /// Total. `None` off the document tier, because no other tier anchors a
    /// version chain — the same key under an account is the sub-account chain
    /// (Conflicts §8), whose members are not versions of anything — and for
    /// a document-tier address whose chain has no member, registered or not.
    /// PUB-6.37's polarity — registration precedes every chain read — stays
    /// the caller's for the reason it is on [`M3State::published`]: an
    /// unregistered address is answered by the registration check, and a
    /// `None` here says only that the chain is empty.
    ///
    /// [`first_version_address`]: crate::first_version_address
    pub fn latest_version(&self, source: &Address) -> Option<Address> {
        if source.level() != Level::Document {
            return None;
        }
        let key = version_ns(source);
        let m = self.frontiers.get(&key).filter(|m| !m.is_zero())?;
        Some(nth_in(&key, m).expect("k = 1 passes TA5a on every anchor"))
    }

    /// `published(doc)` — THE engine's one definition of a document's
    /// publication state (owner ruling D1; PUB-1.68, PUB-7.8): the bit its
    /// minting `Allocate` journaled, read off the publication map at one
    /// point lookup — the record-lookup cost the PUB pack names for a build
    /// answering off M3's document records (§5.5), and the map the engine's
    /// derived exception set (PUB-7.5) is a membership index over. A version
    /// address answers its OWN member's bit; projecting a member to its
    /// document ahead of a gate (PUB-2.15) is the caller's address
    /// arithmetic, not this read's.
    ///
    /// CONTRACT — `doc` is a REGISTERED document: callers gate on
    /// [`M3State::is_registered_document`] first (PUB-6.37: registration
    /// precedes publication, and an unregistered address is answered by the
    /// registration check and by nothing here). On any slice M3's own fold
    /// produced, every registered document has an entry, because the
    /// allocation record that registers it carries the bit and the fold writes
    /// both in one step.
    ///
    /// `false` FOR A MISSING ENTRY is the fail-private direction (PUB-1.1),
    /// and it answers two different absences. An unregistered address has no
    /// allocation record, so what this returns for one is no answer at all —
    /// a caller that reads it has skipped the gate. A REGISTERED document with
    /// NO entry is the other, and it is not a caller's bug: it is reachable
    /// outside [`M3State::apply_m3`]'s totality domain — a jumped `Allocate`
    /// registers the ordinals it skipped — and is the case
    /// [`M3State::documents`] states has no remedy here. This read answers it
    /// PRIVATE. A derived index that stores the UNPUBLISHED side and answers
    /// by membership MISS inverts that, and should say so where it is built.
    ///
    /// IMMUTABLE: no M3 function changes a document's bit after its mint —
    /// there is no publication transition, in either direction (PUB-1.9,
    /// PUB-1.68), and the publish shot changes none either: it mints a NEW
    /// member of a version chain, born published.
    pub fn published(&self, doc: &Address) -> bool {
        self.publication.get(doc).copied().unwrap_or(false)
    }

    /// Every registered DOCUMENT with its publication bit, in address order —
    /// the ENUMERATION of the publication map [`M3State::published`] reads
    /// one entry of. One entry per registered document, versions included, on
    /// any slice M3's own fold produced: the allocation record that registers
    /// a document carries its bit and [`M3State::apply_m3`] writes both in one
    /// step, and nothing else writes here. A checkpoint is bytes, so a reader
    /// that must not fail-stop on a corrupted one re-asks
    /// [`M3State::is_registered_document`] per entry, as the engine's seed
    /// does. The order is the `OrdMap`'s — a function of the contents, so two
    /// boards with one history enumerate alike, and the walk's back end is the
    /// address-greatest entry, which address order does not make the newest: a
    /// version of doc 1 sorts BETWEEN doc 1 and doc 2, whichever was minted
    /// first. Double-ended and exact-size, as a map walk is in std — `.rev()`
    /// and `.len()` are the hidden type's own, promised rather than hidden, so
    /// that end and the document count each cost one call and no walk.
    ///
    /// The fold-produced scope is load-bearing in one direction only. A
    /// checkpoint or a journal outside [`M3State::apply_m3`]'s totality domain
    /// can hold a registered document with NO entry — a jumped `Allocate`
    /// registers the ordinals it skipped — and that direction has no remedy
    /// here: the claim relates the frontier map to this one, which no
    /// per-entry door can settle, and checking it at load would mean expanding
    /// every document chain to its members, the Θ(documents) cost B1's
    /// compression exists to avoid. What a reader owes is the POLARITY.
    /// [`M3State::published`] answers `false` for a missing entry, which is
    /// fail-private; an index that stores the UNPUBLISHED side and answers by
    /// membership MISS inverts that, so a document this walk omits reads
    /// PUBLISHED there. A derived index built by ADDITION over this walk
    /// inherits the open direction and should say so where it is built.
    ///
    /// Published for the reader that cannot ask per address: a derived index
    /// over the bit (the engine's exception set, PUB-7.5 — PUB-7.7's seed
    /// half) and a rendering of the map. Both would otherwise rebuild this
    /// walk from the slice's serde form by a private field name, which no
    /// compiler edge protects.
    pub fn documents(
        &self,
    ) -> impl DoubleEndedIterator<Item = (&Address, bool)> + ExactSizeIterator + '_ {
        self.publication
            .iter()
            .map(|(doc, published)| (doc, *published))
    }

    /// ω's resolution step: the Π entry whose prefix is the LONGEST covering
    /// prefix of `a` (§5) — THE one walk. [`M3State::effective_owner`]
    /// projects the id, [`M3State::effective_owner_prefix`] the prefix,
    /// [`M3State::effective_owner_pair`] hands the entry back whole, and
    /// [`M3State::is_effective_owner`] compares. `effective_owner` states the
    /// walk's cost and filter as a guarantee and the other three inherit
    /// them; the `principals` range-walk upgrade lands here once, serving all
    /// four, and the reasons for the walk's shape are below.
    ///
    /// The walk is over Π, keeping the longest covering prefix — the reference
    /// form the design names — and NEVER over `a`'s own reconstructed
    /// prefixes. That is a cost decision, and it is load-bearing: `a` arrives
    /// from a caller, and T4 bounds its zero pattern but not its DEPTH, so a
    /// per-candidate walk would do work quadratic in a length the caller
    /// chooses (an account-tier `[1, 0, 1, 1, …]` has an admissible candidate
    /// at every length, and rebuilding each one clones its components), while
    /// `create_new_document` and `delegate` both evaluate ω in-closure under
    /// the held global `M3State::principals_lock_key`. Here the work is
    /// `Σ_{p ∈ Π} |p|` component comparisons, and the walk's only heap use is
    /// its iterator's path through Π's tree — never a copy of `a` — so a deep
    /// probe costs no more than a shallow one and neither costs O(#allocated).
    ///
    /// But the walk visits EVERY seat, and the gates that admit a seat do not
    /// bound how many there are. Every account holder is ω of its own
    /// sub-account chain, and a session as an account that holds no keys of
    /// its own opens with the keys of the nearest keyed account above it
    /// (AUTH-4.30 (i)), so ONE key holder can seat principals in breadth and
    /// in depth — one durable delegation each, with no other party's consent,
    /// and permanently (O12). The walk is therefore Θ(|Π|) per call, with |Π|
    /// a number any key holder can raise, and a reader that takes ω per
    /// request pays it per request; nothing in M3 bounds |Π|
    /// ([`crate::Namespace::delegate`] names whose bound it is). And the cost
    /// is per CALL, so a caller that takes one ω per entry of a walk pays the
    /// PRODUCT — an index built that way over [`M3State::documents`] costs
    /// Θ(entries · |Π|) each time it is built — which is why a registered
    /// document's owner has a read of its own, [`M3State::account_seat`], one
    /// lookup where this is a walk. The rest lands with the `principals`
    /// range-walk upgrade, which must not stand on `OrdMap::get_prev` or
    /// `get_next`: im 15.1.0's `lookup_prev`/`lookup_next` return a child
    /// node's answer as-is, so once Π outgrows one 64-key leaf, a child holding
    /// no key on the near side answers `None` where the parent's separator key
    /// is the neighbour — a false `None` in an ownership oracle. The
    /// integration suite holds ω to [`M3State::account_seat`]'s exact lookup
    /// over a Π past one leaf, at every seated account's doc-1 slot `A·0·1` —
    /// the first address past that seat in key order, where such a `None`
    /// falls when the seat is a separator.
    ///
    /// The tier filter is O1a, and it is a refusal rather than an
    /// optimisation. O1a is a producer invariant (genesis plus `delegate`'s
    /// hoisted `NotAccountTier` gate), so a below-tier entry is unreachable
    /// through the ops and representable only in a corrupted checkpoint — and
    /// ω is the one reader whose answer to such an entry would be a PASS,
    /// which is why ω is the one reader that refuses it. The other readers of
    /// Π need no filter: [`M3State::has_principal_strictly_under`] already
    /// answers a rejection when it sees one, [`M3State::account_seat`] looks
    /// up an account-tier key and so never meets one, and
    /// [`M3State::principal_prefix`] and [`M3State::principals`] answer the
    /// registry verbatim — a prefix every mint that could receive it then
    /// refuses on its own tier gate. No tie is possible here: two prefixes of
    /// one address have different lengths, and Π is prefix-injective.
    fn omega(&self, a: &Address) -> Option<(&Address, PrincipalId)> {
        self.principals
            .iter()
            .filter(|(p, _)| {
                matches!(p.level(), Level::Node | Level::Account) && prefix_contains(p, a)
            })
            .max_by_key(|(p, _)| p.tumbler().len())
            .map(|(p, id)| (p, *id))
    }

    /// ω(a): WHO owns `a` — the longest-prefix match over Π, answered as the
    /// owning id (§5; ASN-0042 O2/O3/O5). A pure prefix query — valid even
    /// when `a` is not (yet) allocated. One projection of the single Π walk
    /// [`M3State::effective_owner_prefix`] shares, and the authorization
    /// predicate [`M3State::is_effective_owner`] is stated in terms of this
    /// one.
    ///
    /// COST — one walk of Π: `Σ_{p ∈ Π} |p|` component comparisons, and heap
    /// use that does not grow with `a`, however deep it is, so a probe a caller
    /// made deep costs no more than a shallow one — but every call is Θ(|Π|),
    /// and |Π| is a number any account holder can raise (`omega` says how);
    /// the bound is per CALL, so one ω per entry of a walk pays the product. A
    /// seat below the account tier — representable only off a corrupted
    /// checkpoint — is never the answer (O1a). Who owns a registered document
    /// or account is [`M3State::account_seat`]'s question: the same seat by
    /// one lookup.
    ///
    /// For WHETHER a given id owns `a` — the authorization question — ask
    /// [`M3State::is_effective_owner`], which settles it without naming the
    /// owner.
    pub fn effective_owner(&self, a: &Address) -> Option<PrincipalId> {
        self.omega(a).map(|(_, id)| id)
    }

    /// ω(a) as the PREFIX rather than the id: the node or account address the
    /// effective owner is seated at (§5; ASN-0042 O2/O3). Same walk, same
    /// tier filter, same cost as [`M3State::effective_owner`] — this is its
    /// other projection, and it is published because the composition a caller
    /// would otherwise write, `principal_prefix(effective_owner(a))`, is two
    /// scans and is the same answer only while Π is id-injective, which is a
    /// PRODUCER invariant (`delegate`'s `DuplicateId` gate) that
    /// [`M3State::apply_m3`] does not re-check. Here the prefix IS the entry ω
    /// matched, so the two cannot come apart. A caller that needs the
    /// principal as well asks [`M3State::effective_owner_pair`], which answers
    /// both off this one walk.
    ///
    /// FOR A REGISTERED DOCUMENT, ITS OWN ACCOUNT. ASN-0042's O6 promises only
    /// containment — every owner sits at or above an address's account,
    /// `pfx(ω(a)) ≼ acct(a)` — and its own worked example owns a document
    /// element from ABOVE its account, under a sub-account baptized with no
    /// principal of its own (ASN-0042's "organizational namespace"). M3 makes
    /// the containment an EQUALITY for every registered document, on any
    /// state its own ops produce: the document's own account holds a seat
    /// ([`M3State::account_seat`] states why), and no node- or account-tier
    /// prefix of the document is longer than its account. So for a registered
    /// document this answers the account it lies in — never `None`, never the
    /// node above it, never an ancestor account. That account is the
    /// document's OWNER ACCOUNT, and [`M3State::account_seat`] is its read:
    /// the same seat by one lookup, answering `None` rather than an ancestor
    /// where the account holds no seat. Ask ω for the covering owner of an
    /// arbitrary address.
    pub fn effective_owner_prefix(&self, a: &Address) -> Option<&Address> {
        self.omega(a).map(|(prefix, _)| prefix)
    }

    /// ω(a) UNPROJECTED: the Π entry ω matched, as the PAIR — the node or
    /// account address the effective owner is seated at AND the principal
    /// seated there (§5; ASN-0042 O2/O3). Same walk, same tier filter, same
    /// cost as [`M3State::effective_owner`]: this is that ONE walk's whole
    /// answer, where the two projections beside it each keep half.
    ///
    /// The read for any caller that needs BOTH halves of one entry — the seat
    /// and who sits there, or whether a given id does. Asking
    /// [`M3State::effective_owner_prefix`] and then
    /// [`M3State::effective_owner`] or [`M3State::is_effective_owner`] gets
    /// the same answer off one snapshot but walks Π twice — twice the cost
    /// [`M3State::effective_owner`] states. `None` is exactly the projections'
    /// `None`: no node- or account-tier seat contains `a`, so the two halves
    /// are absent TOGETHER by construction.
    ///
    /// The owner-of-address read (AUTH-6.37) is one such caller: it reads
    /// `prefix == a` as an ACCOUNT's allocation test and needs the principal
    /// seated AT that prefix. For an account the test is sound because its
    /// seat is its allocation ([`crate::Namespace::delegate`]); at every other
    /// tier it is no allocation test, since a node `register_node` admitted
    /// and every minted document are seated nowhere. A caller holding a
    /// registered document or account and asking who owns it asks
    /// [`M3State::account_seat`] instead: the same pair by one lookup, where
    /// this walks Π.
    pub fn effective_owner_pair(&self, a: &Address) -> Option<(&Address, PrincipalId)> {
        self.omega(a)
    }

    /// THE OWNER of a registered document or account: the seat at `a`'s own
    /// ACCOUNT, `acct(a)` — the prefix of `a` through its user field,
    /// `N·0·U` — and the principal seated there, found by ONE point lookup in
    /// Π. `None` when no principal is seated exactly there, and for a node
    /// address, which has no account. Never a walk: the work is one copy of
    /// `acct(a)` — none of the document or element fields past it — and
    /// O(log |Π|) comparisons, where every ω reader pays Θ(|Π|).
    ///
    /// It answers for EVERY registered document and every registered account,
    /// on every state M3's own ops produce, because M3 allocates no account
    /// without its seat — an account's seat is its allocation
    /// ([`crate::Namespace::delegate`]) — and every registered document, a
    /// version included, lies in a registered account:
    /// [`M3State::mint_document`] mints only under a registered account (P8)
    /// and [`M3State::mint_version`] only under a registered document. So
    /// this is a document's OWNER ACCOUNT and the principal seated there —
    /// what the doc-metadata read reports (PUB-8.12), the engine's draft memo
    /// keeps (PUB-7.5) and its grant admission names as issuer (PUB-5.19) —
    /// and it is the read for that question whether a reader asks it once or
    /// once per entry of a walk over the store, where one ω per entry would
    /// cost Θ(entries · |Π|), each factor grown by one write apiece.
    ///
    /// Wherever it answers, it answers ω: no node- or account-tier prefix of
    /// `a` is longer than `acct(a)`, so a seat AT `acct(a)` is the longest
    /// covering one, and this equals [`M3State::effective_owner_pair`]. Where
    /// the two differ, `a` is a node or `acct(a)` holds no seat, and this
    /// answers `None` where ω climbs to an ancestor account or to the node:
    /// the fail-CLOSED side, so an owner read from it is always the account
    /// `a` lies in. Where the question IS the covering owner of an address
    /// whose own account holds no seat — `create_new_document`'s and
    /// `delegate`'s authorization — ask ω.
    pub fn account_seat(&self, a: &Address) -> Option<(&Address, PrincipalId)> {
        let user = a.account_field()?;
        // `acct(a)` is the prefix of `a` through its user field: the node
        // field, its separator, then `U`.
        let len = a.node_field().len() + 1 + user.len();
        // That prefix of a T4-valid address is a T4-valid account — one
        // separator, both fields nonempty and zero-free, no trailing zero —
        // so the `Address` invariant discharges both `expect`s below. One
        // firing is a defect in this derivation and is reported as one: it is
        // never answered `None`, which here means no seat.
        let prefix = Tumbler::new(a.tumbler().iter().take(len).cloned())
            .expect("acct(a) is nonempty: a node field, its separator, then a user field");
        let account =
            validate(prefix).expect("acct(a) of a T4-valid address is a T4-valid account");
        self.principals
            .get_key_value(&account)
            .map(|(seat, id)| (seat, *id))
    }

    /// THE authorization predicate: is `id` the effective owner ω of `a`? An
    /// absent ω is not-owner, never a pass (§5; ASN-0042 O5).
    ///
    /// Every ω-gated op asks this rather than reassembling it from
    /// [`M3State::effective_owner`], and NEVER
    /// [`prefix_contains`] — the ownership-divergence trap: π₀'s prefix `[1]`
    /// contains every account delegated under it, so containment is true for
    /// several principals at once, and only the longest match arbitrates. O2
    /// exclusivity is then a theorem given prefix-injectivity, which Π's key
    /// makes structural (O1b); id-injectivity (`DuplicateId`) makes the id
    /// comparison equivalent to comparing the principals themselves.
    pub fn is_effective_owner(&self, id: PrincipalId, a: &Address) -> bool {
        self.effective_owner(a) == Some(id)
    }

    /// `pfx(id)` — the projection the id-centric ops (`fork`, `delegate`) and
    /// the M5→M3 cross-owner-VERSION seam need, since `principals` is keyed by
    /// PREFIX, not id: an O(|Π|) scan, not a point lookup (the §5 scan) — and
    /// |Π| is unbounded, since O1a bounds a seat's tier and not how many seats
    /// one holder can create (`omega`). The answer is the registry's own key,
    /// so the prefix a principal is seated at and the prefix it is reported
    /// at are one value. SINGLE-VALUED because `delegate` enforces
    /// id-freshness (`DuplicateId`), so at most one principal carries any id
    /// (§5/§6). Value-stable across snapshots: prefixes are immutable (O13)
    /// and principals persist (O12), and the fold writes a seat only where
    /// none is held — so a caller that needs the prefix as a value says
    /// `.cloned()`, and one that only probes or forwards it pays nothing.
    pub fn principal_prefix(&self, id: PrincipalId) -> Option<&Address> {
        self.principals
            .iter()
            .find(|(_, pid)| **pid == id)
            .map(|(prefix, _)| prefix)
    }

    /// Every seat in Π (§5) with the principal seated there, in address
    /// order — the ENUMERATION of the principal registry that ω walks,
    /// [`M3State::account_seat`] probes one entry of and
    /// [`M3State::principal_prefix`] scans by id. Verbatim, as
    /// `principal_prefix` answers: π₀'s node-tier seat at `[1]`, the system
    /// account genesis seats, every account [`crate::Namespace::delegate`]
    /// seated — and, off a corrupted checkpoint, a below-tier entry, which ω's
    /// O1a filter refuses and this walk does not. The order is the `OrdMap`'s,
    /// a function of the contents, so two boards with one history enumerate
    /// alike; double-ended and exact-size, as [`M3State::documents`] is, so
    /// `.len()` is |Π| at one call and no walk.
    ///
    /// The read for a caller that holds neither an address nor an id — one
    /// that names the seat a commit made by comparing this walk on the worlds
    /// either side of it, or one that renders the registry. Such a caller
    /// otherwise rebuilds Π from the account chains' frontiers and misses
    /// every seat beneath a node [`crate::Namespace::register_node`] admitted,
    /// which no frontier walk from the genesis seats reaches, since M3
    /// enumerates no nodes. Each walk is Θ(|Π|), and |Π| is a number any key
    /// holder can raise (`omega` says how); who owns an address is ω's
    /// question, and where an id is seated `principal_prefix`'s.
    ///
    /// A COMPARISON OF TWO WALKS is one pass, never a search: both run in
    /// address order, and across a commit the later registry holds every seat
    /// of the earlier — the fold writes a seat once and removes none
    /// (O12/O13) — so the two walked in step leave exactly the seats the
    /// commit added, in Θ(|Π|). Searching one walk once per entry of the other
    /// gives the same answer at Θ(|Π|²), in a number any key holder raises one
    /// delegation at a time.
    pub fn principals(
        &self,
    ) -> impl DoubleEndedIterator<Item = (&Address, PrincipalId)> + ExactSizeIterator + '_ {
        self.principals.iter().map(|(prefix, id)| (prefix, *id))
    }

    /// §6 (iv): does a registered principal sit STRICTLY under `p`? The
    /// extensions of `p` sort as one block immediately after `p` (T5), so
    /// ONE probe settles it: the first key after `p` is a strict extension
    /// iff any key is. No full scan, and no precondition: whether `p` is
    /// itself seated does not move the answer.
    pub(crate) fn has_principal_strictly_under(&self, p: &Address) -> bool {
        self.principals
            .range::<_, Address>((Excluded(p), Unbounded))
            .next()
            .is_some_and(|(first, _)| prefix_contains(p, first))
    }
}
