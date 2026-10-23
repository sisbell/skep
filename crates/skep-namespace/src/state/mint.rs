//! §A, beneath [`M3State`]: the lock keys, the six mints and the two peeks.
//!
//! The lock keys are those a transaction holds; the six mints read their
//! frontiers — five single mints and the content chain's range mint; and the
//! two peeks — [`M3State::next_account_prefix`] and
//! [`M3State::next_content_address`] — are each its chain's mint without the
//! record, kept beside the mints they call. An `impl M3State` child of
//! `state`: it reaches the frontier arithmetic (`next_in`) the way a child
//! does, and keeps `mint_on`, the mint behind the five single mints, private
//! to itself, so no other module reaches that mint except through one of the
//! gates.

use skep_address::{Address, GateViolation, Level, Nat};
use skep_kernel::{LockKey, Space};

use super::{M3State, MAX_PRINCIPAL_COMPONENTS, NO_PUBLICATION_STATE};
use crate::error::MintError;
use crate::ns::{account_ns, content_ns, document_ns, link_ns, ns_lock_key, version_ns, NsKey};
use crate::record::{Allocation, M3Rec, RangeAllocation};

// ---------------------------------------------------------------------------
// §A The lock-key constructors: one per chain, and the two registry keys.
// ---------------------------------------------------------------------------

impl M3State {
    /// Returns the content chain's `LockKey`, `(b_C(home), 1)` (§1/§3).
    ///
    /// It pairs with [`M3State::mint_content`]`(home)` — take it for
    /// `transact`'s `keys` before the closure; the mint inside reads this
    /// key's frontier, and the [`M3Rec`] you stage advances it. Never a
    /// coarser `(home_doc, g)` key: the three g = 1 chains under one document
    /// — content `(b_C(d), 1)`, link `(b_L(d), 1)`, version `(d, 1)` — get
    /// three distinct locks (B7/B8).
    ///
    /// Total on every [`Address`], and the caller's one obligation is to pass
    /// the same `home` the paired mint receives. A wrong-tier `home` costs the
    /// key its T4-validity or its identity. Below the document tier the anchor
    /// leaves T4 — an element's content base carries four separators. Above
    /// it `b_C(home)` is a real address and the key is another chain's:
    /// `b_C(A)` for an account `A` is `A·0·1`, so the key is the version chain
    /// of its doc 1, and `b_C([1])` is `1.0.1`, so the key is that account's
    /// sub-account chain. Harmless either way, since a lock key is only ever
    /// compared, and the paired mint refuses that `home` `HomeNotRegistered`
    /// a moment later.
    pub fn content_lock_key(home: &Address) -> LockKey {
        ns_lock_key(&content_ns(home))
    }

    /// Returns the link chain's `LockKey`, `(b_L(home), 1)` (§1/§3).
    ///
    /// It pairs with [`M3State::mint_link`]`(home)` — take it before the
    /// closure; the mint inside reads this key's frontier, and the [`M3Rec`]
    /// you stage advances it. Same obligation and same latitude as
    /// [`M3State::content_lock_key`]: pass the mint's own `home`; a wrong-tier
    /// one costs the key its T4-validity or its identity, as there — `b_L(A)`
    /// for an account `A` is `A·0·2`, so the key is the version chain of its
    /// doc 2 — harmlessly for the same reason.
    pub fn link_lock_key(home: &Address) -> LockKey {
        ns_lock_key(&link_ns(home))
    }

    /// Returns the version chain's `LockKey`, `(source, 1)`.
    ///
    /// It is separate from the document chain below (ASN-0123 VD). It pairs
    /// with [`M3State::mint_version`]`(source, published)` — take it before
    /// the closure; the mint inside reads this key's frontier, and the
    /// [`M3Rec`] you stage advances it.
    ///
    /// Total on every [`Address`], and the anchor is the argument itself, so
    /// the key is T4-valid whatever tier arrives. What a wrong tier costs is
    /// not well-formedness but identity: `(A, 1)` under an account is the
    /// sub-account chain's key, not a version chain's. Harmless, since a lock
    /// key is only ever compared and the paired mint refuses that `source`
    /// `SourceNotRegistered` a moment later — but the caller's one obligation
    /// is to pass the same `source` the mint receives.
    pub fn version_lock_key(source: &Address) -> LockKey {
        ns_lock_key(&version_ns(source))
    }

    /// Returns the document chain's `LockKey`, `(account, 2)`.
    ///
    /// It pairs with [`M3State::mint_document`]`(account, published)` — take
    /// it before the closure; the mint inside reads this key's frontier, and
    /// the [`M3Rec`] you stage advances it.
    ///
    /// Same shape as [`M3State::version_lock_key`]: total on every
    /// [`Address`], T4-valid whatever tier arrives because the anchor is the
    /// argument itself, and a wrong tier names a different chain — `(N, 2)`
    /// under a node is the account chain's key. Harmless for the same reason,
    /// and the caller's one obligation is the same: pass the mint's own
    /// `account`, which it refuses `NotAnAccount` a moment later if it is
    /// not one.
    pub fn document_lock_key(account: &Address) -> LockKey {
        ns_lock_key(&document_ns(account))
    }

    /// Returns the account chain's `LockKey` under `parent`.
    ///
    /// It is `(parent, 2)` under a node and `(parent, 1)` under an account —
    /// the one key whose `g` the chain-family rule picks from `parent`'s tier
    /// (Conflicts §8). It pairs with [`M3State::mint_account`]`(parent)` —
    /// take it before the closure; the mint inside reads this key's frontier,
    /// and the [`M3Rec`] you stage advances it. `pub(crate)` for the reason
    /// the mint is: `delegate` is the only caller and lives in this crate.
    pub(crate) fn account_lock_key(parent: &Address) -> LockKey {
        ns_lock_key(&account_ns(parent))
    }

    /// Returns the single global principal-registry key.
    ///
    /// It is not per-subtree (§8 / Open build decisions "Serialization
    /// granularity"). It is load-bearing in `delegate`: it serializes that
    /// op's fresh-prefix top-down / next-form / authorization reads against
    /// concurrent same-namespace delegations and its id-freshness read
    /// against concurrent same-id delegations — the id race is
    /// cross-namespace (same `new_id`, different `new_prefix`), which no
    /// per-namespace key can serialize. Held defensively by
    /// `create_new_document`, whose ω read is stale-safe for the reason
    /// stated beside that read (§6/§8). Redundant under M2 v1's global
    /// applier lock. `pub(crate)` because only this crate's ops take it: a
    /// store that took it as well would, under a per-key M2, serialize itself
    /// against every delegation in the docuverse.
    pub(crate) fn principals_lock_key() -> LockKey {
        LockKey::new(Space::Principals, &[])
    }

    /// Returns the single global node-registry key.
    ///
    /// It is one key for the whole registry, argument-free like
    /// [`M3State::principals_lock_key`] and plural for the same reason: two
    /// `register_node` calls for different nodes contend on it. Held by
    /// `register_node` so a concurrent duplicate `RegisterNode` surfaces
    /// `NotFresh` instead of silently coalescing. Node admission needs no lock
    /// for safety (idempotent `OrdSet` insert, monotone freshness); this only
    /// preserves the typed rejection under per-key concurrency. Redundant
    /// under v1's global lock, exactly like [`M3State::principals_lock_key`],
    /// and `pub(crate)` for the same reason: `register_node` is the only op
    /// that takes it.
    pub(crate) fn nodes_lock_key() -> LockKey {
        LockKey::new(Space::Nodes, &[])
    }
}

// ---------------------------------------------------------------------------
// §A The six pure mints: five single mints covering the six chain families,
// since `mint_account` serves both account-tier families (`A_account(N)`
// under a node and the sub-account `(A, 1)` under an account, whose `g` the
// chain-family rule picks), and the content chain's range mint. So every
// address M3 originates past genesis's fixed seed is minted here. Five are
// public and fold into M5/M7 composites (M2 contract 3); the sixth,
// `mint_account`, is `pub(crate)` because its callers — `delegate` and the
// account peek — live in this crate.
//
// Each is a query: called on a transaction's working state, it checks one
// structural precondition and hands back the next address on its chain
// together with the single `M3Rec` that realizes it. Advancing the frontier
// is the caller's half — hold the paired `*_lock_key` across the
// transaction, call the mint on its working state, and stage the returned
// record in it before the next mint on that chain — and it is an obligation
// nothing here can enforce, because the record is delivered inside a tuple
// the caller has already destructured. "An address is never reused" is M3's
// to keep *given* the caller's half; what dropping the record, or staging it
// anywhere else, costs is stated on `M3Rec::Allocate`, the record the
// caller stages.
// ---------------------------------------------------------------------------

impl M3State {
    /// Returns the next address on the chain `key` names, and its one record.
    ///
    /// This is the mint behind the five single mints: the record is the one
    /// [`M3Rec`] that realizes the address, stamped `published` — a caller's
    /// resolved bit on a document chain, [`NO_PUBLICATION_STATE`] on every
    /// other. The address and its record leave together, which is what makes
    /// the key a mint reads and the key its record advances one key (§A);
    /// each single mint is this behind its own structural gate.
    ///
    /// # Errors
    ///
    /// Fails where `next_in` does: the [`GateViolation`] of the inc gate
    /// refusing the chain's next slot.
    fn mint_on(&self, key: &NsKey, published: bool) -> Result<(Address, M3Rec), GateViolation> {
        let addr = self.next_in(key)?;
        Ok((
            addr.clone(),
            M3Rec::Allocate(Allocation { addr, published }),
        ))
    }

    /// Returns the next content address under `home`, with its record (§3).
    ///
    /// Its namespace is `(b_C(home), 1)` and its element field `[s_C, m+1]`.
    /// [M5: INSERT and the publish shot] It checks only the structural
    /// precondition P6/C2. To realize it, the caller holds
    /// [`M3State::content_lock_key`]`(home)`, calls this on that
    /// transaction's working state and stages the returned [`M3Rec`] there,
    /// before its next mint on the chain — so successive mints in one
    /// composite each see the prior one ([`M3Rec::Allocate`] states the rule
    /// and what breaking it costs). [`M3State::next_content_address`] is this
    /// without the record, which is the content chain's peek: the read for a
    /// caller that wants the address and mints nothing.
    ///
    /// # Errors
    ///
    /// `HomeNotRegistered` where `home` is no registered document; `Gate`
    /// where the inc gate refuses the address, which no live path reaches.
    pub fn mint_content(&self, home: &Address) -> Result<(Address, M3Rec), MintError> {
        if !self.is_registered_document(home) {
            return Err(MintError::HomeNotRegistered); // P6/C2
        }
        self.mint_on(&content_ns(home), NO_PUBLICATION_STATE)
            .map_err(MintError::Gate)
    }

    /// Returns the next `count` content addresses under `home`, in one record.
    ///
    /// Their namespace is `(b_C(home), 1)`, the first at element field
    /// `[s_C, m+1]` and the rest at the ordinals after it — byte for byte the
    /// addresses `count` calls of [`M3State::mint_content`] would issue (B2),
    /// the one [`M3Rec::AllocateRange`] advancing the frontier by `count`
    /// where those calls would advance it one record at a time. [M5: INSERT
    /// and the publish shot, for a run of single-byte values M4 stores as one
    /// stretch.] The same gate as `mint_content` (P6/C2), the same key
    /// ([`M3State::content_lock_key`]`(home)`) held before the closure, the
    /// same staging obligation ([`M3Rec::Allocate`] states it): called on the
    /// transaction's working state, its record staged there before the next
    /// mint on the chain, which then issues `first ⊕ count`.
    ///
    /// # Errors
    ///
    /// `HomeNotRegistered` where `home` is no registered document; `Gate`
    /// where M1's TA5a gate refuses the first address, which no live path
    /// reaches.
    ///
    /// # Panics
    ///
    /// Panics on a zero `count`, on every build, against the precondition
    /// `count ≥ 1`: a range of nothing moves no frontier, so the chain's next
    /// mint would issue its first address again, and its record is refused at
    /// decode, so no replay could read the journal that held it. The caller's
    /// bug is answered before any record exists; M5's staging site passes the
    /// length of a stretch, which is at least one.
    pub fn mint_content_range(
        &self,
        home: &Address,
        count: &Nat,
    ) -> Result<(Address, M3Rec), MintError> {
        assert!(
            *count != Nat::default(),
            "mint_content_range precondition: count ≥ 1 — a content range mints at least one address"
        );
        if !self.is_registered_document(home) {
            return Err(MintError::HomeNotRegistered); // P6/C2
        }
        let first = self.next_in(&content_ns(home)).map_err(MintError::Gate)?;
        Ok((
            first.clone(),
            M3Rec::AllocateRange(RangeAllocation { first, count: count.clone() }),
        ))
    }

    /// Returns the next link address under `home`, with its record (§3).
    ///
    /// Its namespace is `(b_L(home), 1)` and its element field `[s_L, m+1]`.
    /// [M7: every link deposit — MAKELINK, EDITLINK, `emit`, `assert_sup`,
    /// `nullify`] To realize it, the caller holds
    /// [`M3State::link_lock_key`]`(home)`, calls this on that transaction's
    /// working state and stages the returned [`M3Rec`] there, before its next
    /// mint on the chain ([`M3Rec::Allocate`]).
    ///
    /// # Errors
    ///
    /// `HomeNotRegistered` where `home` is no registered document; `Gate`
    /// where the inc gate refuses the address, which no live path reaches.
    pub fn mint_link(&self, home: &Address) -> Result<(Address, M3Rec), MintError> {
        if !self.is_registered_document(home) {
            return Err(MintError::HomeNotRegistered); // L1a
        }
        self.mint_on(&link_ns(home), NO_PUBLICATION_STATE)
            .map_err(MintError::Gate)
    }

    /// Returns the next version identity of `source`, with its record.
    ///
    /// Its namespace is `(source, 1)` — the version chain, kept separate from
    /// the document chain (ASN-0123). [M5: owned CREATENEWVERSION; the publish
    /// shot's member] To realize it, the caller holds
    /// [`M3State::version_lock_key`]`(source)`, calls this on that
    /// transaction's working state and stages the returned [`M3Rec`] there,
    /// before its next mint on the chain ([`M3Rec::Allocate`]).
    ///
    /// `published` is the resolved bit the version is born with, stamped on
    /// the `Allocate` exactly as passed (PUB-8.18): the three-valued flag and
    /// its absent ⇒ inherit `published(source)` rule are the calling
    /// composite's to resolve off its own working state (PUB-8.17), and this
    /// mint applies no default of its own — a version of a private source
    /// passed `true` is born published and passed `false` private, the
    /// composite's choice both times. The write-path refusals that bound
    /// that choice (PUB-2.7, PUB-2.9) are applied ahead of this mint by the
    /// composite that resolves the flag (PUB-kickoff D2b), not by this mint.
    ///
    /// # Errors
    ///
    /// `SourceNotRegistered` where `source` is no registered document, an
    /// unregistered address and a registered non-document alike; `Gate` where
    /// the inc gate refuses the address, which no live path reaches.
    pub fn mint_version(
        &self,
        source: &Address,
        published: bool,
    ) -> Result<(Address, M3Rec), MintError> {
        if !self.is_registered_document(source) {
            // V-WF: registered Document (covers unregistered and non-document).
            return Err(MintError::SourceNotRegistered);
        }
        self.mint_on(&version_ns(source), published)
            .map_err(MintError::Gate)
    }

    /// Returns the next document identity under `account`, with its record.
    ///
    /// Its namespace is `(account, 2)`. [CREATENEWDOCUMENT; cross-owner
    /// VERSION; fork] To realize it, the caller holds
    /// [`M3State::document_lock_key`]`(account)`, calls this on that
    /// transaction's working state and stages the returned [`M3Rec`] there,
    /// before its next mint on the chain ([`M3Rec::Allocate`]).
    ///
    /// `published` is the resolved bit the document is born with, stamped on
    /// the `Allocate` exactly as passed (PUB-8.18) — never the caller's
    /// three-valued flag, and never a default of this mint's own. In
    /// particular the empty-account rule (PUB-8.21: a flagless first mint is
    /// born published) belongs to the create path and lives in
    /// [`crate::Namespace::create_new_document`], which resolves it before
    /// calling here; a cross-owner `version` into an empty account passes
    /// whatever bit its composite resolved (PUB-8.17), and a `false` there
    /// mints private. Whether that first mint is refused is the daemon's
    /// door, not M3's (PUB-kickoff D2c): its mint-first door refuses a
    /// `version` into an empty account whatever the bit, where PUB-8.20's
    /// door refuses an explicit-`false` first create.
    ///
    /// # Errors
    ///
    /// `NotAnAccount` where `account` is no registered account, an
    /// unregistered address and a registered non-account alike; `Gate` where
    /// the inc gate refuses the address, which no live path reaches.
    pub fn mint_document(
        &self,
        account: &Address,
        published: bool,
    ) -> Result<(Address, M3Rec), MintError> {
        if !self.is_registered_account(account) {
            // P8/CND.pre (covers unregistered and non-account).
            return Err(MintError::NotAnAccount);
        }
        self.mint_on(&document_ns(account), published)
            .map_err(MintError::Gate)
    }

    /// Returns the next account identity under `parent`, with its record.
    ///
    /// Its namespace is `(parent, 2)` under a node and `(parent, 1)` under an
    /// account — the sixth family (Conflicts §8), whose `g` the chain-family
    /// rule picks. [`crate::Namespace::delegate`]
    ///
    /// `None`, never a [`MintError`], unless `parent` is a registered node or
    /// account: its callers are in this crate — `delegate`, which already has
    /// a typed rejection for that one refusal, and the peek
    /// [`M3State::next_account_prefix`] — so a fifth `MintError` leaf would
    /// put a permanently dead arm in M5's, M7's and M10's vocabularies for a
    /// mint none of them can reach.
    ///
    /// To realize it, the caller holds
    /// [`M3State::account_lock_key`]`(parent)`, calls this on that
    /// transaction's working state and stages the returned [`M3Rec`] there,
    /// before its next mint on the chain ([`M3Rec::Allocate`]);
    /// [`M3State::next_account_prefix`] is this without the record — the
    /// peek, which also answers `None` past the depth cap. `delegate`, its one
    /// caller that stages the record, also seats every prefix this mints, in
    /// the same transaction, which is what makes an account's seat its
    /// allocation ([`crate::Namespace::delegate`]); a second such caller owes
    /// the same seat.
    pub(crate) fn mint_account(&self, parent: &Address) -> Option<(Address, M3Rec)> {
        if !matches!(self.entity_level(parent)?, Level::Node | Level::Account) {
            return None;
        }
        Some(
            self.mint_on(&account_ns(parent), NO_PUBLICATION_STATE)
                .expect("a registered node/account anchor with g ≤ 2 passes TA5a"),
        )
    }
}

// ---------------------------------------------------------------------------
// §A The two peeks — each its chain's mint without the record. Called
// without staging, a mint answers the next address on its chain and moves
// nothing; two chains publish that answer as a read: `next_account_prefix`
// for the account chain, the next-form `delegate` demands, and
// `next_content_address` for the content chain, the content-frontier read
// (AUTH-6.38). They are §C reads by role and live here because of what they
// call: each calls its chain's mint, and the mints call `query`'s gates, so
// with the peeks beside the mints the two files depend one way. Every mint
// answers the same way unstaged; the allocation suite's determinism
// assertions rely on it.
// ---------------------------------------------------------------------------

impl M3State {
    /// Peeks the next delegable account-tier prefix under `parent`.
    ///
    /// It is the exact value `delegate` will demand as next-form (O17c), so a
    /// caller obtains a valid `new_prefix` instead of guess-and-retry on
    /// `NotNextForm`. It is the account chain's mint — the one `delegate`
    /// makes — without the record, so the value a caller peeks and the value
    /// the gate compares come off one chain by one code path. `g` follows
    /// `parent`'s level: a node ⇒ the `(parent, 2)` account chain; an account
    /// ⇒ the `(parent, 1)` sub-account chain (the sixth chain family ASN-0042
    /// licenses — Conflicts §8). Both yield zeros = 1. Pure frontier read off
    /// any snapshot; `None` for two reasons, and both are monotone, so a
    /// `Some` answer never regresses: `parent` is not a registered node or
    /// account (E is append-only), or the slot it names would exceed
    /// [`MAX_PRINCIPAL_COMPONENTS`], which is a compiled constant. That
    /// second refusal is here so the peek and `delegate`'s `TooDeep` gate
    /// read one bound and no caller is handed a prefix the gate refuses. The
    /// returned prefix still faces `delegate`'s full in-closure gate — two
    /// racing peeks of the same value leave exactly one winner.
    pub fn next_account_prefix(&self, parent: &Address) -> Option<Address> {
        self.mint_account(parent)
            .map(|(addr, _)| addr)
            .filter(|addr| addr.tumbler().len() <= MAX_PRINCIPAL_COMPONENTS)
    }

    /// Peeks the content chain's next address under `home`.
    ///
    /// It is the content address [`M3State::mint_content`]`(home)` would
    /// issue, past the chain's frontier: the content-frontier read's answer
    /// (AUTH-6.38, "the home's mint frontier at N"), one of the four
    /// chain-end reads, beside [`M3State::next_account_prefix`] and of its
    /// shape — the mint without its record, so the value a reader peeks and
    /// the value the next mint issues come off one chain by one code path.
    /// That read and the wire's `content_frontier` say *frontier* for this
    /// next ordinal; M3 says it for the count a chain stores, at or below
    /// which every member's ordinal lies and past which this address lies.
    /// Pure frontier read off any snapshot; `None` where `home` is not a
    /// registered document (E is append-only, so a `Some` never regresses to
    /// `None`), which is [`MintError::HomeNotRegistered`]'s one cause read as
    /// an absence. The ordinal only grows, and every value `home` ever minted
    /// — arranged, deleted, or never placed — lies below it, so the read says
    /// nothing of what they hold. It is the document's mint count plus one on
    /// every document but one: on [`crate::ghost_home_document`]'s content
    /// chain the first member lands past the ghost region, so there the
    /// ordinal is the mint count plus [`crate::GHOST_POSITIONS`] + 1, and the
    /// read counts that document's mints only once the floor is taken off.
    pub fn next_content_address(&self, home: &Address) -> Option<Address> {
        match self.mint_content(home) {
            Err(MintError::HomeNotRegistered) => None,
            minted => Some(minted.expect("k = 1 passes TA5a on every anchor").0),
        }
    }
}
