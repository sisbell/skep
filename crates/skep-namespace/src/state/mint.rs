//! §A, beneath [`M3State`]: the lock keys a transaction holds, the five mints
//! that read their frontiers, and the account chain's peek
//! ([`M3State::next_account_prefix`]), which is the account mint without its
//! record. An `impl M3State` child of `state`: it reaches the frontier
//! arithmetic (`next_in`) the way a child does, and keeps `mint_on`, the mint
//! behind the five, private to itself, so no other module reaches that mint
//! except through one of the five gates.

use skep_address::{Address, GateViolation, Level};
use skep_kernel::{LockKey, Space};

use super::{M3Rec, M3State, MAX_PRINCIPAL_COMPONENTS, NO_PUBLICATION_STATE};
use crate::error::MintError;
use crate::ns::{account_ns, content_ns, document_ns, link_ns, ns_lock_key, version_ns, NsKey};

// ---------------------------------------------------------------------------
// §A The lock-key constructors: one per chain, and the two registry keys.
// ---------------------------------------------------------------------------

impl M3State {
    /// Content-chain `LockKey`: `(b_C(home), 1)` (§1/§3). Pairs with
    /// [`M3State::mint_content`]`(home)` — take it for `transact`'s `keys`
    /// BEFORE the closure; the mint inside READS this key's frontier, and the
    /// [`M3Rec`] you stage ADVANCES it. Never a coarser `(home_doc, g)` key:
    /// the three g = 1 chains under one document — content `(b_C(d), 1)`,
    /// link `(b_L(d), 1)`, version `(d, 1)` — get three DISTINCT locks
    /// (B7/B8).
    ///
    /// Total on every [`Address`], and the caller's one obligation is to pass
    /// the SAME `home` the paired mint receives. A `home` below the document
    /// tier yields a key whose anchor is outside T4 — harmless, since a lock
    /// key is only ever compared, and the paired mint refuses that `home`
    /// `HomeNotRegistered` a moment later.
    pub fn content_lock_key(home: &Address) -> LockKey {
        ns_lock_key(&content_ns(home))
    }

    /// Link-chain `LockKey`: `(b_L(home), 1)` (§1/§3). Pairs with
    /// [`M3State::mint_link`]`(home)` — take it BEFORE the closure; the mint
    /// inside READS this key's frontier, and the [`M3Rec`] you stage ADVANCES
    /// it. Same obligation and same latitude as
    /// [`M3State::content_lock_key`]: pass the mint's own `home`, and a
    /// wrong-tier one costs only the key's own T4-validity, which nothing
    /// reads.
    pub fn link_lock_key(home: &Address) -> LockKey {
        ns_lock_key(&link_ns(home))
    }

    /// Version-chain `LockKey`: `(source, 1)` — SEPARATE from the document
    /// chain below (ASN-0123 VD). Pairs with
    /// [`M3State::mint_version`]`(source, published)` — take it BEFORE the
    /// closure; the mint inside READS this key's frontier, and the [`M3Rec`]
    /// you stage ADVANCES it.
    ///
    /// Total on every [`Address`], and the anchor is the argument itself, so
    /// the key is T4-valid whatever tier arrives. What a wrong tier costs is
    /// not well-formedness but IDENTITY: `(A, 1)` under an account is the
    /// SUB-ACCOUNT chain's key, not a version chain's. Harmless, since a lock
    /// key is only ever compared and the paired mint refuses that `source`
    /// `SourceNotRegistered` a moment later — but the caller's one obligation
    /// is to pass the SAME `source` the mint receives.
    pub fn version_lock_key(source: &Address) -> LockKey {
        ns_lock_key(&version_ns(source))
    }

    /// Document-chain `LockKey`: `(account, 2)`. Pairs with
    /// [`M3State::mint_document`]`(account, published)` — take it BEFORE the
    /// closure; the mint inside READS this key's frontier, and the [`M3Rec`]
    /// you stage ADVANCES it.
    ///
    /// Same shape as [`M3State::version_lock_key`]: total on every
    /// [`Address`], T4-valid whatever tier arrives because the anchor is the
    /// argument itself, and a wrong tier names a DIFFERENT chain — `(N, 2)`
    /// under a node is the ACCOUNT chain's key. Harmless for the same reason,
    /// and the caller's one obligation is the same: pass the mint's own
    /// `account`, which it refuses `NotAnAccount` a moment later if it is
    /// not one.
    pub fn document_lock_key(account: &Address) -> LockKey {
        ns_lock_key(&document_ns(account))
    }

    /// Account-chain `LockKey`: `(parent, 2)` under a node, `(parent, 1)`
    /// under an account — the one family whose `g` the chain-family rule
    /// picks (Conflicts §8). Pairs with [`M3State::mint_account`]`(parent)`
    /// — take it BEFORE the closure; the mint inside READS this key's
    /// frontier, and the [`M3Rec`] you stage ADVANCES it. `pub(crate)` for
    /// the reason the mint is: `delegate` is the only caller and lives in
    /// this crate.
    pub(crate) fn account_lock_key(parent: &Address) -> LockKey {
        ns_lock_key(&account_ns(parent))
    }

    /// THE single global principal-registry key (NOT per-subtree — §8 / Open
    /// build decisions "Serialization granularity"). LOAD-BEARING in
    /// `delegate`: serializes its fresh-prefix top-down / next-form /
    /// authorization reads against concurrent same-namespace delegations AND
    /// its id-freshness read against concurrent same-id delegations — the id
    /// race is CROSS-namespace (same `new_id`, different `new_prefix`), which
    /// no per-namespace key can serialize. Held DEFENSIVELY by
    /// `create_new_document` (its ω read is stale-safe — ω of an *existing*
    /// account is stable, §6/§8). Redundant under M2 v1's global applier lock.
    /// `pub(crate)` because only this crate's ops take it: a store that took
    /// it as well would, under a per-key M2, serialize itself against every
    /// delegation in the docuverse.
    pub(crate) fn principals_lock_key() -> LockKey {
        LockKey::new(Space::Principals, &[])
    }

    /// THE single global node-registry key — one key for the whole registry,
    /// argument-free like [`M3State::principals_lock_key`] and plural for the
    /// same reason: two `register_node` calls for DIFFERENT nodes contend on
    /// it. Held by `register_node` so a concurrent duplicate `RegisterNode`
    /// surfaces `NotFresh` instead of silently coalescing. Node admission
    /// needs NO lock for SAFETY (idempotent `OrdSet` insert, monotone
    /// freshness); this only preserves the typed rejection under per-key
    /// concurrency. Redundant under v1's global lock, exactly like
    /// [`M3State::principals_lock_key`], and `pub(crate)` for the same reason:
    /// `register_node` is the only op that takes it.
    pub(crate) fn nodes_lock_key() -> LockKey {
        LockKey::new(Space::Nodes, &[])
    }
}

// ---------------------------------------------------------------------------
// §A The five pure mints — one per chain, covering the corpus's six
// families, since `mint_account` serves both account-tier families
// (`A_account(N)` under a node and the sub-account `(A, 1)` under an
// account, whose `g` the chain-family rule picks). So every address M3
// originates is minted here. Four are public and fold into M5/M7 composites
// (M2 contract 3); the fifth, `mint_account`, is `pub(crate)` because
// `delegate` is its only caller and lives in this crate.
//
// Each is a query: it reads WORKING state, checks one structural
// precondition, and hands back the next address on its chain together with
// the single `M3Rec` that realizes it. Advancing the frontier is the
// CALLER's half — hold the paired `*_lock_key` across the transaction and
// stage the returned record in it — and it is an obligation nothing here can
// enforce, because the record is delivered inside a tuple the caller has
// already destructured.
//
// The cost of dropping it is stated rather than guarded: a mint whose record
// is never staged leaves the frontier where it stood, so the next mint on
// that chain hands out the SAME address, and the fold's contiguity check
// cannot see it — the second `Allocate` is legitimately `m + 1`. So "an
// address is never reused" is M3's to keep GIVEN the caller's half; unmet,
// nothing in the system says so.
//
// So a mint is also the chain's PEEK: called without staging it answers the
// next address and moves nothing, which is what `next_account_prefix`
// publishes for the account chain and what the determinism assertions here
// ask of the other four.
// ---------------------------------------------------------------------------

impl M3State {
    /// The mint behind the five mints: the next address on the chain `key`
    /// names and the ONE [`M3Rec`] that realizes it, stamped `published` — a
    /// caller's RESOLVED bit on a document chain, [`NO_PUBLICATION_STATE`] on
    /// every other. The address and its record leave together, which is what
    /// makes the key a mint reads and the key its record advances one key
    /// (§A); each public mint is this behind its own structural gate.
    fn mint_on(&self, key: &NsKey, published: bool) -> Result<(Address, M3Rec), GateViolation> {
        let addr = self.next_in(key)?;
        Ok((addr.clone(), M3Rec::Allocate { addr, published }))
    }

    /// Next content address under `home`: namespace `(b_C(home), 1)`, element
    /// field `[s_C, m+1]` (§3). [M5: INSERT] Reads the caller's WORKING state
    /// (successive mints in one composite each see the prior mint); checks
    /// only the structural precondition P6/C2; to realize it, the caller holds
    /// [`M3State::content_lock_key`] and stages the returned [`M3Rec`].
    pub fn mint_content(&self, home: &Address) -> Result<(Address, M3Rec), MintError> {
        if !self.is_registered_document(home) {
            return Err(MintError::HomeNotRegistered); // P6/C2
        }
        self.mint_on(&content_ns(home), NO_PUBLICATION_STATE)
            .map_err(MintError::Gate)
    }

    /// Next link address under `home`: namespace `(b_L(home), 1)`, element
    /// field `[s_L, m+1]` (§3). [M7: MAKELINK] To realize it, the caller holds
    /// [`M3State::link_lock_key`]`(home)` and stages the returned [`M3Rec`].
    pub fn mint_link(&self, home: &Address) -> Result<(Address, M3Rec), MintError> {
        if !self.is_registered_document(home) {
            return Err(MintError::HomeNotRegistered); // L1a
        }
        self.mint_on(&link_ns(home), NO_PUBLICATION_STATE)
            .map_err(MintError::Gate)
    }

    /// Next version identity: namespace `(source, 1)` — the version chain,
    /// kept SEPARATE from the document chain (ASN-0123). [M5: owned
    /// CREATENEWVERSION] To realize it, the caller holds
    /// [`M3State::version_lock_key`]`(source)` and stages the returned
    /// [`M3Rec`].
    ///
    /// `published` is the RESOLVED bit the version is born with, stamped on
    /// the `Allocate` exactly as passed (PUB-8.18): the three-valued flag and
    /// its ABSENT ⇒ INHERIT `published(source)` rule are the CALLING
    /// composite's to resolve off its own working state (PUB-8.17), and this
    /// mint applies no default of its own — a version of a private source
    /// passed `true` is born published and passed `false` private, the
    /// composite's choice both times. The write-path refusals that bound
    /// that choice (PUB-2.7, PUB-2.9) are applied ahead of this mint by the
    /// composite that resolves the flag (owner ruling D2b), not by this mint.
    pub fn mint_version(
        &self,
        source: &Address,
        published: bool,
    ) -> Result<(Address, M3Rec), MintError> {
        if !self.is_registered_document(source) {
            // V-WF: registered Document (covers unregistered AND non-document).
            return Err(MintError::SourceNotRegistered);
        }
        self.mint_on(&version_ns(source), published)
            .map_err(MintError::Gate)
    }

    /// Next document identity under an account: namespace `(account, 2)`.
    /// [CREATENEWDOCUMENT; cross-owner VERSION; fork] To realize it, the
    /// caller holds [`M3State::document_lock_key`]`(account)` and stages the
    /// returned [`M3Rec`].
    ///
    /// `published` is the RESOLVED bit the document is born with, stamped on
    /// the `Allocate` exactly as passed (PUB-8.18) — never the caller's
    /// three-valued flag, and NEVER a default of this mint's own. In
    /// particular the empty-account rule (PUB-8.21: a flagless FIRST mint is
    /// born published) belongs to the CREATE path and lives in
    /// [`crate::Namespace::create_new_document`], which resolves it before
    /// calling here; a cross-owner `version` into an empty account passes
    /// whatever bit its composite resolved (PUB-8.17), and a `false` there
    /// mints private. Whether that first mint is REFUSED (PUB-8.20) is the
    /// daemon's door, not M3's (owner ruling D2c).
    pub fn mint_document(
        &self,
        account: &Address,
        published: bool,
    ) -> Result<(Address, M3Rec), MintError> {
        if !self.is_registered_account(account) {
            // P8/CND.pre (covers unregistered AND non-account).
            return Err(MintError::NotAnAccount);
        }
        self.mint_on(&document_ns(account), published)
            .map_err(MintError::Gate)
    }

    /// Next account identity under `parent`: namespace `(parent, 2)` under a
    /// node, `(parent, 1)` under an account — the sixth family (Conflicts §8),
    /// whose `g` the chain-family rule picks. [`crate::Namespace::delegate`]
    ///
    /// `None`, never a [`MintError`], unless `parent` is a REGISTERED node or
    /// account: `delegate` is the only caller, it is in this crate, and it
    /// already has a typed rejection for that one refusal — a fifth
    /// `MintError` leaf would put a permanently dead arm in M5's, M7's and
    /// M10's vocabularies for a mint none of them can reach.
    ///
    /// To realize it, the caller holds
    /// [`M3State::account_lock_key`]`(parent)` and stages the returned
    /// [`M3Rec`]; [`M3State::next_account_prefix`] is this without the record,
    /// which is the peek. Its one caller also seats every prefix this mints,
    /// in the same transaction, which is what makes an account's seat its
    /// allocation ([`crate::Namespace::delegate`]); a second caller owes the
    /// same seat.
    pub(crate) fn mint_account(&self, parent: &Address) -> Option<(Address, M3Rec)> {
        if !matches!(self.entity_level(parent)?, Level::Node | Level::Account) {
            return None;
        }
        Some(
            self.mint_on(&account_ns(parent), NO_PUBLICATION_STATE)
                .expect("a registered node/account anchor with g ≤ 2 passes TA5a"),
        )
    }

    /// Peek the next delegable account-tier prefix under `parent` — the exact
    /// value `delegate` will demand as next-form (O17c), so a caller obtains a
    /// valid `new_prefix` instead of guess-and-retry on `NotNextForm`. It is
    /// [`M3State::mint_account`] without the record, so the value a caller
    /// peeks and the value the gate compares come off one chain by one code
    /// path. `g` follows `parent`'s level: a node ⇒ the `(parent, 2)` account
    /// chain; an account ⇒ the `(parent, 1)` sub-account chain (the sixth
    /// chain family ASN-0042 licenses — Conflicts §8). Both yield zeros = 1.
    /// Pure frontier read off any snapshot; `None` for two reasons, and both
    /// are monotone, so a `Some` answer never regresses: `parent` is not a
    /// REGISTERED node or account (E is append-only), or the slot it names
    /// would exceed [`MAX_PRINCIPAL_COMPONENTS`], which is a compiled
    /// constant. That second refusal is here so the peek and `delegate`'s
    /// `TooDeep` gate read one bound and no caller is handed a prefix the
    /// gate refuses. The returned prefix still faces `delegate`'s full
    /// in-closure gate — two racing peeks of the same value leave exactly one
    /// winner.
    pub fn next_account_prefix(&self, parent: &Address) -> Option<Address> {
        self.mint_account(parent)
            .map(|(addr, _)| addr)
            .filter(|addr| addr.tumbler().len() <= MAX_PRINCIPAL_COMPONENTS)
    }
}
