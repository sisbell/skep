//! The AUTH session layer and write-path gates (spec parts 03/04/06).
//!
//! It holds the two origin sets and their publication, the
//! challenge/response handshake, the sessions store and per-request
//! resolution, the credential write lock and the pinned refusal producers it
//! scopes, and the daemon's readers of the World's identity slice.
//!
//! It also holds the write-path signature seam: the entry frame the daemon
//! composes for an attested write (`entry`), and the check that verifies a
//! presented `attest` over it against the fold's key set before the
//! transaction (`policy`, behind the RES-26 gate). The hybrid signature's
//! frozen rules are not here: `skep-signature` is the one crate that links
//! the signature libraries; skepd calls its verify (AUTH-2.2) and its
//! all-halves decode, and builds none of its signer's side — the daemon
//! itself holds no key and never signs. That signer is handed a seed and
//! knows nothing of where one is kept, so it too is custody-agnostic.
//!
//! Custody-agnostic (R1-kickoff D1): nothing here knows where a private key
//! lives — the handshake verifies signatures over bytes, deposits commit
//! records carrying pubkeys, `key_set` reads records.
//!
//! The identity fold is the engine's (AUTH-2.79–2.88): the World carries the
//! key table and the claim as its identity slice, `World::apply` steps it at
//! each credential deposit's commit, and every checkpoint carries it — so
//! this crate holds no fold of its own, rebuilds none at open and advances
//! none at runtime. Every reader here takes the slice off the one World
//! snapshot it already holds (`skep_identity::HasIdentity`), so the world a
//! check reads and the table it reads are one committed state. The
//! credential write lock is this crate's: it is what makes the precheck and
//! the execute it gates one atomic step (AUTH-3.3), which no slice placement
//! supplies.

// What the rest of the daemon reaches.
pub mod policy;
pub mod session;

// What only this module reaches.
mod blocked;
mod entropy;
mod entry;
mod lock;
mod memo;
mod options;
mod origin;
mod prefix;

pub use options::{AuthOptions, PortAlreadyBound};
pub use origin::{NotCanonical, Origin};
pub use prefix::{NodePrefix, NotANodePrefix};

// What the rest of the daemon names from here, and nothing more.
pub use blocked::Reissue;
pub use entropy::OsEntropy;
pub use lock::LockWrite;
pub use origin::startup_warnings;
// What the daemon reaches through `AuthState`'s fields and the answers of
// the items above — each `pub` so the type it holds or is handed is
// nameable where it is held.
pub use blocked::{BlockedHeader, BlockedPrefixes};
pub use lock::{CredentialLock, LockRead};
pub use memo::CredMemo;
pub use options::{AuthConfig, Mode};
pub use origin::Warning;

use std::collections::BTreeSet;
use std::io;
use std::path::Path;

use serde_json::Value;
use skep_address::Address;
use skep_febe::{ReqId, SessionId};
use skep_identity::{HasIdentity, IdentityState, KeySet};
use skep_namespace::HasM3;
use skep_util::json::obj;

use skep_engine::World;
use session::{Challenges, Sessions};

// Names this module and its own files use: its children reach them as
// `super::…` or `crate::auth::…`.
use blocked::{BlockedIssue, BlockedSupply};
use origin::{bare_origins, signed_origins};

/// The challenge store's default cap on live nonces (AUTH-1.48).
///
/// Past it the oldest is evicted. It is entered into the store once, at
/// `new`, and read by the daemon's line for the store's first live
/// eviction, which names the bound it met (`operations.md` §1.1 m12) — a
/// memory bound and never an abuse bound, so the figure says what the store
/// holds and nothing of who asked.
pub const MAX_LIVE_NONCES: usize = 4096;

/// The whole auth state one daemon holds.
///
/// It is the config, the two ephemeral stores, the credential write lock,
/// the credential idempotency memo, and the blocked-prefix list's supply
/// channel. The identity table is not here: it is the World's slice, read
/// off whichever snapshot a caller holds.
pub struct AuthState {
    /// The session layer's configuration, as the options became it.
    pub cfg: AuthConfig,
    /// The challenge store: the live nonces, capped (AUTH-1.48).
    pub challenges: Challenges,
    /// The sessions store: every live binding, by token (AUTH-4.23).
    pub sessions: Sessions,
    /// The credential write lock (AUTH-3.3).
    pub credential_lock: CredentialLock,
    /// The credential write sequence's idempotency memo.
    pub memo: CredMemo,
    /// The blocked-prefix list's supply channel.
    ///
    /// `None` where the operator named no file, and the list then stays
    /// empty for the process's life.
    blocked_supply: Option<BlockedSupply>,
}

impl AuthState {
    /// Assembles the auth state at daemon open over the recovered world.
    ///
    /// The engine resolved that world's identity slice at load (AUTH-2.86:
    /// the daemon serves from the resolved World). The open installs the
    /// blocked-prefix list from the start-up supply (AUTH-4.70; RES-115)
    /// against the claimant that slice names.
    ///
    /// # Errors
    ///
    /// Fails only on that supply: a file the options name that cannot be
    /// read, is not a list, or is past the channel's byte cap
    /// (`MAX_BLOCKED_SUPPLY_BYTES`). An operator condition — a daemon that
    /// started on an empty list instead would lapse every standing block in
    /// silence, which is the one thing "supplied at every start" rules out.
    pub fn open(opts: AuthOptions, world: &World) -> io::Result<AuthState> {
        let (blocked_supply, issue) = match opts.blocked_supply_path.as_deref() {
            Some(path) => {
                let (supply, issue) = BlockedSupply::open(path)?;
                (Some(supply), issue)
            }
            None => (None, BlockedIssue::default()),
        };
        let state = AuthState {
            cfg: AuthConfig::new(opts),
            challenges: Challenges::new(MAX_LIVE_NONCES),
            sessions: Sessions::new(),
            credential_lock: CredentialLock::new(),
            memo: CredMemo::new(),
            blocked_supply,
        };
        state.install_blocked(&state.credential_lock.write(), issue, world.identity());
        Ok(state)
    }

    /// Installs one issue, whole, under the credential write lock.
    ///
    /// The issue is compared against the two inert comparands (AUTH-4.36
    /// step 4b) — the header's, the claimant taken where it names none, the
    /// off-board test read against the node prefix in force — and the result
    /// swapped in. `identity` is the slice of the world in force at the
    /// install — read under that lock by the caller, because the claim
    /// commits only under it: the comparands an install resolves are the
    /// ones in force at its own position.
    fn install_blocked(&self, lock: &LockWrite<'_>, issue: BlockedIssue, identity: &IdentityState) {
        let list =
            BlockedPrefixes::installed_under(issue, identity.claimant(), self.cfg.node_prefix());
        self.cfg.install_blocked(lock, list);
    }

    /// Re-installs the issue in force at the claim flip (RES-65 item 4).
    ///
    /// This is the claim flip's half of the install: "at the install, and
    /// again at the claim flip where the flip makes an entry inert". The
    /// claimant is the comparand wherever the header names none, and it is
    /// set once, by the claim — so the issue in force is re-compared at that
    /// one transition, under the write guard the claim itself commits under,
    /// against `identity`, the post-commit world's slice, which names the
    /// claimant the flip seated.
    ///
    /// It answers nothing: whether the flip is worth a log line is the log's
    /// question, and the list in force answers it
    /// ([`BlockedPrefixes::issue_is_empty`]) at the site that writes the
    /// line. This install keeps the issue's entries, so that read is the
    /// same either side of it.
    pub fn reinstall_blocked_at_claim(&self, lock: &LockWrite<'_>, identity: &IdentityState) {
        let issue = self.cfg.blocked_prefixes().issue().clone();
        self.install_blocked(lock, issue, identity);
    }

    /// Re-reads a moved supply file and installs its issue (AUTH-4.70).
    ///
    /// This is the reissue channel's daemon half — "re-issued to the running
    /// daemon without restart": where the supply file moved since it was last
    /// looked at, it re-reads the file and installs the new issue under the
    /// credential write lock. `None` where nothing moved — the ordinary
    /// request's answer, at the cost of one `stat`.
    ///
    /// **Precondition.** The caller holds no credential lock and no
    /// serialization lock — this takes the credential write lock.
    /// `skepd::Daemon` calls it at the head of routing, ahead of every lock
    /// a request takes, which is also what makes the kill exact: a request
    /// that arrives after the file moved installs the issue *before* it
    /// resolves its own actor.
    ///
    /// A re-read that fails installs nothing (the list is replaced whole or
    /// not at all): the list in force stands, the refusal is returned for
    /// the log once, and the file is not retried until it moves again.
    ///
    /// The look itself is `BlockedSupply::reissue`'s — the file's identity
    /// is that type's own knowledge. What this half owns is the install,
    /// which takes a lock the channel knows nothing about, and the claimant
    /// it compares against is read through `head_identity` — called at most
    /// once, under that lock, and not at all where nothing moved or the
    /// re-read failed — the head's slice as it stands once no credential
    /// write can land, so the comparands an install resolves are the ones in
    /// force at its own position.
    pub fn reissue_blocked_prefixes(
        &self,
        head_identity: impl FnOnce() -> IdentityState,
    ) -> Option<Reissue> {
        self.blocked_supply.as_ref()?.reissue(|issue| {
            let lock = self.credential_lock.write();
            let identity = head_identity();
            self.install_blocked(&lock, issue, &identity)
        })
    }

    /// Returns the supply file's path for the log; `None` where none was named.
    pub fn blocked_supply_path(&self) -> Option<&Path> {
        self.blocked_supply.as_ref().map(|s| s.path.as_path())
    }

    /// Returns `/health`'s `auth` object (AUTH-6.13).
    ///
    /// It is rendered here because this is where its state lives — the
    /// convention `auth/` keeps for everything else it publishes
    /// ([`origin::Warning`]'s `Display`, [`AuthConfig::node_prefix_line`],
    /// [`BlockedPrefixes::log_lines`]), and the one the codec's module doc
    /// states for a transport shape: built where its state lives,
    /// deterministic through [`skep_util::json::obj`].
    ///
    /// Four members, each published verbatim from the function that answers
    /// it, so the published list and the arm's own rule are one rule: the
    /// claimant from the fold, `local_trust` from the config, and the two
    /// origin sets from `bare_origins` and `signed_origins`. No `mode`
    /// field — the negative pin, and it belongs beside [`Mode`], which says
    /// why: the wire publishes the pair and the client derives the mode, so
    /// the type is the daemon's and not the wire's.
    ///
    /// One slice for the whole object — `identity`, off the one world
    /// snapshot the route took — so `claimant` and `signed_origins` cannot
    /// straddle the claim between themselves; `/health`'s own card states
    /// the straddle its independent reads still admit.
    pub fn auth_object(&self, identity: &IdentityState) -> Value {
        let claimed = identity.claimant().is_some();
        let origins = |set: BTreeSet<Origin>| {
            Value::Array(set.iter().map(|o| Value::String(o.as_str().to_string())).collect())
        };
        obj(vec![
            (
                "claimant",
                identity
                    .claimant()
                    .map(|a| Value::String(a.tumbler().to_string()))
                    .unwrap_or(Value::Null),
            ),
            ("local_trust", Value::Bool(self.cfg.local_trust)),
            ("origins", origins(bare_origins(&self.cfg))),
            ("signed_origins", origins(signed_origins(&self.cfg, claimed))),
        ])
    }

    /// Runs the credential path's committed tail (AUTH-3.43).
    ///
    /// Under the write guard the caller already holds, it memoizes the
    /// marshaled ack under the frame's id (AUTH-7.20's first horn), and
    /// answers whether this commit flipped the board claimed — the
    /// claim-flip warning's trigger — read off the two slices the caller
    /// holds, the locked snapshot's before the commit and the post-commit
    /// snapshot's after it.
    ///
    /// The fold step is the engine's (AUTH-2.80): the deposit's commit steps
    /// the World's slice inside the transaction that commits it, so `after`
    /// already holds the deposit folded, and nothing here can fall behind
    /// the world — a panic between the commit and this tail costs the memo
    /// entry alone, never a key.
    ///
    /// The flip is a property of the transition, which no read of one state
    /// recovers: a claimant present in `after` was absent in `before` iff
    /// *this* commit seated it, and the claim is set once (AUTH-2.67, I6).
    ///
    /// # Panics
    ///
    /// Panics in a debug build where the slice did not move. E4 (precheck ≡
    /// fold) is checkable here: a committed credential deposit was
    /// classified `Honored` under the gate against `before`'s world, and the
    /// fold, stepping the same deposit over the post-commit world, honors it
    /// too — every honored verdict moves the slice (a genesis or an
    /// enrollment adds a key, a retirement moves one, a claim seats the
    /// claimant), so an unmoved slice names a broken E4. The head writer's
    /// own commits inside this step (`H.1`) touch no credential and move
    /// nothing here.
    pub fn commit_tail(
        &self,
        lock: &LockWrite<'_>,
        before: &IdentityState,
        after: &IdentityState,
        sid: SessionId,
        id: Option<ReqId>,
        ack: &[u8],
    ) -> bool {
        debug_assert!(
            before != after,
            "a committed credential deposit must fold honored and move the slice (E4)"
        );
        if let Some(id) = id {
            self.memo.store(lock, sid, id, ack.to_vec());
        }
        before.claimant().is_none() && after.claimant().is_some()
    }
}

// ── the key_set read's identity half (AUTH-6.18–6.20) ────────────────────

/// Returns `world`'s key set for `account`, or `None` for a non-account.
///
/// The set is `world`'s own identity slice's. This is the one account-hood
/// test both `/op` (the head snapshot) and `/op-at` (the reconstructed world)
/// call, so the two routes cannot diverge on it, and the account-hood and
/// the table stand on one committed state by construction (AUTH-6.20:
/// "`/op-at` on the reconstructed World, the slice riding in it"). The
/// rendering is [`crate::codec::key_set_reply`]'s, where the operation
/// channel's shapes are rendered.
pub fn key_set_of<'a>(world: &'a World, account: &Address) -> Option<&'a KeySet> {
    world.m3().is_registered_account(account).then(|| world.identity().key_set(account))
}
