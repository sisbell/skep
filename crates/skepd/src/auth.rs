//! The AUTH session layer and write-path gates (spec parts 03/04/06): the
//! two origin sets and their publication, the challenge/response handshake,
//! the sessions store and per-request resolution, the credential write lock
//! and the pinned refusal producers it scopes, and the daemon's readers of
//! the World's identity slice.
//!
//! And, since signed ops (the seam build 2026-09-25), the write-path
//! signature seam: the ENTRY frame the daemon composes for an attested
//! write (`entry`), and the check that verifies a presented `attest` over it
//! against the fold's key set before the transaction (`policy`, behind the
//! RES-26 gate). The HYBRID signature's frozen rules are not here:
//! `skep-signature` is the one crate that links the signature libraries;
//! skepd calls its verify (AUTH-2.2) and its all-halves decode, and builds
//! none of its signer's side — the daemon itself holds no key and never
//! signs. That signer is handed a seed and knows nothing of where one is
//! kept: custody-agnostic still.
//!
//! Custody-agnostic by ruling (D1): nothing here knows where a private key
//! lives — the handshake verifies signatures over bytes, deposits commit
//! records carrying pubkeys, `key_set` reads records.
//!
//! The identity fold is the ENGINE's (AUTH-2.79–2.88): the World carries
//! the key table and the claim as its identity slice, `World::apply` steps
//! it at each credential deposit's commit, and every checkpoint carries it —
//! so this crate holds no fold of its own, rebuilds none at open and
//! advances none at runtime. Every reader here takes the slice off the one
//! World snapshot it already holds (`skep_identity::HasIdentity`), so the
//! world a check reads and the table it reads are one committed state. The
//! credential write lock stays: it is what makes the precheck and the
//! execute it gates one atomic step (AUTH-3.3), which no slice placement
//! supplies.

// What the rest of the daemon reaches.
pub(crate) mod policy;
pub(crate) mod session;

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
pub(crate) use blocked::Reissue;
pub(crate) use entropy::OsEntropy;
pub(crate) use lock::LockWrite;
pub(crate) use origin::startup_warnings;

use std::collections::BTreeSet;
use std::io;
use std::path::Path;

use serde_json::Value;
use skep_address::Address;
use skep_febe::{ReqId, SessionId};
use skep_identity::{HasIdentity, IdentityState, KeySet};
use skep_namespace::HasM3;

use crate::codec::obj;
use crate::World;
use memo::CredMemo;
use session::{Challenges, Sessions};

// Names this module and its own files use: its children reach them as
// `super::…`, and nothing outside `auth` names them.
use blocked::{BlockedIssue, BlockedPrefixes, BlockedSupply};
use lock::{CredentialLock, LockRead};
use options::{AuthConfig, Mode};
use origin::{bare_origins, signed_origins};

/// The challenge store's default cap (AUTH-1.48): live nonces retained;
/// past it the oldest is evicted. Entered into the store once, at `new`.
const MAX_LIVE_NONCES: usize = 4096;

/// The whole auth state one daemon holds: config, the two ephemeral stores,
/// the credential write lock, and the credential idempotency memo. The
/// identity table is NOT here: it is the World's slice, read off whichever
/// snapshot a caller holds.
pub(crate) struct AuthState {
    pub cfg: AuthConfig,
    pub challenges: Challenges,
    pub sessions: Sessions,
    pub credential_lock: CredentialLock,
    pub memo: CredMemo,
    /// The blocked-prefix list's supply channel; `None` where the operator
    /// named no file, and the list then stays empty for the process's life.
    blocked_supply: Option<BlockedSupply>,
}

impl AuthState {
    /// Assemble at daemon open over the RECOVERED world — whose identity
    /// slice the engine resolved at load (AUTH-2.86: the daemon serves from
    /// the resolved World) — and install the blocked-prefix list from the
    /// START-UP SUPPLY (AUTH-4.70; RES-115) against the claimant that slice
    /// names.
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

    /// One install, whole: the issue compared against the two INERT
    /// comparands (AUTH-4.36 step 4b) — the header's, the claimant taken
    /// where it names none, the off-board test read against the node prefix
    /// in force — and the result swapped in under the credential write lock.
    /// `identity` is the slice of the world in force at the install — read
    /// under that lock by the caller, because the claim commits only under
    /// it: the comparands an install resolves are the ones in force at its
    /// own position.
    fn install_blocked(&self, lock: &LockWrite<'_>, issue: BlockedIssue, identity: &IdentityState) {
        let list =
            BlockedPrefixes::installed_under(issue, identity.claimant(), self.cfg.node_prefix());
        self.cfg.install_blocked(lock, list);
    }

    /// THE CLAIM FLIP's half of the install (RES-65 item 4: "at the install,
    /// and again at the claim flip where the flip makes an entry inert").
    /// The claimant is the comparand wherever the header names none, and it
    /// is set ONCE, by the claim — so the issue in force is re-compared at
    /// that one transition, under the write guard the claim itself commits
    /// under, against `identity`, the POST-COMMIT world's slice, which names
    /// the claimant the flip seated.
    ///
    /// Answers NOTHING: whether the flip is worth a log line is the log's
    /// question, and the list in force answers it
    /// ([`BlockedPrefixes::issue_is_empty`]) at the site that writes the
    /// line. This install keeps the issue's entries, so that read is the
    /// same either side of it.
    pub fn reinstall_blocked_at_claim(&self, lock: &LockWrite<'_>, identity: &IdentityState) {
        let issue = self.cfg.blocked_prefixes().issue().clone();
        self.install_blocked(lock, issue, identity);
    }

    /// THE REISSUE CHANNEL's daemon half (AUTH-4.70 "RE-ISSUED to the
    /// running daemon without restart"): where the supply file MOVED since
    /// it was last looked at, re-read it and install the new issue under
    /// the credential write lock. `None` where nothing moved — the ordinary
    /// request's answer, at the cost of one `stat`.
    ///
    /// PRECONDITION: the caller holds NO credential lock and no
    /// serialization lock — this takes the credential write lock.
    /// [`crate::Daemon`] calls it at the head of routing, ahead of every lock
    /// a request takes, which is also what makes the kill exact: a request
    /// that arrives after the file moved installs the issue BEFORE it
    /// resolves its own actor.
    ///
    /// A re-read that FAILS installs nothing (the list is replaced WHOLE or
    /// not at all): the list in force stands, the refusal is returned for
    /// the log ONCE, and the file is not retried until it moves again.
    ///
    /// The look itself is [`BlockedSupply::reissue`]'s — the file's identity
    /// is that type's own knowledge. What this half owns is the INSTALL, which
    /// takes a lock the channel knows nothing about, and the claimant it
    /// compares against is read through `head_identity` UNDER that lock —
    /// the head's slice as it stands once no credential write can land — so
    /// the comparands an install resolves are the ones in force at its own
    /// position, as they were when the daemon held a fold of its own.
    pub fn reissue_blocked_prefixes(
        &self,
        head_identity: impl Fn() -> IdentityState,
    ) -> Option<Reissue> {
        self.blocked_supply.as_ref()?.reissue(|issue| {
            let lock = self.credential_lock.write();
            let identity = head_identity();
            self.install_blocked(&lock, issue, &identity)
        })
    }

    /// The supply file's path, for the log; `None` where none was named.
    pub fn blocked_supply_path(&self) -> Option<&Path> {
        self.blocked_supply.as_ref().map(|s| s.path.as_path())
    }

    /// `/health`'s `auth` OBJECT (AUTH-6.13), rendered HERE because this is
    /// where its state lives — the convention `auth/` keeps for everything
    /// else it publishes ([`origin::Warning`]'s `Display`,
    /// [`AuthConfig::node_prefix_line`], [`BlockedPrefixes::log_lines`]), and
    /// the one the codec's module doc states for a transport shape: built
    /// where its state lives, deterministic through [`crate::codec::obj`].
    ///
    /// Four members, each published VERBATIM from the function that answers
    /// it, so the published list and the arm's own rule are ONE rule: the
    /// claimant from the fold, `local_trust` from the config, and the TWO
    /// origin sets from [`bare_origins`] and [`signed_origins`]. NO `mode`
    /// field — the negative pin, and it belongs beside [`Mode`], which says
    /// why: the wire publishes the PAIR and the client derives the mode, so
    /// the type is the daemon's and not the wire's.
    ///
    /// ONE slice for the whole object — `identity`, off the one world
    /// snapshot the route took — so `claimant` and `signed_origins` cannot
    /// straddle the claim between THEMSELVES; `/health`'s own card states
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

    /// The credential path's committed tail (AUTH-3.43), under the write
    /// guard the caller already holds: memoize the marshaled ack under the
    /// frame's id (AUTH-7.20's first horn), and answer whether this commit
    /// flipped the board claimed — the claim-flip warning's trigger — read
    /// off the two slices the caller holds, the locked snapshot's before the
    /// commit and the post-commit snapshot's after it.
    ///
    /// The fold step that stood here is the ENGINE's now (AUTH-2.80): the
    /// deposit's commit stepped the World's slice inside the transaction that
    /// committed it, so `after` already holds the deposit folded, and nothing
    /// here can fall behind the world — a panic between the commit and this
    /// tail costs the memo entry alone, never a key.
    ///
    /// The flip is a property of the TRANSITION, which no read of one state
    /// recovers: a claimant present in `after` was absent in `before` iff
    /// THIS commit seated it, and the claim is set once (AUTH-2.67, I6).
    ///
    /// E4, checkable here as it was at the live step (precheck ≡ fold): a
    /// committed credential deposit was classified `Honored` under the gate
    /// against `before`'s world, and the fold, stepping the same deposit over
    /// the post-commit world, honors it too — every honored verdict MOVES the
    /// slice (a genesis or an enrollment adds a key, a retirement moves one, a
    /// claim seats the claimant), so an unmoved slice names a broken E4. The
    /// head writer's own commits inside this step (`H.1`) touch no credential
    /// and move nothing here.
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

/// The key set `world` holds for an address — its own identity slice's —
/// or `None` when the address is not an account: the ONE account-hood test
/// both `/op` (the head snapshot) and `/op-at` (the reconstructed world)
/// call, so the two routes cannot diverge on it, and the account-hood and
/// the table stand on one committed state by construction (AUTH-6.20:
/// "`/op-at` on the reconstructed World, the slice riding in it"). The
/// rendering is [`crate::codec::key_set_reply`]'s, where every wire shape
/// this crate emits is rendered.
pub(crate) fn key_set_of<'a>(world: &'a World, account: &Address) -> Option<&'a KeySet> {
    world.m3().is_registered_account(account).then(|| world.identity().key_set(account))
}
