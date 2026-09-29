//! The AUTH session layer and write-path gates (spec parts 03/04/06): the
//! two origin sets and their publication, the challenge/response handshake,
//! the sessions store and per-request resolution, the credential write lock
//! and the pinned refusal producers it scopes, and the identity fold the
//! daemon composes BESIDE the engine.
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
//! The identity fold is DERIVED state: rebuilt from the recovered world at
//! open (`fold::canonical_identity`) and advanced from every committed
//! credential deposit at runtime, under the credential write lock. It is
//! never persisted by this crate — the journal remains the one source of
//! truth.

// What the rest of the daemon reaches.
pub(crate) mod fold;
pub(crate) mod policy;
pub(crate) mod session;

// What only this module reaches.
mod blocked;
mod entropy;
mod entry;
mod lock;
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
use skep_febe::{ReqId, SessionId};
use skep_identity::LinkDeposit;

use crate::codec::obj;
use crate::World;
use fold::{CredMemo, IdentityFold};
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
/// the credential write lock, the identity fold, and the credential
/// idempotency memo.
pub(crate) struct AuthState {
    pub cfg: AuthConfig,
    pub challenges: Challenges,
    pub sessions: Sessions,
    pub credential_lock: CredentialLock,
    pub fold: IdentityFold,
    pub memo: CredMemo,
    /// The blocked-prefix list's supply channel; `None` where the operator
    /// named no file, and the list then stays empty for the process's life.
    blocked_supply: Option<BlockedSupply>,
}

impl AuthState {
    /// Assemble at daemon open: the fold is seeded from the RECOVERED world
    /// (the canonical rebuild — derived state, never a second persistence
    /// layer), and the blocked-prefix list is installed from the START-UP
    /// SUPPLY (AUTH-4.70; RES-115) — after the fold, whose claimant the
    /// install's comparands read.
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
            fold: IdentityFold::seeded(fold::canonical_identity(world)),
            memo: CredMemo::new(),
            blocked_supply,
        };
        state.install_blocked(&state.credential_lock.write(), issue);
        Ok(state)
    }

    /// One install, whole: the issue compared against the two INERT
    /// comparands (AUTH-4.36 step 4b) — the header's, the claimant taken
    /// where it names none, the off-board test read against the node prefix
    /// in force — and the result swapped in under the credential write lock.
    /// The claimant is read HERE, under that lock, because the claim commits
    /// only under it: the comparands an install resolves are the ones in
    /// force at its own position.
    fn install_blocked(&self, lock: &LockWrite<'_>, issue: BlockedIssue) {
        let claimant = self.fold.snapshot().claimant().cloned();
        let list = BlockedPrefixes::installed_under(issue, claimant.as_ref(), self.cfg.node_prefix());
        self.cfg.install_blocked(lock, list);
    }

    /// THE CLAIM FLIP's half of the install (RES-65 item 4: "at the install,
    /// and again at the claim flip where the flip makes an entry inert").
    /// The claimant is the comparand wherever the header names none, and it
    /// is set ONCE, by the claim — so the issue in force is re-compared at
    /// that one transition, under the write guard the claim itself commits
    /// under.
    ///
    /// Answers NOTHING: whether the flip is worth a log line is the log's
    /// question, and the list in force answers it
    /// ([`BlockedPrefixes::issue_is_empty`]) at the site that writes the
    /// line. This install keeps the issue's entries, so that read is the
    /// same either side of it.
    pub fn reinstall_blocked_at_claim(&self, lock: &LockWrite<'_>) {
        let issue = self.cfg.blocked_prefixes().issue().clone();
        self.install_blocked(lock, issue);
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
    /// takes a lock the channel knows nothing about.
    pub fn reissue_blocked_prefixes(&self) -> Option<Reissue> {
        self.blocked_supply
            .as_ref()?
            .reissue(|issue| self.install_blocked(&self.credential_lock.write(), issue))
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
    /// ONE fold snapshot for the whole object, so `claimant` and
    /// `signed_origins` cannot straddle the claim between THEMSELVES;
    /// `/health`'s own card states the straddle its independent reads still
    /// admit.
    pub fn auth_object(&self) -> Value {
        let identity = self.fold.snapshot();
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

    /// The credential path's committed tail (AUTH-3.43), whole and under
    /// the write guard the caller already holds: advance the fold from the
    /// deposit this write committed, memoize the marshaled ack under the
    /// frame's id (AUTH-7.20's first horn), and answer whether this step
    /// flipped the board claimed — the claim-flip warning's trigger.
    ///
    /// One method because the three are one obligation: a fold advanced
    /// without its memo entry replays nothing on retry, and a memo entry
    /// stored without the fold step memoizes an ack for a state the fold
    /// never reached. `world_post` is the POST-COMMIT snapshot — the ctx
    /// the deposit's own commit is visible in.
    ///
    /// The returned flip is [`fold::IdentityFold::step_committed`]'s, and a
    /// COMMAND's answer for the reason stated there: it is a property of
    /// the transition, which no read of the resulting state recovers.
    pub fn commit_tail(
        &self,
        lock: &LockWrite<'_>,
        world_post: &World,
        dep: &LinkDeposit<'_>,
        sid: SessionId,
        id: Option<ReqId>,
        ack: &[u8],
    ) -> bool {
        let flipped = self.fold.step_committed(lock, world_post, dep);
        if let Some(id) = id {
            self.memo.store(lock, sid, id, ack.to_vec());
        }
        flipped
    }
}
