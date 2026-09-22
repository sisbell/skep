//! The AUTH session layer and write-path gates (spec parts 03/04/06): the
//! two origin sets and their publication, the challenge/response handshake,
//! the sessions store and per-request resolution, the credential write lock
//! and the pinned refusal producers it scopes, and the identity fold the
//! daemon composes BESIDE the engine.
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

pub(crate) mod fold;
pub(crate) mod policy;
pub(crate) mod session;

use std::collections::BTreeSet;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::SystemTime;

use ed25519_dalek::VerifyingKey;
use rand_core::{CryptoRng, RngCore};
use serde_json::{Map, Value};
use skep_address::{validate, Address, Level, Nat, Tumbler};
use skep_febe::{ReqId, SessionId};
use skep_identity::{LinkDeposit, PublicKey};
use skep_namespace::prefix_contains;

use crate::codec::{check_keys, wire_address};
use crate::World;
use fold::{CredMemo, IdentityFold};
use session::{Challenges, Sessions};

/// The challenge store's default cap (AUTH-1.48): live nonces retained;
/// past it the oldest is evicted. Entered into the store once, at `new`.
pub(crate) const MAX_LIVE_NONCES: usize = 4096;

/// The most bytes one ISSUE of the blocked-prefix list may carry
/// ([`BlockedSupply`]), refused before the read rather than after it.
///
/// The cap bounds the FAILURE case and not the legitimate one: an entry is
/// two addresses in the registry's global form under a small JSON wrapper,
/// under a hundred bytes, so this admits order 90,000 standing takedown
/// records — four orders of magnitude above a board's plausible list. What
/// it removes is the unbounded one, which is a path that is NOT a list: a
/// read-to-end followed by a whole `serde_json::Value` over those bytes, at
/// the ~20× transient heap this crate prices on [`crate::body_cap`]. It is
/// paid at [`AuthState::open`] before the listener binds, where the open
/// promises a named refusal rather than a hang; and at every reissue with
/// the supply's `seen` HELD at the head of routing, so every in-flight
/// request waits on it, `/health` and `/session` included.
///
/// The number is [`crate::body_cap`]'s own largest admitted input, cited
/// rather than re-derived: this file carries strictly less per record than a
/// frame does, so the same ceiling is the same headroom or more.
const MAX_BLOCKED_SUPPLY_BYTES: usize = 8 * 1024 * 1024;

/// The daemon's session-layer configuration, as the operator supplies it:
/// the local-trust flag (Phase A default ON — a hosted image must set it
/// AFFIRMATIVELY false, AUTH-4.57 (i)) and the configured origins
/// (AUTH-4.7: configure what the board is actually reachable at).
///
/// `#[non_exhaustive]`, paired with the [`Default`] below: a caller starts
/// from the defaults and sets what it means to change, so a knob added
/// later arrives at its default rather than breaking every construction.
/// The OPPOSITE call from [`crate::HttpRequest`], deliberately — a field
/// there is a fact about the request that a caller must supply, and one
/// added silently would be answered from a default the caller never chose;
/// here every field is an operator's option and abstention is the safe
/// state, which is the whole shape of `local_trust`'s own ruling.
///
/// From outside this crate that starting-and-setting is the MUTATION form:
/// `#[non_exhaustive]` bars a struct expression, functional update syntax
/// (`..Default::default()`) included, so the shape this file's own tests use
/// is in-crate only.
///
/// ```
/// use skepd::AuthOptions;
///
/// let mut opts = AuthOptions::default();
/// opts.local_trust = false;
/// // …and whatever else this caller means to change; a knob added later
/// // arrives at its own default rather than at whatever a literal omitted.
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AuthOptions {
    /// Bare binds honored on loopback after the claim (CLAIMED-PERMISSIVE)
    /// when true; ENFORCING when false. Pre-claim the flag is not consulted:
    /// the board is UNCLAIMED whatever it says ([`Mode::of`], AUTH-4.26).
    pub local_trust: bool,
    /// The CONFIGURED origin set — the signed arm's whole set once claimed;
    /// unioned with the loopback defaults on the bare arm.
    ///
    /// Deliberately not `origins`: `/health` publishes a field of that name
    /// (AUTH-6.13) and it is the BARE set — configured ∪ the three loopback
    /// defaults — so copying that field back into this one re-admits the
    /// defaults the claim-time drop exists to remove.
    pub configured: Vec<Origin>,
    /// The BLOCKED-PREFIX LIST's supply (AUTH-1.44, AUTH-4.70): the file
    /// the operator maintains from the standing takedown records of
    /// the board it fronts — `--blocked-prefixes <FILE>`. SUPPLIED AT EVERY
    /// START, as `configured` is: a named file is read at open, and one
    /// that cannot be read or is not a list FAILS the open, so no restart
    /// starts the daemon on an empty list the standing records do not
    /// support. RE-ISSUED while the daemon runs by replacing the file; the
    /// format and the re-read are [`BlockedSupply`]'s. `None` is a board
    /// whose operator supplies none — the notebook — and no prefix is
    /// blocked.
    ///
    /// Deliberately not `blocked_prefixes`, as `configured` is deliberately
    /// not `origins`: [`blocked_prefixes`] is the function answering the
    /// LIST IN FORCE, and this is the path of the FILE that supplies it.
    /// The flag keeps the list's name — `--blocked-prefixes` is what an
    /// operator thinks about — and the field keeps the file's.
    pub blocked_supply_path: Option<PathBuf>,
    /// The board's full NODE PREFIX in the registry — `--node-prefix 1.N`
    /// (REG-1.69): EGRESS AND ASSERTION CONFIG, per daemon, supplied at
    /// every start as `configured` is and never a journaled genesis fact,
    /// which is what lets the same board answer to a successor under a
    /// fresh prefix — taken by a reconfigure and restart (REG-1.70). In no
    /// record, journal, sidecar or fold. The ONE thing this daemon decides
    /// by it: the blocked-prefix list's OFF-BOARD test
    /// ([`BlockedPrefixes::installed_under`]) — whether the list's configured
    /// operator account is an account of this board — read against this
    /// prefix and never against the local root `1`, under which every
    /// address in the registry's global form would read as this board's own
    /// (REG-1.66). `None` is a board that has not been told its prefix: the
    /// notebook, or a hosted board mis-launched — and that test is then OFF,
    /// every operator reading as on-board, the start-up log saying so.
    ///
    /// The FORM is [`NodePrefix`]'s, carried by the type: a `Some` is a node
    /// address strictly under the root because nothing else can be built.
    pub node_prefix: Option<NodePrefix>,
}

impl Default for AuthOptions {
    fn default() -> AuthOptions {
        AuthOptions {
            local_trust: true,
            configured: Vec::new(),
            blocked_supply_path: None,
            node_prefix: None,
        }
    }
}

/// The resolved configuration the auth surface reads: options plus the
/// BOUND port, which exists only once the listener does. `serve` sets it;
/// a socket-free embedder that wants origin-set behavior calls
/// [`crate::Daemon::bind_auth_port`] itself. Until set there is no port and
/// so no loopback defaults — origin membership then admits only what an
/// explicit `--origin` names, which is the honest degenerate for a daemon
/// that is not serving, and which [`AuthConfig::port`] says in its type
/// rather than through a sentinel every reader has to carve around.
///
/// Beside the members the BLOCKED-PREFIX LIST (AUTH-1.44): daemon config as
/// `configured` is, never board state — in no record, journal, sidecar or
/// fold — and the one member RE-ISSUED WHILE THE DAEMON RUNS, which is why
/// it alone sits behind a lock. Read through [`blocked_prefixes`]; replaced
/// whole by [`AuthConfig::install_blocked`], under the credential write
/// gate. And the NODE PREFIX (REG-1.69), fixed at open as `configured` is:
/// a fresh one is a reconfigure and restart (REG-1.70), so it sits behind
/// no lock, and every install of the list reads the one in force.
pub(crate) struct AuthConfig {
    pub local_trust: bool,
    pub configured: BTreeSet<Origin>,
    port: OnceLock<u16>,
    /// The list IN FORCE. The `RwLock` makes the swap of one pointer safe
    /// for readers that hold no credential lock (the handshake, the route
    /// level's `resolve`); what ORDERS an install against the writes it
    /// ends is the credential write gate its installer holds.
    blocked: parking_lot::RwLock<Arc<BlockedPrefixes>>,
    /// [`AuthOptions::node_prefix`], as supplied; `None` where the daemon
    /// was told none.
    node_prefix: Option<NodePrefix>,
}

impl AuthConfig {
    fn new(opts: AuthOptions) -> AuthConfig {
        AuthConfig {
            local_trust: opts.local_trust,
            configured: opts.configured.into_iter().collect(),
            port: OnceLock::new(),
            // Empty until [`AuthState::open`] installs the start-up supply.
            blocked: parking_lot::RwLock::new(Arc::new(BlockedPrefixes::default())),
            node_prefix: opts.node_prefix,
        }
    }

    /// The node prefix in force (REG-1.69), or `None` where the daemon was
    /// told none — the one reader is the list's install, and the log.
    pub fn node_prefix(&self) -> Option<&NodePrefix> {
        self.node_prefix.as_ref()
    }

    /// The start-up line's text: the node prefix in force, or its absence
    /// — said once, at start, whether or not a list is supplied, because a
    /// hosted board launched without its prefix has its off-board test OFF
    /// and would otherwise learn so only at its first install.
    pub fn node_prefix_line(&self) -> String {
        match &self.node_prefix {
            Some(prefix) => format!(
                "node prefix {prefix} (--node-prefix): egress and assertion config, never \
                 journaled; the blocked-prefix list's off-board test runs against it"
            ),
            None => "no --node-prefix: the off-board test is off (every operator account reads \
                     as this board's own); a hosted board must supply one"
                .to_string(),
        }
    }

    /// THE INSTALL (AUTH-4.70): the list REPLACED WHOLE, atomically, under
    /// the credential write gate the caller holds and names here (AUTH-3.3)
    /// — that install being the list's COMMIT. The guard is the obligation,
    /// not a decoration: every session-authenticated write re-resolves
    /// under that gate, so a covered session's write that took the gate
    /// first lands BEFORE this install and one arriving after meets its
    /// death (AUTH-4.63's second trigger) — no `/changes` entry of a killed
    /// session carries a position after it.
    fn install_blocked(&self, _lock: &LockWrite<'_>, list: BlockedPrefixes) {
        *self.blocked.write() = Arc::new(list);
    }

    /// [`PortAlreadyBound`] carries the port ALREADY BOUND — the number
    /// every live session's origin set was established against, which is
    /// what a caller disagreeing about it needs to be told. The value is set
    /// ONCE, so a second bind would otherwise be a silent no-op.
    /// [`crate::serve`] and a socket-free embedder are the two callers, and
    /// they are exclusive by design.
    ///
    /// PRECONDITION: `port != 0`, and it stops here loudly rather than being
    /// admitted — the posture [`crate::serve`] takes on a zero worker count,
    /// for the same reason: it is a caller's bug and not an outcome.
    /// [`AuthConfig::port`] states that zero is not a port this daemon can
    /// serve on, and zero is the one value that makes [`Origin::from_parts`]
    /// build text [`Origin::parse`] refuses — `http://127.0.0.1:0` fails the
    /// leading-zero clause. Admitted, it fires that constructor's debug
    /// assert on every request that reads a derived origin, and in release
    /// publishes a `/health` origin set whose members this daemon's own
    /// parser rejects and no `Origin` header can match. `serve` cannot reach
    /// it (the OS never assigns port 0 to a bound listener), so the one
    /// caller is the socket-free embedder.
    pub fn bind_port(&self, port: u16) -> Result<(), PortAlreadyBound> {
        assert!(port != 0, "port 0 is not a port this daemon can serve on");
        self.port.set(port).map_err(|_| {
            PortAlreadyBound(self.port().expect("set once, so a refusal means one is bound"))
        })
    }

    /// The bound port, or `None` while no listener exists. An `Option`
    /// rather than a zero: port 0 is not a port this daemon can serve on,
    /// and a sentinel would make every reader of a derived origin carve the
    /// case out for itself.
    pub fn port(&self) -> Option<u16> {
        self.port.get().copied()
    }
}

/// The board's MODE (wire.md §Identity: "the board is always in exactly one
/// of three MODES, derived from two facts `GET /health` publishes"). The ONE
/// place the corpus's three names are said in the code rather than
/// re-derived as a conjunction of `claimed` and `local_trust`.
///
/// UNCLAIMED admits only the claim ceremony's own write shapes and honors
/// bare loopback binds; CLAIMED-PERMISSIVE honors them still (the default's
/// disclosed cost, which [`Warning::ClaimedWithLocalTrust`] names);
/// ENFORCING refuses every bare session, so only signed sessions write.
///
/// Derived and never stored: the claim lives in the identity fold and the
/// flag in [`AuthConfig`], so a mode value is always a reading of the pair
/// as of one snapshot. The wire publishes the PAIR and deliberately no
/// `mode` field (AUTH-6.13), which is why this type is the daemon's and not
/// the wire's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    Unclaimed,
    ClaimedPermissive,
    Enforcing,
}

impl Mode {
    /// The mode this config is in at a snapshot whose claim is `claimed` —
    /// the pair, read once, so a caller states the mode it means rather than
    /// the conjunction that computes it.
    pub fn of(cfg: &AuthConfig, claimed: bool) -> Mode {
        match (claimed, cfg.local_trust) {
            // Pre-claim the flag is not consulted (AUTH-4.26).
            (false, _) => Mode::Unclaimed,
            (true, true) => Mode::ClaimedPermissive,
            (true, false) => Mode::Enforcing,
        }
    }
}

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
    /// ([`MAX_BLOCKED_SUPPLY_BYTES`]). An operator condition — a daemon that
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
    /// in force — and the result swapped in under the write gate. The
    /// claimant is read HERE, under that gate, because the claim commits
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
        let issue = blocked_prefixes(&self.cfg).issue.clone();
        self.install_blocked(lock, issue);
    }

    /// THE REISSUE CHANNEL's daemon half (AUTH-4.70 "RE-ISSUED to the
    /// running daemon without restart"): where the supply file MOVED since
    /// it was last looked at, re-read it and install the new issue under
    /// the credential write gate. `None` where nothing moved — the ordinary
    /// request's answer, at the cost of one `stat`.
    ///
    /// PRECONDITION: the caller holds NO credential lock and no
    /// serialization lock — this takes the write gate. [`crate::Daemon`]
    /// calls it at the head of routing, ahead of every lock a request takes,
    /// which is also what makes the kill exact: a request that arrives after
    /// the file moved installs the issue BEFORE it resolves its own actor.
    ///
    /// A re-read that FAILS installs nothing (the list is replaced WHOLE or
    /// not at all): the list in force stands, the refusal is returned for
    /// the log ONCE, and the file is not retried until it moves again.
    ///
    /// The look itself is [`BlockedSupply::reissue`]'s — the file's identity
    /// is that type's own knowledge. What this half owns is the INSTALL, which
    /// takes a gate the channel knows nothing about.
    pub fn reissue_blocked_prefixes(&self) -> Option<Reissue> {
        self.blocked_supply
            .as_ref()?
            .reissue(|issue| self.install_blocked(&self.credential_lock.write(), issue))
    }

    /// The supply file's path, for the log; `None` where none was named.
    pub fn blocked_supply_path(&self) -> Option<&Path> {
        self.blocked_supply.as_ref().map(|s| s.path.as_path())
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

// ── the credential write lock (AUTH-3.1–3.3) ─────────────────────────────

/// The credential write lock: serializes credential-changing writes against
/// every other session-authenticated write. Writer-preferring by
/// requirement (AUTH-3.2); `parking_lot::RwLock` satisfies it (task-fair: a
/// waiting writer blocks new readers), which is the existence proof
/// AUTH-7.18 records — the REQUIREMENT binds, not the crate.
///
/// `auth/` holds exactly this one lock, so its guards are unqualified.
/// What the lock SCOPES is a different thing and wears a different word:
/// the refusal rules it serializes are the GATES (`publish_gate`,
/// `pre_claim_gate`, the precheck's ordered slots), which is wire.md's
/// term for a rule that refuses a write.
pub(crate) struct CredentialLock(parking_lot::RwLock<()>);

/// The read guard, newtyped so a function whose contract is "under the read
/// lock" names it in its arguments (AUTH-3.3).
pub(crate) struct LockRead<'a>(#[allow(dead_code)] parking_lot::RwLockReadGuard<'a, ()>);

/// The write guard — the credential path's.
pub(crate) struct LockWrite<'a>(#[allow(dead_code)] parking_lot::RwLockWriteGuard<'a, ()>);

impl CredentialLock {
    pub fn new() -> CredentialLock {
        CredentialLock(parking_lot::RwLock::new(()))
    }

    pub fn read(&self) -> LockRead<'_> {
        LockRead(self.0.read())
    }

    pub fn write(&self) -> LockWrite<'_> {
        LockWrite(self.0.write())
    }
}

// ── OS entropy (AUTH-4.13) ───────────────────────────────────────────────

/// The daemon's one production RNG: every draw comes from the OS
/// (`getrandom`), so a token or nonce is never a function of process state.
/// Implements `rand_core`'s `CryptoRng` because the declared signatures on
/// the auth surface carry that bound (AUTH-4.19, AUTH-4.23).
pub(crate) struct OsEntropy;

impl RngCore for OsEntropy {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_ne_bytes(b)
    }

    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_ne_bytes(b)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        // Fail-stop: a board that cannot draw OS entropy must not mint
        // credentials from anything weaker.
        getrandom::fill(dest).expect("OS entropy unavailable");
    }
}

impl CryptoRng for OsEntropy {}

// ── the signature seam (AUTH-2.2, AUTH-2.99) ─────────────────────────────

/// The verifier for one enrolled key, or `None` when its raw form is not a
/// canonical Ed25519 point — THE place this crate turns a
/// [`skep_identity::PublicKey`] into a verifier.
///
/// One function because two callers must agree: [`session::verify`] is what
/// a signature actually meets, and [`policy::precheck`]'s slot (4)
/// (`undecodable_key`) refuses a deposit BECAUSE such a key could never
/// sign — a courtesy that holds only while the two decode alike. A stricter
/// deposit test refuses an enrollment that would have worked; a laxer one
/// seats a key that occupies a slot against [`policy::MAX_ENROLLED_KEYS`]
/// and is walked by `find_signer` on every handshake attempt, permanently,
/// since retiring it needs an anchor session of that account.
///
/// `from_bytes` is the canonical point decode (the crate pick is argued in
/// `Cargo.toml`), and the 32-byte width is what refuses a key of another
/// algorithm rather than reading its bytes as an Ed25519 one — the one
/// place `skep_identity::ALGS` would be consulted if this crate ever
/// verified a second.
pub(crate) fn verifying_key(key: &PublicKey) -> Option<VerifyingKey> {
    let raw = <[u8; 32]>::try_from(key.raw()).ok()?;
    VerifyingKey::from_bytes(&raw).ok()
}

// ── origins (AUTH-4.1–4.8) ───────────────────────────────────────────────

/// One canonical web origin: `scheme://host[:port]`, lowercase, no path, no
/// trailing slash, the scheme's default port OMITTED (AUTH-4.2). `parse`
/// admits ONLY the canonical text, so `parse(s).as_str() == s` for every
/// admitted `s` and the handshake's already-canonical check IS this parse.
///
/// The canonical text is the whole value; `https` and `host` sit beside it
/// because they are what tells a LOOPBACK-HOST origin
/// ([`Origin::names_loopback_host`]), which is the one question anything
/// asks of an origin's parts. No resolved port is kept: an origin's port is
/// IN that text (omitted at the scheme's default, which is what makes the
/// text canonical), and every other reader asks only for membership, which
/// the text decides — the admission rule above makes it determine the rest.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Origin {
    canonical: String,
    https: bool,
    host: String,
}

impl Origin {
    /// Parse a canonical origin; `None` for anything else — uppercase, a
    /// path, a trailing slash, `null`, an explicit default port, a
    /// zero-padded port.
    pub fn parse(s: &str) -> Option<Origin> {
        let (https, rest) = if let Some(r) = s.strip_prefix("http://") {
            (false, r)
        } else if let Some(r) = s.strip_prefix("https://") {
            (true, r)
        } else {
            return None;
        };
        let (host, port_text) = if let Some(after) = rest.strip_prefix('[') {
            // Bracketed IPv6 host.
            let close = after.find(']')?;
            let host = &rest[..close + 2];
            match &after[close + 1..] {
                "" => (host, None),
                p => (host, Some(p.strip_prefix(':')?)),
            }
        } else {
            match rest.split_once(':') {
                Some((h, p)) => (h, Some(p)),
                None => (rest, None),
            }
        };
        if host.is_empty() || !host_is_canonical(host) {
            return None;
        }
        let default = if https { 443 } else { 80 };
        if let Some(p) = port_text {
            // The two conditions std does NOT perform: a leading zero is
            // not canonical, and `u16::from_str` would accept a leading
            // `+`. Emptiness and the range are its own — an empty or
            // over-65535 port fails the parse here.
            if p.starts_with('0') || !p.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            // Canonical form omits the scheme's default port.
            if p.parse::<u16>().ok()? == default {
                return None;
            }
        }
        Some(Origin { canonical: s.to_string(), https, host: host.to_string() })
    }

    /// Build the canonical origin from parts — the loopback defaults'
    /// constructor. The SECOND mint site, so it owes what [`Origin::parse`]
    /// admits, and the assert is what keeps the two in step: every origin
    /// built here is one the front door would accept. Reached only for a
    /// port a listener is bound to, which is why the claim needs no
    /// exception ([`loopback_defaults`] has no port to build from until
    /// then).
    fn from_parts(https: bool, host: &str, port: u16) -> Origin {
        let scheme = if https { "https" } else { "http" };
        let default = if https { 443 } else { 80 };
        let canonical = if port == default {
            format!("{scheme}://{host}")
        } else {
            format!("{scheme}://{host}:{port}")
        };
        debug_assert!(
            Origin::parse(&canonical).is_some(),
            "from_parts built an origin the front door refuses: {canonical}"
        );
        Origin { canonical, https, host: host.to_string() }
    }

    /// The canonical text — what the wire carries and what health publishes.
    pub fn as_str(&self) -> &str {
        &self.canonical
    }

    /// Whether this origin names one of the three [`LOOPBACK_HOSTS`] over
    /// plain HTTP — the shape [`loopback_defaults`] mints, whatever port it
    /// carries. The ONE question anything asks of an origin's parts, so the
    /// parts answer it here: [`startup_warnings`]'s port-change arm is about
    /// a configured origin naming a loopback host at a port this daemon is
    /// not bound to, and this is the first half of that sentence.
    fn names_loopback_host(&self) -> bool {
        !self.https && LOOPBACK_HOSTS.contains(&self.host.as_str())
    }
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.canonical)
    }
}

/// [`Origin::parse`] refused: the text is not a canonical origin. Carries
/// no reason — the canonical form is one shape, and enumerating the ways to
/// miss it here would be a second enumeration to keep in step with
/// `parse`'s own doc.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NotCanonical;

impl fmt::Display for NotCanonical {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(
            "not a canonical origin (scheme://host[:port], lowercase, \
             the scheme's default port omitted)",
        )
    }
}

impl std::error::Error for NotCanonical {}

/// [`crate::Daemon::bind_auth_port`] refused: a port is ALREADY BOUND.
/// Carries that port — the number every live session's origin set was
/// established against, which is what a caller disagreeing about it needs
/// to be told — and not the number it offered, which it already has.
///
/// A named error rather than a bare `u16`, for [`NotCanonical`]'s reason:
/// this is an ecosystem door, and only a type carrying `Display` and
/// `std::error::Error` composes with `?` in a caller's own error type. A
/// caller cannot add either impl to an integer, and an `Err(8642)` says
/// nothing about which of the two ports it names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PortAlreadyBound(u16);

impl PortAlreadyBound {
    /// The port already bound.
    pub fn port(self) -> u16 {
        self.0
    }
}

impl fmt::Display for PortAlreadyBound {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "the auth port is already bound to {}", self.0)
    }
}

impl std::error::Error for PortAlreadyBound {}

/// The ecosystem door. [`Origin::parse`] stays: its `Option` is the
/// predicate form this module uses internally (`Origin::parse(h)
/// .is_some_and(…)`), and `FromStr` is what a generic caller — including
/// `main.rs`'s own `from_env<T: FromStr>` — can reach.
impl std::str::FromStr for Origin {
    type Err = NotCanonical;

    fn from_str(s: &str) -> Result<Origin, NotCanonical> {
        Origin::parse(s).ok_or(NotCanonical)
    }
}

/// Host canonicality: lowercase letters, digits, `.`, `-`, and the
/// bracketed-IPv6 alphabet (`[`, `]`, `:`). Uppercase anywhere refuses —
/// canonical-only admission is what makes `parse` the already-canonical
/// check.
fn host_is_canonical(host: &str) -> bool {
    host.bytes().all(|b| {
        b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-' | b'[' | b']' | b':')
    })
}

/// The three loopback-host names — the whole defaults set (AUTH-7.21: the
/// set is deliberately CLOSED at these three; a fourth member falsifies the
/// alias-drop claims silently).
const LOOPBACK_HOSTS: [&str; 3] = ["127.0.0.1", "localhost", "[::1]"];

/// The bound port's three loopback origins, canonical members, DERIVED from
/// the port — never configured, never stored (AUTH-4.1, AUTH-4.2). An
/// unbound config has no port, so it has no defaults: the set is empty
/// rather than three members at a port nothing can serve on, which is the
/// same honest degenerate stated once, in the type.
pub(crate) fn loopback_defaults(port: Option<u16>) -> BTreeSet<Origin> {
    let Some(port) = port else { return BTreeSet::new() };
    LOOPBACK_HOSTS.iter().map(|h| Origin::from_parts(false, h, port)).collect()
}

/// The BARE arm's origin set: `configured ∪ loopback_defaults(port)` in
/// EVERY mode (AUTH-4.3) — the bare arm is loopback-privileged by design
/// and the defaults never drop from it.
pub(crate) fn bare_origins(cfg: &AuthConfig) -> BTreeSet<Origin> {
    let mut set = loopback_defaults(cfg.port());
    set.extend(cfg.configured.iter().cloned());
    set
}

/// The SIGNED arm's origin set: `configured` ALONE once claimed — the
/// claim-time drop that closes the cross-board relay — else the bare set
/// (AUTH-4.3). `claimed` is the mode boundary (CLAIMED-PERMISSIVE and
/// ENFORCING alike), read from the identity fold beside the engine — the
/// spec's `&World` argument presumes the slice rides in the world, which
/// this build keeps beside it (see the build report).
pub(crate) fn signed_origins(cfg: &AuthConfig, claimed: bool) -> BTreeSet<Origin> {
    if claimed {
        cfg.configured.clone()
    } else {
        bare_origins(cfg)
    }
}

// ── startup warnings (AUTH-4.9–4.11) ─────────────────────────────────────

/// The three config-lockout warnings — evaluated at startup and at the
/// claim flip, logged both times (RES-30: unconditionally at the flip).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Warning {
    ClaimedWithLocalTrust,
    ClaimedWithEmptyConfigured,
    /// Carries the OFFENDING configured origin (AUTH-4.10), one arm each.
    ConfiguredLoopbackPortChanged(Origin),
}

impl fmt::Display for Warning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Warning::ClaimedWithLocalTrust => f.write_str(
                "board is claimed with --local-trust still on: any loopback \
                 party may write as any principal (CLAIMED-PERMISSIVE)",
            ),
            Warning::ClaimedWithEmptyConfigured => f.write_str(
                "board is claimed with no configured origin: signed_origins \
                 is empty and every signed session will be refused",
            ),
            Warning::ConfiguredLoopbackPortChanged(o) => write!(
                f,
                "configured origin {o} names a loopback host at a port this \
                 daemon is not bound to; re-issue the origin for the bound \
                 port (keys enrolled under {o} are stranded until then)",
            ),
        }
    }
}

/// The one pure warnings function (AUTH-4.9): arm 1 CLAIMED-PERMISSIVE,
/// arm 2 claimed-with-empty-configured, arm 3 the port change — pure set
/// membership over config, one arm per offending origin.
pub(crate) fn startup_warnings(cfg: &AuthConfig, claimed: bool) -> Vec<Warning> {
    let mut out = Vec::new();
    if Mode::of(cfg, claimed) == Mode::ClaimedPermissive {
        out.push(Warning::ClaimedWithLocalTrust);
    }
    if claimed && cfg.configured.is_empty() {
        out.push(Warning::ClaimedWithEmptyConfigured);
    }
    let defaults = loopback_defaults(cfg.port());
    for o in &cfg.configured {
        if o.names_loopback_host() && !defaults.contains(o) {
            out.push(Warning::ConfiguredLoopbackPortChanged(o.clone()));
        }
    }
    out
}

// ── the node prefix (REG-1.69) ───────────────────────────────────────────

/// The board's full NODE PREFIX in the registry (REG-1.69): a T4-valid NODE
/// address STRICTLY UNDER the root `1` — an org's `1.N` (REG-1.66: orgs are
/// allocated second components, `1.2`, `1.3`, …), a subnode deeper beneath
/// it (`1.3.2`). The invariant is the TYPE's, as [`Origin`]'s canonical form
/// is: every value comes through the [`FromStr`](std::str::FromStr) below,
/// so no field of this type holds the root itself (a board AT the root
/// answers to no prefix but `1`, and every address is under it — the
/// off-board test has no work there), an address under another first
/// component (REG-1.67: no other root is assigned), an account or document
/// address, or text no tumbler spells.
///
/// WHY THE TYPE AND NOT A PRECONDITION: it is the OFF-BOARD TEST's
/// comparand ([`BlockedPrefixes::installed_under`]) and nothing else, and
/// that test is `prefix_contains(node_prefix, operator)` — address
/// arithmetic, which ANSWERS for any address at all and so cannot refuse a
/// prefix that is not one. An account address there — the obvious slip, the
/// operator field it is compared against being one — or the root would yield
/// an off-board verdict meaning nothing, and a wrong verdict either lifts a
/// standing takedown block or makes the served board's claimant blockable,
/// the two cells REG-4.198 rules out. So the form is checked where a value
/// is made rather than where it is used, and the daemon that holds one holds
/// a prefix.
///
/// ONE door, where [`Origin`] keeps two: that type's `parse` exists for an
/// internal predicate use (`Origin::parse(h).is_some_and(…)`) this one has
/// none of, so `str::parse` is the whole surface — which is also what lets
/// `main.rs`'s `from_env` carry this setting like every other.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NodePrefix(Address);

impl NodePrefix {
    /// The prefix as an address — what [`prefix_contains`] takes.
    pub fn address(&self) -> &Address {
        &self.0
    }
}

impl fmt::Display for NodePrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.tumbler())
    }
}

/// [`NodePrefix`]'s parse refused: the text is not a node prefix. Carries no
/// reason, as [`NotCanonical`] carries none: the form is one shape, and this
/// states it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NotANodePrefix;

impl fmt::Display for NotANodePrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("not a node prefix (1.N — a node address strictly under the root 1)")
    }
}

impl std::error::Error for NotANodePrefix {}

/// The ecosystem door, and the ONLY one: every [`NodePrefix`] is one this
/// parse admitted, which is what makes the type's invariant a fact rather
/// than a precondition a caller owes.
impl std::str::FromStr for NodePrefix {
    type Err = NotANodePrefix;

    fn from_str(s: &str) -> Result<NodePrefix, NotANodePrefix> {
        let prefix = wire_address(s).map_err(|_| NotANodePrefix)?;
        let root = root();
        let under_root =
            prefix.level() == Level::Node && prefix != root && prefix_contains(&root, &prefix);
        under_root.then_some(NodePrefix(prefix)).ok_or(NotANodePrefix)
    }
}

/// The registry's ROOT, `1` (REG-1.66: every global address begins with it;
/// a board's OWN space is `1.x` locally, the leading `1` reading as THIS NODE
/// locally and as the root globally). The reference a [`NodePrefix`] is
/// admitted under — and NOT the off-board test's comparand: under it every
/// global-form address reads as this board's own, which is the defect the
/// node prefix exists to close.
fn root() -> Address {
    let one = Tumbler::new([Nat::from(1u32)]).expect("one component is a tumbler");
    validate(one).expect("`1` is a T4-valid node address")
}

// ── the blocked-prefix list (AUTH-1.44, AUTH-4.36 step 4b, AUTH-4.70) ────

/// One entry of the BLOCKED-PREFIX LIST (AUTH-4.36 step 4b): a prefix, and
/// the version address of the takedown record the entry cites — the ONE
/// public datum the handshake's 403 carries (AUTH-6.5). The daemon reads no
/// record and knows no takedown: `record` is echoed and never dereferenced,
/// which is why it is held as the address it was issued as and nothing
/// more.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BlockedEntry {
    pub prefix: Address,
    pub record: Address,
}

/// The list's two-field HEADER (AUTH-4.36 step 4b; AUTH-4.70 "the header
/// two values on it"). Read from config and from nowhere else: the daemon
/// derives neither field and reads no record for one.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct BlockedHeader {
    /// The CONFIGURED OPERATOR ACCOUNT. `None` where the header names none,
    /// and the claimant is then taken in its place.
    pub operator: Option<Address>,
    /// The board's BINDING-WRITING ACCOUNT — the claimant on an unforked
    /// lineage, the SEAT on a forked one, never the superseded claimant
    /// (REG-3.52). `None` where the header omits it, and the claimant is
    /// then taken in its place. Its SECOND reader is AUTH-3.21's seat carve
    /// at slot (6), which reads it beside the claimant and compares it
    /// (RES-175), through [`BlockedPrefixes::header`].
    pub binding_writer: Option<Address>,
}

/// One ISSUE of the list, as the operator supplies it: the header and
/// every entry, in supply order, before the install's comparison.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct BlockedIssue {
    pub header: BlockedHeader,
    pub entries: Vec<BlockedEntry>,
}

/// Which of the install's two INERT comparands an entry covers (AUTH-4.36
/// step 4b; REG-4.198: the block never reaches the hand that lifts it and
/// never takes a board from the party that writes its bindings).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Comparand {
    /// (a) the configured operator account.
    Operator,
    /// (b) the board's binding-writing account — a comparand only where the
    /// operator account is NOT an account of this board.
    BindingWriter,
}

/// The list IN FORCE: one issue, with the install's verdict on each entry
/// beside it. An entry covering a comparand is INERT — ignored at install
/// and said so in the log — and every other entry blocks.
///
/// The issue is kept WHOLE, inert entries included, because the comparison
/// is run twice over one issue: at the install, and again at the claim
/// flip, where the claimant the header defers to first exists.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct BlockedPrefixes {
    issue: BlockedIssue,
    /// Per entry of `issue.entries`: the comparand it covers, or `None` for
    /// an entry in force.
    inert: Vec<Option<Comparand>>,
    /// Comparand (a) as this install resolved it: the header's operator,
    /// else the claimant, else none (an unclaimed board naming none).
    operator: Option<Address>,
    /// Comparand (b) as this install resolved it — `Some` only where it is
    /// LIVE, which is where the operator account is off-board.
    binding_writer: Option<Address>,
    /// The node prefix the off-board test ran against (REG-1.69), or `None`
    /// where the daemon was told none and the test was off — kept beside
    /// the verdicts so the log can say which.
    node_prefix: Option<NodePrefix>,
}

impl BlockedPrefixes {
    /// THE INSTALL'S COMPARISON (AUTH-4.36 step 4b, in its own words): an
    /// entry covering (a) the CONFIGURED OPERATOR ACCOUNT — the claimant
    /// where the header names none — or (b), where that account is NOT an
    /// account of this board, the board's BINDING-WRITING ACCOUNT — the
    /// claimant where the header omits it — is INERT.
    ///
    /// "NOT an account of this board" is THE OFF-BOARD TEST, and as ruled
    /// (2026-09-18, W2a's escalation 3) it reads the header's operator
    /// account against the board's NODE PREFIX (REG-1.69):
    /// `!prefix_contains(node_prefix, operator)`. NEVER against the local
    /// root `1` (REG-1.66), which the rule's sealed wording names and which
    /// this build does not keep beside it: every address in the registry's
    /// GLOBAL form begins with `1`, so under that test a host's `1.3.0.7`
    /// read as on-board, (b) went silent, and the hosted board's claimant
    /// became blockable — the cell REG-4.198 rules out. Two arms beside the
    /// test: the claimant taken in the header's place is an account of this
    /// board BY CONSTRUCTION ((a) and (b) are one account where the header
    /// names none), so only a NAMED operator is tested — the fold's claimant
    /// is in the local form, which no `1.N` contains; and with NO node
    /// prefix supplied the daemon CANNOT tell, so every operator reads as
    /// on-board — (b) silent — and the log says so once. The named operator
    /// is read AS SPELLED, against the prefix and against the entries alike:
    /// the header is the operator's to spell in the registry's global
    /// form, the form the boundary speaks (REG-1.66).
    ///
    /// So (a) and (b) are one account where the header names none and at
    /// the root; (b) is SILENT on a fork the community itself serves, whose
    /// seat is an account of the copy, so the old claimant stays blockable
    /// (RES-66); and (b) is LIVE where the host is off-board — at a hosted
    /// tier, exempting the served board's claimant, and on a fork a third
    /// party serves, exempting the SEAT the field names and never the old
    /// claimant (RES-67, RES-68). On an UNCLAIMED board whose header names
    /// none there is no comparand and every entry stands as issued (RES-65
    /// item 4's named residue) — until the claim flip re-runs this.
    ///
    /// COVER, never descent (AUTH-4.70): the test is
    /// `prefix_contains(entry.prefix, comparand)`, so an entry BELOW a
    /// comparand — the agent space, a delegated subtree — blocks as before.
    fn installed_under(
        issue: BlockedIssue,
        claimant: Option<&Address>,
        node_prefix: Option<&NodePrefix>,
    ) -> BlockedPrefixes {
        let operator = issue.header.operator.as_ref().or(claimant).cloned();
        let off_board = match (&issue.header.operator, node_prefix) {
            (Some(named), Some(prefix)) => !prefix_contains(prefix.address(), named),
            _ => false,
        };
        let binding_writer = if off_board {
            issue.header.binding_writer.as_ref().or(claimant).cloned()
        } else {
            None
        };
        let covers = |entry: &BlockedEntry, comparand: &Option<Address>| {
            comparand.as_ref().is_some_and(|c| prefix_contains(&entry.prefix, c))
        };
        let inert = issue
            .entries
            .iter()
            .map(|entry| {
                if covers(entry, &operator) {
                    Some(Comparand::Operator)
                } else if covers(entry, &binding_writer) {
                    Some(Comparand::BindingWriter)
                } else {
                    None
                }
            })
            .collect();
        BlockedPrefixes { issue, inert, operator, binding_writer, node_prefix: node_prefix.cloned() }
    }

    /// AUTH-4.36 step 4b's one predicate: `Some` iff some entry IN FORCE
    /// contains `account` — M3's containment, [`prefix_contains`] — and the
    /// address carried is the LONGEST covering prefix's record, the nearest
    /// ground. A party under more than one entry is admitted only when
    /// every one is lifted, which falls out: each lift leaves the next
    /// longest covering it. Two entries over ONE prefix tie, and the first
    /// in supply order answers — the operator's own order, so the
    /// datum is a function of the issue alone.
    ///
    /// A scan of the list per consult, and a list is as long as a board's
    /// STANDING takedown records.
    pub fn covers(&self, account: &Address) -> Option<&Address> {
        let mut longest: Option<&BlockedEntry> = None;
        for (entry, inert) in self.judged() {
            if inert.is_some() || !prefix_contains(&entry.prefix, account) {
                continue;
            }
            let depth = |e: &BlockedEntry| e.prefix.tumbler().len();
            if longest.is_none_or(|held| depth(entry) > depth(held)) {
                longest = Some(entry);
            }
        }
        longest.map(|entry| &entry.record)
    }

    /// Each entry of the issue beside the install's verdict on it — THE one
    /// pairing, so the two vectors meet at one site rather than at three
    /// `zip`s. A `zip` truncates silently, and the direction that truncates
    /// is the one that fails OPEN: an `inert` shorter than `entries` makes
    /// every entry past its end invisible to [`BlockedPrefixes::covers`],
    /// which is a standing block that stops blocking with nothing to say so.
    ///
    /// INVARIANT: the two have equal length, established by
    /// [`BlockedPrefixes::installed_under`], which maps one from the other,
    /// and by `Default`, which leaves both empty. Nothing mutates either
    /// after the install; a lift is a fresh ISSUE and a fresh install.
    fn judged(&self) -> impl Iterator<Item = (&BlockedEntry, Option<Comparand>)> {
        debug_assert_eq!(
            self.issue.entries.len(),
            self.inert.len(),
            "an entry and its verdict are built together and never moved apart"
        );
        self.issue.entries.iter().zip(self.inert.iter().copied())
    }

    /// The header as issued — what the log names, and the seat carve's read
    /// (AUTH-3.21, RES-175).
    pub fn header(&self) -> &BlockedHeader {
        &self.issue.header
    }

    /// The entries in force — every entry of the issue but the inert ones.
    fn in_force(&self) -> usize {
        self.judged().filter(|(_, inert)| inert.is_none()).count()
    }

    /// Whether the issue carries NO entries — the question the claim flip's
    /// log asks, and about the ISSUE rather than the entries in force: the
    /// flip's news is exactly that an entry became INERT, so an inert entry
    /// is something to say and an absent one is not.
    pub fn issue_is_empty(&self) -> bool {
        self.issue.entries.is_empty()
    }

    /// THE LOG (AUTH-4.70 "the startup log names the list in force";
    /// AUTH-4.36 step 4b "ignored at install and said so in the log"): one
    /// line naming the count, the header as resolved and the node prefix
    /// the off-board test ran against — or, where none was supplied, that
    /// the test was off, said once per install and not per entry — then one
    /// line per INERT entry, by name, with the comparand it covers. Entries
    /// in force are counted and not listed: the file is theirs to be read
    /// from, and a line per standing takedown at every reissue is a log
    /// nobody reads.
    pub fn log_lines(&self) -> Vec<String> {
        let named = |field: &Option<Address>, resolved: &Option<Address>, absent: &str| {
            match (field, resolved) {
                (Some(a), _) => format!("{} (the header's)", a.tumbler()),
                (None, Some(a)) => format!("{} (the claimant — {absent})", a.tumbler()),
                (None, None) => format!("none ({absent}, and the board is unclaimed)"),
            }
        };
        let header = self.header();
        let operator = named(&header.operator, &self.operator, "the header names none");
        let binding_writer = match (&self.binding_writer, &self.node_prefix) {
            (live @ Some(_), Some(prefix)) => format!(
                "{} — exempt, the operator account being off-board (not under the node \
                 prefix {prefix})",
                named(&header.binding_writer, live, "the header omits it"),
            ),
            // Unreachable by construction — (b) is live only against a
            // prefix — and answered rather than asserted: a log line is not
            // the place to stop a daemon.
            (live @ Some(_), None) => format!(
                "{} — exempt, the operator account being off-board",
                named(&header.binding_writer, live, "the header omits it"),
            ),
            (None, Some(prefix)) => format!(
                "not a comparand (the operator account is an account of this board — under \
                 the node prefix {prefix}, or the claimant taken in the header's place — or \
                 there is none)"
            ),
            (None, None) => "not a comparand (no --node-prefix: the off-board test is off; a \
                             hosted board must supply one)"
                .to_string(),
        };
        let inert = self.judged().filter(|(_, verdict)| verdict.is_some()).count();
        let mut lines = vec![format!(
            "{} of {} entries in force, {inert} inert; operator account {operator}; \
             binding-writing account {binding_writer}",
            self.in_force(),
            self.issue.entries.len(),
        )];
        for (entry, comparand) in self.judged() {
            let (covered, exempted) = match comparand {
                None => continue,
                Some(Comparand::Operator) => ("the configured operator account", &self.operator),
                Some(Comparand::BindingWriter) => {
                    ("the board's binding-writing account", &self.binding_writer)
                }
            };
            // Unreachable by construction — [`BlockedPrefixes::installed_under`]
            // judges an entry against a comparand only inside `covers`, which
            // requires that comparand `Some` — and ANSWERED rather than
            // asserted, for the reason the arm above gives. The cell is
            // sharper here than there: this renders from
            // `credential_sequence` under both write locks AFTER the claim has
            // committed ([`crate::notice`]), so a panic is `500
            // internal_panic` for a one-time-only write that landed and whose
            // retry meets `already_claimed`. The debug assert is what makes
            // the premise loud where a test can see it.
            debug_assert!(exempted.is_some(), "an entry is inert only against a comparand");
            let account =
                exempted.as_ref().map(|a| format!(" {}", a.tumbler())).unwrap_or_default();
            lines.push(format!(
                "entry {} (record {}) is INERT — it covers {covered}{account}; ignored",
                entry.prefix.tumbler(),
                entry.record.tumbler(),
            ));
        }
        lines
    }
}

/// The installed list — AUTH-4.36 step 4b's `blocked_prefixes(cfg)`, a pure
/// read of the list in force. By value (one pointer clone), so no reader
/// holds the cell's lock across its own work and an install never waits on
/// a handshake's verify loop.
pub(crate) fn blocked_prefixes(cfg: &AuthConfig) -> Arc<BlockedPrefixes> {
    Arc::clone(&cfg.blocked.read())
}

/// What one look at a moved supply file came to — the reissue's two
/// outcomes, for the log [`crate::Daemon`] writes.
#[derive(Debug)]
pub(crate) enum Reissue {
    /// The new issue is the list in force.
    Installed,
    /// The file could not be read, is not a list, or is past the byte cap:
    /// nothing was installed and the list in force stands.
    Refused(io::Error),
}

/// THE CHANNEL (AUTH-4.70: "its channel the build's"; RES-65 item 4's
/// recommendation, "a file the flag `--blocked-prefixes <path>` names"): a
/// file the operator owns, read at every start and RE-READ WHEN IT
/// MOVES — its identity checked at the head of every request
/// ([`AuthState::reissue_blocked_prefixes`]), one `stat`.
///
/// Not the conventional reload SIGNAL, deliberately. This daemon has no
/// signal handling at all (`main.rs`: crash-stop is the shutdown story), a
/// signal is the PROCESS's and a [`crate::Daemon`] is a value — several
/// live in one process wherever the library is embedded, this crate's own
/// suites included — and a signal says only "look again", which the file's
/// identity already says without a second channel to keep in step with the
/// first. What the check buys beside that: the install happens BEFORE the
/// request that noticed it resolves its actor, so a reissue is in force at
/// the first presentation after it, with no window a sleeping watcher
/// thread would leave.
///
/// THE FILE is one JSON object, strict keys, nothing else admitted:
///
/// ```json
/// {"operator": "<address>", "binding_writer": "<address>",
///  "entries": [{"prefix": "<address>", "record": "<address>"}, …]}
/// ```
///
/// `operator` and `binding_writer` are the two-field HEADER, each OPTIONAL
/// — absent is "the header names none", and there is no other spelling;
/// `entries` is REQUIRED, and an empty array is the explicit empty list (a
/// lift of everything is an ISSUE, never an absent file). Every address is
/// dotted decimal under the codec's own tumbler caps, T4-valid. JSON
/// because a truncated object does not parse: a reader racing a writer
/// that did not replace the file atomically REFUSES the torn issue and
/// keeps the list in force, where a line format would install the half it
/// saw. The operator still owes the ATOMIC REPLACE (write beside,
/// rename over) — it is also what gives every issue a fresh identity.
#[derive(Debug)]
pub(crate) struct BlockedSupply {
    path: PathBuf,
    /// The file's identity as last looked at — `None` for a file that was
    /// not there. A FAILED look is remembered too, so a bad issue is
    /// refused and logged once rather than at every request until it moves.
    seen: parking_lot::Mutex<Option<FileStamp>>,
}

/// A file's identity, cheaply: what moves when the operator replaces
/// it. The inode is what makes two issues written inside one timestamp tick
/// distinct (a rename-over is always a new file); where there is none, the
/// modification time and the length carry it alone.
#[derive(Clone, Debug, PartialEq, Eq)]
struct FileStamp {
    modified: Option<SystemTime>,
    len: u64,
    #[cfg(unix)]
    inode: (u64, u64),
}

impl FileStamp {
    fn of(meta: &std::fs::Metadata) -> FileStamp {
        #[cfg(unix)]
        use std::os::unix::fs::MetadataExt;
        FileStamp {
            modified: meta.modified().ok(),
            len: meta.len(),
            #[cfg(unix)]
            inode: (meta.dev(), meta.ino()),
        }
    }

    /// The identity of whatever is at `path` now; `None` where nothing can
    /// be stat'ed there.
    fn at(path: &Path) -> Option<FileStamp> {
        std::fs::metadata(path).ok().as_ref().map(FileStamp::of)
    }
}

impl BlockedSupply {
    /// The START-UP SUPPLY (RES-115): read the named file, or fail the open.
    fn open(path: &Path) -> io::Result<(BlockedSupply, BlockedIssue)> {
        let supply = BlockedSupply { path: path.to_path_buf(), seen: parking_lot::Mutex::new(None) };
        let (stamp, issue) = supply.read()?;
        *supply.seen.lock() = Some(stamp);
        Ok((supply, issue))
    }

    /// One read of the file, whole: its identity off the OPEN handle — so
    /// the stamp names the bytes read, and a replace landing between this
    /// and the next look is seen as one — then the byte cap, then the
    /// parse. Every failure is an `io::Error` naming the path; a file that
    /// is not a list, and one past [`MAX_BLOCKED_SUPPLY_BYTES`], are both
    /// `InvalidData`, so the channel's two refusals travel as one kind.
    fn read(&self) -> io::Result<(FileStamp, BlockedIssue)> {
        use std::io::Read;
        let with_path =
            |e: io::Error| io::Error::new(e.kind(), format!("{}: {e}", self.path.display()));
        let file = std::fs::File::open(&self.path).map_err(with_path)?;
        let stamp = FileStamp::of(&file.metadata().map_err(with_path)?);
        let mut bytes = Vec::new();
        // ONE PAST the cap, so a file that exactly fills it is told apart
        // from one that exceeds it — and `take` rather than a length test
        // off the stamp, which a file being appended to concurrently
        // outruns.
        file.take(MAX_BLOCKED_SUPPLY_BYTES as u64 + 1).read_to_end(&mut bytes).map_err(with_path)?;
        if bytes.len() > MAX_BLOCKED_SUPPLY_BYTES {
            return Err(with_path(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("the list is past the {MAX_BLOCKED_SUPPLY_BYTES}-byte supply cap"),
            )));
        }
        let issue = parse_issue(&bytes)
            .map_err(|detail| with_path(io::Error::new(io::ErrorKind::InvalidData, detail)))?;
        Ok((stamp, issue))
    }

    /// One look at the file, and the install where it MOVED — the channel's
    /// whole operation, here because the identity it turns on is this type's
    /// own. `None` is the ordinary request's answer: nothing moved, at the
    /// cost of one `stat`.
    ///
    /// `install` is the CALLER's, because the list is replaced under a gate
    /// this type knows nothing about. It runs with `seen` HELD, so a request
    /// arriving mid-install waits for it rather than resolving under a list an
    /// earlier request has already seen superseded. Lock order is therefore
    /// `seen` → whatever `install` takes, and nothing holding that gate
    /// touches `seen`.
    ///
    /// A re-read that FAILS calls `install` not at all — the list is replaced
    /// WHOLE or not — and the failed look is REMEMBERED, so the refusal is
    /// answered once rather than at every request until the file moves again.
    fn reissue(&self, install: impl FnOnce(BlockedIssue)) -> Option<Reissue> {
        let current = FileStamp::at(&self.path);
        let mut seen = self.seen.lock();
        if *seen == current {
            return None;
        }
        match self.read() {
            Ok((stamp, issue)) => {
                install(issue);
                *seen = Some(stamp);
                Some(Reissue::Installed)
            }
            Err(e) => {
                *seen = current;
                Some(Reissue::Refused(e))
            }
        }
    }
}

/// Parse one issue of the list — [`BlockedSupply`] states the format. The
/// never-silent device throughout ([`check_keys`]): a field this daemon does
/// not read is a named refusal, never a header quietly ignored.
fn parse_issue(bytes: &[u8]) -> Result<BlockedIssue, String> {
    let v: Value = serde_json::from_slice(bytes).map_err(|e| format!("invalid JSON: {e}"))?;
    let Value::Object(m) = v else {
        return Err("the list must be a JSON object".into());
    };
    check_keys(&m, &["operator", "binding_writer", "entries"])?;
    let header = BlockedHeader {
        operator: address_field(&m, "operator")?,
        binding_writer: address_field(&m, "binding_writer")?,
    };
    let entries = m
        .get("entries")
        .and_then(Value::as_array)
        .ok_or("missing or non-array field 'entries'")?
        .iter()
        .enumerate()
        .map(|(i, entry)| {
            let in_entry = |detail: String| format!("entries[{i}]: {detail}");
            let Value::Object(entry) = entry else {
                return Err(in_entry("expected a JSON object".into()));
            };
            check_keys(entry, &["prefix", "record"]).map_err(in_entry)?;
            let required = |k: &str| {
                address_field(entry, k)
                    .map_err(in_entry)?
                    .ok_or_else(|| in_entry(format!("missing field '{k}'")))
            };
            Ok(BlockedEntry { prefix: required("prefix")?, record: required("record")? })
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(BlockedIssue { header, entries })
}

/// One address member: absent ⇒ `None`; present ⇒ a dotted-decimal string
/// through [`crate::codec::wire_address`], the wire's one capped-and-T4
/// address door — or a named refusal, this file's own grammar supplying the
/// field name and that door the fault.
fn address_field(m: &Map<String, Value>, k: &str) -> Result<Option<Address>, String> {
    let Some(v) = m.get(k) else { return Ok(None) };
    let s = v.as_str().ok_or_else(|| format!("field '{k}' must be a dotted-decimal string"))?;
    wire_address(s).map(Some).map_err(|detail| format!("field '{k}': {detail}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// AUTH-4.2 — the canonical-member rule: at the scheme's default port
    /// the port is omitted, and `parse` admits only the canonical text.
    #[test]
    fn origins_are_canonical_only() {
        for ok in ["http://127.0.0.1:8642", "http://localhost:8642", "http://[::1]:8642",
                   "http://127.0.0.1", "https://example.org", "https://skep.example:8443"] {
            let o = Origin::parse(ok).unwrap_or_else(|| panic!("'{ok}' is canonical"));
            assert_eq!(o.as_str(), ok);
        }
        for bad in ["http://127.0.0.1:80", "https://example.org:443", "HTTP://x",
                    "http://X.org", "http://x/", "http://x/path", "null", "",
                    "http://x:08642", "ftp://x", "http://", "http://x:", "http://x:0"] {
            assert!(Origin::parse(bad).is_none(), "'{bad}' must not parse");
        }
    }

    /// AUTH-4.1 — the defaults are the three loopback origins of the bound
    /// port, canonical (port omitted at 80) — and an UNBOUND config has
    /// none, which is the honest degenerate stated in the type: the
    /// alternative is three members at a port no listener serves and no
    /// `Origin` header can name.
    #[test]
    fn loopback_defaults_are_the_three_canonical_members() {
        let at_8642: Vec<String> =
            loopback_defaults(Some(8642)).iter().map(|o| o.as_str().to_string()).collect();
        assert_eq!(
            at_8642,
            ["http://127.0.0.1:8642", "http://[::1]:8642", "http://localhost:8642"]
        );
        let at_80: Vec<String> =
            loopback_defaults(Some(80)).iter().map(|o| o.as_str().to_string()).collect();
        assert_eq!(at_80, ["http://127.0.0.1", "http://[::1]", "http://localhost"]);
        assert!(loopback_defaults(None).is_empty(), "an unbound config derives no defaults");
    }

    /// [`AuthConfig::bind_port`] refuses a second bind and names the port
    /// already bound — the number every live session's origin set was
    /// established against, which is what the second caller needs told.
    #[test]
    fn a_second_bind_is_refused_and_names_the_bound_port() {
        let cfg = cfg_with(8642, true, &[]);
        assert_eq!(cfg.port(), Some(8642));
        assert_eq!(
            cfg.bind_port(9999),
            Err(PortAlreadyBound(8642)),
            "the bound port, not the refused one"
        );
        assert_eq!(cfg.port(), Some(8642), "and the binding did not move");
    }

    /// Port 0 is the one value from which [`loopback_defaults`] derives
    /// origins [`Origin::parse`] refuses: `http://127.0.0.1:0` fails the
    /// leading-zero clause, so admitting the bind fires
    /// [`Origin::from_parts`]'s debug assert on every request that reads a
    /// derived origin, and in release publishes a `/health` set whose
    /// members no `Origin` header can match. The bind refuses it instead —
    /// a caller's bug, stopped loudly, as a zero worker count is at
    /// [`crate::serve`].
    #[test]
    #[should_panic(expected = "port 0 is not a port")]
    fn port_zero_is_a_callers_bug() {
        // The premise, first: this is what the defaults would derive from it.
        assert!(
            Origin::parse("http://127.0.0.1:0").is_none(),
            "the front door refuses the text a zero-port default would carry"
        );
        let cfg = AuthConfig::new(AuthOptions::default());
        let _ = cfg.bind_port(0);
    }

    /// An unbound config has no port, so its bare set is `configured`
    /// alone — no unmatchable members, and nothing `/health` publishes that
    /// [`Origin::parse`] would refuse if an operator copied it back.
    #[test]
    fn an_unbound_config_derives_no_origins() {
        let cfg = AuthConfig::new(AuthOptions {
            local_trust: true,
            configured: vec![Origin::parse("https://board.example").expect("canonical")],
            ..AuthOptions::default()
        });
        assert_eq!(cfg.port(), None);
        let bare = bare_origins(&cfg);
        assert_eq!(bare.len(), 1, "configured alone: {bare:?}");
        assert!(bare.contains(&Origin::parse("https://board.example").unwrap()));
    }

    fn cfg_with(port: u16, local_trust: bool, configured: &[&str]) -> AuthConfig {
        let cfg = AuthConfig::new(AuthOptions {
            local_trust,
            configured: configured.iter().map(|s| Origin::parse(s).expect("canonical")).collect(),
            ..AuthOptions::default()
        });
        cfg.bind_port(port).expect("a fresh config binds once");
        cfg
    }

    /// AUTH-4.3 — the two sets: bare keeps the defaults in every mode;
    /// signed drops to configured alone at the claim.
    #[test]
    fn the_two_origin_sets_split_at_the_claim() {
        let cfg = cfg_with(8642, false, &["https://board.example"]);
        let bare = bare_origins(&cfg);
        assert_eq!(bare.len(), 4, "configured ∪ the three defaults");
        assert!(bare.contains(&Origin::parse("http://localhost:8642").unwrap()));
        let unclaimed = signed_origins(&cfg, false);
        assert_eq!(unclaimed, bare, "unclaimed: the signed set is the bare set");
        let claimed = signed_origins(&cfg, true);
        assert_eq!(claimed.len(), 1, "claimed: configured alone");
        assert!(claimed.contains(&Origin::parse("https://board.example").unwrap()));
    }

    /// AUTH-4.9/AUTH-4.62 item 9 — the warning cells, the canonical-form
    /// cell included: bound at 80, configured `http://127.0.0.1` is silent
    /// and `http://127.0.0.1:8080` warns, naming the origin.
    #[test]
    fn each_warning_arm_fires_only_on_its_own_cell() {
        assert!(startup_warnings(&cfg_with(8642, false, &["https://b.example"]), true).is_empty());
        assert_eq!(
            startup_warnings(&cfg_with(8642, true, &["https://b.example"]), true),
            [Warning::ClaimedWithLocalTrust]
        );
        assert_eq!(
            startup_warnings(&cfg_with(8642, false, &[]), true),
            [Warning::ClaimedWithEmptyConfigured]
        );
        let moved = cfg_with(80, false, &["http://127.0.0.1", "http://127.0.0.1:8080"]);
        assert_eq!(
            startup_warnings(&moved, false),
            [Warning::ConfiguredLoopbackPortChanged(
                Origin::parse("http://127.0.0.1:8080").unwrap()
            )],
            "the canonical member is silent; the moved port warns and is named"
        );
        // A hosted board configured with its public origin alone is silent.
        assert!(startup_warnings(&cfg_with(443, false, &["https://b.example"]), false).is_empty());
    }

    fn addr(s: &str) -> Address {
        wire_address(s).expect("a T4-valid address")
    }

    fn node_prefix(s: &str) -> NodePrefix {
        s.parse().expect("a node prefix")
    }

    fn issue(operator: Option<&str>, binding_writer: Option<&str>, entries: &[(&str, &str)]) -> BlockedIssue {
        BlockedIssue {
            header: BlockedHeader {
                operator: operator.map(addr),
                binding_writer: binding_writer.map(addr),
            },
            entries: entries
                .iter()
                .map(|(prefix, record)| BlockedEntry { prefix: addr(prefix), record: addr(record) })
                .collect(),
        }
    }

    /// AUTH-4.36 step 4b's predicate: M3's containment, the LONGEST covering
    /// prefix's record, COVER and never descent (AUTH-4.70) — an entry over
    /// `X.k` covers `X.k` and everything below it and does not reach `X` —
    /// and component-wise, so `1.0.2` does not contain `1.0.21`.
    #[test]
    fn covers_answers_the_longest_covering_entrys_record() {
        let list = BlockedPrefixes::installed_under(
            issue(None, None, &[("1.0.2", "1.0.1.0.7.1"), ("1.0.2.1", "1.0.1.0.8.1")]),
            None,
            None,
        );
        assert_eq!(list.covers(&addr("1.0.2")), Some(&addr("1.0.1.0.7.1")), "the prefix itself");
        assert_eq!(list.covers(&addr("1.0.2.5")), Some(&addr("1.0.1.0.7.1")), "and below it");
        assert_eq!(list.covers(&addr("1.0.2.1")), Some(&addr("1.0.1.0.8.1")), "the longest");
        assert_eq!(list.covers(&addr("1.0.2.1.4")), Some(&addr("1.0.1.0.8.1")));
        assert_eq!(list.covers(&addr("1.0.3")), None, "a sibling");
        assert_eq!(list.covers(&addr("1.0.21")), None, "containment is by component");
        let below =
            BlockedPrefixes::installed_under(issue(None, None, &[("1.0.2.1", "1.0.1.0.8.1")]), None, None);
        assert_eq!(below.covers(&addr("1.0.2")), None, "an entry over X.k does not reach X");
        // Two entries over ONE prefix: the first in supply order answers.
        let tied = BlockedPrefixes::installed_under(
            issue(None, None, &[("1.0.2", "1.0.1.0.7.1"), ("1.0.2", "1.0.1.0.8.1")]),
            None,
            None,
        );
        assert_eq!(tied.covers(&addr("1.0.2")), Some(&addr("1.0.1.0.7.1")));
        assert_eq!(BlockedPrefixes::default().covers(&addr("1.0.2")), None, "no supply, no block");
    }

    /// THE INSTALL'S TWO INERT COMPARANDS, at every cell AUTH-4.36 step 4b
    /// states: (a) and (b) one account where the header names none; (b)
    /// SILENT on a fork the community itself serves; (b) LIVE where the host
    /// is off-board — the claimant taken where the header omits the second
    /// field, the SEAT and never the old claimant where it names one. Every
    /// board here is launched `--node-prefix 1.3`, so the off-board test is
    /// LIVE and reads the header's operator against that prefix (REG-1.69):
    /// the seat a self-served fork names is spelled in the GLOBAL form the
    /// header carries, `1.3.0.2`, and so is the entry over it — the operator
    /// is read as spelled against the entries too, and a LOCAL-form entry
    /// over the same account stands (the last cell; the report escalates the
    /// form).
    #[test]
    fn the_install_ignores_exactly_the_entries_covering_a_comparand() {
        let (claimant, seat, member, host) = ("1.0.1", "1.0.2", "1.0.3", "2.0.7");
        let seat_global = "1.3.0.2";
        let record = "1.0.1.0.7.1";
        let prefix = node_prefix("1.3");
        let entries =
            [(claimant, record), (seat, record), (member, record), (host, record), (seat_global, record)];
        let verdicts = |operator, binding_writer, claimed: Option<&str>| {
            let claimed = claimed.map(addr);
            BlockedPrefixes::installed_under(
                issue(operator, binding_writer, &entries),
                claimed.as_ref(),
                Some(&prefix),
            )
            .inert
        };
        let (a, b) = (Some(Comparand::Operator), Some(Comparand::BindingWriter));
        assert_eq!(
            verdicts(None, None, Some(claimant)),
            [a, None, None, None, None],
            "the root: the header names none, so the claimant is the one comparand"
        );
        assert_eq!(
            verdicts(Some(seat_global), None, Some(claimant)),
            [None, None, None, None, a],
            "a self-served fork: the seat is on-board (under the prefix), (b) is silent, the \
             old claimant blockable — and the operator is read as spelled: the global-form \
             entry over the seat is inert, the local-form one stands"
        );
        assert_eq!(
            verdicts(Some(host), None, Some(claimant)),
            [b, None, None, a, None],
            "a hosted tier: the operator off-board, the claimant taken for the omitted field"
        );
        assert_eq!(
            verdicts(Some(host), Some(seat), Some(claimant)),
            [None, b, None, a, None],
            "a third-party-hosted fork: the SEAT exempt, never the old claimant"
        );
        assert_eq!(
            verdicts(None, None, None),
            [None, None, None, None, None],
            "unclaimed, the header naming none: no comparand, every entry stands as issued"
        );
        assert_eq!(
            verdicts(Some(seat), None, Some(claimant)),
            [b, a, None, None, None],
            "the seat spelled in the LOCAL form is under no `1.N` and reads OFF-board: (b) \
             goes live and exempts the old claimant — the header's first field is the \
             operator's to spell globally (escalated)"
        );
        // COVER: a prefix ABOVE a comparand covers it — the board's own node
        // included — and one BELOW it does not.
        let list = BlockedPrefixes::installed_under(
            issue(None, None, &[("1", record), ("1.0.1.1", record)]),
            Some(&addr(claimant)),
            Some(&prefix),
        );
        assert_eq!(list.inert, [a, None], "above is inert; the agent space beneath blocks");
        assert_eq!(list.covers(&addr(member)), None, "an inert entry blocks nobody");
        assert!(list.covers(&addr("1.0.1.1")).is_some());
    }

    /// The claim flip's log question ([`BlockedPrefixes::issue_is_empty`]) is
    /// about the ISSUE and never about the entries in force. The two differ
    /// at exactly the cell the flip's log exists for — every entry inert,
    /// because the claimant the flip seats is what made them so — so a
    /// version asking `in_force() == 0` instead would fall silent on the one
    /// install AUTH-4.36 step 4b requires be "said so in the log".
    #[test]
    fn an_all_inert_issue_is_not_an_empty_one() {
        let claimant = addr("1.0.1");
        let all_inert = BlockedPrefixes::installed_under(
            issue(None, None, &[("1.0.1", "1.0.1.0.9.1")]),
            Some(&claimant),
            Some(&node_prefix("1.3")),
        );
        assert_eq!(all_inert.in_force(), 0, "the claim made its one entry inert");
        assert!(!all_inert.issue_is_empty(), "and that is exactly what the log must say");
        let empty =
            BlockedPrefixes::installed_under(issue(None, None, &[]), Some(&claimant), None);
        assert!(empty.issue_is_empty(), "an issue with no entries has nothing to say");
        assert!(BlockedPrefixes::default().issue_is_empty(), "nor has no supply at all");
    }

    /// THE OFF-BOARD TEST (AUTH-4.36 step 4b's comparand (b) as ruled
    /// 2026-09-18; REG-1.69): a host's account in the registry's GLOBAL form,
    /// `1.3.0.7`, is on-board under `--node-prefix 1.3` and off-board under
    /// `--node-prefix 1.5` — the test runs against the prefix and never the
    /// local root `1`, under which that address read as on-board on every
    /// board (W2a's escalation 3). With NO prefix the test is off and every
    /// operator reads as on-board. The claimant taken in the header's place
    /// is never tested: it is an account of this board by construction.
    #[test]
    fn the_off_board_test_reads_the_node_prefix_and_never_the_local_root() {
        let (claimant, record) = ("1.0.1", "1.0.1.0.7.1");
        let (own, foreign) = (node_prefix("1.3"), node_prefix("1.5"));
        let entries = [(claimant, record), ("1.3.0.7", record)];
        let verdicts = |operator: Option<&str>, prefix: Option<&NodePrefix>| {
            BlockedPrefixes::installed_under(issue(operator, None, &entries), Some(&addr(claimant)), prefix)
                .inert
        };
        let (a, b) = (Some(Comparand::Operator), Some(Comparand::BindingWriter));
        assert_eq!(
            verdicts(Some("1.3.0.7"), Some(&own)),
            [None, a],
            "under 1.3 the operator is ON-board: (b) silent, the claimant's entry live"
        );
        assert_eq!(
            verdicts(Some("1.3.0.7"), Some(&foreign)),
            [b, a],
            "under 1.5 the same operator is OFF-board: (b) live, the served claimant exempt"
        );
        assert_eq!(
            verdicts(Some("1.3.0.7"), None),
            [None, a],
            "no node prefix: the test is off, every operator on-board"
        );
        assert_eq!(
            verdicts(None, Some(&foreign)),
            [a, None],
            "the claimant taken in the header's place is on-board by construction, whatever \
             the prefix — its local form is under no `1.N`"
        );
        let installed = BlockedPrefixes::installed_under(issue(Some("1.3.0.7"), None, &[]), None, Some(&own));
        assert_eq!(installed.node_prefix, Some(own), "the prefix the install read is kept for the log");
    }

    /// REG-1.69's form, at the parse: a NODE address strictly under the root
    /// `1` — an org's `1.N`, a subnode beneath — and nothing else: the root
    /// itself, another first component (REG-1.67), an account or document
    /// address, a trailing zero, text no tumbler spells.
    #[test]
    fn a_node_prefix_is_a_node_address_strictly_under_the_root() {
        for ok in ["1.2", "1.3", "1.3.2", "1.1024.7"] {
            let parsed: NodePrefix =
                ok.parse().unwrap_or_else(|_| panic!("'{ok}' is a node prefix"));
            assert_eq!(parsed.address(), &addr(ok));
            assert_eq!(parsed.address().level(), Level::Node);
            assert_eq!(parsed.to_string(), ok, "and renders as the operator spelled it");
        }
        for bad in ["1", "2.4", "2", "1.3.0.7", "1.3.0.7.0.1", "1.0", "0.3", "1..3", "", "x", "1.3."] {
            assert!(bad.parse::<NodePrefix>().is_err(), "'{bad}' is not a node prefix");
        }
    }

    /// The log NAMES the list in force (AUTH-4.70) — the count, the header
    /// as resolved, the node prefix the off-board test ran against or that
    /// the test was off — and every INERT entry by name with the comparand
    /// it covers (AUTH-4.36 step 4b: "ignored at install and said so in the
    /// log"). Entries in force are counted, never listed.
    #[test]
    fn the_install_log_names_the_count_the_header_and_each_inert_entry() {
        let claimant = addr("1.0.1");
        let prefix = node_prefix("1.3");
        let list = BlockedPrefixes::installed_under(
            issue(Some("2.0.7"), None, &[("1.0.1", "1.0.1.0.9.1"), ("1.0.3", "1.0.1.0.7.1"), ("2.0.7", "1.0.1.0.11.1")]),
            Some(&claimant),
            Some(&prefix),
        );
        assert_eq!(
            list.log_lines(),
            [
                "1 of 3 entries in force, 2 inert; operator account 2.0.7 (the header's); \
                 binding-writing account 1.0.1 (the claimant — the header omits it) — exempt, \
                 the operator account being off-board (not under the node prefix 1.3)",
                "entry 1.0.1 (record 1.0.1.0.9.1) is INERT — it covers the board's \
                 binding-writing account 1.0.1; ignored",
                "entry 2.0.7 (record 1.0.1.0.11.1) is INERT — it covers the configured \
                 operator account 2.0.7; ignored",
            ]
        );
        let root = BlockedPrefixes::installed_under(
            issue(None, None, &[("1.0.3", "1.0.1.0.7.1")]),
            Some(&claimant),
            Some(&prefix),
        );
        assert_eq!(
            root.log_lines(),
            ["1 of 1 entries in force, 0 inert; operator account 1.0.1 (the claimant — the \
              header names none); binding-writing account not a comparand (the operator \
              account is an account of this board — under the node prefix 1.3, or the \
              claimant taken in the header's place — or there is none)"]
        );
        // No node prefix: the test is off, and the header line says so ONCE
        // — per install, not per entry — whatever the header names.
        let untold = BlockedPrefixes::installed_under(
            issue(Some("1.3.0.7"), None, &[("1.0.1", "1.0.1.0.9.1"), ("1.0.3", "1.0.1.0.7.1")]),
            Some(&claimant),
            None,
        );
        assert_eq!(
            untold.log_lines(),
            ["2 of 2 entries in force, 0 inert; operator account 1.3.0.7 (the header's); \
              binding-writing account not a comparand (no --node-prefix: the off-board test \
              is off; a hosted board must supply one)"]
        );
        let unclaimed = BlockedPrefixes::installed_under(issue(None, None, &[]), None, None);
        assert!(
            unclaimed.log_lines()[0].contains("operator account none (the header names none, and the board is unclaimed)"),
            "{:?}",
            unclaimed.log_lines()
        );
    }

    /// The supply's BYTE CAP at both ends: a file AT the cap is read and
    /// parsed, one byte past it is refused unread. The at-cap half is the
    /// load-bearing one — a `>` that became a `>=` would refuse a list the
    /// budget admits — and the padding is insignificant whitespace, so what
    /// the refusal answers is the SIZE and not the grammar.
    #[test]
    fn a_supply_past_the_byte_cap_is_refused_unread() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("blocked.json");
        let mut at_cap = br#"{"entries":[]}"#.to_vec();
        at_cap.resize(MAX_BLOCKED_SUPPLY_BYTES, b' ');
        std::fs::write(&path, &at_cap).expect("write");
        let (_supply, issue) = BlockedSupply::open(&path).expect("a supply at the cap is read");
        assert_eq!(issue, BlockedIssue::default(), "and parses to the empty list");

        let mut over = at_cap;
        over.push(b' ');
        std::fs::write(&path, &over).expect("write");
        let e = BlockedSupply::open(&path).expect_err("one byte past the cap is refused");
        assert_eq!(e.kind(), io::ErrorKind::InvalidData, "the channel's one refusal kind");
        assert!(e.to_string().contains("supply cap"), "the refusal names the cap: {e}");
    }

    /// The supply file's grammar: one strict JSON object. `entries` is
    /// required (an empty array IS the empty list), the two header fields
    /// are optional and have ONE spelling of "none" — absence — and an
    /// unread field, a torn object, or an address no tumbler spells is a
    /// named refusal, never a list quietly shorter than the one issued.
    #[test]
    fn the_supply_file_is_one_strict_json_object() {
        let parsed = parse_issue(
            br#"{"operator":"2.0.7","binding_writer":"1.0.2","entries":[{"prefix":"1.0.3","record":"1.0.1.0.7.1"}]}"#,
        )
        .expect("the whole grammar");
        assert_eq!(parsed, issue(Some("2.0.7"), Some("1.0.2"), &[("1.0.3", "1.0.1.0.7.1")]));
        assert_eq!(parse_issue(br#"{"entries":[]}"#), Ok(BlockedIssue::default()), "the empty list");
        for (bad, why) in [
            (&br#"{}"#[..], "entries is required"),
            (br#"[]"#, "not an object"),
            (br#"{"entries":[{"prefix":"1.0.3","#, "a torn object does not parse"),
            (br#"{"entries":[],"lifted":true}"#, "an unread field"),
            (br#"{"operator":null,"entries":[]}"#, "absence is the one spelling of none"),
            (br#"{"entries":[{"prefix":"1.0.3"}]}"#, "an entry without its record"),
            (br#"{"entries":[{"prefix":"1.0.3","record":"1.0.1.0.7.1","note":"x"}]}"#, "an unread entry field"),
            (br#"{"entries":[{"prefix":"1..3","record":"1.0.1.0.7.1"}]}"#, "not a tumbler"),
            (br#"{"entries":[{"prefix":"1.0.0.3","record":"1.0.1.0.7.1"}]}"#, "not T4-valid"),
            (br#"{"entries":["1.0.3"]}"#, "an entry that is not an object"),
        ] {
            assert!(parse_issue(bad).is_err(), "{why}: {}", String::from_utf8_lossy(bad));
        }
    }
}
