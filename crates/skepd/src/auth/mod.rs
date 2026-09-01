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
use std::sync::OnceLock;

use rand_core::{CryptoRng, RngCore};
use skep_febe::{ReqId, SessionId};
use skep_identity::LinkDeposit;

use crate::World;
use fold::{CredMemo, IdentityFold};
use session::{Challenges, Sessions};

/// The challenge store's default cap (AUTH-1.48): live nonces retained;
/// past it the oldest is evicted. Entered into the store once, at `new`.
pub(crate) const MAX_LIVE_NONCES: usize = 4096;

/// The daemon's session-layer configuration, as the operator supplies it:
/// the local-trust flag (Phase A default ON — a hosted image must set it
/// AFFIRMATIVELY false, AUTH-4.57 (i)) and the configured origins
/// (AUTH-4.7: configure what the board is actually reachable at).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthOptions {
    /// Bare binds honored on loopback after the claim (CLAIMED-PERMISSIVE)
    /// when true; ENFORCING when false. Pre-claim the flag is not consulted
    /// (AUTH-4.26's mode conjunct short-circuits on `!claimed`).
    pub local_trust: bool,
    /// The configured origin set — the signed arm's whole set once claimed;
    /// unioned with the loopback defaults on the bare arm.
    pub origins: Vec<Origin>,
}

impl Default for AuthOptions {
    fn default() -> AuthOptions {
        AuthOptions { local_trust: true, origins: Vec::new() }
    }
}

/// The resolved configuration the auth surface reads: options plus the
/// BOUND port, which exists only once the listener does. `serve` sets it;
/// a socket-free embedder that wants origin-set behavior calls
/// [`crate::Daemon::bind_auth_port`] itself. Until set, the port reads 0 —
/// origin membership then admits only what an explicit `--origin` names,
/// which is the honest degenerate for a daemon that is not serving.
pub(crate) struct AuthConfig {
    pub local_trust: bool,
    pub configured: BTreeSet<Origin>,
    port: OnceLock<u16>,
}

impl AuthConfig {
    fn new(opts: AuthOptions) -> AuthConfig {
        AuthConfig {
            local_trust: opts.local_trust,
            configured: opts.origins.into_iter().collect(),
            port: OnceLock::new(),
        }
    }

    /// `Err(port)` when a port is already bound. The value is set ONCE, so
    /// a second bind would otherwise be a silent no-op — and the origin
    /// sets every live session was established against derive from it, so
    /// two callers disagreeing about the number must not be quiet.
    /// [`crate::serve`] and a socket-free embedder are the two, and they
    /// are exclusive by design.
    pub fn bind_port(&self, port: u16) -> Result<(), u16> {
        self.port.set(port)
    }

    pub fn port(&self) -> u16 {
        self.port.get().copied().unwrap_or(0)
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
}

impl AuthState {
    /// Assemble at daemon open: the fold is seeded from the RECOVERED world
    /// (the canonical rebuild — derived state, never a second persistence
    /// layer).
    pub fn open(opts: AuthOptions, world: &World) -> AuthState {
        AuthState {
            cfg: AuthConfig::new(opts),
            challenges: Challenges::new(MAX_LIVE_NONCES),
            sessions: Sessions::new(),
            credential_lock: CredentialLock::new(),
            fold: IdentityFold::seeded(fold::canonical_identity(world)),
            memo: CredMemo::new(),
        }
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
            self.memo.store(sid, id, ack.to_vec());
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

// ── origins (AUTH-4.1–4.8) ───────────────────────────────────────────────

/// One canonical web origin: `scheme://host[:port]`, lowercase, no path, no
/// trailing slash, the scheme's default port OMITTED (AUTH-4.2). `parse`
/// admits ONLY the canonical text, so `parse(s).as_str() == s` for every
/// admitted `s` and the handshake's already-canonical check IS this parse.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Origin {
    canonical: String,
    https: bool,
    host: String,
    /// The resolved port — the explicit one, or the scheme's default.
    port: u16,
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
        let port = match port_text {
            None => default,
            Some(p) => {
                if p.is_empty() || p.len() > 5 || p.starts_with('0') || !p.bytes().all(|b| b.is_ascii_digit()) {
                    return None;
                }
                let n: u32 = p.parse().ok()?;
                let n = u16::try_from(n).ok()?;
                // Canonical form omits the scheme's default port.
                if n == default {
                    return None;
                }
                n
            }
        };
        Some(Origin { canonical: s.to_string(), https, host: host.to_string(), port })
    }

    /// Build the canonical origin from parts — the loopback defaults'
    /// constructor. The SECOND mint site, so it owes what [`Origin::parse`]
    /// admits: canonical by construction for every port this daemon
    /// SERVES on, and not for port 0, which `parse` refuses. That is the
    /// unbound [`AuthConfig`]'s honest degenerate, where the three defaults
    /// are deliberately unmatchable because no request's `Origin` header
    /// can parse to a port-0 origin. The assert is what keeps the two mint
    /// sites in step for every other input.
    fn from_parts(https: bool, host: &str, port: u16) -> Origin {
        let scheme = if https { "https" } else { "http" };
        let default = if https { 443 } else { 80 };
        let canonical = if port == default {
            format!("{scheme}://{host}")
        } else {
            format!("{scheme}://{host}:{port}")
        };
        debug_assert!(
            port == 0 || Origin::parse(&canonical).is_some(),
            "from_parts built an origin the front door refuses: {canonical}"
        );
        Origin { canonical, https, host: host.to_string(), port }
    }

    /// The canonical text — what the wire carries and what health publishes.
    pub fn as_str(&self) -> &str {
        &self.canonical
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
/// the port — never configured, never stored (AUTH-4.1, AUTH-4.2).
pub(crate) fn loopback_defaults(port: u16) -> BTreeSet<Origin> {
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
    if claimed && cfg.local_trust {
        out.push(Warning::ClaimedWithLocalTrust);
    }
    if claimed && cfg.configured.is_empty() {
        out.push(Warning::ClaimedWithEmptyConfigured);
    }
    let defaults = loopback_defaults(cfg.port());
    for o in &cfg.configured {
        let is_loopback_host = !o.https && LOOPBACK_HOSTS.contains(&o.host.as_str());
        if is_loopback_host && !defaults.contains(o) {
            out.push(Warning::ConfiguredLoopbackPortChanged(o.clone()));
        }
    }
    out
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
    /// port, canonical (port omitted at 80).
    #[test]
    fn loopback_defaults_are_the_three_canonical_members() {
        let at_8642: Vec<String> =
            loopback_defaults(8642).iter().map(|o| o.as_str().to_string()).collect();
        assert_eq!(
            at_8642,
            ["http://127.0.0.1:8642", "http://[::1]:8642", "http://localhost:8642"]
        );
        let at_80: Vec<String> =
            loopback_defaults(80).iter().map(|o| o.as_str().to_string()).collect();
        assert_eq!(at_80, ["http://127.0.0.1", "http://[::1]", "http://localhost"]);
    }

    fn cfg_with(port: u16, local_trust: bool, origins: &[&str]) -> AuthConfig {
        let cfg = AuthConfig::new(AuthOptions {
            local_trust,
            origins: origins.iter().map(|s| Origin::parse(s).expect("canonical")).collect(),
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
    fn warning_arms_fire_exactly() {
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
}
