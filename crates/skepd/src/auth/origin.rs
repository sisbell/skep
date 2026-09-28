//! `Origin`, `NotCanonical`, `PortAlreadyBound`, the origin sets, and startup warnings.

use std::collections::BTreeSet;
use std::fmt;

use super::options::{AuthConfig, Mode};

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
pub struct PortAlreadyBound(pub(super) u16);

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
            // The ORIGIN consequence alone (AUTH-4.9 as RES-206 landed it,
            // xb-d10): no key strands at an origin change — the frontend's
            // keys are its shell's, bound to no origin, and no per-origin key
            // store is planned — so the warning names the re-issue and
            // nothing of keys.
            Warning::ConfiguredLoopbackPortChanged(o) => write!(
                f,
                "configured origin {o} names a loopback host at a port this \
                 daemon is not bound to; re-issue the origin for the bound port",
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
