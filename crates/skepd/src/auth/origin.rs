//! Web origins (AUTH-4.1–4.11): the canonical form, the two origin sets the
//! handshake and the bare bind admit from, and the config-lockout warnings.

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
fn loopback_defaults(port: Option<u16>) -> BTreeSet<Origin> {
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
/// ENFORCING alike), read off the World's identity slice by the caller,
/// which hands over the one bit this function reads.
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

#[cfg(test)]
mod tests {
    use super::super::AuthOptions;
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
}
