//! The canonical web origin (AUTH-4.2) — this crate's OWN reproduction of the
//! daemon's grammar. The grammar is the DAEMON's (AUTH-4.1; AUTH RES-61:
//! `Origin` and `session_payload` live at `skepd::auth`), and a client that
//! must not link the daemon reproduces the parse from the written rule and
//! holds it equal to the daemon's by a VECTOR SET fed from the daemon's own
//! admitted and refused strings (P5; `client.md` §1.6, §9 item 6): the
//! `tests` module below runs `skepd::auth::origin`'s own vectors against
//! this parse, and never derives the grammar from the daemon.
//!
//! Why the parse admits ONLY the canonical text: the origin a client signs
//! (AUTH-4.8 — the origin of the board it ADDRESSES, the one it dialed) is
//! compared byte for byte against the board's published sets, so a
//! non-canonical spelling that parsed here would sign a string no board
//! answers for. `parse(s).as_str() == s` for every admitted `s`.

use std::fmt;
use std::net::IpAddr;

/// One canonical web origin: `scheme://host[:port]`, lowercase, no path, no
/// trailing slash, the scheme's default port OMITTED (AUTH-4.2). The
/// canonical text is the whole value; the parts beside it answer the two
/// questions a client asks of an origin — what to dial (host, port, scheme)
/// and whether the host is a loopback one (the plaintext warning, §9 item
/// 23).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Origin {
    canonical: String,
    https: bool,
    host: String,
    port: u16,
}

/// The three loopback-host names the daemon's bare set derives from
/// (AUTH-4.1; AUTH-7.21: the set is CLOSED at these three).
const LOOPBACK_HOSTS: [&str; 3] = ["127.0.0.1", "localhost", "[::1]"];

impl Origin {
    /// Parse a canonical origin; `None` for anything else — uppercase, a
    /// path, a trailing slash, `null`, an explicit default port, a
    /// zero-padded port, an empty host, a port past 65535 (the daemon's own
    /// doc, reproduced; the daemon's refused strings are the test's).
    pub fn parse(s: &str) -> Option<Origin> {
        let (https, rest) = if let Some(r) = s.strip_prefix("http://") {
            (false, r)
        } else if let Some(r) = s.strip_prefix("https://") {
            (true, r)
        } else {
            return None;
        };
        let (host, port_text) = if let Some(after) = rest.strip_prefix('[') {
            // A bracketed IPv6 host.
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
        let default: u16 = if https { 443 } else { 80 };
        let port = match port_text {
            Some(p) => {
                // The two conditions std does not perform: a leading zero
                // is not canonical, and `u16::from_str` admits a `+`.
                if p.starts_with('0') || !p.bytes().all(|b| b.is_ascii_digit()) {
                    return None;
                }
                let port: u16 = p.parse().ok()?;
                // Canonical form omits the scheme's default port.
                if port == default {
                    return None;
                }
                port
            }
            None => default,
        };
        Some(Origin { canonical: s.to_string(), https, host: host.to_string(), port })
    }

    /// The canonical text — what the signed body carries and what the
    /// bindings file keys on.
    pub fn as_str(&self) -> &str {
        &self.canonical
    }

    /// `https://`, the `tls` arm's dial.
    pub fn is_https(&self) -> bool {
        self.https
    }

    /// The host as the origin spells it — brackets kept for an IPv6
    /// literal, which is how the `Host` header carries it.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The host to RESOLVE — the IPv6 literal's brackets shed.
    pub fn dial_host(&self) -> &str {
        self.host.trim_start_matches('[').trim_end_matches(']')
    }

    /// The port the origin names, the scheme's default where it omits one.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// `host[:port]` as the origin spells it — the `Host` header's value.
    pub fn authority(&self) -> &str {
        &self.canonical[if self.https { "https://".len() } else { "http://".len() }..]
    }

    /// Whether the host is a LOOPBACK one — one of the daemon's three
    /// loopback names, or an IP literal in the loopback range — the fact
    /// the plaintext warning keys on (AUTH-4.53: a plaintext non-loopback
    /// bind is signed-session-unsafe for the dialing client; §9 item 23).
    pub fn names_loopback_host(&self) -> bool {
        LOOPBACK_HOSTS.contains(&self.host.as_str())
            || self.dial_host().parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
    }
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.canonical)
    }
}

/// Host canonicality: lowercase letters, digits, `.`, `-`, and the
/// bracketed-IPv6 alphabet (`[`, `]`, `:`) — the daemon's own alphabet, so
/// a `.onion` host parses like any other (§7: parsed, dialed by no client).
fn host_is_canonical(host: &str) -> bool {
    host.bytes().all(|b| {
        b.is_ascii_lowercase()
            || b.is_ascii_digit()
            || matches!(b, b'.' | b'-' | b'[' | b']' | b':')
    })
}

/// [`Origin::parse`] refused: the text is not a canonical origin. The phrase
/// is the daemon's `NotCanonical` phrase VERBATIM (`client.md` §7), so a
/// person meets one sentence for one grammar at either end.
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

impl std::str::FromStr for Origin {
    type Err = NotCanonical;

    fn from_str(s: &str) -> Result<Origin, NotCanonical> {
        Origin::parse(s).ok_or(NotCanonical)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// THE VECTOR AGREEMENT (P5; AUTH-4.2; `client.md` §1.6): the daemon's
    /// own admitted and refused strings — `skepd::auth::origin`'s
    /// `origins_are_canonical_only`, copied here as the vector set and never
    /// linked — parse the same way under this crate's parse. Run against
    /// BOTH parses: the daemon's `Origin` is on this suite's path through
    /// the dev-dependency, so a divergence fails here and not in a person's
    /// hands as a self-inflicted 401.
    #[test]
    fn the_daemons_vectors_agree_with_this_parse() {
        let admitted = [
            "http://127.0.0.1:8642",
            "http://localhost:8642",
            "http://[::1]:8642",
            "http://127.0.0.1",
            "https://example.org",
            "https://skep.example:8443",
        ];
        let refused = [
            "http://127.0.0.1:80",
            "https://example.org:443",
            "HTTP://x",
            "http://X.org",
            "http://x/",
            "http://x/path",
            "null",
            "",
            "http://x:08642",
            "ftp://x",
            "http://",
            "http://x:",
            "http://x:0",
        ];
        for ok in admitted {
            let o = Origin::parse(ok).unwrap_or_else(|| panic!("'{ok}' is canonical"));
            assert_eq!(o.as_str(), ok, "the admitted text is the canonical text");
            assert_eq!(o.to_string(), ok);
            assert!(
                skepd::Origin::parse(ok).is_some(),
                "the daemon admits '{ok}' — the vector set's premise"
            );
        }
        for bad in refused {
            assert!(Origin::parse(bad).is_none(), "'{bad}' must not parse");
            assert!(
                skepd::Origin::parse(bad).is_none(),
                "the daemon refuses '{bad}' — the vector set's premise"
            );
        }
    }

    /// THE AGREEMENT AS A LAW (P5): over every string of a generated family
    /// — schemes, hosts, ports and tails no person picked, the near misses
    /// among them — this parse admits exactly what the daemon's admits, and
    /// each admitted string is its own canonical text.
    #[test]
    fn the_two_parses_agree_over_a_generated_family() {
        let schemes = ["http://", "https://", "HTTP://", "ftp://", ""];
        let hosts = [
            "127.0.0.1", "localhost", "[::1]", "example.org", "skep.example", "abc.onion", "xn--bcher-kva.example",
            "X.org", "x_y", "a b", "[::1", "[]", "",
        ];
        let ports = ["", ":", ":0", ":80", ":443", ":8642", ":08642", ":+8642", ":65535", ":65536", ":8642:1", ":-1"];
        let tails = ["", "/", "?q", "#f", "@y", "/path"];
        let mut admitted = 0;
        for scheme in schemes {
            for host in hosts {
                for port in ports {
                    for tail in tails {
                        let s = format!("{scheme}{host}{port}{tail}");
                        let ours = Origin::parse(&s);
                        assert_eq!(ours.is_some(), skepd::Origin::parse(&s).is_some(), "the two parses disagree on {s:?}");
                        if let Some(o) = ours {
                            assert_eq!((o.as_str(), o.to_string()), (s.as_str(), s.clone()), "the admitted text is the canonical text");
                            admitted += 1;
                        }
                    }
                }
            }
        }
        assert!(admitted > 0, "the family admits no string: it tests nothing");
    }

    /// The parts answer what a dial asks: scheme, host (brackets kept for
    /// the `Host` header, shed for the resolver), the port the scheme
    /// defaults, and the loopback test the plaintext warning keys on.
    #[test]
    fn the_parts_answer_the_dial_and_the_loopback_test() {
        let o = Origin::parse("http://[::1]:8642").unwrap();
        assert_eq!((o.host(), o.dial_host(), o.port(), o.authority()), ("[::1]", "::1", 8642, "[::1]:8642"));
        assert!(!o.is_https() && o.names_loopback_host());
        let o = Origin::parse("https://board.example").unwrap();
        assert_eq!((o.port(), o.authority()), (443, "board.example"));
        assert!(o.is_https() && !o.names_loopback_host());
        assert!(Origin::parse("http://127.5.0.1:9000").unwrap().names_loopback_host());
        assert!(!Origin::parse("http://10.0.0.7:9000").unwrap().names_loopback_host());
        assert!(Origin::parse("http://abc.onion").is_some(), "an onion host parses (§7)");
        assert_eq!("x".parse::<Origin>().unwrap_err().to_string(), NotCanonical.to_string());
    }
}
