//! THE RESOLVER'S OWN CHECKS (REG-3.34 to REG-3.37; R5 (f), (o)) — https is
//! enforced AT THE RESOLVER with zero protocol machinery, the refusal has a
//! SECOND TERM, the HOST, and the ordered walk over the endpoint's members
//! has ONE precedence.
//!
//! An endpoint record's value is an ORDERED LIST OF ORIGINS in the org's own
//! order (REG-3.34). Each member is judged here, in that order, and the
//! judgement answers which member this resolver WOULD dial and why the
//! others would not. NO SOCKET IS OPENED to any member: the dial itself is
//! the caller's, with the transports it holds; what this module settles is
//! the terms a member meets BEFORE ANY CONNECTION IS MADE (REG-3.35).
//!
//! * THE SCHEME TERM (REG-3.34): every member is `https`, or a
//!   SELF-AUTHENTICATING origin — one whose address IS the service's key, so
//!   the check https performs is already performed; the `.onion` address is
//!   the first admitted kind, under either scheme. A plaintext `http` member
//!   to any other host, and a member that is no canonical origin at all, is
//!   REFUSED on this term.
//! * THE HOST TERM (REG-3.35; RES-30): a resolver refuses an endpoint whose
//!   host is not GLOBALLY ROUTABLE — a loopback, a link-local, a private
//!   range, a host-local metadata service — at every origin it would dial.
//!   The term is MET BY AN ADDRESS AND NEVER BY A NAME: a host written as an
//!   IP literal is tested as that literal; a host written as a NAME is tested
//!   at EVERY ADDRESS this resolver's own resolution of the name yields, and
//!   the dial connects only to an address that passed. A name that yields
//!   addresses and no routable one is refused as the literal is; a name that
//!   yields none is not refused but DEAD (endpoint rot). A
//!   self-authenticating member meets the term by construction: there is
//!   nothing to test.
//! * THE THIRD WAY A MEMBER DOES NOT DIAL (REG-3.34 as RES-28 amends it): a
//!   member of an ADMITTED kind whose TRANSPORT this resolver does not hold —
//!   an `.onion` address on a client with no onion transport — is NOT DIALED,
//!   no refusal and the record standing admitted.
//! * THE ONE PRECEDENCE (REG-3.34 as RES-16 amends it; REG-3.80): the walk
//!   falls through every member that would not dial, and P resolves at the
//!   FIRST member that would; the terminal faces render only where NO member
//!   would, and then P's face is the FIRST member's in the list's order, each
//!   later member's outcome renderable beside it.
//! * NO RESOLVER CLASS keyed on a board's health face exists (REG-3.37):
//!   nothing live is read here; the test reads the endpoint RECORD.
//!
//! The canonical origin grammar is the daemon's own (`scheme://host[:port]`,
//! lowercase, no path, the scheme's default port omitted) — the precedent
//! for the scheme term, re-spelled here because a client links no daemon.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};

/// One canonical web origin: `scheme://host[:port]`, lowercase, no path, no
/// trailing slash, the scheme's default port omitted — the daemon's own
/// grammar for an origin (AUTH-4.2), which this crate re-spells since it
/// links no daemon. `parse` admits ONLY the canonical text.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Origin {
    canonical: String,
    https: bool,
    host: String,
    port: u16,
}

impl Origin {
    /// Parse a canonical origin; `None` for anything else — uppercase, a
    /// path, a trailing slash, an explicit default port, a zero-padded port,
    /// a scheme that is neither `http` nor `https`.
    pub fn parse(s: &str) -> Option<Origin> {
        let (https, rest) = s
            .strip_prefix("http://")
            .map(|r| (false, r))
            .or_else(|| s.strip_prefix("https://").map(|r| (true, r)))?;
        let (host, port_text) = if let Some(after) = rest.strip_prefix('[') {
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
            Some(p) => {
                if p.starts_with('0') || !p.bytes().all(|b| b.is_ascii_digit()) {
                    return None;
                }
                let port = p.parse::<u16>().ok()?;
                if port == default || port == 0 {
                    return None;
                }
                port
            }
            None => default,
        };
        Some(Origin { canonical: s.to_string(), https, host: host.to_string(), port })
    }

    /// The canonical text.
    pub fn as_str(&self) -> &str {
        &self.canonical
    }

    /// The host as written — a name, an IPv4 literal, or a bracketed IPv6
    /// literal.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The port the dial would use: the one written, or the scheme's
    /// default.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Whether the scheme is `https`.
    pub fn is_https(&self) -> bool {
        self.https
    }

    /// The SELF-AUTHENTICATING kind the host is, where it is one (REG-3.34
    /// as RES-1 amends it) — an origin whose address IS the service's key,
    /// under either scheme: an `.onion` host is [`MemberKind::Onion`], the
    /// first admitted kind; a later kind is one more arm here, by name.
    pub fn self_authenticating_kind(&self) -> Option<MemberKind> {
        self.host.ends_with(".onion").then_some(MemberKind::Onion)
    }

    /// The host as an IP literal, where it is one.
    pub fn ip_literal(&self) -> Option<IpAddr> {
        let bare = self.host.trim_start_matches('[').trim_end_matches(']');
        bare.parse::<IpAddr>().ok()
    }
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.canonical)
    }
}

/// Host canonicality: lowercase letters, digits, `.`, `-`, and the
/// bracketed-IPv6 alphabet.
fn host_is_canonical(host: &str) -> bool {
    host.bytes().all(|b| {
        b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-' | b'[' | b']' | b':')
    })
}

/// THE HOST TERM's test (REG-3.35): whether an address is GLOBALLY ROUTABLE
/// — not a loopback, a link-local (the host-local metadata service lives
/// there), a private range, the shared address space, the unspecified
/// address, a broadcast or multicast address, a reserved or documentation
/// range. An IPv4-mapped IPv6 address is tested as its IPv4.
pub fn routable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => routable_v4(v4),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => routable_v4(v4),
            None => routable_v6(v6),
        },
    }
}

fn routable_v4(a: Ipv4Addr) -> bool {
    let [o0, o1, _, _] = a.octets();
    !(a.is_unspecified()
        || a.is_loopback()
        || a.is_private()
        || a.is_link_local()
        || a.is_broadcast()
        || a.is_multicast()
        || a.is_documentation()
        || o0 == 0
        || (o0 == 100 && (64..=127).contains(&o1))
        || (o0 == 192 && o1 == 0 && a.octets()[2] == 0)
        || (o0 == 198 && (o1 == 18 || o1 == 19))
        || o0 >= 240)
}

fn routable_v6(a: Ipv6Addr) -> bool {
    let seg = a.segments();
    !(a.is_unspecified()
        || a.is_loopback()
        || a.is_multicast()
        || (seg[0] & 0xffc0) == 0xfe80
        || (seg[0] & 0xfe00) == 0xfc00
        || (seg[0] == 0x2001 && seg[1] == 0x0db8))
}

/// THIS RESOLVER'S OWN RESOLUTION OF A NAME (REG-3.35): the addresses a host
/// name yields, which the host term is then tested at. A trait so a suite
/// can hold the yield fixed; the shipped resolver is [`SystemResolver`].
/// `Err` is a resolution that could not run; an empty `Ok` is a name that
/// yields none — both are the DEAD arm, never a refusal.
pub trait NameResolver {
    fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, String>;
}

/// The operating system's resolver, over `std::net::ToSocketAddrs`.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemResolver;

impl NameResolver for SystemResolver {
    fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, String> {
        let addrs = (host, 0u16).to_socket_addrs().map_err(|e| e.to_string())?;
        Ok(addrs.map(|a| a.ip()).collect())
    }
}

/// The transports this resolver holds, one per admitted kind, by the kind's
/// name (REG-3.34 as RES-28 amends it): a member of a kind whose transport
/// is not held is NOT DIALED. The default is the frontend's: https held, no
/// onion transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Transports {
    pub https: bool,
    pub onion: bool,
}

impl Default for Transports {
    fn default() -> Transports {
        Transports { https: true, onion: false }
    }
}

/// The admitted kinds of an endpoint member (REG-3.34), each by its name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MemberKind {
    /// An `https` origin.
    Https,
    /// An `.onion` address — the first admitted SELF-AUTHENTICATING kind
    /// (REG-3.34 as RES-1 amends it), its transport the onion transport
    /// (RES-28).
    Onion,
}

impl MemberKind {
    /// The kind's name, a token a renderer keys on.
    pub fn name(self) -> &'static str {
        match self {
            MemberKind::Https => "https",
            MemberKind::Onion => "onion",
        }
    }

    /// Whether the kind's address IS the service's key: the host term met
    /// by construction (REG-3.35), each such kind admitted BY NAME
    /// (REG-3.34).
    pub fn is_self_authenticating(self) -> bool {
        match self {
            MemberKind::Https => false,
            MemberKind::Onion => true,
        }
    }
}

/// WHICH TERM refused a member (REG-3.80's unreachable-by-policy row): the
/// scheme (REG-3.34), or the host (REG-3.35) — on the host term met at a
/// name, with the addresses THIS RESOLVER's own resolution yielded, labelled
/// as this resolver's yield and never the record's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Term {
    Scheme,
    Host { yielded: Vec<IpAddr> },
}

/// One member's outcome at this resolver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemberOutcome {
    /// The member passes every term and this resolver holds its transport:
    /// it WOULD be dialed — at `addresses`, the literal or the routable
    /// addresses this resolver's resolution yielded (never one that did not
    /// pass the test).
    WouldDial { origin: Origin, kind: MemberKind, addresses: Vec<IpAddr> },
    /// The member is refused on a term; the record's string as deposited.
    Refused { member: String, term: Term },
    /// An admitted kind whose transport this resolver does not hold: not
    /// dialed, not refused.
    NotDialed { origin: Origin, kind: MemberKind },
    /// A name that yields no address: dead, not refused.
    Dead { origin: Origin },
}

/// The endpoint member this resolver WOULD dial: its index in the org's
/// order, the origin, and the addresses that passed the host term.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointDial {
    pub member: usize,
    pub origin: Origin,
    pub kind: MemberKind,
    pub addresses: Vec<IpAddr>,
}

/// The ordered walk's whole answer: every member's outcome in the org's
/// order, and the first that would dial, where one would.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointWalk {
    pub outcomes: Vec<MemberOutcome>,
    pub dial: Option<EndpointDial>,
}

/// Judge ONE member (REG-3.34, REG-3.35): the scheme term, the kind, the
/// transport held, then the host term at the literal or at every address the
/// name yields. No connection is made.
pub fn judge_member(member: &str, names: &dyn NameResolver, transports: &Transports) -> MemberOutcome {
    let refused = |term: Term| MemberOutcome::Refused { member: member.to_string(), term };
    let Some(origin) = Origin::parse(member) else {
        return refused(Term::Scheme);
    };
    // The kind: a self-authenticating kind under either scheme; else https
    // alone.
    let kind = match origin.self_authenticating_kind() {
        Some(kind) => kind,
        None if origin.is_https() => MemberKind::Https,
        None => return refused(Term::Scheme),
    };
    let held = match kind {
        MemberKind::Https => transports.https,
        MemberKind::Onion => transports.onion,
    };
    if !held {
        return MemberOutcome::NotDialed { origin, kind };
    }
    // The host term: nothing to test at a self-authenticating member.
    if kind.is_self_authenticating() {
        return MemberOutcome::WouldDial { origin, kind, addresses: Vec::new() };
    }
    if let Some(literal) = origin.ip_literal() {
        return if routable(literal) {
            MemberOutcome::WouldDial { origin, kind, addresses: vec![literal] }
        } else {
            refused(Term::Host { yielded: vec![literal] })
        };
    }
    let yielded = names.resolve(origin.host()).unwrap_or_default();
    if yielded.is_empty() {
        return MemberOutcome::Dead { origin };
    }
    let passed: Vec<IpAddr> = yielded.iter().copied().filter(|ip| routable(*ip)).collect();
    if passed.is_empty() {
        refused(Term::Host { yielded })
    } else {
        MemberOutcome::WouldDial { origin, kind, addresses: passed }
    }
}

/// THE ORDERED WALK over an endpoint's members (REG-3.34's one precedence):
/// every member judged in the org's order, the first that would dial taken
/// as the dial; where none would, the dial is `None` and the first member's
/// outcome is the face's (REG-3.80).
pub fn walk_members(origins: &[String], names: &dyn NameResolver, transports: &Transports) -> EndpointWalk {
    let outcomes: Vec<MemberOutcome> =
        origins.iter().map(|m| judge_member(m, names, transports)).collect();
    let dial = outcomes.iter().enumerate().find_map(|(i, o)| match o {
        MemberOutcome::WouldDial { origin, kind, addresses } => Some(EndpointDial {
            member: i,
            origin: origin.clone(),
            kind: *kind,
            addresses: addresses.clone(),
        }),
        _ => None,
    });
    EndpointWalk { outcomes, dial }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The canonical grammar admits the canonical text alone, as the
    /// daemon's own origin parse does.
    #[test]
    fn origins_are_canonical_only() {
        for ok in ["https://acme.example", "https://acme.example:8443", "http://x.onion", "https://[2606:2800:220:1:248:1893:25c8:1946]", "http://127.0.0.1:8642"] {
            let o = Origin::parse(ok).unwrap_or_else(|| panic!("'{ok}' is canonical"));
            assert_eq!(o.as_str(), ok);
        }
        for bad in ["https://acme.example:443", "http://x:80", "HTTPS://x", "https://X.org", "https://x/", "https://x/path", "ftp://x", "https://", "https://x:", "https://x:0", "https://x:08443", "", "acme.example"] {
            assert!(Origin::parse(bad).is_none(), "'{bad}' must not parse");
        }
        assert_eq!(Origin::parse("https://acme.example").unwrap().port(), 443);
        assert_eq!(Origin::parse("http://acme.example").unwrap().port(), 80);
    }

    /// REG-3.35's classes are not routable; a public address is.
    #[test]
    fn the_host_term_refuses_the_named_ranges_and_passes_a_public_address() {
        for bad in ["127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254", "0.0.0.0", "255.255.255.255", "224.0.0.1", "100.64.0.1", "192.0.2.1", "198.18.0.1", "::1", "fe80::1", "fd00::1", "ff02::1", "::", "2001:db8::1", "::ffff:127.0.0.1"] {
            assert!(!routable(bad.parse().unwrap()), "{bad} is not globally routable");
        }
        for ok in ["93.184.216.34", "8.8.8.8", "2606:2800:220:1:248:1893:25c8:1946", "::ffff:8.8.8.8"] {
            assert!(routable(ok.parse().unwrap()), "{ok} is globally routable");
        }
    }
}
