//! THE RESOLVER'S OWN CHECKS (REG-3.34 to REG-3.37; R5 (f), (o)) on the
//! members themselves, no board needed: the scheme term, the host term at a
//! literal and at a name — this resolver's own yield, and the system
//! resolver's at `localhost` — the self-authenticating member with and
//! without its transport, and the ordered walk's one precedence.

use std::collections::HashMap;
use std::net::IpAddr;

use skep_resolve::{judge_member, walk_members, MemberKind, MemberOutcome, SystemResolver, Term, Transports};

use crate::{loopback, public_ip, Names};

fn table(entries: &[(&'static str, Vec<IpAddr>)]) -> Names {
    Names(entries.iter().cloned().collect::<HashMap<_, _>>())
}

const ONION: &str = "http://vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd.onion";

/// REG-3.34, REG-3.35 at a LITERAL: an https member at a public address would
/// dial, at that address; at a loopback, a private or a link-local literal
/// it is refused on the HOST term, the literal named as the yield.
#[test]
fn https_at_a_literal_would_dial_and_a_non_routable_literal_is_refused_on_the_host_term() {
    let names = table(&[]);
    let t = Transports::default();
    assert_eq!(
        judge_member("https://93.184.216.34", &names, &t),
        MemberOutcome::WouldDial { origin: skep_resolve::Origin::parse("https://93.184.216.34").unwrap(), kind: MemberKind::Https, addresses: vec![public_ip()] }
    );
    for (member, ip) in [("https://127.0.0.1", "127.0.0.1"), ("https://10.0.0.7:8443", "10.0.0.7"), ("https://169.254.169.254", "169.254.169.254"), ("https://[::1]", "::1")] {
        assert_eq!(
            judge_member(member, &names, &t),
            MemberOutcome::Refused { member: member.into(), term: Term::Host { yielded: vec![ip.parse().unwrap()] } },
            "{member}"
        );
    }
}

/// REG-3.35 at a NAME: the term is met by the addresses THIS RESOLVER's own
/// resolution yields — every one tested; a name yielding a routable address
/// beside a non-routable one dials the routable alone; a name yielding
/// non-routable addresses only is refused with its yield; a name yielding
/// none is dead, not refused.
#[test]
fn https_at_a_name_is_tested_at_every_address_this_resolver_yields() {
    let names = table(&[
        ("mixed.example", vec![loopback(), public_ip()]),
        ("loop.example", vec![loopback(), "10.1.1.1".parse().unwrap()]),
        ("dead.example", Vec::new()),
    ]);
    let t = Transports::default();
    match judge_member("https://mixed.example", &names, &t) {
        MemberOutcome::WouldDial { addresses, .. } => assert_eq!(addresses, [public_ip()], "connects only to an address that passed"),
        other => panic!("{other:?}"),
    }
    assert_eq!(
        judge_member("https://loop.example", &names, &t),
        MemberOutcome::Refused { member: "https://loop.example".into(), term: Term::Host { yielded: vec![loopback(), "10.1.1.1".parse().unwrap()] } }
    );
    assert!(matches!(judge_member("https://dead.example", &names, &t), MemberOutcome::Dead { .. }));
}

/// REG-3.35 at a name THE SYSTEM resolves: `localhost` yields this host's own
/// loopback addresses, every one non-routable, so the member is refused on
/// the host term with that yield beside it — the resolver's network, not the
/// record's fault.
#[test]
fn at_a_name_the_system_resolver_yields_its_own_addresses() {
    match judge_member("https://localhost", &SystemResolver, &Transports::default()) {
        MemberOutcome::Refused { member, term: Term::Host { yielded } } => {
            assert_eq!(member, "https://localhost");
            assert!(!yielded.is_empty(), "localhost resolves");
            assert!(yielded.iter().all(|ip| ip.is_loopback()), "{yielded:?}");
        }
        other => panic!("{other:?}"),
    }
}

/// REG-3.34 as RES-1 and RES-28 amend it: an `.onion` member is a
/// self-authenticating origin under either scheme — not dialed without its
/// transport, with no refusal and the record standing admitted; dialed with
/// it, there being nothing to test.
#[test]
fn a_self_authenticating_member_is_not_dialed_without_its_transport_and_dialed_with_it() {
    let names = table(&[]);
    for member in [ONION, &ONION.replacen("http://", "https://", 1)] {
        assert!(
            matches!(judge_member(member, &names, &Transports::default()), MemberOutcome::NotDialed { kind: MemberKind::SelfAuthenticating, .. }),
            "{member}"
        );
        match judge_member(member, &names, &Transports { https: true, self_authenticating: true }) {
            MemberOutcome::WouldDial { kind: MemberKind::SelfAuthenticating, addresses, .. } => assert!(addresses.is_empty()),
            other => panic!("{member}: {other:?}"),
        }
    }
}

/// REG-3.34: a plaintext `http` member to any other host, and a member that
/// is no canonical origin at all — a bare host, a path, an uppercase scheme —
/// are refused on the SCHEME term.
#[test]
fn a_plaintext_member_and_a_bare_host_are_refused_on_the_scheme_term() {
    let names = table(&[("plain.example", vec![public_ip()])]);
    let t = Transports::default();
    for member in ["http://plain.example", "plain.example", "https://plain.example/", "HTTPS://plain.example", "ftp://plain.example", ""] {
        assert_eq!(judge_member(member, &names, &t), MemberOutcome::Refused { member: member.into(), term: Term::Scheme }, "{member}");
    }
}

/// REG-3.34's ONE PRECEDENCE (RES-16, RES-28): the walk falls through every
/// member that would not dial and P resolves at the FIRST that would; where
/// none would, the dial is none and the first member's outcome is the face's.
#[test]
fn the_ordered_walk_has_one_precedence() {
    let names = table(&[("dead.example", Vec::new()), ("acme.example", vec![public_ip()])]);
    let t = Transports::default();
    let walk = |members: &[&str]| walk_members(&members.iter().map(|m| m.to_string()).collect::<Vec<_>>(), &names, &t);
    assert_eq!(walk(&[ONION, "https://acme.example"]).dial.map(|d| d.member), Some(1));
    assert_eq!(walk(&["http://plain.example", "https://acme.example"]).dial.map(|d| d.member), Some(1));
    assert_eq!(walk(&["https://dead.example", "https://127.0.0.1", "https://acme.example"]).dial.map(|d| d.member), Some(2));
    assert_eq!(walk(&["https://acme.example", ONION]).dial.map(|d| d.member), Some(0));
    let none = walk(&["http://plain.example", ONION, "https://dead.example"]);
    assert_eq!(none.dial, None);
    assert_eq!(none.outcomes.len(), 3);
    assert!(matches!(none.outcomes[0], MemberOutcome::Refused { term: Term::Scheme, .. }));
    assert!(matches!(none.outcomes[1], MemberOutcome::NotDialed { .. }));
    assert!(matches!(none.outcomes[2], MemberOutcome::Dead { .. }));
    assert_eq!(walk(&[]).dial, None, "no member, no dial");
}
