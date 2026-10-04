//! THE WALK over the fixture (REG-3.7 to REG-3.9; REG-3.79 to REG-3.84;
//! REG-1.10, REG-1.11): the three answers — BOUND, UNREGISTERED,
//! BOUND-BUT-UNREACHABLE — RETIRED-WITH-HISTORY, THE HOP NOT MADE, the faces
//! of the resolver's own checks, and the set AS OF the position.

use skep_identity::Fingerprint;
use skep_resolve::{MemberKind, MemberOutcome, Resolution, Term, Transports, Unreachable, Verdict};

use crate::{addr, loopback, names, open_fixture_mirror, public_ip, resolve_prefix};

/// REG-3.7, REG-3.80: `1.2` is BOUND — its binding, its key set, its current
/// endpoint and the member this resolver would dial, every record's verdict
/// beside it; `1.99` is UNREGISTERED, a visible state; `1.3`, bound with no
/// deposit yet, is BOUND-BUT-UNREACHABLE and never UNREGISTERED.
#[test]
fn the_walks_three_answers() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (_, mut mirror) = open_fixture_mirror(dir.path());
    match resolve_prefix(&mut mirror, "1.2") {
        Resolution::Bound { standing, keys, endpoint, dial, members } => {
            assert_eq!(standing.prefix, addr("1.2"));
            assert!(matches!(standing.current.verdict, Verdict::Signed(_)));
            assert_eq!(standing.history.len(), 1);
            assert_eq!(keys.len(), 1, "the node's one key");
            assert!(matches!(endpoint.verdict, Verdict::Signed(_)));
            assert_eq!(endpoint.record.origins, ["https://acme.example.net"]);
            assert_eq!((dial.member, dial.origin.as_str(), dial.kind), (0, "https://acme.example.net", MemberKind::Https));
            assert_eq!(dial.addresses, [public_ip()]);
            assert_eq!(members.len(), 1);
        }
        other => panic!("{other:?}"),
    }
    let unregistered = resolve_prefix(&mut mirror, "1.99");
    assert_eq!(unregistered, Resolution::Unregistered { prefix: addr("1.99") });
    assert_eq!(unregistered.face(), "UNREGISTERED");
    match resolve_prefix(&mut mirror, "1.3") {
        Resolution::BoundButUnreachable { standing, endpoint: None, cause: Unreachable::NoEndpointYet, members, .. } => {
            assert_eq!(standing.prefix, addr("1.3"));
            assert!(members.is_empty());
        }
        other => panic!("{other:?}"),
    }
}

/// REG-3.80, REG-3.83: a RETIRED prefix renders that the org existed, with
/// its history — the allocation and the retirement that replaced it — and
/// names no successor where no ground record stands; never UNREGISTERED.
#[test]
fn retired_with_history_names_the_org_that_existed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (_, mut mirror) = open_fixture_mirror(dir.path());
    match resolve_prefix(&mut mirror, "1.5") {
        Resolution::RetiredWithHistory { standing, successor } => {
            assert_eq!(standing.history.len(), 2);
            assert!(standing.history[0].record.account.is_some(), "the allocation named an account");
            assert_eq!(standing.current.record.account, None, "the retirement names none");
            assert_eq!(standing.current.record.replaces, Some(standing.history[0].link.clone()));
            assert_eq!(successor, None);
        }
        other => panic!("{other:?}"),
    }
}

/// REG-3.82: a depth address whose parent this board binds resolves to the
/// parent's standing and THE HOP NOT MADE, never UNREGISTERED and never a
/// blank; a depth address under no bound prefix is UNREGISTERED.
#[test]
fn the_hop_not_made_at_a_depth_address() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (_, mut mirror) = open_fixture_mirror(dir.path());
    match resolve_prefix(&mut mirror, "1.2.3") {
        Resolution::HopNotMade { prefix, parent } => {
            assert_eq!(prefix, addr("1.2.3"));
            assert!(matches!(*parent, Resolution::Bound { .. }), "{parent:?}");
            assert_eq!(parent.standing().map(|s| s.prefix.clone()), Some(addr("1.2")));
        }
        other => panic!("{other:?}"),
    }
    assert!(matches!(resolve_prefix(&mut mirror, "1.99.1"), Resolution::Unregistered { .. }));
    match resolve_prefix(&mut mirror, "1.5.2") {
        Resolution::HopNotMade { parent, .. } => assert!(matches!(*parent, Resolution::RetiredWithHistory { .. })),
        other => panic!("{other:?}"),
    }
}

/// REG-3.34, REG-3.35, REG-3.80: the faces of the resolver's own checks —
/// unreachable-by-policy on the SCHEME term; on the HOST term at a literal;
/// on the HOST term at a NAME with this resolver's own yield beside it; THE
/// DIAL NOT MADE at an onion member; the one precedence at an onion then an
/// https member; a dead origin; and the org's own nullify leaving the earlier
/// deposit current (REG-1.11).
#[test]
fn the_faces_of_the_resolvers_own_checks() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (_, mut mirror) = open_fixture_mirror(dir.path());
    match resolve_prefix(&mut mirror, "1.8") {
        Resolution::UnreachableByPolicy { member, term: Term::Scheme, members, .. } => {
            assert_eq!(member, "http://plain.example");
            assert_eq!(members.len(), 1);
        }
        other => panic!("{other:?}"),
    }
    match resolve_prefix(&mut mirror, "1.9") {
        Resolution::UnreachableByPolicy { member, term: Term::Host { yielded }, .. } => {
            assert_eq!(member, "https://127.0.0.1");
            assert_eq!(yielded, [loopback()]);
        }
        other => panic!("{other:?}"),
    }
    match resolve_prefix(&mut mirror, "1.12") {
        Resolution::UnreachableByPolicy { member, term: Term::Host { yielded }, .. } => {
            assert_eq!(member, "https://loop.example");
            assert_eq!(yielded, [loopback()], "this resolver's own yield, not the record's");
        }
        other => panic!("{other:?}"),
    }
    match resolve_prefix(&mut mirror, "1.10") {
        Resolution::DialNotMade { member, kind, members, .. } => {
            assert!(member.ends_with(".onion"), "{member}");
            assert_eq!(kind, MemberKind::SelfAuthenticating);
            assert!(matches!(members[0], MemberOutcome::NotDialed { .. }));
        }
        other => panic!("{other:?}"),
    }
    match resolve_prefix(&mut mirror, "1.11") {
        Resolution::Bound { dial, members, .. } => {
            assert_eq!((dial.member, dial.origin.as_str()), (1, "https://eleven.example"));
            assert!(matches!(members[0], MemberOutcome::NotDialed { kind: MemberKind::SelfAuthenticating, .. }));
            assert!(matches!(members[1], MemberOutcome::WouldDial { .. }));
        }
        other => panic!("{other:?}"),
    }
    match resolve_prefix(&mut mirror, "1.15") {
        Resolution::BoundButUnreachable { cause: Unreachable::DeadOrigin { member }, endpoint: Some(_), .. } => {
            assert_eq!(member, "https://dead.example");
        }
        other => panic!("{other:?}"),
    }
    match resolve_prefix(&mut mirror, "1.7") {
        Resolution::Bound { dial, endpoint, .. } => {
            assert_eq!(dial.origin.as_str(), "https://seven.example");
            assert_eq!(endpoint.record.origins, ["https://seven.example"]);
        }
        other => panic!("{other:?}"),
    }
}

/// With an onion transport held, the onion member is the one dialed (REG-3.34
/// as RES-28 amends it): the kind, not the record, decided THE DIAL NOT MADE.
#[test]
fn the_onion_transport_held_dials_the_onion_member() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (_, mut mirror) = open_fixture_mirror(dir.path());
    let transports = Transports { https: true, self_authenticating: true };
    match skep_resolve::resolve(&mut mirror, &addr("1.10"), &names(), &transports).expect("resolve") {
        Resolution::Bound { dial, .. } => {
            assert_eq!((dial.member, dial.kind), (0, MemberKind::SelfAuthenticating));
            assert!(dial.addresses.is_empty(), "nothing to test at a self-authenticating member");
        }
        other => panic!("{other:?}"),
    }
    match skep_resolve::resolve(&mut mirror, &addr("1.11"), &names(), &transports).expect("resolve") {
        Resolution::Bound { dial, .. } => assert_eq!(dial.member, 0, "the first member in the org's order dials"),
        other => panic!("{other:?}"),
    }
}

/// The set AS OF the position (REG-1.86 (e); the mirror reads `key_set` on
/// `/op-at`, never the live table): every binding on the fixture board was
/// signed by the registrar's device key, which the registrar retired after
/// enrolling a third — each is SIGNED under that fingerprint, which the
/// claimant's current set no longer holds; a live-table verifier would have
/// called every one of them unsigned.
#[test]
fn the_set_as_of_the_position_judges_the_record() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (_, mut mirror) = open_fixture_mirror(dir.path());
    let claimant = mirror.claim().map(|(_, c)| c.clone()).expect("the claim");
    let current: Vec<Fingerprint> = mirror.current_keys(&claimant).expect("read").iter().map(|e| Fingerprint::of(&e.key)).collect();
    assert_eq!(current.len(), 2, "the anchor and the rotated key");
    let mut signers = std::collections::BTreeSet::new();
    for prefix in ["1.2", "1.5", "1.6", "1.13"] {
        let face = resolve_prefix(&mut mirror, prefix);
        let standing = face.standing().unwrap_or_else(|| panic!("{prefix}: {face:?}"));
        for binding in &standing.history {
            match &binding.verdict {
                Verdict::Signed(fp) => {
                    assert!(!current.contains(fp), "{prefix}: signed by the key since retired");
                    signers.insert(*fp);
                }
                other => panic!("{prefix}: {other:?}"),
            }
        }
    }
    assert_eq!(signers.len(), 1, "one hand signed every binding");
    match resolve_prefix(&mut mirror, "1.13") {
        Resolution::Bound { dial, .. } => assert_eq!(dial.origin.as_str(), "https://thirteen.example"),
        other => panic!("{other:?}"),
    }
}

/// Every record a face carries stands beside its verdict (REG-1.86 (e)), and
/// every face the fixture reaches names itself.
#[test]
fn every_record_a_face_carries_has_its_verdict_beside_it() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (fixture, mut mirror) = open_fixture_mirror(dir.path());
    let mut faces = std::collections::BTreeSet::new();
    for prefix in fixture.prefixes.clone() {
        let face = resolve_prefix(&mut mirror, &prefix);
        faces.insert(face.face());
        if let Some(standing) = face.standing() {
            assert!(matches!(standing.current.verdict, Verdict::Signed(_)), "{prefix}");
            assert!(standing.history.iter().all(|b| matches!(b.verdict, Verdict::Signed(_))), "{prefix}");
        }
        if let Resolution::Bound { endpoint, .. } | Resolution::UnreachableByPolicy { endpoint, .. } | Resolution::DialNotMade { endpoint, .. } = &face {
            assert!(matches!(endpoint.verdict, Verdict::Signed(_)), "{prefix}");
        }
    }
    for expected in ["BOUND", "UNREGISTERED", "BOUND-BUT-UNREACHABLE", "RETIRED-WITH-HISTORY", "unreachable-by-policy", "THE DIAL NOT MADE", "THE HOP NOT MADE"] {
        assert!(faces.contains(expected), "{expected} not reached: {faces:?}");
    }
}
