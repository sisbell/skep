use skep_engine::Engine;
use skep_febe::OperationSurface;
use skep_identity::SigAlgRow;
use skep_kernel::{CheckpointPolicy, Durability, KernelConfig, SaltSource};
use skep_signature::{TAG_FNDSA512_PREVIEW_ED25519, TAG_MLDSA65_ED25519};

use super::super::AuthOptions;
use super::*;

/// The two rows' blob widths, pinned by hand — tag 1's ML-DSA-65 3,309
/// bytes then Ed25519's 64, tag 3's FN-DSA-512 666 then 64 — and held to
/// `SIG_ALGS` by `the_sig_is_admitted_at_exactly_the_two_hybrid_widths`.
const TAG1_SIG_LEN: usize = 3373;
const TAG3_SIG_LEN: usize = 730;

/// A config bound at `port`, with no configured origin — so the bare
/// set is exactly the three loopback defaults and every membership
/// answer below is the defaults' own.
fn cfg_at(port: u16, local_trust: bool) -> AuthConfig {
    let cfg = AuthConfig::new(AuthOptions { local_trust, ..AuthOptions::default() });
    cfg.bind_port(port).expect("a fresh config binds once");
    cfg
}

/// AUTH-4.16 — strict lowercase nonces: the round trip is
/// byte-identical, uppercase refuses.
#[test]
fn nonce_hex_is_strict_lowercase() {
    let n = Nonce([0xab; 32]);
    assert_eq!(n.to_hex(), "ab".repeat(32));
    assert_eq!(Nonce::parse_hex(&n.to_hex()), Some(n));
    assert!(Nonce::parse_hex(&"AB".repeat(32)).is_none(), "uppercase is a syntax fault");
    assert!(Nonce::parse_hex("ab").is_none());
}

/// AUTH-4.17 — token round-trip and strict admission.
#[test]
fn token_parse_admits_only_to_wire_output() {
    let t = Token([0xab; 16]);
    // Compared through `to_wire`, which is injective (AUTH-4.17), so
    // this is the same property — and a failure names the wire form
    // rather than the two `<redacted>`s `Token`'s own `Debug` prints.
    assert_eq!(Token::parse(&t.to_wire()).map(|p| p.to_wire()), Some(t.to_wire()));
    assert!(Token::parse("nonsense").is_none());
    assert!(Token::parse(&t.to_wire().to_uppercase()).is_none());
    // The old daemon's prefix.suffix shape is refused — AUTH-7.25 names
    // it as exactly the forbidden one.
    assert!(Token::parse("9f3a6c21d4b8e07a.1").is_none());
}

/// The token's `Debug` is its presence and never its bytes ("compared
/// exactly, never logged"): the bytes are the credential, and a derived
/// `Debug` prints them wherever a token rides a `{:?}`.
#[test]
fn a_tokens_debug_prints_no_part_of_the_credential() {
    let t = Token([0xab; 16]);
    let printed = format!("{t:?}");
    assert!(!printed.contains(&t.to_wire()), "the wire form: {printed}");
    assert!(!printed.contains(&format!("{:?}", [0xabu8; 16])), "the bytes: {printed}");
}

/// AUTH-4.21 — single use: a burned nonce is gone whether or not it
/// validated; expiry and wrong-principal both burn.
#[test]
fn challenges_are_single_use_and_expire() {
    let ch = Challenges::new(4);
    let mut rng = super::super::OsEntropy;
    let now = Instant::now();
    let n = ch.issue(PrincipalId(7), now, &mut rng);
    assert!(!ch.burn(&n, PrincipalId(8), now), "wrong principal refuses");
    assert!(!ch.burn(&n, PrincipalId(7), now), "and the entry burned with it");
    let n2 = ch.issue(PrincipalId(7), now, &mut rng);
    assert!(!ch.burn(&n2, PrincipalId(7), now + CHALLENGE_TTL), "expiry refuses");
    let n3 = ch.issue(PrincipalId(7), now, &mut rng);
    assert!(ch.burn(&n3, PrincipalId(7), now + Duration::from_secs(1)));
    assert!(!ch.burn(&n3, PrincipalId(7), now + Duration::from_secs(1)), "single use");
}

/// The burn's SWEEP is skipped on a MISS, and a miss leaves the store
/// exactly as it was — the premise that makes skipping it
/// answer-preserving. `POST /session` reaches the burn with any 64-hex
/// nonce, past the origin-set test and nothing else, so the miss is the
/// path a stranger drives; if a miss ever began to disturb the store, the
/// skip would silently change behaviour rather than merely cost less.
#[test]
fn a_burn_that_misses_leaves_the_store_untouched() {
    let ch = Challenges::new(2);
    let mut rng = super::super::OsEntropy;
    let now = Instant::now();
    let a = ch.issue(PrincipalId(1), now, &mut rng);
    let b = ch.issue(PrincipalId(1), now, &mut rng);
    let stranger = Nonce([0x5a; 32]);
    for _ in 0..8 {
        assert!(!ch.burn(&stranger, PrincipalId(1), now), "a nonce nobody issued");
    }
    // Both live nonces still burn: the misses removed nothing and, at a
    // cap of two, displaced nothing either.
    assert!(ch.burn(&a, PrincipalId(1), now), "the first still burns");
    assert!(ch.burn(&b, PrincipalId(1), now), "and so does the second");
}

/// AUTH-4.14's classification, at the two cells its near-misses get
/// wrong in opposite directions: the WHOLE of `127.0.0.0/8` and `::1`
/// are loopback — so an IPv4-literal test would deny a legitimate `::1`
/// bare bind — and every routable address is remote, including the
/// private ranges a host-reachability notion would admit, which is the
/// silent widening that hands the bare bind to a LAN.
#[test]
fn a_peer_is_loopback_over_the_whole_of_both_loopback_ranges() {
    for ip in ["127.0.0.1", "127.0.0.2", "127.255.255.254", "::1"] {
        let parsed: IpAddr = ip.parse().expect("a literal address");
        assert_eq!(Peer::of(parsed), Peer::Loopback, "{ip}");
    }
    for ip in ["10.0.0.1", "192.168.1.7", "172.16.0.1", "8.8.8.8", "::", "fe80::1", "2001:db8::1"] {
        let parsed: IpAddr = ip.parse().expect("a literal address");
        assert_eq!(Peer::of(parsed), Peer::Remote, "{ip}");
    }
    // The v4-mapped form of a loopback address is NOT itself loopback —
    // `::ffff:127.0.0.1` is a v6 address whose own range is routable —
    // so a peer that arrives in it is refused the bare bind rather than
    // granted it by a mapping this daemon does not perform.
    let mapped: IpAddr = "::ffff:127.0.0.1".parse().expect("a literal address");
    assert_eq!(Peer::of(mapped), Peer::Remote);
}

/// AUTH-4.26 — the bare-bind cells, the board's MODE first: a loopback
/// peer at an admitted origin is refused in ENFORCING, and a
/// non-loopback peer or an unadmitted origin is refused for THIS
/// REQUEST, which is not death.
#[test]
fn bare_bind_cells_answer_mode_before_request() {
    let cfg = cfg_at(8642, true);
    let dialed = format!("http://127.0.0.1:{}", 8642);
    // UNCLAIMED and CLAIMED-PERMISSIVE both honor the bare bind.
    for claimed in [false, true] {
        assert_eq!(
            bare_bind_allowed(&cfg, Peer::Loopback, None, claimed),
            BareBind::Allowed,
            "claimed={claimed}: an absent Origin is ok"
        );
        assert_eq!(
            bare_bind_allowed(&cfg, Peer::Loopback, Some(&dialed), claimed),
            BareBind::Allowed,
            "claimed={claimed}: a loopback default is in the bare set"
        );
        assert_eq!(
            bare_bind_allowed(&cfg, Peer::Remote, None, claimed),
            BareBind::RequestRefused,
            "claimed={claimed}: a non-loopback peer is refused for this request"
        );
        for bad in ["https://evil.example", "null", "http://127.0.0.1:9999"] {
            assert_eq!(
                bare_bind_allowed(&cfg, Peer::Loopback, Some(bad), claimed),
                BareBind::RequestRefused,
                "claimed={claimed}: '{bad}' is not in the bare set"
            );
        }
    }
    // The claimed board with the flag off is ENFORCING, which answers
    // the MODE refusal FIRST — so a cell where both the mode and the
    // request would refuse still answers `ModeRefused`. The same config
    // reads UNCLAIMED before the claim, which is the last cell.
    let enforcing_cfg = cfg_at(8642, false);
    assert_eq!(Mode::of(&enforcing_cfg, true), Mode::Enforcing);
    assert_eq!(Mode::of(&enforcing_cfg, false), Mode::Unclaimed, "the flag is not consulted");
    assert_eq!(Mode::of(&cfg, true), Mode::ClaimedPermissive, "claimed with the flag on");
    assert_eq!(
        bare_bind_allowed(&enforcing_cfg, Peer::Loopback, Some(&dialed), true),
        BareBind::ModeRefused,
        "the mode is tested first"
    );
    assert_eq!(
        bare_bind_allowed(&enforcing_cfg, Peer::Remote, Some("null"), true),
        BareBind::ModeRefused
    );
    assert_eq!(
        bare_bind_allowed(&enforcing_cfg, Peer::Loopback, None, false),
        BareBind::Allowed,
        "pre-claim the flag is not consulted"
    );
}

/// AUTH-4.25/4.28 — the `Lookup` → `Actor` map, arm by arm. `resolve`
/// decides whether a request may write at all, and every arm but
/// `Principal` answers with a REASON the glue dispatches on: only
/// `Unknown` and `BindingDead` close the binding.
#[test]
fn resolve_maps_every_lookup_arm_to_its_actor() {
    let engine = Engine::open(KernelConfig {
        durability: Durability::InMemory,
        checkpoint: CheckpointPolicy::Manual,
        salt: SaltSource::Seeded(0),
    })
    .expect("in-memory genesis cannot fail");
    let febe = OperationSurface::new(Box::new(engine.stores()));
    let snap = engine.kernel().snapshot();
    let world = snap.world();
    // Genesis: no account holds any key, so no signed binding is live.
    let identity = IdentityState::genesis();
    let cfg = cfg_at(8642, true);
    let actor_of = |lookup, peer, origin| resolve(&cfg, lookup, peer, origin, world, &identity);

    assert_eq!(
        actor_of(Lookup::NoToken, Peer::Loopback, None),
        Actor::Guest(GuestReason::NoToken),
        "no token: nothing to close"
    );
    assert_eq!(
        actor_of(Lookup::Unknown, Peer::Loopback, None),
        Actor::Guest(GuestReason::Unknown),
        "an unknown token: the glue closes and signals"
    );

    let bare = SessionBinding {
        sid: febe.open_session(PrincipalId(7)),
        principal: PrincipalId(7),
        signer: None,
        scope: Scope::Full,
    };
    assert_eq!(
        actor_of(Lookup::Found(bare.clone()), Peer::Loopback, None),
        Actor::Principal(bare.clone()),
        "a bare bind the mode honors resolves to its principal"
    );
    assert_eq!(
        actor_of(Lookup::Found(bare.clone()), Peer::Remote, None),
        Actor::Guest(GuestReason::RequestRefused),
        "a bare bind off loopback: refused for this request, and it LIVES"
    );

    // A signed binding whose key no account holds is DEAD — the arm the
    // glue closes on, and the one a retirement produces.
    let signed = SessionBinding {
        signer: Fingerprint::parse_hex(&"ab".repeat(32)),
        ..bare
    };
    assert!(signed.signer.is_some(), "the fixture fingerprint parses");
    // The signed arm consults no origin and no peer — dead is dead —
    // which is why the two cells below must answer alike.
    for peer in [Peer::Loopback, Peer::Remote] {
        assert_eq!(
            actor_of(Lookup::Found(signed.clone()), peer, Some("https://evil.example")),
            Actor::Guest(GuestReason::BindingDead),
            "{peer:?}: a signer no key set holds is dead"
        );
    }
}

/// AUTH-4.62 item 1's EXPIRED arm — the one of the thirteen no wire test
/// drives, since reaching it over HTTP needs the 60 s TTL. Here `now` is
/// an argument: a nonce presented at its expiry dies at the burn and is
/// the UNIT refusal, which `refuse_handshake` marshals to the one 401
/// body — byte-identical with every other arm by construction — and
/// never the second value, which only step 4b produces.
#[test]
fn an_expired_nonce_is_the_unit_refusal() {
    let engine = Engine::open(KernelConfig {
        durability: Durability::InMemory,
        checkpoint: CheckpointPolicy::Manual,
        salt: SaltSource::Seeded(0),
    })
    .expect("in-memory genesis cannot fail");
    let snap = engine.kernel().snapshot();
    let identity = IdentityState::genesis();
    let cfg = cfg_at(8642, true);
    let challenges = Challenges::new(4);
    let issued = Instant::now();
    let principal = PrincipalId(7);
    let nonce = challenges.issue(principal, issued, &mut super::super::OsEntropy);
    let body = SessionBody::Signed {
        principal,
        nonce,
        // UNCLAIMED, so the signed set is the bare set and the dialed
        // loopback default passes step 2: what refuses is the burn.
        origin: Origin::parse("http://127.0.0.1:8642").expect("canonical"),
        scope: Scope::Full,
        sig: SessionSig::parse(&"00".repeat(TAG1_SIG_LEN)).expect("tag 1's width"),
    };
    let refusal = handshake(
        &cfg,
        &challenges,
        snap.world(),
        &identity,
        body,
        Peer::Loopback,
        None,
        issued + CHALLENGE_TTL,
    )
    .expect_err("an expired nonce is a failure of the credential");
    assert!(
        matches!(refusal, HandshakeRefusal::Rejected(SessionRejected)),
        "the UNIT refusal, never step 4b's second value: {refusal:?}"
    );
    assert!(
        !challenges.burn(&nonce, principal, issued),
        "and the expired entry burned with the attempt"
    );
}

/// AUTH-6.2/6.3 — the THREE body forms and the strict fourth field. A
/// signed body without `scope` is FULL (the second form, byte for byte);
/// `scope` takes exactly the JSON string `content`; any other value or
/// type — and `scope` on the BARE body, whatever it holds — is "any other
/// body". The parse stands ahead of the burn, so each `Err` here is a 400
/// that spends no nonce.
#[test]
fn the_session_body_takes_three_forms_and_scope_is_strict() {
    let signed = |scope: &str| {
        format!(
            r#"{{"principal":7,"nonce":"{}","origin":"http://127.0.0.1:8642"{scope},"sig":"{}"}}"#,
            "ab".repeat(32),
            "cd".repeat(TAG1_SIG_LEN)
        )
    };
    assert!(matches!(
        parse_session_body(br#"{"principal":7}"#),
        Ok(SessionBody::Bare { principal: PrincipalId(7) })
    ));
    assert!(matches!(
        parse_session_body(signed("").as_bytes()),
        Ok(SessionBody::Signed { scope: Scope::Full, .. })
    ));
    assert!(matches!(
        parse_session_body(signed(r#","scope":"content""#).as_bytes()),
        Ok(SessionBody::Signed { scope: Scope::Content, .. })
    ));
    // No `full` spelling, no case variant, no other type: absence IS full.
    for bad in [
        r#""full""#,
        r#""Content""#,
        r#""CONTENT""#,
        r#""content ""#,
        r#""""#,
        "null",
        "true",
        "1",
        r#"["content"]"#,
        r#"{"content":true}"#,
    ] {
        assert!(
            parse_session_body(signed(&format!(r#","scope":{bad}"#)).as_bytes()).is_err(),
            "scope {bad} is a syntax fault"
        );
    }
    // The bare arm is scope-less: even the one admitted value refuses.
    for bare in [r#"{"principal":7,"scope":"content"}"#, r#"{"principal":7,"scope":null}"#] {
        assert!(parse_session_body(bare.as_bytes()).is_err(), "{bare}");
    }
    // …and a scope does not complete a partial signed triple.
    assert!(parse_session_body(
        format!(r#"{{"principal":7,"nonce":"{}","scope":"content"}}"#, "ab".repeat(32))
            .as_bytes()
    )
    .is_err());
}

/// AUTH-6.3 / AUTH-4.34 — `sig` is admitted at EXACTLY the two hybrid
/// blob widths, 6,746 hex (tag 1, 3,373 bytes) and 1,460 hex (tag 3, 730
/// bytes), case-free; every other width — the classical 128 hex among
/// them, and one byte either side of each width — is a syntax fault, the
/// 400 whose nonce survives, never a 401; a non-hex byte at a right width
/// refuses too. The widths are the table's, read at the parse: every row's
/// is admitted, and the type names no row.
#[test]
fn the_sig_is_admitted_at_exactly_the_two_hybrid_widths() {
    let width = |tag| SigAlgRow::of_tag(tag).map(SigAlgRow::sig_len);
    assert_eq!(
        (width(TAG_MLDSA65_ED25519), width(TAG_FNDSA512_PREVIEW_ED25519)),
        (Some(TAG1_SIG_LEN), Some(TAG3_SIG_LEN)),
        "SIG_ALGS' widths, pinned by hand"
    );
    let tag1 = SessionSig::parse(&"ab".repeat(TAG1_SIG_LEN)).expect("6,746 hex is tag 1's width");
    assert_eq!(tag1.as_bytes().len(), 3373);
    assert_eq!(tag1.as_bytes()[0], 0xab);
    let tag3 = SessionSig::parse(&"cd".repeat(TAG3_SIG_LEN)).expect("1,460 hex is tag 3's width");
    assert_eq!(tag3.as_bytes().len(), 730);
    // Case-free: decoded, never framed.
    assert_eq!(SessionSig::parse(&"AB".repeat(TAG1_SIG_LEN)), Some(tag1.clone()));
    // Every other width is NO sig — the classical 64 bytes first.
    for bytes in [64usize, 0, 1, 3372, 3374, 729, 731, 4032] {
        assert!(
            SessionSig::parse(&"ab".repeat(bytes)).is_none(),
            "{bytes} bytes is none of the hybrid blob widths"
        );
    }
    // An odd hex length, and a non-hex byte at a right width.
    assert!(SessionSig::parse(&"a".repeat(TAG1_SIG_LEN * 2 - 1)).is_none());
    assert!(SessionSig::parse(&format!("zz{}", "ab".repeat(TAG1_SIG_LEN - 1))).is_none());
    // Every row's width is admitted, read off the table as the parse reads
    // it — so a row added upstream needs no edit in `session.rs`.
    for row in SIG_ALGS {
        let sig = SessionSig::parse(&"ab".repeat(row.sig_len()))
            .unwrap_or_else(|| panic!("tag {}'s width is a hybrid width", row.tag));
        assert_eq!(sig.as_bytes().len(), row.sig_len());
    }
    // …and through the body parse, the 400's own detail names the field and
    // every width the table admits, rendered off the table too.
    let body = format!(
        r#"{{"principal":7,"nonce":"{}","origin":"http://127.0.0.1:8642","sig":"{}"}}"#,
        "ab".repeat(32),
        "cd".repeat(64)
    );
    let detail = parse_session_body(body.as_bytes()).err().expect("a 64-byte sig is a syntax fault");
    assert!(detail.contains("'sig'"), "{detail}");
    assert!(
        detail.ends_with("exactly 3373 bytes (tag 1, 6746 hex) or 730 bytes (tag 3, 1460 hex)"),
        "{detail}"
    );
}

/// AUTH-4.32 — `verify` is the HYBRID verification under the KEY's own
/// row: a tag-1 key verifies its signer's tag-1 blob over the payload;
/// the same blob over other bytes fails; the blob with its post-quantum
/// half broken fails and with its Ed25519 half broken fails — no half
/// opens a session alone; a blob of the OTHER row's width fails under
/// this key (the width is not the row's), as does a 64-byte classical
/// signature; and a tag-3 key verifies only its own row's blob. Never a
/// panic on any of them.
#[test]
fn verify_is_both_halves_under_the_keys_own_row() {
    use skep_signature::{HybridSigner, SeededRng06};
    let seed = [0x33u8; 32];
    let payload = session_payload(
        &Origin::parse("http://127.0.0.1:8642").expect("canonical"),
        &"ab".repeat(32),
        PrincipalId(7),
        Scope::Full,
    );
    let s1 = HybridSigner::from_seed(TAG_MLDSA65_ED25519, &seed).expect("tag 1");
    let s3 = HybridSigner::from_seed(TAG_FNDSA512_PREVIEW_ED25519, &seed).expect("tag 3");
    let blob1 = s1.sign(&payload);
    let blob3 = s3.sign_with_rng(&payload, &mut SeededRng06::new([9; 32]));
    assert_eq!((blob1.len(), blob3.len()), (TAG1_SIG_LEN, TAG3_SIG_LEN));

    assert!(verify(s1.public_key(), &payload, &blob1), "tag 1: both halves over the payload");
    assert!(verify(s3.public_key(), &payload, &blob3), "tag 3: both halves over the payload");
    assert!(!verify(s1.public_key(), b"other bytes", &blob1), "other bytes fail");
    let mut pq_broken = blob1.clone();
    pq_broken[5] ^= 1;
    assert!(!verify(s1.public_key(), &payload, &pq_broken), "the PQ half broken: no session");
    let mut ed_broken = blob1.clone();
    ed_broken[TAG1_SIG_LEN - 1] ^= 1;
    assert!(!verify(s1.public_key(), &payload, &ed_broken), "the Ed25519 half broken: no session");
    assert!(!verify(s1.public_key(), &payload, &blob3), "the other row's width under a tag-1 key");
    assert!(!verify(s3.public_key(), &payload, &blob1), "the other row's width under a tag-3 key");
    // The classical signature: the tag-1 blob's Ed25519 half — the key's
    // Ed25519 half over the payload, 64 bytes (Ed25519 signs deterministically).
    let classical: [u8; 64] = blob1[TAG1_SIG_LEN - 64..].try_into().expect("64 bytes");
    assert!(!verify(s1.public_key(), &payload, &classical), "64 bytes is no row's width");
    assert!(!verify(s1.public_key(), &payload, &[]), "and neither is nothing");
    // The Ed25519 half alone, padded to the row's width, is not a blob
    // either half of which verifies as the row's.
    let mut padded = vec![0u8; TAG1_SIG_LEN - 64];
    padded.extend_from_slice(&classical);
    assert!(!verify(s1.public_key(), &payload, &padded), "a right-width blob with a dead PQ half");
}

/// AUTH-6.4 — the layout is VERSIONED: an unscoped body signs the v1
/// bytes, unmoved, and a scoped body the v2 bytes — the same three fields
/// then `be32(|scope|)‖scope`, the body's own `content`. Pinned as BYTES,
/// spelled by hand: this is the reference layout a client signs — both
/// halves of the key sign these same bytes (the hybrid handshake), the
/// layouts themselves unmoved under the v1/v2 names.
#[test]
fn a_scoped_body_signs_the_v2_layout_and_an_unscoped_one_the_v1() {
    let origin = Origin::parse("http://127.0.0.1:8642").expect("canonical");
    let nonce = "ab".repeat(32);
    let field = |bytes: &[u8]| {
        let len = u32::try_from(bytes.len()).expect("a field fits be32");
        [&len.to_be_bytes()[..], bytes].concat()
    };
    let body = [
        field(origin.as_str().as_bytes()),
        field(nonce.as_bytes()),
        field(b"42"), // the principal as shortest ASCII decimal
    ]
    .concat();

    let v1 = [&b"skep-session-v1"[..], &body].concat();
    assert_eq!(session_payload(&origin, &nonce, PrincipalId(42), Scope::Full), v1);
    let v2 = [&b"skep-session-v2"[..], &body, &field(b"content")].concat();
    assert_eq!(session_payload(&origin, &nonce, PrincipalId(42), Scope::Content), v2);
    // Neither is a prefix of the other, so no signature over one layout
    // verifies over the other.
    assert!(!v2.starts_with(&v1) && !v1.starts_with(&v2));
}

/// AUTH-4.20 — the cap evicts oldest-first.
#[test]
fn challenge_cap_evicts_oldest() {
    let ch = Challenges::new(2);
    let mut rng = super::super::OsEntropy;
    let now = Instant::now();
    let a = ch.issue(PrincipalId(1), now, &mut rng);
    let b = ch.issue(PrincipalId(1), now, &mut rng);
    let c = ch.issue(PrincipalId(1), now, &mut rng);
    assert!(!ch.burn(&a, PrincipalId(1), now), "the oldest was evicted");
    assert!(ch.burn(&b, PrincipalId(1), now));
    assert!(ch.burn(&c, PrincipalId(1), now));
}
