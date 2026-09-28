//! The publish-class and pre-claim gates' accept AND refuse cells over real
//! HTTP: the pre-claim ceremony's shapes, the publish-class gate and the
//! version member it projects, the first-mint door, and the credential
//! `nullify` cell.

use super::*;

/// Delegate a fresh EMPTY account under principal 0 — no home mint — and
/// answer `(account, a bare session bound to it)`. The seat every first-mint
/// cell is judged against, before its home exists.
fn delegate_empty_account(port: u16, boot: &str, id: u64) -> (String, String) {
    let v = op(port, Some(boot), r#"{"op":"next_account_prefix","parent":"1"}"#);
    let account =
        expect_resp(&v, "maybe_addr")["addr"].as_str().expect("a delegable prefix").to_string();
    let v = op(port, Some(boot), &format!(r#"{{"op":"delegate","new_prefix":"{account}","new_id":{id}}}"#));
    expect_resp(&v, "ack_addr");
    (account, open_session(port, id))
}

/// The pre-claim admission gate (RES-27): an unclaimed daemon runs nothing
/// but the ceremony — refuse cells before the claim, the ceremony's own
/// accept cells inside `claim_board`, and ordinary ops after it.
#[test]
fn pre_claim_gate_admits_only_the_ceremony() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn_unclaimed(dir.path());
    let port = sd.port();
    let boot = open_session(port, 0);
    // Refuse cell: an ordinary write, bare 0 session — claim_first with the
    // pinned shape (credential_refused, permanent).
    let v = op(port, Some(&boot), r#"{"op":"register_node","addr":"1.2"}"#);
    assert_eq!(rejected_detail(&v), "credential_refused:claim_first");
    assert_eq!(v["disposition"].as_str(), Some("permanent"));
    // Refuse cell: a guest write answers unauthenticated AHEAD of the gate
    // (slot 0 of every order).
    let v = op(port, None, r#"{"op":"register_node","addr":"1.2"}"#);
    assert_eq!(v["code"].as_str(), Some("unauthenticated"), "{v}");
    // Reads stand untouched pre-claim.
    let v = op(port, Some(&boot), r#"{"op":"next_account_prefix","parent":"1"}"#);
    expect_resp(&v, "maybe_addr");
    // The accept cells ARE the ceremony (delegate-from-0, the home mint,
    // the genesis insert + deposit, the signed claim).
    claim_board(port);
    // …and the same ordinary write commits once claimed.
    let v = op(port, Some(&boot), r#"{"op":"register_node","addr":"1.2"}"#);
    expect_resp(&v, "ack_addr");
    sd.shutdown();
}

/// The publish gate (RES-26) on a claimed board: a bare session's write
/// into a published home (an account's doc 1) refuses
/// `signed_session_required`; its draft mints and draft-homed writes stand
/// (CLAIMED-PERMISSIVE's disclosed cost); the signed session passes.
#[test]
fn publish_gate_shuts_bare_published_writes_and_admits_signed_ones() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let bare = open_session(port, CLAIMANT_PRINCIPAL);
    // Refuse: a bare write homed in the published doc 1 (ordinal 2 — the
    // one legal insert slot after the ceremony's atom, so the gate is what
    // refuses it, not the arrangement's bounds).
    let v = op(
        port,
        Some(&bare),
        &format!(
            r#"{{"op":"insert","doc":"{CLAIMANT_DOC1}","at":{{"subspace":"1","ordinal":"2"}},"values":["x"]}}"#
        ),
    );
    assert_eq!(rejected_detail(&v), "credential_refused:signed_session_required");
    // Refuse: a bare flagless version of the published doc 1.
    let v = op(port, Some(&bare), &format!(r#"{{"op":"version","d_src":"{CLAIMANT_DOC1}"}}"#));
    assert_eq!(rejected_detail(&v), "credential_refused:signed_session_required");
    // Accept: a bare DRAFT mint and a write homed in it.
    let v = op(
        port,
        Some(&bare),
        &format!(r#"{{"op":"create_new_document","account":"{CLAIMANT_ACCOUNT}"}}"#),
    );
    let draft = acked_addr(&v);
    let v = op(
        port,
        Some(&bare),
        &format!(
            r#"{{"op":"insert","doc":"{draft}","at":{{"subspace":"1","ordinal":"1"}},"values":["d"]}}"#
        ),
    );
    expect_resp(&v, "ack_addr");
    // Accept: the SIGNED session writes the SAME position into the
    // published home — as the DECLARED deposit the write path admits there
    // (PUB-2.59; an undeclared insert is the refused in-place edit, PUB-2.11,
    // which is the store's cell, `tests/version_chain.rs`). The byte is
    // prose, PUB-2.60's residue, declared under a MEMBER type — ENROLL's.
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let v = op(
        port,
        Some(&signed),
        &format!(
            r#"{{"op":"insert","doc":"{CLAIMANT_DOC1}","at":{{"subspace":"1","ordinal":"2"}},"values":["y"],"deposit":"{T_ENROLL}"}}"#
        ),
    );
    expect_resp(&v, "ack_addr");
    sd.shutdown();
}

/// The MINT-FIRST gate: fork/version into an empty account refuse
/// `mint_home_first`; the home mint clears it.
#[test]
fn mint_home_first_refuses_until_the_home_exists() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let boot = open_session(port, 0);
    let v = op(port, Some(&boot), r#"{"op":"next_account_prefix","parent":"1"}"#);
    let prefix = expect_resp(&v, "maybe_addr")["addr"].as_str().expect("prefix").to_string();
    let v = op(
        port,
        Some(&boot),
        &format!(r#"{{"op":"delegate","new_prefix":"{prefix}","new_id":77}}"#),
    );
    expect_resp(&v, "ack_addr");
    let account_token = open_session(port, 77);
    let v = op(port, Some(&account_token), r#"{"op":"fork"}"#);
    assert_eq!(rejected_detail(&v), "credential_refused:mint_home_first");
    // version into the empty account refuses the same way (§4.3): MINT-FIRST
    // reads the caller's account, never the source, so any registered source
    // meets it — the mint slot stands ahead of the board-state gate, so this
    // is `mint_home_first`, not the published-source `signed_session_required`.
    let v =
        op(port, Some(&account_token), &format!(r#"{{"op":"version","d_src":"{CLAIMANT_DOC1}"}}"#));
    assert_eq!(rejected_detail(&v), "credential_refused:mint_home_first");
    let v = op(
        port,
        Some(&account_token),
        &format!(r#"{{"op":"create_new_document","account":"{prefix}"}}"#),
    );
    expect_resp(&v, "ack_addr");
    let v = op(port, Some(&account_token), r#"{"op":"fork"}"#);
    expect_resp(&v, "ack_addr");
    sd.shutdown();
}

/// PUB-2.15 — the publish gate projects a VERSION member to its DOCUMENT
/// before the read: a bare write homed in doc 1's version, and a bare version
/// of that member, both refuse `signed_session_required`. The drift sweep's
/// claim-2 defect: the retired equality compare read doc 1's versions as
/// unpublished and ADMITTED both. The signed session performs both.
#[test]
fn the_publish_gate_projects_a_version_member_to_its_document() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let v = op(port, Some(&signed), &format!(r#"{{"op":"version","d_src":"{CLAIMANT_DOC1}"}}"#));
    let version = acked_addr(&v);
    assert_eq!(version, format!("{CLAIMANT_DOC1}.1"));

    let bare = open_session(port, CLAIMANT_PRINCIPAL);
    // A bare write homed in the member: refused — the member projects to the
    // published doc 1. (Declared under a member type — ENROLL's, the byte
    // being prose — and at the member's fresh position, so the store's
    // in-place refusal is not what answers below: the write is the deposit a
    // published head admits, PUB-2.59.)
    let insert = format!(
        r#"{{"op":"insert","doc":"{version}","at":{{"subspace":"1","ordinal":"2"}},"values":["x"],"deposit":"{T_ENROLL}"}}"#
    );
    assert_eq!(rejected_detail(&op(port, Some(&bare), &insert)), "credential_refused:signed_session_required");
    // A bare version OF the member: refused the same way.
    let version_of_version = format!(r#"{{"op":"version","d_src":"{version}"}}"#);
    assert_eq!(
        rejected_detail(&op(port, Some(&bare), &version_of_version)),
        "credential_refused:signed_session_required"
    );
    // The signed session lands both.
    expect_resp(&op(port, Some(&signed), &insert), "ack_addr");
    let v = op(port, Some(&signed), &version_of_version);
    assert_eq!(acked_addr(&v), format!("{CLAIMANT_DOC1}.1.1"));

    sd.shutdown();
}

/// PUB-6.37 — `published()` is evaluated only on REGISTERED addresses: a
/// membership miss is the published fast path, so an unregistered argument
/// would otherwise read PUBLISHED and meet the gate as
/// `signed_session_required`, a code named for nothing the op could have
/// done. Registration stands ahead: a bare write to a never-minted slot of
/// the claimant's own account answers the registration refusal, and so does
/// a bare version of one.
#[test]
fn the_publish_gate_reads_publication_only_on_registered_addresses() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let bare = open_session(port, CLAIMANT_PRINCIPAL);
    // A document slot of the claimant's own chain that no mint has reached.
    let never = format!("{CLAIMANT_ACCOUNT}.0.99");

    let v = op(
        port,
        Some(&bare),
        &format!(
            r#"{{"op":"insert","doc":"{never}","at":{{"subspace":"1","ordinal":"1"}},"values":["x"]}}"#
        ),
    );
    assert_eq!(expect_resp(&v, "rejected")["code"].as_str(), Some("doc_not_registered"), "{v}");
    let v = op(port, Some(&bare), &format!(r#"{{"op":"version","d_src":"{never}"}}"#));
    assert_eq!(expect_resp(&v, "rejected")["code"].as_str(), Some("source_not_registered"), "{v}");

    sd.shutdown();
}

/// PUB-8.20 / the H1 first-mint pair (PUB-6.58): an explicit `published:false`
/// on an account's FIRST document is REFUSED at the daemon's door
/// (`mint_home_public`, permanent, nothing committed), and a FLAGLESS first
/// mint is HONORED — the home born PUBLISHED. Also the door's neighbours
/// (PUB-8.21, §4.2): explicit `true` on a first mint is honored public, and
/// once the home exists a flagless or explicit-`false` mint is an ordinary
/// private draft that refuses nothing.
///
/// "Born published" is read behaviourally: a bare session's write into a
/// published home hits the publish gate (`signed_session_required`), while a
/// write into a draft it owns commits — so the gate's verdict on a bare
/// insert reports the mint's resolved publication state.
#[test]
fn the_first_mint_door_refuses_explicit_false_and_a_flagless_first_mint_is_public() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path()); // claimed, CLAIMED-PERMISSIVE (bare binds honored)
    let port = sd.port();
    let boot = open_session(port, 0);

    let (account, session) = delegate_empty_account(port, &boot, 808);
    let create = |flag: &str| {
        op(port, Some(&session), &format!(r#"{{"op":"create_new_document","account":"{account}"{flag}}}"#))
    };
    // A bare write into `doc` at `ord`: published ⇒ the publish gate refuses;
    // draft ⇒ it commits. `ord` is chosen free so the arrangement is silent.
    let bare_write_published = |doc: &str, ord: u64| -> bool {
        let v = op(port, Some(&session), &format!(
            r#"{{"op":"insert","doc":"{doc}","at":{{"subspace":"1","ordinal":"{ord}"}},"values":["p"]}}"#
        ));
        match v["resp"].as_str() {
            Some("rejected") => {
                assert_eq!(rejected_detail(&v), "credential_refused:signed_session_required",
                    "a bare write into {doc} refused for another reason: {v}");
                true
            }
            Some("ack_addr") => false,
            _ => panic!("unexpected insert response for {doc}: {v}"),
        }
    };

    // H1 cell 1: explicit `false` on the FIRST mint is refused, nothing commits.
    let v = create(r#","published":false"#);
    assert_eq!(rejected_detail(&v), "credential_refused:mint_home_public");
    assert_eq!(v["disposition"].as_str(), Some("permanent"));

    // H1 cell 2: a FLAGLESS first mint is honored, the home born PUBLISHED.
    let home = acked_addr(&create(""));
    assert!(bare_write_published(&home, 1), "a flagless first mint is born published");

    // Once the home exists, a flagless mint is a PRIVATE draft (§4.2).
    let draft = acked_addr(&create(""));
    assert!(!bare_write_published(&draft, 1), "a later flagless mint is a private draft");

    // …and an explicit `false` on a non-first mint refuses nothing — private.
    let priv2 = acked_addr(&create(r#","published":false"#));
    assert!(!bare_write_published(&priv2, 1), "a non-first explicit-false mint is private, not refused");

    // §4.2 empty + `true`: a fresh account's first mint with explicit `true`
    // is honored public (the exemption admits the content-empty home under
    // any flag).
    let (account2, session2) = delegate_empty_account(port, &boot, 809);
    let v = op(port, Some(&session2), &format!(r#"{{"op":"create_new_document","account":"{account2}","published":true}}"#));
    let home2 = acked_addr(&v);
    let v = op(port, Some(&session2), &format!(
        r#"{{"op":"insert","doc":"{home2}","at":{{"subspace":"1","ordinal":"1"}},"values":["p"]}}"#
    ));
    assert_eq!(rejected_detail(&v), "credential_refused:signed_session_required",
        "an explicit-true first mint is honored public");

    sd.shutdown();
}

/// The first-mint pair's THIRD vector ((c) row 9 (ii)): TWO CONCURRENT FIRST
/// MINTS into ONE empty account — both ACKED, EXACTLY ONE born published. The
/// flagless default is resolved off WORKING state inside the mint's own
/// transaction (PUB-8.21), under the kernel's single applier lock, taken
/// before the base root is loaded — and the daemon stands AHEAD of that, its
/// gates and the execute they gate under one serialization lock (AUTH-3.35's
/// plain sequence). So the two serialize: the second mint's base already
/// holds the first's document, and it is born a PRIVATE draft — never a
/// second home, and never refused (the door refuses an explicit `false`
/// alone). What is pinned here is the OUTCOME at the wire, whichever layer
/// holds it: a daemon that resolved the default ahead of its serialization
/// lock hands both mints `true`, and only a real race shows it.
///
/// The race is REAL: one daemon; per round one fresh EMPTY account, TWO live
/// sessions of its principal, two threads released off one barrier, each
/// sending the flagless `create_new_document`. Which session's mint commits
/// first is the scheduler's to say, so the rounds run until BOTH orders have
/// occurred, and never fewer than `MIN_ROUNDS`: the pin holds whichever wins.
///
/// "Born published" is read three ways — `doc_metadata.published` as the owner,
/// the guest's read (served the home, `withheld` the draft), and the
/// behavioural read of the door's own vector above: a bare write into the home
/// meets the publish gate, a bare write into the draft commits.
#[test]
fn two_concurrent_first_mints_bear_exactly_one_published_home() {
    use std::sync::{Arc, Barrier};

    const MIN_ROUNDS: usize = 16;
    const MAX_ROUNDS: usize = 256;

    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path()); // claimed, CLAIMED-PERMISSIVE (bare binds honored)
    let port = sd.port();
    let boot = open_session(port, 0);

    // `won[i]`: the rounds in which session `i`'s mint committed FIRST.
    let mut won = [0usize; 2];
    let mut rounds = 0;
    while rounds < MAX_ROUNDS && (rounds < MIN_ROUNDS || won.contains(&0)) {
        let id = 810_000 + rounds as u64;
        let (account, first) = delegate_empty_account(port, &boot, id);
        let sessions = [first, open_session(port, id)];
        assert_ne!(sessions[0], sessions[1], "two live sessions of the one principal");

        let barrier = Arc::new(Barrier::new(sessions.len()));
        let mints: Vec<_> = sessions
            .iter()
            .map(|session| {
                let (barrier, session) = (Arc::clone(&barrier), session.clone());
                let frame = create_frame(&account, None);
                std::thread::spawn(move || {
                    barrier.wait();
                    op(port, Some(&session), &frame)
                })
            })
            .collect();
        // Both ACKED — neither is refused, neither is lost.
        let minted: Vec<String> =
            mints.into_iter().map(|mint| acked_addr(&mint.join().expect("a mint thread"))).collect();

        // The chain's first two documents, one each: the account's doc 1 went
        // to the mint that committed first.
        let (home, draft) = (format!("{account}.0.1"), format!("{account}.0.2"));
        let winner = minted.iter().position(|doc| *doc == home).unwrap_or_else(|| {
            panic!("round {rounds}: neither mint is {home}: {minted:?}")
        });
        assert_eq!(minted[1 - winner], draft, "round {rounds}: two distinct addresses: {minted:?}");

        // EXACTLY ONE born published — and it is the home.
        let published = |doc: &str| {
            let meta = doc_metadata(port, Some(&sessions[0]), doc);
            expect_resp(&meta, "doc_metadata")["published"].as_bool().expect("a boolean")
        };
        assert!(published(&home), "round {rounds}: the first committed mint is born published");
        assert!(!published(&draft), "round {rounds}: the second is born PRIVATE, never a second home");
        // The guest is served the one and withheld the other.
        let meta = doc_metadata(port, None, &home);
        assert_eq!(expect_resp(&meta, "doc_metadata")["published"].as_bool(), Some(true), "{meta}");
        assert_withheld(&doc_metadata(port, None, &draft), &draft);
        // The door's behavioural read, from the LOSING session: the home is
        // behind the publish gate, the draft takes a bare write.
        let bare_write = |doc: &str| {
            op(port, Some(&sessions[1 - winner]), &insert_frame(doc, 1, "p", false))
        };
        assert_eq!(rejected_detail(&bare_write(&home)), GATED, "round {rounds}");
        expect_resp(&bare_write(&draft), "ack_addr");

        won[winner] += 1;
        rounds += 1;
    }
    eprintln!("concurrent first mints: {rounds} rounds; committed first — session 0: {}, session 1: {}", won[0], won[1]);
    assert!(
        !won.contains(&0),
        "both orders must occur — {rounds} rounds, committed first {won:?}"
    );

    sd.shutdown();
}

/// The first-mint pair's FOURTH vector ((c) row 9 (iii); the conformance
/// pack's §2.13 row 4; AUTH RES-182) — THE CORPUS ROW "REACHED ONLY OUTSIDE A
/// CONFORMING DAEMON" (AUTH-3.58): a board built WITHOUT the daemon's refusal
/// producer serves a private "home", and AUTH-3.58's and AUTH-3.72's
/// NO-CLEARING-ACT cells stand on it.
///
/// The explicit-`false` FIRST mint is written BELOW the door — by the engine
/// directly, through `OperationSurface`, no daemon in the path — since M3 mints
/// it private and refuses nothing (the door is the daemon's alone, PUB-8.20).
/// The account is seated on a claimed board first, by the daemon, and keyed
/// after, by the claimant's hire into the claimant's own PUBLISHED doc 1, so
/// the account is a HOLDER whose one honored home is a draft. skepd over that
/// dir serves doc 1 PRIVATE, and then:
///
/// - the HOLDER cell: an enrolment and a retirement homed in doc 1 answer
///   `unpublished`; the same record in a published second document answers
///   `not_doc_one`; written again in doc 1 it re-fires `unpublished` — no
///   clearing act, the set unmoved;
/// - the GENESIS cell (AUTH-3.72): the genesis this delegator writes for its
///   own delegate, homed in its doc 1 — the one legal genesis home — answers
///   `unpublished`, and `not_doc_one` anywhere else: a keyless subtree.
#[test]
fn a_home_minted_private_below_the_door_is_served_private_and_has_no_clearing_act() {
    use skep_engine::{Engine, KernelConfig};
    use skep_febe::{Codec, OperationSurface, Response};
    use skep_kernel::{BurnedSeqPolicy, CheckpointPolicy, Durability, SaltSource};
    use skep_namespace::PrincipalId;
    use skepd::JsonCodec;

    const HOLDER: u64 = 820;
    let dir = tempfile::tempdir().expect("tempdir");

    // Phase 1 — the daemon: a claimed board, and one EMPTY account seated on it.
    let account = {
        let sd = spawn(dir.path());
        let port = sd.port();
        let boot = open_session(port, 0);
        let (account, _) = delegate_empty_account(port, &boot, HOLDER);
        sd.shutdown();
        account
    };
    let home = format!("{account}.0.1");

    // Phase 2 — BELOW THE DOOR: the engine directly, the account's own
    // principal, its FIRST mint carrying the explicit `false`.
    {
        let cfg = KernelConfig {
            durability: Durability::Fsync {
                journal_path: dir.path().to_path_buf(),
                retain_checkpoints: 2,
                burned_seq: BurnedSeqPolicy::Rollback,
            },
            checkpoint: CheckpointPolicy::EveryN(1024),
            salt: SaltSource::Seeded(0),
        };
        let engine = Engine::open(cfg).expect("engine recover");
        let febe = OperationSurface::new(Box::new(engine.stores()));
        let codec = JsonCodec;
        let req = codec
            .parse(create_frame(&account, Some(false)).as_bytes())
            .unwrap_or_else(|e| panic!("test frame does not parse: {:?}", e.detail));
        match febe.execute(febe.open_session(PrincipalId(HOLDER)), req) {
            Response::AckAddr { addr, .. } => {
                assert_eq!(addr.tumbler().to_string(), home, "the first mint IS doc 1")
            }
            other => panic!(
                "M3 mints an explicit-false first document private and refuses nothing: {}",
                String::from_utf8_lossy(&codec.marshal(&other))
            ),
        }
        drop(febe);
        drop(engine); // releases the journal-directory lock for the daemon
    }

    // Phase 3 — skepd over that dir.
    let sd = spawn(dir.path());
    let port = sd.port();
    let boot = open_session(port, 0);
    // The door stands on this very daemon: the same mint through it is refused,
    // so the private home came from nowhere a conforming daemon reaches.
    let (other_account, other) = delegate_empty_account(port, &boot, HOLDER + 1);
    assert_eq!(
        rejected_detail(&op(port, Some(&other), &create_frame(&other_account, Some(false)))),
        "credential_refused:mint_home_public"
    );

    // Doc 1 is served PRIVATE: `published: false` to its owner, withheld from
    // the guest.
    let bare = open_session(port, HOLDER);
    let meta = doc_metadata(port, Some(&bare), &home);
    let meta = expect_resp(&meta, "doc_metadata");
    assert_eq!(meta["published"].as_bool(), Some(false), "a private \"home\": {meta}");
    assert_eq!(meta["owner"].as_str(), Some(account.as_str()), "{meta}");
    assert_withheld(&doc_metadata(port, None, &home), &home);

    // The claimant keys the account — its genesis homed in the CLAIMANT's doc 1
    // (AUTH-2.62), which is published — so the account is a HOLDER.
    let claimant = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let holder_key = distinct_key(21);
    let holder = hire(port, &claimant, CLAIMANT_DOC1, &account, HOLDER, &holder_key);
    let enrolled = |of: &str| {
        let v = op(port, None, &format!(r#"{{"op":"key_set","account":"{of}"}}"#));
        expect_resp(&v, "key_set")["enrolled"].as_array().expect("enrolled").len()
    };
    assert_eq!(enrolled(&account), 1);

    // A credential deposit for `subject` homed in `doc`, from the holder's
    // SIGNED session: the record atom at `ordinal`, then the link naming it.
    // The atom's insert is DECLARED (PUB-2.63): the published second document
    // admits no other, and into a draft the declaration is inert.
    let deposit_in = |doc: &str, ordinal: u64, atom: &str, subject: &str, ty: &str| -> Value {
        let v = op(
            port,
            Some(&holder),
            &format!(
                r#"{{"op":"insert","doc":"{doc}","at":{{"subspace":"1","ordinal":"{ordinal}"}},"values":[{{"atom":{atom}}}],"deposit":"{ty}"}}"#
            ),
        );
        let atom_addr = acked_addr(&v);
        op(
            port,
            Some(&holder),
            &format!(
                r#"{{"op":"make_link","home":"{doc}","from":{{"addrs":["{atom_addr}"]}},"to":{{"addrs":["{subject}"]}},"ty":{{"addrs":["{ty}"]}}}}"#
            ),
        )
    };
    // The one other home a holder can publish: a second document, minted
    // `published: true` from its signed session.
    let second = acked_addr(&op(port, Some(&holder), &create_frame(&account, Some(true))));
    assert_eq!(second, format!("{account}.0.2"));

    // THE HOLDER CELL (AUTH-3.58).
    let another_key = enroll_atom(&[&distinct_key(22)]);
    assert_eq!(
        rejected_detail(&deposit_in(&home, 1, &another_key, &account, T_ENROLL)),
        "credential_refused:unpublished",
        "the holder's one honored home is a draft"
    );
    assert_eq!(
        rejected_detail(&deposit_in(&second, 1, &another_key, &account, T_ENROLL)),
        "credential_refused:not_doc_one",
        "every other home answers the home pin"
    );
    assert_eq!(
        rejected_detail(&deposit_in(&home, 2, &another_key, &account, T_ENROLL)),
        "credential_refused:unpublished",
        "written again in doc 1, it re-fires: no clearing act"
    );
    let holder_fp = fingerprint_hex(&holder_key);
    let retirement = retire_atom(&[holder_fp.as_str()]);
    assert_eq!(
        rejected_detail(&deposit_in(&home, 3, &retirement, &account, T_RETIRE)),
        "credential_refused:unpublished",
        "a retirement included"
    );
    assert_eq!(enrolled(&account), 1, "the set is unmoved");

    // THE GENESIS CELL (AUTH-3.72): this account's doc 1 is its delegates'
    // genesis registry. A LATER child — the first is the agent space, which
    // takes no genesis from any hand (RES-80).
    reserve_agent_space(port, &holder, &account, HOLDER + 2);
    let (delegate, _) = delegate_under(port, &holder, &account, HOLDER + 3);
    let genesis = enroll_atom(&[&distinct_key(23)]);
    assert_eq!(
        rejected_detail(&deposit_in(&home, 4, &genesis, &delegate, T_ENROLL)),
        "credential_refused:unpublished",
        "the one legal genesis home is a draft"
    );
    assert_eq!(
        rejected_detail(&deposit_in(&second, 2, &genesis, &delegate, T_ENROLL)),
        "credential_refused:not_doc_one"
    );
    assert_eq!(enrolled(&delegate), 0, "a keyless subtree");

    sd.shutdown();
}

/// The publish gate's EXPLICIT-FLAG row (PUB-6.43, §4.5): on a claimed board a
/// bare session's `published:true` mint into a NON-empty account lands in the
/// published world and is refused `signed_session_required`; a draft mint
/// (flagless or explicit `false`) from the same bare session is accepted; and
/// a signed session publishes.
#[test]
fn the_publish_gate_refuses_an_explicit_true_mint_from_a_bare_session() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let bare = open_session(port, CLAIMANT_PRINCIPAL);
    let create = |token: &str, flag: &str| {
        op(port, Some(token), &format!(r#"{{"op":"create_new_document","account":"{CLAIMANT_ACCOUNT}"{flag}}}"#))
    };

    // Explicit `true` into the claimant's non-empty account → published write.
    let v = create(&bare, r#","published":true"#);
    assert_eq!(rejected_detail(&v), "credential_refused:signed_session_required");
    // Draft mints from the same bare session are accepted.
    expect_resp(&create(&bare, ""), "ack_addr");
    expect_resp(&create(&bare, r#","published":false"#), "ack_addr");
    // A signed session publishes it.
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    expect_resp(&create(&signed, r#","published":true"#), "ack_addr");

    sd.shutdown();
}

/// The dump's exception set — the `publication.drafts` hint, draft document →
/// owner account (PUB-7.5) — as its rendered text. The one wire surface that
/// shows a version MEMBER's own journaled bit: the publish gate reads the
/// DOCUMENT a member projects to (PUB-2.15), so a bare-write probe answers
/// the document's state and never the member's.
///
/// Read at `token`'s CLASS (lane 3.4 §4): the dump filters at the presented
/// principal, so this probe presents the OWNER's session — a guest sees an
/// empty slice — to read the owner's own drafts back.
fn drafts_section(port: u16, token: &str) -> String {
    let (st, body) = http(port, "GET", "/dump", Some(token), b"");
    assert_eq!(st, 200);
    let text = String::from_utf8(body).expect("dump is utf-8 text");
    let start = text
        .find(r#""publication.drafts": {"#)
        .expect("the dump's hints section renders the exception set");
    let rest = &text[start..];
    // The map's values are quoted addresses, so the first brace closes it.
    let end = rest.find('}').expect("a rendered map closes");
    rest[..=end].to_string()
}

/// PUB-8.17 (§4.4): `version`'s ABSENT flag INHERITS the source's publication
/// state — in the RECORD: the resolved bit is what the member's `Allocate`
/// journals (PUB-8.18), and the dump's exception set shows it. Since lane 3.1
/// the write path's own two refusals bound what an OWNER may resolve (owner
/// ruling D2b, PUB-8.2): a version of the owner's PRIVATE source is
/// versionless whatever the flag (PUB-2.9, `private_source_versionless`),
/// and an explicit `false` over the owner's PUBLISHED source is the private
/// member the chain admits nothing of (PUB-2.7,
/// `private_version_of_published`) — so the record never holds a private
/// member, and the publish gate's projection of a member to its document
/// (PUB-2.15) and the record agree. Over empty published/private sources so
/// the version snapshots no content and ordinal 1 is always free.
#[test]
fn version_inherits_publication_and_the_write_path_refuses_the_private_arms() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let bare = open_session(port, CLAIMANT_PRINCIPAL);
    // A bare insert into `doc` at ordinal 1: `Ok` ⇒ its document is private
    // (it commits), the publish refusal ⇒ its document is published.
    let bare_write_published = |doc: &str| -> bool {
        let v = op(port, Some(&bare), &format!(
            r#"{{"op":"insert","doc":"{doc}","at":{{"subspace":"1","ordinal":"1"}},"values":["p"]}}"#
        ));
        match v["resp"].as_str() {
            Some("rejected") => {
                assert_eq!(rejected_detail(&v), "credential_refused:signed_session_required", "{v}");
                true
            }
            Some("ack_addr") => false,
            _ => panic!("unexpected response for {doc}: {v}"),
        }
    };
    let create = |flag: &str| {
        acked_addr(&op(port, Some(&signed), &format!(
            r#"{{"op":"create_new_document","account":"{CLAIMANT_ACCOUNT}"{flag}}}"#
        )))
    };
    let head = |port: u16| json(&get(port, "/health").1)["log_position"].as_u64().expect("head");
    // Empty PRIVATE and empty PUBLISHED sources (signed, non-first mints).
    let priv_src = create(""); // flagless non-first → private
    let pub_src = create(r#","published":true"#); // explicit true → published

    // PUB-2.9: a version of the owner's PRIVATE source refuses, whatever the
    // flag and whatever the session — the refusal is the store's, behind
    // every daemon gate — and nothing mints. ONE code; the face splits on
    // the flag the client sent, which is the client's to render (PUB-8.3).
    let before = head(port);
    for (token, flag) in [
        (&bare, ""),
        (&bare, r#","published":false"#),
        (&signed, ""),
        (&signed, r#","published":false"#),
        (&signed, r#","published":true"#),
    ] {
        let v = op(port, Some(token), &format!(r#"{{"op":"version","d_src":"{priv_src}"{flag}}}"#));
        let rej = expect_resp(&v, "rejected");
        assert_eq!(rej["code"].as_str(), Some("private_source_versionless"), "flag {flag:?}: {v}");
        assert_eq!(rej["disposition"].as_str(), Some("permanent"), "a permanent class: {v}");
        assert!(rej.get("detail").is_none(), "the face keys on the code and the flag sent: {v}");
    }
    // …and a BARE `published:true` meets the publish-class gate FIRST
    // (PUB-6.36 slot 4 ahead of slot 5): the face's split arm names the
    // versionless act there (RES-195), the daemon's code being the gate's.
    let v = op(port, Some(&bare), &format!(r#"{{"op":"version","d_src":"{priv_src}","published":true}}"#));
    assert_eq!(rejected_detail(&v), "credential_refused:signed_session_required");
    assert_eq!(head(port), before, "a refused version mints nothing");

    // Flagless version of a PUBLISHED source → published (inherit). Needs a
    // signed session (bare would meet the publish gate at the version itself).
    let v_pub = acked_addr(&op(port, Some(&signed), &format!(r#"{{"op":"version","d_src":"{pub_src}"}}"#)));
    assert!(bare_write_published(&v_pub), "flagless version of an edition inherits published");
    // An explicit `true` is the same act spelled out.
    let v_true = acked_addr(&op(port, Some(&signed), &format!(r#"{{"op":"version","d_src":"{pub_src}","published":true}}"#)));
    assert!(bare_write_published(&v_true));

    // PUB-2.7: an explicit `false` over the owner's PUBLISHED source refuses
    // — from the bare session (a draft mint, which the publish-class gate
    // does not take) and the signed one alike — so no private member of a
    // published chain is ever minted, and the record has none to show.
    let before = head(port);
    for token in [&bare, &signed] {
        let v = op(port, Some(token), &format!(r#"{{"op":"version","d_src":"{pub_src}","published":false}}"#));
        let rej = expect_resp(&v, "rejected");
        assert_eq!(rej["code"].as_str(), Some("private_version_of_published"), "{v}");
        assert_eq!(rej["disposition"].as_str(), Some("permanent"));
        assert!(rej.get("detail").is_none(), "{v}");
    }
    assert_eq!(head(port), before, "a refused version mints nothing");
    // A member the owner mints is itself a source whose private arm refuses
    // the same way (PUB-2.10: every version address names a published state).
    let v = op(port, Some(&signed), &format!(r#"{{"op":"version","d_src":"{v_pub}","published":false}}"#));
    assert_eq!(expect_resp(&v, "rejected")["code"].as_str(), Some("private_version_of_published"));

    // The RECORD's bits, off the dump's exception set at the OWNER's class
    // (the guest's slice is empty since lane 3.4): the private source is a
    // draft of the claimant's account; the inherited members are not, and no
    // member of the published chain is.
    let drafts = drafts_section(port, &signed);
    assert!(
        drafts.contains(&format!(r#""{priv_src}": "{CLAIMANT_ACCOUNT}""#)),
        "the flagless non-first mint is a draft in the record: {drafts}"
    );
    assert!(
        !drafts.contains(&format!(r#""{v_pub}""#)) && !drafts.contains(&format!(r#""{v_true}""#)),
        "the versions of an edition inherit published in the record: {drafts}"
    );
    assert!(
        !drafts.contains(&format!(r#""{pub_src}."#)),
        "no member of the published chain is a draft: {drafts}"
    );

    sd.shutdown();
}

/// The NULLIFY class (AUTH-3.7–3.9) and RES-32's entitlement scope in one
/// producer: a credential-typed link's retraction is refused
/// `nullify_not_retraction` to the owner of the home it would land in, and
/// on a CLAIMED board the shape token reaches nobody else — anyone else
/// falls through to execute and answers ω's own `not_owner`,
/// indistinguishable from its non-credential answer.
///
/// Both arms are one producer's, so a reader auditing RES-32 finds the
/// whole rule where the code that enforces it is, and the two verdicts a
/// caller can receive are pinned side by side.
#[test]
fn a_credential_nullify_refuses_the_home_owner_and_masks_everyone_else() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());

    // One fresh credential-typed link in the owner's own doc 1.
    let v = op(
        port,
        Some(&signed),
        &format!(
            r#"{{"op":"insert","doc":"{CLAIMANT_DOC1}","at":{{"subspace":"1","ordinal":"2"}},"values":[{{"atom":{}}}],"deposit":"{T_ENROLL}"}}"#,
            enroll_atom(&[&distinct_key(3)])
        ),
    );
    expect_resp(&v, "ack_addr");
    let v = op(
        port,
        Some(&signed),
        &format!(
            r#"{{"op":"make_link","home":"{CLAIMANT_DOC1}","from":{{"addrs":["{CLAIMANT_DOC1}.0.1.2"]}},"to":{{"addrs":["{CLAIMANT_ACCOUNT}"]}},"ty":{{"addrs":["{T_ENROLL}"]}}}}"#
        ),
    );
    let credential = acked_addr(&v);

    // The home's owner gets the shape token.
    let v = op(
        port,
        Some(&signed),
        &format!(r#"{{"op":"nullify","home":"{CLAIMANT_DOC1}","target":"{credential}"}}"#),
    );
    assert_eq!(rejected_detail(&v), "credential_refused:nullify_not_retraction");

    // A stranger naming the same home does not: masked, the op reaches
    // execute, and ω answers. Seated post-claim, which the publish gate
    // admits (delegate presents no input form).
    let boot = open_session(port, 0);
    let v = op(port, Some(&boot), r#"{"op":"next_account_prefix","parent":"1"}"#);
    let prefix = expect_resp(&v, "maybe_addr")["addr"].as_str().expect("prefix").to_string();
    let v = op(
        port,
        Some(&boot),
        &format!(r#"{{"op":"delegate","new_prefix":"{prefix}","new_id":31}}"#),
    );
    expect_resp(&v, "ack_addr");
    let stranger = open_session(port, 31);
    let v = op(
        port,
        Some(&stranger),
        &format!(r#"{{"op":"nullify","home":"{CLAIMANT_DOC1}","target":"{credential}"}}"#),
    );
    let rej = expect_resp(&v, "rejected");
    assert_eq!(
        rej["code"].as_str(),
        Some("not_owner"),
        "the shape token is masked, so ω answers as it would for any link: {v}"
    );

    // …and the credential link is untouched by either refusal.
    let v = op(port, None, &format!(r#"{{"op":"read_link","a":"{credential}"}}"#));
    assert!(
        !expect_resp(&v, "link_value")["link"].is_null(),
        "neither refusal retracted anything"
    );
    sd.shutdown();
}

/// The plain path's slot order (PUB-6.36 as RES-195 places it): the
/// credential-typed `nullify` cell takes slot 5's position, BEHIND the
/// board-state gate in slot 4's — so on an UNCLAIMED board the pre-claim
/// admission gate (PUB-6.35; RES-27) answers `claim_first` and the shape
/// token is never reached, for the home's own owner as for a signed
/// session. Post-claim the order is observable too, since lane 3.5 gave the
/// publish-class gate PUB-6.43's `nullify` row (a retraction lands at its
/// target, so a record against a link in the published doc 1 is a
/// published write): the SAME frame from the SAME bare session answers
/// `signed_session_required` once the board is claimed — slot 4 still ahead
/// of slot 5 — and the SIGNED session, which the gate admits, reaches the
/// cell: `nullify_not_retraction`. The cell moved behind the gate; it did
/// not go away.
#[test]
fn pre_claim_a_credential_nullify_answers_claim_first_ahead_of_the_nullify_cell() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn_unclaimed(dir.path());
    let port = sd.port();

    // The ceremony's first four steps (AUTH-5.55 1–4) with the signed claim
    // WITHHELD: delegate from 0, the home mint, the genesis atom and its
    // deposit — which leaves one credential-typed link on an unclaimed
    // board. Spelled out rather than borrowed from `claim_board`, whose
    // fifth step is the one this cell must not take yet.
    let boot = open_session(port, 0);
    let v = op(port, Some(&boot), r#"{"op":"next_account_prefix","parent":"1"}"#);
    let prefix = expect_resp(&v, "maybe_addr")["addr"].as_str().expect("prefix").to_string();
    assert_eq!(prefix, CLAIMANT_ACCOUNT, "the ceremony must be the board's first delegate");
    let v = op(
        port,
        Some(&boot),
        &format!(r#"{{"op":"delegate","new_prefix":"{prefix}","new_id":{CLAIMANT_PRINCIPAL}}}"#),
    );
    expect_resp(&v, "ack_addr");
    let claimant = open_session(port, CLAIMANT_PRINCIPAL);
    let v = op(
        port,
        Some(&claimant),
        &format!(r#"{{"op":"create_new_document","account":"{CLAIMANT_ACCOUNT}"}}"#),
    );
    assert_eq!(acked_addr(&v), CLAIMANT_DOC1, "the home mint is doc 1");
    let v = op(
        port,
        Some(&claimant),
        &format!(
            r#"{{"op":"insert","doc":"{CLAIMANT_DOC1}","at":{{"subspace":"1","ordinal":"1"}},"values":[{{"atom":{}}}],"deposit":"{T_ENROLL}"}}"#,
            enroll_atom_flagged(&[(&anchor_key(), true), (&device_key(), false)])
        ),
    );
    expect_resp(&v, "ack_addr");
    let credential =
        acked_addr(&deposit(port, &claimant, &format!("{CLAIMANT_DOC1}.0.1.1"), T_ENROLL));
    assert!(!claimed(port), "the genesis deposit alone claims nothing");

    let retract = format!(r#"{{"op":"nullify","home":"{CLAIMANT_DOC1}","target":"{credential}"}}"#);

    // The home's owner, bare: the admission gate answers first, in the
    // pinned shape (credential_refused, permanent).
    let v = op(port, Some(&claimant), &retract);
    assert_eq!(rejected_detail(&v), "credential_refused:claim_first");
    assert_eq!(v["disposition"].as_str(), Some("permanent"));
    // A signed session fares no better: pre-claim the gate is session-blind
    // (RES-27: "bare and signed sessions alike").
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let v = op(port, Some(&signed), &retract);
    assert_eq!(rejected_detail(&v), "credential_refused:claim_first");
    // The credential link is untouched by either refusal.
    let v = op(port, None, &format!(r#"{{"op":"read_link","a":"{credential}"}}"#));
    assert!(!expect_resp(&v, "link_value")["link"].is_null(), "nothing was retracted");

    // Step 5 — the signed claim. The SAME frame from the SAME bare session
    // now meets the publish-class gate (slot 4, its claimed arm: the
    // retraction lands in the published doc 1, PUB-6.43's `nullify` row),
    // still ahead of the cell…
    let v = claim_deposit(port, &signed, CLAIMANT_DOC1, CLAIMANT_ACCOUNT);
    expect_resp(&v, "ack_addr");
    assert!(claimed(port), "the claim link flips the board claimed");
    let v = op(port, Some(&claimant), &retract);
    assert_eq!(rejected_detail(&v), "credential_refused:signed_session_required");
    // …and the signed session, which that gate admits, reaches the cell
    // behind it.
    let v = op(port, Some(&signed), &retract);
    assert_eq!(rejected_detail(&v), "credential_refused:nullify_not_retraction");
    let v = op(port, None, &format!(r#"{{"op":"read_link","a":"{credential}"}}"#));
    assert!(!expect_resp(&v, "link_value")["link"].is_null(), "nothing was retracted");
    sd.shutdown();
}
