//! THE HOSTED ARM (`client.md` §4.5) against the real daemon, THE WHOLE-SET
//! COMPARE against the genesis record it wrote (AUTH-4.58's detection), and
//! the first-signed-session composition `bind` runs — its two arms selected
//! by the reads alone.

use skep_client::board::{KeySetAnswer, Scope};
use skep_client::ceremony::claim::{hosted, HostedOutcome};
use skep_client::ceremony::first_session::{document_present, first_session, FirstSessionReads};
use skep_client::ceremony::handshake::{handshake, Site};
use skep_client::derive::records::{compare_whole_set, credential_records, Difference, Held};
use skep_client::derive::principal_of;
use skep_client::sheet::{KeyFile, Label, Seed};
use skep_client::sign::{signer_from_seed, signer_from_seed_under};
use skep_client::store::{Binding, FileStore};
use skep_identity::{encode_enroll, Enrollment, Fingerprint};
use skep_signature::{HybridSigner, TAG_FNDSA512_PREVIEW_ED25519};

use crate::common::{board, keygen, spawn};

/// The customer's door-side material: two anchors in memory (as `keygen
/// --anchors` makes them) and the store's device key.
fn customer_material(store: &FileStore) -> (Vec<Enrollment>, Fingerprint, KeyFile) {
    let fp = keygen(store, "customer notebook");
    let device = store.load(&store.key_path(&fp)).unwrap();
    let a = KeyFile::new(Seed::fresh(), true, Some(Label::new("paper a").unwrap()), None);
    let b = KeyFile::new(Seed::fresh(), true, Some(Label::new("paper b").unwrap()), None);
    let entries = vec![
        Enrollment::new(a.public.clone(), true, Some("paper a".into())).unwrap(),
        Enrollment::new(b.public.clone(), true, Some("paper b".into())).unwrap(),
        Enrollment::new(device.public.clone(), false, Some("customer notebook".into())).unwrap(),
    ];
    (entries, fp, device)
}

fn held_of(entries: &[Enrollment]) -> Vec<Held> {
    entries.iter().map(|e| Held { fingerprint: Fingerprint::of(&e.key), anchor: e.anchor, label: e.label().map(str::to_string) }).collect()
}

/// H0–H6: the payload refused ahead of any write where it is not canonical
/// or names a preview kind; the claim from bare sessions, the record
/// VERBATIM; the reply off `/health`; idempotent on the claimed board; the
/// customer's key opens a session.
#[test]
fn the_hosted_arm_claims_from_the_payload_verbatim_and_is_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let sd = spawn(&dir.path().join("board"), false);
    let board = board(sd.port());
    let store = FileStore::open(dir.path().join("store"));
    let (entries, fp, device) = customer_material(&store);
    let payload = encode_enroll(&entries);

    // Refused ahead of H3: not canonical; a preview-kind key.
    let err = hosted(&board, b"{\"not\":\"a record\"}", 1).expect_err("garbage");
    assert!(err.to_string().contains("not a canonical enrollment record"), "{err}");
    let preview = signer_from_seed_under(TAG_FNDSA512_PREVIEW_ED25519, &[3; 32]).expect("tag 3 is a row");
    let preview_payload = encode_enroll(&[Enrollment::new(HybridSigner::public_key(&preview).clone(), false, Some("preview".into())).unwrap()]);
    let err = hosted(&board, preview_payload.as_bytes(), 1).expect_err("preview kind");
    assert!(err.to_string().contains("PREVIEW-kind key"), "{err}");
    assert_eq!(board.next_account_prefix("1").unwrap().as_deref(), Some("1.0.1"), "nothing was delegated by a refused payload");

    // THE CLAIM.
    let out = hosted(&board, payload.as_bytes(), 1).expect("the hosted claim");
    let HostedOutcome::Claimed(reply) = out else { panic!("{out:?}") };
    assert_eq!((reply.claimant.as_str(), reply.facts.account.as_str(), reply.facts.principal, &reply.facts.origin), ("1.0.1", "1.0.1", 1, board.dialed()));
    assert!(!reply.anchorless);
    assert_eq!(reply.log.iter().filter(|l| l.starts_with("payload entry:")).count(), 3);
    assert_eq!(board.health().unwrap().claimant(), Some("1.0.1"));
    let KeySetAnswer::Set(set) = board.key_set("1.0.1").unwrap() else { panic!() };
    assert_eq!(set.enrolled.len(), 3);
    // The record stands VERBATIM: the genesis's bytes are the payload's.
    let records = credential_records(&board, "1.0.1", &[]).unwrap();
    let genesis = records.genesis().expect("the genesis");
    assert_eq!(std::str::from_utf8(&genesis.bytes).unwrap().trim_end(), payload.trim_end());
    // Idempotent.
    assert_eq!(hosted(&board, payload.as_bytes(), 1).unwrap(), HostedOutcome::AlreadyClaimed { claimant: "1.0.1".into() });
    // The customer signs in from their own device.
    let session = handshake(&board, Scope::Content, &device.signer(), 1, Site::Hosted).expect("the customer's session");
    assert_eq!(session.fingerprint(), fp);
    session.close().unwrap();

    // ANCHORLESS: a device-only payload founds an anchorless account, said.
    let dir2 = tempfile::tempdir().unwrap();
    let sd2 = spawn(&dir2.path().join("board"), true);
    let board2 = board_at(sd2.port());
    let lone = signer_from_seed(&[11; 32]);
    let p = encode_enroll(&[Enrollment::new(HybridSigner::public_key(&lone).clone(), false, Some("lone".into())).unwrap()]);
    let HostedOutcome::Claimed(reply) = hosted(&board2, p.as_bytes(), 1).unwrap() else { panic!() };
    assert!(reply.anchorless);
    assert!(reply.log.iter().any(|l| l.contains("ANCHORLESS PERMANENTLY")));
    assert!(reply.log.iter().any(|l| l.contains("CLAIMED-PERMISSIVE")), "local trust ON is warned");
}

fn board_at(port: u16) -> skep_client::board::Board {
    board(port)
}

/// THE WHOLE-SET COMPARE: the genesis record entry for entry — fingerprint
/// AND anchor flag — against what the person holds; a key the operator
/// planted shows as a difference; later acts are listed, never differences.
/// MUTATION 4: reduced to one key's membership the planted key passes and
/// this test fails.
#[test]
fn the_whole_set_compare_detects_a_planted_key_and_passes_the_honest_genesis() {
    // The honest board.
    let dir = tempfile::tempdir().unwrap();
    let sd = spawn(&dir.path().join("board"), false);
    let board = board(sd.port());
    let store = FileStore::open(dir.path().join("store"));
    let (entries, fp, device) = customer_material(&store);
    let HostedOutcome::Claimed(_) = hosted(&board, encode_enroll(&entries).as_bytes(), 1).unwrap() else { panic!() };
    let records = credential_records(&board, "1.0.1", &[(fp, device.public.clone())]).unwrap();
    let KeySetAnswer::Set(set) = board.key_set("1.0.1").unwrap() else { panic!() };
    let whole = compare_whole_set(&records, &set, &held_of(&entries)).expect("a genesis");
    assert!(whole.differences.is_empty(), "{:?}", whole.differences);
    assert!(whole.later.is_empty());
    // A flag flipped in what the person holds reads as a difference.
    let mut flipped = held_of(&entries);
    flipped[0].anchor = false;
    let whole = compare_whole_set(&records, &set, &flipped).unwrap();
    assert_eq!(whole.differences.len(), 1);
    assert!(matches!(&whole.differences[0], Difference::FlagFlipped { held_anchor: false, genesis_anchor: true, .. }));
    // A key missing from the genesis.
    let whole = compare_whole_set(&records, &set, &held_of(&entries[..2])).unwrap();
    assert!(matches!(&whole.differences[..], [Difference::Added { anchor: false, .. }]));

    // The planted board: the operator adds a device key of their own.
    let dir = tempfile::tempdir().unwrap();
    let sd = spawn(&dir.path().join("board"), false);
    let board = board_at(sd.port());
    let store = FileStore::open(dir.path().join("store"));
    let (entries, fp, device) = customer_material(&store);
    let planted = signer_from_seed(&[42; 32]);
    let planted_fp = Fingerprint::of(HybridSigner::public_key(&planted));
    let mut doctored = entries.clone();
    doctored.push(Enrollment::new(HybridSigner::public_key(&planted).clone(), false, Some("planted".into())).unwrap());
    let HostedOutcome::Claimed(_) = hosted(&board, encode_enroll(&doctored).as_bytes(), 1).unwrap() else { panic!() };
    let records = credential_records(&board, "1.0.1", &[(fp, device.public.clone())]).unwrap();
    let KeySetAnswer::Set(set) = board.key_set("1.0.1").unwrap() else { panic!() };
    assert!(set.enrolled(&fp).is_some(), "the customer's key IS a member — membership alone sees nothing");
    let whole = compare_whole_set(&records, &set, &held_of(&entries)).expect("a genesis");
    assert_eq!(whole.differences, vec![Difference::Added { fingerprint: planted_fp, anchor: false, label: Some("planted".into()) }]);
    assert!(whole.later.is_empty());
}

/// THE FIRST SIGNED SESSION's composition, `bind`'s two arms by the reads:
/// on a hosted board the home stands and the setup act is OWED; after one
/// run nothing is, and a second take opens no session.
#[test]
fn first_session_owes_the_setup_act_once_and_nothing_after() {
    let dir = tempfile::tempdir().unwrap();
    let sd = spawn(&dir.path().join("board"), false);
    let board = board(sd.port());
    let store = FileStore::open(dir.path().join("store"));
    let (entries, fp, device) = customer_material(&store);
    let HostedOutcome::Claimed(_) = hosted(&board, encode_enroll(&entries).as_bytes(), 1).unwrap() else { panic!() };
    let signer = device.signer();

    let reads = FirstSessionReads::take(&board, "1.0.1", &fp, Some(&store)).unwrap();
    assert!(reads.home_present, "H3 minted the home");
    assert!(reads.set_nonempty);
    assert_eq!(reads.agent_space, "1.0.1.1");
    assert_eq!(reads.agent_space_principal, None);
    assert!(!reads.agent_space_home_present);
    assert_eq!(reads.persisted_new_id, None);
    assert!(matches!(reads.key_opens_agent_space, Some(skep_client::derive::KeyDiagnosis::Enrolled { anchor: false })), "{:?}", reads.key_opens_agent_space);
    assert!(!reads.mint_owed() && reads.setup_owed() && reads.anything_owed());

    let session = handshake(&board, Scope::Content, &signer, 1, Site::Tail).unwrap();
    let done = first_session(&board, &reads, &session, &signer, Some(&store)).expect("the composition");
    session.close().unwrap();
    assert!(!done.minted_home);
    let agent_space_principal = done.agent_space_principal.expect("the agent space is seated");
    assert!(done.minted_agent_space_home && done.setup_skipped.is_none() && !done.setup_stopped_seeded);
    assert_eq!(principal_of(&board, "1.0.1.1").unwrap(), Some(agent_space_principal));
    assert_eq!(board.principal_prefix(agent_space_principal).unwrap().as_deref(), Some("1.0.1.1"));
    assert!(document_present(&board, "1.0.1.1.0.1").unwrap(), "the agent space's home");
    assert!(agent_space_principal >= 2 && agent_space_principal <= (1u64 << 53) - 1, "a client-minted new_id in the domain (AUTH-5.20)");
    let persisted = store.all_bindings().unwrap().into_iter().find_map(|b| match b {
        Binding::Enrollment { account, principal, fingerprint, .. } if account == "1.0.1.1" => Some((principal, fingerprint)),
        _ => None,
    });
    assert_eq!(persisted, Some((agent_space_principal, fp)), "the persist-first line names the new_id and the key");
    // The agent space opens BY REFERENCE: its own set is empty and the key
    // stands in the account's.
    let KeySetAnswer::Set(own) = board.key_set("1.0.1.1").unwrap() else { panic!() };
    assert!(own.is_empty());

    // Nothing owed after.
    let reads2 = FirstSessionReads::take(&board, "1.0.1", &fp, Some(&store)).unwrap();
    assert_eq!((reads2.agent_space_principal, reads2.agent_space_home_present, reads2.persisted_new_id), (Some(agent_space_principal), true, Some(agent_space_principal)));
    assert!(!reads2.anything_owed(), "bind's second arm: no session is opened");
}
