//! THE HOP's signed-in half (`client.md` §2.2 `enroll`; AUTH-5.32): store B's
//! payload enrolled from store A's own FULL session, the three facts
//! answered and NO binding appended at A; `--reply` re-derives them with no
//! write; an anchor-flagged payload refused at the paste; a retired key's
//! payload I4's halt; the same payload twice reconciled; `too_many_enrolled`
//! faced with `skep retire` named, and answered by `deposit` as its armed arm;
//! the by-reference halt.

use skep_client::board::{KeySetAnswer, Scope};
use skep_client::ceremony::deposit::{deposit, Deposit, DepositHalt, DepositKind};
use skep_client::ceremony::enroll::{enroll, reply, EnrollOptions};
use skep_client::ceremony::handshake::{handshake, Site};
use skep_client::person::scripted::{Script, Scripted};
use skep_client::sheet::{KeyFile, Label, Seed};
use skep_client::sign::signer_from_seed;
use skep_client::store::FileStore;
use skep_identity::{encode_enroll, Enrollment, Fingerprint};
use skep_signature::HybridSigner;

use crate::common::{board, claim, entry_of, fill_to_the_cap, key_file, keygen, spawn};

fn opts(payload: &str) -> EnrollOptions {
    EnrollOptions { principal: 1, payload: format!("{payload}\n").into_bytes() }
}

/// THE HOP: the payload enrolled from A's full session after the consent
/// comparison; the facts are reads and A appends no line; `reply` re-prints
/// them; twice is reconciled; the anchor-flagged and retired arrivals are
/// refused with nothing written.
#[test]
fn the_hop_enrolls_another_devices_payload_from_a_full_session_and_appends_no_binding() {
    let dir = tempfile::tempdir().unwrap();
    let sd = spawn(&dir.path().join("board"), false);
    let board = board(sd.port());
    let store_a = FileStore::open(dir.path().join("a"));
    let fp_a = keygen(&store_a, "notebook");
    claim(&board, &store_a, &dir.path().join("anchors"));
    let lines_before = store_a.all_bindings().unwrap().len();
    // Store B's `keygen --payload`.
    let store_b = FileStore::open(dir.path().join("b"));
    let fp_b = keygen(&store_b, "phone");
    let payload = encode_enroll(&[entry_of(&key_file(&store_b, &fp_b), "phone")]);

    let mut person = Scripted::new(vec![Script::Confirm(true)]);
    let done = enroll(&board, &store_a, &mut person, &opts(&payload)).unwrap_or_else(|h| panic!("{h}\n{}", person.transcript.join("\n")));
    assert_eq!((done.facts.account.as_str(), done.facts.principal, done.facts.origin.as_str()), ("1.0.1", 1, board.dialed().as_str()));
    assert_eq!(done.fingerprints, vec![fp_b]);
    assert!(!done.reconciled);
    assert!(person.said("key to enroll — fingerprint re-derived") && person.said("phone") && person.said("PUBLIC, PERMANENT and UNCORRECTABLE"), "the comparison beat:\n{}", person.transcript.join("\n"));
    assert!(person.said("[R48]") && person.said("these bytes parsed as a canonical record — and nothing about who composed them"), "the parse's one line:\n{}", person.transcript.join("\n"));
    assert!(person.said("CONSENT confirm: `skep enroll`"), "a CONSENT moment (cs6-1)");
    assert_eq!(store_a.all_bindings().unwrap().len(), lines_before, "NO binding line appended at the enrolling device (§3.7)");
    let KeySetAnswer::Set(set) = board.key_set("1.0.1").unwrap() else { panic!() };
    assert!(set.enrolled(&fp_b).is_some_and(|e| !e.anchor), "B's key is enrolled, device-flagged");
    // The record stands VERBATIM: B's own `keygen --payload` bytes.
    let records = skep_client::derive::records::credential_records(&board, "1.0.1", &[]).unwrap();
    let rec = records.records.iter().find(|r| r.enrolled.iter().any(|e| Fingerprint::of(&e.key) == fp_b)).expect("the hop's record");
    assert_eq!(rec.sigless, payload, "the pasted bytes are the sig-less body (AUTH-4.58)");
    assert!(rec.sig.is_some(), "the writing hand's sig at the record grade");
    // B signs in with it.
    let b = key_file(&store_b, &fp_b).signer();
    handshake(&board, Scope::Content, &b, 1, Site::Session).expect("B's session").close().unwrap();

    // `--reply`: the facts re-derived, no write.
    let before = board.health().unwrap().log_position();
    let again = reply(&board, 1, &fp_b.to_hex()[..8]).expect("the reply");
    assert_eq!(again.facts, done.facts);
    assert_eq!(board.health().unwrap().log_position(), before, "no write");
    let err = reply(&board, 1, "ffffffff").expect_err("not enrolled");
    assert!(err.to_string().contains("no enrolled key"), "{err}");

    // The same payload twice: reconciled, exit 0.
    let mut person = Scripted::new(vec![Script::Confirm(true)]);
    let twice = enroll(&board, &store_a, &mut person, &opts(&payload)).expect("reconciled");
    assert!(twice.reconciled, "{}", person.transcript.join("\n"));
    assert!(person.said("every key of the record stands enrolled"));

    // An anchor-flagged payload: refused at the paste, nothing written.
    let anchor = KeyFile::new(Seed::new([7; 32]), true, Some(Label::new("paper c").unwrap()), None);
    let flagged = encode_enroll(&[Enrollment::new(anchor.public.clone(), true, Some("paper c".into())).unwrap()]);
    let mut person = Scripted::new(vec![]);
    let err = enroll(&board, &store_a, &mut person, &opts(&flagged)).expect_err("refused at the paste");
    assert!(err.to_string().contains("ANCHOR-flagged entry") && err.to_string().contains("--anchor-lost"), "{err}");
    assert_eq!(err.exit_code(), 3);
    assert!(!person.said("CONSENT"), "nothing was compared, nothing written");
    let KeySetAnswer::Set(set) = board.key_set("1.0.1").unwrap() else { panic!() };
    assert!(set.enrolled(&anchor.fingerprint).is_none());

    // A retired key's payload: I4's halt, exit 3.
    let a = key_file(&store_a, &fp_a).signer();
    let full = handshake(&board, Scope::Full, &a, 1, Site::Session).unwrap();
    deposit(&board, full.token(), &Deposit { home: "1.0.1.0.1", subject: "1.0.1", kind: DepositKind::Retire(vec![fp_b]), hand: Some(&a), id: "test.retire-b" }).expect("retired");
    full.close().unwrap();
    let mut person = Scripted::new(vec![Script::Confirm(true)]);
    let err = enroll(&board, &store_a, &mut person, &opts(&payload)).expect_err("I4");
    assert!(err.to_string().contains("RETIRED") && err.to_string().contains("I4 (AUTH-2.98)"), "{err}");
    assert_eq!(err.exit_code(), 3);

    // The typed answer `no`: nothing written.
    let store_c = FileStore::open(dir.path().join("c"));
    let fp_c = keygen(&store_c, "tablet");
    let payload_c = encode_enroll(&[entry_of(&key_file(&store_c, &fp_c), "tablet")]);
    let mut person = Scripted::new(vec![Script::Confirm(false)]);
    let err = enroll(&board, &store_a, &mut person, &opts(&payload_c)).expect_err("declined");
    assert!(err.to_string().contains("declined"), "{err}");
    let KeySetAnswer::Set(set) = board.key_set("1.0.1").unwrap() else { panic!() };
    assert!(set.enrolled(&fp_c).is_none());
    // A malformed paste: re-take, never edit.
    let mut person = Scripted::new(vec![]);
    let err = enroll(&board, &store_a, &mut person, &opts("{\"type\":\"skep-enroll\",\"keys\":[]} ")).expect_err("malformed");
    assert!(err.to_string().contains("re-take the payload"), "{err}");
}

/// `too_many_enrolled` faced with THE ACT, `skep retire` (AUTH-5.13) — and
/// answered by `deposit` AS ITS ARM, as is a dead token's death signal, so a
/// walk acts on the arm and never on a face's words; and the by-reference
/// halt at an account that holds no keys of its own (AUTH-6.37).
#[test]
fn the_cap_names_the_act_and_a_by_reference_account_halts_in_the_reads() {
    let dir = tempfile::tempdir().unwrap();
    let sd = spawn(&dir.path().join("board"), false);
    let board = board(sd.port());
    let store = FileStore::open(dir.path().join("a"));
    let fp = keygen(&store, "notebook");
    let done = claim(&board, &store, &dir.path().join("anchors")).0;
    let a = key_file(&store, &fp).signer();
    // Fill the set to the cap (16) from A's full session.
    let full = handshake(&board, Scope::Full, &a, 1, Site::Session).unwrap();
    fill_to_the_cap(&board, full.token(), &a);
    let extra = signer_from_seed(&[99; 32]);
    let over = || DepositKind::Enroll(vec![Enrollment::new(HybridSigner::public_key(&extra).clone(), false, Some("one too many".into())).unwrap()]);
    let at_cap = deposit(&board, full.token(), &Deposit { home: "1.0.1.0.1", subject: "1.0.1", kind: over(), hand: Some(&a), id: "test.over-cap" });
    assert!(matches!(at_cap, Err(DepositHalt::SetFull(_))), "{at_cap:?}");
    let dead = full.token().clone();
    full.close().unwrap();
    let after = deposit(&board, &dead, &Deposit { home: "1.0.1.0.1", subject: "1.0.1", kind: over(), hand: Some(&a), id: "test.dead" });
    assert!(matches!(after, Err(DepositHalt::SessionClosed(_))), "{after:?}");
    let store_b = FileStore::open(dir.path().join("b"));
    let fp_b = keygen(&store_b, "phone");
    let payload = encode_enroll(&[entry_of(&key_file(&store_b, &fp_b), "phone")]);
    let mut person = Scripted::new(vec![Script::Confirm(true)]);
    let err = enroll(&board, &store, &mut person, &opts(&payload)).expect_err("the cap");
    assert!(err.to_string().contains("too_many_enrolled") && err.to_string().contains("skep retire"), "the act, never the count: {err}");
    assert_eq!(err.exit_code(), 3);
    // The agent space opens by reference: an enrollment AT it halts naming
    // where the act is made.
    let space_id = store.all_bindings().unwrap().into_iter().find_map(|b| match b {
        skep_client::store::Binding::Enrollment { account, principal, .. } if account == "1.0.1.1" => Some(principal),
        _ => None,
    }).expect("the agent space's line");
    assert_eq!(done.agent_space.as_deref(), Some("1.0.1.1"));
    let mut person = Scripted::new(vec![]);
    let err = enroll(&board, &store, &mut person, &EnrollOptions { principal: space_id, payload: payload.clone().into_bytes() }).expect_err("by reference");
    assert!(err.to_string().contains("opens by reference") && err.to_string().contains("make the act at 1.0.1"), "{err}");
}
