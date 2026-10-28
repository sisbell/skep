use skep_address::{Address, Nat};
use skep_arrangement::Shot;
use skep_engine::types::t_grant;
use skep_febe::Disposition;
use skep_kernel::{CheckpointPolicy, Durability, KernelConfig, SaltSource};
use skep_links::SlotArg;
use skep_namespace::BOOTSTRAP_PRINCIPAL;

use skep_engine::types::{t_claim, t_enroll, t_retire};

use super::*;
use crate::auth::policy::addr_of;

/// Checks the arms no wire test can reach, on a board with no `H.1`.
///
/// The board is the genesis world. A3: a home the system account owns by
/// ω is exempt, nothing demanded even with no board term (the head writer
/// never passes dispatch, so no wire write meets A3). The checked set
/// stands aside ahead of the entry frame too, and so does the narrowed
/// exemption of signed-ops D26 (SO-I4): a record of the declared kind
/// carrying its `sig` into a doc 1 — the system account's, the one doc 1
/// genesis holds — is exempt, while the same record *without* its `sig`
/// is refused `record_sig_required` ahead of A3's own exemption of that
/// home, and the same signed record into a document that is no doc 1
/// takes the check. Every other checked write answers
/// `attestation_invalid:board_unavailable` with no attest presented — the
/// board term is read before the member is asked for (the design record
/// §4.5's order: `board_unavailable` and (1) ahead of the composition), so
/// the absent term is told as its own cause, never as
/// `attestation_required` — a declared deposit of no credential kind and
/// a declared deposit of a credential kind whose atom is no record
/// included. And the tokens and their classes are the wire's.
#[test]
fn a_board_with_no_h1_answers_board_unavailable_except_where_the_check_stands_aside() {
    use skep_arrangement::VPos;
    use skep_content::Val;
    use skep_identity::{canonical_record, Enrollment};
    use skep_namespace::ghost_home_document;
    use skep_signature::{HybridSigner, TAG_MLDSA65_ED25519};

    let engine = skep_engine::Engine::open(KernelConfig {
        durability: Durability::InMemory,
        checkpoint: CheckpointPolicy::Manual,
        salt: SaltSource::Seeded(0),
    })
    .expect("in-memory genesis cannot fail");
    let snap = engine.kernel().snapshot();
    let world = snap.world();
    let doc1 = addr_of(&[1, 0, 1, 0, 1]);
    let grant_in = |home: Address| Op::MakeLink {
        home,
        from: SlotArg::Addrs(Vec::new()),
        to: SlotArg::Addrs(Vec::new()),
        ty: SlotArg::Addrs(vec![t_grant().clone()]),
        replaces: None,
    };
    let insert = |doc: &Address, deposit: Deposit, atom: &str| Op::Insert {
        doc: doc.clone(),
        at: VPos::content(Nat::from(1u32)),
        values: vec![Val::new(atom.as_bytes().to_vec())],
        deposit,
    };
    let check = |op: Op| attestation_check(world, &op, BOOTSTRAP_PRINCIPAL, None, None);
    let unavailable: Result<Option<Attestation>, CredentialRefusal> =
        Err(CredentialRefusal::AttestationInvalid(AttestFault::BoardUnavailable));
    let enroll = t_enroll().clone();

    assert_eq!(check(grant_in(skep_namespace::head_document())), Ok(None), "A3: exempt by ω");
    // Prose declared under every credential kind takes the check like
    // any insert.
    for ty in [t_enroll(), t_retire(), t_claim()] {
        assert_eq!(
            check(insert(&doc1, Deposit::Declared(ty.clone()), "x")),
            unavailable,
            "a declared deposit whose atom is no record is no D26 case"
        );
    }
    // A record of the kind: with its `sig` into a doc 1, exempt; without
    // it, refused at the insert, ahead of A3; with it elsewhere, checked.
    let key = HybridSigner::from_seed(TAG_MLDSA65_ED25519, &[9; 32]).expect("tag 1");
    let entries = [Enrollment::new(key.public_key().clone(), false, None).expect("no label")];
    let (signed, sig_less) = (
        canonical_record(&entries, Some(&"ab".repeat(3373))),
        canonical_record(&entries, None),
    );
    let system_doc1 = ghost_home_document();
    assert_eq!(
        check(insert(&system_doc1, Deposit::Declared(enroll.clone()), &signed)),
        Ok(None),
        "a record carrying its sig into a doc 1: exempt"
    );
    assert_eq!(
        check(insert(&system_doc1, Deposit::Declared(enroll.clone()), &sig_less)),
        Err(CredentialRefusal::RecordSigRequired),
        "a sig-less record of the kind: refused at its insert, ahead of A3's exemption of the home"
    );
    assert_eq!(
        check(insert(&doc1, Deposit::Declared(enroll.clone()), &signed)),
        unavailable,
        "a signed record into a document that is no doc 1: the check runs"
    );
    let delete =
        Op::Delete { doc: doc1.clone(), p: VPos::content(Nat::from(1u32)), width: Nat::from(1u32) };
    assert_eq!(check(delete), Ok(None), "outside the checked set");
    assert_eq!(check(grant_in(doc1.clone())), unavailable, "a grant, no attest presented");
    assert_eq!(check(insert(&doc1, Deposit::Undeclared, "x")), unavailable, "an undeclared insert");
    assert_eq!(
        check(insert(&doc1, Deposit::Declared(t_grant().clone()), "x")),
        unavailable,
        "a declared deposit of no credential kind is no D26 case"
    );
    let r = CredentialRefusal::AttestationInvalid(AttestFault::BoardUnavailable);
    assert_eq!(
        (r.token(), r.disposition()),
        ("attestation_invalid:board_unavailable".to_string(), Disposition::Reorder)
    );
    let r = CredentialRefusal::RecordSigRequired;
    assert_eq!(
        (r.token(), r.disposition()),
        ("record_sig_required".to_string(), Disposition::Permanent)
    );
}

/// Checks that the check asks M5's own admission of the shot.
///
/// It asks over the snapshot it is handed. Over genesis, the system
/// principal's shot into the head document `H` (published, memberless,
/// its own): with no base the admission passes the shot through its gate,
/// so `false` — and with a base outside `H`'s chain the store refuses
/// `base_not_in_chain` ahead of the gate, so `true`. An op that is no
/// shot names no run origin at all and is answered `false`, the side the
/// check refuses on.
#[test]
fn the_check_answers_the_store_s_own_admission_of_the_shot() {
    use skep_arrangement::{Base, VPos};
    use skep_namespace::{ghost_home_document, head_document, SYSTEM_PRINCIPAL};

    let engine = skep_engine::Engine::open(KernelConfig {
        durability: Durability::InMemory,
        checkpoint: CheckpointPolicy::Manual,
        salt: SaltSource::Seeded(0),
    })
    .expect("in-memory genesis cannot fail");
    let snap = engine.kernel().snapshot();
    let world = snap.world();
    let h = head_document();
    let into_h = |base: Option<Base>| Op::Publish {
        doc: h.clone(),
        shot: Shot { base, draft: None, runs: Vec::new() },
        places: Vec::new(),
    };
    assert!(
        !refused_at_or_before_the_source_gate(world, &into_h(None), SYSTEM_PRINCIPAL),
        "a shot the store admits through its gate is not refused there"
    );
    let foreign = Base { member: ghost_home_document(), extent: Nat::from(0u32) };
    assert!(
        refused_at_or_before_the_source_gate(world, &into_h(Some(foreign)), SYSTEM_PRINCIPAL),
        "a base outside the document's chain is refused ahead of the gate"
    );
    let not_a_shot =
        Op::Delete { doc: h.clone(), p: VPos::content(Nat::from(1u32)), width: Nat::from(1u32) };
    assert!(
        !refused_at_or_before_the_source_gate(world, &not_a_shot, SYSTEM_PRINCIPAL),
        "an op that is no shot is answered on the side the check refuses on"
    );
    assert_eq!(
        engine.kernel().current_seq(),
        snap.seq(),
        "the admission commits nothing to the live kernel"
    );
}

/// Checks that the session's own key is the first candidate an attest meets.
///
/// Over a board whose account `1.0.1` holds three keys of one row — the
/// ceremony's genesis, run through M10 — [`candidates`] answers the set's
/// own order with no signer, and with the signer the key that order puts
/// last, that key first and the other two in the set's order; a key the set
/// does not hold moves nothing. So an attested write signed by the key that
/// opened its session meets that key at its first verify.
#[test]
fn the_sessions_own_key_is_the_first_candidate() {
    use serde_json::json;
    use skep_febe::{Codec, OperationSurface, Response};
    use skep_identity::encode_enroll;
    use skep_signature::{HybridSigner, TAG_MLDSA65_ED25519};

    use crate::codec::JsonCodec;

    let engine = skep_engine::Engine::open(KernelConfig {
        durability: Durability::InMemory,
        checkpoint: CheckpointPolicy::Manual,
        salt: SaltSource::Seeded(0),
    })
    .expect("in-memory genesis cannot fail");
    let febe = OperationSurface::new(Box::new(engine.stores()), std::num::NonZeroUsize::MIN);
    let exec = |sid, frame: serde_json::Value| -> String {
        let req = JsonCodec
            .parse(frame.to_string().as_bytes())
            .unwrap_or_else(|e| panic!("{frame}: {:?}", e.detail));
        match febe.execute(sid, req) {
            Response::AckAddr { addr, .. } => addr.tumbler().to_string(),
            other => panic!("{frame}: {}", String::from_utf8_lossy(&JsonCodec.marshal(&other))),
        }
    };
    let enroll = t_enroll().tumbler().to_string();
    let genesis: Vec<Enrollment> = (1..=3u8)
        .map(|n| {
            let signer = HybridSigner::from_seed(TAG_MLDSA65_ED25519, &[n; 32]).expect("tag 1");
            Enrollment::new(signer.public_key().clone(), false, None).expect("no label")
        })
        .collect();
    let account = PrincipalId(900);
    exec(febe.bootstrap_session(), json!({"op": "delegate", "new_prefix": "1.0.1", "new_id": 900}));
    let sid = febe.open_session(account);
    let doc1 = exec(sid, json!({"op": "create_new_document", "account": "1.0.1"}));
    let atom = exec(
        sid,
        json!({"op": "insert", "doc": doc1, "at": {"subspace": "1", "ordinal": "1"},
               "values": [{"atom": encode_enroll(&genesis)}], "deposit": enroll}),
    );
    exec(
        sid,
        json!({"op": "make_link", "home": doc1, "from": {"addrs": [atom]},
               "to": {"addrs": ["1.0.1"]}, "ty": {"addrs": [enroll]}}),
    );
    let snap = engine.kernel().snapshot();
    let world = snap.world();
    let row = SigAlgRow::of_tag(TAG_MLDSA65_ED25519).expect("tag 1's row");
    let in_set_order = candidates(world, account, None, row);
    assert_eq!(in_set_order.len(), 3, "the premise: the genesis enrolled three keys of the row");
    let last = Fingerprint::of(in_set_order[2]);
    assert_eq!(
        candidates(world, account, Some(&last), row),
        [in_set_order[2], in_set_order[0], in_set_order[1]],
        "the signer leads, the rest in the set's order"
    );
    let stranger = Fingerprint::parse_hex(&"ab".repeat(32)).expect("a fingerprint");
    assert_eq!(
        candidates(world, account, Some(&stranger), row),
        in_set_order,
        "a key the set does not hold moves nothing"
    );
}
