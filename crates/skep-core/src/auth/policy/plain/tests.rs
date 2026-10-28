use skep_address::subtree_of;
use skep_identity::CredentialKind;

use skep_engine::types::t_enroll;

use super::*;
use crate::auth::policy::addr_of;

/// Checks that PUB-2.15's projection is address arithmetic and total.
///
/// A version member answers its document, a document answers itself, a
/// member of a member peels to the same document — and off the document
/// tier the arithmetic changes nothing (an account has no document field;
/// an element's field is its document's own). The projection the gate
/// reads is M5's, so this pins the one spelling the daemon shares with the
/// write path.
#[test]
fn a_version_member_projects_to_its_document() {
    let doc = addr_of(&[1, 0, 1, 0, 1]);
    assert_eq!(trunk_of(&doc), doc, "a document is its own trunk");
    assert_eq!(trunk_of(&addr_of(&[1, 0, 1, 0, 1, 1])), doc, "a version");
    assert_eq!(trunk_of(&addr_of(&[1, 0, 1, 0, 1, 1, 2])), doc, "a version of a version");
    let acct = addr_of(&[1, 0, 1]);
    assert_eq!(trunk_of(&acct), acct);
    let element = addr_of(&[1, 0, 1, 0, 1, 0, 1, 1]);
    assert_eq!(trunk_of(&element), element);
}

/// Checks the write path's input as wired.
///
/// Every pinned class address classifies to its own arm, the credential
/// kinds answer through the same input as `kind_of` does, the edition
/// class is *no* class (PUB-6.32 — its owner's retraction is admitted),
/// and a content span is nothing. The wiring itself — the `LazyLock`
/// constructing without the prefix-free assertion firing — is what the
/// first call proves.
#[test]
fn the_write_path_input_recognizes_every_pinned_class() {
    let types = write_types();
    let unit = |a: &Address| vec![subtree_of(a.tumbler())];
    assert_eq!(
        types.target_class(&unit(t_enroll())),
        Some(TargetClass::Credential(CredentialKind::Enroll))
    );
    assert_eq!(types.target_class(&unit(t_grant())), Some(TargetClass::Grant));
    for (class, addr) in [
        (AuditClass::SuccessorOf, t_successor_of()),
        (AuditClass::DelegatorEndorsement, t_endorse()),
        (AuditClass::ConsumptionMarker, t_consumption_marker()),
        (AuditClass::JournalDesignation, t_journal_designation()),
        (AuditClass::RailRecord, t_rail_record()),
        (AuditClass::StewardClassification, t_steward_classification()),
        (AuditClass::Replaces, t_replaces()),
        (AuditClass::Binding, t_binding()),
        (AuditClass::TakedownRecord, t_takedown()),
        (AuditClass::PolicyLink, t_policy_link()),
        (AuditClass::Supersession, &supersedes_type()),
    ] {
        assert_eq!(
            types.target_class(&unit(addr)),
            Some(TargetClass::AuditView(class)),
            "{} is {class:?}",
            addr.tumbler()
        );
    }
    // The supersession class's address is M7's reserved ghost tumbler,
    // read from M7 and spelled here only to pin the reading: a stored
    // claim's type slot is exactly that class.
    assert_eq!(supersedes_type(), addr_of(&[1, 1, 0, 1, 0, 1, 0, 1, 4]));
    let claim = skep_links::supersession_claim(
        &addr_of(&[1, 0, 1, 0, 1, 0, 2, 1]),
        &addr_of(&[1, 0, 1, 0, 1, 0, 2, 2]),
    );
    assert_eq!(
        types.target_class(claim.type_slot()),
        Some(TargetClass::AuditView(AuditClass::Supersession))
    );
    // The registry's subtype rows are their kinds' members by prefix
    // (REG-1.21); the endpoint is no class at all (REG-1.11, REG-1.46).
    for (class, addr) in [
        (AuditClass::TakedownRecord, skep_engine::types::t_takedown_lifted()),
        (AuditClass::PolicyLink, skep_engine::types::t_disavowal()),
        (AuditClass::PolicyLink, skep_engine::types::t_succession_policy()),
    ] {
        assert_eq!(types.target_class(&unit(addr)), Some(TargetClass::AuditView(class)));
    }
    assert_eq!(types.target_class(&unit(skep_engine::types::t_endpoint())), None);
    // The edition class (3.14) is read under the active view: no class.
    assert_eq!(types.target_class(&unit(skep_engine::types::t_edition())), None);
    // A content I-span names nothing here either.
    let content = subtree_of(addr_of(&[1, 0, 1, 0, 1, 0, 1, 1]).tumbler());
    assert_eq!(types.target_class(&[content]), None);
    // A subtype by prefix is its class's member (L10): `endorse.trust`.
    let trust = addr_of(&[1, 1, 0, 1, 0, 1, 0, 3, 42, 2]);
    assert_eq!(
        types.target_class(&unit(&trust)),
        Some(TargetClass::AuditView(AuditClass::DelegatorEndorsement))
    );
}

/// Checks the supersession claim's two keys (PUB-6.64; skep #677).
///
/// The board is built through M10 alone and left unclaimed, where
/// [`nullify_refusal`] answers a class's token to every caller, so the
/// class decision is read bare. A claim in its maker's private notes is a
/// member where its `new` is homed in a published document and its `old`
/// is the maker's own: an ordinary link in the maker's account, or a
/// credential whose subject is the maker's account wherever it is homed —
/// the genesis a first rotation's trail names, in another account's doc 1.
/// The same claim over another account's ordinary link is an ordinary
/// link, and so is one over a credential naming another account, in the
/// maker's own home as anywhere, and one whose `new` is private. The keys
/// are facts of the claim: the maker and another account asking get one
/// answer.
#[test]
fn a_supersession_claim_is_a_member_only_over_its_makers_own_old() {
    use serde_json::json;
    use skep_febe::{Codec, OperationSurface, Response};
    use skep_kernel::{CheckpointPolicy, Durability, KernelConfig, SaltSource};

    use crate::auth::CredentialLock;
    use crate::codec::JsonCodec;

    let engine = skep_engine::Engine::open(KernelConfig {
        durability: Durability::InMemory,
        checkpoint: CheckpointPolicy::Manual,
        salt: SaltSource::Seeded(0),
    })
    .expect("in-memory genesis cannot fail");
    let febe = OperationSurface::new(Box::new(engine.stores()), std::num::NonZeroUsize::MIN);
    let exec = |sid, frame: serde_json::Value| -> Address {
        let req = JsonCodec
            .parse(frame.to_string().as_bytes())
            .unwrap_or_else(|e| panic!("{frame}: {:?}", e.detail));
        match febe.execute(sid, req) {
            Response::AckAddr { addr, .. } => addr,
            other => panic!("{frame}: {}", String::from_utf8_lossy(&JsonCodec.marshal(&other))),
        }
    };
    let (maker_id, other_id) = (PrincipalId(900), PrincipalId(901));
    let boot = febe.bootstrap_session();
    exec(boot, json!({"op": "delegate", "new_prefix": "1.0.1", "new_id": maker_id.0}));
    exec(boot, json!({"op": "delegate", "new_prefix": "1.0.2", "new_id": other_id.0}));
    let (maker, other) = (febe.open_session(maker_id), febe.open_session(other_id));
    // Each account's home, born published; then the maker's private notes.
    let mint = |sid, account: &str| {
        exec(sid, json!({"op": "create_new_document", "account": account})).to_string()
    };
    let (home, other_home) = (mint(maker, "1.0.1"), mint(other, "1.0.2"));
    let notes = mint(maker, "1.0.1");
    let link = |sid, doc: &str, n: u32| -> String {
        exec(
            sid,
            json!({"op": "make_link", "home": doc, "from": {"addrs": []},
                   "to": {"addrs": []}, "ty": {"addrs": [format!("{doc}.0.3.6.{n}")]}}),
        )
        .to_string()
    };
    // An enroll-typed link naming `subject`: the class is its type slot's,
    // so the record atom a deposit's `from` names is left out.
    let credential = |sid, doc: &str, subject: &str| -> String {
        exec(
            sid,
            json!({"op": "make_link", "home": doc, "from": {"addrs": []},
                   "to": {"addrs": [subject]}, "ty": {"addrs": [t_enroll().to_string()]}}),
        )
        .to_string()
    };
    let own_old = link(maker, &notes, 1);
    let published_new = link(maker, &home, 2);
    let private_new = link(maker, &notes, 3);
    let foreign_old = link(other, &other_home, 4);
    // The maker's genesis as its registrar would home it, in another
    // account's doc 1; a credential the maker filed for another account in
    // its own; one naming the maker in its own.
    let makers_genesis = credential(other, &other_home, "1.0.1");
    let others_credential = credential(maker, &home, "1.0.2");
    let makers_credential = credential(maker, &home, "1.0.1");
    let claim = |old: &str, new: &str| {
        exec(maker, json!({"op": "assert_sup", "home": notes, "old": old, "new": new}))
    };
    let own = claim(&own_old, &published_new);
    let over_another = claim(&foreign_old, &published_new);
    let private = claim(&own_old, &private_new);
    let over_makers_genesis = claim(&makers_genesis, &published_new);
    let over_others_credential = claim(&others_credential, &published_new);
    let over_makers_credential = claim(&makers_credential, &published_new);

    let snap = engine.kernel().snapshot();
    let world = snap.world();
    assert!(world.identity().claimant().is_none(), "the premise: unclaimed, every caller told");
    let notes = crate::codec::wire_address(&notes).expect("the notes' address");
    let lock = CredentialLock::new();
    for caller in [maker_id, other_id] {
        let class_of = |target: &Address| {
            let op = Op::Nullify { home: notes.clone(), target: target.clone() };
            nullify_refusal(&lock.read(), world, &op, caller)
        };
        let member = |why: &str| format!("{caller:?}: {why}, a published `new`: a member");
        let audit_view = Some(CredentialRefusal::NullifyAuditView);
        assert_eq!(class_of(&own), audit_view, "{}", member("the maker's own `old`"));
        assert_eq!(
            class_of(&over_makers_genesis),
            audit_view,
            "{}",
            member("a credential naming the maker, homed in another's doc 1")
        );
        assert_eq!(
            class_of(&over_makers_credential),
            audit_view,
            "{}",
            member("a credential naming the maker, homed in its own")
        );
        let ordinary = |why: &str| format!("{caller:?}: {why}: an ordinary link");
        assert_eq!(class_of(&over_another), None, "{}", ordinary("another's `old`"));
        assert_eq!(class_of(&private), None, "{}", ordinary("a private `new`"));
        assert_eq!(
            class_of(&over_others_credential),
            None,
            "{}",
            ordinary("a credential naming another account, homed in the maker's own")
        );
    }
}
