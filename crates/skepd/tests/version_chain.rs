//! The version-chain model's three write-path refusals, over the wire (PUB
//! round 2, lane 3.1; owner ruling D2b, 2026-09-05): a published document
//! advances by versions, never in place (PUB-2.11, `published_target`); a
//! published document the caller owns admits no private member (PUB-2.7,
//! `private_version_of_published`); a private document the caller owns is
//! versionless (PUB-2.9, `private_source_versionless`). The refusals are the
//! STORE's — typed errors out of M5's transact, beside the ownership check
//! (PUB-8.2) — and the daemon adds no gate logic for them: what this file
//! asserts is the TRANSPORT (the codes survive lowering and marshaling, the
//! class is PERMANENT, no `detail` and no `site` ride them) and the ORDER
//! the daemon's own gates stand in ahead of them (PUB-6.36: the publish
//! class at slot 4, the store's refusal at slot 5, registration ahead of
//! both, PUB-6.37).
//!
//! The one door into a published head is the DECLARED deposit (PUB-2.59,
//! PUB-2.63): `insert` with `deposit:true` at fresh positions past the
//! arranged extent. The write path keys on the insert's deposit
//! declaration; an undeclared append on a published head is an in-place
//! edit and refuses (PUB-9.13).
//!
//! Every suite runs post-claim on a CLAIMED-PERMISSIVE board (`spawn`): the
//! claimant's doc 1 is the published document under test — born published,
//! holding the ceremony's one record atom at content ordinal 1 — and its
//! later mints are the drafts.

mod common;

use common::*;
use serde_json::Value;

/// The committed head, off `/health` — unchanged across a refusal.
fn head(port: u16) -> u64 {
    json(&get(port, "/health").1)["log_position"].as_u64().expect("log_position")
}

/// Assert a store refusal of the version-chain class: the code, PERMANENT,
/// and neither `detail` nor `site` — the face keys on the code alone (and,
/// for PUB-2.9, on the flag the client itself sent), so nothing rides
/// beside it (PUB-8.3).
fn refused(v: &Value, code: &str) {
    let rej = expect_resp(v, "rejected");
    assert_eq!(rej["code"].as_str(), Some(code), "{v}");
    assert_eq!(rej["disposition"].as_str(), Some("permanent"), "a permanent class: {v}");
    assert!(rej.get("detail").is_none(), "no detail rides the code: {v}");
    assert!(rej.get("site").is_none(), "no site rides the code: {v}");
}

/// Assert the daemon's own publish-class gate answered — slot 4, ahead of
/// the store's refusal at slot 5.
fn gated(v: &Value) {
    let rej = expect_resp(v, "rejected");
    assert_eq!(rej["code"].as_str(), Some("credential_refused"), "{v}");
    assert_eq!(rej["detail"].as_str(), Some("signed_session_required"), "{v}");
}

fn insert(doc: &str, at: u64, text: &str, deposit: bool) -> String {
    let flag = if deposit { r#","deposit":true"# } else { "" };
    format!(
        r#"{{"op":"insert","doc":"{doc}","at":{{"subspace":"1","ordinal":"{at}"}},"values":["{text}"]{flag}}}"#
    )
}

fn delete(doc: &str, at: u64, width: u64) -> String {
    format!(
        r#"{{"op":"delete","doc":"{doc}","p":{{"subspace":"1","ordinal":"{at}"}},"width":"{width}"}}"#
    )
}

fn copy(doc: &str, at: u64, source: &str, from: u64, width: u64) -> String {
    format!(
        r#"{{"op":"copy","doc":"{doc}","at":{{"subspace":"1","ordinal":"{at}"}},"specs":[{{"source":"{source}","span":{{"start":"1.{from}","width":"0.{width}"}}}}]}}"#
    )
}

fn rearrange(doc: &str, cuts: [u64; 3]) -> String {
    let [a, b, c] = cuts;
    format!(
        r#"{{"op":"rearrange","doc":"{doc}","cuts":[{{"subspace":"1","ordinal":"{a}"}},{{"subspace":"1","ordinal":"{b}"}},{{"subspace":"1","ordinal":"{c}"}}]}}"#
    )
}

/// `version` with the flag as the client would send it: `""`, or
/// `,"published":true` / `,"published":false`.
fn version(source: &str, flag: &str) -> String {
    format!(r#"{{"op":"version","d_src":"{source}"{flag}}}"#)
}

/// A later mint into the claimant's account — flagless, hence PRIVATE
/// (the home already exists), the draft every edit is staged in.
fn draft(port: u16, session: &str) -> String {
    acked_addr(&op(
        port,
        Some(session),
        &format!(r#"{{"op":"create_new_document","account":"{CLAIMANT_ACCOUNT}"}}"#),
    ))
}

/// A draft holding `text` per-byte from ordinal 1 — an undeclared insert,
/// which a draft admits from its owner's bare session.
fn draft_with(port: u16, session: &str, text: &str) -> String {
    let d = draft(port, session);
    expect_resp(&op(port, Some(session), &insert(&d, 1, text, false)), "ack_addr");
    d
}

/// PUB-2.11 — the four in-place edits on the owner's PUBLISHED document
/// refuse `published_target`, one code for the four, and commit nothing.
/// From the SIGNED session, so the daemon's publish-class gate (slot 4) is
/// passed and the store's refusal (slot 5) is what answers; from the bare
/// session the gate answers first and the store is never reached. The same
/// four edits on a draft commit as they always did.
#[test]
fn in_place_edits_refuse_a_published_target_and_commit_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let bare = open_session(port, CLAIMANT_PRINCIPAL);
    let src = draft_with(port, &bare, "xy");

    let before = head(port);
    // An undeclared insert at the head's fresh position IS an in-place edit
    // (PUB-9.13); so is one at an arranged position.
    refused(&op(port, Some(&signed), &insert(CLAIMANT_DOC1, 2, "e", false)), "published_target");
    refused(&op(port, Some(&signed), &insert(CLAIMANT_DOC1, 1, "e", false)), "published_target");
    refused(&op(port, Some(&signed), &delete(CLAIMANT_DOC1, 1, 1)), "published_target");
    // `copy` INTO the published document — its sources are never read.
    refused(&op(port, Some(&signed), &copy(CLAIMANT_DOC1, 2, &src, 1, 2)), "published_target");
    // Ahead of the op's own shape checks: doc 1 holds ONE content element,
    // so these cuts would answer `out_of_bounds` on a draft — the
    // publication refusal is what answers here (PUB-6.36 slot 5 before the
    // shape checks).
    refused(&op(port, Some(&signed), &rearrange(CLAIMANT_DOC1, [1, 2, 3])), "published_target");
    assert_eq!(head(port), before, "a refused edit commits nothing");

    // The daemon's publish-class gate stands AHEAD (slot 4): a bare session
    // is refused there and never reaches the store's code.
    gated(&op(port, Some(&bare), &delete(CLAIMANT_DOC1, 1, 1)));
    assert_eq!(head(port), before);

    // A draft: the same four edits, as today, from the owner's bare session.
    let d = draft_with(port, &bare, "abc");
    expect_resp(&op(port, Some(&bare), &delete(&d, 1, 1)), "ack"); // "bc"
    expect_resp(&op(port, Some(&bare), &rearrange(&d, [1, 2, 3])), "ack"); // "cb"
    expect_resp(&op(port, Some(&bare), &copy(&d, 3, &src, 1, 2)), "ack"); // "cbxy"
    expect_resp(&op(port, Some(&bare), &insert(&d, 5, "z", false)), "ack_addr");
    let v = op(
        port,
        None,
        &format!(r#"{{"op":"retrieve_v","specs":[{{"doc":"{d}","span":{{"start":"1.1","width":"0.5"}}}}]}}"#),
    );
    let text: String = expect_resp(&v, "delivery")["items"]
        .as_array()
        .expect("items")
        .iter()
        .map(|i| i["content"].as_str().unwrap_or(""))
        .collect();
    assert_eq!(text, "cbxyz", "the draft's edits landed as they always did: {v}");
    sd.shutdown();
}

/// PUB-2.15 — a version MEMBER is judged as its document: the member of the
/// published doc 1 refuses the in-place edits under the document's bit,
/// admits the declared deposit at its own fresh position, and a member of
/// the member projects the same way.
#[test]
fn a_version_member_target_is_judged_as_its_document() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());

    let m = acked_addr(&op(port, Some(&signed), &version(CLAIMANT_DOC1, "")));
    assert_eq!(m, format!("{CLAIMANT_DOC1}.1"), "the owner's version is a member of the chain");
    let before = head(port);
    refused(&op(port, Some(&signed), &delete(&m, 1, 1)), "published_target");
    refused(&op(port, Some(&signed), &insert(&m, 2, "e", false)), "published_target");
    refused(&op(port, Some(&signed), &rearrange(&m, [1, 2, 3])), "published_target");
    refused(&op(port, Some(&signed), &copy(&m, 2, CLAIMANT_DOC1, 1, 1)), "published_target");
    assert_eq!(head(port), before);
    // The member's own fresh position: the snapshot holds doc 1's one
    // element, so ordinal 2 is fresh there, and the declared deposit lands.
    expect_resp(&op(port, Some(&signed), &insert(&m, 2, "r", true)), "ack_addr");

    let mm = acked_addr(&op(port, Some(&signed), &version(&m, "")));
    assert_eq!(mm, format!("{m}.1"));
    refused(&op(port, Some(&signed), &delete(&mm, 1, 1)), "published_target");
    sd.shutdown();
}

/// PUB-2.7 — `version` of the owner's PUBLISHED document: an explicit
/// `false` refuses `private_version_of_published` (from the bare session
/// too — a draft mint is not the publish class's input, so the store's
/// refusal is what answers), absent inherits published, and `true` is the
/// same act spelled out. A member is itself such a source.
#[test]
fn version_of_the_owners_published_source_admits_no_private_member() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let bare = open_session(port, CLAIMANT_PRINCIPAL);

    let before = head(port);
    let private = r#","published":false"#;
    refused(&op(port, Some(&signed), &version(CLAIMANT_DOC1, private)), "private_version_of_published");
    refused(&op(port, Some(&bare), &version(CLAIMANT_DOC1, private)), "private_version_of_published");
    assert_eq!(head(port), before, "a refused version mints nothing");
    // A bare FLAGLESS version resolves published, and the daemon's gate
    // takes it first (slot 4).
    gated(&op(port, Some(&bare), &version(CLAIMANT_DOC1, "")));
    assert_eq!(head(port), before);

    let m1 = acked_addr(&op(port, Some(&signed), &version(CLAIMANT_DOC1, "")));
    let m2 = acked_addr(&op(port, Some(&signed), &version(CLAIMANT_DOC1, r#","published":true"#)));
    assert_eq!(m1, format!("{CLAIMANT_DOC1}.1"));
    assert_eq!(m2, format!("{CLAIMANT_DOC1}.2"));
    // Every version address names a published state (PUB-2.10): the member
    // is a published source whose private arm refuses the same way.
    refused(&op(port, Some(&signed), &version(&m1, private)), "private_version_of_published");
    sd.shutdown();
}

/// PUB-2.9 — `version` of a PRIVATE document the caller owns refuses
/// `private_source_versionless` whatever the flag: ONE code, the face
/// splitting on the flag the client sent, which the client holds. A
/// flagless later mint and a flagless `fork` are both such sources. The
/// bare session's explicit `true` meets the daemon's publish-class gate
/// first (slot 4 ahead of slot 5).
#[test]
fn version_of_the_owners_private_source_refuses_whatever_the_flag() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let bare = open_session(port, CLAIMANT_PRINCIPAL);
    let d = draft_with(port, &bare, "abc");
    let f = acked_addr(&op(port, Some(&bare), r#"{"op":"fork"}"#));

    let before = head(port);
    for flag in ["", r#","published":false"#, r#","published":true"#] {
        refused(&op(port, Some(&signed), &version(&d, flag)), "private_source_versionless");
        refused(&op(port, Some(&signed), &version(&f, flag)), "private_source_versionless");
    }
    for flag in ["", r#","published":false"#] {
        refused(&op(port, Some(&bare), &version(&d, flag)), "private_source_versionless");
    }
    gated(&op(port, Some(&bare), &version(&d, r#","published":true"#)));
    assert_eq!(head(port), before, "a refused version mints nothing");

    // The draft is still the owner's to edit in place.
    expect_resp(&op(port, Some(&bare), &insert(&d, 4, "d", false)), "ack_addr");
    sd.shutdown();
}

/// PUB-2.14 — the cross-owner branch is refused by NEITHER rule: a stranger's
/// `version` of the claimant's published doc 1 mints a fresh document in
/// the stranger's own account (the source's default plus the flag, as round
/// 1 built it), here an explicit `false` — the very flag that refuses the
/// OWNER — yielding the stranger's private copy, editable in place.
#[test]
fn the_cross_owner_branch_is_refused_by_neither_rule() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let boot = open_session(port, 0);
    let v = op(port, Some(&boot), r#"{"op":"next_account_prefix","parent":"1"}"#);
    let account =
        expect_resp(&v, "maybe_addr")["addr"].as_str().expect("a delegable prefix").to_string();
    let v = op(port, Some(&boot), &format!(r#"{{"op":"delegate","new_prefix":"{account}","new_id":901}}"#));
    expect_resp(&v, "ack_addr");
    let stranger = open_session(port, 901);
    // MINT-FIRST: the stranger's home, then the fork.
    let home = acked_addr(&op(
        port,
        Some(&stranger),
        &format!(r#"{{"op":"create_new_document","account":"{account}"}}"#),
    ));
    assert_eq!(home, format!("{account}.0.1"));

    let copy_doc = acked_addr(&op(port, Some(&stranger), &version(CLAIMANT_DOC1, r#","published":false"#)));
    assert_eq!(copy_doc, format!("{account}.0.2"), "a fresh document in the stranger's account, not a member");
    // Private, and the stranger's own: an undeclared insert at its fresh
    // position (the snapshot holds doc 1's one element) commits.
    expect_resp(&op(port, Some(&stranger), &insert(&copy_doc, 2, "m", false)), "ack_addr");
    // The claimant's own explicit-`false` version of the same source is the
    // owner's arm, and refuses.
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    refused(&op(port, Some(&signed), &version(CLAIMANT_DOC1, r#","published":false"#)), "private_version_of_published");
    sd.shutdown();
}

/// PUB-2.59 / PUB-9.13 (the DECLARED horn): a published head admits the
/// DECLARED deposit at a fresh position and nothing else. Undeclared at the
/// fresh position — refused; declared at an arranged position — refused;
/// declared and fresh — committed, and a link may then name it (the
/// deposit's second half); declared past the append boundary — the
/// arrangement's own `out_of_bounds`, the refusal having cleared. Into a
/// draft the declaration is inert.
#[test]
fn the_declared_deposit_is_the_one_door_into_a_published_head() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let bare = open_session(port, CLAIMANT_PRINCIPAL);

    // Doc 1 holds the ceremony's one atom at ordinal 1; ordinal 2 is fresh.
    refused(&op(port, Some(&signed), &insert(CLAIMANT_DOC1, 2, "u", false)), "published_target");
    refused(&op(port, Some(&signed), &insert(CLAIMANT_DOC1, 1, "d", true)), "published_target");
    // A declared write into the LINK subspace is no deposit either — the
    // refusal answers ahead of the shape check (`not_content_subspace`).
    let v = op(
        port,
        Some(&signed),
        &format!(
            r#"{{"op":"insert","doc":"{CLAIMANT_DOC1}","at":{{"subspace":"2","ordinal":"1"}},"values":["l"],"deposit":true}}"#
        ),
    );
    refused(&v, "published_target");
    // The daemon's gate stands ahead of the door: a bare declared deposit
    // is the publish class's input and refuses there.
    gated(&op(port, Some(&bare), &insert(CLAIMANT_DOC1, 2, "b", true)));

    let atom = acked_addr(&op(port, Some(&signed), &insert(CLAIMANT_DOC1, 2, "r", true)));
    assert_eq!(atom, format!("{CLAIMANT_DOC1}.0.1.2"), "the record lands at the head's fresh position");
    let v = op(
        port,
        Some(&signed),
        &format!(
            r#"{{"op":"make_link","home":"{CLAIMANT_DOC1}","from":{{"addrs":["{atom}"]}},"to":{{"addrs":[]}},"ty":{{"addrs":["{CLAIMANT_DOC1}.0.3.6.1"]}}}}"#
        ),
    );
    expect_resp(&v, "ack_addr");
    // Fresh but past the append boundary (two elements arranged, ordinal 3
    // the boundary): the refusal clears and the arrangement's own bound
    // speaks.
    let v = op(port, Some(&signed), &insert(CLAIMANT_DOC1, 4, "p", true));
    assert_eq!(expect_resp(&v, "rejected")["code"].as_str(), Some("out_of_bounds"), "{v}");
    // The next deposit, at the new fresh position.
    expect_resp(&op(port, Some(&signed), &insert(CLAIMANT_DOC1, 3, "s", true)), "ack_addr");

    // A draft: declared or not, at an arranged position or a fresh one.
    let d = draft_with(port, &bare, "ab");
    expect_resp(&op(port, Some(&bare), &insert(&d, 1, "c", true)), "ack_addr");
    expect_resp(&op(port, Some(&bare), &insert(&d, 4, "e", false)), "ack_addr");
    sd.shutdown();
}

/// PUB-6.37 — the refusal reads publication on REGISTERED addresses only:
/// an unregistered target answers `doc_not_registered` (the registration
/// check ahead of it, in the daemon's gate and the store alike), and an
/// unregistered MEMBER address of the published doc 1 answers the same —
/// the projection to the document runs only after registration.
#[test]
fn an_unregistered_target_answers_registration_not_publication() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let bare = open_session(port, CLAIMANT_PRINCIPAL);
    let ghost = format!("{CLAIMANT_ACCOUNT}.0.9");
    let ghost_member = format!("{CLAIMANT_DOC1}.7");

    let before = head(port);
    for session in [&bare, &signed] {
        for doc in [&ghost, &ghost_member] {
            for frame in [
                insert(doc, 1, "x", false),
                insert(doc, 1, "x", true),
                delete(doc, 1, 1),
                copy(doc, 1, CLAIMANT_DOC1, 1, 1),
                rearrange(doc, [1, 2, 3]),
            ] {
                let v = op(port, Some(session), &frame);
                let rej = expect_resp(&v, "rejected");
                assert_eq!(rej["code"].as_str(), Some("doc_not_registered"), "{v}");
                assert_eq!(rej["disposition"].as_str(), Some("reorder"), "{v}");
            }
            let v = op(port, Some(session), &version(doc, ""));
            assert_eq!(expect_resp(&v, "rejected")["code"].as_str(), Some("source_not_registered"), "{v}");
        }
    }
    assert_eq!(head(port), before);
    sd.shutdown();
}

/// `fork`'s flag resolves as `create_new_document`'s does (PUB-8.21 for a
/// non-empty account): flagless and explicit `false` mint drafts, an
/// explicit `true` mints a published document — from a signed session; a
/// bare `true` is the publish class's input — and the minted document is
/// then judged by its bit like any other.
#[test]
fn fork_resolves_its_flag_as_create_does() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let bare = open_session(port, CLAIMANT_PRINCIPAL);

    let f_absent = acked_addr(&op(port, Some(&bare), r#"{"op":"fork"}"#));
    let f_false = acked_addr(&op(port, Some(&bare), r#"{"op":"fork","published":false}"#));
    gated(&op(port, Some(&bare), r#"{"op":"fork","published":true}"#));
    let f_true = acked_addr(&op(port, Some(&signed), r#"{"op":"fork","published":true}"#));

    // Drafts: edited in place by their owner's bare session, versionless.
    for f in [&f_absent, &f_false] {
        expect_resp(&op(port, Some(&bare), &insert(f, 1, "d", false)), "ack_addr");
        refused(&op(port, Some(&signed), &version(f, "")), "private_source_versionless");
    }
    // Published: gated from the bare session, refused in place from the
    // signed one, open to the declared deposit, and versionable.
    gated(&op(port, Some(&bare), &insert(&f_true, 1, "p", false)));
    refused(&op(port, Some(&signed), &insert(&f_true, 1, "p", false)), "published_target");
    expect_resp(&op(port, Some(&signed), &insert(&f_true, 1, "p", true)), "ack_addr");
    let m = acked_addr(&op(port, Some(&signed), &version(&f_true, "")));
    assert_eq!(m, format!("{f_true}.1"));
    sd.shutdown();
}
