//! H1 — THE `nullify` CLASS CELLS (PUB round 2, lane 3.5): slot 5's three
//! refusals in PUB-6.36's order as RES-195 places them — the credential-typed
//! cell lane 3.3c built (PUB-6.10), and the two this lane adds: the
//! GRANT-TYPED target (PUB-6.30, `nullify_not_revocation`) and the
//! AUDIT-VIEW class (PUB-6.64, `nullify_audit_view` — the succession pair,
//! the consumption marker, the journal designation, the rail record, the
//! steward's classification link where its home is published). Each cell ×
//! the caller classes the pack names: the OWNER (signed), a STRANGER (signed,
//! non-entitled), the GUEST, and the BARE OWNER on a published home — plus
//! the negative cell (the edition claim's owner retraction ADMITTED) and the
//! ordering pins: `not_owner` ahead of every occupancy test (PUB-6.9), the
//! publish-class gate (slot 4) ahead of the class cells (slot 5), and the
//! byte-identity of a stranger's answers across every target class.
//!
//! The class addresses are the engine's commons pins (`skep_engine::types`),
//! spelled here as a client names them.

use crate::common;

use common::*;
use serde_json::Value;

/// The GRANTS class is `common::T_GRANT` (3.90). The audit-view members, as
/// pinned in `skep_engine::types` (each confirmed by the owner 2026-09-07).
const T_SUCCESSOR_OF: &str = "1.1.0.1.0.1.0.3.59";
const T_ENDORSE: &str = "1.1.0.1.0.1.0.3.42";
const T_MARKER: &str = "1.1.0.1.0.1.0.3.91";
const T_DESIGNATION: &str = "1.1.0.1.0.1.0.3.22";
const T_RAIL: &str = "1.1.0.1.0.1.0.3.60";
const T_STEWARD: &str = "1.1.0.1.0.1.0.3.61";
/// The R20 edition class (3.14) and one descriptive subtype — read under the
/// ACTIVE view (PUB-6.32), so OUTSIDE PUB-6.64 by its own test.
const T_EDITION: &str = "1.1.0.1.0.1.0.3.14";
const T_EDITION_EXPANDED: &str = "1.1.0.1.0.1.0.3.14.2";

/// A rejection's verdict: the code, or `credential_refused:<token>` for the
/// daemon-originated family (the `auth_wire` convention).
fn verdict(v: &Value) -> String {
    let rej = expect_resp(v, "rejected");
    match (rej["code"].as_str().unwrap_or("?"), rej["detail"].as_str()) {
        ("credential_refused", Some(d)) => format!("credential_refused:{d}"),
        (c, _) => c.to_string(),
    }
}

/// `not_owner` (permanent), `site.addr` naming the address that failed ω.
fn assert_not_owner(v: &Value, failing: &str) {
    assert_eq!(verdict(v), "not_owner", "{v}");
    assert_eq!(v["disposition"].as_str(), Some("permanent"), "{v}");
    assert_eq!(v["site"]["addr"].as_str(), Some(failing), "the address that failed ω: {v}");
}

fn nullify_frame(home: &str, target: &str) -> String {
    format!(r#"{{"op":"nullify","home":"{home}","target":"{target}"}}"#)
}

fn nullify(port: u16, token: Option<&str>, home: &str, target: &str) -> Value {
    op(port, token, &nullify_frame(home, target))
}

/// An address-form link of type `ty` homed in `home`, from `token`.
fn typed_link(port: u16, token: &str, home: &str, from: &[&str], to: &[&str], ty: &str) -> Value {
    let list = |xs: &[&str]| -> String {
        let quoted: Vec<String> = xs.iter().map(|x| format!("\"{x}\"")).collect();
        format!(r#"{{"addrs":[{}]}}"#, quoted.join(","))
    };
    op(
        port,
        Some(token),
        &format!(
            r#"{{"op":"make_link","home":"{home}","from":{},"to":{},"ty":{{"addrs":["{ty}"]}}}}"#,
            list(from),
            list(to)
        ),
    )
}

fn typed_link_addr(port: u16, token: &str, home: &str, from: &[&str], to: &[&str], ty: &str) -> String {
    acked_addr(&typed_link(port, token, home, from, to, ty))
}

/// A fresh account under node 1, delegated from the bootstrap principal —
/// `(account, its BARE session)`.
fn stranger(port: u16, id: u64) -> (String, String) {
    let boot = open_session(port, 0);
    let v = op(port, Some(&boot), r#"{"op":"next_account_prefix","parent":"1"}"#);
    let account =
        expect_resp(&v, "maybe_addr")["addr"].as_str().expect("a delegable prefix").to_string();
    expect_resp(
        &op(port, Some(&boot), &format!(r#"{{"op":"delegate","new_prefix":"{account}","new_id":{id}}}"#)),
        "ack_addr",
    );
    (account, open_session(port, id))
}

/// A SIGNED stranger: a bootstrap-delegated account the claimant keys through
/// the hire (its genesis registry is the claimant's doc 1, AUTH-2.62) — the
/// NON-ENTITLED signed caller. `(account, signed session)`.
fn signed_stranger(port: u16, claimant_signed: &str, id: u64, seed: u8) -> (String, String) {
    let (account, _bare) = stranger(port, id);
    let signed = hire(port, claimant_signed, CLAIMANT_DOC1, &account, id, &distinct_key(seed));
    (account, signed)
}

/// A private draft of the claimant's (a non-first flagless mint).
fn owner_draft(port: u16, token: &str) -> String {
    acked_addr(&op(
        port,
        Some(token),
        &format!(r#"{{"op":"create_new_document","account":"{CLAIMANT_ACCOUNT}"}}"#),
    ))
}

/// A private draft of `account`'s, from its own session — the second mint,
/// after the MINT-FIRST home.
fn own_draft(port: u16, session: &str, account: &str) -> String {
    let create = || {
        acked_addr(&op(
            port,
            Some(session),
            &format!(r#"{{"op":"create_new_document","account":"{account}"}}"#),
        ))
    };
    create();
    create()
}

/// One credential-typed link in the claimant's published doc 1: an enroll
/// record atom deposited at the next free position, then the `T_ENROLL`
/// deposit naming it — through the credential path, from the SIGNED session.
fn credential_link(port: u16, signed: &str, seed: u8) -> String {
    let ordinal = next_content_ordinal(port, Some(signed), CLAIMANT_DOC1);
    let v = op(
        port,
        Some(signed),
        &format!(
            r#"{{"op":"insert","doc":"{CLAIMANT_DOC1}","at":{{"subspace":"1","ordinal":"{ordinal}"}},"values":[{{"atom":{}}}],"deposit":true}}"#,
            enroll_atom(&[&distinct_key(seed)])
        ),
    );
    let atom = acked_addr(&v);
    typed_link_addr(port, signed, CLAIMANT_DOC1, &[atom.as_str()], &[CLAIMANT_ACCOUNT], T_ENROLL)
}

fn head(port: u16) -> u64 {
    json(&get(port, "/health").1)["log_position"].as_u64().expect("log_position")
}

fn link_resident(port: u16, token: Option<&str>, a: &str) -> bool {
    let v = op(port, token, &format!(r#"{{"op":"read_link","a":"{a}"}}"#));
    !expect_resp(&v, "link_value")["link"].is_null()
}

/// H1 cell 1 — the GRANT-TYPED target (PUB-6.30), every caller class, and
/// the two order pins that run through it. PRE-CLAIM the row's probe surface
/// is EMPTY (PUB-6.10's mode-disjointness): the admission gate refuses the
/// grant's own deposit and any `nullify` alike, `claim_first`, so no
/// grant-typed link can exist on an unclaimed board. CLAIMED: the ISSUER's
/// signed session is refused `nullify_not_revocation` — retraction is never
/// a second revocation path; the BARE issuer meets the publish-class gate
/// first (PUB-6.36 slot 4 before slot 5; PUB-6.43's `nullify` row — the
/// record lands in the published doc 1), `signed_session_required`, never
/// the grant code; a signed STRANGER answers `not_owner`, occupancy-blind;
/// the GUEST is `unauthenticated` at slot 0. Nothing is retracted and
/// nothing commits.
///
/// Spawned CONFIGURED and unclaimed (`spawn`'s first half, the shape a
/// production claimed board is launched in): the signed STRANGER is hired
/// AFTER the claim, and a claimed board's signed arm accepts only the
/// configured origins (AUTH-4.3's claim-time drop) — on `spawn_unclaimed`'s
/// origin-less board every post-claim signed handshake is `session_rejected`.
#[test]
fn a_grant_typed_nullify_is_refused_to_the_issuer_and_masked_for_everyone_else() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn_configured(dir.path(), true);
    let port = sd.port();

    // The ceremony's first four steps (AUTH-5.55 1–4), the signed claim
    // WITHHELD: delegate from 0, the home mint, the genesis atom and its
    // deposit — the unclaimed window with a keyed claimant in it.
    let boot = open_session(port, 0);
    let v = op(port, Some(&boot), r#"{"op":"next_account_prefix","parent":"1"}"#);
    let prefix = expect_resp(&v, "maybe_addr")["addr"].as_str().expect("prefix").to_string();
    assert_eq!(prefix, CLAIMANT_ACCOUNT, "the ceremony must be the board's first delegate");
    expect_resp(
        &op(port, Some(&boot), &format!(r#"{{"op":"delegate","new_prefix":"{prefix}","new_id":{CLAIMANT_PRINCIPAL}}}"#)),
        "ack_addr",
    );
    let bare = open_session(port, CLAIMANT_PRINCIPAL);
    let v = op(port, Some(&bare), &format!(r#"{{"op":"create_new_document","account":"{CLAIMANT_ACCOUNT}"}}"#));
    assert_eq!(acked_addr(&v), CLAIMANT_DOC1, "the home mint is doc 1");
    let v = op(
        port,
        Some(&bare),
        &format!(
            r#"{{"op":"insert","doc":"{CLAIMANT_DOC1}","at":{{"subspace":"1","ordinal":"1"}},"values":[{{"atom":{}}}],"deposit":true}}"#,
            enroll_atom_flagged(&[(&anchor_key(), true), (&device_key(), false)])
        ),
    );
    expect_resp(&v, "ack_addr");
    let genesis_atom = format!("{CLAIMANT_DOC1}.0.1.1");
    typed_link_addr(port, &bare, CLAIMANT_DOC1, &[genesis_atom.as_str()], &[CLAIMANT_ACCOUNT], T_ENROLL);
    assert!(!claimed(port), "the genesis deposit alone claims nothing");
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());

    // PRE-CLAIM: the grant's deposit is refused by the admission gate — no
    // grant-typed link can exist here — and so is every `nullify`, from the
    // bare and the signed session alike, `claim_first` in the pinned shape.
    let grant_frame = format!(
        r#"{{"op":"make_link","home":"{CLAIMANT_DOC1}","from":{{"addrs":["{CLAIMANT_DOC1}"]}},"to":{{"addrs":[]}},"ty":{{"addrs":["{T_GRANT}"]}}}}"#
    );
    assert_eq!(verdict(&op(port, Some(&signed), &grant_frame)), "credential_refused:claim_first");
    let probe = format!("{CLAIMANT_DOC1}.0.2.9"); // an address in doc 1's link subspace
    for token in [&bare, &signed] {
        let v = nullify(port, Some(token), CLAIMANT_DOC1, &probe);
        assert_eq!(verdict(&v), "credential_refused:claim_first", "pre-claim, slot 4 answers first: {v}");
        assert_eq!(v["disposition"].as_str(), Some("permanent"));
    }

    // Step 5 — the signed claim.
    let v = typed_link(port, &signed, CLAIMANT_DOC1, &[CLAIMANT_ACCOUNT], &[], T_CLAIM);
    expect_resp(&v, "ack_addr");
    assert!(claimed(port), "the claim link flips the board claimed");

    // The issuer grants a draft of its own to a grantee, from its published
    // doc 1 (the residence the fold admits, PUB-5.17).
    let draft = owner_draft(port, &bare);
    let (grantee, _) = stranger(port, 941);
    let grant = deposit_grant(port, &signed, CLAIMANT_DOC1, &draft, Some(&grantee));
    let (_, stranger_signed) = signed_stranger(port, &signed, 942, 42);
    let before = head(port);

    // OWNER, signed: the grant-typed cell, in the credential family's shape.
    let v = nullify(port, Some(&signed), CLAIMANT_DOC1, &grant);
    assert_eq!(verdict(&v), "credential_refused:nullify_not_revocation");
    assert_eq!(v["disposition"].as_str(), Some("permanent"), "{v}");
    assert_eq!(v["op"].as_str(), Some("nullify"), "{v}");
    // BARE OWNER: the publish-class gate first — the retraction lands in the
    // published doc 1 — never the grant code (slot 4 before slot 5).
    let v = nullify(port, Some(&bare), CLAIMANT_DOC1, &grant);
    assert_eq!(verdict(&v), "credential_refused:signed_session_required", "{v}");
    // STRANGER, signed and non-entitled: ω's own answer, naming the home it
    // does not own — indistinguishable from its answer on any link there.
    let v = nullify(port, Some(&stranger_signed), CLAIMANT_DOC1, &grant);
    assert_not_owner(&v, CLAIMANT_DOC1);
    // GUEST: slot 0.
    assert_eq!(verdict(&nullify(port, None, CLAIMANT_DOC1, &grant)), "unauthenticated");

    // Nothing committed, nothing retracted: the grant stands, resident and
    // active to its own discovery.
    assert_eq!(head(port), before, "four refusals commit nothing");
    assert!(link_resident(port, None, &grant), "the grant record stands (a doc-1 link is guest-readable)");
    let v = op(
        port,
        Some(&signed),
        &format!(
            r#"{{"op":"find_links_ftt","q":{{"home":"any","from":"any","to":"any","ty":[{{"start":"{T_GRANT}","width":"0.0.0.0.0.0.0.0.1"}}]}}}}"#
        ),
    );
    let addrs = expect_resp(&v, "addrs")["addrs"].as_array().expect("addrs").clone();
    assert!(addrs.iter().any(|a| a.as_str() == Some(grant.as_str())), "still ACTIVE: {v}");
    sd.shutdown();
}

/// H1 cells 2 and 3 — the AUDIT-VIEW classes (PUB-6.64): the succession pair
/// (both members, PUB-7.63), the rail record (PUB-5.76) and the steward's
/// classification link (PUB-5.43) in the owner's PUBLISHED doc 1; the
/// consumption marker and the journal designation (PUB-4.12) in the owner's
/// private DRAFT journal (PUB-4.1). ONE code for the class, `nullify_audit_view`,
/// to the record's own ω owner; a stranger answers `not_owner`,
/// occupancy-blind — the same bytes as for a plain link at an EMPTY address of
/// the same home; the bare owner on a published home meets the publish-class
/// gate first; and a classification link with a DRAFT home is an ordinary
/// link, its owner's retraction ADMITTED (RES-207's keying).
#[test]
fn an_audit_view_class_nullify_is_refused_to_the_owner_and_masked_for_strangers() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let bare = open_session(port, CLAIMANT_PRINCIPAL);
    let (sub_account, _) = stranger(port, 951); // a subject for the pair's slots
    let (_, stranger_signed) = signed_stranger(port, &signed, 952, 52);
    let (_, stranger_bare) = stranger(port, 953);

    // PUBLISHED-HOME members, deposited from the owner's signed session into
    // its doc 1: the succession pair, the rail, the classification link.
    let successor =
        typed_link_addr(port, &signed, CLAIMANT_DOC1, &[CLAIMANT_ACCOUNT], &[sub_account.as_str()], T_SUCCESSOR_OF);
    let endorsement =
        typed_link_addr(port, &signed, CLAIMANT_DOC1, &[CLAIMANT_ACCOUNT], &[successor.as_str()], T_ENDORSE);
    let rail = typed_link_addr(port, &signed, CLAIMANT_DOC1, &[sub_account.as_str()], &[CLAIMANT_DOC1], T_RAIL);
    let classification =
        typed_link_addr(port, &signed, CLAIMANT_DOC1, &[CLAIMANT_DOC1], &[CLAIMANT_DOC1], T_STEWARD);
    let before = head(port);
    for (what, target) in [
        ("successor-of", &successor),
        ("delegator endorsement", &endorsement),
        ("rail record", &rail),
        ("steward classification (published home)", &classification),
    ] {
        // OWNER, signed: the class code.
        let v = nullify(port, Some(&signed), CLAIMANT_DOC1, target);
        assert_eq!(verdict(&v), "credential_refused:nullify_audit_view", "{what}: {v}");
        assert_eq!(v["disposition"].as_str(), Some("permanent"), "{what}: {v}");
        // BARE OWNER: slot 4 first — the record lands in the published doc 1.
        let v = nullify(port, Some(&bare), CLAIMANT_DOC1, target);
        assert_eq!(verdict(&v), "credential_refused:signed_session_required", "{what}: {v}");
        // STRANGERS, signed or bare: ω's own answer, naming the home.
        assert_not_owner(&nullify(port, Some(&stranger_signed), CLAIMANT_DOC1, target), CLAIMANT_DOC1);
        assert_not_owner(&nullify(port, Some(&stranger_bare), CLAIMANT_DOC1, target), CLAIMANT_DOC1);
        // GUEST: slot 0.
        assert_eq!(verdict(&nullify(port, None, CLAIMANT_DOC1, target)), "unauthenticated", "{what}");
        assert!(link_resident(port, None, target), "{what}: nothing was retracted");
    }
    assert_eq!(head(port), before, "the refusals commit nothing");

    // DRAFT-HOME members: the owner's journal is a private draft (PUB-4.1);
    // the marker names an offer link, the designation is the journal's own
    // typed self-link (PUB-4.3). Deposited bare — a draft write.
    let journal = owner_draft(port, &bare);
    let offer = format!("{CLAIMANT_DOC1}.0.2.7"); // any address in the marker's TO slot
    let accepted = format!("{CLAIMANT_DOC1}.0.1.1"); // stands in for the well-known value address
    let marker = typed_link_addr(port, &bare, &journal, &[accepted.as_str()], &[offer.as_str()], T_MARKER);
    let designation =
        typed_link_addr(port, &bare, &journal, &[journal.as_str()], &[journal.as_str()], T_DESIGNATION);
    let before = head(port);
    for (what, target) in [("consumption marker", &marker), ("journal designation", &designation)] {
        // The OWNER, bare and signed alike: a draft-homed record against a
        // draft-homed target takes no publish gate, so the class cell answers.
        for token in [&bare, &signed] {
            let v = nullify(port, Some(token), &journal, target);
            assert_eq!(verdict(&v), "credential_refused:nullify_audit_view", "{what}: {v}");
        }
        assert!(link_resident(port, Some(&bare), target), "{what}: PUB-4.12 — the record stands");
    }
    // A STRANGER naming the journal as home: `not_owner`, occupancy-blind —
    // byte-identical to its answer for a plain link at an EMPTY address of
    // that same link subspace.
    let empty = format!("{journal}.0.2.99");
    let (_, on_marker) = http(port, "POST", "/op", Some(&stranger_signed), nullify_frame(&journal, &marker).as_bytes());
    let (_, on_designation) = http(port, "POST", "/op", Some(&stranger_signed), nullify_frame(&journal, &designation).as_bytes());
    let (_, on_empty) = http(port, "POST", "/op", Some(&stranger_signed), nullify_frame(&journal, &empty).as_bytes());
    assert_not_owner(&json(&on_empty), &journal);
    assert_eq!(on_marker, on_empty, "the marker's occupancy is invisible to a stranger");
    assert_eq!(on_designation, on_empty, "the designation's occupancy is invisible to a stranger");
    assert_eq!(head(port), before, "the refusals commit nothing");

    // The classification link's second key (RES-207): a DRAFT-homed one is
    // OUTSIDE the class — an ordinary link the steward corrects by, its
    // owner's retraction ADMITTED.
    let working = owner_draft(port, &bare);
    let draft_classification =
        typed_link_addr(port, &bare, &working, &[working.as_str()], &[working.as_str()], T_STEWARD);
    expect_resp(&nullify(port, Some(&bare), &working, &draft_classification), "ack_addr");
    sd.shutdown();
}

/// H1 cell 4 — the NEGATIVE cell that keeps the classifier honest (PUB-6.32,
/// PUB-6.64's exclusion): the R20 edition claim is read under the ACTIVE
/// view, so its owner's `nullify` clears the state its faces read and is
/// ADMITTED — for the class address and for a descriptive subtype alike.
#[test]
fn the_edition_claim_s_owner_retraction_is_admitted() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let edition = acked_addr(&op(
        port,
        Some(&signed),
        &format!(r#"{{"op":"create_new_document","account":"{CLAIMANT_ACCOUNT}","published":true}}"#),
    ));
    let claim = typed_link_addr(port, &signed, &edition, &[edition.as_str()], &[CLAIMANT_DOC1], T_EDITION);
    let expanded =
        typed_link_addr(port, &signed, &edition, &[edition.as_str()], &[CLAIMANT_DOC1], T_EDITION_EXPANDED);
    for target in [&claim, &expanded] {
        expect_resp(&nullify(port, Some(&signed), &edition, target), "ack_addr");
    }
    // …and a BARE owner's retraction in the published edition meets the
    // publish-class gate, as any published-homed write does — the gate's
    // `nullify` row, not a class refusal.
    let bare = open_session(port, CLAIMANT_PRINCIPAL);
    let third = typed_link_addr(port, &signed, &edition, &[edition.as_str()], &[CLAIMANT_DOC1], T_EDITION);
    assert_eq!(
        verdict(&nullify(port, Some(&bare), &edition, &third)),
        "credential_refused:signed_session_required"
    );
    sd.shutdown();
}

/// H1 cell 5 — the ORDERING PINS. (a) PUB-6.9: ω on the TARGET fires ahead of
/// every occupancy test — a stranger's `nullify` of an EMPTY address in a
/// draft's link subspace, filed from a home of its own, answers `not_owner`
/// naming the target, never `bad_target`. (b) PUB-6.36 slot 4 ahead of slot
/// 5 and of occupancy: a bare owner's `nullify` of an EMPTY address in its own
/// published doc 1 answers `signed_session_required`, where the signed owner
/// reaches the store's `bad_target`. (c) PUB-6.10's byte-identity, extended
/// to the two new cells: a stranger's answers on a grant-typed, an
/// audit-class, a credential-typed and a plain target in the owner's doc 1
/// are ONE body — the same bytes, one assertion over the four.
#[test]
fn the_ordering_pins_hold_across_every_target_class() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let bare = open_session(port, CLAIMANT_PRINCIPAL);
    let (s_account, s_bare) = stranger(port, 961);
    let s_home = own_draft(port, &s_bare, &s_account);

    // (a) An EMPTY address in the OWNER's draft, from the stranger's own home.
    // Past the draft's NEXT link address (`.0.2.1`, which a retraction filed
    // there would itself occupy — M7's born-nullified case), so the address
    // is empty AND not this call's own fresh emitter.
    let draft = owner_draft(port, &bare);
    let empty_in_draft = format!("{draft}.0.2.5");
    assert_not_owner(&nullify(port, Some(&s_bare), &s_home, &empty_in_draft), &empty_in_draft);
    // …and the owner itself, naming the same empty address, reaches the
    // store's occupancy test: the order is ω, then occupancy.
    assert_eq!(verdict(&nullify(port, Some(&bare), &draft, &empty_in_draft)), "bad_target");

    // (b) An EMPTY address in the owner's PUBLISHED doc 1: the bare owner is
    // told to sign, never what occupies the address; the signed owner meets
    // the store's `bad_target`.
    let empty_in_home = format!("{CLAIMANT_DOC1}.0.2.99");
    assert_eq!(
        verdict(&nullify(port, Some(&bare), CLAIMANT_DOC1, &empty_in_home)),
        "credential_refused:signed_session_required"
    );
    assert_eq!(verdict(&nullify(port, Some(&signed), CLAIMANT_DOC1, &empty_in_home)), "bad_target");

    // (c) Four targets in the owner's doc 1, one stranger, one body.
    let (grantee, _) = stranger(port, 962);
    let grant = deposit_grant(port, &signed, CLAIMANT_DOC1, &draft, Some(&grantee));
    let rail = typed_link_addr(port, &signed, CLAIMANT_DOC1, &[grantee.as_str()], &[CLAIMANT_DOC1], T_RAIL);
    let credential = credential_link(port, &signed, 63);
    let ghost = format!("{CLAIMANT_DOC1}.0.3.6.1");
    let plain = typed_link_addr(port, &signed, CLAIMANT_DOC1, &[], &[], &ghost);
    let (_, s_signed) = signed_stranger(port, &signed, 964, 64);
    let bodies: Vec<Vec<u8>> = [&grant, &rail, &credential, &plain]
        .iter()
        .map(|target| {
            let frame = nullify_frame(CLAIMANT_DOC1, target.as_str());
            http(port, "POST", "/op", Some(&s_signed), frame.as_bytes()).1
        })
        .collect();
    assert_not_owner(&json(&bodies[3]), CLAIMANT_DOC1);
    assert!(
        bodies.iter().all(|b| *b == bodies[3]),
        "a stranger's answer is one body across every target class:\n grant:      {}\n audit:      {}\n credential: {}\n plain:      {}",
        String::from_utf8_lossy(&bodies[0]),
        String::from_utf8_lossy(&bodies[1]),
        String::from_utf8_lossy(&bodies[2]),
        String::from_utf8_lossy(&bodies[3])
    );
    // The same four from the OWNER's signed session: three tokens and one
    // ack — the plain link's retraction lands — which is what the stranger's
    // one body is masking.
    assert_eq!(verdict(&nullify(port, Some(&signed), CLAIMANT_DOC1, &grant)), "credential_refused:nullify_not_revocation");
    assert_eq!(verdict(&nullify(port, Some(&signed), CLAIMANT_DOC1, &rail)), "credential_refused:nullify_audit_view");
    assert_eq!(verdict(&nullify(port, Some(&signed), CLAIMANT_DOC1, &credential)), "credential_refused:nullify_not_retraction");
    // The credential cell is scoped on the TARGET's owner too (PUB-6.10):
    // a signed stranger filing from a home IT OWNS against the claimant's
    // credential link answers ω's `not_owner` naming the target — never the
    // shape token, which would tell it the target's class.
    let (s_account2, s_signed2) = signed_stranger(port, &signed, 965, 65);
    let s_own = own_draft(port, &s_signed2, &s_account2);
    assert_not_owner(&nullify(port, Some(&s_signed2), &s_own, &credential), &credential);
    expect_resp(&nullify(port, Some(&signed), CLAIMANT_DOC1, &plain), "ack_addr");
    sd.shutdown();
}
