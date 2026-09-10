//! THE TWO PUBLICATION READS AND THE PER-CLASS DUMP over the wire (PUB round
//! 2, lane 3.4): `doc_metadata` (PUB-8.12) and `edition_claims` (PUB-8.46)
//! answered through the read predicate, the `/dump` filter at the presented
//! token's class (§4), and the cache headers the four class-varying routes
//! carry (§5). The engine's own suites hold the class the world answers and
//! the filter's tree shape; this file holds the WIRE — the shapes, the
//! consult, the home filter, the two-world `/dump?at`, and the headers.

use crate::common;

use common::*;
use serde_json::Value;

/// The EDITION class type address (commons-seeding.md `3.14 | edition`) as a
/// client names it — the type an edition claim's link carries.
const T_EDITION: &str = "1.1.0.1.0.1.0.3.14";

/// A stranger account under node 1, delegated from the bootstrap principal,
/// with its own session. Returns `(account, session)`.
fn stranger(port: u16, id: u64) -> (String, String) {
    let boot = open_session(port, 0);
    let v = op(port, Some(&boot), r#"{"op":"next_account_prefix","parent":"1"}"#);
    let account =
        expect_resp(&v, "maybe_addr")["addr"].as_str().expect("a delegable prefix").to_string();
    let v = op(
        port,
        Some(&boot),
        &format!(r#"{{"op":"delegate","new_prefix":"{account}","new_id":{id}}}"#),
    );
    expect_resp(&v, "ack_addr");
    (account.clone(), open_session(port, id))
}

/// A private draft under the claimant's account holding `text` from ordinal 1.
fn private_draft(port: u16, owner: &str, text: &str) -> String {
    let d = acked_addr(&op(
        port,
        Some(owner),
        &format!(r#"{{"op":"create_new_document","account":"{CLAIMANT_ACCOUNT}"}}"#),
    ));
    expect_resp(
        &op(
            port,
            Some(owner),
            &format!(
                r#"{{"op":"insert","doc":"{d}","at":{{"subspace":"1","ordinal":"1"}},"values":["{text}"]}}"#
            ),
        ),
        "ack_addr",
    );
    d
}

/// A PUBLISHED edition under the claimant's account — an explicit
/// `published:true` mint from the SIGNED session (the published-mint gate).
fn published_edition(port: u16, signed: &str) -> String {
    acked_addr(&op(
        port,
        Some(signed),
        &format!(r#"{{"op":"create_new_document","account":"{CLAIMANT_ACCOUNT}","published":true}}"#),
    ))
}

/// Deposit an edition claim in `home` denoting `target`: a `make_link` with
/// address-form slots, from `token` — the SIGNED session for a published
/// home, a bare owner session for a private-draft home. Returns the claim's
/// address.
fn claim(port: u16, token: &str, home: &str, target: &str) -> String {
    acked_addr(&op(
        port,
        Some(token),
        &format!(
            r#"{{"op":"make_link","home":"{home}","from":{{"addrs":["{home}"]}},"to":{{"addrs":["{target}"]}},"ty":{{"addrs":["{T_EDITION}"]}}}}"#
        ),
    ))
}

fn edition_claims(port: u16, token: Option<&str>, target: &str) -> Value {
    op(port, token, &format!(r#"{{"op":"edition_claims","target":"{target}"}}"#))
}

fn doc_metadata(port: u16, token: Option<&str>, doc: &str) -> Value {
    op(port, token, &format!(r#"{{"op":"doc_metadata","doc":"{doc}"}}"#))
}

/// The claim addresses in an `edition_claims` answer, with each row's active
/// flag, as `(claim, active)` pairs in the order returned.
fn rows(v: &Value) -> Vec<(String, bool)> {
    expect_resp(v, "edition_claims")["claims"]
        .as_array()
        .expect("claims")
        .iter()
        .map(|c| {
            (
                c["claim"].as_str().expect("claim addr").to_string(),
                c["active"].as_bool().expect("active flag"),
            )
        })
        .collect()
}

fn assert_withheld(v: &Value, doc: &str) {
    let rej = expect_resp(v, "rejected");
    assert_eq!(rej["code"].as_str(), Some("withheld"), "{v}");
    assert_eq!(rej["disposition"].as_str(), Some("reorder"), "{v}");
    assert_eq!(rej["site"]["addr"].as_str(), Some(doc), "the withheld document: {v}");
    assert!(rej.get("detail").is_none(), "withheld carries no detail: {v}");
}

fn head(port: u16) -> u64 {
    json(&get(port, "/health").1)["log_position"].as_u64().expect("log_position")
}

/// §7 item 1 — the doc-metadata read over four reader classes. The published
/// home is readable by all; a private draft takes the doc-argument consult,
/// so the guest and a stranger are withheld and the owner and a grantee read
/// it. The owner account is CARRIED, exact.
#[test]
fn doc_metadata_serves_the_publication_state_per_class() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let (b_account, b) = stranger(port, 910);

    // The published home: every class reads its state, owner carried exact.
    for token in [Some(owner.as_str()), None, Some(b.as_str())] {
        let v = doc_metadata(port, token, CLAIMANT_DOC1);
        let meta = expect_resp(&v, "doc_metadata");
        assert_eq!(meta["doc"].as_str(), Some(CLAIMANT_DOC1), "the trunk document: {v}");
        assert_eq!(meta["published"].as_bool(), Some(true), "born published: {v}");
        assert_eq!(meta["owner"].as_str(), Some(CLAIMANT_ACCOUNT), "ω carried: {v}");
        assert!(meta.get("birth").is_some(), "the field is present (null before a member): {v}");
    }

    // A private draft: withheld to the guest and the stranger, read by the
    // owner (subtree) and — once granted — by the grantee (PUB-6.13's twin on
    // the read's own argument).
    let draft = private_draft(port, &owner, "s");
    assert_eq!(
        expect_resp(&doc_metadata(port, Some(&owner), &draft), "doc_metadata")["published"].as_bool(),
        Some(false),
        "the owner reads its draft's state"
    );
    assert_withheld(&doc_metadata(port, None, &draft), &draft);
    assert_withheld(&doc_metadata(port, Some(&b), &draft), &draft);
    deposit_grant(port, &signed, CLAIMANT_DOC1, &draft, Some(&b_account));
    let v = doc_metadata(port, Some(&b), &draft);
    assert_eq!(
        expect_resp(&v, "doc_metadata")["owner"].as_str(),
        Some(CLAIMANT_ACCOUNT),
        "the grantee now reads it, owner carried: {v}"
    );

    // An UNREGISTERED address is fail-open at the consult and takes the
    // store's own registration code, never `withheld`.
    let v = doc_metadata(port, Some(&owner), "1.0.1.0.9.0.1.7");
    assert_eq!(
        expect_resp(&v, "rejected")["code"].as_str(),
        Some("doc_not_registered"),
        "an unregistered document answers its own code: {v}"
    );
    sd.shutdown();
}

/// §7 item 1 (the version-member row) — a version member answers its
/// DOCUMENT's state (PUB-2.15): the `doc` field is the trunk, and the birth
/// version with its base extent is what PUB-3.19's edition test images over.
#[test]
fn doc_metadata_projects_a_version_member_to_its_document() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());

    // Before any member: the birth fields are null.
    let v = doc_metadata(port, Some(&signed), CLAIMANT_DOC1);
    let meta = expect_resp(&v, "doc_metadata");
    assert!(meta["birth"].is_null(), "no chain member yet: {v}");
    assert!(meta["birth_extent"].is_null(), "…and no extent: {v}");

    // The published home has one content element (the ceremony atom), so its
    // birth version snapshots an extent of 1.
    let member = acked_addr(&op(
        port,
        Some(&signed),
        &format!(r#"{{"op":"version","d_src":"{CLAIMANT_DOC1}"}}"#),
    ));
    assert_eq!(member, "1.0.1.0.1.1", "the birth version is the chain's first member D.1");

    // doc_metadata on the MEMBER: the doc field is the trunk, and the birth
    // version and its base extent are named.
    let v = doc_metadata(port, Some(&signed), &member);
    let meta = expect_resp(&v, "doc_metadata");
    assert_eq!(meta["doc"].as_str(), Some(CLAIMANT_DOC1), "the member projects to its document: {v}");
    assert_eq!(meta["published"].as_bool(), Some(true), "the document's state: {v}");
    assert_eq!(meta["birth"].as_str(), Some(member.as_str()), "the birth version: {v}");
    assert_eq!(meta["birth_extent"].as_str(), Some("1"), "the ceremony atom's one element: {v}");

    // The trunk now reports the same birth, so a client images one edition's
    // content over `birth` for the edition test whichever address it holds.
    let v = doc_metadata(port, Some(&signed), CLAIMANT_DOC1);
    assert_eq!(
        expect_resp(&v, "doc_metadata")["birth"].as_str(),
        Some(member.as_str()),
        "the trunk and the member name one birth version: {v}"
    );
    sd.shutdown();
}

/// §7 item 2 — the audit-view edition-claim lookup: two editions claim the
/// published home, one claim is then RETRACTED, and the audit view lists BOTH
/// with the retraction stated where an active-view result set (`find_links_ftt`)
/// returns one.
#[test]
fn edition_claims_lists_admitted_claims_retracted_or_not() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let owner = open_session(port, CLAIMANT_PRINCIPAL);

    let e1 = published_edition(port, &signed);
    let e2 = published_edition(port, &signed);
    let c1 = claim(port, &signed, &e1, CLAIMANT_DOC1);
    let c2 = claim(port, &signed, &e2, CLAIMANT_DOC1);
    // Retract c2: the home nullifies its own claim.
    expect_resp(
        &op(port, Some(&signed), &format!(r#"{{"op":"nullify","home":"{e2}","target":"{c2}"}}"#)),
        "ack_addr",
    );

    // The audit view lists both — the retraction STATED, not hidden.
    let mut got = rows(&edition_claims(port, Some(&owner), CLAIMANT_DOC1));
    got.sort();
    let mut want = vec![(c1.clone(), true), (c2.clone(), false)];
    want.sort();
    assert_eq!(got, want, "both claims, the retraction stated");

    // An ACTIVE-view result set returns the one live claim: find_links_ftt of
    // the edition class over its subtree span (active view by default).
    let ty_span = format!(
        r#"[{{"start":"{T_EDITION}","width":"0.0.0.0.0.0.0.0.1"}}]"#
    );
    let v = op(
        port,
        Some(&owner),
        &format!(r#"{{"op":"find_links_ftt","q":{{"home":"any","from":"any","to":"any","ty":{ty_span}}}}}"#),
    );
    let active: Vec<String> = expect_resp(&v, "addrs")["addrs"]
        .as_array()
        .expect("addrs")
        .iter()
        .map(|a| a.as_str().expect("addr").to_string())
        .collect();
    assert!(active.contains(&c1), "the live claim is in the active view: {v}");
    assert!(!active.contains(&c2), "the retracted claim is not: {v}");
    sd.shutdown();
}

/// §7 item 2 (the home filter, PUB-6.13) — a claim homed in a DRAFT edition
/// is returned to a reader whose class reads that home and dropped for a
/// stranger; the target itself (the published home) is readable by both, so
/// the difference is the HOME rule, not the target consult.
#[test]
fn edition_claims_filters_rows_by_readable_home() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let (_b_account, b) = stranger(port, 911);

    // A claim from a PUBLISHED edition (readable by all) and one from a DRAFT
    // edition (readable only within the owner's subtree), both denoting the
    // published home.
    let e_pub = published_edition(port, &signed);
    let c_pub = claim(port, &signed, &e_pub, CLAIMANT_DOC1);
    let e_draft = private_draft(port, &owner, "d"); // a private draft, its own home
    let c_draft = claim(port, &owner, &e_draft, CLAIMANT_DOC1);

    // The owner reads both editions, so both claims are returned.
    let owner_claims: Vec<String> =
        rows(&edition_claims(port, Some(&owner), CLAIMANT_DOC1)).into_iter().map(|(c, _)| c).collect();
    assert!(owner_claims.contains(&c_pub), "the owner sees the published edition's claim");
    assert!(owner_claims.contains(&c_draft), "…and its draft edition's claim");

    // The stranger reads the target (published) but NOT the draft edition, so
    // its claim drops while the published edition's stays (PUB-6.13).
    let b_claims: Vec<String> =
        rows(&edition_claims(port, Some(&b), CLAIMANT_DOC1)).into_iter().map(|(c, _)| c).collect();
    assert!(b_claims.contains(&c_pub), "the stranger sees the published edition's claim");
    assert!(!b_claims.contains(&c_draft), "a draft edition's claim is invisible to the stranger");

    // An unreadable TARGET is the consult's own withheld (the H1 row), where
    // the home filter above is the H4/result-set row: a private draft target
    // withholds from the guest.
    let secret_target = private_draft(port, &owner, "t");
    assert_withheld(&edition_claims(port, None, &secret_target), &secret_target);
    sd.shutdown();
}

/// §7 item 5 — the four class-varying routes carry `Cache-Control: no-store`
/// and `Vary: Skepd-Session`; `/health` (class-invariant) carries neither.
#[test]
fn the_four_class_varying_routes_carry_the_cache_headers() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let at = head(port);

    let carries = |headers: &[(String, String)], route: &str| {
        assert_eq!(
            header(headers, "Cache-Control"),
            Some("no-store"),
            "{route} must forbid caching a class-varying answer"
        );
        assert_eq!(
            header(headers, "Vary"),
            Some("Skepd-Session"),
            "{route} must vary on the session token"
        );
    };

    let (_s, h, _b) =
        http_full(port, "POST", "/op", Some(&owner), br#"{"op":"doc_metadata","doc":"1.0.1.0.1"}"#);
    carries(&h, "/op");
    let envelope = format!(r#"{{"at":{at},"frame":{{"op":"doc_metadata","doc":"{CLAIMANT_DOC1}"}}}}"#);
    let (_s, h, _b) = http_full(port, "POST", "/op-at", Some(&owner), envelope.as_bytes());
    carries(&h, "/op-at");
    let (_s, h, _b) = http_full(port, "GET", "/changes?since=0", Some(&owner), b"");
    carries(&h, "/changes");
    #[cfg(feature = "observe")]
    {
        let (_s, h, _b) = http_full(port, "GET", "/dump", Some(&owner), b"");
        carries(&h, "/dump");
    }

    // /health is class-invariant: it carries neither header.
    let (_s, h, _b) = http_full(port, "GET", "/health", None, b"");
    assert_eq!(header(&h, "Cache-Control"), None, "/health carries no Cache-Control");
    assert_eq!(header(&h, "Vary"), None, "/health carries no Vary");
    sd.shutdown();
}

/// §7 item 3 (H4) — the wire `/dump` equals the post-filter of the
/// harness-only walk byte for byte, the guest's publication slice is EMPTY,
/// and an owner's lists its drafts.
#[cfg(feature = "observe")]
#[test]
fn dump_is_per_class_over_the_wire() {
    use skep_namespace::PrincipalId;

    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let draft = private_draft(port, &owner, "z");

    // The wire body equals the daemon's own per-class dump, byte for byte.
    let (st, body) = http(port, "GET", "/dump", Some(&owner), b"");
    assert_eq!(st, 200);
    let expected = sd.daemon().dump_visible_to(Some(PrincipalId(CLAIMANT_PRINCIPAL)));
    assert_eq!(body, expected.as_bytes(), "the wire dump is the post-filter of the walk");

    let owner_text = String::from_utf8(body).expect("utf-8 dump");
    assert!(owner_text.starts_with("skep-world-dump v5"), "the v5 banner: {owner_text:.32}");
    assert!(
        owner_text.contains(&format!("{:?}", draft)),
        "the owner's dump lists its draft in the publication slice"
    );

    // The guest's dump: the publication slice is EMPTY and the draft's own
    // address is absent from it (the identity section may still name it).
    let guest = String::from_utf8(get(port, "/dump").1).expect("utf-8 dump");
    assert!(guest.contains("\"publication\": []"), "the guest's publication slice is empty:\n{guest}");
    assert_eq!(
        String::from_utf8(get(port, "/dump").1).expect("utf-8"),
        guest,
        "two guest dumps of one world are byte-equal"
    );
    assert_ne!(guest, owner_text, "the guest and the owner read different worlds");
    sd.shutdown();
}

/// §7 item 4 — the two-world `/dump?at=N`: a grant committed AFTER N makes a
/// draft readable at `/dump?at=N` (the HEAD predicate), while a stranger
/// without the grant does not see it, so the STATE is the position's and the
/// PREDICATE is the head's.
#[cfg(feature = "observe")]
#[test]
fn dump_at_filters_the_position_at_the_head_class() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let (b_account, b) = stranger(port, 912);
    let (_c_account, c) = stranger(port, 913);

    // A draft, then the as-of position N — the draft exists at N.
    let draft = private_draft(port, &owner, "q");
    let n = head(port);
    let dotted = format!("{:?}", draft);

    // A grant to B lands AFTER N.
    deposit_grant(port, &signed, CLAIMANT_DOC1, &draft, Some(&b_account));

    // B's /dump?at=N: the draft is in the as-of-N publication slice AND
    // readable to B at the head (the grant), so its address appears.
    let b_at_n =
        String::from_utf8(http(port, "GET", &format!("/dump?at={n}"), Some(&b), b"").1).expect("utf-8");
    assert!(b_at_n.contains(&dotted), "a grant after N opens the draft at /dump?at=N:\n{b_at_n}");

    // C, with no grant, does not read the draft at the head, so it is filtered
    // out of C's /dump?at=N — the predicate is the head's, per class.
    let c_at_n =
        String::from_utf8(http(port, "GET", &format!("/dump?at={n}"), Some(&c), b"").1).expect("utf-8");
    assert!(!c_at_n.contains(&dotted), "an ungranted stranger does not see the draft:\n{c_at_n}");

    // The guest never does, and `at` = head is byte-equal to plain /dump.
    let guest_at_head =
        String::from_utf8(http(port, "GET", &format!("/dump?at={}", head(port)), None, b"").1)
            .expect("utf-8");
    assert_eq!(
        guest_at_head,
        String::from_utf8(get(port, "/dump").1).expect("utf-8"),
        "at=head equals plain /dump at one class"
    );
    sd.shutdown();
}
