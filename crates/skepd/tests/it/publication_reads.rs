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

/// The content extent `doc` answers — `retrieve_doc_v_span_set`'s content
/// span width, `0` when the set carries none.
fn content_extent(port: u16, token: &str, doc: &str) -> u64 {
    next_content_ordinal(port, Some(token), doc) - 1
}

/// The `birth_extent` a `doc_metadata` answer carries, as the wire spells it.
fn birth_extent(v: &Value) -> Option<&str> {
    expect_resp(v, "doc_metadata")["birth_extent"].as_str()
}

/// PUB-3.19 as RES-276 reads it, under the owner's D2 (the pack's member-state
/// row 1 — the ONE-MEMBER EDITION AS HEAD): `birth_extent` is the content the
/// home was BORN with, FROZEN at the mint. A home born with N positions, then
/// a declared deposit into `D.1` while `D.1` is still the head: the head's
/// arrangement grows (PUB-2.66) and `doc_metadata` still answers
/// `birth_extent == N`, on the trunk and on the member, on `/op` and — as of a
/// position before the deposit and one after it — on `/op-at`, the same value.
#[test]
fn birth_extent_stays_at_the_birth_content_when_the_head_takes_a_deposit() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());

    // The home holds the ceremony atom, so its birth version is born with 1.
    let member = acked_addr(&op(
        port,
        Some(&signed),
        &format!(r#"{{"op":"version","d_src":"{CLAIMANT_DOC1}"}}"#),
    ));
    let born_at = head(port);
    assert_eq!(birth_extent(&doc_metadata(port, Some(&signed), &member)), Some("1"));
    assert_eq!(content_extent(port, &signed, &member), 1);

    // Two declared deposits into the bare address while `D.1` is the head:
    // each lands in `D.1` (PUB-2.66) and neither joins the birth content.
    for (ordinal, grown) in [(2u64, 2u64), (3, 3)] {
        expect_resp(
            &op(
                port,
                Some(&signed),
                &format!(
                    r#"{{"op":"insert","doc":"{CLAIMANT_DOC1}","at":{{"subspace":"1","ordinal":"{ordinal}"}},"values":["z"],"deposit":true}}"#
                ),
            ),
            "ack_addr",
        );
        assert_eq!(content_extent(port, &signed, &member), grown, "the head's arrangement grew");
        for named in [CLAIMANT_DOC1, member.as_str()] {
            let v = doc_metadata(port, Some(&signed), named);
            assert_eq!(birth_extent(&v), Some("1"), "the birth content did not, asked of {named}: {v}");
        }
    }

    // `/op-at`: as of the mint (before either deposit) and as of the head
    // (after both), the same value — a historical world folds the same memo.
    let after = head(port);
    assert!(after > born_at, "the deposits committed");
    let frame = format!(r#"{{"op":"doc_metadata","doc":"{CLAIMANT_DOC1}"}}"#);
    for at in [born_at, after] {
        let v = op_at_ok(port, Some(&signed), at, &frame);
        assert_eq!(birth_extent(&v), Some("1"), "as of {at}: {v}");
    }
    sd.shutdown();
}

/// T5(b) (iii)'s daemon half and T6(b)'s VECTOR (PUB-3.19, PUB-3.106; RES-276,
/// RES-284, RES-286's claimed half): a ONE-MEMBER edition whose claim was
/// written over its complete content (PUB-3.10), which then takes a declared
/// deposit. The claim read images the edition over `birth` / `birth_extent`:
/// the image is ADDRESS FOR ADDRESS what it was at the mint — and so byte for
/// byte, a content address naming its bytes for good — and still EQUALS the
/// claim's FROM, so the edition stays in the selection domain and the fill's
/// edition side does not fire MISMATCH — while the image over the member's
/// WHOLE arrangement is one run longer, which is the extent a read that
/// compared the live count would have used.
#[test]
fn a_deposited_one_member_edition_still_images_its_birth_content_under_the_claim_read() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let owner = open_session(port, CLAIMANT_PRINCIPAL);

    // The edition E, born by ONE shot over a staging draft's two positions
    // (PUB-3.11): its birth version E.1 holds exactly the confirmed runs.
    let staged = private_draft(port, &owner, "ab");
    let edition = published_edition(port, &signed);
    let birth = acked_addr(&op(
        port,
        Some(&signed),
        &format!(
            r#"{{"op":"publish","doc":"{edition}","draft":"{staged}","runs":[{{"origin":"{staged}","i_start":"{staged}.0.1.1","width":"2"}}]}}"#
        ),
    ));
    assert_eq!(birth, format!("{edition}.1"));
    // The I-addresses positions `1 ..= extent` of the birth version image to,
    // one per position — the form the claim's FROM is compared in.
    let image_over = |extent: &str| -> Vec<String> {
        let v = op(
            port,
            Some(&signed),
            &format!(
                r#"{{"op":"image","d":"{birth}","region":[{{"start":"1.1","width":"0.{extent}"}}]}}"#
            ),
        );
        expect_resp(&v, "runs")["runs"]
            .as_array()
            .expect("runs")
            .iter()
            .flat_map(|run| {
                addresses(
                    run["i_start"].as_str().expect("i_start"),
                    run["width"].as_str().expect("width"),
                )
            })
            .collect()
    };
    let meta = doc_metadata(port, Some(&signed), &edition);
    assert_eq!(expect_resp(&meta, "doc_metadata")["birth"].as_str(), Some(birth.as_str()));
    assert_eq!(birth_extent(&meta), Some("2"));
    // The edition's claim, written over its COMPLETE content at the mint
    // (PUB-3.10): its FROM names exactly the addresses the birth images to,
    // the draft's text re-minted under the edition's own I-space.
    let born_with = image_over("2");
    assert_eq!(born_with, vec![format!("{edition}.0.1.1"), format!("{edition}.0.1.2")]);
    let claim_addr = acked_addr(&op(
        port,
        Some(&signed),
        &format!(
            r#"{{"op":"make_link","home":"{edition}","from":{{"addrs":["{}","{}"]}},"to":{{"addrs":["{CLAIMANT_DOC1}"]}},"ty":{{"addrs":["{T_EDITION}"]}}}}"#,
            born_with[0], born_with[1]
        ),
    ));
    // The claim's FROM as deposited, read back off the link: one address per
    // position its spans cover.
    let claim_from = || -> Vec<String> {
        let v = op(port, Some(&signed), &format!(r#"{{"op":"read_link","a":"{claim_addr}"}}"#));
        expect_resp(&v, "link_value")["link"]["slots"][0]
            .as_array()
            .expect("the FROM slot")
            .iter()
            .flat_map(|span| {
                let width = span["width"].as_str().expect("width");
                addresses(
                    span["start"].as_str().expect("start"),
                    width.rsplit('.').next().expect("a span width ends in its count"),
                )
            })
            .collect()
    };
    assert_eq!(claim_from(), born_with, "at the mint FROM and extent are equal");

    // A declared deposit into the edition while its birth version is the head.
    expect_resp(
        &op(
            port,
            Some(&signed),
            &format!(
                r#"{{"op":"insert","doc":"{edition}","at":{{"subspace":"1","ordinal":"3"}},"values":["z"],"deposit":true}}"#
            ),
        ),
        "ack_addr",
    );
    assert_eq!(content_extent(port, &signed, &birth), 3, "the head's arrangement grew");

    // The claim read, run as a client runs it: the class lookup names the
    // claim and its home, `doc_metadata` of the home names `birth` and
    // `birth_extent`, and the image over that extent is compared with the
    // claim's FROM. `birth_extent` is unmoved, the image is what it was at the
    // mint, and FROM still EQUALS it — the selection domain is not emptied
    // (T5(b) (iii)) and the byte check compares the birth content (T6(b)'s
    // vector).
    let listed = edition_claims(port, Some(&signed), CLAIMANT_DOC1);
    assert_eq!(rows(&listed), vec![(claim_addr.clone(), true)], "the claim stands: {listed}");
    assert_eq!(listed["claims"][0]["home"].as_str(), Some(edition.as_str()));
    let meta = doc_metadata(port, Some(&signed), &edition);
    let extent = birth_extent(&meta).expect("a born edition carries its extent").to_string();
    assert_eq!(extent, "2", "frozen at the mint: {meta}");
    assert_eq!(image_over(&extent), born_with, "the birth content, address for address");
    assert_eq!(claim_from(), image_over(&extent), "and the claim still matches it");
    // The extent a live-count read would have compared is one position wider:
    // its image holds the deposit, and EQUALS against the claim's FROM fails —
    // the permanent MISMATCH, and the emptied domain, RES-276 closed.
    let whole = image_over("3");
    assert_eq!(whole.len(), 3, "the whole arrangement holds the deposit too");
    assert_eq!(whole[..2], born_with[..], "the birth content is its LEADING runs");
    assert_ne!(claim_from(), whole);
    sd.shutdown();
}

/// The `count` I-addresses from `start` on, one per position: `start` with its
/// last component advanced. How a run (`i_start`, `width`) and a link span
/// (`start`, the count its `width` ends in) are brought to one form.
fn addresses(start: &str, count: &str) -> Vec<String> {
    let (prefix, first) = start.rsplit_once('.').expect("an element address has an ordinal");
    let first: u64 = first.parse().expect("a decimal ordinal");
    let count: u64 = count.parse().expect("a decimal count");
    (first..first + count).map(|k| format!("{prefix}.{k}")).collect()
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
