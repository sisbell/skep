//! THE PUBLICATION READS AND THE PER-CLASS DUMP over the wire (PUB round
//! 2, lane 3.4): `doc_metadata` (PUB-8.12) and `edition_claims` (PUB-8.46)
//! answered through the read predicate, the `/dump` filter at the presented
//! token's class (§4), and the cache headers the four class-varying routes
//! carry (§5). The engine's own suites hold the class the world answers and
//! the filter's tree shape; this file holds the WIRE — the shapes, the
//! consult, the home filter, the two-world `/dump?at`, and the headers.
//! And the price read, `publish_cost`: its answer's members, the consult
//! over the drafts it names and the originals' homes, the guest's answer,
//! the claim a `supersede` entry is priced at, and that it writes nothing.

use crate::common;

use common::*;
use serde_json::{json, Value};

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
    let v = doc_metadata(port, Some(&owner), "1.0.1.0.71.0.1.7");
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

/// THE FORK SOURCE (the fork-source design record's arm A, its ten decisions
/// owner-ruled 2026-10-17): `doc_metadata`'s `source` is the member or bare
/// document the address named was born sharing — the `version` snapshot's
/// own source, kept in the board's state — answered OF THE ADDRESS NAMED to
/// whoever may read it. An owned version answers the surface its `version`
/// took (the bare document for `D.1`, the head member for `D.2`); a
/// cross-owner fork answers the member it was taken from; the trunk, a
/// `fork`-minted document and a shot member answer `null`; `/op-at` at the
/// mint's position and after answer the same, and before it the fork is no
/// document; and a reader who may read the fork but NOT its source still
/// gets the address (decision 2): the forker, its share of the source since
/// revoked, reads its own fork's source and is withheld the source itself.
#[test]
fn doc_metadata_serves_the_source_a_fork_was_born_sharing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let (b_account, b) = stranger(port, 914);
    // The stranger's HOME first: a mint into an account without one — the
    // fork's included — is refused `mint_home_first`.
    let b_home = acked_addr(&op(
        port,
        Some(&b),
        &format!(r#"{{"op":"create_new_document","account":"{b_account}"}}"#),
    ));
    assert_eq!(b_home, format!("{b_account}.0.1"));
    let source_of = |v: &Value| -> Value { expect_resp(v, "doc_metadata")["source"].clone() };
    let version = |token: &str, d_src: &str, flag: &str| -> String {
        acked_addr(&op(port, Some(token), &format!(r#"{{"op":"version","d_src":"{d_src}"{flag}}}"#)))
    };

    // The trunk: minted by no `version`, so the member is present and null.
    let v = doc_metadata(port, Some(&signed), CLAIMANT_DOC1);
    assert!(source_of(&v).is_null(), "the trunk answers null: {v}");

    // An OWNED version of the memberless home is born sharing the bare
    // document — what its snapshot took; a second one, the chain having a
    // head, is born sharing that member. Each keeps its own for good, and
    // the trunk answers null still, never a member's.
    let d1 = version(&signed, CLAIMANT_DOC1, "");
    assert_eq!(d1, "1.0.1.0.1.1");
    assert_eq!(source_of(&doc_metadata(port, Some(&signed), &d1)), json!(CLAIMANT_DOC1));
    let d2 = version(&signed, CLAIMANT_DOC1, "");
    assert_eq!(d2, "1.0.1.0.1.2");
    assert_eq!(
        source_of(&doc_metadata(port, Some(&signed), &d2)),
        json!(d1),
        "an owned version answers the member it was minted against"
    );
    assert_eq!(source_of(&doc_metadata(port, Some(&signed), &d1)), json!(CLAIMANT_DOC1), "noted once");
    let v = doc_metadata(port, Some(&signed), CLAIMANT_DOC1);
    assert!(source_of(&v).is_null(), "the trunk still answers null: {v}");

    // A `fork` mints empty and shares nothing; a shot member is minted off
    // no source: each null.
    let forked = acked_addr(&op(port, Some(&owner), r#"{"op":"fork"}"#));
    let v = doc_metadata(port, Some(&owner), &forked);
    assert!(source_of(&v).is_null(), "a `fork`-minted document: {v}");
    let staged = private_draft(port, &owner, "ab");
    let edition = published_edition(port, &signed);
    let e1 = acked_addr(&op(
        port,
        Some(&signed),
        &format!(
            r#"{{"op":"publish","doc":"{edition}","draft":"{staged}","runs":[{{"origin":"{staged}","i_start":"{staged}.0.1.1","width":"2"}}]}}"#
        ),
    ));
    assert_eq!(e1, format!("{edition}.1"));
    let v = doc_metadata(port, Some(&signed), &e1);
    assert_eq!(expect_resp(&v, "doc_metadata")["placed"].as_str(), Some("2"), "a shot member: {v}");
    assert!(source_of(&v).is_null(), "…minted off no source: {v}");

    // A CROSS-OWNER fork of the published home by the stranger — a private
    // document of its own account — is born sharing the chain's head `D.2`,
    // and says so to its reader: `doc` the fork itself, `source` the member.
    let before = head(port);
    let f = version(&b, CLAIMANT_DOC1, r#","published":false"#);
    assert!(f.starts_with(&format!("{b_account}.0.")), "a fresh document of the forker's: {f}");
    let born_at = head(port);
    let v = doc_metadata(port, Some(&b), &f);
    let meta = expect_resp(&v, "doc_metadata");
    assert_eq!(meta["doc"].as_str(), Some(f.as_str()), "the fork is its own trunk: {v}");
    assert_eq!(meta["owner"].as_str(), Some(b_account.as_str()), "{v}");
    assert_eq!(meta["source"], json!(d2), "born sharing the head member at the mint: {v}");
    assert!(meta["birth"].is_null() && meta["placed"].is_null(), "no member, no shot: {v}");
    // The same at every position from the mint on — the trunk's chain
    // moving afterwards moves nothing — and before it, no document.
    let d3 = version(&signed, CLAIMANT_DOC1, "");
    assert_eq!(d3, "1.0.1.0.1.3");
    let after = head(port);
    assert!(after > born_at, "the third version committed");
    let frame = format!(r#"{{"op":"doc_metadata","doc":"{f}"}}"#);
    for at in [born_at, after] {
        let v = op_at_ok(port, Some(&b), at, &frame);
        assert_eq!(source_of(&v), json!(d2), "as of {at}: {v}");
    }
    let (st, v) = op_at(port, Some(&b), before, &frame);
    assert_eq!(st, 200, "{v}");
    assert_eq!(
        expect_resp(&v, "rejected")["code"].as_str(),
        Some("doc_not_registered"),
        "before the mint the fork is no document: {v}"
    );
    assert_eq!(source_of(&doc_metadata(port, Some(&b), &f)), json!(d2), "live, the trunk moved on");
    // The fork's OWN gate decides who reads it: the guest is withheld the
    // private fork, source and all.
    assert_withheld(&doc_metadata(port, None, &f), &f);

    // DECISION 2 — served to every reader of the fork, ungated by the
    // source's readability. A private draft of the claimant's, shared with
    // the stranger, forked by the stranger — a private source has no member,
    // so the source is the bare draft — and the share then REVOKED: the
    // forker is withheld the source and still reads its own fork's source.
    let secret = private_draft(port, &owner, "s");
    let grant = deposit_grant(port, &signed, CLAIMANT_DOC1, &secret, Some(&b_account));
    let f2 = version(&b, &secret, "");
    assert_eq!(source_of(&doc_metadata(port, Some(&b), &f2)), json!(secret), "the bare draft");
    revoke_grant(port, &signed, &grant);
    assert_withheld(&doc_metadata(port, Some(&b), &secret), &secret);
    let v = doc_metadata(port, Some(&b), &f2);
    assert_eq!(source_of(&v), json!(secret), "the fact is the fork's own, kept past the revoke: {v}");
    sd.shutdown();
}

/// THE STAGED DRAFT's SOURCE (the staging act, B3-S10): `source` is widened
/// from a `version`'s snapshot to a `stage`'s copy — a draft staged off a
/// member answers the member, one staged off the memberless home the home,
/// an alternative staged off a draft that draft — one hop, kept past the
/// source's own moves, answered to whoever may read the draft; and beside it
/// the draft's `base` and `base_copied`, which a `fork`-minted document, a
/// shot member and a `version`'s fork answer `null`.
#[test]
fn doc_metadata_serves_the_source_a_staged_draft_was_copied_from() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let read = |token: &str, doc: &str| -> (Value, Value, Value) {
        let v = doc_metadata(port, Some(token), doc);
        let m = expect_resp(&v, "doc_metadata");
        (m["source"].clone(), m["base"].clone(), m["base_copied"].clone())
    };
    // Off the memberless home: the home, its atom counted.
    let of_home = stage_of(port, &owner, CLAIMANT_DOC1);
    let atoms = content_extent(port, &owner, CLAIMANT_DOC1).to_string();
    assert_eq!(read(&owner, &of_home), (json!(CLAIMANT_DOC1), json!(CLAIMANT_DOC1), json!(atoms)));
    // Off a member: the member.
    let d1 = acked_addr(&op(port, Some(&signed), &format!(r#"{{"op":"version","d_src":"{CLAIMANT_DOC1}"}}"#)));
    let of_member = stage_of(port, &owner, &d1);
    assert_eq!(read(&owner, &of_member), (json!(d1), json!(d1), json!(atoms)));
    // Off the bare home once it has a member: its head, as a version takes it.
    let of_bare = stage_of(port, &owner, CLAIMANT_DOC1);
    assert_eq!(read(&owner, &of_bare), (json!(d1), json!(d1), json!(atoms)), "the head, pinned at the stage");
    // An alternative: the source draft, the base inherited.
    let of_draft = stage_of(port, &owner, &of_member);
    assert_eq!(read(&owner, &of_draft), (json!(of_member), json!(d1), json!(atoms)));
    // The others answer no base: a `fork`-minted document, the member, the
    // trunk.
    let forked = acked_addr(&op(port, Some(&owner), r#"{"op":"fork"}"#));
    assert_eq!(read(&owner, &forked), (Value::Null, Value::Null, Value::Null));
    assert_eq!(read(&signed, &d1), (json!(CLAIMANT_DOC1), Value::Null, Value::Null));
    assert_eq!(read(&signed, CLAIMANT_DOC1), (Value::Null, Value::Null, Value::Null));
    // The guest is withheld the private draft, base and all.
    assert_withheld(&doc_metadata(port, None, &of_member), &of_member);
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
    // The byte is prose — PUB-2.60's residue, the very atom RES-276 is about
    // — declared under a MEMBER type, ENROLL's (PUB-2.11, PUB-2.64).
    for (ordinal, grown) in [(2u64, 2u64), (3, 3)] {
        expect_resp(
            &op(
                port,
                Some(&signed),
                &format!(
                    r#"{{"op":"insert","doc":"{CLAIMANT_DOC1}","at":{{"subspace":"1","ordinal":"{ordinal}"}},"values":["z"],"deposit":"{T_ENROLL}"}}"#
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

    // A declared deposit into the edition while its birth version is the head
    // — prose under a MEMBER type, ENROLL's, as above.
    expect_resp(
        &op(
            port,
            Some(&signed),
            &format!(
                r#"{{"op":"insert","doc":"{edition}","at":{{"subspace":"1","ordinal":"3"}},"values":["z"],"deposit":"{T_ENROLL}"}}"#
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
/// and `Vary: Skepd-Session`; `/health` and `/chain` (class-invariant) carry
/// neither.
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
    // /chain is class-invariant too (wire.md §Reading history), presented
    // WITH a token, so the negative is about the route and not a missing one.
    let (s, h, b) = http_full(port, "GET", &format!("/chain?at={at}"), Some(&owner), b"");
    assert_eq!(s, 200, "/chain answers at the head: {}", String::from_utf8_lossy(&b));
    assert_eq!(header(&h, "Cache-Control"), None, "/chain carries no Cache-Control");
    assert_eq!(header(&h, "Vary"), None, "/chain carries no Vary");
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

// ── THE PRICE READ ───────────────────────────────────────────────────────

/// A `publish_cost` of `draft`'s first `width` positions into `doc`, the
/// run's place its first position, with `extra`'s members beside them.
fn publish_cost(doc: &str, draft: &str, width: u64, extra: Value) -> String {
    let mut frame = json!({
        "op": "publish_cost",
        "doc": doc,
        "draft": draft,
        "runs": [{"origin": draft, "i_start": format!("{draft}.0.1.1"), "width": width.to_string()}],
        "places": [{"subspace": "1", "ordinal": "1"}],
    });
    for (k, v) in extra.as_object().expect("an object of members") {
        frame[k] = v.clone();
    }
    frame.to_string()
}

/// The feed's entries past `since`, as `token`'s class.
fn changes_since(port: u16, token: &str, since: u64) -> Vec<Value> {
    let (st, body) = http(port, "GET", &format!("/changes?since={since}"), Some(token), b"");
    assert_eq!(st, 200, "/changes: {}", String::from_utf8_lossy(&body));
    json(&body)["changes"].as_array().expect("changes").clone()
}

/// THE PRICE READ's ANSWER. A publication of a draft's three bytes with
/// their kept place answers `publish_cost`: eleven members and the tag, each
/// figure a JSON integer — the claimant's one link-holding home, its home
/// page, where the claim ceremony left its credential links; no entry; the
/// draft's one run and its one placed piece; one re-inserted run; the
/// staged bytes from the table; the draft's three typed bytes as the one
/// unit the commit would stage them as — beside the two budgets the refusal
/// ahead of the lock holds the reads and the bytes to and the two the store
/// holds the re-insert to, M5's own, read at the head.
/// It moves no
/// position and leaves no row in the feed. An `id` rides as on any frame;
/// an `attest` is an unknown field; and a frame the codec refuses as a
/// `publish` is refused the same.
#[test]
fn publish_cost_answers_the_six_figures_and_the_four_budgets_and_writes_nothing() {
    use skep_links::{
        stored_tumbler_bytes, ReadPrice, CORRESPONDENCE_RECORD_BYTES, KEPT_PLACE_BYTES, PLACED_RUN_BYTES, REINSERTED_UNIT_BYTES, REWINDOWED_DRAFT_BYTES, SHOT_BYTES,
    };
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let bare = open_session(port, CLAIMANT_PRINCIPAL);
    let e = published_edition(port, &signed);
    let d = private_draft(port, &bare, "abc");
    let before = head(port);
    let v = op(port, Some(&bare), &publish_cost(&e, &d, 3, json!({})));
    let cost = expect_resp(&v, "publish_cost");
    let keys: Vec<&str> = cost.as_object().expect("an object").keys().map(String::as_str).collect();
    assert_eq!(
        keys,
        ["as_of", "byte_budget", "entries", "fence", "homes", "position_budget", "read_budget", "resp", "rewindow", "staged_bytes", "unit_budget", "units"],
        "{v}"
    );
    // The draft's address rides the placing record's slot and the
    // re-window's one record; both drafts of the claimant lie at one depth.
    let draft_addr = stored_tumbler_bytes(&skep_core::codec::wire_address(&d).expect("an address").tumbler().clone());
    let staged = SHOT_BYTES + draft_addr + (PLACED_RUN_BYTES + CORRESPONDENCE_RECORD_BYTES) + (REINSERTED_UNIT_BYTES + 3) + (REWINDOWED_DRAFT_BYTES + draft_addr) + KEPT_PLACE_BYTES;
    assert_eq!(
        *cost,
        json!({
            "resp": "publish_cost",
            "homes": 1,
            "entries": 0,
            "rewindow": 1 + 1,
            "fence": 1,
            "staged_bytes": staged,
            "units": 1,
            "read_budget": ReadPrice::BUDGET,
            "byte_budget": ReadPrice::BYTE_BUDGET,
            "unit_budget": skep_arrangement::MAX_REINSERTED_UNITS,
            "position_budget": skep_arrangement::MAX_REINSERTED_VALUES,
            "as_of": before,
        }),
        "the home page; the draft's one run and its one piece; one fence stab; the table's bytes; the three typed bytes one unit; the store's own two budgets"
    );
    assert_eq!((cost["unit_budget"].as_u64(), cost["position_budget"].as_u64()), (Some(1 << 17), Some(1 << 20)), "the two numbers, as the wire states them");
    assert_eq!(head(port), before, "a read moves no position");
    assert!(changes_since(port, &bare, before).is_empty(), "and leaves no row in the feed");
    // An `id` rides as on any frame, and the answer is the same.
    let keyed = op(port, Some(&bare), &publish_cost(&e, &d, 3, json!({"id": "price-1"})));
    assert_eq!(expect_resp(&keyed, "publish_cost"), cost);
    // No `attest`: the read is outside the checked set.
    let (st, body) = http(port, "POST", "/op", Some(&bare), publish_cost(&e, &d, 3, json!({"attest": {"alg": "mldsa65-ed25519", "sig": "00"}})).as_bytes());
    let refused = json(&body);
    assert_eq!((st, refused["code"].as_str()), (200, Some("malformed")), "{refused}");
    assert!(refused["detail"].as_str().is_some_and(|d| d.contains("unknown field 'attest'")), "{refused}");
    // A frame the codec refuses as a `publish` is refused here the same: a
    // place past the runs' length is no place.
    let long = json(&http(port, "POST", "/op", Some(&bare), publish_cost(&e, &d, 3, json!({"places": [null, {"subspace": "1", "ordinal": "1"}]})).as_bytes()).1);
    let as_publish = json(&http(port, "POST", "/op", Some(&bare), publish_cost(&e, &d, 3, json!({"places": [null, {"subspace": "1", "ordinal": "1"}]})).replace("publish_cost", "publish").as_bytes()).1);
    assert_eq!((long["code"].as_str(), long["detail"].as_str()), (Some("malformed"), as_publish["detail"].as_str()), "{long} against {as_publish}");
    assert_eq!(head(port), before);
    sd.shutdown();
}

/// THE CONSULT, AND THE GUEST. The price states the run count of each draft
/// a list re-windows, so a draft the caller may not read answers `withheld`
/// naming it — the rendering draft, then an `also` draft — to a stranger
/// and to the guest; and the home of an `originals` entry is consulted by
/// derivation. A frame naming no draft is answered: the guest, holding no
/// account, with no homes, and the owner with its own two — its home page
/// and the notes document.
#[test]
fn publish_cost_withholds_a_draft_the_caller_may_not_read_and_prices_a_guest_with_no_homes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let bare = open_session(port, CLAIMANT_PRINCIPAL);
    let (_, other) = stranger(port, 9);
    let e = published_edition(port, &signed);
    let d = private_draft(port, &bare, "abc");
    let d2 = private_draft(port, &bare, "xy");
    // One link in a private notes document: a link-holding home of the
    // claimant's, and an original a rider could name.
    let notes = private_draft(port, &bare, "n");
    let original = acked_addr(&op(
        port,
        Some(&bare),
        &format!(r#"{{"op":"make_link","home":"{notes}","from":{{"addrs":["{d}"]}},"to":{{"addrs":[]}},"ty":{{"addrs":["{notes}.0.3.6.1"]}}}}"#),
    ));
    for reader in [Some(other.as_str()), None] {
        assert_withheld(&op(port, reader, &publish_cost(&e, &d, 3, json!({}))), &d);
        assert_withheld(&op(port, reader, &publish_cost(&e, &d, 3, json!({"also": [d2]}))), &d);
    }
    // A draft the stranger reads, an `also` draft it does not.
    let (st, body) = http(port, "POST", "/op", Some(&other), br#"{"op":"create_new_document","account":"1.0.2"}"#);
    assert_eq!(st, 200, "{}", String::from_utf8_lossy(&body));
    let theirs = acked_addr(&json(&body));
    let naming_also = json!({
        "op": "publish_cost",
        "doc": e,
        "draft": theirs,
        "also": [d2],
        "runs": [],
    });
    assert_withheld(&op(port, Some(&other), &naming_also.to_string()), &d2);
    // An original in a home the stranger may not read, by derivation.
    let naming_original = json!({"op": "publish_cost", "doc": e, "runs": [], "originals": [{"old": original}], "retract": [original]});
    assert_withheld(&op(port, Some(&other), &naming_original.to_string()), &notes);
    // No draft named: an answer for every caller, the homes the caller's own.
    let draftless = json!({"op": "publish_cost", "doc": e, "runs": []}).to_string();
    let mine = op(port, Some(&bare), &draftless);
    assert_eq!(expect_resp(&mine, "publish_cost")["homes"].as_u64(), Some(2), "the claimant's home page and its notes: {mine}");
    for reader in [Some(other.as_str()), None] {
        let v = op(port, reader, &draftless);
        assert_eq!(expect_resp(&v, "publish_cost")["homes"].as_u64(), Some(0), "no home of this caller's holds a link: {v}");
    }
    sd.shutdown();
}

/// A `supersede` ENTRY IS PRICED: each daughter the request names is an
/// entry read over the caller's homes and a claim the commit would stage,
/// so the price read counts it in `entries` and its claim in the staged
/// bytes — the figures a `publish` of the same members is refused on.
#[test]
fn publish_cost_counts_each_supersede_entry_and_the_claim_it_stages() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let bare = open_session(port, CLAIMANT_PRINCIPAL);
    let e = published_edition(port, &signed);
    let d = private_draft(port, &bare, "abc");
    let priced = |extra: Value| -> Value { expect_resp(&op(port, Some(&bare), &publish_cost(&e, &d, 3, extra)), "publish_cost").clone() };
    let plain = priced(json!({}));
    let daughters = priced(json!({"supersede": [format!("{e}.1.1"), format!("{e}.1.2")]}));
    assert_eq!((plain["entries"].as_u64(), daughters["entries"].as_u64()), (Some(0), Some(2)), "a daughter an entry: {daughters}");
    assert_eq!(
        daughters["staged_bytes"].as_u64().expect("bytes") - plain["staged_bytes"].as_u64().expect("bytes"),
        2 * skep_links::CLAIM_BYTES,
        "and a claim each: {daughters}"
    );
    for member in ["homes", "rewindow", "fence", "units", "read_budget", "byte_budget", "unit_budget", "position_budget"] {
        assert_eq!(daughters[member], plain[member], "{member} stands");
    }
    sd.shutdown();
}

/// THE UNITS THE READ ANSWERS ARE THE UNITS THE COMMIT STAGES. A draft
/// holds `abc`, an atom, and `de`, typed in one insert: six positions the
/// caller counts, three units the board counts off the stored values — two
/// runs of typed bytes and the atom between them — and the staged bytes
/// price each unit at the table's figure and its own bytes. The publication
/// of the same members then lands the member as those three stored pieces:
/// its delivery reads the first run, the atom, the second run, each one
/// item.
#[test]
fn publish_cost_answers_the_units_the_publication_then_stages() {
    use skep_links::{stored_tumbler_bytes, CORRESPONDENCE_RECORD_BYTES, PLACED_RUN_BYTES, REINSERTED_UNIT_BYTES, SHOT_BYTES};
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let bare = open_session(port, CLAIMANT_PRINCIPAL);
    let e = published_edition(port, &signed);
    let d = owner_draft(port, &bare);
    let typed = format!(r#"{{"op":"insert","doc":"{d}","at":{{"subspace":"1","ordinal":"1"}},"values":["abc",{{"atom":"XY"}},"de"]}}"#);
    expect_resp(&op(port, Some(&bare), &typed), "ack_addr");
    let runs = [run(&d, &format!("{d}.0.1.1"), 6)];
    let asked = publish_frame(&e, None, Some(&d), &runs).replace(r#""op":"publish""#, r#""op":"publish_cost""#);
    let v = op(port, Some(&bare), &asked);
    let cost = expect_resp(&v, "publish_cost");
    assert_eq!(cost["units"].as_u64(), Some(3), "two runs of typed bytes and the atom between them, where the positions are six: {v}");
    let draft_addr = stored_tumbler_bytes(&skep_core::codec::wire_address(&d).expect("an address").tumbler().clone());
    assert_eq!(
        cost["staged_bytes"].as_u64(),
        Some(SHOT_BYTES + draft_addr + (PLACED_RUN_BYTES + CORRESPONDENCE_RECORD_BYTES) + 3 * REINSERTED_UNIT_BYTES + (3 + 2 + 2)),
        "a unit at the table's figure and its own bytes: {v}"
    );
    let member = shot(port, &signed, &e, None, Some(&d), &runs);
    let delivered = op(port, None, &format!(r#"{{"op":"retrieve_v","specs":[{{"doc":"{member}","span":{{"start":"1.1","width":"0.6"}}}}]}}"#));
    let items = expect_resp(&delivered, "delivery")["items"].as_array().expect("items").clone();
    assert_eq!(items.len() as u64, cost["units"].as_u64().expect("units"), "the member's six positions are three stored pieces, one a unit: {delivered}");
    assert_eq!((items[0]["content"].as_str(), items[2]["content"].as_str()), (Some("abc"), Some("de")), "{delivered}");
    sd.shutdown();
}

/// NO COUNT FROM A DRAFT THE CALLER CANNOT READ. The claimant's private
/// draft is published into its edition: its first three words as three
/// runs, which leaves THREE correspondence records in the draft naming the
/// edition's first three words, and its last four as one run, ONE record
/// naming the next four; the first value of the claimant's home, a deposit,
/// is published content NO record names. A frame placing a stray run of
/// such words in a published document every caller reads is priced for
/// each of them: the guest, another account, and a principal seated at no
/// account, none of whom may read the draft, are each answered the SAME
/// figures whichever words the run names — the stray one piece — where the
/// claimant, who reads its draft, is priced one piece for the home's value
/// and for the one record's words and three for the three records'. And a
/// `publish` of the other account's past the transaction budget is refused
/// with the same detail, byte for byte, whichever words its stray names —
/// and, where it names the claimant's draft itself to re-insert from,
/// whichever of that draft's positions it names, held or not: no unit of a
/// draft it may not read is counted.
#[test]
fn publish_cost_and_the_refusal_count_no_record_homed_in_a_draft_the_caller_may_not_read() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let bare = open_session(port, CLAIMANT_PRINCIPAL);
    let (their_account, other) = stranger(port, 9);
    let unseated = open_session(port, 4242);
    let e = published_edition(port, &signed);
    let d = private_draft(port, &bare, "abcdefg");
    let word = |ordinal: u64, width: u64| run(&d, &format!("{d}.0.1.{ordinal}"), width);
    shot(port, &signed, &e, None, Some(&d), &[word(1, 1), word(3, 1), word(2, 1), word(4, 4)]);
    // A published document of the claimant's, empty, to place the stray in.
    let p = published_edition(port, &signed);
    // The stray runs, by how many records in the draft name their words.
    let strays = [(0u64, run(CLAIMANT_DOC1, &format!("{CLAIMANT_DOC1}.0.1.1"), 1)), (1, run(&e, &format!("{e}.0.1.4"), 2)), (3, run(&e, &format!("{e}.0.1.1"), 3))];
    let placing = |name: &str, doc: &str, draft: &str, stray: &str, extra: &str| {
        format!(r#"{{"op":"{name}","doc":"{doc}","draft":"{draft}","runs":[{stray}{extra}],"places":[{{"subspace":"1","ordinal":"1"}}]}}"#)
    };
    let figures = |v: &Value| -> Vec<u64> {
        let cost = expect_resp(v, "publish_cost");
        ["homes", "entries", "rewindow", "fence", "staged_bytes", "units"].iter().map(|member| cost[member].as_u64().unwrap_or_else(|| panic!("{member}: {v}"))).collect()
    };
    let priced = |token: Option<&str>| -> Vec<Vec<u64>> { strays.iter().map(|(_, stray)| figures(&op(port, token, &placing("publish_cost", &p, &p, stray, "")))).collect() };
    for (reader, token) in [("the guest", None), ("another account", Some(other.as_str())), ("a principal seated at no account", Some(unseated.as_str()))] {
        let answers = priced(token);
        assert_eq!(answers[1], answers[0], "{reader}: one record in a draft it may not read moves no figure");
        assert_eq!(answers[2], answers[0], "{reader}: nor do three");
        assert_eq!((answers[0][0], answers[0][2]), (0, 1), "{reader}: no home, and the stray's one piece in a document of no runs");
    }
    // The claimant reads its draft: a piece a record.
    let mine = priced(Some(&bare));
    assert_eq!(mine.iter().map(|answer| answer[2]).collect::<Vec<_>>(), [1, 1, 3], "the records the caller may read are its pieces");
    assert_eq!(mine[2][4] - mine[1][4], 2 * skep_links::KEPT_PLACE_BYTES, "and a kept place's change a piece");
    // The refusal ahead of the lock: the other account's own publication,
    // past the transaction budget on a hundred wide `links` entries over a
    // shot of 4,096 runs — the stray its first and its one placed run, then
    // one run a byte of a burst typed into a draft of its own.
    let create = format!(r#"{{"op":"create_new_document","account":"{their_account}"}}"#);
    let (their_home, their_draft) = (acked_addr(&op(port, Some(&other), &create)), acked_addr(&op(port, Some(&other), &create)));
    expect_resp(&op(port, Some(&other), &format!(r#"{{"op":"insert","doc":"{their_draft}","at":{{"subspace":"1","ordinal":"1"}},"values":["{}"]}}"#, "x".repeat(4095))), "ack_addr");
    let burst: String = (1..=4095).map(|k| format!(",{}", run(&their_draft, &format!("{their_draft}.0.1.{k}"), 1))).collect();
    let wide = r#"{"home":"member","from":{"member":[{"ordinal":"1","width":"4096"}]},"to":{"addrs":[]},"ty":{"addrs":["1.1.0.1.0.1.0.3.13"]}}"#;
    let links = format!(r#","links":[{}]}}"#, vec![wide; 100].join(","));
    let details: Vec<String> = strays
        .iter()
        .map(|(_, stray)| {
            let frame = placing("publish", &their_home, &their_draft, stray, &burst);
            let frame = format!("{}{links}", frame.strip_suffix('}').expect("an object"));
            let v = op_as_written(port, Some(&other), &frame);
            let rej = expect_resp(&v, "rejected");
            assert_eq!(rej["code"].as_str(), Some("publication_over_budget"), "{}", rej["detail"]);
            rej["detail"].as_str().expect("the bound passed, with its figures").to_string()
        })
        .collect();
    assert!(details[0].contains("bytes would be staged against the transaction budget"), "premise: the bytes speak: {}", details[0]);
    assert_eq!(details[1], details[0], "one record it may not read moves no figure of the detail");
    assert_eq!(details[2], details[0], "nor do three");
    // NO UNIT EITHER. The same account names the claimant's private draft
    // beside its own, among `also`, and re-inserts three of its positions
    // ahead of the burst: the first three, which hold typed bytes, or three
    // far past its end, which hold nothing. It may not read that draft, and
    // this refusal stands ahead of the store's own judgment of who owns it,
    // so no unit of either draft is counted: the detail is the same, byte
    // for byte, whichever positions the run names.
    let naming = |first: u64| {
        let theirs = run(&d, &format!("{d}.0.1.{first}"), 3);
        let frame = format!(r#"{{"op":"publish","doc":"{their_home}","draft":"{their_draft}","also":["{d}"],"runs":[{theirs}{burst}]{links}"#);
        let v = op_as_written(port, Some(&other), &frame);
        let rej = expect_resp(&v, "rejected");
        assert_eq!(rej["code"].as_str(), Some("publication_over_budget"), "{}", rej["detail"]);
        rej["detail"].as_str().expect("the bound passed, with its figures").to_string()
    };
    let (held, missing) = (naming(1), naming(5_000));
    assert!(held.contains("bytes would be staged against the transaction budget"), "premise: the bytes speak: {held}");
    assert_eq!(held, missing, "a draft it may not read moves no byte of the detail, whatever its positions hold");
    sd.shutdown();
}
