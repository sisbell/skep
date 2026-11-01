//! THE STAGING ACT over the wire (B3-S10; A-350): `stage {from}` mints a
//! private draft of its source in one commit, copies the source's whole
//! surface by identity and records where the draft began — its base, the
//! extent the copy took and its source — which `doc_metadata` of the draft
//! answers as `base`, `base_copied` and `source`; the base moves to the
//! member each publication of the draft makes; an alternative inherits its
//! source draft's base; the bare document is its own base; the three
//! refusals; a bare session admitted; the ack's row and the bare row's
//! class.

use crate::common;

use common::*;
use serde_json::Value;

/// The `doc_metadata` answer's `(base, base_copied, source)` for `doc`, as
/// `token` reads it — each `None` where the board serves `null`.
fn base_of(port: u16, token: &str, doc: &str) -> (Option<String>, Option<String>, Option<String>) {
    let v = doc_metadata(port, Some(token), doc);
    let meta = expect_resp(&v, "doc_metadata");
    let s = |member: &str| meta[member].as_str().map(str::to_string);
    (s("base"), s("base_copied"), s("source"))
}

fn some(s: &str) -> Option<String> {
    Some(s.to_string())
}

/// The feed's entries since `since`, as `token` reads them.
fn changes_since(port: u16, token: Option<&str>, since: u64) -> Vec<Value> {
    let (st, body) = http(port, "GET", &format!("/changes?since={since}"), token, b"");
    assert_eq!(st, 200, "changes: {}", String::from_utf8_lossy(&body));
    json(&body)["changes"].as_array().expect("changes").clone()
}

/// Drops the last whole record of `commits.log`, so the position it
/// recorded is served BARE at the next open and its op is the journal's to
/// name (PUB-6.45).
fn drop_the_last_record(dir: &std::path::Path) {
    let sidecar = dir.join("commits.log");
    let contents = std::fs::read_to_string(&sidecar).expect("read commits.log");
    let trimmed = &contents[..contents.len() - 1];
    let cut = trimmed.rfind('\n').map(|i| i + 1).unwrap_or(0);
    std::fs::write(&sidecar, &contents[..cut]).expect("drop the last record");
}

/// ONE OPERATION: a stage off a version member acks the new draft's address
/// — a PRIVATE document of the stager's account holding the member's whole
/// text by identity — and `doc_metadata` of the draft answers its `base`
/// (the member), `base_copied` (the three positions the copy took) and
/// `source` (the member), with no birth and no shot terms; the member
/// itself answers no base. The ack's row names the draft alone (never the
/// source), classed `stage`; a bare session is admitted on this
/// claimed-permissive board; and the draft's typed state starts at the
/// stage's ack — an edit typed before it is refused `arrangement_moved`,
/// one typed at it lands (skep #442's board half).
#[test]
fn a_stage_mints_a_private_draft_of_the_member_and_doc_metadata_serves_its_base() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let edition = edition_with(port, &signed, "abc");
    let v1 = acked_addr(&version_of(port, &signed, &edition, None));
    assert_eq!(v1, format!("{edition}.1"));
    let before = head_position(port);
    let ack = op(port, Some(&owner), &stage_frame(&v1));
    let draft = acked_addr(&ack);
    let at = acked_at(&ack);
    assert!(draft.starts_with(&format!("{CLAIMANT_ACCOUNT}.0.")), "a document of the stager's account: {draft}");
    assert_eq!(at, head_position(port), "the ack's position is the head");
    // The draft: private, the member's text by identity.
    let meta = doc_metadata(port, Some(&owner), &draft);
    let m = expect_resp(&meta, "doc_metadata");
    assert_eq!(m["doc"].as_str(), Some(draft.as_str()), "its own trunk: {meta}");
    assert_eq!(m["published"], Value::Bool(false), "born private: {meta}");
    assert_eq!(m["owner"].as_str(), Some(CLAIMANT_ACCOUNT), "{meta}");
    assert!(m["birth"].is_null() && m["placed"].is_null() && m["base_extent"].is_null(), "no member, no shot: {meta}");
    assert_eq!(m["at"].as_u64(), Some(at), "minted at the ack: {meta}");
    assert_eq!(base_of(port, &owner, &draft), (some(&v1), some("3"), some(&v1)), "the base, the count the copy took, the source: {meta}");
    assert_eq!(text_of(port, Some(&owner), &draft, 1, 3), "abc");
    assert_eq!(origins_of(port, Some(&owner), &draft, 1, 3), vec![edition.clone()], "the edition's own identity, shared");
    // The source answers no base.
    assert_eq!(base_of(port, &signed, &v1), (None, None, some(&edition)), "the member: a version's source, no base");
    assert_eq!(base_of(port, &signed, &edition), (None, None, None), "the trunk");
    // The ack's row: the draft alone, classed `stage`, recorded.
    let rows = changes_since(port, Some(&owner), before);
    assert_eq!(rows.len(), 1, "one write, one row: {rows:?}");
    assert_eq!(rows[0]["op"].as_str(), Some("stage"), "{:?}", rows[0]);
    assert_eq!(rows[0]["docs"], serde_json::json!([draft]), "the draft it minted, never the source: {:?}", rows[0]);
    assert_eq!(rows[0]["at"].as_u64(), Some(at));
    assert_eq!(rows[0]["key"].as_str(), Some("bare"), "a bare session's write: {:?}", rows[0]);
    // The typed state starts at the stage's ack.
    let stale = op_as_written(port, Some(&owner), &insert_frame(&draft, 4, "z", false, before));
    assert_eq!(expect_resp(&stale, "rejected")["code"].as_str(), Some("arrangement_moved"), "{stale}");
    expect_resp(&op_as_written(port, Some(&owner), &insert_frame(&draft, 4, "z", false, at)), "ack_addr");
    assert_eq!(text_of(port, Some(&owner), &draft, 1, 4), "abcz");
    assert_eq!(text_of(port, None, &v1, 1, 3), "abc", "the member is untouched");
    // The bare published document with a member stages its HEAD.
    let off_bare = stage_of(port, &owner, &edition);
    assert_eq!(base_of(port, &owner, &off_bare), (some(&v1), some("3"), some(&v1)), "the head, not the pre-chain arrangement");
    sd.shutdown();
}

/// THE BARE DOCUMENT AS THE BASE (skep #741): staged while its chain is
/// empty, a published document is its own base and `base_copied` is what
/// the copy took of it — `0` for an empty edition, its count once content
/// stands there, and the memberless HOME's genesis atom counted, measured —
/// never a constant.
#[test]
fn the_bare_document_is_its_own_base_with_the_count_the_copy_took() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let empty = published_edition(port, &signed);
    let of_empty = stage_of(port, &owner, &empty);
    assert_eq!(base_of(port, &owner, &of_empty), (some(&empty), some("0"), some(&empty)), "the empty edition, at zero");
    assert_eq!(content_extent(port, Some(&owner), &of_empty), 0);
    deposit_text(port, &signed, &empty, 1, "abc");
    let of_full = stage_of(port, &owner, &empty);
    assert_eq!(base_of(port, &owner, &of_full), (some(&empty), some("3"), some(&empty)), "the count the copy took");
    assert_eq!(text_of(port, Some(&owner), &of_full, 1, 3), "abc");
    assert_eq!(base_of(port, &owner, &of_empty), (some(&empty), some("0"), some(&empty)), "the earlier record stands");
    // The memberless home holds its genesis atom: counted.
    let home_count = content_extent(port, None, CLAIMANT_DOC1);
    assert!(home_count >= 1, "the ceremony's atom stands in the home");
    let of_home = stage_of(port, &owner, CLAIMANT_DOC1);
    assert_eq!(base_of(port, &owner, &of_home), (some(CLAIMANT_DOC1), some(&home_count.to_string()), some(CLAIMANT_DOC1)), "the home, its atom counted");
    sd.shutdown();
}

/// THE POOL SIBLING (#742): an alternative staged from a draft of the
/// caller's inherits the draft's recorded base and extent, its `source`
/// that draft, holding the draft's current words; an alternative of a plain
/// draft the board holds no base for records none — a free-standing draft,
/// its source noted all the same.
#[test]
fn an_alternative_inherits_its_source_drafts_base_and_an_unrecorded_draft_leaves_none() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let edition = edition_with(port, &signed, "abc");
    let v1 = acked_addr(&version_of(port, &signed, &edition, None));
    let staged = stage_of(port, &owner, &v1);
    expect_resp(&insert_text(port, &owner, &staged, 4, "z"), "ack_addr");
    let alternative = stage_of(port, &owner, &staged);
    assert_eq!(base_of(port, &owner, &alternative), (some(&v1), some("3"), some(&staged)), "inherited; the draft its source");
    assert_eq!(text_of(port, Some(&owner), &alternative, 1, 4), "abcz", "the draft's current words");
    let nested = stage_of(port, &owner, &alternative);
    assert_eq!(base_of(port, &owner, &nested), (some(&v1), some("3"), some(&alternative)), "one hop further, the same base");
    let plain = draft_with(port, &owner, "xy");
    let free = stage_of(port, &owner, &plain);
    assert_eq!(base_of(port, &owner, &free), (None, None, some(&plain)), "free-standing: no base, the source noted");
    assert_eq!(text_of(port, Some(&owner), &free, 1, 2), "xy");
    sd.shutdown();
}

/// THE BASE MOVES ON PUBLISH (#745): at each shot naming the draft as its
/// rendering draft, the board moves the draft's base to the member the shot
/// minted and `base_copied` to that member's whole count, keeping the
/// source — so the draft staged from version 1 that publishes version 2
/// publishes version 3 next, never a daughter of version 1; a shot naming no
/// draft moves nothing; and the request's own `base` is checked against the
/// chain alone, never against the record.
#[test]
fn the_base_moves_to_the_member_the_draft_renders_at_each_publish() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let edition = edition_with(port, &signed, "abc");
    let v1 = acked_addr(&version_of(port, &signed, &edition, None));
    let draft = stage_of(port, &owner, &v1);
    let z = acked_addr(&insert_text(port, &owner, &draft, 4, "z"));
    let mut runs = shot_runs(port, Some(&owner), &edition, 1, 3);
    runs.push(run(&draft, &z, 1));
    let v2 = shot(port, &signed, &edition, Some((&v1, 3)), Some(&draft), &runs);
    assert_eq!(v2, format!("{edition}.2"), "the trunk's next member");
    assert_eq!(base_of(port, &owner, &draft), (some(&v2), some("4"), some(&v1)), "moved to the member, its whole count, the source kept");
    assert_eq!(text_of(port, None, &v2, 1, 4), "abcz");
    // The next shot, off the base the board now records: version 3.
    let v3 = shot(port, &signed, &edition, Some((&v2, 4)), Some(&draft), &shot_runs(port, Some(&owner), &edition, 1, 4));
    assert_eq!(v3, format!("{edition}.3"), "not a daughter of version 1");
    assert_eq!(base_of(port, &owner, &draft), (some(&v3), some("4"), some(&v1)));
    // A shot naming no draft moves nothing.
    let v4 = shot(port, &signed, &edition, Some((&v3, 4)), None, &shot_runs(port, Some(&owner), &edition, 1, 4));
    assert_eq!(v4, format!("{edition}.4"));
    assert_eq!(base_of(port, &owner, &draft), (some(&v3), some("4"), some(&v1)), "no draft named: the base stands");
    // The request's base is the client's statement: a shot naming version 1
    // lands as its daughter (PUB-2.39) and moves the base there — nothing
    // compares it with the record.
    let daughter = shot(port, &signed, &edition, Some((&v1, 3)), Some(&draft), &shot_runs(port, Some(&owner), &edition, 1, 3));
    assert_eq!(daughter, format!("{v1}.1"));
    assert_eq!(base_of(port, &owner, &draft), (some(&daughter), some("3"), some(&v1)));
    sd.shutdown();
}

/// THE REFUSALS, as the lowering maps them: a source the stager may not
/// read is `withheld` naming it (the door's consult, nothing minted); an
/// unregistered source `source_not_registered`; a stage into an account
/// without a home `mint_home_first` — the home minted, the stage lands,
/// private, in that account.
#[test]
fn a_stage_is_refused_withheld_source_not_registered_and_mint_home_first() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let secret = draft_with(port, &owner, "s");
    let (account, stranger) = bootstrap_delegate(port, 912);
    let before = head_position(port);
    // No home yet: the mint slot stands ahead of the source consult.
    let v = op(port, Some(&stranger), &stage_frame(CLAIMANT_DOC1));
    assert_eq!(verdict(&v), "credential_refused:mint_home_first", "{v}");
    assert_eq!(head_position(port), before, "refused ahead of any commit");
    let home = acked_addr(&op(port, Some(&stranger), &create_frame(&account, None)));
    assert_eq!(home, format!("{account}.0.1"));
    let after_home = head_position(port);
    assert!(after_home > before, "the home committed");
    // The owner's private draft: withheld from the stranger, naming it.
    let v = op(port, Some(&stranger), &stage_frame(&secret));
    assert_withheld(&v, &secret);
    // An address naming no document.
    let v = op(port, Some(&stranger), &stage_frame(&format!("{CLAIMANT_ACCOUNT}.0.99")));
    assert_eq!(expect_resp(&v, "rejected")["code"].as_str(), Some("source_not_registered"), "{v}");
    assert_eq!(head_position(port), after_home, "the home alone committed; every refusal minted nothing");
    // The published home of the claimant: readable by all, staged into the
    // stranger's own account.
    let theirs = stage_of(port, &stranger, CLAIMANT_DOC1);
    assert!(theirs.starts_with(&format!("{account}.0.")), "{theirs}");
    let meta = doc_metadata(port, Some(&stranger), &theirs);
    assert_eq!(expect_resp(&meta, "doc_metadata")["owner"].as_str(), Some(account.as_str()), "{meta}");
    assert_eq!(meta["published"], Value::Bool(false));
    assert_eq!(base_of(port, &stranger, &theirs), (some(CLAIMANT_DOC1), some(&content_extent(port, None, CLAIMANT_DOC1).to_string()), some(CLAIMANT_DOC1)));
    // The guest and the stranger are withheld the private draft, source and
    // base alike; its owner reads it.
    assert_withheld(&doc_metadata(port, None, &theirs), &theirs);
    assert_withheld(&doc_metadata(port, Some(&owner), &theirs), &theirs);
    sd.shutdown();
}

/// THE BARE ROW's CLASS (PUB-6.45): a stage's commit whose record the
/// sidecar lost is served bare and classed `stage` off the journal — the
/// draft's base present after the commit and absent before — while an owned
/// `version`'s bare row is still classed `version`, the member it minted
/// carrying no base.
#[test]
fn a_stages_bare_row_is_classed_stage_and_a_versions_still_version() {
    let dir = tempfile::tempdir().expect("tempdir");
    let (stage_at, version_at, draft, member);
    {
        let sd = spawn(dir.path());
        let port = sd.port();
        let owner = open_session(port, CLAIMANT_PRINCIPAL);
        let ack = op(port, Some(&owner), &stage_frame(CLAIMANT_DOC1));
        draft = acked_addr(&ack);
        stage_at = acked_at(&ack);
        sd.shutdown();
    }
    drop_the_last_record(dir.path());
    {
        let sd = spawn(dir.path());
        let port = sd.port();
        let owner = open_session(port, CLAIMANT_PRINCIPAL);
        let rows = changes_since(port, Some(&owner), stage_at - 1);
        let row = rows.iter().find(|r| r["at"].as_u64() == Some(stage_at)).unwrap_or_else(|| panic!("the stage's row stands: {rows:?}"));
        assert!(row["docs"].is_null() && row["key"].is_null(), "a lost record answers null testimony: {row}");
        assert_eq!(row["op"].as_str(), Some("stage"), "the journal names the op: {row}");
        assert_eq!(base_of(port, &owner, &draft), (some(CLAIMANT_DOC1), some(&content_extent(port, None, CLAIMANT_DOC1).to_string()), some(CLAIMANT_DOC1)), "the base is M5 state, not the row's");
        // An owned version of the home as the last write: a member.
        let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
        let ack = version_of(port, &signed, CLAIMANT_DOC1, None);
        member = acked_addr(&ack);
        assert_eq!(member, format!("{CLAIMANT_DOC1}.1"));
        version_at = acked_at(&ack);
        sd.shutdown();
    }
    drop_the_last_record(dir.path());
    {
        let sd = spawn(dir.path());
        let port = sd.port();
        let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
        let rows = changes_since(port, Some(&signed), version_at - 1);
        let row = rows.iter().find(|r| r["at"].as_u64() == Some(version_at)).unwrap_or_else(|| panic!("the version's row stands: {rows:?}"));
        assert!(row["docs"].is_null(), "{row}");
        assert_eq!(row["op"].as_str(), Some("version"), "a version's bare row: {row}");
        assert_eq!(base_of(port, &signed, &member), (None, None, some(CLAIMANT_DOC1)), "a version records no base");
        sd.shutdown();
    }
}
