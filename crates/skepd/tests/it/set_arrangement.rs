//! SET_ARRANGEMENT over the wire (the landing lane, brief A; skep #764):
//! a draft's whole arrangement set by identity in one commit, typed against
//! the draft's state. What this file pins end to end against the real
//! daemon: the landing — the arrangement set, the base re-recorded and the
//! marker served by `doc_metadata` — with `arrangement_moved` wiping
//! nothing; land and tell (`head_moved`); the fork gate's refusal
//! (`fork_base_moved`) and admission (the source is the head); a baseless
//! draft admitted with nothing moved, its head naming no registered
//! document refused `source_not_registered`, and `no_base_to_record`; a
//! free-standing draft's head naming a draft its caller may not read,
//! acked at any extent, and the runs naming that draft `withheld`; the
//! head's three refusals and the base's; `doc_metadata` and `image` on
//! `/op-at` at `at − 1` answering the pre-landing state; `write_at_history`
//! on `/op-at`; the feed row and its two terms; a merge taken out and put
//! back naming its landing's position (`merge.at`), a position naming no
//! marker refused `marker_not_restorable` and one beside no `base`
//! `malformed`; the wire's example frame answered as the op. The door's
//! consult is `source_gate.rs`'s pattern;
//! the marker's inheritance and the shot's clear are `stage.rs`'s.
//!
//! Every suite runs post-claim on a CLAIMED-PERMISSIVE board (`spawn`).

use crate::common;

use common::*;
use serde_json::Value;

/// `doc`'s `(base, base_copied, merge)` as `token` reads them.
fn standing(port: u16, token: &str, doc: &str) -> (Option<String>, Option<String>, Value) {
    let v = doc_metadata(port, Some(token), doc);
    let meta = expect_resp(&v, "doc_metadata");
    let s = |member: &str| meta[member].as_str().map(str::to_string);
    (s("base"), s("base_copied"), meta["merge"].clone())
}

fn some(s: &str) -> Option<String> {
    Some(s.to_string())
}

/// The runs `image` answers for content ordinals `from ..` of `doc`, in the
/// frame builder's form.
fn runs_of(port: u16, token: &str, doc: &str, from: u64, width: u64) -> Vec<(String, String, u64)> {
    image_runs(port, Some(token), doc, from, width)
        .iter()
        .map(|(i_start, w)| (origin_of(i_start), i_start.clone(), *w))
        .collect()
}

fn borrowed(runs: &[(String, String, u64)]) -> Vec<(&str, &str, u64)> {
    runs.iter().map(|(o, s, w)| (o.as_str(), s.as_str(), *w)).collect()
}

/// A permanent rejection carrying `code`.
fn assert_permanent(v: &Value, code: &str) {
    let rej = expect_resp(v, "rejected");
    assert_eq!(rej["code"].as_str(), Some(code), "{v}");
    assert_eq!(rej["disposition"].as_str(), Some("permanent"), "{v}");
}

/// The feed's entries since `since`, as `token` reads them.
fn changes_since(port: u16, token: &str, since: u64) -> Vec<Value> {
    let (st, body) = http(port, "GET", &format!("/changes?since={since}"), Some(token), b"");
    assert_eq!(st, 200, "changes: {}", String::from_utf8_lossy(&body));
    json(&body)["changes"].as_array().expect("changes").clone()
}

/// The edition holding `abc`, its version 1, and a staging draft of it
/// holding `abcz`: `(edition, v1, draft)`.
fn family(port: u16, signed: &str, owner: &str) -> (String, String, String) {
    let edition = edition_with(port, signed, "abc");
    let v1 = acked_addr(&version_of(port, signed, &edition, None));
    assert_eq!(v1, format!("{edition}.1"));
    let draft = stage_of(port, owner, &v1);
    expect_resp(&insert_text(port, owner, &draft, 4, "z"), "ack_addr");
    assert_eq!(text_of(port, Some(owner), &draft, 1, 4), "abcz");
    (edition, v1, draft)
}

/// THE LANDING IS ONE COMMIT (the owner's rulings R1, R2, R4; skep #764):
/// the draft's whole arrangement set by identity — the edition's last two
/// words and nothing of the draft's own — its base re-recorded on the head
/// told and the marker served beside it with the landing's position; the
/// feed row names the draft and carries the base and the merge it recorded;
/// a frame typed against the state before the landing is refused
/// `arrangement_moved` with NOTHING wiped; `doc_metadata` and `image` on
/// `/op-at` at `at − 1` answer the pre-landing base, extent, null marker
/// and arrangement; and a write on `/op-at` is refused at the transport.
#[test]
fn a_landing_sets_the_arrangement_records_the_base_and_the_marker_in_one_commit() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let (edition, v1, draft) = family(port, &signed, &owner);
    let side = format!("{v1}.1");
    let before = head_position(port);
    let runs = runs_of(port, &owner, &edition, 2, 2);
    let frame = set_arrangement_frame(&draft, &borrowed(&runs), Some((&v1, 3)), Some((&v1, 3)), Some(&[&side]), None);
    let ack = op(port, Some(&owner), &frame);
    let at = acked_at(&ack);
    assert_eq!(expect_resp(&ack, "ack")["at"].as_u64(), Some(at));
    assert!(ack.get("head_moved").is_none(), "the head is the trunk's: {ack}");
    assert_eq!(at, head_position(port), "one commit, the ack's position the head");
    assert_eq!(text_of(port, Some(&owner), &draft, 1, 2), "bc", "the whole arrangement");
    assert_eq!(content_extent(port, Some(&owner), &draft), 2, "nothing of the draft's own stands");
    assert_eq!(origins_of(port, Some(&owner), &draft, 1, 2), vec![edition.clone()], "by identity");
    let marker = serde_json::json!({"at": at, "head": v1, "head_copied": "3", "sides": [side]});
    assert_eq!(standing(port, &owner, &draft), (some(&v1), some("3"), marker.clone()), "the base re-recorded, the marker beside it");
    // The feed row: the draft, the base and the merge recorded.
    let rows = changes_since(port, &owner, before);
    assert_eq!(rows.len(), 1, "one write, one row: {rows:?}");
    let row = &rows[0];
    assert_eq!(row["op"].as_str(), Some("set_arrangement"), "{row}");
    assert_eq!(row["docs"], serde_json::json!([draft]), "the draft, never a run's origin: {row}");
    assert_eq!(row["at"].as_u64(), Some(at));
    assert_eq!(row["base"].as_str(), Some(v1.as_str()), "the base recorded: {row}");
    assert_eq!(row["merge"], serde_json::json!({"head": v1, "sides": [side]}), "the merge recorded: {row}");
    assert_eq!(row["key"].as_str(), Some("bare"));
    // Typed against the state before the landing: refused, nothing wiped.
    let stale = op(port, Some(&owner), &set_arrangement_frame(&draft, &runs_of(port, &owner, &edition, 1, 1).iter().map(|(o, s, w)| (o.as_str(), s.as_str(), *w)).collect::<Vec<_>>(), None, None, None, before));
    let rej = expect_resp(&stale, "rejected");
    assert_eq!(rej["code"].as_str(), Some("arrangement_moved"), "{stale}");
    assert_eq!((rej["site"]["as_of"].as_u64(), rej["site"]["current"].as_u64()), (Some(before), Some(at)), "{stale}");
    assert_eq!(head_position(port), at, "nothing committed");
    assert_eq!(text_of(port, Some(&owner), &draft, 1, 2), "bc", "nothing wiped");
    assert_eq!(standing(port, &owner, &draft).2, marker, "the marker stands");
    // Before the landing, on `/op-at`: the arrangement, the base and no
    // marker the draft held then — what an undo reads. THE POSITION BEFORE
    // THE LANDING is the committed position below the ack's `at`, which is
    // NOT `at − 1`: the landing is one commit of three records (the removal,
    // the placement, the base record), so `at − 1` lies inside it and
    // `/op-at` answers `not_a_position` naming the position before as
    // `nearest` — the row before it on the feed names the same.
    let (st, inside) = op_at(port, Some(&owner), at - 1, &doc_metadata_frame(&draft));
    assert_eq!((st, inside["error"].as_str(), inside["nearest"].as_u64()), (400, Some("not_a_position"), Some(before)), "{inside}");
    let then = op_at_ok(port, Some(&owner), before, &doc_metadata_frame(&draft));
    let meta = expect_resp(&then, "doc_metadata");
    assert_eq!((meta["base"].as_str(), meta["base_copied"].as_str()), (Some(v1.as_str()), Some("3")), "the pre-landing base: {then}");
    assert!(meta["merge"].is_null(), "no marker then: {then}");
    assert_eq!(meta["as_of"].as_u64(), Some(before));
    let image = op_at_ok(port, Some(&owner), before, &image_frame(&draft, 1, 4));
    let widths: u64 = runs_in(&image).iter().map(|(_, w)| w).sum();
    assert_eq!(widths, 4, "the four positions the draft arranged then: {image}");
    // A write on `/op-at`: the transport's refusal, before any store — the
    // frame typed, so the refusal is the route's and not the parse's.
    let typed = set_arrangement_frame(&draft, &borrowed(&runs), Some((&v1, 3)), Some((&v1, 3)), Some(&[&side]), at);
    let (st, body) = op_at(port, Some(&owner), at, &typed);
    assert_eq!(st, 400, "{body}");
    assert_eq!(body["error"].as_str(), Some("write_at_history"));
    assert_eq!(head_position(port), at);
    sd.shutdown();
}

/// A merge taken out is put back with its landing's position (skep #870).
///
/// A landing, the merge taken out — the base re-sent, no merge — and the
/// merge put back naming the landing's own
/// position: `doc_metadata` serves the marker as the landing left it, its
/// `at` the landing's, and the write's row carries the position put back in
/// its `merge`; the withdrawal's position names no marker the board put on
/// the draft and is refused `marker_not_restorable`, permanent, nothing
/// written; and a position beside no `base` is `malformed` at the parse.
#[test]
fn a_merge_taken_out_is_put_back_with_its_landings_own_position() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let (edition, v1, draft) = family(port, &signed, &owner);
    let side = format!("{v1}.1");
    let runs = runs_of(port, &owner, &edition, 2, 2);
    let landing = set_arrangement_frame(&draft, &borrowed(&runs), Some((&v1, 3)), Some((&v1, 3)), Some(&[&side]), None);
    let landed = acked_at(&op(port, Some(&owner), &landing));
    let marker = serde_json::json!({"at": landed, "head": v1, "head_copied": "3", "sides": [side]});
    let withdrawn = acked_at(&op(port, Some(&owner), &set_arrangement_frame(&draft, &borrowed(&runs), None, Some((&v1, 3)), None, None)));
    assert!(standing(port, &owner, &draft).2.is_null(), "the premise: the marker cleared");
    let put_back = |at: u64| {
        let mut frame: Value = serde_json::from_str(&landing).expect("the landing's frame");
        frame["merge"]["at"] = serde_json::json!(at);
        frame.to_string()
    };
    let before = head_position(port);
    assert_permanent(&op(port, Some(&owner), &put_back(withdrawn)), "marker_not_restorable");
    assert_eq!(head_position(port), before, "nothing committed");
    let mut baseless: Value = serde_json::from_str(&put_back(landed)).expect("a frame");
    baseless.as_object_mut().expect("an object").remove("base");
    let rej = op(port, Some(&owner), &baseless.to_string());
    assert_eq!(expect_resp(&rej, "rejected")["code"].as_str(), Some("malformed"), "{rej}");
    assert_eq!(head_position(port), before, "nothing committed");
    let restored = acked_at(&op(port, Some(&owner), &put_back(landed)));
    assert_eq!(standing(port, &owner, &draft), (some(&v1), some("3"), marker), "the marker as the landing left it, its `at` the landing's");
    assert_eq!(text_of(port, Some(&owner), &draft, 1, 2), "bc", "the words as sent");
    let rows = changes_since(port, &owner, before);
    let row = rows.iter().find(|r| r["at"].as_u64() == Some(restored)).expect("the write's row");
    assert_eq!(row["merge"], serde_json::json!({"at": landed, "head": v1, "sides": [side]}), "the row names the position put back: {row}");
    assert_eq!(row["base"].as_str(), Some(v1.as_str()), "{row}");
    sd.shutdown();
}

/// LAND AND TELL (the owner's ruling R5, its precision P1): a version
/// published since the merge was composed refuses nothing — the landing
/// lands, records base and marker on the head USED, and the ack names the
/// trunk's current head; composed on that head, the next landing tells
/// nothing. The extent recorded is the extent AS READ: a deposit the head
/// took between stands past it.
#[test]
fn a_landing_composed_on_an_older_head_lands_and_tells_the_newer_one() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let (edition, v1, draft) = family(port, &signed, &owner);
    // Version 2 lands from a sibling draft: the trunk moves past version 1.
    let sibling = stage_of(port, &owner, &v1);
    let v2 = shot(port, &signed, &edition, Some((&v1, 3)), Some(&sibling), &shot_runs(port, Some(&owner), &edition, 1, 3));
    assert_eq!(v2, format!("{edition}.2"));
    let runs = runs_of(port, &owner, &edition, 1, 2);
    let ack = op(port, Some(&owner), &set_arrangement_frame(&draft, &borrowed(&runs), Some((&v1, 3)), Some((&v1, 3)), Some(&[]), None));
    let at = acked_at(&ack);
    assert_eq!(ack["head_moved"].as_str(), Some(v2.as_str()), "the trunk's current head, told: {ack}");
    assert_eq!(text_of(port, Some(&owner), &draft, 1, 2), "ab");
    assert_eq!(
        standing(port, &owner, &draft),
        (some(&v1), some("3"), serde_json::json!({"at": at, "head": v1, "head_copied": "3", "sides": []})),
        "recorded on the head used"
    );
    // Composed on the trunk's head: nothing to tell, the base moved there.
    let ack = op(port, Some(&owner), &set_arrangement_frame(&draft, &borrowed(&runs), Some((&v2, 3)), Some((&v2, 3)), Some(&[]), None));
    assert!(ack.get("head_moved").is_none(), "{ack}");
    assert_eq!(standing(port, &owner, &draft).0, some(&v2));
    // The head's three refusals — a member no mint has made, a head off the
    // chain, another edition's member, and an extent past the head's count
    // — and the base's same three, version 2 holding three; each commits
    // nothing. The edition's ninth member lies in the chain by its address
    // and passes an extent of zero, and is refused by its registration,
    // reorder: the same frame lands once a mint makes it.
    let other = edition_with(port, &signed, "xy");
    let other_v1 = acked_addr(&version_of(port, &signed, &other, None));
    let unminted = format!("{edition}.9");
    let head = head_position(port);
    for frame in [
        set_arrangement_frame(&draft, &borrowed(&runs), Some((&unminted, 0)), None, None, None),
        set_arrangement_frame(&draft, &borrowed(&runs), None, Some((&unminted, 0)), None, None),
    ] {
        let v = op(port, Some(&owner), &frame);
        let rej = expect_resp(&v, "rejected");
        assert_eq!((rej["code"].as_str(), rej["disposition"].as_str()), (Some("source_not_registered"), Some("reorder")), "{v}");
    }
    assert_permanent(&op(port, Some(&owner), &set_arrangement_frame(&draft, &borrowed(&runs), Some((&other_v1, 1)), None, None, None)), "base_not_in_chain");
    assert_permanent(&op(port, Some(&owner), &set_arrangement_frame(&draft, &borrowed(&runs), Some((&v2, 4)), None, None, None)), "base_extent_too_large");
    assert_permanent(&op(port, Some(&owner), &set_arrangement_frame(&draft, &borrowed(&runs), None, Some((&other_v1, 1)), None, None)), "base_not_in_chain");
    assert_permanent(&op(port, Some(&owner), &set_arrangement_frame(&draft, &borrowed(&runs), None, Some((&v2, 4)), None, None)), "base_extent_too_large");
    // The edition itself: the store's `published_target` from the signed
    // owner; from the bare session the daemon's publish-class gate stands
    // ahead of it, as on the five in-place edits.
    assert_permanent(&op(port, Some(&signed), &set_arrangement_frame(&edition, &borrowed(&runs), None, None, None, None)), "published_target");
    assert_eq!(verdict(&op(port, Some(&owner), &set_arrangement_frame(&edition, &borrowed(&runs), None, None, None, None))), "credential_refused:signed_session_required");
    assert_eq!(head_position(port), head, "every refusal commits nothing");
    assert_eq!(text_of(port, Some(&owner), &draft, 1, 2), "ab");
    sd.shutdown();
}

/// THE FORK GATE (the owner's ruling N4, its precision P5): a stranger's
/// private fork of version 1 takes a landing composed on version 1 — its
/// source — gaining no base and no marker; composed on version 2, the
/// landing is refused `fork_base_moved` naming the source, nothing
/// written, since the source the board records never moves.
#[test]
fn a_fork_is_admitted_where_its_source_is_the_head_and_refused_by_name_where_it_is_not() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let (edition, v1, draft) = family(port, &signed, &owner);
    // The stranger's home, then a PRIVATE fork of version 1.
    let (account, stranger) = bootstrap_delegate(port, 931);
    acked_addr(&op(port, Some(&stranger), &create_frame(&account, None)));
    let fork = acked_addr(&version_of(port, &stranger, &v1, Some(false)));
    assert!(fork.starts_with(&format!("{account}.0.")), "{fork}");
    let meta = doc_metadata(port, Some(&stranger), &fork);
    assert_eq!(meta["source"].as_str(), Some(v1.as_str()), "{meta}");
    assert!(meta["base"].is_null() && meta["merge"].is_null(), "a version records no base: {meta}");
    // The source is the head: admitted, nothing moved.
    let runs = runs_of(port, &stranger, &edition, 3, 1);
    let ack = op(port, Some(&stranger), &set_arrangement_frame(&fork, &borrowed(&runs), Some((&v1, 3)), None, Some(&[]), None));
    expect_resp(&ack, "ack");
    assert!(ack.get("head_moved").is_none());
    assert_eq!(text_of(port, Some(&stranger), &fork, 1, 1), "c");
    let meta = doc_metadata(port, Some(&stranger), &fork);
    assert!(meta["base"].is_null() && meta["merge"].is_null(), "no base, no marker: {meta}");
    assert_eq!(meta["source"].as_str(), Some(v1.as_str()), "the source stands");
    // Version 2 lands; a landing composed on it is refused by name.
    let v2 = shot(port, &signed, &edition, Some((&v1, 3)), Some(&draft), &shot_runs(port, Some(&owner), &edition, 1, 3));
    let head = head_position(port);
    let refused = op(port, Some(&stranger), &set_arrangement_frame(&fork, &borrowed(&runs), Some((&v2, 3)), None, Some(&[]), None));
    assert_permanent(&refused, "fork_base_moved");
    assert_eq!(refused["site"]["addr"].as_str(), Some(v1.as_str()), "the source named: {refused}");
    assert_eq!(head_position(port), head, "nothing written");
    assert_eq!(text_of(port, Some(&stranger), &fork, 1, 1), "c");
    // A base named for the fork: nothing to record.
    assert_permanent(&op(port, Some(&stranger), &set_arrangement_frame(&fork, &borrowed(&runs), Some((&v1, 3)), Some((&v1, 3)), None, None)), "no_base_to_record");
    assert_eq!(head_position(port), head);
    sd.shutdown();
}

/// A FREE-STANDING DRAFT'S HEAD TELLS NOTHING (PUB-1.13): a stranger's own
/// draft — a mint after their home, no base and no source — takes a landing
/// whose head names the owner's private draft at its count and past it, each
/// acked with no `head_moved` and nothing recorded, so the answer says
/// nothing of the size of a document the stranger may not read; the runs,
/// which the op does read, are consulted: runs naming that draft are
/// `withheld` naming it, nothing written.
#[test]
fn a_free_standing_drafts_head_tells_nothing_of_a_draft_its_caller_may_not_read() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let edition = edition_with(port, &signed, "abc");
    let plain = draft_with(port, &owner, "xy");
    assert_eq!(content_extent(port, Some(&owner), &plain), 2, "the owner's draft holds two");
    // The stranger's home, then a draft of their own: free-standing.
    let stranger = seat_stranger(port, 932);
    let own = create_doc(port, &stranger.session, &stranger.account);
    let v = doc_metadata(port, Some(&stranger.session), &own);
    let meta = expect_resp(&v, "doc_metadata");
    assert!(meta["base"].is_null() && meta["source"].is_null(), "free-standing: {v}");
    assert_withheld(&doc_metadata(port, Some(&stranger.session), &plain), &plain);
    let runs = runs_of(port, &stranger.session, &edition, 1, 3);
    for extent in [2, 3, 1_000_000] {
        let ack = op(port, Some(&stranger.session), &set_arrangement_frame(&own, &borrowed(&runs), Some((&plain, extent)), None, None, None));
        assert_eq!(ack["resp"].as_str(), Some("ack"), "extent {extent}: {ack}");
        assert!(ack.get("head_moved").is_none(), "extent {extent}: {ack}");
        let v = doc_metadata(port, Some(&stranger.session), &own);
        let meta = expect_resp(&v, "doc_metadata");
        assert!(meta["base"].is_null() && meta["merge"].is_null(), "extent {extent}, nothing recorded: {v}");
    }
    assert_eq!(text_of(port, Some(&stranger.session), &own, 1, 3), "abc");
    // The runs are what the op reads: naming the owner's draft, refused.
    let head = head_position(port);
    let theirs = runs_of(port, &owner, &plain, 1, 2);
    let refused = op(port, Some(&stranger.session), &set_arrangement_frame(&own, &borrowed(&theirs), None, None, None, None));
    assert_withheld(&refused, &plain);
    assert_eq!(head_position(port), head, "nothing written");
    assert_eq!(text_of(port, Some(&stranger.session), &own, 1, 3), "abc");
    sd.shutdown();
}

/// A BASELESS DRAFT (N4): a plain draft — minted and written, never staged
/// — takes a landing whose head names a registered document, nothing moved,
/// no base and no marker gained, its feed row carrying the request's merge
/// beside a null base — the one place the landing's position is kept; a
/// head naming no registered document is `source_not_registered`, reorder,
/// and naming a `base` for it is `no_base_to_record`, each with nothing
/// written; an empty `runs` empties it; and the wire's documented example
/// is answered as the op.
#[test]
fn a_baseless_draft_is_admitted_with_nothing_moved_and_refuses_a_base_by_name() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let edition = edition_with(port, &signed, "abc");
    let v1 = acked_addr(&version_of(port, &signed, &edition, None));
    let plain = draft_with(port, &owner, "xy");
    let meta = doc_metadata(port, Some(&owner), &plain);
    assert!(meta["base"].is_null() && meta["source"].is_null() && meta["merge"].is_null(), "{meta}");
    let runs = runs_of(port, &owner, &edition, 1, 3);
    let head = head_position(port);
    assert_permanent(&op(port, Some(&owner), &set_arrangement_frame(&plain, &borrowed(&runs), Some((&v1, 3)), Some((&v1, 3)), Some(&[]), None)), "no_base_to_record");
    assert_eq!(head_position(port), head, "nothing written");
    assert_eq!(text_of(port, Some(&owner), &plain, 1, 2), "xy");
    // Admitted with the head and a merge, nothing recorded; the row carries
    // the merge all the same.
    let ack = op(port, Some(&owner), &set_arrangement_frame(&plain, &borrowed(&runs), Some((&v1, 3)), None, Some(&[]), None));
    expect_resp(&ack, "ack");
    assert_eq!(text_of(port, Some(&owner), &plain, 1, 3), "abc");
    let meta = doc_metadata(port, Some(&owner), &plain);
    assert!(meta["base"].is_null() && meta["merge"].is_null(), "nothing moved: {meta}");
    let row = changes_since(port, &owner, head).remove(0);
    assert_eq!(row["op"].as_str(), Some("set_arrangement"));
    assert_eq!(row["at"].as_u64(), Some(acked_at(&ack)));
    assert!(row["base"].is_null(), "no base named: {row}");
    assert_eq!(row["merge"], serde_json::json!({"head": v1, "sides": []}), "the request's merge beside no base: {row}");
    // A head naming no registered document — the edition's ninth member,
    // which no mint has made — is refused by its registration, reorder, as
    // on a draft with a chain, nothing written.
    let before = head_position(port);
    let unminted = format!("{edition}.9");
    let v = op(port, Some(&owner), &set_arrangement_frame(&plain, &borrowed(&runs), Some((&unminted, 0)), None, None, None));
    let rej = expect_resp(&v, "rejected");
    assert_eq!((rej["code"].as_str(), rej["disposition"].as_str()), (Some("source_not_registered"), Some("reorder")), "{v}");
    assert_eq!(head_position(port), before, "nothing written");
    assert_eq!(text_of(port, Some(&owner), &plain, 1, 3), "abc");
    // The empty arrangement.
    let ack = op(port, Some(&owner), &set_arrangement_frame(&plain, &[], None, None, None, None));
    expect_resp(&ack, "ack");
    assert_eq!(content_extent(port, Some(&owner), &plain), 0, "emptied");
    // The wire's example, verbatim: parsed and answered as the op.
    let example = r#"{"as_of":12,"base":{"at":"1.0.1.0.1.2","extent":"6"},"doc":"1.0.1.0.2","head":{"at":"1.0.1.0.1.2","extent":"6"},"merge":{"sides":["1.0.1.0.1.1.1"]},"op":"set_arrangement","runs":[{"i_start":"1.0.1.0.1.0.1.1","origin":"1.0.1.0.1","width":"4"},{"i_start":"1.0.1.0.2.0.1.1","origin":"1.0.1.0.2","width":"2"}]}"#;
    let v = op_as_written(port, Some(&owner), example);
    assert_eq!(v["resp"].as_str(), Some("rejected"), "{v}");
    assert_eq!(v["op"].as_str(), Some("set_arrangement"), "the frame is the op: {v}");
    // A run list past the wire's cap is refused at the parse, as a shot's.
    let many: Vec<(String, String, u64)> = (0..4097).map(|_| runs[0].clone()).collect();
    let v = op(port, Some(&owner), &set_arrangement_frame(&plain, &borrowed(&many), None, None, None, None));
    assert_eq!(expect_resp(&v, "rejected")["code"].as_str(), Some("malformed"), "{}", v["detail"]);
    sd.shutdown();
}
