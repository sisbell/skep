//! EDIT over the wire: a list of positional changes to one draft in one
//! commit, under the two names the board takes it by — `edit`, whose
//! changes mint, and `set_arrangement`, whose changes place runs by
//! identity. What this file pins end to end against the real daemon: a
//! call of several changes is one position and one feed row, named as its
//! frame was, and one refused change leaves nothing of it, the refusal
//! naming the change; the ack names the first address minted, the bytes of
//! every change standing from there in the frame's order; the refusal
//! order the board gives; a frame typed before a call's commit refused,
//! whichever edit it is; the frame's caps and the retired whole form
//! refused at the parse; a frame sent again under its `id` landing once,
//! and after a restart refused as typed before its own commit, whose row
//! the feed then shows under the session's key; a landing's base and
//! merge refused on an `edit` frame and carried by `set_arrangement`
//! alone; a `set_arrangement` of one changed stretch landing in a draft of
//! 5,000 runs, whose image the board serves in pages; and the media door
//! and the cell index — a cell no lease binds refused through `edit`, and
//! a bound cell minted through it kept by a pruner pass once its lease has
//! lapsed.
//!
//! Every suite runs post-claim on a CLAIMED-PERMISSIVE board (`spawn`).

use crate::common;

use common::*;
use serde_json::{json, Value};

/// The feed's entries since `since`, as `token` reads them.
fn changes_since(port: u16, token: &str, since: u64) -> Vec<Value> {
    let (st, body) = http(port, "GET", &format!("/changes?since={since}"), Some(token), b"");
    assert_eq!(st, 200, "changes: {}", String::from_utf8_lossy(&body));
    json(&body)["changes"].as_array().expect("changes").clone()
}

/// The rejection `v` carries: its code and the change its site names.
fn refused(v: &Value) -> (String, Option<u64>) {
    let rej = expect_resp(v, "rejected");
    (rej["code"].as_str().unwrap_or_default().to_string(), rej["site"]["index"].as_u64())
}

/// `frame` with the idempotency `id` beside its members.
fn with_id(frame: &str, id: &str) -> String {
    let mut v: Value = serde_json::from_str(frame).expect("a frame");
    v["id"] = json!(id);
    v.to_string()
}

/// ONE COMMIT, ONE ROW. Three changes to `abcdef` land at one position
/// under one `edit` row naming the draft; the ack is `ack_addr`, the first
/// address minted, and the changes' bytes stand from there in the frame's
/// order; a call whose third change runs past the draft is refused naming
/// it, with nothing of the call standing; and a call that mints nothing is
/// acknowledged by `ack`.
#[test]
fn an_edit_of_several_changes_is_one_commit_and_one_row_or_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let draft = draft_with(port, &owner, "abcdef");
    let before = head_position(port);
    // The third change of this call reaches past the draft's six positions.
    let v = op(port, Some(&owner), &edit_frame(&draft, &[(1, 0, "X"), (3, 1, "YY"), (6, 4, "Z")], None));
    assert_eq!(refused(&v), ("out_of_bounds".to_string(), Some(2)), "{v}");
    assert_eq!(head_position(port), before, "a refused call draws no position");
    assert_eq!(text_of(port, Some(&owner), &draft, 1, 6), "abcdef", "and none of its changes stands");
    // X before a; c replaced by YY; f removed and Z put in its place.
    let ack = op(port, Some(&owner), &edit_frame(&draft, &[(1, 0, "X"), (3, 1, "YY"), (6, 1, "Z")], None));
    let at = acked_at(&ack);
    let first = expect_resp(&ack, "ack_addr")["addr"].as_str().expect("the first address minted").to_string();
    assert!(ack.get("head_moved").is_none(), "no head named: {ack}");
    assert_eq!(text_of(port, Some(&owner), &draft, 1, 8), "XabYYdeZ");
    assert_eq!(at, head_position(port), "one commit, the ack's position the head");
    // The four bytes minted stand at consecutive addresses in the frame's
    // order: X, then YY, then Z, each change's first the ack's plus the
    // bytes of the changes before it.
    let ordinal = |addr: &str| addr.rsplit('.').next().and_then(|n| n.parse::<u64>().ok()).expect("an ordinal");
    let stem = first.rsplit_once('.').expect("an address").0.to_string();
    let image = image_runs(port, Some(&owner), &draft, 1, 8);
    let minted: Vec<(u64, u64)> = image.iter().filter(|(start, _)| ordinal(start) >= ordinal(&first) && start.starts_with(&stem)).map(|(start, w)| (ordinal(start) - ordinal(&first), *w)).collect();
    assert_eq!(minted, vec![(0, 1), (1, 2), (3, 1)], "X, YY and Z from the ack's address on: {image:?}");
    let rows = changes_since(port, &owner, before);
    assert_eq!(rows.len(), 1, "one call, one row: {rows:?}");
    let row = &rows[0];
    assert_eq!((row["op"].as_str(), row["at"].as_u64()), (Some("edit"), Some(at)), "{row}");
    assert_eq!(row["docs"], json!([draft]), "{row}");
    assert!(row["base"].is_null() && row["merge"].is_null(), "a text edit names neither term: {row}");
    // A call that only removes mints nothing, and is acknowledged by `ack`.
    let ack = op(port, Some(&owner), &edit_frame(&draft, &[(1, 1, ""), (4, 2, "")], None));
    expect_resp(&ack, "ack");
    assert_eq!(text_of(port, Some(&owner), &draft, 1, 5), "abdeZ");
    sd.shutdown();
}

/// THE REFUSAL ORDER the board gives, one cell a pair of adjacent refusals,
/// nothing written by any: a draft that is not registered, then one the
/// caller does not own, then a published target, then the typed state, then
/// the landing's terms, then the empty call, then each change's shape — the
/// first defective change naming itself. A frame typed before a call's own
/// commit is refused whichever of the edits it is, and a frame typed at it
/// lands.
#[test]
fn the_board_refuses_an_edit_in_one_order_and_types_every_edit_against_its_commit() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let stranger = seat_stranger(port, 77);
    let edition = edition_with(port, &signed, "abc");
    let draft = draft_with(port, &owner, "abcdef");
    let typed = head_position(port);
    let stale = typed - 1;
    let bad = [(9, 9, "q")];
    // Not registered, ahead of everything; not the caller's, ahead of the
    // typed state and the shapes.
    let ghost = format!("{}.0.9999", CLAIMANT_ACCOUNT);
    assert_eq!(refused(&op(port, Some(&owner), &edit_frame(&ghost, &bad, stale))).0, "doc_not_registered");
    assert_eq!(refused(&op(port, Some(&stranger.session), &edit_frame(&draft, &bad, stale))).0, "not_owner");
    // A published target, ahead of the typed state: under both names, from
    // the signed owner; the bare session meets the publish-class gate first.
    assert_eq!(refused(&op(port, Some(&signed), &edit_frame(&edition, &bad, stale))).0, "published_target");
    assert_eq!(refused(&op(port, Some(&signed), &changes_frame("set_arrangement", &edition, &[(9, 9, &[])], None, None, None, stale))).0, "published_target");
    assert_eq!(verdict(&op(port, Some(&owner), &edit_frame(&edition, &bad, stale))), GATED);
    // The typed state, ahead of the terms and of every shape.
    let v = op(port, Some(&owner), &edit_frame(&draft, &bad, stale));
    let rej = expect_resp(&v, "rejected");
    assert_eq!(rej["code"].as_str(), Some("arrangement_moved"), "{v}");
    assert_eq!((rej["site"]["as_of"].as_u64(), rej["site"]["current"].as_u64()), (Some(stale), Some(typed)), "{v}");
    let unminted = format!("{edition}.9");
    let v = op(port, Some(&owner), &changes_frame("set_arrangement", &draft, &[(9, 9, &[])], Some((&unminted, 0)), None, None, stale));
    assert_eq!(refused(&v).0, "arrangement_moved", "ahead of the head's registration: {v}");
    let v = op(port, Some(&owner), &changes_frame("set_arrangement", &draft, &[(9, 9, &[])], Some((&unminted, 0)), None, None, typed));
    assert_eq!(refused(&v).0, "source_not_registered", "the terms ahead of the shapes: {v}");
    // The empty call, then the shapes, each naming its change.
    assert_eq!(refused(&op(port, Some(&owner), &edit_frame(&draft, &[], typed))), ("empty_result".to_string(), None));
    for (changes, code, index) in [
        (vec![(2, 1, "q"), (8, 1, "q")], "not_arranged", 1),
        (vec![(2, 1, "q"), (6, 2, "q")], "out_of_bounds", 1),
        (vec![(8, 0, "q")], "out_of_bounds", 0),
        (vec![(1, 1, "q"), (3, 0, "")], "empty_result", 1),
    ] {
        let v = op(port, Some(&owner), &edit_frame(&draft, &changes, typed));
        assert_eq!(refused(&v), (code.to_string(), Some(index)), "{changes:?}: {v}");
    }
    let link = format!(r#"{{"op":"edit","doc":"{draft}","changes":[{{"at":{{"subspace":"2","ordinal":"1"}},"width":"9","values":["q"]}}],"as_of":{typed}}}"#);
    assert_eq!(refused(&op(port, Some(&owner), &link)), ("not_content_subspace".to_string(), Some(0)));
    assert_eq!(head_position(port), typed, "every refusal commits nothing");
    // A call lands; each of the six edits typed before it is then refused.
    let landed = acked_at(&op(port, Some(&owner), &edit_frame(&draft, &[(1, 1, "A")], typed)));
    let run = image_runs(port, Some(&owner), &draft, 2, 1).into_iter().next().expect("a run");
    let by_identity = [(origin_of(&run.0), run.0.clone(), 1u64)];
    let by_identity: Vec<(&str, &str, u64)> = by_identity.iter().map(|(o, s, w)| (o.as_str(), s.as_str(), *w)).collect();
    for frame in [
        edit_frame(&draft, &[(1, 1, "B")], typed),
        changes_frame("set_arrangement", &draft, &[(1, 1, &by_identity)], None, None, None, typed),
        insert_frame(&draft, 1, "B", false, typed),
        delete_frame(&draft, 1, 1, typed),
        copy_frame(&draft, 1, &edition, 1, 1, typed),
        reinstate_frame(&draft, 1, &by_identity, typed),
        rearrange_frame(&draft, [1, 2, 3], typed),
    ] {
        let v = op(port, Some(&owner), &frame);
        let rej = expect_resp(&v, "rejected");
        assert_eq!(rej["code"].as_str(), Some("arrangement_moved"), "{frame}: {v}");
        assert_eq!(rej["site"]["current"].as_u64(), Some(landed), "{frame}: {v}");
    }
    expect_resp(&op(port, Some(&owner), &edit_frame(&draft, &[(1, 1, "B")], landed)), "ack_addr");
    assert_eq!(text_of(port, Some(&owner), &draft, 1, 6), "Bbcdef");
    sd.shutdown();
}

/// THE FRAME. Out of order and overlapping changes, a list one past the
/// wire's cap, an `attest` under either name and the retired whole form are
/// each refused `malformed` at the parse, nothing written; changes that
/// touch land.
#[test]
fn the_parse_refuses_a_misordered_an_overlong_an_attested_and_a_whole_form_frame() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let draft = draft_with(port, &owner, "abcdef");
    let before = head_position(port);
    let malformed = |frame: &str| {
        let v = op_as_written(port, Some(&owner), frame);
        let rej = expect_resp(&v, "rejected");
        assert_eq!(rej["code"].as_str(), Some("malformed"), "{}: {v}", &frame[..frame.len().min(160)]);
        rej["site"]["index"].as_u64()
    };
    assert_eq!(malformed(&edit_frame(&draft, &[(4, 0, "x"), (2, 0, "y")], before)), Some(1), "out of order");
    assert_eq!(malformed(&edit_frame(&draft, &[(2, 3, "x"), (4, 0, "y")], before)), Some(1), "overlapping");
    let many: Vec<(u64, u64, &str)> = (0..4097).map(|_| (1, 0, "x")).collect();
    assert_eq!(malformed(&edit_frame(&draft, &many, before)), None, "one change past the cap");
    let attested = |frame: String| format!(r#"{},"attest":{{"alg":"ed25519","sig":"00"}}}}"#, &frame[..frame.len() - 1]);
    malformed(&attested(edit_frame(&draft, &[(1, 0, "x")], before)));
    malformed(&attested(set_arrangement_frame(&draft, 0, &[], Some((&draft, 0)), None, None, before)));
    let run = image_runs(port, Some(&owner), &draft, 1, 6).into_iter().next().expect("the draft's run");
    let whole = format!(r#"{{"op":"set_arrangement","doc":"{draft}","runs":[{}],"as_of":{before}}}"#, common::run(&origin_of(&run.0), &run.0, run.1));
    malformed(&whole);
    // A change of the other name's member is no change of this frame's.
    malformed(&format!(r#"{{"op":"edit","doc":"{draft}","changes":[{{"at":{{"subspace":"1","ordinal":"1"}},"width":"0","runs":[]}}],"as_of":{before}}}"#));
    assert_eq!(head_position(port), before, "nothing written");
    // Two changes that touch: the second begins where the first's removal ends.
    expect_resp(&op(port, Some(&owner), &edit_frame(&draft, &[(2, 2, "X"), (4, 0, "Y")], before)), "ack_addr");
    assert_eq!(text_of(port, Some(&owner), &draft, 1, 6), "aXYdef");
    sd.shutdown();
}

/// A FRAME SENT AGAIN. Under its `id` in the session that sent it, an edit
/// is answered the acknowledgment it was given and lands once. After a
/// restart the board remembers no `id`: the same frame is judged afresh and
/// refused as typed before its own commit, nothing landed twice — and the
/// feed past the typed state shows the call's row first, an `edit` naming
/// the draft under the session's key, which is what tells its sender the
/// call landed.
#[test]
fn an_edit_sent_again_lands_once_and_its_row_tells_a_sender_who_lost_the_answer() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let draft = draft_with(port, &owner, "abc");
    let typed = head_position(port);
    let frame = with_id(&edit_frame(&draft, &[(2, 0, "XY")], typed), "edit-once");
    let first = op_as_written(port, Some(&owner), &frame);
    let at = acked_at(&first);
    let again = op_as_written(port, Some(&owner), &frame);
    assert_eq!(again, first, "the acknowledgment it was given, its address among it");
    assert_eq!(head_position(port), at, "nothing committed by the second ask");
    assert_eq!(text_of(port, Some(&owner), &draft, 1, 5), "aXYbc", "landed once");
    sd.shutdown();
    // The restart: every token and every remembered `id` is gone.
    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let v = op_as_written(port, Some(&owner), &frame);
    let rej = expect_resp(&v, "rejected");
    assert_eq!(rej["code"].as_str(), Some("arrangement_moved"), "judged afresh, typed before its own commit: {v}");
    assert_eq!((rej["site"]["as_of"].as_u64(), rej["site"]["current"].as_u64()), (Some(typed), Some(at)), "{v}");
    assert_eq!(text_of(port, Some(&owner), &draft, 1, 5), "aXYbc", "never applied twice");
    let (st, body) = http(port, "GET", &format!("/changes?under={draft}&since={typed}"), Some(&owner), b"");
    assert_eq!(st, 200, "{}", String::from_utf8_lossy(&body));
    let rows = json(&body)["changes"].as_array().expect("changes").clone();
    let row = rows.first().expect("the call's row, the first past the typed state");
    assert_eq!((row["op"].as_str(), row["at"].as_u64(), row["key"].as_str()), (Some("edit"), Some(at), Some("bare")), "{row}");
    assert_eq!(row["docs"], json!([draft]), "{row}");
    sd.shutdown();
}

/// **The feed's names, and a landing's one name.** One operation, two rows by
/// the name its frame came under: an `edit` frame's row is `edit`, a
/// `set_arrangement` frame's is `set_arrangement`. A landing is
/// `set_arrangement`'s alone: an `edit` frame carrying `base`, and one
/// carrying `merge` beside `head`, are each refused at the parse, nothing
/// written and no row; a landing under `set_arrangement` records its base
/// and stamps its marker, its row carrying both, and tells a head the trunk
/// has moved past beside its ack; and an `edit` naming such a head lands and
/// tells the same, its row carrying no landing's terms.
#[test]
fn the_feed_names_a_call_by_its_frame_and_a_landing_is_set_arrangements_alone() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let edition = edition_with(port, &signed, "abc");
    let v1 = acked_addr(&version_of(port, &signed, &edition, None));
    let draft = stage_of(port, &owner, &v1);
    let side = format!("{v1}.1");
    let before = head_position(port);
    // A landing that changes no position: no change at all beside its base
    // and its merge.
    let ack = op(port, Some(&owner), &set_arrangement_frame(&draft, 0, &[], Some((&v1, 3)), Some((&v1, 3)), Some(&[&side]), None));
    let landed = acked_at(expect_resp(&ack, "ack"));
    let meta = doc_metadata(port, Some(&owner), &draft);
    assert_eq!(meta["merge"]["at"].as_u64(), Some(landed), "the marker stamped at the landing: {meta}");
    assert_eq!(meta["arranged_at"].as_u64(), Some(landed), "and the draft's position moved by a call of no change: {meta}");
    assert_eq!(text_of(port, Some(&owner), &draft, 1, 3), "abc", "no position changed");
    // The head moves on.
    let v2 = acked_addr(&version_of(port, &signed, &edition, None));
    // An `edit` frame carries no landing: its base, and its merge beside a
    // head, are each an unknown field of the frame.
    let minting = |members: Value| {
        let mut frame: Value = serde_json::from_str(&edit_frame(&draft, &[(4, 0, "!")], None)).expect("a frame");
        for (name, member) in members.as_object().expect("members") {
            frame[name] = member.clone();
        }
        frame.to_string()
    };
    let unlanded = head_position(port);
    for (members, named) in [
        (json!({"base": {"at": v1, "extent": "3"}}), "unknown field 'base'"),
        (json!({"head": {"at": v1, "extent": "3"}, "merge": {"sides": [side]}}), "unknown field 'merge'"),
    ] {
        let refusal = op(port, Some(&owner), &minting(members));
        let rejection = expect_resp(&refusal, "rejected");
        assert_eq!((rejection["code"].as_str(), rejection["op"].as_str()), (Some("malformed"), Some("unparseable")), "{rejection}");
        assert!(rejection["detail"].as_str().is_some_and(|detail| detail.contains(named)), "{rejection}");
    }
    assert_eq!(head_position(port), unlanded, "nothing written");
    assert_eq!(text_of(port, Some(&owner), &draft, 1, 4), "abc", "and nothing minted");
    assert_eq!(doc_metadata(port, Some(&owner), &draft)["merge"]["at"].as_u64(), Some(landed), "the marker as the first landing left it");
    // A second landing, under the one name a landing has, placing the
    // draft's own first byte at its end and naming the head it read.
    let first = image_runs(port, Some(&owner), &draft, 1, 1).into_iter().next().expect("the first run");
    let placed = [(origin_of(&first.0), first.0.clone(), 1u64)];
    let placed: Vec<(&str, &str, u64)> = placed.iter().map(|(o, s, w)| (o.as_str(), s.as_str(), *w)).collect();
    let ack = op(port, Some(&owner), &changes_frame("set_arrangement", &draft, &[(4, 0, &placed)], Some((&v1, 3)), Some((&v1, 3)), Some(&[&side]), None));
    let relanded = acked_at(expect_resp(&ack, "ack"));
    assert_eq!(ack["head_moved"].as_str(), Some(v2.as_str()), "the tell rides the landing's ack: {ack}");
    assert_eq!(doc_metadata(port, Some(&owner), &draft)["merge"]["at"].as_u64(), Some(relanded));
    assert_eq!(text_of(port, Some(&owner), &draft, 1, 4), "abca");
    // An edit naming the head it read: it lands, and tells the same.
    let ack = op(port, Some(&owner), &minting(json!({"head": {"at": v1, "extent": "3"}})));
    let minted_at = acked_at(expect_resp(&ack, "ack_addr"));
    assert_eq!(ack["head_moved"].as_str(), Some(v2.as_str()), "the tell rides the address ack: {ack}");
    assert_eq!(text_of(port, Some(&owner), &draft, 1, 5), "abc!a");
    assert_eq!(doc_metadata(port, Some(&owner), &draft)["merge"]["at"].as_u64(), Some(relanded), "an edit stamps no marker");
    let rows: Vec<Value> = changes_since(port, &owner, before).into_iter().filter(|r| r["docs"] == json!([draft])).collect();
    let named: Vec<(Option<&str>, Option<u64>)> = rows.iter().map(|r| (r["op"].as_str(), r["at"].as_u64())).collect();
    assert_eq!(
        named,
        vec![(Some("set_arrangement"), Some(landed)), (Some("set_arrangement"), Some(relanded)), (Some("edit"), Some(minted_at))],
        "the refused frames left no row: {rows:?}"
    );
    for row in &rows[..2] {
        assert_eq!(row["base"].as_str(), Some(v1.as_str()), "the base its frame named: {row}");
        assert_eq!(row["merge"], json!({"head": v1, "sides": [side]}), "the merge its frame named: {row}");
    }
    assert!(rows[2]["base"].is_null() && rows[2]["merge"].is_null(), "an edit's row carries no landing: {}", rows[2]);
    sd.shutdown();
}

/// A DRAFT PAST THE IMAGE'S RUN BUDGET TAKES A WRITE. One call of 2,500
/// placements cuts a draft's one run into 5,000; the board then serves its
/// image a page at a time, and a `set_arrangement` of one changed stretch —
/// one change naming two positions, placing one run by identity — lands
/// reading none of it, every other run of the draft standing; so does an
/// `edit` there.
#[test]
fn a_draft_of_five_thousand_runs_takes_a_change_of_one_stretch() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let draft = draft_with(port, &owner, &"a".repeat(2_501));
    // A byte placed before each of positions 2 to 2,501: the one run of
    // 2,501 cut into 2,501 pieces, 2,500 minted bytes between them.
    let cuts: Vec<(u64, u64, &str)> = (2..=2_501).map(|at| (at, 0, "b")).collect();
    expect_resp(&op(port, Some(&owner), &edit_frame(&draft, &cuts, None)), "ack_addr");
    assert_eq!(content_extent(port, Some(&owner), &draft), 5_001);
    let whole = op(port, Some(&owner), &image_frame(&draft, 1, 5_001));
    assert_eq!(expect_resp(&whole, "image_page")["ispans"].as_array().map(Vec::len), Some(4_096), "5,001 runs, the first page of them");
    assert_eq!(text_of(port, Some(&owner), &draft, 1, 7), "abababa");
    // One stretch: positions 3 and 4 (`a`, `b`) replaced by the draft's own
    // first byte, placed by identity.
    let first = image_runs(port, Some(&owner), &draft, 1, 1).into_iter().next().expect("the first run");
    let placed = [(origin_of(&first.0), first.0.clone(), 1u64)];
    let placed: Vec<(&str, &str, u64)> = placed.iter().map(|(o, s, w)| (o.as_str(), s.as_str(), *w)).collect();
    let before = head_position(port);
    let ack = op(port, Some(&owner), &changes_frame("set_arrangement", &draft, &[(3, 2, &placed)], None, None, None, None));
    let at = acked_at(expect_resp(&ack, "ack"));
    assert_eq!(at, before + 1, "one commit of one record");
    assert_eq!(content_extent(port, Some(&owner), &draft), 5_000, "two positions gone, one placed");
    assert_eq!(text_of(port, Some(&owner), &draft, 1, 7), "abaabab", "the stretch changed, its neighbours standing");
    assert_eq!(text_of(port, Some(&owner), &draft, 4_994, 7), "abababa", "and the draft's far end as it stood");
    // And a text edit there, which reads no image either.
    expect_resp(&op(port, Some(&owner), &edit_frame(&draft, &[(5_000, 1, "Z")], None)), "ack_addr");
    assert_eq!(text_of(port, Some(&owner), &draft, 4_998, 3), "abZ");
    sd.shutdown();
}

/// THE MEDIA DOOR AND THE CELL INDEX (M-I1 (a); M-I5 (b)). An `edit` whose
/// second change mints a cell over bytes no lease of the principal's holds
/// is refused `unbound_cell`, nothing written — the insert's arm, read over
/// every change's values (the mutant that gives the frame the door's no-arm
/// branch lands it). The bytes deposited, the same frame lands, and its
/// commit enters the cell in the cell index: the lease lapsed, a pruner
/// pass keeps the file, a reference kept by no lease, where a file no cell
/// names is unlinked beside it (the mutant whose commit does not enter an
/// edit's cells unlinks both, the cell left naming bytes the board no
/// longer holds).
#[test]
fn an_edit_mints_a_cell_through_the_media_door_and_its_commit_enters_the_cell_index() {
    const LEASE_MS: u64 = 7 * 24 * 3600 * 1000;
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let token = open_session(port, CLAIMANT_PRINCIPAL);
    let (named, unnamed) = (seeded_bytes(3_000, 1), seeded_bytes(4_000, 2));
    let draft = owner_draft(port, &token);
    let frame = |bytes: &[u8]| {
        json!({
            "op": "edit", "doc": draft,
            "changes": [
                {"at": {"subspace": "1", "ordinal": "1"}, "width": "0", "values": ["caption "]},
                {"at": {"subspace": "1", "ordinal": "1"}, "width": "0", "values": [{"atom": cell_of(bytes, bytes.len() as u64)}]},
            ],
        })
        .to_string()
    };
    let before = head_position(port);
    assert_eq!(verdict(&op(port, Some(&token), &frame(&named))), "credential_refused:unbound_cell", "no lease binds the bytes");
    assert_eq!((head_position(port), own_count(port, &token, &draft)), (before, 0), "nothing written");
    put_whole(port, &token, &named);
    put_whole(port, &token, &unnamed);
    assert_eq!(verdict(&op(port, Some(&token), &frame(&named))), "ok", "bound by the principal's own lease");
    assert_eq!(own_count(port, &token, &draft), 9, "the caption's eight bytes and the cell's one position");
    sd.daemon().advance_media_clock_ms(LEASE_MS);
    let pass = sd.daemon().prune_now().expect("the index is ready");
    assert_eq!((pass.unlinked, pass.kept, pass.halted.as_deref()), (1, 1, None), "{pass:?}");
    let blobs = dir.path().join("blobs").join("blake3");
    assert!(blobs.join(blob_hex(&named)).is_file(), "named by the cell the edit minted: kept past its lease");
    assert!(!blobs.join(blob_hex(&unnamed)).exists(), "lapsed and unnamed: gone");
    sd.shutdown();
}
