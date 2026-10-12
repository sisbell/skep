//! REINSTATE over the wire — THE WRITE BY IDENTITY (the replacement act's
//! record; the owner's ruling E2 (a): undo restores the SAME bytes): runs of
//! permanent content I-addresses placed into a draft at a position, so a
//! removed span comes back at its own addresses and every link on it
//! returns. What this file pins end to end against the real daemon: the
//! link's return at the SAME link address (T2); a published document's
//! refusal by name — the store's `published_target` from the signed owner,
//! the gate's `signed_session_required` from a bare session on the claimed
//! board, a member of the chain judged as its document — and the document
//! unchanged (T3); a staging draft's reinstated run of the edition's own
//! bytes riding the next shot BY REFERENCE, a public link on the edition's
//! paragraph surviving the new version (T7); the wire's frame answered as
//! the op; and the store's guard order as the daemon lowers it, a write on
//! `/op-at` included. The door's consult — `withheld`, the wide reach — is
//! `source_gate.rs`'s; the feed row is `changes.rs`'s.
//!
//! Every suite runs post-claim on a CLAIMED-PERMISSIVE board (`spawn`): the
//! claimant's doc 1 is a published document, holding the ceremony's one
//! record atom at content ordinal 1; its later flagless mints are drafts.

use crate::common;

use common::*;
use serde_json::Value;

/// `doc`'s content element at `ordinal` — M3's minted shape, `doc.0.1.k`.
fn element(doc: &str, ordinal: u64) -> String {
    format!("{doc}.0.1.{ordinal}")
}

/// One run as the client states it: the origin, the first address, the
/// width — the publish shot's form.
fn run(origin: &str, i_start: &str, width: u64) -> String {
    format!(r#"{{"origin":"{origin}","i_start":"{i_start}","width":"{width}"}}"#)
}

fn reinstate(doc: &str, at: u64, runs: &[String]) -> String {
    format!(
        r#"{{"op":"reinstate","doc":"{doc}","at":{{"subspace":"1","ordinal":"{at}"}},"runs":[{}]}}"#,
        runs.join(",")
    )
}

/// The shot: `base` with the extent the staged copy took (both or neither),
/// the staging `draft` when there is one, and the runs.
fn publish(doc: &str, base: Option<(&str, u64)>, draft: Option<&str>, runs: &[String]) -> String {
    let base = base
        .map(|(m, extent)| format!(r#","base":"{m}","base_extent":"{extent}""#))
        .unwrap_or_default();
    let draft = draft.map(|d| format!(r#","draft":"{d}""#)).unwrap_or_default();
    format!(r#"{{"op":"publish","doc":"{doc}"{base}{draft},"runs":[{}]}}"#, runs.join(","))
}

/// A `make_link` homed in `home` whose `from` RESOLVES content ordinals
/// `from ..` of `source` — the recorded endset is that span's permanent
/// I-addresses — its `to` empty, its `ty` a ghost under `home`.
fn link_from(port: u16, session: &str, home: &str, source: &str, from: u64, width: u64, ghost: u64) -> String {
    acked_addr(&op(
        port,
        Some(session),
        &format!(
            r#"{{"op":"make_link","home":"{home}","from":[{{"source":"{source}","span":{{"start":"1.{from}","width":"0.{width}"}}}}],"to":{{"addrs":[]}},"ty":{{"addrs":["{home}.0.3.6.{ghost}"]}}}}"#
        ),
    ))
}

fn region(doc: &str, from: u64, width: u64) -> String {
    format!(r#""d":"{doc}","region":[{{"start":"1.{from}","width":"0.{width}"}}]"#)
}

/// The active links whose endsets touch content ordinals `from ..` of
/// `doc` — the region read, through the arrangement.
fn count_v(port: u16, token: Option<&str>, doc: &str, from: u64, width: u64) -> u64 {
    let v = op(port, token, &format!(r#"{{"op":"count_v",{}}}"#, region(doc, from, width)));
    expect_resp(&v, "count")["n"].as_u64().expect("n")
}

fn links_v(port: u16, token: Option<&str>, doc: &str, from: u64, width: u64) -> Vec<String> {
    addrs_of(&op(port, token, &format!(r#"{{"op":"find_links_v",{}}}"#, region(doc, from, width))))
}

/// The links whose `from` end covers the I-SPAN `[i_start, +width)` — the
/// descriptor read, which matches the link store's recorded endsets and
/// reads no arrangement.
fn links_from_i(port: u16, token: Option<&str>, i_start: &str, width: u64) -> Vec<String> {
    let width = width.to_string();
    let mut comps = vec!["0"; i_start.split('.').count() - 1];
    comps.push(width.as_str());
    let w = comps.join(".");
    addrs_of(&op(
        port,
        token,
        &format!(
            r#"{{"op":"find_links_ftt","q":{{"home":"any","from":[{{"start":"{i_start}","width":"{w}"}}],"to":"any","ty":"any"}}}}"#
        ),
    ))
}

/// The V→I image of content ordinals `from ..` of `doc`: `(i_start, width)`.
fn image(port: u16, token: Option<&str>, doc: &str, from: u64, width: u64) -> Vec<(String, String)> {
    let v = op(port, token, &format!(r#"{{"op":"image",{}}}"#, region(doc, from, width)));
    expect_resp(&v, "runs")["runs"]
        .as_array()
        .expect("runs")
        .iter()
        .map(|r| {
            (
                r["i_start"].as_str().expect("i_start").to_string(),
                r["width"].as_str().expect("width").to_string(),
            )
        })
        .collect()
}

/// The per-byte text at content ordinals `from ..` of `doc`.
fn text(port: u16, token: Option<&str>, doc: &str, from: u64, width: u64) -> String {
    let v = op(
        port,
        token,
        &format!(
            r#"{{"op":"retrieve_v","specs":[{{"doc":"{doc}","span":{{"start":"1.{from}","width":"0.{width}"}}}}]}}"#
        ),
    );
    expect_resp(&v, "delivery")["items"]
        .as_array()
        .expect("items")
        .iter()
        .map(|i| i["content"].as_str().unwrap_or(""))
        .collect()
}

/// The content extent `doc` answers — its content span's width, `0` when
/// the set carries none.
fn content_extent(port: u16, token: Option<&str>, doc: &str) -> u64 {
    let v = op(port, token, &format!(r#"{{"op":"retrieve_doc_v_span_set","doc":"{doc}"}}"#));
    expect_resp(&v, "span_set")["set"]
        .as_array()
        .expect("set")
        .iter()
        .find(|s| s["start"].as_str() == Some("1.1"))
        .map(|s| {
            s["width"]
                .as_str()
                .expect("width")
                .strip_prefix("0.")
                .expect("a depth-2 width")
                .parse()
                .expect("a count")
        })
        .unwrap_or(0)
}

/// A PERMANENT store refusal carrying neither `detail` nor `site`.
fn assert_permanent(v: &Value, code: &str) {
    let rej = expect_resp(v, "rejected");
    assert_eq!(rej["code"].as_str(), Some(code), "{v}");
    assert_eq!(rej["disposition"].as_str(), Some("permanent"), "a permanent class: {v}");
    assert!(rej.get("detail").is_none(), "no detail rides the code: {v}");
    assert!(rej.get("site").is_none() || rej["site"].is_null(), "no site rides the code: {v}");
}

/// T2 — THE ACT, end to end (the owner's ruling: undo restores the SAME
/// bytes). A link made on a span of a draft; the span deleted, after which
/// no region read finds the link — though the link stands, its endset the
/// permanent I-span, as the descriptor read shows; the span REINSTATED at
/// its own addresses, and the link is found again by the region reads at
/// the SAME address: no new link, no new bytes, one run as before.
#[test]
fn a_reinstated_span_brings_its_links_back_at_the_same_address() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let token = Some(owner.as_str());
    let draft = draft_with(port, &owner, "hello world");
    // The census over the span before any link of this test's: the claim
    // ceremony's links, homed in doc 1, name the claimant's ACCOUNT by
    // address and so reach every region under it — the floor every count
    // below stands on.
    let floor = count_v(port, token, &draft, 3, 4);
    let link = link_from(port, &owner, &draft, &draft, 3, 4, 1);
    assert_eq!(count_v(port, token, &draft, 3, 4), floor + 1, "premise: the link on positions 3–6");
    assert!(links_v(port, token, &draft, 3, 4).contains(&link));
    // The I-run under the span, imaged while the arrangement still speaks
    // for it — what an editor keeps for its undo entry.
    let i_start = element(&draft, 3);
    assert_eq!(image(port, token, &draft, 3, 4), vec![(i_start.clone(), "4".to_string())]);

    expect_resp(&op(port, token, &delete_frame(&draft, 3, 4)), "ack");
    assert_eq!(text(port, token, &draft, 1, 7), "heworld");
    assert_eq!(count_v(port, token, &draft, 3, 4), floor, "the suffix shifted in: the link is on no position");
    assert!(!links_v(port, token, &draft, 1, 7).contains(&link), "no arranged position carries the link");
    let by_identity = links_from_i(port, token, &i_start, 4);
    assert!(by_identity.contains(&link), "the link stands, at its permanent I-span: {by_identity:?}");

    expect_resp(&op(port, token, &reinstate(&draft, 3, &[run(&draft, &i_start, 4)])), "ack");
    assert_eq!(text(port, token, &draft, 1, 11), "hello world");
    assert_eq!(
        image(port, token, &draft, 1, 11),
        vec![(element(&draft, 1), "11".to_string())],
        "one run again: the same addresses, coalesced as before the delete"
    );
    assert_eq!(count_v(port, token, &draft, 3, 4), floor + 1, "the link is back");
    assert!(links_v(port, token, &draft, 3, 4).contains(&link));
    assert_eq!(
        links_from_i(port, token, &i_start, 4),
        by_identity,
        "the SAME link address: nothing was re-made, nothing minted"
    );

    sd.shutdown();
}

/// T3 — the published arm (the record's Q3: refused by name). From the
/// signed OWNER, the store's own `published_target` — permanent, no site,
/// no detail; from a BARE session on the claimed board, the daemon's
/// publish-class gate first — `signed_session_required`, slot 4 ahead of
/// slot 5 (PUB-6.36); a version member of the chain is judged as its
/// document (PUB-2.15); and the document is unchanged — no commit, the same
/// extent. Into a draft the same run lands: the control.
#[test]
fn a_reinstate_into_a_published_document_is_refused_by_name_and_the_document_is_unchanged() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let bare = open_session(port, CLAIMANT_PRINCIPAL);
    let draft = draft_with(port, &bare, "ab");
    let own = run(&draft, &element(&draft, 1), 2);
    let extent = content_extent(port, None, CLAIMANT_DOC1);
    assert!(extent >= 1, "premise: doc 1 holds the ceremony's atom");

    let before = head_position(port);
    assert_permanent(
        &op(port, Some(&signed), &reinstate(CLAIMANT_DOC1, extent + 1, &[own.clone()])),
        "published_target",
    );
    assert_eq!(
        verdict(&op(port, Some(&bare), &reinstate(CLAIMANT_DOC1, extent + 1, &[own.clone()]))),
        "credential_refused:signed_session_required",
        "a bare session on the claimed board: the gate ahead of the store"
    );
    assert_eq!(head_position(port), before, "no refusal commits");
    assert_eq!(content_extent(port, None, CLAIMANT_DOC1), extent, "the document is unchanged");

    // A MEMBER of the chain — the birth version, shot off the memberless
    // document with its atom by reference — answers as its document.
    let member = acked_addr(&op(
        port,
        Some(&signed),
        &publish(
            CLAIMANT_DOC1,
            Some((CLAIMANT_DOC1, extent)),
            None,
            &[run(CLAIMANT_DOC1, &element(CLAIMANT_DOC1, 1), extent)],
        ),
    ));
    let before = head_position(port);
    assert_permanent(
        &op(port, Some(&signed), &reinstate(&member, extent + 1, &[own.clone()])),
        "published_target",
    );
    assert_eq!(
        verdict(&op(port, Some(&bare), &reinstate(&member, extent + 1, &[own.clone()]))),
        "credential_refused:signed_session_required"
    );
    assert_eq!(head_position(port), before);
    assert_eq!(content_extent(port, None, &member), extent);

    // The control: into the draft, the same run lands — a duplicate of its
    // own two positions, as `copy` would place one.
    expect_resp(&op(port, Some(&bare), &reinstate(&draft, 3, &[own])), "ack");
    assert_eq!(text(port, Some(&bare), &draft, 1, 4), "abab");

    sd.shutdown();
}

/// T7 — the act's larger stake (the record's P4): a staging draft of a
/// published document holds the edition's own bytes by reference; a span
/// of them is removed and REINSTATED at its own addresses; the next shot
/// places that run BY REFERENCE — the member's positions are the edition's
/// own I-addresses, not fresh identity — so a PUBLIC link on the edition's
/// paragraph, homed in doc 1, is found on the new member. The inverse
/// insert the editor used to make would have been draft-native text,
/// re-minted at the shot, and the link lost in the new version.
#[test]
fn a_reinstated_run_of_the_editions_own_bytes_rides_the_next_shot_by_reference_with_its_link() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let mine = Some(owner.as_str());

    // THE EDITION, with prose of its own: a second published document of the
    // claimant's, its birth version shot from a draft holding "hello" — five
    // positions re-inserted as the edition's OWN I-space.
    let edition = published_edition(port, &signed);
    let d0 = draft_with(port, &owner, "hello");
    let member1 = acked_addr(&op(
        port,
        Some(&signed),
        &publish(&edition, None, Some(&d0), &[run(&d0, &element(&d0, 1), 5)]),
    ));
    let own_run = (element(&edition, 1), "5".to_string());
    assert_eq!(image(port, None, &member1, 1, 5), vec![own_run.clone()], "the edition's own I-space");
    assert_eq!(text(port, None, &member1, 1, 5), "hello");
    // The census floor: the ceremony's links name the claimant's account
    // and reach every region under it (as in T2).
    let floor = count_v(port, None, &member1, 2, 2);
    // A PUBLIC link on the edition's positions 2–3 ("el"): homed in doc 1,
    // its `from` resolving the member's span, so its endset is the edition's
    // own addresses 2–3.
    let plink = link_from(port, &signed, CLAIMANT_DOC1, &member1, 2, 2, 71);
    assert_eq!(count_v(port, None, &member1, 2, 2), floor + 1);
    assert!(links_v(port, None, &member1, 2, 2).contains(&plink));

    // THE STAGING DRAFT (PUB-2.27): the member's five positions by reference.
    let d1 = owner_draft(port, &owner);
    expect_resp(&op(port, mine, &copy_frame(&d1, 1, &member1, 1, 5)), "ack");
    assert_eq!(image(port, mine, &d1, 1, 5), vec![own_run.clone()]);
    assert!(links_v(port, mine, &d1, 2, 2).contains(&plink), "the public link reaches the draft's copy");
    let floor_d1 = count_v(port, mine, &d1, 2, 2) - 1;

    // THE EDIT: positions 2–3 removed — the link is on no position of the
    // draft — then REINSTATED at their own addresses.
    expect_resp(&op(port, mine, &delete_frame(&d1, 2, 2)), "ack");
    assert_eq!(text(port, mine, &d1, 1, 3), "hlo");
    assert_eq!(count_v(port, mine, &d1, 2, 2), floor_d1);
    assert!(!links_v(port, mine, &d1, 1, 3).contains(&plink), "the link is on no position of the draft");
    expect_resp(
        &op(port, mine, &reinstate(&d1, 2, &[run(&edition, &element(&edition, 2), 2)])),
        "ack",
    );
    assert_eq!(text(port, mine, &d1, 1, 5), "hello");
    assert_eq!(image(port, mine, &d1, 1, 5), vec![own_run.clone()], "whole again, one run");
    assert_eq!(count_v(port, mine, &d1, 2, 2), floor_d1 + 1, "the link is back on the draft");
    assert!(links_v(port, mine, &d1, 2, 2).contains(&plink));

    // THE SHOT, off member1 with the draft's whole arrangement: one run of
    // the edition's own I-space.
    let member2 = acked_addr(&op(
        port,
        Some(&signed),
        &publish(&edition, Some((&member1, 5)), Some(&d1), &[run(&edition, &element(&edition, 1), 5)]),
    ));
    assert_ne!(member2, member1);
    assert_eq!(
        image(port, None, &member2, 1, 5),
        vec![own_run],
        "the member carries the reinstated run BY REFERENCE: the SAME I-addresses"
    );
    assert_eq!(text(port, None, &member2, 1, 5), "hello");
    assert_eq!(
        count_v(port, None, &member2, 2, 2),
        floor + 1,
        "the public link on the edition's paragraph survives the new version"
    );
    assert!(links_v(port, None, &member2, 2, 2).contains(&plink));
    // And the bare address floats to it (PUB-2.49).
    assert!(links_v(port, None, &edition, 2, 2).contains(&plink));

    sd.shutdown();
}

/// The wire's shape and the store's order, as the daemon answers them. The
/// published example's frame — `at`, `doc`, `op`, `runs`; per run `i_start`,
/// `origin`, `width` — is parsed as the op (the bytes' canonical form is
/// `wire_doc.rs`'s); a write, it is refused `write_at_history` on `/op-at`;
/// and behind the destination's own checks (`not_content_subspace`,
/// `out_of_bounds`, ahead of any run) the runs are judged in order — the
/// store's refusals over the wire are `source_gate.rs`'s cells — with a
/// refused request committing nothing and a duplicate admitted.
#[test]
fn the_wire_frame_is_the_op_and_a_write_on_op_at_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let owner = open_session(port, CLAIMANT_PRINCIPAL);
    let mine = Some(owner.as_str());

    // The example's frame, verbatim: parsed and answered as `reinstate`.
    let example = r#"{"at":{"ordinal":"3","subspace":"1"},"doc":"1.0.1.0.2","op":"reinstate","runs":[{"i_start":"1.0.1.0.2.0.1.4","origin":"1.0.1.0.2","width":"5"}]}"#;
    let v = op(port, mine, example);
    assert_eq!(v["resp"].as_str(), Some("rejected"), "{v}");
    assert_eq!(v["op"].as_str(), Some("reinstate"), "the frame is the op: {v}");

    let draft = draft_with(port, &owner, "abc");
    let one = run(&draft, &element(&draft, 1), 1);
    let head = head_position(port);
    // A write on `/op-at`: the transport's refusal, before any store.
    let (st, body) = http(
        port,
        "POST",
        "/op-at",
        mine,
        format!(r#"{{"at":{head},"frame":{}}}"#, reinstate(&draft, 1, &[one.clone()])).as_bytes(),
    );
    assert_eq!(st, 400, "{}", String::from_utf8_lossy(&body));
    assert_eq!(json(&body)["error"].as_str(), Some("write_at_history"));
    // The destination's own checks stand ahead of every run: a run
    // defective in its shape (a link element) is never looked at.
    let bad = run(&draft, &format!("{draft}.0.2.1"), 1);
    let send = |at: u64, subspace: u64, runs: &[String]| {
        op(
            port,
            mine,
            &format!(
                r#"{{"op":"reinstate","doc":"{draft}","at":{{"subspace":"{subspace}","ordinal":"{at}"}},"runs":[{}]}}"#,
                runs.join(",")
            ),
        )
    };
    assert_permanent(&send(1, 2, &[bad.clone()]), "not_content_subspace");
    assert_permanent(&send(5, 1, &[bad.clone()]), "out_of_bounds");
    assert_permanent(&send(0, 1, &[one.clone()]), "out_of_bounds");
    assert_permanent(&send(1, 1, &[bad]), "bad_run");
    assert_permanent(&send(1, 1, &[]), "empty_result");
    assert_eq!(head_position(port), head, "every refusal commits nothing");
    // The duplicate edge (the record's edge 1 under the wide reach): a run
    // the draft still arranges, placed again at its end.
    let at = acked_at(&send(4, 1, &[one]));
    assert!(at > head);
    assert_eq!(text(port, mine, &draft, 1, 4), "abca");
    assert_eq!(
        image(port, mine, &draft, 4, 1),
        vec![(element(&draft, 1), "1".to_string())],
        "the same address at a second position"
    );
    assert_eq!(image(port, mine, &draft, 1, 1), image(port, mine, &draft, 4, 1));

    sd.shutdown();
}
