//! The publish shot and head-float, over the wire (PUB round 2, lane 3.2):
//! `publish` appends the next member of a published document's chain in ONE
//! commit from the client's own runs (PUB-2.33, PUB-8.1); a bare DOCUMENT
//! address then answers its trunk head from every arrangement reader
//! (PUB-2.49), a version address answers itself forever (PUB-2.50), and a
//! declared deposit into the chain lands in the HEAD member's arrangement
//! (PUB-2.66). The shot's refusals stand in PUB-6.36's order — ownership,
//! registration, the model's own, the base's shape, the SOURCE GATE
//! (`withheld`, naming the origin's document and nothing else, PUB-8.4/8.5),
//! existence — and a refused shot commits nothing.
//!
//! What this file asserts is the TRANSPORT and the ORDER: the codes survive
//! lowering and marshaling with the shapes wire.md pins, the daemon's own
//! publish-class gate (slot 4) stands ahead of the store, and the readers
//! float. The composite's own arithmetic is M5's suite.
//!
//! Every suite runs post-claim on a CLAIMED-PERMISSIVE board (`spawn`): the
//! claimant's doc 1 is the published document under test — born published,
//! holding the ceremony's one record atom at content ordinal 1 — its later
//! flagless mints are the drafts, and a stranger's account supplies the
//! foreign origins.

mod common;

use common::*;
use serde_json::Value;

/// The ceremony atom: doc 1's one content element.
const ATOM: &str = "1.0.1.0.1.0.1.1";

/// The committed head, off `/health` — unchanged across a refusal.
fn head(port: u16) -> u64 {
    json(&get(port, "/health").1)["log_position"].as_u64().expect("log_position")
}

/// The change-feed entries past `since`.
fn changes_since(port: u16, since: u64) -> Vec<Value> {
    let (st, body) = http(port, "GET", &format!("/changes?since={since}"), None, b"");
    assert_eq!(st, 200, "/changes: {}", String::from_utf8_lossy(&body));
    json(&body)["changes"].as_array().expect("changes").clone()
}

/// Assert a PERMANENT store refusal carrying neither `detail` nor `site`.
fn refused(v: &Value, code: &str) {
    let rej = expect_resp(v, "rejected");
    assert_eq!(rej["code"].as_str(), Some(code), "{v}");
    assert_eq!(rej["disposition"].as_str(), Some("permanent"), "a permanent class: {v}");
    assert!(rej.get("detail").is_none(), "no detail rides the code: {v}");
    assert!(rej.get("site").is_none(), "no site rides the code: {v}");
}

/// Assert the source gate's refusal (PUB-8.4, PUB-8.5): `withheld`,
/// `reorder`, the origin's DOCUMENT in `site.addr` and nothing else — no
/// `detail`, ever, and no other site field.
fn withheld(v: &Value, origin: &str) {
    let rej = expect_resp(v, "rejected");
    assert_eq!(rej["code"].as_str(), Some("withheld"), "{v}");
    assert_eq!(rej["disposition"].as_str(), Some("reorder"), "a later grant may fill it: {v}");
    assert!(rej.get("detail").is_none(), "withheld carries no detail, ever: {v}");
    let site = rej["site"].as_object().expect("site");
    assert_eq!(site.len(), 1, "the site is the address alone: {v}");
    assert_eq!(site["addr"].as_str(), Some(origin), "the origin's document: {v}");
}

/// Assert `not_owner` naming `doc` — slot 1, ahead of every other answer.
fn not_owner(v: &Value, doc: &str) {
    let rej = expect_resp(v, "rejected");
    assert_eq!(rej["code"].as_str(), Some("not_owner"), "{v}");
    assert_eq!(rej["site"]["addr"].as_str(), Some(doc), "{v}");
}

/// Assert the daemon's own publish-class gate answered — slot 4, ahead of
/// the store.
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

/// One run of a shot, as the client renders it.
fn run(origin: &str, i_start: &str, width: u64) -> String {
    format!(r#"{{"origin":"{origin}","i_start":"{i_start}","width":"{width}"}}"#)
}

/// The shot: `base` with the extent the staged copy took (both or neither —
/// neither is the birth version), the staging `draft` when there is one,
/// and the runs.
fn publish(doc: &str, base: Option<(&str, u64)>, draft: Option<&str>, runs: &[String]) -> String {
    let base = base
        .map(|(m, extent)| format!(r#","base":"{m}","base_extent":"{extent}""#))
        .unwrap_or_default();
    let draft = draft.map(|d| format!(r#","draft":"{d}""#)).unwrap_or_default();
    format!(r#"{{"op":"publish","doc":"{doc}"{base}{draft},"runs":[{}]}}"#, runs.join(","))
}

/// A later mint into the claimant's account — flagless, hence PRIVATE.
fn draft(port: u16, session: &str) -> String {
    acked_addr(&op(
        port,
        Some(session),
        &format!(r#"{{"op":"create_new_document","account":"{CLAIMANT_ACCOUNT}"}}"#),
    ))
}

/// A draft holding `text` per-byte from ordinal 1.
fn draft_with(port: u16, session: &str, text: &str) -> String {
    let d = draft(port, session);
    expect_resp(&op(port, Some(session), &insert(&d, 1, text, false)), "ack_addr");
    d
}

/// A second EDITION of the claimant's: an explicit `published:true` mint,
/// from the signed session the publish class demands.
fn edition(port: u16, signed: &str) -> String {
    acked_addr(&op(
        port,
        Some(signed),
        &format!(
            r#"{{"op":"create_new_document","account":"{CLAIMANT_ACCOUNT}","published":true}}"#
        ),
    ))
}

/// The content extent a bare address answers — `retrieve_doc_v_span_set`'s
/// content span width, `0` when the set carries none.
fn content_extent(port: u16, doc: &str) -> u64 {
    let v = op(port, None, &format!(r#"{{"op":"retrieve_doc_v_span_set","doc":"{doc}"}}"#));
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

/// The per-byte text at content ordinals `from ..` of `doc`.
fn text(port: u16, doc: &str, from: u64, width: u64) -> String {
    let v = op(
        port,
        None,
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

/// The V→I image of content ordinals `from ..` of `doc`: `(i_start, width)`.
fn image(port: u16, doc: &str, from: u64, width: u64) -> Vec<(String, String)> {
    let v = op(
        port,
        None,
        &format!(
            r#"{{"op":"image","d":"{doc}","region":[{{"start":"1.{from}","width":"0.{width}"}}]}}"#
        ),
    );
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

/// The origin documents of content ordinals `from ..` of `doc`.
fn origins(port: u16, doc: &str, from: u64, width: u64) -> Vec<String> {
    let v = op(
        port,
        None,
        &format!(
            r#"{{"op":"show_origin","doc":"{doc}","span":{{"start":"1.{from}","width":"0.{width}"}}}}"#
        ),
    );
    addrs_of(&v)
}

fn addrs_of(v: &Value) -> Vec<String> {
    expect_resp(v, "addrs")["addrs"]
        .as_array()
        .expect("addrs")
        .iter()
        .map(|a| a.as_str().expect("an address").to_string())
        .collect()
}

fn region(doc: &str, from: u64, width: u64) -> String {
    format!(r#""d":"{doc}","region":[{{"start":"1.{from}","width":"0.{width}"}}]"#)
}

fn links_v(port: u16, doc: &str, from: u64, width: u64) -> Vec<String> {
    addrs_of(&op(port, None, &format!(r#"{{"op":"find_links_v",{}}}"#, region(doc, from, width))))
}

fn count_v(port: u16, doc: &str, from: u64, width: u64) -> u64 {
    let v = op(port, None, &format!(r#"{{"op":"count_v",{}}}"#, region(doc, from, width)));
    expect_resp(&v, "count")["n"].as_u64().expect("n")
}

/// PUB-2.33 / PUB-2.40 / PUB-2.41 — the ordinary shot: the client's whole
/// rendering, the edition's own positions by reference and the draft's text
/// re-minted under the edition's own I-space, lands as the chain's next
/// member in ONE commit — one feed entry naming the member — and the bare
/// address floats to it. The bare session meets the publish-class gate.
#[test]
fn the_shot_appends_the_next_member_in_one_commit_and_the_bare_address_floats() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let bare = open_session(port, CLAIMANT_PRINCIPAL);

    // Doc 1: the atom, then a deposited `ab` — three positions.
    expect_resp(&op(port, Some(&signed), &insert(CLAIMANT_DOC1, 2, "ab", true)), "ack_addr");
    assert_eq!(content_extent(port, CLAIMANT_DOC1), 3);
    // The staging draft: doc 1's three by reference (PUB-2.27), then `cd`.
    let d = draft(port, &bare);
    expect_resp(&op(port, Some(&bare), &copy(&d, 1, CLAIMANT_DOC1, 1, 3)), "ack");
    let d_text = acked_addr(&op(port, Some(&bare), &insert(&d, 4, "cd", false)));
    assert_eq!(d_text, format!("{d}.0.1.1"));

    let shot = publish(
        CLAIMANT_DOC1,
        Some((CLAIMANT_DOC1, 3)),
        Some(&d),
        &[run(CLAIMANT_DOC1, ATOM, 3), run(&d, &d_text, 2)],
    );
    // The publish class's input, from a bare session: gated (slot 4).
    let before = head(port);
    gated(&op(port, Some(&bare), &shot));
    assert_eq!(head(port), before);

    let member = acked_addr(&op(port, Some(&signed), &shot));
    assert_eq!(member, format!("{CLAIMANT_DOC1}.1"), "the chain's first member");
    let feed = changes_since(port, before);
    assert_eq!(feed.len(), 1, "one commit: {feed:?}");
    assert_eq!(feed[0]["op"].as_str(), Some("publish"));
    assert_eq!(feed[0]["docs"], serde_json::json!([member]), "the feed names the member minted");

    // The member: five positions, the draft's text as FRESH identity under
    // doc 1's own content chain — no address of the draft (PUB-2.41).
    assert_eq!(content_extent(port, &member), 5);
    assert_eq!(text(port, &member, 4, 2), "cd");
    let img = image(port, &member, 1, 5);
    assert!(
        img.iter().all(|(start, _)| start.starts_with("1.0.1.0.1.0.1.")),
        "every run is doc 1's own I-space: {img:?}"
    );
    assert_eq!(image(port, &member, 4, 2), vec![("1.0.1.0.1.0.1.4".to_string(), "2".to_string())]);
    // The draft is what it was: the shot read its bytes, not its arrangement.
    assert_eq!(content_extent(port, &d), 5);
    assert_eq!(image(port, &d, 4, 2), vec![(d_text.clone(), "2".to_string())]);

    // Head-float (PUB-2.49): the bare address answers the member.
    assert_eq!(content_extent(port, CLAIMANT_DOC1), 5);
    assert_eq!(text(port, CLAIMANT_DOC1, 4, 2), "cd");
    assert_eq!(image(port, CLAIMANT_DOC1, 4, 2), image(port, &member, 4, 2));
    sd.shutdown();
}

/// PUB-2.39 / PUB-2.44 / PUB-2.45 / PUB-2.66 — two shots staged off one
/// head both land, the first advancing the trunk and the second as the
/// head's daughter; a deposit that lands in the staging interval is carried
/// by the shot; a deposit into the chain — named bare, by the head, or by a
/// pinned member — lands in the HEAD member's arrangement and nowhere else;
/// the in-place refusal still refuses; and the base's shape refusals are
/// clean no-ops.
#[test]
fn a_daughter_lands_under_its_base_and_a_deposit_lands_in_the_head_member() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let bare = open_session(port, CLAIMANT_PRINCIPAL);

    // Shot A off the memberless document: the first member, holding the atom.
    let m1 = acked_addr(&op(
        port,
        Some(&signed),
        &publish(CLAIMANT_DOC1, Some((CLAIMANT_DOC1, 1)), None, &[run(CLAIMANT_DOC1, ATOM, 1)]),
    ));
    assert_eq!(m1, format!("{CLAIMANT_DOC1}.1"));
    assert_eq!(content_extent(port, &m1), 1);

    // A deposit into the BARE address while a draft is staged off m1: it
    // lands in the head m1 (PUB-2.66), minted under doc 1's own chain.
    let z = acked_addr(&op(port, Some(&signed), &insert(CLAIMANT_DOC1, 2, "z", true)));
    assert_eq!(z, "1.0.1.0.1.0.1.2", "minted under the document's own content chain");
    assert_eq!(content_extent(port, &m1), 2, "the head's arrangement grew");
    assert_eq!(text(port, &m1, 2, 1), "z");
    assert_eq!(content_extent(port, CLAIMANT_DOC1), 2, "and the bare address floats to it");
    // The feed names the address written to; the arrangement that changed
    // is the head's.
    // The in-place refusal stands on every address of the chain (PUB-2.11):
    // an undeclared append, a declared write at an ARRANGED position of the
    // head, a delete of the member.
    let before = head(port);
    refused(&op(port, Some(&signed), &insert(CLAIMANT_DOC1, 3, "q", false)), "published_target");
    refused(&op(port, Some(&signed), &insert(CLAIMANT_DOC1, 2, "q", true)), "published_target");
    refused(&op(port, Some(&signed), &delete(&m1, 1, 1)), "published_target");
    assert_eq!(head(port), before);

    // Shot B, staged off m1 BEFORE the deposit (extent 1): the composite
    // appends the deposit the render post-dates (PUB-2.42, PUB-2.45).
    let m2 = acked_addr(&op(
        port,
        Some(&signed),
        &publish(CLAIMANT_DOC1, Some((&m1, 1)), None, &[run(CLAIMANT_DOC1, ATOM, 1)]),
    ));
    assert_eq!(m2, format!("{CLAIMANT_DOC1}.2"), "the base was still the head: the trunk advances");
    assert_eq!(content_extent(port, &m2), 2);
    assert_eq!(text(port, &m2, 2, 1), "z", "the interval's deposit, carried");

    // Shot C, ALSO staged off m1, after B landed: m1's DAUGHTER, in the
    // nested form (PUB-2.55) — nothing is refused for want of a base.
    let daughter = acked_addr(&op(
        port,
        Some(&signed),
        &publish(
            CLAIMANT_DOC1,
            Some((&m1, 2)),
            None,
            &[run(CLAIMANT_DOC1, ATOM, 1), run(CLAIMANT_DOC1, &z, 1)],
        ),
    ));
    assert_eq!(daughter, format!("{m1}.1"));
    assert_eq!(content_extent(port, &daughter), 2);
    // The bare address floats to the TRUNK head alone (PUB-2.53); every
    // member answers itself.
    assert_eq!(content_extent(port, CLAIMANT_DOC1), 2);
    assert_eq!(content_extent(port, &m1), 2);

    // A deposit named by the PINNED member m1 lands in the head m2: m1 never
    // grows (PUB-2.66); the atom's identity is minted under m1's own chain.
    let y = acked_addr(&op(port, Some(&signed), &insert(&m1, 3, "y", true)));
    assert_eq!(y, format!("{m1}.0.1.1"));
    assert_eq!(content_extent(port, &m1), 2, "a pinned member's arrangement never grows");
    assert_eq!(content_extent(port, &m2), 3, "the head's did");
    assert_eq!(text(port, &m2, 3, 1), "y");
    assert_eq!(content_extent(port, CLAIMANT_DOC1), 3);

    // The base's shape, each a permanent refusal and a clean no-op: once a
    // member exists the memberless base and the birth shape are superseded
    // (the shot must name the member it was staged from); an extent past
    // the base's count; a base outside the chain; a run whose stated
    // origin is not the document that minted it.
    let d = draft_with(port, &bare, "abc");
    let before = head(port);
    refused(
        &op(port, Some(&signed), &publish(CLAIMANT_DOC1, Some((CLAIMANT_DOC1, 1)), None, &[])),
        "base_superseded",
    );
    refused(&op(port, Some(&signed), &publish(CLAIMANT_DOC1, None, None, &[])), "base_superseded");
    refused(
        &op(port, Some(&signed), &publish(CLAIMANT_DOC1, Some((&m2, 9)), None, &[])),
        "base_extent_too_large",
    );
    refused(
        &op(port, Some(&signed), &publish(CLAIMANT_DOC1, Some((&d, 1)), None, &[])),
        "base_not_in_chain",
    );
    refused(
        &op(port, Some(&signed), &publish(CLAIMANT_DOC1, Some((&m2, 3)), None, &[run(&d, ATOM, 1)])),
        "bad_run",
    );
    assert_eq!(head(port), before, "a refused shot commits nothing");
    sd.shutdown();
}

/// PUB-2.49 / PUB-2.50 / PUB-2.53 — head-float in every arrangement reader:
/// after a shot that re-arranges the edition, `retrieve_v`,
/// `retrieve_doc_v_span`, `retrieve_doc_v_span_set`, `show_origin`,
/// `image`, `find_links_v`, `count_v` and `compare` on the BARE address all
/// answer the trunk head; a version address answers its own member forever;
/// a memberless edition answers its own arrangement; a draft is untouched.
#[test]
fn every_arrangement_reader_of_a_bare_address_answers_the_trunk_head() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let bare = open_session(port, CLAIMANT_PRINCIPAL);

    // Doc 1: atom, `a`, `b`. The shot drops `a`: the member is [atom, b].
    expect_resp(&op(port, Some(&signed), &insert(CLAIMANT_DOC1, 2, "ab", true)), "ack_addr");
    let b = "1.0.1.0.1.0.1.3";
    assert_eq!(text(port, CLAIMANT_DOC1, 2, 2), "ab", "the pre-chain arrangement");
    let m1 = acked_addr(&op(
        port,
        Some(&signed),
        &publish(
            CLAIMANT_DOC1,
            Some((CLAIMANT_DOC1, 3)),
            None,
            &[run(CLAIMANT_DOC1, ATOM, 1), run(CLAIMANT_DOC1, b, 1)],
        ),
    ));
    assert_eq!(m1, format!("{CLAIMANT_DOC1}.1"));

    // retrieve_v, retrieve_doc_v_span_set, retrieve_doc_v_span, image,
    // show_origin: the bare address answers [atom, b].
    assert_eq!(text(port, CLAIMANT_DOC1, 2, 1), "b", "ordinal 2 is `b` on the head, `a` before it");
    assert_eq!(content_extent(port, CLAIMANT_DOC1), 2);
    let v = op(port, None, &format!(r#"{{"op":"retrieve_doc_v_span","doc":"{CLAIMANT_DOC1}"}}"#));
    let set = expect_resp(&v, "span_set")["set"].as_array().expect("set").clone();
    assert_eq!(set.len(), 1, "{v}");
    assert_eq!(set[0]["width"].as_str(), Some("0.2"), "the member's two content positions: {v}");
    assert_eq!(
        image(port, CLAIMANT_DOC1, 1, 2),
        vec![(ATOM.to_string(), "1".to_string()), (b.to_string(), "1".to_string())]
    );
    assert_eq!(origins(port, CLAIMANT_DOC1, 1, 2), vec![CLAIMANT_DOC1.to_string()]);

    // find_links_v / count_v: a link FROM `b`, found through the bare
    // address at ordinal 2 — where the pre-chain arrangement holds `a`.
    let link = acked_addr(&op(
        port,
        Some(&signed),
        &format!(
            r#"{{"op":"make_link","home":"{CLAIMANT_DOC1}","from":{{"addrs":["{b}"]}},"to":{{"addrs":[]}},"ty":{{"addrs":["{CLAIMANT_DOC1}.0.3.6.1"]}}}}"#
        ),
    ));
    let found = links_v(port, CLAIMANT_DOC1, 2, 1);
    assert!(found.contains(&link), "the link from `b` is found at the head's ordinal 2: {found:?}");
    assert_eq!(found, links_v(port, &m1, 2, 1), "the bare address and the head agree");
    assert_eq!(count_v(port, CLAIMANT_DOC1, 2, 1), found.len() as u64);

    // compare: the bare address's two positions ARE the member's.
    let v = op(
        port,
        None,
        &format!(
            r#"{{"op":"compare","rho1":[{{"doc":"{CLAIMANT_DOC1}","spans":[{{"start":"1.1","width":"0.2"}}]}}],"rho2":[{{"doc":"{m1}","spans":[{{"start":"1.1","width":"0.2"}}]}}]}}"#
        ),
    );
    let pairs = expect_resp(&v, "compare")["pairs"].as_array().expect("pairs").clone();
    let shared: u64 = pairs.iter().map(|p| p["width"].as_str().expect("width").parse::<u64>().expect("a count")).sum();
    assert_eq!(shared, 2, "{v}");
    assert!(pairs.iter().all(|p| p["d1"].as_str() == Some(CLAIMANT_DOC1)), "the foot keeps the address named: {v}");

    // A version address answers itself forever (PUB-2.50): after the trunk
    // advances to [atom], m1 still answers [atom, b].
    let m2 = acked_addr(&op(
        port,
        Some(&signed),
        &publish(CLAIMANT_DOC1, Some((&m1, 2)), None, &[run(CLAIMANT_DOC1, ATOM, 1)]),
    ));
    assert_eq!(m2, format!("{CLAIMANT_DOC1}.2"));
    assert_eq!(content_extent(port, CLAIMANT_DOC1), 1);
    assert_eq!(content_extent(port, &m1), 2);
    assert_eq!(text(port, &m1, 2, 1), "b");
    assert_eq!(content_extent(port, &m2), 1);

    // A memberless edition answers its own arrangement; a draft is inert.
    let e = edition(port, &signed);
    expect_resp(&op(port, Some(&signed), &insert(&e, 1, "xy", true)), "ack_addr");
    assert_eq!(content_extent(port, &e), 2);
    assert_eq!(text(port, &e, 1, 2), "xy");
    let d = draft_with(port, &bare, "abc");
    assert_eq!(content_extent(port, &d), 3);
    assert_eq!(text(port, &d, 1, 3), "abc");
    sd.shutdown();
}

/// PUB-8.1 / PUB-8.4 / PUB-8.5 / PUB-6.36 — the source gate: a run onto a
/// document the caller may not read is `withheld`, naming the origin's
/// DOCUMENT in `site.addr` and nothing else, BEHIND ownership (a stranger's
/// shot answers `not_owner` whatever its runs) and AHEAD of existence (a
/// dangling run onto an unreadable origin is withheld, not dangling). A
/// readable origin is placed as a window that answers its origin.
#[test]
fn the_source_gate_answers_behind_ownership_and_ahead_of_existence() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let bare = open_session(port, CLAIMANT_PRINCIPAL);

    // A stranger: its own account, its home (published, empty — bare writes
    // into a home are gated by design) and a private draft holding `xy`.
    let boot = open_session(port, 0);
    let v = op(port, Some(&boot), r#"{"op":"next_account_prefix","parent":"1"}"#);
    let account =
        expect_resp(&v, "maybe_addr")["addr"].as_str().expect("a delegable prefix").to_string();
    let v = op(
        port,
        Some(&boot),
        &format!(r#"{{"op":"delegate","new_prefix":"{account}","new_id":901}}"#),
    );
    expect_resp(&v, "ack_addr");
    let stranger = open_session(port, 901);
    let mint = format!(r#"{{"op":"create_new_document","account":"{account}"}}"#);
    let s_home = acked_addr(&op(port, Some(&stranger), &mint));
    let s_draft = acked_addr(&op(port, Some(&stranger), &mint));
    let s_text = acked_addr(&op(port, Some(&stranger), &insert(&s_draft, 1, "xy", false)));
    assert_eq!(s_text, format!("{s_draft}.0.1.1"));
    // The claimant's second edition, holding `pq`: a readable foreign origin
    // to any reader, being published.
    let e2 = edition(port, &signed);
    let e2_text = acked_addr(&op(port, Some(&signed), &insert(&e2, 1, "pq", true)));
    assert_eq!(e2_text, format!("{e2}.0.1.1"));
    let d = draft_with(port, &bare, "abc");

    let before = head(port);
    // (1) A run onto the stranger's draft: withheld, naming the draft.
    withheld(
        &op(
            port,
            Some(&signed),
            &publish(
                CLAIMANT_DOC1,
                Some((CLAIMANT_DOC1, 1)),
                None,
                &[run(CLAIMANT_DOC1, ATOM, 1), run(&s_draft, &s_text, 2)],
            ),
        ),
        &s_draft,
    );
    // (2) A DANGLING run onto it: still withheld — existence is never asked
    //     about what the caller may not read.
    withheld(
        &op(
            port,
            Some(&signed),
            &publish(
                CLAIMANT_DOC1,
                Some((CLAIMANT_DOC1, 1)),
                None,
                &[run(&s_draft, &format!("{s_draft}.0.1.9"), 1)],
            ),
        ),
        &s_draft,
    );
    // (3) The stranger shooting doc 1, with a run onto the claimant's own
    //     draft it may not read: ownership answers first (slot 1).
    not_owner(
        &op(
            port,
            Some(&stranger),
            &publish(CLAIMANT_DOC1, None, None, &[run(&d, &format!("{d}.0.1.1"), 3)]),
        ),
        CLAIMANT_DOC1,
    );
    // (4) The stranger's shot on its OWN home from a bare session: the
    //     publish class's gate (slot 4), ahead of the store.
    gated(&op(port, Some(&stranger), &publish(&s_home, None, None, &[])));
    // (5) A dangling run onto a READABLE origin: existence, behind the gate.
    refused(
        &op(
            port,
            Some(&signed),
            &publish(
                CLAIMANT_DOC1,
                Some((CLAIMANT_DOC1, 1)),
                None,
                &[run(&e2, &format!("{e2}.0.1.9"), 1)],
            ),
        ),
        "dangling_source",
    );
    assert_eq!(head(port), before, "every refusal commits nothing");

    // (6) The readable window: placed, answering its origin — through the
    //     member and through the bare address alike.
    let m1 = acked_addr(&op(
        port,
        Some(&signed),
        &publish(
            CLAIMANT_DOC1,
            Some((CLAIMANT_DOC1, 1)),
            None,
            &[run(CLAIMANT_DOC1, ATOM, 1), run(&e2, &e2_text, 2)],
        ),
    ));
    assert_eq!(m1, format!("{CLAIMANT_DOC1}.1"));
    assert_eq!(text(port, &m1, 2, 2), "pq");
    assert_eq!(image(port, &m1, 2, 2), vec![(e2_text.clone(), "2".to_string())], "a window keeps its origin's identity");
    assert_eq!(origins(port, &m1, 2, 2), vec![e2.clone()]);
    assert_eq!(origins(port, CLAIMANT_DOC1, 2, 2), vec![e2.clone()], "show_origin floats");
    // (7) Carried: the next shot re-supplies the window m1 arranges and
    //     lands — the base already arranging a run is the gate's own answer.
    let m2 = acked_addr(&op(
        port,
        Some(&signed),
        &publish(
            CLAIMANT_DOC1,
            Some((&m1, 3)),
            None,
            &[run(CLAIMANT_DOC1, ATOM, 1), run(&e2, &e2_text, 2)],
        ),
    ));
    assert_eq!(m2, format!("{CLAIMANT_DOC1}.2"));
    assert_eq!(text(port, CLAIMANT_DOC1, 2, 2), "pq");
    sd.shutdown();
}

/// PUB-2.9's `true` face on the shot — ONE code, `private_source_versionless`,
/// permanent, carrying nothing: a private document has no chain. Behind
/// registration (PUB-6.37): an unregistered document answers
/// `doc_not_registered`, an unregistered base or origin
/// `source_not_registered`. The draft stays the owner's to edit in place.
#[test]
fn a_shot_on_a_private_document_is_refused_with_one_code() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let bare = open_session(port, CLAIMANT_PRINCIPAL);
    let d = draft_with(port, &bare, "abc");
    let d_text = format!("{d}.0.1.1");

    let before = head(port);
    refused(
        &op(port, Some(&signed), &publish(&d, None, None, &[run(&d, &d_text, 3)])),
        "private_source_versionless",
    );
    refused(
        &op(port, Some(&signed), &publish(&d, Some((&d, 3)), Some(&d), &[run(&d, &d_text, 3)])),
        "private_source_versionless",
    );
    // The shot is the publish class's input whatever the document's state:
    // from the bare session the daemon's gate answers first (slot 4).
    gated(&op(port, Some(&bare), &publish(&d, None, None, &[run(&d, &d_text, 3)])));
    // Registration ahead of everything.
    let ghost = format!("{CLAIMANT_ACCOUNT}.0.9");
    let v = op(port, Some(&signed), &publish(&ghost, None, None, &[]));
    assert_eq!(expect_resp(&v, "rejected")["code"].as_str(), Some("doc_not_registered"), "{v}");
    let v = op(port, Some(&signed), &publish(CLAIMANT_DOC1, Some((&ghost, 1)), None, &[]));
    assert_eq!(expect_resp(&v, "rejected")["code"].as_str(), Some("source_not_registered"), "{v}");
    let v = op(
        port,
        Some(&signed),
        &publish(CLAIMANT_DOC1, None, None, &[run(&ghost, &format!("{ghost}.0.1.1"), 1)]),
    );
    assert_eq!(expect_resp(&v, "rejected")["code"].as_str(), Some("source_not_registered"), "{v}");
    assert_eq!(head(port), before, "a refused shot commits nothing");

    // The draft is still edited in place.
    expect_resp(&op(port, Some(&bare), &insert(&d, 4, "d", false)), "ack_addr");
    sd.shutdown();
}

/// PUB-2.34 — the birth version is this same composite with the base
/// absent: one commit, one feed entry, the member born with the draft's
/// text as fresh identity from the edition's first content ordinal. A shot
/// refused at its last check — behind the draft-native run it would have
/// re-minted — leaves NO residue: no commit, no feed entry, no member, and
/// no content mint (the next shot's identities start where they would
/// have). Once the member exists the birth shape is superseded.
#[test]
fn the_birth_version_is_one_commit_and_a_refused_shot_leaves_no_residue() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let bare = open_session(port, CLAIMANT_PRINCIPAL);

    let e = edition(port, &signed);
    assert_eq!(content_extent(port, &e), 0, "born empty");
    let d = draft_with(port, &bare, "abc");
    let d_text = format!("{d}.0.1.1");
    let member = format!("{e}.1");

    let before = head(port);
    refused(
        &op(
            port,
            Some(&signed),
            &publish(&e, None, Some(&d), &[run(&d, &d_text, 3), run(&d, &format!("{d}.0.1.9"), 1)]),
        ),
        "dangling_source",
    );
    assert_eq!(head(port), before, "no commit");
    assert!(changes_since(port, before).is_empty(), "no feed entry");
    let v = op(port, None, &format!(r#"{{"op":"retrieve_doc_v_span_set","doc":"{member}"}}"#));
    assert_eq!(expect_resp(&v, "rejected")["code"].as_str(), Some("doc_not_registered"), "no member: {v}");

    let minted = acked_addr(&op(
        port,
        Some(&signed),
        &publish(&e, None, Some(&d), &[run(&d, &d_text, 3)]),
    ));
    assert_eq!(minted, member, "the chain's first member");
    let feed = changes_since(port, before);
    assert_eq!(feed.len(), 1, "one commit: {feed:?}");
    assert_eq!(feed[0]["op"].as_str(), Some("publish"));
    assert_eq!(feed[0]["docs"], serde_json::json!([member]));
    assert_eq!(content_extent(port, &member), 3);
    assert_eq!(text(port, &member, 1, 3), "abc");
    assert_eq!(
        image(port, &member, 1, 3),
        vec![(format!("{e}.0.1.1"), "3".to_string())],
        "fresh identity from the edition's FIRST ordinal: the refused shot minted nothing"
    );
    // The bare address floats to the member; the birth shape is now
    // superseded.
    assert_eq!(content_extent(port, &e), 3);
    assert_eq!(text(port, &e, 1, 3), "abc");
    refused(
        &op(port, Some(&signed), &publish(&e, None, Some(&d), &[run(&d, &d_text, 3)])),
        "base_superseded",
    );
    sd.shutdown();
}
