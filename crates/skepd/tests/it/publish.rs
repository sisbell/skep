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

use crate::common;

use common::*;
use serde_json::Value;

/// The ceremony atom: doc 1's one content element.
const ATOM: &str = "1.0.1.0.1.0.1.1";

/// The committed head, off `/health` — unchanged across a refusal.
fn head(port: u16) -> u64 {
    json(&get(port, "/health").1)["log_position"].as_u64().expect("log_position")
}

/// The change-feed entries past `since`, as the guest.
fn changes_since(port: u16, since: u64) -> Vec<Value> {
    changes_since_as(port, None, since)
}

/// The change-feed entries past `since`, as `token`'s class.
fn changes_since_as(port: u16, token: Option<&str>, since: u64) -> Vec<Value> {
    let (st, body) = http(port, "GET", &format!("/changes?since={since}"), token, b"");
    assert_eq!(st, 200, "/changes: {}", String::from_utf8_lossy(&body));
    json(&body)["changes"].as_array().expect("changes").clone()
}

/// The one feed entry a write produced, off the head as it stood before it.
fn one_entry(port: u16, before: u64, what: &str) -> Value {
    let entries = changes_since(port, before);
    assert_eq!(entries.len(), 1, "{what}: one write, one entry: {entries:?}");
    entries[0].clone()
}

/// Assert a PERMANENT store refusal carrying neither `detail` nor `site`.
fn assert_refused(v: &Value, code: &str) {
    let rej = expect_resp(v, "rejected");
    assert_eq!(rej["code"].as_str(), Some(code), "{v}");
    assert_eq!(rej["disposition"].as_str(), Some("permanent"), "a permanent class: {v}");
    assert!(rej.get("detail").is_none(), "no detail rides the code: {v}");
    assert!(rej.get("site").is_none(), "no site rides the code: {v}");
}

/// Assert the source gate's refusal (PUB-8.4, PUB-8.5): `withheld`,
/// `reorder`, the origin's DOCUMENT in `site.addr` and nothing else — no
/// `detail`, ever, and no other site field.
fn assert_withheld(v: &Value, origin: &str) {
    let rej = expect_resp(v, "rejected");
    assert_eq!(rej["code"].as_str(), Some("withheld"), "{v}");
    assert_eq!(rej["disposition"].as_str(), Some("reorder"), "a later grant may fill it: {v}");
    assert!(rej.get("detail").is_none(), "withheld carries no detail, ever: {v}");
    let site = rej["site"].as_object().expect("site");
    assert_eq!(site.len(), 1, "the site is the address alone: {v}");
    assert_eq!(site["addr"].as_str(), Some(origin), "the origin's document: {v}");
}

/// Assert `not_owner` naming `doc` — slot 1, ahead of every other answer.
fn assert_not_owner(v: &Value, doc: &str) {
    let rej = expect_resp(v, "rejected");
    assert_eq!(rej["code"].as_str(), Some("not_owner"), "{v}");
    assert_eq!(rej["site"]["addr"].as_str(), Some(doc), "{v}");
}

/// Assert the daemon's own publish-class gate answered — slot 4, ahead of
/// the store.
fn assert_gated(v: &Value) {
    let rej = expect_resp(v, "rejected");
    assert_eq!(rej["code"].as_str(), Some("credential_refused"), "{v}");
    assert_eq!(rej["detail"].as_str(), Some("signed_session_required"), "{v}");
}

/// A per-byte PROSE insert, undeclared or DECLARED. A declared one names a
/// MEMBER type of the deposit class, ENROLL's (PUB-2.11, PUB-2.64): what
/// these suites deposit is prose — PUB-2.60's residue, bytes of the
/// depositor's choosing under a declared class type — which the door admits
/// on the type alone.
fn insert(doc: &str, at: u64, text: &str, deposit: bool) -> String {
    let declaration = if deposit { format!(r#","deposit":"{T_ENROLL}""#) } else { String::new() };
    format!(
        r#"{{"op":"insert","doc":"{doc}","at":{{"subspace":"1","ordinal":"{at}"}},"values":["{text}"]{declaration}}}"#
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
/// content span width, `0` when the set carries none. Read as the guest: the
/// published documents these tests probe answer every class (PUB-6.3); a
/// DRAFT is withheld from the guest and is read through
/// [`content_extent_as`] with its owner's token.
fn content_extent(port: u16, doc: &str) -> u64 {
    content_extent_as(port, None, doc)
}

/// [`content_extent`] as `token`'s principal.
fn content_extent_as(port: u16, token: Option<&str>, doc: &str) -> u64 {
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

/// The BIRTH extent `doc_metadata` serves for `doc`'s document (PUB-3.19 as
/// RES-276 reads it): the content its birth version `D.1` was minted with,
/// frozen there — where [`content_extent`] of `D.1` is that member's LIVE
/// arrangement, which grows with every deposit it takes as the head. Read as
/// the guest, like [`content_extent`].
fn birth_extent(port: u16, doc: &str) -> u64 {
    let v = op(port, None, &format!(r#"{{"op":"doc_metadata","doc":"{doc}"}}"#));
    expect_resp(&v, "doc_metadata")["birth_extent"]
        .as_str()
        .expect("a document with a chain member carries its birth extent")
        .parse()
        .expect("a count")
}

/// The per-byte text at content ordinals `from ..` of `doc`, read as the
/// guest (a published document; see [`content_extent`]).
fn text(port: u16, doc: &str, from: u64, width: u64) -> String {
    text_as(port, None, doc, from, width)
}

/// [`text`] as `token`'s principal — how a DRAFT is read.
fn text_as(port: u16, token: Option<&str>, doc: &str, from: u64, width: u64) -> String {
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

/// The V→I image of content ordinals `from ..` of `doc`: `(i_start, width)`,
/// read as the guest (a published document; see [`content_extent`]).
fn image(port: u16, doc: &str, from: u64, width: u64) -> Vec<(String, String)> {
    image_as(port, None, doc, from, width)
}

/// [`image`] as `token`'s principal — how a DRAFT is imaged.
fn image_as(
    port: u16,
    token: Option<&str>,
    doc: &str,
    from: u64,
    width: u64,
) -> Vec<(String, String)> {
    let v = op(
        port,
        token,
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
    assert_gated(&op(port, Some(&bare), &shot));
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
    // The draft is what it was: the shot read its bytes, not its arrangement
    // (read as its owner — a draft is withheld from the guest).
    assert_eq!(content_extent_as(port, Some(&bare), &d), 5);
    assert_eq!(image_as(port, Some(&bare), &d, 4, 2), vec![(d_text.clone(), "2".to_string())]);

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
    assert_eq!(birth_extent(port, CLAIMANT_DOC1), 1, "born with the atom");

    // A deposit into the BARE address while a draft is staged off m1: it
    // lands in the head m1 (PUB-2.66), minted under doc 1's own chain.
    let before_deposit = head(port);
    let z = acked_addr(&op(port, Some(&signed), &insert(CLAIMANT_DOC1, 2, "z", true)));
    assert_eq!(z, "1.0.1.0.1.0.1.2", "minted under the document's own content chain");
    assert_eq!(content_extent(port, &m1), 2, "the head's arrangement grew");
    // …and the birth content did not (PUB-3.19, RES-276): the deposit is
    // I-adjacent to the atom, so m1 now holds ONE run of two — nothing in the
    // arrangement marks where the birth content ended, and the extent served
    // is the one frozen at the mint.
    assert_eq!(image(port, &m1, 1, 2), vec![(ATOM.to_string(), "2".to_string())]);
    assert_eq!(birth_extent(port, CLAIMANT_DOC1), 1, "the birth extent stays at the mint's");
    assert_eq!(text(port, &m1, 2, 1), "z");
    assert_eq!(content_extent(port, CLAIMANT_DOC1), 2, "and the bare address floats to it");
    // wire.md §The change feed: a declared deposit "names the address the
    // `insert` was written to, though the arrangement it lands in is the
    // chain's head member". Here the two DIFFER — written to the bare
    // address, landed in m1 — so naming what CHANGED is a distinguishable
    // answer, and the one a client watching its own address never sees.
    let entry = one_entry(port, before_deposit, "the deposit at the bare address");
    assert_eq!(entry["op"].as_str(), Some("insert"));
    assert_eq!(
        entry["docs"],
        serde_json::json!([CLAIMANT_DOC1]),
        "the address written to, not the head member it landed in"
    );

    // The in-place refusal stands on every address of the chain (PUB-2.11):
    // an undeclared append, a declared write at an ARRANGED position of the
    // head, a delete of the member.
    let before = head(port);
    assert_refused(&op(port, Some(&signed), &insert(CLAIMANT_DOC1, 3, "q", false)), "published_target");
    assert_refused(&op(port, Some(&signed), &insert(CLAIMANT_DOC1, 2, "q", true)), "published_target");
    assert_refused(&op(port, Some(&signed), &delete(&m1, 1, 1)), "published_target");
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
    let before_pinned = head(port);
    let y = acked_addr(&op(port, Some(&signed), &insert(&m1, 3, "y", true)));
    assert_eq!(y, format!("{m1}.0.1.1"));
    assert_eq!(content_extent(port, &m1), 2, "a pinned member's arrangement never grows");
    assert_eq!(content_extent(port, &m2), 3, "the head's did");
    assert_eq!(text(port, &m2, 3, 1), "y");
    assert_eq!(content_extent(port, CLAIMANT_DOC1), 3);
    // The pack's member-state row 2 — a trunk member that took a deposit while
    // it was the head, now pinned: its arrangement stands at two and its
    // birth content at one, asked of any address of the chain.
    for named in [CLAIMANT_DOC1, m1.as_str(), m2.as_str(), daughter.as_str()] {
        assert_eq!(birth_extent(port, named), 1, "the document's birth extent, asked of {named}");
    }
    // The other direction, and the cell that fixes the rule as "the address
    // NAMED": this deposit named the PINNED member m1 and grew m2, so an
    // entry naming the head would name an address the frame never carried.
    let entry = one_entry(port, before_pinned, "the deposit at the pinned member");
    assert_eq!(entry["docs"], serde_json::json!([m1]), "the pinned address, not the head m2");

    // The base's shape, each a permanent refusal and a clean no-op: once a
    // member exists the memberless base and the birth shape are superseded
    // (the shot must name the member it was staged from); an extent past
    // the base's count; a base outside the chain; a run whose stated
    // origin is not the document that minted it.
    let d = draft_with(port, &bare, "abc");
    let before = head(port);
    assert_refused(
        &op(port, Some(&signed), &publish(CLAIMANT_DOC1, Some((CLAIMANT_DOC1, 1)), None, &[])),
        "base_superseded",
    );
    assert_refused(&op(port, Some(&signed), &publish(CLAIMANT_DOC1, None, None, &[])), "base_superseded");
    assert_refused(
        &op(port, Some(&signed), &publish(CLAIMANT_DOC1, Some((&m2, 9)), None, &[])),
        "base_extent_too_large",
    );
    assert_refused(
        &op(port, Some(&signed), &publish(CLAIMANT_DOC1, Some((&d, 1)), None, &[])),
        "base_not_in_chain",
    );
    assert_refused(
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
    assert_eq!(content_extent_as(port, Some(&bare), &d), 3);
    assert_eq!(text_as(port, Some(&bare), &d, 1, 3), "abc");
    sd.shutdown();
}

/// PUB-2.49 on the POINTWISE PAIR (wire.md §Head-float, as built since
/// `32b70bc`; owner 2026-09-25): `project` and `discoverable_from` on a bare
/// published address answer the HEAD member's arrangement — the link is read
/// against the arrangement a reader of `d` sees, in the head's V-coordinates
/// — and on a pinned older member that member's own; `delete_orphans` on the
/// bare address reads the ADDRESS NAMED, the document's own pre-chain
/// arrangement, and does not float. Three arrangements hold `b` at three
/// different ordinals — the pre-chain at 3, the pinned member at 2, the head
/// at 1 — so each reader's answer names the arrangement it read.
#[test]
fn the_pointwise_pair_floats_to_the_trunk_head_and_delete_orphans_reads_the_address_named() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());

    // Doc 1's pre-chain arrangement: [atom, a, b] — `a` at ordinal 2, `b` at 3.
    expect_resp(&op(port, Some(&signed), &insert(CLAIMANT_DOC1, 2, "ab", true)), "ack_addr");
    let a = "1.0.1.0.1.0.1.2";
    let b = "1.0.1.0.1.0.1.3";
    assert_eq!(text(port, CLAIMANT_DOC1, 2, 2), "ab");
    // One link FROM `a` and one FROM `b`, both homed in doc 1.
    let link_from = |addr: &str| -> String {
        acked_addr(&op(
            port,
            Some(&signed),
            &format!(
                r#"{{"op":"make_link","home":"{CLAIMANT_DOC1}","from":{{"addrs":["{addr}"]}},"to":{{"addrs":[]}},"ty":{{"addrs":["{CLAIMANT_DOC1}.0.3.6.1"]}}}}"#
            ),
        ))
    };
    let l_a = link_from(a);
    let l_b = link_from(b);

    // m1 = [atom, b]: `b` at ordinal 2. m2 = [b, atom], the trunk's head: `b`
    // at ordinal 1, and `a` arranged in no member.
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
    let m2 = acked_addr(&op(
        port,
        Some(&signed),
        &publish(
            CLAIMANT_DOC1,
            Some((&m1, 2)),
            None,
            &[run(CLAIMANT_DOC1, b, 1), run(CLAIMANT_DOC1, ATOM, 1)],
        ),
    ));
    assert_eq!(m2, format!("{CLAIMANT_DOC1}.2"));
    assert_eq!(text(port, CLAIMANT_DOC1, 1, 1), "b", "the head opens on `b`");

    // `project`: the FROM slot's footprint in `d`, read as the guest.
    let project = |link: &str, d: &str| -> Vec<(String, String)> {
        let v = op(port, None, &format!(r#"{{"a":"{link}","d":"{d}","op":"project","slot":1}}"#));
        expect_resp(&v, "span_set")["set"]
            .as_array()
            .expect("set")
            .iter()
            .map(|s| {
                (
                    s["start"].as_str().expect("start").to_string(),
                    s["width"].as_str().expect("width").to_string(),
                )
            })
            .collect()
    };
    let one_at = |ordinal: u64| vec![(format!("1.{ordinal}"), "0.1".to_string())];
    // The bare address answers the HEAD member's arrangement (`b` at 1, `a`
    // absent); the pinned member its own (`b` at 2); neither the pre-chain
    // arrangement's (`b` at 3, `a` at 2).
    assert_eq!(project(&l_b, CLAIMANT_DOC1), one_at(1), "the bare address floats to the head");
    assert_eq!(project(&l_b, &m2), one_at(1), "and agrees with the head named");
    assert_eq!(project(&l_b, &m1), one_at(2), "a pinned member answers its own arrangement");
    assert!(
        project(&l_a, CLAIMANT_DOC1).is_empty(),
        "`a` is arranged in no member: the bare address does not read the pre-chain arrangement"
    );
    assert!(project(&l_a, &m1).is_empty());

    // `discoverable_from`: the same float, as a bool.
    let discoverable = |link: &str, d: &str| -> bool {
        let v = op(port, None, &format!(r#"{{"a":"{link}","d":"{d}","op":"discoverable_from"}}"#));
        expect_resp(&v, "bool")["val"].as_bool().expect("val")
    };
    assert!(discoverable(&l_b, CLAIMANT_DOC1), "reachable from the head");
    assert!(discoverable(&l_b, &m1), "and from the pinned member");
    assert!(
        !discoverable(&l_a, CLAIMANT_DOC1),
        "reachable through the pre-chain arrangement alone: not from the head"
    );
    assert!(!discoverable(&l_a, &m1));

    // `delete_orphans` on the bare address reads the ADDRESS NAMED — the
    // pre-chain arrangement [atom, a, b], three positions: a delete of
    // ordinal 3 (`b`) is in range and orphans the link from `b`. On the head,
    // two positions, the same request is out of bounds.
    let orphans_of = |d: &str| -> Value {
        op(
            port,
            None,
            &format!(
                r#"{{"d":"{d}","op":"delete_orphans","p":{{"ordinal":"3","subspace":"1"}},"width":"1"}}"#
            ),
        )
    };
    let v = orphans_of(CLAIMANT_DOC1);
    assert_eq!(expect_resp(&v, "orphans")["orphaned"], serde_json::json!([l_b]), "{v}");
    let v = orphans_of(&m2);
    assert_eq!(
        expect_resp(&v, "rejected")["code"].as_str(),
        Some("out_of_bounds"),
        "the head holds two positions: {v}"
    );
    sd.shutdown();
}

/// THE PUBLICATION's FEED ROW AND ITS RECORDS (the link-sets design §5.7;
/// wire.md §The change feed, §The publish shot and head-float): a drafted
/// shot's ONE commit mints, per piece of draft identity it re-inserts, one
/// correspondence record homed in the draft — `from` the draft-native
/// I-span, `to` the member's span it became, typed `3.102.1`, the draft's
/// first link, readable to the draft's owner and withheld from a guest —
/// and its row names the member FIRST and the draft beside it to the
/// owner, the member alone to the guest, KEEPING its `attest` on both pages
/// (the exemption: the preimage names no member the reduction withholds).
/// A second shot re-inserting a run the record names is refused
/// `already_published`, permanent, `site.addr` the member, nothing
/// committed; one re-inserting nothing names the member alone on every
/// page and mints no record.
#[test]
fn a_drafted_shots_row_names_the_draft_beside_the_member_for_its_owner_and_keeps_its_attest() {
    const T_CORRESPONDENCE: &str = "1.1.0.1.0.1.0.3.102.1";
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let bare = open_session(port, CLAIMANT_PRINCIPAL);
    let e = edition(port, &signed);
    let d = draft_with(port, &bare, "abc");
    let d_text = format!("{d}.0.1.1");

    let before = head(port);
    let member = acked_addr(&op(port, Some(&signed), &publish(&e, None, Some(&d), &[run(&d, &d_text, 3)])));
    assert_eq!(member, format!("{e}.1"));
    // The record: the draft's first link, from the draft's run to the
    // member's fresh run.
    let record = read_link(port, Some(&bare), &format!("{d}.0.2.1"));
    assert_eq!(record["slots"][0][0]["start"].as_str(), Some(d_text.as_str()), "`from` the draft's run: {record}");
    assert_eq!(
        record["slots"][1][0]["start"].as_str(),
        Some(image(port, &member, 1, 3)[0].0.as_str()),
        "`to` the member's fresh run: {record}"
    );
    assert_eq!(record["slots"][2][0]["start"].as_str(), Some(T_CORRESPONDENCE), "{record}");
    assert!(
        read_link(port, None, &format!("{d}.0.2.1")).is_null(),
        "the draft is withheld from a guest: a link read of it answers absence, as for an address never deposited"
    );
    // The row: the member first and the draft beside it for the owner, the
    // member alone for the guest, the `attest` kept on both.
    let owners = changes_since_as(port, Some(&signed), before);
    let guests = changes_since(port, before);
    assert_eq!((owners.len(), guests.len()), (1, 1), "one commit: {owners:?} / {guests:?}");
    assert_eq!(owners[0]["docs"], serde_json::json!([member, d]), "the member first, the draft beside it: {}", owners[0]);
    assert_eq!(guests[0]["docs"], serde_json::json!([member]), "reduced to the member: {}", guests[0]);
    assert!(owners[0]["attest"].is_object(), "the owner's row carries the attest: {}", owners[0]);
    assert_eq!(guests[0]["attest"], owners[0]["attest"], "the guest's reduced row keeps it: the exemption");
    assert!(guests[0].get("key").is_none(), "a signed row carries no key: {}", guests[0]);

    // The twin fence: the same words again, whole or a piece.
    let before = head(port);
    for width in [3, 1] {
        let v = op(port, Some(&signed), &publish(&e, Some((&member, 3)), Some(&d), &[run(&d, &d_text, width)]));
        let rej = expect_resp(&v, "rejected");
        assert_eq!(rej["code"].as_str(), Some("already_published"), "{v}");
        assert_eq!(rej["disposition"].as_str(), Some("permanent"), "{v}");
        assert_eq!(rej["site"]["addr"].as_str(), Some(member.as_str()), "the member the words were published into: {v}");
    }
    assert_eq!(head(port), before, "nothing committed");
    assert!(changes_since(port, before).is_empty());

    // A shot re-inserting nothing: the member alone on every page, no record.
    let m2 = acked_addr(&op(port, Some(&signed), &publish(&e, Some((&member, 3)), Some(&d), &[run(&e, &image(port, &member, 1, 3)[0].0, 3)])));
    assert_eq!(m2, format!("{e}.2"));
    let owners = changes_since_as(port, Some(&signed), before);
    assert_eq!(owners[0]["docs"], serde_json::json!([m2]), "nothing re-inserted: no draft on the row: {}", owners[0]);
    assert!(read_link(port, Some(&bare), &format!("{d}.0.2.2")).is_null(), "no second record");
    sd.shutdown();
}

/// PUB-8.1 / PUB-8.4 / PUB-8.5 / PUB-6.36 — the source gate: a run onto a
/// document the caller may not read is `withheld`, naming the origin's
/// DOCUMENT in `site.addr` and nothing else, BEHIND ownership (a stranger's
/// shot answers `not_owner` whatever its runs) and AHEAD of existence (a
/// dangling run onto an unreadable origin is withheld, not dangling) —
/// whatever bytes the shot's signature was made over: the true ones or a
/// wrong guess, the answer is the same, the write-path check reading no
/// value the caller may not read. Since the address form (l6-A4,
/// 2026-09-29) such a run is a WINDOW the check composes by address, unread,
/// and an UNATTESTED shot naming one — as every unattested shot, (1) standing
/// ahead of the composition — meets the check's own `attestation_required`
/// ahead of the store's gate; the signed cells answer the store's `withheld`.
/// A readable origin is placed as a window that answers its origin.
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
    // (1) A run onto the stranger's draft: withheld, naming the draft. The
    //     claimant signs over the bytes it knows it is placing, and that
    //     decides nothing: the check composes no value the store would
    //     withhold, so the shot passes through and the store's gate answers,
    //     whatever is attached — (1′) and (2′) below.
    let mut known = values_of(port, Some(&signed), CLAIMANT_DOC1, 1, 1);
    known.push(b"x".to_vec());
    known.push(b"y".to_vec());
    let known: Vec<&[u8]> = known.iter().map(Vec::as_slice).collect();
    assert_withheld(
        &op_with_publish_values(
            port,
            &signed,
            &publish(
                CLAIMANT_DOC1,
                Some((CLAIMANT_DOC1, 1)),
                None,
                &[run(CLAIMANT_DOC1, ATOM, 1), run(&s_draft, &s_text, 2)],
            ),
            &known,
        ),
        &s_draft,
    );
    // (2) A DANGLING run onto it: still withheld — existence is never asked
    //     about what the caller may not read.
    assert_withheld(
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
    // (1′) The shot of (1) signed over a WRONG guess at the draft's second
    //      byte: the same answer — no verdict turns on a byte the caller may
    //      not read.
    let mut guess = values_of(port, Some(&signed), CLAIMANT_DOC1, 1, 1);
    guess.push(b"x".to_vec());
    guess.push(b"z".to_vec());
    let guess: Vec<&[u8]> = guess.iter().map(Vec::as_slice).collect();
    assert_withheld(
        &op_with_publish_values(
            port,
            &signed,
            &publish(
                CLAIMANT_DOC1,
                Some((CLAIMANT_DOC1, 1)),
                None,
                &[run(CLAIMANT_DOC1, ATOM, 1), run(&s_draft, &s_text, 2)],
            ),
            &guess,
        ),
        &s_draft,
    );
    // (2′) An EXISTING run onto it, UNATTESTED: the check's own answer, the
    //      window composed by address and unread — existence is not told
    //      through the check either, nor is readability: a dangling run and
    //      an existing one onto the same origin answer alike here.
    for existing in [true, false] {
        let start = if existing { s_text.clone() } else { format!("{s_draft}.0.1.9") };
        let v = op_as_written(
            port,
            Some(&signed),
            &publish(CLAIMANT_DOC1, Some((CLAIMANT_DOC1, 1)), None, &[run(&s_draft, &start, 2)]),
        );
        let rej = expect_resp(&v, "rejected");
        assert_eq!(
            (rej["code"].as_str(), rej["detail"].as_str(), rej["disposition"].as_str()),
            (Some("credential_refused"), Some("attestation_required"), Some("reorder")),
            "unattested, existing = {existing}: {v}"
        );
    }
    // (3) The stranger shooting doc 1, with a run onto the claimant's own
    //     draft it may not read: ownership answers first (slot 1).
    assert_not_owner(
        &op(
            port,
            Some(&stranger),
            &publish(CLAIMANT_DOC1, None, None, &[run(&d, &format!("{d}.0.1.1"), 3)]),
        ),
        CLAIMANT_DOC1,
    );
    // (4) The stranger's shot on its OWN home from a bare session: the
    //     publish class's gate (slot 4), ahead of the store.
    assert_gated(&op(port, Some(&stranger), &publish(&s_home, None, None, &[])));
    // (5) A dangling run onto a READABLE origin: existence, behind the gate.
    assert_refused(
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
    assert_refused(
        &op(port, Some(&signed), &publish(&d, None, None, &[run(&d, &d_text, 3)])),
        "private_source_versionless",
    );
    assert_refused(
        &op(port, Some(&signed), &publish(&d, Some((&d, 3)), Some(&d), &[run(&d, &d_text, 3)])),
        "private_source_versionless",
    );
    // The shot is the publish class's input whatever the document's state:
    // from the bare session the daemon's gate answers first (slot 4).
    assert_gated(&op(port, Some(&bare), &publish(&d, None, None, &[run(&d, &d_text, 3)])));
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
/// have). Once the member exists the birth shape is superseded. Beside it,
/// m1's FIRST ORDER VECTOR (SO-I7 (f), SO-I9 (a); round 7's
/// `m1-reorder-has-no-lane`, the code landed at `37f611a`): an unsigned
/// `publish` naming a missing source answers `attestation_required`, never
/// `dangling_source`.
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
    let refused =
        publish(&e, None, Some(&d), &[run(&d, &d_text, 3), run(&d, &format!("{d}.0.1.9"), 1)]);
    // Unattested, the check's (1) answers ahead of the composition, and so
    // ahead of the existence walk (the design record §4.5, ratified m1:
    // `attestation_required` BEFORE `dangling_source`).
    let v = op_as_written(port, Some(&signed), &refused);
    assert_eq!(verdict(&v), "credential_refused:attestation_required", "{v}");
    // Attested — by a member no frame verifies, since none composes over a
    // value M4 does not hold — the store's own existence walk refuses it.
    assert_refused(
        &op_as_written(port, Some(&signed), &with_unverifiable_attest(&refused)),
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
    assert_refused(
        &op(port, Some(&signed), &publish(&e, None, Some(&d), &[run(&d, &d_text, 3)])),
        "base_superseded",
    );
    sd.shutdown();
}

/// THE KEPT PLACES ON THE WIRE (the link-sets design §5.7; wire.md §The
/// publish shot and head-float, the kept places; §Arrangement, `places`): a
/// shot carrying, beside its `runs`, the place a draft-native run held in
/// the draft — composed from the draft's image as its owner — has the draft
/// RE-WINDOWED in the shot's one commit: the draft reads the same text and
/// images the member's fresh run where its own words were, its own `a`
/// before them at its own address; the member is minted; the record stands;
/// and the feed row is as the publication's spine left it, one row, the
/// member first and the draft beside it to its owner, its `attest` kept.
/// THE SIGNED FRAME IS UNCHANGED: the entry signature the suite's signer
/// made over the frame WITHOUT `places` verifies the frame WITH them — the
/// places lie outside the preimage. A place the draft no longer honours —
/// the run's words rearranged after the place was read — is refused
/// `kept_place_moved`, permanent, `site.index` the `runs` entry and nothing
/// else, no detail, nothing committed and the draft as the rearrangement
/// left it. And the shape is the codec's, ahead of every store: a place on
/// a window onto another document, and a list longer than `runs`, are
/// `malformed` with `site.index` the entry — while a place on a run of the
/// edition's own identity is a STRAY place (lane F4), admitted by the codec
/// and refused by the store `stray_place_unrecorded` where no record of the
/// draft names that identity.
#[test]
fn a_shot_with_kept_places_re_windows_the_draft_on_the_wire_and_a_moved_place_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let bare = open_session(port, CLAIMANT_PRINCIPAL);
    let e = edition(port, &signed);
    let d = draft_with(port, &bare, "abc");
    let b = format!("{d}.0.1.2");
    // The client's reading: `b c` at ordinal 2 of the draft, one run.
    assert_eq!(image_as(port, Some(&bare), &d, 2, 2), vec![(b.clone(), "2".to_string())]);
    let placed = |frame: &str, places: Value| -> Value {
        let mut v: Value = serde_json::from_str(frame).expect("a frame");
        v["places"] = places;
        v
    };
    let place = |ordinal: u64| serde_json::json!([{"subspace": "1", "ordinal": ordinal.to_string()}]);

    // The signature over the frame without places, attached to the frame
    // with them.
    let unplaced = publish(&e, None, Some(&d), &[run(&d, &b, 2)]);
    let attested: Value = serde_json::from_str(&attach_attest(port, &signed, &unplaced)).expect("a frame");
    let attest = attested["attest"].clone();
    assert!(attest.is_object(), "the suite's signer attested the shot: {attested}");
    let mut shot = placed(&unplaced, place(2));
    shot["attest"] = attest;
    let before = head(port);
    let member = acked_addr(&op_as_written(port, Some(&signed), &shot.to_string()));
    assert_eq!(member, format!("{e}.1"));
    // The draft: the same text, the member's fresh run where `b c` were.
    assert_eq!(text_as(port, Some(&bare), &d, 1, 3), "abc");
    assert_eq!(content_extent_as(port, Some(&bare), &d), 3);
    let fresh = image(port, &member, 1, 2);
    assert_eq!(fresh, vec![(format!("{e}.0.1.1"), "2".to_string())]);
    assert_eq!(image_as(port, Some(&bare), &d, 2, 2), fresh, "the draft arranges the member's identity at the place");
    assert_eq!(image_as(port, Some(&bare), &d, 1, 1), vec![(format!("{d}.0.1.1"), "1".to_string())], "the draft's own `a` at its own address");
    assert_eq!(text(port, &member, 1, 2), "bc");
    // The record, and the row as the spine left it.
    let record = read_link(port, Some(&bare), &format!("{d}.0.2.1"));
    assert_eq!(record["slots"][0][0]["start"].as_str(), Some(b.as_str()), "the record names the draft's run: {record}");
    let owners = changes_since_as(port, Some(&signed), before);
    assert_eq!(owners.len(), 1, "one commit: {owners:?}");
    assert_eq!(owners[0]["docs"], serde_json::json!([member, d]), "the member first, the draft beside it: {}", owners[0]);
    assert!(owners[0]["attest"].is_object(), "{}", owners[0]);

    // A moved place: a second draft `x y z`, `y` and `x` swapped after the
    // place of `y z` was read.
    let d2 = draft_with(port, &bare, "xyz");
    let yz = format!("{d2}.0.1.2");
    assert_eq!(image_as(port, Some(&bare), &d2, 2, 2), vec![(yz.clone(), "2".to_string())]);
    expect_resp(&op(port, Some(&bare), &rearrange_frame(&d2, [1, 2, 3])), "ack");
    assert_eq!(text_as(port, Some(&bare), &d2, 1, 3), "yxz");
    let stale = placed(&publish(&e, Some((&member, 2)), Some(&d2), &[run(&d2, &yz, 2)]), place(2));
    let before = head(port);
    let v = op(port, Some(&signed), &stale.to_string());
    let rej = expect_resp(&v, "rejected");
    assert_eq!(rej["code"].as_str(), Some("kept_place_moved"), "{v}");
    assert_eq!(rej["disposition"].as_str(), Some("permanent"), "{v}");
    assert_eq!(rej["site"], serde_json::json!({"index": 0}), "the runs entry, and nothing else: {v}");
    assert!(rej.get("detail").is_none(), "no detail rides the code: {v}");
    assert_eq!(head(port), before, "nothing committed");
    assert!(changes_since(port, before).is_empty());
    assert_eq!(text_as(port, Some(&bare), &d2, 1, 3), "yxz", "the draft as the rearrangement left it");

    // The shape, refused at the codec with the entry, before any store: a
    // window onto a third document, and a list longer than `runs`.
    let d3 = draft_with(port, &bare, "q");
    let before = head(port);
    let windowed = publish(&e, Some((&member, 2)), Some(&d2), &[run(&d3, &format!("{d3}.0.1.1"), 1), run(&d2, &yz, 2)]);
    let v = op_as_written(port, Some(&signed), &placed(&windowed, serde_json::json!([{"subspace": "1", "ordinal": "1"}, null])).to_string());
    let rej = expect_resp(&v, "rejected");
    assert_eq!((rej["code"].as_str(), rej["op"].as_str()), (Some("malformed"), Some("unparseable")), "{v}");
    assert_eq!(rej["site"], serde_json::json!({"index": 0}), "a place on a window onto another document: {v}");
    let v = op_as_written(port, Some(&signed), &placed(&windowed, serde_json::json!([null, null, null])).to_string());
    assert_eq!(expect_resp(&v, "rejected")["site"], serde_json::json!({"index": 2}), "longer than runs: {v}");
    assert_eq!(head(port), before);
    // A place on the edition's own run is a stray place: admitted by the
    // codec, and refused by the store where no record of the draft names
    // that identity — `d2` has none — `stray_place_unrecorded`, the entry.
    let both = publish(&e, Some((&member, 2)), Some(&d2), &[run(&e, &format!("{e}.0.1.1"), 2), run(&d2, &yz, 2)]);
    let v = op(port, Some(&signed), &placed(&both, serde_json::json!([{"subspace": "1", "ordinal": "1"}, null])).to_string());
    let rej = expect_resp(&v, "rejected");
    assert_eq!(rej["code"].as_str(), Some("stray_place_unrecorded"), "{v}");
    assert_eq!(rej["disposition"].as_str(), Some("permanent"), "{v}");
    assert_eq!(rej["site"], serde_json::json!({"index": 0}), "the runs entry, and nothing else: {v}");
    assert!(rej.get("detail").is_none(), "{v}");
    assert_eq!(head(port), before, "nothing committed");
    sd.shutdown();
}

/// THE STRAY PLACES ON THE WIRE (the link-sets design §5.7, "AND THE STRAY
/// PLACES WITH THEM"; wire.md §The publish shot and head-float, the kept
/// places; lane F4): a draft published with `b c` at its place, then a raw
/// `reinstate` of the draft's own `b c` after them — the record's draft
/// words back in the draft as private text — and a second shot whose
/// `runs` re-compose them BY REFERENCE to the record's published words,
/// E's own identity, with their kept place beside: the draft, read back as
/// its owner, holds the same text and images E's identity at the place,
/// its own words nowhere; the member holds the run by reference, twice;
/// no new record (the draft's second link address is empty); the feed row
/// one commit with its `attest` kept and the member FIRST with the draft
/// beside it in its `docs` to the owner — the row names the draft where
/// the commit wrote it, a record minted in it or a kept place re-windowing
/// it (F4's owed line; wire.md §The change feed), and a stray-only shot
/// re-windows it though it mints none — the member alone to a guest, the
/// `attest` kept on the reduced row; the owner's page under the draft
/// carries the commit; and the signature the suite's signer made over the
/// frame WITHOUT `places` verifies the frame with them. Then identity of E
/// minted from another draft's words, re-composed from this draft with a
/// place, is refused `stray_place_unrecorded`, permanent, `site.index` the
/// entry and nothing else, nothing committed.
#[test]
fn a_stray_run_re_composed_by_reference_to_its_record_is_re_windowed_on_the_wire_and_an_unrecorded_one_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let bare = open_session(port, CLAIMANT_PRINCIPAL);
    let e = edition(port, &signed);
    let d = draft_with(port, &bare, "abc");
    let b = format!("{d}.0.1.2");
    let fresh = format!("{e}.0.1.1");
    let placed = |frame: &str, places: Value| -> Value {
        let mut v: Value = serde_json::from_str(frame).expect("a frame");
        v["places"] = places;
        v
    };
    // E.1: `b c` with its place — the draft re-windowed, as S2 left it.
    let first = placed(&publish(&e, None, Some(&d), &[run(&d, &b, 2)]), serde_json::json!([{"subspace": "1", "ordinal": "2"}]));
    let member = acked_addr(&op(port, Some(&signed), &first.to_string()));
    assert_eq!(member, format!("{e}.1"));
    assert_eq!(image_as(port, Some(&bare), &d, 2, 2), vec![(fresh.clone(), "2".to_string())]);
    // The stray act: the draft's own `b c`, reinstated after them.
    expect_resp(&op(port, Some(&bare), &reinstate_frame(&d, 4, &[(&d, &b, 2)])), "ack");
    assert_eq!(text_as(port, Some(&bare), &d, 1, 5), "abcbc");
    assert_eq!(image_as(port, Some(&bare), &d, 4, 2), vec![(b.clone(), "2".to_string())], "the record's draft words, private text again");
    // The second shot: the head's `b c` by reference, then the stray run
    // re-composed by reference to the record's `to`, its place beside it —
    // the signature over the frame without places, attached to the frame
    // with them.
    let unplaced = publish(&e, Some((&member, 2)), Some(&d), &[run(&e, &fresh, 2), run(&e, &fresh, 2)]);
    let attested: Value = serde_json::from_str(&attach_attest(port, &signed, &unplaced)).expect("a frame");
    let attest = attested["attest"].clone();
    assert!(attest.is_object(), "the suite's signer attested the shot: {attested}");
    let mut shot = placed(&unplaced, serde_json::json!([null, {"subspace": "1", "ordinal": "4"}]));
    shot["attest"] = attest;
    let before = head(port);
    let second = acked_addr(&op_as_written(port, Some(&signed), &shot.to_string()));
    assert_eq!(second, format!("{e}.2"));
    assert_eq!(text_as(port, Some(&bare), &d, 1, 5), "abcbc", "the draft reads the same text");
    assert_eq!(content_extent_as(port, Some(&bare), &d), 5);
    assert_eq!(image_as(port, Some(&bare), &d, 4, 2), vec![(fresh.clone(), "2".to_string())], "E's identity at the place");
    assert_eq!(image_as(port, Some(&bare), &d, 2, 2), vec![(fresh.clone(), "2".to_string())], "and where S2 put it");
    assert_eq!(text(port, &second, 1, 4), "bcbc");
    // `image` answers a SET of distinct runs, so the run held twice is read
    // at each place.
    assert_eq!(image(port, &second, 1, 2), vec![(fresh.clone(), "2".to_string())], "the member holds the run by reference");
    assert_eq!(image(port, &second, 3, 2), vec![(fresh.clone(), "2".to_string())], "twice");
    let record = read_link(port, Some(&bare), &format!("{d}.0.2.1"));
    assert_eq!(record["slots"][0][0]["start"].as_str(), Some(b.as_str()), "the S1 record stands: {record}");
    let none = read_link(port, Some(&bare), &format!("{d}.0.2.2"));
    assert!(none["link"].is_null(), "no new record: {none}");
    // The row: ONE commit, its `attest` kept — the member first and the
    // draft beside it to the owner: the feed names the staging draft where
    // the commit wrote it — "minted a correspondence record in it or
    // re-windowed it at a kept place" (§The change feed) — and a stray-only
    // shot mints none yet re-windows the draft's content, so the owner's
    // pages of the draft carry the commit that moved it. The guest's row is
    // reduced to the member, its `attest` kept (the exemption: the first
    // document is the member, which the reduction keeps).
    let owners = changes_since_as(port, Some(&signed), before);
    assert_eq!(owners.len(), 1, "one commit: {owners:?}");
    assert_eq!(owners[0]["docs"], serde_json::json!([second, d]), "the member first, the re-windowed draft beside it: {}", owners[0]);
    assert!(owners[0]["attest"].is_object(), "{}", owners[0]);
    let guests = changes_since(port, before);
    assert_eq!(guests.len(), 1, "one commit: {guests:?}");
    assert_eq!(guests[0]["docs"], serde_json::json!([second]), "reduced to the member for a guest: {}", guests[0]);
    assert_eq!(guests[0]["attest"], owners[0]["attest"], "the reduced row keeps its attest");
    let (st, body) = http(port, "GET", &format!("/changes?since={before}&under={d}"), Some(&signed), b"");
    assert_eq!(st, 200, "{}", String::from_utf8_lossy(&body));
    let under = json(&body)["changes"].as_array().expect("changes").clone();
    assert_eq!(under.len(), 1, "the owner's page under the draft carries the re-window: {under:?}");
    assert_eq!(under[0]["at"], owners[0]["at"]);
    let (st, body) = http(port, "GET", &format!("/changes?since={before}&under={d}"), None, b"");
    assert_eq!(st, 200, "{}", String::from_utf8_lossy(&body));
    assert!(json(&body)["changes"].as_array().expect("changes").is_empty(), "a guest's page under the draft is empty");
    // Unrecorded: `x y` minted into E from a second draft — recorded there,
    // not in `d` — re-composed from `d` with a place.
    let d2 = draft_with(port, &bare, "xy");
    let x = format!("{d2}.0.1.1");
    let third = acked_addr(&op(port, Some(&signed), &publish(&e, Some((&second, 4)), Some(&d2), &[run(&e, &fresh, 2), run(&e, &fresh, 2), run(&d2, &x, 2)])));
    assert_eq!(third, format!("{e}.3"));
    let xy = format!("{e}.0.1.3");
    assert_eq!(image(port, &third, 5, 2), vec![(xy.clone(), "2".to_string())]);
    let stale = placed(
        &publish(&e, Some((&third, 6)), Some(&d), &[run(&e, &fresh, 2), run(&e, &fresh, 2), run(&e, &xy, 2)]),
        serde_json::json!([null, null, {"subspace": "1", "ordinal": "1"}]),
    );
    let before = head(port);
    let v = op(port, Some(&signed), &stale.to_string());
    let rej = expect_resp(&v, "rejected");
    assert_eq!(rej["code"].as_str(), Some("stray_place_unrecorded"), "{v}");
    assert_eq!(rej["disposition"].as_str(), Some("permanent"), "{v}");
    assert_eq!(rej["site"], serde_json::json!({"index": 2}), "the runs entry, and nothing else: {v}");
    assert!(rej.get("detail").is_none(), "no detail rides the code: {v}");
    assert_eq!(head(port), before, "nothing committed");
    assert!(changes_since(port, before).is_empty());
    sd.shutdown();
}

// ── THE PUBLICATION's DEPOSITS AND ITS SIGNED BODY (the link-sets design §5.7; lane S3) ──

/// `frame` with the members of `extra` set beside the shot's own.
fn with_members(frame: &str, extra: Value) -> String {
    let mut v: Value = serde_json::from_str(frame).expect("a JSON frame");
    for (k, val) in extra.as_object().expect("an object of members") {
        v[k] = val.clone();
    }
    v.to_string()
}

/// The board every deposit cell stands on: the claimant's signed session S
/// and bare session B; `E`, an empty published edition; `D`, a private
/// draft holding `abc`; `N`, a private notes document holding the original
/// `L` (homed in `N`, `from` the draft's text, a ghost type); `SET`, a
/// second published edition holding the link `R` (homed in it, signed).
struct DepositBoard {
    signed: String,
    bare: String,
    e: String,
    d: String,
    d_text: String,
    n: String,
    l: String,
    set: String,
    r: String,
}

fn deposit_board(port: u16) -> DepositBoard {
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let bare = open_session(port, CLAIMANT_PRINCIPAL);
    let e = edition(port, &signed);
    let d = draft_with(port, &bare, "abc");
    let d_text = format!("{d}.0.1.1");
    let n = draft(port, &bare);
    let l = acked_addr(&op(port, Some(&bare), &link_frame(&n, &addrs_slot(&[&d_text]), &addrs_slot(&[]), &ghost_ty(&n, 1))));
    assert_eq!(l, format!("{n}.0.2.1"));
    let set = edition(port, &signed);
    let r = acked_addr(&op(port, Some(&signed), &link_frame(&set, &addrs_slot(&[&set]), &addrs_slot(&[]), &ghost_ty(&set, 1))));
    assert_eq!(r, format!("{set}.0.2.1"));
    DepositBoard { signed, bare, e, d, d_text, n, l, set, r }
}

impl DepositBoard {
    /// The drafted shot of `D`'s three bytes into `E`, as a birth version.
    fn shot(&self) -> String {
        publish(&self.e, None, Some(&self.d), &[run(&self.d, &self.d_text, 3)])
    }

    /// One accepted link: homed in the member, `from` the member's own three
    /// positions (the draft's new words, by the member-position form), `to`
    /// `SET`, typed a ghost type of `E`'s, the original `L` named.
    fn copy_entry(&self) -> Value {
        serde_json::json!({
            "home": "member",
            "from": {"member": [{"ordinal": "1", "width": "3"}]},
            "to": {"addrs": [self.set]},
            "ty": {"addrs": [format!("{}.0.3.6.1", self.e)]},
            "old": self.l,
        })
    }

    /// The shot carrying the copy, `R`'s retraction and the read-with.
    fn full(&self) -> String {
        with_members(&self.shot(), serde_json::json!({"links": [self.copy_entry()], "retract": [self.r], "read_with": [self.set]}))
    }
}

/// The first span of slot `k` of a link value: `(start, width's last component)`.
fn slot_span(link: &Value, k: usize) -> (String, String) {
    let span = &link["slots"][k][0];
    let width = span["width"].as_str().expect("a width").rsplit('.').next().expect("a component").to_string();
    (span["start"].as_str().expect("a start").to_string(), width)
}

/// Assert a deposit refusal: the code, permanent, `site.index` the entry and
/// nothing else in the site, the detail as given.
fn assert_deposit_refused(v: &Value, code: &str, index: u64, detail: Option<&str>) {
    let rej = expect_resp(v, "rejected");
    assert_eq!(rej["code"].as_str(), Some(code), "{v}");
    assert_eq!(rej["disposition"].as_str(), Some("permanent"), "{v}");
    assert_eq!(rej["site"], serde_json::json!({"index": index}), "the entry, and nothing else: {v}");
    assert_eq!(rej["detail"].as_str(), detail, "{v}");
}

/// THE ONE COMMIT (the link-sets design §5.7, THE COMPOSITE's DEPOSITS): a
/// signed publication carrying a `links` entry with its original, a
/// `retract` and a `read_with` lands the member, the correspondence record,
/// the public copy in the member's own link subspace — its `from` the fresh
/// run the member-position end resolved to, its `to` and type as given —
/// the original's supersession claim in `N`, the retraction tuple in
/// `SET` and the read-with in `SET`, in ONE commit (one feed entry); the
/// original stands, superseded, not retracted; `R` is gone from the active
/// view; and the row's `docs` name the member FIRST, then `D`, then every
/// other home the commit touched in address order — `N` (the claim's home)
/// and `SET` — for the owner, reduced to the member and `SET` for a guest,
/// the `attest` kept on both pages. Then THE PIN at the wire: `SET`'s links
/// rise in the plan's order — the retraction, then the read-with.
#[test]
fn a_publication_lands_its_copy_claim_retraction_and_read_with_in_one_commit_and_names_every_home() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let b = deposit_board(port);
    let before = head(port);
    let member = acked_addr(&op(port, Some(&b.signed), &b.full()));
    assert_eq!(member, format!("{}.1", b.e));
    assert_eq!(text(port, &member, 1, 3), "abc");
    let entries = changes_since_as(port, Some(&b.signed), before);
    assert_eq!(entries.len(), 1, "one commit: {entries:?}");
    // The copy, in the member's own subspace: `from` the fresh run the
    // member's positions resolved to, `to` SET's unit span, the type as given.
    let fresh = image(port, &member, 1, 3);
    assert_eq!(fresh.len(), 1, "one fresh run: {fresh:?}");
    let copy = read_link(port, None, &format!("{member}.0.2.1"));
    assert!(!copy.is_null(), "the copy is the member's first link");
    assert_eq!(slot_span(&copy, 0), (fresh[0].0.clone(), "3".to_string()), "`from` the member's fresh run: {copy}");
    assert_eq!(slot_span(&copy, 1).0, b.set, "`to` the set: {copy}");
    assert_eq!(slot_span(&copy, 2).0, format!("{}.0.3.6.1", b.e), "typed as given: {copy}");
    // The claim in N: `from` L, `to` the copy, the supersedes class; L stands.
    let claim = read_link(port, Some(&b.bare), &format!("{}.0.2.2", b.n));
    assert_eq!(slot_span(&claim, 0).0, b.l, "{claim}");
    assert_eq!(slot_span(&claim, 1).0, format!("{member}.0.2.1"), "{claim}");
    assert_eq!(slot_span(&claim, 2).0, T_SUPERSEDES, "{claim}");
    assert!(!read_link(port, Some(&b.bare), &b.l).is_null(), "the original stands, superseded");
    // The retraction tuple in SET, then the read-with: the addresses rising
    // in the plan's order (THE PIN).
    let retraction = read_link(port, None, &format!("{}.0.2.2", b.set));
    assert_eq!(slot_span(&retraction, 2).0, T_RETRACTION, "{retraction}");
    assert_eq!(slot_span(&retraction, 1).0, b.r, "`to` R: {retraction}");
    let read_with = read_link(port, None, &format!("{}.0.2.3", b.set));
    assert_eq!(slot_span(&read_with, 2).0, T_READ_WITH, "{read_with}");
    assert_eq!(slot_span(&read_with, 0).0, b.e, "`from` the edition: {read_with}");
    assert_eq!(slot_span(&read_with, 1).0, b.set, "`to` the set: {read_with}");
    let active = find_links_ftt_home(port, None, &b.set);
    assert!(!active.contains(&b.r), "R is retracted: {active:?}");
    assert!(active.contains(&format!("{}.0.2.3", b.set)), "the read-with is active: {active:?}");
    // The row: the member first, D, then N and SET in address order; the
    // guest's reduced to what it may read, its attest kept.
    let mut others = vec![b.n.clone(), b.set.clone()];
    others.sort_by_key(|a| a.split('.').map(|c| c.parse::<u64>().unwrap()).collect::<Vec<_>>());
    let mut want = vec![member.clone(), b.d.clone()];
    want.extend(others);
    assert_eq!(entries[0]["docs"], serde_json::json!(want), "{}", entries[0]);
    assert!(entries[0]["attest"].is_object(), "{}", entries[0]);
    let guests = changes_since(port, before);
    assert_eq!(guests[0]["docs"], serde_json::json!([member, b.set]), "reduced for the guest: {}", guests[0]);
    assert_eq!(guests[0]["attest"], entries[0]["attest"], "the exemption keeps the attest");
    sd.shutdown();
}

/// THE SIGNED BODY (the signed-ops record's D25 delta): the deposit rows are
/// IN the preimage — a signature made over the shot's body alone, the rows
/// left out, is refused `attestation_invalid:signature`, nothing committed;
/// and a body naming a deposit the plan SKIPS — a `retract` of a link
/// already retracted — is refused the same way, where the signer that reads
/// the skip as the board does lands the publication with no row for it, the
/// feed row then naming no home for the skipped entry.
#[test]
fn a_body_missing_the_deposit_rows_or_naming_a_skipped_one_is_refused_for_its_signature() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let b = deposit_board(port);
    let before = head(port);
    // The rows left out: the shot alone's attest, moved onto the frame with
    // its links.
    let signed_shot: Value = serde_json::from_str(&attach_attest(port, &b.signed, &b.shot())).expect("a frame");
    let mut frame: Value = serde_json::from_str(&with_members(&b.shot(), serde_json::json!({"links": [b.copy_entry()]}))).expect("a frame");
    frame["attest"] = signed_shot["attest"].clone();
    let v = op_as_written(port, Some(&b.signed), &frame.to_string());
    let rej = expect_resp(&v, "rejected");
    assert_eq!((rej["code"].as_str(), rej["detail"].as_str()), (Some("credential_refused"), Some("attestation_invalid:signature")), "{v}");
    assert_eq!(head(port), before, "nothing committed");
    // A skipped deposit: R retracted first, then a publication retracting it
    // again — signed over the row, refused; signed as the board reads the
    // skip, landed with no row and no home for it.
    expect_resp(&op(port, Some(&b.signed), &nullify_frame(&b.set, &b.r)), "ack_addr");
    let before = head(port);
    let skipped = with_members(&b.shot(), serde_json::json!({"retract": [b.r]}));
    let v = op_unskipped(port, &b.signed, &skipped);
    let rej = expect_resp(&v, "rejected");
    assert_eq!((rej["code"].as_str(), rej["detail"].as_str()), (Some("credential_refused"), Some("attestation_invalid:signature")), "{v}");
    assert_eq!(head(port), before, "nothing committed");
    let member = acked_addr(&op(port, Some(&b.signed), &skipped));
    let owners = changes_since_as(port, Some(&b.signed), before);
    assert_eq!(owners.len(), 1);
    assert_eq!(owners[0]["docs"], serde_json::json!([member, b.d]), "the skipped entry names no home: {}", owners[0]);
    assert!(read_link(port, None, &format!("{}.0.2.3", b.set)).is_null(), "no second retraction in SET");
    sd.shutdown();
}

/// THE MINT FORM on the wire: `account` with `mint` and `claim`, no `doc` —
/// the commit mints a published edition `E′` under the account, its first
/// member `E′.1` holding the draft's words (the ack's address), the edition
/// claim homed in `E′` `to` the draft (`edition_claims` lists it, active),
/// and the read-with from `E′` in `SET`; the row names the member, then the
/// edition, then the draft, then `SET`. A stranger's mint under the
/// claimant's account is `not_owner` naming the account. And THE CLAIM AT
/// THE DOCUMENT FORM WHERE A MEMBER STANDS (skep #692): once `E` holds a
/// first version, a shot off it carrying `claim: true` is `claim_refused`,
/// `member_stands`, `site.addr` the edition — the shot's own table ahead,
/// the plan's step behind — nothing committed.
#[test]
fn the_mint_form_mints_the_edition_its_member_the_claim_and_the_read_with_in_one_commit() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let b = deposit_board(port);
    let mint = format!(
        r#"{{"op":"publish","account":"{CLAIMANT_ACCOUNT}","mint":true,"claim":true,"draft":"{}","runs":[{}],"read_with":["{}"]}}"#,
        b.d,
        run(&b.d, &b.d_text, 3),
        b.set
    );
    let before = head(port);
    let member = acked_addr(&op(port, Some(&b.signed), &mint));
    let edition = member.strip_suffix(".1").expect("the edition's first member").to_string();
    assert!(edition.starts_with(&format!("{CLAIMANT_ACCOUNT}.0.")), "minted under the account: {member}");
    assert_ne!(edition, b.e, "a fresh edition");
    assert_eq!(doc_metadata(port, None, &edition)["published"], serde_json::json!(true), "born published");
    assert_eq!(text(port, &member, 1, 3), "abc");
    let claims = op(port, Some(&b.bare), &format!(r#"{{"op":"edition_claims","target":"{}"}}"#, b.d));
    let rows = expect_resp(&claims, "edition_claims")["claims"].as_array().expect("claims").clone();
    assert_eq!(rows.len(), 1, "the one claim: {claims}");
    assert_eq!((rows[0]["home"].as_str(), rows[0]["active"].as_bool()), (Some(edition.as_str()), Some(true)), "{claims}");
    let read_with = read_link(port, None, &format!("{}.0.2.2", b.set));
    assert_eq!(slot_span(&read_with, 0).0, edition, "`from` the minted edition: {read_with}");
    let owners = changes_since_as(port, Some(&b.signed), before);
    assert_eq!(owners.len(), 1, "one commit: {owners:?}");
    assert_eq!(owners[0]["docs"], serde_json::json!([member, edition, b.d, b.set]), "{}", owners[0]);
    // A stranger's mint under the claimant's account.
    let boot = open_session(port, 0);
    let before = head(port);
    assert_not_owner(&op(port, Some(&boot), &mint), CLAIMANT_ACCOUNT);
    assert_eq!(head(port), before);
    // The claim at the document form where a member stands: a first version
    // lands in `E` from a fresh draft (the deposit board's `D` is published
    // already, its words fenced); then a shot off that member carrying
    // `claim: true` is refused naming the edition, nothing committed.
    let d2 = draft_with(port, &b.bare, "xyz");
    let e1 = acked_addr(&op(port, Some(&b.signed), &publish(&b.e, None, Some(&d2), &[run(&d2, &format!("{d2}.0.1.1"), 3)])));
    assert_eq!(e1, format!("{}.1", b.e));
    let before = head(port);
    let claiming = with_members(&publish(&b.e, Some((&e1, 3)), Some(&d2), &[]), serde_json::json!({"claim": true}));
    let v = op(port, Some(&b.signed), &claiming);
    let rej = expect_resp(&v, "rejected");
    assert_eq!((rej["code"].as_str(), rej["disposition"].as_str(), rej["detail"].as_str()), (Some("claim_refused"), Some("permanent"), Some("member_stands")), "{v}");
    assert_eq!(rej["site"], serde_json::json!({"addr": b.e}), "the edition, and nothing else: {v}");
    assert_eq!(head(port), before, "nothing committed");
    sd.shutdown();
}

/// THE CLAIM AT A FIRST VERSION INTO AN EMPTY EDITION (skep #692; the
/// owner's publication-redesign decision 2 (i)): a published document with
/// no version in it takes its first version from a staging draft by the
/// DOCUMENT form — `doc` the edition, no mint — with `claim: true`, and the
/// one commit writes the edition claim homed in the edition exactly as the
/// mint form writes it: `edition_claims` of the draft lists it, active, its
/// home the edition; the link is typed `3.14`, `from` the edition, `to` the
/// draft; the feed's one row names the member, the draft, then the edition
/// among the homes the deposits touched. A second publication claiming into
/// the same edition, a member standing, is `claim_refused` with
/// `member_stands` and `site.addr` the edition, nothing committed; `claim`
/// at the document form with no `draft` is `malformed` naming `draft`, at
/// the codec.
#[test]
fn a_first_version_into_an_empty_edition_carries_its_claim() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let bare = open_session(port, CLAIMANT_PRINCIPAL);
    let e = edition(port, &signed);
    let d = draft_with(port, &bare, "abc");
    let before = head(port);
    let first = with_members(&publish(&e, None, Some(&d), &[run(&d, &format!("{d}.0.1.1"), 3)]), serde_json::json!({"claim": true}));
    let member = acked_addr(&op(port, Some(&signed), &first));
    assert_eq!(member, format!("{e}.1"), "the edition's first member");
    assert_eq!(text(port, &member, 1, 3), "abc");
    // The claim: listed by the draft, homed in the edition, active — the
    // mint form's record, in the edition `doc` named.
    let claims = op(port, Some(&bare), &format!(r#"{{"op":"edition_claims","target":"{d}"}}"#));
    let rows = expect_resp(&claims, "edition_claims")["claims"].as_array().expect("claims").clone();
    assert_eq!(rows.len(), 1, "the one claim: {claims}");
    assert_eq!((rows[0]["home"].as_str(), rows[0]["active"].as_bool()), (Some(e.as_str()), Some(true)), "{claims}");
    let claim = read_link(port, None, &format!("{e}.0.2.1"));
    assert_eq!(slot_span(&claim, 2).0, T_EDITION, "typed the edition class: {claim}");
    assert_eq!(slot_span(&claim, 0).0, e, "`from` the edition: {claim}");
    assert_eq!(slot_span(&claim, 1).0, d, "`to` the draft: {claim}");
    // One commit; its row names the member, the draft, then the edition.
    let owners = changes_since_as(port, Some(&signed), before);
    assert_eq!(owners.len(), 1, "one commit: {owners:?}");
    assert_eq!(owners[0]["docs"], serde_json::json!([member, d, e]), "{}", owners[0]);
    // A member stands: a second publication claiming into E — from a fresh
    // draft, off the member, so the shot's own table and the twin fence are
    // passed — is refused naming the edition, nothing committed.
    let d2 = draft_with(port, &bare, "xyz");
    let before = head(port);
    let second = with_members(&publish(&e, Some((&member, 3)), Some(&d2), &[run(&d2, &format!("{d2}.0.1.1"), 3)]), serde_json::json!({"claim": true}));
    let v = op(port, Some(&signed), &second);
    let rej = expect_resp(&v, "rejected");
    assert_eq!((rej["code"].as_str(), rej["disposition"].as_str(), rej["detail"].as_str()), (Some("claim_refused"), Some("permanent"), Some("member_stands")), "{v}");
    assert_eq!(rej["site"], serde_json::json!({"addr": e}), "the edition, and nothing else: {v}");
    assert_eq!(head(port), before, "nothing committed");
    assert!(changes_since(port, before).is_empty());
    // The same shot without its claim lands as the second member.
    assert_eq!(acked_addr(&op(port, Some(&signed), &publish(&e, Some((&member, 3)), Some(&d2), &[run(&d2, &format!("{d2}.0.1.1"), 3)]))), format!("{e}.2"));
    // `claim` with no `draft`: the codec's refusal, naming the member owed.
    let v = op_as_written(port, Some(&signed), &with_members(&publish(&e, Some((&member, 3)), None, &[]), serde_json::json!({"claim": true})));
    let rej = expect_resp(&v, "rejected");
    assert_eq!((rej["code"].as_str(), rej["op"].as_str()), (Some("malformed"), Some("unparseable")), "{v}");
    assert!(rej["detail"].as_str().is_some_and(|d| d.contains("'draft'")), "{v}");
    sd.shutdown();
}

/// THE TOKENS over the wire, each with `site.index` the entry in its own
/// list, permanent, nothing committed, in the plan's order: a `links` entry
/// homed in a private draft is `link_home_refused`; one naming an absent
/// original `old_refused` with `absent`; a second entry naming one original
/// `duplicate_original` at the second; one typed the read-with
/// `read_with_in_links`; a `retract` of an absent link `retract_refused`
/// with `absent`, of the claimant's own credential link `not_retraction`
/// (the `nullify` class's cell, the daemon's own); a `read_with` naming a
/// private draft `read_with_refused` with `not_published`, an unregistered
/// document `not_registered`. The plan runs behind the shot's own table:
/// the same entries on a shot whose base is outside the chain answer
/// `base_not_in_chain`.
#[test]
fn each_refused_deposit_names_its_entry_and_commits_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let b = deposit_board(port);
    let d2 = draft(port, &b.bare);
    let before = head(port);
    let entry = |home: &str, old: Option<&str>, ty: &str| {
        let mut e = b.copy_entry();
        e["home"] = serde_json::json!(home);
        e["ty"] = serde_json::json!({"addrs": [ty]});
        match old {
            Some(old) => e["old"] = serde_json::json!(old),
            None => {
                e.as_object_mut().unwrap().remove("old");
            }
        }
        e
    };
    let ghost = format!("{}.0.3.6.1", b.e);
    let cells: Vec<(Value, &str, u64, Option<&str>)> = vec![
        (serde_json::json!({"links": [entry(&d2, None, &ghost)]}), "link_home_refused", 0, None),
        (serde_json::json!({"links": [entry("member", Some(&format!("{}.0.2.9", b.n)), &ghost)]}), "old_refused", 0, Some("absent")),
        (serde_json::json!({"links": [entry("member", Some(&b.l), &ghost), entry("member", Some(&b.l), &ghost)]}), "duplicate_original", 1, None),
        (serde_json::json!({"links": [entry("member", None, T_READ_WITH)]}), "read_with_in_links", 0, None),
        (serde_json::json!({"retract": [format!("{}.0.2.9", b.set)]}), "retract_refused", 0, Some("absent")),
        (serde_json::json!({"retract": [b.r, format!("{CLAIMANT_DOC1}.0.2.1")]}), "retract_refused", 1, Some("not_retraction")),
        (serde_json::json!({"read_with": [d2]}), "read_with_refused", 0, Some("not_published")),
        (serde_json::json!({"read_with": [b.set, "1.0.1.0.99"]}), "read_with_refused", 1, Some("not_registered")),
    ];
    for (members, code, index, detail) in cells {
        let v = op(port, Some(&b.signed), &with_members(&b.shot(), members.clone()));
        assert_deposit_refused(&v, code, index, detail);
        assert_eq!(head(port), before, "{code}: nothing committed");
    }
    // Behind the shot's own table.
    let stale = with_members(&publish(&b.e, Some((&b.set, 0)), Some(&b.d), &[run(&b.d, &b.d_text, 3)]), serde_json::json!({"read_with": [d2]}));
    assert_refused(&op(port, Some(&b.signed), &stale), "base_not_in_chain");
    assert_eq!(head(port), before);
    sd.shutdown();
}

// ───────────────────────── the ops items (lane S4) ─────────────────────────

/// THE HOLD's RELEASE on every path (`write_pool.rs`'s shape): a worker
/// parked at the guard's hold is one the daemon's stop joins, so a claim
/// that armed the hold releases it before its daemon drops.
struct Released;

impl Drop for Released {
    fn drop(&mut self) {
        skepd::Daemon::release_the_write_guard();
    }
}

/// Sends one `POST /op` as `token` and DROPS the connection without reading
/// its answer: the frame is on the daemon's socket whole, and its client is
/// gone (wire.md §Transport, a frame received is applied).
fn send_and_drop(port: u16, token: &str, frame: &str) {
    use std::io::Write as _;
    let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect to skepd");
    let head = format!(
        "POST /op HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\nContent-Length: {}\r\n\
         Skepd-Session: {token}\r\nContent-Type: application/json\r\n\r\n",
        frame.len()
    );
    stream.write_all(head.as_bytes()).expect("the request head");
    stream.write_all(frame.as_bytes()).expect("the request body");
    stream.flush().expect("flushed");
}

/// A records-less publish off `member`, which holds `abc` as one fresh run:
/// the next member of `E` with the same words, placed by reference, naming
/// no draft and so minting no record.
fn records_less_shot(port: u16, b: &DepositBoard, member: &str) -> String {
    let fresh_start = image(port, member, 1, 3)[0].0.clone();
    publish(&b.e, Some((member, 3)), None, &[run(&b.e, &fresh_start, 3)])
}

/// Whether `doc` — a member among them — is registered: `doc_metadata`
/// answers it rather than refusing.
fn registered(port: u16, doc: &str) -> bool {
    op(port, None, &doc_metadata_frame(doc))["resp"].as_str() == Some("doc_metadata")
}

/// The hold's shape for the pending-frame cells: the guard armed, one
/// writer parked at it holding the serialization lock — THE LARGE COMMIT
/// the design holds the applier with — then `frame` sent under `token` and
/// its connection dropped, then the re-ask of `frame` on a thread, each
/// given its moment to be received and to park at the lock; the guard
/// released, the parked writer joined and the re-ask's answer returned.
fn pending_then_re_ask(sd: &skepd::Skepd, b: &DepositBoard, frame: &str) -> Value {
    let port = sd.port();
    skepd::Daemon::hold_the_write_guard();
    let _released = Released;
    let parked = {
        let bare = b.bare.clone();
        std::thread::spawn(move || op(port, Some(&bare), &create_frame(CLAIMANT_ACCOUNT, None)))
    };
    std::thread::sleep(std::time::Duration::from_millis(500));
    send_and_drop(port, &b.signed, frame);
    std::thread::sleep(std::time::Duration::from_millis(500));
    let re_ask = {
        let (token, frame) = (b.signed.clone(), frame.to_string());
        std::thread::spawn(move || op_as_written(port, Some(&token), &frame))
    };
    std::thread::sleep(std::time::Duration::from_millis(500));
    skepd::Daemon::release_the_write_guard();
    expect_resp(&parked.join().expect("the parked writer"), "ack_addr");
    re_ask.join().expect("the re-ask")
}

/// THE PRICE AHEAD OF THE LOCK over the wire (the link-sets design §5.7, W8
/// (1)): the draft fragmented into eighteen content runs by seventeen inserts
/// at its first position, and a shot of 4096 runs over it priced at
/// 18 × 4096 — past `MAX_PUBLICATION_READS` — is refused
/// `publication_over_budget`, permanent, no `site`, its `detail` the four
/// terms, the total and the budget, WITH EVERY WRITE PERMIT HELD: the refusal
/// stands ahead of the pool, so ahead of both locks and of the admission
/// (the frame is sent unsigned, and the price answers before the signature
/// is asked for); nothing committed. The same draft under 3640 runs prices
/// inside the budget and passes the step, the admission then answering for
/// the unsigned frame; and an ordinary one-run shot off the fragmented
/// draft, priced 18, lands.
#[test]
fn a_publication_priced_past_the_reads_budget_is_refused_ahead_of_the_write_pool_and_commits_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let b = deposit_board(port);
    for _ in 0..17 {
        expect_resp(&op(port, Some(&b.bare), &insert(&b.d, 1, "x", false)), "ack_addr");
    }
    let runs: Vec<String> = (0..4096).map(|_| run(&b.d, &b.d_text, 1)).collect();
    let over = publish(&b.e, None, Some(&b.d), &runs);
    let before = head(port);
    let mut held = Vec::new();
    while let Some(permit) = sd.daemon().try_hold_write_permit() {
        held.push(permit);
    }
    assert!(!held.is_empty(), "the pool's permits, every one held");
    let v = op_as_written(port, Some(&b.signed), &over);
    let rej = expect_resp(&v, "rejected");
    assert_eq!(rej["code"].as_str(), Some("publication_over_budget"), "{v}");
    assert_eq!(rej["disposition"].as_str(), Some("permanent"), "{v}");
    assert!(rej.get("site").is_none(), "no site: {v}");
    let detail = rej["detail"].as_str().expect("the price's detail");
    assert!(detail.starts_with(&format!("{} in-lock reads priced over the budget of {}: ", 18 * 4096, skep_links::MAX_PUBLICATION_READS)), "{detail}");
    assert!(detail.ends_with("link-holding homes × 0 links and read-with entries + 18 draft runs × 4096 runs; narrow the request"), "{detail}");
    drop(held);
    assert_eq!(head(port), before, "nothing committed");
    // Inside the budget: 18 × 3640 = 65520 passes the price; the unsigned
    // frame then meets the admission, never the price.
    let v = op_as_written(port, Some(&b.signed), &publish(&b.e, None, Some(&b.d), &runs[..3640]));
    let rej = expect_resp(&v, "rejected");
    assert_ne!(rej["code"].as_str(), Some("publication_over_budget"), "at the budget the price admits: {v}");
    assert_eq!(head(port), before);
    // An ordinary shot off the fragmented draft, priced 18, lands.
    let member = acked_addr(&op(port, Some(&b.signed), &publish(&b.e, None, Some(&b.d), &[run(&b.d, &b.d_text, 1)])));
    assert_eq!(member, format!("{}.1", b.e));
    sd.shutdown();
}

/// THE STAGED BYTES PRICED AHEAD OF THE LOCK over the wire (the link-sets
/// design §5.6, M6; lane F4): a shot of 4096 runs, one per byte of a
/// 4096-byte burst in the draft, and a hundred `links` entries whose `from`
/// names the member's 4096 positions in the member-position form — each up
/// to 4096 stored spans for 36 bytes of body, which the price bounds by the
/// runs — prices past `MAX_TXN_BYTES` with the reads inside their budget,
/// and is refused `publication_over_budget`, permanent, no `site`, its
/// `detail` the bytes and the transaction budget and no word of the reads,
/// WITH EVERY WRITE PERMIT HELD: ahead of the pool, both locks and the
/// admission (the frame is sent unsigned); nothing committed. One such
/// entry prices inside both budgets and passes the step, the unsigned frame
/// then meeting the admission.
#[test]
fn a_publication_priced_past_the_transaction_budget_is_refused_ahead_of_the_write_pool_and_commits_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let b = deposit_board(port);
    // Four thousand and ninety-six bytes after `a b c`, one run of the
    // draft from `{d}.0.1.4`; the shot names each as a run of its own.
    let burst: String = "x".repeat(4096);
    expect_resp(&op(port, Some(&b.bare), &insert(&b.d, 4, &burst, false)), "ack_addr");
    let runs: Vec<String> = (0..4096u64).map(|i| run(&b.d, &format!("{}.0.1.{}", b.d, 4 + i), 1)).collect();
    let wide = |count: usize| {
        let entries: Vec<Value> = (0..count)
            .map(|_| serde_json::json!({"home": "member", "from": {"member": [{"ordinal": "1", "width": "4096"}]}, "to": {"addrs": []}, "ty": {"addrs": [format!("{}.0.3.6.1", b.e)]}}))
            .collect();
        with_members(&publish(&b.e, None, Some(&b.d), &runs), serde_json::json!({"links": entries}))
    };
    let before = head(port);
    let mut held = Vec::new();
    while let Some(permit) = sd.daemon().try_hold_write_permit() {
        held.push(permit);
    }
    assert!(!held.is_empty(), "the pool's permits, every one held");
    let v = op_as_written(port, Some(&b.signed), &wide(100));
    let rej = expect_resp(&v, "rejected");
    assert_eq!(rej["code"].as_str(), Some("publication_over_budget"), "{v}");
    assert_eq!(rej["disposition"].as_str(), Some("permanent"), "{v}");
    assert!(rej.get("site").is_none(), "no site: {v}");
    let detail = rej["detail"].as_str().expect("the price's detail");
    let budget = skep_links::ReadPrice::BYTE_BUDGET;
    assert!(detail.ends_with(&format!(" bytes would be staged against the transaction budget of {budget}; narrow the request")), "{detail}");
    assert!(!detail.contains("in-lock reads"), "the bytes, not the reads: {detail}");
    let bytes: u64 = detail.split(' ').next().and_then(|n| n.parse().ok()).expect("the bytes lead the detail");
    assert!(bytes > budget && bytes < 2 * budget, "{bytes} against {budget}");
    drop(held);
    assert_eq!(head(port), before, "nothing committed");
    // One wide entry: inside both budgets; the unsigned frame then meets the
    // admission, never the price.
    let v = op_as_written(port, Some(&b.signed), &wide(1));
    let rej = expect_resp(&v, "rejected");
    assert_ne!(rej["code"].as_str(), Some("publication_over_budget"), "inside the budgets the price admits: {v}");
    assert_eq!(head(port), before);
    sd.shutdown();
}

/// THE PENDING FRAME (a) (the link-sets design §5.7, W8 (2)): the applier
/// held with a large commit, a records-less publish sent under an `id` and
/// its connection dropped before its answer, the same frame re-asked under
/// the same `id` on the same session while the first still waits — the
/// re-ask WAITS and is answered the acknowledgment: the one member the frame
/// landed, by reference to the words `E.1` holds, and ONE version — no
/// daughter under `E.1` and no third member — one publish row on the feed.
/// A second execution queued behind the first would land `E.1.1`.
#[test]
fn a_re_ask_under_a_pending_records_less_frames_id_waits_and_lands_one_version() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let b = deposit_board(port);
    let member1 = acked_addr(&op(port, Some(&b.signed), &b.shot()));
    let frame = with_members(&records_less_shot(port, &b, &member1), serde_json::json!({"id": "pending-a"}));
    let signed = attach_attest(port, &b.signed, &frame);
    let before = head(port);
    let answer = pending_then_re_ask(&sd, &b, &signed);
    let member2 = acked_addr(&answer);
    assert_eq!(member2, format!("{}.2", b.e), "the re-ask is answered the acknowledgment of the one version: {answer}");
    assert_eq!(text(port, &member2, 1, 3), "abc");
    assert!(!registered(port, &format!("{}.1.1", b.e)), "no daughter: the frame ran once");
    assert!(!registered(port, &format!("{}.3", b.e)), "no third member");
    let rows = changes_since_as(port, Some(&b.signed), before);
    assert_eq!(rows.iter().filter(|r| r["op"].as_str() == Some("publish")).count(), 1, "one publish commit: {rows:?}");
    sd.shutdown();
}

/// THE PENDING FRAME (b): the same with links — S3's deposit board's full
/// publication, its copy, claim, retraction and read-with — re-asked while
/// the first frame waits: the acknowledgment read, never `old_refused` for
/// the original the first frame's own commit made public (no race face);
/// the copy in the member once, the claim in `N` once, one publish row.
#[test]
fn a_re_ask_under_a_pending_publications_id_is_answered_its_acknowledgment_and_never_a_race_face() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let b = deposit_board(port);
    let frame = with_members(&b.full(), serde_json::json!({"id": "pending-b"}));
    let signed = attach_attest(port, &b.signed, &frame);
    let before = head(port);
    let answer = pending_then_re_ask(&sd, &b, &signed);
    let member = acked_addr(&answer);
    assert_eq!(member, format!("{}.1", b.e), "the acknowledgment, not old_refused: {answer}");
    assert!(!read_link(port, None, &format!("{member}.0.2.1")).is_null(), "the copy, the member's first link");
    assert!(read_link(port, None, &format!("{member}.0.2.2")).is_null(), "…and its only one");
    assert!(!read_link(port, Some(&b.bare), &format!("{}.0.2.2", b.n)).is_null(), "the claim in N");
    assert!(read_link(port, Some(&b.bare), &format!("{}.0.2.3", b.n)).is_null(), "one claim, not two");
    assert!(!registered(port, &format!("{}.2", b.e)), "one version");
    let rows = changes_since_as(port, Some(&b.signed), before);
    assert_eq!(rows.iter().filter(|r| r["op"].as_str() == Some("publish")).count(), 1, "one publish commit: {rows:?}");
    sd.shutdown();
}

/// THE PENDING FRAME (c), THE ONE GAP: a `500` injected AFTER the commit —
/// the checkpoint thread held and the byte bound at one, so the
/// publication's own commit runs the backstop's checkpoint inline past its
/// install, armed to panic — answers `500 internal_panic` with the version
/// committed and its acknowledgment never memoized. THE READ BEFORE ANY
/// RE-SEND finds it: the trunk head is the member holding the request's
/// runs, so the landed test passes and the client re-sends nothing. The
/// hazard the read prevents, pinned as the wire states it: a blind re-send
/// under the same `id` re-executes and lands a daughter.
#[test]
fn a_publication_answered_500_after_its_commit_stands_and_the_read_precedes_any_re_send() {
    use skep_kernel::Step;

    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let b = deposit_board(port);
    let member1 = acked_addr(&op(port, Some(&b.signed), &b.shot()));
    let frame = with_members(&records_less_shot(port, &b, &member1), serde_json::json!({"id": "lost-c"}));
    let signed = attach_attest(port, &b.signed, &frame);
    sd.daemon().hold_the_checkpoint_thread();
    sd.daemon().set_checkpoint_bytes_bound(1);
    // The first crossing sets the due flag; the publication's crossing then
    // runs the backstop inline, which panics past the commit's install.
    expect_resp(&op(port, Some(&b.bare), &create_frame(CLAIMANT_ACCOUNT, None)), "ack_addr");
    let before = head(port);
    sd.daemon().panic_at_the_next_kernel_step(Step::CheckpointCreate);
    let (st, body) = http(port, "POST", "/op", Some(&b.signed), signed.as_bytes());
    assert_eq!(st, 500, "{}", String::from_utf8_lossy(&body));
    assert_eq!(json(&body)["error"].as_str(), Some("internal_panic"), "{}", String::from_utf8_lossy(&body));
    // THE READ: the version stands, the commit recorded, nothing to re-send.
    let member2 = format!("{}.2", b.e);
    assert!(head(port) > before, "committed past the position before it");
    assert_eq!(text(port, &member2, 1, 3), "abc", "the version the 500 hid stands");
    assert!(!registered(port, &format!("{}.1.1", b.e)) && !registered(port, &format!("{}.3", b.e)), "one version");
    // The hazard: a blind re-send under the same id, with no memo to answer
    // it, re-executes — off a base the trunk has moved past, a daughter.
    let again = op_as_written(port, Some(&b.signed), &signed);
    assert_eq!(acked_addr(&again), format!("{}.1.1", b.e), "the wire's gap: a retry after a 500 may re-execute");
    sd.daemon().release_the_checkpoint_thread();
    sd.shutdown();
}

/// THE POSITION-FENCED READ (the link-sets design §5.7, W7 (3)): three
/// publications deposit links homed in `SET` — two, three, one — after the
/// board's own `R` at ordinal 1; the client, holding the middle commit's
/// position and the home, finds that commit's deposits over `read_link`
/// alone: the frontier by a galloping probe — `read_link` past it answers
/// `link_value` with a null `link` and no `at` — then a binary search over
/// the ordinals' `at` for the first at or past the position and the first
/// past it, `O(log n)` reads in all; the run found is exactly the middle
/// commit's, ordinals 4 through 6, in its declared order.
#[test]
fn a_commits_deposits_in_a_home_are_the_contiguous_ordinals_a_binary_search_over_read_links_at_finds() {
    use std::cell::Cell;

    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let b = deposit_board(port);
    let member1 = acked_addr(&op(port, Some(&b.signed), &b.shot()));
    let entry = |k: u32| serde_json::json!({"home": b.set, "from": {"addrs": [b.e]}, "to": {"addrs": []}, "ty": {"addrs": [format!("{}.0.3.6.{k}", b.e)]}});
    let mut member = member1;
    let mut ats = Vec::new();
    for (commit, count) in [2u32, 3, 1].into_iter().enumerate() {
        let links: Vec<Value> = (1..=count).map(|n| entry(10 * commit as u32 + n)).collect();
        let v = op(port, Some(&b.signed), &with_members(&records_less_shot(port, &b, &member), serde_json::json!({"links": links})));
        member = acked_addr(&v);
        ats.push(acked_at(&v));
    }
    assert!(ats[0] < ats[1] && ats[1] < ats[2]);
    // The client's reads, counted: `read_link` at SET's ordinal `k`.
    let reads = Cell::new(0u32);
    let at_of = |k: u32| -> Option<u64> {
        reads.set(reads.get() + 1);
        let v = op(port, None, &read_link_frame(&format!("{}.0.2.{k}", b.set)));
        expect_resp(&v, "link_value");
        if v["link"].is_null() {
            assert!(v["at"].is_null(), "past the frontier: a null link and no at: {v}");
            return None;
        }
        Some(v["at"].as_u64().expect("a link's at"))
    };
    // The frontier: gallop to the first null, then the search between.
    let mut probe = 1u32;
    while at_of(probe).is_some() {
        probe *= 2;
    }
    let (mut lo, mut hi) = (probe / 2, probe);
    while hi - lo > 1 {
        let mid = (lo + hi) / 2;
        if at_of(mid).is_some() {
            lo = mid;
        } else {
            hi = mid;
        }
    }
    let frontier = lo;
    assert_eq!(frontier, 7, "R, then two, three and one deposits");
    let lower_bound = |target: u64, strict: bool| -> u32 {
        let (mut lo, mut hi) = (1u32, frontier + 1);
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let at = at_of(mid).expect("inside the frontier");
            if if strict { at > target } else { at >= target } {
                hi = mid;
            } else {
                lo = mid + 1;
            }
        }
        lo
    };
    let (first, past) = (lower_bound(ats[1], false), lower_bound(ats[1], true));
    assert_eq!((first, past), (4, 7), "the middle commit's deposits are SET's ordinals 4 through 6");
    for (i, k) in (first..past).enumerate() {
        let link = read_link(port, None, &format!("{}.0.2.{k}", b.set));
        assert_eq!(slot_span(&link, 2).0, format!("{}.0.3.6.{}", b.e, 11 + i as u32), "in the declared order");
    }
    let log2 = (frontier + 1).next_power_of_two().trailing_zeros();
    assert!(reads.get() <= 5 * log2, "{} reads over a frontier of {frontier}: past 5·⌈log₂⌉", reads.get());
    sd.shutdown();
}

/// THE MEMO AHEAD OF THE ADMISSION (ruling 4): a publication that accepted
/// an original, retried under the same `id` on the same session after its
/// ack, is answered its acknowledgment — the same member, the same position
/// — and never re-judged: its own commit superseded the original it names,
/// which the admission's plan refuses `old_refused` with `superseded` for
/// the same entry sent under a fresh `id` on a shot staged off the member
/// it minted (the shot's own table standing ahead of the plan, a birth
/// shape would answer `base_superseded` first).
#[test]
fn a_retry_of_a_committed_publication_replays_its_ack_ahead_of_the_admission() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let b = deposit_board(port);
    let frame = with_members(&b.full(), serde_json::json!({"id": "pub-1"}));
    let first = op(port, Some(&b.signed), &frame);
    let member = acked_addr(&first);
    let before = head(port);
    let again = op(port, Some(&b.signed), &frame);
    assert_eq!(again, first, "the committed publication's ack, replayed");
    assert_eq!(head(port), before, "a replayed ack commits nothing");
    let fresh_start = image(port, &member, 1, 3)[0].0.clone();
    let staged_off_member = publish(&b.e, Some((&member, 3)), None, &[run(&b.e, &fresh_start, 3)]);
    let fresh = op(port, Some(&b.signed), &with_members(&staged_off_member, serde_json::json!({"links": [b.copy_entry()], "id": "pub-2"})));
    assert_deposit_refused(&fresh, "old_refused", 0, Some("superseded"));
    assert_eq!(head(port), before);
    assert_eq!(text(port, &member, 1, 3), "abc");
    sd.shutdown();
}
