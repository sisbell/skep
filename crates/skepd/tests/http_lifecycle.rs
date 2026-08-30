//! End-to-end over a real socket: session → delegate → create → insert →
//! retrieve → makelink → findlinks, with sessions interleaved, the guest
//! (session-less) path, unparseable frames, transport errors, the
//! request-body cap, idempotent retry, and concurrent clients on one
//! world. Store semantics are trusted to the stores' own tests — these
//! assert the transport.

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use common::*;
use serde_json::Value;

/// Bootstrap the standard working chain: π₀ session → next prefix under
/// node [1] → delegate principal 1 → its session + account.
fn delegate_first_principal(port: u16) -> (String, String) {
    let boot = open_session(port, 0);
    let v = op(port, Some(&boot), r#"{"op":"next_account_prefix","parent":"1"}"#);
    let prefix = expect_resp(&v, "maybe_addr")["addr"]
        .as_str()
        .expect("node [1] has a delegable prefix")
        .to_string();
    let v = op(
        port,
        Some(&boot),
        &format!(r#"{{"op":"delegate","new_prefix":"{prefix}","new_id":1}}"#),
    );
    let account = acked_addr(&v);
    (open_session(port, 1), account)
}

fn create_doc(port: u16, session: &str, account: &str) -> String {
    let v = op(
        port,
        Some(session),
        &format!(r#"{{"op":"create_new_document","account":"{account}"}}"#),
    );
    acked_addr(&v)
}

fn insert_at(port: u16, session: &str, doc: &str, ordinal: u64, value: &str) -> Value {
    op(
        port,
        Some(session),
        &format!(
            r#"{{"op":"insert","doc":"{doc}","at":{{"subspace":"1","ordinal":"{ordinal}"}},"values":[{value}]}}"#
        ),
    )
}

/// Concatenated text of a delivery over `width` positions from ordinal 1.
fn read_text(port: u16, doc: &str, width: u64) -> String {
    let v = op(
        port,
        None,
        &format!(
            r#"{{"op":"retrieve_v","specs":[{{"doc":"{doc}","span":{{"start":"1.1","width":"0.{width}"}}}}]}}"#
        ),
    );
    expect_resp(&v, "delivery")["items"]
        .as_array()
        .expect("items")
        .iter()
        .map(|i| i["content"].as_str().unwrap_or(""))
        .collect()
}

#[test]
fn lifecycle_session_create_insert_retrieve_makelink_findlinks() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();

    let (st, body) = get(port, "/health");
    assert_eq!(st, 200);
    assert_eq!(json(&body)["ok"], Value::Bool(true));

    let (s1, account1) = delegate_first_principal(port);

    // Principal 1's document; the string write form is per-byte, so
    // "hello, wire" seats eleven values at positions 1..=11.
    let doc1 = create_doc(port, &s1, &account1);
    expect_resp(&insert_at(port, &s1, &doc1, 1, r#""hello, wire""#), "ack_addr");

    // Second principal, delegated under account1 by its owner (session 1),
    // interleaving with principal 1's edits.
    let v = op(port, Some(&s1), &format!(r#"{{"op":"next_account_prefix","parent":"{account1}"}}"#));
    let prefix2 = expect_resp(&v, "maybe_addr")["addr"].as_str().expect("prefix").to_string();
    let v = op(port, Some(&s1), &format!(r#"{{"op":"delegate","new_prefix":"{prefix2}","new_id":2}}"#));
    let account2 = acked_addr(&v);
    let s2 = open_session(port, 2);

    let doc2 = create_doc(port, &s2, &account2);
    expect_resp(&insert_at(port, &s2, &doc2, 1, r#""linked text""#), "ack_addr");
    expect_resp(&insert_at(port, &s1, &doc1, 12, r#"" and more""#), "ack_addr");

    assert_eq!(read_text(port, &doc1, 20), "hello, wire and more");
    assert_eq!(read_text(port, &doc2, 11), "linked text");

    // principal_prefix resolves the account the session was told at open.
    let v = op(port, None, r#"{"op":"principal_prefix","principal":2}"#);
    assert_eq!(expect_resp(&v, "maybe_addr")["addr"].as_str(), Some(account2.as_str()));

    // A link: type slot resolved from a types document's content.
    let tdoc = create_doc(port, &s1, &account1);
    expect_resp(&insert_at(port, &s1, &tdoc, 1, r#""type:jump""#), "ack_addr");
    let v = op(
        port,
        Some(&s1),
        &format!(
            concat!(
                r#"{{"op":"make_link","home":"{d1}","#,
                r#""from":[{{"source":"{d1}","span":{{"start":"1.1","width":"0.1"}}}}],"#,
                r#""to":[{{"source":"{d2}","span":{{"start":"1.1","width":"0.1"}}}}],"#,
                r#""ty":[{{"source":"{t}","span":{{"start":"1.1","width":"0.1"}}}}]}}"#
            ),
            d1 = doc1,
            d2 = doc2,
            t = tdoc
        ),
    );
    let link = acked_addr(&v);

    // Discovery finds it from the covered region of doc1.
    let v = op(
        port,
        None,
        &format!(
            r#"{{"op":"find_links_v","d":"{doc1}","region":[{{"start":"1.1","width":"0.1"}}]}}"#
        ),
    );
    let addrs = expect_resp(&v, "addrs")["addrs"].as_array().expect("addrs");
    assert!(
        addrs.iter().any(|a| a.as_str() == Some(link.as_str())),
        "find_links_v must discover {link}: {addrs:?}"
    );

    // Raw read-back and slot coverage.
    let v = op(port, None, &format!(r#"{{"op":"read_link","a":"{link}"}}"#));
    let slots = expect_resp(&v, "link_value")["link"]["slots"].as_array().expect("slots");
    assert_eq!(slots.len(), 3);
    let v = op(port, None, &format!(r#"{{"op":"follow_link","a":"{link}","slot":2}}"#));
    let covered = expect_resp(&v, "follow")["result"]["ok"].as_array().expect("ok spans");
    assert!(!covered.is_empty(), "TO slot coverage must be nonempty");

    sd.shutdown();
}

/// Wire v5: address-form endsets on make_link, end to end. Ghost NAMES in a
/// registry document's never-occupied subspace 3 type links; the recorded
/// endsets are the names verbatim (no resolution, contents never examined);
/// follow answers the name span; an ftt type filter over the exact name
/// finds every link sharing it and no other; a filter over the names'
/// common prefix subtree finds the whole family; a link address is an
/// ordinary endset name (link-to-link); and the type floor reads as-given —
/// empty addrs FROM/TO admitted, empty addrs TY rejected.
#[test]
fn addrs_form_endsets_and_ghost_types() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let (s1, account1) = delegate_first_principal(port);

    let doc = create_doc(port, &s1, &account1);
    expect_resp(&insert_at(port, &s1, &doc, 1, r#""anchor text""#), "ack_addr");
    // The registry document: nothing is ever inserted in its subspace 3, so
    // the names below are pure names — ghosts.
    let registry = create_doc(port, &s1, &account1);
    let name1 = format!("{registry}.0.3.6.1");
    let name2 = format!("{registry}.0.3.6.2");
    // enc records one unit subtree span per name: width 0.….0.1 at the
    // name's own component count.
    let unit_w = |addr: &str| {
        let mut comps = vec!["0"; addr.split('.').count() - 1];
        comps.push("1");
        comps.join(".")
    };

    // Link 1: content-resolved FROM, empty addrs TO, ghost-name TY.
    let v = op(
        port,
        Some(&s1),
        &format!(
            r#"{{"op":"make_link","home":"{doc}","from":[{{"source":"{doc}","span":{{"start":"1.1","width":"0.6"}}}}],"to":{{"addrs":[]}},"ty":{{"addrs":["{name1}"]}}}}"#
        ),
    );
    let l1 = acked_addr(&v);

    // read_link: the type slot is exactly enc({name1}) — the NAME, not any
    // content — and the empty addrs TO is the empty endset.
    let ty_endset: Value = serde_json::from_str(&format!(
        r#"[{{"start":"{name1}","width":"{}"}}]"#,
        unit_w(&name1)
    ))
    .expect("json");
    let v = op(port, None, &format!(r#"{{"op":"read_link","a":"{l1}"}}"#));
    let slots = expect_resp(&v, "link_value")["link"]["slots"].as_array().expect("slots");
    assert_eq!(slots[2], ty_endset, "the addrs-form ty records the name verbatim");
    assert_eq!(slots[1], Value::Array(vec![]), "the empty addrs to-endset is ⟨⟩");

    // follow slot 3 answers the name span.
    let v = op(port, None, &format!(r#"{{"op":"follow_link","a":"{l1}","slot":3}}"#));
    assert_eq!(expect_resp(&v, "follow")["result"]["ok"], ty_endset);

    // The two answers wire.md keeps apart, PRODUCED here rather than only
    // marshaled from a fixture: an empty endset is a DEFINED success (l1's
    // addrs-form TO is empty), and an absent link or slot is the other
    // answer. M7 calls the distinction unforgeable and M10 declines to
    // lower it to a rejection; nothing in this suite had ever seen either
    // shape, since every live follow returns a non-empty `ok` and every
    // fixture carries exactly one span.
    let v = op(port, None, &format!(r#"{{"op":"follow_link","a":"{l1}","slot":2}}"#));
    assert_eq!(
        expect_resp(&v, "follow")["result"],
        serde_json::json!({"ok": []}),
        "an empty endset is a defined answer, not an error: {v}"
    );
    for (what, frame) in [
        ("a slot no link has", format!(r#"{{"op":"follow_link","a":"{l1}","slot":4}}"#)),
        ("slot 0 — the wire is 1-based", format!(r#"{{"op":"follow_link","a":"{l1}","slot":0}}"#)),
        ("an address holding no link", format!(r#"{{"op":"follow_link","a":"{doc}","slot":1}}"#)),
    ] {
        let v = op(port, None, &frame);
        assert_eq!(
            expect_resp(&v, "follow")["result"],
            serde_json::json!({"err": "invalid"}),
            "{what} is ⊥, distinct from the empty answer above: {v}"
        );
    }

    // Link 2 shares name1 and points TO l1 by address (link-to-link).
    let v = op(
        port,
        Some(&s1),
        &format!(
            r#"{{"op":"make_link","home":"{doc}","from":[{{"source":"{doc}","span":{{"start":"1.7","width":"0.4"}}}}],"to":{{"addrs":["{l1}"]}},"ty":{{"addrs":["{name1}"]}}}}"#
        ),
    );
    let l2 = acked_addr(&v);
    let v = op(port, None, &format!(r#"{{"op":"read_link","a":"{l2}"}}"#));
    let to_expect: Value =
        serde_json::from_str(&format!(r#"[{{"start":"{l1}","width":"{}"}}]"#, unit_w(&l1)))
            .expect("json");
    assert_eq!(
        expect_resp(&v, "link_value")["link"]["slots"][1],
        to_expect,
        "the addrs-form to records the link address"
    );

    // Link 3: the sibling name under …3.6, with both FROM and TO empty in
    // the addrs form (both admitted).
    let v = op(
        port,
        Some(&s1),
        &format!(
            r#"{{"op":"make_link","home":"{doc}","from":{{"addrs":[]}},"to":{{"addrs":[]}},"ty":{{"addrs":["{name2}"]}}}}"#
        ),
    );
    let l3 = acked_addr(&v);

    // ftt over the exact name: the two links sharing name1, and only them.
    let has = |v: &Value, addr: &str| {
        v["addrs"].as_array().expect("addrs").iter().any(|a| a.as_str() == Some(addr))
    };
    let v = op(
        port,
        None,
        &format!(
            r#"{{"op":"find_links_ftt","q":{{"home":"any","from":"any","to":"any","ty":[{{"start":"{name1}","width":"{}"}}]}}}}"#,
            unit_w(&name1)
        ),
    );
    expect_resp(&v, "addrs");
    assert!(has(&v, &l1) && has(&v, &l2), "shared-identity typing: both name1 links found");
    assert!(!has(&v, &l3), "the sibling name must not match the exact-name filter");

    // One query spanning …3.6's subtree finds the whole family — the type
    // hierarchy is the tumbler prefix order.
    let prefix = format!("{registry}.0.3.6");
    let v = op(
        port,
        None,
        &format!(
            r#"{{"op":"find_links_ftt","q":{{"home":"any","from":"any","to":"any","ty":[{{"start":"{prefix}","width":"{}"}}]}}}}"#,
            unit_w(&prefix)
        ),
    );
    expect_resp(&v, "addrs");
    assert!(has(&v, &l1) && has(&v, &l2) && has(&v, &l3), "the prefix subtree finds all three");

    // Order is verbatim on the store side too (wire.md §Links): the recorded
    // endset is one unit span per address IN THE ORDER GIVEN. The descending
    // pair below is what a canonicalizer would reorder, and every other
    // endset in this suite is a single span, where order is invisible.
    let v = op(
        port,
        Some(&s1),
        &format!(
            r#"{{"op":"make_link","home":"{doc}","from":{{"addrs":[]}},"to":{{"addrs":[]}},"ty":{{"addrs":["{name2}","{name1}"]}}}}"#
        ),
    );
    let l4 = acked_addr(&v);
    let v = op(port, None, &format!(r#"{{"op":"read_link","a":"{l4}"}}"#));
    let expect: Value = serde_json::from_str(&format!(
        r#"[{{"start":"{name2}","width":"{}"}},{{"start":"{name1}","width":"{}"}}]"#,
        unit_w(&name2),
        unit_w(&name1)
    ))
    .expect("json");
    assert_eq!(
        expect_resp(&v, "link_value")["link"]["slots"][2],
        expect,
        "an addrs endset records one unit span per address in the order given"
    );

    // The type floor is as-given: an empty addrs TY rejects exactly as an
    // empty resolution does.
    let v = op(
        port,
        Some(&s1),
        &format!(
            r#"{{"op":"make_link","home":"{doc}","from":{{"addrs":[]}},"to":{{"addrs":[]}},"ty":{{"addrs":[]}}}}"#
        ),
    );
    let rej = expect_resp(&v, "rejected");
    assert_eq!(rej["op"].as_str(), Some("make_link"));
    assert_eq!(rej["code"].as_str(), Some("empty_type_resolution"));

    sd.shutdown();
}

/// Wire v2 granularity through the real store: a mixed insert (per-byte
/// text, a composite atom, raw non-UTF-8 bytes) comes back from retrieve_v
/// with its granularity intact — per-byte runs coalesce, the atom stays its
/// own item, and the delivery is injective about which world this is.
#[test]
fn atom_values_round_trip_through_the_store() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let (s1, account1) = delegate_first_principal(port);
    let doc = create_doc(port, &s1, &account1);

    // "ab" per-byte (positions 1-2), one 5-byte atom (position 3), "yz"
    // per-byte (4-5), then two raw non-UTF-8 bytes per-byte (6-7).
    let v = insert_at(port, &s1, &doc, 1, r#""ab",{"atom":"chunk"},"yz""#);
    expect_resp(&v, "ack_addr");
    let v = insert_at(port, &s1, &doc, 6, r#"{"hex":"c328"}"#);
    expect_resp(&v, "ack_addr");

    // Seven positions, three items: the trailing run y,z,0xc3,0x28 is judged
    // UTF-8 as a whole, fails, and renders on the hex path.
    let v = op(
        port,
        None,
        &format!(
            r#"{{"op":"retrieve_v","specs":[{{"doc":"{doc}","span":{{"start":"1.1","width":"0.7"}}}}]}}"#
        ),
    );
    let items = &expect_resp(&v, "delivery")["items"];
    let expect: Value =
        serde_json::from_str(r#"[{"content":"ab"},{"atom":"chunk"},{"hex":"797ac328"}]"#)
            .expect("json");
    assert_eq!(items, &expect, "granularity must survive the store round trip");

    // The whole composite value sits at ONE position.
    let v = op(
        port,
        None,
        &format!(
            r#"{{"op":"retrieve_v","specs":[{{"doc":"{doc}","span":{{"start":"1.3","width":"0.1"}}}}]}}"#
        ),
    );
    let items = &expect_resp(&v, "delivery")["items"];
    let expect: Value = serde_json::from_str(r#"[{"atom":"chunk"}]"#).expect("json");
    assert_eq!(items, &expect);

    sd.shutdown();
}

#[test]
fn idempotent_retry_replays_the_ack() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let (s1, account1) = delegate_first_principal(port);

    let frame =
        format!(r#"{{"op":"create_new_document","account":"{account1}","id":"retry-1"}}"#);
    let (st1, first) = http(port, "POST", "/op", Some(&s1), frame.as_bytes());
    let (st2, second) = http(port, "POST", "/op", Some(&s1), frame.as_bytes());
    assert_eq!((st1, st2), (200, 200));
    assert_eq!(first, second, "a same-id retry must replay the identical ack");
    // A fresh id mints a fresh document.
    let frame2 =
        format!(r#"{{"op":"create_new_document","account":"{account1}","id":"retry-2"}}"#);
    let (_, third) = http(port, "POST", "/op", Some(&s1), frame2.as_bytes());
    assert_ne!(first, third);

    sd.shutdown();
}

/// wire.md §Correlation and idempotency: the `id` hint "is never applied
/// to reads". A client that stamps an id on every frame it sends — a
/// reasonable reading of "any string, unique within your session" — must
/// still see the world move; a memoized read would replay a frozen
/// snapshot, `as_of` and all, under a key the client believes is only a
/// retry hint. `authz.rs` covers the rejection half of that sentence at
/// the wire and `history.rs` covers `/op-at`; this is the read half on
/// `/op`.
#[test]
fn an_id_on_a_read_frame_never_memoizes_the_answer() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let (s1, account1) = delegate_first_principal(port);
    let doc = create_doc(port, &s1, &account1);
    expect_resp(&insert_at(port, &s1, &doc, 1, r#""alpha""#), "ack_addr");

    // Read as TEXT, so a replayed answer names itself in the failure
    // rather than arriving as two identical byte arrays.
    let read_frame = format!(r#"{{"op":"retrieve_doc_v_span_set","id":"k","doc":"{doc}"}}"#);
    let span_set = |body: &[u8]| {
        let v = json(body);
        expect_resp(&v, "span_set");
        String::from_utf8(body.to_vec()).expect("utf-8 body")
    };
    let (st, body) = http(port, "POST", "/op", Some(&s1), read_frame.as_bytes());
    assert_eq!(st, 200, "{}", String::from_utf8_lossy(&body));
    let first = span_set(&body);

    expect_resp(&insert_at(port, &s1, &doc, 6, r#""beta""#), "ack_addr");

    let (st, body) = http(port, "POST", "/op", Some(&s1), read_frame.as_bytes());
    assert_eq!(st, 200, "{}", String::from_utf8_lossy(&body));
    let second = span_set(&body);
    assert_ne!(
        first, second,
        "a read under an id must answer the current world, never replay an earlier one"
    );
    // And it is the CURRENT answer, not merely a different one: nine
    // positions after the second insert, where the first read saw five.
    let width = |answer: &str| {
        json(answer.as_bytes())["set"][0]["width"]
            .as_str()
            .expect("an extent names its width")
            .rsplit('.')
            .next()
            .expect("component")
            .to_string()
    };
    assert_eq!(width(&first), "5", "the first read saw \"alpha\": {first}");
    assert_eq!(width(&second), "9", "the second sees \"alpha\" + \"beta\": {second}");

    sd.shutdown();
}

/// wire.md §Operations: a node address "is capped at 32 components —
/// deeper is `too_deep`". Both ends of that comparison at the wire, and
/// the only place in this crate that produces the code at all — its wire
/// name is otherwise emitted by `code_name` and read back by nothing.
#[test]
fn the_node_depth_cap_is_exactly_32_components_on_the_wire() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let boot = open_session(port, 0);
    let node = |n: usize| vec!["1"; n].join(".");

    let v = op(port, Some(&boot), &format!(r#"{{"op":"register_node","addr":"{}"}}"#, node(32)));
    assert_eq!(acked_addr(&v), node(32), "a node AT the depth cap registers");

    let v = op(port, Some(&boot), &format!(r#"{{"op":"register_node","addr":"{}"}}"#, node(33)));
    let rej = expect_resp(&v, "rejected");
    assert_eq!(rej["op"].as_str(), Some("register_node"));
    assert_eq!(rej["code"].as_str(), Some("too_deep"), "the documented code: {v}");
    assert_eq!(rej["disposition"].as_str(), Some("permanent"));

    sd.shutdown();
}

/// wire.md §Sessions: the answer carries exactly the token and the echoed
/// principal — the echo being the only place a client learns which
/// principal its opaque token was bound to. Every helper in this suite
/// reads `session` and drops the rest, so nothing watched it.
#[test]
fn session_open_echoes_the_principal_it_bound() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();

    // 0 is the bootstrap principal; 4294967296 is past u32, where a
    // narrowed echo would wrap rather than merely differ.
    for principal in [0u64, 1, 7, 4_294_967_296] {
        let body = format!(r#"{{"principal":{principal}}}"#);
        let (st, resp) = http(port, "POST", "/session", None, body.as_bytes());
        assert_eq!(st, 200, "principal {principal}: {}", String::from_utf8_lossy(&resp));
        let v = json(&resp);
        assert_eq!(
            v["principal"].as_u64(),
            Some(principal),
            "the answer echoes the principal it bound: {v}"
        );
        assert!(v["session"].is_string(), "and the opaque token beside it: {v}");
        assert_eq!(
            v.as_object().expect("a JSON object").len(),
            2,
            "exactly the two documented fields, nothing else: {v}"
        );
    }

    sd.shutdown();
}

#[test]
fn guest_requests_read_but_cannot_write() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();

    // Reads are principal-free: served with no session at all.
    let v = op(port, None, r#"{"op":"next_account_prefix","parent":"1"}"#);
    expect_resp(&v, "maybe_addr");

    // Writes without a session get M10's own verdict, marshaled.
    let v = op(port, None, r#"{"op":"fork"}"#);
    let rej = expect_resp(&v, "rejected");
    assert_eq!(rej["op"].as_str(), Some("fork"));
    assert_eq!(rej["code"].as_str(), Some("unauthenticated"));
    assert_eq!(rej["disposition"].as_str(), Some("permanent"));

    // An unknown token behaves exactly like no token.
    let v = op(port, Some("no-such-token"), r#"{"op":"fork"}"#);
    assert_eq!(expect_resp(&v, "rejected")["code"].as_str(), Some("unauthenticated"));

    // Malformed session bodies are transport errors, not op responses.
    let (st, body) = http(port, "POST", "/session", None, br#"{"user":"alice"}"#);
    assert_eq!(st, 400);
    assert_eq!(json(&body)["error"].as_str(), Some("malformed_session_request"));
    // A negative principal is not a principal (wire.md: a non-negative
    // integer). Read as signed it would wrap onto u64::MAX — which is the
    // id the guest session itself is minted with.
    let (st, body) = http(port, "POST", "/session", None, br#"{"principal":-1}"#);
    assert_eq!(st, 400, "{}", String::from_utf8_lossy(&body));
    assert_eq!(json(&body)["error"].as_str(), Some("malformed_session_request"));

    sd.shutdown();
}

#[test]
fn unparseable_frames_get_the_unparseable_rejection() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();

    for frame in [
        &b"this is not json"[..],
        br#"{"op":"frobnicate"}"#,
        br#"{"op":"fork","stray":true}"#,
        br#"{"op":"version","d_src":"not-an-address"}"#,
        // A zero-width span is rejected at PARSE (wire.md §Value
        // encodings), so it reaches the client on the operation channel as
        // `unparseable` — never as a store's verdict about the world.
        br#"{"op":"show_origin","doc":"1.0.1.0.1","span":{"start":"1.1","width":"0.0"}}"#,
    ] {
        let (st, body) = http(port, "POST", "/op", None, frame);
        assert_eq!(st, 200, "unparseable frames still get a marshaled response");
        let v = json(&body);
        let rej = expect_resp(&v, "rejected");
        assert_eq!(rej["op"].as_str(), Some("unparseable"));
        assert_eq!(rej["code"].as_str(), Some("malformed"));
        assert!(rej["detail"].is_string(), "unparseable carries what failed: {rej}");
    }

    sd.shutdown();
}

#[test]
fn transport_errors_are_json() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();

    let (st, body) = get(port, "/nope");
    assert_eq!(st, 404);
    assert_eq!(json(&body)["error"].as_str(), Some("no_such_endpoint"));

    let (st, body) = get(port, "/op");
    assert_eq!(st, 405);
    assert_eq!(json(&body)["error"].as_str(), Some("method_not_allowed"));

    sd.shutdown();
}

/// The documented request-body cap (wire.md §Transport, pre-media value);
/// the daemon's `MAX_REQUEST_BODY` moving without the doc fails here.
const BODY_CAP: usize = 8 * 1024 * 1024;

#[test]
fn a_body_at_the_cap_is_served() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();

    // Exactly-at-cap non-JSON: the transport must read all of it and hand
    // it to the codec — 200 with the marshaled unparseable rejection, not
    // a refusal.
    let body = vec![b'x'; BODY_CAP];
    let (st, resp) = http(port, "POST", "/op", None, &body);
    assert_eq!(st, 200, "a body at the cap is served: {}", String::from_utf8_lossy(&resp));
    let v = json(&resp);
    let rej = expect_resp(&v, "rejected");
    assert_eq!(rej["op"].as_str(), Some("unparseable"));

    sd.shutdown();
}

#[test]
fn a_byte_over_the_cap_is_refused_on_the_declared_length_alone() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();

    // Declare one byte past the cap and send NO body. The refusal must
    // arrive on the declared Content-Length alone — before the daemon
    // reads (or allocates for) a single body byte. The client deadline
    // sits well under the server's 30 s request read timeout, so a daemon
    // that entered the body loop (blocking on bytes that never come)
    // fails here instead of allocating.
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connect");
    stream.set_read_timeout(Some(Duration::from_secs(10))).expect("read timeout");
    let head = format!(
        "POST /op HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
        BODY_CAP + 1
    );
    stream.write_all(head.as_bytes()).expect("write head");
    let mut raw = Vec::new();
    stream
        .read_to_end(&mut raw)
        .expect("the refusal arrives without any body byte being sent");
    let sep = raw.windows(4).position(|w| w == b"\r\n\r\n").expect("response separator");
    let head = std::str::from_utf8(&raw[..sep]).expect("ascii response head");
    assert!(
        head.starts_with("HTTP/1.1 413 "),
        "the payload-too-large disposition, not a generic parse error: {head}"
    );
    let v = json(&raw[sep + 4..]);
    assert_eq!(v["error"].as_str(), Some("payload_too_large"), "refusal body: {v}");
    assert!(v["detail"].is_string(), "the refusal names the declared length: {v}");

    sd.shutdown();
}

#[test]
fn concurrent_clients_share_one_world() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let (s1, account1) = delegate_first_principal(port);

    let doc_a = create_doc(port, &s1, &account1);
    let doc_b = create_doc(port, &s1, &account1);

    let mut handles = Vec::new();
    for (doc, tag) in [(doc_a.clone(), "a"), (doc_b.clone(), "b")] {
        let session = s1.clone();
        handles.push(std::thread::spawn(move || {
            // Each two-char chunk is two per-byte values, so chunk i appends
            // at ordinal 2i-1.
            for i in 1..=5u64 {
                let v = insert_at(port, &session, &doc, 2 * i - 1, &format!("\"{tag}{i}\""));
                expect_resp(&v, "ack_addr");
            }
        }));
    }
    for h in handles {
        h.join().expect("client thread");
    }

    assert_eq!(read_text(port, &doc_a, 10), "a1a2a3a4a5");
    assert_eq!(read_text(port, &doc_b, 10), "b1b2b3b4b5");

    sd.shutdown();
}

#[cfg(feature = "observe")]
#[test]
fn dump_serves_the_world_dump() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();

    let (st, body) = get(port, "/dump");
    assert_eq!(st, 200);
    let text = String::from_utf8(body).expect("dump is utf-8 text");
    assert!(text.starts_with("skep-world-dump v2"), "unexpected dump header: {text:.40}");

    sd.shutdown();
}
