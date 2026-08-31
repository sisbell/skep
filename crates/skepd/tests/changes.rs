//! The change feed and its sidecar (wire v6): `/changes` lists exactly the
//! committed writes with op kind, affected docs, and commit times; paging
//! via `limit`/`more`/`last`; determinism across calls and restarts; the
//! sidecar's crash honesty (torn tail truncated, lost and pre-feature
//! records answered as bare `null`-field positions, never invented); and
//! `head_time` on `/health`. The doc examples in wire.md §The change feed
//! are asserted against live daemon bytes here (times normalized — the one
//! nondeterministic field; the bare example is byte-exact).

mod common;

use std::path::Path;

use common::*;
use serde_json::Value;

/// The scripted flow behind the wire.md examples. Positions are pinned by
/// the stores' record counts: `delegate` commits 2 records (position 14),
/// the home mint 1 (position 15) — MINT-FIRST (RES-26): the account's doc 1
/// is born published, where bare writes are gated by design, so the flow
/// writes a SECOND, private document — that mint 1 (position 16), a
/// two-byte `insert` 5 — two mints, two content writes, one placement —
/// (position 21), `make_link` 3 — mint, link, seat — (position 24). If an
/// ack below drifts, a store changed its transaction shape and wire.md
/// §The change feed must be re-pinned.
/// The head the claim ceremony leaves behind (`common::claim_board`):
/// delegate (2 records), the home mint (1), the one-atom insert (3), the
/// genesis link (3), the claim link (3) — twelve records, and the base
/// every seeded position below sits on. Lane 3.2 re-pins wire.md's
/// change-feed examples onto these numbers.
const CEREMONY_HEAD: u64 = 12;

/// The ceremony's own commit positions (the record counts above,
/// cumulative): delegate, the home mint, the record insert, the genesis
/// link, the claim link.
const CEREMONY_ATS: [u64; 5] = [2, 3, 6, 9, 12];

/// [`seed_flow`]'s commit positions on the ceremony's base: delegate, the
/// home mint, the private second mint, the insert, the make_link.
const SEEDED_ATS: [u64; 5] = [
    CEREMONY_HEAD + 2,
    CEREMONY_HEAD + 3,
    CEREMONY_HEAD + 4,
    CEREMONY_HEAD + 9,
    CEREMONY_HEAD + 12,
];

/// Every committed position a claimed, seeded board holds: the ceremony's
/// five commits, then the seeded five.
fn all_ats() -> Vec<u64> {
    CEREMONY_ATS.iter().chain(SEEDED_ATS.iter()).copied().collect()
}

fn seed_flow(port: u16) -> String {
    let boot = open_session(port, 0);
    let v = op(port, Some(&boot), r#"{"op":"next_account_prefix","parent":"1"}"#);
    let prefix = expect_resp(&v, "maybe_addr")["addr"].as_str().expect("prefix").to_string();
    assert_eq!(
        prefix, "1.0.2",
        "the ceremony holds 1.0.1; frontier drift here means re-pinning the examples"
    );
    let v = op(
        port,
        Some(&boot),
        &format!(r#"{{"op":"delegate","new_prefix":"{prefix}","new_id":1}}"#),
    );
    assert_eq!(
        acked_at(&v),
        CEREMONY_HEAD + 2,
        "delegate is a 2-record commit (Allocate + RegisterPrincipal)"
    );
    let s1 = open_session(port, 1);
    let v = op(
        port,
        Some(&s1),
        &format!(r#"{{"op":"create_new_document","account":"{prefix}"}}"#),
    );
    assert_eq!(acked_addr(&v), "1.0.2.0.1", "the home mint is doc 1; re-pin the examples");
    assert_eq!(acked_at(&v), CEREMONY_HEAD + 3, "create_new_document is a 1-record commit");
    let v = op(
        port,
        Some(&s1),
        &format!(r#"{{"op":"create_new_document","account":"{prefix}"}}"#),
    );
    let doc = acked_addr(&v);
    assert_eq!(doc, "1.0.2.0.2", "second document address drifted; re-pin the examples");
    assert_eq!(acked_at(&v), CEREMONY_HEAD + 4, "create_new_document is a 1-record commit");
    let v = op(
        port,
        Some(&s1),
        &format!(
            r#"{{"op":"insert","doc":"{doc}","at":{{"subspace":"1","ordinal":"1"}},"values":["hi"]}}"#
        ),
    );
    assert_eq!(acked_at(&v), CEREMONY_HEAD + 9, "a 2-value insert is a 5-record commit");
    let v = op(
        port,
        Some(&s1),
        &format!(
            concat!(
                r#"{{"op":"make_link","home":"{d}","#,
                r#""from":[{{"source":"{d}","span":{{"start":"1.1","width":"0.2"}}}}],"#,
                r#""to":{{"addrs":["{d}"]}},"ty":{{"addrs":["{d}.0.3.1"]}}}}"#
            ),
            d = doc
        ),
    );
    assert_eq!(
        acked_at(&v),
        CEREMONY_HEAD + 12,
        "make_link is a 3-record commit (mint + link + seat)"
    );
    doc
}

fn acked_at(v: &Value) -> u64 {
    v["at"].as_u64().unwrap_or_else(|| panic!("no committed at in {v}"))
}

fn changes_raw(port: u16, query: &str) -> (u16, Vec<u8>) {
    http(port, "GET", &format!("/changes?{query}"), None, b"")
}

fn changes_ok(port: u16, query: &str) -> Value {
    let (st, body) = changes_raw(port, query);
    assert_eq!(st, 200, "/changes?{query}: {}", String::from_utf8_lossy(&body));
    json(&body)
}

fn entry_ats(v: &Value) -> Vec<u64> {
    v["changes"]
        .as_array()
        .expect("changes array")
        .iter()
        .map(|e| e["at"].as_u64().expect("entry at"))
        .collect()
}

/// A `<!-- wire: changes <name> -->` fenced block from wire.md.
fn doc_changes_block(name: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/wire.md");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    let marker = format!("<!-- wire: changes {name} -->");
    let mut lines = text.lines();
    loop {
        let line = lines
            .next()
            .unwrap_or_else(|| panic!("wire.md lacks the marker '{marker}'"));
        if line.trim() == marker {
            break;
        }
    }
    let mut body = String::new();
    let mut in_fence = false;
    for l in lines {
        let t = l.trim();
        if !in_fence {
            if t.is_empty() {
                continue;
            }
            assert!(t.starts_with("```"), "marker '{marker}' not followed by a fence");
            in_fence = true;
            continue;
        }
        if t.starts_with("```") {
            break;
        }
        body.push_str(l);
        body.push('\n');
    }
    body.trim_end().to_string()
}

/// The page with each entry's wire-v7 `key` field removed — the one field
/// wire.md's frozen examples predate; lane 3.2's doc delta restores the
/// byte comparison.
fn strip_keys(v: &Value) -> Value {
    let mut v = v.clone();
    if let Some(entries) = v.get_mut("changes").and_then(Value::as_array_mut) {
        for e in entries {
            if let Some(m) = e.as_object_mut() {
                m.remove("key");
            }
        }
    }
    v
}

#[test]
fn change_feed_lists_writes_pages_and_matches_the_doc() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn_unclaimed(dir.path());
    let port = sd.port();

    // A fresh world has no recorded commit: head_time is null, honestly.
    let (st, body) = get(port, "/health");
    assert_eq!(st, 200);
    assert!(json(&body)["head_time"].is_null(), "fresh world: head_time null");

    // …and the feed answers the empty page, not a refusal: this is every
    // client's first poll, and a 410 here would break it before the world
    // has anything in it to be wrong about.
    let (st, body) = changes_raw(port, "since=0");
    assert_eq!(st, 200, "a fresh world's feed: {}", String::from_utf8_lossy(&body));
    let v = json(&body);
    assert_eq!(entry_ats(&v), Vec::<u64>::new());
    assert_eq!((v["last"].as_u64(), v["more"].as_bool()), (Some(0), Some(false)));

    common::claim_board(port);
    let doc = seed_flow(port);

    // Reads and rejected writes are not in the feed: issue both, then
    // assert the feed holds exactly the five committed writes.
    let v = op(
        port,
        None,
        &format!(
            r#"{{"op":"retrieve_v","specs":[{{"doc":"{doc}","span":{{"start":"1.1","width":"0.2"}}}}]}}"#
        ),
    );
    expect_resp(&v, "delivery");
    let v = op(
        port,
        None,
        &format!(
            r#"{{"op":"insert","doc":"{doc}","at":{{"subspace":"1","ordinal":"3"}},"values":["x"]}}"#
        ),
    );
    assert_eq!(expect_resp(&v, "rejected")["code"].as_str(), Some("unauthenticated"));

    // ── the full seeded feed: ops, docs, ordering, testimony ──
    // (The wire.md 'feed'/'feed_page' byte comparisons ride to lane 3.2,
    // which re-pins the examples onto the post-ceremony positions and the
    // wire-v7 `key` field; the structural pins below are this round's.)
    let b = CEREMONY_HEAD;
    let (st, body) = changes_raw(port, &format!("since={b}"));
    assert_eq!(st, 200);
    let v = json(&body);
    assert_eq!(entry_ats(&v), SEEDED_ATS.to_vec());
    let entries = v["changes"].as_array().expect("changes");
    assert_eq!(entries[0]["op"].as_str(), Some("delegate"));
    assert_eq!(entries[0]["docs"], serde_json::json!([]), "delegate names no doc");
    assert_eq!(entries[4]["op"].as_str(), Some("make_link"));
    assert_eq!(
        entries[4]["docs"],
        serde_json::json!([doc]),
        "a link write names its home doc"
    );
    // The wire-v7 testimony (AUTH-6.15): every one of these was a
    // bare-session write, so every entry reads "bare" — never null.
    for e in entries {
        assert_eq!(e["key"].as_str(), Some("bare"), "bare-session testimony: {e}");
    }
    let times: Vec<u64> =
        entries.iter().map(|e| e["time"].as_u64().expect("live entries carry times")).collect();
    assert!(times.windows(2).all(|w| w[0] <= w[1]), "times monotone in position: {times:?}");
    assert_eq!(v["last"].as_u64(), Some(b + 12));
    assert_eq!(v["more"], Value::Bool(false));

    // Determinism: the same question answers byte-identically.
    let (_, again) = changes_raw(port, &format!("since={b}"));
    assert_eq!(body, again, "same (since, limit) on the same journal must be byte-equal");

    // ── paging ──
    let v = changes_ok(port, &format!("since={b}&limit=2"));
    assert_eq!(entry_ats(&v), vec![b + 2, b + 3]);
    assert_eq!((v["last"].as_u64(), v["more"].as_bool()), (Some(b + 3), Some(true)));
    let v = changes_ok(port, &format!("since={}&limit=2", b + 3));
    assert_eq!(entry_ats(&v), vec![b + 4, b + 9]);
    assert_eq!((v["last"].as_u64(), v["more"].as_bool()), (Some(b + 9), Some(true)));
    let v = changes_ok(port, &format!("since={}&limit=2", b + 9));
    assert_eq!(entry_ats(&v), vec![b + 12]);
    assert_eq!((v["last"].as_u64(), v["more"].as_bool()), (Some(b + 12), Some(false)));

    // `since` is a fence, not a position: an interior number pages cleanly.
    let v = changes_ok(port, &format!("since={}", b + 5));
    assert_eq!(entry_ats(&v), vec![b + 9, b + 12]);

    // since ≥ head: empty, `last` echoes `since`.
    let v = changes_ok(port, &format!("since={}", b + 12));
    assert_eq!(entry_ats(&v), Vec::<u64>::new());
    assert_eq!((v["last"].as_u64(), v["more"].as_bool()), (Some(b + 12), Some(false)));
    let v = changes_ok(port, "since=999");
    assert_eq!(entry_ats(&v), Vec::<u64>::new());
    assert_eq!(v["last"].as_u64(), Some(999));

    // head_time now reports the newest recorded commit's time.
    let (st, body) = get(port, "/health");
    assert_eq!(st, 200);
    assert_eq!(json(&body)["head_time"].as_u64(), Some(*times.last().expect("four times")));

    // ── malformed queries: refused, never guessed ──
    for bad in [
        "",
        "limit=2",
        "since=abc",
        "since=0&limit=0",
        "since=0&limit=4097",
        "since=0&since=1",
        "since=0&frobnicate=1",
    ] {
        let path = if bad.is_empty() { "/changes".to_string() } else { format!("/changes?{bad}") };
        let (st, body) = http(port, "GET", &path, None, b"");
        assert_eq!(st, 400, "'{bad}' must be refused: {}", String::from_utf8_lossy(&body));
        assert_eq!(json(&body)["error"].as_str(), Some("malformed_changes"), "'{bad}'");
    }

    // An idempotent retry re-acks the original commit and records nothing
    // new: the feed gains exactly one entry for the pair.
    let s1 = open_session(port, 1);
    let frame = format!(
        r#"{{"op":"insert","doc":"{doc}","id":"dup-1","at":{{"subspace":"1","ordinal":"3"}},"values":["x"]}}"#
    );
    let first = op(port, Some(&s1), &frame);
    let at5 = acked_at(&first);
    let second = op(port, Some(&s1), &frame);
    assert_eq!(acked_at(&second), at5, "the retry re-acks the original commit");
    let v = changes_ok(port, "since=0");
    let mut with_retry = all_ats();
    with_retry.push(at5);
    assert_eq!(entry_ats(&v), with_retry, "one entry per commit, retries excluded");

    sd.shutdown();
}

/// The `limit` range is exactly `1..=4096` (wire.md §The change feed) —
/// both ends of the comparison, in and out. The maximum itself must be
/// ACCEPTED, which nothing watched: a `>` quietly become `>=` refuses the
/// very page size the document invites a client to ask for.
#[test]
fn the_changes_limit_range_is_exactly_one_through_the_maximum() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    seed_flow(port);
    let total = all_ats().len(); // the ceremony's five commits + the seeded five

    for limit in [1usize, 2, 4095, 4096] {
        let (st, body) = changes_raw(port, &format!("since=0&limit={limit}"));
        assert_eq!(st, 200, "limit={limit} is in range: {}", String::from_utf8_lossy(&body));
        assert_eq!(
            entry_ats(&json(&body)).len(),
            limit.min(total),
            "limit={limit} caps the page at min(limit, the committed writes)"
        );
    }
    for limit in ["0", "4097", "18446744073709551616"] {
        let (st, body) = changes_raw(port, &format!("since=0&limit={limit}"));
        assert_eq!(st, 400, "limit={limit} is out of range: refused, never clamped");
        assert_eq!(json(&body)["error"].as_str(), Some("malformed_changes"), "limit={limit}");
    }

    sd.shutdown();
}

/// The committed head, from the daemon's own `/health`.
fn head(port: u16) -> u64 {
    let (st, body) = get(port, "/health");
    assert_eq!(st, 200, "/health: {}", String::from_utf8_lossy(&body));
    json(&body)["log_position"].as_u64().expect("log_position")
}

/// One write, its ack, and exactly the one feed entry it produced — the
/// page is taken from the head as it stood before the write, so nothing
/// earlier can be mistaken for this write's entry.
fn feed_entry(port: u16, token: &str, what: &str, frame: &str) -> (Value, Value) {
    let before = head(port);
    let ack = op(port, Some(token), frame);
    assert!(ack["at"].is_u64(), "{what} must commit: {ack}");
    let page = changes_ok(port, &format!("since={before}"));
    let entries = page["changes"].as_array().expect("changes");
    assert_eq!(entries.len(), 1, "{what}: one write, one entry: {page}");
    (ack, entries[0].clone())
}

/// The key testimony (AUTH-4.48, wire v7) names the key that established
/// the committing session — the field a reader of the feed attributes a
/// write by, so both of its answers are pinned here and pinned apart.
///
/// `"bare"` is the load-bearing one: it is a positive claim that nobody
/// signed, not a null a reader can distrust, and the sidecar never
/// re-derives an entry it holds — so a signed write recorded under it is
/// permanently misattributed with nothing to notice. The fingerprint is
/// read out of `key_set`, tying the entry to what the wire itself
/// publishes about that key rather than to a value this test computes.
#[test]
fn the_key_testimony_names_the_key_that_signed_the_session() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();

    // The ceremony enrolls two keys: the anchor, and the device key every
    // signed session here is opened with.
    let v = op(port, None, &format!(r#"{{"op":"key_set","account":"{OWNER_ACCOUNT}"}}"#));
    let device_fp = v["enrolled"]
        .as_array()
        .expect("enrolled")
        .iter()
        .find(|e| e["anchor"] == Value::Bool(false))
        .and_then(|e| e["fingerprint"].as_str())
        .expect("the ceremony enrolls one non-anchor device key")
        .to_string();

    let signed = open_signed_session(port, OWNER_PRINCIPAL, &device_key());
    let (_, entry) = feed_entry(
        port,
        &signed,
        "a signed write",
        &format!(
            r#"{{"op":"insert","doc":"{OWNER_DOC1}","at":{{"subspace":"1","ordinal":"2"}},"values":["s"]}}"#
        ),
    );
    assert_eq!(
        entry["key"].as_str(),
        Some(device_fp.as_str()),
        "a signed write testifies the establishing key's fingerprint: {entry}"
    );

    // The bare arm beside it, from the SAME principal on the same account
    // — so the two entries differ in their testimony and nothing else a
    // reader could attribute by, which is what makes the field worth
    // reading. A draft mint, since the publish gate is the bare session's
    // wall at the published home.
    let bare = open_session(port, OWNER_PRINCIPAL);
    let (_, entry) = feed_entry(
        port,
        &bare,
        "a bare write",
        &format!(r#"{{"op":"create_new_document","account":"{OWNER_ACCOUNT}"}}"#),
    );
    assert_eq!(entry["key"].as_str(), Some("bare"), "a bare bind testifies bare: {entry}");

    sd.shutdown();
}

/// wire.md §The change feed fixes `docs` as a table: the target doc for
/// arrangement writes; a link write's HOME (`edit_link` both its homes,
/// successor's first); the MINTED document for create/fork/version; `[]`
/// for `delegate` and `register_node`. Four of the fourteen rows were
/// watched, and `edit_link` — the one row with an order to get wrong — was
/// not: `docs` is the field a client dispatches on to decide what to
/// refresh, so a wrong or missing address is a pane that never updates,
/// with a well-formed feed and no error anywhere.
#[test]
fn the_affected_docs_convention_holds_for_every_write_kind() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();

    // One account, so principal 1 owns every document below — which is what
    // `edit_link`'s both-homes gate needs, and what lets `version`/`fork`
    // mint into a known place.
    let boot = open_session(port, 0);
    let v = op(port, Some(&boot), r#"{"op":"next_account_prefix","parent":"1"}"#);
    let prefix = expect_resp(&v, "maybe_addr")["addr"].as_str().expect("prefix").to_string();
    let v = op(
        port,
        Some(&boot),
        &format!(r#"{{"op":"delegate","new_prefix":"{prefix}","new_id":1}}"#),
    );
    let account = acked_addr(&v);
    let s1 = open_session(port, 1);
    let create = || {
        let v = op(
            port,
            Some(&s1),
            &format!(r#"{{"op":"create_new_document","account":"{account}"}}"#),
        );
        acked_addr(&v)
    };
    // MINT-FIRST (RES-26): the first mint is the account's doc 1, born
    // published, where bare writes are gated by design — the rows below
    // write the later, private mints.
    create();
    let doc_a = create();
    let doc_b = create();
    let v = op(
        port,
        Some(&s1),
        &format!(
            r#"{{"op":"insert","doc":"{doc_a}","at":{{"subspace":"1","ordinal":"1"}},"values":["abcdefgh"]}}"#
        ),
    );
    expect_resp(&v, "ack_addr");
    // Three ghost-typed links in doc_a, for the link-write rows.
    let mint_link = |n: u64| {
        let v = op(
            port,
            Some(&s1),
            &format!(
                r#"{{"op":"make_link","home":"{doc_a}","from":{{"addrs":[]}},"to":{{"addrs":[]}},"ty":{{"addrs":["{doc_a}.0.3.6.{n}"]}}}}"#
            ),
        );
        acked_addr(&v)
    };
    let (l1, l2, l3) = (mint_link(1), mint_link(2), mint_link(3));

    // (what, frame, expected docs) — one row per convention. Each row's
    // `docs` is stated here, not read from the daemon.
    let mut rows: Vec<(&str, String, Value)> = vec![
        (
            "delete",
            format!(
                r#"{{"op":"delete","doc":"{doc_a}","p":{{"subspace":"1","ordinal":"1"}},"width":"1"}}"#
            ),
            serde_json::json!([doc_a]),
        ),
        (
            // The DESTINATION, never the source.
            "copy",
            format!(
                r#"{{"op":"copy","doc":"{doc_b}","at":{{"subspace":"1","ordinal":"1"}},"specs":[{{"source":"{doc_a}","span":{{"start":"1.1","width":"0.2"}}}}]}}"#
            ),
            serde_json::json!([doc_b]),
        ),
        (
            "rearrange",
            format!(
                r#"{{"op":"rearrange","doc":"{doc_a}","cuts":[{{"subspace":"1","ordinal":"1"}},{{"subspace":"1","ordinal":"2"}},{{"subspace":"1","ordinal":"3"}}]}}"#
            ),
            serde_json::json!([doc_a]),
        ),
        (
            "register_node",
            r#"{"op":"register_node","addr":"1.9001"}"#.to_string(),
            serde_json::json!([]),
        ),
        (
            "emit",
            format!(
                r#"{{"op":"emit","home":"{doc_a}","ty":[{{"start":"1.1.0.1.0.1.0.1.3","width":"0.0.0.0.0.0.0.0.1"}}],"from":"{doc_a}.0.3.9.1","to":[]}}"#
            ),
            serde_json::json!([doc_a]),
        ),
        (
            "nullify",
            format!(r#"{{"op":"nullify","home":"{doc_a}","target":"{l3}"}}"#),
            serde_json::json!([doc_a]),
        ),
        (
            "assert_sup",
            format!(r#"{{"op":"assert_sup","home":"{doc_a}","old":"{l1}","new":"{l2}"}}"#),
            serde_json::json!([doc_a]),
        ),
        (
            // Both homes, successor's (d_s) FIRST — the one row where the
            // order can be reversed and still compile.
            "edit_link (two homes)",
            format!(
                r#"{{"op":"edit_link","original":"{l1}","d_s":"{doc_b}","d_a":"{doc_a}","successor":{{"from":[],"to":[],"ty":{{"addrs":["{doc_b}.0.3.6.1"]}}}}}}"#
            ),
            serde_json::json!([doc_b, doc_a]),
        ),
        (
            // One home named twice is one document: the dedup write_meta
            // performs when d_a == d_s.
            "edit_link (one home)",
            format!(
                r#"{{"op":"edit_link","original":"{l2}","d_s":"{doc_a}","d_a":"{doc_a}","successor":{{"from":[],"to":[],"ty":{{"addrs":["{doc_a}.0.3.6.2"]}}}}}}"#
            ),
            serde_json::json!([doc_a]),
        ),
    ];
    // The two minting rows name a document known only from the ack, so
    // their expectation is built from it rather than stated up front.
    let minting = [
        ("version", format!(r#"{{"op":"version","d_src":"{doc_a}"}}"#)),
        ("fork", r#"{"op":"fork"}"#.to_string()),
    ];

    fn op_of(what: &str) -> &str {
        what.split_whitespace().next().expect("row names its op")
    }
    for (what, frame, docs) in rows.drain(..) {
        let (_, entry) = feed_entry(port, &s1, what, &frame);
        assert_eq!(entry["op"].as_str(), Some(op_of(what)), "{what}: the entry's op kind");
        assert_eq!(entry["docs"], docs, "{what}: the affected-docs convention");
    }
    for (what, frame) in minting {
        let (ack, entry) = feed_entry(port, &s1, what, &frame);
        let minted = ack["addr"].as_str().expect("a minting write acks its address");
        assert_eq!(entry["op"].as_str(), Some(what), "{what}: the entry's op kind");
        assert_eq!(
            entry["docs"],
            serde_json::json!([minted]),
            "{what}: names the document it minted, which is knowable only from the ack"
        );
    }

    sd.shutdown();
}

#[test]
fn sidecar_survives_restart_truncates_torn_tail_and_bares_lost_records() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sidecar_path = dir.path().join("commits.log");

    let before: Vec<u8>;
    {
        let sd = spawn(dir.path());
        let port = sd.port();
        seed_flow(port);
        let (st, body) = changes_raw(port, "since=0");
        assert_eq!(st, 200);
        before = body;
        sd.shutdown();
    }

    // ── restart: the feed is byte-identical (times included — persisted) ──
    {
        let sd = spawn(dir.path());
        let port = sd.port();
        let (st, body) = changes_raw(port, "since=0");
        assert_eq!(st, 200);
        assert_eq!(body, before, "/changes drifted across a clean restart");
        sd.shutdown();
    }

    // ── torn tail: a partial trailing record is truncated at open; the
    //    daemon comes up and the feed is unchanged. (The fragment's number
    //    must not prefix any REAL record's `{"at":N,` — every committed
    //    position here is ≤ 24.) ──
    {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&sidecar_path)
            .expect("append to commits.log");
        f.write_all(b"{\"at\":9999").expect("write the torn tail");
        drop(f);
        let sd = spawn(dir.path());
        let port = sd.port();
        let (st, body) = changes_raw(port, "since=0");
        assert_eq!(st, 200);
        assert_eq!(body, before, "a torn sidecar tail must not change the feed");
        let contents = std::fs::read_to_string(&sidecar_path).expect("read commits.log");
        assert!(!contents.contains("{\"at\":9999"), "the torn tail was truncated on open");
        sd.shutdown();
    }

    // ── lost record: drop the last whole record (the make_link entry at
    //    24). Reopen: the position is reconstructed as a BARE entry — the
    //    daemon reports null, never a wrong value — while earlier entries
    //    keep their recorded metadata verbatim. ──
    {
        let contents = std::fs::read_to_string(&sidecar_path).expect("read commits.log");
        let trimmed = &contents[..contents.len() - 1]; // drop the final \n
        let cut = trimmed.rfind('\n').map(|i| i + 1).unwrap_or(0);
        std::fs::write(&sidecar_path, &contents[..cut]).expect("drop the last record");

        let sd = spawn(dir.path());
        let port = sd.port();
        let v = changes_ok(port, "since=0");
        assert_eq!(entry_ats(&v), all_ats());
        let entries = v["changes"].as_array().expect("changes");
        let (tail, kept) = entries.split_last().expect("ten entries");
        assert!(
            tail["op"].is_null() && tail["docs"].is_null() && tail["time"].is_null(),
            "a lost record answers bare nulls: {tail}"
        );
        let old: Value = serde_json::from_slice(&before).expect("json");
        assert_eq!(
            kept,
            &old["changes"].as_array().expect("changes")[..kept.len()],
            "surviving records keep their metadata verbatim"
        );
        // The head's record is bare, so head_time honestly answers null.
        let (st, body) = get(port, "/health");
        assert_eq!(st, 200);
        assert!(json(&body)["head_time"].is_null());
        sd.shutdown();
    }
}

/// A `min_since` fence describing a journal other than this one — an
/// operator restoring a data dir, or copying one whose journal was later
/// replaced by a shorter one, which is the case the entry clamp beside it
/// already defends against. It is discarded at open, exactly as an entry
/// above the head is.
///
/// Left standing, it makes `(min_since, head]` empty and the feed answers
/// `410` — with no `floor`, since none survives above the fence — for every
/// position this journal HAS, while `/op-at` serves those positions and
/// `/events` announces them. And it is PERMANENT: the file still carries
/// the number, so every restart reproduces it, on a daemon whose `/health`
/// reports `ok` throughout.
#[test]
fn a_fence_above_the_head_is_not_this_journals_and_is_discarded() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sidecar_path = dir.path().join("commits.log");

    let before: Vec<u8>;
    {
        let sd = spawn(dir.path());
        let port = sd.port();
        seed_flow(port);
        let (st, body) = changes_raw(port, "since=0");
        assert_eq!(st, 200);
        before = body;
        sd.shutdown();
    }

    {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&sidecar_path)
            .expect("append to commits.log");
        f.write_all(b"{\"min_since\":999999}\n").expect("write the foreign fence");
    }

    let sd = spawn(dir.path());
    let port = sd.port();
    let (st, body) = changes_raw(port, "since=0");
    assert_eq!(
        st,
        200,
        "a fence past the head must not refuse the positions this journal holds: {}",
        text(&body)
    );
    assert_eq!(
        entry_ats(&json(&body)),
        all_ats(),
        "and the feed still enumerates every committed write"
    );
    // The metadata survives too: the walk re-covers only what is uncovered,
    // and the entries were never the foreign fence's to drop.
    assert_eq!(body, before, "/changes drifted under a fence that was not this journal's");

    // Not merely repaired in memory — the file no longer carries the number,
    // so a second restart cannot reintroduce it.
    let contents = std::fs::read_to_string(&sidecar_path).expect("read commits.log");
    assert!(
        !contents.contains("999999"),
        "the foreign fence must not survive the rewrite: {contents}"
    );
    sd.shutdown();

    let sd = spawn(dir.path());
    let (st, body) = changes_raw(sd.port(), "since=0");
    assert_eq!(st, 200, "and the second restart is clean too: {}", text(&body));
    assert_eq!(body, before);
    sd.shutdown();
}

/// A data dir written before the sidecar existed (here: by the engine
/// directly, with no daemon): every committed position still appears in
/// `/changes`, reconstructed from the journal via the engine's bounded
/// replay — as bare `null`-field entries, byte-equal to the wire.md
/// example.
#[test]
fn pre_feature_positions_answer_bare_entries() {
    use skep_engine::{Engine, KernelConfig};
    use skep_febe::{Codec, Operation, Response, SessionId};
    use skep_kernel::{BurnedSeqPolicy, CheckpointPolicy, Durability};
    use skep_namespace::PrincipalId;
    use skepd::JsonCodec;

    let dir = tempfile::tempdir().expect("tempdir");
    {
        let cfg = KernelConfig {
            durability: Durability::Fsync {
                journal_path: dir.path().to_path_buf(),
                retain_checkpoints: 2,
                burned_seq: BurnedSeqPolicy::Rollback,
            },
            checkpoint: CheckpointPolicy::EveryN(1024),
        };
        let engine = Engine::open(cfg).expect("engine genesis");
        let febe = Operation::new(Box::new(engine.stores()));
        let codec = JsonCodec;
        let exec = |sid: SessionId, frame: &str| {
            let req = codec
                .parse(frame.as_bytes())
                .unwrap_or_else(|e| panic!("test frame does not parse: {:?}", e.detail));
            febe.execute(sid, req)
        };
        let unexpected = |r: &Response| -> String {
            String::from_utf8_lossy(&codec.marshal(r)).into_owned()
        };

        let boot = febe.bootstrap_session();
        let prefix = match exec(boot, r#"{"op":"next_account_prefix","parent":"1"}"#) {
            Response::MaybeAddr { addr: Some(a), .. } => a.tumbler().to_string(),
            other => panic!("next_account_prefix: {}", unexpected(&other)),
        };
        let account = match exec(
            boot,
            &format!(r#"{{"op":"delegate","new_prefix":"{prefix}","new_id":1}}"#),
        ) {
            Response::AckAddr { addr, at } => {
                assert_eq!(at.0, 2, "delegate commits at position 2; re-pin wire.md");
                addr.tumbler().to_string()
            }
            other => panic!("delegate: {}", unexpected(&other)),
        };
        let s1 = febe.open_session(PrincipalId(1));
        let doc = match exec(
            s1,
            &format!(r#"{{"op":"create_new_document","account":"{account}"}}"#),
        ) {
            Response::AckAddr { addr, at } => {
                assert_eq!(at.0, 3, "create commits at position 3; re-pin wire.md");
                addr.tumbler().to_string()
            }
            other => panic!("create: {}", unexpected(&other)),
        };
        match exec(
            s1,
            &format!(
                r#"{{"op":"insert","doc":"{doc}","at":{{"subspace":"1","ordinal":"1"}},"values":["hi"]}}"#
            ),
        ) {
            Response::AckAddr { at, .. } => {
                assert_eq!(at.0, 8, "the insert commits at position 8; re-pin wire.md")
            }
            other => panic!("insert: {}", unexpected(&other)),
        }
        drop(febe);
        drop(engine); // releases the journal-directory lock for the daemon
    }
    assert!(
        !dir.path().join("commits.log").exists(),
        "the engine alone must write no sidecar (it is the daemon's file)"
    );

    // Spawned UNCLAIMED: this fixture's whole point is a pre-feature
    // journal served as-is, and claiming would append the ceremony's
    // commits after the bare region. Reads are untouched pre-claim.
    let sd = spawn_unclaimed(dir.path());
    let port = sd.port();
    let (st, body) = changes_raw(port, "since=0");
    assert_eq!(st, 200);
    // Compared MODULO the wire-v7 `key` field (null on every bare entry),
    // which lands in wire.md with lane 3.2's doc delta.
    assert_eq!(
        strip_keys(&json(&body)),
        strip_keys(&serde_json::from_str(&doc_changes_block("bare")).expect("doc json")),
        "wire.md 'changes bare' example drifted from the daemon"
    );
    // Pre-feature commits have no recorded time: head_time is null.
    let (st, body) = get(port, "/health");
    assert_eq!(st, 200);
    let health = json(&body);
    assert!(health["head_time"].is_null());
    assert_eq!(health["log_position"].as_u64(), Some(8));
    // Paging over bare entries behaves like any other page.
    let v = changes_ok(port, "since=3&limit=1");
    assert_eq!(entry_ats(&v), vec![8]);
    assert_eq!((v["last"].as_u64(), v["more"].as_bool()), (Some(8), Some(false)));
    let v = changes_ok(port, "since=8");
    assert_eq!(entry_ats(&v), Vec::<u64>::new());
    sd.shutdown();
}

/// Compaction: the feed's memory is bounded by the journal's retention,
/// not by the world's age. Positions the journal has reclaimed are refused
/// by `/op-at` and `/dump?at`, so an entry naming one describes a commit no
/// client can reach — the sidecar drops those entries and rewrites itself
/// around them, and `/changes` answers below the new fence with exactly the
/// `410 history_reclaimed` discipline wire.md gives the rest of history.
///
/// Reclamation is reached honestly rather than simulated, and the daemon
/// makes every commit itself, so the sidecar has FULL coverage when it
/// reopens: the reconstruction walk has nothing to do and cannot be what
/// advances the fence. Only the retention probe can, which is what makes
/// this a test of compaction rather than of the walk.
#[test]
fn the_sidecar_compacts_to_the_journals_retention() {
    use skep_engine::{Engine, KernelConfig};
    use skep_kernel::{BurnedSeqPolicy, CheckpointPolicy, Durability, Seq};

    let dir = tempfile::tempdir().expect("tempdir");

    // Phase 1 — the daemon writes everything, so every position it will
    // later serve is one it recorded. Bulk inserts, because reclamation is
    // at SEGMENT granularity and a segment has to rotate before anything
    // below it can be reclaimed at all.
    let (early, head) = {
        let sd = spawn(dir.path());
        let port = sd.port();
        let doc = seed_flow(port);
        let v = changes_ok(port, "since=0");
        assert_eq!(entry_ats(&v), all_ats(), "the feed starts with every position");
        assert!(v["changes"][0]["op"].is_string(), "and with real metadata");
        let s1 = open_session(port, 1);
        let bulk = "z".repeat(8192);
        for _ in 0..6 {
            // Prepends, so every ordinal is in bounds whatever the doc holds.
            let v = op(
                port,
                Some(&s1),
                &format!(
                    r#"{{"op":"insert","doc":"{doc}","at":{{"subspace":"1","ordinal":"1"}},"values":["{bulk}"]}}"#
                ),
            );
            expect_resp(&v, "ack_addr");
        }
        let (st, body) = get(port, "/health");
        assert_eq!(st, 200);
        let head = json(&body)["log_position"].as_u64().expect("log_position");
        let ats = entry_ats(&changes_ok(port, "since=0"));
        assert_eq!(ats.last(), Some(&head), "the feed covers every position through the head");
        sd.shutdown();
        (ats, head)
    };

    // Phase 2 — reclaim WITHOUT committing anything: one checkpoint at the
    // current head, retaining one, drops the segments wholly below it. No
    // new position appears, so the sidecar's coverage stays complete.
    {
        let cfg = KernelConfig {
            durability: Durability::Fsync {
                journal_path: dir.path().to_path_buf(),
                retain_checkpoints: 1,
                burned_seq: BurnedSeqPolicy::Rollback,
            },
            checkpoint: CheckpointPolicy::Manual,
        };
        let engine = Engine::open(cfg).expect("engine recover");
        engine.kernel().checkpoint().expect("checkpoint reclaims below itself");
        assert_eq!(engine.kernel().current_seq().0, head, "no new commit was made");
        assert!(
            engine.world_at(Seq(0)).is_err(),
            "the journal must actually have reclaimed for this test to mean anything"
        );
        drop(engine);
    }

    // Phase 3 — reopening compacts. The oldest entries are gone from the
    // file and from the feed, and the feed refuses below its new fence.
    let sd = spawn(dir.path());
    let port = sd.port();

    let contents = std::fs::read_to_string(dir.path().join("commits.log")).expect("commits.log");
    assert!(
        contents.contains("min_since"),
        "compaction records the fence it compacted to: {contents}"
    );
    assert!(
        !contents.contains(r#"{"at":2,"#),
        "a reclaimed position's entry does not survive compaction: {contents}"
    );

    let (st, body) = changes_raw(port, "since=0");
    assert_eq!(st, 410, "below the fence is the reclaimed discipline: {}", text(&body));
    let v = json(&body);
    assert_eq!(v["error"].as_str(), Some("history_reclaimed"));
    let floor = v["floor"].as_u64().expect("the refusal names the oldest surviving position");
    assert!(floor > early[0], "the fence advanced past the oldest recorded position");

    // At and above the fence the feed answers normally and still reaches
    // the head — compaction dropped what was unreachable and nothing else.
    let v = changes_ok(port, &format!("since={}", floor - 1));
    let ats = entry_ats(&v);
    assert!(ats.contains(&floor), "the floor itself is served: {ats:?}");
    assert_eq!(ats.last(), Some(&head), "and the feed still runs to the head");

    // The dropped positions are unreachable by every other route too,
    // which is what makes dropping them honest rather than lossy.
    // Not merely "not 200": this test's whole argument is that dropping
    // those entries is honest BECAUSE every route refuses them the same
    // documented way, and a 500 or a 503 would satisfy an inequality while
    // meaning the opposite.
    let env = format!(r#"{{"at":{},"frame":{{"op":"read_link","a":"1.0.1.0.1"}}}}"#, early[0]);
    let (st, body) = http(port, "POST", "/op-at", None, env.as_bytes());
    assert_eq!(
        st,
        410,
        "a reclaimed position gets /op-at's own reclaimed discipline: {}",
        text(&body)
    );
    let v = json(&body);
    assert_eq!(v["error"].as_str(), Some("history_reclaimed"));
    assert!(
        v["floor"].is_u64() || v.get("floor").is_none(),
        "floor is named when known and omitted otherwise, never something else: {v}"
    );

    // …and by the third positioned route, which this test's own preamble
    // names. `/dump?at` shares `/op-at`'s refusal mapping, so what this
    // pins is the ROUTE: `get_dump`'s own error arm answering the same
    // documented discipline.
    #[cfg(feature = "observe")]
    {
        let (st, body) = get(port, &format!("/dump?at={}", early[0]));
        assert_eq!(st, 410, "a reclaimed position is /dump?at's 410 too: {}", text(&body));
        assert_eq!(json(&body)["error"].as_str(), Some("history_reclaimed"));
    }

    sd.shutdown();
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}
