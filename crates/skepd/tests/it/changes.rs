//! The change feed and its sidecar (wire v6): `/changes` lists exactly the
//! committed writes with op kind, affected docs, and commit times; paging
//! via `limit`/`more`/`last`; determinism across calls and restarts; the
//! sidecar's crash honesty (torn tail truncated, lost and pre-feature
//! records answered as bare `null`-field positions, never invented); and
//! `head_time` on `/health`. The doc examples in wire.md §The change feed
//! are asserted against live daemon bytes here (times normalized — the one
//! nondeterministic field; the bare example is byte-exact).
//!
//! Since wire v7.8 (PUB round 2, lane 3.6) the feed is CLASS-GATED: a draft
//! write is masked from every class that cannot read the draft. The seeded
//! flow writes into principal 1's PRIVATE second document, so every read
//! over it here is the OWNER's (principal 1's session), and the guest's
//! masked page stands beside it as its own cell; the class oracle itself is
//! `tests/it/feed_class.rs`.
//!
//! Since wire v7.11 (signed ops; the design record §7.3 (i), D12, D25,
//! r6-2a) the feed carries THE MIRROR'S INPUTS: the entry's `attest` off the
//! marker-mirroring attest store, `key` only on unsigned rows, a
//! `delegate`'s minted pair, a `make_link`'s minted link address, a
//! `publish`'s placed count and base extent — the end-to-end walk, Π and the
//! claim boundary read off the feed alone, the store's crash honesty and its
//! keep below the reclaim floor, and D12 on a record deposit's two rows.

use crate::common;

use std::collections::BTreeMap;
use std::path::Path;

use common::*;
use serde_json::Value;
use skep_identity::Fingerprint;
use skepd::Seq;

/// The claim link's committed position on a fresh board — the ceremony's
/// fifth commit (`common::claim_board`): delegate (2 records), the home mint
/// (1), the one-atom insert (3), the genesis link (3), the claim link (3) —
/// twelve records. The claim's own step then writes the board's first head
/// `H.1` above it ([`H1_ATS`]; signed ops, s1), so the board the claim leaves
/// behind stands at [`CLAIMED_HEAD`], the base every seeded position below
/// sits on. Lane 3.2 re-pinned wire.md's change-feed examples onto the
/// ceremony's numbers; the s1 lane onto these.
const CLAIM_POSITION: u64 = 12;

/// The ceremony's own commit positions (the record counts above,
/// cumulative): delegate, the home mint, the record insert, the genesis
/// link, the claim link.
const CEREMONY_ATS: [u64; 5] = [2, 3, 6, 9, 12];

/// `H.1`'s three commits, in the claim's own step: the staging draft's mint,
/// the head record's insert into it, the publish shot into `H`. The first
/// two write the system account's PRIVATE draft and are masked at every
/// class but the system's; the publish is public, `key: "system"`.
const H1_ATS: [u64; 3] = [CLAIM_POSITION + 1, CLAIM_POSITION + 4, CLAIM_POSITION + 8];

/// `H.1`'s publish — the one head entry every class sees.
const H1_PUBLISH_AT: u64 = H1_ATS[2];

/// The claimed board's head: the ceremony and its `H.1`.
const CLAIMED_HEAD: u64 = H1_PUBLISH_AT;

/// [`seed_flow`]'s commit positions on the claimed board's base: delegate,
/// the home mint, the private second mint, the insert, the make_link.
const SEEDED_ATS: [u64; 5] = [
    CLAIMED_HEAD + 2,
    CLAIMED_HEAD + 3,
    CLAIMED_HEAD + 4,
    CLAIMED_HEAD + 9,
    CLAIMED_HEAD + 12,
];

/// Every committed position a claimed, seeded board's OWNER (principal 1)
/// sees: the ceremony's five commits, `H.1`'s publish (its draft mint and
/// insert are the system account's private writes, masked), then the
/// seeded five.
fn all_ats() -> Vec<u64> {
    CEREMONY_ATS.iter().chain([H1_PUBLISH_AT].iter()).chain(SEEDED_ATS.iter()).copied().collect()
}

/// The scripted flow behind the wire.md examples. Positions are pinned by
/// the stores' record counts: `delegate` commits 2 records (position 22),
/// the home mint 1 (position 23) — MINT-FIRST (RES-26): the account's doc 1
/// is born published, where bare writes are gated by design, so the flow
/// writes a SECOND, private document — that mint 1 (position 24), a
/// two-byte `insert` 5 — two mints, two content writes, one placement —
/// (position 29), `make_link` 3 — mint, link, seat — (position 32). If an
/// ack below drifts, a store changed its transaction shape and wire.md
/// §The change feed must be re-pinned.
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
        CLAIMED_HEAD + 2,
        "delegate is a 2-record commit (Allocate + RegisterPrincipal)"
    );
    let s1 = open_session(port, 1);
    let v = op(
        port,
        Some(&s1),
        &format!(r#"{{"op":"create_new_document","account":"{prefix}"}}"#),
    );
    assert_eq!(acked_addr(&v), "1.0.2.0.1", "the home mint is doc 1; re-pin the examples");
    assert_eq!(acked_at(&v), CLAIMED_HEAD + 3, "create_new_document is a 1-record commit");
    let v = op(
        port,
        Some(&s1),
        &format!(r#"{{"op":"create_new_document","account":"{prefix}"}}"#),
    );
    let doc = acked_addr(&v);
    assert_eq!(doc, "1.0.2.0.2", "second document address drifted; re-pin the examples");
    assert_eq!(acked_at(&v), CLAIMED_HEAD + 4, "create_new_document is a 1-record commit");
    let v = op(
        port,
        Some(&s1),
        &format!(
            r#"{{"op":"insert","doc":"{doc}","at":{{"subspace":"1","ordinal":"1"}},"values":["hi"]}}"#
        ),
    );
    assert_eq!(acked_at(&v), CLAIMED_HEAD + 9, "a 2-value insert is a 5-record commit");
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
        CLAIMED_HEAD + 12,
        "make_link is a 3-record commit (mint + link + seat)"
    );
    doc
}

fn acked_at(v: &Value) -> u64 {
    v["at"].as_u64().unwrap_or_else(|| panic!("no committed at in {v}"))
}

/// `GET /changes?{query}` as `token` (`None` = the guest).
fn changes_raw(port: u16, token: Option<&str>, query: &str) -> (u16, Vec<u8>) {
    http(port, "GET", &format!("/changes?{query}"), token, b"")
}

fn changes_ok(port: u16, token: Option<&str>, query: &str) -> Value {
    let (st, body) = changes_raw(port, token, query);
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

/// One live page against its wire.md example, `time` normalized away — the
/// one field a live daemon cannot reproduce, and wire.md's own stated
/// exception ("the `time` values are illustrative"). EVERY other field is
/// compared, `key` included: the testimony is what distinguishes a
/// bare-session write from a signed one and lost metadata from both.
fn matches_doc(live: &Value, name: &str) {
    let strip_time = |v: &Value| -> Value {
        let mut v = v.clone();
        for e in v["changes"].as_array_mut().expect("changes") {
            e.as_object_mut().expect("entry").remove("time");
        }
        v
    };
    assert_eq!(
        strip_time(live),
        strip_time(&serde_json::from_str(&doc_changes_block(name)).expect("doc json")),
        "wire.md 'changes {name}' drifted from the daemon"
    );
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
    let (st, body) = changes_raw(port, None, "since=0");
    assert_eq!(st, 200, "a fresh world's feed: {}", String::from_utf8_lossy(&body));
    let v = json(&body);
    assert_eq!(entry_ats(&v), Vec::<u64>::new());
    assert_eq!((v["last"].as_u64(), v["more"].as_bool()), (Some(0), Some(false)));

    common::claim_board(port);
    // THE CLAIM WROTE `H.1` (signed ops, s1): the three head entries sit
    // between the claim and the seeded flow — the publish public with
    // `key: "system"`, the private draft's mint and insert masked from
    // everyone but the system account — and the examples below page from
    // above them.
    let (st, body) = changes_raw(port, None, &format!("since={CLAIM_POSITION}"));
    assert_eq!(st, 200, "{}", String::from_utf8_lossy(&body));
    let v = json(&body);
    assert_eq!(entry_ats(&v), vec![H1_PUBLISH_AT], "the guest sees H.1's publish and nothing else of it");
    assert_eq!(v["changes"][0]["op"].as_str(), Some("publish"), "{v}");
    assert_eq!(v["changes"][0]["key"].as_str(), Some("system"), "{v}");
    assert_eq!(head(port), CLAIMED_HEAD, "the claim and its head: twenty records");
    let doc = seed_flow(port);
    let s1 = open_session(port, 1);
    // The owner's view of its own feed — the seeded document is principal
    // 1's private draft, so its entries are the owner's to see.
    let owner = Some(s1.as_str());
    let (st, body) = changes_raw(port, owner, &format!("since={CLAIM_POSITION}&limit=1"));
    assert_eq!(st, 200);
    assert_eq!(entry_ats(&json(&body)), vec![H1_PUBLISH_AT], "the owner too: the draft's writes are the system's");

    // Reads and rejected writes are not in the feed: issue both, then
    // assert the feed holds exactly the five committed writes. The read is
    // the owner's — the seeded document is a private draft.
    let v = op(
        port,
        Some(&s1),
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
    let b = CLAIMED_HEAD;
    let (st, body) = changes_raw(port, owner, &format!("since={b}"));
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
    // …and the whole page against wire.md's own 'feed' example, which is the
    // first thing a client author reads.
    matches_doc(&v, "feed");

    // Determinism: the same question answers byte-identically — per class.
    let (_, again) = changes_raw(port, owner, &format!("since={b}"));
    assert_eq!(body, again, "same (since, limit) on the same journal must be byte-equal");

    // ── the GUEST's page over the same range (wire v7.8, PUB-6.44/6.45):
    //    the delegate (no doc) and the born-published home mint are shown;
    //    the private second document's mint, insert and make_link are
    //    MASKED — omitted, never present with nulled fields — and `last`
    //    is the last VISIBLE position. ──
    let (st, guest_body) = changes_raw(port, None, &format!("since={b}"));
    assert_eq!(st, 200);
    let g = json(&guest_body);
    assert_eq!(entry_ats(&g), vec![b + 2, b + 3], "the guest sees the two published-world writes");
    let guest_entries = g["changes"].as_array().expect("changes");
    assert_eq!(guest_entries[0]["docs"], serde_json::json!([]), "delegate names no doc");
    assert_eq!(guest_entries[1]["docs"], serde_json::json!(["1.0.2.0.1"]), "the home, published");
    assert_eq!((g["last"].as_u64(), g["more"].as_bool()), (Some(b + 3), Some(false)));
    let (_, guest_again) = changes_raw(port, None, &format!("since={b}"));
    assert_eq!(guest_body, guest_again, "the guest's page is byte-equal across repeats");
    matches_doc(&g, "feed_guest");
    // Paging over the guest's VISIBLE stream (PUB-6.44): a page of one is
    // never short of its limit before the head, `more` counts visible
    // entries alone, and `last` is a visible position or the fence.
    let v = changes_ok(port, None, &format!("since={b}&limit=1"));
    assert_eq!(entry_ats(&v), vec![b + 2]);
    assert_eq!((v["last"].as_u64(), v["more"].as_bool()), (Some(b + 2), Some(true)));
    let v = changes_ok(port, None, &format!("since={}&limit=1", b + 2));
    assert_eq!(entry_ats(&v), vec![b + 3]);
    assert_eq!(
        (v["last"].as_u64(), v["more"].as_bool()),
        (Some(b + 3), Some(false)),
        "the masked run past the home mint is not `more`"
    );
    let v = changes_ok(port, None, &format!("since={}", b + 3));
    assert_eq!(entry_ats(&v), Vec::<u64>::new(), "the whole tail is masked for the guest");
    assert_eq!((v["last"].as_u64(), v["more"].as_bool()), (Some(b + 3), Some(false)));

    // ── paging (the owner's) ──
    let v = changes_ok(port, owner, &format!("since={b}&limit=2"));
    assert_eq!(entry_ats(&v), vec![b + 2, b + 3]);
    assert_eq!((v["last"].as_u64(), v["more"].as_bool()), (Some(b + 3), Some(true)));
    matches_doc(&v, "feed_page");
    let v = changes_ok(port, owner, &format!("since={}&limit=2", b + 3));
    assert_eq!(entry_ats(&v), vec![b + 4, b + 9]);
    assert_eq!((v["last"].as_u64(), v["more"].as_bool()), (Some(b + 9), Some(true)));
    let v = changes_ok(port, owner, &format!("since={}&limit=2", b + 9));
    assert_eq!(entry_ats(&v), vec![b + 12]);
    assert_eq!((v["last"].as_u64(), v["more"].as_bool()), (Some(b + 12), Some(false)));

    // `since` is a fence, not a position: an interior number pages cleanly.
    let v = changes_ok(port, owner, &format!("since={}", b + 5));
    assert_eq!(entry_ats(&v), vec![b + 9, b + 12]);

    // since ≥ head: empty, `last` echoes `since`.
    let v = changes_ok(port, owner, &format!("since={}", b + 12));
    assert_eq!(entry_ats(&v), Vec::<u64>::new());
    assert_eq!((v["last"].as_u64(), v["more"].as_bool()), (Some(b + 12), Some(false)));
    let v = changes_ok(port, owner, "since=999");
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
        "since=0&under=",
        "since=0&under=1..2",
        "since=0&under=abc",
        "since=0&drafts=yes",
        "since=0&drafts=true&drafts=false",
    ] {
        let path = if bad.is_empty() { "/changes".to_string() } else { format!("/changes?{bad}") };
        let (st, body) = http(port, "GET", &path, None, b"");
        assert_eq!(st, 400, "'{bad}' must be refused: {}", String::from_utf8_lossy(&body));
        assert_eq!(json(&body)["error"].as_str(), Some("malformed_changes"), "'{bad}'");
    }

    // An idempotent retry re-acks the original commit and records nothing
    // new: the feed gains exactly one entry for the pair.
    let frame = format!(
        r#"{{"op":"insert","doc":"{doc}","id":"dup-1","at":{{"subspace":"1","ordinal":"3"}},"values":["x"]}}"#
    );
    let first = op(port, Some(&s1), &frame);
    let at5 = acked_at(&first);
    let second = op(port, Some(&s1), &frame);
    assert_eq!(acked_at(&second), at5, "the retry re-acks the original commit");
    let v = changes_ok(port, owner, "since=0");
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
    let s1 = open_session(port, 1);
    let total = all_ats().len(); // the ceremony's five commits, H.1's publish, the seeded five

    for limit in [1usize, 2, 4095, 4096] {
        let (st, body) = changes_raw(port, Some(&s1), &format!("since=0&limit={limit}"));
        assert_eq!(st, 200, "limit={limit} is in range: {}", String::from_utf8_lossy(&body));
        assert_eq!(
            entry_ats(&json(&body)).len(),
            limit.min(total),
            "limit={limit} caps the page at min(limit, the committed writes)"
        );
    }
    for limit in ["0", "4097", "18446744073709551616"] {
        let (st, body) = changes_raw(port, Some(&s1), &format!("since=0&limit={limit}"));
        assert_eq!(st, 400, "limit={limit} is out of range: refused, never clamped");
        assert_eq!(json(&body)["error"].as_str(), Some("malformed_changes"), "limit={limit}");
    }

    sd.shutdown();
}

/// The `under` tumbler's two wire caps and the `since` fence's top, both
/// ends each. A query string's tumbler goes through the codec's own bounded
/// parse, the door a frame's tumbler meets, and that door is the only thing
/// between this route and an unbounded `Tumbler` — one the `under=` merge
/// branch clones per range call. The AT-CAP rows are the load-bearing half:
/// a `>` quietly become `>=` refuses a prefix the substrate can legitimately
/// name, and the refusal list beside them only ever tested the grammar.
///
/// It is also the one wire assertion that the query and the frame share that
/// door: nothing else here would notice the route growing a second grammar
/// or a second budget of its own.
#[test]
fn the_changes_query_meets_its_tumbler_caps_and_its_fence_at_both_ends() {
    /// `codec::MAX_TUMBLER_COMPONENTS`, restated: the constant is private
    /// to the module that spends it, so moving it must be a visible
    /// decision here.
    const UNDER_COMPONENT_CAP: usize = 256;
    /// `codec::MAX_NAT_DIGITS`, restated for the same reason.
    const UNDER_DIGIT_CAP: usize = 4096;

    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    seed_flow(port);

    // An admitted prefix at either cap names no document this board holds —
    // every one is `1.0.N.0.M` — so the page is empty and `last` echoes the
    // fence. What is asserted is the ADMISSION: the query reached the feed.
    let admitted = |under: String, what: &str| {
        let v = changes_ok(port, None, &format!("since=0&under={under}"));
        assert_eq!(entry_ats(&v), Vec::<u64>::new(), "{what}: names no document of this board");
        assert_eq!((v["last"].as_u64(), v["more"].as_bool()), (Some(0), Some(false)), "{what}");
    };
    let refused = |under: String, what: &str| {
        let (st, body) = changes_raw(port, None, &format!("since=0&under={under}"));
        assert_eq!(st, 400, "{what}: {}", text(&body));
        assert_eq!(json(&body)["error"].as_str(), Some("malformed_changes"), "{what}");
    };

    admitted(vec!["1"; UNDER_COMPONENT_CAP].join("."), "a tumbler at the depth cap");
    refused(vec!["1"; UNDER_COMPONENT_CAP + 1].join("."), "one component past the depth cap");
    admitted(format!("1.{}", "9".repeat(UNDER_DIGIT_CAP)), "a component at the digit cap");
    refused(format!("1.{}", "9".repeat(UNDER_DIGIT_CAP + 1)), "one digit past the digit cap");

    // The fence's top: `since` is a fence and not a position, so any number
    // works — and `u64::MAX` is the one value for which the feed cannot form
    // `since + 1`. Unguarded it panics in a debug build and, in release,
    // wraps to the start of the feed and serves the whole history to a
    // caller who asked for nothing past the top.
    let v = changes_ok(port, None, &format!("since={}", u64::MAX));
    assert_eq!(entry_ats(&v), Vec::<u64>::new(), "the top of the range is above every position");
    assert_eq!(
        (v["last"].as_u64(), v["more"].as_bool()),
        (Some(u64::MAX), Some(false)),
        "…and the fence is echoed, never wrapped to the start of the feed"
    );

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
/// earlier can be mistaken for this write's entry. Read as the WRITER
/// (`token`), whose own drafts the entry may name. Posted through [`op`],
/// which attaches the suite's `attest` where the token names a signer.
fn feed_entry(port: u16, token: &str, what: &str, frame: &str) -> (Value, Value) {
    let before = head(port);
    let ack = op(port, Some(token), frame);
    assert!(ack["at"].is_u64(), "{what} must commit: {ack}");
    (ack, one_entry_since(port, token, what, before))
}

/// [`feed_entry`] with the frame posted AS WRITTEN — no `attest` attached
/// beyond what the caller composed — so a cell can hold the request's own
/// `attest` bytes beside the row, or present none on purpose.
fn feed_entry_as_written(port: u16, token: &str, what: &str, frame: &str) -> (Value, Value) {
    let before = head(port);
    let ack = op_unattested(port, Some(token), frame);
    assert!(ack["at"].is_u64(), "{what} must commit: {ack}");
    (ack, one_entry_since(port, token, what, before))
}

fn one_entry_since(port: u16, token: &str, what: &str, before: u64) -> Value {
    let page = changes_ok(port, Some(token), &format!("since={before}"));
    let entries = page["changes"].as_array().expect("changes");
    assert_eq!(entries.len(), 1, "{what}: one write, one entry: {page}");
    entries[0].clone()
}

/// The whole feed from the floor as `token` (`None` = the guest), one page
/// — the boards here are far under the page cap.
fn all_entries(port: u16, token: Option<&str>) -> Vec<Value> {
    let v = changes_ok(port, token, "since=0&limit=4096");
    assert_eq!(v["more"], Value::Bool(false), "one page holds the whole feed: {v}");
    v["changes"].as_array().expect("changes").clone()
}

/// The entry at `at` among `entries`.
fn entry_at(entries: &[Value], at: u64) -> &Value {
    entries
        .iter()
        .find(|e| e["at"].as_u64() == Some(at))
        .unwrap_or_else(|| panic!("no entry at {at} in {entries:?}"))
}

/// The five op terms a row may carry, by name.
const TERMS: [&str; 5] = ["new_prefix", "new_id", "link", "placed", "base_extent"];

/// The terms an op's row carries (wire.md §The change feed); every other
/// is ABSENT on its row — `emit` and `edit_link` mint links too and carry
/// none (r6-2a names `make_link` alone).
fn terms_of(op: &str) -> &'static [&'static str] {
    match op {
        "delegate" => &["new_prefix", "new_id"],
        "make_link" => &["link"],
        "publish" => &["placed", "base_extent"],
        _ => &[],
    }
}

/// Every member named is ABSENT from the entry — not null, not anything.
fn assert_absent(entry: &Value, members: &[&str], what: &str) {
    for m in members {
        assert!(entry.get(m).is_none(), "{what}: `{m}` must be absent: {entry}");
    }
}

/// The row carries exactly the terms its op carries, and none other.
fn assert_terms_by_op(entry: &Value, what: &str) {
    let op = entry["op"].as_str().unwrap_or_else(|| panic!("{what}: a recorded op: {entry}"));
    for m in TERMS {
        let carried = terms_of(op).contains(&m);
        assert_eq!(
            entry.get(m).is_some(),
            carried,
            "{what}: a {op} row {} `{m}`: {entry}",
            if carried { "carries" } else { "does not carry" }
        );
    }
}

/// The fingerprint hex a seed carrier's hybrid key enrols under — what a
/// signed session's unsigned writes testify as their `key`.
fn fingerprint_of(sk: &ed25519_dalek::SigningKey) -> String {
    Fingerprint::of(&public_key_of(sk)).to_hex()
}

/// The write's TESTIMONY (AUTH-4.48, wire v7) — the wire's `key` field —
/// names the key that established the committing session, and since
/// wire v7.11 (D12) is served ONLY where the entry carries no signature:
/// a row whose entry FILLED ITS MARKER carries `attest` — the request's
/// own member, byte for byte — and no `key`; a signed-session write that
/// presented no `attest` (an op outside the checked set) still carries the
/// key; a bare write carries `"bare"`. All three pinned here, and apart.
///
/// `"bare"` is the load-bearing one: it is a positive claim that nobody
/// signed, not a null a reader can distrust, and the sidecar never
/// re-derives an entry it holds — so a signed write recorded under it is
/// permanently misattributed with nothing to notice. The fingerprint is
/// read out of `key_set`, tying the entry to what the wire itself
/// publishes about that key rather than to a value this test computes.
#[test]
fn the_testimony_names_the_key_that_signed_the_session() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();

    // The ceremony enrolls two keys: the anchor, and the device key every
    // signed session here is opened with.
    let v = op(port, None, &format!(r#"{{"op":"key_set","account":"{CLAIMANT_ACCOUNT}"}}"#));
    let device_fp = v["enrolled"]
        .as_array()
        .expect("enrolled")
        .iter()
        .find(|e| e["anchor"] == Value::Bool(false))
        .and_then(|e| e["fingerprint"].as_str())
        .expect("the ceremony enrolls one non-anchor device key")
        .to_string();

    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    // A write that FILLS ITS MARKER: a grant link into the published home
    // — publish class, the checked set — composed and signed by the suite's
    // signer, posted as composed so the request's `attest` is in hand.
    let frame = typed_link_frame(CLAIMANT_DOC1, &[CLAIMANT_ACCOUNT], &[], T_GRANT);
    let sent = attach_attest(port, &signed, &frame);
    let sent: Value = serde_json::from_str(&sent).expect("the composed frame is JSON");
    assert!(sent["attest"].is_object(), "the suite's signer attached an attest: {sent}");
    let (ack, entry) = feed_entry_as_written(port, &signed, "a marker-signed write", &sent.to_string());
    assert!(
        entry.get("key").is_none(),
        "a signed entry has one authority for its hand, its own signature — no `key`: {entry}"
    );
    assert_eq!(
        entry["attest"], sent["attest"],
        "the row's attest is the request's own — alg token and sig hex, byte-equal: {entry}"
    );
    assert_eq!(entry["link"].as_str(), Some(acked_addr(&ack).as_str()), "the minted link: {entry}");
    let slot = sd.daemon().attestation_at(Seq(acked_at(&ack))).expect("a boundary").expect("filled");
    assert_eq!(
        entry["attest"]["sig"].as_str().map(str::to_string),
        Some(hex(slot.sig())),
        "…and the marker's own bytes, which the store mirrors"
    );

    // A signed-session write that PRESENTED NO `attest` — a draft mint,
    // outside the checked set, so no signature exists for it: the key is
    // served, the fingerprint of the session's establishing key.
    let (_, entry) = feed_entry_as_written(
        port,
        &signed,
        "a signed-session write with no attest",
        &format!(r#"{{"op":"create_new_document","account":"{CLAIMANT_ACCOUNT}"}}"#),
    );
    assert_eq!(
        entry["key"].as_str(),
        Some(device_fp.as_str()),
        "an unsigned entry from a signed session testifies the establishing key's fingerprint: {entry}"
    );
    assert_absent(&entry, &["attest"], "no marker, no attest");

    // The bare arm beside it, from the SAME principal on the same account
    // — so the two entries differ in their testimony and nothing else a
    // reader could attribute by, which is what makes the field worth
    // reading. A draft mint, since the publish gate is the bare session's
    // wall at the published home.
    let bare = open_session(port, CLAIMANT_PRINCIPAL);
    let (_, entry) = feed_entry(
        port,
        &bare,
        "a bare write",
        &format!(r#"{{"op":"create_new_document","account":"{CLAIMANT_ACCOUNT}"}}"#),
    );
    assert_eq!(entry["key"].as_str(), Some("bare"), "a bare bind testifies bare: {entry}");
    assert_absent(&entry, &["attest"], "a bare write");

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
///
/// And since wire v7.11 the OP'S OWN TERMS, per kind: a `delegate` row's
/// minted pair, a `make_link` row's minted link address, and NOTHING on any
/// other row — `emit`'s among them, which mints a link too and carries no
/// `link` (r6-2a names `make_link` alone). Every write here is a bare
/// session's, so every row carries `key: "bare"` and no `attest`.
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
    let (ack, entry) = feed_entry(
        port,
        &boot,
        "delegate",
        &format!(r#"{{"op":"delegate","new_prefix":"{prefix}","new_id":1}}"#),
    );
    let account = acked_addr(&ack);
    assert_eq!(entry["docs"], serde_json::json!([]), "delegate names no doc");
    assert_eq!(
        entry["new_prefix"].as_str(),
        Some(account.as_str()),
        "the minted account address, the ack's: {entry}"
    );
    assert_eq!(entry["new_id"].as_u64(), Some(1), "the principal seated: {entry}");
    assert_terms_by_op(&entry, "delegate");
    assert_absent(&entry, &["attest"], "delegate");
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
    // A fourth, watched: the `make_link` row carries the minted link's
    // address, the ack's.
    let (ack, entry) = feed_entry(
        port,
        &s1,
        "make_link",
        &format!(
            r#"{{"op":"make_link","home":"{doc_a}","from":{{"addrs":[]}},"to":{{"addrs":[]}},"ty":{{"addrs":["{doc_a}.0.3.6.4"]}}}}"#
        ),
    );
    assert_eq!(entry["link"].as_str(), Some(acked_addr(&ack).as_str()), "the minted link: {entry}");
    assert_terms_by_op(&entry, "make_link");

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
    // their expectation is built from it rather than stated up front. The
    // version is the CROSS-OWNER arm — a private copy of the claimant's
    // published home, minted into principal 1's own account — since a
    // version of one's own draft is versionless (PUB-2.9, the store's
    // `private_source_versionless`; `tests/it/version_chain.rs`).
    let minting = [
        ("version", format!(r#"{{"op":"version","d_src":"{CLAIMANT_DOC1}","published":false}}"#)),
        ("fork", r#"{"op":"fork"}"#.to_string()),
    ];

    fn op_of(what: &str) -> &str {
        what.split_whitespace().next().expect("row names its op")
    }
    for (what, frame, docs) in rows.drain(..) {
        let (_, entry) = feed_entry(port, &s1, what, &frame);
        assert_eq!(entry["op"].as_str(), Some(op_of(what)), "{what}: the entry's op kind");
        assert_eq!(entry["docs"], docs, "{what}: the affected-docs convention");
        // The terms: none on any of these rows — `emit` mints a link and
        // carries no `link`, `assert_sup` and `nullify` deposit records and
        // carry none either.
        assert_terms_by_op(&entry, what);
        assert_eq!(entry["key"].as_str(), Some("bare"), "{what}: a bare session's write");
        assert_absent(&entry, &["attest"], what);
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
        assert_terms_by_op(&entry, what);
    }

    sd.shutdown();
}

/// The seeded feed as its OWNER, principal 1 — a fresh session per daemon
/// life (tokens are uptime-scoped; the class is the principal's).
fn owner_changes(port: u16, query: &str) -> (u16, Vec<u8>) {
    let s1 = open_session(port, 1);
    changes_raw(port, Some(&s1), query)
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
        let (st, body) = owner_changes(port, "since=0");
        assert_eq!(st, 200);
        before = body;
        sd.shutdown();
    }

    // ── restart: the feed is byte-identical (times included — persisted) ──
    {
        let sd = spawn(dir.path());
        let port = sd.port();
        let (st, body) = owner_changes(port, "since=0");
        assert_eq!(st, 200);
        assert_eq!(body, before, "/changes drifted across a clean restart");
        sd.shutdown();
    }

    // ── torn tail: a partial trailing record is truncated at open; the
    //    daemon comes up and the feed is unchanged. (The fragment's number
    //    must not prefix any REAL record's `{"at":N,` — every committed
    //    position here is ≤ 32.) ──
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
        let (st, body) = owner_changes(port, "since=0");
        assert_eq!(st, 200);
        assert_eq!(body, before, "a torn sidecar tail must not change the feed");
        let contents = std::fs::read_to_string(&sidecar_path).expect("read commits.log");
        assert!(!contents.contains("{\"at\":9999"), "the torn tail was truncated on open");
        sd.shutdown();
    }

    // ── lost record: drop the last whole record (the make_link entry at
    //    32). Reopen: the position is reconstructed as a BARE entry — the
    //    daemon reports null, never a wrong value — while earlier entries
    //    keep their recorded metadata verbatim. ──
    {
        let contents = std::fs::read_to_string(&sidecar_path).expect("read commits.log");
        let trimmed = &contents[..contents.len() - 1]; // drop the final \n
        let cut = trimmed.rfind('\n').map(|i| i + 1).unwrap_or(0);
        std::fs::write(&sidecar_path, &contents[..cut]).expect("drop the last record");

        let sd = spawn(dir.path());
        let port = sd.port();
        let s1 = open_session(port, 1);
        let v = changes_ok(port, Some(&s1), "since=0");
        assert_eq!(entry_ats(&v), all_ats());
        let entries = v["changes"].as_array().expect("changes");
        let (tail, kept) = entries.split_last().expect("eleven entries");
        assert!(
            tail["op"].is_null()
                && tail["docs"].is_null()
                && tail["time"].is_null()
                && tail["key"].is_null(),
            "a lost record answers null in EVERY metadata field, `key` included: the \
             null is RESERVED for lost testimony, and `\"bare\"` is a positive claim \
             that this write was unsigned — one nobody made about it: {tail}"
        );
        // …the op's own terms included: the lost record was a `make_link`,
        // whose minted link address is now lost with it — every term reads
        // `null`, since a bare row's op is unknown, and none is invented.
        for term in TERMS {
            assert!(
                tail.get(term).is_some_and(Value::is_null),
                "a bare row's `{term}` is the reserved null: {tail}"
            );
        }
        assert_absent(tail, &["attest"], "a bare row whose marker was empty");
        let old: Value = serde_json::from_slice(&before).expect("json");
        assert_eq!(
            kept,
            &old["changes"].as_array().expect("changes")[..kept.len()],
            "surviving records keep their metadata verbatim"
        );
        // The bare position CLASSIFIES FROM THE JOURNAL (PUB-6.45): it was
        // a make_link into principal 1's private draft, so the guest's page
        // omits it exactly as it omitted the recorded entry — a lost
        // sidecar never unmasks a draft write.
        let g = changes_ok(port, None, "since=0");
        assert_eq!(
            entry_ats(&g),
            [CEREMONY_ATS.as_slice(), &[H1_PUBLISH_AT], &SEEDED_ATS[..2]].concat(),
            "the guest sees the ceremony, H.1's publish and the two published-world writes, bare tail masked"
        );
        // The head's record is bare, so head_time honestly answers null.
        let (st, body) = get(port, "/health");
        assert_eq!(st, 200);
        assert!(json(&body)["head_time"].is_null());
        sd.shutdown();
    }
}

/// A RECORDED position carrying a MALFORMED document name answers as a BARE
/// one — op, docs, time and key all null — and its op, its time and the
/// FINGERPRINT of the key whose session committed it are not disclosed.
///
/// `commits.log` is a trust boundary: an operator's edit, or a build whose
/// address rendering differs, and its `docs` array replays as arbitrary
/// strings. Left recorded, a list none of whose names parse classifies the
/// position EMPTY — and an empty class is a `[]`-docs entry, which is never
/// masked, so the write is served to EVERY class carrying that testimony.
/// Demoted, it discloses its position alone, the residue a position the
/// journal cannot classify already carries.
///
/// The rewritten line keeps its `op`, `time` and `key` intact: what the
/// daemon refuses is a HALF-RECORDED position, exactly as `parse_line`
/// already refuses a line carrying some of those three and not the others.
#[test]
fn a_position_carrying_a_malformed_document_name_answers_bare() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sidecar_path = dir.path().join("commits.log");
    {
        let sd = spawn(dir.path());
        seed_flow(sd.port());
        sd.shutdown();
    }

    // Make the LAST document-naming record's docs MALFORMED — the seeded
    // `make_link` into principal 1's PRIVATE draft, so the mask is what the
    // demotion is protecting. `1.0` is a dotted decimal that is not an
    // address (T4 refuses a trailing zero), so the LINE still parses as a
    // record and only its names do not.
    let contents = std::fs::read_to_string(&sidecar_path).expect("read commits.log");
    let mut lines: Vec<String> = Vec::new();
    let mut doctored: Option<u64> = None;
    for line in contents.lines().rev() {
        let mut v: Value = serde_json::from_str(line).expect("a sidecar line is JSON");
        let names = v.get("docs").and_then(Value::as_array).map_or(0, Vec::len);
        if doctored.is_none() && names > 0 {
            doctored = Some(v["at"].as_u64().expect("a record carries its position"));
            v["docs"] = serde_json::json!(["1.0"]);
        }
        lines.push(serde_json::to_string(&v).expect("json"));
    }
    lines.reverse();
    let at = doctored.expect("the seeded feed holds a record naming a document");
    assert_eq!(at, SEEDED_ATS[4], "the doctored position is the make_link into the draft");
    std::fs::write(&sidecar_path, format!("{}\n", lines.join("\n"))).expect("rewrite");

    let bare_to_owner_masked_from_guest = |port: u16, what: &str| {
        let s1 = open_session(port, 1);
        let v = changes_ok(port, Some(&s1), "since=0");
        assert_eq!(entry_ats(&v), all_ats(), "{what}: the owner still sees the position");
        let entry = v["changes"]
            .as_array()
            .expect("changes")
            .iter()
            .find(|e| e["at"].as_u64() == Some(at))
            .expect("the doctored position")
            .clone();
        assert!(
            entry["op"].is_null()
                && entry["docs"].is_null()
                && entry["time"].is_null()
                && entry["key"].is_null(),
            "{what}: a position whose names this daemon cannot parse stands behind \
             none of its testimony — not its op, not its time, and not the \
             fingerprint of the key whose session committed it: {entry}"
        );
        let g = changes_ok(port, None, "since=0");
        assert!(
            !entry_ats(&g).contains(&at),
            "{what}: and a draft write is not unmasked by testimony this daemon \
             cannot parse: {:?}",
            entry_ats(&g)
        );
    };

    // The derived index still holds that position's GOOD names, and the
    // demotion is driven by the authority file regardless — so the entry
    // renders bare while its class, and with it the mask, is untouched.
    {
        let sd = spawn(dir.path());
        bare_to_owner_masked_from_guest(sd.port(), "with the derived index intact");
        sd.shutdown();
    }

    // And with the index gone, so no derived file rescues the class: the
    // position classifies from the JOURNAL (the bare path, PUB-6.45) and
    // still discloses none of its testimony. This is the leg where the
    // defect lives — a class none of whose names parse is EMPTY, and an
    // empty class is a `[]`-docs entry, which is never masked.
    std::fs::remove_file(dir.path().join("feed-index.log")).expect("drop the derived index");
    {
        let sd = spawn(dir.path());
        bare_to_owner_masked_from_guest(sd.port(), "with the derived index gone");
        sd.shutdown();
    }
}

/// A DERIVED index record whose `docs` array holds an element that is not a
/// string at all does not unmask the draft write it names.
///
/// The one loss a `docs` read must count against what the file CLAIMED and
/// not against what could be read out of it. An array of `[42]` claims one
/// name and yields none, so a read that drops the non-string BEFORE its
/// "did every name parse?" test sees zero against zero, agrees, and
/// classifies the position EMPTY — and an empty class is a `[]`-docs entry,
/// which is never masked, so the write reaches every class including the
/// guest. The same read one element longer is the same species one step
/// less visible: a list of `["<doc>", 42]` classifies by a SMALLER set than
/// the write touched, so an entry is masked against fewer documents than it
/// named.
///
/// `feed-masked.log` is deleted so the bitmap must be re-derived from that
/// classification, which is what makes the loss reach the wire: held over
/// from a previous open the bitmap decides the guest's page on its own
/// (`Inner::masked`'s card states that direction), and a short class would
/// sit behind it undisclosed until the next whole-file loss.
#[test]
fn a_derived_index_record_naming_a_non_string_does_not_unmask() {
    let dir = tempfile::tempdir().expect("tempdir");
    let index_path = dir.path().join("feed-index.log");
    {
        let sd = spawn(dir.path());
        seed_flow(sd.port());
        sd.shutdown();
    }

    // The seeded `make_link` into principal 1's PRIVATE draft — the one
    // position whose masking is what this read is protecting.
    let at = SEEDED_ATS[4];
    let contents = std::fs::read_to_string(&index_path).expect("read feed-index.log");
    let doctored: Vec<String> = contents
        .lines()
        .map(|line| {
            let mut v: Value = serde_json::from_str(line).expect("a derived line is JSON");
            if v.get("at").and_then(Value::as_u64) == Some(at) {
                assert!(
                    v.get("docs").and_then(Value::as_array).is_some_and(|d| !d.is_empty()),
                    "the doctored position must name a document: {v}"
                );
                v["docs"] = serde_json::json!([42]);
            }
            serde_json::to_string(&v).expect("json")
        })
        .collect();
    assert!(
        doctored.iter().any(|l| l.contains("42")),
        "the index must hold a record for the make_link into the draft"
    );
    std::fs::write(&index_path, format!("{}\n", doctored.join("\n"))).expect("rewrite");
    std::fs::remove_file(dir.path().join("feed-masked.log")).expect("drop the bitmap");

    let sd = spawn(dir.path());
    let port = sd.port();
    let g = changes_ok(port, None, "since=0");
    assert!(
        !entry_ats(&g).contains(&at),
        "a draft write is not unmasked by a derived record this daemon cannot read: {:?}",
        entry_ats(&g)
    );
    let s1 = open_session(port, 1);
    let v = changes_ok(port, Some(&s1), "since=0");
    assert_eq!(
        entry_ats(&v),
        all_ats(),
        "and the owner's page is whole: the class fell back to the authority file's names"
    );
    sd.shutdown();
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
        let (st, body) = owner_changes(port, "since=0");
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
    let (st, body) = owner_changes(port, "since=0");
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
    let (st, body) = owner_changes(sd.port(), "since=0");
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
    use skep_febe::{Codec, OperationSurface, Response, SessionId};
    use skep_kernel::{BurnedSeqPolicy, CheckpointPolicy, Durability, SaltSource};
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
            salt: SaltSource::Seeded(0),
        };
        let engine = Engine::open(cfg).expect("engine genesis");
        let febe = OperationSurface::new(Box::new(engine.stores()));
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
        // Doc 1 is born published (PUB-8.21), so this is a DECLARED deposit-shaped
        // append at a fresh position (PUB-2.59's shape; PUB-9.13's declared horn) —
        // the one write a published home admits in place, its prose declared under
        // a MEMBER type, ENROLL's (PUB-2.60's residue). The subject is unchanged.
        match exec(
            s1,
            &format!(
                r#"{{"op":"insert","doc":"{doc}","at":{{"subspace":"1","ordinal":"1"}},"values":["hi"],"deposit":"{T_ENROLL}"}}"#
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
    // Read as the GUEST: every bare position here classifies PUBLISHED from
    // the journal (a delegate, the born-published home's mint, a deposit
    // into it), so the guest's page is the whole pre-feature history.
    let (st, body) = changes_raw(port, None, "since=0");
    assert_eq!(st, 200);
    // BYTE-EXACT, which wire.md claims of this example alone: a bare
    // position has no recorded time, so there is no field to normalize and
    // nothing is excluded from the comparison.
    assert_eq!(
        json(&body),
        serde_json::from_str::<Value>(&doc_changes_block("bare")).expect("doc json"),
        "wire.md 'changes bare' example drifted from the daemon"
    );
    // Pre-feature commits have no recorded time: head_time is null.
    let (st, body) = get(port, "/health");
    assert_eq!(st, 200);
    let health = json(&body);
    assert!(health["head_time"].is_null());
    assert_eq!(health["log_position"].as_u64(), Some(8));
    // Paging over bare entries behaves like any other page.
    let v = changes_ok(port, None, "since=3&limit=1");
    assert_eq!(entry_ats(&v), vec![8]);
    assert_eq!((v["last"].as_u64(), v["more"].as_bool()), (Some(8), Some(false)));
    let v = changes_ok(port, None, "since=8");
    assert_eq!(entry_ats(&v), Vec::<u64>::new());
    sd.shutdown();
}

/// Reclaim everything below the head WITHOUT committing anything: one
/// checkpoint at the current head, retaining one, drops the segments wholly
/// below it. No new position appears, so the sidecar's coverage stays
/// complete, and the retention floor lands AT the head.
fn reclaim_below_the_head(dir: &Path, head: u64) {
    use skep_engine::{Engine, KernelConfig};
    use skep_kernel::{BurnedSeqPolicy, CheckpointPolicy, Durability, SaltSource};

    let cfg = KernelConfig {
        durability: Durability::Fsync {
            journal_path: dir.to_path_buf(),
            retain_checkpoints: 1,
            burned_seq: BurnedSeqPolicy::Rollback,
        },
        checkpoint: CheckpointPolicy::Manual,
        salt: SaltSource::Seeded(0),
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

/// Six bulk prepends into `doc` from `session` — reclamation is at SEGMENT
/// granularity, and a segment has to rotate before anything below it can
/// be reclaimed at all.
fn rotate_a_segment(port: u16, session: &str, doc: &str) {
    let bulk = "z".repeat(8192);
    for _ in 0..6 {
        // Prepends, so every ordinal is in bounds whatever the doc holds.
        let v = op(
            port,
            Some(session),
            &format!(
                r#"{{"op":"insert","doc":"{doc}","at":{{"subspace":"1","ordinal":"1"}},"values":["{bulk}"]}}"#
            ),
        );
        expect_resp(&v, "ack_addr");
    }
}

/// A marker-signed write: a ghost-typed link into the claimant's published
/// doc 1 from `signed`, the device session — publish class, the checked set,
/// its `attest` composed by the suite's signer and admitted. Answers its
/// position and its row's `attest` as the feed serves it.
fn signed_ghost_link(port: u16, signed: &str, n: u64) -> (u64, Value) {
    let before = head(port);
    let v = op(
        port,
        Some(signed),
        &link_frame(CLAIMANT_DOC1, r#"{"addrs":[]}"#, r#"{"addrs":[]}"#, &ghost_ty(CLAIMANT_DOC1, n)),
    );
    let at = acked_at(&v);
    let entry = one_entry_since(port, signed, "a signed ghost link", before);
    assert!(entry["attest"].is_object(), "the row carries the marker: {entry}");
    (at, entry["attest"].clone())
}

/// The attest store's lines, `position → (alg tag, sig hex)`, read off the
/// file as an operator would.
fn attest_store_lines(dir: &Path) -> BTreeMap<u64, (u64, String)> {
    let text = std::fs::read_to_string(dir.join("feed-attest.log")).expect("feed-attest.log");
    text.lines()
        .filter_map(|line| {
            let v: Value = serde_json::from_str(line).expect("a store line is JSON");
            let at = v.get("at")?.as_u64()?;
            Some((at, (v["alg"].as_u64().expect("alg"), v["sig"].as_str().expect("sig").to_string())))
        })
        .collect()
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
///
/// THE ATTEST STORE IS THE EXCEPTION (BW-01; the design record §7.3 (i)): a
/// marker-signed write landed early keeps its line in `feed-attest.log`
/// after the reclamation puts its position under the floor — the file is
/// primary state there, the entry signature's only copy at the origin —
/// where `commits.log` drops the position's entry.
#[test]
fn the_sidecar_compacts_to_the_journals_retention() {
    let dir = tempfile::tempdir().expect("tempdir");

    // Phase 1 — the daemon writes everything, so every position it will
    // later serve is one it recorded. Bulk inserts, because reclamation is
    // at SEGMENT granularity and a segment has to rotate before anything
    // below it can be reclaimed at all.
    let (early, head, signed_at, signed_attest) = {
        let sd = spawn(dir.path());
        let port = sd.port();
        let doc = seed_flow(port);
        let s1 = open_session(port, 1);
        let v = changes_ok(port, Some(&s1), "since=0");
        assert_eq!(entry_ats(&v), all_ats(), "the feed starts with every position");
        assert!(v["changes"][0]["op"].is_string(), "and with real metadata");
        // The signed write the reclamation will bury.
        let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
        let (signed_at, signed_attest) = signed_ghost_link(port, &signed, 1);
        rotate_a_segment(port, &s1, &doc);
        let (st, body) = get(port, "/health");
        assert_eq!(st, 200);
        let head = json(&body)["log_position"].as_u64().expect("log_position");
        let ats = entry_ats(&changes_ok(port, Some(&s1), "since=0"));
        assert_eq!(ats.last(), Some(&head), "the feed covers every position through the head");
        sd.shutdown();
        (ats, head, signed_at, signed_attest)
    };

    // Phase 2 — reclaim WITHOUT committing anything.
    reclaim_below_the_head(dir.path(), head);

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

    let s1 = open_session(port, 1);
    let (st, body) = changes_raw(port, Some(&s1), "since=0");
    assert_eq!(st, 410, "below the fence is the reclaimed discipline: {}", text(&body));
    let v = json(&body);
    assert_eq!(v["error"].as_str(), Some("history_reclaimed"));
    let floor = v["floor"].as_u64().expect("the refusal names the oldest surviving position");
    assert!(floor > early[0], "the fence advanced past the oldest recorded position");

    // THE ATTEST STORE KEEPS ITS LINE BELOW THE FLOOR, where `commits.log`
    // dropped the position's entry: the file is read as an operator reads
    // it, since no route serves a position below the floor.
    assert!(signed_at < floor, "the signed write lies below the floor: {signed_at} < {floor}");
    assert!(
        !contents.contains(&format!("{{\"at\":{signed_at},")),
        "commits.log compacted the signed write's entry away: {contents}"
    );
    let lines = attest_store_lines(dir.path());
    let (alg, sig) = lines.get(&signed_at).unwrap_or_else(|| {
        panic!("feed-attest.log KEEPS its line for position {signed_at} below the floor: {lines:?}")
    });
    assert_eq!(*alg, u64::from(FIXTURE_TAG), "the line carries the marker's tag");
    assert_eq!(sig, signed_attest["sig"].as_str().expect("sig"), "…and the blob's hex");
    // The fence is class-invariant — positions are (PUB-6.52): the guest
    // meets the same refusal with the same floor.
    let (st, guest) = changes_raw(port, None, "since=0");
    assert_eq!(st, 410);
    assert_eq!(json(&guest)["floor"].as_u64(), Some(floor), "one floor for every class");

    // At and above the fence the feed answers normally and still reaches
    // the head — compaction dropped what was unreachable and nothing else.
    let v = changes_ok(port, Some(&s1), &format!("since={}", floor - 1));
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

// ── the mirror's inputs (wire v7.11) ─────────────────────────────────────

/// THE FEED IS THE MIRROR'S WHOLE INPUT (wire v7.11; the design record
/// §7.3 (i), D12, D25, r6-2a): one end-to-end walk over the wire on a
/// claimed board, every kind of row the fence names —
///
/// * a signed-session `publish` presenting `attest`: its row carries
///   `attest` byte-equal to the request's (the `alg` token, the `sig` hex),
///   `placed` and `base_extent` exactly as `doc_metadata` serves them for
///   the member, and NO `key`;
/// * a signed-session `insert` presenting none: `key` the fingerprint, no
///   `attest`;
/// * a bare draft mint: `key: "bare"`; the head writer's rows: `key:
///   "system"`, the publish with its terms;
/// * a `delegate`: `new_prefix` and `new_id` equal to the ack's and to
///   `effective_owner`'s answer; a `make_link`: `link` equal to its
///   `ack_addr`;
/// * a credential record deposit above the claim (lane D's signed form):
///   BOTH rows without `key` and without `attest`; the ceremony's rows
///   below the claim: `key` served, no `attest` —
///
/// and the same page byte-identical across a restart (PUB-8.26) with every
/// new member.
#[test]
fn the_feed_is_the_mirrors_whole_input() {
    let dir = tempfile::tempdir().expect("tempdir");
    let before_restart: Vec<u8>;
    {
        let sd = spawn(dir.path());
        let port = sd.port();
        let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
        let device_fp = fingerprint_of(&device_key());
        let at = |e: &Value| e["at"].as_u64().expect("at");

        // A `delegate` from the bootstrap principal: the minted pair.
        let boot = open_session(port, 0);
        let prefix = next_prefix_under(port, Some(&boot), "1");
        let v = op(
            port,
            Some(&boot),
            &format!(r#"{{"op":"delegate","new_prefix":"{prefix}","new_id":1}}"#),
        );
        let (delegate_at, delegate_addr) = (acked_at(&v), acked_addr(&v));

        // A credential record deposit ABOVE the claim, lane D's signed form:
        // the hire of principal 1 — the record's atom, signed at the record
        // grade, then the enroll link the daemon verifies the `sig` at.
        let hire_from = head(port);
        let _agent = hire(port, &signed, CLAIMANT_DOC1, &prefix, 1, &distinct_key(1));
        let hire_rows = changes_ok(port, Some(&signed), &format!("since={hire_from}"))["changes"]
            .as_array()
            .expect("changes")
            .clone();
        assert_eq!(hire_rows.len(), 2, "the hire is two writes: {hire_rows:?}");

        // A signed `publish` presenting `attest` over doc 1's whole extent,
        // posted AS COMPOSED so the request's own member is in hand.
        let extent = content_extent(port, None, CLAIMANT_DOC1);
        let runs = shot_runs(port, Some(&signed), CLAIMANT_DOC1, 1, extent);
        let frame = publish_frame(CLAIMANT_DOC1, Some((CLAIMANT_DOC1, extent)), None, &runs);
        let sent: Value =
            serde_json::from_str(&attach_attest(port, &signed, &frame)).expect("a JSON frame");
        assert!(sent["attest"].is_object(), "the suite's signer signed the shot: {sent}");
        let v = op_unattested(port, Some(&signed), &sent.to_string());
        let (publish_at, member) = (acked_at(&v), acked_addr(&v));

        // A signed-session `insert` presenting none — a private draft's own
        // edit, and the draft's mint before it, both outside the checked set.
        let v = op_unattested(port, Some(&signed), &create_frame(CLAIMANT_ACCOUNT, None));
        let (draft_at, draft) = (acked_at(&v), acked_addr(&v));
        let v = op_unattested(port, Some(&signed), &insert_frame(&draft, 1, "x", false));
        let insert_at = acked_at(&v);

        // A bare draft mint, and a bare `make_link` into it.
        let bare = open_session(port, CLAIMANT_PRINCIPAL);
        let v = op(port, Some(&bare), &create_frame(CLAIMANT_ACCOUNT, None));
        let (bare_mint_at, bare_doc) = (acked_at(&v), acked_addr(&v));
        let v = op(
            port,
            Some(&bare),
            &link_frame(&bare_doc, r#"{"addrs":[]}"#, r#"{"addrs":[]}"#, &ghost_ty(&bare_doc, 1)),
        );
        let (link_at, link_addr) = (acked_at(&v), acked_addr(&v));

        // THE WALK, as the claimant — whose class sees every row above but
        // the system account's two private draft writes.
        let entries = all_entries(port, Some(&signed));
        let mut want_ats: Vec<u64> = CEREMONY_ATS.to_vec();
        want_ats.push(H1_PUBLISH_AT);
        want_ats.push(delegate_at);
        want_ats.extend(hire_rows.iter().map(at));
        want_ats.extend([publish_at, draft_at, insert_at, bare_mint_at, link_at]);
        assert_eq!(entries.iter().map(at).collect::<Vec<_>>(), want_ats);
        for e in &entries {
            assert_terms_by_op(e, "the walk");
        }
        // `attest` rides exactly one row, the shot's; `key` is absent on
        // exactly the signed rows — the shot's and the deposit's two.
        let attested: Vec<u64> =
            entries.iter().filter(|e| e.get("attest").is_some()).map(at).collect();
        assert_eq!(attested, vec![publish_at], "attest rides the marker-signed row alone");
        let mut signed_rows: Vec<u64> = hire_rows.iter().map(at).collect();
        signed_rows.push(publish_at);
        let keyless: Vec<u64> = entries.iter().filter(|e| e.get("key").is_none()).map(at).collect();
        assert_eq!(keyless, signed_rows, "key is absent on the signed rows and served on every other");

        // The signed publish.
        let e = entry_at(&entries, publish_at);
        assert_eq!(e["op"].as_str(), Some("publish"));
        assert_eq!(e["docs"], serde_json::json!([member]));
        assert_eq!(e["attest"], sent["attest"], "byte-equal to the request's: {e}");
        let md = doc_metadata(port, None, &member);
        assert_eq!(e["placed"], md["placed"], "the count, as the member read serves it: {e}");
        assert_eq!(e["base_extent"], md["base_extent"], "the base extent, as the member read serves it: {e}");
        assert_eq!(e["placed"].as_str(), Some(extent.to_string().as_str()), "Σ width of the runs");
        assert_eq!(e["base_extent"].as_str(), Some(extent.to_string().as_str()), "the extent the shot named");

        // The signed-session writes that presented none: the fingerprint.
        for (what, at_) in [("the draft's mint", draft_at), ("the draft's insert", insert_at)] {
            let e = entry_at(&entries, at_);
            assert_eq!(e["key"].as_str(), Some(device_fp.as_str()), "{what}: {e}");
            assert_absent(e, &["attest"], what);
        }

        // The bare session's writes.
        assert_eq!(entry_at(&entries, bare_mint_at)["key"].as_str(), Some("bare"));
        let e = entry_at(&entries, link_at);
        assert_eq!(e["key"].as_str(), Some("bare"));
        assert_eq!(e["link"].as_str(), Some(link_addr.as_str()), "the minted link, the ack's: {e}");

        // The head writer's row every class sees: `H.1`'s publish, with the
        // shot's terms as `doc_metadata` serves them for the member.
        let e = entry_at(&entries, H1_PUBLISH_AT);
        assert_eq!((e["key"].as_str(), e["op"].as_str()), (Some("system"), Some("publish")));
        let md = doc_metadata(port, None, HEAD_MEMBER_1);
        assert_eq!(e["placed"], md["placed"], "H.1's count: {e}");
        assert_eq!(e["base_extent"], md["base_extent"], "H.1's base extent: {e}");
        assert_absent(e, &["attest"], "the head writer's row");

        // The delegate: the pair is the ack's, and ω's.
        let e = entry_at(&entries, delegate_at);
        assert_eq!(e["new_prefix"].as_str(), Some(delegate_addr.as_str()));
        assert_eq!(delegate_addr, prefix, "the ack names the prefix the request asked");
        assert_eq!(e["new_id"].as_u64(), Some(1));
        assert_eq!(
            effective_owner(port, None, &prefix),
            Some((prefix.clone(), 1)),
            "ω at the head agrees with the row"
        );
        assert_eq!(e["key"].as_str(), Some("bare"));

        // The record deposit's two rows (D26; e-Q2): the atom's insert and
        // its credential link — one signature at the record grade, so
        // neither carries `key` nor `attest`; the link row names its link.
        let (atom_row, link_row) = (&hire_rows[0], &hire_rows[1]);
        assert_eq!(atom_row["op"].as_str(), Some("insert"), "{atom_row}");
        assert_eq!(atom_row["docs"], serde_json::json!([CLAIMANT_DOC1]));
        assert_eq!(link_row["op"].as_str(), Some("make_link"), "{link_row}");
        for (what, row) in [("the record's atom", atom_row), ("the record's link", link_row)] {
            assert_absent(row, &["key", "attest"], what);
            assert_terms_by_op(row, what);
        }
        assert!(
            link_row["link"].as_str().is_some_and(|l| l.starts_with(&format!("{CLAIMANT_DOC1}.0.2."))),
            "the enroll link, minted in the registry's link subspace: {link_row}"
        );

        // The ceremony's rows below the claim: `key` served, no `attest`.
        for at_ in CEREMONY_ATS {
            let e = entry_at(&entries, at_);
            assert!(e["key"].is_string(), "a ceremony row serves its key: {e}");
            assert_absent(e, &["attest"], "a ceremony row");
        }
        let e = entry_at(&entries, CEREMONY_ATS[0]);
        assert_eq!(
            (e["new_prefix"].as_str(), e["new_id"].as_u64()),
            (Some(CLAIMANT_ACCOUNT), Some(CLAIMANT_PRINCIPAL)),
            "the ceremony's delegate: {e}"
        );
        assert_eq!(
            entry_at(&entries, CEREMONY_ATS[2])["key"].as_str(),
            Some("bare"),
            "the genesis record's atom, unsigned below the claim, from a bare session"
        );
        assert!(entry_at(&entries, CEREMONY_ATS[3])["link"].is_string(), "the genesis link");
        let claim = entry_at(&entries, CLAIM_POSITION);
        assert_eq!(
            claim["key"].as_str(),
            Some(device_fp.as_str()),
            "the claim, from the signed device session, unjudged at the record grade: {claim}"
        );
        assert!(claim["link"].is_string(), "the claim link's address rides its row: {claim}");

        before_restart = changes_raw(port, Some(&bare), "since=0&limit=4096").1;
        sd.shutdown();
    }

    // DETERMINISM PER CLASS across a restart (PUB-8.26), every member included.
    let sd = spawn(dir.path());
    let port = sd.port();
    let bare = open_session(port, CLAIMANT_PRINCIPAL);
    assert_eq!(
        changes_raw(port, Some(&bare), "since=0&limit=4096").1,
        before_restart,
        "the same query answers byte-identically across a restart"
    );
    sd.shutdown();
}

/// Π FROM THE FEED ALONE (AUTH-6.36 consumer (1); r6-2a, m3): a walk of
/// `/changes` from the floor, paging, taking every `delegate` row's pair,
/// equals `effective_owner`'s answer for every minted prefix at the head —
/// the mirror recipe's ω derivation from the board's own records, never the
/// node registry.
#[test]
fn pi_from_the_feed_alone_is_effective_owners_answer_for_every_minted_prefix() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let boot = open_session(port, 0);
    let (a, s_a) = delegate_under(port, &boot, "1", 1);
    let (b, _) = delegate_under(port, &boot, "1", 2);
    let (a1, _) = delegate_under(port, &s_a, &a, 3);

    // THE MIRROR RECIPE: page from the floor, `delegate` rows alone.
    let mut pi: BTreeMap<String, u64> = BTreeMap::new();
    let mut since = 0;
    loop {
        let page = changes_ok(port, None, &format!("since={since}&limit=3"));
        for e in page["changes"].as_array().expect("changes") {
            if e["op"].as_str() == Some("delegate") {
                let prefix = e["new_prefix"].as_str().expect("a delegate row names its prefix");
                let id = e["new_id"].as_u64().expect("…and the principal it seated");
                assert!(pi.insert(prefix.to_string(), id).is_none(), "one row per mint: {e}");
            }
        }
        if !page["more"].as_bool().expect("more") {
            break;
        }
        since = page["last"].as_u64().expect("last");
    }
    let want: BTreeMap<String, u64> =
        [(CLAIMANT_ACCOUNT.to_string(), CLAIMANT_PRINCIPAL), (a.clone(), 1), (b.clone(), 2), (a1.clone(), 3)]
            .into_iter()
            .collect();
    assert_eq!(pi, want, "Π off the feed is every account the board minted, with its principal");
    for (prefix, id) in &pi {
        assert_eq!(
            effective_owner(port, None, prefix),
            Some((prefix.clone(), *id)),
            "ω at the head agrees with the feed's pair for {prefix}"
        );
    }
    // ω over an address BENEATH a prefix is the longest of Π's prefixes —
    // the derivation a mirror makes from these rows, checked against the
    // board's own: a document under A.1 is A.1's, not A's.
    assert_eq!(effective_owner(port, None, &format!("{a1}.0.1")), Some((a1.clone(), 3)));
    assert_eq!(effective_owner(port, None, &format!("{a}.0.9")), Some((a.clone(), 1)));
    sd.shutdown();
}

/// THE BOUNDARY FROM THE FEED ALONE (the design record §5.2's owed read):
/// the claim link's address, as `find_links` answers it, equals the `link`
/// of exactly one `make_link` row, whose `at` is the claim's position —
/// `H.1`'s own — so a reader maps the link to its commit position off the
/// feed, with no `H.1` to name it.
#[test]
fn the_claim_boundary_is_read_off_the_feed_alone() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let claim_at = board_term(port).expect("H.1").log_position;
    assert_eq!(claim_at, CLAIM_POSITION);

    let claims = addrs_of(&op(port, None, &class_scan_frame("find_links_ftt", T_CLAIM)));
    assert_eq!(claims.len(), 1, "one claim link on the board: {claims:?}");
    let entries = all_entries(port, None);
    let rows: Vec<&Value> = entries
        .iter()
        .filter(|e| e["op"].as_str() == Some("make_link"))
        .filter(|e| e["link"].as_str() == Some(claims[0].as_str()))
        .collect();
    assert_eq!(rows.len(), 1, "exactly one make_link row names the claim link: {entries:?}");
    assert_eq!(rows[0]["at"].as_u64(), Some(claim_at), "…at the claim's position: {}", rows[0]);
    sd.shutdown();
}

/// ABSENCE IS A VERDICT, SO THE STORE IS HONEST — above the floor: a lost or
/// torn `feed-attest.log` is rebuilt at open from the journal's markers
/// (`Kernel::attestation_at`) and the feed serves the SAME `attest` bytes;
/// with `commits.log` lost beside it, the rows come back bare and the slot
/// rides the bare row — the journal's own fact beside the lost testimony.
#[test]
fn a_lost_or_torn_attest_store_is_rebuilt_from_the_journal_and_serves_the_same_bytes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = dir.path().join("feed-attest.log");
    let (before, signed_ats, attests) = {
        let sd = spawn(dir.path());
        let port = sd.port();
        let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
        let (a1, attest1) = signed_ghost_link(port, &signed, 1);
        let (a2, attest2) = signed_ghost_link(port, &signed, 2);
        let bare = open_session(port, CLAIMANT_PRINCIPAL);
        expect_resp(&op(port, Some(&bare), &create_frame(CLAIMANT_ACCOUNT, None)), "ack_addr");
        let before = changes_raw(port, Some(&bare), "since=0&limit=4096").1;
        // The store's own lines: `{"alg":T,"at":N,"sig":"<hex>"}`, one per
        // attested position, the tag and the blob as the marker holds them.
        let lines = attest_store_lines(dir.path());
        assert_eq!(lines.keys().copied().collect::<Vec<_>>(), vec![a1, a2]);
        for (at, attest) in [(a1, &attest1), (a2, &attest2)] {
            let (alg, sig) = &lines[&at];
            assert_eq!(*alg, u64::from(FIXTURE_TAG));
            assert_eq!(sig, attest["sig"].as_str().expect("sig"));
            let slot = sd.daemon().attestation_at(Seq(at)).expect("a boundary").expect("filled");
            assert_eq!(*sig, hex(slot.sig()), "the line mirrors the marker");
        }
        sd.shutdown();
        (before, vec![a1, a2], vec![attest1, attest2])
    };
    let judge = |ctx: &str| {
        let sd = spawn(dir.path());
        let port = sd.port();
        let bare = open_session(port, CLAIMANT_PRINCIPAL);
        assert_eq!(
            changes_raw(port, Some(&bare), "since=0&limit=4096").1,
            before,
            "{ctx}: the feed serves the same bytes, attest included"
        );
        assert_eq!(
            attest_store_lines(dir.path()).keys().copied().collect::<Vec<_>>(),
            signed_ats,
            "{ctx}: the store is rebuilt whole"
        );
        sd.shutdown();
    };
    // Deleted after commit: rebuilt from the journal.
    std::fs::remove_file(&store).expect("lose the store");
    judge("the store deleted");
    // Torn: the last line cut into, truncated at open, its position re-derived.
    let len = std::fs::metadata(&store).expect("metadata").len();
    let fh = std::fs::OpenOptions::new().write(true).open(&store).expect("open");
    fh.set_len(len.saturating_sub(37)).expect("tear the tail");
    drop(fh);
    judge("the store torn");
    // The testimony gone too: bare rows, the slot riding them.
    std::fs::remove_file(dir.path().join("commits.log")).expect("lose the testimony");
    std::fs::remove_file(&store).expect("lose the store");
    let sd = spawn(dir.path());
    let port = sd.port();
    let bare = open_session(port, CLAIMANT_PRINCIPAL);
    let entries = all_entries(port, Some(&bare));
    for (at, attest) in signed_ats.iter().zip(&attests) {
        let e = entry_at(&entries, *at);
        assert!(e["op"].is_null() && e["key"].is_null(), "a bare row: {e}");
        assert_eq!(e["attest"], *attest, "the slot is the journal's fact, served on the bare row: {e}");
    }
    for e in entries.iter().filter(|e| !signed_ats.contains(&e["at"].as_u64().expect("at"))) {
        assert_absent(e, &["attest"], "a bare row whose marker is empty");
    }
    sd.shutdown();
}

/// ABSENCE IS A VERDICT — at and below the floor (BW-01): after a
/// reclamation drops `commits.log`'s entries below the floor,
/// `feed-attest.log` still holds its line there (the file read directly:
/// no route serves a below-floor position, e-Q1), and the row AT the floor
/// — whose marker the journal refuses `Reclaimed`, the segment holding it
/// gone — serves its slot off the kept line; with the line lost, that row
/// renders `attest: null`, LOST, never absent, and still no `key`.
#[test]
fn the_attest_store_keeps_below_the_floor_and_serves_a_lost_slot_at_the_floor_as_null() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = dir.path().join("feed-attest.log");
    let (early_at, last_at, last_attest) = {
        let sd = spawn(dir.path());
        let port = sd.port();
        let doc = seed_flow(port);
        let s1 = open_session(port, 1);
        let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
        let (early_at, _) = signed_ghost_link(port, &signed, 1);
        rotate_a_segment(port, &s1, &doc);
        let (last_at, last_attest) = signed_ghost_link(port, &signed, 2);
        assert_eq!(last_at, head(port), "the signed write is the head");
        sd.shutdown();
        (early_at, last_at, last_attest)
    };
    reclaim_below_the_head(dir.path(), last_at);

    // The store kept: the line below the floor survives in the file, and
    // the row at the floor serves its slot off the kept line.
    {
        let sd = spawn(dir.path());
        let port = sd.port();
        let bare = open_session(port, CLAIMANT_PRINCIPAL);
        let (st, body) = changes_raw(port, Some(&bare), "since=0");
        assert_eq!(st, 410, "{}", text(&body));
        let floor = json(&body)["floor"].as_u64().expect("floor");
        assert_eq!(floor, last_at, "the floor is the checkpoint's own position, the head");
        assert!(early_at < floor);
        let commits = std::fs::read_to_string(dir.path().join("commits.log")).expect("commits.log");
        assert!(
            !commits.contains(&format!("{{\"at\":{early_at},")),
            "commits.log dropped the early signed write's entry: {commits}"
        );
        let lines = attest_store_lines(dir.path());
        assert!(lines.contains_key(&early_at), "the store KEEPS its line below the floor: {lines:?}");
        assert!(lines.contains_key(&last_at), "…and the line at the floor: {lines:?}");
        assert!(
            matches!(sd.daemon().attestation_at(Seq(last_at)), Err(skepd::HistoryError::Reclaimed { .. })),
            "the journal refuses the marker at the floor: its segment is reclaimed"
        );
        let page = changes_ok(port, Some(&bare), &format!("since={}", floor - 1));
        let e = entry_at(page["changes"].as_array().expect("changes"), last_at);
        assert_eq!(e["attest"], last_attest, "the row at the floor serves its slot off the kept line: {e}");
        assert_absent(e, &["key"], "a signed row");
        sd.shutdown();
    }
    // The store lost: the journal refuses the slot, nothing is rebuilt, and
    // the row — recorded signed — renders LOST.
    {
        std::fs::remove_file(&store).expect("lose the store");
        let sd = spawn(dir.path());
        let port = sd.port();
        let bare = open_session(port, CLAIMANT_PRINCIPAL);
        let page = changes_ok(port, Some(&bare), &format!("since={}", last_at - 1));
        let e = entry_at(page["changes"].as_array().expect("changes"), last_at);
        assert!(
            e.get("attest").is_some_and(Value::is_null),
            "recorded signed, the store silent, the journal refusing: attest is null — LOST, never absent: {e}"
        );
        assert_absent(e, &["key"], "the entry IS signed; only its hand is out of reach");
        assert!(attest_store_lines(dir.path()).is_empty(), "nothing was rebuilt: the journal refused the slot");
        sd.shutdown();
    }
}

/// D12 ON A RECORD DEPOSIT'S TWO ROWS (e-Q2): the atom's `insert` and the
/// credential `make_link` that names it — one signature at the record
/// grade, the record's own `sig` — carry neither `key` nor `attest`; and a
/// record deposited ABOVE the claim carrying NO `sig` keeps its atom's
/// `key` (the entry carries no signature anywhere) while its link is refused
/// `attestation_required` (lane D), the atom an orphan no link names.
#[test]
fn a_record_deposits_two_rows_carry_neither_key_nor_attest_and_a_sig_less_atom_keeps_its_key() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let device_fp = fingerprint_of(&device_key());
    let boot = open_session(port, 0);
    let (a, _) = delegate_under(port, &boot, "1", 1);

    let from = head(port);
    hire(port, &signed, CLAIMANT_DOC1, &a, 1, &distinct_key(1));
    let rows = changes_ok(port, Some(&signed), &format!("since={from}"))["changes"]
        .as_array()
        .expect("changes")
        .clone();
    assert_eq!(rows.len(), 2, "the atom's insert and its link: {rows:?}");
    assert_eq!((rows[0]["op"].as_str(), rows[1]["op"].as_str()), (Some("insert"), Some("make_link")));
    for row in &rows {
        assert_absent(row, &["key", "attest"], "a record deposit's row");
        assert_terms_by_op(row, "a record deposit's row");
    }

    // The sig-less record: its atom lands (the insert's check demands no
    // `attest` of a record deposit, D26), testifying the session's key.
    let (b, _) = delegate_under(port, &boot, "1", 2);
    let ordinal = next_content_ordinal(port, Some(&signed), CLAIMANT_DOC1);
    let atom = enroll_atom(&[&distinct_key(2)]);
    let (ack, e) = feed_entry(
        port,
        &signed,
        "a sig-less record's atom",
        &format!(
            r#"{{"op":"insert","doc":"{CLAIMANT_DOC1}","at":{{"subspace":"1","ordinal":"{ordinal}"}},"values":[{{"atom":{atom}}}],"deposit":"{T_ENROLL}"}}"#
        ),
    );
    assert_eq!(
        e["key"].as_str(),
        Some(device_fp.as_str()),
        "a record carrying no sig is an unsigned entry: its key is served: {e}"
    );
    assert_absent(&e, &["attest"], "a record deposit's atom");
    let v = typed_link(port, &signed, CLAIMANT_DOC1, &[&acked_addr(&ack)], &[&b], T_ENROLL);
    assert_eq!(verdict(&v), "credential_refused:attestation_required", "{v}");
    sd.shutdown();
}
