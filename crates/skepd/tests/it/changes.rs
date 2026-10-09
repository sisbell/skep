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
//! r6-2a) each row also carries THE MIRROR'S INPUTS — its `attest` off the
//! marker-mirroring attest store, `key` only on unsigned rows, and its op's
//! own terms. Their per-row shape is pinned here beside the rest of the
//! entry's (the testimony and affected-docs cells); the cells that read the
//! feed as the mirror's WHOLE input, and the attest store's crash honesty,
//! are the child `mirror` — all but the store's cells against the
//! reclamation (SO-I5 (d)) — its crash test, its sync, its halt — which
//! stand here beside the compaction cell whose helpers they share. What more
//! than one family uses — the seeded flow, the feed readers, the per-kind
//! term checks, the reclaim helpers — lives here.

use crate::common;

use std::collections::BTreeMap;
use std::path::Path;

use common::*;
use serde_json::Value;
use skepd::Seq;

mod mirror;

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

/// THE PAGE BYTE BUDGET (SO-I9 — nobody's request does unbounded work; round
/// 7's bu7-2 = reg-H1; P29): a page whose entries would marshal past
/// `MAX_CHANGES_PAGE_BYTES` (2 MiB: 256 rows × 8 KiB) is REFUSED whole —
/// 400 `malformed_changes`, the face carrying `budget` and `fits`, the
/// largest `limit` whose page from that `since` fits — never served short
/// (PUB-6.44). Over three hundred attested grants, each row ~6.9 KB of
/// `attest` hex under tag 1: the maximal `limit` is refused, `limit=fits` is
/// served whole with `more`, one past it is refused again, and the DEFAULT
/// page of attested rows is served whole. The determinism-per-class test
/// beside it is unmoved: a page under the budget is the page it was.
#[test]
fn a_page_past_the_byte_budget_is_refused_whole_and_one_within_it_is_served_whole() {
    const BUDGET: u64 = 256 * 8 * 1024;
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let grant = typed_link_frame(CLAIMANT_DOC1, &[CLAIMANT_ACCOUNT], &[], T_GRANT);
    for _ in 0..320 {
        expect_resp(&op(port, Some(&signed), &grant), "ack_addr");
    }
    let (st, body) = changes_raw(port, None, "since=0&limit=4096");
    assert_eq!(st, 400, "the maximal page of attested rows passes the budget: {}", text(&body));
    let face = json(&body);
    assert_eq!(face["error"].as_str(), Some("malformed_changes"), "{face}");
    assert_eq!(face["budget"].as_u64(), Some(BUDGET), "the face names the budget: {face}");
    let fits = face["fits"].as_u64().expect("the face names the largest limit that fits");
    assert!((256..320).contains(&fits), "~300 rows of ~6.9 KB fit 2 MiB: {fits}");
    assert!(face["detail"].as_str().is_some_and(|d| d.contains(&BUDGET.to_string()) && d.contains(&fits.to_string())), "{face}");

    let v = changes_ok(port, None, &format!("since=0&limit={fits}"));
    assert_eq!(entry_ats(&v).len() as u64, fits, "limit=fits: the page served whole");
    assert_eq!(v["more"].as_bool(), Some(true), "…with more past it");
    let (st, body) = changes_raw(port, None, &format!("since=0&limit={}", fits + 1));
    assert_eq!(st, 400, "one row more passes the budget: {}", text(&body));
    assert_eq!(json(&body)["fits"].as_u64(), Some(fits), "the same answer");
    let v = changes_ok(port, None, "since=0");
    assert_eq!(entry_ats(&v).len(), 256, "the default page of attested rows is served whole");
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

/// `/health`'s `writes.halted` (wire.md §The other endpoints): whether the
/// daemon refuses every write until a restart.
fn writes_halted(port: u16) -> bool {
    let (st, body) = get(port, "/health");
    assert_eq!(st, 200, "/health: {}", String::from_utf8_lossy(&body));
    json(&body)["writes"]["halted"].as_bool().expect("writes.halted")
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
    let ack = op_as_written(port, Some(token), frame);
    assert!(ack["at"].is_u64(), "{what} must commit: {ack}");
    (ack, one_entry_since(port, token, what, before))
}

fn one_entry_since(port: u16, token: &str, what: &str, before: u64) -> Value {
    let page = changes_ok(port, Some(token), &format!("since={before}"));
    let entries = page["changes"].as_array().expect("changes");
    assert_eq!(entries.len(), 1, "{what}: one write, one entry: {page}");
    entries[0].clone()
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
            tail["docs"].is_null() && tail["time"].is_null() && tail["key"].is_null(),
            "a lost record answers null in EVERY testimony field, `key` included: the \
             null is RESERVED for lost testimony, and `\"bare\"` is a positive claim \
             that this write was unsigned — one nobody made about it: {tail}"
        );
        // …while the op's own terms are THE JOURNAL'S (round 7's as7-F3): the
        // lost record was a `make_link`, and the one link the commit
        // deposited is the journal's own fact — served as `link`, equal to
        // the recorded row's, the op left null (a plain `make_link` and an
        // `emit` deposit one link alike) and the members no link write
        // carries absent, as on the recorded row. Nothing is invented.
        let old: Value = serde_json::from_slice(&before).expect("json");
        let recorded_tail = old["changes"].as_array().expect("changes").last().expect("the lost record");
        assert!(tail["op"].is_null(), "a plain make_link's op is not the journal's to name: {tail}");
        assert_eq!(tail["link"], recorded_tail["link"], "the bare row's `link` is the journal's: {tail}");
        for term in TERMS.iter().filter(|t| **t != "link") {
            assert!(tail.get(term).is_none(), "a bare link row carries no `{term}`: {tail}");
        }
        assert_absent(tail, &["attest"], "a bare row whose marker was empty");
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
        let febe = OperationSurface::new(Box::new(engine.stores()), std::num::NonZeroUsize::MIN);
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
/// complete, and the reclaim floor lands AT the head.
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

/// The five feed files' positions as an operator reads them off the data
/// dir: for each, the `at` of every entry line, and `commits.log`'s
/// `min_since` fence and the four derived files' `covered` fence.
fn feed_files_positions(dir: &Path) -> BTreeMap<&'static str, (Vec<u64>, Option<u64>)> {
    [
        "commits.log",
        "feed-index.log",
        "feed-offsets.log",
        "feed-masked.log",
        "feed-streams.log",
    ]
    .into_iter()
    .map(|name| {
        let text = std::fs::read_to_string(dir.join(name)).unwrap_or_else(|e| panic!("{name}: {e}"));
        let (mut ats, mut fence) = (Vec::new(), None);
        for line in text.lines() {
            let v: Value = serde_json::from_str(line).unwrap_or_else(|e| panic!("{name}: {line}: {e}"));
            if let Some(at) = v.get("at").and_then(Value::as_u64) {
                ats.push(at);
            }
            if let Some(f) = v.get("min_since").or_else(|| v.get("covered")).and_then(Value::as_u64) {
                fence = Some(f);
            }
        }
        (name, (ats, fence))
    })
    .collect()
}

/// One small committing write as `session` into `doc` — a one-byte prepend —
/// answering its position.
fn small_commit(port: u16, session: &str, doc: &str) -> u64 {
    let v = op(
        port,
        Some(session),
        &format!(r#"{{"op":"insert","doc":"{doc}","at":{{"subspace":"1","ordinal":"1"}},"values":["q"]}}"#),
    );
    acked_at(&v)
}

/// COMPACTION AT THE CHECKPOINT, WHILE SERVING (jw-R3 (i); M-I5 (f); P22):
/// the reclaim floor moves at a checkpoint and at no other moment, so the
/// checkpoint thread compacts the five feed files after each landing — the
/// SAME rewrite the open runs, mid-uptime, under the feed's lock. A board
/// whose journal has rotated past a segment: the thread's act (through its
/// seam, on this thread) lands the checkpoint, the journal reclaims the
/// closed segment below it, and `commits.log` and the four derived files
/// shrink to the retained window — the open's own assertions, now with the
/// daemon serving: the fence recorded, no entry at or below it, the derived
/// files fenced at the head — while the attest store keeps its line below
/// the floor. The feed refuses below the fence with the floor and serves
/// from it to the head; a commit after the compaction lands in the
/// rewritten files, which are whole and take it.
#[test]
fn the_checkpoint_threads_landing_compacts_the_five_feed_files_while_serving() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let doc = seed_flow(port);
    let s1 = open_session(port, 1);
    let early = entry_ats(&changes_ok(port, Some(&s1), "since=0"));
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let (signed_at, signed_attest) = signed_ghost_link(port, &signed, 1);
    rotate_a_segment(port, &s1, &doc);
    let head = head(port);
    assert!(sd.daemon().newest_checkpoint().is_none(), "no checkpoint yet");
    let before = feed_files_positions(dir.path());
    assert!(before["commits.log"].0.contains(&early[0]), "the oldest position is recorded");
    // The seeded insert names a document, so the index file holds it (the
    // ceremony's delegate at `early[0]` names none and never enters it).
    assert!(before["feed-index.log"].0.contains(&SEEDED_ATS[3]));

    // THE THREAD's ACT: the checkpoint lands at the head, reclaims the
    // closed segments below it, and the compaction follows.
    sd.daemon().service_the_checkpoint_now();
    let newest = sd.daemon().newest_checkpoint().expect("the thread's checkpoint landed");
    assert_eq!(newest.seq.0, head, "at the head, no commit between");
    assert!(sd.daemon().stopped_feed_files().is_empty(), "every file took its rewrite");

    let after = feed_files_positions(dir.path());
    let (ref ats, fence) = after["commits.log"];
    let fence = fence.expect("compaction records the fence it compacted to");
    assert!(fence >= early[0], "the fence advanced past the oldest recorded position");
    assert!(ats.iter().all(|&at| at > fence), "no entry at or below the fence: {ats:?}");
    assert!(ats.contains(&head), "the head's entry survives: {ats:?}");
    for name in ["feed-index.log", "feed-offsets.log", "feed-masked.log", "feed-streams.log"] {
        let (ref ats, covered) = after[name];
        assert!(ats.iter().all(|&at| at > fence), "{name}: no entry at or below the fence: {ats:?}");
        assert_eq!(covered, Some(head), "{name}: fenced at the head after the rewrite");
    }
    assert_eq!(after["feed-offsets.log"].0, after["commits.log"].0, "one position set, the log's");
    // THE ATTEST STORE keeps its line below the floor (BW-01): primary there.
    assert!(signed_at <= fence, "the signed write lies below the fence: {signed_at} <= {fence}");
    let lines = attest_store_lines(dir.path());
    let (_, sig) = lines
        .get(&signed_at)
        .unwrap_or_else(|| panic!("feed-attest.log keeps position {signed_at}'s line: {lines:?}"));
    assert_eq!(sig, signed_attest["sig"].as_str().expect("sig"));

    // The feed refuses below the fence with the floor and serves from it.
    let (st, body) = changes_raw(port, Some(&s1), "since=0");
    assert_eq!(st, 410, "below the fence: {}", text(&body));
    let floor = json(&body)["floor"].as_u64().expect("the floor");
    assert_eq!(floor, fence + 1, "the floor is the first position above the fence");
    let v = changes_ok(port, Some(&s1), &format!("since={fence}"));
    assert_eq!(entry_ats(&v).first(), Some(&floor));
    assert_eq!(entry_ats(&v).last(), Some(&head));
    // A commit after the compaction lands in the rewritten files (the head
    // writer's own commits may follow it: the landed checkpoint is a base
    // the next head names, trigger (b)).
    let at = small_commit(port, &s1, &doc);
    let later = feed_files_positions(dir.path());
    assert!(later["commits.log"].0.contains(&at), "the rewritten log takes the next line");
    assert!(later["feed-offsets.log"].0.contains(&at), "…and so does each derived file");
    assert!(later["feed-index.log"].0.contains(&at));
    let served = entry_ats(&changes_ok(port, Some(&s1), &format!("since={head}")));
    assert_eq!(served.first(), Some(&at), "served: {served:?}");
    assert!(sd.daemon().stopped_feed_files().is_empty());

    // Nothing lies below the floor now, so a second landing compacts nothing
    // and the files stand.
    sd.daemon().service_the_checkpoint_now();
    assert_eq!(feed_files_positions(dir.path()), later, "no segment was reclaimed: nothing moved");
    sd.shutdown();
}

/// THE STOP, carried into the compaction's rewrite (jw-R3 (i); P22; the
/// settled disposition for `record`: reported, never failing an op): a
/// rewrite that fails PAST its rename — the new file in place, the handle
/// naming the replaced one — STOPS its file for the uptime, said once, and
/// the next append is a no-op; the write it followed is acked and served
/// this uptime from the resident entries; the next open re-derives the
/// unrecorded position as a bare entry. Driven through the seam that refuses
/// the reopen of each of the five files.
#[test]
fn a_feed_rewrite_failed_past_its_rename_stops_the_file_and_fails_no_op() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let doc = seed_flow(port);
    let s1 = open_session(port, 1);
    rotate_a_segment(port, &s1, &doc);
    let head = head(port);
    sd.daemon().fail_the_feeds_next_rewrite_past_rename();
    sd.daemon().service_the_checkpoint_now();
    assert_eq!(sd.daemon().newest_checkpoint().map(|h| h.seq.0), Some(head), "the checkpoint landed");
    assert_eq!(
        sd.daemon().stopped_feed_files(),
        vec!["commits.log", "feed-index.log", "feed-offsets.log", "feed-masked.log", "feed-streams.log"],
        "each file's rewrite failed past its rename: every one is stopped"
    );
    // The rewritten files are whole and in place: the fence recorded, the
    // positions trimmed.
    let after = feed_files_positions(dir.path());
    let fence = after["commits.log"].1.expect("the rewritten file carries the fence");
    assert!(after["commits.log"].0.iter().all(|&at| at > fence));
    let lengths: BTreeMap<&str, u64> = after
        .keys()
        .map(|name| (*name, std::fs::metadata(dir.path().join(name)).unwrap().len()))
        .collect();

    // THE NEXT APPEND IS A NO-OP on every stopped file, and the write it
    // followed is acked and served this uptime.
    let at = small_commit(port, &s1, &doc);
    for (name, len) in &lengths {
        assert_eq!(
            std::fs::metadata(dir.path().join(name)).unwrap().len(),
            *len,
            "{name}: a stopped file takes no line"
        );
    }
    // Served this uptime from the resident entries, with full testimony —
    // the head writer's own commits may follow it (trigger (b), the landed
    // base), each a stopped file took no line of either.
    let v = changes_ok(port, Some(&s1), &format!("since={head}"));
    assert_eq!(entry_ats(&v).first(), Some(&at), "the write is served this uptime: {v}");
    assert!(v["changes"][0]["op"].is_string(), "with full testimony: {v}");
    sd.shutdown();

    // THE NEXT OPEN re-derives: the unrecorded position is a bare entry, and
    // the files take lines again.
    let sd = spawn(dir.path());
    let port = sd.port();
    let s1 = open_session(port, 1);
    let v = changes_ok(port, Some(&s1), &format!("since={head}"));
    let entries = v["changes"].as_array().expect("changes");
    assert!(entries.iter().any(|e| e["at"].as_u64() == Some(at)), "re-derived: {v}");
    let bare = entries.iter().find(|e| e["at"].as_u64() == Some(at)).unwrap();
    assert!(bare["docs"].is_null() && bare["time"].is_null(), "bare, never invented: {bare}");
    assert!(sd.daemon().stopped_feed_files().is_empty(), "a fresh open stops nothing");
    let again = small_commit(port, &s1, &doc);
    assert!(feed_files_positions(dir.path())["commits.log"].0.contains(&again));
    sd.shutdown();
}

/// The crash child's environment: its data dir, and the point it is killed
/// after — `append`, the signed write acked, or `checkpoint`, the reclaiming
/// checkpoint returned. Set by the parent alone; their presence IS child mode.
const RECLAIM_CRASH_DIR: &str = "SKEP_CHANGES_RECLAIM_CRASH_DIR";
const RECLAIM_CRASH_AFTER: &str = "SKEP_CHANGES_RECLAIM_CRASH_AFTER";

/// The child's lines on stderr: `attested <at> <tag> <hex>` per attested
/// position, `doc <addr>`, `signed <at>`, then `held`, each after this.
const RECLAIM_CRASH_LINE: &str = "reclaim-crash:";

/// What a killed child reported: every attested position's slot, read off
/// the journal before any checkpoint (`position → (tag, sig hex)`, the
/// shape [`attest_store_lines`] reads the store in), the seeded flow's
/// private document, and the signed write's position.
struct Crash {
    oracle: BTreeMap<u64, (u64, String)>,
    doc: String,
    signed_at: u64,
}

/// The store's line for `at` is the journal's slot, compared whole and
/// named in brief — its tag, and its blob's length and first bytes — so a
/// failure does not print a whole signature.
fn assert_line(lines: &BTreeMap<u64, (u64, String)>, crash: &Crash, at: u64, what: &str) {
    let brief = |line: Option<&(u64, String)>| match line {
        Some((tag, sig)) => {
            format!("tag {tag}, {} hex from {}", sig.len(), &sig[..sig.len().min(16)])
        }
        None => "no line".to_string(),
    };
    let (held, slot) = (lines.get(&at), crash.oracle.get(&at));
    assert!(
        held == slot,
        "{what}: the store holds {} where the journal's slot is {}",
        brief(held),
        brief(slot)
    );
}

/// The journal's segment files in `dir` (`seg-<first seq>.wal`).
fn segment_files(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut segs: Vec<_> = std::fs::read_dir(dir)
        .expect("read the journal directory")
        .map(|e| e.expect("a directory entry").path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("seg-") && n.ends_with(".wal"))
        })
        .collect();
    segs.sort();
    segs
}

/// `src`'s tree copied to `dst`, so one killed board serves the boundaries
/// that share its crash.
fn copy_tree(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).expect("create the copy");
    for entry in std::fs::read_dir(src).expect("read the crashed board") {
        let entry = entry.expect("a directory entry");
        let to = dst.join(entry.file_name());
        if entry.file_type().expect("a file type").is_dir() {
            copy_tree(&entry.path(), &to);
        } else {
            std::fs::copy(entry.path(), &to).expect("copy a file");
        }
    }
}

/// Cut `path`'s lines for position `at` off its end — what a record step
/// killed before it reached the file had not written. Each must be the
/// file's last, as a crash leaves it: a truncation, never a hole.
fn cut_trailing_position(path: &Path, at: u64) {
    let text = std::fs::read_to_string(path).expect("a feed file");
    let of = |line: &str| serde_json::from_str::<Value>(line).ok()?.get("at")?.as_u64();
    let mut lines: Vec<&str> = text.lines().collect();
    while lines.last().is_some_and(|&l| of(l) == Some(at)) {
        lines.pop();
    }
    assert!(
        lines.iter().all(|&l| of(l) != Some(at)),
        "{}: position {at}'s line is not the file's last",
        path.display()
    );
    let kept: String = lines.iter().map(|l| format!("{l}\n")).collect();
    std::fs::write(path, kept).expect("cut the file");
}

/// The crash child: a claimed board served in-process, the seeded flow and
/// one signed write from the claimant's device session — the head, no head
/// owed after it — then every attested position's slot reported off the
/// journal. Killed `after` the `checkpoint`, it first rotates a segment and
/// copies the segment files aside, then takes the board's FIRST checkpoint,
/// which retains itself alone and so unlinks every closed segment below it,
/// the signed write's among them. Then it parks for the parent's SIGKILL.
/// Never returns.
fn reclaim_crash_child(dir: &Path, after: &str) -> ! {
    let sd = spawn(dir);
    let port = sd.port();
    let doc = seed_flow(port);
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let (signed_at, _) = signed_ghost_link(port, &signed, 1);
    assert_eq!(signed_at, head(port), "the signed write is the head");
    for at in 1..=signed_at {
        if let Ok(Some(slot)) = sd.daemon().attestation_at(Seq(at)) {
            eprintln!("{RECLAIM_CRASH_LINE} attested {at} {} {}", slot.sig_alg(), hex(slot.sig()));
        }
    }
    if after == "checkpoint" {
        rotate_a_segment(port, &open_session(port, 1), &doc);
        let aside = dir.parent().expect("the data dir's parent").join("segments-aside");
        std::fs::create_dir_all(&aside).expect("the aside directory");
        for seg in segment_files(dir) {
            std::fs::copy(&seg, aside.join(seg.file_name().expect("a name")))
                .expect("copy a segment aside");
        }
        sd.daemon().checkpoint_now();
    }
    eprintln!("{RECLAIM_CRASH_LINE} doc {doc}");
    eprintln!("{RECLAIM_CRASH_LINE} signed {signed_at}");
    eprintln!("{RECLAIM_CRASH_LINE} held");
    loop {
        std::thread::park();
    }
}

/// The crash child, SIGKILLed however the parent leaves the scope that holds
/// it — a panic included — so no parked board outlives its test.
struct KilledOnDrop(std::process::Child);

impl Drop for KilledOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Run the crash child to its hold `after` the named point and SIGKILL it
/// there: the board it leaves, under `data/` (and `segments-aside/`) in the
/// directory answered, and what it reported.
fn kill_reclaim_crash_child(after: &str) -> (tempfile::TempDir, Crash) {
    use std::io::{BufRead, BufReader};
    use std::process::{Command, Stdio};
    use std::sync::mpsc;
    use std::time::Duration;

    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path().join("data");
    std::fs::create_dir_all(&dir).expect("data dir");
    let exe = std::env::current_exe().expect("test binary path");
    let mut child = KilledOnDrop(
        Command::new(exe)
            .args([
                "changes::a_kill_at_each_boundary_keeps_every_signature_below_the_floor",
                "--exact",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(RECLAIM_CRASH_DIR, &dir)
            .env(RECLAIM_CRASH_AFTER, after)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn the crash child"),
    );
    let stderr = child.0.stderr.take().expect("child stderr");
    let (tx, rx) = mpsc::channel::<String>();
    let tag = after.to_string();
    let reader = std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines() {
            let Ok(line) = line else { break };
            match line.strip_prefix(RECLAIM_CRASH_LINE) {
                Some(said) => {
                    let _ = tx.send(said.trim().to_string());
                }
                // The child's other notices, and a failing child's panic
                // message, land in this test's own output.
                None => eprintln!("[reclaim-crash child {tag}] {line}"),
            }
        }
    });
    let mut crash = Crash { oracle: BTreeMap::new(), doc: String::new(), signed_at: 0 };
    loop {
        let said = match rx.recv_timeout(Duration::from_secs(120)) {
            Ok(said) => said,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                panic!("the {after} child reached no hold within 120s");
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                panic!("the {after} child exited before its hold — its stderr is forwarded above");
            }
        };
        let words: Vec<&str> = said.split(' ').collect();
        match words[..] {
            ["attested", at, tag, sig] => {
                let at = at.parse().expect("a position");
                crash.oracle.insert(at, (tag.parse().expect("a tag"), sig.to_string()));
            }
            ["doc", doc] => crash.doc = doc.to_string(),
            ["signed", at] => crash.signed_at = at.parse().expect("a position"),
            ["held"] => break,
            _ => panic!("the {after} child said what this parent does not read: {said}"),
        }
    }
    child.0.kill().expect("SIGKILL the held child");
    drop(child);
    reader.join().expect("stderr reader thread");
    assert!(
        crash.oracle.contains_key(&crash.signed_at),
        "the journal answered the signed write's slot before any checkpoint"
    );
    (tmp, crash)
}

/// THE ATTEST STORE AGAINST RECLAMATION (SO-I5 (d); BW-01): below the
/// reclaim floor a store line is a signature's only copy at the origin, so
/// no crash may leave an attested position there with neither its line nor
/// the journal segment that holds its marker. The order a running daemon
/// keeps, for a signed write and the checkpoint that later reclaims its
/// segment:
///
/// 1. the write commits — its marker, the signature in the slot, fsynced in
///    the journal — under the write path's serialization guard;
/// 2. inside that commit, once it is durable, the kernel's on-commit cadence
///    (every 1,024 commits) may checkpoint: the file written, two retained,
///    then every closed segment wholly below the OLDEST retained unlinked
///    and the directory fsynced;
/// 3. under the same guard, `commits.log`'s line, then the store's —
///    written, then synced to disk before the step goes on — then the four
///    derived files'.
///
/// The checkpoint that reclaims a write's segment is a LATER commit's step
/// 2, since the oldest retained checkpoint must lie above that segment, and
/// every later commit opens after the write's step 3: the line is on disk
/// before any checkpoint that could reclaim its segment begins, and the open
/// takes no checkpoint, so it rebuilds a missing line from the journal
/// first. So a process killed anywhere loses no signature, and power lost
/// after the sync loses none either. What no kill shows is the sync itself —
/// the OS holds a killed process's line whether or not it was synced — which
/// is why [`each_attest_store_line_is_synced_before_the_next_commit_begins`]
/// observes it through its seam.
///
/// Each boundary is judged on a copy of a SIGKILLed child's board (this
/// binary re-exec'd, as `hazard.rs` does), its checkpoints the kernel's own,
/// taken between writes through `checkpoint_now`: STORE APPEND, the write
/// committed and its line not yet appended — the lines the record step had
/// not reached cut off the files' ends, `commits.log`, written first,
/// keeping its own; STORE SYNC, the line written and its sync not yet
/// returned — to a kill, the board the ack leaves, the OS holding the line
/// either way; CHECKPOINT, the reclaiming checkpoint written, its unlink not
/// reached — the segments it unlinked restored from a copy taken before it;
/// SEGMENT UNLINK, after it. Each reopens, is driven until the signed write
/// lies below the floor, and reopens again: every attested position, read
/// off the journal before any checkpoint, still has its line, and the
/// journal refuses each one below the floor.
#[test]
fn a_kill_at_each_boundary_keeps_every_signature_below_the_floor() {
    if let (Some(dir), Ok(after)) =
        (std::env::var_os(RECLAIM_CRASH_DIR), std::env::var(RECLAIM_CRASH_AFTER))
    {
        reclaim_crash_child(Path::new(&dir), &after);
    }
    let appended = kill_reclaim_crash_child("append");
    let checkpointed = kill_reclaim_crash_child("checkpoint");
    for (boundary, (crashed, crash)) in [
        ("store append", &appended),
        ("store sync", &appended),
        ("checkpoint", &checkpointed),
        ("segment unlink", &checkpointed),
    ] {
        let case = tempfile::tempdir().expect("tempdir");
        let dir = case.path().join("data");
        copy_tree(&crashed.path().join("data"), &dir);
        let signed_at = crash.signed_at;
        match boundary {
            "store append" => {
                for file in [
                    "feed-attest.log",
                    "feed-offsets.log",
                    "feed-index.log",
                    "feed-masked.log",
                    "feed-streams.log",
                ] {
                    cut_trailing_position(&dir.join(file), signed_at);
                }
                assert!(
                    !attest_store_lines(&dir).contains_key(&signed_at),
                    "{boundary}: the store holds no line for the signed write"
                );
            }
            "checkpoint" => {
                let mut restored = 0;
                for seg in segment_files(&crashed.path().join("segments-aside")) {
                    let to = dir.join(seg.file_name().expect("a name"));
                    if !to.exists() {
                        std::fs::copy(&seg, &to).expect("restore a segment");
                        restored += 1;
                    }
                }
                assert!(restored > 0, "{boundary}: the checkpoint had unlinked a segment");
            }
            _ => {}
        }
        // Above the floor still, but at the unlink: the line stands — at the
        // store append, rebuilt from the journal by the open — and the board
        // is driven until a checkpoint unlinks the signed write's segment.
        if boundary != "segment unlink" {
            let sd = spawn(&dir);
            let port = sd.port();
            assert_line(
                &attest_store_lines(&dir),
                crash,
                signed_at,
                &format!("{boundary}: the signed write's line stands above the floor"),
            );
            if boundary != "checkpoint" {
                rotate_a_segment(port, &open_session(port, 1), &crash.doc);
            }
            sd.daemon().checkpoint_now();
            sd.shutdown();
        }
        let sd = spawn(&dir);
        let port = sd.port();
        let (st, body) = changes_raw(port, None, "since=0");
        assert_eq!(st, 410, "{boundary}: the feed has a floor: {}", text(&body));
        let floor = json(&body)["floor"].as_u64().expect("the refusal names the floor");
        assert!(signed_at < floor, "{boundary}: the signed write lies below the floor");
        let lines = attest_store_lines(&dir);
        for at in crash.oracle.keys() {
            assert_line(
                &lines,
                crash,
                *at,
                &format!("{boundary}: attested position {at} keeps its line"),
            );
            if *at < floor {
                assert!(
                    matches!(
                        sd.daemon().attestation_at(Seq(*at)),
                        Err(skepd::HistoryError::Reclaimed { .. })
                    ),
                    "{boundary}: the journal holds no copy of position {at}'s marker"
                );
            }
        }
        sd.shutdown();
    }
}

/// EACH STORE LINE IS DURABLE BEFORE THE NEXT COMMIT BEGINS (SO-I5 (d)):
/// below the reclaim floor a store line is an entry signature's only copy,
/// and the checkpoint that reclaims the journal's copy runs inside a LATER
/// commit — so each attested commit's line is synced before its record step
/// returns, and the open syncs the lines it rebuilds before the first
/// commit. No kill can show either, the OS holding a killed process's line
/// whether or not it was synced, so the sync is observed through its own
/// seam: the coverage the store's last successful `sync_data` made durable,
/// read between commits. After each attested write, before the next is
/// sent, the store holds the write's line and the synced coverage has
/// reached its position; after a reopen that lost the file, the rebuilt
/// lines are synced through the head before any write.
#[test]
fn each_attest_store_line_is_synced_before_the_next_commit_begins() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let mut sigs = BTreeMap::new();
    for n in 1..=3 {
        let (at, attest) = signed_ghost_link(port, &signed, n);
        assert_eq!(
            sd.daemon().attest_store_synced_through(),
            at,
            "write {n}: the store's synced coverage reaches its position before the next commit"
        );
        let sig = attest["sig"].as_str().expect("sig").to_string();
        assert_eq!(
            attest_store_lines(dir.path()).get(&at).map(|(_, held)| held),
            Some(&sig),
            "write {n}: the line the sync covers is the row's signature"
        );
        sigs.insert(at, sig);
    }
    let head_at = head(port);
    sd.shutdown();

    std::fs::remove_file(dir.path().join("feed-attest.log")).expect("lose the store");
    let sd = spawn(dir.path());
    assert_eq!(head(sd.port()), head_at, "the reopen commits nothing");
    assert_eq!(
        sd.daemon().attest_store_synced_through(),
        head_at,
        "the open synced the lines it rebuilt, through the head, before any write"
    );
    let rebuilt: BTreeMap<u64, String> =
        attest_store_lines(dir.path()).into_iter().map(|(at, (_, sig))| (at, sig)).collect();
    assert_eq!(rebuilt, sigs, "every attested position's line is rebuilt from the journal");
    sd.shutdown();
}

/// A FAILED STORE LINE HALTS WRITES (SO-I5 (d)): a store that failed a
/// line holds no copy of that signature, and any later commit could trigger
/// the checkpoint that deletes the journal's — so the daemon refuses every
/// later write, `poisoned` at the `halt` disposition, for the rest of the
/// uptime, while reads are served; the restart's open rebuilds the line from
/// the journal, which the halt kept. The failure is forced through its seam
/// — the store's next write fails at the OS — on the write after a healthy
/// one, with the head writer's clock past the hour, so the turn after the
/// failing write has a head due. That write is acked, and nothing commits
/// after it, the due head included; every later write — an attested link,
/// an attested mint, an unattested `delegate` — is refused `poisoned`;
/// reads answer, the feed serving the failed position's row with its
/// `attest`; and after a restart the store holds the failed position's
/// signature and writes are admitted again. `/health`'s `writes.halted`
/// (wire.md §The other endpoints; op-D10 (a)) reads the halt at both points:
/// `true` from the failing write on, `false` after the restart.
#[test]
fn a_failed_attest_store_line_halts_every_later_write_until_a_restart() {
    let dir = tempfile::tempdir().expect("tempdir");
    let ghost = |n| {
        link_frame(CLAIMANT_DOC1, r#"{"addrs":[]}"#, r#"{"addrs":[]}"#, &ghost_ty(CLAIMANT_DOC1, n))
    };
    let (failed_at, failed_sig) = {
        let sd = spawn(dir.path());
        let port = sd.port();
        let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
        signed_ghost_link(port, &signed, 1);
        assert!(!writes_halted(port), "a healthy board: /health says writes are not halted");
        sd.daemon().set_head_writer_clock_millis(u64::MAX);
        sd.daemon().fail_the_attest_stores_next_write();
        let before = head(port);
        let failed_at = acked_at(&op(port, Some(&signed), &ghost(2)));
        assert_eq!(head(port), failed_at, "the failing write is acked, and the due head refused");
        assert!(
            writes_halted(port),
            "FINDING (op-D10 (a)): /health's writes.halted is false after the attest halt"
        );
        assert!(
            !attest_store_lines(dir.path()).contains_key(&failed_at),
            "the store holds no line for the failed position"
        );
        assert!(
            matches!(sd.daemon().attestation_at(Seq(failed_at)), Ok(Some(_))),
            "the journal holds its marker"
        );

        let boot = open_session(port, 0);
        let v = op(port, Some(&boot), r#"{"op":"next_account_prefix","parent":"1"}"#);
        let prefix =
            expect_resp(&v, "maybe_addr")["addr"].as_str().expect("a read answers").to_string();
        for (what, token, frame) in [
            ("an attested link", &signed, ghost(3)),
            (
                "an attested mint",
                &signed,
                format!(r#"{{"op":"create_new_document","account":"{CLAIMANT_ACCOUNT}"}}"#),
            ),
            (
                "an unattested delegate",
                &boot,
                format!(r#"{{"op":"delegate","new_prefix":"{prefix}","new_id":1}}"#),
            ),
        ] {
            let v = op(port, Some(token), &frame);
            assert_eq!(
                (v["resp"].as_str(), v["code"].as_str(), v["disposition"].as_str()),
                (Some("rejected"), Some("poisoned"), Some("halt")),
                "{what} is refused while the store has failed: {v}"
            );
        }
        assert_eq!(head(port), failed_at, "no refused write committed");
        let row = one_entry_since(port, &signed, "the failed write's row", before);
        assert_eq!(row["at"].as_u64(), Some(failed_at));
        let sig = row["attest"]["sig"].as_str().expect("the uptime serves the slot").to_string();
        sd.shutdown();
        (failed_at, sig)
    };

    let sd = spawn(dir.path());
    let port = sd.port();
    assert_eq!(
        attest_store_lines(dir.path()).get(&failed_at).map(|(_, sig)| sig),
        Some(&failed_sig),
        "the restart's open rebuilt the failed position's line from the journal"
    );
    assert!(!writes_halted(port), "after the restart /health says writes are not halted");
    let signed = open_signed_session(port, CLAIMANT_PRINCIPAL, &device_key());
    let (at, _) = signed_ghost_link(port, &signed, 3);
    assert!(at > failed_at, "writes are admitted again");
    sd.shutdown();
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}
