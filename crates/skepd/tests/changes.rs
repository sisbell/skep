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
/// the stores' record counts: `delegate` commits 2 records (position 2),
/// `create_new_document` 1 (position 3), a two-byte `insert` 5 — two mints,
/// two content writes, one placement — (position 8), `make_link` 3 — mint,
/// link, seat — (position 11). If an ack below drifts, a store changed its
/// transaction shape and wire.md §The change feed must be re-pinned.
fn seed_flow(port: u16) -> String {
    let boot = open_session(port, 0);
    let v = op(port, Some(&boot), r#"{"op":"next_account_prefix","parent":"1"}"#);
    let prefix = expect_resp(&v, "maybe_addr")["addr"].as_str().expect("prefix").to_string();
    assert_eq!(
        prefix, "1.0.1",
        "genesis frontier drifted; the wire.md change-feed examples must be re-pinned"
    );
    let v = op(
        port,
        Some(&boot),
        &format!(r#"{{"op":"delegate","new_prefix":"{prefix}","new_id":1}}"#),
    );
    assert_eq!(acked(&v), 2, "delegate is a 2-record commit (Allocate + RegisterPrincipal)");
    let s1 = open_session(port, 1);
    let v = op(
        port,
        Some(&s1),
        &format!(r#"{{"op":"create_new_document","account":"{prefix}"}}"#),
    );
    let doc = acked_addr(&v);
    assert_eq!(doc, "1.0.1.0.1", "first document address drifted; re-pin wire.md");
    assert_eq!(acked(&v), 3, "create_new_document is a 1-record commit");
    let v = op(
        port,
        Some(&s1),
        &format!(
            r#"{{"op":"insert","doc":"{doc}","at":{{"subspace":"1","ordinal":"1"}},"values":["hi"]}}"#
        ),
    );
    assert_eq!(acked(&v), 8, "a 2-value insert is a 5-record commit");
    let v = op(
        port,
        Some(&s1),
        &format!(
            concat!(
                r#"{{"op":"make_link","home":"{d}","#,
                r#""from":[{{"source":"{d}","span":{{"start":"1.1","width":"0.2"}}}}],"#,
                r#""to":{{"addrs":["{d}"]}},"ty":{{"addrs":["1.0.1.0.1.0.3.1"]}}}}"#
            ),
            d = doc
        ),
    );
    assert_eq!(acked(&v), 11, "make_link is a 3-record commit (mint + link + seat)");
    doc
}

fn acked(v: &Value) -> u64 {
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

/// Replace every `"time":<digits>` value with `"time":0` — the one field a
/// live daemon cannot reproduce byte-for-byte. `"time":null` is untouched,
/// so a bare entry stays byte-exact.
fn normalize_times(s: &str) -> String {
    let bytes = s.as_bytes();
    let pat: &[u8] = b"\"time\":";
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i..].starts_with(pat) {
            out.extend_from_slice(pat);
            i += pat.len();
            if i < bytes.len() && bytes[i].is_ascii_digit() {
                while i < bytes.len() && bytes[i].is_ascii_digit() {
                    i += 1;
                }
                out.push(b'0');
            }
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).expect("normalization preserves UTF-8")
}

#[test]
fn change_feed_lists_writes_pages_and_matches_the_doc() {
    let dir = tempfile::tempdir().expect("tempdir");
    let sd = spawn(dir.path());
    let port = sd.port();

    // A fresh world has no recorded commit: head_time is null, honestly.
    let (st, body) = get(port, "/health");
    assert_eq!(st, 200);
    assert!(json(&body)["head_time"].is_null(), "fresh world: head_time null");

    let doc = seed_flow(port);

    // Reads and rejected writes are not in the feed: issue both, then
    // assert the feed holds exactly the four committed writes.
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

    // ── the full feed: ops, docs, ordering — and the doc-pinned bytes ──
    let (st, body) = changes_raw(port, "since=0");
    assert_eq!(st, 200);
    let full = String::from_utf8(body.clone()).expect("utf-8 body");
    assert_eq!(
        normalize_times(&full),
        normalize_times(&doc_changes_block("feed")),
        "wire.md 'changes feed' example drifted from the daemon"
    );
    let v = json(&body);
    assert_eq!(entry_ats(&v), vec![2, 3, 8, 11]);
    let entries = v["changes"].as_array().expect("changes");
    assert_eq!(entries[0]["op"].as_str(), Some("delegate"));
    assert_eq!(entries[0]["docs"], serde_json::json!([]), "delegate names no doc");
    assert_eq!(entries[3]["op"].as_str(), Some("make_link"));
    assert_eq!(
        entries[3]["docs"],
        serde_json::json!([doc]),
        "a link write names its home doc"
    );
    let times: Vec<u64> =
        entries.iter().map(|e| e["time"].as_u64().expect("live entries carry times")).collect();
    assert!(times.windows(2).all(|w| w[0] <= w[1]), "times monotone in position: {times:?}");
    assert_eq!(v["last"].as_u64(), Some(11));
    assert_eq!(v["more"], Value::Bool(false));

    // Determinism: the same question answers byte-identically.
    let (_, again) = changes_raw(port, "since=0");
    assert_eq!(body, again, "same (since, limit) on the same journal must be byte-equal");

    // ── paging ──
    let (st, body) = changes_raw(port, "since=0&limit=2");
    assert_eq!(st, 200);
    let page = String::from_utf8(body).expect("utf-8 body");
    assert_eq!(
        normalize_times(&page),
        normalize_times(&doc_changes_block("feed_page")),
        "wire.md 'changes feed_page' example drifted from the daemon"
    );
    let v: Value = serde_json::from_str(&page).expect("json");
    assert_eq!(entry_ats(&v), vec![2, 3]);
    assert_eq!((v["last"].as_u64(), v["more"].as_bool()), (Some(3), Some(true)));
    let v = changes_ok(port, "since=3&limit=2");
    assert_eq!(entry_ats(&v), vec![8, 11]);
    assert_eq!((v["last"].as_u64(), v["more"].as_bool()), (Some(11), Some(false)));

    // `since` is a fence, not a position: an interior number pages cleanly.
    let v = changes_ok(port, "since=5");
    assert_eq!(entry_ats(&v), vec![8, 11]);

    // since ≥ head: empty, `last` echoes `since`.
    let v = changes_ok(port, "since=11");
    assert_eq!(entry_ats(&v), Vec::<u64>::new());
    assert_eq!((v["last"].as_u64(), v["more"].as_bool()), (Some(11), Some(false)));
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
    let at5 = acked(&first);
    let second = op(port, Some(&s1), &frame);
    assert_eq!(acked(&second), at5, "the retry re-acks the original commit");
    let v = changes_ok(port, "since=0");
    assert_eq!(entry_ats(&v), vec![2, 3, 8, 11, at5], "one entry per commit, retries excluded");

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
    //    daemon comes up and the feed is unchanged ──
    {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&sidecar_path)
            .expect("append to commits.log");
        f.write_all(b"{\"at\":9").expect("write the torn tail");
        drop(f);
        let sd = spawn(dir.path());
        let port = sd.port();
        let (st, body) = changes_raw(port, "since=0");
        assert_eq!(st, 200);
        assert_eq!(body, before, "a torn sidecar tail must not change the feed");
        let contents = std::fs::read_to_string(&sidecar_path).expect("read commits.log");
        assert!(!contents.contains("{\"at\":9"), "the torn tail was truncated on open");
        sd.shutdown();
    }

    // ── lost record: drop the last whole record (the make_link entry at
    //    11). Reopen: the position is reconstructed as a BARE entry — the
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
        assert_eq!(entry_ats(&v), vec![2, 3, 8, 11]);
        let entries = v["changes"].as_array().expect("changes");
        assert!(
            entries[3]["op"].is_null()
                && entries[3]["docs"].is_null()
                && entries[3]["time"].is_null(),
            "a lost record answers bare nulls: {}",
            entries[3]
        );
        let old: Value = serde_json::from_slice(&before).expect("json");
        assert_eq!(
            entries[..3],
            old["changes"].as_array().expect("changes")[..3],
            "surviving records keep their metadata verbatim"
        );
        // The head's record is bare, so head_time honestly answers null.
        let (st, body) = get(port, "/health");
        assert_eq!(st, 200);
        assert!(json(&body)["head_time"].is_null());
        sd.shutdown();
    }
}

/// A data dir written before the sidecar existed (here: by the engine
/// directly, with no daemon): every committed position still appears in
/// `/changes`, reconstructed from the journal via the engine's bounded
/// replay — as bare `null`-field entries, byte-equal to the wire.md
/// example.
#[test]
fn pre_feature_positions_answer_bare_entries() {
    use skep_engine::{Engine, GenesisConfig, KernelCfg};
    use skep_febe::{Codec, Operation, Response, SessionId};
    use skep_kernel::{BurnedSeqPolicy, CheckpointPolicy, Durability};
    use skep_namespace::PrincipalId;
    use skepd::{tumbler_string, JsonCodec};

    let dir = tempfile::tempdir().expect("tempdir");
    {
        let cfg = KernelCfg {
            journal_path: dir.path().to_path_buf(),
            durability: Durability::Fsync { burned_seq: BurnedSeqPolicy::Rollback },
            checkpoint: CheckpointPolicy::EveryN(1024),
            retain_checkpoints: 2,
        };
        let engine = Engine::open(cfg, GenesisConfig::standard()).expect("engine genesis");
        let op = Operation::new(Box::new(engine.stores()));
        let codec = JsonCodec;
        let exec = |sid: SessionId, frame: &str| {
            let req = codec
                .parse(frame.as_bytes())
                .unwrap_or_else(|e| panic!("test frame does not parse: {:?}", e.detail));
            op.execute(sid, req)
        };
        let unexpected = |r: &Response| -> String {
            String::from_utf8_lossy(&codec.marshal(r)).into_owned()
        };

        let boot = op.bootstrap_session();
        let prefix = match exec(boot, r#"{"op":"next_account_prefix","parent":"1"}"#) {
            Response::MaybeAddr { addr: Some(a), .. } => tumbler_string(a.tumbler()),
            other => panic!("next_account_prefix: {}", unexpected(&other)),
        };
        let account = match exec(
            boot,
            &format!(r#"{{"op":"delegate","new_prefix":"{prefix}","new_id":1}}"#),
        ) {
            Response::AckAddr { addr, at } => {
                assert_eq!(at.0, 2, "delegate commits at position 2; re-pin wire.md");
                tumbler_string(addr.tumbler())
            }
            other => panic!("delegate: {}", unexpected(&other)),
        };
        let s1 = op.open_session(PrincipalId(1));
        let doc = match exec(
            s1,
            &format!(r#"{{"op":"create_new_document","account":"{account}"}}"#),
        ) {
            Response::AckAddr { addr, at } => {
                assert_eq!(at.0, 3, "create commits at position 3; re-pin wire.md");
                tumbler_string(addr.tumbler())
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
        drop(op);
        drop(engine); // releases the journal-directory lock for the daemon
    }
    assert!(
        !dir.path().join("commits.log").exists(),
        "the engine alone must write no sidecar (it is the daemon's file)"
    );

    let sd = spawn(dir.path());
    let port = sd.port();
    let (st, body) = changes_raw(port, "since=0");
    assert_eq!(st, 200);
    assert_eq!(
        String::from_utf8(body).expect("utf-8 body"),
        doc_changes_block("bare"),
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
