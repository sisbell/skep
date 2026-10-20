//! The fence: the adapter as an agent's door, each case keyed to its rulings.
//!
//! A1 signed only — its writes attested or testified, and no key stops startup;
//! A1b a principal under the claimant's account signs by reference with the
//! key enrolled in the set above; A2 the startup line names the refusing
//! seam and no ceremony tool is listed; A3 the tools — every wire op, the
//! shell's calls, the apparatus — a publish landing a version, and `fetch`'s
//! image block, resource blob, cap and cut stream; A4 `changes_since`
//! answering a published write after a position, `next` advancing; A5
//! `SKEP_BOARD` read and `SKEPD_URL` alone refused; A6 the session's life —
//! the key retired stops the process, and a relaunch refuses before serving,
//! a re-open the board refuses stops naming it, the board gone answers
//! `unreachable` and the adapter stays up (the restart's re-open is
//! `mcp.rs`'s); A7 a board rejection as data, an unreachable board as an
//! error, a write whose answer was lost unreachable, landing once, a write
//! refused `poisoned` landing at the restart, and a burst the board refuses
//! held, the bursts behind it waiting on `resolve`; A8 the TALK lines on
//! stderr alone and stdin's end closing the session. The daemon, the claim,
//! the library's walks and the driver are `common`'s.

use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::common::{base64_decode, draft_of, seeded_bytes, stamped, FetchStreamHeld, Fixture, Launch, Mcp, WriteGuardHeld, AGENT_SPACE, CLAIMANT_ACCOUNT, CLAIMANT_DOC1};

/// The ten ceremonial rows, the two media rows the shell does not reach,
/// and the three calls the adapter makes of the shell itself (`op`,
/// `session`, `close`) — no tool of the adapter's.
const NOT_OFFERED: [&str; 15] = ["keygen", "fingerprint", "claim", "enroll", "bind", "recover", "rotate", "retire", "handoff", "accept", "upload", "restore", "op", "session", "close"];

/// The seven wire ops the first catalog lacked.
const ADDED_OPS: [&str; 7] = ["publish", "effective_owner", "key_set", "retrieve_i", "content_frontier", "edition_claims", "universal_grants"];

/// The shell's calls and the apparatus, as tools.
const ADAPTER_TOOLS: [&str; 10] = ["boards", "health", "probe", "search", "places", "held", "resolve", "session_info", "changes_since", "fetch"];

/// The adapter's cap on one fetch, as `media.rs` states it.
const MAX_FETCH_BYTES: usize = 8 * 1024 * 1024;

/// The `changes_since` entry at `at`, read from `since`, waited for: the
/// board's feed may trail the ack by a moment.
fn entry_at(mcp: &mut Mcp, since: u64, at: u64) -> Value {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let page = mcp.call_json("changes_since", json!({"since": since}));
        if let Some(entry) = page["entries"].as_array().and_then(|entries| entries.iter().find(|e| e["at"] == at)) {
            return entry.clone();
        }
        assert!(Instant::now() < deadline, "the entry at {at} never appeared after {since}: {page}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// A1: the signed session writes, and no key stops startup.
///
/// `session_info` says `writes` true and names the claimant's key, and each
/// write lands under it: a publish-class mint's `/changes` row carries
/// `attest`, the entry's own signature, and a draft write's row the key's
/// fingerprint, the board's testimony (wire.md §The change feed: `key` on an
/// unsigned entry, `attest` on a signed one; the mutant with a bare fallback
/// lands them `key: "bare"` and `signed_session_required`). The startup line
/// names the key, the account and the session opened, which the clean stop's
/// line names again. With the key removed — a fresh, keyless store — startup
/// stops with the plain face (`no_key`) and serves nothing: an `initialize`
/// on stdin is answered by the end of stdout, exit 1.
#[test]
fn a1_the_signed_session_writes_and_no_key_stops_startup() {
    let fixture = Fixture::new("a1");
    let mut mcp = Launch::over(&fixture, 1).logged().spawn();
    mcp.initialize();
    let info = mcp.call_json("session_info", json!({}));
    assert_eq!((info["writes"].as_bool(), info["key"]["fingerprint"].as_str()), (Some(true), Some(fixture.fingerprint.as_str())), "{info}");
    let since = info["health"]["log_position"].as_u64().expect("the position");
    let edition = mcp.acked("create_new_document", json!({"account": CLAIMANT_ACCOUNT, "published": true}));
    let row = entry_at(&mut mcp, since, edition["at"].as_u64().expect("the commit's position"));
    assert!(row["attest"]["alg"].is_string() && row["attest"]["sig"].is_string(), "the publish-class mint landed attested: {row}");
    assert!(row.get("key").is_none(), "a signed entry's one authority is its signature: {row}");
    assert_eq!((row["class"].as_str(), &row["docs"]), (Some("published"), &json!([edition["addr"]])), "{row}");
    let draft = draft_of(&mut mcp, CLAIMANT_ACCOUNT);
    let inserted = mcp.acked("insert", json!({"doc": draft, "at": {"subspace": "1", "ordinal": "1"}, "values": ["signed"]}));
    let row = entry_at(&mut mcp, since, inserted["at"].as_u64().expect("the commit's position"));
    assert_eq!(row["key"], fixture.fingerprint, "the draft write's testimony names the signing key: {row}");
    assert_eq!((row["class"].as_str(), &row["docs"]), (Some("drafts"), &json!([draft])), "{row}");
    let (status, log) = mcp.finish_logged();
    assert!(status.success(), "{status:?}");
    let signed = log.lines().find(|line| line.contains("signed as principal ")).unwrap_or_else(|| panic!("the startup line:\n{log}"));
    assert!(
        signed.contains(&format!("signed as principal 1 (account {CLAIMANT_ACCOUNT}) with the key {} (notebook) from ", fixture.fingerprint)),
        "the startup line names the key and the account:\n{log}"
    );
    let session = signed.split(" under session ").nth(1).and_then(|rest| rest.split(':').next()).unwrap_or_else(|| panic!("the session named: {signed}"));
    assert!(session.starts_with("s-") && log.contains(&format!("saving the index (session {session})")), "the session opened is the one the stop closes:\n{log}");
    // The key removed: a keyless store in its place.
    let keyless = fixture.dir.path().join("keyless");
    std::fs::create_dir_all(&keyless).expect("a keyless store");
    let mut stopped = Launch::over(&fixture, 1).env("SKEP_KEYSTORE", &keyless).logged().spawn();
    stopped.send_line(r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{}}}"#);
    assert!(stopped.stdout_closed(), "nothing is served");
    let status = stopped.wait_exit(Duration::from_secs(30)).expect("the adapter stopped");
    assert_eq!(status.code(), Some(1), "{status:?}");
    let log = stopped.log_holding(&["stopped before serving: no key to sign with: no_key"], Duration::from_secs(5));
    assert!(log.contains("keyless for this claimed board"), "the face in plain words:\n{log}");
    assert!(!log.contains("serving "), "the serving line never came:\n{log}");
}

/// A1b BY REFERENCE: a principal under the claimant's account — the agent
/// space `1.0.1.1` the claim delegated, which holds no key of its own —
/// opens with the store's one device key, enrolled in the set above it,
/// and writes under its own account: `session_info` names that principal,
/// its account and the claimant's key; a published document minted in its
/// account lands attested, and a draft written into testified by the key;
/// `effective_owner` seats the draft at the agent space (the mutant that
/// opens the session as the claimant answers principal 1 and account
/// `1.0.1`, and the draft's mint `not_owner`).
#[test]
fn a1b_a_principal_under_the_claimants_account_signs_by_reference() {
    let fixture = Fixture::new("a1b");
    let agent = fixture.agent_principal();
    assert_ne!(agent, 1, "the agent space's principal is its own");
    let mut mcp = Launch::over(&fixture, agent).logged().spawn();
    mcp.initialize();
    let info = mcp.call_json("session_info", json!({}));
    assert_eq!((info["principal"].as_u64(), info["account"].as_str(), info["writes"].as_bool()), (Some(agent), Some(AGENT_SPACE), Some(true)), "{info}");
    assert_eq!(info["key"]["fingerprint"], fixture.fingerprint, "the key enrolled above: {info}");
    let since = info["health"]["log_position"].as_u64().expect("the position");
    let edition = mcp.acked("create_new_document", json!({"account": AGENT_SPACE, "published": true}));
    let row = entry_at(&mut mcp, since, edition["at"].as_u64().expect("at"));
    assert!(row["attest"]["sig"].is_string() && row.get("key").is_none(), "the agent's publish-class mint landed attested: {row}");
    let draft = draft_of(&mut mcp, AGENT_SPACE);
    assert!(draft.starts_with(&format!("{AGENT_SPACE}.0.")), "a document of the agent space's own: {draft}");
    let inserted = mcp.acked("insert", json!({"doc": draft, "at": {"subspace": "1", "ordinal": "1"}, "values": ["by reference"]}));
    let row = entry_at(&mut mcp, since, inserted["at"].as_u64().expect("at"));
    assert_eq!(row["key"], fixture.fingerprint, "the draft write's testimony is the key above: {row}");
    let owner = mcp.call_json("effective_owner", json!({"addr": draft}));
    assert_eq!((owner["prefix"].as_str(), owner["principal"].as_u64()), (Some(AGENT_SPACE), Some(agent)), "{owner}");
    let set = mcp.call_json("key_set", json!({"account": AGENT_SPACE}));
    assert!(set["enrolled"].as_array().is_some_and(Vec::is_empty), "the agent space holds no key of its own: {set}");
    let (status, log) = mcp.finish_logged();
    assert!(status.success());
    assert!(log.contains(&format!("signed as principal {agent} (account {AGENT_SPACE}) with the key {}", fixture.fingerprint)), "{log}");
}

/// A2 NO PERSON: the startup line on stderr names the refusing seam —
/// `person seam: refuse` — and `tools/list` names no ceremony, no `upload`,
/// no `restore`, and none of the calls the adapter makes of the shell itself
/// (the mutant that opens the shell under the auto arm says
/// `person seam: auto`).
#[test]
fn a2_the_startup_line_names_the_refusing_seam_and_no_ceremony_tool_is_listed() {
    let fixture = Fixture::new("a2");
    let mut mcp = Launch::over(&fixture, 1).logged().spawn();
    mcp.initialize();
    let log = mcp.log_holding(&["person seam: refuse"], Duration::from_secs(10));
    assert!(log.contains("person seam: refuse — no secret or consent moment is answered here"), "{log}");
    assert!(!log.contains("person seam: auto") && !log.contains("person seam: script"), "{log}");
    let names = mcp.tool_names();
    for not_offered in NOT_OFFERED {
        assert!(!names.iter().any(|n| n == not_offered), "`{not_offered}` is listed: {names:?}");
    }
    assert!(mcp.finish().success());
}

/// A3: every tool is listed, and a publish through MCP lands a version.
///
/// `tools/list` names every wire op — the seven the first catalog lacked among
/// them — the shell's seven calls and the three apparatus tools; and the
/// publish: a published document minted, a draft written, `image` giving the
/// runs, `publish` taking them, the member read back, its metadata naming the
/// shot.
#[test]
fn a3_every_tool_is_listed_and_a_publish_lands_a_version() {
    let fixture = Fixture::new("a3-tools");
    let mut mcp = Launch::over(&fixture, 1).spawn();
    mcp.initialize();
    let names = mcp.tool_names();
    for tool in ADDED_OPS.iter().chain(ADAPTER_TOOLS.iter()).chain(["insert", "make_link", "retrieve_v", "image", "doc_metadata", "window_ftt", "out_claims"].iter()) {
        assert!(names.iter().any(|n| n == tool), "`{tool}` is listed: {names:?}");
    }
    // The shell's calls answer.
    let boards = mcp.call_json("boards", json!({}));
    assert_eq!(boards[0]["origin"], fixture.origin(), "{boards}");
    assert!(boards[0]["board"].as_str().is_some_and(|b| b.starts_with("b-")), "{boards}");
    let health = mcp.call_json("health", json!({}));
    assert_eq!(health["mode"], "CLAIMED-PERMISSIVE", "{health}");
    assert_eq!(mcp.call_json("probe", json!({}))["daemon"], "running");
    assert_eq!(mcp.call_json("held", json!({})), json!([]));
    let resolve = mcp.call_error("resolve", json!({"held": 1, "act": "drop"}));
    assert_eq!(resolve["name"], "no_such_held", "{resolve}");
    let listed = mcp.call_json("places", json!({}));
    assert!(listed["docs"].is_array() && listed["state"]["arm"].is_string(), "{listed}");
    let found = mcp.call_json("search", json!({"query": "hello", "opts": {"limit": 3}}));
    assert!(found["hits"].is_array() && found["state"]["arm"].is_string(), "{found}");
    let grants = mcp.call_json("universal_grants", json!({}));
    assert_eq!(grants["resp"], "universal_grants", "{grants}");
    // THE PUBLISH: the shot composed from `image`.
    let edition = mcp.acked("create_new_document", json!({"account": CLAIMANT_ACCOUNT, "published": true}))["addr"].as_str().expect("the edition").to_string();
    let draft = draft_of(&mut mcp, CLAIMANT_ACCOUNT);
    mcp.acked("insert", json!({"doc": draft, "at": {"subspace": "1", "ordinal": "1"}, "values": ["abc"]}));
    let image = mcp.call_json("image", json!({"d": draft, "region": [{"start": "1.1", "width": "0.3"}]}));
    assert_eq!(image["resp"], "runs", "{image}");
    let run = &image["runs"][0];
    let shot = mcp.acked("publish", json!({"doc": edition, "draft": draft, "runs": [{"origin": draft, "i_start": run["i_start"], "width": run["width"]}]}));
    let member = shot["addr"].as_str().expect("the member").to_string();
    assert!(member.starts_with(&edition), "a member of the edition's chain: {member}");
    let read = mcp.call_json("retrieve_v", json!({"specs": [{"doc": member, "span": {"start": "1.1", "width": "0.3"}}]}));
    assert_eq!(read["items"], json!([{"content": "abc"}]), "{read}");
    let meta = mcp.call_json("doc_metadata", json!({"doc": member}));
    assert_eq!((meta["doc"].as_str(), meta["published"].as_bool()), (Some(edition.as_str()), Some(true)), "{meta}");
    assert_eq!(meta["placed"].as_str(), Some("3"), "the shot's three positions: {meta}");
    let frontier = mcp.call_json("content_frontier", json!({"doc": draft}));
    assert_eq!(frontier["resp"], "frontier", "{frontier}");
    let by_identity = mcp.call_json("retrieve_i", json!({"spans": [{"start": run["i_start"], "width": "3"}]}));
    assert_eq!(by_identity["resp"], "i_delivery", "{by_identity}");
    assert!(mcp.finish().success());
}

/// A3 FETCH (rulings 1 (a) and 2 (a)): a seeded PNG comes back as an IMAGE
/// block with its type sniffed off the magic and its bytes intact; a blob
/// that is no image as an embedded RESOURCE blob of
/// `application/octet-stream` at the fetch's own URI; a file one byte past
/// the cap is refused `isError` naming the cap, no byte read; one at the
/// cap answers whole; a value that is no cell is the board's own verdict,
/// data (the mutant without the cap answers the oversized file; the sniff
/// answering every file as a blob hands the PNG back as a resource).
#[test]
fn a3_fetch_answers_an_image_block_a_resource_blob_and_refuses_past_the_cap() {
    let fixture = Fixture::new("a3-fetch");
    let mut mcp = Launch::over(&fixture, 1).spawn();
    mcp.initialize();
    let png = seeded_bytes(1_000, 1, b"\x89PNG\r\n\x1a\n");
    let png_cell = fixture.seed_picture(&png);
    let (is_error, block) = mcp.call_block("fetch", json!({"i": png_cell}));
    assert!(!is_error, "{block}");
    assert_eq!((block["type"].as_str(), block["mimeType"].as_str()), (Some("image"), Some("image/png")), "{block}");
    assert_eq!(base64_decode(block["data"].as_str().expect("base64")), png, "the bytes intact");
    let plain = seeded_bytes(2_000, 2, b"SKEP");
    let plain_cell = fixture.seed_picture(&plain);
    let (is_error, block) = mcp.call_block("fetch", json!({"i": plain_cell}));
    assert!(!is_error, "{block}");
    assert_eq!(block["type"], "resource", "{block}");
    assert_eq!(block["resource"]["mimeType"], "application/octet-stream", "{block}");
    assert_eq!(block["resource"]["uri"], format!("{}/blob?i={plain_cell}", fixture.origin()), "{block}");
    assert_eq!(base64_decode(block["resource"]["blob"].as_str().expect("base64")), plain, "the bytes intact");
    // The cap, from below and from above.
    let at_cap = seeded_bytes(MAX_FETCH_BYTES, 3, b"SKEP");
    let at_cap_cell = fixture.seed_picture(&at_cap);
    let (is_error, block) = mcp.call_block("fetch", json!({"i": at_cap_cell}));
    assert!(!is_error, "a file at the cap answers: {:.200}", block.to_string());
    assert_eq!(base64_decode(block["resource"]["blob"].as_str().expect("base64")), at_cap, "the bytes intact at the cap");
    let past = seeded_bytes(MAX_FETCH_BYTES + 1, 4, b"SKEP");
    let past_cell = fixture.seed_picture(&past);
    let (is_error, text) = mcp.call("fetch", json!({"i": past_cell}));
    assert!(is_error, "{text}");
    assert!(text.contains(&format!("{} bytes, past this adapter's cap of {MAX_FETCH_BYTES} bytes (8 MiB)", MAX_FETCH_BYTES + 1)) && text.contains("no byte of it was read"), "the cap named: {text}");
    // A value that is no cell: the board's verdict, as data.
    let verdict = mcp.call_json("fetch", json!({"i": format!("{CLAIMANT_DOC1}.0.1.1")}));
    assert_eq!((verdict["kind"].as_str(), verdict["name"].as_str(), verdict["status"].as_u64()), (Some("refused"), Some("not_a_cell"), Some(404)), "{verdict}");
    assert!(mcp.finish().success());
}

/// A3: a fetch cut short is an error in plain words; fetched again, whole.
///
/// The board's fetch stream is held after its first chunk, so the body stops
/// until skep-client's read bound ends the read: `isError`, the bytes that
/// came of the declared length said, and "fetch it again" — which answers
/// the file whole once the stream is free. The call held the loop past a
/// dial's read bound, and the log says so, by its tool and its answer.
#[test]
fn a3_a_fetch_cut_short_is_an_error_in_plain_words_and_fetched_again_whole() {
    let fixture = Fixture::alone("a3-cut");
    let mut mcp = Launch::over(&fixture, 1).logged().spawn();
    mcp.initialize();
    // Sixteen of the board's 64 KiB chunks, so the stream stops after one.
    let bytes = seeded_bytes(1024 * 1024, 5, b"SKEP");
    let i = fixture.seed_picture(&bytes);
    let hold = FetchStreamHeld::arm(&fixture);
    let (is_error, text) = mcp.call("fetch", json!({"i": i}));
    drop(hold);
    assert!(is_error, "a cut stream is isError: {text}");
    assert!(text.starts_with(&format!("the fetch of {i} ended before the file was whole: ")) && text.ends_with("fetch it again"), "{text}");
    assert!(text.contains(&format!(" of {} bytes came", bytes.len())) && !text.contains(&format!("{0} of {0}", bytes.len())), "short of the declared length: {text}");
    mcp.log_holding(&["the `fetch` call of request ", " held the loop ", " s: answered isError"], Duration::from_secs(10));
    let (is_error, block) = mcp.call_block("fetch", json!({"i": i}));
    assert!(!is_error, "{block}");
    assert_eq!(base64_decode(block["resource"]["blob"].as_str().expect("base64")), bytes, "fetched again, the file is whole");
    assert!(mcp.finish().success());
}

/// A4: what changed after a position is answered, and `next` advances.
///
/// A published write after the position N — a second key enrolled into the
/// claimant's set, the library's declared deposit into the claimant's
/// published doc 1 under its own signed session — appears in
/// `changes_since(N)` of the `published` class; `next` advances past it, and
/// the next ask from `next` answers nothing new; a draft written by a second
/// session of the claimant's appears of the `drafts` class; a sibling
/// account's published home appears, and its draft — which the claimant's
/// reader class never reads — never does.
#[test]
fn a4_changes_since_answers_a_published_write_after_a_position_and_next_advances() {
    let fixture = Fixture::new("a4");
    let mut mcp = Launch::over(&fixture, 1).spawn();
    mcp.initialize();
    let n = mcp.call_json("session_info", json!({}))["health"]["log_position"].as_u64().expect("the position");
    let second = fixture.dir.path().join("second");
    let k2 = fixture.enroll_second_key(&second, "second");
    let set = mcp.call_json("key_set", json!({"account": CLAIMANT_ACCOUNT}));
    assert!(set["enrolled"].as_array().is_some_and(|e| e.iter().any(|k| k["fingerprint"] == k2)), "premise: the second key is enrolled: {set}");
    let page = mcp.call_json("changes_since", json!({"since": n}));
    let entries = page["entries"].as_array().expect("entries");
    let deposit = entries
        .iter()
        .find(|e| e["class"] == "published" && e["docs"].as_array().is_some_and(|d| d.contains(&json!(CLAIMANT_DOC1))))
        .unwrap_or_else(|| panic!("the deposit into doc 1 after {n}: {page}"));
    assert!(deposit["at"].as_u64().is_some_and(|at| at > n), "{deposit}");
    assert_eq!(deposit["position"], deposit["at"], "{deposit}");
    let next = page["next"].as_u64().expect("next");
    assert!(next >= deposit["at"].as_u64().expect("at") && page["head"].as_u64().is_some_and(|h| h >= n), "{page}");
    let again = mcp.call_json("changes_since", json!({"since": next}));
    assert_eq!(again["entries"], json!([]), "nothing new from `next`: {again}");
    assert!(again["next"].as_u64().is_some_and(|n2| n2 >= next), "`next` never falls back: {again}");
    // A draft by a second session of the claimant's: the `drafts` class. A
    // sibling's home and draft beside it: the home everyone's, the draft
    // nobody's but the sibling's.
    let one = fixture.bare_session(1);
    let draft = fixture.write(&one, json!({"op": "create_new_document", "account": CLAIMANT_ACCOUNT}));
    let boot = fixture.bare_session(0);
    let sibling = fixture.guest(json!({"op": "next_account_prefix", "parent": "1"}))["addr"].as_str().expect("a delegable prefix").to_string();
    fixture.write(&boot, json!({"op": "delegate", "new_prefix": sibling, "new_id": 2}));
    let two = fixture.bare_session(2);
    let sibling_home = fixture.write(&two, json!({"op": "create_new_document", "account": sibling}));
    let foreign = fixture.write(&two, json!({"op": "create_new_document", "account": sibling}));
    fixture.write(&two, json!({"op": "insert", "doc": foreign, "at": {"subspace": "1", "ordinal": "1"}, "values": ["theirs"]}));
    let page = mcp.call_json("changes_since", json!({"since": next}));
    let entries = page["entries"].as_array().expect("entries");
    assert!(entries.iter().any(|e| e["class"] == "drafts" && e["docs"] == json!([draft])), "the claimant's own draft rides the drafts class: {page}");
    assert!(entries.iter().any(|e| e["class"] == "published" && e["docs"] == json!([sibling_home])), "the sibling's published home is everyone's: {page}");
    assert!(entries.iter().all(|e| e["docs"].as_array().is_none_or(|docs| !docs.contains(&json!(foreign)))), "a draft the session cannot read never appears: {page}");
    assert!(entries.windows(2).all(|pair| pair[0]["at"].as_u64() < pair[1]["at"].as_u64()), "oldest first, each position once: {page}");
    let limited = mcp.call_json("changes_since", json!({"since": next, "limit": 1}));
    assert_eq!(limited["entries"].as_array().map(Vec::len), Some(1), "{limited}");
    assert_eq!(limited["next"], limited["entries"][0]["at"], "`next` is the last entry kept: {limited}");
    let malformed = mcp.call_error("changes_since", json!({"since": "x"}));
    assert_eq!((malformed["name"].as_str(), malformed["what"].as_str()), (Some("malformed_args"), Some("since")), "{malformed}");
    assert!(mcp.finish().success());
}

/// A5 #470: the board is named as the `skep` command names it — `SKEP_BOARD`
/// by variable, `--board` by flag — and `SKEPD_URL` alone is refused with
/// the line naming `SKEP_BOARD` and saying the old variable is read no
/// longer.
#[test]
fn a5_skep_board_is_read_and_skepd_url_alone_is_refused_naming_skep_board() {
    let fixture = Fixture::new("a5");
    let mut by_variable = Launch::over(&fixture, 1).spawn();
    assert_eq!(by_variable.initialize()["serverInfo"]["name"], "skep");
    assert_eq!(by_variable.call_json("session_info", json!({}))["board"], fixture.origin());
    assert!(by_variable.finish().success());
    let mut by_flag = Launch::new().args(["--board", &fixture.origin(), "--dir", fixture.store.to_str().expect("a UTF-8 path"), "--principal", "1"]).spawn();
    assert_eq!(by_flag.initialize()["serverInfo"]["name"], "skep");
    assert!(by_flag.finish().success());
    let (code, err) = Launch::new().env("SKEPD_URL", fixture.origin()).env("SKEP_KEYSTORE", &fixture.store).env("SKEP_PRINCIPAL", "1").refusal();
    assert_eq!(code, Some(1), "{err}");
    assert!(err.contains("--board (or SKEP_BOARD) is required"), "{err}");
    assert!(err.contains("SKEPD_URL is set and no longer read"), "{err}");
    let (code, err) = Launch::new().env("SKEP_BOARD", "127.0.0.1:8642").env("SKEP_KEYSTORE", &fixture.store).env("SKEP_PRINCIPAL", "1").refusal();
    assert_eq!(code, Some(1), "{err}");
    assert!(err.contains("is not a canonical origin"), "{err}");
}

/// A6: a retired key stops the adapter, and a relaunch refuses it.
///
/// A second key is enrolled into the claimant's set from the claimant's own
/// device, then the adapter's key retired from the second device's store —
/// the retirement of a set's last key being refused, "it would empty the
/// set" — and the adapter's session dies on the `retired` arm, which the
/// shell does not re-open (ruling 4 (c)): the process stops, exit 1, with one
/// plain line naming the retirement and the hand, and how long the stop
/// waited behind earlier calls, its clean stop saying the session already
/// ended at the board, and serves nothing after. Started again over the same
/// store, it stays stopped: the open is refused `retired` before anything is
/// served, and no bare session stands in.
#[test]
fn a6_a_retired_key_stops_the_adapter_and_a_relaunch_refuses_before_serving() {
    let fixture = Fixture::new("a6-retired");
    let mut mcp = Launch::over(&fixture, 1).logged().spawn();
    mcp.initialize();
    assert_eq!(mcp.call_json("session_info", json!({}))["writes"], true);
    let second = fixture.dir.path().join("second");
    let k2 = fixture.enroll_second_key(&second, "second");
    fixture.retire_from(&second, &fixture.fingerprint);
    let status = mcp.wait_exit(Duration::from_secs(60)).unwrap_or_else(|| panic!("the adapter did not stop:\n{}", mcp.log()));
    assert_eq!(status.code(), Some(1), "{status:?}\n{}", mcp.log());
    let log = mcp.log_holding(&["stopped: the key ", "; the stop waited ", "stopping: the session already ended at the board"], Duration::from_secs(5));
    assert!(
        log.contains(&format!("stopped: the key {} was retired at the board by the key {k2} (second): the person who enrolled it stops this agent so", fixture.fingerprint)),
        "the plain line:\n{log}"
    );
    assert!(log.contains("a relaunch over this store is refused `retired` until the person gives the agent a key enrolled anew"), "the act that clears it:\n{log}");
    assert!(mcp.stdout_closed(), "nothing is served after the stop");
    let out = Launch::over(&fixture, 1).output();
    assert_eq!(out.status.code(), Some(1), "a relaunch with the retired key refuses: {out:?}");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("stopped before serving: the signed session did not open: retired"), "the refusal names the retirement:\n{err}");
    assert!(out.stdout.is_empty(), "nothing is served: {:?}", String::from_utf8_lossy(&out.stdout));
}

/// A6 THE SESSION's LIFE, a re-open the board refuses: the board restarted
/// as a board moved to another name — its signed arm reads another origin
/// alone — so the restart arm's re-open meets the origin state and the
/// shell does not re-open; the process STOPS, exit 1, naming the refusal.
#[test]
fn a6_a_reopen_the_board_refuses_stops_naming_the_refusal() {
    let mut fixture = Fixture::new("a6-refused");
    let mut mcp = Launch::over(&fixture, 1).logged().spawn();
    mcp.initialize();
    assert_eq!(mcp.call_json("session_info", json!({}))["writes"], true);
    fixture.restart_signing_elsewhere();
    let status = mcp.wait_exit(Duration::from_secs(60)).unwrap_or_else(|| panic!("the adapter did not stop:\n{}", mcp.log()));
    assert_eq!(status.code(), Some(1), "{status:?}\n{}", mcp.log());
    let log = mcp.log_holding(&["refused this key at the re-open (origin_state)"], Duration::from_secs(5));
    assert!(log.contains("stopped: the board restarted and refused this key at the re-open (origin_state)"), "{log}");
}

/// A6 THE SESSION's LIFE, the board gone: a read and a non-burst write
/// answer `isError` `unreachable` and the adapter stays up, answering;
/// a burst is HELD as data (`resp: held`, `cause: unreachable`); the board
/// back, the restart arm re-opens the session, the held burst is resent
/// and lands, and the next read answers (the mutant that never swaps the
/// reference serves `session_ended` after the board's return).
#[test]
fn a6_a_board_that_is_gone_answers_unreachable_and_the_adapter_stays_up() {
    let mut fixture = Fixture::new("a6-gone");
    let mut mcp = Launch::over(&fixture, 1).logged().spawn();
    mcp.initialize();
    let draft = draft_of(&mut mcp, CLAIMANT_ACCOUNT);
    fixture.stop();
    let read = mcp.call_error("doc_metadata", json!({"doc": draft}));
    assert_eq!(read["kind"], "unreachable", "{read}");
    let mint = mcp.call_error("create_new_document", json!({"account": CLAIMANT_ACCOUNT}));
    assert_eq!(mint["kind"], "unreachable", "a non-burst write is faced: {mint}");
    let held = mcp.call_json("insert", json!({"doc": draft, "at": {"subspace": "1", "ordinal": "1"}, "values": ["held"]}));
    assert_eq!((held["resp"].as_str(), held["cause"].as_str()), (Some("held"), Some("unreachable")), "a burst is held: {held}");
    let lines = mcp.call_json("held", json!({}));
    assert_eq!(lines[0]["doc"], draft, "{lines}");
    assert_eq!(mcp.request("ping", json!({}))["result"], json!({}), "the adapter keeps answering");
    fixture.restart();
    let meta = mcp.call_json("doc_metadata", json!({"doc": draft}));
    assert_eq!(meta["resp"], "doc_metadata", "the board back, the read answers: {meta}\n{}", mcp.log());
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        if mcp.call_json("held", json!({})) == json!([]) {
            break;
        }
        assert!(Instant::now() < deadline, "the held burst was never resent:\n{}", mcp.log());
        std::thread::sleep(Duration::from_millis(200));
    }
    let read = mcp.call_json("retrieve_v", json!({"specs": [{"doc": draft, "span": {"start": "1.1", "width": "0.4"}}]}));
    assert_eq!(read["items"], json!([{"content": "held"}]), "the held burst landed: {read}");
    let (status, log) = mcp.finish_logged();
    assert!(status.success(), "{status:?}\n{log}");
    assert!(log.contains("re-opened under a fresh reference"), "{log}");
}

/// A7 A REFUSAL AS A RESULT (ruling 3 (a)): the board's rejection of a
/// frame rides as data — `isError` false, the verdict's body verbatim, the
/// refusal's `name` the token — a non-200 verdict too; and the board
/// unreachable is `isError` true with the refusal's value (the mutant that
/// marks every refusal `isError` fails the rejection; the one that marks
/// none fails the unreachable board).
#[test]
fn a7_a_board_rejection_is_data_and_an_unreachable_board_is_an_error() {
    let mut fixture = Fixture::new("a7");
    let mut mcp = Launch::over(&fixture, 1).spawn();
    mcp.initialize();
    let (is_error, text) = mcp.call("retrieve_v", json!({"specs": [{"doc": "1.0.9.0.1", "span": {"start": "1.1", "width": "0.1"}}]}));
    assert!(!is_error, "{text}");
    let v: Value = serde_json::from_str(&text).expect("JSON");
    assert_eq!((v["kind"].as_str(), v["name"].as_str(), v["status"].as_u64(), v["op"].as_str()), (Some("refused"), Some("doc_not_registered"), Some(200), Some("retrieve_v")), "{v}");
    assert_eq!(v["body"], json!({"code": "doc_not_registered", "disposition": "reorder", "op": "retrieve_v", "resp": "rejected", "site": {"addr": "1.0.9.0.1"}}), "the verdict verbatim: {v}");
    let (is_error, text) = mcp.call("delegate", json!({"new_prefix": "1.0.9", "new_id": 9}));
    assert!(!is_error, "{text}");
    let v: Value = serde_json::from_str(&text).expect("JSON");
    assert_eq!((v["kind"].as_str(), v["body"]["resp"].as_str()), (Some("refused"), Some("rejected")), "{v}");
    let (is_error, text) = mcp.call("fetch", json!({"i": format!("{CLAIMANT_DOC1}.0.1.1")}));
    assert!(!is_error, "a non-200 verdict is data too: {text}");
    let v: Value = serde_json::from_str(&text).expect("JSON");
    assert_eq!((v["kind"].as_str(), v["status"].as_u64(), v["name"].as_str()), (Some("refused"), Some(404), Some("not_a_cell")), "{v}");
    fixture.stop();
    let (is_error, text) = mcp.call("doc_metadata", json!({"doc": CLAIMANT_DOC1}));
    assert!(is_error, "{text}");
    let v: Value = serde_json::from_str(&text).expect("JSON");
    assert_eq!((v["kind"].as_str(), v["name"].as_str()), (Some("unreachable"), Some("unreachable")), "{v}");
    assert!(v["text"].as_str().is_some_and(|t| !t.is_empty()), "{v}");
    let (is_error, text) = mcp.call("session_info", json!({}));
    assert!(is_error, "session_info needs the board's health: {text}");
    fixture.restart();
    assert!(mcp.finish().success());
}

/// A7: a write whose answer is lost is unreachable, and lands once.
///
/// The board's write guard is held, so the write parks inside the daemon
/// with its permit, its frame read, until skep-client's read bound ends the
/// exchange: the call answers `isError`, `unreachable`, the pool one permit
/// short — exactly one attempt reached the board (a reissue parks a second).
/// Released, the write commits, as the catalog warns it may — its document
/// reads back — and once: the next mint is the one after it. The call held
/// the loop past a dial's read bound, and the log says so, by its tool and
/// its answer. A call read behind the parked write waits out its read bound,
/// the loop serving one call at a time, and the log says that call too, for
/// its wait: its own time is no part of it.
#[test]
fn a7_a_write_whose_answer_is_lost_is_unreachable_and_lands_once() {
    let fixture = Fixture::alone("a7-lost");
    let mut mcp = Launch::over(&fixture, 1).logged().spawn();
    mcp.initialize();
    let before = draft_of(&mut mcp, CLAIMANT_ACCOUNT);
    let pool = fixture.free_write_permits();
    let hold = WriteGuardHeld::arm(&fixture);
    // `boards` dials nothing: its own time is the loop's alone.
    mcp.send_line(&json!({"jsonrpc": "2.0", "id": "lost", "method": "tools/call", "params": {"name": "create_new_document", "arguments": {"account": CLAIMANT_ACCOUNT}}}).to_string());
    mcp.send_line(&json!({"jsonrpc": "2.0", "id": "behind", "method": "tools/call", "params": {"name": "boards", "arguments": {}}}).to_string());
    let answered = mcp.read_message();
    assert_eq!((&answered["id"], &answered["result"]["isError"]), (&json!("lost"), &json!(true)), "the lost write is answered first: {answered}");
    let lost: Value = serde_json::from_str(answered["result"]["content"][0]["text"].as_str().expect("a text block")).expect("JSON text");
    assert_eq!(lost["kind"], "unreachable", "a lost answer is faced unreachable: {lost}");
    let behind = mcp.read_message();
    assert_eq!((&behind["id"], &behind["result"]["isError"]), (&json!("behind"), &json!(false)), "the call behind it is served next: {behind}");
    mcp.log_holding(&["the `create_new_document` call of request \"lost\" waited ", " held the loop ", " s: answered isError"], Duration::from_secs(10));
    let behind = "the `boards` call of request \"behind\" waited ";
    let log = mcp.log_holding(&[behind], Duration::from_secs(10));
    let line = log.lines().find(|line| line.contains(behind)).expect("the line behind");
    let figure = |after: &str| -> f64 { line.split(after).nth(1).and_then(|rest| rest.split(' ').next()).and_then(|n| n.parse().ok()).unwrap_or_else(|| panic!("the figure after {after:?}: {line}")) };
    assert!(line.contains(" s behind earlier calls and held the loop ") && line.ends_with(" s: answered"), "{line}");
    assert!(figure(" held the loop ") < 1.0, "said for its wait behind the parked write, not its own time: {line}");
    assert_eq!(fixture.free_write_permits(), pool - 1, "exactly one attempt reached the board, parked there");
    drop(hold);
    let deadline = Instant::now() + Duration::from_secs(30);
    while fixture.free_write_permits() < pool {
        assert!(Instant::now() < deadline, "the released write never finished");
        std::thread::sleep(Duration::from_millis(20));
    }
    let (docs, last) = before.rsplit_once('.').expect("a document address");
    let n: u64 = last.parse().expect("a document ordinal");
    let landed = mcp.call_json("doc_metadata", json!({"doc": format!("{docs}.{}", n + 1)}));
    assert_eq!(landed["resp"], "doc_metadata", "the write answered unreachable landed: {landed}");
    assert_eq!(draft_of(&mut mcp, CLAIMANT_ACCOUNT), format!("{docs}.{}", n + 2), "it landed once");
    assert!(mcp.finish().success());
}

/// A7: a write refused `poisoned` is data, and lands at the restart.
///
/// The kernel's next commit is poisoned, so the write that meets it is
/// refused `poisoned` — the board's verdict, `isError` false, disposition
/// `halt` — its frames left in the journal. The board restarted, the write
/// has landed, as the catalog warns it may: the document it minted reads
/// back.
#[test]
fn a7_a_write_refused_poisoned_is_data_and_lands_at_the_restart() {
    let mut fixture = Fixture::new("a7-poisoned");
    let mut mcp = Launch::over(&fixture, 1).spawn();
    mcp.initialize();
    let before = draft_of(&mut mcp, CLAIMANT_ACCOUNT);
    fixture.poison_the_next_commit();
    let poisoned = mcp.call_json("create_new_document", json!({"account": CLAIMANT_ACCOUNT}));
    assert_eq!((poisoned["kind"].as_str(), poisoned["name"].as_str(), poisoned["body"]["disposition"].as_str()), (Some("refused"), Some("poisoned"), Some("halt")), "{poisoned}");
    fixture.restart();
    let (docs, last) = before.rsplit_once('.').expect("a document address");
    let n: u64 = last.parse().expect("a document ordinal");
    let landed = mcp.call_json("doc_metadata", json!({"doc": format!("{docs}.{}", n + 1)}));
    assert_eq!(landed["resp"], "doc_metadata", "the write refused poisoned landed at the restart: {landed}");
    assert!(mcp.finish().success());
}

/// A7: a burst the board refuses is held, and the bursts behind it wait.
///
/// An insert at an ordinal past the draft's end is rejected `out_of_bounds`,
/// a permanent rejection — and, a burst, answers `held` as data, its cause
/// the rejection's token and held() listing the board's verdict beside its
/// line, never the `refused` verdict a write that is no burst answers. A
/// later insert on the draft answers `held`, cause `behind`, unsent;
/// `resolve(drop)` drops the refused line and the line behind it, neither of
/// which lands — the draft's frontier counts the one insert acked after —
/// and an insert into the published home is held as its rejection's run too.
#[test]
fn a7_a_burst_the_board_refuses_is_held_and_the_bursts_behind_it_wait() {
    let fixture = Fixture::new("a7-refused-run");
    let mut mcp = Launch::over(&fixture, 1).spawn();
    mcp.initialize();
    let draft = draft_of(&mut mcp, CLAIMANT_ACCOUNT);
    let refused = mcp.call_json("insert", json!({"doc": draft, "at": {"subspace": "1", "ordinal": "900000"}, "values": ["r"]}));
    assert_eq!(refused["resp"], "held", "a rejected burst is held, as data: {refused}");
    assert!(refused["cause"].as_str().is_some_and(|c| c.starts_with("out_of_bounds")), "its cause the rejection's token: {refused}");
    let lines = mcp.call_json("held", json!({}));
    assert_eq!(lines[0]["refusal"]["code"], "out_of_bounds", "the board's verdict beside the line: {lines}");
    let behind = mcp.call_json("insert", json!({"doc": draft, "at": {"subspace": "1", "ordinal": "1"}, "values": ["s"]}));
    assert_eq!((behind["resp"].as_str(), behind["cause"].as_str()), (Some("held"), Some("behind")), "a later burst waits behind it: {behind}");
    let k = refused["held"].as_u64().expect("the refused line's ordinal");
    assert_eq!(mcp.call_json("resolve", json!({"held": k, "act": "drop"})), json!({}));
    assert_eq!(mcp.call_json("held", json!({})), json!([]), "the drop takes the line behind it too");
    mcp.acked("insert", json!({"doc": draft, "at": {"subspace": "1", "ordinal": "1"}, "values": ["t"]}));
    let frontier = mcp.call_json("content_frontier", json!({"doc": draft}));
    assert_eq!(frontier["next"], "2", "the insert acked is the one value the draft minted: neither dropped line landed: {frontier}");
    let home = mcp.call_json("insert", json!({"doc": CLAIMANT_DOC1, "at": {"subspace": "1", "ordinal": "1"}, "values": ["h"]}));
    assert_eq!(home["resp"], "held", "an insert into the published home is held: {home}");
    assert!(home["cause"].as_str().is_some_and(|c| c.starts_with("published_target")), "its cause the rejection's token: {home}");
    assert!(mcp.finish().success());
}

/// A8: talk lines go to stderr alone, and stdin's end closes the session.
///
/// Every line on stdout is JSON-RPC, while the shell's talk — the feed thread's
/// lines at a restart, and the adapter's own re-open line, the drain's — goes
/// to stderr under the adapter's prefix, each line opening on the moment it
/// was said; and stdin's end closes the session at the board: the end is
/// said, then the stop line with what the loop answered, how busy it was and
/// the longest a request waited, then the shell's stop's time, the shell's
/// close met no silence, exit 0.
#[test]
fn a8_talk_lines_go_to_stderr_never_stdout_and_eof_closes_the_session() {
    let mut fixture = Fixture::new("a8");
    let mut mcp = Launch::over(&fixture, 1).logged().spawn();
    mcp.initialize();
    let draft = draft_of(&mut mcp, CLAIMANT_ACCOUNT);
    fixture.restart();
    // The write after the restart answers on stdout, which the driver
    // parses line by line, while the drain says the re-open on talk.
    let v = mcp.call_json("insert", json!({"doc": draft, "at": {"subspace": "1", "ordinal": "1"}, "values": ["x"]}));
    assert_eq!(v["resp"], "ack_addr", "{v}");
    for _ in 0..3 {
        assert_eq!(mcp.request("ping", json!({}))["result"], json!({}));
    }
    let (status, log) = mcp.finish_logged();
    assert!(status.success(), "{status:?}\n{log}");
    assert!(log.contains("re-opened under a fresh reference"), "the drain's re-open line, on stderr:\n{log}");
    assert!(log.lines().filter(|l| !l.is_empty()).all(|l| l.starts_with("skep-mcp: ") || l.starts_with("  ")), "every stderr line is the adapter's stream:\n{log}");
    for line in log.lines().filter(|l| l.starts_with("skep-mcp: ")) {
        assert!(stamped(line).is_some(), "each line opens on the moment it was said: {line}");
    }
    let ended = log.find("stdin's end: no request follows").unwrap_or_else(|| panic!("the end said:\n{log}"));
    let stopping = log.find("stopping: closing the session at the board, saving the index").unwrap_or_else(|| panic!("the stop said:\n{log}"));
    assert!(ended < stopping, "the end's cause before the stop's line:\n{log}");
    // The initialize, the draft's mint, the insert and the three pings.
    let stop = log[stopping..].lines().next().unwrap_or_default();
    assert!(
        stop.contains(" — 6 answers written in ") && stop.contains(" s of it: 2 tool results, 0 of them isError, and 0 JSON-RPC errors; no request waited longer than "),
        "the stop says what the loop answered: {stop}"
    );
    assert!(stop.contains(" s of serving, the loop busy ") && stop.ends_with(" s behind earlier calls"), "and how busy the loop was, and its longest wait: {stop}");
    let took = log[stopping..].lines().skip(1).filter_map(stamped).any(|(_, text)| text.starts_with("the shell's stop took "));
    assert!(took, "the stop's time, said once it returned, after the stop's line:\n{log}");
    assert!(!log.contains("did not close"), "the board closed the session:\n{log}");
}
