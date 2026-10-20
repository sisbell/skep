//! Integration against the real stack: an in-process skepd (it is a
//! library crate in this workspace) on an ephemeral port over a temp data
//! dir, its board claimed through the library so the adapter's store holds
//! the claimant's key, and the built `skep-mcp` binary spawned with its
//! settings naming the board — real JSON-RPC driven through its
//! stdin/stdout. Store semantics are trusted to the stores' own tests;
//! these assert the adapter: protocol framing, the board's verdict as
//! data, the session's re-open across a daemon restart, the token in no
//! answer and no log line, and startup's refusals — the settings, the
//! tools-file↔dispatch no-drift errors among them. The fence's cases — the
//! signed session, the seam, the tools, the pull, `SKEP_BOARD`, the
//! session's life, a refusal as a result, the stream — are `agent.rs`'s.
//! The daemon, the claim and the driver are `common`'s.

use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::json;

use crate::common::{embedded_catalog, holds_a_token, Fixture, Launch, TempDir, AGENT_SPACE, CLAIMANT_ACCOUNT, CLAIMANT_DOC1, VARIABLES};

/// A width tumbler at `addr`'s own depth: zeros with `last` in the final
/// component. `width_of(a, 1)` is the unit subtree span width the daemon
/// records for an address-form endset member; `width_of(a, k)` the width of
/// a k-position I-run starting at `a`.
fn width_of(addr: &str, last: u64) -> String {
    let n = addr.split('.').count();
    let mut comps = vec!["0".to_string(); n];
    comps[n - 1] = last.to_string();
    comps.join(".")
}

/// A fresh draft of the claimant's account, through the adapter.
fn draft_of(mcp: &mut crate::common::Mcp) -> String {
    mcp.acked("create_new_document", json!({"account": CLAIMANT_ACCOUNT}))["addr"].as_str().expect("doc addr").to_string()
}

// ── the tests ────────────────────────────────────────────────────────────

/// `--version` is answered before the catalog, the environment or stdin is
/// consulted: ONE line on stdout — `skep-mcp <crate version> (<commit>)`,
/// the version this test's own `CARGO_PKG_VERSION` and the commit
/// `SKEP_GIT_SHA` named at build time, `unknown` where it named none —
/// nothing on stderr, exit 0, with no setting set (a start would refuse
/// that) and stdin held open by the test, which a read of it would wait on.
#[test]
fn version_is_one_line_on_stdout_before_the_environment_or_stdin_is_read() {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_skep-mcp"));
    cmd.arg("--version").stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    for var in VARIABLES {
        cmd.env_remove(var);
    }
    let mut child = cmd.spawn().expect("spawn skep-mcp");
    let held_open = child.stdin.take().expect("child stdin");
    let status = child.wait().expect("wait for skep-mcp");
    drop(held_open);
    let (mut stdout, mut stderr) = (String::new(), String::new());
    child.stdout.take().expect("child stdout").read_to_string(&mut stdout).expect("read stdout");
    child.stderr.take().expect("child stderr").read_to_string(&mut stderr).expect("read stderr");
    assert_eq!(status.code(), Some(0), "exit 0: {stderr}");
    assert_eq!(stdout, format!("skep-mcp {} ({})\n", env!("CARGO_PKG_VERSION"), option_env!("SKEP_GIT_SHA").unwrap_or("unknown")), "the one line");
    assert!(stderr.is_empty(), "nothing on stderr: {stderr}");
}

#[test]
fn initialize_and_tools_list_serve_the_catalog() {
    let fixture = Fixture::new("catalog");
    let mut mcp = Launch::over(&fixture, 1).spawn();
    let init = mcp.initialize();
    assert_eq!(init["protocolVersion"], "2025-06-18", "a client naming 2025-06-18 is answered it — also the fallback, so this cannot tell an echo from a constant");
    assert_eq!(init["serverInfo"]["name"], "skep");
    assert!(init["instructions"].as_str().is_some_and(|s| !s.is_empty()), "instructions non-empty: {init}");
    assert!(init["capabilities"]["tools"].is_object(), "tools capability: {init}");

    let v = mcp.request("tools/list", json!({}));
    let tools = v["result"]["tools"].as_array().expect("tools array").clone();
    let listed: Vec<&str> = tools.iter().map(|t| t["name"].as_str().expect("name")).collect();
    let file = embedded_catalog();
    let expected: Vec<&str> = file["tools"].as_array().expect("file tools").iter().map(|t| t["name"].as_str().expect("file name")).collect();
    assert_eq!(listed, expected, "exactly the tools file's names, in file order");
    assert_eq!(v["result"]["tools"], file["tools"], "tools/list is the file's entries, verbatim");
    for t in &tools {
        assert!(t["description"].as_str().is_some_and(|s| !s.is_empty()), "every tool carries a description: {t}");
        assert!(t["inputSchema"].is_object(), "every tool carries a schema: {t}");
    }

    // Protocol basics alongside: ping, and unknown method → -32601.
    let v = mcp.request("ping", json!({}));
    assert_eq!(v["result"], json!({}));
    let v = mcp.request("resources/list", json!({}));
    assert_eq!(v["error"]["code"], json!(-32601), "unknown method: {v}");

    // Invalid params and an invalid request, JSON-RPC 2.0's own codes.
    let v = mcp.request("tools/call", json!({}));
    assert_eq!(v["error"]["code"], json!(-32602), "params that name no tool: {v}");
    mcp.send_line(r#"{"jsonrpc":"2.0","id":"no-method"}"#);
    let v = mcp.read_message();
    assert_eq!(v["error"]["code"], json!(-32600), "a request that names no method: {v}");
    assert_eq!(v["id"], json!("no-method"), "answered under its own id: {v}");

    // Stdin EOF is the clean exit.
    let status = mcp.finish();
    assert!(status.success(), "clean exit on stdin EOF: {status:?}");
}

/// A client that names no protocolVersion is answered the revision this
/// server was written against, 2025-06-18 — params without one, or no
/// params at all.
#[test]
fn initialize_answers_the_fallback_revision_when_none_is_named() {
    let fixture = Fixture::new("fallback");
    let mut mcp = Launch::over(&fixture, 1).spawn();
    let v = mcp.request("initialize", json!({"capabilities": {}}));
    assert_eq!(v["result"]["protocolVersion"], "2025-06-18", "params without a revision: {v}");
    mcp.send_line(r#"{"jsonrpc":"2.0","id":"bare","method":"initialize"}"#);
    let v = mcp.read_message();
    assert_eq!((&v["id"], &v["result"]["protocolVersion"]), (&json!("bare"), &json!("2025-06-18")));
}

/// `session_info` reports the adapter's standing: the principal, its
/// account, the key it signs with — the claimant's, by fingerprint and
/// label — the board's origin, `writes`, the board's mode and its health
/// document whole, `log_position` among its members.
#[test]
fn session_info_reports_the_adapters_standing() {
    let fixture = Fixture::new("sessinfo");
    let mut mcp = Launch::over(&fixture, 1).spawn();
    mcp.initialize();
    let info = mcp.call_json("session_info", json!({}));
    assert_eq!(info["principal"], json!(1));
    assert_eq!(info["account"], CLAIMANT_ACCOUNT, "{info}");
    assert_eq!(info["key"]["fingerprint"], fixture.fingerprint, "{info}");
    assert_eq!(info["key"]["label"], "notebook", "{info}");
    assert_eq!(info["board"], fixture.origin(), "{info}");
    assert_eq!(info["writes"], true, "{info}");
    assert_eq!(info["mode"], "CLAIMED-PERMISSIVE", "{info}");
    assert_eq!(info["health"]["ok"], json!(true));
    assert!(info["health"]["log_position"].is_u64(), "health rides along: {info}");
    assert_eq!(info["health"]["auth"]["claimant"], CLAIMANT_ACCOUNT, "{info}");
    assert!(mcp.finish().success());
}

#[test]
fn lifecycle_create_insert_retrieve_link_and_rejections() {
    let fixture = Fixture::new("life");
    let mut mcp = Launch::over(&fixture, 1).spawn();
    mcp.initialize();

    // create → insert → retrieve. The string write form is per-byte:
    // "hello" seats five values at positions 1..=5, so width "0.5" covers
    // it exactly and the delivery is one content item.
    let doc = draft_of(&mut mcp);
    let v = mcp.call_json("insert", json!({"doc": doc, "at": {"subspace": "1", "ordinal": "1"}, "values": ["hello"]}));
    assert_eq!(v["resp"], "ack_addr", "insert: {v}");

    let v = mcp.call_json("retrieve_v", json!({"specs": [{"doc": doc, "span": {"start": "1.1", "width": "0.5"}}]}));
    assert_eq!(v["resp"], "delivery");
    assert_eq!(v["items"], json!([{"content": "hello"}]));

    // An atom form: ONE composite value at ONE position, never coalesced
    // into the per-byte run beside it.
    let v = mcp.call_json("insert", json!({"doc": doc, "at": {"subspace": "1", "ordinal": "6"}, "values": [{"atom": "chunk"}]}));
    assert_eq!(v["resp"], "ack_addr", "atom insert: {v}");
    let v = mcp.call_json("retrieve_v", json!({"specs": [{"doc": doc, "span": {"start": "1.1", "width": "0.6"}}]}));
    assert_eq!(v["items"], json!([{"content": "hello"}, {"atom": "chunk"}]));

    // make_link (through the schema's from_ → the wire's from) and
    // follow_link on the TO slot.
    let doc2 = draft_of(&mut mcp);
    let v = mcp.call_json("insert", json!({"doc": doc2, "at": {"subspace": "1", "ordinal": "1"}, "values": ["linked"]}));
    assert_eq!(v["resp"], "ack_addr");
    let tdoc = draft_of(&mut mcp);
    let v = mcp.call_json("insert", json!({"doc": tdoc, "at": {"subspace": "1", "ordinal": "1"}, "values": ["type:jump"]}));
    assert_eq!(v["resp"], "ack_addr");

    let v = mcp.call_json(
        "make_link",
        json!({
            "home": doc,
            "from_": [{"source": doc, "span": {"start": "1.1", "width": "0.5"}}],
            "to": [{"source": doc2, "span": {"start": "1.1", "width": "0.6"}}],
            "ty": [{"source": tdoc, "span": {"start": "1.1", "width": "0.1"}}]
        }),
    );
    assert_eq!(v["resp"], "ack_addr", "make_link with from_: {v}");
    let link = v["addr"].as_str().expect("link addr").to_string();

    let v = mcp.call_json("follow_link", json!({"a": link, "slot": 2}));
    assert_eq!(v["resp"], "follow");
    assert!(v["result"]["ok"].as_array().is_some_and(|s| !s.is_empty()), "TO coverage nonempty: {v}");

    // A rejection is a NORMAL result: isError false, the board's verdict
    // verbatim under `body`, the shell's envelope beside it.
    let v = mcp.call_json("retrieve_v", json!({"specs": [{"doc": "1.0.9.0.1", "span": {"start": "1.1", "width": "0.1"}}]}));
    assert_eq!(v["kind"], "refused", "rejections pass through as content: {v}");
    assert_eq!(v["name"], "doc_not_registered");
    assert_eq!(v["body"]["resp"], "rejected", "the verdict verbatim: {v}");
    assert_eq!(v["body"]["code"], "doc_not_registered");
    assert_eq!(v["body"]["op"], "retrieve_v");

    // A malformed JSON line gets -32700 with id null, and the process
    // survives to answer the next request.
    mcp.send_line("this is not json");
    let v = mcp.read_message();
    assert_eq!(v["error"]["code"], json!(-32700), "parse error: {v}");
    assert!(v["id"].is_null(), "parse errors carry id null: {v}");
    let v = mcp.request("ping", json!({}));
    assert_eq!(v["result"], json!({}), "the adapter survives malformed input");

    // A line that is not UTF-8 is a parse error too, never the end of stdin.
    mcp.send_bytes(b"\xff\xfe\n");
    let v = mcp.read_message();
    assert_eq!(v["error"]["code"], json!(-32700), "non-UTF-8 parse error: {v}");
    assert!(v["id"].is_null(), "parse errors carry id null: {v}");
    let v = mcp.request("ping", json!({}));
    assert_eq!(v["result"], json!({}), "the adapter survives a non-UTF-8 line");
    assert!(mcp.finish().success());
}

/// The restart arm through the adapter: a write after a restart is acked.
///
/// The daemon is killed mid-session — every token dies with it — and started
/// again on the same data dir at the same port; the adapter's next write
/// answers through the session the shell re-opened silently under a fresh
/// reference, which the adapter took from the death's `session-died`, the write
/// that met it waiting for that and reissued once, so the agent sees an ack
/// (the mutant that keeps the first reference serves `session_ended` forever
/// after the restart); the log says the session was re-opened, and
/// `session_info` still answers.
#[test]
fn daemon_restart_reopens_the_session_and_reissues() {
    let mut fixture = Fixture::new("restart");
    let mut mcp = Launch::over(&fixture, 1).logged().spawn();
    mcp.initialize();
    let doc = draft_of(&mut mcp);
    let v = mcp.call_json("insert", json!({"doc": doc, "at": {"subspace": "1", "ordinal": "1"}, "values": ["hello"]}));
    assert_eq!(v["resp"], "ack_addr", "the pre-restart write: {v}");

    fixture.restart();

    let v = mcp.call_json("insert", json!({"doc": doc, "at": {"subspace": "1", "ordinal": "6"}, "values": [", wire"]}));
    assert_eq!(v["resp"], "ack_addr", "the write after restart must succeed: {v}\n{}", mcp.talk());

    let v = mcp.call_json("retrieve_v", json!({"specs": [{"doc": doc, "span": {"start": "1.1", "width": "0.11"}}]}));
    assert_eq!(v["items"], json!([{"content": "hello, wire"}]));
    let info = mcp.call_json("session_info", json!({}));
    assert_eq!(info["writes"], true, "{info}");
    let (status, log) = mcp.finish_logged();
    assert!(status.success(), "{status:?}\n{log}");
    assert!(log.contains("the board restarted: the session was re-opened under a fresh reference"), "the re-open is said:\n{log}");
}

/// Wire v5's two-form slots through the adapter, one link exercising both:
/// FROM as a V-spec array (content-resolved to permanent I-spans — the v4
/// meaning, pinned by the exact recorded span), TO and TYPE as
/// `{"addrs": […]}` (the names verbatim, one unit subtree span per
/// address, the TYPE a ghost nothing occupies).
#[test]
fn make_link_addrs_form_records_names_verbatim() {
    let fixture = Fixture::new("addrs");
    let mut mcp = Launch::over(&fixture, 1).spawn();
    mcp.initialize();

    let doc = draft_of(&mut mcp);
    let v = mcp.call_json("insert", json!({"doc": doc, "at": {"subspace": "1", "ordinal": "1"}, "values": ["hello"]}));
    assert_eq!(v["resp"], "ack_addr", "insert: {v}");
    let i_start = v["addr"].as_str().expect("first minted I-address").to_string();

    let doc2 = draft_of(&mut mcp);
    // A ghost: doc2's never-occupied subspace 3. Nothing resides there and
    // nothing has to — the addrs form records names, not contents.
    let ghost = format!("{doc2}.0.3.6.1");

    let v = mcp.call_json(
        "make_link",
        json!({
            "home": doc,
            "from_": [{"source": doc, "span": {"start": "1.1", "width": "0.5"}}],
            "to": {"addrs": [doc2]},
            "ty": {"addrs": [ghost]}
        }),
    );
    assert_eq!(v["resp"], "ack_addr", "two-form make_link: {v}");
    let link = v["addr"].as_str().expect("link addr").to_string();

    let v = mcp.call_json("read_link", json!({"a": link}));
    assert_eq!(
        v["link"]["slots"],
        json!([[{"start": i_start, "width": width_of(&i_start, 5)}], [{"start": doc2, "width": width_of(&doc2, 1)}], [{"start": ghost, "width": width_of(&ghost, 1)}]]),
        "recorded endsets — resolved I-span, then names verbatim: {v}"
    );
    assert!(mcp.finish().success());
}

/// The slot forms' failure modes are the board's verdicts, data: an object
/// mixing the two forms is the daemon's unparseable rejection, an empty
/// addrs TYPE its empty_type_resolution, and FROM spelled both ways the
/// daemon's unknown-field refusal — each `isError` false, the verdict
/// under `body`.
#[test]
fn slot_form_faults_surface_as_normal_results() {
    let fixture = Fixture::new("slotfault");
    let mut mcp = Launch::over(&fixture, 1).spawn();
    mcp.initialize();
    let doc = draft_of(&mut mcp);

    // Both forms at once in one slot: not a form ('resolve' is not a
    // make_link key), so the frame never becomes an operation.
    let v = mcp.call_json("make_link", json!({"home": doc, "from_": [], "to": [], "ty": {"addrs": ["1.1"], "resolve": []}}));
    assert_eq!(v["kind"], "refused", "mixed forms: {v}");
    assert_eq!(v["body"]["resp"], "rejected");
    assert_eq!(v["body"]["op"], "unparseable");
    assert_eq!(v["body"]["code"], "malformed");

    // An empty addrs TYPE parses; the store rejects it exactly as an empty
    // resolution always has — the type floor reads the slot as given.
    let v = mcp.call_json("make_link", json!({"home": doc, "from_": [], "to": [], "ty": {"addrs": []}}));
    assert_eq!(v["kind"], "refused", "empty addrs type: {v}");
    assert_eq!(v["name"], "empty_type_resolution");
    assert_eq!(v["body"]["code"], "empty_type_resolution");

    // FROM spelled both ways at once: the relay resolves nothing, so the
    // daemon's unknown-field refusal answers, as it would the raw frame.
    let v = mcp.call_json("make_link", json!({"home": doc, "from": [], "from_": [], "to": [], "ty": {"addrs": []}}));
    assert_eq!((&v["body"]["op"], &v["body"]["code"]), (&json!("unparseable"), &json!("malformed")), "{v}");
    assert!(v["body"]["detail"].as_str().is_some_and(|d| d.contains("from_")), "{v}");
    assert!(mcp.finish().success());
}

/// `doc_metadata` IS DISPATCHED (the fork-source design record, decision 10),
/// the first rule holding — the name the frame's `op`, the arguments the
/// frame — and its answer carries the `source` a fork was born sharing.
/// The agent space's principal, signing by reference with the claimant's
/// key, forks the claimant's published doc 1 through the adapter (a
/// cross-owner `version`, private, into its own account), then reads the
/// fork's metadata: `doc` the fork itself, `owner` its account, `source`
/// the document forked; the document forked answers `source` null; and an
/// unregistered document is the daemon's own rejection, as data.
#[test]
fn doc_metadata_is_dispatched_with_the_source_a_fork_was_born_sharing() {
    let fixture = Fixture::new("doc-metadata");
    let agent = fixture.agent_principal();
    let mut mcp = Launch::over(&fixture, agent).spawn();
    mcp.initialize();
    let forked = mcp.call_json("version", json!({"d_src": CLAIMANT_DOC1, "published": false}));
    assert_eq!(forked["resp"], "ack_addr", "the fork minted: {forked}");
    let fork = forked["addr"].as_str().expect("the fork's address").to_string();
    assert!(fork.starts_with(&format!("{AGENT_SPACE}.0.")), "a document of the agent space's own: {fork}");
    let meta = mcp.call_json("doc_metadata", json!({"doc": fork}));
    assert_eq!(meta["resp"], "doc_metadata", "{meta}");
    assert_eq!(meta["doc"], json!(fork), "the fork is its own trunk: {meta}");
    assert_eq!(meta["owner"], json!(AGENT_SPACE), "{meta}");
    assert_eq!(meta["published"], json!(false), "{meta}");
    assert_eq!(meta["source"], json!(CLAIMANT_DOC1), "born sharing the document forked: {meta}");
    assert!(meta["birth"].is_null() && meta["placed"].is_null(), "no member, no shot: {meta}");
    let meta = mcp.call_json("doc_metadata", json!({"doc": CLAIMANT_DOC1}));
    assert_eq!(meta["resp"], "doc_metadata", "{meta}");
    assert!(meta["source"].is_null(), "the document forked was minted by no `version`: {meta}");
    assert_eq!(meta["published"], json!(true), "{meta}");
    let v = mcp.call_json("doc_metadata", json!({"doc": "1.0.1.0.9.0.1.7"}));
    assert_eq!(v["kind"], "refused", "{v}");
    assert_eq!(v["body"]["code"], "doc_not_registered", "the daemon's own rejection, verbatim: {v}");
    assert_eq!(v["body"]["op"], "doc_metadata", "{v}");
    assert!(mcp.finish().success());
}

/// No session token leaves the adapter: not in a tool result — an answer,
/// a refusal, or `session_info` — and not in a log line, across the
/// session's open, a restart's re-open and the stop. The shell's
/// references (`s-…`, `b-…`) are names, never the token; a 32-lowercase-hex
/// run is the token's shape, and none appears.
#[test]
fn a_session_token_reaches_no_tool_result_and_no_log_line() {
    let mut fixture = Fixture::new("token");
    let mut mcp = Launch::over(&fixture, 1).logged().spawn();
    mcp.initialize();
    let mut texts = Vec::new();
    texts.push(mcp.call("session_info", json!({})).1);
    let doc = draft_of(&mut mcp);
    texts.push(mcp.call("insert", json!({"doc": doc, "at": {"subspace": "1", "ordinal": "1"}, "values": ["x"]})).1);
    fixture.restart();
    texts.push(mcp.call("insert", json!({"doc": doc, "at": {"subspace": "1", "ordinal": "2"}, "values": ["y"]})).1);
    texts.push(mcp.call("boards", json!({})).1);
    texts.push(mcp.call("retrieve_v", json!({"specs": [{"doc": "1.0.9.0.1", "span": {"start": "1.1", "width": "0.1"}}]})).1);
    let (status, log) = mcp.finish_logged();
    assert!(status.success(), "{status:?}");
    assert!(log.contains("re-opened under a fresh reference"), "premise: the re-open happened:\n{log}");
    for text in &texts {
        assert!(!holds_a_token(text), "a token-shaped run in an answer: {text}");
    }
    assert!(!holds_a_token(&log), "a token-shaped run in the log:\n{log}");
}

/// MCP's stdio transport lets a client ignore the server's stderr, and a
/// log no one reads fails every line written to it. No log line is worth
/// the work it reports on: startup's lines, the shell's TALK, a write's
/// answer and the clean exit all go on without it, and a refusal is still
/// exit 1.
#[test]
fn a_log_no_one_reads_fails_no_work() {
    let fixture = Fixture::new("unread");
    let (reader, writer) = std::io::pipe().expect("a pipe");
    drop(reader);
    let mut mcp = Launch::over(&fixture, 1).stderr(Stdio::from(writer)).spawn();
    mcp.initialize();
    let doc = draft_of(&mut mcp);
    let v = mcp.call_json("insert", json!({"doc": doc, "at": {"subspace": "1", "ordinal": "1"}, "values": ["x"]}));
    assert_eq!(v["resp"], "ack_addr", "{v}");
    assert!(mcp.finish().success(), "the clean exit, its log unwritable");
    let (reader, writer) = std::io::pipe().expect("a pipe");
    drop(reader);
    let (code, _) = Launch::new().env("SKEP_BOARD", fixture.origin()).env("SKEP_KEYSTORE", &fixture.store).stderr(Stdio::from(writer)).refusal();
    assert_eq!(code, Some(1), "a refusal its log cannot carry is still exit 1");
}

/// A board the adapter cannot reach stops startup: the session cannot
/// open, so nothing is served — exit 1, the plain line naming the stop and
/// the board, nothing on stdout. Port 1 sits below 1024, where no
/// unprivileged process can listen, so the connect is refused.
#[test]
fn a_board_that_does_not_answer_stops_startup() {
    let dir = TempDir::new("noboard");
    let out = Launch::new().env("SKEP_BOARD", "http://127.0.0.1:1").env("SKEP_KEYSTORE", dir.path()).env("SKEP_PRINCIPAL", "1").output();
    assert_eq!(out.status.code(), Some(1), "{out:?}");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("stopped before serving: the board did not answer"), "{err}");
    assert!(err.contains("http://127.0.0.1:1"), "the board named: {err}");
    assert!(out.stdout.is_empty(), "nothing served: {:?}", String::from_utf8_lossy(&out.stdout));
}

/// The adapter's own refusals of a call it will not run take the channel
/// call_params' faults take — -32602 under the call's id, never isError: a
/// name outside the catalog, a ceremony's name among them, and an argument
/// an adapter tool's row does not take (the adapter is the one party that
/// reads those: ignored, a `principal` of 2 to `session_info` would be
/// answered with this adapter's own standing, as if it were 2's; an
/// `under` to `changes_since` is a narrowing the tool does not take yet).
/// A wire op's arguments pass through unread: the board's verdict on a
/// stranger member is data.
#[test]
fn a_call_the_adapter_will_not_run_is_invalid_params_naming_why() {
    let fixture = Fixture::new("refuse");
    let mut mcp = Launch::over(&fixture, 1).spawn();
    mcp.initialize();
    for (call, names) in [
        (json!({"name": "frobnicate", "arguments": {}}), "'frobnicate'"),
        (json!({"name": "keygen", "arguments": {"label": "x"}}), "'keygen'"),
        (json!({"name": "session_info", "arguments": {"principal": 2}}), "'principal'"),
        (json!({"name": "search", "arguments": {"query": "x", "board": "b-1"}}), "'board'"),
        (json!({"name": "changes_since", "arguments": {"since": 0, "under": "1.0.1"}}), "'under'"),
        (json!({"name": "fetch", "arguments": {"i": "1.0.1.0.1.0.1.1", "session": "s-1"}}), "'session'"),
    ] {
        let v = mcp.request("tools/call", call);
        assert_eq!(v["error"]["code"], json!(-32602), "{v}");
        let message = v["error"]["message"].as_str().unwrap_or_default();
        assert!(message.contains(names), "the refusal names {names}: {v}");
    }
    let v = mcp.call_json("doc_metadata", json!({"doc": CLAIMANT_DOC1, "stranger": 1}));
    assert_eq!((v["kind"].as_str(), v["body"]["op"].as_str()), (Some("refused"), Some("unparseable")), "a wire op's stranger member is the board's to refuse: {v}");
    assert!(mcp.finish().success());
}

/// The principal is required and one the board seats: unset, startup
/// refuses by name; set to anything that is no integer from 0 to 2^53 − 1,
/// it refuses quoting the value; set to an id the board seats no account
/// for — 2^53 − 1, the largest a board registers, and an undelegated 2 —
/// the session's pre-check stops startup `not_registered`, exit 1, with
/// nothing served. A flag beats its variable.
#[test]
fn the_principal_is_required_and_one_the_board_seats() {
    let fixture = Fixture::new("principal");
    let (code, err) = Launch::new().env("SKEP_BOARD", fixture.origin()).env("SKEP_KEYSTORE", &fixture.store).refusal();
    assert_eq!(code, Some(1), "unset: {err}");
    assert!(err.contains("--principal (or SKEP_PRINCIPAL) is required"), "{err}");
    for bad in ["", "abc", "-1", "1.5", "9007199254740992", "18446744073709551616"] {
        let (code, err) = Launch::over(&fixture, 1).env("SKEP_PRINCIPAL", bad).refusal();
        assert_eq!(code, Some(1), "'{bad}': {err}");
        assert!(err.contains(&format!("'{bad}' is not a principal")), "{err}");
    }
    for unseated in ["9007199254740991", "2"] {
        let (code, err) = Launch::over(&fixture, 1).env("SKEP_PRINCIPAL", unseated).refusal();
        assert_eq!(code, Some(1), "{unseated}: {err}");
        assert!(err.contains("stopped before serving: the signed session did not open: not_registered"), "{unseated}: {err}");
    }
    let mut mcp = Launch::over(&fixture, 1).env("SKEP_PRINCIPAL", "2").args(["--principal", "1"]).spawn();
    mcp.initialize();
    assert_eq!(mcp.call_json("session_info", json!({}))["principal"], json!(1), "the flag beats the variable");
    assert!(mcp.finish().success());
}

/// A word the usage does not name, a flag without its value, or a flag
/// given twice, is a usage error — exit 2, the usage on stderr — never
/// ignored: a mistyped `--tools-file` must not quietly serve the embedded
/// catalog instead, nor a second `--board` quietly win.
#[test]
fn an_unknown_word_or_a_flag_without_its_value_or_given_twice_is_a_usage_error() {
    let dir = TempDir::new("usage");
    let settings = [("SKEP_BOARD", "http://127.0.0.1:1"), ("SKEP_KEYSTORE", dir.path().to_str().expect("a UTF-8 path")), ("SKEP_PRINCIPAL", "1")];
    for (args, says) in [
        (&["--tool-file", "mine.json"][..], "unknown argument '--tool-file'"),
        (&["--tools-file"][..], "--tools-file needs a value"),
        (&["--tools-file", "a.json", "--tools-file", "b.json"][..], "--tools-file is given at most once"),
        (&["--board"][..], "--board needs a value"),
        (&["--board", "http://127.0.0.1:1", "--board", "http://127.0.0.1:2"][..], "--board is given at most once"),
        (&["--principal", "1", "--principal", "2"][..], "--principal is given at most once"),
        (&["--dir"][..], "--dir needs a value"),
    ] {
        let mut launch = Launch::new().args(args);
        for (var, value) in settings {
            launch = launch.env(var, value);
        }
        let (code, err) = launch.refusal();
        assert_eq!(code, Some(2), "{args:?}: {err}");
        assert!(err.contains(says) && err.contains("usage: skep-mcp"), "{args:?}: {err}");
    }
}

/// A harness that hangs up stdout ends the adapter: the first answer it
/// cannot write is its exit, stdin still open — no orphan goes on taking
/// requests whose answers nobody reads.
#[test]
fn a_closed_stdout_ends_the_adapter() {
    let fixture = Fixture::new("hangup");
    let mut child = Launch::over(&fixture, 1).stderr(Stdio::null()).child();
    drop(child.stdout.take());
    let mut stdin = child.stdin.take().expect("child stdin");
    stdin.write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n").expect("a request");
    stdin.flush().expect("flush");
    let deadline = Instant::now() + Duration::from_secs(30);
    let exited = loop {
        match child.try_wait().expect("poll the adapter") {
            Some(status) => break Some(status),
            None if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            None => break None,
        }
    };
    if exited.is_none() {
        let _ = child.kill();
        let _ = child.wait();
    }
    drop(stdin);
    assert!(exited.is_some(), "the adapter outlived its closed stdout by 30 s, stdin open");
}

/// SKEP_COMMONS set: the instructions carry the commons sentence with the
/// address substituted, and the serving line names the commons. Unset:
/// byte-identical to the tools file's instructions.
#[test]
fn skep_commons_appends_the_commons_sentence() {
    let fixture = Fixture::new("commons");
    let file = embedded_catalog();
    let base = file["instructions"].as_str().expect("instructions").to_string();
    let template = file["commons_instructions"].as_str().expect("template").to_string();

    let commons = "1.0.2.0.9";
    let mut mcp = Launch::over(&fixture, 1).env("SKEP_COMMONS", commons).logged().spawn();
    let init = mcp.initialize();
    let expected = format!("{base}\n\n{}", template.replace("{addr}", commons));
    assert_eq!(init["instructions"].as_str(), Some(expected.as_str()), "the sentence is appended with the address substituted");
    assert!(expected.contains(&format!("{commons}.0.3.50")), "the defines-type address rides in the sentence: {expected}");
    let (status, log) = mcp.finish_logged();
    assert!(status.success());
    assert!(log.contains(", commons 1.0.2.0.9"), "the serving line names the commons:\n{log}");

    let mut mcp = Launch::over(&fixture, 1).spawn();
    let init = mcp.initialize();
    assert_eq!(init["instructions"].as_str(), Some(base.as_str()), "unset leaves the instructions byte-identical");
    assert!(mcp.finish().success());
}

/// A malformed SKEP_COMMONS refuses startup naming the variable — before
/// any dial: the board here answers nothing, and the refusal is the
/// commons' own.
#[test]
fn malformed_skep_commons_refuses_startup() {
    let dir = TempDir::new("badcommons");
    for bad in ["", "banana", "1..2", "0.1", "1.0", "1.0.0.1", "1.0.1.0.1.0.1.0.2"] {
        let (code, err) = Launch::new().env("SKEP_BOARD", "http://127.0.0.1:1").env("SKEP_KEYSTORE", dir.path()).env("SKEP_PRINCIPAL", "1").env("SKEP_COMMONS", bad).refusal();
        assert_eq!(code, Some(1), "'{bad}' must refuse startup: {err}");
        assert!(err.contains("SKEP_COMMONS"), "stderr names the variable for '{bad}': {err}");
        assert!(!err.contains("did not answer"), "refused before any dial: {err}");
    }
}

/// A variable set to bytes that are not UTF-8 is refused by name, never
/// read as unset: an unreadable SKEP_BOARD must not fall back to anything.
#[cfg(unix)]
#[test]
fn non_utf8_environment_refuses_startup() {
    use std::os::unix::ffi::OsStrExt;
    let dir = TempDir::new("nonutf8");
    let bytes = std::ffi::OsStr::from_bytes(b"\xff");
    for var in ["SKEP_PRINCIPAL", "SKEP_BOARD", "SKEP_KEYSTORE", "SKEP_COMMONS"] {
        let (code, err) = Launch::new().env("SKEP_BOARD", "http://127.0.0.1:1").env("SKEP_KEYSTORE", dir.path()).env("SKEP_PRINCIPAL", "1").env(var, bytes).refusal();
        assert_eq!(code, Some(1), "a non-UTF-8 {var} must refuse startup: {err}");
        assert!(err.contains(&format!("{var}: the value is not UTF-8 text")), "{var}: {err}");
    }
}

/// A path is an OS string: a `--tools-file` that is not UTF-8 is read as a
/// path — here one that does not exist, a refusal naming the flag — never a
/// panic in argument parsing.
#[cfg(unix)]
#[test]
fn non_utf8_tools_file_path_is_a_path() {
    use std::os::unix::ffi::OsStrExt;
    let (code, err) = Launch::new().arg("--tools-file").arg(std::ffi::OsStr::from_bytes(b"/nonexistent/\xff.json")).refusal();
    assert_eq!(code, Some(1), "a refusal, not a panic: {err}");
    assert!(err.contains("--tools-file"), "{err}");
}

/// The catalog is checked against the dispatch's two kinds in both
/// directions before any setting or dial: a file entry the dispatch
/// doesn't know — a stranger, a ceremony's name — refuses startup naming
/// it; a dispatch tool with no file entry — a wire op, an adapter tool —
/// refuses naming it; and the undoctored file starts, then exits cleanly on
/// immediate EOF.
#[test]
fn tools_file_dispatch_drift_refuses_startup_both_directions() {
    let dir = TempDir::new("drift");
    let real = embedded_catalog();

    for stranger in ["frobnicate", "retire"] {
        let mut extra = real.clone();
        extra["tools"].as_array_mut().expect("tools").push(json!({"name": stranger, "description": "no tool of the dispatch", "inputSchema": {"type": "object"}}));
        let path = dir.path().join(format!("extra-{stranger}.json"));
        std::fs::write(&path, extra.to_string()).expect("write doctored file");
        let err = tools_file_refusal(&path);
        assert!(err.contains(stranger), "stderr names the unknown tool: {err}");
    }

    for missing in ["insert", "changes_since"] {
        let mut doctored = real.clone();
        doctored["tools"].as_array_mut().expect("tools").retain(|t| t["name"] != missing);
        let path = dir.path().join(format!("missing-{missing}.json"));
        std::fs::write(&path, doctored.to_string()).expect("write doctored file");
        let err = tools_file_refusal(&path);
        assert!(err.contains(missing), "stderr names the uncovered tool: {err}");
    }

    let fixture = Fixture::new("drift-real");
    let path = dir.path().join("real.json");
    std::fs::write(&path, real.to_string()).expect("write real file");
    let out = Launch::over(&fixture, 1).args(["--tools-file", path.to_str().expect("utf-8 path")]).output();
    assert!(out.status.success(), "the real catalog must start: {}", String::from_utf8_lossy(&out.stderr));
}

/// The adapter run to completion on `tools_file`, which startup must
/// refuse before any setting is read: its stderr, the refusal.
fn tools_file_refusal(tools_file: &Path) -> String {
    let (code, err) = Launch::new().args(["--tools-file", tools_file.to_str().expect("utf-8 path")]).refusal();
    assert_eq!(code, Some(1), "a drifted tools file must refuse startup: {err}");
    assert!(err.contains("tools file:"), "{err}");
    err
}
