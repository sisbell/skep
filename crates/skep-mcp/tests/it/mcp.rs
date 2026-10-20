//! The protocol and the tools, end to end against a real board.
//!
//! An in-process skepd on an ephemeral port over a temp data dir, its board
//! claimed through the library so the adapter's store holds the claimant's key,
//! and the built `skep-mcp` binary spawned over it, real JSON-RPC driven
//! through its stdin/stdout. Store semantics are trusted to the stores' own
//! tests; these assert the adapter: the protocol's framing and codes, the
//! tools' frames and answers, the board's verdict as data, the shell's own
//! refusal of a frame it cannot send, the session's re-open across a daemon
//! restart, the token and the key's seed in no answer and no log line, and its
//! own streams — a log no one reads fails no work, a closed stdout ends it.
//! Startup is `startup.rs`'s; the fence's cases are `agent.rs`'s; the daemon,
//! the claim and the driver are `common`'s.

use std::io::{Read, Write};
use std::process::Stdio;
use std::time::{Duration, Instant};

use serde_json::json;

use crate::common::{draft_of, embedded_catalog, holds_a_token, Fixture, Launch, AGENT_SPACE, CLAIMANT_ACCOUNT, CLAIMANT_DOC1};

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

// ── the tests ────────────────────────────────────────────────────────────

/// `initialize` and `tools/list` answer the catalog the binary embeds.
///
/// `initialize` answers 2025-06-18 to a client naming it, the server's name and
/// version, its instructions and the tools capability; `tools/list` is the
/// tools file's entries verbatim, in file order; stdin's end is the clean exit.
#[test]
fn initialize_and_tools_list_serve_the_catalog() {
    let fixture = Fixture::new("catalog");
    let mut mcp = Launch::over(&fixture, 1).spawn();
    let init = mcp.initialize();
    assert_eq!(init["protocolVersion"], "2025-06-18", "a client naming 2025-06-18 is answered it — also the fallback, so this cannot tell an echo from a constant");
    assert_eq!(init["serverInfo"]["name"], "skep");
    assert_eq!(init["serverInfo"]["version"], env!("CARGO_PKG_VERSION"), "MCP's Implementation names its version: {init}");
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

/// `initialize` answers the revision the client names, as it names it.
///
/// A client naming 2024-11-05 is answered 2024-11-05: the echo `respond`
/// states, where MCP 2025-06-18's version negotiation has a server answer a
/// revision it supports, and this adapter names no such set.
#[test]
fn initialize_answers_the_revision_the_client_names() {
    let fixture = Fixture::new("echo");
    let mut mcp = Launch::over(&fixture, 1).spawn();
    let v = mcp.request("initialize", json!({"protocolVersion": "2024-11-05", "capabilities": {}}));
    assert_eq!(v["result"]["protocolVersion"], "2024-11-05", "{v}");
    assert!(mcp.finish().success());
}

/// A notification is consumed, and nothing it names runs.
///
/// A `tools/call` sent with no id — a mint's — answers nothing and mints
/// nothing: the draft minted next is the one after the draft minted before
/// it, and the next request's answer is the next line on stdout.
#[test]
fn a_tools_call_sent_as_a_notification_runs_nothing() {
    let fixture = Fixture::new("notified");
    let mut mcp = Launch::over(&fixture, 1).spawn();
    mcp.initialize();
    let before = draft_of(&mut mcp, CLAIMANT_ACCOUNT);
    mcp.send_line(&json!({"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "create_new_document", "arguments": {"account": CLAIMANT_ACCOUNT}}}).to_string());
    let after = draft_of(&mut mcp, CLAIMANT_ACCOUNT);
    let (docs, last) = before.rsplit_once('.').expect("a document address");
    let n: u64 = last.parse().expect("a document ordinal");
    assert_eq!(after, format!("{docs}.{}", n + 1), "the notification minted nothing");
    assert!(mcp.finish().success());
}

/// `session_info` reports who the adapter acts as, and its session's facts.
///
/// The principal, its account, the key it signs with — the claimant's, by
/// fingerprint and label — the board's origin, `writes`, the board's mode and
/// its `/health` answer whole, `log_position` among its members.
#[test]
fn session_info_reports_who_the_adapter_acts_as() {
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

/// `insert` seats a string byte by byte, and an atom at one position.
///
/// "hello" is five values at five positions, read back over width 0.5 as one
/// content item; an atom inserted after it is one value at one position, never
/// coalesced into the run, read back as its own item.
#[test]
fn insert_seats_a_string_byte_by_byte_and_an_atom_at_one_position() {
    let fixture = Fixture::new("life");
    let mut mcp = Launch::over(&fixture, 1).spawn();
    mcp.initialize();

    // create → insert → retrieve. The string write form is per-byte:
    // "hello" seats five values at positions 1..=5, so width "0.5" covers
    // it exactly and the delivery is one content item.
    let doc = draft_of(&mut mcp, CLAIMANT_ACCOUNT);
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
    assert!(mcp.finish().success());
}

/// `make_link` takes `from_` as the wire's `from`; `follow_link` reads TO.
///
/// A link from five positions of one draft to six of another, typed by a
/// third's first, acks through the schema's `from_`, and its TO slot's coverage
/// reads back nonempty.
#[test]
fn make_link_takes_from_as_the_wires_from_and_follow_link_reads_the_to_slot() {
    let fixture = Fixture::new("life-link");
    let mut mcp = Launch::over(&fixture, 1).spawn();
    mcp.initialize();
    let doc = draft_of(&mut mcp, CLAIMANT_ACCOUNT);
    let v = mcp.call_json("insert", json!({"doc": doc, "at": {"subspace": "1", "ordinal": "1"}, "values": ["hello"]}));
    assert_eq!(v["resp"], "ack_addr", "insert: {v}");

    // make_link (through the schema's from_ → the wire's from) and
    // follow_link on the TO slot.
    let doc2 = draft_of(&mut mcp, CLAIMANT_ACCOUNT);
    let v = mcp.call_json("insert", json!({"doc": doc2, "at": {"subspace": "1", "ordinal": "1"}, "values": ["linked"]}));
    assert_eq!(v["resp"], "ack_addr");
    let tdoc = draft_of(&mut mcp, CLAIMANT_ACCOUNT);
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
    let doc = draft_of(&mut mcp, CLAIMANT_ACCOUNT);
    let v = mcp.call_json("insert", json!({"doc": doc, "at": {"subspace": "1", "ordinal": "1"}, "values": ["hello"]}));
    assert_eq!(v["resp"], "ack_addr", "the pre-restart write: {v}");

    fixture.restart();

    let v = mcp.call_json("insert", json!({"doc": doc, "at": {"subspace": "1", "ordinal": "6"}, "values": [", wire"]}));
    assert_eq!(v["resp"], "ack_addr", "the write after restart must succeed: {v}\n{}", mcp.log());

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

    let doc = draft_of(&mut mcp, CLAIMANT_ACCOUNT);
    let v = mcp.call_json("insert", json!({"doc": doc, "at": {"subspace": "1", "ordinal": "1"}, "values": ["hello"]}));
    assert_eq!(v["resp"], "ack_addr", "insert: {v}");
    let i_start = v["addr"].as_str().expect("first minted I-address").to_string();

    let doc2 = draft_of(&mut mcp, CLAIMANT_ACCOUNT);
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
    let doc = draft_of(&mut mcp, CLAIMANT_ACCOUNT);

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

/// A frame the shell cannot send is refused before the board sees it.
///
/// The board's strict parse judges a wire op's frame once the shell sends it;
/// the shell judges some first, nothing sent. Its own refusals are `isError`:
/// an insert — a burst — whose `doc` is an account, no document address, at
/// the burst's door (`malformed_args` naming `frame.doc`), no line held; and a
/// `create_new_document`, a kind the session's key attests, whose `account` is
/// no address, at the attest's composer (`attest_not_composed`, a halt). The
/// board's refusal of a read the composer makes is data, that read's verdict:
/// a `make_link` whose `from_` slot reads a document the board does not
/// register is answered `image`'s refusal, never `make_link`'s.
#[test]
fn a_frame_the_shell_cannot_send_is_refused_before_the_board_sees_it() {
    let fixture = Fixture::new("shell-refuses");
    let mut mcp = Launch::over(&fixture, 1).spawn();
    mcp.initialize();
    let refused = mcp.call_error("insert", json!({"doc": CLAIMANT_ACCOUNT, "at": {"subspace": "1", "ordinal": "1"}, "values": ["x"]}));
    assert_eq!((refused["kind"].as_str(), refused["name"].as_str(), refused["what"].as_str()), (Some("shell"), Some("malformed_args"), Some("frame.doc")), "the burst's door: {refused}");
    assert_eq!(mcp.call_json("held", json!({})), json!([]), "no line held");
    let halted = mcp.call_error("create_new_document", json!({"account": 7}));
    assert_eq!((halted["kind"].as_str(), halted["name"].as_str()), (Some("halt"), Some("attest_not_composed")), "the attest's composer: {halted}");
    let doc = draft_of(&mut mcp, CLAIMANT_ACCOUNT);
    let unread = json!([{"source": "1.0.9.0.1", "span": {"start": "1.1", "width": "0.1"}}]);
    let read = mcp.call_json("make_link", json!({"home": doc, "from_": unread, "to": {"addrs": [doc]}, "ty": {"addrs": [doc]}}));
    assert_eq!((read["kind"].as_str(), read["op"].as_str()), (Some("refused"), Some("image")), "the composer's read refused, as data: {read}");
    assert!(mcp.finish().success());
}

/// `doc_metadata` IS DISPATCHED (the fork-source design record, decision 10),
/// *every tool is one call of the shell* holding — the name the frame's `op`,
/// the arguments the frame — and its answer carries the `source` a fork was
/// born sharing.
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

/// No session token and no key seed reaches a tool result or a log line.
///
/// Not in a tool result — an answer, a refusal, or `session_info` — and not
/// in a log line, across the session's open, a restart's re-open and the
/// stop. The shell's references (`s-…`, `b-…`) are names, never the token;
/// a 32-lowercase-hex run is the token's shape, and none appears. The key's
/// private seed is read off the store's own key file, so the test knows
/// exactly what must never appear.
#[test]
fn no_session_token_and_no_key_seed_reaches_a_tool_result_or_a_log_line() {
    let mut fixture = Fixture::new("token");
    let seed = fixture.key_seed_hex();
    let mut mcp = Launch::over(&fixture, 1).logged().spawn();
    mcp.initialize();
    let mut texts = Vec::new();
    texts.push(mcp.call("session_info", json!({})).1);
    let doc = draft_of(&mut mcp, CLAIMANT_ACCOUNT);
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
        assert!(!text.contains(&seed), "the key's seed in an answer: {text}");
    }
    assert!(!holds_a_token(&log), "a token-shaped run in the log:\n{log}");
    assert!(!log.contains(&seed), "the key's seed in the log:\n{log}");
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
    let doc = draft_of(&mut mcp, CLAIMANT_ACCOUNT);
    let v = mcp.call_json("insert", json!({"doc": doc, "at": {"subspace": "1", "ordinal": "1"}, "values": ["x"]}));
    assert_eq!(v["resp"], "ack_addr", "{v}");
    assert!(mcp.finish().success(), "the clean exit, its log unwritable");
    let (reader, writer) = std::io::pipe().expect("a pipe");
    drop(reader);
    let (code, _) = Launch::new().env("SKEP_BOARD", fixture.origin()).env("SKEP_KEYSTORE", &fixture.store).stderr(Stdio::from(writer)).refusal();
    assert_eq!(code, Some(1), "a refusal its log cannot carry is still exit 1");
}

/// A call the adapter will not run is -32602; one of the wrong form, refused.
///
/// The adapter's own refusals of a call it will not run take the channel
/// `call_params`' faults take, params that name no tool among them — -32602
/// under the call's id, never `isError`: a name outside the catalog, a
/// ceremony's name among them; an argument an adapter tool's row does not take,
/// or its `opts` (the adapter is the one party that refuses those: ignored, a
/// `principal` of 2 to `session_info` would be answered with this adapter's own
/// facts, as if they were 2's, and a misspelt `under` would list the whole
/// index as though narrowed; an `under` to `changes_since` is a narrowing the
/// tool does not take yet), `search`'s `reindex` among them, the refresh of
/// every unit the index holds, which the door withholds from an agent; and a
/// wire op's arguments of the shape the shell reads as its `/op-at` form, whose
/// inner frame it would send to the board's history. A wire op's other
/// arguments pass through unread: the board's verdict on a stranger member is
/// data. A member of the wrong form, or missing, reaches the shell — `fetch`'s
/// `i`, and an adapter tool's `opts` or an option in it, which the door passes
/// on whole — which refuses it `malformed_args` naming it, `isError`; the
/// adapter never crashes on it.
#[test]
fn a_call_the_adapter_will_not_run_is_invalid_params_and_one_of_the_wrong_form_the_shells_refusal() {
    let fixture = Fixture::new("refuse");
    let mut mcp = Launch::over(&fixture, 1).spawn();
    mcp.initialize();
    for (call, names) in [
        (json!({}), "'name'"),
        (json!({"name": "frobnicate", "arguments": {}}), "'frobnicate'"),
        (json!({"name": "keygen", "arguments": {"label": "x"}}), "'keygen'"),
        (json!({"name": "session_info", "arguments": {"principal": 2}}), "'principal'"),
        (json!({"name": "search", "arguments": {"query": "x", "board": "b-1"}}), "'board'"),
        (json!({"name": "changes_since", "arguments": {"since": 0, "under": "1.0.1"}}), "'under'"),
        (json!({"name": "fetch", "arguments": {"i": "1.0.1.0.1.0.1.1", "session": "s-1"}}), "'session'"),
        (json!({"name": "places", "arguments": {"opts": {"undr": "1.0.1"}}}), "'undr'"),
        (json!({"name": "search", "arguments": {"query": "x", "opts": {"reindex": true}}}), "'reindex'"),
        (json!({"name": "doc_metadata", "arguments": {"at": 1, "frame": {"op": "retrieve_v", "specs": []}}}), "'frame'"),
    ] {
        let v = mcp.request("tools/call", call);
        assert_eq!(v["error"]["code"], json!(-32602), "{v}");
        let message = v["error"]["message"].as_str().unwrap_or_default();
        assert!(message.contains(names), "the refusal names {names}: {v}");
    }
    let v = mcp.call_json("doc_metadata", json!({"doc": CLAIMANT_DOC1, "stranger": 1}));
    assert_eq!((v["kind"].as_str(), v["body"]["op"].as_str()), (Some("refused"), Some("unparseable")), "a wire op's stranger member is the board's to refuse: {v}");
    for (tool, args, what) in [
        ("fetch", json!({}), "i"),
        ("fetch", json!({"i": 7}), "i"),
        ("fetch", json!({"i": "1..2"}), "i"),
        ("search", json!({"query": "x", "opts": {"limit": "three"}}), "opts.limit"),
        ("places", json!({"opts": {"under": 7}}), "opts.under"),
        ("places", json!({"opts": 3}), "opts"),
    ] {
        let refused = mcp.call_error(tool, args.clone());
        assert_eq!((refused["kind"].as_str(), refused["name"].as_str(), refused["what"].as_str()), (Some("shell"), Some("malformed_args"), Some(what)), "{tool} {args}: {refused}");
    }
    assert!(mcp.finish().success());
}

/// A harness that hangs up stdout ends the adapter, cleanly.
///
/// The first answer it cannot write is its exit, stdin still open — no
/// orphan goes on taking requests whose answers nobody reads — said in the log
/// with the write's own error, and the exit is the clean one: the clean stop
/// runs after that line, the session closed at the board, as at stdin's end.
#[test]
fn a_closed_stdout_ends_the_adapter() {
    let fixture = Fixture::new("hangup");
    let mut child = Launch::over(&fixture, 1).logged().child();
    let log = {
        let mut stderr = child.stderr.take().expect("the adapter's log");
        std::thread::spawn(move || {
            let mut log = String::new();
            let _ = stderr.read_to_string(&mut log);
            log
        })
    };
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
    let status = exited.unwrap_or_else(|| panic!("the adapter outlived its closed stdout by 30 s, stdin open"));
    let log = log.join().expect("the log's reader");
    assert!(status.success(), "a harness that hung up is the clean exit: {status:?}");
    let said = log.find("Z stdout: ").unwrap_or_else(|| panic!("the hang-up said, with its cause:\n{log}"));
    assert!(log[said..].contains(": the harness reads no more answers"), "{log}");
    let stopping = log.find("stopping: closing the session at the board, saving the index").unwrap_or_else(|| panic!("the clean stop ran, its session closed at the board:\n{log}"));
    assert!(said < stopping, "the end's cause before the stop's line:\n{log}");
}
