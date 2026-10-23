//! The two session modes against a real daemon in-process.
//!
//! The bare mode, the keyless session that reads alone: its claim through
//! the shell's own `claim` call (every public moment answered as the page
//! would), a session in the token's place, a draft the library minted under
//! its token read back as its `feed` update — the board's own row — and every
//! write of its refused `write_in_bare_session` before any dial, the board's
//! position unmoved; a history read past the head refused `beyond_head`
//! under the board's own status, `accept`'s armed names read off the real
//! walk, the stale and foreign references, the token's text, a seed the walk
//! made and the store's location in no answer, no event and no log entry — a
//! paper claim's among them — a scripted claim's anchors placed where its
//! script says, a search's query recorded nowhere, a death signal at a
//! call's own dial ending its session, and a bare session's death at a
//! restart and at the flip to `ENFORCING`. The signed mode, which writes,
//! over the same store: a publish-class write acked — the attest the shell
//! composed — and the same write under the bare mode refused before any
//! dial; every kind with an entry frame judged and acked, an `emit` and a
//! record deposited into a published document among them, each the board's
//! own `signed_session_required` under a bare session's token; a closed
//! session's drafts rows ahead of its `session-died`, a released supplement
//! keeping its drafts cursor, a session opened after its principal's narrow
//! fed from its own open, and the document index listed at the call's
//! class; the daemon's restart: the session it ended, ended once, re-opened
//! under a fresh reference its arm names, and written under; a `write_busy`
//! reissued once within the call; and a death signal met at a read the
//! attest needs ending the session. Beside them: a session's open position
//! the board's own under either mode, read before it opened; the declared
//! fields of the real answers; a close the board does not answer still the
//! shell's close, and the stop's close of one said on `Talk` as `close` says
//! it; every event held to its declaration; and the codec's private budgets,
//! each the shell's. The `session` answer saying whether its session writes,
//! under either mode. And the refusing arm, the setting of a client with no
//! person present: every secret and consent moment a walk reaches refused
//! `person_required` and answered by nothing.

use super::*;

/// Checks that the bare mode claims, opens, reads and hands the page nothing.
///
/// The bare mode is the keyless session, which reads alone: its claim, its
/// session, its reads, a draft the library minted under its token fed to the
/// page, and every write of its refused before any dial (foundations §3.3
/// state 3; the mutant that fences the guest form alone commits the bare
/// session's writes unattested) — and the page handed nothing the shell
/// builds: no token, no seed the walk made, no path under the store, in any
/// answer, event or log entry or in the refusals it binds (the faces carried
/// from `skep-client`, `no_key`'s among them, name the store as the library
/// builds them), no seed on `Talk`, no search's query in the log, on `Talk`
/// or in its refusal; and every event, and the claim's answer, held to its
/// declaration.
#[test]
fn the_bare_mode_claims_opens_reads_and_hands_the_page_nothing() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let origin = format!("http://127.0.0.1:{}", sd.port());
    let store = dir.path().join("store");
    let (shell, lines) = open_shell(&origin, &store, SessionMode::Bare { principal: 1 });
    let seen = Arc::new(Mutex::new(Vec::new()));
    let answerer = answer_moments(shell.subscribe(), Arc::clone(&shell.pending), Arc::clone(&seen));
    // boards(), and the unknown board.
    let boards = shell.call("boards", &json!({})).unwrap();
    let board = boards[0]["board"].as_str().unwrap().to_string();
    assert!(board.starts_with("b-"));
    assert_eq!(boards[0]["origin"], origin);
    assert_eq!(shell.call("health", &json!({"board": "b-nowhere"})).unwrap_err().name(), "unknown_board");
    // The claim needs a key: `no_key` before one is made.
    assert_eq!(shell.call("claim", &json!({"board": board})).unwrap_err().name(), "no_key");
    let keygen = shell.call("keygen", &json!({"label": "notebook"})).unwrap();
    assert_eq!(keygen["fingerprint"].as_str().unwrap().len(), 64);
    let rows = shell.call("fingerprint", &json!({"payload": true})).unwrap();
    assert_eq!(rows[0]["unbound"], true);
    assert!(skep_identity::parse_enroll(rows[0]["payload"].as_str().unwrap().as_bytes()).is_ok());
    // The claim through the shell: the label boxes answered by the "page".
    let claimed = shell.call("claim", &json!({"board": board, "name": "a name"})).unwrap_or_else(|r| panic!("{r}\n{}", lines.lock().unwrap().join("\n")));
    assert_eq!(claimed["account"], "1.0.1");
    assert_eq!(claimed["principal"], 1);
    assert_eq!(claimed["agent_space"], "1.0.1.1");
    crate::shapes::assert_declared("Claimed", &claimed);
    // The claimant key is bound now: its row names the binding the claim
    // appended, and no outstanding act.
    let bound = shell.call("fingerprint", &json!({})).unwrap();
    let claimant = bound.as_array().unwrap().iter().find(|row| row["fingerprint"] == keygen["fingerprint"]).expect("the claimant key is listed");
    assert_eq!(claimant["unbound"], false, "{claimant}");
    assert!(claimant["bindings"].as_array().unwrap().contains(&json!(format!("{origin} principal 1 account 1.0.1"))), "{claimant}");
    let health = shell.call("health", &json!({"board": board})).unwrap();
    assert_eq!(health["mode"], "CLAIMED-PERMISSIVE");
    assert_eq!(health["health"]["auth"]["claimant"], "1.0.1");
    let moments: Vec<Event> = seen.lock().unwrap().iter().filter(|e| e.name == EventName::Moment).cloned().collect();
    assert!(moments.iter().any(|m| m.data["kind"] == "label"), "the anchor boxes crossed as moments");
    assert!(moments.iter().all(|m| m.data["walk"] == "claim"));
    assert!(!lines.lock().unwrap().iter().any(|l| l.contains("seed")), "nothing of a seed on TALK");
    wait_for(&seen, |e| e.name == EventName::Mode && e.data["mode"] == "CLAIMED-PERMISSIVE");
    // A second claim on the claimed board, this store's: the idempotent answer.
    let again = shell.call("claim", &json!({"board": board})).unwrap();
    assert_eq!(again["account"], "1.0.1");
    // The session, in the token's place.
    let opened = shell.call("session", &json!({"board": board, "principal": 1})).unwrap();
    let session = opened["session"].as_str().unwrap().to_string();
    assert!(session.starts_with("s-"));
    assert_eq!(opened["account"], "1.0.1");
    let token = shell.sessions.get(&session).unwrap().token.as_str().to_string();
    assert_ne!(session, token);
    assert!(!session.contains(&token[..8]), "the reference is not derived from the token");
    // A draft the library itself minted under the session's token — the
    // shell commits no write of a bare session's — read back by the page
    // under it: its feed event carries the board reference.
    let session_token = shell.sessions.get(&session).unwrap().token.clone();
    let library = Board::new(Origin::parse(&origin).unwrap(), skep_client::PlainHttp::new());
    let Answer::Document(minted) = library.op(Some(&session_token), &skep_client::board::frames::create_document("1.0.1", false, None)).unwrap() else { panic!("the session stands") };
    let draft = minted["addr"].as_str().unwrap().to_string();
    let feed = wait_for(&seen, |e| e.name == EventName::Feed && e.data["update"]["docs"] == json!([draft]));
    assert_eq!(feed.data["board"], board);
    // The update's shape, this crate's own: the `/changes` row's members
    // verbatim, with `position` its `at`, `class` and, on a drafts row, the
    // `session` it was read under.
    let update = &feed.data["update"];
    assert_eq!(update["position"], update["at"]);
    assert_eq!((update["class"].as_str(), update["session"].as_str()), (Some("drafts"), Some(session.as_str())), "{update}");
    let at = update["at"].as_u64().unwrap();
    let mut row = update.clone();
    for member in ["position", "class", "session"] {
        row.as_object_mut().unwrap().remove(member);
    }
    let served = changes_under(&shell.boards[0].board, &session_token, &draft, at - 1);
    assert_eq!(served.first(), Some(&row), "the update is the row the board serves, verbatim: {update}");
    // Every write under the bare session — the keyless session, which reads
    // alone — refused before any dial: a draft's mint, an insert into the
    // draft, a publish-class mint; the board's position stands.
    let position = |v: &Value| v["health"]["log_position"].as_u64().unwrap();
    let before = position(&shell.call("health", &json!({"board": board})).unwrap());
    let writes = [
        json!({"op": "create_new_document", "account": "1.0.1"}),
        json!({"op": "insert", "doc": draft, "at": {"subspace": "1", "ordinal": "1"}, "values": ["hello"]}),
        json!({"op": "create_new_document", "account": "1.0.1", "published": true}),
    ];
    let refused: Vec<Refusal> = writes.iter().map(|frame| shell.call("op", &json!({"session": session, "frame": frame})).unwrap_err()).collect();
    for (frame, refused) in writes.iter().zip(&refused) {
        let v = refused.to_value();
        assert_eq!((refused.name(), v["kind"].as_str(), v["op"].as_str()), ("write_in_bare_session", Some("shell"), frame["op"].as_str()), "{frame}: {v}");
    }
    assert_eq!(position(&shell.call("health", &json!({"board": board})).unwrap()), before, "the refused writes committed nothing");
    // The guest form: a read answers, a write is refused without a dial.
    let guest = shell.call("op", &json!({"guest": true, "board": board, "frame": {"op": "doc_metadata", "doc": draft}})).unwrap_err();
    assert_eq!(guest.name(), "withheld", "a draft is withheld from a guest");
    let write = shell.call("op", &json!({"guest": true, "board": board, "frame": {"op": "create_new_document", "account": "1.0.1"}})).unwrap_err();
    assert_eq!(write.name(), "write_in_guest_form");
    assert_eq!(position(&shell.call("health", &json!({"board": board})).unwrap()), before, "the refused write committed nothing");
    // The write by identity is a write of the wire (`reinstate`): the guest
    // form refuses it, as it refuses every `WRITE_KINDS` member — undialed,
    // which a listener that counts its connections holds
    // (`the_guest_form_refuses_every_write_kind_of_the_wire_without_a_dial`).
    let reinstate = shell.call("op", &json!({"guest": true, "board": board, "frame": {"op": "reinstate", "doc": draft, "at": {"subspace": "1", "ordinal": "1"}, "runs": [{"origin": draft, "i_start": format!("{draft}.0.1.1"), "width": "1"}]}})).unwrap_err();
    assert_eq!(reinstate.name(), "write_in_guest_form");
    assert_eq!(position(&shell.call("health", &json!({"board": board})).unwrap()), before, "the refused reinstate committed nothing");
    // History past the head: the board's own `beyond_head` under its own
    // status, in the session form and the guest form alike — a refusal,
    // never a result.
    let past = before + 1_000_000;
    let key_set = json!({"op": "key_set", "account": "1.0.1"});
    for args in [json!({"session": session, "frame": {"at": past, "frame": key_set}}), json!({"guest": true, "board": board, "frame": {"at": past, "frame": key_set}})] {
        let refused = shell.call("op", &args).unwrap_err();
        let v = refused.to_value();
        assert_eq!((refused.name(), v["kind"].as_str(), v["status"].as_u64()), ("beyond_head", Some("refused"), Some(400)), "{v}");
        assert!(v["body"]["head"].is_u64(), "the head the board named rides its verdict: {v}");
    }
    // `accept`'s armed names, read off the real walk's halt: an address the
    // giver has not delegated, and the claim's agent space — delegated, no
    // set of its own — under an empty label, refused at the box.
    assert_eq!(shell.call("accept", &json!({"board": board, "address": "1.0.1.7"})).unwrap_err().name(), "not_delegated");
    assert_eq!(shell.call("accept", &json!({"board": board, "address": "1.0.1.1", "label": ""})).unwrap_err().name(), "empty_label");
    // Search: the index is the consumer's, read in the session form. A query
    // is recorded nowhere: no log entry, no `Talk` line, no refusal.
    let query = "zqxjvk";
    let answer = shell.call("search", &json!({"session": session, "board": board, "query": query, "opts": {"limit": 5}})).unwrap();
    assert!(answer["state"]["arm"].is_string());
    let too_long = shell.call("search", &json!({"session": session, "query": "x".repeat(2000)})).unwrap_err();
    assert_eq!(too_long.name(), "query_too_long");
    assert!(!too_long.to_value().to_string().contains("xxxxxxxx"), "the refusal holds no query text: {too_long}");
    let elsewhere = shell.call("search", &json!({"session": session, "board": "b-elsewhere", "query": "hello"})).unwrap_err();
    assert_eq!((elsewhere.name(), elsewhere.to_value()["what"].as_str()), ("malformed_args", Some("board")), "a session searches its own board");
    // Close: `{}`, the event, then the stale reference.
    assert_eq!(shell.call("close", &json!({"session": session})).unwrap(), json!({}));
    let died = wait_for(&seen, |e| e.name == EventName::SessionDied);
    assert_eq!(died.data["session"], session);
    assert_eq!(died.data["reason"]["arm"], "closed");
    assert_eq!(shell.call("op", &json!({"session": session, "frame": {"op": "doc_metadata", "doc": draft}})).unwrap_err().name(), "session_ended");
    assert_eq!(shell.call("close", &json!({"session": session})).unwrap_err().name(), "session_ended");
    // The token's text, a seed the walk made, a path under the store: in no
    // answer, no refusal, no event and no log entry — the page holds
    // nothing — and no seed on `Talk`, the shell's own window.
    let answers = [&boards, &keygen, &rows, &claimed, &bound, &health, &again, &opened, &answer];
    let refusals: Vec<Value> = refused.iter().chain([&guest, &write, &reinstate, &too_long]).map(Refusal::to_value).collect();
    let all = format!("{answers:?}{refusals:?}{:?}{:?}{:?}", died.data, seen.lock().unwrap(), shell.log().entries());
    assert!(!all.contains(&token), "the token never crosses");
    let seeds = seeds_of(&store);
    assert_eq!(seeds.len(), 3, "the device key and the two anchors");
    let talked = lines.lock().unwrap().join("\n");
    for seed in &seeds {
        assert!(!all.contains(seed.as_str()) && !talked.contains(seed.as_str()), "a seed crossed");
    }
    let store_text = store.display().to_string();
    let leaked: Vec<String> = seen.lock().unwrap().iter().map(|e| e.data.to_string()).filter(|data| data.contains(&store_text)).collect();
    assert!(leaked.is_empty() && !all.contains(&store_text), "a path under the store crossed: {leaked:?}");
    let logged = Value::from(shell.log().entries()).to_string();
    for text in [query, "xxxxxxxx"] {
        assert!(!logged.contains(text) && !talked.contains(text), "a search's query is recorded: `{text}`");
    }
    assert_events_declared(&seen.lock().unwrap());
    assert_eq!(shell.call("upload", &json!({"session": "s-gone"})).unwrap_err().name(), "session_ended");
    shell.shutdown();
    drop(shell);
    answerer.join().unwrap();
    sd.shutdown();
}

/// Checks that a closed session's drafts rows precede its `session-died`.
///
/// The drafts rows a signed session committed are `feed` events ahead of the
/// `session-died` its close emits — read under its token at the close,
/// however far the board's feed thread trails the commits — so a page that
/// closes straight after a write still sees the write, and every subscriber
/// sees one sequence.
#[test]
fn a_closed_sessions_drafts_rows_precede_its_session_died() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let origin = format!("http://127.0.0.1:{}", sd.port());
    let store = dir.path().join("store");
    claim_board(&origin, &store);
    let (shell, _) = open_shell(&origin, &store, SessionMode::Signed { principal: 1 });
    let rx = shell.subscribe();
    let board = shell.call("boards", &json!({})).unwrap()[0]["board"].as_str().unwrap().to_string();
    let session = shell.call("session", &json!({"board": board})).unwrap()["session"].as_str().unwrap().to_string();
    let draft = shell.call("op", &json!({"session": session, "frame": {"op": "create_new_document", "account": "1.0.1"}})).unwrap()["addr"].as_str().unwrap().to_string();
    shell.call("op", &json!({"session": session, "frame": {"op": "insert", "doc": draft, "at": {"subspace": "1", "ordinal": "1"}, "values": ["x"]}})).unwrap();
    shell.call("close", &json!({"session": session})).unwrap();
    // The close has answered: everything it emitted is on the stream.
    let seen: Vec<Event> = rx.try_iter().filter(|e| e.name == EventName::Feed || e.name == EventName::SessionDied).collect();
    let sequence: Vec<&str> = seen.iter().map(|e| if e.name == EventName::Feed { e.data["update"]["op"].as_str().unwrap_or("?") } else { e.name.as_str() }).collect();
    assert_eq!(sequence, ["create_new_document", "insert", "session-died"], "{seen:?}");
    assert!(seen[..2].iter().all(|e| e.data["update"]["class"] == "drafts" && e.data["update"]["session"] == session), "{seen:?}");
    shell.shutdown();
    sd.shutdown();
}

/// Checks that the signed mode composes the attest a publish-class write needs.
///
/// The store that claimed the board opens a content-scoped session and a
/// publish-class write is acked — the attest the shell composed — its `feed`
/// update the guest feed's own row, of the `published` class and naming no
/// session; the same write under the bare mode, the keyless session that
/// reads alone, is refused before any dial.
#[test]
fn the_signed_mode_composes_the_attest_a_publish_class_write_needs() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let origin = format!("http://127.0.0.1:{}", sd.port());
    let store = dir.path().join("store");
    claim_board(&origin, &store);
    let (signed, lines) = open_shell(&origin, &store, SessionMode::Signed { principal: 1 });
    let seen = Arc::new(Mutex::new(Vec::new()));
    let _answerer = answer_moments(signed.subscribe(), Arc::clone(&signed.pending), Arc::clone(&seen));
    assert_eq!(signed.check_signed_key().unwrap().len(), 1);
    let board = signed.call("boards", &json!({})).unwrap()[0]["board"].as_str().unwrap().to_string();
    let opened = signed.call("session", &json!({"board": board})).unwrap();
    let session = opened["session"].as_str().unwrap().to_string();
    let edition = signed.call("op", &json!({"session": session, "frame": {"op": "create_new_document", "account": "1.0.1", "published": true}})).unwrap_or_else(|r| panic!("{r}\n{}", lines.lock().unwrap().join("\n")));
    assert_eq!(edition["resp"], "ack_addr", "{edition}");
    let doc = edition["addr"].as_str().unwrap().to_string();
    // The update's shape on the published class: the guest feed's own row,
    // with `position` and `class`, and no `session`.
    let at = edition["at"].as_u64().unwrap();
    let feed = wait_for(&seen, |e| e.name == EventName::Feed && e.data["update"]["at"] == at);
    let update = &feed.data["update"];
    assert_eq!((update["class"].as_str(), update.get("session")), (Some("published"), None), "{update}");
    let mut row = update.clone();
    for member in ["position", "class"] {
        row.as_object_mut().unwrap().remove(member);
    }
    let ChangesAnswer::Page(page) = signed.boards[0].board.changes(None, &ChangesQuery { since: at - 1, limit: Some(1), ..ChangesQuery::default() }).unwrap() else {
        panic!("a page of the guest feed")
    };
    assert_eq!(page.changes.first(), Some(&row), "the update is the guest feed's row, verbatim: {update}");
    // A draft, filled, then the shot into the edition: the body read back.
    let draft = signed.call("op", &json!({"session": session, "frame": {"op": "create_new_document", "account": "1.0.1"}})).unwrap()["addr"].as_str().unwrap().to_string();
    signed.call("op", &json!({"session": session, "frame": {"op": "insert", "doc": draft, "at": {"subspace": "1", "ordinal": "1"}, "values": ["abc"]}})).unwrap();
    let image = signed.call("op", &json!({"session": session, "frame": skep_client::board::frames::image(&draft, 1, 3)})).unwrap();
    let run = &image["runs"][0];
    let shot = signed
        .call("op", &json!({"session": session, "frame": {"op": "publish", "doc": doc, "draft": draft, "runs": [{"origin": draft, "i_start": run["i_start"], "width": run["width"]}]}}))
        .unwrap_or_else(|r| panic!("{r}\n{}", lines.lock().unwrap().join("\n")));
    assert_eq!(shot["resp"], "ack_addr", "{shot}");
    let member = shot["addr"].as_str().unwrap();
    let read = signed.call("op", &json!({"guest": true, "board": board, "frame": skep_client::board::frames::retrieve_v(member, 1, 3)})).unwrap();
    assert_eq!(read["items"][0]["content"], "abc");
    // A link homed in the edition, the from-end a V-spec: attested too.
    let link = signed
        .call("op", &json!({"session": session, "frame": {"op": "make_link", "home": doc, "from": [{"source": member, "span": {"start": "1.1", "width": "0.2"}}], "to": {"addrs": [draft]}, "ty": {"addrs": ["1.1.0.1.0.1.0.3.13"]}}}))
        .unwrap_or_else(|r| panic!("{r}\n{}", lines.lock().unwrap().join("\n")));
    assert_eq!(link["resp"], "ack_addr", "{link}");
    signed.call("close", &json!({"session": session})).unwrap();
    signed.shutdown();
    // The same write under the bare mode: refused before any dial.
    let (bare, _) = open_shell(&origin, &store, SessionMode::Bare { principal: 1 });
    let board = bare.call("boards", &json!({})).unwrap()[0]["board"].as_str().unwrap().to_string();
    let session = bare.call("session", &json!({"board": board})).unwrap()["session"].as_str().unwrap().to_string();
    let refused = bare.call("op", &json!({"session": session, "frame": {"op": "create_new_document", "account": "1.0.1", "published": true}})).unwrap_err();
    assert_eq!((refused.name(), refused.to_value()["kind"].as_str()), ("write_in_bare_session", Some("shell")), "{refused}");
    bare.shutdown();
    sd.shutdown();
}

/// Checks that every kind with an entry frame is judged and acked when signed.
///
/// Every kind of wire.md's checked set is judged and acked under the signed
/// session — the composer is the daemon's twin, so each kind the cell above
/// leaves unsent goes to the daemon here: a shot with a base group and a
/// window segment, `fork`, `version`, `nullify`, `assert_sup`, `edit_link`
/// with its successor's type in each of the wire's two forms,
/// `{"addrs": […]}` and `{"resolve": […]}`, and an `emit` of the PredDef
/// class — Unary, so its `to` is empty, and a class that confers no behavior
/// on what it names (wire.md's own example takes Retired, whose read filter
/// would hide the member the edit cells read). Each frame goes first under a
/// bare session of the same principal — the shell refusing it
/// `write_in_bare_session` before any dial, and the library dialing it under
/// that session's token itself — whose `signed_session_required` from the
/// board proves the write publish-class, so the signed session's ack proves
/// its attest verified, never dropped. Then the one `insert` a published
/// document admits (PUB-2.59): a record deposited at the fresh position past
/// its head member's extent, the member named and its trunk the frame's
/// `doc` term — the board's verdict on it under the bare session's token the
/// same, and acked under the signed one (a composer arm that spells a doc
/// term or a slot otherwise, signs over the member named, drops the declared
/// deposit, or reads an atom as its bytes, is refused
/// `attestation_invalid:signature`; one that reads no `{"resolve"}` slot
/// refuses the edit unsent, `attest_not_composed`).
#[test]
fn every_kind_with_an_entry_frame_is_judged_and_acked_under_the_signed_session() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let origin = format!("http://127.0.0.1:{}", sd.port());
    let store = dir.path().join("store");
    claim_board(&origin, &store);
    let (signed, lines) = open_shell(&origin, &store, SessionMode::Signed { principal: 1 });
    let (bare, _) = open_shell(&origin, &store, SessionMode::Bare { principal: 1 });
    let open = |shell: &Shell| -> String {
        let board = shell.call("boards", &json!({})).unwrap()[0]["board"].as_str().unwrap().to_string();
        shell.call("session", &json!({"board": board})).unwrap()["session"].as_str().unwrap().to_string()
    };
    let (signed_session, bare_session) = (open(&signed), open(&bare));
    // A write under the bare session: the shell sends none, and the board's
    // own verdict on it is read by the library, under that session's token.
    let bare_token = bare.sessions.get(&bare_session).unwrap().token.clone();
    let library = Board::new(Origin::parse(&origin).unwrap(), skep_client::PlainHttp::new());
    let bare_write = |what: &str, frame: &Value| {
        let refused = bare.call("op", &json!({"session": bare_session, "frame": frame})).unwrap_err();
        assert_eq!(refused.name(), "write_in_bare_session", "{what}: the shell sends no write of a bare session's: {refused}");
        let Answer::Document(verdict) = library.op(Some(&bare_token), frame).unwrap() else { panic!("{what}: the bare session stands") };
        assert_eq!((verdict["code"].as_str(), verdict["detail"].as_str()), (Some("credential_refused"), Some("signed_session_required")), "{what}: the write is publish-class: {verdict}");
    };
    let talk = || lines.lock().unwrap().join("\n");
    let write = |frame: Value| -> Value { signed.call("op", &json!({"session": signed_session, "frame": frame})).unwrap_or_else(|r| panic!("{r}\n{}", talk())) };
    let addr = |v: Value| v["addr"].as_str().unwrap_or_else(|| panic!("no addr: {v}")).to_string();
    let first_run = |doc: &str, width: u64| write(skep_client::board::frames::image(doc, 1, width))["runs"][0].clone();
    // An edition born of a draft of `text` by its shot: (the edition, the
    // draft, the member).
    let edition = |text: &str| -> (String, String, String) {
        let doc = addr(write(json!({"op": "create_new_document", "account": "1.0.1", "published": true})));
        let draft = addr(write(json!({"op": "create_new_document", "account": "1.0.1"})));
        write(json!({"op": "insert", "doc": draft, "at": {"subspace": "1", "ordinal": "1"}, "values": [text]}));
        let run = first_run(&draft, text.len() as u64);
        let member = addr(write(json!({"op": "publish", "doc": doc, "draft": draft, "runs": [{"origin": draft, "i_start": run["i_start"], "width": run["width"]}]})));
        (doc, draft, member)
    };
    let (doc, draft, member) = edition("abc");
    let (other, _, other_member) = edition("xy");
    let (member_run, other_run) = (first_run(&member, 3), first_run(&other_member, 2));
    let citation = "1.1.0.1.0.1.0.3.13";
    let link_to = |to: &String| addr(write(json!({"op": "make_link", "home": doc, "from": {"addrs": [member]}, "to": {"addrs": [to]}, "ty": {"addrs": [citation]}})));
    let [edited, retracted, old, new, resolved] = [&draft, &doc, &other, &other_member, &member].map(link_to);
    let vspec = |start: &str| json!({"source": member, "span": {"start": start, "width": "0.1"}});
    let cells = [
        (
            "a shot with a base and a window",
            json!({"op": "publish", "doc": doc, "base": member, "base_extent": "3", "runs": [{"origin": doc, "i_start": member_run["i_start"], "width": "3"}, {"origin": other_member, "i_start": other_run["i_start"], "width": "2"}]}),
        ),
        ("fork", json!({"op": "fork", "published": true})),
        ("version", json!({"op": "version", "d_src": doc})),
        ("nullify", json!({"op": "nullify", "home": doc, "target": retracted})),
        ("assert_sup", json!({"op": "assert_sup", "home": doc, "old": old, "new": new})),
        // `d_s` and `d_a` two documents, so an arm that trades them is seen.
        (
            "edit_link, its type by address",
            json!({"op": "edit_link", "original": edited, "d_s": doc, "d_a": other, "successor": {"from": [vspec("1.1")], "to": [vspec("1.2")], "ty": {"addrs": [citation]}}}),
        ),
        (
            "edit_link, its type resolved",
            json!({"op": "edit_link", "original": resolved, "d_s": other, "d_a": doc, "successor": {"from": [vspec("1.1")], "to": [vspec("1.2")], "ty": {"resolve": [vspec("1.3")]}}}),
        ),
        // A typed relation of the PredDef class: Unary, so `to` is empty.
        ("emit", json!({"op": "emit", "home": doc, "ty": [{"start": "1.1.0.1.0.1.0.1.1", "width": "0.0.0.0.0.0.0.0.1"}], "from": member, "to": []})),
    ];
    for (kind, frame) in cells {
        bare_write(kind, &frame);
        let acked = signed.call("op", &json!({"session": signed_session, "frame": frame})).unwrap_or_else(|r| panic!("{kind}: {r}\n{}", talk()));
        assert!(acked["resp"].as_str().is_some_and(|resp| resp.starts_with("ack")), "{kind}: {acked}");
    }
    // The record deposit names the head member, so a `doc` term that is not
    // the trunk shows.
    let token = signed.sessions.get(&signed_session).unwrap().token.clone();
    let next = skep_client::ceremony::deposit::next_content_ordinal(&signed.boards[0].board, Some(&token), &other).unwrap();
    let deposit = json!({"op": "insert", "doc": other_member, "at": {"subspace": "1", "ordinal": next.to_string()}, "values": [{"atom": "xy"}], "deposit": "1.1.0.1.0.1.0.3.1"});
    bare_write("the deposit", &deposit);
    let acked = signed.call("op", &json!({"session": signed_session, "frame": deposit})).unwrap_or_else(|r| panic!("the deposit: {r}\n{}", talk()));
    assert!(acked["resp"].as_str().is_some_and(|resp| resp.starts_with("ack")), "the deposit: {acked}");
    signed.shutdown();
    bare.shutdown();
    sd.shutdown();
}

/// Checks that a session's open position is read before it opened.
///
/// The open position (§3c.2's fallback `base`) is the board's own, read
/// before the session opened, under either mode: bracketed by the position
/// read before the `session` call and the one read after it (the opening
/// that records 0 sends the first held burst of every fresh session's read
/// over the document's whole history, and faces the person's own text
/// `moved`).
#[test]
fn a_sessions_open_position_is_the_boards_position_read_before_it_opened() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let origin = format!("http://127.0.0.1:{}", sd.port());
    let store = dir.path().join("store");
    claim_board(&origin, &store);
    for session_mode in [SessionMode::Bare { principal: 1 }, SessionMode::Signed { principal: 1 }] {
        let (shell, _) = open_shell(&origin, &store, session_mode);
        let board = shell.call("boards", &json!({})).unwrap()[0]["board"].as_str().unwrap().to_string();
        let position = || shell.call("health", &json!({"board": board})).unwrap()["health"]["log_position"].as_u64().unwrap();
        let before = position();
        let session = shell.call("session", &json!({"board": board})).unwrap()["session"].as_str().unwrap().to_string();
        let after = position();
        let opened_at = shell.sessions.get(&session).unwrap().opened_at;
        assert!(before > 0 && before <= opened_at && opened_at <= after, "{}: {before} ≤ {opened_at} ≤ {after}", session_mode.name());
        shell.shutdown();
    }
    sd.shutdown();
}

/// Checks that a session the restart ended re-opens under a fresh reference.
///
/// Under the signed mode, the session the daemon's restart ended is met by
/// the caller that meets it first — the board's feed thread, here, before
/// any call — and ended once: one `session-died` on the restart arm,
/// re-opened under a fresh reference the arm names and registered, its
/// supplement widened (an `index` event names it), and a publish-class write
/// acked under it; the old reference names nothing.
#[test]
fn a_session_the_restart_ended_is_reopened_under_a_fresh_reference() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let port = sd.port();
    let origin = format!("http://127.0.0.1:{port}");
    let store = dir.path().join("store");
    claim_board(&origin, &store);
    let (signed, lines) = open_shell(&origin, &store, SessionMode::Signed { principal: 1 });
    let seen = Arc::new(Mutex::new(Vec::new()));
    let answerer = answer_moments(signed.subscribe(), Arc::clone(&signed.pending), Arc::clone(&seen));
    let board = signed.call("boards", &json!({})).unwrap()[0]["board"].as_str().unwrap().to_string();
    let session = signed.call("session", &json!({"board": board})).unwrap()["session"].as_str().unwrap().to_string();
    wait_for(&seen, |e| e.name == EventName::Index && e.data["session"] == session);
    sd.shutdown();
    let sd = spawn_at(&dir.path().join("board"), true, port);
    let died = wait_for(&seen, |e| e.name == EventName::SessionDied && e.data["session"] == session);
    let reason = &died.data["reason"];
    assert_eq!((reason["arm"].as_str(), reason["reopened"].as_bool()), (Some("restart"), Some(true)), "{reason}\n{}", lines.lock().unwrap().join("\n"));
    let reopened = reason["session"].as_str().expect("the arm names the re-opened session").to_string();
    assert!(reopened.starts_with("s-") && reopened != session, "{reopened}");
    assert!(signed.sessions.get(&reopened).is_some(), "the re-opened session is registered");
    wait_for(&seen, |e| e.name == EventName::Index && e.data["session"] == reopened);
    let edition = signed
        .call("op", &json!({"session": reopened, "frame": {"op": "create_new_document", "account": "1.0.1", "published": true}}))
        .unwrap_or_else(|r| panic!("{r}\n{}", lines.lock().unwrap().join("\n")));
    assert_eq!(edition["resp"], "ack_addr", "{edition}");
    assert_eq!(signed.call("op", &json!({"session": session, "frame": {"op": "key_set", "account": "1.0.1"}})).unwrap_err().name(), "session_ended");
    assert_eq!(seen.lock().unwrap().iter().filter(|e| e.name == EventName::SessionDied).count(), 1, "the session ended once");
    signed.shutdown();
    drop(signed);
    answerer.join().unwrap();
    sd.shutdown();
}

/// Checks that a bare session's death names the restart or the flip (§4b.2).
///
/// A restart that keeps the board's trust is the `restart` arm, never
/// re-opened — a bare session is never re-opened silently; a restart into
/// `ENFORCING` is the flip, the `mode` arm, announced on the `mode` event
/// with the pair it moved to; and the bare bind on the enforcing board is
/// refused with the board's one 401, verbatim (the mutants that face the
/// flip as a restart, re-open a bare session, or answer the 401 as the
/// shell's own refusal).
#[test]
fn a_bare_sessions_death_names_the_restart_or_the_flip() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let port = sd.port();
    let origin = format!("http://127.0.0.1:{port}");
    let store = dir.path().join("store");
    claim_board(&origin, &store);
    let (shell, _) = open_shell(&origin, &store, SessionMode::Bare { principal: 1 });
    let seen = Arc::new(Mutex::new(Vec::new()));
    let _answerer = answer_moments(shell.subscribe(), Arc::clone(&shell.pending), Arc::clone(&seen));
    let board = shell.call("boards", &json!({})).unwrap()[0]["board"].as_str().unwrap().to_string();
    let open = || shell.call("session", &json!({"board": board})).unwrap()["session"].as_str().unwrap().to_string();
    let died = |session: &str| wait_for(&seen, |e| e.name == EventName::SessionDied && e.data["session"] == session).data["reason"].clone();
    // A restart that keeps the trust.
    let first = open();
    sd.shutdown();
    let sd = spawn_at(&dir.path().join("board"), true, port);
    assert_eq!(died(&first), json!({"arm": "restart", "reopened": false}));
    // A restart into `ENFORCING`: the flip.
    let second = open();
    sd.shutdown();
    let sd = spawn_at(&dir.path().join("board"), false, port);
    assert_eq!(died(&second), json!({"arm": "mode", "mode": "ENFORCING"}));
    let flip = wait_for(&seen, |e| e.name == EventName::Mode && e.data["mode"] == "ENFORCING");
    assert_eq!(flip.data, json!({"board": board, "mode": "ENFORCING", "claimant": "1.0.1", "local_trust": false}));
    // The bare bind on the enforcing board: the board's one 401.
    let refused = shell.call("session", &json!({"board": board})).unwrap_err();
    let v = refused.to_value();
    assert_eq!((refused.name(), v["kind"].as_str(), v["status"].as_u64()), ("session_rejected", Some("refused"), Some(401)), "{v}");
    shell.shutdown();
    sd.shutdown();
}

/// Checks that the real answers carry the declared fields.
///
/// The declarations name the shell's own answers: every field a real
/// `boards`, `session`, `health`, `probe`, `keygen` and `fingerprint` answer
/// carries is declared.
#[test]
fn the_real_answers_carry_the_declared_fields() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let origin = format!("http://127.0.0.1:{}", sd.port());
    let (shell, _) = open_shell(&origin, &dir.path().join("store"), SessionMode::Bare { principal: 0 });
    let fields = |name: &str| -> std::collections::BTreeSet<String> { crate::shapes::shape(name).unwrap().fields.iter().map(|f| f.name.to_string()).collect() };
    let keys = |v: &Value| -> std::collections::BTreeSet<String> { v.as_object().unwrap().keys().cloned().collect() };
    let boards = shell.call("boards", &json!({})).unwrap();
    assert_eq!(keys(&boards[0]), fields("BoardRow"));
    let board = boards[0]["board"].as_str().unwrap().to_string();
    let opened = shell.call("session", &json!({"board": board, "principal": 0})).unwrap();
    assert_eq!(keys(&opened), fields("SessionOpened"));
    assert_eq!(keys(&shell.call("health", &json!({"board": board})).unwrap()), fields("Health"));
    assert_eq!(keys(&shell.call("probe", &json!({})).unwrap()), fields("Probe"));
    assert_eq!(keys(&shell.call("keygen", &json!({"label": "k"})).unwrap()), fields("Keygen"));
    assert_eq!(keys(&shell.call("fingerprint", &json!({})).unwrap()[0]), fields("FingerprintRow"));
    shell.shutdown();
    sd.shutdown();
}

/// Checks that a `write_busy` is reissued once within the call.
///
/// It is reissued after the short wait (§4b.1's `op` row: "reissued by the
/// shell and reach the page as the ack or the next refusal"): the daemon's
/// write permits all held, a signed session's `create_new_document` is
/// dialed twice — the log's two `POST /op` answered `503` at the attested
/// frame's own size — and the reissue's `write_busy` is the refusal the page
/// meets; the permits let go, the next mint is acked at its first dial (the
/// mutants that face the first `write_busy`, or reissue it without bound).
#[test]
fn a_write_busy_is_reissued_once_within_the_call() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let origin = format!("http://127.0.0.1:{}", sd.port());
    let store = dir.path().join("store");
    claim_board(&origin, &store);
    let (shell, _) = open_shell(&origin, &store, SessionMode::Signed { principal: 1 });
    let board = shell.board_references().remove(0);
    let session = shell.call("session", &json!({"board": board})).unwrap()["session"].as_str().unwrap().to_string();
    let frame = json!({"op": "create_new_document", "account": "1.0.1"});
    // Every attest of one frame under one key is one size: the signature's
    // width is the algorithm's.
    let attested = json_len(&shell.sessions.get(&session).unwrap().attest(&shell.store, &frame).unwrap());
    let busy_dials = || shell.log().entries().iter().filter(|e| e["kind"] == "dial" && e["path"] == "/op" && e["status"] == 503 && e["bytes_in"] == attested).count();
    let mut permits = Vec::new();
    while let Some(permit) = sd.daemon().try_hold_write_permit() {
        permits.push(permit);
    }
    let refused = shell.call("op", &json!({"session": session, "frame": frame})).unwrap_err();
    assert_eq!((refused.name(), refused.to_value()["status"].as_u64()), ("write_busy", Some(503)), "{refused}");
    assert_eq!(busy_dials(), 2, "the write and its one reissue");
    drop(permits);
    let minted = shell.call("op", &json!({"session": session, "frame": frame})).unwrap();
    assert_eq!((minted["resp"].as_str(), busy_dials()), (Some("ack_addr"), 2), "{minted}");
    shell.shutdown();
    sd.shutdown();
}

/// Checks that a death met at a read the attest needs ends the session.
///
/// It ends at the call itself (`Sessions::end`) and is no refusal of the
/// composer's: a signed session's token closed at the board while its feed
/// stands quiet, then a `make_link` whose V-spec slot the composer resolves
/// through `image` under that token — the call answers `session_died` with
/// the restart's re-open, and the old reference names nothing (the mutant
/// that reads the death as the composer's halt tells the page the shell
/// could not sign).
#[test]
fn a_death_met_at_a_read_the_attest_needs_ends_the_session() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let origin = format!("http://127.0.0.1:{}", sd.port());
    let store = dir.path().join("store");
    claim_board(&origin, &store);
    let (signed, lines) = open_shell(&origin, &store, SessionMode::Signed { principal: 1 });
    let rx = signed.subscribe();
    let board = signed.board_references().remove(0);
    let session = signed.call("session", &json!({"board": board})).unwrap()["session"].as_str().unwrap().to_string();
    // The feed widens the session's supplement, then falls quiet: nothing
    // commits, so the call is the first caller to meet the death.
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut widened = false;
    let mut quiet_since = Instant::now();
    while !(widened && quiet_since.elapsed() > Duration::from_millis(500)) {
        assert!(Instant::now() < deadline, "the session's supplement was never widened");
        for event in rx.try_iter() {
            widened |= event.name == EventName::Index && event.data["session"] == session;
            quiet_since = Instant::now();
        }
        thread::sleep(Duration::from_millis(20));
    }
    let token = signed.sessions.get(&session).unwrap().token.clone();
    Board::new(Origin::parse(&origin).unwrap(), skep_client::PlainHttp::new()).session_close(&token).unwrap();
    let vspec = json!({"source": "1.0.1.0.1", "span": {"start": "1.1", "width": "0.1"}});
    let frame = json!({"op": "make_link", "home": "1.0.1.0.1", "from": [vspec], "to": {"addrs": ["1.0.1.0.1"]}, "ty": {"addrs": ["1.1.0.1.0.1.0.3.13"]}});
    let refused = signed.call("op", &json!({"session": session, "frame": frame})).unwrap_err();
    let v = refused.to_value();
    assert_eq!((refused.name(), v["reason"]["arm"].as_str()), ("session_died", Some("restart")), "{v}\n{}", lines.lock().unwrap().join("\n"));
    assert_eq!(signed.call("held", &json!({"session": session})).unwrap_err().name(), "session_ended");
    signed.shutdown();
    sd.shutdown();
}

/// Checks that a close the board does not answer still closes.
///
/// The close is the shell's act, whatever the board says (§4b.1's `close`
/// row arms no refusal at the board): a session closed while its board is
/// down answers `{}`, its `session-died` names the `closed` arm, the board's
/// silence is said on `Talk`, and the reference then names nothing (the
/// mutant that carries the board's silence back refuses a close that already
/// took effect); and the stop's close of a session at that board says the
/// board's silence on `Talk` as `close` says it (the mutant that drops it
/// keeps a token the board still holds out of the shell's window).
#[test]
fn a_close_the_board_does_not_answer_still_closes() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let origin = format!("http://127.0.0.1:{}", sd.port());
    let (shell, lines) = open_shell(&origin, &dir.path().join("store"), SessionMode::Bare { principal: 1 });
    let board = shell.board_references().remove(0);
    let session = shell.call("session", &json!({"board": board})).unwrap()["session"].as_str().unwrap().to_string();
    let standing = shell.call("session", &json!({"board": board})).unwrap()["session"].as_str().unwrap().to_string();
    let rx = shell.subscribe();
    sd.shutdown();
    let probe = Board::new(Origin::parse(&origin).unwrap(), skep_client::PlainHttp::new());
    let deadline = Instant::now() + Duration::from_secs(10);
    while probe.health().is_ok() {
        assert!(Instant::now() < deadline, "the stopped board still answers");
        thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(shell.call("close", &json!({"session": session})).unwrap(), json!({}));
    let died: Vec<Value> = rx.try_iter().filter(|e| e.name == EventName::SessionDied).map(|e| e.data).collect();
    assert_eq!(died, [json!({"session": session, "reason": {"arm": "closed"}})]);
    assert!(lines.lock().unwrap().iter().any(|l| l.contains("did not close") && l.contains(&session)), "{}", lines.lock().unwrap().join("\n"));
    assert_eq!(shell.call("close", &json!({"session": session})).unwrap_err().name(), "session_ended");
    shell.shutdown();
    assert!(lines.lock().unwrap().iter().any(|l| l.starts_with("stop:") && l.contains("did not close") && l.contains(&standing)), "{}", lines.lock().unwrap().join("\n"));
}

/// Checks that the codec's private budgets are the shell's.
///
/// They are judged by the board's own parse: an array at [`MAX_WIRE_LIST`]
/// elements, an address at [`MAX_TUMBLER_COMPONENTS`] components and an
/// insert of [`MAX_INSERT_VALUES`] values each parse — refused past the
/// parse, if at all, for what they name — and one more of each is refused at
/// the parse, `malformed` with the frame unparsed (`op: unparseable`) (a
/// budget the shell keeps past the board's refuses what the board takes; one
/// short of it composes what the board refuses).
#[test]
fn the_codecs_budgets_are_the_shells() {
    use crate::attest::MAX_WIRE_LIST;
    use crate::wire::{MAX_INSERT_VALUES, MAX_TUMBLER_COMPONENTS};
    use skep_client::board::{Opened, Rejection, SessionBody};
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let board = Board::new(Origin::parse(&format!("http://127.0.0.1:{}", sd.port())).unwrap(), skep_client::PlainHttp::new());
    let Opened::Token(token) = board.session_open(SessionBody::Bare { principal: 1 }).unwrap() else { panic!("a bare session on an unclaimed board") };
    let unparsed = |frame: Value| -> bool {
        let Answer::Document(v) = board.op(Some(&token), &frame).unwrap() else { panic!("the session stands") };
        Rejection::of(&v).is_some() && v["code"] == "malformed" && v["op"] == "unparseable"
    };
    let spec = json!({"doc": "1.0.1.0.1", "span": {"start": "1.1", "width": "0.1"}});
    let deep = |components: usize| format!("1.0.1.0.1{}", ".1".repeat(components - 5));
    let insert = |values: usize| json!({"op": "insert", "doc": "1.0.1.0.9", "at": {"subspace": "1", "ordinal": "1"}, "values": ["a".repeat(values)]});
    let cells = [
        ("a list", json!({"op": "retrieve_v", "specs": vec![spec.clone(); MAX_WIRE_LIST]}), json!({"op": "retrieve_v", "specs": vec![spec; MAX_WIRE_LIST + 1]})),
        ("an address", json!({"op": "doc_metadata", "doc": deep(MAX_TUMBLER_COMPONENTS)}), json!({"op": "doc_metadata", "doc": deep(MAX_TUMBLER_COMPONENTS + 1)})),
        ("an insert's values", insert(MAX_INSERT_VALUES), insert(MAX_INSERT_VALUES + 1)),
    ];
    for (cell, at, past) in cells {
        assert!(!unparsed(at), "{cell} at the budget parses");
        assert!(unparsed(past), "{cell} past the budget is refused at the parse");
    }
    sd.shutdown();
}

/// Checks that a paper claim hands the page no seed and no path.
///
/// It is §4b.3's: the anchor file's destination is native, "its copy the
/// ladder words" with it. The notebook claim with its anchors printed — the
/// sheets the dev arm's, the re-type declined, so AUTH-5.41's line on the
/// unverified print is said beside AUTH-5.40's ladder words — carries none
/// of its three seeds, nor a path under the store, in any answer, event or
/// log entry, and no seed on `Talk`, where the two native lines are said
/// (the mutant that forwards a native statement hands the page the anchor
/// file's path).
#[test]
fn a_paper_claim_hands_the_page_no_seed_and_no_path() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let origin = format!("http://127.0.0.1:{}", sd.port());
    let store = dir.path().join("store");
    let (shell, lines) = open_shell(&origin, &store, SessionMode::Bare { principal: 1 });
    let seen = Arc::new(Mutex::new(Vec::new()));
    let answerer = answer_moments(shell.subscribe(), Arc::clone(&shell.pending), Arc::clone(&seen));
    let board = shell.board_references().remove(0);
    let keygen = shell.call("keygen", &json!({"label": "notebook"})).unwrap();
    let claimed = shell.call("claim", &json!({"board": board, "name": "a name", "paper": true})).unwrap_or_else(|r| panic!("{r}\n{}", lines.lock().unwrap().join("\n")));
    assert_eq!(claimed["account"], "1.0.1");
    let talked = lines.lock().unwrap().join("\n");
    assert!(talked.contains("dev arm: the sheet for fingerprint"), "the SECRET sheets went to the dev arm:\n{talked}");
    assert!(talked.contains("dev arm: AUTH-5.40: anchor file written: ") && talked.contains("dev arm: AUTH-5.41: "), "the native lines are said on TALK:\n{talked}");
    let all = format!("{keygen:?}{claimed:?}{:?}{:?}", seen.lock().unwrap(), shell.log().entries());
    let seeds = seeds_of(&store);
    assert_eq!(seeds.len(), 3, "the device key and the two anchors");
    for seed in &seeds {
        assert!(!all.contains(seed.as_str()) && !talked.contains(seed.as_str()), "a seed crossed");
    }
    let store_text = store.display().to_string();
    let leaked: Vec<String> = seen.lock().unwrap().iter().map(|e| e.data.to_string()).filter(|data| data.contains(&store_text)).collect();
    assert!(leaked.is_empty() && !all.contains(&store_text), "a path under the store crossed: {leaked:?}");
    assert_events_declared(&seen.lock().unwrap());
    shell.shutdown();
    drop(shell);
    answerer.join().unwrap();
    sd.shutdown();
}

/// Checks that a scripted claim places its anchors where its script says.
///
/// It is §4b.3's: an anchor file's destination is the shell's own window's,
/// one per anchor, and the dev arm's in the provider. A notebook claim under
/// a script of two `destination` lines — the claim's only secret moments
/// where nothing is printed — lands each anchor file in its own named
/// directory, the dev arm saying each placement on `Talk` (the mutant row
/// that hands the walk destinations of its own lands both files where the
/// script never said, its two lines unread).
#[test]
fn a_scripted_claim_places_its_anchors_where_its_script_says() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let origin = format!("http://127.0.0.1:{}", sd.port());
    let (a, b) = (dir.path().join("anchor-a"), dir.path().join("anchor-b"));
    let (talk, lines) = talk();
    let mut opts = ShellOptions::new(vec![Origin::parse(&origin).unwrap()], dir.path().join("store"), SessionMode::Bare { principal: 1 }, talk);
    opts.arm = ArmConfig::Script(vec![script::Answer::Destination(a.clone()), script::Answer::Destination(b.clone())]);
    let shell = Shell::open(opts);
    let answerer = answer_moments(shell.subscribe(), Arc::clone(&shell.pending), Arc::new(Mutex::new(Vec::new())));
    let board = shell.board_references().remove(0);
    shell.call("keygen", &json!({"label": "notebook"})).unwrap();
    let claimed = shell.call("claim", &json!({"board": board, "name": "a name"})).unwrap_or_else(|r| panic!("{r}\n{}", lines.lock().unwrap().join("\n")));
    assert_eq!(claimed["account"], "1.0.1");
    let talked = lines.lock().unwrap().join("\n");
    for (which, place) in [(0, &a), (1, &b)] {
        let files = std::fs::read_dir(place).map(Iterator::count).unwrap_or(0);
        assert_eq!(files, 1, "anchor {which}'s one file under {}:\n{talked}", place.display());
        assert!(talked.contains(&format!("dev arm: anchor {which} is placed under {}", place.display())), "the dev arm placed anchor {which}:\n{talked}");
    }
    shell.shutdown();
    drop(shell);
    answerer.join().unwrap();
    sd.shutdown();
}

/// Checks that a death signal at a call's own dial ends the session.
///
/// It ends at the call itself (`Sessions::end`) at each dial a call makes
/// under its token — an `op`'s `/op`, an `/op-at` read's, and `fetch`'s
/// `/blob`: three sessions as principals the board seats no account for, so
/// no supplement presents their tokens, the board quiet and each token
/// closed at it; each call answers `session_died` with the reason its end
/// derived, its reference then names nothing, and one `session-died` goes
/// out per session (the mutants that drop a call's death arm leave the
/// session standing behind a refusal the page cannot read as the restart).
#[test]
fn a_death_signal_at_a_calls_own_dial_ends_the_session() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let origin = format!("http://127.0.0.1:{}", sd.port());
    let store = dir.path().join("store");
    claim_board(&origin, &store);
    let (shell, lines) = open_shell(&origin, &store, SessionMode::Bare { principal: 1 });
    let rx = shell.subscribe();
    let board = shell.board_references().remove(0);
    let sessions: Vec<String> = (2..=4).map(|principal| shell.call("session", &json!({"board": board, "principal": principal})).unwrap()["session"].as_str().unwrap().to_string()).collect();
    // The board falls quiet: nothing commits, so each call is the first
    // caller to meet its session's death.
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut quiet_since = Instant::now();
    while quiet_since.elapsed() < Duration::from_millis(500) {
        assert!(Instant::now() < deadline, "the board never fell quiet");
        if rx.try_iter().count() > 0 {
            quiet_since = Instant::now();
        }
        thread::sleep(Duration::from_millis(20));
    }
    let fresh = Board::new(Origin::parse(&origin).unwrap(), skep_client::PlainHttp::new());
    for session in &sessions {
        fresh.session_close(&shell.sessions.get(session).unwrap().token).unwrap();
    }
    let head = shell.call("health", &json!({"board": board})).unwrap()["health"]["log_position"].as_u64().unwrap();
    let answers = [
        shell.call("op", &json!({"session": sessions[0], "frame": {"op": "doc_metadata", "doc": "1.0.1.0.1"}})),
        shell.call("op", &json!({"session": sessions[1], "frame": {"at": head, "frame": {"op": "key_set", "account": "1.0.1"}}})),
        shell.fetch(&json!({"session": sessions[2], "i": "1.0.1.0.1.0.1.1"})).map(|_| json!({})),
    ];
    for (session, answer) in sessions.iter().zip(answers) {
        let v = answer.expect_err("the death is the call's answer").to_value();
        assert_eq!((v["name"].as_str(), v["reason"]["arm"].as_str()), (Some("session_died"), Some("restart")), "{v}\n{}", lines.lock().unwrap().join("\n"));
        assert_eq!(shell.call("held", &json!({"session": session})).unwrap_err().name(), "session_ended", "{session} names nothing");
    }
    let died: Vec<String> = rx.try_iter().filter(|e| e.name == EventName::SessionDied).map(|e| e.data["session"].as_str().unwrap_or("?").to_string()).collect();
    assert_eq!(died, sessions, "one `session-died` per session");
    shell.shutdown();
    sd.shutdown();
}

/// Checks that a released supplement keeps its drafts cursor.
///
/// It is `Sessions::release`'s: two signed sessions of one principal — two
/// tabs — and the first, having minted a draft and written it, closes; the
/// supplement handed to the second reads on from where the reads left it,
/// so each drafts row reaches the page once (the mutant whose widen resets
/// the cursor to the second session's open feeds the first's rows again — a
/// duplicate at every subscriber whenever one of two tabs closes).
#[test]
fn a_released_supplement_keeps_its_drafts_cursor() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let origin = format!("http://127.0.0.1:{}", sd.port());
    let store = dir.path().join("store");
    claim_board(&origin, &store);
    let (shell, _) = open_shell(&origin, &store, SessionMode::Signed { principal: 1 });
    let seen = Arc::new(Mutex::new(Vec::new()));
    let _answerer = answer_moments(shell.subscribe(), Arc::clone(&shell.pending), Arc::clone(&seen));
    let board = shell.board_references().remove(0);
    let open = || shell.call("session", &json!({"board": board})).unwrap()["session"].as_str().unwrap().to_string();
    let (first, second) = (open(), open());
    let drafts_row = |at: &Value| {
        let at = at.clone();
        move |e: &Event| e.name == EventName::Feed && e.data["update"]["class"] == "drafts" && e.data["update"]["at"] == at
    };
    let minted = shell.call("op", &json!({"session": first, "frame": {"op": "create_new_document", "account": "1.0.1"}})).unwrap();
    let draft = minted["addr"].as_str().unwrap().to_string();
    let inserted = shell.call("op", &json!({"session": first, "frame": {"op": "insert", "doc": draft, "at": {"subspace": "1", "ordinal": "1"}, "values": ["a"]}})).unwrap();
    wait_for(&seen, drafts_row(&minted["at"]));
    wait_for(&seen, drafts_row(&inserted["at"]));
    assert_eq!(shell.call("close", &json!({"session": first})).unwrap(), json!({}));
    let again = shell.call("op", &json!({"session": second, "frame": {"op": "insert", "doc": draft, "at": {"subspace": "1", "ordinal": "2"}, "values": ["b"]}})).unwrap();
    wait_for(&seen, drafts_row(&again["at"]));
    let fed: Vec<u64> = seen.lock().unwrap().iter().filter(|e| e.name == EventName::Feed && e.data["update"]["class"] == "drafts").filter_map(|e| e.data["update"]["at"].as_u64()).collect();
    for at in [&minted["at"], &inserted["at"], &again["at"]] {
        let at = at.as_u64().unwrap();
        assert_eq!(fed.iter().filter(|row| **row == at).count(), 1, "the drafts row at {at} reaches the page once: {fed:?}");
    }
    shell.shutdown();
    sd.shutdown();
}

/// Checks that a session opened after a narrow is fed from its own open.
///
/// It is the `feed` update's definition: "a session's drafts at the position
/// the session opened at". A signed session mints a draft and closes, the
/// last of its principal at the board, so the supplement narrows and its
/// drafts cursor goes with it; a session opened after it mints another, fed
/// under its own reference — and the first draft's row reaches the page
/// once, never again under the new session (the mutant whose widen starts a
/// fresh cursor at 0 re-feeds the principal's whole drafts history at every
/// reload).
#[test]
fn a_session_opened_after_its_principals_narrow_is_fed_from_its_own_open() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let origin = format!("http://127.0.0.1:{}", sd.port());
    let store = dir.path().join("store");
    claim_board(&origin, &store);
    let (shell, _) = open_shell(&origin, &store, SessionMode::Signed { principal: 1 });
    let seen = Arc::new(Mutex::new(Vec::new()));
    let _answerer = answer_moments(shell.subscribe(), Arc::clone(&shell.pending), Arc::clone(&seen));
    let board = shell.board_references().remove(0);
    let open = || shell.call("session", &json!({"board": board})).unwrap()["session"].as_str().unwrap().to_string();
    let mint = |session: &str| shell.call("op", &json!({"session": session, "frame": {"op": "create_new_document", "account": "1.0.1"}})).unwrap()["at"].as_u64().unwrap();
    let drafts_row = |at: u64| move |e: &Event| e.name == EventName::Feed && e.data["update"]["class"] == "drafts" && e.data["update"]["at"] == at;
    let first = open();
    let before = mint(&first);
    wait_for(&seen, drafts_row(before));
    assert_eq!(shell.call("close", &json!({"session": first})).unwrap(), json!({}));
    let second = open();
    let after = mint(&second);
    let fed = wait_for(&seen, drafts_row(after));
    assert_eq!(fed.data["update"]["session"], second, "{fed:?}");
    let fed_before = seen.lock().unwrap().iter().filter(|e| drafts_row(before)(e)).count();
    assert_eq!(fed_before, 1, "the first draft's row reaches the page once");
    shell.shutdown();
    sd.shutdown();
}

/// Checks that the board's documents are listed at the call's class (A-255).
///
/// Foundations §2's far scale is "drawn from the client's index read
/// whole", masked at the reader's class. Against the real daemon, a draft
/// written under a signed session reaches the session's listing, labelled by
/// its first line and `yours_to_read`, beside the board's own published
/// documents; the guest's listing is the same documents, its drafts aside.
/// Each answer and its parts are held to their declarations, the counts
/// tallied over the documents listed, a prefix narrows both, and a
/// session's listing at another board is refused. The mutants that list the
/// published part alone for a session, the principal's part for the guest,
/// or counts the documents listed do not make, hand the page a plane of the
/// wrong class.
#[test]
fn places_lists_the_boards_documents_at_the_calls_class() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let origin = format!("http://127.0.0.1:{}", sd.port());
    let store = dir.path().join("store");
    claim_board(&origin, &store);
    let (shell, _) = open_shell(&origin, &store, SessionMode::Signed { principal: 1 });
    let board = shell.board_references().remove(0);
    let session = shell.call("session", &json!({"board": board})).unwrap()["session"].as_str().unwrap().to_string();
    let draft = shell.call("op", &json!({"session": session, "frame": {"op": "create_new_document", "account": "1.0.1"}})).unwrap()["addr"].as_str().unwrap().to_string();
    shell.call("op", &json!({"session": session, "frame": {"op": "insert", "doc": draft, "at": {"subspace": "1", "ordinal": "1"}, "values": ["hello\nworld"]}})).unwrap();
    let place = json!({"doc": draft, "kind": "draft", "label": "hello", "standing": "yours_to_read"});
    let deadline = Instant::now() + Duration::from_secs(30);
    let own = loop {
        let listing = shell.call("places", &json!({"session": session})).unwrap();
        if listing["docs"].as_array().is_some_and(|docs| docs.contains(&place)) {
            break listing;
        }
        assert!(Instant::now() < deadline, "the draft never reached the listing: {listing}");
        thread::sleep(Duration::from_millis(50));
    };
    let declared = |listing: &Value| {
        crate::shapes::assert_declared("PlacesAnswer", listing);
        listing["docs"].as_array().unwrap().iter().for_each(|p| crate::shapes::assert_declared("Place", p));
        listing["counts"].as_array().unwrap().iter().for_each(|c| crate::shapes::assert_declared("AccountCount", c));
    };
    // The account a document address lies under: its components before the
    // second `0`.
    let account_of = |doc: &str| {
        let comps: Vec<&str> = doc.split('.').collect();
        let second_zero = comps.iter().enumerate().filter(|(_, c)| **c == "0").nth(1).map(|(i, _)| i).expect("a document address");
        comps[..second_zero].join(".")
    };
    let tally = |listing: &Value| {
        let mut tally = std::collections::BTreeMap::<String, u64>::new();
        listing["docs"].as_array().unwrap().iter().for_each(|p| *tally.entry(account_of(p["doc"].as_str().unwrap())).or_default() += 1);
        let counted: std::collections::BTreeMap<String, u64> =
            listing["counts"].as_array().unwrap().iter().map(|c| (c["account"].as_str().unwrap().to_string(), c["documents"].as_u64().unwrap())).collect();
        assert_eq!(counted, tally, "the counts are the documents listed: {listing}");
    };
    declared(&own);
    tally(&own);
    let guest = shell.call("places", &json!({"guest": true, "board": board})).unwrap();
    declared(&guest);
    tally(&guest);
    let editions: Vec<&Value> = own["docs"].as_array().unwrap().iter().filter(|p| p["kind"] == "edition").collect();
    assert!(!editions.is_empty(), "the claim's published documents are listed: {own}");
    assert_eq!(guest["docs"].as_array().unwrap().iter().collect::<Vec<_>>(), editions, "the guest's listing is the session's, its drafts aside");
    let narrowed = shell.call("places", &json!({"session": session, "opts": {"under": draft}})).unwrap();
    assert_eq!((narrowed["docs"].clone(), narrowed["counts"].clone()), (json!([place]), json!([{"account": "1.0.1", "documents": 1}])), "a document's own address lists it alone");
    let elsewhere = shell.call("places", &json!({"session": session, "opts": {"under": "1.0.9"}})).unwrap();
    assert_eq!((elsewhere["docs"].clone(), elsewhere["counts"].clone()), (json!([]), json!([])));
    let refused = shell.call("places", &json!({"session": session, "board": "b-elsewhere"})).unwrap_err();
    assert_eq!((refused.name(), refused.to_value()["what"].as_str()), ("malformed_args", Some("board")), "a session lists its own board");
    shell.shutdown();
    sd.shutdown();
}

/// Checks that the session answer says whether the session writes.
///
/// Its `writes` is `false` under the bare mode — the keyless session, which
/// reads alone, its mint refused `write_in_bare_session` — and `true` under
/// the signed mode, the same mint acked; each answer held to its
/// declaration, and the shell's own verdict on the write agreeing with what
/// the answer said before it was offered (the mutant that answers `true` for
/// every session has the page offer a keyless reader an edit the shell
/// refuses at the save).
#[test]
fn the_session_answer_says_whether_the_session_writes() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let origin = format!("http://127.0.0.1:{}", sd.port());
    let store = dir.path().join("store");
    claim_board(&origin, &store);
    for (mode, writes) in [(SessionMode::Bare { principal: 1 }, false), (SessionMode::Signed { principal: 1 }, true)] {
        let (shell, lines) = open_shell(&origin, &store, mode);
        let board = shell.board_references().remove(0);
        let opened = shell.call("session", &json!({"board": board})).unwrap();
        crate::shapes::assert_declared("SessionOpened", &opened);
        assert_eq!(opened["writes"], json!(writes), "{}: {opened}", mode.name());
        let session = opened["session"].as_str().unwrap();
        match shell.call("op", &json!({"session": session, "frame": {"op": "create_new_document", "account": "1.0.1"}})) {
            Ok(acked) => assert!(writes && acked["resp"] == "ack_addr", "{}: a write under a session whose answer said `writes: {writes}` was acked: {acked}", mode.name()),
            Err(refused) => assert!(
                !writes && refused.name() == "write_in_bare_session",
                "{}: a write under a session whose answer said `writes: {writes}` was refused: {refused}\n{}",
                mode.name(),
                lines.lock().unwrap().join("\n")
            ),
        }
        shell.shutdown();
    }
    sd.shutdown();
}

/// Checks that the refusing arm refuses every secret and consent moment.
///
/// It is `ArmConfig::Refuse`, the setting of a client with no person
/// present: every secret and consent moment a walk reaches is refused and
/// answered by nothing — `retire` at its preview's typed confirmation
/// (consent), the key still enrolled and nothing retired; `accept` at the
/// agent space, at its pair's first destination (secret), no anchor placed
/// anywhere — each call answering `person_required` naming the walk, the
/// moment and its class, a confirmation's text beside it and no secret
/// moment's prompt; no answer recorded on `Talk`, where the person's own
/// refusals are said and the walk's native statement (§3a, the key file
/// written) still lands, in the arm's place and on no event; the public
/// moments still the page's; the board's position unmoved (the mutant that
/// falls back to the auto arm retires the key and places the pair under
/// `<store>-anchors/`; the one that names the refusal `abandoned` tells the
/// caller a person cancelled).
#[test]
fn the_refusing_arm_refuses_every_secret_and_consent_moment_and_answers_nothing() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let origin = format!("http://127.0.0.1:{}", sd.port());
    let store = dir.path().join("store");
    claim_board(&origin, &store);
    let (talk, lines) = talk();
    let mut opts = ShellOptions::new(vec![Origin::parse(&origin).unwrap()], store.clone(), SessionMode::Bare { principal: 1 }, talk);
    opts.arm = ArmConfig::Refuse;
    let shell = Shell::open(opts);
    assert!(!shell.arm_is_script());
    let seen = Arc::new(Mutex::new(Vec::new()));
    let answerer = answer_moments(shell.subscribe(), Arc::clone(&shell.pending), Arc::clone(&seen));
    let board = shell.board_references().remove(0);
    let position = || shell.call("health", &json!({"board": board})).unwrap()["health"]["log_position"].as_u64().unwrap();
    let anchor_files = || -> usize {
        let mut anchors = store.as_os_str().to_owned();
        anchors.push("-anchors");
        std::fs::read_dir(PathBuf::from(anchors)).into_iter().flatten().flatten().map(|dir| std::fs::read_dir(dir.path()).map(Iterator::count).unwrap_or(0)).sum()
    };
    let (before, placed) = (position(), anchor_files());
    assert_eq!(placed, 2, "the claim's pair, placed by the auto arm that claimed");
    let k1 = shell.call("fingerprint", &json!({})).unwrap()[0]["fingerprint"].as_str().unwrap().to_string();
    // Consent: the retirement's typed confirmation.
    let refused = shell.call("retire", &json!({"board": board, "fingerprint": k1})).unwrap_err();
    let v = refused.to_value();
    assert_eq!(
        (v["name"].as_str(), v["kind"].as_str(), v["walk"].as_str(), v["moment"].as_str(), v["class"].as_str()),
        (Some("person_required"), Some("shell"), Some("retire"), Some("confirm_typed"), Some("consent")),
        "{v}\n{}",
        lines.lock().unwrap().join("\n")
    );
    assert!(v["text"].as_str().is_some_and(|text| text.contains("CONFIRM THE RETIREMENT")), "the confirmation's text, public data, rides the refusal: {v}");
    let set = shell.call("op", &json!({"guest": true, "board": board, "frame": {"op": "key_set", "account": "1.0.1"}})).unwrap();
    assert!(set["enrolled"].as_array().unwrap().iter().any(|e| e["fingerprint"] == k1) && set["retired"].as_array().is_none_or(Vec::is_empty), "the key stands enrolled, nothing retired: {set}");
    // Secret: the pair's first destination at the agent space's accept.
    let refused = shell.call("accept", &json!({"board": board, "address": "1.0.1.1", "label": "agent"})).unwrap_err();
    let v = refused.to_value();
    assert_eq!(
        (v["name"].as_str(), v["walk"].as_str(), v["moment"].as_str(), v["class"].as_str(), v.get("text")),
        (Some("person_required"), Some("accept"), Some("destination"), Some("secret"), None),
        "{v}\n{}",
        lines.lock().unwrap().join("\n")
    );
    assert_eq!(anchor_files(), placed, "no anchor was placed");
    assert_eq!(position(), before, "no write reached the board");
    let talked = lines.lock().unwrap().join("\n");
    assert!(!talked.contains("dev arm:"), "no answer was recorded:\n{talked}");
    assert!(
        talked.contains("person: the confirm_typed moment (CONSENT) of `retire` is refused") && talked.contains("person: the destination moment (SECRET) of `accept` is refused"),
        "the refusals are said:\n{talked}"
    );
    assert!(talked.contains("person: §3a: key file written: "), "the native statement is said on TALK in the arm's place:\n{talked}");
    let events = seen.lock().unwrap();
    assert!(
        events.iter().all(|e| !e.data.to_string().contains("§3a") && !e.data.to_string().contains(&store.display().to_string())),
        "a native statement, or a path under the store, crossed to the page"
    );
    assert!(events.iter().any(|e| e.name == EventName::Moment && e.data["walk"] == "accept" && e.data["kind"] == "label"), "the PUBLIC boxes still cross to the page");
    assert_events_declared(&events);
    drop(events);
    shell.shutdown();
    drop(shell);
    answerer.join().unwrap();
    sd.shutdown();
}
