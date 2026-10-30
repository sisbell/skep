//! The publication family (`client.md` §4b.1's four rows, §4b.2's event).
//!
//! The suite checks the rules the shell alone keeps, with no daemon behind
//! it — a `publish` frame through `op` refused as a call before any dial,
//! the six unholdable writes refused under a stopped node and `unreachable`
//! not of the set, `count` and `confirm` with no panel `no_panel`, `cancel`
//! idempotent, a bare session refused at `open`, and the row's own members
//! read before the session — and, against the real daemon, the family end
//! to end: the panel over a draft with a notes link and a read-with set, the
//! count as a row flips, the confirm acknowledged with its two events and
//! the feed row naming the member and the homes, the second open inert,
//! the stopped node refusing the confirm before it composes, the mint form
//! with its claim, and `claim_refused` crossing as answered with the board
//! unmoved.

use super::*;
use crate::sessions::{Facts, Open};

/// Returns a signed session's facts: a key that signs nothing here.
fn signed_facts(principal: u64) -> Facts {
    let fingerprint = skep_identity::Fingerprint::parse_hex(&"5a".repeat(32)).unwrap();
    Facts { principal, account: Some(format!("1.0.{principal}")), kind: SessionKind::Signed { fingerprint, set_account: format!("1.0.{principal}") } }
}

/// Registers a session of `facts` at the shell's first board: its reference.
fn register(shell: &Shell, token: &str, facts: Facts) -> String {
    let board = shell.board_references().remove(0);
    let open = Open { token: Token::parse(&token.repeat(16)).unwrap(), facts, opened_at: 0 };
    shell.sessions.register(&shell.boards[0], open, &mut shell.feed(&board)).reference.clone()
}

/// Checks that a `publish` frame through `op` is refused as a call (§4b.1).
///
/// Under a signed session the frame is refused `publish_is_a_call` naming
/// its op, after the bare check — a bare session's is `write_in_bare_session`
/// first — and before any dial: a listener at the board records no frame
/// (the mutant that dials the page's publish sends a request the page
/// composed, which S-35 (a) forbids; the one that checks the publish ahead
/// of the bare check tells a keyless session a publication is a call).
#[test]
fn a_publish_frame_through_op_is_refused_as_a_call_before_any_dial() {
    let dir = TempDir::new().unwrap();
    let (origin, frames) = super::door::recording_listener();
    let (shell, _) = open_shell(&origin, &dir.path().join("store"), SessionMode::Bare { principal: 1 });
    let signed = register(&shell, "8e", signed_facts(2));
    let bare = register(&shell, "9f", Facts { principal: 1, account: Some("1.0.1".into()), kind: SessionKind::Bare });
    let publish = json!({"op": "publish", "doc": "1.0.2.0.1", "draft": "1.0.2.0.2", "runs": []});
    let refused = shell.call("op", &json!({"session": signed, "frame": publish})).unwrap_err();
    let v = refused.to_value();
    assert_eq!((refused.name(), v["kind"].as_str(), v["op"].as_str()), ("publish_is_a_call", Some("shell"), Some("publish")), "{v}");
    let at_form = shell.call("op", &json!({"session": signed, "frame": {"at": 5, "frame": publish}})).unwrap_err();
    assert_eq!(at_form.name(), "publish_is_a_call", "the /op-at form too: {at_form}");
    assert_eq!(shell.call("op", &json!({"session": bare, "frame": publish})).unwrap_err().name(), "write_in_bare_session", "the bare check first");
    // A read under the signed session is dialed, so the listener sees what a
    // dial would be, and no publish among the frames it recorded.
    let read = json!({"op": "doc_metadata", "doc": "1.0.2.0.1"});
    assert_eq!(shell.call("op", &json!({"session": signed, "frame": read})).unwrap_err().name(), "unreachable");
    let recorded = frames.lock().unwrap().clone();
    assert!(recorded.iter().all(|f| f["op"] != "publish") && recorded.contains(&read), "no publish reached the board: {recorded:?}");
}

/// Checks that the six unholdable writes are refused under a stopped node.
///
/// With the own node stopped, each of `fork`, `version`, `make_link`,
/// `nullify` and `edit_link` through `op` is refused `stopped` naming its op
/// and dialed never (`publish` is refused as a call ahead of it); a write
/// outside the six — a draft's mint — is dialed as it dials; and with the
/// node running, the same writes at a board that does not answer meet the
/// dial's own `unreachable`, never a hold's cause (§3c.4: "`unreachable`
/// not of this set").
#[test]
fn the_unholdable_writes_are_refused_under_a_stopped_node_and_unreachable_is_not_of_the_set() {
    let dir = TempDir::new().unwrap();
    let (origin, frames) = super::door::recording_listener();
    let (talk, _) = talk();
    let mut opts = ShellOptions::new(vec![Origin::parse(&origin).unwrap()], dir.path().join("store"), SessionMode::Bare { principal: 1 }, talk);
    opts.own_node = Some(Origin::parse(&origin).unwrap());
    let shell = Shell::open(opts);
    let session = register(&shell, "8e", signed_facts(2));
    let writes = [
        json!({"op": "fork", "published": true}),
        json!({"op": "version", "d_src": "1.0.2.0.1"}),
        json!({"op": "make_link", "home": "1.0.2.0.1", "from": {"addrs": ["1.0.2.0.1"]}, "to": {"addrs": []}, "ty": {"addrs": ["1.1.0.1.0.1.0.3.13"]}}),
        json!({"op": "nullify", "home": "1.0.2.0.1", "target": "1.0.2.0.1.0.2.1"}),
        json!({"op": "edit_link", "original": "1.0.2.0.1.0.2.1", "d_s": "1.0.2.0.1", "d_a": "1.0.2.0.1", "successor": {"from": {"addrs": []}, "to": {"addrs": []}, "ty": {"addrs": ["1.1.0.1.0.1.0.3.13"]}}}),
    ];
    shell.set_node_state(NodeState::Stopped);
    for frame in &writes {
        let refused = shell.call("op", &json!({"session": session, "frame": frame})).unwrap_err();
        let v = refused.to_value();
        assert_eq!((refused.name(), v["kind"].as_str(), v["op"].as_str()), ("stopped", Some("shell"), frame["op"].as_str()), "{v}");
    }
    assert!(frames.lock().unwrap().is_empty(), "nothing of the six is dialed under the stop");
    let mint = json!({"op": "create_new_document", "account": "1.0.2"});
    assert_eq!(shell.call("op", &json!({"session": session, "frame": mint})).unwrap_err().name(), "unreachable", "a write outside the six dials as it dials");
    shell.set_node_state(NodeState::Running);
    for frame in &writes {
        let refused = shell.call("op", &json!({"session": session, "frame": frame})).unwrap_err();
        assert_eq!(refused.name(), "unreachable", "{}: the dial fails as it fails, no hold's cause: {refused}", frame["op"]);
    }
    // Under the running node each write dials — a signed session's first
    // reads the board's `H.1` for its attest, which is what the listener
    // records of a write it never answers.
    let recorded = frames.lock().unwrap().clone();
    assert!(recorded.len() >= 6, "the mint and the five writes under the running node reached the listener: {recorded:?}");
}

/// Checks the family's answers where no panel stands, and the row's members.
///
/// `count` and `confirm` with no panel under the session's board and
/// principal answer `no_panel`; `cancel` answers `{}` twice and says no
/// `publication` event; `open` reads its own members before the session —
/// `draft` missing, neither `doc` nor `mint`, both — each `malformed_args`
/// naming the member, and a bare session is refused `write_in_bare_session`
/// naming the call, since a publication is a write and the keyless session
/// reads alone.
#[test]
fn no_panel_cancel_is_idempotent_and_the_rows_read_their_members_first() {
    let dir = TempDir::new().unwrap();
    let (shell, _) = open_shell(&super::door::nowhere(), &dir.path().join("store"), SessionMode::Bare { principal: 1 });
    let rx = shell.subscribe();
    let signed = register(&shell, "8e", signed_facts(2));
    let bare = register(&shell, "9f", Facts { principal: 1, account: Some("1.0.1".into()), kind: SessionKind::Bare });
    for call in ["publication.count", "publication.confirm"] {
        let refused = shell.call(call, &json!({"session": signed})).unwrap_err();
        let v = refused.to_value();
        assert_eq!((refused.name(), v["session"].as_str()), ("no_panel", Some(signed.as_str())), "{call}: {v}");
    }
    assert_eq!(shell.call("publication.cancel", &json!({"session": signed})).unwrap(), json!({}));
    assert_eq!(shell.call("publication.cancel", &json!({"session": signed})).unwrap(), json!({}), "idempotent");
    assert!(rx.try_iter().all(|e| e.name != EventName::Publication), "no panel dropped, nothing said");
    let what = |args: Value| {
        let refused = shell.call("publication.open", &args).unwrap_err();
        let v = refused.to_value();
        assert_eq!(refused.name(), "malformed_args", "{args}: {v}");
        v["what"].as_str().unwrap().to_string()
    };
    assert_eq!(what(json!({"session": signed, "doc": "1.0.2.0.1"})), "draft");
    assert_eq!(what(json!({"session": signed, "draft": "1.0.2.0.2"})), "doc or mint");
    assert_eq!(what(json!({"session": signed, "draft": "1.0.2.0.2", "doc": "1.0.2.0.1", "mint": "1.0.2"})), "mint");
    assert_eq!(what(json!({"session": "s-gone", "draft": "1.0.2.0.2", "doc": "1.0.2.0.1", "claim": "yes"})), "claim", "the members before the session");
    assert_eq!(what(json!({"session": signed, "draft": "1.0.2.0.2", "doc": "1.0.2.0.1", "selection": [{"origin": "1.0.2.0.2", "i_start": 1, "width": 0}]})), "selection", "a run of no width");
    let stale = shell.call("publication.open", &json!({"session": "s-gone", "draft": "1.0.2.0.2", "doc": "1.0.2.0.1"})).unwrap_err();
    assert_eq!(stale.name(), "session_ended");
    let keyless = shell.call("publication.open", &json!({"session": bare, "draft": "1.0.1.0.2", "doc": "1.0.1.0.1"})).unwrap_err();
    assert_eq!((keyless.name(), keyless.to_value()["call"].as_str()), ("write_in_bare_session", Some("publication.open")), "{keyless}");
}

/// The signed shell over a claimed board, its own node the board: the
/// shell, the events seen, the board's and a signed session's references.
struct Ground {
    shell: Shell,
    seen: Arc<Mutex<Vec<Event>>>,
    board: String,
    session: String,
}

fn ground(dir: &TempDir, sd: &Skepd) -> Ground {
    let origin = format!("http://127.0.0.1:{}", sd.port());
    let store = dir.path().join("store");
    claim_board(&origin, &store);
    let (talk, _) = talk();
    let mut opts = ShellOptions::new(vec![Origin::parse(&origin).unwrap()], store, SessionMode::Signed { principal: 1 }, talk);
    opts.own_node = Some(Origin::parse(&origin).unwrap());
    let shell = Shell::open(opts);
    let seen = Arc::new(Mutex::new(Vec::new()));
    let _answerer = answer_moments(shell.subscribe(), Arc::clone(&shell.pending), Arc::clone(&seen));
    let board = shell.call("boards", &json!({})).unwrap()[0]["board"].as_str().unwrap().to_string();
    let session = shell.call("session", &json!({"board": board})).unwrap()["session"].as_str().unwrap().to_string();
    Ground { shell, seen, board, session }
}

impl Ground {
    fn op(&self, frame: Value) -> Value {
        self.shell.call("op", &json!({"session": self.session, "frame": frame})).unwrap_or_else(|r| panic!("{frame}: {r}"))
    }

    fn addr(&self, frame: Value) -> String {
        self.op(frame)["addr"].as_str().expect("an ack_addr").to_string()
    }

    /// A draft of the claimant's holding `text`.
    fn draft(&self, text: &str) -> String {
        let d = self.addr(json!({"op": "create_new_document", "account": "1.0.1"}));
        self.op(json!({"op": "insert", "doc": d, "at": {"subspace": "1", "ordinal": "1"}, "values": [text]}));
        d
    }

    fn call(&self, name: &str, args: Value) -> Result<Value, Refusal> {
        self.shell.call(name, &args)
    }

    /// The `publication` events seen so far, their states in order.
    fn states(&self) -> Vec<String> {
        self.seen.lock().unwrap().iter().filter(|e| e.name == EventName::Publication).map(|e| e.data["state"].as_str().unwrap_or("?").to_string()).collect()
    }

    fn position(&self) -> u64 {
        self.shell.call("health", &json!({"board": self.board})).unwrap()["health"]["log_position"].as_u64().unwrap()
    }
}

/// Checks the family end to end against the daemon.
///
/// A draft with text, a citation of the person's in a notes draft on those
/// words, a published set the edition is read with: `publication.open`
/// answers the panel — the notes row OFF with its one link, the counts at
/// the default, `windows` empty, `read_with` naming the set, the price under
/// its caps, every member declared; `publication.count` with the row ON
/// counts ⟨l⟩ one up, pure local; `publication.confirm` is acknowledged —
/// the member `E.1`, `via: answer`, `claim: false` — with the event's `sent`
/// then `acknowledged`, the panel gone, and the feed's publish row naming
/// the member, the draft and the notes; a second `open` finds no window and
/// its `confirm` is `inert: unchanged`; `cancel` says `cancelled` once and
/// answers `{}` twice; a `publish` frame through `op` is `publish_is_a_call`;
/// the node stopped, `confirm` and a `make_link` are refused `stopped`
/// before anything is composed or dialed; the mint form with `claim` mints
/// the edition, its first member and `claim: true`; a second claim into that
/// edition is `claim_refused` naming it, the board's position unmoved —
/// crossing as answered, nothing re-sent.
#[test]
fn the_family_publishes_a_drafts_links_and_answers_as_data() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let g = ground(&dir, &sd);
    let edition = g.addr(json!({"op": "create_new_document", "account": "1.0.1", "published": true}));
    let draft = g.draft("the quick brown fox");
    let notes = g.draft("notes here");
    let set = g.addr(json!({"op": "create_new_document", "account": "1.0.1", "published": true}));
    let citation = "1.1.0.1.0.1.0.3.13";
    // The notes' citation on the draft's words 5..9 ("quick"), the set read
    // with the edition.
    let link = g.addr(json!({"op": "make_link", "home": notes, "from": [{"source": draft, "span": {"start": "1.5", "width": "0.5"}}], "to": {"addrs": []}, "ty": {"addrs": [citation]}}));
    g.addr(json!({"op": "make_link", "home": set, "from": {"addrs": [edition]}, "to": {"addrs": [set]}, "ty": {"addrs": ["1.1.0.1.0.1.0.3.71"]}}));
    let inputs = json!({"session": g.session, "draft": draft, "doc": edition, "notes": [notes], "readable_drafts": [draft, notes], "published": [edition, set]});
    let panel = g.call("publication.open", inputs.clone()).unwrap_or_else(|r| panic!("{r}"));
    crate::shapes::assert_declared("PublicationPanel", &panel);
    for row in panel["rows"].as_array().unwrap() {
        crate::shapes::assert_declared("PublicationRow", row);
    }
    crate::shapes::assert_declared("Formatting", &panel["formatting"]);
    crate::shapes::assert_declared("Count", &panel["count"]);
    crate::shapes::assert_declared("Price", &panel["price"]);
    let rows = panel["rows"].as_array().unwrap();
    assert_eq!(rows.len(), 1, "the notes row alone — the draft's own set holds no link: {panel}");
    assert_eq!((rows[0]["home"].as_str(), rows[0]["kind"].as_str(), rows[0]["label"].as_str()), (Some(notes.as_str()), Some("notes"), Some("notes here")));
    assert_eq!(rows[0]["links"], json!([link]));
    assert_eq!(rows[0]["types"][0]["ty"], citation);
    assert_eq!(panel["count"], json!({"l": 0, "n": 0, "r": 0, "e": 0, "claim": false, "read_with": []}), "the counts at the default: every private row OFF");
    assert_eq!(panel["windows"], json!([]), "no run windows an unpublished origin of the person's");
    assert_eq!(panel["read_with"], json!({set.clone(): true}), "the set the edition is read with");
    assert_eq!(panel["price"]["over"], json!([]), "under every cap: {}", panel["price"]);
    assert!(panel["price"]["bytes"].as_u64().unwrap() > 0 && panel.get("hold").is_none(), "{panel}");
    // The count with the notes ON: ⟨l⟩ up by one, nothing dialed.
    let dials = g.shell.log().entries().len();
    let counted = g.call("publication.count", json!({"session": g.session, "switches": {"on": [notes]}})).unwrap();
    assert_eq!(counted["count"], json!({"l": 1, "n": 0, "r": 0, "e": 0, "claim": false, "read_with": []}), "{counted}");
    crate::shapes::assert_declared("Price", &counted["price"]);
    assert!(counted["price"]["bytes"].as_u64().unwrap() > panel["price"]["bytes"].as_u64().unwrap(), "the price moves with the switches: {counted}");
    assert_eq!(g.shell.log().entries().len(), dials + 1, "the count is pure local: its own call logged and no dial");
    let bad_home = g.call("publication.count", json!({"session": g.session, "switches": {"on": [edition]}})).unwrap_err();
    assert_eq!((bad_home.name(), bad_home.to_value()["what"].as_str()), ("malformed_args", Some("switches.on")), "a home no private row holds");
    let bad_answer = g.call("publication.count", json!({"session": g.session, "answers": {"0": "drop"}})).unwrap_err();
    assert_eq!((bad_answer.name(), bad_answer.to_value()["what"].as_str()), ("malformed_args", Some("answers")), "a run no window names");
    // The confirm: acknowledged, the events, the feed row.
    let before = g.position();
    let acked = g.call("publication.confirm", json!({"session": g.session, "switches": {"on": [notes]}})).unwrap_or_else(|r| panic!("{r}"));
    crate::shapes::assert_declared("Acknowledged", &acked);
    let member = format!("{edition}.1");
    assert_eq!((acked["outcome"].as_str(), acked["member"].as_str(), acked["via"].as_str(), acked["claim"].as_bool(), acked["edition"].is_null()), (Some("acknowledged"), Some(member.as_str()), Some("answer"), Some(false), true), "{acked}");
    let at = acked["at"].as_u64().unwrap();
    assert!(at > before);
    assert_eq!(g.states(), ["sent", "acknowledged"], "the event at the send and at the outcome");
    let events: Vec<Event> = g.seen.lock().unwrap().iter().filter(|e| e.name == EventName::Publication).cloned().collect();
    assert_events_declared(&events);
    assert_eq!((events[1].data["member"].as_str(), events[1].data["at"].as_u64(), events[1].data["draft"].as_str()), (Some(member.as_str()), Some(at), Some(draft.as_str())), "{:?}", events[1]);
    let entry = g.shell.sessions.get(&g.session).unwrap();
    let rows = changes_under(&entry.board, &entry.token, &edition, at - 1);
    let row = rows.iter().find(|r| r["at"] == at && r["op"] == "publish").unwrap_or_else(|| panic!("the publish row at {at}: {rows:?}"));
    let docs: Vec<&str> = row["docs"].as_array().unwrap().iter().filter_map(Value::as_str).collect();
    assert!(docs[0] == member && docs.contains(&draft.as_str()) && docs.contains(&notes.as_str()), "the row names the member, the draft and the notes: {docs:?}");
    let read = g.call("op", json!({"guest": true, "board": g.board, "frame": skep_client::board::frames::retrieve_v(&member, 1, 19)})).unwrap();
    assert_eq!(read["items"][0]["content"], "the quick brown fox");
    // The panel is gone with the acknowledgment; a second open finds the
    // draft re-windowed onto the member, no window, nothing to publish.
    assert_eq!(g.call("publication.count", json!({"session": g.session})).unwrap_err().name(), "no_panel", "the ceremony ended with the acknowledgment");
    let again = g.call("publication.open", inputs.clone()).unwrap_or_else(|r| panic!("{r}"));
    assert_eq!((again["windows"].clone(), again.get("hold")), (json!([]), None), "{again}");
    let inert = g.call("publication.confirm", json!({"session": g.session})).unwrap_or_else(|r| panic!("{r}"));
    crate::shapes::assert_declared("PublicationRefused", &inert);
    assert_eq!(inert, json!({"outcome": "refused", "arm": "inert", "inert": "unchanged"}));
    assert_eq!(g.states().last().map(String::as_str), Some("refused"));
    // The cancel, twice.
    assert_eq!(g.call("publication.cancel", json!({"session": g.session})).unwrap(), json!({}));
    assert_eq!(g.states().last().map(String::as_str), Some("cancelled"));
    let said = g.states().len();
    assert_eq!(g.call("publication.cancel", json!({"session": g.session})).unwrap(), json!({}));
    assert_eq!(g.states().len(), said, "the second cancel says nothing");
    assert_eq!(g.call("publication.confirm", json!({"session": g.session})).unwrap_err().name(), "no_panel");
    // A publish frame through op.
    let through_op = g.call("op", json!({"session": g.session, "frame": {"op": "publish", "doc": edition, "draft": draft, "runs": []}})).unwrap_err();
    assert_eq!(through_op.name(), "publish_is_a_call", "{through_op}");
    // The node stopped: the confirm refused before it composes, a make_link
    // before any dial.
    let fresh = g.draft("more words");
    g.call("publication.open", json!({"session": g.session, "draft": fresh, "doc": edition, "readable_drafts": [fresh], "published": [edition, set]})).unwrap_or_else(|r| panic!("{r}"));
    g.shell.set_node_state(NodeState::Stopped);
    let dials = g.shell.log().entries().iter().filter(|e| e["kind"] == "dial").count();
    let stopped = g.call("publication.confirm", json!({"session": g.session})).unwrap_err();
    assert_eq!((stopped.name(), stopped.to_value()["op"].as_str()), ("stopped", Some("publish")), "{stopped}");
    let link_stopped = g.call("op", json!({"session": g.session, "frame": {"op": "make_link", "home": notes, "from": {"addrs": [notes]}, "to": {"addrs": []}, "ty": {"addrs": [citation]}}})).unwrap_err();
    assert_eq!((link_stopped.name(), link_stopped.to_value()["op"].as_str()), ("stopped", Some("make_link")), "{link_stopped}");
    assert_eq!(g.shell.log().entries().iter().filter(|e| e["kind"] == "dial").count(), dials, "nothing dialed under the stop");
    assert_eq!(g.states().last().map(String::as_str), Some("refused"), "the event names the refusal's arm");
    g.shell.set_node_state(NodeState::Running);
    g.call("publication.cancel", json!({"session": g.session})).unwrap();
    // The mint form: the edition minted with its first member and the claim.
    let free = g.draft("a free-standing draft");
    let minted_panel = g.call("publication.open", json!({"session": g.session, "draft": free, "mint": "1.0.1", "claim": true, "readable_drafts": [free], "published": [edition, set]})).unwrap_or_else(|r| panic!("{r}"));
    assert_eq!(minted_panel["count"]["claim"], true);
    let minted = g.call("publication.confirm", json!({"session": g.session})).unwrap_or_else(|r| panic!("{r}"));
    let new_edition = minted["edition"].as_str().expect("the edition minted").to_string();
    assert_eq!((minted["outcome"].as_str(), minted["member"].as_str(), minted["claim"].as_bool()), (Some("acknowledged"), Some(format!("{new_edition}.1").as_str()), Some(true)), "{minted}");
    // A second claim into that edition: refused by the board, crossing as
    // answered, nothing re-sent, the board unmoved.
    let another = g.draft("another draft");
    g.call("publication.open", json!({"session": g.session, "draft": another, "doc": new_edition, "claim": true, "readable_drafts": [another], "published": [edition, set, new_edition]})).unwrap_or_else(|r| panic!("{r}"));
    let before = g.position();
    let refused = g.call("publication.confirm", json!({"session": g.session})).unwrap_or_else(|r| panic!("{r}"));
    assert_eq!(refused, json!({"outcome": "refused", "arm": "claim_refused", "edition": new_edition}), "{refused}");
    assert_eq!(g.position(), before, "a refusal commits nothing, and nothing is re-sent");
    assert!(g.states().ends_with(&["sent".to_string(), "refused".to_string()]), "{:?}", g.states());
    g.shell.shutdown();
    sd.shutdown();
}
