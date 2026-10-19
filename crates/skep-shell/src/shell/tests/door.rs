//! THE SHELL ALONE, with no daemon behind it: an `/op-at` refusal
//! rebuilt into the board's verdict under the wire's status; the dispatch
//! naming every call by its own spelling — `fetch` answered `streamed_call`
//! through it — and logging each as one entry of its outcome and sizes, and
//! `fetch` logging its own call, a stream's as its body is dropped; a
//! present argument of another form refused before any dial, `fetch`'s
//! address among them, and every optional argument a call row declares
//! read in its declared form; the guest form refusing every write kind of
//! the wire undialed and reading the board its reference or its origin
//! names, the reference first and the target before the frame; a bare
//! session refusing every write kind undialed, its `/op-at` form and its
//! `resolve(send)` too, while its read is dialed and a signed session's
//! write goes out; a search's
//! `opts` read as one value, and its query held to the shell's bound at
//! every target; a listing where no index stands its whole shape with no
//! document; a `select` of two keys or none refused by its name, a
//! label the box refuses `empty_label` naming its cause, and the signed
//! mode's check naming a keyless store; a probe of an own node that does
//! not answer `unreachable`; the shell's options printing no seed and the
//! open's preconditions stopped loudly; every day dated as the calendar
//! counts it; and the stop abandoning a walk that waits on the page, a walk
//! begun after it asking the page nothing, and a search or a listing after
//! it answered `feed_stopped`.

use std::io::{Read, Write};

use super::*;
use crate::sessions::{Facts, Open};
use crate::shapes::{Field, CALL_ROWS};

/// The `/op-at` refusals `skep-client` answers as values are the board's
/// verdicts again, each under the status and error document the wire
/// gives it, a member the variant knows riding the body and one it does
/// not left out.
#[test]
fn an_op_at_refusal_is_the_boards_verdict_under_the_wires_status() {
    let verdict = |a: AtAnswer| {
        let v = at_refusal(a).to_value();
        (v["kind"].as_str().map(str::to_string), v["status"].as_u64(), v["body"].clone())
    };
    let refused = |status: u64, body: Value| (Some("refused".to_string()), Some(status), body);
    assert_eq!(verdict(AtAnswer::HistoryReclaimed { floor: Some(5) }), refused(410, json!({"error": "history_reclaimed", "floor": 5})));
    assert_eq!(verdict(AtAnswer::HistoryReclaimed { floor: None }), refused(410, json!({"error": "history_reclaimed"})));
    assert_eq!(verdict(AtAnswer::BeyondHead { head: Some(12) }), refused(400, json!({"error": "beyond_head", "head": 12})));
    assert_eq!(verdict(AtAnswer::NotAPosition { nearest: Some(7) }), refused(400, json!({"error": "not_a_position", "nearest": 7})));
    assert_eq!(verdict(AtAnswer::Busy), refused(503, json!({"error": "history_busy"})));
    assert_eq!(at_refusal(AtAnswer::Busy).name(), "history_busy");
}

/// THE DISPATCH's NAMES: every call parses back from its own spelling, so no
/// two calls share one; `CALLS` is those spellings in §4b.1's order, the
/// document index's listing `places` beside `search`; a name of no call
/// names none, and `call` answers it `unknown_call`; and `fetch`, which
/// streams on its transport's own route, is answered `streamed_call` through
/// the door, whatever its arguments.
#[test]
fn every_call_is_named_by_its_own_spelling() {
    for call in Call::ALL {
        assert_eq!(Call::named(call.as_str()), Some(call));
    }
    assert_eq!(CALLS.map(Call::named), Call::ALL.map(Some));
    assert_eq!((CALLS.len(), CALLS[0], CALLS[23]), (24, "boards", "changes"));
    assert_eq!((CALLS[19], CALLS[20]), ("search", "places"));
    assert_eq!(Call::named("verify"), None);
    let (dir, (talk, _)) = (TempDir::new().unwrap(), talk());
    let shell = Shell::open(ShellOptions::new(Vec::new(), dir.path().join("store"), SessionMode::Bare { principal: 1 }, talk));
    assert_eq!(shell.call("verify", &json!({})).unwrap_err().name(), "unknown_call");
    assert_eq!(shell.call("fetch", &json!({"session": "s-x", "i": "1.0.1.0.1.0.1.1"})).unwrap_err().name(), "streamed_call");
}

/// A shell's options print what they name and nothing secret: the boards,
/// the store, the mode, the arm — a script's typed seed as `…` — and the own
/// node, the TALK sink left out.
#[test]
fn a_shells_options_print_no_seed() {
    let (talk, _) = talk();
    let mut opts = ShellOptions::new(vec![Origin::parse("http://127.0.0.1:8642").unwrap()], PathBuf::from("/tmp/store"), SessionMode::Signed { principal: 3 }, talk);
    opts.arm = ArmConfig::Script(vec![script::Answer::ImportTyped { seed_hex: "5e".repeat(32), fingerprint_prefix: "abcd".into() }]);
    let shown = format!("{opts:?}");
    assert!(shown.starts_with("ShellOptions { boards: [") && shown.contains("Signed { principal: 3 }") && shown.contains("ImportTyped") && shown.ends_with(", .. }"), "{shown}");
    assert!(!shown.contains("5e5e"), "{shown}");
}

/// THE OPEN's PRECONDITIONS are its caller's, stopped loudly before
/// anything starts: an own node outside the boards.
#[test]
#[should_panic(expected = "own_node")]
fn an_own_node_outside_the_boards_is_the_callers_bug() {
    let (talk, _) = talk();
    let mut opts = ShellOptions::new(Vec::new(), PathBuf::from("/nonexistent/store"), SessionMode::Bare { principal: 1 }, talk);
    opts.own_node = Some(Origin::parse("http://127.0.0.1:9").unwrap());
    let _ = Shell::open(opts);
}

/// THE OPEN's PRECONDITIONS: a board listed twice — two feeds and two held
/// stores over one chain — is the caller's bug.
#[test]
#[should_panic(expected = "distinct")]
fn a_board_listed_twice_is_the_callers_bug() {
    let (talk, _) = talk();
    let origin = Origin::parse("http://127.0.0.1:9").unwrap();
    let _ = Shell::open(ShellOptions::new(vec![origin.clone(), origin], PathBuf::from("/nonexistent/store"), SessionMode::Bare { principal: 1 }, talk));
}

/// An origin nothing answers at: a port bound and let go.
fn nowhere() -> String {
    let port = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap().local_addr().unwrap().port();
    format!("http://127.0.0.1:{port}")
}

/// A PRESENT ARGUMENT OF ANOTHER FORM is refused `malformed_args` naming it,
/// never read as absent and so never the row's default: a principal spelled
/// as a string or past 2^53 − 1, a label, a select, a paper flag, a lost
/// fingerprint, a search limit of another type, a listing's `opts` of no
/// object and its `under` of no address or of another spelling, and an `op`
/// naming neither form or both — each before any dial, the shell's board
/// one nothing answers at, where a dial would answer `unreachable`, and the
/// guest origin a listener counting every dial (the mutants that read such
/// a member as absent act as the mode's principal, open the label box, list
/// every key or the whole index, or dial a guest read the page never asked
/// for). A `null` is the row's default: the session opens as the mode's
/// principal and meets the board's silence.
#[test]
fn a_present_argument_of_another_form_is_refused_never_read_as_absent() {
    let dir = TempDir::new().unwrap();
    let (shell, _) = open_shell(&nowhere(), &dir.path().join("store"), SessionMode::Bare { principal: 1 });
    let _answerer = answer_moments(shell.subscribe(), Arc::clone(&shell.pending), Arc::new(Mutex::new(Vec::new())));
    let board = shell.board_references().remove(0);
    let (listener, dials) = counting_listener();
    let read = json!({"op": "doc_metadata", "doc": "1.0.1.0.1"});
    let cases = [
        ("session", json!({"board": board, "principal": "1"}), "principal"),
        ("session", json!({"board": board, "principal": 1u64 << 53}), "principal"),
        ("keygen", json!({"label": 7}), "label"),
        ("fingerprint", json!({"select": 7}), "select"),
        ("claim", json!({"board": board, "paper": "yes"}), "paper"),
        ("recover", json!({"board": board, "lost": [7]}), "lost"),
        ("search", json!({"guest": true, "board": board, "query": "x", "opts": {"limit": "5"}}), "opts.limit"),
        ("places", json!({"guest": true, "board": board, "opts": 7}), "opts"),
        ("places", json!({"guest": true, "board": board, "opts": {"under": 7}}), "opts.under"),
        ("places", json!({"guest": true, "board": board, "opts": {"under": "01.0.1"}}), "opts.under"),
        ("op", json!({"origin": listener, "frame": read}), "session"),
        ("op", json!({"guest": true, "session": "s-x", "origin": listener, "frame": read}), "session"),
    ];
    for (call, args, member) in cases {
        let refused = shell.call(call, &args).unwrap_err();
        let v = refused.to_value();
        assert_eq!((refused.name(), v["what"].as_str()), ("malformed_args", Some(member)), "{call} {args}: {v}");
    }
    assert_eq!(dials.load(Ordering::SeqCst), 0, "no dial for a refused argument");
    let defaulted = shell.call("session", &json!({"board": board, "principal": null})).unwrap_err();
    assert_eq!(defaulted.name(), "unreachable", "a null is the row's default, and the call goes on to the board");
}

/// EVERY OPTIONAL ARGUMENT A CALL ROW DECLARES IS READ IN ITS FORM (the
/// declarations' `CALL_ROWS`): for each row of one form, each optional
/// member it names — sent in a form no reader of its declared type takes,
/// beside the row's required members in theirs — is refused
/// `malformed_args` naming it, before any dial and before any moment (the
/// mutants that stop reading a declared member, or read it in another form
/// than the declared one, answer otherwise; the rows of two forms keep their
/// cells in `a_present_argument_of_another_form_is_refused_never_read_as_absent`).
#[test]
fn every_declared_optional_argument_is_read_in_its_form() {
    let dir = TempDir::new().unwrap();
    let (shell, _) = open_shell(&nowhere(), &dir.path().join("store"), SessionMode::Bare { principal: 1 });
    let _answerer = answer_moments(shell.subscribe(), Arc::clone(&shell.pending), Arc::new(Mutex::new(Vec::new())));
    let board = shell.board_references().remove(0);
    let in_form = |field: &Field| match (field.name, field.ty) {
        ("board", _) => json!(board),
        (_, "number") => json!(1),
        _ => json!("x"),
    };
    let in_no_form = |field: &Field| match field.ty {
        "string" => json!(7),
        "string[]" => json!([7]),
        _ => json!("x"),
    };
    let mut asked = 0;
    for row in CALL_ROWS {
        let [form] = row.forms else { continue };
        for member in form.iter().filter(|f| !f.required) {
            let mut args: serde_json::Map<String, Value> = form.iter().filter(|f| f.required).map(|f| (f.name.to_string(), in_form(f))).collect();
            args.insert(member.name.to_string(), in_no_form(member));
            let args = Value::Object(args);
            let refused = match shell.call(row.name, &args) {
                Ok(v) => panic!("{} {args}: answered {v}", row.name),
                Err(r) => r.to_value(),
            };
            assert_eq!((refused["name"].as_str(), refused["what"].as_str()), (Some("malformed_args"), Some(member.name)), "{} {args}: {refused}", row.name);
            asked += 1;
        }
    }
    assert_eq!(asked, 22, "the optional members of the eleven rows of one form that declare any");
}

/// THE GUEST FORM's SEARCH reads the board its reference or its canonical
/// origin names (§4b.1's `search` row): the shell's own board's origin is
/// that board — the target its reference is — and a reference is read
/// first, an origin beside it unread; an origin the shell holds no board at
/// answers with no index, a non-canonical one is refused `not_canonical`,
/// and a guest form naming neither is refused `malformed_args` (the mutants
/// that answer every origin with no index, read the origin ahead of the
/// reference, or read a missing target as a search with no index).
#[test]
fn a_guest_search_reads_the_board_its_reference_or_origin_names() {
    let dir = TempDir::new().unwrap();
    let own = nowhere();
    let (shell, _) = open_shell(&own, &dir.path().join("store"), SessionMode::Bare { principal: 1 });
    let board = shell.board_references().remove(0);
    for args in [json!({"guest": true, "board": board}), json!({"guest": true, "origin": own}), json!({"guest": true, "board": board, "origin": "not an origin"})] {
        assert!(matches!(shell.guest_target(&args), Ok(GuestTarget::Board(entry)) if entry.reference == board), "{args}");
    }
    let answer = shell.call("search", &json!({"guest": true, "origin": "http://127.0.0.1:9", "query": "x"})).unwrap();
    assert_eq!(answer["state"]["arm"], "none", "{answer}");
    let refused = shell.call("search", &json!({"guest": true, "origin": "not an origin", "query": "x"})).unwrap_err();
    assert_eq!(refused.name(), "not_canonical", "{refused}");
    let refused = shell.call("search", &json!({"guest": true, "query": "x"})).unwrap_err();
    assert_eq!((refused.name(), refused.to_value()["what"].as_str()), ("malformed_args", Some("board or origin")), "{refused}");
}

/// A listing where no index stands is its whole shape with no document.
///
/// At an origin this shell holds no board at, and at its own board whose
/// index never opened, prefix or none, the listing (A-255) is `{docs: [],
/// counts: [], state: none}`; and the guest form naming no target is refused
/// as `search`'s is. The mutants that answer the search's shape, or read the
/// foreign origin as a refusal, hand the page a listing it cannot draw.
#[test]
fn a_listing_where_no_index_stands_is_its_whole_shape_with_no_document() {
    let dir = TempDir::new().unwrap();
    let (shell, _) = open_shell(&nowhere(), &dir.path().join("store"), SessionMode::Bare { principal: 1 });
    let board = shell.board_references().remove(0);
    let empty = json!({"docs": [], "counts": [], "state": {"arm": "none"}});
    for args in [json!({"guest": true, "origin": "http://127.0.0.1:9"}), json!({"guest": true, "board": board}), json!({"guest": true, "board": board, "opts": {"under": "1.0.1"}})] {
        let listing = shell.call("places", &args).unwrap();
        crate::shapes::assert_declared("PlacesAnswer", &listing);
        assert_eq!(listing, empty, "{args}");
    }
    let refused = shell.call("places", &json!({"guest": true})).unwrap_err();
    assert_eq!((refused.name(), refused.to_value()["what"].as_str()), ("malformed_args", Some("board or origin")), "{refused}");
}

/// THE QUERY's BOUND is the shell's, asked of the call's text at every
/// target (§4b.1's `search` row: "length-bounded … then parsed"): a query a
/// byte past `QUERY_BOUND` is refused `query_too_long`, naming the bound
/// and the length and nothing of the text, at an origin this shell holds no
/// index for and at its own board alike, while a query at the bound is
/// answered (the mutant that leaves the bound to the library's index
/// answers the first `state: none`).
#[test]
fn a_query_past_the_bound_is_refused_at_every_target() {
    let dir = TempDir::new().unwrap();
    let (shell, _) = open_shell(&nowhere(), &dir.path().join("store"), SessionMode::Bare { principal: 1 });
    let board = shell.board_references().remove(0);
    let past = "x".repeat(QUERY_BOUND + 1);
    for args in [json!({"guest": true, "origin": "http://127.0.0.1:9", "query": past}), json!({"guest": true, "board": board, "query": past})] {
        let refused = shell.call("search", &args).unwrap_err().to_value();
        assert_eq!((refused["name"].as_str(), refused["bound"].as_u64(), refused["length"].as_u64()), (Some("query_too_long"), Some(1024), Some(1025)), "{refused}");
        assert!(!refused.to_string().contains("xxxxxxxx"), "the refusal holds no query text: {refused}");
    }
    let at = shell.call("search", &json!({"guest": true, "origin": "http://127.0.0.1:9", "query": "x".repeat(QUERY_BOUND)})).unwrap();
    assert_eq!(at["state"]["arm"], "none", "{at}");
}

/// A `search` call's `opts` are ONE value, as the bridge declares them:
/// absent, the defaults — the library's bounds and no refresh; present, each
/// member read into its place, the bounds the library takes and the refresh
/// beside them, a bound past `usize` saturating and never wrapping to a
/// smaller one (the mutant that reads `reindex` as absent searches an index
/// the page asked to refresh first; the one that narrows a bound with `as`
/// wraps a 32-bit target's offset of 2^32 + 5 back to the sixth hit).
#[test]
fn a_searchs_opts_are_one_value_as_the_bridge_declares_them() {
    assert_eq!(search_opts(&json!({"query": "x"})).unwrap(), BridgeSearchOpts::default());
    let opts = search_opts(&json!({"query": "x", "opts": {"limit": 5, "offset": 10, "reindex": true}})).unwrap();
    assert_eq!(opts, BridgeSearchOpts { bounds: SearchOpts { limit: 5, offset: 10 }, reindex: true });
    let wide = (1u64 << 32) + 5;
    let opts = search_opts(&json!({"query": "x", "opts": {"limit": wide, "offset": wide}})).unwrap();
    let kept = |bound: usize| bound == usize::MAX || u64::try_from(bound).is_ok_and(|b| b >= wide);
    assert!(kept(opts.bounds.limit) && kept(opts.bounds.offset), "a bound past `usize` saturates, never wraps: {opts:?}");
}

/// A shell over no board, its store a throwaway directory: no feed thread,
/// so nothing of its own dials.
fn boardless(dir: &TempDir) -> Shell {
    let (talk, _) = talk();
    Shell::open(ShellOptions::new(Vec::new(), dir.path().join("store"), SessionMode::Bare { principal: 1 }, talk))
}

/// EVERY CALL IS ONE LOG ENTRY (the call log the page's gate reads): a
/// result, an armed refusal, a call of no name and `fetch` through the door
/// each placed once, in order, its outcome the one it answered and its
/// sizes the compact JSON of its arguments and of its answer — the refusal
/// as the page renders it — and the call of no name kept as `<unknown>` by
/// its name's length (the mutants that log results alone, swap the two
/// outcomes, skip a call of no name, keep its bytes, or measure a refusal by
/// its text).
#[test]
fn every_call_is_one_log_entry_naming_its_outcome_and_sizes() {
    let dir = TempDir::new().unwrap();
    let shell = boardless(&dir);
    let calls = [
        ("boards", json!({})),
        ("probe", json!({})),
        ("health", json!({"board": "b-nowhere"})),
        ("verify", json!({})),
        ("fetch", json!({"session": "s-gone", "i": "1.0.1.0.1.0.1.1"})),
        ("held", json!({"session": "s-gone"})),
    ];
    let mut expected = Vec::new();
    for (name, args) in &calls {
        let (outcome, bytes_out) = match shell.call(name, args) {
            Ok(v) => ("result", v.to_string().len()),
            Err(r) => ("refused", r.to_value().to_string().len()),
        };
        // A name the bridge does not spell is logged by its length alone.
        let logged_as = if CALLS.contains(name) { *name } else { "<unknown>" };
        expected.push(json!({"kind": "call", "call": logged_as, "outcome": outcome, "bytes_in": args.to_string().len(), "bytes_out": bytes_out}));
    }
    let outcomes: Vec<&str> = expected.iter().map(|e| e["outcome"].as_str().unwrap()).collect();
    assert_eq!(outcomes, ["result", "result", "refused", "refused", "refused", "refused"]);
    let logged: Vec<Value> =
        shell.log().entries().iter().map(|e| json!({"kind": e["kind"], "call": e["call"], "outcome": e["outcome"], "bytes_in": e["bytes_in"], "bytes_out": e["bytes_out"]})).collect();
    assert_eq!(logged, expected, "one entry per call, in order");
    assert_eq!(shell.log().entries()[3]["name_bytes"], "verify".len(), "the unknown name's length, never its bytes");
}

/// A board answering one `/blob` read with `body`, its `200` declaring the
/// body's length.
fn one_blob(body: &'static [u8]) -> String {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let origin = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    thread::spawn(move || {
        let Ok((mut stream, _)) = listener.accept() else { return };
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            match stream.read(&mut byte) {
                Ok(1) => head.push(byte[0]),
                _ => return,
            }
        }
        let _ = write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
        let _ = stream.write_all(body);
    });
    origin
}

/// A FETCH LOGS ITS OWN CALL, as `call` logs every row: a refusal at once,
/// its sizes the compact JSON of its arguments and of the refusal; a stream
/// as its body is dropped — never while the body is read — `bytes_out` the
/// bytes its reader took (the mutants that leave the entry to the
/// transport, which a page hanging up mid-stream skips, or write it as
/// `fetch` returns, before a byte is read).
#[test]
fn a_fetch_logs_its_own_call() {
    let dir = TempDir::new().unwrap();
    let shell = boardless(&dir);
    let fetches = || -> Vec<Value> { shell.log().entries().into_iter().filter(|e| e["kind"] == "call" && e["call"] == "fetch").collect() };
    let gone = json!({"session": "s-gone", "i": "1.0.1.0.1.0.1.1"});
    let refused = shell.fetch(&gone).unwrap_err();
    let logged = fetches();
    assert_eq!(logged.len(), 1, "{logged:?}");
    let sizes = |e: &Value| (e["outcome"].as_str().map(str::to_string), e["bytes_in"].as_u64(), e["bytes_out"].as_u64());
    assert_eq!(sizes(&logged[0]), (Some("refused".into()), Some(gone.to_string().len() as u64), Some(refused.to_value().to_string().len() as u64)), "{}", logged[0]);
    let guest = json!({"guest": true, "origin": one_blob(b"hello"), "i": "1.0.1.0.1.0.1.1"});
    let mut fetched = shell.fetch(&guest).unwrap();
    let mut read = [0u8; 2];
    fetched.body.read_exact(&mut read).unwrap();
    assert_eq!(&read, b"he");
    assert_eq!(fetches().len(), 1, "no entry while the body is read");
    drop(fetched);
    let logged = fetches();
    assert_eq!(logged.len(), 2, "{logged:?}");
    assert_eq!(sizes(&logged[1]), (Some("stream".into()), Some(guest.to_string().len() as u64), Some(2)), "{}", logged[1]);
}

/// A FETCH's ADDRESS IS READ BEFORE ANY DIAL (`fetch`'s row: `i` an
/// address, else `malformed_args` naming it), so no page's text reaches the
/// request line the shell sends: an address carrying a second query member,
/// one carrying a line break and a header of its own, one in another
/// spelling and one of another type are each refused naming `i` while a
/// listener at the named origin counts no connection — and an address in
/// its one spelling there is dialed (the mutant that drops the check
/// splices the page's text into the request the board is sent).
#[test]
fn a_fetchs_address_is_read_before_any_dial() {
    let dir = TempDir::new().unwrap();
    let shell = boardless(&dir);
    let (origin, dials) = counting_listener();
    let fetch = |i: Value| shell.fetch(&json!({"guest": true, "origin": origin, "i": i}));
    for i in [json!("1.0.1.0.1.0.1.1&i=1.0.2.0.1.0.1.1"), json!("1.0.1.0.1.0.1.1 HTTP/1.1\r\nX-Injected: 1"), json!("01.0.1.0.1.0.1.1"), json!(7)] {
        let refused = fetch(i.clone()).unwrap_err().to_value();
        assert_eq!((refused["name"].as_str(), refused["what"].as_str()), (Some("malformed_args"), Some("i")), "{i}: {refused}");
    }
    assert_eq!(dials.load(Ordering::SeqCst), 0, "no address of another form is dialed");
    assert_eq!(fetch(json!("1.0.1.0.1.0.1.1")).unwrap_err().name(), "unreachable", "the listener answers nothing");
    let deadline = Instant::now() + Duration::from_secs(5);
    while dials.load(Ordering::SeqCst) == 0 && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    assert!(dials.load(Ordering::SeqCst) >= 1, "an address in its one spelling is dialed");
}

/// A PROBE OF A NODE THAT DOES NOT ANSWER is `unreachable` (`probe()`'s
/// row): a shell whose own node is a board nothing answers at names that
/// node, dialed and signed at itself, and its state `unreachable`; a shell
/// over no board names none (the mutant that reads the node's silence as
/// `running` tells the page a node it cannot reach stands).
#[test]
fn a_probe_of_a_node_that_does_not_answer_is_unreachable() {
    let (dir, other) = (TempDir::new().unwrap(), TempDir::new().unwrap());
    let own = nowhere();
    let (talk, _) = talk();
    let mut opts = ShellOptions::new(vec![Origin::parse(&own).unwrap()], dir.path().join("store"), SessionMode::Bare { principal: 1 }, talk);
    opts.own_node = Some(Origin::parse(&own).unwrap());
    let shell = Shell::open(opts);
    assert_eq!(shell.call("probe", &json!({})).unwrap(), json!({"daemon": "unreachable", "dialed": own, "signed": own}));
    assert_eq!(boardless(&other).call("probe", &json!({})).unwrap(), json!({"daemon": "unreachable", "dialed": null, "signed": null}));
}

/// A listener that accepts every connection, counts it and drops it: a
/// board that answers nothing and says how many dials reached it.
fn counting_listener() -> (String, Arc<AtomicUsize>) {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let origin = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let dials = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&dials);
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            counted.fetch_add(1, Ordering::SeqCst);
            drop(stream);
        }
    });
    (origin, dials)
}

/// A listener that accepts every connection, reads its one request — its
/// head through the blank line, its body as long as its `Content-Length`
/// says — keeps the body's JSON, and drops the connection: a board that
/// answers nothing and says what frames reached it.
fn recording_listener() -> (String, Arc<Mutex<Vec<Value>>>) {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let origin = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let frames = Arc::new(Mutex::new(Vec::new()));
    let kept = Arc::clone(&frames);
    thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            let kept = Arc::clone(&kept);
            thread::spawn(move || {
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    match stream.read(&mut byte) {
                        Ok(1) => head.push(byte[0]),
                        _ => return,
                    }
                }
                let head = String::from_utf8_lossy(&head).into_owned();
                let declared = head.lines().filter_map(|line| line.split_once(':')).find(|(name, _)| name.eq_ignore_ascii_case("content-length")).and_then(|(_, n)| n.trim().parse().ok()).unwrap_or(0);
                let mut body = vec![0u8; declared];
                if stream.read_exact(&mut body).is_ok() {
                    if let Ok(frame) = serde_json::from_slice::<Value>(&body) {
                        kept.lock().unwrap().push(frame);
                    }
                }
            });
        }
    });
    (origin, frames)
}

/// A BARE SESSION's WRITE IS REFUSED BEFORE ANY DIAL (foundations §3.3 state
/// 3, E16 (a′): the keyless session reads alone, "no `bare` write ever
/// committed by this client"): under a bare session every write kind of the
/// wire is refused `write_in_bare_session` naming its op, in the `op` form
/// and the `/op-at` form alike, and its `resolve(send)` naming its act, while
/// a listener at its board records no write frame; its read is dialed, and
/// `resolve`'s `drop`, which commits nothing to the board, is answered as
/// the line's absence; a signed session's write at the same board is dialed
/// (the mutant that refuses in the guest form alone sends the bare session's
/// write unattested, for the board to commit as `bare`; the one that fences
/// the `op` form alone sends its `/op-at` form).
#[test]
fn a_bare_sessions_write_is_refused_before_any_dial() {
    let dir = TempDir::new().unwrap();
    let (origin, frames) = recording_listener();
    let (shell, _) = open_shell(&origin, &dir.path().join("store"), SessionMode::Bare { principal: 1 });
    let board = shell.board_references().remove(0);
    let register = |token: &str, facts: Facts| -> String {
        let open = Open { token: Token::parse(&token.repeat(16)).unwrap(), facts, opened_at: 0 };
        shell.sessions.register(&shell.boards[0], open, &mut shell.feed(&board)).reference.clone()
    };
    let bare = register("9f", Facts { principal: 1, account: Some("1.0.1".into()), kind: SessionKind::Bare });
    let fingerprint = skep_identity::Fingerprint::parse_hex(&"5a".repeat(32)).unwrap();
    let signed = register("8e", Facts { principal: 2, account: Some("1.0.2".into()), kind: SessionKind::Signed { fingerprint, set_account: "1.0.2".into() } });
    for op in WRITE_KINDS {
        for frame in [json!({"op": op}), json!({"at": 5, "frame": {"op": op}})] {
            let refused = shell.call("op", &json!({"session": bare, "frame": frame})).unwrap_err();
            let v = refused.to_value();
            assert_eq!((refused.name(), v["kind"].as_str(), v["op"].as_str()), ("write_in_bare_session", Some("shell"), Some(op)), "{frame}: {v}");
        }
    }
    let refused = shell.call("resolve", &json!({"session": bare, "held": 1, "act": "send"})).unwrap_err().to_value();
    assert_eq!((refused["name"].as_str(), refused["act"].as_str()), (Some("write_in_bare_session"), Some("send")), "{refused}");
    assert_eq!(shell.call("resolve", &json!({"session": bare, "held": 1, "act": "drop"})).unwrap_err().name(), "no_such_held", "a drop commits nothing to the board, and stands");
    let read = json!({"op": "doc_metadata", "doc": "1.0.1.0.1"});
    assert_eq!(shell.call("op", &json!({"session": bare, "frame": read})).unwrap_err().name(), "unreachable", "a read is dialed");
    let delete = json!({"op": "delete", "doc": "1.0.2.0.1", "p": {"subspace": "1", "ordinal": "1"}, "width": "1"});
    let held = shell.call("op", &json!({"session": signed, "frame": delete})).unwrap();
    assert_eq!(held["resp"], "held", "the signed session's write is dialed, its answer lost: {held}");
    let recorded = frames.lock().unwrap().clone();
    let writes: Vec<&Value> = recorded.iter().filter(|f| f["op"].as_str().is_some_and(|op| WRITE_KINDS.contains(&op))).collect();
    assert_eq!(writes, [&delete], "the signed session's write alone reached the board: {recorded:?}");
    assert!(recorded.contains(&read), "the bare session's read reached it: {recorded:?}");
}

/// THE GUEST FORM REFUSES EVERY WRITE KIND OF THE WIRE WITHOUT A DIAL (ps3-5):
/// `WRITE_KINDS` is the wire's sixteen write kinds (`docs/wire.md`
/// §Operations; skepd's `parse_op`), each refused `write_in_guest_form`
/// naming its op while a listener at the named origin counts no connection
/// — the target the form names read first, so a write at a board this
/// shell never issued is `unknown_board` — and a guest READ there is
/// dialed, so the listener sees what a dial would be (the mutants that dial
/// first and refuse after, or refuse the write before its target is read).
#[test]
fn the_guest_form_refuses_every_write_kind_of_the_wire_without_a_dial() {
    let mut listed = WRITE_KINDS.to_vec();
    listed.sort_unstable();
    let mut wire = [
        "create_new_document",
        "delegate",
        "register_node",
        "fork",
        "insert",
        "delete",
        "copy",
        "reinstate",
        "rearrange",
        "version",
        "publish",
        "make_link",
        "emit",
        "nullify",
        "assert_sup",
        "edit_link",
    ];
    wire.sort_unstable();
    assert_eq!(listed, wire, "the guest form's write kinds are the wire's");
    let dir = TempDir::new().unwrap();
    let shell = boardless(&dir);
    let (origin, dials) = counting_listener();
    for op in WRITE_KINDS {
        let refused = shell.call("op", &json!({"guest": true, "origin": origin, "frame": {"op": op}})).unwrap_err();
        let v = refused.to_value();
        assert_eq!((refused.name(), v["op"].as_str()), ("write_in_guest_form", Some(op)), "{v}");
    }
    let unknown = shell.call("op", &json!({"guest": true, "board": "b-nowhere", "frame": {"op": "insert"}})).unwrap_err();
    assert_eq!(unknown.name(), "unknown_board", "the target is read before the frame: {unknown}");
    assert_eq!(dials.load(Ordering::SeqCst), 0, "no write in the guest form is dialed");
    let read = shell.call("op", &json!({"guest": true, "origin": origin, "frame": {"op": "doc_metadata", "doc": "1.0.1.0.1"}}));
    assert_eq!(read.unwrap_err().name(), "unreachable", "the listener answers nothing");
    let deadline = Instant::now() + Duration::from_secs(5);
    while dials.load(Ordering::SeqCst) == 0 && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(10));
    }
    assert!(dials.load(Ordering::SeqCst) >= 1, "the listener counts a guest read's dial");
}

/// THE STOP ABANDONS A WALK WAITING ON THE PAGE: `keygen` with no label
/// waits on its device-name box, a PUBLIC moment; the shell's stop cancels
/// it, and the walk answers `abandoned` (the mutant whose stop cancels no
/// pending moment leaves the walk — and the transport's connection thread
/// with it — waiting for an answer no page will give; the deadline cancels
/// it by hand, so the mutant fails rather than hangs).
#[test]
fn the_stop_abandons_a_walk_waiting_on_the_page() {
    let dir = TempDir::new().unwrap();
    let shell = boardless(&dir);
    let rx = shell.subscribe();
    let (moment, finished, answer) = thread::scope(|s| {
        let walk = s.spawn(|| shell.call("keygen", &json!({})));
        let moment = rx.recv_timeout(Duration::from_secs(5)).ok();
        shell.shutdown();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !walk.is_finished() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        let finished = walk.is_finished();
        if let Some(id) = moment.as_ref().and_then(|m| m.data["id"].as_str()) {
            let _ = shell.cancel(id);
        }
        (moment, finished, walk.join().unwrap())
    });
    assert_eq!(moment.map(|m| m.data["kind"].clone()), Some(json!("label")), "the walk waited on its device-name box");
    assert!(finished, "the stop left the walk waiting on the page");
    assert_eq!(answer.unwrap_err().name(), "abandoned");
}

/// A WALK BEGUN AFTER THE STOP asks the page nothing: the stop closes the
/// moment table, so `keygen` with no label — its device-name box a PUBLIC
/// moment — is abandoned at once, no `moment` event sent (the mutant whose
/// stop drains the table and leaves it open enters the box and waits on a
/// page that will never answer; the deadline cancels it by hand, so the
/// mutant fails rather than hangs).
#[test]
fn a_walk_begun_after_the_stop_asks_the_page_nothing() {
    let dir = TempDir::new().unwrap();
    let shell = boardless(&dir);
    let rx = shell.subscribe();
    shell.shutdown();
    let (finished, moments, answer) = thread::scope(|s| {
        let walk = s.spawn(|| shell.call("keygen", &json!({})));
        let deadline = Instant::now() + Duration::from_secs(5);
        while !walk.is_finished() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        let finished = walk.is_finished();
        let moments: Vec<Event> = rx.try_iter().filter(|e| e.name == EventName::Moment).collect();
        for id in moments.iter().filter_map(|m| m.data["id"].as_str()) {
            let _ = shell.cancel(id);
        }
        (finished, moments, walk.join().unwrap())
    });
    assert!(finished, "a walk begun after the stop waited on the page");
    assert!(moments.is_empty(), "a moment after the stop crossed to the page: {moments:?}");
    assert_eq!(answer.unwrap_err().name(), "abandoned");
}

/// A `select` MATCHING TWO KEYS, OR NONE, is refused by its name: two keys
/// under one label answer `ambiguous`, naming each match by its fingerprint
/// and label; a label of no key answers `not_found`, naming it (the mutants
/// that read either as the store's own fault, `store_unreadable`, or list
/// every key for a select that names none).
#[test]
fn a_select_of_two_keys_or_none_is_refused_by_its_name() {
    let dir = TempDir::new().unwrap();
    let shell = boardless(&dir);
    let fingerprints: Vec<Value> = (0..2).map(|_| shell.call("keygen", &json!({"label": "phone"})).unwrap()["fingerprint"].clone()).collect();
    let refused = shell.call("fingerprint", &json!({"select": "phone"})).unwrap_err().to_value();
    let matches = refused["matches"].as_array().cloned().unwrap_or_default();
    assert_eq!((refused["name"].as_str(), matches.len()), (Some("ambiguous"), 2), "{refused}");
    assert!(matches.iter().all(|m| m["label"] == "phone" && fingerprints.contains(&m["fingerprint"])), "each match named by its key: {refused}");
    let refused = shell.call("fingerprint", &json!({"select": "a-label-of-no-key"})).unwrap_err().to_value();
    assert_eq!((refused["name"].as_str(), refused["select"].as_str()), (Some("not_found"), Some("a-label-of-no-key")), "{refused}");
}

/// A LABEL REFUSED AT THE BOX is `empty_label` over AUTH-1.24's whole
/// domain, naming its `cause`: an empty label, one holding a line break and
/// one a byte past the bound, each refused with no key written — and a label
/// at the bound exactly taken (the mutants that name a line break or a long
/// label another refusal, drop the `cause`, or write a key for a label the
/// box refuses).
#[test]
fn a_label_refused_at_the_box_is_empty_label_naming_its_cause() {
    let dir = TempDir::new().unwrap();
    let shell = boardless(&dir);
    for (label, cause) in [(String::new(), "a name is required"), ("a\nb".to_string(), "line break"), ("x".repeat(129), "129 bytes")] {
        let refused = shell.call("keygen", &json!({"label": label})).unwrap_err().to_value();
        assert_eq!(refused["name"], "empty_label", "{label:?}: {refused}");
        assert!(refused["cause"].as_str().is_some_and(|c| c.contains(cause)), "{label:?}: the refusal names its cause: {refused}");
    }
    assert!(shell.call("fingerprint", &json!({})).unwrap().as_array().unwrap().is_empty(), "no key is written for a label the box refuses");
    assert!(shell.call("keygen", &json!({"label": "x".repeat(128)})).is_ok(), "a label at the bound exactly is taken");
}

/// THE SIGNED MODE's CHECK before serving names a keyless store: `no_key`
/// under the signed mode, the board's mode read for the face alone — a
/// board nothing answers at taken as unclaimed — and, under the bare mode,
/// `Ok` with no key, its sessions signing nothing (the mutant that answers
/// a keyless signed check `Ok` serves a signed page that can sign nothing).
#[test]
fn the_signed_modes_check_names_a_keyless_store() {
    let dir = TempDir::new().unwrap();
    let (signed, _) = open_shell(&nowhere(), &dir.path().join("signed"), SessionMode::Signed { principal: 1 });
    assert_eq!(signed.check_signed_key().unwrap_err().name(), "no_key");
    let (bare, _) = open_shell(&nowhere(), &dir.path().join("bare"), SessionMode::Bare { principal: 1 });
    assert!(bare.check_signed_key().unwrap().is_empty(), "the bare mode's sessions sign nothing");
}

/// A search or a listing after the stop answers `feed_stopped` at once.
///
/// The board's feed thread is joined, its handle's send meets no receiver,
/// and the call is refused — never a panic at the send, never a wait. The
/// mutant that unwraps the send panics the transport's connection thread.
#[test]
fn a_search_or_a_listing_after_the_stop_answers_feed_stopped() {
    let dir = TempDir::new().unwrap();
    let (shell, _) = open_shell(&nowhere(), &dir.path().join("store"), SessionMode::Bare { principal: 1 });
    let board = shell.board_references().remove(0);
    shell.shutdown();
    let started = Instant::now();
    let refused = shell.call("search", &json!({"guest": true, "board": board, "query": "x"})).unwrap_err();
    assert_eq!(refused.name(), "feed_stopped", "{refused}");
    let refused = shell.call("places", &json!({"guest": true, "board": board})).unwrap_err();
    assert_eq!(refused.name(), "feed_stopped", "{refused}");
    assert!(started.elapsed() < Duration::from_secs(1), "answered at once, not after {:?}", started.elapsed());
}

/// EVERY DAY IS DATED as the calendar counts it: `civil_date` over every day
/// from 1970-01-01 through 2400-12-31, at its first second and at its last,
/// against a day-by-day count with the Gregorian leap rule spelled out — the
/// date an anchor box's default label carries, which AUTH-5.42 makes
/// permanent (the mutants in the algorithm's constants, its month fold or
/// its year carry misdate some day of the four centuries).
#[test]
fn every_day_is_dated_as_the_calendar_counts_it() {
    let leap = |year: u64| (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400);
    let mut day = 0u64;
    for year in 1970..=2400u64 {
        for month in 1..=12u64 {
            let days = match month {
                2 if leap(year) => 29,
                2 => 28,
                4 | 6 | 9 | 11 => 30,
                _ => 31,
            };
            for date in 1..=days {
                let counted = format!("{year:04}-{month:02}-{date:02}");
                assert_eq!(civil_date(day * 86_400), counted, "the first second of day {day}");
                assert_eq!(civil_date(day * 86_400 + 86_399), counted, "the last second of day {day}");
                day += 1;
            }
        }
    }
}
