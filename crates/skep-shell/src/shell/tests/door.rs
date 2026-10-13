//! THE SHELL's OWN FRAME, with no daemon behind it: an `/op-at` refusal
//! rebuilt into the board's verdict under the wire's status; the dispatch
//! naming every call by its own spelling and logging each as one entry of
//! its outcome and sizes; a present argument of another form refused before
//! any dial; the guest form refusing every write kind of the wire undialed
//! and reading the board its reference or its origin names; a search's
//! `opts` read as one value; a `select` of two keys or none refused by its
//! name, and the signed mode's check naming a keyless store; its options
//! printing no seed and the open's preconditions stopped loudly; every day
//! dated as the calendar counts it; and the stop abandoning a walk that
//! waits on the page, a search after it answered `feed_stopped`.

use super::*;

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
/// two calls share one; `CALLS` is those spellings in §4b.1's order; a name
/// of no call names none, and `call` answers it `unknown_call`.
#[test]
fn every_call_is_named_by_its_own_spelling() {
    for call in Call::ALL {
        assert_eq!(Call::named(call.as_str()), Some(call));
    }
    assert_eq!(CALLS.map(Call::named), Call::ALL.map(Some));
    assert_eq!((CALLS.len(), CALLS[0], CALLS[21]), (22, "boards", "resolve"));
    assert_eq!(Call::named("verify"), None);
    let (dir, (talk, _)) = (TempDir::new().unwrap(), talk());
    let shell = Shell::open(ShellOptions::new(Vec::new(), dir.path().join("store"), SessionMode::Bare { principal: 1 }, talk));
    assert_eq!(shell.call("verify", &json!({})).unwrap_err().name(), "unknown_call");
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
/// fingerprint, a search limit of another type, and an `op` naming neither
/// form or both — each before any dial, the shell's board one nothing
/// answers at, where a dial would answer `unreachable`, and the guest
/// origin a listener counting every dial (the mutants that read such a
/// member as absent act as the mode's principal, open the label box, list
/// every key, or dial a guest read the page never asked for). A `null` is
/// the row's default: the session opens as the mode's principal and meets
/// the board's silence.
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

/// THE GUEST FORM's SEARCH reads the board its reference or its canonical
/// origin names (§4b.1's `search` row): the shell's own board's origin is
/// that board — the target its reference is — an origin the shell holds no
/// board at answers with no index, a non-canonical one is refused
/// `not_canonical`, and a guest form naming neither is refused
/// `malformed_args` (the mutants that answer every origin with no index, or
/// read a missing target as a search with no index).
#[test]
fn a_guest_search_reads_the_board_its_reference_or_origin_names() {
    let dir = TempDir::new().unwrap();
    let own = nowhere();
    let (shell, _) = open_shell(&own, &dir.path().join("store"), SessionMode::Bare { principal: 1 });
    let board = shell.board_references().remove(0);
    for args in [json!({"guest": true, "board": board}), json!({"guest": true, "origin": own})] {
        assert!(matches!(shell.guest_target(&args), Ok(GuestTarget::Board(entry)) if entry.reference == board), "{args}");
    }
    let answer = shell.call("search", &json!({"guest": true, "origin": "http://127.0.0.1:9", "query": "x"})).unwrap();
    assert_eq!(answer["state"]["arm"], "none", "{answer}");
    let refused = shell.call("search", &json!({"guest": true, "origin": "not an origin", "query": "x"})).unwrap_err();
    assert_eq!(refused.name(), "not_canonical", "{refused}");
    let refused = shell.call("search", &json!({"guest": true, "query": "x"})).unwrap_err();
    assert_eq!((refused.name(), refused.to_value()["what"].as_str()), ("malformed_args", Some("board or origin")), "{refused}");
}

/// A `search` call's `opts` are ONE value, as the bridge declares them:
/// absent, the defaults — the library's bounds and no refresh; present, each
/// member read into its place, the bounds the library takes and the refresh
/// beside them (the mutant that reads `reindex` as absent searches an index
/// the page asked to refresh first).
#[test]
fn a_searchs_opts_are_one_value_as_the_bridge_declares_them() {
    assert_eq!(search_opts(&json!({"query": "x"})).unwrap(), BridgeSearchOpts::default());
    let opts = search_opts(&json!({"query": "x", "opts": {"limit": 5, "offset": 10, "reindex": true}})).unwrap();
    assert_eq!(opts, BridgeSearchOpts { bounds: SearchOpts { limit: 5, offset: 10 }, reindex: true });
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

/// THE GUEST FORM REFUSES EVERY WRITE KIND OF THE WIRE WITHOUT A DIAL (ps3-5):
/// `WRITE_KINDS` is the wire's sixteen write kinds (`docs/wire.md`
/// §Operations; skepd's `parse_op`), each refused `write_in_guest_form`
/// naming its op while a listener at the named origin counts no connection
/// — and a guest READ there is dialed, so the listener sees what a dial
/// would be (the mutant that dials first and refuses after).
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

/// A SEARCH AFTER THE STOP answers `feed_stopped` at once: the board's feed
/// thread joined, its handle's send meets no receiver, and the call is
/// refused — never a panic at the send, never a wait (the mutant that
/// unwraps the send panics the transport's connection thread).
#[test]
fn a_search_after_the_stop_answers_feed_stopped() {
    let dir = TempDir::new().unwrap();
    let (shell, _) = open_shell(&nowhere(), &dir.path().join("store"), SessionMode::Bare { principal: 1 });
    let board = shell.board_references().remove(0);
    shell.shutdown();
    let started = Instant::now();
    let refused = shell.call("search", &json!({"guest": true, "board": board, "query": "x"})).unwrap_err();
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
