//! The follower write against the real daemon in-process (§3c.6).
//!
//! Its writes are a signed session's on a claimed board — the attest a
//! follower's resolved I-span ends sign over among them. The suite checks a
//! mark sent after its insert was acked landing on the insert's own words,
//! its `to` the I-span the piece names; a follower of a burst the own node's
//! stop held refused `not_followed`, nothing written; a `nullify` following a
//! `delete`, and a piece after a `delete` refused; a follower that overtakes
//! its insert waiting for it and landing; and the shell's stop finishing a
//! follower whose burst it answers while the stop waits, before any session
//! closes, the mark read back by a fresh shell.

use super::*;

/// The type the suite's marks carry: an address, as a link type is named.
const MARK_TYPE: &str = "1.1.0.1.0.1.0.3.13";

/// The ground every cell stands on.
///
/// It is the shell over a claimed board, its TALK lines, a signed session's
/// reference and a draft just minted — each by its name, so no cell takes
/// one reference for another.
struct FollowGround {
    shell: Shell,
    lines: Arc<Mutex<Vec<String>>>,
    origin: String,
    store: PathBuf,
    session: String,
    draft: String,
    /// The draft's state as the ground leaves it, which its first burst is
    /// typed against (`as_of`, wire.md §Arrangement).
    at: u64,
}

/// Builds the ground: a claimed board, a signed shell over it — the board
/// its own node where `own_node` — a session and a draft.
fn follow_ground(dir: &TempDir, sd: &Skepd, own_node: bool) -> FollowGround {
    let origin = format!("http://127.0.0.1:{}", sd.port());
    let store = dir.path().join("store");
    claim_board(&origin, &store);
    let (talk, lines) = talk();
    let mut opts = ShellOptions::new(vec![Origin::parse(&origin).unwrap()], store.clone(), SessionMode::Signed { principal: 1 }, talk);
    if own_node {
        opts.own_node = Some(Origin::parse(&origin).unwrap());
    }
    let shell = Shell::open(opts);
    let board = shell.call("boards", &json!({})).unwrap()[0]["board"].as_str().unwrap().to_string();
    let session = shell.call("session", &json!({"board": board})).unwrap()["session"].as_str().unwrap().to_string();
    let minted = shell.call("op", &json!({"session": session, "frame": {"op": "create_new_document", "account": "1.0.1"}})).unwrap();
    let (draft, at) = (minted["addr"].as_str().unwrap().to_string(), minted["at"].as_u64().unwrap());
    FollowGround { shell, lines, origin, store, session, draft, at }
}

impl FollowGround {
    /// The answer of an `op` frame under the ground's session.
    fn op(&self, frame: Value) -> Result<Value, Refusal> {
        self.shell.call("op", &json!({"session": self.session, "frame": frame}))
    }

    /// The answer of a follower of the burst `after`.
    fn follow(&self, after: &str, frame: Value) -> Result<Value, Refusal> {
        self.shell.call("op", &json!({"session": self.session, "after": after, "frame": frame}))
    }

    /// An insert of `text` at the draft's first position, carrying `id`
    /// where one is given.
    fn insert(&self, id: Option<&str>, text: &str) -> Value {
        let mut frame = json!({"op": "insert", "doc": self.draft, "at": {"subspace": "1", "ordinal": "1"}, "values": [text], "as_of": self.at});
        if let Some(id) = id {
            frame["id"] = Value::from(id);
        }
        frame
    }

    /// A formatting mark homed in the draft: a one-sided link, its matter in
    /// `to`, the I-span form's `spans` — a piece among them.
    fn mark(&self, spans: Value) -> Value {
        json!({"op": "make_link", "home": self.draft, "from": {"spans": []}, "to": {"spans": spans}, "ty": {"addrs": [MARK_TYPE]}})
    }

    /// The TALK lines said so far, joined.
    fn talk(&self) -> String {
        self.lines.lock().unwrap().join("\n")
    }
}

/// The I-address `n` positions past `addr`, at its last component.
fn advanced(addr: &str, n: u64) -> String {
    let (prefix, last) = addr.rsplit_once('.').unwrap();
    format!("{prefix}.{}", last.parse::<u64>().unwrap() + n)
}

/// The link `a`'s `to` slot as `read_link` answers it under `shell`'s
/// `session`, and the text its first span names, read by identity.
fn to_of(shell: &Shell, session: &str, a: &Value) -> (Value, String) {
    let link = shell.call("op", &json!({"session": session, "frame": {"op": "read_link", "a": a}})).unwrap();
    let to = link["link"]["slots"][1].clone();
    let width = to[0]["width"].as_str().and_then(|w| w.rsplit('.').next()?.parse::<u64>().ok()).unwrap_or(0);
    let read = shell.call("op", &json!({"session": session, "frame": {"op": "retrieve_i", "spans": [{"start": to[0]["start"], "width": width.to_string()}]}})).unwrap();
    let text = read["items"].as_array().into_iter().flatten().filter_map(|item| item["value"]["content"].as_str()).collect();
    (to, text)
}

/// Checks that a follower of an acked insert lands on the insert's words.
///
/// An insert carrying an `id` is acked; a mark sent after it, `after` the
/// insert's `id`, its `to` a piece six positions into the words and five
/// wide, lands — the burst answered before its follower arrived, followed
/// from its kept outcome — its `to` the I-span the piece names, the
/// insert's first minted address advanced by six, five positions, which
/// reads back as the words the person marked; and the attest the signed
/// session composed over that I-span verified (the mutant that refuses a
/// follower of an answered burst loses this mark; the composer that reads no
/// `{"spans"}` slot refuses it `attest_not_composed`).
#[test]
fn a_follower_of_an_acked_insert_lands_on_its_words() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let g = follow_ground(&dir, &sd, false);
    let words = g.op(g.insert(Some("b-1"), "hello world")).unwrap();
    assert_eq!(words["resp"], "ack_addr", "{words}");
    let mark = g.follow("b-1", g.mark(json!([{"burst": "b-1", "offset": 6, "width": 5}]))).unwrap_or_else(|r| panic!("{r}\n{}", g.talk()));
    assert_eq!(mark["resp"], "ack_addr", "{mark}");
    let (to, text) = to_of(&g.shell, &g.session, &mark["addr"]);
    let start = advanced(words["addr"].as_str().unwrap(), 6);
    assert_eq!((to[0]["start"].as_str(), to.as_array().map(Vec::len), text.as_str()), (Some(start.as_str()), Some(1), "world"), "{to}");
    g.shell.shutdown();
    sd.shutdown();
}

/// Checks that a follower of a held burst is refused and nothing is written.
///
/// The own node stopped by its owner, an insert carrying an `id` is held
/// `stopped` without a dial; its follower is refused `not_followed`, `why:
/// "burst"` and `cause: "stopped"`, said in the shell's own window, and the
/// board's change feed since the draft's mint holds no link — the follower
/// held nowhere, since a link write is none of the held kinds (the mutant
/// that dials a follower whatever its burst's answer writes a mark on words
/// the board does not hold).
#[test]
fn a_follower_of_a_held_burst_is_refused_and_nothing_is_written() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let g = follow_ground(&dir, &sd, true);
    g.shell.set_node_state(NodeState::Stopped);
    let held = g.op(g.insert(Some("b-2"), "hello")).unwrap();
    assert_eq!((held["resp"].as_str(), held["cause"].as_str()), (Some("held"), Some("stopped")), "{held}");
    let refused = g.follow("b-2", g.mark(json!([{"burst": "b-2", "offset": 0, "width": 5}]))).unwrap_err().to_value();
    assert_eq!((refused["name"].as_str(), refused["why"].as_str(), refused["cause"].as_str()), (Some("not_followed"), Some("burst"), Some("stopped")), "{refused}");
    assert!(g.talk().contains("the write after burst `b-2` was not sent"), "{}", g.talk());
    let changes = g.shell.call("changes", &json!({"session": g.session, "since": g.at})).unwrap();
    assert!(changes["entries"].as_array().unwrap().iter().all(|entry| entry["op"] != "make_link"), "no link was written: {changes}");
    g.shell.shutdown();
    sd.shutdown();
}

/// Checks that a `nullify` follows a `delete`, and a piece after a `delete`
/// is refused.
///
/// A follower follows any of the five kinds: a take-off chord pressed after
/// a `delete` carrying an `id` — the burst committed by the chord — writes
/// its `nullify` at the delete's ack; a piece is an insert's alone, the one
/// burst whose ack names its words, so a mark with a piece after the delete
/// is refused `malformed_args` naming its slot, nothing dialed for it (the
/// mutant that follows inserts alone loses the take-off pressed after a
/// typo's delete).
#[test]
fn a_nullify_follows_a_delete_and_a_piece_after_a_delete_is_refused() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let g = follow_ground(&dir, &sd, false);
    let words = g.op(g.insert(None, "abc")).unwrap();
    let link = g.op(json!({"op": "make_link", "home": g.draft, "from": {"spans": []}, "to": {"addrs": [g.draft]}, "ty": {"addrs": [MARK_TYPE]}})).unwrap();
    let delete = json!({"op": "delete", "id": "b-3", "doc": g.draft, "p": {"subspace": "1", "ordinal": "1"}, "width": "1", "as_of": words["at"]});
    assert_eq!(g.op(delete).unwrap()["resp"], "ack");
    let nullified = g.follow("b-3", json!({"op": "nullify", "home": g.draft, "target": link["addr"]})).unwrap_or_else(|r| panic!("{r}\n{}", g.talk()));
    assert_eq!(nullified["resp"], "ack_addr", "{nullified}");
    let refused = g.follow("b-3", g.mark(json!([{"burst": "b-3", "offset": 0, "width": 1}]))).unwrap_err().to_value();
    assert_eq!((refused["name"].as_str(), refused["what"].as_str()), (Some("malformed_args"), Some("frame.to")), "{refused}");
    g.shell.shutdown();
    sd.shutdown();
}

/// Checks that a follower that overtakes its insert waits for it and lands.
///
/// Two calls of one page cross the transport in no promised order: a mark
/// whose `after` names an insert not yet sent waits for it, and lands on its
/// words once the insert, sent a moment later, is acked (the mutant that
/// refuses at once answers `no_such_burst`, and the mark is lost).
#[test]
fn a_follower_that_overtakes_its_insert_waits_for_it_and_lands() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let g = follow_ground(&dir, &sd, false);
    let (mark, words) = thread::scope(|scope| {
        let follower = scope.spawn(|| g.follow("b-4", g.mark(json!([{"burst": "b-4", "offset": 0, "width": 2}]))));
        let deadline = Instant::now() + Duration::from_secs(10);
        while g.shell.followers.waiting() == 0 {
            assert!(Instant::now() < deadline, "the follower never arrived");
            thread::sleep(Duration::from_millis(5));
        }
        thread::sleep(Duration::from_millis(100));
        let words = g.op(g.insert(Some("b-4"), "hi there")).unwrap();
        (follower.join().unwrap(), words)
    });
    let mark = mark.unwrap_or_else(|r| panic!("{r}\n{}", g.talk()));
    let (to, text) = to_of(&g.shell, &g.session, &mark["addr"]);
    assert_eq!((to[0]["start"].as_str(), text.as_str()), (words["addr"].as_str(), "hi"), "{to}");
    g.shell.shutdown();
    sd.shutdown();
}

/// Checks that the shell's stop finishes a follower before its sessions
/// close.
///
/// A burst carrying an `id` is entered as the `op` row enters one and stands
/// unanswered — its dial in flight, as at a window's close (§3c.6 step (1));
/// its follower waits on it; the stop, begun on another thread, waits on the
/// follower; the burst is answered while it waits, with an insert's real
/// ack, and the follower lands under its session, still open, before the
/// stop closes it — the mark read back by a fresh shell over the same store,
/// on the insert's words (the mutant that closes the sessions first ends the
/// follower with its session: `session_died`, and no mark).
#[test]
fn the_stop_finishes_a_follower_before_its_sessions_close() {
    let dir = TempDir::new().unwrap();
    let sd = spawn(&dir.path().join("board"), true);
    let g = follow_ground(&dir, &sd, false);
    let words = g.op(g.insert(None, "hello")).unwrap();
    let in_flight = json!({"op": "insert", "id": "b-5", "doc": g.draft, "at": {"subspace": "1", "ordinal": "1"}, "values": ["hello"], "as_of": g.at});
    let sent = g.shell.followers.sent(&g.session, &in_flight, || true).expect("a burst with an id is kept");
    let mark = thread::scope(|scope| {
        let follower = scope.spawn(|| g.follow("b-5", g.mark(json!([{"burst": "b-5", "offset": 1, "width": 3}]))));
        let deadline = Instant::now() + Duration::from_secs(10);
        while g.shell.followers.waiting() == 0 {
            assert!(Instant::now() < deadline, "the follower never arrived");
            thread::sleep(Duration::from_millis(5));
        }
        let stop = scope.spawn(|| g.shell.shutdown());
        while !g.shell.followers.stopping() {
            assert!(Instant::now() < deadline, "the stop never reached its followers");
            thread::sleep(Duration::from_millis(5));
        }
        sent.settle(&Ok(words.clone()));
        stop.join().unwrap();
        follower.join().unwrap()
    });
    let mark = mark.unwrap_or_else(|r| panic!("{r}\n{}", g.talk()));
    assert_eq!(mark["resp"], "ack_addr", "{mark}");
    let (fresh, _) = open_shell(&g.origin, &g.store, SessionMode::Signed { principal: 1 });
    let board = fresh.call("boards", &json!({})).unwrap()[0]["board"].as_str().unwrap().to_string();
    let session = fresh.call("session", &json!({"board": board})).unwrap()["session"].as_str().unwrap().to_string();
    let (to, text) = to_of(&fresh, &session, &mark["addr"]);
    assert_eq!((to[0]["start"].as_str(), text.as_str()), (Some(advanced(words["addr"].as_str().unwrap(), 1).as_str()), "ell"), "{to}");
    fresh.shutdown();
    sd.shutdown();
}
