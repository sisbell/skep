//! THE FOLLOWED BURSTS, with no board behind them: a burst entered and
//! answered by hand, a follower's dial a closure that records each frame it
//! is handed — the wait for a burst in flight and for one that has not
//! arrived, the kept outcome a late follower is followed from, a held burst
//! refusing its followers with nothing dialed, the turns in arrival order and
//! a refusal stopping those behind it, a piece resolved by its offset and one
//! past the insert's positions refused, the stop's wait and its bound, a
//! session's end, and the table's keeping of its newest answered bursts.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use super::*;

const SESSION: &str = "s-1";

/// The followers over a talk that keeps its lines.
fn followers() -> (Followers, Arc<Mutex<Vec<String>>>) {
    let lines = Arc::new(Mutex::new(Vec::new()));
    let kept = Arc::clone(&lines);
    (Followers::new(Arc::new(move |line: &str| kept.lock().unwrap().push(line.to_string()))), lines)
}

/// An insert of `text` carrying the `id`.
fn insert(id: &str, text: &str) -> Value {
    json!({"op": "insert", "doc": "1.0.1.0.1", "id": id, "at": {"subspace": "1", "ordinal": "1"}, "values": [text], "as_of": 3})
}

/// A `make_link` whose `to` is `pieces` of the I-span form.
fn mark(pieces: Value) -> Value {
    json!({"op": "make_link", "home": "1.0.1.0.1", "from": {"spans": []}, "to": {"spans": pieces}, "ty": {"addrs": ["1.1.0.1.0.1.0.3.13"]}})
}

/// The follower the door reads off `frame` with `after`.
fn follower(after: &str, frame: &Value) -> Follower {
    Follower::of(&json!({"after": after}), frame, None).unwrap().expect("a follower")
}

/// An insert's ack, its first minted I-address `1.0.1.0.1.0.1.<first>`.
fn ack_addr(first: u64) -> Result<Value, Refusal> {
    Ok(json!({"resp": "ack_addr", "addr": format!("1.0.1.0.1.0.1.{first}"), "at": 9}))
}

/// The frames a recording dial was handed, in order.
type Dialed = Arc<Mutex<Vec<Value>>>;

/// A dial that records the frames it is handed and acks each.
fn recording() -> (Dialed, impl Fn(Value) -> Result<Value, Refusal> + Clone) {
    let dialed = Arc::new(Mutex::new(Vec::new()));
    let kept = Arc::clone(&dialed);
    (dialed, move |frame: Value| {
        kept.lock().unwrap().push(frame);
        Ok(json!({"resp": "ack_addr", "addr": "1.0.1.0.1.0.2.1", "at": 10}))
    })
}

/// Waits until `n` followers wait in the tables.
fn until_waiting(f: &Followers, n: usize) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while f.waiting() != n {
        assert!(Instant::now() < deadline, "{} followers wait, not {n}", f.waiting());
        thread::sleep(Duration::from_millis(2));
    }
}

/// The refusal's name and its detail's `why`, of a follower's answer.
fn refused(followed: Followed) -> (String, Option<String>) {
    match followed {
        Followed::Answered(Err(r)) => (r.name().to_string(), r.to_value()["why"].as_str().map(str::to_string)),
        other => panic!("refused: {other:?}"),
    }
}

/// Checks that a follower waits for its burst in flight and goes at its ack.
///
/// The follower holds its turn, nothing dialed, while the burst's call has
/// not answered; at the insert's ack its piece is resolved against the
/// first I-address the ack names, advanced by its offset — `width` positions
/// in the I-span form — and the frame is dialed once, the follower answered
/// with the dial's answer, the turn left (the mutant that dials at once
/// writes the mark ahead of the words it names).
#[test]
fn a_follower_waits_for_its_burst_in_flight_and_goes_at_its_ack() {
    let (f, _) = followers();
    let sent = f.sent(SESSION, &insert("b-1", "hello world"), || true).expect("a burst with an id is kept");
    let (dialed, dial) = recording();
    let frame = mark(json!([{"burst": "b-1", "offset": 6, "width": 5}, {"start": "1.0.1.0.2.0.1.1", "width": "2"}]));
    thread::scope(|scope| {
        let waiting = scope.spawn(|| f.follow(SESSION, follower("b-1", &frame), frame.clone(), || true, dial));
        until_waiting(&f, 1);
        thread::sleep(Duration::from_millis(20));
        assert!(dialed.lock().unwrap().is_empty(), "nothing is dialed while the burst is in flight");
        sent.settle(&ack_addr(12));
        let Followed::Answered(Ok(answer)) = waiting.join().unwrap() else { panic!("the follower is answered") };
        assert_eq!(answer["addr"], "1.0.1.0.1.0.2.1");
    });
    let dialed = dialed.lock().unwrap();
    assert_eq!(dialed.len(), 1, "{dialed:?}");
    assert_eq!(
        dialed[0]["to"]["spans"],
        json!([{"start": "1.0.1.0.1.0.1.18", "width": "5"}, {"start": "1.0.1.0.2.0.1.1", "width": "2"}]),
        "the piece resolved in its place, the span beside it as given"
    );
    assert_eq!(f.waiting(), 0, "the follower left the table");
}

/// Checks that a burst answered before its follower arrives is followed from
/// its kept outcome.
///
/// The page hands a write over while it has not seen the ack; the shell may
/// have answered the burst already, the answer still on its way to the page
/// (the mutant that follows only an unanswered burst refuses that follower,
/// and the mark is lost in the case the follower exists for).
#[test]
fn a_burst_answered_before_its_follower_arrives_is_followed_from_its_kept_outcome() {
    let (f, _) = followers();
    f.sent(SESSION, &insert("b-1", "abc"), || true).unwrap().settle(&ack_addr(1));
    let (dialed, dial) = recording();
    let frame = mark(json!([{"burst": "b-1", "offset": 0, "width": 3}]));
    let Followed::Answered(Ok(_)) = f.follow(SESSION, follower("b-1", &frame), frame.clone(), || true, dial) else { panic!("followed") };
    assert_eq!(dialed.lock().unwrap()[0]["to"]["spans"], json!([{"start": "1.0.1.0.1.0.1.1", "width": "3"}]));
}

/// Checks that a held burst refuses its followers and nothing is dialed.
///
/// A burst answered `held` — any hold, the own node stopped here — and one
/// refused are not acked: each follower is refused `not_followed`, `why:
/// "burst"` with the burst's cause, its dial never called, and the refusal
/// said in the shell's own window, since the page that asked may be gone
/// (SP-12); a `nullify` follows as a `make_link` does.
#[test]
fn a_held_or_refused_burst_refuses_its_followers_and_nothing_is_dialed() {
    let (f, lines) = followers();
    f.sent(SESSION, &insert("b-1", "abc"), || true).unwrap().settle(&Ok(json!({"resp": "held", "held": 1, "cause": "stopped"})));
    f.sent(SESSION, &json!({"op": "delete", "doc": "1.0.1.0.1", "id": "b-2", "p": {"subspace": "1", "ordinal": "1"}, "width": "1", "as_of": 3}), || true)
        .unwrap()
        .settle(&Err(Refusal::shell(Name::FRAME_TOO_LARGE, json!({}))));
    let dials = AtomicUsize::new(0);
    let dial = |_: Value| -> Result<Value, Refusal> {
        dials.fetch_add(1, Ordering::SeqCst);
        Ok(json!({}))
    };
    let frame = mark(json!([{"burst": "b-1", "offset": 0, "width": 1}]));
    let answer = f.follow(SESSION, follower("b-1", &frame), frame.clone(), || true, dial);
    let Followed::Answered(Err(r)) = answer else { panic!("refused") };
    assert_eq!((r.name(), r.to_value()["why"].as_str(), r.to_value()["cause"].as_str(), r.to_value()["after"].as_str()), ("not_followed", Some("burst"), Some("stopped"), Some("b-1")));
    let nullify = json!({"op": "nullify", "home": "1.0.1.0.1", "target": "1.0.1.0.1.0.2.1"});
    let answer = f.follow(SESSION, follower("b-2", &nullify), nullify, || true, dial);
    let Followed::Answered(Err(r)) = answer else { panic!("refused") };
    assert_eq!((r.to_value()["why"].as_str(), r.to_value()["cause"].as_str()), (Some("burst"), Some("frame_too_large")));
    assert_eq!(dials.load(Ordering::SeqCst), 0, "nothing is dialed");
    let said = lines.lock().unwrap();
    assert_eq!(said.iter().filter(|line| line.contains("not sent") && line.contains("nothing of it was written")).count(), 2, "{said:?}");
}

/// Checks that followers go in arrival order and one not acked refuses
/// those behind it.
///
/// Three followers of one burst take their turns as they arrived; the first
/// is acked, the second's own dial refused, and the third — a write of the
/// same chord's step — is refused `not_followed`, `why: "ahead"`, unsent (D6
/// BM-69: a step never lands half; the mutant that lets each follower go on
/// its own lands the step's second write over a first that failed).
#[test]
fn followers_go_in_arrival_order_and_one_not_acked_refuses_those_behind() {
    let (f, _) = followers();
    let sent = f.sent(SESSION, &insert("b-1", "abc"), || true).unwrap();
    let order = Mutex::new(Vec::new());
    let dial_as = |n: usize, ok: bool| {
        let order = &order;
        move |_: Value| -> Result<Value, Refusal> {
            order.lock().unwrap().push(n);
            if ok {
                Ok(json!({"resp": "ack_addr", "addr": "1.0.1.0.1.0.2.1", "at": 10}))
            } else {
                Err(Refusal::malformed("x"))
            }
        }
    };
    let nullify = json!({"op": "nullify", "home": "1.0.1.0.1", "target": "1.0.1.0.1.0.2.1"});
    thread::scope(|scope| {
        let first = scope.spawn(|| f.follow(SESSION, follower("b-1", &nullify), nullify.clone(), || true, dial_as(1, true)));
        until_waiting(&f, 1);
        let second = scope.spawn(|| f.follow(SESSION, follower("b-1", &nullify), nullify.clone(), || true, dial_as(2, false)));
        until_waiting(&f, 2);
        let third = scope.spawn(|| f.follow(SESSION, follower("b-1", &nullify), nullify.clone(), || true, dial_as(3, true)));
        until_waiting(&f, 3);
        sent.settle(&ack_addr(1));
        assert!(matches!(first.join().unwrap(), Followed::Answered(Ok(_))));
        assert_eq!(refused(second.join().unwrap()).0, "malformed_args", "the second's own answer");
        assert_eq!(refused(third.join().unwrap()), ("not_followed".to_string(), Some("ahead".to_string())));
    });
    assert_eq!(*order.lock().unwrap(), [1, 2], "dialed in arrival order, the third never");
}

/// Checks that a piece resolves by its offset and one past the burst's
/// positions, or after a burst that names no words, is refused.
///
/// The positions are those the insert's frame mints — a byte of a text, one
/// an atom — so a piece over the last of them is followed and one a
/// position past it refused `malformed_args` naming its slot, as a piece
/// after a `delete` is, whose ack names no words; neither is dialed, nor
/// waits for the burst's answer (the mutant that counts characters admits a
/// piece past an atom's one position).
#[test]
fn a_piece_resolves_by_its_offset_and_one_past_the_bursts_positions_is_refused() {
    let (f, _) = followers();
    let words = json!({"op": "insert", "doc": "1.0.1.0.1", "id": "b-1", "at": {"subspace": "1", "ordinal": "1"}, "values": ["ab", {"atom": "xyz"}], "as_of": 3});
    let in_flight = f.sent(SESSION, &words, || true).unwrap();
    let delete = json!({"op": "delete", "doc": "1.0.1.0.1", "id": "b-2", "p": {"subspace": "1", "ordinal": "1"}, "width": "1", "as_of": 3});
    let _deleting = f.sent(SESSION, &delete, || true).unwrap();
    let (dialed, dial) = recording();
    for (cell, after, piece) in [("past the atom", "b-1", json!({"burst": "b-1", "offset": 2, "width": 2})), ("after a delete", "b-2", json!({"burst": "b-2", "offset": 0, "width": 1}))] {
        let frame = json!({"op": "make_link", "home": "1.0.1.0.1", "from": {"spans": [piece]}, "to": {"spans": []}, "ty": {"addrs": ["1.1.0.1.0.1.0.3.13"]}});
        let (name, _) = refused(f.follow(SESSION, follower(after, &frame), frame.clone(), || true, dial.clone()));
        assert_eq!(name, "malformed_args", "{cell}");
    }
    assert_eq!(f.waiting(), 0, "neither waited for its burst");
    in_flight.settle(&ack_addr(u64::MAX - 1));
    let over = mark(json!([{"burst": "b-1", "offset": 2, "width": 1}]));
    let (name, why) = refused(f.follow(SESSION, follower("b-1", &over), over.clone(), || true, dial.clone()));
    assert_eq!((name.as_str(), why.as_deref()), ("not_followed", Some("ack")), "a start past what an address spells is no I-address");
    assert!(dialed.lock().unwrap().is_empty());
    assert_eq!(Minted::of("1.0.1.0.1.0.1.7").and_then(|m| m.span(Piece { slot: Slot::To, index: 0, offset: 2, width: 1 })), Some(json!({"start": "1.0.1.0.1.0.1.9", "width": "1"})));
    assert_eq!(Minted::of("1.0.1.0.1.0.1.x"), None, "an ack naming no address names no words");
}

/// Checks that the stop waits for the followers and refuses the rest at its
/// bound.
///
/// The drain waits while a follower waits on a burst in flight, and at its
/// deadline answers it `not_followed`, `why: "stop"`, saying the followers
/// still under way; a follower arriving after the drain is refused so at
/// once, and a second drain finds the wait over (the mutant that does not
/// wait leaves the follower to dial under a session the stop closes; the one
/// that waits past its bound holds the stop on a board that never answers).
#[test]
fn the_stop_waits_for_the_followers_and_refuses_the_rest_at_its_bound() {
    let (f, lines) = followers();
    let _in_flight = f.sent(SESSION, &insert("b-1", "abc"), || true).unwrap();
    let (dialed, dial) = recording();
    let frame = mark(json!([{"burst": "b-1", "offset": 0, "width": 1}]));
    thread::scope(|scope| {
        let waiting = scope.spawn(|| f.follow(SESSION, follower("b-1", &frame), frame.clone(), || true, dial.clone()));
        until_waiting(&f, 1);
        let started = Instant::now();
        f.drain(started + Duration::from_millis(100));
        assert!(started.elapsed() >= Duration::from_millis(100), "the drain waited its bound");
        assert_eq!(refused(waiting.join().unwrap()), ("not_followed".to_string(), Some("stop".to_string())));
    });
    assert_eq!(refused(f.follow(SESSION, follower("b-1", &frame), frame.clone(), || true, dial)), ("not_followed".to_string(), Some("stop".to_string())));
    let started = Instant::now();
    f.drain(started + Duration::from_secs(5));
    assert!(started.elapsed() < Duration::from_secs(1), "a second drain finds the wait over");
    assert!(dialed.lock().unwrap().is_empty());
    assert!(lines.lock().unwrap().iter().any(|line| line.contains("still under way at the stop's")), "{:?}", lines.lock().unwrap());
}

/// Checks that the drain answers at once where no follower waits, and waits
/// for one whose burst is answered while it waits.
#[test]
fn the_drain_answers_once_its_followers_are_answered() {
    let (f, _) = followers();
    let sent = f.sent(SESSION, &insert("b-1", "abc"), || true).unwrap();
    let (dialed, dial) = recording();
    let frame = mark(json!([{"burst": "b-1", "offset": 0, "width": 1}]));
    thread::scope(|scope| {
        let waiting = scope.spawn(|| f.follow(SESSION, follower("b-1", &frame), frame.clone(), || true, dial));
        until_waiting(&f, 1);
        let draining = scope.spawn(|| f.drain(Instant::now() + Duration::from_secs(30)));
        while !f.stopping() {
            thread::sleep(Duration::from_millis(2));
        }
        sent.settle(&ack_addr(1));
        let started = Instant::now();
        draining.join().unwrap();
        assert!(started.elapsed() < Duration::from_secs(5), "the drain answers once its follower is");
        assert!(matches!(waiting.join().unwrap(), Followed::Answered(Ok(_))));
    });
    assert_eq!(dialed.lock().unwrap().len(), 1);
}

/// Checks that a follower that overtakes its burst waits for it, and one
/// whose burst never comes is refused `no_such_burst`.
///
/// Two calls of one page cross the transport in no promised order: a
/// follower arriving before its burst waits up to `BURST_ARRIVAL_WAIT` for
/// it and goes at its ack; past it, it is refused `no_such_burst` naming its
/// `after` — or answered as its session's end where the session no longer
/// stands (the mutant that refuses at once loses the mark a fast follower
/// carries).
#[test]
fn a_follower_that_overtakes_its_burst_waits_for_it() {
    let (f, _) = followers();
    let (dialed, dial) = recording();
    let frame = mark(json!([{"burst": "b-1", "offset": 1, "width": 1}]));
    thread::scope(|scope| {
        let waiting = scope.spawn(|| f.follow(SESSION, follower("b-1", &frame), frame.clone(), || true, dial.clone()));
        until_waiting(&f, 1);
        thread::sleep(Duration::from_millis(100));
        f.sent(SESSION, &insert("b-1", "abc"), || true).unwrap().settle(&ack_addr(4));
        assert!(matches!(waiting.join().unwrap(), Followed::Answered(Ok(_))));
    });
    assert_eq!(dialed.lock().unwrap()[0]["to"]["spans"], json!([{"start": "1.0.1.0.1.0.1.5", "width": "1"}]));
    let never = mark(json!([{"burst": "b-9", "offset": 0, "width": 1}]));
    let started = Instant::now();
    let unknown = f.follow(SESSION, follower("b-9", &never), never.clone(), || true, dial.clone());
    assert!(started.elapsed() >= BURST_ARRIVAL_WAIT, "it waited for its burst");
    let Followed::Answered(Err(r)) = unknown else { panic!("refused") };
    assert_eq!((r.name(), r.to_value()["after"].as_str()), ("no_such_burst", Some("b-9")));
    assert!(matches!(f.follow(SESSION, follower("b-9", &never), never.clone(), || false, dial), Followed::Ended), "its session gone, the follower answers as its end");
    assert_eq!((f.waiting(), dialed.lock().unwrap().len()), (0, 1), "neither was dialed");
}

/// Checks that a session's end answers its followers and lets its table go.
///
/// A follower waiting on a burst in flight answers [`Followed::Ended`] at
/// the session's end, nothing dialed; the burst settled after it finds no
/// table, and no burst of the ended session is entered — the table goes
/// with its last follower (the mutant that keeps the table leaks one per
/// session the shell ever served).
#[test]
fn a_sessions_end_answers_its_followers_and_lets_its_table_go() {
    let (f, _) = followers();
    let sent = f.sent(SESSION, &insert("b-1", "abc"), || true).unwrap();
    let (dialed, dial) = recording();
    let frame = mark(json!([{"burst": "b-1", "offset": 0, "width": 1}]));
    thread::scope(|scope| {
        let waiting = scope.spawn(|| f.follow(SESSION, follower("b-1", &frame), frame.clone(), || true, dial));
        until_waiting(&f, 1);
        f.ended(SESSION);
        assert!(matches!(waiting.join().unwrap(), Followed::Ended));
    });
    sent.settle(&ack_addr(1));
    assert!(dialed.lock().unwrap().is_empty());
    assert!(f.lock().tables.is_empty(), "the ended session's table is gone");
    assert!(f.sent(SESSION, &insert("b-2", "abc"), || false).is_none(), "a burst of a session no longer standing is kept nowhere");
    assert!(f.lock().tables.is_empty(), "and the table entered for it is let go");
}

/// Checks that the table keeps the newest answered bursts, and every burst
/// in flight or followed.
///
/// Past `BURSTS_KEPT` answered bursts the oldest answered is let go, while a
/// burst still in flight — the oldest of all here — is kept, as one a
/// follower holds a turn of would be (SP-17: the table is bounded by the
/// bursts the page may still name); a frame of no burst kind, or whose `id`
/// is past its bound, is kept nowhere.
#[test]
fn the_table_keeps_the_newest_answered_bursts_and_every_one_in_flight() {
    let (f, _) = followers();
    let _in_flight = f.sent(SESSION, &insert("first", "a"), || true).unwrap();
    for n in 0..BURSTS_KEPT + 5 {
        f.sent(SESSION, &insert(&format!("b-{n}"), "a"), || true).unwrap().settle(&ack_addr(1));
    }
    let kept = f.kept_ids(SESSION);
    assert_eq!(kept.len(), BURSTS_KEPT + 1, "{kept:?}");
    assert_eq!((kept[0].as_str(), kept[1].as_str(), kept.last().map(String::as_str)), ("first", "b-5", Some(format!("b-{}", BURSTS_KEPT + 4).as_str())));
    assert!(f.sent(SESSION, &json!({"op": "make_link", "id": "l-1"}), || true).is_none(), "a link write is no burst");
    assert!(f.sent(SESSION, &insert(&"x".repeat(MAX_BURST_ID_BYTES + 1), "a"), || true).is_none(), "an id past its bound");
    assert!(f.sent(SESSION, &insert(&"x".repeat(MAX_BURST_ID_BYTES), "a"), || true).is_some(), "an id at its bound");
}

/// Checks that the declared piece is the one the door reads.
///
/// A piece of the members `shapes`' `BurstPiece` declares, each in its
/// declared type, is read as a piece; one without its `offset` or its
/// `width` is refused naming its slot, and one without its `burst` is no
/// piece — a span of the frame's own — so the declaration and the door name
/// one form (the mutant that renames a member in the door alone refuses
/// every mark the page composes from the declaration).
#[test]
fn the_declared_piece_is_the_one_the_door_reads() {
    let declared = crate::shapes::shape("BurstPiece").expect("the piece is declared");
    let piece: serde_json::Map<String, Value> = declared.fields.iter().map(|f| (f.name.to_string(), if f.ty == "string" { json!("b-1") } else { json!(1) })).collect();
    let read = |piece: serde_json::Map<String, Value>| Follower::of(&json!({"after": "b-1"}), &mark(json!([Value::Object(piece)])), None);
    assert_eq!(read(piece.clone()).unwrap().map(|f| f.pieces.len()), Some(1));
    for field in declared.fields {
        let mut short = piece.clone();
        short.remove(field.name);
        match field.name {
            "burst" => assert_eq!(read(short).unwrap().map(|f| f.pieces.len()), Some(0), "without its burst, no piece"),
            name => assert_eq!(read(short).unwrap_err().to_value()["what"], "frame.to", "{name}"),
        }
    }
}

/// Checks that a burst whose call unwound is not acked, so no follower waits
/// on it for ever.
#[test]
fn a_burst_whose_call_unwound_is_not_acked() {
    let (f, _) = followers();
    drop(f.sent(SESSION, &insert("b-1", "abc"), || true).unwrap());
    let (_, dial) = recording();
    let frame = mark(json!([{"burst": "b-1", "offset": 0, "width": 1}]));
    let Followed::Answered(Err(r)) = f.follow(SESSION, follower("b-1", &frame), frame.clone(), || true, dial) else { panic!("refused") };
    assert_eq!((r.to_value()["why"].as_str(), r.to_value()["cause"].as_str()), (Some("burst"), Some("unanswered")));
}
