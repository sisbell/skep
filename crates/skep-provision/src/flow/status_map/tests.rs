//! T8 — THE STATUS MAP: rebuilt from a snippet directory holding two routed
//! names; a token the map does not hold answering nothing; a post in flight
//! while queued or running and ended once live or failed; a post in flight
//! holding its name, and a post that ends adding no name to those routed at
//! start; a move of a token never admitted, or of an ended post, and a token
//! admitted twice, each the caller's bug, panicking — the last before the
//! map changes; and the map's `Debug` showing no token. (The book that moves
//! its posts is the desk's suite's, `flow/tests/desk.rs`.)

use std::fs;

use super::*;
use crate::scratch::Scratch;

fn name(n: &str) -> Name {
    Name::parse(n.as_bytes()).expect("a name")
}

/// T8: THE MAP REBUILT from a directory holding `alice.caddy` and
/// `bob.caddy` holds the two names routed at start — and no post, no token.
#[test]
fn the_map_rebuilt_from_the_snippets_holds_the_names_routed_at_start() {
    let dir = Scratch::new();
    fs::write(dir.path().join("alice.caddy"), b"").expect("a snippet");
    fs::write(dir.path().join("bob.caddy"), b"").expect("a snippet");
    let map = StatusMap::rebuild(dir.path()).expect("rebuilt");
    assert_eq!(map.routed_at_start().iter().collect::<Vec<_>>(), vec![&name("alice"), &name("bob")]);
    assert!(map.post("anything").is_none(), "a token minted before a restart answers nothing");
}

/// T8: A TOKEN NOT IN THE MAP is `None`; a post's state moves; a queued or
/// running post holds its name, an ended one does not; and a post's end,
/// live or failed, adds no name to those routed at start.
#[test]
fn the_map_answers_its_tokens_and_their_holds() {
    let mut map = StatusMap::default();
    map.admit("t1".into(), name("alice"), true);
    assert_eq!(map.post("t1").map(|p| p.state), Some(PostState::Queued));
    assert!(map.post("t2").is_none());
    assert!(map.holds(&name("alice")));
    assert!(!map.holds(&name("bob")));
    map.set("t1", PostState::Running);
    assert!(map.holds(&name("alice")));
    map.set("t1", PostState::Live);
    assert!(!map.holds(&name("alice")), "a live name's truth is its snippet's");
    assert!(map.post("t1").expect("the post").anchorless);
    map.admit("t3".into(), name("bob"), false);
    map.set("t3", PostState::Failed);
    assert!(!map.holds(&name("bob")));
    assert!(map.routed_at_start().is_empty(), "a post that ends is live or failed by its own state, never a name added to those routed at start");
}

/// A POST IS IN FLIGHT while queued or running, and ENDED once live or
/// failed: its state final, its name held no more.
#[test]
fn a_post_is_in_flight_until_it_ends_live_or_failed() {
    for (state, ended) in [(PostState::Queued, false), (PostState::Running, false), (PostState::Live, true), (PostState::Failed, true)] {
        assert_eq!(state.ended(), ended, "{state:?}");
    }
}

/// SETTING A TOKEN THIS PROCESS NEVER ADMITTED IS THE CALLER's BUG: `set`
/// panics naming the precondition — never a quiet no-op, which would leave
/// the caller's post at D-7 with its name held for good.
#[test]
#[should_panic(expected = "`set` names a token this process admitted")]
fn setting_a_token_never_admitted_is_the_callers_bug() {
    StatusMap::default().set("never-admitted", PostState::Running);
}

/// AN ENDED POST's STATE IS FINAL: moving a live or a failed post again is
/// the caller's bug, and panics naming the precondition — its page says how
/// it ended, and an ended post holds no name.
#[test]
fn moving_an_ended_post_is_the_callers_bug() {
    for ended in [PostState::Live, PostState::Failed] {
        let moved = std::panic::catch_unwind(|| {
            let mut map = StatusMap::default();
            map.admit("t0k3n".into(), name("alice"), true);
            map.set("t0k3n", PostState::Running);
            map.set("t0k3n", ended);
            map.set("t0k3n", PostState::Running);
        });
        let payload = moved.expect_err("an ended post moved again");
        let said = payload.downcast_ref::<String>().map(String::as_str).or_else(|| payload.downcast_ref::<&str>().copied()).unwrap_or_default();
        assert!(said.contains("an ended post's state is final"), "{ended:?}: {said}");
    }
}

/// A TOKEN ADMITTED TWICE IS THE CALLER's BUG: `admit` panics naming the
/// precondition before the map changes — a token is its post's identity, and
/// an ended post's state is final, so neither a post in flight nor an ended
/// one is admitted again under its token, nor its entry touched.
#[test]
fn admitting_a_token_twice_is_the_callers_bug() {
    for ended in [false, true] {
        let mut map = StatusMap::default();
        map.admit("t0k3n".into(), name("alice"), true);
        if ended {
            map.set("t0k3n", PostState::Running);
            map.set("t0k3n", PostState::Live);
        }
        let before = map.post("t0k3n").cloned();
        let again = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| map.admit("t0k3n".into(), name("bob"), false)));
        let payload = again.expect_err("a token admitted twice");
        let said = payload.downcast_ref::<String>().map(String::as_str).or_else(|| payload.downcast_ref::<&str>().copied()).unwrap_or_default();
        assert!(said.contains("`admit` takes a token this process never admitted"), "ended {ended}: {said}");
        assert_eq!(map.post("t0k3n").cloned(), before, "ended {ended}: the map changed before its gate refused");
        assert!(!map.holds(&name("bob")), "ended {ended}");
    }
}

/// The map's `Debug` shows how many posts it holds and the names routed at
/// start — never a status token, the key it holds a post by.
#[test]
fn the_maps_debug_shows_no_token() {
    let dir = Scratch::new();
    fs::write(dir.path().join("alice.caddy"), b"").expect("a snippet");
    let mut map = StatusMap::rebuild(dir.path()).expect("rebuilt");
    map.admit("t0k3n".into(), name("bob"), true);
    assert_eq!(format!("{map:?}"), "StatusMap { posts: 1, routed_at_start: {Name(\"alice\")} }");
}
