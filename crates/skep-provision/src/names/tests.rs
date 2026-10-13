//! T8 — THE TRUTH ABOUT NAMES and THE STATUS MAP: taken iff any one of the
//! snippet, the volume and the container stands — every one of the eight
//! combinations, the reads made in the order fixed here and no further than
//! the first that stands; the map rebuilt from a snippet directory holding
//! two live names; a token the map does not hold answering nothing; a post
//! gone live joining the live names; a post in flight holding its name; an
//! unguessable value's form; what took a name, as the log says it; the
//! map's `Debug` showing no token;
//! and the labelled volumes sorted against the snippet directory — half-made,
//! routed, or under no name of the grammar. (The two posts on one name, the
//! fifth past the queue and the sweep are the flow's — `flow/tests.rs`.)

use std::fs;

use super::*;
use crate::docker::fake::{line, FakeDocker};
use crate::scratch::Scratch;

fn name(n: &str) -> Name {
    Name::parse(n.as_bytes()).expect("a name")
}

/// T8: TAKEN IFF ANY ONE OF THE THREE — all eight combinations of the
/// snippet, the volume and the container: the snippet read first with no
/// call, then `volume_inspect`, then `container_inspect`, the first that
/// stands answering and no further call made.
#[test]
fn a_name_is_taken_iff_any_one_of_the_three_stands() {
    for snippet in [false, true] {
        for volume in [false, true] {
            for container in [false, true] {
                let dir = Scratch::new();
                if snippet {
                    fs::write(dir.path().join("alice.caddy"), b"").expect("a snippet");
                }
                let mut script = String::new();
                if !snippet {
                    script.push_str(&line("volume_inspect", Some("alice"), if volume { 0 } else { 1 }, "", ""));
                    if !volume {
                        script.push_str(&line("container_inspect", Some("alice"), if container { 0 } else { 1 }, "", ""));
                    }
                }
                let fake = FakeDocker::parse(&script).expect("a script");
                let taken_by = taken(&fake, dir.path(), &name("alice")).expect("docker ran");
                let want = if snippet {
                    Some(TakenBy::Snippet)
                } else if volume {
                    Some(TakenBy::Volume)
                } else if container {
                    Some(TakenBy::Container)
                } else {
                    None
                };
                assert_eq!(taken_by, want, "snippet {snippet}, volume {volume}, container {container}");
                fake.assert_done();
            }
        }
    }
}

/// T8: THE MAP REBUILT from a directory holding `alice.caddy` and
/// `bob.caddy` holds two live names — and no post, no token.
#[test]
fn the_map_rebuilt_from_the_snippets_holds_their_live_names() {
    let dir = Scratch::new();
    fs::write(dir.path().join("alice.caddy"), b"").expect("a snippet");
    fs::write(dir.path().join("bob.caddy"), b"").expect("a snippet");
    let map = StatusMap::rebuild(dir.path()).expect("rebuilt");
    assert_eq!(map.live().iter().collect::<Vec<_>>(), vec![&name("alice"), &name("bob")]);
    assert!(map.post("anything").is_none(), "a token minted before a restart answers nothing");
}

/// T8: A TOKEN NOT IN THE MAP is `None`; a post's state moves, and one gone
/// live joins the live names; a queued or running post holds its name, a
/// finished one does not.
#[test]
fn the_map_answers_its_tokens_and_their_holds() {
    let mut map = StatusMap::default();
    map.admit("t1".into(), name("alice"), true);
    assert_eq!(map.post("t1").map(|p| p.state), Some(State::Queued));
    assert!(map.post("t2").is_none());
    assert!(map.holds(&name("alice")));
    assert!(!map.holds(&name("bob")));
    map.set("t1", State::Running);
    assert!(map.holds(&name("alice")));
    assert!(!map.live().contains(&name("alice")), "a running post is no live name");
    map.set("t1", State::Live);
    assert!(!map.holds(&name("alice")), "a live name's truth is its snippet's");
    assert!(map.live().contains(&name("alice")), "a post gone live joins the live names");
    assert!(map.post("t1").expect("the post").anchorless);
    map.admit("t3".into(), name("bob"), false);
    map.set("t3", State::Failed);
    assert!(!map.holds(&name("bob")));
    assert!(!map.live().contains(&name("bob")));
}

/// THE LABELLED VOLUMES SORTED: a listing of `alice`, `bob`, `Carol_X`,
/// `Dave` and a blank line, with `alice.caddy` standing — `bob` half-made
/// (a name, no snippet), `alice` routed, `Carol_X` under no name of the
/// grammar and `Dave` likewise (it lowercases to a name that does not spell
/// it back, as a snippet's stem must); an empty listing sorts to nothing;
/// a snippet directory that cannot be searched is the error.
#[test]
fn the_labelled_volumes_sort_into_half_made_routed_and_unnamed() {
    let dir = Scratch::new();
    fs::write(dir.path().join("alice.caddy"), b"").expect("a snippet");
    let sorted = labelled(b"alice\nbob\nCarol_X\n\nDave\n", dir.path()).expect("sorted");
    assert_eq!(sorted, Labelled { half_made: vec![name("bob")], routed: vec![name("alice")], unnamed: vec!["Carol_X".into(), "Dave".into()] });
    assert_eq!(labelled(b"", dir.path()).expect("sorted"), Labelled::default());
    assert_eq!(labelled(b"bob\r\n", dir.path()).expect("sorted").half_made, vec![name("bob")], "a CRLF listing");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let boards = dir.path().join("boards");
        fs::create_dir(&boards).expect("a directory");
        fs::set_permissions(&boards, fs::Permissions::from_mode(0o000)).expect("unsearchable");
        assert!(labelled(b"bob\n", &boards).is_err(), "the snippet directory's error");
    }
}

/// An unguessable value — a status token, a minted invite code: 128 bits as
/// 32 lowercase hex digits, fresh each time.
#[test]
fn an_unguessable_value_is_32_lowercase_hex_digits() {
    let (a, b) = (unguessable().expect("entropy"), unguessable().expect("entropy"));
    assert_eq!(a.len(), 32);
    assert!(a.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)), "{a}");
    assert_ne!(a, b);
}

/// What took a name, as the log says it.
#[test]
fn what_took_a_name_as_the_log_says_it() {
    let said = [TakenBy::Snippet, TakenBy::Volume, TakenBy::Container].map(|by| by.to_string());
    assert_eq!(said, ["its snippet stands", "a volume stands under it", "a container stands under it"]);
}

/// The map's `Debug` shows how many posts it holds and the live names —
/// never a status token, the key it holds a post by.
#[test]
fn the_maps_debug_shows_no_token() {
    let mut map = StatusMap::default();
    map.admit("t0k3n".into(), name("alice"), true);
    map.set("t0k3n", State::Live);
    assert_eq!(format!("{map:?}"), "StatusMap { posts: 1, live: {Name(\"alice\")} }");
}
