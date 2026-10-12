//! T8 — THE TRUTH ABOUT NAMES and THE STATUS MAP: taken iff any one of the
//! snippet, the volume and the container stands — every one of the eight
//! combinations, the reads made in the order fixed here and no further than
//! the first that stands; the map rebuilt from a snippet directory holding
//! two live names with the constant facts; a token the map does not hold
//! answering nothing; a post in flight holding its name; the token's form.
//! (The two posts on one name, and the fifth past the queue, are the
//! flow's — `flow/tests.rs`.)

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
                let holder = taken(&fake, dir.path(), &name("alice")).expect("docker ran");
                let want = if snippet {
                    Some(Holder::Snippet)
                } else if volume {
                    Some(Holder::Volume)
                } else if container {
                    Some(Holder::Container)
                } else {
                    None
                };
                assert_eq!(holder, want, "snippet {snippet}, volume {volume}, container {container}");
                fake.assert_done();
            }
        }
    }
}

/// T8: THE MAP REBUILT from a directory holding `alice.caddy` and
/// `bob.caddy` holds two live names, each with the constant facts — and no
/// post, no token.
#[test]
fn the_map_rebuilt_from_the_snippets_holds_their_live_names() {
    let dir = Scratch::new();
    fs::write(dir.path().join("alice.caddy"), b"").expect("a snippet");
    fs::write(dir.path().join("bob.caddy"), b"").expect("a snippet");
    let map = StatusMap::rebuild(dir.path(), "skep.host").expect("rebuilt");
    let live: Vec<(&Name, &Facts)> = map.live().iter().collect();
    assert_eq!(
        live,
        vec![
            (&name("alice"), &Facts { account: "1.0.1", principal: 1, origin: "https://alice.skep.host".into() }),
            (&name("bob"), &Facts { account: "1.0.1", principal: 1, origin: "https://bob.skep.host".into() }),
        ]
    );
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
    map.set("t1", State::Running, None);
    assert!(map.holds(&name("alice")));
    map.set("t1", State::Live, Some(facts(&name("alice"), "skep.host")));
    assert!(!map.holds(&name("alice")), "a live name's truth is its snippet's");
    assert_eq!(map.live().get(&name("alice")).map(|f| f.origin.as_str()), Some("https://alice.skep.host"));
    assert!(map.post("t1").expect("the post").anchorless);
    map.admit("t3".into(), name("bob"), false);
    map.set("t3", State::Failed, None);
    assert!(!map.holds(&name("bob")));
    assert!(!map.live().contains_key(&name("bob")));
}

/// The status token: 128 bits as 32 lowercase hex digits, fresh each time.
#[test]
fn a_fresh_token_is_32_lowercase_hex_digits() {
    let (a, b) = (fresh_token().expect("entropy"), fresh_token().expect("entropy"));
    assert_eq!(a.len(), 32);
    assert!(a.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)), "{a}");
    assert_ne!(a, b);
}
