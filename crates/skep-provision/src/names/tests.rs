//! T8 — THE TRUTH ABOUT NAMES: taken iff any one of the snippet, the volume
//! and the container stands — every one of the eight combinations, the reads
//! made in the order fixed here and no further than the first that stands;
//! an unguessable value's form; what took a name, as the log says it; and
//! the labelled volumes sorted against the snippet directory — half-made,
//! routed, or under no name of the grammar. (The status map is the book's —
//! `flow/status_map/tests.rs`; the two posts on one name and the fifth past
//! the queue are the desk's — `flow/tests/desk.rs`; the sweep is the start's
//! — `flow/tests/start.rs`.)

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
fn what_took_a_name_displays_as_the_log_says_it() {
    let said = [TakenBy::Snippet, TakenBy::Volume, TakenBy::Container].map(|by| by.to_string());
    assert_eq!(said, ["its snippet stands", "a volume stands under it", "a container stands under it"]);
}
