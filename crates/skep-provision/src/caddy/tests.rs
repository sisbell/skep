//! T7 — THE SNIPPET: byte for byte the deployment notes' block for `alice`
//! under `skep.host`, tabs included; every occurrence substituted for
//! another name and another suffix; written whole by rename, one file and
//! no temp file left; an unwritable directory an error; and whether it
//! stands, the removal, the reload and the rebuild's read of the directory.

use super::*;
use crate::docker::fake::{line, FakeDocker};
use crate::scratch::Scratch;

/// THE NOTES' BLOCK, as a LITERAL: `_designs/deployment-notes.md` §4a, "One
/// board's snippet", `/etc/caddy/boards/alice.caddy` — from `@alice host
/// alice.skep.host` to its closing brace, each indent a TAB as the notes
/// write it, a line break ending every line.
const ALICE: &str = "@alice host alice.skep.host\n\
handle @alice {\n\
\treverse_proxy alice:8642 {\n\
\t\t# AUTH-4.57 (d): the route stands only while /health answers\n\
\t\t# the pair \u{2014} claimant not null AND local_trust false\n\
\t\thealth_uri /health\n\
\t\thealth_interval 10s\n\
\t\thealth_timeout 5s\n\
\t\thealth_status 200\n\
\t\thealth_body `\"claimant\":\"1\\.0\\.1\",\"local_trust\":false`\n\
\t\t# GET /events: no response buffering (media setting 2)\n\
\t\tflush_interval -1\n\
\t}\n\
}\n";

fn name(n: &str) -> Name {
    Name::parse(n.as_bytes()).expect("a name")
}

/// The directory's file names, sorted.
fn listing(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir).expect("the directory").map(|e| e.expect("an entry").file_name().to_string_lossy().into_owned()).collect();
    names.sort();
    names
}

/// T7: THE SNIPPET FOR `alice` UNDER `skep.host` IS THE NOTES' BLOCK, BYTE
/// FOR BYTE.
#[test]
fn the_snippet_is_the_notes_block_byte_for_byte() {
    assert_eq!(snippet(&name("alice"), "skep.host"), ALICE);
    assert_eq!(snippet(&name("alice"), "skep.host").matches('\t').count(), 20, "the notes' tabs");
}

/// T7: ANOTHER NAME SUBSTITUTES EVERY OCCURRENCE — the matcher, the
/// handle, the host and the upstream — and another suffix the host's.
#[test]
fn another_name_and_suffix_substitute_every_occurrence() {
    let bob = snippet(&name("bob"), "skep.host");
    assert_eq!(bob, ALICE.replace("alice", "bob"));
    assert!(!bob.contains("alice"));
    assert_eq!(bob.matches("bob").count(), 4);
    let elsewhere = snippet(&name("alice"), "example.org");
    assert_eq!(elsewhere, ALICE.replace("alice.skep.host", "alice.example.org"));
}

/// T7: THE WRITE leaves EXACTLY ONE FILE — `<name>.caddy`, the snippet,
/// readable by all — and no temp file; a second write replaces it whole.
#[test]
fn the_write_leaves_one_file_and_no_temp_file() {
    let dir = Scratch::new();
    write(dir.path(), &name("alice"), "skep.host").expect("written");
    assert_eq!(listing(dir.path()), vec!["alice.caddy"]);
    assert_eq!(fs::read_to_string(path(dir.path(), &name("alice"))).expect("the snippet"), ALICE);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(path(dir.path(), &name("alice"))).expect("its mode").permissions().mode() & 0o777, 0o644);
    }
    write(dir.path(), &name("alice"), "example.org").expect("written again");
    assert_eq!(listing(dir.path()), vec!["alice.caddy"]);
    assert!(fs::read_to_string(path(dir.path(), &name("alice"))).expect("the snippet").contains("alice.example.org"));
}

/// T7: A DIRECTORY THAT CANNOT BE WRITTEN is an error — the flow's failed
/// step — and leaves no file.
#[cfg(unix)]
#[test]
fn an_unwritable_directory_is_an_error() {
    use std::os::unix::fs::PermissionsExt;
    let dir = Scratch::new();
    let boards = dir.path().join("boards");
    fs::create_dir(&boards).expect("the boards directory");
    fs::set_permissions(&boards, fs::Permissions::from_mode(0o555)).expect("read-only");
    assert!(write(&boards, &name("alice"), "skep.host").is_err());
    fs::set_permissions(&boards, fs::Permissions::from_mode(0o700)).expect("writable again");
    assert!(listing(&boards).is_empty());
    assert!(write(dir.path().join("absent").as_path(), &name("alice"), "skep.host").is_err(), "a directory that does not stand");
}

/// A SNIPPET STANDS from its write until its removal: not before its
/// write, then after it, and not after its removal — another name's
/// snippet standing for none of it.
#[test]
fn a_snippet_stands_from_its_write_until_its_removal() {
    let dir = Scratch::new();
    write(dir.path(), &name("bob"), "skep.host").expect("bob's snippet");
    assert!(!stands(dir.path(), &name("alice")).expect("read"));
    write(dir.path(), &name("alice"), "skep.host").expect("written");
    assert!(stands(dir.path(), &name("alice")).expect("read"));
    remove(dir.path(), &name("alice")).expect("removed");
    assert!(!stands(dir.path(), &name("alice")).expect("read"));
    assert!(stands(dir.path(), &name("bob")).expect("read"));
}

/// The removal answers whether a snippet stood: `true` where one did,
/// `false` after; the reload is one call through the runner.
#[test]
fn a_removal_answers_whether_one_stood_and_a_reload_is_one_call() {
    let dir = Scratch::new();
    write(dir.path(), &name("alice"), "skep.host").expect("written");
    assert!(remove(dir.path(), &name("alice")).expect("removed"));
    assert!(!remove(dir.path(), &name("alice")).expect("nothing to remove"));
    assert!(listing(dir.path()).is_empty());
    let fake = FakeDocker::parse(&line("caddy_reload", None, 0, "", "")).expect("a script");
    assert!(reload(&fake).expect("an answer").ok());
    fake.assert_done();
}

/// THE ROUTED NAMES: each `<name>.caddy` file whose stem is a name in the
/// grammar, sorted; a temp file, another file, a directory and a stem out
/// of the grammar passed over.
#[test]
fn only_a_snippet_file_whose_stem_is_a_name_is_routed() {
    let dir = Scratch::new();
    for file in ["bob.caddy", "alice.caddy", "alice.caddy.tmp", "README", "Upper.caddy", "-x.caddy", "a.b.caddy"] {
        fs::write(dir.path().join(file), b"").expect("a file");
    }
    fs::create_dir(dir.path().join("carol.caddy")).expect("a directory");
    assert_eq!(routed(dir.path()).expect("read"), vec![name("alice"), name("bob")]);
}
