//! T10 — THE SIGN-UP FILE: a sign-up appends one line, the address and a
//! date — a line of its own after the owner's trim too, the file saved with
//! no last line break; sign-ups made at once are every one kept, one writer
//! at a time; a malformed address appends nothing; a file that cannot be
//! written keeps nothing, and a sign-up past the file's cap keeps nothing,
//! each refusal an error saying which; the stretch at the cap counted, its
//! first refusal told it opens it and the next sign-up kept how many it
//! ends; the file's fill, for the start and every sign-up kept to say; and
//! where two refusals
//! hold, the field's speaks first, then the file's in the order met. (The
//! address rule is `mail_address`'s suite, and the state directory's door
//! and the writer beneath the file are `statedir`'s; the page's DRAFT
//! refusal and the log's silence about the address are the pages' and the
//! flow's suites'.)

use std::fs;

use super::*;
use crate::scratch::Scratch;

/// T10: A SIGN-UP APPENDS ONE LINE — the address and today's date — and a
/// repeated address is one more line.
#[test]
fn a_sign_up_appends_one_line_with_the_address_and_a_date() {
    let dir = Scratch::new();
    let state_dir = StateDir::open(&dir.path().join("state")).expect("the state directory");
    let signups = SignUps::new(&state_dir);
    let before = today();
    signups.append(b"person@example.com").expect("kept");
    let after = today();
    let text = fs::read_to_string(state_dir.file(SIGNUPS)).expect("the file");
    let (address, date) = text.trim_end().split_once(' ').expect("two fields");
    assert_eq!(address, "person@example.com");
    assert!(date == before || date == after, "{date}, not {before} or {after}");
    assert_eq!(date.len(), 10);
    signups.append(b"other@example.org").expect("kept");
    signups.append(b"person@example.com").expect("kept again");
    let lines: Vec<String> = fs::read_to_string(state_dir.file(SIGNUPS)).expect("the file").lines().map(|l| l.split(' ').next().unwrap_or("").to_owned()).collect();
    assert_eq!(lines, vec!["person@example.com", "other@example.org", "person@example.com"]);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(state_dir.file(SIGNUPS)).expect("its mode").permissions().mode() & 0o777, 0o600);
    }
}

/// ONE LINE PER ADDRESS, after the owner's trim too: a file the owner cut
/// down by hand and saved with no last line break — a shell's `$(…)` drops
/// it — takes the next sign-up on a line of its own, the owner's last line
/// kept whole: never two addresses glued into one line.
#[test]
fn a_sign_up_after_a_trim_with_no_last_line_break_is_a_line_of_its_own() {
    let dir = Scratch::new();
    let state_dir = StateDir::open(&dir.path().join("state")).expect("the state directory");
    let signups = SignUps::new(&state_dir);
    fs::write(state_dir.file(SIGNUPS), "kept@example.org 2026-10-01").expect("a file trimmed by hand, its last line break gone");
    signups.append(b"person@example.com").expect("kept");
    let text = fs::read_to_string(state_dir.file(SIGNUPS)).expect("the file");
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 2, "{text:?}");
    assert_eq!(lines[0], "kept@example.org 2026-10-01", "{text:?}");
    assert!(lines[1].starts_with("person@example.com ") && text.ends_with('\n'), "{text:?}");
}

/// T10: ONE WRITER AT A TIME — sign-ups made at once, each on a thread of
/// its own as the service serves every connection, are every one kept:
/// none lost to another's rewrite of the file.
#[test]
fn sign_ups_made_at_once_are_every_one_kept() {
    let dir = Scratch::new();
    let state_dir = StateDir::open(&dir.path().join("state")).expect("the state directory");
    let signups = SignUps::new(&state_dir);
    std::thread::scope(|s| {
        for t in 0..4 {
            let signups = &signups;
            s.spawn(move || {
                for n in 0..8 {
                    signups.append(format!("person{t}.{n}@example.com").as_bytes()).expect("kept");
                }
            });
        }
    });
    let mut kept: Vec<String> = fs::read_to_string(state_dir.file(SIGNUPS)).expect("the file").lines().map(|l| l.split(' ').next().unwrap_or("").to_owned()).collect();
    let mut sent: Vec<String> = (0..4).flat_map(|t| (0..8).map(move |n| format!("person{t}.{n}@example.com"))).collect();
    assert_eq!(kept.len(), sent.len(), "a sign-up lost to another's rewrite");
    kept.sort();
    sent.sort();
    assert_eq!(kept, sent);
}

/// T10: A MALFORMED ADDRESS IS REFUSED and appends nothing — no file where
/// none stood, the file unchanged where one did.
#[test]
fn a_malformed_address_appends_nothing() {
    let dir = Scratch::new();
    let state_dir = StateDir::open(&dir.path().join("state")).expect("the state directory");
    let signups = SignUps::new(&state_dir);
    assert!(matches!(signups.append(b"not an address"), Err(SignUpRefused::NotAnAddress)));
    assert!(matches!(signups.append(&[0xff, b'@', b'b']), Err(SignUpRefused::NotAnAddress)));
    assert!(!state_dir.file(SIGNUPS).exists());
    signups.append(b"person@example.com").expect("kept");
    let before = fs::read(state_dir.file(SIGNUPS)).expect("the file");
    assert!(matches!(signups.append(b"a@b@c"), Err(SignUpRefused::NotAnAddress)));
    assert_eq!(fs::read(state_dir.file(SIGNUPS)).expect("the file"), before);
}

/// EACH REFUSAL IS AN ERROR saying what kept nothing: no address by the
/// rule; or the file's own failure — a directory gone from under it — which
/// reaches the refusal through `?`, never as no address.
#[test]
fn each_refusal_is_an_error_saying_what_kept_nothing() {
    let dir = Scratch::new();
    let state_dir = StateDir::open(&dir.path().join("state")).expect("the state directory");
    let signups = SignUps::new(&state_dir);
    let refused: &dyn std::error::Error = &signups.append(b"not an address").expect_err("no address");
    assert_eq!(refused.to_string(), "the field is no address by the rule");
    fs::remove_dir(dir.path().join("state")).expect("the state directory removed");
    let failed = signups.append(b"person@example.com").expect_err("no directory to write in");
    assert!(matches!(failed, SignUpRefused::Io(_)), "{failed:?}");
    assert!(failed.to_string().starts_with("the sign-up file: "), "{failed}");
}

/// THE CAP: a sign-up that carries the file to `MAX_SIGNUPS_BYTES` exactly
/// is kept; the next, past it, is refused `Full` and keeps nothing — the
/// file as it was, no temp file — and the refusal says the cap.
#[test]
fn a_sign_up_past_the_cap_is_refused_and_keeps_nothing() {
    let dir = Scratch::new();
    let state_dir = StateDir::open(&dir.path().join("state")).expect("the state directory");
    let signups = SignUps::new(&state_dir);
    let line_bytes = format!("person@example.com {}\n", today()).len();
    fs::write(state_dir.file(SIGNUPS), format!("{}\n", "#".repeat(MAX_SIGNUPS_BYTES - line_bytes - 1))).expect("a file one line short of its cap");
    signups.append(b"person@example.com").expect("kept, to the cap");
    let full = fs::read(state_dir.file(SIGNUPS)).expect("the file");
    assert_eq!(full.len(), MAX_SIGNUPS_BYTES);
    let refused = signups.append(b"a@b").expect_err("past the cap");
    assert!(matches!(refused, SignUpRefused::Full { .. }), "{refused:?}");
    assert_eq!(fs::read(state_dir.file(SIGNUPS)).expect("the file"), full, "a refused sign-up wrote");
    assert!(!crate::whole::temp_of(&state_dir.file(SIGNUPS)).exists());
    let said: &dyn std::error::Error = &refused;
    assert_eq!(said.to_string(), "the sign-up file is at its 262144-byte cap");
}

/// THE STRETCH AT THE CAP, COUNTED under the file's own lock: its first
/// refusal opens it — none refused before — each later one counts the
/// refusals before it, the first sign-up kept once the file is trimmed says
/// how many the stretch refused, and the next kept says none; and every
/// sign-up kept says the bytes the file then holds.
#[test]
fn the_stretch_at_the_cap_is_counted_and_its_end_said_once() {
    let dir = Scratch::new();
    let state_dir = StateDir::open(&dir.path().join("state")).expect("the state directory");
    let signups = SignUps::new(&state_dir);
    let line_bytes = format!("person@example.com {}\n", today()).len() as u64;
    assert_eq!(signups.append(b"person@example.com").expect("kept"), Kept { refused_at_cap: 0, held: line_bytes }, "below the cap throughout");
    fs::write(state_dir.file(SIGNUPS), format!("{}\n", "#".repeat(MAX_SIGNUPS_BYTES - 1))).expect("a file at its cap");
    for before in 0..3 {
        assert!(matches!(signups.append(b"a@b"), Err(SignUpRefused::Full { refused_before }) if refused_before == before), "refusal {before}");
    }
    assert!(matches!(signups.append(b"not an address"), Err(SignUpRefused::NotAnAddress)), "a field refused is none of the stretch's");
    fs::write(state_dir.file(SIGNUPS), "").expect("the owner's trim");
    assert_eq!(signups.append(b"person@example.com").expect("kept after the trim"), Kept { refused_at_cap: 3, held: line_bytes });
    assert_eq!(signups.append(b"person@example.com").expect("kept"), Kept { refused_at_cap: 0, held: 2 * line_bytes }, "the stretch's end said once");
    assert_eq!(held_bytes(&state_dir).expect("read"), 2 * line_bytes, "the fill a sign-up says is the file's");
}

/// THE FILE's FILL, for the start to say against its cap: nothing where the
/// file does not stand, and its bytes where it does.
#[test]
fn the_fill_is_the_files_bytes_and_none_before_it_stands() {
    let dir = Scratch::new();
    let state_dir = StateDir::open(&dir.path().join("state")).expect("the state directory");
    assert_eq!(held_bytes(&state_dir).expect("read"), 0, "no file yet");
    SignUps::new(&state_dir).append(b"person@example.com").expect("kept");
    let bytes = fs::metadata(state_dir.file(SIGNUPS)).expect("the file").len();
    assert_eq!(held_bytes(&state_dir).expect("read"), bytes);
    assert_eq!(bytes, format!("person@example.com {}\n", today()).len() as u64);
}

/// WHICH REFUSAL SPEAKS where two hold: the field's first — no address by
/// the rule, the file untouched — then the file's in the order met, a read
/// that fails before the cap, the cap before a rewrite that fails; one case
/// for each pair, the file at its cap in each, and left as it was.
#[cfg(unix)]
#[test]
fn where_two_refusals_hold_the_field_speaks_then_the_file_in_its_order() {
    use std::os::unix::fs::PermissionsExt;
    let dir = Scratch::new();
    let state_dir = StateDir::open(&dir.path().join("state")).expect("the state directory");
    let signups = SignUps::new(&state_dir);
    let file = state_dir.file(SIGNUPS);
    fs::write(&file, format!("{}\n", "#".repeat(MAX_SIGNUPS_BYTES - 1))).expect("a file at its cap");
    let full = fs::read(&file).expect("the file");
    assert!(matches!(signups.append(b"not an address"), Err(SignUpRefused::NotAnAddress)), "the field before the cap");
    fs::set_permissions(&file, fs::Permissions::from_mode(0o000)).expect("unreadable");
    assert!(matches!(signups.append(b"person@example.com"), Err(SignUpRefused::Io(_))), "a read that fails before the cap");
    fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).expect("readable again");
    fs::set_permissions(dir.path().join("state"), fs::Permissions::from_mode(0o500)).expect("unwritable");
    assert!(matches!(signups.append(b"person@example.com"), Err(SignUpRefused::Full { .. })), "the cap before a rewrite that fails");
    fs::set_permissions(dir.path().join("state"), fs::Permissions::from_mode(0o700)).expect("writable again");
    assert_eq!(fs::read(&file).expect("the file"), full, "a refused sign-up wrote");
}
