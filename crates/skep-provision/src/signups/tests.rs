//! T10 — THE SIGN-UP FILE: a sign-up appends one line, the address and a
//! date; a malformed address appends nothing; and beneath it THE STATE
//! DIRECTORY's door — made `0700`, refused loose in the daemon's words — and
//! THE WRITER, whose failure between the write and the rename leaves the old
//! file whole and no temp file. (The page's DRAFT refusal and the log's
//! silence about the address are the pages' and the flow's suites'.)

use std::fs;

use super::*;
use crate::scratch::Scratch;

/// The address rule: one `@` with a side each way, at most 254 bytes, no
/// control character and no whitespace.
#[test]
fn the_address_rule() {
    for ok in ["a@b", "person@example.com", "first.last+tag@sub.example.org"] {
        assert!(address_ok(ok), "{ok}");
    }
    let long = format!("{}@b", "a".repeat(MAX_ADDRESS_BYTES - 2));
    assert!(address_ok(&long));
    for bad in ["", "ab", "@b", "a@", "a@b@c", "a b@c", "a@b\n", "a\t@b", "a@b\r", "\u{a0}a@b"] {
        assert!(!address_ok(bad), "{bad:?}");
    }
    assert!(!address_ok(&format!("{long}c")), "255 bytes");
}

/// T10: A SIGN-UP APPENDS ONE LINE — the address and today's date — and a
/// repeated address is one more line.
#[test]
fn a_sign_up_appends_one_line_with_the_address_and_a_date() {
    let dir = Scratch::new();
    let state = StateDir::open(&dir.path().join("state")).expect("the state directory");
    let signups = SignUps::new(&state);
    signups.append(b"person@example.com").expect("kept");
    let text = fs::read_to_string(state.file(SIGNUPS)).expect("the file");
    let (address, date) = text.trim_end().split_once(' ').expect("two fields");
    assert_eq!(address, "person@example.com");
    assert_eq!(date, today());
    assert_eq!(date.len(), 10);
    signups.append(b"other@example.org").expect("kept");
    signups.append(b"person@example.com").expect("kept again");
    let lines: Vec<String> = fs::read_to_string(state.file(SIGNUPS)).expect("the file").lines().map(|l| l.split(' ').next().unwrap_or("").to_owned()).collect();
    assert_eq!(lines, vec!["person@example.com", "other@example.org", "person@example.com"]);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(state.file(SIGNUPS)).expect("its mode").permissions().mode() & 0o777, 0o600);
    }
}

/// T10: A MALFORMED ADDRESS IS REFUSED and appends nothing — no file where
/// none stood, the file unchanged where one did.
#[test]
fn a_malformed_address_appends_nothing() {
    let dir = Scratch::new();
    let state = StateDir::open(&dir.path().join("state")).expect("the state directory");
    let signups = SignUps::new(&state);
    assert!(matches!(signups.append(b"not an address"), Err(SignUpRefused::NotAnAddress)));
    assert!(matches!(signups.append(&[0xff, b'@', b'b']), Err(SignUpRefused::NotAnAddress)));
    assert!(!state.file(SIGNUPS).exists());
    signups.append(b"person@example.com").expect("kept");
    let before = fs::read(state.file(SIGNUPS)).expect("the file");
    assert!(matches!(signups.append(b"a@b@c"), Err(SignUpRefused::NotAnAddress)));
    assert_eq!(fs::read(state.file(SIGNUPS)).expect("the file"), before);
}

/// THE STATE DIRECTORY's DOOR: made `0700` where absent; refused where it
/// stands with a group or other bit set, in `skepd`'s `LooseDataDir`
/// words; admitted at `0700`; refused where a file stands at the path.
#[cfg(unix)]
#[test]
fn the_state_directory_is_owner_only_or_refused() {
    use std::os::unix::fs::PermissionsExt;
    let dir = Scratch::new();
    let made = dir.path().join("made");
    StateDir::open(&made).expect("made");
    assert_eq!(fs::metadata(&made).expect("its mode").permissions().mode() & 0o777, 0o700);
    let loose = dir.path().join("loose");
    fs::create_dir(&loose).expect("a directory");
    fs::set_permissions(&loose, fs::Permissions::from_mode(0o755)).expect("loosened");
    let refused = StateDir::open(&loose).expect_err("loose");
    assert_eq!(
        refused.to_string(),
        format!("the state directory {0} is mode 755: other users of this machine can read the sign-up addresses and the invite codes; chmod 700 {0} and start again", loose.display())
    );
    assert_eq!(fs::read_dir(&loose).expect("listed").count(), 0, "nothing created, nothing repaired");
    fs::set_permissions(&loose, fs::Permissions::from_mode(0o700)).expect("tightened");
    StateDir::open(&loose).expect("admitted at 0700");
    let file = dir.path().join("file");
    fs::write(&file, b"").expect("a file");
    assert!(matches!(StateDir::open(&file), Err(StateDirRefused::Io { .. })));
}

/// THE WRITER: a failure between the write and the rename leaves the old
/// file whole and no temp file behind; a write that completes replaces it.
#[test]
fn a_failure_before_the_rename_leaves_the_old_file_whole() {
    let dir = Scratch::new();
    let path = dir.path().join("file");
    write_whole(&path, b"old\n").expect("written");
    let failed = write_whole_with(&path, b"new\n", &|| Err(io::Error::other("a failure between the write and the rename")));
    assert!(failed.is_err());
    assert_eq!(fs::read(&path).expect("the file"), b"old\n");
    assert!(!temp_of(&path).exists(), "no temp file left");
    write_whole(&path, b"new\n").expect("written");
    assert_eq!(fs::read(&path).expect("the file"), b"new\n");
    assert!(!temp_of(&path).exists());
}

/// The date: `yyyy-mm-dd` in UTC, from unix seconds.
#[test]
fn the_civil_date() {
    assert_eq!(civil_date(0), "1970-01-01");
    assert_eq!(civil_date(86_399), "1970-01-01");
    assert_eq!(civil_date(86_400), "1970-01-02");
    assert_eq!(civil_date(951_782_400), "2000-02-29");
    assert_eq!(civil_date(1_791_763_200), "2026-10-12");
}
