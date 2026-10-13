//! T10 — THE SIGN-UP FILE: a sign-up appends one line, the address and a
//! date; a malformed address appends nothing. (The address rule, the state
//! directory's door and the writer beneath the file are `statedir`'s suite;
//! the page's DRAFT refusal and the log's silence about the address are the
//! pages' and the flow's suites'.)

use std::fs;

use super::*;
use crate::scratch::Scratch;

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
