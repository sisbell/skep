//! ONE CHILD RUN TO ITS END, over `/bin/sh` — no Docker and no mailer is
//! run: the input arrives on the child's stdin and closes; with none, the
//! child's stdin answers at once; stdout, stderr and the exit code come back
//! apart; a child that exits before reading its input answers its own exit,
//! the broken pipe no error of the call's; and an end by signal answers no
//! code. (The command each caller builds is pinned in `docker`'s and
//! `sender`'s suites.)

#![cfg(unix)]

use super::*;

/// `/bin/sh -c <script>`, built as a caller builds its command: the program
/// and its arguments.
fn sh(script: &str) -> Command {
    let mut cmd = Command::new("/bin/sh");
    cmd.args(["-c", script]);
    cmd
}

/// THE INPUT GOES IN AND THE STREAMS COME BACK APART: the bytes reach the
/// child's stdin, which closes — `cat` ends — and its stdout, its stderr
/// and its exit code answer apart; with no input, `cat` ends at once.
#[test]
fn the_input_goes_in_and_the_streams_come_back_apart() {
    let exit = run(sh("cat; printf 'err' >&2; exit 7"), Some(b"the record")).expect("ran");
    assert_eq!(exit, Exit { code: Some(7), stdout: b"the record".to_vec(), stderr: b"err".to_vec() });
    assert!(!exit.ok());
    assert_eq!(exit.said(), "7");
    let none = run(sh("cat; printf 'read'"), None).expect("ran");
    assert_eq!((none.code, none.stdout.as_slice()), (Some(0), &b"read"[..]));
    assert!(none.ok());
}

/// A CHILD THAT NEVER READS ITS INPUT: a megabyte it exits without reading
/// breaks the pipe, and the call answers the child's own exit.
#[test]
fn a_child_that_never_reads_its_input_answers_its_own_exit() {
    let exit = run(sh("exit 3"), Some(&vec![b'x'; 1 << 20])).expect("the broken pipe is no error of the call's");
    assert_eq!(exit.code, Some(3));
}

/// AN END BY SIGNAL answers no code, and the log says `signal`.
#[test]
fn an_end_by_signal_answers_no_code() {
    let exit = run(sh("kill -9 $$"), None).expect("ran");
    assert_eq!(exit.code, None);
    assert_eq!(exit.said(), "signal");
}
