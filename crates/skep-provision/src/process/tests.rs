//! ONE CHILD RUN TO ITS END, over `/bin/sh` — no Docker and no mailer is
//! run: the input arrives on the child's stdin and closes; with none, the
//! child's stdin answers at once; stdout, stderr and the exit code come back
//! apart; the input is fed on a thread of its own, so a child that writes
//! more than a pipe holds before it reads cannot stall it; a child that
//! exits before reading its input answers its own exit, the broken pipe no
//! error of the call's; an end by signal answers no code; a program that
//! cannot be spawned is the call's error; and an input whose thread the OS
//! refuses is the call's error too, its child ended at once and never a
//! panic. (The command each caller builds is pinned in `docker`'s and
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

/// THE INPUT IS FED ON A THREAD OF ITS OWN: a child that writes more than a
/// pipe holds before it reads a byte of its input — the input more than a
/// pipe holds too — still runs to its end. Fed inline, before the streams
/// were read, both pipes would fill and the call would never answer.
#[test]
fn a_child_that_writes_before_it_reads_cannot_stall_its_input() {
    let (answered, answer) = std::sync::mpsc::channel();
    thread::spawn(move || {
        let _ = answered.send(run(sh("head -c 1048576 /dev/zero; wc -c"), Some(&vec![b'x'; 1 << 20])));
    });
    let exit = answer.recv_timeout(std::time::Duration::from_secs(30)).expect("the call never answered: its input stalled against the child's output").expect("ran");
    assert_eq!(exit.code, Some(0));
    assert!(exit.stdout.len() > 1 << 20, "{}", exit.stdout.len());
    assert_eq!(String::from_utf8_lossy(&exit.stdout[1 << 20..]).trim(), "1048576", "every byte of the input read");
}

/// A PROGRAM THAT CANNOT BE SPAWNED IS THE CALL's ERROR, never an exit —
/// with an input to feed and without.
#[test]
fn a_program_that_cannot_be_spawned_is_the_calls_error() {
    for stdin in [None, Some(&b"the record"[..])] {
        assert!(run(Command::new("/nonexistent/skep-provision-test"), stdin).is_err(), "{stdin:?}");
    }
}

/// A FEEDER THE OS WILL NOT GIVE IS THE CALL's ERROR, never a panic: the
/// input's thread refused — its builder asking a stack of 32 PiB, which no
/// machine maps — the call answers the error at once, its child ended
/// unfed rather than waited out (this `sleep`, which never reads its input,
/// would hold the call half a minute), so the worker or the sender's thread
/// that called lives on to its next call.
#[test]
fn a_feeder_the_os_refuses_is_the_calls_error_and_its_child_is_ended() {
    let (answered, answer) = std::sync::mpsc::channel();
    thread::spawn(move || {
        let refused = thread::Builder::new().stack_size(1 << 55);
        let _ = answered.send(run_fed_by(sh("exec sleep 30"), Some(b"the record"), refused).map(|exit| exit.code));
    });
    let ran = answer.recv_timeout(std::time::Duration::from_secs(10)).expect("the call panicked, or waited its child out");
    assert!(ran.is_err(), "{ran:?}");
}
