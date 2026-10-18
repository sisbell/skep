//! One child process, run to its end: `docker` and the mailer alike.
//!
//! It is the one way this program runs a program of the host's: [`Exit`],
//! what the child answered, and [`run`], the child spawned from the command
//! its caller built — the program and its arguments, nothing else — with its
//! streams this module's to set: stdin a pipe that carries the caller's input
//! and closes, or null where there is none, never the service's own; stdout
//! and stderr piped and read to their ends, apart.
//!
//! The input is written on a thread of its own, so a child that writes before
//! it has read cannot stall the write; a child that exits before reading it
//! breaks the pipe without failing the call, its exit code saying what
//! happened; and where the OS gives no such thread, the call is the error and
//! the child is ended unfed — never a panic in the thread that called: a
//! worker, a connection thread at a post's look, `serve`'s own thread at its
//! sweep or the sender's thread.

use std::io::{self, Write};
use std::process::{Command, Stdio};
use std::thread;

/// What one child answered: its exit code, its stdout and its stderr.
///
/// The exit code is `None` where the child ended by a signal, and the three
/// are each apart. It has no `Default`: an empty one would claim a child
/// ended by a signal where none did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exit {
    /// The exit code, or `None` where the process ended by a signal.
    pub code: Option<i32>,
    /// Everything it wrote on stdout.
    pub stdout: Vec<u8>,
    /// Everything it wrote on stderr.
    pub stderr: Vec<u8>,
}

impl Exit {
    /// Returns whether the child exited 0.
    ///
    /// It is `std::process::ExitStatus::success`'s question, in its word: an
    /// end by a signal is no success.
    pub fn success(&self) -> bool {
        self.code == Some(0)
    }

    /// Returns the exit code as the log spells it: the number, or `signal`.
    pub fn said(&self) -> String {
        self.code.map_or_else(|| "signal".to_owned(), |c| c.to_string())
    }
}

/// Runs one child: `cmd` spawned with its streams set, and waited for.
///
/// The streams: `input`'s bytes on a pipe written by a thread of its own and
/// closed, or a null stdin where there are none; stdout and stderr piped, the
/// two read to their ends. The writer is scoped to the call: it borrows the
/// bytes the caller lends, so none is copied, and it is joined before the
/// call answers. The call never panics: its callers are a worker, a
/// connection thread at a post's look, `serve`'s own thread at its sweep and
/// the sender's thread, and a panic would cost each what it was doing — a
/// post, an answer, the start, a mail.
///
/// # Errors
///
/// A child that could not be spawned or waited for, or one whose input could
/// not be given a thread of its own — that child ended unfed and reaped —
/// and never its exit.
pub fn run(cmd: Command, input: Option<&[u8]>) -> io::Result<Exit> {
    run_fed_by(cmd, input, thread::Builder::new())
}

/// Runs `cmd` as [`run`] does, its input fed by a thread `builder` makes.
///
/// It is the seam a suite hands a builder the OS refuses, to show the call
/// then answers the error, its child ended.
///
/// # Errors
///
/// As [`run`]'s; the thread an input is fed by is the one `builder` makes.
fn run_fed_by(mut cmd: Command, input: Option<&[u8]>, builder: thread::Builder) -> io::Result<Exit> {
    cmd.stdin(if input.is_some() { Stdio::piped() } else { Stdio::null() }).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = cmd.spawn()?;
    let pipe = child.stdin.take();
    let out = thread::scope(|s| {
        let feeder = match input.zip(pipe) {
            None => None,
            Some((bytes, mut pipe)) => match builder.spawn_scoped(s, move || pipe.write_all(bytes)) {
                Ok(feeder) => Some(feeder),
                Err(e) => {
                    // No thread to feed the input: the closure the OS
                    // refused was dropped, the pipe with it, so the child's
                    // input ends unfed; the child is ended and reaped, and
                    // the call is the error — a step's "docker could not
                    // run", the mail's retry.
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(e);
                }
            },
        };
        let out = child.wait_with_output();
        if let Some(feeder) = feeder {
            // A child that exits before reading its stdin breaks the pipe; its
            // exit code says what happened, so the write's error is not the
            // call's.
            let _ = feeder.join();
        }
        out
    })?;
    Ok(Exit { code: out.status.code(), stdout: out.stdout, stderr: out.stderr })
}

#[cfg(test)]
mod tests;
