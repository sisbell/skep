//! ONE CHILD PROCESS, RUN TO ITS END — the one way this program runs a
//! program of the host's, `docker` and the mailer alike: [`Exit`], what the
//! child answered, and [`run`], the child spawned from the command its caller
//! built — the program and its arguments, nothing else — with its streams
//! this module's to set: stdin a pipe that carries the caller's input and
//! closes, or null where there is none, never the service's own; stdout and
//! stderr piped and read to their ends, apart. The input is written on a
//! thread of its own, so a child that writes before it has read cannot stall
//! the write; and a child that exits before reading it breaks the pipe
//! without failing the call, its exit code saying what happened.

use std::io::{self, Write};
use std::process::{Command, Stdio};
use std::thread;

/// What one child answered: its exit code (`None` where it ended by a
/// signal), its stdout and its stderr, each apart.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Exit {
    /// The exit code, or `None` where the process ended by a signal.
    pub code: Option<i32>,
    /// Everything it wrote on stdout.
    pub stdout: Vec<u8>,
    /// Everything it wrote on stderr.
    pub stderr: Vec<u8>,
}

impl Exit {
    /// Whether it exited 0.
    pub fn ok(&self) -> bool {
        self.code == Some(0)
    }

    /// The exit code as the log spells it: the number, or `signal`.
    pub fn said(&self) -> String {
        self.code.map_or_else(|| "signal".to_owned(), |c| c.to_string())
    }
}

/// ONE CHILD RUN: `cmd` spawned with its streams set — `stdin`'s bytes on a
/// pipe written by a thread of its own and closed, or a null stdin where
/// there are none; stdout and stderr piped — and waited for, its two streams
/// read to their ends. The error is a child that could not be spawned or
/// waited for, never its exit.
pub fn run(mut cmd: Command, stdin: Option<&[u8]>) -> io::Result<Exit> {
    cmd.stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() }).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = cmd.spawn()?;
    let feeder = match (stdin, child.stdin.take()) {
        (Some(bytes), Some(mut pipe)) => {
            let bytes = bytes.to_vec();
            Some(thread::spawn(move || pipe.write_all(&bytes)))
        }
        _ => None,
    };
    let out = child.wait_with_output()?;
    if let Some(feeder) = feeder {
        // A child that exits before reading its stdin breaks the pipe; its
        // exit code says what happened, so the write's error is not the
        // call's.
        let _ = feeder.join();
    }
    Ok(Exit { code: out.status.code(), stdout: out.stdout, stderr: out.stderr })
}

#[cfg(test)]
mod tests;
