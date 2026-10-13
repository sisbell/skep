//! THE MAIL FAKE — `test-hooks` alone, so no shipped build holds it: a
//! [`Sender`] that APPENDS each message it accepts to its log file — the
//! binary's `--mailer-fake <log>` — and answers the exit code its SCRIPT
//! gives, try by try: a list of codes taken in order, `0` once the list is
//! spent, so an empty script accepts every message. A message is appended
//! only where its try answers 0 — the log is the mail that was sent — and
//! every try, accepted or refused, is recorded in memory with the message
//! it carried.
//!
//! THE LOG's FORM: each message is the line [`SEPARATOR`] and then the
//! message's text, its headers and its body, as the real mailer would read
//! it on stdin (`messages` reads them back).

use std::collections::VecDeque;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::Mutex;

use super::{Message, Sender};
use crate::process::Exit;

/// The line that opens each message in the log.
const SEPARATOR: &str = "=== skep-provision mail-fake: one message ===";

/// THE FAKE: the log, the script, every try.
#[derive(Debug)]
pub struct FakeSender {
    log: PathBuf,
    script: Mutex<VecDeque<i32>>,
    tries: Mutex<Vec<Message>>,
}

impl FakeSender {
    /// The fake appending to `log`, answering `script`'s codes in order.
    pub fn new(log: PathBuf, script: Vec<i32>) -> FakeSender {
        FakeSender { log, script: Mutex::new(script.into()), tries: Mutex::new(Vec::new()) }
    }

    /// Every try, in order, with the message it carried.
    #[cfg(test)]
    pub fn tries(&self) -> Vec<Message> {
        self.tries.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

impl Sender for FakeSender {
    fn send(&self, message: &Message) -> io::Result<Exit> {
        self.tries.lock().unwrap_or_else(|e| e.into_inner()).push(message.clone());
        let code = self.script.lock().unwrap_or_else(|e| e.into_inner()).pop_front().unwrap_or(0);
        if code == 0 {
            let mut log = OpenOptions::new().create(true).append(true).open(&self.log)?;
            log.write_all(format!("{SEPARATOR}\n{}", message.text()).as_bytes())?;
        }
        Ok(Exit { code: Some(code), stdout: Vec::new(), stderr: Vec::new() })
    }
}

/// The messages a log holds, each its text as appended; none where the log
/// does not stand.
#[cfg(test)]
pub fn messages(log: &std::path::Path) -> io::Result<Vec<String>> {
    let text = match std::fs::read_to_string(log) {
        Ok(text) => text,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    Ok(text.split(&format!("{SEPARATOR}\n")).filter(|m| !m.is_empty()).map(str::to_owned).collect())
}
