//! The mail fake: a [`Sender`] that appends each message it accepts to a file.
//!
//! It is `test-hooks` alone, so no shipped build holds it. The file is its
//! mail log — the binary's `--mailer-fake <log>` — and the fake answers the
//! exit code its script gives, try by try: a list of codes taken in order,
//! `0` once the list is spent, so an empty script accepts every message the
//! mail log takes. A message is appended only where its try answers 0 — the
//! mail log is the mail that was sent — and a try the script answers 0
//! whose message the mail log will not take answers the append's error
//! instead; every try, accepted or refused, is recorded in memory with the
//! message it carried.
//!
//! **The mail log's form.** Each message is the line [`SEPARATOR`] and then
//! the message's text, its headers and its body, as the real mailer would
//! read it on stdin (`messages` reads them back).

use std::collections::VecDeque;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::Mutex;

use super::{Message, Sender};
use crate::process::Exit;

/// The line that opens each message in the mail log.
const SEPARATOR: &str = "=== skep-provision mail-fake: one message ===";

/// The fake: the mail log, the script, every try.
#[derive(Debug)]
pub struct FakeSender {
    mail_log: PathBuf,
    script: Mutex<VecDeque<i32>>,
    tries: Mutex<Vec<Message>>,
}

impl FakeSender {
    /// Returns the fake appending to `mail_log`.
    ///
    /// It answers `script`'s codes in order.
    pub fn new(mail_log: PathBuf, script: Vec<i32>) -> FakeSender {
        FakeSender { mail_log, script: Mutex::new(script.into()), tries: Mutex::new(Vec::new()) }
    }

    /// Returns every try, in order, with the message it carried.
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
            let mut file = OpenOptions::new().create(true).append(true).open(&self.mail_log)?;
            file.write_all(format!("{SEPARATOR}\n{}", message.text()).as_bytes())?;
        }
        Ok(Exit { code: Some(code), stdout: Vec::new(), stderr: Vec::new() })
    }
}

/// Reads the messages a mail log holds, each its text as appended.
///
/// It answers none where the mail log does not stand.
///
/// # Errors
///
/// The read's, where the mail log stands and cannot be read as text.
#[cfg(test)]
pub fn messages(mail_log: &std::path::Path) -> io::Result<Vec<String>> {
    let text = match std::fs::read_to_string(mail_log) {
        Ok(text) => text,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    Ok(text.split(&format!("{SEPARATOR}\n")).filter(|m| !m.is_empty()).map(str::to_owned).collect())
}
