//! THE FOLLOW-UP MAIL (Q3 (b) and the sender ruling): the service sends it
//! itself, to the address on the post's invite line, once the board is
//! live — never before, and never in the way of the next post.
//!
//! * [`Message`] — PLAIN TEXT: `To:` the invite's address, `From:` the
//!   `--from` address, `Reply-To:` the owner's `--reply-to`, a DRAFT
//!   subject, and the body the reply renders for the page too (`reply`), so
//!   the mail is the page's text and the headers.
//! * [`Sender`] — the TRAIT, one method: hand one message over.
//! * [`Mailer`] — its one real implementation, SHELLING OUT to the
//!   host-installed relay client the operator names (`--mailer`), as the
//!   service shells out to `docker`: `<mailer> -t`, the message with its
//!   headers on standard input — the convention `sendmail` and `msmtp`
//!   share as this crate knows them (UNVERIFIED HERE): `-t` reads the
//!   recipients off the `To:` header. The relay's credentials are the relay
//!   client's configuration on the VM, never this program's; no mail or TLS
//!   library is linked.
//! * [`Outbox`] — the SENDER THREAD of its own: the worker hands it a
//!   message after the status turned live and goes on to the next post; the
//!   thread sends it, and a refusal — a non-zero exit, a mailer that cannot
//!   run — is logged and RETRIED ([`MAIL_TRIES`] tries, [`MAIL_INTERVAL`]
//!   apart) while the status page stands live, then logged as given up. A
//!   mail outage never loses a board: its page and its route stand
//!   whatever the mail does.
//! * `fake` — under `test-hooks` alone: the messages appended to a file.
//!
//! The log names the board, the try and the exit code, and NEVER the
//! address or the body, which carries the status token.

use std::fmt;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use crate::docker::Exit;
use crate::name::Name;

/// The tries a message gets: the first and six more — an hour of a
/// relay's outage at [`MAIL_INTERVAL`].
pub const MAIL_TRIES: u32 = 7;

/// The sleep between two tries.
const MAIL_INTERVAL: Duration = Duration::from_secs(10 * 60);

/// The flag the mailer reads its recipients off the headers by.
const READ_RECIPIENTS: &str = "-t";

/// The log a thread writes to: one line, no line break.
pub type Log = Arc<dyn Fn(&str) + Send + Sync>;

/// The sleep a wait takes: `thread::sleep` in the program, nothing in a
/// test.
pub type Sleep = Arc<dyn Fn(Duration) + Send + Sync>;

/// ONE MAIL.
#[derive(Clone, PartialEq, Eq)]
pub struct Message {
    /// The board it is about — the one thing the log may name.
    pub name: Name,
    /// The invite's address.
    pub to: String,
    /// `--from`.
    pub from: String,
    /// `--reply-to`: where a reply goes.
    pub reply_to: String,
    /// The subject.
    pub subject: String,
    /// The reply's text.
    pub body: String,
}

/// The board alone: neither the address nor the body reaches a `{:?}`.
impl fmt::Debug for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Message").field("name", &self.name).finish_non_exhaustive()
    }
}

impl Message {
    /// THE MESSAGE AS SENT: its headers, a blank line, its body — plain
    /// text in UTF-8, the body's dashes and quotes as written.
    pub fn text(&self) -> String {
        format!(
            "To: {}\nFrom: {}\nReply-To: {}\nSubject: {}\nMIME-Version: 1.0\nContent-Type: text/plain; charset=utf-8\nContent-Transfer-Encoding: 8bit\n\n{}",
            self.to, self.from, self.reply_to, self.subject, self.body
        )
    }
}

/// THE SENDER: one message handed over, answered with the hand-over's exit.
pub trait Sender: Send + Sync {
    /// One try at `message`.
    fn send(&self, message: &Message) -> io::Result<Exit>;
}

/// THE REAL SENDER: the host's relay client.
#[derive(Debug, Clone)]
pub struct Mailer {
    program: PathBuf,
}

impl Mailer {
    /// The mailer at `program` — a path, or a name found on `PATH`.
    pub fn new(program: PathBuf) -> Mailer {
        Mailer { program }
    }
}

/// THE COMMAND for a mailer: `<program> -t` and nothing else, the message
/// to go on its stdin, its stdout and stderr captured apart.
fn command(program: &Path) -> Command {
    let mut cmd = Command::new(program);
    cmd.arg(READ_RECIPIENTS).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    cmd
}

impl Sender for Mailer {
    fn send(&self, message: &Message) -> io::Result<Exit> {
        let mut child = command(&self.program).spawn()?;
        let mut stdin = child.stdin.take().ok_or_else(|| io::Error::other("the mailer's stdin was not piped"))?;
        let text = message.text().into_bytes();
        let feeder = thread::spawn(move || stdin.write_all(&text));
        let out = child.wait_with_output()?;
        let _ = feeder.join();
        Ok(Exit { code: out.status.code(), stdout: out.stdout, stderr: out.stderr })
    }
}

/// ONE MESSAGE DELIVERED, or given up: up to `tries` tries, `sleep`ing
/// `interval` between two, each refusal logged with its exit code; `true`
/// once a try exits 0. The mailer's stderr is not logged: a relay's refusal
/// names the recipient, and an address is never a log line's.
fn deliver(sender: &dyn Sender, message: &Message, tries: u32, interval: Duration, sleep: &dyn Fn(Duration), log: &dyn Fn(&str)) -> bool {
    let name = &message.name;
    for at in 1..=tries {
        match sender.send(message) {
            Ok(exit) if exit.ok() => {
                log(&format!("{name}: mail: sent at try {at} of {tries}"));
                return true;
            }
            Ok(exit) => log(&format!("{name}: mail: try {at} of {tries} refused, exit {}", exit.said())),
            Err(e) => log(&format!("{name}: mail: try {at} of {tries} failed, the mailer could not run: {}", e.kind())),
        }
        if at < tries {
            sleep(interval);
        }
    }
    log(&format!("{name}: mail: given up after {tries} tries; the board stands live and its status page with it"));
    false
}

/// THE OUTBOX: where the worker hands a message.
pub struct Outbox {
    way: Way,
}

enum Way {
    /// The sender thread's queue.
    Thread(Mutex<mpsc::Sender<Message>>),
    /// Delivered on the caller's own thread: a unit suite's, so the order
    /// of a send against the status is the order of the calls.
    #[cfg(test)]
    Inline { sender: Box<dyn Sender>, log: Log, sleep: Sleep },
}

impl Outbox {
    /// THE SENDER THREAD, started: it delivers each message handed over, in
    /// turn, until the program ends.
    pub fn spawn(sender: Box<dyn Sender>, log: Log, sleep: Sleep) -> io::Result<Outbox> {
        let (tx, rx): (mpsc::Sender<Message>, Receiver<Message>) = mpsc::channel();
        thread::Builder::new().name("sender".into()).spawn(move || {
            for message in rx {
                deliver(sender.as_ref(), &message, MAIL_TRIES, MAIL_INTERVAL, sleep.as_ref(), log.as_ref());
            }
        })?;
        Ok(Outbox { way: Way::Thread(Mutex::new(tx)) })
    }

    /// The outbox a unit suite drives: each message delivered at once, on
    /// the caller's thread.
    #[cfg(test)]
    pub fn inline(sender: Box<dyn Sender>, log: Log, sleep: Sleep) -> Outbox {
        Outbox { way: Way::Inline { sender, log, sleep } }
    }

    /// One message handed over.
    pub fn post(&self, message: Message) {
        match &self.way {
            Way::Thread(tx) => {
                // The thread ends only with the program; a send that fails
                // has no reader left to fail to.
                let _ = tx.lock().unwrap_or_else(|e| e.into_inner()).send(message);
            }
            #[cfg(test)]
            Way::Inline { sender, log, sleep } => {
                deliver(sender.as_ref(), &message, MAIL_TRIES, MAIL_INTERVAL, sleep.as_ref(), log.as_ref());
            }
        }
    }
}

/// A shared sender is a sender: a unit suite hands the outbox an `Arc` of
/// its fake and keeps one to read the tries after.
#[cfg(test)]
impl<S: Sender + ?Sized> Sender for Arc<S> {
    fn send(&self, message: &Message) -> io::Result<Exit> {
        (**self).send(message)
    }
}

#[cfg(feature = "test-hooks")]
pub mod fake;

#[cfg(test)]
mod tests;
