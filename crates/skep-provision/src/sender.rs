//! THE FOLLOW-UP MAIL (Q3 (b) and the sender ruling): the service sends it
//! itself, to the address on the post's invite line, once the board is
//! live — never before, and never in the way of the next post.
//!
//! * [`Message`] — PLAIN TEXT: `To:` the invite's address, `From:` the
//!   `--from` address, `Reply-To:` the owner's `--reply-to`, a DRAFT
//!   subject, and the body the reply renders for the page too (`reply`), so
//!   the mail is the page's text and the headers. The board, the recipient
//!   and the body are each post's; the other three are the outbox's own,
//!   the same for every board.
//! * [`Sender`] — the TRAIT, one method: hand one message over.
//! * [`RelaySender`] — its one real implementation, SHELLING OUT to the
//!   host-installed relay client — the mailer the operator names
//!   (`--mailer`) — through `process::run`, the runner `docker`'s calls go
//!   through too: `<mailer> -t`, the message with its headers on standard
//!   input — the convention `sendmail` and `msmtp` share as this crate
//!   knows them (UNVERIFIED HERE): `-t` reads the recipients off the `To:`
//!   header. The relay's credentials are the relay client's configuration
//!   on the VM, never this program's; no mail or TLS library is linked.
//! * [`Outbox`] — the SENDER THREAD of its own, and the follow-up mail's
//!   `From:`, `Reply-To:` and subject: the worker hands it a board, the
//!   invite's address and the live reply after the status turned live and
//!   goes on to the next post; the outbox makes the message and the thread
//!   sends it, and a refusal — a non-zero exit, a mailer that cannot
//!   run — is logged and RETRIED ([`MAIL_WAIT`]: seven tries, ten minutes
//!   apart) while the status page stands live, then logged as given up. A
//!   mail outage never loses a board: its page and its route stand
//!   whatever the mail does.
//! * [`Log`] and [`Sleep`] — the two hooks every thread of the service is
//!   handed: the log it writes a line to, and the sleep a wait takes. They
//!   live here, in the first module that takes them — the sender's thread
//!   takes both, and no module declared above this one in `main.rs` takes
//!   either — and `flow` and `main`, below it, take them from here.
//! * `fake` — under `test-hooks` alone: the messages appended to a file.
//!
//! The log names the board, the try and the exit code, and NEVER the
//! address or the body, which carries the status token.

use std::fmt;
use std::io;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::mpsc::{self, Receiver};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crate::name::Name;
use crate::process::{self, Exit};
use crate::statedir::MailAddress;
use crate::strings::{fill, MAIL_SUBJECT};
use crate::wait::Wait;

/// THE MAIL's WAIT: seven tries — the first and six more — ten minutes
/// apart, an hour of a relay's outage.
pub const MAIL_WAIT: Wait = Wait { tries: NonZeroU32::new(7).expect("seven is not zero"), interval: Duration::from_secs(10 * 60) };

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
    /// `--reply-to`: the owner's mailbox, where an answer to this mail goes.
    pub reply_to: String,
    /// The subject.
    pub subject: String,
    /// The live reply's text.
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

/// THE REAL SENDER: the host's relay client, the mailer `--mailer` names.
#[derive(Debug, Clone)]
pub struct RelaySender {
    program: PathBuf,
}

impl RelaySender {
    /// The relay client at `program` — a path, or a name found on `PATH`.
    pub fn new(program: PathBuf) -> RelaySender {
        RelaySender { program }
    }
}

/// THE COMMAND for a relay client: `<program> -t` and nothing else; its
/// streams are `process::run`'s to set — the message on its stdin, its
/// stdout and stderr captured apart.
fn command(program: &Path) -> Command {
    let mut cmd = Command::new(program);
    cmd.arg(READ_RECIPIENTS);
    cmd
}

impl Sender for RelaySender {
    fn send(&self, message: &Message) -> io::Result<Exit> {
        process::run(command(&self.program), Some(message.text().as_bytes()))
    }
}

/// ONE MESSAGE DELIVERED, or given up: tried over `wait`, paced by `sleep`
/// ([`Wait::paced`]), each refusal logged with its exit code; `true` once a
/// try exits 0. The mailer's stderr is not logged: a relay's refusal names
/// the recipient, and an address is never a log line's.
fn deliver(sender: &dyn Sender, message: &Message, wait: Wait, sleep: &dyn Fn(Duration), log: &dyn Fn(&str)) -> bool {
    let (name, tries) = (&message.name, wait.tries);
    for at in wait.paced(sleep) {
        match sender.send(message) {
            Ok(exit) if exit.ok() => {
                log(&format!("{name}: mail: sent at try {at} of {tries}"));
                return true;
            }
            Ok(exit) => log(&format!("{name}: mail: try {at} of {tries} refused, exit {}", exit.said())),
            Err(e) => log(&format!("{name}: mail: try {at} of {tries} failed, the mailer could not run: {}", e.kind())),
        }
    }
    log(&format!("{name}: mail: given up after {tries} tries; the board stands live and its status page with it"));
    false
}

/// THE OUTBOX: where the worker hands a follow-up mail — the sender's own
/// thread, and the three headers every follow-up mail carries alike.
pub struct Outbox {
    /// What delivers each message handed over.
    delivered_by: DeliveredBy,
    /// `--from`: the sending address.
    from: MailAddress,
    /// `--reply-to`: the owner's mailbox, where an answer to the mail goes.
    reply_to: MailAddress,
}

/// WHAT DELIVERS each message handed over: the sender's own thread, or —
/// in a unit suite's outbox — the caller.
enum DeliveredBy {
    /// The sender's own thread, through its queue.
    Thread(mpsc::Sender<Message>),
    /// The caller, on its own thread: a unit suite's, so the order of a
    /// send against the status is the order of the calls.
    #[cfg(test)]
    Caller { sender: Box<dyn Sender>, log: Log, sleep: Sleep },
}

impl Outbox {
    /// THE SENDER THREAD, started over the follow-up mail's `From:` and
    /// `Reply-To:`: it delivers each message handed over, in turn, until the
    /// process ends.
    pub fn spawn(sender: Box<dyn Sender>, from: MailAddress, reply_to: MailAddress, log: Log, sleep: Sleep) -> io::Result<Outbox> {
        let (tx, rx): (mpsc::Sender<Message>, Receiver<Message>) = mpsc::channel();
        thread::Builder::new().name("sender".into()).spawn(move || {
            for message in rx {
                deliver(sender.as_ref(), &message, MAIL_WAIT, sleep.as_ref(), log.as_ref());
            }
        })?;
        Ok(Outbox { delivered_by: DeliveredBy::Thread(tx), from, reply_to })
    }

    /// The outbox a unit suite drives: each message delivered at once, on
    /// the caller's thread.
    #[cfg(test)]
    pub fn inline(sender: Box<dyn Sender>, from: MailAddress, reply_to: MailAddress, log: Log, sleep: Sleep) -> Outbox {
        Outbox { delivered_by: DeliveredBy::Caller { sender, log, sleep }, from, reply_to }
    }

    /// ONE FOLLOW-UP MAIL handed over: the board, the invite's address and
    /// the live reply; `From:`, `Reply-To:` and the subject are the outbox's
    /// own, the same for every board.
    pub fn hand_over(&self, name: Name, to: String, body: String) {
        let message = Message { name, to, from: self.from.as_str().to_owned(), reply_to: self.reply_to.as_str().to_owned(), subject: fill(MAIL_SUBJECT, &[]), body };
        match &self.delivered_by {
            DeliveredBy::Thread(tx) => {
                // The thread ends only with the process; a send that fails
                // has no reader left to fail to.
                let _ = tx.send(message);
            }
            #[cfg(test)]
            DeliveredBy::Caller { sender, log, sleep } => {
                deliver(sender.as_ref(), &message, MAIL_WAIT, sleep.as_ref(), log.as_ref());
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
