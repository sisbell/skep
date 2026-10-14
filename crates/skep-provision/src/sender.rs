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
//!   Whether the client can be run at all is asked at start ([`runnable`]),
//!   so one not installed refuses the start rather than every board's mail.
//! * [`Outbox`] — the SENDER THREAD of its own, and the follow-up mail's
//!   `From:`, `Reply-To:` and subject: the worker hands it a board, the
//!   invite's address and the live reply after the status turned live and
//!   goes on to the next post — the hand-over said with the mails ahead of
//!   it, so a relay client that never returns reads as a count that only
//!   climbs; the outbox makes the message and the thread sends it, and a
//!   refusal — a non-zero exit, a mailer that cannot run — is logged and
//!   RETRIED ([`MAIL_WAIT`]: seven tries, ten minutes apart) while the status
//!   page stands live, then logged as given up, naming the operator's act —
//!   the person written to by hand; a send that panics gives up its own
//!   mail, and no other. A mail outage never loses a board: its page and its
//!   route stand whatever the mail does.
//! * [`Log`] and [`Sleep`] — the two hooks every thread of the service is
//!   handed: the log it writes a line to, and the sleep a wait takes; and
//!   beside them what the panic hook reads of a thread — the board it works
//!   on ([`on_board`], [`board_of_this_thread`]) — and the hook's line
//!   ([`panic_line`]). They live here, in the first module that takes them —
//!   the sender's thread takes the four, and no module declared above this
//!   one in `main.rs` takes any — and `flow` and `main`, below it, take them
//!   from here.
//! * `fake` — under `test-hooks` alone: the messages appended to a file.
//!
//! The log names the board, the try and the exit code — a relay's refusal
//! by its code and the name `sysexits.h` gives it — and NEVER the address or
//! the body, which carries the status token.

use std::cell::RefCell;
use std::ffi::OsStr;
use std::fmt;
use std::fs;
use std::io;
use std::num::NonZeroU32;
use std::panic::{catch_unwind, AssertUnwindSafe, Location};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use crate::mail_address::MailAddress;
use crate::name::Name;
use crate::process::{self, Exit};
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

thread_local! {
    /// THE BOARD this thread works on, where it works on one: set by
    /// [`on_board`] for a worker's post and for a mail's delivery, and read
    /// by the panic hook alone.
    static BOARD: RefCell<Option<String>> = const { RefCell::new(None) };
}

/// `work` run with `name` as this thread's board, the board cleared after it
/// on its return and on its unwind alike, by a guard — so the panic hook,
/// which runs inside the unwind before the guard drops, names the board, and
/// a line after the catch reads none.
pub fn on_board<T>(name: &Name, work: impl FnOnce() -> T) -> T {
    /// The guard that clears the board as its frame ends.
    struct Cleared;
    impl Drop for Cleared {
        fn drop(&mut self) {
            let _ = BOARD.try_with(|board| board.try_borrow_mut().map(|mut board| *board = None));
        }
    }
    let _ = BOARD.try_with(|board| board.try_borrow_mut().map(|mut board| *board = Some(name.to_string())));
    let _cleared = Cleared;
    work()
}

/// THIS THREAD's BOARD, where [`on_board`] has set one: `None` outside it,
/// and where the thread's storage is gone or held — never a panic, the
/// panic hook its one reader.
pub fn board_of_this_thread() -> Option<String> {
    BOARD.try_with(|board| board.try_borrow().ok().and_then(|board| board.clone())).ok().flatten()
}

/// THE PANIC HOOK's LINE, the words alone — `skepd`'s hook's (its
/// `operations.md` §1.1 row 41), with the board this service works per
/// thread: the board where the thread works on one (`<board>: `), the
/// thread by its name (`an unnamed thread` where it has none), the location
/// as std spells it (`file:line:column`; `an unknown location` where the
/// hook's info carries none), and the payload ONLY where it is a `&'static
/// str` — a literal the code wrote, which no request can have formatted — so
/// a formatted panic (`expect`, an index, an `assert_eq!`) shows its
/// location alone, which names the site, and nothing the log never carries
/// can ride the line.
pub fn panic_line(board: Option<&str>, thread: Option<&str>, location: Option<&Location<'_>>, payload: Option<&str>) -> String {
    let board = board.map_or_else(String::new, |board| format!("{board}: "));
    let thread = thread.map_or_else(|| "an unnamed thread".to_owned(), |thread| format!("the {thread} thread"));
    let at = location.map_or_else(|| "an unknown location".to_owned(), Location::to_string);
    match payload {
        Some(payload) => format!("{board}{thread} panicked at {at}: {payload}"),
        None => format!("{board}{thread} panicked at {at}"),
    }
}

/// ONE MAIL. Its four header fields — `to`, `from`, `reply_to`, `subject` —
/// are each one line, the three addresses one recipient each, and its body
/// holds no line that is a lone `.`, which `sendmail -t` without `-i` reads
/// as the message's end (as this crate knows sendmail — UNVERIFIED HERE):
/// the builder's obligation, which [`Message::text`] writes as held and
/// nothing here checks. The program's one builder, the outbox, keeps it:
/// `from` and `reply_to` addresses by the rule, the subject a strings row,
/// the body the live reply the worker hands it — the strings table's rows,
/// which the reply's suite holds to it; and `to` handed on as the invite
/// file's line holds it — the mint's address by the rule, unless the
/// operator's hand has edited the line.
#[derive(Clone, PartialEq, Eq)]
pub struct Message {
    /// The board it is about — the one thing the log may name.
    pub name: Name,
    /// The invite's address, as its line holds it.
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
/// A SEND THAT UNWINDS: the sender's thread catches it and hands the next
/// message to the same sender, so a sender keeps nothing a send can leave
/// half-changed; the relay client keeps nothing at all.
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

/// WHETHER `program` CAN BE RUN as the relay client, asked at start — so a
/// relay client not installed is a start refused, and never every board's
/// mail given up an hour after the board went live: where `program` names a
/// path, the file there with an execute bit; a bare name, such a file in a
/// directory of `PATH`, as `Command` finds one. The error says which.
pub fn runnable(program: &Path) -> Result<(), String> {
    runnable_on(program, std::env::var_os("PATH").as_deref())
}

/// [`runnable`] over `path`, the `PATH` a bare name is looked for on: the
/// seam a suite hands a `PATH` of its own, the process's own left as it is.
fn runnable_on(program: &Path, path: Option<&OsStr>) -> Result<(), String> {
    if program.to_string_lossy().contains('/') {
        return match fs::metadata(program) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => Err("no file stands at it".to_owned()),
            Err(e) => Err(format!("it cannot be read: {e}")),
            Ok(meta) if !meta.is_file() => Err("it is not a file".to_owned()),
            Ok(meta) if !executable(&meta) => Err("it is a file with no execute bit".to_owned()),
            Ok(_) => Ok(()),
        };
    }
    let on_path = path.into_iter().flat_map(std::env::split_paths).any(|dir| fs::metadata(dir.join(program)).is_ok_and(|meta| meta.is_file() && executable(&meta)));
    if on_path {
        Ok(())
    } else {
        Err("no directory of PATH holds it as a file with an execute bit".to_owned())
    }
}

/// Whether a file's mode lets it be run: an execute bit, on unix; any file
/// elsewhere.
fn executable(meta: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        true
    }
}

/// A MAIL GIVEN UP, as the log says it — `cause` its words after `given up`
/// — with what still stands, the board live and its reply on its status
/// page until the process ends, and the operator's act: the person written
/// to by hand, at the address the invite file's line spent under the board
/// holds, which no log line carries.
fn given_up(name: &Name, cause: &str) -> String {
    format!(
        "{name}: mail: given up{cause}; the board stands live and its reply on its status page until the process ends — write to the person by hand: their address is on the invite file's line spent under {name} (RUNBOOK §10 step 11)"
    )
}

/// THE NAME `sysexits.h` gives an exit code, where it gives one: the codes
/// from 64 to 78, which `sendmail` and `msmtp` both exit by (as this crate
/// knows them — UNVERIFIED HERE for the VM's builds), so the one figure the
/// log carries of a relay's refusal — its stderr names the recipient, and is
/// withheld whole — says which kind of refusal it was.
fn sysexits_name(code: i32) -> Option<&'static str> {
    Some(match code {
        64 => "EX_USAGE",
        65 => "EX_DATAERR",
        66 => "EX_NOINPUT",
        67 => "EX_NOUSER",
        68 => "EX_NOHOST",
        69 => "EX_UNAVAILABLE",
        70 => "EX_SOFTWARE",
        71 => "EX_OSERR",
        72 => "EX_OSFILE",
        73 => "EX_CANTCREAT",
        74 => "EX_IOERR",
        75 => "EX_TEMPFAIL",
        76 => "EX_PROTOCOL",
        77 => "EX_NOPERM",
        78 => "EX_CONFIG",
        _ => return None,
    })
}

/// A RELAY CLIENT's EXIT as the log spells it: the code as [`Exit::said`]
/// spells it, and after it, in brackets, the name `sysexits.h` gives it
/// where it gives one — `75 (EX_TEMPFAIL)`.
fn relay_exit_said(exit: &Exit) -> String {
    match exit.code.and_then(sysexits_name) {
        Some(named) => format!("{} ({named})", exit.said()),
        None => exit.said(),
    }
}

/// ONE MESSAGE DELIVERED, or given up: tried over `wait`, paced by `sleep`
/// ([`Wait::paced`]), each refusal logged with its exit code and the name
/// `sysexits.h` gives it; `true` once a try exits 0. The mailer's stderr is
/// not logged: a relay's refusal names the recipient, and an address is never
/// a log line's.
fn deliver(sender: &dyn Sender, message: &Message, wait: Wait, sleep: &dyn Fn(Duration), log: &dyn Fn(&str)) -> bool {
    let (name, tries) = (&message.name, wait.tries);
    for at in wait.paced(sleep) {
        match sender.send(message) {
            Ok(exit) if exit.success() => {
                log(&format!("{name}: mail: sent at try {at} of {tries}"));
                return true;
            }
            Ok(exit) => log(&format!("{name}: mail: try {at} of {tries} refused, exit {}", relay_exit_said(&exit))),
            Err(e) => log(&format!("{name}: mail: try {at} of {tries} failed, the mailer could not run: {}", e.kind())),
        }
    }
    log(&given_up(name, &format!(" after {tries} tries")));
    false
}

/// THE OUTBOX: where the worker hands a follow-up mail — the sender's own
/// thread, the three headers every follow-up mail carries alike, and the log
/// the hand-over is said on.
pub struct Outbox {
    /// What delivers each message handed over.
    delivered_by: DeliveredBy,
    /// `--from`: the sending address.
    from: MailAddress,
    /// `--reply-to`: the owner's mailbox, where an answer to the mail goes.
    reply_to: MailAddress,
    /// The log a hand-over is said on.
    log: Log,
}

/// WHAT DELIVERS each message handed over: the sender's own thread, or —
/// in a unit suite's outbox — the caller.
enum DeliveredBy {
    /// The sender's own thread, through its channel, and the mails handed
    /// to it and not yet delivered or given up — the one in its try among
    /// them.
    Thread { tx: mpsc::Sender<Message>, pending: Arc<AtomicUsize> },
    /// The caller, on its own thread: a unit suite's, so the order of a
    /// send against the status is the order of the calls, and no mail is
    /// ever ahead of another.
    #[cfg(test)]
    Caller { sender: Box<dyn Sender>, sleep: Sleep },
}

impl Outbox {
    /// THE SENDER THREAD, started over the follow-up mail's `From:` and
    /// `Reply-To:`: it delivers each message handed over, in turn, until the
    /// process ends, each with its board as the thread's ([`on_board`]), and
    /// counts each out of the mails pending once delivered or given up. A
    /// send that panics costs its own mail alone — given up, and logged so by
    /// its board — never the thread, which nothing would start again, and
    /// every mail after it with it.
    pub fn spawn(sender: Box<dyn Sender>, from: MailAddress, reply_to: MailAddress, log: Log, sleep: Sleep) -> io::Result<Outbox> {
        let (tx, rx): (mpsc::Sender<Message>, Receiver<Message>) = mpsc::channel();
        let pending = Arc::new(AtomicUsize::new(0));
        let (thread_log, thread_pending) = (Arc::clone(&log), Arc::clone(&pending));
        thread::Builder::new().name("sender".into()).spawn(move || {
            for message in rx {
                on_board(&message.name, || {
                    // AssertUnwindSafe, and sound: a sender keeps nothing a
                    // send can leave half-changed, `Sender`'s own obligation —
                    // the relay client nothing at all — so the next message
                    // meets it as the last did.
                    if catch_unwind(AssertUnwindSafe(|| deliver(sender.as_ref(), &message, MAIL_WAIT, sleep.as_ref(), thread_log.as_ref()))).is_err() {
                        thread_log(&given_up(&message.name, ", a try having panicked"));
                    }
                });
                thread_pending.fetch_sub(1, Ordering::AcqRel);
            }
        })?;
        Ok(Outbox { delivered_by: DeliveredBy::Thread { tx, pending }, from, reply_to, log })
    }

    /// The outbox a unit suite drives: each message delivered at once, on
    /// the caller's thread.
    #[cfg(test)]
    pub fn inline(sender: Box<dyn Sender>, from: MailAddress, reply_to: MailAddress, log: Log, sleep: Sleep) -> Outbox {
        Outbox { delivered_by: DeliveredBy::Caller { sender, sleep }, from, reply_to, log }
    }

    /// ONE FOLLOW-UP MAIL handed over: the board, the invite's address — as
    /// the invite file's line holds it: put there through the address rule
    /// by the mint, and read back unchecked, a hand edit of the line the
    /// operator's own act — and the live reply; `From:`, `Reply-To:` and the
    /// subject are the outbox's own, the same for every board. Said first,
    /// `<name>: mail: handed to the sender, <n> ahead of it` — before the
    /// message reaches the sender's thread, so the hand-over is said ahead of
    /// every line of its delivery — `<n>` the mails handed over and not yet
    /// delivered or given up: a relay client that never returns holds every
    /// later mail behind its try, and reads as a count that only climbs.
    pub fn hand_over(&self, name: Name, to: String, body: String) {
        let ahead = match &self.delivered_by {
            DeliveredBy::Thread { pending, .. } => pending.fetch_add(1, Ordering::AcqRel),
            #[cfg(test)]
            DeliveredBy::Caller { .. } => 0,
        };
        (self.log)(&format!("{name}: mail: handed to the sender, {ahead} ahead of it"));
        let message = Message { name, to, from: self.from.as_str().to_owned(), reply_to: self.reply_to.as_str().to_owned(), subject: fill(MAIL_SUBJECT, &[]), body };
        match &self.delivered_by {
            DeliveredBy::Thread { tx, .. } => {
                // The channel's send fails only where its reader, the
                // sender's thread, has ended — and the thread ends only with
                // the process.
                let _ = tx.send(message);
            }
            #[cfg(test)]
            DeliveredBy::Caller { sender, sleep } => {
                deliver(sender.as_ref(), &message, MAIL_WAIT, sleep.as_ref(), self.log.as_ref());
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
