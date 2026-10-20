//! The adapter's log: stderr, one line per notice, never waiting on a reader.
//!
//! Every line the adapter says goes through [`log`] — startup's lines, the
//! stops, the loop's own and the shell's TALK — so stdout stays the JSON-RPC
//! stream alone. A line is rendered by `logged`, and opens with the moment it
//! was said: `skep-mcp: 2026-10-20T14:05:12.345Z the board restarted: …`, RFC
//! 3339 UTC to the millisecond, read from the system clock where the line is
//! said — never where the writer below writes it, which a slow reader makes
//! later — and rendered by the civil-date conversion skep-util's `notice`
//! stamps the daemon's stream with, copied here (`Rfc3339`). So a log kept in a
//! file carries its own moments, and joins the board's stream by them.
//!
//! **What a line never carries.** The log says what happened at the board,
//! never what a principal read (D9). A line can quote an answer all the same:
//! skep-client's refusal of an answer it cannot parse quotes the answer whole,
//! and the shell's feed thread says such a refusal where its read of a
//! document's text — a draft's among them, under the agent's own session —
//! met an intermediary that re-framed or cut the answer. So `logged` cuts each
//! such quote at its parse error (`QUOTED_ANSWER`), and clips every line at
//! `LINE_BYTES` of rendered text, each cut saying how many bytes it took.
//!
//! Three rules travel with a line's write, the ones `notice` keeps for the
//! daemon: it never fails the work it reports on, never reports, and never
//! waits.
//!
//! **Never fails, never reports.** The write's result is discarded — never
//! `eprintln!`, which panics when the write fails — so a pipe whose reader has
//! gone (EPIPE) or a full volume (ENOSPC) costs the line alone.
//!
//! **Never waits.** MCP's stdio transport lets a client ignore the server's
//! stderr, and a pipe whose reader stays open and stops reading blocks the
//! write that meets it full. Every thread says lines here — the loop, the
//! drain, and the shell's feed thread, whose resend says one every two seconds
//! while a held line is not taken — and a feed thread blocked so would hold
//! every `search` and `places`, the loop and `ping` behind them. So [`log`]
//! puts its line on a queue bounded in bytes and returns, and one thread,
//! `skep-mcp-log`, writes the lines to stderr in order, one write a line. A
//! line that meets a full queue is dropped and counted, and the gap is said
//! where it is, at the moment its first line was said: the next line the
//! queue takes follows one naming how many went, and a gap still open at the
//! exit is said by the drain. Where the OS refuses the thread, each line is
//! written where it is said. [`drain`] waits for the queue before the process
//! exits, for as long as the reader takes lines: one that has taken none for
//! `DRAIN_STALL` costs the exit the lines it left, never the exit.
//!
//! A panic is a line of it too ([`install_the_panic_hook`]).

use std::borrow::Cow;
use std::collections::VecDeque;
use std::fmt::{self, Display};
use std::io::Write;
use std::panic::Location;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock, PoisonError};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use skep_client::sheet::render_inert;

/// The most bytes the queue holds before a line is dropped.
///
/// A line's rendered text runs to `LINE_BYTES`, so lines vary in bytes from a
/// few dozen to some four thousand, and the bound is in bytes, not lines: a
/// reader that stopped costs the process this much and the line the writer
/// holds, no more. A line meeting an empty queue is taken whatever its size.
const QUEUE_BYTES: usize = 1024 * 1024;

/// The most bytes of rendered text one line carries past its prefix and time.
///
/// It is past every line the adapter composes — the usage a usage error says
/// is the longest, under three kilobytes — so it clips a board's text alone: a
/// refusal or a face whose text runs on, the rest named by its count. It
/// bounds the rendered text, so a control's eight-byte rendering does not
/// multiply it.
const LINE_BYTES: usize = 4096;

/// The words that open skep-client's quote of an answer it cannot parse.
///
/// The refusal reads `the answer was not JSON (<the parse error>): <the
/// answer>` (skep-client's `json_of`), the answer whole, up to the client's
/// answer cap: `logged` keeps the parse error, which names a line and a column
/// and no text, and cuts the rest of the line, since where the answer ends no
/// byte of it says.
const QUOTED_ANSWER: &str = "the answer was not JSON";

/// The longest the exit waits on a reader that takes no line.
const DRAIN_STALL: Duration = Duration::from_secs(2);

/// The writer thread's name, which a panic's line names it by.
const THREAD: &str = "skep-mcp-log";

/// The stream over the process's stderr, made at the first line.
static STDERR: OnceLock<Arc<Stream>> = OnceLock::new();

/// Writes one line of the log, stderr, as `logged` renders it.
///
/// The moment is read first, where the line is said; the line is queued,
/// never written here, so it neither fails, reports nor waits (the module
/// doc). The shell's `Talk` lines come through here too.
pub fn log(line: impl Display) {
    let at = SystemTime::now();
    STDERR.get_or_init(|| Stream::over(Box::new(std::io::stderr()))).say(at, &logged(at, line));
}

/// Waits for the lines said so far to reach stderr, before the process ends.
///
/// A gap still open is said first, at its first dropped line's moment. It
/// returns once each line is written, or once the reader has taken none for
/// `DRAIN_STALL`: a reader that stopped costs the lines, never the exit. A
/// process that has said no line waits for nothing.
pub fn drain() {
    if let Some(stream) = STDERR.get() {
        stream.drain(DRAIN_STALL);
    }
}

/// Installs the panic hook: a panic is one line of the log.
///
/// It is installed first, before the command line is read, so no thread of
/// the process panics outside it. The line is `panic_line`'s, prefixed and
/// inert as every line is, so Rust's own text — unprefixed, three lines —
/// never reaches stderr. A panic on `main`'s thread unwinds to the process's
/// end at exit 101, the shell's stop, where it is open, running in the unwind
/// (its `Drop`), so the hook drains the log there first and the panic's line
/// reaches stderr; a panic on another thread leaves the process running
/// without that thread, its line saying so, with the act: a restart.
pub fn install_the_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        let current = thread::current();
        let payload = info.payload().downcast_ref::<&'static str>().copied();
        log(panic_line(current.name(), info.location(), payload));
        if current.name() == Some("main") {
            drain();
        }
    }));
}

/// Returns the panic hook's line.
///
/// It names the thread by its name (`an unnamed thread` where it has none, as
/// the shell's are), the location as std spells it, and the payload only where
/// it is a `&'static str` — a literal the code wrote, which no answer can have
/// formatted — so a formatted panic (`expect`, an index, an `assert_eq!`)
/// shows its location alone, and no token or board's text rides the line, as
/// skepd's and skep-provision's hooks keep it; then the build it ran, so the
/// line is reported whole wherever the log was cut, and the act. A panic on
/// `main`'s thread ends the process; one on any other leaves it running
/// without that thread, so its act adds the restart, and what the thread's
/// loss leaves undone until then: stdin's reader reading no request, the
/// drain settling no death of the session, or the shell's own threads — its
/// feed, which `search`, `places`, the drafts' reads and the held bursts'
/// resend run on.
fn panic_line(thread: Option<&str>, location: Option<&Location<'_>>, payload: Option<&str>) -> String {
    let restart = match thread {
        Some("main") => "",
        _ => {
            ", and restart the adapter — it runs on without that thread, and what the thread did stays undone until a restart: stdin's reader reads no request, the drain settles no death of the session, and an unnamed thread is the shell's, its feed, search, places and held-burst resend among them"
        }
    };
    let thread = thread.map_or_else(|| "an unnamed thread".to_string(), |name| format!("the {name} thread"));
    let at = location.map_or_else(|| "an unknown location".to_string(), ToString::to_string);
    let payload = payload.map(|p| format!(": {p}")).unwrap_or_default();
    format!("{thread} panicked at {at}{payload} — a bug of skep-mcp's or its shell's, in skep-mcp {}: report this line{restart}", crate::build())
}

/// Returns `line` as the log carries it, said at `at`.
///
/// It opens `skep-mcp: ` and the moment, RFC 3339 UTC to the millisecond.
/// Every control `render_inert` disarms — the C0 controls, DEL and the bidi
/// controls (AUTH-5.2) — is shown as its code point, and every line it breaks
/// onto is indented two spaces, an empty one left empty. A board's text rides
/// many lines here — a refusal's code and detail, the `/health` claimant, a
/// block's record and ground, the shell's `Talk` of its feed and held threads
/// — and the log is read on a terminal, or kept and shown on one later, where
/// a control acts: ESC opens a sequence that retitles the window, moves the
/// cursor or writes the clipboard, CR overwrites the line. So no C0 control,
/// DEL or bidi control a board chose acts there, and no text it chose opens a
/// line of the log as `skep-mcp: `. A C1 control passes as it came, as
/// `render_inert` passes it. An answer skep-client quotes is cut at its parse
/// error (`unquoted_answer`), and the rendered text clipped at `LINE_BYTES`
/// (`clipped`), before the line reaches the queue (D9).
fn logged(at: SystemTime, line: impl Display) -> String {
    let text = line.to_string();
    let mut body = String::new();
    for (k, piece) in unquoted_answer(&text).split('\n').enumerate() {
        if k > 0 {
            body.push('\n');
            if !piece.is_empty() {
                body.push_str("  ");
            }
        }
        body.push_str(&render_inert(piece));
    }
    format!("skep-mcp: {} {}", Rfc3339(at), clipped(&body))
}

/// Returns `text` with the answer skep-client quotes cut, where it quotes one.
///
/// The quote opens `QUOTED_ANSWER` and its parse error in parentheses, then
/// `: ` and the answer whole; what follows the parse error's closing
/// parenthesis is cut, to the line's end, and named by its count. Where no
/// parse error follows, everything past `QUOTED_ANSWER` is cut.
fn unquoted_answer(text: &str) -> Cow<'_, str> {
    let Some(at) = text.find(QUOTED_ANSWER) else { return Cow::Borrowed(text) };
    let stem = at + QUOTED_ANSWER.len();
    // serde_json's messages hold no `): `, so the first closes the error.
    let kept = match text[stem..].strip_prefix(" (").and_then(|error| error.find("): ")) {
        Some(close) => stem + " (".len() + close + ")".len(),
        None => stem,
    };
    Cow::Owned(format!("{}: the answer's text and the rest of this line not shown ({} bytes)", &text[..kept], text.len() - kept))
}

/// Returns a line's rendered text clipped at `LINE_BYTES`, its rest counted.
fn clipped(body: &str) -> Cow<'_, str> {
    if body.len() <= LINE_BYTES {
        return Cow::Borrowed(body);
    }
    let mut end = LINE_BYTES;
    while !body.is_char_boundary(end) {
        end -= 1;
    }
    Cow::Owned(format!("{}… ({} bytes of this line not shown)", &body[..end], body.len() - end))
}

/// Returns the line that says a gap: how many lines the queue dropped.
///
/// It is said at `since`, the moment the first of them was said, so the gap's
/// window reads off its time and the next line's.
fn gap_line(since: SystemTime, dropped: u64) -> String {
    let lines = if dropped == 1 { "1 line of the log was".to_string() } else { format!("{dropped} lines of the log were") };
    logged(since, format_args!("{lines} dropped here, the first said at this line's time: its reader took none while they came"))
}

/// An instant as a line's time: RFC 3339, UTC, to the millisecond.
///
/// It reads `2026-10-06T22:31:04.512Z`. The millisecond is truncated, never
/// rounded, so the rendered moment is never after the instant and a second's
/// last millisecond never carries into the next second. The form spells the
/// years 0000 through 9999, and a clock outside them is a host's fault, not a
/// line's: an instant before the epoch renders as the epoch,
/// `1970-01-01T00:00:00.000Z`, and one past the year 9999 as that year's last
/// millisecond, so the line still carries a time, and one read as a clock gone
/// wrong. It is skep-util's `notice`'s, whose stream the daemon's lines carry,
/// so the two streams spell a moment alike.
struct Rfc3339(SystemTime);

/// The last second the form spells, `9999-12-31T23:59:59Z`.
///
/// It is 8,030 years from the epoch, 1,947 of them leap — the 2,007 fourth
/// years less the 60 century years no 400 divides — a second short of the
/// year 10000.
const LAST_SECOND: u64 = (8_030 * 365 + 1_947) * 86_400 - 1;

impl Display for Rfc3339 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let since = self.0.duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO);
        let (secs, millis) = if since.as_secs() > LAST_SECOND { (LAST_SECOND, 999) } else { (since.as_secs(), since.subsec_millis()) };
        let (year, month, day) = civil_from_days(secs / 86_400);
        let of_day = secs % 86_400;
        write!(f, "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{millis:03}Z", of_day / 3_600, of_day % 3_600 / 60, of_day % 60)
    }
}

/// Returns the civil date of a day counted from the epoch: year, month, day.
///
/// It counts from 0000-03-01, 719,468 days before the epoch, so that a year
/// runs March to February and its leap day, where it has one, is its last
/// day; and in eras of 400 years, 146,097 days, after which the Gregorian
/// calendar repeats exactly. Within an era the year is read off the day with
/// the century rule applied — a fourth year is leap unless it is a century
/// year no 400 divides — and the month off the day of that year by the
/// five-month cycle 31, 30, 31, 30, 31 that March opens. The unit suite holds
/// it to instants computed by hand.
fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let shifted = days + 719_468;
    let era = shifted / 146_097;
    let of_era = shifted - era * 146_097;
    let year_of_era = (of_era - of_era / 1_460 + of_era / 36_524 - of_era / 146_096) / 365;
    let of_year = of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_from_march = (5 * of_year + 2) / 153;
    let day = of_year - (153 * month_from_march + 2) / 5 + 1;
    let month = if month_from_march < 10 { month_from_march + 3 } else { month_from_march - 9 };
    let year = year_of_era + era * 400 + u64::from(month <= 2);
    (year, month, day)
}

/// The queue and the thread that writes it.
///
/// One stream runs over stderr for the process; the unit suite runs its own
/// over sinks of the test's.
struct Stream {
    state: Mutex<State>,
    /// Raised when a line is queued, for the writer.
    pending: Condvar,
    /// Raised when a line has been written, for [`Stream::drain`].
    written: Condvar,
}

/// What the stream's lock guards.
struct State {
    /// The lines queued, oldest first, each ending `\n`.
    lines: VecDeque<String>,
    /// The bytes `lines` holds, never past `QUEUE_BYTES` but for one line and
    /// a gap's line the drain says.
    bytes: usize,
    /// Lines queued since the stream began, and lines written: a drain waits
    /// for the second to reach the first as it stood at the call.
    queued: u64,
    taken: u64,
    /// Lines dropped since the last line the queue took.
    dropped: u64,
    /// The moment the first of them was said, while any stands dropped.
    dropped_since: Option<SystemTime>,
    /// Whether the writer runs; where it does not, a line is written where it
    /// is said.
    threaded: bool,
    /// The sink, until the writer takes it; the sayer's own where none runs.
    sink: Option<Box<dyn Write + Send>>,
}

impl State {
    /// Returns the gap's line, ended, where lines stand dropped; the count
    /// starts again.
    fn take_gap(&mut self) -> Option<String> {
        let since = self.dropped_since.take()?;
        let dropped = std::mem::take(&mut self.dropped);
        Some(format!("{}\n", gap_line(since, dropped)))
    }

    /// Queues `text`, one or more lines each ending `\n`, for the writer.
    fn push(&mut self, text: String) {
        self.bytes += text.len();
        self.lines.push_back(text);
        self.queued += 1;
    }
}

impl Stream {
    /// Returns a stream over `sink`, its writer spawned.
    ///
    /// Where the OS refuses the thread, the stream writes each line where it
    /// is said.
    fn over(sink: Box<dyn Write + Send>) -> Arc<Stream> {
        let stream = Stream::synchronous(sink);
        let writer = Arc::clone(&stream);
        if thread::Builder::new().name(THREAD.into()).spawn(move || writer.write_each_in_order()).is_ok() {
            stream.lock().threaded = true;
        }
        stream
    }

    /// Returns a stream with no writer: each line written where it is said.
    fn synchronous(sink: Box<dyn Write + Send>) -> Arc<Stream> {
        let state = State { lines: VecDeque::new(), bytes: 0, queued: 0, taken: 0, dropped: 0, dropped_since: None, threaded: false, sink: Some(sink) };
        Arc::new(Stream { state: Mutex::new(state), pending: Condvar::new(), written: Condvar::new() })
    }

    /// Locks the stream's state, poisoned or not.
    ///
    /// Nothing under the lock is left half-done by an unwind — a push, a pop,
    /// a count — and a line fails no work.
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Says one rendered line, said at `at`: queued, or dropped and counted.
    ///
    /// It never waits on the sink. A line meeting a full queue is dropped, and
    /// the first dropped notes its moment; a line the queue takes after a gap
    /// follows the gap's line (`gap_line`). Where no writer runs, the line is
    /// written here.
    fn say(&self, at: SystemTime, line: &str) {
        let mut st = self.lock();
        if !st.threaded {
            if let Some(sink) = st.sink.as_mut() {
                let _ = sink.write_all(format!("{line}\n").as_bytes());
            }
            return;
        }
        if !st.lines.is_empty() && st.bytes + line.len() + 1 > QUEUE_BYTES {
            st.dropped += 1;
            st.dropped_since.get_or_insert(at);
            return;
        }
        let mut text = st.take_gap().unwrap_or_default();
        text.push_str(line);
        text.push('\n');
        st.push(text);
        self.pending.notify_one();
    }

    /// Writes each queued line in order, for the writer's whole life.
    ///
    /// One write a line, its result discarded; the wait for the next costs
    /// nothing while nothing is said.
    fn write_each_in_order(&self) {
        let Some(mut sink) = self.lock().sink.take() else { return };
        loop {
            let text = {
                let mut st = self.lock();
                loop {
                    if let Some(text) = st.lines.pop_front() {
                        st.bytes -= text.len();
                        break text;
                    }
                    st = self.pending.wait(st).unwrap_or_else(PoisonError::into_inner);
                }
            };
            let _ = sink.write_all(text.as_bytes());
            let _ = sink.flush();
            self.lock().taken += 1;
            self.written.notify_all();
        }
    }

    /// Returns whether every line queued at the call has been written.
    ///
    /// A gap still open is queued first, past the queue's bound — one short
    /// line, so no gap ends the log unsaid. It waits until the lines are
    /// written, or until no line has been written for `stall` — the deadline
    /// moves only when one is — and answers at once where no writer runs.
    fn drain(&self, stall: Duration) -> bool {
        let mut st = self.lock();
        if st.threaded {
            if let Some(gap) = st.take_gap() {
                st.push(gap);
                self.pending.notify_one();
            }
        }
        let target = st.queued;
        let mut landed = st.taken;
        let mut deadline = Instant::now() + stall;
        while st.threaded && st.taken < target {
            if st.taken != landed {
                landed = st.taken;
                deadline = Instant::now() + stall;
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return false;
            }
            st = self.written.wait_timeout(st, left).unwrap_or_else(PoisonError::into_inner).0;
        }
        true
    }
}

#[cfg(test)]
mod tests;
