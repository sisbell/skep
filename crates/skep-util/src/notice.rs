//! The operator's stream — the ONE place the daemon's crates write to
//! stderr.
//!
//! Three things travel with a notice, and none is a caller's to remember:
//!
//! * the `skepd: ` prefix, so every line on a shared stream is attributable
//!   — the program's name, spelled once here as `PROGRAM`; the crate root's
//!   doc says why a library spells it;
//! * the time, on the head line of every notice — RFC 3339 UTC to the
//!   millisecond, `skepd: 2026-10-06T22:31:04.512Z landing: …` — read from
//!   the system clock at the door and rendered by a civil-date conversion of
//!   this module's own, so a stream carries its own moments wherever it is
//!   captured, and the crate takes no clock crate for them;
//! * the write, which NEVER FAILS the work the notice is about and NEVER
//!   WAITS on it.
//!
//! NEVER FAILS: the result of every write is DISCARDED, never `eprintln!`,
//! which PANICS when the stderr write fails. A daemon whose log pipe has
//! lost its reader would otherwise fail the work the notice is ABOUT — and
//! every notice the daemon writes is about work that has already succeeded.
//! The commit-metadata append (`CommitsLog::record`, in `write_path::sidecar`)
//! runs between a commit and its ack, which is owed whatever the file does;
//! the derived appends beside it are the same trade one layer down. The
//! sharper cell is the credential write sequence's, which writes the
//! claim-flip warnings and the list re-install AFTER the claim has committed,
//! holding the credential write lock and the serialization lock: an unwind
//! there is caught and answered `500 internal_panic` for a one-time-only
//! write that landed, whose retry then meets `already_claimed` and never
//! learns its position.
//!
//! NEVER WAITS: a notice that never failed its work could still WAIT on it.
//! A write to a full pipe blocks until the pipe's reader drains it, and the
//! write path's lines — the sidecar's appends, the attest line, the head
//! writer's — are written under its serialization guard, so a log reader
//! that stalled stalled the board's writes behind it. So no door writes.
//! Each renders its line, puts it on a bounded in-process queue and returns;
//! one thread of the daemon's own, `skepd-notice`, takes the lines off in
//! order and writes each notice to stderr as ONE write. The queue holds
//! `QUEUE_BOUND` lines; a line that arrives at a full queue is DROPPED —
//! that one, the newest, never an older — and counted, and the next line
//! that goes through carries `({n} lines dropped)` after its time, so a gap
//! on the stream is said on the stream. The thread is spawned at the first
//! line, so an in-process daemon under a suite and the shipped binary are
//! served alike; where the OS refuses it, every door writes for itself,
//! under the lock, as every notice once did. The queue is drained before
//! `main` exits through [`drain`]. The alternative, `O_NONBLOCK` on fd 2, is
//! refused: the flag sits on the open file description a parent shell or
//! supervisor shares, and `write_all` on a `WouldBlock` leaves a TORN line.
//!
//! So a notice never fails, never reports and never waits. A caller wanting
//! the condition back holds it already.

use std::collections::VecDeque;
use std::fmt::{self, Display, Write as _};
use std::io::Write;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// The program every notice names — spelled once. The crate root's doc
/// states why a library holds it: one program writes the operator's stream,
/// and the media crate runs inside it.
const PROGRAM: &str = "skepd";

/// The drain thread's name, as `ps` and a panic message show it.
const THREAD: &str = "skepd-notice";

/// The most lines the queue holds while the drain thread is behind its
/// sink: a line that arrives when this many wait is dropped — the arriving
/// one, never an older — and counted, and the next line taken carries the
/// count after its time. A line is 100–300 bytes, so the queue holds at most
/// some 300 KB; the open writes ten to twenty lines in a burst and a landing
/// one to three, so the bound is many bursts, and reaching it means the
/// stream's reader has stood still, not that the daemon has said too much.
const QUEUE_BOUND: usize = 1_024;

/// The class word every line of the grammar opens with, after the prefix
/// and the time — `failure:`, `landing:`, `open:`, `warning (at …):`,
/// `standing:`, `progress:` — spelled here so every site spells it one way,
/// and taken by [`emit`] and [`emit_lines`] as a value of this type so that
/// no site can omit it: a line with no class does not compile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Class {
    /// An act that failed: the act, the thing by path or position, the cause,
    /// the act that clears it and what still serves — said once per
    /// condition, never per request.
    Failure,
    /// A checkpoint, a pruner's pass, a compaction: the figures that moved,
    /// the act's duration among them.
    Landing,
    /// The open's report: a setting in force with its source, the recovery's
    /// base, the directory, the limits, the warnings, the mode.
    Open,
    /// A configuration whose consequence the operator may not intend: the
    /// setting, the consequence and the act that changes it — at the moment
    /// the daemon read it.
    Warning(Moment),
    /// The daemon-owned periodic line that re-says each standing bad state
    /// while it stands.
    Standing,
    /// The walk thread's cadence line while a lost or torn log is re-covered
    /// behind the listener.
    Progress,
}

/// When a warning's setting was read, as its class word spells it —
/// `warning (at start):`. Four moments, closed, so a site names one rather
/// than spelling a label.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Moment {
    /// Before the listener serves.
    AtStart,
    /// At the claim flip.
    AtClaim,
    /// Inside the open, before anything is served.
    AtOpen,
    /// At a reissue of the blocked-prefix list — a replaced supply file
    /// installed while the daemon runs.
    AtReissue,
}

/// The class word as a line spells it: the word alone, the colon the line's.
impl Display for Class {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Class::Failure => f.write_str("failure"),
            Class::Landing => f.write_str("landing"),
            Class::Open => f.write_str("open"),
            Class::Warning(moment) => write!(f, "warning ({moment})"),
            Class::Standing => f.write_str("standing"),
            Class::Progress => f.write_str("progress"),
        }
    }
}

/// The moment as the warning's class word spells it.
impl Display for Moment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Moment::AtStart => "at start",
            Moment::AtClaim => "at claim",
            Moment::AtOpen => "at open",
            Moment::AtReissue => "at reissue",
        })
    }
}

/// One classed notice line — `skepd: {time} {class}: {what}` — where `what`
/// is anything the daemon can render: `format_args!` where the text must be
/// built, and a `String`, a `&str` or a value whose own `Display` IS the
/// notice (a startup `Warning`, a `NotANodePrefix`) directly, with no
/// formatting ceremony to route it through. Rendered now and written by the
/// drain thread: the call returns at once, whatever the stream's reader is
/// doing.
pub fn emit(class: Class, what: impl Display) {
    submit(Some(class), what, &[]);
}

/// One classed notice spanning several lines: `head` after the class word,
/// then each of `rest` indented beneath it, every line carrying the prefix
/// and the head alone the time.
///
/// Written as ONE write because a line per write lets another thread's
/// notice land inside this one, and a notice a reader cannot tell the extent
/// of is worse than a long line.
pub fn emit_lines(class: Class, head: impl Display, rest: &[String]) {
    submit(Some(class), head, rest);
}

/// The un-classed door: [`emit`] with no class word — `skepd: {time} {what}`.
/// Kept for the call sites written before the class existed, each of which
/// moves to [`emit`] with the lane that re-cuts its line; the last of those
/// lanes removes this door. Through the queue, and timed, as [`emit`] is.
pub fn line(what: impl Display) {
    submit(None, what, &[]);
}

/// The un-classed door for a notice of several lines: [`emit_lines`] with no
/// class word, the time on the head alone. Kept, and retired, as [`line()`] is.
pub fn lines(head: impl Display, rest: &[String]) {
    submit(None, head, rest);
}

/// Wait until every line enqueued before this call has reached the sink —
/// the binary's call at each of its exits after the open, because
/// `std::process::exit` and a returning `main` both end the process without
/// the drain thread's leave. Returns at once when nothing waits, and without
/// starting the stream when no line ever went through it. A line another
/// thread enqueues after this call is not waited for: the drain is of what
/// stood at the call, and a thread still running past it is its caller's
/// concern. A sink that never takes the bytes holds the call, as it held
/// every synchronous write before.
pub fn drain() {
    if let Some(stream) = STREAM.get() {
        stream.drain();
    }
}

/// The stream every door goes through, over stderr — made at the first
/// line, the thread spawned then.
static STREAM: OnceLock<Arc<Stream>> = OnceLock::new();

/// The one path behind the four doors: the moment read, the body rendered —
/// the caller's `Display` runs here, outside the lock, so a slow formatter
/// delays no other thread's line — and the line handed to the stream.
fn submit(class: Option<Class>, head: impl Display, rest: &[String]) {
    let at = SystemTime::now();
    let body = body(class, head, rest);
    STREAM.get_or_init(|| Stream::over(Box::new(std::io::stderr()))).take(at, &body);
}

/// A notice's body: the class word and its colon where there is one, the
/// head, each line of `rest` on its own line under the prefix — `skepd:   `,
/// no time — and one newline at the end. A `Display` that fails leaves the
/// text where it failed; the notice fails nothing.
fn body(class: Option<Class>, head: impl Display, rest: &[String]) -> String {
    let mut text = String::new();
    if let Some(class) = class {
        let _ = write!(text, "{class}: ");
    }
    let _ = write!(text, "{head}");
    for line in rest {
        text.push('\n');
        text.push_str(PROGRAM);
        text.push_str(":   ");
        text.push_str(line);
    }
    text.push('\n');
    text
}

/// The line as the drain thread writes it: the prefix, the time, the count
/// of lines dropped before it where there were any — `({n} lines dropped)`,
/// after the time and before the class word, so the class word still opens
/// the sentence and a pattern on it still matches — and the body.
fn render(at: SystemTime, dropped: u64, body: &str) -> String {
    let mut text = format!("{PROGRAM}: {}", Rfc3339(at));
    if dropped > 0 {
        let _ = write!(text, " ({dropped} lines dropped)");
    }
    text.push(' ');
    text.push_str(body);
    text
}

/// The queue and the thread that drains it — one over stderr for the
/// process, and one over a sink of the test's own in the unit suite.
struct Stream {
    state: Mutex<State>,
    /// Woken when a line is put on the queue, for the drain thread.
    pending: Condvar,
    /// Woken when a line has reached the sink, for [`Stream::drain`].
    landed: Condvar,
}

struct State {
    /// The rendered lines, oldest first; never past [`QUEUE_BOUND`].
    queue: VecDeque<String>,
    /// Lines put on the queue since the stream began, and lines the thread
    /// has written: a drain waits for the second to reach the first as it
    /// stood at the call.
    enqueued: u64,
    written: u64,
    /// Lines dropped since the last line that carried the count.
    dropped: u64,
    /// Whether a thread drains the queue. Where none does, the doors write
    /// to `sink` themselves, under the lock — the fallback when the OS
    /// refused the thread.
    queued: bool,
    /// The sink, until the drain thread takes it; the doors' own where no
    /// thread drains.
    sink: Option<Box<dyn Write + Send>>,
}

impl Stream {
    /// A stream over `sink`, its thread spawned; where the OS refuses the
    /// thread, the stream writes synchronously.
    fn over(sink: Box<dyn Write + Send>) -> Arc<Stream> {
        let stream = Stream::synchronous(sink);
        let worker = Arc::clone(&stream);
        let spawned = std::thread::Builder::new()
            .name(THREAD.into())
            .spawn(move || worker.write_each_in_order());
        if spawned.is_ok() {
            stream.lock().queued = true;
        }
        stream
    }

    /// A stream with no thread: every door writes to `sink` for itself.
    fn synchronous(sink: Box<dyn Write + Send>) -> Arc<Stream> {
        Arc::new(Stream {
            state: Mutex::new(State {
                queue: VecDeque::new(),
                enqueued: 0,
                written: 0,
                dropped: 0,
                queued: false,
                sink: Some(sink),
            }),
            pending: Condvar::new(),
            landed: Condvar::new(),
        })
    }

    /// The lock, poisoned or not: nothing under it is left half-done by an
    /// unwind — a push, a pop, a count — and a notice fails no work.
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// One notice, rendered at `at`: queued, or dropped and counted when the
    /// queue is full — never a wait on the sink. Where no thread drains, it
    /// is written here.
    fn take(&self, at: SystemTime, body: &str) {
        let mut st = self.lock();
        if st.queued && st.queue.len() >= QUEUE_BOUND {
            st.dropped += 1;
            return;
        }
        let dropped = std::mem::take(&mut st.dropped);
        let text = render(at, dropped, body);
        if st.queued {
            st.queue.push_back(text);
            st.enqueued += 1;
            self.pending.notify_one();
        } else if let Some(sink) = st.sink.as_mut() {
            let _ = sink.write_all(text.as_bytes());
        }
    }

    /// The drain thread's whole life: each line off the queue in order, one
    /// write per notice, the result discarded, the landing counted — and
    /// the wait for the next, which costs nothing while nothing is said.
    fn write_each_in_order(&self) {
        let Some(mut sink) = self.lock().sink.take() else {
            return;
        };
        loop {
            let text = {
                let mut st = self.lock();
                loop {
                    if let Some(text) = st.queue.pop_front() {
                        break text;
                    }
                    st = self.pending.wait(st).unwrap_or_else(|poisoned| poisoned.into_inner());
                }
            };
            let _ = sink.write_all(text.as_bytes());
            self.lock().written += 1;
            self.landed.notify_all();
        }
    }

    /// [`drain()`]'s wait: until every line enqueued at the call has been
    /// written; at once where none waits, or where the doors write for
    /// themselves.
    fn drain(&self) {
        let mut st = self.lock();
        let target = st.enqueued;
        while st.queued && st.written < target {
            st = self.landed.wait(st).unwrap_or_else(|poisoned| poisoned.into_inner());
        }
    }
}

/// An instant as the head line spells it: RFC 3339, UTC, to the millisecond
/// — `2026-10-06T22:31:04.512Z`. The millisecond is TRUNCATED, never
/// rounded, so the rendered moment is never after the instant and a
/// second's last millisecond never carries into the next second. The form
/// spells the years 0000 through 9999, and a clock outside them is a host's
/// fault, not a line's: an instant before the epoch renders AS the epoch,
/// `1970-01-01T00:00:00.000Z`, and one past the year 9999 as that year's
/// last millisecond, so the line still carries a time, and one an operator
/// reads as a clock gone wrong.
struct Rfc3339(SystemTime);

/// The last second the form spells, `9999-12-31T23:59:59Z`: 8,030 years from
/// the epoch, 1,947 of them leap — the 2,007 fourth years less the 60
/// century years no 400 divides — a second short of the year 10000.
const LAST_SECOND: u64 = (8_030 * 365 + 1_947) * 86_400 - 1;

impl Display for Rfc3339 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let since = self.0.duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO);
        let (secs, millis) = if since.as_secs() > LAST_SECOND {
            (LAST_SECOND, 999)
        } else {
            (since.as_secs(), since.subsec_millis())
        };
        let (year, month, day) = civil_from_days(secs / 86_400);
        let of_day = secs % 86_400;
        write!(
            f,
            "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{millis:03}Z",
            of_day / 3_600,
            of_day % 3_600 / 60,
            of_day % 60
        )
    }
}

/// Days since the epoch to the civil date — the hand-written conversion the
/// stream's time rests on. Counted from 0000-03-01, 719,468 days before the
/// epoch, so that a year runs March to February and its leap day, where it
/// has one, is its LAST day; and in eras of 400 years, 146,097 days, after
/// which the Gregorian calendar repeats exactly. Within an era the year is
/// read off the day with the century rule applied — a fourth year is leap
/// unless it is a century year no 400 divides — and the month off the day
/// of that year by the five-month cycle 31, 30, 31, 30, 31 that March opens.
/// The unit suite holds it to instants computed by hand.
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

#[cfg(test)]
mod tests;
