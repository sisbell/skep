//! The adapter's log: stderr, one line per notice, never waiting on a reader.
//!
//! Every line the adapter says goes through [`log`] — startup's lines, the
//! stops, the loop's own and the shell's TALK — so stdout stays the JSON-RPC
//! stream alone. A line is rendered by `logged`, and three rules travel with
//! its write, the ones skep-util's `notice` keeps for the daemon: it never
//! fails the work it reports on, never reports, and never waits.
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
//! line that meets a full queue is dropped and counted, and the next line the
//! queue takes follows one saying how many went, so a gap is said where it is.
//! Where the OS refuses the thread, each line is written where it is said.
//! [`drain`] waits for the queue before the process exits, for as long as the
//! reader takes lines: one that has taken none for `DRAIN_STALL` costs the
//! exit the lines it left, never the exit.
//!
//! A panic is a line of it too ([`install_the_panic_hook`]).

use std::collections::VecDeque;
use std::fmt::Display;
use std::io::Write;
use std::panic::Location;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use skep_client::sheet::render_inert;

/// The most bytes the queue holds before a line is dropped.
///
/// A line can carry a board's text — a refusal quoting an answer the client
/// could not read, up to skep-client's answer cap — so the bound is in bytes,
/// not lines: a reader that stopped costs the process this much and the line
/// the writer holds, no more. A line meeting an empty queue is taken whatever
/// its size.
const QUEUE_BYTES: usize = 1024 * 1024;

/// The longest the exit waits on a reader that takes no line.
const DRAIN_STALL: Duration = Duration::from_secs(2);

/// The writer thread's name, which a panic's line names it by.
const THREAD: &str = "skep-mcp-log";

/// The stream over the process's stderr, made at the first line.
static STDERR: OnceLock<Arc<Stream>> = OnceLock::new();

/// Writes one line of the log, stderr, as `logged` renders it.
///
/// The line is queued, never written here, so it neither fails, reports nor
/// waits (the module doc); the shell's `Talk` lines come through here too.
pub fn log(line: impl Display) {
    STDERR.get_or_init(|| Stream::over(Box::new(std::io::stderr()))).say(&logged(line));
}

/// Waits for the lines said so far to reach stderr, before the process ends.
///
/// It returns once each is written, or once the reader has taken none for
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
/// reaches stderr; a panic on another thread leaves the process serving.
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
/// skepd's and skep-provision's hooks keep it; then the act.
fn panic_line(thread: Option<&str>, location: Option<&Location<'_>>, payload: Option<&str>) -> String {
    let thread = thread.map_or_else(|| "an unnamed thread".to_string(), |name| format!("the {name} thread"));
    let at = location.map_or_else(|| "an unknown location".to_string(), ToString::to_string);
    let payload = payload.map(|p| format!(": {p}")).unwrap_or_default();
    format!("{thread} panicked at {at}{payload} — a bug of skep-mcp's or its shell's: report this line with the version line this run began with")
}

/// Returns `line` as the log carries it.
///
/// It is prefixed `skep-mcp: `; every control `render_inert` disarms — the
/// C0 controls, DEL and the bidi controls (AUTH-5.2) — is shown as its code
/// point; and every line it breaks onto is indented two spaces, an empty one
/// left empty. A board's text rides many lines here — a refusal's code and
/// detail, the `/health` claimant, a block's record and ground, the shell's
/// `Talk` of its feed and held threads — and the log is read on a terminal,
/// or kept and shown on one later, where a control acts: ESC opens a
/// sequence that retitles the window, moves the cursor or writes the
/// clipboard, CR overwrites the line. So no C0 control, DEL or bidi control
/// a board chose acts there, and no text it chose opens a line of the log as
/// `skep-mcp: `. A C1 control passes as it came, as `render_inert` passes
/// it.
fn logged(line: impl Display) -> String {
    let text = line.to_string();
    let mut out = String::from("skep-mcp: ");
    for (k, piece) in text.split('\n').enumerate() {
        if k > 0 {
            out.push('\n');
            if !piece.is_empty() {
                out.push_str("  ");
            }
        }
        out.push_str(&render_inert(piece));
    }
    out
}

/// Returns the line that says a gap: how many lines the queue dropped.
fn gap_line(dropped: u64) -> String {
    let lines = if dropped == 1 { "1 line of the log was".to_string() } else { format!("{dropped} lines of the log were") };
    logged(format_args!("{lines} dropped here: its reader took none while they came"))
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
    /// The bytes `lines` holds, never past `QUEUE_BYTES` but for one line.
    bytes: usize,
    /// Lines queued since the stream began, and lines written: a drain waits
    /// for the second to reach the first as it stood at the call.
    queued: u64,
    taken: u64,
    /// Lines dropped since the last line the queue took.
    dropped: u64,
    /// Whether the writer runs; where it does not, a line is written where it
    /// is said.
    threaded: bool,
    /// The sink, until the writer takes it; the sayer's own where none runs.
    sink: Option<Box<dyn Write + Send>>,
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
        let state = State { lines: VecDeque::new(), bytes: 0, queued: 0, taken: 0, dropped: 0, threaded: false, sink: Some(sink) };
        Arc::new(Stream { state: Mutex::new(state), pending: Condvar::new(), written: Condvar::new() })
    }

    /// Locks the stream's state, poisoned or not.
    ///
    /// Nothing under the lock is left half-done by an unwind — a push, a pop,
    /// a count — and a line fails no work.
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Says one rendered line: queued, or dropped and counted at a full queue.
    ///
    /// It never waits on the sink. A line the queue takes after a gap follows
    /// the gap's line (`gap_line`). Where no writer runs, the line is written
    /// here.
    fn say(&self, line: &str) {
        let mut st = self.lock();
        if !st.threaded {
            if let Some(sink) = st.sink.as_mut() {
                let _ = sink.write_all(format!("{line}\n").as_bytes());
            }
            return;
        }
        if !st.lines.is_empty() && st.bytes + line.len() + 1 > QUEUE_BYTES {
            st.dropped += 1;
            return;
        }
        let mut text = String::new();
        let dropped = std::mem::take(&mut st.dropped);
        if dropped > 0 {
            text.push_str(&gap_line(dropped));
            text.push('\n');
        }
        text.push_str(line);
        text.push('\n');
        st.bytes += text.len();
        st.lines.push_back(text);
        st.queued += 1;
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
    /// It waits until they have, or until no line has been written for
    /// `stall` — the deadline moves only when one is — and answers at once
    /// where no writer runs.
    fn drain(&self, stall: Duration) -> bool {
        let mut st = self.lock();
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
mod tests {
    use std::io;

    use super::*;

    /// A flag a thread raises once and another waits on.
    type Flag = Arc<(Mutex<bool>, Condvar)>;

    /// Returns a flag, lowered.
    fn flag() -> Flag {
        Arc::new((Mutex::new(false), Condvar::new()))
    }

    /// Raises `flag` and wakes its waiters.
    fn raise(flag: &Flag) {
        *flag.0.lock().expect("the flag's lock") = true;
        flag.1.notify_all();
    }

    /// Waits until `flag` is raised.
    fn wait_for(flag: &Flag) {
        let mut raised = flag.0.lock().expect("the flag's lock");
        while !*raised {
            raised = flag.1.wait(raised).expect("the flag's lock");
        }
    }

    /// A sink that takes nothing until its gate opens, then keeps each byte.
    ///
    /// `entered` is raised at its first write, so a test knows the writer
    /// holds a line in it.
    struct Gated {
        gate: Flag,
        entered: Flag,
        kept: Arc<Mutex<Vec<u8>>>,
    }

    impl Gated {
        /// Returns a gated sink, its gate closed.
        fn closed() -> Gated {
            Gated { gate: flag(), entered: flag(), kept: Arc::new(Mutex::new(Vec::new())) }
        }

        /// Returns the bytes the sink has taken, as text.
        fn text(kept: &Mutex<Vec<u8>>) -> String {
            String::from_utf8(kept.lock().expect("the kept lock").clone()).expect("UTF-8")
        }
    }

    impl Write for Gated {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            raise(&self.entered);
            wait_for(&self.gate);
            self.kept.lock().expect("the kept lock").extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// A log line is inert, and only its first line opens as the adapter's.
    ///
    /// A control a board's text carries — ESC opening a terminal sequence,
    /// BEL, CR, a bidi override — is shown as its code point, on any line; a
    /// line break it carries continues the line indented, so a forged
    /// `skep-mcp: ` opens no line; a face's own lines keep their order, each
    /// indented; an empty line stays empty; printable text passes as written.
    #[test]
    fn a_log_line_is_inert_and_opens_as_the_adapters_once() {
        assert_eq!(logged("claimant \u{1b}]0;owned\u{7}"), "skep-mcp: claimant <U+001B>]0;owned<U+0007>");
        assert_eq!(logged("x\r\u{202e}y"), "skep-mcp: x<U+000D><U+202E>y");
        assert_eq!(logged("a\nb\u{1b}c"), "skep-mcp: a\n  b<U+001B>c");
        assert_eq!(logged("the board refused: x\nskep-mcp: signed as principal 0"), "skep-mcp: the board refused: x\n  skep-mcp: signed as principal 0");
        assert_eq!(logged("no_key: s\n  cause: c\n  act: a"), "skep-mcp: no_key: s\n    cause: c\n    act: a");
        assert_eq!(logged("unknown argument 'x'\n\nusage: skep-mcp"), "skep-mcp: unknown argument 'x'\n\n  usage: skep-mcp");
        assert_eq!(logged("person seam: refuse — é"), "skep-mcp: person seam: refuse — é");
    }

    /// A line never waits on a reader that takes none, and a gap is said.
    ///
    /// The sink takes nothing until its gate opens, and the writer holds the
    /// first line in it, so the queue fills: every line is said at once all the
    /// same, those past the queue's bytes dropped and counted. Once the sink
    /// reads, the lines the queue kept arrive in order, none skipped, and the
    /// next line said follows the one naming how many went.
    #[test]
    fn a_line_never_waits_on_a_reader_that_takes_none_and_a_gap_is_said() {
        let sink = Gated::closed();
        let (gate, entered, kept) = (Arc::clone(&sink.gate), Arc::clone(&sink.entered), Arc::clone(&sink.kept));
        let stream = Stream::over(Box::new(sink));
        stream.say("0");
        wait_for(&entered);
        let filler = "x".repeat(1000);
        let said = 3 * QUEUE_BYTES / filler.len();
        let started = Instant::now();
        for k in 1..said {
            stream.say(&format!("{k} {filler}"));
        }
        assert!(started.elapsed() < Duration::from_secs(5), "no line waits on the reader: {:?}", started.elapsed());
        raise(&gate);
        assert!(stream.drain(Duration::from_secs(10)), "the lines kept reach the reader once it reads");
        stream.say("after the gap");
        assert!(stream.drain(Duration::from_secs(10)), "the next line too");
        let text = Gated::text(&kept);
        let lines: Vec<&str> = text.lines().collect();
        let (taken, said_after) = lines.split_at(lines.len() - 2);
        for (k, line) in taken.iter().enumerate() {
            let numbered = line.split(' ').next().and_then(|n| n.parse::<usize>().ok());
            assert_eq!(numbered, Some(k), "in order, none skipped: line {k} reads {line:.20}");
        }
        let dropped = said - taken.len();
        assert!(dropped > 0, "premise: the queue filled");
        assert_eq!(said_after, [gap_line(dropped as u64).as_str(), "after the gap"], "the gap said where it is");
    }

    /// The drain gives up on a reader that takes nothing, at its stall.
    #[test]
    fn the_drain_gives_up_on_a_reader_that_takes_none() {
        let sink = Gated::closed();
        let kept = Arc::clone(&sink.kept);
        let stream = Stream::over(Box::new(sink));
        stream.say("held at the reader");
        let started = Instant::now();
        assert!(!stream.drain(Duration::from_millis(200)), "a reader that takes nothing is given up on");
        assert!(started.elapsed() < Duration::from_secs(5), "at the stall: {:?}", started.elapsed());
        assert!(Gated::text(&kept).is_empty(), "premise: the reader took nothing");
    }

    /// Where no writer runs, a line is written where it is said.
    #[test]
    fn without_its_writer_a_line_is_written_where_it_is_said() {
        let sink = Gated::closed();
        let kept = Arc::clone(&sink.kept);
        raise(&sink.gate);
        let stream = Stream::synchronous(Box::new(sink));
        stream.say("one");
        assert_eq!(Gated::text(&kept), "one\n", "written in the call");
        assert!(stream.drain(Duration::ZERO), "nothing waits");
    }

    /// A panic's line names the thread and the site, a literal payload alone.
    ///
    /// A thread is named by its name, `an unnamed thread` where it has none; a
    /// `&'static str` payload rides the line, any other is left off; the line
    /// ends on the act, the version line to report it with.
    #[test]
    fn a_panics_line_names_the_thread_and_the_site_and_a_literal_payload_alone() {
        let at = Location::caller();
        let named = panic_line(Some("main"), Some(at), Some("the shell broke a promise"));
        assert!(named.starts_with(&format!("the main thread panicked at {at}: the shell broke a promise — ")), "{named}");
        let unnamed = panic_line(None, None, None);
        assert!(unnamed.starts_with("an unnamed thread panicked at an unknown location — "), "{unnamed}");
        assert!(unnamed.ends_with("report this line with the version line this run began with"), "{unnamed}");
    }
}
