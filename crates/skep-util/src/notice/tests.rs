use super::*;
use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::Instant;

/// A day in seconds.
const DAY: u64 = 86_400;
/// Days from the epoch to 2024-01-01: 54 whole years, 13 of them leap
/// (1972 through 2020, every fourth).
const DAYS_TO_2024: u64 = 54 * 365 + 13;
/// To 2026-01-01: 56 whole years, 14 leap (2024 joins).
const DAYS_TO_2026: u64 = 56 * 365 + 14;
/// To 2100-01-01: 130 whole years, 32 leap (1972 through 2096; 2000 among
/// them, a century year 400 divides).
const DAYS_TO_2100: u64 = 130 * 365 + 32;
/// To 10000-01-01: 8,030 whole years, 1,947 leap — the 2,007 fourth years
/// less the 60 century years no 400 divides.
const DAYS_TO_10000: u64 = 8_030 * 365 + 1_947;

/// The grammar's example instant, `2026-10-06T22:31:04.512Z`, by hand: the
/// days to 2026, January through September (273), the five days before
/// October's sixth, then the time of day.
fn example() -> SystemTime {
    let secs = (DAYS_TO_2026 + 273 + 5) * DAY + 22 * 3_600 + 31 * 60 + 4;
    UNIX_EPOCH + Duration::from_millis(secs * 1_000 + 512)
}

/// A sink the test owns. HELD, it takes no byte until released and says
/// when a write stands at it; released, it records every write.
#[derive(Default)]
struct Sink {
    inner: Mutex<SinkState>,
    changed: Condvar,
}

#[derive(Default)]
struct SinkState {
    released: bool,
    waiting: bool,
    bytes: Vec<u8>,
    writes: usize,
}

impl Sink {
    fn held() -> Arc<Sink> {
        Arc::new(Sink::default())
    }

    fn released() -> Arc<Sink> {
        let sink = Sink::held();
        sink.release();
        sink
    }

    fn release(&self) {
        self.inner.lock().unwrap().released = true;
        self.changed.notify_all();
    }

    fn text(&self) -> String {
        String::from_utf8(self.inner.lock().unwrap().bytes.clone()).unwrap()
    }

    fn writes(&self) -> usize {
        self.inner.lock().unwrap().writes
    }

    /// Until a write stands parked at the held sink.
    fn wait_until_a_write_waits(&self) {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut st = self.inner.lock().unwrap();
        while !st.waiting {
            let left = deadline.saturating_duration_since(Instant::now());
            assert!(!left.is_zero(), "no write reached the sink in 10 s");
            st = self.changed.wait_timeout(st, left).unwrap().0;
        }
    }

    /// Until the text taken satisfies `done`; the text then.
    fn wait_for(&self, done: impl Fn(&str) -> bool) -> String {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let text = self.text();
            if done(&text) {
                return text;
            }
            assert!(Instant::now() < deadline, "the sink never took what was waited for:\n{text}");
            thread::sleep(Duration::from_millis(5));
        }
    }
}

/// The stream's end of a [`Sink`].
struct Writer(Arc<Sink>);

impl Write for Writer {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut st = self.0.inner.lock().unwrap();
        st.waiting = true;
        self.0.changed.notify_all();
        while !st.released {
            st = self.0.changed.wait(st).unwrap();
        }
        st.waiting = false;
        st.bytes.extend_from_slice(buf);
        st.writes += 1;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// A sink whose every write FAILS, counting the attempts.
struct Failing(Arc<AtomicUsize>);

impl Write for Failing {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(io::Error::from(io::ErrorKind::BrokenPipe))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn stream_over(sink: &Arc<Sink>) -> Arc<Stream> {
    Stream::over(Box::new(Writer(Arc::clone(sink))))
}

/// The un-classed door's shape over `stream`, at the example instant.
fn say(stream: &Stream, what: &str) {
    stream.take(example(), &body(None, what, &[]));
}

/// `act` on a thread of its own, waited for `within`: an act that blocks
/// fails its test by name rather than wedging the suite.
fn returns_within(within: Duration, act: impl FnOnce() + Send + 'static) -> bool {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        act();
        let _ = tx.send(());
    });
    rx.recv_timeout(within).is_ok()
}

/// §1 THE HEAD BYTES: a line is the program's name, a colon and a space,
/// the time, the class word and a colon, the text and a newline —
/// `skepd: 2026-10-06T22:31:04.512Z landing: x\n` — and nothing else; the
/// un-classed door the same with no class word. Pinned as the bytes
/// themselves, never through `PROGRAM`, so a change to the prefix fails
/// here.
#[test]
fn a_line_is_the_program_name_the_time_the_class_the_text_and_a_newline() {
    assert_eq!(
        render(example(), 0, &body(Some(Class::Landing), "x", &[])),
        "skepd: 2026-10-06T22:31:04.512Z landing: x\n"
    );
    assert_eq!(
        render(example(), 0, &body(Some(Class::Warning(Moment::AtOpen)), "x", &[])),
        "skepd: 2026-10-06T22:31:04.512Z warning (at open): x\n"
    );
    assert_eq!(render(example(), 0, &body(None, "x", &[])), "skepd: 2026-10-06T22:31:04.512Z x\n");
}

/// §1 THE HEAD BYTES, a several-line notice: the head with the time, then
/// each line of the rest indented under the bare prefix — no time — one
/// newline at the end, and ONE write.
#[test]
fn lines_carry_the_prefix_on_every_line_the_time_on_the_head_alone_and_end_once() {
    let rest = ["one".to_string(), "two".to_string()];
    let whole = "skepd: 2026-10-06T22:31:04.512Z landing: head\nskepd:   one\nskepd:   two\n";
    assert_eq!(render(example(), 0, &body(Some(Class::Landing), "head", &rest)), whole);
    assert_eq!(
        render(example(), 0, &body(None, "head", &rest)),
        "skepd: 2026-10-06T22:31:04.512Z head\nskepd:   one\nskepd:   two\n"
    );
    let sink = Sink::released();
    let stream = stream_over(&sink);
    stream.take(example(), &body(Some(Class::Landing), "head", &rest));
    stream.drain();
    assert_eq!(sink.writes(), 1, "one notice, one write");
    assert_eq!(sink.text(), whole);
}

/// §1 THE CLASS WORDS: each of the six renders as the grammar spells it,
/// the warning's three moments included.
#[test]
fn each_class_word_renders_as_the_grammar_spells_it() {
    for (class, word) in [
        (Class::Failure, "failure"),
        (Class::Landing, "landing"),
        (Class::Open, "open"),
        (Class::Warning(Moment::AtStart), "warning (at start)"),
        (Class::Warning(Moment::AtClaim), "warning (at claim)"),
        (Class::Warning(Moment::AtOpen), "warning (at open)"),
        (Class::Standing, "standing"),
        (Class::Progress, "progress"),
    ] {
        assert_eq!(class.to_string(), word);
    }
}

/// §1 THE BOUND, THE DROP, THE COUNT, the bytes: the count rides after the
/// time and before the class word, in the design's words.
#[test]
fn the_count_of_dropped_lines_rides_after_the_time_and_before_the_class() {
    assert_eq!(
        render(example(), 3, &body(Some(Class::Landing), "x", &[])),
        "skepd: 2026-10-06T22:31:04.512Z (3 lines dropped) landing: x\n"
    );
    assert_eq!(
        render(example(), 1, &body(None, "x", &[])),
        "skepd: 2026-10-06T22:31:04.512Z (1 lines dropped) x\n"
    );
}

/// §1 THE CIVIL DATE: the epoch, a leap day, a day the century rule decides
/// (2100 is no leap year), the grammar's example and the last instant the
/// form spells — each instant computed by hand above, never by the code
/// under test — then the millisecond's truncation and the two ends.
#[test]
fn the_civil_date_holds_at_instants_computed_by_hand() {
    let at = |secs: u64, millis: u64| {
        Rfc3339(UNIX_EPOCH + Duration::from_millis(secs * 1_000 + millis)).to_string()
    };
    assert_eq!(at(0, 0), "1970-01-01T00:00:00.000Z");
    // The leap day's last millisecond: January's 31 days and February's 28
    // past the year's first day, then the day's last second.
    assert_eq!(at((DAYS_TO_2024 + 31 + 28) * DAY + DAY - 1, 999), "2024-02-29T23:59:59.999Z");
    // 2100 is a century year no 400 divides, so no leap day precedes its
    // March: a conversion that gave it one renders February 29th here.
    assert_eq!(at((DAYS_TO_2100 + 31 + 28) * DAY, 0), "2100-03-01T00:00:00.000Z");
    assert_eq!(
        at((DAYS_TO_2026 + 273 + 5) * DAY + 22 * 3_600 + 31 * 60 + 4, 512),
        "2026-10-06T22:31:04.512Z"
    );
    assert_eq!(at(DAYS_TO_10000 * DAY - 1, 999), "9999-12-31T23:59:59.999Z");
    // Truncated, never rounded: 999,999 microseconds is .999, not the next
    // second.
    assert_eq!(
        Rfc3339(UNIX_EPOCH + Duration::from_micros(999_999)).to_string(),
        "1970-01-01T00:00:00.999Z"
    );
    // Outside the form, the nearer end.
    assert_eq!(
        Rfc3339(UNIX_EPOCH - Duration::from_secs(1)).to_string(),
        "1970-01-01T00:00:00.000Z"
    );
    assert_eq!(at(DAYS_TO_10000 * DAY, 0), "9999-12-31T23:59:59.999Z");
}

/// §1 A FULL PIPE NEVER BLOCKS THE DOOR: with a sink that never takes a
/// byte, every shape of notice — one line, several, classed, un-classed —
/// returns, three times the queue's bound of them, in bounded time; the
/// sink has taken nothing. The write path's serialization guard is the
/// reason: a door that waited on the stream's reader would hold it.
#[test]
fn a_sink_that_never_takes_a_byte_blocks_no_door() {
    let sink = Sink::held();
    let stream = stream_over(&sink);
    let s = Arc::clone(&stream);
    let returned = returns_within(Duration::from_secs(10), move || {
        let more = [String::from("more")];
        for i in 0..3 * QUEUE_BOUND {
            let what = format!("line {i}");
            match i % 4 {
                0 => s.take(example(), &body(None, &what, &[])),
                1 => s.take(example(), &body(None, &what, &more)),
                2 => s.take(example(), &body(Some(Class::Landing), &what, &[])),
                _ => s.take(example(), &body(Some(Class::Failure), &what, &more)),
            }
        }
    });
    assert!(returned, "a door waited on a sink that never took a byte");
    assert_eq!(sink.writes(), 0, "the sink took nothing, and the doors returned anyway");
}

/// §1 THE BOUND, THE DROP, THE COUNT: with the sink holding the first line,
/// the queue takes 1,024 and drops the next three — each the one arriving,
/// never an older — and once the sink moves, the next line through carries
/// `(3 lines dropped)` and the line after it carries no count.
#[test]
fn the_bound_holds_the_newest_line_is_the_one_dropped_and_the_next_carries_the_count() {
    let sink = Sink::held();
    let stream = stream_over(&sink);
    say(&stream, "first");
    // "first" is off the queue and parked at the sink: the queue is empty.
    sink.wait_until_a_write_waits();
    for i in 0..QUEUE_BOUND {
        say(&stream, &format!("kept {i}"));
    }
    for i in 0..3 {
        say(&stream, &format!("dropped {i}"));
    }
    sink.release();
    stream.drain();
    say(&stream, "after");
    say(&stream, "last");
    stream.drain();
    let text = sink.text();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 1 + QUEUE_BOUND + 2, "{text}");
    assert_eq!(lines[0], "skepd: 2026-10-06T22:31:04.512Z first");
    for i in 0..QUEUE_BOUND {
        assert!(lines[1 + i].ends_with(&format!(" kept {i}")), "line {}: {}", 1 + i, lines[1 + i]);
    }
    assert!(!text.contains("dropped 0"), "the newest line is the one dropped, never an older");
    assert_eq!(lines[1 + QUEUE_BOUND], "skepd: 2026-10-06T22:31:04.512Z (3 lines dropped) after");
    assert_eq!(lines[2 + QUEUE_BOUND], "skepd: 2026-10-06T22:31:04.512Z last");
}

/// §1 DRAINED AT EXIT: the drain returns only after every line enqueued
/// before it has reached the sink — not while the sink holds them — and the
/// sink's bytes hold them all, in order; a stream with nothing waiting
/// returns at once, whatever its sink would do.
#[test]
fn drain_returns_after_every_line_before_it_landed_and_at_once_when_none_waits() {
    let sink = Sink::held();
    let stream = stream_over(&sink);
    for i in 0..10 {
        say(&stream, &format!("line {i}"));
    }
    let (tx, rx) = mpsc::channel();
    let s = Arc::clone(&stream);
    thread::spawn(move || {
        s.drain();
        let _ = tx.send(());
    });
    assert!(
        rx.recv_timeout(Duration::from_millis(300)).is_err(),
        "the drain returned while the sink held every line"
    );
    sink.release();
    assert!(
        rx.recv_timeout(Duration::from_secs(10)).is_ok(),
        "the drain did not return once the lines landed"
    );
    let text = sink.text();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 10, "{text}");
    for (i, line) in lines.iter().enumerate() {
        assert!(line.ends_with(&format!(" line {i}")), "in order: {line}");
    }
    let empty = stream_over(&Sink::held());
    assert!(
        returns_within(Duration::from_secs(5), move || empty.drain()),
        "nothing waits: at once"
    );
}

/// §1 A PARKED ENQUEUER's LINE LANDS: a thread puts one line on the queue
/// and parks for good; the line reaches the sink with no second line and
/// no drain — the drain thread writes each line as it comes, batching
/// nothing.
#[test]
fn a_thread_that_enqueues_one_line_and_parks_still_has_it_written() {
    let sink = Sink::released();
    let stream = stream_over(&sink);
    let s = Arc::clone(&stream);
    thread::spawn(move || {
        say(&s, "held here");
        loop {
            thread::park();
        }
    });
    let text = sink.wait_for(|text| text.contains("held here"));
    assert_eq!(text, "skepd: 2026-10-06T22:31:04.512Z held here\n");
}

/// THE OLD RULE STANDS: a sink whose every write fails leaves each door
/// returning normally, the drain returning, and the thread alive for the
/// next line — no panic, no error surfaces; with and without the thread.
#[test]
fn a_failing_write_fails_no_door_and_stops_no_later_line() {
    let attempts = Arc::new(AtomicUsize::new(0));
    let stream = Stream::over(Box::new(Failing(Arc::clone(&attempts))));
    let s = Arc::clone(&stream);
    let returned = returns_within(Duration::from_secs(10), move || {
        say(&s, "a");
        say(&s, "b");
        s.drain();
        say(&s, "c");
        s.drain();
    });
    assert!(returned, "a refused write held a door or the drain");
    assert_eq!(attempts.load(Ordering::SeqCst), 3, "every line offered, every refusal discarded");
    let attempts = Arc::new(AtomicUsize::new(0));
    let direct = Stream::synchronous(Box::new(Failing(Arc::clone(&attempts))));
    say(&direct, "a");
    direct.drain();
    assert_eq!(attempts.load(Ordering::SeqCst), 1);
}

/// THE FALLBACK: where no thread drains — the OS refused it — each door
/// writes for itself at the call, and the drain has nothing to wait for.
#[test]
fn where_no_thread_drains_each_door_writes_for_itself() {
    let sink = Sink::released();
    let stream = Stream::synchronous(Box::new(Writer(Arc::clone(&sink))));
    say(&stream, "now");
    assert_eq!(sink.text(), "skepd: 2026-10-06T22:31:04.512Z now\n", "written at the door");
    assert!(returns_within(Duration::from_secs(5), move || stream.drain()));
}

/// The process's own stream: the drain before any line starts nothing; the
/// four doors return; the drain after them returns with the queue empty and
/// every line written by the thread.
#[test]
fn the_four_doors_and_the_drain_return_over_the_process_stream() {
    drain();
    assert!(STREAM.get().is_none(), "a drain with no line through starts no stream");
    line("the un-classed door");
    lines("the un-classed door, several lines", &["one".to_string()]);
    emit(Class::Open, "the classed door");
    emit_lines(
        Class::Warning(Moment::AtStart),
        "the classed door, several lines",
        &["one".to_string()],
    );
    assert!(returns_within(Duration::from_secs(10), drain), "the process stream's drain");
    let stream = STREAM.get().expect("the first line made the stream");
    let st = stream.lock();
    assert!(st.queued, "the thread was spawned");
    assert!(st.queue.is_empty());
    assert_eq!(st.written, st.enqueued);
    assert!(st.written >= 4);
}
