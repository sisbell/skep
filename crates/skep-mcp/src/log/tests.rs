use std::io::{self, Read};

use serde_json::json;
use skep_client::dial::{Headers, RequestHead, StreamedResponse};
use skep_client::{Board, DialError, Dialer, Origin, Request, Response};

use super::*;

/// A line's opening at the epoch: the prefix and the moment.
const EPOCH: &str = "skep-mcp: 1970-01-01T00:00:00.000Z ";

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

/// Returns the moment `k` milliseconds past the epoch: line `k`'s, below.
fn at(k: usize) -> SystemTime {
    UNIX_EPOCH + Duration::from_millis(k as u64)
}

/// A stream whose reader takes nothing, its queue said past its bound.
///
/// The writer holds line `0` in the gated sink, so lines `1` on fill the
/// queue, those past its bytes dropped and counted, each said at its own
/// millisecond. Returns the stream, the gate, what the sink keeps, and how
/// many lines were said.
fn filled() -> (Arc<Stream>, Flag, Arc<Mutex<Vec<u8>>>, usize) {
    let sink = Gated::closed();
    let (gate, entered, kept) = (Arc::clone(&sink.gate), Arc::clone(&sink.entered), Arc::clone(&sink.kept));
    let stream = Stream::over(Box::new(sink));
    stream.say(at(0), "0");
    wait_for(&entered);
    let filler = "x".repeat(1000);
    let said = 3 * QUEUE_BYTES / filler.len();
    let started = Instant::now();
    for k in 1..said {
        stream.say(at(k), &format!("{k} {filler}"));
    }
    assert!(started.elapsed() < Duration::from_secs(5), "no line waits on the reader: {:?}", started.elapsed());
    (stream, gate, kept, said)
}

/// Returns the lines the sink took, the kept ones checked in order.
///
/// The last `after` lines are what followed the kept ones; every line before
/// them reads its own number, none skipped. Returns those lines and how many
/// the queue dropped.
fn kept_in_order(kept: &Mutex<Vec<u8>>, said: usize, after: usize) -> (Vec<String>, usize) {
    let text = Gated::text(kept);
    let lines: Vec<&str> = text.lines().collect();
    let (taken, following) = lines.split_at(lines.len() - after);
    for (k, line) in taken.iter().enumerate() {
        let numbered = line.split(' ').next().and_then(|n| n.parse::<usize>().ok());
        assert_eq!(numbered, Some(k), "in order, none skipped: line {k} reads {line:.20}");
    }
    assert!(said > taken.len(), "premise: the queue filled");
    (following.iter().map(ToString::to_string).collect(), taken.len())
}

/// A dialer whose every answer is a `200` carrying its body whole.
struct Answering(&'static str);

impl Dialer for Answering {
    fn exchange(&self, _: &Origin, _: &Request) -> Result<Response, DialError> {
        Ok(Response { status: 200, headers: Headers::default(), body: self.0.as_bytes().to_vec() })
    }

    fn stream(&self, _: &Origin, _: &RequestHead, _: &mut dyn Read, _: &mut dyn FnMut(&Headers)) -> Result<StreamedResponse, DialError> {
        Err(DialError::Connect("no stream here".into()))
    }
}

/// A log line is inert, and only its first line opens as the adapter's.
///
/// A control a board's text carries — ESC opening a terminal sequence,
/// BEL, CR, a bidi override — is shown as its code point, on any line; a
/// line break it carries continues the line indented, so a forged
/// `skep-mcp: ` opens no line; a face's own lines keep their order, each
/// indented; an empty line stays empty; printable text passes as written; the
/// moment opens the first line alone.
#[test]
fn a_log_line_is_inert_and_opens_as_the_adapters_once() {
    let at_epoch = |line: &str| logged(UNIX_EPOCH, line);
    assert_eq!(at_epoch("claimant \u{1b}]0;owned\u{7}"), format!("{EPOCH}claimant <U+001B>]0;owned<U+0007>"));
    assert_eq!(at_epoch("x\r\u{202e}y"), format!("{EPOCH}x<U+000D><U+202E>y"));
    assert_eq!(at_epoch("a\nb\u{1b}c"), format!("{EPOCH}a\n  b<U+001B>c"));
    assert_eq!(at_epoch("the board refused: x\nskep-mcp: signed as principal 0"), format!("{EPOCH}the board refused: x\n  skep-mcp: signed as principal 0"));
    assert_eq!(at_epoch("no_key: s\n  cause: c\n  act: a"), format!("{EPOCH}no_key: s\n    cause: c\n    act: a"));
    assert_eq!(at_epoch("unknown argument 'x'\n\nusage: skep-mcp"), format!("{EPOCH}unknown argument 'x'\n\n  usage: skep-mcp"));
    assert_eq!(at_epoch("person seam: refuse — é"), format!("{EPOCH}person seam: refuse — é"));
}

/// An answer skep-client quotes reaches the log cut at its parse error.
///
/// The client's own refusal of a `200` it cannot parse — a document's text
/// a stand-in dialer answers, cut short — said in a feed line as the shell
/// says it: the parse error stays, naming a line and a column, and the
/// answer's text goes, to the line's end, its bytes counted; a quote with no
/// parse error after it is cut whole; a line that quotes nothing is as it
/// came (D9).
#[test]
fn an_answer_the_client_quotes_reaches_the_log_cut_at_its_parse_error() {
    const ANSWER: &str = r#"{"resp":"delivery","items":[{"content":"a draft's private sentence"#;
    let board = Board::new(Origin::parse("http://127.0.0.1:1").expect("a canonical origin"), Answering(ANSWER));
    let halt = board.guest(&json!({"op": "retrieve_v", "specs": []})).expect_err("an answer the client cannot parse");
    let said = logged(UNIX_EPOCH, format_args!("feed b-1: the poll at 7 failed: {halt}"));
    assert!(!said.contains("a draft's private sentence"), "the document's text reaches the log: {said}");
    let error = said.split("the answer was not JSON (").nth(1).and_then(|rest| rest.split_once("): ")).map(|(error, _)| error).expect("the parse error kept");
    assert!(error.contains(" at line 1 column "), "the parse error names its line and column: {said}");
    assert!(said.ends_with(&format!("): the answer's text and the rest of this line not shown ({} bytes)", ": ".len() + ANSWER.len())), "{said}");
    let bare = logged(UNIX_EPOCH, "x: the answer was not JSON: {\"session\":\"t\"}\n  more");
    assert_eq!(bare, format!("{EPOCH}x: the answer was not JSON: the answer's text and the rest of this line not shown (24 bytes)"));
    assert_eq!(logged(UNIX_EPOCH, "the answer arrived whole"), format!("{EPOCH}the answer arrived whole"));
}

/// No line runs past `LINE_BYTES` of rendered text, its rest counted.
///
/// A line at the bound passes whole; one past it is cut at a character's
/// boundary and says how many bytes went; and the bound holds on the rendered
/// text, so controls, each rendered as eight bytes, cannot multiply it.
#[test]
fn no_line_runs_past_its_bound_of_rendered_text() {
    let body = |line: String| line.strip_prefix(EPOCH).expect("the line's opening").to_string();
    assert_eq!(body(logged(UNIX_EPOCH, "x".repeat(LINE_BYTES))), "x".repeat(LINE_BYTES), "a line at the bound passes whole");
    assert_eq!(body(logged(UNIX_EPOCH, "x".repeat(3 * LINE_BYTES))), format!("{}… ({} bytes of this line not shown)", "x".repeat(LINE_BYTES), 2 * LINE_BYTES));
    let euros = body(logged(UNIX_EPOCH, "€".repeat(2_000)));
    let kept = LINE_BYTES / 3 * 3;
    assert_eq!(euros, format!("{}… ({} bytes of this line not shown)", "€".repeat(kept / 3), 6_000 - kept), "cut at a character's boundary");
    let controls = body(logged(UNIX_EPOCH, "\u{1b}".repeat(1_000)));
    assert!(controls.ends_with(&format!("… ({} bytes of this line not shown)", 8 * 1_000 - LINE_BYTES)), "the rendered text is bounded: {controls:.60}");
}

/// The civil date holds at instants computed by hand.
///
/// The epoch, a leap day, a day the century rule decides (2100 is no leap
/// year), the example instant and the last instant the form spells — each
/// computed by hand above, never by the code under test — then the
/// millisecond's truncation and the two ends; and a line opens on the moment
/// it was said.
#[test]
fn the_civil_date_holds_at_instants_computed_by_hand() {
    let at = |secs: u64, millis: u64| Rfc3339(UNIX_EPOCH + Duration::from_millis(secs * 1_000 + millis)).to_string();
    assert_eq!(at(0, 0), "1970-01-01T00:00:00.000Z");
    // The leap day's last millisecond: January's 31 days and February's 28
    // past the year's first day, then the day's last second.
    assert_eq!(at((DAYS_TO_2024 + 31 + 28) * DAY + DAY - 1, 999), "2024-02-29T23:59:59.999Z");
    // 2100 is a century year no 400 divides, so no leap day precedes its
    // March: a conversion that gave it one renders February 29th here.
    assert_eq!(at((DAYS_TO_2100 + 31 + 28) * DAY, 0), "2100-03-01T00:00:00.000Z");
    // The days to 2026, January through September (273), the five days
    // before October's sixth, then the time of day.
    let example = (DAYS_TO_2026 + 273 + 5) * DAY + 22 * 3_600 + 31 * 60 + 4;
    assert_eq!(at(example, 512), "2026-10-06T22:31:04.512Z");
    assert_eq!(at(DAYS_TO_10000 * DAY - 1, 999), "9999-12-31T23:59:59.999Z");
    // Truncated, never rounded: 999,999 microseconds is .999, not the next
    // second.
    assert_eq!(Rfc3339(UNIX_EPOCH + Duration::from_micros(999_999)).to_string(), "1970-01-01T00:00:00.999Z");
    // Outside the form, the nearer end.
    assert_eq!(Rfc3339(UNIX_EPOCH - Duration::from_secs(1)).to_string(), "1970-01-01T00:00:00.000Z");
    assert_eq!(at(DAYS_TO_10000 * DAY, 0), "9999-12-31T23:59:59.999Z");
    let said = UNIX_EPOCH + Duration::from_millis(example * 1_000 + 512);
    assert_eq!(logged(said, "the board restarted"), "skep-mcp: 2026-10-06T22:31:04.512Z the board restarted");
}

/// A line never waits on a reader that takes none, and a gap is said.
///
/// The sink takes nothing until its gate opens, and the writer holds the
/// first line in it, so the queue fills: every line is said at once all the
/// same, those past the queue's bytes dropped and counted. Once the sink
/// reads, the lines the queue kept arrive in order, none skipped, and the next
/// line said follows the one naming how many went, at the moment the first of
/// them was said.
#[test]
fn a_line_never_waits_on_a_reader_that_takes_none_and_a_gap_is_said() {
    let (stream, gate, kept, said) = filled();
    raise(&gate);
    let deadline = Instant::now() + Duration::from_secs(10);
    while !stream.lock().lines.is_empty() {
        assert!(Instant::now() < deadline, "the lines kept reach the reader once it reads");
        thread::sleep(Duration::from_millis(1));
    }
    stream.say(at(said), "after the gap");
    assert!(stream.drain(Duration::from_secs(10)), "the next line too");
    let (following, taken) = kept_in_order(&kept, said, 2);
    assert_eq!(following, [gap_line(at(taken), (said - taken) as u64), "after the gap".to_string()], "the gap said where it is");
}

/// A gap still open at the exit is said by the drain.
///
/// The queue filled past its bound, the reader reads, and no line is said
/// after: the drain says the gap, past the bound, as the last line the reader
/// takes — at the moment its first line was said, naming how many went.
#[test]
fn a_gap_still_open_at_the_exit_is_said_by_the_drain() {
    let (stream, gate, kept, said) = filled();
    raise(&gate);
    assert!(stream.drain(Duration::from_secs(10)), "the lines kept, and the gap, reach the reader");
    let (following, taken) = kept_in_order(&kept, said, 1);
    assert_eq!(following, [gap_line(at(taken), (said - taken) as u64)], "the gap, last");
}

/// The drain gives up on a reader that takes nothing, at its stall.
#[test]
fn the_drain_gives_up_on_a_reader_that_takes_none() {
    let sink = Gated::closed();
    let kept = Arc::clone(&sink.kept);
    let stream = Stream::over(Box::new(sink));
    stream.say(UNIX_EPOCH, "held at the reader");
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
    stream.say(UNIX_EPOCH, "one");
    assert_eq!(Gated::text(&kept), "one\n", "written in the call");
    assert!(stream.drain(Duration::ZERO), "nothing waits");
}

/// A panic's line names the thread and the site, a literal payload alone.
///
/// A thread is named by its name, `an unnamed thread` where it has none; a
/// `&'static str` payload rides the line, any other is left off; the line
/// names the build it ran, and ends on the act: a report where the panic ends
/// the process — `main`'s — and where it leaves the process running without
/// the thread — any other's, the adapter's own named ones among them — the
/// restart too, with what stays undone until it.
#[test]
fn a_panics_line_names_the_thread_and_the_site_and_a_literal_payload_alone() {
    let at = Location::caller();
    let named = panic_line(Some("main"), Some(at), Some("the shell broke a promise"));
    assert!(named.starts_with(&format!("the main thread panicked at {at}: the shell broke a promise — ")), "{named}");
    assert!(named.ends_with("report this line"), "main's panic ends the process, its act the report: {named}");
    let unnamed = panic_line(None, None, None);
    assert!(unnamed.starts_with("an unnamed thread panicked at an unknown location — "), "{unnamed}");
    assert!(unnamed.contains(&format!(", in skep-mcp {}: report this line, and restart the adapter — ", crate::build())), "the build it ran, and the restart: {unnamed}");
    assert!(unnamed.ends_with("its feed, search, places and held-burst resend among them"), "what stays undone until the restart: {unnamed}");
    let drain = panic_line(Some("skep-mcp-drain"), None, None);
    assert!(drain.starts_with("the skep-mcp-drain thread panicked at ") && drain.contains("restart the adapter"), "{drain}");
}
