//! THE SINK SETTER over the process's own stream — this file's binary, a
//! process no daemon runs in and no other test says a line in, so the sink
//! is installed before the stream's first line, as an embedding program
//! installs its own: the line `emit` says reaches the sink, prefixed, timed
//! and classed as the stream writes every line; and a second install is
//! refused, the stream unchanged, every later line still reaching the
//! first sink.

use std::io::{self, Write};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use skep_util::notice::{self, Class, StreamAlreadyMade};

/// The drain's bound: far past any write the kept sink makes, which takes
/// every line at once.
const PATIENCE: Duration = Duration::from_secs(10);

/// A sink the test reads back: every byte written to it, kept in order.
#[derive(Clone, Default)]
struct Kept(Arc<Mutex<Vec<u8>>>);

impl Kept {
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).expect("the stream writes text")
    }
}

impl Write for Kept {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// The sink this process installed, at the first call — before any line —
/// with the install's answer asserted there. Both tests take it, so neither
/// depends on the other: a runner that gives each test a process of its own
/// installs it in each, and one that runs them as threads of one process
/// installs it once.
fn the_first_sink() -> &'static Kept {
    static FIRST: OnceLock<Kept> = OnceLock::new();
    FIRST.get_or_init(|| {
        let kept = Kept::default();
        assert_eq!(
            notice::set_sink(Box::new(kept.clone())),
            Ok(()),
            "the first install, before any line, makes the stream over its sink"
        );
        kept
    })
}

/// The one line of `text` that ends with `said`, which the test said once.
fn the_line_saying<'t>(text: &'t str, said: &str) -> &'t str {
    let mut lines = text.lines().filter(|line| line.ends_with(said));
    let line = lines.next().unwrap_or_else(|| panic!("no line says {said:?}:\n{text}"));
    assert!(lines.next().is_none(), "one line says {said:?}:\n{text}");
    line
}

/// THE SINK TAKES THE LINES: a sink installed before the first line receives
/// the line `emit` says once `drain` returns, as the stream writes every
/// line — the program's name, the time to the millisecond in RFC 3339 UTC,
/// the class word and its colon, the text, one newline — and not on the
/// process's stderr, which no assertion here can read and none needs to.
#[test]
fn a_sink_installed_before_the_first_line_takes_it_prefixed_timed_and_classed() {
    let sink = the_first_sink();
    notice::emit(Class::Landing, "the embedder's own sink took this line");
    assert_eq!(notice::drain(PATIENCE), Ok(()), "the kept sink takes every line");
    let text = sink.text();
    let line = the_line_saying(&text, " landing: the embedder's own sink took this line");
    assert!(text.contains(&format!("{line}\n")), "the line ends with its newline:\n{text}");
    let time =
        line.strip_prefix("skepd: ").unwrap_or_else(|| panic!("the prefix opens the line: {line}"));
    let time = &time[..time.find(' ').expect("a space after the time")];
    let shape: String = time.chars().map(|c| if c.is_ascii_digit() { '9' } else { c }).collect();
    assert_eq!(
        shape, "9999-99-99T99:99:99.999Z",
        "the time is RFC 3339 UTC to the millisecond: {line}"
    );
}

/// A SECOND INSTALL IS REFUSED AND CHANGES NOTHING: after the first sink,
/// another answers `StreamAlreadyMade`; the line said after it reaches the
/// first sink, and the refused one takes no byte.
#[test]
fn a_second_sink_is_refused_and_the_lines_still_reach_the_first() {
    let first = the_first_sink();
    let refused = Kept::default();
    assert_eq!(
        notice::set_sink(Box::new(refused.clone())),
        Err(StreamAlreadyMade),
        "the stream is made: a later sink is refused"
    );
    notice::emit(Class::Failure, "said after a refused install");
    assert_eq!(notice::drain(PATIENCE), Ok(()), "the kept sink takes every line");
    let text = first.text();
    the_line_saying(&text, " failure: said after a refused install");
    assert_eq!(refused.text(), "", "the refused sink took no byte");
}
