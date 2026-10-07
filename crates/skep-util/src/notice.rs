//! The operator's stream — the ONE place the daemon's crates write to
//! stderr.
//!
//! Two rules travel with a notice, and neither is a caller's to remember:
//!
//! * the `skepd: ` prefix, so every line on a shared stream is attributable
//!   — the program's name, spelled once here as `PROGRAM`; the crate root's
//!   doc says why a library spells it;
//! * `writeln!` with the result DISCARDED, never `eprintln!`, which PANICS
//!   when the stderr write fails. A daemon whose log pipe has lost its reader
//!   would otherwise fail the work the notice is ABOUT — and every notice
//!   the daemon writes is about work that has already succeeded. The
//!   commit-metadata append (`CommitsLog::record`, in `write_path::sidecar`) runs
//!   between a commit and its ack, which is owed whatever the file does; the
//!   derived appends beside it are the same trade one layer down. The sharper
//!   cell is the credential write sequence's, which writes the claim-flip
//!   warnings and the list re-install AFTER the claim has committed, holding
//!   the credential write lock and the serialization lock: an unwind there is
//!   caught and answered `500 internal_panic` for a one-time-only write that
//!   landed, whose retry then meets `already_claimed` and never learns its
//!   position.
//!
//! So a notice never fails and never reports. A caller wanting the condition
//! back holds it already.

use std::fmt::Display;
use std::io::Write;

/// The program every notice names — spelled once. The crate root's doc
/// states why a library holds it: one program writes the operator's stream,
/// and the media crate runs inside it.
const PROGRAM: &str = "skepd";

/// One notice line — anything the daemon can render: `format_args!` where
/// the text must be built, and a `String`, a `&str` or a value whose own
/// `Display` IS the notice (a startup `Warning`, a `NotANodePrefix`)
/// directly, with no formatting ceremony to route it through.
pub fn line(what: impl Display) {
    write_line(&mut std::io::stderr(), what);
}

/// One notice spanning several lines: `head`, then each of `rest` indented
/// beneath it, every line carrying the prefix.
///
/// Written as ONE `writeln!` because a line per write lets another thread's
/// notice land inside this one, and a notice a reader cannot tell the extent
/// of is worse than a long line.
pub fn lines(head: impl Display, rest: &[String]) {
    write_lines(&mut std::io::stderr(), head, rest);
}

/// [`line()`]'s bytes onto `out` — the stream in production, a buffer under
/// test — the result discarded for the reason the module doc gives.
fn write_line(out: &mut impl Write, what: impl Display) {
    let _ = writeln!(out, "{PROGRAM}: {what}");
}

/// [`lines()`]'s bytes onto `out`, built whole and written once.
fn write_lines(out: &mut impl Write, head: impl Display, rest: &[String]) {
    let mut text = format!("{PROGRAM}: {head}");
    for line in rest {
        text.push('\n');
        text.push_str(PROGRAM);
        text.push_str(":   ");
        text.push_str(line);
    }
    let _ = writeln!(out, "{text}");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// THE LOG BYTES: a line is the program's name, a colon and a space, the
    /// text and a newline — `skepd: x\n` — and nothing else. Pinned as the
    /// bytes themselves, never through `PROGRAM`, so a change to the prefix
    /// fails here.
    #[test]
    fn a_line_is_the_program_name_a_colon_the_text_and_a_newline() {
        let mut out = Vec::new();
        write_line(&mut out, "x");
        assert_eq!(out, b"skepd: x\n");
    }

    /// A several-line notice: the head, then each line of the rest indented
    /// under the same prefix, one newline at the end — one write.
    #[test]
    fn lines_carry_the_prefix_on_every_line_and_end_once() {
        let mut out = Vec::new();
        write_lines(&mut out, "head", &["one".to_string(), "two".to_string()]);
        assert_eq!(out, b"skepd: head\nskepd:   one\nskepd:   two\n");
    }
}
