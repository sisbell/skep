//! The operator's stream — the ONE place this crate writes to stderr.
//!
//! Two rules travel with a notice, and neither is a caller's to remember:
//!
//! * the `skepd: ` prefix, so every line on a shared stream is attributable;
//! * `writeln!` with the result DISCARDED, never `eprintln!`, which PANICS
//!   when the stderr write fails. A daemon whose log pipe has lost its reader
//!   would otherwise fail the work the notice is ABOUT — and every notice
//!   this crate writes is about work that has already succeeded. The
//!   commit-metadata append ([`crate::sidecar::CommitsLog::record`]) runs
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

use std::io::Write;

/// One notice line.
pub(crate) fn line(args: std::fmt::Arguments<'_>) {
    let _ = writeln!(std::io::stderr(), "skepd: {args}");
}

/// One notice spanning several lines: `head`, then each of `rest` indented
/// beneath it, every line carrying the prefix.
///
/// Written as ONE `writeln!` because a line per write lets another thread's
/// notice land inside this one, and an entry a reader cannot tell the extent
/// of is worse than a long line.
pub(crate) fn block(head: std::fmt::Arguments<'_>, rest: &[String]) {
    let mut entry = format!("skepd: {head}");
    for line in rest {
        entry.push_str("\nskepd:   ");
        entry.push_str(line);
    }
    let _ = writeln!(std::io::stderr(), "{entry}");
}
