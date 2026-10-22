//! The reads below the resident window: a feed file read by position.
//!
//! The change feed's five files are kept whole from genesis (wire.md §The
//! change feed, Retention; the daemon's memory for the feed is the resident
//! window alone, `limits::FEED_RESIDENT_WINDOW` positions), so a page whose
//! positions lie below the window, the head writer's resume below it, and
//! the open's derivation of a file's missing tail read the files themselves.
//! This module is the one read they share: a [`Cursor`] over one line file,
//! placed at the first line whose position lies above a fence by a binary
//! search over the file's bytes, and read forward from there a whole line
//! at a time.
//!
//! **The order the search rests on.** Every feed file is position-ordered:
//! `commits.log`'s entry lines are appended in position order under the
//! write path's serialization lock and its fence lines (`min_since`) stand
//! at or above every entry before them; the four derived files' records
//! are appended in position order and their fences (`covered`) likewise;
//! the attest store's lines are appended in `Seq` order and rebuilt in it.
//! So the position a line names — an entry's `at`, a fence's `covered` or
//! `min_since` ([`position_of`]) — never decreases down a file, and a line
//! whose position lies above `since` has every later line above it too.
//! Each file's open holds the order: trust ends at a line that lies below
//! the line before it, as it ends at a line that does not parse
//! (`sidecar.rs`, `derived.rs`), so no file this daemon serves breaks it.
//!
//! **The search** probes a byte, finds the first line beginning at or after
//! it, reads that line's position and halves the range: order log₂(the
//! file's bytes) probes, each one seek and one short read — some thirty
//! probes on a file of a few gigabytes — then one sequential read of the
//! lines the caller wants. A torn last line, or a line the search cannot
//! read a position from, is treated as lying above every `since`: the
//! cursor placed at it reads nothing, which is what a file cut at that line
//! at the next open would answer.
//!
//! **What it does not do.** It parses no line beyond its position: each
//! file's own reader parses the lines a cursor hands it — `commits.log`'s
//! entries (`sidecar.rs`), the derived records (`derived.rs`), the attest
//! store's slots (`attest.rs`) — so the file's one reader stays its one
//! reader. And it holds nothing resident: the cursor is a buffered handle
//! and the byte the next line begins at.

use std::fs::File;
use std::io::{self, BufRead, BufReader, Read, Seek, SeekFrom};
use std::path::Path;

use serde_json::Value;

/// A cursor over one feed file, read forward a whole line at a time.
///
/// It is placed by [`Cursor::open_above`] at the first line whose position
/// lies above a fence and advanced by [`Cursor::next_line`]; it ends at the
/// file's end, at a torn last line, or where the caller stops asking.
pub(super) struct Cursor {
    reader: BufReader<File>,
    /// The byte the next line begins at.
    next: u64,
    /// Whether the cursor met the file's end or a torn line.
    done: bool,
}

impl Cursor {
    /// Opens the file at `path` at the first line whose position is above `since`.
    ///
    /// The search is the module doc's: a binary search over the file's
    /// bytes by the position each line names ([`position_of`]), so the
    /// cursor answers in order log₂(the file) probes. A `since` at or above
    /// every line's position places the cursor at the file's end, where it
    /// reads nothing.
    ///
    /// # Errors
    ///
    /// The OS refused the open, a seek or a read.
    pub(super) fn open_above(path: &Path, since: u64) -> io::Result<Cursor> {
        let mut file = File::open(path)?;
        let len = file.metadata()?.len();
        // `lo` is always a line's start; `hi` bounds the answer from above.
        let (mut lo, mut hi) = (0u64, len);
        let mut answer = len;
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let start = if mid == lo { lo } else { line_start_at_or_after(&mut file, mid)? };
            if start >= hi {
                hi = mid;
                continue;
            }
            match read_line_at(&mut file, start)? {
                // A whole line at or below the fence: the answer lies past it.
                Some((line, end)) if position_of(&line).is_some_and(|p| p <= since) => lo = end,
                // A line above the fence, or one no position reads from — a
                // torn last line among them: the answer is here or before.
                _ => {
                    answer = start;
                    hi = mid;
                }
            }
        }
        let mut reader = BufReader::with_capacity(64 * 1024, file);
        reader.seek(SeekFrom::Start(answer))?;
        Ok(Cursor { reader, next: answer, done: answer >= len })
    }

    /// Returns the byte the cursor stands at: where its next line begins.
    ///
    /// Fresh from [`Cursor::open_above`] it is the byte the first line above
    /// the fence begins at, or the file's length — the byte a file cut back
    /// to that fence ends at (`LineFile::cut_back_to`).
    pub(super) fn offset(&self) -> u64 {
        self.next
    }

    /// Returns the whole line that ends just before `offset`, without its newline.
    ///
    /// It is the line whose newline is the byte before `offset`: what a file
    /// cut at `offset` ends with, and so its coverage after the cut. `None`
    /// at `offset` zero, or where no newline stands at the byte before it.
    ///
    /// # Errors
    ///
    /// The OS refused the open, a seek or a read.
    pub(super) fn line_before(path: &Path, offset: u64) -> io::Result<Option<Vec<u8>>> {
        if offset == 0 {
            return Ok(None);
        }
        let mut file = File::open(path)?;
        // The bytes before `offset`, read backwards a chunk at a time until
        // the previous newline, or the file's start, is in hand.
        let mut held: Vec<u8> = Vec::new();
        let mut from = offset;
        let start = loop {
            let chunk = from.min(64 * 1024);
            if chunk == 0 {
                break 0;
            }
            from -= chunk;
            file.seek(SeekFrom::Start(from))?;
            let mut buf = vec![0u8; chunk as usize];
            file.read_exact(&mut buf)?;
            buf.extend_from_slice(&held);
            held = buf;
            // The last byte is `offset - 1`, the line's own newline; the
            // newline before it, if any, ends the line before.
            if held.last() != Some(&b'\n') {
                return Ok(None);
            }
            let body = &held[..held.len() - 1];
            if let Some(nl) = body.iter().rposition(|&b| b == b'\n') {
                break from + nl as u64 + 1;
            }
        };
        let skip = (start - from) as usize;
        let line = held[skip..held.len() - 1].to_vec();
        Ok(Some(line))
    }

    /// Returns the next whole line, without its newline, and the byte it begins at.
    ///
    /// `None` at the file's end, and at a torn last line — one ended by no
    /// newline — after which the cursor answers `None` for good.
    ///
    /// # Errors
    ///
    /// The OS refused the read.
    pub(super) fn next_line(&mut self) -> io::Result<Option<(u64, Vec<u8>)>> {
        if self.done {
            return Ok(None);
        }
        let mut line = Vec::new();
        let read = self.reader.read_until(b'\n', &mut line)?;
        if read == 0 || !line.ends_with(b"\n") {
            self.done = true;
            return Ok(None);
        }
        let offset = self.next;
        self.next += read as u64;
        line.pop();
        Ok(Some((offset, line)))
    }
}

/// Returns the position a line names for the order the files keep.
///
/// It is an entry's `at`, or a fence's `covered` (the derived files and the
/// attest store) or `min_since` (`commits.log`, which also reads the older
/// spelling `floor`); `None` for a line that is not a JSON object naming
/// one, which the search treats as lying above every fence.
pub(super) fn position_of(line: &[u8]) -> Option<u64> {
    let v: Value = serde_json::from_slice(line).ok()?;
    let m = v.as_object()?;
    ["at", "covered", "min_since", "floor"].iter().find_map(|key| m.get(*key)?.as_u64())
}

/// Returns the byte the first line beginning at or after `at` starts at.
///
/// It is the byte after the first newline at or after `at − 1`, so a line
/// that begins exactly at `at` is found as itself; the file's length where
/// no newline follows.
///
/// # Errors
///
/// The OS refused the seek or the read.
fn line_start_at_or_after(file: &mut File, at: u64) -> io::Result<u64> {
    debug_assert!(at > 0, "the first line begins at byte 0 and is never searched for");
    file.seek(SeekFrom::Start(at - 1))?;
    let (read, whole) = {
        let mut reader = BufReader::new(&mut *file);
        let mut skipped = Vec::new();
        let read = reader.read_until(b'\n', &mut skipped)?;
        (read, skipped.ends_with(b"\n"))
    };
    if whole {
        Ok(at - 1 + read as u64)
    } else {
        Ok(file.metadata()?.len())
    }
}

/// Returns the whole line beginning at `start` and the byte after it.
///
/// `None` where the line is torn — ended by no newline — or nothing stands
/// at `start`.
///
/// # Errors
///
/// The OS refused the seek or the read.
fn read_line_at(file: &mut File, start: u64) -> io::Result<Option<(Vec<u8>, u64)>> {
    file.seek(SeekFrom::Start(start))?;
    let mut reader = BufReader::new(&mut *file);
    let mut line = Vec::new();
    let read = reader.read_until(b'\n', &mut line)?;
    if read == 0 || !line.ends_with(b"\n") {
        return Ok(None);
    }
    line.pop();
    Ok(Some((line, start + read as u64)))
}

#[cfg(test)]
mod tests;
