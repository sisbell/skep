//! The four DERIVED sidecars (PUB-7.19) — line files beside `commits.log`,
//! each a projection of that file and the journal, appended AT COMMIT
//! outside the journal transaction, replayed at open, tail-checked against
//! the head, and rebuilt whole only on whole-file loss (PUB-7.21):
//!
//! | file                | record                              | twin (`feed/mod.rs`)              |
//! |---------------------|-------------------------------------|-----------------------------------|
//! | `feed-index.log`    | `{"at":N,"docs":["…"]}`             | the per-document POSITION INDEX   |
//! | `feed-offsets.log`  | `{"at":N,"offset":O}`               | the position → OFFSET array       |
//! | `feed-masked.log`   | `{"at":N}`                          | the MASKED-POSITION BITMAP        |
//! | `feed-streams.log`  | `{"at":N,"owners":["…"]}`           | the PER-OWNER DRAFT-POSITION STREAMS |
//!
//! plus, in every file, the COVERAGE FENCE `{"covered":N}`: every position
//! at or below `N` has been processed into this file — the record it has
//! for a position that contributed nothing being exactly no record.
//!
//! One shape, one discipline, shared with `commits.log` (`sidecar.rs`):
//!
//! * a line is a JSON object built through the codec's key-sorting device,
//!   newline-terminated; trust ends at the first line that is torn or does
//!   not parse, and the file is truncated there at open;
//! * a record above the journal's head, or a fence above it, describes a
//!   different journal (an operator swapped files under the sidecar) and is
//!   dropped — and the file rewritten without it, so a journal that later
//!   grows past the number cannot resurrect it;
//! * COVERAGE is `max(fence, highest record) ≤ head`. A position above it is
//!   one this file has NOT processed — its contribution is re-derived by the
//!   feed's open from `commits.log` (a recorded position) or the journal (a
//!   bare one) and appended, then a fence at the head closes the check. A
//!   position at or below coverage with no record contributed nothing.
//!   This is what makes a lost tail SILENT INCOMPLETENESS the check closes,
//!   never a wrong answer: an entry the index does not list is one no
//!   narrowing can reach and the published walk still serves; a masked
//!   position the bitmap does not hold is walked and MASKED AT RENDER
//!   (PUB-7.20 — the bitmap is a skip accelerator, never the authority);
//!   a stream a position is missing from is a supplement short by it.
//! * appends are flushed to the OS, not fsynced (the trade `commits.log`
//!   makes: testimony never doubles a write's fsync); a rewrite goes to
//!   `<file>.compact` and is renamed over the original — whole old file or
//!   whole new one, never half of either.
//!
//! Loss unmasks nothing: no derived file is consulted for WHAT an entry
//! says (that is `commits.log`'s) or for WHETHER a class may see it (that
//! is the read predicate's, re-applied per rendered entry); they decide
//! only WHICH positions are candidates, and a candidate the mask refuses is
//! omitted whatever put it forward.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use serde_json::{Map, Value};

use crate::codec::obj;
use crate::sidecar::line_bytes;

/// The per-document position index's file.
pub(crate) const INDEX_FILE: &str = "feed-index.log";
/// The position → offset array's file.
pub(crate) const OFFSETS_FILE: &str = "feed-offsets.log";
/// The masked-position bitmap's file.
pub(crate) const MASKED_FILE: &str = "feed-masked.log";
/// The per-owner draft-position streams' file.
pub(crate) const STREAMS_FILE: &str = "feed-streams.log";

/// One replayed line.
enum Line {
    /// `{"covered":N}` — every position ≤ N is processed.
    Fence(u64),
    /// A record for position `at`, with its whole object (the feed reads the
    /// per-file fields off it).
    Record(u64, Map<String, Value>),
}

/// One derived sidecar: its append handle and its coverage.
pub(crate) struct DerivedFile {
    file: File,
    dir: PathBuf,
    name: &'static str,
    coverage: u64,
}

/// The records a derived file replays: `(position, the line's object)`,
/// in file order.
pub(crate) type Records = Vec<(u64, Map<String, Value>)>;

impl DerivedFile {
    /// Replay `name` in `dir`: truncate a torn tail, drop what describes
    /// another journal (rewriting the file without it), and hand back the
    /// records at or below `head` with the file's coverage.
    pub fn open(dir: &Path, name: &'static str, head: u64) -> io::Result<(DerivedFile, Records)> {
        let path = dir.join(name);
        let mut file = OpenOptions::new().create(true).read(true).append(true).open(&path)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        let (lines, valid_end) = parse_lines(&bytes);
        if valid_end < bytes.len() {
            file.set_len(valid_end as u64)?;
        }
        let mut coverage = 0u64;
        let mut records = Vec::new();
        let mut foreign = false;
        for line in lines {
            match line {
                Line::Fence(n) if n <= head => coverage = coverage.max(n),
                Line::Record(at, m) if at <= head => {
                    coverage = coverage.max(at);
                    records.push((at, m));
                }
                Line::Fence(_) | Line::Record(..) => foreign = true,
            }
        }
        let mut this = DerivedFile { file, dir: dir.to_path_buf(), name, coverage };
        if foreign {
            // Purge what is not this journal's, once, so it cannot come back.
            let lines = records
                .iter()
                .map(|(at, m)| record_line(*at, m.iter().map(|(k, v)| (k.clone(), v.clone()))))
                .collect();
            this.rewrite(lines, coverage)?;
        }
        Ok((this, records))
    }

    /// Every position at or below this is processed into the file.
    pub fn coverage(&self) -> u64 {
        self.coverage
    }

    /// Append one record for `at` with the file's own fields. The `at` key
    /// is added here, so a record cannot omit it.
    pub fn append(&mut self, at: u64, fields: Vec<(&'static str, Value)>) -> io::Result<()> {
        let mut pairs = fields;
        pairs.push(("at", Value::Number(at.into())));
        self.file.write_all(&line_bytes(obj(pairs)))?;
        self.coverage = self.coverage.max(at);
        Ok(())
    }

    /// Append the coverage fence `{"covered":N}` — a no-op when the file
    /// already covers `covered`.
    pub fn fence(&mut self, covered: u64) -> io::Result<()> {
        if covered <= self.coverage {
            return Ok(());
        }
        self.file.write_all(&fence_line(covered))?;
        self.coverage = covered;
        Ok(())
    }

    /// Rewrite the whole file as `lines` behind a fence at `covered`, through
    /// a temp file renamed over the original (compaction, and the purge of a
    /// foreign fence). `lines` are whole record objects already carrying
    /// their `at`.
    pub fn rewrite(&mut self, lines: Vec<Value>, covered: u64) -> io::Result<()> {
        let path = self.dir.join(self.name);
        let tmp = self.dir.join(format!("{}.compact", self.name));
        let mut out = Vec::new();
        for line in lines {
            out.extend_from_slice(&line_bytes(line));
        }
        out.extend_from_slice(&fence_line(covered));
        let mut f = File::create(&tmp)?;
        f.write_all(&out)?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, &path)?;
        self.file = OpenOptions::new().create(true).read(true).append(true).open(&path)?;
        self.coverage = covered;
        Ok(())
    }
}

/// A record object for `at` from its fields — the shape [`DerivedFile::append`]
/// writes, for a rewrite to reproduce.
pub(crate) fn record_line(at: u64, fields: impl IntoIterator<Item = (String, Value)>) -> Value {
    // Sorted by key — the codec's own device for `&'static str` keys, done
    // here for owned ones — so a rewritten line is byte-identical to an
    // appended one whatever backs serde_json's map.
    let mut sorted: std::collections::BTreeMap<String, Value> = fields.into_iter().collect();
    sorted.insert("at".to_string(), Value::Number(at.into()));
    let mut m = Map::new();
    for (k, v) in sorted {
        m.insert(k, v);
    }
    Value::Object(m)
}

fn fence_line(covered: u64) -> Vec<u8> {
    line_bytes(obj(vec![("covered", Value::Number(covered.into()))]))
}

/// Whole newline-terminated lines; trust ends at the first that is torn or
/// does not parse. Returns the lines and the byte offset after the last
/// whole one.
fn parse_lines(bytes: &[u8]) -> (Vec<Line>, usize) {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < bytes.len() {
        let Some(nl) = bytes[pos..].iter().position(|&b| b == b'\n') else { break };
        match parse_line(&bytes[pos..pos + nl]) {
            Some(line) => out.push(line),
            None => break,
        }
        pos += nl + 1;
    }
    (out, pos)
}

/// One line: a fence, or a record with a position. Anything else is torn.
fn parse_line(line: &[u8]) -> Option<Line> {
    let v: Value = serde_json::from_slice(line).ok()?;
    let Value::Object(m) = v else { return None };
    if let Some(c) = m.get("covered") {
        return Some(Line::Fence(c.as_u64()?));
    }
    let at = m.get("at")?.as_u64()?;
    Some(Line::Record(at, m))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A file replays to exactly what was appended, torn tails end trust,
    /// and coverage is the fence-or-record maximum.
    #[test]
    fn records_and_fences_replay_and_coverage_follows_them() {
        let dir = tempfile::tempdir().expect("tempdir");
        let head = 20;
        {
            let (mut f, replayed) = DerivedFile::open(dir.path(), MASKED_FILE, head).expect("open");
            assert!(replayed.is_empty());
            assert_eq!(f.coverage(), 0);
            f.append(3, vec![]).expect("append");
            f.append(7, vec![("docs", Value::Array(vec![Value::String("1.0.2.0.2".into())]))])
                .expect("append");
            f.fence(9).expect("fence");
            assert_eq!(f.coverage(), 9);
            f.fence(5).expect("a fence below coverage is a no-op");
            assert_eq!(f.coverage(), 9);
        }
        let path = dir.path().join(MASKED_FILE);
        let contents = std::fs::read_to_string(&path).expect("read");
        assert_eq!(
            contents,
            "{\"at\":3}\n{\"at\":7,\"docs\":[\"1.0.2.0.2\"]}\n{\"covered\":9}\n",
            "lines are key-sorted and newline-terminated"
        );
        // A torn tail: truncated at open, coverage unaffected by it.
        std::fs::write(&path, format!("{contents}{{\"at\":11,\"do")).expect("tear");
        let (f, replayed) = DerivedFile::open(dir.path(), MASKED_FILE, head).expect("reopen");
        assert_eq!(replayed.iter().map(|(at, _)| *at).collect::<Vec<_>>(), vec![3, 7]);
        assert_eq!(f.coverage(), 9);
        assert_eq!(std::fs::read_to_string(&path).expect("read"), contents, "the tail is cut");
        drop(f);
        // A record and a fence above the head are another journal's: dropped
        // and purged from the file.
        std::fs::write(&path, format!("{contents}{{\"at\":99}}\n{{\"covered\":999}}\n"))
            .expect("foreign lines");
        let (f, replayed) = DerivedFile::open(dir.path(), MASKED_FILE, head).expect("reopen");
        assert_eq!(replayed.iter().map(|(at, _)| *at).collect::<Vec<_>>(), vec![3, 7]);
        assert_eq!(f.coverage(), 9, "a foreign fence does not raise coverage");
        let purged = std::fs::read_to_string(&path).expect("read");
        assert!(!purged.contains("99"), "the foreign lines are gone: {purged}");
        assert!(purged.ends_with("{\"covered\":9}\n"), "and the rewrite fences at the coverage: {purged}");
    }
}
