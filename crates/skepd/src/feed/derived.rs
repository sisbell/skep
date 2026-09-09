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
//!   (PUB-7.20 — for a position it does not hold, the bitmap is a skip
//!   accelerator and never the authority); a stream a position is missing
//!   from is a supplement short by it.
//! * a GAP is what coverage cannot describe, so no file is left holding one:
//!   the first failed append STOPS its file for the uptime
//!   ([`DerivedFile`]'s `stopped`), so the on-disk claim stays below the
//!   position that was lost and the next open re-derives from there. Without
//!   it a later successful append raises coverage past the gap, and the
//!   position reads as one that contributed nothing — which for
//!   `feed-index.log` is a `[]`-docs entry, and those are never masked.
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

// Each file below is named BESIDE the field its records carry, because this
// module owns the LINE and would otherwise own only half of what a line is:
// [`DerivedFile::append`] takes any name, so a write site that spells a field
// apart from the read site produces a line that replays with no field. That
// position then contributes nothing and is served as a `[]`-docs entry, which
// is never masked — a draft write unmasked to every class — and it still
// carries an `at`, so it counts toward coverage and the tail derivation never
// revisits it. It is the one loss the coverage check does not close.

/// The per-document position index's file.
pub(crate) const INDEX_FILE: &str = "feed-index.log";
/// Its records' one field: the classified documents, dotted-decimal.
pub(crate) const INDEX_DOCS: &str = "docs";
/// The position → offset array's file.
pub(crate) const OFFSETS_FILE: &str = "feed-offsets.log";
/// Its records' one field: the line's byte offset in `commits.log`.
pub(crate) const OFFSETS_OFFSET: &str = "offset";
/// The masked-position bitmap's file. Its records carry the position alone,
/// so it has no field constant — membership IS the record.
pub(crate) const MASKED_FILE: &str = "feed-masked.log";
/// The per-owner draft-position streams' file.
pub(crate) const STREAMS_FILE: &str = "feed-streams.log";
/// Its records' one field: the owner accounts, dotted-decimal.
pub(crate) const STREAMS_OWNERS: &str = "owners";

/// One replayed line, parsed — `sidecar.rs`'s vocabulary, which this file
/// shares its whole discipline with: a LINE is the bytes on disk, a RECORD
/// is the parsed value, and an ENTRY is a record carrying a position.
enum Record {
    /// `{"covered":N}` — every position ≤ N is processed.
    Fence(u64),
    /// One position's own record, with its whole object (the feed reads the
    /// per-file fields off it).
    Entry(u64, Map<String, Value>),
}

/// One derived sidecar: its append handle and its coverage.
pub(crate) struct DerivedFile {
    file: File,
    dir: PathBuf,
    name: &'static str,
    coverage: u64,
    /// Set by the first FAILED [`DerivedFile::append`] of this uptime, after
    /// which this file takes no further APPEND and no FENCE.
    ///
    /// [`DerivedFile::rewrite`] is EXEMPT and needs no guard, on two counts.
    /// It writes the file WHOLE from the resident twin and fences at the
    /// coverage it has just made true, so it CLOSES a gap rather than
    /// claiming over one — which is the opposite of what this flag guards
    /// against. And it is unreachable past a stop in any case: every
    /// [`DerivedFile::append`] in [`crate::feed::Feed::open`] is
    /// `?`-propagated into `DaemonError::Sidecar`, so a failure there
    /// returns before any rewrite runs, and no rewrite happens at commit
    /// time at all.
    ///
    /// COVERAGE IS A CLAIM, and a gap beneath it is the one loss the check
    /// cannot close: a position at or below coverage with no record reads as
    /// "contributed nothing", which for `feed-index.log` is a `[]`-docs entry
    /// and so is never masked. A failed append leaves coverage where it
    /// stands, and the NEXT successful one would raise it past the gap — so
    /// the file stops instead, its on-disk coverage stays below the failure,
    /// and the next open's tail derivation re-covers the failure and every
    /// position after it from `commits.log`. The resident twin is updated
    /// ahead of every append, so this uptime still answers correctly; what
    /// stops is the testimony, which is what the next open reads.
    stopped: bool,
}

/// The ENTRIES a derived file replays — its position-carrying records,
/// `(position, the record's object)`, in file order. A fence carries no
/// position and so is not one of these; it is folded into the coverage.
pub(crate) type Entries = Vec<(u64, Map<String, Value>)>;

impl DerivedFile {
    /// Replay `name` in `dir`: truncate a torn tail, drop what describes
    /// another journal (rewriting the file without it), and hand back the
    /// entries at or below `head` with the file's coverage.
    pub fn open(dir: &Path, name: &'static str, head: u64) -> io::Result<(DerivedFile, Entries)> {
        let path = dir.join(name);
        let mut file = OpenOptions::new().create(true).read(true).append(true).open(&path)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        let (records, valid_end) = parse_records(&bytes);
        if valid_end < bytes.len() {
            file.set_len(valid_end as u64)?;
        }
        let mut coverage = 0u64;
        let mut entries = Vec::new();
        let mut foreign = false;
        for record in records {
            match record {
                Record::Fence(n) if n <= head => coverage = coverage.max(n),
                Record::Entry(at, m) if at <= head => {
                    coverage = coverage.max(at);
                    entries.push((at, m));
                }
                Record::Fence(_) | Record::Entry(..) => foreign = true,
            }
        }
        let mut this =
            DerivedFile { file, dir: dir.to_path_buf(), name, coverage, stopped: false };
        if foreign {
            // Purge what is not this journal's, once, so it cannot come back.
            let kept = entries
                .iter()
                .map(|(at, m)| {
                    replayed_record_object(*at, m.iter().map(|(k, v)| (k.clone(), v.clone())))
                })
                .collect();
            this.rewrite(kept, coverage)?;
        }
        Ok((this, entries))
    }

    /// Every position at or below this is processed into the file.
    pub fn coverage(&self) -> u64 {
        self.coverage
    }

    /// Append one record for `at` with the file's own fields, in the shape
    /// [`record_object`] fixes — so an appended line and the rewritten line
    /// that reproduces it are one spelling rather than two that must agree.
    ///
    /// A file [`DerivedFile::stopped`] closed takes nothing and answers `Ok`:
    /// the failure was reported once, at the append that raised it, and this
    /// file's on-disk coverage must not rise past the gap it left.
    pub fn append(&mut self, at: u64, fields: Vec<(&'static str, Value)>) -> io::Result<()> {
        if self.stopped {
            return Ok(());
        }
        if let Err(e) = self.file.write_all(&line_bytes(record_object(at, fields))) {
            self.stopped = true;
            return Err(e);
        }
        self.coverage = self.coverage.max(at);
        Ok(())
    }

    /// Append the coverage fence `{"covered":N}` — a no-op when the file
    /// already covers `covered`, and a no-op on a stopped file, whose
    /// coverage claim must stay below the position it lost.
    pub fn fence(&mut self, covered: u64) -> io::Result<()> {
        if self.stopped || covered <= self.coverage {
            return Ok(());
        }
        self.file.write_all(&fence_line(covered))?;
        self.coverage = covered;
        Ok(())
    }

    /// Rewrite the whole file as `records` behind a fence at `covered`,
    /// through a temp file renamed over the original (compaction, and the
    /// purge of a foreign fence). `records` are whole record objects already
    /// carrying their `at`; [`crate::sidecar::line_bytes`] is what makes each
    /// a line.
    pub fn rewrite(&mut self, records: Vec<Value>, covered: u64) -> io::Result<()> {
        let path = self.dir.join(self.name);
        let tmp = self.dir.join(format!("{}.compact", self.name));
        let mut out = Vec::new();
        for record in records {
            out.extend_from_slice(&line_bytes(record));
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

/// One record object for `at` from its fields — THE shape a derived line
/// takes, in both directions: [`DerivedFile::append`] writes it and a
/// rewrite reproduces it, so each file's field name is spelled once and a
/// compacted file's lines are byte-identical to appended ones. The `at` key
/// is added here, so a record cannot omit it.
pub(crate) fn record_object(at: u64, fields: Vec<(&'static str, Value)>) -> Value {
    let mut pairs = fields;
    pairs.push(("at", Value::Number(at.into())));
    obj(pairs)
}

/// The record object of one REPLAYED record, re-sorted —
/// [`DerivedFile::open`]'s purge alone, whose keys are owned because they
/// came off disk. Every other caller holds `&'static str` keys and goes
/// through [`record_object`], of which this is the owned-key twin.
fn replayed_record_object(at: u64, fields: impl IntoIterator<Item = (String, Value)>) -> Value {
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

/// The records of every whole newline-terminated line; trust ends at the
/// first line that is torn or does not parse. Returns those records and the
/// byte offset after the last whole line.
fn parse_records(bytes: &[u8]) -> (Vec<Record>, usize) {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < bytes.len() {
        let Some(nl) = bytes[pos..].iter().position(|&b| b == b'\n') else { break };
        match parse_line(&bytes[pos..pos + nl]) {
            Some(record) => out.push(record),
            None => break,
        }
        pos += nl + 1;
    }
    (out, pos)
}

/// One line's record: a fence, or an entry with a position. Anything else is
/// torn.
fn parse_line(line: &[u8]) -> Option<Record> {
    let v: Value = serde_json::from_slice(line).ok()?;
    let Value::Object(m) = v else { return None };
    if let Some(c) = m.get("covered") {
        return Some(Record::Fence(c.as_u64()?));
    }
    let at = m.get("at")?.as_u64()?;
    Some(Record::Entry(at, m))
}

#[cfg(test)]
impl DerivedFile {
    /// A [`DerivedFile`] whose appends FAIL — a READ-ONLY handle on the file
    /// in `dir` — which is the one condition the stop rule is about and the
    /// one no portable test can produce from [`DerivedFile::open`]'s handle.
    fn over_unwritable(dir: &Path, name: &'static str, coverage: u64) -> DerivedFile {
        let path = dir.join(name);
        File::create(&path).expect("create the file to be opened read-only");
        let file = File::open(&path).expect("a read-only handle");
        DerivedFile { file, dir: dir.to_path_buf(), name, coverage, stopped: false }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A file replays to exactly what was appended, torn tails end trust,
    /// and coverage is the fence-or-record maximum.
    ///
    /// The field name below is a LITERAL and not one of the per-file
    /// constants, deliberately: this file's discipline is field-agnostic —
    /// [`DerivedFile::append`] writes whatever it is given — so the test
    /// that pins the discipline names a field no file's schema fixes.
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
        // Byte-identical to the file the APPENDS wrote: the rewrite fences at
        // the coverage, and a rewritten record line reproduces the appended
        // one exactly. That equality is the whole coupling between the two
        // directions — [`record_object`] makes it structural for every
        // rewrite holding its own field names, and this purge is the one
        // rewrite that cannot (its keys came off disk), so the two spellings
        // are held together here or nowhere.
        assert_eq!(purged, contents, "a rewritten line is the appended line");
    }

    /// A file whose append FAILS takes nothing further, so its on-disk
    /// coverage cannot rise past the position it lost.
    ///
    /// Coverage is `max(fence, highest record)` and a position at or below it
    /// with no record means "contributed nothing". Left running, the NEXT
    /// successful append raises the claim over the gap, and the next open's
    /// tail derivation starts above it and never revisits it — which for
    /// `feed-index.log` classifies the position EMPTY, and an empty class is
    /// a `[]`-docs entry the mask never masks: a draft write served to every
    /// requester, carrying its op, its wall-clock time and the fingerprint of
    /// the key that signed it, permanently.
    #[test]
    fn a_failed_append_stops_its_file_so_coverage_never_covers_the_gap() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut f = DerivedFile::over_unwritable(dir.path(), INDEX_FILE, 9);

        assert!(f.append(10, vec![]).is_err(), "a read-only handle refuses the line");
        assert_eq!(f.coverage(), 9, "and the refused position does not raise the claim");

        // The position AFTER the gap: accepted as an outcome, written
        // nowhere, and — the whole point — not counted as covered.
        f.append(11, vec![(INDEX_DOCS, Value::Array(vec![]))])
            .expect("a stopped file reports its failure once, at the append that raised it");
        assert_eq!(f.coverage(), 9, "a stopped file's coverage stays where the gap left it");
        f.fence(20).expect("a fence on a stopped file is a no-op");
        assert_eq!(f.coverage(), 9, "…and does not close the check over the gap either");
        assert_eq!(
            std::fs::read(dir.path().join(INDEX_FILE)).expect("read"),
            Vec::<u8>::new(),
            "nothing reached the file after the failure"
        );

        // What the next open therefore sees: coverage 9, so its tail
        // derivation re-covers 10 and everything above it.
        drop(f);
        let (reopened, entries) = DerivedFile::open(dir.path(), INDEX_FILE, 20).expect("reopen");
        assert!(entries.is_empty());
        assert_eq!(reopened.coverage(), 0, "an empty file claims nothing");
    }
}
