//! The four DERIVED sidecars (PUB-7.19) — line files beside `commits.log`,
//! each a projection of that file and the journal, appended AT COMMIT
//! outside the journal transaction, replayed at open, tail-checked against
//! the head, and rebuilt whole only on whole-file loss (PUB-7.21) — and
//! [`LineFile`], the one line-file type all five of the feed's files share,
//! the attest store's included (`attest.rs`, which states that store's own
//! class):
//!
//! | file                | record                              | twin (`feed.rs`)                  |
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
//!   not parse, and the file is truncated there at open — a [`LineFile`]'s
//!   cut named on the operator stream, since in the attest store it can take
//!   primary state with it;
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
//!   ([`LineFile`]'s `stopped`), so the on-disk claim stays below the
//!   position that was lost and the next open re-derives from there. Without
//!   it a later successful append raises coverage past the gap, and the
//!   position reads as one that contributed nothing — which for
//!   `feed-index.log` is a `[]`-docs entry, and those are never masked.
//! * appends are flushed to the OS, not fsynced (the trade `commits.log`
//!   makes: testimony never doubles a write's fsync) — the attest store's
//!   alone excepted, each of its lines synced before its record step
//!   returns ([`LineFile::append_synced`]; SO-I5 (d), which `attest.rs`
//!   states); a rewrite goes to `<file>.compact` and is renamed over the
//!   original — whole old file or whole new one, never half of either. A
//!   rewrite runs at open and, since the reclaim floor moves at a checkpoint
//!   and at no other moment, after each checkpoint the daemon's checkpoint
//!   thread lands; one that fails PAST its rename while serving leaves the
//!   handle naming the replaced file, so it STOPS the file as a failed
//!   append does, said once (P22: a slower answer at the next open, never
//!   an outage).
//!
//! Loss unmasks nothing: no derived file is consulted for WHAT an entry
//! says (that is `commits.log`'s) or for WHETHER a class may see it (that
//! is the read predicate's, re-applied per rendered entry); they decide
//! only WHICH positions are candidates, and a candidate the mask refuses is
//! omitted whatever put it forward.

use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

use serde_json::{Map, Value};

use super::super::sidecar::{line_bytes, RewriteFail};
use crate::codec::obj;

// Each file below is named BESIDE the field its records carry, because this
// module owns the LINE and would otherwise own only half of what a line is:
// [`LineFile::append`] takes any name, so a write site that spells a field
// apart from the read site produces a line that replays with no field. That
// position then contributes nothing and is served as a `[]`-docs entry, which
// is never masked — a draft write unmasked to every class — and it still
// carries an `at`, so it counts toward coverage and the tail derivation never
// revisits it. It is the one loss the coverage check does not close.

/// The per-document position index's file.
pub(super) const INDEX_FILE: &str = "feed-index.log";
/// Its records' one field: the classified documents, dotted-decimal.
pub(super) const INDEX_DOCS: &str = "docs";
/// The position → offset array's file.
pub(super) const OFFSETS_FILE: &str = "feed-offsets.log";
/// Its records' one field: the line's byte offset in `commits.log`.
pub(super) const OFFSETS_OFFSET: &str = "offset";
/// The masked-position bitmap's file. Its records carry the position alone,
/// so it has no field constant — membership IS the record.
pub(super) const MASKED_FILE: &str = "feed-masked.log";
/// The per-owner draft-position streams' file.
pub(super) const STREAMS_FILE: &str = "feed-streams.log";
/// Its records' one field: the owner accounts, dotted-decimal.
pub(super) const STREAMS_OWNERS: &str = "owners";

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

/// One line file — a derived sidecar, or the attest store (`attest.rs`): its
/// append handle and its coverage. Named for the SHAPE the five files share,
/// never for a class: the attest store is no projection below the reclaim
/// floor (BW-01), so a class word here would mislabel the one file whose lines
/// there are an entry signature's only copy.
pub(super) struct LineFile {
    file: File,
    dir: PathBuf,
    name: &'static str,
    coverage: u64,
    /// Set by the first FAILED [`LineFile::append`] of this uptime — or
    /// failed [`LineFile::sync`], or a [`LineFile::rewrite`] that failed
    /// PAST its rename — after which this file takes no further APPEND and
    /// no FENCE.
    ///
    /// [`LineFile::rewrite`] is not GUARDED by it: it writes the file WHOLE
    /// from the resident twin and fences at the coverage it has just made
    /// true, so it CLOSES a gap rather than claiming over one — the opposite
    /// of what this flag guards against — and a stopped file rewritten
    /// whole is right on disk again while the flag stands for the uptime.
    /// What a rewrite can do is SET it. At open every rewrite's failure is
    /// fatal — `?`-propagated into `DaemonError::Sidecar` before any append
    /// — so the flag is moot there; but the checkpoint thread's compaction
    /// runs the same rewrite while serving, and one that fails past its
    /// rename leaves this handle naming the REPLACED file, which no open
    /// reads: the file stops, said once, and the next open re-derives from
    /// the rewritten file's own fence.
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
    /// The coverage the last successful [`LineFile::sync`] made durable —
    /// set in that sync's own success arm, so no line reads as synced that
    /// no `sync_data` covered.
    #[cfg(any(test, feature = "test-hooks"))]
    synced: u64,
    /// The test seam behind `crate::Daemon::fail_the_feeds_next_rewrite_past_rename`:
    /// the next [`LineFile::rewrite`] fails at the reopen of the file it has
    /// just renamed into place, so the stop that arm carries is reachable
    /// without a disk that fails on cue.
    #[cfg(any(test, feature = "test-hooks"))]
    fail_next_rewrite_past_rename: bool,
}

/// The ENTRIES a line file replays — the position-carrying records its
/// caller KEEPS, `(position, the record's object)`, in file order. A fence
/// carries no position and so is not one of these; it is folded into the
/// coverage.
pub(super) type Entries = Vec<(u64, Map<String, Value>)>;

impl LineFile {
    /// Replay `name` in `dir` a line at a time: truncate at the first line
    /// that is torn or does not parse, saying so on the operator stream, drop
    /// what describes another journal (rewriting the file without it), and
    /// hand back the entries at or below `head` that `keep` admits, with the
    /// file's coverage — which counts every trusted line, kept or not.
    ///
    /// The scan holds one line and the kept entries, never the file. The
    /// attest store's file is NEVER COMPACTED (`attest.rs`), so a replay that
    /// held every line would hold the store's whole history at every open —
    /// order twice the file, a line for every attested commit the board ever
    /// made — and the open that cannot afford it is the restart a crash leaves.
    pub fn open(
        dir: &Path,
        name: &'static str,
        head: u64,
        keep: impl Fn(u64) -> bool,
    ) -> io::Result<(LineFile, Entries)> {
        let path = dir.join(name);
        let file = OpenOptions::new().create(true).read(true).append(true).open(&path)?;
        let mut coverage = 0u64;
        let mut entries = Vec::new();
        let mut foreign = false;
        let mut valid_end = 0u64;
        let mut reader = BufReader::new(&file);
        let mut line = Vec::new();
        loop {
            line.clear();
            let read = reader.read_until(b'\n', &mut line)?;
            // Trust ends at the first line that is torn — no newline, the end
            // of the file included — or does not parse.
            let Some(record) = line.strip_suffix(b"\n").and_then(parse_line) else { break };
            valid_end += read as u64;
            match record {
                Record::Fence(n) if n <= head => coverage = coverage.max(n),
                Record::Entry(at, m) if at <= head => {
                    coverage = coverage.max(at);
                    if keep(at) {
                        entries.push((at, m));
                    }
                }
                Record::Fence(_) | Record::Entry(..) => foreign = true,
            }
        }
        drop(reader);
        let len = file.metadata()?.len();
        if valid_end < len {
            // Said, never silent: in the attest store the cut can take
            // primary state with it, below the floor.
            crate::notice::line(format_args!(
                "{name}: trust ends at byte {valid_end} of {len}; the {} bytes after it are cut",
                len - valid_end
            ));
            file.set_len(valid_end)?;
        }
        let mut this = LineFile {
            file,
            dir: dir.to_path_buf(),
            name,
            coverage,
            stopped: false,
            #[cfg(any(test, feature = "test-hooks"))]
            synced: 0,
            #[cfg(any(test, feature = "test-hooks"))]
            fail_next_rewrite_past_rename: false,
        };
        if foreign {
            // Purge what is not this journal's, once, so it cannot come back.
            this.purge_foreign(head)?;
        }
        Ok((this, entries))
    }

    /// Every position at or below this is processed into the file.
    pub fn coverage(&self) -> u64 {
        self.coverage
    }

    /// The first position this file has NOT processed — one past its
    /// coverage, and where each open's re-derivation of its MISSING TAIL
    /// begins. The `+ 1` is what the fence MEANS
    /// ([`LineFile::coverage`]: every position at or below it is
    /// processed), so that reading is a fact of this type rather than of the
    /// arithmetic each caller would otherwise spell — one per derived
    /// structure in [`super::Feed::open`], over two different maps, and the
    /// attest store's in [`super::attest::AttestStore::open`].
    ///
    /// Saturating, so a file covering `u64::MAX` answers `u64::MAX` and its
    /// tail is the empty range rather than a wrap to genesis.
    pub fn first_uncovered(&self) -> u64 {
        self.coverage().saturating_add(1)
    }

    /// Append one record for `at` with the file's own fields, in the shape
    /// [`record_object`] fixes — so an appended line and the rewritten line
    /// that reproduces it are one spelling rather than two that must agree.
    ///
    /// A file [`LineFile::stopped`] closed takes nothing and answers `Ok`:
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

    /// Append one record and REPORT a failed write rather than returning it —
    /// the RECORD-time disposition, where the commit has landed and the ack is
    /// owed whatever this file does. [`LineFile::append`] keeps the
    /// fallible form for [`super::Feed::open`], which propagates into
    /// `DaemonError::Sidecar`: at open nothing is owed yet, so a data dir that
    /// cannot take a write the kernel just performed is an operator condition
    /// worth reporting rather than limping past.
    ///
    /// The notice names THIS file, from the name this handle already holds, so
    /// no caller pairs a handle with a file-name constant. ONE per file per
    /// uptime: [`LineFile::stopped`] answers `Ok` and writes nothing after
    /// the first failure, so a busy board's stderr carries it alone, and that
    /// field's own card says what the stop buys.
    pub fn append_or_report(&mut self, at: u64, fields: Vec<(&'static str, Value)>) {
        if let Err(e) = self.append(at, fields) {
            crate::notice::line(format_args!(
                "{} append failed at position {at}: {e}",
                self.name
            ));
        }
    }

    /// Append one record and SYNC the file before answering — the attest
    /// store's record-time append (SO-I5 (d)): there a line below the
    /// reclaim floor is an entry signature's only copy, so it must be on disk
    /// before any later commit, which could reclaim the journal's copy, can
    /// begin. The four derived files never take it; what they lose the next
    /// open re-derives.
    ///
    /// A failed write or sync STOPS the file and is ANSWERED, never reported
    /// here: the caller owes the failure a disposition of its own. A stopped
    /// file takes nothing and answers an error, never `Ok` — a line it did
    /// not write is no durable line.
    pub fn append_synced(&mut self, at: u64, fields: Vec<(&'static str, Value)>) -> io::Result<()> {
        if self.stopped {
            return Err(io::Error::other(format!("{} stopped at an earlier failure", self.name)));
        }
        self.append(at, fields)?;
        self.sync()
    }

    /// Sync the file's data to disk (`sync_data`): every line appended so
    /// far made durable. A failed sync STOPS the file as a failed append
    /// does — whether the lines reached the disk is then unknown, and the
    /// next open's replay is what decides what it covers.
    pub fn sync(&mut self) -> io::Result<()> {
        match self.file.sync_data() {
            Ok(()) => {
                #[cfg(any(test, feature = "test-hooks"))]
                {
                    self.synced = self.coverage;
                }
                Ok(())
            }
            Err(e) => {
                self.stopped = true;
                Err(e)
            }
        }
    }

    /// The test seam behind `crate::Daemon::attest_store_synced_through`:
    /// the coverage the last successful [`LineFile::sync`] made durable —
    /// every position at or below it whose line this file holds is on disk.
    /// Not a stable API.
    #[cfg(any(test, feature = "test-hooks"))]
    pub fn synced(&self) -> u64 {
        self.synced
    }

    /// The test seam behind `crate::Daemon::fail_the_attest_stores_next_write`:
    /// swap this file's handle for a READ-ONLY one on the same file, so its
    /// next write fails at the OS, as a full or failing disk's would, and
    /// the failure takes the path a real one takes. Not a stable API.
    #[cfg(any(test, feature = "test-hooks"))]
    pub fn make_unwritable(&mut self) -> io::Result<()> {
        self.file = File::open(self.dir.join(self.name))?;
        Ok(())
    }

    /// The test seam behind `crate::Daemon::fail_the_feeds_next_rewrite_past_rename`:
    /// the next [`LineFile::rewrite`] fails past its rename, at the reopen.
    /// Not a stable API.
    #[cfg(any(test, feature = "test-hooks"))]
    pub fn fail_next_rewrite_past_rename(&mut self) {
        self.fail_next_rewrite_past_rename = true;
    }

    /// The test seam's reading of the stop: whether this file takes no
    /// further line. Not a stable API.
    #[cfg(any(test, feature = "test-hooks"))]
    pub fn is_stopped(&self) -> bool {
        self.stopped
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
    /// through a temp file renamed over the original — the compaction from
    /// the twins, at open and after each checkpoint the daemon's thread
    /// lands. `records` are whole record objects already carrying their
    /// `at`; [`super::super::sidecar::line_bytes`] is what makes each a
    /// line.
    ///
    /// Which side of the rename a failure fell on travels as
    /// [`RewriteFail`], since the two leave different files behind: BEFORE
    /// it the old file stands whole and this handle still names it, nothing
    /// lost, the next checkpoint's compaction trying again; PAST it the new
    /// file is in place and this handle names the REPLACED one, which no
    /// open reads, so the file is STOPPED for the uptime as a failed append
    /// stops it — said once, here — its coverage the fence the new file
    /// carries, which the next open re-derives from. At open either side is
    /// fatal; while serving the caller reports the before-rename arm and
    /// moves on.
    pub fn rewrite(&mut self, records: Vec<Value>, covered: u64) -> Result<(), RewriteFail> {
        let path = self.dir.join(self.name);
        let tmp = self.dir.join(format!("{}.compact", self.name));
        let mut out = Vec::new();
        for record in records {
            out.extend_from_slice(&line_bytes(record));
        }
        out.extend_from_slice(&fence_line(covered));
        let renamed = (|| -> io::Result<()> {
            let mut f = File::create(&tmp)?;
            f.write_all(&out)?;
            f.sync_all()?;
            drop(f);
            std::fs::rename(&tmp, &path)
        })();
        renamed.map_err(RewriteFail::BeforeRename)?;
        #[cfg(any(test, feature = "test-hooks"))]
        let reopened = if std::mem::take(&mut self.fail_next_rewrite_past_rename) {
            Err(io::Error::other("test seam: the rewritten file's reopen refused"))
        } else {
            OpenOptions::new().create(true).read(true).append(true).open(&path)
        };
        #[cfg(not(any(test, feature = "test-hooks")))]
        let reopened = OpenOptions::new().create(true).read(true).append(true).open(&path);
        self.coverage = covered;
        match reopened {
            Ok(file) => {
                self.file = file;
                Ok(())
            }
            Err(e) => {
                self.stopped = true;
                crate::notice::line(format_args!(
                    "{} rewrite failed past its rename: {e}; this file takes no further line, so \
                     the next open re-derives from its fence",
                    self.name
                ));
                Err(RewriteFail::PastRename(e))
            }
        }
    }

    /// Rewrite the file without another journal's lines — every ENTRY line
    /// at or below `head` copied VERBATIM, in file order, then one fence at
    /// the coverage — through `<file>.compact` renamed over the original, a
    /// line at a time as [`LineFile::open`]'s scan is. A line is copied
    /// whether or not a caller kept it: in the attest store a line no caller
    /// keeps lies below the floor and is an entry signature's only copy, so
    /// its bytes are moved and never re-rendered. The file is already cut at
    /// its trusted end, so every line read here is whole.
    fn purge_foreign(&mut self, head: u64) -> io::Result<()> {
        let path = self.dir.join(self.name);
        let tmp = self.dir.join(format!("{}.compact", self.name));
        let mut out = BufWriter::new(File::create(&tmp)?);
        let mut reader = BufReader::new(File::open(&path)?);
        let mut line = Vec::new();
        while reader.read_until(b'\n', &mut line)? > 0 {
            if let Some(Record::Entry(at, _)) = line.strip_suffix(b"\n").and_then(parse_line) {
                if at <= head {
                    out.write_all(&line)?;
                }
            }
            line.clear();
        }
        out.write_all(&fence_line(self.coverage))?;
        let f = out.into_inner().map_err(io::IntoInnerError::into_error)?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, &path)?;
        self.file = OpenOptions::new().create(true).read(true).append(true).open(&path)?;
        Ok(())
    }
}

/// One record object for `at` from its fields — THE shape every line of a
/// [`LineFile`] takes, in both directions: [`LineFile::append`] writes it and a
/// rewrite reproduces it, so each file's field name is spelled once and a
/// compacted file's lines are byte-identical to appended ones. The `at` key
/// is added here, so a record cannot omit it.
pub(super) fn record_object(at: u64, fields: Vec<(&'static str, Value)>) -> Value {
    let mut pairs = fields;
    pairs.push(("at", Value::Number(at.into())));
    obj(pairs)
}

fn fence_line(covered: u64) -> Vec<u8> {
    line_bytes(obj(vec![("covered", Value::Number(covered.into()))]))
}

/// One line's record — the line without its newline: a fence, or an entry
/// with a position. Anything else is torn.
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
impl LineFile {
    /// A [`LineFile`] whose appends FAIL — a READ-ONLY handle on the file
    /// in `dir` — which is the one condition the stop rule is about and the
    /// one no portable test can produce from [`LineFile::open`]'s handle.
    fn over_unwritable(dir: &Path, name: &'static str, coverage: u64) -> LineFile {
        let path = dir.join(name);
        File::create(&path).expect("create the file to be opened read-only");
        let file = File::open(&path).expect("a read-only handle");
        LineFile {
            file,
            dir: dir.to_path_buf(),
            name,
            coverage,
            stopped: false,
            synced: 0,
            fail_next_rewrite_past_rename: false,
        }
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
    /// [`LineFile::append`] writes whatever it is given — so the test
    /// that pins the discipline names a field no file's schema fixes.
    #[test]
    fn records_and_fences_replay_and_coverage_follows_them() {
        let dir = tempfile::tempdir().expect("tempdir");
        let head = 20;
        {
            let (mut f, replayed) =
                LineFile::open(dir.path(), MASKED_FILE, head, |_| true).expect("open");
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
        let (f, replayed) =
            LineFile::open(dir.path(), MASKED_FILE, head, |_| true).expect("reopen");
        assert_eq!(replayed.iter().map(|(at, _)| *at).collect::<Vec<_>>(), vec![3, 7]);
        assert_eq!(f.coverage(), 9);
        assert_eq!(std::fs::read_to_string(&path).expect("read"), contents, "the tail is cut");
        drop(f);
        // A record and a fence above the head are another journal's: dropped
        // and purged from the file.
        std::fs::write(&path, format!("{contents}{{\"at\":99}}\n{{\"covered\":999}}\n"))
            .expect("foreign lines");
        let (f, replayed) =
            LineFile::open(dir.path(), MASKED_FILE, head, |_| true).expect("reopen");
        assert_eq!(replayed.iter().map(|(at, _)| *at).collect::<Vec<_>>(), vec![3, 7]);
        assert_eq!(f.coverage(), 9, "a foreign fence does not raise coverage");
        let purged = std::fs::read_to_string(&path).expect("read");
        assert!(!purged.contains("99"), "the foreign lines are gone: {purged}");
        // Byte-identical to the file the APPENDS wrote: the purge copies this
        // journal's entry lines verbatim, drops every fence, and fences once
        // at the coverage.
        assert_eq!(purged, contents, "a purged file keeps this journal's lines as written");
    }

    /// A replay HOLDS only the entries its caller keeps — the attest store's
    /// file is never compacted, so a replay holding every line would hold its
    /// whole history at every open — while coverage still counts every
    /// trusted line; and a foreign purge keeps every entry line of THIS
    /// journal, verbatim, kept or not: in the attest store a line no caller
    /// keeps lies below the floor and is an entry signature's only copy.
    #[test]
    fn a_replay_holds_only_what_its_caller_keeps_and_a_purge_drops_only_the_foreign() {
        let dir = tempfile::tempdir().expect("tempdir");
        {
            let (mut f, _) =
                LineFile::open(dir.path(), MASKED_FILE, 20, |_| true).expect("open");
            for at in [3, 7, 9] {
                f.append(at, vec![]).expect("append");
            }
        }
        let path = dir.path().join(MASKED_FILE);
        let ours = std::fs::read_to_string(&path).expect("read");
        let held = |entries: &Entries| entries.iter().map(|(at, _)| *at).collect::<Vec<_>>();
        let (f, entries) =
            LineFile::open(dir.path(), MASKED_FILE, 20, |at| at == 7).expect("reopen");
        assert_eq!(held(&entries), [7], "only the kept entry is held");
        assert_eq!(f.coverage(), 9, "coverage counts the lines no caller kept");
        drop(f);
        let unmoved = std::fs::read_to_string(&path).expect("read");
        assert_eq!(unmoved, ours, "a replay with nothing to purge writes nothing");
        std::fs::write(&path, format!("{ours}{{\"at\":99}}\n")).expect("a foreign line");
        let (f, entries) =
            LineFile::open(dir.path(), MASKED_FILE, 20, |at| at == 7).expect("purge");
        assert_eq!((held(&entries), f.coverage()), (vec![7], 9));
        assert_eq!(
            std::fs::read_to_string(&path).expect("read"),
            format!("{ours}{{\"covered\":9}}\n"),
            "the foreign line is gone, and 3 and 9, which no caller kept, survive verbatim"
        );
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
        let mut f = LineFile::over_unwritable(dir.path(), INDEX_FILE, 9);

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
        let (reopened, entries) =
            LineFile::open(dir.path(), INDEX_FILE, 20, |_| true).expect("reopen");
        assert!(entries.is_empty());
        assert_eq!(reopened.coverage(), 0, "an empty file claims nothing");
    }

    /// The RECORD-time append swallows its failure and composes the stop rule:
    /// a caller between a commit and its ack owes an ack whatever this file
    /// does, so [`LineFile::append_or_report`] answers unit — a caller
    /// cannot forget to handle what it is never given — and still leaves
    /// coverage BELOW the position it lost, which is what the next open's
    /// tail derivation reads. A version writing past [`LineFile::append`]
    /// rather than through it would report and then claim the gap.
    #[test]
    fn the_record_time_append_swallows_its_failure_and_still_stops_the_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut f = LineFile::over_unwritable(dir.path(), INDEX_FILE, 9);

        f.append_or_report(10, vec![(INDEX_DOCS, Value::Array(vec![]))]);
        assert_eq!(f.coverage(), 9, "the lost position does not raise the claim");

        // The position after the gap, and the fence over it: both no-ops, so
        // the on-disk claim can never cover what was lost.
        f.append_or_report(11, vec![(INDEX_DOCS, Value::Array(vec![]))]);
        f.fence(20).expect("a fence on a stopped file is a no-op");
        assert_eq!(f.coverage(), 9, "a stopped file's coverage stays where the gap left it");
        assert_eq!(
            std::fs::read(dir.path().join(INDEX_FILE)).expect("read"),
            Vec::<u8>::new(),
            "nothing reached the file after the failure"
        );
    }

    /// A rewrite that fails PAST its rename — the new file in place, the
    /// handle naming the replaced one — STOPS the file (P22; the settled
    /// disposition for `record`: reported, never failing an op): the next
    /// append and the next fence are no-ops, the on-disk file is the
    /// rewritten whole one and nothing after, and the next open replays it
    /// and re-derives from its fence. One that fails BEFORE its rename stops
    /// nothing: the old file stands and the handle still appends to it.
    #[test]
    fn a_rewrite_failed_past_its_rename_stops_the_file_and_one_failed_before_it_does_not() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(MASKED_FILE);
        let (mut f, _) = LineFile::open(dir.path(), MASKED_FILE, 20, |_| true).expect("open");
        f.append(3, vec![]).expect("append");
        f.append(7, vec![]).expect("append");

        // BEFORE the rename: a directory on the temp file's name refuses
        // the create, so nothing moved and nothing stopped.
        let tmp = dir.path().join(format!("{MASKED_FILE}.compact"));
        std::fs::create_dir(&tmp).expect("a directory on the temp's name");
        let refused = f
            .rewrite(vec![record_object(7, vec![])], 9)
            .expect_err("the temp file's create is refused");
        assert!(matches!(refused, RewriteFail::BeforeRename(_)), "{refused:?}");
        assert!(!f.is_stopped(), "the old file stands and the handle names it");
        f.append(8, vec![]).expect("…so it still takes a line");
        assert_eq!(
            std::fs::read_to_string(&path).expect("read"),
            "{\"at\":3}\n{\"at\":7}\n{\"at\":8}\n",
            "the old file, whole, with the append after the refused rewrite"
        );
        std::fs::remove_dir(&tmp).expect("clear the name");

        // PAST the rename: the seam refuses the reopen. The new file is in
        // place; the handle names the replaced one; the file stops.
        f.fail_next_rewrite_past_rename();
        let refused = f
            .rewrite(vec![record_object(7, vec![]), record_object(8, vec![])], 9)
            .expect_err("the reopen is refused");
        assert!(matches!(refused, RewriteFail::PastRename(_)), "{refused:?}");
        assert!(f.is_stopped(), "the file is stopped for the uptime");
        assert_eq!(f.coverage(), 9, "the fence the rewritten file carries");
        f.append(10, vec![]).expect("a stopped file answers Ok and writes nothing");
        f.append_or_report(11, vec![]);
        f.fence(20).expect("a fence on a stopped file is a no-op");
        assert_eq!(f.coverage(), 9, "the claim never rises past the stop");
        assert_eq!(
            std::fs::read_to_string(&path).expect("read"),
            "{\"at\":7}\n{\"at\":8}\n{\"covered\":9}\n",
            "the rewritten file, whole, and nothing after it"
        );
        drop(f);
        let (reopened, entries) =
            LineFile::open(dir.path(), MASKED_FILE, 20, |_| true).expect("reopen");
        assert_eq!(entries.iter().map(|(at, _)| *at).collect::<Vec<_>>(), vec![7, 8]);
        assert_eq!(reopened.coverage(), 9, "the next open re-derives from 10");
        assert!(!reopened.is_stopped());
    }

    /// The attest store's append (SO-I5 (d)) is synced through its own line,
    /// ANSWERS its failure rather than reporting it, and on a stopped file
    /// answers every later line an error, never `Ok`: a line the file did
    /// not write is no durable line.
    #[test]
    fn a_synced_append_answers_its_failure_and_a_stopped_file_holds_no_line_durable() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (mut f, _) = LineFile::open(dir.path(), MASKED_FILE, 20, |_| true).expect("open");
        f.append_synced(3, vec![]).expect("a writable file takes and syncs the line");
        assert_eq!(f.synced(), 3, "the sync covers the line it follows");
        let mut f = LineFile::over_unwritable(dir.path(), INDEX_FILE, 3);
        assert!(f.append_synced(4, vec![]).is_err(), "a read-only handle refuses the line");
        assert!(f.append_synced(5, vec![]).is_err(), "a stopped file answers no later line Ok");
        assert_eq!((f.coverage(), f.synced()), (3, 0), "nothing covered past it, nothing synced");
    }
}
