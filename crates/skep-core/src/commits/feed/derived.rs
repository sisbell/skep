//! The four derived sidecars (PUB-7.19) and [`LineFile`], the type they share.
//!
//! The sidecars are line files beside `commits.log`, each a projection of
//! that file and the journal, appended at commit outside the journal
//! transaction, replayed at open, tail-checked against the head, and rebuilt
//! whole only on whole-file loss (PUB-7.21). [`LineFile`] is the one
//! line-file type all five of the feed's files share, the attest store's
//! included (`attest.rs`, which states that store's own class):
//!
//! | file                | record                              | twin (`feed.rs`)                  |
//! |---------------------|-------------------------------------|-----------------------------------|
//! | `feed-index.log`    | `{"at":N,"docs":["…"]}`             | the per-document position index   |
//! | `feed-offsets.log`  | `{"at":N,"offset":O}`               | the position → offset array       |
//! | `feed-masked.log`   | `{"at":N}`                          | the masked-position bitmap        |
//! | `feed-streams.log`  | `{"at":N,"owners":["…"]}`           | the per-owner draft-position streams |
//!
//! plus, in every file, the coverage fence `{"covered":N}`: every position
//! at or below `N` has been processed into this file — the record it has
//! for a position that contributed nothing being exactly no record.
//!
//! One shape, one discipline, shared with `commits.log` (`sidecar.rs`):
//!
//! * a line is a JSON object built through the codec's key-sorting device,
//!   newline-terminated; trust ends at the first line that is torn or does
//!   not parse, and the file is truncated there at open — a [`LineFile`]'s
//!   cut answered to its caller (`Cut`: the trusted end, the length, the
//!   last trusted position, the position a torn last line names and the
//!   whole lines past a damaged one), which names it on the operator stream
//!   with its own case — a derived file's cut part is re-derived; in the
//!   attest store the cut can take primary state with it, and its open says
//!   which side of the reclaim floor it reached;
//! * a record above the journal's head, or a fence above it, describes a
//!   different journal (an operator swapped files under the sidecar) and is
//!   dropped — and the file rewritten without it, so a journal that later
//!   grows past the number cannot resurrect it;
//! * coverage is `max(fence, highest record) ≤ head`. A position above it is
//!   one this file has *not* processed — its contribution is re-derived by
//!   the feed's open from `commits.log` (a recorded position) or the journal
//!   (a bare one) and appended, then a fence at the head closes the check. A
//!   position at or below coverage with no record contributed nothing.
//!   This is what makes a lost tail silent incompleteness the check closes,
//!   never a wrong answer: an entry the index does not list is one no
//!   narrowing can reach and the published walk still serves; a masked
//!   position the bitmap does not hold is walked and masked at render
//!   (PUB-7.20 — for a position it does not hold, the bitmap is a skip
//!   accelerator and never the authority); a stream a position is missing
//!   from is a supplement short by it.
//! * a gap is what coverage cannot describe, so no file is left holding one:
//!   the first failed append stops its file for the uptime
//!   ([`LineFile`]'s `stopped`), so the on-disk claim stays below the
//!   position that was lost and the next open re-derives from there. Without
//!   it a later successful append raises coverage past the gap, and the
//!   position reads as one that contributed nothing — which for
//!   `feed-index.log` is a `[]`-docs entry, and those are never masked.
//! * appends are flushed to the OS, not fsynced (the trade `commits.log`
//!   makes: testimony never doubles a write's fsync) — the attest store's
//!   alone excepted, each of its lines synced before its record step returns
//!   ([`LineFile::append_owing_sync`], through the file's [`SyncHandle`];
//!   SO-I5 (d), which `attest.rs` states); a rewrite goes to
//!   `<file>.compact` and is renamed over the original — whole old file or
//!   whole new one, never half of either. A rewrite runs at open and, since
//!   the reclaim floor moves at a checkpoint and at no other moment, after
//!   each checkpoint the daemon's checkpoint thread lands; one that fails
//!   past its rename while serving leaves the handle naming the replaced
//!   file, so it stops the file as a failed append does, said once per
//!   uptime — the later landings' rewrites still run, the stop moving in
//!   silence to the newest fence of each that fails past its rename again
//!   (P22: a slower answer at the next open, never an outage). The walk's
//!   landing rewrites too, over files fenced below its region, so one that
//!   fails there before its rename leaves a file short of the region, which
//!   the landing stops at the region's lower edge as the gap rule above asks.
//!
//! Loss unmasks nothing: no derived file is consulted for *what* an entry
//! says (that is `commits.log`'s) or for *whether* a class may see it (that
//! is the read predicate's, re-applied per rendered entry); they decide
//! only *which* positions are candidates, and a candidate the mask refuses
//! is omitted whatever put it forward.

use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use serde_json::{Map, Value};
use skep_util::json::obj;
use skep_util::notice::Class;

use super::super::sidecar::{
    keep_dropped_lines, line_bytes, say_a_compact_twin, Cut, EntryLines, IoCause, KeptName,
    RewriteFail,
};
use super::super::Lines;

// Each file below is named beside the field its records carry, because this
// module owns the line and would otherwise own only half of what a line is:
// [`LineFile::append`] takes any name, so a write site that spells a field
// apart from the read site produces a line that replays with no field. That
// position then contributes nothing — in `feed-index.log` it is served as a
// `[]`-docs entry, which is never masked: a draft write unmasked to every
// class — and it still carries an `at`, so it counts toward coverage and the
// tail derivation never revisits it. It is the one loss the coverage check
// does not close.

/// The per-document position index's file.
pub(super) const INDEX_FILE: &str = "feed-index.log";
/// Its records' one field: the classified documents, dotted-decimal.
pub(super) const INDEX_DOCS: &str = "docs";
/// The position → offset array's file.
pub(super) const OFFSETS_FILE: &str = "feed-offsets.log";
/// Its records' one field: the line's byte offset in `commits.log`.
pub(super) const OFFSETS_OFFSET: &str = "offset";
/// The masked-position bitmap's file.
///
/// Its records carry the position alone, so it has no field constant —
/// membership *is* the record.
pub(super) const MASKED_FILE: &str = "feed-masked.log";
/// The per-owner draft-position streams' file.
pub(super) const STREAMS_FILE: &str = "feed-streams.log";
/// Its records' one field: the owner accounts, dotted-decimal.
pub(super) const STREAMS_OWNERS: &str = "owners";

/// One replayed line, parsed.
///
/// It speaks `sidecar.rs`'s vocabulary, which this file shares its whole
/// discipline with: a line is the bytes on disk, a record is the parsed
/// value, and an entry is a record carrying a position.
enum Record {
    /// `{"covered":N}` — every position ≤ N is processed.
    Fence(u64),
    /// One position's own record, with its whole object.
    ///
    /// The feed reads the per-file fields off it.
    Entry(u64, Map<String, Value>),
}

/// One line file, a derived sidecar or the attest store (`attest.rs`).
///
/// It holds its append handle and its coverage. Named for the shape the five
/// files share, never for a class: the attest store is no projection below
/// the reclaim floor, so a class word here would mislabel the one file whose
/// lines there are an entry signature's only copy.
pub(super) struct LineFile {
    file: File,
    dir: PathBuf,
    name: &'static str,
    coverage: u64,
    /// The classed door with the daemon's record ([`Lines`]).
    ///
    /// It is what the file's stop is said through, once per uptime: a failed
    /// append's ([`LineFile::append_or_report`]) or a rewrite's.
    lines: Lines,
    /// Where this file stopped this uptime, `None` while it takes lines.
    ///
    /// It is set by the first failed [`LineFile::append`] of this uptime — or
    /// failed [`LineFile::sync`], or an owed sync that failed
    /// ([`LineFile::stop_after_a_failed_sync`]), or a [`LineFile::rewrite`]
    /// that failed past its rename, or the walk's landing over a rewrite that
    /// failed before it ([`LineFile::stop_at`]) — after which this file takes
    /// no further append and no fence. `Some` carries the position the stop was
    /// set at — the position the stop's own line names, an ordering the
    /// standing line re-says the stop by (`operations.md` §1 the rates,
    /// `{file} stopped since position {p}`): the failed append's position; the
    /// coverage a failed sync was asked to make durable; the fence a rewrite
    /// failed past its rename at, or the region's lower edge a landing left the
    /// file fenced at, which is what the next open re-derives from.
    ///
    /// [`LineFile::rewrite`] is not guarded by it: it writes the file whole
    /// from the resident twin and fences at the coverage it has just made true,
    /// so it closes a gap rather than claiming over one — the opposite of what
    /// this flag guards against — and a stopped file rewritten whole is right
    /// on disk again while the flag stands for the uptime. What a rewrite can
    /// do is set it, and a rewrite past its rename on a file already stopped
    /// moves it to the newest fence. At open every rewrite's failure is fatal —
    /// `?`-propagated into `DaemonError::Sidecar` before any append — so the
    /// flag is moot there; but the checkpoint thread's compaction runs the same
    /// rewrite while serving, and one that fails past its rename leaves this
    /// handle naming the replaced file, which no open reads: the file stops,
    /// said once per uptime at the transition, and the next open re-derives
    /// from the rewritten file's own fence.
    ///
    /// **Coverage is a claim**, and a gap beneath it is the one loss the check
    /// cannot close: a position at or below coverage with no record reads as
    /// "contributed nothing", which for `feed-index.log` is a `[]`-docs entry
    /// and so is never masked. A failed append leaves coverage where it stands,
    /// and the next successful one would raise it past the gap — so the file
    /// stops instead, its on-disk coverage stays below the failure, and the
    /// next open's tail derivation re-covers the failure and every position
    /// after it from `commits.log`. The resident twin is updated ahead of every
    /// append, so this uptime still answers correctly; what stops is the
    /// testimony, which is what the next open reads.
    stopped: Option<u64>,
    /// The coverage the last successful sync made durable.
    ///
    /// It is set in [`LineFile::sync`]'s own success arm, or where an owed sync
    /// that succeeded is settled ([`LineFile::settle`]), so no line reads as
    /// synced that no `sync_data` covered.
    #[cfg(any(test, feature = "test-hooks"))]
    synced: u64,
    /// The test seam that fails the next rewrite past its rename.
    ///
    /// It is behind `skepd::Daemon::fail_the_feeds_next_rewrite_past_rename`:
    /// the next [`LineFile::rewrite`] fails at the reopen of the file it has
    /// just renamed into place, so the stop that arm carries is reachable
    /// without a disk that fails on cue.
    #[cfg(any(test, feature = "test-hooks"))]
    fail_next_rewrite_past_rename: bool,
}

/// A line appended and its sync owed, [`LineFile::append_owing_sync`]'s answer.
///
/// It names the position whose line is written and not yet durable. The
/// caller makes it durable through the file's [`SyncHandle`] and then spends
/// this: where the sync failed, on [`LineFile::stop_after_a_failed_sync`];
/// where it was made, by dropping it — under the test seam, on
/// `LineFile::settle`, which moves the seam's mark to it.
#[must_use = "the line is not durable until its sync is made and settled"]
pub(super) struct OwedSync {
    /// The position whose line awaits its sync.
    pub(super) at: u64,
}

/// A second handle on a line file, for its sync alone.
///
/// It is the file's own open handle duplicated ([`LineFile::sync_handle`]),
/// one open file, so a sync through it makes durable every line the file's
/// handle wrote; and it syncs through a shared borrow, so the attest store's
/// line is made durable off the change feed's lock (`Feed::record`). The
/// attest store's file is rewritten at its open alone, ahead of the
/// handle's duplication, so the handle names that file for the uptime.
pub(super) struct SyncHandle(File);

impl SyncHandle {
    /// Syncs the file's data to disk (`sync_data`).
    ///
    /// # Errors
    ///
    /// The OS refused the sync; whether the lines reached the disk is then
    /// unknown.
    pub(super) fn sync(&self) -> io::Result<()> {
        self.0.sync_data()
    }
}

/// The entries a line file replays, which its caller *keeps*.
///
/// Each is a position-carrying record, `(position, the record's object)`, in
/// file order. A fence carries no position and so is not one of these; it is
/// folded into the coverage.
pub(super) type Entries = Vec<(u64, Map<String, Value>)>;

/// What a line file's replay cut and dropped, each its caller's to say.
///
/// [`LineFile::open`] answers it beside the entries: the [`Cut`] where trust
/// ended before the file's end, and the entry lines past the head it purged
/// ([`EntryLines`]) — each with the file the dropped bytes were kept in,
/// where they were ([`keep_dropped_lines`]): a damaged line's cut, never a
/// torn line's, and every purge. A derived file re-derives both; the attest
/// store says each, its lines being primary below the reclaim floor.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct Replayed {
    /// The cut, or `None` for a file read whole.
    pub cut: Option<Cut>,
    /// The file the cut bytes were kept in, where the cut was a damaged
    /// line's.
    pub kept: Option<KeptName>,
    /// The entry lines past the head, or `None` where the file named none.
    pub foreign: Option<EntryLines>,
    /// The file the entry lines past the head were kept in, where it named
    /// any.
    pub foreign_kept: Option<KeptName>,
}

impl LineFile {
    /// Replays `name` in `dir` a line at a time.
    ///
    /// It truncates at the first line that is torn or does not parse —
    /// answering the cut to the caller ([`Cut`]: the trusted end, the length
    /// before it and the last trusted position, which is the coverage the
    /// scan reached; the position the cut line names where it is a torn line
    /// at the file's end whose `at` stands whole; and, past a damaged line,
    /// the whole entry lines the cut takes with it, read before the
    /// truncation), never saying it here, since the case is the caller's: a
    /// derived file re-derives the cut part, the attest store says which side
    /// of the reclaim floor it lies on — drops what describes another journal
    /// (rewriting the file without it, and answering the entry lines dropped,
    /// [`EntryLines`]), and hands back the entries at or below `head` that
    /// `keep` admits, with the file's coverage — which counts every trusted
    /// line at or below `head`, kept or not. What it drops in class B it
    /// keeps beside the file first, durably ([`keep_dropped_lines`]): the
    /// bytes from a damaged line — one ended by its newline that does not
    /// parse, which no crash leaves — to the file's end, and the entry lines
    /// above the head; a torn last line is cut and gone. Every answer rides
    /// [`Replayed`]: `None` for the cut is a file read whole, `None` for the
    /// foreign lines a file naming no entry past the head, and each kept
    /// name `None` where nothing was kept.
    ///
    /// `lines` is the classed door the file keeps for its stop's line while
    /// serving, a failed append's or a rewrite's; the open says through it a
    /// rewrite's temp file found beside the file (`operations.md` §1.1 m8;
    /// [`say_a_compact_twin`]).
    ///
    /// The scan holds one line and the kept entries, never the file. The
    /// attest store's file is never compacted (`attest.rs`), so a replay that
    /// held every line would hold the store's whole history at every open —
    /// order twice the file, a line for every attested commit the board ever
    /// made — and the open that cannot afford it is the restart a crash leaves.
    ///
    /// # Errors
    ///
    /// Every failure names this file, the kind kept (`operations.md` §1.1 row
    /// 2): one closure wraps each `?` the open takes on the file — the open,
    /// the read, the length, the truncation, the purge — as the blocked list's
    /// read wraps its path, so the daemon's `change-feed sidecar: {e}` reads
    /// `{name}: {e}`.
    pub(crate) fn open(
        dir: &Path,
        name: &'static str,
        head: u64,
        keep: impl Fn(u64) -> bool,
        lines: &Lines,
    ) -> io::Result<(LineFile, Entries, Replayed)> {
        let with_file = |e: io::Error| io::Error::new(e.kind(), format!("{name}: {e}"));
        say_a_compact_twin(lines, dir, name);
        let path = dir.join(name);
        let file = open_line_file(&path).map_err(with_file)?;
        let mut coverage = 0u64;
        let mut entries = Vec::new();
        let mut foreign = false;
        let mut foreign_entries = None;
        // The byte the first entry line above the head begins at: where the
        // purge's keep is named from.
        let mut first_foreign: Option<u64> = None;
        let mut valid_end = 0u64;
        let mut reader = BufReader::new(&file);
        let mut line = Vec::new();
        loop {
            line.clear();
            let read = reader.read_until(b'\n', &mut line).map_err(with_file)?;
            // Trust ends at the first line that is torn — no newline, the end
            // of the file included — or does not parse.
            let Some(record) = line.strip_suffix(b"\n").and_then(parse_line) else { break };
            let offset = valid_end;
            valid_end += read as u64;
            match record {
                Record::Fence(n) if n <= head => coverage = coverage.max(n),
                Record::Entry(at, m) if at <= head => {
                    coverage = coverage.max(at);
                    if keep(at) {
                        entries.push((at, m));
                    }
                }
                Record::Entry(at, _) => {
                    foreign = true;
                    first_foreign.get_or_insert(offset);
                    foreign_entries = Some(EntryLines::with(foreign_entries, at));
                }
                Record::Fence(_) => foreign = true,
            }
        }
        // The line the scan stopped on, read for the caller's case: a torn
        // line — no newline, the file's end — names its own position where
        // its `at` stands whole; a whole line that does not parse is damage,
        // its digits no witness, and the whole lines after it are read on —
        // and it is the cut's class: a damaged line's cut is kept, a torn
        // line's is gone.
        let damaged = line.ends_with(b"\n");
        let (first, whole_after) = if damaged {
            let mut whole_after = None;
            loop {
                line.clear();
                if reader.read_until(b'\n', &mut line).map_err(with_file)? == 0 {
                    break;
                }
                if let Some(Record::Entry(at, _)) = line.strip_suffix(b"\n").and_then(parse_line) {
                    if at <= head {
                        whole_after = Some(EntryLines::with(whole_after, at));
                    }
                }
            }
            (None, whole_after)
        } else {
            (torn_position(&line).filter(|&at| at > coverage && at <= head), None)
        };
        drop(reader);
        let len = file.metadata().map_err(with_file)?.len();
        let (cut, kept) = if valid_end < len {
            // A damaged line's cut is kept first, from the file itself —
            // the bytes from the trusted end on, never held whole in memory
            // — durably, before the truncation; a torn line's is not.
            let kept = if damaged {
                (&file).seek(SeekFrom::Start(valid_end)).map_err(with_file)?;
                let dropped = (&file).take(len - valid_end);
                Some(keep_dropped_lines(dir, name, valid_end, dropped).map_err(with_file)?)
            } else {
                None
            };
            // Cut, and answered: the caller says it, with its own case — in
            // the attest store the cut can take primary state with it.
            file.set_len(valid_end).map_err(with_file)?;
            (Some(Cut { valid_end, len, trusted: coverage, first, whole_after }), kept)
        } else {
            (None, None)
        };
        let mut this = LineFile {
            file,
            dir: dir.to_path_buf(),
            name,
            coverage,
            lines: lines.clone(),
            stopped: None,
            #[cfg(any(test, feature = "test-hooks"))]
            synced: 0,
            #[cfg(any(test, feature = "test-hooks"))]
            fail_next_rewrite_past_rename: false,
        };
        let mut foreign_kept = None;
        if foreign {
            // Purge what is not this journal's, once, so it cannot come back
            // — its entry lines kept beside the file first.
            foreign_kept = this.purge_foreign(head, first_foreign).map_err(with_file)?;
        }
        Ok((this, entries, Replayed { cut, kept, foreign: foreign_entries, foreign_kept }))
    }

    /// Returns the file's length in bytes, as its handle reads it.
    ///
    /// # Errors
    ///
    /// The handle's metadata could not be read.
    pub(crate) fn len(&self) -> io::Result<u64> {
        self.file.metadata().map(|m| m.len())
    }

    /// Returns the file's coverage.
    ///
    /// Every position at or below it is processed into the file.
    pub(crate) fn coverage(&self) -> u64 {
        self.coverage
    }

    /// Returns the first position this file has *not* processed.
    ///
    /// It is one past its coverage, and where each open's re-derivation of
    /// its missing tail begins. The `+ 1` is what the fence *means*
    /// ([`LineFile::coverage`]: every position at or below it is
    /// processed), so that reading is a fact of this type rather than of the
    /// arithmetic each caller would otherwise spell — one per derived
    /// structure in [`super::Feed::open`], over two different maps. The
    /// attest store's rebuild asks the kernel for the boundaries *above* its
    /// coverage itself, in one scan, and reads [`LineFile::coverage`].
    ///
    /// Saturating, so a file covering `u64::MAX` answers `u64::MAX` and its
    /// tail is the empty range rather than a wrap to genesis.
    pub(crate) fn first_uncovered(&self) -> u64 {
        self.coverage().saturating_add(1)
    }

    /// Appends one record for `at` with the file's own fields.
    ///
    /// The record takes the shape [`record_object`] fixes — so an appended
    /// line and the rewritten line that reproduces it are one spelling rather
    /// than two that must agree.
    ///
    /// A file [`LineFile::stopped`] closed takes nothing and answers `Ok`:
    /// the failure was reported once, where it was raised, and this file's
    /// on-disk coverage must not rise past the gap it left.
    ///
    /// # Errors
    ///
    /// The OS refused the write, which stops the file at `at`: it takes no
    /// further line this uptime.
    pub(crate) fn append(&mut self, at: u64, fields: Vec<(&'static str, Value)>) -> io::Result<()> {
        if self.stopped.is_some() {
            return Ok(());
        }
        if let Err(e) = self.file.write_all(&line_bytes(&record_object(at, fields))) {
            self.stopped = Some(at);
            return Err(e);
        }
        self.coverage = self.coverage.max(at);
        Ok(())
    }

    /// Appends one record and reports a failed write rather than returning it.
    ///
    /// It is the record-time disposition, where the commit has landed and the
    /// ack is owed whatever this file does. [`LineFile::append`] keeps the
    /// fallible form for [`super::Feed::open`], which propagates into
    /// `DaemonError::Sidecar`: at open nothing is owed yet, so a data dir that
    /// cannot take a write the kernel just performed is an operator condition
    /// worth reporting rather than limping past.
    ///
    /// The line names *this* file, from the name this handle already holds,
    /// so no caller pairs a handle with a file-name constant, and goes through
    /// the classed door this file holds (`operations.md` §1.1 row 32): the
    /// position, the cause ([`IoCause`]), the stop, that the board serves
    /// from memory and loses nothing, and the act owed before the restart,
    /// whose open writes the file ([`IoCause::before_the_restart`]). One per
    /// file per uptime: [`LineFile::stopped`] answers `Ok` and writes nothing
    /// after the first failure, so a busy board's stream carries it alone, and
    /// that field's own card says what the stop buys.
    pub(crate) fn append_or_report(&mut self, at: u64, fields: Vec<(&'static str, Value)>) {
        if let Err(e) = self.append(at, fields) {
            let cause = IoCause(&e);
            self.lines.say(
                Class::Failure,
                format_args!(
                    "{} append failed at position {at}: {cause}; this file takes no further line \
                     until a restart, whose open re-derives it — the board serves from memory, \
                     and nothing is lost{}",
                    self.name,
                    cause.before_the_restart()
                ),
            );
        }
    }

    /// Appends one record whose sync the caller owes, refusing a stopped file.
    ///
    /// It is the attest store's record-time append (SO-I5 (d)): there a line
    /// below the reclaim floor is an entry signature's only copy, so it must
    /// be on disk before any later commit, which could reclaim the journal's
    /// copy, can begin. The line is written here and made durable through
    /// the file's [`SyncHandle`] — off any lock the caller holds over this
    /// file — and the answer ([`OwedSync`]) is the sync owed, which a failed
    /// sync spends on [`LineFile::stop_after_a_failed_sync`]. The four
    /// derived files never take it; what they lose the next open re-derives.
    ///
    /// # Errors
    ///
    /// A failed write, which stops the file, or a file already stopped: a
    /// stopped file takes nothing and answers an error, never `Ok` — a line
    /// it did not write is no durable line. Either is answered, never
    /// reported here: the caller owes the failure a disposition of its own.
    pub(crate) fn append_owing_sync(
        &mut self,
        at: u64,
        fields: Vec<(&'static str, Value)>,
    ) -> io::Result<OwedSync> {
        if self.stopped.is_some() {
            return Err(io::Error::other(format!("{} stopped at an earlier failure", self.name)));
        }
        self.append(at, fields)?;
        Ok(OwedSync { at })
    }

    /// Returns a second handle on this file, for its sync alone.
    ///
    /// It is this file's open handle duplicated ([`SyncHandle`]).
    ///
    /// # Errors
    ///
    /// The OS refused to duplicate the handle.
    pub(crate) fn sync_handle(&self) -> io::Result<SyncHandle> {
        self.file.try_clone().map(SyncHandle)
    }

    /// Settles `owed`, its sync through the file's [`SyncHandle`] made.
    ///
    /// It moves the test seam's mark ([`LineFile::synced`]) and nothing else.
    #[cfg(any(test, feature = "test-hooks"))]
    pub(crate) fn settle(&mut self, owed: OwedSync) {
        self.synced = owed.at;
    }

    /// Stops the file after `owed`'s sync failed, as a failed sync stops it.
    ///
    /// Whether the lines reached the disk is then unknown, so the file takes
    /// no further line from the position the sync was owed for
    /// ([`LineFile::sync`]'s failure arm); a file already stopped keeps its
    /// stop.
    pub(crate) fn stop_after_a_failed_sync(&mut self, owed: OwedSync) {
        self.stopped.get_or_insert(owed.at);
    }

    /// Syncs the file's data to disk (`sync_data`).
    ///
    /// Every line appended so far is made durable.
    ///
    /// # Errors
    ///
    /// The OS refused the sync, which stops the file as a failed append does
    /// — whether the lines reached the disk is then unknown, and the next
    /// open's replay is what decides what it covers.
    pub(crate) fn sync(&mut self) -> io::Result<()> {
        match self.file.sync_data() {
            Ok(()) => {
                #[cfg(any(test, feature = "test-hooks"))]
                {
                    self.synced = self.coverage;
                }
                Ok(())
            }
            Err(e) => {
                self.stopped = Some(self.coverage);
                Err(e)
            }
        }
    }

    /// The test seam behind `skepd::Daemon::attest_store_synced_through`.
    ///
    /// It answers the coverage the last successful sync made durable — every
    /// position at or below it whose line this file holds is on disk. Not a
    /// stable API.
    #[cfg(any(test, feature = "test-hooks"))]
    pub(crate) fn synced(&self) -> u64 {
        self.synced
    }

    /// The test seam behind `skepd::Daemon::fail_the_attest_stores_next_write`.
    ///
    /// It swaps this file's handle for a read-only one on the same file, so
    /// its next write fails at the OS, as a full or failing disk's would, and
    /// the failure takes the path a real one takes. Not a stable API.
    ///
    /// # Errors
    ///
    /// The OS refused to open the file read-only.
    #[cfg(any(test, feature = "test-hooks"))]
    pub(crate) fn make_unwritable(&mut self) -> io::Result<()> {
        self.file = File::open(self.dir.join(self.name))?;
        Ok(())
    }

    /// The test seam that fails the next rewrite past its rename.
    ///
    /// It is behind `skepd::Daemon::fail_the_feeds_next_rewrite_past_rename`:
    /// the next [`LineFile::rewrite`] fails past its rename, at the reopen.
    /// Not a stable API.
    #[cfg(any(test, feature = "test-hooks"))]
    pub(crate) fn fail_next_rewrite_past_rename(&mut self) {
        self.fail_next_rewrite_past_rename = true;
    }

    /// Returns the stop as a read: the position this file's stop was set at.
    ///
    /// [`LineFile`]'s `stopped` says which position each cause carries, and
    /// the answer is `None` while the file takes lines — what the standing
    /// line re-says a stopped file by, once an hour while it stands.
    pub(crate) fn stopped_since(&self) -> Option<u64> {
        self.stopped
    }

    /// Stops the file at `at`, as a failed append stops it.
    ///
    /// It is the walk's landing's stop: a rewrite there that failed before
    /// its rename leaves the file whole and fenced at the region's lower edge
    /// `at`, short of the region and of every write held while it pended, so
    /// a later append would raise its coverage claim over that gap. A file
    /// already stopped keeps its stop.
    pub(crate) fn stop_at(&mut self, at: u64) {
        self.stopped.get_or_insert(at);
    }

    /// Returns whether this file takes no further line.
    ///
    /// It is the unit suite's reading of the stop. Not a stable API.
    #[cfg(test)]
    pub(crate) fn is_stopped(&self) -> bool {
        self.stopped.is_some()
    }

    /// Appends the coverage fence `{"covered":N}`.
    ///
    /// It is a no-op when the file already covers `covered`, and a no-op on a
    /// stopped file, whose coverage claim must stay below the position it
    /// lost.
    ///
    /// # Errors
    ///
    /// The OS refused the write.
    pub(crate) fn fence(&mut self, covered: u64) -> io::Result<()> {
        if self.stopped.is_some() || covered <= self.coverage {
            return Ok(());
        }
        self.file.write_all(&fence_line(covered))?;
        self.coverage = covered;
        Ok(())
    }

    /// Appends the coverage fence and reports a failed write rather than
    /// returning it.
    ///
    /// It is the walk's disposition for the index file it appends as it
    /// sorts the bare positions the index lost (`Feed::land_sorted`): the
    /// position is sorted whatever this file does, so a failed fence is
    /// reported through the classed door in [`LineFile::append_or_report`]'s
    /// words, naming the fence's position, and stops the file at it — a file
    /// whose claim cannot be raised takes no further line, and the next open
    /// re-derives above its fence. A stopped file takes nothing and says
    /// nothing, as [`LineFile::fence`] does.
    pub(crate) fn fence_or_report(&mut self, covered: u64) {
        if let Err(e) = self.fence(covered) {
            self.stopped = Some(covered);
            let cause = IoCause(&e);
            self.lines.say(
                Class::Failure,
                format_args!(
                    "{} append failed at position {covered}: {cause}; this file takes no further \
                     line until a restart, whose open re-derives it — the board serves from \
                     memory, and nothing is lost{}",
                    self.name,
                    cause.before_the_restart()
                ),
            );
        }
    }

    /// Rewrites the whole file as `records` behind a fence at `covered`.
    ///
    /// It goes through a temp file renamed over the original — the compaction
    /// from the twins, at open and after each checkpoint the daemon's thread
    /// lands. `records` are whole record objects already carrying their
    /// `at`; [`super::super::sidecar::line_bytes`] is what makes each a
    /// line.
    ///
    /// # Errors
    ///
    /// [`RewriteFail`], which carries the side of the rename a failure fell
    /// on, since the two leave different files behind: *before* it the old
    /// file stands whole and this handle still names it, nothing lost, the
    /// next checkpoint's compaction trying again — save at the walk's
    /// landing, where the old file is short of the region and the landing
    /// stops it ([`LineFile::stop_at`]); *past* it the new file is in place
    /// and this handle names the *replaced* one, which no open reads, so the
    /// file is stopped for the uptime as a failed append stops it — said once
    /// per uptime, here, at the stop's transition (`operations.md` §1.1 row
    /// 30): a stopped file is rewritten again at every compacting landing, its
    /// stop moving in silence to the newest fence where that rewrite fails
    /// past its rename again, the standing line re-saying it — its coverage
    /// the fence the new file carries, which the next open re-derives from.
    /// At open either side is fatal; while serving the caller reports the
    /// before-rename arm and moves on.
    pub(crate) fn rewrite(&mut self, records: Vec<Value>, covered: u64) -> Result<(), RewriteFail> {
        let path = self.dir.join(self.name);
        let tmp = self.dir.join(format!("{}.compact", self.name));
        let mut out = Vec::new();
        for record in &records {
            out.extend_from_slice(&line_bytes(record));
        }
        out.extend_from_slice(&fence_line(covered));
        let renamed = (|| -> io::Result<()> {
            let mut f = create_rewrite_temp(&tmp)?;
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
            open_line_file(&path)
        };
        #[cfg(not(any(test, feature = "test-hooks")))]
        let reopened = open_line_file(&path);
        self.coverage = covered;
        match reopened {
            Ok(file) => {
                self.file = file;
                Ok(())
            }
            Err(e) => {
                let first = self.stopped.is_none();
                self.stopped = Some(covered);
                if first {
                    self.lines.say(
                        Class::Failure,
                        format_args!(
                            "{} rewrite failed past its rename: {}; this file takes no further \
                             line, so the next open re-derives above its fence at position {}",
                            self.name,
                            IoCause(&e),
                            covered
                        ),
                    );
                }
                Err(RewriteFail::PastRename(e))
            }
        }
    }

    /// Rewrites the file without another journal's lines, kept first.
    ///
    /// Every entry line at or below `head` is copied verbatim, in file order,
    /// then one fence at the coverage — through `<file>.compact` renamed over
    /// the original, a line at a time as [`LineFile::open`]'s scan is. A line
    /// is copied whether or not a caller kept it: in the attest store a line
    /// no caller keeps lies below the floor and is an entry signature's only
    /// copy, so its bytes are moved and never re-rendered. The file is already
    /// cut at its trusted end, so every line read here is whole. The entry
    /// lines above `head` — another journal's, or the cut commits' own after
    /// a journal tail cut — are kept beside the file before the rewrite
    /// ([`keep_dropped_lines`]), named by `first_foreign`, the byte the first
    /// of them begins at, and gathered in memory first: they are the lines a
    /// copy holds past its journal's head, a bounded few. Answers the kept
    /// name, `None` where no entry line lay above the head (a fence alone).
    ///
    /// # Errors
    ///
    /// The OS refused the keep, the temp file's creation, a read, a write,
    /// the sync, the rename or the reopen.
    fn purge_foreign(
        &mut self,
        head: u64,
        first_foreign: Option<u64>,
    ) -> io::Result<Option<KeptName>> {
        let path = self.dir.join(self.name);
        let kept = match first_foreign {
            Some(byte) => {
                let mut above_the_head = Vec::new();
                let mut reader = BufReader::new(File::open(&path)?);
                reader.seek(SeekFrom::Start(byte))?;
                let mut line = Vec::new();
                while reader.read_until(b'\n', &mut line)? > 0 {
                    if let Some(Record::Entry(at, _)) =
                        line.strip_suffix(b"\n").and_then(parse_line)
                    {
                        if at > head {
                            above_the_head.extend_from_slice(&line);
                        }
                    }
                    line.clear();
                }
                Some(keep_dropped_lines(&self.dir, self.name, byte, above_the_head.as_slice())?)
            }
            None => None,
        };
        let tmp = self.dir.join(format!("{}.compact", self.name));
        let mut out = BufWriter::new(create_rewrite_temp(&tmp)?);
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
        self.file = open_line_file(&path)?;
        Ok(kept)
    }
}

/// Opens a line file for reading and appending, created where absent.
///
/// It is born `0600` on unix, the mode set at creation, which the process
/// umask can narrow and never widen; a file that already stands keeps its
/// mode. It is the one open every line file takes, the attest store's
/// included: at the replay, and after each rewrite's rename.
///
/// # Errors
///
/// The OS refused the open.
fn open_line_file(path: &Path) -> io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.create(true).read(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
}

/// Creates a rewrite's temp file afresh.
///
/// It is born `0600` on unix, the mode set at creation, which the rename
/// carries onto the line file.
///
/// # Errors
///
/// The OS refused the creation.
fn create_rewrite_temp(path: &Path) -> io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
}

/// Returns one record object for `at` from its fields.
///
/// It is *the* shape every entry line of a [`LineFile`] takes, in both
/// directions: [`LineFile::append`] writes it and a rewrite reproduces it,
/// so each file's field name is spelled once and a compacted file's lines
/// are byte-identical to appended ones. The `at` key is added here, so a
/// record cannot omit it.
pub(super) fn record_object(at: u64, fields: Vec<(&'static str, Value)>) -> Value {
    let mut pairs = fields;
    pairs.push(("at", Value::Number(at.into())));
    obj(pairs)
}

fn fence_line(covered: u64) -> Vec<u8> {
    line_bytes(&obj(vec![("covered", Value::Number(covered.into()))]))
}

/// Returns the position a torn line names, where its `at` stands whole.
///
/// A line is a key-sorted object, so `"at":` comes ahead of every string
/// member — `alg` sorts before it and every other field after — and a torn
/// line is a prefix of the line its append was writing. Its digits stand
/// whole where the separator the whole line carries after them, `,` or `}`,
/// stands too; a tear inside them, or bytes holding no `"at":` key with digits
/// and a separator after it, a volume's zero-fill among them, answer `None`.
fn torn_position(fragment: &[u8]) -> Option<u64> {
    const KEY: &[u8] = b"\"at\":";
    let start = fragment.windows(KEY.len()).position(|w| w == KEY)? + KEY.len();
    let rest = &fragment[start..];
    let digits = rest.iter().take_while(|b| b.is_ascii_digit()).count();
    if digits == 0 || !matches!(rest.get(digits), Some(b',' | b'}')) {
        return None;
    }
    std::str::from_utf8(&rest[..digits]).ok()?.parse().ok()
}

/// Parses one line's record, the line without its newline.
///
/// The record is a fence, or an entry with a position. Anything else answers
/// `None`: a line that does not parse.
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
    /// Returns a [`LineFile`] whose appends *fail*.
    ///
    /// It holds a read-only handle on the file in `dir`, which is the one
    /// condition the stop rule is about and the one no portable test can
    /// produce from [`LineFile::open`]'s handle.
    ///
    /// # Panics
    ///
    /// Panics where the file cannot be created, or opened read-only.
    fn over_unwritable(dir: &Path, name: &'static str, coverage: u64) -> LineFile {
        let path = dir.join(name);
        File::create(&path).expect("create the file to be opened read-only");
        let file = File::open(&path).expect("a read-only handle");
        LineFile {
            file,
            dir: dir.to_path_buf(),
            name,
            coverage,
            lines: Lines::new(),
            stopped: None,
            synced: 0,
            fail_next_rewrite_past_rename: false,
        }
    }
}

#[cfg(test)]
mod tests;
