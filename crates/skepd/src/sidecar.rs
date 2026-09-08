//! The commit-metadata sidecar (wire v6): `commits.log` in the data dir —
//! one JSON line per committed write `(position, op kind, affected docs,
//! unix millis, key testimony)`, appended by the write path at ack time and
//! replayed on reopen. This is daemon-owned TRANSPORT METADATA, never
//! substrate state (wire.md §The change feed) — exempt from the
//! no-second-persistence-layer rule for the same reason as the kernel's
//! journal-lock file: it persists nothing about the WORLD, since two
//! daemons replaying one journal still converge on byte-identical worlds.
//! The sidecar is the daemon's testimony about its own service, and it
//! feeds `GET /changes` and `/health`'s `head_time`.
//!
//! This file is the feed's AUTHORITY file: what a position's entry SAYS —
//! its op, its docs, its time, its key — is recorded here and nowhere else.
//! The feed's four DERIVED sidecars (`feed/derived.rs`: the per-document
//! position index, the offset array, the masked-position bitmap and the
//! per-owner draft streams; PUB-7.19) are projections of this file and the
//! journal, rebuilt from them on loss; `feed/mod.rs` composes the five.
//!
//! Crash honesty is the contract:
//!
//! * A torn tail is truncated at the last whole record on open — trust ends
//!   at the first unparseable line; the daemon never wedges on its own
//!   testimony.
//! * Positions whose record was lost, or that predate the feature, are
//!   reconstructed as BARE positions and answer `op`/`docs`/`time` as
//!   `null`. NEVER an invented value.
//! * Reconstruction uses the one public journal-fed surface the daemon
//!   already holds — the engine's bounded replay (`Engine::world_at`):
//!   walking down from the head, an `Ok` probe proves a boundary, a
//!   `NotABoundary { nearest }` names the next one below, and any other
//!   error (reclaimed, corrupt, I/O) honestly ends the feed's reach there —
//!   recorded as the smallest `since` this feed can honor, under which
//!   `/changes` answers the same 410 discipline as `/op-at`. The kernel's
//!   own journal reader stays closed. Reconstructed positions are appended
//!   to the file, so the walk runs once per uncovered region, not once per
//!   open.
//! * A bare position CLASSIFIES FROM THE JOURNAL (PUB-6.45: "a lost sidecar
//!   never unmasks a draft write"): the walk holds the world at each
//!   boundary and the one below it, and the diff of the two — the drafts
//!   minted, the links deposited (their homes, and a retraction's targets'
//!   homes), the drafts whose arrangement moved (`feed::classify::derived_docs`)
//!   — is the set of documents the feed's mask classifies the position by.
//!   The wire entry still answers `docs: null` (lost testimony is never
//!   invented); what the journal supplies is the CLASS, so a draft write
//!   whose record was lost is omitted from a guest's page exactly as a
//!   recorded one is. A boundary whose predecessor world the journal can no
//!   longer answer (the oldest boundary above a reclaimed region) is
//!   UNCLASSIFIABLE and is served to every class: it discloses its position
//!   alone, which `/events` and `head_time` already disclose board-wide
//!   (PUB-6.52's accepted residue), and nothing of what it wrote.
//!
//! The file — and the entries replayed from it — are bounded by the
//! journal's own retention, not by the world's age. Positions the journal has
//! reclaimed are unanswerable across the whole history surface, so at open
//! the sidecar drops its entries below that floor and rewrites itself
//! around them (see [`CommitsLog::open`]). Without that the feed's memory
//! would be the only structure in the daemon that grows with total commits
//! ever made rather than with commits still reachable, and it is fully
//! resident.
//!
//! The sidecar is written under the write path's serialization lock — held
//! by `write_path.rs`, which takes that lock and calls the feed's `record`
//! in one operation — so file order is position order and recorded times
//! are monotone non-decreasing in position (wall-clock reads are
//! additionally clamped against the last recorded time). Appends are
//! flushed to the OS but not fsynced — a lost tail answers bare, which is
//! the honest trade for not doubling every write's fsync cost on testimony.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;
use skep_address::Address;
use skep_engine::{Engine, HistoryError, World};
use skep_kernel::Seq;

use crate::codec::{obj, to_bytes};
use crate::feed::classify::derived_docs;

/// The sidecar's file name inside the data dir (beside the kernel's own
/// journal/checkpoint files, which this crate never touches).
pub(crate) const SIDECAR_FILE: &str = "commits.log";

/// One committed position's metadata — and this file's crash-honesty rule
/// as a type. A position is either one the daemon OBSERVED committing,
/// carrying all of op/docs/time, or a BARE one reconstructed from the
/// journal, carrying none of them. Three independent `Option`s would admit
/// six more combinations, and this file has a meaning for neither the
/// half-recorded position nor the record that remembers when but not what.
#[derive(Clone, Debug)]
pub(crate) enum CommitMeta {
    /// Reconstructed, not witnessed: served as explicit `null`s, never as
    /// an invented value. Its CLASS — which documents the journal shows it
    /// touched — lives in the feed's classification map, not here: this
    /// file records testimony, and the journal's answer is not testimony.
    Bare,
    /// Witnessed at ack time by the daemon's own write path. `key` is the
    /// AUTH testimony (AUTH-4.48): the fingerprint hex of the enrolled key
    /// that established the authoring session, or `"bare"` for a bare one.
    /// `None` only for a line written before the feature — served as the
    /// reserved null (AUTH-1.52's lost-metadata meaning), never for a
    /// commit this daemon served since.
    Recorded { op: String, docs: Vec<String>, time: u64, key: Option<String> },
}

impl CommitMeta {
    /// One `GET /changes` entry: the position and all four fields, a bare
    /// position's rendering as explicit `null`s — the crash-honesty rule of
    /// this file, expressed where the rule is stated rather than at the
    /// handler. `docs` is the list the FEED renders for a recorded entry —
    /// the record's own docs REDUCED to the requester's readable ones
    /// (PUB-6.45) — and is ignored for a bare one, whose docs are the
    /// reserved null whatever its class. Deliberately NOT [`entry_line`]'s
    /// convention, which omits absent fields: the file is daemon-private and
    /// [`parse_line`] reads absent and null alike, so the shorter line costs
    /// nothing there, while a client reading the wire is owed the field it
    /// asked about.
    pub fn entry(&self, at: u64, docs: Vec<String>) -> Value {
        let (docs, op, time, key) = match self {
            CommitMeta::Bare => (Value::Null, Value::Null, Value::Null, Value::Null),
            CommitMeta::Recorded { op, time, key, .. } => (
                Value::Array(docs.into_iter().map(Value::String).collect()),
                Value::String(op.clone()),
                Value::Number((*time).into()),
                key.clone().map(Value::String).unwrap_or(Value::Null),
            ),
        };
        obj(vec![
            ("at", Value::Number(at.into())),
            ("docs", docs),
            ("key", key),
            ("op", op),
            ("time", time),
        ])
    }

    /// The recorded wall-clock time, or `None` for a bare position.
    fn time(&self) -> Option<u64> {
        match self {
            CommitMeta::Bare => None,
            CommitMeta::Recorded { time, .. } => Some(*time),
        }
    }
}

/// One replayed file record.
#[derive(Debug)]
enum Record {
    Entry(u64, CommitMeta),
    /// The smallest `since` this feed can honor — see [`CommitsLog::min_since`].
    MinSince(u64),
}

/// One bare position the reconstruction walk covered this open, with the
/// journal's classification of it: the documents the commit touched as the
/// world diff shows them (`Some`, possibly empty), or `None` where the
/// world below the boundary could not be answered — unclassifiable, served
/// to every class (the module doc's residue).
#[derive(Debug)]
pub(crate) struct Walked {
    pub at: u64,
    pub docs: Option<Vec<Address>>,
}

/// The replayed `commits.log`: the file handle, every enumerable entry above
/// the fence, and the bookkeeping the feed's derived structures key on.
pub(crate) struct CommitsLog {
    file: File,
    /// Every enumerable position above `min_since`, in order.
    pub entries: BTreeMap<u64, CommitMeta>,
    /// Each entry's line's byte offset in the file — the offset array's
    /// in-memory twin (PUB-7.19), learned from the replay itself and
    /// advanced by every append; a rewrite recomputes it whole.
    pub offsets: BTreeMap<u64, u64>,
    /// The smallest admissible `since`: coverage is complete over
    /// `(min_since, head]`; below it the walk was stopped (reclaimed or
    /// unreadable journal) and `/changes` answers 410. Deliberately not
    /// called a floor — the wire's `floor` is the oldest position still
    /// ANSWERABLE, whereas this is the highest one that is not.
    ///
    /// INVARIANT: `min_since <= head` always. A fence above the head is not
    /// a fact about this journal and is discarded at open, exactly as an
    /// entry above it is — the coverage clause above means something only
    /// under that.
    pub min_since: u64,
    /// The journal head at open — the fence between replayed history and
    /// this uptime's commits. An ack carrying a position at or below it
    /// (an idempotency-cache replay, `emit`'s incumbent ack) is never a
    /// new commit and is never re-recorded.
    pub open_head: u64,
    /// Whether this open REWROTE the file — compaction to the journal's
    /// retention, or the purge of a foreign fence — so every offset moved
    /// and the derived offset array must be rewritten with it.
    pub rewritten: bool,
    /// Monotone clamp for recorded wall-clock times.
    last_time: u64,
    /// The file's length — the offset the next appended line lands at.
    len: u64,
}

impl CommitsLog {
    /// Replay (truncating a torn tail), drop everything the file says about
    /// a journal other than this one — entries beyond the head AND a fence
    /// above it — reconstruct any uncovered `(last recorded, head]` region
    /// as bare positions, classifying each from the journal, and persist
    /// what the reconstruction learned. Returns the replayed log and the
    /// walk's classified positions for the feed's derived structures.
    ///
    /// COST, and the only step of daemon startup that is not O(1) in the
    /// data dir: reconstruction spends one whole-world `Engine::world_at`
    /// per uncovered boundary — a checkpoint deserialize plus a journal
    /// fold each — plus one world diff per boundary for its classification
    /// (`derived_docs` states that cost), so a dir with NO coverage (a
    /// sidecar deleted, arrived corrupt, or written before this feature)
    /// pays that for every boundary the journal still holds, before `open`
    /// returns. The region is bounded below by journal reclamation, so the
    /// ceiling is the retained window, which `server.rs` chooses as
    /// `CHECKPOINT_EVERY_COMMITS × RETAINED_CHECKPOINTS` commits. The
    /// walk's findings are appended here (and its classifications to the
    /// feed's position index), so a covered region is walked once ever
    /// rather than once per open.
    ///
    /// COMPACTION runs at the other end, and is what bounds the file and
    /// the resident entries: positions the journal has reclaimed are refused by
    /// `/op-at` and `/dump?at` alike, so an entry naming one describes a
    /// commit no client can reach by any route. Those entries are dropped
    /// and the file rewritten around them, leaving retention exactly where
    /// wire.md puts it — the feed's memory is the sidecar plus what the
    /// journal can still reconstruct, and below that the same `410
    /// history_reclaimed` discipline `/op-at` answers with.
    ///
    /// The floor is learned by probing position 0, which costs nothing:
    /// genesis is its own base, so a healthy store folds no journal to
    /// answer, and a reclaimed one refuses from the checkpoint listing
    /// alone. The rewrite goes to a temp file and is renamed over the
    /// original, so a crash mid-compaction leaves the whole old file or
    /// the whole new one — never a half of either.
    ///
    /// DISPOSITION, deliberately the opposite of [`CommitsLog::record`]'s:
    /// every I/O failure here is fatal and reaches the caller as
    /// `DaemonError::Sidecar`, including the walk's append, whose loss
    /// would cost only a repeated walk on a later open. At ack time the ack
    /// is already owed, so lost testimony degrades to bare; at open nothing
    /// is owed yet, and a data dir that cannot take a write the kernel just
    /// performed is an operator condition worth reporting rather than
    /// limping past.
    pub fn open(dir: &Path, engine: &Engine) -> io::Result<(CommitsLog, Vec<Walked>)> {
        let path = dir.join(SIDECAR_FILE);
        let mut file = OpenOptions::new().create(true).read(true).append(true).open(&path)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        let (records, valid_end) = parse_records(&bytes);
        if valid_end < bytes.len() {
            // The torn (or corrupt) tail: truncate at the last whole record.
            // Anything the dropped lines described is re-covered as bare
            // positions by the walk below.
            file.set_len(valid_end as u64)?;
        }
        let mut len = valid_end as u64;
        let mut entries = BTreeMap::new();
        let mut offsets = BTreeMap::new();
        let mut min_since = 0u64;
        for (offset, rec) in records {
            match rec {
                Record::Entry(at, meta) => {
                    entries.insert(at, meta);
                    offsets.insert(at, offset as u64);
                }
                Record::MinSince(s) => min_since = min_since.max(s),
            }
        }
        let head = engine.kernel().current_seq().0;
        // Entries beyond this journal's head describe a different journal
        // (an operator swapped files under the sidecar); never serve them.
        if head < u64::MAX {
            let dropped = entries.split_off(&(head + 1));
            for at in dropped.keys() {
                offsets.remove(at);
            }
        }
        // A fence above the head describes that other journal too, and is
        // the half the entry clamp above does not reach. Left standing it
        // makes `(min_since, head]` empty, so `changes` refuses every
        // position this journal HAS — permanently, since nothing re-derives
        // a fence the file already holds — while `/events` announces them
        // and `/op-at` serves them. Discarded, the walk below covers
        // `(last entry, head]` from scratch and the retention probe
        // re-derives the true fence for THIS journal, which is what keeps
        // `min_since <= head`.
        let stale_fence = min_since > head;
        if stale_fence {
            min_since = 0;
        }
        let low = entries.keys().next_back().copied().unwrap_or(0).max(min_since);
        let mut walked = Vec::new();
        if head > low {
            // The walk's own fence, qualified because the accumulator it
            // folds into holds the plain name.
            let (found, walk_min_since) = reconstruct(engine, low, head);
            for w in &found {
                entries.insert(w.at, CommitMeta::Bare);
                offsets.insert(w.at, len);
                let line = entry_line(w.at, &CommitMeta::Bare);
                file.write_all(&line)?;
                len += line.len() as u64;
            }
            if let Some(walked_min) = walk_min_since {
                min_since = min_since.max(walked_min);
                let line = min_since_line(walked_min);
                file.write_all(&line)?;
                len += line.len() as u64;
            }
            walked = found;
        }
        // Compaction: everything the journal has reclaimed leaves the feed
        // with it. The probe answers the oldest position still answerable,
        // so the smallest admissible `since` is the fence just under it —
        // asking `since = F - 1` still yields the whole surviving feed. A
        // reclaimed journal that can name no floor at all leaves this at 0
        // and prunes nothing: the sidecar's own testimony is the half of
        // the feed's memory that does not depend on the journal, and
        // discarding it over a floor nobody can locate would lose the only
        // record of those commits that still exists.
        if let Some(f) = retention_floor(engine) {
            min_since = min_since.max(f.saturating_sub(1));
        }
        // The rewrite is unconditional under a discarded fence, so a journal
        // that later grows past that number cannot resurrect it from the
        // file.
        let mut rewritten = false;
        if stale_fence || entries.keys().next().is_some_and(|&oldest| oldest <= min_since) {
            entries = entries.split_off(&min_since.saturating_add(1));
            let (f, o, l) = rewrite(dir, &entries, min_since)?;
            file = f;
            offsets = o;
            len = l;
            rewritten = true;
            walked.retain(|w| w.at > min_since);
        }
        let last_time = entries.values().filter_map(CommitMeta::time).max().unwrap_or(0);
        Ok((
            CommitsLog { file, entries, offsets, min_since, open_head: head, rewritten, last_time, len },
            walked,
        ))
    }

    /// Record one committed write at ack time; `Some(offset)` — the byte
    /// offset the line landed at — when this call recorded a NEW position,
    /// `None` when it declined. Idempotent against replayed acks: a position
    /// at or below the open-time head, or one already recorded this uptime,
    /// is an ack for an OLD commit (idempotency-cache hit, `emit`
    /// incumbent) — re-recording it would invent a time.
    ///
    /// CALLER CONTRACT — call only while holding the daemon's
    /// write-serialization lock, between a commit and its ack. That is what
    /// makes this file's two invariants true: file order is position order,
    /// and recorded times are monotone non-decreasing in position. The lock
    /// the feed holds around this guards its own state and nothing more, so
    /// calls arriving out of position order would append out of order and
    /// stamp a later position with an earlier time — both silent, both
    /// permanent, and both load-bearing for the feed's paging and
    /// [`CommitsLog::head_time`]. Nothing here can check it, which is why
    /// `write_path.rs` holds the lock and this call in ONE operation and is
    /// the only caller: the obligation is discharged by there being nowhere
    /// else to fail it.
    ///
    /// The clamp against `last_time` below covers the other half of the
    /// monotonicity — a wall clock that steps backwards — and that one IS
    /// this file's own obligation rather than the caller's.
    pub fn record(
        &mut self,
        at: u64,
        op: &'static str,
        docs: Vec<String>,
        key: String,
    ) -> Option<u64> {
        if at <= self.open_head || self.entries.contains_key(&at) {
            return None;
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let time = now.max(self.last_time);
        self.last_time = time;
        let meta = CommitMeta::Recorded { op: op.to_string(), docs, time, key: Some(key) };
        let offset = self.len;
        // Testimony must not fail the op: the write is committed and the
        // ack is owed regardless; a lost append answers bare after restart.
        // Reported without `eprintln!`, which PANICS when the stderr write
        // fails: a daemon whose log pipe has lost its reader would then fail
        // the op this arm exists to keep succeeding, answering
        // `internal_panic` for a write that committed and losing the caller
        // its position. Both failures are swallowed for the one reason.
        let line = entry_line(at, &meta);
        match self.file.write_all(&line) {
            Ok(()) => self.len += line.len() as u64,
            Err(e) => {
                let _ = writeln!(
                    std::io::stderr(),
                    "skepd: commits.log append failed at position {at}: {e}"
                );
            }
        }
        self.entries.insert(at, meta);
        self.offsets.insert(at, offset);
        Some(offset)
    }

    /// The HEAD POSITION's recorded wall-clock time — `None` when the head's
    /// record is bare (lost, or written before the feature) or nothing is
    /// recorded at all.
    ///
    /// Deliberately not "the newest recorded time anywhere in the feed":
    /// this answers FOR THE HEAD, so an older surviving record is not
    /// offered in its place, any more than a bare position's fields are
    /// invented.
    ///
    /// What it reads is the LAST RECORDED position's time, which IS the
    /// head's because every commit is recorded: `WritePath::commit_under`
    /// records and announces inside the guard its caller holds across both,
    /// and `/op` is the only live write path. That premise is this file's
    /// RELIANCE, not its check — a `CommitsLog` never learns the live head
    /// — and two states break it.
    ///
    /// Transiently: any in-flight write. `/health` reads this and the log
    /// position independently and under no lock, so its pair may straddle
    /// one commit and report the previous position's time beside the new
    /// position's number. The next call answers the head again.
    ///
    /// Permanently: a panic between M10's commit and this file's append,
    /// which `serve_connection`'s unwind note names. That position stays
    /// unrecorded until the reopen walk covers it as a bare entry, after
    /// which this honestly answers `None`.
    pub fn head_time(&self) -> Option<u64> {
        self.entries.values().next_back().and_then(CommitMeta::time)
    }
}

/// The oldest position the journal can still answer, or `None` when it can
/// still answer genesis (nothing has been reclaimed) — the bound the feed's
/// retention follows.
///
/// Asked by probing position 0 through the same public replay everything
/// else here uses. The probe is free either way: genesis IS the base a
/// position-0 question selects, so a healthy store folds no journal to
/// answer it, and a reclaimed store refuses from the checkpoint listing
/// before touching a segment. Every other refusal — corrupt, I/O,
/// unjournaled — reports no floor, so the feed keeps what it has rather
/// than discarding entries over a fault that may be transient.
fn retention_floor(engine: &Engine) -> Option<u64> {
    match engine.world_at(Seq(0)) {
        Err(HistoryError::Reclaimed { floor }) => Some(floor.map(|f| f.0).unwrap_or(0)),
        _ => None,
    }
}

/// Rewrite `commits.log` as the surviving entries behind one `min_since`
/// record, and hand back the reopened append handle, the offsets every
/// surviving entry now sits at, and the new length.
///
/// Written to a temp file and renamed over the original, which is what
/// makes compaction crash-honest in the same sense the rest of this file
/// is: a reader only ever sees the whole old file or the whole new one.
/// The alternative — truncating in place — has a window in which the file
/// says the feed remembers nothing, and a crash there would cost the
/// surviving metadata for no reason, since it is exactly the metadata the
/// journal can no longer reconstruct.
///
/// The temp is `commits.log.compact`, a fixed name — safe because
/// [`crate::server::Daemon::open`]'s precondition admits one live kernel
/// per data dir. It is not cleaned up: a crash or an I/O failure between
/// the create and the rename leaves it until the next compaction truncates
/// it, which is the price of the rename being the only atomic step.
fn rewrite(
    dir: &Path,
    entries: &BTreeMap<u64, CommitMeta>,
    min_since: u64,
) -> io::Result<(File, BTreeMap<u64, u64>, u64)> {
    let path = dir.join(SIDECAR_FILE);
    let tmp = dir.join(format!("{SIDECAR_FILE}.compact"));
    let mut out = Vec::new();
    let mut offsets = BTreeMap::new();
    out.extend_from_slice(&min_since_line(min_since));
    for (at, meta) in entries {
        offsets.insert(*at, out.len() as u64);
        out.extend_from_slice(&entry_line(*at, meta));
    }
    let mut f = File::create(&tmp)?;
    f.write_all(&out)?;
    f.sync_all()?;
    drop(f);
    std::fs::rename(&tmp, &path)?;
    let file = OpenOptions::new().create(true).read(true).append(true).open(&path)?;
    Ok((file, offsets, out.len() as u64))
}

/// Enumerate the committed boundaries in `(low, head]`, newest first, via
/// the engine's public bounded replay — `head` is a boundary by definition;
/// an `Ok` probe of `b - 1` proves another; `NotABoundary` jumps to
/// `nearest` — and CLASSIFY each from the journal on the way down: the walk
/// holds the world at the boundary it stands on and, once the boundary
/// below is found, diffs the two (`derived_docs`) for the documents that
/// commit touched. Returns the boundaries (ascending, each with its
/// classification) and, when the journal stopped answering (reclaimed /
/// corrupt / I/O), the smallest `since` the feed can honor from there on —
/// [`CommitsLog::min_since`]'s number, not the wire's `floor`.
///
/// The head's world is the live root (no replay); every other world is one
/// `world_at`. The lowest boundary's predecessor is `low` itself where `low`
/// is a boundary — genesis, or the last recorded position — and where it is
/// a fence (a previous walk's stopping point) its world refuses and the
/// boundary above it is unclassifiable (`docs: None`).
///
/// The descent holds its OWN termination: every step strictly decreases
/// `boundary`, checked here rather than inherited from M2's reading of
/// `nearest`. A `nearest` that did not descend ends the walk, and the
/// region it would have covered is covered as bare entries on a later
/// open — which is the honest outcome, since this runs inside
/// `Daemon::open`, before the listener is bound, where a loop that did not
/// terminate would be a daemon that never starts.
fn reconstruct(engine: &Engine, low: u64, head: u64) -> (Vec<Walked>, Option<u64>) {
    // The world AT `boundary`: the head's is the installed root.
    let mut upper: World = engine.kernel().snapshot().world().clone();
    let mut boundary = head;
    let mut out: Vec<Walked> = Vec::new();
    let mut min_since = None;
    let classify = |below: Option<&World>, upper: &World| below.map(|b| derived_docs(b, upper));
    loop {
        // The descent's own guard: `probe` exists only when there is a
        // position below `boundary` and it is still above `low`, so the step
        // down cannot leave `u64` — a premise this loop holds rather than
        // one it inherits from a caller's range check.
        let Some(probe) = boundary.checked_sub(1).filter(|p| *p > low) else {
            // Nothing between `low` and `boundary`: the boundary below is
            // `low` where `low` is one (genesis, or a recorded position);
            // a fence's world refuses and the position stays unclassified.
            let below = engine.world_at(Seq(low)).ok();
            out.push(Walked { at: boundary, docs: classify(below.as_ref(), &upper) });
            break;
        };
        match engine.world_at(Seq(probe)) {
            Ok(w) => {
                out.push(Walked { at: boundary, docs: classify(Some(&w), &upper) });
                boundary = probe;
                upper = w;
            }
            Err(HistoryError::NotABoundary { nearest }) => {
                // M2's `nearest` is the boundary BELOW the probe, which is
                // what makes this descent terminate. Enforced rather than
                // relied on: a `nearest` at or above the current boundary
                // would loop here forever, inside `Daemon::open` and so
                // before the listener is bound — a daemon that never starts,
                // with no port to ask and no line to read.
                let nearest = nearest.0;
                if nearest >= boundary {
                    out.push(Walked { at: boundary, docs: None });
                    break;
                }
                match engine.world_at(Seq(nearest)) {
                    Ok(w) => {
                        out.push(Walked { at: boundary, docs: classify(Some(&w), &upper) });
                        if nearest <= low {
                            break;
                        }
                        boundary = nearest;
                        upper = w;
                    }
                    Err(_) => {
                        // The boundary M2 named cannot be answered: the feed
                        // reaches down to `boundary` and no further.
                        out.push(Walked { at: boundary, docs: None });
                        if nearest > low {
                            min_since = Some(nearest);
                        }
                        break;
                    }
                }
            }
            Err(_) => {
                out.push(Walked { at: boundary, docs: None });
                min_since = Some(probe);
                break;
            }
        }
    }
    out.reverse();
    (out, min_since)
}

/// Parse whole newline-terminated records; trust ends at the first line
/// that is torn (no `\n`) or does not parse. Returns each record with the
/// byte offset its line starts at, and the byte offset after the last whole
/// one.
fn parse_records(bytes: &[u8]) -> (Vec<(usize, Record)>, usize) {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < bytes.len() {
        let Some(nl) = bytes[pos..].iter().position(|&b| b == b'\n') else { break };
        match parse_line(&bytes[pos..pos + nl]) {
            Some(rec) => out.push((pos, rec)),
            None => break,
        }
        pos += nl + 1;
    }
    (out, pos)
}

/// One file line. The file is daemon-private; unknown keys are ignored (a
/// newer daemon's extension), malformed known fields are torn-treatment.
/// The min-since record has two spellings in the field — `min_since` and
/// `floor` — and both read, because an unparseable line ends trust in
/// everything after it.
///
/// The three entry fields are read TOGETHER, because [`CommitMeta`] has only two
/// states: all three present is a recorded position, all three absent (or
/// `null`) is a bare one, and a line carrying some of them is not a line
/// this daemon wrote — so trust ends there exactly as at an unparseable
/// one, and the reopen walk re-covers the position as bare.
fn parse_line(line: &[u8]) -> Option<Record> {
    let v: Value = serde_json::from_slice(line).ok()?;
    let m = v.as_object()?;
    if let Some(s) = m.get("min_since").or_else(|| m.get("floor")) {
        return Some(Record::MinSince(s.as_u64()?));
    }
    let at = m.get("at")?.as_u64()?;
    // Each field is read THROUGH the same lookup that decides it is
    // present — `serde_json::Map` panics on a missing key, and an
    // indexing read here would rest on a separate presence test agreeing
    // with it about what "present" means. `?` is the torn verdict a
    // half-written line is owed, so the two cannot come apart.
    let field = |k: &str| match m.get(k) {
        None | Some(Value::Null) => None,
        Some(v) => Some(v),
    };
    let meta = match (field("op"), field("docs"), field("time")) {
        (None, None, None) => CommitMeta::Bare,
        (Some(op), Some(docs), Some(time)) => CommitMeta::Recorded {
            op: op.as_str()?.to_string(),
            docs: docs
                .as_array()?
                .iter()
                .map(|d| d.as_str().map(str::to_string))
                .collect::<Option<Vec<String>>>()?,
            time: time.as_u64()?,
            // Absent on a pre-feature line — the reserved null, never
            // invented (AUTH-1.52); present-but-not-a-string is torn.
            key: match field("key") {
                None => None,
                Some(k) => Some(k.as_str()?.to_string()),
            },
        },
        _ => return None,
    };
    Some(Record::Entry(at, meta))
}

/// `{"at":N}` for a bare position; `{"at":N,"docs":[…],"op":"…","time":T}`
/// for a recorded one. Built through the codec's key-sorting device, so a
/// line is the same bytes whatever backs serde_json's map — which is what
/// lets `GET /changes` answer byte-identically across a restart.
fn entry_line(at: u64, meta: &CommitMeta) -> Vec<u8> {
    let mut pairs = vec![("at", Value::Number(at.into()))];
    if let CommitMeta::Recorded { op, docs, time, key } = meta {
        pairs.push(("op", Value::String(op.clone())));
        pairs.push((
            "docs",
            Value::Array(docs.iter().map(|d| Value::String(d.clone())).collect()),
        ));
        pairs.push(("time", Value::Number((*time).into())));
        if let Some(k) = key {
            pairs.push(("key", Value::String(k.clone())));
        }
    }
    line_bytes(obj(pairs))
}

/// `{"min_since":N}` — the smallest `since` the feed can honor from here
/// on. The key is deliberately not `floor`, which on the wire names the
/// oldest position still ANSWERABLE — a different number, and one an
/// operator reading this file beside a `410` body would otherwise conflate.
fn min_since_line(min_since: u64) -> Vec<u8> {
    line_bytes(obj(vec![("min_since", Value::Number(min_since.into()))]))
}

/// One newline-terminated file line — the codec's serializer, so a line is
/// the same bytes whatever backs serde_json's map and the "cannot fail"
/// argument is the one written there rather than a second copy of it.
pub(crate) fn line_bytes(v: Value) -> Vec<u8> {
    let mut b = to_bytes(v);
    b.push(b'\n');
    b
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A line's bytes are fixed, key order included — the determinism
    /// `/changes` inherits — and every line round-trips through the reader
    /// that will replay it, each at the offset the replay reports.
    #[test]
    fn lines_are_key_sorted_and_replay_as_written() {
        let meta = CommitMeta::Recorded {
            op: "insert".into(),
            docs: vec!["1.0.1.0.1".into()],
            time: 1_700_000_000_000,
            key: Some("bare".into()),
        };
        assert_eq!(
            entry_line(8, &meta),
            b"{\"at\":8,\"docs\":[\"1.0.1.0.1\"],\"key\":\"bare\",\"op\":\"insert\",\"time\":1700000000000}\n"
        );
        // A pre-feature recorded line carries no `key` field at all —
        // omitted in the file, replayed as `None` below.
        let pre_feature = CommitMeta::Recorded {
            op: "insert".into(),
            docs: vec!["1.0.1.0.1".into()],
            time: 1_700_000_000_001,
            key: None,
        };
        assert_eq!(
            entry_line(9, &pre_feature),
            b"{\"at\":9,\"docs\":[\"1.0.1.0.1\"],\"op\":\"insert\",\"time\":1700000000001}\n"
        );
        assert_eq!(entry_line(3, &CommitMeta::Bare), b"{\"at\":3}\n");
        assert_eq!(min_since_line(2048), b"{\"min_since\":2048}\n");

        let mut file: Vec<u8> = Vec::new();
        file.extend_from_slice(&entry_line(8, &meta));
        let second_offset = file.len();
        file.extend_from_slice(&entry_line(9, &pre_feature));
        file.extend_from_slice(&entry_line(3, &CommitMeta::Bare));
        file.extend_from_slice(&min_since_line(2048));
        let (records, valid_end) = parse_records(&file);
        assert_eq!(valid_end, file.len(), "every whole line is trusted");
        assert_eq!(records.len(), 4);
        match &records[0] {
            (0, Record::Entry(at, CommitMeta::Recorded { op, docs, time, key })) => {
                assert_eq!((*at, op.as_str(), *time), (8, "insert", 1_700_000_000_000));
                assert_eq!(docs.as_slice(), ["1.0.1.0.1".to_string()]);
                assert_eq!(key.as_deref(), Some("bare"), "testimony replays as written");
            }
            other => panic!("first line is a recorded entry at offset 0: {other:?}"),
        }
        assert!(
            matches!(&records[1], (o, Record::Entry(9, CommitMeta::Recorded { key: None, .. })) if *o == second_offset),
            "a pre-feature line replays with no testimony, at its own offset: {:?}",
            records[1]
        );
        assert!(
            matches!(records[2], (_, Record::Entry(3, CommitMeta::Bare))),
            "third line is a bare entry: {:?}",
            records[2]
        );
        assert!(
            matches!(records[3], (_, Record::MinSince(2048))),
            "fourth line names the smallest admissible since: {:?}",
            records[3]
        );
    }

    /// Both spellings of the min-since record read, and reading one does
    /// not end trust in the lines behind it — a data dir carrying the
    /// `floor` spelling replays whole rather than truncating there.
    #[test]
    fn both_spellings_of_the_min_since_record_replay() {
        let mut file: Vec<u8> = Vec::new();
        file.extend_from_slice(b"{\"floor\":2048}\n");
        file.extend_from_slice(&entry_line(2049, &CommitMeta::Bare));
        let (records, valid_end) = parse_records(&file);
        assert_eq!(valid_end, file.len(), "the `floor` spelling does not end trust");
        assert!(
            matches!(records[0], (_, Record::MinSince(2048))),
            "a `floor` line is a min-since record: {:?}",
            records[0]
        );
        assert!(
            matches!(records[1], (_, Record::Entry(2049, _))),
            "the line behind it still replays: {:?}",
            records[1]
        );
    }

    /// A position is recorded or it is bare; a line naming some of the
    /// three fields is not one this daemon wrote, so trust ends there —
    /// the same treatment an unparseable line gets, and the reopen walk
    /// re-covers the position as bare rather than serving half a record.
    #[test]
    fn a_half_recorded_line_ends_trust() {
        let mut file: Vec<u8> = Vec::new();
        file.extend_from_slice(&entry_line(1, &CommitMeta::Bare));
        file.extend_from_slice(b"{\"at\":2,\"op\":\"insert\"}\n");
        file.extend_from_slice(&entry_line(3, &CommitMeta::Bare));
        let (records, valid_end) = parse_records(&file);
        assert_eq!(records.len(), 1, "trust ends at the half-recorded line");
        assert_eq!(valid_end, entry_line(1, &CommitMeta::Bare).len(), "and truncation cuts there");
        // A `null`-valued field is absence, not a half record.
        let (records, _) = parse_records(b"{\"at\":4,\"docs\":null,\"op\":null,\"time\":null}\n");
        assert!(matches!(records.as_slice(), [(_, Record::Entry(4, CommitMeta::Bare))]));
    }

    /// The wire entry names every field, a bare position's as explicit
    /// `null` — never invented, and never merely absent, which a client
    /// could not tell from a field this daemon does not know about. The
    /// file line omits what the wire nulls; both are deliberate. `key`'s
    /// null is AUTH-1.52's reserved lost-metadata meaning: a pre-feature
    /// record reads it exactly as a bare position does. The docs rendered
    /// are the REDUCED list the feed hands in — here the whole record's.
    #[test]
    fn wire_entries_null_what_the_file_line_omits() {
        let meta = CommitMeta::Recorded {
            op: "insert".into(),
            docs: vec!["1.0.1.0.1".into()],
            time: 1_700_000_000_000,
            key: Some("bare".into()),
        };
        assert_eq!(
            serde_json::to_string(&meta.entry(8, vec!["1.0.1.0.1".into()])).expect("json"),
            r#"{"at":8,"docs":["1.0.1.0.1"],"key":"bare","op":"insert","time":1700000000000}"#
        );
        let pre_feature = CommitMeta::Recorded {
            op: "insert".into(),
            docs: vec!["1.0.1.0.1".into()],
            time: 1_700_000_000_000,
            key: None,
        };
        assert_eq!(
            serde_json::to_string(&pre_feature.entry(8, vec!["1.0.1.0.1".into()])).expect("json"),
            r#"{"at":8,"docs":["1.0.1.0.1"],"key":null,"op":"insert","time":1700000000000}"#
        );
        assert_eq!(
            serde_json::to_string(&CommitMeta::Bare.entry(3, vec!["1.0.1.0.1".into()]))
                .expect("json"),
            r#"{"at":3,"docs":null,"key":null,"op":null,"time":null}"#,
            "a bare entry's docs are the reserved null whatever the feed hands in"
        );
    }
}
