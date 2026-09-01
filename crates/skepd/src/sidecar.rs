//! The commit-metadata sidecar (wire v6): `commits.log` in the data dir —
//! one JSON line per committed write `(position, op kind, affected docs,
//! unix millis)`, appended by the write path at ack time and replayed on
//! reopen. This is daemon-owned TRANSPORT METADATA, never substrate state
//! (wire.md §The change feed) — exempt from the
//! no-second-persistence-layer rule for the same reason as the kernel's
//! journal-lock file: it persists nothing about the WORLD, since two
//! daemons replaying one journal still converge on byte-identical worlds.
//! The sidecar is the daemon's testimony about its own service, and it
//! feeds `GET /changes` and `/health`'s `head_time`.
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
//!
//! The file — and the entries replayed from it — are bounded by the
//! journal's own retention, not by the world's age. Positions the journal has
//! reclaimed are unanswerable across the whole history surface, so at open
//! the sidecar drops its entries below that floor and rewrites itself
//! around them (see [`Sidecar::open`]). Without that the feed's memory
//! would be the only structure in the daemon that grows with total commits
//! ever made rather than with commits still reachable, and it is fully
//! resident.
//!
//! The sidecar is written under the write path's serialization lock — held
//! by `write_path.rs`, which takes that lock and calls [`Sidecar::record`]
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

use parking_lot::Mutex;
use serde_json::Value;
use skep_engine::{Engine, HistoryError};
use skep_kernel::Seq;

use crate::codec::{obj, to_bytes};

/// The sidecar's file name inside the data dir (beside the kernel's own
/// journal/checkpoint files, which this crate never touches).
const SIDECAR_FILE: &str = "commits.log";

/// One committed position's metadata — and this file's crash-honesty rule
/// as a type. A position is either one the daemon OBSERVED committing,
/// carrying all of op/docs/time, or a BARE one reconstructed from the
/// journal, carrying none of them. Three independent `Option`s would admit
/// six more combinations, and this file has a meaning for neither the
/// half-recorded position nor the record that remembers when but not what.
#[derive(Clone, Debug)]
pub(crate) enum CommitMeta {
    /// Reconstructed, not witnessed: served as explicit `null`s, never as
    /// an invented value.
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
    /// One `GET /changes` entry: the position and all three fields, a bare
    /// position's rendering as explicit `null`s — the crash-honesty rule of
    /// this file, expressed where the rule is stated rather than at the
    /// handler. Deliberately NOT [`entry_line`]'s convention, which omits
    /// absent fields: the file is daemon-private and [`parse_line`] reads
    /// absent and null alike, so the shorter line costs nothing there,
    /// while a client reading the wire is owed the field it asked about.
    pub fn into_entry(self, at: u64) -> Value {
        let (docs, op, time, key) = match self {
            CommitMeta::Bare => (Value::Null, Value::Null, Value::Null, Value::Null),
            CommitMeta::Recorded { op, docs, time, key } => (
                Value::Array(docs.into_iter().map(Value::String).collect()),
                Value::String(op),
                Value::Number(time.into()),
                key.map(Value::String).unwrap_or(Value::Null),
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
    /// The smallest `since` this feed can honor — see [`Inner::min_since`].
    MinSince(u64),
}

/// The answer `GET /changes` marshals.
#[derive(Debug)]
pub(crate) enum ChangesAnswer {
    /// `since` reaches below what the feed can enumerate; `floor` is the
    /// oldest position that still has an entry, when one exists — the
    /// wire's sense of the word (wire.md §Reading history: the oldest
    /// position still answerable), which is NOT [`Inner::min_since`].
    Reclaimed { floor: Option<u64> },
    /// The entries in `(since, head]`, oldest first, capped at `limit`;
    /// `last` is the final entry's position (or `since` echoed when the
    /// page is empty) and `more` says whether entries remain past it.
    Page { entries: Vec<(u64, CommitMeta)>, last: u64, more: bool },
}

pub(crate) struct Sidecar {
    inner: Mutex<Inner>,
}

struct Inner {
    file: File,
    /// Every enumerable position above `min_since`, in order.
    entries: BTreeMap<u64, CommitMeta>,
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
    min_since: u64,
    /// The journal head at open — the fence between replayed history and
    /// this uptime's commits. An ack carrying a position at or below it
    /// (an idempotency-cache replay, `emit`'s incumbent ack) is never a
    /// new commit and is never re-recorded.
    open_head: u64,
    /// Monotone clamp for recorded wall-clock times.
    last_time: u64,
}

impl Sidecar {
    /// Replay (truncating a torn tail), drop everything the file says about
    /// a journal other than this one — entries beyond the head AND a fence
    /// above it — reconstruct any uncovered `(last recorded, head]` region
    /// as bare positions, and persist what the reconstruction learned.
    ///
    /// COST, and the only step of daemon startup that is not O(1) in the
    /// data dir: reconstruction spends one whole-world `Engine::world_at`
    /// per uncovered boundary — a checkpoint deserialize plus a journal
    /// fold each — so a dir with NO coverage (a sidecar deleted, arrived
    /// corrupt, or written before this feature) pays that for every
    /// boundary the journal still holds, before `open` returns. The region
    /// is bounded below by journal reclamation, so the ceiling is the
    /// retained window, which `server.rs` chooses as
    /// `CHECKPOINT_EVERY_COMMITS × RETAINED_CHECKPOINTS` commits. The
    /// walk's findings are appended here, so a covered region is walked
    /// once ever rather than once per open.
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
    /// DISPOSITION, deliberately the opposite of [`Sidecar::record`]'s:
    /// every I/O failure here is fatal and reaches the caller as
    /// `DaemonError::Sidecar`, including the walk's append, whose loss
    /// would cost only a repeated walk on a later open. At ack time the ack
    /// is already owed, so lost testimony degrades to bare; at open nothing
    /// is owed yet, and a data dir that cannot take a write the kernel just
    /// performed is an operator condition worth reporting rather than
    /// limping past.
    pub fn open(dir: &Path, engine: &Engine) -> io::Result<Sidecar> {
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
        let mut entries = BTreeMap::new();
        let mut min_since = 0u64;
        for rec in records {
            match rec {
                Record::Entry(at, meta) => {
                    entries.insert(at, meta);
                }
                Record::MinSince(s) => min_since = min_since.max(s),
            }
        }
        let head = engine.kernel().current_seq().0;
        // Entries beyond this journal's head describe a different journal
        // (an operator swapped files under the sidecar); never serve them.
        if head < u64::MAX {
            let _ = entries.split_off(&(head + 1));
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
        if head > low {
            // The walk's own fence, qualified because the accumulator it
            // folds into holds the plain name.
            let (bare, walk_min_since) = reconstruct(engine, low, head);
            for &at in &bare {
                entries.insert(at, CommitMeta::Bare);
                file.write_all(&entry_line(at, &CommitMeta::Bare))?;
            }
            if let Some(walked) = walk_min_since {
                min_since = min_since.max(walked);
                file.write_all(&min_since_line(walked))?;
            }
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
        if stale_fence || entries.keys().next().is_some_and(|&oldest| oldest <= min_since) {
            entries = entries.split_off(&min_since.saturating_add(1));
            file = rewrite(dir, &entries, min_since)?;
        }
        let last_time = entries.values().filter_map(CommitMeta::time).max().unwrap_or(0);
        Ok(Sidecar {
            inner: Mutex::new(Inner { file, entries, min_since, open_head: head, last_time }),
        })
    }

    /// Record one committed write at ack time. Idempotent against replayed
    /// acks: a position at or below the open-time head, or one already
    /// recorded this uptime, is an ack for an OLD commit (idempotency-cache
    /// hit, `emit` incumbent) — re-recording it would invent a time.
    ///
    /// CALLER CONTRACT — call only while holding the daemon's
    /// write-serialization lock, between a commit and its ack. That is what
    /// makes this file's two invariants true: file order is position order,
    /// and recorded times are monotone non-decreasing in position. The lock
    /// inside guards `Inner` and nothing more, so calls arriving out of
    /// position order would append out of order and stamp a later position
    /// with an earlier time — both silent, both permanent, and both
    /// load-bearing for [`Sidecar::changes`] and [`Sidecar::head_time`].
    /// Nothing here can check it, which is why `write_path.rs` holds the
    /// lock and this call in ONE operation and is the only caller: the
    /// obligation is discharged by there being nowhere else to fail it.
    ///
    /// The clamp against `last_time` below covers the other half of the
    /// monotonicity — a wall clock that steps backwards — and that one IS
    /// this file's own obligation rather than the caller's.
    pub fn record(&self, at: u64, op: &'static str, docs: Vec<String>, key: String) {
        let mut inner = self.inner.lock();
        if at <= inner.open_head || inner.entries.contains_key(&at) {
            return;
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let time = now.max(inner.last_time);
        inner.last_time = time;
        let meta = CommitMeta::Recorded { op: op.to_string(), docs, time, key: Some(key) };
        // Testimony must not fail the op: the write is committed and the
        // ack is owed regardless; a lost append answers bare after restart.
        // Reported without `eprintln!`, which PANICS when the stderr write
        // fails: a daemon whose log pipe has lost its reader would then fail
        // the op this arm exists to keep succeeding, answering
        // `internal_panic` for a write that committed and losing the caller
        // its position. Both failures are swallowed for the one reason.
        if let Err(e) = inner.file.write_all(&entry_line(at, &meta)) {
            let _ = writeln!(
                std::io::stderr(),
                "skepd: commits.log append failed at position {at}: {e}"
            );
        }
        inner.entries.insert(at, meta);
    }

    /// The data behind `GET /changes?since=N&limit=K`.
    pub fn changes(&self, since: u64, limit: usize) -> ChangesAnswer {
        let inner = self.inner.lock();
        if since < inner.min_since {
            // The wire's `floor`: the oldest position still answerable,
            // which is the first entry ABOVE the smallest admissible since.
            let floor =
                inner.entries.range(inner.min_since.saturating_add(1)..).next().map(|(k, _)| *k);
            return ChangesAnswer::Reclaimed { floor };
        }
        let entries: Vec<(u64, CommitMeta)> = match since.checked_add(1) {
            Some(start) => {
                inner.entries.range(start..).take(limit).map(|(k, v)| (*k, v.clone())).collect()
            }
            None => Vec::new(),
        };
        let (last, more) = match entries.last() {
            Some(&(k, _)) => (k, inner.entries.range(k.saturating_add(1)..).next().is_some()),
            None => (since, false),
        };
        ChangesAnswer::Page { entries, last, more }
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
    /// RELIANCE, not its check — a `Sidecar` never learns the live head —
    /// and two states break it.
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
        self.inner.lock().entries.values().next_back().and_then(CommitMeta::time)
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
/// record, and hand back the reopened append handle.
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
fn rewrite(dir: &Path, entries: &BTreeMap<u64, CommitMeta>, min_since: u64) -> io::Result<File> {
    let path = dir.join(SIDECAR_FILE);
    let tmp = dir.join(format!("{SIDECAR_FILE}.compact"));
    let mut out = Vec::new();
    out.extend_from_slice(&min_since_line(min_since));
    for (at, meta) in entries {
        out.extend_from_slice(&entry_line(*at, meta));
    }
    let mut f = File::create(&tmp)?;
    f.write_all(&out)?;
    f.sync_all()?;
    drop(f);
    std::fs::rename(&tmp, &path)?;
    OpenOptions::new().create(true).read(true).append(true).open(&path)
}

/// Enumerate the committed boundaries in `(low, head]`, newest first, via
/// the engine's public bounded replay: `head` is a boundary by definition;
/// an `Ok` probe of `b - 1` proves another; `NotABoundary` jumps to
/// `nearest`. Returns the boundaries (ascending) and, when the journal
/// stopped answering (reclaimed / corrupt / I/O), the smallest `since` the
/// feed can honor from there on — [`Inner::min_since`]'s number, not the
/// wire's `floor`.
///
/// The descent holds its OWN termination: every step strictly decreases
/// `boundary`, checked here rather than inherited from M2's reading of
/// `nearest`. A `nearest` that did not descend ends the walk, and the
/// region it would have covered is covered as bare entries on a later
/// open — which is the honest outcome, since this runs inside
/// `Daemon::open`, before the listener is bound, where a loop that did not
/// terminate would be a daemon that never starts.
fn reconstruct(engine: &Engine, low: u64, head: u64) -> (Vec<u64>, Option<u64>) {
    let mut boundaries = vec![head];
    let mut boundary = head;
    let mut min_since = None;
    // The descent's own guard: `probe` exists only when there is a position
    // below `boundary` and it is still above `low`, so the step down cannot
    // leave `u64` — a premise this loop holds rather than one it inherits
    // from a caller's range check.
    while let Some(probe) = boundary.checked_sub(1).filter(|p| *p > low) {
        match engine.world_at(Seq(probe)) {
            Ok(_) => {
                boundary = probe;
                boundaries.push(boundary);
            }
            Err(HistoryError::NotABoundary { nearest }) => {
                // M2's `nearest` is the boundary BELOW the probe, which is
                // what makes this descent terminate. Enforced rather than
                // relied on: a `nearest` at or above the current boundary
                // would loop here forever, inside `Daemon::open` and so
                // before the listener is bound — a daemon that never starts,
                // with no port to ask and no line to read.
                if nearest.0 <= low || nearest.0 >= boundary {
                    break;
                }
                boundary = nearest.0;
                boundaries.push(boundary);
            }
            Err(_) => {
                min_since = Some(probe);
                break;
            }
        }
    }
    boundaries.reverse();
    (boundaries, min_since)
}

/// Parse whole newline-terminated records; trust ends at the first line
/// that is torn (no `\n`) or does not parse. Returns the records and the
/// byte offset after the last whole one.
fn parse_records(bytes: &[u8]) -> (Vec<Record>, usize) {
    let mut out = Vec::new();
    let mut pos = 0;
    while pos < bytes.len() {
        let Some(nl) = bytes[pos..].iter().position(|&b| b == b'\n') else { break };
        match parse_line(&bytes[pos..pos + nl]) {
            Some(rec) => out.push(rec),
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
fn line_bytes(v: Value) -> Vec<u8> {
    let mut b = to_bytes(v);
    b.push(b'\n');
    b
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A line's bytes are fixed, key order included — the determinism
    /// `/changes` inherits — and every line round-trips through the reader
    /// that will replay it.
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
        file.extend_from_slice(&entry_line(9, &pre_feature));
        file.extend_from_slice(&entry_line(3, &CommitMeta::Bare));
        file.extend_from_slice(&min_since_line(2048));
        let (records, valid_end) = parse_records(&file);
        assert_eq!(valid_end, file.len(), "every whole line is trusted");
        assert_eq!(records.len(), 4);
        match &records[0] {
            Record::Entry(at, CommitMeta::Recorded { op, docs, time, key }) => {
                assert_eq!((*at, op.as_str(), *time), (8, "insert", 1_700_000_000_000));
                assert_eq!(docs.as_slice(), ["1.0.1.0.1".to_string()]);
                assert_eq!(key.as_deref(), Some("bare"), "testimony replays as written");
            }
            other => panic!("first line is a recorded entry: {other:?}"),
        }
        assert!(
            matches!(&records[1], Record::Entry(9, CommitMeta::Recorded { key: None, .. })),
            "a pre-feature line replays with no testimony: {:?}",
            records[1]
        );
        assert!(
            matches!(records[2], Record::Entry(3, CommitMeta::Bare)),
            "third line is a bare entry: {:?}",
            records[2]
        );
        assert!(
            matches!(records[3], Record::MinSince(2048)),
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
            matches!(records[0], Record::MinSince(2048)),
            "a `floor` line is a min-since record: {:?}",
            records[0]
        );
        assert!(
            matches!(records[1], Record::Entry(2049, _)),
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
        assert!(matches!(records.as_slice(), [Record::Entry(4, CommitMeta::Bare)]));
    }

    /// The wire entry names every field, a bare position's as explicit
    /// `null` — never invented, and never merely absent, which a client
    /// could not tell from a field this daemon does not know about. The
    /// file line omits what the wire nulls; both are deliberate. `key`'s
    /// null is AUTH-1.52's reserved lost-metadata meaning: a pre-feature
    /// record reads it exactly as a bare position does.
    #[test]
    fn wire_entries_null_what_the_file_line_omits() {
        let meta = CommitMeta::Recorded {
            op: "insert".into(),
            docs: vec!["1.0.1.0.1".into()],
            time: 1_700_000_000_000,
            key: Some("bare".into()),
        };
        assert_eq!(
            serde_json::to_string(&meta.into_entry(8)).expect("json"),
            r#"{"at":8,"docs":["1.0.1.0.1"],"key":"bare","op":"insert","time":1700000000000}"#
        );
        let pre_feature = CommitMeta::Recorded {
            op: "insert".into(),
            docs: vec!["1.0.1.0.1".into()],
            time: 1_700_000_000_000,
            key: None,
        };
        assert_eq!(
            serde_json::to_string(&pre_feature.into_entry(8)).expect("json"),
            r#"{"at":8,"docs":["1.0.1.0.1"],"key":null,"op":"insert","time":1700000000000}"#
        );
        assert_eq!(
            serde_json::to_string(&CommitMeta::Bare.into_entry(3)).expect("json"),
            r#"{"at":3,"docs":null,"key":null,"op":null,"time":null}"#
        );
    }
}
