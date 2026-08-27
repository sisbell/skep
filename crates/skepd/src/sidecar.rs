//! The commit-metadata sidecar (wire v6): `commits.log` in the data dir —
//! one JSON line per committed write `(position, op kind, affected docs,
//! unix millis)`, appended by the write path at ack time and replayed on
//! reopen. This is daemon-owned OBSERVATION metadata, exempt from the
//! no-second-persistence-layer rule for the same reason as the kernel's
//! journal-lock file: it persists nothing about the WORLD — two daemons
//! replaying one journal still converge on byte-identical worlds; the
//! sidecar is the daemon's testimony about its own service, and it feeds
//! `GET /changes` and `/health`'s `head_time`.
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
//! The sidecar is written under the daemon's write-serialization lock, so
//! file order is position order and recorded times are monotone
//! non-decreasing in position (wall-clock reads are additionally clamped
//! against the last recorded time). Appends are flushed to the OS but not
//! fsynced — a lost tail answers bare, which is the honest trade for not
//! doubling every write's fsync cost on testimony.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use parking_lot::Mutex;
use serde_json::Value;
use skep_engine::{Engine, HistoryError};
use skep_kernel::Seq;

use crate::codec::obj;

/// The sidecar's file name inside the data dir (beside the kernel's own
/// journal/checkpoint files, which this crate never touches).
const SIDECAR_FILE: &str = "commits.log";

/// One committed position's metadata — and this file's crash-honesty rule
/// as a type. A position is either one the daemon OBSERVED committing,
/// carrying all of op/docs/time, or a BARE one reconstructed from the
/// journal, carrying none of them. Three independent `Option`s would admit
/// six more combinations, and this file has a meaning for neither the
/// half-recorded position nor the record that remembers when but not what.
#[derive(Clone)]
pub(crate) enum Meta {
    /// Reconstructed, not witnessed: served as explicit `null`s, never as
    /// an invented value.
    Bare,
    /// Witnessed at ack time by the daemon's own write path.
    Recorded { op: String, docs: Vec<String>, time: u64 },
}

impl Meta {
    /// One `GET /changes` entry: the position and all three fields, a bare
    /// position's rendering as explicit `null`s — the crash-honesty rule of
    /// this file, expressed where the rule is stated rather than at the
    /// handler. Deliberately NOT [`entry_line`]'s convention, which omits
    /// absent fields: the file is daemon-private and [`parse_line`] reads
    /// absent and null alike, so the shorter line costs nothing there,
    /// while a client reading the wire is owed the field it asked about.
    pub fn entry(&self, at: u64) -> Value {
        let (docs, op, time) = match self {
            Meta::Bare => (Value::Null, Value::Null, Value::Null),
            Meta::Recorded { op, docs, time } => (
                Value::Array(docs.iter().map(|s| Value::String(s.clone())).collect()),
                Value::String(op.clone()),
                Value::Number((*time).into()),
            ),
        };
        obj(vec![
            ("at", Value::Number(at.into())),
            ("docs", docs),
            ("op", op),
            ("time", time),
        ])
    }

    /// The recorded wall-clock time, or `None` for a bare position.
    fn time(&self) -> Option<u64> {
        match self {
            Meta::Bare => None,
            Meta::Recorded { time, .. } => Some(*time),
        }
    }
}

/// One replayed file record.
enum Rec {
    Entry(u64, Meta),
    /// The smallest `since` this feed can honor — see [`Inner::min_since`].
    MinSince(u64),
}

/// The answer `GET /changes` marshals.
pub(crate) enum ChangesAnswer {
    /// `since` reaches below what the feed can enumerate; `floor` is the
    /// oldest position that still has an entry, when one exists — the
    /// wire's sense of the word (wire.md §Reading history: the oldest
    /// position still answerable), which is NOT [`Inner::min_since`].
    Reclaimed { floor: Option<u64> },
    /// The entries in `(since, head]`, oldest first, capped at `limit`;
    /// `last` is the final entry's position (or `since` echoed when the
    /// page is empty) and `more` says whether entries remain past it.
    Page { entries: Vec<(u64, Meta)>, last: u64, more: bool },
}

pub(crate) struct Sidecar {
    inner: Mutex<Inner>,
}

struct Inner {
    file: File,
    /// Every enumerable position above `min_since`, in order.
    map: BTreeMap<u64, Meta>,
    /// The smallest admissible `since`: coverage is complete over
    /// `(min_since, head]`; below it the walk was stopped (reclaimed or
    /// unreadable journal) and `/changes` answers 410. Deliberately not
    /// called a floor — the wire's `floor` is the oldest position still
    /// ANSWERABLE, whereas this is the highest one that is not.
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
    /// Replay (truncating a torn tail), drop entries beyond this journal's
    /// head, reconstruct any uncovered `(last recorded, head]` region as
    /// bare positions, and persist what the reconstruction learned.
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
        let mut map = BTreeMap::new();
        let mut min_since = 0u64;
        for rec in records {
            match rec {
                Rec::Entry(at, meta) => {
                    map.insert(at, meta);
                }
                Rec::MinSince(s) => min_since = min_since.max(s),
            }
        }
        let head = engine.kernel().current_seq().0;
        // Entries beyond this journal's head describe a different journal
        // (an operator swapped files under the sidecar); never serve them.
        if head < u64::MAX {
            let _ = map.split_off(&(head + 1));
        }
        let low = map.keys().next_back().copied().unwrap_or(0).max(min_since);
        if head > low {
            let (bare, stop) = reconstruct(engine, low, head);
            for &at in &bare {
                map.insert(at, Meta::Bare);
                file.write_all(&entry_line(at, &Meta::Bare))?;
            }
            if let Some(s) = stop {
                min_since = min_since.max(s);
                file.write_all(&min_since_line(s))?;
            }
        }
        let last_time = map.values().filter_map(Meta::time).max().unwrap_or(0);
        Ok(Sidecar {
            inner: Mutex::new(Inner { file, map, min_since, open_head: head, last_time }),
        })
    }

    /// Record one committed write at ack time. Idempotent against replayed
    /// acks: a position at or below the open-time head, or one already
    /// recorded this uptime, is an ack for an OLD commit (idempotency-cache
    /// hit, `emit` incumbent) — re-recording it would invent a time.
    pub fn record(&self, at: u64, op: &'static str, docs: Vec<String>) {
        let mut g = self.inner.lock();
        if at <= g.open_head || g.map.contains_key(&at) {
            return;
        }
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let time = now.max(g.last_time);
        g.last_time = time;
        let meta = Meta::Recorded { op: op.to_string(), docs, time };
        // Testimony must not fail the op: the write is committed and the
        // ack is owed regardless; a lost append answers bare after restart.
        if let Err(e) = g.file.write_all(&entry_line(at, &meta)) {
            eprintln!("skepd: commits.log append failed at position {at}: {e}");
        }
        g.map.insert(at, meta);
    }

    /// The data behind `GET /changes?since=N&limit=K`.
    pub fn changes(&self, since: u64, limit: usize) -> ChangesAnswer {
        let g = self.inner.lock();
        if since < g.min_since {
            // The wire's `floor`: the oldest position still answerable,
            // which is the first entry ABOVE the smallest admissible since.
            let floor = g.map.range(g.min_since.saturating_add(1)..).next().map(|(k, _)| *k);
            return ChangesAnswer::Reclaimed { floor };
        }
        let entries: Vec<(u64, Meta)> = match since.checked_add(1) {
            Some(start) => {
                g.map.range(start..).take(limit).map(|(k, v)| (*k, v.clone())).collect()
            }
            None => Vec::new(),
        };
        let (last, more) = match entries.last() {
            Some(&(k, _)) => (k, g.map.range(k.saturating_add(1)..).next().is_some()),
            None => (since, false),
        };
        ChangesAnswer::Page { entries, last, more }
    }

    /// The newest recorded commit's wall-clock time — `null` when the head
    /// position's record is bare or nothing is recorded (never invented).
    pub fn head_time(&self) -> Option<u64> {
        self.inner.lock().map.values().next_back().and_then(Meta::time)
    }
}

/// Enumerate the committed boundaries in `(low, head]`, newest first, via
/// the engine's public bounded replay: `head` is a boundary by definition;
/// an `Ok` probe of `b - 1` proves another; `NotABoundary` jumps to
/// `nearest`. Returns the boundaries (ascending) and, when the journal
/// stopped answering (reclaimed / corrupt / I/O), the smallest `since` the
/// feed can honor from there on.
fn reconstruct(engine: &Engine, low: u64, head: u64) -> (Vec<u64>, Option<u64>) {
    let mut found = vec![head];
    let mut b = head;
    let mut stop = None;
    while b - 1 > low {
        match engine.world_at(Seq(b - 1)) {
            Ok(_) => {
                b -= 1;
                found.push(b);
            }
            Err(HistoryError::NotABoundary { nearest }) => {
                if nearest.0 <= low {
                    break;
                }
                b = nearest.0;
                found.push(b);
            }
            Err(_) => {
                stop = Some(b - 1);
                break;
            }
        }
    }
    found.reverse();
    (found, stop)
}

/// Parse whole newline-terminated records; trust ends at the first line
/// that is torn (no `\n`) or does not parse. Returns the records and the
/// byte offset after the last whole one.
fn parse_records(bytes: &[u8]) -> (Vec<Rec>, usize) {
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
/// The three entry fields are read TOGETHER, because [`Meta`] has only two
/// states: all three present is a recorded position, all three absent (or
/// `null`) is a bare one, and a line carrying some of them is not a line
/// this daemon wrote — so trust ends there exactly as at an unparseable
/// one, and the reopen walk re-covers the position as bare.
fn parse_line(line: &[u8]) -> Option<Rec> {
    let v: Value = serde_json::from_slice(line).ok()?;
    let m = v.as_object()?;
    if let Some(s) = m.get("min_since").or_else(|| m.get("floor")) {
        return Some(Rec::MinSince(s.as_u64()?));
    }
    let at = m.get("at")?.as_u64()?;
    let present = |k: &str| !matches!(m.get(k), None | Some(Value::Null));
    let meta = match (present("op"), present("docs"), present("time")) {
        (false, false, false) => Meta::Bare,
        (true, true, true) => Meta::Recorded {
            op: m["op"].as_str()?.to_string(),
            docs: m["docs"]
                .as_array()?
                .iter()
                .map(|d| d.as_str().map(str::to_string))
                .collect::<Option<Vec<String>>>()?,
            time: m["time"].as_u64()?,
        },
        _ => return None,
    };
    Some(Rec::Entry(at, meta))
}

/// `{"at":N}` for a bare position; `{"at":N,"docs":[…],"op":"…","time":T}`
/// for a recorded one. Built through the codec's key-sorting device, so a
/// line is the same bytes whatever backs serde_json's map — which is what
/// lets `GET /changes` answer byte-identically across a restart.
fn entry_line(at: u64, meta: &Meta) -> Vec<u8> {
    let mut pairs = vec![("at", Value::Number(at.into()))];
    if let Meta::Recorded { op, docs, time } = meta {
        pairs.push(("op", Value::String(op.clone())));
        pairs.push((
            "docs",
            Value::Array(docs.iter().map(|d| Value::String(d.clone())).collect()),
        ));
        pairs.push(("time", Value::Number((*time).into())));
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

fn line_bytes(v: Value) -> Vec<u8> {
    let mut b =
        serde_json::to_vec(&v).expect("serializing a serde_json::Value cannot fail");
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
        let meta = Meta::Recorded {
            op: "insert".into(),
            docs: vec!["1.0.1.0.1".into()],
            time: 1_700_000_000_000,
        };
        assert_eq!(
            entry_line(8, &meta),
            b"{\"at\":8,\"docs\":[\"1.0.1.0.1\"],\"op\":\"insert\",\"time\":1700000000000}\n"
        );
        assert_eq!(entry_line(3, &Meta::Bare), b"{\"at\":3}\n");
        assert_eq!(min_since_line(2048), b"{\"min_since\":2048}\n");

        let mut file: Vec<u8> = Vec::new();
        file.extend_from_slice(&entry_line(8, &meta));
        file.extend_from_slice(&entry_line(3, &Meta::Bare));
        file.extend_from_slice(&min_since_line(2048));
        let (recs, end) = parse_records(&file);
        assert_eq!(end, file.len(), "every whole line is trusted");
        assert_eq!(recs.len(), 3);
        match &recs[0] {
            Rec::Entry(at, Meta::Recorded { op, docs, time }) => {
                assert_eq!((*at, op.as_str(), *time), (8, "insert", 1_700_000_000_000));
                assert_eq!(docs.as_slice(), ["1.0.1.0.1".to_string()]);
            }
            _ => panic!("first line is a recorded entry"),
        }
        match recs[1] {
            Rec::Entry(at, Meta::Bare) => assert_eq!(at, 3),
            _ => panic!("second line is a bare entry"),
        }
        match recs[2] {
            Rec::MinSince(s) => assert_eq!(s, 2048),
            Rec::Entry(..) => panic!("third line names the smallest admissible since"),
        }
    }

    /// Both spellings of the min-since record read, and reading one does
    /// not end trust in the lines behind it — a data dir carrying the
    /// `floor` spelling replays whole rather than truncating there.
    #[test]
    fn both_spellings_of_the_min_since_record_replay() {
        let mut file: Vec<u8> = Vec::new();
        file.extend_from_slice(b"{\"floor\":2048}\n");
        file.extend_from_slice(&entry_line(2049, &Meta::Bare));
        let (recs, end) = parse_records(&file);
        assert_eq!(end, file.len(), "the `floor` spelling does not end trust");
        match recs[0] {
            Rec::MinSince(s) => assert_eq!(s, 2048),
            Rec::Entry(..) => panic!("a `floor` line is a min-since record"),
        }
        match recs[1] {
            Rec::Entry(at, _) => assert_eq!(at, 2049),
            Rec::MinSince(_) => panic!("the line behind it still replays"),
        }
    }

    /// A position is recorded or it is bare; a line naming some of the
    /// three fields is not one this daemon wrote, so trust ends there —
    /// the same treatment an unparseable line gets, and the reopen walk
    /// re-covers the position as bare rather than serving half a record.
    #[test]
    fn a_half_recorded_line_ends_trust() {
        let mut file: Vec<u8> = Vec::new();
        file.extend_from_slice(&entry_line(1, &Meta::Bare));
        file.extend_from_slice(b"{\"at\":2,\"op\":\"insert\"}\n");
        file.extend_from_slice(&entry_line(3, &Meta::Bare));
        let (recs, end) = parse_records(&file);
        assert_eq!(recs.len(), 1, "trust ends at the half-recorded line");
        assert_eq!(end, entry_line(1, &Meta::Bare).len(), "and truncation cuts there");
        // A `null`-valued field is absence, not a half record.
        let (recs, _) = parse_records(b"{\"at\":4,\"docs\":null,\"op\":null,\"time\":null}\n");
        assert!(matches!(recs.as_slice(), [Rec::Entry(4, Meta::Bare)]));
    }

    /// The wire entry names every field, a bare position's as explicit
    /// `null` — never invented, and never merely absent, which a client
    /// could not tell from a field this daemon does not know about. The
    /// file line omits what the wire nulls; both are deliberate.
    #[test]
    fn wire_entries_null_what_the_file_line_omits() {
        let meta = Meta::Recorded {
            op: "insert".into(),
            docs: vec!["1.0.1.0.1".into()],
            time: 1_700_000_000_000,
        };
        assert_eq!(
            serde_json::to_string(&meta.entry(8)).expect("json"),
            r#"{"at":8,"docs":["1.0.1.0.1"],"op":"insert","time":1700000000000}"#
        );
        assert_eq!(
            serde_json::to_string(&Meta::Bare.entry(3)).expect("json"),
            r#"{"at":3,"docs":null,"op":null,"time":null}"#
        );
    }
}
