//! THE HELD-BURST STORE (`client.md` §3c.1–§3c.3), beside the key store: one
//! file per (board, principal), `held/<chain>/principal-<n>.held`, APPEND-ONLY
//! in the key store's idiom (§3.2, §3.7). The first line is the HEADER, written
//! once under `create_new` (`store.rs`'s `write_once` idiom): one JSON object,
//! no whitespace outside strings, lowercase hex, a `v`, no unknown member, one
//! `\n`. After it, one JSON object per line in TWO forms and no third — a
//! `held` line (a burst the board could not take) and a `done` line (its
//! resolution). Each line is ONE `write` followed by `sync_data` BEFORE `op`
//! answers `held` — PERSIST-FIRST (J1): the answer is a promise the disk
//! already keeps. A reader IGNORES a final line without `\n` (a torn last line
//! is the burst a crash caught mid-append, R14's one).
//!
//! THE FILE IS PRIMARY (PATTERNS P38; §3c.3): a newer `v`, an unknown header
//! member or a middle line that does not parse HALTS this principal's writing
//! at this board naming the path — never rebuilt over, never moved, never
//! removed. A MISPLACED file (header `board` not the directory's chain, or
//! `principal` not the file's name) is MOVED ASIDE by a rename that never
//! overwrites (`aside_name`'s form, the index's idiom), this principal's file
//! started fresh. COMPACTION: once every `held` line has its `done`, the file
//! is REMOVED under the lock; a file is never rewritten in place.
//!
//! THE LOCK `held/<chain>/lock` (the key store's `flock` idiom, copied from
//! `search::directory::BoardDir::try_lock` — the index directory's type is the
//! index's) is held for the shell's life; a second shell finding it held holds
//! NOTHING. No size bound of the store's own: the wire's 8 MiB per frame is the
//! bound, and hours of typing are kilobytes (§3c.3).

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;
use skep_search::{aside_name, Chain};

/// The lock file's name, the key store's idiom (`search.md` §5.6).
const LOCK_NAME: &str = "lock";

/// Unix milliseconds now — a line's `time`.
pub fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

/// One `held` line, parsed: the burst the board could not take.
#[derive(Debug, Clone, PartialEq)]
pub struct HeldLine {
    /// The file's monotone ordinal — the resend order, across the documents.
    pub k: u64,
    /// The frame's document.
    pub doc: String,
    /// The page's envelope `id`, where it sent one (A-60).
    pub id: Option<String>,
    /// The `at` of the last ACKED write on `doc` under this session, or the
    /// session's open position — the `since` of the resend's read (§3c.5).
    pub base: u64,
    /// The page's wire frame AS COMPOSED, with no `attest` (§3c.2).
    pub frame: Value,
    /// Why the line is held (§3c.4's tokens).
    pub cause: String,
    /// The board's verdict verbatim beside a REFUSED run's line, for the face.
    pub refusal: Option<Value>,
    /// Whether a dial was made whose answer was lost (`Timeout`/`Io`/
    /// `Truncated` — the burst MAY have landed) or never made.
    pub sent: bool,
    /// The append's wall-clock unix milliseconds.
    pub time: u64,
}

/// What opening a principal's file yields.
pub enum Opened {
    /// The file (fresh, or read whole): its un-done `held` lines in `k` order.
    Live(HeldFile),
    /// P38's HALT: the file was written by a newer skep, carries an unknown
    /// header member, or a middle line does not parse — the path and the reason.
    Halted { path: PathBuf, why: HaltWhy },
}

/// Why a file is halted (P38).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HaltWhy {
    /// A `v` above the reader's — "written by a newer skep".
    Newer,
    /// A header member the reader does not know.
    UnknownMember,
    /// A middle line that does not parse — a damaged body.
    Damaged,
}

impl HaltWhy {
    /// The token the halt's face carries.
    pub fn token(self) -> &'static str {
        match self {
            HaltWhy::Newer => "newer",
            HaltWhy::UnknownMember => "unknown_member",
            HaltWhy::Damaged => "damaged",
        }
    }
}

/// THE DIRECTORY `held/<chain>/`: ensured `0700`, locked once for the shell's
/// life, a principal's file opened under it.
pub struct HeldDir {
    path: PathBuf,
    chain: Chain,
}

impl HeldDir {
    /// `<store_dir>/held/<chain>/` (§3c.8: the same `<data>` the index takes).
    pub fn new(store_dir: &Path, chain: Chain) -> HeldDir {
        HeldDir { path: store_dir.join("held").join(chain.to_string()), chain }
    }

    /// The directory and `held/` above it, each `0700`, created once (§3c.1).
    pub fn ensure(&self) -> io::Result<()> {
        let mut dirs = Vec::new();
        if let Some(parent) = self.path.parent() {
            dirs.push(parent.to_path_buf());
        }
        dirs.push(self.path.clone());
        for dir in dirs {
            if dir.is_dir() {
                continue;
            }
            let mut builder = fs::DirBuilder::new();
            builder.recursive(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            builder.create(&dir)?;
        }
        Ok(())
    }

    /// THE LOCK (`BoardDir::try_lock`'s idiom, copied): `held/<chain>/lock`
    /// opened `0600` and `flock`ed. `Some(file)` holds it for the file's life —
    /// it dies with the process — and `None` says another shell holds it.
    pub fn try_lock(&self) -> io::Result<Option<File>> {
        let mut opts = OpenOptions::new();
        opts.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let file = opts.open(self.path.join(LOCK_NAME))?;
        match file.try_lock() {
            Ok(()) => Ok(Some(file)),
            Err(fs::TryLockError::WouldBlock) => Ok(None),
            Err(fs::TryLockError::Error(e)) => Err(e),
        }
    }

    /// The file name for a principal (P39: the file, never a column).
    pub fn file_name(principal: u64) -> String {
        format!("principal-{principal}.held")
    }

    /// Open the principal's file, reading it WHOLE with P38's faces (§3c.3): a
    /// newer `v`, an unknown header member or a damaged middle line HALTS; a
    /// MISPLACED file is moved aside and this principal's file started fresh.
    pub fn open_file(&self, principal: u64, account: &str) -> io::Result<Opened> {
        let path = self.path.join(Self::file_name(principal));
        let base = HeldFile { path: path.clone(), chain: self.chain, principal, account: account.to_string(), held: Vec::new(), next_k: 1, created: false };
        let bytes = match fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Opened::Live(base)),
            Err(e) => return Err(e),
        };
        // A torn last line (no final `\n`) is ignored; `split` then drops the
        // post-`\n` element (the empty tail, or the torn line itself).
        let text = String::from_utf8_lossy(&bytes);
        let mut complete: Vec<&str> = text.split('\n').collect();
        complete.pop();
        let Some(header_text) = complete.first() else {
            // No complete line — a header torn before its sync; treat as damaged.
            return Ok(Opened::Halted { path, why: HaltWhy::Damaged });
        };
        let header: Value = match serde_json::from_str(header_text) {
            Ok(v) => v,
            Err(_) => return Ok(Opened::Halted { path, why: HaltWhy::Damaged }),
        };
        // `v` read FIRST (§3c.2): a `v` above 1 is the newer face, never half-read.
        match header.get("v").and_then(Value::as_u64) {
            Some(1) => {}
            Some(n) if n > 1 => return Ok(Opened::Halted { path, why: HaltWhy::Newer }),
            _ => return Ok(Opened::Halted { path, why: HaltWhy::UnknownMember }),
        }
        // No unknown member, and the type pinned.
        let Some(members) = header.as_object() else { return Ok(Opened::Halted { path, why: HaltWhy::Damaged }) };
        if header["type"].as_str() != Some("skep-held-bursts") {
            return Ok(Opened::Halted { path, why: HaltWhy::UnknownMember });
        }
        if members.keys().any(|k| !matches!(k.as_str(), "type" | "v" | "board" | "principal" | "account")) {
            return Ok(Opened::Halted { path, why: HaltWhy::UnknownMember });
        }
        // A MISPLACED file — header `board` not the directory's chain, or
        // `principal` not the file's name — moved aside, this file started fresh.
        let own_chain = header["board"].as_str().and_then(Chain::parse);
        let board_here = own_chain == Some(self.chain);
        let principal_here = header["principal"].as_u64() == Some(principal);
        if !board_here || !principal_here {
            let aside_chain = own_chain.unwrap_or(self.chain);
            self.move_aside(&Self::file_name(principal), &aside_chain)?;
            return Ok(Opened::Live(base));
        }
        // The lines: `held` and `done`, no third. A middle line that does not
        // parse is a damaged body — HALT (§3c.3).
        let mut held: Vec<HeldLine> = Vec::new();
        let mut max_k = 0u64;
        for line in &complete[1..] {
            let v: Value = match serde_json::from_str(line) {
                Ok(v) => v,
                Err(_) => return Ok(Opened::Halted { path, why: HaltWhy::Damaged }),
            };
            if let Some(k) = v.get("held").and_then(Value::as_u64) {
                max_k = max_k.max(k);
                held.push(HeldLine {
                    k,
                    doc: v["doc"].as_str().unwrap_or_default().to_string(),
                    id: v["id"].as_str().map(str::to_string),
                    base: v["base"].as_u64().unwrap_or(0),
                    frame: v["frame"].clone(),
                    cause: v["cause"].as_str().unwrap_or_default().to_string(),
                    refusal: v.get("refusal").filter(|r| !r.is_null()).cloned(),
                    sent: v["sent"].as_bool().unwrap_or(false),
                    time: v["time"].as_u64().unwrap_or(0),
                });
            } else if let Some(k) = v.get("done").and_then(Value::as_u64) {
                max_k = max_k.max(k);
                held.retain(|l| l.k != k);
            } else {
                return Ok(Opened::Halted { path, why: HaltWhy::Damaged });
            }
        }
        Ok(Opened::Live(HeldFile { held, next_k: max_k + 1, created: true, ..base }))
    }

    /// THE ASIDE (`aside_name`'s form, the index's idiom): `name` renamed to
    /// `principal-<n>.held.aside.<its own chain>.<m>` by a rename that NEVER
    /// overwrites — the name taken by a hard link, which fails where it exists,
    /// then the original unlinked. A second misplaced file lands beside the
    /// first at `.2`. Said once in the shell's own window, never to the page.
    pub fn move_aside(&self, name: &str, own_chain: &Chain) -> io::Result<PathBuf> {
        let from = self.path.join(name);
        for m in 1u32.. {
            let to = self.path.join(aside_name(name, own_chain, m));
            match fs::hard_link(&from, &to) {
                Ok(()) => {
                    fs::remove_file(&from)?;
                    return Ok(to);
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e),
            }
        }
        unreachable!("the ordinals do not run out")
    }
}

/// ONE PRINCIPAL's FILE: its un-done `held` lines in `k` order, the next
/// ordinal, and whether the header is on disk yet (created lazily on the first
/// append, under `create_new`).
pub struct HeldFile {
    path: PathBuf,
    chain: Chain,
    principal: u64,
    account: String,
    held: Vec<HeldLine>,
    next_k: u64,
    created: bool,
}

/// Why a `done` could not be written.
#[derive(Debug, PartialEq, Eq)]
pub enum DoneError {
    /// No `held` line of that ordinal stands — the writer refuses it (T4).
    NoSuchLine,
}

impl HeldFile {
    /// The un-done `held` lines, in `k` order.
    pub fn lines(&self) -> &[HeldLine] {
        &self.held
    }

    /// Whether the file is on disk (a header has been written).
    #[cfg(test)]
    pub fn on_disk(&self) -> bool {
        self.path.exists()
    }

    /// APPEND A `held` LINE — one `write` then `sync_data` (PERSIST-FIRST, J1):
    /// the header written once first where the file is new. Answers the ordinal
    /// the line took. An I/O failure (a full disk, a read-only volume) is
    /// `store_unwritable` to the caller, which then holds the burst in memory.
    #[allow(clippy::too_many_arguments)]
    pub fn hold(&mut self, doc: &str, id: Option<&str>, base: u64, frame: Value, cause: &str, refusal: Option<Value>, sent: bool) -> io::Result<u64> {
        let line = HeldLine { k: self.next_k, doc: doc.to_string(), id: id.map(str::to_string), base, frame, cause: cause.to_string(), refusal, sent, time: now_ms() };
        self.ensure_header()?;
        self.append(&held_line_bytes(&line))?;
        self.next_k += 1;
        let k = line.k;
        self.held.push(line);
        Ok(k)
    }

    /// RE-MARK a standing line's cause (and `sent`) in place of a fresh hold —
    /// a hold that recurs, or a `moved` re-facing — appended as a new `held`
    /// line of the same ordinal is NOT done; instead the in-memory line is
    /// updated and a fresh `held` line written so the file reads it on reopen.
    /// The ordinal is kept; no `done` is owed. Answers whether a line stood.
    pub fn remark(&mut self, k: u64, cause: &str, refusal: Option<Value>, sent: bool) -> io::Result<bool> {
        let Some(mut line) = self.held.iter().find(|l| l.k == k).cloned() else { return Ok(false) };
        line.cause = cause.to_string();
        line.refusal = refusal;
        line.sent = sent;
        line.time = now_ms();
        self.ensure_header()?;
        self.append(&held_line_bytes(&line))?;
        if let Some(slot) = self.held.iter_mut().find(|l| l.k == k) {
            *slot = line;
        }
        Ok(true)
    }

    /// APPEND A `done` LINE resolving ordinal `k` — `kept` with the `at` of its
    /// ack (or the row the read found), `dropped` by the person's act (§3c.2).
    /// COMPACTION: once every `held` line has its `done`, the file is REMOVED
    /// under the lock (§3c.3). A `done` for an ordinal with no `held` line is
    /// REFUSED (T4).
    pub fn done(&mut self, k: u64, kept: bool, at: Option<u64>) -> Result<(), DoneError> {
        if !self.held.iter().any(|l| l.k == k) {
            return Err(DoneError::NoSuchLine);
        }
        if self.append(&done_line_bytes(k, kept, at)).is_err() {
            // A failed `done` append (a full disk) is harmless: the line stands
            // and the next resend's read heals it (§3c.5). Nothing is removed.
            return Ok(());
        }
        self.held.retain(|l| l.k != k);
        if self.held.is_empty() {
            // The file is gone; the directory stays. A fresh burst recreates it.
            let _ = fs::remove_file(&self.path);
            self.created = false;
            self.next_k = 1;
        }
        Ok(())
    }

    /// The header written once under `create_new` (`store.rs`'s idiom), mode
    /// `0600`; a no-op once it stands.
    fn ensure_header(&mut self) -> io::Result<()> {
        if self.created {
            return Ok(());
        }
        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut file = opts.open(&self.path)?;
        file.write_all(&header_bytes(&self.chain, self.principal, &self.account))?;
        file.sync_data()?;
        self.created = true;
        Ok(())
    }

    /// ONE `write` of the whole line, then `sync_data` BEFORE the caller builds
    /// its answer (PERSIST-FIRST). A `#[cfg(test)]` seam forces the sync to
    /// fail (T5's `store_unwritable`) and interposes a read of the file after
    /// the sync, so a suite pins the line ON DISK before the answer is built.
    ///
    /// UNVERIFIED HERE (§3c.3, the record §7 items 2–3): that one small
    /// `write_all` is one `write(2)` (and may split for a large buffer — the
    /// torn-last-line rule covers either), and that `sync_data` orders the line
    /// before the answer, is Rust's std and APFS's `F_FULLFSYNC` — the barrier
    /// the kernel's own durability assumes, not measured here. The write-ahead
    /// variant (every burst appended before its dial, tombstoned at its ack, so
    /// even the burst in flight survives a crash) is named and NOT taken
    /// (§3c.6): R14's bound does not ask it, and the typing cadence would pay a
    /// synced append and tombstone churn.
    fn append(&self, bytes: &[u8]) -> io::Result<()> {
        let mut file = OpenOptions::new().append(true).open(&self.path)?;
        file.write_all(bytes)?;
        #[cfg(test)]
        if tests::fail_sync() {
            return Err(io::Error::new(io::ErrorKind::StorageFull, "the held store's sync was made to fail"));
        }
        file.sync_data()?;
        #[cfg(test)]
        tests::after_sync(&self.path);
        Ok(())
    }
}

/// The header's exact bytes (§3c.2): members in one order, no whitespace
/// outside strings, lowercase hex, one `\n`.
fn header_bytes(chain: &Chain, principal: u64, account: &str) -> Vec<u8> {
    format!("{{\"type\":\"skep-held-bursts\",\"v\":1,\"board\":\"{chain}\",\"principal\":{principal},\"account\":{}}}\n", json_str(account)).into_bytes()
}

/// A `held` line's exact bytes (§3c.2): `held, doc, id?, base, frame, cause,
/// refusal?, sent, time`, in that order.
fn held_line_bytes(l: &HeldLine) -> Vec<u8> {
    let mut s = format!("{{\"held\":{},\"doc\":{}", l.k, json_str(&l.doc));
    if let Some(id) = &l.id {
        s.push_str(&format!(",\"id\":{}", json_str(id)));
    }
    s.push_str(&format!(",\"base\":{},\"frame\":{}", l.base, l.frame));
    s.push_str(&format!(",\"cause\":{}", json_str(&l.cause)));
    if let Some(r) = &l.refusal {
        s.push_str(&format!(",\"refusal\":{r}"));
    }
    s.push_str(&format!(",\"sent\":{},\"time\":{}}}\n", l.sent, l.time));
    s.into_bytes()
}

/// A `done` line's exact bytes (§3c.2): `done, as, at?, time`, in that order.
fn done_line_bytes(k: u64, kept: bool, at: Option<u64>) -> Vec<u8> {
    let mut s = format!("{{\"done\":{k},\"as\":{}", if kept { "\"kept\"" } else { "\"dropped\"" });
    if let Some(at) = at {
        s.push_str(&format!(",\"at\":{at}"));
    }
    s.push_str(&format!(",\"time\":{}}}\n", now_ms()));
    s.into_bytes()
}

/// A string as a JSON string literal — the one escaper the forms share.
fn json_str(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| "\"\"".to_string())
}

#[cfg(test)]
mod tests;
