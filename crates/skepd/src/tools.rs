//! The operator's tools: the inventory and the pull.
//!
//! They are two acts over a board directory (`media.md` §Recovery, "THE
//! OPERATOR CAN LIST THE HOLES", "AND IS RESTORED BY THE OPERATOR's OWN
//! PULL", "NEITHER OPENS THE STORE AS skepd DOES"; the register M-I5 (d),
//! M-I5 (e), M-I6 (d), M-I6 (f); DOCTRINE D9), the `skepd` binary's two
//! subcommands, run with no server — no port, no session, no `/health`, no
//! log line of the daemon's. Both are the origin cell's: a replica's
//! reference cells are foreign and their bytes a cache's, which neither
//! tool reads.
//!
//! **The inventory** ([`inventory`];
//! `skepd inventory --data-dir <dir> [--no-rehash]`), over a directory no
//! daemon serves — a stopped board, a served board's one moment's copy, a
//! backup: it opens the board's journal through the engine's ordinary
//! public open — recovery reads the committed state, under the exclusion
//! lock the kernel takes, so a directory a daemon serves is refused at that
//! lock and never read beside it — walks the replayed world into a fresh
//! cell index through the walk the daemon's open runs (`skep-media`'s
//! `index.rs`), and opens the blob store read-only (`skep-blobs`'s
//! `Store::inspect`: the logs read as the open reads them, their torn tails
//! cut in memory alone, nothing reconciled, compacted, swept, synced or
//! created). It prints one JSON object: the holes — every reference cell
//! (the picture kind's; a blind cell is never a hole, nothing of its kind
//! naming a file) whose file is absent at its hex, present at a length
//! other than the cell's `size`, or present and re-hashing to another hash
//! — the re-hash one whole read per file, skipped under
//! [`HoleCheck::LengthOnly`] (`--no-rehash`); per account its base (the
//! index's number) and its pending bytes (its live leases on hashes none of
//! its cells names, plus its standing uploads' bytes received), the
//! unattributed bytes no account's scope holds (a live lease's or a
//! standing upload's whose key spells no principal of this build), and the
//! venue total they all sum to — the gate's own figure, under the gate's
//! own pending rule and its own reading of a record's key
//! (`MediaGate::lease_counted`, `MediaGate::upload_counted`, the
//! inventory's two calls on `MediaGate`), which the limits record is
//! written against; the standing uploads and the expired ones by count;
//! the halt marks and any foreign designation directory; the asides and
//! the partials no upload record names, by count; the cells and the values
//! the walk read and the files the cells reference, by count, and whether
//! the holes were re-hashed; the blob store's two logs as read
//! (`blob_logs`: each by name, whether it stood, its whole lines, the lines
//! read as no record, and the cut the open would make — where trust ends,
//! the whole lines after it, and whether it is damage, the first untrusted
//! line whole, or a crash's torn line); and the journal's log position, its
//! start point, the checkpoints its open skipped and the corrupt runs it
//! passed over, by count, the tail it cut with the position the cut claimed,
//! where it began, the intact frames among it and the files it kept them
//! in, and every kept file standing beside the journal and the logs
//! (`journal.kept_files`, [`kept_files`]). It records no read anywhere (D9)
//! and writes nothing under `blobs/`. What the engine's open writes to the
//! directory it is run over — the copy the inventory proves — is the
//! kernel's own: the lock file `kernel.lock`, created where absent; a
//! crash's torn tail cut off the journal's end, which the inventory reports
//! as `journal.tail_cut` — the bytes cut, `0` where the last committed
//! marker ended the journal: a count and never `null`, since every open
//! runs the cut and a cut that took nothing leaves the journal a clean close
//! left it; and a stray `checkpoint.tmp` — a checkpoint a crash or a full
//! volume left half-written — removed, which the inventory reports as
//! `journal.stray_checkpoint_removed`; no checkpoint, no commit, no head,
//! no feed sidecar — the daemon's own open is never run. A copy whose tail
//! is damage rather than a crash's — an intact marker committing nothing, a
//! frame that does not decode, more bytes than one append leaves — is
//! refused by the kernel's own refusal ([`ToolError::Journal`]), the copy as
//! found: the tools accept no cut, so `journal.tail_cut_kept` never names a
//! file this run kept. So the copy is run over writable: one the open cannot
//! write — a read-only mount, a directory or a file without its write bit —
//! is refused by name ([`ToolError::ReadOnlyCopy`]), never read as a
//! journal that would not open.
//!
//! **The pull** ([`pull`];
//! `skepd pull --data-dir <dir> [--hash <hex>] <file>`): takes a file,
//! hashes it (BLAKE3) and installs it at `blobs/blake3/<hex>` as the PUT's
//! order installs one (`Store::install_file`: the temp file in the
//! designation directory, fsynced, renamed onto the hash name — replace
//! where a file stands, which ends any hole — the directory fsynced, then
//! `blobs/` and the board's own directory), for a hash a committed
//! reference cell names: the pull is a restore, never a deposit, and writes
//! no lease, no record, no journal entry and no log line of the daemon's.
//! Which cell names the hash is read one of two ways: with no `--hash`, off
//! the board's own journal — opened as the inventory opens it, which the
//! kernel's lock refuses beside a serving daemon — a file no committed cell
//! names refused with one line; with `--hash <hex>`, off the inventory's own
//! listing, the hex the operator took from it, which the pull checks
//! against no cell, the file held to it and the journal left unopened — the
//! form that runs beside a serving daemon holding none of its gates, the
//! daemon's fetch serving the restored file at its next read. A daemon's
//! open that meets the pull's temp file mid-pull removes it as an orphan,
//! the pull then run again.

use std::fmt;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use serde_json::Value;
use skep_blobs::{Inspection, Store};
use skep_engine::{Engine, EngineError};
use skep_kernel::{
    BurnedSeqPolicy, CheckpointPolicy, Durability, KernelConfig, OpenError, SaltSource,
};
use skep_media::cell::{DESIGNATION, HASH_BYTES, PINNED_DESIGNATIONS};
use skep_media::gate::{wall_clock_ms, Counted, MediaGate, DEPOSIT_FUNCTION, STORE_DIR};
use skep_media::index::{self, CellIndex};
use skep_namespace::{HasM3, PrincipalId};
use skep_util::json::{obj, parse_lower_hex};

/// Why a tool refused — each one line to the operator.
#[derive(Debug)]
#[non_exhaustive]
pub enum ToolError {
    /// No board stands at the directory: no journal segment there.
    ///
    /// Judged by the kernel's own test of a segment's name
    /// ([`board_stands`]), so a file the kernel would not read back is no
    /// board here either; a directory that does not exist holds none. A
    /// directory that cannot be read is not this but [`ToolError::Io`].
    NoBoard(PathBuf),
    /// The journal is held: the kernel's exclusion lock refused this open.
    ///
    /// A live kernel holds the directory — a serving daemon's, or another
    /// tool run's.
    JournalHeld(PathBuf),
    /// The copy cannot be written.
    ///
    /// It is a read-only mount, a directory or a file without its write bit,
    /// where the engine's open writes the kernel's lock and may cut a torn
    /// tail: the operator's copy to make writable, told apart from a journal
    /// that would not open.
    ReadOnlyCopy(PathBuf),
    /// The engine's open refused the journal for another reason.
    ///
    /// A corrupt journal, a bad checkpoint, a damaged tail — the kernel's
    /// refusal of a tail that is not a crash's, which the tools never accept
    /// the cut of: the operator's condition, named in the kernel's words.
    Journal(EngineError),
    /// The data directory, the blob store or the file could not be read.
    ///
    /// The data directory's listing failing other than for its absence —
    /// a permission, a device — is this, named `{dir}: list: {cause}`, and
    /// never [`ToolError::NoBoard`]: the board may well stand there.
    Io(io::Error),
    /// The pull: a hex that is not 64 lowercase hexadecimal characters.
    NotAHash(String),
    /// The pull: the file's hash is one no committed reference cell names.
    ///
    /// A restore of nothing, refused rather than deposited; `hex` is that
    /// hash.
    Unnamed { hex: String },
    /// The pull's install refused the file, or could not make it durable.
    ///
    /// A refusal — its bytes hash to another hash than the one named, no
    /// board directory stands at the path, or it could not be read or
    /// written — reads `nothing installed: …`; an install it could not make
    /// durable reads `installed at …, but …`. The store's error says which
    /// side of the rename it failed on (`Store::install_file`), and is said
    /// whole.
    Install(io::Error),
}

impl fmt::Display for ToolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ToolError::NoBoard(dir) => {
                write!(f, "no board at {}: no journal segment stands there", dir.display())
            }
            ToolError::JournalHeld(dir) => write!(
                f,
                "the journal at {} is held by a running daemon: run the inventory over a copy or \
                 a stopped board, and pass --hash <hex> from its listing to pull beside the daemon",
                dir.display()
            ),
            ToolError::ReadOnlyCopy(dir) => write!(
                f,
                "the copy at {} is read-only: the inventory's open writes the kernel's lock and may \
                 cut a torn tail; run it over a writable copy",
                dir.display()
            ),
            ToolError::Journal(e) => write!(f, "the journal could not be opened: {e}"),
            ToolError::Io(e) => write!(f, "{e}"),
            ToolError::NotAHash(hex) => {
                write!(f, "'{hex}' is not a hash: 64 lowercase hexadecimal characters")
            }
            ToolError::Unnamed { hex } => write!(
                f,
                "no committed reference cell names {hex}: the pull restores a file a cell already \
                 names and deposits nothing"
            ),
            ToolError::Install(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for ToolError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ToolError::Journal(e) => Some(e),
            ToolError::Io(e) | ToolError::Install(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for ToolError {
    fn from(e: io::Error) -> ToolError {
        ToolError::Io(e)
    }
}

/// What a pull installed.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Pulled {
    /// The file's hash, 64 lowercase hex — the name it stands under.
    pub hex: String,
    /// The file's byte count.
    pub size: u64,
    /// Where it stands: `<dir>/blobs/blake3/<hex>`.
    pub path: PathBuf,
}

/// What the inventory holds a referenced file's bytes to.
///
/// It is its length alone, or its length and — one whole read per file —
/// its hash (`--no-rehash` asks for the first).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HoleCheck {
    /// Length and hash.
    ///
    /// A file of the cell's length holding other bytes is a hole, found by
    /// reading it whole.
    Rehash,
    /// Length alone: no referenced file is read.
    LengthOnly,
}

/// Takes the inventory of the board at `data_dir` (the module doc).
///
/// It answers one JSON object, its members in sorted order, the holes found
/// under `check` — re-hashed, one whole read per referenced file, where it
/// is [`HoleCheck::Rehash`].
///
/// # Errors
///
/// In the order it meets them: [`ToolError::NoBoard`] where no journal
/// segment stands at `data_dir` or the directory does not stand, and
/// [`ToolError::Io`] where it cannot be read; [`ToolError::JournalHeld`]
/// where a live kernel holds the journal, [`ToolError::ReadOnlyCopy`] where
/// the copy cannot be written, and [`ToolError::Journal`] where the engine's
/// open refuses the journal for another reason — a damaged tail among them,
/// which the inventory never cuts; and [`ToolError::Io`] where the blob
/// store, the kept files' listing or a referenced file cannot be read.
pub fn inventory(data_dir: &Path, check: HoleCheck) -> Result<Value, ToolError> {
    require_board(data_dir)?;
    let engine = open_journal(data_dir)?;
    let snapshot = engine.kernel().snapshot();
    let index = CellIndex::new();
    let report = index::walk(&snapshot, &index);
    let world = snapshot.world();
    let now = wall_clock_ms();
    let store = inspect_store(data_dir)?;

    // The holes: every reference whose file is absent, short or long, or —
    // re-hashed — not the bytes the cell names.
    let references = index.references();
    let mut holes = Vec::new();
    for r in &references {
        let fault = match &store {
            None => Some("absent"),
            Some(s) => match s.blob_size(&r.designation, &r.hex)? {
                None => Some("absent"),
                Some(len) if len != r.size => Some("length"),
                Some(_) if check == HoleCheck::Rehash => {
                    let path = s.blob_path(&r.designation, &r.hex).expect("a listed reference's names are well-formed");
                    (hash_file(&path)? != r.hex).then_some("hash")
                }
                Some(_) => None,
            },
        };
        if let Some(fault) = fault {
            holes.push(obj(vec![
                ("cells", Value::Array(r.cells.iter().map(|c| Value::String(c.to_string())).collect())),
                ("designation", Value::String(r.designation.clone())),
                ("fault", Value::String(fault.into())),
                ("hash", Value::String(r.hex.clone())),
                ("size", Value::Number(r.size.into())),
            ]));
        }
    }

    // Per account: the base off the index, the pending bytes off the store's
    // records by the gate's own rule (`MediaGate::lease_counted`,
    // `MediaGate::upload_counted`) — every principal the index names or a
    // live lease or standing upload counts pending — and the unattributed
    // bytes, a live lease's or a standing upload's whose key spells no
    // principal of this build: in no account's scope, and in the venue's
    // total as the gate counts it.
    let mut accounts: std::collections::BTreeMap<PrincipalId, (u64, u64)> =
        index.accounts().into_iter().map(|(p, base)| (p, (base, 0))).collect();
    let mut unattributed = 0u64;
    let (mut standing_uploads, mut expired_uploads, mut orphan_partials, mut asides) = (0usize, 0usize, 0usize, 0usize);
    if let Some(s) = &store {
        for lease in s.leases() {
            if now >= lease.expires {
                continue;
            }
            match MediaGate::lease_counted(&index, lease) {
                Counted::Base => {}
                Counted::Pending(p) => accounts.entry(p).or_insert((0, 0)).1 += lease.size,
                Counted::Unattributed => unattributed = unattributed.saturating_add(lease.size),
            }
        }
        for record in s.uploads() {
            if now >= record.expires {
                expired_uploads += 1;
                continue;
            }
            standing_uploads += 1;
            match MediaGate::upload_counted(record) {
                Some(p) => accounts.entry(p).or_insert((0, 0)).1 += record.offset,
                None => unattributed = unattributed.saturating_add(record.offset),
            }
        }
        for designation in PINNED_DESIGNATIONS {
            asides += s.asides_of(designation)?.len();
            orphan_partials += s
                .partials_of(designation)?
                .into_iter()
                .filter(|id| !s.uploads().iter().any(|r| r.id == *id))
                .count();
        }
    }
    let venue_total =
        accounts.values().fold(unattributed, |acc, (b, p)| acc.saturating_add(*b).saturating_add(*p));
    let accounts: Vec<Value> = accounts
        .into_iter()
        .map(|(p, (base, pending))| {
            obj(vec![
                (
                    "account",
                    world.m3().principal_prefix(p).map_or(Value::Null, |a| Value::String(a.tumbler().to_string())),
                ),
                ("base", Value::Number(base.into())),
                ("pending", Value::Number(pending.into())),
                ("principal", Value::Number(p.0.into())),
            ])
        })
        .collect();

    let halts: Vec<Value> = index
        .halts()
        .into_iter()
        .map(|h| {
            obj(vec![
                ("at", Value::String(h.at.tumbler().to_string())),
                ("fault", Value::String(h.fault)),
                ("kind", Value::String(h.kind)),
            ])
        })
        .collect();
    let foreign: Vec<Value> = match &store {
        Some(s) => s
            .designation_dirs()?
            .into_iter()
            .filter(|d| !PINNED_DESIGNATIONS.contains(&d.as_str()))
            .map(Value::String)
            .collect(),
        None => Vec::new(),
    };
    let recovery = engine.recovery();
    // The blob store's two logs as the inspection read them: what the open
    // would cut and keep, and the lines it would drop, cut and kept nowhere
    // by the inspection.
    let blob_logs: Vec<Value> = match &store {
        Some(s) => {
            let (uploads_log, leases_log) = s.logs();
            [uploads_log, leases_log].into_iter().map(log_read_object).collect()
        }
        None => Vec::new(),
    };
    // The kept files beside the journal and the logs: every `*.cut-*` the
    // copy holds, this open's among them (`operations.md` §3.5 step 2).
    let kept_files: Vec<Value> = kept_files(data_dir)?.into_iter().map(Value::String).collect();
    let number = |n: u64| Value::Number(n.into());
    let strings = |names: &[String]| {
        Value::Array(names.iter().map(|name| Value::String(name.clone())).collect())
    };
    // The change feed's coverage: the first position `commits.log` holds a
    // line for, read off the file alone — the one change-feed file the
    // inventory reads, and for this member alone — `null` where the copy
    // holds no such line, and the failure's words where the OS refused the
    // read, so a copy whose feed file is unreadable still proves its journal.
    let feed_from = match skep_core::commits::Commits::feed_first_held(data_dir) {
        Ok(Some(first)) => Value::Number(first.into()),
        Ok(None) => Value::Null,
        Err(e) => Value::String(format!("unread: {e}")),
    };
    Ok(obj(vec![
        ("accounts", Value::Array(accounts)),
        ("asides", Value::Number((asides as u64).into())),
        ("blob_logs", Value::Array(blob_logs)),
        ("cells", Value::Number((report.cells as u64).into())),
        ("expired_uploads", Value::Number((expired_uploads as u64).into())),
        ("foreign_designations", Value::Array(foreign)),
        ("halts", Value::Array(halts)),
        ("holes", Value::Array(holes)),
        (
            "journal",
            obj(vec![
                ("feed_from", feed_from),
                ("kept_files", Value::Array(kept_files)),
                ("log_position", Value::Number(engine.kernel().current_seq().0.into())),
                // The corrupt runs below the start point the open read and
                // passed over, which a fallback past that start point meets.
                ("runs_passed_over", number(recovery.map_or(0, |r| r.runs_passed_over))),
                (
                    "skipped_checkpoints",
                    Value::Number((recovery.map_or(0, |r| r.skipped.len()) as u64).into()),
                ),
                ("start_point", Value::Number(recovery.map_or(0, |r| r.start_point.0).into())),
                (
                    "stray_checkpoint_removed",
                    engine
                        .kernel()
                        .stray_checkpoint_removed()
                        .map_or(Value::Null, |n| Value::Number(n.into())),
                ),
                // The tail cut's bytes: a count, `0` for a clean close — the
                // kernel's member is one, every journaled open running the
                // cut — and `0` too where the engine gave no account, as the
                // start point renders the same absence. Beside it, what the
                // count does not say: the position an intact marker in the
                // cut claimed (`null` where none did), where the cut began
                // (`null` where nothing was cut), the intact frames among the
                // cut bytes, and the files this open kept them in — never
                // more than none, since the tools accept no damaged tail's
                // cut, so a copy whose tail is damage is refused instead.
                ("tail_cut", Value::Number(recovery.map_or(0, |r| r.tail_cut).into())),
                (
                    "tail_cut_claimed",
                    recovery.and_then(|r| r.tail_cut_claimed).map_or(Value::Null, |c| number(c.0)),
                ),
                (
                    "tail_cut_from",
                    recovery.and_then(|r| r.tail_cut_from.as_ref()).map_or(Value::Null, |(seg, b)| {
                        obj(vec![("byte", number(*b)), ("segment", Value::String(seg.clone()))])
                    }),
                ),
                ("tail_cut_intact", number(recovery.map_or(0, |r| r.tail_cut_intact))),
                ("tail_cut_kept", strings(recovery.map_or(&[][..], |r| &r.tail_cut_kept))),
            ]),
        ),
        ("orphan_partials", Value::Number((orphan_partials as u64).into())),
        ("references", Value::Number((references.len() as u64).into())),
        ("rehashed", Value::Bool(check == HoleCheck::Rehash)),
        ("standing_uploads", Value::Number((standing_uploads as u64).into())),
        ("unattributed", Value::Number(unattributed.into())),
        ("values_walked", Value::Number((report.values as u64).into())),
        ("venue_total", Value::Number(venue_total.into())),
    ]))
}

/// Pulls `file` into the board at `data_dir` (the module doc).
///
/// The file is held to `expected` where one is given, the journal unopened;
/// else to the board's own index, read off its journal.
///
/// # Errors
///
/// With `expected`: [`ToolError::NotAHash`] where it is not 64 lowercase
/// hexadecimal characters. Without it, in the order the pull meets them:
/// [`ToolError::NoBoard`], [`ToolError::JournalHeld`],
/// [`ToolError::ReadOnlyCopy`] or [`ToolError::Journal`] as [`inventory`]
/// meets them; [`ToolError::Io`] where `file` cannot be read; and
/// [`ToolError::Unnamed`] where no committed reference cell names its hash.
/// Either way, last, [`ToolError::Install`] where the install refuses the
/// file — its bytes hashing to another hash than the one named among the
/// causes — or cannot make it durable.
pub fn pull(data_dir: &Path, file: &Path, expected: Option<&str>) -> Result<Pulled, ToolError> {
    let hex = match expected {
        Some(hex) => {
            if parse_lower_hex::<HASH_BYTES>(hex).is_none() {
                return Err(ToolError::NotAHash(hex.to_string()));
            }
            hex.to_string()
        }
        None => {
            require_board(data_dir)?;
            let engine = open_journal(data_dir)?;
            let index = CellIndex::new();
            index::walk(&engine.kernel().snapshot(), &index);
            let hex = hash_file(file)?;
            if !index.referenced(DESIGNATION, &hex) {
                return Err(ToolError::Unnamed { hex });
            }
            hex
        }
    };
    // The gate's function for the schema's designation — the designation
    // the index read above names — under the store's directory the gate
    // opens, so the file lands where the binding and the fetch read it.
    let root = data_dir.join(STORE_DIR);
    let finished = Store::install_file(&root, DEPOSIT_FUNCTION, file, Some(&hex)).map_err(ToolError::Install)?;
    Ok(Pulled { path: root.join(&finished.designation).join(&finished.hex), hex: finished.hex, size: finished.size })
}

/// Returns whether a board stands at `dir`: the kernel's own answer.
///
/// A board is a directory holding at least one journal segment, judged by
/// the kernel's test of a segment's name (`skep_kernel::journal_stands`):
/// the one spelling its writer emits, `seg-<n>.wal`, read back by the same
/// round trip — so a file named `seg-01.wal`, which the kernel would not
/// read, is no segment here either, and a tool that trusted it would open a
/// fresh journal beside it. The binary asks this before it begins a board
/// (`--create`), the two tools before they open one. Nothing is created.
///
/// # Errors
///
/// The directory could not be listed, named `{dir}: list: {cause}`, the
/// kind kept: `NotFound` where it does not stand, which the callers read
/// as no board, and every other kind — a permission, a device — as the
/// read's own failure, never as a directory with no board in it.
pub fn board_stands(dir: &Path) -> io::Result<bool> {
    skep_kernel::journal_stands(dir)
}

/// Checks that a board stands at `dir` ([`board_stands`]).
///
/// Nothing is created for a directory that holds none — the engine's open
/// would make a genesis there.
///
/// # Errors
///
/// [`ToolError::NoBoard`] where `dir` holds no journal segment or does not
/// stand; [`ToolError::Io`] where it cannot be read.
fn require_board(dir: &Path) -> Result<(), ToolError> {
    match board_stands(dir) {
        Ok(true) => Ok(()),
        Ok(false) => Err(ToolError::NoBoard(dir.to_path_buf())),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Err(ToolError::NoBoard(dir.to_path_buf())),
        Err(e) => Err(ToolError::Io(e)),
    }
}

/// Returns the kept files beside the journal and the logs at `dir`, sorted.
///
/// They are every regular file whose name holds `.cut-` in the data
/// directory and in `blobs/` under it — the kernel's `seg-<n>.wal.cut-<byte>`
/// (`….<k>`), the change feed's `commits.log.cut-<byte>` and
/// `feed-*.log.cut-<byte>`, the blob store's `blobs/uploads.log.cut-<byte>`
/// and `blobs/leases.log.cut-<byte>` — each named within the data
/// directory, as the lines name them. Each holds bytes an open cut as damage
/// and kept, a standing state until the operator removes it
/// (`operations.md` §1.1 m11): the daemon lists them at every open and at
/// the standing line's tick, the inventory under `journal.kept_files`. An
/// absent `blobs/` holds none.
///
/// # Errors
///
/// The data directory's listing failing, named `{dir}: list: {cause}`, or
/// `blobs/`'s save for its absence.
pub fn kept_files(dir: &Path) -> io::Result<Vec<String>> {
    let listed = |dir: &Path, e: io::Error| {
        io::Error::new(e.kind(), format!("{}: list: {e}", dir.display()))
    };
    let kept_in = |under: &Path, prefix: &str, out: &mut Vec<String>| -> io::Result<()> {
        for entry in fs::read_dir(under).map_err(|e| listed(under, e))? {
            let entry = entry.map_err(|e| listed(under, e))?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.contains(".cut-") && entry.file_type().map_err(|e| listed(under, e))?.is_file()
            {
                out.push(format!("{prefix}{name}"));
            }
        }
        Ok(())
    };
    let mut kept = Vec::new();
    kept_in(dir, "", &mut kept)?;
    let blobs = dir.join(STORE_DIR);
    match fs::symlink_metadata(&blobs) {
        Ok(meta) if meta.is_dir() => kept_in(&blobs, &format!("{STORE_DIR}/"), &mut kept)?,
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(listed(&blobs, e)),
    }
    kept.sort();
    Ok(kept)
}

/// Returns one blob log's reading as the inventory renders it.
///
/// The members, in sorted order: `absent`, `cut` — `null`, or the cut the
/// open would make: `at`, `len`, `lines_after` and `damage`, whether the
/// first untrusted line was whole, which the open keeps and a crash's torn
/// line is not — `lines`, `name` and `unread` (`LogRead`'s fields; nothing
/// is cut or kept by the inspection).
fn log_read_object(read: &skep_blobs::LogRead) -> Value {
    let number = |n: u64| Value::Number(n.into());
    obj(vec![
        ("absent", Value::Bool(read.absent)),
        (
            "cut",
            read.cut.map_or(Value::Null, |cut| {
                obj(vec![
                    ("at", number(cut.at)),
                    ("damage", Value::Bool(cut.damage())),
                    ("len", number(cut.len)),
                    ("lines_after", number(cut.lines_after as u64)),
                ])
            }),
        ),
        ("lines", number(read.lines as u64)),
        ("name", Value::String(read.name.clone())),
        ("unread", number(read.unread as u64)),
    ])
}

/// Opens the engine over `dir` through its ordinary public open.
///
/// It is the daemon's own configuration but for the checkpoint cadence,
/// manual here, so no checkpoint is ever taken: nothing commits through
/// this handle.
///
/// # Errors
///
/// Two of the kernel's I/O refusals are told apart from every other, read
/// off the open's own I/O arm: the lock refused (`WouldBlock`) is the held
/// journal, [`ToolError::JournalHeld`]; and a write the copy would not take
/// is the read-only copy, [`ToolError::ReadOnlyCopy`] —
/// `ReadOnlyFilesystem`, a snapshot mount's answer to every write, and
/// `PermissionDenied`, what a directory or a file without its write bit
/// answers the lock's creation, its open or the tail's cut (`chmod a-w`, an
/// immutable flag). Both are one fault to the operator — the copy is not
/// theirs to write — and take one remedy. Every other refusal is
/// [`ToolError::Journal`]: a refusal the open carries as a base's or a
/// damaged region's cause — a checkpoint that could not be read — is not
/// the copy's mode and stays the journal's own.
fn open_journal(dir: &Path) -> Result<Engine, ToolError> {
    let cfg = KernelConfig {
        durability: Durability::Fsync {
            journal_path: dir.to_path_buf(),
            retain_checkpoints: 2,
            burned_seq: BurnedSeqPolicy::Rollback,
            cut_damaged_tail: false,
        },
        checkpoint: CheckpointPolicy::Manual,
        salt: SaltSource::Os,
    };
    Engine::open(cfg).map_err(|e| {
        let mut source: Option<&(dyn std::error::Error + 'static)> = Some(&e);
        while let Some(err) = source {
            if let Some(OpenError::Io(io)) = err.downcast_ref::<OpenError>() {
                match io.kind() {
                    io::ErrorKind::WouldBlock => return ToolError::JournalHeld(dir.to_path_buf()),
                    io::ErrorKind::ReadOnlyFilesystem | io::ErrorKind::PermissionDenied => {
                        return ToolError::ReadOnlyCopy(dir.to_path_buf())
                    }
                    _ => {}
                }
            }
            source = err.source();
        }
        ToolError::Journal(e)
    })
}

/// Returns the store's inspection at [`STORE_DIR`] in `dir`.
///
/// `None` where no `blobs/` stands — a board that never opened its store.
///
/// # Errors
///
/// [`ToolError::Io`] where the store cannot be inspected
/// (`Store::inspect`'s refusals).
fn inspect_store(dir: &Path) -> Result<Option<Inspection>, ToolError> {
    let root = dir.join(STORE_DIR);
    if !root.is_dir() {
        return Ok(None);
    }
    Ok(Some(Store::inspect(root)?))
}

/// Returns the BLAKE3 hash of the file at `path`, as 64 lowercase hex.
///
/// It takes one whole read.
///
/// # Errors
///
/// The file's open or read error.
fn hash_file(path: &Path) -> io::Result<String> {
    let mut f = fs::File::open(path)?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize().to_hex().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Checks the hash spelling, the file hash and a directory with no board.
    ///
    /// The spelling check is the pull's. A directory with no board meets the
    /// refusals, and nothing is created for it.
    #[test]
    fn the_hash_spelling_the_file_hash_and_a_directory_with_no_board() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("picture");
        fs::write(&file, b"the bytes").unwrap();
        assert_eq!(hash_file(&file).unwrap(), blake3::hash(b"the bytes").to_hex().to_string());
        let empty = dir.path().join("empty");
        fs::create_dir(&empty).unwrap();
        assert!(matches!(inventory(&empty, HoleCheck::Rehash), Err(ToolError::NoBoard(_))));
        assert!(matches!(pull(&empty, &file, None), Err(ToolError::NoBoard(_))));
        assert!(fs::read_dir(&empty).unwrap().next().is_none(), "nothing created where no board stands");
        for not_a_hash in ["xyz".to_string(), "AB".repeat(32), "ab".repeat(31)] {
            assert!(
                matches!(pull(&empty, &file, Some(not_a_hash.as_str())), Err(ToolError::NotAHash(_))),
                "{not_a_hash}"
            );
        }
        assert!(fs::read_dir(&empty).unwrap().next().is_none(), "and a hash refused creates nothing");
        assert!(matches!(
            inventory(&dir.path().join("absent"), HoleCheck::Rehash),
            Err(ToolError::NoBoard(_))
        ));
    }
}
