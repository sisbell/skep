//! THE OPERATOR's TOOLS — THE INVENTORY AND THE PULL (`media.md` §Recovery,
//! "THE OPERATOR CAN LIST THE HOLES", "AND IS RESTORED BY THE OPERATOR's
//! OWN PULL", "NEITHER OPENS THE STORE AS skepd DOES"; the register M-I5
//! (d), M-I5 (e), M-I6 (d), M-I6 (f); DOCTRINE D9): two acts over a BOARD
//! DIRECTORY, the `skepd` binary's two subcommands, run with NO server —
//! no port, no session, no `/health`, no log line of the daemon's. Both are
//! the ORIGIN cell's: a replica's reference cells are foreign and their
//! bytes a cache's, which neither tool reads.
//!
//! THE INVENTORY ([`inventory`]; `skepd inventory --data-dir <dir>
//! [--no-rehash]`), OVER A DIRECTORY NO DAEMON SERVES — a stopped board, a
//! served board's one moment's copy, a backup: it opens the board's JOURNAL
//! through the engine's ordinary public open — recovery reads the
//! committed state, under the exclusion lock the kernel takes, so a
//! directory a daemon serves is refused at that lock and never read
//! beside it — walks the replayed world into a FRESH cell index through
//! the walk the daemon's open runs (`media/index.rs`), and opens the blob
//! store READ-ONLY (`skep-blobs`'s `Store::inspect`: the logs read as the
//! open reads them, their torn tails cut in memory alone, nothing
//! reconciled, compacted, swept, synced or created). It prints ONE JSON
//! object: THE HOLES — every reference cell (the picture kind's; a blind
//! cell is never a hole, nothing of its kind naming a file) whose file is
//! absent at its hex, present at a length other than the cell's `size`,
//! or present and re-hashing to another hash — the re-hash one whole read
//! per file, skipped by `--no-rehash`; PER ACCOUNT its base (the index's
//! number) and its pending bytes (its live leases on hashes none of its
//! cells names, plus its standing uploads' bytes received), the UNATTRIBUTED
//! bytes no account's scope holds (a live lease's or a standing upload's
//! whose key spells no principal of this build), and THE VENUE TOTAL they
//! all sum to — the gate's own figure, under the gate's own pending rule
//! (`MediaGate::counts_as_pending`), which the limits record is written
//! against; the standing uploads and the expired ones by count; the halt
//! marks and any foreign designation directory. It RECORDS NO READ anywhere
//! (D9) and writes nothing under `blobs/`. What the engine's open writes to
//! the directory it is run over — the copy the inventory proves — is the
//! kernel's own: the lock file `kernel.lock`, created where absent; a torn
//! tail cut off the last segment where a crash left one; and a stray
//! `checkpoint.tmp` — a checkpoint a crash or a full volume left
//! half-written — removed, which the inventory reports as
//! `journal.stray_checkpoint_removed`; no checkpoint, no commit, no head,
//! no feed sidecar — the daemon's own open is never run.
//!
//! THE PULL ([`pull`]; `skepd pull --data-dir <dir> [--hash <hex>] <file>`):
//! takes a FILE, hashes it (BLAKE3) and INSTALLS it at
//! `blobs/blake3/<hex>` as the PUT's order installs one (`Store::install_file`:
//! the temp file in the designation directory, fsynced, renamed onto the
//! hash name — REPLACE where a file stands, which ends any hole — the
//! directory fsynced), ONLY WHERE A COMMITTED REFERENCE CELL NAMES THAT
//! HASH: the pull is a restore, never a deposit, and writes NO lease, NO
//! record, NO journal entry and NO log line of the daemon's. Which cell
//! names the hash is read one of two ways: with no `--hash`, off the
//! board's own journal — opened as the inventory opens it, which the
//! kernel's lock refuses beside a serving daemon — a file no committed
//! cell names refused with one line; with `--hash <hex>`, off the
//! inventory's own listing, the hex the operator took from it, the file
//! held to it and the journal left unopened — the form that runs BESIDE A
//! SERVING DAEMON holding none of its gates, the daemon's fetch serving the
//! restored file at its next read. A daemon's open that meets the pull's
//! temp file mid-pull removes it as an orphan, the pull then run again.

use std::fmt;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use serde_json::Value;
use skep_blobs::{HashFunction, Inspection, Store};
use skep_engine::{Engine, EngineError};
use skep_kernel::{BurnedSeqPolicy, CheckpointPolicy, Durability, KernelConfig, SaltSource};
use skep_namespace::{HasM3, PrincipalId};

use crate::codec::obj;
use crate::media::cell::DESIGNATION;
use crate::media::gate::{wall_clock_ms, MediaGate};
use crate::media::index::{self, CellIndex};
use crate::media::pruner::PINNED_DESIGNATIONS;

/// Why a tool refused — each one line to the operator.
#[derive(Debug)]
#[non_exhaustive]
pub enum ToolError {
    /// No board stands at the directory: no journal segment there.
    NoBoard(PathBuf),
    /// The journal is HELD — a daemon serves the directory, and the
    /// kernel's exclusion lock refused this open.
    JournalHeld(PathBuf),
    /// The engine's open refused the journal for another reason — a
    /// corrupt journal, a bad checkpoint: the operator's condition.
    Journal(EngineError),
    /// The blob store or the file could not be read.
    Io(io::Error),
    /// The pull: a hex that is not 64 lowercase hexadecimal characters.
    NotAHash(String),
    /// The pull: the file's hash is one no committed reference cell names
    /// — a restore of nothing, refused rather than deposited.
    Unnamed { hex: String },
    /// The pull's install refused the file — its bytes hash to another
    /// hash than the one named — or could not be written.
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
            ToolError::Install(e) => write!(f, "nothing installed: {e}"),
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

/// THE INVENTORY over the board at `data_dir` (the module doc): one JSON
/// object, its members in sorted order, the holes re-hashed where `rehash`
/// — one whole read per referenced file.
pub fn inventory(data_dir: &Path, rehash: bool) -> Result<Value, ToolError> {
    require_board(data_dir)?;
    let engine = open_journal(data_dir)?;
    let snapshot = engine.kernel().snapshot();
    let index = CellIndex::new();
    let report = index::walk(&snapshot, &index);
    let world = snapshot.world();
    let now = wall_clock_ms();
    let store = inspect_store(data_dir)?;

    // THE HOLES: every reference whose file is absent, short or long, or —
    // re-hashed — not the bytes the cell names.
    let references = index.references();
    let mut holes = Vec::new();
    for r in &references {
        let fault = match &store {
            None => Some("absent"),
            Some(s) => match s.blob_size(&r.designation, &r.hex)? {
                None => Some("absent"),
                Some(len) if len != r.size => Some("length"),
                Some(_) if rehash => {
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

    // PER ACCOUNT: the base off the index, the pending bytes off the store's
    // records by the gate's own rule (`MediaGate::counts_as_pending`) — every
    // principal the index or either log names — and the UNATTRIBUTED bytes, a
    // live lease's or a standing upload's whose key spells no principal of
    // this build: in no account's scope, and in the venue's total as the gate
    // counts it.
    let mut accounts: std::collections::BTreeMap<PrincipalId, (u64, u64)> =
        index.accounts().into_iter().map(|(p, base)| (p, (base, 0))).collect();
    let mut unattributed = 0u64;
    let (mut standing_uploads, mut expired_uploads, mut orphan_partials, mut asides) = (0usize, 0usize, 0usize, 0usize);
    if let Some(s) = &store {
        for lease in s.leases() {
            if now >= lease.expires || !MediaGate::counts_as_pending(&index, lease) {
                continue;
            }
            match MediaGate::principal_of_key(&lease.principal) {
                Some(p) => accounts.entry(p).or_insert((0, 0)).1 += lease.size,
                None => unattributed = unattributed.saturating_add(lease.size),
            }
        }
        for record in s.uploads() {
            if now >= record.expires {
                expired_uploads += 1;
                continue;
            }
            standing_uploads += 1;
            match MediaGate::principal_of_key(&record.principal) {
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
    Ok(obj(vec![
        ("accounts", Value::Array(accounts)),
        ("asides", Value::Number((asides as u64).into())),
        ("cells", Value::Number((report.cells as u64).into())),
        ("expired_uploads", Value::Number((expired_uploads as u64).into())),
        ("foreign_designations", Value::Array(foreign)),
        ("halts", Value::Array(halts)),
        ("holes", Value::Array(holes)),
        (
            "journal",
            obj(vec![
                ("log_position", Value::Number(engine.kernel().current_seq().0.into())),
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
            ]),
        ),
        ("orphan_partials", Value::Number((orphan_partials as u64).into())),
        ("references", Value::Number((references.len() as u64).into())),
        ("rehashed", Value::Bool(rehash)),
        ("standing_uploads", Value::Number((standing_uploads as u64).into())),
        ("unattributed", Value::Number(unattributed.into())),
        ("values_walked", Value::Number((report.values as u64).into())),
        ("venue_total", Value::Number(venue_total.into())),
    ]))
}

/// THE PULL of `file` into the board at `data_dir` (the module doc): held
/// to `expected` where one is given, the journal unopened; else to the
/// board's own index, read off its journal.
pub fn pull(data_dir: &Path, file: &Path, expected: Option<&str>) -> Result<Pulled, ToolError> {
    let hex = match expected {
        Some(hex) => {
            if !is_hex64(hex) {
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
    let root = data_dir.join("blobs");
    let finished = Store::install_file(&root, HashFunction::Blake3, file, Some(&hex)).map_err(ToolError::Install)?;
    Ok(Pulled { path: root.join(&finished.designation).join(&finished.hex), hex: finished.hex, size: finished.size })
}

/// A board stands at `dir`: a directory holding at least one journal
/// segment. Nothing is created for a directory that holds none — the
/// engine's open would make a genesis there.
fn require_board(dir: &Path) -> Result<(), ToolError> {
    let has_segment = fs::read_dir(dir)
        .map(|entries| {
            entries.flatten().any(|e| {
                let name = e.file_name().to_string_lossy().into_owned();
                name.starts_with("seg-") && name.ends_with(".wal")
            })
        })
        .unwrap_or(false);
    if has_segment {
        Ok(())
    } else {
        Err(ToolError::NoBoard(dir.to_path_buf()))
    }
}

/// The engine's ordinary public open over `dir` — the daemon's own
/// configuration but for the checkpoint cadence, MANUAL here, so no
/// checkpoint is ever taken: nothing commits through this handle. The
/// kernel's lock refused is the held journal, told apart from every other
/// refusal.
fn open_journal(dir: &Path) -> Result<Engine, ToolError> {
    let cfg = KernelConfig {
        durability: Durability::Fsync {
            journal_path: dir.to_path_buf(),
            retain_checkpoints: 2,
            burned_seq: BurnedSeqPolicy::Rollback,
        },
        checkpoint: CheckpointPolicy::Manual,
        salt: SaltSource::Os,
    };
    Engine::open(cfg).map_err(|e| {
        let mut source: Option<&(dyn std::error::Error + 'static)> = Some(&e);
        while let Some(err) = source {
            if let Some(io) = err.downcast_ref::<io::Error>() {
                if io.kind() == io::ErrorKind::WouldBlock {
                    return ToolError::JournalHeld(dir.to_path_buf());
                }
            }
            source = err.source();
        }
        ToolError::Journal(e)
    })
}

/// The store's inspection under `dir/blobs`, or `None` where no `blobs/`
/// stands — a board that never opened its store.
fn inspect_store(dir: &Path) -> Result<Option<Inspection>, ToolError> {
    let root = dir.join("blobs");
    if !root.is_dir() {
        return Ok(None);
    }
    Ok(Some(Store::inspect(root)?))
}

/// BLAKE3 of the file at `path`, as 64 lowercase hex — one whole read.
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

/// 64 lowercase hexadecimal characters — the hash's one spelling.
fn is_hex64(hex: &str) -> bool {
    hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The pull's spelling check, the hash of a file, and the refusals a
    /// directory with no board meets: nothing is created for it.
    #[test]
    fn the_hash_spelling_the_file_hash_and_a_directory_with_no_board() {
        assert!(is_hex64(&"ab".repeat(32)));
        assert!(!is_hex64(&"AB".repeat(32)));
        assert!(!is_hex64(&"ab".repeat(31)));
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("picture");
        fs::write(&file, b"the bytes").unwrap();
        assert_eq!(hash_file(&file).unwrap(), blake3::hash(b"the bytes").to_hex().to_string());
        let empty = dir.path().join("empty");
        fs::create_dir(&empty).unwrap();
        assert!(matches!(inventory(&empty, true), Err(ToolError::NoBoard(_))));
        assert!(matches!(pull(&empty, &file, None), Err(ToolError::NoBoard(_))));
        assert!(fs::read_dir(&empty).unwrap().next().is_none(), "nothing created where no board stands");
        assert!(matches!(pull(&empty, &file, Some("xyz")), Err(ToolError::NotAHash(_))));
        assert!(matches!(inventory(&dir.path().join("absent"), true), Err(ToolError::NoBoard(_))));
    }
}
