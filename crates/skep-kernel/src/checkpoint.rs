//! Checkpoint files (§6): a serialized `W` @ `Seq` — a recoverable prefix-fold
//! cache, written temp → fsync → atomic-rename, with a header checksum over
//! the serialized `W` bytes. That checksum is what load validates before
//! trusting a base (serde deserialization alone does not reliably detect
//! bit-rot, and a silently-wrong base would defeat the `BadCheckpoint`
//! fallback chain).
//!
//! Layout: `[magic 4][seq u64 LE][crc32c(body) u32 LE][body_len u64 LE][body]`,
//! at `checkpoint.<S>`; the fixed temp name `checkpoint.tmp` is ignored by
//! recovery (a crash mid-checkpoint leaves at most an ignored `.tmp` — §6).

use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::journal::fsync_dir;

const MAGIC: [u8; 4] = *b"SKC1";
const HEADER_LEN: usize = 24;

/// One checkpoint on disk: the coordinate its name claims, and where it is.
pub(crate) struct CheckpointMeta {
    pub seq: u64,
    path: PathBuf,
}

impl CheckpointMeta {
    /// Load and validate this checkpoint. `None` means unreadable / failed its
    /// checksum / name-header seq mismatch — the caller falls back to the
    /// next-older retained checkpoint, then genesis-while-reachable (§6/§7).
    ///
    /// The name-versus-header cross-check compares two independent sources,
    /// which is what makes it a check rather than a tautology: the seq comes
    /// from the directory entry, the header from the bytes.
    pub(crate) fn load<W: DeserializeOwned>(&self) -> Option<W> {
        let data = fs::read(&self.path).ok()?;
        if data.len() < HEADER_LEN || data[0..4] != MAGIC {
            return None;
        }
        let seq = u64::from_le_bytes(data[4..12].try_into().ok()?);
        let crc = u32::from_le_bytes(data[12..16].try_into().ok()?);
        let body_len = u64::from_le_bytes(data[16..24].try_into().ok()?);
        if seq != self.seq {
            return None;
        }
        let body = &data[HEADER_LEN..];
        if body.len() as u64 != body_len || crc32c::crc32c(body) != crc {
            return None;
        }
        bincode::deserialize(body).ok()
    }
}

/// Where the checkpoint embodying `Seq ≤ seq` lives: `checkpoint.<seq>` (§6).
///
/// Stated as a pair with [`parse_checkpoint_name`], because the format and the
/// parse are one agreement: a change to either that the other does not match
/// makes every retained base invisible, and recovery then falls all the way
/// down its chain to genesis without a word.
fn checkpoint_path(dir: &Path, seq: u64) -> PathBuf {
    dir.join(format!("checkpoint.{seq}"))
}

/// Read back the seq [`checkpoint_path`] wrote. `None` for any other name —
/// `checkpoint.tmp` among them, which is why a crash mid-write leaves at most
/// a file recovery ignores.
fn parse_checkpoint_name(name: &str) -> Option<u64> {
    name.strip_prefix("checkpoint.")?.parse().ok()
}

/// All checkpoints in `dir`, ascending by seq. `checkpoint.tmp` and foreign
/// names fail the name parse and are skipped.
pub(crate) fn list(dir: &Path) -> io::Result<Vec<CheckpointMeta>> {
    let mut v = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(seq) = name.to_str().and_then(parse_checkpoint_name) else {
            continue;
        };
        v.push(CheckpointMeta {
            seq,
            path: entry.path(),
        });
    }
    v.sort_by_key(|cp| cp.seq);
    Ok(v)
}

/// Keep the newest `keep` checkpoints, delete the rest, and fsync the
/// directory so the unlinks are durable. Answers the oldest retained seq —
/// the journal-reclamation floor and the `BadCheckpoint` fallback base (§6) —
/// or `None` when no checkpoint remains.
pub(crate) fn retain(dir: &Path, keep: usize) -> io::Result<Option<u64>> {
    let mut checkpoints = list(dir)?;
    let excess = checkpoints.len().saturating_sub(keep);
    for victim in checkpoints.drain(..excess) {
        fs::remove_file(&victim.path)?;
    }
    fsync_dir(dir)?;
    Ok(checkpoints.first().map(|cp| cp.seq))
}

/// What a checkpoint write refused. The two are different answers for the
/// caller — a serializer refuses the same way until `W` itself changes, an I/O
/// failure is retryable — so the distinction travels rather than being
/// flattened here.
#[derive(Debug)]
pub(crate) enum WriteFail {
    /// `W`'s own serializer refused, and carries its own account of what it
    /// could not encode. Nothing was written, not even the temp file: the
    /// encode precedes the first file operation.
    Serialize(Box<dyn std::error::Error + Send + Sync + 'static>),
    /// A file operation failed. At most an ignored `checkpoint.tmp` survives —
    /// the rename is what publishes a checkpoint, so a failure before it
    /// leaves no base, and one after it leaves a whole one (§6).
    Io(io::Error),
}

impl From<io::Error> for WriteFail {
    fn from(e: io::Error) -> Self {
        WriteFail::Io(e)
    }
}

/// Persist a checkpoint embodying all records with `Seq ≤ seq`: serialize
/// `world`, then temp → fsync → atomic-rename → dir fsync (§6). Only
/// authoritative state need survive the round trip — a world may
/// `#[serde(skip)]` its derived hints and reseed them through
/// [`crate::WorldState::rebuild_derived`] at load (§6/§7).
pub(crate) fn write<W: Serialize>(dir: &Path, seq: u64, world: &W) -> Result<(), WriteFail> {
    let body = bincode::serialize(world).map_err(|e| WriteFail::Serialize(e))?;
    let tmp = dir.join("checkpoint.tmp");
    let mut f = File::create(&tmp)?;
    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(&MAGIC);
    header.extend_from_slice(&seq.to_le_bytes());
    header.extend_from_slice(&crc32c::crc32c(&body).to_le_bytes());
    header.extend_from_slice(&(body.len() as u64).to_le_bytes());
    f.write_all(&header)?;
    f.write_all(&body)?;
    f.sync_all()?;
    fs::rename(&tmp, checkpoint_path(dir, seq))?;
    fsync_dir(dir)?;
    Ok(())
}
