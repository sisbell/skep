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

use crate::journal::fsync_dir;

const CKPT_MAGIC: [u8; 4] = *b"SKC1";
const HEADER_LEN: usize = 24;

pub(crate) struct CkptMeta {
    pub seq: u64,
    pub path: PathBuf,
}

/// All checkpoints in `dir`, ascending by seq. `checkpoint.tmp` and foreign
/// names fail the numeric parse and are skipped.
pub(crate) fn list(dir: &Path) -> io::Result<Vec<CkptMeta>> {
    let mut v = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(stem) = name.strip_prefix("checkpoint.") else {
            continue;
        };
        let Ok(seq) = stem.parse::<u64>() else { continue };
        v.push(CkptMeta {
            seq,
            path: entry.path(),
        });
    }
    v.sort_by_key(|c| c.seq);
    Ok(v)
}

/// Keep the newest `retain` checkpoints, delete the rest, and fsync the
/// directory so the unlinks are durable. Answers the oldest retained seq —
/// the journal-reclamation floor and the `BadCheckpoint` fallback base (§6) —
/// or `None` when no checkpoint remains.
pub(crate) fn prune(dir: &Path, retain: usize) -> io::Result<Option<u64>> {
    let mut cps = list(dir)?;
    while cps.len() > retain {
        let victim = cps.remove(0);
        fs::remove_file(&victim.path)?;
    }
    fsync_dir(dir)?;
    Ok(cps.first().map(|c| c.seq))
}

/// Persist a checkpoint embodying all records with `Seq ≤ seq`:
/// temp → fsync → atomic-rename → dir fsync (§6).
pub(crate) fn write(dir: &Path, seq: u64, body: &[u8]) -> io::Result<()> {
    let tmp = dir.join("checkpoint.tmp");
    let mut f = File::create(&tmp)?;
    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(&CKPT_MAGIC);
    header.extend_from_slice(&seq.to_le_bytes());
    header.extend_from_slice(&crc32c::crc32c(body).to_le_bytes());
    header.extend_from_slice(&(body.len() as u64).to_le_bytes());
    f.write_all(&header)?;
    f.write_all(body)?;
    f.sync_all()?;
    fs::rename(&tmp, dir.join(format!("checkpoint.{seq}")))?;
    fsync_dir(dir)
}

/// Load and validate one checkpoint. `None` means unreadable / failed its
/// checksum / name-header seq mismatch — the caller falls back to the
/// next-older retained checkpoint, then genesis-while-reachable (§6/§7).
pub(crate) fn load<W: DeserializeOwned>(path: &Path, expected_seq: u64) -> Option<W> {
    let data = fs::read(path).ok()?;
    if data.len() < HEADER_LEN || data[0..4] != CKPT_MAGIC {
        return None;
    }
    let seq = u64::from_le_bytes(data[4..12].try_into().ok()?);
    let crc = u32::from_le_bytes(data[12..16].try_into().ok()?);
    let body_len = u64::from_le_bytes(data[16..24].try_into().ok()?);
    if seq != expected_seq {
        return None;
    }
    let body = &data[HEADER_LEN..];
    if body.len() as u64 != body_len || crc32c::crc32c(body) != crc {
        return None;
    }
    bincode::deserialize(body).ok()
}
