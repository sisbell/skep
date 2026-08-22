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
///
/// A slice of these must be ascending by `seq`, as [`list`] produces it: every
/// operation over one reads a position in the slice as an age. [`retain`]
/// deletes from the FRONT as the oldest, [`crate::replay::select_base`] walks
/// from the BACK as the newest and reads the front as the oldest base still
/// derivable ([`crate::replay::Unreachable`]'s floor). An unordered slice makes
/// all three wrong, and one of them deletes files.
pub(crate) struct CheckpointMeta {
    pub seq: u64,
    path: PathBuf,
}

impl CheckpointMeta {
    /// Load and validate this checkpoint. `None` means unreadable / failed its
    /// checksum / name-header seq mismatch — the caller falls back to the
    /// next-older retained checkpoint, then genesis-while-reachable (§6/§7).
    ///
    /// The header this splits at [`HEADER_LEN`] is the one [`fn@write`]
    /// appends, field for field; see there for what a drifted half costs,
    /// which is every retained base at once and no signal that it happened.
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

/// The one file name the checkpoint embodying `Seq ≤ seq` has:
/// `checkpoint.<seq>` (§6).
///
/// Stated as a pair with [`parse_checkpoint_name`], which reads it back by
/// re-emitting it, because the format and the parse are one agreement: a
/// change to either that the other does not match makes every retained base
/// invisible, and recovery then falls all the way down its chain to genesis
/// without a word.
fn checkpoint_name(seq: u64) -> String {
    format!("checkpoint.{seq}")
}

/// Where the checkpoint embodying `Seq ≤ seq` lives (§6).
fn checkpoint_path(dir: &Path, seq: u64) -> PathBuf {
    dir.join(checkpoint_name(seq))
}

/// Read back the seq [`checkpoint_name`] wrote — and ONLY the spelling it
/// writes. `u64::from_str` accepts a leading `+` and any number of leading
/// zeros, so the round trip is what keeps `checkpoint.07` from counting as a
/// second base beside `checkpoint.7`, where [`retain`] counts entries and a
/// configured fallback chain of `N` would silently hold fewer. `None` for any
/// other name — `checkpoint.tmp` among them, which is why a crash mid-write
/// leaves at most a file recovery ignores.
fn parse_checkpoint_name(name: &str) -> Option<u64> {
    let seq: u64 = name.strip_prefix("checkpoint.")?.parse().ok()?;
    (name == checkpoint_name(seq)).then_some(seq)
}

/// All checkpoints in `dir`, ascending by seq. `checkpoint.tmp` and foreign
/// names fail the name parse and are skipped.
pub(crate) fn list(dir: &Path) -> io::Result<Vec<CheckpointMeta>> {
    let mut checkpoints = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(seq) = name.to_str().and_then(parse_checkpoint_name) else {
            continue;
        };
        checkpoints.push(CheckpointMeta {
            seq,
            path: entry.path(),
        });
    }
    checkpoints.sort_by_key(|cp| cp.seq);
    Ok(checkpoints)
}

/// Keep the newest `keep` checkpoints, delete the rest, and fsync the
/// directory so the unlinks are durable. Answers the oldest retained seq —
/// the journal-reclamation floor and the `BadCheckpoint` fallback base (§6) —
/// or `None` when no checkpoint remains.
pub(crate) fn retain(dir: &Path, keep: usize) -> io::Result<Option<u64>> {
    let mut checkpoints = list(dir)?;
    let excess = checkpoints.len().saturating_sub(keep);
    for cp in checkpoints.drain(..excess) {
        fs::remove_file(&cp.path)?;
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
///
/// Stated as a pair with [`CheckpointMeta::load`], which splits the header
/// this builds at [`HEADER_LEN`], because the layout and the split are one
/// agreement: a field appended here without that constant moving with it
/// leaves `body_len` disagreeing with the body, and EVERY retained base is
/// then unloadable — recovery falls silently to genesis where it is
/// reachable, and refuses with `BadCheckpoint` where it is not. The layout
/// test is what pins the two together.
///
/// CALLER OBLIGATION — this builds through the FIXED `checkpoint.tmp` in
/// `dir`, so calls against one directory must be serialized by the caller.
/// Two concurrent ones interleave into that single file and rename the
/// mixture into place: `load`'s header checksum catches it, so nothing wrong
/// is ever served, but the base is then useless — and under the documented
/// `N = 1` retention it is the only one. [`crate::Kernel::checkpoint`]'s
/// checkpoint mutex is the one place that obligation is discharged.
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    /// A stand-in world: the format is generic over `W`, so what a fixture
    /// needs is something that serializes, not something that resembles one.
    fn world() -> Vec<u64> {
        vec![10, 20, 30]
    }

    #[test]
    fn checkpoint_header_layout_is_magic_seq_crc_and_body_len() {
        // A checkpoint file written by one build is read by the next, so the
        // layout is pinned here rather than left to whatever `write`'s four
        // appends and `load`'s `HEADER_LEN` split happen to agree on. A field
        // added to one without the other makes `body_len` disagree with the
        // body, which makes EVERY retained base unloadable — and recovery
        // then falls silently to genesis, or refuses with `BadCheckpoint`.
        let dir = tempdir().unwrap();
        write(dir.path(), 7, &world()).expect("fixture checkpoint");
        let data = fs::read(checkpoint_path(dir.path(), 7)).unwrap();
        let body = bincode::serialize(&world()).unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(b"SKC1");
        expected.extend_from_slice(&7u64.to_le_bytes()); // seq
        expected.extend_from_slice(&crc32c::crc32c(&body).to_le_bytes()); // crc(body)
        expected.extend_from_slice(&(body.len() as u64).to_le_bytes()); // body_len
        assert_eq!(expected.len(), HEADER_LEN, "the header is what `load` splits at");
        assert_eq!(&data[..HEADER_LEN], expected.as_slice());
        assert_eq!(&data[HEADER_LEN..], body.as_slice());

        // …and the whole file loads back through the door every base walks
        // through.
        let listed = list(dir.path()).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].seq, 7);
        assert_eq!(listed[0].load::<Vec<u64>>(), Some(world()));

        // A crash mid-write leaves a `.tmp`, which is not a base.
        fs::write(dir.path().join("checkpoint.tmp"), b"not a checkpoint").unwrap();
        assert_eq!(list(dir.path()).unwrap().len(), 1);
    }

    #[test]
    fn a_flipped_body_byte_refuses_the_base() {
        // The header checksum is what `load` validates before trusting a base,
        // because serde alone does not reliably detect bit-rot and a silently
        // wrong base would defeat the whole `BadCheckpoint` fallback chain.
        let dir = tempdir().unwrap();
        write(dir.path(), 3, &world()).expect("fixture checkpoint");
        let path = checkpoint_path(dir.path(), 3);
        let mut data = fs::read(&path).unwrap();
        let last = data.len() - 1;
        data[last] ^= 0xFF;
        fs::write(&path, &data).unwrap();
        assert_eq!(list(dir.path()).unwrap()[0].load::<Vec<u64>>(), None);
    }

    #[test]
    fn only_the_name_the_writer_emits_is_a_checkpoint() {
        // `checkpoint.07` parses as 7 under a bare `u64::from_str`, so without
        // the round trip it is a second entry at one coordinate — and
        // `retain` counts entries, so a configured `N = 2` fallback chain
        // would silently hold one real base and one alias of it.
        let dir = tempdir().unwrap();
        write(dir.path(), 7, &world()).expect("fixture checkpoint");
        fs::copy(checkpoint_path(dir.path(), 7), dir.path().join("checkpoint.07")).unwrap();
        fs::copy(checkpoint_path(dir.path(), 7), dir.path().join("checkpoint.+7")).unwrap();
        let listed = list(dir.path()).unwrap();
        assert_eq!(listed.len(), 1, "only one spelling names a checkpoint");
        assert_eq!(listed[0].seq, 7);
    }
}
