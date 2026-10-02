//! Checkpoint files (§6): a serialized `W` @ `Seq` — a recoverable prefix-fold
//! cache, written temp → fsync → atomic-rename, with a header checksum over
//! the serialized `W` bytes. That checksum is what load validates before
//! trusting a base (serde deserialization alone does not reliably detect
//! bit-rot, and a silently-wrong base would defeat the `BadCheckpoint`
//! fallback chain).
//!
//! Layout (`SKC4`): `[magic 4][seq u64 LE][crc32c(body) u32 LE][body_len u64 LE]
//! [chain_head 32][body_hash 32][body]`, at `checkpoint.<S>`; the fixed temp
//! name `checkpoint.tmp` is ignored by recovery (a crash mid-checkpoint leaves
//! at most an ignored `.tmp` — §6). `chain_head` is the commit chain's value
//! at `seq` — the marker that held it may be reclaimed, and this is where a
//! replay above the base continues the chain from; `body_hash` is SHA-256 over
//! the body, meaningful because the body is CANONICAL under `SKC4`: every
//! serialized slice iterates in key order (the encoding report's option (i)),
//! so two writes of one world, on two processes or two machines, yield one
//! byte string, and a published head can name a checkpoint by
//! `(seq, chain_head, body_hash)`. The CRC stays as the first, cheap bit-rot
//! check `load` runs before anything else.

use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use bincode::Options;
use serde::de::DeserializeOwned;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::error::{stamp_text, Cause, NO_MIGRATION_REMEDY};
use crate::journal::{codec, fsync_dir};
use crate::Seq;

// The trailing numeral is the checkpoint's FORMAT stamp; bumped 1 → 2 at
// the 2026-08-26 genesis re-baseline (M7's slice no longer carries a sealed
// type config, so pre-baseline checkpoint bytes are not this format's), and
// 2 → 3 on 2026-09-23 with the journal's `SKJ3` (QUEUE item 10): the header
// gained `chain_head` and `body_hash`, and the body went canonical; and 3 → 4
// on 2026-09-24 with the journal's `SKJ4` (the chain's salt): nothing in the
// layout moved, but `chain_head` is a value under the salted preimage, which
// no `SKC3` header's is. NOT bumped on 2026-09-29, when the chain's preimage
// gained the signature slot's digest and M5's slice a fourth field (the
// shot terms): a format event by the marker doc's own definition, landed
// under the same stamps by the owner's no-stamp ruling — no served board
// exists, dev boards regenerate, and the golden fixture was regenerated once
// (`tests/golden/`). A checkpoint under another stamp is refused at `load`
// naming the stamp found; one written under this stamp before that day
// fails at the body's decode or at the chain, as corruption.
const MAGIC: [u8; 4] = *b"SKC4";
/// The header's fields, at the offsets `write` lays them down and
/// [`parse_header`] reads them at — one spelling of each, so the two cannot
/// drift.
const SEQ_AT: usize = 4;
const CRC_AT: usize = 12;
const BODY_LEN_AT: usize = 16;
const CHAIN_HEAD_AT: usize = 24;
const BODY_HASH_AT: usize = 56;
const HEADER_LEN: usize = 88;

/// The refusal a file too short to hold [`HEADER_LEN`] bytes answers with,
/// whichever reader met it.
const SHORT_OF_HEADER: &str = "checkpoint is shorter than its own header";

/// SHA-256 over a checkpoint body — the header's `body_hash`.
fn body_hash(body: &[u8]) -> [u8; 32] {
    Sha256::digest(body).into()
}

/// The `N`-byte field at offset `AT` of a header. The window is checked
/// against [`HEADER_LEN`] when this is COMPILED, for every field any reader
/// names, so no read of a header can fail on its bounds — the array type
/// fixes the header's length, and this fixes each field inside it.
fn field<const AT: usize, const N: usize>(header: &[u8; HEADER_LEN]) -> [u8; N] {
    const { assert!(AT + N <= HEADER_LEN, "a header field lies past HEADER_LEN") };
    std::array::from_fn(|i| header[AT + i])
}

/// A checkpoint header as [`fn@write`] lays it down, read under every check a
/// header can pass without its body ([`parse_header`], the only site that
/// makes one): this build's stamp, and a seq agreeing with the file's name.
/// The body's own checks — its length, checksum and hash — are
/// [`CheckpointMeta::load`]'s, which alone reads the body. Private to this
/// module: what a header CLAIMS leaves it as a [`CheckpointHeader`], and the
/// fields that exist only to check the body never leave it.
#[derive(Debug)]
struct Header {
    /// CRC32C over the body, as written.
    crc: u32,
    /// The body's length in bytes, as written.
    body_len: u64,
    /// The commit chain's value at this checkpoint's seq.
    chain_head: [u8; 32],
    /// SHA-256 over the body — the header's commitment to it, which a party
    /// holding the file verifies the body by.
    body_hash: [u8; 32],
}

/// What a checkpoint's `SKC4` header CLAIMS, read without its body: the
/// coordinate the checkpoint embodies, the commit chain's value there, and
/// SHA-256 over its canonical body — the three a published head names a base
/// by ([`crate::Kernel::newest_checkpoint`]). Only this crate makes one, and
/// only under every check a header can pass without its body: this build's
/// stamp, and a seq the file's name agrees with. The body is NOT verified —
/// its checksum and hash need the body — and `body_hash` is what a party
/// holding the file verifies it by.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CheckpointHeader {
    /// The coordinate the checkpoint embodies — its file name and its header
    /// agreeing on it.
    pub seq: Seq,
    /// The commit chain's value at `seq`.
    pub chain_head: [u8; 32],
    /// SHA-256 over the checkpoint's canonical body.
    pub body_hash: [u8; 32],
}

/// The one parse of a checkpoint header, for [`CheckpointMeta::load`] and
/// [`CheckpointMeta::header`] alike, in the order that makes each check mean
/// something: the stamp FIRST, so another format's header has none of its
/// other fields read as this format's — refused by name with the ruled remedy
/// ([`NO_MIGRATION_REMEDY`]) — then the seq against `named_seq`, the
/// directory entry's claim. The name-versus-header cross-check compares two
/// independent sources, which is what makes it a check rather than a
/// tautology: the seq comes from the directory, the header from the bytes.
fn parse_header(named_seq: u64, bytes: &[u8; HEADER_LEN]) -> Result<Header, LoadRefused> {
    let stamp: [u8; 4] = field::<0, 4>(bytes);
    if stamp != MAGIC {
        return Err(format!(
            "checkpoint is not this build's format: it opens with the stamp `{}`, this build \
             reads and writes `{}` only; {NO_MIGRATION_REMEDY}",
            stamp_text(&stamp),
            stamp_text(&MAGIC)
        )
        .into());
    }
    let seq = u64::from_le_bytes(field::<SEQ_AT, 8>(bytes));
    if seq != named_seq {
        return Err(
            format!("checkpoint header claims seq {seq}, its name claims {named_seq}").into(),
        );
    }
    Ok(Header {
        crc: u32::from_le_bytes(field::<CRC_AT, 4>(bytes)),
        body_len: u64::from_le_bytes(field::<BODY_LEN_AT, 8>(bytes)),
        chain_head: field::<CHAIN_HEAD_AT, 32>(bytes),
        body_hash: field::<BODY_HASH_AT, 32>(bytes),
    })
}

/// What a loaded checkpoint hands back: the world, and the commit chain's
/// value at the coordinate the world embodies, which the scan above it
/// continues from.
#[derive(Debug)]
pub(crate) struct Loaded<W> {
    pub world: W,
    pub chain_head: [u8; 32],
}

/// Why a checkpoint could not stand in as a base (§6). Every refusal is
/// skipped the same way — the caller falls to the next-older retained base —
/// so this carries no taxonomy to branch on, only the account that says which
/// REMEDY, at the one point where that matters: the whole fallback chain
/// exhausted, with nothing else left to tell an operator.
pub(crate) type LoadRefused = Cause;

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

/// Read the [`HEADER_LEN`] bytes a checkpoint file opens with, and nothing
/// after them — the one read of a header, for [`CheckpointMeta::load`] and
/// [`CheckpointMeta::header`] alike, so a file too short to hold one answers
/// [`SHORT_OF_HEADER`] whichever reader met it.
fn read_header(file: &mut File) -> Result<[u8; HEADER_LEN], LoadRefused> {
    let mut bytes = [0u8; HEADER_LEN];
    file.read_exact(&mut bytes).map_err(|e| -> LoadRefused {
        if e.kind() == io::ErrorKind::UnexpectedEof {
            SHORT_OF_HEADER.into()
        } else {
            e.into()
        }
    })?;
    Ok(bytes)
}

impl CheckpointMeta {
    /// Load and validate this checkpoint, or say why it cannot stand in as a
    /// base: unreadable, short of its own header, a foreign format stamp, a
    /// header seq disagreeing with the name, a file whose length disagrees
    /// with its header's `body_len`, a body failing its checksum or its hash,
    /// or a body that will not decode as `W`. The caller falls back to the
    /// next-older retained checkpoint, then genesis-while-reachable (§6/§7) —
    /// every refusal alike, which is why the account travels as one type
    /// rather than as a taxonomy nobody branches on.
    ///
    /// The body is read only once the file's length and the header's
    /// `body_len` — two claims, from the directory and from the bytes — agree,
    /// and the read is sized by that agreed figure and held to it: a file
    /// extended past its body, or a header claiming more than the file holds,
    /// sizes nothing, so the cost of a refused base is its header.
    ///
    /// Two of those an operator most needs named. A foreign stamp is a
    /// checkpoint written under another format, and the account names the
    /// stamp found, the stamp expected and the ruled remedy
    /// ([`NO_MIGRATION_REMEDY`]) — the same sentence the journal's own refusal
    /// renders, so when the fallback chain is exhausted the daemon prints it
    /// through `BadCheckpoint`'s cause.
    /// A body that will not decode: the header checksum and hash have passed
    /// by then, so the bytes ARE the bytes that were written and the refusal
    /// is not rot — it is a writer/reader skew, a binary on the wrong side of
    /// a `W` format change, whose remedy is to roll the binary rather than to
    /// restore the media.
    ///
    /// Its header is the one [`fn@write`] appends, field for field, read
    /// through [`parse_header`] — the parse [`CheckpointMeta::header`] shares;
    /// see [`fn@write`] for what a drifted half costs, which is every retained
    /// base at once and no signal that it happened.
    pub(crate) fn load<W: DeserializeOwned>(&self) -> Result<Loaded<W>, LoadRefused> {
        let mut file = File::open(&self.path)?;
        let header = parse_header(self.seq, &read_header(&mut file)?)?;
        // The file's length and the header's `body_len` are both claims; the
        // read is sized only once they agree, so a file extended past its body
        // sizes nothing. Checked, since a header claiming near `u64::MAX`
        // would otherwise overflow the sum: a panic in a checked build, and in
        // a release one a wrap back onto a length that matches.
        let file_len = file.metadata()?.len();
        if (HEADER_LEN as u64).checked_add(header.body_len) != Some(file_len) {
            return Err(format!(
                "checkpoint file is {file_len} bytes, its header claims {HEADER_LEN} + {}",
                header.body_len
            )
            .into());
        }
        // Reserved fallibly: a header and a length that agree on more than this
        // process can hold refuse as the base they cannot be, rather than abort
        // the process the way an infallible reservation would.
        let mut body = Vec::new();
        body.try_reserve_exact(usize::try_from(header.body_len)?)?;
        // `take` holds the read to the agreed figure even if the file grows
        // beneath it; a file that shrank beneath it reads short, refused below.
        file.take(header.body_len).read_to_end(&mut body)?;
        if body.len() as u64 != header.body_len {
            return Err(format!(
                "checkpoint body is {} bytes, its header claims {}",
                body.len(),
                header.body_len
            )
            .into());
        }
        if crc32c::crc32c(&body) != header.crc {
            return Err(
                "checkpoint body failed its header checksum (bit-rot or a torn write)".into(),
            );
        }
        if body_hash(&body) != header.body_hash {
            return Err("checkpoint body failed its header hash (bit-rot or a torn write)".into());
        }
        // The serializer's refusal becomes the account in place: `bincode::Error`
        // is already a `Box<ErrorKind>`, so it unsizes into `LoadRefused` here.
        // `?` alone would compile and box that box again, leaving a cause no
        // caller could downcast to the serializer's `ErrorKind`.
        let world = codec()
            .deserialize(&body)
            .map_err(|skew| -> LoadRefused { skew })?;
        Ok(Loaded {
            world,
            chain_head: header.chain_head,
        })
    }

    /// What this checkpoint's header claims ([`CheckpointHeader`]), read
    /// ALONE — [`HEADER_LEN`] bytes, and nothing after them — under every
    /// check a header can pass without its body ([`parse_header`]): this
    /// build's stamp, and a seq agreeing with the file's name. So it costs one
    /// short read whatever the world's size, where [`CheckpointMeta::load`]
    /// reads and hashes the whole serialized world. The body is NOT verified:
    /// its checksum and hash need the body, and `body_hash` is what a party
    /// holding the file verifies it by.
    pub(crate) fn header(&self) -> Result<CheckpointHeader, LoadRefused> {
        let header = parse_header(self.seq, &read_header(&mut File::open(&self.path)?)?)?;
        Ok(CheckpointHeader {
            seq: Seq(self.seq),
            chain_head: header.chain_head,
            body_hash: header.body_hash,
        })
    }
}

/// The one file name the checkpoint embodying `Seq ≤ seq` has:
/// `checkpoint.<seq>` (§6).
///
/// Stated as a pair with [`parse_checkpoint_name`], which reads it back by
/// re-emitting it, because the format and the parse are one agreement: a
/// change to either that the other does not match makes every retained base
/// invisible, and recovery then falls all the way down its fallback chain to
/// genesis without a word.
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
    Serialize(Cause),
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
/// `world` under [`codec`], then temp → fsync → atomic-rename → dir fsync
/// (§6). Only authoritative state need survive the round trip — a world may
/// `#[serde(skip)]` its derived hints and reseed them through
/// [`crate::WorldState::rebuild_derived`] at load (§6/§7). `chain_head` is
/// the commit chain's value at `seq` — the installed root's, which the
/// transaction that installed it carried in its marker — and rides the
/// header so a replay above this base continues the chain from it.
///
/// Stated as a pair with [`parse_header`], which reads the header this builds
/// at [`HEADER_LEN`] for both [`CheckpointMeta::load`] and
/// [`CheckpointMeta::header`], because the layout and the parse are one
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
pub(crate) fn write<W: Serialize>(
    dir: &Path,
    seq: u64,
    world: &W,
    chain_head: &[u8; 32],
) -> Result<(), WriteFail> {
    let body = codec().serialize(world).map_err(|e| WriteFail::Serialize(e))?;
    let tmp = dir.join("checkpoint.tmp");
    let mut f = File::create(&tmp)?;
    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(&MAGIC);
    header.extend_from_slice(&seq.to_le_bytes());
    header.extend_from_slice(&crc32c::crc32c(&body).to_le_bytes());
    header.extend_from_slice(&(body.len() as u64).to_le_bytes());
    header.extend_from_slice(chain_head);
    header.extend_from_slice(&body_hash(&body));
    debug_assert_eq!(header.len(), HEADER_LEN);
    f.write_all(&header)?;
    f.write_all(&body)?;
    f.sync_all()?;
    fs::rename(&tmp, checkpoint_path(dir, seq))?;
    fsync_dir(dir)?;
    Ok(())
}

#[cfg(test)]
mod tests;
