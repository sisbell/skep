//! Checkpoint files (§6): a serialized `W` @ `Seq` — a recoverable prefix-fold
//! cache, written temp → fsync → atomic-rename, with a header checksum over
//! the serialized `W` bytes. That checksum is what load validates before
//! trusting a base (serde deserialization alone does not reliably detect
//! bit-rot, and a silently-wrong base would defeat the `BadCheckpoint`
//! fallback chain).
//!
//! Layout (`SKC4`): `[magic 4][seq u64 LE][crc32c(body) u32 LE][body_len u64 LE]
//! [chain_head 32][body_hash 32][body]`, at `checkpoint.<S>`; the fixed temp
//! name `checkpoint.tmp` is no base — recovery REMOVES it (a crash
//! mid-checkpoint leaves at most a `.tmp` the next open deletes, and a failed
//! write deletes its own before answering — §6; the directory is the
//! kernel's alone, so the file is the kernel's to delete). `chain_head` is the commit chain's value
//! at `seq` — the marker that held it may be reclaimed, and this is where a
//! replay above the base continues the chain from; `body_hash` is SHA-256 over
//! the body, meaningful because the body is CANONICAL under `SKC4` —
//! [`crate::WorldState`]'s canonical-encoding obligation, which the engine
//! discharges with every serialized slice iterating in key order (the
//! encoding report's option (i)) — so two writes of one world, on two
//! processes or two machines, yield one byte string, and a published head can
//! name a checkpoint by `(seq, chain_head, body_hash)`. The CRC stays as the
//! first, cheap bit-rot check `load` runs before anything else.

use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use bincode::Options;
use serde::de::DeserializeOwned;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::error::{stamp_text, Cause, NO_MIGRATION_REMEDY};
use crate::journal::{codec, fsync_dir};
use crate::{Seam, Seq, Step};

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
/// by ([`crate::Kernel::newest_checkpoint`]) — and the file's length, the
/// figure a caller sizes a floor or a byte bound by. Only this crate makes
/// one, and only under every check a header can pass without its body: this
/// build's stamp, and a seq the file's name agrees with. The body is NOT
/// verified — its checksum and hash need the body — and `body_hash` is what
/// a party holding the file verifies it by.
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
    /// The file's length in bytes AS THE HEADER CLAIMS IT: the fixed header
    /// plus the `body_len` it carries — parsed from what the file already
    /// holds, no field of the layout added for it, so a checkpoint written
    /// before this member reads the same. The length `load` holds the file
    /// to, so for every checkpoint that is a base it IS the file's size; a
    /// header whose claim the file contradicts is no base, and `load` refuses
    /// it before a byte of its body is read. Saturating at `u64::MAX` for a
    /// claim no file could hold.
    pub len: u64,
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
            len: (HEADER_LEN as u64).saturating_add(header.body_len),
        })
    }
}

/// The fixed temp name a checkpoint is built through, in `dir`.
fn tmp_path(dir: &Path) -> PathBuf {
    dir.join("checkpoint.tmp")
}

/// Remove a stray `checkpoint.tmp` from `dir` — a checkpoint a crash or a
/// failed write left half-written under the fixed temp name — answering its
/// length in bytes, or `None` where none stood. The open's act, under the
/// flock ([`crate::Kernel::open`]): the file is no base ([`list`] skips the
/// name) and keeps its room on the volume, which after a write the volume's
/// room failed is the room the next checkpoint needs; the directory is the
/// kernel's alone, so the deletion is the kernel's. A file that is there and
/// cannot be removed fails the open as the I/O condition it is.
pub(crate) fn remove_stray_tmp(dir: &Path) -> io::Result<Option<u64>> {
    let tmp = tmp_path(dir);
    let len = match fs::metadata(&tmp) {
        Ok(meta) => meta.len(),
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    fs::remove_file(&tmp)?;
    fsync_dir(dir)?;
    Ok(Some(len))
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

/// What the NEWEST checkpoint in `dir` claims, by its header alone
/// ([`CheckpointMeta::header`]) — or `None` where none stands, the directory
/// cannot be listed, or the header refuses. FAIL-QUIET, for the two readers
/// that must never fail over it: [`crate::Kernel::newest_checkpoint`], whose
/// head writer writes `base: null` instead, and [`fn@write`], which sizes a
/// buffer by the length. [`list`] is ascending by seq (§6), so the last entry
/// is the newest.
pub(crate) fn newest_header(dir: &Path) -> Option<CheckpointHeader> {
    list(dir).ok()?.pop()?.header().ok()
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

/// What the checkpoint at `seq` in `dir` claims, by its header alone
/// ([`CheckpointMeta::header`]) — or `None` where no file of that name
/// stands, or its header refuses. FAIL-QUIET, as [`newest_header`] is, for
/// the same kind of reader: [`crate::Kernel::checkpoint_header`], which a
/// caller sizes by and must never fail over. The file is named directly from
/// the seq ([`checkpoint_path`]), with no listing: the name and the header
/// are then the two sources the header parse cross-checks, as they are for a
/// listed entry.
pub(crate) fn header_at(dir: &Path, seq: u64) -> Option<CheckpointHeader> {
    CheckpointMeta { seq, path: checkpoint_path(dir, seq) }.header().ok()
}

/// Keep the newest `keep` checkpoints THAT LOAD, delete the rest, and fsync
/// the directory so the unlinks are durable. Answers the oldest kept seq —
/// the journal-reclamation floor and the `BadCheckpoint` fallback base (§6) —
/// or `None` when no checkpoint remains.
///
/// RETENTION COUNTS THE BASES THAT LOAD. `skipped` names the checkpoints the
/// open passed over — the seqs the kernel's [`crate::Recovery`] lists as
/// skipped, less any a later checkpoint has written over — and none of them
/// is counted among the `keep`: every one is removed as excess, whatever its
/// age, and the newest `keep` of the others are kept. So the first landing
/// after an open that skipped `B` and loaded from `A` keeps `A` beside the
/// new base and removes `B`, where counting by name alone would keep `B`,
/// delete `A` — the one base that loaded — and reclaim the journal below the
/// base that did not, leaving the board on one loadable base with genesis
/// gone. No rename aside and no new file name: the diagnosis a kept damaged
/// file would offer is already in the open's report, which carries why each
/// skipped base refused. A base that loaded is counted as it always was, so
/// with nothing skipped this is the rule it was.
pub(crate) fn retain(dir: &Path, keep: usize, skipped: &[u64]) -> io::Result<Option<u64>> {
    let checkpoints = list(dir)?;
    let loadable = checkpoints.iter().filter(|cp| !skipped.contains(&cp.seq)).count();
    let excess = loadable.saturating_sub(keep);
    let mut passed_over = 0;
    let mut floor = None;
    // Ascending by seq, so the loadable bases met first are the oldest: the
    // first `excess` of them go, every skipped one goes, and the rest stand.
    for cp in &checkpoints {
        let remove = if skipped.contains(&cp.seq) {
            true
        } else if passed_over < excess {
            passed_over += 1;
            true
        } else {
            false
        };
        if remove {
            fs::remove_file(&cp.path)?;
        } else {
            floor.get_or_insert(cp.seq);
        }
    }
    fsync_dir(dir)?;
    Ok(floor)
}

/// What a checkpoint write refused. The three are different answers for the
/// caller — a serializer refuses the same way until `W` itself changes, an
/// I/O failure before the rename is retryable and left nothing, one after it
/// left a base — so the distinction travels rather than being flattened here.
#[derive(Debug)]
pub(crate) enum WriteFail {
    /// `W`'s own serializer refused, and carries its own account of what it
    /// could not encode. Nothing was written, not even the temp file: the
    /// encode precedes the first file operation.
    Serialize(Cause),
    /// A file operation BEFORE the rename failed. No `checkpoint.tmp`
    /// survives it: the rename is what publishes a checkpoint, so a failure
    /// before it leaves no base, and the temp file is removed before this is
    /// answered — best-effort, its own failure folded into the account (§6).
    Io(io::Error),
    /// The directory's fsync AFTER the rename failed: the base is on disk,
    /// whole, under its own name — the rename published it — and what the
    /// step would have settled is whether its directory entry is durable.
    /// The caller's step after a landed base ([`crate::LandedStep`]'s first).
    Landed(io::Error),
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
///
/// A failure past the temp file's creation and before its rename — the
/// write, the sync or the rename itself — REMOVES the temp file before it is
/// answered: a half-written checkpoint under the fixed name is no base and
/// would keep its room on the volume, and after a write the volume's room
/// failed that is exactly the room the next attempt needs. Best-effort: the
/// removal's own failure is folded into the account beside the write's and
/// never masks it. A crash in the same window leaves the file for the next
/// open to remove ([`remove_stray_tmp`]).
///
/// ONE PASS over the world. The body is serialized with the codec's
/// `serialize_into` into a buffer, never with its `serialize`: bincode 1's
/// `serialize` walks the value twice, once to size the buffer it then fills,
/// and `serialize_into` repeats that size pass only under a byte limit, which
/// [`codec`] sets none of. In the size pass's place the buffer is sized by a
/// HINT: the length the newest checkpoint in `dir` claims, read off its
/// header alone ([`newest_header`] — one directory listing and one short
/// read, fail-quiet: none before the first, and the buffer then grows as any
/// `Vec` does), which the next body outgrows by one window's growth at most.
/// A hint, never a promise: a length the process cannot reserve is dropped,
/// and the header is built from the finished body — its checksum, its hash,
/// its length — so the hint is no part of the bytes.
///
/// THE SEAM (`test-hooks`): three of the steps below are the write-fault
/// seam's ([`Step`]) — the temp file's creation, its fsync, and the
/// directory's fsync after the rename — each hooked through `seam` BEFORE
/// it runs, after every step before it has completed: an armed failure
/// answers in the step's place and travels out of the kind armed, as
/// [`WriteFail::Io`] for the two before the rename, the removal above running
/// for a failure inside the window as for any, and as [`WriteFail::Landed`]
/// for the directory's fsync, the base on disk; an armed panic unwinds there,
/// and runs no removal. `seam` is the kernel's, handed by
/// [`crate::Kernel::checkpoint`]; in a build without the feature its hook is
/// a no-op.
pub(crate) fn write<W: Serialize>(
    dir: &Path,
    seq: u64,
    world: &W,
    chain_head: &[u8; 32],
    seam: &Seam,
) -> Result<(), WriteFail> {
    let hint = newest_header(dir).map_or(0, |header| header.len);
    let mut body = Vec::new();
    // Reserved fallibly: a hint the process cannot grant — a header claiming
    // more than any volume holds — is dropped, never a capacity panic in
    // place of a checkpoint.
    let _ = body.try_reserve_exact(usize::try_from(hint).unwrap_or(usize::MAX));
    codec().serialize_into(&mut body, world).map_err(|e| WriteFail::Serialize(e))?;
    let tmp = tmp_path(dir);
    seam.before(Step::CheckpointCreate)?;
    let mut f = File::create(&tmp)?;
    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(&MAGIC);
    header.extend_from_slice(&seq.to_le_bytes());
    header.extend_from_slice(&crc32c::crc32c(&body).to_le_bytes());
    header.extend_from_slice(&(body.len() as u64).to_le_bytes());
    header.extend_from_slice(chain_head);
    header.extend_from_slice(&body_hash(&body));
    debug_assert_eq!(header.len(), HEADER_LEN);
    // The window the temp file exists in: its creation above succeeded, and
    // the rename below is what publishes it. A failure inside answers with
    // the file removed.
    let published = (|| -> io::Result<()> {
        f.write_all(&header)?;
        f.write_all(&body)?;
        seam.before(Step::CheckpointSync)?;
        f.sync_all()?;
        drop(f);
        fs::rename(&tmp, checkpoint_path(dir, seq))
    })();
    if let Err(failed) = published {
        let removal = match fs::remove_file(&tmp) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        };
        return Err(WriteFail::Io(match removal {
            Ok(()) => failed,
            Err(not_removed) => io::Error::new(
                failed.kind(),
                format!("{failed}; and checkpoint.tmp could not be removed after it: {not_removed}"),
            ),
        }));
    }
    // Past the rename: the base is on disk whatever follows, which is what
    // a failure from here answers over (`WriteFail::Landed`'s card).
    seam.before(Step::CheckpointDirSync).and_then(|()| fsync_dir(dir)).map_err(WriteFail::Landed)
}

#[cfg(test)]
mod tests;
