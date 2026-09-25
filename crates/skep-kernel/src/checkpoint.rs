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

use crate::error::{stamp_text, NO_MIGRATION_REMEDY};
use crate::journal::{codec, fsync_dir};
use crate::Seq;

// The trailing numeral is the checkpoint's FORMAT stamp; bumped 1 → 2 at
// the 2026-08-26 genesis re-baseline (M7's slice no longer carries a sealed
// type config, so pre-baseline checkpoint bytes are not this format's), and
// 2 → 3 on 2026-09-23 with the journal's `SKJ3` (QUEUE item 10): the header
// gained `chain_head` and `body_hash`, and the body went canonical; and 3 → 4
// on 2026-09-24 with the journal's `SKJ4` (the chain's salt): nothing in the
// layout moved, but `chain_head` is a value under the salted preimage, which
// no `SKC3` header's is. A checkpoint under another stamp is refused at
// `load` naming the stamp found.
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
/// module: what a header ATTESTS leaves it as a [`CheckpointHeader`], and the
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

/// What a checkpoint's `SKC4` header ATTESTS, read without its body: the
/// coordinate the checkpoint embodies, the commit chain's value there, and
/// SHA-256 over its canonical body — the three a published head names a base
/// by ([`crate::Kernel::newest_checkpoint`]). Only this crate makes one, and
/// only under every check a header can pass without its body: this build's
/// stamp, and a seq the file's name agrees with. The body is NOT verified —
/// its checksum and hash need the body — and `body_hash` is what a party
/// holding the file verifies it by.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
pub(crate) type LoadRefused = Box<dyn std::error::Error + Send + Sync + 'static>;

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
    /// Load and validate this checkpoint, or say why it cannot stand in as a
    /// base: unreadable, short of its own header, a foreign format stamp, a
    /// header seq disagreeing with the name, a body failing its checksum or
    /// its hash, or a body that will not decode as `W`. The caller falls back
    /// to the next-older retained checkpoint, then genesis-while-reachable
    /// (§6/§7) — every refusal alike, which is why the account travels as one
    /// type rather than as a taxonomy nobody branches on.
    ///
    /// Two of those an operator most needs named. A foreign stamp is a board
    /// written under another format, and the account names the stamp found,
    /// the stamp expected and the ruled remedy ([`NO_MIGRATION_REMEDY`]) — the
    /// same sentence the journal's own refusal renders, so when the fallback
    /// chain is exhausted the daemon prints it through `BadCheckpoint`'s cause.
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
        let data = fs::read(&self.path)?;
        let Some((header, body)) = data.split_first_chunk::<HEADER_LEN>() else {
            return Err(SHORT_OF_HEADER.into());
        };
        let header = parse_header(self.seq, header)?;
        if body.len() as u64 != header.body_len {
            return Err(format!(
                "checkpoint body is {} bytes, its header claims {}",
                body.len(),
                header.body_len
            )
            .into());
        }
        if crc32c::crc32c(body) != header.crc {
            return Err(
                "checkpoint body failed its header checksum (bit-rot or a torn write)".into(),
            );
        }
        if body_hash(body) != header.body_hash {
            return Err("checkpoint body failed its header hash (bit-rot or a torn write)".into());
        }
        match codec().deserialize(body) {
            Ok(world) => Ok(Loaded {
                world,
                chain_head: header.chain_head,
            }),
            // The unsizing coercion site: `bincode::Error` is a boxed
            // `ErrorKind`, which unsizes against this function's return type
            // here and would need a `From` impl that does not exist under `?`.
            Err(skew) => Err(skew),
        }
    }

    /// What this checkpoint's header attests ([`CheckpointHeader`]), read
    /// ALONE — [`HEADER_LEN`] bytes, and nothing after them — under every
    /// check a header can pass without its body ([`parse_header`]): this
    /// build's stamp, and a seq agreeing with the file's name. So it costs one
    /// short read whatever the world's size, where [`CheckpointMeta::load`]
    /// reads and hashes the whole serialized world. The body is NOT verified:
    /// its checksum and hash need the body, and `body_hash` is what a party
    /// holding the file verifies it by.
    pub(crate) fn header(&self) -> Result<CheckpointHeader, LoadRefused> {
        let mut bytes = [0u8; HEADER_LEN];
        File::open(&self.path)?
            .read_exact(&mut bytes)
            .map_err(|e| -> LoadRefused {
                if e.kind() == io::ErrorKind::UnexpectedEof {
                    SHORT_OF_HEADER.into()
                } else {
                    e.into()
                }
            })?;
        let header = parse_header(self.seq, &bytes)?;
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
mod tests {
    use super::*;
    use tempfile::tempdir;

    /// A stand-in world: the format is generic over `W`, so what a fixture
    /// needs is something that serializes, not something that resembles one.
    fn world() -> Vec<u64> {
        vec![10, 20, 30]
    }

    /// A stand-in chain head: a value with a shape, so a header that carried
    /// the wrong thing here would not carry zeros by coincidence.
    const CHAIN_HEAD: [u8; 32] = [0xC4; 32];

    #[test]
    fn checkpoint_header_layout_is_magic_seq_crc_body_len_chain_head_and_body_hash() {
        // A checkpoint file written by one build is read by the next, so the
        // layout is pinned here rather than left to whatever `write`'s six
        // appends and `load`'s `HEADER_LEN` split happen to agree on. A field
        // added to one without the other makes `body_len` disagree with the
        // body, which makes EVERY retained base unloadable — and recovery
        // then falls silently to genesis, or refuses with `BadCheckpoint`.
        let dir = tempdir().unwrap();
        write(dir.path(), 7, &world(), &CHAIN_HEAD).expect("fixture checkpoint");
        let data = fs::read(checkpoint_path(dir.path(), 7)).unwrap();
        let body = codec().serialize(&world()).unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(b"SKC4");
        expected.extend_from_slice(&7u64.to_le_bytes()); // seq
        expected.extend_from_slice(&crc32c::crc32c(&body).to_le_bytes()); // crc(body)
        expected.extend_from_slice(&(body.len() as u64).to_le_bytes()); // body_len
        expected.extend_from_slice(&CHAIN_HEAD); // chain_head
        expected.extend_from_slice(&<[u8; 32]>::from(Sha256::digest(&body))); // body_hash
        assert_eq!(expected.len(), HEADER_LEN, "the header is what `load` splits at");
        assert_eq!(HEADER_LEN, 88);
        assert_eq!(&data[..HEADER_LEN], expected.as_slice());
        assert_eq!(&data[HEADER_LEN..], body.as_slice());

        // …and the whole file loads back through the door every base walks
        // through, the chain head with it.
        let listed = list(dir.path()).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].seq, 7);
        let loaded = listed[0].load::<Vec<u64>>().expect("the base loads");
        assert_eq!(loaded.world, world());
        assert_eq!(loaded.chain_head, CHAIN_HEAD);

        // A crash mid-write leaves a `.tmp`, which is not a base.
        fs::write(dir.path().join("checkpoint.tmp"), b"not a checkpoint").unwrap();
        assert_eq!(list(dir.path()).unwrap().len(), 1);
    }

    #[test]
    fn a_flipped_body_byte_refuses_the_base() {
        // The header checksum is what `load` validates before trusting a base,
        // because serde alone does not reliably detect bit-rot and a silently
        // wrong base would defeat the whole `BadCheckpoint` fallback chain —
        // so the account must say the CHECKSUM caught it, which is what tells
        // an operator to restore media rather than to roll a binary.
        let dir = tempdir().unwrap();
        write(dir.path(), 3, &world(), &CHAIN_HEAD).expect("fixture checkpoint");
        let path = checkpoint_path(dir.path(), 3);
        let mut data = fs::read(&path).unwrap();
        let last = data.len() - 1;
        data[last] ^= 0xFF;
        fs::write(&path, &data).unwrap();
        let refused = list(dir.path()).unwrap()[0]
            .load::<Vec<u64>>()
            .expect_err("a flipped body byte is not a base");
        assert!(refused.to_string().contains("checksum"), "got {refused}");
    }

    #[test]
    fn a_body_hash_that_disagrees_with_the_body_refuses_the_base() {
        // The hash is the header's COMMITMENT to the body — what a published
        // head names a checkpoint by — and `load` holds the file to it after
        // the checksum: a header whose hash names another body is not a base,
        // whatever its checksum says.
        let dir = tempdir().unwrap();
        write(dir.path(), 3, &world(), &CHAIN_HEAD).expect("fixture checkpoint");
        let path = checkpoint_path(dir.path(), 3);
        let mut data = fs::read(&path).unwrap();
        data[BODY_HASH_AT] ^= 0xFF;
        fs::write(&path, &data).unwrap();
        let refused = list(dir.path()).unwrap()[0]
            .load::<Vec<u64>>()
            .expect_err("a header hashing another body is not a base");
        assert!(refused.to_string().contains("hash"), "got {refused}");
    }

    #[test]
    fn a_foreign_stamp_is_refused_by_name_with_the_remedy() {
        // A checkpoint under another format names the stamp it found, the
        // stamp this build writes, and the ruled remedy — the sentence the
        // daemon prints through `BadCheckpoint` when the fallback chain is
        // exhausted. It is the FIRST check after the length, so an old-format
        // header's other fields are never read as this format's.
        let dir = tempdir().unwrap();
        write(dir.path(), 3, &world(), &CHAIN_HEAD).expect("fixture checkpoint");
        let path = checkpoint_path(dir.path(), 3);
        let mut data = fs::read(&path).unwrap();
        data[..4].copy_from_slice(b"SKC2");
        fs::write(&path, &data).unwrap();
        let refused = list(dir.path()).unwrap()[0]
            .load::<Vec<u64>>()
            .expect_err("another format's checkpoint is not a base")
            .to_string();
        for named in ["`SKC2`", "`SKC4`", "not this build's format", "delete the data directory"] {
            assert!(refused.contains(named), "{named} missing from: {refused}");
        }
    }

    #[test]
    fn a_header_reads_without_its_body_under_the_checks_a_header_holds() {
        // `header` is what a published head names a base by, so it must cost
        // the header and never the world: it reads HEADER_LEN bytes and stops
        // — a file cut to its header answers the same, where `load`, which
        // verifies the body, refuses — and it holds those bytes to every check
        // that needs no body: this build's stamp, and a seq the name agrees
        // with.
        let dir = tempdir().unwrap();
        write(dir.path(), 7, &world(), &CHAIN_HEAD).expect("fixture checkpoint");
        let path = checkpoint_path(dir.path(), 7);
        let data = fs::read(&path).unwrap();
        let written_hash = <[u8; 32]>::from(Sha256::digest(&data[HEADER_LEN..]));
        let header_of = |dir: &Path| list(dir).unwrap()[0].header();

        let header = header_of(dir.path()).expect("the header reads");
        let attested = CheckpointHeader {
            seq: Seq(7),
            chain_head: CHAIN_HEAD,
            body_hash: written_hash,
        };
        assert_eq!(header, attested, "the coordinate, the chain there, the body's hash");

        // Cut to its header: nothing after it is read, so the answer is the
        // same — and the body `load` must verify is no longer there.
        fs::write(&path, &data[..HEADER_LEN]).unwrap();
        let header = header_of(dir.path()).expect("the header reads without its body");
        assert_eq!(header, attested);
        assert!(list(dir.path()).unwrap()[0].load::<Vec<u64>>().is_err());

        // One byte short of a header is not one.
        fs::write(&path, &data[..HEADER_LEN - 1]).unwrap();
        let refused = header_of(dir.path()).expect_err("short of its own header");
        assert!(refused.to_string().contains("shorter"), "got {refused}");

        // Another format's stamp is refused by name, as `load` refuses it.
        let mut foreign = data.clone();
        foreign[..4].copy_from_slice(b"SKC3");
        fs::write(&path, &foreign).unwrap();
        let refused = header_of(dir.path()).expect_err("another format's header");
        assert!(refused.to_string().contains("`SKC3`"), "got {refused}");

        // A whole, valid file under another checkpoint's name: the seq its
        // bytes claim is not the seq its name does.
        fs::write(&path, &data).unwrap();
        fs::rename(&path, checkpoint_path(dir.path(), 8)).unwrap();
        let listed = list(dir.path()).unwrap();
        assert_eq!(listed[0].seq, 8);
        let refused = listed[0].header().expect_err("a misnamed header");
        assert!(refused.to_string().contains("claims seq 7"), "got {refused}");
    }

    #[test]
    fn a_body_that_survives_its_checksum_and_will_not_decode_is_a_skew() {
        // The one refusal the checksum has already ruled rot out of: these ARE
        // the bytes that were written, and they still are not a `W`. That is a
        // binary on the wrong side of a `W` format change, and the
        // serializer's own account is the only thing that says so — where a
        // bare "this base does not load" sends an operator to their disk.
        //
        // `bool` is the cheapest certain wrong type: its decoder rejects any
        // byte but 0 and 1, and a `Vec`'s first byte is its length.
        let refusal_for = |len: usize| {
            let dir = tempdir().unwrap();
            write(dir.path(), 3, &vec![10u64; len], &CHAIN_HEAD).expect("fixture checkpoint");
            let refused = list(dir.path()).unwrap()[0]
                .load::<bool>()
                .expect_err("a body that is not a `bool` does not load as one");
            assert!(
                !refused.to_string().contains("checksum"),
                "the checksum passed; this is a skew, not rot: {refused}"
            );
            refused.to_string()
        };
        // Two bodies rejected for two reasons, so what travels has to be the
        // SERIALIZER's account of these bytes: a sentence this module could
        // have written instead would be the same for both, and would leave an
        // operator with no more than "it did not load".
        assert_ne!(refusal_for(3), refusal_for(7));
    }

    #[test]
    fn a_base_that_cannot_be_read_says_so_rather_than_looking_damaged() {
        // Unreadable is not the same remedy as damaged, and the two were once
        // one silent refusal. A directory bearing a checkpoint's name is the
        // deterministic, privilege-free injection: `list` parses names and not
        // file types, which the `journal_path` caller contract already says.
        let dir = tempdir().unwrap();
        fs::create_dir(checkpoint_path(dir.path(), 5)).unwrap();
        let listed = list(dir.path()).unwrap();
        assert_eq!(listed.len(), 1, "a name is a checkpoint, whatever the file type");
        assert!(listed[0].load::<Vec<u64>>().is_err());
    }

    #[test]
    fn only_the_name_the_writer_emits_is_a_checkpoint() {
        // `checkpoint.07` parses as 7 under a bare `u64::from_str`, so without
        // the round trip it is a second entry at one coordinate — and
        // `retain` counts entries, so a configured `N = 2` fallback chain
        // would silently hold one real base and one alias of it.
        let dir = tempdir().unwrap();
        write(dir.path(), 7, &world(), &CHAIN_HEAD).expect("fixture checkpoint");
        fs::copy(checkpoint_path(dir.path(), 7), dir.path().join("checkpoint.07")).unwrap();
        fs::copy(checkpoint_path(dir.path(), 7), dir.path().join("checkpoint.+7")).unwrap();
        let listed = list(dir.path()).unwrap();
        assert_eq!(listed.len(), 1, "only one spelling names a checkpoint");
        assert_eq!(listed[0].seq, 7);
    }

    #[test]
    fn checkpoints_list_in_seq_order_across_a_digit_boundary() {
        // Every operation over `list`'s answer reads a position as an age:
        // `retain` deletes from the front as the oldest, `select_base` walks
        // from the back as the newest and reads the front as the floor. Name
        // order and seq order agree while seqs have one digit — and
        // `checkpoint.10` sorts BEFORE `checkpoint.9` by name.
        let seqs_in = |dir: &Path| -> Vec<u64> {
            list(dir).unwrap().iter().map(|cp| cp.seq).collect()
        };
        let dir = tempdir().unwrap();
        for seq in [10, 1, 100, 9, 99] {
            write(dir.path(), seq, &world(), &CHAIN_HEAD).expect("fixture checkpoint");
        }
        assert_eq!(seqs_in(dir.path()), vec![1, 9, 10, 99, 100]);
        // …so retention keeps the numerically newest, and names the floor
        // from them.
        assert_eq!(retain(dir.path(), 2).unwrap(), Some(99));
        assert_eq!(
            seqs_in(dir.path()),
            vec![99, 100],
            "retention kept other than the newest bases"
        );
    }
}
