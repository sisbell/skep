//! Naming and damaging the files a kernel keeps — the operations both
//! integration tiers perform on a CLOSED store: name a segment or a
//! checkpoint, flip a byte, cut a file short, append past the end.
//!
//! These know no format. What each tier restates for itself is the *layout*
//! it judges — the frame header, the checkpoint header, the frame walk —
//! because reading the on-disk shape from outside the crate is the point of
//! testing it at this tier. Reading a path and writing it back is not, so it
//! is stated once.
//!
//! Failures here are the harness's own, never a finding: a panic names which
//! step of the mutilation could not be performed.

use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};

/// The journal segment beginning at `first_seq` (§1's name-by-firstSeq).
pub fn seg_file(dir: &Path, first_seq: u64) -> PathBuf {
    dir.join(format!("seg-{first_seq}.wal"))
}

/// The checkpoint embodying `Seq ≤ seq` (§6).
pub fn ckpt_file(dir: &Path, seq: u64) -> PathBuf {
    dir.join(format!("checkpoint.{seq}"))
}

/// Invert every bit of the byte at `offset`, so a single-bit-rot fixture
/// damages exactly the field it names and nothing beside it.
pub fn flip_byte(path: &Path, offset: u64) {
    let mut data = fs::read(path).expect("read for flip");
    data[offset as usize] ^= 0xFF;
    fs::write(path, data).expect("write flipped");
}

/// Cut `path` to `len` bytes — a crash that lost everything after it.
pub fn truncate_file(path: &Path, len: u64) {
    let f = OpenOptions::new()
        .write(true)
        .open(path)
        .expect("open for truncate");
    f.set_len(len).expect("truncate");
}

/// Append `bytes` past the end — a partial write that landed, or junk.
pub fn append_bytes(path: &Path, bytes: &[u8]) {
    use std::io::Write as _;
    let mut f = OpenOptions::new()
        .append(true)
        .open(path)
        .expect("open for append");
    f.write_all(bytes).expect("append");
}
