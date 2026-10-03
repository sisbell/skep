//! The store's refusals — what a caller is told beside an I/O failure.

use std::fmt;
use std::io;

/// Why the store refused — one variant per answer a caller acts on
/// differently. I/O failures ride [`BlobError::Io`] verbatim; everything
/// else is the store's own verdict, and none of them says anything about
/// another key's uploads or files (the record's M-I2 (e)).
#[derive(Debug)]
pub enum BlobError {
    /// The data directory refused I/O — a write, a sync, a rename, a read.
    Io(io::Error),
    /// The identifier names no upload of THIS key's: expired, retired,
    /// another key's, or never minted — ONE answer for all four, exactly
    /// as an expired one answers (the record's clause (1)).
    NoUpload,
    /// A resume stated an offset other than the record's — the standard
    /// shape's offset conflict — and carries the record's, the one a resume
    /// continues from (clause (5)).
    Offset { recorded: u64 },
    /// The bytes would pass the upload's declared length: the record's
    /// `length` and the offset the bytes would start at (clause (1)).
    Length { length: u64, offset: u64 },
    /// A finish asked of an upload whose bytes received fall short of its
    /// length — a caller's defect, never a wire state: the daemon finishes
    /// only where the offset reaches the length (clause (7)).
    Incomplete { offset: u64, length: u64 },
    /// `append` or `finish` on an upload no `resume` opened in this
    /// process — a caller's defect.
    NotResumed,
}

impl From<io::Error> for BlobError {
    fn from(e: io::Error) -> BlobError {
        BlobError::Io(e)
    }
}

impl fmt::Display for BlobError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BlobError::Io(e) => write!(f, "blob store I/O: {e}"),
            BlobError::NoUpload => f.write_str("no upload of this key's by that identifier"),
            BlobError::Offset { recorded } => {
                write!(f, "the stated offset is not the record's ({recorded})")
            }
            BlobError::Length { length, offset } => {
                write!(f, "the bytes at offset {offset} would pass the declared length {length}")
            }
            BlobError::Incomplete { offset, length } => {
                write!(f, "a finish at offset {offset} of a length-{length} upload")
            }
            BlobError::NotResumed => f.write_str("the upload was not resumed in this process"),
        }
    }
}

impl std::error::Error for BlobError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            BlobError::Io(e) => Some(e),
            _ => None,
        }
    }
}
