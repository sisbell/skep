//! The store's refusals — what a caller is told beside an I/O failure.

use std::fmt;
use std::io;

/// Why the store refused — one variant per answer a caller acts on
/// differently. I/O failures ride [`BlobError::Io`] verbatim; everything
/// else is the store's own verdict, and none of them says anything about
/// another principal's uploads or files (the register M-I2 (e)).
///
/// A caller's bug is none of these. A finish short of the declared length
/// PANICS, naming the obligation it breaks
/// ([`Stream::finish`](crate::Stream::finish)): an honest caller has ruled
/// it out before it calls, so an answer for it would be an arm every caller
/// handles for a state it cannot be in.
///
/// Deliberately not `#[non_exhaustive]`: the daemon's exhaustive match over
/// it gives each refusal its wire answer, and a new variant breaks that
/// match on purpose, where the `_` arm `#[non_exhaustive]` demands of an
/// outside crate would answer it as whatever that arm answers.
#[derive(Debug)]
pub enum BlobError {
    /// The data directory refused I/O — a write, a sync, a rename, a read.
    Io(io::Error),
    /// The identifier names no upload of THIS principal's: expired,
    /// retired, another principal's, or never minted — ONE answer for all
    /// four, exactly as an expired one answers (`media.md` Op inventory 1,
    /// the resumable upload (1)). Every act that judges a standing upload
    /// answers it for all four; [`Stream::append`](crate::Stream::append),
    /// whose resume judged the upload standing, judges only that its record
    /// has not been retired under it.
    NoUpload,
    /// A resume stated an offset other than the record's — the standard
    /// shape's offset conflict — and carries the record's, the one a resume
    /// continues from (clause (5)).
    Offset { recorded: u64 },
    /// The bytes would pass the upload's declared length: the record's
    /// `length` and the offset the bytes would start at (clause (1)).
    Length { length: u64, offset: u64 },
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
            BlobError::NoUpload => f.write_str("no upload of this principal's by that identifier"),
            BlobError::Offset { recorded } => {
                write!(f, "the stated offset is not the record's ({recorded})")
            }
            BlobError::Length { length, offset } => {
                write!(f, "the bytes at offset {offset} would pass the declared length {length}")
            }
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
