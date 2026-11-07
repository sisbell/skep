//! The store's refusals — what a caller is told beside an I/O failure — and
//! an expiry's failure, which says whether its partial went.

use std::fmt;
use std::io;

/// Why the store refused: one variant per answer a caller acts on differently.
///
/// I/O failures ride [`BlobError::Io`] verbatim; everything else is the
/// store's own verdict, and none of them says anything about another
/// principal's uploads or files (the register M-I2 (e)).
///
/// A caller's bug is none of these. A finish short of the declared length
/// panics, naming the obligation it breaks
/// ([`Stream::finish`](crate::Stream::finish)): an honest caller has ruled
/// it out before it calls, so an answer for it would be an arm every caller
/// handles for a state it cannot be in. Nor is a defect of the store's own:
/// a byte received marked past its record's length panics too
/// (`UploadRecords::mark_received`), where a `Length` would tell a client of
/// bytes it never sent.
///
/// Deliberately not `#[non_exhaustive]`: the daemon's exhaustive match over
/// it gives each refusal its wire answer, and a new variant breaks that
/// match on purpose, where the `_` arm `#[non_exhaustive]` demands of an
/// outside crate would answer it as whatever that arm answers.
#[derive(Debug)]
pub enum BlobError {
    /// The data directory refused I/O, now or earlier.
    ///
    /// The act is an open, a stat, a read, a write, a sync, a cut-back, a
    /// link, a rename or a removal; or the directory holds a partial the
    /// store cannot continue from. A torn stream refuses every later write
    /// and sync of its partial, and a stopped log every later append, as
    /// `Io` (see [`Stream`](crate::Stream), [`Store`](crate::Store)); and a
    /// resume over a partial shorter than its record's offset answers `Io`,
    /// the partial refused and never extended
    /// ([`Store::resume`](crate::Store::resume)). Its text names the file
    /// within the data directory, a partial by its directory alone. Where the
    /// OS refused, the text is `{file}: {act}: {cause}` and the kind is the
    /// OS's; a torn stream's and a stopped log's refusals are `Other`, and a
    /// short partial's `InvalidData`.
    Io(io::Error),
    /// The identifier names no upload of *this* principal's.
    ///
    /// The upload is expired, retired, another principal's, or never minted
    /// — one answer for all four, exactly as an expired one answers
    /// (`media.md` Op inventory 1, the resumable upload (1)). Every act that
    /// judges a standing upload answers it for all four;
    /// [`Stream::append`](crate::Stream::append), whose resume judged the
    /// upload standing, judges only that its record has not been retired
    /// under it.
    NoUpload,
    /// A resume stated an offset other than the record's.
    ///
    /// It is the standard shape's offset conflict, and carries the record's
    /// offset, the one a resume continues from (clause (5)).
    Offset { recorded: u64 },
    /// The bytes would pass the upload's declared length.
    ///
    /// It is an append's refusal, nothing written
    /// ([`Stream::append`](crate::Stream::append)): the record's `length`
    /// and the offset the bytes would start at (clause (1)).
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

/// Why an expired upload's removal failed, and whether its partial went.
///
/// [`Store::expire_upload`](crate::Store::expire_upload) answers it, the
/// pruner's act: the pass counts an expiry by whether its partial went, its
/// bytes with it, and goes on to the next, so the two acts' failures are told
/// apart here where one `io::Error` would fold them. Its text is the inner
/// error's, the store's own `{file}: {act}: {cause}` or a stopped log's
/// refusal, and its source that error.
///
/// Deliberately not `#[non_exhaustive]`, for [`BlobError`]'s reason: the
/// pass's match over it is exhaustive, and a new variant breaks that match on
/// purpose.
#[derive(Debug)]
pub enum ExpiryFailed {
    /// The partial's unlink failed, or the directory's fsync after it.
    ///
    /// The record stands, expired, for the next pass to take again. Where the
    /// unlink went and the fsync alone failed, the next pass finds no partial
    /// and retires the record freeing nothing, so the bytes that unlink freed
    /// are counted in no answer.
    Removal(io::Error),
    /// The partial went, and its record's retirement line did not land.
    ///
    /// The record has left this process, so nothing is owed: the log's next
    /// rewrite — the one that lifts a stop, or the next open's — writes it
    /// without the record.
    Retirement {
        /// The bytes the partial's unlink freed.
        freed: u64,
        /// The append's refusal — a stopped log's, naming its cause — or its
        /// failure.
        error: io::Error,
    },
}

impl ExpiryFailed {
    /// Returns the inner error: the act's own, as the store spelled it.
    fn inner(&self) -> &io::Error {
        match self {
            ExpiryFailed::Removal(error) | ExpiryFailed::Retirement { error, .. } => error,
        }
    }
}

impl fmt::Display for ExpiryFailed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self.inner(), f)
    }
}

impl std::error::Error for ExpiryFailed {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.inner())
    }
}
