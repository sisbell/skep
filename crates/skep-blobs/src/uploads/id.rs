//! The upload identifier: 128 bits drawn from the OS per upload.
//!
//! It is the resumable upload's identifier (`media.md` Op inventory 1, the
//! resumable upload's clause (1)): never a sequence, spelled as 32 lowercase
//! hex. `UploadId`'s bytes are private to this file: an identifier is
//! minted here or parsed here from exactly that spelling, and made nowhere
//! else.

use std::fmt;
use std::io;
use std::str::FromStr;

/// The identifier's width: 128 bits.
pub const IDENTIFIER_BYTES: usize = 16;

/// One upload's identifier: 128 bits from the OS, compared exactly.
///
/// It is ordered by its bytes, which is the order of its hex spelling.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct UploadId([u8; IDENTIFIER_BYTES]);

impl UploadId {
    /// Returns a fresh identifier from the OS.
    ///
    /// # Errors
    ///
    /// Fail-stop on an OS that refuses entropy, answered as `OS entropy:
    /// {cause}`: an upload is never keyed by anything weaker.
    pub(crate) fn mint() -> io::Result<UploadId> {
        let mut raw = [0u8; IDENTIFIER_BYTES];
        getrandom::fill(&mut raw).map_err(|e| io::Error::other(format!("OS entropy: {e}")))?;
        Ok(UploadId(raw))
    }

    /// Parses only 32 lowercase hex; anything else is no identifier.
    ///
    /// The predicate form, which the daemon's path parse uses; [`FromStr`]
    /// answers the same text with a refusal a generic caller can propagate.
    pub fn parse(s: &str) -> Option<UploadId> {
        let b = s.as_bytes();
        if b.len() != 2 * IDENTIFIER_BYTES {
            return None;
        }
        let nibble = |d: u8| match d {
            b'0'..=b'9' => Some(d - b'0'),
            b'a'..=b'f' => Some(d - b'a' + 10),
            _ => None,
        };
        let mut raw = [0u8; IDENTIFIER_BYTES];
        for (slot, &[hi, lo]) in raw.iter_mut().zip(b.as_chunks::<2>().0) {
            *slot = (nibble(hi)? << 4) | nibble(lo)?;
        }
        Some(UploadId(raw))
    }

    /// Returns the wire and file spelling: 32 lowercase hex.
    ///
    /// It is the identifier's [`Display`](fmt::Display) as a `String` — by
    /// value, as a `Copy` type's `to_` conversion takes it (C-CONV).
    pub fn to_hex(self) -> String {
        self.to_string()
    }
}

/// The spelling, written a byte at a time: 32 lowercase hex.
impl fmt::Display for UploadId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.iter().try_for_each(|b| write!(f, "{b:02x}"))
    }
}

impl fmt::Debug for UploadId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UploadId({self})")
    }
}

/// The refusal of [`UploadId`]'s [`FromStr`]: the text is not 32 lowercase hex.
///
/// It carries no reason — the spelling is one shape.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct NotAnUploadId;

impl fmt::Display for NotAnUploadId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("not an upload identifier (32 lowercase hex)")
    }
}

impl std::error::Error for NotAnUploadId {}

/// The ecosystem's spelling of [`UploadId::parse`].
///
/// It is what a generic caller — an argument parser, an environment reader —
/// can reach, the same spelling admitted.
///
/// # Errors
///
/// Anything else is refused as [`NotAnUploadId`].
impl FromStr for UploadId {
    type Err = NotAnUploadId;

    fn from_str(s: &str) -> Result<UploadId, NotAnUploadId> {
        UploadId::parse(s).ok_or(NotAnUploadId)
    }
}
