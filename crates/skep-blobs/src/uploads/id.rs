//! THE IDENTIFIER (`media.md` Op inventory 1, the resumable upload's clause
//! (1)): 128 bits drawn from the OS per upload, never a sequence, spelled as
//! 32 lowercase hex. `UploadId`'s bytes are private to this file: an
//! identifier is minted here or parsed here from exactly that spelling, and
//! made nowhere else.

use std::fmt;
use std::io;
use std::str::FromStr;

/// The identifier's width: 128 bits.
pub const IDENTIFIER_BYTES: usize = 16;

/// One upload's identifier — 128 bits from the OS, compared exactly, and
/// ordered by its bytes, which is the order of its hex spelling.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct UploadId([u8; IDENTIFIER_BYTES]);

impl UploadId {
    /// A fresh identifier from the OS. Fail-stop on an OS that refuses
    /// entropy: an upload is never keyed by anything weaker.
    pub(crate) fn mint() -> io::Result<UploadId> {
        let mut raw = [0u8; IDENTIFIER_BYTES];
        getrandom::fill(&mut raw).map_err(|e| io::Error::other(format!("OS entropy: {e}")))?;
        Ok(UploadId(raw))
    }

    /// ONLY 32 lowercase hex; anything else is no identifier. The predicate
    /// form, which the daemon's path parse uses; [`FromStr`] answers the
    /// same text with a refusal a generic caller can propagate.
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

    /// The wire and file spelling: 32 lowercase hex, the identifier's
    /// [`Display`](fmt::Display) as a `String` — by value, as a `Copy`
    /// type's `to_` conversion takes it (C-CONV).
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

/// [`UploadId::parse`] refused: the text is not 32 lowercase hex. Carries
/// no reason — the spelling is one shape.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct NotAnUploadId;

impl fmt::Display for NotAnUploadId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("not an upload identifier (32 lowercase hex)")
    }
}

impl std::error::Error for NotAnUploadId {}

/// The ecosystem's spelling of [`UploadId::parse`]: what a generic caller —
/// an argument parser, an environment reader — can reach, the same spelling
/// admitted and anything else refused as [`NotAnUploadId`].
impl FromStr for UploadId {
    type Err = NotAnUploadId;

    fn from_str(s: &str) -> Result<UploadId, NotAnUploadId> {
        UploadId::parse(s).ok_or(NotAnUploadId)
    }
}
