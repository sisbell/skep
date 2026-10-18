//! An invite code (the intake funnel's second arm): an opaque string.
//!
//! The code is compared whole — 128 bits of OS entropy as lowercase hex where
//! `invite` mints one, or the value `--code` hands in, so a later mint can
//! hand in a document's address in a random string's place, the format left
//! open between the two — and held to the alphabet ([`code_ok`]), the URL's
//! unreserved characters, so it rides the invite link unescaped and the
//! invite file's line (`invites`) splits on its spaces.
//!
//! Its value ([`InviteCode`]) is the alphabet's one door: every code that
//! comes in — the `invite` verb's `--code` and the claim post's field — is
//! one only once [`InviteCode::parse`] admits it; and this module holds the
//! value and its alphabet alone, so no other module can make one any other
//! way — the invite file, which reads codes back from lines an owner may
//! have edited by hand, among them. A code is never logged.

use std::fmt;

/// A code's byte bound: room for a document's address, and no more.
pub const MAX_CODE_BYTES: usize = 128;

/// Returns whether `code` is in the code's alphabet.
///
/// The alphabet: 1 to [`MAX_CODE_BYTES`] of the URL's unreserved characters
/// — letters, digits, `-`, `.`, `_`, `~` — so the code rides the invite link
/// as it is and the invite file's line splits on its spaces.
fn code_ok(code: &str) -> bool {
    !code.is_empty() && code.len() <= MAX_CODE_BYTES && code.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
}

/// A code in the alphabet: the value every door hands on.
///
/// It goes from `--code` to the invite file's mint and from the claim post's
/// field to its lookup and its spend, and it is the mint's answer.
/// [`InviteCode::parse`] is the only way to one, so a code of this type rides
/// the invite link as it is and keeps the invite file's line splitting on its
/// spaces, and no other string of a code's shape — a status token among them
/// — can stand in for one. Its `Debug` shows none of it: a code is never
/// logged.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct InviteCode(String);

impl InviteCode {
    /// Parses `text` as a code, where [`code_ok`] admits it.
    pub fn parse(text: &str) -> Option<InviteCode> {
        code_ok(text).then(|| InviteCode(text.to_owned()))
    }

    /// Returns the code as text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Nothing of the code: a `{:?}` can carry none of it.
impl fmt::Debug for InviteCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("InviteCode(…)")
    }
}

#[cfg(test)]
mod tests;
