//! Framing and the tag set — AUTH-1.11–1.17.
//!
//! Framing is the domain separation of what is hashed or signed under a
//! declared tag: a key's fingerprint, a session handshake, a node hello, and
//! an entry's or a record's frame. Declaring a constant beside [`framed`] is
//! the only way to hold a [`Tag`] (AUTH-1.13), and [`framed`] debug-asserts
//! membership in [`TAGS`] (AUTH-1.14) — the two mechanisms close two
//! different directions (AUTH-1.16): nothing undeclared can be framed, and
//! nothing declared escapes the prefix-free check over `TAGS` (the assertion
//! verifying AUTH-1.15 is a test obligation pinned with I2, AUTH-2.93).

use core::fmt;

/// A framing tag (AUTH-1.11).
///
/// The field is private, with no public constructor (AUTH-1.13): a foreign
/// crate cannot frame under an undeclared tag — consumers (bebe's
/// `NODE_HELLO_TAG`, AUTH-2.118) hold the declared constants only. Tags
/// chosen in other documents (the invite payload's, the realm fingerprint's
/// — AUTH-1.17) are declared here when chosen: the constant and its row in
/// [`TAGS`], one edit in one place.
///
/// `Copy`, because a tag is two words that [`framed`] only reads: a caller
/// binds a declared constant, or walks [`TAGS`], and frames under what it
/// holds as often as it likes. `PartialEq` is what membership in `TAGS` is
/// tested by, here and in the conformance assertion.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Tag(&'static [u8]);

impl Tag {
    /// Returns the tag's bytes (AUTH-1.11).
    pub fn as_bytes(&self) -> &'static [u8] {
        self.0
    }
}

/// The tag as written.
///
/// Every declared tag begins `skep-` and is ASCII (AUTH-1.15), so the bytes
/// are the name.
impl fmt::Debug for Tag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Tag({})", String::from_utf8_lossy(self.0))
    }
}

/// The key-fingerprint framing tag (AUTH-1.11).
///
/// `Fingerprint::of` hashes `framed(KEY_TAG, [alg, raw])` (AUTH-1.8).
pub const KEY_TAG: Tag = Tag(b"skep-key-v1");

/// The session-handshake framing tag (AUTH-1.11).
///
/// Its consumers are the handshake's two sides: the signing client, which
/// signs the session body, and the daemon's challenge/response surface,
/// `skep-core`'s session layer, which verifies it. The v1 bytes sign an
/// unscoped (full-scope) session body.
pub const SESSION_TAG: Tag = Tag(b"skep-session-v1");

/// The v2 session-handshake framing tag (AUTH-1.11, RES-63).
///
/// It frames the bytes a content-scoped session body signs, distinct from
/// [`SESSION_TAG`] so a v1 signature over a scoped body verifies under
/// neither. Consumed by the same two sides as [`SESSION_TAG`]; declared here
/// beside `framed` with its `TAGS` row, one edit in one place (AUTH-1.17).
/// `skep-session-v1` and `skep-session-v2` are not prefixes of each other
/// (AUTH-1.15).
pub const SESSION_TAG_V2: Tag = Tag(b"skep-session-v2");

/// The node-hello framing tag (AUTH-1.11).
///
/// It is consumed by bebe as the declared constant (AUTH-2.118).
pub const NODE_HELLO_TAG: Tag = Tag(b"skep-node-hello-v1");

/// The entry frame's tag, a tag chosen in another document.
///
/// It is declared in AUTH-1.11's block as AUTH-1.17 binds one (signed ops;
/// the design record §2.5, §4.2 (C)). It frames the bytes a publish-class
/// entry's signature, or under the `record` token a record's `sig` (the
/// frame merge), is made over —
/// `framed(ENTRY_TAG, [alg, board, account, doc, op, body])`, composed by
/// [`crate::entry_frame`], a record's through [`crate::RecordFrame`] —
/// signed by the writing hand, an entry's at its own write and a record's
/// before its deposit, and verified by the daemon before the commit and by
/// any reader beside the table. The tag is the frame's whole domain
/// separation: FIPS 204's `ctx` and FN-DSA's domain context are empty under
/// every marker tag (the ctx pin), so nothing but this tag tells an entry's
/// or a record's signature from a session's or a key fingerprint's preimage;
/// the `op` member's token tells the two grades apart.
pub const ENTRY_TAG: Tag = Tag(b"skep-entry-v1");

/// The declared tag set (AUTH-1.11).
///
/// Every tag begins `skep-` and no tag is a prefix of another (AUTH-1.15);
/// the conformance assertion ranging over this value is the I2 obligation
/// AUTH-2.93 pins.
pub const TAGS: &[Tag] = &[KEY_TAG, SESSION_TAG, SESSION_TAG_V2, NODE_HELLO_TAG, ENTRY_TAG];

/// Returns `tag ‖ (per field f, in order: be32(len(f)) ‖ f)` (AUTH-1.12).
///
/// `be32` is the 4-byte big-endian byte length; the framing is injective for
/// a fixed tag.
///
/// # Panics
///
/// Panics where a field is 2^32 bytes or longer — a length `be32` cannot
/// write — naming the obligation. A longer field is a caller's bug and not
/// an outcome: no field the workspace frames reaches it. The
/// largest is an entry body, and each grammar's is held to a bound of its
/// own before it is framed: an `insert`'s values, and every address a
/// request names, by the daemon's request cap; a link write's slots as
/// stored — a V-spec slot's I-extents, which the store resolves and no
/// request carries — by M7's per-slot span budget; a `publish`'s, read off
/// the store, by the daemon's shot-body budget; a `record`'s sig-less record
/// by the record cap ([`MAX_RECORD_BYTES`](crate::MAX_RECORD_BYTES)).
/// Truncating the length would silently break the injectivity above rather
/// than refuse it, so it panics.
///
/// Panics in a debug build where `tag` is not a member of [`TAGS`]
/// (AUTH-1.14), so a tag declared but not listed fails at its first use;
/// release builds pay nothing and produce identical bytes.
pub fn framed(tag: Tag, fields: &[&[u8]]) -> Vec<u8> {
    debug_assert!(
        TAGS.contains(&tag),
        "framed: {tag:?} is declared but not listed in TAGS (AUTH-1.14)"
    );
    let mut out = Vec::with_capacity(
        tag.0.len() + fields.iter().map(|f| delimited_len(f.len())).sum::<usize>(),
    );
    out.extend_from_slice(tag.0);
    for field in fields {
        push_delimited(&mut out, field);
    }
    out
}

/// Writes one length-delimited element, `be32(len) ‖ bytes`, onto `out`.
///
/// It is AUTH-1.12's field rule, and the rule every length-delimited element
/// nested inside a field follows too (the entry frame's members, in the
/// design record's word, are [`framed`]'s fields). One function at every
/// level is what makes the injectivity [`framed`] states hold at every
/// level.
///
/// # Panics
///
/// Panics where the element is 2^32 bytes or longer, as [`framed`] does: the
/// bound is enforced by a panic rather than a truncated length.
pub(crate) fn push_delimited(out: &mut Vec<u8>, bytes: &[u8]) {
    let len = u32::try_from(bytes.len()).expect("framed element length exceeds be32");
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
}

/// Returns how many bytes [`push_delimited`] writes for a `len`-byte element.
///
/// They are its `be32` length, then the element, so a budget measured before
/// an element is written reads the delimiting rule's cost where the rule is
/// stated. Saturating: an element no `be32` can measure is
/// [`push_delimited`]'s panic to refuse, never a wrapped length here.
pub(crate) fn delimited_len(len: usize) -> usize {
    len.saturating_add(std::mem::size_of::<u32>())
}

#[cfg(all(test, debug_assertions))]
mod tests {
    use super::{framed, Tag, TAGS};

    /// Checks that a declared but unlisted tag panics at framing (AUTH-1.14).
    ///
    /// It is the second of AUTH-1.16's two mechanisms. The private field
    /// stops an undeclared tag; this assertion stops one declared but
    /// missing from [`TAGS`], at its first use. Without it a forgotten row
    /// frames silently and escapes the prefix-free check, which ranges over
    /// `TAGS` alone — so a tag colliding with an existing prefix would ship
    /// and domain separation would be broken for whatever it signs. Written
    /// here because only this module can hold an unlisted `Tag`, which is
    /// the first mechanism working.
    #[test]
    #[should_panic(expected = "AUTH-1.14")]
    fn framing_under_a_declared_but_unlisted_tag_is_refused() {
        let unlisted = Tag(b"skep-unlisted-v1");
        assert!(
            !TAGS.contains(&unlisted),
            "fixture: the tag must not be listed"
        );
        let _ = framed(unlisted, &[b"x"]);
    }
}
