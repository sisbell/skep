//! Framing and the tag set — AUTH-1.11–1.17.
//!
//! Domain separation for every byte string this system hashes or (later)
//! signs. Declaring a constant beside [`framed`] is the ONLY way to hold a
//! [`Tag`] (AUTH-1.13), and [`framed`] debug-asserts membership in [`TAGS`]
//! (AUTH-1.14) — the two mechanisms close two different directions
//! (AUTH-1.16): nothing UNDECLARED can be framed, and nothing DECLARED
//! escapes the prefix-free check over `TAGS` (the assertion verifying
//! AUTH-1.15 is a test obligation pinned with I2, AUTH-2.93).

use core::fmt;

/// A framing tag (AUTH-1.11). The field is private, with no public
/// constructor (AUTH-1.13): a foreign crate CANNOT frame under an undeclared
/// tag — consumers (bebe's `NODE_HELLO_TAG`, AUTH-2.118) hold the declared
/// constants only. Tags chosen in other documents (the invite payload's, the
/// realm fingerprint's — AUTH-1.17) are declared HERE when chosen: the
/// constant AND its row in [`TAGS`], one edit in one place.
///
/// `Copy`, because a tag is two words that [`framed`] only reads: a caller
/// binds a declared constant, or walks [`TAGS`], and frames under what it
/// holds as often as it likes. `PartialEq` is what membership in `TAGS` is
/// tested by, here and in the conformance assertion.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Tag(&'static [u8]);

impl Tag {
    /// The tag's bytes (AUTH-1.11).
    pub fn as_bytes(&self) -> &'static [u8] {
        self.0
    }
}

/// The tag as written: every declared tag begins `skep-` and is ASCII
/// (AUTH-1.15), so the bytes are the name.
impl fmt::Debug for Tag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Tag({})", String::from_utf8_lossy(self.0))
    }
}

/// The key-fingerprint framing tag (AUTH-1.11): `Fingerprint::of` hashes
/// `framed(KEY_TAG, [alg, raw])` (AUTH-1.8).
pub const KEY_TAG: Tag = Tag(b"skep-key-v1");

/// The session-handshake framing tag (AUTH-1.11); its consumer is skepd's
/// challenge/response signing surface.
pub const SESSION_TAG: Tag = Tag(b"skep-session-v1");

/// The node-hello framing tag (AUTH-1.11); consumed by bebe as the declared
/// constant (AUTH-2.118).
pub const NODE_HELLO_TAG: Tag = Tag(b"skep-node-hello-v1");

/// The declared tag set (AUTH-1.11). Every tag begins `skep-` and no tag is
/// a prefix of another (AUTH-1.15); the conformance assertion ranging over
/// this value is the I2 obligation AUTH-2.93 pins.
pub const TAGS: &[Tag] = &[KEY_TAG, SESSION_TAG, NODE_HELLO_TAG];

/// AUTH-1.12 — `framed(tag, fields)` produces
/// `tag ‖ (per field f, in order: be32(len(f)) ‖ f)`, where `be32` is the
/// 4-byte big-endian byte length; the framing is injective for a fixed tag.
///
/// AUTH-1.14 — debug-asserts that `tag` is a member of [`TAGS`], so a tag
/// declared but not listed fails at its first use; release builds pay
/// nothing and produce identical bytes.
pub fn framed(tag: Tag, fields: &[&[u8]]) -> Vec<u8> {
    debug_assert!(
        TAGS.contains(&tag),
        "framed: {tag:?} is declared but not listed in TAGS (AUTH-1.14)"
    );
    let mut out =
        Vec::with_capacity(tag.0.len() + fields.iter().map(|f| 4 + f.len()).sum::<usize>());
    out.extend_from_slice(tag.0);
    for field in fields {
        // be32 framing: a field a u32 cannot measure would silently break
        // injectivity, so it is refused loudly instead (no caller frames one:
        // the fields here are alg tokens and raw keys).
        let len = u32::try_from(field.len()).expect("framed field length exceeds be32");
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(field);
    }
    out
}
