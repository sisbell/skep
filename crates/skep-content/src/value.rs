//! §Types & errors — the opaque content value, `Val`.

use std::fmt;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

/// An opaque, immutable content value — an element of ASN-0036's `Val`
/// (§Types & errors). Write-once ⇒ never edited ⇒ needs no internal COW; the
/// `Arc` gives O(1) clone, so the map's structural sharing just bumps
/// refcounts. M4 is **value-oblivious**: it never inspects these bytes. A
/// value's *kind* — text or anything else — is read from the address it is
/// stored at, as that address's subspace identifier `E(a)₁` (ASN-0093 L0;
/// M1's `Address::subspace`), never from a tag stored with the value:
/// ASN-0036 leaves `Val`'s typing open (its first open question), and the M4
/// design settles it untyped (Conflicts #5).
///
/// Serde rides serde's `rc` feature for the `Arc<[u8]>` impls (an M4-local
/// dependency knob). A value serializes as a SEQUENCE of `u8` — serde has no
/// byte specialization for `[u8]` — which bincode, M2's journal and
/// checkpoint format, lays down as the length then the raw bytes; a transcode
/// to a value tree, like the engine's world dump, sees one integer per byte
/// (skep-engine's `a_content_byte_costs_a_whole_tree_node` pins that).
///
/// A value's bytes never render into a log: its `Debug` is its LENGTH, the
/// redaction M2's `Attestation` gives a signature, so a type holding a `Val`
/// derives `Debug` and inherits it. No `Hash`, so no map can key on a value:
/// identity is by address (S4).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Val(Arc<[u8]>);

impl Val {
    /// Wrap bytes as a value — anything `Into<Arc<[u8]>>`: `&[u8]`,
    /// `[u8; N]`, `Vec<u8>`, `Box<[u8]>`, …. The bytes land in one shared
    /// allocation, so a `Vec` built only to be wrapped costs a second:
    /// `Val::new([b])` is a one-byte value in one allocation,
    /// `Val::new(vec![b])` in two.
    pub fn new(bytes: impl Into<Arc<[u8]>>) -> Val {
        Val(bytes.into())
    }

    /// The value's bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The value's length in bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the value is zero bytes long — legal, as an empty `Vec` is.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// `3 bytes`: the length, never a byte. Bare, as `Duration` renders `1.5s`,
/// so a holder's derived `Debug` reads `val: 3 bytes` or `Content(3 bytes)`.
impl fmt::Debug for Val {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} bytes", self.len())
    }
}

/// The value's bytes, for APIs generic over `AsRef<[u8]>` — the conversion
/// `Vec<u8>`, `String` and `Arc<[u8]>` offer beside their inherent views.
impl AsRef<[u8]> for Val {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
