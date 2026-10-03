//! §Types & errors — the opaque content value, `Val`.

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
/// (skep-engine's `a_content_byte_costs_a_whole_tree_node` pins that). No
/// `Debug` on purpose: a value's bytes never render into logs —
/// [`ContentWrite`]'s manual `Debug` reports only the byte length.
///
/// [`ContentWrite`]: crate::ContentWrite
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Val(Arc<[u8]>);

#[allow(clippy::len_without_is_empty)] // the interface declares len() only; a zero-length value is legal, not an "empty store"
impl Val {
    /// Wrap bytes as a value (`Vec<u8>`, `&[u8]`, `Box<[u8]>`, … — anything
    /// `Into<Arc<[u8]>>`).
    pub fn new(b: impl Into<Arc<[u8]>>) -> Val {
        Val(b.into())
    }

    /// The value's bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The value's length in bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }
}
