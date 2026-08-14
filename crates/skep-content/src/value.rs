//! §Types & errors — the opaque content payload.

use std::sync::Arc;

use serde::{Deserialize, Serialize};

/// Opaque, immutable content payload (§Types & errors). Write-once ⇒ never
/// edited ⇒ needs no internal COW; the `Arc` gives O(1) clone, so the map's
/// structural sharing just bumps refcounts. M4 is **value-oblivious**: it
/// never inspects these bytes — *kind* (text vs. anything else) is recovered
/// from the I-address structure via M1 (`subspace`/`classify`), never from a
/// stored tag (ASN-0036 content-typing: no type discriminator on the value).
///
/// Serde rides serde's `rc` feature for the `Arc<[u8]>` impls (an M4-local
/// dependency knob); the payload serializes as a plain byte blob. No `Debug`
/// on purpose: blobs never render into logs — [`ContentWrite`]'s manual
/// `Debug` reports only the byte length.
///
/// [`ContentWrite`]: crate::ContentWrite
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Val(Arc<[u8]>);

#[allow(clippy::len_without_is_empty)] // the interface declares len() only; a zero-length value is a legal payload, not an "empty store"
impl Val {
    /// Wrap a byte payload (`Vec<u8>`, `&[u8]`, `Box<[u8]>`, … — anything
    /// `Into<Arc<[u8]>>`).
    pub fn new(b: impl Into<Arc<[u8]>>) -> Val {
        Val(b.into())
    }

    /// The payload bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The payload length in bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }
}
