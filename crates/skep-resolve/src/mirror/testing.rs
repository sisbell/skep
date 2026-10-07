//! What the mirror's tests share: the hint they are scoped to, a key, and a
//! mirror over a board the test holds fixed, with that board's answers.

use std::path::Path;

use serde_json::{json, Value};
use skep_identity::{Fingerprint, PublicKey};
use skep_signature::{HybridSigner, TAG_MLDSA65_ED25519};

use super::Mirror;
use crate::board::Board;
use crate::hint::RootHint;
use crate::http::{Transport, TransportError};
use crate::origin::Origin;

/// The tag-1 hybrid key whose seed is the byte `seed`, thirty-two times.
pub(super) fn key(seed: u8) -> PublicKey {
    HybridSigner::from_seed(TAG_MLDSA65_ED25519, &[seed; 32]).expect("tag 1").public_key().clone()
}

/// The hint every mirror below is opened or rebuilt under: one origin, at a
/// port no board answers, and the genesis fingerprint `ab`×32 the copies the
/// tests write name.
pub(super) fn hint() -> RootHint {
    let genesis = Fingerprint::parse_hex(&"ab".repeat(32)).unwrap();
    RootHint::new(vec![Origin::parse("http://127.0.0.1:1").unwrap()], genesis, None).unwrap()
}

/// A mirror over `board` under `dir`, at no root: every read a pull, a fold
/// or a fetch makes, the board alone answers.
pub(super) fn over(board: impl Transport + 'static, dir: &Path) -> Mirror {
    Mirror::fresh(&hint(), None, Some(Board::new(Box::new(board))), dir)
}

/// A 200 answer of `v`.
pub(super) fn answer(v: Value) -> Result<(u16, Vec<u8>), TransportError> {
    Ok((200, v.to_string().into_bytes()))
}

/// A span over one address as `read_link` answers a slot.
pub(super) fn span(start: &str) -> Value {
    json!({ "start": start, "width": "0.1" })
}

/// A `key_set` answer: `k` alone, the table as of `as_of`.
pub(super) fn table(k: &PublicKey, as_of: u64) -> Value {
    json!({ "resp": "key_set", "as_of": as_of, "enrolled": [{ "alg": k.alg(), "key": k.to_hex(), "anchor": true }] })
}
