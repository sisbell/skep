//! The minimal engine assembly the suites run on, and the helpers they
//! share. The toy `World`/`Rec` pair is what the composition contract
//! prescribes: `HasContent` read accessor, the `From<ContentWrite>` and
//! `From<ContentStretch>` record lifts, `apply` dispatching into
//! `ContentStore::apply_write` and `ContentStore::apply_stretch`.

use std::path::Path;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use skep_address::{validate, Address, Nat, Tumbler};
use skep_content::{ContentStore, ContentStretch, ContentWrite, HasContent, Piece, Val};
use skep_kernel::{
    BurnedSeqPolicy, CheckpointPolicy, Durability, Kernel, KernelConfig, SaltSource, TxnError,
    WorldState,
};

// ---- the minimal engine assembly (composition contract) ----

#[derive(Clone, Serialize, Deserialize)]
pub struct World {
    content: ContentStore,
}

#[derive(Clone, Serialize, Deserialize)]
pub enum Rec {
    Write(ContentWrite),
    Stretch(ContentStretch),
}

impl From<ContentWrite> for Rec {
    fn from(r: ContentWrite) -> Rec {
        Rec::Write(r)
    }
}

impl From<ContentStretch> for Rec {
    fn from(r: ContentStretch) -> Rec {
        Rec::Stretch(r)
    }
}

impl HasContent for World {
    fn content(&self) -> &ContentStore {
        &self.content
    }
}

impl WorldState for World {
    type Record = Rec;
    fn apply(&self, r: &Rec) -> World {
        World {
            content: match r {
                Rec::Write(x) => self.content.apply_write(x),
                Rec::Stretch(x) => self.content.apply_stretch(x),
            },
        }
    }
}

// ---- helpers ----
//
// A helper that checks what its caller handed it — a literal that must be
// a tumbler or a T4-valid address, an outcome that must be a rejection —
// is `#[track_caller]`, as the library's two write doors are, so its
// panic is reported at the test's line, never at this file's.

#[track_caller]
pub fn t(comps: &[u32]) -> Tumbler {
    Tumbler::new(comps.iter().map(|&c| Nat::from(c))).expect("test tumblers are nonempty")
}

#[track_caller]
pub fn a(comps: &[u32]) -> Address {
    validate(t(comps)).expect("test addresses are T4-valid")
}

/// A content element address in M3's minted shape: doc `[1,0,1,0,1]`,
/// element field `[s_C = 1, ordinal]`.
#[track_caller]
pub fn ca(ordinal: u32) -> Address {
    a(&[1, 0, 1, 0, 1, 0, 1, ordinal])
}

/// One T4-valid address of each shape the routing assertion stops in a debug
/// build — each level short of an element, and an element in a subspace other
/// than content's — with the name a failure reports it by. Two tests read it:
/// store.rs's release staging test stages each as given, and recovery.rs's
/// decode test admits each, so the shapes one door takes and the other admits
/// cannot part.
pub const MIS_ROUTED: &[(&str, &[u32])] = &[
    ("a node address", &[1]),
    ("an account address", &[1, 0, 1]),
    ("a document address", &[1, 0, 1, 0, 1]),
    ("a link-subspace element address", &[1, 0, 1, 0, 1, 0, 2, 1]),
    ("a subspace-3 element address", &[1, 0, 1, 0, 1, 0, 3, 1]),
];

pub fn val(b: &[u8]) -> Val {
    Val::new(b)
}

/// A stretch's bytes as `stage_stretch` and `write_stretch` take them.
pub fn bytes(b: &[u8]) -> Arc<[u8]> {
    Arc::from(b)
}

/// The bytes a point read answers — a value's, or the one byte inside a
/// stretch — so a test reads `value_at` without naming the piece's arm.
pub fn read(c: &ContentStore, at: &Tumbler) -> Option<Vec<u8>> {
    c.value_at(at).map(|piece| piece.as_bytes().to_vec())
}

/// The arm and the bytes a point read answers, for a test that pins which
/// kind of entry answered: `Some((true, bytes))` for a byte inside a stretch,
/// `Some((false, bytes))` for a value.
pub fn read_arm(c: &ContentStore, at: &Tumbler) -> Option<(bool, Vec<u8>)> {
    c.value_at(at).map(|piece| match piece {
        Piece::Bytes(b) => (true, b.to_vec()),
        Piece::Value(v) => (false, v.as_bytes().to_vec()),
    })
}

/// The pieces of `[start, start ⊕ width)` as `(is_bytes, bytes)` pairs, and
/// whether the window was covered — the walk by `by_ref()`, then `covered`.
pub fn pieces_of(c: &ContentStore, start: &Tumbler, width: u32) -> (Vec<(bool, Vec<u8>)>, bool) {
    let mut walk = c.pieces(start, &Nat::from(width));
    let parts: Vec<(bool, Vec<u8>)> = walk
        .by_ref()
        .map(|piece| match piece {
            Piece::Bytes(b) => (true, b.to_vec()),
            Piece::Value(v) => (false, v.as_bytes().to_vec()),
        })
        .collect();
    (parts, walk.covered())
}

pub fn genesis() -> World {
    World {
        content: ContentStore::default(),
    }
}

pub fn mem_kernel() -> Kernel<World> {
    let cfg = KernelConfig {
        durability: Durability::InMemory,
        checkpoint: CheckpointPolicy::Manual,
        salt: SaltSource::Seeded(0),
    };
    Kernel::open(cfg, genesis()).expect("in-memory open")
}

pub fn cfg_fsync(dir: &Path) -> KernelConfig {
    KernelConfig {
        durability: Durability::Fsync {
            journal_path: dir.to_path_buf(),
            retain_checkpoints: 1,
            burned_seq: BurnedSeqPolicy::Rollback,
            cut_damaged_tail: false,
        },
        checkpoint: CheckpointPolicy::Manual,
        salt: SaltSource::Seeded(0),
    }
}

/// Unwrap an op's typed rejection (`TxnError::Rejected(E)` — surfaced
/// verbatim, per M2's transact contract).
#[track_caller]
pub fn rejected<T: std::fmt::Debug, E: std::fmt::Debug>(r: Result<T, TxnError<E>>) -> E {
    match r {
        Err(TxnError::Rejected(e)) => e,
        other => panic!("expected TxnError::Rejected, got {other:?}"),
    }
}
