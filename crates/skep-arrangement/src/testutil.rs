//! In-crate test fixtures. Addresses follow M3's minted shapes: account
//! `[1,0,1]`, documents `[1,0,1,0,d]`, content elements `[doc·0·s_C·k]`
//! (length 8), the version fork `doc·1` whose content elements are length 9 —
//! the mixed-length transclusion case the level-class discipline exists for.

use skep_address::{validate, Address, Nat, Span, Tumbler};
use skep_namespace::{M3Rec, M3State, PrincipalId};

use crate::error::VPos;
use crate::run::Run;

pub(crate) fn t(comps: &[u32]) -> Tumbler {
    Tumbler::new(comps.iter().map(|&c| Nat::from(c))).expect("test tumblers are nonempty")
}

pub(crate) fn a(comps: &[u32]) -> Address {
    validate(t(comps)).expect("test addresses are T4-valid")
}

pub(crate) fn n(x: u32) -> Nat {
    Nat::from(x)
}

/// Document 1: `[1,0,1,0,1]`.
pub(crate) fn doc1() -> Address {
    a(&[1, 0, 1, 0, 1])
}

/// Document 2: `[1,0,1,0,2]`.
pub(crate) fn doc2() -> Address {
    a(&[1, 0, 1, 0, 2])
}

/// The first version fork of doc1 on M3's `(d_src, 1)` chain: `[1,0,1,0,1,1]`.
pub(crate) fn vdoc() -> Address {
    a(&[1, 0, 1, 0, 1, 1])
}

/// doc1 content element `k` (length 8): `[1,0,1,0,1,0,1,k]`.
pub(crate) fn ca(ordinal: u32) -> Address {
    a(&[1, 0, 1, 0, 1, 0, 1, ordinal])
}

/// doc1 link element `k` (length 8): `[1,0,1,0,1,0,2,k]`.
pub(crate) fn la(ordinal: u32) -> Address {
    a(&[1, 0, 1, 0, 1, 0, 2, ordinal])
}

/// vdoc content element `k` (length 9): `[1,0,1,0,1,1,0,1,k]` — a different
/// level class than [`ca`].
pub(crate) fn vca(ordinal: u32) -> Address {
    a(&[1, 0, 1, 0, 1, 1, 0, 1, ordinal])
}

/// An in-crate `Run` literal (fields are crate-private; tests uphold the
/// standing invariants: element-level start, width ≥ 1).
pub(crate) fn run(start: &Address, width: u32) -> Run {
    Run {
        i_start: start.clone(),
        width: n(width),
    }
}

/// An ordinal-level depth-2 V-span `[subspace, ordinal]` × `[0, count]`.
pub(crate) fn vspan(subspace: u32, ordinal: u32, count: u32) -> Span {
    Span::new(t(&[subspace, ordinal]), t(&[0, count])).expect("ordinal-level V-span is T12-valid")
}

/// A depth-2 V-position.
pub(crate) fn vp(subspace: u32, ordinal: u32) -> VPos {
    VPos {
        subspace: n(subspace),
        ordinal: n(ordinal),
    }
}

/// An M3 slice with two principal-owned accounts and two registered
/// documents, built by folding exactly the records M3's own `delegate` /
/// `create_new_document` would stage: account `[1,0,1]` → principal 1 (owns
/// doc1, doc2), account `[1,0,2]` → principal 2.
pub(crate) fn seeded_m3() -> M3State {
    M3State::genesis()
        .apply_m3(&M3Rec::Allocate { addr: a(&[1, 0, 1]) })
        .apply_m3(&M3Rec::RegisterPrincipal {
            prefix: a(&[1, 0, 1]),
            id: PrincipalId(1),
        })
        .apply_m3(&M3Rec::Allocate { addr: a(&[1, 0, 2]) })
        .apply_m3(&M3Rec::RegisterPrincipal {
            prefix: a(&[1, 0, 2]),
            id: PrincipalId(2),
        })
        .apply_m3(&M3Rec::Allocate {
            addr: a(&[1, 0, 1, 0, 1]),
        })
        .apply_m3(&M3Rec::Allocate {
            addr: a(&[1, 0, 1, 0, 2]),
        })
}
