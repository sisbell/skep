//! The ghost region (owner ruling, 2026-08-26: reserved types are in-docuverse
//! ghost tumblers; the out-of-tree 9-space is abolished). M3's half of the
//! ruling: the five addresses and the floor that keeps every mint past them;
//! what each one means is M7's.

use std::sync::LazyLock;

use num_traits::Zero;
use skep_address::{content_subspace, elem_addr, validate, Address, ElemPos, Nat, Tumbler};

use crate::ns::{content_ns, NsKey};

/// How many content addresses of [`ghost_home_document`] are the GHOST
/// REGION: the realm-global reserved type addresses M7 compiles as its format
/// constants (`ReservedAddrs::format` builds them from [`ghost_position`], so
/// the two crates cannot drift). The ruling's "positions 1–5" are ordinals on
/// the document's content CHAIN, never positions in its arrangement: once the
/// document is written, the first five positions of its arrangement hold
/// ordinary content, as any document's do. A ghost tumbler is a reserved type
/// address and nothing else — a fixed, well-known, T4-valid name at which
/// nothing exists and nothing may ever be minted.
///
/// M3 owes the allocation half of that sentence, and it is the load-bearing
/// clause of the whole ruling: dispatch is by number, so a fresh content mint
/// landing on the `retraction` value would be catastrophic. The old 9-space
/// bought non-collision by sitting outside every admissible subtree; the
/// ghost region sits INSIDE the docuverse, at the first five content
/// addresses of doc 1 of the system account `1.1.0.1`, a REAL document
/// seeded at genesis (`M3State::genesis`, PUB-6.65) whose content chain any
/// INSERT by its principal would extend — so unreachability cannot be proven
/// and an explicit allocator skip is required. The skip is `ghost_floor`;
/// the argument that it suffices is stated there.
pub const GHOST_POSITIONS: u32 = 5;

/// The ghost region's home document — doc 1 of the SYSTEM ACCOUNT `1.1.0.1`:
/// `[1,1,0,1,0,1]` (owner numbering, FINAL 2026-08-27: registry = node 1.1,
/// host = 1.2, root `[1]` abstract — the ruling's registry node is this
/// crate's [`crate::system_node`]). Account ordinal 1 under the system node
/// `1.1` is seated at genesis by `M3State::genesis` for
/// `SYSTEM_PRINCIPAL` (PUB-6.65), keyless and no operator's — at every other
/// node the first delegate receives ordinal 1 by the claim-ceremony
/// convention, which `delegate`'s next-form gate enforces — and doc 1 is
/// born at genesis beside doc 2, the head document, not minted by a ceremony.
/// Both land at their ordinary ordinals: the document is REAL, only the
/// content addresses 1..=[`GHOST_POSITIONS`] under it are ghost, and its first
/// content mint lands at ordinal [`GHOST_POSITIONS`] + 1.
pub fn ghost_home_document() -> Address {
    let comps = [1u32, 1, 0, 1, 0, 1].into_iter().map(Nat::from);
    let t = Tumbler::new(comps).expect("a six-component sequence is nonempty");
    validate(t).expect("the ghost home document 1.1.0.1.0.1 is T4-valid by construction")
}

/// Ghost tumbler `ordinal` of the region — M1's element address of
/// [`ghost_home_document`] at [`content_subspace`], at that ordinal:
/// `[1,1,0,1,0,1,0,1,ordinal]`. The one mint-shaped spelling of the five
/// reserved type addresses; M7's `ReservedAddrs::format` reads them here. The
/// document and the subspace each have exactly one spelling — the document is
/// [`ghost_home_document`]'s and the subspace is M1's — so the addresses M7
/// dispatches on and the namespace the allocator floors
/// ([`GHOST_POSITIONS`]) cannot come apart.
///
/// # Panics
///
/// Outside `1..=GHOST_POSITIONS` — the region has exactly five names, and a
/// sixth would be an ordinarily mintable content address.
pub fn ghost_position(ordinal: u32) -> Address {
    assert!(
        (1..=GHOST_POSITIONS).contains(&ordinal),
        "the ghost region is content addresses 1..={GHOST_POSITIONS} of doc 1.1.0.1.0.1"
    );
    elem_addr(ElemPos {
        doc: ghost_home_document(),
        subspace: content_subspace(),
        ordinal: Nat::from(ordinal),
    })
    .expect("ghost_home_document is Document-level; s_C ≥ 1; ordinal ≥ 1 by the assert above")
}

/// Is `key` THE ghost content namespace — `(b_C(ghost_home_document), 1)`,
/// the one namespace whose chain contains the five ghost tumblers? Decided by
/// key equality against a lazily-built constant, so the compare on every
/// other namespace fails at the first differing component and the hot paths
/// pay a short comparison.
fn is_ghost_ns(key: &NsKey) -> bool {
    static GHOST_NS: LazyLock<NsKey> = LazyLock::new(|| content_ns(&ghost_home_document()));
    *key == *GHOST_NS
}

/// The allocator skip: the frontier FLOOR of `key` — [`GHOST_POSITIONS`] for
/// the ghost content namespace, 0 for every other. Answered as a [`Nat`],
/// the frontier's own type, so the sites that compare against it just
/// compare, and the ordinary zero floor is a value rather than a case.
/// Three readers, each keeping one property. `M3State::next_in` mints past
/// `max(frontier, floor)`: non-reissue, argued below.
/// `M3State::is_chain_member` refuses ordinals at or below the floor, so
/// `is_allocated` answers false at all five ghost tumblers on every board,
/// forever, however far the chain past them has advanced. And
/// [`M3State::apply_m3`]'s contiguity check expects
/// `max(frontier, floor) + 1`, so a debug build's fold accepts the chain's
/// first `Allocate`, at [`GHOST_POSITIONS`] + 1, and fail-stops on one
/// inside the region.
///
/// NON-REISSUE, the property this floor exists for: no mint, on any board
/// running this format, ever yields a ghost tumbler. Every mint returns
/// `c_{m+1}` of the one namespace its key names, and by T4b unique-parse the
/// decomposed namespace of a ghost tumbler `[1,1,0,1,0,1,0,1,x]` is exactly
/// the ghost content namespace (a `g = 2` member would carry a separator
/// before its ordinal; every other `g = 1` family differs in subspace, tier
/// gate, or anchor) — so the ghost content chain is the ONLY chain that
/// could issue one. Every mint it serves carries the ordinal one past the
/// effective frontier, and the effective frontier is `max(stored, floor)`:
/// never below the floor whatever the stored count reads, a count regressed
/// off a corrupted checkpoint or journal included. So every such mint has an
/// ordinal above [`GHOST_POSITIONS`] on every build, resting on that MAX and
/// not on the fold's contiguity check, which is a `debug_assert`.
///
/// The floor is a compiled constant, not genesis state: genesis seeds the
/// ghost home document EMPTY, so its content chain has no frontier until a
/// first mint lands past the floor; every board agrees because the floor IS
/// the format, and a checkpoint has nothing extra to carry.
///
/// [`M3State::apply_m3`]: crate::M3State::apply_m3
pub(crate) fn ghost_floor(key: &NsKey) -> Nat {
    if is_ghost_ns(key) {
        Nat::from(GHOST_POSITIONS)
    } else {
        Nat::zero()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::ns::namespace_of;
    use skep_address::Level;

    fn t(comps: &[u32]) -> Tumbler {
        Tumbler::new(comps.iter().map(|&c| Nat::from(c))).expect("nonempty")
    }

    fn a(comps: &[u32]) -> Address {
        validate(t(comps)).expect("T4-valid")
    }

    /// The two halves of non-reissue meet: every address M7 dispatches on is a
    /// member of the ONE chain the allocator floors. `ghost_position` names the
    /// five and `ghost_floor` skips a namespace; nothing else ties them, so
    /// this asserts the tie directly rather than through the `is_allocated`
    /// consequence the integration suite checks.
    #[test]
    fn every_ghost_position_sits_in_the_namespace_the_floor_skips() {
        let ghost_ns = content_ns(&ghost_home_document());
        assert_eq!(ghost_floor(&ghost_ns), Nat::from(GHOST_POSITIONS));
        for ordinal in 1..=GHOST_POSITIONS {
            let position = ghost_position(ordinal);
            assert_eq!(
                namespace_of(&position),
                Some(ghost_ns.clone()),
                "ghost {ordinal} is not in the floored namespace"
            );
            // M1's reader, spelled whole: the loop variable is the ordinal
            // this address is supposed to carry.
            assert_eq!(
                *skep_address::ordinal(position.tumbler()),
                Nat::from(ordinal)
            );
            assert_eq!(position.level(), Level::Element);
            assert_eq!(position.subspace(), Some(&content_subspace()));
        }
        // The floor is exactly five content addresses of ONE document: a
        // sibling doc's content chain carries none.
        assert_eq!(
            ghost_floor(&content_ns(&a(&[1, 1, 0, 1, 0, 2]))),
            Nat::zero()
        );
    }
}
