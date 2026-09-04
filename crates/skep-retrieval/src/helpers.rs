//! §Internal design — what every operation shares: the request-span
//! well-formedness gate, the subspace numerals and the classifier that reads
//! them, answer presentation (dedup-and-sort in T1 order), and the D-SEQ★
//! occupancy tripwire the extent queries stand on.

use std::sync::LazyLock;

use num_traits::{One, Zero};
use skep_address::{action_point, content_subspace, link_subspace, zeros, Address, Nat, Span};
use skep_arrangement::{M5State, VPos};

use crate::error::SpanFault;

// Content (s_C) / link (s_L) subspace numerals. M1 owns T7 and names them
// ([`content_subspace`]/[`link_subspace`]); M6 memoizes what M1 names, because
// `Nat = BigUint` cannot be `const` and a bare call would re-allocate a fresh
// `BigUint` on every reference. [`subspace_of`] only COMPARES against them —
// by reference, with no allocation — while the O(1)-per-query construction
// sites clone.

/// `s_C` = M1's content-subspace numeral (ASN-0047; T7 convention).
pub(crate) static S_C: LazyLock<Nat> = LazyLock::new(content_subspace);

/// `s_L` = M1's link-subspace numeral (ASN-0047; T7 convention).
pub(crate) static S_L: LazyLock<Nat> = LazyLock::new(link_subspace);

/// Which of a document's two subspaces (T7; ASN-0047) a numeral names, or
/// `None` for a foreign one. `Nat` cannot appear in a pattern, so this is the
/// ONE place the two comparisons are written: every site that must tell
/// content from link matches on the answer instead of re-deriving the chain
/// and carrying its own fall-through.
///
/// `pub(crate)`, because M1 owns T7 and a second published subspace
/// vocabulary is exactly what memoizing M1's numerals avoids.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Subspace {
    Content,
    Link,
}

/// Classify a start subspace numeral (see [`Subspace`]).
pub(crate) fn subspace_of(s: &Nat) -> Option<Subspace> {
    if *s == *S_C {
        Some(Subspace::Content)
    } else if *s == *S_L {
        Some(Subspace::Link)
    } else {
        None
    }
}

/// The SPAN half of ASN-0115's V-spec well-formedness: zero-free,
/// ordinal-level, level-uniform, depth `#start ≥ 2`. A V-spec is the pair
/// `ρ = (d, σ)`, so the other half — that `d` is a registered document — is
/// the per-operation registry gate, which raises its own typed rejection.
///
/// It deliberately does NOT gate depth-COMPATIBILITY (`#start == 2`):
/// ASN-0115 is explicit that depth-compatibility is a consulting-state
/// predicate, NOT a well-formedness condition, so a well-formed `#start ≥ 3`
/// span passes here and resolves to ⟨⟩ downstream (R6 silent-empty;
/// SHOWORIGIN_V alone rejects it, as its own WF_V(v) precondition).
pub(crate) fn gate_vspan(span: &Span) -> Result<(), SpanFault> {
    if !span.is_level_uniform() {
        return Err(SpanFault::NotLevelUniform); // #start == #width
    }
    if action_point(span.width()) != Some(span.width().len()) {
        return Err(SpanFault::NotOrdinalLevel); // width acts at deepest
    }
    if zeros(span.start()) != 0 {
        return Err(SpanFault::StartNotZeroFree); // ⇒ all components > 0
    }
    if span.start().len() < 2 {
        return Err(SpanFault::StartTooShallow); // ASN-0115 WF: #start ≥ 2
    }
    Ok(())
}

/// A stream of addresses as the deduplicated, T1-SORTED set it denotes. Both
/// halves are published guarantees, not conveniences: SHOWORIGIN_V answers
/// "deduplicated origin documents in tumbler order" and SHOWDELETIONS' halves
/// are each "the deduped, Tumbler-ordered set" (D-ORD), and this is the one
/// place either is established.
///
/// Identity and order are both `Address`'s own — its `Eq` is tumbler equality
/// (the level is a function of the tumbler) and its `Ord` IS the T1 tumbler
/// order — so sorting and deduplicating is exactly dedup-by-tumbler, with no
/// `.tumbler()` detour and no key clone.
///
/// Used for origin DOCUMENTS (SHOWORIGIN_V) and content I-ADDRESSES
/// (SHOWDELETIONS) alike — both are `Address`, so one neutral helper serves
/// either (the name says "addr", not "doc", because at the SHOWDELETIONS site
/// the deduped elements are content addresses, not documents).
pub(crate) fn sorted_addr_set(it: impl IntoIterator<Item = Address>) -> Vec<Address> {
    let mut out: Vec<Address> = it.into_iter().collect();
    out.sort_unstable(); // T1 order; the dedup below makes stability unobservable
    out.dedup();
    out
}

/// D-SEQ★ defense-in-depth for the extent queries (open build decision,
/// documented default: trust `content_count`/`link_count` in release, assert
/// in debug).
///
/// D-SEQ★ (PerSubspaceSequentialPositions, ASN-0047) is the invariant the
/// counts stand on: an occupied subspace's V-positions are exactly the dense,
/// origin-anchored prefix `V_S(d) = {[S, k] : 1 ≤ k ≤ n_S}` — which is what
/// ASN-0113 W4 forces, and which ASN-0047 derives from contiguity D-CTG★ plus
/// minimum-position D-MIN★. Its two ingredients are what the two assertions
/// check: each subspace's run widths sum to its count (density — a hole would
/// make the count over-report the extent), and an occupied subspace anchors
/// at ordinal 1 (D-MIN★ itself; ASN-0112 V8 origin permanence, append-only
/// link seating). The whole body is compiled out of release builds, which
/// read the counts directly.
pub(crate) fn debug_assert_sequential_positions(m5: &M5State, doc: &Address) {
    if cfg!(debug_assertions) {
        for (sub, count, runs) in [
            (&*S_C, m5.content_count(doc), m5.content_runs(doc)),
            (&*S_L, m5.link_count(doc), m5.link_runs(doc)),
        ] {
            let width_sum = runs.iter().fold(Nat::zero(), |acc, r| acc + r.width());
            debug_assert!(
                width_sum == count,
                "D-SEQ★: a subspace's run widths must sum to its count"
            );
            debug_assert!(
                count.is_zero()
                    || m5
                        .point(
                            doc,
                            &VPos {
                                subspace: sub.clone(),
                                ordinal: Nat::one(),
                            },
                        )
                        .is_some(),
                "D-MIN★: an occupied subspace must anchor at ordinal 1"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use skep_address::{validate, Tumbler};

    fn t(comps: &[u32]) -> Tumbler {
        Tumbler::new(comps.iter().map(|&c| Nat::from(c))).expect("test tumblers are nonempty")
    }

    fn a(comps: &[u32]) -> Address {
        validate(t(comps)).expect("test addresses are T4-valid")
    }

    fn span(start: &[u32], width: &[u32]) -> Span {
        Span::new(t(start), t(width)).expect("test spans are T12-valid")
    }

    #[test]
    fn the_subspace_numerals_are_m1s() {
        // M1 owns T7, so the numeral that decides content-from-link is read
        // from M1 and memoized here, never restated.
        assert_eq!(*S_C, content_subspace());
        assert_eq!(*S_L, link_subspace());
    }

    #[test]
    fn subspace_of_classifies_the_two_real_subspaces_and_refuses_the_rest() {
        // The one place content-from-link is decided: every operation matches
        // on this answer rather than re-deriving the comparison chain.
        assert_eq!(subspace_of(&content_subspace()), Some(Subspace::Content));
        assert_eq!(subspace_of(&link_subspace()), Some(Subspace::Link));
        assert_eq!(subspace_of(&Nat::from(3u32)), None);
        assert_eq!(subspace_of(&Nat::zero()), None);
    }

    #[test]
    fn gate_vspan_admits_wellformed_spans_of_any_depth_at_least_2() {
        // ASN-0115 WF admits #start ≥ 2; a #start ≥ 3 span is well-formed
        // (depth-COMPATIBILITY is consulting-state, gated elsewhere).
        assert!(gate_vspan(&span(&[1, 1], &[0, 3])).is_ok());
        assert!(gate_vspan(&span(&[2, 1], &[0, 1])).is_ok());
        assert!(gate_vspan(&span(&[1, 1, 1], &[0, 0, 1])).is_ok());
        // A foreign start subspace is not a WELL-FORMEDNESS matter either.
        assert!(gate_vspan(&span(&[3, 1], &[0, 1])).is_ok());
    }

    #[test]
    fn gate_vspan_rejects_each_fault_in_documented_order() {
        // Level-uniformity is checked before ordinal-level: a [1]-width on a
        // depth-2 start fails BOTH, and NotLevelUniform wins.
        assert_eq!(
            gate_vspan(&span(&[1, 1], &[1])),
            Err(SpanFault::NotLevelUniform)
        );
        // Level-uniform but action point 1 ≠ 2: not ordinal-level.
        assert_eq!(
            gate_vspan(&span(&[1, 1], &[1, 0])),
            Err(SpanFault::NotOrdinalLevel)
        );
        // Ordinal-level and uniform, but the start carries a separator.
        assert_eq!(
            gate_vspan(&span(&[1, 0, 1], &[0, 0, 1])),
            Err(SpanFault::StartNotZeroFree)
        );
        // Everything else passes, but #start = 1 < 2.
        assert_eq!(
            gate_vspan(&span(&[5], &[1])),
            Err(SpanFault::StartTooShallow)
        );
    }

    #[test]
    fn sorted_addr_set_is_deduped_and_t1_ordered() {
        let d2 = a(&[1, 0, 1, 0, 2]);
        let d1 = a(&[1, 0, 1, 0, 1]);
        let got = sorted_addr_set(vec![d2.clone(), d1.clone(), d2.clone(), d1.clone()]);
        assert_eq!(got, vec![d1, d2]);
        assert!(sorted_addr_set(std::iter::empty()).is_empty());
    }
}
