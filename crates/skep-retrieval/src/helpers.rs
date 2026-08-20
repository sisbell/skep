//! §Internal design — the shared helpers every operation composes: the
//! registry gate, the VSpec well-formedness gate, run-address enumeration,
//! Tumbler-keyed dedup-and-sort, and the CURRENT(·, d) content enumeration.

use std::collections::HashSet;

use num_traits::{One, Zero};
use once_cell::sync::Lazy;
use skep_address::{
    action_point, document_of, elem_addr, ordinal, shift_ordinal, zeros, Address, ElemPos, Nat,
    Span, Tumbler,
};
use skep_arrangement::{M5State, VPos};
use skep_namespace::M3State;

use crate::error::SpecFault;

// Content (s_C = 1) / link (s_L = 2) subspace constants (ASN-0047).
// `Nat = BigUint` cannot be `const`, so each is memoized ONCE via
// `once_cell::sync::Lazy` instead of re-allocating a fresh `BigUint` on every
// reference. The hot per-position loop (`retrieve_v`) only COMPARES against
// them — `*sub == *S_C` is a by-reference compare with no allocation — while
// the O(1)-per-query construction sites clone via `(*S_C).clone()`.

/// `s_C` = 1 — the content-subspace numeral (ASN-0047; M1's T7 convention).
pub(crate) static S_C: Lazy<Nat> = Lazy::new(|| Nat::from(1u8));

/// `s_L` = 2 — the link-subspace numeral (ASN-0047; M1's T7 convention).
pub(crate) static S_L: Lazy<Nat> = Lazy::new(|| Nat::from(2u8));

/// The universal allocation gate: M3 supplies the bool; converting
/// registered-but-empty → the op's empty form and unregistered → the op's
/// typed failure is M6's owned distinction (decomposition; W-pre 0112/0113).
pub(crate) fn require_registered(m3: &M3State, d: &Address) -> bool {
    m3.is_registered_document(d)
}

/// VSpec WELL-FORMEDNESS only (ASN-0115): zero-free, ordinal-level,
/// level-uniform, depth `#start ≥ 2`. It deliberately does NOT gate
/// depth-COMPATIBILITY (`#start == 2`): ASN-0115 is explicit that
/// depth-compatibility is a consulting-state predicate, NOT a
/// well-formedness condition, so a well-formed `#start ≥ 3` span passes here
/// and resolves to ⟨⟩ downstream (R6 silent-empty; SHOWORIGIN_V alone
/// rejects it, as its own WF_V(v) precondition).
pub(crate) fn gate_vspec(span: &Span) -> Result<(), SpecFault> {
    if !span.is_level_uniform() {
        return Err(SpecFault::NotLevelUniform); // #start == #width
    }
    if action_point(span.width()) != Some(span.width().len()) {
        return Err(SpecFault::NotOrdinalLevel); // width acts at deepest
    }
    if zeros(span.start()) != 0 {
        return Err(SpecFault::StartNotZeroFree); // ⇒ all components > 0
    }
    if span.start().len() < 2 {
        return Err(SpecFault::StartTooShallow); // ASN-0115 WF: #start ≥ 2
    }
    Ok(())
}

/// k-th address of a run. LOAD-BEARING ASSUMPTION (used directly here by
/// RETRIEVEV and SHOWDELETIONS, and mirrored by the element-level I-address
/// arithmetic in SHOWORIGIN_V and COMPARE): every content/link I-address has
/// a 2-COMPONENT element field `[subspace, ordinal]` (zeros = 3), as M3 mints
/// them. `ElemPos` models exactly that 2-component field, so reconstructing
/// i_start as `ElemPos { doc, subspace, ordinal }` and advancing the ordinal
/// is faithful and dodges the raw-shift subspace-crossing footgun (M1 TA7a)
/// — but a LONGER element field would be silently truncated here, so a debug
/// tripwire fails loudly if one ever arrives (M3 makes it unreachable — a
/// guard, not a path).
///
/// WHY THE ElemPos ROUND-TRIP, NOT A RAW `shift`: `run_addr` returns a
/// validated **`Address`** (not the bare `Tumbler` a raw `shift` would give)
/// because two of its consumers are `Address`-typed and cannot take a
/// `Tumbler` — `DeliveryItem::Ref(Address)` (RETRIEVEV link references) and
/// [`dedup_addrs`] (SHOWDELETIONS); the others (`value_at`/`denotes`) read
/// `.tumbler()`, but the `Ref`/dedup paths fix the return type. Do NOT
/// "simplify" this to a raw shift. COMPARE's `reach_i` *does* raw-`shift` an
/// identical element-level i_start — deliberately — because it needs only a
/// `Tumbler` endpoint for the half-open I-interval compare, where no
/// `Address` invariant is consumed. Same i_start shape, two different lifts,
/// because the consumers differ.
pub(crate) fn run_addr(i_start: &Address, k: &Nat) -> Address {
    debug_assert!(
        i_start.element_field().is_some_and(|e| e.len() == 2),
        "run_addr: I-address must carry a 2-component element field [subspace, ordinal] \
         (else silent truncation)"
    );
    let p = ElemPos {
        doc: document_of(i_start).expect("an element-level I-address has a Document prefix"),
        subspace: i_start
            .subspace()
            .expect("an element-level I-address has a subspace component")
            .clone(),
        ordinal: ordinal(i_start.tumbler()).clone(),
    };
    elem_addr(shift_ordinal(p, k))
        .expect("ordinal-shifting a valid element position stays T4-valid")
}

/// Dedup a stream of addresses by their `Tumbler` and return them T1-sorted
/// (first-insert-wins; the Tumbler carries the order). Used for origin
/// DOCUMENTS (SHOWORIGIN_V) and content I-ADDRESSES (SHOWDELETIONS) alike —
/// both are `Address`, so one neutral helper serves either (the name says
/// "addrs", not "docs", because at the SHOWDELETIONS site the deduped
/// elements are content addresses, not documents).
pub(crate) fn dedup_addrs(it: impl Iterator<Item = Address>) -> Vec<Address> {
    let mut seen: HashSet<Tumbler> = HashSet::new();
    let mut out: Vec<Address> = it.filter(|a| seen.insert(a.tumbler().clone())).collect();
    out.sort_by(|a, b| a.tumbler().cmp(b.tumbler())); // T1 order
    out
}

/// D-CTG★ defense-in-depth for the extent queries (open build decision,
/// documented default: trust `content_count`/`link_count` in release, assert
/// in debug). The counts M6 treats AS extents are honest only under the
/// dense-slice occupancy ASN-0113 W4 proves — each subspace's run widths sum
/// to its count, and an occupied subspace anchors at ordinal 1 (ASN-0112 V8
/// origin permanence; append-only link seating). The whole body is compiled
/// out of release builds, which read the counts directly.
pub(crate) fn debug_assert_dense_occupancy(m5: &M5State, doc: &Address) {
    if cfg!(debug_assertions) {
        for (sub, count, runs) in [
            (&*S_C, m5.content_count(doc), m5.content_runs(doc)),
            (&*S_L, m5.link_count(doc), m5.link_runs(doc)),
        ] {
            let width_sum = runs.iter().fold(Nat::zero(), |acc, r| acc + r.width());
            debug_assert!(
                width_sum == count,
                "D-CTG★: a subspace's run widths must sum to its count"
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
                "D-CTG★: an occupied subspace must anchor at ordinal 1"
            );
        }
    }
}

/// CURRENT(·, d) on the content side — every content I-address d's
/// arrangement currently binds (the math `content_image(d)`, realized in M6
/// by enumerating M5's V-ordered content runs per-position, exactly as
/// RETRIEVEV does; M5's own `content_image` is private and is NOT called
/// here). May repeat an address under intra-doc transclusion — callers dedup.
pub(crate) fn arranged_content(m5: &M5State, d: &Address) -> Vec<Address> {
    let mut out = Vec::new();
    let one = Nat::one();
    for run in m5.content_runs(d) {
        let mut k = Nat::zero();
        while &k < run.width() {
            out.push(run_addr(run.i_start(), &k));
            k = &k + &one;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use skep_address::validate;

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
    fn gate_vspec_admits_wellformed_spans_of_any_depth_at_least_2() {
        // ASN-0115 WF admits #start ≥ 2; a #start ≥ 3 span is well-formed
        // (depth-COMPATIBILITY is consulting-state, gated elsewhere).
        assert!(gate_vspec(&span(&[1, 1], &[0, 3])).is_ok());
        assert!(gate_vspec(&span(&[2, 1], &[0, 1])).is_ok());
        assert!(gate_vspec(&span(&[1, 1, 1], &[0, 0, 1])).is_ok());
        // A foreign start subspace is not a WELL-FORMEDNESS matter either.
        assert!(gate_vspec(&span(&[3, 1], &[0, 1])).is_ok());
    }

    #[test]
    fn gate_vspec_rejects_each_fault_in_documented_order() {
        // Level-uniformity is checked before ordinal-level: a [1]-width on a
        // depth-2 start fails BOTH, and NotLevelUniform wins.
        assert_eq!(
            gate_vspec(&span(&[1, 1], &[1])),
            Err(SpecFault::NotLevelUniform)
        );
        // Level-uniform but action point 1 ≠ 2: not ordinal-level.
        assert_eq!(
            gate_vspec(&span(&[1, 1], &[1, 0])),
            Err(SpecFault::NotOrdinalLevel)
        );
        // Ordinal-level and uniform, but the start carries a separator.
        assert_eq!(
            gate_vspec(&span(&[1, 0, 1], &[0, 0, 1])),
            Err(SpecFault::StartNotZeroFree)
        );
        // Everything else passes, but #start = 1 < 2.
        assert_eq!(
            gate_vspec(&span(&[5], &[1])),
            Err(SpecFault::StartTooShallow)
        );
    }

    #[test]
    fn run_addr_advances_the_ordinal_only() {
        // The k-th address of a run keeps doc & subspace, bumps the ordinal —
        // never the raw-shift subspace-crossing form (M1 TA7a).
        let ca1 = a(&[1, 0, 1, 0, 1, 0, 1, 1]);
        assert_eq!(run_addr(&ca1, &Nat::from(0u8)), ca1);
        assert_eq!(run_addr(&ca1, &Nat::from(2u8)), a(&[1, 0, 1, 0, 1, 0, 1, 3]));
        let la1 = a(&[1, 0, 1, 0, 1, 0, 2, 1]);
        assert_eq!(run_addr(&la1, &Nat::from(1u8)), a(&[1, 0, 1, 0, 1, 0, 2, 2]));
    }

    #[test]
    fn dedup_addrs_dedups_by_tumbler_and_sorts_in_t1_order() {
        let d2 = a(&[1, 0, 1, 0, 2]);
        let d1 = a(&[1, 0, 1, 0, 1]);
        let got = dedup_addrs(vec![d2.clone(), d1.clone(), d2.clone(), d1.clone()].into_iter());
        assert_eq!(got, vec![d1, d2]);
        assert!(dedup_addrs(std::iter::empty()).is_empty());
    }
}
