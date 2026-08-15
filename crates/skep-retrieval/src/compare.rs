//! §D COMPARE / SHOWRELATIONOF2VERSIONS (ASN-0122) — an interval equi-join on
//! I-address, complete under fan-out. The contract is a relational join keyed
//! on **address equality, never value** — so COMPARE never opens M4. Three
//! phases: resolve regions to blocks, interval-join on the I-axis with
//! cross-product on overlap (X8 completeness), coalesce-and-canonicalize
//! (X12 R3 determinism; R4 maximality NOT required — v1 ships the
//! finer-than-maximal per-overlap report, fully conforming under R1–R3).

use skep_address::{ordinal, shift, Address, Nat, Tumbler};
use skep_arrangement::{HasM5, M5State, VPos};
use skep_namespace::HasM3;

use crate::error::{CompareError, Operand};
use crate::helpers::{gate_vspec, require_registered, S_C};
use crate::types::{CompareReport, CorrPair, Region};
use crate::{M6World, Query};

impl<'s, W: M6World> Query<'s, W> {
    /// COMPARE (ASN-0122): two content-subspace spec-sets, each a set of
    /// `Region`s (the shared (document, span-set) idiom — ASN-0122's `ρ`);
    /// reports address-equal correspondences (X1/X2 — value-blind, NEVER
    /// opens M4), complete under fan-out (X8), in deterministic canonical
    /// order (X12 R3); in each pair, slot 1 ⇐ ρ₁ and slot 2 ⇐ ρ₂.
    ///
    /// Gate, per operand so a fault carries an unambiguous
    /// `(operand, region, span-index)`: each region's doc registered; each
    /// span starting in the content subspace (`NotContentSubspace` — the
    /// residence check runs BEFORE the well-formedness gate) and well-formed
    /// (`MalformedSpan`). A well-formed depth-incompatible span passes and
    /// resolves to an empty region (consulting-state — success, X12);
    /// overlapping/repeated windows within one operand are redundant, not
    /// wrong (⟦Γ⟧ is a set-union; duplicates collapse denotationally and the
    /// stable sort keeps the listed order deterministic).
    pub fn compare(&self, rho1: &[Region], rho2: &[Region]) -> Result<CompareReport, CompareError> {
        let w = self.0.world();
        let (m3, m5) = (w.m3(), w.m5());
        for (operand, regions) in [(Operand::First, rho1), (Operand::Second, rho2)] {
            for (ri, r) in regions.iter().enumerate() {
                if !require_registered(m3, &r.doc) {
                    return Err(CompareError::DocNotRegistered(r.doc.clone()));
                }
                for (si, span) in r.spans.iter().enumerate() {
                    if *span.start().get(1) != *S_C {
                        // Start must lie in the content subspace (Open build
                        // decision: reject loudly, the recommended default —
                        // spans that merely DENOTE link positions from a
                        // content start are always legal; resolve clips them).
                        return Err(CompareError::NotContentSubspace {
                            operand,
                            region: ri,
                            index: si,
                        });
                    }
                    gate_vspec(span).map_err(|f| CompareError::MalformedSpan {
                        operand,
                        region: ri,
                        index: si,
                        fault: f,
                    })?;
                }
            }
        }
        let (p, q) = (resolve_blocks(m5, rho1), resolve_blocks(m5, rho2)); // reads ONLY M5
        let pairs = interval_join(&p, &q); // cross-product per overlap (X8)
        Ok(CompareReport(canonicalize(pairs))) // R1–R3 conforming, deterministic (X12)
    }
}

/// Transient per-query working row for COMPARE: built by [`resolve_blocks`],
/// consumed by [`overlap_pair`]/[`interval_join`]/[`reach_i`]; dropped at
/// return. One block per resolved I-run of one region span.
struct Block {
    doc: Address,
    v_start: Tumbler,
    i_start: Address,
    width: Nat,
}

/// Resolve every region span to its I-run blocks, reconstructing each run's
/// V-start by accumulation.
///
/// V-RECONSTRUCTION LEMMA (load-bearing for X12-R1 soundness, correct ONLY
/// under D-CTG★): content is gap-free, so the FIRST bound V-position of a
/// content span IS `span.start()`, and `resolve`'s runs tile the bound prefix
/// CONTIGUOUSLY in V. Hence the V-cursor starts at `span.start()` and
/// advances by each run's width — there are no V-gaps to skip. A
/// depth-incompatible (`#start ≥ 3`) content span resolves to ⟨⟩, so produces
/// no blocks (empty region). The lemma is asserted on EVERY run — firing
/// per run (not first-run-only) localizes a future M5 density regression to
/// the EXACT mis-aligning run instead of letting a mid-document V-gap slip
/// past a first-run check and silently mis-set a later block's `v_start`.
/// (`vpos_of(&v)` is depth-2-safe each iteration — a run exists only for a
/// depth-2 span.)
fn resolve_blocks(m5: &M5State, regions: &[Region]) -> Vec<Block> {
    let mut out = Vec::new();
    for r in regions {
        for span in &r.spans {
            let mut v = span.start().clone();
            for run in m5.resolve(&r.doc, span) {
                debug_assert!(
                    m5.point(&r.doc, &vpos_of(&v)).as_ref() == Some(run.i_start()),
                    "D-CTG★: each content run must begin at the V-cursor (gap-free tiling)"
                );
                out.push(Block {
                    doc: r.doc.clone(),
                    v_start: v.clone(),
                    i_start: run.i_start().clone(),
                    width: run.width().clone(),
                });
                v = shift(&v, run.width()); // accumulate V offset by run width (no V-gaps in content)
            }
        }
    }
    out
}

// ── COMPARE helpers — ALL operate on `Tumbler` (thread `.tumbler()` off any
// `Address`) ──
//
// CO-CHAIN PRECONDITION: `overlap_pair` calls `ordinal_gap` only AFTER the
// `lo < hi` overlap guard, i.e. only on runs whose I-intervals overlap.
// Overlapping content runs lie on ONE content chain (shared origin
// sub-allocator ⇒ equal-length, equal prefix below the action point), so a
// bare ordinal subtraction is a TOTAL `Nat` op — no borrow, no underflow.
// Different-chain pairs have disjoint I-intervals and are rejected by the
// guard before any ordinal arithmetic runs.

/// `i_start ⊕ δ(width, #)`: one I-step past the run. The raw `shift` is SAFE
/// here (i_start is element-level, so the last component is the ordinal —
/// M1's TA7a safe window): a bare `Tumbler` endpoint is all the `lo < hi`
/// compare needs — no `Address` invariant is consumed (cf. `run_addr`'s
/// `ElemPos` round-trip, whose consumers ARE `Address`-typed).
fn reach_i(b: &Block) -> Tumbler {
    shift(b.i_start.tumbler(), &b.width)
}

/// Co-chain ⇒ `ordinal(hi) ≥ ordinal(lo)` — total under the precondition.
fn ordinal_gap(hi: &Tumbler, lo: &Tumbler) -> Nat {
    ordinal(hi) - ordinal(lo)
}

fn max_tumbler(a: &Tumbler, b: &Tumbler) -> Tumbler {
    if a >= b {
        a.clone()
    } else {
        b.clone()
    }
}

fn min_tumbler(a: &Tumbler, b: &Tumbler) -> Tumbler {
    if a <= b {
        a.clone()
    } else {
        b.clone()
    }
}

/// Depth-2 V-position tumbler → `VPos`.
fn vpos_of(t: &Tumbler) -> VPos {
    VPos {
        subspace: t.get(1).clone(),
        ordinal: t.get(2).clone(),
    }
}

/// Advance a depth-2 V-position's ordinal by `k`.
fn vpos_shift(v: &Tumbler, k: &Nat) -> VPos {
    VPos {
        subspace: v.get(1).clone(),
        ordinal: v.get(2).clone() + k,
    }
}

/// One correspondence per I-overlap of two blocks, or `None` when the
/// I-intervals are disjoint. THE SECOND FOOT IS COMPUTED WITHIN ITS OWN
/// BLOCK: `u2` offsets `qb.v_start` by `lo ⊖ qb.i_start` (lo's position
/// inside the Q-block), not `lo ⊖ pb.i_start` — in the normal cross-document
/// case `lo` is one operand's start, so the inter-block gap would otherwise
/// shift `u2` and make `res_Σ(d2, u2) ≠ a`, violating X12 R1 (soundness).
/// With the per-block offset, both feet resolve to the shared address `lo`.
fn overlap_pair(pb: &Block, qb: &Block) -> Option<CorrPair> {
    let lo = max_tumbler(pb.i_start.tumbler(), qb.i_start.tumbler());
    let hi = min_tumbler(&reach_i(pb), &reach_i(qb));
    if lo >= hi {
        return None; // disjoint I-intervals ⇒ no correspondence
    }
    // lo < hi now discharges the co-chain precondition: every ordinal_gap
    // below is total.
    Some(CorrPair {
        d1: pb.doc.clone(),
        u1: vpos_shift(&pb.v_start, &ordinal_gap(&lo, pb.i_start.tumbler())), // slot 1 ⇐ operand 1
        d2: qb.doc.clone(),
        u2: vpos_shift(&qb.v_start, &ordinal_gap(&lo, qb.i_start.tumbler())), // slot 2 ⇐ operand 2
        width: ordinal_gap(&hi, &lo),
    })
}

/// v1 REFERENCE IMPLEMENTATION: exhaustive O(|P|·|Q|) double-loop block join —
/// emit EVERY I-overlap (X8 fan-out completeness: an address in multiple
/// P-blocks and/or Q-blocks yields the full cross-product, never a lockstep
/// merge). Sort-by-i_start + sweep (or an interval tree) is a drop-in
/// optimization of this SAME join (same pair multiset); the independent TEST
/// ORACLE is a per-position hash join on address. One vocabulary — see the
/// design's Open build decisions (canonical statement).
fn interval_join(p: &[Block], q: &[Block]) -> Vec<CorrPair> {
    let mut out = Vec::new();
    for pb in p {
        for qb in q {
            if let Some(c) = overlap_pair(pb, qb) {
                out.push(c);
            }
        }
    }
    out
}

/// Deterministic presentation (X12 R3) of the complete+sound relation
/// (R1/R2); NOT claimed maximal (R4 optional). Sort lexicographically by
/// `(d1, u1, d2, u2)` — `sort_by_cached_key` computes each four-`Tumbler` key
/// ONCE per element (a bare `sort_by` would rebuild both keys per
/// *comparison*) and is a STABLE sort, so duplicate overlaps keep a
/// deterministic listed order (R3). The adjacent-pair fold is the IDENTITY in
/// v1 (a finer-than-maximal, per-overlap report conforms — see
/// [`fold_adjacent`]).
fn canonicalize(mut pairs: Vec<CorrPair>) -> Vec<CorrPair> {
    pairs.sort_by_cached_key(corr_key);
    fold_adjacent(pairs)
}

fn corr_key(c: &CorrPair) -> (Tumbler, Tumbler, Tumbler, Tumbler) {
    (
        c.d1.tumbler().clone(),
        vpos_tumbler(&c.u1),
        c.d2.tumbler().clone(),
        vpos_tumbler(&c.u2),
    )
}

fn vpos_tumbler(v: &VPos) -> Tumbler {
    Tumbler::new([v.subspace.clone(), v.ordinal.clone()])
        .expect("a two-component sequence is nonempty")
}

/// Adjacent-pair folding is OPTIONAL — X12 R4 (maximal pairs) is NOT
/// required, and a per-overlap, finer-than-maximal report already satisfies
/// R1–R3. v1 ships the IDENTITY (no fold); the reference is therefore
/// complete, not an unimplemented stub. A builder wanting the X11 maximal
/// form merges feet-successor-adjacent pairs here (pair₂'s two feet are the
/// unit-successors of pair₁'s last positions AND their I-addresses are
/// consecutive) into one wider pair — a pure presentation post-pass that
/// never changes ⟦Γ⟧.
fn fold_adjacent(pairs: Vec<CorrPair>) -> Vec<CorrPair> {
    pairs
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

    fn n(x: u32) -> Nat {
        Nat::from(x)
    }

    /// doc1 content element k, M3's minted shape.
    fn ca(k: u32) -> Address {
        a(&[1, 0, 1, 0, 1, 0, 1, k])
    }

    fn block(doc: &[u32], v_ord: u32, i_start: Address, width: u32) -> Block {
        Block {
            doc: a(doc),
            v_start: t(&[1, v_ord]),
            i_start,
            width: n(width),
        }
    }

    #[test]
    fn overlap_pair_computes_each_foot_within_its_own_block() {
        // X12 R1: u2 offsets qb.v_start by lo ⊖ qb.i_start — NOT by lo ⊖
        // pb.i_start — so both feet resolve to the shared address lo.
        let pb = block(&[1, 0, 1, 0, 1], 1, ca(1), 3); // [ca1, ca4) at V 1..
        let qb = block(&[1, 0, 1, 0, 2], 1, ca(2), 1); // [ca2, ca3) at V 1..
        let c = overlap_pair(&pb, &qb).expect("overlapping I-intervals correspond");
        assert_eq!(c.d1, a(&[1, 0, 1, 0, 1]));
        assert_eq!(c.u1.subspace, n(1));
        assert_eq!(c.u1.ordinal, n(2)); // lo = ca2 is offset 1 within P
        assert_eq!(c.d2, a(&[1, 0, 1, 0, 2]));
        assert_eq!(c.u2.subspace, n(1));
        assert_eq!(c.u2.ordinal, n(1)); // lo = ca2 is offset 0 within Q
        assert_eq!(c.width, n(1));
    }

    #[test]
    fn overlap_pair_rejects_disjoint_and_cross_chain_intervals() {
        // Same chain, disjoint: [ca1, ca4) vs [ca5, ca6).
        let pb = block(&[1, 0, 1, 0, 1], 1, ca(1), 3);
        let qb = block(&[1, 0, 1, 0, 2], 1, ca(5), 1);
        assert!(overlap_pair(&pb, &qb).is_none());
        // Adjacent (half-open, touching): [ca1, ca4) vs [ca4, ca5) share
        // nothing.
        let qb = block(&[1, 0, 1, 0, 2], 1, ca(4), 1);
        assert!(overlap_pair(&pb, &qb).is_none());
        // Different chains have disjoint I-intervals — the guard rejects
        // BEFORE any ordinal arithmetic runs (co-chain precondition).
        let da1 = a(&[1, 0, 1, 0, 2, 0, 1, 1]);
        let qb = block(&[1, 0, 1, 0, 2], 1, da1, 2);
        assert!(overlap_pair(&pb, &qb).is_none());
    }

    #[test]
    fn canonicalize_sorts_by_the_four_tumbler_key_and_folds_identity() {
        // X12 R3: deterministic lexicographic (d1, u1, d2, u2) order; v1's
        // fold is the identity (finer-than-maximal conforms, R4 optional).
        let mk = |u2_ord: u32| CorrPair {
            d1: a(&[1, 0, 1, 0, 1]),
            u1: vpos_of(&t(&[1, 1])),
            d2: a(&[1, 0, 1, 0, 2]),
            u2: vpos_of(&t(&[1, u2_ord])),
            width: n(1),
        };
        let got = canonicalize(vec![mk(2), mk(1)]);
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].u2.ordinal, n(1));
        assert_eq!(got[1].u2.ordinal, n(2));
    }
}
