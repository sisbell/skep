//! §D COMPARE / SHOWRELATIONOF2VERSIONS (ASN-0122) — an interval equi-join on
//! I-address, complete under fan-out. The contract is a relational join keyed
//! on **address equality, never value** — so COMPARE never opens M4. Three
//! phases: resolve each spec-set to the blocks of its region, interval-join on
//! the I-axis with cross-product on overlap (X8 completeness), sort into one
//! deterministic presentation (X12 R3; R4's canonical maximal form NOT
//! required — v1 ships the finer-than-maximal per-overlap report, fully
//! conforming under R1–R3).

use skep_address::{ordinal, Address, Nat, Tumbler};
use skep_arrangement::{M5State, Run, VPos};

use crate::error::{CompareError, Operand};
use crate::helpers::{gate_vspan, S_C};
use crate::types::{CompareReport, CorrPair, RegionSpec};
use crate::{M6World, Query};

impl<'s, W: M6World> Query<'s, W> {
    /// COMPARE (ASN-0122): two content-subspace spec-sets `ρ₁, ρ₂`, each a set
    /// of [`RegionSpec`]s — ASN-0122's `(dᵢ, Sᵢ)`; reports address-equal
    /// correspondences (X1/X2 — value-blind, NEVER opens M4), complete under
    /// fan-out (X8), in one deterministic presentation (X12 R3); in each pair,
    /// slot 1 ⇐ ρ₁ and slot 2 ⇐ ρ₂.
    ///
    /// A spec-set denotes its region `R_Σ(ρᵢ)` — each span clipped against the
    /// document's current content arrangement — and that region is what
    /// [`resolve_blocks`] hands back as the block list `p`/`q`. Every reported
    /// pair is confined to those two regions (X12 R1), and a span that clips
    /// to nothing contributes to neither.
    ///
    /// Gate, per operand so a span fault carries an unambiguous
    /// `(operand, region, span-index)`: each spec's doc registered; each span
    /// starting in the content subspace (`NotContentSubspace` — the residence
    /// check runs BEFORE the well-formedness gate) and well-formed
    /// (`MalformedSpan`). A well-formed depth-incompatible span passes and
    /// contributes nothing to its region (consulting-state — success, X12);
    /// overlapping/repeated windows within one operand are redundant, not
    /// wrong (⟦Γ⟧ is a set-union; duplicates collapse denotationally and the
    /// stable sort keeps the listed order deterministic).
    pub fn compare(
        &self,
        rho1: &[RegionSpec],
        rho2: &[RegionSpec],
    ) -> Result<CompareReport, CompareError> {
        let w = self.0.world();
        let (m3, m5) = (w.m3(), w.m5());
        for (operand, regions) in [(Operand::First, rho1), (Operand::Second, rho2)] {
            for (ri, r) in regions.iter().enumerate() {
                if !m3.is_registered_document(&r.doc) {
                    return Err(CompareError::DocNotRegistered(r.doc.clone()));
                }
                for (si, span) in r.spans.iter().enumerate() {
                    if span.start().get(1) != Some(&S_C) {
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
                    gate_vspan(span).map_err(|f| CompareError::MalformedSpan {
                        operand,
                        region: ri,
                        index: si,
                        fault: f,
                    })?;
                }
            }
        }
        // p = R_Σ(ρ₁), q = R_Σ(ρ₂), as blocks — reads ONLY M5.
        let (p, q) = (resolve_blocks(m5, rho1), resolve_blocks(m5, rho2));
        let pairs = interval_join(&p, &q); // cross-product per overlap (X8)
        Ok(CompareReport(deterministic_presentation(pairs))) // R1–R3 (X12)
    }
}

/// Transient per-query working row for COMPARE: built by [`resolve_blocks`],
/// consumed by [`overlap_pair`]/[`interval_join`]; dropped at return. One
/// block per resolved I-run of one spec's span — the run as M5 handed it
/// over, plus where the block's first position sits in its document's V-space.
struct Block {
    doc: Address,
    v_start: VPos,
    run: Run,
}

impl Block {
    /// One I-step past the block: the run's own exclusive reach, which is all
    /// the half-open `lo < hi` compare needs. A `Tumbler` endpoint, because no
    /// `Address` invariant is consumed by a comparison.
    fn reach_i(&self) -> Tumbler {
        self.run.tumbler_at(self.run.width())
    }

    /// The V-position of the I-address `i` WITHIN THIS BLOCK — `v_start`
    /// advanced by `i`'s offset from the block's own I-start. Each foot of a
    /// correspondence is computed by the block it comes from, so the
    /// inter-block I-gap of a cross-document pair can never leak into the
    /// other operand's V-coordinate (X12 R1 soundness: both feet must resolve
    /// to the shared address).
    ///
    /// REQUIRES `i` inside this block's I-interval — the co-chain
    /// precondition [`ordinal_gap`] states, discharged by [`overlap_pair`]'s
    /// overlap guard before it asks.
    fn vpos_at(&self, i: &Tumbler) -> VPos {
        VPos {
            subspace: self.v_start.subspace.clone(),
            ordinal: &self.v_start.ordinal + &ordinal_gap(i, self.run.i_start().tumbler()),
        }
    }
}

/// The region a spec-set denotes, as blocks: resolve every spec's span to its
/// I-run blocks, reconstructing each run's V-start by accumulation.
///
/// V-RECONSTRUCTION LEMMA (load-bearing for X12-R1 soundness, correct ONLY
/// under D-SEQ★): a content subspace's occupied positions are the dense
/// prefix `{[s_C, k] : 1 ≤ k ≤ n_C}`, so the FIRST bound V-position of a
/// content span IS `span.start()` — a start beyond the prefix binds nothing
/// at all, rather than skipping forward to a later occupied position — and
/// `resolve`'s runs tile the bound prefix CONTIGUOUSLY in V. Hence the
/// V-cursor starts at `span.start()` and advances by each run's width: there
/// are no V-gaps to skip. The lemma is asserted on EVERY run — firing per run
/// (not first-run-only) localizes a future M5 regression to the EXACT
/// mis-aligning run instead of letting a mid-document V-gap slip past a
/// first-run check and silently mis-set a later block's `v_start`.
///
/// REQUIRES GATED SPECS: every span content-subspace-started and
/// `gate_vspan`-clean, which [`Query::compare`]'s gate establishes before it
/// calls. Two things ride on that gate. The lemma above is the CONTENT
/// subspace's — D-SEQ★ holds per subspace, and a link-started span would read
/// a V-cursor against a prefix the lemma says nothing about. And `#start ≥ 2`
/// puts both `[subspace, ordinal]` components at every start, so the let-else
/// is the total form of a fact the caller has already settled, not a case
/// that arises.
///
/// A depth-incompatible (`#start ≥ 3`) span reads its cursor here like any
/// other and still contributes no blocks — `resolve`'s own shape reader
/// refuses it and hands back no runs, so the span contributes nothing to the
/// region.
fn resolve_blocks(m5: &M5State, regions: &[RegionSpec]) -> Vec<Block> {
    let mut out = Vec::new();
    for r in regions {
        for span in &r.spans {
            let (Some(sub), Some(ord)) = (span.start().get(1), span.start().get(2)) else {
                continue;
            };
            let mut v = VPos {
                subspace: sub.clone(),
                ordinal: ord.clone(),
            };
            for run in m5.resolve(&r.doc, span) {
                debug_assert!(
                    m5.point(&r.doc, &v).as_ref() == Some(run.i_start()),
                    "D-SEQ★: each content run must begin at the V-cursor (gap-free tiling)"
                );
                // Accumulate the V offset by run width (no V-gaps in content).
                let next = &v.ordinal + run.width();
                out.push(Block {
                    doc: r.doc.clone(),
                    v_start: v.clone(),
                    run,
                });
                v.ordinal = next;
            }
        }
    }
    out
}

// ── COMPARE helpers ──
//
// CO-CHAIN PRECONDITION: `overlap_pair` calls `ordinal_gap` — directly, and
// through `Block::vpos_at` — only AFTER the `lo < hi` overlap guard, i.e.
// only on runs whose I-intervals overlap. Overlapping content runs lie on ONE
// content chain (shared origin sub-allocator ⇒ equal-length, equal prefix
// below the action point), so a bare ordinal subtraction is a TOTAL `Nat` op
// — no borrow, no underflow. Different-chain pairs have disjoint I-intervals
// and are rejected by the guard before any ordinal arithmetic runs.

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

/// One correspondence per I-overlap of two blocks, or `None` when the
/// I-intervals are disjoint. Each foot is asked of the block it belongs to
/// ([`Block::vpos_at`]), so both resolve to the shared address `lo`.
fn overlap_pair(pb: &Block, qb: &Block) -> Option<CorrPair> {
    let lo = max_tumbler(pb.run.i_start().tumbler(), qb.run.i_start().tumbler());
    let hi = min_tumbler(&pb.reach_i(), &qb.reach_i());
    if lo >= hi {
        return None; // disjoint I-intervals ⇒ no correspondence
    }
    // lo < hi now discharges the co-chain precondition: every ordinal_gap
    // below is total.
    Some(CorrPair {
        d1: pb.doc.clone(),
        u1: pb.vpos_at(&lo), // slot 1 ⇐ operand 1
        d2: qb.doc.clone(),
        u2: qb.vpos_at(&lo), // slot 2 ⇐ operand 2
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

/// The one presentation X12 R3 requires the implementation to fix, over the
/// complete+sound relation (R1/R2). NOT R4's canonical report, which is the
/// MAXIMAL pairs of X11 and is explicitly not required for conformance. Sort
/// lexicographically by `(d1, u1, d2, u2)` — `sort_by_cached_key` computes
/// each four-`Tumbler` key ONCE per element (a bare `sort_by` would rebuild
/// both keys per *comparison*) and is a STABLE sort, so duplicate overlaps
/// keep a deterministic listed order (R3). The adjacent-pair fold is the
/// IDENTITY in v1 (a finer-than-maximal, per-overlap report conforms — see
/// [`fold_adjacent`]).
fn deterministic_presentation(mut pairs: Vec<CorrPair>) -> Vec<CorrPair> {
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
/// never changes ⟦Γ⟧. Implementing that merge is exactly what would make the
/// output X11's `CANON`, and only then would *canonical* be the right word
/// for this step.
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

    fn vp(subspace: u32, ordinal: u32) -> VPos {
        VPos {
            subspace: n(subspace),
            ordinal: n(ordinal),
        }
    }

    fn block(doc: &[u32], v_ord: u32, i_start: Address, width: u32) -> Block {
        Block {
            doc: a(doc),
            v_start: vp(1, v_ord),
            run: Run::new(i_start, n(width)).expect("test runs are well-formed"),
        }
    }

    #[test]
    fn overlap_pair_computes_each_foot_within_its_own_block() {
        // X12 R1: a block answers for its own V-coordinates, so each foot is
        // offset within the block it comes from and both resolve to the
        // shared address lo.
        let pb = block(&[1, 0, 1, 0, 1], 1, ca(1), 3); // [ca1, ca4) at V 1..
        let qb = block(&[1, 0, 1, 0, 2], 1, ca(2), 1); // [ca2, ca3) at V 1..
        // The same I-address is a different V-position in each block…
        assert_eq!(pb.vpos_at(ca(2).tumbler()), vp(1, 2));
        assert_eq!(qb.vpos_at(ca(2).tumbler()), vp(1, 1));
        // …and each block's reach is one I-step past its own last position.
        assert_eq!(pb.reach_i(), *ca(4).tumbler());
        assert_eq!(qb.reach_i(), *ca(3).tumbler());
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
    fn the_presentation_sorts_by_the_four_tumbler_key_and_folds_identity() {
        // X12 R3: one deterministic lexicographic (d1, u1, d2, u2)
        // presentation; v1's fold is the identity (finer-than-maximal
        // conforms — R4's canonical form is not required).
        let mk = |u2_ord: u32| CorrPair {
            d1: a(&[1, 0, 1, 0, 1]),
            u1: vp(1, 1),
            d2: a(&[1, 0, 1, 0, 2]),
            u2: vp(1, u2_ord),
            width: n(1),
        };
        let got = deterministic_presentation(vec![mk(2), mk(1)]);
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].u2.ordinal, n(1));
        assert_eq!(got[1].u2.ordinal, n(2));
    }
}
