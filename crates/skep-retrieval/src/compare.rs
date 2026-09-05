//! §D COMPARE / SHOWRELATIONOF2VERSIONS (ASN-0122) — an interval equi-join on
//! I-address, complete under fan-out. The contract is a relational join keyed
//! on **address equality, never value** — so COMPARE never opens M4. Three
//! phases: resolve each spec-set to the blocks of its region, interval-join on
//! the I-axis with cross-product on overlap (X12 R2 completeness; the
//! cross-product is `corr`'s own comprehension over `P × Q`), sort into one
//! deterministic presentation (X12 R3; R4's canonical maximal form NOT
//! required — v1 ships the finer-than-maximal per-overlap report, fully
//! conforming under R1–R3).
//!
//! COMPARE is the one M6 operation whose cost is SUPERLINEAR in its request —
//! `|P|·|Q|` over two block lists a caller sizes independently — so it is the
//! one that carries budgets of its own: [`MAX_COMPARE_OPERAND_BLOCKS`] per
//! operand and [`MAX_COMPARE_PAIRS`] per report, each a refusal rather than a
//! truncation.

use std::cmp;

use num_traits::CheckedSub;
use skep_address::{ordinal, Address, Nat, Tumbler};
use skep_arrangement::{M5State, Run, VPos};

use skep_namespace::M3State;

use crate::error::{CompareError, Operand};
use crate::types::{CompareReport, CorrPair, RegionSpec};
use crate::vspan::{gate_vspan, span_subspace, span_vpos, Subspace};
use crate::{Query, RetrievalWorld};

/// The most blocks one COMPARE operand may resolve to, and so the ceiling on
/// the join's two factors.
///
/// The budget: the join is `|P|·|Q|` candidate tests, so an operand budget
/// SQUARES — `2^12` bounds one query at `2^24` ≈ 1.7×10⁷ tests, each two
/// `Tumbler` comparisons over element addresses, which is order a second of
/// one worker. The number is also M10's own per-array wire cap, so an operand
/// that is a FLAT list of 4096 single-run spans — the largest flat span list
/// the transport admits — is admitted here unchanged.
///
/// What it refuses is the two shapes no wire cap prices: the NESTED
/// region×span product, whose region-set cost model the transport leaves to
/// M6, and the multi-run expansion, where one span over a fragmented document
/// resolves to many blocks from a single wire element.
pub const MAX_COMPARE_OPERAND_BLOCKS: usize = 1 << 12;

/// The most correspondences one COMPARE may report, and so the ceiling on what
/// the REPORT makes M6 hold live.
///
/// The budget: a [`CorrPair`] is two `Address`es, two `VPos`es and a `Nat` —
/// order a kilobyte of live heap once the `BigUint` digit vectors are counted
/// — and the report is what the query holds, the presentation sorting it in
/// place over borrowed keys and holding nothing beside it. `2^16` is therefore
/// order 64 MiB of report; it is also M5's `MAX_PLACED_RUNS`, the substrate's
/// existing answer to how many runs one operation may materialize.
///
/// It is not a ceiling on the whole query's heap, and neither budget is: one
/// span over a fragmented document materializes that document's entire
/// resolution before a block is counted (see [`resolve_blocks`]).
///
/// [`MAX_COMPARE_OPERAND_BLOCKS`] cannot stand in for it: two operands at that
/// budget whose spans all name ONE shared position report the SQUARE of it in
/// pairs, so fan-out is bounded only by counting the pairs themselves.
pub const MAX_COMPARE_PAIRS: usize = 1 << 16;

impl<W: RetrievalWorld> Query<'_, W> {
    /// COMPARE (ASN-0122): two content-subspace spec-sets `ρ₁, ρ₂`, each a set
    /// of [`RegionSpec`]s — ASN-0122's `(dᵢ, Sᵢ)`; reports address-equal
    /// correspondences (X1/X2 — value-blind, NEVER opens M4), complete under
    /// fan-out (X12 R2), in one deterministic presentation (X12 R3); in each
    /// pair, slot 1 ⇐ ρ₁ and slot 2 ⇐ ρ₂.
    ///
    /// A spec-set denotes its region `R_Σ(ρᵢ)` — each span clipped against the
    /// document's current content arrangement — and that region is what
    /// [`resolve_blocks`] hands back as the block list `p`/`q`. Every reported
    /// pair is confined to those two regions (X12 R1), and a span that clips
    /// to nothing contributes to neither.
    ///
    /// Gate, per operand ([`gate_spec_set`]): each spec's doc registered, each
    /// span content-subspace-started (`NotContentSubspace`) and well-formed
    /// (`MalformedSpan`), every span fault located by an unambiguous
    /// `(operand, region, span-index)`. A well-formed depth-incompatible span
    /// passes and
    /// contributes nothing to its region (consulting-state — success, X12);
    /// overlapping/repeated windows within one operand are redundant, not
    /// wrong (⟦Γ⟧ is a set-union; duplicates collapse denotationally and the
    /// stable sort keeps the listed order deterministic).
    ///
    /// WHICH REFUSAL SPEAKS. The gate walks ρ₁'s regions and their spans in
    /// submitted order, then ρ₂'s, and reports the FIRST fault whatever its
    /// kind — so `(operand, region, index)` promises that everything listed
    /// before it is clean. BOTH operands are gated in FULL before either is
    /// resolved, so a gate fault always outranks a budget refusal: a client
    /// told `TooManyBlocks { operand: First }` knows ρ₂ was examined too and
    /// found well-formed.
    ///
    /// COST, AND THE TWO BUDGETS THAT BOUND IT. The join is `|P|·|Q|`
    /// candidate tests over the two regions' blocks, and BOTH factors are the
    /// request's: a region names a span list and a spec-set names a region
    /// list, so their product is the caller's to choose and squares in it. So
    /// each operand is capped at [`MAX_COMPARE_OPERAND_BLOCKS`] blocks
    /// (`TooManyBlocks`, refused BEFORE the join runs, ρ₁ resolved first) and
    /// the report at [`MAX_COMPARE_PAIRS`] correspondences (`TooManyPairs`,
    /// refused AS THE PAIRS ARE PRODUCED, so an over-budget fan-out stops
    /// accumulating rather than being built and then measured).
    ///
    /// Both are REFUSALS, never truncations: a request past either gets a
    /// typed rejection and no report, so X12 R1–R2 hold verbatim for every
    /// request COMPARE answers. A caller wanting more splits the request,
    /// exactly as an over-budget transaction is split.
    pub fn compare(
        &self,
        rho1: &[RegionSpec],
        rho2: &[RegionSpec],
    ) -> Result<CompareReport, CompareError> {
        let w = self.0.world();
        let (m3, m5) = (w.m3(), w.m5());
        // BOTH operands whole, before either resolves.
        gate_spec_set(m3, Operand::First, rho1)?;
        gate_spec_set(m3, Operand::Second, rho2)?;
        // p = R_Σ(ρ₁), q = R_Σ(ρ₂), as blocks — reads ONLY M5, each operand
        // within its own block budget.
        let p = resolve_blocks(m5, rho1).ok_or(CompareError::TooManyBlocks {
            operand: Operand::First,
        })?;
        let q = resolve_blocks(m5, rho2).ok_or(CompareError::TooManyBlocks {
            operand: Operand::Second,
        })?;
        // Cross-product per overlap (`corr` is a comprehension over `P × Q`),
        // within the report budget.
        let pairs = interval_join(&p, &q).ok_or(CompareError::TooManyPairs)?;
        Ok(CompareReport(deterministic_presentation(pairs))) // R1–R3 (X12)
    }
}

/// One operand's admissibility: every region's doc registered, every span
/// content-subspace-started and well-formed, faults located by
/// `(operand, region, span-index)`.
///
/// Walks the regions and their spans in SUBMITTED ORDER and returns at the
/// first fault whatever its kind, which is what makes the triple locate
/// anything: it names a position everything before which is clean. Per span
/// the residence check runs BEFORE [`gate_vspan`] — a link-started span that
/// is also malformed reports `NotContentSubspace` — because a request naming
/// the wrong subspace is a different request, not a misshapen one.
///
/// Content residence is COMPARE's own clause (ASN-0122 spec-sets are
/// content-subspace), rejected loudly rather than resolved to nothing: a span
/// that merely DENOTES link positions from a content start is always legal,
/// and `resolve` clips it.
fn gate_spec_set(
    m3: &M3State,
    operand: Operand,
    regions: &[RegionSpec],
) -> Result<(), CompareError> {
    for (region, r) in regions.iter().enumerate() {
        if !m3.is_registered_document(&r.doc) {
            return Err(CompareError::DocNotRegistered(r.doc.clone()));
        }
        for (index, span) in r.spans.iter().enumerate() {
            if span_subspace(span) != Some(Subspace::Content) {
                return Err(CompareError::NotContentSubspace {
                    operand,
                    region,
                    index,
                });
            }
            gate_vspan(span).map_err(|fault| CompareError::MalformedSpan {
                operand,
                region,
                index,
                fault,
            })?;
        }
    }
    Ok(())
}

/// Transient per-query working row for COMPARE: built by [`resolve_blocks`],
/// consumed by [`overlap_pair`]/[`interval_join`]; dropped at return. One
/// block per resolved I-run of one spec's span — the run as M5 handed it
/// over, plus where the block's first position sits in its document's V-space
/// and one I-step past its last position.
///
/// A block REFERS TO the document of the region that named it, which outlives
/// every block built from it, so the row borrows what it only reads and owns
/// only what it computed. The join builds one block per resolved run BEFORE it
/// emits anything, so an owned document here would be one `Address` clone per
/// block — paid in full by a query whose two regions share nothing and report
/// no pairs at all.
#[derive(Debug)]
struct Block<'a> {
    doc: &'a Address,
    v_start: VPos,
    run: Run,
    /// One I-step past the block: the run's own exclusive reach, which is all
    /// the half-open `start < reach` compare needs. A `Tumbler` endpoint,
    /// because no `Address` invariant is consumed by a comparison.
    ///
    /// Stored rather than derived per comparison, because the exhaustive join
    /// asks for it once per CANDIDATE PAIR: deriving it is a fresh
    /// `Vec<BigUint>` with a `BigUint` clone per component, so a block whose
    /// reach is computed on demand pays `|Q|` vector allocations where one
    /// suffices, and the budget arithmetic behind
    /// [`MAX_COMPARE_OPERAND_BLOCKS`] is priced on the stored form.
    reach: Tumbler,
}

impl<'a> Block<'a> {
    /// One block over one resolved run, with its reach taken once —
    /// [`Run::reach`], the run's own exclusive I-end.
    fn new(doc: &'a Address, v_start: VPos, run: Run) -> Block<'a> {
        let reach = run.reach();
        Block {
            doc,
            v_start,
            run,
            reach,
        }
    }

    /// The block's inclusive I-start, borrowed — the run's own, unpacked to
    /// the `Tumbler` a comparison consumes. Paired with the stored `reach` so
    /// the block answers for BOTH its endpoints and the overlap guard reads as
    /// the half-open interval it is.
    fn i_start(&self) -> &Tumbler {
        self.run.i_start().tumbler()
    }

    /// The FOOT this block contributes at the I-address `i` — X11's word for
    /// one side of a correspondence, `(document, position)`: the block's own
    /// document, and its `v_start` advanced by `i`'s offset from its own
    /// I-start. A foot comes WHOLE from the block it belongs to, so its
    /// document and its position can never be drawn from different blocks, and
    /// the inter-block I-gap of a cross-document pair can never leak into the
    /// other block's V-coordinate (X12 R1 soundness: both feet must resolve to
    /// the shared address).
    ///
    /// REQUIRES `i` inside this block's I-interval — the co-chain
    /// precondition [`ordinal_gap`] states, discharged by [`overlap_pair`]'s
    /// overlap guard before it asks.
    fn foot_at(&self, i: &Tumbler) -> (Address, VPos) {
        (
            self.doc.clone(),
            VPos {
                subspace: self.v_start.subspace.clone(),
                ordinal: &self.v_start.ordinal + &ordinal_gap(i, self.i_start()),
            },
        )
    }
}

/// The region a spec-set denotes, as blocks: resolve every spec's span to its
/// I-run blocks, reconstructing each run's V-start by accumulation. `None`
/// when the operand reaches [`MAX_COMPARE_OPERAND_BLOCKS`] — refused AS THE
/// BLOCKS ARE PRODUCED, so an over-budget operand stops resolving rather than
/// resolving whole and then being measured.
///
/// THE BUDGET'S GRANULARITY IS A SPAN. The walk stops at the first span whose
/// runs carry the accumulator past the budget, so what the budget bounds is
/// the block LIST — the join's factor, which is what it is priced on. Within
/// one span it bounds nothing: `resolve` hands back the whole of that span's
/// resolution, whose size is the DOCUMENT's fragmentation rather than the
/// request's shape, and M5 keeps the lazy form crate-private. So one span over
/// a heavily fragmented document builds every run of its resolution before the
/// count is consulted, and that transient is sized by neither budget here.
///
/// V-RECONSTRUCTION (load-bearing for X12-R1 soundness): `resolve` PROMISES
/// that its runs tile V contiguously from the first run's `max(ordinal, 1)`,
/// each next run beginning where the previous one ends — which is precisely
/// what lets a caller recover every run's V-start by accumulating widths from
/// the span's own ordinal, with no V-gaps to skip and no second question
/// asked. That promise rests on D-SEQ★ (ASN-0047), a subspace's arranged
/// positions being its dense prefix, and D-SEQ★ is what the per-run assertion
/// tripwires. Asserting on EVERY run (not first-run-only) localizes a future
/// M5 regression to the EXACT mis-aligning run instead of letting a
/// mid-document V-gap slip past a first-run check and silently mis-set a later
/// block's `v_start`.
///
/// REQUIRES GATED SPECS: every span content-subspace-started and
/// `gate_vspan`-clean, which [`Query::compare`]'s gate establishes before it
/// calls. Three clauses of that gate ride here. The ZERO-FREE start puts
/// `ordinal ≥ 1` at every span, so the cursor M6 opens at `span.start()`'s
/// ordinal IS `resolve`'s `max(ordinal, 1)` and M6 carries no clamp of its own
/// — relax zero-freedom and every foot of every correspondence from an
/// ordinal-0 span is off by one, with the assertion below the only thing that
/// would say so, and only in debug. `#start ≥ 2` puts both components at every
/// start, which is the condition [`span_vpos`] hands back `None` on and
/// therefore the one the let-else stands in for. And the CONTENT-subspace
/// start is ASN-0122's own restriction on
/// what a spec-set may name — the regions this builds are content regions
/// because the gate admits nothing else.
///
/// A depth-incompatible (`#start ≥ 3`) span reads its cursor here like any
/// other and still contributes no blocks — `resolve`'s own shape reader
/// refuses it and hands back no runs, so the span contributes nothing to the
/// region.
///
/// The blocks borrow the REGIONS, not `m5`: each carries a reference to the
/// document of the spec that named it, so the lifetime is written out rather
/// than elided — two input lifetimes and no `&self` leave nothing for elision
/// to pick.
fn resolve_blocks<'a>(m5: &M5State, regions: &'a [RegionSpec]) -> Option<Vec<Block<'a>>> {
    let mut out = Vec::new();
    for r in regions {
        for span in &r.spans {
            let Some(mut cursor) = span_vpos(span) else {
                continue;
            };
            for run in m5.resolve(&r.doc, span) {
                if out.len() >= MAX_COMPARE_OPERAND_BLOCKS {
                    return None; // the operand's budget, refused as produced
                }
                debug_assert!(
                    m5.point(&r.doc, &cursor).as_ref() == Some(run.i_start()),
                    "D-SEQ★: each content run must begin at the V-cursor (gap-free tiling)"
                );
                // Accumulate the V offset by run width (no V-gaps in content).
                let next = &cursor.ordinal + run.width();
                out.push(Block::new(&r.doc, cursor.clone(), run));
                cursor.ordinal = next;
            }
        }
    }
    Some(out)
}

// ── COMPARE helpers ──
//
// CO-CHAIN PRECONDITION: `overlap_pair` calls `ordinal_gap` — directly, and
// through `Block::foot_at` — only AFTER the `start < reach` overlap guard,
// i.e. only on runs whose I-intervals overlap. Overlapping content runs lie on
// ONE content chain (shared origin sub-allocator ⇒ equal-length, equal prefix
// below the action point), so the ordinal subtraction is a TOTAL `Nat` op —
// no borrow, no underflow. Different-chain pairs have disjoint I-intervals
// and are rejected by the guard before any ordinal arithmetic runs.

/// Co-chain ⇒ `ordinal(hi) ≥ ordinal(lo)`, so the subtraction is total under
/// the precondition — and the `expect` names the lemma a violation would have
/// falsified, rather than surfacing as a bignum borrow panic from inside
/// `num-bigint` that says nothing about the argument.
fn ordinal_gap(hi: &Tumbler, lo: &Tumbler) -> Nat {
    ordinal(hi)
        .checked_sub(ordinal(lo))
        .expect("co-chain overlap ⇒ ordinal(hi) ≥ ordinal(lo)")
}

/// One correspondence per I-overlap of two blocks, or `None` when the
/// I-intervals are disjoint. The overlap is itself an I-interval, named the
/// way M1 names one: inclusive `start`, exclusive `reach`. Each FOOT is asked
/// whole of the block it belongs to ([`Block::foot_at`]), so both resolve to
/// the shared address `start` and slot `i` draws from operand `i` (X3).
///
/// Each endpoint is asked of the block that owns it — [`Block::i_start`] and
/// the reach it stores — and both stay BORROWED across the guard: the
/// exhaustive join asks this of every candidate pair, and most are disjoint,
/// so a rejected pair must build nothing and clone nothing to be compared.
fn overlap_pair(pb: &Block<'_>, qb: &Block<'_>) -> Option<CorrPair> {
    let start = cmp::max(pb.i_start(), qb.i_start());
    let reach = cmp::min(&pb.reach, &qb.reach);
    if start >= reach {
        return None; // disjoint I-intervals ⇒ no correspondence
    }
    // start < reach now discharges the co-chain precondition: every
    // ordinal_gap below is total.
    let (d1, u1) = pb.foot_at(start); // slot 1 ⇐ operand 1 (X3)
    let (d2, u2) = qb.foot_at(start); // slot 2 ⇐ operand 2
    Some(CorrPair {
        d1,
        u1,
        d2,
        u2,
        width: ordinal_gap(reach, start),
    })
}

/// v1 REFERENCE IMPLEMENTATION: exhaustive O(|P|·|Q|) double-loop block join —
/// emit EVERY I-overlap (X12 R2 completeness: `corr_Σ(P, Q)` is the
/// comprehension over the whole rectangle `P × Q`, so an address in multiple
/// P-blocks and/or Q-blocks yields the full cross-product, never a lockstep
/// merge). Sort-by-i_start + sweep (or an interval tree) is a drop-in
/// optimization of this SAME join (same pair multiset); the independent TEST
/// ORACLE is a per-position hash join on address. One vocabulary — see the
/// design's Open build decisions (canonical statement).
///
/// `None` when the report would run to MORE THAN [`MAX_COMPARE_PAIRS`]
/// correspondences — a report of exactly the budget is answered, and the pair
/// past it is refused AS THE PAIRS ARE PRODUCED. That budget is on the REPORT,
/// not on the join's shape: a sweep changes how many candidate pairs are
/// TESTED and not how many are EMITTED, so the same cap stands whichever join
/// ships, and it is the only one that sees a fan-out. The guard is written
/// `>=` for that reason and not as an equality on the accumulator: a sweep or
/// an interval tree emits one event point's pairs TOGETHER, so a cap that can
/// only see the counter land exactly on the budget is a cap the successor join
/// steps over.
fn interval_join(p: &[Block<'_>], q: &[Block<'_>]) -> Option<Vec<CorrPair>> {
    let mut out = Vec::new();
    for pb in p {
        for qb in q {
            if let Some(c) = overlap_pair(pb, qb) {
                if out.len() >= MAX_COMPARE_PAIRS {
                    return None; // the report's budget, refused as produced
                }
                out.push(c);
            }
        }
    }
    Some(out)
}

/// The one presentation X12 R3 requires the implementation to fix, over the
/// complete+sound relation (R1/R2). NOT R4's canonical report, which is the
/// MAXIMAL pairs of X11 and is explicitly not required for conformance. Sort
/// lexicographically by `(d1, u1, d2, u2)` over a BORROWED key: the pair's own
/// components already carry the order the comparison wants, so the sort builds
/// nothing and clones nothing. `sort_by` rather than `sort_by_cached_key` for
/// that reason — caching amortizes an EXPENSIVE key computation, and taking
/// four references is not one — and STABLE either way, so duplicate overlaps
/// keep a deterministic listed order (R3). The adjacent-pair fold is the
/// IDENTITY in v1 (a finer-than-maximal, per-overlap report conforms — see
/// [`fold_adjacent`]).
///
/// THE SECOND FOOT IS IN THE KEY BECAUSE OF FAN-OUT, which is X11's own
/// strictness clause: two pairs sharing both starts would share their first
/// element and coincide, and sharing ONLY the first start "happens exactly
/// under fan-out" — where several chains land on one first foot — so the
/// second key is what separates them. A presentation keyed on the first foot
/// alone would leave a fanned-out report's order undetermined.
fn deterministic_presentation(mut pairs: Vec<CorrPair>) -> Vec<CorrPair> {
    pairs.sort_by(|a, b| corr_key(a).cmp(&corr_key(b)));
    fold_adjacent(pairs)
}

/// The four components X12 R3's presentation is keyed on, borrowed. The
/// documents order by their own `Ord`, which IS the T1 tumbler order; each
/// foot orders as the pair its layout denotes ([`foot_key`]). Nesting rather
/// than flattening to six, so the key has the four components the card
/// describes.
fn corr_key(c: &CorrPair) -> (&Address, (&Nat, &Nat), &Address, (&Nat, &Nat)) {
    (&c.d1, foot_key(&c.u1), &c.d2, foot_key(&c.u2))
}

/// A foot's position as the `[subspace, ordinal]` pair its layout denotes —
/// the writing direction of the layout [`span_vpos`] reads, in the order a
/// comparison consumes. `VPos` carries no order of its own, so the ordering is
/// stated here; it is `Tumbler`'s own slice-lexicographic order on the two
/// components, which is what that layout means.
///
/// [`span_vpos`]: crate::vspan::span_vpos
fn foot_key(v: &VPos) -> (&Nat, &Nat) {
    (&v.subspace, &v.ordinal)
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
///
/// Landing that merge would leave every report EQUIVALENT to today's and
/// UNEQUAL to it — which is exactly what R4 licenses, conformance being
/// denotational. So a consumer that must survive a presentation change
/// compares denotations, not [`CompareReport`] values; `==` is the listing's.
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

    /// doc1's content element at `ordinal`, M3's minted shape.
    fn ca(ordinal: u32) -> Address {
        a(&[1, 0, 1, 0, 1, 0, 1, ordinal])
    }

    fn vp(subspace: u32, ordinal: u32) -> VPos {
        VPos {
            subspace: n(subspace),
            ordinal: n(ordinal),
        }
    }

    /// A block over `doc`, which the block borrows and the caller therefore
    /// binds first — the same shape `resolve_blocks` has, where the document
    /// belongs to the region that named the span.
    fn block(doc: &Address, v_ordinal: u32, i_start: Address, width: u32) -> Block<'_> {
        Block::new(
            doc,
            vp(1, v_ordinal),
            Run::new(i_start, n(width)).expect("test runs are well-formed"),
        )
    }

    #[test]
    fn overlap_pair_computes_each_foot_within_its_own_block() {
        // X12 R1: a block answers for its own foot WHOLE — document and
        // position together — so each foot is offset within the block it
        // comes from and both resolve to the overlap's shared start address.
        let (d1, d2) = (a(&[1, 0, 1, 0, 1]), a(&[1, 0, 1, 0, 2]));
        let pb = block(&d1, 1, ca(1), 3); // [ca1, ca4) at V 1..
        let qb = block(&d2, 1, ca(2), 1); // [ca2, ca3) at V 1..
        // The same I-address is a different foot in each block…
        assert_eq!(pb.foot_at(ca(2).tumbler()), (d1.clone(), vp(1, 2)));
        assert_eq!(qb.foot_at(ca(2).tumbler()), (d2.clone(), vp(1, 1)));
        // …and each block's reach is one I-step past its own last position.
        assert_eq!(pb.reach, *ca(4).tumbler());
        assert_eq!(qb.reach, *ca(3).tumbler());
        let c = overlap_pair(&pb, &qb).expect("overlapping I-intervals correspond");
        assert_eq!(c.d1, d1);
        assert_eq!(c.u1.subspace, n(1));
        assert_eq!(c.u1.ordinal, n(2)); // start = ca2 is offset 1 within P
        assert_eq!(c.d2, d2);
        assert_eq!(c.u2.subspace, n(1));
        assert_eq!(c.u2.ordinal, n(1)); // start = ca2 is offset 0 within Q
        assert_eq!(c.width, n(1));
    }

    #[test]
    fn overlap_pair_rejects_disjoint_and_cross_chain_intervals() {
        let (d1, d2) = (a(&[1, 0, 1, 0, 1]), a(&[1, 0, 1, 0, 2]));
        // Same chain, disjoint: [ca1, ca4) vs [ca5, ca6).
        let pb = block(&d1, 1, ca(1), 3);
        let qb = block(&d2, 1, ca(5), 1);
        assert!(overlap_pair(&pb, &qb).is_none());
        // Adjacent (half-open, touching): [ca1, ca4) vs [ca4, ca5) share
        // nothing.
        let qb = block(&d2, 1, ca(4), 1);
        assert!(overlap_pair(&pb, &qb).is_none());
        // Different chains have disjoint I-intervals — the guard rejects
        // BEFORE any ordinal arithmetic runs (co-chain precondition).
        let da1 = a(&[1, 0, 1, 0, 2, 0, 1, 1]);
        let qb = block(&d2, 1, da1, 2);
        assert!(overlap_pair(&pb, &qb).is_none());
    }

    #[test]
    fn the_presentation_sorts_by_the_four_component_key_and_folds_identity() {
        // X12 R3: one deterministic lexicographic (d1, u1, d2, u2)
        // presentation; v1's fold is the identity (finer-than-maximal
        // conforms — R4's canonical form is not required).
        let pair = |u2_ordinal: u32| CorrPair {
            d1: a(&[1, 0, 1, 0, 1]),
            u1: vp(1, 1),
            d2: a(&[1, 0, 1, 0, 2]),
            u2: vp(1, u2_ordinal),
            width: n(1),
        };
        let got = deterministic_presentation(vec![pair(2), pair(1)]);
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].u2.ordinal, n(1));
        assert_eq!(got[1].u2.ordinal, n(2));
    }
}
