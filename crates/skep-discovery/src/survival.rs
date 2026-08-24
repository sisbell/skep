//! §6 — the pre-edit link-survival check (ASN-0117): a pure what-if over the
//! snapshot — it never calls M5's delete — built on the F-UDIST set identity
//! `orphaned = findlinks(A_del) ∖ findlinks(retained_range)` over the ACTIVE
//! view (a nullified link that lost its last witness in `d` is NOT reported —
//! a deliberate divergence from ASN-0117's `D(d,Σ)` over `dom(L)`,
//! Conflicts #8).

use im::OrdSet;
use num_traits::{One, Zero};
use skep_address::{Address, Nat, Span, Tumbler};
use skep_arrangement::{HasM5, Run, VPos};
use skep_kernel::{Snapshot, WorldState};
use skep_links::{Endset, HasLinks};
use skep_namespace::HasM3;

use crate::helpers::stab_union;
use crate::types::{OrphanReport, QueryError};

/// A single ordinal-level depth-2 V-span value `[subspace, ordinal] ×
/// [0, width]` — no algebra. Unwrap-safe under the callers' width ≥ 1 guard:
/// T12 holds because `actionPoint([0, w]) = 2 ≤ #start = 2`.
fn vspan(subspace: &Nat, ordinal: &Nat, width: &Nat) -> Span {
    let start = Tumbler::new([subspace.clone(), ordinal.clone()])
        .expect("a two-component sequence is nonempty");
    let disp =
        Tumbler::new([Nat::zero(), width.clone()]).expect("a two-component sequence is nonempty");
    Span::new(start, disp).expect("width ≥ 1 ⇒ actionPoint([0, w]) = 2 ≤ #start = 2 (T12)")
}

/// Pre-edit what-if (ASN-0117): the links the proposed DELETE `[p, p+width)`
/// would drop from `d` — read-only, never the edit path.
///
/// Mirrors DELETE's preconditions so the preview is of the REQUESTED delete,
/// never a silently-clipped different one, and the rejection is actionable:
/// `DocNotRegistered`; non-`s_C` `p` → `NotContentSubspace`; zero `width` →
/// `EmptyWidth`; out-of-range `(p, width)` → `OutOfBounds` — the last
/// deliberately folding M5's `NotArranged` + `OutOfBounds`, to which the
/// single check `p < 1 ∨ p + width > n_C + 1` is jointly equivalent under
/// width ≥ 1 (nothing is accepted or rejected differently; only the variant
/// label differs on the `p > n_C` case).
///
/// `orphaned = findlinks(A_del) ∖ findlinks(retained)` where `retained` =
/// the prefix + suffix content that survives plus the link runs (a text
/// delete never touches links) — the last-witness condition with no per-pair
/// reasoning. Both sides stab the ACTIVE view. The relative complement is
/// `OrdSet::relative_complement` — NEVER `im`'s `difference`, which is
/// SYMMETRIC difference and would wrongly fold in the plainly-surviving
/// links. The global-ghost determination (LP17 — discoverable from NO
/// document) reaches provenance R and is M6 territory; M8 stops at the
/// per-document set.
pub fn delete_orphans_on<W>(
    s: &Snapshot<W>,
    d: &Address,
    p: &VPos,
    width: &Nat,
) -> Result<OrphanReport, QueryError>
where
    W: WorldState + HasLinks + HasM5 + HasM3,
{
    let w = s.world();
    if !w.m3().is_registered_document(d) {
        return Err(QueryError::DocNotRegistered);
    }
    if p.subspace != Nat::one() {
        return Err(QueryError::NotContentSubspace); // s_C only (mirror M5 DeleteError)
    }
    let np = p.ordinal.clone();
    let nc = w.m5().content_count(d);
    if width.is_zero() {
        return Err(QueryError::EmptyWidth); // mirror M5 EmptyWidth
    }
    if np < Nat::one() || &np + width > &nc + Nat::one() {
        return Err(QueryError::OutOfBounds); // folds M5's NotArranged + OutOfBounds (width ≥ 1)
    }

    let del_span = vspan(&Nat::one(), &np, width); // [s_C, np] × [0, width]
    let a_del = w.m5().resolve(d, &del_span); // no clipping now (bounds checked)
    let pre = if np > Nat::one() {
        Some(vspan(&Nat::one(), &Nat::one(), &(&np - Nat::one())))
    } else {
        None
    };
    let suf_start = &np + width;
    let suf = if suf_start <= nc {
        Some(vspan(&Nat::one(), &suf_start, &(&nc - &suf_start + Nat::one())))
    } else {
        None
    };
    let mut retained = w.m5().link_runs(d); // a text delete never touches links
    for sp in [pre, suf].into_iter().flatten() {
        retained.extend(w.m5().resolve(d, &sp));
    }
    // The a_del QUERY endset is non-empty under the bounds check (every
    // deleted position is arranged, so resolve returns ≥ 1 run); cand — the
    // stab RESULT — is legitimately empty whenever no link touches the range,
    // so its emptiness is never asserted.
    let cand = stab_union(w, &Endset::from_spans(a_del.iter().map(Run::iextent)));
    let surv = if retained.is_empty() {
        OrdSet::new() // mirror findlinks_v: keep the ∅-query off M7's stab
    } else {
        stab_union(w, &Endset::from_spans(retained.iter().map(Run::iextent)))
    };
    Ok(OrphanReport {
        orphaned: cand.relative_complement(surv).into_iter().collect(),
    })
}
