//! §6 — the pre-edit link-survival check (ASN-0117): a pure what-if over the
//! snapshot — it never calls M5's delete — built on the F-UDIST set identity
//! `orphaned = findlinks(A_del) ∖ findlinks(retained_range)` over the ACTIVE
//! view (a nullified link that lost its last witness in `d` is NOT reported —
//! a deliberate divergence from ASN-0117's `D(d,Σ)` over `dom(L)`,
//! Conflicts #8).

use num_traits::{One, Zero};
use skep_address::{content_subspace, Address, Nat, Span};
use skep_arrangement::VPos;
use skep_kernel::Snapshot;

use crate::helpers::stab_runs;
use crate::region::content_vspan;
use crate::types::{OrphanError, OrphanReport};
use crate::DiscoveryWorld;

/// [`content_vspan`] at a bare content `ordinal`: `count` positions from it,
/// built through the query surface's own V-span constructor — so the spans
/// this hands `resolve` are the shape `resolve` reads and the shape the
/// region gate accepts. Total where the published constructor is partial: the
/// subspace is `s_C` here by construction, and the callers' width ≥ 1 guard
/// excludes `count = 0`, the only other thing declined.
fn content_vspan_at(ordinal: &Nat, count: &Nat) -> Span {
    let at = VPos {
        subspace: content_subspace(),
        ordinal: ordinal.clone(),
    };
    content_vspan(&at, count).expect("s_C ∧ width ≥ 1 ⇒ count ≥ 1")
}

/// Pre-edit what-if (ASN-0117): the links the proposed DELETE `[p, p+width)`
/// would drop from `d` — read-only, never the edit path.
///
/// Refuses exactly the requests DELETE refuses, so the preview is of the
/// REQUESTED delete and never a silently-clipped different one:
/// `DocNotRegistered`; non-`s_C` `p` → `NotContentSubspace`; zero `width` →
/// `EmptyWidth`; and `p < 1 ∨ p + width > n_C + 1` → `OutOfBounds`, the single
/// check to which M5's `NotArranged` + `OutOfBounds` pair is jointly
/// equivalent under width ≥ 1.
///
/// The accepted set is M5's exactly. Two LABELS differ, both where M5 would
/// say `NotArranged` (`p ∉ [1, n_C]`): this reports `OutOfBounds` when
/// `width ≥ 1`, and `EmptyWidth` when `width = 0`, because the width check
/// runs ahead of the bounds check here and behind it in M5. A caller relaying
/// a refusal verbatim relays a different word for the same refusal, never a
/// different verdict.
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
pub fn delete_orphans_on<W: DiscoveryWorld>(
    s: &Snapshot<W>,
    d: &Address,
    p: &VPos,
    width: &Nat,
) -> Result<OrphanReport, OrphanError> {
    let w = s.world();
    if !w.m3().is_registered_document(d) {
        return Err(OrphanError::DocNotRegistered);
    }
    if p.subspace != content_subspace() {
        return Err(OrphanError::NotContentSubspace); // s_C only (mirror M5 DeleteError)
    }
    let np = p.ordinal.clone();
    let nc = w.m5().content_count(d);
    if width.is_zero() {
        return Err(OrphanError::EmptyWidth); // mirror M5 EmptyWidth
    }
    if np < Nat::one() || &np + width > &nc + Nat::one() {
        return Err(OrphanError::OutOfBounds); // folds M5's NotArranged + OutOfBounds (width ≥ 1)
    }

    let a_del = w.m5().resolve(d, &content_vspan_at(&np, width)); // no clipping now (bounds checked)
    let pre = if np > Nat::one() {
        Some(content_vspan_at(&Nat::one(), &(&np - Nat::one())))
    } else {
        None
    };
    let suf_start = &np + width;
    let suf = if suf_start <= nc {
        Some(content_vspan_at(&suf_start, &(&nc - &suf_start + Nat::one())))
    } else {
        None
    };
    let mut retained = w.m5().link_runs(d); // a text delete never touches links
    for sp in [pre, suf].into_iter().flatten() {
        retained.extend(w.m5().resolve(d, &sp));
    }
    let cand = stab_runs(w.links(), &a_del);
    let surv = stab_runs(w.links(), &retained);
    Ok(OrphanReport {
        orphaned: cand.relative_complement(surv).into_iter().collect(),
    })
}
