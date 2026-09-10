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

use crate::budget::MAX_IMAGE_RUNS;
use crate::home::home_readable;
use crate::region::content_vspan;
use crate::sets::stab_runs;
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
/// Refuses the requests DELETE refuses on its checks of the REQUEST — its
/// target's registration and its range's shape — so the preview is of the
/// REQUESTED delete and never a silently-clipped different one:
/// `DocNotRegistered`; non-`s_C` `p` → `NotContentSubspace`; zero `width` →
/// `EmptyWidth`; and `p < 1 ∨ p + width > n_C + 1` → `OutOfBounds`, the
/// single check to which M5's `NotArranged` + `OutOfBounds` pair is jointly
/// equivalent under width ≥ 1.
///
/// TWO of M5's DELETE refusals have no counterpart here, and they are not
/// alike:
///
/// * The ω GATE, by decision. M5 refuses a caller who does not own `d` with
///   `NotOwner`; this takes no `Caller`, so it answers alike for every asker,
///   and a non-owner previewing a delete they cannot perform gets the
///   preview. That is not M8's word to withhold — ownership is M5's rule and
///   the session is M10's — and it is a fact about the ASKER, where every
///   check above is a fact about the request.
/// * The PUBLICATION refusal, as a GAP and not a decision. M5 refuses
///   `PublishedTarget` (PUB-2.11) on a `d` whose document is published —
///   after registration, ahead of every shape check this mirrors, and for
///   `Caller::System` as for a principal — so a published `d` is refused
///   there and answered here. That is a fact about the request's TARGET,
///   which the reason given for the ω gate does not reach, and it does worse
///   than answer for an edit M5 refuses: on a published `d` with a member,
///   this reads `d`'s own arrangement, frozen at its pre-chain state, while
///   every reader of `d` answers from its trunk head — so the report
///   describes positions no reader of `d` sees. On every `d` M5's DELETE
///   admits, `d` IS its own reading surface, which is why the preview reads
///   `d` and does not float.
///
/// And ONE refusal is the preview's own, which DELETE has no word for
/// because DELETE stabs nothing: `ImageTooLarge`, asked last, when the runs
/// the two stabs below would join are past [`crate::MAX_IMAGE_RUNS`]. Every
/// stab walks the whole link store testing each query span against every
/// slot span of every link, so these runs are the side of that join the
/// preview supplies, held to the number the region family holds its image
/// to. The runs counted are `d`'s own, content and link, plus one for each
/// end of the range that falls INSIDE a run: M5's `resolve` clips a run to
/// the span asked, so the prefix, the deleted range and the suffix each take
/// a piece of a run the range cuts. So a `d` whose own runs are past the
/// budget is refused every range; a `d` that one or two cut runs would carry
/// past it — at the budget, or one run under — is refused exactly the ranges
/// that cut that many; and every other `d` is answered for every range. A
/// faulty request names its own fault first. The runs are resolved before
/// they are counted, M5 publishing no count, so a refused preview has paid
/// for reading them and for no stab.
///
/// The accepted set is M5's DELETE admission minus those two gates, and minus
/// every request whose runs, as its range splits them, are past the run
/// budget. Two LABELS differ within it, both where M5 would say `NotArranged`
/// (`p ∉ [1, n_C]`): this reports `OutOfBounds` when `width ≥ 1`, and
/// `EmptyWidth` when `width = 0`, because the width check runs ahead of the
/// bounds check here and behind it in M5. A caller relaying a refusal
/// verbatim relays a different word for the same refusal, never a different
/// verdict.
///
/// The report's `orphaned` is in ascending address order — the permanent key
/// every enumeration here reads out by, inherited from walking the links that
/// touch the deleted range in that order.
///
/// `orphaned = findlinks(A_del) ∖ findlinks(retained)` where `retained` =
/// the prefix + suffix content that survives plus the link runs (a text
/// delete never touches links) — the last-witness condition with no per-pair
/// reasoning. Both sides stab the ACTIVE view. The relative complement is
/// walked from the DELETED side — a link touching what goes is kept unless
/// the retained side also holds it — NEVER `im`'s `difference`, which is
/// SYMMETRIC and would fold in the plainly-surviving links, and not `im`'s
/// `relative_complement`, which walks its argument, the retained side,
/// through `im`'s copying consuming iterator. The global-ghost determination
/// (LP17 — discoverable from NO document) reaches provenance R and is M6
/// territory; M8 stops at the per-document set.
///
/// The result-set filter (PUB round 2, lane 3.3, §3): the orphaned set drops
/// every link whose HOME `readable` refuses, at link identity — a `d`
/// argument's own readability is the caller's doc-argument consult
/// (pre-dispatch), not this preview's. The home rule runs AFTER the set
/// identity, so it changes which orphans are reported and never which links
/// are orphaned.
pub fn delete_orphans_on<W: DiscoveryWorld>(
    s: &Snapshot<W>,
    d: &Address,
    p: &VPos,
    width: &Nat,
    readable: &dyn Fn(&Address) -> bool,
) -> Result<OrphanReport, OrphanError> {
    let w = s.world();
    if !w.m3().is_registered_document(d) {
        return Err(OrphanError::DocNotRegistered);
    }
    if p.subspace != content_subspace() {
        return Err(OrphanError::NotContentSubspace); // s_C only (mirror M5 DeleteError)
    }
    let p_ordinal = &p.ordinal;
    let n_c = w.m5().content_count(d);
    if width.is_zero() {
        return Err(OrphanError::EmptyWidth); // mirror M5 EmptyWidth
    }
    let suffix_start = p_ordinal + width; // the first position past the deleted range
    if *p_ordinal < Nat::one() || suffix_start > &n_c + Nat::one() {
        return Err(OrphanError::OutOfBounds); // folds M5's NotArranged + OutOfBounds (width ≥ 1)
    }

    let a_del = w.m5().resolve(d, &content_vspan_at(p_ordinal, width)); // no clipping now (bounds checked)
    let prefix = if *p_ordinal > Nat::one() {
        Some(content_vspan_at(&Nat::one(), &(p_ordinal - Nat::one())))
    } else {
        None
    };
    let suffix = if suffix_start <= n_c {
        Some(content_vspan_at(
            &suffix_start,
            &(&n_c - &suffix_start + Nat::one()),
        ))
    } else {
        None
    };
    let mut retained = w.m5().link_runs(d); // a text delete never touches links
    for span in [prefix, suffix].into_iter().flatten() {
        retained.extend(w.m5().resolve(d, &span));
    }
    // The run budget, on the side of the join the preview supplies: the runs
    // both stabs below take as their query, after every check of the request.
    if a_del.len() + retained.len() > MAX_IMAGE_RUNS {
        return Err(OrphanError::ImageTooLarge);
    }
    let touching_deleted = stab_runs(w.links(), &a_del);
    let touching_retained = stab_runs(w.links(), &retained);
    Ok(OrphanReport {
        orphaned: touching_deleted
            .iter()
            .filter(|&a| !touching_retained.contains(a)) // the relative complement, from the deleted side
            .filter(|&a| home_readable(readable, a)) // §3 — drop unreadable-home orphans
            .cloned()
            .collect(),
    })
}
