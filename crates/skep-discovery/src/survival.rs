//! §6 — the pre-edit link-survival check (ASN-0117), which the crate calls
//! the delete-orphan preview: which links a proposed DELETE would ORPHAN from
//! `d`. The survival it checks is a link's discoverability from `d`, the one
//! thing ASN-0117 lets a delete take: ASN-0117's own LINK SURVIVAL — the link
//! and its coverage outlasting every DELETE — holds by construction, and no
//! read checks it. A pure what-if over the snapshot — it never calls M5's
//! delete — built on the F-UDIST set identity
//! `orphaned = findlinks(A_del) ∖ findlinks(retained)` over the ACTIVE
//! view (a nullified link that lost its last witness in `d` is NOT reported —
//! a deliberate divergence from ASN-0117's `D(d,Σ)` over `dom(L)`,
//! Conflicts #8). The preview is of the DELETE requested, never of a clipped
//! one: it restates M5's DELETE admission, which M5 keeps private, in
//! [`DeletePartition::of`], the one element here a change to DELETE's
//! admission changes.

use num_traits::{One, Zero};
use skep_address::{Address, Nat, Span};
use skep_arrangement::{M5State, Run, VPos};
use skep_kernel::Snapshot;

use crate::budget::MAX_IMAGE_RUNS;
use crate::home::home_readable;
use crate::image::content_vspan;
use crate::sets::stab_runs;
use crate::types::{OrphanError, OrphanReport};
use crate::DiscoveryWorld;

/// `d`'s content as a requested DELETE `[p, p + width)` partitions it —
/// ASN-0117's three-region (prefix/deleted/suffix) partition: the range it
/// takes, and the prefix `[1, p)` and suffix `[p + width, n_C]` it leaves,
/// each `None` where it is empty — no prefix at `p = 1`, and no suffix once
/// the range reaches `n_C`. All three are built by the query surface's own
/// V-span constructor, [`content_vspan`], so what M5 resolves is the shape the
/// region gate accepts.
struct DeletePartition {
    deleted: Span,
    prefix: Option<Span>,
    suffix: Option<Span>,
}

impl DeletePartition {
    /// The partition, or the refusal of the range's shape —
    /// `NotContentSubspace`, then `EmptyWidth`, then `OutOfBounds` — that M5's
    /// DELETE gives the same request, in the order and under the labels
    /// [`delete_orphans_on`] states. The document gate is not this element's:
    /// the preview asks it first, as M5's DELETE does.
    ///
    /// A RESTATEMENT. M5 keeps DELETE's admission pair (ASN-0117)
    /// crate-private — `arranges_content_position`, the position test behind
    /// its `NotArranged` (`p ∈ [1, n_C]`), and `contains_content_range`, the
    /// containment test behind its `OutOfBounds` (`p + width ≤ n_C + 1`) — so
    /// the bounds check here is a second statement of the two, folded into one
    /// check as [`delete_orphans_on`] states. The two statements change
    /// together: the admission grid in `tests/it/survival.rs` holds this one to
    /// M5's DELETE on every request it draws. The partition is built from the
    /// check's own arithmetic, so the deleted range is never clipped and
    /// neither side's count can underflow — the check holds `p ≥ 1` and
    /// `p + width ≤ n_C + 1`.
    fn of(
        m5: &M5State,
        d: &Address,
        p: &VPos,
        width: &Nat,
    ) -> Result<DeletePartition, OrphanError> {
        if !p.is_content() {
            return Err(OrphanError::NotContentSubspace); // s_C only (mirror M5 DeleteError)
        }
        let p_ordinal = &p.ordinal;
        if width.is_zero() {
            return Err(OrphanError::EmptyWidth); // mirror M5 EmptyWidth
        }
        let suffix_start = p_ordinal + width; // the first position past the deleted range
        let content_end = m5.content_count(d) + Nat::one(); // n_C + 1, past the arranged content
        if p_ordinal.is_zero() || suffix_start > content_end {
            return Err(OrphanError::OutOfBounds); // folds M5's NotArranged + OutOfBounds, width ≥ 1
        }
        let suffix_count = &content_end - &suffix_start;
        Ok(DeletePartition {
            deleted: content_vspan(p, width)
                .expect("p is s_C and width ≥ 1, both refused above when not"),
            prefix: content_vspan(&VPos::content(Nat::one()), &(p_ordinal - Nat::one())),
            suffix: content_vspan(&VPos::content(suffix_start), &suffix_count),
        })
    }
}

/// Pre-edit what-if (ASN-0117): the links the proposed DELETE `[p, p+width)`
/// would orphan from `d` — read-only, never the edit path.
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
/// end of the range that falls INSIDE a run: M5's resolution clips a run to
/// the span asked, so the prefix, the deleted range and the suffix each take
/// a piece of a run the range cuts. So a `d` whose own runs are past the
/// budget is refused every range; a `d` that one or two cut runs would carry
/// past it — at the budget, or one run under — is refused exactly the ranges
/// that cut that many; and every other `d` is answered for every range. A
/// faulty request names its own fault first.
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
/// reasoning. Both sides stab the ACTIVE view through the region family's
/// lift, so a link whose coverage meets `d`'s run extents only strictly
/// beneath a deleted address is reported orphaned — the one shape the crate
/// header states — though it has no witness in `d` in ASN-0117's sense (an
/// arranged address its coverage contains), and ASN-0117's `D(d,Σ)`, over
/// ASN-0098's membership, never counted it discoverable from `d`. The
/// global-ghost determination (LP17 — discoverable from NO document) reaches
/// provenance R and is M6 territory; M8 stops at the per-document set.
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
    // DELETE's checks of the range's shape, restated, and the partition the
    // range makes of `d`'s content.
    let DeletePartition {
        deleted,
        prefix,
        suffix,
    } = DeletePartition::of(w.m5(), d, p, width)?;
    // The run budget as `d` alone already settles it, off M5's own `#runs`,
    // which reads no run: the partition's three spans cover `[1, n_C]` and
    // every content run contributes at least one piece, so this is a LOWER
    // bound on the exact count taken after they resolve, and refuses nothing
    // that check would admit. What it buys is that a `d` past the budget
    // however the range falls is refused without its arrangement being
    // resolved into a vector first.
    let link_run_count = w.m5().link_run_count(d);
    if w.m5().content_run_count(d) + link_run_count > MAX_IMAGE_RUNS {
        return Err(OrphanError::ImageTooLarge);
    }

    let a_del = w.m5().resolve(d, &deleted);
    // The surviving CONTENT runs, pulled off M5's lazy resolution straight into
    // `retained`, so no side is collected into a vector of its own only to be
    // drained. `d`'s link runs are retained too — a text delete never touches
    // links — and are chained onto these where the query is lifted, so M5's
    // loan of them is read rather than copied.
    let mut retained: Vec<Run> = Vec::new();
    for span in [prefix, suffix].into_iter().flatten() {
        retained.extend(w.m5().iter_resolve(d, &span));
    }
    // The run budget, exactly, on the side of the join the preview supplies:
    // the runs both stabs below take as their query, after every check of the
    // request. The content is counted RESOLVED because the exact count holds
    // the pieces the range's two ends cut out of runs, which no count M5
    // publishes shows; the link runs, which no text range cuts, are counted
    // off M5's own `#runs` — the count the pre-check read — so they are never
    // touched to be counted.
    if a_del.len() + retained.len() + link_run_count > MAX_IMAGE_RUNS {
        return Err(OrphanError::ImageTooLarge);
    }
    let touching_deleted = stab_runs(w.links(), &a_del);
    let touching_retained = stab_runs(w.links(), retained.iter().chain(w.m5().link_runs(d)));
    // The relative complement is walked from the DELETED side — a link
    // touching what goes is kept unless the retained side also holds it —
    // NEVER `im`'s `difference`, which is SYMMETRIC and would fold in the
    // plainly-surviving links, and not `im`'s `relative_complement`, which
    // walks its argument, the retained side, through `im`'s copying consuming
    // iterator.
    Ok(OrphanReport {
        orphaned: touching_deleted
            .iter()
            .filter(|&a| !touching_retained.contains(a)) // the relative complement, from the deleted side
            .filter(|&a| home_readable(readable, a)) // PUB-6.13 — drop unreadable-home orphans
            .cloned()
            .collect(),
    })
}
