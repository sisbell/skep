//! §1/§2/§4 — the content-region discovery family (V-anchored, present-tense,
//! doc-gated, disjunctive over slots) — `findlinks_v`, `count_v`, `window_v`
//! and RETRIEVEENDSETS — each ASN-0127's two-phase query: [`image_on`], the
//! region resolver that lives in `image`, chained into M7's matcher. Every
//! result is ASN-0131's selection index `sel = findlinks_V ∩ addressable`,
//! read out four ways — nullified links never surface (Conflicts #8, a
//! deliberate divergence from ASN-0127/0108's `findlinks_V`/`Match`, which no
//! addressability filter narrows). Its touch is M7's overlap with the image's
//! run extents, wider than ASN-0127's `matches` on the one shape the crate
//! header states.

use std::collections::HashSet;

use im::OrdSet;
use skep_address::{Address, Span};
use skep_kernel::Snapshot;
use skep_links::Endset;

use crate::budget::MAX_ANSWER_SPANS;
use crate::home::home_readable;
use crate::image::image_on;
use crate::sets::{stab_runs, stab_runs_by_slot, union_slots, window_over};
use crate::types::{Cursor, QueryError, Window};
use crate::DiscoveryWorld;

/// The region family's shared selection index: the disjunctive ASN-0127
/// `findlinks(image(W,d))` ∩ the active view (View::Active internally ==
/// addressable == `dom(L)` ∖ nullified), as M7's native `OrdSet<Address>`
/// (address order — ASN-0108's permanent enumeration key). The image reaches
/// M7 as its runs' I-extents, so the touch is M7's overlap with them — wider
/// than ASN-0127's `matches` on the one shape the crate header states.
fn findlinks_v_set_on<W: DiscoveryWorld>(
    s: &Snapshot<W>,
    d: &Address,
    region: &[Span],
) -> Result<OrdSet<Address>, QueryError> {
    let image = image_on(s, d, region)?; // document gate + region gate + resolve, on THIS snap
    Ok(stab_runs(s.world().links(), &image))
}

/// Links touching `region` (ASN-0127 findlinks over the image, disjunctive
/// across slots `{FROM, TO, TYPE}` — exact by the v1 arity-3 invariant — and
/// touched by M7's overlap with the image's run extents, which the crate
/// header states is wider than ASN-0127's `matches` on one shape), in
/// ASCENDING ADDRESS ORDER: ASN-0108's permanent enumeration key, so this
/// enumerates in the order [`window_v_on`] pages by.
/// result = `findlinks_V ∩ addressable` (`View::Active`) — nullified links
/// never surface; diverges from ASN-0127's `findlinks_V` over all of
/// `dom(L)` (Conflicts #8).
///
/// REFUSES what [`image_on`] refuses, in its order — `DocNotRegistered`,
/// `BadRegion`, `ImageTooLarge` — and nothing else: a request none of the
/// three refuses is answered, ∅ included. A registered `d` and a well-formed
/// region (one built through [`crate::content_vspan`] included) get past only
/// the first two; the budgets still judge what the region asks of `d`'s
/// surface, so a caller that has checked both must still handle
/// `ImageTooLarge`.
///
/// The result-set filter (PUB round 2, lane 3.3, §3; PUB-6.13): every link
/// whose HOME `readable` refuses is DROPPED, at link IDENTITY, before the
/// caller sees it. M7's link readers stay principal-free (Conflicts #1); the
/// filter is M8's, applied over the selection index.
pub fn findlinks_v_on<W: DiscoveryWorld>(
    s: &Snapshot<W>,
    d: &Address,
    region: &[Span],
    readable: &dyn Fn(&Address) -> bool,
) -> Result<Vec<Address>, QueryError> {
    let sel = findlinks_v_set_on(s, d, region)?;
    Ok(sel.iter().filter(|&a| home_readable(readable, a)).cloned().collect())
}

/// Present-tense census of region-reaching links; the cardinality of
/// `findlinks_V ∩ addressable`. Non-monotone (ASN-0127 D-NONMONO); a `0`
/// asserts that, over the active view, no link the reader may see is
/// presently reachable — not history (D-ZERO) — the region family's zero,
/// distinct from [`crate::count_ftt_on`]'s store-wide CN-ZERO.
///
/// REFUSES what [`image_on`] refuses, in its order: `DocNotRegistered`,
/// `BadRegion`, `ImageTooLarge`. The zero above is therefore a census and
/// never a stand-in for a refusal: an unregistered `d` errs rather than
/// counting 0, which is precisely the distinction a caller collapsing this
/// `Result` to a number would lose.
///
/// The cardinality is the FILTERED one (PUB round 2, lane 3.3, §3;
/// PUB-6.19): of the links the home rule admits, by ENUMERATION — the same
/// set [`findlinks_v_on`] returns under the same `readable`, counted rather
/// than collected, so the two cannot disagree given a predicate that answers
/// each home the same way in both calls (the crate header states the
/// predicate's contract).
pub fn count_v_on<W: DiscoveryWorld>(
    s: &Snapshot<W>,
    d: &Address,
    region: &[Span],
    readable: &dyn Fn(&Address) -> bool,
) -> Result<usize, QueryError> {
    let sel = findlinks_v_set_on(s, d, region)?;
    Ok(sel.iter().filter(|&a| home_readable(readable, a)).count())
}

/// Windowed enumeration of the region family (ASN-0108, the
/// `Match = findlinks_V` reading); result = `findlinks_V ∩ addressable` —
/// nullified links never surface. `n = 0` is clamped to 1 (the API is total,
/// W9); a window holds at most `max(n, 1)` links, and [`Window`] states what
/// a window and a pass return.
///
/// EVERY `Address` IS A LEGAL CURSOR, and none is checked: resume is a
/// key-cut strictly past `cur`, never a lookup of it, so a cursor naming a
/// link that has since been nullified or has left the region still resumes
/// at the right place (W8), and no continuously-matching link is skipped or
/// duplicated (W4/W5). A caller relaying a cursor from a request owes it no
/// validation — validating would refuse exactly the case the key-cut exists
/// to serve.
///
/// REFUSES what [`image_on`] refuses, in its order: `DocNotRegistered`,
/// `BadRegion`, `ImageTooLarge`. A refusal is never reported as an empty
/// exhausted window.
///
/// The result-set filter (PUB round 2, lane 3.3, §3): the home rule is
/// applied LAZILY during the key-cut, at link identity and BEFORE the window
/// slice (PUB-6.14), so a link it refuses is skipped rather than counted
/// against `n`.
pub fn window_v_on<W: DiscoveryWorld>(
    s: &Snapshot<W>,
    d: &Address,
    region: &[Span],
    cur: Cursor,
    n: usize,
    readable: &dyn Fn(&Address) -> bool,
) -> Result<Window, QueryError> {
    let sel = findlinks_v_set_on(s, d, region)?; // document gate + region gate inside
    Ok(window_over(&sel, cur, n, |a| home_readable(readable, a)))
}

/// RETRIEVEENDSETS (ASN-0131): the `(slot, endset)` pairs touching `region`,
/// WITHHOLDING link identity (RE-UNIT) — value-identical endsets from
/// distinct links collapse to one pair. Endsets are surfaced WHOLE — the full
/// stored value from `readlink`, never clipped (RE-CLIP/RE-WHOLE, preserving
/// RE-UDIST) — and content-identity (I-address; V-rendering is a lossy layer
/// above). Slot attribution is read off M7's per-slot stab sets — `(i, eᵢ)`
/// surfaces iff `a ∈ stab(i, query, Active)` — so M7's overlap verdict
/// (ProperOverlap | Containment | Equal, never Adjacent) is the ONLY touch
/// test and cross-subspace disjointness (RE-NCD) is discharged by M7. Output
/// order is pinned — ascending slot, then the endsets' span sequences
/// compared lexicographically, each span by its `(start, width)` in tumbler
/// order (`Span` has no order of its own) — and so deterministic at a
/// snapshot.
///
/// Refuses past [`MAX_ANSWER_SPANS`] with `EndsetsTooLarge`, accumulated over
/// the spans of the pairs actually KEPT — what the answer carries is what the
/// budget prices, so the identity-withholding collapse counts once, as it
/// ships once — and checked AS THE ANSWER IS PRODUCED, so an over-budget
/// request stops accumulating and never reaches the sort. A refusal, never a
/// truncation: a short answer would silently withhold endsets that touch the
/// region, which is the one thing RE-UNIT does not license.
///
/// REFUSES, IN THIS ORDER: [`image_on`]'s three — `DocNotRegistered`,
/// `BadRegion`, `ImageTooLarge` — and then this read's own
/// `EndsetsTooLarge`, which comes last because it is priced on what the
/// store hands back and so cannot be known until the image is in hand.
///
/// The result-set filter (PUB round 2, lane 3.3, §3; PUB-6.15): filtered at
/// link HOME, UNFILTERED at origin — a link whose home the reader may not
/// read contributes no pair, but a surviving link's endset is surfaced WHOLE,
/// its spans never masked by their origin. So the home rule is asked at the
/// CANDIDATE link's identity, once, before its slots are read.
pub fn retrieve_endsets_on<W: DiscoveryWorld>(
    s: &Snapshot<W>,
    d: &Address,
    region: &[Span],
    readable: &dyn Fn(&Address) -> bool,
) -> Result<Vec<(usize, Endset)>, QueryError> {
    let w = s.world();
    let image = image_on(s, d, region)?; // document gate + region gate inside, on THIS snap
    let by_slot = stab_runs_by_slot(w.links(), &image); // KEPT SEPARATE — slot i of a touches iff a ∈ its set
    let sel = union_slots(&by_slot);
    // Dedup by structural Eq, keyed on borrows into the store's endsets — a
    // pair is copied once, when it ships.
    let mut kept: HashSet<(usize, &Endset)> = HashSet::new();
    let mut spans_kept: usize = 0;
    for a in sel.iter() {
        // The home rule (PUB-6.13), at the candidate link's identity: a link
        // whose home is unreadable contributes no pair. Its endset — if it
        // survived — is unfiltered at origin (PUB-6.15).
        if !home_readable(readable, a) {
            continue;
        }
        let link = w.links().readlink(a).expect("stab keys are resident links");
        for (i, hits) in &by_slot {
            if hits.contains(a) {
                let e = link
                    .slot(*i)
                    .expect("a link in slot i's stab set has slot i: M7's per-slot overlap is false for an absent slot");
                if kept.insert((*i, e)) {
                    // WHOLE endset, no clip
                    spans_kept += e.len();
                    if spans_kept > MAX_ANSWER_SPANS {
                        return Err(QueryError::EndsetsTooLarge);
                    }
                }
            }
        }
    }
    let mut pairs: Vec<(usize, &Endset)> = kept.into_iter().collect();
    // Unstable is exact here: the pairs are distinct, and the comparator is
    // equal only on equal pairs — slot, then each span's `(start, width)`,
    // which is the whole of `Span`'s equality — so no two elements tie.
    pairs.sort_unstable_by(|(i, e), (j, f)| {
        i.cmp(j).then_with(|| {
            e.spans()
                .map(|sp| (sp.start(), sp.width()))
                .cmp(f.spans().map(|sp| (sp.start(), sp.width())))
        })
    });
    Ok(pairs.into_iter().map(|(i, e)| (i, e.clone())).collect())
}
