//! §1/§2/§4 — the content-region discovery family (V-anchored, present-tense,
//! doc-gated, disjunctive over slots) — `findlinks_v`, `count_v`, `window_v`
//! and RETRIEVEENDSETS — each ASN-0127's two-phase query: [`image_on`], the
//! region resolver that lives in `image`, chained into M7's matcher, home by
//! home. Every result is ASN-0131's selection index `sel = findlinks_V ∩
//! addressable`, read out four ways — nullified links never surface
//! (Conflicts #8, a deliberate divergence from ASN-0127/0108's
//! `findlinks_V`/`Match`, which no addressability filter narrows). Its touch
//! is M7's overlap with the image's run extents, wider than ASN-0127's
//! `matches` on the one shape the crate header states.
//!
//! The family's composition is homes-first (PUB-7.18, at every slot): the
//! image's extents are lifted to one query, M7's `homes_touching` names the
//! candidate homes of that query at every v1 slot in address order, the
//! reader is asked of each once ahead of its links, and an admitted home is
//! stabbed once, at every slot together, over the spans that named it at
//! each and at the parts of the stab whose ranges named it — M7's
//! `stab_in_slots`, which answers the home's `(link, slot)` pairs in address
//! order and builds no set per slot, so a home holding no hit on the query
//! costs those parts and nothing else. The per-home answers concatenated in
//! home order are the selection index in address order, so nothing is
//! merged and a window resumes in its cursor's home. The pieces
//! the composition shares with the descriptor family and the delete preview
//! — the slot list, the extents' lift, the probes, the disjunction over
//! slots, the window over homes — are `sets`'.

use std::collections::HashSet;

use skep_address::{Address, Span};
use skep_kernel::Snapshot;
use skep_links::{Endset, Link, LinkState, Touch, View};

use crate::budget::MAX_ANSWER_SPANS;
use crate::home::home_admitted;
use crate::image::image_on;
use crate::sets::{distinct, extents, probes, window_homes, V1_SLOTS};
use crate::types::{Cursor, QueryError, Window};
use crate::DiscoveryWorld;

/// The candidate homes of `query` at every v1 slot, in address order, each
/// with the spans that named it per slot — M7's walk over the three
/// `(slot, query)` pairs, pair `i` being [`V1_SLOTS`]`[i]`.
fn touching<'l>(l: &'l LinkState, query: &'l Endset) -> impl Iterator<Item = Touch<'l>> + 'l {
    l.homes_touching(V1_SLOTS.map(|slot| (slot, query)))
}

/// One admitted home's share of the selection index, per slot and KEPT
/// SEPARATE — slot `i` of `a` touches iff the pair `(a, i)` is among them —
/// as M7's per-home stab answers it over the spans that named the home at
/// each slot, at the parts that named them, in address order and then slot
/// order. `View::Active` discharges addressability — nullified links never
/// match.
fn touched_by_slot(l: &LinkState, touch: &Touch<'_>) -> Vec<(Address, usize)> {
    l.stab_in_slots(touch, probes(0), View::Active)
}

/// One admitted home's share of the selection index: the disjunction over
/// its slots (ASN-0127's `findlinks` OR, M7 having no slot-collapsed
/// primitive), each link once, in address order.
fn touched(l: &LinkState, touch: &Touch<'_>) -> impl Iterator<Item = Address> {
    distinct(touched_by_slot(l, touch))
}

/// The region family's selection index under a reader, home by home: for
/// each candidate home of the image at any slot, in address order, admitted
/// by `readable` once ahead of its links, that home's touching links. The
/// disjunctive ASN-0127 `findlinks(image(W,d))` ∩ the active view, as the
/// concatenation of per-home answers — address order, ASN-0108's permanent
/// enumeration key, since a home's links are one key range of the store.
fn selection<'a>(
    l: &'a LinkState,
    query: &'a Endset,
    readable: &'a dyn Fn(&Address) -> bool,
) -> impl Iterator<Item = Address> + 'a {
    touching(l, query)
        .filter(move |touch| home_admitted(readable, touch.home()))
        .flat_map(move |touch| touched(l, &touch))
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
/// The result-set filter (PUB round 2, lane 3.3, §3; PUB-6.13, PUB-7.18):
/// every link whose HOME `readable` refuses is never read — the rule is
/// asked of each candidate home ONCE, ahead of its links, and a refused
/// home's links are left unstabbed — so the answer's cost follows the
/// readable homes' links and the count of candidate homes, never the links
/// of a home the reader may not read. M7's link readers stay principal-free
/// (Conflicts #1); the composition is M8's.
pub fn findlinks_v_on<W: DiscoveryWorld>(
    s: &Snapshot<W>,
    d: &Address,
    region: &[Span],
    readable: &dyn Fn(&Address) -> bool,
) -> Result<Vec<Address>, QueryError> {
    let image = image_on(s, d, region)?; // document gate + region gate + resolve, on THIS snap
    let query = extents(&image);
    Ok(selection(s.world().links(), &query, readable).collect())
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
/// PUB-6.19): of the links homed where the home rule admits, by
/// ENUMERATION — the same per-home answers [`findlinks_v_on`] concatenates
/// under the same `readable`, counted rather than collected, so the two
/// cannot disagree given a predicate that answers each home the same way in
/// both calls (the crate header states the predicate's contract).
pub fn count_v_on<W: DiscoveryWorld>(
    s: &Snapshot<W>,
    d: &Address,
    region: &[Span],
    readable: &dyn Fn(&Address) -> bool,
) -> Result<usize, QueryError> {
    let image = image_on(s, d, region)?;
    let query = extents(&image);
    Ok(selection(s.world().links(), &query, readable).count())
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
/// LAZY (D5 of the home-index record): the cursor names the home to resume
/// in and the position within it, so the window passes the homes behind the
/// cursor unasked, cuts the cursor's home past it, and walks on home by home
/// until `n` links are in hand — paying for `n` and the homes it passes,
/// never for the population behind them. The result-set filter (PUB round 2,
/// lane 3.3, §3): the home rule is asked of each home it reaches, once,
/// BEFORE the window slice (PUB-6.14), so a refused home's links are skipped
/// unread rather than counted against `n`.
pub fn window_v_on<W: DiscoveryWorld>(
    s: &Snapshot<W>,
    d: &Address,
    region: &[Span],
    cur: Cursor,
    n: usize,
    readable: &dyn Fn(&Address) -> bool,
) -> Result<Window, QueryError> {
    let image = image_on(s, d, region)?; // document gate + region gate inside
    let query = extents(&image);
    let l = s.world().links();
    Ok(window_homes(
        touching(l, &query),
        |touch| touch.home(),
        |touch| touched(l, &touch).collect::<Vec<Address>>(),
        readable,
        cur,
        n,
    ))
}

/// RETRIEVEENDSETS (ASN-0131): the `(slot, endset)` pairs touching `region`,
/// WITHHOLDING link identity (RE-UNIT) — value-identical endsets from
/// distinct links collapse to one pair. Endsets are surfaced WHOLE — the full
/// stored value from `readlink`, never clipped (RE-CLIP/RE-WHOLE, preserving
/// RE-UDIST) — and content-identity (I-address; V-rendering is a lossy layer
/// above). Slot attribution is read off M7's per-slot, per-home stab —
/// `(i, eᵢ)` surfaces iff `(a, i)` is among `stab_in_slots`' pairs for
/// `a`'s home over the query — so M7's overlap verdict (ProperOverlap |
/// Containment | Equal, never Adjacent) is the ONLY touch test and
/// cross-subspace disjointness (RE-NCD) is discharged by M7. Output order is
/// pinned — ascending slot, then the endsets' span sequences compared
/// lexicographically, each span by its `(start, width)` in tumbler order
/// (`Span` has no order of its own) — and so deterministic at a snapshot.
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
/// its spans never masked by their origin. So the home rule is asked of each
/// candidate HOME, once, before any of its links' slots are read.
pub fn retrieve_endsets_on<W: DiscoveryWorld>(
    s: &Snapshot<W>,
    d: &Address,
    region: &[Span],
    readable: &dyn Fn(&Address) -> bool,
) -> Result<Vec<(usize, Endset)>, QueryError> {
    let w = s.world();
    let image = image_on(s, d, region)?; // document gate + region gate inside, on THIS snap
    let query = extents(&image);
    let l = w.links();
    // Dedup by structural Eq, keyed on borrows into the store's endsets — a
    // pair is copied once, when it ships.
    let mut kept: HashSet<(usize, &Endset)> = HashSet::new();
    let mut spans_kept: usize = 0;
    for touch in touching(l, &query) {
        // The home rule (PUB-6.13), at the candidate home: a home whose links
        // the reader may not read contributes no pair, and is never read. An
        // admitted home's surviving endsets are unfiltered at origin
        // (PUB-6.15).
        if !home_admitted(readable, touch.home()) {
            continue;
        }
        // KEPT SEPARATE — slot i of a touches iff (a, i) is a pair; a link's
        // pairs are adjacent, so it is read once.
        let by_slot = touched_by_slot(l, &touch);
        let mut read: Option<(&Address, &Link)> = None;
        for (a, i) in &by_slot {
            let link = match read {
                Some((at, link)) if at == a => link,
                _ => {
                    let link = l.readlink(a).expect("stab keys are resident links");
                    read = Some((a, link));
                    link
                }
            };
            let e = link
                .slot(*i)
                .expect("a link in slot i's stab pairs has slot i: M7's per-slot overlap is false for an absent slot");
            if kept.insert((*i, e)) {
                // WHOLE endset, no clip
                spans_kept += e.len();
                if spans_kept > MAX_ANSWER_SPANS {
                    return Err(QueryError::EndsetsTooLarge);
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
