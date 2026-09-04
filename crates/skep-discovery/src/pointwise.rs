//! §5 — pointwise projection & discoverability (content subspace): `project`
//! (ASN-0098 I→V, through M5's level-class-safe `project`) and
//! `addressably_discoverable_from` (ASN-0098's LP12 discoverability narrowed
//! to ASN-0121/0132's addressable population, `dom(L) ∖ nullified`). The two
//! read the active view differently, and deliberately:
//! `addressably_discoverable_from` conjoins `is_active`, while `project`
//! reports the recorded coverage M7's `followlink` hands over, retracted
//! links included.
//! The per-link `classify_spans` touch test here is M8's one
//! pointwise span comparison — a level-gate-free order relation, total on
//! cross-length spans, categorically distinct from the level-gated set
//! algebra M8 avoids.

use skep_address::{classify_spans, Address, Span, SpanRel, SpanSet};
use skep_kernel::Snapshot;
use skep_links::Endset;

use crate::types::QueryError;
use crate::DiscoveryWorld;

/// I→V projection of link `a`'s `slot` into `d`'s CONTENT subspace (ASN-0098
/// `project`).
///
/// UNFILTERED — the one read here that is not narrowed to the active view.
/// The coverage comes from M7's `followlink`, which takes no `View` and
/// reports what is recorded, so a NULLIFIED link's slot still projects to the
/// V-positions it covers. That is ASN-0098's `project`, which knows nothing of
/// retraction; the addressable-narrowed question — is this link discoverable
/// AND active? — is [`addressably_discoverable_from_on`], and a caller who
/// wants "the live links reaching here" asks that or the region family, not
/// this.
///
/// CONTENT-SUBSPACE ONLY — strictly weaker than ASN-0098's subspace-agnostic
/// `project`: a link reachable solely through `d`'s LINK subspace projects ∅
/// here (a non-empty projection witnesses discoverability through content
/// only; LP12's biconditional holds only within the content subspace). The
/// link-subspace POSITIONAL projection that would close that gap is NOT M7's
/// BH3 (BH3 is typed reverse *lookup*, target→sources — it yields no
/// V-positions); it is the scoped-out contextual EL11a, composed above M8.
///
/// `NotALink` subsumes BOTH `a ∉ dom(L)` AND an out-of-range `slot` (M7's
/// `followlink` conflates them; a `BadSlot` split is deferred — it would cost
/// an extra `readlink` to read arity).
///
/// The result is a NORMALIZED set of depth-2 content V-spans
/// (`[s_C, ordinal] × [0, count]`) in `d`'s own V-coordinates, M5's `project`
/// guarantee handed back verbatim — so a caller reads the covered positions
/// straight off the spans. The two probe routes are `SpanSet` membership
/// (`denotes(&[s_C, k])` over `k ∈ 1..=content_count(d)`, cross-checkable via
/// M5's `point`) and `SpanSet::is_empty`, which is total where the
/// level-gated set comparisons can fault. M8 itself never tests the
/// projection for emptiness.
pub fn project_on<W: DiscoveryWorld>(
    s: &Snapshot<W>,
    a: &Address,
    slot: usize,
    d: &Address,
) -> Result<SpanSet, QueryError> {
    let w = s.world();
    if !w.m3().is_registered_document(d) {
        return Err(QueryError::DocNotRegistered);
    }
    let cov = w
        .links()
        .followlink(a, slot)
        .map_err(|_| QueryError::NotALink)?; // Err(Invalid) ⇒ NotALink (a ∉ dom(L) OR slot OOB)
    Ok(w.m5().project(d, &cov)) // I→V, content subspace, level-class-safe inside M5
}

/// `coverage(e) ∩ ⋃ extents ≠ ∅` — pointwise, mirroring M7's stab overlap
/// relations (ProperOverlap | Containment | Equal, never Adjacent).
/// `classify_spans` is a pure, level-gate-free order relation, total on
/// cross-length spans (a link-address span against a content run classifies
/// by plain tumbler order — no fault), so the cross-subspace cases just work.
/// Vacuously false over an empty extent list.
///
/// `extents` are the I-extents of the document's runs, lifted by the caller:
/// this is asked once per slot of a link, and a run's extent depends on the
/// run alone, so the lift belongs where the runs are read.
fn touches(e: &Endset, extents: &[Span]) -> bool {
    e.spans().any(|s| {
        extents.iter().any(|x| {
            matches!(
                classify_spans(s, x),
                SpanRel::ProperOverlap | SpanRel::Containment | SpanRel::Equal
            )
        })
    })
}

/// Is `a` discoverable from `d` AND addressable? Both halves are the corpus's
/// own words in their corpus senses: `discoverable_from` is ASN-0098's LP12
/// (arrangement-reachable, derived and per-document), and `addressable` is
/// ASN-0121/0132's population `dom(L) ∖ nullified`. Their conjunction is
/// STRICTLY stronger than LP12 alone (Conflicts #8) — a nullified-but-
/// reachable link is discoverable and not addressable, so it answers
/// `Ok(false)`. Bare LP12, which predates retraction, is M7's `followlink`
/// composed with M5's `project`.
///
/// Tests LP12's characterisation directly per link —
/// `∃ i : coverage(Σ.L(a).eᵢ) ∩ ran(M(d)) ≠ ∅` over BOTH subspaces
/// (`content_runs` + `link_runs`) — conjoined with `is_active(a)`; O(arity ×
/// |runs|), never the F-FULL whole-document-stab membership route. The test
/// iterates the link's full arity, so it carries no arity-3 caveat.
///
/// `Err(NotALink)` iff `a ∉ dom(L)` (aligned with `project`'s non-link
/// handling). A *nullified* link is still a link: it passes the residence
/// gate and returns `Ok(false)` through the `is_active` conjunct —
/// distinguishing "not a link" from "a retracted link". A registered-but-
/// empty `d` short-circuits to `Ok(false)` (nothing is reachable; `touches`
/// over an empty extent list is vacuously false, so the early-out is cheap,
/// not a correctness guard).
pub fn addressably_discoverable_from_on<W: DiscoveryWorld>(
    s: &Snapshot<W>,
    a: &Address,
    d: &Address,
) -> Result<bool, QueryError> {
    let w = s.world();
    if !w.m3().is_registered_document(d) {
        return Err(QueryError::DocNotRegistered);
    }
    let link = w.links().readlink(a).ok_or(QueryError::NotALink)?;
    if !w.links().is_active(a) {
        return Ok(false); // the ADDRESSABLE half (Conflicts #8)
    }
    let extents: Vec<Span> = w
        .m5()
        .content_runs(d)
        .into_iter()
        .chain(w.m5().link_runs(d))
        .map(|r| r.iextent())
        .collect(); // ran(M(d)) as I-extents, BOTH subspaces (LP12)
    if extents.is_empty() {
        return Ok(false); // registered-empty d ⇒ nothing reachable
    }
    Ok((1..=link.arity()).any(|i| touches(link.slot(i).expect("i ≤ arity"), &extents)))
}
