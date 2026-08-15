//! §5 — pointwise projection & discoverability (content subspace): `project`
//! (ASN-0098 I→V, through M5's level-class-safe `project`) and
//! `discoverable_from` (the compound "arrangement-reachable AND active" —
//! NOT pure LP12). The per-link `classify_spans` touch test here is M8's one
//! pointwise span comparison — a level-gate-free order relation, total on
//! cross-length spans, categorically distinct from the level-gated set
//! algebra M8 avoids.

use skep_address::{classify_spans, Address, SpanRel, SpanSet};
use skep_arrangement::{HasM5, Run};
use skep_kernel::{Snapshot, WorldState};
use skep_links::{Endset, HasLinks};
use skep_namespace::HasM3;

use crate::types::QueryError;

/// I→V projection of link `a`'s `slot` into `d`'s CONTENT subspace (ASN-0098
/// `project`).
///
/// CONTENT-SUBSPACE ONLY — strictly weaker than ASN-0098's subspace-agnostic
/// `project`: a link reachable solely through `d`'s LINK subspace projects ∅
/// here (`project(a, slot, d) ≠ ∅` witnesses discoverability through content
/// only; LP12's biconditional holds only within the content subspace). The
/// link-subspace POSITIONAL projection that would close that gap is NOT M7's
/// BH3 (BH3 is typed reverse *lookup*, target→sources — it yields no
/// V-positions); it is the scoped-out contextual EL11a, composed above M8.
///
/// `NotALink` subsumes BOTH `a ∉ dom(L)` AND an out-of-range `slot` (M7's
/// `followlink` conflates them; a `BadSlot` split is deferred — it would cost
/// an extra `readlink` to read arity). The returned `SpanSet` is handed back
/// verbatim — M8 never tests the projection for emptiness; a caller probes it
/// with `SpanSet` membership (`denotes(&[s_C, k])` over
/// `k ∈ 1..=content_count(d)`, cross-checkable via M5's `point`) or an
/// emptiness check (`equiv(&proj, &SpanSet::empty())`).
pub fn project_on<W>(
    s: &Snapshot<W>,
    a: &Address,
    slot: usize,
    d: &Address,
) -> Result<SpanSet, QueryError>
where
    W: WorldState + HasLinks + HasM5 + HasM3,
{
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

/// `coverage(e) ∩ ⋃ runs ≠ ∅` — pointwise, mirroring M7's stab overlap
/// relations (ProperOverlap | Containment | Equal, never Adjacent).
/// `classify_spans` is a pure, level-gate-free order relation, total on
/// cross-length spans (a link-address span against a content run classifies
/// by plain tumbler order — no fault), so the cross-subspace cases just work.
/// Vacuously false over an empty run list.
fn touches(e: &Endset, runs: &[Run]) -> bool {
    e.spans().any(|s| {
        runs.iter().any(|r| {
            matches!(
                classify_spans(s, &r.iextent()),
                SpanRel::ProperOverlap | SpanRel::Containment | SpanRel::Equal
            )
        })
    })
}

/// NOT pure LP12 — active-filtered (Conflicts #8). The compound
/// "arrangement-reachable AND active": a nullified-but-reachable link returns
/// `Ok(false)` where LP12 (which predates retraction) would call it
/// discoverable. For raw LP12 compose M7's `followlink` + M5's `project`
/// yourself.
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
/// over an empty run list is vacuously false, so the early-out is cheap, not
/// a correctness guard).
pub fn discoverable_from_on<W>(s: &Snapshot<W>, a: &Address, d: &Address) -> Result<bool, QueryError>
where
    W: WorldState + HasLinks + HasM5 + HasM3,
{
    let w = s.world();
    if !w.m3().is_registered_document(d) {
        return Err(QueryError::DocNotRegistered);
    }
    let link = w.links().readlink(a).ok_or(QueryError::NotALink)?;
    if !w.links().is_active(a) {
        return Ok(false); // the ACTIVE half of the compound (Conflicts #8)
    }
    let full: Vec<Run> = w
        .m5()
        .content_runs(d)
        .into_iter()
        .chain(w.m5().link_runs(d))
        .collect(); // ran(M(d)), BOTH subspaces (LP12)
    if full.is_empty() {
        return Ok(false); // registered-empty d ⇒ nothing reachable
    }
    Ok((1..=link.arity())
        .any(|i| touches(link.slot(i).expect("i ≤ arity"), &full)))
}
