//! §A RETRIEVEV (ASN-0115): resolve, then dereference — the one operation
//! that delivers bytes, and so the one impl block bounded by `HasContent`.

use skep_address::Address;
use skep_arrangement::reading_surface;
use skep_content::HasContent;

use super::{run_origin, Query, RetrievalWorld};
use crate::error::RetrieveError;
use crate::types::{Delivery, DeliveryItem, Spec};
use crate::vspan::{gate_vspan, Subspace};

/// RETRIEVEV alone opens M4, so RETRIEVEV alone names it: `HasContent` is
/// this impl block's bound and nowhere else's, which is what makes the other
/// six operations' value-blindness structural rather than a rule their cards
/// ask a maintainer to keep — and `tests/it/tidy.rs` holds it, failing on any
/// other file under `src/` that names the content store.
impl<W: RetrievalWorld + HasContent> Query<'_, W> {
    /// RETRIEVEV (ASN-0115) — resolve, then dereference, in order (the
    /// load-bearing two-phase factoring): resolve V-spans to I-addresses
    /// (M5), then fetch values (M4, content) or pass the address through
    /// (links — never reads M4).
    ///
    /// The arrangement resolved is each named document's READING SURFACE
    /// (crate doc, *Which arrangement an operation answers from*): the gate
    /// runs on the address named, the surface answers, and the delivery is
    /// reported under the name given.
    ///
    /// Rejects the WHOLE request on any malformed spec (well-formedness
    /// precondition); gaps / depth-incompatible (`#start ≥ 3`) / foreign or
    /// empty subspaces degrade to silent empty contributions, never an error
    /// (R6 — M5's defensive `resolve` returns fewer-or-zero runs). Empty
    /// spec-set ⇒ `Ok(empty)`. Delivery is one item per active V-position of
    /// every DELIVERED run (R3 exactness, R8 no-dedup) — and one
    /// [`DeliveryItem::Withheld`] per run whose origin is not a registered
    /// document, occupying that run's `width` positions (PUB-1.57): the one
    /// masking the identity predicate leaves, since the predicate is
    /// contracted to registered documents (PUB-6.37) and RES-162's unheld
    /// origin — a mirror that never held the draft a published window names —
    /// is a run this form can meet. Per-spec concatenation in submitted order
    /// (R5), ascending-V within, no merge, no global sort.
    ///
    /// WHICH REFUSAL SPEAKS. The gate walks the spec-set in SUBMITTED ORDER
    /// and reports the FIRST faulty spec, whatever the kind of its fault;
    /// within one spec the registry check precedes the span gate. So
    /// `MalformedSpec { index: i }` and `DocNotRegistered` both carry a
    /// promise about the specs before the offending one: a caller may rely on
    /// specs `0..i` being registered documents with well-formed spans, and
    /// repair a batch by walking forward rather than re-checking it whole.
    ///
    /// COST IS THE ANSWER'S SIZE, AND THE ANSWER'S SIZE IS A PRODUCT M6 MAY
    /// NOT NARROW. The delivery is `Σᵢ |σᵢ ∩ [1, n_Sᵢ]|` items, so `k` specs
    /// each naming a whole document deliver `k · n_C` items — one `Arc` clone
    /// per item, never a byte copy, but one item nonetheless — and `k` is the
    /// caller's. R3 forbids delivering fewer, R5 forbids reordering into
    /// something cheaper and R8 forbids collapsing the repeats, so no refusal
    /// M6 could add here would leave RETRIEVEV the operation ASN-0115
    /// specifies. The only cap that closes it is a spec-count or response-size
    /// cap on the route, which is M10's as the request lifecycle's owner.
    pub fn retrieve_v(&self, specs: &[Spec]) -> Result<Delivery, RetrieveError> {
        // The masked form under the all-true predicate: its only `Withheld`
        // items are unregistered-origin runs (PUB-6.37; RES-162). M10's
        // dispatch calls [`Query::retrieve_v_masked`] with the predicate it
        // threads in per request; this delegate serves the callers that read
        // for no principal — this crate's suite and skep-engine's cross-store
        // lifecycle suite — unchanged.
        self.retrieve_v_masked(specs, &|_| true)
    }

    /// RETRIEVEV with the per-origin consult (PUB-6.41; PUB round 2, lane 3.3,
    /// §2/§4): the same delivery, but each RUN is tested against its origin
    /// DOCUMENT (M1's `document_of` of the run's I-start, which block
    /// uniformity makes the origin of every position in it) through
    /// `readable`, and a masked run — its origin unreadable to the reading
    /// principal, OR unregistered — is emitted as [`DeliveryItem::Withheld`]
    /// AT ITS OWN POSITION rather than delivered (PUB-6.58: one item per run,
    /// never coalesced). The NAMED document's own readability is the caller's
    /// doc-argument consult (PUB-6.12), run pre-dispatch; this masks only the
    /// ORIGINS its runs window. M6 decides no readability here — it applies
    /// the predicate M10 threads in, at the run, which is the granularity the
    /// delivery has.
    ///
    /// THE PREDICATE'S OWN PRECONDITION IS DISCHARGED HERE. `readable` is
    /// contracted to REGISTERED documents (PUB-6.37, the rule
    /// `reading_surface` is under too), and the gate established that of the
    /// documents NAMED, not of the origins their runs window; so each origin
    /// is checked against the registry before the predicate is asked, and one
    /// that is not a registered document — reachable as RES-162's unheld
    /// origin, the mirror that never held the draft a published window names
    /// — takes the withheld arm directly, the predicate unconsulted. The
    /// predicate is consulted only after the gate has passed the whole
    /// request (a rejected request consults it of nothing), once per resolved
    /// run with a registered origin, of the origin document alone — which may
    /// be a version address — and never of the document named.
    pub fn retrieve_v_masked(
        &self,
        specs: &[Spec],
        readable: &dyn Fn(&Address) -> bool,
    ) -> Result<Delivery, RetrieveError> {
        let w = self.0.world();
        let (m3, m5, content) = (w.m3(), w.m5(), w.content());
        // Gate the whole request first — VSpec WELL-FORMEDNESS is the only
        // in-model failure (ASN-0115). A well-formed but depth-incompatible
        // (#start ≥ 3) spec is NOT rejected here (R6).
        for (index, spec) in specs.iter().enumerate() {
            if !m3.is_registered_document(&spec.doc) {
                return Err(RetrieveError::DocNotRegistered(spec.doc.clone()));
            }
            gate_vspan(&spec.span)
                .map_err(|fault| RetrieveError::MalformedSpec { index, fault })?;
        }
        let mut out = Vec::new();
        for spec in specs {
            // Concatenate per spec, IN ORDER (R5) — no global sort. Classify
            // ONCE per spec, because the answer is constant over the spec's
            // positions. Gated on the address named above; the surface
            // answers.
            let sub = Subspace::of_span(&spec.span);
            let surface = reading_surface(m3, &spec.doc);
            for run in m5.resolve(&surface, &spec.span) {
                // The per-origin consult (PUB-6.41), asked once per run: the
                // run's origin DOCUMENT, tested BEFORE the run is expanded.
                // The registry check first is the predicate's precondition
                // (PUB-6.37: registered documents only), M6's to discharge at
                // this site because the gate saw the named document and not
                // the origin; an unregistered origin (RES-162) is withheld
                // without the predicate being asked. Either way the WHOLE run
                // is masked as one withheld item at its own position — never
                // coalesced with a neighbour (PUB-6.58).
                let origin = run_origin(&run);
                if !m3.is_registered_document(&origin) || !readable(&origin) {
                    out.push(DeliveryItem::Withheld { origin, width: run.width().clone() });
                    continue;
                }
                // Per active position, ascending V (R3) — no dedup (R8); the
                // run answers for its own positions, in the owned form, since
                // `resolve` hands the run over and it outlives only this walk.
                for a in run.into_addrs() {
                    match sub {
                        // S3★ — an arranged content position has an M4 value
                        // — is kept on M5's WRITE path, and this read is
                        // where a regression in it would surface. The two
                        // sites that keep it: `insert` rides mint, write and
                        // place in one transaction, and `copy` places only
                        // runs its `SourceNotContentSubspace` (no link
                        // address at a content position) and per-run
                        // `DanglingSource` (M4 holds the run's start) guards
                        // admit. Widening either is what would put an
                        // address here that M4 never stored.
                        Some(Subspace::Content) => out.push(DeliveryItem::Content(
                            content
                                .value_at(a.tumbler())
                                .expect("S3★: an arranged content position has a stored value")
                                .clone(),
                        )),
                        // The link reference IS the address — never reads M4.
                        Some(Subspace::Link) => out.push(DeliveryItem::Ref(a)),
                        // UNREACHABLE for an ACTIVE position: S3★-aux
                        // confines every bound V-position to subspace ∈
                        // {s_C, s_L}, and `resolve` yields NO runs for any
                        // other start subspace, so executing here means
                        // upstream corruption. PANIC IN ALL PROFILES — one
                        // read-path policy with the S3★ `expect` above:
                        // silently dropping an active position would violate
                        // exactness (R3).
                        None => unreachable!(
                            "active V-position must be content or link subspace (S3★-aux)"
                        ),
                    }
                }
            }
        }
        Ok(Delivery(out)) // empty spec-set ⇒ Ok(Delivery(vec![]))
    }
}
