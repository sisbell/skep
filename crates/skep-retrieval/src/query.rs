//! §§A–C, D (SHOWDELETIONS), E — six of the seven operations (COMPARE lives
//! in `compare`). Every operation begins by reading its slices off the single
//! bound snapshot, runs its gate (typed rejection), then composes upstream
//! primitives.

use num_traits::{One, Zero};
use skep_address::{document_of, ordinal, union, Address, Nat, Span, SpanSet};
use skep_arrangement::{ordinal_vspan, M5State, Run, VPos};

use crate::error::{DeletionsError, ExtentError, FindError, OriginError, RetrieveError};
use crate::helpers::{debug_assert_sequential_positions, dedup_addrs, gate_vspan, S_C, S_L};
use crate::types::{Deletions, Delivery, DeliveryItem, RegionSpec, Spec};
use crate::{M6World, Query};

/// `ext(d, S) = ([S, 1], [0, n_S])` — the per-subspace exact extent span
/// (ASN-0113 W2/W4: a count fixes an extent under sequential positions). The
/// anchor is written ONCE, here, as the subspace origin `[S, 1]` — never
/// absorbed into a confluent summary, which is how the negative-origin hazard
/// (0112 OQ5) is designed out.
///
/// Built with M5's `ordinal_vspan`, so the extent M6 REPORTS is the shape M5's
/// `resolve` READS: the constructor and the recognizer every request span is
/// folded through are the two halves of one definition and cannot come apart.
/// `None` iff `n_S == 0`, which both call sites have already excluded.
fn ext_span(s: Nat, n: &Nat) -> Span {
    ordinal_vspan(
        &VPos {
            subspace: s,
            ordinal: Nat::one(),
        },
        n,
    )
    .expect("n_S ≥ 1 ⇒ a nonempty extent")
}

/// The enumeration of `CURRENT(·, d)` on the content side (ASN-0075's
/// predicate; ASN-0124 calls the set `ran_C(d)`) — every content I-address
/// `d`'s arrangement currently binds, in V order. M5's own `content_image` is
/// the same set and is private, so it is NOT called here.
///
/// `CURRENT` is a set and this is an enumeration WITH MULTIPLICITY: an
/// address placed at two V-positions of `d` by intra-document transclusion is
/// yielded twice, so callers dedup.
fn current_content(m5: &M5State, d: &Address) -> Vec<Address> {
    let runs = m5.content_runs(d);
    runs.iter().flat_map(Run::addrs).collect()
}

impl<'s, W: M6World> Query<'s, W> {
    /// RETRIEVEV (ASN-0115) — resolve, then dereference, in order (the
    /// load-bearing two-phase factoring): resolve V-spans to I-addresses
    /// (M5), then fetch values (M4, content) or pass the address through
    /// (links — never reads M4).
    ///
    /// Rejects the WHOLE request on any malformed spec (well-formedness
    /// precondition); gaps / depth-incompatible (`#start ≥ 3`) / foreign or
    /// empty subspaces degrade to silent empty contributions, never an error
    /// (R6 — M5's defensive `resolve` returns fewer-or-zero runs). Empty
    /// spec-set ⇒ `Ok(empty)`. Delivery is one item per active V-position
    /// (R3 exactness, R8 no-dedup), per-spec concatenation in submitted
    /// order (R5), ascending-V within, no merge, no global sort.
    pub fn retrieve_v(&self, specs: &[Spec]) -> Result<Delivery, RetrieveError> {
        let w = self.0.world();
        let (m3, m5, c) = (w.m3(), w.m5(), w.content());
        // Gate the whole request first — VSpec WELL-FORMEDNESS is the only
        // in-model failure (ASN-0115). A well-formed but depth-incompatible
        // (#start ≥ 3) spec is NOT rejected here (R6).
        for (i, s) in specs.iter().enumerate() {
            if !m3.is_registered_document(&s.doc) {
                return Err(RetrieveError::DocNotRegistered(s.doc.clone()));
            }
            gate_vspan(&s.span).map_err(|f| RetrieveError::MalformedSpec { index: i, fault: f })?;
        }
        let mut out = Vec::new();
        for s in specs {
            // Concatenate per spec, IN ORDER (R5) — no global sort. The gate
            // guarantees #start ≥ 2 and zero-free, so get(1) is the subspace
            // at any depth (1 = content, 2 = link).
            let sub = s.span.start().get(1).expect("the gate ⇒ #start ≥ 2");
            for run in m5.resolve(&s.doc, &s.span) {
                // Per active position, ascending V (R3) — no dedup (R8); the
                // run answers for its own positions.
                for a in run.addrs() {
                    if *sub == *S_C {
                        out.push(DeliveryItem::Content(
                            c.value_at(a.tumbler())
                                .expect("S3★: an arranged content position has a stored value")
                                .clone(),
                        ));
                    } else if *sub == *S_L {
                        // The link reference IS the address — never reads M4.
                        out.push(DeliveryItem::Ref(a));
                    } else {
                        // UNREACHABLE for an ACTIVE position: S3★-aux
                        // confines every bound V-position to subspace ∈
                        // {s_C, s_L}, and `resolve` yields NO runs for any
                        // other start subspace, so executing here means
                        // upstream corruption. PANIC IN ALL PROFILES — one
                        // read-path policy with the S3★ `expect` above:
                        // silently dropping an active position would violate
                        // exactness (R3).
                        unreachable!(
                            "active V-position must be content or link subspace (S3★-aux)"
                        );
                    }
                }
            }
        }
        Ok(Delivery(out)) // empty spec-set ⇒ Ok(Delivery(vec![]))
    }

    /// RETRIEVEDOCVSPAN (ASN-0112) — the whole-document bounding span:
    /// singleton `⟨σ_d⟩`, or `⟨⟩` for a registered-empty document; a document
    /// that is not registered ⇒ Err. Across subspaces it is a bounding box
    /// bridging the inter-subspace void, insensitive to mid-document content
    /// edits (V9) — by design (route fragmentation-sensitive callers to
    /// `doc_vspanset`).
    ///
    /// σ_d IS the hull of the per-subspace extents, so it is taken from
    /// [`Query::doc_vspanset`] rather than derived a second time: the registry
    /// gate, the D-SEQ★ trust and the count-read all happen once, in one
    /// place. Those extents are W13-normalized, so the FIRST member's start is
    /// the anchor `[s, 1]` of the lowest occupied subspace and the LAST
    /// member's reach is one ordinal step past the highest occupied position.
    ///
    /// `from_endpoints` is INFALLIBLE on that pair: both endpoints are depth-2
    /// (no `LevelMismatch`) and `min.start ≤ max.start < max.reach` (no
    /// `NotIncreasing`); the stored width `reach ⊖ min` round-trips exactly —
    /// `divergence(min, reach) ≤ #min` discharges D1, INCLUDING the
    /// cross-subspace box — so the singleton is faithfully ASN-0112's
    /// `σ_d = (origin_d, extent_d)`.
    pub fn doc_vspan(&self, doc: &Address) -> Result<SpanSet, ExtentError> {
        let extents = self.doc_vspanset(doc)?;
        let (Some(min), Some(max)) = (extents.iter().next(), extents.iter().last()) else {
            return Ok(SpanSet::empty()); // registered-empty ⇒ ⟨⟩
        };
        Ok(SpanSet::singleton(
            Span::from_endpoints(min.start().clone(), &max.reach())
                .expect("min.start < max.reach at one depth-2 length"),
        ))
    }

    /// RETRIEVEDOCVSPANSET (ASN-0113) — per-subspace exact extents: ≤2
    /// members (content, then link), already W13-normalized; `⟨⟩` for a
    /// registered-empty document; a document that is not registered ⇒ Err.
    ///
    /// The count-read core of both extent queries. M5's O(1)
    /// `content_count`/`link_count` ARE the extents, because each subspace's
    /// occupied V-positions form the dense, origin-anchored run `[S, 1..n_S]`
    /// (D-SEQ★ — the sequential-position occupancy ASN-0113 W4 forces; M5's
    /// write-path property, trusted here and tripwired in debug). Built by
    /// `union` of singletons — concatenation preserves the already-disjoint,
    /// content-before-link normal form (asserted in debug); no invented M1
    /// constructor.
    pub fn doc_vspanset(&self, doc: &Address) -> Result<SpanSet, ExtentError> {
        let w = self.0.world();
        let (m3, m5) = (w.m3(), w.m5());
        if !m3.is_registered_document(doc) {
            return Err(ExtentError::DocNotRegistered); // not registered ⇒ fail
        }
        debug_assert_sequential_positions(m5, doc);
        let (nc, nl) = (m5.content_count(doc), m5.link_count(doc));
        let mut result = SpanSet::empty();
        if !nc.is_zero() {
            result = union(&result, &SpanSet::singleton(ext_span((*S_C).clone(), &nc)));
        }
        if !nl.is_zero() {
            result = union(&result, &SpanSet::singleton(ext_span((*S_L).clone(), &nl)));
        }
        debug_assert!(
            result.is_normalized(),
            "W13: content-before-link, subspace-separated ⇒ already normal"
        );
        Ok(result)
    }

    /// SHOWORIGIN over a V-span (ASN-0077, V-arity) — block-decompose, then
    /// project ONE origin per run (`document_of`, M1): block uniformity (O2)
    /// means all addresses in one run share an origin, so this is O(runs),
    /// not O(positions). Returns deduplicated origin documents in tumbler
    /// order; for the link subspace `document_of(link)` is the home document
    /// (CL-OWN) — handled uniformly, no special case. The I-arity is
    /// de-scoped (see the crate docs); only this V-arity exists.
    ///
    /// Inadmissible (Err) — reject, never silently clamp (O13): a document
    /// that is not registered (WF_V i), a malformed span (ii/iv), a foreign
    /// subspace (`NoSuchSubspace`) or empty real subspace (`EmptySubspace`,
    /// iii), a depth-incompatible `#start ≥ 3` span (`DepthIncompatible`,
    /// WF_V v — its own check, kept distinct from the range case so a client
    /// can tell "wrong depth" from "unbound positions"), and a depth-2 span
    /// overrunning the bound prefix (`RangeNotPresent`, WF_V vi — the
    /// depth-agnostic `resolved < ordinal(width)` test).
    pub fn show_origin_v(&self, doc: &Address, span: &Span) -> Result<Vec<Address>, OriginError> {
        let w = self.0.world();
        let (m3, m5) = (w.m3(), w.m5());
        if !m3.is_registered_document(doc) {
            return Err(OriginError::DocNotRegistered); // WF_V (i)
        }
        gate_vspan(span).map_err(OriginError::MalformedSpan)?; // (ii)/(iv)
        // subspace at any depth (gate ⇒ #start ≥ 2)
        let sub = span.start().get(1).expect("the gate ⇒ #start ≥ 2");
        let n_s = if *sub == *S_C {
            m5.content_count(doc)
        } else if *sub == *S_L {
            m5.link_count(doc)
        } else {
            // Foreign subspace ∉ {s_C, s_L}: distinct from a real-but-empty
            // subspace.
            return Err(OriginError::NoSuchSubspace);
        };
        if n_s.is_zero() {
            return Err(OriginError::EmptySubspace); // (iii)
        }
        if span.start().len() != 2 {
            return Err(OriginError::DepthIncompatible); // (v): depth must equal m_S ≡ 2
        }
        // Span now depth-2 (≥ 3 rejected above); resolve may still be partial
        // if the span overruns the bound prefix.
        let runs = m5.resolve(doc, span);
        let resolved = runs.iter().fold(Nat::zero(), |acc, r| acc + r.width());
        // The nominal count is read via ordinal(width) — the last component,
        // which level-uniformity ties to #start — keeping the overrun test
        // depth-agnostic, not a hard-coded get(2).
        if &resolved < ordinal(span.width()) {
            return Err(OriginError::RangeNotPresent); // (vi): reject, never clamp (O13)
        }
        Ok(dedup_addrs(runs.iter().map(|r| {
            document_of(r.i_start()).expect("an element-level I-address has a Document prefix")
        })))
    }

    /// SHOWDELETIONS (ASN-0075) — gate, then membership-test the
    /// cross-document combine IN M6 from M5's per-document primitives:
    /// `DeletedFromAWithB = { a : CURRENT(a, d_b) ∧ DELETED(a, d_a) }` and its
    /// symmetric twin. CURRENT(·, d) is enumerated by [`current_content`],
    /// which asks each content run for its addresses exactly as RETRIEVEV
    /// does; DELETED(·, d) is tested by membership in M5's per-document
    /// deleted cover (`deletions(d).denotes(a)`) — exact *unconditionally* by
    /// `difference_sets`' denotational contract
    /// (`⟦deletions(d)⟧ = {x : DELETED(x, d)}` whatever the cover's internal
    /// span packing), so there are no false positives. Never opens M4; both
    /// halves read off the one bound snapshot (single consistent `(M, R)` —
    /// no torn-read phantom deletion).
    ///
    /// Both documents must be registered (Err otherwise; `d_a` checked
    /// first); registered-empty is fine and yields empty halves. Each half is
    /// the deduped, Tumbler-ordered set of the EXISTING I-addresses
    /// (D-IDENT — never copies; D-ORD).
    ///
    /// COST IS UNBOUNDED AND M6 DOES NOT BOUND IT — and unlike RETRIEVEV's,
    /// it is not bounded by the answer either. No span narrows the request, so
    /// both documents are enumerated WHOLE: the work is
    /// `n_C(d_a)·|deletions(d_b)| + n_C(d_b)·|deletions(d_a)|`, paid in full
    /// even when the two share nothing and both halves come back empty. M6
    /// owns no admission control and no refusal for it: capping request rate
    /// and concurrency for a route carrying this read is M10's, as the request
    /// lifecycle's owner.
    pub fn show_deletions(
        &self,
        d_a: &Address,
        d_b: &Address,
    ) -> Result<Deletions, DeletionsError> {
        let w = self.0.world();
        let (m3, m5) = (w.m3(), w.m5());
        for d in [d_a, d_b] {
            if !m3.is_registered_document(d) {
                return Err(DeletionsError::DocNotRegistered(d.clone()));
            }
        }
        let del_a = m5.deletions(d_a); // { a : DELETED(a, d_a) } as a per-level-class cover
        let del_b = m5.deletions(d_b); // { a : DELETED(a, d_b) }
        // CURRENT in the one document ∧ DELETED from the other, both ways.
        let deleted_from_a_with_b = dedup_addrs(
            current_content(m5, d_b)
                .into_iter()
                .filter(|a| del_a.denotes(a.tumbler())),
        );
        let deleted_from_b_with_a = dedup_addrs(
            current_content(m5, d_a)
                .into_iter()
                .filter(|a| del_b.denotes(a.tumbler())),
        );
        Ok(Deletions {
            deleted_from_a_with_b,
            deleted_from_b_with_a,
        })
    }

    /// FINDDOCSCONTAINING (ASN-0124 `finddocs`) — resolve, then a
    /// present-tense filter over M5's historical superset: phase 1 unions each
    /// region span's `image` (raw, possibly mixed-length — M5's
    /// `docs_ever_containing`/`project` apply the level-class discipline
    /// INTERNALLY, so M6 passes the raw union straight through and owns no
    /// level-class discipline anywhere); phase 2 narrows the tumbler-ordered
    /// candidate superset with `project(d, coverage)` non-emptiness — the
    /// present-tense soundness filter (FD-SOUND), which is what separates this
    /// live answer from M5's `docs_ever_containing` (FD-HIST), the two
    /// differing exactly by FD-GHOST's ghosts. Returns bare deduplicated
    /// identities, tumbler-ordered — no positions, no counts (FD codomain;
    /// present-tense CONTAINERS, distinct from SHOWORIGIN's allocators).
    ///
    /// Every named document must be registered and every region span
    /// well-formed (Err otherwise — a malformed span would silently
    /// UNDER-resolve and drop containers, violating FD-COMPLETE); the gate
    /// does NOT restrict subspace — a link/foreign-subspace span passes and
    /// stays inert downstream (R⁻¹ indexes content provenance only, J-LV),
    /// and a depth-incompatible span resolves to empty coverage
    /// (consulting-state, like RETRIEVEV's R6). Registered-empty contributes
    /// nothing.
    ///
    /// Emptiness is tested with M1's `SpanSet::is_empty` — denotationally
    /// exact because no algebra result carries a zero-width member (zero
    /// members ⇔ empty denotation), the predicate the design's M1-seam ask
    /// named (landed in the built M1).
    ///
    /// COST IS UNBOUNDED AND M6 DOES NOT BOUND IT. The candidate scan is
    /// `|coverage|` — the union of the region images, itself unbounded in the
    /// spans a caller may name — against the whole of M5's R⁻¹ index, and the
    /// filter runs one `project` per candidate. M6 owns no admission control
    /// and no refusal for it: capping request size, rate and concurrency for a
    /// route carrying this read is M10's, as the request lifecycle's owner.
    pub fn find_docs_containing(&self, regions: &[RegionSpec]) -> Result<Vec<Address>, FindError> {
        let w = self.0.world();
        let (m3, m5) = (w.m3(), w.m5());
        // The gate first, over the WHOLE request — the first fault wins, and
        // no upstream work is done for a request that will be rejected.
        for (ri, r) in regions.iter().enumerate() {
            if !m3.is_registered_document(&r.doc) {
                return Err(FindError::DocNotRegistered(r.doc.clone()));
            }
            for (si, span) in r.spans.iter().enumerate() {
                gate_vspan(span).map_err(|f| FindError::MalformedSpan {
                    region: ri,
                    index: si,
                    fault: f,
                })?;
            }
        }
        // Phase 1: resolve to content I-coverage. Raw mixed-length cover;
        // union is concatenation.
        let mut coverage = SpanSet::empty();
        for r in regions {
            for span in &r.spans {
                coverage = union(&coverage, &m5.image(&r.doc, span));
            }
        }
        // Phase 2: the historical superset (tumbler-ordered, level-classes
        // handled inside M5), narrowed by the present-tense filter — one
        // `project` per candidate.
        let candidates = m5.docs_ever_containing(&coverage);
        Ok(candidates
            .into_iter()
            .filter(|d| !m5.project(d, &coverage).is_empty()) // FD-SOUND
            .collect())
    }
}
