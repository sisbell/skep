//! §§A–C, D (SHOWDELETIONS), E — six of the seven operations (COMPARE lives
//! in `compare`). Every operation begins by reading its slices off the single
//! bound snapshot, runs its gate (typed rejection), then composes upstream
//! primitives.

use num_traits::{One, Zero};
use skep_address::{document_of, ordinal, shift, union, Address, Nat, Span, SpanSet, Tumbler};
use skep_arrangement::{M5State, Run};

use crate::error::{DeletionsError, ExtentError, FindError, OriginError, RetrieveError};
use crate::helpers::{
    debug_assert_dense_occupancy, dedup_addrs, gate_vspec, is_registered, S_C, S_L,
};
use crate::types::{Deletions, Delivery, DeliveryItem, Region, Spec};
use crate::{M6World, Query};

/// A depth-2 V-position tumbler `[subspace, ordinal]`.
fn vpos(s: Nat, n: &Nat) -> Tumbler {
    Tumbler::new([s, n.clone()]).expect("a two-component sequence is nonempty")
}

/// `ext(d, S) = ([S, 1], [0, n_S])` — the per-subspace exact extent span
/// (ASN-0113 W2/W4: a count fixes an extent under dense occupancy).
fn ext_span(s: Nat, n: &Nat) -> Span {
    Span::new(
        Tumbler::new([s, Nat::one()]).expect("a two-component sequence is nonempty"),
        Tumbler::new([Nat::zero(), n.clone()]).expect("a two-component sequence is nonempty"),
    )
    .expect("n_S ≥ 1 makes the ordinal-level depth-2 extent T12-valid")
}

/// CURRENT(·, d) on the content side — every content I-address d's
/// arrangement currently binds (the math `content_image(d)`; M5's own
/// `content_image` is private and is NOT called here). May repeat an address
/// under intra-doc transclusion — callers dedup.
fn arranged_content(m5: &M5State, d: &Address) -> Vec<Address> {
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
            if !is_registered(m3, &s.doc) {
                return Err(RetrieveError::DocNotRegistered(s.doc.clone()));
            }
            gate_vspec(&s.span).map_err(|f| RetrieveError::MalformedSpec { index: i, fault: f })?;
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
    /// singleton `⟨σ_d⟩`, or `⟨⟩` for an allocated-empty document;
    /// unallocated ⇒ Err. Across subspaces it is a bounding box bridging the
    /// inter-subspace void, insensitive to mid-document content edits (V9) —
    /// by design (route fragmentation-sensitive callers to `doc_vspanset`).
    ///
    /// Synthesized from M5's O(1) `content_count`/`link_count`: the counts
    /// ARE the extents because each subspace's occupied V-positions form the
    /// dense, origin-anchored run `[S, 1..n_S]` (D-CTG★ — the dense-slice
    /// occupancy ASN-0113 W4 proves; M5's write-path property, trusted here).
    /// `min` is read as the subspace anchor `[s, 1]`, never absorbed into a
    /// confluent summary — the negative-origin hazard (0112 OQ5) is designed
    /// out.
    pub fn doc_vspan(&self, doc: &Address) -> Result<SpanSet, ExtentError> {
        let w = self.0.world();
        let (m3, m5) = (w.m3(), w.m5());
        if !is_registered(m3, doc) {
            return Err(ExtentError::DocNotRegistered); // unallocated ⇒ fail
        }
        debug_assert_dense_occupancy(m5, doc);
        let (nc, nl) = (m5.content_count(doc), m5.link_count(doc));
        if nc.is_zero() && nl.is_zero() {
            return Ok(SpanSet::empty()); // registered-empty ⇒ ⟨⟩
        }
        // min O(d): the anchor [s, 1] of the lowest occupied subspace.
        let min = vpos(
            if !nc.is_zero() {
                (*S_C).clone()
            } else {
                (*S_L).clone()
            },
            &Nat::one(),
        );
        let max = vpos(
            if !nl.is_zero() {
                (*S_L).clone()
            } else {
                (*S_C).clone()
            },
            if !nl.is_zero() { &nl } else { &nc },
        );
        let reach = shift(&max, &Nat::one()); // one ordinal step past max
        // from_endpoints is INFALLIBLE here: #min == #reach == 2 (no
        // LevelMismatch) and min ≤ max < reach (no NotIncreasing); the stored
        // width reach ⊖ min round-trips exactly — divergence(min, reach) ≤
        // #min discharges D1, INCLUDING the cross-subspace box — so the
        // singleton is faithfully ASN-0112's σ_d = (origin_d, extent_d).
        Ok(SpanSet::singleton(
            Span::from_endpoints(min, &reach).expect("min < reach at one depth-2 length"),
        ))
    }

    /// RETRIEVEDOCVSPANSET (ASN-0113) — per-subspace exact extents: ≤2
    /// members (content, then link), already W13-normalized; `⟨⟩` for an
    /// allocated-empty document; unallocated ⇒ Err. Same count-read core as
    /// `doc_vspan` (D-CTG★), built by `union` of singletons — concatenation
    /// preserves the already-disjoint, content-before-link normal form
    /// (asserted in debug); no invented M1 constructor.
    pub fn doc_vspanset(&self, doc: &Address) -> Result<SpanSet, ExtentError> {
        let w = self.0.world();
        let (m3, m5) = (w.m3(), w.m5());
        if !is_registered(m3, doc) {
            return Err(ExtentError::DocNotRegistered);
        }
        debug_assert_dense_occupancy(m5, doc);
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
    /// Inadmissible (Err) — reject, never silently clamp (O13): an
    /// unallocated document (WF_V i), a malformed span (ii/iv), a foreign
    /// subspace (`NoSuchSubspace`) or empty real subspace (`EmptySubspace`,
    /// iii), a depth-incompatible `#start ≥ 3` span (`DepthIncompatible`,
    /// WF_V v — its own check, kept distinct from the range case so a client
    /// can tell "wrong depth" from "unbound positions"), and a depth-2 span
    /// overrunning the bound prefix (`RangeNotPresent`, WF_V vi — the
    /// depth-agnostic `resolved < ordinal(width)` test).
    pub fn show_origin_v(&self, doc: &Address, span: &Span) -> Result<Vec<Address>, OriginError> {
        let w = self.0.world();
        let (m3, m5) = (w.m3(), w.m5());
        if !is_registered(m3, doc) {
            return Err(OriginError::DocNotRegistered); // WF_V (i)
        }
        gate_vspec(span).map_err(OriginError::MalformedSpan)?; // (ii)/(iv)
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
    /// `a_with_b = { a ∈ content_image(d_b) : DELETED(a, d_a) }` and its
    /// symmetric twin. CURRENT(·, d) is `arranged_content`, which asks each
    /// content run for its addresses exactly as RETRIEVEV does; DELETED(·, d)
    /// is tested by membership in M5's per-document deleted cover
    /// (`deletions(d).denotes(a)`) — exact *unconditionally* by
    /// `difference_sets`' denotational contract
    /// (`⟦deletions(d)⟧ = {x : DELETED(x, d)}` whatever the cover's internal
    /// span packing), so there are no false positives. Never opens M4; both
    /// halves read off the one bound snapshot (single consistent `(M, R)` —
    /// no torn-read phantom deletion).
    ///
    /// Both documents must be registered (Err otherwise; `d_a` checked
    /// first); allocated-empty is fine and yields empty halves. Each half is
    /// the deduped, Tumbler-ordered set of the EXISTING I-addresses
    /// (D-IDENT — never copies; D-ORD).
    pub fn show_deletions(
        &self,
        d_a: &Address,
        d_b: &Address,
    ) -> Result<Deletions, DeletionsError> {
        let w = self.0.world();
        let (m3, m5) = (w.m3(), w.m5());
        for d in [d_a, d_b] {
            if !is_registered(m3, d) {
                return Err(DeletionsError::DocNotRegistered(d.clone()));
            }
        }
        let del_a = m5.deletions(d_a); // { a : DELETED(a, d_a) } as a per-level-class cover
        let del_b = m5.deletions(d_b); // { a : DELETED(a, d_b) }
        // a_with_b = current-in-B ∧ deleted-from-A; b_with_a symmetric.
        let a_with_b = dedup_addrs(
            arranged_content(m5, d_b)
                .into_iter()
                .filter(|a| del_a.denotes(a.tumbler())),
        );
        let b_with_a = dedup_addrs(
            arranged_content(m5, d_a)
                .into_iter()
                .filter(|a| del_b.denotes(a.tumbler())),
        );
        Ok(Deletions { a_with_b, b_with_a })
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
    /// current HOLDERS, distinct from SHOWORIGIN's allocators).
    ///
    /// Every named document must be registered and every region span
    /// well-formed (Err otherwise — a malformed span would silently
    /// UNDER-resolve and drop containers, violating FD-COMPLETE); the gate
    /// does NOT restrict subspace — a link/foreign-subspace span passes and
    /// stays inert downstream (R⁻¹ indexes content provenance only, J-LV),
    /// and a depth-incompatible span resolves to empty coverage
    /// (consulting-state, like RETRIEVEV's R6). Allocated-empty contributes
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
    pub fn find_docs_containing(&self, regions: &[Region]) -> Result<Vec<Address>, FindError> {
        let w = self.0.world();
        let (m3, m5) = (w.m3(), w.m5());
        // The gate first, over the WHOLE request — the first fault wins, and
        // no upstream work is done for a request that will be rejected.
        for (ri, r) in regions.iter().enumerate() {
            if !is_registered(m3, &r.doc) {
                return Err(FindError::DocNotRegistered(r.doc.clone()));
            }
            for (si, span) in r.spans.iter().enumerate() {
                gate_vspec(span).map_err(|f| FindError::MalformedSpan {
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
