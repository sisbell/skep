//! §§A–C, D (SHOWDELETIONS), E — six of the seven operations (COMPARE lives
//! in `compare`). Every operation begins by reading its slices off the single
//! bound snapshot, runs its gate (typed rejection), then composes upstream
//! primitives.

use num_traits::{One, Zero};
use skep_address::{document_of, ordinal, union, Address, Nat, Span, SpanSet};
use skep_arrangement::{is_ordinal_vspan, ordinal_vspan, M5State, Run, VPos};
use skep_content::HasContent;

use crate::error::{DeletionsError, ExtentError, FindError, OriginError, RetrieveError};
use crate::types::{Deletions, Delivery, DeliveryItem, RegionSpec, Spec};
use crate::vspan::{gate_vspan, span_subspace, Subspace};
use crate::{Query, RetrievalWorld};

/// `ext(d, S) = ([S, 1], [0, n_S])` — the per-subspace exact extent span
/// (ASN-0113 W2/W4: a count fixes an extent under sequential positions). The
/// anchor is written ONCE, here, as the subspace origin `[S, 1]` — never
/// absorbed into a confluent summary, which is how the negative-origin hazard
/// (0112 OQ5) is designed out.
///
/// Built with M5's `ordinal_vspan`, so the extent M6 REPORTS is the shape M5's
/// `resolve` READS: the constructor and the recognizer every request span is
/// folded through are the two halves of one definition and cannot come apart.
/// `None` iff `n_S == 0`, which its one call site has already excluded.
///
/// The subspace arrives CLASSIFIED rather than as a numeral, so the two
/// arguments have different types and `ext_span(count, subspace)` fails to
/// compile — the hazard M5 designs out of `ordinal_vspan` by taking a `VPos`,
/// since a swap here builds a well-formed span naming a subspace that selects
/// nothing and reports as emptiness far downstream.
fn ext_span(s: Subspace, n: &Nat) -> Span {
    ordinal_vspan(
        &VPos {
            subspace: s.numeral().clone(),
            ordinal: Nat::one(),
        },
        n,
    )
    .expect("n_S ≥ 1 ⇒ a nonempty extent")
}

/// The enumeration of `CURRENT(·, d)` (ASN-0075's predicate; ASN-0124 calls
/// the set `ran_C(d)`) — every content I-address `d`'s arrangement currently
/// binds, in V order. M5's own `content_image` is the same set and is private,
/// so it is NOT called here.
///
/// Walking the CONTENT runs is not a narrowing of `CURRENT` but its whole
/// extent: ASN-0075 defines the predicate over `a ∈ dom(C)`, so
/// `{a : CURRENT(a, d)} = ran(M(d)) ∩ dom(C) = ran_C(d)` and no link run is
/// skipped — there is none to skip (D-SUBSP).
///
/// `CURRENT` is a set and this is an enumeration WITH MULTIPLICITY: an
/// address placed at two V-positions of `d` by intra-document transclusion is
/// yielded twice, so callers dedup.
///
/// LAZY, and that is the point rather than a style: `d`'s arrangement binds
/// one content position per byte the document was written with, and each
/// position enumerated is an OWNED `Address` — a `Vec<Nat>` of element
/// components, order hundreds of bytes and a handful of allocations. Handing
/// back a `Vec` would make the peak live heap of a two-document combine the
/// size of both documents, from a request naming two addresses and nothing
/// else; streaming makes it the size of the part the caller's filter keeps.
/// Each run's positions are enumerated by the run that owns them, exactly as
/// [`Query::retrieve_v`] does — `Run::into_addrs`, the owned form, because
/// this iterator consumes the run-list and each run outlives only its own
/// walk.
fn current_content(m5: &M5State, d: &Address) -> impl Iterator<Item = Address> {
    m5.content_runs(d).into_iter().flat_map(Run::into_addrs)
}

/// A stream of addresses as the deduplicated, T1-SORTED set it denotes. Both
/// the dedup and the sort are published guarantees, not conveniences:
/// [`Query::show_origin_v`] answers "deduplicated origin documents in tumbler
/// order" and each half of [`Query::show_deletions`]' answer is a
/// deduplicated, T1-ascending listing, and this is the one place either is
/// established.
///
/// THE TWO GUARANTEES STAND ON DIFFERENT AUTHORITIES, and only one of them is
/// the corpus's. The DEDUP is the comprehension's: ASN-0075's
/// `DeletedFromAWithB` is `{a ∈ dom(C) : …}`, a set, and SHOWORIGIN_V's answer
/// is a set of origin documents. The ORDERING is M6's own presentation of that
/// set — D-ORD licenses it (each output half is a finite subset of
/// `dom(C) ⊆ T`, so T1-orderability is a property of the output addresses) and
/// does not require it (the operation "carries no ordering of its own"), which
/// is why fixing one is M6's to do and to state.
///
/// Identity and order are both `Address`'s own — its `Eq` is tumbler equality
/// (the level is a function of the tumbler) and its `Ord` IS the T1 tumbler
/// order — so sorting and deduplicating is exactly dedup-by-tumbler, with no
/// `.tumbler()` detour and no key clone.
///
/// Used for origin DOCUMENTS (SHOWORIGIN_V) and content I-ADDRESSES
/// (SHOWDELETIONS) alike — both are `Address`, so one neutral helper serves
/// either (the name says "addr", not "doc", because at the SHOWDELETIONS site
/// the deduped elements are content addresses, not documents).
fn sorted_addr_set(it: impl IntoIterator<Item = Address>) -> Vec<Address> {
    let mut out: Vec<Address> = it.into_iter().collect();
    out.sort_unstable(); // T1 order; the dedup below makes stability unobservable
    out.dedup();
    out
}

/// D-SEQ★ defense-in-depth for the extent queries (open build decision,
/// documented default: trust `content_count`/`link_count` in release, assert
/// in debug).
///
/// D-SEQ★ (PerSubspaceSequentialPositions, ASN-0047) is the invariant the
/// counts stand on: an occupied subspace's V-positions are exactly the dense,
/// origin-anchored prefix `V_S(d) = {[S, k] : 1 ≤ k ≤ n_S}` — which is what
/// ASN-0113 W4 forces, and which ASN-0047 derives from contiguity D-CTG★ plus
/// minimum-position D-MIN★. Its two ingredients are what the two assertions
/// check: each subspace's run widths sum to its count (density — a hole would
/// make the count over-report the extent), and an occupied subspace anchors
/// at ordinal 1 (D-MIN★ itself; ASN-0112 V8 origin permanence, append-only
/// link seating). The whole body is compiled out of release builds, which
/// read the counts directly.
fn debug_assert_sequential_positions(m5: &M5State, doc: &Address) {
    if cfg!(debug_assertions) {
        for (sub, count, runs) in [
            (
                Subspace::Content,
                m5.content_count(doc),
                m5.content_runs(doc),
            ),
            (Subspace::Link, m5.link_count(doc), m5.link_runs(doc)),
        ] {
            let width_sum = runs.iter().fold(Nat::zero(), |acc, r| acc + r.width());
            debug_assert!(
                width_sum == count,
                "D-SEQ★: a subspace's run widths must sum to its count"
            );
            debug_assert!(
                count.is_zero()
                    || m5
                        .point(
                            doc,
                            &VPos {
                                subspace: sub.numeral().clone(),
                                ordinal: Nat::one(),
                            },
                        )
                        .is_some(),
                "D-MIN★: an occupied subspace must anchor at ordinal 1"
            );
        }
    }
}

/// RETRIEVEV alone opens M4, so RETRIEVEV alone names it: `HasContent` is
/// this impl block's bound and nowhere else's, which is what makes the other
/// six operations' value-blindness structural rather than a rule their cards
/// ask a maintainer to keep.
impl<W: RetrievalWorld + HasContent> Query<'_, W> {
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
        let w = self.0.world();
        let (m3, m5, content) = (w.m3(), w.m5(), w.content());
        // Gate the whole request first — VSpec WELL-FORMEDNESS is the only
        // in-model failure (ASN-0115). A well-formed but depth-incompatible
        // (#start ≥ 3) spec is NOT rejected here (R6).
        for (i, spec) in specs.iter().enumerate() {
            if !m3.is_registered_document(&spec.doc) {
                return Err(RetrieveError::DocNotRegistered(spec.doc.clone()));
            }
            gate_vspan(&spec.span)
                .map_err(|f| RetrieveError::MalformedSpec { index: i, fault: f })?;
        }
        let mut out = Vec::new();
        for spec in specs {
            // Concatenate per spec, IN ORDER (R5) — no global sort. Classify
            // ONCE per spec, because the answer is constant over the spec's
            // positions.
            let sub = span_subspace(&spec.span);
            for run in m5.resolve(&spec.doc, &spec.span) {
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

impl<W: RetrievalWorld> Query<'_, W> {
    /// RETRIEVEDOCVSPAN (ASN-0112) — the whole-document bounding span:
    /// singleton `⟨σ_d⟩`, or `⟨⟩` for a registered-empty document; a document
    /// that is not registered ⇒ Err. Across subspaces it is a bounding box
    /// bridging the inter-subspace void.
    ///
    /// WHAT THE BOX CANNOT SHOW (V9). Being a function of the two EXTREMES
    /// alone, the cross-subspace box is fixed at `[[s_C, 1], [s_L, n_L + 1])`
    /// under any content edit that leaves `n_C ≥ 1`, while
    /// [`Query::doc_vspanset`]'s content member moves with `n_C` — so a caller
    /// that must observe a CONTENT-COUNT change asks for the extents, not the
    /// box. Neither reports run structure: under D-SEQ★ both are functions of
    /// `n_C` and `n_L` alone, and a document's fragmentation is M5's
    /// `content_runs`, which is not part of M6's surface.
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
    /// write-path property, trusted here and tripwired in debug). Each
    /// subspace travels with its OWN count in one pair, and reaches
    /// [`ext_span`] classified rather than as a numeral, so the two can be
    /// crossed neither by the pairing nor by the call; the occupied ones are
    /// `collect`ed through M1's `FromIterator<Span>` — which collects AS
    /// GIVEN, preserving the already-disjoint, content-before-link normal form
    /// (asserted in debug); no invented M1 constructor.
    pub fn doc_vspanset(&self, doc: &Address) -> Result<SpanSet, ExtentError> {
        let w = self.0.world();
        let (m3, m5) = (w.m3(), w.m5());
        if !m3.is_registered_document(doc) {
            return Err(ExtentError::DocNotRegistered); // not registered ⇒ fail
        }
        debug_assert_sequential_positions(m5, doc);
        let (nc, nl) = (m5.content_count(doc), m5.link_count(doc));
        let extents: SpanSet = [(Subspace::Content, &nc), (Subspace::Link, &nl)]
            .into_iter()
            .filter(|(_, n)| !n.is_zero())
            .map(|(s, n)| ext_span(s, n))
            .collect();
        debug_assert!(
            extents.is_normalized(),
            "W13: content-before-link, subspace-separated ⇒ already normal"
        );
        Ok(extents)
    }

    /// SHOWORIGIN over a V-span (ASN-0077, V-arity) — block-decompose, then
    /// project ONE origin per run (`document_of`, M1): block uniformity (O2)
    /// means all addresses in one run share an origin, so this is O(runs),
    /// not O(positions). Returns deduplicated origin documents in tumbler
    /// order; for the link subspace `document_of(link)` is the home document
    /// (CL-OWN) — handled uniformly, no special case. The I-arity is
    /// de-scoped (see the crate docs); only this V-arity exists.
    ///
    /// A success is never empty: an admissible request has an occupied
    /// subspace (`n_s ≥ 1`), a depth-2 span, and a fully resolved width, so at
    /// least one run is projected and `Ok(vec![])` is not an answer this
    /// operation gives.
    ///
    /// Inadmissible (Err) — reject, never silently clamp (O13), and the
    /// listing below IS the precedence: the checks run in this order and the
    /// FIRST condition that holds is the one reported. A document that is not
    /// registered (WF_V i), a malformed span (ii/iv), a foreign subspace
    /// (`NoSuchSubspace`) or empty real subspace (`EmptySubspace`, iii), a
    /// depth-incompatible `#start ≥ 3` span (`DepthIncompatible`, WF_V v —
    /// decided by M5's `is_ordinal_vspan`, the recognizer its `resolve` folds
    /// every span through, so the span this refuses and the span `resolve`
    /// would silently empty are one span; kept distinct from the range case so
    /// a client can tell "wrong depth" from "unbound positions"), and a
    /// depth-2 span overrunning
    /// the bound prefix (`RangeNotPresent`, WF_V vi — the depth-agnostic
    /// `resolved_width < ordinal(width)` test). So a malformed span in a
    /// foreign subspace is `MalformedSpan`, and a deep span over an empty
    /// subspace is `EmptySubspace`.
    pub fn show_origin_v(&self, doc: &Address, span: &Span) -> Result<Vec<Address>, OriginError> {
        let w = self.0.world();
        let (m3, m5) = (w.m3(), w.m5());
        if !m3.is_registered_document(doc) {
            return Err(OriginError::DocNotRegistered); // WF_V (i)
        }
        gate_vspan(span).map_err(OriginError::MalformedSpan)?; // (ii)/(iv)
        // The start's subspace, at any depth.
        let n_s = match span_subspace(span) {
            Some(Subspace::Content) => m5.content_count(doc),
            Some(Subspace::Link) => m5.link_count(doc),
            // Foreign subspace ∉ {s_C, s_L}: distinct from a real-but-empty
            // subspace.
            None => return Err(OriginError::NoSuchSubspace),
        };
        if n_s.is_zero() {
            return Err(OriginError::EmptySubspace); // (iii)
        }
        if !is_ordinal_vspan(span) {
            // (v): depth must equal the subspace common depth m_S ≡ 2, asked
            // as "the shape `resolve` serves" — so this refusal and
            // `resolve`'s silent ⟨⟩ can never name different spans. After
            // `gate_vspan` the only clause of M5's shape still open IS the
            // depth one: level-uniformity ties `#width` to `#start`, and
            // ordinal-level puts the width's only nonzero component last, so
            // `#start == 2` gives `width = [0, n≥1]` and every other gated
            // span fails on depth alone.
            return Err(OriginError::DepthIncompatible);
        }
        // Span now depth-2 (≥ 3 rejected above); resolve may still be partial
        // if the span overruns the bound prefix.
        let runs = m5.resolve(doc, span);
        let resolved_width = runs.iter().fold(Nat::zero(), |acc, r| acc + r.width());
        // The nominal count is read via ordinal(width) — the last component,
        // which level-uniformity ties to #start — keeping the overrun test
        // depth-agnostic, not a hard-coded get(2).
        if &resolved_width < ordinal(span.width()) {
            return Err(OriginError::RangeNotPresent); // (vi): reject, never clamp (O13)
        }
        Ok(sorted_addr_set(runs.iter().map(|r| {
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
    /// a set of the EXISTING I-addresses (D-IDENT — never copies), returned
    /// deduplicated and T1-ascending: the dedup is the comprehension's, the
    /// ordering M6's own presentation, which D-ORD licenses (T1-orderability
    /// is a property of the addresses) and does not require (the operation
    /// transports no ordering of its own).
    ///
    /// BOTH HALVES ARE CONTENT I-ADDRESSES BY DEFINITION (D-SUBSP): ASN-0075
    /// classifies `(a, d)` with `a ∈ dom(C)`, so `CURRENT` and `DELETED` are
    /// defined only there and both output sets are `{a ∈ dom(C) : …}` — every
    /// such `a` has `subspace_I(a) = s_C`, and `dom(C) ∩ dom(L) = ∅` (L14), so
    /// no link address can appear in either half whatever the enumeration does.
    /// The operation's domain is what confines it, not this implementation's
    /// choice of walk.
    ///
    /// What the implementation gets from that: enumerating the content runs
    /// alone loses nothing AND needs no filter behind it. `DELETED(a, d)`
    /// requires `(a, d) ∈ R`, and R is appended only where content is placed —
    /// seating a link records nothing in it — so a link position enumerated
    /// here could only be filtered away again.
    ///
    /// TIME IS UNBOUNDED AND M6 DOES NOT BOUND IT — and unlike RETRIEVEV's,
    /// it is not bounded by the answer either. No span narrows the request, so
    /// both documents are enumerated WHOLE: the work is
    /// `|R↾d_a| log |R↾d_a| + |R↾d_b| log |R↾d_b|`, the two `M5State::deletions`
    /// calls that build the halves (each rebuilds and SORTS the document's
    /// whole provenance record — M5 states this cost where it is paid), plus
    /// `n_C(d_a)·|deletions(d_b)| + n_C(d_b)·|deletions(d_a)|` for the
    /// membership pass, all paid in full even when the two share nothing and
    /// both halves come back empty. THE FIRST TERM USUALLY DOMINATES, and it
    /// is the one a document's current size does not reveal: R never loses a
    /// member, so a document that has deleted far more than it holds carries a
    /// record far larger than its arrangement. M6 owns no admission control
    /// and no refusal for any of it: capping request rate and concurrency for
    /// a route carrying this read is M10's, as the request lifecycle's owner —
    /// and a request-size cap is no help here, this request being two
    /// addresses whatever the documents behind them hold.
    ///
    /// MEMORY IS THE ANSWER'S. [`current_content`] streams, so what is held
    /// live is the deduped halves and one address at a time, not a
    /// materialized copy of either document's position list. The worst case
    /// is therefore the honest one: two documents where each has deleted what
    /// the other still holds, whose answer genuinely is that many addresses.
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
        let deleted_from_a_with_b =
            sorted_addr_set(current_content(m5, d_b).filter(|a| del_a.denotes(a.tumbler())));
        let deleted_from_b_with_a =
            sorted_addr_set(current_content(m5, d_a).filter(|a| del_b.denotes(a.tumbler())));
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
    /// live answer from M5's `docs_ever_containing`. TWO narrowings separate
    /// that superset from the live answer, and this filter discharges both at
    /// once — from order-overlap to genuine ever-containment, M5's test
    /// admitting the merely ADJACENT candidates whose recorded spans touch the
    /// coverage without sharing a position, so the superset is coarser even
    /// than FD-HIST's `finddocs_R`; and from ever to now, dropping FD-GHOST's
    /// `ghosts` (`finddocs_R ∖ finddocs`), the documents that held the queried
    /// material at some past boundary and hold none of it now. Returns bare
    /// deduplicated identities, tumbler-ordered — no positions, no counts
    /// (FD codomain; present-tense CONTAINERS, distinct from SHOWORIGIN's
    /// allocators).
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
    /// WHICH REFUSAL SPEAKS. The gate walks the regions in submitted order and
    /// each region's spans in submitted order, reporting the FIRST fault
    /// whatever its kind; within one region the registry check precedes the
    /// span gate. It also completes over the WHOLE request before any `image`
    /// is taken, so a rejected request costs `O(spans)` and nothing upstream,
    /// and `(region, index)` promises that every region and span before the
    /// named one is clean.
    ///
    /// Emptiness is tested with M1's `SpanSet::is_empty` — denotationally
    /// exact because no algebra result carries a zero-width member (zero
    /// members ⇔ empty denotation), the predicate the design's M1-seam ask
    /// named (landed in the built M1).
    ///
    /// COST IS UNBOUNDED AND M6 DOES NOT BOUND IT, in three factors and not
    /// one. `|coverage|` is the union of the region images, itself unbounded
    /// in the spans a caller may name; the candidate scan is that coverage
    /// against the whole of M5's R⁻¹ index; and the filter is one `project`
    /// per candidate, each itself `#runs(d) · |coverage|` in the CANDIDATE's
    /// own fragmentation — a factor the request never names and M6 never sees.
    /// So the work is `|candidates| · #runs(d) · |coverage|`.
    ///
    /// It is LINEAR in the request, unlike COMPARE's join, which is why a
    /// request-size cap would bound it proportionally and no budget is taken
    /// here. That cap is unassigned rather than delegated: M6 hands request
    /// size, rate and concurrency to M10 as the request lifecycle's owner, and
    /// M10's codec records that the cost model of a REGION SET is M6's rather
    /// than its own. One of the two must take the number.
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

#[cfg(test)]
mod tests {
    use super::*;
    use skep_address::{validate, Tumbler};

    fn a(comps: &[u32]) -> Address {
        let t =
            Tumbler::new(comps.iter().map(|&c| Nat::from(c))).expect("test tumblers are nonempty");
        validate(t).expect("test addresses are T4-valid")
    }

    #[test]
    fn sorted_addr_set_is_deduped_and_t1_ordered() {
        let d2 = a(&[1, 0, 1, 0, 2]);
        let d1 = a(&[1, 0, 1, 0, 1]);
        let got = sorted_addr_set(vec![d2.clone(), d1.clone(), d2.clone(), d1.clone()]);
        assert_eq!(got, vec![d1, d2]);
        assert!(sorted_addr_set(std::iter::empty()).is_empty());
    }
}
