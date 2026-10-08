//! §D/§E — arrangement reads (resolve/iter_resolve/point/image/project/
//! arranges_any), the content subspace's admission predicates, and the
//! provenance reads (deletions/docs_ever_containing), pure over any M2
//! snapshot (§2, §9).
//!
//! **Level-class discipline** (§2): a SpanSet aggregated across runs — a
//! region image, an endset's coverage, the internal `content_image`, a
//! document's `ever_contained` cover (R↾doc) — is in general MIXED-LENGTH
//! (transclusion mixes origin lengths), and M1's length-gated set ops fault
//! `LevelMismatch` on mixed operands. Where geometry is needed, M5 partitions
//! each operand into level-classes by endpoint length
//! (`SpanSet::by_level_class`), runs the M1 op within each class, and unions
//! the per-class results; where overlap/membership suffices it uses the total
//! `classify_spans`/`contains`. The discipline is ENCAPSULATED behind the
//! query methods ([`M5State::project`], [`M5State::arranges_any`],
//! [`M5State::deletions`]) and OWED by whoever aggregates run I-extents
//! themselves — [`M5State::image`]'s raw cover, and the runs
//! [`M5State::resolve`] and [`M5State::iter_resolve`] hand back for a caller
//! to lift. Both routes reach [`Run::iextent`], where the obligation is stated
//! (Conflicts #8).

use num_traits::One;
use skep_address::{difference_sets, union, Address, Nat, Span, SpanSet};

use crate::run::Run;
use crate::runlist::{RunUnion, Runs};
use crate::state::M5State;
use crate::vspace::{as_ordinal_vspan, ordinal_vspan, VPos};

impl M5State {
    /// V→I resolution (§2; ASN-0058 C0; ASN-0118 accept-and-intersect):
    /// I-runs covering an ORDINAL-LEVEL depth-2 V-span (width `[0, n]`,
    /// action point 2), V-ordered, clipped to the arranged range. The span's
    /// subspace, ordinal and count come from the one reader that establishes
    /// it has them.
    ///
    /// THE RUNS TILE V CONTIGUOUSLY, which is what lets a caller recover each
    /// run's V-position without asking a second time: the FIRST run returned
    /// holds V-ordinal `max(ord, 1)` — the clamp is load-bearing, a span
    /// opening at ordinal 0 still starting its answer at 1 — and each next run
    /// begins where the previous one ends, so accumulating widths from that
    /// start gives every run's V-start. There are no V-gaps to skip because
    /// there are none to have: a subspace's arranged positions are its dense
    /// prefix (D-SEQ★, stated on [`M5State`]), so a span reaching past the
    /// prefix is clipped and one opening past it binds nothing at all rather
    /// than skipping forward to a later position.
    ///
    /// DEFENSIVE (returns ⟨⟩, cannot fault — no `Result`) unless the span is
    /// usable: a span the shared shape reader refuses — the same shape COPY's
    /// `NotOrdinalVSpan` rejects on — yields ⟨⟩, and so does a shape-valid
    /// span whose subspace ∉ {s_C, s_L}, a `DocArrangement` having exactly the
    /// content and link run-lists. Absent doc ⇒ ⟨⟩ (M6/M8 disambiguate
    /// registered-empty vs unallocated via M3). A caller that must tell "bad
    /// request" from "genuinely empty" calls
    /// [`is_ordinal_vspan`](crate::is_ordinal_vspan) itself before asking;
    /// M6's own request gate is deliberately WEAKER (ASN-0115
    /// well-formedness, `#start ≥ 2`), leaving depth compatibility to this
    /// defensive fold.
    ///
    /// MIXED-LENGTH HAZARD for whoever aggregates the returned runs'
    /// I-extents: see [`Run::iextent`].
    pub fn resolve(&self, doc: &Address, span: &Span) -> Vec<Run> {
        self.iter_resolve(doc, span).collect()
    }

    /// [`resolve`](M5State::resolve)'s LAZY twin — the same runs, in the same
    /// order, under the same defensive folds, clipped as they are pulled — so
    /// every promise `resolve` makes of its runs, the contiguous V tiling
    /// included, is made of what this yields.
    ///
    /// The form for a consumer that carries a budget of its own, and the
    /// reason is what the two forms cost: a resolution's size is the SOURCE
    /// document's fragmentation, which the asking request does not choose.
    /// Pulled a run at a time and counted as it is pulled, an over-budget
    /// span stops its walk at the budget rather than materializing the
    /// source's every run and being refused afterwards, so what the consumer
    /// holds live is its budget and not the resolution. COPY's accumulator
    /// (capped at [`MAX_PLACED_RUNS`](crate::MAX_PLACED_RUNS)) consumes it so,
    /// and so do the neighbours' produced-as-they-go budgets: M6's COMPARE
    /// blocks and FINDDOCSCONTAINING coverage, M7's MAKELINK slot spans and
    /// M10's successor slot spans. [`resolve`](M5State::resolve) is this
    /// collected, for a caller that hands the runs onward whole.
    ///
    /// What pulling does NOT bound is the walk to the span's opening ordinal:
    /// the prefix-sum walk passes every run that ends before it before the
    /// first run is yielded — all of them, for a span opening past the
    /// arranged end — so one call is `Θ(#runs left of the opening ordinal)`
    /// steps whatever it yields, and
    /// [`content_run_count`](M5State::content_run_count) is that walk's
    /// ceiling for a content span, readable before asking.
    pub fn iter_resolve(&self, doc: &Address, span: &Span) -> impl Iterator<Item = Run> + '_ {
        as_ordinal_vspan(span)
            .and_then(|vspan| {
                self.arrangement_of(doc)
                    .list(vspan.subspace)
                    .map(|list| list.iter_resolve_range(vspan.ordinal, vspan.count))
            })
            .into_iter()
            .flatten()
    }

    /// `M(d)(p)` (§2): the I-address at V-position `p`, or `None` when
    /// `p.subspace ∉ {s_C, s_L}` (no such run-list) or the ordinal is
    /// unarranged — which under D-SEQ★ ([`M5State`]) is exactly
    /// `p.ordinal ∉ [1, n_s]`, a subspace's arranged positions being its dense
    /// prefix, so one bound settles membership. Every returned `Address` is
    /// T4-valid (synthesis routes through `validate`).
    pub fn point(&self, doc: &Address, p: &VPos) -> Option<Address> {
        self.arrangement_of(doc)
            .list(&p.subspace)?
            .point(&p.ordinal)
    }

    /// The region's I-image as a SpanSet (§2; ASN-0127 `image(W, d, Σ)`, the
    /// addresses `doc`'s arrangement maps the V-region `span` onto):
    /// `⋃ r.iextent()` over the runs [`resolve`](M5State::resolve) returns —
    /// the coverage operand
    /// [`docs_ever_containing`](M5State::docs_ever_containing),
    /// [`project`](M5State::project) and
    /// [`arranges_any`](M5State::arranges_any) take, collected whole. A
    /// caller that counts its coverage against a budget pulls the same runs
    /// off [`iter_resolve`](M5State::iter_resolve) and lifts each with
    /// [`Run::iextent`] as it counts, as M6's FINDDOCSCONTAINING does, so an
    /// over-budget region stops at the budget rather than being collected
    /// here first. `union` (concatenation) only ⇒ total, never faults, NOT
    /// normalized; possibly mixed-length when `span` covers transcluded runs,
    /// so it is consumed under the level-class discipline (the hazard is
    /// stated on [`Run::iextent`], which every aggregator of run I-extents
    /// reaches, whether or not it comes through here).
    pub fn image(&self, doc: &Address, span: &Span) -> SpanSet {
        self.iter_resolve(doc, span).map(|r| r.iextent()).collect()
    }

    /// The canonical, V-ordered content run decomposition — maximally merged
    /// (ASN-0058 M12), and so UNIQUE: two content arrangements are the same
    /// V→I map exactly when their decompositions are equal. Absent doc ⇒
    /// yields nothing. The runs tile the whole content prefix `[1, n_C]`
    /// contiguously (D-SEQ★, stated on [`M5State`]), so the first begins at
    /// V-ordinal 1 and each next where the previous ends.
    ///
    /// LENT, not cloned: the runs are stored whole, so this hands out a borrow
    /// of each. A caller that keeps runs `.cloned()` the ones it keeps; two
    /// decompositions compare with `Iterator::eq` without collecting either;
    /// and `.len()` is the number
    /// [`content_run_count`](M5State::content_run_count) answers.
    pub fn content_runs(&self, doc: &Address) -> Runs<'_> {
        self.content_list(doc).iter()
    }

    /// The canonical, V-ordered link run decomposition — maximally merged, and
    /// so UNIQUE as [`content_runs`](M5State::content_runs)' is: two link
    /// arrangements are the same V→I map exactly when their decompositions
    /// are equal. Absent doc ⇒ yields nothing; it tiles `[1, n_L]` as
    /// `content_runs` tiles the content prefix, D-SEQ★ holding per subspace.
    /// Lent as `content_runs`' runs are, and its `.len()` is
    /// [`link_run_count`](M5State::link_run_count).
    pub fn link_runs(&self, doc: &Address) -> Runs<'_> {
        self.link_list(doc).iter()
    }

    /// `n_C(d)` — the arranged content width. Absent doc ⇒ 0. Under D-SEQ★
    /// ([`M5State`]) it is equally the LARGEST arranged content ordinal and
    /// the width sum of [`content_runs`](M5State::content_runs): the content
    /// positions are `[1, n_C]` with no holes, so a count fixes the extent
    /// (ASN-0113 W2/W4) rather than over-reporting one.
    pub fn content_count(&self, doc: &Address) -> Nat {
        self.content_list(doc).total_width()
    }

    /// `n_L(d)` — the arranged link width. Absent doc ⇒ 0; the D-SEQ★ reading
    /// of [`content_count`](M5State::content_count) holds per subspace, so
    /// this is likewise the largest arranged link ordinal.
    pub fn link_count(&self, doc: &Address) -> Nat {
        self.link_list(doc).total_width()
    }

    /// `#runs(doc)` in the content subspace — how many runs
    /// [`content_runs`](M5State::content_runs) would hand back, without handing
    /// them back. NOT [`content_count`](M5State::content_count), which is the
    /// positions those runs cover. It is the quantity COPY's resolve walk —
    /// which COPY charges at this number against
    /// [`MAX_COPY_RESOLVE_STEPS`](crate::MAX_COPY_RESOLVE_STEPS) —
    /// [`project`](M5State::project)'s and
    /// [`arranges_any`](M5State::arranges_any)'s joins, VERSION's R-append and
    /// the shot's carried-run union are priced in, so a caller that owns
    /// admission control for one of them reads the number here rather than
    /// materializing the runs to count them. One map lookup, reading no run;
    /// absent doc ⇒ 0.
    pub fn content_run_count(&self, doc: &Address) -> usize {
        self.content_list(doc).run_count()
    }

    /// `#runs(doc)` in the link subspace, as
    /// [`content_run_count`](M5State::content_run_count) is in the content
    /// one. One map lookup, reading no run; absent doc ⇒ 0.
    pub fn link_run_count(&self, doc: &Address) -> usize {
        self.link_list(doc).run_count()
    }

    /// `|R↾doc|` — how many spans R records for `doc`: one per run it has ever
    /// placed, deleted or not (P2). The term that dominates
    /// [`deletions`](M5State::deletions)' cost, and the one a document's
    /// current arrangement does not reveal, so a caller pricing SHOWDELETIONS
    /// reads it here. One map lookup, reading no span; absent doc ⇒ 0.
    pub fn recorded_span_count(&self, doc: &Address) -> usize {
        self.provenance.recorded_span_count(doc)
    }

    /// Does the content subspace admit `ord` as a PLACEMENT boundary —
    /// `1 ≤ ord ≤ n_C + 1` (§1/§3)? The arrangement's own admission rule,
    /// asked rather than re-derived, so the append boundary (and the
    /// `ord = 1` case at `n_C = 0`, ASN-0116's FirstInsertionPosition) has one
    /// definition for INSERT, COPY and REARRANGE's cuts to share. The verdict
    /// each op reports for a refusal stays with that op's error type.
    pub(crate) fn admits_content_boundary(&self, doc: &Address, ord: &Nat) -> bool {
        *ord >= Nat::one() && *ord <= &self.content_count(doc) + &Nat::one()
    }

    /// Does `doc` arrange no content — `n_C = 0`? Asked of the run-list's
    /// emptiness, O(1), rather than of [`content_count`](M5State::content_count),
    /// which sums every run's width to learn the same bit. COPY's
    /// `EmptySource` and REARRANGE's `EmptyContentSubspace` ask it. Absent
    /// doc ⇒ `true`.
    pub(crate) fn content_is_empty(&self, doc: &Address) -> bool {
        self.content_list(doc).is_empty()
    }

    /// Does `doc` ARRANGE content ordinal `ord` — is it a position holding an
    /// I-address, `ord ∈ [1, n_C]` (§4)? Answered off the run-list's own
    /// locate, which is the same walk `point` uses. One short of
    /// [`admits_content_boundary`](M5State::admits_content_boundary), which
    /// admits the append boundary as well.
    pub(crate) fn arranges_content_position(&self, doc: &Address, ord: &Nat) -> bool {
        self.content_list(doc).locate(ord).is_some()
    }

    /// Does `at` name a FRESH content position of `doc` — one PAST the
    /// arranged extent, `at.subspace = s_C ∧ at.ordinal > n_C` — so that an
    /// insert there appends and disturbs no arrangement (PUB-2.59, PUB-2.61:
    /// the deposit shape)? The one fact the write path keys the deposit
    /// exemption on beside the caller's declaration (PUB-9.13, DECLARED).
    ///
    /// Deliberately WIDER than the append boundary: an ordinal past
    /// `n_C + 1` is fresh too — it touches nothing arranged — and is left for
    /// the op's own shape check to refuse `OutOfBounds`, so a declared
    /// deposit aimed past the boundary is told its position is bad rather
    /// than that its target is published. An insert AT or BELOW `n_C` shifts
    /// the suffix, which IS a disturbance, and a link-subspace position is
    /// not a deposit shape at all.
    pub(crate) fn names_fresh_content_position(&self, doc: &Address, at: &VPos) -> bool {
        at.is_content() && at.ordinal > self.content_count(doc)
    }

    /// Does `doc`'s arranged content CONTAIN the whole range `[from, from +
    /// width)` — `from + width ≤ n_C + 1`, subtraction-free (§4)? The
    /// containment half of DELETE's admission (ASN-0117: "containment within
    /// the document's current arranged extent"), stated where `n_C` lives.
    /// "Contain" here is the V-SIDE word: a range of V-ordinals lying inside
    /// the arranged prefix `[1, n_C]`. It is not the corpus's I-side
    /// containment — a document holding an I-address in its image (FD-FIND)
    /// — whose present tense is [`project`](M5State::project) and whose
    /// history is [`docs_ever_containing`](M5State::docs_ever_containing).
    ///
    /// REQUIRES `from ≥ 1`, and this is the UPPER BOUND ALONE. Arranged
    /// content is `[1, n_C]`, so containment of `[from, from + width)` is
    /// `from ≥ 1 ∧ from + width ≤ n_C + 1`; given the first conjunct the test
    /// below IS containment, and without it the answer says nothing about
    /// where the range opens — `from = 0` passes for every document,
    /// including an empty one, though ordinal 0 is arranged nowhere. Every
    /// caller establishes the conjunct by asking
    /// [`arranges_content_position`](M5State::arranges_content_position)
    /// first, which is why this predicate does not re-ask it.
    pub(crate) fn contains_content_range(&self, doc: &Address, from: &Nat, width: &Nat) -> bool {
        from + width <= &self.content_count(doc) + &Nat::one()
    }

    /// The UNION of `doc`'s content runs' I-extents ([`RunUnion`]) — every
    /// address its CONTENT arrangement holds, merged so that whether it holds
    /// EVERY address of a run is one search ([`RunUnion::covers`]), the
    /// membership question of [`seats_link`](M5State::seats_link) asked of a
    /// run's whole I-extent. The publish shot's carried-run test (PUB-6.24,
    /// PUB-8.1): a supplied run the base already arranges takes no source
    /// gate, the base having answered for those addresses when it was
    /// published. Merged once and asked of every run, so a request of many
    /// runs pays `doc`'s run count once: `O(n log n)` in
    /// [`content_run_count`](M5State::content_run_count), and a pointer per
    /// run. Absent doc ⇒ the empty union, which covers nothing.
    pub(crate) fn content_union(&self, doc: &Address) -> RunUnion<'_> {
        RunUnion::of(self.content_list(doc).iter())
    }

    /// The content runs of `doc` PAST ordinal `extent` — positions
    /// `[extent + 1, n_C]`, V-ordered, the boundary run clipped, and nothing
    /// at all when `extent ≥ n_C`. The publish shot's carried tail (PUB-2.42,
    /// PUB-2.45): a published member changes only by deposits appended at
    /// fresh positions (PUB-2.43), so its positions past the extent a staged
    /// copy took are exactly the deposits that copy's render post-dates.
    /// Asked of the arrangement, which knows where its content ends, so the
    /// shot names a boundary and derives no count of its own.
    ///
    /// Answered off the run-list's own suffix walk, which names no upper
    /// bound and sums no total to find one. Lazy as that walk is, so a
    /// consumer with a budget of its own stops it at the budget. Absent doc
    /// ⇒ nothing.
    pub(crate) fn content_runs_past(&self, doc: &Address, extent: &Nat) -> impl Iterator<Item = Run> + '_ {
        self.content_list(doc).iter_resolve_from(&(extent + &Nat::one()))
    }

    /// Is `link` already seated in `doc`'s link subspace (§8, CL-UNIQ)? The
    /// link run-list's own membership answer, so a link INTERIOR to a
    /// coalesced link run counts as seated. Absent doc ⇒ not seated.
    pub(crate) fn seats_link(&self, doc: &Address, link: &Address) -> bool {
        self.link_list(doc).holds(link)
    }

    /// I→V projection (§2; ASN-0119 RA7c) — CONTENT subspace ONLY, by
    /// construction (link reverse-discovery is M7's BH3; there is no subspace
    /// argument): the V-positions of `doc` whose content I-address falls in
    /// `coverage` — an I-address cover, an endset's coverage (M8's route) or a
    /// region [`image`](M5State::image) alike, possibly fragmented and
    /// mixed-length — as depth-2 V-spans, normalized. The result is the
    /// FOOTPRINT those addresses have in `doc` (ASN-0119's `project`), which
    /// is why a footprint interrupted in V-space comes back as several spans.
    /// TOTAL — the level-class discipline is applied internally, so the call
    /// is fault-free for any coverage, including cross-length prefix/subtree
    /// spans.
    ///
    /// Per content block × coverage span: the block's run reports which of
    /// its offsets the span covers (the run owns both the same-level-class
    /// intersection and the cross-class boundary search that decide it), and
    /// this method turns that offset range into a V-range by adding the
    /// block's V-start to where the range opens — the range answering for how
    /// many positions it covers, so no reader subtracts its bounds. Scan of
    /// the forward content map (Open decision #2 v1 default), so the cost is
    /// `#runs(doc) × |coverage|` — the product of two quantities this method
    /// does not bound. `#runs(doc)` grows with `doc`'s own edit and
    /// transclusion history; `|coverage|` is the caller's — on M8's route an
    /// endset's coverage, capped at deposit (M7's `MAX_SLOT_SPANS`).
    /// Admission control is the caller's, as it is for
    /// [`docs_ever_containing`](M5State::docs_ever_containing), and both
    /// factors are cheap to read before asking:
    /// [`content_run_count`](M5State::content_run_count) and
    /// `coverage.len()`.
    ///
    /// HEAP, which the work does not state: the footprint is built whole
    /// before it is normalized — one V-span per overlapping (block, cover)
    /// pair, held live — so the transient reaches that product itself where a
    /// coverage repeats an address the arrangement repeats. A caller pricing
    /// this read prices that vector, as M8's answer budget does; a caller that
    /// needs only whether the footprint is empty asks
    /// [`arranges_any`](M5State::arranges_any), which builds none of it.
    pub fn project(&self, doc: &Address, coverage: &SpanSet) -> SpanSet {
        let mut vspans: Vec<Span> = Vec::new();
        // An absent document is a CASE and not a path: its content run-list is
        // the empty one, which iterates no blocks and answers ⟨⟩.
        for block in self.content_list(doc).iter_blocks() {
            for cover in coverage.iter() {
                let Some(covered) = block.run.offsets_covered_by(cover) else {
                    continue;
                };
                let at = VPos::content(&block.v_start + covered.lo());
                vspans.push(
                    ordinal_vspan(&at, &covered.width())
                        .expect("an OffsetRange is nonempty, so its width is ≥ 1"),
                );
            }
        }
        let set: SpanSet = vspans.into_iter().collect();
        // The output V-spans are all depth-2, hence one level class — safe to
        // normalize (fragmentation across runs/spans coalesces where ranges
        // touch).
        set.normalize()
            .expect("depth-2 V-spans share one level class")
    }

    /// Does `doc`'s CONTENT arrangement hold ANY address `coverage` contains —
    /// is its [`project`](M5State::project) footprint non-empty? Exactly
    /// `!project(doc, coverage).is_empty()`, answered without building the
    /// footprint: the same run-by-cover question `project` asks, stopping at
    /// the first yes, so nothing is held beyond one pair's transient. The
    /// present tense of the corpus's I-side containment (FD-FIND), and the
    /// narrowing that turns
    /// [`docs_ever_containing`](M5State::docs_ever_containing)'s candidates
    /// into present containers — what M6's FINDDOCSCONTAINING asks of each
    /// candidate.
    ///
    /// TOTAL for any coverage, mixed-length included: every run is asked about
    /// every cover through the run's own offset arithmetic
    /// (`Run::offsets_covered_by`, both of whose branches are total), never
    /// through the carried-run test's chain match (`RunUnion::covers`), which
    /// is sound only between two runs — a subtree cover holds addresses of
    /// every length beneath it. CONTENT subspace only, as `project` is.
    ///
    /// COST: at most `#runs(doc) × |coverage|` pair tests — `project`'s
    /// factors, whose admission control stays the caller's — and no heap
    /// beyond one pair's. Absent doc or empty coverage ⇒ `false`.
    pub fn arranges_any(&self, doc: &Address, coverage: &SpanSet) -> bool {
        self.content_list(doc).iter().any(|run| {
            coverage
                .iter()
                .any(|cover| run.offsets_covered_by(cover).is_some())
        })
    }

    /// The current content-image cover (M5-INTERNAL — the SHOWDELETIONS
    /// operand consumed only by `deletions`, §2/§9): `⋃ r.iextent()` over the
    /// content runs. Union (concatenation) only; possibly mixed-length across
    /// transcluded origins — never blindly normalized, and it never crosses a
    /// module seam.
    fn content_image(&self, doc: &Address) -> SpanSet {
        self.content_list(doc).image()
    }

    /// SHOWDELETIONS primitive (§9; ASN-0047 P2; ASN-0075's
    /// `DELETED(a, d) ≡ (a, d) ∈ R ∧ a ∉ ran(M(d))`): what `doc` has ever
    /// contained, minus its current content image, computed PER LEVEL-CLASS —
    /// both operands are iextent-covers that mix origin-lengths when `doc`
    /// transcludes across heterogeneous-depth documents, so each is
    /// partitioned by endpoint length (M1's `by_level_class`),
    /// `difference_sets` runs within each class, and the per-class results
    /// are unioned. Per-class is also the correct semantics:
    /// different-length addresses are distinct and cannot cancel. Classes
    /// ascend by endpoint length, the partition being ordered. M6 reads
    /// SHOWDELETIONS straight off this — neither operand crosses the
    /// boundary. Fault-free.
    ///
    /// COST, AND WHO OWNS IT — the historical operand is what dominates, and
    /// the answer's size bounds none of it. Per call both operands are rebuilt
    /// and partitioned, and each per-class `difference_sets` normalizes and
    /// SORTS its two operands, so the work is
    /// `Θ(|R↾doc| log |R↾doc|) + Θ(#runs(doc))` and the transient heap is
    /// several full copies of `R↾doc`. `|R↾doc|` —
    /// [`recorded_span_count`](M5State::recorded_span_count), cheap to read —
    /// is not bounded here and is monotone (P2, R losing no member): it is
    /// every span `doc` has ever placed, grown by COPY up to
    /// [`MAX_PLACED_RUNS`](crate::MAX_PLACED_RUNS) per request and by VERSION
    /// without a ceiling ([`Vstream::version`](crate::Vstream::version)), so a
    /// document that has deleted much more than it holds costs far more here
    /// than its current arrangement suggests. There is no index over R in v1
    /// (Open decision #3) and no admission gate: this read refuses nothing and
    /// bounds nothing, so admission control and concurrency for the query that
    /// composes on it are the CALLER's, as they are for
    /// [`docs_ever_containing`](M5State::docs_ever_containing) — and a request
    /// naming two documents is not a small request whatever its size.
    pub fn deletions(&self, doc: &Address) -> SpanSet {
        let image = self.content_image(doc).by_level_class();
        // A class the current image does not reach subtracts nothing.
        let absent = SpanSet::empty();
        let mut out = SpanSet::empty();
        for (len, ever) in self.provenance.ever_contained(doc).by_level_class() {
            let now = image.get(&len).unwrap_or(&absent);
            let deleted = difference_sets(&ever, now).expect(
                "per-class operands share one length class, and every span of \
                 either is a run I-extent hence level-uniform — the gate passes",
            );
            out = union(&out, &deleted);
        }
        out
    }

    /// R⁻¹ candidate documents (§9; Conflicts #6) — every document with a
    /// recorded span NOT `Separated` from a span of `coverage`, distinct and
    /// in deterministic Tumbler order. A CANDIDATE SUPERSET of ASN-0124's
    /// FD-HIST `finddocs_R` (the documents that have ever contained an address
    /// of `coverage`), and not that set itself: `SpanRel::Adjacent` is
    /// touching with the spans half-open, so an adjacent recorded span shares
    /// no position with the coverage and its document need never have
    /// contained an address of `coverage` at all.
    ///
    /// WHY THE COARSE TEST. Membership is decided by M1's `classify_spans`,
    /// which is total and length-gate-free, so a MIXED-LENGTH coverage — which
    /// is what transclusion across heterogeneous-depth origins produces — is
    /// answered without the level-class discipline. Exact ever-containment
    /// would cost a per-class intersection of the whole relation against the
    /// coverage, which this read declines; the narrowing below removes the
    /// difference anyway.
    ///
    /// HISTORY, NOT CONTAINMENT, and the corpus keeps the two apart: present
    /// containment is `finddocs` (FD-FIND), whose members each carry a live
    /// witness (FD-SOUND), and it is a SUBSET of this answer (FD-SUPER). TWO
    /// narrowings separate them — from order-overlap to genuine
    /// ever-containment, and from ever to now, the second being FD-GHOST's
    /// `ghosts`, documents that held queried material at some past boundary
    /// and hold none of it now. A caller wanting present containment
    /// discharges BOTH at once with
    /// [`arranges_any`](M5State::arranges_any)`(d, coverage)` — `project(d,
    /// coverage) ≠ ⟨⟩` without the footprint — off the same M2 snapshot, which
    /// answers from the live arrangement and so admits neither a ghost nor a
    /// merely adjacent candidate (M6's FINDDOCSCONTAINING).
    ///
    /// A SUPERSET with no false negatives: a document genuinely holding an
    /// address of `coverage` placed a span that overlaps it in the tumbler
    /// order (P4★ puts every present containment in R), so it is always a
    /// candidate — which is what makes the narrowing sound. Total for any
    /// coverage, mixed-length included.
    ///
    /// COST, AND WHO OWNS IT. Per call: one span comparison for every pair of
    /// (recorded span, coverage span) over the WHOLE relation, each deriving
    /// both operands' endpoints. Neither factor is bounded here — R never
    /// loses a member (P2), so it is the sum of every run ever placed by any
    /// document, and `coverage` is as large as the caller's own aggregation
    /// (M6 builds it from region images, whose size is the source documents'
    /// fragmentation, and caps it as it is produced). There is no index over R
    /// in v1 (Open decision #3, which belongs here, R's owner) and no
    /// admission gate: this method refuses nothing and bounds nothing, so
    /// admission control and concurrency for the query that composes on it
    /// are the CALLER's, and a route that carries this read owes that number.
    /// The relation's total size has no cheap read: it is
    /// [`recorded_span_count`](M5State::recorded_span_count) summed over every
    /// document, which v1 does not keep.
    pub fn docs_ever_containing(&self, coverage: &SpanSet) -> Vec<Address> {
        self.provenance.docs_ever_containing(coverage)
    }
}

#[cfg(test)]
mod tests;
