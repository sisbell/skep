//! Arrangement reads, admission predicates and provenance reads (§D/§E).
//!
//! The arrangement reads (resolve/iter_resolve/point, the run decompositions
//! and their counts, project/arranges_any, the content past an extent), the
//! admission predicates the ops ask, the provenance reads
//! (recorded_span_count/deletions/docs_ever_containing) and the fork-source
//! read (fork_source) are pure over any M2 snapshot (§2, §9).
//!
//! **Level-class discipline** (§2): a SpanSet aggregated across runs — a
//! region image, an endset's coverage, the internal `content_image`, a
//! document's `ever_contained` cover (R↾doc) — is in general mixed-length
//! (transclusion mixes origin lengths), and M1's length-gated set ops fault
//! `LevelMismatch` on mixed operands. Where geometry is needed, M5 keeps each
//! set op inside one class: [`M5State::deletions`] partitions each operand
//! into level-classes by endpoint length (`SpanSet::by_level_class`), runs
//! the M1 op within each class, and unions the per-class results, while
//! [`M5State::project`] and [`M5State::arranges_any`] ask runs about spans
//! pair by pair, intersecting within the run's own class and searching the
//! run's boundary across classes. Where overlap or membership alone suffices
//! — the R⁻¹ candidates, a link's seat — it uses the total
//! `classify_spans`/`contains`. The discipline is encapsulated behind the
//! query methods ([`M5State::project`], [`M5State::arranges_any`],
//! [`M5State::deletions`]) and owed by whoever applies those set ops to run
//! I-extents it aggregates itself — lifting the runs [`M5State::resolve`] and
//! [`M5State::iter_resolve`] hand back through [`Run::iextent`], where the
//! obligation is stated (Conflicts #8).

use num_traits::One;
use skep_address::{difference_sets, union, Address, Nat, Span, SpanSet};

use crate::run::Run;
use crate::run_list::Runs;
use crate::state::M5State;
use crate::vspace::{as_ordinal_vspan, ordinal_vspan, VPos};

impl M5State {
    /// Resolves V→I: the I-runs covering an ordinal-level depth-2 V-span.
    ///
    /// It is V→I resolution (§2; ASN-0058 C0; ASN-0118 accept-and-intersect):
    /// the span's width is `[0, n]`, action point 2, and the runs come
    /// V-ordered, clipped to the arranged range. The span's subspace, ordinal
    /// and count come from the one reader that establishes it has them.
    ///
    /// **The runs tile V contiguously**, which is what lets a caller recover
    /// each run's V-position without asking a second time: the first run
    /// returned holds V-ordinal `max(ord, 1)` — the clamp is load-bearing, a
    /// span opening at ordinal 0 still starting its answer at 1 — and each
    /// next run begins where the previous one ends, so accumulating widths
    /// from that start gives every run's V-start. There are no V-gaps to skip
    /// because there are none to have: a subspace's arranged positions are its
    /// dense prefix (D-SEQ★, stated on [`M5State`]), so a span reaching past
    /// the prefix is clipped and one opening past it binds nothing at all
    /// rather than skipping forward to a later position.
    ///
    /// **Defensive** (returns ⟨⟩, cannot fault — no `Result`) unless the span
    /// is usable: a span the shared shape reader refuses — the same shape
    /// COPY's `NotOrdinalVSpan` rejects on — yields ⟨⟩, and so does a
    /// shape-valid span whose subspace ∉ {s_C, s_L}, a `DocArrangement` having
    /// exactly the content and link run-lists. Absent doc ⇒ ⟨⟩ (M6/M8
    /// disambiguate registered-empty vs unallocated via M3). A caller that
    /// must tell "bad request" from "genuinely empty" calls
    /// [`is_ordinal_vspan`](crate::is_ordinal_vspan) itself before asking;
    /// M6's own request gate is deliberately weaker (ASN-0115
    /// well-formedness, `#start ≥ 2`), leaving depth compatibility to this
    /// defensive fold.
    ///
    /// **Mixed-length hazard** for whoever aggregates the returned runs'
    /// I-extents: see [`Run::iextent`].
    pub fn resolve(&self, doc: &Address, span: &Span) -> Vec<Run> {
        self.iter_resolve(doc, span).collect()
    }

    /// Returns [`resolve`](M5State::resolve)'s runs lazily, as they are pulled.
    ///
    /// It is `resolve`'s lazy twin — the same runs, in the same order, under
    /// the same defensive folds, clipped as they are pulled — so every promise
    /// `resolve` makes of its runs, the contiguous V tiling included, is made
    /// of what this yields.
    ///
    /// The form for a consumer that carries a budget of its own, and the
    /// reason is what the two forms cost: a resolution's size is the source
    /// document's fragmentation, which the asking request does not choose.
    /// Pulled a run at a time and counted as it is pulled, an over-budget
    /// span stops its walk at the budget rather than materializing the
    /// source's every run and being refused afterwards, so what the consumer
    /// holds live is its budget and not the resolution. COPY's accumulator
    /// (capped at [`MAX_PLACED_RUNS`](crate::MAX_PLACED_RUNS)) consumes it so,
    /// and so do the neighbours' produced-as-they-go budgets: M6's COMPARE
    /// blocks, FINDDOCSCONTAINING coverage and RETRIEVEV delivery,
    /// skep-discovery's region images, M7's MAKELINK slot spans and M10's
    /// successor slot spans. [`resolve`](M5State::resolve) is this collected,
    /// for a caller that hands the runs onward whole.
    ///
    /// What pulling does not bound is the walk to the span's opening ordinal,
    /// whatever the call yields. Its contract is a ceiling: `#runs` of the
    /// list the span's subspace selects —
    /// [`content_run_count`](M5State::content_run_count) or
    /// [`link_run_count`](M5State::link_run_count), one lookup before asking
    /// — which a span opening past the arranged end reaches, and which holds
    /// under any backing the run-list takes (Open decision #1). The
    /// `im::Vector` backing walks from the first run, passing every run that
    /// ends before the opening ordinal, so it also stops within
    /// `min(#runs, ord + count)` runs: each run holds at least one position of
    /// the dense prefix (D-SEQ★), so fewer runs than `ord + count` open before
    /// the span's reach. That tighter figure is the backing's and not this
    /// card's: the profiling-gated alternatives Open decision #1 holds in
    /// reserve locate the opening ordinal in `O(log #runs)` steps whatever its
    /// reach, so a caller pricing a walk by its reach re-prices when the
    /// backing changes, and one pricing it at `#runs` does not.
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

    /// Returns `M(d)(p)`, the I-address at V-position `p` (§2).
    ///
    /// It answers `None` when `p.subspace ∉ {s_C, s_L}` (no such run-list) or
    /// the ordinal is unarranged — which under D-SEQ★ ([`M5State`]) is
    /// exactly `p.ordinal ∉ [1, n_s]`, a subspace's arranged positions being
    /// its dense prefix, so one bound settles membership. Every returned
    /// `Address` is T4-valid (synthesis routes through `validate`).
    pub fn point(&self, doc: &Address, p: &VPos) -> Option<Address> {
        self.arrangement_of(doc)
            .list(&p.subspace)?
            .point(&p.ordinal)
    }

    /// Returns the canonical, V-ordered content run decomposition, lent.
    ///
    /// It is maximally merged (ASN-0058 M12), and so unique: two content
    /// arrangements are the same V→I map exactly when their decompositions
    /// are equal. Absent doc ⇒ yields nothing. The runs tile the whole content
    /// prefix `[1, n_C]` contiguously (D-SEQ★, stated on [`M5State`]), so the
    /// first begins at V-ordinal 1 and each next where the previous ends.
    ///
    /// **Lent, not cloned**: the runs are stored whole, so this hands out a
    /// borrow of each. A caller that keeps runs `.cloned()` the ones it keeps;
    /// two decompositions compare with `Iterator::eq` without collecting
    /// either; and `.len()` is the number
    /// [`content_run_count`](M5State::content_run_count) answers.
    pub fn content_runs(&self, doc: &Address) -> Runs<'_> {
        self.content_list(doc).iter()
    }

    /// Returns the canonical, V-ordered link run decomposition, lent.
    ///
    /// It is maximally merged, and so unique as
    /// [`content_runs`](M5State::content_runs)' is: two link arrangements are
    /// the same V→I map exactly when their decompositions are equal. Absent
    /// doc ⇒ yields nothing; it tiles `[1, n_L]` as `content_runs` tiles the
    /// content prefix, D-SEQ★ holding per subspace. Lent as `content_runs`'
    /// runs are, and its `.len()` is
    /// [`link_run_count`](M5State::link_run_count).
    pub fn link_runs(&self, doc: &Address) -> Runs<'_> {
        self.link_list(doc).iter()
    }

    /// Returns `n_C(d)`, the arranged content width.
    ///
    /// Absent doc ⇒ 0. Under D-SEQ★ ([`M5State`]) it is equally the largest
    /// arranged content ordinal and the width sum of
    /// [`content_runs`](M5State::content_runs): the content positions are
    /// `[1, n_C]` with no holes, so a count fixes the extent (ASN-0113 W2/W4)
    /// rather than over-reporting one.
    pub fn content_count(&self, doc: &Address) -> Nat {
        self.content_list(doc).total_width()
    }

    /// Returns `n_L(d)`, the arranged link width.
    ///
    /// Absent doc ⇒ 0; the D-SEQ★ reading of
    /// [`content_count`](M5State::content_count) holds per subspace, so this
    /// is likewise the largest arranged link ordinal.
    pub fn link_count(&self, doc: &Address) -> Nat {
        self.link_list(doc).total_width()
    }

    /// Returns `#runs(doc)` in the content subspace.
    ///
    /// That is how many runs [`content_runs`](M5State::content_runs) would
    /// hand back, without handing them back — not
    /// [`content_count`](M5State::content_count), which is the positions those
    /// runs cover. It is the quantity COPY's resolve walk — which COPY charges
    /// at this number against
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

    /// Returns `#runs(doc)` in the link subspace.
    ///
    /// It is what [`content_run_count`](M5State::content_run_count) is in the
    /// content one. One map lookup, reading no run; absent doc ⇒ 0.
    pub fn link_run_count(&self, doc: &Address) -> usize {
        self.link_list(doc).run_count()
    }

    /// Returns `|R↾doc|`, how many spans R records for `doc`.
    ///
    /// That is one per run it has ever placed, deleted or not (P2). It is one
    /// of the two terms of [`deletions`](M5State::deletions)' cost, and the
    /// one a document's current arrangement does not reveal, so a caller
    /// pricing SHOWDELETIONS reads it here. One map lookup, reading no span;
    /// absent doc ⇒ 0.
    pub fn recorded_span_count(&self, doc: &Address) -> usize {
        self.provenance.recorded_span_count(doc)
    }

    /// Returns whether `ord` is a placement boundary of `doc`'s content.
    ///
    /// A boundary is `1 ≤ ord ≤ n_C + 1` (§1/§3): the arrangement's own
    /// admission rule, asked rather than re-derived, so the append boundary
    /// (and the `ord = 1` case at `n_C = 0`, ASN-0116's
    /// FirstInsertionPosition) has one definition for INSERT, COPY, REINSTATE
    /// and REARRANGE's cuts to share. The verdict each op reports for a
    /// refusal stays with that op's error type.
    pub(crate) fn admits_content_boundary(&self, doc: &Address, ord: &Nat) -> bool {
        *ord >= Nat::one() && *ord <= &self.content_count(doc) + &Nat::one()
    }

    /// Returns whether `doc` arranges no content, `n_C = 0`.
    ///
    /// Asked of the run-list's emptiness, O(1), rather than of
    /// [`content_count`](M5State::content_count), which sums every run's
    /// width to learn the same bit. COPY's `EmptySource` and REARRANGE's
    /// `EmptyContentSubspace` ask it. Absent doc ⇒ `true`.
    pub(crate) fn content_is_empty(&self, doc: &Address) -> bool {
        self.content_list(doc).is_empty()
    }

    /// Returns whether `doc` arranges content ordinal `ord` (§4).
    ///
    /// That is, whether `ord` is a position holding an I-address,
    /// `ord ∈ [1, n_C]`. Answered off the run-list's own locate, which is the
    /// same walk `point` uses. One short of
    /// [`admits_content_boundary`](M5State::admits_content_boundary), which
    /// admits the append boundary as well.
    pub(crate) fn arranges_content_position(&self, doc: &Address, ord: &Nat) -> bool {
        self.content_list(doc).locate(ord).is_some()
    }

    /// Returns whether `at` names a fresh content position of `doc`.
    ///
    /// A fresh position lies past the arranged extent,
    /// `at.subspace = s_C ∧ at.ordinal > n_C`, so that an insert there appends
    /// and disturbs no arrangement (PUB-2.59, PUB-2.61: the deposit shape).
    /// It is the one fact the write path keys the deposit exemption on beside
    /// the caller's declaration (PUB-9.13, declared).
    ///
    /// Deliberately wider than the append boundary: an ordinal past
    /// `n_C + 1` is fresh too — it touches nothing arranged — and is left for
    /// the op's own shape check to refuse `OutOfBounds`, so a declared
    /// deposit aimed past the boundary is told its position is bad rather
    /// than that its target is published. An insert at or below `n_C` shifts
    /// the suffix, which is a disturbance, and a link-subspace position is
    /// not a deposit shape at all.
    pub(crate) fn names_fresh_content_position(&self, doc: &Address, at: &VPos) -> bool {
        at.is_content() && at.ordinal > self.content_count(doc)
    }

    /// Returns whether `doc`'s arranged content contains the whole range.
    ///
    /// The range is `[from, from + width)`, and the test
    /// `from + width ≤ n_C + 1`, subtraction-free (§4): the containment half
    /// of DELETE's admission (ASN-0117: "containment within the document's
    /// current arranged extent"), stated where `n_C` lives. "Contain" here is
    /// the V-side word: a range of V-ordinals lying inside the arranged prefix
    /// `[1, n_C]`. It is not the corpus's I-side containment — a document
    /// holding an I-address in its image (FD-FIND) — whose present tense is
    /// [`project`](M5State::project) and whose history is
    /// [`docs_ever_containing`](M5State::docs_ever_containing).
    ///
    /// **Precondition.** `from ≥ 1`, and this is the upper bound alone.
    /// Arranged content is `[1, n_C]`, so containment of `[from, from + width)`
    /// is `from ≥ 1 ∧ from + width ≤ n_C + 1`; given the first conjunct the
    /// test below is containment, and without it the answer says nothing about
    /// where the range opens — `from = 0` passes for every document, including
    /// an empty one, though ordinal 0 is arranged nowhere. Every caller
    /// establishes the conjunct by asking
    /// [`arranges_content_position`](M5State::arranges_content_position)
    /// first, which is why this predicate does not re-ask it.
    pub(crate) fn contains_content_range(&self, doc: &Address, from: &Nat, width: &Nat) -> bool {
        from + width <= &self.content_count(doc) + &Nat::one()
    }

    /// Returns the content runs of `doc` past ordinal `extent`.
    ///
    /// They are positions `[extent + 1, n_C]`, V-ordered, the boundary run
    /// clipped, and nothing at all when `extent ≥ n_C`. The publish shot's
    /// carried tail (PUB-2.42, PUB-2.45): a published member's content
    /// changes only by deposits appended at fresh positions (PUB-2.43), so
    /// its positions past the extent a staged copy took are exactly the
    /// deposits that copy's render post-dates. Asked of the arrangement,
    /// which knows where its content ends, so the shot names a boundary and
    /// derives no count of its own.
    ///
    /// Answered off the run-list's own suffix walk, which names no upper
    /// bound and sums no total to find one. Lazy as that walk is, so a
    /// consumer with a budget of its own stops it at the budget. Absent doc
    /// ⇒ nothing.
    pub(crate) fn content_runs_past(&self, doc: &Address, extent: &Nat) -> impl Iterator<Item = Run> + '_ {
        self.content_list(doc).iter_resolve_from(&(extent + &Nat::one()))
    }

    /// Returns whether `link` is seated in `doc`'s link subspace (§8, CL-UNIQ).
    ///
    /// It is the link run-list's own membership answer, so a link interior to
    /// a coalesced link run counts as seated. Absent doc ⇒ not seated.
    pub(crate) fn seats_link(&self, doc: &Address, link: &Address) -> bool {
        self.link_list(doc).holds(link)
    }

    /// Returns the V-positions whose content I-address falls in `coverage`.
    ///
    /// It is I→V projection (§2; ASN-0119 RA7c) over `doc`, content subspace
    /// only, by construction (link reverse-discovery is M7's BH3; there is no
    /// subspace argument). `coverage` is an I-address cover, an endset's
    /// coverage (M8's route) or a region's runs lifted through
    /// [`Run::iextent`] alike, possibly fragmented and mixed-length; the
    /// positions come back as depth-2 V-spans, normalized. The result is the
    /// footprint those addresses have in `doc` (ASN-0119's `project`), which
    /// is why a footprint interrupted in V-space comes back as several spans.
    /// Total — the level-class discipline is applied internally, so the call
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
    /// **Heap**, which the work does not state: the footprint is built whole
    /// before it is normalized — one V-span per overlapping (block, cover)
    /// pair, held live — so the transient reaches that product itself where a
    /// coverage repeats an address the arrangement repeats. A caller pricing
    /// this read prices that vector, as M8's answer budget does; a caller that
    /// needs only whether the footprint is empty asks
    /// [`arranges_any`](M5State::arranges_any), which builds none of it.
    pub fn project(&self, doc: &Address, coverage: &SpanSet) -> SpanSet {
        let mut vspans: Vec<Span> = Vec::new();
        // An absent document is a case and not a path: its content run-list is
        // the empty one, which iterates no blocks and answers ⟨⟩.
        for block in self.content_list(doc).iter_blocks() {
            for cover in coverage.iter() {
                let Some(covered) = block.run.offsets_covered_by(cover) else {
                    continue;
                };
                let at = VPos::content(&block.v_start + covered.lo());
                vspans.push(
                    ordinal_vspan(at, covered.width())
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

    /// Returns whether `doc`'s content holds any address `coverage` contains.
    ///
    /// That is, whether its [`project`](M5State::project) footprint is
    /// non-empty: exactly `!project(doc, coverage).is_empty()`, answered
    /// without building the footprint — the same run-by-cover question
    /// `project` asks, stopping at the first yes, so nothing is held beyond
    /// one pair's transient. The present tense of the corpus's I-side
    /// containment (FD-FIND), and the narrowing that turns
    /// [`docs_ever_containing`](M5State::docs_ever_containing)'s candidates
    /// into present containers — what M6's FINDDOCSCONTAINING asks of each
    /// candidate its reader may read.
    ///
    /// Total for any coverage, mixed-length included: each run is asked about
    /// a cover through the run's own offset arithmetic
    /// (`Run::offsets_covered_by`, both of whose branches are total), never
    /// through the carried-run test's chain match (`RunUnion::covers`), which
    /// is sound only between two runs — a subtree cover holds addresses of
    /// every length beneath it. Content subspace only, as `project` is.
    ///
    /// **Cost**: at most `#runs(doc) × |coverage|` pair tests — `project`'s
    /// factors, whose admission control stays the caller's — and no heap
    /// beyond one pair's. Absent doc or empty coverage ⇒ `false`.
    pub fn arranges_any(&self, doc: &Address, coverage: &SpanSet) -> bool {
        self.content_list(doc).iter().any(|run| {
            coverage
                .iter()
                .any(|cover| run.offsets_covered_by(cover).is_some())
        })
    }

    /// Returns the current image cover: `⋃ r.iextent()` over the content runs.
    ///
    /// It is M5-internal — the SHOWDELETIONS operand consumed only by
    /// `deletions` (§2/§9). Union (concatenation) only; possibly mixed-length
    /// across transcluded origins — never blindly normalized, and it never
    /// crosses a module seam.
    fn content_image(&self, doc: &Address) -> SpanSet {
        self.content_list(doc).image()
    }

    /// Returns what `doc` has ever contained, minus its current content image.
    ///
    /// It is the SHOWDELETIONS primitive (§9; ASN-0047 P2; ASN-0075's
    /// `DELETED(a, d) ≡ (a, d) ∈ R ∧ a ∉ ran(M(d))`), computed per
    /// level-class — both operands are iextent-covers that mix origin-lengths
    /// when `doc` transcludes across heterogeneous-depth documents, so each is
    /// partitioned by endpoint length (M1's `by_level_class`),
    /// `difference_sets` runs within each class, and the per-class results
    /// are unioned. Per-class is also the correct semantics:
    /// different-length addresses are distinct and cannot cancel. Classes
    /// ascend by endpoint length, the partition being ordered. M6 reads
    /// SHOWDELETIONS straight off this — neither operand crosses the
    /// boundary. Fault-free.
    ///
    /// **Cost, and who owns it** — the historical operand can dominate, and
    /// the answer's size bounds none of it. Per call both operands are rebuilt
    /// and partitioned, and each per-class `difference_sets` normalizes and
    /// sorts its two operands, so the work is
    /// `Θ(|R↾doc| log |R↾doc| + #runs(doc) log #runs(doc))` and the transient
    /// heap is several full copies of each operand. `|R↾doc|` —
    /// [`recorded_span_count`](M5State::recorded_span_count), cheap to read —
    /// is not bounded here and is monotone (P2, R losing no member): it is
    /// every span `doc` has ever placed, grown by INSERT, by COPY, REINSTATE
    /// and the shot up to [`MAX_PLACED_RUNS`](crate::MAX_PLACED_RUNS) per
    /// request, and by VERSION without a ceiling
    /// ([`Vstream::version`](crate::Vstream::version)), so a document that has
    /// deleted much more than it holds costs far more here than its current
    /// arrangement suggests. There is no index over R in v1 (Open decision #3)
    /// and no admission gate: this read refuses nothing and bounds nothing, so
    /// admission control and concurrency for the query that composes on it
    /// are the caller's, as they are for
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

    /// Returns the fork source of `doc`: the address `doc` was born sharing.
    ///
    /// It is the `source` of the
    /// [`VersionSnapshot`](crate::M5Rec::VersionSnapshot) that minted it,
    /// which is the reading surface `version` resolved at the mint — a version
    /// member where the source had a chain (its head, pinned then, or the
    /// member named), the bare document otherwise — and which the doc-metadata
    /// read serves as `source` to every reader of the fork (the fork-source
    /// design record).
    ///
    /// **The invariant** it answers under is SOURCE★, stated on [`M5State`]:
    /// the entry is written by the `version` record alone, once, at the
    /// mint, and never moved — not by a shot, which mints its member off no
    /// source, not by a placement, not by a `fork`, which reaches this slice
    /// with no record. So `Some` exactly for a document a `version` minted,
    /// an owned member and a cross-owner fork alike, and `None` for every
    /// other address: a trunk document no `version` minted, a shot member, a
    /// `fork`-minted or created document, and an address never minted. The
    /// answer is one hop — a fork of a fork answers the fork it was taken
    /// from, never the line's root — and it is the same at every position
    /// from the mint on, the fact being immutable.
    ///
    /// Answers the address named, as every read here does: a trunk whose
    /// chain a `version` opened answers its own entry — `None` unless a
    /// `version` minted the trunk itself — never its member's source; a
    /// member answers its own. One map lookup, reading no run; the address
    /// is lent, as [`shot_terms`](M5State::shot_terms) lends the terms, and a
    /// caller keeping it clones it.
    pub fn fork_source(&self, doc: &Address) -> Option<&Address> {
        self.fork_sources.get(doc)
    }

    /// Returns the R⁻¹ candidate documents for `coverage` (§9; Conflicts #6).
    ///
    /// They are every document with a recorded span not `Separated` from a
    /// span of `coverage`, distinct and in deterministic Tumbler order: a
    /// candidate superset of ASN-0124's FD-HIST `finddocs_R` (the documents
    /// that have ever contained an address of `coverage`), and not that set
    /// itself: `SpanRel::Adjacent` is touching with the spans half-open, so an
    /// adjacent recorded span shares no position with the coverage and its
    /// document need never have contained an address of `coverage` at all.
    ///
    /// **Why the coarse test.** Membership is decided by M1's
    /// `classify_spans`, which is total and length-gate-free, so a
    /// mixed-length coverage — which is what transclusion across
    /// heterogeneous-depth origins produces — is answered without the
    /// level-class discipline. Exact ever-containment would cost a per-class
    /// intersection of the whole relation against the coverage, which this
    /// read declines; the narrowing below removes the difference anyway.
    ///
    /// **History, not containment**, and the corpus keeps the two apart:
    /// present containment is `finddocs` (FD-FIND), whose members each carry a
    /// live witness (FD-SOUND), and it is a subset of this answer (FD-SUPER).
    /// Two narrowings separate them — from order-overlap to genuine
    /// ever-containment, and from ever to now, the second being FD-GHOST's
    /// `ghosts`, documents that held queried material at some past boundary
    /// and hold none of it now. A caller wanting present containment
    /// discharges both at once with
    /// [`arranges_any`](M5State::arranges_any)`(d, coverage)` — `project(d,
    /// coverage) ≠ ⟨⟩` without the footprint — off the same M2 snapshot, which
    /// answers from the live arrangement and so admits neither a ghost nor a
    /// merely adjacent candidate (M6's FINDDOCSCONTAINING).
    ///
    /// **A superset with no false negatives**: a document genuinely holding an
    /// address of `coverage` placed a span that overlaps it in the tumbler
    /// order (P4★ puts every present containment in R), so it is always a
    /// candidate — which is what makes the narrowing sound. Total for any
    /// coverage, mixed-length included.
    ///
    /// **Cost, and who owns it.** Per call: at most one span comparison for
    /// every pair of (recorded span, coverage span) over the whole relation —
    /// a document's walk stops at its first match — each deriving both
    /// operands' endpoints. Neither factor is bounded here — R never
    /// loses a member (P2), so it is the sum of every run ever placed by any
    /// document, and `coverage` is as large as the caller's own aggregation
    /// (M6 builds it from region images, whose size is the source documents'
    /// fragmentation, and caps it as it is produced). There is no index over R
    /// in v1 (Open decision #3, which belongs here, R's owner) and no
    /// admission gate: this method refuses nothing and bounds nothing, so
    /// admission control and concurrency for the query that composes on it
    /// are the caller's, and a route that carries this read owes that number.
    /// The relation's total size has no cheap read: it is
    /// [`recorded_span_count`](M5State::recorded_span_count) summed over every
    /// document, which v1 does not keep.
    pub fn docs_ever_containing(&self, coverage: &SpanSet) -> Vec<Address> {
        self.provenance.docs_ever_containing(coverage)
    }
}

#[cfg(test)]
mod tests;
