//! §A — the `Run` value: one contiguous I-extent placed in an arrangement,
//! the run's own position arithmetic, and the ONE admissible Run→Span lift
//! ([`Run::iextent`]).
//!
//! The arithmetic divides by whether a caller can get the question wrong.
//! [`Run::addrs`], [`Run::into_addrs`] and [`Run::reach`] take no offset, so
//! they are total and published; [`Run::tumbler_at`], [`Run::addr_at`] and
//! [`Run::offsets_covered_by`] (with the [`OffsetRange`] it answers in) are
//! crate-private, the first two carrying a `k ≤ width` precondition nothing
//! can report and the third an operand the level-class discipline governs.

use num_traits::{One, Zero};
use serde::{Deserialize, Serialize};
use skep_address::{intersect, shift, validate, Address, Nat, Span, Tumbler};

/// One arrangement run: `width` consecutive I-addresses starting at
/// `i_start`, occupying implicit consecutive V-ordinals (§Core data model —
/// V-positions are never stored; a run's V-start is a prefix sum, which is
/// what makes D-SEQ★/D-CTG★/D-MIN★ hold by construction).
///
/// STANDING INVARIANTS: every `Run` has `width ≥ 1` AND an `i_start` that is
/// a FULL ELEMENT POSITION — `doc·0·subspace·ordinal`, an element field of
/// exactly two components — so its LAST COMPONENT IS THE ORDINAL. That second
/// clause is the one the position arithmetic stands on, and element level
/// alone does not supply it: T4b admits element fields of any length ≥ 1, so
/// a subspace BASE `doc·0·subspace` is element-level too, and advancing its
/// last component walks the subspace id rather than an ordinal (M1's TA7a
/// hazard, stated on `shift`). `Run::admits_start` is the predicate; both
/// invariants hold for every `Run` in the process, not merely for every one
/// this crate minted.
///
/// Fields are CRATE-PRIVATE: a foreign crate can neither build a `Run` by
/// struct literal nor mutate one it holds — including an OWNED `Run` returned
/// by `resolve`/`content_runs`/`link_runs` — so runs are read-only across
/// every seam (M6/M7/M8 read via the [`i_start`](Run::i_start)/
/// [`width`](Run::width) accessors). [`Run::new`] is the sole foreign
/// constructor, and it is also the DESERIALIZATION path: a decoded Run
/// re-enters it through the serde shadow below, so a journalled
/// [`ContentPlace`](crate::M5Rec::ContentPlace) cannot carry a Run the
/// constructor would refuse, and a journalled
/// [`LinkSeat`](crate::M5Rec::LinkSeat) — which carries a bare `Address` and
/// so re-enters T4 alone — is minted through it by the fold. That is what
/// justifies the `.expect`s in the
/// run's own position arithmetic — they rest on the type, not on M2's
/// checkpoint integrity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RunShadow")]
pub struct Run {
    pub(crate) i_start: Address,
    pub(crate) width: Nat,
}

/// The deserialization mint path (the serde `try_from` shadow, as M1's
/// `Address`/`Span`/`Tumbler` each carry one): decoded field-by-field, then
/// re-entered through [`Run::new`], so a `width = 0` or a start that is not a
/// full element position in a journal or a checkpoint is a decode failure M2
/// reports as corruption rather than a value that panics [`Run::iextent`] on
/// the next fold to touch it.
///
/// It reads exactly what a `Run` writes: the same two fields in the same
/// order, and `Serialize` is derived on `Run` itself, so the shadow costs the
/// encoding nothing.
#[derive(Deserialize)]
struct RunShadow {
    i_start: Address,
    width: Nat,
}

impl TryFrom<RunShadow> for Run {
    type Error = &'static str;
    fn try_from(s: RunShadow) -> Result<Run, &'static str> {
        Run::new(s.i_start, s.width)
            .ok_or("run: width ≥ 1 and a full element-position i_start (doc·0·subspace·ordinal)")
    }
}

/// A NONEMPTY half-open range `[lo, hi)` of one run's own offsets — the
/// positions of that run which some span covers, within `[0, width]`. The
/// answer [`Run::offsets_covered_by`] gives, given a name because it is one
/// thing: the two bounds never travel apart, and the quantity the I→V read
/// actually wants from them is [`width`](OffsetRange::width), which the range
/// derives rather than its reader.
///
/// NONEMPTY IS THE INVARIANT, and it is why `width` is total: `lo < hi`
/// always, "covers none" being `None` rather than an empty range. The fields
/// are private to this module and [`Run::offsets_covered_by`] is the only
/// producer, so no reader can forge a range the subtraction would underflow
/// on — both of that method's branches establish the strict inequality, the
/// intersect branch from `start < reach` on the intersection it found and the
/// boundary-search branch from its explicit `k_lo < k_hi` test.
///
/// Named fields, not a tuple: both bounds are `Nat`, so a positional
/// destructuring would put them back within swapping distance of each other —
/// the reason [`VPos`](crate::VPos) and the span reader's `OrdinalVSpan`
/// carry theirs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct OffsetRange {
    /// The first covered offset.
    lo: Nat,
    /// One past the last covered offset.
    hi: Nat,
}

impl OffsetRange {
    /// Where the covered range OPENS — the run offset whose V-position is the
    /// first the covering span reaches.
    pub(crate) fn lo(&self) -> &Nat {
        &self.lo
    }

    /// HOW MANY of the run's positions the range covers, `hi − lo`. The count
    /// a V-range is built from, derived here rather than at the read that
    /// needs it, and ≥ 1 by the standing nonemptiness invariant.
    pub(crate) fn width(&self) -> Nat {
        &self.hi - &self.lo
    }
}

impl Run {
    /// May `a` start a run — is it a FULL ELEMENT POSITION
    /// `doc·0·subspace·ordinal`? The one definition of what the position
    /// arithmetic below requires of a start, so [`Run::new`] and the crate's
    /// other mint sites ask one question rather than each spelling a clause.
    ///
    /// The element field must be EXACTLY two components. `Some` alone —
    /// element level, `zeros(a) = 3` — is not enough: T4b admits element
    /// fields of any length ≥ 1, so a one-component field is a subspace base
    /// whose last component is the subspace id, and a longer one is a
    /// subdivision T7 leaves open whose last component is not an ordinal
    /// either. In both cases the ordinal advance of [`tumbler_at`](Run::tumbler_at)
    /// would move something that is not an ordinal.
    pub(crate) fn admits_start(a: &Address) -> bool {
        a.element_field().is_some_and(|e| e.len() == 2)
    }

    /// Checked constructor — the ONE door: `None` iff `width == 0` OR
    /// `i_start` is not a full element position `doc·0·subspace·ordinal`.
    /// Every Run that is not built by M5's own emission sites walks through
    /// here, an external producer and a decoded journal or checkpoint alike —
    /// the serde `try_from` shadow routes deserialization into this function.
    ///
    /// M5's own sites divide in two. The PROPAGATING ones — run-list
    /// split/coalesce, `resolve`, `content_runs`/`link_runs`, the content
    /// placing fold — build Runs by the in-crate struct literal from a start
    /// that is already one: a start reaching them is a minted element address
    /// or an in-crate ordinal shift of one, and such a shift preserves the
    /// element field's length. The two ORIGINATING ones establish it instead,
    /// and each does so at its own door: `insert` places what
    /// `M3State::mint_content` returns, which is `doc·0·s_C·ordinal` by
    /// construction, and the `LinkSeat` fold seats an address that arrives in
    /// a record, so it calls THIS function — `stage_seat_link` checks the
    /// shape on the live path, but a replayed record's `Address` re-enters
    /// only M1's `validate`, and T4-validity does not imply a full element
    /// position.
    ///
    /// Field privacy then closes the mutate-after-obtain path: a foreign
    /// holder cannot later set `width = 0` or swap `i_start` on any Run it
    /// obtained, owned or borrowed.
    pub fn new(i_start: Address, width: Nat) -> Option<Run> {
        if width.is_zero() || !Run::admits_start(&i_start) {
            return None;
        }
        Some(Run { i_start, width })
    }

    /// Read accessor — with [`width`](Run::width), the only foreign field
    /// access.
    pub fn i_start(&self) -> &Address {
        &self.i_start
    }

    /// Read accessor — the run's width (≥ 1 by standing invariant).
    pub fn width(&self) -> &Nat {
        &self.width
    }

    /// The tumbler at offset `k`: `i_start` advanced by `k` ordinals. Offsets
    /// `k ∈ [0, width)` are the run's own positions; `k = width` is its
    /// exclusive reach.
    ///
    /// REQUIRES `k ≤ width` — the CALLER's obligation, and one nothing can
    /// report. Past the reach the shift still yields a well-formed tumbler,
    /// which [`addr_at`](Run::addr_at) still validates: an address outside
    /// this run, indistinguishable from one it holds. A debug build stops on
    /// it, because a value is the wrong answer to a broken precondition.
    ///
    /// THE ONE PLACE the raw `shift` is applied to a run, and the one place
    /// the safety argument is made: the standing full-element-position
    /// invariant ([`admits_start`](Run::admits_start) — an element field of
    /// exactly two components, so the last component IS the ordinal) puts
    /// every such shift inside M1's stated safe window, never the TA7a
    /// text→link mis-shift of a subspace base. Every other position question
    /// in the crate — [`addr_at`](Run::addr_at), [`reach`](Run::reach),
    /// [`iextent`](Run::iextent), the run-list's I-adjacency test — is asked
    /// of the run through one of those, so the argument is discharged once.
    ///
    /// CRATE-PRIVATE for the sake of that same precondition, as
    /// [`addr_at`](Run::addr_at) beside it is: an offset is a thing a caller
    /// can get wrong, and outside this crate there is no question about a
    /// run's positions that needs one. A consumer wanting the positions asks
    /// [`addrs`](Run::addrs) or [`into_addrs`](Run::into_addrs); one wanting
    /// the exclusive end asks [`reach`](Run::reach), which takes no offset at
    /// all. Every published question about a run is therefore total.
    pub(crate) fn tumbler_at(&self, k: &Nat) -> Tumbler {
        debug_assert!(
            *k <= self.width,
            "run offset past the reach: k ≤ width is the caller's obligation"
        );
        shift(self.i_start.tumbler(), k)
    }

    /// The `Address` at offset `k` — the run's start advanced by `k` ordinals
    /// and re-validated, REQUIRING `k ≤ width` as the shift does.
    /// Ordinal-shifting a valid element I-start preserves T4-validity, so the
    /// `.expect` flags an internal-invariant violation, never a domain case.
    ///
    /// CRATE-PRIVATE for the precondition it inherits, and for the reason
    /// [`tumbler_at`](Run::tumbler_at) states: past the reach this answers
    /// with a T4-valid element address OUTSIDE the run, which no caller could
    /// tell from one the run holds and no release build stops on.
    pub(crate) fn addr_at(&self, k: &Nat) -> Address {
        validate(self.tumbler_at(k))
            .expect("ordinal shift of a valid element I-start is T4-valid by construction")
    }

    /// ONE I-STEP PAST the run's last position — the exclusive end of its
    /// I-extent, `i_start` advanced by `width`. The half-open upper bound
    /// every question about where a run *ends* wants: [`iextent`](Run::iextent)
    /// is `[i_start, reach)`, and two runs are I-adjacent exactly when the
    /// right one starts where the left one reaches.
    ///
    /// NO PRECONDITION, which is the point of publishing it: there is no
    /// offset to get wrong, so a consumer asking for a run's end cannot ask
    /// for something else by miscounting. `Tumbler` rather than `Address`
    /// because the reach is a bound and not a position — it names the first
    /// address the run does NOT hold, which the run has no claim about.
    pub fn reach(&self) -> Tumbler {
        self.tumbler_at(&self.width)
    }

    /// The run's addresses — offsets `[0, width)`, in I-order, which is also
    /// V-order (a run occupies consecutive V-ordinals). The sequence a run
    /// denotes, asked of the run, so a consumer that needs the positions
    /// rather than the extent does not count them itself. For a caller
    /// holding the run BY VALUE, [`into_addrs`](Run::into_addrs).
    ///
    /// Yields OWNED addresses because a run stores none: it stores a start and
    /// a width, and each position is the start advanced by an offset.
    /// That is why this is an inherent method and not `IntoIterator for &Run`,
    /// where a caller would rightly expect borrowed items. It is likewise not
    /// an `ExactSizeIterator`: `width` is a `Nat`, so a `len() -> usize` would
    /// be a lie at the top of its range.
    pub fn addrs(&self) -> impl Iterator<Item = Address> + '_ {
        let mut k = Nat::zero();
        std::iter::from_fn(move || {
            (k < self.width).then(|| {
                let a = self.addr_at(&k);
                k = &k + &Nat::one();
                a
            })
        })
    }

    /// The run's addresses, TAKING THE RUN — the same sequence
    /// [`addrs`](Run::addrs) yields, for a caller that owns the run rather
    /// than keeping it. That is the commoner shape at M5's seams: `resolve`,
    /// `content_runs` and `link_runs` all hand back `Vec<Run>`, so a consumer
    /// flat-mapping runs to addresses holds each run only for as long as it
    /// walks it, and the borrowing form cannot outlive the vector it consumes.
    ///
    /// The two share a body rather than one calling the other: expressing this
    /// through `addrs` would need the run alive beside the iterator, and
    /// expressing `addrs` through this one would clone a run its caller has
    /// already borrowed. Owned items and no `ExactSizeIterator`, for the
    /// reasons stated on [`addrs`](Run::addrs).
    pub fn into_addrs(self) -> impl Iterator<Item = Address> {
        let mut k = Nat::zero();
        std::iter::from_fn(move || {
            (k < self.width).then(|| {
                let a = self.addr_at(&k);
                k = &k + &Nat::one();
                a
            })
        })
    }

    /// The ONE admissible Run→Span lift: the level-uniform, element-level
    /// I-extent `[i_start, reach)` — the run's own two endpoints, its start
    /// and its [`reach`](Run::reach). Centralized (public) so no consumer
    /// re-derives it and none writes the malformed `Span(i_start, [0, width])`
    /// — an element-level start against a depth-2 width gives
    /// `#start ≠ #width`, faulting every downstream
    /// `intersect`/`difference`/`normalize` with `LevelMismatch`.
    ///
    /// TOTAL given the two standing invariants: `width ≥ 1` makes the reach
    /// advance (`start < reach`, TS4) and the shift is length-preserving
    /// (`#start = #reach`), so `from_endpoints` cannot fault.
    ///
    /// MIXED-LENGTH HAZARD: iextents of runs from different origin documents
    /// have different endpoint lengths, so any SpanSet aggregating them is
    /// outside the domain of M1's length-gated set ops — `intersect`,
    /// `difference_sets`, `normalize` and `canonical_key` each fault
    /// `LevelMismatch` on mixed operands. A consumer that aggregates iextents
    /// (M7's slot endsets, M6's region images) must partition by endpoint
    /// length, operate within each class, and combine the per-class results:
    /// in particular a coverage-class dedup key is ONE `canonical_key` PER
    /// level class, never one over the raw aggregate.
    pub fn iextent(&self) -> Span {
        Span::from_endpoints(self.i_start.tumbler().clone(), &self.reach())
            .expect("width ≥ 1 ⇒ start < reach ∧ #start = #reach ⇒ from_endpoints cannot fault")
    }

    /// The [`OffsetRange`] of this run's positions that `span` covers, or
    /// `None` when it covers none — the I→V question asked of the run that
    /// owns the arithmetic (§2 project).
    ///
    /// Two branches, one answer. A span that is level-uniform at the run's own
    /// endpoint length is intersected with M1 (`intersect`, both operands
    /// inside one level class); the intersection lies within the run's extent,
    /// so both endpoints share the run's prefix and the offsets are
    /// last-component differences. Any other span — a different length, or the
    /// same length but non-uniform, either of which `intersect` would fault on
    /// — takes the total membership boundary search: the run's addresses are
    /// contiguous and a span is order-convex, so the covered subset is one
    /// contiguous offset range. TOTAL either way.
    ///
    /// THE SOLE PRODUCER of an `OffsetRange`, which is what makes that type's
    /// nonemptiness structural: an intersection satisfies `start < reach`
    /// (TS4), and the search branch tests `k_lo < k_hi` before answering at
    /// all.
    pub(crate) fn offsets_covered_by(&self, span: &Span) -> Option<OffsetRange> {
        let addr_len = self.i_start.tumbler().len();
        if span.is_level_uniform() && span.start().len() == addr_len {
            let sub = intersect(&self.iextent(), span)
                .expect("both operands level-uniform at one length — gate passes")?;
            let ordinal_of = |t: &Tumbler| {
                t.get(addr_len)
                    .expect("run extent endpoints have #t == addr_len")
                    .clone()
            };
            let base = ordinal_of(self.i_start.tumbler());
            let reach = sub.reach();
            Some(OffsetRange {
                lo: ordinal_of(sub.start()) - &base,
                hi: ordinal_of(&reach) - &base,
            })
        } else {
            let k_lo = self.lower_bound(span.start());
            let k_hi = self.lower_bound(&span.reach());
            (k_lo < k_hi).then_some(OffsetRange { lo: k_lo, hi: k_hi })
        }
    }

    /// The least offset `k ∈ [0, width]` with `tumbler_at(k) ≥ bound`.
    /// Monotone in `k` (TS1 strict order), so binary search applies; total
    /// across lengths, because `Tumbler`'s order is defined over all of the
    /// carrier.
    fn lower_bound(&self, bound: &Tumbler) -> Nat {
        let mut lo = Nat::zero();
        let mut hi = self.width.clone();
        let two = Nat::from(2u32);
        while lo < hi {
            let mid = (&lo + &hi) / &two;
            if self.tumbler_at(&mid) >= *bound {
                hi = mid;
            } else {
                lo = &mid + &Nat::one();
            }
        }
        lo
    }
}

#[cfg(test)]
mod tests {
    use skep_address::subtree_of;

    use super::*;
    use crate::testutil::{a, ca, n, t, vca};

    #[test]
    fn new_rejects_width_zero_and_starts_that_are_not_full_element_positions() {
        // Interface: None ⇔ width == 0 ∨ the element field is not exactly
        // [subspace, ordinal].
        assert!(Run::new(ca(1), n(0)).is_none());
        assert!(Run::new(a(&[1, 0, 1, 0, 1]), n(1)).is_none()); // Document, zeros = 2
        assert!(Run::new(a(&[1, 0, 1]), n(1)).is_none()); // Account, zeros = 1
        // The starts element level alone would have admitted. A SUBSPACE BASE
        // `doc·0·s`: T4-valid, zeros = 3, `subspace()` answers — and its last
        // component is the subspace id, so `tumbler_at(1)` would advance
        // content → link (M1's TA7a) and `iextent` would cover the whole
        // subspace rather than one position.
        assert_eq!(a(&[1, 0, 1, 0, 1, 0, 1]).level(), skep_address::Level::Element);
        assert!(Run::new(a(&[1, 0, 1, 0, 1, 0, 1]), n(1)).is_none()); // content base
        assert!(Run::new(a(&[1, 0, 1, 0, 1, 0, 2]), n(1)).is_none()); // link base
        // And a field T7 leaves open to further subdivision, whose last
        // component is not an ordinal either.
        assert!(Run::new(a(&[1, 0, 1, 0, 1, 0, 1, 2, 3]), n(1)).is_none());
        let r = Run::new(ca(3), n(2)).expect("a full element position with width ≥ 1 is admitted");
        assert_eq!(r.i_start(), &ca(3));
        assert_eq!(r.width(), &n(2));
    }

    #[test]
    fn iextent_is_the_half_open_ordinal_shift_extent() {
        // §2: [i_start, shift(i_start, width)) — level-uniform, element-level.
        let r = Run::new(ca(2), n(3)).expect("valid run");
        let s = r.iextent();
        assert_eq!(s.start(), ca(2).tumbler());
        assert_eq!(s.reach(), *ca(5).tumbler()); // ordinal 2 + width 3
        assert!(s.is_level_uniform());
        assert!(s.contains(ca(2).tumbler()));
        assert!(s.contains(ca(4).tumbler()));
        assert!(!s.contains(ca(5).tumbler())); // half-open
    }

    #[test]
    fn a_run_answers_for_its_own_positions() {
        // §A: offset 0 is the start, offset k the k-th position, and `reach`
        // is one I-step past the last — the same tumbler offset `width`
        // names, asked without an offset, which is why it is the published
        // form. addr_at re-validates what the shift advances.
        let r = Run::new(ca(2), n(3)).expect("valid run");
        assert_eq!(r.addr_at(&n(0)), ca(2));
        assert_eq!(r.addr_at(&n(2)), ca(4));
        assert_eq!(r.reach(), *ca(5).tumbler());
        assert_eq!(r.reach(), r.tumbler_at(&n(3)));
        // And it is the extent's own upper endpoint, which is what makes the
        // lift the run's two endpoints and nothing derived twice.
        assert_eq!(r.iextent().reach(), r.reach());
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "run offset past the reach")]
    fn asking_a_run_past_its_reach_is_the_callers_bug_and_stops() {
        // §A: `k ≤ width` is the caller's obligation, and past it there is no
        // honest value to return — `addr_at(width + 2)` would be a T4-valid
        // element address two positions OUTSIDE the run, indistinguishable
        // from one the run holds. A precondition violation is the caller's
        // bug, so it stops rather than answering.
        let r = Run::new(ca(2), n(3)).expect("valid run");
        let _ = r.addr_at(&n(5));
    }

    #[test]
    fn addrs_enumerates_the_half_open_offset_range() {
        // §A: the run's own sequence — offsets [0, width), never the reach.
        let r = Run::new(ca(2), n(3)).expect("valid run");
        assert_eq!(r.addrs().collect::<Vec<_>>(), vec![ca(2), ca(3), ca(4)]);
        // A width-1 run yields exactly its start.
        let one = Run::new(ca(7), n(1)).expect("valid run");
        assert_eq!(one.addrs().collect::<Vec<_>>(), vec![ca(7)]);
        // Every yielded address is the run's own addr_at of that offset.
        assert!(r
            .addrs()
            .enumerate()
            .all(|(k, a)| a == r.addr_at(&n(k as u32))));
    }

    #[test]
    fn taking_the_run_yields_the_same_sequence_as_borrowing_it() {
        // §A: the owned form is the shape M5's own seams hand back — a
        // `Vec<Run>` flat-mapped to addresses — and it must denote exactly
        // what the borrowing form does, since the two carry the same body for
        // the reason stated on `into_addrs` rather than one calling the other.
        let r = Run::new(ca(2), n(3)).expect("valid run");
        let borrowed: Vec<_> = r.addrs().collect();
        assert_eq!(r.clone().into_addrs().collect::<Vec<_>>(), borrowed);
        assert_eq!(borrowed, vec![ca(2), ca(3), ca(4)]);
        // Width 1, and the flat-map over owned runs that motivates it.
        let one = Run::new(ca(7), n(1)).expect("valid run");
        assert_eq!(one.into_addrs().collect::<Vec<_>>(), vec![ca(7)]);
        let runs = vec![
            Run::new(ca(1), n(2)).expect("valid run"),
            Run::new(vca(1), n(1)).expect("valid run"),
        ];
        assert_eq!(
            runs.into_iter().flat_map(Run::into_addrs).collect::<Vec<_>>(),
            vec![ca(1), ca(2), vca(1)]
        );
    }

    #[test]
    fn offsets_covered_by_answers_in_both_branches() {
        // §2: a same-length level-uniform cover goes through M1's intersect;
        // any other cover takes the total boundary search. Both name the
        // run's own half-open offset range.
        let r = Run::new(ca(2), n(3)).expect("valid run"); // ca(2), ca(3), ca(4)
        let inner = Run::new(ca(3), n(1)).expect("valid run").iextent();
        assert_eq!(
            r.offsets_covered_by(&inner),
            Some(OffsetRange { lo: n(1), hi: n(2) })
        );
        // The two quantities the I→V read takes off a range: where it opens,
        // and how many of the run's positions it names — the second derived by
        // the range, so `project` does not subtract the bounds itself.
        let one = r.offsets_covered_by(&inner).expect("the cover is nonempty");
        assert_eq!(one.lo(), &n(1));
        assert_eq!(one.width(), n(1));
        let apart = Run::new(ca(9), n(1)).expect("valid run").iextent();
        assert_eq!(r.offsets_covered_by(&apart), None);
        // Cross-length fallback: doc1's content-base subtree covers every
        // length-8 ca(·)…
        let base = subtree_of(&t(&[1, 0, 1, 0, 1, 0, 1]));
        assert_eq!(
            r.offsets_covered_by(&base),
            Some(OffsetRange { lo: n(0), hi: n(3) })
        );
        // …and none of the fork's length-9 elements.
        let forked = Run::new(vca(1), n(2)).expect("valid run");
        assert_eq!(forked.offsets_covered_by(&base), None);
        // The fallback's OTHER entry condition: a span at the run's own
        // endpoint length that is not level-uniform. M1's `intersect` gates
        // on uniformity as well as on length, so this span would fault the
        // same-class branch — and it covers only PART of the run, which is
        // the contiguous-subset half of the claim. `[ca(3), [2])` opens at
        // the run's second position and reaches past its last.
        let partial = Span::new(ca(3).tumbler().clone(), t(&[1])).expect("T12: action point 1 ≤ 8");
        assert_eq!(partial.start().len(), r.i_start.tumbler().len());
        assert!(!partial.is_level_uniform());
        assert_eq!(
            r.offsets_covered_by(&partial),
            Some(OffsetRange { lo: n(1), hi: n(3) })
        );
    }

    #[test]
    fn offsets_covered_by_names_exactly_the_positions_the_span_contains() {
        // §2: the answer is a LAW over covering spans, and the oracle is the
        // span's own membership — for every span, the range must be exactly
        // the offsets whose address it contains. The same-length
        // level-uniform family is small enough to exhaust, and it is the
        // branch the worked example above visits only strictly INSIDE the
        // run: the equal case, a span opening before the run and one
        // reaching past it are all cases M1's `intersect` CLIPS, and the
        // clipping is what those offsets are derived from. The second family
        // is non-uniform at the run's own length, which takes the boundary
        // search, and it walks that search's every boundary.
        let r = Run::new(ca(4), n(3)).expect("valid run"); // ca4, ca5, ca6
        let check = |span: &Span, label: String| {
            let covered: Vec<Nat> = (0..3u32)
                .map(n)
                .filter(|k| span.contains(r.addr_at(k).tumbler()))
                .collect();
            match r.offsets_covered_by(span) {
                None => assert!(
                    covered.is_empty(),
                    "{label}: covers offsets {covered:?}, answered None"
                ),
                Some(range) => {
                    assert!(
                        !covered.is_empty(),
                        "{label}: covers no offset, answered {range:?}"
                    );
                    assert_eq!(
                        range.lo(),
                        &covered[0],
                        "{label}: opens at the first covered offset"
                    );
                    assert_eq!(
                        range.width(),
                        n(covered.len() as u32),
                        "{label}: names as many positions as the span contains"
                    );
                    // Contiguity, the other half of the claim: the covered
                    // subset of a run is one unbroken offset range.
                    let last = covered.last().expect("nonempty");
                    assert_eq!(
                        &covered[0] + &range.width(),
                        last + &n(1),
                        "{label}: the covered offsets are contiguous"
                    );
                }
            }
        };
        // Level-uniform at the run's own length ⇒ the intersect branch. 45
        // spans: before, abutting, overlapping either end, equal, containing.
        for lo in 1..=9u32 {
            for hi in lo + 1..=10u32 {
                let span = Span::from_endpoints(ca(lo).tumbler().clone(), ca(hi).tumbler())
                    .expect("lo < hi at one length ⇒ well-formed");
                check(&span, format!("[ca{lo}, ca{hi})"));
            }
        }
        // Same length, NOT level-uniform ⇒ the boundary-search branch, whose
        // reach is [2] — every length-8 address at or after ca(k) is covered.
        for k in 1..=9u32 {
            let span = Span::new(ca(k).tumbler().clone(), t(&[1])).expect("T12: action point 1 ≤ 8");
            assert!(!span.is_level_uniform());
            check(&span, format!("[ca{k}, [2])"));
        }
    }

    #[test]
    fn run_survives_a_bincode_round_trip() {
        // §A: Run is a journaled type (inside ContentPlace); bincode is M2's
        // actual wire format.
        let r = Run::new(ca(7), n(4)).expect("valid run");
        let bytes = bincode::serialize(&r).expect("run serializes");
        let back: Run = bincode::deserialize(&bytes).expect("run deserializes");
        assert_eq!(back, r);
        assert_eq!(back.i_start(), &ca(7));
        assert_eq!(back.width(), &n(4));
    }

    #[test]
    fn decoding_a_run_re_enters_the_constructor() {
        // §A: the invariants the position arithmetic's `.expect`s stand on
        // are the TYPE's, so the decode path is the constructor. A field pair
        // no `Run::new` would admit is refused as a decode failure — which
        // M2 reports as checkpoint corruption — rather than admitted as a
        // value that panics `iextent` on the next fold to touch it.
        //
        // The bytes are made by encoding the shadow, which is the exact
        // field-by-field form a corrupt journal would present.
        #[derive(Serialize)]
        struct Wire {
            i_start: Address,
            width: Nat,
        }
        let zero = bincode::serialize(&Wire {
            i_start: ca(7),
            width: n(0),
        })
        .expect("the shadow encodes");
        assert!(bincode::deserialize::<Run>(&zero).is_err(), "width 0 is not a run");
        let document = bincode::serialize(&Wire {
            i_start: a(&[1, 0, 1, 0, 1]),
            width: n(1),
        })
        .expect("the shadow encodes");
        assert!(
            bincode::deserialize::<Run>(&document).is_err(),
            "a document-level start is not a run start"
        );
        let base = bincode::serialize(&Wire {
            i_start: a(&[1, 0, 1, 0, 1, 0, 2]),
            width: n(1),
        })
        .expect("the shadow encodes");
        assert!(
            bincode::deserialize::<Run>(&base).is_err(),
            "a subspace base is element-level and still not a run start"
        );
        // The door costs the encoding nothing: a well-formed field pair
        // encodes to exactly the bytes `Run` itself writes, so the shadow is
        // a check on the decode path and not a second wire format.
        let good = Run::new(ca(7), n(4)).expect("valid run");
        assert_eq!(
            bincode::serialize(&Wire {
                i_start: ca(7),
                width: n(4)
            })
            .expect("the shadow encodes"),
            bincode::serialize(&good).expect("the run encodes")
        );
    }
}
