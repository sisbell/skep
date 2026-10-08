//! §A — the `Run` value: one contiguous I-extent placed in an arrangement,
//! the run's own position arithmetic, and the ONE admissible Run→Span lift
//! ([`Run::iextent`]).
//!
//! The arithmetic divides by whether a caller can get the question wrong.
//! [`Run::addrs`], [`Run::into_addrs`] and [`Run::reach`] take no offset, so
//! they are total and published; [`Run::tumbler_at`] is private to this
//! module and [`Run::addr_at`] and [`Run::offsets_covered_by`] (with the
//! [`OffsetRange`] it answers in) are crate-private, the first two carrying a
//! `k ≤ width` precondition nothing can report and the third an operand the
//! level-class discipline governs.

use std::borrow::Borrow;
use std::error::Error;
use std::fmt;

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
/// struct literal nor mutate one it holds — including an OWNED `Run` that
/// `resolve` returns or that a caller clones out of `content_runs` or
/// `link_runs` — so runs are read-only across every seam (M6/M7/M8 read via
/// the [`i_start`](Run::i_start)/[`width`](Run::width) accessors). In-crate,
/// ONE site mutates a built `Run`: `extend_or_push_run` widens the
/// accumulator's last run by the width of an I-adjacent one — a positive
/// width added to a positive width, the start untouched — so both invariants
/// survive it. A second mutation site joins this sentence or the invariant is
/// re-examined.
/// [`Run::new`] is the sole foreign constructor, and it is also the
/// DESERIALIZATION path: a decoded Run re-enters it through the serde shadow
/// below, so a journalled [`ContentPlace`](crate::M5Rec::ContentPlace) cannot
/// carry a Run the constructor would refuse, and a journalled
/// [`LinkSeat`](crate::M5Rec::LinkSeat) — which carries a bare `Address` and
/// so re-enters T4 alone — is minted through it by the fold. That is what
/// justifies the `.expect`s in the run's own position arithmetic — they rest
/// on the type, not on M2's checkpoint integrity.
///
/// `Hash` agrees with `Eq`: a run IS its start and its width, so a set or map
/// keyed on runs keys on exactly that pair, and no caller spells a proxy key
/// that could drop half of it. There is no `Ord`. A run's place in an
/// arrangement is its V-order, which the value does not carry; an I-order
/// derived from the fields would let `runs.sort()` compile on the V-ordered
/// sequences `resolve` returns and `content_runs` lends, once collected, and
/// scramble them.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "RunShadow")]
pub struct Run {
    pub(crate) i_start: Address,
    pub(crate) width: Nat,
}

/// Why [`Run::new`] refused — the standing invariant broken, one variant per
/// clause, as M1's `T12Clause` and `ElemError` name theirs. Which answers when
/// both clauses are broken is [`Run::new`]'s to state, and it does
/// (`ZeroWidth`); declaration order carries no contract, as in every error
/// type of this crate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RunError {
    /// `width == 0`: a run holds at least one position.
    ZeroWidth,
    /// `i_start` is not a full element position `doc·0·subspace·ordinal` — an
    /// element field of exactly two components, the shape the run's ordinal
    /// arithmetic stands on.
    NotAnElementPosition,
}

impl fmt::Display for RunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            RunError::ZeroWidth => "run: width must be ≥ 1",
            RunError::NotAnElementPosition => {
                "run: i_start is not a full element position (doc·0·subspace·ordinal)"
            }
        })
    }
}
impl Error for RunError {}

/// The deserialization mint path (the serde `try_from` shadow, as M1's
/// `Address`/`Span`/`Tumbler` each carry one): decoded field-by-field, then
/// re-entered through [`Run::new`], so a `width = 0` or a start that is not a
/// full element position in a journal or a checkpoint is a decode failure M2
/// reports as corruption — naming the clause, the constructor's own
/// [`RunError`] being the failure — rather than a value that panics
/// [`Run::iextent`] on the next fold to touch it.
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
    type Error = RunError;
    fn try_from(s: RunShadow) -> Result<Run, RunError> {
        Run::new(s.i_start, s.width)
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

/// The walk both address iterators share — offsets `[0, width)`, in I-order,
/// which is V-order — over a run held by reference or by value: `Borrow<Run>`
/// admits both, so one body serves the borrowing form ([`Run::addrs`]) and
/// the taking form ([`Run::into_addrs`]), and neither clones the run to reach
/// it.
fn addrs_of<R: Borrow<Run>>(run: R) -> impl Iterator<Item = Address> {
    let mut k = Nat::zero();
    std::iter::from_fn(move || {
        let run = run.borrow();
        (k < run.width).then(|| {
            let a = run.addr_at(&k);
            k = &k + &Nat::one();
            a
        })
    })
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

    /// Checked constructor — the ONE door, refusing with the clause broken:
    /// [`RunError::ZeroWidth`] when `width == 0`, whatever the start, else
    /// [`RunError::NotAnElementPosition`] when `i_start` is not a full element
    /// position `doc·0·subspace·ordinal`. Every Run that is not built by M5's
    /// own emission sites walks through here, an external producer and a
    /// decoded journal or checkpoint alike — the serde `try_from` shadow
    /// routes deserialization into this function.
    ///
    /// M5's own sites divide in two. The PROPAGATING ones — the run-list's
    /// split (`split_runs`, both halves of a boundary run), its one clip
    /// (`RunList::clipped_runs`, under every range and suffix walk: `resolve`,
    /// the shot's carried tail, the address form read at the member), and a
    /// run union's merged pieces (`UnionPiece::to_run`) — build Runs by the
    /// in-crate struct literal from a start that is already one: another run's
    /// start, which this type holds to be one, or an in-crate ordinal shift of
    /// one, and such a shift preserves the element field's length. Coalescing
    /// builds no Run: it widens one, at the one mutation site the type's card
    /// names. The two
    /// ORIGINATING ones establish it instead, and each does so at its own
    /// door: `allocate_for_placement` — INSERT's per-value step, which the
    /// publish shot's re-insert shares — places what `M3State::mint_content`
    /// returns, which is `doc·0·s_C·ordinal` by construction, and the
    /// `LinkSeat` fold seats an address that arrives in a record, so it calls
    /// THIS function — `stage_seat_link` checks the shape on the live path,
    /// but a replayed record's `Address` re-enters only M1's `validate`, and
    /// T4-validity does not imply a full element position.
    ///
    /// Field privacy then closes the mutate-after-obtain path: a foreign
    /// holder cannot later set `width = 0` or swap `i_start` on any Run it
    /// obtained, owned or borrowed.
    pub fn new(i_start: Address, width: Nat) -> Result<Run, RunError> {
        if width.is_zero() {
            return Err(RunError::ZeroWidth);
        }
        if !Run::admits_start(&i_start) {
            return Err(RunError::NotAnElementPosition);
        }
        Ok(Run { i_start, width })
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
    /// PRIVATE to this module, for the sake of that same precondition: an
    /// offset is a thing a caller can get wrong, and the run's own arithmetic
    /// — [`addr_at`](Run::addr_at), [`reach`](Run::reach) and the boundary
    /// search — is its only caller. A consumer wanting the positions asks
    /// [`addrs`](Run::addrs) or [`into_addrs`](Run::into_addrs); one wanting
    /// the exclusive end asks [`reach`](Run::reach), which takes no offset at
    /// all. Every published question about a run is therefore total.
    fn tumbler_at(&self, k: &Nat) -> Tumbler {
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
    /// rather than the I-extent does not count them itself. For a caller
    /// holding the run BY VALUE, [`into_addrs`](Run::into_addrs).
    ///
    /// Yields OWNED addresses because a run stores none: it stores a start and
    /// a width, and each position is the start advanced by an offset.
    /// That is why this is an inherent method and not `IntoIterator for &Run`,
    /// where a caller would rightly expect borrowed items. It is likewise not
    /// an `ExactSizeIterator`: `width` is a `Nat`, so a `len() -> usize` would
    /// be a lie at the top of its range.
    pub fn addrs(&self) -> impl Iterator<Item = Address> + '_ {
        addrs_of(self)
    }

    /// The run's addresses, TAKING THE RUN — the same sequence
    /// [`addrs`](Run::addrs) yields, for a caller that owns the run rather
    /// than keeping it. That is the shape `resolve` hands back — `Vec<Run>`,
    /// runs it clipped and so owns — and a consumer flat-mapping those runs to
    /// addresses holds each run only for as long as it walks it, where the
    /// borrowing form cannot outlive the vector it consumes.
    ///
    /// The two are one body, `addrs_of`, generic over `Borrow<Run>` —
    /// instantiated with `Run` here and `&Run` there — so neither form clones
    /// the run to walk it. Owned items and no `ExactSizeIterator`, for the
    /// reasons stated on [`addrs`](Run::addrs).
    pub fn into_addrs(self) -> impl Iterator<Item = Address> {
        addrs_of(self)
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
    /// MIXED-LENGTH HAZARD: iextents of runs whose origin documents sit at
    /// different DEPTHS (a trunk and one of its members, or documents of
    /// accounts at different depths) have different endpoint lengths, so any
    /// SpanSet aggregating them is outside the domain of M1's length-gated set
    /// ops — `intersect`, `difference_sets`, `normalize` and `canonical_key`
    /// each fault `LevelMismatch` on mixed operands. A consumer that
    /// aggregates iextents (M7's slot endsets, M6's region images) must
    /// partition by endpoint length, operate within each class, and combine
    /// the per-class results: in particular a coverage-class dedup key is ONE
    /// `canonical_key` PER level class, never one over the raw aggregate. A
    /// level class is set by an origin's depth, not by which document it is:
    /// two sibling documents are two origins in one class, so partitioning by
    /// length is not partitioning by origin, and one class can hold many
    /// origins.
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
    /// inside one level class); the intersection lies within the run's I-extent,
    /// so both endpoints share the run's prefix and the offsets are
    /// last-component differences. Any other span — a different length, or the
    /// same length but non-uniform, either of which `intersect` would fault on
    /// — takes the total membership boundary search: the run's addresses are
    /// contiguous and a span is order-convex, so the covered subset is one
    /// contiguous offset range. TOTAL either way.
    ///
    /// The boundary search costs `2⌈log₂(width + 1)⌉` steps over THIS run's
    /// own width, each a `Nat` halving and an ordinal shift at that width's
    /// magnitude. That is bounded by stored state when `self` is a resident
    /// run — [`project`](crate::M5State::project) asks each of a document's
    /// runs about a caller's coverage — which is why no caller asks it of a
    /// CLIENT's run, whose width the client chose: the publish shot's
    /// carried-run test answers whether a client's run is arranged from a
    /// merged union of the base's runs
    /// ([`RunUnion::covers`](crate::runlist::RunUnion::covers)), searching no
    /// width at all.
    ///
    /// THE SOLE PRODUCER of an `OffsetRange`, which is what makes that type's
    /// nonemptiness structural: an intersection satisfies `start < reach`
    /// (TS4), and the search branch tests `k_lo < k_hi` before answering at
    /// all.
    pub(crate) fn offsets_covered_by(&self, span: &Span) -> Option<OffsetRange> {
        let addr_len = self.i_start.tumbler().len();
        if span.is_level_uniform() && span.start().len() == addr_len {
            let intersection = intersect(&self.iextent(), span)
                .expect("both operands level-uniform at one length — gate passes")?;
            // The last component of an endpoint of this run's own length — its
            // ordinal. A nested fn rather than a closure so it hands back the
            // borrow `get` already made: a closure's elided lifetimes do not
            // tie its return to its argument, and a clone would be the price
            // of that.
            fn ordinal_of(t: &Tumbler, addr_len: usize) -> &Nat {
                t.get(addr_len)
                    .expect("run I-extent endpoints have #t == addr_len")
            }
            let start_ordinal = ordinal_of(self.i_start.tumbler(), addr_len);
            let reach = intersection.reach();
            Some(OffsetRange {
                lo: ordinal_of(intersection.start(), addr_len) - start_ordinal,
                hi: ordinal_of(&reach, addr_len) - start_ordinal,
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
mod tests;
