//! The request budgets, each a REFUSAL rather than a truncation: COMPARE's
//! operand budget, [`MAX_COMPARE_OPERAND_BLOCKS`] per operand, and pair
//! budget, [`MAX_COMPARE_PAIRS`] per report; FINDDOCSCONTAINING's coverage
//! budget, [`MAX_FIND_COVERAGE_SPANS`]; RETRIEVEV's delivery budget,
//! [`MAX_DELIVERY_ITEMS`] per spec-set; and the line read's walk budget,
//! [`MAX_WALK_STEPS`], on the runs its one walk of a document pulls — and
//! the [`Count`] every count against them is taken through. The four
//! operations count against them and the
//! rejections render them, so the numbers, their argument and the count that
//! enforces them live here, apart from all of them.
//! [`MAX_COMPARE_OPERAND_BLOCKS`]'s card is the one statement of why the
//! operand budget is counted twice, of why the coverage budget, which takes
//! its number by definition, is too, and of which budgets move with that
//! number; [`MAX_WALK_STEPS`]'s is the one statement of what the line
//! read's walk costs, why no other operation's walks are budgeted, and
//! `vspan.rs`'s [`walk_price`]'s of how that walk is priced — which the
//! crate doc's *What M6 refuses for size* publishes to callers,
//! `walk_price` being private; [`Count`]'s card is the one statement of
//! where a count's boundary falls.
//!
//! [`walk_price`]: crate::vspan::walk_price

/// The most blocks one COMPARE operand may resolve to, and the most spans it
/// may hand to M5 — ONE budget on an operand's resolution, counted twice, on
/// the spans handed and on the blocks built — and so the ceiling on the join's
/// two factors and on how many resolutions an operand asks of M5.
///
/// The budget: the join is `|P|·|Q|` candidate tests, so an operand budget
/// SQUARES — `2^12` bounds one query at `2^24` ≈ 1.7×10⁷ tests, each two
/// `Tumbler` comparisons over element addresses, which is order a second of
/// one worker. The number is also M10's own per-array wire cap, so an operand
/// that is a FLAT list of 4096 single-run spans — the largest flat span list
/// the transport admits — passes this budget unchanged, however many runs
/// the surface holds and wherever along it the spans reach.
///
/// ONE NUMBER, THREE BUDGETS. FINDDOCSCONTAINING's coverage budget,
/// [`MAX_FIND_COVERAGE_SPANS`], is this number by definition, and the walk
/// budget the line read prices its one walk against is its square (crate
/// doc, *What M6 refuses for size*) — the line read's, which has no other
/// tie to COMPARE. So an edit of this line is an edit of those two as well,
/// the walk's by the square, and is argued for them too: the walk budget's
/// own argument is made at `2^24`, which is this number's square at `2^12`,
/// and an assertion beside the walk budget holds it at that value when the
/// crate compiles, so an edit of this line fails the build there, where the
/// walk tests, which size their requests from this constant, would follow
/// it unremarked.
///
/// What it refuses is the two shapes no wire cap prices, and the two counts
/// are what refuse them. The NESTED region×span product, whose region-set
/// cost model the transport leaves to M6, is refused by the SPAN count: every
/// span handed to M5 is one resolution whether or not it yields a block — a
/// span opening past the arranged extent yields none — so a block count alone
/// would admit any number of empty-resolving spans, from a request the body
/// cap alone sizes. How far along its surface a resolution REACHES is no
/// count's: M5 reaches a span by a descent of the run-list, a node a level
/// of its tree, whatever the list holds left of the span, so a span costs
/// that descent and the runs it yields. The multi-run expansion, where one
/// span over a fragmented document resolves to many blocks from a single
/// span on the wire, is refused by the BLOCK count, which a span count
/// cannot see.
///
/// COUNTED ON THE SPANS HANDED TO M5, not on the resolutions M5 performs: a
/// span M5 folds to nothing at once (wrong depth, foreign subspace) is
/// counted all the same, so the count is an upper bound on the resolutions —
/// refusing more, never less — and M5's fold conditions stay M5's: no count
/// here tests them.
///
/// WHAT THE COUNTS STOP, AND WHAT THEY DO NOT. Both are consulted as M5's lazy
/// `iter_resolve` produces each run — the block count at COMPARE, the coverage
/// count at FINDDOCSCONTAINING — so a span over a heavily fragmented document
/// stops its walk at the budget, and what one span makes M6 hold live exceeds
/// the budget by at most the run that trips it: each count bounds the LIST —
/// the join's factor, the scans' multiplier — and the peak heap of building
/// it. Neither bounds the way to a span's opening ordinal, and none needs
/// to: it is a descent of the run-list's tree, a node a level, whatever the
/// document's fragmentation and whatever the span yields.
pub const MAX_COMPARE_OPERAND_BLOCKS: usize = 1 << 12;

/// The most correspondences one COMPARE may report, and so the ceiling on what
/// the REPORT makes M6 hold live.
///
/// The budget: a [`CorrPair`] is two `Address`es, two `VPos`es and a `Nat` —
/// order a kilobyte of live heap once the `BigUint` digit vectors are counted
/// — and the report is what the query holds, the presentation sorting it in
/// place over borrowed keys and holding nothing beside it. `2^16` is therefore
/// order 64 MiB of report; it is also M5's `MAX_PLACED_RUNS`, the substrate's
/// existing answer to how many runs one operation may materialize.
///
/// With [`MAX_COMPARE_OPERAND_BLOCKS`] it bounds what the query holds live —
/// the two operands' block lists and this report; that card says what the
/// operand counts stop within one span.
///
/// [`MAX_COMPARE_OPERAND_BLOCKS`] cannot stand in for it: two operands at that
/// budget whose spans all resolve to ONE shared I-address report the SQUARE of
/// it in pairs, so fan-out is bounded only by counting the pairs themselves.
///
/// [`CorrPair`]: crate::CorrPair
pub const MAX_COMPARE_PAIRS: usize = 1 << 16;

/// The most I-coverage spans one FINDDOCSCONTAINING request may resolve to,
/// and the most spans it may hand to M5 — one budget on the request's
/// resolution, counted on the spans handed and on the coverage they produce
/// — and so the ceiling on the multiplier the REQUEST applies to the two
/// world-sized scans behind it.
///
/// THE OPERAND BUDGET'S NUMBER, not a second. `docs_ever_containing` joins
/// this coverage against the whole of R, and `arranges_any` runs it against
/// each candidate's runs, so the coverage is one side of a join exactly as a
/// COMPARE operand is — and it takes the operand budget's number BY
/// DEFINITION, is counted the same two ways (the spans handed to M5's lazy
/// `iter_resolve`, and the coverage they produce), and is priced on
/// [`MAX_COMPARE_OPERAND_BLOCKS`]'s card, which also says why the count is
/// two, what each count refuses, and what the counts stop within one span and
/// what they do not. Pricing the two apart is a deliberate edit of this line,
/// never a drift between two literals.
///
/// WHAT IT DOES NOT BOUND, and neither could any number here: `|R|` and a
/// candidate's `#runs(d)` are the WORLD's, not the request's, so they stay
/// with rate and concurrency — M10's, exactly as [`Query::show_deletions`]'
/// cost already is. This bounds the coverage the request materializes, and the
/// factor the request multiplies those scans by; it does not bound the scans.
///
/// [`Query::show_deletions`]: crate::Query::show_deletions
pub const MAX_FIND_COVERAGE_SPANS: usize = MAX_COMPARE_OPERAND_BLOCKS;

/// The most items one RETRIEVEV's delivery may carry, counted in POSITIONS —
/// one per position of each delivered run, a byte-run item standing for its
/// run's width, and one per withheld run — and so the ceiling on what the
/// DELIVERY makes M6 hold live. [`Delivery::len`] counts the items
/// themselves, fewer wherever a run of single-byte positions is one item.
///
/// THE EXTENT IS VIRTUAL, which is why no request field prices it. M5 caps the
/// runs one placing request stores (`MAX_PLACED_RUNS`) and caps no position
/// count, so one COPY of 4096 specs, each naming a document's whole `W`-position
/// run, places `4096·W` positions from `W` stored values, and a copy of a
/// document's whole extent onto its own tail doubles that extent for one
/// request's cost. One spec naming one such document is a delivery no wire cap
/// sees, and a response cap downstream refuses one allocation too late: the
/// delivery is built here, whole, before any caller holds it.
///
/// The budget: a content item is one [`DeliveryItem`] — order 64 bytes inline,
/// its value an `Arc` clone and never a byte copy, a byte-run item one
/// allocation of its bytes for all its positions — and a link reference or a
/// withheld run owns an `Address` besides, order 300 heap bytes. `2^17` items
/// is therefore 8 MiB of delivery, and about 45 MiB at worst: under
/// [`MAX_COMPARE_PAIRS`]' 64 MiB report, the largest answer any budget here
/// admits. It is also M5's `MAX_REINSERTED_UNITS`, the substrate's existing
/// ceiling on how many units — values, or whole runs of single bytes — one
/// publish shot may stage live. What the items
/// RENDER to — each content item's bytes — is the transport's to bound.
///
/// A REFUSAL, never a truncation, counted as the delivery is produced: a
/// withheld run as one item, a delivered run's positions as ONE batch admitted
/// before its first position is expanded. So R3 (exactness), R5 (submitted
/// order) and R8 (no dedup) hold verbatim for every delivery answered, as
/// COMPARE's budgets leave X12 R1–R2 and FINDDOCSCONTAINING's leaves
/// FD-COMPLETE. A caller wanting more splits the spec-set or narrows its spans.
///
/// [`Delivery::len`]: crate::Delivery::len
/// [`DeliveryItem`]: crate::DeliveryItem
pub const MAX_DELIVERY_ITEMS: usize = 1 << 17;

/// The most runs one line read's walk of its document may pull, priced
/// before the first is pulled.
///
/// The line read answers line numbers by walking its reading surface's
/// whole content extent, from the first position to the last, whatever its
/// two lists hold: every content run of the surface is pulled once. No
/// count of the request sees that walk — the lists it is asked name
/// positions and lines, not runs — and `#runs` is cheap to grow: one COPY
/// places up to M5's `MAX_PLACED_RUNS` runs. So the walk is priced at the
/// runs it will pull, the surface's content run count, read off M5's O(1)
/// run count (`vspan.rs`'s [`walk_price`]), and refused past this budget.
///
/// **No other operation's walk is budgeted**, because no other walks more
/// than it yields. RETRIEVEV, COMPARE and FINDDOCSCONTAINING resolve spans:
/// M5 reaches a span by a descent of the run-list, a node a level of its
/// tree whatever the list holds left of the span, and reads from there the
/// runs the span yields — none, for a span opening past the arranged end.
/// What those three pull is therefore what they produce, and their own
/// budgets count it as it is produced: the delivery's items, an operand's
/// blocks, the coverage's spans, each beside the count of the spans handed
/// over. The line read alone reads every run of a surface for an answer of
/// a few numbers.
///
/// The budget is the operand budget's square, `2^24` — the bound
/// [`MAX_COMPARE_OPERAND_BLOCKS`]' card prices COMPARE's join at, order a
/// second of one worker at a comparison a step. A step of the line read's
/// walk is two reads of M4's line-break counts for a run it may read,
/// each a predecessor lookup and a scan of less than one block of a stretch,
/// so a line read of a surface at the budget runs longer than that second.
/// It bounds how fragmented a surface one line read may walk: a surface of
/// more content runs than the budget is refused whatever is asked of it,
/// and a version of fewer runs is asked instead. No
/// test builds a surface past the budget, so no test reaches the
/// refusal: `tests/it/tidy.rs` holds that the walk pulled is a walk priced,
/// and the refusal's rendering is pinned.
///
/// Crate-private, as M8's join budget is: no answer here reports the run
/// counts a caller would size a request against, so the refusal renders the
/// number and nothing publishes it to compute with.
///
/// [`walk_price`]: crate::vspan::walk_price
pub(crate) const MAX_WALK_STEPS: usize = MAX_COMPARE_OPERAND_BLOCKS * MAX_COMPARE_OPERAND_BLOCKS;

// The walk budget held at the value its card argues for, `2^24`, when the
// crate COMPILES: it is the operand budget's square, so an edit of
// `MAX_COMPARE_OPERAND_BLOCKS` moves the line read's walk budget by the
// square, and nothing else would remark it. The build that follows such an
// edit fails here, before any test is run.
const _: () = assert!(
    MAX_WALK_STEPS == 1 << 24,
    "MAX_WALK_STEPS is argued at 2^24 runs; an edit of \
     MAX_COMPARE_OPERAND_BLOCKS moves it by the square"
);

/// One count taken against one of the budgets above — the spans a COMPARE
/// operand or a FINDDOCSCONTAINING request hands to M5, the blocks or coverage
/// they produce, the pairs a join emits, the items a delivery holds, or the
/// runs a line read's walk is priced at — and the one place a
/// count's boundary is spelled. It admits items until its budget is spent and
/// refuses any that would exceed it, BEFORE they are kept: exactly the budget
/// is admitted, and a batch that would exceed it is refused whole, admitting
/// none of itself. So a producer that hands its items over in batches is held
/// to the budget exactly as one that hands them over singly; a guard comparing
/// the accumulator to the budget before a batch lands — `>=` as much as `==` —
/// would admit the batch that crosses it, and answer past the budget when that
/// batch is the last. A delivered run's positions and a line read's walk are
/// such batches.
///
/// `tests/it/tidy.rs` refuses any code line outside this file that names a
/// `MAX_` budget beside a comparison — the spelling a hand-written guard takes.
#[derive(Debug)]
pub(crate) struct Count {
    budget: usize,
    admitted: usize,
}

/// A count would exceed its budget. The request is refused whole: the
/// operation answers with its own typed rejection and no partial answer.
#[derive(Debug)]
pub(crate) struct OverBudget;

impl Count {
    /// A count against `budget`, nothing yet admitted.
    pub(crate) fn against(budget: usize) -> Count {
        Count {
            budget,
            admitted: 0,
        }
    }

    /// Admits `items` more, or — if they would exceed the budget — refuses them
    /// all and admits none. Asked before the items are kept, and for a line
    /// read before its walk.
    pub(crate) fn admit(&mut self, items: usize) -> Result<(), OverBudget> {
        // `admitted ≤ budget` holds from construction on, so this cannot wrap.
        if items > self.budget - self.admitted {
            return Err(OverBudget);
        }
        self.admitted += items;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_count_admits_exactly_its_budget_and_refuses_the_item_past_it() {
        let mut count = Count::against(3);
        assert!((0..3).all(|_| count.admit(1).is_ok()));
        assert!(count.admit(1).is_err());
    }

    #[test]
    fn a_count_refuses_a_batch_that_would_exceed_its_budget_whole() {
        // Two counts admit batches today — a delivered run's positions, as one
        // batch, and the line read's priced walk — and `interval_join`'s successor
        // would too: a guard comparing the accumulator to the budget before a
        // batch lands admits the batch that crosses it; a count refuses it
        // before it lands. No integration test ends a count on a batch that
        // crosses its budget from below, so this is the test that tells the
        // two guards apart.
        let mut count = Count::against(4);
        assert!(count.admit(3).is_ok());
        assert!(count.admit(2).is_err(), "3 + 2 would exceed 4");
        assert!(
            count.admit(1).is_ok(),
            "the refused batch admitted none of itself"
        );
        assert!(count.admit(1).is_err());
    }
}
