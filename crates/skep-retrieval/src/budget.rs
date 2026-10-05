//! The three request budgets, each a REFUSAL rather than a truncation:
//! COMPARE's [`MAX_COMPARE_OPERAND_BLOCKS`] per operand and
//! [`MAX_COMPARE_PAIRS`] per report, and FINDDOCSCONTAINING's
//! [`MAX_FIND_COVERAGE_SPANS`] — and the [`Count`] every count against them is
//! taken through. The two operations count against them and the rejections
//! render them, so the numbers, their argument and the count that enforces
//! them live here, apart from all three. [`MAX_COMPARE_OPERAND_BLOCKS`]'s card
//! is the one statement of why an operand-side budget is counted twice, and the
//! coverage budget is defined as that one; [`Count`]'s card is the one
//! statement of where a count's boundary falls.

/// The most blocks one COMPARE operand may resolve to, and the most spans it
/// may hand to M5 — ONE budget on an operand's resolution, counted twice, on
/// the spans handed and on the blocks built — and so the ceiling on the join's
/// two factors and on the resolution walks behind them.
///
/// The budget: the join is `|P|·|Q|` candidate tests, so an operand budget
/// SQUARES — `2^12` bounds one query at `2^24` ≈ 1.7×10⁷ tests, each two
/// `Tumbler` comparisons over element addresses, which is order a second of
/// one worker. The number is also M10's own per-array wire cap, so an operand
/// that is a FLAT list of 4096 single-run spans — the largest flat span list
/// the transport admits — is admitted here unchanged.
///
/// What it refuses is the two shapes no wire cap prices, and the two counts
/// are what refuse them. The NESTED region×span product, whose region-set
/// cost model the transport leaves to M6, is refused by the SPAN count: every
/// span costs one `resolve` walk, `Θ(#runs(doc))` whether or not it yields a
/// block — a span opening past the arranged extent is walked to the end and
/// yields none — so a block count alone would admit any number of
/// empty-resolving spans and the walks with them, from a request the body cap
/// alone sizes. The multi-run expansion, where one span over a fragmented
/// document resolves to many blocks from a single span on the wire, is refused
/// by the BLOCK count, which a span count cannot see.
///
/// COUNTED ON THE SPANS HANDED TO M5, not on the walks M5 performs: a span
/// M5's reader declines at once (wrong depth, foreign subspace) is counted
/// all the same, so the count is an upper bound on the walks — refusing
/// more, never less — and M5's fold conditions stay M5's, restated nowhere
/// in this crate.
///
/// WHAT THE COUNTS STOP, AND WHAT THEY DO NOT. Both are consulted as M5's lazy
/// `iter_resolve` produces each run — the block count at COMPARE, the coverage
/// count at FINDDOCSCONTAINING — so a span over a heavily fragmented document
/// stops its walk at the budget, and what one span makes M6 hold live passes
/// the budget by at most the run that trips it: each count bounds the LIST —
/// the join's factor, the scans' multiplier — and the peak heap of building
/// it. Neither bounds `#runs(doc)`, the document's own fragmentation: each
/// span's walk to its opening ordinal passes that many runs whatever the span
/// yields, and it is the world's factor, not the request's.
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
/// With [`MAX_COMPARE_OPERAND_BLOCKS`] it bounds what the query holds live:
/// the two operands' block lists and this report, every span's resolution
/// being pulled a run at a time off M5's lazy `iter_resolve` and stopped at
/// the block budget (that card says what the operand counts stop).
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
/// ONE join-side budget, not a second. `docs_ever_containing` joins this
/// coverage against the whole of R, and `arranges_any` runs it against each
/// candidate's runs, so the coverage is one side of a join exactly as a
/// COMPARE operand is — and it takes that operand's budget BY DEFINITION,
/// counted the same two ways (the spans handed to M5's lazy `iter_resolve`,
/// and the coverage they produce) and priced on
/// [`MAX_COMPARE_OPERAND_BLOCKS`]'s card, which also says why the count is
/// two, what each count refuses, and what the counts stop within one span and
/// what they do not. Pricing the two apart is a deliberate edit of this line,
/// never a drift between two literals.
///
/// WHAT IT DOES NOT BOUND, and neither could any number here: `|R|` and
/// `#runs(d)` are the WORLD's, not the request's, so they stay with rate and
/// concurrency — M10's, exactly as [`Query::show_deletions`]' `|R↾d|` term
/// already is. This bounds the coverage the request materializes, and the
/// factor the request multiplies those scans by; it does not bound the scans.
///
/// [`Query::show_deletions`]: crate::Query::show_deletions
pub const MAX_FIND_COVERAGE_SPANS: usize = MAX_COMPARE_OPERAND_BLOCKS;

/// One count taken against one of the budgets above — the spans a request
/// side hands to M5, the blocks or coverage they produce, or the pairs a join
/// emits — and the one place a count's boundary is spelled. It admits items
/// until its budget is spent and refuses any that would pass it, BEFORE they
/// are kept: exactly the budget is admitted, and a batch that would pass it is
/// refused whole, admitting none of itself. So a producer that hands its items
/// over together — the successor join `interval_join` names, which emits one
/// event point's pairs at once — is held to the budget exactly as one that
/// hands them over singly; a guard comparing the accumulator to the budget
/// before a batch lands would admit the batch that crosses it.
///
/// `tests/it/tidy.rs` holds the assignment: no code line under `src/` but
/// this file compares anything to a budget, so a producer cannot spell the
/// boundary for itself.
#[derive(Debug)]
pub(crate) struct Count {
    budget: usize,
    admitted: usize,
}

/// A count would pass its budget. The request is refused whole: the operation
/// answers with its own typed rejection and no partial answer.
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

    /// Admits `items` more, or — if they would pass the budget — refuses them
    /// all and admits none. Asked before the items are kept, and for a span
    /// before its walk.
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
    fn a_count_refuses_a_batch_that_would_pass_its_budget_whole() {
        // The form `interval_join`'s successor needs: a guard comparing the
        // accumulator to the budget before a batch lands admits the batch
        // that crosses it; a count refuses it before it lands.
        let mut count = Count::against(4);
        assert!(count.admit(3).is_ok());
        assert!(count.admit(2).is_err(), "3 + 2 would pass 4");
        assert!(
            count.admit(1).is_ok(),
            "the refused batch admitted none of itself"
        );
        assert!(count.admit(1).is_err());
    }
}
