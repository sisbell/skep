//! The request budgets, each a REFUSAL rather than a truncation: COMPARE's
//! operand budget, [`MAX_COMPARE_OPERAND_BLOCKS`] per operand, and pair
//! budget, [`MAX_COMPARE_PAIRS`] per report; FINDDOCSCONTAINING's coverage
//! budget, [`MAX_FIND_COVERAGE_SPANS`]; RETRIEVEV's delivery budget,
//! [`MAX_DELIVERY_ITEMS`] per spec-set; and the walk budget,
//! [`MAX_WALK_STEPS`], on the run-list steps the spans of one COMPARE operand,
//! FINDDOCSCONTAINING request or RETRIEVEV spec-set may make M5 walk — and the
//! [`Count`] every count against them is taken through. The three operations
//! count against them and the rejections render them, so the numbers, their
//! argument and the count that enforces them live here, apart from all four.
//! [`MAX_COMPARE_OPERAND_BLOCKS`]'s card is the one statement of why the
//! operand budget is counted twice, and of why the coverage budget, which
//! takes its number by definition, is too; [`MAX_WALK_STEPS`]'s is the one
//! statement of what a span's walk costs and how it is priced; [`Count`]'s
//! card is the one statement of where a count's boundary falls.

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
/// span costs one resolution walk, `Θ(#runs(doc))` whether or not it yields a
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
/// stops its walk at the budget, and what one span makes M6 hold live exceeds
/// the budget by at most the run that trips it: each count bounds the LIST —
/// the join's factor, the scans' multiplier — and the peak heap of building
/// it. Neither bounds the walk to a span's opening ordinal, which passes up to
/// `#runs(doc)` runs — the document's own fragmentation — whatever the span
/// yields; the walk budget prices that walk, ahead of it.
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

/// The most items one RETRIEVEV may deliver — one per position of each
/// delivered run and one per withheld run, as [`Delivery::len`] counts — and so
/// the ceiling on what the DELIVERY makes M6 hold live.
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
/// its value an `Arc` clone and never a byte copy — and a link reference or a
/// withheld run owns an `Address` besides, order 300 heap bytes. `2^17` items
/// is therefore 8 MiB of delivery, and about 45 MiB at worst: under
/// [`MAX_COMPARE_PAIRS`]' 64 MiB report, the most one query here holds. It is
/// also M5's `MAX_REINSERTED_VALUES`, the substrate's existing ceiling on how
/// many values one operation may stage live. What the items RENDER to — each
/// content item's bytes — is the transport's to bound.
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

/// The most run-list steps the spans of one request may make M5 walk — per
/// COMPARE operand, per FINDDOCSCONTAINING request, per RETRIEVEV spec-set —
/// priced over the whole request before its first span is walked.
///
/// The walk is the one cost no count above sees. M5 reaches a span by walking
/// the selected run list from its first run, so a span costs up to `#runs`
/// steps whatever it yields — every run, for a span opening past the arranged
/// end — while the span count sees one span and the block, coverage and item
/// counts see at most what it yields. A request of spans aimed past the end of
/// a fragmented document costs `|spans| · #runs(doc)` steps and produces
/// nothing, and `#runs` is cheap to grow: one COPY places up to M5's
/// `MAX_PLACED_RUNS` runs. `walk_ceiling` prices each span at the most its walk
/// can take, read off M5's O(1) run counts.
///
/// The budget is the operand budget's square, `2^24` — the bound
/// [`MAX_COMPARE_OPERAND_BLOCKS`]' card prices COMPARE's join at, order a
/// second of one worker — and M8's `MAX_JOIN_STEPS` holds the same walk behind
/// its region reads to the same number. It bounds the request's MULTIPLE of a
/// document's fragmentation, never the fragmentation itself: a span reaching
/// deep into a document of more runs than the budget is refused whatever it
/// yields, and is asked of a less fragmented surface or nearer its start.
/// Crate-private, as M8's is: no answer here reports the run counts a caller
/// would size a request against, so the refusal renders the number and nothing
/// publishes it to compute with.
pub(crate) const MAX_WALK_STEPS: usize = MAX_COMPARE_OPERAND_BLOCKS * MAX_COMPARE_OPERAND_BLOCKS;

/// One count taken against one of the budgets above — the spans a COMPARE
/// operand or a FINDDOCSCONTAINING request hands to M5, the blocks or coverage
/// they produce, the pairs a join emits, the items a delivery holds, or the
/// run-list steps a request's spans are priced at — and the one place a
/// count's boundary is spelled. It admits items until its budget is spent and
/// refuses any that would exceed it, BEFORE they are kept: exactly the budget
/// is admitted, and a batch that would exceed it is refused whole, admitting
/// none of itself. So a producer that hands its items over in batches is held
/// to the budget exactly as one that hands them over singly; a guard comparing
/// the accumulator to the budget before a batch lands — `>=` as much as `==` —
/// would admit the batch that crosses it, and answer past the budget when that
/// batch is the last. A delivered run's positions and a span's walk are such
/// batches.
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
    fn a_count_refuses_a_batch_that_would_exceed_its_budget_whole() {
        // The form `interval_join`'s successor needs: a guard comparing the
        // accumulator to the budget before a batch lands admits the batch
        // that crosses it; a count refuses it before it lands.
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
