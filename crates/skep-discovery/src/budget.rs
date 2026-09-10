//! §Public interface — the two budgets, both REFUSALS rather than
//! truncations: [`MAX_IMAGE_RUNS`], held at the four reads of a document's
//! runs — the region family's image, the pointwise pair, the delete-orphan
//! preview — each over the run count its own work multiplies, with its
//! square [`MAX_JOIN_STEPS`] for the two joins no run count prices; and
//! [`MAX_ENDSET_SPANS`], which bounds what a RETRIEVEENDSETS answer carries.
//! Each read applies its own; the numbers and their argument live here
//! because the region family, the pointwise pair and the preview all consult
//! them.

/// The most arrangement I-runs one request may make M8 materialize or join
/// against, and so the ceiling on the multiplier the REQUEST applies to the
/// world-sized scan behind it.
///
/// ONE constant, held at the four sites that read a document's runs, each
/// against the run count that site's OWN work multiplies — so the number is
/// one and the quantities are four:
///
/// * [`crate::image_on`] counts the runs the REGION resolves, which is a
///   request-shaped multiple of `#runs(d)`, so whether a `d` is refused
///   depends on the region asked and not on `d` alone;
/// * [`crate::project_on`] counts `#content_runs(d)`, because M5's `project`
///   joins the coverage against the content runs alone;
/// * [`crate::addressably_discoverable_from_on`] counts
///   `#content_runs(d) + #link_runs(d)`, because LP12 ranges over both
///   subspaces and every one of those extents is tested;
/// * [`crate::delete_orphans_on`] counts the runs its two stabs join — `d`'s
///   own arrangement as the range splits it, at most two runs more than `d`
///   holds — so its verdict depends on `d` and, at the budget or one run
///   under it, on where the range's ends fall.
///
/// So the four refuse DIFFERENT documents, and the inclusions run only one
/// way: the pointwise pair's counts differ by `d`'s link runs, so a `d`
/// `project_on` answers about may be one
/// [`crate::addressably_discoverable_from_on`] refuses, and neither relates
/// to `image_on`'s verdict, which the caller's region moves. Each site
/// prices the factor it multiplies; what the budget bounds is the multiple
/// of the world's fragmentation one request may make M8 pay for, never the
/// fragmentation itself.
///
/// The budget: the runs become one side of a join in every case — lifted into
/// a query `Endset` for M7's `stab`, which walks the whole store testing
/// every query span against every slot span of every link; lifted into an
/// I-extent apiece for the pointwise touch test; handed to M5's `project`,
/// which states the cost as `#runs(d) × |coverage|` and leaves admission
/// control to its caller. `2^12` is this workspace's existing answer for how
/// large one side of a join may be (M6's COMPARE operand and its coverage
/// budget both). It is also M7's `MAX_SLOT_SPANS`, the ceiling a STORED slot
/// is held to — a query endset costs more than a stored one, never less — and
/// M10's per-array wire cap, so a FLAT region of 4096 spans each resolving to
/// one run — the largest region the transport admits — passes the run count
/// unchanged. It passes the walk (below) too over any reading surface of at
/// most 4096 content runs; over a more fragmented surface the walk decides,
/// and it refuses such a region when its spans lie deep in the run-list.
///
/// What it refuses is the shape no wire cap prices: the region×image product,
/// where each admitted span resolves to the whole of a fragmented document.
///
/// Its SQUARE, `2^24`, holds the two joins whose other side no run count
/// reaches, and M6's COMPARE budget is its argument: an operand budget
/// squares, and `2^12` a side bounds one query at `2^24` steps, order a
/// second of one worker.
///
/// * The RUN-LIST WALK behind [`crate::image_on`]. M5 reaches a span by
///   walking the run-list from its first run — in M5's own cost note,
///   resolving the last position of an `n`-run list costs `n` steps however
///   narrow the answer — so a region walks up to `|region| × #runs(d)` runs,
///   and a span past the end of a fragmented document walks every run and
///   returns none. The count above prices runs RETURNED and never sees that
///   walk; the square prices it, ahead of the first `resolve`.
/// * The TOUCH TEST behind the pointwise pair: every span of a link's
///   coverage against every run, where a link's WHOLE coverage is up to
///   `MAX_SLOT_SPANS` a slot, so the run count alone admits three times the
///   square. M5's `project` makes the same join over one slot, and the square
///   holds it too, rather than leaving it to M7's cap agreeing with this one.
///
/// THE GRANULARITY IS A REGION SPAN, as M6's coverage budget's is: the
/// resolution stops at the first span whose image carries the accumulator
/// past the budget, so an over-budget request stops resolving rather than
/// resolving whole and then being measured. Within one span it bounds
/// nothing — M5's `resolve` answers that span whole, at a size that is the
/// DOCUMENT's fragmentation rather than the request's shape.
///
/// `#runs(d)` and `|links|` are the WORLD's, and no number here reaches them:
/// they stay with request rate and concurrency, which are M10's as the
/// request lifecycle's owner.
pub const MAX_IMAGE_RUNS: usize = 1 << 12;

/// [`MAX_IMAGE_RUNS`] squared: the most steps one join of a side the request
/// supplies against a document's runs may take. [`MAX_IMAGE_RUNS`] states the
/// two joins it holds and the budget behind it; crate-private because it is
/// that square and nothing of its own.
pub(crate) const MAX_JOIN_STEPS: usize = MAX_IMAGE_RUNS * MAX_IMAGE_RUNS;

/// The most spans one RETRIEVEENDSETS answer may carry, and so the ceiling on
/// what the pair set makes M8 hold live and what the presentation sorts.
///
/// The budget: a pair's cost is its spans, and the answer's is their sum —
/// the sort is `O(B log B)` span comparisons over `B` accumulated spans (a
/// comparison walks two span sequences to their first difference, so a long
/// endset pays its length once rather than once per comparison), each span
/// two `Tumbler`s. `2^16` is M5's `MAX_PLACED_RUNS` and M6's
/// `MAX_COMPARE_PAIRS` — the substrate's existing answer to how large one
/// REPORT may be.
///
/// Not `MAX_IMAGE_RUNS`: that budget bounds one side of a join a caller
/// supplies, and this bounds an answer the STORE supplies. One deposit may
/// legitimately carry `MAX_SLOT_SPANS` = `2^12` spans in a single slot, so a
/// `2^12` answer budget would refuse a region touched by two such links —
/// while `2^16` admits some twenty thousand ordinary small-endset links
/// through one region.
///
/// WHAT IT DOES NOT BOUND: `|links|` and any one link's endset size are the
/// WORLD's, so the candidate walk this budget rides on is world-sized whatever
/// the number — the same division M6 draws — and the answer's marshalled form
/// is M10's, which owns no ceiling of its own beyond the one this bounds.
pub const MAX_ENDSET_SPANS: usize = 1 << 16;
