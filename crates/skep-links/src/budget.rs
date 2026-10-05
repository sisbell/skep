//! The two per-slot budgets every caller-shaped slot is held to: the spans a
//! slot KEEPS ([`MAX_SLOT_SPANS`]) and the run-list steps a `Resolve` slot's
//! specs COMMAND ([`MAX_SLOT_RESOLVE_STEPS`]) — its result and its work,
//! neither of which bounds the other. MAKELINK, `emit` and `editlink` enforce
//! them, each refusing an over-budget slot `SlotTooLarge`, and the rejections'
//! `Display` text names the numbers.

/// The most spans ONE slot may carry — the budget every caller-shaped slot
/// is held to, whichever form built it: MAKELINK's
/// [`SlotArg::Resolve`](crate::SlotArg::Resolve) and
/// [`SlotArg::Addrs`](crate::SlotArg::Addrs) slots
/// ([`MakeLinkError::SlotTooLarge`](crate::MakeLinkError::SlotTooLarge)), an
/// `editlink` successor's slots
/// ([`EditLinkError::SlotTooLarge`](crate::EditLinkError::SlotTooLarge)), and
/// BOTH of [`emit`](crate::LinkWriter::emit)'s caller-sized slots — `to` and
/// `ty` ([`EmitError::SlotTooLarge`](crate::EmitError::SlotTooLarge)).
///
/// Both slot forms amplify, and differently. A `Resolve` slot's span count is
/// not the request's size at all: `resolve` yields one run per contiguous
/// I-segment, so one ~80-byte spec expands to as many spans as the SOURCE
/// document happens to be fragmented, a slot's specs sum those, and the
/// result is stored VERBATIM (ML1 coverage-exactness forbids coalescing it
/// away). An address-named slot's span COUNT is linear in the request, but
/// its BYTES are not: a dotted address is ~19 wire bytes and the span it
/// becomes is `subtree_of` over it — two 8-component `BigUint` tumblers,
/// order half a kilobyte live — so a slot bounded only by the request body
/// would name hundreds of thousands of spans.
///
/// The budget is the per-slot STORED endset's live memory and permanent store
/// — the spans a slot KEEPS. `MAX_TXN_BYTES` bounds neither: it is charged
/// against the ENCODED transaction after the closure returns, and the encoded
/// form of a span is a
/// small fraction of the live one. At order half a kilobyte per element-level
/// span this bound is ~2 MB a slot and ~6 MB across a three-slot MAKELINK:
/// the order of the request body a caller is allowed to send in the first
/// place. MAKELINK's three slots are additionally built and held under M2's
/// applier lock; `emit` builds its value before the transact, and an
/// `editlink` successor is built entirely by its caller.
///
/// It bounds a slot's RESULT and, the resolution being pulled a run at a
/// time and stopped here, the live peak of building it — and nothing else.
/// The WORK a `Resolve` slot commands is bounded by its companion
/// [`MAX_SLOT_RESOLVE_STEPS`], because the result cannot bound it: a spec
/// aimed past its source's arranged end keeps no span and walks the whole run
/// list. And M10 additionally reuses this number as its wire list cap
/// (`MAX_WIRE_LIST = MAX_SLOT_SPANS`), which makes it the bound on a QUERY
/// endset's span count too — a use this
/// argument does not cover: a query's cost is
/// `|links| × |query spans| × |slot spans|` ([`crate::LinkState::stab`]), and
/// this constant bounds two of those three factors while the store size,
/// which no caller chooses, is the third.
pub const MAX_SLOT_SPANS: usize = 4096;

/// The most run-list steps ONE `Resolve` slot's specs may command — the
/// companion of [`MAX_SLOT_SPANS`], which bounds a slot's RESULT where this
/// bounds its WORK.
///
/// The two are independent because the result does not bound the work. M5
/// states the cost at its one clip: resolving a span is
/// `Θ(#runs left of its opening ordinal)` — one `Nat` addition and one
/// comparison per run the prefix-sum walk passes over — so resolving the LAST
/// position of an n-run list costs n steps however narrow the answer, and a
/// spec opening PAST the arranged end keeps nothing at all while walking all
/// of it. A slot of such specs is therefore unbounded in work at zero span
/// count, and every step of it runs inside MAKELINK's transact, under M2's
/// applier lock, where it stalls every writer in the engine rather than only
/// the caller.
///
/// The charge is the SOURCE's whole run count
/// ([`M5State::content_run_count`](skep_arrangement::M5State::content_run_count), one
/// map lookup reading no run), which is
/// the worst case rather than the actual steps: the runs left of an ordinal
/// are not derivable from the ordinal, run widths being arbitrary, and M5's
/// resolution does not report the steps it spent. That makes the bound
/// conservative in the one direction that is safe — a narrow early span over
/// a hugely fragmented source is refused for work it would not have done.
///
/// It bounds a DURATION and not a transient: each spec's runs are pulled one
/// at a time off M5's lazy `iter_resolve`, and the span budget above stops
/// the walk where the slot crosses it, so a slot's live peak is the spans it
/// keeps — [`MAX_SLOT_SPANS`]' figure — whatever this constant admits.
///
/// `64 × MAX_SLOT_SPANS` steps: the product admits the wire's 4096 specs over
/// a 64-run source, 64 specs over a 4096-run one, or one spec over a
/// 262,144-run one. At order 50 ns per `Nat` add-and-compare that is ~13 ms
/// of applier-lock hold per slot and ~40 ms across a three-slot MAKELINK.
/// What an operator prices that against is its own documents' fragmentation,
/// which is what the charge reads, and its tolerance for holding the write
/// path.
pub const MAX_SLOT_RESOLVE_STEPS: usize = 64 * MAX_SLOT_SPANS;
