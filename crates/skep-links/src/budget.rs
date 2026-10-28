//! The two per-slot budgets caller-shaped slots are held to, and the
//! publication's budget on the reads it makes under the lock.
//!
//! They are the spans a slot keeps ([`MAX_SLOT_SPANS`]), which every
//! caller-shaped slot is held to, and the run-list steps a `Resolve` slot's
//! specs command ([`MAX_SLOT_RESOLVE_STEPS`]) — its result and its work,
//! neither of which bounds the other. MAKELINK enforces both, and `emit` and
//! `editlink` the first, each refusing an over-budget slot `SlotTooLarge`;
//! the rejections' `Display` text names the numbers. The third,
//! [`MAX_PUBLICATION_READS`], bounds the reads a publication's composite
//! makes under the serialization lock, priced ahead of the lock by
//! `price_publication_reads` (the publication's module) and refused there by
//! the daemon; this crate compares against it and refuses nothing itself.

/// The most spans one slot may carry.
///
/// It is the budget every caller-shaped slot is held to, whichever form
/// built it: MAKELINK's [`SlotArg::Resolve`](crate::SlotArg::Resolve) and
/// [`SlotArg::Addrs`](crate::SlotArg::Addrs) slots
/// ([`MakeLinkError::SlotTooLarge`](crate::MakeLinkError::SlotTooLarge)); an
/// `editlink` successor's slots, which M10 builds from V-specs — its type
/// slot from address names instead, where the request names them — and
/// which so amplify as MAKELINK's slots do
/// ([`EditLinkError::SlotTooLarge`](crate::EditLinkError::SlotTooLarge)); and
/// both of [`emit`](crate::LinkWriter::emit)'s caller-sized slots, `to` and
/// `ty` ([`EmitError::SlotTooLarge`](crate::EmitError::SlotTooLarge)).
///
/// Both slot forms amplify, and differently. A `Resolve` slot's span count is
/// not the request's size at all: `resolve` yields one run per contiguous
/// I-segment, so one ~80-byte spec expands to as many spans as the source
/// document happens to be fragmented, a slot's specs sum those, and the
/// result is stored verbatim (ML1 coverage-exactness forbids coalescing it
/// away). An address-named slot's span count is linear in the request, but
/// its bytes are not: an eight-component dotted address is ~19 wire bytes,
/// and the span it becomes is `subtree_of` over it — two `BigUint` tumblers
/// as deep as the address, order half a kilobyte live at eight components —
/// so a slot bounded only by the request body would name hundreds of
/// thousands of spans.
///
/// The budget is a count — the spans a slot keeps — so it bounds what the
/// stored endset costs, live and for good (the store holds every link in
/// memory), only through what one span costs, and that is set by the depth of
/// the span's two tumblers rather than by this crate: order half a kilobyte at
/// the eight components of a top-level document's element, ~16–20 KB at the
/// 256 components skepd's codec admits — a depth M5's daughter chains let a
/// `Resolve` slot reach without naming it. So a slot at budget is ~2 MB live
/// at the shallow end and ~70 MB at the deep one (~21 MB journaled), and a
/// three-slot MAKELINK stores up to ~200 MB from a ~6 MB frame; M10's
/// `Codec::parse` doc carries the arithmetic. The spanfilade files every kept
/// span once more — its start, a pointer to its link, a pointer to its home
/// (the home's tumbler held once per index, whatever the link count) and its
/// coordinates — at order 0.4 KB a span at the shallow end and 6 KB at the
/// deep one, about as much again as the span and about half as much; and its
/// directory of homes takes at most two entries per span, one for the block
/// its start falls in and one for the node it files at, each written once per
/// home and so in practice a few per home per slot, at order 0.1 KB apiece —
/// so the index adds ~3 MB and ~27 MB a slot at budget, live and never
/// journaled. `MAX_TXN_BYTES` does not
/// bound the live figure: it is charged against the encoded transaction after
/// the closure returns, and a span's encoded form is a fraction of its live
/// one, so the deep three-slot MAKELINK journals inside it. MAKELINK's three
/// slots are built and held under M2's applier lock, and every deposit's slots
/// are filed there; `emit` builds its value before the transact, and an
/// `editlink` successor is built entirely by its caller.
///
/// It bounds a slot's result and, the resolution being pulled a run at a
/// time and stopped here, the live peak of building it — and nothing else.
/// The work a `Resolve` slot commands is bounded by its companion
/// [`MAX_SLOT_RESOLVE_STEPS`], because the result cannot bound it: a spec
/// aimed past its source's arranged end keeps no span and walks the whole run
/// list. And skepd's codec, M10's production `Codec`, additionally reuses
/// this number as its wire list cap (`MAX_WIRE_LIST = MAX_SLOT_SPANS`), which
/// makes it the bound on a query endset's span count too — a use this
/// argument does not cover: a stab ([`crate::LinkState::stab`]) probes the
/// spanfilade once per query span, so this constant bounds its probes, and
/// what it pays past them is its hits, which the store's contents set and no
/// caller chooses.
pub const MAX_SLOT_SPANS: usize = 4096;

/// The most run-list steps one `Resolve` slot's specs may command.
///
/// It is the companion of [`MAX_SLOT_SPANS`], which bounds a slot's result
/// where this bounds its work.
///
/// The two are independent because the result does not bound the work. M5
/// states the cost at its one clip: resolving a span is
/// `Θ(#runs left of its opening ordinal)` — one `Nat` addition and one
/// comparison per run the prefix-sum walk passes over — so resolving the last
/// position of an n-run list costs n steps however narrow the answer, and a
/// spec opening past the arranged end keeps nothing at all while walking all
/// of it. A slot of such specs is therefore unbounded in work at zero span
/// count, and every step of it runs inside MAKELINK's transact, under M2's
/// applier lock, where it stalls every writer in the engine rather than only
/// the caller.
///
/// The charge is the source's whole run count
/// ([`M5State::content_run_count`], one map lookup reading no run), which is
/// the worst case rather than the actual steps: the runs left of an ordinal
/// are not derivable from the ordinal, run widths being arbitrary, and M5's
/// resolution does not report the steps it spent. That makes the bound
/// conservative in the one direction that is safe — a narrow early span over
/// a hugely fragmented source is refused for work it would not have done.
///
/// It bounds a duration and not a transient: each spec's runs are pulled one
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
///
/// [`M5State::content_run_count`]: skep_arrangement::M5State::content_run_count
pub const MAX_SLOT_RESOLVE_STEPS: usize = 64 * MAX_SLOT_SPANS;

/// The most in-lock reads one publication may command (the link-sets design
/// §5.7, EVERY IN-LOCK READ IS BOUNDED BY A REFUSAL AHEAD OF THE LOCK).
///
/// It bounds the price `price_publication_reads` computes — the caller's
/// link-holding home count × (`links` entries + `read_with` entries), plus
/// the draft's content run count × the request's runs — which is the work
/// the composite's four in-lock reads do, counted in the two units they are
/// paid in: the first product in index probes (`stab_typed_in` of the
/// supersession class per own home per `links` entry, twice — the claim's
/// test and the successor's original's — and `read_with_in`'s probe per
/// published own home per `read_with` entry), the second in run-list steps
/// (the kept-place check's resolution of each placed run over the draft's
/// run-list, and the twin fence's one stab per re-inserted run beside it).
/// Like [`MAX_SLOT_RESOLVE_STEPS`] the charge is an upper bound read before
/// the work — every own home is charged whether or not it holds a claim,
/// every run whether or not it carries a place — so it is conservative in
/// the one direction that is safe, and the daemon prices it on a snapshot
/// taken before its lock, so the counts may have moved by the time the
/// composite reads: a request refused here would have cost at least this
/// much, and one admitted may cost a little more.
///
/// `16 × MAX_SLOT_SPANS`, a quarter of the run-list steps one `Resolve`
/// slot may command under the applier lock. The two units differ: a
/// run-list step is one `Nat` add-and-compare, order 50 ns, while an index
/// probe descends the home's spanfilade and tests its hits, order one to a
/// few microseconds — so at this budget the second term holds the lock for
/// about a quarter of what [`MAX_SLOT_RESOLVE_STEPS`] tolerates per slot and
/// the first for order a tenth of a second, inside the transport's 30 s
/// deadlines by two orders and inside what a maximal shot's own staging
/// already holds it for. What it admits: the wire's 4096 entries over 16
/// link-holding homes, 1024 over 64, 256 over 256; a draft of 256 content
/// runs re-supplied whole as 256 runs, or 4096 runs windowing a draft of 16;
/// and the terms share the one budget, so a request near it on one has
/// little room on the other. A refusal is permanent for the request as
/// sent — the same board prices it the same — and the act that exists is a
/// narrower one: fewer entries, or a draft re-read into fewer runs.
pub const MAX_PUBLICATION_READS: usize = 16 * MAX_SLOT_SPANS;
