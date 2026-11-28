//! The per-slot budget caller-shaped slots are held to, and the
//! publication's budget on the reads it makes under the lock.
//!
//! The first is the spans a slot keeps ([`MAX_SLOT_SPANS`]), which every
//! caller-shaped slot is held to: MAKELINK, `emit` and `editlink` each
//! refuse an over-budget slot `SlotTooLarge`, and the rejections' `Display`
//! text names the number. It is the one budget of a slot. A `Resolve`
//! slot's work is its result's: each spec's resolution descends its
//! source's run-list to the span — a node a level of the list's tree,
//! whatever the source holds — and then reads the runs it yields, each a
//! span kept and counted, so no second budget prices a walk to the span.
//! The second,
//! [`MAX_PUBLICATION_READS`], bounds the reads a publication's composite
//! makes under the serialization lock and the run-list steps its
//! re-window is priced at, priced ahead of the lock by
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
/// time and stopped here, the live peak of building it — and, with them,
/// the work a `Resolve` slot commands: a spec's resolution reaches its span
/// by a descent of its source's run-list and reads from there the runs it
/// yields, so a spec aimed past its source's arranged end keeps no span and
/// reads no run, and a slot's walks are the spans it keeps and a descent a
/// spec. And skepd's codec, M10's production `Codec`, additionally reuses
/// this number as its wire list cap (`MAX_WIRE_LIST = MAX_SLOT_SPANS`), which
/// makes it the bound on a query endset's span count too — a use this
/// argument does not cover: a stab ([`crate::LinkState::stab`]) probes the
/// spanfilade once per query span, so this constant bounds its probes, and
/// what it pays past them is its hits, which the store's contents set and no
/// caller chooses.
pub const MAX_SLOT_SPANS: usize = 4096;

/// The most in-lock reads one publication may command (the link-sets design
/// §5.7, EVERY IN-LOCK READ IS BOUNDED BY A REFUSAL AHEAD OF THE LOCK).
///
/// It bounds the price `price_publication_reads` computes — the caller's
/// link-holding home count, the homes under its seat that the class the
/// price is taken at admits, × (`links` + `originals` + `read_with` +
/// `supersede` entries); plus, per document the commit re-windows, its
/// content runs and the pieces its lists place; plus one per re-inserted
/// run — which is the work the composite's in-lock reads and the re-window's
/// one pass do, counted in the two units they are paid in. The first
/// product and the last term are index probes:
/// `stab_typed_in` of the supersession class per own home per `links`
/// entry, twice — the claim's test and the successor's original's — and per
/// `originals` entry, `read_with_in`'s probe per published own home per
/// `read_with` entry, the claim read per own home per `supersede` entry, and
/// the twin fence's one stab per re-inserted run. The re-window's term is
/// priced in run-list steps, a step a content run of each re-windowed
/// draft and a step a piece: the ceiling of a check and two folds that each
/// read the draft's whole list. The list is held as a tree, so the check
/// by identity descends to each kept place and each fold of the one record
/// of those places reads the list at the places' cuts alone; the term
/// charges every run of the draft all the same, and so prices the
/// re-window above its work by the runs no place reaches. The charge is an
/// upper bound read before the work — every own home is charged whether or
/// not it holds a claim, and every piece at the pairing's bound — so it is
/// conservative in the one direction that is
/// safe; a run no list places adds no piece to the re-window's term. The
/// daemon prices it on a snapshot taken before its
/// lock, so the counts may have moved by the time the composite reads: a
/// request refused here would have cost at least this much, and one admitted
/// may cost a little more.
///
/// `16 × MAX_SLOT_SPANS`: a number kept by choice, and derived from no
/// measured hold. The two units differ: a run-list step is a run of a
/// re-windowed draft counted, which the check and the folds read only
/// where a place cuts it, while an index probe
/// descends the home's spanfilade and tests its hits, order one
/// to a few microseconds. What holds the lock longest is neither: the
/// writes the commit stages — a correspondence record a minted piece, the
/// re-insert's records, every record folded again at the seal — are priced
/// by no read. This budget bounds the reads; the staged bytes, held to the
/// transaction budget by the same price (`ReadPrice::BYTE_BUDGET`), bound
/// the writes. What it
/// admits: the wire's 4096 entries over 16 link-holding homes, 1024 over
/// 64, 256 over 256; one typed word — one placed run — in a draft of up to
/// 65,534 runs; a change of 1,613 pieces into a draft of 4,167 runs, at
/// 5,780 steps and its 1,613 fence stabs; a first publication placed run
/// for run of a draft of up to 21,845 runs, three steps a run — the run
/// walked, its piece, its fence stab — which is inside what one request's
/// `runs` list carries (the store's 65,536, `MAX_PLACED_RUNS`), so a
/// publication re-windowing a draft at more places than that is refused
/// here though its frame parses; and the terms share the one budget, so a
/// request near it on one has little room on the others. A refusal is permanent for the
/// request as sent — the same board prices it the same — and the act that
/// exists is a narrower one: fewer entries, or fewer places.
pub const MAX_PUBLICATION_READS: usize = 16 * MAX_SLOT_SPANS;
