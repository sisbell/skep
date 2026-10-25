//! The class-scan bound: the class pool and the per-document pool.
//!
//! The items are `MAX_CONCURRENT_CLASS_SCANS`, `MAX_REGION_READS_PER_DOCUMENT`,
//! `MAX_CONCURRENT_REGION_READS`, `ClassScans`, `ScanPermit`, `RegionPermit`,
//! `ScanBusy`, `is_class_scan` and `region_document`.

use std::collections::BTreeMap;
use std::fmt;

use parking_lot::Mutex;
use skep_address::{document_of, validate, Address, Tumbler};
use skep_discovery::{FourSet, SlotSpec};
use skep_febe::Op;
use skep_util::permits::{edge_clock_now, EdgeTracker, Permit, Permits};

use skep_core::limits::EDGE_HOLD_DOWN;

/// The cap on class scans admitted at `/op` at once (PUB-8.36, PUB-8.37).
///
/// Class scans (wire v7.9) are the link-discovery reads whose SHAPE is
/// world-sized — [`is_class_scan`] states the shapes: a four-set that walks
/// a whole type class or the whole board, or every home under an account or
/// the node — each costing one home test per home the class or the board
/// holds, whatever the request's own size, and each repeatable at will from
/// any unauthenticated peer.
///
/// The reconstruction pool's own number
/// ([`crate::history::MAX_CONCURRENT_RECONSTRUCTIONS`]), for the same reason
/// it is that pool's: two keep directories serviceable without letting a
/// stranger's scans occupy the worker pool. The wire names it as a constant
/// the daemon may raise later — a configuration question, not this bound's.
/// Since the home-index lane the region family draws on the per-document
/// pool below and not on this one, so a board's own reading pane never
/// contends here.
///
/// One pool for the board: global across every class-scan shape, across
/// every type class, and across every session and the guest (a stranger is
/// the case). Disjoint from the reconstruction pool and from the
/// per-document pool — an instance of [`Permits`] of its own, never a share
/// of another — so history panes and mirror bootstraps are never starved by
/// directory scans, nor the reverse, and a flooded page's readers never
/// refuse a directory.
///
/// The sum of this pool, the per-document pool's ceiling and the other four
/// — the reconstruction, fetch, upload and write pools — must leave a worker
/// free: [`MIN_WORKERS`](super::MIN_WORKERS) holds that relation, and an
/// assertion beside it holds the shipped default to it.
pub(super) const MAX_CONCURRENT_CLASS_SCANS: usize = 2;

/// The cap on region reads of ONE document admitted at once (the home-index
/// record's D3 and D4; skep #651).
///
/// A region read — the region family and `delete_orphans`, every read whose
/// frame names a document `d` — costs, since the home-index lane, the homes
/// its spans touch and the readable homes' links: a flooded PUBLIC passage
/// still costs its public population, which satisfies the request, so a
/// read of it is sized by that page and not by the request. The bound is
/// therefore BY DOCUMENT: at most this many region reads of one document at
/// once, so a flooded page's readers contend among themselves, and a read
/// of any other page never meets them. Two, as the class pool's width: a
/// board's reading pane holds one per scroll, and the second is the one a
/// second reader of the same page takes.
pub(super) const MAX_REGION_READS_PER_DOCUMENT: usize = 2;

/// The ceiling on region reads admitted at once across every document (D3,
/// D4).
///
/// Per-document pools multiply with the documents read at once, and a pool
/// per document with no ceiling would let a stranger reading many pages
/// hold every worker inside a bound. So the per-document widths sit inside
/// ONE ceiling: a region read takes a slot of its document's width AND a
/// slot of this ceiling, and the ceiling is the term
/// [`MIN_WORKERS`](super::MIN_WORKERS) counts, not the widths. Six: three
/// pages read two at a time, the shape a board of a few readers makes.
pub(super) const MAX_CONCURRENT_REGION_READS: usize = 6;

/// The class-scan bound, whole (wire v7.9; PUB-8.36, PUB-8.37; D3).
///
/// It holds what counts as a class scan ([`is_class_scan`]), which reads
/// draw on the per-document pool ([`region_document`]), how many of each run
/// at once ([`MAX_CONCURRENT_CLASS_SCANS`], [`MAX_REGION_READS_PER_DOCUMENT`]
/// inside [`MAX_CONCURRENT_REGION_READS`]), and the permit that spans one
/// answer. One card, as [`crate::history::History`] is for the
/// reconstruction budget, so the shape test and the pools it gates cannot
/// drift apart and a later meter has a whole thing to copy rather than
/// pieces on [`Daemon`](super::Daemon).
///
/// Two pools, disjoint by the borrow rather than by convention: the class
/// pool and the per-document pool's ceiling are each an instance of
/// [`skep_util::permits`]'s mechanism, a [`Permit`] names the pool that
/// issued it, and the per-document widths are a table this card alone
/// writes. Neither can spend a reconstruction slot or the other's. Beside
/// the pools, the bound's one edge pair (`operations.md` §1.1 m12): an
/// [`EdgeTracker`] the admission tells of every refusal and every permit
/// taken, by either pool — the two share one refusal word on the wire,
/// `scan_busy`, so they share the operator's two lines — whose edges the
/// daemon drains ([`ClassScans::edge`]) and says through its classed door:
/// `the scan pool is saturated` at the first refusal of an episode, `has
/// room again` at the first admission a hold-down after its last refusal.
pub(super) struct ClassScans {
    /// The class pool: a slot per class scan in flight.
    scans: Permits,
    /// The per-document pool's ceiling: a slot per region read in flight,
    /// whatever its document.
    ceiling: Permits,
    /// The per-document pool's widths: each document holding a region read,
    /// with how many it holds. An entry lives exactly while a permit of its
    /// document does, and every permit holds a slot of the ceiling, so the
    /// table holds at most [`MAX_CONCURRENT_REGION_READS`] entries, whatever
    /// a stranger names.
    by_document: Mutex<BTreeMap<Address, usize>>,
    edge: EdgeTracker,
}

/// The class-scan bound's refusal: which of its three bounds had no slot
/// for the read — every class-scan permit in use, or the read's document
/// holding its width, or the board holding its ceiling.
///
/// It says nothing about HTTP, as [`crate::history::Unavailable`] does not:
/// the mapping onto the wire is
/// [`refuse_scan_busy`](super::reply::refuse_scan_busy)'s, beside the
/// transport channel's other refusal constructors, and the wire name it maps
/// to is [`TransportError::ScanBusy`](super::reply::TransportError::ScanBusy)
/// — the same condition one layer out, which is why the two share a word and
/// why the type keeps them apart. The variant is what the refusal's `detail`
/// names, one fixed sentence per bound, rendered there and quoted by the
/// wire: a reader of a flooded page learns it is the page that is busy and
/// not the board.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ScanBusy {
    /// Every one of the [`MAX_CONCURRENT_CLASS_SCANS`] class-scan permits is
    /// in use.
    Class,
    /// The read's document holds [`MAX_REGION_READS_PER_DOCUMENT`] region
    /// reads already: the page's own readers contend.
    Document,
    /// The board holds [`MAX_CONCURRENT_REGION_READS`] region reads already,
    /// across its documents: the ceiling.
    Ceiling,
}

/// The permit an admitted read holds for its whole answer and returns on
/// every exit: a class scan's slot of the class pool, or a region read's
/// slots of its document's width and the ceiling.
///
/// Held, never read: dropping it is what returns the slots.
#[derive(Debug)]
#[must_use = "a permit dropped at once holds nothing"]
pub(super) enum ScanPermit<'a> {
    /// A class scan's permit.
    Class(#[allow(dead_code)] Permit<'a>),
    /// A region read's permit.
    Region(#[allow(dead_code)] RegionPermit<'a>),
}

/// One region read's permit: a slot of its document's width and a slot of
/// the board's ceiling, both returned on drop, early returns and panics
/// included.
///
/// Public because the daemon's test hook `Daemon::try_hold_region_permit`
/// returns it, a hook of the same standing as [`Permit`]'s:
/// `#[doc(hidden)]`, not a stable API, and nameable from outside the crate
/// by no path — a suite binds one, holds it and drops it.
#[doc(hidden)]
#[must_use = "a permit dropped at once returns both its slots at once: bind it for as long \
              as the read it licenses runs"]
pub struct RegionPermit<'a> {
    /// The ceiling's slot: `Some` until the drop returns it, under the
    /// table's lock, with the width's count.
    ceiling: Option<Permit<'a>>,
    pool: &'a ClassScans,
    document: Address,
}

/// The permit's `Debug` names the document it holds a slot of, and nothing
/// of the pool behind it.
impl fmt::Debug for RegionPermit<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RegionPermit").field("document", &self.document).finish_non_exhaustive()
    }
}

impl Drop for RegionPermit<'_> {
    fn drop(&mut self) {
        let mut table = self.pool.by_document.lock();
        if let Some(held) = table.get_mut(&self.document) {
            *held -= 1;
            if *held == 0 {
                table.remove(&self.document);
            }
        }
        // The ceiling's slot returns under the same lock as the width's
        // count, so an admission — which takes the lock, then the ceiling —
        // never sees one returned and not the other.
        drop(self.ceiling.take());
    }
}

impl ClassScans {
    pub(super) fn new() -> ClassScans {
        ClassScans {
            scans: Permits::new(MAX_CONCURRENT_CLASS_SCANS),
            ceiling: Permits::new(MAX_CONCURRENT_REGION_READS),
            by_document: Mutex::new(BTreeMap::new()),
            edge: EdgeTracker::new(EDGE_HOLD_DOWN),
        }
    }

    /// Admits one read, with a permit where the read is bounded.
    ///
    /// A class-scan-shaped read ([`is_class_scan`]) takes one of the
    /// [`MAX_CONCURRENT_CLASS_SCANS`] permits for the whole answer; a region
    /// read ([`region_document`]) takes one of its document's
    /// [`MAX_REGION_READS_PER_DOCUMENT`] inside the board's
    /// [`MAX_CONCURRENT_REGION_READS`]; any other read is admitted with no
    /// permit (`Ok(None)`).
    ///
    /// Taken before the read consult and the store call, both of which run
    /// inside M10's `execute`: a refused request has cost the parse and the
    /// session read alone, and an admitted one that M10 then withholds or
    /// rejects — never reaching M7 — still returns its permit by the guard.
    /// Both pools are the board's: the guest and the claimant draw on them
    /// alike, and which class is scanned is not consulted. Which pool the
    /// request draws on, if any, is the one thing decided here; what it
    /// answers stays the stores' — an admitted read's answer is byte-for-byte
    /// the unbounded one.
    ///
    /// **The edge pair's one site** (m12). A bounded read's refusal or
    /// admission, by either pool, is told to the tracker at the edge clock's
    /// instant and the edge it answers queued for the daemon's door; a read
    /// that takes no permit crosses none, and neither do the test hooks
    /// below, which hold a pool and not a request.
    ///
    /// # Errors
    ///
    /// [`ScanBusy`] at once where the pool the read draws on has no slot for
    /// it — a retry-class refusal, never a queue (D3: no bounded wait).
    pub(super) fn admit(&self, op: &Op) -> Result<Option<ScanPermit<'_>>, ScanBusy> {
        let taken = if is_class_scan(op) {
            self.scans.try_acquire().map(ScanPermit::Class).ok_or(ScanBusy::Class)
        } else if let Some(d) = region_document(op) {
            self.take_region(d).map(ScanPermit::Region)
        } else {
            return Ok(None);
        };
        let now = edge_clock_now();
        self.edge.queue(match &taken {
            Ok(_) => self.edge.admitted(now),
            Err(_) => self.edge.refused(now),
        });
        taken.map(Some)
    }

    /// Takes a region read's permit for `d`: a slot of `d`'s width, then a
    /// slot of the ceiling, under the table's lock, so two reads of one
    /// document racing for its last slot cannot both take it.
    ///
    /// The width is judged first, so a document at its width is refused
    /// [`ScanBusy::Document`] whether or not the ceiling has room, and the
    /// ceiling's refusal, [`ScanBusy::Ceiling`], is met only by a read its
    /// document would admit. An entry is written for `d` only once both
    /// slots are in hand, so a refused read leaves no trace in the table.
    fn take_region(&self, d: &Address) -> Result<RegionPermit<'_>, ScanBusy> {
        let mut table = self.by_document.lock();
        let held = table.get(d).copied().unwrap_or(0);
        if held >= MAX_REGION_READS_PER_DOCUMENT {
            return Err(ScanBusy::Document);
        }
        let ceiling = self.ceiling.try_acquire().ok_or(ScanBusy::Ceiling)?;
        *table.entry(d.clone()).or_insert(0) += 1;
        Ok(RegionPermit { ceiling: Some(ceiling), pool: self, document: d.clone() })
    }

    /// Returns the bound's edge tracker, for the daemon to drain.
    ///
    /// It holds the edges the admission crossed since the last drain, in
    /// order.
    pub(super) fn edge(&self) -> &EdgeTracker {
        &self.edge
    }

    /// Holds one class-scan permit exactly as an in-flight class scan does.
    ///
    /// **Test hook**, reached through `Daemon::try_hold_scan_permit`.
    #[cfg(any(test, feature = "test-hooks"))]
    #[must_use = "a permit dropped at once holds nothing"]
    pub(super) fn try_hold(&self) -> Option<Permit<'_>> {
        self.scans.try_acquire()
    }

    /// Holds one region-read permit of `d` exactly as an in-flight region
    /// read of `d` does: a slot of `d`'s width and a slot of the ceiling.
    ///
    /// **Test hook**, reached through `Daemon::try_hold_region_permit`.
    #[cfg(any(test, feature = "test-hooks"))]
    #[must_use = "a permit dropped at once holds nothing"]
    pub(super) fn try_hold_region(&self, d: &Address) -> Option<RegionPermit<'_>> {
        self.take_region(d).ok()
    }

    /// The documents holding a region read: the table's size.
    #[cfg(test)]
    fn documents_held(&self) -> usize {
        self.by_document.lock().len()
    }
}

/// Returns whether `op` is a class scan: a read whose SHAPE is world-sized,
/// one the class pool bounds.
///
/// It is the class-scan test (wire v7.9; PUB-6.54, PUB-6.56, PUB-8.36) —
/// the one statement of what the class pool bounds — and since the
/// home-index lane it bounds the SHAPE of the query and not the op. The
/// link store's coverage index is grouped by home and carries a directory of
/// homes, so every link read M8 answers is served home by home: the homes
/// some link of which could meet the query are named without visiting a
/// link, the reader's predicate is asked of each once, and an admitted
/// home's links alone are read ([M8's cost statement](skep_discovery#cost),
/// which this card restates and which a change to any read changes in the
/// same commit). So a read's cost is its candidate homes and the readable
/// homes' links, and what the WORLD sets, rather than the request, is the
/// count of homes a shape must visit: a type class's or the board's, or
/// every home under an account or the node.
///
/// **The class scans**, each a four-set shape of `find_links_ftt`,
/// `count_ftt` or `window_ftt`, bounded whatever `cur` and `n` say and
/// whichever type class is named:
///
/// * `ty` constrained and `home`, `from`, `to` all `"any"` — M8's
///   `homes_touching` off the typed slices, one seek per home the class
///   holds and one predicate test apiece, then the admitted homes' links: a
///   whole class, grouped by home (the design's directory shape, PUB-6.54;
///   PUB-6.56's consumption class). A `ty` of `"empty"` is the same shape
///   answered off its own slots before M7 is asked; it is bounded all the
///   same, and its permit is back in the pool a moment later;
/// * the all-`"any"` four-set — M8's `homes`, a seek per home the store
///   holds, one test apiece and the admitted homes' chains: the whole
///   board, that shape's superset;
/// * a `home` slot some span of which names an ACCOUNT or the NODE — M8's
///   `homes_under`, a seek per home under the span and one test apiece,
///   each admitted home's chain read as one key range and tested against
///   the link slots. The home slot drives wherever it is constrained, so
///   this shape walks every home under the account or the board whatever
///   its other slots hold: a `ty` or a `from` beside it narrows the
///   survivors of each chain, never the homes walked, and costs a test per
///   link beside the walk the `home`-only form pays. The one place a slot's
///   VALUE is read at admission: the span's start, projected by M1's
///   `document_of` — `None` for an account or the node, which lie under no
///   document — the projection M8's own home rule uses, so the bound and the
///   reads agree on what a home is. A start that is no address names no
///   account.
///
/// **The region reads** draw on the per-document pool and not on this one
/// ([`region_document`]): `find_links_v`, `count_v`, `window_v`,
/// `retrieve_endsets` — one `homes_touching` over the image's extents at the
/// three v1 slots, at up to [`skep_discovery::MAX_IMAGE_RUNS`] query spans,
/// a predicate test per candidate home and three `stab_in`s per admitted
/// home, the window no further than the home that fills its `n` — and
/// `delete_orphans` — the same over the deleted and the retained runs, six
/// pairs in one walk and six `stab_in`s per admitted home, and no owner
/// gate, so every asker reaches it on any registered document. Each costs
/// the homes touching one document's spans and their readable links: a
/// flooded PUBLIC page still costs its population, which satisfies the
/// request, so the read is sized by the page the frame names (`d`), and the
/// bound is keyed by it.
///
/// **Every other link read takes no permit**, each absence a fact about the
/// read rather than a judgement:
///
/// * the FTT family's other shapes — a `home` naming a document or a version
///   member, whatever else is constrained, reads that home's chain alone
///   (`homes_under` at one seek, `homed_in` over one key range); a `from` or
///   a `to` constrained, with or without `ty`, drives from the directory of
///   homes with a filing in the span's blocks, the constraint with the
///   fewest candidate homes driving (`fewest_homes`, a bounded walk of
///   directory entries) and the rest tested per survivor — the request's
///   spans size each, never the class or the board. The wire's sentence
///   holds of the build: a query constraining a second slot is no class
///   scan;
/// * `in_claims`, `out_claims` — one `stab_typed` at the key's own span on
///   the claim's slot, cut to the supersession class: the directory's
///   candidate homes for that span and a step per claim naming the key, no
///   walk of the class and none of the store;
/// * `edition_claims` — one `match_links` at a single-span `to` range
///   against the edition class, the constraint with the fewest homes
///   driving: the claims on the target, which its depositors choose;
/// * `image`, `project` and `discoverable_from` walk no link store — their
///   work is a walk of one document's run-list, or a join of one link's
///   coverage against that document's runs, each held by M8 to a number its
///   cost statement records: the square of [`skep_discovery::MAX_IMAGE_RUNS`]
///   for the walk and for the boolean touch test, and
///   [`skep_discovery::MAX_ANSWER_SPANS`] for the projection; `read_link`
///   and `follow_link` are lookups; the M6 family (`retrieve_v`, `compare`,
///   `show_deletions`, `find_docs_containing`, `show_origin`) and the M3
///   reads touch no link store at all.
///
/// **Not exhaustive over `Op`**: the three FTT ops are matched by name and
/// every other op answers `false`, so a new read that walks a whole class
/// must be added here by hand — `write_meta`'s table, which the compiler
/// does force, reaches writes alone. Of a query, the slots' constrainedness
/// and the home slot's tier are read, and nothing else: not the class, not
/// the cursor, not whether M8 would answer it off its own descriptor.
pub(super) fn is_class_scan(op: &Op) -> bool {
    match op {
        Op::FindLinksFtt { q } | Op::CountFtt { q } | Op::WindowFtt { q, .. } => class_scan_shape(q),
        _ => false,
    }
}

/// Whether the four-set `q` is a class-scan shape: `ty` alone or nothing
/// constrained, or a `home` span at an account or the node.
fn class_scan_shape(q: &FourSet) -> bool {
    match &q.home {
        // The home slot drives: every home under the span, whatever else
        // the four-set holds.
        SlotSpec::Spans(h) => h.spans().any(|span| names_an_account_or_the_node(span.start())),
        // The zero: unsatisfiable, answered off the slots.
        SlotSpec::Empty => false,
        // No home: the class (`ty` alone) or the board (nothing at all).
        SlotSpec::Any => matches!((&q.from, &q.to), (SlotSpec::Any, SlotSpec::Any)),
    }
}

/// Whether `start` is an address with no document field — an account or the
/// node — so a `home` span starting there covers every home beneath it.
fn names_an_account_or_the_node(start: &Tumbler) -> bool {
    validate(start.clone()).is_ok_and(|a| document_of(&a).is_none())
}

/// Returns the document a region read names, the key of the per-document
/// pool: `d` of `find_links_v`, `count_v`, `window_v`, `retrieve_endsets`
/// and `delete_orphans`; `None` for every other op.
///
/// The region family and the delete preview are the reads whose frame names
/// the document whose spans they walk ([`is_class_scan`] states what each
/// costs); the FTT family names none, so its world-sized shapes stay the
/// class pool's and its other shapes take no permit. Not exhaustive over
/// `Op`, as [`is_class_scan`] is not: a new read keyed by a document is
/// added here by hand.
pub(super) fn region_document(op: &Op) -> Option<&Address> {
    match op {
        Op::FindLinksV { d, .. }
        | Op::CountV { d, .. }
        | Op::WindowV { d, .. }
        | Op::RetrieveEndsets { d, .. }
        | Op::DeleteOrphans { d, .. } => Some(d),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use skep_febe::Codec;

    use super::*;
    use skep_core::codec::JsonCodec;

    fn parse(frame: &str) -> Op {
        JsonCodec.parse(frame.as_bytes()).unwrap_or_else(|e| panic!("{frame}: {:?}", e.detail)).op
    }

    /// A four-set frame of `op` over the four slots as given, each already
    /// JSON: `"any"`, `"empty"`, or a span array.
    fn ftt(op: &str, home: &str, from: &str, to: &str, ty: &str) -> String {
        format!(r#"{{"op":"{op}","q":{{"from":{from},"home":{home},"to":{to},"ty":{ty}}}}}"#)
    }

    const ANY: &str = r#""any""#;
    const EMPTY: &str = r#""empty""#;
    /// A type class: a unit span at a type address.
    const TY: &str = r#"[{"start":"1.1.0.1.0.1.0.3.90","width":"0.0.0.0.0.0.0.0.1"}]"#;
    /// A content span in document `1.0.1.0.1`, for a link slot.
    const CONTENT: &str = r#"[{"start":"1.0.1.0.1.0.1.1","width":"0.0.0.0.0.0.0.5"}]"#;
    /// A `home` span at a document.
    const DOC: &str = r#"[{"start":"1.0.1.0.1","width":"0.0.0.0.1"}]"#;
    /// A `home` span at a version member of that document.
    const MEMBER: &str = r#"[{"start":"1.0.1.0.1.1","width":"0.0.0.0.0.1"}]"#;
    /// A `home` span at an account.
    const ACCOUNT: &str = r#"[{"start":"1.0.1","width":"0.0.1"}]"#;
    /// A `home` span at the node.
    const NODE: &str = r#"[{"start":"1","width":"1"}]"#;
    const REGION: &str = r#"[{"start":"1.1","width":"0.1"}]"#;

    /// Checks the class-scan test over the query's SHAPE, and the region
    /// test over the frame's document, with the reads that take no permit
    /// beside them.
    ///
    /// Every row is parsed through the codec rather than built by hand, so
    /// the test reads the frames a client sends. The three lists are
    /// disjoint; the class list is held to the three FTT ops and the region
    /// list to its five, restated, so an op moved between the arms fails its
    /// row where a list names it and a new op's row added without restating
    /// the count fails the last assertions.
    #[test]
    fn a_class_scan_is_a_shape_and_a_region_read_names_its_document() {
        /// The ops that have a class-scan shape, and the ops the per-document
        /// pool bounds, restated.
        const CLASS_OPS: usize = 3;
        const REGION_OPS: usize = 5;

        let class = [
            // `ty` alone: the class, at each of the three ops, `cur` and `n`
            // notwithstanding; `"empty"` is the same shape annihilated.
            ftt("find_links_ftt", ANY, ANY, ANY, TY),
            ftt("count_ftt", ANY, ANY, ANY, TY),
            format!(
                r#"{{"cur":null,"n":16,"op":"window_ftt","q":{{"from":"any","home":"any","to":"any","ty":{TY}}}}}"#
            ),
            ftt("find_links_ftt", ANY, ANY, ANY, EMPTY),
            // Nothing at all: the board.
            ftt("find_links_ftt", ANY, ANY, ANY, ANY),
            ftt("count_ftt", ANY, ANY, ANY, ANY),
            // A `home` at an account or the node: every home under it, the
            // other slots narrowing the survivors and never the walk.
            ftt("find_links_ftt", ACCOUNT, ANY, ANY, ANY),
            ftt("find_links_ftt", NODE, ANY, ANY, ANY),
            ftt("find_links_ftt", ACCOUNT, ANY, ANY, TY),
            ftt("count_ftt", NODE, CONTENT, ANY, ANY),
        ];
        let region = [
            format!(r#"{{"d":"1.0.1.0.1","op":"find_links_v","region":{REGION}}}"#),
            format!(r#"{{"d":"1.0.1.0.1","op":"count_v","region":{REGION}}}"#),
            format!(r#"{{"cur":null,"d":"1.0.1.0.1","n":16,"op":"window_v","region":{REGION}}}"#),
            format!(r#"{{"d":"1.0.1.0.1","op":"retrieve_endsets","region":{REGION}}}"#),
            r#"{"d":"1.0.1.0.1","op":"delete_orphans","p":{"subspace":"1","ordinal":"1"},"width":"1"}"#
                .to_string(),
        ];
        let unbounded = [
            // A `home` at a document or a member: one chain, whatever else
            // is constrained.
            ftt("find_links_ftt", DOC, ANY, ANY, ANY),
            ftt("find_links_ftt", MEMBER, ANY, ANY, ANY),
            ftt("find_links_ftt", DOC, ANY, ANY, TY),
            ftt("count_ftt", DOC, CONTENT, ANY, TY),
            // A link slot beside `ty`, or alone: the directory drives.
            ftt("find_links_ftt", ANY, CONTENT, ANY, TY),
            ftt("count_ftt", ANY, ANY, CONTENT, TY),
            ftt("find_links_ftt", ANY, CONTENT, ANY, ANY),
            ftt("find_links_ftt", ANY, CONTENT, CONTENT, ANY),
            // The zero in the home slot: unsatisfiable.
            ftt("find_links_ftt", EMPTY, ANY, ANY, TY),
            // The lineage pair and the edition claims: the index, not the
            // class.
            r#"{"op":"in_claims","y":"1.0.1.0.1.0.2.1","view":"default"}"#.to_string(),
            r#"{"op":"out_claims","x":"1.0.1.0.1.0.2.1","view":"default"}"#.to_string(),
            r#"{"op":"edition_claims","target":"1.0.1.0.1"}"#.to_string(),
            // M5's resolve and one `readlink`: no store walk.
            format!(r#"{{"d":"1.0.1.0.1","op":"image","region":{REGION}}}"#),
            r#"{"a":"1.0.1.0.1.0.2.1","d":"1.0.1.0.1","op":"project","slot":1}"#.to_string(),
            r#"{"a":"1.0.1.0.1.0.2.1","d":"1.0.1.0.1","op":"discoverable_from"}"#.to_string(),
            r#"{"op":"read_link","a":"1.0.1.0.1.0.2.1"}"#.to_string(),
            r#"{"op":"follow_link","a":"1.0.1.0.1.0.2.1","slot":1}"#.to_string(),
            // The M6 and M3 reads touch no link store at all.
            r#"{"op":"retrieve_v","specs":[{"doc":"1.0.1.0.1","span":{"start":"1.1","width":"0.1"}}]}"#
                .to_string(),
            r#"{"op":"show_deletions","d_a":"1.0.1.0.1","d_b":"1.0.1.0.2"}"#.to_string(),
            r#"{"op":"doc_metadata","doc":"1.0.1.0.1"}"#.to_string(),
            r#"{"op":"next_account_prefix","parent":"1"}"#.to_string(),
        ];
        let mut class_names = std::collections::BTreeSet::new();
        for frame in &class {
            let op = parse(frame);
            assert!(is_class_scan(&op), "a class-scan shape, so the class pool bounds it: {frame}");
            assert!(region_document(&op).is_none(), "and the per-document pool does not: {frame}");
            class_names.insert(skep_core::codec::op_name(op.kind()));
        }
        let mut region_names = std::collections::BTreeSet::new();
        for frame in &region {
            let op = parse(frame);
            assert!(!is_class_scan(&op), "a region read is no class scan: {frame}");
            let d = region_document(&op).unwrap_or_else(|| panic!("names its document: {frame}"));
            assert_eq!(d, &address("1.0.1.0.1"), "the key is the frame's `d`: {frame}");
            region_names.insert(skep_core::codec::op_name(op.kind()));
        }
        for frame in &unbounded {
            let op = parse(frame);
            assert!(!is_class_scan(&op), "takes no class permit: {frame}");
            assert!(region_document(&op).is_none(), "takes no region permit: {frame}");
        }
        assert_eq!(class_names.len(), CLASS_OPS, "the class shapes' ops: {class_names:?}");
        assert_eq!(region_names.len(), REGION_OPS, "the region reads' ops: {region_names:?}");
    }

    fn address(text: &str) -> Address {
        let comps = text.split('.').map(|c| skep_address::Nat::from(c.parse::<u64>().expect("a digit")));
        validate(Tumbler::new(comps).expect("nonempty")).expect("a valid address")
    }

    /// Checks the class pool's admission at both ends (wire v7.9).
    ///
    /// A class-scan shape takes one of the [`MAX_CONCURRENT_CLASS_SCANS`]
    /// permits and a read of no pool takes none, a drained pool refuses
    /// rather than queueing, and a released permit reopens its slot. The
    /// pool is per shape, so an unbounded read is admitted while it is
    /// drained — which is what keeps the bound off the reads that walk no
    /// whole class.
    #[test]
    fn the_class_pool_admission_takes_a_permit_only_for_a_class_scan_shape() {
        let bounded = parse(&ftt("count_ftt", ANY, ANY, ANY, ANY));
        let narrowed = parse(&ftt("count_ftt", DOC, ANY, ANY, TY));
        let unbounded = parse(r#"{"op":"doc_metadata","doc":"1.0.1.0.1"}"#);
        let scans = ClassScans::new();
        for op in [&unbounded, &narrowed] {
            assert!(
                scans.admit(op).expect("an unbounded read is admitted").is_none(),
                "…and spends no permit"
            );
        }
        let held: Vec<_> = (0..MAX_CONCURRENT_CLASS_SCANS)
            .map(|_| scans.admit(&bounded).expect("a permit").expect("a class scan takes one"))
            .collect();
        assert_eq!(
            scans.admit(&bounded).err(),
            Some(ScanBusy::Class),
            "a drained pool refuses, by the class pool; it never queues"
        );
        for op in [&unbounded, &narrowed] {
            assert!(
                scans.admit(op).expect("an unbounded read is admitted").is_none(),
                "a drained pool does not reach the reads it does not bound"
            );
        }
        drop(held);
        assert!(
            scans.admit(&bounded).expect("a released permit reopens its slot").is_some(),
            "and the reopened slot is a permit, not an admission with none"
        );
    }

    /// Checks the per-document pool (D3, D4): a document admits its width
    /// and refuses the read past it while another document is admitted; the
    /// ceiling refuses past [`MAX_CONCURRENT_REGION_READS`] across documents,
    /// and a read of a document at its width is refused by the width ahead
    /// of the ceiling; the two pools are disjoint; and the table holds an
    /// entry per document holding a permit and nothing once they are
    /// returned, whatever was refused.
    #[test]
    fn the_per_document_pool_admits_a_width_per_document_inside_the_ceiling() {
        let scans = ClassScans::new();
        let read = |d: &str| parse(&format!(r#"{{"d":"{d}","op":"find_links_v","region":{REGION}}}"#));
        let (a, b, c, e) = (address("1.0.1.0.1"), address("1.0.1.0.2"), address("1.0.1.0.3"), address("1.0.1.0.4"));

        // A's width, then A refused while B is admitted.
        let a1 = scans.take_region(&a).expect("A's first");
        let a2 = scans.take_region(&a).expect("A's second");
        assert_eq!(scans.take_region(&a).err(), Some(ScanBusy::Document), "A holds its width");
        assert_eq!(
            scans.admit(&read("1.0.1.0.1")).err(),
            Some(ScanBusy::Document),
            "a wire read of A is refused, by its width"
        );
        let b1 = scans.admit(&read("1.0.1.0.2")).expect("B is admitted").expect("with a permit");
        assert_eq!(scans.documents_held(), 2, "an entry per document holding a permit");

        // The ceiling: six across three documents, the seventh refused by the
        // ceiling — and a document at its width by its width, first.
        let b2 = scans.take_region(&b).expect("B's second");
        let c1 = scans.take_region(&c).expect("C's first");
        let c2 = scans.take_region(&c).expect("C's second");
        assert_eq!(
            scans.take_region(&e).err(),
            Some(ScanBusy::Ceiling),
            "the board holds its ceiling"
        );
        assert_eq!(
            scans.take_region(&a).err(),
            Some(ScanBusy::Document),
            "the width is judged first"
        );
        assert_eq!(scans.documents_held(), 3, "a refused read leaves no entry");

        // Disjoint: every region permit held, the class pool is whole; and
        // every class permit held, a region read is admitted.
        let class: Vec<_> = (0..MAX_CONCURRENT_CLASS_SCANS)
            .map(|_| scans.try_hold().expect("a class permit with every region permit held"))
            .collect();
        drop(c2);
        let c3 = scans.take_region(&c).expect("C's returned slot, with every class permit held");
        drop(class);

        // Returned permits free the width, the ceiling and the table.
        drop(a1);
        let _ = scans.take_region(&a).expect("A's returned slot");
        drop((a2, b1, b2, c1, c3));
        assert_eq!(scans.documents_held(), 0, "no permit held, no entry");
        assert_eq!(scans.ceiling.try_acquire().map(|_| ()), Some(()), "the ceiling is whole again");
    }
}
