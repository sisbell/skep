//! The class-scan bound: the class pool and the per-document pool.
//!
//! The items are `MAX_CONCURRENT_CLASS_SCANS`, `MAX_REGION_READS_PER_DOCUMENT`,
//! `MAX_CONCURRENT_REGION_READS`, `REGION_READ_WAIT`,
//! `MAX_REGION_READ_WAITERS`, `ClassScans`, `ScanPermit`, `RegionPermit`,
//! `ScanBusy`, `is_class_scan` and `region_document`.

use std::collections::BTreeMap;
use std::fmt;
use std::time::{Duration, Instant};

use parking_lot::{Condvar, Mutex};
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
/// The sum of this pool, the per-document pool's ceiling and its waiting
/// slots ([`MAX_REGION_READ_WAITERS`]), and the other four — the
/// reconstruction, fetch, upload and write pools — must leave a worker free:
/// [`MIN_WORKERS`](super::MIN_WORKERS) holds that relation, and an assertion
/// beside it holds the shipped default to it.
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
///
/// A read that finds its document at this width waits for one of the
/// document's permits, [`REGION_READ_WAIT`] at most, before it is refused
/// (the home-index record's D3 (b)).
pub(super) const MAX_REGION_READS_PER_DOCUMENT: usize = 2;

/// The ceiling on region reads admitted at once across every document (D3,
/// D4).
///
/// Per-document pools multiply with the documents read at once, and a pool
/// per document with no ceiling would let a stranger reading many pages
/// hold every worker inside a bound. So the per-document widths sit inside
/// ONE ceiling: a region read takes a slot of its document's width AND a
/// slot of this ceiling, and the ceiling and the waiting slots
/// ([`MAX_REGION_READ_WAITERS`]) are the terms
/// [`MIN_WORKERS`](super::MIN_WORKERS) counts, not the widths. Six: three
/// pages read two at a time, the shape a board of a few readers makes.
pub(super) const MAX_CONCURRENT_REGION_READS: usize = 6;

/// How long a region read whose document holds its width waits for one of
/// that document's permits before it is refused: two milliseconds (the
/// home-index record's D3 (b)).
///
/// A page's permits turn over at the pace of its answers, so a read that
/// meets the width of a lightly loaded page is one a returning permit admits
/// almost at once. The spike S43 measured a board's reading pane — four
/// readers of one page, two of them refused in nearly every trial — and a
/// permit came free for each refused read within about a quarter of a
/// millisecond at the 99th percentile, a holder's whole answer taking about
/// one. Two milliseconds, the top of the ruling's one or two, covers such an
/// answer twice over. A flooded page's permits come free only as its
/// answers end — about 28 ms at ten thousand links — so a read of one is
/// still refused, after the wait, as before it; a wait long enough to admit
/// it would hold the worker for a flooded page's whole answer, a queue in
/// all but name.
///
/// The wait holds the read's worker and no lock: the read parks on the
/// pool's condition variable, woken as any region permit returns, and takes
/// a slot the moment its own document has one. The class pool and the
/// ceiling refuse at once: the measurements behind the wait are a page's
/// own readers', and neither pool is a page's — a class-scan permit comes
/// free only as a world-sized answer ends, and the ceiling binds a reader of
/// many pages, the case it exists to refuse.
pub(super) const REGION_READ_WAIT: Duration = Duration::from_millis(2);

/// The most region reads waiting at once, across the board: two (the
/// home-index record's D3 (b)).
///
/// A waiting read holds its worker for the wait, so the waiters are a term
/// of the worker budget beside the pools' permits, and
/// [`MIN_WORKERS`](super::MIN_WORKERS) counts them. One count for the board
/// and never one per page: a cap per page would multiply with the pages read
/// at once, as the widths would without their ceiling. Two, a page's width
/// again: the measured four readers of one page are two holding its permits
/// and two waiting. A read that finds both waiting slots taken — by readers
/// of any page — is refused at once, as every read past its width was before
/// the wait. Outside the ceiling: a waiter holds no permit, so the ceiling's
/// six admitted reads and the two waiters stand together, each on a worker.
pub(super) const MAX_REGION_READ_WAITERS: usize = 2;

/// The class-scan bound, whole (wire v7.9; PUB-8.36, PUB-8.37; D3).
///
/// It holds what counts as a class scan ([`is_class_scan`]), which reads
/// draw on the per-document pool ([`region_document`]), how many of each run
/// at once ([`MAX_CONCURRENT_CLASS_SCANS`], [`MAX_REGION_READS_PER_DOCUMENT`]
/// inside [`MAX_CONCURRENT_REGION_READS`]), how long a region read at its
/// document's width waits and how many wait at once ([`REGION_READ_WAIT`],
/// [`MAX_REGION_READ_WAITERS`]), and the permit that spans one answer. One
/// card, as [`crate::history::History`] is for the reconstruction budget, so
/// the shape test and the pools it gates cannot drift apart and a later meter
/// has a whole thing to copy rather than pieces on [`Daemon`](super::Daemon).
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
///
/// One wait, the per-document pool's (the home-index record's D3 (b)): a
/// region read whose document holds its width waits, [`REGION_READ_WAIT`] at
/// most and in one of [`MAX_REGION_READ_WAITERS`] waiting slots, for one of
/// that document's permits to return — parked on `freed`, which every
/// returned region permit notifies — and is admitted the moment one does; a
/// read still at its document's width when the wait ends, or one finding
/// every waiting slot taken, is refused as before. A bound and never a
/// queue: no order is kept among the waiters, and a waiter woken by another
/// page's permit re-checks its own page and waits on. The class pool and the
/// ceiling refuse at once.
pub(super) struct ClassScans {
    /// The class pool: a slot per class scan in flight.
    scans: Permits,
    /// The per-document pool's ceiling: a slot per region read in flight,
    /// whatever its document.
    ceiling: Permits,
    /// The per-document pool's widths and its waiters, under one lock that
    /// every take and every return of a ceiling slot holds too.
    region: Mutex<RegionTable>,
    /// Notified as a region permit returns where a read waits: the waiters'
    /// one wake, each re-checking its own document.
    freed: Condvar,
    edge: EdgeTracker,
}

/// The per-document pool's state under its one lock: each document's region
/// reads in flight, and the reads waiting at their document's width.
struct RegionTable {
    /// Each document holding a region read, with how many it holds. An entry
    /// lives exactly while a permit of its document does, and every permit
    /// holds a slot of the ceiling, so the table holds at most
    /// [`MAX_CONCURRENT_REGION_READS`] entries, whatever a stranger names.
    by_document: BTreeMap<Address, usize>,
    /// The reads waiting at their document's width, across the board: at
    /// most [`MAX_REGION_READ_WAITERS`].
    waiting: usize,
}

impl RegionTable {
    /// Returns the region reads of `d` in flight.
    fn held(&self, d: &Address) -> usize {
        self.by_document.get(d).copied().unwrap_or(0)
    }
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
    /// The read's document holds its [`MAX_REGION_READS_PER_DOCUMENT`]
    /// region reads: still when the read's wait ([`REGION_READ_WAIT`]) ended,
    /// or already when the read arrived to find every waiting slot
    /// ([`MAX_REGION_READ_WAITERS`]) taken. The page's own readers contend.
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
        let mut table = self.pool.region.lock();
        if let Some(held) = table.by_document.get_mut(&self.document) {
            *held -= 1;
            if *held == 0 {
                table.by_document.remove(&self.document);
            }
        }
        // The ceiling's slot returns under the same lock as the width's
        // count, so an admission — which takes the lock, then the ceiling —
        // never sees one returned and not the other.
        drop(self.ceiling.take());
        // A waiter counts itself under this lock and gives the lock up only
        // inside its wait, so one counted before this drop took the lock is
        // parked by now and hears the notice, and one counting itself after
        // reads the returned slot before it waits. Every waiter is woken,
        // each re-checking its own document: the slot may be another page's.
        let wake = table.waiting > 0;
        drop(table);
        if wake {
            self.pool.freed.notify_all();
        }
    }
}

impl ClassScans {
    pub(super) fn new() -> ClassScans {
        ClassScans {
            scans: Permits::new(MAX_CONCURRENT_CLASS_SCANS),
            ceiling: Permits::new(MAX_CONCURRENT_REGION_READS),
            region: Mutex::new(RegionTable { by_document: BTreeMap::new(), waiting: 0 }),
            freed: Condvar::new(),
            edge: EdgeTracker::new(EDGE_HOLD_DOWN),
        }
    }

    /// Admits one read, with a permit where the read is bounded.
    ///
    /// A class-scan-shaped read ([`is_class_scan`]) takes one of the
    /// [`MAX_CONCURRENT_CLASS_SCANS`] permits for the whole answer; a region
    /// read ([`region_document`]) takes one of its document's
    /// [`MAX_REGION_READS_PER_DOCUMENT`] inside the board's
    /// [`MAX_CONCURRENT_REGION_READS`], waiting [`REGION_READ_WAIT`] at most
    /// for one where its document holds its width; any other read is
    /// admitted with no permit (`Ok(None)`).
    ///
    /// Taken before the read consult and the store call, both of which run
    /// inside M10's `execute`: a refused request has cost the parse, the
    /// session read and, at its document's width, at most the wait; and an
    /// admitted one that M10 then withholds or rejects — never reaching M7 —
    /// still returns its permit by the guard. A waiting read holds its worker
    /// and, while it is parked, no lock, the pool's own given up for the wait.
    /// Both pools are the board's: the guest and the claimant draw on them
    /// alike, and which class is scanned is not consulted. Which pool the
    /// request draws on, if any, is the one thing decided here; what it
    /// answers stays the stores' — an admitted read's answer is byte-for-byte
    /// the unbounded one.
    ///
    /// **The edge pair's one site** (m12). A bounded read's refusal or
    /// admission, by either pool, is told to the tracker at the edge clock's
    /// instant — a waiting read's once its wait has ended — and the edge it
    /// answers queued for the daemon's door; a read that takes no permit
    /// crosses none, and neither do the test hooks below, which hold a pool
    /// and not a request.
    ///
    /// # Errors
    ///
    /// [`ScanBusy`] where the pool the read draws on has no slot for it — a
    /// retry-class refusal, and never a queue:
    ///
    /// 1. [`ScanBusy::Class`] at once, for a class scan past its pool;
    /// 2. [`ScanBusy::Document`] for a region read whose document holds its
    ///    width: at once where every waiting slot is taken, and otherwise
    ///    when its wait ends with the width still held;
    /// 3. [`ScanBusy::Ceiling`] at once, for a region read its document
    ///    admits on a board that holds its ceiling.
    pub(super) fn admit(&self, op: &Op) -> Result<Option<ScanPermit<'_>>, ScanBusy> {
        let taken = if is_class_scan(op) {
            self.scans.try_acquire().map(ScanPermit::Class).ok_or(ScanBusy::Class)
        } else if let Some(d) = region_document(op) {
            self.take_region(d, REGION_READ_WAIT).map(ScanPermit::Region)
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
    ///
    /// Where `d` holds its width, the read waits for one of `d`'s permits —
    /// `wait` at most, in one of the [`MAX_REGION_READ_WAITERS`] waiting
    /// slots — parked on `freed` with the table's lock given up, and woken as
    /// any region permit returns. It re-checks `d` at every wake, so a permit
    /// of another page wakes it only to wait on, and no order is kept among
    /// the waiters: whichever takes the lock first takes the slot. A `wait`
    /// of zero never waits — the test hook's, which holds a pool and not a
    /// request.
    ///
    /// # Errors
    ///
    /// In order:
    ///
    /// 1. [`ScanBusy::Document`] at once where `d` holds its width and the
    ///    read may not wait: `wait` is zero, or every waiting slot is taken;
    /// 2. [`ScanBusy::Document`] where `d` still holds its width when the
    ///    wait ends;
    /// 3. [`ScanBusy::Ceiling`] at once where `d` has room and the board
    ///    holds its ceiling, which is never waited for.
    fn take_region(&self, d: &Address, wait: Duration) -> Result<RegionPermit<'_>, ScanBusy> {
        let mut table = self.region.lock();
        if table.held(d) >= MAX_REGION_READS_PER_DOCUMENT {
            if wait.is_zero() || table.waiting >= MAX_REGION_READ_WAITERS {
                return Err(ScanBusy::Document);
            }
            table.waiting += 1;
            let began = Instant::now();
            while table.held(d) >= MAX_REGION_READS_PER_DOCUMENT {
                let left = wait.saturating_sub(began.elapsed());
                if left.is_zero() || self.freed.wait_for(&mut table, left).timed_out() {
                    break;
                }
            }
            table.waiting -= 1;
            if table.held(d) >= MAX_REGION_READS_PER_DOCUMENT {
                return Err(ScanBusy::Document);
            }
        }
        let ceiling = self.ceiling.try_acquire().ok_or(ScanBusy::Ceiling)?;
        *table.by_document.entry(d.clone()).or_insert(0) += 1;
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
    /// It answers `None` at once where a read would wait for its document's
    /// width: a hook holds a pool and not a request, so it takes no waiting
    /// slot.
    ///
    /// **Test hook**, reached through `Daemon::try_hold_region_permit`.
    #[cfg(any(test, feature = "test-hooks"))]
    #[must_use = "a permit dropped at once holds nothing"]
    pub(super) fn try_hold_region(&self, d: &Address) -> Option<RegionPermit<'_>> {
        self.take_region(d, Duration::ZERO).ok()
    }

    /// The documents holding a region read: the table's size.
    #[cfg(test)]
    fn documents_held(&self) -> usize {
        self.region.lock().by_document.len()
    }

    /// The reads waiting at their document's width.
    #[cfg(test)]
    fn waiting(&self) -> usize {
        self.region.lock().waiting
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
///   each admitted home's chain read as one key range, or stabbed within
///   the home on the cheapest link slot where one is constrained beside.
///   The home slot drives wherever it is constrained, so
///   this shape walks every home under the account or the board whatever
///   its other slots hold: a `ty` or a `from` beside it narrows each home's
///   read to its hits on that slot, never the homes walked. The one place a slot's
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
/// a predicate test per candidate home and one `stab_in_slots` per admitted
/// home, over the spans and the parts of the stab that named it, the window
/// no further than the home that fills its `n` — `count_v_by_home` — the
/// same walk, a `contains` over the frame's `except` list and a predicate
/// test per candidate home and one `count_in_slots` per admitted home it
/// does not name, the stab's probes and sort with no lift, the walk no
/// further than the home whose count brings the sum to its `n`, so it costs
/// the homes ahead of its budget and never a flooded page's whole
/// population — `find_links_v_history` — the same walk over the AUDIT slice,
/// a predicate test per candidate home and one `stab_in_slots` under the
/// audit view per admitted home, the home's audit hits, a population that
/// only grows since a retraction removes nothing from it, the window no
/// further than the home that fills its `n`, and per row answered one lookup
/// of M7's retractions hint and two `minted_at` lookups of M3's position
/// map, no home named for them — and `delete_orphans` — the
/// same over the deleted and the retained runs, six pairs in one walk and
/// two `stab_in_slots` per admitted home, one a side, and no owner gate, so
/// every asker reaches it on any registered document. Each costs
/// the homes touching one document's spans and their readable links: a
/// flooded PUBLIC page still costs its population, which satisfies the
/// request, so the read is sized by the page the frame names (`d`), and the
/// bound is keyed by it — the count by home's budget bounds its share of
/// that population, the retracted-links read's window bounds its share of
/// the audit population, and each one's directory walk is still the page's.
///
/// **Every other link read takes no permit**, each absence a fact about the
/// read rather than a judgement:
///
/// * the FTT family's other shapes — a `home` naming a document or a version
///   member, whatever else is constrained, reads that home's links alone
///   (`homes_under` at one seek, then `homed_in` over one key range, or
///   `match_links_in`, the stab within the home on the cheapest link slot,
///   where one is constrained beside); a `from` or
///   a `to` constrained, with or without `ty`, drives from the directory of
///   homes with a filing in the span's blocks, the constraint with the
///   fewest candidate homes driving (`fewest_homes`, a bounded walk of
///   directory entries) and the rest tested per survivor — the request's
///   spans size each, never the class or the board. The wire's sentence
///   holds of the build: a query constraining a second slot is no class
///   scan;
/// * `in_claims`, `out_claims` — one `homes_touching` at the key's own span
///   on the claim's slot, a predicate test per candidate home and one
///   `stab_typed_in` per admitted home, cut to the supersession class: a step
///   per claim naming the key in a home the reader may read, no walk of the
///   class and none of the store;
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
/// pool: `d` of `find_links_v`, `count_v`, `window_v`, `count_v_by_home`,
/// `find_links_v_history`, `retrieve_endsets` and `delete_orphans`; `None`
/// for every other op.
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
        | Op::CountVByHome { d, .. }
        | Op::FindLinksVHistory { d, .. }
        | Op::RetrieveEndsets { d, .. }
        | Op::DeleteOrphans { d, .. } => Some(d),
        _ => None,
    }
}

#[cfg(test)]
mod tests;
