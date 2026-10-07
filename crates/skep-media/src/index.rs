//! THE CELL INDEX (`media.md` Op inventory 1 — "ONE DERIVED INDEX SERVES THE
//! BASE AND THE PRUNER's REFERENCE TEST BOTH … held by skepd IN MEMORY … ON
//! PATTERNS P22's RECOMPUTE ARM"; the register M-I5 (b), M-I6 (a); the
//! rulings ms5-R and ms5-T4): per hash, the cells naming it; per account,
//! the DISTINCT hashes its cells name at their size — the BASE, one number
//! derived from the record and nothing else (M-I6 (a)). Two writers and
//! three readers. ENTERED AT EVERY COMMIT THAT MINTS A CELL, whichever op
//! minted it — an `insert`'s values, a shot's re-inserted values — before
//! that commit's serialization guard drops ([`CellIndex::enter_insert`],
//! [`CellIndex::enter_publish`], the write path's one hook). REBUILT WHOLE
//! AT EVERY OPEN from the world replayed there and never from the retained
//! journal alone: a thread walks an immutable snapshot of the content store
//! ([`walk`]) while every other request is served, adding every cell it
//! finds INTO THE ONE COPY the commits since the open have entered their
//! own into, never installing a copy in its place — THE COMPOSITION CLAUSE,
//! which holds by construction because an entry is IDEMPOTENT PER CELL
//! ADDRESS: a cell is permanent, so an entry made twice is made once.
//! THE READINESS (`CellIndex::is_ready`) flips when that walk completes,
//! and until then the index's three readers alone — the PUT's creation and
//! resume, the pruner's pass, the deposit read's base — refuse with one
//! retry-class token (ms5-R, the narrow reading: every other request is
//! served throughout, the door's binding reading the lease arm alone).
//!
//! THE HALT MARK (DOCTRINE D13's carve-out, ms5-T4): a value naming the
//! cell's kind that parses under no schema this build pins is entered as a
//! halt mark — its address and the fault — and counts in no base; while
//! one stands the pruner halts its unlink pass, naming it, and never reads
//! the value as absent, since at the pruner absence is a permission. The
//! door refuses such a value at its own insert, so a halt mark is reachable
//! only from a board another build wrote.
//!
//! THE LOCK IS THE INDEX's OWN: the commit enters under the serialization
//! guard, the media gate reads under the credential lock's read arm, the
//! pruner under its write arm, the walk under neither — so the index sits
//! behind a `parking_lot::RwLock` taken innermost and held across no other
//! lock.
//! The cheap PREFIX TEST (`cell::names_kind_by_prefix`, the picture kind's
//! canonical opening) stands before every parse, so a walk over a prose
//! board's million one-byte values costs a byte compare apiece and a parse
//! for the cells alone.
//!
//! THE INVENTORY's READS ([`CellIndex::references`], [`CellIndex::accounts`],
//! [`CellIndex::halts`]; `media.md` §Recovery, "THE OPERATOR CAN LIST THE
//! HOLES"): the operator's tool walks a copy's world into a fresh index
//! through the same [`walk`] and reads it whole — every reference with the
//! cells naming it and the size they name, every account's base, every halt
//! mark — recording nothing (D9).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

#[cfg(any(test, feature = "test-hooks"))]
use parking_lot::Condvar;
use parking_lot::{Mutex, RwLock};
use skep_address::{
    content_subspace, document_of, elem_addr, ordinal, shift, validate, Address, ElemPos, Nat,
    Tumbler,
};
use skep_arrangement::{trunk_of, MAX_REINSERTED_VALUES};
use skep_febe::FebeWorld;
use skep_kernel::{Kernel, Snapshot};
use skep_namespace::PrincipalId;
use skep_util::json::hex_string;
use skep_util::notice;

use crate::cell::{self, names_kind_by_prefix, Cell, DESIGNATION};

/// A hash as every sidecar keys it: its function's designation and its hex.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct HashKey {
    designation: String,
    hex: String,
}

impl HashKey {
    fn of(cell: &Cell) -> HashKey {
        HashKey { designation: DESIGNATION.to_string(), hex: hex_string(&cell.hash) }
    }

    fn named(designation: &str, hex: &str) -> HashKey {
        HashKey { designation: designation.to_string(), hex: hex.to_string() }
    }
}

/// One account's side of the index: the distinct hashes its cells name,
/// each at the size counted for it, and their sum, THE BASE.
#[derive(Default)]
struct Account {
    hashes: BTreeMap<HashKey, u64>,
    base: u64,
}

/// A HALT MARK: a value at `at` naming the kind under no pinned schema.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HaltMark {
    /// The value's address.
    pub at: Address,
    /// The kind the value names.
    pub kind: String,
    /// The schema fault, as the door's token spells it.
    pub fault: String,
}

/// One REFERENCE as the inventory reads it: a hash, the cells naming it,
/// and the size they name it at — the largest any names, as the base
/// counts it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reference {
    /// The hash function's designation, as the sidecar key spells it.
    pub designation: String,
    /// The hash, 64 lowercase hex characters.
    pub hex: String,
    /// The size the cells name the hash at — the largest any names.
    pub size: u64,
    /// The cells naming the hash, by address, in address order.
    pub cells: Vec<Tumbler>,
}

/// The entries, behind the index's lock.
#[derive(Default)]
struct Entries {
    /// Per hash, the cells naming it — the pruner's reference test.
    by_hash: BTreeMap<HashKey, BTreeSet<Tumbler>>,
    /// Per hash, the largest size any cell names it at — the inventory's
    /// length test, kept for a cell under no seat too.
    sizes: BTreeMap<HashKey, u64>,
    /// Per account (the principal seated at it, ω of the cell's document),
    /// the hashes its cells name at their size — the base.
    by_account: BTreeMap<PrincipalId, Account>,
    /// The halt marks, by address.
    halts: BTreeMap<Tumbler, HaltMark>,
    /// Every cell address entered — the idempotency's set.
    cells: BTreeSet<Tumbler>,
}

/// THE REBUILD's REPORT: what the walk at open found and what it cost —
/// the record's measure (its §Costs: "the time from open to the first PUT
/// the gate [the media gate] admits") read off the daemon rather than
/// guessed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rebuild {
    /// The values the walk read — every value the world held at open.
    pub values: usize,
    /// The cells it entered.
    pub cells: usize,
    /// The halt marks it entered.
    pub halts: usize,
    /// The walk's whole duration, the parses included.
    pub walk: Duration,
    /// The time spent past the prefix test: the parses and the entries.
    pub parse: Duration,
}

/// The index.
pub struct CellIndex {
    entries: RwLock<Entries>,
    ready: AtomicBool,
    rebuild: Mutex<Option<Rebuild>>,
}

/// What the one entry path did with a value past the prefix test.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Entered {
    Cell,
    Halt,
    Nothing,
}

impl CellIndex {
    /// An empty index, NOT READY: the walk makes it ready.
    pub fn new() -> CellIndex {
        CellIndex {
            entries: RwLock::new(Entries::default()),
            ready: AtomicBool::new(false),
            rebuild: Mutex::new(None),
        }
    }

    /// Whether the walk at open has completed — what the three readers
    /// consult. Monotone: once ready, ready for the life of the process.
    pub(crate) fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }

    /// The walk's report, once it has completed — the open-cost measure's
    /// read, a suite's.
    #[cfg(any(test, feature = "test-hooks"))]
    #[doc(hidden)]
    pub fn rebuild_report(&self) -> Option<Rebuild> {
        self.rebuild.lock().clone()
    }

    /// THE WALK's COMPLETION: the report kept, the readiness flipped, the
    /// operator told. The walk's own door; a test readies an index it built
    /// by hand through it.
    pub(crate) fn complete(&self, report: Rebuild) {
        notice::line(format_args!(
            "cell index rebuilt at open: {} values walked, {} cells, {} halt marks, {:?} ({:?} past the prefix test)",
            report.values, report.cells, report.halts, report.walk, report.parse
        ));
        if let Some(mark) = self.first_halt() {
            notice::line(format_args!(
                "cell index: a value at {} names the kind {} under no schema this build reads ({}): the pruner's unlink pass halts while it stands",
                mark.at, mark.kind, mark.fault
            ));
        }
        *self.rebuild.lock() = Some(report);
        self.ready.store(true, Ordering::Release);
    }

    /// ENTER one cell at `at`, minted in a document `owner` is seated over
    /// (`None`: a document under no seat — counted in no base, named for the
    /// pruner all the same). IDEMPOTENT per address — the composition
    /// clause's premise: a cell is permanent, so a second entry of one
    /// address changes nothing. `true` where the entry was new.
    pub(crate) fn enter(&self, at: &Address, owner: Option<PrincipalId>, cell: &Cell) -> bool {
        let key = HashKey::of(cell);
        let mut entries = self.entries.write();
        if !entries.cells.insert(at.tumbler().clone()) {
            return false;
        }
        entries.by_hash.entry(key.clone()).or_default().insert(at.tumbler().clone());
        let named = entries.sizes.entry(key.clone()).or_insert(0);
        *named = (*named).max(cell.size);
        if let Some(owner) = owner {
            let account = entries.by_account.entry(owner).or_default();
            // One size per hash per account, order-independent — the LARGEST
            // its cells name — so the base is one number whatever order the
            // walk and the commits entered in (M-I6 (a)); cells disagreeing
            // on a hash's size are reachable only off a board another build
            // wrote, the door holding each to the file's length.
            let counted = account.hashes.entry(key).or_insert(0);
            if cell.size > *counted {
                account.base = account.base.saturating_sub(*counted).saturating_add(cell.size);
                *counted = cell.size;
            }
        }
        true
    }

    /// ENTER A HALT MARK at `at`. Idempotent per address. `true` where new.
    fn halt(&self, at: &Address, fault: &str) -> bool {
        let mut entries = self.entries.write();
        if entries.halts.contains_key(at.tumbler()) {
            return false;
        }
        entries.halts.insert(
            at.tumbler().clone(),
            HaltMark { at: at.clone(), kind: cell::KIND.to_string(), fault: fault.to_string() },
        );
        true
    }

    /// Whether `owner`'s OWN cells name `<designation>/<hex>` — the
    /// binding's index-first arm: a reference, kept by no lease.
    pub(crate) fn names(&self, owner: PrincipalId, designation: &str, hex: &str) -> bool {
        self.size_named(owner, designation, hex).is_some()
    }

    /// The size `owner`'s own cells name `<designation>/<hex>` at — the
    /// size its base counts the hash at — or `None` where none names it.
    pub(crate) fn size_named(&self, owner: PrincipalId, designation: &str, hex: &str) -> Option<u64> {
        self.entries
            .read()
            .by_account
            .get(&owner)
            .and_then(|a| a.hashes.get(&HashKey::named(designation, hex)).copied())
    }

    /// Whether ANY cell names `<designation>/<hex>` — the pruner's reference
    /// test, whose null is a permission; the pull's test of the file it is
    /// handed.
    pub fn referenced(&self, designation: &str, hex: &str) -> bool {
        self.entries.read().by_hash.contains_key(&HashKey::named(designation, hex))
    }

    /// THE BASE of `owner`'s account: the sum of its distinct hashes' sizes
    /// — the deposit read's first figure.
    pub fn base(&self, owner: PrincipalId) -> u64 {
        self.entries.read().by_account.get(&owner).map_or(0, |a| a.base)
    }

    /// Every account's base, summed — the venue total's record-derived
    /// half beside the pending bytes.
    pub(crate) fn total_base(&self) -> u64 {
        self.entries.read().by_account.values().fold(0u64, |acc, a| acc.saturating_add(a.base))
    }

    /// The first halt mark standing, by address — what the pruner halts on
    /// and names.
    pub(crate) fn first_halt(&self) -> Option<HaltMark> {
        self.entries.read().halts.values().next().cloned()
    }

    /// The counts: cells, distinct hashes, halt marks — a suite's read.
    #[cfg(any(test, feature = "test-hooks"))]
    #[doc(hidden)]
    pub fn counts(&self) -> (usize, usize, usize) {
        let e = self.entries.read();
        (e.cells.len(), e.by_hash.len(), e.halts.len())
    }

    /// EVERY REFERENCE — the inventory's read: per hash, the cells naming
    /// it and the size they name, in hash order.
    pub fn references(&self) -> Vec<Reference> {
        let e = self.entries.read();
        e.by_hash
            .iter()
            .map(|(key, cells)| Reference {
                designation: key.designation.clone(),
                hex: key.hex.clone(),
                size: e.sizes.get(key).copied().unwrap_or(0),
                cells: cells.iter().cloned().collect(),
            })
            .collect()
    }

    /// EVERY ACCOUNT's BASE — the inventory's read: the principal seated at
    /// the account and its base, in principal order.
    pub fn accounts(&self) -> Vec<(PrincipalId, u64)> {
        self.entries.read().by_account.iter().map(|(p, a)| (*p, a.base)).collect()
    }

    /// EVERY HALT MARK standing, by address — the inventory's read.
    pub fn halts(&self) -> Vec<HaltMark> {
        self.entries.read().halts.values().cloned().collect()
    }

    /// THE ONE ENTRY PATH for a value past the prefix test, at `at` in
    /// `world`: the one parser's verdict — a cell is entered under ω of the
    /// cell's document (M3's one walk, read once per cell); a value naming
    /// the kind under no schema is entered as a halt mark — a body past the
    /// cap that opens as the picture kind among them, since the cap bounds
    /// the parse and never the classification; a value the parser reads as
    /// no cell of the kind — malformed past the prefix, or past the cap and
    /// opening as no kind — is nothing, as it is to the door. Generic over
    /// the world M10 reads ([`FebeWorld`]), as every entry and the walk are:
    /// the daemon instantiates them at its `World`.
    fn enter_value<W: FebeWorld>(&self, world: &W, at: &Address, bytes: &[u8]) -> Entered {
        match cell::parse(bytes) {
            Ok(cell) => {
                let owner = document_of(at)
                    .and_then(|doc| world.m3().effective_owner_pair(&doc).map(|(_, id)| id));
                self.enter(at, owner, &cell);
                Entered::Cell
            }
            Err(refusal) if refusal.names_kind() => {
                self.halt(at, "unknown_cell_schema");
                Entered::Halt
            }
            Err(_) => Entered::Nothing,
        }
    }

    /// THE ENTRY AT AN `insert`'s COMMIT: the values the ack placed, read off
    /// the post-commit `world` at the addresses the commit minted — `start`
    /// (the ack's address, the first minted) and the next ones, I-adjacent
    /// under the named document's content chain — for the value indices
    /// `naming` the prefix test admitted ahead of the commit.
    pub fn enter_insert<W: FebeWorld>(&self, world: &W, start: &Address, naming: &[usize]) {
        let content = world.content();
        for &i in naming {
            let Ok(at) = validate(shift(start.tumbler(), &Nat::from(i as u64))) else { continue };
            if let Some(value) = content.value_at(at.tumbler()) {
                if names_kind_by_prefix(value.as_bytes()) {
                    self.enter_value(world, &at, value.as_bytes());
                }
            }
        }
    }

    /// THE ENTRY AT A SHOT's COMMIT: the `reinserted` values the shot minted
    /// as fresh identity under the trunk's content chain — the last
    /// `reinserted` addresses of that chain in the post-commit `world`,
    /// read off its frontier (M3's content mint, asked and not staged, is
    /// the chain's peek) — each put through the prefix test and the one
    /// entry path.
    pub fn enter_publish<W: FebeWorld>(&self, world: &W, member: &Address, reinserted: u64) {
        let trunk = trunk_of(member);
        let Ok((next, _)) = world.m3().mint_content(&trunk) else { return };
        let next_ordinal = ordinal(next.tumbler()).clone();
        let content = world.content();
        let bounded = reinserted.min(MAX_REINSERTED_VALUES as u64);
        for k in 1..=bounded {
            let back = Nat::from(k);
            if back >= next_ordinal {
                break;
            }
            let position = ElemPos {
                doc: trunk.clone(),
                subspace: content_subspace(),
                ordinal: &next_ordinal - back,
            };
            let Ok(at) = elem_addr(position) else { continue };
            if let Some(value) = content.value_at(at.tumbler()) {
                if names_kind_by_prefix(value.as_bytes()) {
                    self.enter_value(world, &at, value.as_bytes());
                }
            }
        }
    }
}

/// THE WALK AT OPEN: every value of the world `snapshot` holds, through the
/// prefix test and then the one entry path, into `index` — the one copy
/// the commits since the open enter their own into. Reads an immutable
/// snapshot, so commits proceed on later roots while it walks.
pub fn walk<W: FebeWorld>(snapshot: &Snapshot<W>, index: &CellIndex) -> Rebuild {
    #[cfg(any(test, feature = "test-hooks"))]
    WALK_HOLD.wait();
    let started = Instant::now();
    let world = snapshot.world();
    let (mut values, mut cells, mut halts) = (0usize, 0usize, 0usize);
    let mut parse = Duration::ZERO;
    for (tumbler, value) in world.content().iter() {
        values += 1;
        let bytes = value.as_bytes();
        if !names_kind_by_prefix(bytes) {
            continue;
        }
        let at_parse = Instant::now();
        // Every minted address is T4-valid; one that is not names nothing
        // this index reads.
        if let Ok(at) = validate(tumbler.clone()) {
            match index.enter_value(world, &at, bytes) {
                Entered::Cell => cells += 1,
                Entered::Halt => halts += 1,
                Entered::Nothing => {}
            }
        }
        parse += at_parse.elapsed();
    }
    Rebuild { values, cells, halts, walk: started.elapsed(), parse }
}

/// START THE WALK on a thread of its own over the world as `kernel` holds it
/// now — the daemon's engine's kernel, the one thing of the engine the walk
/// needs — completing `index` when it is done. Where the OS refuses the
/// thread the walk runs here instead: the daemon then serves later rather
/// than never readying (P22 — a derived structure's loss is a slower
/// answer, not an outage).
pub fn start_walk<W: FebeWorld>(kernel: &Kernel<W>, index: Arc<CellIndex>) {
    let snapshot = kernel.snapshot();
    let shared = Arc::clone(&index);
    let spawned = thread::Builder::new().name("skepd-cell-index".into()).spawn(move || {
        let report = walk(&snapshot, &shared);
        shared.complete(report);
    });
    if spawned.is_err() {
        notice::line("cell index: the OS refused the rebuild's thread; the walk runs at open");
        let snapshot = kernel.snapshot();
        let report = walk(&snapshot, &index);
        index.complete(report);
    }
}

/// TEST SEAM: a hold on the walk, armed before a daemon opens, so a suite
/// can serve requests against a daemon whose index is not ready and release
/// the walk at its own moment.
#[cfg(any(test, feature = "test-hooks"))]
#[doc(hidden)]
pub struct WalkHold {
    held: Mutex<bool>,
    released: Condvar,
}

/// The test seam's one hold on the walk — process-wide, since the walk
/// starts inside the open.
#[cfg(any(test, feature = "test-hooks"))]
#[doc(hidden)]
pub static WALK_HOLD: WalkHold = WalkHold { held: Mutex::new(false), released: Condvar::new() };

#[cfg(any(test, feature = "test-hooks"))]
impl WalkHold {
    /// Arm: every walk started from here on parks before its first entry.
    pub fn hold(&self) {
        *self.held.lock() = true;
    }

    /// Release: every parked walk proceeds, and later walks never park.
    pub fn release(&self) {
        *self.held.lock() = false;
        self.released.notify_all();
    }

    fn wait(&self) {
        let mut held = self.held.lock();
        while *held {
            self.released.wait(&mut held);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A test address from its dotted form, T4-validated.
    fn addr(s: &str) -> Address {
        let comps: Vec<Nat> = s.split('.').map(|c| Nat::from(c.parse::<u32>().unwrap())).collect();
        validate(Tumbler::new(comps).expect("a tumbler")).expect("a test address")
    }

    /// The two maps and the base: an entry is idempotent per address; two
    /// cells of one account over one hash count once; a second account's
    /// cell over the same hash counts in its own base; a halt mark counts
    /// in no base and is the first halt; readiness flips once.
    #[test]
    fn entries_are_idempotent_per_cell_and_the_base_counts_distinct_hashes_once() {
        let index = CellIndex::new();
        assert!(!index.is_ready());
        let hash = [7u8; 32];
        let cell = Cell { hash, size: 10 };
        let hex = hex_string(&hash);
        let (a, b) = (PrincipalId(1), PrincipalId(2));
        assert!(index.enter(&addr("1.0.1.0.2.0.1.1"), Some(a), &cell));
        assert!(!index.enter(&addr("1.0.1.0.2.0.1.1"), Some(a), &cell), "idempotent per address");
        assert!(index.enter(&addr("1.0.1.0.3.0.1.1"), Some(a), &cell), "a second cell of a's");
        assert_eq!(index.base(a), 10, "one hash, counted once");
        assert!(index.enter(&addr("1.0.2.0.1.0.1.1"), Some(b), &Cell { hash, size: 10 }));
        assert_eq!(index.base(b), 10);
        assert_eq!(index.total_base(), 20);
        assert!(index.names(a, DESIGNATION, &hex));
        assert!(index.names(b, DESIGNATION, &hex));
        assert!(!index.names(PrincipalId(3), DESIGNATION, &hex));
        assert!(index.referenced(DESIGNATION, &hex));
        assert!(!index.referenced("sha256-tree", &hex), "the designation is part of the key");
        assert_eq!(index.counts(), (3, 1, 0));
        // A cell under no seat: named for the pruner, counted for nobody.
        let other = Cell { hash: [9u8; 32], size: 4 };
        assert!(index.enter(&addr("1.0.9.0.1.0.1.1"), None, &other));
        assert!(index.referenced(DESIGNATION, &hex_string(&other.hash)));
        assert_eq!(index.total_base(), 20);
        // The larger size wins per hash per account, whatever the order.
        assert!(index.enter(&addr("1.0.1.0.4.0.1.1"), Some(a), &Cell { hash, size: 12 }));
        assert_eq!(index.base(a), 12);
        assert!(index.enter(&addr("1.0.1.0.5.0.1.1"), Some(a), &Cell { hash, size: 11 }));
        assert_eq!(index.base(a), 12);
        assert_eq!(index.first_halt(), None);
        assert!(index.halt(&addr("1.0.1.0.6.0.1.1"), "unknown_cell_schema"));
        assert!(!index.halt(&addr("1.0.1.0.6.0.1.1"), "unknown_cell_schema"));
        let mark = index.first_halt().expect("a halt mark");
        assert_eq!(mark.fault, "unknown_cell_schema");
        assert_eq!(mark.kind, cell::KIND);
        assert_eq!(index.counts(), (6, 2, 1));
        assert_eq!(index.total_base(), 22, "a halt mark counts in no base");
        // The inventory's reads: every reference at the largest size named,
        // its cells in address order; every account's base; the halt marks.
        let refs = index.references();
        assert_eq!(refs.len(), 2);
        assert_eq!((refs[0].hex.as_str(), refs[0].size, refs[0].cells.len()), (hex.as_str(), 12, 5));
        assert_eq!((refs[1].size, refs[1].cells.len()), (4, 1), "a cell under no seat: named, sized");
        assert_eq!(index.accounts(), vec![(a, 12), (b, 10)]);
        assert_eq!(index.halts().len(), 1);
        index.complete(Rebuild { values: 0, cells: 0, halts: 0, walk: Duration::ZERO, parse: Duration::ZERO });
        assert!(index.is_ready());
        assert_eq!(index.rebuild_report().map(|r| r.values), Some(0));
    }
}
