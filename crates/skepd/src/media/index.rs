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
//! THE READINESS ([`CellIndex::is_ready`]) flips when that walk completes,
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
//! guard, the gate reads under the credential lock's read arm, the pruner
//! under its write arm, the walk under neither — so the index sits behind
//! a `parking_lot::RwLock` taken innermost and held across no other lock.
//! The cheap PREFIX TEST ([`names_kind_by_prefix`]) stands before every
//! parse, so a walk over a prose board's million one-byte values costs a
//! byte compare apiece and a parse for the cells alone.

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
use skep_content::HasContent;
use skep_engine::{Engine, World};
use skep_kernel::Snapshot;
use skep_namespace::{HasM3, PrincipalId};

use super::cell::{self, Cell};
use super::gate::{hex_of, DESIGNATION};
use crate::notice;

/// A hash as every sidecar keys it: its function's designation and its hex.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct HashKey {
    pub designation: String,
    pub hex: String,
}

impl HashKey {
    fn of(cell: &Cell) -> HashKey {
        HashKey { designation: DESIGNATION.to_string(), hex: hex_of(&cell.hash) }
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
pub(crate) struct HaltMark {
    pub at: Address,
    /// The kind the value names.
    pub kind: String,
    /// The schema fault, as the door's token spells it.
    pub fault: String,
}

/// The entries, behind the index's lock.
#[derive(Default)]
struct Entries {
    /// Per hash, the cells naming it — the pruner's reference test.
    by_hash: BTreeMap<HashKey, BTreeSet<Tumbler>>,
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
/// the gate admits") read off the daemon rather than guessed.
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
pub(crate) struct CellIndex {
    entries: RwLock<Entries>,
    ready: AtomicBool,
    rebuild: Mutex<Option<Rebuild>>,
}

/// What the one entry path did with a value past the prefix test.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Entered {
    Cell,
    Halt,
    Nothing,
}

impl CellIndex {
    /// An empty index, NOT READY: the walk makes it ready.
    pub(crate) fn new() -> CellIndex {
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
    pub(crate) fn rebuild_report(&self) -> Option<Rebuild> {
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
    pub(crate) fn halt(&self, at: &Address, fault: &str) -> bool {
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
    /// test, whose null is a permission.
    pub(crate) fn referenced(&self, designation: &str, hex: &str) -> bool {
        self.entries.read().by_hash.contains_key(&HashKey::named(designation, hex))
    }

    /// THE BASE of `owner`'s account: the sum of its distinct hashes' sizes.
    pub(crate) fn base(&self, owner: PrincipalId) -> u64 {
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
    pub(crate) fn counts(&self) -> (usize, usize, usize) {
        let e = self.entries.read();
        (e.cells.len(), e.by_hash.len(), e.halts.len())
    }

    /// THE ONE ENTRY PATH for a value past the prefix test, at `at` in
    /// `world`: the one parser's verdict — a cell is entered under ω of the
    /// cell's document (M3's one walk, read once per cell); a value naming
    /// the kind under no schema is entered as a halt mark; a value the
    /// parser reads as no cell of the kind — past the cap, malformed past
    /// the prefix — is nothing, as it is to the door.
    pub(crate) fn enter_value(&self, world: &World, at: &Address, bytes: &[u8]) -> Entered {
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
    pub(crate) fn enter_insert(&self, world: &World, start: &Address, naming: &[usize]) {
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
    pub(crate) fn enter_publish(&self, world: &World, member: &Address, reinserted: u64) {
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

/// THE CHEAP PREFIX TEST, ahead of every parse: past leading JSON
/// whitespace, the bytes open `{"type":"<the kind's address>"` — the
/// canonical spelling every pinned schema puts first (D13: one JSON object
/// naming its kind), so a value that names the kind in that form costs a
/// parse and every other value a byte compare. A value naming the kind in
/// a spelling no canonical schema produces — the member reordered, a space
/// inside the object — is read as no cell here, as the door refuses it.
pub(crate) fn names_kind_by_prefix(bytes: &[u8]) -> bool {
    let start = bytes
        .iter()
        .position(|b| !matches!(b, b' ' | b'\t' | b'\n' | b'\r'))
        .unwrap_or(bytes.len());
    let Some(rest) = bytes[start..].strip_prefix(b"{\"type\":\"") else { return false };
    let kind = cell::KIND.as_bytes();
    rest.len() > kind.len() && rest.starts_with(kind) && rest[kind.len()] == b'"'
}

/// THE WALK AT OPEN: every value of the world `snapshot` holds, through the
/// prefix test and then the one entry path, into `index` — the one copy
/// the commits since the open enter their own into. Reads an immutable
/// snapshot, so commits proceed on later roots while it walks.
pub(crate) fn walk(snapshot: &Snapshot<World>, index: &CellIndex) -> Rebuild {
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

/// START THE WALK on a thread of its own over the world as `engine` holds it
/// now, completing `index` when it is done. Where the OS refuses the
/// thread the walk runs here instead: the daemon then serves later rather
/// than never readying (P22 — a derived structure's loss is a slower
/// answer, not an outage).
pub(crate) fn start_walk(engine: &Engine, index: Arc<CellIndex>) {
    let snapshot = engine.kernel().snapshot();
    let shared = Arc::clone(&index);
    let spawned = thread::Builder::new().name("skepd-cell-index".into()).spawn(move || {
        let report = walk(&snapshot, &shared);
        shared.complete(report);
    });
    if spawned.is_err() {
        notice::line("cell index: the OS refused the rebuild's thread; the walk runs at open");
        let snapshot = engine.kernel().snapshot();
        let report = walk(&snapshot, &index);
        index.complete(report);
    }
}

/// TEST SEAM: a hold on the walk, armed before a daemon opens, so a suite
/// can serve requests against a daemon whose index is not ready and release
/// the walk at its own moment.
#[cfg(any(test, feature = "test-hooks"))]
pub(crate) struct WalkHold {
    held: Mutex<bool>,
    released: Condvar,
}

#[cfg(any(test, feature = "test-hooks"))]
pub(crate) static WALK_HOLD: WalkHold =
    WalkHold { held: Mutex::new(false), released: Condvar::new() };

#[cfg(any(test, feature = "test-hooks"))]
impl WalkHold {
    /// Arm: every walk started from here on parks before its first entry.
    pub(crate) fn hold(&self) {
        *self.held.lock() = true;
    }

    /// Release: every parked walk proceeds, and later walks never park.
    pub(crate) fn release(&self) {
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

    const HASH: &str = "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262";

    fn addr(s: &str) -> Address {
        crate::codec::wire_address(s).expect("a test address")
    }

    /// The prefix test admits the canonical opening — past JSON whitespace —
    /// and refuses prose, another kind, a longer address sharing the kind's
    /// digits, and a value naming the kind in a spelling no schema produces.
    #[test]
    fn the_prefix_test_reads_the_canonical_opening_alone() {
        let canonical = format!(r#"{{"type":"{}","hash":"{HASH}","size":5}}"#, cell::KIND);
        assert!(names_kind_by_prefix(canonical.as_bytes()));
        assert!(names_kind_by_prefix(format!(" \n{canonical}").as_bytes()));
        assert!(names_kind_by_prefix(format!(r#"{{"type":"{}","hash_alg":"x"}}"#, cell::KIND).as_bytes()), "a second schema's form");
        assert!(!names_kind_by_prefix(b"prose"));
        assert!(!names_kind_by_prefix(b"{\"type\":\"1.1.0.1.0.1.0.3.1\"}"), "another kind");
        assert!(!names_kind_by_prefix(format!(r#"{{"type":"{}1"}}"#, cell::KIND).as_bytes()), "a longer address");
        assert!(!names_kind_by_prefix(format!(r#"{{ "type":"{}"}}"#, cell::KIND).as_bytes()), "a space inside");
        assert!(!names_kind_by_prefix(b""));
        assert!(!names_kind_by_prefix(b"   "));
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
        let hex = hex_of(&hash);
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
        assert!(index.referenced(DESIGNATION, &hex_of(&other.hash)));
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
        index.complete(Rebuild { values: 0, cells: 0, halts: 0, walk: Duration::ZERO, parse: Duration::ZERO });
        assert!(index.is_ready());
        assert_eq!(index.rebuild_report().map(|r| r.values), Some(0));
    }
}
