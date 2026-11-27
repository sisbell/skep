//! The cell index: per hash the cells naming it, per account the base.
//!
//! Its rules are `media.md` Op inventory 1 — "one derived index serves the
//! base and the pruner's reference test both … held by skepd in memory … on
//! PATTERNS P22's recompute arm" — and the register M-I5 (b), M-I6 (a). Per
//! hash it holds the cells naming it; per account, the distinct hashes its
//! cells name at their size — the base, one number derived from the record
//! and nothing else (M-I6 (a)). Two writers, and three readers beside the
//! door's binding and the pruner's pass. Entered at every commit that mints
//! a cell, whichever op minted it — an `insert`'s values, an edit's, a
//! shot's re-inserted values — before that commit's serialization guard
//! drops
//! ([`CellIndex::enter_insert`], [`CellIndex::enter_publish`], the write
//! path's one hook). Rebuilt whole at every open from the world replayed
//! there and never from the retained journal alone: a thread walks an
//! immutable snapshot of the content store ([`walk`]) while every other
//! request is served, adding every cell it finds into the one copy the
//! commits since the open have entered their own into, never installing a
//! copy in its place — the composition clause, which holds by construction
//! because an entry is idempotent per cell address: a cell is permanent, so
//! an entry made twice is made once. The readiness (`CellIndex::is_ready`)
//! flips when that walk completes, and until then the index's three
//! readers — the PUT's creation and resume, the deposit read's base —
//! refuse with one retry-class token and the pruner's pass does not start
//! (every other request is served throughout, the door's binding reading
//! the lease arm alone).
//!
//! **The failed state** (`CellIndex::is_failed`; `operations.md` §4 row 26,
//! §1.1 row 41; PATTERNS P10, P22's honest-null arm). Where the walk dies —
//! on its own thread, or on the opening thread where the OS refused it one —
//! its catch marks the index failed: a third state beside ready and
//! not-ready, the two exclusive by construction, since a walk that completed
//! never fails and a walk that failed never completes. The state is said
//! once in the operator's terms and re-said by the daemon's standing line;
//! the three readers then refuse for the life of the process with a token
//! of its own and no retry hint, the door answers the lease arm's verdict
//! as final, and the pruner runs no pass. A window that ends, or a state
//! that stands: never a retry that cannot succeed, and never an open that
//! fails for a structure the board can serve without.
//!
//! **The halt mark** (DOCTRINE D13's carve-out). A value opening as the
//! cell's kind (the prefix test) that parses under no schema this build
//! pins is entered as a halt mark — its address and the fault — and counts
//! in no base; while one stands the pruner halts its unlink pass, naming
//! it, and never reads the value as absent, since at the pruner absence is
//! a permission. The door refuses such a value at its own insert, so a
//! halt mark is reachable only from a board another build wrote.
//!
//! **The lock is the index's own.** The commit enters under the
//! serialization guard, the door's binding reads under the credential
//! lock's read arm, the PUT's scopes and the deposit read under no arm of
//! it, the pruner under its write arm, the walk under neither — so the
//! index sits behind a `parking_lot::RwLock` taken innermost and held across
//! no other lock. The cheap prefix test (`cell::names_kind_by_prefix`, the
//! picture kind's canonical opening) stands before every parse, and a
//! stretch — one entry for a run of single-byte values, none of which can be
//! a cell — is counted and skipped whole by its arm before the test, so a
//! walk over a prose board's million one-byte values costs a step per
//! stretch, a board of atoms a byte compare apiece, and a parse for the
//! cells alone.
//!
//! **The inventory's reads** ([`CellIndex::references`],
//! [`CellIndex::accounts`], [`CellIndex::halts`]; `media.md` §Recovery, "the
//! operator can list the holes"). The operator's tool walks a copy's world
//! into a fresh index through the same [`walk`] and reads it whole — every
//! reference with the cells naming it and the size they name, every
//! account's base, every halt mark — recording nothing (D9).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io;
use std::panic::AssertUnwindSafe;
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
use skep_content::Piece;
use skep_febe::FebeWorld;
use skep_kernel::{Kernel, Snapshot};
use skep_namespace::PrincipalId;
use skep_util::caught::{self, Caught};
use skep_util::json::hex_string;
use skep_util::notice::{self, Class};

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

/// One account's side of the index: its hashes and their sum, the base.
///
/// The hashes are the distinct ones its cells name, each at the size
/// counted for it.
#[derive(Default)]
struct Account {
    hashes: BTreeMap<HashKey, u64>,
    base: u64,
}

/// A halt mark: a value at `at` naming the kind under no pinned schema.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HaltMark {
    /// The value's address.
    pub at: Address,
    /// The kind the value names.
    pub kind: String,
    /// The schema fault: `unknown_cell_schema`.
    ///
    /// It is the name of the cell's own verdict, as the door's arm 4 answers
    /// it.
    pub fault: String,
}

/// One reference as the inventory reads it: a hash, its cells and its size.
///
/// The cells are those naming the hash; the size is the one they name it
/// at — the largest any names, as the base counts it.
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
    /// Per hash, the largest size any cell names it at.
    ///
    /// It is the inventory's length test, kept for a cell under no seat too.
    sizes: BTreeMap<HashKey, u64>,
    /// Per account, the hashes its cells name at their size: the base.
    ///
    /// The account is the principal seated at it, ω of the cell's document.
    by_account: BTreeMap<PrincipalId, Account>,
    /// The halt marks, by address.
    halts: BTreeMap<Tumbler, HaltMark>,
    /// Every cell address entered — the idempotency's set.
    cells: BTreeSet<Tumbler>,
}

/// The rebuild's report: what the walk at open found and what it cost.
///
/// It is the record's measure (its §Costs: "the time from open to the first
/// PUT the gate [the media gate] admits") read off the daemon rather than
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
    /// The readiness: the walk at open completed.
    ///
    /// Monotone.
    ready: AtomicBool,
    /// The failed state: the walk at open died, caught.
    ///
    /// Set by that catch ([`CellIndex::fail`]; `operations.md` §4 row 26),
    /// whichever thread the walk ran on, and by a test on an index it built
    /// by hand; never cleared: nothing walks again but a restart. Exclusive
    /// with `ready` by construction on the walk's path: `complete` runs only
    /// after a walk returned, `fail` only on an unwind out of the walk or its
    /// completion.
    failed: AtomicBool,
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
    /// Returns an empty index, not ready and not failed.
    ///
    /// The walk makes it ready, or its death marks it failed.
    pub fn new() -> CellIndex {
        CellIndex {
            entries: RwLock::new(Entries::default()),
            ready: AtomicBool::new(false),
            failed: AtomicBool::new(false),
            rebuild: Mutex::new(None),
        }
    }

    /// Returns whether the walk at open has completed.
    ///
    /// It is what the three readers consult. Monotone: once ready, ready for
    /// the life of the process.
    pub(crate) fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }

    /// Returns whether the walk at open died: the failed state.
    ///
    /// It is the third state beside ready and not-ready (`operations.md` §4
    /// row 26): the three readers refuse `index_failed` for the life of the
    /// process, the door answers the lease arm's verdict as final, the
    /// pruner runs no pass. Monotone, and never true beside
    /// `CellIndex::is_ready`.
    pub(crate) fn is_failed(&self) -> bool {
        self.failed.load(Ordering::Acquire)
    }

    /// Returns the walk's report, once it has completed.
    ///
    /// It is the open-cost measure's read, a suite's.
    #[cfg(any(test, feature = "test-hooks"))]
    #[doc(hidden)]
    pub fn rebuild_report(&self) -> Option<Rebuild> {
        self.rebuild.lock().clone()
    }

    /// Completes the walk, keeping its report and flipping the readiness.
    ///
    /// It says the walk's landing (`operations.md` §1.1 row 13), its figures
    /// and its two durations in milliseconds ([`RebuiltLine`]), and, where a
    /// halt mark stands — a value opening as the picture kind under no schema
    /// this build reads — the standing failure that halts the pruner's unlink
    /// pass (row 14), once. It is the walk's own door; a test readies an
    /// index it built by hand through it.
    pub(crate) fn complete(&self, report: Rebuild) {
        notice::emit(Class::Landing, RebuiltLine { report: &report });
        if let Some(mark) = self.first_halt() {
            notice::emit(
                Class::Failure,
                format_args!(
                    "cell index: a value at {} names the kind {} under no schema this build reads ({}): the pruner's unlink pass halts while it stands",
                    mark.at, mark.kind, mark.fault
                ),
            );
        }
        *self.rebuild.lock() = Some(report);
        self.ready.store(true, Ordering::Release);
    }

    /// Marks the index failed, then says the catch's line once.
    ///
    /// It is the walk's failure (`operations.md` §4 row 26; §1.1 row 41): the
    /// line goes out under `Class::Failure` in the operator's terms
    /// ([`WalkFailedLine`]) — the panic `caught`, at the site the hook noted,
    /// with its literal where a `panic!` wrote one; what refuses from here;
    /// and the act. The walk's catch alone calls it ([`walk_under_the_catch`]),
    /// whichever thread the walk ran on, once per life of the process; a test
    /// fails an index it built by hand through it. The binary's hook has said
    /// the panic on the line before (row 41: the hook's line is the binary's,
    /// this one the library's).
    pub(crate) fn fail(&self, caught: &Caught) {
        self.failed.store(true, Ordering::Release);
        notice::emit(Class::Failure, WalkFailedLine { caught });
    }

    /// Enters one cell at `at`, minted in a document `owner` is seated over.
    ///
    /// `None` is a document under no seat — counted in no base, named for the
    /// pruner all the same. Idempotent per address — the composition clause's
    /// premise: a cell is permanent, so a second entry of one address changes
    /// nothing. Answers `true` where the entry was new.
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
            // One size per hash per account, order-independent — the largest
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

    /// Enters a halt mark at `at`.
    ///
    /// There the picture kind is named under no pinned schema; the mark's
    /// fault is the verdict's own name ([`cell::UNKNOWN_SCHEMA_TOKEN`]).
    /// Idempotent per address. Answers `true` where new.
    fn halt(&self, at: &Address) -> bool {
        let mut entries = self.entries.write();
        if entries.halts.contains_key(at.tumbler()) {
            return false;
        }
        let mark = HaltMark {
            at: at.clone(),
            kind: cell::KIND.to_string(),
            fault: cell::UNKNOWN_SCHEMA_TOKEN.to_string(),
        };
        entries.halts.insert(at.tumbler().clone(), mark);
        true
    }

    /// Returns whether `owner`'s own cells name `<designation>/<hex>`.
    ///
    /// It is the pending rule's read (`MediaGate::lease_counted`): a hash its
    /// own cells name is a reference, kept by no lease.
    pub(crate) fn names(&self, owner: PrincipalId, designation: &str, hex: &str) -> bool {
        self.size_named(owner, designation, hex).is_some()
    }

    /// Returns the size `owner`'s own cells name `<designation>/<hex>` at.
    ///
    /// It is the size its base counts the hash at — the binding's index-first
    /// arm reads it — or `None` where none names it.
    pub(crate) fn size_named(&self, owner: PrincipalId, designation: &str, hex: &str) -> Option<u64> {
        self.entries
            .read()
            .by_account
            .get(&owner)
            .and_then(|a| a.hashes.get(&HashKey::named(designation, hex)).copied())
    }

    /// Returns whether any cell names `<designation>/<hex>`.
    ///
    /// It is the pruner's reference test, whose null is a permission; the
    /// pull's test of the file it is handed.
    pub fn referenced(&self, designation: &str, hex: &str) -> bool {
        self.entries.read().by_hash.contains_key(&HashKey::named(designation, hex))
    }

    /// Returns the base of `owner`'s account.
    ///
    /// It is the sum of its distinct hashes' sizes — the deposit read's first
    /// figure.
    pub fn base(&self, owner: PrincipalId) -> u64 {
        self.entries.read().by_account.get(&owner).map_or(0, |a| a.base)
    }

    /// Returns every account's base, summed.
    ///
    /// It is the venue total's record-derived half beside the pending bytes.
    pub(crate) fn total_base(&self) -> u64 {
        self.entries.read().by_account.values().fold(0u64, |acc, a| acc.saturating_add(a.base))
    }

    /// Returns the first halt mark standing, by address.
    ///
    /// It is what the pruner halts on and names.
    pub(crate) fn first_halt(&self) -> Option<HaltMark> {
        self.entries.read().halts.values().next().cloned()
    }

    /// Returns the counts: cells, distinct hashes, halt marks — a suite's read.
    #[cfg(any(test, feature = "test-hooks"))]
    #[doc(hidden)]
    pub fn counts(&self) -> (usize, usize, usize) {
        let e = self.entries.read();
        (e.cells.len(), e.by_hash.len(), e.halts.len())
    }

    /// Returns every reference: the inventory's read.
    ///
    /// Per hash, it gives the cells naming it and the size they name, in hash
    /// order.
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

    /// Returns every account's base: the inventory's read.
    ///
    /// It gives the principal seated at the account and its base, in
    /// principal order.
    pub fn accounts(&self) -> Vec<(PrincipalId, u64)> {
        self.entries.read().by_account.iter().map(|(p, a)| (*p, a.base)).collect()
    }

    /// Returns every halt mark standing, by address: the inventory's read.
    pub fn halts(&self) -> Vec<HaltMark> {
        self.entries.read().halts.values().cloned().collect()
    }

    /// Enters a value past the prefix test, at `at` in `world`.
    ///
    /// It is the one entry path, by the one parser's verdict: a cell is
    /// entered under ω of the cell's document (M3's one walk, read once per
    /// cell); a value naming the kind under no schema is entered as a halt
    /// mark — a body past the cap that opens as the picture kind among them,
    /// since the cap bounds the parse and never the classification; a value
    /// the parser reads as no cell of the kind — malformed past the prefix,
    /// or past the cap and opening as no kind — is nothing, as it is to the
    /// door. Generic over the world M10 reads ([`FebeWorld`]), as every entry
    /// and the walk are: the daemon instantiates them at its `World`.
    fn enter_value<W: FebeWorld>(&self, world: &W, at: &Address, bytes: &[u8]) -> Entered {
        match cell::parse(bytes) {
            Ok(cell) => {
                let owner = document_of(at)
                    .and_then(|doc| world.m3().effective_owner_pair(&doc).map(|(_, id)| id));
                self.enter(at, owner, &cell);
                Entered::Cell
            }
            Err(refusal) if refusal.names_kind() => {
                self.halt(at);
                Entered::Halt
            }
            Err(_) => Entered::Nothing,
        }
    }

    /// Enters the values an `insert`'s commit placed, or an edit's: the
    /// entry at its commit.
    ///
    /// They are read off the post-commit `world` at the addresses the commit
    /// minted — `start` (the ack's address, the first minted) and the next
    /// ones, I-adjacent under the named document's content chain — for the
    /// value indices `naming` the prefix test admitted ahead of the commit.
    /// An edit's values are counted over all its changes, in the order they
    /// are minted, which is the changes' own: one index space from the one
    /// address its ack names.
    pub fn enter_insert<W: FebeWorld>(&self, world: &W, start: &Address, naming: &[usize]) {
        let content = world.content();
        for &i in naming {
            let Ok(at) = validate(shift(start.tumbler(), &Nat::from(i as u64))) else { continue };
            // The point read lends a piece: a value's bytes, or the one byte
            // at an address inside a stretch, which the prefix test refuses by
            // itself — a one-byte value never opens `{"type":"`.
            if let Some(piece) = content.value_at(at.tumbler()) {
                if names_kind_by_prefix(piece.as_bytes()) {
                    self.enter_value(world, &at, piece.as_bytes());
                }
            }
        }
    }

    /// Enters the values a shot's commit minted: the entry at its commit.
    ///
    /// They are the `reinserted` values the shot minted as fresh identity
    /// under the trunk's content chain — the last `reinserted` addresses of
    /// that chain in the post-commit `world`, where
    /// `skep_arrangement::Vstream::publish` states a shot's fresh identity
    /// lands, read off its frontier (M3's content mint, asked and not staged,
    /// is the chain's peek) — each atom among them put through the prefix
    /// test and the one entry path.
    ///
    /// **By stored piece.** The fresh addresses are read by M4's run read,
    /// one predecessor lookup and then piece by piece, as the walk at open
    /// reads the whole store: a stretch — a run of single-byte values, none
    /// of which can be a cell — is skipped whole by its arm, and a value is
    /// put through the test. So a shot that re-minted a megabyte of typed
    /// text as one stretch costs this entry one step, where a point read a
    /// position would cost it a lookup a byte, under the commit's
    /// serialization guard. Returns the stored pieces it read — the entry's
    /// cost, a figure and no part of the index — at most `reinserted`,
    /// itself held to M5's positions budget.
    pub fn enter_publish<W: FebeWorld>(&self, world: &W, member: &Address, reinserted: u64) -> u64 {
        let trunk = trunk_of(member);
        let Ok((next, _)) = world.m3().mint_content(&trunk) else { return 0 };
        let next_ordinal = ordinal(next.tumbler()).clone();
        // The fresh identity: the chain's last `reinserted` addresses, no
        // further back than its first and no more than a shot re-inserts.
        let minted = Nat::from(reinserted.min(MAX_REINSERTED_VALUES as u64));
        let first_ordinal = Nat::from(1u32);
        let width = if next_ordinal > minted { minted } else { &next_ordinal - &first_ordinal };
        let position = ElemPos { doc: trunk, subspace: content_subspace(), ordinal: &next_ordinal - &width };
        let Ok(mut at) = elem_addr(position) else { return 0 };
        let mut read = 0u64;
        for piece in world.content().pieces(at.tumbler(), &width) {
            read += 1;
            let taken = match piece {
                // A re-minted stretch: single-byte values, none a cell.
                Piece::Bytes(bytes) => bytes.len(),
                Piece::Value(v) => {
                    if names_kind_by_prefix(v.as_bytes()) {
                        self.enter_value(world, &at, v.as_bytes());
                    }
                    1
                }
            };
            // The next piece begins where this one reached; an address the
            // chain cannot spell ends the walk, as it ends the store's.
            let Ok(next) = validate(shift(at.tumbler(), &Nat::from(taken as u64))) else { break };
            at = next;
        }
        read
    }
}

/// The walk's landing line: its figures and its two durations.
///
/// Its words (`operations.md` §1.1 row 13): `cell index rebuilt at open: {n}
/// values walked, {n} cells, {n} halt marks, {ms} ms ({ms} ms past the prefix
/// test)` — the walk's whole duration, then its time past the prefix test,
/// each in whole milliseconds, the one spelling `operations.md` §1 gives a
/// duration on the stream. The line ends the readiness window: from the open
/// until it, the index's three readers refuse `index_rebuilding`. A pure
/// value pinned by `to_string()` in the unit suite; emitted under
/// `Class::Landing` by [`CellIndex::complete`], once.
struct RebuiltLine<'a> {
    report: &'a Rebuild,
}

impl fmt::Display for RebuiltLine<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let r = self.report;
        write!(
            f,
            "cell index rebuilt at open: {} values walked, {} cells, {} halt marks, {} ms ({} ms \
             past the prefix test)",
            r.values,
            r.cells,
            r.halts,
            r.walk.as_millis(),
            r.parse.as_millis()
        )
    }
}

/// The line the walk's refused thread says: the OS's cause, and what runs.
///
/// Its words (`operations.md` §1.1 row 15, in the form of the pruner's and
/// the checkpoint thread's, rows 21 and 22): `cell index: the OS refused the
/// rebuild's thread ({error}); the walk runs at open` — the error in the OS's
/// own words, which name the limit the spawn met. A pure value pinned by
/// `to_string()` in the unit suite; emitted under `Class::Failure` by
/// [`start_walk`], once, where the spawn is refused.
struct ThreadRefusedLine<'a> {
    error: &'a io::Error,
}

impl fmt::Display for ThreadRefusedLine<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "cell index: the OS refused the rebuild's thread ({}); the walk runs at open",
            self.error
        )
    }
}

/// The catch's line: the walk failed, what refuses for the uptime, the act.
///
/// Its words (`operations.md` §4 row 26; §1.1 row 41): `cell index: the walk
/// failed (a panic at {location}: {literal}); the upload family and the
/// door's index arm refuse for the uptime; the act: a restart, or the build's
/// fix where it recurs` — the parenthesis the panic as [`Caught`] renders it:
/// the location the binary's hook noted at the panic, on this thread, and
/// says on the line before, or `an unknown location` under a hook that noted
/// none; then the literal a `panic!` wrote, where it wrote one, and never a
/// formatted message, whose text the walk's values may have made. A pure
/// value pinned by `to_string()` in the unit suite; emitted under
/// `Class::Failure` by [`CellIndex::fail`], once.
struct WalkFailedLine<'a> {
    caught: &'a Caught,
}

impl fmt::Display for WalkFailedLine<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "cell index: the walk failed ({}); the upload family and the door's index arm refuse \
             for the uptime; the act: a restart, or the build's fix where it recurs",
            self.caught
        )
    }
}

/// Walks every value of the world `snapshot` holds into `index`.
///
/// It is the walk at open: a stretch's values counted and skipped whole,
/// every other value through the prefix test and then the one entry path,
/// into `index` — the one copy the commits since the open enter their own
/// into. Reads an immutable snapshot, so commits proceed on later roots
/// while it walks.
pub fn walk<W: FebeWorld>(snapshot: &Snapshot<W>, index: &CellIndex) -> Rebuild {
    #[cfg(any(test, feature = "test-hooks"))]
    WALK_HOLD.wait();
    #[cfg(any(test, feature = "test-hooks"))]
    WALK_FAULT.fire_if_armed();
    let started = Instant::now();
    let world = snapshot.world();
    let (mut values, mut cells, mut halts) = (0usize, 0usize, 0usize);
    let mut parse = Duration::ZERO;
    for (at, piece) in world.content().iter() {
        // By arm, not by the prefix test: a stretch is N single-byte values,
        // none of which can be a cell, so it is counted — `values` keeps
        // counting *values*, which keeps the operator line's words true — and
        // skipped whole; the test run over a whole stretch's bytes would take
        // typed text that happens to open `{"type":"` for a cell. A value is
        // put through the test.
        let bytes = match piece {
            Piece::Bytes(bytes) => {
                values += bytes.len();
                continue;
            }
            Piece::Value(v) => {
                values += 1;
                v.as_bytes()
            }
        };
        if !names_kind_by_prefix(bytes) {
            continue;
        }
        let at_parse = Instant::now();
        match index.enter_value(world, at, bytes) {
            Entered::Cell => cells += 1,
            Entered::Halt => halts += 1,
            Entered::Nothing => {}
        }
        parse += at_parse.elapsed();
    }
    Rebuild { values, cells, halts, walk: started.elapsed(), parse }
}

/// Starts the walk at open over the world as `kernel` holds it now.
///
/// The walk runs on a thread of its own and completes `index` when it is
/// done; `kernel` is the daemon's engine's kernel, the one thing of the
/// engine the walk needs. Where the OS refuses the thread, this says so in
/// the OS's words (`ThreadRefusedLine`; `operations.md` §1.1 row 15) and
/// runs the walk here instead, on the opening thread, before it returns: the
/// daemon then serves later rather than never readying (P22: a derived
/// structure's loss is a slower answer, not an outage).
///
/// **The catch** (`operations.md` §4 row 26; §1.1 row 41, a per-thread catch,
/// as the daemon's loops run under). Both arms run the walk and its completion
/// under one catch, `walk_under_the_catch`, and an unwind out of either marks
/// the index failed through `CellIndex::fail`, said once, in place of a walk
/// that died unsaid and an index that never readied, where the three readers
/// would have answered the retry-class token for the uptime. So a walk that
/// dies leaves the board serving degraded on either arm, and this call never
/// unwinds for it: a panic in the walk run here is contained here, and the
/// open that called it goes on.
pub fn start_walk<W: FebeWorld>(kernel: &Kernel<W>, index: Arc<CellIndex>) {
    let snapshot = kernel.snapshot();
    let shared = Arc::clone(&index);
    let body = move || walk_under_the_catch(&snapshot, &shared);
    #[cfg(test)]
    let refused = REFUSE_THE_WALKS_THREAD.swap(false, Ordering::AcqRel);
    #[cfg(not(test))]
    let refused = false;
    let spawned = if refused {
        Err(io::Error::other("test seam: the walk's thread refused"))
    } else {
        thread::Builder::new().name("skepd-cell-index".into()).spawn(body)
    };
    if let Err(error) = spawned {
        notice::emit(Class::Failure, ThreadRefusedLine { error: &error });
        walk_under_the_catch(&kernel.snapshot(), &index);
    }
}

/// Runs the walk at open and its completion under the catch.
///
/// The walk over `snapshot` adds into `index` and completes it; an unwind out
/// of either is caught here, by `caught::catch` with the site the hook noted,
/// and marks the index failed through [`CellIndex::fail`] (`operations.md`
/// §4 row 26; §1.1 row 41). It is the one catch both of [`start_walk`]'s arms
/// run the walk under — its own thread's, and the opening thread's where the
/// OS refuses that one — so the two cannot differ on a walk that dies.
/// Unwind-safe by the argument the transport makes for its handlers: the
/// index's lock does not poison, an entry left half-made under the failed
/// state is consulted by no reader the state does not refuse, and the snapshot
/// is immutable.
fn walk_under_the_catch<W: FebeWorld>(snapshot: &Snapshot<W>, index: &CellIndex) {
    let walked = caught::catch(AssertUnwindSafe(|| {
        let report = walk(snapshot, index);
        index.complete(report);
    }));
    if let Err(caught) = walked {
        index.fail(&caught);
    }
}

/// The test seam: the OS refuses the next walk's thread, once.
///
/// Armed, the next [`start_walk`] meets the refusal its `Err` arm answers —
/// the walk run on the opening thread, under the same catch — and disarms.
/// Compiled for this crate's own suite alone: no hook of the daemon's
/// reaches it.
#[cfg(test)]
static REFUSE_THE_WALKS_THREAD: AtomicBool = AtomicBool::new(false);

/// The test seam's hold on the walk, armed before a daemon opens.
///
/// It is there so a suite can serve requests against a daemon whose index
/// is not ready and release the walk at its own moment.
#[cfg(any(test, feature = "test-hooks"))]
#[doc(hidden)]
pub struct WalkHold {
    held: Mutex<bool>,
    released: Condvar,
}

/// The test seam's one hold on the walk.
///
/// It is process-wide, since the walk starts inside the open.
#[cfg(any(test, feature = "test-hooks"))]
#[doc(hidden)]
pub static WALK_HOLD: WalkHold = WalkHold { held: Mutex::new(false), released: Condvar::new() };

#[cfg(any(test, feature = "test-hooks"))]
impl WalkHold {
    /// Arms the hold: every walk started from here on parks.
    ///
    /// It parks before its first entry.
    pub fn hold(&self) {
        *self.held.lock() = true;
    }

    /// Releases the hold: every parked walk proceeds.
    ///
    /// Later walks park only where the hold is armed again.
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

/// The test seam's fault in the walk, armed before a daemon opens.
///
/// A suite serves requests against a daemon whose index failed: the next
/// walk in this process panics — after the hold's wait and before its first
/// entry, with a literal payload — and the walk's catch contains it and
/// marks the index by it, whichever thread the walk ran on. Taken once: the
/// arm is disarmed as it fires, so a later walk meets no fault.
#[cfg(any(test, feature = "test-hooks"))]
#[doc(hidden)]
pub struct WalkFault {
    armed: AtomicBool,
}

/// The test seam's one fault in the walk.
///
/// It is process-wide, as the hold is, since the walk starts inside the
/// open.
#[cfg(any(test, feature = "test-hooks"))]
#[doc(hidden)]
pub static WALK_FAULT: WalkFault = WalkFault { armed: AtomicBool::new(false) };

#[cfg(any(test, feature = "test-hooks"))]
impl WalkFault {
    /// Arms the fault: the next walk to pass its hold panics.
    ///
    /// Arming again re-arms.
    pub fn arm(&self) {
        self.armed.store(true, Ordering::Release);
    }

    /// Takes the arm where it stands: the walk's side.
    ///
    /// # Panics
    ///
    /// Panics where the fault is armed — once per arming, the payload a
    /// literal the binary's hook carries.
    fn fire_if_armed(&self) {
        if self.armed.swap(false, Ordering::AcqRel) {
            panic!("the test seam's walk fault");
        }
    }
}

#[cfg(test)]
mod tests;
