//! THE SERVE — THE FETCH's COMPOSED ORDER (`media.md` Op inventory 3, "THE
//! FETCH IS A READ BY IDENTITY, GATED AS EVERY READ IS", "EVERY v1 ANSWER
//! THEREFORE READS ITS WHOLE FILE BEFORE ITS FIRST BYTE, AND THE ROUTE
//! ADMITS AT MOST A PERMIT POOL OF ANSWERS AT ONCE", "AT A BYTE INTERVAL
//! THE SUBSYSTEM DESIGN PINS WITH THE ROUTE … OR AT A TIME INTERVAL PINNED
//! BESIDE IT, WHICHEVER COMES FIRST"; the register M-I2 (a)–(d), (g), M-I3
//! (b), M-I7 (a), (b); the rulings s6-E1 (a), s6-leak-b; PATTERNS P29): what
//! `GET /blob?i=` and its `HEAD` run (`server/blob_routes.rs`), and what the
//! transport then streams (`server/listen.rs`). ONE order, stated once:
//!
//! 0. THE SHAPE — `i` names an element position of a document, or the
//!    request is malformed before any store is asked.
//! 1.–3. THE GATE IS M10's READ BY IDENTITY: `retrieve_i` of the one span
//!    `{i, 1}`, executed as the presented session — the guest where none
//!    was — through `OperationSurface::execute`, so the doc-argument consult
//!    walks the DERIVED document (the head's read predicate: published ∨
//!    subtree ∨ grant, PUB-1.31), the rejection is M10's own (`withheld`
//!    naming the home, every other code as `/op` would answer it), and
//!    NOTHING of a value the requester may not read is read on its behalf
//!    (PATTERNS P31). The route holds no second reading of the predicate
//!    (M-I2 (a): THE FETCH IS GATED BY THE SAME PREDICATE AS THE READ).
//! 4. THE CLASSIFICATION — the value answered, read by [`cell::classify`]:
//!    no value at the address; a value naming no media kind; a value naming
//!    a kind under no schema this build reads (D13's halt, the door's
//!    `unknown_cell_schema` on this surface); a BLIND cell, whose picture
//!    this board holds no byte of (`media/blind.rs`: nothing the daemon does
//!    for one reads a file, a lease or an index entry — this arm reaches no
//!    store); or the picture's cell, whose `hash` and `size` the file is
//!    held to.
//! 5. THE PERMIT — one of [`MAX_CONCURRENT_FETCHES`], or the retry-class
//!    refusal: a fetch holds its whole file from the check to the last
//!    byte written, so the pool is the route's memory bound,
//!    [`MAX_BLOB_BYTES`] × the pool (M-I7 (b): BOUNDED BY A POOL, NEVER BY A
//!    QUEUE).
//! 6. THE WHOLE FILE, CHECKED BEFORE ITS FIRST BYTE (M-I3 (b): THE BYTES
//!    SERVED ARE THE BYTES THE CELL NAMES; the ruled v1 cut, whole-file
//!    serving): the store's file under the cell's hash, read whole, its
//!    length the cell's `size` and its BLAKE3 the cell's `hash`, or the
//!    refusal naming what the cell names and the store did not have — the
//!    file absent, or present and not the deposit as written. No byte of a
//!    file the cell does not name is written, and no byte of this one before
//!    the check is complete.
//!
//! Then THE STREAM, the transport's: the head with the file's length, the
//! body one [`BLOB_CHUNK`](crate::limits::BLOB_CHUNK) at a time under the
//! idle bound and the transfer bound, and BETWEEN CHUNKS the re-resolution
//! (M-I2 (g): THE ENTITLEMENT IS RE-RESOLVED MID-STREAM) at whichever of
//! [`Progress`]'s two intervals comes first — the requester against the
//! head and the gate run again ([`gate_admits`]) — a stream whose requester
//! died or whose gate now withholds ended by a RESET, never a clean close
//! that a client could read as the whole file. The permit spans the answer:
//! it is held in the [`Admitted`] the transport streams from, and returns
//! when that value drops, on every exit.
//!
//! Sits at the write path's layer beside the gate and the door
//! (`ARCHITECTURE.md` §The daemon): it reads the store through the gate and
//! M10 through its front door, and names nothing of the transport or the
//! routes. Every pin here is INTERIM (sm-Q8).

use std::fs::File;
use std::io::{self, Read};

use skep_address::{document_of, Address, Level, Nat};
use skep_content::Val;
use skep_engine::World;
use skep_febe::{ISpan, Op, OperationSurface, Rejection, Request, Response, SessionId};

use super::cell::{self, Class};
use super::gate::{hex_of, MediaGate, DESIGNATION};
use crate::limits::{
    FETCH_RECHECK_BYTES, FETCH_RECHECK_INTERVAL, MAX_BLOB_BYTES, MAX_CONCURRENT_FETCHES,
};
use crate::permits::{Permit, Permits};

/// THE FETCH POOL — the third instance of [`crate::permits`]'s mechanism,
/// disjoint from the reconstruction pool and the class-scan pool by the
/// borrow: a [`Permit`] names the pool that issued it, so no fetch spends a
/// slot of either and neither spends one of these. [`MAX_CONCURRENT_FETCHES`]
/// slots; a drained pool REFUSES, never queues.
pub(crate) struct FetchPool(Permits);

impl FetchPool {
    pub(crate) fn new() -> FetchPool {
        FetchPool(Permits::new(MAX_CONCURRENT_FETCHES))
    }

    /// One permit for a whole answer, or `None` right now.
    fn admit(&self) -> Option<Permit<'_>> {
        self.0.try_acquire()
    }

    /// TEST HOOK, reached through `Daemon::try_hold_fetch_permit`: hold one
    /// permit exactly as an in-flight fetch does.
    #[cfg(any(test, feature = "test-hooks"))]
    #[must_use = "a permit dropped at once holds nothing"]
    pub(crate) fn try_hold(&self) -> Option<Permit<'_>> {
        self.0.try_acquire()
    }
}

/// An ADMITTED fetch: the address served, the whole file checked against
/// its cell, and the permit the answer holds until this value drops — which
/// the transport does after the last byte, or at the reset. The file's
/// bytes are what the stream writes and nothing else; its length is the
/// cell's `size`, by the check.
pub(crate) struct Admitted<'a> {
    i: Address,
    bytes: Vec<u8>,
    _permit: Permit<'a>,
}

impl Admitted<'_> {
    /// The address served — what the mid-stream re-check asks the gate about
    /// again.
    pub(crate) fn i(&self) -> &Address {
        &self.i
    }

    /// The file's length: the cell's `size`, by the check.
    pub(crate) fn size(&self) -> u64 {
        self.bytes.len() as u64
    }

    /// The file, whole.
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// What the cell names, carried on the two refusals that say the store did
/// not have it: the hash as the cell spells it and the size — the cell's
/// own members, which the requester could read at the address already, so
/// the refusal discloses nothing the gate did not admit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CellFace {
    pub(crate) hash: String,
    pub(crate) size: u64,
}

/// Why a fetch is refused — one variant per step of the order that can
/// refuse, in the order's own sequence; the mapping onto the wire's status
/// and token is `server/reply.rs`'s (`refuse_fetch`), not this module's.
#[derive(Debug)]
pub(crate) enum Refusal {
    /// Step 0: `i` is not an element position of a document.
    Shape(String),
    /// Steps 1–3: M10's own rejection of the read by identity — `withheld`
    /// naming the derived home, or any other code as `/op` answers it.
    Rejected(Rejection),
    /// Step 4: no value is minted at the address.
    NoValue,
    /// Step 4: the value names no media kind — prose, a def, a record of
    /// another kind.
    NotACell,
    /// Step 4: the value names a media kind — the picture's or the blind
    /// document's — under no schema this build reads: D13's halt.
    UnknownCellSchema,
    /// Step 4: a blind document's cell — this board holds no byte of its
    /// picture, and no store is asked.
    BlindCell,
    /// Step 6: the store has no file under the cell's hash.
    BlobMissing(CellFace),
    /// Step 6: the store's file is not the deposit the cell names — the
    /// wrong length, or the wrong bytes under the right name.
    BlobDamaged(CellFace),
    /// Step 6: the store refused I/O.
    BlobIo(io::Error),
    /// Step 5: every fetch permit is in use.
    Busy,
}

/// THE FETCH, steps 0 through 6 — the module's order, run once. `febe` is
/// M10's front door and `session` the presented session the read runs as
/// ([`SessionId::GUEST`] where none was presented); `gate` is the daemon's
/// media resource the file is read through; `pool` the fetch pool the
/// answer's permit comes from, which the [`Admitted`] holds for as long as
/// it lives.
pub(crate) fn fetch<'a>(
    febe: &OperationSurface<World>,
    session: SessionId,
    gate: &MediaGate,
    pool: &'a FetchPool,
    i: &Address,
) -> Result<Admitted<'a>, Refusal> {
    // 0 — the shape: an element position of some document, or nothing is
    // asked of any store.
    if i.level() != Level::Element || document_of(i).is_none() {
        return Err(Refusal::Shape(format!(
            "i: '{}' names no element position of a document",
            i.tumbler()
        )));
    }
    // 1–3 — the gate: M10's read by identity, as the presented session.
    let value = read_by_identity(febe, session, i).map_err(Refusal::Rejected)?;
    let Some(value) = value else {
        return Err(Refusal::NoValue);
    };
    // 4 — the classification, one parse for both kinds.
    let cell = match cell::classify(value.as_bytes()) {
        Class::Picture(Ok(cell)) => cell,
        Class::Picture(Err(_)) | Class::Blind(Err(_)) => return Err(Refusal::UnknownCellSchema),
        Class::Blind(Ok(_)) => return Err(Refusal::BlindCell),
        Class::None(_) => return Err(Refusal::NotACell),
    };
    // 5 — the permit, for the whole answer.
    let permit = pool.admit().ok_or(Refusal::Busy)?;
    // 6 — the whole file, checked against the cell before any byte of it
    // is answered.
    let bytes = read_whole(gate, &cell)?;
    Ok(Admitted { i: i.clone(), bytes, _permit: permit })
}

/// THE RE-CHECK's gate (M-I2 (g)): the read by identity run again as
/// `session` — `true` where it answers a value at `i`, `false` where M10
/// now withholds or rejects it, or no value is minted there any more. The
/// requester's own re-resolution against the head is the route's, run
/// before this.
pub(crate) fn gate_admits(febe: &OperationSurface<World>, session: SessionId, i: &Address) -> bool {
    matches!(read_by_identity(febe, session, i), Ok(Some(_)))
}

/// M10's read by identity of the one span `{i, 1}`, as `session`: the value
/// minted at `i`, `None` where none is, or M10's rejection.
fn read_by_identity(
    febe: &OperationSurface<World>,
    session: SessionId,
    i: &Address,
) -> Result<Option<Val>, Rejection> {
    let request = Request {
        id: None,
        op: Op::RetrieveI { spans: vec![ISpan { start: i.clone(), width: Nat::from(1u32) }] },
        attest: None,
    };
    match febe.execute(session, request) {
        Response::IDelivery { items, .. } => {
            Ok(items.into_iter().next().and_then(|item| item.value))
        }
        Response::Rejected(rejection) => Err(rejection),
        // M10's own contract: a read answers its one shape or a rejection.
        _ => unreachable!("retrieve_i answers i_delivery or a rejection"),
    }
}

/// Step 6: the store's file under the cell's hash, whole, held to the
/// cell's `size` and `hash` — [`Refusal::BlobMissing`] where there is none,
/// [`Refusal::BlobDamaged`] where what is there is not the deposit the cell
/// names. The length is read first and held to the cell's before a byte is
/// read, so no cell can command an allocation past [`MAX_BLOB_BYTES`]; one
/// byte past that length is asked for, so a file grown under the open reads
/// as not the deposit either.
fn read_whole(gate: &MediaGate, cell: &cell::Cell) -> Result<Vec<u8>, Refusal> {
    let hex = hex_of(&cell.hash);
    let face = || CellFace { hash: hex.clone(), size: cell.size };
    let Some(path) = gate.store().blob_path(DESIGNATION, &hex) else {
        return Err(Refusal::BlobMissing(face()));
    };
    let mut file = match File::open(&path) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(Refusal::BlobMissing(face())),
        Err(e) => return Err(Refusal::BlobIo(e)),
    };
    let len = file.metadata().map_err(Refusal::BlobIo)?.len();
    if len != cell.size || len > MAX_BLOB_BYTES {
        return Err(Refusal::BlobDamaged(face()));
    }
    let mut bytes = Vec::with_capacity(len as usize);
    file.by_ref().take(len + 1).read_to_end(&mut bytes).map_err(Refusal::BlobIo)?;
    if bytes.len() as u64 != len || *blake3::hash(&bytes).as_bytes() != cell.hash {
        return Err(Refusal::BlobDamaged(face()));
    }
    Ok(bytes)
}

/// THE STREAM's INTERVAL ARITHMETIC (M-I2 (g); s6-E1 (a); s6-leak-b): the
/// bytes written since the last re-check and the gate's clock at it. The
/// re-check is DUE at whichever of the two bounds comes first — the byte
/// interval [`FETCH_RECHECK_BYTES`], or the time interval
/// [`FETCH_RECHECK_INTERVAL`] on the media gate's clock, so a suite drives
/// the time bound through the clock seam and a reader draining at a
/// trickle holds no interval open past it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Progress {
    since_check: u64,
    checked_ms: u64,
}

impl Progress {
    /// At the stream's open, `now_ms` the gate's clock: nothing written
    /// since the gate's own answer, which stands as the first check.
    pub(crate) fn new(now_ms: u64) -> Progress {
        Progress { since_check: 0, checked_ms: now_ms }
    }

    /// `n` more bytes written.
    pub(crate) fn advance(&mut self, n: u64) {
        self.since_check = self.since_check.saturating_add(n);
    }

    /// Whether a re-check is due at `now_ms`: the byte interval reached, or
    /// the time interval elapsed on the gate's clock.
    pub(crate) fn due(&self, now_ms: u64) -> bool {
        self.since_check >= FETCH_RECHECK_BYTES
            || now_ms.saturating_sub(self.checked_ms) >= FETCH_RECHECK_INTERVAL.as_millis() as u64
    }

    /// A re-check passed at `now_ms`: both intervals start over.
    pub(crate) fn reset(&mut self, now_ms: u64) {
        self.since_check = 0;
        self.checked_ms = now_ms;
    }
}

/// TEST SEAM: a hold on every fetch stream between two of its chunks,
/// armed by a suite before its request, so the suite can kill the session
/// or revoke the grant WHILE the stream stands and release it at its own
/// moment — the mid-stream re-check driven through a seam rather than a
/// race against the transport. Process-wide, as the cell index walk's hold
/// is; a `wait` while no hold is armed returns at once.
#[cfg(any(test, feature = "test-hooks"))]
pub(crate) struct StreamHold {
    held: parking_lot::Mutex<bool>,
    released: parking_lot::Condvar,
}

#[cfg(any(test, feature = "test-hooks"))]
pub(crate) static STREAM_HOLD: StreamHold =
    StreamHold { held: parking_lot::Mutex::new(false), released: parking_lot::Condvar::new() };

#[cfg(any(test, feature = "test-hooks"))]
impl StreamHold {
    /// Arm: every stream parks between its chunks from here on.
    pub(crate) fn hold(&self) {
        *self.held.lock() = true;
    }

    /// Release: every parked stream proceeds, and later streams never park.
    pub(crate) fn release(&self) {
        *self.held.lock() = false;
        self.released.notify_all();
    }

    /// The stream's side: park here while the hold is armed.
    pub(crate) fn wait(&self) {
        let mut held = self.held.lock();
        while *held {
            self.released.wait(&mut held);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The pool holds exactly [`MAX_CONCURRENT_FETCHES`] permits, refuses
    /// the next rather than queueing, and a released permit reopens its slot.
    #[test]
    fn the_fetch_pool_admits_the_pools_count_and_refuses_the_next() {
        let pool = FetchPool::new();
        let held: Vec<_> =
            (0..MAX_CONCURRENT_FETCHES).map(|_| pool.admit().expect("a permit")).collect();
        assert!(pool.admit().is_none(), "a drained pool refuses; it never queues");
        drop(held);
        assert!(pool.admit().is_some(), "a released permit reopens its slot");
        assert_eq!(MAX_CONCURRENT_FETCHES, 2);
        assert_eq!(
            MAX_BLOB_BYTES * MAX_CONCURRENT_FETCHES as u64,
            128 * 1024 * 1024,
            "the memory bound"
        );
    }

    /// The interval arithmetic: not due under both bounds; due at exactly
    /// the byte interval, whatever the clock; due at exactly the time
    /// interval on the gate's clock, whatever the bytes; a reset starts
    /// both over.
    #[test]
    fn a_recheck_is_due_at_whichever_interval_comes_first() {
        let interval_ms = FETCH_RECHECK_INTERVAL.as_millis() as u64;
        let mut progress = Progress::new(1_000);
        assert!(!progress.due(1_000));
        progress.advance(FETCH_RECHECK_BYTES - 1);
        assert!(!progress.due(1_000 + interval_ms - 1), "under both bounds");
        progress.advance(1);
        assert!(progress.due(1_000), "the byte interval, the clock unmoved");
        progress.reset(2_000);
        assert!(!progress.due(2_000 + interval_ms - 1));
        assert!(progress.due(2_000 + interval_ms), "the time interval, no byte written");
        assert!(
            !progress.due(1_000),
            "a clock that went backwards is read as no time: not due by time"
        );
        progress.advance(FETCH_RECHECK_BYTES);
        assert!(progress.due(1_000));
        assert_eq!(FETCH_RECHECK_BYTES, 1024 * 1024);
        assert_eq!(interval_ms, 5_000);
    }

    /// Step 6 at the store: no file is `blob_missing` naming the cell; a
    /// file of the right length under the right name holding other bytes is
    /// `blob_damaged`; a file of the wrong length is `blob_damaged` before
    /// any byte of it is hashed; the deposit as written is answered whole.
    #[test]
    fn the_whole_file_is_held_to_the_cell_before_its_first_byte() {
        let dir = tempfile::tempdir().expect("tempdir");
        let gate = MediaGate::open(dir.path()).expect("the store opens");
        let bytes = b"the picture's bytes";
        let cell = cell::Cell { hash: *blake3::hash(bytes).as_bytes(), size: bytes.len() as u64 };
        let face = CellFace { hash: hex_of(&cell.hash), size: cell.size };
        assert!(matches!(read_whole(&gate, &cell), Err(Refusal::BlobMissing(f)) if f == face));
        let path = gate.store().blob_path(DESIGNATION, &face.hash).expect("a path");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"the picture's bytez").unwrap();
        assert!(
            matches!(read_whole(&gate, &cell), Err(Refusal::BlobDamaged(f)) if f == face),
            "other bytes, the right length"
        );
        std::fs::write(&path, b"short").unwrap();
        assert!(
            matches!(read_whole(&gate, &cell), Err(Refusal::BlobDamaged(f)) if f == face),
            "the wrong length"
        );
        std::fs::write(&path, bytes).unwrap();
        assert_eq!(read_whole(&gate, &cell).expect("the deposit as written"), bytes);
        let past = cell::Cell { hash: cell.hash, size: MAX_BLOB_BYTES + 1 };
        assert!(
            matches!(read_whole(&gate, &past), Err(Refusal::BlobDamaged(_))),
            "a size past the cap names no deposit"
        );
    }

    /// The hold: a wait while no hold is armed returns at once, and a
    /// release wakes a parked wait.
    #[test]
    fn the_stream_hold_parks_only_while_armed() {
        STREAM_HOLD.wait();
        STREAM_HOLD.hold();
        let waiter = std::thread::spawn(|| STREAM_HOLD.wait());
        std::thread::sleep(std::time::Duration::from_millis(20));
        assert!(!waiter.is_finished(), "parked while armed");
        STREAM_HOLD.release();
        waiter.join().expect("released");
    }
}
