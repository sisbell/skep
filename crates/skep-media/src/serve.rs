//! The serve: the fetch's composed order.
//!
//! Its rules are `media.md` Op inventory 3, "the fetch is a read by
//! identity, gated as every read is", "every v1 answer therefore reads its
//! whole file before its first byte, and the route admits at most a permit
//! pool of answers at once", "at a byte interval the subsystem design pins
//! with the route … or at a time interval pinned beside it, whichever comes
//! first"; the register M-I2 (a)–(d), (g), M-I3 (b), M-I5 (f), M-I7 (a),
//! (b); PATTERNS P29. It is what `GET /blob?i=` and its `HEAD` run
//! (`server/blob_routes.rs`), and what the transport then streams
//! (`server/listen.rs`). One order, stated once:
//!
//! 0. The shape — `i` names an element position of a document, or the
//!    request is malformed before any store is asked.
//! 1.–3. The gate is M10's read by identity: `retrieve_i` of the one span
//!    `{i, 1}`, executed as the presented session — the guest where none
//!    was — through `OperationSurface::execute`, so the doc-argument consult
//!    walks the derived document (the head's read predicate: published ∨
//!    subtree ∨ grant, PUB-1.31), the rejection is M10's own (`withheld`
//!    naming the home, every other code as `/op` would answer it), and
//!    nothing of a value the requester may not read is read on its behalf
//!    (PATTERNS P31). The route holds no second reading of the predicate
//!    (M-I2 (a): the fetch is gated by the same predicate as the read).
//! 4. The classification — the value answered, read by `cell::classify`:
//!    no value at the address; a value naming no media kind; a value naming
//!    a kind under no schema this build reads (D13's halt, the door's
//!    `unknown_cell_schema` on this surface); a blind cell, whose picture
//!    this board holds no byte of (`cell/blind.rs`: nothing the daemon does
//!    for one reads a file, a lease or an index entry — this arm reaches no
//!    store); or the picture's cell, whose `hash` and `size` the file is
//!    held to.
//! 5. The permit — one of [`FetchPool`]'s
//!    [`MAX_CONCURRENT_FETCHES`](crate::limits::MAX_CONCURRENT_FETCHES), or
//!    the retry-class refusal: a fetch holds its whole file from the check
//!    to the last byte written, so the pool is the route's memory bound,
//!    [`MAX_BLOB_BYTES`] × the pool (M-I5 (f): bounded by a pool, never by a
//!    queue).
//! 6. The whole file, checked before its first byte (M-I3 (b): the bytes
//!    served are the bytes the cell names; the v1 cut, whole-file serving):
//!    the store's file under the cell's hash, read whole, its length the
//!    cell's `size` and its BLAKE3 the cell's `hash`, or the refusal naming
//!    what the cell names and the store did not have — the file absent, or
//!    present and not the deposit as written or longer than
//!    [`MAX_BLOB_BYTES`] — or the store's refusal of the I/O. No byte of a
//!    file the cell does not name is written, and no byte of this one before
//!    the check is complete.
//!
//! Then the stream, the transport's: the head with the file's length, the
//! body one `BLOB_CHUNK` (the daemon's) at a time under the idle bound and
//! the transfer bound, and between chunks the re-resolution (M-I2 (g): the
//! entitlement is re-resolved mid-stream) at whichever of [`Progress`]'s two
//! intervals comes first — the requester against the head and the gate run
//! again ([`gate_admits`]) — a stream whose requester died or whose gate now
//! withholds ended by a reset, never a clean close that a client could read
//! as the whole file. The permit spans the answer: it is held in the
//! [`Admitted`] the transport streams from, and returns when that value
//! drops, on every exit.
//!
//! Sits at the write path's layer beside the media gate and the door
//! (`ARCHITECTURE.md` §The media resource): it reads the store through the
//! media gate and M10 through its front door, and names nothing of the
//! transport or the routes. Every pin here is interim.

use std::fs::File;
use std::io::{self, Read};

use skep_address::{document_of, Address, Level, Nat};
use skep_arrangement::M5Rec;
use skep_content::{ContentStretch, ContentWrite, Val};
use skep_febe::{FebeWorld, ISpan, Op, OperationSurface, Rejection, Request, Response, SessionId};
use skep_links::LinkRec;
use skep_namespace::M3Rec;
use skep_util::json::hex_string;
use skep_util::permits::Permit;

use crate::cell::{self, Class, DESIGNATION};
use crate::gate::MediaGate;
use crate::limits::{FETCH_RECHECK_BYTES, FETCH_RECHECK_INTERVAL, MAX_BLOB_BYTES};
use crate::pools::FetchPool;

/// An admitted fetch: the address served, its file, and the answer's permit.
///
/// The whole file is checked against its cell, and the permit is held until
/// this value drops — which the transport does after the last byte, at the
/// reset, or as a panic unwinds its frame. The file's bytes are what the
/// stream writes and nothing else; its length is the cell's `size`, by the
/// check.
pub struct Admitted<'a> {
    i: Address,
    bytes: Vec<u8>,
    _permit: Permit<'a>,
}

impl Admitted<'_> {
    /// Returns the address served.
    ///
    /// It is what the mid-stream re-check asks the gate about again.
    pub fn i(&self) -> &Address {
        &self.i
    }

    /// Returns the file's length: the cell's `size`, by the check.
    pub fn size(&self) -> u64 {
        self.bytes.len() as u64
    }

    /// Returns the file, whole.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// The blob the cell names: its hash as the cell spells it, and its size.
///
/// They are the cell's own members, carried on the two refusals that say
/// the store did not have it (`blob_missing`, `blob_damaged`). Data, never
/// prose: the face a person reads is the client's, composed from these
/// (PUB-6.7; the media record's "the missing-blob face"). The requester
/// could read both members at the address already, so the refusal
/// discloses nothing the gate did not admit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamedBlob {
    /// The cell's `hash`, 64 lowercase hex characters.
    pub hash: String,
    /// The cell's `size`.
    pub size: u64,
}

/// Why a fetch is refused: the refusals of the order's steps.
///
/// Each step that can refuse has its variants, in the order's own sequence
/// but for step 5's, listed last; the mapping onto the wire's status and
/// token is `server/reply.rs`'s (`refuse_fetch`), not this module's.
#[derive(Debug)]
pub enum FetchRefusal {
    /// Step 0: `i` is not an element position of a document.
    Shape(String),
    /// Steps 1–3: M10's own rejection of the read by identity.
    ///
    /// It is `withheld` naming the derived home, or any other code as `/op`
    /// answers it.
    Rejected(Rejection),
    /// Step 4: no value is minted at the address.
    NoValue,
    /// Step 4: the value names no media kind.
    ///
    /// It is prose, a def, a record of another kind.
    NotACell,
    /// Step 4: the value names a media kind under no schema this build reads.
    ///
    /// The kind is the picture's or the blind document's: D13's halt.
    UnknownCellSchema,
    /// Step 4: a blind document's cell.
    ///
    /// This board holds no byte of its picture, and no store is asked.
    BlindCell,
    /// Step 6: the store has no file under the cell's hash.
    BlobMissing(NamedBlob),
    /// Step 6: the store's file is not the deposit the cell names.
    ///
    /// It has the wrong length, a length past [`MAX_BLOB_BYTES`], or the
    /// wrong bytes under the right name.
    BlobDamaged(NamedBlob),
    /// Step 6: the store refused I/O.
    BlobIo(io::Error),
    /// Step 5: every fetch permit is in use.
    Busy,
}

/// Runs the fetch, steps 0 through 6: the module's order, run once.
///
/// `febe` is M10's front door and `session` the presented session the read
/// runs as ([`SessionId::GUEST`] where none was presented); `media_gate` is
/// the media gate, the daemon's media resource the file is read through;
/// `pool` the fetch pool the answer's permit comes from, which the
/// [`Admitted`] holds for as long as it lives; `i` the address asked for,
/// taken by value because the [`Admitted`] keeps it as the mid-stream
/// re-check's subject. Generic over the world M10 reads ([`FebeWorld`])
/// under the record lift M10's own `execute` requires of it — the bound
/// `skep-febe` writes, and no other; the daemon instantiates it at its
/// `World`.
///
/// # Errors
///
/// The refusal of the first step that refuses, in the order's sequence:
/// step 0's [`FetchRefusal::Shape`]; steps 1–3's [`FetchRefusal::Rejected`];
/// step 4's [`FetchRefusal::NoValue`], [`FetchRefusal::UnknownCellSchema`],
/// [`FetchRefusal::BlindCell`] or [`FetchRefusal::NotACell`]; step 5's
/// [`FetchRefusal::Busy`]; and step 6's [`FetchRefusal::BlobMissing`],
/// [`FetchRefusal::BlobDamaged`] or [`FetchRefusal::BlobIo`].
pub fn fetch<'a, W>(
    febe: &OperationSurface<W>,
    session: SessionId,
    media_gate: &MediaGate,
    pool: &'a FetchPool,
    i: Address,
) -> Result<Admitted<'a>, FetchRefusal>
where
    W: FebeWorld,
    W::Record: From<M3Rec> + From<M5Rec> + From<LinkRec> + From<ContentWrite> + From<ContentStretch>,
{
    // 0 — the shape: an element position of some document, or nothing is
    // asked of any store.
    if i.level() != Level::Element || document_of(&i).is_none() {
        return Err(FetchRefusal::Shape(format!(
            "i: '{}' names no element position of a document",
            i.tumbler()
        )));
    }
    // 1–3 — the gate: M10's read by identity, as the presented session.
    let value = read_by_identity(febe, session, &i).map_err(FetchRefusal::Rejected)?;
    let Some(value) = value else {
        return Err(FetchRefusal::NoValue);
    };
    // 4 — the classification, one parse for both kinds.
    let cell = match cell::classify(value.as_bytes()) {
        Class::Picture(Ok(cell)) => cell,
        Class::Picture(Err(_)) | Class::Blind(Err(_)) => {
            return Err(FetchRefusal::UnknownCellSchema)
        }
        Class::Blind(Ok(_)) => return Err(FetchRefusal::BlindCell),
        Class::None(_) => return Err(FetchRefusal::NotACell),
    };
    // 5 — the permit, for the whole answer.
    let permit = pool.admit().ok_or(FetchRefusal::Busy)?;
    // 6 — the whole file, checked against the cell before any byte of it
    // is answered.
    let bytes = read_whole(media_gate, &cell)?;
    Ok(Admitted { i, bytes, _permit: permit })
}

/// Returns whether the re-check's gate admits `i` (M-I2 (g)).
///
/// It is the read by identity run again as `session` — `true` where it
/// answers a value at `i`, `false` where M10 now withholds or rejects it, or
/// no value is minted there any more. The requester's own re-resolution
/// against the head is the route's, run before this.
pub fn gate_admits<W>(febe: &OperationSurface<W>, session: SessionId, i: &Address) -> bool
where
    W: FebeWorld,
    W::Record: From<M3Rec> + From<M5Rec> + From<LinkRec> + From<ContentWrite> + From<ContentStretch>,
{
    matches!(read_by_identity(febe, session, i), Ok(Some(_)))
}

/// Reads the one span `{i, 1}` by identity through M10, as `session`.
///
/// The answer is the value minted at `i`, or `None` where none is.
///
/// # Errors
///
/// M10's rejection of the read.
///
/// # Panics
///
/// Panics where `execute` answers the read with any shape but an
/// `i_delivery` or a rejection, which its own contract rules out.
fn read_by_identity<W>(
    febe: &OperationSurface<W>,
    session: SessionId,
    i: &Address,
) -> Result<Option<Val>, Rejection>
where
    W: FebeWorld,
    W::Record: From<M3Rec> + From<M5Rec> + From<LinkRec> + From<ContentWrite> + From<ContentStretch>,
{
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

/// Reads the store's file under the cell's hash, whole: step 6.
///
/// The file is held to the cell's `size` and `hash`. The length is read
/// first and held to the cell's and to [`MAX_BLOB_BYTES`] before a byte is
/// read, so no cell can command an allocation past that cap; one byte past
/// the length is asked for, so a file grown under the open reads as not the
/// deposit either.
///
/// # Errors
///
/// [`FetchRefusal::BlobMissing`] where there is no file;
/// [`FetchRefusal::BlobDamaged`] where what is there is not the deposit the
/// cell names, or is longer than [`MAX_BLOB_BYTES`];
/// [`FetchRefusal::BlobIo`] where opening, stating or reading the file
/// fails, but for its absence.
fn read_whole(media_gate: &MediaGate, cell: &cell::Cell) -> Result<Vec<u8>, FetchRefusal> {
    let hex = hex_string(&cell.hash);
    let named = || NamedBlob { hash: hex.clone(), size: cell.size };
    let Some(path) = media_gate.store().blob_path(DESIGNATION, &hex) else {
        return Err(FetchRefusal::BlobMissing(named()));
    };
    let mut file = match File::open(&path) {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Err(FetchRefusal::BlobMissing(named()))
        }
        Err(e) => return Err(FetchRefusal::BlobIo(e)),
    };
    let len = file.metadata().map_err(FetchRefusal::BlobIo)?.len();
    if len != cell.size || len > MAX_BLOB_BYTES {
        return Err(FetchRefusal::BlobDamaged(named()));
    }
    let mut bytes = Vec::with_capacity(len as usize);
    file.by_ref().take(len + 1).read_to_end(&mut bytes).map_err(FetchRefusal::BlobIo)?;
    if bytes.len() as u64 != len || *blake3::hash(&bytes).as_bytes() != cell.hash {
        return Err(FetchRefusal::BlobDamaged(named()));
    }
    Ok(bytes)
}

/// The stream's interval arithmetic (M-I2 (g)).
///
/// It holds the bytes written since the last re-check and the media gate's
/// clock at it. The re-check is due at whichever of the two bounds comes
/// first — the byte interval `limits::FETCH_RECHECK_BYTES`, or the time
/// interval `limits::FETCH_RECHECK_INTERVAL` on the media gate's clock, so a
/// suite drives the time bound through the clock seam and a reader draining
/// at a trickle holds no interval open past it but for the chunk being
/// written. The two intervals are this crate's own: the transport reads the
/// rule through this type alone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Progress {
    since_check: u64,
    checked_ms: u64,
}

impl Progress {
    /// Returns the arithmetic at the stream's open.
    ///
    /// `now_ms` is the media gate's clock: nothing is written since the
    /// gate's own answer, which stands as the first check.
    pub fn new(now_ms: u64) -> Progress {
        Progress { since_check: 0, checked_ms: now_ms }
    }

    /// Counts `n` more bytes written.
    pub fn advance(&mut self, n: u64) {
        self.since_check = self.since_check.saturating_add(n);
    }

    /// Returns whether a re-check is due at `now_ms`.
    ///
    /// It is due where the byte interval is reached, or the time interval has
    /// elapsed on the media gate's clock.
    pub fn due(&self, now_ms: u64) -> bool {
        self.since_check >= FETCH_RECHECK_BYTES
            || now_ms.saturating_sub(self.checked_ms) >= FETCH_RECHECK_INTERVAL.as_millis() as u64
    }

    /// Starts both intervals over: a re-check passed at `now_ms`.
    pub fn reset(&mut self, now_ms: u64) {
        self.since_check = 0;
        self.checked_ms = now_ms;
    }
}

/// The test seam's hold on every fetch stream between two of its chunks.
///
/// It is armed by a suite before its request, so the suite can kill the
/// session or revoke the grant while the stream stands and release it at
/// its own moment — the mid-stream re-check driven through a seam rather
/// than a race against the transport. Process-wide, as the cell index walk's
/// hold is; a `wait` while no hold is armed returns at once.
#[cfg(any(test, feature = "test-hooks"))]
#[doc(hidden)]
pub struct StreamHold {
    held: parking_lot::Mutex<bool>,
    released: parking_lot::Condvar,
}

/// The test seam's one hold on the stream, process-wide.
///
/// The transport waits on it between chunks in a `test-hooks` build.
#[cfg(any(test, feature = "test-hooks"))]
#[doc(hidden)]
pub static STREAM_HOLD: StreamHold =
    StreamHold { held: parking_lot::Mutex::new(false), released: parking_lot::Condvar::new() };

#[cfg(any(test, feature = "test-hooks"))]
impl StreamHold {
    /// Arms the hold: every stream parks between its chunks from here on.
    pub fn hold(&self) {
        *self.held.lock() = true;
    }

    /// Releases the hold: every parked stream proceeds.
    ///
    /// Later streams park only where the hold is armed again.
    pub fn release(&self) {
        *self.held.lock() = false;
        self.released.notify_all();
    }

    /// Parks the calling stream while the hold is armed: the stream's side.
    pub fn wait(&self) {
        let mut held = self.held.lock();
        while *held {
            self.released.wait(&mut held);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Checks that a re-check is due at whichever interval comes first.
    ///
    /// The arithmetic is not due under both bounds; due at exactly the byte
    /// interval, whatever the clock; due at exactly the time interval on the
    /// media gate's clock, whatever the bytes; a reset starts both over.
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

    /// Checks step 6 at the store.
    ///
    /// No file is `blob_missing` naming the cell; a file of the right length
    /// under the right name holding other bytes is `blob_damaged`; a file of
    /// the wrong length is `blob_damaged` before any byte of it is hashed;
    /// the deposit as written is answered whole.
    #[test]
    fn the_whole_file_is_held_to_the_cell_before_its_first_byte() {
        let dir = tempfile::tempdir().expect("tempdir");
        let media_gate = MediaGate::open(dir.path()).expect("the store opens");
        let bytes = b"the picture's bytes";
        let cell = cell::Cell { hash: *blake3::hash(bytes).as_bytes(), size: bytes.len() as u64 };
        let named = NamedBlob { hash: hex_string(&cell.hash), size: cell.size };
        assert!(
            matches!(
                read_whole(&media_gate, &cell),
                Err(FetchRefusal::BlobMissing(f)) if f == named
            ),
            "no file under the cell's hash"
        );
        let path = media_gate.store().blob_path(DESIGNATION, &named.hash).expect("a path");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"the picture's bytez").unwrap();
        assert!(
            matches!(
                read_whole(&media_gate, &cell),
                Err(FetchRefusal::BlobDamaged(f)) if f == named
            ),
            "other bytes, the right length"
        );
        std::fs::write(&path, b"short").unwrap();
        assert!(
            matches!(
                read_whole(&media_gate, &cell),
                Err(FetchRefusal::BlobDamaged(f)) if f == named
            ),
            "the wrong length"
        );
        std::fs::write(&path, bytes).unwrap();
        assert_eq!(read_whole(&media_gate, &cell).expect("the deposit as written"), bytes);
        let past = cell::Cell { hash: cell.hash, size: MAX_BLOB_BYTES + 1 };
        assert!(
            matches!(read_whole(&media_gate, &past), Err(FetchRefusal::BlobDamaged(_))),
            "a size past the cap names no deposit"
        );
    }

    /// Checks that the stream hold parks only while armed.
    ///
    /// A wait while no hold is armed returns at once, and a release wakes a
    /// parked wait.
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
