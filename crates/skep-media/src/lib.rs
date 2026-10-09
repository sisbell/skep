//! THE MEDIA DOOR, THE MEDIA GATE and the cell beneath them, THE CELL INDEX
//! and THE PRUNER beside them (the media record `media.md` item 4, §The
//! publication seam, Op inventory 1 and 2, §The media stores; the register
//! M-I1 (a), (f), M-I2 (e), M-I3 (a), M-I5 (a)–(c), (f), M-I6 (a)–(c),
//! (e); the owner's rulings sm-Q1, STOP-2 "take i", mb-crate as the crate
//! ruling of 2026-10-07 re-cut it — the tree is a crate of its own,
//! `skep-media`, the cell and the door with it — ms5-R, ms5-T4, mb-K2).
//!
//! A picture is a document whose content is ONE REFERENCE CELL — a composite
//! value whose bytes are one JSON object naming its kind (DOCTRINE D13).
//! This crate holds the daemon's media decisions: [`cell`], the cell's one
//! parser under the one canonical rule; [`door`], the one step of the plain
//! write sequence that acts on what that parser answers — `published_target`
//! at a published target whatever the declaration, the shot's owner test,
//! and THE BINDING: a cell is admitted where its hash is one the requester's
//! own cells already name, or one this principal deposited under its own
//! live lease; [`gate`], the media gate, the daemon's media resource — the blob store
//! (`skep-blobs`, the four stores under `blobs/`), the limits in force with
//! their daemon default and install hook, the hold a stream has on its
//! upload, the three scopes a PUT is refused on, and the binding's read;
//! [`index`], THE CELL INDEX — per hash the cells naming it, per account the
//! distinct hashes its cells name at their size (the base) — entered at
//! every commit that mints a cell and rebuilt whole at every open on a
//! thread, its three readers refusing until that walk completes; [`pruner`],
//! THE PASS that removes expired partials and, under the credential lock's
//! exclusive arm one file at a time, unlinks the files no cell names and no
//! live lease holds, halting on a schema it does not know; `blind`, THE
//! BLIND DOCUMENT's CELL, the second kind beside the picture's — a
//! commitment and nothing the daemon can read a file by — under the one
//! classification [`cell`] holds for both; [`limits`], the resource's own
//! numbers, the four the daemon reads too among them; and [`serve`], THE
//! FETCH's COMPOSED ORDER (Op inventory 3; the register M-I2 (a)–(d), (g),
//! M-I3 (b), M-I5 (f), M-I7 (a), (b)): the shape, M10's read by identity as
//! the gate, the classification, the permit, the whole file checked against
//! the cell before its first byte, the permit spanning the answer — what
//! `GET /blob?i=` (`server/blob_routes.rs`) runs and the transport streams,
//! re-resolving the requester at an interval. And beside the fetch's pool,
//! THE UPLOAD POOL ([`UploadPool`]; Op inventory 1, "AN UPLOAD IS ADMITTED
//! AT MOST AN UPLOAD PERMIT POOL AT ONCE"; M-I5 (f)): the fetch pool's twin,
//! whose permit the PUT's creation and resume hold for a body's whole
//! stream, counted into the worker budget beside the three other pools. The
//! deposit read — the one read of a principal's own deposits and uploads,
//! its base the index's number — is the daemon's own route helper
//! (`skepd`'s `server/blob_routes.rs`), built off this gate's reads.
//!
//! The media gate, the door, the index, the pruner and the serve sit at the
//! write path's layer (`ARCHITECTURE.md` §The media resource, §The daemon),
//! the daemon's second resource beside it — A CRATE OF ITS OWN below the
//! daemon and above the stores, GENERIC OVER THE WORLD M10 reads
//! (`skep_febe::FebeWorld`, the one bound) and naming no engine, the daemon
//! instantiating every world parameter at its `World`: the door reads the
//! lease store, `blobs/` and the index through the media gate, which no
//! producer of the session layer's admission may, so it is a step of its
//! own; the write path enters the index at commit, a sideways step at its
//! own layer; the PUT's routes (`server/blob_routes.rs`) reach the media
//! gate as `op.rs` reaches the write path, and the PUT commits nothing to
//! the journal and takes no `Serial` — the finish runs under the credential
//! lock's READ arm from the rename through the lease's sync, the pruner's
//! rename-aside under its WRITE arm; the serve reads a file through the
//! media gate's store and consults nothing itself — the fetch's gate is
//! M10's `execute`. The two cells are leaves.
//!
//! THE UPLOAD SETTING ([`MediaOptions`]; `media.md` Op inventory 1, "ONLY
//! ON A BOARD WHOSE UPLOADS ARE OPEN"; the register M-I7 (e)): a boundary
//! setting of the daemon's, as `--local-trust` is (PATTERNS P37), carried
//! on the media resource and ECHOED on `/health` as the `media` object, so
//! a client keys the fence-only face off the echo before any face that
//! names an upload speaks. OPEN by default (the owner's ruling), with the
//! default per-account limit in force from start; OFF, the upload's
//! creation and its resume are refused `upload_refused` with `detail`
//! `uploads_closed` before any body byte, the upload kept where one stood,
//! and every read, the termination, the door's binding and the pruner's
//! pass are served as before.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use skep_util::permits::{Permit, Permits};
use skep_util::source::Source;

use crate::limits::MAX_CONCURRENT_UPLOADS;

/// The media resource's configuration, as the operator supplies it — the
/// upload setting, `--no-uploads` (`SKEPD_UPLOADS=false`): `uploads` OPEN
/// by default, and beside it WHERE the setting came from
/// (`uploads_source`), so the open's report names the switch with its
/// source (`operations.md` §1.1 row 8). `#[non_exhaustive]` and paired
/// with [`Default`] for the reason `skepd::AuthOptions` is: a caller starts
/// from the defaults and sets what it means to change, so a knob added
/// later arrives at its default rather than breaking every construction.
/// Daemon config, never board state: in no record, journal, sidecar or
/// fold; `/health` echoes the switch as `media.uploads`, and nothing of its
/// source.
///
/// ```
/// use skep_media::MediaOptions;
///
/// let mut media = MediaOptions::default();
/// media.uploads = false;
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct MediaOptions {
    /// Whether the upload family is OPEN: the creation and the resume
    /// admitted. OFF, both answer `403 upload_refused` with `detail`
    /// `uploads_closed` before any body byte; nothing else of the family or
    /// the door moves.
    pub uploads: bool,
    /// Where `uploads` came from — the default, the flag (`--uploads` /
    /// `--no-uploads`) or the variable (`SKEPD_UPLOADS`) — as the binary's
    /// parse recorded it; `Source::Default` from a caller that sets the
    /// switch and names no source, which the daemon's line then says.
    pub uploads_source: Source,
}

impl Default for MediaOptions {
    fn default() -> MediaOptions {
        MediaOptions { uploads: true, uploads_source: Source::Default }
    }
}

/// THE UPLOAD POOL — the fourth instance of [`skep_util::permits`]'s mechanism
/// and the fetch pool's twin ([`serve::FetchPool`]), disjoint from the
/// reconstruction, class-scan and fetch pools by the borrow: a [`Permit`]
/// names the pool that issued it, so no upload spends a slot of theirs and
/// none of them spends one of these. [`MAX_CONCURRENT_UPLOADS`] slots, one
/// per creation or resume of `/blob/upload` for the request's whole life —
/// the body's stream, the finish included (`server/blob_routes.rs`, THE
/// PERMIT) — so what the pool bounds is how many workers the family holds
/// at once (M-I5 (f): PICTURES NEVER STARVE OR STALL THE JOURNAL — bounded
/// by a pool, never a queue). A drained pool REFUSES, never queues (ms5-R:
/// nothing of the family waits), and is asked or refused, never told (D9).
pub struct UploadPool(Permits);

impl UploadPool {
    /// The pool at its count, [`MAX_CONCURRENT_UPLOADS`], every slot free.
    pub fn new() -> UploadPool {
        UploadPool(Permits::new(MAX_CONCURRENT_UPLOADS))
    }

    /// One permit for a whole request, or `None` right now — never blocks.
    #[must_use = "a permit dropped at once returns its slot at once: bind it for the request's \
                  whole life"]
    pub fn admit(&self) -> Option<Permit<'_>> {
        self.0.try_acquire()
    }

    /// TEST HOOK, reached through `Daemon::try_hold_upload_permit`: hold one
    /// permit exactly as an in-flight creation or resume does.
    #[cfg(any(test, feature = "test-hooks"))]
    #[doc(hidden)]
    #[must_use = "a permit dropped at once holds nothing"]
    pub fn try_hold(&self) -> Option<Permit<'_>> {
        self.0.try_acquire()
    }
}

// The cell: its schema, its one parser, its encoder, its designation — and
// the one classification of every media kind, the canonical opening read
// past the cap among it.
pub mod cell;
// The blind document's cell: the second kind, a commitment and nothing else.
// Reached by no caller outside this crate: the daemon reads a blind cell
// through the one classification alone.
pub(crate) mod blind;
// The door: the one step, its armed set.
pub mod door;
// The media gate: the store, the limits, the hold, the scopes, the binding.
pub mod gate;
// The index: per hash the cells, per account the base; the walk at open.
pub mod index;
// The limits: the resource's eleven numbers, the daemon's four readers
// among their takers.
pub mod limits;
// The pruner: the pass, its halts, its cadence.
pub mod pruner;
// The serve: the fetch's composed order, its pool, its answer and refusals,
// the stream's interval arithmetic.
pub mod serve;
