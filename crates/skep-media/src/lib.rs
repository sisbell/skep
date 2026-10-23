//! The media door and gate, the cell beneath them, the index and the pruner.
//!
//! Their rules are the media record's (`media.md` item 4, §The publication
//! seam, Op inventory 1 and 2, §The media stores) and the register's (M-I1
//! (a), (f), M-I2 (e), M-I3 (a), M-I5 (a)–(c), (f), M-I6 (a)–(c), (e)). The
//! tree is a crate of its own, `skep-media`, the cell and the door with it.
//!
//! A picture is a document whose content is one reference cell — a composite
//! value whose bytes are one JSON object naming its kind (DOCTRINE D13).
//! This crate holds the daemon's media decisions: [`cell`], the cell's one
//! parser under the one canonical rule; [`door`], the one step of the plain
//! write sequence that acts on what that parser answers — `published_target`
//! at a published target whatever the declaration, the shot's owner test,
//! and the binding: a cell is admitted where its hash is one the requester's
//! own cells already name, or one this principal deposited under its own
//! live lease, and its file is whole at the cell's size; [`gate`], the media
//! gate, the daemon's media resource — the blob store (`skep-blobs`, the four
//! stores under `blobs/`), the limits in force with their daemon default and
//! install hook, the hold a stream has on its upload, the three scopes and
//! the standing-uploads bound a PUT is refused on, the deposit's terms its
//! creation and finish apply, the floor it keeps from the checkpoints the
//! daemon notes, and the binding's read, a deposit's file the store cannot
//! read said at the condition's edges and re-said by the standing line;
//! [`index`], the cell index — per hash the cells naming it, per account the
//! distinct hashes its cells name at their size (the base) — entered at
//! every commit that mints a cell and rebuilt whole at every open on a
//! thread, its three readers refusing until that walk completes — or, where
//! that walk died, failed for the life of the process, the third state
//! beside ready and not-ready (`operations.md` §4 row 26); [`pruner`], the
//! pruner, one per daemon, and its pass that removes expired partials and
//! takes the files no cell names and no live lease holds, one file per
//! acquisition of the credential lock's exclusive arm — renamed aside under
//! it, unlinked after it — halting on a schema it does not know;
//! `cell::blind`, the blind document's cell, the second kind beside the
//! picture's — a commitment and nothing the daemon can read a file by — a
//! child of [`cell`], under the one classification it holds for both;
//! [`limits`], the resource's own numbers, each `pub` where another crate
//! reads it; and [`serve`], the fetch's composed order (Op inventory 3; the
//! register M-I2 (a)–(d), (g), M-I3 (b), M-I5 (f), M-I7 (a), (b)): the shape,
//! M10's read by identity as the gate, the classification, the permit, the
//! whole file checked against the cell before its first byte, the permit
//! spanning the answer — what `GET /blob?i=` (`server/blob_routes.rs`) runs
//! and the transport streams, re-resolving the requester at an interval.
//! And [`pools`], the two permit pools: the fetch pool a fetch's permit
//! comes from, and its twin the upload pool ([`pools::UploadPool`]; Op
//! inventory 1, "an upload is admitted at most an upload permit pool at
//! once"; M-I5 (f)), whose permit the PUT's creation and resume hold for a
//! body's whole stream — both counted into the daemon's worker minimum
//! beside its own three pools. Each says its edge pair (`operations.md`
//! §1.1 m12) — its saturation when a request first meets it, its room again
//! once it has stood clear for the daemon's hold-down — through the gate's
//! classed door, and nothing per request. The deposit read — the one read
//! of a principal's own deposits and uploads, its base the index's number —
//! is the daemon's own route helper (`skepd`'s `server/blob_routes.rs`),
//! built off this gate's reads.
//!
//! The media gate, the door, the index, the pruner, the pools and the serve
//! sit at the write path's layer (`ARCHITECTURE.md` §The media resource,
//! §The daemon), the daemon's second resource beside it — a crate of its
//! own below the daemon and above the stores, generic over the world M10
//! reads (`skep_febe::FebeWorld`, the one bound) and naming no engine, the
//! daemon instantiating every world parameter at its `World`: the door
//! reads the lease store, `blobs/` and the index through the media gate,
//! which no producer of the session layer's admission may, so it is a step
//! of its own; the write path enters the index at commit, a sideways step
//! at its own layer; the PUT's routes (`server/blob_routes.rs`) reach the
//! media gate as `op.rs` reaches the write path, and the PUT commits nothing
//! to the journal and takes no `Serial` — the finish runs under the
//! credential lock's read arm from the rename through the lease's sync, the
//! pruner's rename-aside under its write arm; the serve reads a file through
//! the media gate's store and consults nothing itself — the fetch's gate is
//! M10's `execute`. The two cells are leaves.
//!
//! The upload setting ([`MediaOptions`]; `media.md` Op inventory 1, "only on
//! a board whose uploads are open"; the register M-I7 (e)) is a boundary
//! setting of the daemon's, as `--local-trust` is (PATTERNS P37), carried on
//! the media resource and echoed on `/health` as the `media` object, so a
//! client keys the fence-only face off the echo before any face that names
//! an upload speaks. It is open by default, with the default per-account
//! limit in force from start; off, the upload's creation and its resume are
//! refused `upload_refused` with `detail` `uploads_closed` before any body
//! byte, the upload kept where one stood, and every read, the termination,
//! the door's binding and the pruner's pass are served as they are with
//! uploads open.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

// The cell: its schema, its one parser, its encoder, its designation and the
// pinned set of them — and the one classification of every media kind, the
// canonical opening read past the cap among it, with its child `blind`, the
// blind document's cell, the second kind.
pub mod cell;
// The door: the one step, its armed set.
pub mod door;
// The media gate: the store, the limits, the hold, the scopes, the binding.
pub mod gate;
// The index: per hash the cells, per account the base; the walk at open.
pub mod index;
// The limits: the resource's eleven numbers, each `pub` where another crate
// reads it.
pub mod limits;
// The pools: the fetch pool and its twin the upload pool, each saying its
// edge pair through the gate's classed door.
pub mod pools;
// The pruner: the pass as one daemon runs it, its halts, its cadence.
pub mod pruner;
// The serve: the fetch's composed order, its answer and refusals, the
// stream's interval arithmetic.
pub mod serve;

use skep_util::source::Source;

/// The media resource's configuration, as the operator supplies it.
///
/// It is the upload setting, `--no-uploads` (`SKEPD_UPLOADS=false`):
/// `uploads` open by default, and beside it where the setting came from
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
    /// Whether the upload family is open.
    ///
    /// Open is the creation and the resume admitted. Off, both answer
    /// `403 upload_refused` with `detail` `uploads_closed` before any body
    /// byte; nothing else of the family or the door moves.
    pub uploads: bool,
    /// Where `uploads` came from, as the binary's parse recorded it.
    ///
    /// It is the default, the flag (`--uploads` / `--no-uploads`) or the
    /// variable (`SKEPD_UPLOADS`); `Source::Default` from a caller that sets
    /// the switch and names no source, which the daemon's line then says.
    pub uploads_source: Source,
}

impl Default for MediaOptions {
    fn default() -> MediaOptions {
        MediaOptions { uploads: true, uploads_source: Source::Default }
    }
}
