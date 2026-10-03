//! THE MEDIA DOOR, THE GATE and the cell beneath them (media lanes A and B
//! — STOP-2's write-path half, fenced before the first served board, and
//! the stores, the PUT and the lease behind it: the media record `media.md`
//! item 4, §The publication seam, Op inventory 1 and 2, §The media stores;
//! the register M-I1 (a), (f), M-I2 (e), M-I3 (a), M-I5 (a), (c), M-I6
//! (a)–(c), (e); the owner's rulings sm-Q1, STOP-2 "take i", mb-crate).
//!
//! A picture is a document whose content is ONE REFERENCE CELL — a composite
//! value whose bytes are one JSON object naming its kind (DOCTRINE D13).
//! This module holds the daemon's media decisions: [`cell`], the cell's one
//! parser under the one canonical rule; [`door`], the one step of the plain
//! write sequence that acts on what that parser answers — `published_target`
//! at a published target whatever the declaration, the shot's owner test,
//! and THE BINDING: a cell is admitted only where its hash is one this
//! principal deposited under its own live lease; [`gate`], the daemon's
//! media resource — the blob store (`skep-blobs`, the four stores under
//! `blobs/`), the limits in force with their daemon default and install
//! hook, the hold a stream has on its upload, the three scopes a PUT is
//! refused on, and the binding's read; and [`deposit_read`], the one read
//! of a principal's own deposits and uploads. Nothing here serves a byte:
//! the fetch route is lane D's, the cell index and the pruner lane C's.
//!
//! The gate and the door sit at the write path's layer (`ARCHITECTURE.md`
//! §The daemon), the daemon's second resource beside it: the door reads the
//! lease store and `blobs/` through the gate, which no producer of the
//! session layer's admission may, so it is a step of its own; the PUT's
//! routes (`server/blob_routes.rs`) reach the gate as `op.rs` reaches the
//! write path, and the PUT commits nothing to the journal and takes no
//! `Serial` — the finish runs under the credential lock's READ arm from the
//! rename through the lease's sync. The cell is a leaf.

// The cell: its schema, its one parser, its encoder, its designation.
pub(crate) mod cell;
// The deposit read: one read of the principal's own records.
pub(crate) mod deposit_read;
// The door: the one step, its armed set.
pub(crate) mod door;
// The gate: the store, the limits, the hold, the scopes, the binding.
pub(crate) mod gate;
