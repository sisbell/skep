//! THE MEDIA DOOR and the cell beneath it (media lane A — STOP-2's
//! write-path half, fenced before the first served board: the media record
//! `media.md` item 4, §The publication seam and Op inventory 2; the register
//! M-I1 (a), (f) and M-I3 (a); the owner's rulings sm-Q1 and STOP-2 "take
//! i").
//!
//! A picture is a document whose content is ONE REFERENCE CELL — a composite
//! value whose bytes are one JSON object naming its kind (DOCTRINE D13).
//! This module holds the daemon's media decisions as far as lane A builds
//! them: [`cell`], the cell's one parser under the one canonical rule, and
//! [`door`], the one step of the plain write sequence that acts on what
//! that parser answers — `published_target` at a published target whatever
//! the declaration, the shot's owner test, and the two refusals a draft's
//! cell meets while no upload exists. Nothing here serves, stores or hashes
//! a byte: the upload, the blob store, the lease, the index and the fetch
//! route are lanes B, C and D, and no cell lands on any board of this build.
//!
//! The door sits at the write path's layer (`ARCHITECTURE.md` §The daemon):
//! from lane B it reads the lease store and `blobs/`, which no producer of
//! the session layer's admission may — those are pure functions of the
//! locked snapshot and the op — so it is a step of its own from the first
//! lane and stays where it is placed. The cell is a leaf.

// The cell: its schema, its one parser, its encoder, its designation.
pub(crate) mod cell;
// The door: the one step, its armed set.
pub(crate) mod door;
