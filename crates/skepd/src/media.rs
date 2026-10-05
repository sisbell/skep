//! THE MEDIA DOOR, THE GATE and the cell beneath them, THE CELL INDEX and
//! THE PRUNER beside them (the media record `media.md` item 4, §The
//! publication seam, Op inventory 1 and 2, §The media stores; the register
//! M-I1 (a), (f), M-I2 (e), M-I3 (a), M-I5 (a)–(c), (f), M-I6 (a)–(c),
//! (e); the owner's rulings sm-Q1, STOP-2 "take i", mb-crate, ms5-R,
//! ms5-T4, mb-K2).
//!
//! A picture is a document whose content is ONE REFERENCE CELL — a composite
//! value whose bytes are one JSON object naming its kind (DOCTRINE D13).
//! This module holds the daemon's media decisions: [`cell`], the cell's one
//! parser under the one canonical rule; [`door`], the one step of the plain
//! write sequence that acts on what that parser answers — `published_target`
//! at a published target whatever the declaration, the shot's owner test,
//! and THE BINDING: a cell is admitted where its hash is one the requester's
//! own cells already name, or one this principal deposited under its own
//! live lease; [`gate`], the daemon's media resource — the blob store
//! (`skep-blobs`, the four stores under `blobs/`), the limits in force with
//! their daemon default and install hook, the hold a stream has on its
//! upload, the three scopes a PUT is refused on, and the binding's read;
//! [`index`], THE CELL INDEX — per hash the cells naming it, per account the
//! distinct hashes its cells name at their size (the base) — entered at
//! every commit that mints a cell and rebuilt whole at every open on a
//! thread, its three readers refusing until that walk completes; [`pruner`],
//! THE PASS that removes expired partials and, under the credential lock's
//! exclusive arm one file at a time, unlinks the files no cell names and no
//! live lease holds, halting on a schema it does not know; and
//! [`deposit_read`], the one read of a principal's own deposits and uploads,
//! its base the index's number; [`blind`], THE BLIND DOCUMENT's CELL, the
//! second kind beside the picture's — a commitment and nothing the daemon
//! can read a file by — under the one classification [`cell`] holds for
//! both; and [`serve`], THE FETCH's COMPOSED ORDER (Op inventory 3; the
//! register M-I2 (a)–(d), (g), M-I3 (b), M-I7 (a), (b)): the shape, M10's
//! read by identity as the gate, the classification, the permit, the whole
//! file checked against the cell before its first byte, the permit spanning
//! the answer — what `GET /blob?i=` (`server/blob_routes.rs`) runs and the
//! transport streams, re-resolving the requester at an interval.
//!
//! The gate, the door, the index, the pruner and the serve sit at the write
//! path's layer (`ARCHITECTURE.md` §The daemon), the daemon's second
//! resource beside it: the door reads the lease store, `blobs/` and the
//! index through the gate, which no producer of the session layer's
//! admission may, so it is a step of its own; the write path enters the
//! index at commit, a sideways step at its own layer; the PUT's routes
//! (`server/blob_routes.rs`) reach the gate as `op.rs` reaches the write
//! path, and the PUT commits nothing to the journal and takes no `Serial` —
//! the finish runs under the credential lock's READ arm from the rename
//! through the lease's sync, the pruner's unlink under its WRITE arm; the
//! serve reads a file through the gate's store and consults nothing itself
//! — its gate is M10's `execute`. The two cells are leaves.

// The cell: its schema, its one parser, its encoder, its designation — and
// the one classification of every media kind.
pub(crate) mod cell;
// The blind document's cell: the second kind, a commitment and nothing else.
pub(crate) mod blind;
// The deposit read: one read of the principal's own records.
pub(crate) mod deposit_read;
// The door: the one step, its armed set.
pub(crate) mod door;
// The gate: the store, the limits, the hold, the scopes, the binding.
pub(crate) mod gate;
// The index: per hash the cells, per account the base; the walk at open.
pub(crate) mod index;
// The pruner: the pass, its halts, its cadence.
pub(crate) mod pruner;
// The serve: the fetch's composed order, its pool, its answer and refusals,
// the stream's interval arithmetic.
pub(crate) mod serve;
