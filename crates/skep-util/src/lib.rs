//! # skep-util — the support crate below the daemon and the clients
//!
//! Five utilities two or more crates of the workspace take and none owns —
//! the daemon, the media crate, the client library and the shell's core
//! stand above it — in one home, so the media crate's move out of the
//! daemon copies no helper, the daemon's five pools keep one permit type,
//! and the client's and the shell's files keep one tail rule:
//!
//! * [`permits`] — the counting permit pool: a try-acquire with no queue
//!   and no blocking, whose guard returns its slot on drop. One mechanism
//!   behind the daemon's five bounded pools; a permit is a slot of the pool
//!   that minted it, so no bound can spend another's. Beside it, the edge
//!   tracker: the once-per-episode memory of a bound that refuses — the
//!   first refusal an edge, the clearing an edge once the condition has
//!   stood clear for a hold-down — which the five pools, the daemon's
//!   worker pool, its stream budget and its streams' threads, its challenge
//!   store and its accept loop each hold, and the one clock their hold-down
//!   is judged against.
//! * [`notice`] — the operator's stream: one line, or one notice of several
//!   lines, every line opening with the program's name and the head carrying
//!   its time, handed to one thread that writes them in order — so that a
//!   failed write never panics the work the notice is about, a stalled
//!   reader never waits it, and the drain at an exit waits on a stalled
//!   reader for the caller's bound and no longer.
//! * [`json`] — the determinism helpers: [`json::obj`], the key-sorting
//!   object builder every JSON object the daemon emits goes through;
//!   [`json::hex_string`], lowercase hex; [`json::parse_lower_hex`] and
//!   [`json::hex_nibble`], its exact inverse at a fixed width, refusing
//!   what `hex_string` never writes.
//! * [`source`] — [`source::Source`], where a setting's value in force came
//!   from: the default, a flag, a variable — carried beside the value on
//!   the daemon's session-layer options and the media crate's upload
//!   setting, so the open's report names each setting's source.
//! * [`file`](mod@file) — a file one process writes and reads back after
//!   a crash, a kill or a refused write, under one tail rule: a read that
//!   hands back a file's lines as bytes and classifies its tail, an append written
//!   where the last whole line ends with a torn tail first cut off or
//!   closed by a mark, a whole file written once or published by a locked
//!   temp and a rename, a removal that answers what it did, and the sweep
//!   of the temps a dead run left — the client's key store, bindings file
//!   and anchor export and the shell's held-writes file take it.
//!
//! ## The rule of membership
//!
//! An item lives here if and only if at least two crates take it and it
//! has no subject of its own. A constant is configuration, not a utility —
//! the limits the two daemon crates share are the media crate's own public
//! numbers, and the daemon's stay the daemon's; the bound a client file's
//! line keeps is that file's own — so none lives here. A setting's SOURCE
//! is the rule's positive case beside the permit: both daemon crates'
//! option types carry one, and whether a value came from a flag or a
//! variable is a fact about the parse, the subject of neither crate. The
//! crate names no store and no engine; it depends on `serde_json` and
//! `std` alone, and on nothing of skep.
//!
//! ## The program's name
//!
//! Every notice line opens `skepd: `, spelled in this library — a decision,
//! not an oversight. The prefix names the PROCESS a shared stream attributes
//! a line to, and in this workspace exactly one program writes the
//! operator's stream: the daemon, as the shipped `skepd` binary and as the
//! `Skepd` library an embedder or a suite runs in-process under the same
//! name. `skep-media` is a component of that process and of no other. A
//! name handed in at each call would make the media crate spell the
//! daemon's name or be told it, for no line that would read differently; a
//! name installed once by the binary's `main` would leave every in-process
//! daemon unprefixed. So the name is a constant of [`notice`], spelled once;
//! a second program linking this crate makes it a parameter then, and the
//! call sites' shape stays. `notice`'s unit test pins the bytes.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod file;
pub mod json;
pub mod notice;
pub mod permits;
pub mod source;
