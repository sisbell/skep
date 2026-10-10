//! # skep-util — the support crate below the daemon and the media crate
//!
//! Four utilities `skepd` and `skep-media` both take and neither owns, in
//! one home, so the media crate's move out of the daemon copies no helper
//! and the daemon's five pools keep one permit type:
//!
//! * [`permits`] — the counting permit pool: a try-acquire with no queue
//!   and no blocking, whose guard returns its slot on drop. One mechanism
//!   behind the daemon's five bounded pools; a permit is a slot of the pool
//!   that minted it, so no bound can spend another's. Beside it, the edge
//!   tracker: the once-per-episode memory of a bound that refuses — the
//!   first refusal an edge, the clearing an edge once the condition has
//!   stood clear for a hold-down — which the five pools, the daemon's
//!   stream budget, its challenge store and its accept loop each hold, and
//!   the one clock their hold-down is judged against.
//! * [`notice`] — the operator's stream: one line, or one notice of several
//!   lines, every line opening with the program's name and the head carrying
//!   its time, handed to one thread that writes them in order — so that a
//!   failed write never panics the work the notice is about, and a stalled
//!   reader never waits it.
//! * [`json`] — the determinism helpers: [`json::obj`], the key-sorting
//!   object builder every JSON object the daemon emits goes through;
//!   [`json::hex_string`], lowercase hex; [`json::parse_lower_hex`] and
//!   [`json::hex_nibble`], its exact inverse at a fixed width, refusing
//!   what `hex_string` never writes.
//! * [`source`] — [`source::Source`], where a setting's value in force came
//!   from: the default, a flag, a variable — carried beside the value on
//!   the daemon's session-layer options and the media crate's upload
//!   setting, so the open's report names each setting's source.
//!
//! ## The rule of membership
//!
//! An item lives here if and only if BOTH `skepd` and `skep-media` take it
//! AND it has no subject of its own. A constant is configuration, not a
//! utility — the limits the two crates share are the media crate's own
//! public numbers, and the daemon's stay the daemon's — so none lives here.
//! A setting's SOURCE is the rule's positive case beside the permit: both
//! crates' option types carry one, and whether a value came from a flag or
//! a variable is a fact about the parse, the subject of neither crate. The
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

pub mod json;
pub mod notice;
pub mod permits;
pub mod source;
