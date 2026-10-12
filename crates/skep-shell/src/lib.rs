//! # skep-shell — the shell's core, written once
//!
//! The bridge of `client.md` §4b — "the contract between the bundled app's
//! shell and its page" — as a library over `skep-client`: [`Shell`] answers
//! every call of §4b.1 through ONE DOOR, [`Shell::call`], which logs each,
//! and pushes every event of §4b.2 on one stream; and the three things the
//! library does not hold and every shell needs are written here once, so
//! the dev provider (`skep-dev serve`) and the desktop shell share them and
//! rewrite the transport alone. A transport reaches the crate through this
//! root — [`Shell`] and what opens it, [`Refusal`], [`Log`], [`Talk`],
//! [`CALLS`] — and three public modules, [`events`], [`script`] and
//! [`shapes`]; the rest is private. The modules, in the order they are
//! declared, each naming only those above it:
//!
//! * `refs` — THE REFERENCE REGISTRY's names (§4b.1, THE PIN): a board
//!   reference and a session reference are opaque NAMES this process mints
//!   from OS entropy, never a credential, never derived from an origin or a
//!   token, valid in this process alone.
//! * `log` — [`Log`], the call log and the dial log the page's gate reads
//!   (the structure record §6.3's class 5): every call the page made and
//!   every dial the shell made, sizes and timing, never a token or a body.
//! * [`events`] — THE EVENT STREAM: every §4b.2 event as a value, fanned
//!   out to every subscriber.
//! * `refusal` — [`Refusal`], the one refusal shape the page renders: the
//!   board's own verdict verbatim, a halt's face, the block, the
//!   unreachable board, and the shell's own armed refusals, each named by
//!   ONE token from one closed list.
//! * [`script`] — THE DEV ARM's SCRIPT: the grammar a script file's answers
//!   are parsed by.
//! * `dev_arm` — THE DEV ARM for the SECRET and CONSENT moments (§4b.3): a
//!   script's answers in order, or an auto-answer, each answer said on the
//!   TALK stream and never sent to the page.
//! * `person` — THE PERSON OVER THE BRIDGE: a `Person` whose PUBLIC
//!   moments become `moment(id, kind, data)` events and block on a channel
//!   the page's `answer(id, …)` or `cancel(id)` fills, and whose SECRET and
//!   CONSENT moments go to the dev arm.
//! * `attest` — THE PUBLISH-CLASS ATTEST a signed session composes
//!   (t5: "signs where signed ops requires"): the entry frame over the ten
//!   kinds that have one, each axis composed by the shell from its own
//!   reads and never from a preimage the page supplies.
//! * `sessions` — THE SESSION TABLE: every token this shell holds under
//!   the reference the page holds, the two openings (bare, signed), and a
//!   session's END — one sequence, whichever hand met the death signal —
//!   with the arm a `session-died` carries, derived from public reads as
//!   §4b.2 says.
//! * `feed` — THE FEED CONSUMER's thread per board: `search::Consumer`
//!   polled on each `/events` commit, the `/changes` pages re-read for the
//!   `feed` events, the `index`, `mode` and `daemon` events as the state
//!   moves, and the bridge's `search` call answered off it.
//! * `shell` — [`Shell`]: the boards, the sessions, the session mode
//!   (bare as the claimant, or signed with a dev key), and one private
//!   method per §4b.1 row behind [`Shell::call`], each taking and answering
//!   values shaped exactly as the row's columns; [`Shell::fetch`] is public
//!   beside it because it streams, and its transport logs it.
//! * [`shapes`] — THE DECLARATIONS: [`shapes::declarations`], a TypeScript
//!   declaration file for every value that crosses the bridge, pinned by a
//!   test that round-trips each type's JSON against the declared fields.
//!
//! The crate honours `skep-client`'s own rule — no async runtime, no HTTP
//! crate, no argument-parsing crate: std alone beside the workspace's
//! crates — and holds no transport: the loopback server is the dev verb's,
//! the native bridge the shell's. `ARCHITECTURE.md` §The shell's core draws
//! how the modules fit and the rules that cross them, and `tests/it/tidy.rs`
//! holds the declaration order and the three public modules to it.

#![forbid(unsafe_code)]

use std::sync::Arc;

mod refs;
mod log;
pub mod events;
mod refusal;
pub mod script;
mod dev_arm;
mod person;
mod attest;
mod sessions;
mod feed;
mod shell;
pub mod shapes;

pub use events::{Event, EventBus};
pub use log::Log;
pub use refusal::Refusal;
pub use shell::{ArmConfig, Fetched, NodeState, SessionMode, Shell, ShellOptions, CALLS};

/// Where the shell's TALK lines go: the verb's stderr, a suite's vector.
pub type Talk = Arc<dyn Fn(&str) + Send + Sync>;

/// The auto-traits this crate promises without saying so: a transport holds
/// the shell behind an `Arc` across its connection threads, and an event
/// crosses to the thread that writes it out.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Shell>();
    assert_send_sync::<Event>();
    assert_send_sync::<EventBus>();
    assert_send_sync::<Refusal>();
};
