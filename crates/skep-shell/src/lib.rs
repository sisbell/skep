//! # skep-shell — the shell's core, written once
//!
//! The bridge of `client.md` §4b — "the contract between the bundled app's
//! shell and its page" — as a library over `skep-client`: [`Shell`] answers
//! every call of §4b.1 through ONE DOOR, [`Shell::call`], which logs each,
//! and pushes every event of §4b.2 on one stream; and the three things the
//! library does not hold and every shell needs are written here once, so
//! the dev provider (`skep-dev serve`) and the desktop shell share them and
//! rewrite the transport alone. A transport reaches the crate through this
//! root — [`Shell`] and what opens it, [`Refusal`] and its [`Name`], [`Log`]
//! and its [`CallOutcome`], [`Event`] and its [`EventName`] (an
//! [`UnknownEventName`] where a spelling names none), [`Talk`], [`CALLS`] —
//! and two public modules, [`script`] and [`shapes`]; the rest is private.
//! The modules, in the order they are declared, each naming only those
//! above it:
//!
//! * `refs` — THE REFERENCE REGISTRY's names (§4b.1, THE PIN): a board
//!   reference and a session reference are opaque NAMES this process mints
//!   from OS entropy, never a credential, never derived from an origin or a
//!   token, valid in this process alone; and `BoardEntry`, one board under
//!   the reference minted for it, the pair every reader takes whole.
//! * `log` — [`Log`], the call log and the dial log the page's gate reads
//!   (the structure record §6.3's class 5): every call the page made and
//!   every dial the shell made, sizes and timing, never a token or a body,
//!   the latest entries kept and a call of no name kept by its length — and
//!   the one dialer every board dials through, which dials nothing once the
//!   shell's stop stands.
//! * `events` — THE EVENT STREAM: every §4b.2 event as a value, named by
//!   an [`EventName`] of the seven, fanned out to every subscriber.
//! * `refusal` — [`Refusal`], the one refusal shape the page renders: the
//!   board's own verdict verbatim, a halt's face, the block, the
//!   unreachable board, and the shell's own armed refusals, each named by
//!   ONE token from one closed list.
//! * `wire` — THE WIRE's SHARED FACTS the composer, the held store, the
//!   burst's door and the resend, and the call log read: the board's frame
//!   cap and a frame's compact bytes, the tumbler component budget and an
//!   address read within it, the document address in its one spelling, and
//!   the wire's value forms both ways with the insert's value budget.
//! * `attest` — THE ATTEST a signed session composes for the checked set
//!   (t5: "signs where signed ops requires"): the entry frame over the ten
//!   kinds that have one, each axis composed by the shell from its own
//!   reads and never from a preimage the page supplies — and THE BOARD's
//!   BUDGETS the composer keeps as the board keeps them: its wire lists, an
//!   insert's values, a slot's spans, a shot's re-inserted values and its
//!   body.
//! * `held` — THE HELD-BURST STORE (`client.md` §3c): one append-only file
//!   per (board, principal) beside the key store — a header and two line
//!   forms, the directory lock, the line-by-line read with P38's faces, the
//!   synced append (persist-first) and the compaction at every line done —
//!   and a principal's queue, the memory the queue and the file its copy,
//!   a hold adding no line past the board's frame cap in its frames or past
//!   a line budget in its lines, and its file's re-marks within a re-mark
//!   budget.
//! * [`script`] — THE DEV ARM's SCRIPT: the grammar a script file's answers
//!   are parsed by.
//! * `dev_arm` — THE DEV ARM for the SECRET and CONSENT moments (§4b.3): a
//!   script's answers in order, or an auto-answer, each answer said on the
//!   TALK stream and never sent to the page — the NATIVE statements, naming
//!   where key material rests, said there too.
//! * `person` — THE PERSON OVER THE BRIDGE: a `Person` whose PUBLIC
//!   moments become `moment(id, kind, data)` events and block on a channel
//!   the page's `answer(id, …)` — of the form the moment's kind takes — or
//!   `cancel(id)` fills, and whose SECRET and CONSENT moments, and NATIVE
//!   statements, go to the dev arm.
//! * `sessions` — THE SESSION TABLE: every token this shell holds, beside
//!   the board it is valid at, under the reference the page holds, the two
//!   openings (bare, signed), the attest a session's key signs, and a
//!   session's END — one sequence, whichever caller met the death signal —
//!   with the reason a `session-died` carries, derived from public reads as
//!   §4b.2 says under the key store the table holds; a leaving session's
//!   drafts supplement, one per principal, released to another standing
//!   session of its principal.
//! * `hold` — THE HOLD (`client.md` §3c.4, §3c.5): the one path of every
//!   `/op` under a session — attested, dialed, each answer read through the
//!   classification table, the one owner of every reissue's bound, and each
//!   ack noted for the base — and among it a burst's door, admitted where
//!   some send of it the board can take and held where the board cannot
//!   take it; the per-(board, principal) queue over `held`'s file, each
//!   board's under its own lock; its child `resend` holds the walk the feed
//!   thread's probe drains: one read per document, with §3c.5's three
//!   outcomes, the lines then sent in `k` order across the documents.
//! * `feed` — THE FEED THREAD per board, its state the feeder:
//!   `search::Consumer` polled on the `/events` commits, coalesced into one
//!   waiting read, the published feed read from the head the board first
//!   answers with, the `/changes` pages re-read to the head by one reader
//!   for the `feed` events, the `index`, `mode` and `daemon` events as the
//!   state moves, and the bridge's `search` call answered off it; it also
//!   hands each tick's `/health` read to the hold, which reads its
//!   `writes.halted`, and runs THE PROBE on a deadline of its own and at a
//!   hand-over.
//! * `shell` — [`Shell`]: the boards, the sessions, the session mode
//!   (bare as the claimant, or signed with a dev key), and one private
//!   method per §4b.1 row behind [`Shell::call`], whose dispatch the
//!   compiler holds to one arm per call — the ten ceremonial rows in its
//!   child `ceremony` — each row taking and answering values shaped
//!   exactly as the row's columns — an argument of another form refused,
//!   never read as absent; [`Shell::fetch`] is public beside it because it
//!   streams, and logs its own call. Dropping a shell stops it: no feed
//!   thread, open session or `held/<chain>/` lock of it outlives it, and
//!   each board's `/events` reader, asked to stop, ends at its next read.
//! * [`shapes`] — THE DECLARATIONS: [`shapes::declarations`], a TypeScript
//!   declaration file for every value that crosses the bridge, pinned by a
//!   test that round-trips each type's JSON against the declared fields.
//!
//! The crate honours `skep-client`'s own rule — no async runtime, no HTTP
//! crate, no argument-parsing crate: std alone beside the workspace's
//! crates — and holds no transport: the loopback server is the dev verb's,
//! the native bridge the shell's. `ARCHITECTURE.md` §The shell's core draws
//! how the modules fit and the rules that cross them, and `tests/it/tidy.rs`
//! holds the crate to that arrangement.

#![forbid(unsafe_code)]

use std::sync::Arc;

mod refs;
mod log;
mod events;
mod refusal;
mod wire;
mod attest;
mod held;
pub mod script;
mod dev_arm;
mod person;
mod sessions;
mod hold;
mod feed;
mod shell;
pub mod shapes;

pub use events::{Event, EventBus, EventName, UnknownEventName};
pub use log::{CallOutcome, Log};
pub use refusal::{Name, Refusal};
pub use shell::{ArmConfig, Fetched, NodeState, SessionMode, Shell, ShellOptions, CALLS};

/// Where the shell's TALK lines go: the verb's stderr, a suite's vector.
pub type Talk = Arc<dyn Fn(&str) + Send + Sync>;

/// The auto-traits and the error trait this crate promises without saying
/// so: a transport holds the shell behind an `Arc` across its connection
/// threads and shares its log; an event crosses to the thread that writes
/// it out; a shell's options cross to the thread that opens it, and a
/// fetched body to the thread that reads it; and every error the crate
/// answers is a `std::error::Error` a caller's `?` carries. Beside them,
/// every plain value a transport compares or counts by — an outcome, a
/// mode, an arm, a node's state, a scripted answer, an event's or a
/// refusal's name, a declared shape — is a key: `Eq + Hash`.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    fn assert_send<T: Send>() {}
    fn assert_error<E: std::error::Error + Send + Sync + 'static>() {}
    fn assert_key<K: Eq + std::hash::Hash>() {}
    assert_send_sync::<Shell>();
    assert_send_sync::<ShellOptions>();
    assert_send_sync::<Log>();
    assert_send_sync::<Event>();
    assert_send_sync::<EventBus>();
    assert_send_sync::<Refusal>();
    assert_send::<Fetched>();
    assert_error::<Refusal>();
    assert_error::<script::ScriptError>();
    assert_error::<UnknownEventName>();
    assert_key::<CallOutcome>();
    assert_key::<SessionMode>();
    assert_key::<ArmConfig>();
    assert_key::<NodeState>();
    assert_key::<script::Answer>();
    assert_key::<EventName>();
    assert_key::<Name>();
    assert_key::<shapes::Shape>();
    assert_key::<shapes::Field>();
};
