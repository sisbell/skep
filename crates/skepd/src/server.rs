//! The process: one long-running server owning one `World`. The daemon is
//! transport, configuration, and lifetime — every handler is
//! parse/marshal/dispatch/configure; every decision lives in a store, save
//! the three the spec gives the daemon — the session layer's gates (`auth/`,
//! the upload family's among them), the published head's cadence
//! (`write_path/head.rs`) and the media door (`skep-media`'s `door.rs`).
//!
//! Split for testability: [`Daemon`] holds the state and routes
//! `&HttpRequest → Routed` with no socket anywhere; [`serve`]/[`Skepd`]
//! wrap it in a synchronous accept loop over a plain `TcpListener`. The
//! HTTP/1.1 subset this daemon speaks (GET/POST/OPTIONS, `Content-Length`
//! bodies, one request per connection, `Connection: close` on every
//! response) is written out here rather than taken from a server library,
//! because the commit stream needs two things a pull-based library response
//! cannot give: event bytes flushed to the socket at commit time, and a
//! server-initiated close at shutdown. Owning the socket makes both
//! one-line facts.
//!
//! **History is served from the journal** (wire v3): `POST /op-at` answers
//! any READ frame as of any committed position, `GET /dump?at=N`
//! (observe builds) dumps that position's world, and `GET /chain?at=N`
//! answers the commit chain's value there — the kernel's recomputation off
//! its journal, no world folded. All three ask `history.rs`, which owns the
//! reconstruction (the engine's bounded replay), the chain read beside it,
//! their one concurrency budget, and the `as_of` stamping; what `server`
//! adds is the envelope, the read/write classification, and the one mapping
//! from an unavailable answer onto the wire's transport errors. Writes never
//! reach history — a write frame is refused at the transport
//! (`400 write_at_history`) before anything runs — and the live `/op` path
//! is untouched.
//!
//! **Durability is configuration, not code**: [`Daemon::open`] opens M2's
//! kernel on a real directory with `Durability::Fsync` (rollback burned-seq
//! policy), a checkpoint cadence of every 1024 commits OR a byte bound,
//! whichever first — the bound a quarter of the newest checkpoint's size
//! and never below 24 MiB, re-read as each checkpoint lands — DEFERRED to
//! the daemon's own checkpoint thread (`server/listen.rs`), which runs the
//! checkpoint off the write path's guard, says a failure once on the
//! operator stream, and compacts the change feed's files to the journal's
//! reclaim floor after each landing; and two retained checkpoints — genesis
//! on a fresh store, recovery on an existing one, both inside
//! `Engine::open`. The only files this crate writes itself are the
//! change feed's: the commit-metadata sidecar `commits.log`, its four
//! derived sidecars (`feed-index.log`, `feed-offsets.log`, `feed-masked.log`,
//! `feed-streams.log`), the attest store `feed-attest.log` — the marker slot
//! mirrored per attested commit, the one daemon file that is primary state
//! below the reclaim floor — and, transiently while any is compacted, its
//! `.compact` twin — all opened here through `WritePath::open` and owned by
//! `write_path/sidecar.rs` and `write_path/feed/`; nothing here writes any
//! file of the WORLD's, which is why two daemons replaying one journal still
//! converge byte-identically.
//!
//! **Identity is the AUTH session layer** (`auth/`): `GET /challenge` and
//! `POST /session` mint a session by one of two arms — a BARE bind (v1's
//! form, honored only from a loopback peer at an admitted origin, and only
//! while the board is not ENFORCING) or a SIGNED challenge/response — and
//! the daemon maps the opaque token → M10-minted `SessionId` in its own
//! state, so a `SessionId` never rides the wire (M10's non-forgeability
//! precondition). A request with no token, or one whose binding is gone,
//! runs under M10's guest session (`SessionId::GUEST`, bound to no
//! principal): reads are principal-free and succeed, writes get M10's own
//! `Unauthenticated`, and a token naming a binding this daemon has closed
//! carries `Skepd-Session: closed` back.
//! `auth/` owns the rest and `server` holds none of it: the two origin
//! sets and their publication, the handshake, the credential write lock,
//! the ordered refusal producers, and the readers of the World's identity
//! slice — the key table the engine folds at each credential commit and
//! checkpoints with the world (AUTH-2.79), which every route here reads off
//! the one head snapshot it already holds, so the world a check reads and
//! the table it reads are one committed state.
//! What `server` adds is the three write sequences that call them in their
//! pinned order, and the `/session` and `/health` marshals. Tokens are
//! uptime-scoped; the daemon binds 127.0.0.1 only.
//!
//! **Cross-origin posture (wire v7)**: every response carries
//! `Access-Control-Allow-Origin: *` and
//! `Access-Control-Expose-Headers: Skepd-Session`, written from one
//! constant ([`UNIVERSAL_HEADERS`]) by both response writers — the reply
//! path and the event stream — so nothing this daemon answers can miss
//! them, and `OPTIONS` on any known path answers a 204 preflight naming
//! the allowed methods and headers. The `*` is a scope decision, and it
//! was revisited when authentication landed (wire.md §Cross-origin
//! access): it stays, because neither credential is browser-ambient.
//! Reads are principal-free, so `*` grants any page the whole read
//! surface. Writes do not follow it: a write needs a session,
//! [`crate::auth::session::bare_bind_allowed`] refuses a bare bind whose
//! `Origin` is not in the bare set (a browser sends that header on every
//! cross-origin POST), and the signed arm binds its origin inside the
//! signature. A foreign page's POST is fenced by the daemon rather than
//! by what the browser lets it read back, which is why a narrower ACAO
//! was weighed and declined.
//!
//! **The class-scan bound (wire v7.9; PUB-8.36, PUB-8.37 — PUB round 2,
//! lane 3.7)**: `/op` admits at most [`MAX_CONCURRENT_CLASS_SCANS`](scan::MAX_CONCURRENT_CLASS_SCANS)
//! CLASS-SCAN-shaped reads at once — the reads that walk the LINK STORE END
//! TO END, or the lineage pair the whole supersession class, which as M7 is
//! built is every link-discovery read there is
//! (`scan::is_class_scan` enumerates them and states why the shape of a
//! query does not narrow one). [`ClassScans`] is the whole bound on one card — the
//! op test, the pool, and the admission that takes the permit after the
//! parse and the session read and before M10 is asked, so a refused request
//! costs the parse alone and an admitted one holds its slot for the WHOLE
//! answer. The pool is a second instance of [`skep_util::permits::Permits`],
//! disjoint from the reconstruction pool — a scan spends no reconstruction
//! permit and a reconstruction spends no scan permit. The bound admits or
//! refuses a REQUEST (`503 scan_busy`, retry-class, the body naming the op)
//! and never alters an answer: M7 and M8 are not told a query is bounded. A
//! concurrency bound, never a rate statement.
//!
//! **Writes go through one card** (`write_path/`): `POST /op` — the
//! daemon's only write ROUTE — hands each write to
//! `WritePath::commit_under`, which commits it, records its change-feed
//! entry, and announces its position, in that order and inside the
//! serialization guard the write sequences here hold — and then gives the
//! published head writer its turn, which when the cadence is due writes `H`
//! under that same guard before `commit_under` returns. What `server` adds
//! is the frame's parse, its classification, and the three write sequences,
//! which take `serial_lock` themselves so their gates and the execute they
//! gate stand on one committed state; the ordering the commit stream and
//! the change feed below rest on is not a thing a handler here can take
//! apart. Reads execute directly and take no lock.
//!
//! **The commit stream (wire v4)**: `GET /events` is a `text/event-stream`
//! of committed log positions — one event carrying the last announced
//! position on connect, then an event whenever a later position is
//! announced.
//! `write_path/` owns the stream: what a subscriber is told first and
//! next, and the coalescing that falls out of asking "anything past what I
//! last sent"; `Subscribers` (in `listen.rs`) owns the budget, the admission, and
//! the join at shutdown. What `server` adds is the SSE framing (`http.rs`'s
//! `write_commit_event`), the subscriber's loop (`listen.rs`'s
//! `serve_events`), and the hand-off that keeps an open stream off the op
//! pool — the accepting worker gives the socket to a dedicated thread and
//! returns to `accept`.
//!
//! **The change feed (wire v6; class-gated since v7.8)**: `GET
//! /changes?since=N` answers the committed positions in `(N, head]` the
//! presented token's class may see, oldest first, each with its op kind,
//! affected document(s) reduced to the readable ones, and commit
//! wall-clock time — so clients refresh what they display instead of
//! re-walking the world on every SSE tick. `sidecar.rs` owns
//! `commits.log`: its crash honesty, its retention, and what a position
//! whose record was lost answers; `feed/` owns the mask, the four derived
//! sidecars, the attest store, the supplement merge and the two narrowings
//! (`under=`, `drafts=true`); `write_path/` owns the ordering that makes the
//! sidecar's invariants true. What `server` adds is the query's parse,
//! the requester's FEED CLASS — resolved once per request off ONE head
//! snapshot and threaded down (PUB-6.40) — the marshal, and `/health`'s
//! `head_time`.
//!
//! **The served client (wire v6, `client` feature, default OFF)**: `GET /`
//! answers the embedded authoring client (`skep/clients/board.html`,
//! `include_str!` at build — the binary is self-contained), `text/html`,
//! same CORS posture as everything else. One file by design; there is no
//! asset pipeline. The client ACTS — it generates keys and opens signed
//! sessions — so it is opted into rather than opted out of, and abstention
//! is the safe state; the feature's note in `Cargo.toml` carries the
//! ruling. A build without the feature has no `/` route (404).

// The transport: sockets, threads, and the HTTP bytes.
mod http;
mod listen;

// The routes: `Daemon`'s handlers, each an `impl Daemon` block, and the
// caller each request resolves to.
mod actor;
mod blob_routes;
#[cfg(any(test, feature = "test-hooks"))]
mod hooks;
mod op;
mod read_routes;
mod session_routes;

// The vocabulary the routes and the transport share.
mod reply;
mod request;
mod scan;

use std::fmt;
use std::num::NonZeroU64;
use std::path::Path;
#[cfg(any(test, feature = "test-hooks"))]
use std::sync::atomic::AtomicBool;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

#[cfg(any(test, feature = "test-hooks"))]
use parking_lot::Condvar;
use parking_lot::Mutex;
use skep_engine::{Engine, EngineError, HistoryError, Recovery, World};
use skep_febe::OperationSurface;
use skep_identity::HasIdentity;
use skep_kernel::{
    BurnedSeqPolicy, CheckpointError, CheckpointPolicy, Durability, KernelConfig, LandedStep,
    SaltSource, Seq,
};
use skep_media::gate::MediaGate;
use skep_media::index;
use skep_media::limits::MAX_BLOB_BYTES;
use skep_media::serve::FetchPool;
use skep_media::{MediaOptions, UploadPool};
#[cfg(feature = "observe")]
use skep_namespace::PrincipalId;
use skep_util::notice::{self, Class};

use std::sync::Arc;

use crate::auth::{startup_warnings, AuthOptions, AuthState, PortAlreadyBound, Reissue};
use crate::codec::JsonCodec;
use crate::history::History;
use crate::limits::{MAX_REQUEST_BODY, MAX_SMALL_BODY};
use crate::write_path::{FeedCompaction, WritePath};
use actor::Resolved;
use reply::{class_varying, refuse, with_signal, TransportError};
use request::BodySource;
use scan::ClassScans;

pub use crate::auth::session::Peer;
pub use http::UNIVERSAL_HEADERS;
pub use listen::{bind, serve, serve_bound, Listener, Skepd, DEFAULT_WORKERS, MIN_WORKERS};
pub use reply::{Body, Fetch, Reply, Routed};
pub use request::HttpRequest;

/// Auto-checkpoint cadence, the commit half: every N commits (M2 evaluates
/// on-commit; the daemon's checkpoint thread waits on the kernel's due flag,
/// not on a timer — no timer thread exists anywhere in this daemon).
/// Together with [`RETAINED_CHECKPOINTS`] this sets the sidecar's
/// reconstruction ceiling at open (see `CommitsLog::open`): raising either
/// lengthens startup on a data dir whose commit metadata is missing. The
/// byte half beside it — [`CHECKPOINT_BYTES_FLOOR`], [`CHECKPOINT_BYTES_SHARE`]
/// — crosses first on a board of large commits, where this count alone would
/// let the journal outrun the floor.
const CHECKPOINT_EVERY_COMMITS: u64 = 1024;

/// THE CADENCE's BYTE BOUND, its FLOOR — 24 MiB, INTERIM (D1; the
/// journal-writes investigation §3.2, the owner's ruling jw-R1): the least
/// the byte bound B is, whatever the newest checkpoint's size. The bound is
/// what makes the media floor a guarantee: the floor must hold the next
/// checkpoint, the journal appended until it lands and the daemon's own
/// lines for those commits, which holds iff B·(1 + g + d) ≤ C — C the
/// newest checkpoint's size, g the checkpoint's growth per journal byte, d
/// the daemon's lines per journal byte, 1 + g + d measured from 1.35 (bulk
/// prose) to ≈ 3.0 (tiny attested commits). Below the floor's crossover
/// the constant half of the media floor covers C + 3·B + one segment at
/// 24 MiB with room; above it [`CHECKPOINT_BYTES_SHARE`] holds. The grace
/// of the deferred cadence (one window, the backstop's) doubles the window
/// the floor must cover, which the share's slack absorbs.
const CHECKPOINT_BYTES_FLOOR: u64 = 24 * 1024 * 1024;

/// THE CADENCE's BYTE BOUND, its SHARE — 4, INTERIM (D1; jw-R1): the byte
/// bound B is the newest checkpoint's size divided by this, never below
/// [`CHECKPOINT_BYTES_FLOOR`], re-read as each checkpoint lands. A quarter
/// holds the inequality above at every measured regime with slack of at
/// least C/4 — a half holds prose and 1 KiB values alone, a third every
/// unsigned size and the signed tiny case at its edge — at a checkpoint I/O
/// of about four bytes of checkpoint per byte of journal on bulk inserts.
/// The owner may move the divisor; the bound stays RELATIVE to the newest
/// checkpoint, never a constant: a constant sized for a small board lets a
/// large one's journal outrun its floor, and one sized for a large board
/// checkpoints a small one at every few megabytes.
const CHECKPOINT_BYTES_SHARE: u64 = 4;

/// THE BYTE BOUND for a newest checkpoint of `newest_checkpoint_len` bytes
/// (`None`: none yet, the floor alone): `max(CHECKPOINT_BYTES_FLOOR, C /
/// CHECKPOINT_BYTES_SHARE)`. Non-zero by the floor, which is what the
/// kernel's setter takes.
fn cadence_bytes_for(newest_checkpoint_len: Option<u64>) -> NonZeroU64 {
    let share = newest_checkpoint_len.map_or(0, |c| c / CHECKPOINT_BYTES_SHARE);
    NonZeroU64::new(share.max(CHECKPOINT_BYTES_FLOOR))
        .expect("the byte bound's floor is a non-zero constant")
}

/// Retained checkpoints: two, so `BadCheckpoint` recovery can fall back to
/// the older base instead of a full-journal replay from genesis. The other
/// factor of the sidecar's reconstruction ceiling — see
/// [`CHECKPOINT_EVERY_COMMITS`].
const RETAINED_CHECKPOINTS: usize = 2;

/// THE RETRY MEMO's CAPACITY — 1024 entries, INTERIM: the daemon's own pin,
/// handed to M10's `OperationSurface::new` at the open as the construction
/// parameter the M10 design makes it (§7's knob "with no implicit default";
/// the operations design §2.6, op-D5; the configuration register's row "the
/// retry memo's capacity, THE DAEMON's PIN"). Never an operator knob: the
/// memo is a best-effort hint nobody can observe — an evicted key costs one
/// re-execution and nothing says so — so a flag for it would be a setting
/// with no echo and no face. The figure is the one the crate fixed before
/// the parameter existed, so no board's behaviour moves with it.
const MEMO_CAPACITY: std::num::NonZeroUsize =
    std::num::NonZeroUsize::new(1024).expect("1024 is nonzero");

/// The body cap for a request — its method and its path — checked on the
/// declared `Content-Length` before a byte is read, so a route that cannot
/// use a large body is never asked to allocate for one: the frame routes,
/// `/op` and `/op-at`, take `MAX_REQUEST_BODY` whatever the method; the
/// blob upload's two body-carrying methods — the creation's `POST` and the
/// resume's `PATCH` — take `MAX_BLOB_BYTES`, a body the daemon's own
/// transport never holds whole (`server/http.rs`, THE STREAMING ARM) and a
/// caller over its own transport holds whole if it buffers; every other
/// request, the rest of the blob family's included, takes `MAX_SMALL_BODY`.
///
/// Public because [`HttpRequest`] names it as a caller's obligation: a
/// caller building a request for [`Daemon::route`] over a transport of its
/// own takes the bound from here rather than transcribing it, so a
/// route-scoped raise moves for them too — and the bound it takes is the one
/// the daemon's own transport applies, for every method and path.
pub fn body_cap(method: &str, path: &str) -> usize {
    match path {
        "/op" | "/op-at" => MAX_REQUEST_BODY,
        p if blob_routes::streams_body(method, p) => MAX_BLOB_BYTES as usize,
        _ => MAX_SMALL_BODY,
    }
}

/// The embedded authoring client (wire v6): one file, compiled in so the
/// binary is self-contained.
#[cfg(feature = "client")]
const BOARD_HTML: &str = include_str!("../../../clients/board.html");

/// `Daemon::open` failure — WHICH SUBSYSTEM refused, and not a disposition:
/// four of the five are uniform operator-intervention conditions (report and
/// stop, never retry) and `Engine` is not. A caller that means to RETRY reads
/// the wrapped error and never this enum alone, which cannot tell a failure a
/// retry clears from one it does not.
#[derive(Debug)]
#[non_exhaustive]
pub enum DaemonError {
    /// The engine could not genesis/recover — M2's [`OpenError`](crate::OpenError)
    /// verbatim, re-exported beside [`EngineError`] so the match this doc
    /// describes is written against this crate alone, and the ONE variant
    /// here whose disposition is the WRAPPED error's rather than this enum's.
    /// `ForeignFormat`, `BadCheckpoint` and `Corruption` are operator
    /// intervention and `InvalidConfig` wants a corrected configuration; `Io`
    /// fuses failures no retry clears WITH the two M2 documents as clearable
    /// — the journal-path exclusion lock ([`Daemon::open`]'s precondition: a
    /// second live kernel on this data dir) and a recovery truncation the
    /// next open repeats. So `Io` narrows a failure to POSSIBLY retryable and
    /// no further, and a caller that retries on it bounds its attempts. Reach
    /// it through this enum's `source`, or by destructuring
    /// `Engine(EngineError::Open(…))`.
    Engine(EngineError),
    /// `commits.log` (the commit-metadata sidecar), one of the change
    /// feed's four derived sidecars or its attest store could not be opened,
    /// replayed, or extended. A torn tail is NOT an error (it truncates);
    /// this is the data dir refusing I/O the kernel just performed.
    Sidecar(std::io::Error),
    /// The blocked-prefix list's START-UP SUPPLY
    /// ([`AuthOptions::blocked_supply_path`]) could not be read, is not a
    /// list, or is past the byte cap the supply channel applies — the last
    /// two both `InvalidData`; the error names the file and, for the cap,
    /// the number. The list is supplied at every start (AUTH-4.70), so a
    /// daemon that cannot read the one it was handed does not start on an
    /// empty one: that would lapse every standing block in silence.
    BlockedPrefixes(std::io::Error),
    /// The blob store under `blobs/` in the data dir (media lane B) could
    /// not be opened: its two logs tail-checked and compacted, its partials
    /// reconciled with its records, the directory synced — the data dir
    /// refusing I/O, as [`DaemonError::Sidecar`] is.
    Media(std::io::Error),
    /// THE REGISTRY'S SEEDING CHECK refused the genesis (REG-1.28 to
    /// REG-1.32): one of its three arms — disjointness, completeness, the
    /// count — fired over the registry's twelve rows and every other commons
    /// row this build holds, the refusal naming the arm. Run ahead of
    /// `Engine::open` on every open, so a refusal is a genesis that does not
    /// complete: nothing is written and no engine is opened. A BUILD fault,
    /// never a data dir's: the rows and the domain are compiled constants,
    /// so the condition is operator intervention at the build and no retry.
    /// The payload is re-exported as [`SeedingRefusal`](crate::SeedingRefusal),
    /// so a caller names it through this crate alone.
    Registry(skep_registry::SeedingRefusal),
}

impl std::fmt::Display for DaemonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DaemonError::Engine(e) => write!(f, "{e}"),
            DaemonError::Sidecar(e) => write!(f, "change-feed sidecar: {e}"),
            DaemonError::BlockedPrefixes(e) => write!(f, "blocked-prefix list: {e}"),
            DaemonError::Media(e) => write!(f, "blob store: {e}"),
            DaemonError::Registry(e) => write!(f, "registry seeding: {e}"),
        }
    }
}

/// `Display` states the whole condition on one line — that is what the
/// operator reads — and `source` additionally exposes the cause as a link,
/// so a generic reporter walking the chain finds one where there is one.
impl std::error::Error for DaemonError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            DaemonError::Engine(e) => Some(e),
            DaemonError::Sidecar(e) => Some(e),
            DaemonError::BlockedPrefixes(e) => Some(e),
            DaemonError::Media(e) => Some(e),
            DaemonError::Registry(e) => Some(e),
        }
    }
}

/// The paths this daemon serves — the one place the route set is stated, so
/// preflight, method refusal and dispatch cannot disagree about what exists.
/// A known path answers `OPTIONS` with a preflight and a wrong method with
/// `405`; everything else is the ordinary `404`. The blob upload's path
/// family (media lane B) is known as a family: `/blob/upload` and
/// `/blob/upload/<id>`, the latter known for any `<id>` and refused by name
/// where it is no identifier; the blob fetch's path `/blob` is known beside
/// it.
fn path_is_known(path: &str) -> bool {
    matches!(
        path,
        "/session"
            | "/session/close"
            | "/challenge"
            | "/op"
            | "/op-at"
            | "/health"
            | "/events"
            | "/changes"
            | "/chain"
    ) || (cfg!(feature = "observe") && path == "/dump")
        || (cfg!(feature = "client") && path == "/")
        || blob_routes::is_blob_path(path)
        || blob_routes::is_fetch_path(path)
}

// The token ↔ session binding, the handshake, and per-request resolution
// live in `crate::auth` (the AUTH session layer). The glue that remains is
// `actor.rs`.

/// The daemon's state: the assembled engine, M10's front door, the codec,
/// and the token → session binding. Socket-free — [`Daemon::route`] is the
/// entire HTTP surface as a request→reply function over this state, with no
/// socket in its signature. Not a PURE one: see [`Daemon::route`].
pub struct Daemon {
    engine: Engine,
    /// M10's front door — the operation surface every frame executes
    /// against. `op` throughout this crate names an operation or its kind
    /// (`Op`, `OpKind`, `op_name`, the wire's own `"op"` field), so the
    /// boundary takes the boundary's name.
    febe: OperationSurface<World>,
    codec: JsonCodec,
    /// The AUTH session layer: config, the challenge and session stores,
    /// the credential write lock, the credential memo.
    auth: AuthState,
    /// The write path: the serialization point, the commit-metadata sidecar
    /// behind `GET /changes` and `head_time` (wire v6), the commit stream
    /// behind `GET /events` (wire v4), and the published head writer behind
    /// them. One field because the four are one ordering — commit, record,
    /// announce, then the head writer's turn — that no handler may take
    /// apart.
    writes: WritePath,
    /// The history surface behind `/op-at`, `/dump?at` and `/chain?at`,
    /// holding its own reconstruction budget: a guest may ask any of them
    /// and replay is per-call uncached, so without that budget any local
    /// caller could pin every worker on reconstruction.
    history: History,
    /// The class-scan bound behind `/op`'s class-scan-shaped FTT reads (wire
    /// v7.9; PUB-8.36), holding its own shape test and its own pool — a
    /// second instance of [`skep_util::permits`]'s mechanism, and so disjoint
    /// from the reconstruction pool `history` holds. Lives in the serving
    /// path and nowhere lower (doctrine D9: the meter is an attribute of a
    /// gate, never of the substrate): M8 and M7 are asked or not asked, and
    /// never told.
    scans: ClassScans,
    /// The daemon's MEDIA resource: the blob store under `blobs/` in the
    /// data dir — the files, the partials, the upload records and the lease
    /// log — the limits in force, the hold a stream has on its upload, THE
    /// CELL INDEX (entered by the write path at every commit that mints a
    /// cell, rebuilt at open on a thread) and the binding the write door
    /// asks. The PUT's routes reach it as `op.rs` reaches the write path;
    /// the door reads it under the plain sequence's locks; the pruner's
    /// pass reads it under the credential lock's write arm. It commits
    /// nothing to the journal and takes no `Serial`.
    media: MediaGate,
    /// The fetch pool behind `GET /blob?i=` (wire.md §Media, THE FETCH;
    /// M-I5 (f)) — the third instance of [`skep_util::permits`]'s mechanism,
    /// disjoint from the reconstruction and class-scan pools by the borrow:
    /// an admitted fetch holds its whole file from the check to the last
    /// byte written, so the pool is the route's memory bound, and its count
    /// is the third term of [`MIN_WORKERS`]. In the serving path like the
    /// scan pool (D9): the serve is asked or refused, never told.
    fetches: FetchPool,
    /// The upload pool behind the PUT's two body-carrying methods — the
    /// creation and the resume of `/blob/upload` (wire.md §Media, THE
    /// PERMIT; M-I5 (f)) — the fourth instance of [`skep_util::permits`]'s
    /// mechanism and the fetch pool's twin, disjoint from the three others
    /// by the borrow: an admitted creation or resume holds its worker from
    /// the permit to its finish, so the pool is the family's bound on worker
    /// occupancy, and its count is the fourth term of [`MIN_WORKERS`]. In
    /// the serving path like the fetch pool (D9): the family is asked or
    /// refused, never told.
    uploads: UploadPool,
    /// THE CHECKPOINT THREAD's MEMORY between its wakes ([`CheckpointMemory`]):
    /// the inline count as it last said it and the position that count is
    /// counted from, the newest checkpoint as it last looked, and the
    /// resident set's high-water. Held here because the thread is
    /// `listen.rs`'s and the test seam runs its arms on a caller's thread.
    checkpointer: CheckpointMemory,
    /// The dirty-crash harness's one seam into the claim's step
    /// (`Daemon::hold_between_the_claim_and_its_head`): armed, the
    /// claim-flip tail announces the crash window and parks there, both
    /// locks held, for the harness to SIGKILL. `false` is the only state
    /// production ever sees; compiled under the `test-hooks` feature, not
    /// `cfg(test)` alone, because the harness is an integration test of
    /// this crate's library, outside its `cfg(test)`.
    #[cfg(any(test, feature = "test-hooks"))]
    hold_between_claim_and_head: AtomicBool,
}

/// Deliberately opaque: reporting the log position would take the kernel's
/// lock, and a `Debug` that can block is one that turns `dbg!` into a
/// hazard. [`Daemon::log_position`] is how you ask.
impl std::fmt::Debug for Daemon {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Daemon").finish_non_exhaustive()
    }
}

impl Daemon {
    /// Open (genesis or recover) the one world at `data_dir`, replay the
    /// commit-metadata sidecar, and assemble the operation surface.
    ///
    /// A COMMAND on the journal beyond genesis and recovery, on one kind of
    /// board: a CLAIMED board whose head writer resumes no head from `H` —
    /// the crash window between the claim and its head, a claim whose `H.1`
    /// the head writer's driver refused while serving, or a board claimed
    /// under a build that wrote no head at the claim — has `H.1` written
    /// before this returns ([`Daemon::write_the_claims_head_if_owed`];
    /// signed ops, s1): up to three commits of the daemon's own, as the
    /// system account's principal (the staging draft's one-time mint, the
    /// record's insert, the publish into `H`), so [`Daemon::log_position`]
    /// can stand past the recovered head. A refusal there fails nothing: the
    /// head writer surfaces it on the operator stream, the open returns `Ok`,
    /// and the board answers attested writes
    /// `attestation_invalid:board_unavailable` until a head lands.
    ///
    /// PRECONDITION: no other live kernel holds `data_dir`. M2 takes an
    /// exclusive lock on the journal directory, and a second open fails on
    /// it — the one CONDITION here a retry can clear, and so the one
    /// exception to the disposition below. It is NOT a variant of
    /// [`DaemonError`]: it arrives inside `Engine`, as
    /// `EngineError::Open(OpenError::Io(_))`, an arm that also carries
    /// failures no retry clears — so a caller that retries matches the
    /// wrapped `OpenError` and bounds its attempts, where one matching
    /// `DaemonError::Engine(_)` alone would loop on a corrupt journal. Every
    /// name in that pattern is this crate's to hand out —
    /// [`OpenError`](crate::OpenError) is re-exported beside [`EngineError`]
    /// — so the match takes no dependency but this one.
    /// [`Skepd::shutdown`] and `Skepd`'s `Drop` both release that lock before
    /// returning, which is what closes the race with a stopping server. Every
    /// other condition is an operator-intervention one (corrupt journal, bad
    /// checkpoint, a data dir refusing I/O the kernel just performed):
    /// surface it and exit, never retry.
    ///
    /// ONE step here costs more than O(1) in the data dir beyond the engine's
    /// own recovery: the feed's open. Where commit metadata is missing it
    /// reconstructs the uncovered positions from the journal, one whole-world
    /// replay (plus one world diff, for the position's class) each, up to the
    /// retained window (`CHECKPOINT_EVERY_COMMITS` × `RETAINED_CHECKPOINTS`).
    /// `CommitsLog::open` states that bound; `Feed::open` the derived
    /// sidecars' own, O(their files) plus O(any missing tail); and the attest
    /// store's open inside it (`write_path/feed/attest.rs`'s
    /// `AttestStore::open`) is O(its file) — the one feed file the journal's
    /// retention does not bound, a line for every attested commit the board
    /// has ever made, never compacted — plus one bounded journal scan per
    /// uncovered retained position. The identity table costs nothing here:
    /// it rides in the World the engine recovered, checkpointed with it and
    /// stepped by the replay (AUTH-2.79, AUTH-2.80). What the engine's
    /// recovery can cost over it is a base written WITHOUT the slice over
    /// credential deposits — not a start point, so the open steps back to an
    /// older one or to genesis and replays, slower, once — and that is said
    /// on the operator stream (AUTH-2.86; [`Engine::recovery`]). A board with
    /// no start point left refuses to open (AUTH-2.88): `Engine` carries
    /// `BadCheckpoint` with the slice's own remedy, and nothing is invented.
    pub fn open(data_dir: impl AsRef<Path>) -> Result<Daemon, DaemonError> {
        Daemon::open_with(data_dir, AuthOptions::default())
    }

    /// [`Daemon::open`] with the session-layer configuration named: the
    /// local-trust flag, the configured origins, and the blocked-prefix
    /// list's supply. [`Daemon::open`]'s PRECONDITION, its account of which
    /// failures a retry can clear, and the commits it makes on a claimed board
    /// whose journal holds no head are this one's too — that method delegates
    /// here, so both doors carry one contract. The identity table is the
    /// recovered World's own slice (AUTH-2.86: the daemon serves from the
    /// resolved World): nothing is rebuilt here, and what the engine's open
    /// skipped or resolved on the way to that World is logged here as the two
    /// warnings that rule names.
    ///
    /// A supply file the options name is read HERE, at every start, and the
    /// list installed from it before anything is served
    /// ([`DaemonError::BlockedPrefixes`] where it cannot be).
    pub fn open_with(data_dir: impl AsRef<Path>, opts: AuthOptions) -> Result<Daemon, DaemonError> {
        Self::open_configured(data_dir, opts, MediaOptions::default())
    }

    /// [`Daemon::open_with`] with the MEDIA resource's configuration named
    /// beside the session layer's: the upload setting (`--no-uploads`,
    /// wire.md §Media), echoed on `/health` as the `media` object. The two
    /// doors above delegate here, so all three carry one contract.
    pub fn open_configured(
        data_dir: impl AsRef<Path>,
        opts: AuthOptions,
        media: MediaOptions,
    ) -> Result<Daemon, DaemonError> {
        // THE PRODUCTION SALT (`SKJ4`): OS entropy per transaction, the one
        // source a daemon opens under — a seeded stream is a pure function
        // of the seed and the position, which is exactly the predictability
        // the salt exists to deny a reader of `/chain?at=N`. The seeded
        // source reaches a daemon through the test seam alone
        // (`Daemon::open_seeded`, compiled only under `test-hooks`).
        Self::open_under(data_dir.as_ref(), opts, media, SaltSource::Os)
    }

    /// The one open, under a named salt source — [`Daemon::open_configured`]'s
    /// body, which that door reaches with [`SaltSource::Os`] and the test
    /// seam `Daemon::open_seeded` with a seeded stream. Private, so no
    /// fourth caller can name a source; and over `&Path`, so the public
    /// doors are the generic shims and this body is compiled ONCE whatever
    /// path type a caller holds — the split std keeps, `File::open` over its
    /// inner `&Path`.
    fn open_under(
        data_dir: &Path,
        opts: AuthOptions,
        media_opts: MediaOptions,
        salt: SaltSource,
    ) -> Result<Daemon, DaemonError> {
        // THE OPEN's FIRST LINE (§3.1 step 3; m7): the directory, before the
        // seeding check and the engine's open — the one line on the operator
        // stream that names the directory, which a collector keys on, and
        // the tell that an open has begun where it is long.
        say_open_line(DataDirLine(data_dir));
        // THE CADENCE (jw-R1, jw-R2): every `CHECKPOINT_EVERY_COMMITS` OR the
        // byte bound, whichever first, DEFERRED — a crossing sets the
        // kernel's due flag and the checkpoint thread runs it off the write
        // path's guard; a second crossing before the thread has serviced the
        // first runs inline as the kernel's backstop. The byte bound opens at
        // its floor and is re-read off the newest checkpoint below, once the
        // engine has opened, and by the thread as each one lands.
        let cfg = KernelConfig {
            durability: Durability::Fsync {
                journal_path: data_dir.to_path_buf(),
                retain_checkpoints: RETAINED_CHECKPOINTS,
                burned_seq: BurnedSeqPolicy::Rollback,
            },
            checkpoint: CheckpointPolicy::Deferred(Box::new(CheckpointPolicy::EitherOf(
                Box::new(CheckpointPolicy::EveryN(CHECKPOINT_EVERY_COMMITS)),
                Box::new(CheckpointPolicy::JournalBytes(CHECKPOINT_BYTES_FLOOR)),
            ))),
            salt,
        };
        // THE SEEDING CHECK, THIS DAEMON ITS HAND (REG-1.28, REG-1.32): the
        // registry's three arms over its twelve rows and every other commons
        // row this build holds, AHEAD of the engine on every open — a fresh
        // data dir's genesis and a reopen's re-genesis alike — so a refusal
        // is a genesis that does not complete: no claim, no session and no
        // board record, nothing written, no engine opened.
        crate::auth::policy::genesis_seeding_check().map_err(DaemonError::Registry)?;
        // THE ENGINE's OPEN, TIMED: the daemon's own `Instant` around the
        // call, the figure the recovery's landing carries.
        let began = Instant::now();
        let engine = Engine::open(cfg).map_err(DaemonError::Engine)?;
        let open_ms = began.elapsed().as_millis();
        // THE START POINT's account (AUTH-2.86): every retained checkpoint
        // the engine's open passed over, with the start point it resolved
        // from, and a slice-less start point that resolved to the empty
        // table — said before anything is served, and only where there is
        // something to say.
        for warning in recovery_warnings(engine.recovery()) {
            notice::line(format_args!("warning (at open): {warning}"));
        }
        // THE RECOVERY's LANDING (m7): the base the open loaded, the commits
        // it replayed above it and how long the engine's open took — said on
        // EVERY open, not on a skip alone, after the account above of what
        // was passed over on the way to that base.
        say_open_line(RecoveredLine::of(engine.recovery(), open_ms));
        // THE STRAY TEMP FILE (jw-R4; AUTH-2.86's family of startup reports):
        // a checkpoint a crash or a full volume left half-written, which the
        // kernel's open found and removed — said here, the kernel answering
        // the fact, so the operator's acts at the floor stay two.
        if let Some(bytes) = engine.kernel().stray_checkpoint_removed() {
            notice::line(format_args!(
                "checkpoint.tmp found ({bytes} bytes) and removed: a checkpoint a crash or the \
                 journal's own full volume left half-written, no base, its room on the volume \
                 reclaimed by the open"
            ));
        }
        // THE START POINT's SIZE, read once here: the byte bound of the
        // cadence and the floor in force both scale by a checkpoint's size,
        // and the one the open sizes by is the START POINT's — the base the
        // engine's open LOADED the world from (`recovery.start_point`), its
        // header read by name — never the newest file's, whose header may be
        // a skipped base's claim: a damaged `body_len` the open passed over
        // would otherwise refuse every deposit at a floor sized to the claim
        // and hold the cadence's byte half off until the first landing. A
        // start point at genesis names no file and sizes as no checkpoint
        // does. The thread re-reads the NEWEST checkpoint as each one lands,
        // every later base having loaded.
        let start_point = engine.recovery().map_or(Seq(0), |recovery| recovery.start_point);
        let start_point_len =
            engine.kernel().checkpoint_header(start_point).map(|header| header.len);
        engine.kernel().set_cadence_bytes(cadence_bytes_for(start_point_len));
        // The newest checkpoint as the thread will find it at its first wake,
        // so a wake with no flag and no landing re-reads nothing off a header
        // the open did not size by.
        let newest_at_open = engine.kernel().newest_checkpoint().map(|header| header.seq);
        // THE BLOB STORE, opened under `blobs/` beside the journal: its
        // reconciliation and compaction complete here, before anything is
        // served (the record: "OPEN's PASSES OVER BOTH STORES … COMPLETE
        // BEFORE THE DAEMON SERVES ITS FIRST REQUEST"). The limits in force
        // — the daemon's default, one eighth of the volume's capacity read
        // once here, until the serving layer's channel installs a record
        // (AUTH-4.70, owed) — are named on the operator stream with their
        // source, the floor in force at start beside them, and the upload
        // setting after. Opened AHEAD of the write path, which takes the
        // gate's cell index to enter at every commit from here on.
        let media = MediaGate::open_with(data_dir, media_opts).map_err(DaemonError::Media)?;
        media.set_floor(MediaGate::floor_in_force(start_point_len));
        notice::line(media.startup_line());
        notice::line(format_args!(
            "media uploads: {}",
            if media.uploads_open() { "open (the default)" } else { "CLOSED (--no-uploads): the creation and the resume are refused uploads_closed" }
        ));
        let writes = WritePath::open(data_dir, &engine, Arc::clone(media.index()))
            .map_err(DaemonError::Sidecar)?;
        // THE READ PREDICATE (PUB-1.31; PUB-6.39's one-per-request shape;
        // PUB round 2, lane 3.3). The live front door is given NO consult:
        // M10 answers `World::readable` — published ∨ subtree ∨ grant, with
        // the version member projected to its document (PUB-2.15) — off the
        // ONE snapshot it pins per request, so every named argument, every
        // per-run mask and the result-set filter of one request stand on one
        // committed state, the state its `as_of` names; and the publish
        // shot's source gate (PUB-6.23, PUB-8.1) reads the same predicate
        // over the working world of the shot's own transaction, which M5
        // hands it. A consult closed over a per-call snapshot of the live
        // kernel — lane 3.2's shape — would judge one request's arguments
        // against different heads. The one front door that DOES take a
        // consult is history's (`history.rs`): a read as of N answers the
        // N-world's content through the HEAD's sets (PUB-6.48), which no
        // world of its own can supply.
        //
        // And the write-path check leans on this door carrying none: its dry
        // run of a shot's source gate (`auth/policy/attestation.rs`) asks
        // `World::visible_to` at the principal, which is what this door lends
        // the store ONLY while it carries no consult — a consult added here is
        // owed to that dry run too, or the check passes through, UNATTESTED, a
        // shot the store then admits.
        let febe = OperationSurface::new(Box::new(engine.stores()), MEMO_CAPACITY);
        let auth = {
            let snap = engine.kernel().snapshot();
            AuthState::open(opts, snap.world()).map_err(DaemonError::BlockedPrefixes)?
        };
        let daemon = Daemon {
            engine,
            febe,
            codec: JsonCodec,
            auth,
            writes,
            history: History::new(),
            scans: ClassScans::new(),
            media,
            fetches: FetchPool::new(),
            uploads: UploadPool::new(),
            checkpointer: CheckpointMemory::at_open(start_point, newest_at_open),
            #[cfg(any(test, feature = "test-hooks"))]
            hold_between_claim_and_head: AtomicBool::new(false),
        };
        // THE CRASH WINDOW, closed before anything is served (signed ops, s1;
        // see the method): a claimed board whose journal holds no head owes
        // `H.1`, and the open is where it is paid.
        daemon.write_the_claims_head_if_owed();
        // THE CELL INDEX's WALK, on a thread of its own over the world as it
        // stands now — every commit from here on enters its own cells, and
        // the walk adds the world's into the same copy (the composition
        // clause). The daemon serves while it walks; the index's three
        // readers refuse `index_rebuilding` until it completes (ms5-R).
        index::start_walk(daemon.engine.kernel(), Arc::clone(daemon.media.index()));
        Ok(daemon)
    }

    /// THE CRASH WINDOW (signed ops, s1; RULED 2026-09-25 — "THE CLAIM WRITES
    /// `H.1`"): the claim and its head are TWO transactions in one serialized
    /// step ([`Daemon::on_claim_flip`]), and a process that dies between them
    /// — the claim durable, no head — leaves a claimed board with no board
    /// term on disk, as does a claim whose `H.1` the head writer's driver
    /// refused while serving ([`Daemon::on_claim_flip`] states that refusal):
    /// the two states in which the check's `board_unavailable` would
    /// otherwise answer every attested write until the cadence's next head.
    /// Closed HERE, at open and before anything is served: a claimed board
    /// (its identity slice naming a claimant) whose head writer resumed no
    /// head writes `H.1` now ([`WritePath::write_first_head`]) under the write
    /// path's own lock, naming the committed pair as it stands — the claim's
    /// own position where the crash was the split, and the last commit's on a
    /// board whose claim's `H.1` the driver refused, or claimed under a build
    /// that wrote no head at the claim. The unclaimed board writes nothing
    /// here: no head by a claim that did not happen (A1/A5). A claimed board
    /// with its head finds writing it a no-op, so a clean restart writes none.
    /// The line on the operator stream is I11 (c)'s: a head written for a
    /// reason other than the cadence's is said, never silent. A head the
    /// driver refuses HERE is surfaced as every refused head is, and fails
    /// nothing: the open returns all the same, and the board answers attested
    /// writes `board_unavailable` until a head lands.
    ///
    /// WHY NOT ONE TRANSACTION. A head names the committed `(position,
    /// chain)` pair read BEFORE its own write opens — a coordinate strictly
    /// below its own commit, since no bytes can carry their own hash — so a
    /// head folded into the claim's transaction could name only the position
    /// BEFORE the claim, and the claim's own chain value does not exist until
    /// its transaction closes. The two-transaction shape is the head's rule
    /// (`head.rs`, WHAT A HEAD IS), not a limit of the journal's format, and
    /// this open is what closes the gap it leaves.
    fn write_the_claims_head_if_owed(&self) {
        if self.engine.kernel().snapshot().world().identity().claimant().is_none() {
            return;
        }
        let serial = self.writes.serial_lock();
        if self.writes.write_first_head(&serial) {
            notice::line(
                "the board is claimed and its journal held no head: H.1 written at open, \
                 naming the committed pair as it stood",
            );
        }
    }

    /// Bind the auth surface to the served port — the origin sets and the
    /// `/health.auth` lists derive from it. [`serve`] calls this with the
    /// bound port; a socket-free embedder that wants origin behavior calls
    /// it itself. The two are exclusive: a [`PortAlreadyBound`] says a port
    /// is already bound, and the number it carries is the one already
    /// there — the number every live session's origin set was established
    /// against — not the one refused.
    ///
    /// PRECONDITION: `port != 0`, which PANICS rather than being refused —
    /// a caller's bug and not an outcome, so it is not one of the errors
    /// above. Zero is not a port this daemon can serve on, and it is the one
    /// value from which the loopback defaults derive origins this daemon's
    /// own parser rejects and no `Origin` header can match.
    pub fn bind_auth_port(&self, port: u16) -> Result<(), PortAlreadyBound> {
        self.auth.cfg.bind_port(port)
    }

    /// The world as of a committed position — the same bounded replay
    /// `POST /op-at` answers from, for embedders that want the state rather
    /// than a wire answer. Unbudgeted: the reconstruction permit bounds
    /// concurrent HTTP callers, and an embedder calling this holds the
    /// daemon itself.
    pub fn world_at(&self, at: Seq) -> Result<World, HistoryError> {
        self.engine.world_at(at)
    }

    /// The committed world's dump at `principal`'s class — what `GET /dump`
    /// answers a session bound to `principal` (`None` = the guest), through
    /// the same engine call, so a suite holding the daemon can state the H4
    /// oracle: the wire body equals this post-filter of the harness-only
    /// walk byte for byte. Unbudgeted, like [`Daemon::world_at`]: an
    /// embedder calling this holds the daemon itself.
    ///
    /// The answer's type is re-exported as [`crate::WorldDump`], for the
    /// reason the engine types beside it are: naming it must not oblige a
    /// caller to depend on the engine.
    #[cfg(feature = "observe")]
    pub fn dump_visible_to(&self, principal: Option<PrincipalId>) -> crate::WorldDump {
        self.engine.world_dump_visible_to(principal)
    }

    /// Current log position (M10's `log_position`; never regresses).
    pub fn log_position(&self) -> Seq {
        self.febe.log_position()
    }

    /// The router — the whole HTTP surface, still socket-free: the two
    /// routes that cannot be a request/response `Reply` — `GET /events`, an
    /// unbounded response, and the blob fetch's admitted answer, a file
    /// streamed with its requester re-resolved between chunks — are returned
    /// as their own [`Routed`] variants, and the accept path owns the socket
    /// from there.
    ///
    /// A COMMAND, not a query. `POST /op` commits to the journal, records
    /// the change-feed entry, and announces the commit — and where that
    /// commit makes the published head due (wire.md §The other endpoints: 64
    /// commits since the last head, a moved checkpoint, or the hour), the
    /// daemon's own head writer commits up to three writes of its own before
    /// the reply is built, so the journal can stand past the ack's `at` when
    /// this returns — and the credential write that CLAIMS the board is
    /// followed by its first head `H.1` in the same step, whatever the
    /// cadence says (signed ops, s1), where the head writer's driver admits
    /// it ([`Daemon::on_claim_flip`] states the refusal); `POST /session`
    /// mints an M10 session; `GET /challenge` mints a nonce into the bounded
    /// challenge store and evicts the oldest past
    /// `auth`'s `MAX_LIVE_NONCES` — a GET that is not safe, and
    /// whose eviction can spend another caller's outstanding nonce;
    /// `POST /session/close` retires a binding. And EVERY token-accepting
    /// route (`/op`, `/op-at`, `/changes`, `/dump`, `/session/close`, the
    /// blob family and the blob fetch, and `/events` on the accept path)
    /// can retire one, because
    /// [`Daemon::resolve_actor`]'s death arm closes the binding a dead or
    /// unknown token names — in this daemon's map, in M10, and in the
    /// credential memo. So routing one write frame twice COMMITS TWICE
    /// unless the frame carries an idempotency `id` (wire.md §Correlation
    /// and idempotency) — a speculative retry after a timeout duplicates
    /// the insert or mints a second document. Of the DISPATCH arms, the
    /// three that alter nothing are `GET /health`, `GET /chain` — whose
    /// permit returns within the request — and, in `client` builds, `GET /`;
    /// but no route does, because the reissue below sits ahead of dispatch
    /// on every request.
    ///
    /// What the caller owes on the way in is [`HttpRequest`]'s field
    /// precondition, which routing cannot check; what a [`Reply`] is not on
    /// the way out is the headers [`http::write_reply`] supplies,
    /// [`UNIVERSAL_HEADERS`] among them, which wire.md promises on every
    /// response.
    ///
    /// PANICS where the OS refuses entropy — the one panic this crate's own
    /// code raises by design on an honest request: `GET /challenge` and
    /// `POST /session` draw their nonce and their token from the crate's
    /// fail-stop OS source (`auth/entropy.rs`), which never mints a
    /// credential from anything weaker. `POST /session` draws AFTER M10 has
    /// minted the session the token would name (AUTH-4.23 declares the store
    /// that way), so that unwind drops a `SessionId` nothing can close, and a
    /// signed body's nonce is spent. Every other panic this router can raise
    /// is a defect — a premise this crate, or a store beneath it, relies on,
    /// failing — never a refusal an honest input earns. [`serve`] contains
    /// each to `500 internal_panic` and the worker survives it; a caller
    /// routing over its own transport owes the same containment, and finds
    /// the daemon serviceable after the unwind, every lock it holds being one
    /// that does not poison.
    ///
    /// Every request FIRST looks at the blocked-prefix list's supply
    /// ([`Daemon::reissue_blocked_prefixes`]) — ahead of dispatch and of
    /// every lock, so a reissue is in force before the request that noticed
    /// it resolves its own actor, `/events` included.
    ///
    /// THE BLOB UPLOAD's BODY: a caller over its own transport hands the
    /// family's two body-carrying methods their body in `req.body`, and the
    /// route reads it through the same source type the daemon's own
    /// transport streams a socket through (`server/http.rs`, THE STREAMING
    /// ARM) — that transport's body stays on the socket and reaches the route
    /// by a door of its own, beside the request and by value
    /// (`Daemon::route_parked`), so it is read by the one routing it was
    /// parked for.
    ///
    /// THE BLOB FETCH's ANSWER (wire.md §Media, THE FETCH): `GET /blob?i=`
    /// and `HEAD /blob?i=` admitted are [`Routed::Fetch`] — the whole file,
    /// checked, with the fetch pool's permit the value holds — which the
    /// accept path streams; every refusal of the route is a [`Routed::Reply`].
    pub fn route(&self, req: &HttpRequest) -> Routed<'_> {
        self.route_parked(req, None)
    }

    /// [`Daemon::route`], for the daemon's own transport, with the body that
    /// transport left on the socket — the blob upload's creation and resume
    /// (`server/http.rs`, THE STREAMING ARM) — handed in BESIDE the request,
    /// by value, so it is read by this one routing and by no other. Private:
    /// a caller over its own transport has no socket to park, and
    /// [`Daemon::route`] reads the request's own `body` through the same
    /// source type.
    fn route_parked(&self, req: &HttpRequest, parked: Option<BodySource<'static>>) -> Routed<'_> {
        self.reissue_blocked_prefixes();
        match (req.method.as_str(), req.path.as_str()) {
            ("GET", "/events") => Routed::EventStream,
            ("GET" | "HEAD", p) if blob_routes::is_fetch_path(p) => self.fetch_route(req),
            _ => Routed::Reply(self.reply(req, parked)),
        }
    }

    /// The request/response routes — every method/path pair but the event
    /// stream and the fetch's admitted answer, decided in one match. The
    /// token-accepting set (AUTH-4.43) is the arms wearing
    /// [`Daemon::token_route`]: `/op`, `/op-at`, `/changes`, `/dump` and
    /// `/session/close` here, plus `/events`, which the accept path runs by
    /// hand because a stream is not a [`Reply`] — and the blob upload's
    /// family and the blob fetch, whose every method resolves its actor the
    /// same way inside `blob_route` and `fetch_route` and carries the signal
    /// the same. `/health`, `/chain`, `/challenge`, `/session` and `/` are
    /// token-blind by design.
    fn reply(&self, req: &HttpRequest, parked: Option<BodySource<'static>>) -> Reply {
        match (req.method.as_str(), req.path.as_str()) {
            // The blob family's preflight names its own four methods, the
            // fetch's its own two; every other known path keeps the common
            // preflight, byte-identical.
            ("OPTIONS", p) if blob_routes::is_blob_path(p) => Reply::preflight_blob(),
            ("OPTIONS", p) if blob_routes::is_fetch_path(p) => Reply::preflight_fetch(),
            // CORS preflight (wire v4): 204 on any known path; an unknown
            // path falls through to the ordinary 404 below.
            ("OPTIONS", p) if path_is_known(p) => Reply::preflight(),
            // THE BLOB UPLOAD (media lane B; wire.md §Media): the family's
            // five method/path pairs, dispatched inside — each answer a
            // function of the presented token, so each wears the
            // class-varying headers as `/op`'s does.
            (_, p) if blob_routes::is_blob_path(p) => {
                let mut source = parked.unwrap_or_else(|| BodySource::bytes(&req.body));
                class_varying(self.blob_route(req, &mut source))
            }
            ("GET", "/challenge") => self.get_challenge(req.query.as_deref()),
            ("POST", "/session") => self.post_session(req),
            ("POST", "/session/close") => {
                self.token_route(req, |r| self.post_session_close(r, req))
            }
            // The four CLASS-VARYING routes (wire v7.6, lane 3.4 §5): each
            // answer is a function of the presented token's class, so each
            // wears [`class_varying`] — `Cache-Control: no-store` and
            // `Vary: Skepd-Session` — on every reply it can give, transport
            // refusals included. The blob family above and the blob fetch
            // (`fetch_route`) wear it the same, on the stream's head too.
            ("POST", "/op") => class_varying(self.token_route(req, |r| self.post_op(r, req))),
            ("POST", "/op-at") => {
                class_varying(self.token_route(req, |r| self.post_op_at(r, &req.body)))
            }
            ("GET", "/health") => self.get_health(),
            // Token-blind and class-invariant like `/health`, whose value it
            // recomputes at any position: a hash over the whole journal
            // discloses no byte, so no class varies it and no cache header
            // rides it.
            ("GET", "/chain") => self.get_chain(req.query.as_deref()),
            ("GET", "/changes") => {
                class_varying(self.token_route(req, |r| self.get_changes(r, req.query.as_deref())))
            }
            #[cfg(feature = "observe")]
            ("GET", "/dump") => {
                class_varying(self.token_route(req, |r| self.get_dump(r, req.query.as_deref())))
            }
            #[cfg(feature = "client")]
            ("GET", "/") => {
                Reply::bodied(200, "text/html; charset=utf-8", BOARD_HTML.as_bytes().to_vec())
            }
            (_, p) if path_is_known(p) => {
                refuse(TransportError::MethodNotAllowed, Some("see wire.md for the endpoint list"))
            }
            _ => refuse(TransportError::NoSuchEndpoint, Some(&req.path)),
        }
    }

    /// [`Daemon::resolve_actor`] against the HEAD — the route-level
    /// resolution run before dispatch on every token-accepting route, over
    /// ONE head snapshot: the world and the key table it carries. The
    /// resolved actor is handed to dispatch; the write sequences re-resolve
    /// at their own sites against the snapshot their gates stand on.
    ///
    /// A COMMAND: `resolve_actor`'s death arm retires the binding a dead or
    /// unknown token names, in this daemon's map, in M10 and in the
    /// credential memo. Idempotent — a second resolution of the same token
    /// finds `Unknown` and closes nothing — which is what makes running it
    /// at the route level and again under the lock harmless.
    fn resolve_at_head(&self, req: &HttpRequest) -> Resolved {
        let snap = self.engine.kernel().snapshot();
        self.resolve_actor(req, snap.world())
    }

    /// One token-accepting route (AUTH-4.43): resolve the actor against the
    /// HEAD — which may retire the binding a dead or unknown token names —
    /// run the handler, and attach the `Skepd-Session: closed` header the
    /// answer may owe (AUTH-6.7). The arm that wears this IS its
    /// declaration that the route accepts a token, so the set is a fact of
    /// [`Daemon::reply`]'s shape rather than a list each arm keeps for
    /// itself. `/events` is the one member that cannot: a stream is not a
    /// [`Reply`], so the accept path runs the same pair by hand
    /// (AUTH-4.44).
    ///
    /// The three write sequences wrap again, against their own LOCKED
    /// resolution — which can find a death this one did not — and that
    /// double is harmless by construction: [`with_signal`] attaches the
    /// header once however many sites observed the death.
    fn token_route(&self, req: &HttpRequest, f: impl FnOnce(&Resolved) -> Reply) -> Reply {
        let resolved = self.resolve_at_head(req);
        with_signal(f(&resolved), resolved.closed)
    }

    /// Log the config-lockout warnings (AUTH-4.9–4.11) to stderr — at
    /// startup, and again at the claim flip, which RES-30 requires
    /// unconditionally. One method because the three are one obligation:
    /// WHICH warnings apply is [`crate::auth::startup_warnings`]'s, but the
    /// claim reading they are computed against and the stream they go to
    /// are this daemon's, and [`serve`] would otherwise reach two levels
    /// into [`crate::auth::AuthState`] to spell them.
    ///
    /// `when` only labels the line. The claim itself is READ from the head's
    /// slice rather than supplied, so no caller can hand this method a fact
    /// the daemon can answer.
    fn log_config_warnings(&self, when: Moment) {
        let claimed = self.engine.kernel().snapshot().world().identity().claimant().is_some();
        for w in startup_warnings(&self.auth.cfg, claimed) {
            notice::line(format_args!("warning ({when}): {w}"));
        }
    }

    /// Log the blocked-prefix list IN FORCE to stderr (AUTH-4.70: "the
    /// startup log names the list in force"; AUTH-4.36 step 4b: an inert
    /// entry is "ignored at install and said so in the log") — the count,
    /// the header as the install resolved it, and the inert entries by
    /// name. Written at the three [`Moment`]s an install happens — at start,
    /// on a reissue, and at the claim, where the flip re-compares the issue
    /// against the claimant it first has. WHAT the lines say is
    /// `BlockedPrefixes::log_lines`'s; the stream is this
    /// daemon's, for [`Daemon::log_config_warnings`]'s reason.
    ///
    /// SILENT where no supply was named: that is a board whose operator
    /// supplies none, and there is no list to name.
    fn log_blocked_prefixes(&self, when: Moment) {
        let Some(path) = self.auth.blocked_supply_path() else { return };
        notice::lines(
            format_args!("blocked-prefix list ({when}, {}):", path.display()),
            &self.auth.cfg.blocked_prefixes().log_lines(),
        );
    }

    /// The node prefix in force, or its absence (REG-1.69), named ONCE at
    /// start — whether or not a list is supplied, because a hosted board
    /// launched without its prefix has its off-board test OFF and would
    /// otherwise learn so only at its first install. It is the one config the
    /// blocked-prefix list's off-board test reads (AUTH-4.36 step 4b as ruled
    /// 2026-09-18). WHAT the line says is
    /// `AuthConfig::node_prefix_line`'s; the stream is this
    /// daemon's, for [`Daemon::log_config_warnings`]'s reason.
    fn log_node_prefix(&self) {
        notice::line(self.auth.cfg.node_prefix_line());
    }

    /// THE REISSUE, at the head of every request (AUTH-4.70): where the
    /// supply file moved, [`AuthState::reissue_blocked_prefixes`] re-reads
    /// it and installs the new issue WHOLE under the credential write lock
    /// — the list's commit — and the log names the list then in force. A
    /// file that cannot be read, or is not a list, installs NOTHING: the
    /// list in force stands and the refusal is logged, once.
    ///
    /// A COMMAND, and called under NO lock: it takes the credential write
    /// lock, which is why it runs here and not where the list is read. The
    /// claimant the install compares against is the head's slice, read
    /// under that lock through the closure handed down.
    fn reissue_blocked_prefixes(&self) {
        let head_identity = || self.engine.kernel().snapshot().world().identity().clone();
        match self.auth.reissue_blocked_prefixes(head_identity) {
            None => {}
            Some(Reissue::Installed) => self.log_blocked_prefixes(Moment::Reissued),
            Some(Reissue::Refused(e)) => notice::line(format_args!(
                "blocked-prefix list: reissue REFUSED — {e}; the list in force stands"
            )),
        }
    }
}

// ── the checkpoint thread's work ─────────────────────────────────────────
//
// What the thread `listen.rs` spawns runs, as `Daemon` methods at the routes'
// layer: the kernel's flag read; the checkpoint with its consequences — the
// byte bound and the floor re-read, the feed compacted, the landing or the
// failure said; and, on a wake with no flag, the backstop's landing followed
// the same way. The three lines are rendered by the pure types below this
// block — `LandingLine`, `FailureLine`, `BackstopLine` — which the unit
// suite pins by `to_string()`, and every one goes to the operator stream
// through `Daemon::say_checkpoint_line`, classed.

/// THE CHECKPOINT THREAD's MEMORY between wakes — what one line of the
/// thread's leaves for the next: the inline count as last said and the
/// position it is counted from, the newest checkpoint as the thread last
/// looked, the resident set's high-water, and — under the test seam — every
/// line the arms rendered this uptime, since no suite captures stderr
/// in-process.
struct CheckpointMemory {
    looked: Mutex<Looked>,
    /// THE RESIDENT SET's HIGH-WATER: the largest reading the daemon has
    /// taken of its own physical memory (`memory_stats`), one reading per
    /// landing and per backstop wake, on the checkpoint thread — the figure
    /// line 25 carries as "peaked at". The daemon's own, not the kernel's
    /// `ru_maxrss`, which this differs from by what rose and fell between two
    /// readings. Zero before the first reading: a resident set is never zero.
    resident_peak: AtomicU64,
    /// TEST SEAM: the lines rendered this uptime, each `{class}: {text}`.
    #[cfg(any(test, feature = "test-hooks"))]
    lines: Mutex<Vec<String>>,
    /// TEST SEAM: the hold the two-crossings claim parks the thread at, read
    /// by `listen.rs`'s loop before it looks at the flag.
    #[cfg(any(test, feature = "test-hooks"))]
    hold: CheckpointHold,
}

/// What the thread last looked at and last said — one value under one lock,
/// because the three move together at every line.
struct Looked {
    /// THE INLINE COUNT AS LAST SAID (m13): the kernel's `inline_checkpoints`
    /// as the thread last carried it on a line — line 25's inline clause or
    /// the backstop's line. The next line's `{n}` is the count past this.
    inline_said: u64,
    /// THE POSITION THE COUNT IS COUNTED FROM — the next line's `{p}`: the
    /// newest checkpoint's position as the thread read it at the wake it
    /// last said a line at (the landing's own position on line 25), and
    /// before any line this uptime the open's START POINT, genesis as `0`.
    since: Seq,
    /// The newest checkpoint's position as the thread last looked — at the
    /// open, and at every line since — so a wake with no flag takes the
    /// landing's re-reads only where the newest moved.
    newest: Option<Seq>,
}

impl CheckpointMemory {
    /// The memory at the open: nothing said, the count counted from the start
    /// point, the newest checkpoint as the open found it.
    fn at_open(start_point: Seq, newest: Option<Seq>) -> CheckpointMemory {
        CheckpointMemory {
            looked: Mutex::new(Looked { inline_said: 0, since: start_point, newest }),
            resident_peak: AtomicU64::new(0),
            #[cfg(any(test, feature = "test-hooks"))]
            lines: Mutex::new(Vec::new()),
            #[cfg(any(test, feature = "test-hooks"))]
            hold: CheckpointHold { held: Mutex::new(false), released: Condvar::new() },
        }
    }

    /// One reading of the process's resident set, folded into the high-water,
    /// which is answered — `None` where no reading was ever made, this one
    /// included. A reading the crate cannot make moves nothing and fails
    /// nothing: the line then carries the peak so far, or says it is unread.
    fn note_resident_set(&self) -> Option<u64> {
        if let Some(reading) = memory_stats::memory_stats() {
            self.resident_peak.fetch_max(reading.physical_mem as u64, Ordering::AcqRel);
        }
        match self.resident_peak.load(Ordering::Acquire) {
            0 => None,
            peak => Some(peak),
        }
    }
}

/// TEST SEAM: the hold `Daemon::hold_the_checkpoint_thread` arms — the
/// thread parks at the top of its loop, before it looks at the flag, until
/// the release — so a suite lands a second crossing while the flag still
/// stands and the kernel's backstop runs it inline, with no race against
/// the thread. The stream hold's shape (`skep_media::serve::STREAM_HOLD`),
/// per daemon rather than per process.
#[cfg(any(test, feature = "test-hooks"))]
struct CheckpointHold {
    held: Mutex<bool>,
    released: Condvar,
}

/// THE LANDING's RE-READS, what follows ANY checkpoint — the figures the
/// one function below answers for the line.
struct ReRead {
    bytes_bound: NonZeroU64,
    floor: u64,
    compaction: FeedCompaction,
}

impl Daemon {
    /// Whether the kernel's cadence has crossed since the last checkpoint
    /// began (`Kernel::checkpoint_due`) — what the checkpoint thread reads
    /// before each run, and after one, since a crossing during a run sets
    /// the flag again.
    pub(crate) fn checkpoint_is_due(&self) -> bool {
        self.engine.kernel().checkpoint_due()
    }

    /// THE LANDING's RE-READS, after ANY checkpoint — the thread's own, a
    /// base that landed before its run failed, or a backstop's found on a
    /// wake with no flag: the cadence's byte bound ([`cadence_bytes_for`])
    /// and the media floor (`MediaGate::floor_in_force`) set from the newest
    /// checkpoint's size, then the change feed's five files compacted to the
    /// journal's reclaim floor (`WritePath::compact_feed_below_reclaim_floor`).
    /// ONE function, so the three arms cannot disagree about what follows a
    /// landing; the newest header is the caller's one read of it, its length
    /// handed in. Where the floor has not moved — a reclamation that failed,
    /// a landing below the retained window — the compaction finds nothing
    /// below the floor and writes nothing.
    fn re_read_after_a_landing(&self, newest_len: Option<u64>) -> ReRead {
        let bytes_bound = cadence_bytes_for(newest_len);
        self.engine.kernel().set_cadence_bytes(bytes_bound);
        let floor = MediaGate::floor_in_force(newest_len);
        self.media.set_floor(floor);
        let compaction = self.writes.compact_feed_below_reclaim_floor(&self.engine);
        ReRead { bytes_bound, floor, compaction }
    }

    /// One line of the checkpoint thread's on the operator stream, with its
    /// class word — the classed door, so no line of this section can go out
    /// without one — and, under the test seam, kept for the suite.
    fn say_checkpoint_line(&self, class: Class, text: String) {
        #[cfg(any(test, feature = "test-hooks"))]
        self.checkpointer.lines.lock().push(format!("{class}: {text}"));
        notice::emit(class, text);
    }

    /// RUN THE CHECKPOINT THE CADENCE CALLS FOR, on the calling thread —
    /// the checkpoint thread's one act (jw-R2 (c)), off the write path's
    /// guard: `Kernel::checkpoint`, which clears the due flag first and
    /// takes its own mutex and no applier lock, so every write proceeds
    /// beside it, timed by this thread's own `Instant` around the call,
    /// under no lock. On a LANDING: the newest checkpoint's header read once,
    /// the landing's re-reads taken from it ([`Daemon::re_read_after_a_landing`]),
    /// and ONE line — [`LandingLine`], the position and the size, the run's
    /// duration, the journal bytes the kernel reclaimed
    /// (`Kernel::last_reclaimed_bytes`, read after the `Ok`), both bounds in
    /// force, the volume's free space as the media floor reads it (the
    /// gate's one door, so the floor's refusal and this line never
    /// disagree), the resident set's high-water, the feed's compaction per
    /// file, and the inline count where it moved since the thread last said
    /// it. On a FAILURE: ONE line per ATTEMPT — [`FailureLine`]: the head's
    /// position when the run began as an ordering, the cause (a full volume
    /// in the operator's words), and the trailer the cause earns; and where
    /// the kernel answers that a BASE LANDED before the step after its rename
    /// failed (`CheckpointError::Landed`), the newest header is read after
    /// the call — the base is on disk — the landing's re-reads are taken off
    /// it, and the line names the landed position and which step failed.
    /// The kernel removes its own temp file before answering a failure that
    /// landed nothing.
    pub(crate) fn service_the_checkpoint(&self) {
        let kernel = self.engine.kernel();
        let at = kernel.current_seq();
        let began = Instant::now();
        let outcome = kernel.checkpoint();
        let duration_ms = began.elapsed().as_millis();
        match outcome {
            Ok(landed) => {
                let newest = kernel.newest_checkpoint();
                let re_read = self.re_read_after_a_landing(newest.as_ref().map(|h| h.len));
                let runs = kernel.inline_checkpoints();
                let line = {
                    let mut looked = self.checkpointer.looked.lock();
                    let inline = (runs != looked.inline_said).then(|| InlineRuns {
                        runs: runs.saturating_sub(looked.inline_said),
                        since: looked.since,
                    });
                    looked.inline_said = runs;
                    looked.since = landed;
                    looked.newest = newest.as_ref().map(|h| h.seq);
                    LandingLine {
                        position: landed,
                        bytes: newest.map(|h| h.len),
                        duration_ms,
                        reclaimed: kernel.last_reclaimed_bytes().unwrap_or(0),
                        bytes_bound: re_read.bytes_bound.get(),
                        floor: re_read.floor,
                        free_space: self.media.free_space(),
                        resident_peak: self.checkpointer.note_resident_set(),
                        compaction: re_read.compaction,
                        inline,
                    }
                };
                self.say_checkpoint_line(Class::Landing, line.to_string());
            }
            Err(e) => {
                let landed_at = match &e {
                    CheckpointError::Landed { .. } => {
                        let newest = kernel.newest_checkpoint();
                        self.re_read_after_a_landing(newest.as_ref().map(|h| h.len));
                        let seq = newest.map(|h| h.seq);
                        self.checkpointer.looked.lock().newest = seq;
                        seq
                    }
                    CheckpointError::Io(_)
                    | CheckpointError::Serialize(_)
                    | CheckpointError::Poisoned => None,
                };
                let line = FailureLine { at, landed_at, error: &e };
                self.say_checkpoint_line(Class::Failure, line.to_string());
            }
        }
    }

    /// THE BACKSTOP's WAKE (m13; §4 rows 25 and 35) — what the checkpoint
    /// thread runs on every wake AFTER the flag's arm, so a wake with NO flag
    /// is answered: where the kernel's count of checkpoints run inline on a
    /// committing thread (`Kernel::inline_checkpoints`) moved past the count
    /// the thread last said, the newest checkpoint is read ONCE and, where
    /// it moved since the thread last looked, the landing's re-reads are
    /// taken off it — the same function the landing arm runs — and the
    /// backstop's line is said ([`BackstopLine`]): the runs since the last
    /// line, the position they are counted from, and whether the last of
    /// them landed or how it failed (`Kernel::last_inline_checkpoint_failure`).
    /// Said once for each movement of the count and never otherwise; a
    /// count line 25 has just carried is one that moved not. The resident
    /// set is read here too, as at a landing.
    pub(crate) fn follow_the_backstop(&self) {
        let kernel = self.engine.kernel();
        let runs = kernel.inline_checkpoints();
        let line = {
            let mut looked = self.checkpointer.looked.lock();
            if runs == looked.inline_said {
                return;
            }
            let newest = kernel.newest_checkpoint();
            let newest_seq = newest.as_ref().map(|h| h.seq);
            if newest_seq != looked.newest {
                self.re_read_after_a_landing(newest.map(|h| h.len));
                looked.newest = newest_seq;
            }
            let line = BackstopLine {
                runs: runs.saturating_sub(looked.inline_said),
                since: looked.since,
                last_failure: kernel.last_inline_checkpoint_failure(),
            };
            looked.inline_said = runs;
            if let Some(seq) = newest_seq {
                looked.since = seq;
            }
            line
        };
        self.checkpointer.note_resident_set();
        self.say_checkpoint_line(Class::Landing, line.to_string());
    }
}

/// LINE 25 — THE LANDING, in the operator stream's words (`operations.md`
/// §1.1 row 25), rendered from the figures the thread read: a pure value,
/// so the unit suite pins the words by `to_string()` at fixed figures. The
/// class word is the emitter's (`Class::Landing`); every dimension is spelt
/// the stream's one way — a position as `position N`, a file by its name,
/// a duration in milliseconds.
struct LandingLine {
    /// The position the checkpoint embodies — `Kernel::checkpoint`'s answer.
    position: Seq,
    /// The file's length as the newest header claims it, `None` where the
    /// header did not answer — "size unread".
    bytes: Option<u64>,
    /// The run's duration, whole milliseconds, the thread's own `Instant`.
    duration_ms: u128,
    /// The journal bytes the landing reclaimed; zero is "nothing reclaimed".
    reclaimed: u64,
    /// The cadence's byte bound in force after the re-read.
    bytes_bound: u64,
    /// The media floor in force after the re-read.
    floor: u64,
    /// The volume's free space as the media floor reads it.
    free_space: u64,
    /// The daemon's high-water of its resident set, in bytes; `None` where
    /// no reading was ever made — "unread".
    resident_peak: Option<u64>,
    /// The feed's compaction: the fence, and the files that stood.
    compaction: FeedCompaction,
    /// The inline count where it moved since the thread last said it, with
    /// the position it is counted from; `None` where it did not move, and
    /// the clause is absent.
    inline: Option<InlineRuns>,
}

/// The inline clause's two figures — line 25's and the backstop line's.
struct InlineRuns {
    /// The checkpoints run inline on a writer since `since`.
    runs: u64,
    /// The position the count is counted from (`Looked::since`).
    since: Seq,
}

impl fmt::Display for LandingLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "checkpoint at position {} landed (", self.position)?;
        match self.bytes {
            Some(bytes) => write!(f, "{bytes} bytes")?,
            None => f.write_str("size unread")?,
        }
        write!(f, ") in {} ms; ", self.duration_ms)?;
        match self.reclaimed {
            0 => f.write_str("nothing reclaimed")?,
            reclaimed => write!(f, "{reclaimed} journal bytes reclaimed")?,
        }
        write!(
            f,
            "; the cadence's byte bound {}, the media floor in force {}, the volume's free \
             space {}; ",
            self.bytes_bound, self.floor, self.free_space
        )?;
        match self.resident_peak {
            Some(peak) => write!(f, "the process's resident set peaked at {peak} bytes")?,
            None => f.write_str("the process's resident set unread")?,
        }
        f.write_str("; the change feed's files ")?;
        match self.compaction.fence {
            Some(fence) => {
                write!(f, "compacted below position {}", fence.saturating_add(1))?;
                for file in &self.compaction.standing {
                    write!(f, ", {file} standing as it was")?;
                }
            }
            None => f.write_str("hold nothing below the reclaim floor")?,
        }
        if let Some(inline) = &self.inline {
            write!(
                f,
                "; {} checkpoints ran inline on a writer since position {}",
                inline.runs, inline.since
            )?;
        }
        Ok(())
    }
}

/// LINE 26 — THE FAILURE, in the operator stream's words (row 26; §4 row
/// 2), rendered from what the kernel answered: a pure value the unit suite
/// pins by `to_string()` at each cause. Where the error is
/// `CheckpointError::Landed`, the line opens on the landed base — "a
/// checkpoint landed at position {n} but {step} failed" — the step in the
/// DAEMON's three words (the directory's sync, retention, the journal's
/// reclamation), chosen by `LandedStep`'s arm and never the kernel's
/// `Display`; otherwise on the head's position when the run began, worded
/// as the ordering it is. The cause: a full volume (`StorageFull`) in the
/// operator's words beside the OS's text, in the `Io` arm and the `Landed`
/// arm alike; every other cause its own `Display`. The trailer is keyed to
/// the cause: an I/O cause retries at the cadence's next crossing, a
/// poisoned kernel takes no checkpoint until a restart, a world that will
/// not serialize refuses the same way until the build fixes it. The class
/// word is the emitter's (`Class::Failure`).
struct FailureLine<'a> {
    /// `Kernel::current_seq` read BEFORE the call — an ordering, since the
    /// checkpoint loads its own root under its mutex.
    at: Seq,
    /// Where a base landed: the newest checkpoint's position read AFTER the
    /// call, `None` where its header did not answer.
    landed_at: Option<Seq>,
    error: &'a CheckpointError,
}

impl fmt::Display for FailureLine<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.error {
            CheckpointError::Landed { step, cause } => {
                match self.landed_at {
                    Some(landed) => write!(f, "a checkpoint landed at position {landed}")?,
                    None => write!(
                        f,
                        "a checkpoint landed at or above position {} (its header unread)",
                        self.at
                    )?,
                }
                let step = match step {
                    LandedStep::DirectorySync => "the directory's sync",
                    LandedStep::Retention => "retention",
                    LandedStep::Reclamation => "the journal's reclamation",
                };
                write!(f, " but {step} failed: {}", VolumeWords(cause))?;
            }
            CheckpointError::Io(io) => write!(
                f,
                "checkpoint FAILED (the head stood at position {} when the run began): {}",
                self.at,
                VolumeWords(io)
            )?,
            other @ (CheckpointError::Serialize(_) | CheckpointError::Poisoned) => write!(
                f,
                "checkpoint FAILED (the head stood at position {} when the run began): {other}",
                self.at
            )?,
        }
        // THE TRAILER, keyed to the cause: what still serves and when the
        // next attempt comes — a promise of a crossing only where one can.
        f.write_str(match self.error {
            CheckpointError::Io(_) | CheckpointError::Landed { .. } => {
                "; the journal is not reclaimed and holds every commit; the next attempt is at \
                 the cadence's next crossing"
            }
            CheckpointError::Poisoned => {
                "; no checkpoint is taken until a restart (the kernel's halt, said above)"
            }
            CheckpointError::Serialize(_) => {
                "; every crossing refuses the same way until the world encodes: the build's to fix"
            }
        })
    }
}

/// An I/O cause in the operator's words: a full volume (`StorageFull`) is
/// "the volume is full" with the OS's text beside it — the one cause whose
/// act, room freed on the volume, is the operator's alone — and every other
/// kind its own text.
struct VolumeWords<'a>(&'a std::io::Error);

impl fmt::Display for VolumeWords<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.kind() == std::io::ErrorKind::StorageFull {
            write!(f, "the volume is full ({})", self.0)
        } else {
            write!(f, "{}", self.0)
        }
    }
}

/// THE BACKSTOP's LINE (`operations.md` §1.1 m13), rendered from the
/// kernel's count and its last inline run's text: the checkpoints run
/// inline on a writer since the position the count is counted from
/// (`Looked::since` — the newest checkpoint's position at the thread's last
/// line, the start point before any), and whether the last of them landed
/// or how it failed, in the kernel's rendered words. A pure value, pinned by
/// `to_string()`; emitted under `Class::Landing`.
struct BackstopLine {
    runs: u64,
    since: Seq,
    /// `Kernel::last_inline_checkpoint_failure`: `None` where the last inline
    /// run landed.
    last_failure: Option<String>,
}

impl fmt::Display for BackstopLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "checkpoint: the cadence outran the checkpoint thread; {} checkpoints ran inline on \
             a writer since position {}, the last ",
            self.runs, self.since
        )?;
        match &self.last_failure {
            None => f.write_str("landed"),
            Some(cause) => write!(f, "FAILED: {cause}"),
        }
    }
}

/// AUTH-2.86's two startup warnings, rendered from what the engine's open
/// found — one line per retained checkpoint that was NOT a start point,
/// naming it, why, and the start point the world was resolved from; and one
/// line where the start point itself carried no identity slice and resolved
/// to the EMPTY table (AUTH-2.83), naming that checkpoint and the empty
/// resolution — the operator's one tell that a build which wrote no slice
/// ran on this board. Nothing where there is nothing to say, which is every
/// open on a board whose checkpoints carry the slice. The downgrade window's
/// own commits read `key: null` on `/changes` (AUTH-1.52), which needs no
/// line here.
fn recovery_warnings(recovery: Option<&Recovery>) -> Vec<String> {
    let Some(recovery) = recovery else { return Vec::new() };
    let start = Base(recovery.start_point);
    let mut lines: Vec<String> = recovery
        .skipped
        .iter()
        .map(|skipped| {
            format!(
                "checkpoint.{} is not a start point and was SKIPPED — {}; the world was \
                 resolved from {start} and replayed forward from there",
                skipped.seq.0, skipped.why
            )
        })
        .collect();
    if recovery.identity_resolved_empty {
        lines.push(format!(
            "{start} carries no identity slice and no credential deposit: its key table \
             RESOLVED EMPTY — no account keyed, the board unclaimed — rather than being read \
             from the checkpoint; a build that wrote no identity slice ran on this board"
        ));
    }
    lines
}

/// A BASE as every line of the open names it: `genesis` where the world was
/// folded from nothing — `Seq(0)`, no checkpoint file — and `checkpoint.{n}`
/// for a retained checkpoint's position, the file's own name. ONE rendering,
/// so the recovery's landing and the two warnings above it spell the start
/// point one way and a reader joins them on it.
struct Base(Seq);

impl fmt::Display for Base {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Seq(0) => f.write_str("genesis"),
            Seq(seq) => write!(f, "checkpoint.{seq}"),
        }
    }
}

/// THE OPEN's FIRST LINE (`operations.md` §3.1 step 3; m7): the data
/// directory, as the operator named it — `data-dir {path}` — said before
/// the seeding check and the engine's open, so the one line that names the
/// directory stands on the stream before anything is read from it. A pure
/// value the unit suite pins by `to_string()`; emitted under `Class::Open`
/// through [`say_open_line`].
struct DataDirLine<'a>(&'a Path);

impl fmt::Display for DataDirLine<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "data-dir {}", self.0.display())
    }
}

/// THE RECOVERY's LANDING (m7), in the operator stream's words — `recovered
/// from {checkpoint.n | genesis}, {k} commits replayed, in {d} ms` — rendered
/// from the engine's own account of its open: the base it loaded ([`Base`]'s
/// words, the ones the two warnings name the start point by), the commits
/// it replayed above that base (`Recovery::replayed`: transactions, never
/// the records they carry; `0` where the base was the committed head, a
/// fresh board's genesis included) and the engine's open's duration, whole
/// milliseconds, the daemon's own `Instant` around the call. A pure value
/// the unit suite pins by `to_string()`; emitted under `Class::Open` through
/// [`say_open_line`].
struct RecoveredLine {
    start_point: Seq,
    replayed: u64,
    duration_ms: u128,
}

impl RecoveredLine {
    /// The line from the engine's account, where it gave one. An engine that
    /// answers NO account loads nothing — `Durability::InMemory`, which no
    /// daemon opens under: every daemon's open is journaled — and is said as
    /// a genesis that replayed nothing, which is what the open's sizing reads
    /// of the same absence.
    fn of(recovery: Option<&Recovery>, duration_ms: u128) -> RecoveredLine {
        RecoveredLine {
            start_point: recovery.map_or(Seq(0), |r| r.start_point),
            replayed: recovery.map_or(0, |r| r.replayed),
            duration_ms,
        }
    }
}

impl fmt::Display for RecoveredLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "recovered from {}, {} commits replayed, in {} ms",
            Base(self.start_point),
            self.replayed,
            self.duration_ms
        )
    }
}

/// THE OPEN's OWN LINES, SAID: the classed door for the open's report — one
/// function, so every line of the open's own goes out under `Class::Open`
/// and no site spells the class. Through the queue, as every notice is.
fn say_open_line(line: impl fmt::Display) {
    notice::emit(Class::Open, line);
}

/// When the daemon names its configuration on the operator stream — the
/// label every such line carries. Closed, so a caller names one of the three
/// moments rather than spelling a label, and no call site reads backwards.
#[derive(Clone, Copy, Debug)]
enum Moment {
    /// Before the listener serves ([`serve`]).
    AtStart,
    /// A replaced supply file installed ([`Daemon::reissue_blocked_prefixes`]).
    Reissued,
    /// The claim flip (`op.rs`'s `Daemon::on_claim_flip`).
    AtClaim,
}

/// The label as a line spells it.
impl std::fmt::Display for Moment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Moment::AtStart => "at start",
            Moment::Reissued => "reissued",
            Moment::AtClaim => "at claim",
        })
    }
}

#[cfg(test)]
mod tests;
