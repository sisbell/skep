//! The process: one long-running server owning one `World`.
//!
//! The daemon is transport, configuration, and lifetime — every handler is
//! parse/marshal/dispatch/configure; every decision lives in a store, save
//! the three the spec gives the daemon — the session layer's gates
//! (`skep-core`'s `auth/`, the upload family's among them), the published
//! head's cadence (`skep-core`'s `commits/head.rs`) and the media door
//! (`skep-media`'s `door.rs`).
//!
//! Split for testability: [`Daemon`] holds the state and routes
//! `&HttpRequest → Routed` with no socket anywhere; [`serve`]/[`Skepd`]
//! wrap it in a synchronous accept loop over a plain `TcpListener`. The
//! HTTP/1.1 subset this daemon speaks (`GET`, `HEAD`, `POST`, `PATCH`,
//! `DELETE` and `OPTIONS`, `Content-Length` bodies, one request per
//! connection, `Connection: close` on every final response) is written out
//! here rather than taken from a server library, because the commit stream
//! needs two things a pull-based library response cannot give: event bytes
//! flushed to the socket at commit time, and a server-initiated close at
//! shutdown. Owning the socket makes both one-line facts.
//!
//! **History is served from the journal** (wire v3): `POST /op-at` answers
//! any read frame as of any committed position the journal has not
//! reclaimed, `GET /dump?at=N` (observe builds) dumps that position's world,
//! and `GET /chain?at=N` answers the commit chain's value there — the
//! kernel's recomputation off its journal, no world folded. All three ask
//! `history.rs`, which owns the reconstruction (the engine's bounded replay),
//! the chain read beside it, their one concurrency budget, and the `as_of`
//! stamping; what `server` adds is the envelope, the read/write
//! classification, and the one mapping from an unavailable answer onto the
//! wire's transport errors. Writes never reach history — a write frame is
//! refused at the transport (`400 write_at_history`) before anything runs —
//! and the live `/op` path is untouched.
//!
//! **Durability is configuration, not code**: [`Daemon::open`] opens M2's
//! kernel on a real directory with `Durability::Fsync` (rollback burned-seq
//! policy), a checkpoint cadence of every 1024 commits by default or a byte
//! bound, whichever first — the bound a quarter of the newest checkpoint's
//! size, the start point's at open, and never below 24 MiB, re-read as each
//! checkpoint lands — deferred to the daemon's own checkpoint thread
//! (`server/listen.rs`), which runs the checkpoint off the write path's
//! guard, says a failure once on the operator stream, and after each
//! landing reads what the change feed holds for its line; and two retained
//! checkpoints by default, the journal reclaimed below the oldest of them —
//! the cadence's count, the retained count and the reclamation are the
//! start's three settings ([`StartOptions`]), read once at the open, said
//! there and persisted nowhere — genesis on a fresh store, recovery on an
//! existing one, both inside `Engine::open`. The journal's reclamation
//! bounds the board's
//! STATES alone: the change feed's files are kept whole from genesis
//! (wire.md §The change feed, Retention), the daemon holding a window of
//! recent positions in memory and reading the rest from disk by position,
//! so no landing rewrites a feed file. Beside the kernel's files and the
//! blob store's (under `blobs/`, opened through `MediaGate::open_with`), the
//! only files the daemon writes are the change feed's: the commit-metadata
//! sidecar `commits.log`, its four derived sidecars (`feed-index.log`,
//! `feed-offsets.log`, `feed-masked.log`, `feed-streams.log`), the attest
//! store `feed-attest.log` — the marker slot mirrored per attested commit,
//! primary state below the reclaim floor as the five beside it now are —
//! and, transiently while the walk's landing rewrites any, its `.compact`
//! twin — all opened here through `Commits::open` and owned by
//! `skep-core`'s `commits/sidecar.rs` and `commits/feed/`; nothing here
//! writes any file of the world's, which is why two daemons replaying one
//! journal still converge byte-identically.
//!
//! **Identity is the AUTH session layer** (`skep-core`'s `auth/`):
//! `GET /challenge` and `POST /session` mint a session by one of two arms —
//! a bare bind (v1's form, honored only from a loopback peer whose `Origin`,
//! where it sends one, is admitted, and only while the board is not
//! enforcing) or a signed challenge/response — and the daemon maps the
//! opaque token → M10-minted `SessionId` in its own state, so a `SessionId`
//! never rides the wire (M10's non-forgeability precondition). A request
//! with no token, one whose binding is gone, or one whose bare bind its peer
//! or origin refuses runs under M10's guest session (`SessionId::GUEST`,
//! bound to no principal): reads need no principal and are answered at the
//! guest's class, writes get M10's own `Unauthenticated`, and a token naming
//! no live binding — unknown to this daemon, or its binding dead — carries
//! `Skepd-Session: closed` back.
//! `auth/` owns the rest and `server` holds none of it: the two origin
//! sets and their publication, the handshake, the credential write lock,
//! the ordered refusal producers, and the readers of the World's identity
//! slice — the key table the engine folds at each credential commit and
//! checkpoints with the world (AUTH-2.79), which every route here reads off
//! the one head snapshot it already holds, so the world a check reads and
//! the table it reads are one committed state.
//! What `server` adds is the three write sequences that call them in their
//! pinned order, and the `/session` and `/health` marshals. Tokens are
//! uptime-scoped; the daemon binds `127.0.0.1` unless `--bind` or
//! `SKEPD_BIND` names another IPv4 address.
//!
//! **Cross-origin posture (wire v7)**: every final response carries
//! `Access-Control-Allow-Origin: *` and
//! `Access-Control-Expose-Headers: Skepd-Session`, written from one
//! constant ([`UNIVERSAL_HEADERS`]) where every final response begins — the
//! reply path, the event stream and the blob fetch alike — so no final
//! response this daemon writes can miss them, and `OPTIONS` on any known
//! path answers a 204 preflight naming the allowed methods and headers. The
//! `*` is a scope decision that holds with authentication in force (wire.md
//! §Cross-origin access), because neither credential is browser-ambient.
//! Reads need no principal, so `*` grants any page the whole read surface
//! at the guest's class. Writes do not follow it: a write needs a session,
//! `skep_core::auth::session::bare_bind_allowed` refuses a bare bind whose
//! `Origin` is not in the bare set (a browser sends that header on every
//! cross-origin POST), and the signed arm binds its origin inside the
//! signature. A foreign page's POST is fenced by the daemon rather than
//! by what the browser lets it read back, which is why a narrower ACAO is
//! declined.
//!
//! **The class-scan bound (wire v7.9; PUB-8.36, PUB-8.37; the home-index
//! record's D3)**: `/op` bounds the link-discovery reads by two pools on one
//! card, [`ClassScans`]. The class pool admits at most
//! [`MAX_CONCURRENT_CLASS_SCANS`](scan::MAX_CONCURRENT_CLASS_SCANS)
//! class-scan-SHAPED reads at once — the four-sets whose shape is
//! world-sized: `ty` alone, nothing at all, or a `home` at an account or the
//! node (`scan::is_class_scan` states the shapes and what each walks). The
//! per-document pool admits at most
//! [`MAX_REGION_READS_PER_DOCUMENT`](scan::MAX_REGION_READS_PER_DOCUMENT)
//! region reads of one document at once — the region family and
//! `delete_orphans`, keyed by the `d` their frame names — inside a ceiling of
//! [`MAX_CONCURRENT_REGION_READS`](scan::MAX_CONCURRENT_REGION_READS) across
//! every document, so one page's readers contend among themselves and the
//! pools cannot multiply past the workers. A region read that finds its
//! document at its width waits for one of the document's permits —
//! [`REGION_READ_WAIT`](scan::REGION_READ_WAIT) at most, in one of
//! [`MAX_REGION_READ_WAITERS`](scan::MAX_REGION_READ_WAITERS) waiting slots
//! across the board — before it is refused (the home-index record's
//! D3 (b)); the class pool and the ceiling refuse at once. Every other link
//! read takes no permit. The admission takes the permit after the parse and
//! the session read and before M10 is asked, so a refused request costs the
//! parse, the session read and, at its document's width, at most the wait,
//! and an admitted one holds its slot for the whole answer. The pools are
//! instances of [`skep_util::permits::Permits`], disjoint from the
//! reconstruction pool and from each other — a scan spends no reconstruction
//! permit and a reconstruction spends no scan permit. The bound admits or
//! refuses a request (`503 scan_busy`, retry-class, the body naming the op)
//! and never alters an answer: M7 and M8 are not told a query is bounded. A
//! concurrency bound, never a rate statement.
//!
//! **Writes go through one card** (`skep-core`'s `commits`): `POST /op` —
//! the daemon's only write route — hands each write its sequence admits to
//! `Commits::commit_under`, which commits it, records its change-feed
//! entry, and announces its position, in that order and inside the
//! serialization guard the write sequences here hold — and then gives the
//! published head writer its turn, which when the cadence is due writes `H`
//! under that same guard before `commit_under` returns. What `server` adds
//! is the frame's parse, its classification, and the three write sequences,
//! which take `serial_lock` themselves so their gates and the execute they
//! gate stand on one committed state; the ordering the commit stream and
//! the change feed below rest on is not a thing a handler here can take
//! apart. Reads execute directly and take no lock. Every write that reaches
//! a lock holds a permit of the write pool (`operations.md` §4 rows 25, 27),
//! taken before the credential lock and the guard — the plain sequence's
//! first act, and the credential and registry sequences' after the pre-lock
//! refusals they answer, which cost none — the fifth instance of
//! [`skep_util::permits::Permits`], of width [`MAX_CONCURRENT_WRITES`],
//! disjoint from the reconstruction, class-scan, fetch and upload pools,
//! held through `commit_under`'s return; a write that finds none is refused
//! `503 write_busy`, retry-class, before any lock, nothing committed. The
//! head writer's own commits take none: they run in the turn of the write
//! that triggers them — inside `commit_under`, after a refusal, or in the
//! claim's flip — under the permit that write already holds, and at the
//! open before anything is served. So while an inline backstop holds the
//! guard, writes occupy at most W workers — the trigger and W − 1 parked —
//! and `/health`, `/session` and every read stay answered.
//!
//! **The commit stream (wire v4)**: `GET /events` is a `text/event-stream`
//! of committed log positions — one event carrying the last announced
//! position on connect, then an event whenever a later position is
//! announced.
//! `skep-core`'s `commits` owns the stream: what a subscriber is told first
//! and next, and the coalescing that falls out of asking "anything past
//! what I last sent"; `Subscribers` (in `listen.rs`) owns the budget, the
//! admission, and the join at shutdown. What `server` adds is the SSE
//! framing (`http.rs`'s `write_commit_event`), the subscriber's loop
//! (`listen.rs`'s `serve_events`), and the hand-off that keeps an open
//! stream off the op pool — the accepting worker gives the socket to a
//! dedicated thread and returns to `accept`.
//!
//! **The change feed (wire v6; class-gated, wire v7.8)**:
//! `GET /changes?since=N` answers, a page at a time, the committed positions
//! in `(N, head]` the presented token's class may see, oldest first, each
//! with its op kind, affected document(s) reduced to the readable ones, and
//! commit wall-clock time — so clients refresh what they display instead of
//! re-walking the world on every SSE tick. `sidecar.rs` owns `commits.log`:
//! its crash honesty, its retention, and what a position whose record was
//! lost answers; `feed/` owns the mask, the four derived sidecars, the
//! attest store, the supplement merge and the two narrowings (`under=`,
//! `drafts=true`); `skep-core`'s `commits` owns the ordering that makes the
//! sidecar's invariants true. What `server` adds is the query's parse, the
//! requester's feed class — resolved once per request off one head
//! snapshot and threaded down (PUB-6.40) — the marshal, and `/health`'s
//! `head_time`.
//!
//! **The served client (wire v6, `client` feature, default off)**: `GET /`
//! answers the embedded guest reader (`skep/clients/board.html`,
//! `include_str!` at build — the binary is self-contained), `text/html`,
//! same CORS posture as everything else. One file by design; there is no
//! asset pipeline. The page is read-only — it holds no key, token or
//! session and acts on nothing, the guest view R89 permits a board to serve
//! — and the feature is off by default so a hosted image serves no page
//! unless the operator chose to; the notebook packaging turns it on. The
//! feature's note in `Cargo.toml` says the same. A build without the
//! feature has no `/` route (404).

// The transport: sockets, threads, and the HTTP bytes — and beside them, at
// their layer, the embedding helper: the start a program that is not the
// binary takes, and the wait for the cell index's walk.
mod embed;
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
use std::num::{NonZeroU64, NonZeroUsize};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

#[cfg(any(test, feature = "test-hooks"))]
use parking_lot::Condvar;
use parking_lot::Mutex;
use skep_address::Address;
use skep_engine::{Engine, EngineError, HistoryError, Recovery, World, WORLD_FORMAT};
use skep_febe::OperationSurface;
use skep_identity::HasIdentity;
use skep_blobs::{LogRead, Store};
use skep_kernel::{
    BurnedSeqPolicy, CheckpointError, CheckpointHeader, CheckpointPolicy, DamagedTail,
    Durability, InlineCheckpoint, KernelConfig, LandedStep, Reclaim, SaltSource, Seq,
    CHECKPOINT_FORMAT, JOURNAL_FORMAT,
};
use skep_media::cell::DESIGNATION;
use skep_media::gate::{MediaGate, UnreadDeposit, STORE_DIR};
use skep_media::index;
use skep_media::limits::MAX_BLOB_BYTES;
use skep_media::pools::{FetchPool, UploadPool};
use skep_media::pruner::Pruner;
use skep_media::MediaOptions;
#[cfg(feature = "observe")]
use skep_namespace::PrincipalId;
use skep_util::notice::{self, Class, Moment};
use skep_util::permits::{Edge, EdgeTracker, Permits, PoolEdgeLine};
use skep_util::source::Source;

use std::sync::{Arc, OnceLock};

use skep_core::auth::session::CHALLENGE_TTL_MS;
use skep_core::auth::{
    startup_warnings, AuthOptions, AuthStart, AuthState, PortAlreadyBound, Reissue, MAX_LIVE_NONCES,
};
use skep_core::codec::JsonCodec;
use crate::history::History;
use crate::limits::MAX_SMALL_BODY;
use crate::tools;
use skep_core::limits::{EDGE_HOLD_DOWN, MAX_REQUEST_BODY};
#[cfg(any(test, feature = "test-hooks"))]
use skep_core::commits::LinesSaid;
use skep_core::commits::{
    AttestStoreFigures, Commits, FeedFigures, FeedPending, FirstHead, Seeded, StoppedFile,
};
use skep_namespace::ghost_home_document;
use skep_core::serial::SerialFigures;
use actor::Resolved;
use reply::{class_varying, refuse, with_signal, TransportError};
use request::BodySource;
use scan::ClassScans;

pub use skep_core::auth::session::Peer;
#[cfg(any(test, feature = "test-hooks"))]
pub use embed::embed_seeded;
pub use embed::{embed, EmbedError, IndexNotReady};
pub use http::UNIVERSAL_HEADERS;
pub use listen::{
    bind, serve, serve_bound, Listener, Skepd, DEFAULT_PORT, DEFAULT_WORKERS, MIN_WORKERS,
};
pub use reply::{Body, Fetch, Reply, Routed};
pub use request::HttpRequest;

/// The auto-checkpoint cadence's commit half by default: every 1,024 commits.
///
/// It is the default of the start's `checkpoint_every`
/// ([`StartOptions`]; the binary's `--checkpoint-every`), the figure in
/// force at every start that names none. M2 evaluates the count on-commit;
/// the daemon's checkpoint thread runs a checkpoint on the kernel's due
/// flag, never on a timer. Together with the retained count
/// ([`RETAINED_CHECKPOINTS`] by default) the count in force sets the
/// sidecar's reconstruction ceiling (see `CommitsLog::open`): raising either
/// lengthens the walk behind the listener on a data dir whose commit
/// metadata is missing. The byte half beside it —
/// [`CHECKPOINT_BYTES_FLOOR`], [`CHECKPOINT_BYTES_SHARE`] — is no setting,
/// and crosses first on a board of large commits, where this count alone
/// would let the journal outrun the floor.
const CHECKPOINT_EVERY_COMMITS: NonZeroU64 = NonZeroU64::new(1024).expect("1024 is nonzero");

/// The cadence's byte bound's floor, 24 MiB.
///
/// The figure is interim (D1; the journal-writes investigation §3.2). It is
/// the least the byte bound B is, whatever the newest checkpoint's size.
/// The bound is what makes the media floor a guarantee: the floor must hold
/// the next checkpoint, the journal appended until it lands and the
/// daemon's own lines for those commits, which holds iff B·(1 + g + d) ≤ C
/// — C the newest checkpoint's size, g the checkpoint's growth per journal
/// byte, d the daemon's lines per journal byte, 1 + g + d measured from
/// 1.35 (bulk prose) to ≈ 3.0 (tiny attested commits). Below the floor's
/// crossover the constant half of the media floor covers C + 3·B + one
/// segment at 24 MiB with room; above it [`CHECKPOINT_BYTES_SHARE`] holds.
/// The grace of the deferred cadence (one window, the backstop's) doubles
/// the window the floor must cover, which the share's slack absorbs.
const CHECKPOINT_BYTES_FLOOR: u64 = 24 * 1024 * 1024;

/// The cadence's byte bound's share, 4.
///
/// The figure is interim (D1). The byte bound B is the newest checkpoint's
/// size divided by this — at open, the start point's — never below
/// [`CHECKPOINT_BYTES_FLOOR`], re-read as each checkpoint lands. A quarter
/// holds the inequality above at every measured regime with slack of at
/// least C/4 — a half holds prose and 1 KiB values alone, a third every
/// unsigned size and the signed tiny case at its edge — at a checkpoint I/O
/// of about four bytes of checkpoint per byte of journal on bulk inserts.
/// The divisor may be moved; the bound stays relative to the newest
/// checkpoint, never a constant: a constant sized for a small board lets a
/// large one's journal outrun its floor, and one sized for a large board
/// checkpoints a small one at every few megabytes.
const CHECKPOINT_BYTES_SHARE: u64 = 4;

/// Returns the byte bound for a checkpoint of `newest_checkpoint_len` bytes.
///
/// The checkpoint is the newest — at open, the start point — and `None`,
/// no checkpoint to size by, is the floor alone:
/// `max(CHECKPOINT_BYTES_FLOOR, C / CHECKPOINT_BYTES_SHARE)`. Non-zero by
/// the floor, which is what the kernel's setter takes.
fn cadence_bytes_for(newest_checkpoint_len: Option<u64>) -> NonZeroU64 {
    let share = newest_checkpoint_len.map_or(0, |c| c / CHECKPOINT_BYTES_SHARE);
    NonZeroU64::new(share.max(CHECKPOINT_BYTES_FLOOR))
        .expect("the byte bound's floor is a non-zero constant")
}

/// The retained checkpoints by default: two.
///
/// It is the default of the start's `retain_checkpoints`
/// ([`StartOptions`]; the binary's `--retain-checkpoints`), the count in
/// force at every start that names none. With two, `BadCheckpoint` recovery
/// can fall back to the older base instead of a full-journal replay from
/// genesis. The other factor of the sidecar's reconstruction ceiling — see
/// [`CHECKPOINT_EVERY_COMMITS`]. The count says how many copies of the world
/// stand; whether the journal below the oldest of them stands too is the
/// start's third setting, the reclamation ([`JournalReclamation`]).
const RETAINED_CHECKPOINTS: NonZeroUsize = NonZeroUsize::new(2).expect("2 is nonzero");

/// The retry memo's capacity, 1024 entries.
///
/// The figure is interim: the daemon's own pin, handed to M10's
/// `OperationSurface::new` at the open as the construction parameter the
/// M10 design makes it (§7's knob "with no implicit default"; the
/// operations design §2.6, op-D5; the configuration register's row "the
/// retry memo's capacity, THE DAEMON's PIN"). Never an operator knob: the
/// memo is a best-effort hint nobody can observe — an evicted key costs one
/// re-execution and nothing says so — so a flag for it would be a setting
/// with no echo and no face. The figure is this crate's one fixed capacity,
/// the same on every board, so the parameter moves no board's behaviour.
const MEMO_CAPACITY: std::num::NonZeroUsize =
    std::num::NonZeroUsize::new(1024).expect("1024 is nonzero");

/// Returns the body cap for a request, by its method and its path.
///
/// The cap is checked on the declared `Content-Length` before a byte is
/// read, so a route that cannot use a large body is never asked to allocate
/// for one: the frame routes, `/op` and `/op-at`, take `MAX_REQUEST_BODY`
/// whatever the method; the blob upload's two body-carrying methods — the
/// creation's `POST` and the resume's `PATCH` — take `MAX_BLOB_BYTES`, a
/// body the daemon's own transport never holds whole (`server/http.rs`, the
/// streaming arm) and a caller over its own transport holds whole if it
/// buffers; every other request, the rest of the blob family's included,
/// takes `MAX_SMALL_BODY`.
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

/// The embedded guest reader (wire v6).
///
/// It is one file, compiled in so the binary is self-contained.
#[cfg(feature = "client")]
const BOARD_HTML: &str = include_str!("../../../clients/board.html");

/// The `Daemon::open` failure: which subsystem refused, not a disposition.
///
/// Four of the five are uniform operator-intervention conditions (report
/// and stop, never retry) and `Engine` is not. A caller that means to retry
/// reads the wrapped error and never this enum alone, which cannot tell a
/// failure a retry clears from one it does not.
#[derive(Debug)]
#[non_exhaustive]
pub enum DaemonError {
    /// The engine could not genesis or recover.
    ///
    /// It carries M2's [`OpenError`](crate::OpenError) verbatim, re-exported
    /// beside [`EngineError`] so the match this doc describes is written
    /// against this crate alone, and it is the one variant here whose
    /// disposition is the wrapped error's rather than this enum's.
    /// `ForeignFormat`, `BadCheckpoint` and `Corruption` are operator
    /// intervention and `InvalidConfig` wants a corrected configuration; `Io`
    /// fuses failures no retry clears with the two M2 documents as clearable
    /// — the journal-path exclusion lock ([`Daemon::open`]'s precondition: a
    /// second live kernel on this data dir) and a recovery truncation the
    /// next open repeats. So `Io` narrows a failure to possibly retryable and
    /// no further, and a caller that retries on it bounds its attempts. Reach
    /// it through this enum's `source`, or by destructuring
    /// `Engine(EngineError::Open(…))`.
    Engine(EngineError),
    /// A change feed file could not be opened, replayed, or extended.
    ///
    /// The file is `commits.log` (the commit-metadata sidecar), one of the
    /// change feed's four derived sidecars or its attest store. A torn tail
    /// is not an error (it truncates); this is the data dir refusing I/O the
    /// kernel just performed.
    Sidecar(std::io::Error),
    /// The blocked-prefix list's start-up supply could not be read as a list.
    ///
    /// The supply ([`AuthOptions::blocked_supply_path`]) could not be read,
    /// is not a list, or is past the byte cap the supply channel applies —
    /// the last two both `InvalidData`; the error names the file and, for
    /// the cap, the number. The list is supplied at every start (AUTH-4.70),
    /// so a daemon that cannot read the one it was handed does not start on
    /// an empty one: that would lapse every standing block in silence. It is
    /// read before the open touches the data directory, so this refusal
    /// leaves the directory as it found it: mend the file, or name the one
    /// the board was started with, and start again.
    BlockedPrefixes(std::io::Error),
    /// The blob store under `blobs/` in the data dir could not be opened.
    ///
    /// Its open tail-checks and compacts its two logs, reconciles its
    /// partials with its records and syncs the directory; this is the data
    /// dir refusing I/O, as [`DaemonError::Sidecar`] is.
    Media(std::io::Error),
    /// The registry's seeding check refused the genesis (REG-1.28 to REG-1.32).
    ///
    /// One of its three arms — disjointness, completeness, the count — fired
    /// over the registry's twelve rows and every other commons row this build
    /// holds, the refusal naming the arm. Run ahead of `Engine::open` on
    /// every open, so a refusal is a genesis that does not complete: nothing
    /// is written and no engine is opened. A build fault, never a data dir's:
    /// the rows and the domain are compiled constants, so the condition is
    /// operator intervention at the build and no retry. The payload is
    /// re-exported as [`SeedingRefusal`](crate::SeedingRefusal), so a caller
    /// names it through this crate alone.
    Registry(skep_registry::SeedingRefusal),
}

impl std::fmt::Display for DaemonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // The kernel's sentence names the two acts in the kernel's words;
            // where the refusal is a damaged journal tail the daemon adds the
            // spelling of its own one-start flag, which the kernel cannot
            // know (`operations.md` §1.1 row 2).
            DaemonError::Engine(e) => {
                write!(f, "{e}")?;
                if damaged_tail_in(e) {
                    f.write_str(
                        "; under skepd the one-start flag is --cut-damaged-tail \
                         (SKEPD_CUT_DAMAGED_TAIL=true), given to one start and never kept in a \
                         unit file",
                    )?;
                }
                Ok(())
            }
            DaemonError::Sidecar(e) => write!(f, "change-feed sidecar: {e}"),
            DaemonError::BlockedPrefixes(e) => write!(f, "blocked-prefix list: {e}"),
            DaemonError::Media(e) => write!(f, "blob store: {e}"),
            DaemonError::Registry(e) => write!(f, "registry seeding: {e}"),
        }
    }
}

/// Returns whether `e` is the kernel's refusal of a damaged journal tail.
///
/// The kernel carries it as `OpenError::Corruption`'s cause, a typed
/// `DamagedTail` reached through the error chain: the engine's open wraps
/// the kernel's refusal, whose `source` is the cause.
fn damaged_tail_in(e: &EngineError) -> bool {
    let mut source: Option<&(dyn std::error::Error + 'static)> = Some(e);
    while let Some(err) = source {
        if err.downcast_ref::<DamagedTail>().is_some() {
            return true;
        }
        source = err.source();
    }
    false
}

/// What the binary's start asked of the open, beyond the two option types.
///
/// They are the operator's words for one start (`operations.md` §3.1):
/// `cut_damaged_tail` is `--cut-damaged-tail` (`SKEPD_CUT_DAMAGED_TAIL`),
/// the acceptance of a damaged journal tail's cut, which the open otherwise
/// refuses — threaded into the kernel's own knob (`Durability::Fsync`'s
/// `cut_damaged_tail`); `create` is `--create`, the word under which the
/// binary begins a board where none stands, which [`Daemon::open`] does
/// unasked for an embedder or a test; and the three checkpoint settings —
/// `checkpoint_every` (`--checkpoint-every`, `SKEPD_CHECKPOINT_EVERY`),
/// `retain_checkpoints` (`--retain-checkpoints`, `SKEPD_RETAIN_CHECKPOINTS`)
/// and `reclaim_journal` (`--reclaim-journal`, `SKEPD_RECLAIM_JOURNAL`) —
/// threaded into the kernel's cadence and its journal's two policies, read
/// once at the open, said there on one line and persisted nowhere: a start
/// that names none runs at the defaults, so a board run under `never` and
/// restarted without the word reclaims at its next landing. Built from its
/// defaults and set: `#[non_exhaustive]`, so a knob added here arrives at
/// its default, which [`StartOptions::default`] is the one home of.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StartOptions {
    /// Accept the cut of a damaged journal tail at this open.
    ///
    /// The kernel keeps every byte of the tail beside the journal first and
    /// hands out no position it claimed; the open says the cut as a
    /// failure, naming the kept files. A clean tail under it is cut as every
    /// open cuts a crash's, and the open says the flag was not needed.
    pub cut_damaged_tail: bool,
    /// Whether the start was told to begin a board where none stands.
    ///
    /// The open begins one either way where none stands (`Recovery::began`);
    /// this decides the line said of it — the expected landing under the
    /// word, the tell of a wrong directory without it.
    pub create: bool,
    /// The checkpoint cadence's commit count: a checkpoint every this many.
    ///
    /// The commit half of the kernel's cadence (`CheckpointPolicy::EveryN`),
    /// beside the byte bound no setting moves; `CHECKPOINT_EVERY_COMMITS`,
    /// 1,024, by default. With `retain_checkpoints` it bounds how far behind
    /// the head the oldest retained base stands, and so the walk behind the
    /// listener on a data dir whose commit metadata is missing.
    pub checkpoint_every: NonZeroU64,
    /// How many checkpoints a landing keeps: the newest this many.
    ///
    /// The kernel's `retain_checkpoints`; `RETAINED_CHECKPOINTS`, two, by
    /// default. Each is a whole copy of the world on the volume, and the
    /// oldest is where `BadCheckpoint` recovery falls back to; whether the
    /// journal below it stands is `reclaim_journal`'s.
    pub retain_checkpoints: NonZeroUsize,
    /// Whether a landing reclaims the journal below the oldest kept base.
    ///
    /// The kernel's reclamation policy ([`JournalReclamation`]): below the
    /// oldest checkpoint kept by default, or never, which keeps every segment
    /// since genesis while the usual bases stand, so a history read below
    /// the oldest base is served from the kept journal.
    pub reclaim_journal: JournalReclamation,
}

impl Default for StartOptions {
    /// Returns the start every door but the binary's opens under.
    ///
    /// No cut accepted, no board asked for, and the three checkpoint
    /// settings at their defaults — the two constants and the reclaiming
    /// arm — the one home of those defaults, which the binary's help renders
    /// from here.
    fn default() -> StartOptions {
        StartOptions {
            cut_damaged_tail: false,
            create: false,
            checkpoint_every: CHECKPOINT_EVERY_COMMITS,
            retain_checkpoints: RETAINED_CHECKPOINTS,
            reclaim_journal: JournalReclamation::BelowOldestCheckpoint,
        }
    }
}

/// The journal's reclamation, as the start's `--reclaim-journal` names it.
///
/// The operator's two words for the kernel's two arms (`Reclaim`): the
/// start carries the word, the open hands the kernel the arm. Parsed from
/// and rendered as the word the flag and its variable take, so one spelling
/// serves the parse, the help and the open's line.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum JournalReclamation {
    /// `below-oldest-checkpoint`: reclaim below the oldest kept base.
    ///
    /// The default: at every landing the closed journal segments wholly
    /// below the oldest retained checkpoint are removed, so the journal
    /// holds the retained window and no more, and a history read below it
    /// answers `history_reclaimed`.
    #[default]
    BelowOldestCheckpoint,
    /// `never`: reclaim nothing, every segment since genesis kept.
    ///
    /// The checkpoints are kept as under the other word; the journal below
    /// the oldest of them stands too, so a history read there folds from
    /// genesis through it and every landing's line reads `nothing
    /// reclaimed`. One start's word: a restart without it reclaims at its
    /// next landing what this start kept.
    Never,
}

impl JournalReclamation {
    /// The word for the arm that reclaims below the oldest kept base.
    pub const BELOW_OLDEST_CHECKPOINT: &'static str = "below-oldest-checkpoint";
    /// The word for the arm that reclaims nothing.
    pub const NEVER: &'static str = "never";
    /// What the flag and its variable admit, as a refusal names them.
    pub const ADMITTED: &'static str = "below-oldest-checkpoint or never";

    /// Returns the kernel's arm for this word.
    fn kernel(self) -> Reclaim {
        match self {
            JournalReclamation::BelowOldestCheckpoint => Reclaim::BelowOldestRetained,
            JournalReclamation::Never => Reclaim::Never,
        }
    }
}

impl FromStr for JournalReclamation {
    type Err = ();

    /// Reads the word, exactly as the flag and its variable take it.
    ///
    /// # Errors
    ///
    /// Any other spelling: the caller names the setting and
    /// [`JournalReclamation::ADMITTED`].
    fn from_str(word: &str) -> Result<JournalReclamation, ()> {
        match word {
            JournalReclamation::BELOW_OLDEST_CHECKPOINT => {
                Ok(JournalReclamation::BelowOldestCheckpoint)
            }
            JournalReclamation::NEVER => Ok(JournalReclamation::Never),
            _ => Err(()),
        }
    }
}

impl fmt::Display for JournalReclamation {
    /// Writes the word the flag takes.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            JournalReclamation::BelowOldestCheckpoint => JournalReclamation::BELOW_OLDEST_CHECKPOINT,
            JournalReclamation::Never => JournalReclamation::NEVER,
        })
    }
}

/// The open's line for the three checkpoint settings in force.
///
/// It is said once per open, after the directory's line and the two
/// refusals that touch nothing under the directory — the blocked-prefix
/// list's and the blob store's — and before the engine opens under them
/// (`operations.md` §3.1 step 3), so a start the engine refuses shows the
/// settings it was refused under and a start the list refuses says the
/// version, the directory and the refusal alone. It renders
/// `checkpoint settings: a checkpoint every {n} commits (--checkpoint-every),
/// {k} retained (--retain-checkpoints), the journal reclaimed below the
/// oldest retained checkpoint (--reclaim-journal below-oldest-checkpoint);
/// read at this start alone, each the default where neither its flag nor
/// its variable was given`, the reclamation clause `the journal kept whole,
/// never reclaimed (--reclaim-journal never)` under the other word. A pure
/// value the unit suite pins by `to_string()`; emitted under `Class::Open`
/// through [`say_open_line`].
struct CheckpointSettingsLine<'a> {
    start: &'a StartOptions,
}

impl fmt::Display for CheckpointSettingsLine<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "checkpoint settings: a checkpoint every {} commits (--checkpoint-every), {} retained \
             (--retain-checkpoints), ",
            self.start.checkpoint_every, self.start.retain_checkpoints
        )?;
        match self.start.reclaim_journal {
            JournalReclamation::BelowOldestCheckpoint => {
                f.write_str("the journal reclaimed below the oldest retained checkpoint")?
            }
            JournalReclamation::Never => f.write_str("the journal kept whole, never reclaimed")?,
        }
        write!(
            f,
            " (--reclaim-journal {}); read at this start alone, each the default where neither \
             its flag nor its variable was given",
            self.start.reclaim_journal
        )
    }
}

/// The error's chain: `source` exposes the cause as a link.
///
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

/// Returns whether `path` is one of the paths this daemon serves.
///
/// This is the one place the route set is stated, so preflight, method
/// refusal and dispatch cannot disagree about what exists. A known path
/// answers `OPTIONS` with a preflight and a wrong method with `405`;
/// everything else is the ordinary `404`. The blob upload's path family is
/// known as a family: `/blob/upload` and `/blob/upload/<id>`, the latter
/// known for any `<id>` and refused by name where it is no identifier; the
/// blob fetch's path `/blob` is known beside it.
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
// live in `skep_core::auth` (the AUTH session layer). The glue on this side is
// `actor.rs`.

/// The write permit pool's width, W = 4.
///
/// It is the most write requests admitted onto the write path at once
/// (`operations.md` §4 rows 25, 27; the spike S25's measurement), every
/// other refused `503 write_busy` at once, retry-class — a pool and never a
/// queue (P29), as the five other pools are, the per-document pool's bounded
/// wait of two milliseconds before its refusal included.
///
/// **Why a pool on writes at all.** The write path serializes writes under
/// one guard, and the kernel's backstop runs a checkpoint inline on the
/// committing thread when the cadence crosses twice before the checkpoint
/// thread has serviced the first — seconds at ten million positions.
/// Without a pool, every write that arrives during such a run holds a
/// worker blocked on the guard, so [`DEFAULT_WORKERS`] writers at once
/// leave no worker for `/health`, `/session` or any read for the run's
/// length: the board down, not slow. With the pool, writes hold at most W
/// workers through a run — the trigger and W − 1 parked behind it — and the
/// rest are told so at once.
///
/// **Why four.** The upload pool's figure, measured (S25 §5.4): at a shared
/// venue it refuses almost nothing outside a backstop (≈ 0.3% at fifty
/// writes a second) and parks three writers through one, each answered
/// inside a client's ten-second patience on a quiet machine; and it keeps
/// the default's "two free" with every pool saturated —
/// [`DEFAULT_WORKERS`] 24 less the twenty-two pooled slots, the six pools'
/// permits and the per-document pool's two waiting slots. A width of one
/// refuses every overlapping write, backstop or none; two moves the same
/// pins for less.
///
/// It is crate-internal — `pub` in a private module the crate root does not
/// re-export — and [`MIN_WORKERS`] is derived from the six pools' counts and
/// the per-document pool's waiting slots by path, as this crate's own and
/// `skep-media`'s are named there, so the minimum moves with this figure and
/// no reader does the sum. The daemon's own pool, held on [`Daemon`] beside
/// the five.
pub const MAX_CONCURRENT_WRITES: usize = 4;

/// The daemon's state.
///
/// It is the assembled engine, M10's front door, the codec, and the token →
/// session binding. Socket-free — [`Daemon::route`] is the entire HTTP
/// surface as a request→reply function over this state, with no socket in
/// its signature. Not a pure one: see [`Daemon::route`].
pub struct Daemon {
    /// The data directory, as the open was handed it.
    ///
    /// The standing line lists the kept files beside the journal and the
    /// logs from it at each tick (`tools::kept_files`).
    data_dir: PathBuf,
    engine: Engine,
    /// M10's front door: the operation surface every frame executes against.
    ///
    /// `op` throughout this crate names an operation or its kind (`Op`,
    /// `OpKind`, `op_name`, the wire's own `"op"` field), so the boundary
    /// takes the boundary's name.
    febe: OperationSurface<World>,
    codec: JsonCodec,
    /// The AUTH session layer.
    ///
    /// It holds the config, the challenge and session stores, the credential
    /// write lock, the credential memo and the blocked-prefix list's supply.
    auth: AuthState,
    /// The write path.
    ///
    /// It is the serialization point, the commit-metadata sidecar behind
    /// `GET /changes` and `head_time` (wire v6), the commit stream behind
    /// `GET /events` (wire v4), and the published head writer behind them.
    /// One field because the four are one ordering — commit, record,
    /// announce, then the head writer's turn — that no handler may take
    /// apart.
    commits: Commits,
    /// The history surface behind `/op-at`, `/dump?at` and `/chain?at`.
    ///
    /// It holds its own reconstruction budget: a guest may ask any of them
    /// and replay is per-call uncached, so without that budget any local
    /// caller could pin every worker on reconstruction.
    history: History,
    /// The class-scan bound behind `/op`'s link reads.
    ///
    /// It holds its own shape test, its class pool and its per-document
    /// pool under a ceiling (wire v7.9; PUB-8.36; the home-index record's
    /// D3) — two further instances of [`skep_util::permits`]'s mechanism,
    /// and so disjoint from the reconstruction pool `history` holds. Lives
    /// in the serving path and nowhere lower (doctrine D9: the meter is an
    /// attribute of a gate, never of the substrate): M8 and M7 are asked or
    /// not asked, and never told.
    scans: ClassScans,
    /// The daemon's media resource.
    ///
    /// It is the blob store under `blobs/` in the data dir — the files, the
    /// partials, the upload records and the lease log — the limits in force,
    /// the hold a stream has on its upload, the cell index (entered by the
    /// write path at every commit that mints a cell, rebuilt at open on a
    /// thread where the OS gives one) and the binding the write door asks.
    /// The PUT's routes reach it as `op.rs` reaches the write path; the door
    /// reads it under the plain sequence's locks; the pruner's pass reads it
    /// under the credential lock's write arm. It commits nothing to the
    /// journal and takes no `Serial`.
    media: MediaGate,
    /// The pruner beside it (`skep-media`'s `pruner.rs`).
    ///
    /// It is the pass the cadence and the test seam run over `media`, handed
    /// the credential lock's write arm one file at a time
    /// (`Daemon::prune_pass`), and, under the test seam, the pass's own hold
    /// and count.
    pruner: Pruner,
    /// The fetch pool behind `GET /blob?i=`.
    ///
    /// It is the third instance of [`skep_util::permits`]'s mechanism
    /// (wire.md §Media, the fetch; M-I5 (f)), disjoint from the
    /// reconstruction and class-scan pools by the borrow: an admitted fetch
    /// holds its whole file from the check to the last byte written, so the
    /// pool is the route's memory bound, and its count is the third term of
    /// [`MIN_WORKERS`]. In the serving path like the scan pool (D9): the
    /// serve is asked or refused, never told.
    fetches: FetchPool,
    /// The upload pool behind the PUT's two body-carrying methods.
    ///
    /// They are the creation and the resume of `/blob/upload` (wire.md
    /// §Media, the permit; M-I5 (f)). It is the fourth instance of
    /// [`skep_util::permits`]'s mechanism and the fetch pool's twin,
    /// disjoint from the three others by the borrow: an admitted creation or
    /// resume holds its worker from the permit to its finish, so the pool is
    /// the family's bound on worker occupancy, and its count is the fourth
    /// term of [`MIN_WORKERS`]. In the serving path like the fetch pool
    /// (D9): the family is asked or refused, never told.
    uploads: UploadPool,
    /// The write permit pool (`operations.md` §4 rows 25, 27).
    ///
    /// It is an instance of [`skep_util::permits`]'s mechanism, of width
    /// [`MAX_CONCURRENT_WRITES`], disjoint from the five others by the
    /// borrow. Every write request on `/op` that reaches a lock — the plain,
    /// the credential and the registry sequence alike — takes one permit
    /// before the credential lock and the serialization guard (`op.rs`): the
    /// plain sequence's first act, the other two's after their pre-lock
    /// refusals. It holds the permit in the sequence's frame through
    /// `commit_under`'s return, so a writer parked on the guard behind an
    /// inline backstop holds its permit the whole wait and the pool bounds
    /// the workers writes can occupy; a write that finds none is refused
    /// `503 write_busy` before any lock. The head writer's own commits take
    /// none — they run in the turn of the write that triggers them, under
    /// its permit, or at the open before anything is served. Its count is
    /// the fifth term of [`MIN_WORKERS`]. In the serving path like the four
    /// (D9): the write path is asked or not asked, never told.
    write_permits: Permits,
    /// The write pool's edge pair (`operations.md` §1.1 m12; §4 row 27).
    ///
    /// It is the tracker the pool's one door (`op.rs`'s
    /// `Daemon::take_write_permit`) tells of every refusal and every permit
    /// taken, whose edges that door says at once through [`Daemon::say`] —
    /// `the write pool is saturated` at the first refusal of an episode,
    /// `the write pool has room again after {n} refusals` at the first permit
    /// taken a hold-down past its last — once per episode and nothing per
    /// request; the pool's twin of the tracker each of the other pools
    /// holds for itself, the class-scan bound's two pools sharing one.
    write_edge: EdgeTracker,
    /// The checkpoint thread's memory between its wakes ([`CheckpointMemory`]).
    ///
    /// It is the inline count as the thread last said it and the position
    /// that count is counted from, and the newest checkpoint as it last
    /// looked. Held here because the thread is `listen.rs`'s and the test
    /// seam runs its arms on a caller's thread.
    checkpointer: CheckpointMemory,
    /// The daemon's high-water of its own resident set ([`ResidentHighWater`]).
    ///
    /// The checkpoint thread reads it at every landing, a landed failure's
    /// included, and at every backstop wake; the pruner's thread at every
    /// pass that lands. Each line that carries the figure carries that
    /// reading beside the largest of the uptime's readings.
    resident: ResidentHighWater,
    /// The liveness flags of the daemon's two loop threads.
    ///
    /// Each ([`ThreadLiveness`]) is set by its loop's catch as the thread
    /// ends on a caught panic, the pruner's read by the standing line.
    threads: ThreadLiveness,
    /// The aside fault's once-flag (`operations.md` §1.1 row 37).
    ///
    /// It holds whether row 37's line has been said for the unlink fault
    /// that stands — set at [`Daemon::retire_asides`] where the store's
    /// deferred unlink answers an error, the line naming the aside at the
    /// queue's head and the act that clears it; cleared, with the clearing
    /// line, at the next call that answers `Ok` — the queue drained by that
    /// call, or found empty because the pruner's pass swept the aside first
    /// — and clear at every open, the store's queue being empty there. The
    /// pruner's pass clears nothing here: the flag reads the deferred
    /// unlink's own answer and nothing else. Set, read and cleared at one
    /// site, under no lock: the atomic is what makes the field `Sync`.
    aside_fault_said: AtomicBool,
    /// Where a history read first met the journal's damage (RUNBOOK §2).
    ///
    /// It is set once, by the first refusal of this uptime that is the
    /// journal's damage ([`crate::history::Unavailable::journal_damage`]),
    /// where [`Daemon::refuse_history`] says [`HistoryDamageLine`]: the site
    /// [`JournalDamageSite`] renders, the position or the file that line's
    /// account names. The standing line reads it, and re-says the damage at
    /// every tick by that site, so the two lines join. Never cleared while the
    /// daemon runs: the line's act — a copy, the inventory over it, a restore
    /// — is finished by a restart, whose open reads the journal whole.
    history_damage: OnceLock<String>,
    /// The dirty-crash harness's one seam into the claim's step.
    ///
    /// It is armed through `Daemon::hold_between_the_claim_and_its_head`:
    /// armed, the claim-flip tail announces the crash window and parks
    /// there, both locks held, for the harness to SIGKILL. `false` is its
    /// state on every run the harness does not arm, and a build without the
    /// `test-hooks` feature has no such field — compiled under that feature,
    /// not `cfg(test)` alone, because the harness is an integration test of
    /// this crate's library, outside its `cfg(test)`.
    #[cfg(any(test, feature = "test-hooks"))]
    hold_between_claim_and_head: AtomicBool,
    /// The three panic seams the thread-death claims arm ([`ThreadFaults`]).
    ///
    /// **Test seam.** They are the checkpoint thread's, the pruner's and the
    /// deferred unlink's, each fired once at its site and disarmed as it
    /// fires. `false` is each one's state until a suite arms it, and a build
    /// without the `test-hooks` feature has no such field.
    #[cfg(any(test, feature = "test-hooks"))]
    faults: ThreadFaults,
    /// The live streams' thread seam ([`hooks::ThreadRefusals`]).
    ///
    /// **Test seam.** The next streams a suite armed are refused their
    /// thread with the seam's error in place of the OS's spawn. Unarmed until
    /// a suite arms it, and a build without the `test-hooks` feature has no
    /// such field.
    #[cfg(any(test, feature = "test-hooks"))]
    stream_thread_faults: Mutex<hooks::ThreadRefusals>,
    /// The workers' thread seam ([`hooks::ThreadRefusals`]).
    ///
    /// **Test seam.** The next workers `serve_bound` spawns that a suite
    /// armed are refused their thread with the seam's error in place of the
    /// OS's spawn, the start retired as at a refused worker. Unarmed until a
    /// suite arms it, and a build without the `test-hooks` feature has no
    /// such field.
    #[cfg(any(test, feature = "test-hooks"))]
    worker_thread_faults: Mutex<hooks::ThreadRefusals>,
    /// Every line said through this daemon's own classed door this uptime.
    ///
    /// **Test seam.** The door is [`Daemon::say`] and [`Daemon::say_lines`],
    /// each line kept as `{class}: {text}` — the configuration lines after
    /// the bind, the warnings at both their moments, the blocked list, the
    /// flip's landing line, the reissue's refusal, the standing line, the
    /// kernel's halt line and the two thread catches' lines among them —
    /// for `Daemon::lines_said`, since no suite captures stderr in-process.
    /// The record is the write path's ([`LinesSaid`]), shared: the kernel's
    /// halt line has a site below the daemon. The open's own lines are said
    /// before this value exists and the checkpoint thread's keep their own
    /// record; neither is here.
    #[cfg(any(test, feature = "test-hooks"))]
    said: LinesSaid,
}

/// The liveness flags (`operations.md` §1.1 row 41; §4 rows 24 and 25).
///
/// There is one per daemon-owned loop thread, set by the thread's own catch
/// as it ends on a caught panic — never cleared, since nothing re-spawns a
/// thread but a restart. The pruner's is a read of the standing line (`the
/// pruner's thread is gone`); the checkpoint thread's is the standing
/// line's own carrier, so no clause reads it — the hook reads both.
struct ThreadLiveness {
    /// The pruner's thread ended on a caught panic.
    ///
    /// No pass runs until a restart.
    pruner_ended: AtomicBool,
    /// The checkpoint thread ended on a caught panic.
    ///
    /// Every checkpoint from here is the backstop's, and no standing line
    /// comes.
    checkpointer_ended: AtomicBool,
}

/// The three panic seams, each an arm fired once at its site.
///
/// **Test seam.** The checkpoint thread's fires at the top of its next loop
/// turn, the pruner's at the top of its next, the deferred unlink's inside
/// `Daemon::retire_asides` — and each is disarmed as it fires. Per daemon,
/// as the checkpoint hold is, since each site is a method or a loop of one
/// daemon's.
#[cfg(any(test, feature = "test-hooks"))]
struct ThreadFaults {
    checkpointer: AtomicBool,
    pruner: AtomicBool,
    unlink: AtomicBool,
}

/// The daemon's `Debug`, deliberately opaque.
///
/// A `Debug` that can block is one that turns `dbg!` into a hazard, and
/// [`Daemon::log_position`] — a lock-free read of the kernel's root — is
/// how you ask for the position.
impl std::fmt::Debug for Daemon {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Daemon").finish_non_exhaustive()
    }
}

impl Daemon {
    /// Opens the one world at `data_dir`, by genesis or recovery.
    ///
    /// It replays the commit-metadata sidecar and assembles the operation
    /// surface. Two commands on the journal beyond genesis and recovery, both
    /// the daemon's own as the system account's principal. On every board,
    /// the link-type registry's seed (`skep-core`'s `commits/registry.rs`):
    /// what the registry document `1.1.0.1.0.1` lacks of the vocabulary is
    /// written before this returns — every type on a fresh board (the staging
    /// draft's mint, one insert of every section, one publish, one `defines`
    /// link per type), the types a later build added on a board that stands,
    /// nothing on a board that holds them all — so a fresh board's
    /// [`Daemon::log_position`] stands past genesis at its first open. And on
    /// one kind of board: a claimed board whose head writer resumes no head
    /// from `H` — the crash window between the claim and its head, a claim
    /// whose `H.1` the head writer's driver refused while serving, or a board
    /// claimed under a build that wrote no head at the claim — has `H.1`
    /// written before this returns (`Daemon::write_the_claims_head_if_owed`;
    /// signed ops): up to three commits (the staging draft's mint where the
    /// seed has not made it, the record's insert, the publish into `H`). A
    /// refusal of either fails nothing: it is surfaced on the operator
    /// stream, the open returns `Ok`, the seed's rest waits for the next open
    /// and the board answers attested writes
    /// `attestation_invalid:board_unavailable` until a head lands.
    ///
    /// Two steps here cost more than O(1) in the data dir beyond the
    /// engine's own recovery: the blob store's open, which tail-checks and
    /// compacts its two logs and reconciles its partials with its records,
    /// and the feed's. Where commit metadata is missing, the feed's open
    /// leaves the uncovered positions pending for a walk behind the
    /// listener, which reconstructs them from the journal while the board
    /// serves — one whole-world replay (plus one world diff, for the
    /// position's class) each, up to the retained window — the start's
    /// cadence × its retained count ([`StartOptions`]), 1,024 × 2 by
    /// default (`CHECKPOINT_EVERY_COMMITS` × `RETAINED_CHECKPOINTS`), and
    /// the whole journal where the start keeps it whole.
    /// `CommitsLog::open` states that bound; `Feed::open` the derived
    /// sidecars' own, O(their files) plus O(any missing tail); and the
    /// attest store's open inside it (`skep-core`'s `commits/feed/attest.rs`'s
    /// `AttestStore::open`) is O(its file) — a line for every attested
    /// commit the board has ever made, never compacted, as none of the
    /// feed's six files is — plus, after a loss alone, one base loaded and one
    /// journal scan for its whole uncovered tail, a reopen after unattested
    /// commits asking the journal nothing. The identity table costs nothing
    /// here: it rides in the World the engine recovered, checkpointed with it
    /// and stepped by the replay (AUTH-2.79, AUTH-2.80). What the engine's
    /// recovery can cost over it is a base written without the slice over
    /// credential deposits — not a start point, so the open steps back to an
    /// older one or to genesis and replays, slower, once — and that is said on
    /// the operator stream (AUTH-2.86; [`Engine::recovery`]). A board with no
    /// start point left refuses to open (AUTH-2.88): `Engine` carries
    /// `BadCheckpoint` with the slice's own remedy, and nothing is invented.
    ///
    /// # Errors
    ///
    /// In the order the open meets them: [`DaemonError::Registry`] where the
    /// seeding check refuses the genesis, [`DaemonError::Engine`] where the
    /// engine cannot genesis or recover, [`DaemonError::Media`] where the
    /// blob store cannot be opened, and [`DaemonError::Sidecar`] where the
    /// change feed cannot be.
    ///
    /// **Precondition.** No other live kernel holds `data_dir`. M2 takes an
    /// exclusive lock on the journal directory, and a second open fails on
    /// it — a condition a retry can clear, as a recovery truncation the next
    /// open repeats is ([`DaemonError::Engine`] names both), and so an
    /// exception to the disposition below. It is not a variant of
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
    pub fn open(data_dir: impl AsRef<Path>) -> Result<Daemon, DaemonError> {
        Daemon::open_with(data_dir, AuthOptions::default())
    }

    /// Opens as [`Daemon::open`] does, with the session layer's configuration.
    ///
    /// The configuration `opts` names the local-trust flag, the configured
    /// origins, the node prefix, the blocked-prefix list's supply and the
    /// preview-keys allowance. [`Daemon::open`]'s precondition, its account
    /// of which failures a retry can clear, and the commits it makes on a
    /// claimed board whose journal holds no head are this one's too — that
    /// method delegates here, so both doors carry one contract. The identity
    /// table is the recovered World's own slice (AUTH-2.86: the daemon serves
    /// from the resolved World): nothing is rebuilt here, and what the
    /// engine's open skipped or resolved on the way to that World is logged
    /// here as the two warnings that rule names.
    ///
    /// A supply file the options name is read here, at every start — first,
    /// before anything under the data directory is touched — and the list
    /// installed from it, against the recovered world's claimant, before
    /// anything is served.
    ///
    /// # Errors
    ///
    /// [`DaemonError::Registry`] where the seeding check refuses the genesis,
    /// then [`DaemonError::BlockedPrefixes`] where the supply file `opts`
    /// names cannot be read, is not a list, or is past the channel's byte
    /// cap — both before anything under `data_dir` is touched — then the rest
    /// of [`Daemon::open`]'s, in its order.
    pub fn open_with(data_dir: impl AsRef<Path>, opts: AuthOptions) -> Result<Daemon, DaemonError> {
        Self::open_configured(data_dir, opts, MediaOptions::default())
    }

    /// Opens as [`Daemon::open_with`] does, with the media configuration too.
    ///
    /// The media resource's configuration is named beside the session
    /// layer's: the upload setting (`--no-uploads`, wire.md §Media), echoed
    /// on `/health` as the `media` object. The two doors above delegate
    /// here, so all three carry one contract.
    ///
    /// # Errors
    ///
    /// [`Daemon::open_with`]'s: the [`DaemonError`] naming the subsystem
    /// that refused.
    pub fn open_configured(
        data_dir: impl AsRef<Path>,
        opts: AuthOptions,
        media: MediaOptions,
    ) -> Result<Daemon, DaemonError> {
        Self::open_started(data_dir, opts, media, StartOptions::default())
    }

    /// Opens as [`Daemon::open_configured`] does, with the start's own words.
    ///
    /// The start's options ([`StartOptions`]) are the binary's: the
    /// acceptance of a damaged journal tail's cut, and whether the start was
    /// told to begin a board. The three doors above delegate here under the
    /// defaults — no cut accepted, no board asked for — so all four carry
    /// one contract, and an embedder's open begins a board where none stands
    /// as it always has.
    ///
    /// # Errors
    ///
    /// [`Daemon::open_with`]'s: the [`DaemonError`] naming the subsystem
    /// that refused — [`DaemonError::Engine`] carrying the kernel's refusal
    /// of a damaged tail where the cut was not accepted, and
    /// [`DaemonError::Media`] where `blobs/` holds a link or a special file,
    /// refused ahead of the engine's open.
    pub fn open_started(
        data_dir: impl AsRef<Path>,
        opts: AuthOptions,
        media: MediaOptions,
        start: StartOptions,
    ) -> Result<Daemon, DaemonError> {
        // The production salt (`SKJ4`): OS entropy per transaction, the one
        // source a daemon opens under — a seeded stream is a pure function
        // of the seed and the position, which is exactly the predictability
        // the salt exists to deny a reader of `/chain?at=N`. The seeded
        // source reaches a daemon through the test seam alone
        // (`Daemon::open_seeded`, compiled only under `test-hooks` or in this
        // crate's own unit tests).
        Self::open_under_started(data_dir.as_ref(), opts, media, SaltSource::Os, start)
    }

    /// Opens under a named salt source, the start's options at their defaults.
    ///
    /// It is the test seam's door (`Daemon::open_seeded`), a shim over
    /// [`Daemon::open_under_started`], compiled where that door is.
    ///
    /// # Errors
    ///
    /// [`Daemon::open_under_started`]'s.
    #[cfg(any(test, feature = "test-hooks"))]
    fn open_under(
        data_dir: &Path,
        opts: AuthOptions,
        media_opts: MediaOptions,
        salt: SaltSource,
    ) -> Result<Daemon, DaemonError> {
        Self::open_under_started(data_dir, opts, media_opts, salt, StartOptions::default())
    }

    /// Opens under a named salt source: [`Daemon::open_started`]'s body.
    ///
    /// That door reaches it with [`SaltSource::Os`] and the test seam
    /// `Daemon::open_seeded` with a seeded stream. Private, so no caller
    /// outside this module and its children can name a source; and over
    /// `&Path`, so the public doors are the generic shims and this body is
    /// compiled once whatever path type a caller holds — the split std
    /// keeps, `File::open` over its inner `&Path`.
    ///
    /// # Errors
    ///
    /// In the order this body meets them: [`DaemonError::Registry`] where
    /// the seeding check refuses the genesis and
    /// [`DaemonError::BlockedPrefixes`] where the supply file `opts` names
    /// cannot be read as a list, both before anything under `data_dir` is
    /// touched; then [`DaemonError::Media`] where `blobs/` holds a link or a
    /// special file, decided by reading alone and so ahead of the engine's
    /// open (`operations.md` §3.1 step 3); then [`DaemonError::Engine`]
    /// where the engine cannot genesis or recover — a damaged journal tail
    /// among its refusals, unless `start` accepts the cut —
    /// [`DaemonError::Media`] where the blob store cannot be opened, and
    /// [`DaemonError::Sidecar`] where the change feed cannot be.
    fn open_under_started(
        data_dir: &Path,
        opts: AuthOptions,
        media_opts: MediaOptions,
        salt: SaltSource,
        start: StartOptions,
    ) -> Result<Daemon, DaemonError> {
        // The version line, the open's first (§3.4 step 6's gap): the
        // build's version and the three format stamps it reads, before the
        // directory's line and so before anything is read from the
        // directory — a refusal that names the stamp it found has, above
        // it, the line that says which stamps this build reads.
        say_open_line(VersionLine);
        // The first of the open's two m7 lines (§3.1 step 3): the directory,
        // before the seeding check and the engine's open — the one line on
        // the operator stream that names the directory, which a collector
        // keys on, and the tell that an open has begun where it is long.
        say_open_line(DataDirLine(data_dir));
        // The cadence: every `checkpoint_every` commits (the start's;
        // `CHECKPOINT_EVERY_COMMITS` by default) or the byte bound,
        // whichever first, deferred — a crossing sets the kernel's due flag
        // and the checkpoint thread runs it off the write path's guard; a
        // second crossing before the thread has serviced the first runs
        // inline as the kernel's backstop. The byte bound opens at its floor
        // and is re-read off the start point's checkpoint below, once the
        // engine has opened, and by the thread as each one lands.
        let cfg = KernelConfig {
            durability: Durability::Fsync {
                journal_path: data_dir.to_path_buf(),
                // The start's two journal policies: how many bases stand
                // (`RETAINED_CHECKPOINTS` by default), and whether the
                // journal below the oldest of them is reclaimed at a
                // landing or kept whole — each the kernel's knob, read once
                // at the open.
                retain_checkpoints: start.retain_checkpoints.get(),
                reclaim: start.reclaim_journal.kernel(),
                burned_seq: BurnedSeqPolicy::Rollback,
                // The operator's word for this one start, where it was
                // given: the kernel's knob, read once at the open.
                cut_damaged_tail: start.cut_damaged_tail,
            },
            checkpoint: CheckpointPolicy::Deferred(Box::new(CheckpointPolicy::EitherOf(
                Box::new(CheckpointPolicy::EveryN(start.checkpoint_every.get())),
                Box::new(CheckpointPolicy::JournalBytes(CHECKPOINT_BYTES_FLOOR)),
            ))),
            salt,
        };
        // The seeding check, this daemon its hand (REG-1.28, REG-1.32): the
        // registry's three arms over its twelve rows and every other commons
        // row this build holds, ahead of the engine on every open — a fresh
        // data dir's genesis and a reopen's re-genesis alike — so a refusal
        // is a genesis that does not complete: no claim, no session and no
        // board record, nothing written, no engine opened.
        skep_core::auth::policy::genesis_seeding_check().map_err(DaemonError::Registry)?;
        // The blocked-prefix list, read before the directory is touched
        // (PATTERNS P13; AUTH-4.70): the open's one refusal that is the
        // operator's configuration and not the directory's state, decidable
        // from the file alone — so it is answered here, before the engine's
        // open creates the directory, takes `kernel.lock`, removes a stray
        // `checkpoint.tmp`, cuts the journal's tail or begins a board, and
        // before the blob store and the change feed repair their files. Each
        // of those is said once, by the open that makes it, so a start
        // refused after them would spend those lines on a start that serves
        // nothing, and the start that serves once the list is mended would
        // have none left to say. The install waits for the recovered world
        // below, whose claimant the list is compared against (AUTH-4.36
        // step 4b).
        let auth_start = AuthStart::read(opts).map_err(DaemonError::BlockedPrefixes)?;
        // The blob store's read-only refusal, ahead of the engine's open
        // (`operations.md` §3.1 step 3, PATTERNS P13: the refusal at the
        // earliest act the fault is decidable from): a link or a special
        // file under `blobs/` is decided by reading alone, so it is refused
        // here, before the kernel's lock is taken, a stray `checkpoint.tmp`
        // removed or the journal's tail cut — a start refused for it leaves
        // the directory as it found it. The store's own open makes the check
        // again as its precondition; a `blobs/` that does not stand holds
        // nothing to refuse.
        Store::refuse_links_and_special_files(data_dir.join(STORE_DIR))
            .map_err(DaemonError::Media)?;
        // Whether a store stood under the directory before this open makes
        // anything there — its designation directory, the first thing a
        // deposit makes, or either log (`BlobLogLines`): a log absent beside
        // one is a loss the open says; beside a root that held no deposit
        // and no log, a first start's. Read here, ahead of the open that
        // begins the absent logs.
        let store_stood = {
            let root = data_dir.join(STORE_DIR);
            [DESIGNATION, "uploads.log", "leases.log"]
                .iter()
                .any(|name| std::fs::symlink_metadata(root.join(name)).is_ok())
        };
        // The three checkpoint settings in force, said before the engine
        // opens under them and after the two refusals that touch nothing
        // under the directory (the list's, the store's), so a start those
        // refuse says the version, the directory and the refusal alone:
        // the cadence's count, the retained count and the journal's
        // reclamation — the start's, each the default where the start named
        // none — so a start the engine refuses shows what it was refused
        // under, and a board run a month under `never` and restarted
        // without the word reads here that it reclaims again.
        say_open_line(CheckpointSettingsLine { start: &start });
        // The engine's open, timed: the daemon's own `Instant` around the
        // call, the figure the recovery's landing carries.
        let began = Instant::now();
        let engine = Engine::open(cfg).map_err(DaemonError::Engine)?;
        let open_ms = began.elapsed().as_millis();
        // The start point's account (AUTH-2.86): every retained checkpoint
        // the engine's open passed over, with the start point it resolved
        // from, a slice-less start point that resolved to the empty table,
        // and the corrupt runs below the start point the open's scan read
        // and passed over — said before anything is served, and only where
        // there is something to say.
        for warning in recovery_warnings(engine.recovery()) {
            notice::emit(Class::Warning(Moment::AtOpen), warning);
        }
        // The recovery's landing (m7): the base the open loaded, the
        // committed head it came back at, the commits it replayed above that
        // base and how long the engine's open took — said on every open, not
        // on a skip alone, after the account above of what was passed over on
        // the way to that base.
        say_open_line(RecoveredLine::of(engine.recovery(), engine.kernel().current_seq(), open_ms));
        // The beginning (AUTH-2.86's family of startup reports): where no
        // journal stood in the directory the landing above reads `recovered
        // from genesis` all the same, so the open says it began a board —
        // under `--create`, the expected landing of a first start; without
        // the word, an embedder's or a test's open, which begins one unasked,
        // and on a board that had a journal the one tell that the directory
        // opened is not where it lives, before a write lands beside the real
        // journal. The binary refuses to reach here without the word.
        if engine.recovery().is_some_and(|recovery| recovery.began) {
            if start.create {
                say_open_line(BeganUnderCreateLine);
            } else {
                say_open_line(BeganLine);
            }
        }
        // The stray temp file (AUTH-2.86's family of startup reports): a
        // checkpoint a crash or a full volume left half-written, which the
        // kernel's open found and removed — said here, the kernel answering
        // the fact, so the operator's acts at the floor stay two.
        if let Some(bytes) = engine.kernel().stray_checkpoint_removed() {
            say_open_line(format_args!(
                "checkpoint.tmp found ({bytes} bytes) and removed: a checkpoint a crash or \
                 the journal's own full volume left half-written, no base, its room on the \
                 volume reclaimed by the open"
            ));
        }
        // The tail cut (`operations.md` §1.1 m3; §4 row 8): the bytes the
        // kernel's open took off the journal above its last committed marker
        // (`Recovery::tail_cut`), the file and the byte the cut began at, and
        // the position it lies past — the committed head the open left,
        // read before anything is served — said here as the stray file is,
        // and nothing where nothing was cut, which is every open after a
        // clean close. Of two arms (`TailCutLine`): a crash's or a kill's
        // tail, said under `Class::Open` through the door; and a damaged
        // tail cut under `--cut-damaged-tail` — intact frames no torn write
        // leaves among its bytes (`Recovery::tail_cut_intact`), or more of
        // them than one append leaves — where the cut may have taken an
        // acknowledged write: at the position its marker claimed, its bytes
        // kept beside the journal in the files the line names
        // (`Recovery::tail_cut_kept`), the order started past the claim
        // (`Kernel::order_floor`) — said as the failure it is. A tail the
        // open refused never reaches here: the engine's open refused above.
        // The inventory reports the same bytes as `journal.tail_cut`.
        let floor = engine.kernel().order_floor();
        if let Some(cut) = TailCutLine::of(engine.recovery(), engine.kernel().current_seq(), floor)
        {
            match cut.class() {
                Class::Open => say_open_line(cut),
                class => notice::emit(class, cut),
            }
        }
        // The flag given to a start that needed none: said, and the start
        // goes on — a clean tail, or a crash's, is cut under it as under
        // no flag, nothing kept; the word is for one start and must not
        // stand in a unit file (`operations.md` §3.1 step 3).
        if start.cut_damaged_tail && engine.recovery().is_none_or(|r| r.tail_cut_kept.is_empty()) {
            say_open_line(
                "--cut-damaged-tail was given and no damaged tail stood: nothing was kept; the \
                 flag is for one start — remove it from the command line or the unit file",
            );
        }
        // The start point's size, read once here: the byte bound of the
        // cadence and the floor in force both scale by a checkpoint's size,
        // and the one the open sizes by is the start point's — the base the
        // engine's open loaded the world from (`recovery.start_point`), its
        // header read by name — never the newest file's, whose header may be
        // a skipped base's claim: a damaged `body_len` the open passed over
        // would otherwise refuse every deposit at a floor sized to the claim
        // and hold the cadence's byte half off until the first landing. A
        // start point at genesis names no file and sizes as no checkpoint
        // does. The thread re-reads the newest checkpoint as each one lands,
        // every later base having loaded.
        let start_point = engine.recovery().map_or(Seq(0), |recovery| recovery.start_point);
        let start_point_len =
            engine.kernel().checkpoint_header(start_point).map(|header| header.len);
        engine.kernel().set_cadence_bytes(cadence_bytes_for(start_point_len));
        // The newest checkpoint as the thread will find it at its first wake,
        // so a wake with no flag and no landing re-reads nothing off a header
        // the open did not size by.
        let newest_at_open = engine.kernel().newest_checkpoint().map(|header| header.seq);
        // The head at the open: where the write guard's first figures on a
        // landing's line are counted from.
        let head_at_open = engine.kernel().current_seq();
        // The blob store, opened under `blobs/` beside the journal: its
        // reconciliation and compaction complete here, before anything is
        // served (the record: "OPEN's PASSES OVER BOTH STORES … COMPLETE
        // BEFORE THE DAEMON SERVES ITS FIRST REQUEST"). The limits in force
        // — the daemon's default, a share of the volume's capacity
        // (`DEFAULT_LIMIT_SHARE`) read once here, until the serving layer's
        // channel installs a record (AUTH-4.70, owed) — are named on the
        // operator stream with their source, the floor in force at start
        // beside them, and the upload setting after, with its source (§1.1
        // row 8): the default, the flag or the variable, as the parse
        // recorded it on the option type the gate takes. Opened ahead of the
        // write path, which takes the gate's cell index to enter at every
        // commit from here on.
        let uploads_source = media_opts.uploads_source;
        let media = MediaGate::open_with(data_dir, media_opts).map_err(DaemonError::Media)?;
        media.note_checkpoint(start_point_len);
        // What the store's open found of its two logs (`Store::opened`), said
        // here — the store writes no line of its own (`operations.md` §4 row
        // 19): a torn last line, a crash's, as the open's own landing; a
        // damaged line's cut, kept beside the log, the lines read as no
        // record and a log absent beside a standing store as the failures
        // they are, each lost lease or record reading as none. Lease damage
        // halts the pruner's unlink pass for this uptime, below, once the
        // daemon stands.
        let opened = media.store().opened();
        let logs = [
            BlobLogLines { read: &opened.uploads_log, store_stood, each: "upload" },
            BlobLogLines { read: &opened.leases_log, store_stood, each: "lease" },
        ];
        for log in &logs {
            for (class, line) in log.lines() {
                match class {
                    Class::Open => say_open_line(line),
                    class => notice::emit(class, line),
                }
            }
        }
        let lease_damage = logs[1].damage();
        say_open_line(media.startup_line());
        // The volume's free space beside the floor just named (m4): a start
        // below the floor, or one whose read the host refuses, says so here,
        // where the floor's own line waits for the first refused upload and
        // the standing line for the first tick.
        say_open_line(VolumeLine { free_space: media.free_space(), floor: media.floor() });
        say_open_line(UploadsLine { open: media.uploads_open(), source: uploads_source });
        let commits = Commits::open(data_dir, &engine, Arc::clone(media.index()))
            .map_err(DaemonError::Sidecar)?;
        // The kept files beside the journal and the logs (`operations.md`
        // §1.1 m11): a standing state, listed and said at every open while
        // any stands — after every open of this start that keeps, the
        // journal's, the blob logs' and the change feed's, so the ones this
        // open kept are among them, each already said by its own line —
        // until the operator removes them.
        let kept_files = match tools::kept_files(data_dir) {
            Ok(kept) => kept,
            Err(e) => {
                notice::emit(
                    Class::Failure,
                    format_args!(
                        "the kept files beside the journal and the logs could not be listed: \
                         {e}; the standing line lists them again at its next tick"
                    ),
                );
                Vec::new()
            }
        };
        if !kept_files.is_empty() {
            say_open_line(KeptFilesLine { kept: &kept_files });
        }
        // The link-type registry's seed (commons-seeding §1 to §4;
        // `skep-core`'s `commits/registry.rs`): what the registry document
        // `1.1.0.1.0.1` lacks of the vocabulary — one named section and one
        // `defines` link per type — written now, as the system principal
        // through the head writer's door, under the write path's own guard
        // and before anything is served: every row on a fresh board, the
        // missing ones on an upgraded or interrupted one, nothing on a board
        // that holds them all. Said where it wrote, as the open's report,
        // through the write path's classed door rather than the report's
        // own, so the line stands in the one record the suites read beside
        // the seed's own failure line (said once by the seed where a driver
        // refused a row; the open goes on either way). The compiled seeding
        // check above is another thing: it refuses the open; this never does.
        let began = Instant::now();
        let seeded = {
            let serial = commits.serial_lock();
            commits.seed_registry(&serial)
        };
        if seeded.written > 0 {
            let total = skep_registry::vocabulary().len();
            let duration_ms = began.elapsed().as_millis();
            commits.lines().say(Class::Open, RegistrySeededLine { seeded: &seeded, total, duration_ms });
        }
        // The read predicate (PUB-1.31; PUB-6.39's one-per-request shape).
        // The live front door is given no consult: M10 answers
        // `World::readable` — published ∨ subtree ∨ grant, with the version
        // member projected to its document (PUB-2.15) — off the one snapshot
        // it pins per request, so every named argument, every per-run mask
        // and the result-set filter of one request stand on one committed
        // state, the state its `as_of` names; and the publish shot's source
        // gate (PUB-6.23, PUB-8.1) reads the same predicate over the working
        // world of the shot's own transaction, which M5 hands it. A consult
        // closed over a per-call snapshot of the live kernel would judge one
        // request's arguments against different heads. The one front door
        // that does take a consult is history's (`history.rs`): a read as of
        // N answers the N-world's content through the head's sets
        // (PUB-6.48), which no world of its own can supply.
        //
        // And the write-path check leans on this door carrying none: its dry
        // run of a shot's source gate (`skep-core`'s
        // `auth/policy/attestation.rs`) asks `World::visible_to` at the
        // principal, which is what this door lends the store only while it
        // carries no consult — a consult added here is owed to that dry run
        // too, or the check passes through, unattested, a shot the store then
        // admits.
        let febe = OperationSurface::new(Box::new(engine.stores()), MEMO_CAPACITY);
        let auth = {
            let snap = engine.kernel().snapshot();
            AuthState::open(auth_start, snap.world())
        };
        #[cfg(any(test, feature = "test-hooks"))]
        let said = Arc::clone(commits.lines_said());
        // The two media pools, over the media gate's classed door and the
        // daemon's one hold-down for every edge pair (m12): built before the
        // gate moves into the daemon, each holding a clone of its door.
        let fetches = FetchPool::new(&media, EDGE_HOLD_DOWN);
        let uploads = UploadPool::new(&media, EDGE_HOLD_DOWN);
        let daemon = Daemon {
            data_dir: data_dir.to_path_buf(),
            engine,
            febe,
            codec: JsonCodec,
            auth,
            commits,
            history: History::new(),
            scans: ClassScans::new(),
            media,
            pruner: Pruner::new(),
            fetches,
            uploads,
            write_permits: Permits::new(MAX_CONCURRENT_WRITES),
            write_edge: EdgeTracker::new(EDGE_HOLD_DOWN),
            checkpointer: CheckpointMemory::at_open(start_point, newest_at_open, head_at_open),
            resident: ResidentHighWater::new(),
            threads: ThreadLiveness {
                pruner_ended: AtomicBool::new(false),
                checkpointer_ended: AtomicBool::new(false),
            },
            aside_fault_said: AtomicBool::new(false),
            history_damage: OnceLock::new(),
            #[cfg(any(test, feature = "test-hooks"))]
            hold_between_claim_and_head: AtomicBool::new(false),
            #[cfg(any(test, feature = "test-hooks"))]
            faults: ThreadFaults {
                checkpointer: AtomicBool::new(false),
                pruner: AtomicBool::new(false),
                unlink: AtomicBool::new(false),
            },
            #[cfg(any(test, feature = "test-hooks"))]
            stream_thread_faults: Mutex::new(hooks::ThreadRefusals::new()),
            #[cfg(any(test, feature = "test-hooks"))]
            worker_thread_faults: Mutex::new(hooks::ThreadRefusals::new()),
            #[cfg(any(test, feature = "test-hooks"))]
            said,
        };
        // The pruner's unlink pass, halted for the uptime where the lease
        // log's open found damage (`operations.md` §4 row 19): the leases it
        // lost hold no file in memory, so a pass would unlink the files
        // their depositors hold as unreferenced. Said once here; the pass's
        // own line carries the halt hourly (row 34).
        if let Some(reason) = lease_damage {
            daemon.pruner.halt_the_unlink_pass(reason.clone());
            daemon.say(Class::Failure, PrunerHaltedByLeaseDamageLine { reason: &reason });
        }
        // The crash window, closed before anything is served (signed ops;
        // see the method): a claimed board whose journal holds no head owes
        // `H.1`, and the open is where it is paid.
        daemon.write_the_claims_head_if_owed();
        // The cell index's walk, on a thread of its own over the world as it
        // stands now, or here at the open where the OS refuses the thread —
        // every commit from here on enters its own cells, and the walk adds
        // the world's into the same copy (the composition clause). The
        // daemon serves while the thread walks; the index's three readers
        // refuse `index_rebuilding` until it completes. A walk that dies, on
        // its thread or here, is caught and marks the index failed: the open
        // returns all the same, and those three refuse `index_failed`.
        index::start_walk(daemon.engine.kernel(), Arc::clone(daemon.media.index()));
        Ok(daemon)
    }

    /// Closes the crash window: writes `H.1` where a claimed board owes it.
    ///
    /// The claim and its head are two transactions in one serialized step
    /// ([`Daemon::on_claim_flip`]; signed ops), and a process that dies
    /// between them — the claim durable, no head — leaves a claimed board
    /// with no board term on disk, as does a claim whose `H.1` the head
    /// writer's driver refused while serving ([`Daemon::on_claim_flip`]
    /// states that refusal): the two states in which the check's
    /// `board_unavailable` would otherwise answer every attested write until
    /// the cadence's next head. Closed here, at open and before anything is
    /// served: a claimed board (its identity slice naming a claimant) whose
    /// head writer resumed no head writes `H.1` now
    /// ([`Commits::write_first_head`]) under the write path's own lock,
    /// naming the committed pair as it stands — the claim's own position
    /// where the crash was the split, and the last commit's on a board whose
    /// claim's `H.1` the driver refused, or claimed under a build that wrote
    /// no head at the claim. The unclaimed board writes nothing here: no
    /// head by a claim that did not happen (the required-signing check's
    /// A1/A5). A claimed board with its head finds writing it a no-op, so a
    /// clean restart writes none. The line on the operator stream is
    /// I11 (c)'s: a head written for a reason other than the cadence's is
    /// said, never silent — a landing, as the flip's own line is
    /// (`operations.md` §1.1 row 12), through the daemon's classed door —
    /// naming where `H.1` landed, how long its write held the lock, and the
    /// committed pair it names ([`HeadAtOpenLine`]): the one line this board
    /// has of its first head where the crash split the claim from it, so the
    /// flip's own line was never said. A head the driver refuses here is
    /// surfaced as every refused head is, and fails nothing: the open
    /// returns all the same, and the board answers attested writes
    /// `board_unavailable` until a head lands.
    ///
    /// **Why not one transaction.** A head names the committed
    /// `(position, chain)` pair read before its own write opens — a
    /// coordinate strictly below its own commit, since no bytes can carry
    /// their own hash — so a head folded into the claim's transaction could
    /// name only the position before the claim, and the claim's own chain
    /// value does not exist until its transaction closes. The
    /// two-transaction shape is the head's rule (`head.rs`, what a head is),
    /// not a limit of the journal's format, and this open is what closes the
    /// gap it leaves.
    fn write_the_claims_head_if_owed(&self) {
        if !self.board_is_claimed() {
            return;
        }
        let serial = self.commits.serial_lock();
        // The pair the head names is the committed head under this lock, the
        // one `write_first_head` reads before its own write opens.
        let kernel = self.engine.kernel();
        let named = kernel.current_seq();
        let began = Instant::now();
        if self.commits.write_first_head(&serial) == FirstHead::Written {
            let duration_ms = began.elapsed().as_millis();
            self.say(
                Class::Landing,
                HeadAtOpenLine { landed: kernel.current_seq(), duration_ms, named },
            );
        }
    }

    /// Returns whether the board is claimed, from the head's identity slice.
    ///
    /// It is the one bit the mode and the two origin sets turn on
    /// (AUTH-1.42), read here rather than supplied so no caller can hand a
    /// line a fact the daemon can answer.
    fn board_is_claimed(&self) -> bool {
        self.engine.kernel().snapshot().world().identity().claimant().is_some()
    }

    /// Binds the auth surface to the served port.
    ///
    /// The origin sets and the `/health.auth` lists derive from it.
    /// [`serve`] calls this with the bound port; a socket-free embedder that
    /// wants origin behavior calls it itself. The two are exclusive.
    ///
    /// # Errors
    ///
    /// [`PortAlreadyBound`] where a port is already bound: the number it
    /// carries is the one already there — the number every live session's
    /// origin set was established against — not the one refused.
    ///
    /// # Panics
    ///
    /// Panics if `port` is 0 — a caller's bug and not an outcome, so it is
    /// not one of the errors above. Zero is not a port this daemon can serve
    /// on, and it is the one value from which the loopback defaults derive
    /// origins this daemon's own parser rejects and no `Origin` header can
    /// match.
    pub fn bind_auth_port(&self, port: u16) -> Result<(), PortAlreadyBound> {
        self.auth.cfg.bind_port(port)
    }

    /// Returns the world as of a committed position.
    ///
    /// It is the same bounded replay `POST /op-at` answers from, for
    /// embedders that want the state rather than a wire answer. Unbudgeted:
    /// the reconstruction permit bounds concurrent HTTP callers, and an
    /// embedder calling this holds the daemon itself.
    ///
    /// # Errors
    ///
    /// The engine's [`HistoryError`]: `BeyondHead` where `at` is above the
    /// head, `NotABoundary` where it is no commit boundary, `Reclaimed` where
    /// no base at or below it remains derivable, and `Io` or `Corruption`
    /// where the journal cannot be read.
    pub fn world_at(&self, at: Seq) -> Result<World, HistoryError> {
        self.engine.world_at(at)
    }

    /// Returns the committed world's dump at `principal`'s class.
    ///
    /// It is what `GET /dump` answers a session bound to `principal` (`None`
    /// = the guest), through the same engine call, so a suite holding the
    /// daemon can state the oracle: the wire body equals this post-filter of
    /// the harness-only walk byte for byte. Unbudgeted, like
    /// [`Daemon::world_at`]: an embedder calling this holds the daemon
    /// itself.
    ///
    /// The answer's type is re-exported as [`crate::WorldDump`], for the
    /// reason the engine types beside it are: naming it must not oblige a
    /// caller to depend on the engine.
    #[cfg(feature = "observe")]
    pub fn dump_visible_to(&self, principal: Option<PrincipalId>) -> crate::WorldDump {
        self.engine.world_dump_visible_to(principal)
    }

    /// Returns the current log position (M10's `log_position`).
    ///
    /// It never regresses.
    pub fn log_position(&self) -> Seq {
        self.febe.log_position()
    }

    /// Returns whether the cell index's walk at open has completed.
    ///
    /// It is the media gate's readiness, which the index's three readers read
    /// after the gate's failed state. The walk runs on a thread of the
    /// daemon's from the open on — at the open itself where the OS refuses
    /// the thread — seconds to a minute on a large board, and the daemon
    /// serves meanwhile: until this is true, the three readers — the PUT's
    /// creation and resume and the deposit read — refuse
    /// `503 index_rebuilding`, retry-class, and the media door answers a
    /// picture cell's write the same token where the index alone could admit
    /// it (wire.md §Media); every other request is served.
    /// [`Skepd::wait_for_the_index`] waits on this read. A walk that died
    /// never completes (`operations.md` §4 row 26): the three readers refuse
    /// `index_failed` for the uptime instead, and this stays false.
    pub fn index_is_ready(&self) -> bool {
        self.media.index_ready()
    }

    /// Routes one request: the whole HTTP surface, still socket-free.
    ///
    /// The two routes that cannot be a request/response `Reply` —
    /// `GET /events`, an unbounded response, and the blob fetch's admitted
    /// answer, a file streamed with its requester re-resolved between chunks
    /// — are returned as their own [`Routed`] variants, and the accept path
    /// owns the socket from there.
    ///
    /// A command, not a query. `POST /op` commits to the journal, records
    /// the change-feed entry, and announces the commit — and where that
    /// commit makes the published head due (wire.md §The other endpoints: 64
    /// commits since the last head, a moved checkpoint, or the hour), the
    /// daemon's own head writer commits up to three writes of its own before
    /// the reply is built, so the journal can stand past the ack's `at` when
    /// this returns — and the credential write that claims the board is
    /// followed by its first head `H.1` in the same step, whatever the
    /// cadence says (signed ops), where the head writer's driver admits it
    /// (`Daemon::on_claim_flip` states the refusal); `POST /session` mints an
    /// M10 session; `GET /challenge` mints a nonce into the bounded challenge
    /// store and evicts the oldest past `auth`'s `MAX_LIVE_NONCES` — a GET
    /// that is not safe, and whose eviction can spend another caller's
    /// outstanding nonce; `POST /session/close` retires a binding. And every
    /// token-accepting route (`/op`, `/op-at`, `/changes`, `/dump`,
    /// `/session/close`, the blob family and the blob fetch, and `/events`
    /// on the accept path) can retire one, because `Daemon::resolve_actor`'s
    /// death arm closes the binding a dead or unknown token names — in this
    /// daemon's map, in M10, and in the credential memo. So routing one
    /// write frame twice commits twice unless the frame carries an
    /// idempotency `id` (wire.md §Correlation and idempotency) — a
    /// speculative retry after a timeout duplicates the insert or mints a
    /// second document. Of the dispatch arms, those that alter nothing are
    /// the preflights, the `404` and `405` refusals, `GET /health`,
    /// `GET /chain` — whose permit returns within the request — and, in
    /// `client` builds, `GET /`; but no route does, because the reissue
    /// below sits ahead of dispatch on every request.
    ///
    /// What the caller owes on the way in is [`HttpRequest`]'s field
    /// precondition, which routing cannot check; what a [`Reply`] is not on
    /// the way out is the headers `http::write_reply` supplies,
    /// [`UNIVERSAL_HEADERS`] among them, which wire.md promises on every
    /// response.
    ///
    /// Every request first looks at the blocked-prefix list's supply
    /// (`Daemon::reissue_blocked_prefixes`) — ahead of dispatch and of every
    /// lock, so a reissue is in force before the request that noticed it
    /// resolves its own actor, `/events` included.
    ///
    /// **The blob upload's body.** A caller over its own transport hands the
    /// family's two body-carrying methods their body in `req.body`, and the
    /// route reads it through the same source type the daemon's own
    /// transport streams a socket through (`server/http.rs`, the streaming
    /// arm) — that transport's body stays on the socket and reaches the
    /// route by a door of its own, beside the request and by value
    /// (`Daemon::route_parked`), so it is read by the one routing it was
    /// parked for.
    ///
    /// **The blob fetch's answer** (wire.md §Media, the fetch).
    /// `GET /blob?i=` and `HEAD /blob?i=` admitted are [`Routed::Fetch`] —
    /// the whole file, checked, with the fetch pool's permit the value holds
    /// — which the accept path streams; every refusal of the route is a
    /// [`Routed::Reply`].
    ///
    /// **The edge pairs** (`operations.md` §1.1 m12). A routing that first
    /// meets a saturated pool, or first spends a live nonce past the
    /// challenge store's cap, puts one `failure:` line on the operator stream
    /// before its answer is written, and the first routing admitted once the
    /// condition has stood clear for `EDGE_HOLD_DOWN` one `landing:`
    /// (`Daemon::say_the_edges_crossed`); nothing per request. The answers
    /// themselves — the five `503 …_busy` refusals, `/challenge`'s nonce —
    /// are the same with the lines as without them.
    ///
    /// # Panics
    ///
    /// Panics where the OS refuses entropy — the one panic the daemon's own
    /// code, this crate's and `skep-core`'s, raises by design on an honest
    /// request: `GET /challenge` and `POST /session` draw their nonce and
    /// their token from `skep-core`'s fail-stop OS source (`auth/entropy.rs`),
    /// which never mints a credential from anything weaker. `POST /session`
    /// draws after M10 has minted the session the token would name
    /// (AUTH-4.23 declares the store that way), so that unwind drops a
    /// `SessionId` nothing can close, and a signed body's nonce is spent.
    /// Every other panic this router can raise is a defect — a premise this
    /// crate, or a store beneath it, relies on, failing — never a refusal an
    /// honest input earns. [`serve`] contains each to `500 internal_panic`
    /// and the worker survives it; a caller routing over its own transport
    /// owes the same containment, and finds the daemon serviceable after the
    /// unwind, every lock it holds being one that does not poison.
    pub fn route(&self, req: &HttpRequest) -> Routed<'_> {
        self.route_parked(req, None)
    }

    /// Routes as [`Daemon::route`] does, with the body the transport parked.
    ///
    /// It is the daemon's own transport's door: the body that transport left
    /// on the socket — the blob upload's creation and resume
    /// (`server/http.rs`, the streaming arm) — is handed in beside the
    /// request, by value, so it is read by this one routing and by no other.
    /// Private: a caller over its own transport has no socket to park, and
    /// [`Daemon::route`] reads the request's own `body` through the same
    /// source type.
    fn route_parked(&self, req: &HttpRequest, parked: Option<BodySource<'static>>) -> Routed<'_> {
        self.reissue_blocked_prefixes();
        let routed = match (req.method.as_str(), req.path.as_str()) {
            ("GET", "/events") => Routed::EventStream,
            ("GET" | "HEAD", p) if blob_routes::is_fetch_path(p) => self.fetch_route(req),
            _ => Routed::Reply(self.reply(req, parked)),
        };
        // The edges this routing crossed, said (m12): the three holders with
        // no door of their own — the reconstruction pool, the class-scan
        // pool and the challenge store — queued the edge an admission or a
        // refusal crossed; the daemon says each here, after the handler and
        // before the transport writes the reply, through its own classed
        // door.
        self.say_the_edges_crossed();
        routed
    }

    /// Answers the request/response routes, decided in one match.
    ///
    /// They are every method/path pair but `GET /events` and the fetch's
    /// `GET` and `HEAD`. The token-accepting set (AUTH-4.43) is the arms
    /// wearing [`Daemon::token_route`]: `/op`, `/op-at`, `/changes`, `/dump`
    /// and `/session/close` here, plus `/events`, which the accept path runs
    /// by hand because a stream is not a [`Reply`] — and the blob upload's
    /// family and the blob fetch, whose every method resolves its actor the
    /// same way inside `blob_route` and `fetch_route` and carries the signal
    /// the same. `/health`, `/chain`, `/challenge`, `/session` and `/` are
    /// token-blind by design.
    fn reply(&self, req: &HttpRequest, parked: Option<BodySource<'static>>) -> Reply {
        match (req.method.as_str(), req.path.as_str()) {
            // The blob family's preflight names its own four methods, the
            // fetch's its own two; every other known path answers the common
            // preflight.
            ("OPTIONS", p) if blob_routes::is_blob_path(p) => Reply::preflight_blob(),
            ("OPTIONS", p) if blob_routes::is_fetch_path(p) => Reply::preflight_fetch(),
            // CORS preflight (wire v4): 204 on any known path; an unknown
            // path falls through to the ordinary 404 below.
            ("OPTIONS", p) if path_is_known(p) => Reply::preflight(),
            // The blob upload (wire.md §Media): the family's five method/path
            // pairs, dispatched inside — each answer a function of the
            // presented token, so each wears the class-varying headers as
            // `/op`'s does.
            (_, p) if blob_routes::is_blob_path(p) => {
                let mut source = parked.unwrap_or_else(|| BodySource::bytes(&req.body));
                class_varying(self.blob_route(req, &mut source))
            }
            ("GET", "/challenge") => self.get_challenge(req.query.as_deref()),
            ("POST", "/session") => self.post_session(req),
            ("POST", "/session/close") => {
                self.token_route(req, |r| self.post_session_close(r, req))
            }
            // The four class-varying routes (wire v7.6): each answer is a
            // function of the presented token's class, so each wears
            // `class_varying` — `Cache-Control: no-store` and
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

    /// Resolves the request's actor against the head.
    ///
    /// It is [`Daemon::resolve_actor`] at the route level — the resolution
    /// run before dispatch on every token-accepting route, over one head
    /// snapshot: the world and the key table it carries. The
    /// resolved actor is handed to dispatch; the write sequences re-resolve
    /// at their own sites against the snapshot their gates stand on.
    ///
    /// A command: `resolve_actor`'s death arm retires the binding a dead or
    /// unknown token names, in this daemon's map, in M10 and in the
    /// credential memo. Idempotent — a second resolution of the same token
    /// finds `Unknown` and closes nothing — which is what makes running it
    /// at the route level and again under the lock harmless.
    fn resolve_at_head(&self, req: &HttpRequest) -> Resolved {
        let snap = self.engine.kernel().snapshot();
        self.resolve_actor(req, snap.world())
    }

    /// Runs one token-accepting route (AUTH-4.43).
    ///
    /// It resolves the actor against the head — which may retire the binding
    /// a dead or unknown token names — runs the handler, and attaches the
    /// `Skepd-Session: closed` header the answer may owe (AUTH-6.7). The arm
    /// that wears this is its declaration that the route accepts a token, so
    /// the set is a fact of [`Daemon::reply`]'s shape rather than a list each
    /// arm keeps for itself. `/events` and the blob fetch are the members
    /// that cannot: a stream is not a [`Reply`], so the accept path runs the
    /// same pair by hand for `/events` (AUTH-4.44) and `fetch_route` runs it
    /// itself, as `blob_route` does for the upload family.
    ///
    /// The three write sequences wrap again, against their own locked
    /// resolution — which can find a death this one did not — and that
    /// double is harmless by construction: [`with_signal`] attaches the
    /// header once however many sites observed the death.
    fn token_route(&self, req: &HttpRequest, f: impl FnOnce(&Resolved) -> Reply) -> Reply {
        let resolved = self.resolve_at_head(req);
        with_signal(f(&resolved), resolved.closed)
    }

    /// Logs the config-lockout warnings (AUTH-4.9–4.11).
    ///
    /// They are logged at startup, and again at the claim flip, which RES-30
    /// requires unconditionally — each under its class word,
    /// `warning ({when}):`, through the classed door. One method because the
    /// warnings are one obligation: which apply is
    /// [`skep_core::auth::startup_warnings`]'s, but the claim reading they
    /// are computed against and the stream they go to are this daemon's, and
    /// [`serve`] would otherwise reach two levels into
    /// [`skep_core::auth::AuthState`] to spell them.
    ///
    /// `when` is the grammar's moment and only labels the line. The claim
    /// itself is read from the head's slice ([`Daemon::board_is_claimed`])
    /// rather than supplied, so no caller can hand this method a fact the
    /// daemon can answer.
    fn log_config_warnings(&self, when: Moment) {
        let claimed = self.board_is_claimed();
        for w in startup_warnings(&self.auth.cfg, claimed) {
            self.say(Class::Warning(when), w);
        }
    }

    /// Logs the `auth:` line of the open's report.
    ///
    /// It carries the mode as AUTH-5.86 derives it from the pair, the
    /// local-trust flag with its source, and two origin sets, the configured
    /// and the signed (`operations.md` §1.1 m14; §3.1 step 3) — said on
    /// every start, after the bind (the signed set's bare arm is the bound
    /// port's defaults) and the configuration warnings, before the node
    /// prefix and the blocked list. A state line and no warning:
    /// `startup_warnings` says what is wrong, this says what *is*, so an
    /// enforcing board with a mistyped `--origin` names the origin it will
    /// refuse every signed session but. What the line says is
    /// `AuthConfig::auth_line`'s, built where its state lives; the claim
    /// reading and the stream are this daemon's, for
    /// [`Daemon::log_config_warnings`]'s reason.
    fn log_auth_line(&self) {
        self.say(Class::Open, self.auth.cfg.auth_line(self.board_is_claimed()));
    }

    /// Logs the node prefix in force, or its absence (REG-1.69), once at start.
    ///
    /// It is named with its source (§1.1 row 19) — whether or not a list is
    /// supplied, because a hosted board launched without its prefix has its
    /// off-board test off and would otherwise learn so only at its first
    /// install. It is the one config the blocked-prefix list's off-board
    /// test reads (AUTH-4.36 step 4b). What the line says is
    /// `AuthConfig::node_prefix_line`'s; the stream is this daemon's, for
    /// [`Daemon::log_config_warnings`]'s reason. A line of the open's
    /// report, so `Class::Open`.
    fn log_node_prefix(&self) {
        self.say(Class::Open, self.auth.cfg.node_prefix_line());
    }

    /// Logs the blocked-prefix list in force, as one notice of several lines.
    ///
    /// The notice (AUTH-4.70: "the startup log names the list in force";
    /// AUTH-4.36 step 4b: an inert entry is "ignored at install and said so
    /// in the log") carries the count, the header as the install resolved
    /// it, and the inert entries by name, through the classed door. Written
    /// at the three moments an install happens, under the class row 20 gives
    /// each ([`ListHeader`]): at start a line of the open's report,
    /// `Class::Open`; at a reissue and at the claim — where the flip
    /// re-compares the issue against the claimant it first has — a
    /// `Class::Landing`. What the lines say is `BlockedPrefixes::log_lines`'s;
    /// the stream is this daemon's, for [`Daemon::log_config_warnings`]'s
    /// reason.
    ///
    /// Where no supply was named it says so at start, one line of the open's
    /// report (`AuthState::blocked_supply_absent_line`): no list is in force,
    /// and since the path is read at start alone none can be until a
    /// restart names a file. At a claim it says nothing more, there being no
    /// list to re-compare.
    fn log_blocked_prefixes(&self, when: Moment) {
        if when == Moment::AtStart {
            if let Some(absent) = self.auth.blocked_supply_absent_line() {
                self.say(Class::Open, absent);
            }
        }
        let Some(path) = self.auth.blocked_supply_path() else { return };
        let class = match when {
            Moment::AtStart | Moment::AtOpen => Class::Open,
            Moment::AtClaim | Moment::AtReissue => Class::Landing,
        };
        self.say_lines(
            class,
            ListHeader { when, path },
            &self.auth.cfg.blocked_prefixes().log_lines(),
        );
    }

    /// Runs the reissue at the head of every request (AUTH-4.70).
    ///
    /// Where the supply file moved, [`AuthState::reissue_blocked_prefixes`]
    /// re-reads it and installs the new issue whole under the credential
    /// write lock — the list's commit — and the log names the list then in
    /// force, a landing under row 20's `reissued` header. A file that cannot
    /// be read, is not a list, or is past the channel's byte cap installs
    /// nothing: the list in force stands and the refusal is said once per
    /// bad issue, as a failure in row 24's words ([`ReissueRefusedLine`]) —
    /// what stands, and that the next start refuses until a valid list
    /// stands at the path, since every start reads the file again (RES-115).
    /// No warning is written at a reissue: `startup_warnings` is evaluated
    /// at AUTH-4.11's two points alone.
    ///
    /// A command, and called under no lock: it takes the credential write
    /// lock, which is why it runs here and not where the list is read. The
    /// claimant the install compares against is the head's slice, read
    /// under that lock through the closure handed down.
    fn reissue_blocked_prefixes(&self) {
        let head_identity = || self.engine.kernel().snapshot().world().identity().clone();
        match self.auth.reissue_blocked_prefixes(head_identity) {
            None => {}
            Some(Reissue::Installed) => self.log_blocked_prefixes(Moment::AtReissue),
            Some(Reissue::Refused(e)) => {
                // A reissue comes from a supply, so the channel names its
                // file; the arm renders the path it would otherwise have to
                // invent.
                let path = self
                    .auth
                    .blocked_supply_path()
                    .expect("a reissue is the supply channel's, which names its file");
                self.say(Class::Failure, ReissueRefusedLine { error: &e, path });
            }
        }
    }

    /// Says the standing line (`operations.md` §1, the rates; §1.1 m11).
    ///
    /// It is what the checkpoint thread runs at each tick of its timed wait
    /// ([`Woken::Tick`](skep_core::commits::Woken::Tick)): the ten reads —
    /// each atomic loads or one lock, save the floor's fresh read of the
    /// volume and the unread deposit's fresh read of its file, and none under
    /// the serialization guard — in the order the line says them: (1) the
    /// write path's halt with its position, (2) the kernel's poison with the
    /// head it halted at — no commit lands past a poisoned kernel, so the
    /// head at the tick is the position the halt line (m10) named — (3) the
    /// journal damage a history read met this uptime, by the site its line
    /// named (`Daemon::history_damage`; RUNBOOK §2), (4) the feed's stopped
    /// files with theirs, (5) the pruner's liveness flag, (6) the feed walk's
    /// liveness flag with the region its death left uncovered, (7) the cell
    /// index's failed state, the media gate's (`operations.md` §4 row 26),
    /// (8) the media gate's floor binding — its free space below its floor in
    /// force, or a read of it the host refused, the creation's own test
    /// (`MediaGate::floor_binding`, read fresh, so the floor's clause stops by
    /// itself once the read answers room) — (9) the media gate's unread
    /// deposit, a deposit's file the store could not read
    /// (`MediaGate::unread_deposit`, its file read fresh, so the clause stops
    /// by itself, and the episode's end is said, once the store reads it; one
    /// atomic load where none stands) — and (10) the `CLAIMED-PERMISSIVE` bit
    /// as `log_config_warnings` reads the claim; and one line,
    /// [`StandingLine`], under `Class::Standing`, where at least one clause
    /// stands; nothing otherwise. No clause for the checkpoint thread's own
    /// death — it is the carrier.
    pub(crate) fn say_the_standing_line(&self) {
        let kernel = self.engine.kernel();
        let line = StandingLine {
            halted_at: self.commits.halted_at(),
            poisoned: kernel.is_poisoned().then(|| kernel.current_seq()),
            history_damaged: self.history_damage.get().cloned(),
            stopped_files: self.commits.stopped_feed_files(),
            pruner_gone: self.threads.pruner_ended.load(Ordering::Acquire),
            feed_walk_gone: self.commits.feed_walk_gone(),
            index_failed: self.media.index_failed(),
            floor: self
                .media
                .floor_binding()
                .map(|(free_space, floor)| FloorBinding { free_space, floor }),
            unread_deposit: self.media.unread_deposit(),
            claimed_permissive: self.auth.cfg.claimed_permissive(self.board_is_claimed()),
            // (11) the kept files beside the journal and the logs, listed
            // afresh: a listing the host refuses lists none this tick.
            kept_files: tools::kept_files(&self.data_dir).unwrap_or_default(),
        };
        if line.stands() {
            self.say(Class::Standing, line);
        }
    }

    /// Reads the kernel's halt at the catch (m10's second site).
    ///
    /// After the transport caught a panic on a write, it makes one atomic
    /// load of the kernel's poison — an unwind whose repair failed, or that
    /// passed the barrier, poisons the kernel and re-raises, so the
    /// `500 internal_panic` the catch answers is the only answer that write
    /// gives and no `Rejected` comes until the next write, hours away on a
    /// quiet board — and, where it reads poisoned, says the line through the
    /// write path's once-flag ([`Commits::say_the_kernels_halt_once`]),
    /// which the first site shares: said once between the two, whichever is
    /// reached first.
    pub(crate) fn say_the_kernels_halt_if_poisoned(&self) {
        if self.engine.kernel().is_poisoned() {
            self.commits.say_the_kernels_halt_once();
        }
    }

    /// Runs the checkpoint thread's catch, as the thread ends.
    ///
    /// It is what the loop's `catch_unwind` runs on a caught panic
    /// (`operations.md` §1.1 row 41; §4 row 25) — the liveness flag, then
    /// the consequence line ([`CheckpointThreadEndedLine`]) under
    /// `Class::Failure`. The hook's line has said the panic and its site;
    /// this says what the board lost — the standing line among it, which
    /// ends with its carrier — and that a restart is the cure, which nothing
    /// here runs.
    pub(crate) fn the_checkpoint_thread_ended(&self) {
        self.threads.checkpointer_ended.store(true, Ordering::Release);
        self.say(Class::Failure, CheckpointThreadEndedLine);
    }

    /// Runs the pruner's catch, as the thread ends.
    ///
    /// It is what the loop's `catch_unwind` runs on a caught panic (row 41;
    /// §4 row 24) — the liveness flag the standing line reads, then the
    /// consequence line ([`PrunerThreadEndedLine`]) under `Class::Failure`.
    pub(crate) fn the_pruner_thread_ended(&self) {
        self.threads.pruner_ended.store(true, Ordering::Release);
        self.say(Class::Failure, PrunerThreadEndedLine);
    }

    /// Says one classed line of this daemon's own on the operator stream.
    ///
    /// The configuration lines, the warnings, the flip's landing, a refusal,
    /// the standing line and a thread catch's consequence are among them,
    /// each through the classed door, so no line of this daemon's can go out
    /// without its class word; under the test seam each is also kept for the
    /// suite (`Daemon::lines_said`). The checkpoint thread's lines take their
    /// own door ([`Daemon::say_checkpoint_line`]), with their own record.
    fn say(&self, class: Class, what: impl fmt::Display) {
        #[cfg(any(test, feature = "test-hooks"))]
        self.said.lock().push(format!("{class}: {what}"));
        notice::emit(class, what);
    }

    /// Says a notice of several lines, as [`Daemon::say`] says one.
    ///
    /// The notice is the blocked list's, through `emit_lines`: one write,
    /// the head carrying the class word and the time; and, under the test
    /// seam, kept whole, the head and each line of the rest on a line of its
    /// own.
    fn say_lines(&self, class: Class, head: impl fmt::Display, rest: &[String]) {
        #[cfg(any(test, feature = "test-hooks"))]
        {
            let mut whole = format!("{class}: {head}");
            for line in rest {
                whole.push('\n');
                whole.push_str(line);
            }
            self.said.lock().push(whole);
        }
        notice::emit_lines(class, head, rest);
    }

    /// Says the edges one routing crossed.
    ///
    /// The reconstruction pool's, the class-scan pool's and the challenge
    /// store's edge trackers are drained in turn (`operations.md` §1.1 m12;
    /// §4 row 27; §6's three rows) — each the edges its one door crossed
    /// since the last drain, in order — and each edge said through
    /// [`Daemon::say`] in its holder's words under the edge's own class word
    /// ([`PoolEdgeLine`] for a pool, [`ChallengeEdgeLine`] for the store).
    /// Run at the end of every routing ([`Daemon::route_parked`]), on the
    /// request's thread, after the handler has answered and before the
    /// transport writes the reply, so a line is in the record and queued for
    /// the stream by the time its request's answer is read. The three holders
    /// queue because they hold no door: `History` and `ClassScans` know
    /// nothing of the daemon, and the challenge store is the session layer's.
    /// The write pool's door is the daemon's own (`op.rs`'s
    /// `Daemon::take_write_permit`), the live-stream budget, the live
    /// streams' threads, the accept loop and the worker pool hold the daemon
    /// (`listen.rs`), and the two media pools hold the media gate's door:
    /// those seven say their edges at the edge. A routing that crossed no
    /// edge costs three atomic loads here.
    fn say_the_edges_crossed(&self) {
        self.history
            .edge()
            .drain(|edge| self.say(edge.class(), PoolEdgeLine::new(HISTORY_POOL, edge)));
        self.scans.edge().drain(|edge| self.say(edge.class(), PoolEdgeLine::new(SCAN_POOL, edge)));
        self.auth.challenges.edge().drain(|edge| self.say(edge.class(), ChallengeEdgeLine(edge)));
    }
}

// ── the checkpoint thread's work ─────────────────────────────────────────
//
// What the thread `listen.rs` spawns runs, as `Daemon` methods at the routes'
// layer: the kernel's flag read; the checkpoint with its consequences — the
// byte bound and the floor re-read, the feed's figures read, the landing or
// the failure said; and, on a wake with no flag, the backstop's landing
// followed the same way. The three lines are rendered by the pure types below this
// block — `LandingLine`, `FailureLine`, `BackstopLine`, each saying what a
// landing moved wherever one moved (`AfterLanding`) — which the unit suite
// pins by `to_string()`, and every one goes to the operator stream through
// `Daemon::say_checkpoint_line`, classed.

/// The checkpoint thread's memory between wakes.
///
/// It is what one line of the thread's leaves for the next: the inline count
/// as last said and the position it is counted from, the newest checkpoint
/// as the thread last looked, and — under the test seam — every line the
/// arms rendered this uptime, since no suite captures stderr in-process.
struct CheckpointMemory {
    looked: Mutex<Looked>,
    /// The write guard's figures and the head, as the last such line read them.
    ///
    /// They are what the next line that carries the clause counts from
    /// (`GuardTakes`). Apart from `looked`, because the backstop's arm takes
    /// the landing's re-reads while it holds that lock.
    guard_said: Mutex<(SerialFigures, Seq)>,
    /// The lines rendered this uptime, each `{class}: {text}` (a test seam).
    #[cfg(any(test, feature = "test-hooks"))]
    lines: Mutex<Vec<String>>,
    /// The hold the two-crossings claim parks the thread at (a test seam).
    ///
    /// It is read by `listen.rs`'s loop before it looks at the flag.
    #[cfg(any(test, feature = "test-hooks"))]
    hold: CheckpointHold,
}

/// What the thread last looked at and last said, as one value.
///
/// One value under one lock, because the thread reads and moves the three
/// within one hold of it.
struct Looked {
    /// The inline count as last said (m13).
    ///
    /// It is the kernel's `inline_checkpoints` as the thread last carried it
    /// on a line — line 25's inline clause or the backstop's line. The next
    /// line's `{n}` is the count past this.
    inline_said: u64,
    /// The position the count is counted from: the next line's `{p}`.
    ///
    /// It is the newest checkpoint's position as the thread read it at the
    /// wake it last said a landing or backstop line at (the landing's own
    /// position on line 25), and before any such line this uptime the open's
    /// start point, genesis as `0`.
    since: Seq,
    /// The newest checkpoint's position as the thread last looked.
    ///
    /// The thread looks at the open, and at every line since but a failure
    /// that landed nothing — so a wake with no flag takes the landing's
    /// re-reads only where the newest moved.
    newest: Option<Seq>,
}

impl CheckpointMemory {
    /// Returns the memory at the open.
    ///
    /// Nothing is said, the inline count is counted from the start point, the
    /// write guard's takes from `head`, the head at the open, and the newest
    /// checkpoint is as the open found it.
    fn at_open(start_point: Seq, newest: Option<Seq>, head: Seq) -> CheckpointMemory {
        CheckpointMemory {
            looked: Mutex::new(Looked { inline_said: 0, since: start_point, newest }),
            guard_said: Mutex::new((SerialFigures::default(), head)),
            #[cfg(any(test, feature = "test-hooks"))]
            lines: Mutex::new(Vec::new()),
            #[cfg(any(test, feature = "test-hooks"))]
            hold: CheckpointHold { held: Mutex::new(false), released: Condvar::new() },
        }
    }
}

/// The daemon's high-water of its own resident set.
///
/// It holds the largest reading the daemon has taken of its own physical
/// memory (`memory_stats`, the resident set size): one at every checkpoint
/// landing, a landed failure's included, one at every backstop wake, and one
/// at every pruner pass that lands. The largest of those readings and never
/// the kernel's `ru_maxrss`: what rose and fell between two readings is in
/// neither, so a line names the reading it took and the largest of the
/// uptime's beside it ([`ResidentRead`]), and calls neither the process's
/// peak (`operations.md` §1.1 row 25).
struct ResidentHighWater {
    /// The largest reading so far, zero before the first.
    ///
    /// A resident set is never zero, so zero stands for no reading.
    most: AtomicU64,
}

impl ResidentHighWater {
    /// Returns the high-water before any reading.
    fn new() -> ResidentHighWater {
        ResidentHighWater { most: AtomicU64::new(0) }
    }

    /// Takes a reading of the resident set and folds it into the high-water.
    ///
    /// It answers the reading and the largest so far, this one included. A
    /// reading the crate cannot make moves nothing and fails nothing: the
    /// line then says it is unread, beside the largest so far.
    fn read(&self) -> ResidentRead {
        let now = memory_stats::memory_stats().map(|stats| stats.physical_mem as u64);
        if let Some(now) = now {
            self.most.fetch_max(now, Ordering::AcqRel);
        }
        ResidentRead { now, most: self.most() }
    }

    /// Returns the largest reading so far, `None` before the first.
    fn most(&self) -> Option<u64> {
        match self.most.load(Ordering::Acquire) {
            0 => None,
            most => Some(most),
        }
    }
}

/// One reading of the resident set, beside the largest of the uptime's.
///
/// It renders `the process's resident set {now} bytes, the largest of this
/// uptime's readings {most} bytes`, `unread` in place of a figure no reading
/// answered: the one clause line 25, the backstop's line, a failure after a
/// base landed and the pruner's pass line carry (`operations.md` §1.1 rows
/// 25, 26 and 34; m13).
struct ResidentRead {
    /// This reading, in bytes; `None` where the read answered nothing.
    now: Option<u64>,
    /// The largest reading of the uptime, this one included.
    ///
    /// `None` before any reading answered.
    most: Option<u64>,
}

impl fmt::Display for ResidentRead {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.now {
            Some(now) => write!(f, "the process's resident set {now} bytes")?,
            None => f.write_str("the process's resident set unread")?,
        }
        match self.most {
            Some(most) => write!(f, ", the largest of this uptime's readings {most} bytes"),
            None => Ok(()),
        }
    }
}

/// The hold `Daemon::hold_the_checkpoint_thread` arms (a test seam).
///
/// The thread parks at the top of its loop, before it looks at the flag,
/// until the release — so a suite lands a second crossing while the flag
/// still stands and the kernel's backstop runs it inline, with no race
/// against the thread. The stream hold's shape
/// (`skep_media::serve::STREAM_HOLD`), per daemon rather than per process.
#[cfg(any(test, feature = "test-hooks"))]
struct CheckpointHold {
    held: Mutex<bool>,
    released: Condvar,
}

impl Daemon {
    /// Returns whether the kernel's cadence is due (`Kernel::checkpoint_due`).
    ///
    /// That is, whether it has crossed since the last checkpoint began —
    /// what the checkpoint thread reads before each run, and after one, since
    /// a crossing during a run sets the flag again.
    pub(crate) fn checkpoint_is_due(&self) -> bool {
        self.engine.kernel().checkpoint_due()
    }

    /// Takes the landing's re-reads, after any checkpoint, and answers them.
    ///
    /// The checkpoint is the thread's own, a base that landed before its run
    /// failed, or a backstop's found on a wake with no flag. The re-reads
    /// are the cadence's byte bound ([`cadence_bytes_for`]) and the media
    /// floor, kept by the gate from the newest checkpoint's size as it is
    /// noted (`MediaGate::note_checkpoint`), then what the change feed holds
    /// (`Commits::feed_figures`: the first position its files hold a line
    /// for, `commits.log`'s size and the resident window's count beside the
    /// most it has held — the feed's files are kept whole from genesis, so
    /// a landing moves nothing of them and the line says what they hold),
    /// and beside them the volume's free space as the floor's refusal reads
    /// it, through the gate's one door, a reading of the resident set, and
    /// the write guard's takes since the line before
    /// (`Commits::serial_figures`), its baseline moved to this reading —
    /// each call's answer is said on a line, so the baseline is the last
    /// line's. One function, so the three arms cannot disagree about what
    /// follows a landing, and the answer is what each arm's line says of it
    /// ([`AfterLanding`]): no figure a landing moves moves unsaid. The newest
    /// header is the caller's one read of it, its length handed in.
    fn re_read_after_a_landing(&self, newest_len: Option<u64>) -> AfterLanding {
        let bytes_bound = cadence_bytes_for(newest_len);
        self.engine.kernel().set_cadence_bytes(bytes_bound);
        let floor = self.media.note_checkpoint(newest_len);
        let guard = {
            let now = (self.commits.serial_figures(), self.engine.kernel().current_seq());
            let (said, since) = std::mem::replace(&mut *self.checkpointer.guard_said.lock(), now);
            GuardTakes { figures: now.0.since(said), since }
        };
        AfterLanding {
            bytes_bound: bytes_bound.get(),
            floor,
            free_space: self.media.free_space().ok(),
            resident: self.resident.read(),
            guard,
            feed: self.commits.feed_figures(),
            attest: self.commits.attest_store_figures(),
        }
    }

    /// Returns the kernel's reclaim figures for its last whole landing.
    ///
    /// They are `Kernel::last_reclaimed_bytes` and
    /// `Kernel::last_removed_checkpoints`, which the kernel stores at the end
    /// of a call that landed whole and at no other — so a caller asks for
    /// them only where the landing its line names is such a call: the
    /// thread's own landing, or a backstop's whose last inline run landed the
    /// newest base whole.
    fn reclaimed_by_the_last_landing(&self) -> Reclaimed {
        let kernel = self.engine.kernel();
        Reclaimed {
            bytes: kernel.last_reclaimed_bytes().unwrap_or(0),
            removed: kernel.last_removed_checkpoints(),
        }
    }

    /// Says one line of the checkpoint thread's on the operator stream.
    ///
    /// It goes with its class word — the classed door, so no line of this
    /// section can go out without one — and, under the test seam, is kept
    /// for the suite.
    fn say_checkpoint_line(&self, class: Class, text: String) {
        #[cfg(any(test, feature = "test-hooks"))]
        self.checkpointer.lines.lock().push(format!("{class}: {text}"));
        notice::emit(class, text);
    }

    /// Runs the checkpoint the cadence calls for, on the calling thread.
    ///
    /// It is the checkpoint thread's act on the due flag, off the write
    /// path's guard: `Kernel::checkpoint`, which clears the due flag first
    /// and takes its own mutex and no applier lock, so every write proceeds
    /// beside it, timed by this thread's own `Instant` around the call,
    /// under no lock. On a landing: the newest checkpoint's header read
    /// once, the landing's re-reads taken from it
    /// ([`Daemon::re_read_after_a_landing`]), and one line — [`LandingLine`],
    /// the position and the size, the run's duration, the journal bytes the
    /// kernel reclaimed and the checkpoint files its retention removed, each
    /// by name and length (`Kernel::last_reclaimed_bytes`,
    /// `Kernel::last_removed_checkpoints`, read after the `Ok`), what the
    /// re-reads answered — both bounds in force, the volume's free space as
    /// the media floor reads it (the gate's one door, so the floor's refusal
    /// and this line never disagree), the resident set, what the feed holds
    /// — and the inline count where it moved since the
    /// thread last said it. On a failure: one line per attempt —
    /// [`FailureLine`]: the run's duration, the head's position when the run
    /// began as an ordering, the cause (a full volume in the operator's
    /// words), and the trailer the cause earns; and where the kernel answers
    /// that a base landed before the step after its rename failed
    /// (`CheckpointError::Landed`), the newest header is read after the call
    /// — the base is on disk — the landing's re-reads are taken off it, and
    /// the line names the landed base, its size, which step failed and what
    /// the re-reads moved (the reclaim figures it does not carry: the kernel
    /// stores them for a call that landed whole alone). The kernel removes
    /// its own temp file, best-effort, before answering a failure that landed
    /// nothing.
    pub(crate) fn service_the_checkpoint(&self) {
        let kernel = self.engine.kernel();
        let at = kernel.current_seq();
        let began = Instant::now();
        let outcome = kernel.checkpoint();
        let duration_ms = began.elapsed().as_millis();
        match outcome {
            Ok(landed) => {
                let newest = kernel.newest_checkpoint();
                let reclaimed = self.reclaimed_by_the_last_landing();
                let after = self.re_read_after_a_landing(newest.as_ref().map(|h| h.len));
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
                        reclaimed,
                        after,
                        inline,
                    }
                };
                self.say_checkpoint_line(Class::Landing, line.to_string());
            }
            Err(e) => {
                let line = match &e {
                    CheckpointError::Landed { step, cause } => {
                        let newest = kernel.newest_checkpoint();
                        let after = self.re_read_after_a_landing(newest.as_ref().map(|h| h.len));
                        self.checkpointer.looked.lock().newest = newest.as_ref().map(|h| h.seq);
                        FailureLine::Landed {
                            at,
                            duration_ms,
                            base: newest.map(LandedBase::from),
                            step: *step,
                            cause,
                            after: Box::new(after),
                        }
                    }
                    CheckpointError::Io(_)
                    | CheckpointError::Serialize(_)
                    | CheckpointError::Poisoned => {
                        FailureLine::Unlanded { at, duration_ms, error: &e }
                    }
                };
                self.say_checkpoint_line(Class::Failure, line.to_string());
            }
        }
    }

    /// Follows the backstop on a wake (m13; §4 rows 25 and 35).
    ///
    /// It is what the checkpoint thread runs on every wake after the flag's
    /// arm, so a wake with no flag is answered: where the kernel's count of
    /// checkpoints run inline on a committing thread
    /// (`Kernel::inline_checkpoints`) moved past the count the thread last
    /// said, the newest checkpoint is read once and, where it moved since
    /// the thread last looked, the landing's re-reads are taken off it — the
    /// same function the landing arm runs — and the backstop's line is said
    /// ([`BackstopLine`]): the runs since the last line, the position they
    /// are counted from, and of the last of them the commit that ran it, how
    /// long it held every write, and whether it landed or how it failed
    /// (`Kernel::last_inline_checkpoint`); and, where the re-reads were
    /// taken, the newest base and what they moved, with what the landing
    /// reclaimed where the last inline run landed that base whole — the one
    /// line that says the floor or the feed's fence moved under a backstop.
    /// Said once for each movement of the count and never otherwise; a count
    /// line 25 has just carried is one that moved not. The resident set is
    /// read at every such wake, its figure on the line where the re-reads
    /// carry it.
    pub(crate) fn follow_the_backstop(&self) {
        let kernel = self.engine.kernel();
        let runs = kernel.inline_checkpoints();
        let line = {
            let mut looked = self.checkpointer.looked.lock();
            if runs == looked.inline_said {
                return;
            }
            let last = kernel.last_inline_checkpoint().map(LastInlineRun::from);
            let newest = kernel.newest_checkpoint();
            let newest_seq = newest.as_ref().map(|h| h.seq);
            let moved = if newest_seq == looked.newest {
                None
            } else {
                // The reclaim figures are the newest base's only where the
                // last inline run landed it whole: a run that landed a base
                // and then failed stores none, and leaves the previous
                // landing's standing.
                let whole = matches!(
                    &last,
                    Some(LastInlineRun { outcome: Ok(at), .. }) if Some(*at) == newest_seq
                );
                let reclaimed = whole.then(|| self.reclaimed_by_the_last_landing());
                let after = self.re_read_after_a_landing(newest.as_ref().map(|h| h.len));
                looked.newest = newest_seq;
                Some(NewestLanded { base: newest.map(LandedBase::from), reclaimed, after })
            };
            let line = BackstopLine {
                runs: runs.saturating_sub(looked.inline_said),
                since: looked.since,
                last,
                newest: moved,
            };
            looked.inline_said = runs;
            if let Some(seq) = newest_seq {
                looked.since = seq;
            }
            line
        };
        if line.newest.is_none() {
            self.resident.read();
        }
        self.say_checkpoint_line(Class::Landing, line.to_string());
    }
}

/// Line 25, the landing (`operations.md` §1.1 row 25).
///
/// It is rendered in the operator stream's words from the figures the thread
/// read: a pure value, so the unit suite pins the words by `to_string()` at
/// fixed figures. The class word is the emitter's (`Class::Landing`); every
/// dimension is spelt the stream's one way — a position as `position N`, a
/// file by its name, a duration in milliseconds.
struct LandingLine {
    /// The position the checkpoint embodies — `Kernel::checkpoint`'s answer.
    position: Seq,
    /// The file's length as the newest header claims it.
    ///
    /// `None` where the header did not answer — "size unread".
    bytes: Option<u64>,
    /// The run's duration, whole milliseconds, the thread's own `Instant`.
    duration_ms: u128,
    /// What the landing reclaimed, as the kernel's figures say it.
    ///
    /// The call landed whole, so the kernel stored them for it.
    reclaimed: Reclaimed,
    /// What the landing moved: the thread's re-reads off its base.
    after: AfterLanding,
    /// The inline count where it moved since the thread last said it.
    ///
    /// It comes with the position it is counted from; `None` where it did
    /// not move, and the clause is absent.
    inline: Option<InlineRuns>,
}

/// What a landing reclaimed: the kernel's figures for a call that landed whole.
///
/// It renders `{bytes} journal bytes reclaimed`, or `nothing reclaimed` at
/// zero — every landing's figure where the start keeps the journal whole
/// (`--reclaim-journal never`) — then each checkpoint file retention removed
/// — `; checkpoint.{n} removed ({bytes} bytes)`, the rest joined by `, ` —
/// as line 25 and the backstop's line carry it (`operations.md` §1.1 row
/// 25; m13). The kernel stores the figures at the end of a call that landed
/// whole and at no other (`Kernel::last_reclaimed_bytes`), so a line after a
/// base landed and a later step failed carries none.
struct Reclaimed {
    /// The journal bytes reclaimed; zero is "nothing reclaimed".
    bytes: u64,
    /// The checkpoint files the landing's retention removed, oldest first.
    ///
    /// Each is named by its position and its length in bytes
    /// (`Kernel::last_removed_checkpoints`): the oldest base past the
    /// retained count the start runs under (`StartOptions`'s
    /// `retain_checkpoints`, two by default), and any base the open passed
    /// over — the file the open's own `SKIPPED` warning named, which this
    /// clause names by the same `checkpoint.{n}`. Empty where retention
    /// removed none, and the clause is absent.
    removed: Vec<(Seq, u64)>,
}

impl fmt::Display for Reclaimed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.bytes {
            0 => f.write_str("nothing reclaimed")?,
            bytes => write!(f, "{bytes} journal bytes reclaimed")?,
        }
        // Each file by its own name — never `Base`'s, whose `genesis` would
        // misname a checkpoint written at position 0.
        for (i, (seq, len)) in self.removed.iter().enumerate() {
            f.write_str(if i == 0 { "; " } else { ", " })?;
            write!(f, "checkpoint.{} removed ({len} bytes)", seq.0)?;
        }
        Ok(())
    }
}

/// What a landing moved, as every line that follows one says it.
///
/// The figures are the thread's re-reads off the newest base
/// ([`Daemon::re_read_after_a_landing`]): the cadence's byte bound and the
/// media floor in force, the volume's free space as the floor reads it, a
/// reading of the resident set, the write guard's takes since the line
/// before ([`GuardTakes`]), what the change feed holds
/// (`Commits::feed_figures`: the first position its files hold a line for
/// — the `floor` a `410 history_reclaimed` on `/changes` names, `1` on a
/// board that never compacted — `commits.log`'s size, the operator's sizing
/// figure for files kept whole from genesis, and the resident window's
/// count beside the most it has held this uptime, so a window that outgrew
/// its span is told from one that holds it) — and what the never compacted
/// `feed-attest.log` holds, on disk and resident
/// (`Commits::attest_store_figures`): the file grows with every attested
/// commit, and its slots resident with the window, so a resident set that
/// climbs is told apart. Line 25 carries them, and so do the backstop's
/// line where its wake took the re-reads and a failure after a base landed
/// (`operations.md` §1.1 rows 25 and 26; m13; §6), so no figure a landing
/// moves — the floor a deposit is refused at — moves with no line naming
/// it. It renders `the cadence's byte bound {b}, the media floor in force
/// {F}, the volume's free space {f}; {resident}; {guard}; the change feed
/// {holds every line from position {p} | holds no line yet}: commits.log
/// {bytes} bytes, {n} entries resident, the most this uptime {m};
/// feed-attest.log {bytes} bytes, {s} slots resident` — `unread` for the
/// free space where the host refused the read, its cause said by the
/// floor's own line and the standing line; `size unread` for the attest
/// store's bytes where the file's metadata did not answer.
struct AfterLanding {
    /// The cadence's byte bound in force after the re-read.
    bytes_bound: u64,
    /// The media floor in force after the re-read.
    floor: u64,
    /// The volume's free space as the media floor reads it.
    ///
    /// It is `None` where the host refused the read
    /// (`MediaGate::free_space`), which the line says as `unread`.
    free_space: Option<u64>,
    /// A reading of the resident set, beside the uptime's largest.
    resident: ResidentRead,
    /// The write guard's takes since the line before, and its waits.
    guard: GuardTakes,
    /// What the change feed holds: its first position, its size, its window.
    feed: FeedFigures,
    /// What `feed-attest.log` holds: its size and the slots resident.
    attest: AttestStoreFigures,
}

impl fmt::Display for AfterLanding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "the cadence's byte bound {}, the media floor in force {}, the volume's free space ",
            self.bytes_bound, self.floor
        )?;
        match self.free_space {
            Some(free_space) => write!(f, "{free_space}")?,
            None => f.write_str("unread")?,
        }
        write!(f, "; {}; {}; the change feed ", self.resident, self.guard)?;
        match self.feed.first {
            Some(first) => write!(f, "holds every line from position {first}")?,
            None => f.write_str("holds no line yet")?,
        }
        write!(
            f,
            ": commits.log {} bytes, {} entries resident, the most this uptime {}",
            self.feed.bytes, self.feed.resident, self.feed.resident_most
        )?;
        f.write_str("; feed-attest.log ")?;
        match self.attest.bytes {
            Some(bytes) => write!(f, "{bytes} bytes")?,
            None => f.write_str("size unread")?,
        }
        write!(f, ", {} slots resident", self.attest.slots)
    }
}

/// The write guard's takes since the line before, as a landing says them.
///
/// It renders `the write guard taken {t} times since position {p}, {w} of
/// them after a wait`: the takes of the write-serialization guard
/// (`Commits::serial_figures`) since the last line that carried the clause,
/// `{p}` the head position then — the open's head before any such line — and
/// how many of those takes found another writer holding the guard. The
/// share that waited is how busy the serialization point is, so a share that
/// climbs from landing to landing is the write path nearing its limit before
/// the write pool refuses `write_busy` (`operations.md` §1.1 row 25). Counts
/// of writes, never of a reader.
struct GuardTakes {
    /// The takes and the waits since `since`.
    figures: SerialFigures,
    /// The head position the count runs from.
    since: Seq,
}

impl fmt::Display for GuardTakes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "the write guard taken {} times since position {}, {} of them after a wait",
            self.figures.takes, self.since, self.figures.waits
        )
    }
}

/// The inline clause's two figures, as line 25 carries them.
///
/// The backstop line carries the same two in fields of its own.
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
        write!(f, ") in {} ms; {}; {}", self.duration_ms, self.reclaimed, self.after)?;
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

/// Line 26, the failure (row 26; §4 row 2).
///
/// It is rendered in the operator stream's words from what the kernel
/// answered: a pure value the unit suite pins by `to_string()` at each
/// cause, in one of two arms, since a run that landed a base moved what a
/// landing moves and one that landed none moved nothing. A run that landed
/// no base opens on the run's duration and the head's position when it
/// began, worded as the ordering it is — "checkpoint FAILED after {d} ms
/// (the head stood at position {p} when the run began)". A run whose base
/// LANDED before the step after its rename failed (`CheckpointError::Landed`)
/// opens on the base, its size and the run's duration — "a checkpoint landed
/// at position {n} ({bytes} bytes) in {d} ms but {step} failed" — the step
/// in the daemon's three words (the directory's sync, retention, the
/// journal's reclamation), chosen by `LandedStep`'s arm and never the
/// kernel's `Display`, then what the thread's re-reads off the base moved
/// ([`AfterLanding`]); the reclaim figures it does not carry, the kernel
/// storing none for a call that failed. The cause: a full volume
/// (`StorageFull`) in the operator's words beside the OS's text, in either
/// arm; every other cause its own `Display`. The trailer is keyed to the
/// cause: an I/O cause retries at the cadence's next crossing, a poisoned
/// kernel takes no checkpoint until a restart, a world that will not
/// serialize refuses the same way until the build fixes it. The class word
/// is the emitter's (`Class::Failure`).
enum FailureLine<'a> {
    /// A run that landed no base.
    ///
    /// `error` is the kernel's answer — `Io`, `Serialize` or `Poisoned`;
    /// [`FailureLine::Landed`] is the `Landed` error's own arm.
    Unlanded {
        /// `Kernel::current_seq`, read before the call.
        ///
        /// An ordering, since the checkpoint loads its own root under its
        /// mutex.
        at: Seq,
        /// The run's duration, whole milliseconds, the thread's own `Instant`.
        duration_ms: u128,
        /// What the kernel answered.
        error: &'a CheckpointError,
    },
    /// A run whose base landed before the step after its rename failed.
    Landed {
        /// `Kernel::current_seq`, read before the call.
        ///
        /// It is the floor of the landed base's position where its header
        /// did not answer.
        at: Seq,
        /// The run's duration, whole milliseconds, the thread's own `Instant`.
        duration_ms: u128,
        /// The base as the newest header claims it, read after the call.
        ///
        /// `None` where the header did not answer.
        base: Option<LandedBase>,
        /// The step that failed after the rename.
        step: LandedStep,
        /// The step's cause.
        cause: &'a std::io::Error,
        /// What the thread's re-reads off the landed base moved.
        ///
        /// Boxed: the re-reads' figures outweigh the other arm's by far,
        /// and the line is rendered once and dropped.
        after: Box<AfterLanding>,
    },
}

/// The trailer of a failure whose next attempt is the cadence's next crossing.
const RETRIED_AT_THE_NEXT_CROSSING: &str =
    "; the journal is not reclaimed and holds every commit; the next attempt is at the \
     cadence's next crossing";

impl fmt::Display for FailureLine<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FailureLine::Landed { at, duration_ms, base, step, cause, after } => {
                match base {
                    Some(base) => write!(
                        f,
                        "a checkpoint landed at position {} ({} bytes)",
                        base.position, base.bytes
                    )?,
                    None => write!(
                        f,
                        "a checkpoint landed at or above position {at} (its header unread)"
                    )?,
                }
                let step = match step {
                    LandedStep::DirectorySync => "the directory's sync",
                    LandedStep::Retention => "retention",
                    LandedStep::Reclamation => "the journal's reclamation",
                };
                write!(
                    f,
                    " in {duration_ms} ms but {step} failed: {}; {after}",
                    VolumeWords(cause)
                )?;
                f.write_str(RETRIED_AT_THE_NEXT_CROSSING)
            }
            FailureLine::Unlanded { at, duration_ms, error } => {
                write!(
                    f,
                    "checkpoint FAILED after {duration_ms} ms (the head stood at position {at} \
                     when the run began): "
                )?;
                match error {
                    CheckpointError::Io(io) | CheckpointError::Landed { cause: io, .. } => {
                        write!(f, "{}", VolumeWords(io))?
                    }
                    other @ (CheckpointError::Serialize(_) | CheckpointError::Poisoned) => {
                        write!(f, "{other}")?
                    }
                }
                // The trailer, keyed to the cause: what still serves and when
                // the next attempt comes — a promise of a crossing only where
                // one can.
                f.write_str(match error {
                    CheckpointError::Io(_) | CheckpointError::Landed { .. } => {
                        RETRIED_AT_THE_NEXT_CROSSING
                    }
                    CheckpointError::Poisoned => {
                        "; no checkpoint is taken until a restart (the kernel's halt, said above)"
                    }
                    CheckpointError::Serialize(_) => {
                        "; every crossing refuses the same way until the world encodes: the \
                         build's to fix"
                    }
                })
            }
        }
    }
}

/// A base that landed, as its header claims it: its position and its length.
struct LandedBase {
    /// The position the base embodies.
    position: Seq,
    /// The file's length in bytes, as the header claims it.
    bytes: u64,
}

impl From<CheckpointHeader> for LandedBase {
    fn from(header: CheckpointHeader) -> LandedBase {
        LandedBase { position: header.seq, bytes: header.len }
    }
}

/// An I/O cause in the operator's words.
///
/// A full volume (`StorageFull`) is "the volume is full" with the OS's text
/// beside it — the one cause whose act, room freed on the volume, is the
/// operator's alone — and every other kind its own text.
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

/// The backstop's line (`operations.md` §1.1 m13).
///
/// It is rendered from the kernel's count and its record of the last inline
/// run: the checkpoints run inline on a writer since the position the count
/// is counted from (`Looked::since` — the newest checkpoint's position at
/// the thread's last landing or backstop line, the start point before any);
/// and of the last of them, the commit whose crossing ran it, by its
/// position — the one the write's own acknowledgement and the change feed
/// name it by — how long the run held every write, whole milliseconds (the
/// write path's serial guard spans the commit that runs it, so every other
/// writer waited it out: the one figure that tells a slow board's operator
/// the stall was a checkpoint's), and whether it landed and where, or how it
/// failed, in the kernel's rendered words. And where the wake found the
/// newest checkpoint moved and took the landing's re-reads off it, the base
/// and what they moved ([`NewestLanded`]): `; the newest checkpoint at
/// position {n} ({bytes} bytes): {reclaimed; }{after}` — the reclaim figures
/// where the last inline run landed that base whole — so a floor or a feed
/// fence a backstop moved is said where it moved. A pure value, pinned by
/// `to_string()`; emitted under `Class::Landing`.
struct BackstopLine {
    runs: u64,
    since: Seq,
    /// `Kernel::last_inline_checkpoint`, read after the count moved.
    ///
    /// Never `None` then, since the kernel stores a run's record before it
    /// moves the count; rendered `unread` should the type's absence ever
    /// arise, rather than spelled as a landing.
    last: Option<LastInlineRun>,
    /// The newest checkpoint and what its landing moved, where it moved.
    ///
    /// `None` where the newest checkpoint is the one the thread last looked
    /// at — a wake that took no re-read — and the clause is absent.
    newest: Option<NewestLanded>,
}

/// The newest checkpoint as a backstop's wake found it moved.
///
/// It is the base as its header claims it — `None` where the header did not
/// answer — what the landing reclaimed, where the last inline run landed
/// that base whole, and what the thread's re-reads off it moved.
struct NewestLanded {
    base: Option<LandedBase>,
    reclaimed: Option<Reclaimed>,
    after: AfterLanding,
}

impl fmt::Display for NewestLanded {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.base {
            Some(base) => write!(
                f,
                "the newest checkpoint at position {} ({} bytes): ",
                base.position, base.bytes
            )?,
            None => f.write_str("the newest checkpoint's header unread: ")?,
        }
        if let Some(reclaimed) = &self.reclaimed {
            write!(f, "{reclaimed}; ")?;
        }
        write!(f, "{}", self.after)
    }
}

/// The last inline run as [`BackstopLine`] says it.
///
/// It is the kernel's record ([`InlineCheckpoint`], which only the kernel
/// makes) carried in the figures the line renders, so the line stays a pure
/// value the unit suite builds at fixed figures.
struct LastInlineRun {
    /// The commit whose crossing ran the checkpoint, by its position.
    after: Seq,
    /// How long the run held every write, whole milliseconds.
    held_ms: u128,
    /// Where it landed, or its failure in the kernel's rendered words.
    outcome: Result<Seq, String>,
}

impl From<InlineCheckpoint> for LastInlineRun {
    fn from(run: InlineCheckpoint) -> LastInlineRun {
        LastInlineRun { after: run.after, held_ms: run.held.as_millis(), outcome: run.outcome }
    }
}

impl fmt::Display for BackstopLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "checkpoint: the cadence outran the checkpoint thread; {} checkpoints ran inline on \
             a writer since position {}, the last ",
            self.runs, self.since
        )?;
        match &self.last {
            None => f.write_str("unread")?,
            Some(last) => {
                write!(
                    f,
                    "run by the commit at position {}, holding every write {} ms, ",
                    last.after, last.held_ms
                )?;
                match &last.outcome {
                    Ok(landed) => write!(f, "landed at position {landed}")?,
                    Err(cause) => write!(f, "FAILED: {cause}")?,
                }
            }
        }
        match &self.newest {
            Some(newest) => write!(f, "; {newest}"),
            None => Ok(()),
        }
    }
}

/// Renders the startup warnings from what the engine's open found.
///
/// AUTH-2.86's two startup warnings are one line per retained checkpoint
/// that was not a start point, naming it, why, and the start point the world
/// was resolved from; and one line where the start point itself carried no
/// identity slice and resolved to the empty table (AUTH-2.83), naming that
/// checkpoint and the empty resolution — the operator's one tell that a
/// build which wrote no slice ran on this board. After them comes one line
/// where the open's scan read corrupt runs below the start point and passed
/// them over (`Recovery::runs_passed_over`): the start point embodies every
/// position they hold, so the open answered around them, and no other line
/// of an open that succeeds says so — while a history read from an older
/// base, and the open that falls back past this start point the day its
/// checkpoint fails to load, meet the first of them and refuse. It is said
/// with how many and the kernel's account of the first
/// (`Recovery::first_run_passed_over`): its files and bytes, the position it
/// holds none above, and the act that clears it. Nothing where there is
/// nothing to say, which is every open on a board whose retained
/// checkpoints all load and carry the slice and whose journal holds no run.
/// The downgrade window's own commits read `key: null` on `/changes`
/// (AUTH-1.52), which needs no line here.
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
    if let Some(first) = &recovery.first_run_passed_over {
        lines.push(match recovery.runs_passed_over {
            1 => format!(
                "a corrupt run lies below the start point {start} and was PASSED OVER — {first}"
            ),
            runs => format!(
                "{runs} corrupt runs lie below the start point {start} and were PASSED OVER — \
                 the first: {first}"
            ),
        });
    }
    lines
}

/// A base as every line of the open names it.
///
/// It is `genesis` where the world was folded from nothing — `Seq(0)`, no
/// checkpoint file — and `checkpoint.{n}` for a retained checkpoint's
/// position, the file's own name. One rendering, so the recovery's landing
/// and the two warnings above it spell the start point one way and a reader
/// joins them on it.
struct Base(Seq);

impl fmt::Display for Base {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Seq(0) => f.write_str("genesis"),
            Seq(seq) => write!(f, "checkpoint.{seq}"),
        }
    }
}

/// The version line, the open's first (`operations.md` §3.4 step 6's gap).
///
/// The gap reads "no line names the binary's version or the formats it
/// reads at start; the stamp is said only on refusal". The line is
/// `version {v} ({commit}); this build reads journal format {SKJ4},
/// checkpoint format {SKC4} and world format {0x…}; built with {features}`
/// — the build's version and commit as `skepd --version` names them
/// (`CARGO_PKG_VERSION`, the workspace's one, which every build between two
/// releases shares, and the commit the build named through `SKEP_GIT_SHA`,
/// `unknown` where it named none), the three format stamps this build opens
/// under, each from its constant and never a literal here — the kernel's
/// journal and checkpoint stamps ([`JOURNAL_FORMAT`], [`CHECKPOINT_FORMAT`])
/// as the kernel's own refusal spells a stamp, four ASCII bytes, and the
/// engine's World stamp ([`WORLD_FORMAT`]) as the engine's refusal renders
/// it, `{:#018x}` — and the optional features it was built with
/// ([`built_with`]). A build's routes are its features': `observe` serves
/// `GET /dump` to every guest, which the hosted image is built without
/// (`operations.md` §3.9 item 8), and the configuration register leaves
/// features to whoever builds (its §4), so this clause is where a running
/// board says which build serves it. Said before [`DataDirLine`] and so
/// before anything is read from the directory: an open refused at a stamp
/// has, above its refusal, the line that says which stamps this build
/// reads, and an operator reading a board's stream after an upgrade reads
/// which binary opened it, its commit telling two builds of one version
/// apart. A pure value the unit suite pins by `to_string()`; emitted under
/// `Class::Open` through [`say_open_line`].
struct VersionLine;

impl fmt::Display for VersionLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "version {} ({}); this build reads journal format {}, checkpoint format {} and world \
             format {:#018x}; built with {}",
            env!("CARGO_PKG_VERSION"),
            option_env!("SKEP_GIT_SHA").unwrap_or("unknown"),
            JOURNAL_FORMAT.escape_ascii(),
            CHECKPOINT_FORMAT.escape_ascii(),
            WORLD_FORMAT,
            built_with()
        )
    }
}

/// Returns the optional features this binary was built with, as words.
///
/// They are `observe` (the `GET /dump` route), `client` (the guest reader
/// at `GET /`) and `test-hooks` (the test seams, which a binary you run
/// never carries), in `Cargo.toml`'s order and joined by `, `, or `no
/// optional feature` where the build carries none — the hosted image's.
fn built_with() -> String {
    let built: Vec<&str> = [
        (cfg!(feature = "observe"), "observe"),
        (cfg!(feature = "client"), "client"),
        (cfg!(feature = "test-hooks"), "test-hooks"),
    ]
    .into_iter()
    .filter_map(|(on, feature)| on.then_some(feature))
    .collect();
    if built.is_empty() {
        "no optional feature".to_string()
    } else {
        built.join(", ")
    }
}

/// The first of the open's two m7 lines (`operations.md` §3.1 step 3).
///
/// It comes after [`VersionLine`]: the data directory, as the operator
/// named it — `data-dir {path}` — said before the seeding check and the
/// engine's open, so the one line that names the directory stands on the
/// stream before anything is read from it. A pure value the unit suite pins
/// by `to_string()`; emitted under `Class::Open` through [`say_open_line`].
struct DataDirLine<'a>(&'a Path);

impl fmt::Display for DataDirLine<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "data-dir {}", self.0.display())
    }
}

/// The recovery's landing (m7), in the operator stream's words.
///
/// It reads `recovered from {checkpoint.n | genesis} to position {p}, {k}
/// commits replayed, in {d} ms`, rendered from the engine's own account of
/// its open: the base it loaded ([`Base`]'s words, the ones the two warnings
/// name the start point by); the committed head it came back at, every write
/// acknowledged at or below which stands — the position the tail cut, where
/// one was cut, lies past, and the one a mirror resumes against, which no
/// other line of the stream names and `{k}` cannot give, since it counts
/// transactions and not positions; the commits it replayed above that base
/// (`Recovery::replayed`: transactions, never the records they carry; `0`
/// where the base was the committed head, a fresh board's genesis included)
/// and the engine's open's duration, whole milliseconds, the daemon's own
/// `Instant` around the call. A pure value the unit suite pins by
/// `to_string()`; emitted under `Class::Open` through [`say_open_line`].
struct RecoveredLine {
    start_point: Seq,
    /// The committed head the open came back at (`Kernel::current_seq`).
    head: Seq,
    replayed: u64,
    duration_ms: u128,
}

impl RecoveredLine {
    /// Returns the line from the engine's account, where it gave one.
    ///
    /// `head` is the kernel's committed head as the open left it. An engine
    /// that answers no account loads nothing — `Durability::InMemory`, which
    /// no daemon opens under: every daemon's open is journaled — and is said
    /// as a genesis that replayed nothing, which is what the open's sizing
    /// reads of the same absence.
    fn of(recovery: Option<&Recovery>, head: Seq, duration_ms: u128) -> RecoveredLine {
        RecoveredLine {
            start_point: recovery.map_or(Seq(0), |r| r.start_point),
            head,
            replayed: recovery.map_or(0, |r| r.replayed),
            duration_ms,
        }
    }
}

impl fmt::Display for RecoveredLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "recovered from {} to position {}, {} commits replayed, in {} ms",
            Base(self.start_point),
            self.head,
            self.replayed,
            self.duration_ms
        )
    }
}

/// The open's beginning, said after the recovery's landing.
///
/// It is said where the engine's account says no journal stood in the
/// directory (`Recovery::began`): no segment and no checkpoint, so the open
/// began a board at genesis rather than recovering one. The landing reads
/// `recovered from genesis` either way; this line is what tells them apart
/// — the expected line on a fresh board's first start, and on a board that
/// had a journal the tell that the directory opened is not where it lives:
/// a volume not mounted over its mount point, a mistyped `--data-dir`. A
/// pure value the unit suite pins by `to_string()`; emitted under
/// `Class::Open` through [`say_open_line`].
struct BeganLine;

impl fmt::Display for BeganLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(
            "no journal stood in the data directory: this open began a new board at genesis — on \
             a board that had one, the directory named above is not where it lives (a volume not \
             mounted over it, a mistyped --data-dir): stop the daemon before a write lands on the \
             new board",
        )
    }
}

/// The open's beginning under `--create`: the first start's landing.
///
/// It is [`BeganLine`]'s fact under the word the binary begins a board
/// under ([`StartOptions`]'s `create`): no tell of a wrong directory, since
/// the start asked for a board here. A pure value the unit suite pins by
/// `to_string()`; emitted under `Class::Open` through [`say_open_line`].
struct BeganUnderCreateLine;

impl fmt::Display for BeganUnderCreateLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(
            "no journal stood in the data directory: this open began a new board at genesis, as \
             --create asked; start it again without --create",
        )
    }
}

/// The kept files beside the journal and the logs, said at an open.
///
/// They are the `*.cut-*` files a standing state is made of
/// (`operations.md` §1.1 m11; `tools::kept_files`): the journal's
/// `seg-{n}.wal.cut-{byte}`, the change feed's `{file}.cut-{byte}` and the
/// blob store's `blobs/{log}.cut-{byte}`, each holding bytes an open cut as
/// damage and kept — this open's among them, each already said by its own
/// line — listed at every open while any stands, and by the standing line
/// hourly, until the operator removes them. The words: `kept files beside
/// the journal and the logs: {n} — {names}; each holds bytes an open cut as
/// damage: copy them off the volume, and remove them once the writes they
/// held are accounted for`. A pure value the unit suite pins by
/// `to_string()`; emitted under `Class::Open` through [`say_open_line`].
struct KeptFilesLine<'a> {
    kept: &'a [String],
}

impl fmt::Display for KeptFilesLine<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "kept files beside the journal and the logs: {} — {}; each holds bytes an open cut \
             as damage: copy them off the volume, and remove them once the writes they held are \
             accounted for",
            self.kept.len(),
            self.kept.join(", ")
        )
    }
}

/// The pruner's halt for the uptime where the lease log's open found damage.
///
/// It is `operations.md` §4 row 19's consequence said once at the open: the
/// leases the open lost hold no file in memory, so the unlink pass would
/// take the files their depositors hold as unreferenced. The words:
/// `pruner: the unlink pass is halted for this uptime — {reason}: a lease
/// the open lost holds no file in memory, so the pass would unlink files
/// their depositors hold; expired partials are still removed and the logs
/// compacted at each pass; the next start, its open reading the log whole,
/// lifts it`. The pass's own line carries the halt hourly (§1.1 row 34). A
/// pure value the unit suite pins by `to_string()`; emitted under
/// `Class::Failure`.
struct PrunerHaltedByLeaseDamageLine<'a> {
    reason: &'a str,
}

impl fmt::Display for PrunerHaltedByLeaseDamageLine<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "pruner: the unlink pass is halted for this uptime — {}: a lease the open lost holds \
             no file in memory, so the pass would unlink files their depositors hold; expired \
             partials are still removed and the logs compacted at each pass; the next start, \
             its open reading the log whole, lifts it",
            self.reason
        )
    }
}

/// A blob log's open, as the daemon says it (`operations.md` §4 row 19).
///
/// The store answers what its open found of each log and says none of it
/// (`Store::opened`, `LogRead`); these are the lines, one per cause, in the
/// grammar's classes. A torn last line — a crash's or a kill's, its newline
/// unwritten, never answered over — is the open's own landing: `{log}: a
/// torn last line cut ({n} bytes), a crash's or a kill's, never answered
/// over; every acknowledged {each} stands`. A damaged cut — the first
/// untrusted line whole, which no crash leaves — is a failure naming the
/// kept file: `{log}: trust ends at byte {at} of {len}; the {n} bytes after
/// it are cut, kept in {kept}: a whole line that does not read, which no
/// crash leaves — damage to {each}s the store answered over, {m} whole lines
/// after it cut with it; each lost {each} reads as none, cured by a re-PUT`.
/// Lines read as no record are a failure: `{log}: {n} lines read as no
/// {each}: lines another build wrote, or damaged ones, removed by the open's
/// compaction; each reads as none, cured by a re-PUT`. A log absent beside a
/// standing store — one whose designation directory or other log stood
/// before the open ([`BlobLogLines::store_stood`]) — is one: `{log} was
/// absent beside a standing store, and is begun empty: every {each} it held
/// reads as none, cured by a re-PUT`. The
/// leases' failures are the pruner's halt's reasons
/// ([`BlobLogLines::damage`]). A pure value the unit suite pins.
struct BlobLogLines<'a> {
    read: &'a LogRead,
    /// Whether a store stood before the open: its designation directory,
    /// the first thing a deposit makes, or either log stood under `blobs/`.
    ///
    /// A log absent beside one is a loss — a copy that stopped short, a log
    /// removed; beside a root that held no deposit and no log, a first
    /// start's, which the open begins and says nothing of.
    store_stood: bool,
    /// What a line of the log is: `lease` or `upload`.
    each: &'static str,
}

impl BlobLogLines<'_> {
    /// Returns the lines to say, each with its class, in the order they
    /// stand.
    fn lines(&self) -> Vec<(Class, String)> {
        let name = &self.read.name;
        let each = self.each;
        let mut lines = Vec::new();
        if let Some(cut) = self.read.cut {
            if cut.damage() {
                let kept = self.read.kept.as_deref().unwrap_or("no file");
                lines.push((
                    Class::Failure,
                    format!(
                        "{name}: trust ends at byte {} of {}; the {} bytes after it are cut, kept \
                         in {kept}: a whole line that does not read, which no crash leaves — \
                         damage to {each}s the store answered over, {} whole lines after it cut \
                         with it; each lost {each} reads as none, cured by a re-PUT",
                        cut.at,
                        cut.len,
                        cut.bytes(),
                        cut.lines_after
                    ),
                ));
            } else {
                lines.push((
                    Class::Open,
                    format!(
                        "{name}: a torn last line cut ({} bytes), a crash's or a kill's, never \
                         answered over; every acknowledged {each} stands",
                        cut.bytes()
                    ),
                ));
            }
        }
        if self.read.unread > 0 {
            lines.push((
                Class::Failure,
                format!(
                    "{name}: {} lines read as no {each}: lines another build wrote, or damaged \
                     ones, removed by the open's compaction; each reads as none, cured by a \
                     re-PUT",
                    self.read.unread
                ),
            ));
        }
        if self.read.absent && self.store_stood {
            lines.push((
                Class::Failure,
                format!(
                    "{name} was absent beside a standing store, and is begun empty: every {each} \
                     it held reads as none, cured by a re-PUT"
                ),
            ));
        }
        lines
    }

    /// Returns the damage the open found, as the pruner's halt names it.
    ///
    /// It is the first of a damaged cut, lines read as no record and a log
    /// absent beside a standing store; `None` where the log read whole or
    /// lost a torn line alone.
    fn damage(&self) -> Option<String> {
        let name = &self.read.name;
        if let Some(cut) = self.read.cut.filter(|cut| cut.damage()) {
            let kept = self.read.kept.as_deref().unwrap_or("no file");
            return Some(format!(
                "{name}'s open cut a damaged line and the {} whole lines after it, kept in {kept}",
                cut.lines_after
            ));
        }
        if self.read.unread > 0 {
            return Some(format!(
                "{name}'s open read {} lines as no {}",
                self.read.unread, self.each
            ));
        }
        if self.read.absent && self.store_stood {
            return Some(format!("{name} was absent beside a standing store"));
        }
        None
    }
}

/// The tail cut (`operations.md` §1.1 m3; §4 row 8).
///
/// It is rendered in the operator stream's words from the engine's account
/// of its open: the bytes the open took off the journal above its last
/// committed marker (`Recovery::tail_cut`), the file and the byte the cut
/// began at (`Recovery::tail_cut_from`), the position it lies past — the
/// committed head the open left, every position at or below which stands —
/// and, of the frames among the cut bytes, the intact ones no torn write
/// leaves (`Recovery::tail_cut_intact`). Two arms, since the two say
/// opposite things of the acknowledged writes:
///
/// * a crash's tail — nothing kept: a write caught before its commit was
///   durable and so never acknowledged, which every open cuts of its own
///   accord: `Class::Open`;
/// * a damaged tail, cut under `--cut-damaged-tail` and kept beside the
///   journal first (`Recovery::tail_cut_kept`) — intact frames among its
///   bytes, a commit marker whose records failed their check or a frame no
///   writer of this format writes, the signature of rot in or a rewrite of
///   the journal's last transaction; or no frame of it intact and more of
///   it than one append leaves, decay over the trailing bytes — where the
///   cut may have taken a write this daemon acknowledged: `Class::Failure`,
///   naming which — the position an intact marker in the cut claimed
///   (`Recovery::tail_cut_claimed`), the one that write's own acknowledgement
///   and the change feed named it by, where the claim lies above the head;
///   else a position above the head, unnamed — where the bytes still are,
///   the kept files, which no open reads, moves or removes; what the order
///   does next — the positions up to the claim left a gap and the next
///   write taking the one after it (`Kernel::order_floor`), so a client
///   holding that acknowledgement is answered a missing write and never
///   another's — and the act. A tail the open refused never reaches here.
///
/// A pure value the unit suite pins by `to_string()` and
/// [`TailCutLine::class`].
struct TailCutLine {
    bytes: u64,
    intact: u64,
    /// The file the cut began in, by its name, and the byte of it.
    from: Option<(String, u64)>,
    /// The greatest position an intact marker in the cut claimed.
    claimed: Option<Seq>,
    /// The committed head the open left: the cut lies past it.
    head: Seq,
    /// The order's floor: the position the next write takes the one after.
    floor: Seq,
    /// The files in the data directory the cut bytes were kept in, by name.
    kept: Vec<String>,
}

impl TailCutLine {
    /// Returns the line from the engine's account, the head and the floor.
    ///
    /// The head is read before anything is served, so it is the recovered
    /// committed head; the floor is the kernel's (`Kernel::order_floor`),
    /// the head save under an accepted cut whose claim the kernel trusted.
    /// `None` where nothing was cut, which is every open after a clean
    /// close, and where the engine gave no account (`Durability::InMemory`,
    /// which no daemon opens under).
    fn of(recovery: Option<&Recovery>, head: Seq, floor: Seq) -> Option<TailCutLine> {
        let recovery = recovery?;
        (recovery.tail_cut > 0).then(|| TailCutLine {
            bytes: recovery.tail_cut,
            intact: recovery.tail_cut_intact,
            from: recovery.tail_cut_from.clone(),
            claimed: recovery.tail_cut_claimed,
            head,
            floor,
            kept: recovery.tail_cut_kept.clone(),
        })
    }

    /// Returns the class the line is said under.
    ///
    /// It is the report's own, `Class::Open`, for a crash's tail — nothing
    /// kept, no intact frame; `Class::Failure` for a damaged tail's accepted
    /// cut, which kept its bytes, where the cut may have taken an
    /// acknowledged write.
    fn class(&self) -> Class {
        if self.intact == 0 && self.kept.is_empty() {
            Class::Open
        } else {
            Class::Failure
        }
    }
}

impl fmt::Display for TailCutLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let TailCutLine { bytes, intact, from, claimed, head, floor, kept } = self;
        write!(f, "journal tail cut ({bytes} bytes, ")?;
        if let Some((segment, byte)) = from {
            write!(f, "beginning at byte {byte} of {segment}, ")?;
        }
        write!(f, "past position {head})")?;
        if self.class() == Class::Open {
            return f.write_str(
                ": the un-acked tail a crash or a kill left past the last committed marker — a \
                 write caught before its commit was durable, never acknowledged — removed by the \
                 open; every acknowledged write stands",
            );
        }
        if *intact > 0 {
            write!(
                f,
                ", {intact} of its frames intact on disk — a commit marker whose records failed \
                 their check, or a frame no writer of this format writes, the signature of rot \
                 in or a rewrite of the journal's last transaction rather than of a crash — cut \
                 under --cut-damaged-tail: a write this daemon acknowledged may be among the \
                 cut, "
            )?;
        } else {
            write!(
                f,
                ", no frame of it intact and more of it than one interrupted append leaves — \
                 decay over the journal's trailing bytes, or bytes no writer left, rather than a \
                 crash — cut under --cut-damaged-tail: a write this daemon acknowledged may be \
                 among the cut, "
            )?;
        }
        // The claimed position names the write only where it lies above the
        // head: a claim at or below it is a position that stands, and naming
        // it would send an operator after a write the journal still holds.
        match claimed {
            Some(claimed) if claimed > head => write!(
                f,
                "at position {claimed}, the position an intact commit marker in the cut claims"
            )?,
            _ => write!(f, "at a position above {head}")?,
        }
        // Where the bytes are: the files the kernel's open kept them in
        // before it cut one, which every accepted cut does.
        match kept.as_slice() {
            [] => {}
            [one] => write!(
                f,
                "; the open kept the cut bytes in {one}, beside the journal in the data \
                 directory, where no open reads, moves or removes it — copy it off the volume \
                 before you remove it"
            )?,
            [first @ .., last] => write!(
                f,
                "; the open kept the cut bytes in {} and {last}, beside the journal in the data \
                 directory, where no open reads, moves or removes them — copy them off the \
                 volume before you remove them",
                first.join(", ")
            )?,
        }
        // The order: the claimed positions are never handed out again where
        // the kernel trusted the claim, a gap the next write lands past.
        if floor > head {
            write!(
                f,
                "; positions ({head}, {floor}] are left a gap and the next write takes position \
                 {}, so a client holding that acknowledgement is answered a missing write, never \
                 another's",
                floor.0.saturating_add(1)
            )?;
        } else {
            write!(f, "; the next write takes position {}", head.0.saturating_add(1))?;
        }
        f.write_str("; check the volume and its device")
    }
}

/// Says one of the open's own lines, under the report's own class.
///
/// It is the one classed door for every line of the open's report said from
/// `open_under` under the report's own class — the version's, the
/// directory's, the recovery's landing, the beginning's, the stray
/// `checkpoint.tmp`'s, the tail cut's, the media gate's limits, the
/// volume's free space and the upload setting's, the nine the unit suite
/// pins as this door's callers —
/// each rendered here under `Class::Open`, the fixed-form lines as pure
/// values and the conditional or borrowed ones built as they are said, so
/// no site in the open spells the class. The tail cut's failure arm is said
/// under its own class, `Class::Failure`, beside the door. Through the
/// queue, as every notice is.
fn say_open_line(line: impl fmt::Display) {
    notice::emit(Class::Open, line);
}

/// The volume's free space at start (`operations.md` §1.1 m4).
///
/// It reads `the volume's free space at start: {f} bytes`, and where that
/// stands below the floor in force `…, below the floor in force {F}: every
/// deposit is refused until room stands; every other write serves` — the
/// figure the floor's refusal reads (`MediaGate::free_space`, one reading's)
/// beside the floor the open has just set, said after the media limits'
/// line that names the floor. Where the host refused the read, it reads
/// `the volume's free space at start: unread ({cause}): every deposit is
/// refused until the read answers; every other write serves`, the cause in
/// the store's words, and never a figure. A start below the floor, or
/// unread, says so here: the floor's own line comes at the first refused
/// upload, and the standing line at its first tick, an hour on. A pure value
/// the unit suite pins by `to_string()`; emitted under `Class::Open` through
/// [`say_open_line`].
struct VolumeLine {
    free_space: std::io::Result<u64>,
    floor: u64,
}

impl fmt::Display for VolumeLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let free_space = match &self.free_space {
            Ok(free_space) => *free_space,
            Err(cause) => {
                return write!(
                    f,
                    "the volume's free space at start: unread ({cause}): every deposit is \
                     refused until the read answers; every other write serves"
                );
            }
        };
        write!(f, "the volume's free space at start: {free_space} bytes")?;
        if free_space < self.floor {
            write!(
                f,
                ", below the floor in force {}: every deposit is refused until room stands; \
                 every other write serves",
                self.floor
            )?;
        }
        Ok(())
    }
}

/// Line 8, the upload setting (`operations.md` §1.1 row 8).
///
/// It says, in the operator stream's words, the switch's state and its
/// source — `the default`, the flag as typed (`--uploads` / `--no-uploads`)
/// or the variable with its value (`SKEPD_UPLOADS=true` / `=false`) — and,
/// closed, what the family answers. A pure value the unit suite pins by
/// `to_string()`; emitted under `Class::Open` through [`say_open_line`].
struct UploadsLine {
    open: bool,
    source: Source,
}

impl fmt::Display for UploadsLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.open {
            write!(f, "media uploads: open ({})", self.source.words("--uploads", "SKEPD_UPLOADS=true"))
        } else {
            write!(
                f,
                "media uploads: CLOSED ({}): the creation and the resume are refused \
                 uploads_closed",
                self.source.words("--no-uploads", "SKEPD_UPLOADS=false")
            )
        }
    }
}

/// Row 20's header, the head of the blocked list's multi-line notice.
///
/// It reads `blocked-prefix list ({at start | reissued | at claim},
/// {path}):`, in the row's own spelling: the moment's word is the grammar's
/// for the start and the claim, and row 20's own `reissued` where the
/// grammar's warning class would say `at reissue` — two spellings of one
/// moment, the header's kept as the row spells it. A pure value the unit
/// suite pins by `to_string()`.
struct ListHeader<'a> {
    when: Moment,
    path: &'a Path,
}

impl fmt::Display for ListHeader<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let word = match self.when {
            Moment::AtStart => "at start",
            Moment::AtClaim => "at claim",
            Moment::AtReissue => "reissued",
            Moment::AtOpen => "at open",
        };
        write!(f, "blocked-prefix list ({word}, {}):", self.path.display())
    }
}

/// Line 24, a reissue refused (`operations.md` §1.1 row 24; §4 row 20).
///
/// It says, in the operator stream's words, the cause, what stands — the
/// list in force, until a restart — and what the next start does: refuses,
/// until a valid list stands at the path, since every start reads the file
/// again (AUTH-4.70; RES-115); and the lift's form, so a file deleted to
/// lift every block is told from the empty issue that would. A pure value
/// the unit suite pins by `to_string()`; emitted under `Class::Failure`.
struct ReissueRefusedLine<'a> {
    error: &'a std::io::Error,
    path: &'a Path,
}

impl fmt::Display for ReissueRefusedLine<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "blocked-prefix list: reissue REFUSED — {}; the list in force stands until a \
             restart, and the next start REFUSES until a valid list stands at {}: an empty \
             \"entries\" lifts every block, an absent file lifts none",
            self.error,
            self.path.display()
        )
    }
}

/// Line 22, the checkpoint thread refused (`operations.md` §1.1 row 22).
///
/// It says, in the operator stream's words, the cause, what still serves —
/// the kernel's backstop — the act (a restart; nothing else re-spawns the
/// thread) and what is lost with it: every checkpoint is the backstop's and
/// says nothing, the cadence's byte bound and the media floor stay at the
/// open's figures (the re-reads are the thread's, on its wake), and no
/// standing line will come. A pure value the unit suite pins by
/// `to_string()`; emitted under `Class::Failure` at `serve_bound`'s one
/// site.
pub(super) struct CheckpointThreadRefusedLine<'a>(pub(super) &'a std::io::Error);

impl fmt::Display for CheckpointThreadRefusedLine<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "checkpoint thread: the OS refused it ({}); the kernel's backstop runs each second \
             crossing's checkpoint inline on the committing thread instead; until a restart \
             re-spawns it, every checkpoint is the backstop's and says nothing — no landing \
             line and no failure line — and the cadence's byte bound and the media floor stay \
             at the open's figures; and no standing line will come: each state is said at its \
             transition alone",
            self.0
        )
    }
}

/// The journal damage a history read met (RUNBOOK §2).
///
/// It says, in the operator stream's words, the damage as the kernel renders
/// it — `HistoryError`'s own `Display`, naming the damage's position and its
/// account, or the file, the act and the OS's cause, and never the position
/// the reader asked for (D9) — then what serves on, why the next start may
/// refuse, and the act that keeps it from refusing: a copy, the inventory
/// over the copy, whose open reads the journal as a start does, and a
/// restore of what it refuses. A history read scans the journal from its
/// base to its end, so it is the one reader that meets the damage of a
/// segment the write path never reads back, which the next start's open
/// reads where the damage lies above its start point. Said once per uptime,
/// by [`Daemon::refuse_history`], and re-said by the standing line. A pure
/// value the unit suite pins by `to_string()`; emitted under
/// `Class::Failure`.
///
/// **Damage at rest, where no copy holds the file whole.** The line then
/// names the one recovery that loses nothing: keep the board serving until
/// the next checkpoint lands. That checkpoint holds the head, above the
/// damage, and an open from it passes a corrupt run below it over and says
/// so (the kernel's `runs_passed_over`; RUNBOOK §3 step 3 item 5). A copy
/// taken since the damage holds the same bytes, since damage at rest is
/// found only when something reads it, and the active segment's copy holds
/// only the commits made before it was taken, so for either a restore is
/// impossible or a rewind. The line names that wait for damage at rest
/// alone: every open reads the active segment, whatever its start point,
/// and stops at a file it cannot read, so no checkpoint carries an open past
/// an I/O failure there (RUNBOOK §2 gives the closed segment's case).
pub(super) struct HistoryDamageLine<'a>(pub(super) &'a HistoryError);

impl fmt::Display for HistoryDamageLine<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "history: {}; reads at the head and every write serve on, since neither reads the \
             journal back, but the next start's open reads the journal above its start point and \
             may refuse on the same file: copy the data directory, run skepd inventory over the \
             copy (its open reads the journal as a start does), and restore what it refuses \
             from a copy before the board restarts",
            self.0
        )?;
        if let HistoryError::Corruption { .. } = self.0 {
            f.write_str(
                "; where no copy holds that file whole, keep the board serving and do not \
                 restart it until the next checkpoint lands: an open then starts above the \
                 damage and passes it over",
            )?;
        }
        f.write_str("; check the volume and its device")
    }
}

/// Where a history read met the journal's damage, as the standing line says.
///
/// It reads `at position {p}` for damage at rest — the position the kernel's
/// account names, the one [`HistoryDamageLine`] opens on — and `({error})`
/// for an I/O failure, the kernel's file, act and cause; never the position
/// the reader asked for (D9). The standing line's clause carries it, so a
/// stream rotated past the failure line still names the segment to restore
/// before a restart (RUNBOOK §2), and the two lines join on it. A pure value
/// the unit suite pins by `to_string()`; rendered once, by
/// [`Daemon::refuse_history`], into `Daemon::history_damage`.
pub(super) struct JournalDamageSite<'a>(pub(super) &'a HistoryError);

impl fmt::Display for JournalDamageSite<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            HistoryError::Corruption { at, .. } => write!(f, "at position {at}"),
            HistoryError::Io(io) => write!(f, "({io})"),
            other => write!(f, "({other})"),
        }
    }
}

/// The standing line (`operations.md` §1, the rates; §1.1 m11).
///
/// It is in the operator stream's words: one clause per standing bad state,
/// each by name with its position or file, joined by `; ` in the rates'
/// order — ending, where any stand, with the kept files beside the journal
/// and the logs, `kept files beside the journal and the logs: {n}
/// ({names})` — `the write path is halted since position {p} (feed-attest.log)`;
/// `the kernel is poisoned since position {p}`, the position the kernel's
/// halt line named; `a history read found the journal unreadable at
/// position {p}` or `… ({error})` (the damage [`HistoryDamageLine`] said,
/// which the next open reads, by its site — [`JournalDamageSite`]; RUNBOOK
/// §2); `{file} stopped since position {p}` once per stopped file;
/// `the pruner's thread is gone`; `the feed walk's thread is gone;
/// positions ({low}, {head}] stay uncovered` and, or instead, `; {n} bare
/// positions the index lost stay unsorted` (the walk behind the listener
/// dead on a caught panic, what it left pending for the uptime —
/// `operations.md` §3.3 step 2; row 41); `the cell index failed to
/// build`; `deposits refused at the floor (free space {f} below the floor
/// in force {F})`, or `… (free space unread: {cause})` where the host
/// refused the read, the cause in the store's words; `a deposit's file is
/// unread ({cause}), {n} reads failed over {ms} ms`, the cause of the tick's
/// own read in the store's words, the file by its hash;
/// `CLAIMED-PERMISSIVE`. A pure value over the reads
/// ([`Daemon::say_the_standing_line`] makes them), pinned by `to_string()`
/// in the unit suite; emitted under `Class::Standing` at a tick where
/// [`StandingLine::stands`], and never otherwise. States, positions, files
/// and the figures of the floor and the unread deposit or their reads'
/// causes alone — no principal, token, path, query or reader rides it. The
/// index's clause reads the media gate's failed state (`operations.md` §4
/// row 26).
pub(super) struct StandingLine {
    /// The write path's halt and the position it was set at.
    pub(super) halted_at: Option<Seq>,
    /// `Kernel::is_poisoned`, with the head the kernel halted at.
    ///
    /// No commit lands past a poisoned kernel, so `Kernel::current_seq` at
    /// the tick is the position the halt line (m10) named.
    pub(super) poisoned: Option<Seq>,
    /// Where a history read met the journal's damage this uptime.
    ///
    /// It is the site [`Daemon::refuse_history`] kept as it said
    /// [`HistoryDamageLine`] — [`JournalDamageSite`]'s rendering.
    pub(super) history_damaged: Option<String>,
    /// The feed's stopped files, each with its position.
    pub(super) stopped_files: Vec<StoppedFile>,
    /// The pruner's liveness flag.
    pub(super) pruner_gone: bool,
    /// The feed walk's liveness flag, with what it left unlanded.
    ///
    /// It is `Commits::feed_walk_gone`'s read: the region it left uncovered,
    /// the bare positions the index lost it left unsorted, or both.
    pub(super) feed_walk_gone: Option<FeedPending>,
    /// The cell index's failed state, the media gate's read.
    ///
    /// It is `MediaGate::index_failed`'s.
    pub(super) index_failed: bool,
    /// The floor binding: the free space read below the floor in force, or
    /// a read of it the host refused.
    pub(super) floor: Option<FloorBinding>,
    /// A deposit's file the store could not read, as the tick read it again.
    ///
    /// It is `MediaGate::unread_deposit`'s answer.
    pub(super) unread_deposit: Option<UnreadDeposit>,
    /// Whether the board is `CLAIMED-PERMISSIVE`.
    pub(super) claimed_permissive: bool,
    /// The kept files beside the journal and the logs, listed at the tick.
    ///
    /// They are `tools::kept_files`'s: the `*.cut-*` files an open kept
    /// bytes it cut as damage in, a standing state until the operator
    /// removes them (`operations.md` §1.1 m11).
    pub(super) kept_files: Vec<String>,
}

/// The floor's binding at the tick: the free space read, and the floor.
///
/// It is as the media gate answered its binding standing
/// (`MediaGate::floor_binding`): the free space below the floor in force, or
/// the host's refusal of the read, which the clause names by its cause.
pub(super) struct FloorBinding {
    pub(super) free_space: std::io::Result<u64>,
    pub(super) floor: u64,
}

impl StandingLine {
    /// Returns whether at least one clause stands.
    ///
    /// It is the one condition the line is said under.
    pub(super) fn stands(&self) -> bool {
        self.halted_at.is_some()
            || self.poisoned.is_some()
            || self.history_damaged.is_some()
            || !self.stopped_files.is_empty()
            || self.pruner_gone
            || self.feed_walk_gone.is_some()
            || self.index_failed
            || self.floor.is_some()
            || self.unread_deposit.is_some()
            || self.claimed_permissive
            || !self.kept_files.is_empty()
    }
}

impl fmt::Display for StandingLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut clauses: Vec<String> = Vec::new();
        if let Some(at) = self.halted_at {
            clauses.push(format!("the write path is halted since position {at} (feed-attest.log)"));
        }
        if let Some(at) = self.poisoned {
            clauses.push(format!("the kernel is poisoned since position {at}"));
        }
        if let Some(site) = &self.history_damaged {
            clauses.push(format!("a history read found the journal unreadable {site}"));
        }
        for file in &self.stopped_files {
            clauses.push(format!("{} stopped since position {}", file.name, file.since));
        }
        if self.pruner_gone {
            clauses.push("the pruner's thread is gone".to_string());
        }
        if let Some(pending) = self.feed_walk_gone {
            let mut clause = "the feed walk's thread is gone".to_string();
            if let Some((low, head)) = pending.region {
                clause.push_str(&format!("; positions ({low}, {head}] stay uncovered"));
            }
            if let Some(set) = pending.unsorted {
                clause.push_str(&format!(
                    "; {} bare positions the index lost stay unsorted",
                    set.count
                ));
            }
            clauses.push(clause);
        }
        if self.index_failed {
            clauses.push("the cell index failed to build".to_string());
        }
        if let Some(floor) = &self.floor {
            clauses.push(match &floor.free_space {
                Ok(free_space) => format!(
                    "deposits refused at the floor (free space {free_space} below the floor in \
                     force {})",
                    floor.floor
                ),
                Err(cause) => format!("deposits refused at the floor (free space unread: {cause})"),
            });
        }
        if let Some(unread) = &self.unread_deposit {
            clauses.push(format!(
                "a deposit's file is unread ({}), {} reads failed over {} ms",
                unread.cause,
                unread.failed,
                unread.age.as_millis()
            ));
        }
        if self.claimed_permissive {
            clauses.push("CLAIMED-PERMISSIVE".to_string());
        }
        if !self.kept_files.is_empty() {
            clauses.push(format!(
                "kept files beside the journal and the logs: {} ({})",
                self.kept_files.len(),
                self.kept_files.join(", ")
            ));
        }
        f.write_str(&clauses.join("; "))
    }
}

/// The checkpoint thread's consequence line.
///
/// It opens on row 41's words (`operations.md` §1.1 row 41), verbatim — every
/// checkpoint from here is the kernel's backstop's, run inline on a writer
/// and said by nothing, and the byte bound and the media floor stand frozen
/// at the last landing's figures, or the open's where none landed (the
/// re-reads are the thread's) — and goes on with the rest of what the board
/// lost with the thread, as row 22's line says it for the thread refused at
/// start ([`CheckpointThreadRefusedLine`]), and with the act (§4 row 25's,
/// a restart): the landing line, the change feed's figures on it, is the
/// thread's alone, and the standing line rides its timed wait, so from here each standing
/// state is said at its transition and never again, and a stream with no
/// `standing:` line says nothing of the board's health. A pure value pinned
/// by `to_string()`; emitted under `Class::Failure` by
/// [`Daemon::the_checkpoint_thread_ended`], once, after the hook's line has
/// said the panic itself.
pub(super) struct CheckpointThreadEndedLine;

impl fmt::Display for CheckpointThreadEndedLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(
            "checkpoint thread ended: every checkpoint from here is the backstop's, unsaid; the \
             byte bound and the floor stay where they were; until a restart re-spawns it, no \
             standing line will come: each state is said at its transition alone",
        )
    }
}

/// The pruner's consequence line (row 41; §4 row 24).
///
/// Its words, verbatim, say that no pass runs until a restart, so the blob
/// logs are never compacted and the lapsed tail is never reclaimed. A pure
/// value pinned by `to_string()`; emitted under `Class::Failure` by
/// [`Daemon::the_pruner_thread_ended`], once, after the hook's line.
pub(super) struct PrunerThreadEndedLine;

impl fmt::Display for PrunerThreadEndedLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(
            "pruner thread ended: no pass runs until a restart; the blob logs' compaction and \
             the lapsed tail's reclaim stop",
        )
    }
}

/// The claim's flip line (`operations.md` §1.1 m14).
///
/// It reads, in the operator stream's words, `board claimed by {account}
/// at position {p}: the mode is now {mode}; H.1 {written | written before
/// the claim | owed — the head writer refused it}`, rendered from what the
/// flip's tail holds: the claimant the commit seated, spelled as `/health`
/// spells it; the claim's own position, the credential sequence's ack,
/// passed down (P21's boundary — never the head's position after the flip,
/// which the head's own commits move); the mode the board is now in,
/// derived as AUTH-5.86 derives it with the claim read as set; and what
/// [`Commits::write_first_head`] answered. The design's two arms are the
/// first and the third; the second says the one state neither covers — a
/// head the cadence wrote before the claim, so the board term stands and
/// names an earlier position — rather than misname it a refusal. A pure
/// value the unit suite pins by `to_string()`; emitted under
/// `Class::Landing` from `op.rs`'s `Daemon::on_claim_flip`.
pub(super) struct ClaimLine<'a> {
    pub(super) claimant: &'a Address,
    pub(super) position: Seq,
    pub(super) mode: &'a str,
    pub(super) head: FirstHead,
}

impl fmt::Display for ClaimLine<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "board claimed by {} at position {}: the mode is now {}; H.1 {}",
            self.claimant.tumbler(),
            self.position,
            self.mode,
            match self.head {
                FirstHead::Written => "written",
                FirstHead::Stood => "written before the claim",
                FirstHead::Refused => "owed — the head writer refused it",
            }
        )
    }
}

/// The first head written at open (`operations.md` §1.1 row 12).
///
/// It reads `the board is claimed and its journal held no head: H.1 written
/// at open at position {landed} in {d} ms, naming the committed pair at
/// position {named}` — where `H.1`'s last commit landed, how long its write
/// held the write path's lock, and the committed pair it names, the board
/// term every attested write is checked against (signed-ops D13). Said where
/// the crash window split the claim from its head, so the flip's own line
/// ([`ClaimLine`]) was never said and this is the one line the board has of
/// its first head (I11 (c): a head written for a reason other than the
/// cadence's is said, never silent). A pure value the unit suite pins by
/// `to_string()`; emitted under `Class::Landing` by
/// [`Daemon::write_the_claims_head_if_owed`].
struct HeadAtOpenLine {
    /// The committed head once `H.1`'s commits landed.
    landed: Seq,
    /// The head's write, whole milliseconds, under the write path's lock.
    duration_ms: u128,
    /// The committed pair `H.1` names: the head before its own write opened.
    named: Seq,
}

impl fmt::Display for HeadAtOpenLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "the board is claimed and its journal held no head: H.1 written at open at position \
             {} in {} ms, naming the committed pair at position {}",
            self.landed, self.duration_ms, self.named
        )
    }
}

/// The link-type registry's line at an open that wrote into it.
///
/// It is the open's report of the seed (commons-seeding §1 to §4;
/// `skep-core`'s `commits/registry.rs`), in the operator stream's words: the
/// registry document, how many of the vocabulary's types this open wrote a
/// section and a `defines` link for, how many stood already, and how long
/// the seed held the write path's lock — `link-type registry {doc}:
/// {written} of {total} types written, {stood} stood, in {ms} ms`. On a
/// fresh board every type is written and none stood; on a board a later
/// build opens, the types it adds alone; on a reopen nothing is written and
/// the line is not said. Where a driver refused a row the seed's own failure
/// line precedes it, naming the type, and the written count is the rows
/// before it. A pure value the unit suite pins by `to_string()`; emitted
/// under `Class::Open` through the write path's classed door, so it stands
/// in the record beside the seed's failure line.
struct RegistrySeededLine<'a> {
    seeded: &'a Seeded,
    /// The vocabulary's size: the rows the board holds once the seed is whole.
    total: usize,
    /// The seed's whole, whole milliseconds, under the write path's lock.
    duration_ms: u128,
}

impl fmt::Display for RegistrySeededLine<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "link-type registry {}: {} of {} types written, {} stood, in {} ms",
            ghost_home_document(),
            self.seeded.written,
            self.total,
            self.seeded.stood,
            self.duration_ms
        )
    }
}

// ── the edge pairs' words ────────────────────────────────────────────────
//
// What the ten pairs say (`operations.md` §1.1 m12; §4 rows 27 and 33;
// §6's three rows): the six permit pools — the class-scan bound's two under
// one pair, sharing the refusal — and the worker pool in one form —
// `skep_util::permits`'s `PoolEdgeLine`, under the word each pool names
// itself by — the live-stream budget in that form too, the live streams'
// threads, the challenge store and the accept loop in their own words. Each
// a pure value whose words the edge suite pins as said (`tests/it/edges.rs`),
// said under the edge's class word through the classed door and never the
// un-classed one; nothing on a line but the condition and, where the OS
// refused, its own words for the cause — no count (the upload and write
// pools' landings and the accept loop's recovery alone carry one, the
// episode's refusals, which count no reader), no path, query, principal,
// peer, position or reader.

/// The word the reconstruction pool's two lines name it by.
///
/// It is the refusal's own, `history_busy` (m12: one word per pool, the
/// same in both lines).
pub(super) const HISTORY_POOL: &str = "history";

/// The word the class-scan bound's two lines name it by — its class pool's
/// and its per-document pool's alike, the two sharing one refusal and so one
/// edge pair.
///
/// It is the refusal's own, `scan_busy`.
pub(super) const SCAN_POOL: &str = "scan";

/// The word the write pool's two lines name it by.
///
/// It is the refusal's own, `write_busy`.
pub(super) const WRITE_POOL: &str = "write";

/// The word the worker pool's two lines name it by.
///
/// The pool is the request workers, the budget the six permit pools are
/// sized against (`listen.rs`'s `DEFAULT_WORKERS`). Nothing is refused at
/// it — a connection that finds every worker busy waits in the listen
/// backlog — so its word is no refusal's but the threads' own,
/// `skepd-worker`, which the accept pair's lines carry too.
pub(super) const WORKER_POOL: &str = "worker";

/// The live-stream budget's two lines, in the pools' form (m12; §6's row).
///
/// It says `the live-stream budget is saturated` when a stream past the
/// budget is first refused — the 65th, dropped with a clean close — and
/// `the live-stream budget has room again` at the first stream admitted a
/// hold-down past the last refusal. No count: the budget's size is
/// `listen.rs`'s `MAX_SUBSCRIBERS`'s card's, and a line naming no reader
/// and counting nothing is not read telemetry (D9, read loose). Said from
/// `listen.rs`'s `Subscribers::admit` through [`Daemon::say`].
pub(super) struct BudgetEdgeLine(pub(super) Edge);

impl fmt::Display for BudgetEdgeLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self.0 {
            Edge::Failure => "the live-stream budget is saturated",
            Edge::Landing { .. } => "the live-stream budget has room again",
        })
    }
}

/// The live streams' thread pair (m12's form).
///
/// A stream the budget admits is served on a thread of its own, and where the
/// OS refuses that thread the stream is closed before its head, as the 65th
/// is. The first refusal of an episode says so in the OS's words, with what
/// serves and the act — `live stream: the OS refused its thread ({e}); …`;
/// every later refusal inside it says nothing; and the first stream given
/// its thread a hold-down after the last refusal says `live stream: the OS
/// gives the streams their threads again`. Without it every client's live
/// view closes, reconnects and closes again, the budget's own pair says
/// nothing — the budget has room — and nothing on the stream names the
/// host's thread limit. No count, no peer. Said from `listen.rs`'s
/// `Subscribers::admit` through [`Daemon::say`].
pub(super) enum StreamThreadLine<'a> {
    /// The first refusal of an episode, with the OS's own error.
    Refused(&'a std::io::Error),
    /// The first stream given its thread a hold-down after the last refusal.
    Again,
}

impl fmt::Display for StreamThreadLine<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StreamThreadLine::Refused(e) => write!(
                f,
                "live stream: the OS refused its thread ({e}); the stream was closed before its \
                 head, and so is every new one while the OS refuses threads; reads, writes and \
                 /health serve; the act: room under the host's thread limit (a container's pids \
                 limit, the user's process limit)"
            ),
            StreamThreadLine::Again => {
                f.write_str("live stream: the OS gives the streams their threads again")
            }
        }
    }
}

/// The challenge store's two lines (m12; §6's row).
///
/// Their words: `challenge store: a nonce was evicted inside its time to
/// live — more than {MAX_LIVE_NONCES} challenges stood unanswered within
/// {CHALLENGE_TTL_MS} ms; a handshake it belonged to will be refused` when a
/// mint first evicts a nonce younger than its TTL — the bound in force, the
/// store's cap and the TTL, so the line says the rate that trips it — and
/// `challenge store: minting without evicting a live nonce again` at the
/// first mint that evicted no live nonce a hold-down after the last that
/// did. No caller, count or origin (AUTH-1.48: the cap is a memory bound and
/// never an abuse bound — the line says the fact and the bound, not who met
/// it). Said from [`Daemon::say_the_edges_crossed`].
pub(super) struct ChallengeEdgeLine(pub(super) Edge);

impl fmt::Display for ChallengeEdgeLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Edge::Failure => write!(
                f,
                "challenge store: a nonce was evicted inside its time to live — more than \
                 {MAX_LIVE_NONCES} challenges stood unanswered within {CHALLENGE_TTL_MS} ms; a \
                 handshake it belonged to will be refused"
            ),
            Edge::Landing { .. } => {
                f.write_str("challenge store: minting without evicting a live nonce again")
            }
        }
    }
}

/// The accept pair's first line (m12; §4 row 33).
///
/// Its words: `worker: accept failed ({e}); new connections wait`, `{e}`
/// the OS's own text of the error — `Too many open files (os error 24)` at
/// the descriptor wall — which names the cause; the act is the operator's,
/// the descriptor limit. Said once across the workers at the first failed
/// `accept` of an episode, from the worker loop (`listen.rs`) through
/// [`Daemon::say`]; no peer and no worker named.
pub(super) struct AcceptFailedLine<'a>(pub(super) &'a std::io::Error);

impl fmt::Display for AcceptFailedLine<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "worker: accept failed ({}); new connections wait", self.0)
    }
}

/// The accept pair's second line (m12; §4 row 33).
///
/// Its words: `worker: accept recovered after {n} failures`, `{n}` every
/// worker's failures counted into the one episode — said at the first
/// `accept` that succeeded a hold-down after the episode's last failure,
/// from the worker loop through [`Daemon::say`].
pub(super) struct AcceptRecoveredLine {
    pub(super) failures: u64,
}

impl fmt::Display for AcceptRecoveredLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "worker: accept recovered after {} failures", self.failures)
    }
}

#[cfg(test)]
mod tests;
