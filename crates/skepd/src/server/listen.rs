//! The socket server: the worker budget, the accept loop, the event streams.
//!
//! It holds `Skepd`, `Listener`, `bind`, `serve` and `serve_bound`, and the
//! worker counts `DEFAULT_WORKERS` and `MIN_WORKERS`.

use std::io::{self, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use skep_media::limits::{MAX_CONCURRENT_FETCHES, MAX_CONCURRENT_UPLOADS};
use skep_media::pruner::{Cadence, Wake};
use skep_media::serve::Progress;
#[cfg(feature = "test-hooks")]
use skep_media::serve::STREAM_HOLD;
use skep_util::notice::{self, Class, Moment};
use skep_util::permits::{edge_clock_now, Edge, EdgeTracker};

use super::blob_routes;
use super::http::{
    push_header, read_request, refuse_request, reset_close, response_head, write_chunk,
    write_commit_event, write_fetch_head, write_reply, REQUEST_READ_TIMEOUT, TRANSFER_DEADLINE,
    WRITE_TIMEOUT,
};
use super::reply::{refuse, Fetch, Routed, TransportError, SESSION_HEADER};
use super::request::HttpRequest;
use super::scan::MAX_CONCURRENT_CLASS_SCANS;
use super::{
    AcceptFailedLine, AcceptRecoveredLine, BudgetEdgeLine, CheckpointThreadRefusedLine, Daemon,
    StreamThreadLine,
};
use skep_core::auth::session::Peer;
use crate::limits::{BLOB_CHUNK, BLOB_IDLE_BOUND, BLOB_TRANSFER_BOUND, PRUNE_INTERVAL};
use skep_core::limits::EDGE_HOLD_DOWN;
use skep_core::commits::{CheckpointSignal, StreamStep, Woken};

/// The request worker count `skepd` serves with when the operator names none.
///
/// It is held here rather than in the binary because it is the sixth term of
/// a budget the other five are meaningless without.
///
/// The five permit pools bound the five expensive surfaces — the
/// reconstruction, the class scan, the blob fetch, which holds a whole file
/// for its answer, the blob upload, which holds its worker for a whole
/// file's transfer (M-I5 (f)), and the write, which holds its worker on the
/// write path's guard for as long as the write ahead of it takes — an inline
/// backstop's whole checkpoint, seconds on a large board (`operations.md`
/// §4 rows 25, 27) — and each card argues its own number against the work
/// that surface commands. None prices the sum, and the sum is what decides
/// whether the bounds do the thing they exist for: a caller holding every
/// permit of all five pools is inside every bound, and if that exhausts the
/// workers the daemon answers nothing — `/health` and `/session` included —
/// with every structure inside it healthy. The relation is therefore
/// `workers >= `[`MIN_WORKERS`], and the assertion below is what keeps it
/// from being arithmetic a reader has to do across five files.
///
/// Fourteen pooled slots plus two free is the smallest split that keeps the
/// liveness probe, the handshake and every read answerable while every pool
/// is saturated: one worker of slack over the minimum. Two free suffice
/// because an ordinary request completes in milliseconds, where a pooled
/// one is a whole-store scan, a whole-world replay, a whole file's transfer
/// — the fetch's, which streams the file out, or the upload's, which
/// streams it in: "a whole file's transfer" reads both ways, and each holds
/// its worker to the end — or a write parked behind an inline checkpoint.
///
/// An embedder calling [`serve`] with its own count owes the same relation,
/// and [`MIN_WORKERS`] is the form in which they can evaluate it.
pub const DEFAULT_WORKERS: usize = 16;

/// The smallest worker count [`serve`]'s pooled-permit obligation admits.
///
/// It is one more than the slots the five permit pools hold together, so a
/// caller holding every permit of all five still leaves a worker to answer
/// `/health`, `/session` and every read.
///
/// It is public because it is the caller's half of an obligation [`serve`]
/// states and deliberately does not re-check: the five pools' own counts
/// are this crate's and `skep-media`'s, so `workers >= MIN_WORKERS` is the
/// only form an embedder naming its own count can evaluate — and the form
/// the binary's parse refuses a count below, stating the relation. It is
/// derived from the five rather than written down, so a pool that moves
/// moves this with it — which is what keeps the obligation and the check on
/// one number.
pub const MIN_WORKERS: usize = crate::history::MAX_CONCURRENT_RECONSTRUCTIONS
    + MAX_CONCURRENT_CLASS_SCANS
    + MAX_CONCURRENT_FETCHES
    + MAX_CONCURRENT_UPLOADS
    + crate::server::MAX_CONCURRENT_WRITES
    + 1;

const _: () = assert!(
    DEFAULT_WORKERS >= MIN_WORKERS,
    "the shipped default must satisfy serve's own pooled-permit obligation: a caller \
     inside every bound would otherwise occupy every worker"
);

// ── the wire loop ────────────────────────────────────────────────────────

/// The running server.
///
/// It holds the listener, the op workers, the daemon, the event-stream
/// subscriber threads, and the pruner's thread and the checkpoint thread.
///
/// Dropping it stops the server: `Drop` runs the whole stop
/// [`Skepd::shutdown`] runs — the opposite of `std::thread::JoinHandle`,
/// which detaches its thread when dropped. So the type is `#[must_use]`, as
/// the workspace's own `SessionId` is: a `serve(…)?;` or
/// `serve(…).expect(…);` statement whose `Skepd` falls at the semicolon is a
/// server stopped before the next line runs, and the compiler says so rather
/// than the first refused connect. Bind it, then [`Skepd::wait`] on it or
/// [`Skepd::shutdown`] it.
#[must_use = "dropping a `Skepd` stops the server it runs: bind it, then `wait` on it \
              or `shutdown` it"]
pub struct Skepd {
    daemon: Arc<Daemon>,
    /// The listener, held and never read.
    ///
    /// The workers own clones, so this handle is what keeps
    /// [`Skepd::port`] bound for exactly as long as the server value exists
    /// rather than only while a worker survives.
    _listener: Arc<TcpListener>,
    workers: Vec<JoinHandle<()>>,
    subscribers: Arc<Subscribers>,
    stop: Arc<AtomicBool>,
    /// The pruner's thread and its cadence.
    ///
    /// The pass runs once the cell index is ready and then every
    /// [`PRUNE_INTERVAL`]; the stop wakes it at once, and the shutdown joins
    /// it.
    pruner: Option<JoinHandle<()>>,
    cadence: Arc<Cadence>,
    /// The checkpoint thread.
    ///
    /// It waits on the write path's signal and runs the checkpoint the
    /// kernel's deferred cadence calls for, off the guard
    /// ([`checkpoint_on_due`]); the stop wakes it at once, and the shutdown
    /// joins it — a run in flight is let finish.
    checkpointer: Option<JoinHandle<()>>,
    /// The address the listener bound.
    ///
    /// The stop's wake connect dials it, or loopback where it is unspecified
    /// ([`wake_addr`]).
    addr: Ipv4Addr,
    port: u16,
}

/// The server's `Debug`: the bound port and the worker count.
///
/// No lock is taken, so this is safe to reach for from anywhere, including
/// a thread that already holds one.
impl std::fmt::Debug for Skepd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Skepd")
            .field("port", &self.port)
            .field("workers", &self.workers.len())
            .finish_non_exhaustive()
    }
}

/// The accept-failure pause, 10 ms.
///
/// The figure is interim (the configuration register's F15). It is how long a
/// worker whose `accept` failed waits before it tries again, in place of a
/// spin. The failures this meets are transient and clear by themselves —
/// `EMFILE` and kin, a descriptor freed when any connection closes, which is
/// milliseconds on a serving board — so the pause is of that order: long
/// enough that a worker refused at the descriptor wall does not burn a core
/// re-asking, short enough that a connection waiting in the backlog meets a
/// worker again within a few of them. A longer pause would hold every new
/// connection for its length once the wall clears.
const ACCEPT_RETRY_PAUSE: Duration = Duration::from_millis(10);

/// The pruner's readiness poll, 250 ms.
///
/// The figure is interim (the configuration register's F15). It is how often
/// the pruner's thread looks for the cell index's walk at open to complete
/// before its first pass, the one wait of its life with nothing but the stop
/// to wake it (the walk's landing raises no signal; the cadence does,
/// after). The walk is seconds to a minute on a large board, so a
/// quarter-second poll costs four wakes a second on a thread that does
/// nothing else meanwhile, and bounds the first pass's lag behind the walk
/// at that. The stop waits on no poll: [`Cadence::wait`] ends early at the
/// stop, so the stop wakes a thread parked here at once.
const INDEX_READINESS_POLL: Duration = Duration::from_millis(250);

/// The listener [`bind`] bound, carrying the address and the port it bound.
///
/// It is what the open runs with and [`serve_bound`] serves over. Bound
/// before the open, so a held port is refused in milliseconds, before the
/// kernel's lock is taken and before anything is written under the data
/// directory; held through it, so no other process takes the port between
/// the bind and the serve — a connect during the open waits in the socket's
/// backlog, rather than meeting a refusal, and is answered once a worker
/// accepts. Nothing accepts until the workers exist. Dropping it releases
/// the port, which is why the type is `#[must_use]`: a `bind(…)?;`
/// statement whose listener falls at the semicolon has bound nothing a
/// serve can use.
#[must_use = "dropping the listener releases the port it bound: hand it to `serve_bound`"]
#[derive(Debug)]
pub struct Listener {
    listener: TcpListener,
    addr: Ipv4Addr,
    port: u16,
}

impl Listener {
    /// Returns the bound address, read back off the socket.
    ///
    /// It is what the binary's serving line names, so the line says what was
    /// bound and never what was asked for.
    pub fn addr(&self) -> Ipv4Addr {
        self.addr
    }

    /// Returns the bound port.
    ///
    /// It is the number to serve on under `port = 0`, and the one
    /// [`serve_bound`] binds the auth surface to.
    pub fn port(&self) -> u16 {
        self.port
    }
}

/// Where [`bind`] binds: an address and a port, with two spellings.
///
/// A bare port — `bind(port)`, the loopback door `127.0.0.1:port` every
/// suite and the one-call [`serve`] take — or an `(address, port)` pair,
/// `bind((addr, port))`, the binary's door under `--bind`. One function
/// with two spellings rather than two functions, so a caller of the port
/// form names a bare port and the address-taking form is the same `bind`,
/// with the same refusals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListenAt {
    addr: Ipv4Addr,
    port: u16,
}

impl From<u16> for ListenAt {
    /// Returns the loopback door at `port`.
    fn from(port: u16) -> ListenAt {
        ListenAt { addr: Ipv4Addr::LOCALHOST, port }
    }
}

impl From<(Ipv4Addr, u16)> for ListenAt {
    /// Returns `addr:port`, the binary's `--bind` and `--port`.
    fn from((addr, port): (Ipv4Addr, u16)) -> ListenAt {
        ListenAt { addr, port }
    }
}

/// Binds `at` and answers the listener with the address and the port it bound.
///
/// `at` is a port, the loopback door `127.0.0.1:port`, or an
/// `(address, port)` pair; `0` = ephemeral. The bind is the first act of a
/// start, before [`Daemon::open_configured`]: a port another process holds
/// is a fault decidable before any byte of the journal is read, so it is
/// refused here, at once, with the open's whole cost unpaid and no
/// `kernel.lock` taken. Nothing accepts on the listener until
/// [`serve_bound`] spawns the workers.
///
/// The address is the binary's `--bind`, `127.0.0.1` by default — the
/// loopback door a notebook, a developer's machine and a self-run board
/// keep — and the container's address (`0.0.0.0`) in the hosted image,
/// where the container's network is the boundary. An IPv4 address and
/// nothing wider: a dual-stack `::` bind would hand the accept path
/// IPv4-mapped peers (`::ffff:127.0.0.1`), which the peer rule classes
/// `Remote`, so every loopback client would lose the bare bind. Widening the
/// bind widens nothing of the trust model: the peer's loopback-ness is read
/// off the socket at accept ([`Peer::of`]), whatever address was bound.
///
/// # Errors
///
/// Failure is the socket's or the OS's: binding the address, or reading
/// back the address and port it bound — both `io::Error`, which is what
/// lets a caller dispatch on `ErrorKind` — `AddrInUse` to try the next
/// port, `PermissionDenied` for a privileged one — without a downcast.
pub fn bind(at: impl Into<ListenAt>) -> io::Result<Listener> {
    let ListenAt { addr, port } = at.into();
    let listener = TcpListener::bind((addr, port))?;
    let bound = listener.local_addr()?;
    let addr = match bound.ip() {
        std::net::IpAddr::V4(v4) => v4,
        // Unreachable for a socket bound by the tuple above, and said so
        // rather than unwrapped: an IPv4 bind answers an IPv4 address.
        std::net::IpAddr::V6(_) => {
            return Err(io::Error::other("an IPv4 bind answered an IPv6 address"));
        }
    };
    Ok(Listener { listener, addr, port: bound.port() })
}

/// Binds `127.0.0.1:port` (`0` = ephemeral) and serves with `workers` threads.
///
/// It is [`bind`] then [`serve_bound`], in sequence — the one-call door for
/// a caller whose open costs nothing worth refusing a held port ahead of (a
/// test's fresh directory, an embedder's own ordering). The binary takes the
/// two apart: the bind first, the open between, the serve after, so a held
/// port refuses the start before the open runs. Everything below holds of
/// this door and of `serve_bound` alike.
///
/// The loopback address is the one this one-call door binds; a caller
/// wanting another, as the binary's `--bind` does, takes
/// [`bind`]`((addr, port))` and [`serve_bound`] apart. Concurrency policy in
/// full: each worker blocks in `accept`, serves the one request on that
/// connection, closes it — one request per connection, `Connection: close`
/// on every final response (`OperationSurface::execute` is `Sync` and M2's
/// single applier serializes writes, so the worker count is the whole
/// op-concurrency story). `GET /events` is the one exception to
/// request/response: the worker hands the socket to a dedicated subscriber
/// thread and returns to `accept` at once, so open streams never occupy the
/// op pool. The [`Skepd`] it answers is the running server: dropping it
/// stops the server, which is why the type is `#[must_use]`.
///
/// `serve` starts two threads of the daemon's own beside the workers: the
/// pruner's, on its cadence, and the checkpoint thread, which waits on the
/// write path's signal and runs the checkpoint the kernel's deferred cadence
/// calls for — every 1024 commits or the byte bound, whichever first — off
/// the write path's guard, so no write waits for it; it re-reads the byte
/// bound and the media floor from the checkpoint that landed, compacts the
/// change feed's files to the journal's reclaim floor, and says a failure
/// once (`Daemon::service_the_checkpoint`). They are a served daemon's: an
/// embedder routing by hand through [`Daemon::route`] gets no thread and
/// services the flag itself — `Daemon::checkpoint_now` through the test
/// seam, or its own call to the kernel's `checkpoint` — or takes the
/// kernel's backstop, which runs the checkpoint inline on the committing
/// thread at every second crossing and never lets the window grow unbounded.
///
/// **Precondition.** `workers >= `[`MIN_WORKERS`] is the obligation the
/// count carries, which leaves a worker free of the five permit pools. A
/// caller holding every permit of all five is inside every bound, so below
/// that count they occupy the whole pool and the daemon answers nothing,
/// `/health` and `/session` included. [`DEFAULT_WORKERS`] satisfies it and
/// carries the assertion that holds it; an embedder naming its own count
/// owes it, and `serve` does not re-check — the obligation is the caller's,
/// and [`MIN_WORKERS`] is how they evaluate it.
///
/// # Errors
///
/// Failure is the socket's or the OS's: binding the address, reading back
/// the port it bound, or a refused worker thread — all three `io::Error`,
/// which is what lets a caller dispatch on `ErrorKind` — `AddrInUse` to try
/// the next port, `PermissionDenied` for a privileged one — without a
/// downcast. The first two are [`bind`]'s, the third [`serve_bound`]'s. A
/// refused thread retires whatever has already started before returning, so
/// the port and the journal-directory lock are free for that retry.
///
/// # Panics
///
/// Panics if `workers` is zero. A count of zero asks for a server that
/// serves nothing, which is a caller's bug rather than an outcome, so it
/// stops here loudly instead of being repaired into a one-worker server —
/// the same posture `MAX_CHANGES_LIMIT` takes on the wire, where an
/// out-of-range page size is refused and never clamped. `main.rs`
/// establishes `workers >= 1` by refusing every count below
/// [`MIN_WORKERS`], zero among them, where the flag and its variable are
/// read, which is also what makes its startup line's worker count honest.
///
/// Panics if `daemon`'s auth port is already bound. `serve` binds it, and a
/// daemon already carrying one has two callers disagreeing about the number
/// every live session's origin set derives from, so the second stops loudly
/// rather than serving under a set nobody chose. The one caller this
/// excludes is a socket-free embedder that called
/// [`Daemon::bind_auth_port`] itself, which is what that method means by
/// calling the two exclusive. Like the count above, a caller's bug rather
/// than an outcome, so it is a panic and not one of the `io::Error`s above.
pub fn serve(daemon: Daemon, port: u16, workers: usize) -> io::Result<Skepd> {
    serve_bound(daemon, bind(port)?, workers)
}

/// Serves `daemon` over the listener [`bind`] bound, with `workers` threads.
///
/// It is everything [`serve`] does after its bind, and the door the binary
/// takes once the open has run with the port already held: the auth surface
/// bound to the listener's port, the configuration warnings, the
/// open's-report `auth:` line (the mode and the two origin sets), the node
/// prefix, the blocked list, the workers, the pruner's thread and the
/// checkpoint thread, in that order (`operations.md` §3.1 step 3) — the
/// workers after every line and before the two threads, since a worker
/// spawned before a daemon exists would route into nothing. [`serve`]'s
/// concurrency policy is this door's, stated there.
///
/// # Errors
///
/// Failure is the OS's alone: a refused worker thread, an `io::Error`. The
/// listener and the port it bound were the caller's before this call and
/// are released with the retired start, as `serve` releases them. The start
/// is retired before the pruner's thread and the checkpoint thread are
/// spawned (`operations.md` §4 row 23), so a retired start runs no pass and
/// no checkpoint, and its stop waits on neither.
///
/// # Panics
///
/// Panics where [`serve`]'s two preconditions fail, stated there: `workers`
/// is zero, or the daemon's auth port is already bound.
pub fn serve_bound(daemon: Daemon, listener: Listener, workers: usize) -> io::Result<Skepd> {
    assert!(workers >= 1, "serve requires at least one worker thread (workers = 0)");
    let daemon = Arc::new(daemon);
    // The address is the serving line's, read by the binary off the
    // listener before this call and said after it, and the stop's wake
    // connect's; the auth surface derives its sets from the port alone, and
    // the bind enters no set.
    let Listener { listener, addr, port } = listener;
    let listener = Arc::new(listener);
    // The auth surface derives its origin sets from the bound port, and the
    // startup warnings are logged here — the first of the lines the glue
    // says from the config before serving (AUTH-4.11). After the bind, and
    // not before: the port-change arm compares each configured origin
    // against the bound port's loopback defaults, so on an unbound config
    // every configured loopback origin would warn.
    daemon.bind_auth_port(port).expect(
        "serve binds the auth port once; a pre-bound daemon has two callers \
         disagreeing about the number every live session's origin set derives from",
    );
    daemon.log_config_warnings(Moment::AtStart);
    // The open's-report `auth:` line (m14): the mode, the flag with its
    // source and the two origin sets — after the warnings, which say what
    // is wrong with the configuration this says the state of; after the
    // bind, since the signed set's bare arm is the bound port's defaults.
    daemon.log_auth_line();
    // The node prefix in force, or its absence (REG-1.69), which the
    // blocked-prefix list's off-board test reads.
    daemon.log_node_prefix();
    // The list installed at open, named beside the warnings (AUTH-4.70: "a
    // restart never lapses a standing block and the startup log names the
    // list in force").
    daemon.log_blocked_prefixes(Moment::AtStart);
    let stop = Arc::new(AtomicBool::new(false));
    let subscribers = Arc::new(Subscribers::new());
    // The accept pair (`operations.md` §1.1 m12; §4 row 33): one tracker
    // across the workers — the episode's flag and its counter behind one
    // `Arc` — so the first failing `accept` on any worker says the failure
    // line once, every worker's failures count into the one episode, and
    // the first success a hold-down after the last failure says the
    // recovery once, with that count.
    let accepts = Arc::new(EdgeTracker::new(EDGE_HOLD_DOWN));
    // Spawned fallibly, and named: `thread::spawn` panics when the OS
    // refuses a thread, and a panic here would unwind out of a half-built
    // handle vector — detaching the workers that did start, with the
    // listener still bound, the journal-directory lock still held, and no
    // `Skepd` in existence for the settled stop to run against.
    let mut handles = Vec::with_capacity(workers);
    let mut refused = None;
    for _ in 0..workers {
        // The workers' thread seam (test seam, `server/hooks.rs`): the next
        // spawns a suite armed meet the seam's error in place of the OS's.
        #[cfg(any(test, feature = "test-hooks"))]
        if let Some(e) = daemon.take_a_worker_thread_fault() {
            refused = Some(e);
            break;
        }
        let daemon = Arc::clone(&daemon);
        let listener = Arc::clone(&listener);
        let stop = Arc::clone(&stop);
        let subscribers = Arc::clone(&subscribers);
        let accepts = Arc::clone(&accepts);
        let spawned = thread::Builder::new().name("skepd-worker".into()).spawn(move || loop {
            if stop.load(Ordering::Acquire) {
                break;
            }
            let accepted = listener.accept();
            // The accept seam (test seam, `server/hooks.rs`): the next `k`
            // accepts a suite armed answer the chosen error in place of the
            // connection they took, which is dropped — so the pair below is
            // driven without exhausting the process's descriptors.
            #[cfg(any(test, feature = "test-hooks"))]
            let accepted = super::hooks::fail_the_accept_if_armed(accepted);
            let stream = match accepted {
                Ok((s, _)) => {
                    // The accept pair's second edge (m12): a success a whole
                    // hold-down after the episode's last failure says the
                    // recovery, once, with every worker's failures counted.
                    say_accept_recovered_if_due(&daemon, &accepts);
                    s
                }
                Err(e) => {
                    // Transient accept failure (EMFILE and kin): said once
                    // across the workers at the first of an episode — the
                    // OS's text names the cause; the act is the operator's,
                    // the descriptor limit — then a brief pause instead of a
                    // spin, and re-check stop.
                    say_accept_failed_once(&daemon, &accepts, &e);
                    thread::sleep(ACCEPT_RETRY_PAUSE);
                    continue;
                }
            };
            // Shutdown's wake connect lands here: the flag, not the
            // connection, is the signal.
            if stop.load(Ordering::Acquire) {
                break;
            }
            serve_connection(&daemon, &subscribers, stream);
            // The fault door's outside arm (test seam): a panic here, after
            // the reply is written and outside the handler's catch, is the
            // shape a worker's death has — the thread ends, the rest serve,
            // and when the last is gone `wait` returns to the binary.
            #[cfg(any(test, feature = "test-hooks"))]
            super::hooks::fire_the_worker_fault_outside_the_catch();
        });
        match spawned {
            Ok(h) => handles.push(h),
            Err(e) => {
                refused = Some(e);
                break;
            }
        }
    }
    // A refused worker costs the whole start, never a half-started server,
    // and spawns nothing more: the pruner and the checkpoint thread are a
    // serving daemon's, so a start being retired runs no pass and no
    // checkpoint and says neither's refusal. The stop joins the workers that
    // did start, ends any stream they already admitted, and releases the
    // listener and the journal-directory lock — so the port this caller is
    // about to retry on is free before it sees the error.
    if let Some(e) = refused {
        Skepd {
            daemon,
            _listener: listener,
            workers: handles,
            subscribers,
            stop,
            pruner: None,
            cadence: Arc::new(Cadence::new()),
            checkpointer: None,
            addr,
            port,
        }
        .shutdown();
        return Err(e);
    }
    // The pruner (`skep-media`'s `pruner.rs`), on a thread of its own: the
    // pass once the cell index's walk at open completes, then on the
    // cadence. A served daemon's — an embedder routing by hand runs no pass
    // but through the hook. Spawned fallibly like the workers; a refused
    // thread costs the cadence and nothing of the serving, and is said.
    let cadence = Arc::new(Cadence::new());
    let pruner = {
        let daemon = Arc::clone(&daemon);
        let cadence = Arc::clone(&cadence);
        thread::Builder::new()
            .name("skepd-pruner".into())
            .spawn(move || prune_on_cadence(&daemon, &cadence))
    };
    let pruner = match pruner {
        Ok(h) => Some(h),
        Err(e) => {
            notice::emit(
                Class::Failure,
                format_args!(
                    "pruner: the OS refused its thread ({e}); no pass runs on this daemon's cadence"
                ),
            );
            None
        }
    };
    // The checkpoint thread, in the pruner's form: spawned fallibly, named,
    // waiting on the write path's signal, stopped and joined at shutdown. A
    // refused thread costs the deferral and nothing of the serving — the
    // kernel's backstop then runs the checkpoint inline at every second
    // crossing — and is said as a failure, in row 22's words: the act (a
    // restart) and what is lost until it.
    let checkpointer = {
        let daemon = Arc::clone(&daemon);
        thread::Builder::new()
            .name("skepd-checkpoint".into())
            .spawn(move || checkpoint_on_due(&daemon, daemon.commits.checkpoint_signal()))
    };
    let checkpointer = match checkpointer {
        Ok(h) => Some(h),
        Err(e) => {
            notice::emit(Class::Failure, CheckpointThreadRefusedLine(&e));
            None
        }
    };
    Ok(Skepd {
        daemon,
        _listener: listener,
        workers: handles,
        subscribers,
        stop,
        pruner,
        cadence,
        checkpointer,
        addr,
        port,
    })
}

impl Skepd {
    /// Returns the bound port (useful under `port = 0`).
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Returns the served daemon, borrowed for the server's lifetime.
    ///
    /// The borrow is long enough to ask it anything, and not long enough to
    /// outlive [`Skepd::shutdown`], whose last act releases the kernel's
    /// journal-directory lock.
    pub fn daemon(&self) -> &Daemon {
        &self.daemon
    }

    /// Blocks until the workers exit: the binary's foreground call.
    ///
    /// In practice that is until the process ends: `wait` consumes the
    /// server, so nothing is left to set the stop flag, and crash-stop is the
    /// shutdown story (M2's WAL makes recovery the clean path, so there is
    /// no signal machinery). A return is every worker having ended — a
    /// panic past the handler's catch, one worker at a time, until none is
    /// left to accept — which the binary says as the failure it is and exits
    /// 1 on. An embedder that wants to stop a running server keeps the
    /// [`Skepd`] and calls [`Skepd::shutdown`] instead. Returning ends every
    /// event stream too, since the server is dropped here.
    pub fn wait(mut self) {
        for h in self.workers.drain(..) {
            let _ = h.join();
        }
    }

    /// Stops the server in order, for embedders and tests.
    ///
    /// It releases and joins the op workers, then ends every event stream —
    /// the commit stream's broadcast wakes each subscriber, which drops its
    /// socket (the client sees a clean close) and exits — and joins those
    /// threads too. Returning releases the kernel's journal-directory lock,
    /// so the same data dir can be reopened.
    ///
    /// Bounded, and by more than one number: a worker mid-request runs to at
    /// most one `TRANSFER_DEADLINE` plus one socket timeout in each
    /// direction — a blob fetch's answer to one `BLOB_TRANSFER_BOUND` plus
    /// one `BLOB_IDLE_BOUND` — plus its handler's own time; then every
    /// subscriber is woken by the commit stream's broadcast, and one blocked
    /// writing to a peer that stopped draining is joined only when its
    /// socket's `WRITE_TIMEOUT` fires — `serve_events` writes without a
    /// deadline by design (see `write_bounded`). So this stop does wait on a
    /// client, for at most that timeout. Interrupting it would mean holding a
    /// second descriptor per live stream, against the budget
    /// `MAX_SUBSCRIBERS` exists to keep.
    ///
    /// Calling it is how a caller learns the stop *finished*; a server that
    /// is merely dropped stops the same way, so a panic between [`serve`]
    /// and here cannot leak the threads or strand the lock.
    ///
    /// The checkpoint thread is stopped and joined last: a checkpoint in
    /// flight is let finish — the data directory is the beneficiary, a
    /// landed base in place of a `.tmp` the next open would remove — and no
    /// further one begins once the stop is asked.
    pub fn shutdown(mut self) {
        self.stop_and_join();
    }

    /// Runs the whole stop.
    ///
    /// It takes `&mut self` so both [`Skepd::shutdown`] and `Drop` run it.
    /// Idempotent through the flag it already owns: a dropped-after-shutdown
    /// server takes the early return, and the joins have already happened.
    fn stop_and_join(&mut self) {
        if self.stop.swap(true, Ordering::AcqRel) {
            return;
        }
        // One wake connect per worker, at the address `wake_addr` names for
        // the one the listener bound: a worker blocked in `accept` returns
        // and the flag breaks its loop. A worker mid-request exits at its
        // next loop check instead, leaving its wake connect unclaimed in the
        // backlog — harmless; the listener drops with the struct.
        for _ in 0..self.workers.len() {
            let _ = TcpStream::connect((wake_addr(self.addr), self.port));
        }
        for h in self.workers.drain(..) {
            let _ = h.join();
        }
        // The workers are gone, so no new subscriber can appear past here.
        self.daemon.commits.shutdown();
        self.subscribers.join_all();
        // The pruner: woken out of its wait at once and joined — a pass in
        // flight runs to its end first, since the pass reads no stop; the
        // arm is held one file at a time.
        self.cadence.stop();
        if let Some(h) = self.pruner.take() {
            let _ = h.join();
        }
        // The checkpoint thread: woken out of its wait at once, joined — a
        // checkpoint in flight let finish, no further one begun.
        self.daemon.commits.checkpoint_signal().stop();
        if let Some(h) = self.checkpointer.take() {
            let _ = h.join();
        }
    }
}

/// Returns where the stop's wake connect dials a listener bound to `bound`.
///
/// It is that address itself — a listener bound to one specific address
/// answers there alone, so loopback would miss it — or loopback where the
/// bind was unspecified (`0.0.0.0`, the hosted image's), which names every
/// interface rather than one to dial, and a listener on every interface
/// answers on loopback.
pub(super) fn wake_addr(bound: Ipv4Addr) -> Ipv4Addr {
    if bound.is_unspecified() {
        Ipv4Addr::LOCALHOST
    } else {
        bound
    }
}

/// Runs the checkpoint thread's loop.
///
/// While the kernel's due flag stands and no stop has been asked, it runs
/// the checkpoint the cadence calls for with its consequences
/// (`Daemon::service_the_checkpoint`) — again where a crossing during the
/// run set the flag anew; then, flag or none, unless the stop has been
/// asked, it follows the backstop (`Daemon::follow_the_backstop`): the write
/// path raises the same signal where a commit's execute ran a checkpoint
/// inline — the kernel's backstop, a second crossing while the first's flag
/// stood — so a wake with no flag is that landing's, and the thread takes
/// the landing's re-reads and says the backstop's line off the kernel's
/// inline count; a wake the flag's arm has just answered with a landing
/// finds the count said and does nothing. Then it waits on the write path's
/// signal for the next crossing or inline run, the standing interval's tick,
/// or the stop. A flag set, or a count moved, before the thread existed (a
/// crossing inside the open's own commits) is read at the first pass,
/// before any wait. A failure is the operator's line per attempt, and the
/// next crossing's to retry: the kernel clears the flag as it starts, so a
/// kernel that cannot checkpoint is not asked again until a commit crosses.
///
/// **And the tick** (`operations.md` §1, the rates). The wait is timed, and
/// at each tick the thread says the standing line
/// (`Daemon::say_the_standing_line`) — one line where a standing bad state
/// stands, nothing on a healthy board — then takes its turn as after any
/// wake.
///
/// **The catch** (row 41). The whole loop runs under `catch_unwind`, and a
/// panic that escapes a turn ends the thread through its catch
/// (`Daemon::the_checkpoint_thread_ended`): the liveness flag and the
/// consequence line, after the hook's line has said the panic itself. No
/// cure — nothing re-spawns the thread but a restart — and the standing line
/// ends with its carrier.
fn checkpoint_on_due(daemon: &Daemon, signal: &CheckpointSignal) {
    let turns = catch_unwind(AssertUnwindSafe(|| loop {
        // The hold (test seam): a suite parks the thread here, before it
        // looks at the flag, so a second crossing meets the flag still set
        // and runs inline as the backstop; the stop reaches a held thread.
        #[cfg(any(test, feature = "test-hooks"))]
        daemon.wait_while_the_checkpoint_thread_is_held(|| signal.is_stopped());
        // The fault (test seam): a panic at the top of a turn, the shape the
        // thread's death has, which the catch below contains.
        #[cfg(any(test, feature = "test-hooks"))]
        daemon.fire_the_checkpoint_threads_fault();
        while !signal.is_stopped() && daemon.checkpoint_is_due() {
            daemon.service_the_checkpoint();
        }
        if !signal.is_stopped() {
            daemon.follow_the_backstop();
        }
        match signal.wait() {
            Woken::Due => {}
            Woken::Tick => daemon.say_the_standing_line(),
            Woken::Stop => return,
        }
    }));
    if turns.is_err() {
        daemon.the_checkpoint_thread_ended();
    }
}

/// The pruner's line under a failed index (`operations.md` §4 row 26).
///
/// It is the words alone: said once through the daemon's classed door under
/// `Class::Failure` as the loop ends by choice ([`prune_on_cadence`]);
/// pinned by the standing suite (`tests/it/standing.rs`).
const PRUNER_NO_PASS_INDEX_FAILED: &str = "pruner: no pass runs — the cell index failed to build";

/// Runs the pruner's loop.
///
/// It waits for the cell index to ready — in short waits, since nothing
/// signals the walk's landing, each ended at once by the stop — runs the
/// pass, then waits the cadence out or the stop, whichever comes first. The
/// pass's line — row 34, or row 35 where a step failed, naming the failure
/// and the compaction's state, since the pass runs its compaction whatever
/// failed before it — goes through the daemon's classed door
/// (`Daemon::say_the_pass`), and the next pass tries again.
///
/// **The failed index** (`operations.md` §4 row 26). Where the index's walk
/// at open died no pass can ever start, so the loop says so once —
/// [`PRUNER_NO_PASS_INDEX_FAILED`], through the daemon's classed door — and
/// returns: the thread ends by choice, not by a death, so no liveness flag
/// is set and the standing line's `the pruner's thread is gone` never
/// comes; its index clause says why no pass runs, and a restart walks again.
///
/// **The catch** (row 41). The whole loop runs under `catch_unwind`, and a
/// panic that escapes a turn ends the thread through its catch
/// (`Daemon::the_pruner_thread_ended`): the liveness flag the standing line
/// reads hourly, and the consequence line, after the hook's line has said
/// the panic itself. No cure but a restart.
fn prune_on_cadence(daemon: &Daemon, cadence: &Cadence) {
    let turns = catch_unwind(AssertUnwindSafe(|| loop {
        // The fault (test seam): a panic at the top of a turn, the shape the
        // thread's death has, which the catch below contains.
        #[cfg(any(test, feature = "test-hooks"))]
        daemon.fire_the_pruners_fault();
        // The failed index: the walk died, so readiness never comes — said
        // once, and the loop ends by choice, no flag set.
        if daemon.media.index_failed() {
            daemon.say(Class::Failure, PRUNER_NO_PASS_INDEX_FAILED);
            return;
        }
        if daemon.index_is_ready_for_pruning() {
            // The pass's own line — row 34, or row 35 where a step failed —
            // through the daemon's classed door.
            daemon.say_the_pass(&daemon.prune_pass());
            if cadence.wait(PRUNE_INTERVAL) == Wake::Stop {
                return;
            }
        } else if cadence.wait(INDEX_READINESS_POLL) == Wake::Stop {
            return;
        }
    }));
    if turns.is_err() {
        daemon.the_pruner_thread_ended();
    }
}

/// The server's `Drop`, which runs the whole stop.
///
/// The threads, the listener and the journal-directory lock are released by
/// dropping the server, not by remembering to ask — so an unwinding test or
/// an early return leaves nothing running and nothing locked. Panic-free by
/// construction (the locks do not poison, and every join and connect is
/// discarded), so it is safe during an unwind.
impl Drop for Skepd {
    fn drop(&mut self) {
        self.stop_and_join();
    }
}

/// Serves one connection: one request read, routed and answered, then closed.
///
/// For `GET /events` it hands the socket to a dedicated subscriber thread
/// and returns at once instead; for an admitted blob fetch it streams the
/// file on this worker ([`stream_fetch`]), the fetch pool's permit held by
/// the answer bounding how many workers do so at once. A handler panic is
/// contained to a 500 so one bad request cannot take a worker down; the
/// panic still prints to stderr for the operator.
fn serve_connection(daemon: &Arc<Daemon>, subscribers: &Subscribers, mut stream: TcpStream) {
    let _ = stream.set_nodelay(true);
    let _ = stream.set_read_timeout(Some(REQUEST_READ_TIMEOUT));
    let _ = stream.set_write_timeout(Some(WRITE_TIMEOUT));
    // The peer's loopback-ness, off the socket itself (AUTH-4.14) — the class
    // is [`Peer::of`]'s, and what this site decides is the unknowable case: a
    // peer whose address cannot be read is `Remote`, never the bare bind's
    // privilege by default. The daemon binds `--bind` (127.0.0.1 by default,
    // so a notebook's every peer is loopback; the container's address in the
    // hosted image, so every proxied peer is `Remote`); deriving the class
    // rather than asserting it is what keeps this site the same whatever
    // address the bind flag names.
    let peer = stream.peer_addr().map_or(Peer::Remote, |a| Peer::of(a.ip()));
    // One deadline per transfer: the socket's own timeouts bound silence and
    // are renewed by any byte, so this is what bounds a peer that is slow
    // rather than quiet. The reply gets its own below, which is what keeps a
    // request refused at its deadline still answerable.
    let deadline = Instant::now() + TRANSFER_DEADLINE;
    let (req, parked) = match read_request(&mut stream, peer, deadline) {
        Ok(Some(read)) => read,
        // A close, or a failed read, before any byte (a port probe,
        // shutdown's wake connect): no request, so no reply owed.
        Ok(None) => return,
        Err(refusal) => {
            let reply = refuse_request(refusal);
            let _ = write_reply(&mut stream, &reply, Instant::now() + TRANSFER_DEADLINE, false);
            return;
        }
    };
    // The unwind-safety assertion is sound rather than convenient:
    // `parking_lot`'s locks do not poison, so a panic under one releases it
    // with the data as it stands, and no structure this daemon guards is
    // mutated across a point that can unwind — the challenge store's map and
    // queue move together under one lock, the sidecar appends before it
    // inserts, and an upload's hold is a guard its stream drops as it
    // unwinds (`skep_media::gate::Hold`). What a panic can cost is the tail
    // of one write, on two cards, and an M10 session, on a third.
    // `Commits::commit_under` runs `execute` under the serialization lock and
    // under a catch of its own (`operations.md` §4 row 34): a panic inside
    // M10 after its commit is caught at the record step, the committed
    // position recorded on the feed as a classified bare entry — its attest
    // line from the marker the write admitted — and announced, before the
    // panic is re-raised to this catch; so the feed holds no hole, and what
    // the write loses is its answer, this `500`. A panic after a credential
    // commit costs a second thing: `credential_sequence`'s tail runs after
    // `commit_under` returns, so the ack goes unmemoized — a retry under the
    // same `id` re-executes and meets the fold's `nothing_changed` or
    // `already_claimed` in place of the original ack — and, where the commit
    // was the claim, the flip's consequences (`H.1`, the warnings, the list)
    // wait for the open, which closes the crash window. It costs no key: the
    // engine steps the World's identity slice inside the commit itself
    // (AUTH-2.80), so the table a committed world carries is never a deposit
    // behind it, and `/op`'s `key_set` and `/op-at`'s at the head agree.
    //
    // The third card is the one panic the router raises by design, OS
    // entropy refused (`Daemon::route`'s card): `POST /session` draws its
    // token after M10 has minted the session the token would name, so the
    // unwind drops a `SessionId` nothing then presents or closes; `GET
    // /challenge` draws before it touches its store and costs nothing.
    let routed = match catch_unwind(AssertUnwindSafe(|| {
        // The fault door's inside arm (test seam): a panic here is one the
        // catch below contains — the request answers `500 internal_panic`
        // and this worker serves its next connection.
        #[cfg(any(test, feature = "test-hooks"))]
        super::hooks::fire_the_worker_fault_inside_the_catch();
        daemon.route_parked(&req, parked)
    })) {
        Ok(r) => r,
        Err(_) => {
            // The kernel's halt, read here (`operations.md` §1.1 m10, the
            // second site): a panic on a write — `POST /op`, the one route
            // that commits; a read frame on it reads the kernel unpoisoned
            // and costs the one load — may be the kernel's own unwind out of
            // its commit region, which poisons it where the repair failed or
            // the barrier had passed and re-raises: this `500` is then the
            // only answer that write gives, and the quiet-board gap closes
            // here rather than at the next write, hours away.
            if req.method == "POST" && req.path == "/op" {
                daemon.say_the_kernels_halt_if_poisoned();
            }
            Routed::Reply(refuse(TransportError::InternalPanic, None))
        }
    };
    match routed {
        Routed::Reply(reply) => {
            // A `HEAD`'s answer is the `GET`'s head and no body — HTTP's
            // rule, kept by the writer (`write_reply`), so the blob fetch's
            // refusals carry the content headers their `GET` would and no
            // byte of it.
            let head_only = req.method == "HEAD";
            let _ = write_reply(&mut stream, &reply, Instant::now() + TRANSFER_DEADLINE, head_only);
            // The deferred step of a replace: the replaced instance's name
            // unlinked after the answer is on the socket, off the request's
            // path — the blob family's requests alone owe one. Under a
            // catch of its own (row 41; §4 row 32), since it runs outside
            // the handler's: a panic inside it is contained, the aside
            // standing for the pass or the next open, the reply already
            // given, and this worker serves its next connection — so a
            // worker's death is reachable by nothing in its loop but
            // `accept`'s error, which pauses and retries.
            if blob_routes::is_blob_path(&req.path) {
                let _ = catch_unwind(AssertUnwindSafe(|| daemon.retire_asides()));
            }
        }
        Routed::EventStream => {
            // The one token-accepting route the accept path resolves itself,
            // since `Daemon::token_route` cannot wear a stream, which is not
            // a `Reply`: the same pair by hand, `resolve_at_head`
            // before the stream opens (AUTH-4.44), so a dead token meets
            // `Skepd-Session: closed` on the stream's own head, written
            // once, at open.
            //
            // Contained like the handler above, and for the reason
            // `Subscribers::admit`'s spawn is fallible: this call sits in
            // the worker's accept loop rather than inside `route`, so a
            // panic here retires the worker for the life of the process —
            // listener still bound, nothing replacing it, no line but the
            // panic hook's. Not hypothetical in a debug build: a live bare
            // binding presented with an `Origin` header that parses
            // reaches `Origin::from_parts`'s debug assert through
            // `bare_origins`. A refusal costs one stream, and dropping the
            // socket is the clean close a budgeted refusal already gives.
            let Ok(closed) = catch_unwind(AssertUnwindSafe(|| daemon.resolve_at_head(&req).closed))
            else {
                return;
            };
            subscribers.admit(Arc::clone(daemon), stream, closed);
        }
        Routed::Fetch(fetch) => {
            // Contained like the handler: the re-check inside resolves the
            // actor again, which is the same code the stream above contains
            // for the same reason. A panic mid-body ends the stream short of
            // its length, as any failure does, but by the socket's drop as
            // this function returns — a clean close, where `stream_fetch`'s
            // own failures reset it; the permit returns with the unwound
            // frame.
            let _ =
                catch_unwind(AssertUnwindSafe(|| stream_fetch(daemon, &req, &mut stream, fetch)));
        }
    }
}

/// Streams an admitted fetch's answer.
///
/// The stream (wire.md §Media, the fetch; the register M-I2 (g)) is the head
/// with the file's length, then — on the `GET`; a `HEAD` is the head alone —
/// the body one [`BLOB_CHUNK`] at a time, each write under the socket's idle
/// bound ([`BLOB_IDLE_BOUND`], renewed by any byte the peer drains and never
/// by silence) and the whole transfer under [`BLOB_TRANSFER_BOUND`]; and
/// between chunks — never before the first, which the gate's own answer
/// covers — the re-resolution at whichever of [`Progress`]'s two intervals
/// comes first: the requester against the head and M10's gate again
/// ([`Daemon::fetch_still_admitted`]). A stream whose requester died, whose
/// gate now withholds, whose peer stopped draining or whose transfer passed
/// its bound is ended by the reset ([`reset_close`]): never a clean close,
/// which a client holding the declared length could read as the whole file.
/// The fetch's permit returns when `fetch` drops at this function's end, on
/// every path.
fn stream_fetch(daemon: &Daemon, req: &HttpRequest, stream: &mut TcpStream, fetch: Fetch<'_>) {
    let _ = stream.set_write_timeout(Some(BLOB_IDLE_BOUND));
    let deadline = Instant::now() + BLOB_TRANSFER_BOUND;
    if write_fetch_head(stream, &fetch, deadline).is_err() {
        reset_close(stream);
        return;
    }
    if req.method == "HEAD" {
        return;
    }
    let mut progress = Progress::new(daemon.fetch_clock_ms());
    let mut chunks = fetch.bytes().chunks(BLOB_CHUNK).peekable();
    while let Some(chunk) = chunks.next() {
        if Instant::now() >= deadline || write_chunk(stream, chunk, deadline).is_err() {
            reset_close(stream);
            return;
        }
        if chunks.peek().is_none() {
            return;
        }
        progress.advance(chunk.len() as u64);
        #[cfg(feature = "test-hooks")]
        STREAM_HOLD.wait();
        let now = daemon.fetch_clock_ms();
        if progress.due(now) {
            if !daemon.fetch_still_admitted(req, fetch.i()) {
                reset_close(stream);
                return;
            }
            progress.reset(now);
        }
    }
}

/// The cap on live `GET /events` streams served at once.
///
/// Each costs one OS thread and holds one descriptor for as long as its
/// client keeps reading, so without a bound a caller opening streams
/// consumes both until one runs out — and the two run out differently. At
/// the descriptor wall `accept` degrades gracefully (the worker loop pauses
/// and retries); a refused thread does not degrade at all, which is why the
/// spawn in [`Subscribers::admit`] is fallible and why this cap sits above
/// it.
///
/// The number reserves the rest of the process's descriptors for the work
/// the daemon exists to do: against the 256 soft limit still common on the
/// platforms this ships to, 64 streams leave the listener and the op pool
/// three quarters of the table. It is an order of magnitude above what a
/// browser will hold against one origin (~6 connections) and above any
/// plausible fleet of local subscribers, so a client reaches it only by
/// trying to.
const MAX_SUBSCRIBERS: usize = 64;

/// Tells the accept pair's first edge (`operations.md` §1.1 m12; §4 row 33).
///
/// A failed `accept` on this worker is told to the one tracker the workers
/// share at the edge clock's instant — the first of an episode says
/// [`AcceptFailedLine`] through the daemon's classed door, once across the
/// workers, the OS's text as the cause; every later failure inside the
/// episode is counted and restarts the hold-down, and says nothing. The
/// pause and the retry are the loop's.
fn say_accept_failed_once(daemon: &Daemon, accepts: &EdgeTracker, e: &io::Error) {
    if let Some(edge) = accepts.refused(edge_clock_now()) {
        daemon.say(edge.class(), AcceptFailedLine(e));
    }
}

/// Tells the accept pair's second edge (m12; §4 row 33).
///
/// A successful `accept` is told to the shared tracker — the first one a
/// whole hold-down after the episode's last failure says
/// [`AcceptRecoveredLine`], once, with every worker's failures counted. A
/// success with no episode standing costs a clock reading and one atomic
/// load, one inside the hold-down the tracker's lock besides, and neither
/// says anything.
fn say_accept_recovered_if_due(daemon: &Daemon, accepts: &EdgeTracker) {
    if let Some(Edge::Landing { refusals }) = accepts.admitted(edge_clock_now()) {
        daemon.say(Class::Landing, AcceptRecoveredLine { failures: refusals });
    }
}

/// The live event streams: the budget, the admission, and the retirement.
///
/// One card, because a stream admitted here is one shutdown must join, and
/// a slot is free only once the thread that held it has finished — two
/// facts about one set that a bare handle vector states neither of.
#[derive(Debug)]
struct Subscribers {
    live: Mutex<Vec<JoinHandle<()>>>,
    /// The budget's edge pair (`operations.md` §1.1 m12; §6's row).
    ///
    /// It is the tracker the admission tells of every stream refused past
    /// the budget and every stream admitted, whose edges it says at once
    /// through the daemon's classed door ([`BudgetEdgeLine`]) — `the
    /// live-stream budget is saturated` at the first refusal of an episode,
    /// `the live-stream budget has room again` at the first admission a
    /// hold-down past its last refusal — once per episode and nothing per
    /// stream.
    edge: EdgeTracker,
    /// The live streams' thread pair (m12's form).
    ///
    /// It is the tracker the admission tells of every stream the OS refused
    /// a thread and every stream given one, whose edges it says at once
    /// through the daemon's classed door ([`StreamThreadLine`]) — the OS's
    /// refusal at the first of an episode, `the OS gives the streams their
    /// threads again` at the first thread given a hold-down past the last
    /// refusal. The budget's pair cannot carry it: the budget has room.
    threads: EdgeTracker,
}

impl Subscribers {
    fn new() -> Subscribers {
        Subscribers {
            live: Mutex::new(Vec::new()),
            edge: EdgeTracker::new(EDGE_HOLD_DOWN),
            threads: EdgeTracker::new(EDGE_HOLD_DOWN),
        }
    }

    /// Admits one stream and gives it its own thread, or refuses it.
    ///
    /// A refusal drops the socket — a clean close before any stream head,
    /// which is the same end a subscriber meets at shutdown and the one a
    /// reconnecting client already handles — each edge of the budget's pair
    /// said once per episode (m12): the first refusal, and the first
    /// admission a hold-down after the last refusal. A stream the budget
    /// admits and the OS refuses a thread is dropped the same way, its own
    /// pair said the same way ([`StreamThreadLine`]).
    fn admit(&self, daemon: Arc<Daemon>, stream: TcpStream, closed: bool) {
        let mut live = self.live.lock();
        // Reap finished threads so the registry tracks live streams, not
        // history — which is also what returns a departed subscriber's slot.
        live.retain(|h| !h.is_finished());
        if live.len() >= MAX_SUBSCRIBERS {
            // The budget's first edge (m12): the stream past the budget is
            // refused — dropped, a clean close before any head — and the
            // first refusal of an episode says so, once, through the
            // daemon's classed door; the rest say nothing and restart the
            // hold-down.
            if let Some(edge) = self.edge.refused(edge_clock_now()) {
                daemon.say(edge.class(), BudgetEdgeLine(edge));
            }
            return;
        }
        // The budget's second edge (m12): admitted — the budget has room —
        // and where that is the first admission a whole hold-down after the
        // episode's last refusal, said once. Judged here, at the budget's
        // own decision: the spawn below is another condition's, not the
        // budget's.
        if let Some(edge) = self.edge.admitted(edge_clock_now()) {
            daemon.say(edge.class(), BudgetEdgeLine(edge));
        }
        // Spawn fallibly. `thread::spawn` panics when the OS refuses a
        // thread, and this call sits outside the handler's `catch_unwind` —
        // a panic here would unwind the worker's accept loop and retire the
        // worker for the life of the process, so a transient resource
        // condition would become a permanent loss of capacity, with the
        // listener still bound and no line but the panic hook's. A refusal
        // must cost one stream, never a worker; the failed spawn drops the
        // closure and with it the socket, which is the clean close above.
        // The spawn's refusal (test seam): the next streams a suite armed
        // meet the seam's error in place of the OS's spawn, no thread made.
        #[cfg(any(test, feature = "test-hooks"))]
        let refused_by_the_seam = daemon.take_a_stream_thread_fault();
        #[cfg(not(any(test, feature = "test-hooks")))]
        let refused_by_the_seam: Option<io::Error> = None;
        // The daemon moves into the closure; this handle says the pair.
        let sayer = Arc::clone(&daemon);
        let spawned = match refused_by_the_seam {
            Some(e) => Err(e),
            None => thread::Builder::new()
                .name("skepd-events".into())
                .spawn(move || serve_events(&daemon, stream, closed)),
        };
        // The thread pair (m12's form): the first refusal of an episode says
        // the OS's cause and the act, once; the first thread given a whole
        // hold-down after the episode's last refusal says the streams have
        // their threads again.
        match spawned {
            Ok(h) => {
                if let Some(edge) = self.threads.admitted(edge_clock_now()) {
                    sayer.say(edge.class(), StreamThreadLine::Again);
                }
                live.push(h);
            }
            Err(e) => {
                if let Some(edge) = self.threads.refused(edge_clock_now()) {
                    sayer.say(edge.class(), StreamThreadLine::Refused(&e));
                }
            }
        }
    }

    /// Joins every live subscriber.
    ///
    /// It is called after the commit stream has broadcast its shutdown, so
    /// each is awake and on its way out — or blocked writing to a peer that
    /// stopped draining, until its socket's `WRITE_TIMEOUT` fires — which is
    /// what keeps this bounded: a wait on a client for at most that timeout.
    fn join_all(&self) {
        for h in std::mem::take(&mut *self.live.lock()) {
            let _ = h.join();
        }
    }
}

/// Serves one subscriber's event stream (wire v4).
///
/// It writes the stream head and the initial event carrying the last
/// announced position, then follows the commit stream — a `commit` event
/// when a later position is announced, a `:ka` comment on silence — until
/// shutdown or the first failed write (a gone subscriber). Exiting drops the
/// socket, which is the client's end-of-stream. Coalescing is inherent: the
/// stream answers "anything past what I last sent", so a burst of commits
/// is one event.
///
/// The initial position comes from
/// [`Commits::announced`](skep_core::commits::Commits::announced) and not
/// from the kernel, which is what keeps every announced position one
/// `GET /changes` already carries — see that method for the window the
/// distinction closes.
fn serve_events(daemon: &Daemon, mut stream: TcpStream, closed: bool) {
    let mut head = response_head(200);
    push_header(&mut head, "Content-Type", "text/event-stream");
    push_header(&mut head, "Cache-Control", "no-cache");
    if closed {
        // The death signal, written once at open (AUTH-4.44): a session
        // dying mid-stream is a stated residue.
        push_header(&mut head, SESSION_HEADER, "closed");
    }
    head.extend_from_slice(b"\r\n");
    if stream.write_all(&head).is_err() {
        return;
    }
    let mut last = daemon.commits.announced();
    if write_commit_event(&mut stream, last).is_err() {
        return;
    }
    loop {
        match daemon.commits.next_step(last) {
            StreamStep::Shutdown => return,
            StreamStep::Commit(at) => {
                last = at;
                if write_commit_event(&mut stream, at).is_err() {
                    return;
                }
            }
            StreamStep::Keepalive => {
                if stream.write_all(b":ka\n\n").is_err() {
                    return;
                }
            }
        }
    }
}
