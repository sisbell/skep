//! The socket server (`Skepd`, `serve`): the worker budget, the accept loop, the event streams.

use std::io::{self, Write};
use std::net::{TcpListener, TcpStream};
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

use super::blob_routes;
use super::http::{
    push_header, read_request, refuse_request, reset_close, response_head, write_chunk,
    write_commit_event, write_fetch_head, write_reply, REQUEST_READ_TIMEOUT, TRANSFER_DEADLINE,
    WRITE_TIMEOUT,
};
use super::reply::{refuse, Fetch, Routed, TransportError, SESSION_HEADER};
use super::request::HttpRequest;
use super::scan::MAX_CONCURRENT_CLASS_SCANS;
use super::{CheckpointThreadRefusedLine, Daemon};
use crate::auth::session::Peer;
use crate::limits::{BLOB_CHUNK, BLOB_IDLE_BOUND, BLOB_TRANSFER_BOUND, PRUNE_INTERVAL};
use crate::write_path::{CheckpointSignal, StreamStep, Woken};

/// The request worker count `skepd` serves with when the operator names
/// none — held HERE rather than in the binary because it is the FIFTH TERM
/// of a budget the other four are meaningless without.
///
/// The four permit pools bound the four expensive surfaces — the
/// reconstruction, the class scan, the blob fetch, which holds a whole file
/// for its answer, and the blob upload, which holds its worker for a whole
/// file's transfer (M-I5 (f)) — and each card argues its own number against
/// the work that surface commands. None prices the SUM, and the sum is what
/// decides whether the bounds do the thing they exist for: a caller holding
/// every permit of all four pools is inside every bound, and if that
/// exhausts the workers the daemon answers nothing — `/health` and
/// `/session` included — with every structure inside it healthy. The
/// relation is therefore `workers >= `[`MIN_WORKERS`], and the assertion
/// below is what keeps it from being arithmetic a reader has to do across
/// four files.
///
/// Ten pooled slots plus two free is the smallest split that keeps the
/// liveness probe, the handshake and the write path answerable while every
/// pool is saturated — the slack the default kept over the minimum before
/// the upload pool, kept. Two free suffice because an ordinary request
/// completes in milliseconds, where a pooled one is a whole-store scan, a
/// whole-world replay or a whole file's transfer — the fetch's, which
/// streams the file out, or the upload's, which streams it in: "a whole
/// file's transfer" reads both ways, and each holds its worker to the end.
///
/// An embedder calling [`serve`] with its own count owes the same relation,
/// and [`MIN_WORKERS`] is the form in which they can evaluate it.
pub const DEFAULT_WORKERS: usize = 12;

/// The smallest worker count that satisfies [`serve`]'s pooled-permit
/// obligation: ONE MORE than the slots the four permit pools hold
/// together, so a caller holding every permit of all four still leaves a
/// worker to answer `/health`, `/session` and the write path.
///
/// PUBLIC because it is the caller's half of an obligation [`serve`] states
/// and deliberately does not re-check: the four pools' own counts are this
/// crate's, so `workers >= MIN_WORKERS` is the only form an embedder naming
/// its own count can evaluate. DERIVED from the four rather than written
/// down, so a pool that moves moves this with it — which is what keeps the
/// obligation and the check on one number.
pub const MIN_WORKERS: usize = crate::history::MAX_CONCURRENT_RECONSTRUCTIONS
    + MAX_CONCURRENT_CLASS_SCANS
    + MAX_CONCURRENT_FETCHES
    + MAX_CONCURRENT_UPLOADS
    + 1;

const _: () = assert!(
    DEFAULT_WORKERS >= MIN_WORKERS,
    "the shipped default must satisfy serve's own pooled-permit obligation: a caller \
     inside every bound would otherwise occupy every worker"
);

// ── the wire loop ────────────────────────────────────────────────────────

/// The running server: the listener, the op workers, the daemon, and the
/// event-stream subscriber threads.
///
/// DROPPING IT STOPS THE SERVER: `Drop` runs the whole stop
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
    /// Held, never read: the workers own clones, so this handle is what
    /// keeps [`Skepd::port`] bound for exactly as long as the server value
    /// exists rather than only while a worker survives.
    _listener: Arc<TcpListener>,
    workers: Vec<JoinHandle<()>>,
    subscribers: Arc<Subscribers>,
    stop: Arc<AtomicBool>,
    /// THE PRUNER's thread and its cadence: the pass runs once the cell
    /// index is ready and then every [`PRUNE_INTERVAL`]; the stop wakes it
    /// at once, and the shutdown joins it.
    pruner: Option<JoinHandle<()>>,
    cadence: Arc<Cadence>,
    /// THE CHECKPOINT THREAD: waits on the write path's signal, runs the
    /// checkpoint the kernel's deferred cadence calls for, off the guard
    /// ([`checkpoint_on_due`]); the stop wakes it at once, and the shutdown
    /// joins it — a run in flight is let finish.
    checkpointer: Option<JoinHandle<()>>,
    port: u16,
}

/// The bound port and the worker count — no lock is taken, so this is safe
/// to reach for from anywhere, including a thread that already holds one.
impl std::fmt::Debug for Skepd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Skepd")
            .field("port", &self.port)
            .field("workers", &self.workers.len())
            .finish_non_exhaustive()
    }
}

/// THE ACCEPT-FAILURE PAUSE — 10 ms, INTERIM (the register's F15): how long
/// a worker whose `accept` failed waits before it tries again, in place of
/// a spin. The failures this meets are transient and clear by themselves —
/// `EMFILE` and kin, a descriptor freed when any connection closes, which
/// is milliseconds on a serving board — so the pause is of that order: long
/// enough that a worker refused at the descriptor wall does not burn a core
/// re-asking, short enough that a connection waiting in the backlog meets a
/// worker again within a few of them. A longer pause would hold every new
/// connection for its length once the wall clears.
const ACCEPT_RETRY_PAUSE: Duration = Duration::from_millis(10);

/// THE PRUNER's READINESS POLL — 250 ms, INTERIM (the register's F15): how
/// often the pruner's thread looks for the cell index's walk at open to
/// complete before its first pass, the one wait of its life with nothing to
/// wake it (the walk's landing raises no signal; the cadence does, after).
/// The walk is seconds to a minute on a large board, so a quarter-second
/// poll costs four wakes a second on a thread that does nothing else
/// meanwhile, bounds the first pass's lag behind the walk at that, and
/// bounds how long the stop waits on a thread parked here.
const INDEX_READINESS_POLL: Duration = Duration::from_millis(250);

/// The listener [`bind`] bound, carrying the port it bound — what the open
/// runs with and [`serve_bound`] serves over. Bound BEFORE the open, so a
/// held port is refused in milliseconds, before the kernel's lock is taken
/// and before anything is written under the data directory; held THROUGH
/// it, so no other process takes the port between the bind and the serve —
/// a connect during the open waits in the socket's backlog and is answered
/// once a worker accepts, where it met a refusal before. Nothing accepts
/// until the workers exist. DROPPING IT RELEASES THE PORT, which is why the
/// type is `#[must_use]`: a `bind(…)?;` statement whose listener falls at
/// the semicolon has bound nothing a serve can use.
#[must_use = "dropping the listener releases the port it bound: hand it to `serve_bound`"]
#[derive(Debug)]
pub struct Listener {
    listener: TcpListener,
    port: u16,
}

impl Listener {
    /// The bound port (the number to serve on under `port = 0`, and the one
    /// [`serve_bound`] binds the auth surface to).
    pub fn port(&self) -> u16 {
        self.port
    }
}

/// Bind `127.0.0.1:port` (`0` = ephemeral) and answer the listener with
/// the port it bound — the FIRST act of a start, before [`Daemon::open_configured`]:
/// a port another process holds is a fault decidable before any byte of the
/// journal is read, so it is refused here, at once, with the open's whole
/// cost unpaid and no `kernel.lock` taken. Nothing accepts on the listener
/// until [`serve_bound`] spawns the workers.
///
/// Failure is the socket's or the OS's: binding the address, or reading
/// back the port it bound — both `io::Error`, which is what lets a caller
/// dispatch on `ErrorKind` — `AddrInUse` to try the next port,
/// `PermissionDenied` for a privileged one — without a downcast.
pub fn bind(port: u16) -> io::Result<Listener> {
    let listener = TcpListener::bind(("127.0.0.1", port))?;
    let port = listener.local_addr()?.port();
    Ok(Listener { listener, port })
}

/// [`bind`] then [`serve_bound`], in sequence — the one-call door for a
/// caller whose open costs nothing worth refusing a held port ahead of (a
/// test's fresh directory, an embedder's own ordering). The binary takes the
/// two apart: the bind first, the open between, the serve after, so a held
/// port refuses the start before the open runs. Everything below holds of
/// this door and of `serve_bound` alike.
///
/// Bind `127.0.0.1:port` (`0` = ephemeral) and serve with `workers`
/// threads. Concurrency policy in full: each worker blocks in `accept`,
/// serves the one request on that connection, closes it — one request per
/// connection, `Connection: close` on every response
/// (`OperationSurface::execute` is `Sync` and M2's single applier
/// serializes writes, so the worker count is the whole op-concurrency
/// story). `GET /events` is the one exception to request/response: the
/// worker hands the socket to a dedicated subscriber thread and returns to
/// `accept` at once, so open streams never occupy the op pool. The
/// [`Skepd`] it answers IS the running server: dropping it stops the server,
/// which is why the type is `#[must_use]`.
///
/// TWO THREADS OF THE DAEMON's OWN run beside the workers: the pruner's,
/// on its cadence, and THE CHECKPOINT THREAD, which waits on the write
/// path's signal and runs the checkpoint the kernel's DEFERRED cadence
/// calls for — every 1024 commits or the byte bound, whichever first — off
/// the write path's guard, so no write waits for it; it re-reads the byte
/// bound and the media floor from the checkpoint that landed, compacts the
/// change feed's files to the journal's reclaim floor, and says a failure
/// once (`Daemon::service_the_checkpoint`). A served daemon's: an EMBEDDER
/// ROUTING BY HAND through [`Daemon::route`] gets no thread and services
/// the flag itself — `Daemon::checkpoint_now` through the test seam, or its
/// own call to the kernel's `checkpoint` — or takes the kernel's backstop,
/// which runs the checkpoint inline on the committing thread at every second
/// crossing and never lets the window grow unbounded.
///
/// PRECONDITION: `workers >= 1`. A count of zero asks for a server that
/// serves nothing, which is a caller's bug rather than an outcome, so it
/// stops here loudly instead of being repaired into a one-worker server —
/// the same posture `MAX_CHANGES_LIMIT` takes on the wire, where an
/// out-of-range page size is refused and never clamped. `main.rs`
/// establishes it by refusing a zero count where the flag is read, which is
/// also what makes its startup line's worker count honest.
///
/// OBLIGATION the count carries: `workers >= `[`MIN_WORKERS`], which leaves
/// a worker free of the four permit pools. A caller holding every permit of
/// all four is INSIDE every bound, so below that count they occupy the
/// whole pool and the daemon answers nothing, `/health` and `/session`
/// included.
/// [`DEFAULT_WORKERS`] satisfies it and carries the assertion that holds it;
/// an embedder naming its own count owes it, and `serve` does NOT re-check —
/// the obligation is the caller's, and [`MIN_WORKERS`] is how they evaluate
/// it.
///
/// SECOND PRECONDITION: `daemon`'s auth port is UNBOUND. `serve` binds it,
/// and a daemon already carrying one has two callers disagreeing about the
/// number every live session's origin set derives from, so the second stops
/// loudly rather than serving under a set nobody chose. The one caller this
/// excludes is a socket-free embedder that called
/// [`Daemon::bind_auth_port`] itself, which is what that method means by
/// calling the two "exclusive by design". Like the count above, a caller's
/// bug rather than an outcome, so it is a panic and not one of the
/// `io::Error`s below.
///
/// Failure is the socket's or the OS's: binding the address, reading back
/// the port it bound, or a refused worker thread — all three `io::Error`,
/// which is what lets a caller dispatch on `ErrorKind` — `AddrInUse` to try
/// the next port, `PermissionDenied` for a privileged one — without a
/// downcast. The first two are [`bind`]'s, the third [`serve_bound`]'s. A
/// refused thread retires whatever has already started before returning, so
/// the port and the journal-directory lock are free for that retry.
pub fn serve(daemon: Daemon, port: u16, workers: usize) -> io::Result<Skepd> {
    serve_bound(daemon, bind(port)?, workers)
}

/// Serve `daemon` over the listener [`bind`] bound, with `workers` threads —
/// everything [`serve`] does after its bind, and the door the binary takes
/// once the open has run with the port already held: the auth surface bound
/// to the listener's port, the configuration warnings, the open's-report
/// `auth:` line (the mode and the two origin sets), the node prefix, the
/// blocked list, the workers, the pruner's thread and the checkpoint thread,
/// in that order (`operations.md` §3.1 step 3) — the workers LAST, since a
/// worker spawned before a daemon exists would route into nothing.
/// [`serve`]'s concurrency policy and its two PRECONDITIONS — `workers >=
/// 1`, the daemon's auth port unbound — are this door's, stated there.
///
/// Failure is the OS's alone: a refused worker thread, an `io::Error`. The
/// listener and the port it bound were the caller's before this call and
/// are released with the retired start, as `serve` releases them.
pub fn serve_bound(daemon: Daemon, listener: Listener, workers: usize) -> io::Result<Skepd> {
    assert!(workers >= 1, "serve requires at least one worker thread (workers = 0)");
    let daemon = Arc::new(daemon);
    let Listener { listener, port } = listener;
    let listener = Arc::new(listener);
    // The auth surface derives its origin sets from the BOUND port, and the
    // startup warnings are logged here — the one thing the glue does with
    // the config before serving (AUTH-4.11). AFTER the bind, and not before:
    // the port-change arm compares each configured origin against the bound
    // port's loopback defaults, so on an unbound config every configured
    // loopback origin would warn.
    daemon.bind_auth_port(port).expect(
        "serve binds the auth port once; a pre-bound daemon has two callers \
         disagreeing about the number every live session's origin set derives from",
    );
    daemon.log_config_warnings(Moment::AtStart);
    // THE OPEN's-REPORT `auth:` LINE (m14): the mode, the flag with its
    // source and the two origin sets — after the warnings, which say what
    // is wrong with the configuration this says the state of; after the
    // bind, since the signed set's bare arm is the BOUND port's defaults.
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
    // Spawned FALLIBLY, and named: `thread::spawn` panics when the OS
    // refuses a thread, and a panic here would unwind out of a half-built
    // handle vector — detaching the workers that did start, with the
    // listener still bound, the journal-directory lock still held, and no
    // `Skepd` in existence for the settled stop to run against.
    let mut handles = Vec::with_capacity(workers);
    let mut refused = None;
    for _ in 0..workers {
        let daemon = Arc::clone(&daemon);
        let listener = Arc::clone(&listener);
        let stop = Arc::clone(&stop);
        let subscribers = Arc::clone(&subscribers);
        let spawned = thread::Builder::new().name("skepd-worker".into()).spawn(move || loop {
            if stop.load(Ordering::Acquire) {
                break;
            }
            let stream = match listener.accept() {
                Ok((s, _)) => s,
                Err(_) => {
                    // Transient accept failure (EMFILE and kin): brief
                    // pause instead of a spin, then re-check stop.
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
            // THE FAULT DOOR's OUTSIDE ARM (test seam): a panic HERE, after
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
    // THE PRUNER (`skep-media`'s `pruner.rs`), on a thread of its own: the pass once
    // the cell index's walk at open completes, then on the cadence. A
    // served daemon's — an embedder routing by hand runs no pass but
    // through the hook. Spawned fallibly like the workers; a refused thread
    // costs the cadence and nothing of the serving, and is said.
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
            notice::line(format_args!(
                "pruner: the OS refused its thread ({e}); no pass runs on this daemon's cadence"
            ));
            None
        }
    };
    // THE CHECKPOINT THREAD, in the pruner's form: spawned fallibly, named,
    // waiting on the write path's signal, stopped and joined at shutdown. A
    // refused thread costs the deferral and nothing of the serving — the
    // kernel's backstop then runs the checkpoint inline at every second
    // crossing — and is said as a failure, in row 22's words: the act (a
    // restart) and what is lost until it.
    let checkpointer = {
        let daemon = Arc::clone(&daemon);
        thread::Builder::new()
            .name("skepd-checkpoint".into())
            .spawn(move || checkpoint_on_due(&daemon, daemon.writes.checkpoint_signal()))
    };
    let checkpointer = match checkpointer {
        Ok(h) => Some(h),
        Err(e) => {
            notice::emit(Class::Failure, CheckpointThreadRefusedLine(&e));
            None
        }
    };
    let server = Skepd {
        daemon,
        _listener: listener,
        workers: handles,
        subscribers,
        stop,
        pruner,
        cadence,
        checkpointer,
        port,
    };
    match refused {
        // A refused thread costs the whole start, never a half-started
        // server: the stop joins the workers that did start, ends any
        // stream they already admitted, and releases the listener and the
        // journal-directory lock — so the port this caller is about to
        // retry on is free before it sees the error.
        Some(e) => {
            server.shutdown();
            Err(e)
        }
        None => Ok(server),
    }
}

impl Skepd {
    /// The bound port (useful under `port = 0`).
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The served daemon, borrowed for the server's lifetime — long enough
    /// to ask it anything, and not long enough to outlive [`Skepd::shutdown`],
    /// whose last act releases the kernel's journal-directory lock.
    pub fn daemon(&self) -> &Daemon {
        &self.daemon
    }

    /// Block until the workers exit — the binary's foreground call. In
    /// practice that is until the process ends: `wait` consumes the server,
    /// so nothing is left to set the stop flag, and crash-stop is the
    /// shutdown story (M2's WAL makes recovery the clean path, so there is
    /// no signal machinery). A RETURN is every worker having ended — a
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

    /// Orderly stop for embedders and tests: release and join the op
    /// workers, then end every event stream — the commit stream's broadcast
    /// wakes each subscriber, which drops its socket (the client sees a
    /// clean close) and exits — and join those threads too. Returning
    /// releases the kernel's journal-directory lock, so the same data dir
    /// can be reopened.
    ///
    /// Bounded, and by more than one number: a worker mid-request runs to at
    /// most one [`TRANSFER_DEADLINE`] plus one socket timeout in each
    /// direction, plus its handler's own time; then every subscriber is woken
    /// by the commit stream's broadcast, and one blocked writing to a peer
    /// that stopped draining is joined only when its socket's
    /// `WRITE_TIMEOUT` fires — `serve_events` writes without a deadline by
    /// design (see `write_bounded`). So this stop does wait on a client,
    /// for at most that timeout. Interrupting it would mean holding a second
    /// descriptor per live stream, against the budget [`MAX_SUBSCRIBERS`]
    /// exists to keep.
    ///
    /// Calling it is how a caller learns the stop *finished*; a server that
    /// is merely dropped stops the same way, so a panic between [`serve`]
    /// and here cannot leak the threads or strand the lock.
    ///
    /// The checkpoint thread is stopped and joined last: a checkpoint in
    /// flight is LET FINISH — the data directory is the beneficiary, a
    /// landed base in place of a `.tmp` the next open would remove — and no
    /// further one begins once the stop is asked.
    pub fn shutdown(mut self) {
        self.stop_and_join();
    }

    /// The whole stop, against `&mut self` so both [`Skepd::shutdown`] and
    /// `Drop` run it. Idempotent through the flag it already owns: a
    /// dropped-after-shutdown server takes the early return, and the joins
    /// have already happened.
    fn stop_and_join(&mut self) {
        if self.stop.swap(true, Ordering::AcqRel) {
            return;
        }
        // One wake connect per worker: a worker blocked in `accept` returns
        // and the flag breaks its loop. A worker mid-request exits at its
        // next loop check instead, leaving its wake connect unclaimed in
        // the backlog — harmless; the listener drops with the struct.
        for _ in 0..self.workers.len() {
            let _ = TcpStream::connect(("127.0.0.1", self.port));
        }
        for h in self.workers.drain(..) {
            let _ = h.join();
        }
        // The workers are gone, so no new subscriber can appear past here.
        self.daemon.writes.shutdown();
        self.subscribers.join_all();
        // The pruner: woken out of its wait at once, joined — at most one
        // file's work past the wake, the arm held one file at a time.
        self.cadence.stop();
        if let Some(h) = self.pruner.take() {
            let _ = h.join();
        }
        // The checkpoint thread: woken out of its wait at once, joined — a
        // checkpoint in flight let finish, no further one begun.
        self.daemon.writes.checkpoint_signal().stop();
        if let Some(h) = self.checkpointer.take() {
            let _ = h.join();
        }
    }
}

/// THE CHECKPOINT THREAD's LOOP: while the kernel's due flag stands and no
/// stop has been asked, run the checkpoint the cadence calls for with its
/// consequences (`Daemon::service_the_checkpoint`) — again where a crossing
/// during the run set the flag anew; then, flag or none, FOLLOW THE
/// BACKSTOP (`Daemon::follow_the_backstop`): the write path raises the same
/// signal where a commit's execute ran a checkpoint inline — the kernel's
/// backstop, a second crossing while the first's flag stood — so a wake
/// with NO flag is that landing's, and the thread takes the landing's
/// re-reads and says the backstop's line off the kernel's inline count; a
/// wake the flag's arm has just answered finds the count said and does
/// nothing. Then wait on the write path's signal for the next crossing or
/// inline run, or the stop. A flag set, or a count moved, before the thread
/// existed (a crossing inside the open's own commits) is read at the first
/// pass, before any wait. A failure is the operator's line per attempt, and
/// the next crossing's to retry: the kernel clears the flag as it starts, so
/// a kernel that cannot checkpoint is not asked again until a commit crosses.
fn checkpoint_on_due(daemon: &Daemon, signal: &CheckpointSignal) {
    loop {
        // THE HOLD (test seam): a suite parks the thread here, before it
        // looks at the flag, so a second crossing meets the flag still set
        // and runs inline as the backstop; the stop reaches a held thread.
        #[cfg(any(test, feature = "test-hooks"))]
        daemon.wait_while_the_checkpoint_thread_is_held(|| signal.is_stopped());
        while !signal.is_stopped() && daemon.checkpoint_is_due() {
            daemon.service_the_checkpoint();
        }
        if !signal.is_stopped() {
            daemon.follow_the_backstop();
        }
        if signal.wait() == Woken::Stop {
            return;
        }
    }
}

/// THE PRUNER's LOOP: wait for the cell index to ready — in short waits, so
/// the stop reaches it — run the pass, then wait the cadence out or the
/// stop, whichever comes first. A pass's I/O failure is the operator's
/// line, and the next pass tries again.
fn prune_on_cadence(daemon: &Daemon, cadence: &Cadence) {
    loop {
        if daemon.index_is_ready_for_pruning() {
            match daemon.prune_pass() {
                // The pass's own line: its figures, the halt, the logs'
                // compaction and any log that has stopped.
                Ok(Some(pass)) => notice::line(pass),
                Ok(None) => {}
                Err(e) => notice::line(format_args!("pruner: the pass failed: {e}")),
            }
            if cadence.wait(PRUNE_INTERVAL) == Wake::Stop {
                return;
            }
        } else if cadence.wait(INDEX_READINESS_POLL) == Wake::Stop {
            return;
        }
    }
}

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

/// Serve one connection: read the one request, route it, write the one
/// reply, close — or, for `GET /events`, hand the socket to a dedicated
/// subscriber thread and return at once — or, for an admitted blob fetch,
/// stream the file on this worker ([`stream_fetch`]), the fetch pool's
/// permit held by the answer bounding how many workers do so at once. A
/// handler panic is contained to a 500 so one bad request cannot take a
/// worker down; the panic still prints to stderr for the operator.
fn serve_connection(daemon: &Arc<Daemon>, subscribers: &Subscribers, mut stream: TcpStream) {
    let _ = stream.set_nodelay(true);
    let _ = stream.set_read_timeout(Some(REQUEST_READ_TIMEOUT));
    let _ = stream.set_write_timeout(Some(WRITE_TIMEOUT));
    // The peer's loopback-ness, off the socket itself (AUTH-4.14) — the class
    // is [`Peer::of`]'s, and what this site decides is the unknowable case: a
    // peer whose address cannot be read is REMOTE, never the bare bind's
    // privilege by default. This daemon binds 127.0.0.1, so every peer is
    // loopback today; deriving it rather than asserting it is what a
    // bind-override needs no change for.
    let peer = stream.peer_addr().map_or(Peer::Remote, |a| Peer::of(a.ip()));
    // One deadline per transfer: the socket's own timeouts bound silence and
    // are renewed by any byte, so this is what bounds a peer that is slow
    // rather than quiet. The reply gets its own below, which is what keeps a
    // request refused AT its deadline still answerable.
    let deadline = Instant::now() + TRANSFER_DEADLINE;
    let (req, parked) = match read_request(&mut stream, peer, deadline) {
        Ok(Some(read)) => read,
        // Clean close before any byte (a port probe, shutdown's wake
        // connect): no request, so no reply owed.
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
    // inserts, and an upload's hold is a guard its stream drops as it unwinds
    // (`skep_media::gate::Hold`). What a panic can cost is the tail of one write,
    // on two cards, and an M10 session, on a third. `WritePath::commit_under`
    // runs `execute` under the serialization lock, so a panic inside M10 after
    // its commit leaves that position unrecorded and unannounced; the reopen
    // walk re-covers it as a bare entry, and the next commit's announcement
    // carries the stream past it. A panic after a CREDENTIAL commit costs a
    // second thing: `credential_sequence`'s tail runs after `commit_under`
    // returns, so the ack goes unmemoized — a retry under the same `id`
    // re-executes and meets the fold's `nothing_changed` or
    // `already_claimed` in place of the original ack — and, where the commit
    // was the claim, the flip's consequences (`H.1`, the warnings, the list)
    // wait for the open, which closes the crash window. It costs NO key: the
    // engine steps the World's identity slice inside the commit itself
    // (AUTH-2.80), so the table a committed world carries is never a deposit
    // behind it — the window that stood here, a live fold left one deposit
    // short of the committed world until restart, with `/op`'s `key_set` and
    // `/op-at`'s at the head disagreeing meanwhile, is CLOSED.
    //
    // The third card is the one panic the router raises by design, OS
    // entropy refused (`Daemon::route`'s card): `POST /session` draws its
    // token after M10 has minted the session the token would name, so the
    // unwind drops a `SessionId` nothing then presents or closes; `GET
    // /challenge` draws before it touches its store and costs nothing.
    let routed = match catch_unwind(AssertUnwindSafe(|| {
        // THE FAULT DOOR's INSIDE ARM (test seam): a panic HERE is one the
        // catch below contains — the request answers `500 internal_panic`
        // and this worker serves its next connection.
        #[cfg(any(test, feature = "test-hooks"))]
        super::hooks::fire_the_worker_fault_inside_the_catch();
        daemon.route_parked(&req, parked)
    })) {
        Ok(r) => r,
        Err(_) => Routed::Reply(refuse(TransportError::InternalPanic, None)),
    };
    match routed {
        Routed::Reply(reply) => {
            // A `HEAD`'s answer is the `GET`'s head and no body — HTTP's
            // rule, kept by the writer (`write_reply`), so the blob fetch's
            // refusals carry the content headers their `GET` would and no
            // byte of it.
            let head_only = req.method == "HEAD";
            let _ = write_reply(&mut stream, &reply, Instant::now() + TRANSFER_DEADLINE, head_only);
            // THE DEFERRED STEP of a replace: the replaced instance's name
            // unlinked AFTER the answer is on the socket, off the request's
            // path — the blob family's requests alone owe one.
            if blob_routes::is_blob_path(&req.path) {
                daemon.retire_asides();
            }
        }
        Routed::EventStream => {
            // The one token-accepting route `Daemon::token_route` cannot
            // wear, because a stream is not a `Reply`: the same pair by
            // hand, `resolve_at_head` before the stream OPENS (AUTH-4.44), so
            // a dead token meets `Skepd-Session: closed` on the stream's
            // own head, written once, at open.
            //
            // Contained like the handler above, and for the reason
            // `Subscribers::admit`'s spawn is fallible: this call sits in
            // the worker's accept loop rather than inside `route`, so a
            // panic here retires the worker for the life of the process —
            // listener still bound, nothing replacing it, no line
            // anywhere. Not hypothetical in a debug build: a live BARE
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
            // its length, as any failure does; the permit returns with the
            // unwound frame.
            let _ =
                catch_unwind(AssertUnwindSafe(|| stream_fetch(daemon, &req, &mut stream, fetch)));
        }
    }
}

/// THE FETCH's STREAM (wire.md §Media, THE FETCH; the register M-I2 (g);
/// the rulings s6-E1 (a), s6-leak-b): the head with the file's length, then
/// — on the `GET`; a `HEAD` is the head alone — the body one [`BLOB_CHUNK`]
/// at a time, each write under the socket's IDLE BOUND ([`BLOB_IDLE_BOUND`],
/// renewed by any byte the peer drains and never by silence) and the whole
/// transfer under [`BLOB_TRANSFER_BOUND`]; and BETWEEN CHUNKS — never before
/// the first, which the gate's own answer covers — the re-resolution at
/// whichever of [`Progress`]'s two intervals comes first: the requester
/// against the head and M10's gate again ([`Daemon::fetch_still_admitted`]).
/// A stream whose requester died, whose gate now withholds, whose peer
/// stopped draining or whose transfer passed its bound is ended by THE RESET
/// ([`reset_close`]): never a clean close, which a client holding the
/// declared length could read as the whole file. The fetch's permit returns
/// when `fetch` drops at this function's end, on every path.
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

/// Live `GET /events` streams served at once. Each costs one OS thread and
/// holds one descriptor for as long as its client keeps reading, so without
/// a bound a caller opening streams consumes both until one runs out — and
/// the two run out differently. At the descriptor wall `accept` degrades
/// gracefully (the worker loop pauses and retries); a refused thread does
/// not degrade at all, which is why the spawn in [`Subscribers::admit`] is
/// fallible and why this cap sits above it.
///
/// The number reserves the rest of the process's descriptors for the work
/// the daemon exists to do: against the 256 soft limit still common on the
/// platforms this ships to, 64 streams leave the listener and the op pool
/// three quarters of the table. It is an order of magnitude above what a
/// browser will hold against one origin (~6 connections) and above any
/// plausible fleet of local subscribers, so a client reaches it only by
/// trying to.
const MAX_SUBSCRIBERS: usize = 64;

/// The live event streams: the budget, the admission, and the retirement.
/// One card, because a stream admitted here is one shutdown must join, and
/// a slot is free only once the thread that held it has finished — two
/// facts about one set that a bare handle vector states neither of.
#[derive(Debug)]
struct Subscribers {
    live: Mutex<Vec<JoinHandle<()>>>,
}

impl Subscribers {
    fn new() -> Subscribers {
        Subscribers { live: Mutex::new(Vec::new()) }
    }

    /// Admit one stream and give it its own thread, or refuse it by dropping
    /// the socket — a clean close before any stream head, which is the same
    /// end a subscriber meets at shutdown and the one a reconnecting client
    /// already handles.
    fn admit(&self, daemon: Arc<Daemon>, stream: TcpStream, closed: bool) {
        let mut live = self.live.lock();
        // Reap finished threads so the registry tracks live streams, not
        // history — which is also what returns a departed subscriber's slot.
        live.retain(|h| !h.is_finished());
        if live.len() >= MAX_SUBSCRIBERS {
            return;
        }
        // Spawn FALLIBLY. `thread::spawn` panics when the OS refuses a
        // thread, and this call sits outside the handler's `catch_unwind` —
        // a panic here would unwind the worker's accept loop and retire the
        // worker for the life of the process, so a transient resource
        // condition would become a permanent, silent loss of capacity with
        // the listener still bound. A refusal must cost one stream, never a
        // worker; the failed spawn drops the closure and with it the socket,
        // which is the clean close above.
        let spawned = thread::Builder::new()
            .name("skepd-events".into())
            .spawn(move || serve_events(&daemon, stream, closed));
        if let Ok(h) = spawned {
            live.push(h);
        }
    }

    /// Join every live subscriber. Called after the commit stream has
    /// broadcast its shutdown, so each is already awake and on its way out
    /// — which is what keeps this bounded rather than a wait on a client.
    fn join_all(&self) {
        for h in std::mem::take(&mut *self.live.lock()) {
            let _ = h.join();
        }
    }
}

/// One subscriber (wire v4): write the stream head and the initial event
/// carrying the last announced position, then follow the commit stream — a
/// `commit` event when a later position is announced, a `:ka` comment on
/// silence — until shutdown or the first failed write (a gone subscriber).
/// Exiting drops the socket, which is the client's end-of-stream. Coalescing
/// is inherent: the stream answers "anything past what I last sent", so a
/// burst of commits is one event.
///
/// The initial position comes from [`WritePath::announced`](crate::write_path::WritePath::announced) and not from
/// the kernel, which is what keeps every announced position one
/// `GET /changes` already carries — see that method for the window the
/// distinction closes.
fn serve_events(daemon: &Daemon, mut stream: TcpStream, closed: bool) {
    let mut head = response_head(200);
    push_header(&mut head, "Content-Type", "text/event-stream");
    push_header(&mut head, "Cache-Control", "no-cache");
    if closed {
        // The death signal, written ONCE at open (AUTH-4.44): a session
        // dying mid-stream is a stated residue.
        push_header(&mut head, SESSION_HEADER, "closed");
    }
    head.extend_from_slice(b"\r\n");
    if stream.write_all(&head).is_err() {
        return;
    }
    let mut last = daemon.writes.announced();
    if write_commit_event(&mut stream, last).is_err() {
        return;
    }
    loop {
        match daemon.writes.next_step(last) {
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
