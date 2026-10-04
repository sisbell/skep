//! The socket server (`Skepd`, `serve`): the worker budget, the accept loop, the event streams.

use std::io::{self, Write};
use std::net::{TcpListener, TcpStream};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use parking_lot::Mutex;

use super::blob_routes;
use super::http::{
    push_header, read_request, refuse_request, response_head, write_commit_event, write_reply,
    REQUEST_READ_TIMEOUT, TRANSFER_DEADLINE, WRITE_TIMEOUT,
};
use super::reply::{refuse, Routed, TransportError, SESSION_HEADER};
use super::scan::MAX_CONCURRENT_CLASS_SCANS;
use super::{Daemon, Moment};
use crate::auth::session::Peer;
use crate::limits::PRUNE_INTERVAL;
use crate::media::pruner::{Cadence, Wake};
use crate::notice;
use crate::write_path::StreamStep;

/// The request worker count `skepd` serves with when the operator names
/// none — held HERE rather than in the binary because it is the THIRD TERM
/// of a budget the other two are meaningless without.
///
/// The two permit pools bound the two expensive read surfaces, and each
/// card argues its own number against the work that surface commands.
/// Neither prices the SUM, and the sum is what decides whether the bounds
/// do the thing they exist for: a caller holding every permit of both pools
/// is inside both bounds, and if that exhausts the workers the daemon
/// answers nothing — `/health` and `/session` included — with every
/// structure inside it healthy. The relation is therefore
/// `workers >= `[`MIN_WORKERS`], and the assertion below is what keeps it
/// from being arithmetic a reader has to do across two files.
///
/// Four pooled slots plus two free is the smallest split that keeps the
/// liveness probe, the handshake and the write path answerable while both
/// pools are saturated. Two free suffice because an ordinary request
/// completes in milliseconds, where a pooled one is a whole-store scan or a
/// whole-world replay.
///
/// An embedder calling [`serve`] with its own count owes the same relation,
/// and [`MIN_WORKERS`] is the form in which they can evaluate it.
pub const DEFAULT_WORKERS: usize = 6;

/// The smallest worker count that satisfies [`serve`]'s pooled-permit
/// obligation: ONE MORE than the slots the two permit pools hold together,
/// so a caller holding every permit of both still leaves a worker to answer
/// `/health`, `/session` and the write path.
///
/// PUBLIC because it is the caller's half of an obligation [`serve`] states
/// and deliberately does not re-check: the two pools' own counts are this
/// crate's, so `workers >= MIN_WORKERS` is the only form an embedder naming
/// its own count can evaluate. DERIVED from the two rather than written
/// down, so a pool that moves moves this with it — which is what keeps the
/// obligation and the check on one number.
pub const MIN_WORKERS: usize =
    crate::history::MAX_CONCURRENT_RECONSTRUCTIONS + MAX_CONCURRENT_CLASS_SCANS + 1;

const _: () = assert!(
    DEFAULT_WORKERS >= MIN_WORKERS,
    "the shipped default must satisfy serve's own pooled-permit obligation: a caller \
     inside both bounds would otherwise occupy every worker"
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
/// PRECONDITION: `workers >= 1`. A count of zero asks for a server that
/// serves nothing, which is a caller's bug rather than an outcome, so it
/// stops here loudly instead of being repaired into a one-worker server —
/// the same posture `MAX_CHANGES_LIMIT` takes on the wire, where an
/// out-of-range page size is refused and never clamped. `main.rs`
/// establishes it by refusing a zero count where the flag is read, which is
/// also what makes its startup line's worker count honest.
///
/// OBLIGATION the count carries: `workers >= `[`MIN_WORKERS`], which leaves
/// a worker free of the two permit pools. A caller holding every permit of
/// both is INSIDE both bounds, so below that count they occupy the whole
/// pool and the daemon answers nothing, `/health` and `/session` included.
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
/// downcast. A refused thread retires whatever has already started before
/// returning, so the port and the journal-directory lock are free for that
/// retry.
pub fn serve(daemon: Daemon, port: u16, workers: usize) -> io::Result<Skepd> {
    assert!(workers >= 1, "serve requires at least one worker thread (workers = 0)");
    let daemon = Arc::new(daemon);
    let listener = Arc::new(TcpListener::bind(("127.0.0.1", port))?);
    let port = listener.local_addr()?.port();
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
                    thread::sleep(Duration::from_millis(10));
                    continue;
                }
            };
            // Shutdown's wake connect lands here: the flag, not the
            // connection, is the signal.
            if stop.load(Ordering::Acquire) {
                break;
            }
            serve_connection(&daemon, &subscribers, stream);
        });
        match spawned {
            Ok(h) => handles.push(h),
            Err(e) => {
                refused = Some(e);
                break;
            }
        }
    }
    // THE PRUNER (`media/pruner.rs`), on a thread of its own: the pass once
    // the cell index's walk at open completes, then on the cadence. A
    // served daemon's — an embedder routing by hand runs no pass but
    // through the hook. Spawned fallibly like the workers; a refused thread
    // costs the cadence and nothing of the serving, and is said.
    let cadence = Arc::new(Cadence::new());
    let pruner = {
        let daemon = Arc::clone(&daemon);
        let cadence = Arc::clone(&cadence);
        thread::Builder::new().name("skepd-pruner".into()).spawn(move || prune_on_cadence(&daemon, &cadence))
    };
    let pruner = match pruner {
        Ok(h) => Some(h),
        Err(e) => {
            notice::line(format_args!("pruner: the OS refused its thread ({e}); no pass runs on this daemon's cadence"));
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
    /// no signal machinery). An embedder that wants to stop a running server
    /// keeps the [`Skepd`] and calls [`Skepd::shutdown`] instead. Returning
    /// would end every event stream too, since the server is dropped here.
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
    /// [`WRITE_TIMEOUT`] fires — `serve_events` writes without a deadline by
    /// design (see `write_bounded`). So this stop does wait on a client,
    /// for at most that timeout. Interrupting it would mean holding a second
    /// descriptor per live stream, against the budget [`MAX_SUBSCRIBERS`]
    /// exists to keep.
    ///
    /// Calling it is how a caller learns the stop *finished*; a server that
    /// is merely dropped stops the same way, so a panic between [`serve`]
    /// and here cannot leak the threads or strand the lock.
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
                Ok(Some(pass)) => notice::line(format_args!(
                    "pruner: {} expired partials removed, {} files unlinked, {} kept, {} asides removed{}",
                    pass.expired_partials,
                    pass.unlinked,
                    pass.kept,
                    pass.asides,
                    pass.halted.as_deref().map_or(String::new(), |why| format!(" — the unlink pass halted: {why}"))
                )),
                Ok(None) => {}
                Err(e) => notice::line(format_args!("pruner: the pass failed: {e}")),
            }
            if cadence.wait(PRUNE_INTERVAL) == Wake::Stop {
                return;
            }
        } else if cadence.wait(Duration::from_millis(250)) == Wake::Stop {
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
/// subscriber thread and return at once. A handler panic is contained to a
/// 500 so one bad request cannot take a worker down; the panic still prints
/// to stderr for the operator.
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
    let req = match read_request(&mut stream, peer, deadline) {
        Ok(Some(r)) => r,
        // Clean close before any byte (a port probe, shutdown's wake
        // connect): no request, so no reply owed.
        Ok(None) => return,
        Err(refusal) => {
            let reply = refuse_request(refusal);
            let _ = write_reply(&mut stream, &reply, Instant::now() + TRANSFER_DEADLINE);
            return;
        }
    };
    // The unwind-safety assertion is sound rather than convenient:
    // `parking_lot`'s locks do not poison, so a panic under one releases it
    // with the data as it stands, and no structure this daemon guards is
    // mutated across a point that can unwind — the challenge store's map and
    // queue move together under one lock, and the sidecar appends before it
    // inserts. What a panic can cost is the tail of one write, on two
    // cards, and an M10 session, on a third. `WritePath::commit_under` runs
    // `execute` under the serialization lock, so a panic inside M10 after
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
    let routed = match catch_unwind(AssertUnwindSafe(|| daemon.route(&req))) {
        Ok(r) => r,
        Err(_) => Routed::Reply(refuse(TransportError::InternalPanic, None)),
    };
    match routed {
        Routed::Reply(reply) => {
            let _ = write_reply(&mut stream, &reply, Instant::now() + TRANSFER_DEADLINE);
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
            let Ok(closed) =
                catch_unwind(AssertUnwindSafe(|| daemon.resolve_at_head(&req).closed))
            else {
                return;
            };
            subscribers.admit(Arc::clone(daemon), stream, closed);
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
