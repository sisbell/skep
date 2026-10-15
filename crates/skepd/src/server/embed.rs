//! THE EMBEDDING HELPER: the start a program that is NOT `skepd` takes to
//! run the daemon in its own process — [`embed`]: the bind, the open, the
//! serve, in the binary's order, the open retried where the journal
//! directory's lock alone stands in its way — and the wait for the cell
//! index's walk at open, [`Skepd::wait_for_the_index`]. One sequence, so an
//! embedding program, the dev provider's in-process node and the suites
//! start a daemon one way, and the retry, the wait's deadline and the
//! origin's port drift in no copy.
//!
//! TWO CALLS, NOT ONE. The daemon serves from the moment the start returns,
//! and the walk runs behind it — seconds to a minute on a large board —
//! while the index's three readers refuse `index_rebuilding` (wire.md
//! §Media): a caller that shows the board starting needs the server before
//! the walk is done, and one that wants both calls both.
//!
//! FEATURE-FREE: nothing either call reaches compiles under `test-hooks`, so
//! an embedding program's build carries no test door; the suites' seeded
//! start beside them is a test hook, compiled under that feature alone.
//!
//! THE BINARY KEEPS ITS OWN DOOR: `main.rs` runs the same three steps with
//! its own acts between them — the panic hook installed first, a loose data
//! directory refused before the open, each refusal said and exited on — and
//! calls neither. The library's open takes the directory as it finds it; an
//! embedding program that wants that refusal, or a panic posture, makes it
//! its own.

use std::error::Error;
use std::fmt;
use std::io;
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

use skep_media::MediaOptions;

use super::listen::{bind, serve_bound, Skepd};
use super::{Daemon, DaemonError};
use skep_core::auth::AuthOptions;

/// THE OPEN's ATTEMPTS — twelve, [`OPEN_RETRY_PAUSE`] apart — for the ONE
/// condition a start retries ([`lost_the_lock_race`]). A start over the
/// SAME data directory as a stop just made — an embedding program's
/// restart, a suite's reopen — meets the kernel's journal-directory flock
/// from the daemon just dropped, which is not always re-acquirable the
/// instant its close returns, under the parallel suite's load: a transient
/// `WouldBlock` at open. It is not a bad data directory — a fresh one, or
/// one this process itself just held — so it is retried with a brief pause
/// to let the release land, the listener bound afresh each attempt: an
/// ephemeral port fresh each time, a fixed port re-bound. ANY OTHER open
/// error is a real fault and is answered at once.
const OPEN_ATTEMPTS: usize = 12;

/// THE PAUSE between two attempts of the open — 25 ms: long enough for a
/// dropped kernel's lock release to land, short enough that the attempts
/// together stay under a third of a second ([`OPEN_ATTEMPTS`]).
const OPEN_RETRY_PAUSE: Duration = Duration::from_millis(25);

/// THE WAIT's POLL — 5 ms, the suites' figure: how often
/// [`Skepd::wait_for_the_index`] reads the index's readiness, the walk's
/// completion raising no signal of its own. A wake every 5 ms is cheap
/// beside a walk of seconds, and the answer comes within 5 ms of the
/// completion.
const INDEX_POLL: Duration = Duration::from_millis(5);

/// THE START: bind `127.0.0.1:port` (`0` for an ephemeral port), open the
/// board at `data_dir` — genesis on a fresh directory, recovery on a used
/// one — and serve it with `workers` threads, in the binary's order: a held
/// port is refused before the kernel's lock is taken and before anything is
/// written under the directory, and nothing can take the port between the
/// bind and the serve ([`bind`], [`Daemon::open_configured`],
/// [`serve_bound`]). Answers the running server as the serve answers it, the
/// cell index's walk at open running behind it — [`Skepd::wait_for_the_index`]
/// is the wait. Dropping the [`Skepd`] stops the server, and
/// [`Skepd::shutdown`] is the orderly stop, whose return releases the
/// directory for the next start.
///
/// `auth` answers the session layer's options for the port the bind chose,
/// called with that port once per attempt: a configured origin names the
/// port the board answers at — `http://127.0.0.1:{port}`, for a client
/// dialing its own node over loopback — and an ephemeral port is known only
/// once bound, and bound afresh at each attempt. A caller whose options name
/// no port answers the same options at every call. `media` is the media
/// resource's configuration, the upload setting among it.
///
/// THE RETRY, BOUNDED: the open is retried — twelve attempts, 25 ms apart
/// (`OPEN_ATTEMPTS`, `OPEN_RETRY_PAUSE`), the listener dropped and bound
/// afresh each time — ONLY where the refusal's `source` chain carries an
/// [`io::Error`] of kind [`io::ErrorKind::WouldBlock`]: the journal
/// directory's lock, which a stop just made over the same directory may not
/// yet have released ([`Daemon::open`]'s PRECONDITION). Every other refusal
/// is answered at once, and so is the twelfth of the lock's.
///
/// Failure names its step ([`EmbedError`]): the bind's `io::Error` —
/// `AddrInUse` where another process holds a fixed port, at any attempt's
/// bind, nothing opened; the open's [`DaemonError`]; the serve's
/// `io::Error`, a refused worker thread, the start retired and the directory
/// released.
///
/// PRECONDITION: `workers >= 1`, which panics — [`serve_bound`]'s; and
/// `workers >=` [`MIN_WORKERS`](super::MIN_WORKERS) is the caller's
/// obligation, as it is [`serve`](super::serve)'s, which
/// [`DEFAULT_WORKERS`](super::DEFAULT_WORKERS) meets.
pub fn embed(
    data_dir: impl AsRef<Path>,
    port: u16,
    auth: impl FnMut(u16) -> AuthOptions,
    media: MediaOptions,
    workers: usize,
) -> Result<Skepd, EmbedError> {
    let data_dir = data_dir.as_ref();
    start(port, auth, workers, |opts| Daemon::open_configured(data_dir, opts, media.clone()))
}

/// TEST HOOK (the `fuzz_support` standing: `#[doc(hidden)]`, not a stable
/// API): [`embed`] under the SEEDED salt source — `Daemon::open_seeded`'s,
/// every transaction's salt a pure function of the seed and the position —
/// in place of OS entropy, the media resource at its default: the suites'
/// seeded spawn, which the head suite's determinism pins take, through the
/// same bind, retry and serve. NEVER an embedding program's: the seeded
/// stream is the predictability the salt exists to deny a reader of
/// `/chain?at=N`.
#[cfg(any(test, feature = "test-hooks"))]
#[doc(hidden)]
pub fn embed_seeded(
    data_dir: impl AsRef<Path>,
    port: u16,
    auth: impl FnMut(u16) -> AuthOptions,
    workers: usize,
    seed: u64,
) -> Result<Skepd, EmbedError> {
    let data_dir = data_dir.as_ref();
    start(port, auth, workers, |opts| Daemon::open_seeded(data_dir, opts, seed))
}

/// THE ONE SEQUENCE behind [`embed`] and the seeded start: each attempt binds
/// the port, asks `auth` for the options at the port bound and hands them to
/// `open`; an open the lock alone refused ([`lost_the_lock_race`]) drops the
/// listener, pauses and goes again, up to [`OPEN_ATTEMPTS`]; an open that
/// succeeds is served over the listener it ran under.
fn start(
    port: u16,
    mut auth: impl FnMut(u16) -> AuthOptions,
    workers: usize,
    mut open: impl FnMut(AuthOptions) -> Result<Daemon, DaemonError>,
) -> Result<Skepd, EmbedError> {
    let mut attempt = 1;
    loop {
        let listener = bind(port).map_err(EmbedError::Bind)?;
        match open(auth(listener.port())) {
            Ok(daemon) => return serve_bound(daemon, listener, workers).map_err(EmbedError::Serve),
            Err(e) if attempt < OPEN_ATTEMPTS && lost_the_lock_race(&e) => {
                drop(listener);
                thread::sleep(OPEN_RETRY_PAUSE);
                attempt += 1;
            }
            Err(e) => return Err(EmbedError::Open(e)),
        }
    }
}

/// Whether an open's refusal is the journal directory's LOCK alone — the
/// flock of a kernel just dropped over the same directory, not yet
/// re-acquirable — rather than a fault: the refusal's `source` chain walked
/// to its first [`io::Error`], and that error's kind
/// [`io::ErrorKind::WouldBlock`], which `Kernel::open` surfaces from
/// `flock(LOCK_EX | LOCK_NB)` (`OpenError::Io`). Only that kind is retried;
/// a bad checkpoint, a corrupt journal or a directory refusing I/O is a
/// real condition and stops the start.
fn lost_the_lock_race(err: &DaemonError) -> bool {
    let mut cause: Option<&(dyn Error + 'static)> = Some(err);
    while let Some(e) = cause {
        if let Some(io) = e.downcast_ref::<io::Error>() {
            return io.kind() == io::ErrorKind::WouldBlock;
        }
        cause = e.source();
    }
    false
}

impl Skepd {
    /// THE WAIT: block until the cell index's walk at open has completed —
    /// [`Daemon::index_is_ready`], read every 5 ms (`INDEX_POLL`) — or until
    /// `deadline` has passed, answering [`IndexNotReady`] then. The second
    /// call beside [`embed`], apart from it so a caller can say the board is
    /// starting while the walk runs: the server answers throughout, the
    /// index's three readers refusing `index_rebuilding` until the walk
    /// completes. A walk that DIED never completes (`operations.md` §4 row
    /// 26), so the wait runs out its deadline over one, the three readers
    /// refusing `index_failed` meanwhile and after. Answers at once where the
    /// walk has completed, a zero deadline included; a deadline no `Instant`
    /// can reach waits as long as the walk takes.
    pub fn wait_for_the_index(&self, deadline: Duration) -> Result<(), IndexNotReady> {
        let until = Instant::now().checked_add(deadline);
        while !self.daemon().index_is_ready() {
            let left = match until {
                Some(until) => until.saturating_duration_since(Instant::now()),
                None => INDEX_POLL,
            };
            if left.is_zero() {
                return Err(IndexNotReady(deadline));
            }
            thread::sleep(INDEX_POLL.min(left));
        }
        Ok(())
    }
}

/// [`embed`] refused, naming the STEP that refused — the bind, the open or
/// the serve — with that step's own error, so a caller's face can say which
/// and a reporter walking `source` reaches the cause. Exhaustive: the three
/// steps are the whole sequence, and a caller's match names each.
#[derive(Debug)]
pub enum EmbedError {
    /// The bind refused the port — `AddrInUse` where another process holds a
    /// fixed one, `PermissionDenied` for a privileged one. Nothing was opened
    /// at that attempt: no lock taken, nothing written under the directory.
    Bind(io::Error),
    /// The open refused the board — at once, or where the journal
    /// directory's lock refused it, at the twelfth attempt; what each
    /// condition asks of an operator is [`Daemon::open`]'s to state.
    Open(DaemonError),
    /// The serve refused: the OS refused a worker thread. The start is
    /// retired — the workers that started stopped, the port and the
    /// directory released.
    Serve(io::Error),
}

impl fmt::Display for EmbedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EmbedError::Bind(e) => write!(f, "bind: {e}"),
            EmbedError::Open(e) => write!(f, "open: {e}"),
            EmbedError::Serve(e) => write!(f, "serve: the OS refused a worker thread: {e}"),
        }
    }
}

/// `Display` names the step and its cause on one line, as [`DaemonError`]'s
/// does, and `source` exposes the cause as a link.
impl Error for EmbedError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            EmbedError::Bind(e) | EmbedError::Serve(e) => Some(e),
            EmbedError::Open(e) => Some(e),
        }
    }
}

/// [`Skepd::wait_for_the_index`] ran out its deadline: the cell index's walk
/// at open had not completed within it. The daemon serves on, the index's
/// three readers refusing `index_rebuilding` until the walk completes — or
/// `index_failed` for the uptime, where it died. Carries the deadline the
/// wait was given.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IndexNotReady(Duration);

impl IndexNotReady {
    /// The deadline the wait ran out.
    pub fn deadline(self) -> Duration {
        self.0
    }
}

impl fmt::Display for IndexNotReady {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "the cell index's walk did not complete within {:?}", self.0)
    }
}

impl Error for IndexNotReady {}

#[cfg(test)]
mod tests;
