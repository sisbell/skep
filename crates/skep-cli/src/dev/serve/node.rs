//! The daemon's two modes: a running board dialed, or the daemon in-process.
//!
//! Without `--own` the provider dials a daemon that is already running —
//! the local record's recipe — and the fault route answers that it is not
//! built in. With `--own`, in a build with the `dev-hooks` feature, the
//! daemon runs in-process with its `test-hooks` doors (started as
//! `tests/it/common.rs`'s spawn starts it and an embedding app would:
//! `skepd::embed`, then the wait for its cell index) under its keeper
//! ([`Keeper`]): one thread that owns the running daemon and the fault
//! doors' permits, every start, stop and door reaching it as a message, so
//! a stop and a later start replace the daemon. Every start is at the port
//! the first one bound, so the board's origin stands, and with the run's
//! local trust; each start and each stop is said on talk, and a stop drops
//! the permits before the daemon's orderly shutdown. The shell starts and
//! stops the daemon through the keeper, its `NodeControl` (L1): the
//! notebook door's act, `node.start`, and a claim's cancel or close while
//! the board is unclaimed. `POST /bridge/fault/<door>` reaches the running
//! daemon's doors: the three permit pools held full (`write_busy`,
//! `scan_busy`, `fetch_busy`), the held permits released, the head writer's
//! next refusal, the feed walk's hold and release, the media floor's free
//! space, the checkpoint thread's next panic, `halt_writes` — the attest
//! store's next write failed, so a signed commit below the reclaim floor
//! halts the write path and every write after answers `poisoned` (the shell
//! then holds the burst; §3c.4) — and `poison`, the kernel's own halt: the
//! next commit's barrier fails and so does the truncation that would repair
//! it, so the kernel is poisoned and that write answers `poisoned` — the
//! burst held `sent: true`, since its frames stay in the journal and land at
//! the restart (§3c.2). The door arms the daemon's
//! `fail_the_next_checkpoint_step` at `JournalBarrier` and `JournalRepair`,
//! naming the steps by `skep_kernel::Step` as `skepd` re-exports it under
//! `test-hooks`; eleven doors in all. Without the feature no keeper is
//! made: `--own` halts before serving, and the fault route answers
//! `not_built_in`.

use serde_json::Value;
use skep_client::halt::Halt;
use skep_shell::NodeControl;

/// The doors by name, as the route spells them.
pub const DOORS: [&str; 11] = ["write_busy", "scan_busy", "fetch_busy", "release", "refuse_next_head", "hold_feed_walk", "release_feed_walk", "media_free_space", "panic_checkpoint_thread", "halt_writes", "poison"];

#[cfg(feature = "dev-hooks")]
mod built {
    use std::path::{Path, PathBuf};
    use std::sync::mpsc::{channel, Receiver, Sender};
    use std::sync::{Arc, Mutex, PoisonError};
    use std::thread::{self, JoinHandle};
    use std::time::Duration;

    use serde_json::{json, Value};
    use skep_client::halt::Halt;
    use skep_client::Origin;
    use skepd::{embed, AuthOptions, Daemon, EmbedError, MediaOptions, Permit, Skepd, Source, Step, DEFAULT_WORKERS};

    use crate::terminal::talk;

    /// The daemon in-process: the server, and the origin it answers at.
    struct Node {
        skepd: Skepd,
        origin: Origin,
    }

    /// How long the start waits on the cell index's walk at open.
    const INDEX_WAIT: Duration = Duration::from_secs(60);

    impl Node {
        /// Starts the daemon in-process: its own start, `skepd::embed`.
        ///
        /// The port is bound first (a held port is refused before the
        /// journal is read), the daemon opened over `data_dir` with
        /// `local_trust` and its own origin configured, and served; then the
        /// cell index's walk is waited for [`INDEX_WAIT`].
        ///
        /// # Errors
        ///
        /// Each step's refusal is its own halt, a data directory that will
        /// not open faced about that directory, its path beside the words
        /// and never in them (SP-15). A walk that died never completes, so
        /// the wait runs out over it as over one still walking
        /// (`skepd::Skepd::wait_for_the_index`): the two are told apart by
        /// the walk's failed state, each halt with its own cause and act: a
        /// dead walk stays failed until the daemon restarts, while a board
        /// started apart and named by `--board` is waited on by no walk at
        /// all.
        ///
        /// # Panics
        ///
        /// Panics where the port bound is 80: `http://127.0.0.1:80` names
        /// the scheme's default port, so no canonical origin is that text.
        fn start(data_dir: &Path, port: u16, local_trust: bool) -> Result<Node, Halt> {
            let own = |port: u16| {
                let mut opts = AuthOptions::default();
                opts.local_trust = local_trust;
                // Off is this tool's own `--no-local-trust`, named as the
                // flag that set it, so the daemon's `auth:` line never reads
                // it as the daemon's default.
                if !local_trust {
                    opts.local_trust_source = Source::Flag;
                }
                opts.configured = vec![skepd::Origin::parse(&format!("http://127.0.0.1:{port}")).expect("a canonical loopback origin")];
                opts
            };
            let skepd = embed(data_dir, port, own, MediaOptions::default(), DEFAULT_WORKERS).map_err(|e| match e {
                EmbedError::Bind(e) => Halt::face(format!("the daemon's port {port} could not be bound"), e.to_string(), "stop what holds it, or pass --port"),
                EmbedError::Open(e) => Halt::face_at(data_dir, "the daemon could not open its data directory", e.to_string(), "check it: a board another daemon holds is locked"),
                EmbedError::Serve(e) => Halt::face("the daemon could not serve", e.to_string(), "check the port"),
            })?;
            skepd.wait_for_the_index(INDEX_WAIT).map_err(|e| {
                if skepd.daemon().index_is_failed() {
                    Halt::face(
                        e.to_string(),
                        "the cell index's walk DIED on its thread — the daemon's lines above name why — and stays failed until the daemon restarts",
                        "read those lines, then run again: the next run starts the daemon, and its walk, afresh",
                    )
                } else {
                    Halt::face(
                        e.to_string(),
                        format!("the cell index's walk at open runs past this run's {} s wait", INDEX_WAIT.as_secs()),
                        "start the board apart (RUNBOOK.md §3) and pass --board, which waits on no walk",
                    )
                }
            })?;
            let origin = Origin::parse(&format!("http://127.0.0.1:{}", skepd.port())).expect("a canonical loopback origin");
            Ok(Node { skepd, origin })
        }

        /// Returns the served daemon.
        fn daemon(&self) -> &Daemon {
            self.skepd.daemon()
        }
    }

    /// The permits the fault route holds, per pool.
    #[derive(Default)]
    struct Doors<'d> {
        write: Vec<Permit<'d>>,
        scan: Vec<Permit<'d>>,
        fetch: Vec<Permit<'d>>,
    }

    /// Opens one door by name, answering what it did.
    ///
    /// # Errors
    ///
    /// Returns why the door is not one, where no door is named `door`.
    fn fault<'d>(node: &'d Node, doors: &mut Doors<'d>, door: &str, args: &Value) -> Result<Value, String> {
        let daemon = node.daemon();
        let answer = match door {
            "write_busy" => {
                while let Some(p) = daemon.try_hold_write_permit() {
                    doors.write.push(p);
                }
                json!({"door": door, "held": doors.write.len()})
            }
            "scan_busy" => {
                while let Some(p) = daemon.try_hold_scan_permit() {
                    doors.scan.push(p);
                }
                json!({"door": door, "held": doors.scan.len()})
            }
            "fetch_busy" => {
                while let Some(p) = daemon.try_hold_fetch_permit() {
                    doors.fetch.push(p);
                }
                json!({"door": door, "held": doors.fetch.len()})
            }
            "release" => {
                let released = doors.write.len() + doors.scan.len() + doors.fetch.len();
                doors.write.clear();
                doors.scan.clear();
                doors.fetch.clear();
                json!({"door": door, "released": released})
            }
            "refuse_next_head" => {
                daemon.refuse_the_next_head_once();
                json!({"door": door})
            }
            "hold_feed_walk" => {
                Daemon::hold_the_feed_walk();
                json!({"door": door})
            }
            "release_feed_walk" => {
                Daemon::release_the_feed_walk();
                json!({"door": door})
            }
            "media_free_space" => {
                let bytes = args["bytes"].as_u64();
                daemon.set_media_free_space(bytes);
                json!({"door": door, "bytes": bytes})
            }
            "panic_checkpoint_thread" => {
                daemon.panic_the_checkpoint_thread_next();
                json!({"door": door})
            }
            "halt_writes" => {
                // The attest store's next write fails: a signed commit below
                // the reclaim floor halts the write path, and every write after
                // it answers `poisoned` (§3c.4; the shell holds the burst).
                daemon.fail_the_attest_stores_next_write();
                json!({"door": door})
            }
            "poison" => {
                // The kernel's halt (§3c.2's `poisoned`): the next commit's
                // barrier fails, then the truncation that would repair it, so
                // the kernel is poisoned — the write answers `poisoned`, the
                // burst's frames stay in the journal, and a restart lands
                // them. Each arm fires once; both are armed before the write,
                // the barrier's first, as the shell's own suite arms them.
                let kind = io_kind(args["kind"].as_str());
                daemon.fail_the_next_checkpoint_step(Step::JournalBarrier, kind);
                daemon.fail_the_next_checkpoint_step(Step::JournalRepair, kind);
                json!({"door": door})
            }
            other => return Err(format!("no door named `{other}`: the doors are {}", super::DOORS.join(", "))),
        };
        Ok(answer)
    }

    /// Returns the I/O kind the `poison` door's arms fail with.
    ///
    /// It is as the route's `kind` spells it; `Other` where absent or
    /// unknown.
    fn io_kind(name: Option<&str>) -> std::io::ErrorKind {
        use std::io::ErrorKind;
        match name {
            Some("storage_full") => ErrorKind::StorageFull,
            Some("permission_denied") => ErrorKind::PermissionDenied,
            Some("interrupted") => ErrorKind::Interrupted,
            Some("not_found") => ErrorKind::NotFound,
            Some("write_zero") => ErrorKind::WriteZero,
            _ => ErrorKind::Other,
        }
    }

    /// Where the keeper starts the daemon.
    ///
    /// It is the run's data directory and local trust, and the port: the
    /// one `--port` names until a start binds it, then that one for every
    /// later start.
    struct At {
        data_dir: PathBuf,
        port: u16,
        local_trust: bool,
    }

    /// One ask of the keeper's thread, answered on its own channel.
    enum Ask {
        /// Start the daemon where it is not running; the origin it answers at.
        Start(Sender<Result<Origin, Halt>>),
        /// Stop the daemon where it runs.
        Stop(Sender<()>),
        /// Open one fault door of the running daemon.
        Fault { door: String, args: Value, reply: Sender<Result<Value, String>> },
        /// Stop the daemon where it runs, and end the thread.
        End(Sender<()>),
    }

    /// What ended the service of a running daemon ([`running`]).
    enum Next {
        /// A stop, answered once the daemon is down.
        Stopped(Sender<()>),
        /// The keeper's end, answered once the daemon is down.
        End(Sender<()>),
        /// Every handle of the keeper gone.
        Gone,
    }

    /// The keeper of the daemon in-process.
    ///
    /// It is one thread that owns the running daemon and the fault doors'
    /// permits, which borrow it, every start, stop and door reaching it as a
    /// message ([`Ask`]), so a stop and a later start replace the daemon
    /// with no borrow of it outliving it. Dropping it ends it, as
    /// [`Keeper::end`] does.
    pub struct Keeper {
        asks: Sender<Ask>,
        thread: Mutex<Option<JoinHandle<()>>>,
    }

    impl Keeper {
        /// Spawns the keeper of the daemon over `data_dir`, not started.
        ///
        /// Each start binds `port`, then the port the first one bound, with
        /// `local_trust`.
        ///
        /// # Errors
        ///
        /// Returns a halt where the keeper's thread cannot be spawned.
        pub fn spawn(data_dir: &Path, port: u16, local_trust: bool) -> Result<Arc<Keeper>, Halt> {
            let (asks, rx) = channel();
            let at = At { data_dir: data_dir.to_path_buf(), port, local_trust };
            let thread = thread::Builder::new()
                .name("skep-dev in-process daemon".into())
                .spawn(move || keep(at, &rx))
                .map_err(|e| Halt::face("the in-process daemon's keeper could not start", e.to_string(), "run again"))?;
            Ok(Arc::new(Keeper { asks, thread: Mutex::new(Some(thread)) }))
        }

        /// Starts the daemon where it is not running, and answers its origin.
        ///
        /// A daemon already running is left running.
        ///
        /// # Errors
        ///
        /// Returns the start's halt ([`Node::start`]'s), the daemon then not
        /// running; and a halt naming the keeper's end where its thread
        /// ended, a start that panicked among them.
        pub fn start_node(&self) -> Result<Origin, Halt> {
            let (reply, answer) = channel();
            if self.asks.send(Ask::Start(reply)).is_err() {
                return Err(ended());
            }
            answer.recv().unwrap_or_else(|_| Err(ended()))
        }

        /// Stops the daemon where it runs.
        ///
        /// Its permits are released first, then its orderly shutdown runs.
        pub fn stop_node(&self) {
            let (reply, answer) = channel();
            if self.asks.send(Ask::Stop(reply)).is_ok() {
                let _ = answer.recv();
            }
        }

        /// Opens one fault door of the running daemon, answering what it did.
        ///
        /// # Errors
        ///
        /// Returns why the door is not opened: no door of that name, the
        /// daemon not running, or the keeper ended.
        pub fn fault(&self, door: &str, args: &Value) -> Result<Value, String> {
            let gone = || format!("the in-process daemon's keeper has ended, so no door opens; the doors are {}", super::DOORS.join(", "));
            let (reply, answer) = channel();
            if self.asks.send(Ask::Fault { door: door.to_string(), args: args.clone(), reply }).is_err() {
                return Err(gone());
            }
            answer.recv().unwrap_or_else(|_| Err(gone()))
        }

        /// Ends the keeper, stopping the daemon where it runs.
        ///
        /// The stop is said and the thread joined; a keeper ended already
        /// ends nothing more.
        pub fn end(&self) {
            let (reply, answer) = channel();
            if self.asks.send(Ask::End(reply)).is_ok() {
                let _ = answer.recv();
            }
            // The thread's handle, taken once: the lock guards nothing a
            // panic could leave half made.
            if let Some(thread) = self.thread.lock().unwrap_or_else(PoisonError::into_inner).take() {
                let _ = thread.join();
            }
        }
    }

    impl Drop for Keeper {
        /// Ends the keeper where its owner did not ([`Keeper::end`]).
        fn drop(&mut self) {
            self.end();
        }
    }

    /// Returns the halt of an ask the keeper's thread no longer answers.
    fn ended() -> Halt {
        Halt::face("the in-process daemon's keeper has ended", "its thread ended before it answered", "read the lines above — a start that panicked says why — then run again")
    }

    /// Runs the keeper's thread until the end.
    ///
    /// The daemon stands stopped until a start, and is served while it runs.
    fn keep(mut at: At, asks: &Receiver<Ask>) {
        while let Some(node) = stopped(&mut at, asks) {
            let next = running(&node, asks);
            let origin = node.origin.clone();
            node.skepd.shutdown();
            talk(format!("the in-process daemon at {origin} is stopped"));
            match next {
                Next::Stopped(reply) => {
                    let _ = reply.send(());
                }
                Next::End(reply) => {
                    let _ = reply.send(());
                    return;
                }
                Next::Gone => return,
            }
        }
    }

    /// Serves the asks while the daemon is stopped, until a start makes one.
    ///
    /// It answers the daemon started, said on talk, the port it bound kept
    /// for every later start; none at the end.
    fn stopped(at: &mut At, asks: &Receiver<Ask>) -> Option<Node> {
        loop {
            match asks.recv() {
                Ok(Ask::Start(reply)) => match Node::start(&at.data_dir, at.port, at.local_trust) {
                    Ok(node) => {
                        at.port = node.skepd.port();
                        talk(format!(
                            "the daemon runs in-process at {} over {} (local trust {}); its lines are this stream's",
                            node.origin,
                            at.data_dir.display(),
                            if at.local_trust { "on" } else { "off" }
                        ));
                        let _ = reply.send(Ok(node.origin.clone()));
                        return Some(node);
                    }
                    Err(h) => {
                        let _ = reply.send(Err(h));
                    }
                },
                Ok(Ask::Stop(reply)) => {
                    let _ = reply.send(());
                }
                Ok(Ask::Fault { reply, .. }) => {
                    let _ = reply.send(Err(format!("the in-process daemon is not running: the bridge's `node.start` starts it; the doors are {}", super::DOORS.join(", "))));
                }
                Ok(Ask::End(reply)) => {
                    let _ = reply.send(());
                    return None;
                }
                Err(_) => return None,
            }
        }
    }

    /// Serves the asks while `node` runs, until a stop or the end.
    ///
    /// The doors' permits are held in this frame alone, so they are dropped
    /// as it returns, before the daemon's shutdown.
    fn running(node: &Node, asks: &Receiver<Ask>) -> Next {
        let mut doors = Doors::default();
        loop {
            match asks.recv() {
                Ok(Ask::Start(reply)) => {
                    let _ = reply.send(Ok(node.origin.clone()));
                }
                Ok(Ask::Fault { door, args, reply }) => {
                    let _ = reply.send(fault(node, &mut doors, &door, &args));
                }
                Ok(Ask::Stop(reply)) => return Next::Stopped(reply),
                Ok(Ask::End(reply)) => return Next::End(reply),
                Err(_) => return Next::Gone,
            }
        }
    }
}

#[cfg(not(feature = "dev-hooks"))]
mod built {
    use std::convert::Infallible;
    use std::path::Path;
    use std::sync::Arc;

    use serde_json::Value;
    use skep_client::halt::Halt;
    use skep_client::Origin;

    /// No keeper: this build carries no `skepd`, so none is ever made.
    pub struct Keeper(Infallible);

    impl Keeper {
        /// Refuses `--own` in a build without `dev-hooks`.
        ///
        /// # Errors
        ///
        /// Always returns the halt, which names the build.
        pub fn spawn(_data_dir: &Path, _port: u16, _local_trust: bool) -> Result<Arc<Keeper>, Halt> {
            Err(Halt::face(
                "--own needs the dev-hooks build",
                "this skep-dev was built without the `dev-hooks` feature, so it links no daemon and can run none in-process",
                "build with `cargo build -p skep-cli --bin skep-dev --features dev-hooks`, or pass --board for a daemon already running",
            ))
        }

        /// Starts nothing: no keeper of this build is made.
        ///
        /// # Errors
        ///
        /// None: no keeper of this build exists to be asked.
        pub fn start_node(&self) -> Result<Origin, Halt> {
            match self.0 {}
        }

        /// Stops nothing: no keeper of this build is made.
        pub fn stop_node(&self) {
            match self.0 {}
        }

        /// Opens no door: no keeper of this build is made.
        ///
        /// # Errors
        ///
        /// None: no keeper of this build exists to be asked.
        pub fn fault(&self, _door: &str, _args: &Value) -> Result<Value, String> {
            match self.0 {}
        }

        /// Ends nothing: no keeper of this build is made.
        pub fn end(&self) {
            match self.0 {}
        }
    }
}

pub use built::Keeper;

/// The shell's start and stop of the in-process daemon: the keeper's (L1).
impl NodeControl for Keeper {
    fn start(&self) -> Result<(), Halt> {
        self.start_node().map(drop)
    }

    fn stop(&self) {
        self.stop_node();
    }
}

/// Returns the refusal every door answers where none is built in.
///
/// It is answered too where the door is no door, or the daemon not running.
pub fn not_a_door(detail: String) -> Value {
    serde_json::json!({"kind": "shell", "name": "not_built_in", "detail": detail})
}
