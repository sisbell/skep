//! THE DAEMON's TWO MODES. Without `--own` the provider dials a daemon that
//! is already running — the local record's recipe — and the fault route
//! answers that it is not built in. With `--own`, in a build with the
//! `dev-hooks` feature, the daemon runs IN-PROCESS with its `test-hooks`
//! doors (started as `tests/it/common.rs`'s spawn starts it and an embedding
//! app would: `skepd::embed`, then the wait for its cell index), and
//! `POST /bridge/fault/<door>` reaches them: the three
//! permit pools held full (`write_busy`, `scan_busy`, `fetch_busy`), the
//! held permits released, the head writer's next refusal, the feed walk's
//! hold and release, the media floor's free space, the checkpoint thread's
//! next panic, `halt_writes` — the attest store's next write failed, so a
//! signed commit below the reclaim floor halts the write path and every write
//! after answers `poisoned` (the shell then holds the burst; §3c.4) — and
//! `poison`, the kernel's own halt: the next commit's barrier fails and so
//! does the truncation that would repair it, so the kernel is POISONED and
//! that write answers `poisoned` — the burst held `sent: true`, since its
//! frames stay in the journal and land at the restart (§3c.2). The door arms
//! the daemon's `fail_the_next_checkpoint_step` at `JournalBarrier` and
//! `JournalRepair`, naming the steps by `skep_kernel::Step` as `skepd`
//! re-exports it under `test-hooks`; eleven doors in all. Without the feature
//! every door of this module is the one refusal, `not_built_in`, and `--own`
//! halts before serving.

use std::path::Path;

use serde_json::Value;
use skep_client::halt::Halt;
use skep_client::Origin;

/// The doors by name, as the route spells them.
pub const DOORS: [&str; 11] = ["write_busy", "scan_busy", "fetch_busy", "release", "refuse_next_head", "hold_feed_walk", "release_feed_walk", "media_free_space", "panic_checkpoint_thread", "halt_writes", "poison"];

#[cfg(feature = "dev-hooks")]
mod built {
    use std::path::Path;
    use std::time::Duration;

    use serde_json::{json, Value};
    use skep_client::halt::Halt;
    use skep_client::Origin;
    use skepd::{embed, AuthOptions, Daemon, EmbedError, MediaOptions, Permit, Skepd, Source, Step, DEFAULT_WORKERS};

    /// The daemon in-process: the server, and the origin it answers at.
    pub struct Node {
        skepd: Skepd,
        pub origin: Origin,
    }

    /// How long the start waits on the cell index's walk at open.
    const INDEX_WAIT: Duration = Duration::from_secs(60);

    impl Node {
        /// THE START, the daemon's own (`skepd::embed`): the port bound
        /// first (a held port is refused before the journal is read), the
        /// daemon opened over `data_dir` with `local_trust` and its own
        /// origin configured, served — each step's refusal its own halt —
        /// and the cell index's walk waited for [`INDEX_WAIT`]. A walk that
        /// DIED never completes, so the wait runs out over it as over one
        /// still walking (`skepd::Skepd::wait_for_the_index`): the two are
        /// told apart by the walk's FAILED state, each halt with its own
        /// cause and act: a dead walk stays failed until the daemon
        /// restarts, while a board started apart and named by `--board` is
        /// waited on by no walk at all.
        pub fn start(data_dir: &Path, port: u16, local_trust: bool) -> Result<Node, Halt> {
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
                EmbedError::Open(e) => Halt::face(format!("the daemon could not open {}", data_dir.display()), e.to_string(), "check the directory; a board another daemon holds is locked"),
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

        /// The served daemon.
        pub fn daemon(&self) -> &Daemon {
            self.skepd.daemon()
        }

        /// The orderly stop.
        pub fn shutdown(self) {
            self.skepd.shutdown();
        }
    }

    /// The permits the fault route holds, per pool.
    #[derive(Default)]
    pub struct Doors<'d> {
        write: Vec<Permit<'d>>,
        scan: Vec<Permit<'d>>,
        fetch: Vec<Permit<'d>>,
    }

    /// ONE DOOR by name: what it did, or why the door is not one.
    pub fn fault<'d>(node: &'d Node, doors: &mut Doors<'d>, door: &str, args: &Value) -> Result<Value, String> {
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
                // The attest store's next write fails: a signed commit below the
                // reclaim floor halts the write path, and every write after it
                // answers `poisoned` (§3c.4; the shell holds the burst).
                daemon.fail_the_attest_stores_next_write();
                json!({"door": door})
            }
            "poison" => {
                // The kernel's halt (§3c.2's `poisoned`): the next commit's
                // barrier fails, then the truncation that would repair it, so
                // the kernel is POISONED — the write answers `poisoned`, the
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

    /// The I/O kind the `poison` door's arms fail with, as the route's
    /// `kind` spells it; `Other` where absent or unknown.
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
}

#[cfg(not(feature = "dev-hooks"))]
mod built {
    use std::marker::PhantomData;
    use std::path::Path;

    use serde_json::Value;
    use skep_client::halt::Halt;
    use skep_client::Origin;

    /// No daemon in-process: this build carries no `skepd`.
    pub struct Node {
        pub origin: Origin,
    }

    impl Node {
        /// `--own` in a build without `dev-hooks`: the halt names the build.
        pub fn start(_data_dir: &Path, _port: u16, _local_trust: bool) -> Result<Node, Halt> {
            Err(Halt::face(
                "--own needs the dev-hooks build",
                "this skep-dev was built without the `dev-hooks` feature, so it links no daemon and can run none in-process",
                "build with `cargo build -p skep-cli --bin skep-dev --features dev-hooks`, or pass --board for a daemon already running",
            ))
        }

        pub fn shutdown(self) {}
    }

    /// Nothing held.
    #[derive(Default)]
    pub struct Doors<'d>(PhantomData<&'d ()>);

    /// Every door: not built in.
    pub fn fault<'d>(_node: &'d Node, _doors: &mut Doors<'d>, door: &str, _args: &Value) -> Result<Value, String> {
        Err(format!("the fault door `{door}` is not built in: this skep-dev links no daemon (the `dev-hooks` feature is off); the doors a dev-hooks build offers are {}", super::DOORS.join(", ")))
    }
}

pub use built::{fault, Doors, Node};

/// The node started under `--own`, or the halt: a build without the
/// feature halts before serving.
pub fn start(data_dir: &Path, port: u16, local_trust: bool) -> Result<Node, Halt> {
    Node::start(data_dir, port, local_trust)
}

/// The origin a started node answers at.
pub fn origin_of(node: &Node) -> &Origin {
    &node.origin
}

/// The refusal every door answers where none is built in or the door is
/// no door.
pub fn not_a_door(detail: String) -> Value {
    serde_json::json!({"kind": "shell", "name": "not_built_in", "detail": detail})
}
