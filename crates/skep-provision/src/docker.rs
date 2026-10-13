//! THE DOCKER RUNNER: every call the five steps make on the host's Docker
//! Engine, made through the host's own `docker` command (Q1 (b): a plain
//! program on the VM in the `docker` group; the provisioning record §4,
//! shape (ii)) — so this program speaks no Engine API and holds no socket
//! of its own.
//!
//! * [`Docker`] — the TRAIT: ONE METHOD PER CALL and nothing a test cannot
//!   script — the two inspects of the truth about names, the volume's
//!   creation and removal, the claim run, the sidecar's dark claim with the
//!   record on its stdin, the forced removal of a run, the serving run, the
//!   sidecar's `skep health`, the proxy's reload, and the listing of the
//!   volumes this service made. Each answers what the call answered
//!   ([`Exit`]: its exit code, its stdout and its stderr, apart), or the
//!   `io::Error` of a `docker` that could not be run.
//! * [`Call`] — THE ARGV of every call, A PURE FUNCTION of the call and the
//!   [`Settings`] ([`Call::argv`]), which the unit suite pins token by
//!   token against the documents' run lines — the smoke's claim run
//!   (`scripts/docker-smoke.sh`) WORD FOR WORD with the public origin in
//!   the smoke's local one's place, the deployment notes' serving run (§4
//!   step 5), the sidecar's run (the smoke's, the record on stdin in place
//!   of a mount) — so drift from them is a red test.
//! * [`Host`] — the one real implementation: `docker` from `PATH` through
//!   `std::process::Command` built from that argv and nothing else
//!   ([`command`]), stdout and stderr captured apart, the service's own
//!   stdin never inherited — the sidecar's is a pipe that carries the record
//!   and closes, every other call's is null.
//! * `fake` — the scripted fake, under `test-hooks` alone.
//!
//! WHAT THE CALLS ASSUME OF DOCKER, as this crate knows Docker and the
//! provisioning record §8 item 1 lists it, each UNVERIFIED HERE: `docker
//! volume inspect` and `docker container inspect` exit 0 for an object that
//! stands and non-zero for one that does not (a non-zero for any other
//! reason — the Engine unreachable — reads as "not standing", and the
//! post's own `volume create` then fails, nothing made); `docker volume
//! create --label <key>=<value> <name>` makes the volume with that label on
//! it, the option read before the name, and `docker volume ls -q --filter
//! label=<key>=<value>` prints the name of every volume so labelled, one
//! per line and nothing else ([`LABEL_KEY`], [`LABEL_VALUE`]: the mark by
//! which the sweep at start tells this service's volumes from every other
//! on the host); `--network container:<name>` puts the sidecar in the claim
//! run's namespace, where the daemon's loopback is reachable; `-i` keeps the
//! sidecar's stdin open, so `skep claim --hosted -` reads the record from
//! it; a user-defined bridge resolves a container's name, so `skep health
//! --board http://<name>:8642` dials the serving run from a container on
//! the same bridge — the same on the Linux VM and on a Mac, whose host does
//! not reach the bridge; and `docker exec <caddy> caddy reload` reloads
//! Caddy inside its container.

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;

use crate::name::Name;

/// The program every call runs: the host's `docker`, found on `PATH`.
const DOCKER: &str = "docker";

/// THE BOARD THE SIDECAR DIALS: the claim run's daemon on ITS loopback, at
/// the image's baked port — reachable from inside the claim run's network
/// namespace alone, which the sidecar joins (AUTH-4.57 (a), (f)). The
/// sidecar's DATA line 4 names it back (`origin …`); this program asserts it
/// there and shows it nowhere.
pub const SIDECAR_BOARD: &str = "http://127.0.0.1:8642";

/// The port the image's daemon listens on (the baked `SKEPD_PORT`); the
/// serving run is reached at `<name>:8642` on the bridge.
pub const BOARD_PORT: u16 = 8642;

/// Where a board's volume is mounted: the image's `VOLUME`, whose
/// `board/` the daemon creates one level below (the baked
/// `SKEPD_DATA_DIR`).
const VOLUME_MOUNT: &str = "/var/lib/skepd";

/// The Caddyfile the reload names, inside Caddy's container (the
/// deployment notes §4a: `/etc/caddy` mounted read-only there).
const CADDYFILE: &str = "/etc/caddy/Caddyfile";

/// THE LABEL's KEY: the mark every volume this service creates carries,
/// by which the sweep at start lists them and no other volume on the host
/// (`docker volume create --label`, `docker volume ls --filter label=` —
/// UNVERIFIED HERE, as the module doc marks).
const LABEL_KEY: &str = "skep.provision";

/// THE LABEL's VALUE: one, a flag — the key's presence is the mark.
const LABEL_VALUE: &str = "1";

/// The label as both calls spell it: `<key>=<value>`.
fn label() -> String {
    format!("{LABEL_KEY}={LABEL_VALUE}")
}

/// The run configuration every argv is built from: the operator's flags.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settings {
    /// The hosted image's tag (`--image`).
    pub image: String,
    /// The claim sidecar's tag (`--cli-image`): the `skep` command alone.
    pub cli_image: String,
    /// The bridge the serving runs and Caddy share (`--network`).
    pub network: String,
    /// Caddy's container (`--caddy`).
    pub caddy: String,
    /// The domain every board's name stands under (`--suffix`).
    pub suffix: String,
    /// The serving run's log rotation: one file's size (`--log-max-size`).
    pub log_max_size: String,
    /// The serving run's log rotation: the files kept (`--log-max-file`).
    pub log_max_file: u32,
}

/// What one call answered: its exit code (`None` where it ended by a
/// signal), its stdout and its stderr, each apart.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Exit {
    /// The exit code, or `None` where the process ended by a signal.
    pub code: Option<i32>,
    /// Everything it wrote on stdout.
    pub stdout: Vec<u8>,
    /// Everything it wrote on stderr.
    pub stderr: Vec<u8>,
}

impl Exit {
    /// Whether it exited 0.
    pub fn ok(&self) -> bool {
        self.code == Some(0)
    }

    /// The exit code as the log spells it: the number, or `signal`.
    pub fn said(&self) -> String {
        self.code.map_or_else(|| "signal".to_owned(), |c| c.to_string())
    }
}

/// THE RUNNER: one method per call the five steps make, each answering what
/// the call answered.
pub trait Docker: Send + Sync {
    /// `docker volume create --label skep.provision=1 <name>`: the board's
    /// one fresh named volume, labelled as this service's.
    fn volume_create(&self, name: &Name) -> io::Result<Exit>;
    /// `docker volume inspect <name>`: exit 0 iff the volume stands.
    fn volume_inspect(&self, name: &Name) -> io::Result<Exit>;
    /// `docker container inspect <name>`: exit 0 iff a container stands.
    fn container_inspect(&self, name: &Name) -> io::Result<Exit>;
    /// THE CLAIM RUN (step 3): the image bound to its loopback, nothing
    /// published, the public origin configured.
    fn run_claim(&self, name: &Name) -> io::Result<Exit>;
    /// THE DARK CLAIM (step 4): the sidecar in the claim run's namespace,
    /// `record` on its stdin.
    fn sidecar_claim(&self, name: &Name, record: &[u8]) -> io::Result<Exit>;
    /// `docker rm -f <name>`: whichever run stands under the name, removed.
    fn rm_force(&self, name: &Name) -> io::Result<Exit>;
    /// THE SERVING RUN (step 5): the baked bind, the bridge, the route's
    /// label, the same volume.
    fn run_serving(&self, name: &Name) -> io::Result<Exit>;
    /// `docker volume rm <name>`.
    fn volume_rm(&self, name: &Name) -> io::Result<Exit>;
    /// The sidecar's `skep health` against the serving run, on the bridge:
    /// stdout the `/health` body verbatim.
    fn health(&self, name: &Name) -> io::Result<Exit>;
    /// Caddy's reload, inside its container.
    fn caddy_reload(&self) -> io::Result<Exit>;
    /// `docker volume ls -q --filter label=skep.provision=1`: every volume
    /// this service made, one name per line on stdout — what the sweep at
    /// start reads.
    fn volumes(&self) -> io::Result<Exit>;
}

/// One call, as data: what [`Call::argv`] renders and the fake matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Call<'a> {
    /// [`Docker::volume_create`].
    VolumeCreate(&'a Name),
    /// [`Docker::volume_inspect`].
    VolumeInspect(&'a Name),
    /// [`Docker::container_inspect`].
    ContainerInspect(&'a Name),
    /// [`Docker::run_claim`].
    RunClaim(&'a Name),
    /// [`Docker::sidecar_claim`].
    SidecarClaim(&'a Name),
    /// [`Docker::rm_force`].
    RmForce(&'a Name),
    /// [`Docker::run_serving`].
    RunServing(&'a Name),
    /// [`Docker::volume_rm`].
    VolumeRm(&'a Name),
    /// [`Docker::health`].
    Health(&'a Name),
    /// [`Docker::caddy_reload`].
    CaddyReload,
    /// [`Docker::volumes`].
    Volumes,
}

impl Call<'_> {
    /// THE ARGV, after the program: a pure function of the call and the
    /// settings, the one place each run line is spelled.
    fn argv(&self, s: &Settings) -> Vec<String> {
        match *self {
            // THE VOLUME, labelled as this service's before its name — the
            // one mark the sweep at start lists by. The smoke's own line
            // (`scripts/docker-smoke.sh`, `docker volume create "$VOLUME"`)
            // carries no label: the smoke sweeps nothing.
            Call::VolumeCreate(n) => vec!["volume".into(), "create".into(), "--label".into(), label(), n.to_string()],
            Call::VolumeInspect(n) => vec!["volume".into(), "inspect".into(), n.to_string()],
            Call::ContainerInspect(n) => vec!["container".into(), "inspect".into(), n.to_string()],
            // THE CLAIM RUN — the smoke's line word for word
            // (`scripts/docker-smoke.sh`, the claim run): loopback-bound by
            // `SKEPD_BIND=127.0.0.1`, no port published, so only a process in
            // its own namespace reaches the unclaimed board (AUTH-4.57 (a),
            // (f)); the public origin configured, never a loopback one
            // (AUTH-4.57 (b)); the fresh volume at the image's mount.
            Call::RunClaim(n) => vec![
                "run".into(),
                "-d".into(),
                "--init".into(),
                "--name".into(),
                n.to_string(),
                "--read-only".into(),
                "--cap-drop".into(),
                "ALL".into(),
                "--security-opt".into(),
                "no-new-privileges".into(),
                "--ulimit".into(),
                "nofile=1024:1024".into(),
                "-e".into(),
                "SKEPD_BIND=127.0.0.1".into(),
                "-e".into(),
                format!("SKEPD_ORIGIN={}", n.origin(&s.suffix)),
                "-v".into(),
                format!("{n}:{VOLUME_MOUNT}"),
                s.image.clone(),
            ],
            // THE SIDECAR — the smoke's run with the record on stdin (`-i`,
            // `--hosted -`) in place of a mounted file: no host path, no
            // file mode for its user to read (the provisioning record §2.2).
            Call::SidecarClaim(n) => vec![
                "run".into(),
                "--rm".into(),
                "-i".into(),
                "--network".into(),
                format!("container:{n}"),
                s.cli_image.clone(),
                "skep".into(),
                "claim".into(),
                "--board".into(),
                SIDECAR_BOARD.into(),
                "--hosted".into(),
                "-".into(),
            ],
            Call::RmForce(n) => vec!["rm".into(), "-f".into(), n.to_string()],
            // THE SERVING RUN — the deployment notes' step 5 line in its
            // order, with the README's restart and rotation flags: the
            // baked `SKEPD_BIND=0.0.0.0`, the bridge Caddy shares, the same
            // volume, the public origin, the route's label; the rotation
            // the operator's to size.
            Call::RunServing(n) => vec![
                "run".into(),
                "-d".into(),
                "--init".into(),
                "--name".into(),
                n.to_string(),
                "--read-only".into(),
                "--cap-drop".into(),
                "ALL".into(),
                "--security-opt".into(),
                "no-new-privileges".into(),
                "--ulimit".into(),
                "nofile=1024:1024".into(),
                "--restart".into(),
                "on-failure".into(),
                "--log-opt".into(),
                format!("max-size={}", s.log_max_size),
                "--log-opt".into(),
                format!("max-file={}", s.log_max_file),
                "--network".into(),
                s.network.clone(),
                "-v".into(),
                format!("{n}:{VOLUME_MOUNT}"),
                "-e".into(),
                format!("SKEPD_ORIGIN={}", n.origin(&s.suffix)),
                "--label".into(),
                format!("host={}", n.host(&s.suffix)),
                s.image.clone(),
            ],
            Call::VolumeRm(n) => vec!["volume".into(), "rm".into(), n.to_string()],
            // THE `/health` READ — the sidecar's `skep health` on the bridge,
            // where the serving run's name resolves; its stdout is the body
            // verbatim, so this program needs no dialer of its own.
            Call::Health(n) => {
                vec!["run".into(), "--rm".into(), "--network".into(), s.network.clone(), s.cli_image.clone(), "skep".into(), "health".into(), "--board".into(), format!("http://{n}:{BOARD_PORT}")]
            }
            Call::CaddyReload => vec!["exec".into(), s.caddy.clone(), "caddy".into(), "reload".into(), "--config".into(), CADDYFILE.into()],
            // THE LISTING — the names alone (`-q`) of the volumes that carry
            // the label: this service's, and no other volume on the host.
            Call::Volumes => vec!["volume".into(), "ls".into(), "-q".into(), "--filter".into(), format!("label={}", label())],
        }
    }
}

/// THE REAL RUNNER: the host's `docker`, one process per call.
#[derive(Debug, Clone)]
pub struct Host {
    program: PathBuf,
    settings: Settings,
}

impl Host {
    /// The runner over the operator's settings: `docker` from `PATH`.
    pub fn new(settings: Settings) -> Host {
        Host { program: PathBuf::from(DOCKER), settings }
    }

    /// The runner with another program in `docker`'s place: a unit suite's
    /// recording script, so the runner's own process handling is judged
    /// with no Docker run.
    #[cfg(test)]
    fn with_program(program: PathBuf, settings: Settings) -> Host {
        Host { program, settings }
    }

    /// One call run: the command built from its argv, the record written to
    /// the sidecar's stdin on a thread of its own and the pipe closed — so a
    /// child that writes before it has read cannot stall the write — and the
    /// two streams read to their ends.
    fn run(&self, call: Call<'_>, stdin: Option<&[u8]>) -> io::Result<Exit> {
        let mut child = command(&self.program, &call.argv(&self.settings), stdin.is_some()).spawn()?;
        let feeder = match (stdin, child.stdin.take()) {
            (Some(bytes), Some(mut pipe)) => {
                let bytes = bytes.to_vec();
                Some(thread::spawn(move || pipe.write_all(&bytes)))
            }
            _ => None,
        };
        let out = child.wait_with_output()?;
        if let Some(feeder) = feeder {
            // A child that exits before reading its stdin breaks the pipe;
            // its exit code says what happened, so the write's error is not
            // the call's.
            let _ = feeder.join();
        }
        Ok(Exit { code: out.status.code(), stdout: out.stdout, stderr: out.stderr })
    }
}

/// THE COMMAND for an argv: the program — `docker` — the argv, and nothing
/// else — no variable set, no directory changed; stdout and stderr piped
/// apart; stdin a pipe where the call carries input and null where it does
/// not, never the service's own.
fn command(program: &Path, argv: &[String], stdin: bool) -> Command {
    let mut cmd = Command::new(program);
    cmd.args(argv).stdin(if stdin { Stdio::piped() } else { Stdio::null() }).stdout(Stdio::piped()).stderr(Stdio::piped());
    cmd
}

impl Docker for Host {
    fn volume_create(&self, name: &Name) -> io::Result<Exit> {
        self.run(Call::VolumeCreate(name), None)
    }

    fn volume_inspect(&self, name: &Name) -> io::Result<Exit> {
        self.run(Call::VolumeInspect(name), None)
    }

    fn container_inspect(&self, name: &Name) -> io::Result<Exit> {
        self.run(Call::ContainerInspect(name), None)
    }

    fn run_claim(&self, name: &Name) -> io::Result<Exit> {
        self.run(Call::RunClaim(name), None)
    }

    fn sidecar_claim(&self, name: &Name, record: &[u8]) -> io::Result<Exit> {
        self.run(Call::SidecarClaim(name), Some(record))
    }

    fn rm_force(&self, name: &Name) -> io::Result<Exit> {
        self.run(Call::RmForce(name), None)
    }

    fn run_serving(&self, name: &Name) -> io::Result<Exit> {
        self.run(Call::RunServing(name), None)
    }

    fn volume_rm(&self, name: &Name) -> io::Result<Exit> {
        self.run(Call::VolumeRm(name), None)
    }

    fn health(&self, name: &Name) -> io::Result<Exit> {
        self.run(Call::Health(name), None)
    }

    fn caddy_reload(&self) -> io::Result<Exit> {
        self.run(Call::CaddyReload, None)
    }

    fn volumes(&self) -> io::Result<Exit> {
        self.run(Call::Volumes, None)
    }
}

/// A shared runner is a runner: a unit suite hands the service an `Arc` of
/// its fake and keeps one to read the calls after.
#[cfg(test)]
impl<D: Docker + ?Sized> Docker for std::sync::Arc<D> {
    fn volume_create(&self, name: &Name) -> io::Result<Exit> {
        (**self).volume_create(name)
    }

    fn volume_inspect(&self, name: &Name) -> io::Result<Exit> {
        (**self).volume_inspect(name)
    }

    fn container_inspect(&self, name: &Name) -> io::Result<Exit> {
        (**self).container_inspect(name)
    }

    fn run_claim(&self, name: &Name) -> io::Result<Exit> {
        (**self).run_claim(name)
    }

    fn sidecar_claim(&self, name: &Name, record: &[u8]) -> io::Result<Exit> {
        (**self).sidecar_claim(name, record)
    }

    fn rm_force(&self, name: &Name) -> io::Result<Exit> {
        (**self).rm_force(name)
    }

    fn run_serving(&self, name: &Name) -> io::Result<Exit> {
        (**self).run_serving(name)
    }

    fn volume_rm(&self, name: &Name) -> io::Result<Exit> {
        (**self).volume_rm(name)
    }

    fn health(&self, name: &Name) -> io::Result<Exit> {
        (**self).health(name)
    }

    fn caddy_reload(&self) -> io::Result<Exit> {
        (**self).caddy_reload()
    }

    fn volumes(&self) -> io::Result<Exit> {
        (**self).volumes()
    }
}

#[cfg(feature = "test-hooks")]
pub mod fake;

#[cfg(test)]
mod tests;
