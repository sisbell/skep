//! The Docker runner: every call this service makes on the host's Engine.
//!
//! The calls — the post's look at what stands, steps 3 to 5's, the cleanup's
//! and the sweep's — are made through the host's own `docker` command
//! (Q1 (b): a plain program on the VM in the `docker` group; the
//! provisioning record §4, shape (ii)) — so this program speaks no Engine
//! API and holds no socket of its own.
//!
//! * [`Docker`] — the trait: [`Docker::run`], the one method a runner writes,
//!   and one named method per call provided over it, nothing a test cannot
//!   script — the two inspects of the truth about names, the volume's
//!   creation and removal, the claim run, the sidecar's dark claim with the
//!   record on its stdin, a failed run's last lines, the forced removal of a
//!   run, the serving run, the sidecar's `skep health`, the proxy's reload,
//!   and the listing of the volumes this service made. Each answers what the
//!   call answered ([`Exit`], `process`'s: its exit code, its stdout and its
//!   stderr, apart), or the `io::Error` of a `docker` that could not be run.
//! * [`Call`] — one call as data, whole: the board it names and, for the
//!   dark claim, the admitted record its child reads. The argv of every call
//!   is a pure function of the call and the [`Settings`] ([`Call::argv`]),
//!   which the unit suite pins token by token against the documents' run
//!   lines — the smoke's claim run (`scripts/docker-smoke.sh`) word for word
//!   with the public origin in the smoke's local one's place, the deployment
//!   notes' serving run (§4 step 5), the sidecar's run (the smoke's, the
//!   record on stdin in place of a mount) — so drift from them is a red test.
//!   The two runs of the image open with one hardened prefix ([`image_run`]),
//!   and what the image bakes — the port its daemon listens on, the volume a
//!   board lives on — the suite reads back from the `Dockerfile`.
//! * [`HostDocker`] — the one real implementation: `docker` from `PATH`
//!   through `std::process::Command` built from that argv and nothing else
//!   ([`command`]), run by `process::run` — stdout and stderr captured apart,
//!   the service's own stdin never inherited: the sidecar's is a pipe that
//!   carries the record and closes, every other call's is null.
//! * `fake` — the scripted fake, under `test-hooks` alone.
//!
//! **What the calls assume of Docker.** Each assumption is as this crate
//! knows Docker and the provisioning record §8 item 1 lists it, each
//! unverified here: `docker volume inspect` and `docker container inspect`
//! exit 0 for an object that stands and non-zero for one that does not (a
//! non-zero for any other reason — the Engine unreachable — reads as "not
//! standing", and the post's own `volume create` then fails while the Engine
//! stays unreachable, nothing made), where `<name>` is no container's ID
//! prefix: a container command reads its argument as a whole ID, then a
//! name, then the unique prefix of an ID, so a name of hex digits alone would
//! name another container — which the name's grammar refuses; a container's
//! name and a volume's are two bytes at least, which the grammar holds a name
//! to as well; `docker volume create --label <key>=<value> <name>` makes the
//! volume with that label on it, the option read before the name, and on a
//! name a volume already stands under answers 0 and makes nothing, as the
//! provisioning record §5.2 knows Docker;
//! `docker volume ls -q --filter label=<key>=<value>` prints the name of
//! every volume so labelled, one per line and nothing else ([`LABEL_KEY`],
//! [`LABEL_VALUE`]: the mark by which the sweep at start tells this service's
//! volumes from every volume of another making — one service per host, for
//! every `serve` marks its volumes alike); `--network container:<name>` puts
//! the sidecar in the claim run's namespace, where the daemon's loopback is
//! reachable; `-i` keeps the sidecar's stdin open, so `skep claim --hosted -`
//! reads the record from it; a user-defined bridge resolves a container's
//! name, so `skep health --board http://<name>:8642` dials the serving run
//! from a container on the same bridge — the same on the Linux VM and on a
//! Mac, whose host does not reach the bridge — but a container's own
//! `/etc/hosts`, read first, answers `localhost` and six `ip6-` names, which
//! the name's grammar refuses; `docker logs --tail <n> <name>` prints a
//! container's last `n` lines, its stdout's on stdout and its stderr's on
//! stderr, where its log driver can be read back — the `json-file` the
//! serving run's `--log-opt`s assume — and exits non-zero where no container
//! stands under the name; and `docker exec <caddy> caddy reload` reloads
//! Caddy inside its container.

use std::io;
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::domain::Domain;
use crate::name::Name;
use crate::process::{self, Exit};
use crate::record::Record;

/// The program every call runs: the host's `docker`, found on `PATH`.
const DOCKER: &str = "docker";

/// The claim run's bind: its daemon's loopback.
///
/// It is set as `SKEPD_BIND`, over the image's baked `0.0.0.0`, so that only
/// a process in its own network namespace — the sidecar, which joins it —
/// reaches the unclaimed board (AUTH-4.57 (a), (f)); [`dialed_origin`] dials
/// it.
const CLAIM_BIND: &str = "127.0.0.1";

/// The port the image's daemon listens on: the baked `SKEPD_PORT`.
///
/// It is the `Dockerfile`'s, which the unit suite reads back with its
/// `EXPOSE` and the documents that name it: the claim run's, which the
/// sidecar dials ([`dialed_origin`]), and the serving run's, which the proxy
/// reaches at the container's name on the bridge. It is the image's own
/// port, baked so the daemon binary's default never reaches it: every
/// board's snippet names it from the board's making (`caddy.rs`'s
/// `snippet`), so moving it is a migration of every standing board's route.
pub const BOARD_PORT: u16 = 8642;

/// Returns the dialed origin: the board the sidecar dials.
///
/// It is the claim run's daemon at [`CLAIM_BIND`] on [`BOARD_PORT`] —
/// reachable from inside the claim run's network namespace alone, which the
/// sidecar joins (AUTH-4.57 (a), (f)). The sidecar's data line 4 names it
/// back (`origin …`); this program asserts it there and shows it nowhere — a
/// person is shown the public origin, [`Name::origin`] (AUTH-4.57 (b)).
pub fn dialed_origin() -> String {
    format!("http://{CLAIM_BIND}:{BOARD_PORT}")
}

/// Where a board's volume is mounted: the image's `VOLUME`.
///
/// It is the `Dockerfile`'s, which the unit suite reads back, and the daemon
/// creates its `board/` one level below (the baked `SKEPD_DATA_DIR`).
const VOLUME_MOUNT: &str = "/var/lib/skepd";

/// The Caddyfile the reload names, inside Caddy's container.
///
/// The deployment notes §4a mount `/etc/caddy` read-only there.
const CADDYFILE: &str = "/etc/caddy/Caddyfile";

/// The label's key: the mark every volume this service creates carries.
///
/// By it the sweep at start lists them and no volume of another making
/// (`docker volume create --label`, `docker volume ls --filter label=` —
/// unverified here, as the module doc marks). Every `serve` on a host marks
/// its volumes alike, so the sweep cannot tell two services' apart: one
/// service per host.
const LABEL_KEY: &str = "skep.provision";

/// The label's value: one, a flag — the key's presence is the mark.
const LABEL_VALUE: &str = "1";

/// Returns the label as both calls spell it: `<key>=<value>`.
fn label() -> String {
    format!("{LABEL_KEY}={LABEL_VALUE}")
}

/// A failed run's last lines, as many as the cleanup reads: twenty.
///
/// The cleanup reads them before it removes the run and them with it — a
/// daemon's open report and the line that refused it, where it never
/// listened or never paired.
const RUN_LOG_TAIL: usize = 20;

/// Returns the argv of a run of the hosted image under `name`, hardened.
///
/// The run is detached, with an init, and hardened as every run of the image
/// is — a read-only root, no capabilities, no new privileges, 1,024
/// descriptors, the words the deployment notes open both runs with (§4 steps
/// 3 and 5) — then the run's own words, `own_words`, and the image last. One
/// spelling, so a run hardened further is every run hardened further.
fn image_run(name: &Name, own_words: Vec<String>, settings: &Settings) -> Vec<String> {
    let mut argv: Vec<String> = vec![
        "run".into(),
        "-d".into(),
        "--init".into(),
        "--name".into(),
        name.to_string(),
        "--read-only".into(),
        "--cap-drop".into(),
        "ALL".into(),
        "--security-opt".into(),
        "no-new-privileges".into(),
        "--ulimit".into(),
        "nofile=1024:1024".into(),
    ];
    argv.extend(own_words);
    argv.push(settings.image.clone());
    argv
}

/// The run configuration every argv is built from: the operator's flags.
///
/// Each value comes through `args`' doors — the tags, the bridge and the
/// proxy's container one argv word not beginning with `-`, the size
/// `<N>[k|m|g]`, `N` one or more — and is used here unchanged:
/// [`Call::argv`] checks none again; the suffix is a [`Domain`], held to its
/// grammar by its type. The serving run's values — the image, the bridge,
/// the suffix, the rotation — are fixed into each board at its making, and a
/// change to one reaches the boards made after it alone; a tag is resolved
/// by `docker` at each run.
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
    /// The domain every board's name is under, `<name>.<suffix>` (`--suffix`).
    pub suffix: Domain,
    /// The serving run's log rotation: one file's size (`--log-max-size`).
    pub log_max_size: String,
    /// The serving run's log rotation: the files kept (`--log-max-file`).
    ///
    /// They are never none.
    pub log_max_file: NonZeroU32,
}

/// The runner: one method a runner writes, and one named method per call.
///
/// The method a runner writes is [`Docker::run`], and each named method, one
/// per call the service makes, is provided over it — so the host and the
/// fake share one mapping from each named method to its [`Call`], and every
/// suite that drives the fake drives the mapping the host runs.
///
/// **A call that unwinds.** The flow catches a step's or a cleanup's panic,
/// and `pages::connection` a post's look's, and the next calls run through
/// the same runner — so a runner keeps nothing a call can leave
/// half-changed; the host's keeps nothing at all, and the fake its script and
/// its calls under locks it takes poison-recovering.
pub trait Docker: Send + Sync {
    /// Runs one call: the one method a runner writes.
    ///
    /// It answers what `call` answered, the input it carries, where it carries
    /// one, on the child's stdin.
    ///
    /// # Errors
    ///
    /// The runner's, where the call could not be run — a `docker` that could
    /// not be run at all; a call that ran answers its exit, whatever it is.
    fn run(&self, call: Call<'_>) -> io::Result<Exit>;

    /// Creates the board's one fresh named volume, labelled as this service's.
    ///
    /// The call is `docker volume create --label skep.provision=1 <name>`.
    ///
    /// # Errors
    ///
    /// As [`Docker::run`]'s.
    fn volume_create(&self, name: &Name) -> io::Result<Exit> {
        self.run(Call::VolumeCreate(name))
    }

    /// Inspects the volume under `name`: `docker volume inspect <name>`.
    ///
    /// It exits 0 where the volume stands; any other exit where it does not,
    /// or the Engine could not answer.
    ///
    /// # Errors
    ///
    /// As [`Docker::run`]'s.
    fn volume_inspect(&self, name: &Name) -> io::Result<Exit> {
        self.run(Call::VolumeInspect(name))
    }

    /// Inspects the container under `name`: `docker container inspect <name>`.
    ///
    /// It exits 0 where a container stands; any other exit where none does, or
    /// the Engine could not answer.
    ///
    /// # Errors
    ///
    /// As [`Docker::run`]'s.
    fn container_inspect(&self, name: &Name) -> io::Result<Exit> {
        self.run(Call::ContainerInspect(name))
    }

    /// Makes the claim run (step 3): the image bound to its loopback.
    ///
    /// Nothing is published, and the public origin is configured.
    ///
    /// # Errors
    ///
    /// As [`Docker::run`]'s.
    fn run_claim(&self, name: &Name) -> io::Result<Exit> {
        self.run(Call::RunClaim(name))
    }

    /// Makes the dark claim (step 4): the sidecar in the claim run's namespace.
    ///
    /// The admitted `record` is on its stdin — no bytes the post's judge did
    /// not admit can reach it.
    ///
    /// # Errors
    ///
    /// As [`Docker::run`]'s.
    fn sidecar_claim(&self, name: &Name, record: &Record) -> io::Result<Exit> {
        self.run(Call::SidecarClaim(name, record))
    }

    /// Reads a run's last lines: `docker logs --tail 20 <name>`.
    ///
    /// They are the last lines the run under the name wrote — its daemon's
    /// stream on the call's stderr, what it wrote on its stdout on the call's
    /// stdout — read before a failure's cleanup removes the run, and its log
    /// with it.
    ///
    /// # Errors
    ///
    /// As [`Docker::run`]'s.
    fn run_logs(&self, name: &Name) -> io::Result<Exit> {
        self.run(Call::RunLogs(name))
    }

    /// Removes whichever run stands under the name: `docker rm -f <name>`.
    ///
    /// # Errors
    ///
    /// As [`Docker::run`]'s.
    fn rm_force(&self, name: &Name) -> io::Result<Exit> {
        self.run(Call::RmForce(name))
    }

    /// Makes the serving run (step 5).
    ///
    /// It has the baked bind, the bridge, the route's label, the same volume.
    ///
    /// # Errors
    ///
    /// As [`Docker::run`]'s.
    fn run_serving(&self, name: &Name) -> io::Result<Exit> {
        self.run(Call::RunServing(name))
    }

    /// Removes the volume under `name`: `docker volume rm <name>`.
    ///
    /// # Errors
    ///
    /// As [`Docker::run`]'s.
    fn volume_rm(&self, name: &Name) -> io::Result<Exit> {
        self.run(Call::VolumeRm(name))
    }

    /// Reads the serving run's `/health` by the sidecar's `skep health`.
    ///
    /// The read runs on the bridge, its stdout the `/health` body verbatim.
    ///
    /// # Errors
    ///
    /// As [`Docker::run`]'s.
    fn health(&self, name: &Name) -> io::Result<Exit> {
        self.run(Call::Health(name))
    }

    /// Reloads Caddy, inside its container.
    ///
    /// # Errors
    ///
    /// As [`Docker::run`]'s.
    fn caddy_reload(&self) -> io::Result<Exit> {
        self.run(Call::CaddyReload)
    }

    /// Lists the labelled volumes: what the sweep at start reads.
    ///
    /// The call is `docker volume ls -q --filter label=skep.provision=1`, one
    /// name per line on stdout — every volume a `serve` on this host made,
    /// and no other, and so, one service per host, this service's alone.
    ///
    /// # Errors
    ///
    /// As [`Docker::run`]'s.
    fn labelled_volumes(&self) -> io::Result<Exit> {
        self.run(Call::LabelledVolumes)
    }
}

/// One call, as data, whole: the argument of [`Docker::run`].
///
/// It holds the board it names and, for the dark claim, the admitted record
/// its child reads — what [`Call::argv`] renders for the host and the fake
/// matches against its script. A call carries its own input, so no call can
/// be run with another call's; its `Debug` shows of a record its length and
/// its anchorless fact alone, as [`Record`]'s does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Call<'a> {
    /// [`Docker::volume_create`].
    VolumeCreate(&'a Name),
    /// [`Docker::volume_inspect`].
    VolumeInspect(&'a Name),
    /// [`Docker::container_inspect`].
    ContainerInspect(&'a Name),
    /// [`Docker::run_claim`].
    RunClaim(&'a Name),
    /// [`Docker::sidecar_claim`]: the board, and the record for its stdin.
    SidecarClaim(&'a Name, &'a Record),
    /// [`Docker::run_logs`].
    RunLogs(&'a Name),
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
    /// [`Docker::labelled_volumes`].
    LabelledVolumes,
}

impl Call<'_> {
    /// Returns the child's input: the dark claim's record.
    ///
    /// The sidecar's `--hosted -` reads it; no other call's child reads its
    /// stdin.
    fn input(&self) -> Option<&[u8]> {
        match self {
            Call::SidecarClaim(_, record) => Some(record.bytes()),
            _ => None,
        }
    }

    /// Returns the argv, after the program.
    ///
    /// It is a pure function of the call and the settings, the one place each
    /// run line is spelled.
    fn argv(&self, settings: &Settings) -> Vec<String> {
        match *self {
            // The volume, labelled as this service's before its name — the
            // one mark the sweep at start lists by. The smoke's own line
            // (`scripts/docker-smoke.sh`, `docker volume create "$VOLUME"`)
            // carries no label: the smoke sweeps nothing.
            Call::VolumeCreate(name) => vec!["volume".into(), "create".into(), "--label".into(), label(), name.to_string()],
            Call::VolumeInspect(name) => vec!["volume".into(), "inspect".into(), name.to_string()],
            Call::ContainerInspect(name) => vec!["container".into(), "inspect".into(), name.to_string()],
            // The claim run — the smoke's line word for word but its origin
            // (`scripts/docker-smoke.sh`, the claim run): loopback-bound by
            // `SKEPD_BIND` at `CLAIM_BIND`, no port published, so only a
            // process in its own namespace reaches the unclaimed board
            // (AUTH-4.57 (a), (f)); the public origin configured, never a
            // loopback one (AUTH-4.57 (b)); the fresh volume at the image's
            // mount.
            Call::RunClaim(name) => image_run(
                name,
                vec!["-e".into(), format!("SKEPD_BIND={CLAIM_BIND}"), "-e".into(), format!("SKEPD_ORIGIN={}", name.origin(&settings.suffix)), "-v".into(), format!("{name}:{VOLUME_MOUNT}")],
                settings,
            ),
            // The sidecar — the smoke's run with the record on stdin (`-i`,
            // `--hosted -`) in place of a mounted file: no host path, no
            // file mode for its user to read (the provisioning record §2.2).
            Call::SidecarClaim(name, _) => vec![
                "run".into(),
                "--rm".into(),
                "-i".into(),
                "--network".into(),
                format!("container:{name}"),
                settings.cli_image.clone(),
                "skep".into(),
                "claim".into(),
                "--board".into(),
                dialed_origin(),
                "--hosted".into(),
                "-".into(),
            ],
            // A failed run's last lines — the board's own daemon's account of
            // why it never listened or never paired, which the run's removal
            // takes with it.
            Call::RunLogs(name) => vec!["logs".into(), "--tail".into(), RUN_LOG_TAIL.to_string(), name.to_string()],
            Call::RmForce(name) => vec!["rm".into(), "-f".into(), name.to_string()],
            // The serving run — the deployment notes' step 5 line in its
            // order, with the README's restart and rotation flags: the
            // baked `SKEPD_BIND=0.0.0.0`, the bridge Caddy shares, the same
            // volume, the public origin, the route's label; the rotation
            // the operator's to size.
            Call::RunServing(name) => image_run(
                name,
                vec![
                    "--restart".into(),
                    "on-failure".into(),
                    "--log-opt".into(),
                    format!("max-size={}", settings.log_max_size),
                    "--log-opt".into(),
                    format!("max-file={}", settings.log_max_file),
                    "--network".into(),
                    settings.network.clone(),
                    "-v".into(),
                    format!("{name}:{VOLUME_MOUNT}"),
                    "-e".into(),
                    format!("SKEPD_ORIGIN={}", name.origin(&settings.suffix)),
                    "--label".into(),
                    format!("host={}", name.host(&settings.suffix)),
                ],
                settings,
            ),
            Call::VolumeRm(name) => vec!["volume".into(), "rm".into(), name.to_string()],
            // The `/health` read — the sidecar's `skep health` on the bridge,
            // where the serving run's name resolves; its stdout is the body
            // verbatim, so this program needs no dialer of its own.
            Call::Health(name) => vec![
                "run".into(),
                "--rm".into(),
                "--network".into(),
                settings.network.clone(),
                settings.cli_image.clone(),
                "skep".into(),
                "health".into(),
                "--board".into(),
                format!("http://{name}:{BOARD_PORT}"),
            ],
            Call::CaddyReload => vec!["exec".into(), settings.caddy.clone(), "caddy".into(), "reload".into(), "--config".into(), CADDYFILE.into()],
            // The listing — the names alone (`-q`) of the volumes that carry
            // the label: this service's, and no other volume on the host.
            Call::LabelledVolumes => vec!["volume".into(), "ls".into(), "-q".into(), "--filter".into(), format!("label={}", label())],
        }
    }
}

/// The real runner: the host's `docker`, one process per call.
#[derive(Debug, Clone)]
pub struct HostDocker {
    program: PathBuf,
    settings: Settings,
}

impl HostDocker {
    /// Returns the runner over the operator's settings: `docker` from `PATH`.
    pub fn new(settings: Settings) -> HostDocker {
        HostDocker { program: PathBuf::from(DOCKER), settings }
    }

    /// Returns the runner with another program in `docker`'s place.
    ///
    /// The program is a unit suite's recording script, so the runner's own
    /// process handling is judged with no Docker run.
    #[cfg(test)]
    fn with_program(program: PathBuf, settings: Settings) -> HostDocker {
        HostDocker { program, settings }
    }
}

/// Builds the command for an argv: the program, the argv, and nothing else.
///
/// The program is `docker`; no variable is set, no directory changed; its
/// streams are `process::run`'s to set.
fn command(program: &Path, argv: &[String]) -> Command {
    let mut cmd = Command::new(program);
    cmd.args(argv);
    cmd
}

impl Docker for HostDocker {
    /// Runs one call: the command built from its argv, run by `process::run`.
    ///
    /// The call's input — the sidecar's record, and no other call's — goes on
    /// its stdin.
    ///
    /// # Errors
    ///
    /// `process::run`'s: a `docker` that could not be spawned or waited for,
    /// or whose input could not be given a thread of its own.
    fn run(&self, call: Call<'_>) -> io::Result<Exit> {
        process::run(command(&self.program, &call.argv(&self.settings)), call.input())
    }
}

/// A shared runner is a runner.
///
/// A unit suite hands the service an `Arc` of its fake and keeps one to read
/// the calls after.
#[cfg(test)]
impl<D: Docker + ?Sized> Docker for std::sync::Arc<D> {
    fn run(&self, call: Call<'_>) -> io::Result<Exit> {
        (**self).run(call)
    }
}

#[cfg(feature = "test-hooks")]
pub mod fake;

#[cfg(test)]
mod tests;
