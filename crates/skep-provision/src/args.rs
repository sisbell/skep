//! THE COMMAND LINE, parsed by hand in the daemon's style: a leading verb —
//! `serve` or `invite` — then its flags, each `--flag <value>`, the last
//! given winning; `--version` read as the FIRST argument alone, what
//! follows it unread; `--help` the usage text. Every default is a named
//! constant below, and the usage text renders each from its constant, so
//! the program cannot describe a default it does not use. A flag the verb
//! does not take, a flag without its value, a value of the wrong form, a
//! required flag missing, `--mailer` without `--from` or the reverse — each
//! is a usage refusal ([`parse`]'s `Err`), which `main` says with the usage
//! text and answers exit 2. Under `test-hooks` alone, `serve` takes the two
//! fakes' flags; a shipped build calls both unknown arguments.

use std::ffi::OsString;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::num::{NonZeroU32, NonZeroUsize};
use std::path::PathBuf;

use crate::docker::Settings;
use crate::invites::{InviteCode, MAX_CODE_BYTES};
use crate::statedir::MailAddress;

/// THE LISTEN ADDRESS's DEFAULT: loopback, port 8842 — not the daemon's
/// 8642 and not the dev provider's 8742. How Caddy, in its container,
/// reaches the service on the host is the VM's configuration; `--listen`
/// takes any address the operator gives.
const DEFAULT_LISTEN: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8842));

/// THE SNIPPET DIRECTORY's DEFAULT: the one the Caddyfile imports, `import
/// /etc/caddy/boards/*.caddy` (the deployment notes §4a).
const DEFAULT_BOARDS_DIR: &str = "/etc/caddy/boards";

/// THE HOSTED IMAGE's DEFAULT TAG: the `Dockerfile`'s default target, as
/// the README builds it.
const DEFAULT_IMAGE: &str = "skep-hosted";

/// THE SIDECAR's DEFAULT TAG: the `Dockerfile`'s `skep-cli` target, the
/// `skep` command alone.
const DEFAULT_CLI_IMAGE: &str = "skep-cli";

/// THE BRIDGE's DEFAULT: the network Caddy and the boards share (the
/// deployment notes §4 step 5, `docker network create skep`).
const DEFAULT_NETWORK: &str = "skep";

/// CADDY's CONTAINER, by default (the deployment notes §4a's run line).
const DEFAULT_CADDY: &str = "caddy";

/// THE SUFFIX's DEFAULT: the alpha's domain, every board `<name>.skep.host`.
const DEFAULT_SUFFIX: &str = "skep.host";

/// THE SERVING RUN's LOG FILE SIZE, by default: the README's serving line's
/// `max-size=10m` — the operator's to size.
const DEFAULT_LOG_MAX_SIZE: &str = "10m";

/// THE SERVING RUN's LOG FILES KEPT, by default: the README's serving
/// line's `max-file=5` — the operator's to size.
const DEFAULT_LOG_MAX_FILE: NonZeroU32 = NonZeroU32::new(5).expect("five is not zero");

/// THE WORKERS, by default: three threads, each making one board at a
/// time, so three names are made at once — the owner's number for the
/// alpha's VM; `--workers` sets another, never zero.
const DEFAULT_WORKERS: NonZeroUsize = NonZeroUsize::new(3).expect("three is not zero");

/// THE CONNECTIONS, by default: sixteen threads, each serving one
/// connection at a time, made at start — `skepd`'s own default pool. At
/// sixteen the worst bills stay small: a connection holds at most some 10 MB
/// at once — its half-megabyte read, its form, and a refused post's page
/// echoing a field of quotes six bytes for each it was sent — so sixteen
/// hold some 160 MB; and each holds a socket, beside the pipes of the posts'
/// four looks at once, some fifty descriptors of the unit's 1,024. A
/// person's open page asks for one connection, for milliseconds, every five
/// seconds; `--connections` sets another, never zero.
const DEFAULT_CONNECTIONS: NonZeroUsize = NonZeroUsize::new(16).expect("sixteen is not zero");

/// What the command line asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// `--version`: the line [`version_line`] renders.
    Version,
    /// `--help`: the usage text.
    Help,
    /// `serve`: the service — boxed, its settings many times the other
    /// arms' size.
    Serve(Box<ServeArgs>),
    /// `invite`: one invite minted.
    Invite(InviteArgs),
}

/// `serve`'s settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServeArgs {
    /// `--listen`: the address and port the pages are served on.
    pub listen: SocketAddr,
    /// `--state-dir`: the sign-up file and the invite file. Required.
    pub state_dir: PathBuf,
    /// `--boards-dir`: the snippets.
    pub boards_dir: PathBuf,
    /// The run configuration: `--image`, `--cli-image`, `--network`,
    /// `--caddy`, `--suffix`, `--log-max-size`, `--log-max-file`.
    pub settings: Settings,
    /// `--workers`: the worker threads — the boards made at once. One or
    /// more: a service with none would admit posts and make no board.
    pub workers: NonZeroUsize,
    /// `--connections`: the connection threads — the requests served at
    /// once, a further connection waiting in the listener's queue. One or
    /// more: a service with none would accept no connection.
    pub connections: NonZeroUsize,
    /// `--reply-to`: the owner's mailbox, which D-8 names and the mail
    /// replies to. Required.
    pub reply_to: MailAddress,
    /// `--mailer` with `--from`, or neither: no mail.
    pub mail: Option<MailArgs>,
    /// `--docker-fake <script>`: the scripted runner in the host's place.
    #[cfg(feature = "test-hooks")]
    pub docker_fake: Option<PathBuf>,
}

/// The follow-up mail's settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailArgs {
    /// Who hands the message over.
    pub mailer: Mailer,
    /// `--from`: the sending address.
    pub from: MailAddress,
}

/// Who hands a message over.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mailer {
    /// `--mailer <program>`: the host's relay client, `<program> -t`.
    Program(PathBuf),
    /// `--mailer-fake <log>`: each message appended to the log.
    #[cfg(feature = "test-hooks")]
    Fake(PathBuf),
}

/// `invite`'s settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InviteArgs {
    /// `--address`: where the invitation goes, and the mail after.
    pub address: MailAddress,
    /// `--code`: the code to mint; a fresh one where none is given.
    pub code: Option<InviteCode>,
    /// `--state-dir`: where the invite file lives. Required.
    pub state_dir: PathBuf,
    /// `--suffix`: the invite link's host.
    pub suffix: String,
}

/// THE VERSION LINE (`--version`): `skep-provision <crate version>
/// (<commit>)` — the version Cargo compiled in, and the commit the build
/// named through `SKEP_GIT_SHA`, `unknown` where it named none — `skepd`'s
/// form, read at compile time, so the run consults no file and no variable.
pub fn version_line() -> String {
    format!("skep-provision {} ({})", env!("CARGO_PKG_VERSION"), option_env!("SKEP_GIT_SHA").unwrap_or("unknown"))
}

/// THE USAGE TEXT, every default read from its constant.
pub fn usage() -> String {
    let fakes = if cfg!(feature = "test-hooks") {
        "\n  --docker-fake <SCRIPT>  (test-hooks builds alone) the scripted Docker\n                          runner in the host's place; every call it\n                          receives recorded in <SCRIPT>.calls\n  --mailer-fake <LOG>     (test-hooks builds alone) each message appended\n                          to <LOG>, in --mailer's place\n"
    } else {
        ""
    };
    format!(
        "\
usage: skep-provision serve --state-dir <DIR> --reply-to <ADDRESS>
                            [--listen <ADDR:PORT>] [--boards-dir <DIR>]
                            [--image <TAG>] [--cli-image <TAG>]
                            [--network <BRIDGE>] [--caddy <CONTAINER>]
                            [--suffix <DOMAIN>] [--log-max-size <SIZE>]
                            [--log-max-file <N>] [--workers <N>]
                            [--connections <N>]
                            [--mailer <PROGRAM> --from <ADDRESS>]
       skep-provision invite --address <ADDRESS> --state-dir <DIR>
                            [--code <CODE>] [--suffix <DOMAIN>]
       skep-provision --version

serve: the hosted board's sign-up service — the sign-up page and the
claim form over HTTP, each admitted post provisioned through the host's
docker, different names at once and one post per name; at its start, a
board left half-made by a stop is removed — every volume under its label
whose snippet --boards-dir lacks, so one serve per Docker host.

  --state-dir <DIR>       the sign-up file and the invite file (required):
                          made 0700 where absent; refused at start where
                          other users of this machine can read it
  --reply-to <ADDRESS>    the owner's mailbox (required): the failure page
                          names it, and the follow-up mail replies to it
  --listen <ADDR:PORT>    the address the pages are served on (default
                          {DEFAULT_LISTEN})
  --boards-dir <DIR>      the proxy's snippet directory, one <NAME>.caddy
                          per board (default {DEFAULT_BOARDS_DIR})
  --image <TAG>           the hosted image (default {DEFAULT_IMAGE})
  --cli-image <TAG>       the claim sidecar's image (default {DEFAULT_CLI_IMAGE})
  --network <BRIDGE>      the bridge the boards and the proxy share
                          (default {DEFAULT_NETWORK})
  --caddy <CONTAINER>     the proxy's container (default {DEFAULT_CADDY})
  --suffix <DOMAIN>       the domain every board stands under, <NAME>.<DOMAIN>
                          (default {DEFAULT_SUFFIX})
  --log-max-size <SIZE>   a serving run's log file size, <N>[k|m|g]
                          (default {DEFAULT_LOG_MAX_SIZE})
  --log-max-file <N>      a serving run's log files kept (default {DEFAULT_LOG_MAX_FILE})
  --workers <N>           the boards made at once: one worker thread each,
                          one or more (default {DEFAULT_WORKERS})
  --connections <N>       the requests served at once: one thread each,
                          made at start, a further connection waiting in
                          the listener's queue; one or more (default {DEFAULT_CONNECTIONS})
  --mailer <PROGRAM>      the host's relay client — sendmail or msmtp —
                          run as <PROGRAM> -t with the message on stdin;
                          given with --from or not at all, and without
                          both no mail is sent
  --from <ADDRESS>        the follow-up mail's sending address
{fakes}
invite: one invite minted into the state directory's invite file; its
invite link printed on stdout, the one line to mail by hand.

  --address <ADDRESS>     where the invitation goes (required)
  --state-dir <DIR>       as serve's (required)
  --code <CODE>           the code to mint: 1 to {MAX_CODE_BYTES} letters, digits,
                          '-', '.', '_' or '~'; a fresh random code where
                          none is given
  --suffix <DOMAIN>       the invite link's host (default {DEFAULT_SUFFIX})

  --help                  this text
  --version               this binary's version and the commit it was
                          built from"
    )
}

/// THE PARSE: a leading `--version` or `--help`, or a verb and its flags.
pub fn parse(argv: impl IntoIterator<Item = OsString>) -> Result<Command, String> {
    let argv: Vec<String> = argv.into_iter().map(|a| a.into_string().map_err(|_| "an argument is not UTF-8 text".to_owned())).collect::<Result<_, _>>()?;
    let mut it = argv.into_iter();
    match it.next().as_deref() {
        Some("--version") => Ok(Command::Version),
        Some("--help" | "-h") => Ok(Command::Help),
        Some("serve") => parse_serve(it),
        Some("invite") => parse_invite(it),
        Some(other) => Err(format!("unknown verb '{other}': serve or invite")),
        None => Err("a verb is required: serve or invite".to_owned()),
    }
}

/// One flag's value, or the refusal naming the flag.
fn value(it: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
    it.next().ok_or_else(|| format!("{flag} needs a value"))
}

/// A value that becomes one word of a docker argv: not empty, no
/// whitespace, and not beginning with `-`, so it can never be read as a
/// flag of `docker`'s own.
fn word(flag: &str, v: String) -> Result<String, String> {
    if v.is_empty() || v.starts_with('-') || v.chars().any(char::is_whitespace) {
        return Err(format!("{flag}: '{v}' is not one word that does not begin with '-'"));
    }
    Ok(v)
}

/// A DOMAIN, as `--suffix` takes one: lowercase letters, digits, dots and
/// hyphens, its labels non-empty and none beginning or ending with a
/// hyphen — the daemon's origin grammar for the host it closes.
fn domain(v: String) -> Result<String, String> {
    let labels_ok = v.split('.').all(|l| !l.is_empty() && !l.starts_with('-') && !l.ends_with('-'));
    if v.is_empty() || !labels_ok || !v.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-') {
        return Err(format!("--suffix: '{v}' is not a domain of lowercase letters, digits, dots and hyphens"));
    }
    Ok(v)
}

/// A MAIL ADDRESS by the rule: the value `MailAddress::parse` admits.
fn mail_address(flag: &str, v: String) -> Result<MailAddress, String> {
    MailAddress::parse(&v)
        .ok_or_else(|| format!("{flag}: '{v}' is not an address: one @ with a side each way, at most 254 bytes, no space, no control character, none of ( ) < > [ ] : ; \\ , \" and no bidi control"))
}

/// `serve`'s flags.
fn parse_serve(mut it: impl Iterator<Item = String>) -> Result<Command, String> {
    let mut listen = DEFAULT_LISTEN;
    let mut state_dir: Option<PathBuf> = None;
    let mut boards_dir = PathBuf::from(DEFAULT_BOARDS_DIR);
    let mut settings = Settings {
        image: DEFAULT_IMAGE.to_owned(),
        cli_image: DEFAULT_CLI_IMAGE.to_owned(),
        network: DEFAULT_NETWORK.to_owned(),
        caddy: DEFAULT_CADDY.to_owned(),
        suffix: DEFAULT_SUFFIX.to_owned(),
        log_max_size: DEFAULT_LOG_MAX_SIZE.to_owned(),
        log_max_file: DEFAULT_LOG_MAX_FILE,
    };
    let mut workers = DEFAULT_WORKERS;
    let mut connections = DEFAULT_CONNECTIONS;
    let mut reply_to: Option<MailAddress> = None;
    let mut mailer: Option<Mailer> = None;
    let mut from: Option<MailAddress> = None;
    #[cfg(feature = "test-hooks")]
    let mut docker_fake: Option<PathBuf> = None;
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--listen" => {
                let v = value(&mut it, "--listen")?;
                listen = v.parse().map_err(|_| format!("--listen: '{v}' is not an address and a port"))?;
            }
            "--state-dir" => state_dir = Some(PathBuf::from(value(&mut it, "--state-dir")?)).filter(|p| !p.as_os_str().is_empty()),
            "--boards-dir" => boards_dir = PathBuf::from(value(&mut it, "--boards-dir")?),
            "--image" => settings.image = word("--image", value(&mut it, "--image")?)?,
            "--cli-image" => settings.cli_image = word("--cli-image", value(&mut it, "--cli-image")?)?,
            "--network" => settings.network = word("--network", value(&mut it, "--network")?)?,
            "--caddy" => settings.caddy = word("--caddy", value(&mut it, "--caddy")?)?,
            "--suffix" => settings.suffix = domain(value(&mut it, "--suffix")?)?,
            "--log-max-size" => {
                let v = value(&mut it, "--log-max-size")?;
                let digits = v.strip_suffix(['k', 'm', 'g']).unwrap_or(&v);
                if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(format!("--log-max-size: '{v}' is not a size, <N>[k|m|g]"));
                }
                settings.log_max_size = v;
            }
            "--log-max-file" => {
                let v = value(&mut it, "--log-max-file")?;
                settings.log_max_file = v.parse().map_err(|_| format!("--log-max-file: '{v}' is not a count of one or more"))?;
            }
            "--workers" => {
                let v = value(&mut it, "--workers")?;
                workers = v.parse().map_err(|_| format!("--workers: '{v}' is not a count of one or more"))?;
            }
            "--connections" => {
                let v = value(&mut it, "--connections")?;
                connections = v.parse().map_err(|_| format!("--connections: '{v}' is not a count of one or more"))?;
            }
            "--reply-to" => reply_to = Some(mail_address("--reply-to", value(&mut it, "--reply-to")?)?),
            "--mailer" => mailer = Some(Mailer::Program(PathBuf::from(value(&mut it, "--mailer")?))),
            "--from" => from = Some(mail_address("--from", value(&mut it, "--from")?)?),
            #[cfg(feature = "test-hooks")]
            "--docker-fake" => docker_fake = Some(PathBuf::from(value(&mut it, "--docker-fake")?)),
            #[cfg(feature = "test-hooks")]
            "--mailer-fake" => mailer = Some(Mailer::Fake(PathBuf::from(value(&mut it, "--mailer-fake")?))),
            "--help" | "-h" => return Ok(Command::Help),
            "--version" => return Err("--version is read as the first argument: skep-provision --version".to_owned()),
            other => return Err(format!("serve: unknown argument '{other}'")),
        }
    }
    let mail = match (mailer, from) {
        (Some(mailer), Some(from)) => Some(MailArgs { mailer, from }),
        (None, None) => None,
        (Some(_), None) => return Err("--mailer is given without --from: give both, or neither for no mail".to_owned()),
        (None, Some(_)) => return Err("--from is given without --mailer: give both, or neither for no mail".to_owned()),
    };
    Ok(Command::Serve(Box::new(ServeArgs {
        listen,
        state_dir: state_dir.ok_or("serve: --state-dir is required")?,
        boards_dir,
        settings,
        workers,
        connections,
        reply_to: reply_to.ok_or("serve: --reply-to is required")?,
        mail,
        #[cfg(feature = "test-hooks")]
        docker_fake,
    })))
}

/// `invite`'s flags.
fn parse_invite(mut it: impl Iterator<Item = String>) -> Result<Command, String> {
    let mut address: Option<MailAddress> = None;
    let mut code: Option<InviteCode> = None;
    let mut state_dir: Option<PathBuf> = None;
    let mut suffix = DEFAULT_SUFFIX.to_owned();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--address" => address = Some(mail_address("--address", value(&mut it, "--address")?)?),
            "--code" => {
                let v = value(&mut it, "--code")?;
                code = Some(InviteCode::parse(&v).ok_or_else(|| format!("--code: '{v}' is not 1 to {MAX_CODE_BYTES} letters, digits, '-', '.', '_' or '~'"))?);
            }
            "--state-dir" => state_dir = Some(PathBuf::from(value(&mut it, "--state-dir")?)).filter(|p| !p.as_os_str().is_empty()),
            "--suffix" => suffix = domain(value(&mut it, "--suffix")?)?,
            "--help" | "-h" => return Ok(Command::Help),
            "--version" => return Err("--version is read as the first argument: skep-provision --version".to_owned()),
            other => return Err(format!("invite: unknown argument '{other}'")),
        }
    }
    Ok(Command::Invite(InviteArgs { address: address.ok_or("invite: --address is required")?, code, state_dir: state_dir.ok_or("invite: --state-dir is required")?, suffix }))
}

#[cfg(test)]
mod tests;
