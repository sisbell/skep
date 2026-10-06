//! The `skepd` binary: flags/env → [`Daemon::open_configured`] → [`serve`] →
//! wait. Crash-stop is the shutdown story (M2's WAL recovers), so there is
//! no signal handling to get wrong. And THE OPERATOR's TWO TOOLS over a
//! board directory, run with no server — `skepd inventory` and `skepd pull`
//! (`skepd::tools`) — a leading verb parsed before any flag.

use std::path::PathBuf;
use std::process::exit;

// `DEFAULT_WORKERS` is the LIBRARY's, not this binary's: it is the fifth
// term of a relation whose other four are the daemon's permit pools, and the
// library holds the assertion that keeps the five in step.
use skepd::{serve, tools, AuthOptions, Daemon, MediaOptions, NodePrefix, Origin, DEFAULT_WORKERS};

const DEFAULT_PORT: u16 = 8642;

/// One environment setting: the variable's name and what its value must be,
/// paired so the two cannot be handed over in the wrong order — the same
/// reason [`skepd::HttpRequest`] is one value rather than five arguments. A
/// swap reads an unset variable, answers `None`, and silently falls back to
/// the default, so the setting stops working with no message anywhere.
struct EnvSetting {
    var: &'static str,
    expected: &'static str,
}

const SKEPD_PORT: EnvSetting = EnvSetting { var: "SKEPD_PORT", expected: "a port" };
const SKEPD_WORKERS: EnvSetting = EnvSetting { var: "SKEPD_WORKERS", expected: "a count" };
const SKEPD_LOCAL_TRUST: EnvSetting =
    EnvSetting { var: "SKEPD_LOCAL_TRUST", expected: "true or false" };
/// The upload setting's variable (wire.md §Media, THE UPLOAD SETTING):
/// `false` closes the upload family, as `--no-uploads` does.
const SKEPD_UPLOADS: EnvSetting = EnvSetting { var: "SKEPD_UPLOADS", expected: "true or false" };

/// The data dir's variable, a bare name rather than an [`EnvSetting`]: its
/// value is a PATH, which is whatever bytes the platform says and never owes
/// being text, so it is read with `var_os` and nothing about it can be "not
/// what was expected" at the parse.
const SKEPD_DATA_DIR: &str = "SKEPD_DATA_DIR";

/// The origin list's variable, a bare name rather than an [`EnvSetting`]:
/// its value is a LIST, so [`from_env`] cannot carry it, and the phrase
/// that pair exists to hold is [`skepd::NotCanonical`]'s — one home for
/// what a canonical origin is, shared with the `--origin` flag.
const SKEPD_ORIGIN: &str = "SKEPD_ORIGIN";

/// The blocked-prefix list's variable, a bare name as the data dir's is: its
/// value is a PATH, which is whatever bytes the platform says and never owes
/// being text, so it is read with `var_os` and nothing about it can be "not
/// what was expected" at the parse. Whether the file it names is a list is
/// [`Daemon::open_with`]'s to say.
const SKEPD_BLOCKED_PREFIXES: &str = "SKEPD_BLOCKED_PREFIXES";

/// The node prefix's variable (REG-1.69), carried by [`from_env`] like every
/// other setting: [`NodePrefix`]'s `FromStr` is what lets it, so the two
/// rules that pair holds — a non-UTF-8 value refused rather than read as
/// absent, and one message shape — are stated once and spent here too.
const SKEPD_NODE_PREFIX: EnvSetting =
    EnvSetting { var: "SKEPD_NODE_PREFIX", expected: NODE_PREFIX_FORM };

/// What `--node-prefix` takes (REG-1.66, REG-1.69), said once for the flag,
/// the variable and the usage text.
const NODE_PREFIX_FORM: &str =
    "a node prefix of the form 1.N — the board's node address under the root 1, never the root itself";

/// The help text, with each default read from the constant that supplies
/// it — so the program cannot describe a default it does not use.
fn usage() -> String {
    format!(
        "\
usage: skepd --data-dir <DIR> [--port <PORT>] [--workers <N>]
             [--local-trust | --no-local-trust] [--allow-preview-keys]
             [--uploads | --no-uploads]
             [--origin <ORIGIN>]... [--blocked-prefixes <FILE>]
             [--node-prefix <PREFIX>]
       skepd inventory --data-dir <DIR> [--no-rehash]
       skepd pull --data-dir <DIR> [--hash <HEX>] <FILE>

  --data-dir <DIR>   journal/checkpoint directory (env: SKEPD_DATA_DIR);
                     created if absent, recovered if populated
  --port <PORT>      TCP port on 127.0.0.1 (env: SKEPD_PORT; default \
{DEFAULT_PORT};
                     0 picks an ephemeral port)
  --workers <N>      request worker threads (env: SKEPD_WORKERS; default \
{DEFAULT_WORKERS};
                     minimum 1)
  --local-trust      honor bare (unsigned) loopback sessions after the
                     board is claimed (the default — a hosted image must
                     pass --no-local-trust affirmatively)
  --no-local-trust   refuse every bare session once the board is claimed
                     (env: SKEPD_LOCAL_TRUST=true|false)
  --uploads          admit the blob upload family (the default), under a
                     per-account limit of one eighth of the volume's
                     capacity, never below 256 MiB, until a limits record
                     is installed; echoed on /health as media.uploads
  --no-uploads       refuse the upload's creation and resume before any
                     body byte (403 upload_refused, detail uploads_closed);
                     the reads, the termination, the door and the pruner
                     serve as before (env: SKEPD_UPLOADS=true|false)
  --allow-preview-keys
                     a DEV setting: admit the ENROLLMENT of PREVIEW keys
                     (the tag-3 row, fndsa512-preview-ed25519). Off — the
                     default — an enrollment record naming one is refused
                     credential_refused preview_key, a genesis included;
                     a served board runs without it. It gates enrollment
                     alone: verification of tag 3 stays compiled in, and
                     the fold admits the row as syntax
  --origin <ORIGIN>  a canonical origin this board answers for, e.g.
                     https://board.example — repeatable; the signed
                     session arm accepts ONLY these once the board is
                     claimed (env: SKEPD_ORIGIN, comma-separated)
  --blocked-prefixes <FILE>
                     the blocked-prefix list the operator maintains
                     (env: SKEPD_BLOCKED_PREFIXES): one JSON object,
                     {{\"operator\": <account>, \"binding_writer\": <account>,
                      \"entries\": [{{\"prefix\": <address>,
                                   \"record\": <address>}}, ...]}}
                     — the two header fields optional. A session under a
                     listed prefix is refused 403 prefix_blocked and a
                     live one ends. Read at EVERY start (a file that
                     cannot be read, or is not a list, stops the start)
                     and re-read whenever it is REPLACED — write the new
                     list beside it and rename it over; no restart, no
                     signal
  --node-prefix <PREFIX>
                     the board's full node prefix in the registry, 1.N
                     (env: SKEPD_NODE_PREFIX) — an address under the root
                     1, never the root itself. Egress and assertion
                     config, per daemon, supplied at every start and
                     never journaled; a fresh prefix is a reconfigure
                     and restart. What it decides here: the blocked-
                     prefix list's off-board test — whether the list's
                     configured operator account is an account of this
                     board — runs against it. Without it that test is
                     OFF (every operator reads as this board's own): a
                     hosted board must supply one
  --help             this text

The operator's two tools run over a board directory with NO server — no
port, no session — and write no log line of the daemon's:

  skepd inventory --data-dir <DIR> [--no-rehash]
                     over a directory no daemon serves (a stopped board, a
                     backup, one moment's copy): one JSON object on stdout
                     — the holes (every picture cell whose file is absent,
                     of another length, or — re-hashed, one whole read per
                     file, skipped by --no-rehash — of other bytes), each
                     account's base and pending bytes and the venue total,
                     the standing and expired uploads, the halt marks and
                     any foreign designation directory. Recording no read.
                     The journal is opened as the daemon opens it: a
                     directory a daemon serves is refused at the kernel's
                     lock; a torn tail is cut as every open cuts it
  skepd pull --data-dir <DIR> [--hash <HEX>] <FILE>
                     restore <FILE> at blobs/blake3/<its hash> by the PUT's
                     own install order — REPLACE where a file stands — with
                     no lease, no record and no journal entry: a restore,
                     never a deposit. Without --hash the board's journal is
                     read and a file no committed cell names is refused;
                     with --hash <HEX> (the inventory's listing) the file is
                     held to that hash and the journal left unopened, the
                     form that runs beside a serving daemon

The wire protocol is specified in skep/docs/wire.md."
    )
}

/// What the command line asked for: the daemon, or one of the two tools.
enum Command {
    Serve(Args),
    Inventory { data_dir: PathBuf, rehash: bool },
    Pull { data_dir: PathBuf, hash: Option<String>, file: PathBuf },
}

struct Args {
    data_dir: PathBuf,
    port: u16,
    workers: usize,
    local_trust: bool,
    /// `--uploads` / `--no-uploads` (wire.md §Media): the upload family's
    /// switch, OPEN by default.
    uploads: bool,
    /// `--allow-preview-keys` (AUTH-1.44): a flag, no environment variable —
    /// a dev setting a served board never sets, so nothing can turn it on in
    /// silence from the image's environment.
    allow_preview_keys: bool,
    origins: Vec<Origin>,
    blocked_prefixes: Option<PathBuf>,
    node_prefix: Option<NodePrefix>,
}

/// Read one setting from the environment, or `None` when it is UNSET. Each
/// setting is seeded from its variable before the flag loop, so a flag
/// always wins over a variable and the precedence is stated once.
fn from_env<T: std::str::FromStr>(setting: EnvSetting) -> Result<Option<T>, String> {
    use std::env::VarError;
    match std::env::var(setting.var) {
        Err(VarError::NotPresent) => Ok(None),
        // Set, and not readable as text. Refused rather than treated as
        // absent: silently falling back to the default is the one failure
        // [`EnvSetting`] exists to prevent, and it does not become
        // acceptable because the bad value is bytes rather than the wrong
        // word.
        Err(VarError::NotUnicode(_)) => {
            Err(format!("{}: the value is not UTF-8 text", setting.var))
        }
        Ok(v) => v.parse().map(Some).map_err(|_| {
            format!("{}: '{v}' is not {}", setting.var, setting.expected)
        }),
    }
}

/// The command line, or `None` when the caller asked for the usage text:
/// a leading verb names a tool, read before any flag; anything else is the
/// daemon's own line. Parsing decides what was asked for; ending the
/// process is [`main`]'s.
fn parse_command(argv: impl Iterator<Item = String>) -> Result<Option<Command>, String> {
    let mut it = argv.peekable();
    match it.peek().map(String::as_str) {
        Some("inventory") => {
            it.next();
            parse_tool(it, false)
        }
        Some("pull") => {
            it.next();
            parse_tool(it, true)
        }
        _ => Ok(parse_args(it)?.map(Command::Serve)),
    }
}

/// A tool's line: `--data-dir <DIR>` (or the variable), `--no-rehash` for
/// the inventory, `--hash <HEX>` and the one positional `<FILE>` for the
/// pull; `--help` the usage text.
fn parse_tool(mut it: impl Iterator<Item = String>, pull: bool) -> Result<Option<Command>, String> {
    let verb = if pull { "pull" } else { "inventory" };
    let mut data_dir = std::env::var_os(SKEPD_DATA_DIR).map(PathBuf::from);
    let mut rehash = true;
    let mut hash: Option<String> = None;
    let mut file: Option<PathBuf> = None;
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--data-dir" => {
                let v = it.next().ok_or("--data-dir needs a value")?;
                data_dir = Some(PathBuf::from(v));
            }
            "--no-rehash" if !pull => rehash = false,
            "--hash" if pull => {
                let v = it.next().ok_or("--hash needs a value")?;
                hash = Some(v);
            }
            "--help" | "-h" => return Ok(None),
            other if pull && !other.starts_with("--") && file.is_none() => {
                file = Some(PathBuf::from(other));
            }
            other => return Err(format!("{verb}: unknown argument '{other}'")),
        }
    }
    let data_dir =
        data_dir.ok_or_else(|| format!("{verb}: --data-dir (or {SKEPD_DATA_DIR}) is required"))?;
    Ok(Some(if pull {
        let file = file.ok_or("pull: the file to restore is required")?;
        Command::Pull { data_dir, hash, file }
    } else {
        Command::Inventory { data_dir, rehash }
    }))
}

/// The daemon's own command line, or `None` when the caller asked for the
/// usage text.
fn parse_args(argv: impl Iterator<Item = String>) -> Result<Option<Args>, String> {
    let mut data_dir = std::env::var_os(SKEPD_DATA_DIR).map(PathBuf::from);
    let mut port: Option<u16> = from_env(SKEPD_PORT)?;
    let mut workers: Option<usize> = from_env(SKEPD_WORKERS)?;
    let mut local_trust: Option<bool> = from_env(SKEPD_LOCAL_TRUST)?;
    let mut uploads: Option<bool> = from_env(SKEPD_UPLOADS)?;
    // The one setting [`from_env`] cannot carry, being a LIST — so the
    // two rules that helper holds are restated here and nowhere else: a
    // variable set to bytes that are not text is refused rather than read
    // as absent, and each element goes through [`Origin`]'s own `FromStr`.
    let mut origins: Vec<Origin> = match std::env::var(SKEPD_ORIGIN) {
        Err(std::env::VarError::NotPresent) => Vec::new(),
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err(format!("{}: the value is not UTF-8 text", SKEPD_ORIGIN))
        }
        Ok(v) => v
            .split(',')
            .filter(|s| !s.is_empty())
            .map(|s| {
                s.parse::<Origin>().map_err(|e| {
                    format!("{}: '{s}' is {e}", SKEPD_ORIGIN)
                })
            })
            .collect::<Result<_, _>>()?,
    };
    let mut blocked_prefixes = std::env::var_os(SKEPD_BLOCKED_PREFIXES).map(PathBuf::from);
    let mut node_prefix: Option<NodePrefix> = from_env(SKEPD_NODE_PREFIX)?;
    // Default OFF, and no variable seeds it (AUTH-1.44: "the daemon REFUSES
    // ENROLLMENT of a tag-3 key unless this setting allows it").
    let mut allow_preview_keys = false;
    let mut it = argv;
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--data-dir" => {
                let v = it.next().ok_or("--data-dir needs a value")?;
                data_dir = Some(PathBuf::from(v));
            }
            "--port" => {
                let v = it.next().ok_or("--port needs a value")?;
                port = Some(v.parse().map_err(|_| format!("--port: '{v}' is not a port"))?);
            }
            "--workers" => {
                let v = it.next().ok_or("--workers needs a value")?;
                workers =
                    Some(v.parse().map_err(|_| format!("--workers: '{v}' is not a count"))?);
            }
            "--local-trust" => local_trust = Some(true),
            "--no-local-trust" => local_trust = Some(false),
            "--uploads" => uploads = Some(true),
            "--no-uploads" => uploads = Some(false),
            "--allow-preview-keys" => allow_preview_keys = true,
            "--origin" => {
                let v = it.next().ok_or("--origin needs a value")?;
                origins.push(
                    v.parse::<Origin>().map_err(|e| format!("--origin: '{v}' is {e}"))?,
                );
            }
            "--blocked-prefixes" => {
                let v = it.next().ok_or("--blocked-prefixes needs a value")?;
                blocked_prefixes = Some(PathBuf::from(v));
            }
            "--node-prefix" => {
                let v = it.next().ok_or("--node-prefix needs a value")?;
                node_prefix = Some(v.parse::<NodePrefix>().map_err(|_| {
                    format!("--node-prefix: '{v}' is not {NODE_PREFIX_FORM}")
                })?);
            }
            "--help" | "-h" => return Ok(None),
            other => return Err(format!("unknown argument '{other}'")),
        }
    }
    // Refused, never repaired. `serve` states `workers >= 1` as a
    // precondition and asserts it, and the wire surface refuses an
    // out-of-range page size rather than clamping it; a count silently
    // raised to one here would be the third answer to that one question,
    // and the one that teaches a caller its zero was fine.
    let workers = workers.unwrap_or(DEFAULT_WORKERS);
    if workers == 0 {
        return Err("--workers: a server with no workers serves nothing".into());
    }
    Ok(Some(Args {
        data_dir: data_dir
            .ok_or_else(|| format!("--data-dir (or {SKEPD_DATA_DIR}) is required"))?,
        port: port.unwrap_or(DEFAULT_PORT),
        workers,
        // Phase A default ON (AUTH-1.45): a hosted image must set the flag
        // AFFIRMATIVELY false — abstention keeps the notebook behavior.
        local_trust: local_trust.unwrap_or(true),
        // OPEN by default (the owner's ruling), the default per-account
        // limit in force from start; the off switch is affirmative.
        uploads: uploads.unwrap_or(true),
        allow_preview_keys,
        origins,
        blocked_prefixes,
        node_prefix,
    }))
}

fn main() {
    let args = match parse_command(std::env::args().skip(1)) {
        Ok(Some(Command::Serve(a))) => a,
        // THE TOOLS: one object or one line on stdout, one line on stderr
        // where refused, no server bound.
        Ok(Some(Command::Inventory { data_dir, rehash })) => match tools::inventory(&data_dir, rehash) {
            Ok(v) => {
                println!("{}", serde_json::to_string_pretty(&v).expect("a JSON value renders"));
                exit(0);
            }
            Err(e) => {
                eprintln!("skepd inventory: {e}");
                exit(1);
            }
        },
        Ok(Some(Command::Pull { data_dir, hash, file })) => match tools::pull(&data_dir, &file, hash.as_deref()) {
            Ok(pulled) => {
                println!("pulled {} ({} bytes) into {}", pulled.hex, pulled.size, pulled.path.display());
                exit(0);
            }
            Err(e) => {
                eprintln!("skepd pull: {e}");
                exit(1);
            }
        },
        Ok(None) => {
            println!("{}", usage());
            exit(0);
        }
        Err(e) => {
            eprintln!("skepd: {e}\n\n{}", usage());
            exit(2);
        }
    };
    // Genesis-or-recover; every EngineError is an operator condition
    // (corrupt journal, bad checkpoint) — report and stop.
    // `--origin` names the CONFIGURED set — the flag's own vocabulary and
    // the field's meet here, at the two lines that carry them across. Built
    // from the defaults and then set, which is what `AuthOptions` being
    // `#[non_exhaustive]` asks: a knob this binary grows no flag for arrives
    // at its own default rather than at whatever a literal here omitted.
    let mut opts = AuthOptions::default();
    opts.local_trust = args.local_trust;
    // The dev setting (AUTH-1.44): ENROLLMENT of tag-3 keys, refused unless
    // the flag says otherwise; a served board is launched without it.
    opts.allow_preview_keys = args.allow_preview_keys;
    opts.configured = args.origins;
    // Supplied at every start, as `--origin` is (AUTH-4.70): the file is
    // read inside the open, and one that is not a list stops the start.
    opts.blocked_supply_path = args.blocked_prefixes;
    // The node prefix (REG-1.69): egress and assertion config, supplied at
    // every start and never journaled — a fresh one is this binary
    // relaunched (REG-1.70). `serve` names it, or its absence, at start.
    opts.node_prefix = args.node_prefix;
    // The media resource's setting (wire.md §Media): the upload switch,
    // open unless `--no-uploads` closed it.
    let mut media = MediaOptions::default();
    media.uploads = args.uploads;
    let daemon = match Daemon::open_configured(&args.data_dir, opts, media) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("skepd: {e}");
            exit(1);
        }
    };
    let seq = daemon.log_position();
    let running = match serve(daemon, args.port, args.workers) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("skepd: bind 127.0.0.1:{}: {e}", args.port);
            exit(1);
        }
    };
    println!(
        "skepd: serving http://127.0.0.1:{}/ data-dir {} log-position {} workers {}",
        running.port(),
        args.data_dir.display(),
        seq.0,
        args.workers
    );
    running.wait();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(args: &[&str]) -> impl Iterator<Item = String> {
        args.iter().map(|s| s.to_string()).collect::<Vec<_>>().into_iter()
    }

    /// Asking for the usage text is an outcome the caller receives, not an
    /// exit taken inside the parser — which is what makes every other case
    /// here testable at all.
    #[test]
    fn help_is_an_answer_not_an_exit() {
        for flag in ["--help", "-h"] {
            let parsed = parse_args(argv(&[flag])).expect("--help is not an error");
            assert!(parsed.is_none(), "{flag} asks for usage, not a run");
            assert!(parse_command(argv(&["inventory", flag])).expect("usage").is_none());
            assert!(parse_command(argv(&["pull", flag])).expect("usage").is_none());
        }
    }

    /// THE UPLOAD SETTING (wire.md §Media): OPEN unless `--no-uploads` is
    /// given, `--uploads` the affirmative default, and the usage text names
    /// both with the variable.
    #[test]
    fn the_upload_setting_is_open_unless_closed() {
        let absent = parse_args(argv(&["--data-dir", "/tmp/x"])).expect("valid").expect("a run");
        assert!(absent.uploads, "open by default");
        let closed = parse_args(argv(&["--data-dir", "/tmp/x", "--no-uploads"])).expect("valid").expect("a run");
        assert!(!closed.uploads);
        let open = parse_args(argv(&["--data-dir", "/tmp/x", "--no-uploads", "--uploads"])).expect("valid").expect("a run");
        assert!(open.uploads, "the last flag wins, as --local-trust's pair does");
        let text = usage();
        for named in ["--no-uploads", "SKEPD_UPLOADS", "skepd inventory", "skepd pull", "--no-rehash", "--hash"] {
            assert!(text.contains(named), "the usage names {named}");
        }
    }

    /// THE TOOLS' LINES: a leading verb names the tool before any flag; the
    /// inventory takes its directory and `--no-rehash`, the pull its
    /// directory, an optional `--hash` and one file; a missing directory or
    /// file, an unknown flag and a daemon flag under a tool are refused by
    /// name; and a line with no verb is the daemon's own.
    #[test]
    fn the_tools_parse_a_leading_verb_before_their_flags() {
        match parse_command(argv(&["inventory", "--data-dir", "/tmp/b"])).expect("valid").expect("a tool") {
            Command::Inventory { data_dir, rehash } => {
                assert_eq!(data_dir, PathBuf::from("/tmp/b"));
                assert!(rehash, "re-hashed by default");
            }
            _ => panic!("the inventory"),
        }
        match parse_command(argv(&["inventory", "--no-rehash", "--data-dir", "/tmp/b"])).expect("valid").expect("a tool") {
            Command::Inventory { rehash, .. } => assert!(!rehash),
            _ => panic!("the inventory"),
        }
        match parse_command(argv(&["pull", "--data-dir", "/tmp/b", "/tmp/picture"])).expect("valid").expect("a tool") {
            Command::Pull { data_dir, hash, file } => {
                assert_eq!((data_dir, hash, file), (PathBuf::from("/tmp/b"), None, PathBuf::from("/tmp/picture")));
            }
            _ => panic!("the pull"),
        }
        let hex = "ab".repeat(32);
        match parse_command(argv(&["pull", "--hash", &hex, "/tmp/picture", "--data-dir", "/tmp/b"])).expect("valid").expect("a tool") {
            Command::Pull { hash, file, .. } => {
                assert_eq!((hash, file), (Some(hex.clone()), PathBuf::from("/tmp/picture")));
            }
            _ => panic!("the pull"),
        }
        for bad in [
            &["inventory"][..],
            &["pull", "--data-dir", "/tmp/b"],
            &["pull", "--data-dir", "/tmp/b", "a", "b"],
            &["inventory", "--data-dir", "/tmp/b", "--hash", "x"],
            &["pull", "--data-dir", "/tmp/b", "--no-rehash", "f"],
            &["inventory", "--data-dir", "/tmp/b", "--port", "1"],
            &["inventory", "--data-dir"],
        ] {
            assert!(parse_command(argv(bad)).is_err(), "{bad:?} is refused");
        }
        assert!(matches!(
            parse_command(argv(&["--data-dir", "/tmp/x"])).expect("valid"),
            Some(Command::Serve(_))
        ));
    }

    /// Flags are read as given; a missing data dir and an unknown argument
    /// are named refusals.
    #[test]
    fn flags_parse_and_refusals_are_named() {
        let a = parse_args(argv(&["--data-dir", "/tmp/skepd-test", "--port", "0"]))
            .expect("valid flags")
            .expect("a run, not usage");
        assert_eq!(a.data_dir, PathBuf::from("/tmp/skepd-test"));
        assert_eq!(a.port, 0);
        let a = parse_args(argv(&["--data-dir", "/tmp/x", "--blocked-prefixes", "/etc/skepd/blocked.json"]))
            .expect("valid flags")
            .expect("a run, not usage");
        assert_eq!(
            a.blocked_prefixes,
            Some(PathBuf::from("/etc/skepd/blocked.json")),
            "the list's supply is a path, carried as given — reading it is the open's"
        );
        assert!(
            parse_args(argv(&["--data-dir", "/tmp/x", "--blocked-prefixes"])).is_err(),
            "the flag without its file is refused"
        );
        assert!(parse_args(argv(&["--frobnicate"])).is_err(), "an unknown argument is refused");
        assert!(parse_args(argv(&["--port"])).is_err(), "a flag without its value is refused");
        assert!(
            parse_args(argv(&["--data-dir", "/tmp/x", "--port", "notaport"])).is_err(),
            "a non-numeric port is refused"
        );
        assert!(
            parse_args(argv(&["--data-dir", "/tmp/x", "--workers", "0"])).is_err(),
            "a zero worker count is refused, not repaired into a one-worker server"
        );
        assert_eq!(
            parse_args(argv(&["--data-dir", "/tmp/x", "--workers", "2"]))
                .expect("a count of two is in range")
                .expect("a run, not usage")
                .workers,
            2,
            "and a count in range is read as given"
        );
    }

    /// AUTH-1.44's `--allow-preview-keys`: a bare flag, OFF unless given, and
    /// seeded by no environment variable — a served board's image cannot
    /// turn it on in silence.
    #[test]
    fn the_preview_keys_flag_is_off_unless_given() {
        let absent = parse_args(argv(&["--data-dir", "/tmp/x"]))
            .expect("valid flags")
            .expect("a run, not usage");
        assert!(!absent.allow_preview_keys, "the default is OFF");
        let given = parse_args(argv(&["--data-dir", "/tmp/x", "--allow-preview-keys"]))
            .expect("valid flags")
            .expect("a run, not usage");
        assert!(given.allow_preview_keys, "the flag turns it on");
        assert!(
            parse_args(argv(&["--data-dir", "/tmp/x", "--allow-preview-keys", "true"])).is_err(),
            "the flag takes no value: a trailing word is an unknown argument"
        );
    }

    /// REG-1.69's `--node-prefix 1.N`: an address under the root `1`, read
    /// as given and optional; the root itself, an address under another
    /// first component, and an account address are refused at the parse
    /// with the form named — never repaired, never read as absent.
    #[test]
    fn the_node_prefix_flag_takes_a_node_address_under_the_root_and_nothing_else() {
        let a = parse_args(argv(&["--data-dir", "/tmp/x", "--node-prefix", "1.3"]))
            .expect("valid flags")
            .expect("a run, not usage");
        assert_eq!(
            a.node_prefix.as_ref().map(|p| p.to_string()),
            Some("1.3".to_string()),
            "the board's node prefix, as given"
        );
        let absent = parse_args(argv(&["--data-dir", "/tmp/x"]))
            .expect("valid flags")
            .expect("a run, not usage");
        assert!(absent.node_prefix.is_none(), "the flag is optional: a notebook has none");
        for bad in ["1", "2.4", "1.3.0.7", "1.0", "x", ""] {
            match parse_args(argv(&["--data-dir", "/tmp/x", "--node-prefix", bad])) {
                Err(refused) => assert!(
                    refused.starts_with(&format!("--node-prefix: '{bad}' is not a node prefix")),
                    "the refusal names the flag, the value and the form: {refused}"
                ),
                Ok(_) => panic!("'{bad}' is not a node prefix, and was not refused"),
            }
        }
        assert!(
            parse_args(argv(&["--data-dir", "/tmp/x", "--node-prefix"])).is_err(),
            "the flag without its value is refused"
        );
    }
}
