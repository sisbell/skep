//! The `skepd` binary: flags/env → [`Daemon::open`] → [`serve`] → wait.
//! Crash-stop is the shutdown story (M2's WAL recovers), so there is no
//! signal handling to get wrong.

use std::path::PathBuf;
use std::process::exit;

use skepd::{serve, Daemon};

const DEFAULT_PORT: u16 = 8642;
const DEFAULT_WORKERS: usize = 4;

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

/// The help text, with each default read from the constant that supplies
/// it — so the program cannot describe a default it does not use.
fn usage() -> String {
    format!(
        "\
usage: skepd --data-dir <DIR> [--port <PORT>] [--workers <N>]

  --data-dir <DIR>   journal/checkpoint directory (env: SKEPD_DATA_DIR);
                     created if absent, recovered if populated
  --port <PORT>      TCP port on 127.0.0.1 (env: SKEPD_PORT; default \
{DEFAULT_PORT};
                     0 picks an ephemeral port)
  --workers <N>      request worker threads (env: SKEPD_WORKERS; default \
{DEFAULT_WORKERS};
                     minimum 1)
  --help             this text

The wire protocol is specified in skep/docs/wire.md."
    )
}

struct Args {
    data_dir: PathBuf,
    port: u16,
    workers: usize,
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

/// The command line, or `None` when the caller asked for the usage text.
/// Parsing decides what was asked for; ending the process is [`main`]'s.
fn parse_args(argv: impl Iterator<Item = String>) -> Result<Option<Args>, String> {
    let mut data_dir = std::env::var_os("SKEPD_DATA_DIR").map(PathBuf::from);
    let mut port: Option<u16> = from_env(SKEPD_PORT)?;
    let mut workers: Option<usize> = from_env(SKEPD_WORKERS)?;
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
        data_dir: data_dir.ok_or("--data-dir (or SKEPD_DATA_DIR) is required")?,
        port: port.unwrap_or(DEFAULT_PORT),
        workers,
    }))
}

fn main() {
    let args = match parse_args(std::env::args().skip(1)) {
        Ok(Some(a)) => a,
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
    // (corrupt journal, bad checkpoint, drifted genesis) — report and stop.
    let daemon = match Daemon::open(&args.data_dir) {
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
        }
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
}
