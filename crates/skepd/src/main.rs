//! The `skepd` binary: flags/env → [`Daemon::open`] → [`serve`] → wait.
//! Crash-stop is the shutdown story (M2's WAL recovers), so there is no
//! signal handling to get wrong.

use std::path::PathBuf;
use std::process::exit;

use skepd::{serve, Daemon};

const DEFAULT_PORT: u16 = 8642;
const DEFAULT_WORKERS: usize = 4;

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
{DEFAULT_WORKERS})
  --help             this text

The wire protocol is specified in skep/docs/wire.md."
    )
}

struct Args {
    data_dir: PathBuf,
    port: u16,
    workers: usize,
}

/// Read one setting from the environment, or `None` when it is unset. Each
/// setting is seeded from its variable before the flag loop, so a flag
/// always wins over a variable and the precedence is stated once.
fn from_env<T: std::str::FromStr>(var: &str, what: &str) -> Result<Option<T>, String> {
    match std::env::var(var) {
        Err(_) => Ok(None),
        Ok(v) => v
            .parse()
            .map(Some)
            .map_err(|_| format!("{var}: '{v}' is not {what}")),
    }
}

/// The command line, or `None` when the caller asked for the usage text.
/// Parsing decides what was asked for; ending the process is [`main`]'s.
fn parse_args(argv: impl Iterator<Item = String>) -> Result<Option<Args>, String> {
    let mut data_dir = std::env::var_os("SKEPD_DATA_DIR").map(PathBuf::from);
    let mut port: Option<u16> = from_env("SKEPD_PORT", "a port")?;
    let mut workers: Option<usize> = from_env("SKEPD_WORKERS", "a count")?;
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
    Ok(Some(Args {
        data_dir: data_dir.ok_or("--data-dir (or SKEPD_DATA_DIR) is required")?,
        port: port.unwrap_or(DEFAULT_PORT),
        workers: workers.unwrap_or(DEFAULT_WORKERS).max(1),
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
    }
}
