//! The `skepd` binary: flags/env → [`Daemon::open`] → [`serve`] → wait.
//! Crash-stop is the shutdown story (M2's WAL recovers), so there is no
//! signal handling to get wrong.

use std::path::PathBuf;
use std::process::exit;

use skepd::{serve, Daemon};

const DEFAULT_PORT: u16 = 8642;
const DEFAULT_WORKERS: usize = 4;

const USAGE: &str = "\
usage: skepd --data-dir <DIR> [--port <PORT>] [--workers <N>]

  --data-dir <DIR>   journal/checkpoint directory (env: SKEPD_DATA_DIR);
                     created if absent, recovered if populated
  --port <PORT>      TCP port on 127.0.0.1 (env: SKEPD_PORT; default 8642;
                     0 picks an ephemeral port)
  --workers <N>      request worker threads (env: SKEPD_WORKERS; default 4)
  --help             this text

The wire protocol is specified in skep/docs/wire.md.";

struct Args {
    data_dir: PathBuf,
    port: u16,
    workers: usize,
}

fn parse_args(argv: impl Iterator<Item = String>) -> Result<Args, String> {
    let mut data_dir = std::env::var_os("SKEPD_DATA_DIR").map(PathBuf::from);
    let mut port: Option<u16> = None;
    let mut workers: Option<usize> = None;
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
            "--help" | "-h" => {
                println!("{USAGE}");
                exit(0);
            }
            other => return Err(format!("unknown argument '{other}'")),
        }
    }
    if port.is_none() {
        if let Ok(v) = std::env::var("SKEPD_PORT") {
            port = Some(v.parse().map_err(|_| format!("SKEPD_PORT: '{v}' is not a port"))?);
        }
    }
    if workers.is_none() {
        if let Ok(v) = std::env::var("SKEPD_WORKERS") {
            workers =
                Some(v.parse().map_err(|_| format!("SKEPD_WORKERS: '{v}' is not a count"))?);
        }
    }
    Ok(Args {
        data_dir: data_dir.ok_or("--data-dir (or SKEPD_DATA_DIR) is required")?,
        port: port.unwrap_or(DEFAULT_PORT),
        workers: workers.unwrap_or(DEFAULT_WORKERS).max(1),
    })
}

fn main() {
    let args = match parse_args(std::env::args().skip(1)) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("skepd: {e}\n\n{USAGE}");
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
