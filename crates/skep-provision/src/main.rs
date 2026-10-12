//! # skep-provision — the service behind a hosted board's sign-up
//!
//! THE PROGRAM (the deployment notes §4 step 1; the provisioning record,
//! `_designs/hardening/2026-10-12-provisioning-service.md` in the design
//! repository): TWO PAGES served over HTTP on loopback behind the proxy —
//! the sign-up page, where a person leaves an email address, and the claim
//! form, where an invited person names a board and pastes the record their
//! own device printed; the record judged in process before any docker run;
//! FIVE STEPS for an admitted post, one post at a time, through the host's
//! `docker` command — the fresh volume, the claim run bound to its
//! loopback, the dark claim by the sidecar in its namespace, the serving
//! run, the `/health` pair; ONE SNIPPET per board in the proxy's directory
//! and the proxy reloaded; the live page at the post's status address; and
//! ONE MAIL once the board is live. `skep-provision serve` is the service;
//! `skep-provision invite` is the owner's hand, minting one invite and
//! printing its claim address; `skep-provision --version` the version line.
//!
//! WHAT IT HOLDS. NO KEY: the record is the person's PUBLIC line, parsed by
//! `skep-identity`, in which no field type can carry a private key (I1,
//! AUTH-2.89); the sidecar it runs signs nothing; there is no store and no
//! `--dir`. What it does hold: THE DOCKER SOCKET's REACH, through the
//! host's `docker` command and the `docker` group — the VM's root, the
//! record §4's one power; THE SIGN-UP ADDRESSES, the one personal datum it
//! keeps; and THE INVITE FILE — the two files in its state directory,
//! owner-only, which it refuses to start on where other users can read it.
//!
//! WHAT IT NEVER LOGS (the record §4): the record's bytes, a requester's
//! address, an invite code, a status token. Its log — stderr, one line per
//! step — names the board, the step, each call's exit code and the
//! sidecar's stderr whole; its one stdout line is the serving line, and
//! `invite`'s is the claim address.
//!
//! THE ANSWERS it writes carry statuses `skep-http`'s reason table holds,
//! and no other — 200 for every page and every refusal shown on a page, 404
//! for a route or a status token it does not hold, 400 for a body the form
//! decoder refuses, 413 for a body past the cap — so the subset is called
//! as it stands.
//!
//! THE STOP is SIGTERM's default disposition: the process ends at once.
//! Crash-stop, as the daemon's: every file it keeps is replaced whole by a
//! rename, so no stop tears one; a provisioning cut mid-step leaves what it
//! made standing, which the truth about names then reads as TAKEN until the
//! operator clears it (the record §5.2's named gap); the queue, the status
//! tokens and an unsent mail are memory and end with the process. Its exit
//! codes: 0, a verb done; 2, a usage refusal; 1, a start refused — a state
//! directory other users can read, a snippet directory that cannot be read,
//! an address that cannot be bound — or an invite not minted.
//!
//! The modules are declared below in dependency order, each naming only
//! those above it; `ARCHITECTURE.md` §The provisioning service draws them.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

// The form's body decoded: `application/x-www-form-urlencoded`, strictly.
mod urlform;
// The name's grammar, the record's trim and parse, the preview-kind test,
// the anchorless fact.
mod record;
// The Docker runner: the trait, the argv of every call, the host's
// `docker`; the scripted fake under `test-hooks`.
mod docker;
// The sidecar's DATA lines and exit code.
mod sidecar;
// The `/health` pair and the bounded wait.
mod health;
// The proxy's snippet: its text, its write by rename, its removal, the
// reload.
mod caddy;
// The truth about names, the status token, the status map.
mod names;
// The address rule, the state directory, its writer, the sign-up file.
mod signups;
// The invite file: mint, look up, spend.
mod invites;
// The strings table, the pages, the routes over `skep-http`.
mod pages;
// The live reply, for the page and the mail alike.
mod reply;
// The mail: the trait, the mailer, the sender's thread; the fake under
// `test-hooks`.
mod sender;
// The worker, the one lock, the queue, the steps, the cleanup.
mod flow;
// The verbs and the flags, every default a named constant.
mod args;

use std::io::{self, Write};
use std::net::TcpListener;
use std::process::exit;
use std::sync::Arc;
use std::thread;

use args::{Command, Mailer};
use docker::{Docker, Host};
use flow::{Config, Mail, Service};
use pages::Site;
use sender::{Log, Outbox, Sender, Sleep};
use signups::StateDir;

fn main() {
    let code = match args::parse(std::env::args_os().skip(1)) {
        Ok(Command::Version) => say_out(&args::version_line()),
        Ok(Command::Help) => say_out(&args::usage()),
        Ok(Command::Serve(cfg)) => serve(*cfg),
        Ok(Command::Invite(cfg)) => invite(cfg),
        Err(refused) => {
            say_err(&format!("skep-provision: {refused}\n\n{}", args::usage()));
            2
        }
    };
    exit(code);
}

/// A line on stdout — DATA — whose write failing is the run's failure:
/// exit 1, never a panic.
fn say_out(line: &str) -> i32 {
    let mut out = io::stdout().lock();
    match writeln!(out, "{line}").and_then(|()| out.flush()) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

/// A line on stderr, its write's result discarded: a lost reader costs the
/// line and never the service or its exit code.
fn say_err(line: &str) {
    let _ = writeln!(io::stderr(), "{line}");
}

/// The log every thread writes through: `skep-provision: <line>` on stderr.
fn log() -> Log {
    Arc::new(|line: &str| say_err(&format!("skep-provision: {line}")))
}

/// `serve`: the state directory's door, the snippets read, the runner and
/// the mail chosen, the worker and the sender started, the address bound,
/// the serving line — and a thread per connection until the process ends.
fn serve(cfg: args::Serve) -> i32 {
    let log = log();
    let state = match StateDir::open(&cfg.state_dir) {
        Ok(state) => state,
        Err(refused) => {
            say_err(&format!("skep-provision: {refused}"));
            return 1;
        }
    };
    let docker: Box<dyn Docker> = match runner(&cfg) {
        Ok(docker) => docker,
        Err(e) => {
            say_err(&format!("skep-provision: the docker fake: {e}"));
            return 1;
        }
    };
    let sleep: Sleep = Arc::new(thread::sleep);
    let mail = match &cfg.mail {
        None => None,
        Some(m) => match Outbox::spawn(sender_of(&m.mailer), Arc::clone(&log), Arc::clone(&sleep)) {
            Ok(outbox) => Some(Mail { outbox, from: m.from.clone() }),
            Err(e) => {
                say_err(&format!("skep-provision: the sender's thread could not start: {e}"));
                return 1;
            }
        },
    };
    let mailing = if mail.is_some() { "mail on" } else { "mail OFF (no --mailer and --from): no follow-up mail is sent" };
    let config = Config { boards_dir: cfg.boards_dir.clone(), suffix: cfg.settings.suffix.clone(), reply_to: cfg.reply_to.clone() };
    let service = match Service::new(config, state, docker, mail, Arc::clone(&log), sleep) {
        Ok(service) => service,
        Err(e) => {
            say_err(&format!("skep-provision: the boards directory {} could not be read: {e}", cfg.boards_dir.display()));
            return 1;
        }
    };
    let listener = match TcpListener::bind(cfg.listen) {
        Ok(listener) => listener,
        Err(e) => {
            say_err(&format!("skep-provision: bind {}: {e}", cfg.listen));
            return 1;
        }
    };
    // THE BOUND ADDRESS, read back off the listener: the port under
    // `--listen <addr>:0`, never what was asked for.
    let bound = listener.local_addr().map_or_else(|_| cfg.listen.to_string(), |a| a.to_string());
    say_out(&format!(
        "skep-provision: serving http://{bound}/ state-dir {} boards-dir {} suffix {} live {} {mailing}",
        cfg.state_dir.display(),
        cfg.boards_dir.display(),
        cfg.settings.suffix,
        service.live()
    ));
    let site = Site { suffix: cfg.settings.suffix.clone(), reply_to: cfg.reply_to.clone() };
    // THE SERVE: the worker, and a thread per connection beside it; the
    // scope never closes — SIGTERM ends the process.
    thread::scope(|s| {
        s.spawn(|| service.work());
        for conn in listener.incoming() {
            let Ok(stream) = conn else { continue };
            let (site, service) = (&site, &service);
            s.spawn(move || pages::connection(stream, site, service));
        }
    });
    0
}

/// The runner: the host's `docker`, or under `test-hooks` the scripted fake
/// `--docker-fake` names.
fn runner(cfg: &args::Serve) -> io::Result<Box<dyn Docker>> {
    #[cfg(feature = "test-hooks")]
    if let Some(script) = &cfg.docker_fake {
        return Ok(Box::new(docker::fake::FakeDocker::open(script)?));
    }
    Ok(Box::new(Host::new(cfg.settings.clone())))
}

/// The sender: the host's relay client, or under `test-hooks` the fake
/// `--mailer-fake` names.
fn sender_of(mailer: &Mailer) -> Box<dyn Sender> {
    match mailer {
        Mailer::Program(program) => Box::new(sender::Mailer::new(program.clone())),
        #[cfg(feature = "test-hooks")]
        Mailer::Fake(log) => Box::new(sender::fake::FakeSender::new(log.clone(), Vec::new())),
    }
}

/// `invite`: the state directory's door, one invite minted, its claim
/// address the one DATA line.
fn invite(cfg: args::Invite) -> i32 {
    let state = match StateDir::open(&cfg.state_dir) {
        Ok(state) => state,
        Err(refused) => {
            say_err(&format!("skep-provision: {refused}"));
            return 1;
        }
    };
    match invites::mint(&state, &cfg.address, cfg.code.as_deref()) {
        Ok(code) => match say_out(&invites::claim_address(&cfg.suffix, &code)) {
            0 => 0,
            _ => {
                say_err("skep-provision: the invite is minted, and its claim address could not be written on stdout");
                1
            }
        },
        Err(refused) => {
            say_err(&format!("skep-provision: invite: {refused}"));
            1
        }
    }
}

#[cfg(test)]
mod scratch {
    //! A scratch directory for the unit suites: made under the system temp
    //! directory, named by OS entropy, removed when dropped.

    use std::path::{Path, PathBuf};

    /// One scratch directory.
    pub struct Scratch(PathBuf);

    impl Scratch {
        /// A fresh one, `0700`.
        pub fn new() -> Scratch {
            let mut raw = [0u8; 8];
            getrandom::fill(&mut raw).expect("OS entropy");
            let name: String = raw.iter().map(|b| format!("{b:02x}")).collect();
            let path = std::env::temp_dir().join(format!("skep-provision-test-{name}"));
            let mut builder = std::fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            builder.create(&path).expect("a scratch directory");
            Scratch(path)
        }

        /// Its path.
        pub fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            #[cfg(unix)]
            {
                // A test that made a directory unwritable gives it back first.
                use std::os::unix::fs::PermissionsExt;
                if let Ok(entries) = std::fs::read_dir(&self.0) {
                    for entry in entries.flatten() {
                        let _ = std::fs::set_permissions(entry.path(), std::fs::Permissions::from_mode(0o700));
                    }
                }
            }
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}
