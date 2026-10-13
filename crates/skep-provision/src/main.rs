//! # skep-provision — the service behind a hosted board's sign-up
//!
//! THE PROGRAM (the deployment notes §4 step 1; the provisioning record,
//! `_designs/hardening/2026-10-12-provisioning-service.md` in the design
//! repository): TWO PAGES served over HTTP on loopback behind the proxy —
//! the sign-up page, where a person leaves an email address, and the claim
//! form, where an invited person names a board and pastes the record their
//! own device printed; the record judged in process before any docker run;
//! FIVE STEPS for an admitted post — different names at once on a pool of
//! workers, one post per name — through the host's `docker` command: the
//! fresh volume, labelled as this service's, the claim run bound to its
//! loopback, the dark claim by the sidecar in its namespace, the serving
//! run, the `/health` pair; ONE SNIPPET per board in the proxy's directory
//! and the proxy reloaded, the two serial across every name; the live page
//! at the post's status URL; and ONE MAIL once the board is live. At
//! its start, before it listens, A SWEEP removes every board a stop left
//! half-made — a labelled volume with no snippet. `skep-provision serve` is
//! the service; `skep-provision invite` is the owner's hand, minting one
//! invite and printing its invite link; `skep-provision --version` the
//! version line.
//!
//! WHAT IT HOLDS. NO KEY: the record is the person's PUBLIC line, parsed by
//! `skep-identity`, in which no field type can carry a private key (I1,
//! AUTH-2.89); the sidecar it runs signs nothing; there is no store and no
//! `--dir`. What it does hold: THE DOCKER SOCKET's REACH, through the
//! host's `docker` command and the `docker` group — the VM's root, the
//! provisioning record §4's one power; THE SIGN-UP ADDRESSES, the one
//! personal datum it keeps; and THE INVITE FILE — the two files in its
//! state directory, owner-only, which it refuses to start on where other
//! users can read it.
//!
//! WHAT IT NEVER LOGS (the provisioning record §4): the record's bytes, a
//! requester's address, an invite code, a status token. Its log — stderr,
//! one line per step — names the board, the step, each call's exit code and
//! the sidecar's stderr whole; its one stdout line is the serving line, and
//! `invite`'s is the invite link.
//!
//! THE ANSWERS it writes carry statuses `skep-http`'s reason table holds,
//! and no other — 200 for every page and every refusal shown on a page, 404
//! for a request no page takes or a status token it does not hold, 400 for
//! a body the form decoder refuses, 413 for a body past the cap — so the
//! subset is called as it stands.
//!
//! THE STOP is SIGTERM's default disposition: the process ends at once.
//! Crash-stop, as the daemon's: every file it keeps is replaced whole by a
//! rename, so no stop tears one; a provisioning cut mid-step leaves what it
//! made standing, which the truth about names reads as TAKEN until the next
//! start's sweep removes it — a volume under the label with no snippet is
//! half-made, and goes with whatever run stands under its name — or, where
//! a removal fails, until the operator clears it (the provisioning record
//! §5.2's named gap); the queue, the status tokens and an unsent mail are
//! memory and end with the process. Its exit codes: 0, a verb done; 2, a
//! usage refusal; 1, a start refused — a state directory other users can
//! read, a snippet directory that cannot be read, an address that cannot be
//! bound — or an invite not minted.
//!
//! The modules are declared below in dependency order, each naming only
//! those above it — `tests/it/tidy.rs` checks it — and `ARCHITECTURE.md`
//! §The provisioning service draws them.

#![forbid(unsafe_code)]
// A binary exports nothing, so this holds the crate's own doc alone; every
// `pub` item and field in a module is held to its doc by `tests/it/tidy.rs`.
#![deny(missing_docs)]

// Test scaffolding for the unit suites alone: a scratch directory, removed
// when dropped.
#[cfg(test)]
mod scratch;
// The form's body decoded: `application/x-www-form-urlencoded`, strictly.
mod urlform;
// A kept file changed durably: replaced whole by rename at its owner's mode,
// or removed — the directory synced either way.
mod whole;
// A child process run to its end: its input fed on a thread of its own, its
// exit and its two streams apart.
mod process;
// A board's name: one lowercase label, and the host and the public origin
// it stands at.
mod name;
// The record's trim and parse, the preview-kind test, the anchorless fact.
mod record;
// The Docker runner: the trait, the argv of every call, the host's
// `docker`; the scripted fake under `test-hooks`.
mod docker;
// The sidecar's DATA lines and exit code.
mod sidecar;
// The `/health` pair and the bounded wait.
mod health;
// The proxy's snippet: its text, its write by rename, its removal, whether
// it stands, the reload.
mod caddy;
// The truth about names, the status token, the status map.
mod names;
// The state directory: its door, its one writer, and what its two files'
// lines carry — the address rule and its value, the date.
mod statedir;
// The sign-up file.
mod signups;
// The invite file: mint, look up, spend; the code's alphabet and its value.
mod invites;
// Every sentence a person reads: one table, each row naming its id.
mod strings;
// The pages' HTML and the requests they answer over `skep-http`, the desk
// they ask, and the two URLs the service hands out.
mod pages;
// The mail: the trait, the mailer, the sender's thread; the fake under
// `test-hooks`.
mod sender;
// The live reply, for the page and the mail alike.
mod reply;
// The workers, the book of what is in flight, the name as the unit of
// exclusion, the steps, the cleanup, the sweep at start.
mod flow;
// The verbs and the flags, every default a named constant.
mod args;

use std::io::{self, Write};
use std::net::TcpListener;
use std::process::exit;
use std::sync::Arc;
use std::thread;

use args::{Command, Mailer};
use docker::{Docker, HostDocker};
use flow::{Config, Service};
use pages::Site;
use sender::{Log, Outbox, Sender, Sleep};
use statedir::StateDir;

fn main() {
    let code = match args::parse(std::env::args_os().skip(1)) {
        Ok(Command::Version) => say_out(&args::version_line()).map_or(1, |()| 0),
        Ok(Command::Help) => say_out(&args::usage()).map_or(1, |()| 0),
        Ok(Command::Serve(cfg)) => serve(*cfg),
        Ok(Command::Invite(cfg)) => invite(cfg),
        Err(refused) => {
            say_err(&format!("skep-provision: {refused}\n\n{}", args::usage()));
            2
        }
    };
    exit(code);
}

/// A line on stdout — DATA — written and flushed, never a panic: a verb
/// that ends after its one line answers exit 1 where this fails; `serve`
/// serves on past its serving line.
fn say_out(line: &str) -> io::Result<()> {
    let mut out = io::stdout().lock();
    writeln!(out, "{line}")?;
    out.flush()
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
/// the mail chosen, the sender started, THE SWEEP of what a stop left
/// half-made, then the address bound, the serving line, the workers — and
/// a thread per connection until the process ends.
fn serve(cfg: args::ServeArgs) -> i32 {
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
        Some(m) => match Outbox::spawn(sender_of(&m.mailer), m.from.clone(), cfg.reply_to.clone(), Arc::clone(&log), Arc::clone(&sleep)) {
            Ok(outbox) => Some(outbox),
            Err(e) => {
                say_err(&format!("skep-provision: the sender's thread could not start: {e}"));
                return 1;
            }
        },
    };
    let mailing = if mail.is_some() { "mail on" } else { "mail OFF (no --mailer and --from): no follow-up mail is sent" };
    let config = Config { boards_dir: cfg.boards_dir.clone(), suffix: cfg.settings.suffix.clone() };
    let service = match Service::new(config, state, docker, mail, Arc::clone(&log), sleep) {
        Ok(service) => service,
        Err(e) => {
            say_err(&format!("skep-provision: the boards directory {} could not be read: {e}", cfg.boards_dir.display()));
            return 1;
        }
    };
    // THE SWEEP, before the address is bound: no post is judged while a
    // half-made board still stands under its name.
    let swept = service.sweep();
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
    // The serving line: a stdout that cannot take it costs the line, never
    // the service — the address is bound and the run serves on.
    let _ = say_out(&format!(
        "skep-provision: serving http://{bound}/ state-dir {} boards-dir {} suffix {} live {} swept {swept} workers {} {mailing}",
        cfg.state_dir.display(),
        cfg.boards_dir.display(),
        cfg.settings.suffix,
        service.live(),
        cfg.workers
    ));
    let site = Site { suffix: cfg.settings.suffix.clone(), owner_address: cfg.reply_to.as_str().to_owned() };
    // THE SERVE: the pool of workers, and a thread per connection beside
    // them; the scope never closes — SIGTERM ends the process.
    thread::scope(|s| {
        for _ in 0..cfg.workers.get() {
            s.spawn(|| service.work());
        }
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
fn runner(cfg: &args::ServeArgs) -> io::Result<Box<dyn Docker>> {
    #[cfg(feature = "test-hooks")]
    if let Some(script) = &cfg.docker_fake {
        return Ok(Box::new(docker::fake::FakeDocker::open(script)?));
    }
    Ok(Box::new(HostDocker::new(cfg.settings.clone())))
}

/// The sender: the host's relay client, or under `test-hooks` the fake
/// `--mailer-fake` names.
fn sender_of(mailer: &Mailer) -> Box<dyn Sender> {
    match mailer {
        Mailer::Program(program) => Box::new(sender::RelaySender::new(program.clone())),
        #[cfg(feature = "test-hooks")]
        Mailer::Fake(log) => Box::new(sender::fake::FakeSender::new(log.clone(), Vec::new())),
    }
}

/// `invite`: the state directory's door, one invite minted, its invite
/// link the one DATA line.
fn invite(cfg: args::InviteArgs) -> i32 {
    let state = match StateDir::open(&cfg.state_dir) {
        Ok(state) => state,
        Err(refused) => {
            say_err(&format!("skep-provision: {refused}"));
            return 1;
        }
    };
    match invites::mint(&state, &cfg.address, cfg.code) {
        Ok(code) => match say_out(&pages::invite_link(&cfg.suffix, &code)) {
            Ok(()) => 0,
            Err(_) => {
                say_err("skep-provision: the invite is minted, and its invite link could not be written on stdout");
                1
            }
        },
        Err(refused) => {
            say_err(&format!("skep-provision: invite: {refused}"));
            1
        }
    }
}
