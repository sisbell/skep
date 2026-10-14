//! # skep-provision — the service behind a hosted board's sign-up
//!
//! THE PROGRAM (the deployment notes §4 step 1; the provisioning record,
//! `_designs/hardening/2026-10-12-provisioning-service.md` in the design
//! repository): TWO PAGES served over HTTP on loopback behind the proxy —
//! the sign-up page, where a person leaves an email address, and the claim
//! form, where an invited person names a board and pastes the record their
//! own device printed; the record judged in process before any docker run;
//! THE NOTES' STEPS 3 TO 5 for an admitted post — different names at once
//! on a pool of workers, one post per name — through the host's `docker`
//! command: step 3, the claim run, bound to its loopback, on a fresh volume
//! labelled as this service's; step 4, the dark claim by the sidecar in its
//! namespace; step 5, the serving run, the `/health` pair, and ONE SNIPPET
//! per board in the proxy's directory with the proxy reloaded, the snippet
//! and the reload serial across every name; the live page at the post's
//! status URL; and ONE MAIL once the board is live. At its start, its address
//! bound and before it serves, A SWEEP removes every board a stop left
//! half-made — a labelled volume with no snippet; the snippet directory is
//! so the list of boards it spares. One `serve` per Docker host: the label
//! and the names are the host's, and a second `serve` over the same state
//! directory or on the same port is refused before its sweep. Its start
//! says the version it runs and the settings every board is made with,
//! above the serving line. `skep-provision serve` is the service;
//! `skep-provision invite` is the owner's hand, minting one invite and
//! printing its invite link; `skep-provision --version` the version line.
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
//! WHAT IT NEVER LOGS (the provisioning record §4): the record whole or a key
//! of it, a person's address, an invite code, a status token. Its log —
//! stderr, one line per step — names the board, the step, each call's exit
//! code and the sidecar's stderr whole — its TALK, which names each entry of
//! the record by its fingerprint and its label, the person's own words,
//! already on the board with the record; its one stdout line is the serving
//! line, and `invite`'s is the invite link. A panic's line, the binary's
//! hook's, carries its payload only where it is a literal the code wrote, so
//! nothing a request formatted rides it; and a line a stranger can drive — a
//! refusal no invite bounds, a failure met at every request — is said at a
//! rate (`rates`), never once a request.
//!
//! THE ANSWERS it writes carry statuses `skep-http`'s reason table holds,
//! and no other — 200 for every page and every refusal shown on a page, 404
//! for a request no page takes or a status token it does not hold, 400 for
//! a request the HTTP subset refuses — a head past 16 KiB or malformed, one
//! cut off early, one that spent its minute — or a body the form decoder
//! refuses, 413 for a body past the cap — so the subset is called as it
//! stands.
//!
//! THE STOP is SIGTERM's default disposition: the process ends at once.
//! Crash-stop, as the daemon's: every file it keeps is replaced whole by a
//! rename, so no stop tears one. A provisioning cut mid-step leaves what it
//! made standing. Cut before its snippet's write, that is at most a volume
//! under the label with no snippet — half-made — and a run, which the truth
//! about names reads as TAKEN until the next start's sweep removes them, or,
//! where something still stands after the removals, which the log names,
//! until the operator clears it (the provisioning record §5.2's named gap).
//! Cut from its snippet's write until its spend is written, it is a board
//! whose snippet stands — routed, or routed at the proxy's next reload —
//! which the next start counts live and its sweep leaves, its invite still
//! issued. The queue, the status tokens, an unsent mail and the codes its
//! posts hold are memory and end with the process — among those codes two the
//! file still holds issued under a live board: one whose spend could not be
//! written, and one whose post the stop cut off between its snippet's write
//! and its spend. The next start admits a post on either unless the
//! operator has marked it spent; the log names the board — before the stop,
//! `the invite could not be marked spent`, or `snippet: written` with no
//! `the invite is spent` after it; at the next start, `routed at start with
//! no invite line spent under it` — and never the code. Its exit codes: 0, an
//! `invite` minted and its link printed, or the version line or the usage
//! text printed; 2, a usage refusal; 1, a start refused — a state directory
//! other users can read, one another user owns, or one that cannot be made
//! or is no directory, another `serve` holding it, a `--mailer` that cannot
//! be run, a snippet directory that cannot be read or written, an address
//! that cannot be bound, a thread the OS will not give — or an `invite` that
//! printed no invite link, or a version line or usage text that could not be
//! written.
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
// A bounded wait: this many tries, this far apart, a pause before each try
// but the first.
mod wait;
// The rates a line is said at: a condition that recurs at its edges, an
// event a stranger drives once a stretch, each with its count.
mod rates;
// A domain, as `--suffix` takes one: the grammar a suffix is held to, its
// alphabet in words, and the one value a suffix is taken in as.
mod domain;
// A board's name: one lowercase label, and the board's host and public
// origin under the suffix.
mod name;
// The record's trim and parse, the preview-kind test, the hosted genesis's
// decode and cap, the anchorless fact.
mod record;
// A mail address by the rule — one `@`, ASCII alone, none of the specials —
// its words for a refusal, and the one value an address is taken in as.
mod mail_address;
// An invite code: 1 to 128 of the URL's unreserved characters, and the one
// value a code is taken in as.
mod invite_code;
// The Docker runner: the trait, the argv of every call, the host's
// `docker`; the scripted fake under `test-hooks`.
mod docker;
// The sidecar's DATA lines and exit code.
mod sidecar;
// The `/health` pair and its wait.
mod health;
// The proxy's snippet: its text, its write by rename, its removal, whether
// it stands, the reload, and the routed names the status map is rebuilt
// from.
mod caddy;
// The truth about names, the labelled volumes sorted for the sweep, the
// status token.
mod names;
// The state directory: its door, its one writer, and the date its two
// files' lines carry.
mod statedir;
// The sign-up file.
mod signups;
// The invite file: mint, look up, spend, under its lock file.
mod invites;
// Every sentence a person reads: one table, each row naming its id.
mod strings;
// The pages' HTML and the requests they answer over `skep-http`, the desk
// they ask, the two URLs the service hands out, and the accept pair and the
// pool pair the connection threads share.
mod pages;
// The mail: the trait, the mailer, the sender's thread, and the log and the
// sleep every thread is handed, the board a thread works on and the panic
// hook's line; the fake under `test-hooks`.
mod sender;
// The live reply, for the page and the mail alike.
mod reply;
// The desk the pages ask — a sign-up kept, a post admitted, a status read —
// the workers, the book of what is in flight and its status map, the name as
// the unit of exclusion, the steps, the cleanup, the sweep at start.
mod flow;
// The verbs and the flags, every default a named constant.
mod args;

use std::fs::TryLockError;
use std::io::{self, Write};
use std::net::TcpListener;
use std::process::exit;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use args::{Command, MailArgs, Mailer};
use docker::{Docker, HostDocker};
use flow::{Config, Service};
use pages::{Accepts, Serving, Site};
use sender::{Log, Outbox, Sender, Sleep};
use statedir::StateDir;

/// THE PAUSE after an `accept` that fails, before it is asked again —
/// `skepd`'s pause of this name, for its reason: EMFILE and its kin last
/// until a descriptor is freed, and a connection thread that asked again
/// at once would spin a core for as long; ten milliseconds costs nothing
/// at the wall and holds a queued connection little once the wall clears.
const ACCEPT_RETRY_PAUSE: Duration = Duration::from_millis(10);

/// THE SERVE's LOCK FILE in the state directory: held by a running `serve`
/// for its life, so a second `serve` over the same state directory — the
/// binary started by hand beside the unit — is refused at its start, before
/// its sweep could take this one's boards in flight for half-made. `invite`
/// never takes it: a mint beside a running service is safe.
const SERVE_LOCK: &str = "serve.lock";

fn main() {
    install_the_panic_hook();
    let exit_code = match args::parse(std::env::args_os().skip(1)) {
        Ok(Command::Version) => say_out(&args::version_line()).map_or(1, |()| 0),
        Ok(Command::Help) => say_out(&args::usage()).map_or(1, |()| 0),
        Ok(Command::Serve(flags)) => serve(*flags),
        Ok(Command::Invite(flags)) => invite(flags),
        Err(refused) => {
            say_err(&format!("skep-provision: {refused}\n\n{}", args::usage()));
            2
        }
    };
    exit(exit_code);
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

/// THE PANIC HOOK, installed first, before the command line is read, so no
/// thread of this process's panics outside it: one line on stderr, prefixed
/// as every line of the log is, for any thread's panic, before any catch —
/// the board the thread works on where it works on one, the thread, the
/// location, and the payload only where it is a literal the code wrote
/// (`sender::panic_line`), so Rust's own unprefixed text, which carries
/// whatever its site formatted, never reaches the stream.
fn install_the_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        let thread = thread::current();
        let payload = info.payload().downcast_ref::<&'static str>().copied();
        say_err(&format!("skep-provision: {}", sender::panic_line(sender::board_of_this_thread().as_deref(), thread.name(), info.location(), payload)));
    }));
}

/// `serve`: the version said, the state directory's door and its serve lock,
/// the runner and the mail chosen, the sender started, the snippets read and
/// the snippet directory's write tried, the settings said, the address
/// bound, THE SWEEP of what a stop left half-made, the serving line, and the
/// two pools — the workers and the connection threads — until the process
/// ends. Every start refused is one line on stderr naming its cause, exit 1.
fn serve(flags: args::ServeArgs) -> i32 {
    let log = log();
    // THE VERSION, first: a start refused has above its refusal the line
    // that names which binary refused it, and a restart after an upgrade
    // names which binary now runs.
    log(&format!("version {}", args::build()));
    let state_dir = match StateDir::open(&flags.state_dir) {
        Ok(state_dir) => state_dir,
        Err(refused) => {
            say_err(&format!("skep-provision: {refused}"));
            return 1;
        }
    };
    // THE SERVE LOCK, held for the process's life: a second `serve` over this
    // state directory is refused here, before its sweep could take this
    // one's boards in flight for half-made.
    let serve_lock = match state_dir.open_lock_file(SERVE_LOCK) {
        Ok(file) => file,
        Err(e) => {
            say_err(&format!("skep-provision: {}: {e}", state_dir.file(SERVE_LOCK).display()));
            return 1;
        }
    };
    match serve_lock.try_lock() {
        Ok(()) => {}
        Err(TryLockError::WouldBlock) => {
            say_err(&format!("skep-provision: another serve holds {}: one service per Docker host (RUNBOOK §10 step 5)", state_dir.file(SERVE_LOCK).display()));
            return 1;
        }
        Err(TryLockError::Error(e)) => {
            say_err(&format!("skep-provision: {}: {e}", state_dir.file(SERVE_LOCK).display()));
            return 1;
        }
    }
    let docker: Box<dyn Docker> = match runner_of(&flags) {
        Ok(docker) => docker,
        Err(e) => {
            say_err(&format!("skep-provision: the docker fake: {e}"));
            return 1;
        }
    };
    // THE MAILER, asked at start whether it can run: one not installed is a
    // start refused, never every board's mail given up an hour after it.
    if let Some(MailArgs { mailer: Mailer::Program(program), .. }) = &flags.mail {
        if let Err(why) = sender::runnable(program) {
            say_err(&format!("skep-provision: --mailer {}: {why}; install the relay client, or drop --mailer and --from to run without mail", program.display()));
            return 1;
        }
    }
    let sleep: Sleep = Arc::new(thread::sleep);
    let outbox = match &flags.mail {
        None => None,
        Some(m) => match Outbox::spawn(sender_of(&m.mailer), m.from.clone(), flags.reply_to.clone(), Arc::clone(&log), Arc::clone(&sleep)) {
            Ok(outbox) => Some(outbox),
            Err(e) => {
                say_err(&format!("skep-provision: the sender's thread could not start: {e}"));
                return 1;
            }
        },
    };
    let mailing = if outbox.is_some() { "mail on" } else { "mail OFF (no --mailer and --from): no follow-up mail is sent" };
    let config = Config { boards_dir: flags.boards_dir.clone(), suffix: flags.settings.suffix.clone() };
    let mut service = match Service::new(config, state_dir.clone(), docker, outbox, Arc::clone(&log), sleep) {
        Ok(service) => service,
        Err(e) => {
            say_err(&format!("skep-provision: the snippet directory {} could not be read: {e}", flags.boards_dir.display()));
            return 1;
        }
    };
    // THE SNIPPET DIRECTORY's WRITE, tried: one the service's user cannot
    // write is a start refused, never every board's failure after its claim.
    if let Err(e) = caddy::probe(&flags.boards_dir) {
        say_err(&format!("skep-provision: the snippet directory {} cannot be written: {e}; the service's user writes it, on a filesystem with room (RUNBOOK §10 step 3)", flags.boards_dir.display()));
        return 1;
    }
    // THE SETTINGS every board is made with, and the sign-up file's fill
    // against its cap: what the serving line leaves out, said once.
    log(&flags.settings_said());
    match signups::held_bytes(&state_dir) {
        Ok(bytes) => log(&format!("the sign-up file holds {bytes} of its {} bytes", signups::MAX_SIGNUPS_BYTES)),
        Err(e) => log(&format!("the sign-up file could not be read: {e} — {}; a sign-up is refused until it can be", state_dir.file(signups::SIGNUPS).display())),
    }
    // THE BIND, BEFORE THE SWEEP, as skepd binds first: a port another
    // process holds — a second service by the same flags — is refused here,
    // before the sweep could take that service's boards in flight for
    // half-made; the port is held through the sweep, a connect meanwhile
    // waiting in the listener's queue.
    let listener = match TcpListener::bind(flags.listen) {
        Ok(listener) => listener,
        Err(e) => {
            let held = if e.kind() == io::ErrorKind::AddrInUse { " — another process holds it: a second skep-provision? One service per Docker host (RUNBOOK §10 step 5)" } else { "" };
            say_err(&format!("skep-provision: bind {}: {e}{held}", flags.listen));
            return 1;
        }
    };
    // THE SWEEP, before any thread holds the service: no post is judged
    // while a half-made board still stands under its name, and none is in
    // flight while the sweep runs.
    let swept = service.sweep();
    // THE BOUND ADDRESS, read back off the listener: the port under
    // `--listen <addr>:0`, never what was asked for.
    let bound = listener.local_addr().map_or_else(|_| flags.listen.to_string(), |a| a.to_string());
    // The serving line: a stdout that cannot take it costs the line, never
    // the service — the address is bound and the service serves on.
    let _ = say_out(&format!(
        "skep-provision: serving http://{bound}/ state-dir {} boards-dir {} suffix {} live {} swept {swept} workers {} connections {} {mailing}",
        flags.state_dir.display(),
        flags.boards_dir.display(),
        flags.settings.suffix,
        service.routed_at_start_count(),
        flags.workers,
        flags.connections
    ));
    let site = Site { suffix: flags.settings.suffix.clone(), owner_address: flags.reply_to.as_str().to_owned() };
    let (accepts, serving) = (Accepts::default(), Serving::new(flags.connections.get()));
    // THE SERVE: the pool of workers and the pool of connection threads,
    // each of the latter taking the next connection off the listener — one
    // past them waits in the listener's queue — both pools made here, and
    // no thread made per connection. The scope never closes: SIGTERM ends
    // the process, and the serve lock with it.
    thread::scope(|s| {
        for _ in 0..flags.workers.get() {
            made_or_exit(thread::Builder::new().name("worker".into()).spawn_scoped(s, || service.work()), "worker");
        }
        for _ in 0..flags.connections.get() {
            made_or_exit(thread::Builder::new().name("connection".into()).spawn_scoped(s, || serve_connections(&listener, &site, &service, &accepts, &serving, log.as_ref())), "connection");
        }
    });
    drop(serve_lock);
    0
}

/// A THREAD OF THE SERVE's POOLS, made at start: one the OS will not give
/// ends the start, exit 1 for systemd to restart — never a panic in the
/// scope, which would wait out the workers already made, and they never end.
/// Its line names what is lost and the act: nothing serves, the port is
/// released with the process, and the machine's thread limit is the
/// operator's to raise.
fn made_or_exit<T>(spawned: io::Result<T>, which: &str) {
    if let Err(e) = spawned {
        say_err(&format!("skep-provision: the OS refused a {which} thread at start: {e}; nothing serves, the port released — retry under a higher thread limit"));
        exit(1);
    }
}

/// ONE CONNECTION THREAD, for the process's life: the next connection off the
/// listener served, then the next; an `accept` that fails waits
/// [`ACCEPT_RETRY_PAUSE`] before it asks again, never a spin. Both pairs the
/// threads share are said through here, each once as its episode opens and
/// once as it closes, never a line per try: an `accept` that fails
/// ([`Accepts`]), and the pool standing full ([`Serving`]), every connection
/// counted in as it is taken and out once `pages::connection`, which a panic
/// never escapes, has served it.
fn serve_connections(listener: &TcpListener, site: &Site, service: &Service, accepts: &Accepts, serving: &Serving, log: &(dyn Fn(&str) + Send + Sync)) -> ! {
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                let now = Instant::now();
                for line in [accepts.accepted(now), serving.began(now)].into_iter().flatten() {
                    log(&line);
                }
                pages::connection(stream, site, service);
                serving.ended();
            }
            Err(e) => {
                if let Some(line) = accepts.failed(&e, Instant::now()) {
                    log(&line);
                }
                thread::sleep(ACCEPT_RETRY_PAUSE);
            }
        }
    }
}

/// The runner the flags name: the host's `docker`, or under `test-hooks`
/// the scripted fake `--docker-fake` names.
fn runner_of(flags: &args::ServeArgs) -> io::Result<Box<dyn Docker>> {
    #[cfg(feature = "test-hooks")]
    if let Some(script) = &flags.docker_fake {
        return Ok(Box::new(docker::fake::FakeDocker::open(script)?));
    }
    Ok(Box::new(HostDocker::new(flags.settings.clone())))
}

/// The sender: the host's relay client, or under `test-hooks` the fake
/// `--mailer-fake` names.
fn sender_of(mailer: &Mailer) -> Box<dyn Sender> {
    match mailer {
        Mailer::Program(program) => Box::new(sender::RelaySender::new(program.clone())),
        #[cfg(feature = "test-hooks")]
        Mailer::Fake(mail_log) => Box::new(sender::fake::FakeSender::new(mail_log.clone(), Vec::new())),
    }
}

/// `invite`: the state directory's door, one invite minted, its invite
/// link the one DATA line.
fn invite(flags: args::InviteArgs) -> i32 {
    let state_dir = match StateDir::open(&flags.state_dir) {
        Ok(state_dir) => state_dir,
        Err(refused) => {
            say_err(&format!("skep-provision: {refused}"));
            return 1;
        }
    };
    match invites::mint(&state_dir, &flags.address, flags.code) {
        Ok(code) => match say_out(&pages::invite_link(&flags.suffix, &code)) {
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
