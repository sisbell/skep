//! THE FLOW (the deployment notes §4, steps 3 to 5; the provisioning record
//! §2 and §5.2): the [`Service`] the pages' desk is — A POOL OF WORKERS,
//! THE NAME THE UNIT OF EXCLUSION.
//!
//! THE POST ([`Service`]'s `Desk::claim`): the invite looked up — a code the
//! file holds issued; the name's grammar; the record admitted (D-5, D-6) —
//! each in process, before any docker call; then WHAT IS IN FLIGHT, under
//! the book's short lock — the queue's depth ([`QUEUE_DEPTH`]; past it D-8,
//! "try again later"), the codes and the names the posts in flight hold —
//! refused with no docker call; then THE TRUTH ABOUT THE NAME
//! (`names::taken`, D-4), three reads under no lock of this service's; then
//! THE ADMISSION, under the book's lock again: what is in flight looked at
//! again — a post for this name or this code may have been admitted while
//! the reads ran — and the invite looked up again under the same hold — a
//! board gone live meanwhile may have spent it — then the status token
//! minted, the post queued, and D-7 answered with its status address. A
//! refused post leaves nothing: no docker call past the truth's reads, no
//! file, no queue entry. A POST NEVER WAITS ON A PROVISIONING: nothing it
//! takes is held across one.
//!
//! THE NAME IS THE UNIT OF EXCLUSION. A name is held from its admission to
//! its live or failed end (the status map's `holds`), and a second post for
//! a name in flight is refused (D-4) under the very hold that admits — so
//! no two posts for one name are ever in flight, and the worker that takes
//! a post owns its name alone to the end. No lock is held over a
//! provisioning: two workers make two names at once.
//!
//! THE WORKERS ([`Service::work`]), `--workers` threads, each taking the
//! next queued post and running it to its end:
//!
//! 3. the truth about the name read again — a name taken since the post is
//!    not this post's (D-8); `volume_create`, the volume labelled as this
//!    service's; `run_claim`, the public origin configured (AUTH-4.57 (a),
//!    (b), (f));
//! 4. `sidecar_claim`, the record on its stdin, RETRIED on exit 4 while the
//!    claim run's daemon is not yet listening ([`SIDECAR_WAIT`]); its DATA
//!    read (`sidecar`): the six lines are the claim, `claimed by …` on the
//!    volume this flow just made is residue — a failure — and any other
//!    exit or shape a failure, its stderr whole in the log; then `rm_force`
//!    the claim run;
//! 5. `run_serving`; the `/health` wait for the PAIR (`health`) — the
//!    first-start guard beside the proxy's own check (AUTH-4.57 (d)); then
//!    THE SERIAL PAIR under the one `caddy` lock, across every name: the
//!    snippet written (`caddy`, AUTH-4.57 (c)) and `caddy_reload` — so no
//!    reload lands between another name's snippet and its own;
//!
//! then THE STATUS LIVE, then THE INVITE SPENT under the invite file's own
//! lock and its code let go of, in that order, then THE MAIL handed to the
//! sender's own thread, after the page and never ahead of it, so a mail
//! outage holds up no next post.
//!
//! THE CLEANUP (the record §5.2's decision table, D-8 made literally true):
//! on a failed step, what the flow made is undone in the reverse of the
//! order it was made — the snippet removed and Caddy reloaded where the
//! snippet was written, the two under the `caddy` lock as the write was;
//! `rm_force` where a run stands; `volume_rm` where the volume stands — the
//! status FAILED (D-8) and the invite NOT spent, so the person may post
//! again. By the table: `volume_create` failed — nothing; `run_claim`
//! failed — the volume; the dark claim failed (exit 4 past the bound, 3, 1,
//! 2, or `claimed by`) — the claim run and the volume; `run_serving`
//! failed, or the pair never answered, or the snippet's write failed — the
//! serving run and the volume; the reload failed — the snippet and a
//! reload, the serving run, the volume. A board whose claim landed and
//! whose route did not is removed with its volume: no route ever existed,
//! so no one wrote to it, and a re-post claims a fresh volume with the same
//! keys. THE NAMED GAP: a cleanup call that itself fails is logged and
//! leaves the name standing — the truth then refuses re-posts (D-4) until
//! the operator clears it.
//!
//! THE SWEEP AT START ([`Service::sweep`]; `serve` runs it once, before it
//! listens): a stop mid-board leaves a volume, and perhaps a run, under a
//! name with no snippet, which the truth would read as TAKEN for good — so
//! every volume under this service's label is listed, and each under a
//! name of the grammar with no snippet is removed by the table's last two
//! rows; a name whose snippet stands is left, a volume under no name of the
//! grammar is logged and left, and a listing that fails is logged and the
//! sweep skipped — the sign-up still serves.
//!
//! THE LOG, on stderr through [`Log`]: one line per step naming the name,
//! the step and each call's exit code, and the sidecar's stderr whole —
//! NEVER the record's bytes, an address, an invite code or a status token
//! (the record §4).

use std::collections::{HashSet, VecDeque};
use std::io;
use std::path::PathBuf;
use std::sync::{Condvar, Mutex, MutexGuard};
use std::time::Duration;

use crate::caddy;
use crate::docker::{Docker, Exit};
use crate::health::{self, Wait, Waited, HEALTH_WAIT};
use crate::invites;
use crate::name::Name;
use crate::names::{self, State, StatusMap};
use crate::pages::{self, Desk, Post, Refusal, Shown, SignUpRefusal};
use crate::record::{self, Record, RecordRefused};
use crate::reply;
use crate::sender::{Log, Message, Outbox, Sleep};
use crate::sidecar::{self, Answer, Failure};
use crate::signups::{SignUpRefused, SignUps};
use crate::statedir::StateDir;
use crate::strings::{fill, MAIL_SUBJECT};

/// THE QUEUE's DEPTH: four posts WAITING for a worker, the ones the workers
/// run apart (the provisioning record §5.2's figure); a fifth meets D-8,
/// "try again later".
const QUEUE_DEPTH: usize = 4;

/// THE DARK CLAIM's RETRY: thirty tries two seconds apart while the
/// sidecar answers exit 4 — the claim run's daemon not yet listening.
const SIDECAR_WAIT: Wait = Wait { tries: 30, interval: Duration::from_secs(2) };

/// What the service is configured with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// `--boards-dir`: where the snippets live.
    pub boards_dir: PathBuf,
    /// `--suffix`: the domain every board stands under.
    pub suffix: String,
    /// `--reply-to`: the owner's mailbox — D-8 names it, the mail replies to
    /// it.
    pub reply_to: String,
}

/// The follow-up mail's means: the sender's thread and the `From:`.
pub struct Mail {
    /// Where a message is handed.
    pub outbox: Outbox,
    /// `--from`.
    pub from: String,
}

/// One admitted post, waiting or running.
struct Job {
    token: String,
    name: Name,
    record: Record,
    code: String,
    address: String,
}

/// What the routes and the workers share under the book's own short lock:
/// the queue, the status map, and the invite codes a post in flight holds.
struct Book {
    queue: VecDeque<Job>,
    map: StatusMap,
    codes: HashSet<String>,
}

/// What a provisioning has made so far, for the cleanup to undo.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Made {
    volume: bool,
    run: bool,
    snippet: bool,
}

/// THE SERVICE: the desk the routes ask, and the workers' shared state.
pub struct Service {
    config: Config,
    state: StateDir,
    signups: SignUps,
    docker: Box<dyn Docker>,
    mail: Option<Mail>,
    log: Log,
    sleep: Sleep,
    /// THE SERIAL PAIR's LOCK: held across a snippet's write and the
    /// reload, and across a snippet's removal and the reload — nowhere
    /// else.
    caddy: Mutex<()>,
    /// THE BOOK's SHORT LOCK: the queue, the status map, the held codes.
    book: Mutex<Book>,
    ready: Condvar,
}

impl Service {
    /// The service over its configuration, its state directory, its runner
    /// and its mail — the status map REBUILT from the snippet directory.
    pub fn new(config: Config, state: StateDir, docker: Box<dyn Docker>, mail: Option<Mail>, log: Log, sleep: Sleep) -> io::Result<Service> {
        let map = StatusMap::rebuild(&config.boards_dir, &config.suffix)?;
        let signups = SignUps::new(&state);
        Ok(Service { config, state, signups, docker, mail, log, sleep, caddy: Mutex::new(()), book: Mutex::new(Book { queue: VecDeque::new(), map, codes: HashSet::new() }), ready: Condvar::new() })
    }

    /// The live names the map holds — at start, the rebuild's.
    pub fn live(&self) -> usize {
        self.book().map.live().len()
    }

    /// THE SWEEP AT START, run once before the service listens: every
    /// volume under this service's label listed; each under a name of the
    /// grammar with NO snippet is half-made — a stop mid-board left it — and
    /// is removed by the cleanup table's last two rows, whichever run stands
    /// under the name (`rm_force`; a failure logged and gone past, for there
    /// may be no run) then the volume (`volume_rm`; a failure logged, and
    /// the name stays taken, the operator's). A name whose snippet stands is
    /// left — live, or stopped and Docker's `--restart` to bring back — and
    /// so is a listed volume under no name of the grammar, logged. A listing
    /// that fails is logged and the sweep skipped: a listing failure must
    /// not take the sign-up down. Answers the boards removed, for the
    /// serving line.
    pub fn sweep(&self) -> usize {
        let docker = self.docker.as_ref();
        let listing = match docker.volumes() {
            Ok(exit) if exit.ok() => exit,
            Ok(exit) => {
                self.log(&format!("sweep: volumes: exit {}; the sweep is skipped", exit.said()));
                for line in String::from_utf8_lossy(&exit.stderr).lines() {
                    self.log(&format!("sweep: volumes: {line}"));
                }
                return 0;
            }
            Err(e) => {
                self.log(&format!("sweep: volumes: docker could not run: {e}; the sweep is skipped"));
                return 0;
            }
        };
        let labelled = match names::labelled(&listing.stdout, &self.config.boards_dir) {
            Ok(labelled) => labelled,
            Err(e) => {
                self.log(&format!("sweep: the snippet directory could not be read: {e}; the sweep is skipped"));
                return 0;
            }
        };
        for listed in &labelled.unnamed {
            self.log(&format!("sweep: a volume under the label is under no name of the grammar, left: {listed}"));
        }
        let mut swept = 0;
        for name in &labelled.half_made {
            self.log(&format!("{name}: half-made at start (a volume, no snippet) — removing"));
            // The table's last two rows: a run that does not stand is no
            // failure of the sweep's, and the volume is tried either way.
            self.undone(name, "sweep", "rm_force", docker.rm_force(name));
            if self.undone(name, "sweep", "volume_rm", docker.volume_rm(name)) {
                swept += 1;
                self.log(&format!("{name}: sweep: done — nothing stands under the name"));
            } else {
                self.log(&format!("{name}: sweep: INCOMPLETE — the volume stands, and the name refuses posts (D-4) until the operator clears it"));
            }
        }
        swept
    }

    /// ONE WORKER: the next post waited for and provisioned, forever — the
    /// name it took is its alone until the post ends live or failed, for no
    /// second post for a name in flight is ever admitted. `serve` runs
    /// `--workers` of these over one service.
    pub fn work(&self) -> ! {
        loop {
            let job = {
                let mut book = self.book();
                loop {
                    if let Some(job) = book.queue.pop_front() {
                        book.map.set(&job.token, State::Running, None);
                        break job;
                    }
                    book = self.ready.wait(book).unwrap_or_else(|e| e.into_inner());
                }
            };
            self.provision(job);
        }
    }

    /// The next queued post provisioned now, on this thread — `false` where
    /// none waits: one worker's one turn, as a unit suite drives it.
    #[cfg(test)]
    fn run_next(&self) -> bool {
        let job = {
            let mut book = self.book();
            let Some(job) = book.queue.pop_front() else { return false };
            book.map.set(&job.token, State::Running, None);
            job
        };
        self.provision(job);
        true
    }

    fn book(&self) -> MutexGuard<'_, Book> {
        self.book.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn caddy(&self) -> MutexGuard<'_, ()> {
        self.caddy.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn log(&self, line: &str) {
        (self.log)(line);
    }

    /// ONE POST PROVISIONED on the worker that owns its name: the steps,
    /// then live or cleaned up; the mail after.
    fn provision(&self, job: Job) {
        let name = job.name.clone();
        let mut made = Made::default();
        let live = match self.steps(&job, &mut made) {
            Ok(()) => {
                let facts = names::facts(&name, &self.config.suffix);
                let origin = facts.origin.clone();
                self.book().map.set(&job.token, State::Live, Some(facts));
                self.log(&format!("{name}: LIVE at {origin}"));
                let spent = invites::spend(&self.state, &job.code, &name);
                match &spent {
                    Ok(true) => self.log(&format!("{name}: the invite is spent")),
                    Ok(false) => self.log(&format!("{name}: the invite was not found issued at the spend; the board stands")),
                    Err(e) => self.log(&format!("{name}: the invite could not be marked spent ({e}); this run refuses it, and the operator marks it")),
                }
                // The code is let go of AFTER the spend is written: a post
                // that finds the book not holding it then finds the file
                // holding it spent. A spend that could not be written keeps
                // its code held for this run's life: the file still says
                // issued.
                if spent.is_ok() {
                    self.book().codes.remove(&job.code);
                }
                true
            }
            Err(step) => {
                self.log(&format!("{name}: FAILED at {step}"));
                self.cleanup(&name, made);
                let mut book = self.book();
                book.map.set(&job.token, State::Failed, None);
                book.codes.remove(&job.code);
                false
            }
        };
        if live {
            self.send(&job);
        }
    }

    /// STEPS 3 TO 5, in order; the first that fails is named.
    fn steps(&self, job: &Job, made: &mut Made) -> Result<(), &'static str> {
        let name = &job.name;
        let docker = self.docker.as_ref();
        // 3. The truth again: a name made since the post is not this post's.
        match names::taken(docker, &self.config.boards_dir, name) {
            Ok(None) => {}
            Ok(Some(holder)) => {
                self.log(&format!("{name}: taken since the post: {}", holder.said()));
                return Err("the second look at the name");
            }
            Err(e) => {
                self.log(&format!("{name}: the second look at the name could not be made: {e}"));
                return Err("the second look at the name");
            }
        }
        self.call(name, "volume_create", docker.volume_create(name))?;
        made.volume = true;
        // The table's own row for a failed claim run is the volume alone.
        self.call(name, "run_claim", docker.run_claim(name))?;
        made.run = true;
        // 4. The dark claim, then the claim run removed — where the removal
        // fails, the claim run stands and the cleanup removes it.
        self.dark_claim(job)?;
        self.call(name, "rm_force", docker.rm_force(name))?;
        // 5. The serving run: `made.run` stays set across it, for where its
        // `docker run` fails a run may stand all the same (the table's row:
        // the serving run and the volume).
        self.call(name, "run_serving", docker.run_serving(name))?;
        match health::wait(docker, name, HEALTH_WAIT, self.sleep.as_ref()) {
            Ok(Waited::Paired { at }) => self.log(&format!("{name}: health: the pair answered at try {at} of {}", HEALTH_WAIT.tries)),
            Ok(Waited::GaveUp { tries, last }) => {
                self.log(&format!("{name}: health: no pair after {tries} tries (the last exit {})", last.map_or_else(|| "signal".to_owned(), |c| c.to_string())));
                return Err("the /health wait");
            }
            Err(e) => {
                self.log(&format!("{name}: health: docker could not run: {e}"));
                return Err("the /health wait");
            }
        }
        // THE SERIAL PAIR: the snippet's write and the reload under the one
        // `caddy` hold, to the end of this function, so no reload of another
        // name's lands between this snippet and its own reload.
        let _caddy = self.caddy();
        if let Err(e) = caddy::write(&self.config.boards_dir, name, &self.config.suffix) {
            self.log(&format!("{name}: snippet: not written: {e}"));
            return Err("the snippet's write");
        }
        made.snippet = true;
        self.log(&format!("{name}: snippet: written"));
        self.call(name, "caddy_reload", caddy::reload(docker))?;
        Ok(())
    }

    /// STEP 4: the sidecar run until it answers other than exit 4, or the
    /// bound passes; its stderr logged whole every try.
    fn dark_claim(&self, job: &Job) -> Result<(), &'static str> {
        let name = &job.name;
        for at in 1..=SIDECAR_WAIT.tries {
            let exit = match self.docker.sidecar_claim(name, job.record.bytes()) {
                Ok(exit) => exit,
                Err(e) => {
                    self.log(&format!("{name}: sidecar_claim: docker could not run: {e}"));
                    return Err("the dark claim");
                }
            };
            self.log(&format!("{name}: sidecar_claim: try {at} of {}: exit {}", SIDECAR_WAIT.tries, exit.said()));
            for line in String::from_utf8_lossy(&exit.stderr).lines() {
                self.log(&format!("{name}: sidecar: {line}"));
            }
            match sidecar::read(&exit) {
                Ok(Answer::Claimed(c)) => {
                    self.log(&format!("{name}: claimed: claimant {}, account {}, principal {}", c.claimant, c.account, c.principal));
                    return Ok(());
                }
                Ok(Answer::AlreadyClaimed { .. }) => {
                    self.log(&format!("{name}: the volume made for this post answered `claimed by`: residue where none should be"));
                    return Err("the dark claim");
                }
                Err(Failure::Transport) if at < SIDECAR_WAIT.tries => (self.sleep)(SIDECAR_WAIT.interval),
                Err(failure) => {
                    self.log(&format!("{name}: sidecar_claim: {}", failure.said()));
                    return Err("the dark claim");
                }
            }
        }
        Err("the dark claim")
    }

    /// ONE CALL's answer logged and judged: exit 0 goes on; any other exit,
    /// or a `docker` that could not run, fails the step `step`, the call's
    /// stderr logged whole.
    fn call(&self, name: &Name, step: &'static str, answered: io::Result<Exit>) -> Result<Exit, &'static str> {
        match answered {
            Ok(exit) if exit.ok() => {
                self.log(&format!("{name}: {step}: exit 0"));
                Ok(exit)
            }
            Ok(exit) => {
                self.log(&format!("{name}: {step}: exit {}", exit.said()));
                for line in String::from_utf8_lossy(&exit.stderr).lines() {
                    self.log(&format!("{name}: {step}: {line}"));
                }
                Err(step)
            }
            Err(e) => {
                self.log(&format!("{name}: {step}: docker could not run: {e}"));
                Err(step)
            }
        }
    }

    /// THE CLEANUP: what was made, undone in reverse; a removal that fails
    /// is logged, the next still tried, and the name said to stand.
    fn cleanup(&self, name: &Name, made: Made) {
        let docker = self.docker.as_ref();
        let mut stands = false;
        if made.snippet {
            // The serial pair again: the removal and the reload under the
            // one `caddy` hold, to the end of this block.
            let _caddy = self.caddy();
            match caddy::remove(&self.config.boards_dir, name) {
                Ok(_) => self.log(&format!("{name}: cleanup: snippet: removed")),
                Err(e) => {
                    stands = true;
                    self.log(&format!("{name}: cleanup: snippet: not removed: {e}"));
                }
            }
            stands |= !self.undone(name, "cleanup", "caddy_reload", caddy::reload(docker));
        }
        if made.run {
            stands |= !self.undone(name, "cleanup", "rm_force", docker.rm_force(name));
        }
        if made.volume {
            stands |= !self.undone(name, "cleanup", "volume_rm", docker.volume_rm(name));
        }
        if stands {
            self.log(&format!("{name}: cleanup: INCOMPLETE — the name stands, and refuses new posts (D-4) until the operator clears it"));
        } else if made != Made::default() {
            self.log(&format!("{name}: cleanup: done — nothing stands under the name"));
        }
    }

    /// One removal's answer logged under `under` — `cleanup` or `sweep`:
    /// `true` where it exited 0.
    fn undone(&self, name: &Name, under: &str, step: &str, answered: io::Result<Exit>) -> bool {
        match answered {
            Ok(exit) if exit.ok() => {
                self.log(&format!("{name}: {under}: {step}: exit 0"));
                true
            }
            Ok(exit) => {
                self.log(&format!("{name}: {under}: {step}: exit {}", exit.said()));
                for line in String::from_utf8_lossy(&exit.stderr).lines() {
                    self.log(&format!("{name}: {under}: {step}: {line}"));
                }
                false
            }
            Err(e) => {
                self.log(&format!("{name}: {under}: {step}: docker could not run: {e}"));
                false
            }
        }
    }

    /// THE SEND: the reply handed to the sender's thread — where mail is
    /// configured — once the status is live.
    fn send(&self, job: &Job) {
        let Some(mail) = &self.mail else { return };
        let origin = job.name.origin(&self.config.suffix);
        let status = pages::status_address(&self.config.suffix, &job.token);
        mail.outbox.post(Message {
            name: job.name.clone(),
            to: job.address.clone(),
            from: mail.from.clone(),
            reply_to: self.config.reply_to.clone(),
            subject: fill(MAIL_SUBJECT, &[]),
            body: reply::text(&origin, job.record.anchorless(), &status),
        });
    }

    /// WHAT IS IN FLIGHT, under the book's lock the caller holds: the queue
    /// full (D-8, "try again later"), the code held by a post in flight, the
    /// name held by one (D-4) — each logged and refused, no docker call
    /// made.
    fn in_flight(&self, book: &Book, name: &Name, code: &str) -> Result<(), Refusal> {
        if book.queue.len() >= QUEUE_DEPTH {
            self.log(&format!("{name}: a post refused: {QUEUE_DEPTH} posts already wait"));
            return Err(Refusal::Busy);
        }
        if book.codes.contains(code) {
            self.log(&format!("{name}: a post refused: its invite is held by a post in flight"));
            return Err(Refusal::Invite);
        }
        if book.map.holds(name) {
            self.log(&format!("{name}: a post refused: a post in flight holds the name"));
            return Err(Refusal::Name);
        }
        Ok(())
    }
}

impl Desk for Service {
    fn sign_up(&self, address: &[u8]) -> Result<(), SignUpRefusal> {
        match self.signups.append(address) {
            Ok(()) => {
                self.log("a sign-up kept");
                Ok(())
            }
            Err(SignUpRefused::NotAnAddress) => {
                self.log("a sign-up refused: no address");
                Err(SignUpRefusal::NotAnAddress)
            }
            Err(SignUpRefused::Io(e)) => {
                self.log(&format!("a sign-up could not be kept: {e}"));
                Err(SignUpRefusal::Failed)
            }
        }
    }

    fn claim(&self, post: &Post<'_>) -> Result<String, Refusal> {
        // The invite, first: an uninvited post learns nothing about names.
        let Some(code) = std::str::from_utf8(post.invite).ok().filter(|c| invites::code_ok(c)) else {
            self.log("a post refused: no invite code of the code's form");
            return Err(Refusal::Invite);
        };
        let invite = match invites::lookup(&self.state, code) {
            Ok(Some(invite)) if invite.issued() => invite,
            Ok(_) => {
                self.log("a post refused: its invite code is not one the file holds issued");
                return Err(Refusal::Invite);
            }
            Err(e) => {
                self.log(&format!("a post could not be judged: the invite file: {e}"));
                return Err(Refusal::Failed);
            }
        };
        let name = Name::parse(post.name).map_err(|why| {
            self.log(&format!("a post refused: {why}"));
            Refusal::Name
        })?;
        let record = record::admit(post.record).map_err(|refused| {
            self.log(&format!("{name}: a post refused: the record, {}", refused.token()));
            match refused {
                RecordRefused::NotARecord(_) => Refusal::Record,
                RecordRefused::PreviewKey { .. } => Refusal::Preview,
            }
        })?;
        // WHAT IS IN FLIGHT, under the book's short lock: a refusal here
        // costs no docker call.
        self.in_flight(&self.book(), &name, code)?;
        // THE TRUTH ABOUT THE NAME: three reads under no lock of this
        // service's — a post waits on no provisioning.
        match names::taken(self.docker.as_ref(), &self.config.boards_dir, &name) {
            Ok(None) => {}
            Ok(Some(holder)) => {
                self.log(&format!("{name}: a post refused: taken — {}", holder.said()));
                return Err(Refusal::Name);
            }
            Err(e) => {
                self.log(&format!("{name}: a post could not be judged: the look at the name: {e}"));
                return Err(Refusal::Failed);
            }
        }
        let token = names::fresh_token().map_err(|e| {
            self.log(&format!("{name}: a post could not be admitted: {e}"));
            Refusal::Failed
        })?;
        // THE ADMISSION, under the book's lock: what is in flight looked at
        // again — a post for this name or this code may have been admitted
        // while the reads ran — and the invite looked up again under the
        // same hold. A worker spends a code and then lets go of it, in that
        // order, so a code the book does not hold and the file holds issued
        // is one no board has spent; and the name is held from here, so no
        // second post for it is admitted while this one is in flight.
        let waiting = {
            let mut book = self.book();
            self.in_flight(&book, &name, code)?;
            match invites::lookup(&self.state, code) {
                Ok(Some(again)) if again.issued() => {}
                Ok(_) => {
                    self.log(&format!("{name}: a post refused: its invite was spent while the post was judged"));
                    return Err(Refusal::Invite);
                }
                Err(e) => {
                    self.log(&format!("{name}: a post could not be judged: the invite file: {e}"));
                    return Err(Refusal::Failed);
                }
            }
            book.codes.insert(code.to_owned());
            book.map.admit(token.clone(), name.clone(), record.anchorless());
            book.queue.push_back(Job { token: token.clone(), name: name.clone(), record, code: code.to_owned(), address: invite.address });
            book.queue.len()
        };
        self.ready.notify_one();
        self.log(&format!("{name}: admitted; {waiting} waiting"));
        Ok(token)
    }

    fn status(&self, token: &str) -> Option<Shown> {
        let book = self.book();
        let post = book.map.post(token)?;
        Some(match post.state {
            State::Queued | State::Running => Shown::BeingMade,
            State::Live => Shown::Live(reply::text(&post.name.origin(&self.config.suffix), post.anchorless, &pages::status_address(&self.config.suffix, token))),
            State::Failed => Shown::Failed,
        })
    }
}

#[cfg(test)]
mod tests;
