//! THE FLOW (the deployment notes §4, steps 3 to 5; the provisioning record
//! §2 and §5.2): the [`Service`] the pages' desk is, ONE WORKER, ONE LOCK.
//!
//! THE POST ([`Service`]'s `Desk::claim`): the invite looked up — a code the
//! file holds issued; the name's grammar; the record admitted (D-5, D-6) —
//! each in process, before any docker call; then, UNDER THE ONE LOCK, the
//! queue's depth ([`QUEUE_DEPTH`]; past it D-8, "try again later"), the
//! names and the codes a post in flight holds, and THE TRUTH ABOUT THE NAME
//! (`names::taken`, D-4); then the status token minted, the post queued, and
//! D-7 answered with its status address. A refused post leaves nothing: no
//! docker call past the truth's reads, no file, no queue entry. A post that
//! arrives while a provisioning runs waits for the lock before its reads —
//! the lock is the provisioning's whole — and is answered when it is free.
//!
//! THE WORKER ([`Service::work`]), one thread, one post at a time, THE ONE
//! LOCK held over the whole of a provisioning — the steps, the snippet, the
//! reload, the invite's spend:
//!
//! 3. the truth about the name read again; `volume_create`; `run_claim`,
//!    the public origin configured (AUTH-4.57 (a), (b), (f));
//! 4. `sidecar_claim`, the record on its stdin, RETRIED on exit 4 while the
//!    claim run's daemon is not yet listening ([`SIDECAR_WAIT`]); its DATA
//!    read (`sidecar`): the six lines are the claim, `claimed by …` on the
//!    volume this flow just made is residue — a failure — and any other
//!    exit or shape a failure, its stderr whole in the log; then `rm_force`
//!    the claim run;
//! 5. `run_serving`; the `/health` wait for the PAIR (`health`) — the
//!    first-start guard beside the proxy's own check (AUTH-4.57 (d)); the
//!    snippet written (`caddy`, AUTH-4.57 (c)); `caddy_reload`;
//!
//! then THE STATUS LIVE, then THE INVITE SPENT, then — the lock released —
//! THE MAIL handed to the sender's own thread, after the page and never
//! ahead of it, so a mail outage holds up no next post.
//!
//! THE CLEANUP (the record §5.2's decision table, D-8 made literally true):
//! on a failed step, what the flow made is undone in the reverse of the
//! order it was made — the snippet removed and Caddy reloaded where the
//! snippet was written; `rm_force` where a run stands; `volume_rm` where
//! the volume stands — the status FAILED (D-8) and the invite NOT spent, so
//! the person may post again. By the table: `volume_create` failed —
//! nothing; `run_claim` failed — the volume; the dark claim failed (exit 4
//! past the bound, 3, 1, 2, or `claimed by`) — the claim run and the
//! volume; `run_serving` failed, or the pair never answered, or the
//! snippet's write failed — the serving run and the volume; the reload
//! failed — the snippet and a reload, the serving run, the volume. A board
//! whose claim landed and whose route did not is removed with its volume:
//! no route ever existed, so no one wrote to it, and a re-post claims a
//! fresh volume with the same keys. THE NAMED GAP: a cleanup call that
//! itself fails is logged and leaves the name standing — the truth then
//! refuses re-posts (D-4) until the operator clears it.
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
use crate::names::{self, State, StatusMap};
use crate::pages::{self, Desk, Post, Refusal, Shown, SignUpRefusal, MAIL_SUBJECT};
use crate::record::{self, Name, Record, RecordRefused};
use crate::reply;
use crate::sender::{Log, Message, Outbox, Sleep};
use crate::sidecar::{self, Answer, Failure};
use crate::signups::{SignUpRefused, SignUps, StateDir};

/// THE QUEUE's DEPTH: four posts waiting for the worker, the one it runs
/// apart (the provisioning record §5.2's figure); a fifth meets D-8, "try
/// again later".
pub const QUEUE_DEPTH: usize = 4;

/// THE DARK CLAIM's RETRY: thirty tries two seconds apart while the
/// sidecar answers exit 4 — the claim run's daemon not yet listening.
pub const SIDECAR_WAIT: Wait = Wait { tries: 30, interval: Duration::from_secs(2) };

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

/// What the routes and the worker share under the book's own short lock:
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

/// THE SERVICE: the desk the routes ask, and the worker's state.
pub struct Service {
    config: Config,
    state: StateDir,
    signups: SignUps,
    docker: Box<dyn Docker>,
    mail: Option<Mail>,
    log: Log,
    sleep: Sleep,
    /// THE ONE LOCK, over the whole of a provisioning and a post's reads.
    lock: Mutex<()>,
    book: Mutex<Book>,
    ready: Condvar,
}

impl Service {
    /// The service over its configuration, its state directory, its runner
    /// and its mail — the status map REBUILT from the snippet directory.
    pub fn new(config: Config, state: StateDir, docker: Box<dyn Docker>, mail: Option<Mail>, log: Log, sleep: Sleep) -> io::Result<Service> {
        let map = StatusMap::rebuild(&config.boards_dir, &config.suffix)?;
        let signups = SignUps::new(&state);
        Ok(Service { config, state, signups, docker, mail, log, sleep, lock: Mutex::new(()), book: Mutex::new(Book { queue: VecDeque::new(), map, codes: HashSet::new() }), ready: Condvar::new() })
    }

    /// The live names the map holds — at start, the rebuild's.
    pub fn live(&self) -> usize {
        self.book().map.live().len()
    }

    /// THE WORKER: the next post waited for and provisioned, forever.
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
    /// none waits: the worker's one turn, as a unit suite drives it.
    #[cfg(test)]
    pub fn run_next(&self) -> bool {
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

    fn one_lock(&self) -> MutexGuard<'_, ()> {
        self.lock.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn log(&self, line: &str) {
        (self.log)(line);
    }

    /// ONE POST PROVISIONED: the steps under the one lock, then live or
    /// cleaned up; the mail after.
    fn provision(&self, job: Job) {
        let name = job.name.clone();
        let live = {
            let _one = self.one_lock();
            let mut made = Made::default();
            match self.steps(&job, &mut made) {
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
                    // A spend that could not be written keeps its code held
                    // for this run's life: the file still says issued.
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
            match caddy::remove(&self.config.boards_dir, name) {
                Ok(_) => self.log(&format!("{name}: cleanup: snippet: removed")),
                Err(e) => {
                    stands = true;
                    self.log(&format!("{name}: cleanup: snippet: not removed: {e}"));
                }
            }
            stands |= !self.undone(name, "caddy_reload", caddy::reload(docker));
        }
        if made.run {
            stands |= !self.undone(name, "rm_force", docker.rm_force(name));
        }
        if made.volume {
            stands |= !self.undone(name, "volume_rm", docker.volume_rm(name));
        }
        if stands {
            self.log(&format!("{name}: cleanup: INCOMPLETE — the name stands, and refuses new posts (D-4) until the operator clears it"));
        } else if made != Made::default() {
            self.log(&format!("{name}: cleanup: done — nothing stands under the name"));
        }
    }

    /// One cleanup call's answer logged: `true` where it exited 0.
    fn undone(&self, name: &Name, step: &str, answered: io::Result<Exit>) -> bool {
        match answered {
            Ok(exit) if exit.ok() => {
                self.log(&format!("{name}: cleanup: {step}: exit 0"));
                true
            }
            Ok(exit) => {
                self.log(&format!("{name}: cleanup: {step}: exit {}", exit.said()));
                for line in String::from_utf8_lossy(&exit.stderr).lines() {
                    self.log(&format!("{name}: cleanup: {step}: {line}"));
                }
                false
            }
            Err(e) => {
                self.log(&format!("{name}: cleanup: {step}: docker could not run: {e}"));
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
            subject: pages::fill(MAIL_SUBJECT, &[]),
            body: reply::text(&origin, job.record.anchorless(), &status),
        });
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
        // UNDER THE ONE LOCK: the invite again — a post that held it may
        // have spent it while this one waited for the lock — then what is in
        // flight, then what stands.
        let _one = self.one_lock();
        match invites::lookup(&self.state, code) {
            Ok(Some(again)) if again.issued() => {}
            Ok(_) => {
                self.log(&format!("{name}: a post refused: its invite was spent while it waited"));
                return Err(Refusal::Invite);
            }
            Err(e) => {
                self.log(&format!("{name}: a post could not be judged: the invite file: {e}"));
                return Err(Refusal::Failed);
            }
        }
        {
            let book = self.book();
            if book.queue.len() >= QUEUE_DEPTH {
                self.log(&format!("{name}: a post refused: {QUEUE_DEPTH} posts already wait"));
                return Err(Refusal::Busy);
            }
            if book.codes.contains(code) {
                self.log(&format!("{name}: a post refused: its invite is held by a post in flight"));
                return Err(Refusal::Invite);
            }
            if book.map.holds(&name) {
                self.log(&format!("{name}: a post refused: a post in flight holds the name"));
                return Err(Refusal::Name);
            }
        }
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
        let waiting = {
            let mut book = self.book();
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
