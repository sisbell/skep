//! THE FLOW (the deployment notes §4, steps 3 to 5; the provisioning record
//! §2 and §5.2): the [`Service`] the pages' desk is — A POOL OF WORKERS,
//! THE NAME THE UNIT OF EXCLUSION.
//!
//! THE POST ([`Service`]'s `Desk::admit`): the invite looked up — a code the
//! file holds issued; the name's grammar; the record admitted (D-5, D-6) —
//! each in process, before any docker call; then WHAT IS IN FLIGHT, under
//! the book's short lock — the queue's depth ([`QUEUE_DEPTH`]; past it D-8,
//! "try again later"), the codes and the names the posts in flight hold —
//! refused with no docker call; then THE TRUTH ABOUT THE NAME
//! (`names::taken`, D-4), three reads under no lock of this service's, at
//! most [`MAX_LOOKS`] posts' at once — past it D-8, "try again later", with
//! no docker call; then THE ADMISSION, under the book's lock again: what is
//! in flight checked again — a post for this name or this code may have
//! been admitted while the reads ran — and the invite looked up again under
//! the same lock — a board gone live meanwhile may have spent it — then the
//! status token minted, the post queued, and D-7 answered with its status
//! URL. A refused post leaves nothing: no docker call past the truth's
//! reads, no file, no queue entry. A POST NEVER WAITS ON A PROVISIONING: no
//! lock it takes is held across one.
//!
//! THE NAME IS THE UNIT OF EXCLUSION. A name is HELD from its admission to
//! its live or failed end (the status map's `holds`) — the owner's lock per
//! name, an entry in the book that no thread waits on — and a second post
//! for a name in flight is refused (D-4) under the book's lock, the very
//! lock that admits — so no two posts for one name are ever in flight, and
//! the worker that takes a post owns its name alone to the end. No mutex is
//! held over a provisioning: two workers make two names at once.
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
//!    A ROUTE CHANGE under the one route lock, serial across every name:
//!    the snippet written (`caddy`, AUTH-4.57 (c)) and `caddy_reload` — so
//!    no reload lands between another name's snippet and its own reload,
//!    and, where the write or the reload fails, none between that snippet
//!    and the reload that undoes it: the lock is held on into the cleanup;
//!
//! then THE STATUS LIVE, then THE INVITE SPENT under the invite file's own
//! lock and its code let go of, in that order, then THE MAIL handed to the
//! sender's own thread, after the page and never ahead of it, so a mail
//! outage holds up no next post.
//!
//! THE CLEANUP (the provisioning record §5.2's decision table, D-8 made
//! literally true): on a failed step, what the flow made is undone in the
//! reverse of the order it was made — the snippet removed where its write
//! began, and Caddy reloaded where one stood or may stand, the route change's
//! undo under the route lock its write took and held since; `rm_force` where a
//! run may stand; `volume_rm` where the volume stands — and then THE TRUTH
//! ASKED what stands under the name: the three reads a post makes
//! (`names::taken`), the ones D-8's "Nothing stands under your name" speaks
//! of, never the removals' answers. The status FAILED (D-8) and the invite NOT
//! spent, so the person may post again. By the table: `volume_create` failed —
//! nothing; `run_claim` failed — the volume; the dark claim failed (exit 4
//! past the bound, 3, 1, 2, or `claimed by`) — the claim run and the volume;
//! `run_serving` failed, or the pair never answered — the serving run and the
//! volume; the snippet's write failed — the snippet, where its rename landed,
//! and a reload, then the serving run and the volume; the reload failed — the
//! snippet and a reload, the serving run, the volume. A board whose claim
//! landed and whose route did not is removed with its volume: no route ever
//! existed — the route lock kept every other name's reload out while its
//! snippet stood, and its own reload, where one was made, failed — so no one
//! wrote to it, and a re-post claims a fresh volume with the same keys. THE
//! NAMED GAP: where something still stands after the removals — a removal that
//! itself failed — the log says INCOMPLETE and names it, and the truth then
//! refuses re-posts (D-4) until the operator clears it; a refused `rm -f` of a
//! run that never stood, and a reload that fails, leave nothing the truth
//! reads, and the verdict is done.
//!
//! THE SWEEP AT START ([`Service::sweep`]; `serve` runs it once, before it
//! listens): a stop mid-board leaves a volume, and perhaps a run, under a name
//! with no snippet, which the truth would read as TAKEN for good — so every
//! volume under this service's label is listed, and each under a name of the
//! grammar with no snippet is handed to the cleanup itself as what a stop
//! leaves, and so undone by the table's last two rows, the truth asked what
//! stands after; a name whose snippet stands is left, a volume under no name
//! of the grammar is logged and left, and a listing that fails is logged and
//! the sweep skipped — the sign-up still serves. Its precondition is the
//! operator's: ONE SERVICE PER DOCKER HOST, for the label and the names are
//! the host's, and a second service would take the first's boards for
//! half-made.
//!
//! THE DESK's OTHER TWO ANSWERS: a sign-up (`Desk::sign_up`), the address
//! kept through `signups` and logged as kept or refused — never the
//! address — touching nothing of the book; and a status (`Desk::status`),
//! a query of the book's status map, a live post's page rendered by the
//! one renderer from the inputs [`Service`]'s `live_reply` gathers.
//!
//! THE LOG, on stderr through [`Log`]: one line per step naming the name,
//! the step and each call's exit code, and the sidecar's stderr whole —
//! NEVER the record's bytes, an address, an invite code or a status token
//! (the provisioning record §4).

use std::collections::{HashSet, VecDeque};
use std::fmt;
use std::io;
use std::num::NonZeroU32;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex, MutexGuard};
use std::time::Duration;

use crate::caddy;
use crate::docker::Docker;
use crate::health::{self, Waited, HEALTH_WAIT};
use crate::invites::{self, InviteCode};
use crate::name::Name;
use crate::names::{self, PostState, StatusMap};
use crate::pages::{self, Desk, Post, Refusal, Shown, SignUpRefusal};
use crate::process::Exit;
use crate::record::{self, Record, RecordRefused};
use crate::reply;
use crate::sender::{Log, Outbox, Sleep};
use crate::sidecar::{self, Answer, Failure};
use crate::signups::{SignUpRefused, SignUps};
use crate::statedir::StateDir;
use crate::wait::Wait;

/// THE QUEUE's DEPTH: four posts WAITING for a worker, the ones the workers
/// run apart (the provisioning record §5.2's figure); a fifth meets D-8,
/// "try again later".
const QUEUE_DEPTH: usize = 4;

/// THE DARK CLAIM's RETRY: thirty tries two seconds apart while the
/// sidecar answers exit 4 — the claim run's daemon not yet listening.
const SIDECAR_WAIT: Wait = Wait { tries: NonZeroU32::new(30).expect("thirty is not zero"), interval: Duration::from_secs(2) };

/// THE LOOKS' CAP: four posts' looks at what stands under their names at
/// once — [`QUEUE_DEPTH`], the posts that can wait at once. A look is up to
/// two `docker` processes, Go programs of tens of megabytes each, and a post
/// refused D-4 off a container — the proxy's own, `caddy`, stands under its
/// name — leaves its code issued and unheld, so uncapped one issued code
/// would have the service run two for every connection open at once, for as
/// long as its holder looped. A post past it meets D-8, "try again later",
/// with no docker call.
const MAX_LOOKS: usize = QUEUE_DEPTH;

/// What the service is configured with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// `--boards-dir`: where the snippets live.
    pub boards_dir: PathBuf,
    /// `--suffix`: the domain every board stands under.
    pub suffix: String,
}

/// One admitted post, waiting or running.
struct Job {
    token: String,
    name: Name,
    record: Record,
    code: InviteCode,
    address: String,
}

/// THE BOOK: WHAT IS IN FLIGHT, which the pages and the workers share
/// under its own short lock — the posts waiting for a worker, this
/// process's posts by token (the status map), and the invite codes the
/// posts in flight hold — and THE RULES THAT TIE THEM: a post admitted waits
/// with its token in the map and its code held; a post taken is running; a
/// failed post lets its code go at once, and a live one keeps it held until
/// the worker lets it go ([`Book::release`]), once the spend is written; and
/// a new post is refused by a full queue, a held code or a held name, the
/// first of them in that order.
struct Book {
    queue: VecDeque<Job>,
    map: StatusMap,
    codes: HashSet<InviteCode>,
}

/// What in flight refuses a new post.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Blocked {
    /// [`QUEUE_DEPTH`] posts already wait.
    QueueFull,
    /// A post in flight holds the invite code.
    CodeHeld,
    /// A post in flight holds the name.
    NameHeld,
}

impl Book {
    /// The book at start: nothing in flight, the status map as rebuilt.
    fn new(map: StatusMap) -> Book {
        Book { queue: VecDeque::new(), map, codes: HashSet::new() }
    }

    /// What refuses a new post for `name` under `code`: the first of a full
    /// queue, a held code and a held name — `None` where none does.
    fn blocks(&self, name: &Name, code: &InviteCode) -> Option<Blocked> {
        if self.queue.len() >= QUEUE_DEPTH {
            Some(Blocked::QueueFull)
        } else if self.codes.contains(code) {
            Some(Blocked::CodeHeld)
        } else if self.map.holds(name) {
            Some(Blocked::NameHeld)
        } else {
            None
        }
    }

    /// A post admitted: its code held, its token in the map, the post queued
    /// — answered with the posts now waiting.
    fn admit(&mut self, job: Job) -> usize {
        self.codes.insert(job.code.clone());
        self.map.admit(job.token.clone(), job.name.clone(), job.record.anchorless());
        self.queue.push_back(job);
        self.queue.len()
    }

    /// The next waiting post, taken by a worker: now running.
    fn take(&mut self) -> Option<Job> {
        let job = self.queue.pop_front()?;
        self.map.set(&job.token, PostState::Running);
        Some(job)
    }

    /// `token`'s post marked live: its name among the live names. Its code
    /// stays held until its spend is written ([`Book::release`]).
    fn mark_live(&mut self, token: &str) {
        self.map.set(token, PostState::Live);
    }

    /// `code` let go of: a new post may name it — a live post's once the
    /// file says spent, a failed post's at once.
    fn release(&mut self, code: &InviteCode) {
        self.codes.remove(code);
    }

    /// `job`'s post marked failed: its page D-8, and its code let go of at
    /// once — the file still holds it issued, so the person may post again.
    fn mark_failed(&mut self, job: &Job) {
        self.map.set(&job.token, PostState::Failed);
        self.release(&job.code);
    }
}

/// A PERMIT UNDER A CAP — the workspace's word for it, `skep-util`'s
/// `Permit`, which this crate's four dependencies leave out: taken where
/// fewer than the cap are held, and given back when dropped — on every
/// return and every unwind alike, so no permit is ever kept by a look that
/// ended.
struct Permit<'a>(&'a AtomicUsize);

impl<'a> Permit<'a> {
    /// A permit among `held`'s, where fewer than `cap` are held; `None`
    /// where `cap` are.
    fn take(held: &'a AtomicUsize, cap: usize) -> Option<Permit<'a>> {
        held.try_update(Ordering::AcqRel, Ordering::Acquire, |n| (n < cap).then_some(n + 1)).ok().map(|_| Permit(held))
    }
}

impl Drop for Permit<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// What a provisioning has made so far — or, handed to the sweep, what a
/// stop mid-board may have left — for the cleanup to undo; and, once its
/// snippet's write has begun, the route lock that write took, so a failed
/// route change is undone under the lock it was made under. The cleanup
/// takes it apart whole and the sweep builds it whole, so a making added here
/// is a compile error at both until each says what it does with it.
#[derive(Debug, Default)]
struct Made<'s> {
    /// The board's volume, created.
    volume: bool,
    /// A run that may stand under the name: the claim run, then the
    /// serving run.
    run: bool,
    /// THE SNIPPET, from its write's first act: the route lock that write
    /// took — the write's error may come after its rename, the snippet
    /// standing — let go of once the reload succeeds, and otherwise held
    /// on into the cleanup, across the snippet's removal and the reload
    /// that undoes it.
    snippet: Option<MutexGuard<'s, ()>>,
}

/// WHERE A CLEANUP RUNS: on a failed step — the provisioning record §5.2's
/// FAILURE CLEANUP — or at start, on a board a stop left half-made — the
/// owner's CLEANUP ON START, the sweep; and the word its log lines carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CleanupOn {
    /// A step failed: its lines say `cleanup`.
    Failure,
    /// The sweep at start: its lines say `sweep`.
    Start,
}

/// The word a cleanup's lines carry after the name: `cleanup` or `sweep`.
impl fmt::Display for CleanupOn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            CleanupOn::Failure => "cleanup",
            CleanupOn::Start => "sweep",
        })
    }
}

/// THE SERVICE: the desk the pages ask, and the workers' shared state.
pub struct Service {
    config: Config,
    state_dir: StateDir,
    signups: SignUps,
    docker: Box<dyn Docker>,
    /// Where the follow-up mail is handed: `None` where no mail is
    /// configured.
    outbox: Option<Outbox>,
    log: Log,
    sleep: Sleep,
    /// THE ROUTE LOCK: held across a route change — a snippet's write and
    /// the reload that follows it, and where either fails, on across the
    /// snippet's removal and the reload that undoes it — and nowhere else,
    /// so route changes are serial across every name: no reload of another
    /// name's lands between a snippet and its own reload, nor loads a
    /// snippet whose own route change failed.
    route_lock: Mutex<()>,
    /// THE BOOK's SHORT LOCK: what is in flight, and its rules.
    book: Mutex<Book>,
    ready: Condvar,
    /// The posts' looks at what stands under way, at most [`MAX_LOOKS`].
    looks: AtomicUsize,
}

impl Service {
    /// The service over its configuration, its state directory, its runner
    /// and its outbox — `None` where no mail is configured — the status map
    /// REBUILT from the snippet directory.
    pub fn new(config: Config, state_dir: StateDir, docker: Box<dyn Docker>, outbox: Option<Outbox>, log: Log, sleep: Sleep) -> io::Result<Service> {
        let map = StatusMap::rebuild(&config.boards_dir)?;
        let signups = SignUps::new(&state_dir);
        Ok(Service { config, state_dir, signups, docker, outbox, log, sleep, route_lock: Mutex::new(()), book: Mutex::new(Book::new(map)), ready: Condvar::new(), looks: AtomicUsize::new(0) })
    }

    /// HOW MANY live names the map holds — at start, the rebuild's: the
    /// serving line's `live`.
    pub fn live_count(&self) -> usize {
        self.book().map.live().len()
    }

    /// THE SWEEP AT START, run once before the service listens: every volume
    /// under this service's label listed; each under a name of the grammar
    /// with NO snippet is half-made — a stop mid-board left it — and is undone
    /// by [`Service::cleanup`], handed what such a stop leaves: the volume,
    /// and a run that may stand under the name. So the table's last two rows
    /// undo it — whichever run stands (`rm_force`), then the volume
    /// (`volume_rm`), each answer logged — and the truth is then asked what
    /// stands ([`Service::cleared`]): done, or INCOMPLETE naming what stands,
    /// the name then taken until the operator clears it. A name whose snippet
    /// stands is left — live, or stopped and Docker's `--restart` to bring
    /// back — and so is a listed volume under no name of the grammar, logged.
    /// A listing that fails is logged and the sweep skipped: a listing failure
    /// must not take the sign-up down. Answers the boards cleared, for the
    /// serving line.
    ///
    /// ITS PRECONDITION, the operator's: ONE SERVICE PER DOCKER HOST. The
    /// label marks every volume any `serve` on the host made, and a volume
    /// is half-made by this service's snippet directory alone — so a second
    /// service on the host would read the first's boards in flight, and
    /// under another `--boards-dir` its live boards too, as half-made, and
    /// remove them; the host's volume and container names are one namespace
    /// besides. Nothing in a volume tells two services apart, so nothing
    /// here checks it: it is the operator's to keep.
    pub fn sweep(&self) -> usize {
        let docker = self.docker.as_ref();
        let listing = match docker.labelled_volumes() {
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
            // What a stop mid-board leaves — the volume, and a run that may
            // stand under the name — undone by the cleanup: its table's last
            // two rows, then the truth asked what stands.
            if self.cleanup(name, Made { volume: true, run: true, snippet: None }, CleanupOn::Start) {
                swept += 1;
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
                    if let Some(job) = book.take() {
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
        let Some(job) = self.book().take() else { return false };
        self.provision(job);
        true
    }

    fn book(&self) -> MutexGuard<'_, Book> {
        self.book.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn route_lock(&self) -> MutexGuard<'_, ()> {
        self.route_lock.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn log(&self, line: &str) {
        (self.log)(line);
    }

    /// ONE POST PROVISIONED on the worker that owns its name: the steps,
    /// then live — the route lock let go of first — and the mail after it;
    /// or cleaned up, the route lock held on into the cleanup where the steps
    /// took it, and no mail.
    fn provision(&self, job: Job) {
        let name = &job.name;
        let mut made = Made::default();
        match self.steps(&job, &mut made) {
            Ok(()) => {
                // The route change is done: its lock let go of before the
                // spend and the mail, which change no route.
                drop(made);
                self.book().mark_live(&job.token);
                self.log(&format!("{name}: LIVE at {}", name.origin(&self.config.suffix)));
                let spent = invites::spend(&self.state_dir, &job.code, name);
                match &spent {
                    Ok(true) => self.log(&format!("{name}: the invite is spent")),
                    Ok(false) => self.log(&format!("{name}: the invite was not found issued at the spend; the board stands")),
                    Err(e) => self.log(&format!("{name}: the invite could not be marked spent ({e}); this process refuses it, and the operator marks it")),
                }
                // The code is let go of AFTER the spend is written: a post
                // that finds the book not holding it then finds the file
                // holding it spent. A spend that could not be written keeps
                // its code held for the process's life: the file still says
                // issued.
                if spent.is_ok() {
                    self.book().release(&job.code);
                }
                // The mail, last: after the page, never ahead of it.
                self.hand_over_mail(job);
            }
            Err(step) => {
                self.log(&format!("{name}: FAILED at {step}"));
                self.cleanup(name, made, CleanupOn::Failure);
                self.book().mark_failed(&job);
            }
        }
    }

    /// STEPS 3 TO 5, in order; the first that fails is named, and `made`
    /// says what the cleanup undoes — from the snippet's write on, under
    /// the route lock it holds.
    fn steps<'s>(&'s self, job: &Job, made: &mut Made<'s>) -> Result<(), &'static str> {
        let name = &job.name;
        let docker = self.docker.as_ref();
        // 3. The truth again: a name made since the post is not this post's.
        match names::taken(docker, &self.config.boards_dir, name) {
            Ok(None) => {}
            Ok(Some(by)) => {
                self.log(&format!("{name}: taken since the post: {by}"));
                return Err("the second look at the name");
            }
            Err(e) => {
                self.log(&format!("{name}: the second look at the name could not be made: {e}"));
                return Err("the second look at the name");
            }
        }
        self.done(name, "volume_create", docker.volume_create(name))?;
        made.volume = true;
        // The table's own row for a failed claim run is the volume alone.
        self.done(name, "run_claim", docker.run_claim(name))?;
        made.run = true;
        // 4. The dark claim, then the claim run removed — where the removal
        // fails, the claim run stands and the cleanup removes it.
        self.dark_claim(job)?;
        self.done(name, "rm_force", docker.rm_force(name))?;
        // 5. The serving run: `made.run` stays set across it, for where its
        // `docker run` fails a run may stand all the same (the table's row:
        // the serving run and the volume).
        self.done(name, "run_serving", docker.run_serving(name))?;
        match health::wait(docker, name, HEALTH_WAIT, self.sleep.as_ref()) {
            Ok(Waited::Paired { at }) => self.log(&format!("{name}: health: the pair answered at try {at} of {}", HEALTH_WAIT.tries)),
            Ok(Waited::GaveUp { tries, last_code }) => {
                self.log(&format!("{name}: health: no pair after {tries} tries (the last exit {})", last_code.map_or_else(|| "signal".to_owned(), |c| c.to_string())));
                return Err("the /health wait");
            }
            Err(e) => {
                self.log(&format!("{name}: health: docker could not run: {e}"));
                return Err("the /health wait");
            }
        }
        // A ROUTE CHANGE: the snippet's write and the reload under the route
        // lock, which `made` holds from the write's first act — the write's
        // error may come after its rename, the snippet standing — so no
        // reload of another name's lands between this snippet and its own
        // reload, and where either fails, the cleanup undoes the snippet
        // under the same lock.
        made.snippet = Some(self.route_lock());
        if let Err(e) = caddy::write(&self.config.boards_dir, name, &self.config.suffix) {
            self.log(&format!("{name}: snippet: the write failed: {e}"));
            return Err("the snippet's write");
        }
        self.log(&format!("{name}: snippet: written"));
        self.done(name, "caddy_reload", caddy::reload(docker))?;
        Ok(())
    }

    /// STEP 4: the sidecar run over [`SIDECAR_WAIT`] until it answers other
    /// than exit 4, or the bound passes — its last exit 4 then the step's
    /// failure; its stderr logged whole every try.
    fn dark_claim(&self, job: &Job) -> Result<(), &'static str> {
        let name = &job.name;
        for at in SIDECAR_WAIT.paced(self.sleep.as_ref()) {
            let exit = match self.docker.sidecar_claim(name, &job.record) {
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
                // The daemon not yet listening: the next try, after the
                // wait's pause.
                Err(Failure::Transport) => {}
                Err(failure) => {
                    self.log(&format!("{name}: sidecar_claim: {failure}"));
                    return Err("the dark claim");
                }
            }
        }
        self.log(&format!("{name}: sidecar_claim: {}", Failure::Transport));
        Err("the dark claim")
    }

    /// ONE CALL's ANSWER logged and judged, each line opening `prefix` —
    /// `<name>: <step>` in a step, `<name>: <cleanup|sweep>: <step>` in a
    /// removal: exit 0 logged and the answer kept; any other exit logged
    /// with its stderr whole, or a `docker` that could not run logged —
    /// each `None`.
    fn judged(&self, prefix: &str, answered: io::Result<Exit>) -> Option<Exit> {
        match answered {
            Ok(exit) if exit.ok() => {
                self.log(&format!("{prefix}: exit 0"));
                Some(exit)
            }
            Ok(exit) => {
                self.log(&format!("{prefix}: exit {}", exit.said()));
                for line in String::from_utf8_lossy(&exit.stderr).lines() {
                    self.log(&format!("{prefix}: {line}"));
                }
                None
            }
            Err(e) => {
                self.log(&format!("{prefix}: docker could not run: {e}"));
                None
            }
        }
    }

    /// ONE STEP's CALL judged done: exit 0 goes on; any other exit, or a
    /// `docker` that could not run, fails the step `step`.
    fn done(&self, name: &Name, step: &'static str, answered: io::Result<Exit>) -> Result<Exit, &'static str> {
        self.judged(&format!("{name}: {step}"), answered).ok_or(step)
    }

    /// THE CLEANUP, on a failure or at start ([`CleanupOn`]): what was made,
    /// undone in reverse — the snippet under the route lock its write took,
    /// let go of once its reload is made, then the run, then the volume, each
    /// removal logged and the next still tried — and then the verdict,
    /// [`Service::cleared`]: the truth about names asked what stands, never
    /// the removals' answers. `true` where the name is cleared: the look
    /// finds nothing standing, or no look is owed, nothing having been made.
    /// `made` is taken apart whole, so a making added to [`Made`] is a
    /// compile error here until it is undone.
    fn cleanup(&self, name: &Name, made: Made<'_>, on: CleanupOn) -> bool {
        let docker = self.docker.as_ref();
        let Made { volume, run, snippet } = made;
        let made_anything = volume || run || snippet.is_some();
        if let Some(_route_change) = snippet {
            // The route change's undo, under the lock its write took, to the
            // end of this block. The removal's answer says whether a reload
            // is owed: none where no snippet stood; on an error, which may
            // follow the unlink, the snippet is read as standing and the
            // reload follows.
            let reload = match caddy::remove(&self.config.boards_dir, name) {
                Ok(true) => {
                    self.log(&format!("{name}: {on}: snippet: removed"));
                    true
                }
                Ok(false) => {
                    self.log(&format!("{name}: {on}: snippet: none stood"));
                    false
                }
                Err(e) => {
                    self.log(&format!("{name}: {on}: snippet: not removed: {e}"));
                    true
                }
            };
            if reload {
                self.undone(name, on, "caddy_reload", caddy::reload(docker));
            }
        }
        if run {
            self.undone(name, on, "rm_force", docker.rm_force(name));
        }
        if volume {
            self.undone(name, on, "volume_rm", docker.volume_rm(name));
        }
        !made_anything || self.cleared(name, on)
    }

    /// ONE REMOVAL's CALL — a making undone — logged under `on`'s word as
    /// [`Service::judged`] logs it, and nothing concluded from its answer:
    /// what stands after the removals is [`Service::cleared`]'s to ask.
    fn undone(&self, name: &Name, on: CleanupOn, step: &str, answered: io::Result<Exit>) {
        self.judged(&format!("{name}: {on}: {step}"), answered);
    }

    /// THE VERDICT AFTER THE REMOVALS, on a failure or at start: whether the
    /// name is CLEARED, asked of the truth about names itself
    /// ([`names::taken`], the three reads a post makes) and never read off
    /// the removals' answers — a refused `rm -f` may be of a run that never
    /// stood, and a reload removes nothing the truth reads — then logged
    /// under `on`'s word: done, or INCOMPLETE naming what stands, the
    /// operator's to clear. `true` where nothing stands. The reads are the
    /// post's own, an inspect's non-zero exit "not standing" whatever its
    /// reason: an Engine that cannot be reached reads here as nothing
    /// standing, as it does at a post, and the removals' lines logged above
    /// the verdict then name the Engine; a volume so left with no snippet,
    /// and any run under its name, is the next start's sweep's.
    fn cleared(&self, name: &Name, on: CleanupOn) -> bool {
        match names::taken(self.docker.as_ref(), &self.config.boards_dir, name) {
            Ok(None) => {
                self.log(&format!("{name}: {on}: done — nothing stands under the name"));
                true
            }
            Ok(Some(by)) => {
                self.log(&format!("{name}: {on}: INCOMPLETE — {by}, and the name refuses posts (D-4) until the operator clears it"));
                false
            }
            Err(e) => {
                self.log(&format!("{name}: {on}: INCOMPLETE — the look at what stands could not be made: {e}"));
                false
            }
        }
    }

    /// THE MAIL HANDED OVER: the live reply handed to the outbox — where
    /// mail is configured — once the status is live, for the sender's own
    /// thread to send; the post ends here, and its name and address go with
    /// the mail.
    fn hand_over_mail(&self, job: Job) {
        let Some(outbox) = &self.outbox else { return };
        let reply = self.live_reply(&job.name, job.record.anchorless(), &job.token);
        outbox.hand_over(job.name, job.address, reply);
    }

    /// THE LIVE REPLY of a post: what the one renderer, `reply::text`, is
    /// given — the board's public origin, the record's anchorless fact and
    /// the post's status URL — gathered in this one place for the
    /// status page and the mail alike, so the two cannot say two things.
    fn live_reply(&self, name: &Name, anchorless: bool, token: &str) -> String {
        reply::text(&name.origin(&self.config.suffix), anchorless, &pages::status_url(&self.config.suffix, token))
    }

    /// WHAT IS IN FLIGHT, under the book's lock the caller holds: what the
    /// book says blocks the post — the queue full (D-8, "try again later"),
    /// the code held by a post in flight, the name held by one (D-4) —
    /// logged and refused, no docker call made.
    fn in_flight(&self, book: &Book, name: &Name, code: &InviteCode) -> Result<(), Refusal> {
        let Some(blocked) = book.blocks(name, code) else { return Ok(()) };
        let (why, refusal) = match blocked {
            Blocked::QueueFull => (format!("{QUEUE_DEPTH} posts already wait"), Refusal::Busy),
            Blocked::CodeHeld => ("its invite is held by a post in flight".to_owned(), Refusal::Invite),
            Blocked::NameHeld => ("a post in flight holds the name".to_owned(), Refusal::Name),
        };
        self.log(&format!("{name}: a post refused: {why}"));
        Err(refusal)
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
            Err(refused @ SignUpRefused::Full) => {
                self.log(&format!("a sign-up refused: {refused}; the owner trims the file"));
                Err(SignUpRefusal::Failed)
            }
            Err(SignUpRefused::Io(e)) => {
                self.log(&format!("a sign-up could not be kept: {e}"));
                Err(SignUpRefusal::Failed)
            }
        }
    }

    fn admit(&self, post: &Post<'_>) -> Result<String, Refusal> {
        // The invite, first: an uninvited post learns nothing about names.
        let Some(code) = std::str::from_utf8(post.invite).ok().and_then(InviteCode::parse) else {
            self.log("a post refused: no invite code of the code's form");
            return Err(Refusal::Invite);
        };
        let invite = match invites::lookup(&self.state_dir, &code) {
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
            self.log(&format!("{name}: a post refused: the record, {refused}"));
            match refused {
                RecordRefused::NotARecord(_) => Refusal::Record,
                RecordRefused::PreviewKey { .. } => Refusal::Preview,
            }
        })?;
        // WHAT IS IN FLIGHT, under the book's short lock: a refusal here
        // costs no docker call.
        self.in_flight(&self.book(), &name, &code)?;
        // THE TRUTH ABOUT THE NAME: three reads under no lock of this
        // service's — a post waits on no provisioning — under one of the
        // looks' permits, given back as the reads end.
        let taken = {
            let Some(_looking) = Permit::take(&self.looks, MAX_LOOKS) else {
                self.log(&format!("{name}: a post refused: {MAX_LOOKS} posts already look at what stands"));
                return Err(Refusal::Busy);
            };
            names::taken(self.docker.as_ref(), &self.config.boards_dir, &name)
        };
        match taken {
            Ok(None) => {}
            Ok(Some(by)) => {
                self.log(&format!("{name}: a post refused: taken — {by}"));
                return Err(Refusal::Name);
            }
            Err(e) => {
                self.log(&format!("{name}: a post could not be judged: the look at the name: {e}"));
                return Err(Refusal::Failed);
            }
        }
        let token = names::unguessable().map_err(|e| {
            self.log(&format!("{name}: a post could not be admitted: {e}"));
            Refusal::Failed
        })?;
        // THE ADMISSION, under the book's lock: what is in flight checked
        // again — a post for this name or this code may have been admitted
        // while the reads ran — and the invite looked up again under the
        // same lock. A worker spends a code and then lets go of it, in that
        // order, so a code the book does not hold and the file holds issued
        // is one no board has spent; and the name is held from here, so no
        // second post for it is admitted while this one is in flight.
        let waiting = {
            let mut book = self.book();
            self.in_flight(&book, &name, &code)?;
            match invites::lookup(&self.state_dir, &code) {
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
            book.admit(Job { token: token.clone(), name: name.clone(), record, code, address: invite.address })
        };
        self.ready.notify_one();
        self.log(&format!("{name}: admitted; {waiting} waiting"));
        Ok(token)
    }

    fn status(&self, token: &str) -> Option<Shown> {
        let book = self.book();
        let post = book.map.post(token)?;
        Some(match post.state {
            PostState::Queued | PostState::Running => Shown::BeingMade,
            PostState::Live => Shown::Live(self.live_reply(&post.name, post.anchorless, token)),
            PostState::Failed => Shown::Failed,
        })
    }
}

#[cfg(test)]
mod tests;
