//! The flow: the [`Service`] the pages' desk is.
//!
//! It is a pool of workers, the name the unit of exclusion (the deployment
//! notes §4, steps 3 to 5; the provisioning record §2 and §5.2).
//!
//! **The post** ([`Service`]'s `Desk::admit`): the invite looked up — a code
//! the file holds issued; the name's grammar; the record admitted (D-5, D-6)
//! — each in process, before any docker call; then what is in flight, under
//! the book's short lock — the queue's depth ([`QUEUE_DEPTH`]; past it D-8,
//! "try again later"), the codes held and the names the posts in flight hold
//! — refused with no docker call, and the post's code then held for its look
//! ([`CodeLook`]), one look per code; then the truth about the name
//! (`names::taken`, D-4), three reads under no lock of this service's, at
//! most [`MAX_LOOKS`] posts' at once — past it D-8, "try again later", with
//! no docker call; then the status token minted, the look still held — D-8
//! where the OS gives no entropy; then the admission, under the book's lock
//! again: the look ended, and what is in flight checked again — a post for
//! this name may have been admitted while the reads ran, though none for
//! this code, which the look held — and the invite looked up again under the
//! same lock — a spend written since the post's first lookup, by a board gone
//! live on the code before the look held it, or by the operator's hand —
//! then the post queued, and D-7 answered with its status URL. A refused
//! post leaves nothing: no docker call past the truth's reads, no file, no
//! queue entry, no code held. A post never waits on a provisioning: no lock
//! it takes is held across one.
//!
//! **The name is the unit of exclusion.** A name is held from its admission
//! to its live or failed end (the status map's `holds`) — the lock per name,
//! an entry in the book that no thread waits on — and a second post for a
//! name in flight is refused (D-4) under the book's lock, the very lock that
//! admits — so no two posts for one name are ever in flight, and the worker
//! that takes a post owns its name alone to the end. No mutex is held over a
//! provisioning: two workers make two names at once.
//!
//! **The workers** ([`Service::work`]): `--workers` threads, each taking the
//! next queued post and running it to its end:
//!
//! 3. the truth about the name read again — a name taken since the post is
//!    not this post's (D-8); `volume_create`, the volume labelled as this
//!    service's; `run_claim`, the public origin configured (AUTH-4.57 (a),
//!    (b), (f));
//! 4. `sidecar_claim`, the record on its stdin, retried on exit 4 while the
//!    claim run's daemon is not yet listening ([`SIDECAR_WAIT`]); its data
//!    read (`sidecar`): the six lines are the claim, `claimed by …` on the
//!    volume this flow just made is residue — a failure — and any other
//!    exit or shape a failure, its stderr whole in the log; then `rm_force`
//!    the claim run;
//! 5. `run_serving`; the `/health` wait for the pair (`health`) — the
//!    first-start guard beside the proxy's own check (AUTH-4.57 (d)); then
//!    a route change under the one route lock, serial across every name:
//!    the snippet written (`caddy`, AUTH-4.57 (c)) and `caddy_reload` — so
//!    no reload lands between another name's snippet and its own reload,
//!    and, where the write or the reload fails, none between that snippet
//!    and the reload that undoes it: the lock is held on into the cleanup;
//!
//! then the status live, then the invite spent under the invite file's own
//! lock and its code let go of where the spend is answered, in that order,
//! then the mail handed to the sender's own thread, after the page and never
//! ahead of it, so a mail outage holds up no next post. The snippet stands
//! before the spend is written: a stop between the two leaves the board
//! routed — or routed at the proxy's next reload — and its invite issued,
//! which the next start names the board for and admits a post on again until
//! the operator marks it (`main`'s paragraph on the stop). A step that panics
//! is a failed step, and a cleanup that panics fails its post all the same: a
//! panic costs its post, never the worker.
//!
//! **The cleanup** (the provisioning record §5.2's decision table, D-8 made
//! literally true): on a failed step, what the flow made is undone in the
//! reverse of the order it was made — the snippet removed where its write
//! began, and Caddy reloaded where one stood or may stand, the route change's
//! undo under the route lock its write took and held since; `rm_force` where
//! a run may stand, its last lines logged first — the board's own daemon's
//! account of the failure, which the removal takes with the run; `volume_rm`
//! where the volume stands — and then, where anything was made, the truth
//! asked what stands under the name: the three reads a post makes
//! (`names::taken`), the ones D-8's "Nothing stands under your name" speaks
//! of, never the removals' answers.
//! The status is failed (D-8) and the invite not spent, so the person may
//! post again. By the table: `volume_create` failed — nothing; `run_claim`
//! failed — whatever run its `docker run` left, and the volume (the record's
//! row names the volume; its rule, `docker rm -f` whichever run stands,
//! takes the container a failed start leaves); the dark claim failed (exit 4
//! past the bound, 3, 1, 2, `claimed by`, any other exit or shape, or a
//! `docker` that could not run) — the claim run and the volume; `run_serving`
//! failed, or the pair never answered — the serving run and the volume; the
//! snippet's write failed — the snippet, where its rename landed, and a
//! reload, then the serving run and the volume; the reload failed — the
//! snippet and a reload, the serving run, the volume. A board whose claim
//! landed and whose route did not is removed with its volume: no route ever
//! existed — the route lock kept every other name's reload out while its
//! snippet stood, and its own reload, where one was made, failed — so no one
//! wrote to it, and a re-post claims a fresh volume with the same keys.
//!
//! **The named gap.** Where something still stands after the removals — a
//! removal that itself failed — the log says `INCOMPLETE` and names it, and
//! the truth then refuses re-posts (D-4) until the operator clears it; a
//! refused `rm -f` of a run that never stood, and a reload that fails, leave
//! nothing the truth reads, and the verdict is done.
//!
//! **The sweep at start** ([`Service::sweep`]; `serve` runs it once, its
//! address bound and before it serves): a stop mid-board before its
//! snippet's write leaves a volume, and perhaps a run, under a name with no
//! snippet, which the truth would read as taken for good — so every volume
//! under this service's label is listed, the listing named before it is
//! made, and each under a name of the grammar with no snippet is handed to
//! the cleanup itself as what a stop leaves, and so undone by the table's
//! last two rows, the truth asked what stands after; a name whose snippet
//! stands is left — and named where no line of the invite file is spent
//! under it, for a stop from its snippet's write until its spend leaves its
//! invite issued — a volume under no name of the grammar is logged and left,
//! and a listing that fails is logged and the sweep skipped — the sign-up
//! still serves. The snippet directory is the list of boards it spares: a
//! start over a directory emptier than the Engine's labelled volumes — a VM
//! restored with its volumes and not the directory, `--boards-dir` pointed
//! elsewhere — removes every board it lacks. Its precondition is the
//! operator's: one service per Docker host, for the label and the names are
//! the host's, and a second service would take the first's boards for
//! half-made; `serve` refuses one over the same state directory or on the
//! same port before its sweep. And it takes the service whole, by `&mut`, so
//! no post of this service's is in flight while it runs — a post's volume
//! stands with no snippet from its step 3 until its route change.
//!
//! **The desk's other two answers.** A sign-up (`Desk::sign_up`): the address
//! kept through `signups` and logged as kept or refused — never the
//! address — touching nothing of the book; and a status (`Desk::status`): a
//! query of the book's status map, a live post's page rendered by the one
//! renderer from the inputs [`Service`]'s `live_reply` gathers.
//!
//! **The log**, on stderr through [`Log`]: one line per step naming the name,
//! the step and each call's exit code, and the sidecar's stderr whole, which
//! names each record entry by its fingerprint and its label — never the
//! record whole or a key of it, a person's address, an invite code or a
//! status token (the provisioning record §4). A post is said as a worker
//! takes it, with how long it waited and the posts still waiting, and at its
//! end, live or failed, with how long its steps took; the `/health` wait as
//! it begins and at every fifteenth try without the pair, so no stretch of a
//! board's steps goes a minute unsaid — a silence that long is a `docker`
//! call that has not returned. A refusal for a held invite names what holds
//! it, and one for a full queue, or for the looks' cap, the posts that fill
//! it. A line a stranger can drive is said at a rate (`rates`): a refusal no
//! invite bounds at most once a minute, with the count of like ones since;
//! a failure met at every request — the invite file unread, the sign-up file
//! unkept, a look at a name not made — once as it starts and once as it
//! ends, with its count. A file a failure meets is named by its path.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::io;
use std::num::NonZeroU32;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;
#[cfg(test)]
use std::sync::atomic::AtomicU64;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use crate::caddy;
use crate::docker::Docker;
use crate::domain::Domain;
use crate::health::{self, Waited, HEALTH_WAIT};
use crate::invite_code::InviteCode;
use crate::invites::{self, Invite, InviteState};
use crate::name::Name;
use crate::names;
use crate::pages::{self, Desk, Post, Refusal, Shown, SignUpRefusal};
use crate::process::Exit;
use crate::rates::{counted, Edge, Stretch};
use crate::record::{self, Record, RecordRefused};
use crate::reply;
use crate::sender::{self, Log, Outbox, Sleep};
use crate::sidecar::{self, Answer, Failure};
use crate::signups::{SignUpRefused, SignUps, MAX_SIGNUPS_BYTES, SIGNUPS};
use crate::statedir::StateDir;
use crate::wait::Wait;

use status_map::{PostState, StatusMap};

/// The queue's depth: four posts waiting for a worker, whatever `--workers` is.
///
/// They are the ones the workers run apart — the provisioning record §5.2's
/// figure, priced there for one worker, for the pool as well; a fifth meets
/// D-8, "try again later". No flag sets it: a change to it is a design
/// decision's.
const QUEUE_DEPTH: usize = 4;

/// The dark claim's retry: thirty tries two seconds apart.
///
/// The tries go on while the sidecar answers exit 4 — the claim run's daemon
/// not yet listening.
const SIDECAR_WAIT: Wait = Wait { tries: NonZeroU32::new(30).expect("thirty is not zero"), interval: Duration::from_secs(2) };

/// The `/health` wait's progress line: every fifteenth try without the pair.
///
/// The lines come some half a minute apart — each try a `docker run --rm` of
/// the sidecar and a second's pause — so no stretch of a board's steps goes
/// a minute without a line: RUNBOOK §10 step 12 reads a minute's silence from
/// a board taken by a worker as a `docker` call that has not returned.
const HEALTH_PROGRESS: u32 = 15;

/// The looks' cap: four posts' looks at what stands under their names at once.
///
/// It is [`QUEUE_DEPTH`], the posts that can wait at once. A look is up to
/// two `docker` processes, Go programs of tens of megabytes each, and a post
/// refused D-4 off a container — the proxy's own, `caddy`, stands under its
/// name — leaves its code issued and unheld, so uncapped one issued code
/// would have the service run two for every connection open at once, for as
/// long as its holder looped. One code holds one of them at most — its
/// post's code held for the look ([`CodeLook`]) — or one holder's
/// concurrent posts would take all four, and every other person's post
/// would meet this cap. A post past it meets D-8, "try again later", with no
/// docker call.
const MAX_LOOKS: usize = QUEUE_DEPTH;

/// What the service is configured with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// `--boards-dir`: where the snippets live.
    pub boards_dir: PathBuf,
    /// `--suffix`: the domain every board's name is under.
    pub suffix: Domain,
}

/// One admitted post, waiting or running.
struct Job {
    token: String,
    name: Name,
    record: Record,
    code: InviteCode,
    address: String,
    /// The day its invite was issued, as the invite file's line holds it.
    ///
    /// It is the operator's locator for that line — said as the post is
    /// admitted, and again where its spend cannot be written — never its code
    /// or its address, which no log line carries.
    issued: String,
    /// When it was admitted.
    ///
    /// The line a worker takes it with says how long it waited.
    admitted_at: Instant,
}

/// The book, which the pages and the workers share under its own short lock.
///
/// It holds what is in flight — the posts waiting for a worker, and the
/// invite codes held, each by a post admitted (`admitted`) or by a post
/// looking at what stands under its name (`looking`), each code with what
/// holds it, for a refusal to name — and every post this process admitted,
/// by token, in flight or ended (the status map).
///
/// **The rules that tie them.** A post looking at what stands holds its code
/// until its admission or its refusal ([`CodeLook`]); a post admitted waits
/// with its token in the map and its code held; a post taken is running; a
/// post in flight, waiting or running, holds its name; a failed post lets its
/// code go at once, and a live one keeps it held until its spend is answered
/// — written, or the file found holding no such code issued, the operator's
/// hand having marked it or removed its line — and the worker lets it go
/// ([`Book::release`]); a spend that could not be written keeps it held; and
/// a new post is admitted only where none of a full queue, a held code and a
/// held name blocks it — the first of them in that order, as
/// [`Book::blocks`] answers, asked by the admitter under the lock it admits
/// under ([`Book::admit`]'s precondition).
struct Book {
    queue: VecDeque<Job>,
    map: StatusMap,
    /// The codes the posts admitted hold, each with its post's token.
    ///
    /// The token is the key the status map holds the post by, so what holds a
    /// code is read off the post itself: each from its post's admission until
    /// let go of — a failed post's at once, a live post's once its spend is
    /// answered ([`Book::release`]).
    admitted: HashMap<InviteCode, String>,
    /// The codes whose posts are looking at what stands under their names.
    ///
    /// Each is held with its post's name, as surely as one in `admitted`, from
    /// the post's in-flight check to its admission or its refusal, so the
    /// posts on one code hold one of the looks' permits at most.
    looking: HashMap<InviteCode, Name>,
}

/// What in flight refuses a new post.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Blocked {
    /// [`QUEUE_DEPTH`] posts already wait.
    QueueFull,
    /// The invite code is held, by the post for `by`, as `how` says.
    CodeHeld {
        /// The board the post that holds it is for.
        by: Name,
        /// How it holds it.
        how: Held,
    },
    /// A post in flight holds the name.
    NameHeld,
}

/// How a code is held, as its refusal says it.
///
/// The operator reads a code held for good — a live board's whose spend
/// could not be written — apart from one held for the moments a post is
/// judged or made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Held {
    /// By a post looking at what stands under its name ([`CodeLook`]).
    Looking,
    /// By a post in flight, waiting or running.
    InFlight,
    /// By a board gone live, until its spend is answered.
    ///
    /// It is held for the process's life, where the spend could not be
    /// written.
    Live,
}

impl Book {
    /// Returns the book at start: nothing in flight, the status map as rebuilt.
    fn new(map: StatusMap) -> Book {
        Book { queue: VecDeque::new(), map, admitted: HashMap::new(), looking: HashMap::new() }
    }

    /// Returns what refuses a new post for `name` under `code`, if anything.
    ///
    /// It is the first of a full queue, a held code and a held name — `None`
    /// where none does.
    fn blocks(&self, name: &Name, code: &InviteCode) -> Option<Blocked> {
        if self.queue.len() >= QUEUE_DEPTH {
            return Some(Blocked::QueueFull);
        }
        if let Some(token) = self.admitted.get(code) {
            let post = self.map.post(token).expect("`Book::admit` puts a post in the map before its code in `admitted`, and no post leaves the map");
            let how = if post.state == PostState::Live { Held::Live } else { Held::InFlight };
            return Some(Blocked::CodeHeld { by: post.name.clone(), how });
        }
        if let Some(by) = self.looking.get(code) {
            return Some(Blocked::CodeHeld { by: by.clone(), how: Held::Looking });
        }
        self.map.holds(name).then_some(Blocked::NameHeld)
    }

    /// Admits a post: its token in the map, its code held, the post queued.
    ///
    /// It answers with the posts now waiting.
    ///
    /// **Precondition.** The caller's, under the same lock as this call:
    /// nothing in flight blocks the post ([`Book::blocks`] answers `None` for
    /// its name and its code). It is the admitter's alone to check, and the
    /// book does not check it again.
    ///
    /// # Panics
    ///
    /// Panics where the post's token is not fresh: the map's own gate asserts
    /// it ([`StatusMap::admit`]), and it comes first, so a broken admission
    /// panics before the book changes — an admission is whole or not made.
    fn admit(&mut self, job: Job) -> usize {
        self.map.admit(job.token.clone(), job.name.clone(), job.record.anchorless());
        self.admitted.insert(job.code.clone(), job.token.clone());
        self.queue.push_back(job);
        self.queue.len()
    }

    /// Takes the next waiting post for a worker, marking it running.
    fn take(&mut self) -> Option<Job> {
        let job = self.queue.pop_front()?;
        self.map.set(&job.token, PostState::Running);
        Some(job)
    }

    /// Marks `token`'s post live: its page the live reply.
    ///
    /// Its code stays held until its spend is answered ([`Book::release`]).
    fn mark_live(&mut self, token: &str) {
        self.map.set(token, PostState::Live);
    }

    /// Lets `code` go: a new post may name it.
    ///
    /// A live post's goes once the file holds no such code issued, spent by
    /// this post's spend or by the operator's hand, or its line removed; a
    /// failed post's at once.
    fn release(&mut self, code: &InviteCode) {
        self.admitted.remove(code);
    }

    /// Marks `job`'s post failed: its page D-8, and its code let go of at once.
    ///
    /// The file still holds it issued, so the person may post again.
    fn mark_failed(&mut self, job: &Job) {
        self.map.set(&job.token, PostState::Failed);
        self.release(&job.code);
    }
}

/// A permit under a cap: taken where fewer than the cap are held.
///
/// It is the workspace's word for it, `skep-util`'s `Permit`, which this
/// crate's five dependencies leave out; it is given back when dropped — on
/// every return and every unwind alike, so no permit is ever kept by a look
/// that ended.
struct Permit<'a>(&'a AtomicUsize);

impl<'a> Permit<'a> {
    /// Takes a permit among `held`'s, where fewer than `cap` are held.
    ///
    /// It answers `None` where `cap` are.
    fn take(held: &'a AtomicUsize, cap: usize) -> Option<Permit<'a>> {
        held.try_update(Ordering::AcqRel, Ordering::Acquire, |n| (n < cap).then_some(n + 1)).ok().map(|_| Permit(held))
    }
}

impl Drop for Permit<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// A code's look: its post's code held in the book's `looking`.
///
/// It is held while its post reads what stands under its name — so one
/// invite takes one of the looks' permits at most, never all of them — and
/// let go of when dropped, on every return and every unwind alike, unless
/// the admission ended it first, under the lock it admits under.
struct CodeLook<'s> {
    book: &'s Mutex<Book>,
    code: Option<InviteCode>,
}

impl<'s> CodeLook<'s> {
    /// Begins the look, under the book's lock the caller holds.
    ///
    /// `book` is the content of `lock`, and the look begins once the in-flight
    /// check made under it has found nothing blocking the post for `name`: the
    /// code held in `looking`, the name beside it for a refusal to name, and
    /// the hold handed to the guard that lets it go.
    fn begin(lock: &'s Mutex<Book>, book: &mut Book, code: InviteCode, name: Name) -> CodeLook<'s> {
        book.looking.insert(code.clone(), name);
        CodeLook { book: lock, code: Some(code) }
    }

    /// Ends the look at the admission, under the book's lock the caller holds.
    ///
    /// The code goes out of `looking`, so the in-flight check made again there
    /// does not meet this post's own look; and it is taken from the guard, so
    /// its drop — after the lock is let go, by when a worker may have run this
    /// post and let its code go, and a later post's look may hold it — takes
    /// nothing back.
    fn end(mut self, book: &mut Book) {
        if let Some(code) = self.code.take() {
            book.looking.remove(&code);
        }
    }
}

impl Drop for CodeLook<'_> {
    fn drop(&mut self) {
        if let Some(code) = self.code.take() {
            self.book.lock().unwrap_or_else(|e| e.into_inner()).looking.remove(&code);
        }
    }
}

/// What a provisioning has made, or begun to make, for the cleanup to undo.
///
/// It holds what was made, and a making begun where its error can follow its
/// first act — the claim run's `docker run`, the snippet's write — or, as
/// the sweep builds it, what a stop mid-board may have left; and, once its
/// snippet's write has begun, the route lock that write took, so a failed
/// route change is undone under the lock it was made under. The cleanup
/// takes it apart whole and the sweep builds it whole, so a making added
/// here is a compile error at both until each says what it does with it.
#[derive(Debug, Default)]
struct Made<'s> {
    /// The board's volume, created.
    volume: bool,
    /// A run that may stand under the name.
    ///
    /// It is the claim run, from its `docker run`'s first act, then the
    /// serving run.
    run: bool,
    /// The snippet, from its write's first act: the route lock that write took.
    ///
    /// The write's error may come after its rename, the snippet standing; the
    /// lock is let go of once the reload succeeds, and otherwise held on into
    /// the cleanup, across the snippet's removal and the reload that undoes
    /// it.
    snippet: Option<MutexGuard<'s, ()>>,
}

/// Where a cleanup runs, and the word its log lines carry.
///
/// It runs on a failed step — the provisioning record §5.2's failure cleanup
/// — or at start, on a board a stop left half-made — the cleanup on start,
/// the sweep.
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

/// The lines said at a rate (`rates`): the ones a stranger can drive.
///
/// They are the edges of a failure met at every request while it stands —
/// said once as it starts, once as it ends, with its count — and the
/// stretches of a refusal no invite bounds — said at most once a minute, with
/// the count of like ones since.
#[derive(Debug, Default)]
struct Rated {
    /// The invite file unread at a post's lookup.
    invite_file: Edge,
    /// The sign-up file unkept: read or written, refused.
    signup_file: Edge,
    /// A post's look at the name not made.
    look: Edge,
    /// A post with no invite code of the code's form.
    unformed: Stretch,
    /// A post naming a code the invite file does not hold.
    unknown: Stretch,
    /// A post naming a code the invite file holds spent.
    spent: Stretch,
    /// A sign-up with no address by the rule.
    unaddressed: Stretch,
    /// A unit suite's clock.
    ///
    /// It holds what the suite has moved the instant every rate here is judged
    /// at on by, so a hold-down or a stretch passes with no wait.
    #[cfg(test)]
    advanced_ms: AtomicU64,
}

impl Rated {
    /// Returns the instant every rate here is judged at: the monotonic clock.
    ///
    /// In a unit suite, it adds what the suite has moved it on by.
    fn now(&self) -> Instant {
        let now = Instant::now();
        #[cfg(test)]
        let now = now + Duration::from_millis(self.advanced_ms.load(Ordering::Relaxed));
        now
    }

    /// Moves a unit suite's clock on by `by`.
    ///
    /// A hold-down or a stretch passes with no wait.
    ///
    /// # Panics
    ///
    /// Panics where `by` is more milliseconds than a `u64` holds.
    #[cfg(test)]
    fn advance(&self, by: Duration) {
        self.advanced_ms.fetch_add(u64::try_from(by.as_millis()).expect("a suite's step fits in u64 milliseconds"), Ordering::Relaxed);
    }
}

/// The service: the desk the pages ask, and the workers' shared state.
pub struct Service {
    config: Config,
    state_dir: StateDir,
    signups: SignUps,
    docker: Box<dyn Docker>,
    /// Where the follow-up mail is handed.
    ///
    /// It is `None` where no mail is configured.
    outbox: Option<Outbox>,
    log: Log,
    sleep: Sleep,
    /// The route lock: held across a route change, and nowhere else.
    ///
    /// A route change is a snippet's write and the reload that follows it,
    /// and where either fails, the lock is held on across the snippet's
    /// removal and the reload that undoes it — so route changes are serial
    /// across every name: no reload of another name's lands between a snippet
    /// and its own reload, nor loads a snippet whose own route change failed.
    route_lock: Mutex<()>,
    /// The book, under its short lock.
    ///
    /// It holds what is in flight, every post's state, and the rules that tie
    /// them.
    book: Mutex<Book>,
    /// Woken when a post is queued, for a worker waiting at the book.
    queued: Condvar,
    /// How many posts are looking at what stands under their names.
    ///
    /// They are at most [`MAX_LOOKS`].
    looks: AtomicUsize,
    /// The lines a stranger can drive, each said at its rate.
    rated: Rated,
}

impl Service {
    /// Returns the service, its status map rebuilt from the snippet directory.
    ///
    /// The service is over its configuration, its state directory, its runner
    /// and its outbox — `None` where no mail is configured.
    ///
    /// # Errors
    ///
    /// The one error: a snippet directory that cannot be read, which `serve`
    /// names and refuses to start on.
    pub fn new(config: Config, state_dir: StateDir, docker: Box<dyn Docker>, outbox: Option<Outbox>, log: Log, sleep: Sleep) -> io::Result<Service> {
        let map = StatusMap::rebuild(&config.boards_dir)?;
        let signups = SignUps::new(&state_dir);
        Ok(Service {
            config,
            state_dir,
            signups,
            docker,
            outbox,
            log,
            sleep,
            route_lock: Mutex::new(()),
            book: Mutex::new(Book::new(map)),
            queued: Condvar::new(),
            looks: AtomicUsize::new(0),
            rated: Rated::default(),
        })
    }

    /// Counts the boards that stood routed at start: the serving line's `live`.
    ///
    /// They are the names the status map was rebuilt with (Q5 (a)). A board
    /// made live since is not among them; whether a board is live now is what
    /// stands under its name ([`names::taken`]).
    pub fn routed_at_start_count(&self) -> usize {
        self.book().map.routed_at_start().len()
    }

    /// Runs the sweep at start, once, before the service serves.
    ///
    /// Every volume under this service's label is listed — the listing named
    /// on a line of its own before it is made, so an Engine that never answers
    /// leaves that line the start's last, naming the call that has not
    /// returned; each under a name of the grammar with no snippet is half-made
    /// — what a stop mid-board leaves — and is undone by [`Service::cleanup`],
    /// handed what such a stop leaves: the volume, and a run that may stand
    /// under the name. So the table's last two rows undo it — whichever run
    /// stands (`rm_force`), then the volume (`volume_rm`), each answer logged
    /// — and the truth is then asked what stands ([`Service::cleared`]): done,
    /// or `INCOMPLETE` naming what stands, the name then taken until the
    /// operator clears it. A name whose snippet stands is left — live, or its
    /// run stopped: `--restart on-failure` brings a run back from a failure of
    /// its own, and by Docker's documentation not from the Engine's restart or
    /// a reboot (RUNBOOK §10 step 12) — and so is a listed volume under no
    /// name of the grammar, logged. The listing's answer is logged as every
    /// call's is ([`Service::judged`]); one that fails skips the sweep, said
    /// on a line of its own with what the skip leaves taken: a listing failure
    /// must not take the sign-up down. A name whose snippet stands with no
    /// volume under the label — a route to no board, or a board made by hand
    /// — is said and left; so is a routed board under the label with no line
    /// of the invite file spent under it — a stop from its snippet's write
    /// until its spend, a spend that could not be written, or its spent line
    /// removed by hand — whose invite may still say issued, a post naming it
    /// admitted again until the operator marks it ([`invites::spent_names`]);
    /// and the sweep, where neither its listing nor the snippet directory's
    /// read skips it, ends on a line of its own — the volumes listed, the
    /// half-made among them, the boards cleared, the names left `INCOMPLETE`,
    /// the time it took — the start's figures in one place. It answers the
    /// boards cleared, for the serving line. The snippet directory is thus the
    /// list of boards it spares: a labelled volume whose snippet is gone is
    /// half-made to it, however long it has stood.
    ///
    /// **Precondition.** The operator's: one service per Docker host. The
    /// label marks every volume any `serve` on the host made, and a volume is
    /// half-made by this service's snippet directory alone — so a second
    /// service on the host would read the first's boards in flight, and under
    /// another `--boards-dir` its live boards too, as half-made, and remove
    /// them; the host's volume and container names are one namespace besides.
    /// Nothing in a volume tells two services apart; `serve` refuses a second
    /// service over the same state directory or on the same port before its
    /// sweep, and one under another of each is the operator's to keep.
    ///
    /// **Precondition, which its type keeps.** No post of this service's is in
    /// flight. A post's volume stands with no snippet from its step 3 until
    /// its route change, which the sweep would take for half-made and remove
    /// from under its worker; the sweep takes the service by `&mut`, so no
    /// worker and no connection thread holds the service while it runs —
    /// `serve` sweeps before it shares the service with either.
    pub fn sweep(&mut self) -> usize {
        let began = Instant::now();
        // The listing named before it is made: an Engine that does not answer
        // holds the start here, and this line, its last, names the call that
        // has not returned.
        self.log("sweep: listing the volumes under the label");
        let Some(listing) = self.judged("sweep: volumes", self.docker.labelled_volumes()) else {
            self.log(
                "sweep: the volumes under the label could not be listed; the sweep is skipped — a board a stop left half-made stays taken until a start whose listing answers: restart once `docker volume ls` answers as the service's user",
            );
            return 0;
        };
        let labelled = match names::labelled(&listing.stdout, &self.config.boards_dir) {
            Ok(labelled) => labelled,
            Err(e) => {
                self.log(&format!(
                    "sweep: the snippet directory could not be read: {e} — {}; the sweep is skipped — a board a stop left half-made stays taken until a start that reads it: restart once it reads as the service's user",
                    self.config.boards_dir.display()
                ));
                return 0;
            }
        };
        for listed in &labelled.ungrammatical {
            self.log(&format!("sweep: a volume under the label is under no name of the grammar, left: {listed}"));
        }
        // A snippet with no volume under the label: a name the rebuild found
        // routed that the listing holds no volume for — a route to no board,
        // its name taken for good, or a board made by hand, outside the label
        // — said, for the operator to tell which; the sweep leaves it.
        let unbacked: Vec<Name> = self.book().map.routed_at_start().iter().filter(|name| !labelled.routed.contains(name)).cloned().collect();
        for name in &unbacked {
            self.log(&format!("{name}: its snippet stands with no volume under the label — a route to no board, or a board made by hand: `docker volume inspect {name}` tells which"));
        }
        // A routed board with no invite spent under it: one this service made
        // — its volume under the label — whose spend a stop cut off after its
        // snippet's write, or which could not be written, or whose spent line
        // a hand removed, so the invite its post named may still say issued,
        // and a post naming it would make a second board on one invite: said
        // before the service serves, for the operator to mark.
        match invites::spent_names(&self.state_dir) {
            Ok(spent) => {
                for name in labelled.routed.iter().filter(|name| !spent.contains(name.to_string().as_str())) {
                    self.log(&format!(
                        "{name}: routed at start with no invite line spent under it — a stop between its snippet's write and its spend, a spend that could not be written, or its spent line removed by hand: the invite its post named may still say issued, and a post naming it is admitted again until the operator marks it spent under {name} (RUNBOOK §10 step 11), its issue date on the `{name}: admitted` line the log holds from before this start"
                    ));
                }
            }
            Err(e) => self.log(&format!("sweep: the invite file {} could not be read: {e}; the boards routed at start are not held against its spent lines", invites::path(&self.state_dir).display())),
        }
        let (mut swept, mut incomplete) = (0, Vec::new());
        for name in &labelled.half_made {
            self.log(&format!("{name}: half-made at start (a volume, no snippet) — removing"));
            // What a stop mid-board leaves — the volume, and a run that may
            // stand under the name — undone by the cleanup: its table's last
            // two rows, then the truth asked what stands.
            if self.cleanup(name, Made { volume: true, run: true, snippet: None }, CleanupOn::Start) {
                swept += 1;
            } else {
                incomplete.push(name.to_string());
            }
        }
        let listed = labelled.half_made.len() + labelled.routed.len() + labelled.ungrammatical.len();
        let left = if incomplete.is_empty() { String::new() } else { format!("; left INCOMPLETE: {}", incomplete.join(", ")) };
        self.log(&format!(
            "sweep: {} under the label, {} of them half-made and {swept} cleared{left}; in {} ms",
            counted(listed as u64, "volume", "volumes"),
            labelled.half_made.len(),
            began.elapsed().as_millis()
        ));
        swept
    }

    /// Runs one worker: the next post waited for and provisioned, forever.
    ///
    /// The post's name is the worker's alone until the post ends live or
    /// failed, for no second post for a name in flight is ever admitted.
    /// `serve` runs `--workers` of these over one service.
    pub fn work(&self) -> ! {
        loop {
            let job = {
                let mut book = self.book();
                loop {
                    if let Some(job) = book.take() {
                        break job;
                    }
                    book = self.queued.wait(book).unwrap_or_else(|e| e.into_inner());
                }
            };
            self.provision(job);
        }
    }

    /// Provisions the next queued post now, on this thread.
    ///
    /// It answers `false` where none waits: one worker's one turn, as a unit
    /// suite drives it.
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

    /// Provisions one post on the worker that owns its name.
    ///
    /// The steps run, then live — the route lock let go of first — and the
    /// mail after it; or the post is cleaned up, the route lock held on into
    /// the cleanup where the steps took it, and no mail. A step or a cleanup
    /// that panics costs this post alone, never the worker, which the pool
    /// made at start and never makes again: a step that panics is a failed
    /// step, what `made` recorded undone and a making whose record the panic
    /// cut off left standing, as a stop mid-board leaves one; a cleanup that
    /// panics leaves what it had not undone standing, logged `INCOMPLETE`; and
    /// the post fails either way, its code let go of. The post's board is the
    /// worker thread's for its length ([`sender::on_board`]), so a panic's one
    /// line names it.
    fn provision(&self, job: Job) {
        let name = job.name.clone();
        sender::on_board(&name, || self.provision_on_board(job));
    }

    /// Does [`Service::provision`]'s work, its board the thread's.
    fn provision_on_board(&self, job: Job) {
        let name = &job.name;
        // The post's start, said with how long it waited and how many wait
        // behind it: a board `taken by a worker` with no `LIVE` or `FAILED`
        // after it is one being made — or one whose `docker` call has not
        // returned — and never one still queued.
        let taken_at = Instant::now();
        let waiting = self.book().queue.len();
        self.log(&format!("{name}: taken by a worker {} ms after its admission; {waiting} still waiting", taken_at.saturating_duration_since(job.admitted_at).as_millis()));
        let mut made = Made::default();
        // `made` stands outside the catch, with the route lock it may hold,
        // so a panicking step's makings are undone under that lock as after
        // any failed step. AssertUnwindSafe, and sound: `made` changes by
        // whole assignments alone — the claim run and the snippet recorded
        // from their first acts, the volume once made; every lock is taken
        // poison-recovering; and the runner keeps nothing a call can leave
        // half-changed, `Docker`'s own obligation.
        let stepped = catch_unwind(AssertUnwindSafe(|| self.steps(&job, &mut made))).unwrap_or(Err("a step that panicked"));
        match stepped {
            Ok(()) => {
                // The route change is done: its lock let go of before the
                // spend and the mail, which change no route.
                drop(made);
                self.book().mark_live(&job.token);
                self.log(&format!("{name}: LIVE at {}, {} ms after a worker took the post", name.origin(&self.config.suffix), taken_at.elapsed().as_millis()));
                let spend = invites::spend(&self.state_dir, &job.code, name);
                match &spend {
                    Ok(true) => self.log(&format!("{name}: the invite is spent")),
                    Ok(false) => self.log(&format!("{name}: the invite was not found issued at the spend; the board stands")),
                    Err(e) => self.log(&format!(
                        "{name}: the invite could not be marked spent ({e}); this process refuses it until it ends, and the next start admits a post on it until it is marked — mark it spent by hand, before any restart: the line issued {} in {} to the person who asked for {name} (RUNBOOK §10 step 11)",
                        job.issued,
                        invites::path(&self.state_dir).display()
                    )),
                }
                // The code is let go of after the spend is answered — written,
                // or the file found holding no such code issued — so a post
                // that finds the book not holding it finds the file holding
                // no such code issued. A spend that could not be written keeps
                // its code held for the process's life: the file may still say
                // issued.
                if spend.is_ok() {
                    self.book().release(&job.code);
                }
                // The mail, last: after the page, never ahead of it.
                self.hand_over_mail(job);
            }
            Err(step) => {
                self.log(&format!("{name}: FAILED at {step}, {} ms after a worker took the post", taken_at.elapsed().as_millis()));
                if catch_unwind(AssertUnwindSafe(|| self.cleanup(name, made, CleanupOn::Failure))).is_err() {
                    self.log(&format!("{name}: cleanup: INCOMPLETE — the cleanup panicked, and what it had not undone stands until the operator clears it"));
                }
                self.book().mark_failed(&job);
            }
        }
    }

    /// Runs steps 3 to 5, in order.
    ///
    /// The first that fails is named, and `made` says what the cleanup undoes
    /// — from the snippet's write on, under the route lock it holds.
    ///
    /// # Errors
    ///
    /// The name of the first step that fails: the second look at the name,
    /// `volume_create`, `run_claim`, the dark claim, `rm_force`,
    /// `run_serving`, the `/health` wait, the snippet's write or
    /// `caddy_reload`.
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
        // The claim run is the cleanup's from its `docker run`'s first act: a
        // `docker run` makes its container and then starts it, so one that
        // fails can leave the container standing — holding the volume, whose
        // removal it then refuses — as the serving run's can. A
        // `docker rm -f` of a run that never stood leaves nothing the truth
        // reads, and the name's grammar keeps it from naming another
        // container.
        made.run = true;
        self.done(name, "run_claim", docker.run_claim(name))?;
        // 4. The dark claim, then the claim run removed — where the removal
        // fails, the claim run stands and the cleanup removes it.
        self.dark_claim(job)?;
        self.done(name, "rm_force", docker.rm_force(name))?;
        // 5. The serving run: `made.run` stays set across it, for its
        // `docker run` too can fail with its container made (the table's row:
        // the serving run and the volume).
        self.done(name, "run_serving", docker.run_serving(name))?;
        // The `/health` wait, said as it begins with its bound, at every
        // [`HEALTH_PROGRESS`]th try without the pair with what that try saw,
        // and at its end, each with the time into it but where `docker`
        // could not run: the wait is the steps' longest, and a board taken
        // by a worker is never a minute unsaid in it.
        let waiting_from = Instant::now();
        self.log(&format!("{name}: health: waiting for the pair, at most {} tries {} ms apart", HEALTH_WAIT.tries, HEALTH_WAIT.interval.as_millis()));
        let progress = |at: u32, exit: &Exit| {
            if at.is_multiple_of(HEALTH_PROGRESS) && at < HEALTH_WAIT.tries.get() {
                let seen = if exit.success() { health::pair_said(&exit.stdout) } else { format!("exit {}", exit.said()) };
                self.log(&format!("{name}: health: no pair yet at try {at} of {}, {} ms into the wait: {seen}", HEALTH_WAIT.tries, waiting_from.elapsed().as_millis()));
            }
        };
        match health::wait(docker, name, HEALTH_WAIT, self.sleep.as_ref(), &progress) {
            Ok(Waited::Paired { at }) => self.log(&format!("{name}: health: the pair answered at try {at} of {}, {} ms into the wait", HEALTH_WAIT.tries, waiting_from.elapsed().as_millis())),
            Ok(Waited::GaveUp { last }) => {
                self.log(&format!("{name}: health: no pair after {} tries, {} ms into the wait (the last exit {})", HEALTH_WAIT.tries, waiting_from.elapsed().as_millis(), last.said()));
                // What the last try saw: the pair as the board answered it,
                // where it answered, and the sidecar's stderr whole — a claim
                // not on the volume reads apart from local trust on, and an
                // unanswered dial names itself.
                if last.success() {
                    self.log(&format!("{name}: health: the last body's pair: {}", health::pair_said(&last.stdout)));
                }
                for line in String::from_utf8_lossy(&last.stderr).lines() {
                    self.log(&format!("{name}: health: {line}"));
                }
                return Err("the /health wait");
            }
            Err(e) => {
                self.log(&format!("{name}: health: docker could not run: {e}"));
                return Err("the /health wait");
            }
        }
        // A route change: the snippet's write and the reload under the route
        // lock, which `made` holds from the write's first act — the write's
        // error may come after its rename, the snippet standing — so no
        // reload of another name's lands between this snippet and its own
        // reload, and where either fails, the cleanup undoes the snippet
        // under the same lock.
        made.snippet = Some(self.route_lock());
        if let Err(e) = caddy::write(&self.config.boards_dir, name, &self.config.suffix) {
            self.log(&format!("{name}: snippet: the write failed: {e} — {}", caddy::snippet_path(&self.config.boards_dir, name).display()));
            return Err("the snippet's write");
        }
        self.log(&format!("{name}: snippet: written"));
        self.done(name, "caddy_reload", caddy::reload(docker))?;
        Ok(())
    }

    /// Runs step 4, the sidecar, over [`SIDECAR_WAIT`].
    ///
    /// It runs until the sidecar answers other than exit 4, or the bound
    /// passes; its stderr is logged whole every try.
    ///
    /// # Errors
    ///
    /// `the dark claim`: a `docker` that could not run, a `claimed by` on the
    /// volume this flow made, any failure the read names but exit 4, or exit 4
    /// past the bound — its last exit 4 then the step's failure.
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

    /// Logs and judges one call's answer, each line opening `prefix`.
    ///
    /// The prefix is `<name>: <step>` in a step, `<name>: <cleanup|sweep>:
    /// <step>` in a removal, `sweep: volumes` for the sweep's listing: exit 0
    /// is logged and the answer kept; any other exit is logged with its stderr
    /// whole, or a `docker` that could not run logged — each `None`.
    fn judged(&self, prefix: &str, answered: io::Result<Exit>) -> Option<Exit> {
        match answered {
            Ok(exit) if exit.success() => {
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

    /// Judges one step's call done: exit 0 goes on.
    ///
    /// # Errors
    ///
    /// `step`, failing the step, on any other exit or a `docker` that could
    /// not run.
    fn done(&self, name: &Name, step: &'static str, answered: io::Result<Exit>) -> Result<Exit, &'static str> {
        self.judged(&format!("{name}: {step}"), answered).ok_or(step)
    }

    /// Undoes what was made, on a failure or at start ([`CleanupOn`]).
    ///
    /// It undoes in reverse — the snippet under the route lock its write took,
    /// let go of once its reload, where one is owed, is made, then the run,
    /// its last lines logged first where a step failed ([`Service::run_said`]),
    /// then the volume, each removal logged and the next still tried — and
    /// then comes the verdict, [`Service::cleared`]: the truth about names
    /// asked what stands, never the removals' answers. It answers `true` where
    /// the name is cleared: the look finds nothing standing, or no look is
    /// owed, nothing having been made. `made` is taken apart whole, so a
    /// making added to [`Made`] is a compile error here until it is undone.
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
            let reload_owed = match caddy::remove(&self.config.boards_dir, name) {
                Ok(true) => {
                    self.log(&format!("{name}: {on}: snippet: removed"));
                    true
                }
                Ok(false) => {
                    self.log(&format!("{name}: {on}: snippet: none stood"));
                    false
                }
                Err(e) => {
                    self.log(&format!("{name}: {on}: snippet: not removed: {e} — {}", caddy::snippet_path(&self.config.boards_dir, name).display()));
                    true
                }
            };
            if reload_owed {
                self.undone(name, on, "caddy_reload", caddy::reload(docker));
            }
        }
        // A failed run read before it is removed: the board's daemon says on
        // its own stream why it never listened or never paired, and `rm -f`
        // takes that stream with the run — so its last lines are logged
        // first. On a failure alone: the sweep's runs are a stop's leavings,
        // no failure's.
        if run && on == CleanupOn::Failure {
            self.run_said(name, docker.run_logs(name));
        }
        if run {
            self.undone(name, on, "rm_force", docker.rm_force(name));
        }
        if volume {
            self.undone(name, on, "volume_rm", docker.volume_rm(name));
        }
        !made_anything || self.cleared(name, on)
    }

    /// Logs one removal's call — a making undone — under `on`'s word.
    ///
    /// It is logged as [`Service::judged`] logs it, and nothing is concluded
    /// from its answer: what stands after the removals is
    /// [`Service::cleared`]'s to ask.
    fn undone(&self, name: &Name, on: CleanupOn, step: &str, answered: io::Result<Exit>) {
        self.judged(&format!("{name}: {on}: {step}"), answered);
    }

    /// Logs a failed run's last lines, before the cleanup removes the run.
    ///
    /// Each is `<name>: cleanup: the run said: <line>` — its stderr's, the
    /// board's daemon's own stream, then its stdout's — or the log says that
    /// it said nothing; a read that fails is logged as a removal's answer is.
    /// The board's daemon never saw an invite code, a status token or a
    /// person's address, so none is in what it said.
    fn run_said(&self, name: &Name, answered: io::Result<Exit>) {
        match answered {
            Ok(exit) if exit.success() => {
                let (stderr, stdout) = (String::from_utf8_lossy(&exit.stderr), String::from_utf8_lossy(&exit.stdout));
                let mut said = false;
                for line in stderr.lines().chain(stdout.lines()) {
                    self.log(&format!("{name}: cleanup: the run said: {line}"));
                    said = true;
                }
                if !said {
                    self.log(&format!("{name}: cleanup: the run said nothing"));
                }
            }
            other => self.undone(name, CleanupOn::Failure, "run_logs", other),
        }
    }

    /// Returns the verdict after the removals: whether the name is cleared.
    ///
    /// On a failure or at start, it is asked of the truth about names itself
    /// ([`names::taken`], the three reads a post makes) and never read off the
    /// removals' answers — a refused `rm -f` may be of a run that never stood,
    /// and a reload removes nothing the truth reads — then logged under `on`'s
    /// word: done; or `INCOMPLETE` naming what stands, the operator's to clear
    /// — a volume, which the truth reads only where no snippet stands, so
    /// half-made to the next start's sweep, which removes it too; or
    /// `INCOMPLETE` naming the look that could not be made — its source,
    /// `docker` or the snippet directory, in its words ([`names::taken`]) —
    /// and the act once one can be. It answers `true` where nothing stands.
    /// The reads are the post's own, an inspect's non-zero exit "not standing"
    /// whatever its reason: an Engine that cannot be reached reads here as
    /// nothing standing, as it does at a post, and the removals' lines logged
    /// above the verdict then name the Engine; a volume so left with no
    /// snippet, and any run under its name, is the next start's sweep's.
    fn cleared(&self, name: &Name, on: CleanupOn) -> bool {
        match names::taken(self.docker.as_ref(), &self.config.boards_dir, name) {
            Ok(None) => {
                self.log(&format!("{name}: {on}: done — nothing stands under the name"));
                true
            }
            Ok(Some(by)) => {
                let swept = if by == names::TakenBy::Volume { ", or the next start's sweep removes it" } else { "" };
                self.log(&format!("{name}: {on}: INCOMPLETE — {by}, and the name refuses posts (D-4) until the operator clears it{swept}"));
                false
            }
            Err(e) => {
                self.log(&format!(
                    "{name}: {on}: INCOMPLETE — the look at what stands could not be made: {e}; what stands under the name is the operator's to clear once a look can be made (RUNBOOK §10 step 9), a volume with no snippet the next start's sweep's"
                ));
                false
            }
        }
    }

    /// Hands the live reply to the outbox, where mail is configured.
    ///
    /// It is handed once the status is live, for the sender's own thread to
    /// send; the job ends here, its name and address going with the mail.
    fn hand_over_mail(&self, job: Job) {
        let Some(outbox) = &self.outbox else { return };
        let reply = self.live_reply(&job.name, job.record.anchorless(), &job.token);
        outbox.hand_over(job.name, job.address, reply);
    }

    /// Returns the live reply of a post, from what the one renderer is given.
    ///
    /// The one renderer, `reply::text`, is given the board's public origin,
    /// the record's anchorless fact and the post's status URL — gathered in
    /// this one place for the status page and the mail alike, so the two
    /// cannot say two things.
    fn live_reply(&self, name: &Name, anchorless: bool, token: &str) -> String {
        reply::text(&name.origin(&self.config.suffix), anchorless, &pages::status_url(&self.config.suffix, token))
    }

    /// Checks what is in flight, under the book's lock the caller holds.
    ///
    /// What the book says blocks the post is logged and refused, no docker
    /// call made. The line names what fills the queue, its posts in order, and
    /// what holds the code: a post looking at what stands, a post in flight,
    /// or a board gone live until its spend is answered — held for good where
    /// that spend could not be written, the operator's act then named.
    ///
    /// # Errors
    ///
    /// What the book says blocks the post: the queue full (D-8, "try again
    /// later"), the code held (the invite's refusal), the name held by a post
    /// in flight (D-4).
    fn in_flight(&self, book: &Book, name: &Name, code: &InviteCode) -> Result<(), Refusal> {
        let Some(blocked) = book.blocks(name, code) else { return Ok(()) };
        let (why, refusal) = match blocked {
            Blocked::QueueFull => {
                let waiting: Vec<String> = book.queue.iter().map(|job| job.name.to_string()).collect();
                (format!("{QUEUE_DEPTH} posts already wait: {}", waiting.join(", ")), Refusal::Busy)
            }
            Blocked::CodeHeld { by, how: Held::Looking } => (format!("its invite is held by the post for {by}, looking at what stands under its name"), Refusal::Invite),
            Blocked::CodeHeld { by, how: Held::InFlight } => (format!("its invite is held by the post for {by}, in flight"), Refusal::Invite),
            Blocked::CodeHeld { by, how: Held::Live } => (
                format!("its invite is held by {by}'s board, live, until its spend is answered — where the log says it could not be marked spent, mark it by hand (RUNBOOK §10 step 11)"),
                Refusal::Invite,
            ),
            Blocked::NameHeld => ("a post in flight holds the name".to_owned(), Refusal::Name),
        };
        self.log(&format!("{name}: a post refused: {why}"));
        Err(refusal)
    }

    /// Says a refusal no invite bounds through its stretch ([`Stretch`]).
    ///
    /// It is said at most once a minute, with the count of like ones since —
    /// `line` built only where it is said.
    fn say_once_a_stretch(&self, stretch: &Stretch, line: impl FnOnce() -> String) {
        if let Some(line) = stretch.said(self.rated.now(), line) {
            self.log(&line);
        }
    }

    /// Returns the line refusing a code the invite file does not hold.
    ///
    /// It names the file by its path and how many invites it holds issued, so
    /// the operator who minted into one file reads whether the service reads
    /// the same — the count read here, only where the line is said.
    fn not_in_the_file(&self) -> String {
        let path = invites::path(&self.state_dir);
        match invites::issued_count(&self.state_dir) {
            Ok(issued) => format!("a post refused: its invite code is not in {}, which holds {} issued", path.display(), counted(issued as u64, "invite", "invites")),
            Err(e) => format!("a post refused: its invite code is not in {}, whose invites could not be counted: {e}", path.display()),
        }
    }

    /// Says the invite file unread at a post's lookup, at the failure's edge.
    ///
    /// `prefix` is the post's `<name>: ` where the post has one. The edge
    /// ([`Edge`]) says it once as it starts, with the file's path, the cause
    /// and what it refuses; every post it refuses after is counted.
    fn invite_file_unread(&self, prefix: &str, e: &io::Error) {
        if self.rated.invite_file.met(self.rated.now()) {
            self.log(&format!(
                "{prefix}a post could not be judged: the invite file {}: {e}; every post is refused until it reads again — said once, and again once it does",
                invites::path(&self.state_dir).display()
            ));
        }
    }

    /// Says the invite file read at a post's lookup: its failure's end.
    ///
    /// The end is said where a failure stood and its last post refused is a
    /// hold-down past, with the posts it refused.
    fn invite_file_reads(&self) {
        if let Some(ended) = self.rated.invite_file.passed(self.rated.now()) {
            self.log(&format!("the invite file {} reads again: {} could not be judged while it did not{}", invites::path(&self.state_dir).display(), ended.count("post", "posts"), ended.across()));
        }
    }
}

impl Desk for Service {
    fn sign_up(&self, address: &[u8]) -> Result<(), SignUpRefusal> {
        let path = self.state_dir.file(SIGNUPS);
        match self.signups.append(address) {
            Ok(kept) => {
                if kept.refused_at_cap > 0 {
                    self.log(&format!("the sign-up file takes sign-ups again: {} refused while it stood at its cap", kept.refused_at_cap));
                }
                if let Some(ended) = self.rated.signup_file.passed(self.rated.now()) {
                    self.log(&format!("the sign-up file {} keeps sign-ups again: {} could not be kept while it did not{}", path.display(), ended.count("sign-up", "sign-ups"), ended.across()));
                }
                // The file's fill, said at every sign-up kept: it is read
                // filling before a sign-up meets its cap.
                self.log(&format!("a sign-up kept; the file holds {} of its {MAX_SIGNUPS_BYTES} bytes", kept.held));
                Ok(())
            }
            // A refusal no invite bounds: a stranger's to make at a
            // request's rate, so said once a stretch with its count.
            Err(SignUpRefused::NotAnAddress) => {
                self.say_once_a_stretch(&self.rated.unaddressed, || "a sign-up refused: no address".to_owned());
                Err(SignUpRefusal::NotAnAddress)
            }
            // The cap, said once for its stretch — at its first refusal — and
            // its end once, at the next sign-up kept: a stranger's stream of
            // sign-ups against a full file is two lines, never a line each.
            Err(refused @ SignUpRefused::Full { refused_before: 0 }) => {
                self.log(&format!("a sign-up refused: {refused}; every sign-up is refused until the owner trims it (RUNBOOK §10 step 11) — said once, and again when one is kept"));
                Err(SignUpRefusal::Failed)
            }
            Err(SignUpRefused::Full { .. }) => Err(SignUpRefusal::Failed),
            // The file unkept, met at every sign-up while it stands: said at
            // its edge, once as it starts and once, with its count, as it
            // ends.
            Err(SignUpRefused::Io(e)) => {
                if self.rated.signup_file.met(self.rated.now()) {
                    self.log(&format!(
                        "a sign-up could not be kept: the sign-up file {}: {e}; every sign-up is refused until the file can be read and replaced again, by the service's user on a filesystem with room — said once, and again once one is kept",
                        path.display()
                    ));
                }
                Err(SignUpRefusal::Failed)
            }
        }
    }

    fn admit(&self, post: &Post<'_>) -> Result<String, Refusal> {
        // The invite, first: an uninvited post learns nothing about names.
        // Its refusals are a stranger's to make at a request's rate, so each
        // kind is said once a stretch with its count; the file unread, met
        // at every post while it stands, at its edges.
        let Some(code) = std::str::from_utf8(post.invite).ok().and_then(InviteCode::parse) else {
            self.say_once_a_stretch(&self.rated.unformed, || "a post refused: no invite code of the code's form".to_owned());
            return Err(Refusal::Invite);
        };
        let looked_up = invites::lookup(&self.state_dir, &code);
        if looked_up.is_ok() {
            self.invite_file_reads();
        }
        let (address, issued) = match looked_up {
            Ok(Some(Invite { address, state: InviteState::Issued { date }, .. })) => (address, date),
            Ok(Some(Invite { state: InviteState::Spent { name: spent, date }, .. })) => {
                self.say_once_a_stretch(&self.rated.spent, || format!("a post refused: its invite was spent under {spent} on {date}"));
                return Err(Refusal::Invite);
            }
            Ok(None) => {
                self.say_once_a_stretch(&self.rated.unknown, || self.not_in_the_file());
                return Err(Refusal::Invite);
            }
            Err(e) => {
                self.invite_file_unread("", &e);
                return Err(Refusal::Failed);
            }
        };
        let name = Name::parse(post.name).map_err(|refused| {
            self.log(&format!("a post refused: {refused}"));
            Refusal::Name
        })?;
        let record = record::admit(post.record).map_err(|refused| {
            self.log(&format!("{name}: a post refused: the record, {refused}"));
            match refused {
                RecordRefused::NotARecord(_) | RecordRefused::UndecodableKey | RecordRefused::TooManyKeys => Refusal::Record,
                RecordRefused::PreviewKey { .. } => Refusal::Preview,
            }
        })?;
        // What is in flight, under the book's short lock: a refusal here
        // costs no docker call. Passed, the post's code is held for its look
        // — one look per code — until the admission or the refusal lets it
        // go.
        let look = {
            let mut book = self.book();
            self.in_flight(&book, &name, &code)?;
            CodeLook::begin(&self.book, &mut book, code.clone(), name.clone())
        };
        // The truth about the name: three reads under no lock of this
        // service's — a post waits on no provisioning — under one of the
        // looks' permits, given back as the reads end. Past the cap, the
        // refusal names the posts whose invites a look holds — the four with
        // a permit, and any between its look and its admission — this one's
        // own left out.
        let taken = {
            let Some(_permit) = Permit::take(&self.looks, MAX_LOOKS) else {
                let mut looking: Vec<String> = self.book().looking.iter().filter(|(held, _)| *held != &code).map(|(_, by)| by.to_string()).collect();
                looking.sort();
                self.log(&format!("{name}: a post refused: {MAX_LOOKS} posts already look at what stands: {}", looking.join(", ")));
                return Err(Refusal::Busy);
            };
            names::taken(self.docker.as_ref(), &self.config.boards_dir, &name)
        };
        // A look not made is met at every post while its cause stands — a
        // `docker` that cannot be run, a snippet directory that cannot be
        // searched — so it is said at its edges: once as it starts, and once,
        // with the posts it refused, as a look is made again.
        match taken {
            Ok(found) => {
                if let Some(ended) = self.rated.look.passed(self.rated.now()) {
                    self.log(&format!("a look at a name is made again: {} could not be judged while none was{}", ended.count("post", "posts"), ended.across()));
                }
                if let Some(by) = found {
                    self.log(&format!("{name}: a post refused: taken — {by}"));
                    return Err(Refusal::Name);
                }
            }
            Err(e) => {
                if self.rated.look.met(self.rated.now()) {
                    self.log(&format!("{name}: a post could not be judged: the look at the name: {e}; every post is refused until a look is made — said once, and again once one is"));
                }
                return Err(Refusal::Failed);
            }
        }
        // The status token: drawn from the OS before the admission, off the
        // book's short lock, the look still held — so a draw the OS refuses
        // answers D-8 and lets the code go as any refusal does.
        let token = names::unguessable().map_err(|e| {
            self.log(&format!("{name}: a post could not be admitted: {e}"));
            Refusal::Failed
        })?;
        // The admission, under the book's lock: the look ended, then what is
        // in flight checked again, `Book::admit`'s precondition discharged
        // under the lock it admits under — a post for this name may have
        // been admitted while the reads ran, though none for this code, which
        // the look held — and the invite looked up again under the same lock.
        // A worker spends a code and then lets go of it, in that order, so a
        // code the book does not hold and the file holds issued is one no
        // board has spent; and the name is held from here, so no second post
        // for it is admitted while this one is in flight.
        let (waiting, issued_on) = {
            let mut book = self.book();
            look.end(&mut book);
            self.in_flight(&book, &name, &code)?;
            let again = invites::lookup(&self.state_dir, &code);
            if again.is_ok() {
                self.invite_file_reads();
            }
            match again {
                Ok(Some(Invite { state: InviteState::Issued { .. }, .. })) => {}
                Ok(Some(Invite { state: InviteState::Spent { name: spent, .. }, .. })) => {
                    self.log(&format!("{name}: a post refused: its invite was spent under {spent} while the post was judged"));
                    return Err(Refusal::Invite);
                }
                Ok(None) => {
                    self.log(&format!("{name}: a post refused: its invite left the invite file while the post was judged"));
                    return Err(Refusal::Invite);
                }
                Err(e) => {
                    self.invite_file_unread(&format!("{name}: "), &e);
                    return Err(Refusal::Failed);
                }
            }
            let issued_on = issued.clone();
            (book.admit(Job { token: token.clone(), name: name.clone(), record, code, address, issued, admitted_at: Instant::now() }), issued_on)
        };
        self.queued.notify_one();
        // The admission, said with the posts now waiting and its invite's
        // issue date — the invite file's line it will spend, by the one
        // figure of it a log line may carry.
        self.log(&format!("{name}: admitted; {waiting} waiting; its invite issued {issued_on}"));
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

// The book's status map: this process's posts by token, and the names
// routed at start.
mod status_map;

#[cfg(test)]
mod tests;
