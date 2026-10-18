//! The pages, and the requests they answer over `skep_http`.
//!
//! **The pages** (the deployment notes §4 step 1; the provisioning record
//! §5.2): the four pages' HTML — the sign-up page, the claim form, the status
//! page, the refusals — plain HTML with no script and no external resource,
//! every sentence on them a row of the strings table (`strings`), shown with
//! the site's two slots filled ([`Site::fill`]); and each request's dispatch,
//! by its method and its path, over `skep_http`, one request per connection,
//! the request in and the answer out each under a [`TRANSFER_DEADLINE`] of
//! its own.
//!
//! **The requests answered.** `GET /`, the sign-up page; `POST /signup`, the
//! address kept and a thanks page, or a refusal shown on the sign-up page
//! again at 200; `GET /claim`, the claim form, the invite field pre-filled
//! from the `invite` query value where the query decodes and gives one;
//! `POST /claim`, the post's three fields handed to the
//! [`Desk`] — a refusal shown on the form again at 200, an admission
//! answered with D-7 and the post's status URL, no redirect;
//! `GET /status/<token>`, D-7 while the post waits or runs, the live reply
//! once the board's route stands, D-8 once it failed, 404 for a token the
//! desk does not hold — most often one from before the last restart, its
//! page saying so and the person's next act; every other request 404.
//! A request the HTTP subset refuses — a head past [`MAX_HEAD`] or
//! malformed, one cut off early, one that spent its [`TRANSFER_DEADLINE`] —
//! is 400, and so is a body the form decoder refuses; a body past
//! [`MAX_BODY`] is 413 — so every status written is one `skep-http`'s
//! reason table holds. A page that shows D-7 refreshes itself to the status
//! URL every few seconds (a `<meta>` refresh, no script), which is how
//! D-7's "it shows your board when it is live" comes true.
//!
//! The desk ([`Desk`]) is what the pages ask: the sign-up kept, the post
//! admitted or refused, the status read — the flow's, which this file does
//! not name, so the pages are judged here over a desk a test scripts.
//!
//! The two URLs the service hands out are built here, beside the pages they
//! open: a post's status URL ([`status_url`]), and the invite link an
//! invitation carries ([`invite_link`]), which opens the claim form with the
//! code it carries pre-filled.
//!
//! The accept pair ([`Accepts`]) and the pool pair ([`Serving`]) are the
//! connection threads' say on the listener they share, each an edge pair
//! (`rates`' `Edge`): an `accept` that fails opens an episode, said once,
//! and the first that succeeds a hold-down after its last closes it, said
//! once with the count; and the last free thread taking a connection opens
//! one — every thread serving, a connection past them waiting in the
//! listener's queue — said once, and a connection taken with a thread to
//! spare a hold-down after the pool last stood full closes it, said once
//! with how often it stood full.

use std::fmt;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use skep_http::{read_request, write_response, Limits, Refused, Request};
use skep_identity::MAX_RECORD_BYTES;

use crate::domain::Domain;
use crate::invite_code::InviteCode;
use crate::rates::Edge;
use crate::strings::{
    fill, Words, ADDRESS_LABEL, BAD_FORM, BEING_MADE, CLAIM_BUTTON, CLAIM_LEAD, FAILED, INVITE_LABEL, INVITE_REFUSED, NAME_HELP, NAME_LABEL, NAME_REFUSED, NOT_FOUND, PREVIEW_REFUSED, RECORD_HELP,
    RECORD_LABEL, RECORD_REFUSED, SIGNUP_BUTTON, SIGNUP_FAILED, SIGNUP_KEPT, SIGNUP_LEAD, SIGNUP_REFUSED, STATUS_GONE, STATUS_URL, THANKS, TOO_LARGE,
};
use crate::urlform;

// ── The caps and the deadlines ───────────────────────────────────────────

/// The head's cap: a browser's request line and headers, with room.
///
/// The site sets no cookie.
const MAX_HEAD: usize = 16 * 1024;

/// The body's cap: 397,312 bytes.
///
/// It is a record at its cap (`MAX_RECORD_BYTES`, 128 KiB, AUTH-1.18) with
/// every byte percent-encoded, three bytes each, which no record is (its hex
/// digits travel as they are), and 4 KiB for the name, the invite, the field
/// names and the separators. So any record `parse_enroll` could admit fits
/// the form, and nothing much larger is read.
const MAX_BODY: usize = 3 * MAX_RECORD_BYTES + 4096;

/// A read's own timeout: silence past it ends the read.
///
/// Any byte renews it, so it bounds silence alone; slowness is
/// [`TRANSFER_DEADLINE`]'s.
const READ_TIMEOUT: Duration = Duration::from_secs(30);

/// A write's own timeout, as [`READ_TIMEOUT`] is a read's.
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// The transfer deadline: a minute for the request, a fresh one for the answer.
///
/// Each is checked between socket calls — `skepd`'s mechanism, at a figure
/// of its own: `skepd`'s `TRANSFER_DEADLINE`, 30 seconds, is
/// priced for loopback, which delivers its largest body in milliseconds,
/// and this one for a person's uplink, below. The mechanism's reason is
/// `skepd`'s: the socket timeouts are renewed by any byte, and without this
/// a sender trickling one every 29 seconds holds its connection thread, its
/// descriptor and its body's buffer for as long as it likes, and as many
/// such senders as there are threads hold every one. The halves are apart,
/// so a request refused for spending its minute still has one in which to
/// be told so. The budget is the person's uplink, as the proxy streams a
/// body as it is sent: the largest record the form carries, 128 KiB, goes
/// as some 140 KB, under 20 seconds at 64 kbit/s; a record of one to three
/// keys, under 13 KB, in two.
const TRANSFER_DEADLINE: Duration = Duration::from_secs(60);

/// How often a page showing D-7 refreshes itself to the status URL.
const REFRESH_SECS: u32 = 5;

// ── The desk ─────────────────────────────────────────────────────────────

/// The claim form's three fields as posted, bytes as decoded.
#[derive(Clone, Copy)]
pub struct Post<'a> {
    /// The `name` field.
    pub name: &'a [u8],
    /// The `record` field.
    pub record: &'a [u8],
    /// The `invite` field.
    pub invite: &'a [u8],
}

/// The fields' lengths alone.
///
/// A post carries a record's bytes and an invite code, never a log line's,
/// and a name field that may hold anything a person typed.
impl fmt::Debug for Post<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Post").field("name", &self.name.len()).field("record", &self.record.len()).field("invite", &self.invite.len()).finish()
    }
}

/// Why a claim post is refused — each shown on the form again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The invite is refused: the `DRAFT` refusal.
    ///
    /// The field is no code of the code's form, or the code is not in the
    /// file, or spent, or held by another post.
    Invite,
    /// The name is refused: D-4.
    ///
    /// It is no name of the grammar, is taken — something stands under it —
    /// or is held by a post in flight.
    Name,
    /// The record is not one `skep keygen` printed: D-5.
    Record,
    /// The record names a preview key: D-6.
    Preview,
    /// The service is busy: D-8, "try again later".
    ///
    /// The queue is full, or as many posts as it looks for at once already
    /// look at what stands.
    Busy,
    /// The service could not judge the post, or could not admit it: D-8.
    Failed,
}

/// A sign-up refused, as its page shows it.
///
/// It is the address refused by the rule, or one that could not be kept —
/// two answers where the file has three reasons (`signups`'
/// `SignUpRefused`), which the log names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignUpRefusal {
    /// The field is no address.
    NotAnAddress,
    /// The sign-up could not be kept.
    ///
    /// The file could not be read or written, or is at its cap.
    Failed,
}

/// What a status token's page shows.
#[derive(Clone, PartialEq, Eq)]
pub enum Shown {
    /// D-7: queued or running.
    BeingMade,
    /// The live reply's text, as `reply` renders it.
    Live(String),
    /// D-8.
    Failed,
}

/// The page's state, the live reply by its length alone.
///
/// Its last line carries the status URL, and a status token is never a log
/// line's — as a message keeps its body.
impl fmt::Debug for Shown {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Shown::BeingMade => f.write_str("BeingMade"),
            Shown::Live(text) => f.debug_tuple("Live").field(&text.len()).finish(),
            Shown::Failed => f.write_str("Failed"),
        }
    }
}

/// What the pages ask.
///
/// **An answer that unwinds.** It is caught by [`connection`], and the
/// thread that called it serves the next request with the same desk: so a
/// desk keeps nothing an answer can leave half-changed — every lock it takes
/// recovered from poison, no change of its state left half-made where an
/// answer can unwind.
pub trait Desk: Sync {
    /// Keeps the address field's bytes as a sign-up, or refuses them.
    ///
    /// `Ok`: the address kept.
    ///
    /// # Errors
    ///
    /// `NotAnAddress`: nothing kept. `Failed`: nothing kept — or, where the
    /// file's rewrite failed at its directory's sync, after its rename, the
    /// address kept, not known durable.
    fn sign_up(&self, address: &[u8]) -> Result<(), SignUpRefusal>;
    /// Judges a claim post: admitted and queued, or refused.
    ///
    /// `Ok(token)`: the post queued, and answered with its status token,
    /// `token` one [`Desk::status`] answers for the rest of the process's
    /// life — D-7 until the post ends — and one path segment a URL carries as
    /// it is, no `/` in it and nothing a URL escapes: D-7's page sets it into
    /// its status URL and its refresh unencoded, and the status page's path is
    /// the token whole.
    ///
    /// # Errors
    ///
    /// A [`Refusal`]. A refusal leaves nothing: no token, nothing queued, no
    /// file changed.
    fn admit(&self, post: &Post<'_>) -> Result<String, Refusal>;
    /// Returns a status token's page.
    ///
    /// It answers `None` for a token the desk does not hold. It is a query: it
    /// changes nothing.
    fn status(&self, token: &str) -> Option<Shown>;
}

/// What every page fills its slots from.
///
/// It holds the suffix every board's name is under, and the owner's address
/// D-8 names — both filled into every row a page shows ([`Site::fill`]) but
/// the live reply's, which `reply` fills.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Site {
    /// `--suffix`: `skep.host` in the alpha.
    pub suffix: Domain,
    /// `--reply-to`: the owner's address, which D-8 names.
    pub owner_address: String,
}

impl Site {
    /// Fills a row's words with the site's two slots.
    ///
    /// The slots are `{suffix}` and `{owner_address}`, so any row a page fills
    /// here may name either, and no page chooses.
    fn fill(&self, words: Words) -> String {
        self.fill_with(words, &[])
    }

    /// Fills a row as [`Site::fill`] does, with a page's own slots too.
    ///
    /// The page's own slots sit beside the site's two: the status URL on D-7's
    /// page.
    fn fill_with(&self, words: Words, page_slots: &[(&str, &str)]) -> String {
        let site_slots = [("suffix", self.suffix.as_str()), ("owner_address", self.owner_address.as_str())];
        fill(words, &[page_slots, &site_slots[..]].concat())
    }
}

/// Returns a post's status URL (the provisioning record §5.2, the status URL).
///
/// It is `https://<suffix>/status/<token>`, `token` as [`Desk::admit`]
/// answers it: one path segment, carried as it is.
pub fn status_url(suffix: &Domain, token: &str) -> String {
    format!("https://{suffix}/status/{token}")
}

/// Returns the invite link an invitation carries.
///
/// It is `https://<suffix>/claim?invite=<code>` (the intake funnel's second
/// arm) — the claim form's path, and the query value its invite field is
/// pre-filled from.
pub fn invite_link(suffix: &Domain, code: &InviteCode) -> String {
    format!("https://{suffix}/claim?invite={}", code.as_str())
}

// ── The answers ──────────────────────────────────────────────────────────

/// One answer: its status and its page.
#[derive(Clone, PartialEq, Eq)]
struct Answer {
    /// 200, 400, 404 or 413.
    status: u16,
    /// The page's HTML.
    body: String,
}

/// The status and the page's length alone.
///
/// A page carries a refused post's record and invite code back to the form,
/// or a status URL.
impl fmt::Debug for Answer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Answer").field("status", &self.status).field("body", &self.body.len()).finish()
    }
}

/// Returns the headers every page carries.
///
/// They state to the browser, as the page is written, no script and nothing
/// from elsewhere — a style in the page alone, a form posting here alone, no
/// frame — no referrer, so a status URL never rides a request off this site,
/// and no type sniffing.
fn headers() -> Vec<(String, String)> {
    vec![
        ("Content-Security-Policy".into(), "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'".into()),
        ("Referrer-Policy".into(), "no-referrer".into()),
        ("X-Content-Type-Options".into(), "nosniff".into()),
    ]
}

/// A stream under one transfer's deadline.
///
/// A read or a write begun once `until` has passed is `TimedOut`; one begun
/// before runs to its socket timeout, so a transfer is bounded at its
/// deadline and one timeout more. It holds its stream as std's adapters hold
/// theirs, by value — `&mut stream` lent where the caller keeps the stream,
/// as the connection does across its two transfers.
struct Deadlined<S> {
    stream: S,
    until: Instant,
}

impl<S> Deadlined<S> {
    /// Checks the transfer's deadline.
    ///
    /// # Errors
    ///
    /// `TimedOut` once the deadline has passed.
    fn check(&self) -> io::Result<()> {
        if Instant::now() >= self.until {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "the transfer's deadline passed"));
        }
        Ok(())
    }
}

impl<S: Read> Read for Deadlined<S> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.check()?;
        self.stream.read(buf)
    }
}

impl<S: Write> Write for Deadlined<S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.check()?;
        self.stream.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

/// Serves one connection: the timeouts, the read, the answer, the close.
///
/// The one read is made under the caps and its deadline, and the answer
/// under a deadline of its own. A panic anywhere in it costs this connection
/// alone — closed unanswered, the panic said in one line by the binary's
/// hook, its payload only where the code wrote it as a literal — never the
/// thread, which the pool made at start and never makes again.
pub fn connection(stream: TcpStream, site: &Site, desk: &dyn Desk) {
    // AssertUnwindSafe, and sound: a desk keeps nothing an answer can leave
    // half-changed, `Desk`'s own obligation. The service's keeps it so: its
    // book changes under its lock alone, an admission's one check before the
    // book's three inserts and none of those can unwind; every mutex is taken
    // poison-recovering; the invite file's lock is let go of as its file
    // closes; and a look's permit and its code's hold are given back by
    // their `Drop`s as the frame unwinds.
    let _ = catch_unwind(AssertUnwindSafe(|| connection_within(stream, site, desk, TRANSFER_DEADLINE)));
}

/// Serves one connection as [`connection`] does, under a given deadline.
///
/// `deadline` is each transfer's, in [`TRANSFER_DEADLINE`]'s place: the seam
/// a suite shortens.
fn connection_within(mut stream: TcpStream, site: &Site, desk: &dyn Desk, deadline: Duration) {
    let _ = stream.set_read_timeout(Some(READ_TIMEOUT));
    let _ = stream.set_write_timeout(Some(WRITE_TIMEOUT));
    let request = read_request(&mut Deadlined { stream: &mut stream, until: Instant::now() + deadline }, Limits { max_head: MAX_HEAD, max_body: MAX_BODY });
    let answer = match request {
        Ok(Some(request)) => answer(&request, site, desk),
        Ok(None) => return,
        Err(refused) => refused_answer(&refused, site),
    };
    let _ = write_response(&mut Deadlined { stream: &mut stream, until: Instant::now() + deadline }, answer.status, &headers(), Some("text/html; charset=utf-8"), answer.body.as_bytes());
}

/// The accept pair, `skepd`'s (its `operations.md` §1.1 m12).
///
/// It is for the connection threads that take connections off one listener:
/// one episode across them (an [`Edge`]) — the first `accept` that fails, on
/// any thread, opens it and is said once; every thread's failures count into
/// it; the first that succeeds a hold-down (`rates::HOLD_DOWN`) past its
/// last failure closes it, said once with the count and the span the
/// failures came across. Between, nothing: a descriptor wall met every ten
/// milliseconds is two lines, never a line per try, and an `accept` that
/// fails is never silent — the cause is the OS's own words, the unit's
/// `LimitNOFILE=` the act.
#[derive(Debug, Default)]
pub struct Accepts {
    /// The episode of failed `accept`s, across the threads.
    failing: Edge,
}

impl Accepts {
    /// Records an `accept` that failed with `e` at `now`, answering its line.
    ///
    /// It answers the line opening the episode where none stands —
    /// `connections: accept failed (<e>); new connections wait in the
    /// listener's queue` — and `None` where one does, the failure counted into
    /// it.
    pub fn failed(&self, e: &io::Error, now: Instant) -> Option<String> {
        self.failing.met(now).then(|| format!("connections: accept failed ({e}); new connections wait in the listener's queue"))
    }

    /// Records an `accept` that succeeded at `now`, answering a closing line.
    ///
    /// It answers the line closing the episode where one stands and its last
    /// failure is a hold-down past — `connections: accept recovered after <n>
    /// failures, across <d> ms` — and `None` otherwise.
    pub fn accepted(&self, now: Instant) -> Option<String> {
        let ended = self.failing.passed(now)?;
        Some(format!("connections: accept recovered after {}{}", ended.count("failure", "failures"), ended.across()))
    }
}

/// The pool pair, for the connection threads a pool of `pool` serves with.
///
/// It holds how many serve a connection now, and the episode the pool stands
/// full in (an [`Edge`]) — the last free thread taking a connection opens it,
/// said once, a connection past them then waiting in the listener's queue;
/// every time the pool fills again counts into it; the first connection
/// taken with a thread to spare a hold-down (`rates::HOLD_DOWN`) after the
/// pool last stood full closes it, said once with how often it stood full
/// and the span across which it did. So a pool every thread of which a slow
/// client holds — the exposure RUNBOOK §10 step 10 names — is said, never
/// read off the proxy's timeouts alone.
#[derive(Debug)]
pub struct Serving {
    /// The connection threads, every one of them.
    pool: usize,
    /// The threads serving a connection now.
    busy: AtomicUsize,
    /// The episode the pool stands full in.
    full: Edge,
}

impl Serving {
    /// Returns the pair over a pool of `pool` connection threads, none serving.
    pub fn new(pool: usize) -> Serving {
        Serving { pool, busy: AtomicUsize::new(0), full: Edge::default() }
    }

    /// Records a connection taken by a thread at `now`, answering a line owed.
    ///
    /// It answers the line opening the episode where this one fills the pool
    /// with no episode standing — `connections: all <pool> threads serving; a
    /// connection past them waits in the listener's queue` — the line closing
    /// it where a thread is still free and the pool last stood full a
    /// hold-down ago — `connections: a thread free again after all <pool>
    /// stood serving <k> times, across <d> ms` — and `None` otherwise. Every
    /// connection [`Serving::began`] is [`Serving::ended`] once served.
    pub fn began(&self, now: Instant) -> Option<String> {
        let busy = self.busy.fetch_add(1, Ordering::AcqRel) + 1;
        if busy >= self.pool {
            let pool = self.pool;
            return self.full.met(now).then(|| format!("connections: all {pool} threads serving; a connection past them waits in the listener's queue"));
        }
        let ended = self.full.passed(now)?;
        Some(format!("connections: a thread free again after all {} stood serving {}{}", self.pool, ended.count("time", "times"), ended.across()))
    }

    /// Records a connection [`Serving::began`] took as served.
    ///
    /// Its thread is free again.
    pub fn ended(&self) {
        self.busy.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Answers a request the subset refused: 413 past the cap, 400 otherwise.
fn refused_answer(refused: &Refused, site: &Site) -> Answer {
    match refused {
        Refused::TooLarge { .. } => Answer { status: 413, body: page(site, None, &paragraph(&site.fill(TOO_LARGE))) },
        Refused::Malformed(_) => bad_form(site),
    }
}

/// Dispatches one request to its one answer.
fn answer(request: &Request, site: &Site, desk: &dyn Desk) -> Answer {
    match (request.method.as_str(), request.path.as_str()) {
        ("GET", "/") => ok(signup_page(site, None, "")),
        ("POST", "/signup") => {
            let Ok(form) = urlform::decode(&request.body) else { return bad_form(site) };
            let address = form.get("address").unwrap_or_default();
            match desk.sign_up(address) {
                Ok(()) => ok(page(site, None, &paragraph(&site.fill(THANKS)))),
                Err(SignUpRefusal::NotAnAddress) => ok(signup_page(site, Some(SIGNUP_REFUSED), &String::from_utf8_lossy(address))),
                Err(SignUpRefusal::Failed) => ok(signup_page(site, Some(SIGNUP_FAILED), &String::from_utf8_lossy(address))),
            }
        }
        ("GET", "/claim") => {
            let form = request.query.as_deref().and_then(|q| urlform::decode(q.as_bytes()).ok()).unwrap_or_default();
            ok(claim_page(site, None, &Post { name: b"", record: b"", invite: form.get("invite").unwrap_or_default() }))
        }
        ("POST", "/claim") => {
            let Ok(form) = urlform::decode(&request.body) else { return bad_form(site) };
            let post = Post { name: form.get("name").unwrap_or_default(), record: form.get("record").unwrap_or_default(), invite: form.get("invite").unwrap_or_default() };
            match desk.admit(&post) {
                Ok(token) => ok(being_made(site, &token)),
                Err(refusal) => ok(claim_page(site, Some(refusal_words(refusal)), &post)),
            }
        }
        ("GET", path) => match path.strip_prefix("/status/").filter(|t| !t.is_empty() && !t.contains('/')) {
            Some(token) => match desk.status(token) {
                Some(Shown::BeingMade) => ok(being_made(site, token)),
                Some(Shown::Live(text)) => ok(page(site, None, &paragraphs(&text))),
                Some(Shown::Failed) => ok(page(site, None, &refused_paragraph(&site.fill(FAILED)))),
                // A token this process does not hold: most often one from
                // before its last restart, whose page the stop ended — said
                // so, with the person's next act.
                None => Answer { status: 404, body: page(site, None, &paragraph(&site.fill(STATUS_GONE))) },
            },
            None => not_found(site),
        },
        _ => not_found(site),
    }
}

/// Returns the words a claim post's refusal is shown in.
fn refusal_words(refusal: Refusal) -> Words {
    match refusal {
        Refusal::Invite => INVITE_REFUSED,
        Refusal::Name => NAME_REFUSED,
        Refusal::Record => RECORD_REFUSED,
        Refusal::Preview => PREVIEW_REFUSED,
        Refusal::Busy | Refusal::Failed => FAILED,
    }
}

fn ok(body: String) -> Answer {
    Answer { status: 200, body }
}

fn not_found(site: &Site) -> Answer {
    Answer { status: 404, body: page(site, None, &paragraph(&site.fill(NOT_FOUND))) }
}

/// Answers 400 for a request or a body refused, one page for both.
///
/// It answers a request the HTTP subset refuses, or a body the form decoder
/// refuses — the strings table's one row for them, [`BAD_FORM`].
fn bad_form(site: &Site) -> Answer {
    Answer { status: 400, body: page(site, None, &paragraph(&site.fill(BAD_FORM))) }
}

// ── The pages ────────────────────────────────────────────────────────────

/// The style, in the page: no file is fetched for it.
const STYLE: &str = "body{font-family:system-ui,sans-serif;max-width:42rem;margin:2rem auto;padding:0 1rem;line-height:1.5}\
label{display:block;font-weight:600;margin-top:1.25rem}\
input,textarea{width:100%;box-sizing:border-box;font:inherit}\
textarea{font-family:ui-monospace,monospace;font-size:.85rem}\
.help{color:#444;margin:.25rem 0}\
.refused{border-left:4px solid #b00;padding-left:.75rem}\
button{margin-top:1.25rem;font:inherit}";

/// Returns a page in the frame every page shares.
///
/// The frame holds the suffix as its title and heading, the style, and — on
/// a page showing D-7 — the refresh to the status URL.
fn page(site: &Site, refresh_to: Option<&str>, body: &str) -> String {
    let suffix = escape(site.suffix.as_str(), Within::Content);
    let refresh = refresh_to.map_or_else(String::new, |to| format!("<meta http-equiv=\"refresh\" content=\"{REFRESH_SECS}; url={}\">\n", attr(to)));
    format!(
        "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n{refresh}<title>{suffix}</title>\n<style>{STYLE}</style>\n</head>\n<body>\n<h1>{suffix}</h1>\n{body}</body>\n</html>\n"
    )
}

/// Returns the sign-up page.
///
/// It holds the lead, a refusal where one is shown, the address field —
/// pre-filled with what was sent where it was refused — what is kept, the
/// button.
fn signup_page(site: &Site, refusal: Option<Words>, address: &str) -> String {
    let mut body = paragraph(&site.fill(SIGNUP_LEAD));
    if let Some(words) = refusal {
        body.push_str(&refused_paragraph(&site.fill(words)));
    }
    body.push_str(&format!(
        "<form method=\"post\" action=\"/signup\" accept-charset=\"utf-8\">\n<label for=\"address\">{}</label>\n<input id=\"address\" name=\"address\" type=\"email\" autocomplete=\"email\" required value=\"{}\">\n<p class=\"help\">{}</p>\n<button type=\"submit\">{}</button>\n</form>\n",
        row(&site.fill(ADDRESS_LABEL)),
        attr(address),
        row(&site.fill(SIGNUP_KEPT)),
        row(&site.fill(SIGNUP_BUTTON)),
    ));
    page(site, None, &body)
}

/// Returns the claim form.
///
/// It holds D-1, a refusal where one is shown, the three fields — D-2's
/// name, D-3's record, D-9's invite — each pre-filled with what the post
/// sent, or the invite with the link's code, and the button. A field the
/// person sent comes back escaped and nothing else — [`attr`] in a value,
/// [`escape`] in the textarea — never through [`row`], so the next post sends
/// it as it was sent, but for bytes that are not UTF-8: those read as U+FFFD.
fn claim_page(site: &Site, refusal: Option<Words>, post: &Post<'_>) -> String {
    let mut body = paragraph(&site.fill(CLAIM_LEAD));
    if let Some(words) = refusal {
        body.push_str(&refused_paragraph(&site.fill(words)));
    }
    body.push_str(&format!(
        "<form method=\"post\" action=\"/claim\" accept-charset=\"utf-8\">\n\
         <label for=\"name\">{}</label>\n<p class=\"help\">{}</p>\n\
         <input id=\"name\" name=\"name\" required autocomplete=\"off\" autocapitalize=\"none\" spellcheck=\"false\" value=\"{}\">\n\
         <label for=\"record\">{}</label>\n<p class=\"help\">{}</p>\n\
         <textarea id=\"record\" name=\"record\" rows=\"6\" required spellcheck=\"false\">{}</textarea>\n\
         <label for=\"invite\">{}</label>\n\
         <input id=\"invite\" name=\"invite\" required autocomplete=\"off\" spellcheck=\"false\" value=\"{}\">\n\
         <button type=\"submit\">{}</button>\n</form>\n",
        row(&site.fill(NAME_LABEL)),
        row(&site.fill(NAME_HELP)),
        attr(&String::from_utf8_lossy(post.name)),
        row(&site.fill(RECORD_LABEL)),
        row(&site.fill(RECORD_HELP)),
        escape(&String::from_utf8_lossy(post.record), Within::Content),
        row(&site.fill(INVITE_LABEL)),
        attr(&String::from_utf8_lossy(post.invite)),
        row(&site.fill(CLAIM_BUTTON)),
    ));
    page(site, None, &body)
}

/// Returns D-7's page: D-7 and the status URL, refreshing to it.
fn being_made(site: &Site, token: &str) -> String {
    let url = status_url(&site.suffix, token);
    let body = paragraph(&site.fill(BEING_MADE)) + &paragraph(&site.fill_with(STATUS_URL, &[("status_url", &url)]));
    page(site, Some(&format!("/status/{token}")), &body)
}

/// Returns one paragraph of a row's words.
fn paragraph(words: &str) -> String {
    format!("<p>{}</p>\n", row(words))
}

/// Returns one paragraph of a row's words, marked as a refusal.
fn refused_paragraph(words: &str) -> String {
    format!("<p class=\"refused\">{}</p>\n", row(words))
}

/// Returns the live reply's text as paragraphs.
///
/// There is one per blank-line-separated block, its lines — the table's rows,
/// filled (`reply`) — kept apart by `<br>`, the text's closing line break no
/// line.
fn paragraphs(reply: &str) -> String {
    reply.trim_end_matches('\n').split("\n\n").filter(|block| !block.is_empty()).map(|block| format!("<p>{}</p>\n", block.split('\n').map(row).collect::<Vec<_>>().join("<br>\n"))).collect()
}

/// Renders a row's words for an element's content.
///
/// The words are the strings table's, filled, and the live reply's lines:
/// escaped as [`escape`] escapes, and a span between two backticks set as
/// `<code>` — the table's commands — where the backticks pair up; where they
/// do not, every backtick stays as written. Never a person's field: its
/// backticks are the person's, and `<code>` inside a `<textarea>` is text the
/// next post sends back.
fn row(words: &str) -> String {
    let spans: Vec<&str> = words.split('`').collect();
    if spans.len().is_multiple_of(2) {
        return escape(words, Within::Content);
    }
    spans.iter().enumerate().map(|(i, span)| if i % 2 == 1 { format!("<code>{}</code>", escape(span, Within::Content)) } else { escape(span, Within::Content) }).collect()
}

/// Where escaped text is set: an element's content, or an attribute's value.
///
/// The attribute's value is the one place a quote could end what holds it,
/// so the one place the quotes are escaped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Within {
    /// An element's content: the title, a paragraph, a `<code>`, the textarea.
    ///
    /// `&`, `<` and `>` are escaped, the quotes kept as written.
    Content,
    /// An attribute's value: the two quotes escaped too.
    Attribute,
}

/// Escapes an attribute's value: [`escape`] within an attribute.
fn attr(text: &str) -> String {
    escape(text, Within::Attribute)
}

/// Escapes `&`, `<` and `>`, and within an attribute the two quotes too.
///
/// It is the one escaper; nothing else changes, so a person's field reads
/// back as sent.
fn escape(text: &str, within: Within) -> String {
    let quotes = within == Within::Attribute;
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' if quotes => out.push_str("&quot;"),
            '\'' if quotes => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests;
