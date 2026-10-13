//! THE PAGES and THE REQUESTS THEY ANSWER (the deployment notes §4 step 1;
//! the provisioning record §5.2): the four pages' HTML — the sign-up page,
//! the claim form, the status page, the refusals — plain HTML with no script
//! and no external resource, every sentence on them a row of the strings
//! table (`strings`), shown with the site's two slots filled
//! ([`Site::fill`]); and each request's dispatch, by its method and its
//! path, over `skep_http`, one request per connection, the request in and
//! the answer out each under a [`TRANSFER_DEADLINE`] of its own.
//!
//! THE REQUESTS ANSWERED: `GET /`, the sign-up page; `POST /signup`, the
//! address kept and a thanks page; `GET /claim`, the claim form, the invite
//! field pre-filled from the `invite` query value where one is given; `POST
//! /claim`, the post's three fields handed to the [`Desk`] — a refusal shown
//! on the form again at 200, an admission answered with D-7 and the post's
//! status URL, no redirect; `GET /status/<token>`, D-7 while the post waits
//! or runs, the live reply once the board's route stands, D-8 once it
//! failed, 404 for a token the desk does not hold; every other request 404.
//! A request the HTTP subset refuses — a head past [`MAX_HEAD`] or
//! malformed, one cut off early, one that spent its [`TRANSFER_DEADLINE`] —
//! is 400, and so is a body the form decoder refuses; a body past
//! [`MAX_BODY`] is 413 — so every status written is one `skep-http`'s
//! reason table holds. A page that shows D-7 refreshes itself to the status
//! URL every few seconds (a `<meta>` refresh, no script), which is how
//! D-7's "it shows your board when it is live" comes true.
//!
//! THE DESK ([`Desk`]) is what the pages ask: the sign-up kept, the post
//! admitted or refused, the status read — the flow's, which this file does
//! not name, so the pages are judged here over a desk a test scripts.
//!
//! THE TWO URLS the service hands out are built here, beside the pages they
//! open: a post's status URL ([`status_url`]), and the invite link an
//! invitation carries ([`invite_link`]), which opens the claim form with the
//! code it carries pre-filled.

use std::fmt;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::time::{Duration, Instant};

use skep_http::{read_request, write_response, Limits, Refused, Request};
use skep_identity::MAX_RECORD_BYTES;

use crate::domain::Domain;
use crate::invite_code::InviteCode;
use crate::strings::{
    fill, Words, ADDRESS_LABEL, BAD_FORM, BEING_MADE, CLAIM_BUTTON, CLAIM_LEAD, FAILED, INVITE_LABEL, INVITE_REFUSED, NAME_HELP, NAME_LABEL, NAME_REFUSED, NOT_FOUND, PREVIEW_REFUSED, RECORD_HELP,
    RECORD_LABEL, RECORD_REFUSED, SIGNUP_BUTTON, SIGNUP_FAILED, SIGNUP_KEPT, SIGNUP_LEAD, SIGNUP_REFUSED, STATUS_URL, THANKS, TOO_LARGE,
};
use crate::urlform;

// ── THE CAPS AND THE DEADLINES ───────────────────────────────────────────

/// THE HEAD's CAP: a browser's request line and headers, with room — the
/// site sets no cookie.
const MAX_HEAD: usize = 16 * 1024;

/// THE BODY's CAP: 397,312 bytes — a record at its cap (`MAX_RECORD_BYTES`,
/// 128 KiB, AUTH-1.18) with EVERY byte percent-encoded, three bytes each,
/// which no record is (its hex digits travel as they are), and 4 KiB for
/// the name, the invite, the field names and the separators. So any record
/// `parse_enroll` could admit fits the form, and nothing much larger is
/// read.
const MAX_BODY: usize = 3 * MAX_RECORD_BYTES + 4096;

/// A read's own timeout: SILENCE past it ends the read. Any byte renews
/// it, so it bounds silence alone; slowness is [`TRANSFER_DEADLINE`]'s.
const READ_TIMEOUT: Duration = Duration::from_secs(30);

/// A write's own timeout, as [`READ_TIMEOUT`] is a read's.
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// THE TRANSFER DEADLINE: a minute for the request in and a fresh minute for
/// the answer out, each checked between socket calls — `skepd`'s
/// `TRANSFER_DEADLINE`, for its reason: the socket timeouts are renewed by
/// any byte, and without this a sender trickling one every 29 seconds holds
/// its connection thread, its descriptor and its body's buffer for as long
/// as it likes, and as many such senders as there are threads hold every
/// one. The halves are apart, so a request refused for spending its minute
/// still has one in which to be told so. The budget is the person's uplink,
/// as the proxy streams a body as it is sent: the largest record the form
/// carries, 128 KiB, goes as some 140 KB, under 20 seconds at 64 kbit/s; a
/// record of one to three keys, under 13 KB, in two.
const TRANSFER_DEADLINE: Duration = Duration::from_secs(60);

/// How often a page showing D-7 refreshes itself to the status URL.
const REFRESH_SECS: u32 = 5;

// ── THE DESK ─────────────────────────────────────────────────────────────

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

/// The fields' lengths alone: a post carries a record's bytes and an invite
/// code, never a log line's, and a name field that may hold anything a
/// person typed.
impl fmt::Debug for Post<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Post").field("name", &self.name.len()).field("record", &self.record.len()).field("invite", &self.invite.len()).finish()
    }
}

/// Why a claim post is refused — each shown on the form again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The field is no code of the code's form, or the code is not in the
    /// file, or spent, or held by another post: the DRAFT refusal.
    Invite,
    /// The name is not one label, is taken — something stands under it —
    /// or is held by a post in flight: D-4.
    Name,
    /// The record is not one `skep keygen` printed: D-5.
    Record,
    /// The record names a preview key: D-6.
    Preview,
    /// The service is busy — the queue full, or as many posts as it looks
    /// for at once already looking at what stands: D-8, "try again later".
    Busy,
    /// The service could not judge the post: D-8.
    Failed,
}

/// A sign-up refused, AS ITS PAGE SHOWS IT: the address refused by the rule,
/// or one that could not be kept — two answers where the file has three
/// reasons (`signups`' `SignUpRefused`), which the log names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignUpRefusal {
    /// The field is no address.
    NotAnAddress,
    /// The sign-up could not be kept: the file could not be read or
    /// written, or is at its cap.
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

/// The page's state, the live reply by its length alone: its last line is
/// the status URL, and a status token is never a log line's — as a
/// message keeps its body.
impl fmt::Debug for Shown {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Shown::BeingMade => f.write_str("BeingMade"),
            Shown::Live(text) => f.debug_tuple("Live").field(&text.len()).finish(),
            Shown::Failed => f.write_str("Failed"),
        }
    }
}

/// WHAT THE PAGES ASK. AN ANSWER THAT UNWINDS is caught by [`connection`],
/// and the thread that called it serves the next request with the same desk:
/// so a desk keeps nothing an answer can leave half-changed — every lock it
/// takes recovered from poison, no change of its state left half-made where
/// an answer can unwind.
pub trait Desk: Sync {
    /// A sign-up: the address field's bytes kept, or refused. `Ok`: the
    /// address kept. `NotAnAddress`: nothing kept. `Failed`: nothing kept —
    /// or, where the file's rewrite failed at its directory's sync, after
    /// its rename, the address kept, not known durable.
    fn sign_up(&self, address: &[u8]) -> Result<(), SignUpRefusal>;
    /// A claim post judged: admitted — queued, and answered with its status
    /// token — or refused. `Ok(token)`: the post queued, and `token` one
    /// [`Desk::status`] answers for the rest of the process's life — D-7
    /// until the post ends — and one path segment a URL carries as it is, no
    /// `/` in it and nothing a URL escapes: D-7's page sets it into its
    /// status URL and its refresh unencoded, and the status page's path is
    /// the token whole. A refusal leaves nothing: no token, nothing queued,
    /// no file changed.
    fn admit(&self, post: &Post<'_>) -> Result<String, Refusal>;
    /// A status token's page; `None` for a token the desk does not hold. A
    /// query: it changes nothing.
    fn status(&self, token: &str) -> Option<Shown>;
}

/// What every page fills its slots from: the suffix every board's name is
/// under, and the owner's address D-8 names — both filled into every row a
/// page shows ([`Site::fill`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Site {
    /// `--suffix`: `skep.host` in the alpha.
    pub suffix: Domain,
    /// `--reply-to`: the owner's address, which D-8 names.
    pub owner_address: String,
}

impl Site {
    /// A ROW's WORDS AS EVERY PAGE SHOWS THEM: the site's two slots filled,
    /// `{suffix}` and `{owner_address}`, so any row a page shows may name
    /// either, and no page chooses.
    fn fill(&self, words: Words) -> String {
        self.fill_with(words, &[])
    }

    /// [`Site::fill`] with a page's own slots beside the site's two: the
    /// status URL on D-7's page.
    fn fill_with(&self, words: Words, page_slots: &[(&str, &str)]) -> String {
        let site_slots = [("suffix", self.suffix.as_str()), ("owner_address", self.owner_address.as_str())];
        fill(words, &[page_slots, &site_slots[..]].concat())
    }
}

/// A POST's STATUS URL (the provisioning record §5.2, THE STATUS URL):
/// `https://<suffix>/status/<token>`, `token` as [`Desk::admit`] answers it:
/// one path segment, carried as it is.
pub fn status_url(suffix: &Domain, token: &str) -> String {
    format!("https://{suffix}/status/{token}")
}

/// THE INVITE LINK an invitation carries (the intake funnel's second arm):
/// `https://<suffix>/claim?invite=<code>` — the claim form's path, and the
/// query value its invite field is pre-filled from.
pub fn invite_link(suffix: &Domain, code: &InviteCode) -> String {
    format!("https://{suffix}/claim?invite={}", code.as_str())
}

// ── THE ANSWERS ──────────────────────────────────────────────────────────

/// One answer: its status and its page.
#[derive(Clone, PartialEq, Eq)]
struct Answer {
    /// 200, 400, 404 or 413.
    status: u16,
    /// The page's HTML.
    body: String,
}

/// The status and the page's length alone: a page carries a refused post's
/// record and invite code back to the form, or a status URL.
impl fmt::Debug for Answer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Answer").field("status", &self.status).field("body", &self.body.len()).finish()
    }
}

/// THE HEADERS every page carries: no script and nothing from elsewhere,
/// stated to the browser as the page is written — a style in the page
/// alone, a form posting here alone, no frame — no referrer, so a status
/// URL never rides a request off this site, and no type sniffing.
fn headers() -> Vec<(String, String)> {
    vec![
        ("Content-Security-Policy".into(), "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'".into()),
        ("Referrer-Policy".into(), "no-referrer".into()),
        ("X-Content-Type-Options".into(), "nosniff".into()),
    ]
}

/// A STREAM UNDER ONE TRANSFER's DEADLINE: a read or a write begun once
/// `until` has passed is `TimedOut`; one begun before runs to its socket
/// timeout, so a transfer is bounded at its deadline and one timeout more.
/// It holds its stream as std's adapters hold theirs, by value — `&mut
/// stream` lent where the caller keeps the stream, as the connection does
/// across its two transfers.
struct Deadlined<S> {
    stream: S,
    until: Instant,
}

impl<S> Deadlined<S> {
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

/// THE CONNECTION: the timeouts, the one read under the caps and its
/// deadline, the answer under a deadline of its own, the close. A panic
/// anywhere in it costs this connection alone — closed unanswered, the
/// panic said on stderr by the hook — never the thread, which the pool made
/// at start and never makes again.
pub fn connection(stream: TcpStream, site: &Site, desk: &dyn Desk) {
    // AssertUnwindSafe, and sound: a desk keeps nothing an answer can leave
    // half-changed, `Desk`'s own obligation. The service's keeps it so: its
    // book changes under its lock alone, an admission's one check before the
    // book's three inserts and none of those can unwind; every mutex is taken
    // poison-recovering; the invite file's lock is let go of as its file
    // closes; and a look's permit is given back by its `Drop` as the frame
    // unwinds.
    let _ = catch_unwind(AssertUnwindSafe(|| connection_within(stream, site, desk, TRANSFER_DEADLINE)));
}

/// [`connection`] with `deadline` for each transfer's, in
/// [`TRANSFER_DEADLINE`]'s place: the seam a suite shortens.
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

/// A request the subset refused: 413 past the cap, 400 otherwise.
fn refused_answer(refused: &Refused, site: &Site) -> Answer {
    match refused {
        Refused::TooLarge { .. } => Answer { status: 413, body: page(site, None, &paragraph(&site.fill(TOO_LARGE))) },
        Refused::Malformed(_) => bad_form(site),
    }
}

/// THE DISPATCH: one request, one answer.
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
        ("GET", path) => match path.strip_prefix("/status/").filter(|t| !t.is_empty() && !t.contains('/')).and_then(|token| desk.status(token).map(|shown| (token, shown))) {
            Some((token, Shown::BeingMade)) => ok(being_made(site, token)),
            Some((_, Shown::Live(text))) => ok(page(site, None, &paragraphs(&text))),
            Some((_, Shown::Failed)) => ok(page(site, None, &refused_paragraph(&site.fill(FAILED)))),
            None => not_found(site),
        },
        _ => not_found(site),
    }
}

/// The words a claim post's refusal is shown in.
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

/// A request the HTTP subset refuses, or a body the form decoder refuses:
/// 400, one page for both — the strings table's one row for them,
/// [`BAD_FORM`].
fn bad_form(site: &Site) -> Answer {
    Answer { status: 400, body: page(site, None, &paragraph(&site.fill(BAD_FORM))) }
}

// ── THE PAGES ────────────────────────────────────────────────────────────

/// The style, in the page: no file is fetched for it.
const STYLE: &str = "body{font-family:system-ui,sans-serif;max-width:42rem;margin:2rem auto;padding:0 1rem;line-height:1.5}\
label{display:block;font-weight:600;margin-top:1.25rem}\
input,textarea{width:100%;box-sizing:border-box;font:inherit}\
textarea{font-family:ui-monospace,monospace;font-size:.85rem}\
.help{color:#444;margin:.25rem 0}\
.refused{border-left:4px solid #b00;padding-left:.75rem}\
button{margin-top:1.25rem;font:inherit}";

/// THE FRAME every page shares: the suffix as its title and heading, the
/// style, and — on a page showing D-7 — the refresh to the status URL.
fn page(site: &Site, refresh_to: Option<&str>, body: &str) -> String {
    let suffix = escape(site.suffix.as_str(), Within::Content);
    let refresh = refresh_to.map_or_else(String::new, |to| format!("<meta http-equiv=\"refresh\" content=\"{REFRESH_SECS}; url={}\">\n", attr(to)));
    format!(
        "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n{refresh}<title>{suffix}</title>\n<style>{STYLE}</style>\n</head>\n<body>\n<h1>{suffix}</h1>\n{body}</body>\n</html>\n"
    )
}

/// THE SIGN-UP PAGE: the lead, a refusal where one is shown, the address
/// field — pre-filled with what was sent where it was refused — what is
/// kept, the button.
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

/// THE CLAIM FORM: D-1, a refusal where one is shown, the three fields —
/// D-2's name, D-3's record, D-9's invite — each pre-filled with what the
/// post sent, or the invite with the link's code, and the button. A field
/// the person sent comes back escaped and nothing else — [`attr`] in a
/// value, [`escape`] in the textarea — never through [`row`], so the next
/// post sends it as it was sent.
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

/// D-7's PAGE: D-7 and the status URL, refreshing to it.
fn being_made(site: &Site, token: &str) -> String {
    let url = status_url(&site.suffix, token);
    let body = paragraph(&site.fill(BEING_MADE)) + &paragraph(&site.fill_with(STATUS_URL, &[("status_url", &url)]));
    page(site, Some(&format!("/status/{token}")), &body)
}

/// One paragraph of a row's words.
fn paragraph(words: &str) -> String {
    format!("<p>{}</p>\n", row(words))
}

/// One paragraph of a row's words, marked as a refusal.
fn refused_paragraph(words: &str) -> String {
    format!("<p class=\"refused\">{}</p>\n", row(words))
}

/// The live reply's text as paragraphs: one per blank-line-separated block,
/// its lines — the table's rows, filled (`reply`) — kept apart by `<br>`,
/// the text's closing line break no line.
fn paragraphs(reply: &str) -> String {
    reply.trim_end_matches('\n').split("\n\n").filter(|block| !block.is_empty()).map(|block| format!("<p>{}</p>\n", block.split('\n').map(row).collect::<Vec<_>>().join("<br>\n"))).collect()
}

/// A ROW's WORDS for an element's content — the strings table's, filled, and
/// the live reply's lines: escaped as [`escape`] escapes, and a span between
/// two backticks set as `<code>` — the table's commands — where the
/// backticks pair up; where they do not, every backtick stays as written.
/// Never a person's field: its backticks are the person's, and `<code>`
/// inside a `<textarea>` is text the next post sends back.
fn row(words: &str) -> String {
    let spans: Vec<&str> = words.split('`').collect();
    if spans.len().is_multiple_of(2) {
        return escape(words, Within::Content);
    }
    spans.iter().enumerate().map(|(i, span)| if i % 2 == 1 { format!("<code>{}</code>", escape(span, Within::Content)) } else { escape(span, Within::Content) }).collect()
}

/// WHERE ESCAPED TEXT IS SET: an element's content, or an attribute's
/// value — the one place a quote could end what holds it, so the one place
/// the quotes are escaped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Within {
    /// An element's content — the title, a paragraph, a `<code>`, the
    /// textarea: `&`, `<` and `>` escaped, the quotes kept as written.
    Content,
    /// An attribute's value: the two quotes escaped too.
    Attribute,
}

/// AN ATTRIBUTE's VALUE: [`escape`] within an attribute.
fn attr(text: &str) -> String {
    escape(text, Within::Attribute)
}

/// THE ONE ESCAPER: `&`, `<` and `>`, and within an attribute the two
/// quotes too; nothing else changes, so a person's field reads back as sent.
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
