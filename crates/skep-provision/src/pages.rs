//! THE PAGES and THE ROUTES (the deployment notes §4 step 1; the
//! provisioning record §5.2): the four pages' HTML — the sign-up page, the
//! claim form, the status page, the refusals — plain HTML with no script and
//! no external resource, every sentence on them a row of the strings table
//! (`strings`); and the routes' dispatch over `skep_http`, one request per
//! connection.
//!
//! THE ROUTES: `GET /`, the sign-up page; `POST /signup`, the address kept
//! and a thanks page; `GET /claim`, the claim form, the invite field
//! pre-filled from the `invite` query value where one is given; `POST
//! /claim`, the three fields handed to the [`Desk`] — a refusal shown on
//! the form again at 200, an admission answered with D-7 and the post's
//! status address, no redirect; `GET /status/<token>`, D-7 while the post
//! waits or runs, the live reply once the route stands, D-8 once it failed,
//! 404 for a token the desk does not hold; every other route 404. A body
//! the form decoder refuses is 400, a body past [`MAX_BODY`] 413 — so every
//! status written is one `skep-http`'s reason table holds. A page that
//! shows D-7 refreshes itself to the status address every few seconds (a
//! `<meta>` refresh, no script), which is how D-7's "it shows your board
//! when it is live" comes true.
//!
//! THE DESK ([`Desk`]) is what the routes ask: the sign-up kept, the claim
//! admitted, the status read — the flow's, which this file does not name,
//! so the pages are judged here over a desk a test scripts.
//!
//! THE TWO ADDRESSES the service hands out are built here, beside the
//! routes they open: a post's status address ([`status_address`]), and the
//! claim address an invite carries ([`claim_address`]), which opens the
//! claim form with its invite field pre-filled.

use std::net::TcpStream;
use std::time::Duration;

use skep_http::{read_request, write_response, Limits, Refused, Request};
use skep_identity::MAX_RECORD_BYTES;

use crate::strings::{
    fill, Words, ADDRESS_LABEL, BAD_FORM, BEING_MADE, CLAIM_BUTTON, FAILED, INVITE_LABEL, INVITE_REFUSED, LEAD, NAME_HELP, NAME_LABEL, NAME_REFUSED, NOT_FOUND, PREVIEW_REFUSED, RECORD_HELP,
    RECORD_LABEL, RECORD_REFUSED, SIGNUP_BUTTON, SIGNUP_FAILED, SIGNUP_KEPT, SIGNUP_LEAD, SIGNUP_REFUSED, STATUS_ADDRESS, THANKS, TOO_LARGE,
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

/// The socket's read deadline: a stalled client releases its thread.
const READ_TIMEOUT: Duration = Duration::from_secs(30);

/// The socket's write deadline.
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// How often a page showing D-7 refreshes itself to the status address.
const REFRESH_SECS: u32 = 5;

// ── THE DESK ─────────────────────────────────────────────────────────────

/// The claim form's three fields as posted, bytes as decoded.
#[derive(Debug, Clone, Copy)]
pub struct Post<'a> {
    /// The `name` field.
    pub name: &'a [u8],
    /// The `record` field.
    pub record: &'a [u8],
    /// The `invite` field.
    pub invite: &'a [u8],
}

/// Why a claim post is refused — each shown on the form again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// The invite code is not in the file, or spent, or held by a post in
    /// flight: the DRAFT refusal.
    Invite,
    /// The name is not one label, or is taken: D-4.
    Name,
    /// The record is not one `skep keygen` printed: D-5.
    Record,
    /// The record names a preview key: D-6.
    Preview,
    /// The queue is full: D-8, "try again later".
    Busy,
    /// The service could not judge the post: D-8.
    Failed,
}

/// Why a sign-up is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignUpRefusal {
    /// The field is no address.
    NotAnAddress,
    /// The file could not be written.
    Failed,
}

/// What a status token's page shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Shown {
    /// D-7: queued or running.
    BeingMade,
    /// The live reply's text, as `reply` renders it.
    Live(String),
    /// D-8.
    Failed,
}

/// WHAT THE ROUTES ASK.
pub trait Desk: Sync {
    /// A sign-up: the address field's bytes kept, or refused.
    fn sign_up(&self, address: &[u8]) -> Result<(), SignUpRefusal>;
    /// A claim post judged and, where admitted, queued: its status token.
    fn claim(&self, post: &Post<'_>) -> Result<String, Refusal>;
    /// A status token's page; `None` for a token the desk does not hold.
    fn status(&self, token: &str) -> Option<Shown>;
}

/// What every page fills its slots from: the suffix the boards stand
/// under, and the owner's address D-8 names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Site {
    /// `--suffix`: `skep.host` in the alpha.
    pub suffix: String,
    /// `--reply-to`: the owner's mailbox.
    pub reply_to: String,
}

/// A post's status address: `https://<suffix>/status/<token>`.
pub fn status_address(suffix: &str, token: &str) -> String {
    format!("https://{suffix}/status/{token}")
}

/// THE CLAIM ADDRESS an invite carries: `https://<suffix>/claim?invite=<code>`
/// — the claim form's route, and the query value its invite field is
/// pre-filled from.
pub fn claim_address(suffix: &str, code: &str) -> String {
    format!("https://{suffix}/claim?invite={code}")
}

// ── THE ANSWERS ──────────────────────────────────────────────────────────

/// One answer: its status and its page.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Answer {
    /// 200, 400, 404 or 413.
    status: u16,
    /// The page's HTML.
    body: String,
}

/// THE HEADERS every page carries: no script and nothing from elsewhere,
/// stated to the browser as the page is written — a style in the page
/// alone, a form posting here alone, no frame — no referrer, so a status
/// address never rides a request off this site, and no type sniffing.
fn headers() -> Vec<(String, String)> {
    vec![
        ("Content-Security-Policy".into(), "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'".into()),
        ("Referrer-Policy".into(), "no-referrer".into()),
        ("X-Content-Type-Options".into(), "nosniff".into()),
    ]
}

/// THE CONNECTION: the deadlines, the one read under the caps, the answer,
/// the close.
pub fn connection(mut stream: TcpStream, site: &Site, desk: &dyn Desk) {
    let _ = stream.set_read_timeout(Some(READ_TIMEOUT));
    let _ = stream.set_write_timeout(Some(WRITE_TIMEOUT));
    let answer = match read_request(&mut stream, Limits { max_head: MAX_HEAD, max_body: MAX_BODY }) {
        Ok(Some(request)) => answer(&request, site, desk),
        Ok(None) => return,
        Err(refused) => refused_answer(&refused, site),
    };
    let _ = write_response(&mut stream, answer.status, &headers(), Some("text/html; charset=utf-8"), answer.body.as_bytes());
}

/// A request the subset refused: 413 past the cap, 400 otherwise.
fn refused_answer(refused: &Refused, site: &Site) -> Answer {
    match refused {
        Refused::TooLarge { .. } => Answer { status: 413, body: page(site, None, &paragraph(&fill(TOO_LARGE, &[]))) },
        Refused::Malformed(_) => Answer { status: 400, body: page(site, None, &paragraph(&fill(BAD_FORM, &[]))) },
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
                Ok(()) => ok(page(site, None, &paragraph(&fill(THANKS, &[])))),
                Err(SignUpRefusal::NotAnAddress) => ok(signup_page(site, Some(SIGNUP_REFUSED), &String::from_utf8_lossy(address))),
                Err(SignUpRefusal::Failed) => ok(signup_page(site, Some(SIGNUP_FAILED), &String::from_utf8_lossy(address))),
            }
        }
        ("GET", "/claim") => {
            let invite = request.query.as_deref().and_then(|q| urlform::decode(q.as_bytes()).ok()).and_then(|f| f.get("invite").map(<[u8]>::to_vec)).unwrap_or_default();
            ok(claim_page(site, None, &Post { name: b"", record: b"", invite: &invite }))
        }
        ("POST", "/claim") => {
            let Ok(form) = urlform::decode(&request.body) else { return bad_form(site) };
            let post = Post { name: form.get("name").unwrap_or_default(), record: form.get("record").unwrap_or_default(), invite: form.get("invite").unwrap_or_default() };
            match desk.claim(&post) {
                Ok(token) => ok(being_made(site, &token)),
                Err(refusal) => ok(claim_page(site, Some(refusal_words(refusal)), &post)),
            }
        }
        ("GET", path) => match path.strip_prefix("/status/").filter(|t| !t.is_empty() && !t.contains('/')).and_then(|token| desk.status(token).map(|shown| (token, shown))) {
            Some((token, Shown::BeingMade)) => ok(being_made(site, token)),
            Some((_, Shown::Live(text))) => ok(page(site, None, &paragraphs(&text))),
            Some((_, Shown::Failed)) => ok(page(site, None, &refused_paragraph(&fill(FAILED, &[("reply_to", &site.reply_to)])))),
            None => not_found(site),
        },
        _ => not_found(site),
    }
}

/// The words a claim refusal is shown in.
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
    Answer { status: 404, body: page(site, None, &paragraph(&fill(NOT_FOUND, &[]))) }
}

fn bad_form(site: &Site) -> Answer {
    Answer { status: 400, body: page(site, None, &paragraph(&fill(BAD_FORM, &[]))) }
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
/// style, and — on a page showing D-7 — the refresh to the status address.
fn page(site: &Site, refresh: Option<&str>, body: &str) -> String {
    let suffix = escape(&site.suffix, false);
    let refresh = refresh.map_or_else(String::new, |to| format!("<meta http-equiv=\"refresh\" content=\"{REFRESH_SECS}; url={}\">\n", attr(to)));
    format!(
        "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n{refresh}<title>{suffix}</title>\n<style>{STYLE}</style>\n</head>\n<body>\n<h1>{suffix}</h1>\n{body}</body>\n</html>\n"
    )
}

/// THE SIGN-UP PAGE: the lead, a refusal where one is shown, the address
/// field — pre-filled with what was sent where it was refused — what is
/// kept, the button.
fn signup_page(site: &Site, refusal: Option<Words>, address: &str) -> String {
    let slots = [("suffix", site.suffix.as_str())];
    let mut body = paragraph(&fill(SIGNUP_LEAD, &slots));
    if let Some(words) = refusal {
        body.push_str(&refused_paragraph(&fill(words, &slots)));
    }
    body.push_str(&format!(
        "<form method=\"post\" action=\"/signup\" accept-charset=\"utf-8\">\n<label for=\"address\">{}</label>\n<input id=\"address\" name=\"address\" type=\"email\" autocomplete=\"email\" required value=\"{}\">\n<p class=\"help\">{}</p>\n<button type=\"submit\">{}</button>\n</form>\n",
        row(&fill(ADDRESS_LABEL, &slots)),
        attr(address),
        row(&fill(SIGNUP_KEPT, &slots)),
        row(&fill(SIGNUP_BUTTON, &slots)),
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
    let slots = [("suffix", site.suffix.as_str()), ("reply_to", site.reply_to.as_str())];
    let mut body = paragraph(&fill(LEAD, &slots));
    if let Some(words) = refusal {
        body.push_str(&refused_paragraph(&fill(words, &slots)));
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
        row(&fill(NAME_LABEL, &slots)),
        row(&fill(NAME_HELP, &slots)),
        attr(&String::from_utf8_lossy(post.name)),
        row(&fill(RECORD_LABEL, &slots)),
        row(&fill(RECORD_HELP, &slots)),
        escape(&String::from_utf8_lossy(post.record), false),
        row(&fill(INVITE_LABEL, &slots)),
        attr(&String::from_utf8_lossy(post.invite)),
        row(&fill(CLAIM_BUTTON, &slots)),
    ));
    page(site, None, &body)
}

/// D-7's PAGE: D-7 and the status address, refreshing to it.
fn being_made(site: &Site, token: &str) -> String {
    let address = status_address(&site.suffix, token);
    let body = paragraph(&fill(BEING_MADE, &[])) + &paragraph(&fill(STATUS_ADDRESS, &[("status", &address)]));
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
        return escape(words, false);
    }
    spans.iter().enumerate().map(|(i, span)| if i % 2 == 1 { format!("<code>{}</code>", escape(span, false)) } else { escape(span, false) }).collect()
}

/// AN ATTRIBUTE's VALUE: escaped as [`escape`] escapes, the quotes too.
fn attr(words: &str) -> String {
    escape(words, true)
}

/// THE ONE ESCAPER: `&`, `<` and `>`, and with `quotes` the two quotes too;
/// nothing else changes, so a person's field reads back as sent.
fn escape(words: &str, quotes: bool) -> String {
    let mut out = String::with_capacity(words.len());
    for c in words.chars() {
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
