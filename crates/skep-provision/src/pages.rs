//! THE PAGES and THE ROUTES (the deployment notes §4 step 1; the
//! provisioning record §5.2): every sentence a person reads, in ONE TABLE at
//! the top of this file; the four pages' HTML — the sign-up page, the claim
//! form, the status page, the refusals — plain HTML with no script and no
//! external resource; and the routes' dispatch over `skep_http`, one request
//! per connection.
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

use std::net::TcpStream;
use std::time::Duration;

use skep_http::{read_request, write_response, Limits, Refused, Request};
use skep_identity::MAX_RECORD_BYTES;

use crate::urlform;

// ── THE STRINGS TABLE ────────────────────────────────────────────────────
//
// Every person-facing sentence of this program, each row naming its id: a
// row of the deployment notes' table (`D-1` … `D-9`, §4 step 1 and §12 —
// each DRAFT there, carried here as written, the notes' `skep.host` the
// configured suffix and its ⟨the owner's address⟩ the `--reply-to` address);
// `DRAFT`, words this crate wrote where no ruled text exists, each for the
// notes' §12 and the copy inventory; `RULED`, ruled words carried verbatim;
// and `RULED-SUBSTANCE / DRAFT-WORDING`, a ruled sentence the notes give as
// a bullet, put in this crate's words. A `{slot}` is filled where the row is
// shown: `{suffix}`, `{reply_to}`, `{status}`, `{origin}`, `{principal}`,
// `{account}`.

/// One row of the strings table: where its words come from, and the words.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Words {
    /// `D-1` … `D-9`, `DRAFT`, `RULED`, or `RULED-SUBSTANCE / DRAFT-WORDING`.
    pub id: &'static str,
    /// The words, slots unfilled.
    pub text: &'static str,
}

// The sign-up page — no ruled string exists for it.

/// The sign-up page's lead.
pub const SIGNUP_LEAD: Words = Words { id: "DRAFT", text: "Leave your email address to ask for a board of your own under {suffix}. An invitation, when one is sent, comes to this address." };
/// What is kept, said where the address is asked for.
pub const SIGNUP_KEPT: Words = Words { id: "DRAFT", text: "Your address is kept in a file on this service's machine, read by the people who run it, for the invitation alone." };
/// The address field's label.
pub const ADDRESS_LABEL: Words = Words { id: "DRAFT", text: "Your email address" };
/// The sign-up form's button.
pub const SIGNUP_BUTTON: Words = Words { id: "DRAFT", text: "Sign up" };
/// The address refused by the rule.
pub const SIGNUP_REFUSED: Words = Words { id: "DRAFT", text: "That is not an email address. Check it and send it again." };
/// The address could not be written down.
pub const SIGNUP_FAILED: Words = Words { id: "DRAFT", text: "Your address could not be kept just now. Try again later." };
/// The thanks page.
pub const THANKS: Words = Words { id: "DRAFT", text: "Thank you: your address is kept. An invitation, when one is sent, comes to it." };

// The claim form.

/// The claim form's lead.
pub const LEAD: Words = Words { id: "D-1", text: "A board of your own at a name under {suffix}. Your keys stay on your device: this page makes none." };
/// The name field's label.
pub const NAME_LABEL: Words = Words { id: "D-2", text: "Your board's name" };
/// The name field's help.
pub const NAME_HELP: Words = Words { id: "D-2", text: "one label: letters, digits and hyphens; it becomes ⟨name⟩.{suffix}" };
/// The record field's label.
pub const RECORD_LABEL: Words = Words { id: "D-3", text: "Your record" };
/// The record field's help.
pub const RECORD_HELP: Words = Words {
    id: "D-3",
    text: "On your own device run `skep keygen --anchors --anchor-out <a> --anchor-out <b>` (two papers, kept apart) or `skep keygen --payload`, and paste the one line it printed. Paste only what it printed: it holds no private key.",
};
/// The invite field's label.
pub const INVITE_LABEL: Words = Words { id: "D-9", text: "Your invite code" };
/// The claim form's button.
pub const CLAIM_BUTTON: Words = Words { id: "DRAFT", text: "Make my board" };

// The claim's refusals, each shown on the form again.

/// The name refused: taken, or not one label.
pub const NAME_REFUSED: Words = Words { id: "D-4", text: "That name is taken, or is not one label of letters, digits and hyphens. Choose another." };
/// The record refused: not a record `skep keygen` printed.
pub const RECORD_REFUSED: Words = Words { id: "D-5", text: "This is not a record skep keygen printed. Paste the whole line, exactly as printed." };
/// The record refused: a preview-kind key.
pub const PREVIEW_REFUSED: Words =
    Words { id: "D-6", text: "This record names a preview key. A hosted board enrolls the production kind alone: make the record again with a client that generates it." };
/// The invite code refused: not in the file, or spent.
pub const INVITE_REFUSED: Words = Words { id: "DRAFT", text: "That invite code is not one this service issued, or it has been used. Check the link your invitation came with." };

// The status page.

/// While the post waits or its steps run.
pub const BEING_MADE: Words = Words { id: "D-7", text: "Your board is being made. Keep this page open: it shows your board when it is live." };
/// The status address, shown with D-7.
pub const STATUS_ADDRESS: Words = Words { id: "DRAFT", text: "This page's own address, to come back to: {status}" };
/// The post failed, or the queue was full.
pub const FAILED: Words = Words { id: "D-8", text: "Your board could not be made. Nothing stands under your name; try again later, or write to {reply_to}." };

// THE REPLY — "Your board is live." (the notes §4: "The customer's reply,
// the one carrier", cs6-S2), composed by `reply` for the page and the mail
// alike: the four ruled strings, the three facts, the two acts, the status
// address last. Of the four, the `local_trust` clause (AUTH-4.52's reach,
// the notes' third bullet) has NO ROW: this service never shows it — its
// `/health` guard refuses `local_trust: true` as a failed step (D-8), so no
// reply it renders can carry the clause, and no words are written for it.

/// The reply's heading: the notes' own name for the message (§4 step 5).
pub const LIVE: Words = Words { id: "DRAFT", text: "Your board is live." };
/// THE OPERATOR SENTENCE, create-org keyed (AUTH-5.43's create-org sibling;
/// AUTH-5.54 (a); AUTH-4.54) — ALWAYS shown.
pub const OPERATOR: Words = Words {
    id: "RULED-SUBSTANCE / DRAFT-WORDING",
    text: "The party that runs this board can write as you here, visibly and permanently; it can read what you write before you publish it; and on this board it can retire your keys and continue as you. You are this board's own claimant, and the board is portable: it can move with you to another host.",
};
/// THE ANCHORLESS SENTENCE (AUTH-5.62; AUTH-5.16's second arm; AUTH-5.32's
/// hop) — shown IFF the record carried no anchor-flagged entry.
pub const ANCHORLESS: Words = Words {
    id: "RULED-SUBSTANCE / DRAFT-WORDING",
    text: "Your record named no anchor key, so this account has no paper tier: `skep recover` will never be available on it. While a device of yours is signed in, `skep enroll` run from it adds another — the one way this account gains a device.",
};
/// THE PUBLIC-VENUE STATEMENT (AUTH-5.85; PUB-5.25's string with the claim
/// door's parenthetical) — ALWAYS shown, VERBATIM as the notes quote it,
/// its lowercase opening and its want of a closing period included.
pub const PUBLIC_VENUE: Words = Words {
    id: "RULED",
    text: "every edit to this page, including what you later remove, is public history — and the records this page holds (your keys, your claim, the grants you issue) stand as records of their own, so removing the text one names does not remove it: the record stays in force, and the version you removed it from remains readable",
};
/// THE THREE FACTS (AUTH-5.76's channel), as the `skep` command spells them
/// (`print_facts`), the origin the PUBLIC one.
pub const FACTS: Words = Words { id: "RULED", text: "account {account}\nprincipal {principal}\norigin {origin}" };
/// THE FIRST ACT (AUTH-4.58's detection): the `skep` command's own format
/// string (`skep claim --hosted`'s fifth DATA line), the public origin in
/// the dialed one's place.
pub const FIRST_ACT: Words = Words {
    id: "RULED",
    text: "first act: from the device that generated the payload run `skep verify --board {origin} --principal {principal} --payload <the record it printed>` (or `--anchor <a> --anchor <b>`): the genesis record compared entry for entry, fingerprint and anchor flag, against what that device composed — it confirms the keys on the board, and it cannot tell you the board will open a session for you",
};
/// THE SECOND ACT, with AUTH-5.87's sentence: the `skep` command's own line
/// (`skep claim --hosted`'s sixth), its `<origin>` filled with the public
/// origin.
pub const SECOND_ACT: Words = Words {
    id: "RULED",
    text: "second act: in your first signed session the setup act runs — `skep claim --board {origin} --dir <store>` from that device performs it: creating your account also creates a space for your agents beneath it, and its home",
};
/// The status address, last in the reply.
pub const REPLY_STATUS: Words = Words { id: "DRAFT", text: "This reply stays at {status}" };
/// The follow-up mail's subject.
pub const MAIL_SUBJECT: Words = Words { id: "DRAFT", text: "Your board is live" };

// The answers outside the routes.

/// A route or a status token this program does not hold (404).
pub const NOT_FOUND: Words = Words { id: "DRAFT", text: "There is no page here." };
/// A body the form decoder refused, or a request outside the subset (400).
pub const BAD_FORM: Words = Words { id: "DRAFT", text: "This form could not be read. Go back and send it again." };
/// A body past the cap (413).
pub const TOO_LARGE: Words = Words { id: "DRAFT", text: "This form is too large to read. Go back and check what you pasted: a record is one line." };

// ── THE CAPS AND THE DEADLINES ───────────────────────────────────────────

/// THE HEAD's CAP: a browser's request line and headers, with room — the
/// site sets no cookie.
pub const MAX_HEAD: usize = 16 * 1024;

/// THE BODY's CAP: 397,312 bytes — a record at its cap (`MAX_RECORD_BYTES`,
/// 128 KiB, AUTH-1.18) with EVERY byte percent-encoded, three bytes each,
/// which no record is (its hex digits travel as they are), and 4 KiB for
/// the name, the invite, the field names and the separators. So any record
/// `parse_enroll` could admit fits the form, and nothing much larger is
/// read.
pub const MAX_BODY: usize = 3 * MAX_RECORD_BYTES + 4096;

/// The socket's read deadline: a stalled client releases its thread.
pub const READ_TIMEOUT: Duration = Duration::from_secs(30);

/// The socket's write deadline.
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// How often a page showing D-7 refreshes itself to the status address.
pub const REFRESH_SECS: u32 = 5;

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

/// A row's words with its slots filled; a slot not named stays as written.
pub fn fill(words: Words, slots: &[(&str, &str)]) -> String {
    let mut text = words.text.to_owned();
    for (slot, value) in slots {
        text = text.replace(&format!("{{{slot}}}"), value);
    }
    text
}

// ── THE ANSWERS ──────────────────────────────────────────────────────────

/// One answer: its status and its page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    /// 200, 400, 404 or 413.
    pub status: u16,
    /// The page's HTML.
    pub body: String,
}

/// THE HEADERS every page carries: no script and nothing from elsewhere,
/// stated to the browser as the page is written — a style in the page
/// alone, a form posting here alone, no frame — no referrer, so a status
/// address never rides a request off this site, and no type sniffing.
pub fn headers() -> Vec<(String, String)> {
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
pub fn refused_answer(refused: &Refused, site: &Site) -> Answer {
    match refused {
        Refused::TooLarge { .. } => Answer { status: 413, body: page(site, None, &paragraph(&fill(TOO_LARGE, &[]))) },
        Refused::Malformed(_) => Answer { status: 400, body: page(site, None, &paragraph(&fill(BAD_FORM, &[]))) },
    }
}

/// THE DISPATCH: one request, one answer.
pub fn answer(request: &Request, site: &Site, desk: &dyn Desk) -> Answer {
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
pub fn refusal_words(refusal: Refusal) -> Words {
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
    let suffix = text(&site.suffix);
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
        text(&fill(ADDRESS_LABEL, &slots)),
        attr(address),
        text(&fill(SIGNUP_KEPT, &slots)),
        text(&fill(SIGNUP_BUTTON, &slots)),
    ));
    page(site, None, &body)
}

/// THE CLAIM FORM: D-1, a refusal where one is shown, the three fields —
/// D-2's name, D-3's record, D-9's invite — each pre-filled with what the
/// post sent, or the invite with the link's code, and the button.
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
        text(&fill(NAME_LABEL, &slots)),
        text(&fill(NAME_HELP, &slots)),
        attr(&String::from_utf8_lossy(post.name)),
        text(&fill(RECORD_LABEL, &slots)),
        text(&fill(RECORD_HELP, &slots)),
        text(&String::from_utf8_lossy(post.record)),
        text(&fill(INVITE_LABEL, &slots)),
        attr(&String::from_utf8_lossy(post.invite)),
        text(&fill(CLAIM_BUTTON, &slots)),
    ));
    page(site, None, &body)
}

/// D-7's PAGE: D-7 and the status address, refreshing to it.
fn being_made(site: &Site, token: &str) -> String {
    let address = status_address(&site.suffix, token);
    let body = paragraph(&fill(BEING_MADE, &[])) + &paragraph(&fill(STATUS_ADDRESS, &[("status", &address)]));
    page(site, Some(&format!("/status/{token}")), &body)
}

/// One paragraph of plain text.
fn paragraph(words: &str) -> String {
    format!("<p>{}</p>\n", text(words))
}

/// One paragraph marked as a refusal.
fn refused_paragraph(words: &str) -> String {
    format!("<p class=\"refused\">{}</p>\n", text(words))
}

/// A reply's text as paragraphs: one per blank-line-separated block, its
/// lines kept apart by `<br>`, the text's closing line break no line.
pub fn paragraphs(reply: &str) -> String {
    reply.trim_end_matches('\n').split("\n\n").filter(|block| !block.is_empty()).map(|block| format!("<p>{}</p>\n", block.split('\n').map(text).collect::<Vec<_>>().join("<br>\n"))).collect()
}

/// TEXT for an element's content: `&`, `<` and `>` escaped, and a span
/// between two backticks set as `<code>` — the table's commands — where the
/// backticks pair up; where they do not, every backtick stays as written.
pub fn text(words: &str) -> String {
    let spans: Vec<&str> = words.split('`').collect();
    if spans.len().is_multiple_of(2) {
        return escape(words, false);
    }
    spans.iter().enumerate().map(|(i, span)| if i % 2 == 1 { format!("<code>{}</code>", escape(span, false)) } else { escape(span, false) }).collect()
}

/// TEXT for an attribute's value: the quotes escaped as well.
pub fn attr(words: &str) -> String {
    escape(words, true)
}

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
