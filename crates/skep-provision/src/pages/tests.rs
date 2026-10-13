//! THE PAGES and THE REQUESTS THEY ANSWER over a desk the suite scripts:
//! every request's status and page — the sign-up page and its thanks, the
//! claim form with the link's code, each refusal shown on the form again,
//! D-7 with the status URL and its refresh every five seconds, the live
//! reply, D-8, 404 — a bad body 400, a fourth field among them, a body past
//! the cap 413; the connection's budgets the figures the operator is told —
//! a 16 KiB head, a minute each way — its two socket timeouts set before it
//! reads, thirty seconds each, so a silent peer is let go, a request
//! trickled past its deadline answered 400 in the answer's own, and a
//! trickle cut at its deadline both ways; the invite link opening the claim
//! form with its code; plain HTML with no script and nothing fetched from
//! elsewhere, every header that says so checked whole; every row a page shows
//! filled with the site's two slots, the suffix and the owner's address,
//! whichever page shows it; a row's words escaped and its commands set as
//! code; the one escaper keeping the quotes within an element's content and
//! escaping them within an attribute's value; a person's field — a refused
//! record among them — shown back as it was sent, a quote in it never closing
//! its attribute; and the `Debug` of a post, a status page and an answer
//! showing none of what they hold. (The strings table's rows are `strings`'
//! suite.)

use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::Mutex;

use super::*;

/// A desk that answers what the test set, and keeps what it was asked.
#[derive(Default)]
struct Scripted {
    admit: Mutex<Option<Result<String, Refusal>>>,
    sign_up: Mutex<Option<Result<(), SignUpRefusal>>>,
    status: Mutex<Option<Shown>>,
    asked: Mutex<Vec<String>>,
}

impl Desk for Scripted {
    fn sign_up(&self, address: &[u8]) -> Result<(), SignUpRefusal> {
        self.asked.lock().unwrap().push(format!("sign_up {}", String::from_utf8_lossy(address)));
        self.sign_up.lock().unwrap().unwrap_or(Ok(()))
    }

    fn admit(&self, post: &Post<'_>) -> Result<String, Refusal> {
        self.asked.lock().unwrap().push(format!("admit {} {} {}", String::from_utf8_lossy(post.name), post.record.len(), String::from_utf8_lossy(post.invite)));
        self.admit.lock().unwrap().clone().unwrap_or(Ok("t0k3n".into()))
    }

    fn status(&self, token: &str) -> Option<Shown> {
        self.asked.lock().unwrap().push(format!("status {token}"));
        self.status.lock().unwrap().clone()
    }
}

fn site() -> Site {
    Site { suffix: "skep.host".into(), owner_address: "owner@skep.host".into() }
}

/// One request, as the subset reads it.
fn request(method: &str, target: &str, body: &[u8]) -> Request {
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p.to_owned(), Some(q.to_owned())),
        None => (target.to_owned(), None),
    };
    Request { method: method.into(), path, query, headers: Vec::new(), body: body.to_vec() }
}

/// `GET /`: the sign-up page — the lead, the address field, what is kept,
/// the button — at 200, plain HTML with no script and nothing fetched.
#[test]
fn the_sign_up_page_asks_for_an_address_with_no_script_and_nothing_fetched() {
    let answer = answer(&request("GET", "/", b""), &site(), &Scripted::default());
    assert_eq!(answer.status, 200);
    for words in [SIGNUP_LEAD, ADDRESS_LABEL, SIGNUP_KEPT, SIGNUP_BUTTON] {
        assert!(answer.body.contains(&row(&site().fill(words))), "{words:?}");
    }
    assert!(answer.body.contains("action=\"/signup\""));
    for absent in ["<script", "src=", "href=", "<link", "http://", "https://"] {
        assert!(!answer.body.contains(absent), "{absent}");
    }
}

/// `POST /signup`: the desk keeps the address and the thanks page answers;
/// a refused address shows its DRAFT string on the page again, the field
/// as sent; a failed write its own.
#[test]
fn a_sign_up_is_thanked_and_a_refused_address_shown_again_as_sent() {
    let desk = Scripted::default();
    let thanks = answer(&request("POST", "/signup", b"address=person%40example.com"), &site(), &desk);
    assert_eq!(thanks.status, 200);
    assert!(thanks.body.contains(&row(&site().fill(THANKS))));
    assert_eq!(desk.asked.lock().unwrap().as_slice(), ["sign_up person@example.com"]);
    *desk.sign_up.lock().unwrap() = Some(Err(SignUpRefusal::NotAnAddress));
    let refused = answer(&request("POST", "/signup", b"address=not+one"), &site(), &desk);
    assert_eq!(refused.status, 200);
    assert!(refused.body.contains(&format!("<p class=\"refused\">{}</p>", row(&site().fill(SIGNUP_REFUSED)))));
    assert!(refused.body.contains("value=\"not one\""));
    *desk.sign_up.lock().unwrap() = Some(Err(SignUpRefusal::Failed));
    let failed = answer(&request("POST", "/signup", b"address=a%40b"), &site(), &desk);
    assert_eq!(failed.status, 200);
    assert!(failed.body.contains(&row(&site().fill(SIGNUP_FAILED))));
}

/// `GET /claim?invite=<code>`: the claim form — D-1, D-2's label and help,
/// D-3's label and help, D-9 — the invite field pre-filled with the link's
/// code, at 200.
#[test]
fn the_claim_form_carries_the_ruled_strings_and_the_links_code() {
    let answer = answer_of("GET", "/claim?invite=1.1.0.1.0.3", b"");
    assert_eq!(answer.status, 200);
    for words in [CLAIM_LEAD, NAME_LABEL, NAME_HELP, RECORD_LABEL, RECORD_HELP, INVITE_LABEL, CLAIM_BUTTON] {
        assert!(answer.body.contains(&row(&site().fill(words))), "{words:?}");
    }
    assert!(answer.body.contains("id=\"invite\" name=\"invite\" required autocomplete=\"off\" spellcheck=\"false\" value=\"1.1.0.1.0.3\""));
    assert!(answer.body.contains("<code>skep keygen --anchors --anchor-out &lt;a&gt; --anchor-out &lt;b&gt;</code>"), "the commands set as code, escaped");
    let bare = answer_of("GET", "/claim", b"");
    assert!(bare.body.contains("value=\"\""), "no code where the link carries none");
}

fn answer_of(method: &str, target: &str, body: &[u8]) -> Answer {
    answer(&request(method, target, body), &site(), &Scripted::default())
}

/// THE INVITE LINK, `https://<suffix>/claim?invite=<code>`, opens the claim
/// form with its code: the path and the query it names, asked of the pages,
/// answer the form, its invite field pre-filled.
#[test]
fn the_invite_link_opens_the_claim_form_with_its_code() {
    let link = invite_link("skep.host", &InviteCode::parse("1.1.0.1.0.3").expect("a code"));
    assert_eq!(link, "https://skep.host/claim?invite=1.1.0.1.0.3");
    let target = link.strip_prefix("https://skep.host").expect("the site's own host");
    let form = answer_of("GET", target, b"");
    assert_eq!(form.status, 200);
    assert!(form.body.contains("id=\"invite\" name=\"invite\" required autocomplete=\"off\" spellcheck=\"false\" value=\"1.1.0.1.0.3\""), "{}", form.body);
}

/// `POST /claim`: the three fields reach the desk; EACH REFUSAL shows its
/// words on the form again at 200 — D-4, D-5, D-6, the invite's DRAFT row,
/// D-8 for a full queue and a failure — the fields pre-filled as sent.
#[test]
fn each_claim_refusal_is_shown_on_the_form_again() {
    let desk = Scripted::default();
    let body = b"name=alice&record=%7B%22type%22%7D%0D%0A&invite=c0de";
    for (refusal, words) in
        [(Refusal::Name, NAME_REFUSED), (Refusal::Record, RECORD_REFUSED), (Refusal::Preview, PREVIEW_REFUSED), (Refusal::Invite, INVITE_REFUSED), (Refusal::Busy, FAILED), (Refusal::Failed, FAILED)]
    {
        *desk.admit.lock().unwrap() = Some(Err(refusal));
        let answer = answer(&request("POST", "/claim", body), &site(), &desk);
        assert_eq!(answer.status, 200, "{refusal:?}");
        let shown = row(&site().fill(words));
        assert!(answer.body.contains(&format!("<p class=\"refused\">{shown}</p>")), "{refusal:?}");
        assert!(answer.body.contains("value=\"alice\"") && answer.body.contains("{\"type\"}\r\n</textarea>") && answer.body.contains("value=\"c0de\""), "{refusal:?}");
    }
    assert!(site().fill(FAILED).contains("try again later, or write to owner@skep.host."));
    assert_eq!(desk.asked.lock().unwrap()[0], "admit alice 10 c0de", "the record's ten bytes, its CRLF among them");
}

/// `POST /claim` ADMITTED: D-7 and the status URL, no redirect, the page
/// refreshing to the status URL every five seconds — the README's figure.
#[test]
fn an_admitted_post_answers_d7_with_its_status_url() {
    let answer = answer_of("POST", "/claim", b"name=alice&record=x&invite=c0de");
    assert_eq!(answer.status, 200);
    assert!(answer.body.contains(&row(&site().fill(BEING_MADE))));
    assert!(answer.body.contains("This page's own address, to come back to: https://skep.host/status/t0k3n"));
    assert!(answer.body.contains("https://skep.host/status/t0k3n"));
    assert!(answer.body.contains("<meta http-equiv=\"refresh\" content=\"5; url=/status/t0k3n\">"), "{}", answer.body);
}

/// `GET /status/<token>`: D-7 while queued or running, the live reply once
/// live, D-8 once failed, 404 for a token the desk does not hold — and for
/// a path that is no token.
#[test]
fn the_status_page_shows_d7_the_live_reply_d8_or_404() {
    let desk = Scripted::default();
    *desk.status.lock().unwrap() = Some(Shown::BeingMade);
    let being = answer(&request("GET", "/status/t0k3n", b""), &site(), &desk);
    assert_eq!(being.status, 200);
    assert!(being.body.contains(&row(&site().fill(BEING_MADE))) && being.body.contains("url=/status/t0k3n"));
    *desk.status.lock().unwrap() = Some(Shown::Live("Your board is live.\n\naccount 1.0.1\nprincipal 1\n\nrun `skep verify <x>`\n".into()));
    let live = answer(&request("GET", "/status/t0k3n", b""), &site(), &desk);
    assert_eq!(live.status, 200);
    assert!(live.body.contains("<p>Your board is live.</p>\n<p>account 1.0.1<br>\nprincipal 1</p>\n<p>run <code>skep verify &lt;x&gt;</code></p>"), "{}", live.body);
    assert!(!live.body.contains("http-equiv"), "the live page does not refresh");
    *desk.status.lock().unwrap() = Some(Shown::Failed);
    let failed = answer(&request("GET", "/status/t0k3n", b""), &site(), &desk);
    assert_eq!(failed.status, 200);
    assert!(failed.body.contains(&row(&site().fill(FAILED))));
    *desk.status.lock().unwrap() = None;
    assert_eq!(answer(&request("GET", "/status/other", b""), &site(), &desk).status, 404);
    let asked = desk.asked.lock().unwrap().len();
    assert_eq!(answer(&request("GET", "/status/", b""), &site(), &desk).status, 404);
    assert_eq!(answer(&request("GET", "/status/a/b", b""), &site(), &desk).status, 404);
    assert_eq!(desk.asked.lock().unwrap().len(), asked, "a path that is no token never reaches the desk");
}

/// Every other request is 404; a body the decoder refuses is 400 — a bad
/// escape, or a fourth field, which no form of this site's posts — and a
/// claim link whose query names a fourth opens the form unfilled.
#[test]
fn every_other_request_is_404_and_a_bad_body_400() {
    for (method, target) in [("POST", "/"), ("GET", "/signup"), ("PUT", "/claim"), ("GET", "/status"), ("GET", "/favicon.ico"), ("HEAD", "/")] {
        let answer = answer_of(method, target, b"");
        assert_eq!(answer.status, 404, "{method} {target}");
        assert!(answer.body.contains(&row(&site().fill(NOT_FOUND))));
    }
    assert_eq!(answer_of("POST", "/claim", b"name=%zz").status, 400);
    assert_eq!(answer_of("POST", "/signup", b"address=%4").status, 400);
    let desk = Scripted::default();
    for (path, body) in [("/claim", &b"name=alice&record=x&invite=c0de&x=y"[..]), ("/signup", b"address=a%40b&x&y&z")] {
        let refused = answer(&request("POST", path, body), &site(), &desk);
        assert_eq!(refused.status, 400, "{path}");
        assert!(refused.body.contains(&row(&site().fill(BAD_FORM))), "{path}");
    }
    assert!(desk.asked.lock().unwrap().is_empty(), "a body of four fields reached the desk");
    let unfilled = answer_of("GET", "/claim?invite=c0de&a&b&c", b"");
    assert_eq!(unfilled.status, 200);
    assert!(unfilled.body.contains("id=\"invite\" name=\"invite\" required autocomplete=\"off\" spellcheck=\"false\" value=\"\""), "{}", unfilled.body);
}

/// The subset's refusals: past the cap 413, anything else 400.
#[test]
fn the_subsets_refusals_are_413_and_400() {
    assert_eq!(refused_answer(&Refused::TooLarge { declared: MAX_BODY + 1, cap: MAX_BODY }, &site()).status, 413);
    assert_eq!(refused_answer(&Refused::Malformed("x".into()), &site()).status, 400);
    assert_eq!(MAX_BODY, 397_312, "a record at its cap, every byte percent-encoded, and 4 KiB");
}

/// THE CONNECTION's BUDGETS ARE THE DOCUMENTS' FIGURES: a head refused past
/// 16 KiB and a minute for each transfer, as the crate's README tells the
/// operator — and RUNBOOK §10 step 10 the minute — so a change to either
/// figure is a change to what the operator is told.
#[test]
fn the_connections_budgets_are_the_documents_figures() {
    assert_eq!(MAX_HEAD, 16 * 1024, "a head past 16 KiB is 400");
    assert_eq!(TRANSFER_DEADLINE, Duration::from_secs(60), "a minute in and a minute out");
}

/// THE CONNECTION over a real socket: a page with the headers that say no
/// script, nothing from elsewhere, no frame and no referrer, each whole to
/// its line's end; and a declared body past the cap answered 413 before any
/// of it is sent.
#[test]
fn a_connection_answers_with_its_headers_and_refuses_a_body_past_the_cap() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("a port");
    let port = listener.local_addr().expect("its address").port();
    let serve = std::thread::spawn(move || {
        for _ in 0..2 {
            let (stream, _) = listener.accept().expect("a connection");
            connection(stream, &site(), &Scripted::default());
        }
    });
    let talk = |head: &str| {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("connected");
        stream.write_all(head.as_bytes()).expect("written");
        let _ = stream.shutdown(Shutdown::Write);
        let mut raw = String::new();
        stream.read_to_string(&mut raw).expect("an answer");
        raw
    };
    let page = talk("GET / HTTP/1.1\r\nHost: skep.host\r\n\r\n");
    assert!(page.starts_with("HTTP/1.1 200 OK\r\n"), "{page}");
    for header in [
        "Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
        "Referrer-Policy: no-referrer",
        "X-Content-Type-Options: nosniff",
        "Content-Type: text/html; charset=utf-8",
    ] {
        assert!(page.contains(&format!("\r\n{header}\r\n")), "{header}: {page}");
    }
    let too_large = talk(&format!("POST /claim HTTP/1.1\r\nHost: skep.host\r\nContent-Length: {}\r\n\r\n", MAX_BODY + 1));
    assert!(too_large.starts_with("HTTP/1.1 413 Payload Too Large\r\n"), "{too_large}");
    serve.join().expect("served");
}

/// A peer that trickles: one byte a call, each after a pause — never
/// silent long enough for a socket's own timeout — the head of a request
/// that never ends, or a reader that drains an answer a byte at a time.
struct Trickle {
    pause: Duration,
    sent: Vec<u8>,
    drained: usize,
}

impl Trickle {
    fn new(pause: Duration) -> Trickle {
        Trickle { pause, sent: b"GET / HTTP/1.1\r\nX-Trickle: ".to_vec(), drained: 0 }
    }
}

impl Read for Trickle {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        std::thread::sleep(self.pause);
        let Some(first) = buf.first_mut() else { return Ok(0) };
        *first = self.sent.get(self.drained).copied().unwrap_or(b'a');
        self.drained += 1;
        Ok(1)
    }
}

impl Write for Trickle {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        std::thread::sleep(self.pause);
        Ok(usize::from(!buf.is_empty()))
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// THE TRANSFER DEADLINE, BOTH WAYS, over a peer that trickles a byte a
/// millisecond: a request's head that never ends is refused once its
/// deadline passes — never read to the head's cap, sixteen seconds on — and
/// an answer drained a byte at a time is cut at its own, `TimedOut`, never
/// written whole, twenty seconds on.
#[test]
fn a_trickle_is_cut_at_its_deadline_both_ways() {
    let started = Instant::now();
    let mut peer = Trickle::new(Duration::from_millis(1));
    let read = read_request(&mut Deadlined { stream: &mut peer, until: Instant::now() + Duration::from_millis(100) }, Limits { max_head: MAX_HEAD, max_body: MAX_BODY });
    assert!(matches!(&read, Err(Refused::Malformed(why)) if why.contains("deadline")), "{read:?}");
    assert!(peer.drained < 4096, "{} bytes read past the deadline", peer.drained);
    let wrote = Deadlined { stream: &mut peer, until: Instant::now() + Duration::from_millis(100) }.write_all(&[b'x'; 20_000]);
    assert_eq!(wrote.map_err(|e| e.kind()), Err(std::io::ErrorKind::TimedOut));
    assert!(started.elapsed() < Duration::from_secs(5), "{:?}", started.elapsed());
}

/// THE CONNECTION's TWO DEADLINES over a real socket: a head trickled a
/// byte every 100 ms — each read far inside the socket's own 30-second
/// timeout — is refused once the request's deadline passes, and the refusal,
/// 400, is still delivered in the answer's own: one shared window would
/// leave none in which to say it.
#[test]
fn a_trickling_request_is_answered_400_at_its_deadline() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("a port");
    let client = TcpStream::connect(listener.local_addr().expect("its address")).expect("connected");
    let (server, _) = listener.accept().expect("a connection");
    let serve = std::thread::spawn(move || connection_within(server, &site(), &Scripted::default(), Duration::from_millis(500)));
    let mut trickle = client.try_clone().expect("a second handle");
    std::thread::spawn(move || {
        for b in b"GET / HTTP/1.1\r\nX-Trickle: ".iter().chain(std::iter::repeat(&b'a')) {
            if trickle.write_all(&[*b]).is_err() {
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    });
    let (said, heard) = std::sync::mpsc::channel();
    let mut reader = client;
    std::thread::spawn(move || {
        let mut raw = Vec::new();
        let _ = reader.read_to_end(&mut raw);
        let _ = said.send(raw);
    });
    let raw = heard.recv_timeout(Duration::from_secs(10)).expect("the trickle was read past its deadline");
    assert!(raw.starts_with(b"HTTP/1.1 400 Bad Request\r\n"), "{}", String::from_utf8_lossy(&raw));
    serve.join().expect("served");
}

/// SILENCE ENDS A READ: before it reads a byte the connection sets its
/// socket's own timeouts — thirty seconds of a peer's silence ends a read,
/// thirty of a stalled write a write — so a peer that connects and sends
/// nothing holds a connection thread thirty seconds and no longer; the
/// transfer deadline, checked only between socket calls, cannot end a read
/// that never returns. Read off a second handle on the socket, which shares
/// its options, while the client is still silent.
#[test]
fn a_connection_sets_its_sockets_timeouts_before_it_reads() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("a port");
    let mut client = TcpStream::connect(listener.local_addr().expect("its address")).expect("connected");
    let (server, _) = listener.accept().expect("a connection");
    let watch = server.try_clone().expect("a second handle on the socket");
    let serve = std::thread::spawn(move || connection_within(server, &site(), &Scripted::default(), Duration::from_secs(5)));
    let deadline = Instant::now() + Duration::from_secs(5);
    let timeouts = loop {
        let timeouts = (watch.read_timeout().expect("its read timeout"), watch.write_timeout().expect("its write timeout"));
        if timeouts.0.is_some() && timeouts.1.is_some() {
            break timeouts;
        }
        assert!(Instant::now() < deadline, "the connection waits on a silent peer with no timeout of its own, {timeouts:?}: one would hold its thread for good");
        std::thread::sleep(Duration::from_millis(10));
    };
    assert_eq!(timeouts, (Some(Duration::from_secs(30)), Some(Duration::from_secs(30))), "thirty seconds of silence, each way");
    client.write_all(b"GET / HTTP/1.1\r\nHost: skep.host\r\n\r\n").expect("the request");
    serve.join().expect("served");
    drop(watch);
    let mut raw = String::new();
    client.read_to_string(&mut raw).expect("the answer");
    assert!(raw.starts_with("HTTP/1.1 200 OK\r\n"), "{raw}");
}

/// A ROW escapes `&`, `<` and `>` and sets paired backticks as code, an
/// unpaired one kept; an attribute escapes the quotes too.
#[test]
fn a_row_is_escaped_and_its_commands_set_as_code() {
    assert_eq!(row("a < b & `c > d` \"e\" 'f'"), "a &lt; b &amp; <code>c &gt; d</code> \"e\" 'f'");
    assert_eq!(row("one ` alone"), "one ` alone");
    assert_eq!(attr("\"><script>'"), "&quot;&gt;&lt;script&gt;&#39;");
    assert_eq!(paragraphs("a\nb\n\nc\n"), "<p>a<br>\nb</p>\n<p>c</p>\n");
}

/// THE ONE ESCAPER BY WHERE ITS TEXT IS SET: within an element's content
/// the quotes stay as written — the textarea gives a record back as sent —
/// and within an attribute's value both are escaped, so no quote a person
/// sent ends the value it sits in; `&`, `<` and `>` are escaped within both.
#[test]
fn the_escaper_escapes_the_quotes_within_an_attribute_alone() {
    let sent = "{\"label\":\"o'brien\"} <&>";
    assert_eq!(escape(sent, Within::Content), "{\"label\":\"o'brien\"} &lt;&amp;&gt;");
    assert_eq!(escape(sent, Within::Attribute), "{&quot;label&quot;:&quot;o&#39;brien&quot;} &lt;&amp;&gt;");
    assert_eq!(attr(sent), escape(sent, Within::Attribute));
}

/// EVERY PAGE FILLS THE SITE's TWO SLOTS: a row naming the suffix and the
/// owner's address shows both, whichever page shows it; D-7's page fills
/// the status URL beside them.
#[test]
fn every_page_fills_the_sites_two_slots() {
    assert_eq!(site().fill(Words { id: "DRAFT", text: "under {suffix}, write to {owner_address}" }), "under skep.host, write to owner@skep.host");
    assert_eq!(site().fill_with(STATUS_URL, &[("status_url", "https://skep.host/status/t0k3n")]), "This page's own address, to come back to: https://skep.host/status/t0k3n");
}

/// A REFUSED POST's RECORD COMES BACK AS SENT: a label's two backticks are
/// the person's, never the table's code — the form shows the record as it
/// was posted, and the next post sends it back whole.
#[test]
fn a_refused_record_comes_back_as_sent() {
    let desk = Scripted::default();
    *desk.admit.lock().unwrap() = Some(Err(Refusal::Name));
    let answer = answer(&request("POST", "/claim", b"name=alice&record=%7B%22label%22%3A%22%60work%60%22%7D&invite=c0de"), &site(), &desk);
    assert!(answer.body.contains("{\"label\":\"`work`\"}</textarea>"), "{}", answer.body);
    assert!(!answer.body.contains("<code>work</code>"), "{}", answer.body);
}

/// A PERSON's FIELD NEVER CLOSES ITS ATTRIBUTE: the invite link's query, a
/// refused post's name and invite, and a refused sign-up's address, each
/// holding a quote, come back with every quote escaped — never an attribute
/// of the sender's making on the page.
#[test]
fn a_persons_field_never_closes_its_attribute() {
    let link = answer_of("GET", "/claim?invite=%22%20autofocus%20x%3D%27", b"");
    assert!(link.body.contains("value=\"&quot; autofocus x=&#39;\""), "{}", link.body);
    let desk = Scripted::default();
    *desk.admit.lock().unwrap() = Some(Err(Refusal::Name));
    let post = answer(&request("POST", "/claim", b"name=%22n&record=x&invite=%22i"), &site(), &desk);
    assert!(post.body.contains("value=\"&quot;n\"") && post.body.contains("value=\"&quot;i\""), "{}", post.body);
    *desk.sign_up.lock().unwrap() = Some(Err(SignUpRefusal::NotAnAddress));
    let sign_up = answer(&request("POST", "/signup", b"address=%22a"), &site(), &desk);
    assert!(sign_up.body.contains("value=\"&quot;a\""), "{}", sign_up.body);
}

/// WHAT THE PAGES HOLD, `Debug`ged, shows none of it: a post by its fields'
/// lengths, a status page by its state and the live reply's length — its
/// last line the status URL — and an answer by its status and its page's
/// length, a refused post's record and code and a status URL among what the
/// page carries.
#[test]
fn the_debug_of_what_the_pages_hold_shows_none_of_it() {
    assert_eq!(format!("{:?}", Post { name: b"alice", record: b"{}", invite: b"c0de" }), "Post { name: 5, record: 2, invite: 4 }");
    let reply = format!("This reply stays at {}\n", status_url("skep.host", "t0k3n"));
    assert_eq!(format!("{:?}", Shown::Live(reply.clone())), format!("Live({})", reply.len()));
    assert_eq!(format!("{:?}", Shown::BeingMade), "BeingMade");
    assert_eq!(format!("{:?}", Shown::Failed), "Failed");
    let made = answer_of("POST", "/claim", b"name=alice&record=x&invite=c0de");
    assert!(made.body.contains("t0k3n"), "the page carries the status URL");
    assert_eq!(format!("{made:?}"), format!("Answer {{ status: 200, body: {} }}", made.body.len()));
    let desk = Scripted::default();
    *desk.admit.lock().unwrap() = Some(Err(Refusal::Name));
    let refused = answer(&request("POST", "/claim", b"name=alice&record=%7B%22k%22%7D&invite=c0de"), &site(), &desk);
    assert!(refused.body.contains("value=\"c0de\"") && refused.body.contains("{\"k\"}</textarea>"), "the form carries the post back");
    assert_eq!(format!("{refused:?}"), format!("Answer {{ status: 200, body: {} }}", refused.body.len()));
}
