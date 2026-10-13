//! T12 — THE SENDER: the real mailer's command is `<mailer> -t` and the
//! message goes on its stdin — pinned from the `Command`, and over a
//! recording script in the mailer's place; the fake records the headers and
//! the body; a refused send is retried up to its bound and then given up,
//! logged with neither the address nor the body — a relay's refusal, its
//! stderr naming the recipient, by its exit code alone — and a mailer that
//! cannot run is retried the same; the sender's thread delivers what the
//! worker hands it, the message made with the outbox's own `From:`,
//! `Reply-To:` and subject, and a hand-over never waits on a send stuck in
//! its try. (No send before the status is live, and the status live
//! throughout an outage, are the flow's — `flow/tests/provision.rs`.)

use std::path::Path;
use std::sync::Mutex;

use super::fake::{messages, FakeSender};
use super::*;
use crate::scratch::Scratch;

fn message() -> Message {
    Message {
        name: Name::parse(b"alice").expect("a name"),
        to: "person@example.com".into(),
        from: "noreply@skep.host".into(),
        reply_to: "owner@skep.host".into(),
        subject: "Your board is live".into(),
        body: "Your board is live.\n\nThis reply stays at https://skep.host/status/0123\n".into(),
    }
}

/// The lines a log closure kept.
fn kept() -> (Log, Arc<Mutex<Vec<String>>>) {
    let lines = Arc::new(Mutex::new(Vec::new()));
    let into = Arc::clone(&lines);
    (Arc::new(move |line: &str| into.lock().unwrap().push(line.to_owned())), lines)
}

/// T12: THE REAL COMMAND is the mailer and `-t`, nothing else.
#[test]
fn the_real_command_is_the_mailer_and_dash_t() {
    let cmd = command(Path::new("/usr/sbin/sendmail"));
    assert_eq!(cmd.get_program(), "/usr/sbin/sendmail");
    assert_eq!(cmd.get_args().collect::<Vec<_>>(), vec!["-t"]);
    assert_eq!(cmd.get_envs().count(), 0);
    assert_eq!(cmd.get_current_dir(), None);
}

/// T12: THE REAL MAILER over a recording script in the mailer's place: its
/// one argument `-t`, the message — headers and body — on its stdin, its
/// exit code answered.
#[cfg(unix)]
#[test]
fn the_real_mailer_hands_the_message_over_on_stdin() {
    use std::os::unix::fs::PermissionsExt;
    let dir = Scratch::new();
    let script = dir.path().join("sendmail");
    std::fs::write(&script, format!("#!/bin/sh\nprintf '%s\\n' \"$@\" > '{0}/argv'\ncat > '{0}/stdin'\nexit 75\n", dir.path().display())).expect("the script");
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).expect("executable");
    let exit = RelaySender::new(script).send(&message()).expect("the script ran");
    assert_eq!(exit.code, Some(75));
    assert_eq!(std::fs::read_to_string(dir.path().join("argv")).expect("the argv"), "-t\n");
    assert_eq!(std::fs::read_to_string(dir.path().join("stdin")).expect("the stdin"), message().text());
}

/// T12: THE FAKE RECORDS `To:`, `From:`, the subject and the body — the
/// message's text appended to its mail log, as the mailer would read it.
#[test]
fn the_fake_records_the_headers_and_the_body() {
    let dir = Scratch::new();
    let mail_log = dir.path().join("mail.log");
    let fake = FakeSender::new(mail_log.clone(), Vec::new());
    assert!(fake.send(&message()).expect("sent").ok());
    let sent = messages(&mail_log).expect("the mail log");
    assert_eq!(sent.len(), 1);
    let text = &sent[0];
    for header in ["To: person@example.com\n", "From: noreply@skep.host\n", "Reply-To: owner@skep.host\n", "Subject: Your board is live\n"] {
        assert!(text.contains(header), "{header}");
    }
    assert!(text.ends_with(&format!("\n\n{}", message().body)));
    assert_eq!(fake.tries().len(), 1);
}

/// T12: A REFUSED SEND IS RETRIED UP TO ITS BOUND — each try logged with
/// its exit code — AND THEN GIVEN UP, the sleeps between; nothing appended
/// to the mail log; neither the address nor the body in any line.
#[test]
fn a_refused_send_is_retried_to_its_bound_then_given_up() {
    let dir = Scratch::new();
    let mail_log = dir.path().join("mail.log");
    let fake = FakeSender::new(mail_log.clone(), vec![75; MAIL_TRIES as usize]);
    let (log, lines) = kept();
    let sleeps = Arc::new(Mutex::new(Vec::new()));
    let slept = Arc::clone(&sleeps);
    let sent = deliver(&fake, &message(), MAIL_TRIES, MAIL_INTERVAL, &move |d| slept.lock().unwrap().push(d), log.as_ref());
    assert!(!sent);
    assert_eq!(fake.tries().len(), MAIL_TRIES as usize);
    assert_eq!(sleeps.lock().unwrap().as_slice(), vec![MAIL_INTERVAL; MAIL_TRIES as usize - 1].as_slice());
    let lines = lines.lock().unwrap().clone();
    assert_eq!(lines.len(), MAIL_TRIES as usize + 1);
    assert_eq!(lines[0], format!("alice: mail: try 1 of {MAIL_TRIES} refused, exit 75"));
    assert!(lines.last().expect("a line").contains("given up after 7 tries; the board stands live"));
    assert!(lines.iter().all(|l| !l.contains("person@") && !l.contains("status/0123")), "{lines:?}");
    assert!(messages(&mail_log).expect("the mail log").is_empty());
}

/// A send refused twice, then accepted: sent at the third try.
#[test]
fn a_send_accepted_after_refusals_is_sent() {
    let dir = Scratch::new();
    let fake = FakeSender::new(dir.path().join("mail.log"), vec![75, 1, 0]);
    let (log, lines) = kept();
    assert!(deliver(&fake, &message(), MAIL_TRIES, MAIL_INTERVAL, &|_| {}, log.as_ref()));
    assert_eq!(fake.tries().len(), 3);
    assert_eq!(lines.lock().unwrap().last().map(String::as_str), Some("alice: mail: sent at try 3 of 7"));
}

/// A RELAY's REFUSAL NAMES THE RECIPIENT AND IS NEVER LOGGED: tries refused
/// with the address on the mailer's stderr — as a relay's 550 carries it —
/// are logged by their exit code alone, and no line carries the address.
#[test]
fn a_relays_refusal_is_logged_by_its_exit_code_alone() {
    /// A relay that refuses every try, naming the recipient on its stderr.
    struct Refuses;
    impl Sender for Refuses {
        fn send(&self, message: &Message) -> io::Result<Exit> {
            Ok(Exit { code: Some(75), stdout: Vec::new(), stderr: format!("550 5.1.1 <{}>: Recipient address rejected\n", message.to).into_bytes() })
        }
    }
    let (log, lines) = kept();
    assert!(!deliver(&Refuses, &message(), 2, MAIL_INTERVAL, &|_| {}, log.as_ref()));
    assert_eq!(
        *lines.lock().unwrap(),
        ["alice: mail: try 1 of 2 refused, exit 75", "alice: mail: try 2 of 2 refused, exit 75", "alice: mail: given up after 2 tries; the board stands live and its status page with it"]
    );
}

/// A MAILER THAT CANNOT RUN IS RETRIED like a refusal — each try logged by
/// the error's kind, the sleeps between — and the mail sent once it runs.
#[test]
fn a_mailer_that_cannot_run_is_retried() {
    /// A mailer absent for two tries, there at the third.
    struct Returns(Mutex<u32>);
    impl Sender for Returns {
        fn send(&self, _: &Message) -> io::Result<Exit> {
            let mut tries = self.0.lock().unwrap();
            *tries += 1;
            if *tries < 3 {
                return Err(io::Error::from(io::ErrorKind::NotFound));
            }
            Ok(Exit { code: Some(0), stdout: Vec::new(), stderr: Vec::new() })
        }
    }
    let (log, lines) = kept();
    let slept = Mutex::new(0);
    assert!(deliver(&Returns(Mutex::new(0)), &message(), MAIL_TRIES, MAIL_INTERVAL, &|_| *slept.lock().unwrap() += 1, log.as_ref()));
    let lines = lines.lock().unwrap().clone();
    assert_eq!(lines.len(), 3, "{lines:?}");
    assert!(lines[..2].iter().all(|l| l.contains("failed, the mailer could not run: ")), "{lines:?}");
    assert_eq!(lines[2], "alice: mail: sent at try 3 of 7");
    assert_eq!(*slept.lock().unwrap(), 2);
}

/// THE SENDER's THREAD delivers what is handed to it, on its own: the
/// board, the recipient and the body the worker hands over, and the
/// `From:`, `Reply-To:` and subject the outbox holds for every board.
#[test]
fn the_senders_thread_delivers_what_it_is_handed() {
    let dir = Scratch::new();
    let mail_log = dir.path().join("mail.log");
    let (log, _) = kept();
    let address = |text: &str| MailAddress::parse(text).expect("an address");
    let outbox = Outbox::spawn(Box::new(FakeSender::new(mail_log.clone(), Vec::new())), address("noreply@skep.host"), address("owner@skep.host"), log, Arc::new(|_| {})).expect("the thread");
    let handed = message();
    outbox.hand_over(handed.name.clone(), handed.to.clone(), handed.body.clone());
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while messages(&mail_log).expect("the mail log").is_empty() {
        assert!(std::time::Instant::now() < deadline, "the thread delivered nothing");
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert_eq!(messages(&mail_log).expect("the mail log"), vec![handed.text()]);
}

/// THE HAND-OVER NEVER WAITS ON A SEND: the sender's thread stuck inside a
/// try that does not end — a relay that hangs — three mails handed over
/// each return at once, so the worker goes on to its next post; once the
/// stuck try ends, every one is delivered, in the order handed over.
#[test]
fn a_hand_over_never_waits_on_a_send() {
    /// A sender whose every try waits for the test's word.
    struct Waits {
        word: Mutex<Receiver<()>>,
        sent: Arc<Mutex<Vec<String>>>,
    }
    impl Sender for Waits {
        fn send(&self, message: &Message) -> io::Result<Exit> {
            let _ = self.word.lock().unwrap().recv();
            self.sent.lock().unwrap().push(message.to.clone());
            Ok(Exit { code: Some(0), stdout: Vec::new(), stderr: Vec::new() })
        }
    }
    let (word, heard) = mpsc::channel();
    let sent = Arc::new(Mutex::new(Vec::new()));
    let (log, _) = kept();
    let address = |text: &str| MailAddress::parse(text).expect("an address");
    let waits = Waits { word: Mutex::new(heard), sent: Arc::clone(&sent) };
    let outbox = Outbox::spawn(Box::new(waits), address("noreply@skep.host"), address("owner@skep.host"), log, Arc::new(|_| {})).expect("the thread");
    let (handed, all_handed) = mpsc::channel();
    thread::spawn(move || {
        for to in ["first@example.com", "second@example.com", "third@example.com"] {
            outbox.hand_over(Name::parse(b"alice").expect("a name"), to.to_owned(), "Your board is live.\n".to_owned());
        }
        let _ = handed.send(());
    });
    all_handed.recv_timeout(Duration::from_secs(5)).expect("a hand-over waited on a send stuck in its try");
    for _ in 0..3 {
        word.send(()).expect("the sender waits for its word");
    }
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while sent.lock().unwrap().len() < 3 {
        assert!(std::time::Instant::now() < deadline, "the stuck mails were never delivered");
        thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(*sent.lock().unwrap(), ["first@example.com", "second@example.com", "third@example.com"]);
}

/// A message's `Debug` names the board alone.
#[test]
fn a_messages_debug_names_the_board_alone() {
    let shown = format!("{:?}", message());
    assert!(shown.contains("alice") && !shown.contains("person@") && !shown.contains("status"), "{shown}");
}
