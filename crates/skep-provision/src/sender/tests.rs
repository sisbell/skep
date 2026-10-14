//! T12 — THE SENDER: the real mailer's command is `<mailer> -t` and the
//! message goes on its stdin — pinned from the `Command`, and over a recording
//! script in the mailer's place; the fake records the headers and the body; a
//! refused send is retried up to its bound — seven tries ten minutes apart —
//! and then given up, logged with neither the address nor the body but with
//! the operator's act — a relay's refusal, its stderr naming the recipient,
//! by its exit code alone — and a mailer that cannot run is retried the
//! same, and one that cannot be run at all said at start, saying why; the
//! sender's thread delivers what the worker hands it, the message made with
//! the outbox's own `From:`, `Reply-To:` and subject, a hand-over never
//! waits on a send stuck in its try and says the mails ahead of it, and a
//! send that panics costs its own mail alone, never the thread; a relay's
//! exit is named by `sysexits.h`; and the panic hook's line names the board
//! a thread works on, which stands for that work alone. (No send before the
//! status is live, and the status live throughout an outage, are the
//! flow's — `flow/tests/provision.rs`.)

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
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
    assert!(fake.send(&message()).expect("sent").success());
    let sent = messages(&mail_log).expect("the mail log");
    assert_eq!(sent.len(), 1);
    let text = &sent[0];
    for header in ["To: person@example.com\n", "From: noreply@skep.host\n", "Reply-To: owner@skep.host\n", "Subject: Your board is live\n"] {
        assert!(text.contains(header), "{header}");
    }
    assert!(text.ends_with(&format!("\n\n{}", message().body)));
    assert_eq!(fake.tries().len(), 1);
}

/// T12: A REFUSED SEND IS RETRIED UP TO ITS BOUND — seven tries ten minutes
/// apart, each try logged with its exit code — AND THEN GIVEN UP, the sleeps
/// between; nothing appended to the mail log; neither the address nor the
/// body in any line.
#[test]
fn a_refused_send_is_retried_to_its_bound_then_given_up() {
    assert_eq!((MAIL_WAIT.tries.get(), MAIL_WAIT.interval), (7, Duration::from_secs(10 * 60)), "seven tries ten minutes apart");
    let dir = Scratch::new();
    let mail_log = dir.path().join("mail.log");
    let fake = FakeSender::new(mail_log.clone(), vec![75; MAIL_WAIT.tries.get() as usize]);
    let (log, lines) = kept();
    let sleeps = Arc::new(Mutex::new(Vec::new()));
    let slept = Arc::clone(&sleeps);
    let sent = deliver(&fake, &message(), MAIL_WAIT, &move |d| slept.lock().unwrap().push(d), log.as_ref());
    assert!(!sent);
    assert_eq!(fake.tries().len(), MAIL_WAIT.tries.get() as usize);
    assert_eq!(sleeps.lock().unwrap().as_slice(), vec![MAIL_WAIT.interval; MAIL_WAIT.tries.get() as usize - 1].as_slice());
    let lines = lines.lock().unwrap().clone();
    assert_eq!(lines.len(), MAIL_WAIT.tries.get() as usize + 1);
    assert_eq!(lines[0], format!("alice: mail: try 1 of {} refused, exit 75 (EX_TEMPFAIL)", MAIL_WAIT.tries));
    assert!(lines.last().expect("a line").contains("given up after 7 tries; the board stands live"));
    assert!(
        lines.last().expect("a line").ends_with("write to the person by hand: their address is on the invite file's line spent under alice (RUNBOOK §10 step 11)"),
        "the operator's act: {lines:?}"
    );
    assert!(lines.iter().all(|l| !l.contains("person@") && !l.contains("status/0123")), "{lines:?}");
    assert!(messages(&mail_log).expect("the mail log").is_empty());
}

/// A send refused twice, then accepted: sent at the third try.
#[test]
fn a_send_accepted_after_refusals_is_sent() {
    let dir = Scratch::new();
    let fake = FakeSender::new(dir.path().join("mail.log"), vec![75, 1, 0]);
    let (log, lines) = kept();
    assert!(deliver(&fake, &message(), MAIL_WAIT, &|_| {}, log.as_ref()));
    assert_eq!(fake.tries().len(), 3);
    assert_eq!(lines.lock().unwrap().last().map(String::as_str), Some("alice: mail: sent at try 3 of 7"));
}

/// A RELAY's REFUSAL NAMES THE RECIPIENT AND IS NEVER LOGGED: tries refused
/// with the address on the mailer's stderr — as a relay's 550 carries it —
/// are logged by their exit code alone, and the name `sysexits.h` gives it,
/// and no line carries the address.
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
    let twice = Wait { tries: NonZeroU32::new(2).expect("two is not zero"), interval: MAIL_WAIT.interval };
    assert!(!deliver(&Refuses, &message(), twice, &|_| {}, log.as_ref()));
    assert_eq!(
        *lines.lock().unwrap(),
        [
            "alice: mail: try 1 of 2 refused, exit 75 (EX_TEMPFAIL)",
            "alice: mail: try 2 of 2 refused, exit 75 (EX_TEMPFAIL)",
            "alice: mail: given up after 2 tries; the board stands live and its reply on its status page until the process ends — write to the person by hand: their address is on the invite file's line spent under alice (RUNBOOK §10 step 11)"
        ]
    );
}

/// A RELAY's EXIT IS NAMED BY `sysexits.h`: each of the fifteen codes from
/// 64 to 78 by its name — the relay unreachable or deferring, its
/// credentials refused, its configuration wrong among them — and a code
/// outside them, and an end by signal, as the runner spells them alone.
#[test]
fn a_relays_exit_is_named_by_sysexits() {
    let said = |code: Option<i32>| relay_exit_said(&Exit { code, stdout: Vec::new(), stderr: Vec::new() });
    assert_eq!([said(Some(75)), said(Some(77)), said(Some(78))], ["75 (EX_TEMPFAIL)", "77 (EX_NOPERM)", "78 (EX_CONFIG)"]);
    assert_eq!((64..=78).filter_map(sysexits_name).count(), 15, "every code from 64 to 78 named");
    assert_eq!([said(Some(63)), said(Some(79)), said(Some(1)), said(None)], ["63", "79", "1", "signal"]);
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
    assert!(deliver(&Returns(Mutex::new(0)), &message(), MAIL_WAIT, &|_| *slept.lock().unwrap() += 1, log.as_ref()));
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

/// THE HAND-OVER NEVER WAITS ON A SEND, AND SAYS WHAT IS AHEAD OF IT: the
/// sender's thread stuck inside a try that does not end — a relay that hangs
/// — three mails handed over each return at once, so the worker goes on to
/// its next post, each said with the mails ahead of it, the count climbing
/// behind the stuck try; once the stuck try ends, every one is delivered, in
/// the order handed over, and a mail handed over then has none ahead.
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
    let (log, lines) = kept();
    let address = |text: &str| MailAddress::parse(text).expect("an address");
    let waits = Waits { word: Mutex::new(heard), sent: Arc::clone(&sent) };
    let outbox = Outbox::spawn(Box::new(waits), address("noreply@skep.host"), address("owner@skep.host"), log, Arc::new(|_| {})).expect("the thread");
    let outbox = Arc::new(outbox);
    let (handed, all_handed) = mpsc::channel();
    let handing = Arc::clone(&outbox);
    thread::spawn(move || {
        for to in ["first@example.com", "second@example.com", "third@example.com"] {
            handing.hand_over(Name::parse(b"alice").expect("a name"), to.to_owned(), "Your board is live.\n".to_owned());
        }
        let _ = handed.send(());
    });
    all_handed.recv_timeout(Duration::from_secs(5)).expect("a hand-over waited on a send stuck in its try");
    let said = |n: usize| format!("alice: mail: handed to the sender, {n} ahead of it");
    assert_eq!(*lines.lock().unwrap(), [said(0), said(1), said(2)], "the count climbing behind the stuck try");
    for _ in 0..3 {
        word.send(()).expect("the sender waits for its word");
    }
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while sent.lock().unwrap().len() < 3 {
        assert!(std::time::Instant::now() < deadline, "the stuck mails were never delivered");
        thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(*sent.lock().unwrap(), ["first@example.com", "second@example.com", "third@example.com"]);
    let pending = || match &outbox.delivered_by {
        DeliveredBy::Thread { pending, .. } => pending.load(Ordering::Acquire),
        DeliveredBy::Caller { .. } => unreachable!("the outbox spawned its thread"),
    };
    while pending() > 0 {
        assert!(std::time::Instant::now() < deadline, "a mail delivered still counted ahead: {}", pending());
        thread::sleep(Duration::from_millis(10));
    }
    word.send(()).expect("the sender waits for its word");
    outbox.hand_over(Name::parse(b"bob").expect("a name"), "fourth@example.com".to_owned(), "Your board is live.\n".to_owned());
    let lines = lines.lock().unwrap().clone();
    assert!(lines.contains(&"bob: mail: handed to the sender, 0 ahead of it".to_owned()), "a mail delivered still counted ahead: {lines:?}");
}

/// A SEND THAT PANICS COSTS ITS OWN MAIL ALONE: the sender's thread, the
/// first try it makes panicking, gives that mail up — logged so by its
/// board — and delivers the next, never ended by the panic and every mail
/// after it lost with it.
#[test]
fn a_send_that_panics_costs_its_own_mail_alone() {
    /// A sender whose first try panics and whose every later try is
    /// accepted.
    struct PanicsOnce {
        panicked: AtomicBool,
        sent: Arc<Mutex<Vec<String>>>,
    }
    impl Sender for PanicsOnce {
        fn send(&self, message: &Message) -> io::Result<Exit> {
            if !self.panicked.swap(true, Ordering::SeqCst) {
                panic!("a send that panics");
            }
            self.sent.lock().unwrap().push(message.to.clone());
            Ok(Exit { code: Some(0), stdout: Vec::new(), stderr: Vec::new() })
        }
    }
    let sent = Arc::new(Mutex::new(Vec::new()));
    let (log, lines) = kept();
    let address = |text: &str| MailAddress::parse(text).expect("an address");
    let panics_once = PanicsOnce { panicked: AtomicBool::new(false), sent: Arc::clone(&sent) };
    let outbox = Outbox::spawn(Box::new(panics_once), address("noreply@skep.host"), address("owner@skep.host"), log, Arc::new(|_| {})).expect("the thread");
    outbox.hand_over(Name::parse(b"alice").expect("a name"), "first@example.com".to_owned(), "Your board is live.\n".to_owned());
    outbox.hand_over(Name::parse(b"bob").expect("a name"), "second@example.com".to_owned(), "Your board is live.\n".to_owned());
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while !lines.lock().unwrap().iter().any(|l| l == "bob: mail: sent at try 1 of 7") {
        assert!(std::time::Instant::now() < deadline, "the mail after the panic was never delivered");
        thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(*sent.lock().unwrap(), ["second@example.com"]);
    let lines = lines.lock().unwrap().clone();
    let (handed, delivered): (Vec<&String>, Vec<&String>) = lines.iter().partition(|l| l.contains(": mail: handed to the sender, "));
    assert_eq!(handed[0], "alice: mail: handed to the sender, 0 ahead of it");
    assert!(handed[1].starts_with("bob: mail: handed to the sender, "), "{lines:?}");
    assert_eq!(
        delivered,
        [
            "alice: mail: given up, a try having panicked; the board stands live and its reply on its status page until the process ends — write to the person by hand: their address is on the invite file's line spent under alice (RUNBOOK §10 step 11)",
            "bob: mail: sent at try 1 of 7"
        ]
    );
}

/// THE PANIC HOOK's LINE, its four forms: the board where the thread works
/// on one, the thread by its name or as unnamed, the location as std spells
/// it or as unknown, and the payload only where the hook found a literal —
/// never a formatted one, which the hook hands it as none.
#[test]
fn the_panic_hooks_line_names_the_board_the_thread_and_the_site() {
    let at = Location::caller();
    assert_eq!(panic_line(Some("alice"), Some("worker"), Some(at), Some("a literal")), format!("alice: the worker thread panicked at {at}: a literal"));
    assert_eq!(panic_line(None, Some("connection"), Some(at), None), format!("the connection thread panicked at {at}"));
    assert_eq!(panic_line(Some("bob"), Some("sender"), Some(at), None), format!("bob: the sender thread panicked at {at}"));
    assert_eq!(panic_line(None, None, None, Some("a literal")), "an unnamed thread panicked at an unknown location: a literal");
}

/// A THREAD's BOARD stands for its work and no longer: none before it, the
/// board inside it — where the panic hook, called inside an unwind before
/// any catch, reads it — and none after it, on its return and on its unwind
/// alike, the unwind caught.
#[test]
fn a_threads_board_stands_for_its_work_alone() {
    /// What the unwind meets inside the work: the board, read as the work's
    /// frame unwinds, before the guard that clears it drops.
    struct ReadInTheUnwind(Arc<Mutex<Option<String>>>);
    impl Drop for ReadInTheUnwind {
        fn drop(&mut self) {
            *self.0.lock().unwrap() = board_of_this_thread();
        }
    }
    let alice = Name::parse(b"alice").expect("a name");
    assert_eq!(board_of_this_thread(), None, "before the work");
    assert_eq!(on_board(&alice, board_of_this_thread), Some("alice".to_owned()), "inside the work");
    assert_eq!(board_of_this_thread(), None, "after the work's return");
    let read = Arc::new(Mutex::new(None));
    let into = Arc::clone(&read);
    let unwound = catch_unwind(AssertUnwindSafe(|| {
        on_board(&alice, move || {
            let _read = ReadInTheUnwind(into);
            panic!("a step that panics");
        })
    }));
    assert!(unwound.is_err());
    assert_eq!(*read.lock().unwrap(), Some("alice".to_owned()), "the board gone before the unwind left the work");
    assert_eq!(board_of_this_thread(), None, "after the work's unwind");
}

/// A RELAY CLIENT THAT CANNOT BE RUN IS SAID AT START: a path at which no
/// file stands, a directory, and a file with no execute bit are each
/// refused saying which, as is a bare name no directory of the `PATH` given
/// holds as a file with an execute bit; a script with one is runnable, by
/// its path and by its bare name on a `PATH` that holds it.
#[cfg(unix)]
#[test]
fn a_relay_client_that_cannot_be_run_is_said_at_start() {
    use std::os::unix::fs::PermissionsExt;
    let dir = Scratch::new();
    let bin = dir.path().join("bin");
    std::fs::create_dir(&bin).expect("a directory for the program");
    let plain = bin.join("plain");
    std::fs::write(&plain, b"#!/bin/sh\n").expect("a file");
    std::fs::set_permissions(&plain, std::fs::Permissions::from_mode(0o600)).expect("no execute bit");
    let msmtp = bin.join("msmtp");
    std::fs::write(&msmtp, b"#!/bin/sh\n").expect("a script");
    std::fs::set_permissions(&msmtp, std::fs::Permissions::from_mode(0o700)).expect("executable");
    assert_eq!(runnable(&dir.path().join("absent")), Err("no file stands at it".to_owned()));
    assert_eq!(runnable(&bin), Err("it is not a file".to_owned()));
    assert_eq!(runnable(&plain), Err("it is a file with no execute bit".to_owned()));
    assert_eq!(runnable(&msmtp), Ok(()));
    let empty = dir.path().join("empty");
    std::fs::create_dir(&empty).expect("a directory holding nothing");
    let refused = Err("no directory of PATH holds it as a file with an execute bit".to_owned());
    assert_eq!(runnable_on(Path::new("msmtp"), Some(empty.as_os_str())), refused);
    assert_eq!(runnable_on(Path::new("msmtp"), None), refused, "no PATH at all");
    assert_eq!(runnable_on(Path::new("plain"), Some(bin.as_os_str())), refused, "on the PATH with no execute bit");
    let path = std::env::join_paths([empty.as_path(), bin.as_path()]).expect("a PATH");
    assert_eq!(runnable_on(Path::new("msmtp"), Some(path.as_os_str())), Ok(()), "found on the PATH's second directory");
}

/// A message's `Debug` names the board alone.
#[test]
fn a_messages_debug_names_the_board_alone() {
    let shown = format!("{:?}", message());
    assert!(shown.contains("alice") && !shown.contains("person@") && !shown.contains("status"), "{shown}");
}
