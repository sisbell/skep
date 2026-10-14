//! THE DESK, what the pages ask, over the two fakes: the flow's halves of T8
//! (two posts on one name; a fifth past the queue; a post for a name admitted
//! while its reads ran, refused at its own admission; a name Docker cannot
//! take as a name alone, refused with no docker call), T9 (a spent, an
//! unknown and a held code refused; the invite first, so an uninvited post
//! learns nothing about names; a code spent while a post's reads ran, refused
//! at its admission; a live board's code held until its spend is written,
//! kept held where the spend could not be written, and let go of after it —
//! or where the spend finds it no longer issued, the operator's hand having
//! marked it; no code in the log) and T10 (a sign-up, its address in no log
//! line; one past the file's cap, refused); a record the hosted genesis can
//! never take, refused D-5 with no docker call; a fifth post past the looks'
//! cap, refused D-8 with no docker call, and the looks' permits given back;
//! one code holding one look at a time, let go on every refusal and an
//! unwind; where two of a post's faults hold, the first in its order
//! speaking; and THE BOOK keeping its own rules — what blocks a new post,
//! first of three, and what admitting, taking, going live, letting a code go
//! and failing do, an admission whole or not made.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;

use skep_identity::{ALG_FNDSA512_PREVIEW_ED25519, FNDSA512_PREVIEW_ED25519_KEY_LEN};

use super::*;
use crate::docker::Call;
use crate::name::NameRefused;
use crate::record::{decodable_key, undecodable_key};

/// T8: TWO POSTS ON ONE NAME — the second meets D-4 at the post, held by
/// the first in flight, with no docker call made for it.
#[test]
fn a_second_post_on_one_name_meets_d4_at_the_post() {
    let rig = rig(&inspects("alice"), Some(Vec::new()));
    let first = rig.invite();
    rig.admitted("alice", &first);
    let second = rig.invite();
    assert_eq!(rig.post("ALICE", &record(true), second.as_str()), Err(Refusal::Name));
    rig.fake.assert_done();
    assert!(rig.issued(&second));
}

/// T8: A FIFTH POST PAST THE QUEUE meets D-8, "try again later", and leaves
/// no entry — no token, no queued post, no held code, no docker call.
#[test]
fn a_fifth_post_past_the_queue_meets_d8_and_leaves_no_entry() {
    let names = ["alice", "bob", "carol", "dave"];
    let rig = rig(&names.iter().map(|n| inspects(n)).collect::<String>(), Some(Vec::new()));
    for name in names {
        let code = rig.invite();
        rig.admitted(name, &code);
    }
    let fifth = rig.invite();
    assert_eq!(rig.post("erin", &record(true), fifth.as_str()), Err(Refusal::Busy));
    rig.fake.assert_done();
    let book = rig.service.book();
    assert_eq!(book.queue.len(), QUEUE_DEPTH);
    assert_eq!(book.admitted.len(), QUEUE_DEPTH);
    assert!(!book.admitted.contains(&fifth));
    assert!(!book.map.holds(&Name::parse(b"erin").expect("a name")));
    drop(book);
    assert!(rig.log().join("\n").contains("erin: a post refused: 4 posts already wait"));
}

/// THE LOOKS' CAP: four posts paused inside their looks at what stands, a
/// fifth meets D-8, "try again later", at once and with no docker call, its
/// invite still issued; the four, let go, meet D-4 off the volumes standing
/// under their names, and their permits are given back — a sixth post looks
/// and is admitted.
#[test]
fn a_post_past_the_looks_cap_meets_d8_with_no_docker_call() {
    let names = ["alice", "bob", "carol", "dave"];
    assert_eq!(MAX_LOOKS, names.len());
    let gate = Gate::new();
    let pause = Arc::clone(&gate);
    let rig = rig(&(names.iter().map(|&n| line("volume_inspect", Some(n), 0, "", "")).collect::<String>() + &inspects("frank")), None);
    rig.fake.pause(move |method, name| {
        if method == "volume_inspect" && matches!(name, Some("alice" | "bob" | "carol" | "dave")) {
            pause.pause();
        }
    });
    let answers: Vec<_> = names
        .iter()
        .map(|&name| {
            let (service, code) = (Arc::clone(&rig.service), rig.invite());
            let (tx, rx) = mpsc::channel();
            thread::spawn(move || {
                let record = record(true);
                let _ = tx.send(service.admit(&Post { name: name.as_bytes(), record: record.as_bytes(), invite: code.as_str().as_bytes() }));
            });
            rx
        })
        .collect();
    gate.entered(4);
    let fifth = rig.invite();
    assert_eq!(rig.post("erin", &record(true), fifth.as_str()), Err(Refusal::Busy));
    assert!(rig.logged("erin: a post refused: 4 posts already look at what stands"), "{:?}", rig.log());
    assert!(rig.issued(&fifth));
    gate.open();
    for answered in answers {
        assert_eq!(answered.recv_timeout(Duration::from_secs(30)).expect("the paused post answered"), Err(Refusal::Name));
    }
    rig.admitted("frank", &rig.invite());
    rig.fake.assert_done();
}

/// A PERMIT UNDER A CAP is taken where fewer than the cap are held, refused
/// where the cap are, and given back when dropped — the count back at none.
#[test]
fn a_permit_is_given_back_when_dropped() {
    let held = AtomicUsize::new(0);
    let first = Permit::take(&held, 2).expect("a permit");
    let second = Permit::take(&held, 2).expect("a second permit");
    assert!(Permit::take(&held, 2).is_none(), "a third permit under a cap of two");
    drop(first);
    let third = Permit::take(&held, 2).expect("the permit given back");
    assert_eq!(held.load(Ordering::SeqCst), 2);
    drop((second, third));
    assert_eq!(held.load(Ordering::SeqCst), 0);
}

/// THE BOOK KEEPS ITS OWN RULES. A code whose post is looking at what
/// stands is held. Admitted, a post waits with its code and its name held,
/// its page D-7. What blocks a new post is the first of a full queue, a held
/// code and a held name: four waiting block a fifth even on a free name and
/// code, and a post on a held code and a held name meets the code. Taken,
/// the oldest post runs, still holding both. Gone live, it holds its name no
/// more, and its code stays held until it is let go of. Failed, it lets its
/// code go at once and holds its name no more.
#[test]
fn the_book_keeps_its_own_rules() {
    let name = |n: &str| Name::parse(n.as_bytes()).expect("a name");
    let invite_code = |c: &str| InviteCode::parse(c).expect("a code");
    let job = |n: &str, code: &str| Job {
        token: format!("token-{n}"),
        name: name(n),
        record: crate::record::admit(record(true).as_bytes()).expect("a record"),
        code: invite_code(code),
        address: "person@example.com".to_owned(),
    };
    let state = |book: &Book, n: &str| book.map.post(&format!("token-{n}")).map(|p| p.state);
    let mut book = Book::new(StatusMap::default());
    assert_eq!(book.blocks(&name("alice"), &invite_code("c1")), None, "nothing in flight");
    book.looking.insert(invite_code("c9"));
    assert_eq!(book.blocks(&name("zed"), &invite_code("c9")), Some(Blocked::CodeHeld), "a code whose post is looking");
    book.looking.clear();
    for (at, (n, code)) in [("alice", "c1"), ("bob", "c2"), ("carol", "c3"), ("dave", "c4")].into_iter().enumerate() {
        assert_eq!(book.admit(job(n, code)), at + 1, "the posts now waiting");
        assert_eq!(state(&book, n), Some(PostState::Queued));
    }
    assert_eq!(book.blocks(&name("erin"), &invite_code("c5")), Some(Blocked::QueueFull));
    assert_eq!(book.blocks(&name("alice"), &invite_code("c1")), Some(Blocked::QueueFull), "the queue before the code and the name");
    let alice = book.take().expect("a waiting post");
    assert_eq!(alice.name, name("alice"), "the oldest post first");
    assert_eq!(state(&book, "alice"), Some(PostState::Running));
    assert_eq!(book.blocks(&name("erin"), &invite_code("c5")), None, "three waiting");
    assert_eq!(book.blocks(&name("alice"), &invite_code("c1")), Some(Blocked::CodeHeld), "the code before the name");
    assert_eq!(book.blocks(&name("alice"), &invite_code("c5")), Some(Blocked::NameHeld));
    book.mark_live(&alice.token);
    assert_eq!(state(&book, "alice"), Some(PostState::Live));
    assert_eq!(book.blocks(&name("alice"), &invite_code("c5")), None, "a live name's truth is its snippet's");
    assert_eq!(book.blocks(&name("erin"), &invite_code("c1")), Some(Blocked::CodeHeld), "held until its spend is written");
    book.release(&alice.code);
    assert_eq!(book.blocks(&name("erin"), &invite_code("c1")), None);
    let bob = book.take().expect("a waiting post");
    assert_eq!(state(&book, "bob"), Some(PostState::Running));
    book.mark_failed(&bob);
    assert_eq!(state(&book, "bob"), Some(PostState::Failed));
    assert_eq!(book.blocks(&name("erin"), &invite_code("c2")), None, "a failed post's code let go of at once");
    assert_eq!(book.blocks(&name("bob"), &invite_code("c5")), None, "and its name");
    assert_eq!(book.queue.len(), 2);
}

/// AN ADMISSION IS WHOLE OR NOT MADE: a job under a token the map holds
/// panics at the map's gate before the book changes — its code not held,
/// nothing queued, the post the token names untouched, its name not held.
#[test]
fn an_admission_on_a_token_admitted_before_changes_nothing() {
    let name = |n: &str| Name::parse(n.as_bytes()).expect("a name");
    let invite_code = |c: &str| InviteCode::parse(c).expect("a code");
    let job = |n: &str, code: &str| Job {
        token: "t0k3n".to_owned(),
        name: name(n),
        record: crate::record::admit(record(true).as_bytes()).expect("a record"),
        code: invite_code(code),
        address: "person@example.com".to_owned(),
    };
    let mut book = Book::new(StatusMap::default());
    assert_eq!(book.admit(job("alice", "c1")), 1);
    let again = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| book.admit(job("bob", "c2"))));
    assert!(again.is_err(), "a second admission under one token");
    assert!(!book.admitted.contains(&invite_code("c2")), "the refused admission's code held");
    assert_eq!(book.queue.len(), 1, "the refused admission queued");
    assert_eq!(book.map.post("t0k3n").map(|p| (p.name.clone(), p.state)), Some((name("alice"), PostState::Queued)));
    assert!(!book.map.holds(&name("bob")));
}

/// T9: A SPENT CODE, AN UNKNOWN CODE, A CODE OF ANOTHER FORM and A CODE A
/// POST IN FLIGHT HOLDS are refused at the post, no docker call made; D-5
/// and D-6 refuse a record before any — among D-5's a record the hosted
/// genesis can never take, a key's half that does not decode or more
/// entries than its cap, which would fail at the dark claim — the log
/// naming the fault's token, never the record; and D-4 a name Docker cannot
/// take as a name alone — one byte, a hosts-file name, hex digits alone —
/// its code still issued, never let go of by a post that fails at `docker
/// volume create` or the health wait to be posted again.
#[test]
fn the_posts_refusals_come_before_any_docker_call() {
    let rig = rig(&inspects("alice"), Some(Vec::new()));
    let code = rig.invite();
    rig.admitted("alice", &code);
    assert_eq!(rig.post("bob", &record(true), code.as_str()), Err(Refusal::Invite), "held by the post in flight");
    assert_eq!(rig.post("bob", &record(true), "0123456789abcdef0123456789abcdef"), Err(Refusal::Invite), "unknown");
    assert_eq!(rig.post("bob", &record(true), "not a code"), Err(Refusal::Invite), "another form");
    let spent = rig.invite();
    crate::invites::spend(&rig.state_dir, &spent, &Name::parse(b"carol").expect("a name")).expect("spent");
    assert_eq!(rig.post("bob", &record(true), spent.as_str()), Err(Refusal::Invite), "spent");
    let fresh = rig.invite();
    assert_eq!(rig.post("bob", "{\"type\":\"skep-enroll\"}", fresh.as_str()), Err(Refusal::Record));
    let preview = encode_enroll(&[Enrollment::new(PublicKey::parse(ALG_FNDSA512_PREVIEW_ED25519, &"9f".repeat(FNDSA512_PREVIEW_ED25519_KEY_LEN)).expect("a key"), true, None).expect("no label")]);
    assert_eq!(rig.post("bob", &preview, fresh.as_str()), Err(Refusal::Preview));
    let undecodable = encode_enroll(&[Enrollment::new(undecodable_key(), true, None).expect("no label")]);
    assert_eq!(rig.post("bob", &undecodable, fresh.as_str()), Err(Refusal::Record), "a half that does not decode");
    let seventeen = encode_enroll(&(0..17u8).map(|n| Enrollment::new(decodable_key(n), false, None).expect("no label")).collect::<Vec<_>>());
    assert_eq!(rig.post("bob", &seventeen, fresh.as_str()), Err(Refusal::Record), "past the genesis's cap");
    assert_eq!(rig.post("b_b", &record(true), fresh.as_str()), Err(Refusal::Name));
    for name in ["x", "localhost", "ab"] {
        assert_eq!(rig.post(name, &record(true), fresh.as_str()), Err(Refusal::Name), "{name}");
    }
    rig.fake.assert_done();
    assert!(rig.issued(&fresh));
    let log = rig.log().join("\n");
    for token in ["bad_record", "preview_key", "undecodable_key", "too_many_enrolled"] {
        assert!(log.contains(&format!("bob: a post refused: the record, {token}")), "{token}: {log}");
    }
    for refused in [NameRefused::TooShort, NameRefused::HostsFileName, NameRefused::HexDigitsAlone] {
        assert!(log.contains(&format!("a post refused: {refused}")), "{refused:?}: {log}");
    }
    for never in [code.as_str(), spent.as_str(), fresh.as_str(), "skep-enroll", "9f9f", "b_b"] {
        assert!(!log.contains(never), "the log carries {never:?}: {log}");
    }
}

/// T9: THE INVITE, FIRST — an uninvited post learns nothing about names: a
/// code the file does not hold answers the invite's refusal alike for a free
/// name, a name a post in flight holds, a name its snippet takes, a name out
/// of the grammar and a record that is none; no docker call, and no log line
/// naming any of them.
#[test]
fn an_uninvited_post_learns_nothing_about_names() {
    let rig = rig(&inspects("alice"), None);
    rig.admitted("alice", &rig.invite());
    fs::write(rig.snippet("carol"), b"").expect("carol's snippet");
    for (what, name, field) in [
        ("a free name", "bob", record(true)),
        ("a name a post in flight holds", "alice", record(true)),
        ("a name its snippet takes", "carol", record(true)),
        ("a name out of the grammar", "b_b", record(true)),
        ("a record that is none", "bob", "{}".to_owned()),
    ] {
        assert_eq!(rig.post(name, &field, "0123456789abcdef0123456789abcdef"), Err(Refusal::Invite), "{what}");
    }
    rig.fake.assert_done();
    let after: Vec<String> = rig.log().into_iter().skip_while(|l| l != "alice: admitted; 1 waiting").skip(1).collect();
    assert_eq!(after, vec!["a post refused: its invite code is not one the file holds issued"; 5]);
}

/// WHERE TWO OF A POST's FAULTS HOLD, THE FIRST IN ITS ORDER SPEAKS — the
/// invite, the name's grammar, the record, then what is in flight — each
/// with no docker call: a name out of the grammar beside a record that is
/// none answers D-4, and a record that is none beside a full queue D-5, the
/// queue full all the while — the same post with its record whole meets
/// it, D-8.
#[test]
fn where_two_of_a_posts_faults_hold_the_first_in_its_order_speaks() {
    let names = ["alice", "bob", "carol", "dave"];
    let rig = rig(&names.iter().map(|n| inspects(n)).collect::<String>(), None);
    for name in names {
        rig.admitted(name, &rig.invite());
    }
    let code = rig.invite();
    assert_eq!(rig.post("b_b", "{}", code.as_str()), Err(Refusal::Name), "the name's grammar before the record");
    assert_eq!(rig.post("erin", "{}", code.as_str()), Err(Refusal::Record), "the record before what is in flight");
    assert_eq!(rig.post("erin", &record(true), code.as_str()), Err(Refusal::Busy), "the queue full, the record whole");
    rig.fake.assert_done();
}

/// T9: A LIVE BOARD's CODE IS LET GO OF once its spend is written: the book
/// holds it no more, and a post naming it again is refused as spent — the
/// file's word — never as held by another post.
#[test]
fn a_live_boards_code_is_let_go_of_and_refused_as_spent() {
    let script = [
        inspects("alice"),
        inspects("alice"),
        to_the_serving_run(),
        line("run_serving", Some("alice"), 0, "", ""),
        line("health", Some("alice"), 0, PAIRED, ""),
        line("caddy_reload", None, 0, "", ""),
    ]
    .concat();
    let rig = rig(&script, None);
    let code = rig.invite();
    rig.admitted("alice", &code);
    assert!(rig.service.run_next());
    assert!(!rig.service.book().admitted.contains(&code), "the code held past its spend");
    assert_eq!(rig.post("bob", &record(true), code.as_str()), Err(Refusal::Invite));
    assert!(rig.logged("a post refused: its invite code is not one the file holds issued"), "{:?}", rig.log());
    rig.fake.assert_done();
}

/// T9: A LIVE BOARD's CODE IS HELD UNTIL ITS SPEND IS WRITTEN: with the
/// invite file's lock held elsewhere — the owner's `invite` minting that
/// moment — a worker whose board has gone live waits at its spend with the
/// code still held, and a post naming the code meets the invite's refusal
/// with no docker call; the lock let go of, the spend lands, and only then is
/// the code let go of. The wait is the moment a stop would leave behind
/// (`main`'s THE STOP): the snippet standing, the board live, the file saying
/// issued, and the log naming the board's snippet written with no spend after
/// it.
#[test]
fn a_live_boards_code_is_held_until_its_spend_is_written() {
    let rig = rig(&(flow_of("alice", false) + &reloads(1)), None);
    let code = rig.invite();
    let alice = rig.admitted("alice", &code);
    // The lock file beside the invite file, `invites.lock`, held as the
    // `invite` verb holds it: an open of its own, locked exclusively.
    let lock = fs::OpenOptions::new().write(true).open(rig.state_dir.file("invites.lock")).expect("the invite file's lock");
    lock.lock().expect("held");
    rig.spawn_workers(1);
    until("alice live", || rig.live(&alice).then_some(()));
    thread::sleep(Duration::from_millis(300));
    assert!(rig.service.book().admitted.contains(&code), "the code let go of before its spend was written");
    assert_eq!(rig.post("bob", &record(true), code.as_str()), Err(Refusal::Invite));
    assert!(rig.logged("bob: a post refused: its invite is held by another post"), "{:?}", rig.log());
    assert!(rig.issued(&code), "a spend written past the lock");
    assert!(rig.snippet("alice").exists(), "the snippet stands while the file says issued: what a stop here leaves");
    assert!(rig.logged("alice: snippet: written") && !rig.logged("alice: the invite is spent"), "the log names the board, its spend not yet written: {:?}", rig.log());
    drop(lock);
    until("the spend", || (!rig.issued(&code)).then_some(()));
    until("the code let go of", || (!rig.service.book().admitted.contains(&code)).then_some(()));
    rig.fake.assert_done();
}

/// T9: A SPEND THAT COULD NOT BE WRITTEN KEEPS ITS CODE HELD for the
/// process's life: the file still says issued, so a post naming the code
/// meets the invite's refusal — never a second board on one invite — while
/// the board stands live and the log says the operator marks it.
#[cfg(unix)]
#[test]
fn a_spend_that_could_not_be_written_keeps_its_code_held() {
    use std::os::unix::fs::PermissionsExt;
    let rig = rig(&(flow_of("alice", false) + &reloads(1)), None);
    let code = rig.invite();
    let alice = rig.admitted("alice", &code);
    // The state directory read-only: the invite file's rewrite cannot be made.
    fs::set_permissions(rig.dir.path().join("state"), fs::Permissions::from_mode(0o500)).expect("read-only");
    assert!(rig.service.run_next());
    assert!(rig.live(&alice) && rig.issued(&code), "live, the file still saying issued");
    assert!(rig.service.book().admitted.contains(&code), "the code let go of though its spend was never written");
    assert_eq!(rig.post("bob", &record(true), code.as_str()), Err(Refusal::Invite));
    rig.fake.assert_done();
    assert!(rig.log().iter().any(|l| l.starts_with("alice: the invite could not be marked spent (") && l.ends_with("; this process refuses it, and the operator marks it")), "{:?}", rig.log());
}

/// T9: A SPEND THAT FINDS ITS CODE NO LONGER ISSUED — the operator's hand
/// having marked it spent while its board was made — lets the code go all
/// the same: the board stands live, the log names the board and no spend of
/// its own, the file keeps the operator's word, and a post naming the code is
/// refused by the file.
#[test]
fn a_spend_that_finds_its_code_no_longer_issued_lets_it_go() {
    let script = [
        inspects("alice"),
        inspects("alice"),
        to_the_serving_run(),
        line("run_serving", Some("alice"), 0, "", ""),
        line("health", Some("alice"), 0, PAIRED, ""),
        line("caddy_reload", None, 0, "", ""),
    ]
    .concat();
    let rig = rig(&script, None);
    let code = rig.invite();
    let alice = rig.admitted("alice", &code);
    assert!(crate::invites::spend(&rig.state_dir, &code, &Name::parse(b"carol").expect("a name")).expect("written"), "the operator's hand, while the post waits");
    assert!(rig.service.run_next());
    assert!(rig.live(&alice));
    assert!(rig.logged("alice: the invite was not found issued at the spend; the board stands"), "{:?}", rig.log());
    assert!(!rig.logged("alice: the invite is spent"), "{:?}", rig.log());
    assert!(!rig.service.book().admitted.contains(&code), "the code held though the file holds it no longer issued");
    assert!(matches!(lookup(&rig.state_dir, &code).expect("read").expect("held").state, crate::invites::InviteState::Spent { ref name, .. } if name == "carol"), "the operator's word kept");
    assert_eq!(rig.post("bob", &record(true), code.as_str()), Err(Refusal::Invite));
    assert!(rig.logged("a post refused: its invite code is not one the file holds issued"), "{:?}", rig.log());
    rig.fake.assert_done();
}

/// T10: A SIGN-UP through the service is kept and logged — its address in
/// no log line; a malformed one refused, nothing kept.
#[test]
fn a_sign_up_is_kept_and_its_address_is_in_no_log_line() {
    let rig = rig("", None);
    assert_eq!(rig.service.sign_up(b"someone@example.org"), Ok(()));
    assert_eq!(rig.service.sign_up(b"no address"), Err(SignUpRefusal::NotAnAddress));
    let kept = fs::read_to_string(rig.state_dir.file(crate::signups::SIGNUPS)).expect("the file");
    assert_eq!(kept.lines().count(), 1);
    assert!(kept.starts_with("someone@example.org "));
    let log = rig.log().join("\n");
    assert_eq!(log, "a sign-up kept\na sign-up refused: no address");
}

/// T10: A SIGN-UP PAST THE FILE's CAP — the file at its 256 KiB — is
/// refused as one that could not be kept, nothing written, and logged with
/// the cap and the owner's act, never the address.
#[test]
fn a_sign_up_past_the_files_cap_is_refused_and_logged() {
    let rig = rig("", None);
    let full = format!("{}\n", "#".repeat(256 * 1024 - 1));
    fs::write(rig.state_dir.file(crate::signups::SIGNUPS), &full).expect("a file at its cap");
    assert_eq!(rig.service.sign_up(b"someone@example.org"), Err(SignUpRefusal::Failed));
    assert_eq!(fs::read_to_string(rig.state_dir.file(crate::signups::SIGNUPS)).expect("the file"), full);
    assert_eq!(rig.log(), ["a sign-up refused: the sign-up file is at its 262144-byte cap; the owner trims the file"]);
}

/// T8: THE ADMISSION LOOKS AGAIN AT THE NAME — a post paused inside its
/// reads of what stands while a second post for its name is admitted meets
/// D-4 at its own admission, the name held by the post admitted meanwhile,
/// and leaves nothing: one post waits, one code is held, its own still
/// issued.
#[test]
fn a_post_for_a_name_admitted_while_its_reads_ran_meets_d4() {
    let gate = Gate::new();
    let pause = Arc::clone(&gate);
    let seen = Arc::new(AtomicBool::new(false));
    let rig = rig(&(inspects("alice") + &inspects("alice")), None);
    rig.fake.pause(move |method, _| {
        if method == "container_inspect" && !seen.swap(true, Ordering::SeqCst) {
            pause.pause();
        }
    });
    let (paused, other) = (rig.invite(), rig.invite());
    let (service, code) = (Arc::clone(&rig.service), paused.clone());
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let record = record(true);
        let _ = tx.send(service.admit(&Post { name: b"alice", record: record.as_bytes(), invite: code.as_str().as_bytes() }));
    });
    gate.entered(1);
    let token = rig.admitted("alice", &other);
    gate.open();
    assert_eq!(rx.recv_timeout(Duration::from_secs(30)).expect("the paused post answered"), Err(Refusal::Name), "two posts for one name in flight");
    rig.fake.assert_done();
    let book = rig.service.book();
    assert_eq!(book.queue.len(), 1);
    assert!(book.admitted.contains(&other) && !book.admitted.contains(&paused));
    drop(book);
    assert!(rig.issued(&paused));
    assert_eq!(rig.service.status(&token), Some(Shown::BeingMade));
    assert!(rig.logged("alice: a post refused: a post in flight holds the name"), "{:?}", rig.log());
}

/// T9: THE ADMISSION LOOKS AGAIN AT THE INVITE — a post paused inside its
/// reads holds its code, so a post of this service's on the code is refused
/// as held; and where the code is marked spent meanwhile — a spend written
/// between the post's first lookup and its in-flight check, or the
/// operator's by hand — the paused post meets the invite's refusal at its
/// own admission: never a second board on one invite.
#[test]
fn a_post_whose_code_was_spent_while_its_reads_ran_is_refused() {
    let gate = Gate::new();
    let pause = Arc::clone(&gate);
    let rig = rig(&inspects("bob"), None);
    rig.fake.pause(move |method, name| {
        if method == "container_inspect" && name == Some("bob") {
            pause.pause();
        }
    });
    let code = rig.invite();
    let (service, posted) = (Arc::clone(&rig.service), code.clone());
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let record = record(true);
        let _ = tx.send(service.admit(&Post { name: b"bob", record: record.as_bytes(), invite: posted.as_str().as_bytes() }));
    });
    gate.entered(1);
    assert_eq!(rig.post("alice", &record(true), code.as_str()), Err(Refusal::Invite), "the paused post's look holds its code");
    assert!(crate::invites::spend(&rig.state_dir, &code, &Name::parse(b"carol").expect("a name")).expect("written"), "issued until now");
    gate.open();
    assert_eq!(rx.recv_timeout(Duration::from_secs(30)).expect("the paused post answered"), Err(Refusal::Invite), "a second board on one invite");
    rig.fake.assert_done();
    assert!(rig.service.book().queue.is_empty());
    assert!(rig.logged("alice: a post refused: its invite is held by another post"), "{:?}", rig.log());
    assert!(rig.logged("bob: a post refused: its invite was spent while the post was judged"), "{:?}", rig.log());
}

/// ONE CODE, ONE LOOK: a post paused inside its look holds its code — a
/// second post on the same code, under another name, is refused as held
/// with no docker call, so one invite never takes more than one of the
/// looks' permits — while a post on another code looks beside it; let go,
/// the first post's D-4 lets the code go, and the code looks again.
#[test]
fn one_code_holds_one_look_at_a_time() {
    let gate = Gate::new();
    let pause = Arc::clone(&gate);
    let rig = rig(&(line("volume_inspect", Some("alice"), 0, "", "") + &inspects("bob") + &inspects("carol")), None);
    rig.fake.pause(move |method, name| {
        if method == "volume_inspect" && name == Some("alice") {
            pause.pause();
        }
    });
    let code = rig.invite();
    let (service, held) = (Arc::clone(&rig.service), code.clone());
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let record = record(true);
        let _ = tx.send(service.admit(&Post { name: b"alice", record: record.as_bytes(), invite: held.as_str().as_bytes() }));
    });
    gate.entered(1);
    assert_eq!(rig.post("dave", &record(true), code.as_str()), Err(Refusal::Invite), "a second look on one code");
    assert!(rig.logged("dave: a post refused: its invite is held by another post"), "{:?}", rig.log());
    rig.admitted("bob", &rig.invite());
    gate.open();
    assert_eq!(rx.recv_timeout(Duration::from_secs(30)).expect("the paused post answered"), Err(Refusal::Name));
    rig.admitted("carol", &code);
    rig.fake.assert_done();
    assert!(rig.service.book().looking.is_empty(), "a look's hold outlived its post");
}

/// A LOOK THAT UNWINDS LETS ITS CODE GO: a post whose look panics — a
/// `docker` call that panics, caught where the pages catch an answer's
/// panic — leaves its code unheld, and the same code's next post looks and
/// is admitted.
#[test]
fn a_look_that_unwinds_lets_its_code_go() {
    /// A runner whose first volume inspect panics, every other call
    /// answering "not standing".
    struct PanicsOnce(AtomicBool);
    impl Docker for PanicsOnce {
        fn run(&self, call: Call<'_>) -> io::Result<Exit> {
            if matches!(call, Call::VolumeInspect(_)) && !self.0.swap(true, Ordering::SeqCst) {
                panic!("a look's call that panics");
            }
            Ok(Exit { code: Some(1), stdout: Vec::new(), stderr: Vec::new() })
        }
    }
    let dir = Scratch::new();
    let boards = dir.path().join("boards");
    fs::create_dir(&boards).expect("the snippet directory");
    let state_dir = StateDir::open(&dir.path().join("state")).expect("the state directory");
    let config = Config { boards_dir: boards, suffix: suffix() };
    let service = Service::new(config, state_dir.clone(), Box::new(PanicsOnce(AtomicBool::new(false))), None, Arc::new(|_: &str| {}), Arc::new(|_| {})).expect("the service");
    let code = mint(&state_dir, &MailAddress::parse("person@example.com").expect("an address"), None).expect("minted");
    let record = record(true);
    let post = Post { name: b"alice", record: record.as_bytes(), invite: code.as_str().as_bytes() };
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| service.admit(&post))).is_err(), "the look panicked");
    assert!(service.book().looking.is_empty(), "the code held past a look that unwound");
    assert!(service.admit(&post).is_ok(), "the code's next post refused");
}
