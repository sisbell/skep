//! The pool's fence: workers on threads of their own, as `serve` runs them.
//!
//! The suite holds T15 (two workers make two names at once, and one worker
//! does not), T16 (a post answers at once while a worker is paused inside a
//! step), T17 (a second post for a name in flight meets D-4 under two
//! workers, and one `volume_create` per name across a burst), T18 (the
//! snippet's write and the reload serial across names, and a failed route
//! change's lock held across its undo).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;

use super::*;

/// T18: a failed route change keeps the route lock across its undo.
///
/// With `alice`'s reload refused and its worker paused between its failed
/// step and its cleanup, the snippet it wrote standing, `bob`, its board
/// paired and at the route lock, writes nothing; let go, `alice`'s snippet is
/// removed and its reload made before `bob`'s snippet is written, so no
/// reload of `bob`'s loads a snippet whose own route change failed.
#[test]
fn a_failed_route_change_keeps_the_route_lock_across_its_undo() {
    let script = [
        inspects("alice"),
        inspects("alice"),
        to_the_serving_run(),
        line("run_serving", Some("alice"), 0, "", ""),
        line("health", Some("alice"), 0, PAIRED, ""),
        run_and_volume_removed(),
        inspects("alice"),
        flow_of("bob", false),
        line("caddy_reload", None, 1, "", "Error: loading new config\n"),
        reloads(2),
    ]
    .concat();
    let rig = rig(&script, None);
    let (inside, between) = (Gate::new(), Gate::new());
    let (pause, seen) = (Arc::clone(&inside), Arc::new(AtomicBool::new(false)));
    rig.fake.pause(move |method, _| {
        if method == "caddy_reload" && !seen.swap(true, Ordering::SeqCst) {
            pause.pause();
        }
    });
    let pause = Arc::clone(&between);
    rig.on_log(move |line| {
        if line.starts_with("alice: FAILED at caddy_reload, ") {
            pause.pause();
        }
    });
    rig.spawn_workers(2);
    let alice = rig.admitted("alice", &rig.invite());
    inside.entered(1);
    let bob = rig.admitted("bob", &rig.invite());
    until("bob's health", || rig.called("health bob").then_some(()));
    inside.open();
    between.entered(1);
    thread::sleep(Duration::from_millis(300));
    assert!(!rig.logged("bob: snippet: written"), "bob wrote his snippet while alice's failed one stood: {:?}", rig.log());
    between.open();
    until("bob live, alice's cleanup done", || (rig.live(&bob) && rig.service.status(&alice) == Some(Shown::Failed)).then_some(()));
    rig.fake.assert_done();
    let log = rig.log();
    let at = |wanted: &str| log.iter().position(|l| l == wanted).unwrap_or_else(|| panic!("{wanted}: {log:?}"));
    assert!(at("alice: cleanup: caddy_reload: exit 0") < at("bob: snippet: written"), "{log:?}");
    assert!(!rig.snippet("alice").exists() && rig.snippet("bob").exists());
}

/// T15: two names are in flight at once under two workers, and not under one.
///
/// Under two workers, `alice`'s worker paused inside its sidecar wait (exit 4
/// once, the sleep hook at a gate), a post for `bob` is admitted and `bob`
/// reaches `run_claim` in the fake's log before `alice` reaches
/// `run_serving`; under one worker, the same script, `bob`'s `run_claim`
/// comes only after `alice`'s `run_serving` — the pool, not luck, is what
/// interleaves.
#[test]
fn two_workers_make_two_names_at_once_and_one_worker_does_not() {
    for workers in [2usize, 1] {
        let gate = Gate::new();
        let pause = Arc::clone(&gate);
        let rig = rig_with(&(flow_of("alice", true) + &flow_of("bob", false) + &reloads(2)), None, Arc::new(move |_| pause.pause()));
        rig.spawn_workers(workers);
        let alice = rig.admitted("alice", &rig.invite());
        gate.entered(1);
        let bob = rig.admitted("bob", &rig.invite());
        if workers == 2 {
            until("bob's claim run", || rig.called("run_claim bob").then_some(()));
            assert!(!rig.called("run_serving alice"), "alice's serving run came first: {:?}", rig.fake.said());
        } else {
            thread::sleep(Duration::from_millis(300));
            assert!(!rig.called("run_claim bob"), "one worker, paused, yet bob ran: {:?}", rig.fake.said());
        }
        gate.open();
        until("both live", || (rig.live(&alice) && rig.live(&bob)).then_some(()));
        rig.fake.assert_done();
        let said = rig.fake.said();
        let at = |call: &str| said.iter().position(|c| c == call).unwrap_or_else(|| panic!("{call}: {said:?}"));
        if workers == 2 {
            assert!(at("run_claim bob") < at("run_serving alice"), "{workers} workers: {said:?}");
        } else {
            assert!(at("run_claim bob") > at("run_serving alice"), "{workers} worker: {said:?}");
        }
        assert!(rig.snippet("alice").exists() && rig.snippet("bob").exists());
    }
}

/// T16: the post never waits on a provisioning.
///
/// With the one worker paused inside `alice`'s sidecar wait, a post for `bob`
/// through the desk's own path answers within a short bound, admitted, and
/// its status page shows D-7; the paused board goes live after, and `bob`'s
/// turn comes.
#[test]
fn a_post_answers_at_once_while_a_worker_is_paused_inside_a_step() {
    let gate = Gate::new();
    let pause = Arc::clone(&gate);
    let rig = rig_with(&(flow_of("alice", true) + &flow_of("bob", false) + &reloads(2)), None, Arc::new(move |_| pause.pause()));
    rig.spawn_workers(1);
    let alice = rig.admitted("alice", &rig.invite());
    gate.entered(1);
    let code = rig.invite();
    let service = Arc::clone(&rig.service);
    let (tx, rx) = mpsc::channel();
    let started = Instant::now();
    thread::spawn(move || {
        let record = record(true);
        let _ = tx.send(service.admit(&Post { name: b"bob", record: record.as_bytes(), invite: code.as_str().as_bytes() }));
    });
    let answered = rx.recv_timeout(Duration::from_secs(5)).expect("the post waited on the provisioning");
    let bob = answered.unwrap_or_else(|r| panic!("bob refused {r:?}: {:?}", rig.log()));
    assert!(started.elapsed() < Duration::from_secs(5));
    assert_eq!(rig.service.status(&bob), Some(Shown::BeingMade));
    assert_eq!(rig.service.status(&alice), Some(Shown::BeingMade), "alice still paused");
    assert!(rig.logged_opening("bob: admitted; 1 waiting; its invite issued "), "{:?}", rig.log());
    gate.open();
    until("both live", || (rig.live(&alice) && rig.live(&bob)).then_some(()));
    rig.fake.assert_done();
}

/// T17: a second post for the same name in flight is refused D-4.
///
/// Under two workers — `alice`'s worker paused and its name held — a post for
/// `alice` under another code meets `Refusal::Name`, no docker call made, the
/// code still issued; and across a burst of posts (four names, each posted
/// twice, two workers running) the fake's log shows one `volume_create` per
/// name: two workers never both take a job for one name.
#[test]
fn two_workers_never_both_take_a_job_for_one_name() {
    let names = ["alice", "bob", "carol", "dave"];
    let gate = Gate::new();
    let pause = Arc::clone(&gate);
    let script = flow_of("alice", true) + &flow_of("bob", false) + &flow_of("carol", false) + &flow_of("dave", false) + &reloads(4);
    let rig = rig_with(&script, None, Arc::new(move |_| pause.pause()));
    rig.spawn_workers(2);
    let alice = rig.admitted("alice", &rig.invite());
    gate.entered(1);
    let again = rig.invite();
    assert_eq!(rig.post("alice", &record(true), again.as_str()), Err(Refusal::Name));
    assert!(rig.issued(&again));
    assert!(rig.logged("alice: a post refused: a post in flight holds the name"), "{:?}", rig.log());
    let mut tokens = vec![alice];
    for name in &names[1..] {
        tokens.push(rig.admitted(name, &rig.invite()));
        assert_eq!(rig.post(name, &record(true), rig.invite().as_str()), Err(Refusal::Name), "{name} posted twice");
    }
    gate.open();
    until("all four live", || tokens.iter().all(|t| rig.live(t)).then_some(()));
    rig.fake.assert_done();
    let said = rig.fake.said();
    for name in names {
        assert_eq!(said.iter().filter(|c| **c == format!("volume_create {name}")).count(), 1, "{name}: {said:?}");
    }
    assert_eq!(said.iter().filter(|c| c.starts_with("volume_create ")).count(), 4, "{said:?}");
    assert_eq!(said.iter().filter(|c| *c == "caddy_reload").count(), 4, "{said:?}");
}

/// T18: route changes are serial.
///
/// Two names going live at once produce two snippets and two reloads, and no
/// reload lands between another name's snippet write and its own reload:
/// `alice`'s reload paused inside the fake while `bob` runs to the step
/// before its own snippet, `bob` writes nothing while `alice`'s reload stands
/// open; then the recorded order shows each name's write followed at once by
/// its own reload.
#[test]
fn the_snippet_write_and_the_reload_are_serial_across_names() {
    let gate = Gate::new();
    let pause = Arc::clone(&gate);
    let seen = Arc::new(AtomicBool::new(false));
    let rig = rig(&(flow_of("alice", false) + &flow_of("bob", false) + &reloads(2)), None);
    rig.fake.pause(move |method, _| {
        if method == "caddy_reload" && !seen.swap(true, Ordering::SeqCst) {
            pause.pause();
        }
    });
    rig.spawn_workers(2);
    let alice = rig.admitted("alice", &rig.invite());
    gate.entered(1);
    assert!(rig.logged("alice: snippet: written") && !rig.logged("alice: caddy_reload: exit 0"), "alice is inside its reload: {:?}", rig.log());
    let bob = rig.admitted("bob", &rig.invite());
    until("bob's health", || rig.called("health bob").then_some(()));
    thread::sleep(Duration::from_millis(300));
    assert!(!rig.snippet("bob").exists() && !rig.logged("bob: snippet: written"), "bob wrote its snippet while alice's reload ran: {:?}", rig.log());
    gate.open();
    until("both live", || (rig.live(&alice) && rig.live(&bob)).then_some(()));
    rig.fake.assert_done();
    assert!(rig.snippet("alice").exists() && rig.snippet("bob").exists());
    assert_eq!(rig.fake.said().iter().filter(|c| *c == "caddy_reload").count(), 2);
    let log = rig.log();
    let route_changes: Vec<&str> = log.iter().map(String::as_str).filter(|l| l.ends_with(": snippet: written") || l.contains(": caddy_reload: exit")).collect();
    assert_eq!(route_changes.len(), 4, "{route_changes:?}");
    for write_and_reload in route_changes.chunks(2) {
        let name = write_and_reload[0].split(':').next().expect("a name");
        assert!(write_and_reload[0].ends_with(": snippet: written"), "{route_changes:?}");
        assert_eq!(write_and_reload[1], format!("{name}: caddy_reload: exit 0"), "a reload between {name}'s snippet and its own reload: {route_changes:?}");
    }
}
