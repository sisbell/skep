//! THE SERVICE's START: the status map rebuilt from the snippets standing;
//! THE SWEEP, T20 (the half-made board removed, the routed and the unnamed
//! left, a listing that fails skipped); and a `docker` that cannot be run
//! at all — the sweep skipped, a post refused D-8.

use super::*;
use crate::docker::Call;

/// The rebuild at the service's start: the snippets standing are its live
/// names.
#[test]
fn the_service_starts_with_the_snippets_live_names() {
    let rig = rig("", None);
    fs::write(rig.snippet("alice"), b"").expect("a snippet");
    let config = Config { boards_dir: rig.boards.clone(), suffix: "skep.host".into() };
    let again = Service::new(config, rig.state_dir.clone(), Box::new(Arc::clone(&rig.fake)), None, Arc::new(|_: &str| {}), Arc::new(|_| {})).expect("the service");
    assert_eq!(again.live_count(), 1);
}

/// A `docker` THAT CANNOT BE RUN AT ALL: the sweep's listing cannot be made,
/// so the sweep is skipped and the service stands; and a post whose look at
/// the name cannot be made meets D-8 — never D-4's "taken" — and leaves
/// nothing: no post waiting, no code held, the invite still issued.
#[test]
fn a_docker_that_cannot_run_skips_the_sweep_and_refuses_a_post_d8() {
    /// A runner whose `docker` cannot be run: every call the error.
    struct NoDocker;
    impl Docker for NoDocker {
        fn run(&self, _: Call<'_>) -> io::Result<Exit> {
            Err(io::Error::from(io::ErrorKind::NotFound))
        }
    }
    let dir = Scratch::new();
    let boards = dir.path().join("boards");
    fs::create_dir(&boards).expect("the snippet directory");
    let state_dir = StateDir::open(&dir.path().join("state")).expect("the state directory");
    let lines = Arc::new(Mutex::new(Vec::new()));
    let into = Arc::clone(&lines);
    let log: Log = Arc::new(move |line: &str| into.lock().unwrap().push(line.to_owned()));
    let config = Config { boards_dir: boards, suffix: "skep.host".into() };
    let service = Service::new(config, state_dir.clone(), Box::new(NoDocker), None, log, Arc::new(|_| {})).expect("the service");
    assert_eq!(service.sweep(), 0);
    let code = mint(&state_dir, &MailAddress::parse("person@example.com").expect("an address"), None).expect("minted");
    let alice = record(true);
    assert_eq!(service.admit(&Post { name: b"alice", record: alice.as_bytes(), invite: code.as_str().as_bytes() }), Err(Refusal::Failed));
    let book = service.book();
    assert!(book.queue.is_empty() && book.codes.is_empty() && !book.map.holds(&Name::parse(b"alice").expect("a name")));
    drop(book);
    assert!(lookup(&state_dir, &code).expect("read").expect("held").issued());
    let log = lines.lock().unwrap().clone();
    assert!(log.iter().any(|l| l.starts_with("sweep: volumes: docker could not run: ") && l.ends_with("; the sweep is skipped")), "{log:?}");
    assert!(log.iter().any(|l| l.starts_with("alice: a post could not be judged: the look at the name: ")), "{log:?}");
}

/// T20: THE SWEEP — `labelled_volumes` answering `alice`, `bob` and
/// `Carol_X` with `alice.caddy` standing and no `bob.caddy`:
/// `rm_force bob` then `volume_rm bob`, then the look at what stands under
/// `bob`, finding nothing; nothing for `alice`, nothing for `Carol_X`
/// (logged as under no name of the grammar), the count 1, the log naming
/// the name and each step; a `labelled_volumes` exit 1 — the sweep skipped,
/// the count 0, the service standing and taking a post; a `volume_rm`
/// failure — logged, and the look naming the volume that stands, the name
/// left, not counted; an `rm_force` failure (no container) logged as
/// itself, the volume still removed and the look finding nothing.
#[test]
fn the_sweep_removes_a_half_made_board_and_leaves_the_rest() {
    let script = line("labelled_volumes", None, 0, "alice\nbob\nCarol_X\n", "") + &line("rm_force", Some("bob"), 0, "", "") + &line("volume_rm", Some("bob"), 0, "", "") + &inspects("bob");
    let rig = rig(&script, None);
    fs::write(rig.snippet("alice"), b"").expect("alice's snippet");
    assert_eq!(rig.service.sweep(), 1);
    rig.fake.assert_done();
    assert_eq!(rig.fake.said(), said(&["labelled_volumes", "rm_force bob", "volume_rm bob", "volume_inspect bob", "container_inspect bob"]));
    for line in [
        "bob: half-made at start (a volume, no snippet) — removing",
        "bob: sweep: rm_force: exit 0",
        "bob: sweep: volume_rm: exit 0",
        "bob: sweep: done — nothing stands under the name",
        "sweep: a volume under the label is under no name of the grammar, left: Carol_X",
    ] {
        assert!(rig.logged(line), "{line}: {:?}", rig.log());
    }
    assert!(!rig.log().iter().any(|l| l.starts_with("alice")), "{:?}", rig.log());
    assert!(rig.snippet("alice").exists());

    // The listing fails: the sweep skipped, and the service still takes a
    // post.
    let unlisted = rig_with(&(line("labelled_volumes", None, 1, "", "Cannot connect to the Docker daemon\n") + &inspects("erin")), None, Arc::new(|_| {}));
    assert_eq!(unlisted.service.sweep(), 0);
    assert!(unlisted.logged("sweep: volumes: exit 1; the sweep is skipped") && unlisted.logged("sweep: volumes: Cannot connect to the Docker daemon"), "{:?}", unlisted.log());
    unlisted.admitted("erin", &unlisted.invite());
    unlisted.fake.assert_done();

    // A `volume_rm` that fails leaves the volume standing, which the look
    // names; an `rm_force` that fails of a run that never stood leaves
    // nothing, which the look finds.
    let script = line("labelled_volumes", None, 0, "bob\ncarol\n", "")
        + &line("rm_force", Some("bob"), 1, "", "Error: No such container: bob\n")
        + &line("volume_rm", Some("bob"), 1, "", "Error: volume is in use\n")
        + &line("volume_inspect", Some("bob"), 0, "", "")
        + &line("rm_force", Some("carol"), 1, "", "Error: No such container: carol\n")
        + &line("volume_rm", Some("carol"), 0, "", "")
        + &inspects("carol");
    let partly = rig_with(&script, None, Arc::new(|_| {}));
    assert_eq!(partly.service.sweep(), 1);
    partly.fake.assert_done();
    for line in [
        "bob: sweep: rm_force: exit 1",
        "bob: sweep: rm_force: Error: No such container: bob",
        "bob: sweep: volume_rm: exit 1",
        "bob: sweep: volume_rm: Error: volume is in use",
        "bob: sweep: INCOMPLETE — a volume stands under it, and the name refuses posts (D-4) until the operator clears it",
        "carol: sweep: rm_force: exit 1",
        "carol: sweep: volume_rm: exit 0",
        "carol: sweep: done — nothing stands under the name",
    ] {
        assert!(partly.logged(line), "{line}: {:?}", partly.log());
    }
}
