//! THE SERVICE's START: the status map rebuilt from the snippets standing;
//! THE SWEEP, T20 (its listing's answer logged as every call's is, the
//! half-made board removed, the routed and the ungrammatical left, a listing
//! that fails skipped on a line of its own); a `docker` that cannot be run at
//! all — the sweep skipped, a post refused D-8; and a `docker` that lists and
//! then cannot run — the half-made board left INCOMPLETE, never cleared.

use super::*;
use crate::docker::Call;

/// The rebuild at the service's start: the snippets standing are the names
/// routed at start, which the serving line counts as `live`.
#[test]
fn the_service_counts_the_snippets_standing_at_start() {
    let rig = rig("", None);
    fs::write(rig.snippet("alice"), b"").expect("a snippet");
    let config = Config { boards_dir: rig.boards.clone(), suffix: suffix() };
    let again = Service::new(config, rig.state_dir.clone(), Box::new(Arc::clone(&rig.fake)), None, Arc::new(|_: &str| {}), Arc::new(|_| {})).expect("the service");
    assert_eq!(again.routed_at_start_count(), 1);
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
    let config = Config { boards_dir: boards, suffix: suffix() };
    let mut service = Service::new(config, state_dir.clone(), Box::new(NoDocker), None, log, Arc::new(|_| {})).expect("the service");
    assert_eq!(service.sweep(), 0);
    let code = mint(&state_dir, &MailAddress::parse("person@example.com").expect("an address"), None).expect("minted");
    let record = record(true);
    assert_eq!(service.admit(&Post { name: b"alice", record: record.as_bytes(), invite: code.as_str().as_bytes() }), Err(Refusal::Failed));
    let book = service.book();
    assert!(book.queue.is_empty() && book.codes.is_empty() && !book.map.holds(&Name::parse(b"alice").expect("a name")));
    drop(book);
    assert!(lookup(&state_dir, &code).expect("read").expect("held").issued());
    let log = lines.lock().unwrap().clone();
    assert!(log.iter().any(|l| l.starts_with("sweep: volumes: docker could not run: ")), "{log:?}");
    assert!(log.iter().any(|l| l == "sweep: the volumes under the label could not be listed; the sweep is skipped"), "{log:?}");
    assert!(log.iter().any(|l| l.starts_with("alice: a post could not be judged: the look at the name: ")), "{log:?}");
}

/// THE VERDICT WHERE NO LOOK CAN BE MADE: a `docker` that answers the
/// sweep's listing and then cannot be run at all — the run's and the
/// volume's removals each logged as one that could not run, the look after
/// them unmade — leaves the half-made board INCOMPLETE, the look named as
/// what could not be made: never said done, never counted cleared.
#[test]
fn a_look_that_cannot_be_made_never_clears_a_name() {
    /// A runner that lists `bob` and can run nothing after it.
    struct ListsThenGone;
    impl Docker for ListsThenGone {
        fn run(&self, call: Call<'_>) -> io::Result<Exit> {
            match call {
                Call::LabelledVolumes => Ok(Exit { code: Some(0), stdout: b"bob\n".to_vec(), stderr: Vec::new() }),
                _ => Err(io::Error::from(io::ErrorKind::NotFound)),
            }
        }
    }
    let dir = Scratch::new();
    let boards = dir.path().join("boards");
    fs::create_dir(&boards).expect("the snippet directory");
    let state_dir = StateDir::open(&dir.path().join("state")).expect("the state directory");
    let lines = Arc::new(Mutex::new(Vec::new()));
    let into = Arc::clone(&lines);
    let log: Log = Arc::new(move |line: &str| into.lock().unwrap().push(line.to_owned()));
    let config = Config { boards_dir: boards, suffix: suffix() };
    let mut service = Service::new(config, state_dir, Box::new(ListsThenGone), None, log, Arc::new(|_| {})).expect("the service");
    assert_eq!(service.sweep(), 0, "a board counted cleared though no look was made");
    let log = lines.lock().unwrap().clone();
    for opens in ["bob: sweep: rm_force: docker could not run: ", "bob: sweep: volume_rm: docker could not run: ", "bob: sweep: INCOMPLETE — the look at what stands could not be made: "] {
        assert!(log.iter().any(|l| l.starts_with(opens)), "{opens}: {log:?}");
    }
    assert!(!log.iter().any(|l| l.ends_with("done — nothing stands under the name")), "{log:?}");
}

/// T20: THE SWEEP — `labelled_volumes` answering `alice`, `bob` and
/// `Carol_X` with `alice.caddy` standing and no `bob.caddy`: the listing's
/// answer logged as every call's is, then `rm_force bob` and `volume_rm
/// bob`, then the look at what stands under `bob`, finding nothing; nothing
/// for `alice`, nothing for `Carol_X` (logged as under no name of the
/// grammar), the count 1, the log naming the name and each step; a
/// `labelled_volumes` exit 1 — logged with its stderr as every call's is,
/// the skip on a line of its own, the count 0, the service standing and
/// taking a post; a `volume_rm` failure — logged, and the look naming the
/// volume that stands, the name left, not counted; an `rm_force` failure
/// (no container) logged as itself, the volume still removed and the look
/// finding nothing.
#[test]
fn the_sweep_removes_a_half_made_board_and_leaves_the_rest() {
    let script = line("labelled_volumes", None, 0, "alice\nbob\nCarol_X\n", "") + &line("rm_force", Some("bob"), 0, "", "") + &line("volume_rm", Some("bob"), 0, "", "") + &inspects("bob");
    let mut rig = rig(&script, None);
    fs::write(rig.snippet("alice"), b"").expect("alice's snippet");
    assert_eq!(rig.sweep(), 1);
    rig.fake.assert_done();
    assert_eq!(rig.fake.said(), said(&["labelled_volumes", "rm_force bob", "volume_rm bob", "volume_inspect bob", "container_inspect bob"]));
    for logged in [
        "sweep: volumes: exit 0",
        "bob: half-made at start (a volume, no snippet) — removing",
        "bob: sweep: rm_force: exit 0",
        "bob: sweep: volume_rm: exit 0",
        "bob: sweep: done — nothing stands under the name",
        "sweep: a volume under the label is under no name of the grammar, left: Carol_X",
    ] {
        assert!(rig.logged(logged), "{logged}: {:?}", rig.log());
    }
    assert!(!rig.log().iter().any(|l| l.starts_with("alice")), "{:?}", rig.log());
    assert!(rig.snippet("alice").exists());

    // The listing fails: the sweep skipped, and the service still takes a
    // post.
    let mut unlisted = rig_with(&(line("labelled_volumes", None, 1, "", "Cannot connect to the Docker daemon\n") + &inspects("erin")), None, Arc::new(|_| {}));
    assert_eq!(unlisted.sweep(), 0);
    for logged in ["sweep: volumes: exit 1", "sweep: volumes: Cannot connect to the Docker daemon", "sweep: the volumes under the label could not be listed; the sweep is skipped"] {
        assert!(unlisted.logged(logged), "{logged}: {:?}", unlisted.log());
    }
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
    let mut partly = rig_with(&script, None, Arc::new(|_| {}));
    assert_eq!(partly.sweep(), 1);
    partly.fake.assert_done();
    for logged in [
        "bob: sweep: rm_force: exit 1",
        "bob: sweep: rm_force: Error: No such container: bob",
        "bob: sweep: volume_rm: exit 1",
        "bob: sweep: volume_rm: Error: volume is in use",
        "bob: sweep: INCOMPLETE — a volume stands under it, and the name refuses posts (D-4) until the operator clears it",
        "carol: sweep: rm_force: exit 1",
        "carol: sweep: volume_rm: exit 0",
        "carol: sweep: done — nothing stands under the name",
    ] {
        assert!(partly.logged(logged), "{logged}: {:?}", partly.log());
    }
}
