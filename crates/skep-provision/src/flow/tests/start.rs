//! THE SERVICE's START: the status map rebuilt from the snippets standing;
//! THE SWEEP, T20 (its listing named before it is made and its answer logged
//! as every call's is, the half-made board removed — its run's last lines
//! unread, a stop's leavings no failure's — the routed and the ungrammatical
//! left, a listing that fails and a snippet directory it cannot search each
//! skipped on a line of its own naming what the skip leaves taken and the
//! act, a volume the removals left said the next start's too, a snippet with
//! no volume under the label said and left, a routed board with no invite
//! line spent under it named and left, and a sweep that listed ending on its
//! summary); a `docker` that cannot be run at all — the sweep skipped, a post
//! refused D-8, the look's line naming `docker`; and a `docker` that lists
//! and then cannot run — the half-made board left INCOMPLETE, never cleared,
//! the look named as what could not be made, and the act once one can be.

use super::*;
use crate::docker::Call;

/// The line a listing that fails is skipped on: what the skip leaves taken,
/// and the operator's act.
const SKIPPED: &str = "sweep: the volumes under the label could not be listed; the sweep is skipped — a board a stop left half-made stays taken until a start whose listing answers: restart once `docker volume ls` answers as the service's user";

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
/// nothing: no post waiting, no code held — its look's hold let go — the
/// invite still issued.
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
    assert!(book.queue.is_empty() && book.admitted.is_empty() && book.looking.is_empty() && !book.map.holds(&Name::parse(b"alice").expect("a name")));
    drop(book);
    assert!(lookup(&state_dir, &code).expect("read").expect("held").issued());
    let log = lines.lock().unwrap().clone();
    assert!(log.iter().any(|l| l.starts_with("sweep: volumes: docker could not run: ")), "{log:?}");
    assert!(log.iter().any(|l| l == SKIPPED), "{log:?}");
    assert!(log.iter().any(|l| l.starts_with("alice: a post could not be judged: the look at the name: docker could not run: ")), "the look's line naming docker: {log:?}");
}

/// THE VERDICT WHERE NO LOOK CAN BE MADE: a `docker` that answers the
/// sweep's listing and then cannot be run at all — the run's and the
/// volume's removals each logged as one that could not run, the look after
/// them unmade — leaves the half-made board INCOMPLETE, the look named as
/// what could not be made, `docker` its source, and the operator's act once
/// one can be: never said done, never counted cleared.
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
    for opens in ["bob: sweep: rm_force: docker could not run: ", "bob: sweep: volume_rm: docker could not run: "] {
        assert!(log.iter().any(|l| l.starts_with(opens)), "{opens}: {log:?}");
    }
    let act = "; what stands under the name is the operator's to clear once a look can be made (RUNBOOK §10 step 9), a volume with no snippet the next start's sweep's";
    assert!(
        log.iter().any(|l| l.starts_with("bob: sweep: INCOMPLETE — the look at what stands could not be made: docker could not run: ") && l.ends_with(act)),
        "the look named, docker its source, the act after it: {log:?}"
    );
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
/// taking a post, no summary said; a `volume_rm` failure — logged, and the
/// look naming the volume that stands, the name left, not counted; an
/// `rm_force` failure (no container) logged as itself, the volume still
/// removed and the look finding nothing. A sweep that listed ends on its
/// summary: the volumes listed, the half-made, the cleared, the names left
/// INCOMPLETE, the time it took.
#[test]
fn the_sweep_removes_a_half_made_board_and_leaves_the_rest() {
    let script = line("labelled_volumes", None, 0, "alice\nbob\nCarol_X\n", "") + &line("rm_force", Some("bob"), 0, "", "") + &line("volume_rm", Some("bob"), 0, "", "") + &inspects("bob");
    let mut rig = rig(&script, None);
    // `alice` a live board as this service leaves one: its snippet standing,
    // and its invite's line spent under it.
    fs::write(rig.snippet("alice"), b"").expect("alice's snippet");
    let alices = rig.invite();
    crate::invites::spend(&rig.state_dir, &alices, &Name::parse(b"alice").expect("a name")).expect("spent");
    assert_eq!(rig.sweep(), 1);
    rig.fake.assert_done();
    assert_eq!(rig.fake.said(), said(&["labelled_volumes", "rm_force bob", "volume_rm bob", "volume_inspect bob", "container_inspect bob"]));
    let at = |wanted: &str| rig.log().iter().position(|l| l == wanted).unwrap_or_else(|| panic!("{wanted}: {:?}", rig.log()));
    assert!(at("sweep: listing the volumes under the label") < at("sweep: volumes: exit 0"), "the listing named before it is made: {:?}", rig.log());
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
    assert!(rig.logged_around("sweep: 3 volumes under the label, 1 of them half-made and 1 cleared; in ", " ms"), "the sweep's summary: {:?}", rig.log());
    assert_eq!(rig.log().last().map(|l| l.starts_with("sweep: 3 volumes under the label, ")), Some(true), "the summary the sweep's last line: {:?}", rig.log());

    // The listing fails: the sweep skipped, no summary said, and the service
    // still takes a post.
    let mut unlisted = rig_with(&(line("labelled_volumes", None, 1, "", "Cannot connect to the Docker daemon\n") + &inspects("erin")), None, Arc::new(|_| {}));
    assert_eq!(unlisted.sweep(), 0);
    for logged in ["sweep: volumes: exit 1", "sweep: volumes: Cannot connect to the Docker daemon", SKIPPED] {
        assert!(unlisted.logged(logged), "{logged}: {:?}", unlisted.log());
    }
    assert!(!unlisted.log().iter().any(|l| l.contains(" under the label, ")), "a summary of a sweep skipped: {:?}", unlisted.log());
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
        "bob: sweep: INCOMPLETE — a volume stands under it, and the name refuses posts (D-4) until the operator clears it, or the next start's sweep removes it",
        "carol: sweep: rm_force: exit 1",
        "carol: sweep: volume_rm: exit 0",
        "carol: sweep: done — nothing stands under the name",
    ] {
        assert!(partly.logged(logged), "{logged}: {:?}", partly.log());
    }
    assert!(partly.logged_around("sweep: 2 volumes under the label, 2 of them half-made and 1 cleared; left INCOMPLETE: bob; in ", " ms"), "the summary naming what it left: {:?}", partly.log());
}

/// A SNIPPET WITH NO VOLUME UNDER THE LABEL is said at the sweep and left —
/// a route to no board, its name taken for good, or a board made by hand,
/// the operator's to tell, with the inspect that tells it — beside a
/// snippet whose volume the listing holds, which says nothing; nothing is
/// removed for either, and the summary counts what the listing held.
#[test]
fn a_snippet_with_no_volume_under_the_label_is_said_and_left() {
    let dir = Scratch::new();
    let boards = dir.path().join("boards");
    fs::create_dir(&boards).expect("the snippet directory");
    for name in ["alice", "dave"] {
        fs::write(boards.join(format!("{name}.caddy")), b"").expect("a snippet");
    }
    let state_dir = StateDir::open(&dir.path().join("state")).expect("the state directory");
    // `alice` a live board as this service leaves one: its invite's line
    // spent under it.
    let alices = mint(&state_dir, &MailAddress::parse("person@example.com").expect("an address"), None).expect("minted");
    crate::invites::spend(&state_dir, &alices, &Name::parse(b"alice").expect("a name")).expect("spent");
    let lines = Arc::new(Mutex::new(Vec::new()));
    let into = Arc::clone(&lines);
    let log: Log = Arc::new(move |line: &str| into.lock().unwrap().push(line.to_owned()));
    let fake = Arc::new(FakeDocker::parse(&line("labelled_volumes", None, 0, "alice\n", "")).expect("a script"));
    let config = Config { boards_dir: boards, suffix: suffix() };
    let mut service = Service::new(config, state_dir, Box::new(Arc::clone(&fake)), None, log, Arc::new(|_| {})).expect("the service");
    assert_eq!(service.sweep(), 0);
    fake.assert_done();
    let log = lines.lock().unwrap().clone();
    assert!(log.iter().any(|l| l == "dave: its snippet stands with no volume under the label — a route to no board, or a board made by hand: `docker volume inspect dave` tells which"), "{log:?}");
    assert!(!log.iter().any(|l| l.starts_with("alice")), "a snippet the listing holds a volume for, said: {log:?}");
    assert!(log.iter().any(|l| l.starts_with("sweep: 1 volume under the label, 0 of them half-made and 0 cleared; in ") && l.ends_with(" ms")), "{log:?}");
}

/// A ROUTED BOARD WITH NO INVITE SPENT UNDER IT is said at the sweep: a stop
/// between its snippet's write and its spend, or a spend that could not be
/// written, left its invite issued, which a post spends again on a second
/// board — so the start names the board and the act, before it serves, and
/// leaves it, no call made for it; a routed board whose invite is spent under
/// it says nothing.
#[test]
fn a_routed_board_with_no_invite_spent_under_it_is_said_at_the_sweep() {
    let mut rig = rig(&line("labelled_volumes", None, 0, "alice\nbob\n", ""), None);
    for routed in ["alice", "bob"] {
        fs::write(rig.snippet(routed), b"").expect("a snippet");
    }
    let alices = rig.invite();
    crate::invites::spend(&rig.state_dir, &alices, &Name::parse(b"alice").expect("a name")).expect("spent");
    let bobs = rig.invite();
    assert_eq!(rig.sweep(), 0);
    rig.fake.assert_done();
    let act = "the invite its post named may still say issued, and a post naming it is admitted again until the operator marks it spent under bob (RUNBOOK §10 step 11), its issue date on the `bob: admitted` line the log holds from before this start";
    assert!(rig.logged_around("bob: routed at start with no invite line spent under it — ", act), "{:?}", rig.log());
    assert!(!rig.log().iter().any(|l| l.starts_with("alice: routed at start")), "a board spent under, said: {:?}", rig.log());
    assert!(rig.issued(&bobs) && rig.snippet("bob").exists(), "the sweep marks no invite and removes no routed board");
    assert!(rig.logged_around("sweep: 2 volumes under the label, 0 of them half-made and 0 cleared; in ", " ms"), "{:?}", rig.log());
}

/// A SNIPPET DIRECTORY THE SWEEP CANNOT SEARCH skips it on a line of its own
/// naming the directory by its path, what the skip leaves taken and the act
/// — the listing made, nothing removed, the count 0.
#[cfg(unix)]
#[test]
fn a_snippet_directory_the_sweep_cannot_search_skips_it_and_says_what_that_leaves() {
    use std::os::unix::fs::PermissionsExt;
    let mut rig = rig(&line("labelled_volumes", None, 0, "bob\n", ""), None);
    fs::set_permissions(&rig.boards, fs::Permissions::from_mode(0o000)).expect("unsearchable");
    let swept = rig.sweep();
    fs::set_permissions(&rig.boards, fs::Permissions::from_mode(0o700)).expect("searchable again");
    assert_eq!(swept, 0);
    rig.fake.assert_done();
    let skipped = format!(" — {}; the sweep is skipped — a board a stop left half-made stays taken until a start that reads it: restart once it reads as the service's user", rig.boards.display());
    assert!(rig.log().iter().any(|l| l.starts_with("sweep: the snippet directory could not be read: ") && l.ends_with(&skipped)), "the directory named by its path: {:?}", rig.log());
}
