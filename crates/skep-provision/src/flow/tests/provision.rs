//! T13 — ONE POST PROVISIONED on the test's own thread, a worker's one turn
//! (`Service::run_next`): (a) the whole flow, call by call, to the snippet,
//! the live status, its page the reply, the invite spent and ONE mail sent
//! after the status turned live, and an anchorless record's page and mail
//! carrying the anchorless sentence, an anchored one's none; (b) THE DECISION
//! TABLE, one case per failing step as the provisioning record §5.2 tabulates
//! it, a failed claim run's row taking the container its `docker run` may
//! leave — the dark claim's every refusal, a shape the read refuses among
//! them — each removing what was made for the name and nothing for any other,
//! then looking at what stands and saying done, the snippet absent, the
//! reload called where the snippet was written, the status D-8, the invite
//! still issued and no mail; (c) a cleanup's removal failing — a docker
//! call's or the snippet's — logged, and the look after the removals naming
//! what stands, the name left taken; a refused `rm -f` of a run that never
//! stood, and a cleanup's reload failing, each logged as itself, the look
//! finding nothing standing; a snippet whose write failed after its rename,
//! removed by the cleanup; step 3's second look, a name taken since its post
//! failing before anything is made; a step or a cleanup that panics, costing
//! its post alone and never the worker; and the dark claim's retry, thirty
//! tries two seconds apart, its last exit 4 past them the step's failure.
//! Beside them, T12's flow half: no send before live, an outage with the
//! status live throughout, and no mail where none is configured.

use std::sync::atomic::{AtomicBool, Ordering};

use super::*;
use crate::docker::Call;
use crate::invites::InviteState;
use crate::sender::fake::messages;

/// T13 (a): THE WHOLE FLOW — the post's two inspects; then the worker's two
/// inspects, `volume_create`, `run_claim`, `sidecar_claim` with the record
/// trimmed on its stdin, `rm_force`, `run_serving`, `health` once per try,
/// `caddy_reload`, in that order and no other call; the snippet on disk;
/// the status live, its page the reply and its name among the live names;
/// the invite spent; ONE mail sent,
/// to the invite's address, after the status turned live, its body the
/// page's text; and no record byte, address, code or token in the log.
#[test]
fn the_whole_flow_runs_every_step_in_order() {
    let script = [
        inspects("alice"),
        inspects("alice"),
        line("volume_create", Some("alice"), 0, "alice\n", ""),
        line("run_claim", Some("alice"), 0, "c0ffee\n", ""),
        line("sidecar_claim", Some("alice"), 0, SIX, TALK),
        line("rm_force", Some("alice"), 0, "alice\n", ""),
        line("run_serving", Some("alice"), 0, "beef\n", ""),
        line("health", Some("alice"), 1, "", "the board did not answer\n"),
        line("health", Some("alice"), 0, PAIRED, ""),
        line("caddy_reload", None, 0, "", ""),
    ]
    .concat();
    let rig = rig(&script, Some(Vec::new()));
    let code = rig.invite();
    let token = rig.admitted("alice", &code);
    assert_eq!(rig.service.status(&token), Some(Shown::BeingMade));
    assert!(rig.service.run_next());
    assert!(!rig.service.run_next(), "one post, one turn");
    rig.fake.assert_done();
    assert_eq!(
        rig.fake.said(),
        said(&[
            "volume_inspect alice",
            "container_inspect alice",
            "volume_inspect alice",
            "container_inspect alice",
            "volume_create alice",
            "run_claim alice",
            "sidecar_claim alice",
            "rm_force alice",
            "run_serving alice",
            "health alice",
            "health alice",
            "caddy_reload",
        ])
    );
    let trimmed = record(true).trim_end().to_owned();
    assert_eq!(rig.fake.calls()[6].input.as_deref(), Some(trimmed.as_bytes()), "the record, trimmed, on the sidecar's stdin");
    assert_eq!(fs::read_to_string(rig.snippet("alice")).expect("the snippet"), crate::caddy::snippet(&Name::parse(b"alice").expect("a name"), "skep.host"));
    let status_url = crate::pages::status_url("skep.host", &token);
    let page = reply::text("https://alice.skep.host", false, &status_url);
    assert_eq!(rig.service.status(&token), Some(Shown::Live(page.clone())));
    assert!(rig.service.book().map.live().contains(&Name::parse(b"alice").expect("a name")), "alice among the live names");
    assert!(matches!(lookup(&rig.state_dir, &code).expect("read").expect("held").state, InviteState::Spent { ref name, .. } if name == "alice"));
    assert_eq!(rig.probe.seen.lock().unwrap().as_slice(), [Some(Shown::Live(page.clone()))], "one send, made with the status already live");
    let mail = messages(&rig.dir.path().join("mail.log")).expect("the mail log");
    assert_eq!(mail.len(), 1);
    assert!(mail[0].starts_with("To: person@example.com\nFrom: noreply@skep.host\nReply-To: owner@skep.host\nSubject: Your board is live\n"));
    assert!(mail[0].ends_with(&format!("\n\n{page}")), "the mail's body is the page's text");
    let log = rig.log().join("\n");
    for logged in [
        "alice: admitted; 1 waiting",
        "alice: sidecar: payload entry: 9f86d081884c7d65 anchor=true label=(none)",
        "alice: sidecar: the genesis stands: committed",
        "alice: LIVE at https://alice.skep.host",
        "alice: the invite is spent",
        "alice: mail: sent at try 1 of 7",
    ] {
        assert!(log.contains(logged), "{logged}: {log}");
    }
    for never in [code.as_str(), token.as_str(), "person@example.com", "9f9f9f9f", "skep-enroll"] {
        assert!(!log.contains(never), "the log carries {never:?}: {log}");
    }
}

/// THE ANCHORLESS FACT REACHES THE PERSON: a post whose record carries no
/// anchor-flagged entry — `skep keygen --payload`'s — goes live with the
/// anchorless sentence (AUTH-5.62) on its status page and in its mail, the
/// two one text, and an anchored post's carry none: the record's own fact,
/// carried from the post through the book to the page and the mail.
#[test]
fn an_anchorless_records_page_and_mail_carry_the_anchorless_sentence() {
    for anchor in [false, true] {
        let script = [
            inspects("alice"),
            inspects("alice"),
            to_the_serving_run(),
            line("run_serving", Some("alice"), 0, "", ""),
            line("health", Some("alice"), 0, PAIRED, ""),
            line("caddy_reload", None, 0, "", ""),
        ]
        .concat();
        let rig = rig(&script, Some(Vec::new()));
        let token = rig.post("alice", &record(anchor), rig.invite().as_str()).expect("admitted");
        assert!(rig.service.run_next());
        rig.fake.assert_done();
        let page = reply::text("https://alice.skep.host", !anchor, &crate::pages::status_url("skep.host", &token));
        assert_eq!(page.contains(crate::strings::ANCHORLESS.text), !anchor, "the reply for anchor {anchor}");
        assert_eq!(rig.service.status(&token), Some(Shown::Live(page.clone())), "the status page, anchor {anchor}");
        let mail = messages(&rig.dir.path().join("mail.log")).expect("the mail log");
        assert_eq!(mail.len(), 1, "anchor {anchor}");
        assert!(mail[0].ends_with(&format!("\n\n{page}")), "the mail, anchor {anchor}: {}", mail[0]);
    }
}

/// One case of the decision table: the script its worker runs through the
/// failure, the cleanup and the look after it, the calls that follow the
/// four inspects, and what the case does to the rig before the worker's
/// turn.
struct Case {
    what: &'static str,
    script: String,
    calls: Vec<&'static str>,
    reloads: bool,
    before: fn(&Rig),
}

fn nothing(_: &Rig) {}

#[cfg(unix)]
fn boards_read_only(rig: &Rig) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&rig.boards, fs::Permissions::from_mode(0o555)).expect("read-only");
}

fn cases() -> Vec<Case> {
    // The look after a cleanup's removals: the truth asked what stands, the
    // two inspects answering nothing.
    let looked = || vec!["volume_inspect alice", "container_inspect alice"];
    let mut cases = vec![
        Case { what: "volume_create fails", script: line("volume_create", Some("alice"), 1, "", "Error response from daemon\n"), calls: vec!["volume_create alice"], reloads: false, before: nothing },
        Case {
            what: "run_claim fails",
            script: line("volume_create", Some("alice"), 0, "", "")
                + &line("run_claim", Some("alice"), 125, "", "docker: Error response from daemon: failed to create task for container\n")
                + &run_and_volume_removed()
                + &inspects("alice"),
            calls: [vec!["volume_create alice", "run_claim alice", "rm_force alice", "volume_rm alice"], looked()].concat(),
            reloads: false,
            before: nothing,
        },
        Case {
            what: "sidecar_claim exits 4 past the bound",
            script: to_the_claim()
                + &(0..SIDECAR_WAIT.tries.get()).map(|_| line("sidecar_claim", Some("alice"), 4, "", "skep: the board could not be dialed\n")).collect::<String>()
                + &run_and_volume_removed()
                + &inspects("alice"),
            calls: [vec!["volume_create alice", "run_claim alice"], vec!["sidecar_claim alice"; SIDECAR_WAIT.tries.get() as usize], vec!["rm_force alice", "volume_rm alice"], looked()].concat(),
            reloads: false,
            before: nothing,
        },
    ];
    for (exit_code, stdout) in [(3, ""), (1, ""), (2, ""), (0, "claimed by 1.0.1\n")] {
        cases.push(Case {
            what: match exit_code {
                3 => "sidecar_claim exits 3",
                1 => "sidecar_claim exits 1",
                2 => "sidecar_claim exits 2",
                _ => "sidecar_claim answers `claimed by` on the fresh volume",
            },
            script: to_the_claim() + &line("sidecar_claim", Some("alice"), exit_code, stdout, "skep: a halt\n") + &run_and_volume_removed() + &inspects("alice"),
            calls: [vec!["volume_create alice", "run_claim alice", "sidecar_claim alice", "rm_force alice", "volume_rm alice"], looked()].concat(),
            reloads: false,
            before: nothing,
        });
    }
    cases.push(Case {
        what: "sidecar_claim answers six lines naming another account",
        script: to_the_claim() + &line("sidecar_claim", Some("alice"), 0, &SIX.replace("account 1.0.1", "account 1.0.2"), "") + &run_and_volume_removed() + &inspects("alice"),
        calls: [vec!["volume_create alice", "run_claim alice", "sidecar_claim alice", "rm_force alice", "volume_rm alice"], looked()].concat(),
        reloads: false,
        before: nothing,
    });
    let serving = vec!["volume_create alice", "run_claim alice", "sidecar_claim alice", "rm_force alice", "run_serving alice"];
    cases.push(Case {
        what: "run_serving fails",
        script: to_the_serving_run() + &line("run_serving", Some("alice"), 125, "", "Conflict\n") + &run_and_volume_removed() + &inspects("alice"),
        calls: [serving.clone(), vec!["rm_force alice", "volume_rm alice"], looked()].concat(),
        reloads: false,
        before: nothing,
    });
    cases.push(Case {
        what: "health never pairs",
        script: to_the_serving_run()
            + &line("run_serving", Some("alice"), 0, "", "")
            + &(0..HEALTH_WAIT.tries.get()).map(|_| line("health", Some("alice"), 0, UNPAIRED, "")).collect::<String>()
            + &run_and_volume_removed()
            + &inspects("alice"),
        calls: [serving.clone(), vec!["health alice"; HEALTH_WAIT.tries.get() as usize], vec!["rm_force alice", "volume_rm alice"], looked()].concat(),
        reloads: false,
        before: nothing,
    });
    #[cfg(unix)]
    cases.push(Case {
        what: "the snippet's write fails",
        script: to_the_serving_run() + &line("run_serving", Some("alice"), 0, "", "") + &line("health", Some("alice"), 0, PAIRED, "") + &run_and_volume_removed() + &inspects("alice"),
        calls: [serving.clone(), vec!["health alice", "rm_force alice", "volume_rm alice"], looked()].concat(),
        reloads: false,
        before: boards_read_only,
    });
    cases.push(Case {
        what: "caddy_reload fails",
        script: to_the_serving_run()
            + &line("run_serving", Some("alice"), 0, "", "")
            + &line("health", Some("alice"), 0, PAIRED, "")
            + &line("caddy_reload", None, 1, "", "Error: loading new config\n")
            + &line("caddy_reload", None, 0, "", "")
            + &run_and_volume_removed()
            + &inspects("alice"),
        calls: [serving, vec!["health alice", "caddy_reload", "caddy_reload", "rm_force alice", "volume_rm alice"], looked()].concat(),
        reloads: true,
        before: nothing,
    });
    cases
}

/// T13 (b): THE DECISION TABLE — for each failing step, the removals the
/// record tabulates for what was made, a failed claim run's taking the
/// container its `docker run` may leave by the record's own rule, in the
/// reverse of the order made, for the name alone, and then the look at what
/// stands, finding nothing and saying done; the snippet absent; the reload
/// called again where the snippet was written; the status D-8; the invite
/// still issued; no mail tried.
#[test]
fn each_failed_step_removes_what_was_made_and_nothing_else() {
    for case in cases() {
        let rig = rig(&(inspects("alice") + &inspects("alice") + &case.script), Some(Vec::new()));
        let code = rig.invite();
        let token = rig.admitted("alice", &code);
        (case.before)(&rig);
        assert!(rig.service.run_next(), "{}", case.what);
        rig.fake.assert_done();
        let calls = rig.fake.said();
        assert_eq!(calls[4..], said(&case.calls)[..], "{}", case.what);
        assert!(rig.fake.calls().iter().all(|c| c.name.as_deref().is_none_or(|n| n == "alice")), "{}: a call for another name", case.what);
        assert_eq!(calls.iter().filter(|c| *c == "caddy_reload").count(), if case.reloads { 2 } else { 0 }, "{}", case.what);
        assert!(!rig.snippet("alice").exists(), "{}: the snippet stands", case.what);
        assert_eq!(rig.service.status(&token), Some(Shown::Failed), "{}", case.what);
        assert!(rig.issued(&code), "{}: the invite was spent", case.what);
        assert!(rig.probe.seen.lock().unwrap().is_empty(), "{}: a mail was tried", case.what);
        let log = rig.log().join("\n");
        assert!(log.contains("alice: FAILED at "), "{}: {log}", case.what);
        assert!(!log.contains("INCOMPLETE"), "{}: {log}", case.what);
        let looked = case.calls.ends_with(&["volume_inspect alice", "container_inspect alice"]);
        assert_eq!(rig.logged("alice: cleanup: done — nothing stands under the name"), looked, "{}: the verdict, where the look was made: {log}", case.what);
        assert!(!log.contains(code.as_str()) && !log.contains(&token), "{}", case.what);
    }
}

/// T13 (c): A CLEANUP CALL THAT FAILS is logged, the next removal still
/// made, and the look after the removals NAMES WHAT STANDS — the container
/// the refused `rm -f` left — so the name is LEFT TAKEN: a re-post meets D-4
/// off what stands.
#[test]
fn a_failed_cleanup_call_leaves_the_name_taken_and_is_logged() {
    let script = [
        inspects("alice"),
        inspects("alice"),
        to_the_serving_run(),
        line("run_serving", Some("alice"), 125, "", ""),
        line("rm_force", Some("alice"), 1, "", "Error: cannot remove container\n"),
        line("volume_rm", Some("alice"), 0, "", ""),
        line("volume_inspect", Some("alice"), 1, "", ""),
        line("container_inspect", Some("alice"), 0, "[{}]", ""),
        line("volume_inspect", Some("alice"), 1, "", ""),
        line("container_inspect", Some("alice"), 0, "[{}]", ""),
    ]
    .concat();
    let rig = rig(&script, Some(Vec::new()));
    let first = rig.invite();
    let token = rig.admitted("alice", &first);
    assert!(rig.service.run_next());
    assert_eq!(rig.service.status(&token), Some(Shown::Failed));
    let log = rig.log().join("\n");
    assert!(log.contains("alice: cleanup: rm_force: exit 1"), "{log}");
    assert!(log.contains("alice: cleanup: rm_force: Error: cannot remove container"), "{log}");
    assert!(log.contains("alice: cleanup: volume_rm: exit 0"), "the next removal still made: {log}");
    assert!(log.contains("alice: cleanup: INCOMPLETE — a container stands under it, and the name refuses posts (D-4) until the operator clears it"), "{log}");
    let second = rig.invite();
    assert_eq!(rig.post("alice", &record(true), second.as_str()), Err(Refusal::Name));
    assert!(rig.log().join("\n").contains("alice: a post refused: taken — a container stands under it"));
    rig.fake.assert_done();
}

/// T13 (c): THE NAMED GAP AT THE SNIPPET — a snippet the cleanup cannot
/// remove, its directory read-only by the time the reload fails, is logged,
/// the reload still made, the run and the volume still removed, and the
/// look after the removals — the snippet read, no docker call — says
/// INCOMPLETE and names it: the snippet stands, and a re-post meets D-4 off
/// it with no docker call.
#[cfg(unix)]
#[test]
fn a_snippet_the_cleanup_cannot_remove_leaves_the_name_taken_and_is_logged() {
    use std::os::unix::fs::PermissionsExt;
    let script = [
        inspects("alice"),
        inspects("alice"),
        to_the_serving_run(),
        line("run_serving", Some("alice"), 0, "", ""),
        line("health", Some("alice"), 0, PAIRED, ""),
        line("caddy_reload", None, 1, "", "Error: loading new config\n"),
        line("caddy_reload", None, 0, "", ""),
        run_and_volume_removed(),
    ]
    .concat();
    let rig = rig(&script, None);
    let (boards, seen) = (rig.boards.clone(), Arc::new(AtomicBool::new(false)));
    rig.fake.pause(move |method, _| {
        if method == "caddy_reload" && !seen.swap(true, Ordering::SeqCst) {
            fs::set_permissions(&boards, fs::Permissions::from_mode(0o555)).expect("read-only");
        }
    });
    let token = rig.admitted("alice", &rig.invite());
    assert!(rig.service.run_next());
    assert_eq!(rig.service.status(&token), Some(Shown::Failed));
    assert!(rig.snippet("alice").exists(), "the snippet the cleanup could not remove");
    for logged in ["alice: cleanup: caddy_reload: exit 0", "alice: cleanup: rm_force: exit 0", "alice: cleanup: volume_rm: exit 0"] {
        assert!(rig.logged(logged), "{logged}: {:?}", rig.log());
    }
    for opens in ["alice: cleanup: snippet: not removed: ", "alice: cleanup: INCOMPLETE — its snippet stands"] {
        assert!(rig.log().iter().any(|l| l.starts_with(opens)), "{opens}: {:?}", rig.log());
    }
    assert_eq!(rig.post("alice", &record(true), rig.invite().as_str()), Err(Refusal::Name));
    assert!(rig.logged("alice: a post refused: taken — its snippet stands"), "{:?}", rig.log());
    rig.fake.assert_done();
}

/// T13 (c): A CLEANUP WHOSE RELOAD FAILS LEAVES NOTHING STANDING: the
/// reload's failure is logged as itself — the snippet removed, the run and
/// the volume removed — and the look after the removals finds nothing the
/// truth about names reads standing, so the cleanup is said done, never
/// INCOMPLETE: a re-post for the name is admitted.
#[test]
fn a_cleanup_whose_reload_fails_leaves_nothing_standing() {
    let script = [
        inspects("alice"),
        inspects("alice"),
        to_the_serving_run(),
        line("run_serving", Some("alice"), 0, "", ""),
        line("health", Some("alice"), 0, PAIRED, ""),
        line("caddy_reload", None, 1, "", "Error: loading new config\n"),
        line("caddy_reload", None, 1, "", "Error: loading new config\n"),
        run_and_volume_removed(),
        inspects("alice"),
        inspects("alice"),
    ]
    .concat();
    let rig = rig(&script, None);
    let token = rig.admitted("alice", &rig.invite());
    assert!(rig.service.run_next());
    assert_eq!(rig.service.status(&token), Some(Shown::Failed));
    assert!(!rig.snippet("alice").exists(), "the snippet stands");
    for logged in [
        "alice: cleanup: snippet: removed",
        "alice: cleanup: caddy_reload: exit 1",
        "alice: cleanup: rm_force: exit 0",
        "alice: cleanup: volume_rm: exit 0",
        "alice: cleanup: done — nothing stands under the name",
    ] {
        assert!(rig.logged(logged), "{logged}: {:?}", rig.log());
    }
    assert!(!rig.log().iter().any(|l| l.contains("INCOMPLETE")), "{:?}", rig.log());
    rig.admitted("alice", &rig.invite());
    rig.fake.assert_done();
}

/// T13 (c): A REFUSED `rm -f` OF A RUN THAT NEVER STOOD — the serving
/// run's `docker run` refused before it made one — leaves nothing
/// standing: the refusal logged, the volume removed, the look after the
/// removals finding nothing, the cleanup said done, never INCOMPLETE; a
/// re-post for the name is admitted.
#[test]
fn a_refused_rm_of_a_run_that_never_stood_leaves_nothing_standing() {
    let script = [
        inspects("alice"),
        inspects("alice"),
        to_the_serving_run(),
        line("run_serving", Some("alice"), 125, "", "docker: Error response from daemon: network skep not found.\n"),
        line("rm_force", Some("alice"), 1, "", "Error: No such container: alice\n"),
        line("volume_rm", Some("alice"), 0, "", ""),
        inspects("alice"),
        inspects("alice"),
    ]
    .concat();
    let rig = rig(&script, None);
    let token = rig.admitted("alice", &rig.invite());
    assert!(rig.service.run_next());
    assert_eq!(rig.service.status(&token), Some(Shown::Failed));
    for logged in
        ["alice: cleanup: rm_force: exit 1", "alice: cleanup: rm_force: Error: No such container: alice", "alice: cleanup: volume_rm: exit 0", "alice: cleanup: done — nothing stands under the name"]
    {
        assert!(rig.logged(logged), "{logged}: {:?}", rig.log());
    }
    assert!(!rig.log().iter().any(|l| l.contains("INCOMPLETE")), "{:?}", rig.log());
    rig.admitted("alice", &rig.invite());
    rig.fake.assert_done();
}

/// T13 (c): THE SNIPPET's WRITE FAILING AFTER ITS RENAME — the directory's
/// sync refused, the snippet standing — is a failed step whose cleanup
/// removes the snippet and reloads: the snippet is the cleanup's from its
/// write's first act, so the write's error is read as a snippet that may
/// stand, and the look after the removals finds nothing standing under the
/// name.
#[cfg(unix)]
#[test]
fn a_snippet_whose_write_failed_after_its_rename_is_removed_by_the_cleanup() {
    use std::os::unix::fs::PermissionsExt;
    let script = [
        inspects("alice"),
        inspects("alice"),
        to_the_serving_run(),
        line("run_serving", Some("alice"), 0, "", ""),
        line("health", Some("alice"), 0, PAIRED, ""),
        line("caddy_reload", None, 0, "", ""),
        run_and_volume_removed(),
        inspects("alice"),
    ]
    .concat();
    let rig = rig(&script, None);
    // The snippet directory writable and searchable but not readable: the
    // snippet's rename lands and the directory's sync, an open of the
    // directory, is refused. Once the write's failure is logged the
    // directory is readable again, so the cleanup's removal is made whole.
    let boards = rig.boards.clone();
    rig.on_log(move |line| {
        if line.starts_with("alice: snippet: the write failed: ") {
            fs::set_permissions(&boards, fs::Permissions::from_mode(0o700)).expect("readable again");
        }
    });
    let code = rig.invite();
    let token = rig.admitted("alice", &code);
    fs::set_permissions(&rig.boards, fs::Permissions::from_mode(0o300)).expect("not readable");
    assert!(rig.service.run_next());
    rig.fake.assert_done();
    let after = [
        "volume_create alice",
        "run_claim alice",
        "sidecar_claim alice",
        "rm_force alice",
        "run_serving alice",
        "health alice",
        "caddy_reload",
        "rm_force alice",
        "volume_rm alice",
        "volume_inspect alice",
        "container_inspect alice",
    ];
    assert_eq!(rig.fake.said()[4..], said(&after)[..]);
    assert!(!rig.snippet("alice").exists(), "the snippet stands");
    assert_eq!(rig.service.status(&token), Some(Shown::Failed));
    assert!(rig.issued(&code));
    for logged in ["alice: FAILED at the snippet's write", "alice: cleanup: snippet: removed", "alice: cleanup: caddy_reload: exit 0", "alice: cleanup: done — nothing stands under the name"] {
        assert!(rig.logged(logged), "{logged}: {:?}", rig.log());
    }
}

/// THE DARK CLAIM's RETRY: exit 4 — the claim run's daemon not yet
/// listening — is tried again after a sleep of the bound's interval, and
/// the bound is the one the flow states, thirty tries two seconds apart;
/// past it — thirty exits 4, a sleep before each try but the first — the
/// last exit 4 is the step's failure, named once.
#[test]
fn the_dark_claim_retries_exit_4_two_seconds_apart_thirty_times() {
    assert_eq!((SIDECAR_WAIT.tries.get(), SIDECAR_WAIT.interval), (30, Duration::from_secs(2)), "thirty tries two seconds apart");
    let slept = Arc::new(Mutex::new(Vec::new()));
    let into = Arc::clone(&slept);
    let rig = rig_with(&(flow_of("alice", true) + &reloads(1)), None, Arc::new(move |d: Duration| into.lock().unwrap().push(d)));
    let token = rig.admitted("alice", &rig.invite());
    assert!(rig.service.run_next());
    assert!(rig.live(&token));
    assert_eq!(*slept.lock().unwrap(), [SIDECAR_WAIT.interval], "one sleep, between the two tries");
    rig.fake.assert_done();

    let tries = SIDECAR_WAIT.tries.get() as usize;
    let slept = Arc::new(Mutex::new(Vec::new()));
    let into = Arc::clone(&slept);
    let script = inspects("alice")
        + &inspects("alice")
        + &to_the_claim()
        + &line("sidecar_claim", Some("alice"), 4, "", "skep: the board could not be dialed\n").repeat(tries)
        + &run_and_volume_removed()
        + &inspects("alice");
    let past = rig_with(&script, None, Arc::new(move |d: Duration| into.lock().unwrap().push(d)));
    let token = past.admitted("alice", &past.invite());
    assert!(past.service.run_next());
    assert_eq!(past.service.status(&token), Some(Shown::Failed));
    assert_eq!(*slept.lock().unwrap(), vec![SIDECAR_WAIT.interval; tries - 1], "a sleep before each try but the first");
    assert_eq!(past.log().iter().filter(|l| *l == "alice: sidecar_claim: exit 4 (transport)").count(), 1, "{:?}", past.log());
    assert!(past.logged("alice: FAILED at the dark claim"), "{:?}", past.log());
    past.fake.assert_done();
}

/// STEP 3's SECOND LOOK: a name taken since its post — its snippet written,
/// a volume or a container made under it meanwhile — fails the post at the
/// look, D-8, before anything is made: no `volume_create`, and no cleanup,
/// so nothing this post never made is removed — the snippet that took the
/// name stands as written — and the invite still issued.
#[test]
fn a_name_taken_since_its_post_fails_before_anything_is_made() {
    let volume = line("volume_inspect", Some("alice"), 0, "", "");
    let container = line("volume_inspect", Some("alice"), 1, "", "") + &line("container_inspect", Some("alice"), 0, "", "");
    for (by, written, worker, looked) in [
        ("its snippet stands", true, String::new(), vec![]),
        ("a volume stands under it", false, volume, vec!["volume_inspect alice"]),
        ("a container stands under it", false, container, vec!["volume_inspect alice", "container_inspect alice"]),
    ] {
        let rig = rig(&(inspects("alice") + &worker), None);
        let code = rig.invite();
        let token = rig.admitted("alice", &code);
        if written {
            fs::write(rig.snippet("alice"), b"a snippet written by hand").expect("a snippet");
        }
        assert!(rig.service.run_next(), "{by}");
        rig.fake.assert_done();
        assert_eq!(rig.fake.said(), said(&[&["volume_inspect alice", "container_inspect alice"][..], &looked[..]].concat()), "{by}");
        assert_eq!(rig.service.status(&token), Some(Shown::Failed), "{by}");
        assert!(rig.issued(&code), "{by}: the invite was spent");
        for logged in [format!("alice: taken since the post: {by}"), "alice: FAILED at the second look at the name".to_owned()] {
            assert!(rig.logged(&logged), "{logged}: {:?}", rig.log());
        }
        assert!(!rig.log().iter().any(|l| l.contains("cleanup")), "{by}: a cleanup of what this post never made: {:?}", rig.log());
        if written {
            assert_eq!(fs::read(rig.snippet("alice")).expect("the snippet stands"), b"a snippet written by hand");
        }
    }
}

/// T13 (c): A STEP OR A CLEANUP THAT PANICS costs its post alone, never the
/// worker: a step that panics is a failed step — `run_claim` panicking once
/// the volume is made, the run it may have left and the volume removed by the
/// cleanup, and the look after them finding nothing — and a cleanup that
/// panics too — its `volume rm` panicking — is logged INCOMPLETE; either way
/// the worker's turn ends, the post is D-8, its invite still issued and its
/// code let go of: the post made again on it is admitted.
#[test]
fn a_step_or_a_cleanup_that_panics_costs_its_post_alone() {
    /// A runner that panics at the claim run, and at the volume's removal
    /// where `volume_rm_panics`: the volume's creation and its removal
    /// otherwise exit 0, and every other call exit 1 — nothing standing.
    struct Panics {
        volume_rm_panics: bool,
    }
    impl Docker for Panics {
        fn run(&self, call: Call<'_>) -> io::Result<Exit> {
            let exit_code = match call {
                Call::RunClaim(_) => panic!("a step's call that panics"),
                Call::VolumeRm(_) if self.volume_rm_panics => panic!("a cleanup's call that panics"),
                Call::VolumeCreate(_) | Call::VolumeRm(_) => 0,
                _ => 1,
            };
            Ok(Exit { code: Some(exit_code), stdout: Vec::new(), stderr: Vec::new() })
        }
    }
    for volume_rm_panics in [false, true] {
        let dir = Scratch::new();
        let boards = dir.path().join("boards");
        fs::create_dir(&boards).expect("the snippet directory");
        let state_dir = StateDir::open(&dir.path().join("state")).expect("the state directory");
        let lines = Arc::new(Mutex::new(Vec::new()));
        let into = Arc::clone(&lines);
        let log: Log = Arc::new(move |line: &str| into.lock().unwrap().push(line.to_owned()));
        let config = Config { boards_dir: boards, suffix: "skep.host".into() };
        let service = Service::new(config, state_dir.clone(), Box::new(Panics { volume_rm_panics }), None, log, Arc::new(|_| {})).expect("the service");
        let code = mint(&state_dir, &MailAddress::parse("person@example.com").expect("an address"), None).expect("minted");
        let record = record(true);
        let post = Post { name: b"alice", record: record.as_bytes(), invite: code.as_str().as_bytes() };
        let token = service.admit(&post).expect("admitted");
        assert!(service.run_next(), "{volume_rm_panics}");
        assert_eq!(service.status(&token), Some(Shown::Failed), "{volume_rm_panics}");
        assert!(lookup(&state_dir, &code).expect("read").expect("held").issued(), "{volume_rm_panics}: the invite was spent");
        let cleaned = if volume_rm_panics {
            "alice: cleanup: INCOMPLETE — the cleanup panicked, and what it had not undone stands until the operator clears it"
        } else {
            "alice: cleanup: done — nothing stands under the name"
        };
        let log = lines.lock().unwrap().clone();
        for logged in ["alice: FAILED at a step that panicked", cleaned] {
            assert!(log.iter().any(|l| l == logged), "{logged}: {log:?}");
        }
        assert!(log.iter().any(|l| l == "alice: cleanup: rm_force: exit 1"), "the claim run, recorded from its first act, not removed: {log:?}");
        assert!(service.admit(&post).is_ok(), "{volume_rm_panics}: the code, or the name, held past the post's end");
    }
}

/// T12: A MAIL OUTAGE — every try refused — is retried to its bound on the
/// sender's side and given up, THE STATUS LIVE THROUGHOUT: every try made
/// with the page already live, and live after.
#[test]
fn a_mail_outage_leaves_the_status_live_throughout() {
    let script = [
        inspects("alice"),
        inspects("alice"),
        to_the_serving_run(),
        line("run_serving", Some("alice"), 0, "", ""),
        line("health", Some("alice"), 0, PAIRED, ""),
        line("caddy_reload", None, 0, "", ""),
    ]
    .concat();
    let rig = rig(&script, Some(vec![75; crate::sender::MAIL_WAIT.tries.get() as usize]));
    let code = rig.invite();
    let token = rig.admitted("alice", &code);
    assert!(rig.service.run_next());
    let seen = rig.probe.seen.lock().unwrap().clone();
    assert_eq!(seen.len(), crate::sender::MAIL_WAIT.tries.get() as usize);
    assert!(seen.iter().all(|s| matches!(s, Some(Shown::Live(_)))), "a try made before the status was live");
    assert!(matches!(rig.service.status(&token), Some(Shown::Live(_))));
    assert!(messages(&rig.dir.path().join("mail.log")).expect("the log").is_empty());
    assert!(rig.log().join("\n").contains("alice: mail: given up after 7 tries; the board stands live"));
}

/// With no mail configured the board goes live and nothing is sent.
#[test]
fn with_no_mail_the_board_goes_live_and_nothing_is_sent() {
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
    let token = rig.admitted("alice", &code);
    assert!(rig.service.run_next());
    assert!(matches!(rig.service.status(&token), Some(Shown::Live(_))));
    assert!(rig.probe.seen.lock().unwrap().is_empty());
    assert!(!rig.log().join("\n").contains("mail"));
}
