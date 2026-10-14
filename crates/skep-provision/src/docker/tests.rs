//! T4 — THE ARGV of every call, token by token, against the documents' run
//! lines: the smoke's claim run WORD FOR WORD (and read back from
//! `scripts/docker-smoke.sh` itself, so the script's drift is a red test
//! too), the deployment notes' serving run — and the RUNBOOK's line that
//! makes a standing board's serving run again, read back word for word —
//! the sidecar's run with `-i` and `--hosted -`, the `skep health` run, the
//! reload, the two inspects, the two removals, a failed run's last lines
//! read before its removal, the labelled volume and the listing by its
//! label (T19); the image's port and its volume read back from the
//! `Dockerfile`; the real `Command` built from that argv and nothing else;
//! the real runner, over a recording script in `docker`'s place — no Docker
//! is run — passing the argv, the record on stdin and nothing on any other
//! call's, and the two streams apart; each named method running its own
//! call through the one method a runner writes; and the fake refusing a
//! call it was not scripted, its order strict per name and free across
//! names.

use std::path::Path;

use skep_identity::{encode_enroll, Enrollment};

use super::fake::{line, FakeDocker, UNEXPECTED};
use super::*;
use crate::record::{admit, decodable_key};
use crate::scratch::Scratch;

/// The alpha's settings: the README's tags, the notes' bridge and proxy,
/// the README's rotation.
fn settings() -> Settings {
    Settings {
        image: "skep-hosted".into(),
        cli_image: "skep-cli".into(),
        network: "skep".into(),
        caddy: "caddy".into(),
        suffix: domain("skep.host"),
        log_max_size: "10m".into(),
        log_max_file: files(5),
    }
}

/// A count of log files kept: one or more.
fn files(n: u32) -> NonZeroU32 {
    NonZeroU32::new(n).expect("a count of one or more")
}

/// A suffix by the grammar.
fn domain(text: &str) -> Domain {
    Domain::parse(text).expect("a domain")
}

fn alice() -> Name {
    Name::parse(b"alice").expect("a name")
}

/// An admitted record, the one input a call carries: one production key
/// whose halves decode, as the person's device prints it.
fn record() -> Record {
    admit(encode_enroll(&[Enrollment::new(decodable_key(0x9f), true, None).expect("no label")]).as_bytes()).expect("an admitted record")
}

/// A run line as the documents write it, split into its words.
fn words(line: &str) -> Vec<String> {
    line.split_whitespace().map(str::to_owned).collect()
}

/// T4: EVERY CALL's ARGV, token by token. The claim run is the smoke's
/// line (`scripts/docker-smoke.sh`, the claim run) with the public origin
/// in its local one's place; the serving run the deployment notes' step 5
/// line, in its order, the README's rotation; the sidecar the smoke's run
/// with the record on stdin; the health run the sidecar's `skep health` on
/// the bridge; the reload the notes' §4a line; the volume's creation with
/// this service's label before the name, and the listing by that label;
/// and a failed run's last twenty lines, read before the run is removed.
#[test]
fn every_calls_argv_is_the_documents_run_line() {
    let s = settings();
    let (n, r) = (alice(), record());
    let pinned: [(Call<'_>, &str); 12] = [
        (Call::VolumeCreate(&n), "volume create --label skep.provision=1 alice"),
        (Call::VolumeInspect(&n), "volume inspect alice"),
        (Call::ContainerInspect(&n), "container inspect alice"),
        (
            Call::RunClaim(&n),
            "run -d --init --name alice --read-only --cap-drop ALL --security-opt no-new-privileges --ulimit nofile=1024:1024 \
             -e SKEPD_BIND=127.0.0.1 -e SKEPD_ORIGIN=https://alice.skep.host -v alice:/var/lib/skepd skep-hosted",
        ),
        (Call::SidecarClaim(&n, &r), "run --rm -i --network container:alice skep-cli skep claim --board http://127.0.0.1:8642 --hosted -"),
        (Call::RunLogs(&n), "logs --tail 20 alice"),
        (Call::RmForce(&n), "rm -f alice"),
        (
            Call::RunServing(&n),
            "run -d --init --name alice --read-only --cap-drop ALL --security-opt no-new-privileges --ulimit nofile=1024:1024 \
             --restart on-failure --log-opt max-size=10m --log-opt max-file=5 --network skep -v alice:/var/lib/skepd \
             -e SKEPD_ORIGIN=https://alice.skep.host --label host=alice.skep.host skep-hosted",
        ),
        (Call::VolumeRm(&n), "volume rm alice"),
        (Call::Health(&n), "run --rm --network skep skep-cli skep health --board http://alice:8642"),
        (Call::CaddyReload, "exec caddy caddy reload --config /etc/caddy/Caddyfile"),
        (Call::LabelledVolumes, "volume ls -q --filter label=skep.provision=1"),
    ];
    for (call, line) in pinned {
        assert_eq!(call.argv(&s), words(line), "{call:?}");
    }
}

/// T19: THE LABEL — `volume create` carries `--label skep.provision=1`
/// BEFORE the name and the name last; `labelled_volumes` is
/// `volume ls -q --filter label=skep.provision=1`, token by token, the same
/// label; the two constants spell it; neither takes a setting. The claim
/// run and the sidecar stay the smoke's lines (the two drift tests above),
/// and the smoke's own `docker volume create "$VOLUME"` carries no label —
/// those tests read the claim run and the sidecar, never the volume line.
#[test]
fn the_volume_is_labelled_before_its_name_and_the_listing_filters_by_the_label() {
    let n = alice();
    let create = Call::VolumeCreate(&n).argv(&settings());
    assert_eq!(create, words("volume create --label skep.provision=1 alice"));
    assert_eq!(&create[2..4], ["--label", "skep.provision=1"], "the label before the name");
    assert_eq!(create.last().map(String::as_str), Some("alice"), "the name last");
    assert_eq!((LABEL_KEY, LABEL_VALUE), ("skep.provision", "1"));
    assert_eq!(label(), "skep.provision=1");
    let listing = Call::LabelledVolumes.argv(&settings());
    assert_eq!(listing, words("volume ls -q --filter label=skep.provision=1"));
    assert_eq!(listing.last().map(String::as_str), Some(&*format!("label={}", label())));
    let other = Settings {
        image: "img:2".into(),
        cli_image: "cli:2".into(),
        network: "net2".into(),
        caddy: "proxy2".into(),
        suffix: domain("example.org"),
        log_max_size: "50m".into(),
        log_max_file: files(3),
    };
    assert_eq!(Call::LabelledVolumes.argv(&other), listing, "no setting reaches the listing");
    assert_eq!(Call::VolumeCreate(&n).argv(&other), create, "no setting reaches the volume's creation");
    // The fake answers a scripted `labelled_volumes` line — its stdout the
    // names, one per line — and refuses an unscripted one.
    let fake = FakeDocker::parse(&line("labelled_volumes", None, 0, "alice\nbob\n", "")).expect("a script");
    let exit = fake.labelled_volumes().expect("an answer");
    assert_eq!((exit.code, exit.stdout.as_slice()), (Some(0), &b"alice\nbob\n"[..]));
    let refused = fake.labelled_volumes().expect("an answer");
    assert_eq!(refused.code, Some(UNEXPECTED));
    assert!(String::from_utf8_lossy(&refused.stderr).contains("unexpected call labelled_volumes -; the script expected nothing more under -"));
    assert_eq!(fake.said(), vec!["labelled_volumes", "labelled_volumes"]);
    assert_eq!(fake.unexpected().len(), 1);
}

/// The settings reach the words they name and no other: another tag, bridge,
/// proxy, suffix and rotation each move their own tokens.
#[test]
fn the_settings_reach_their_own_words() {
    let s = Settings {
        image: "img:2".into(),
        cli_image: "cli:2".into(),
        network: "net2".into(),
        caddy: "proxy2".into(),
        suffix: domain("example.org"),
        log_max_size: "50m".into(),
        log_max_file: files(3),
    };
    let (n, r) = (Name::parse(b"bob").expect("a name"), record());
    let serving = Call::RunServing(&n).argv(&s);
    for word in ["max-size=50m", "max-file=3", "net2", "SKEPD_ORIGIN=https://bob.example.org", "host=bob.example.org", "img:2", "bob:/var/lib/skepd"] {
        assert!(serving.contains(&word.to_owned()), "{word}: {serving:?}");
    }
    assert_eq!(Call::Health(&n).argv(&s), words("run --rm --network net2 cli:2 skep health --board http://bob:8642"));
    assert_eq!(Call::CaddyReload.argv(&s), words("exec proxy2 caddy reload --config /etc/caddy/Caddyfile"));
    assert_eq!(Call::SidecarClaim(&n, &r).argv(&s)[5], "cli:2");
}

/// The smoke script's own line: from the line that begins `docker run` and
/// holds `marker` through its `\` continuations, cut at its first
/// redirect, its quotes dropped.
fn smoke_line(marker: &str) -> Vec<String> {
    let script = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/docker-smoke.sh")).expect("the smoke script");
    let lines: Vec<&str> = script.lines().collect();
    let start = lines
        .iter()
        .position(|l| l.trim_start().starts_with("docker run") && l.contains(marker) && !l.contains("--entrypoint"))
        .or_else(|| lines.iter().position(|l| l.trim_start().starts_with("if docker run") && l.contains(marker)))
        .unwrap_or_else(|| panic!("the smoke script has no `docker run` holding {marker}"));
    let mut joined = String::new();
    for l in &lines[start..] {
        let l = l.trim();
        match l.strip_suffix('\\') {
            Some(cont) => joined.push_str(cont),
            None => {
                joined.push_str(l);
                break;
            }
        }
        joined.push(' ');
    }
    let cut = joined.find(['>', ';']).unwrap_or(joined.len());
    joined[..cut].replace('"', "").split_whitespace().skip_while(|w| *w != "docker").skip(1).map(str::to_owned).collect()
}

/// T4: THE CLAIM RUN IS THE SMOKE's, WORD FOR WORD — read back from
/// `scripts/docker-smoke.sh` at test time, its names this call's and its
/// local origin the public one, so either side's drift is a red test.
#[test]
fn the_claim_run_is_the_smoke_scripts_line_word_for_word() {
    let smoke: Vec<String> = smoke_line("--name \"$CLAIM\"")
        .into_iter()
        .map(|w| match w.as_str() {
            "$CLAIM" => "alice".to_owned(),
            "$IMAGE" => "skep-hosted".to_owned(),
            "$VOLUME:/var/lib/skepd" => "alice:/var/lib/skepd".to_owned(),
            w if w.starts_with("SKEPD_ORIGIN=") => "SKEPD_ORIGIN=https://alice.skep.host".to_owned(),
            w => w.to_owned(),
        })
        .collect();
    assert_eq!(Call::RunClaim(&alice()).argv(&settings()), smoke);
}

/// T4: THE SIDECAR's RUN IS THE SMOKE's with the record on stdin: the
/// smoke's words, its `-v <file>:/payload:ro` mount gone, `-i` after
/// `--rm`, and `--hosted -` for `--hosted /payload`.
#[test]
fn the_sidecars_run_is_the_smoke_scripts_with_the_record_on_stdin() {
    let mut smoke: Vec<String> = smoke_line("--network \"container:$CLAIM\"")
        .into_iter()
        .map(|w| match w.as_str() {
            "container:$CLAIM" => "container:alice".to_owned(),
            "$CLI_IMAGE" => "skep-cli".to_owned(),
            "/payload" => "-".to_owned(),
            w => w.to_owned(),
        })
        .collect();
    let mount = smoke.iter().position(|w| w == "-v").expect("the smoke mounts the payload");
    smoke.drain(mount..mount + 2);
    smoke.insert(2, "-i".to_owned());
    assert_eq!(Call::SidecarClaim(&alice(), &record()).argv(&settings()), smoke);
}

/// T4: THE SERVING RUN carries every flag of the README's serving line
/// (`README.md`, Running the hosted image), with the public origin and the
/// notes' bridge and label beside them.
#[test]
fn the_serving_run_carries_the_readmes_serving_flags() {
    let readme = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../README.md")).expect("the README");
    let start = readme.find("docker run -d --init --name alice --restart on-failure").expect("the README's serving line");
    let block = &readme[start..start + readme[start..].find("```").expect("its block's end")];
    let serving = Call::RunServing(&alice()).argv(&settings());
    let readme_words: Vec<String> = block.replace('\\', " ").split_whitespace().skip(2).map(str::to_owned).collect();
    for pair in readme_words.windows(2) {
        let (flag, value) = (&pair[0], &pair[1]);
        if !flag.starts_with('-') || value.starts_with('-') {
            continue;
        }
        let value = if flag == "-e" { "SKEPD_ORIGIN=https://alice.skep.host".to_owned() } else { value.clone() };
        assert!(serving.windows(2).any(|w| w[0] == *flag && w[1] == value), "the README's `{flag} {value}` is not in {serving:?}");
    }
    for switch in ["-d", "--init", "--read-only"] {
        assert!(serving.contains(&switch.to_owned()), "{switch}");
    }
}

/// THE RUNBOOK's REMAKE LINE IS THE SERVING RUN's, word for word: RUNBOOK
/// §10 step 13's `docker run`, by which an operator makes a standing
/// board's serving run again after an upgrade, read back at test time, its
/// `<name>` this call's and its values the defaults — the line an operator
/// remakes a board by is the one the service made it with.
#[test]
fn the_runbooks_remake_line_is_the_serving_runs() {
    let runbook = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../RUNBOOK.md")).expect("the RUNBOOK");
    let line = runbook.lines().map(str::trim).find(|l| l.starts_with("docker run -d --init --name <name>")).expect("the RUNBOOK's remake line");
    let words: Vec<String> = line.replace("<name>", "alice").split_whitespace().skip(1).map(str::to_owned).collect();
    assert_eq!(Call::RunServing(&alice()).argv(&settings()), words);
}

/// THE IMAGE's BAKED FACTS ARE THE DOCKERFILE's: the port its daemon
/// listens on — the claim run's, which the sidecar dials, and the serving
/// run's on the bridge — and the volume a board's data lives on, read back
/// from the `Dockerfile` at test time, so a change there is a red test here
/// until the constants follow it.
#[test]
fn the_images_port_and_volume_are_the_dockerfiles() {
    let dockerfile = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../Dockerfile")).expect("the Dockerfile");
    let words: Vec<&str> = dockerfile.split_whitespace().collect();
    assert!(words.contains(&format!("SKEPD_PORT={BOARD_PORT}").as_str()), "the Dockerfile bakes another port than {BOARD_PORT}");
    assert!(words.windows(2).any(|w| w == ["VOLUME", VOLUME_MOUNT]), "the Dockerfile's volume is not {VOLUME_MOUNT}");
}

/// T4: THE REAL COMMAND is `docker` and the argv, nothing else: no variable
/// set, no directory changed.
#[test]
fn the_real_command_is_built_from_the_argv_and_nothing_else() {
    let argv = Call::SidecarClaim(&alice(), &record()).argv(&settings());
    let cmd = command(Path::new(DOCKER), &argv);
    assert_eq!(cmd.get_program(), "docker");
    assert_eq!(cmd.get_args().map(|a| a.to_str().expect("text").to_owned()).collect::<Vec<_>>(), argv);
    assert_eq!(cmd.get_envs().count(), 0);
    assert_eq!(cmd.get_current_dir(), None);
}

/// T4: THE REAL RUNNER over a recording script in `docker`'s place: the
/// argv arrives as built, the record arrives on the sidecar's stdin and
/// nothing on any other call's, whose stdin ends at once — that it is never
/// the service's own is the built binary's suite's to show, where the test
/// holds the service's stdin — and stdout, stderr and the exit code come
/// back apart.
#[cfg(unix)]
#[test]
fn the_real_runner_passes_the_argv_the_record_alone_and_its_streams_apart() {
    use std::os::unix::fs::PermissionsExt;
    let dir = Scratch::new();
    let script = dir.path().join("docker");
    std::fs::write(&script, format!("#!/bin/sh\nprintf '%s\\n' \"$@\" > '{0}/argv'\ncat > '{0}/stdin'\nprintf 'out:%s' \"$1\"\nprintf 'err:%s' \"$1\" >&2\nexit 7\n", dir.path().display()))
        .expect("the script");
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).expect("executable");
    let host = HostDocker::with_program(script, settings());
    let record = record();
    let exit = host.sidecar_claim(&alice(), &record).expect("the script ran");
    assert_eq!(exit, Exit { code: Some(7), stdout: b"out:run".to_vec(), stderr: b"err:run".to_vec() });
    let argv = std::fs::read_to_string(dir.path().join("argv")).expect("the argv");
    assert_eq!(argv.lines().map(str::to_owned).collect::<Vec<_>>(), Call::SidecarClaim(&alice(), &record).argv(&settings()));
    assert_eq!(std::fs::read(dir.path().join("stdin")).expect("the stdin"), record.bytes());
    let exit = host.volume_inspect(&alice()).expect("the script ran");
    assert_eq!(exit.stdout, b"out:volume");
    assert_eq!(std::fs::read(dir.path().join("stdin")).expect("the stdin"), b"", "a call with no input reads nothing");
}

/// THE ONE MAPPING: each named method hands [`Docker::run`] the call its
/// name says — the mapping the host runs and the fake answers alike,
/// written once, in the trait — and the dark claim's call alone carries an
/// input, the record's bytes, which its `Debug` never shows.
#[test]
fn each_named_method_runs_its_own_call() {
    /// A runner that keeps every call it is handed, as its `Debug` spells it.
    #[derive(Default)]
    struct Kept(std::sync::Mutex<Vec<String>>);
    impl Docker for Kept {
        fn run(&self, call: Call<'_>) -> io::Result<Exit> {
            self.0.lock().unwrap_or_else(|e| e.into_inner()).push(format!("{call:?}"));
            Ok(Exit { code: Some(0), stdout: Vec::new(), stderr: Vec::new() })
        }
    }
    let (n, r, kept) = (alice(), record(), Kept::default());
    for answered in [
        kept.volume_create(&n),
        kept.volume_inspect(&n),
        kept.container_inspect(&n),
        kept.run_claim(&n),
        kept.sidecar_claim(&n, &r),
        kept.run_logs(&n),
        kept.rm_force(&n),
        kept.run_serving(&n),
        kept.volume_rm(&n),
        kept.health(&n),
        kept.caddy_reload(),
        kept.labelled_volumes(),
    ] {
        answered.expect("the runner answered");
    }
    let calls = [
        Call::VolumeCreate(&n),
        Call::VolumeInspect(&n),
        Call::ContainerInspect(&n),
        Call::RunClaim(&n),
        Call::SidecarClaim(&n, &r),
        Call::RunLogs(&n),
        Call::RmForce(&n),
        Call::RunServing(&n),
        Call::VolumeRm(&n),
        Call::Health(&n),
        Call::CaddyReload,
        Call::LabelledVolumes,
    ];
    assert_eq!(*kept.0.lock().unwrap_or_else(|e| e.into_inner()), calls.iter().map(|c| format!("{c:?}")).collect::<Vec<_>>());
    for call in calls {
        let want = matches!(call, Call::SidecarClaim(..)).then(|| r.bytes());
        assert_eq!(call.input(), want, "{call:?}");
    }
    let shown = format!("{:?}", Call::SidecarClaim(&n, &r));
    assert!(!shown.contains("9f9f") && shown.contains(&format!("bytes: {}", r.bytes().len())), "{shown}");
}

/// T4: THE FAKE answers its script in order and REFUSES a call it did not
/// expect — another method or another name — with exit 125, recorded, the
/// script left where it was; `assert_done` then fails the test, as it does
/// on a line never called.
#[test]
fn the_fake_refuses_a_call_it_was_not_scripted() {
    let fake = FakeDocker::parse(&format!("{}{}", line("volume_inspect", Some("alice"), 1, "", ""), line("caddy_reload", None, 0, "reloaded\n", "")));
    let fake = fake.expect("a script");
    let unexpected = fake.container_inspect(&alice()).expect("an answer");
    assert_eq!(unexpected.code, Some(UNEXPECTED));
    assert!(String::from_utf8_lossy(&unexpected.stderr).contains("unexpected call container_inspect alice; the script expected volume_inspect alice"));
    assert_eq!(fake.volume_inspect(&alice()).expect("an answer").code, Some(1), "the script was left where it was");
    assert_eq!(fake.volume_inspect(&Name::parse(b"bob").expect("a name")).expect("an answer").code, Some(UNEXPECTED), "another name is another call");
    assert_eq!(fake.caddy_reload().expect("an answer").stdout, b"reloaded\n");
    assert_eq!(fake.said(), vec!["container_inspect alice", "volume_inspect alice", "volume_inspect bob", "caddy_reload"]);
    assert_eq!(fake.unexpected().len(), 2);
    assert!(std::panic::catch_unwind(|| fake.assert_done()).is_err(), "an unexpected call fails the test");
    let left = FakeDocker::parse(&line("rm_force", Some("alice"), 0, "", "")).expect("a script");
    assert!(std::panic::catch_unwind(|| left.assert_done()).is_err(), "a line never called fails the test");
}

/// The script's form: TAB-separated fields, the escapes undone, `-` for no
/// name, a comment and a blank line skipped, a bad line refused naming it.
#[test]
fn the_script_reads_its_escapes_and_refuses_a_bad_line() {
    let text = format!("# a comment\n\n{}", line("sidecar_claim", Some("alice"), 0, "claimant 1.0.1\nback\\slash\ttab", "talk\n"));
    let fake = FakeDocker::parse(&text).expect("a script");
    let record = record();
    let exit = fake.sidecar_claim(&alice(), &record).expect("an answer");
    assert_eq!(exit.stdout, b"claimant 1.0.1\nback\\slash\ttab");
    assert_eq!(exit.stderr, b"talk\n");
    assert_eq!(fake.calls()[0].input.as_deref(), Some(record.bytes()));
    fake.assert_done();
    assert!(FakeDocker::parse("volume_inspect\talice\n").expect_err("two fields").contains("line 1"));
    assert!(FakeDocker::parse("volume_inspect\talice\tx\n").expect_err("no code").contains("no exit code"));
}

/// The fake opened from a file records each call as a line in
/// `<script>.calls`, an unexpected one marked.
#[test]
fn the_fake_from_a_file_records_each_call_beside_it() {
    let dir = Scratch::new();
    let script = dir.path().join("docker.script");
    std::fs::write(&script, line("sidecar_claim", Some("alice"), 0, "", "")).expect("the script");
    let fake = FakeDocker::open(&script).expect("the fake");
    let record = record();
    fake.sidecar_claim(&alice(), &record).expect("an answer");
    fake.caddy_reload().expect("an answer");
    let calls = std::fs::read_to_string(super::fake::calls_path(&script)).expect("the calls");
    assert_eq!(calls, format!("sidecar_claim\talice\t0\tstdin={}\ncaddy_reload\t-\t125\tunexpected\n", record.bytes().len()));
}
