use super::*;

fn argv(args: &[&str]) -> impl Iterator<Item = String> {
    args.iter().map(|s| s.to_string()).collect::<Vec<_>>().into_iter()
}

/// Asking for the usage text is an outcome the caller receives, not an
/// exit taken inside the parser — which is what makes every other case
/// here testable at all.
#[test]
fn help_is_an_answer_not_an_exit() {
    for flag in ["--help", "-h"] {
        let parsed = parse_args(argv(&[flag])).expect("--help is not an error");
        assert!(parsed.is_none(), "{flag} asks for usage, not a run");
        assert!(parse_command(argv(&["inventory", flag])).expect("usage").is_none());
        assert!(parse_command(argv(&["pull", flag])).expect("usage").is_none());
    }
}

/// THE UPLOAD SETTING (wire.md §Media): OPEN unless `--no-uploads` is
/// given, `--uploads` the affirmative default, and the usage text names
/// both with the variable.
#[test]
fn the_upload_setting_is_open_unless_closed() {
    let absent = parse_args(argv(&["--data-dir", "/tmp/x"])).expect("valid").expect("a run");
    assert!(absent.uploads, "open by default");
    let closed = parse_args(argv(&["--data-dir", "/tmp/x", "--no-uploads"])).expect("valid").expect("a run");
    assert!(!closed.uploads);
    let open = parse_args(argv(&["--data-dir", "/tmp/x", "--no-uploads", "--uploads"])).expect("valid").expect("a run");
    assert!(open.uploads, "the last flag wins, as --local-trust's pair does");
    let text = usage();
    for named in ["--no-uploads", "SKEPD_UPLOADS", "skepd inventory", "skepd pull", "--no-rehash", "--hash"] {
        assert!(text.contains(named), "the usage names {named}");
    }
}

/// THE DATA DIRECTORY's SENTENCE (the register's F14): the help names
/// what the daemon writes under `--data-dir` — not the journal and its
/// checkpoints alone, but the blob store and the change feed's files
/// beside them, the attest store by name — so an operator sizing or
/// backing up the directory is not undersold.
#[test]
fn the_usage_names_what_the_data_directory_holds() {
    let text = usage();
    let sentence = text
        .split("\n  --data-dir <DIR>")
        .nth(1)
        .and_then(|rest| rest.split("\n  --port <PORT>").next())
        .expect("the --data-dir sentence");
    for named in ["journal", "checkpoints", "blobs/", "commits.log", "feed-*.log", "feed-attest.log", "SKEPD_DATA_DIR"] {
        assert!(sentence.contains(named), "the --data-dir sentence names {named}: {sentence:?}");
    }
}

/// THE LOOSE DIRECTORY's LINE at fixed inputs: the directory as named,
/// the mode in octal — a setgid directory's shown whole — and the act
/// named once; and the usage's `--data-dir` sentence names how the
/// directory is created (the modes, the umask) and the refusal's act.
#[test]
fn the_loose_directorys_line_names_the_directory_the_mode_and_the_one_act() {
    assert_eq!(
        LooseDataDir { path: Path::new("/srv/board"), mode: 0o755 }.to_string(),
        "the data directory /srv/board is mode 755: other users of this machine can read the \
         board; chmod 700 /srv/board and start again"
    );
    assert_eq!(
        LooseDataDir { path: Path::new("board"), mode: 0o2750 }.to_string(),
        "the data directory board is mode 2750: other users of this machine can read the \
         board; chmod 700 board and start again"
    );
    let text = usage();
    let sentence = text
        .split("\n  --data-dir <DIR>")
        .nth(1)
        .and_then(|rest| rest.split("\n  --port <PORT>").next())
        .expect("the --data-dir sentence");
    for named in ["0700", "0600", "umask", "chmod 700"] {
        assert!(sentence.contains(named), "the --data-dir sentence names {named}: {sentence:?}");
    }
}

/// WHAT THE CHECK FINDS (unix): a directory with any group or other bit
/// set is loose, at its mode; one at `0700` is not; a path that does
/// not exist, and a file, are never refused here — the first is the
/// kernel's to create, the second the open's to refuse by name.
#[cfg(unix)]
#[test]
fn a_loose_directory_is_found_and_a_tight_an_absent_or_a_file_is_not() {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path().join("board");
    std::fs::DirBuilder::new().mode(0o755).create(&dir).expect("a loose directory");
    let found = loose_data_dir(&dir).expect("found loose");
    assert_eq!((found.path, found.mode), (dir.as_path(), 0o755));
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o750)).expect("chmod");
    assert_eq!(loose_data_dir(&dir).map(|l| l.mode), Some(0o750), "a group bit alone is loose");
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).expect("chmod");
    assert!(loose_data_dir(&dir).is_none(), "owner-only is admitted");
    assert!(loose_data_dir(&tmp.path().join("absent")).is_none(), "an absent directory is the kernel's to create");
    let file = tmp.path().join("a-file");
    std::fs::write(&file, b"not a board").expect("a file");
    assert!(loose_data_dir(&file).is_none(), "a file is the open's to refuse by name");
}

/// THE HOOK's LINE (row 41) at fixed inputs: the thread's name, the
/// location as std spells it, and the payload only where the hook found
/// a `&'static str` — a formatted panic shows its location alone; an
/// unnamed thread and a missing location are said as such, never as a
/// hole in the line.
#[test]
fn the_hooks_line_names_the_thread_the_location_and_a_literal_payload_alone() {
    let here = Location::caller();
    assert_eq!(
        panic_line(Some("skepd-worker"), Some(here), Some("the test seam's worker fault")),
        format!("skepd-worker: a thread panicked at {here}: the test seam's worker fault")
    );
    assert_eq!(
        panic_line(Some("skepd-pruner"), Some(here), None),
        format!("skepd-pruner: a thread panicked at {here}"),
        "a formatted payload — a String — is not carried: the location identifies the site"
    );
    assert_eq!(
        panic_line(None, None, Some("boom")),
        "an unnamed thread: a thread panicked at an unknown location: boom"
    );
    assert!(
        here.to_string().ends_with(&format!(":{}:{}", here.line(), here.column())),
        "the location is std's own spelling, file:line:column: {here}"
    );
}

/// THE EXIT's LINE (m16): the words the binary says when `wait` returns,
/// before exit 1 — the state and what it means for the board.
#[test]
fn the_exits_line_says_every_worker_has_ended_and_the_board_serves_nothing() {
    assert_eq!(WORKERS_ENDED, "every worker thread has ended; the board serves nothing");
}

/// THE TOOLS' LINES: a leading verb names the tool before any flag; the
/// inventory takes its directory and `--no-rehash`, the pull its
/// directory, an optional `--hash` and one file; a missing directory or
/// file, an unknown flag and a daemon flag under a tool are refused by
/// name; and a line with no verb is the daemon's own.
#[test]
fn the_tools_parse_a_leading_verb_before_their_flags() {
    match parse_command(argv(&["inventory", "--data-dir", "/tmp/b"])).expect("valid").expect("a tool") {
        Command::Inventory { data_dir, check } => {
            assert_eq!(data_dir, PathBuf::from("/tmp/b"));
            assert_eq!(check, tools::HoleCheck::Rehash, "re-hashed by default");
        }
        _ => panic!("the inventory"),
    }
    match parse_command(argv(&["inventory", "--no-rehash", "--data-dir", "/tmp/b"])).expect("valid").expect("a tool") {
        Command::Inventory { check, .. } => assert_eq!(check, tools::HoleCheck::LengthOnly),
        _ => panic!("the inventory"),
    }
    match parse_command(argv(&["pull", "--data-dir", "/tmp/b", "/tmp/picture"])).expect("valid").expect("a tool") {
        Command::Pull { data_dir, hash, file } => {
            assert_eq!((data_dir, hash, file), (PathBuf::from("/tmp/b"), None, PathBuf::from("/tmp/picture")));
        }
        _ => panic!("the pull"),
    }
    let hex = "ab".repeat(32);
    match parse_command(argv(&["pull", "--hash", &hex, "/tmp/picture", "--data-dir", "/tmp/b"])).expect("valid").expect("a tool") {
        Command::Pull { hash, file, .. } => {
            assert_eq!((hash, file), (Some(hex.clone()), PathBuf::from("/tmp/picture")));
        }
        _ => panic!("the pull"),
    }
    for bad in [
        &["inventory"][..],
        &["pull", "--data-dir", "/tmp/b"],
        &["pull", "--data-dir", "/tmp/b", "a", "b"],
        &["inventory", "--data-dir", "/tmp/b", "--hash", "x"],
        &["pull", "--data-dir", "/tmp/b", "--no-rehash", "f"],
        &["inventory", "--data-dir", "/tmp/b", "--port", "1"],
        &["inventory", "--data-dir"],
    ] {
        assert!(parse_command(argv(bad)).is_err(), "{bad:?} is refused");
    }
    assert!(matches!(
        parse_command(argv(&["--data-dir", "/tmp/x"])).expect("valid"),
        Some(Command::Serve(_))
    ));
}

/// Flags are read as given; a missing data dir and an unknown argument
/// are named refusals.
#[test]
fn flags_parse_and_refusals_are_named() {
    let a = parse_args(argv(&["--data-dir", "/tmp/skepd-test", "--port", "0"]))
        .expect("valid flags")
        .expect("a run, not usage");
    assert_eq!(a.data_dir, PathBuf::from("/tmp/skepd-test"));
    assert_eq!(a.port, 0);
    let a = parse_args(argv(&["--data-dir", "/tmp/x", "--blocked-prefixes", "/etc/skepd/blocked.json"]))
        .expect("valid flags")
        .expect("a run, not usage");
    assert_eq!(
        a.blocked_prefixes,
        Some(PathBuf::from("/etc/skepd/blocked.json")),
        "the list's supply is a path, carried as given — reading it is the open's"
    );
    assert!(
        parse_args(argv(&["--data-dir", "/tmp/x", "--blocked-prefixes"])).is_err(),
        "the flag without its file is refused"
    );
    assert!(parse_args(argv(&["--frobnicate"])).is_err(), "an unknown argument is refused");
    assert!(parse_args(argv(&["--port"])).is_err(), "a flag without its value is refused");
    assert!(
        parse_args(argv(&["--data-dir", "/tmp/x", "--port", "notaport"])).is_err(),
        "a non-numeric port is refused"
    );
    assert!(
        parse_args(argv(&["--data-dir", "/tmp/x", "--workers", "0"])).is_err(),
        "a zero worker count is refused, not repaired into a serving count"
    );
    let in_range = MIN_WORKERS + 1;
    assert_eq!(
        parse_args(argv(&["--data-dir", "/tmp/x", "--workers", &in_range.to_string()]))
            .expect("a count above the minimum is in range")
            .expect("a run, not usage")
            .workers,
        in_range,
        "and a count in range is read as given"
    );
}

/// THE `--workers` FLOOR (`operations.md` §2.3 F1; op-D7 (a)): a count below
/// `MIN_WORKERS` — zero, one, and one short of it — is REFUSED at the parse
/// with the relation stated, in the ruling's words: the count, the minimum
/// rendered from the constant, what the minimum is (one more than the permit
/// pools' slots together) and what a count below it costs (a caller holding
/// every permit leaves no worker for `/health`, `/session` or a write); the
/// minimum itself, one above it and the default are read as given; and the
/// usage text renders the minimum and the default from the constants, the
/// old literal gone. Every figure here is the constant, never a literal, so
/// a pool that moves keeps the claim true.
#[test]
fn the_worker_count_is_refused_below_the_minimum_stating_the_relation() {
    let relation = |n: usize| {
        format!(
            "--workers: {n} is below the minimum {MIN_WORKERS} — one more than the permit pools' \
             slots together; below it a caller holding every permit leaves no worker for \
             /health, /session or a write"
        )
    };
    for below in [0, 1, MIN_WORKERS - 1] {
        let Err(refused) =
            parse_args(argv(&["--data-dir", "/tmp/x", "--workers", &below.to_string()]))
        else {
            panic!("--workers {below} is below the minimum and was not refused");
        };
        assert_eq!(refused, relation(below), "the relation, in the ruling's words");
        assert!(refused.contains(&format!("below the minimum {MIN_WORKERS}")), "{refused}");
        assert!(refused.contains("one more than the permit pools' slots together"), "{refused}");
    }
    for admitted in [MIN_WORKERS, MIN_WORKERS + 1, DEFAULT_WORKERS] {
        let a = parse_args(argv(&["--data-dir", "/tmp/x", "--workers", &admitted.to_string()]))
            .expect("a count at or above the minimum is in range")
            .expect("a run, not usage");
        assert_eq!(a.workers, admitted, "read as given");
    }
    let absent = parse_args(argv(&["--data-dir", "/tmp/x"])).expect("valid").expect("a run");
    assert_eq!(absent.workers, DEFAULT_WORKERS, "the default satisfies the floor");
    let text = usage();
    assert!(text.contains(&format!("minimum {MIN_WORKERS})")), "the help renders the minimum: {text}");
    assert!(text.contains(&format!("default {DEFAULT_WORKERS};")), "the help renders the default: {text}");
    assert!(!text.contains("minimum 1)"), "the old literal is gone: {text}");
}

/// THE VARIABLE MEETS THE SAME FLOOR: `SKEPD_WORKERS` set below `MIN_WORKERS`
/// with no `--workers` on the line is refused by the same arm with the same
/// relation — the variable seeds the count the flag overrides, and the one
/// check reads the count whichever set it — and an in-range flag beside the
/// variable wins, as every flag does over its variable. Judged in a CHILD of
/// this test binary (the hazard suite's self-exec pattern), because the
/// variable is process-wide and this binary's other parse claims run beside
/// this one.
#[test]
fn the_variable_meets_the_same_floor_as_the_flag() {
    const CHILD: &str = "SKEPD_TEST_WORKERS_CHILD";
    if std::env::var_os(CHILD).is_some() {
        // THE CHILD: the parent set `SKEPD_WORKERS` one short of the minimum.
        let Err(refused) = parse_args(argv(&["--data-dir", "/tmp/x"])) else {
            panic!("the variable's count below the minimum was not refused");
        };
        assert!(refused.starts_with("--workers: "), "the same arm: {refused}");
        assert!(refused.contains(&format!("below the minimum {MIN_WORKERS}")), "{refused}");
        assert!(refused.contains("one more than the permit pools' slots together"), "{refused}");
        let a = parse_args(argv(&["--data-dir", "/tmp/x", "--workers", &MIN_WORKERS.to_string()]))
            .expect("the flag wins over the variable")
            .expect("a run, not usage");
        assert_eq!(a.workers, MIN_WORKERS);
        return;
    }
    let exe = std::env::current_exe().expect("the test binary");
    let out = std::process::Command::new(exe)
        .args([
            "tests::the_variable_meets_the_same_floor_as_the_flag",
            "--exact",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD, "1")
        .env(SKEPD_WORKERS.var, (MIN_WORKERS - 1).to_string())
        .output()
        .expect("run the child");
    assert!(
        out.status.success(),
        "the child's claims failed:\n{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

/// AUTH-1.44's `--allow-preview-keys`: a bare flag, OFF unless given, and
/// seeded by no environment variable — a served board's image cannot
/// turn it on in silence.
#[test]
fn the_preview_keys_flag_is_off_unless_given() {
    let absent = parse_args(argv(&["--data-dir", "/tmp/x"]))
        .expect("valid flags")
        .expect("a run, not usage");
    assert!(!absent.allow_preview_keys, "the default is OFF");
    let given = parse_args(argv(&["--data-dir", "/tmp/x", "--allow-preview-keys"]))
        .expect("valid flags")
        .expect("a run, not usage");
    assert!(given.allow_preview_keys, "the flag turns it on");
    assert!(
        parse_args(argv(&["--data-dir", "/tmp/x", "--allow-preview-keys", "true"])).is_err(),
        "the flag takes no value: a trailing word is an unknown argument"
    );
}

/// REG-1.69's `--node-prefix 1.N`: an address under the root `1`, read
/// as given and optional; the root itself, an address under another
/// first component, and an account address are refused at the parse
/// with the form named — never repaired, never read as absent.
#[test]
fn the_node_prefix_flag_takes_a_node_address_under_the_root_and_nothing_else() {
    let a = parse_args(argv(&["--data-dir", "/tmp/x", "--node-prefix", "1.3"]))
        .expect("valid flags")
        .expect("a run, not usage");
    assert_eq!(
        a.node_prefix.as_ref().map(|p| p.to_string()),
        Some("1.3".to_string()),
        "the board's node prefix, as given"
    );
    let absent = parse_args(argv(&["--data-dir", "/tmp/x"]))
        .expect("valid flags")
        .expect("a run, not usage");
    assert!(absent.node_prefix.is_none(), "the flag is optional: a notebook has none");
    for bad in ["1", "2.4", "1.3.0.7", "1.0", "x", ""] {
        match parse_args(argv(&["--data-dir", "/tmp/x", "--node-prefix", bad])) {
            Err(refused) => assert!(
                refused.starts_with(&format!("--node-prefix: '{bad}' is not a node prefix")),
                "the refusal names the flag, the value and the form: {refused}"
            ),
            Ok(_) => panic!("'{bad}' is not a node prefix, and was not refused"),
        }
    }
    assert!(
        parse_args(argv(&["--data-dir", "/tmp/x", "--node-prefix"])).is_err(),
        "the flag without its value is refused"
    );
}
