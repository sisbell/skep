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

/// THE VERSION LINE IS AN ANSWER, NOT AN EXIT, as the usage text is: a
/// leading `--version` parses to `Command::Version`, which `main` prints,
/// with what follows it unread as what follows `--help` is; among the
/// daemon's flags it is refused naming the form, never called unknown; the
/// line is `skepd <crate version> (<commit>)`, the version
/// `CARGO_PKG_VERSION`'s and the commit `SKEP_GIT_SHA`'s at build time —
/// `unknown` where the build set none, which this suite's build never does;
/// and the usage names the flag.
#[test]
fn version_is_an_answer_not_an_exit() {
    let asked = parse_command(argv(&["--version"])).expect("--version is not an error");
    assert!(
        matches!(asked, Some(Command::Version)),
        "--version asks for the version line, not a run"
    );
    let asked = parse_command(argv(&["--version", "--port", "x"])).expect("what follows is unread");
    assert!(matches!(asked, Some(Command::Version)));
    match parse_args(argv(&["--data-dir", "/tmp/x", "--version"])) {
        Err(refused) => {
            assert_eq!(refused, "--version is read as the first argument: skepd --version")
        }
        Ok(_) => panic!("--version among the daemon's flags was not refused"),
    }
    assert_eq!(
        version_line(),
        format!(
            "skepd {} ({})",
            env!("CARGO_PKG_VERSION"),
            option_env!("SKEP_GIT_SHA").unwrap_or("unknown")
        )
    );
    assert!(
        usage().contains("\n  --version          this binary's version"),
        "the usage names it: {}",
        usage()
    );
}

/// THE UPLOAD SETTING (wire.md §Media): OPEN unless `--no-uploads` is
/// given, `--uploads` the affirmative default, and the usage text names
/// both with the variable. THE DEFAULT LIMIT's WORDS (`operations.md` §2.3
/// F4; §1.1 row 7): the `--uploads` sentence renders the default from the
/// two constants that supply it — "a per-account limit of one part in
/// {DEFAULT_LIMIT_SHARE} of the volume's capacity, never below
/// {DEFAULT_LIMIT_FLOOR_BYTES} bytes" — read here through the constants and
/// never a literal, so the help describes no default the daemon does not
/// use; no word table ("one eighth", "256 MiB") anywhere in it. And the
/// sentence says that this build installs no limits record, so an operator
/// looking for the setting that moves the limit learns there is none.
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
    // The help wraps its lines: the sentence is read with its whitespace
    // folded, through the constants.
    let folded = text.split_whitespace().collect::<Vec<_>>().join(" ");
    let sentence = format!(
        "a per-account limit of one part in {DEFAULT_LIMIT_SHARE} of the volume's capacity, never \
         below {DEFAULT_LIMIT_FLOOR_BYTES} bytes"
    );
    assert!(folded.contains(&sentence), "the --uploads sentence renders the constants: {folded}");
    assert!(!text.contains("one eighth") && !text.contains("256 MiB"), "no word table: {text}");
    assert!(
        folded.contains(
            "the capacity read once at start; this build installs no limits record, so no setting \
             moves the limit or sets a venue total"
        ),
        "the --uploads sentence says nothing moves the limit: {folded}"
    );
}

/// THE DATA DIRECTORY's SENTENCE (the register's F14): the help names
/// what the daemon writes under `--data-dir` — not the journal and its
/// checkpoints alone, but the blob store and the change feed's files
/// beside them, the attest store by name — so an operator sizing or
/// backing up the directory is not undersold. The four index files are
/// named one by one and never by a glob such as `feed-*.log`, which matches
/// `feed-attest.log` too: removing what that glob names, to force the index
/// files' rebuild, would delete the only copy of each signature the attest
/// store holds below the reclaim floor.
#[test]
fn the_usage_names_what_the_data_directory_holds() {
    let text = usage();
    let sentence = text
        .split("\n  --data-dir <DIR>")
        .nth(1)
        .and_then(|rest| rest.split("\n  --port <PORT>").next())
        .expect("the --data-dir sentence");
    for named in [
        "journal",
        "checkpoints",
        "blobs/",
        "commits.log",
        "feed-index.log",
        "feed-offsets.log",
        "feed-masked.log",
        "feed-streams.log",
        "feed-attest.log",
        "SKEPD_DATA_DIR",
    ] {
        assert!(sentence.contains(named), "the --data-dir sentence names {named}: {sentence:?}");
    }
    assert!(!sentence.contains('*'), "no glob names the index files: {sentence:?}");
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
/// hole in the line; and the panics the hook counted at the site since its
/// last line there, where it counted any, at the line's end.
#[test]
fn the_hooks_line_names_the_thread_the_location_and_a_literal_payload_alone() {
    let here = Location::caller();
    assert_eq!(
        panic_line(Some("skepd-worker"), Some(here), Some("the test seam's worker fault"), 0),
        format!("skepd-worker: a thread panicked at {here}: the test seam's worker fault")
    );
    assert_eq!(
        panic_line(Some("skepd-pruner"), Some(here), None, 0),
        format!("skepd-pruner: a thread panicked at {here}"),
        "a formatted payload — a String — is not carried: the location identifies the site"
    );
    assert_eq!(
        panic_line(None, None, Some("boom"), 0),
        "an unnamed thread: a thread panicked at an unknown location: boom"
    );
    assert_eq!(
        panic_line(Some("skepd-worker"), Some(here), None, 812),
        format!(
            "skepd-worker: a thread panicked at {here}; 812 more at this site on this thread \
             since its last line"
        ),
        "a recurring panic's line counts the ones the hook did not say"
    );
    assert!(
        here.to_string().ends_with(&format!(":{}:{}", here.line(), here.column())),
        "the location is std's own spelling, file:line:column: {here}"
    );
}

/// THE HOOK's RATE (§1 THE RATES): a site's first panic on a thread is said,
/// `Some(0)`; each later one there inside the interval is counted and says
/// nothing; another thread at the same site is a first of its own (m16: one
/// line per worker); the first past the interval is said with the count since
/// the last line, the interval starting again from it; and past
/// `HOOK_MEMORY_KEYS` keys the memory starts afresh, a key it held said
/// again as a first.
#[test]
fn the_hooks_rate_says_a_sites_panic_once_an_interval_per_thread_with_the_repeats_counted() {
    let interval = Duration::from_secs(3600);
    let t0 = Instant::now();
    let secs = |s| t0 + Duration::from_secs(s);
    let here = std::thread::current().id();
    let there = std::thread::spawn(|| std::thread::current().id()).join().expect("a thread");
    let site = || "crates/skep-core/src/auth/entropy.rs:29:31".to_string();
    let mut memory = HookMemory::new();
    assert_eq!(memory.admit((here, site()), t0, interval), Some(0), "the site's first panic");
    for s in 1..=2 {
        assert_eq!(memory.admit((here, site()), secs(s), interval), None, "counted, unsaid");
    }
    assert_eq!(
        memory.admit((there, site()), secs(3), interval),
        Some(0),
        "another thread at the same site is a first of its own"
    );
    assert_eq!(
        memory.admit((here, site()), t0 + interval, interval),
        Some(2),
        "the first past the interval carries the two counted"
    );
    assert_eq!(
        memory.admit((here, site()), t0 + interval + Duration::from_secs(1), interval),
        None,
        "and the interval starts again from that line"
    );
    for n in 0..HOOK_MEMORY_KEYS {
        memory.admit((here, format!("site {n}")), t0 + interval, interval);
    }
    assert_eq!(
        memory.admit((there, site()), t0 + interval, interval),
        Some(0),
        "past the bound the memory starts afresh: a key inside its interval is a first again"
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

/// Checks that `--allow-preview-keys` is off unless given (AUTH-1.44).
///
/// It is a bare flag, seeded by no environment variable, so a served
/// board's image cannot turn it on in silence. Not given, the parse records
/// nothing and the setting is the library's own default, which is off —
/// the default the help names, held to the library's here.
#[test]
fn the_preview_keys_flag_is_off_unless_given() {
    let absent = parse_args(argv(&["--data-dir", "/tmp/x"]))
        .expect("valid flags")
        .expect("a run, not usage");
    assert!(!absent.allow_preview_keys, "the flag was not given");
    assert!(!AuthOptions::default().allow_preview_keys, "the default is the library's: OFF");
    let folded = usage().split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(
        folded.contains("Off — the default — an enrollment record naming one is refused"),
        "the help names the library's default: {folded}"
    );
    let given = parse_args(argv(&["--data-dir", "/tmp/x", "--allow-preview-keys"]))
        .expect("valid flags")
        .expect("a run, not usage");
    assert!(given.allow_preview_keys, "the flag turns it on");
    assert!(
        parse_args(argv(&["--data-dir", "/tmp/x", "--allow-preview-keys", "true"])).is_err(),
        "the flag takes no value: a trailing word is an unknown argument"
    );
}

/// Checks that the local-trust pair's default has one home, the library's.
///
/// Unset by flag and variable, the parse records no value, so the open keeps
/// the library's default and its source; a flag records its value and its
/// arm. The help names the default arm read off the library's default, so a
/// default moved there moves the help with it.
#[test]
fn the_local_trust_default_is_the_librarys_and_the_help_names_its_arm() {
    let absent = parse_args(argv(&["--data-dir", "/tmp/x"])).expect("valid").expect("a run");
    assert_eq!(absent.local_trust, None, "unset: the library's default stands");
    let off = parse_args(argv(&["--data-dir", "/tmp/x", "--no-local-trust"]))
        .expect("valid")
        .expect("a run");
    assert_eq!((off.local_trust, off.local_trust_source), (Some(false), Source::Flag));
    let arm = if AuthOptions::default().local_trust { "--local-trust" } else { "--no-local-trust" };
    let folded = usage().split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(
        folded.contains(&format!(
            "(env: SKEPD_LOCAL_TRUST=true|false); the default is {arm} — a hosted image must \
             pass --no-local-trust affirmatively"
        )),
        "the help names the library's default arm: {folded}"
    );
}

/// Checks that the blocked-prefix list's help says what a change costs.
///
/// It names each field's form (AUTH-4.70), that the path is read at start
/// alone, the empty list a board that may need a takedown starts on, and
/// that a replaced file is installed at the next request — under a
/// container, a file in a mounted directory.
#[test]
fn the_blocked_prefixes_help_names_the_forms_and_what_a_change_costs() {
    let folded = usage().split_whitespace().collect::<Vec<_>>().join(" ");
    for fact in [
        "operator and each record in the registry's global form (the node prefix in place of the \
         local form's leading 1), binding_writer and each prefix in this board's local form",
        "The PATH is read at start alone: a board started without one blocks nothing until a \
         restart names a file",
        "on a file holding {\"entries\": []}",
        "a container mounting its directory and never the file; the next request installs it",
    ] {
        assert!(folded.contains(fact), "the help says {fact:?}: {folded}");
    }
}

/// THE BIND's DEFAULT IS LOOPBACK (AUTH-4.57 (a); the deployment ruling —
/// the flag's default is loopback, so a notebook, a developer's machine and
/// a self-run board run the plain binary): with no flag and no variable the
/// parsed address is `127.0.0.1`, pinned as the literal loopback constant
/// and never through `DEFAULT_BIND`, so a default moved to the wildcard
/// fails here; and the usage names the flag, its variable, the default and
/// the one sentence that says why it is the default, with `--port`'s
/// sentence no longer stating the bind as a constant.
#[test]
fn the_bind_defaults_to_loopback_and_the_usage_says_so() {
    let absent = parse_args(argv(&["--data-dir", "/tmp/x"])).expect("valid").expect("a run");
    assert_eq!(absent.bind, Ipv4Addr::LOCALHOST, "the default is the loopback address");
    assert_eq!(absent.bind, Ipv4Addr::new(127, 0, 0, 1), "and that address is 127.0.0.1");
    let text = usage();
    for named in ["[--bind <ADDR>]", "\n  --bind <ADDR>      ", "SKEPD_BIND"] {
        assert!(text.contains(named), "the usage names {named:?}: {text}");
    }
    // The help wraps its lines: the sentence is read with its whitespace
    // folded, the default through the constant's rendering.
    let folded = text.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(
        folded.contains(
            "--bind <ADDR> the address to listen on (env: SKEPD_BIND; default 127.0.0.1 — the \
             only safe value outside a container whose network is the boundary)"
        ),
        "the --bind sentence, with its default and its reason: {folded}"
    );
    assert!(
        folded.contains("--port <PORT> TCP port on the address --bind names"),
        "the --port sentence names the bind: {folded}"
    );
    assert!(!text.contains("TCP port on 127.0.0.1"), "the bind is no constant of the help: {text}");
}

/// THE SETTING PARSES AS THE OTHERS DO — THE FLAG: `--bind` reads an IPv4
/// address as given, the wildcard, the loopback address and a routable one
/// alike; a value that is not one — a host name, an IPv6 address (a `::`
/// bind would class every IPv4 loopback client Remote through its mapped
/// form, a mapping this daemon does not perform), a bracketed one, an
/// address with a port, an out-of-range octet, the empty string — is
/// REFUSED with the flag named and the value quoted, in the message every
/// setting's refusal has, never defaulted; and the flag without its value
/// is refused.
#[test]
fn the_bind_flag_parses_an_ipv4_address_and_refuses_anything_else() {
    for (given, want) in [
        ("0.0.0.0", Ipv4Addr::UNSPECIFIED),
        ("127.0.0.1", Ipv4Addr::LOCALHOST),
        ("10.0.0.7", Ipv4Addr::new(10, 0, 0, 7)),
    ] {
        let a = parse_args(argv(&["--data-dir", "/tmp/x", "--bind", given]))
            .expect("valid flags")
            .expect("a run, not usage");
        assert_eq!(a.bind, want, "--bind {given} is read as given");
    }
    let last =
        parse_args(argv(&["--data-dir", "/tmp/x", "--bind", "0.0.0.0", "--bind", "127.0.0.1"]))
            .expect("valid flags")
            .expect("a run, not usage");
    assert_eq!(last.bind, Ipv4Addr::LOCALHOST, "the last flag wins, as every pair's does");
    for bad in ["localhost", "::1", "[::]", "0.0.0.0:8642", "256.0.0.1", "0.0.0", ""] {
        match parse_args(argv(&["--data-dir", "/tmp/x", "--bind", bad])) {
            Err(refused) => assert_eq!(
                refused,
                format!("--bind: '{bad}' is not an IPv4 address"),
                "the refusal names the flag and quotes the value"
            ),
            Ok(_) => panic!("'{bad}' is not an IPv4 address, and was not refused"),
        }
    }
    assert!(
        parse_args(argv(&["--data-dir", "/tmp/x", "--bind"])).is_err(),
        "the flag without its value is refused"
    );
}

/// THE SETTING PARSES AS THE OTHERS DO — THE VARIABLE: `SKEPD_BIND` seeds the
/// address the flag overrides — set to the wildcard with no flag it is
/// read; beside `--bind 127.0.0.1` the flag wins, as every flag does over
/// its variable — and set to a value that is not an IPv4 address it is
/// REFUSED with the variable named, with and without a flag beside it,
/// never read as absent and never defaulted: the one failure `EnvSetting`
/// exists to prevent. Judged in CHILDREN of this test binary (the hazard
/// suite's self-exec pattern), because the variable is process-wide and
/// this binary's other parse claims run beside this one.
#[test]
fn the_bind_variable_seeds_the_flag_and_a_bad_one_is_refused_not_defaulted() {
    const CHILD: &str = "SKEPD_TEST_BIND_CHILD";
    match std::env::var(CHILD).as_deref() {
        Ok("wildcard") => {
            // THE FIRST CHILD: the parent set `SKEPD_BIND=0.0.0.0`.
            let a = parse_args(argv(&["--data-dir", "/tmp/x"])).expect("valid").expect("a run");
            assert_eq!(a.bind, Ipv4Addr::UNSPECIFIED, "the variable seeds the address");
            let a = parse_args(argv(&["--data-dir", "/tmp/x", "--bind", "127.0.0.1"]))
                .expect("the flag wins over the variable")
                .expect("a run, not usage");
            assert_eq!(a.bind, Ipv4Addr::LOCALHOST, "the flag beats the variable");
            return;
        }
        Ok("bad") => {
            // THE SECOND CHILD: the parent set `SKEPD_BIND=not-an-address`.
            let refused = "SKEPD_BIND: 'not-an-address' is not an IPv4 address";
            match parse_args(argv(&["--data-dir", "/tmp/x"])) {
                Err(e) => assert_eq!(e, refused, "the variable's refusal names it"),
                Ok(_) => panic!("the variable's bad value was defaulted, not refused"),
            }
            match parse_args(argv(&["--data-dir", "/tmp/x", "--bind", "127.0.0.1"])) {
                Err(e) => assert_eq!(
                    e, refused,
                    "a flag beside it rescues nothing: the variable is read first"
                ),
                Ok(_) => panic!("the variable's bad value was passed over for the flag"),
            }
            return;
        }
        _ => {}
    }
    let exe = std::env::current_exe().expect("the test binary");
    for (arm, value) in [("wildcard", "0.0.0.0"), ("bad", "not-an-address")] {
        let out = std::process::Command::new(&exe)
            .args([
                "tests::the_bind_variable_seeds_the_flag_and_a_bad_one_is_refused_not_defaulted",
                "--exact",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD, arm)
            .env(SKEPD_BIND.var, value)
            .output()
            .expect("run the child");
        assert!(
            out.status.success(),
            "the {arm} child's claims failed:\n{}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

/// THE ORIGIN LIST's FLAGS BEAT ITS VARIABLE, as every flag beats its
/// variable: `SKEPD_ORIGIN` seeds the list where no `--origin` is given;
/// the first `--origin` replaces it whole, so a stale variable's origin
/// never widens the signed set a flag names; and repeated `--origin`s add to
/// one another, in order — the list carrying the arm that set it. Judged in
/// a CHILD of this test binary, as the bind variable's claims are, because
/// the variable is process-wide.
#[test]
fn the_origin_flags_replace_the_variables_list_and_add_to_one_another() {
    const CHILD: &str = "SKEPD_TEST_ORIGIN_CHILD";
    if std::env::var_os(CHILD).is_some() {
        // THE CHILD: the parent set `SKEPD_ORIGIN=https://old.example`.
        let origins = |line: &[&str]| -> Vec<String> {
            let parsed = parse_args(argv(line)).expect("valid").expect("a run");
            parsed.origins.iter().map(|o| o.as_str().to_string()).collect()
        };
        assert_eq!(
            origins(&["--data-dir", "/tmp/x"]),
            ["https://old.example"],
            "the variable seeds the list"
        );
        assert_eq!(
            origins(&["--data-dir", "/tmp/x", "--origin", "https://new.example"]),
            ["https://new.example"],
            "the first flag replaces the variable's list"
        );
        assert_eq!(
            origins(&[
                "--origin",
                "https://a.example",
                "--data-dir",
                "/tmp/x",
                "--origin",
                "https://b.example",
            ]),
            ["https://a.example", "https://b.example"],
            "repeated flags add to one another, in order"
        );
        // The list carries the arm that set it, which the `auth:` line
        // names beside the set (§1.1 m14).
        let source =
            |line: &[&str]| parse_args(argv(line)).expect("valid").expect("a run").origins_source;
        assert_eq!(source(&["--data-dir", "/tmp/x"]), Source::Env, "the variable's list");
        assert_eq!(
            source(&["--data-dir", "/tmp/x", "--origin", "https://new.example"]),
            Source::Flag,
            "the flag's list"
        );
        return;
    }
    let exe = std::env::current_exe().expect("the test binary");
    let out = std::process::Command::new(exe)
        .args([
            "tests::the_origin_flags_replace_the_variables_list_and_add_to_one_another",
            "--exact",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD, "1")
        .env(SKEPD_ORIGIN, "https://old.example")
        .output()
        .expect("run the child");
    assert!(
        out.status.success(),
        "the child's claims failed:\n{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Checks that an unknown `SKEPD_` variable is refused, named.
///
/// A misspelled `SKEPD_BLOCKED_PREFIX` stops the daemon's parse and a
/// tool's, naming it beside the variables the daemon reads, where it would
/// otherwise start the board with no list and say nothing (`operations.md`
/// §2, validated at start); two unknown names are both named, sorted;
/// `--version` still answers; and `SKEPD_URL`, skep-mcp's, passes. Judged in
/// children of this test binary, as the bind variable's claims are, since
/// the environment is process-wide.
#[test]
fn an_unknown_skepd_variable_is_refused_by_name() {
    const CHILD: &str = "SKEPD_TEST_UNKNOWN_VARIABLE_CHILD";
    let reads = VARIABLES.join(", ");
    match std::env::var(CHILD).as_deref() {
        Ok("misspelled") => {
            let refused =
                format!("SKEPD_BLOCKED_PREFIX: the daemon reads no such variable — it reads {reads}");
            assert_eq!(parse_args(argv(&["--data-dir", "/tmp/x"])).err(), Some(refused.clone()));
            assert_eq!(parse_args(argv(&["--help"])).err(), Some(refused.clone()), "--help too");
            assert_eq!(
                parse_command(argv(&["inventory", "--data-dir", "/tmp/x"])).err(),
                Some(refused),
                "a tool's line too"
            );
            assert!(
                matches!(parse_command(argv(&["--version"])), Ok(Some(Command::Version))),
                "the version line consults no environment"
            );
            return;
        }
        Ok("two") => {
            assert_eq!(
                parse_args(argv(&["--data-dir", "/tmp/x"])).err(),
                Some(format!(
                    "SKEPD_PORTS, SKEPD_UPLOAD: the daemon reads no such variables — it reads \
                     {reads}"
                )),
                "every unknown name, sorted"
            );
            return;
        }
        Ok("another_programs") => {
            assert!(parse_args(argv(&["--data-dir", "/tmp/x"])).is_ok(), "SKEPD_URL is skep-mcp's");
            return;
        }
        _ => {}
    }
    let exe = std::env::current_exe().expect("the test binary");
    for (arm, set) in [
        ("misspelled", &[("SKEPD_BLOCKED_PREFIX", "/etc/skepd/blocked.json")][..]),
        ("two", &[("SKEPD_UPLOAD", "false"), ("SKEPD_PORTS", "8642")][..]),
        ("another_programs", &[("SKEPD_URL", "http://127.0.0.1:8642")][..]),
    ] {
        let out = std::process::Command::new(&exe)
            .args([
                "tests::an_unknown_skepd_variable_is_refused_by_name",
                "--exact",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD, arm)
            .envs(set.iter().copied())
            .output()
            .expect("run the child");
        assert!(
            out.status.success(),
            "the {arm} child's claims failed:\n{}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

/// Checks that the help names every variable the daemon reads, and no other.
///
/// Its `SKEPD_` names are exactly [`VARIABLES`], the list the
/// unknown-variable refusal reads, so a setting documented and not listed
/// fails here rather than being refused when an operator sets it.
#[test]
fn the_help_names_exactly_the_variables_the_daemon_reads() {
    let text = usage();
    let mut named: Vec<&str> = text
        .match_indices("SKEPD_")
        .map(|(at, _)| {
            let rest = &text[at..];
            let end =
                rest.find(|c: char| !(c.is_ascii_uppercase() || c == '_')).unwrap_or(rest.len());
            &rest[..end]
        })
        .filter(|name| name.len() > "SKEPD_".len())
        .collect();
    named.sort_unstable();
    named.dedup();
    let mut reads = VARIABLES.to_vec();
    reads.sort_unstable();
    assert_eq!(named, reads, "the help's variables are the ones the daemon reads");
}

/// A COMMAND LINE THE BINARY CANNOT READ, REFUSED (exit 2): at a terminal,
/// the line and then the usage text, for the person who typed it; anywhere
/// else — a service manager's log, a pipe — the one line, naming `--help`,
/// so a unit that restarts on failure writes one line an attempt and never
/// the usage text at each. The real binary's piped stderr is the
/// child-process suite's (`tests/it/open.rs`).
#[test]
fn a_refused_command_line_carries_the_usage_text_at_a_terminal_alone() {
    let e = "unknown argument '--frobnicate'";
    assert_eq!(usage_refusal(e, true), format!("skepd: {e}\n\n{}", usage()));
    assert_eq!(usage_refusal(e, false), format!("skepd: {e}; skepd --help prints the usage"));
    assert!(!usage_refusal(e, false).contains('\n'), "one line off a terminal");
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
