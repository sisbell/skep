//! T1 — THE COMMAND LINE: `--version` renders `skepd`'s form; every flag's
//! default is its named constant; `--mailer` and `--from` come together or
//! not at all; an unknown flag, a missing value, a value of the wrong form
//! and a missing required flag are each a usage refusal (`main` answers it
//! exit 2 — the binary's suite runs one); `--workers` defaults to its
//! constant and refuses zero (T21); `--docker-fake` and `--mailer-fake` are
//! flags of a `test-hooks` build alone; and the usage text names every flag
//! and renders every default from its constant.

use std::ffi::OsString;

use super::*;

fn argv(args: &[&str]) -> Vec<OsString> {
    args.iter().map(OsString::from).collect()
}

/// `serve` with the two required flags and `rest`.
fn serve(rest: &[&str]) -> Result<Command, String> {
    parse(argv(&[&["serve", "--state-dir", "/var/lib/skep-provision", "--reply-to", "owner@skep.host"][..], rest].concat()))
}

fn served(rest: &[&str]) -> Serve {
    match serve(rest) {
        Ok(Command::Serve(s)) => *s,
        other => panic!("{rest:?}: {other:?}"),
    }
}

/// T1: `--version` RENDERS `version_line`'s FORM — `skep-provision
/// <version> (<commit>)`, the commit `SKEP_GIT_SHA`'s at build time,
/// `unknown` where the build set none — read as the first argument, what
/// follows unread; among a verb's flags, refused naming the form.
#[test]
fn version_renders_the_daemons_form() {
    assert_eq!(version_line(), format!("skep-provision {} ({})", env!("CARGO_PKG_VERSION"), option_env!("SKEP_GIT_SHA").unwrap_or("unknown")));
    assert_eq!(parse(argv(&["--version"])), Ok(Command::Version));
    assert_eq!(parse(argv(&["--version", "--bogus"])), Ok(Command::Version), "what follows is unread");
    assert_eq!(serve(&["--version"]), Err("--version is read as the first argument: skep-provision --version".to_owned()));
    assert!(usage().contains("\n  --version               this binary's version"), "{}", usage());
}

/// T1: EVERY FLAG's DEFAULT EQUALS ITS NAMED CONSTANT.
#[test]
fn every_default_is_its_named_constant() {
    let s = served(&[]);
    assert_eq!(s.listen, DEFAULT_LISTEN);
    assert_eq!(s.boards_dir, PathBuf::from(DEFAULT_BOARDS_DIR));
    assert_eq!(s.settings.image, DEFAULT_IMAGE);
    assert_eq!(s.settings.cli_image, DEFAULT_CLI_IMAGE);
    assert_eq!(s.settings.network, DEFAULT_NETWORK);
    assert_eq!(s.settings.caddy, DEFAULT_CADDY);
    assert_eq!(s.settings.suffix, DEFAULT_SUFFIX);
    assert_eq!(s.settings.log_max_size, DEFAULT_LOG_MAX_SIZE);
    assert_eq!(s.settings.log_max_file, DEFAULT_LOG_MAX_FILE);
    assert_eq!(s.workers, DEFAULT_WORKERS);
    assert_eq!(s.mail, None, "no mail without --mailer and --from");
    assert_eq!(s.state_dir, PathBuf::from("/var/lib/skep-provision"));
    assert_eq!(s.reply_to, "owner@skep.host");
    match parse(argv(&["invite", "--address", "person@example.com", "--state-dir", "/s"])) {
        Ok(Command::Invite(i)) => {
            assert_eq!(i.suffix, DEFAULT_SUFFIX);
            assert_eq!(i.code, None);
        }
        other => panic!("{other:?}"),
    }
    // The constants' own values, as the documents name them.
    assert_eq!(DEFAULT_LISTEN.to_string(), "127.0.0.1:8842");
    assert!(DEFAULT_LISTEN.ip().is_loopback() && DEFAULT_LISTEN.port() != 8642);
    assert_eq!((DEFAULT_BOARDS_DIR, DEFAULT_IMAGE, DEFAULT_CLI_IMAGE, DEFAULT_NETWORK, DEFAULT_CADDY, DEFAULT_SUFFIX), ("/etc/caddy/boards", "skep-hosted", "skep-cli", "skep", "caddy", "skep.host"));
    assert_eq!((DEFAULT_LOG_MAX_SIZE, DEFAULT_LOG_MAX_FILE), ("10m", 5), "the README's serving line");
    assert_eq!(DEFAULT_WORKERS, 3, "the owner's number");
}

/// T21: `--workers` DEFAULTS TO `DEFAULT_WORKERS`; `--workers 0` is a usage
/// refusal (exit 2 at `main`); `--workers 3` and `--workers 1` parse; a
/// value that is no count is refused; the usage names the flag and renders
/// its default from the constant.
#[test]
fn the_workers_flag_defaults_to_its_constant_and_refuses_zero() {
    assert_eq!(served(&[]).workers, DEFAULT_WORKERS);
    assert_eq!(serve(&["--workers", "0"]), Err("--workers: '0' is not a count of one or more".to_owned()));
    assert_eq!(served(&["--workers", "3"]).workers, 3);
    assert_eq!(served(&["--workers", "1"]).workers, 1);
    assert_eq!(served(&["--workers", "1", "--workers", "2"]).workers, 2, "the last given wins");
    assert!(serve(&["--workers", "two"]).is_err());
    assert!(serve(&["--workers", "-1"]).is_err());
    assert_eq!(serve(&["--workers"]), Err("--workers needs a value".to_owned()));
    assert!(parse(argv(&["invite", "--address", "a@b", "--state-dir", "/s", "--workers", "2"])).is_err(), "a flag of serve's alone");
    let text = usage();
    assert!(text.contains("\n  --workers <N>"), "{text}");
    assert!(text.contains("[--workers <N>]"), "{text}");
    assert!(text.split_whitespace().collect::<Vec<_>>().join(" ").contains(&format!("(default {DEFAULT_WORKERS})")), "{text}");
}

/// Every flag given lands in its own setting.
#[test]
fn every_flag_lands_in_its_setting() {
    let s = served(&[
        "--listen",
        "0.0.0.0:9000",
        "--boards-dir",
        "/b",
        "--image",
        "img:2",
        "--cli-image",
        "cli:2",
        "--network",
        "net2",
        "--caddy",
        "proxy2",
        "--suffix",
        "example.org",
        "--log-max-size",
        "50m",
        "--log-max-file",
        "3",
        "--mailer",
        "/usr/bin/msmtp",
        "--from",
        "noreply@example.org",
    ]);
    assert_eq!(s.listen.to_string(), "0.0.0.0:9000");
    assert_eq!(s.boards_dir, PathBuf::from("/b"));
    assert_eq!(
        s.settings,
        Settings { image: "img:2".into(), cli_image: "cli:2".into(), network: "net2".into(), caddy: "proxy2".into(), suffix: "example.org".into(), log_max_size: "50m".into(), log_max_file: 3 }
    );
    assert_eq!(s.mail, Some(MailArgs { mailer: Mailer::Program(PathBuf::from("/usr/bin/msmtp")), from: "noreply@example.org".into() }));
    assert_eq!(served(&["--image", "a", "--image", "b"]).settings.image, "b", "the last given wins");
}

/// T1: `--mailer` WITHOUT `--from`, AND THE REVERSE, IS A USAGE REFUSAL.
#[test]
fn mailer_and_from_come_together_or_not_at_all() {
    assert_eq!(serve(&["--mailer", "/usr/sbin/sendmail"]), Err("--mailer is given without --from: give both, or neither for no mail".to_owned()));
    assert_eq!(serve(&["--from", "noreply@skep.host"]), Err("--from is given without --mailer: give both, or neither for no mail".to_owned()));
}

/// T1: AN UNKNOWN FLAG, a flag without its value, a value of the wrong
/// form and a missing required flag are each a usage refusal.
#[test]
fn every_usage_refusal() {
    assert_eq!(serve(&["--bogus"]), Err("serve: unknown argument '--bogus'".to_owned()));
    assert_eq!(parse(argv(&["invite", "--bogus"])), Err("invite: unknown argument '--bogus'".to_owned()));
    assert_eq!(serve(&["--listen"]), Err("--listen needs a value".to_owned()));
    assert!(serve(&["--listen", "localhost"]).is_err());
    assert!(serve(&["--image", "--privileged"]).expect_err("a flag of docker's").contains("not one word that does not begin with '-'"));
    assert!(serve(&["--network", "a b"]).is_err());
    assert!(serve(&["--suffix", "Skep.Host"]).is_err());
    assert!(serve(&["--suffix", "skep..host"]).is_err());
    assert!(serve(&["--log-max-size", "10x"]).is_err());
    assert!(serve(&["--log-max-file", "0"]).is_err());
    assert!(serve(&["--from", "not an address", "--mailer", "m"]).is_err());
    assert!(parse(argv(&["serve", "--reply-to", "owner@skep.host"])).expect_err("no state dir").contains("--state-dir is required"));
    assert!(parse(argv(&["serve", "--state-dir", "/s"])).expect_err("no reply-to").contains("--reply-to is required"));
    assert!(parse(argv(&["invite", "--state-dir", "/s"])).expect_err("no address").contains("--address is required"));
    assert!(parse(argv(&["invite", "--address", "a@b"])).expect_err("no state dir").contains("--state-dir is required"));
    assert!(parse(argv(&["invite", "--address", "a@b", "--state-dir", "/s", "--code", "a b"])).is_err());
    assert_eq!(parse(argv(&[])), Err("a verb is required: serve or invite".to_owned()));
    assert_eq!(parse(argv(&["provision"])), Err("unknown verb 'provision': serve or invite".to_owned()));
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStringExt;
        assert_eq!(parse(vec![OsString::from("serve"), OsString::from_vec(vec![0xff])]), Err("an argument is not UTF-8 text".to_owned()));
    }
    assert_eq!(parse(argv(&["--help"])), Ok(Command::Help));
    assert_eq!(serve(&["--help"]), Ok(Command::Help));
}

/// T1: `--docker-fake` and `--mailer-fake` ARE FLAGS OF A `test-hooks`
/// BUILD ALONE — pinned under a `cfg` here: in the build this suite runs
/// (the self dev-dependency turns the feature on) they parse, and in any
/// other they are unknown arguments, as the shipped binary refuses them.
#[test]
fn the_fakes_flags_are_a_test_hooks_builds_alone() {
    #[cfg(feature = "test-hooks")]
    {
        let s = served(&["--docker-fake", "/tmp/script", "--mailer-fake", "/tmp/mail.log", "--from", "noreply@skep.host"]);
        assert_eq!(s.docker_fake, Some(PathBuf::from("/tmp/script")));
        assert_eq!(s.mail, Some(MailArgs { mailer: Mailer::Fake(PathBuf::from("/tmp/mail.log")), from: "noreply@skep.host".into() }));
        assert!(usage().contains("--docker-fake <SCRIPT>") && usage().contains("--mailer-fake <LOG>"));
    }
    #[cfg(not(feature = "test-hooks"))]
    {
        assert_eq!(serve(&["--docker-fake", "/tmp/script"]), Err("serve: unknown argument '--docker-fake'".to_owned()));
        assert_eq!(serve(&["--mailer-fake", "/tmp/mail.log"]), Err("serve: unknown argument '--mailer-fake'".to_owned()));
        assert!(!usage().contains("fake"));
    }
}

/// THE USAGE TEXT names every flag and renders each default from its
/// constant.
#[test]
fn the_usage_names_every_flag_and_its_default() {
    let text = usage();
    for flag in [
        "--state-dir <DIR>",
        "--reply-to <ADDRESS>",
        "--listen <ADDR:PORT>",
        "--boards-dir <DIR>",
        "--image <TAG>",
        "--cli-image <TAG>",
        "--network <BRIDGE>",
        "--caddy <CONTAINER>",
        "--suffix <DOMAIN>",
        "--log-max-size <SIZE>",
        "--log-max-file <N>",
        "--workers <N>",
        "--mailer <PROGRAM>",
        "--from <ADDRESS>",
        "--address <ADDRESS>",
        "--code <CODE>",
        "--help",
        "--version",
    ] {
        assert!(text.contains(&format!("\n  {flag}")), "{flag}");
    }
    let folded = text.split_whitespace().collect::<Vec<_>>().join(" ");
    for default in [
        format!("(default {DEFAULT_LISTEN})"),
        format!("(default {DEFAULT_BOARDS_DIR})"),
        format!("(default {DEFAULT_IMAGE})"),
        format!("(default {DEFAULT_CLI_IMAGE})"),
        format!("(default {DEFAULT_NETWORK})"),
        format!("(default {DEFAULT_CADDY})"),
        format!("(default {DEFAULT_SUFFIX})"),
        format!("(default {DEFAULT_LOG_MAX_SIZE})"),
        format!("(default {DEFAULT_LOG_MAX_FILE})"),
        format!("(default {DEFAULT_WORKERS})"),
    ] {
        assert!(folded.contains(&default), "{default}");
    }
}
