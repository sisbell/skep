use super::*;

fn argv(a: &[&str]) -> Vec<OsString> {
    a.iter().copied().map(OsString::from).collect()
}

fn refusal(a: &[&str]) -> String {
    match parse(argv(a)) {
        Err(Usage(text)) => text,
        Ok(_) => panic!("{a:?} parsed"),
    }
}

#[test]
fn a_command_line_parses_and_each_malformed_part_is_refused() {
    let Parsed::CommandLine(c) = parse(argv(&["claim", "--board", "http://127.0.0.1:8642", "--anchor-out", "/a", "--anchor-out", "/b", "--paper"])).unwrap() else { panic!() };
    assert_eq!(c.command, Command::Claim);
    assert_eq!(c.values("--anchor-out"), ["/a", "/b"]);
    assert!(c.switch("--paper"));
    assert_eq!(c.origin().unwrap().as_str(), "http://127.0.0.1:8642");
    assert!(parse(argv(&["frobnicate"])).is_err(), "an unknown command is refused");
    assert!(parse(argv(&["session", "--board"])).is_err(), "a flag without its value is refused");
    assert!(parse(argv(&["health", "--frob"])).is_err(), "an unknown flag is refused");
    assert!(matches!(parse(argv(&["--help"])).unwrap(), Parsed::Help));
    let Parsed::CommandLine(c) = parse(argv(&["recover", "--lost", "ab", "--lost", "cd", "--stolen", "--anchor", "/a"])).unwrap() else { panic!() };
    assert_eq!(c.values("--lost"), ["ab", "cd"], "--lost is repeatable");
    assert!(c.switch("--stolen"));
    assert!(parse(argv(&["retire", "--yes"])).is_err(), "--yes does not exist: a typed answer, never a flag");
    let Parsed::CommandLine(c) = parse(argv(&["keygen", "--payload"])).unwrap() else { panic!() };
    assert!(c.switch("--payload"), "a switch at keygen");
    let Parsed::CommandLine(c) = parse(argv(&["verify", "--payload", "-", "--board", "HTTP://x", "--principal", "7x"])).unwrap() else { panic!() };
    assert_eq!(c.values("--payload"), ["-"], "a value at verify");
    assert!(c.origin().is_err(), "a non-canonical board is a usage refusal");
    assert!(c.origin_given().is_err(), "a board given badly is refused, never read as one not given");
    assert!(c.principal().is_err(), "a principal given badly is refused, never read as one not given");
    let Parsed::CommandLine(c) = parse(argv(&["accept", "--board", "http://127.0.0.1:8642", "--principal", "7"])).unwrap() else { panic!() };
    assert_eq!(c.origin_given().unwrap().map(|o| o.as_str().to_string()), Some("http://127.0.0.1:8642".to_string()));
    assert_eq!(c.principal().unwrap(), Some(7));
}

/// A principal is an integer JSON carries exactly (AUTH-6.36): `2^53 − 1`
/// reads, `2^53` and anything not an integer are none — at the flag as
/// in a reply, through the one grammar.
#[test]
fn a_principal_past_the_wires_range_is_none() {
    assert_eq!(parse_principal("9007199254740991"), Some(MAX_PRINCIPAL));
    assert_eq!(parse_principal("0"), Some(0));
    for none in ["9007199254740992", "18446744073709551615", "-1", "7x", ""] {
        assert_eq!(parse_principal(none), None, "`{none}`");
    }
    let Parsed::CommandLine(c) = parse(argv(&["verify", "--principal", "9007199254740992"])).unwrap() else { panic!() };
    assert!(c.principal().is_err(), "past the range at the flag is a usage refusal, never read as one not given");
}

/// THE GRAMMAR: a flag of another command's is refused naming the
/// command, never accepted and dropped; a second value of a flag that
/// takes one is refused, never the last one standing; a flag that
/// repeats keeps every value; and every flag a row names is one `HELP`
/// documents.
#[test]
fn each_command_takes_its_own_flags_and_a_flag_that_takes_one_value_takes_one() {
    assert_eq!(refusal(&["health", "--fingerprint", "ab"]), "`--fingerprint` is not a flag of `health`");
    assert_eq!(refusal(&["verify", "--anchor-out", "/d"]), "`--anchor-out` is not a flag of `verify`");
    assert_eq!(refusal(&["retire", "--yes"]), "unknown argument `--yes`", "a flag of no command's is unknown");
    assert_eq!(refusal(&["recover", "--anchor", "/a", "--anchor", "/b"]), "`--anchor` is given at most once at `recover`");
    assert_eq!(refusal(&["session", "--principal", "1", "--principal", "2"]), "`--principal` is given at most once at `session`", "a setting takes one value");
    let Parsed::CommandLine(c) = parse(argv(&["verify", "--anchor", "/a", "--anchor", "/b", "--json"])).unwrap() else { panic!() };
    assert_eq!(c.values("--anchor"), ["/a", "/b"], "--anchor repeats at verify");
    assert!(c.switch("--json"), "--json is every command's");
    let Parsed::CommandLine(c) = parse(argv(&["keygen", "--label", "phone", "--dir", "/s"])).unwrap() else { panic!() };
    assert_eq!(c.value("--label"), Some("phone"), "the settings and --label are every command's");
    // A flag named whole: `--anchor` in `--anchor <path>`, never in
    // `--anchor-out`.
    let documented = |flag: &str| HELP.match_indices(flag).any(|(i, _)| !HELP[i + flag.len()..].starts_with(|c: char| c.is_ascii_alphanumeric() || c == '-'));
    for row in &GRAMMAR {
        for &flag in row.once.iter().chain(row.repeated).chain(row.switches).chain(&GLOBAL) {
            assert!(documented(flag), "`{flag}` of `{}` is documented in HELP", row.command);
        }
        assert!(HELP.contains(&format!("\n  {} ", row.command)), "`{}` is listed in HELP", row.command);
    }
}

/// THE FORMS: a flag that belongs to one form of its command is refused
/// outside it, two flags of two forms are refused together, a flag that
/// names one value inside a form is refused a second, and the backup
/// moment's flags are refused past its two anchors — each in its own
/// words, an argument's refusal ahead of every rule's and the rules in
/// their row's order; every form given whole parses; and every flag a
/// rule names is its row's, one a count bounds a flag that repeats.
#[test]
fn a_flag_outside_its_form_is_refused_and_two_forms_together() {
    let refused: [(&[&str], &str); 13] = [
        (&["keygen", "--anchor-out", "/d"], "`--anchor-out` belongs to `keygen --anchors` and is refused without `--anchors`"),
        (&["keygen", "--anchors", "--anchor-label", "a", "--anchor-label", "b", "--anchor-label", "c"], "`--anchor-label` is given at most 2 times at `keygen`"),
        (&["claim", "--hosted", "-", "--name", "n"], "`--hosted` and `--name` belong to two forms of `claim`: give one"),
        (&["enroll", "--reply", "ab", "--payload", "-"], "`--reply` and `--payload` belong to two forms of `enroll`: give one"),
        (&["recover", "--anchor-lost", "--stolen"], "`--anchor-lost` and `--stolen` belong to two forms of `recover`: give one"),
        (&["recover", "--anchor-lost", "--lost", "ab", "--lost", "cd"], "`--lost` is given at most once at `recover --anchor-lost`"),
        (&["recover", "--paper"], "`--paper` belongs to `recover --anchor-lost` and is refused without `--anchor-lost`"),
        (&["handoff", "--account", "1.0.1.2", "--anchor", "/a"], "`--anchor` belongs to `handoff --payload` and is refused without `--payload`"),
        (&["accept", "--anchor", "/a"], "`--anchor` belongs to `accept --reprint` and is refused without `--reprint`"),
        (&["accept", "--no-anchors", "--paper"], "`--no-anchors` and `--paper` belong to two forms of `accept`: give one"),
        (&["accept", "--reprint", "--paper", "--anchor-out", "/d"], "`--reprint` and `--anchor-out` belong to two forms of `accept`: give one"),
        (&["accept", "--anchor-out", "/a", "--anchor-out", "/b", "--anchor-out", "/c"], "`--anchor-out` is given at most 2 times at `accept`"),
        (&["recover", "--anchor-lost", "--stolen", "--frob"], "unknown argument `--frob`"),
    ];
    for (line, words) in refused {
        assert_eq!(refusal(line), words, "{line:?}");
    }
    for line in [
        &["recover", "--lost", "ab", "--lost", "cd", "--stolen", "--anchor", "/a"][..],
        &["recover", "--anchor-lost", "--lost", "ab", "--anchor", "/a", "--anchor-out", "/a", "--anchor-out", "/b", "--paper"],
        &["accept", "--account", "1.0.1.2", "--reprint", "--anchor", "/a", "--anchor", "/b"],
        &["accept", "--account", "1.0.1.2", "--anchor-out", "/a", "--anchor-out", "/b", "--paper"],
        &["accept", "--account", "1.0.1.2", "--no-anchors"],
        &["keygen", "--anchors", "--anchor-label", "a", "--anchor-label", "b", "--anchor-out", "/a", "--anchor-out", "/b", "--paper", "--payload"],
        &["handoff", "--account", "1.0.1.2", "--payload", "-", "--anchor", "/a"],
        &["claim", "--name", "n", "--anchor-out", "/a", "--anchor-out", "/b", "--paper"],
        &["enroll", "--reply", "ab"],
    ] {
        assert!(parse(argv(line)).is_ok(), "{line:?} parses");
    }
    for row in &GRAMMAR {
        for form in row.forms {
            let (named, counted) = match *form {
                Form::Within(a, b) | Form::Apart(a, b) => (vec![a, b], None),
                Form::OnceWithin(a, b) => (vec![a, b], Some(a)),
                Form::AtMost(a, _) => (vec![a], Some(a)),
            };
            for flag in named {
                assert!(row.once.contains(&flag) || row.repeated.contains(&flag) || row.switches.contains(&flag), "`{flag}`, named by {form:?}, is a flag of `{}`", row.command);
            }
            if let Some(flag) = counted {
                assert!(row.repeated.contains(&flag), "{form:?} counts `{flag}`, a flag that repeats at `{}`", row.command);
            }
        }
    }
}

/// THE GRAMMAR from `HELP`'s side: every flag `HELP` shows at a command
/// — in its description or its flags line — is one that command's parser
/// takes, in the form it belongs to, and every flag it lists for all
/// commands is one each takes; so a person following `--help` never
/// meets exit 2 for a flag it showed.
#[test]
fn every_flag_help_shows_at_a_command_is_one_its_parser_takes() {
    let takes = |command: Command, flag: &str| {
        let row = GRAMMAR.iter().find(|r| r.command == command).expect("every command has its row");
        // A flag that belongs to one form is given behind the flag that
        // opens it, with a value where the opener takes one.
        let mut line = vec![command.verb()];
        for form in row.forms {
            if let Form::Within(within, opener) = *form {
                if within == flag {
                    line.push(opener);
                    if row.once.contains(&opener) || row.repeated.contains(&opener) {
                        line.push("x");
                    }
                }
            }
        }
        line.push(flag);
        match parse(argv(&line)) {
            Ok(_) => true,
            Err(Usage(text)) if text == format!("{flag} needs a value") => {
                line.push("x");
                parse(argv(&line)).is_ok()
            }
            Err(_) => false,
        }
    };
    let flags = |line: &str| -> Vec<String> {
        line.match_indices("--").map(|(i, _)| line[i..].chars().take_while(|c| *c == '-' || c.is_ascii_lowercase()).collect::<String>()).filter(|f| f.len() > 2).collect()
    };
    let (mut shown, mut every, mut at) = (Vec::new(), Vec::new(), None);
    for line in HELP.lines().take_while(|l| !l.starts_with("exit codes:")) {
        if let Some(row) = GRAMMAR.iter().find(|r| line.starts_with(&format!("  {} ", r.command)) || line.starts_with(&format!("  {}:", r.command))) {
            at = Some(row.command);
        } else if line.starts_with("  --") {
            at = None;
            every.extend(flags(line));
            continue;
        } else if !line.starts_with("   ") {
            at = None;
        }
        if let Some(command) = at {
            shown.extend(flags(line).into_iter().map(|f| (command, f)));
        }
    }
    assert!(
        shown.contains(&(Command::Handoff, "--anchor".to_string())) && shown.contains(&(Command::Session, "--close".to_string())),
        "the scan reads HELP's command sections: {shown:?}"
    );
    assert!(GLOBAL.iter().all(|g| every.iter().any(|e| e == g)) && every.iter().any(|e| e == "--json"), "the scan reads HELP's flags for all commands: {every:?}");
    for (command, flag) in &shown {
        assert!(takes(*command, flag), "HELP shows `{flag}` at `{command}`, and its parser refuses it");
    }
    for row in &GRAMMAR {
        for flag in &every {
            assert!(takes(row.command, flag), "HELP lists `{flag}` for every command, and `{}` refuses it", row.command);
        }
    }
}

/// Each row is one command's, opened by its own verb: no two rows share
/// a command, and every row's verb parses to that row's command.
#[test]
fn each_row_is_one_command_opened_by_its_verb() {
    let commands: std::collections::HashSet<Command> = GRAMMAR.iter().map(|r| r.command).collect();
    assert_eq!(commands.len(), GRAMMAR.len(), "no two rows share a command");
    for row in &GRAMMAR {
        let Parsed::CommandLine(c) = parse(argv(&[row.command.verb()])).unwrap() else { panic!("`{}` parsed as the help", row.command) };
        assert_eq!(c.command, row.command);
    }
}

/// An argument that is not UTF-8 text is refused naming it — as a
/// variable's is — wherever it stands: the command, a flag, a value.
#[cfg(unix)]
#[test]
fn an_argument_that_is_not_text_is_refused_naming_it() {
    use std::os::unix::ffi::OsStringExt;

    let not_text = || OsString::from_vec(b"store-\xff".to_vec());
    for line in [vec![not_text()], vec!["keygen".into(), not_text()], vec!["keygen".into(), "--dir".into(), not_text()]] {
        match parse(line) {
            Err(Usage(text)) => assert_eq!(text, "the argument 'store-\u{fffd}' is not UTF-8 text"),
            Ok(parsed) => panic!("parsed: {parsed:?}"),
        }
    }
}
