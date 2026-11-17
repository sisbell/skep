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

/// `deposit`'s row (REG-1.9): the node account once, as `bind` takes it,
/// and the board's origins repeated, every value kept in the order given —
/// the order the endpoint's body carries and a reader tries them in — with
/// the settings every command takes; `hint`'s `--also` is no flag of it.
#[test]
fn deposit_takes_its_account_once_and_its_origins_in_the_order_given() {
    let line = ["deposit", "--board", "http://127.0.0.1:8642", "--account", "1.0.2", "--origin", "https://acme.example", "--origin", "https://acme.example.net", "--principal", "931", "--key", "/k"];
    let Parsed::CommandLine(c) = parse(argv(&line)).unwrap() else { panic!() };
    assert_eq!((c.command, c.command.verb()), (Command::Deposit, "deposit"));
    assert_eq!(c.value("--account"), Some("1.0.2"));
    assert_eq!(c.values("--origin"), ["https://acme.example", "https://acme.example.net"], "--origin repeats, in order");
    assert_eq!((c.principal().unwrap(), c.key_file().unwrap()), (Some(931), Some(PathBuf::from("/k"))));
    assert_eq!(refusal(&["deposit", "--account", "1.0.2", "--account", "1.0.3"]), "`--account` is given at most once at `deposit`");
    assert_eq!(refusal(&["deposit", "--also", "https://acme.example"]), "`--also` is not a flag of `deposit`");
    assert_eq!(refusal(&["hint", "--origin", "https://acme.example"]), "`--origin` is not a flag of `hint`");
    assert_eq!(GRAMMAR.len(), 25, "the twenty-five commands, one row each");
}

/// THE REGISTRAR's FOUR (REG-4.107; REG-4.131) and THE OPERAND: `review`
/// takes the settings alone; `approve` its request, the one argument typed
/// after the verb with no flag before it, or `--auto` in its place — two
/// forms, refused together; `deny` its request and `--clause`, once; and
/// `set-policy`, the first verb that holds a hyphen, its file. An operand is
/// read wherever it stands among the flags, refused a second, and refused
/// empty; a command whose row names none refuses a bare word as an unknown
/// argument, as before; and a word that opens with a dash is never an
/// operand, so a misspelled flag is not taken for one.
#[test]
fn the_registrars_four_take_their_operand_once_and_approve_its_request_or_auto() {
    let link = "1.0.1.2.0.1.0.2.3";
    let Parsed::CommandLine(c) = parse(argv(&["review", "--board", "http://127.0.0.1:8642"])).unwrap() else { panic!() };
    assert_eq!((c.command, c.command.verb(), c.operand()), (Command::Review, "review", None));
    let Parsed::CommandLine(c) = parse(argv(&["approve", link, "--board", "http://127.0.0.1:8642", "--principal", "1"])).unwrap() else { panic!() };
    assert_eq!((c.command, c.operand(), c.switch("--auto")), (Command::Approve, Some(link), false));
    let Parsed::CommandLine(c) = parse(argv(&["approve", "--key", "/k", link])).unwrap() else { panic!() };
    assert_eq!((c.operand(), c.key_file().unwrap()), (Some(link), Some(PathBuf::from("/k"))), "the operand is read wherever it stands");
    let Parsed::CommandLine(c) = parse(argv(&["approve", "--auto", "--key", "/k", "--dir", "/s"])).unwrap() else { panic!() };
    assert_eq!((c.operand(), c.switch("--auto")), (None, true), "the unattended hand takes no request");
    let Parsed::CommandLine(c) = parse(argv(&["deny", link, "--clause", "2"])).unwrap() else { panic!() };
    assert_eq!((c.command, c.operand(), c.value("--clause")), (Command::Deny, Some(link), Some("2")));
    let Parsed::CommandLine(c) = parse(argv(&["set-policy", "/etc/door/policy.json", "--board", "http://127.0.0.1:8642"])).unwrap() else { panic!() };
    assert_eq!((c.command, c.command.verb(), c.operand()), (Command::SetPolicy, "set-policy", Some("/etc/door/policy.json")), "a verb that holds a hyphen");
    assert_eq!(refusal(&["approve", link, "--auto"]), format!("`--auto` and `{link}` belong to two forms of `approve`: give one"));
    assert_eq!(refusal(&["approve", "--auto", link]), format!("`--auto` and `{link}` belong to two forms of `approve`: give one"));
    assert_eq!(refusal(&["approve", link, "1.0.1.2.0.1.0.2.4"]), format!("`approve` takes one <request>: `{link}` is given, and `1.0.1.2.0.1.0.2.4` is a second"));
    assert_eq!(refusal(&["set-policy", "a.json", "b.json"]), "`set-policy` takes one <file>: `a.json` is given, and `b.json` is a second");
    assert_eq!(refusal(&["deny", ""]), "<request>: an empty value names nothing");
    assert_eq!(refusal(&["deny", link, "--clause", "1", "--clause", "2"]), "`--clause` is given at most once at `deny`");
    assert_eq!(refusal(&["deny", link, "--auto"]), "`--auto` is not a flag of `deny`", "the unattended hand never denies");
    assert_eq!(refusal(&["approve", link, "--clause", "1"]), "`--clause` is not a flag of `approve`");
    assert_eq!(refusal(&["review", link]), format!("unknown argument `{link}`"), "`review` takes no operand, and no flag of its own");
    assert_eq!(refusal(&["health", "word"]), "unknown argument `word`", "a command whose row names no operand takes none");
    assert_eq!(refusal(&["approve", "--autos"]), "unknown argument `--autos`", "a word that opens with a dash is never an operand");
    assert_eq!(refusal(&["set-policy", "-"]), "unknown argument `-`");
    for row in &GRAMMAR {
        assert_eq!(row.operand.is_some(), matches!(row.command, Command::Approve | Command::Deny | Command::SetPolicy), "`{}`", row.command);
        if let Some(name) = row.operand {
            let opening = format!("  {}:", row.command);
            let line = HELP.lines().find(|line| line.starts_with(&opening)).unwrap_or_else(|| panic!("HELP has a flags line for `{}`", row.command));
            assert!(line[opening.len()..].trim_start().starts_with(name), "`{}`'s flags line opens with its operand {name}: {line}", row.command);
        }
    }
}

/// `register`'s row (REG-4.67; REG-4.104): the door identifier once, a
/// value that holds a space as one argument; `--existing-board`, the switch
/// that makes the request the board-carries-on row's; and the backup
/// moment's flags as `keygen --anchors` takes them — a label and a
/// destination for each anchor, four of each at most at a fresh
/// registration's two pairs and two inside `--existing-board`, the node
/// pair's alone — beside `--label` and `--key`, which every command takes.
/// No `--out` names a file: the request is stdout's.
#[test]
fn register_takes_its_door_once_and_a_label_and_a_place_for_each_anchor_its_kind_makes() {
    let door = "realm:9f2a000000000000000000000000000000000000000000000000000000c41d door:1.1.0.1";
    let four = ["register", "--door", door, "--label", "laptop", "--anchor-label", "ra", "--anchor-label", "rb", "--anchor-label", "na", "--anchor-label", "nb", "--anchor-out", "/1", "--anchor-out", "/2", "--anchor-out", "/1", "--anchor-out", "/2", "--paper", "--dir", "/s"];
    let Parsed::CommandLine(c) = parse(argv(&four)).unwrap() else { panic!() };
    assert_eq!((c.command, c.command.verb()), (Command::Register, "register"));
    assert_eq!(c.value("--door"), Some(door), "the identifier is one value, its space within it");
    assert_eq!(c.values("--anchor-label"), ["ra", "rb", "na", "nb"], "in the order org root a, org root b, node a, node b");
    assert_eq!(c.values("--anchor-out"), ["/1", "/2", "/1", "/2"]);
    assert!(c.switch("--paper") && !c.switch("--existing-board"));
    assert_eq!(c.value("--label"), Some("laptop"));
    let Parsed::CommandLine(c) = parse(argv(&["register", "--door", door, "--existing-board", "--anchor-label", "na", "--anchor-label", "nb", "--anchor-out", "/1", "--anchor-out", "/2", "--key", "/k"])).unwrap() else { panic!() };
    assert!(c.switch("--existing-board"), "the board-carries-on row's form");
    assert_eq!(c.key_file().unwrap(), Some(PathBuf::from("/k")), "the device key, named");
    let five = |flag: &'static str| [&["register", "--door", door][..], &[flag, "1", flag, "2", flag, "3", flag, "4", flag, "5"]].concat();
    assert_eq!(refusal(&five("--anchor-label")), "`--anchor-label` is given at most 4 times at `register`");
    assert_eq!(refusal(&five("--anchor-out")), "`--anchor-out` is given at most 4 times at `register`");
    let three = |flag: &'static str| [&["register", "--door", door, "--existing-board"][..], &[flag, "1", flag, "2", flag, "3"]].concat();
    assert_eq!(refusal(&three("--anchor-label")), "`--anchor-label` is given at most 2 times at `register --existing-board`");
    assert_eq!(refusal(&three("--anchor-out")), "`--anchor-out` is given at most 2 times at `register --existing-board`");
    assert_eq!(refusal(&["register", "--door", door, "--door", door]), "`--door` is given at most once at `register`");
    assert_eq!(refusal(&["register", "--door", door, "--out", "/f"]), "unknown argument `--out`", "the request is printed, never written to a named file");
    assert_eq!(refusal(&["register", "--door", door, "--anchors"]), "`--anchors` is not a flag of `register`", "`keygen`'s form opener is `keygen`'s");
    assert_eq!(refusal(&["keygen", "--door", door]), "`--door` is not a flag of `keygen`");
    assert_eq!(refusal(&["keygen", "--anchors", "--existing-board"]), "`--existing-board` is not a flag of `keygen`");
}

/// `hire`'s row (AUTH-5.58): the agent's key record once, a file or `-` as
/// `enroll` takes it, and the account a re-hire replaces once; the custody
/// pair's destinations, two at most, and `--paper`, as `claim` takes them;
/// and the pair's decline, `--anchorless`, apart from both — two arms, never
/// one line. `keygen`'s `--anchor-label` is no flag of it: the pair's boxes
/// are typed.
#[test]
fn hire_takes_its_payload_and_one_arm_the_pair_or_its_decline() {
    let line = ["hire", "--board", "http://127.0.0.1:8642", "--payload", "-", "--replaces", "1.0.1.1.3", "--anchor-out", "/a", "--anchor-out", "/b", "--paper", "--principal", "1"];
    let Parsed::CommandLine(c) = parse(argv(&line)).unwrap() else { panic!() };
    assert_eq!((c.command, c.command.verb()), (Command::Hire, "hire"));
    assert_eq!((c.value("--payload"), c.value("--replaces")), (Some("-"), Some("1.0.1.1.3")));
    assert_eq!(c.values("--anchor-out"), ["/a", "/b"]);
    assert!(c.switch("--paper") && !c.switch("--anchorless"));
    let Parsed::CommandLine(c) = parse(argv(&["hire", "--payload", "/p", "--anchorless"])).unwrap() else { panic!() };
    assert!(c.switch("--anchorless"), "the decline's arm");
    assert_eq!(refusal(&["hire", "--payload", "/p", "--anchorless", "--anchor-out", "/a"]), "`--anchorless` and `--anchor-out` belong to two forms of `hire`: give one");
    assert_eq!(refusal(&["hire", "--payload", "/p", "--anchorless", "--paper"]), "`--anchorless` and `--paper` belong to two forms of `hire`: give one");
    assert_eq!(refusal(&["hire", "--payload", "/p", "--anchor-out", "/a", "--anchor-out", "/b", "--anchor-out", "/c"]), "`--anchor-out` is given at most 2 times at `hire`");
    assert_eq!(refusal(&["hire", "--payload", "/a", "--payload", "/b"]), "`--payload` is given at most once at `hire`");
    assert_eq!(refusal(&["hire", "--anchor-label", "x"]), "`--anchor-label` is not a flag of `hire`");
    assert_eq!(refusal(&["hire", "--yes"]), "`--yes` is not a flag of `hire`", "the choice's answer is typed, never a flag");
    assert_eq!(refusal(&["enroll", "--anchorless"]), "`--anchorless` is not a flag of `enroll`");
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
    assert_eq!(refusal(&["retire", "--yes"]), "`--yes` is not a flag of `retire`", "`--yes` is `share`'s alone: a retirement's answer is typed");
    assert_eq!(refusal(&["retire", "--frob"]), "unknown argument `--frob`", "a flag of no command's is unknown");
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
                Form::AtMostWithin(a, b, _) => (vec![a, b], Some(a)),
                Form::NoOperand(a) => {
                    assert!(row.operand.is_some(), "{form:?} names the operand of `{}`, a command that takes one", row.command);
                    (vec![a], None)
                }
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

/// THE DEV GRAMMAR over the same machinery: `seed` parses with its six
/// flags and the four settings, each default where absent; `--json` and
/// `--label`, the `skep` command's, are unknown here; a count that is no
/// count, an unknown verb and a missing value are refused; `--help` is the
/// help; and every flag `seed` takes is one the dev help documents.
#[test]
fn the_dev_grammar_parses_seed_with_its_flags_and_their_defaults() {
    use dev::{DevCommand, DEFAULT_DOCUMENTS, DEFAULT_DRAFTS, DEFAULT_PIN, DEFAULT_VERSIONS};

    let Parsed::CommandLine(c) = dev::parse(argv(&[
        "seed",
        "--board",
        "http://127.0.0.1:8642",
        "--repo",
        "/r",
        "--dir",
        "/s",
        "--principal",
        "7",
        "--documents",
        "12",
        "--versions",
        "4",
        "--drafts",
        "3",
        "--pin",
        "abc1234",
        "--from",
        "ux",
    ]))
    .unwrap() else {
        panic!()
    };
    assert_eq!(c.command, DevCommand::Seed);
    assert_eq!(c.origin().unwrap().as_str(), "http://127.0.0.1:8642");
    assert_eq!(c.repo().unwrap().to_str(), Some("/r"));
    assert_eq!(c.store_dir().unwrap().to_str(), Some("/s"));
    assert_eq!(c.principal().unwrap(), Some(7));
    assert_eq!((c.documents().unwrap(), c.versions().unwrap(), c.drafts().unwrap()), (12, 4, 3));
    assert_eq!((c.pin(), c.from()), ("abc1234", Some("ux")));
    let Parsed::CommandLine(c) = dev::parse(argv(&["seed", "--repo", "/r"])).unwrap() else {
        panic!()
    };
    assert_eq!(
        (c.documents().unwrap(), c.versions().unwrap(), c.drafts().unwrap()),
        (DEFAULT_DOCUMENTS, DEFAULT_VERSIONS, DEFAULT_DRAFTS)
    );
    assert_eq!(
        (c.pin(), c.from(), c.principal().unwrap(), c.key_file().unwrap()),
        (DEFAULT_PIN, None, None, None)
    );
    assert!(c.origin().is_err(), "the board is required");
    assert!(matches!(dev::parse(argv(&["--help"])).unwrap(), Parsed::Help));
    assert!(matches!(dev::parse(argv(&["seed", "-h"])).unwrap(), Parsed::Help));
    let refused = |a: &[&str]| match dev::parse(argv(a)) {
        Err(Usage(text)) => text,
        Ok(_) => panic!("{a:?} parsed"),
    };
    assert_eq!(refused(&["frob"]), "unknown command `frob`");
    assert_eq!(refused(&["seed", "--json"]), "unknown argument `--json`");
    assert_eq!(refused(&["seed", "--label", "x"]), "unknown argument `--label`");
    assert_eq!(refused(&["seed", "--repo"]), "--repo needs a value");
    assert_eq!(
        refused(&["seed", "--repo", "/a", "--repo", "/b"]),
        "`--repo` is given at most once at `seed`"
    );
    assert_eq!(
        refused(&["claim"]),
        "unknown command `claim`",
        "the skep command's verbs are no verbs here"
    );
    for (flag, bad) in [("--documents", "0"), ("--versions", "x"), ("--drafts", "-1")] {
        let Parsed::CommandLine(c) = dev::parse(argv(&["seed", flag, bad])).unwrap() else {
            panic!()
        };
        let read = match flag {
            "--documents" => c.documents(),
            "--versions" => c.versions(),
            _ => c.drafts(),
        };
        assert_eq!(read.unwrap_err().0, format!("{flag}: '{bad}' is not a count of at least one"));
    }
    let documented = |flag: &str| {
        dev::HELP.match_indices(flag).any(|(i, _)| {
            !dev::HELP[i + flag.len()..]
                .starts_with(|c: char| c.is_ascii_alphanumeric() || c == '-')
        })
    };
    for flag in [
        "--repo",
        "--pin",
        "--from",
        "--documents",
        "--versions",
        "--drafts",
        "--board",
        "--dir",
        "--key",
        "--principal",
    ] {
        assert!(documented(flag), "`{flag}` is documented in the dev help");
        let Parsed::CommandLine(_) = dev::parse(argv(&["seed", flag, "x"])).unwrap() else {
            panic!("{flag} parses at seed")
        };
    }
    assert!(
        dev::HELP.starts_with("usage: skep-dev <command> [flags]\n")
            && dev::HELP.contains("\n  seed "),
        "{}",
        dev::HELP
    );
}

/// A FLAG's VALUE NAMES SOMETHING: every flag that takes one, at every
/// command of both grammars, refuses an empty value — what a wrapper's
/// unset variable leaves — and a value that is itself one of the grammar's
/// flags, any command's or `--help`, the next flag read where a value was
/// forgotten; `-`, the value that names stdin, stands, as does a value
/// that merely opens with a dash.
#[test]
fn a_flag_given_an_empty_value_or_another_flag_is_refused() {
    let mut checked = 0;
    for row in &GRAMMAR {
        for &flag in row.once.iter().chain(row.repeated).chain(&GLOBAL) {
            assert_eq!(
                refusal(&[row.command.verb(), flag, ""]),
                format!("{flag}: an empty value names nothing"),
                "at `{}`",
                row.command
            );
            checked += 1;
        }
    }
    for row in &dev::GRAMMAR {
        for &flag in row.once.iter().chain(row.repeated).chain(&dev::GLOBAL) {
            match dev::parse(argv(&[row.command.verb(), flag, ""])) {
                Err(Usage(text)) => assert_eq!(
                    text,
                    format!("{flag}: an empty value names nothing"),
                    "at `{}`",
                    row.command
                ),
                Ok(_) => panic!("`{} {flag} ''` parsed", row.command),
            }
            checked += 1;
        }
    }
    assert!(checked > 60, "every value-taking flag of both grammars is read: {checked}");
    assert_eq!(
        refusal(&["claim", "--anchor-out", "/a", "--anchor-out", "--paper"]),
        "--anchor-out needs a value, and `--paper` is a flag"
    );
    assert_eq!(
        refusal(&["keygen", "--label", "--help"]),
        "--label needs a value, and `--help` is a flag"
    );
    assert_eq!(
        refusal(&["bind", "--account", "--fingerprint"]),
        "--account needs a value, and `--fingerprint` is a flag",
        "another command's flag is a flag too"
    );
    assert_eq!(
        refusal(&["verify", "--dir", "--json"]),
        "--dir needs a value, and `--json` is a flag"
    );
    match dev::parse(argv(&["serve", "--secret", "--own"])) {
        Err(Usage(text)) => assert_eq!(text, "--secret needs a value, and `--own` is a flag"),
        Ok(parsed) => panic!("parsed: {parsed:?}"),
    }
    for line in [
        &["session", "--close", "-"][..],
        &["claim", "--hosted", "-"],
        &["verify", "--payload", "-"],
        &["keygen", "--label", "-x"],
    ] {
        assert!(parse(argv(line)).is_ok(), "{line:?} parses");
    }
}

/// The README's settings, as `--dir`, `--key` and the rest are tabled
/// there: the table's lines between `### <program>` and the next heading,
/// each row's cells trimmed — its first cell's flag where it names one.
fn readme_settings(program: &str) -> Vec<(Option<String>, Vec<String>)> {
    let readme =
        std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("README.md"))
            .expect("the crate's README");
    let section =
        readme.split("\n## Settings\n").nth(1).expect("the README has a Settings section");
    let table = section
        .split(&format!("\n### `{program}`\n"))
        .nth(1)
        .unwrap_or_else(|| panic!("Settings tables `{program}`"));
    let table = table.split("\n### ").next().unwrap_or(table);
    table
        .lines()
        .filter(|l| l.starts_with("| ") && !l.starts_with("| setting"))
        .map(|l| {
            let cells: Vec<String> =
                l.trim_matches('|').split(" | ").map(|c| c.trim().to_string()).collect();
            let flag = cells[0]
                .strip_prefix('`')
                .and_then(|c| c.strip_suffix('`'))
                .filter(|f| f.starts_with("--"))
                .map(str::to_string);
            (flag, cells)
        })
        .collect()
}

/// THE SETTINGS TABLE IS THE GRAMMARS': every flag the README tables for a
/// program is one its grammar takes, every setting the grammar reads is a
/// row — `skep`'s four and `--json`, every flag of `skep-dev`'s — and every
/// default the table states for a flag is its constant's.
#[test]
fn the_readmes_settings_table_is_the_grammars() {
    let dev_takes = |flag: &str| {
        dev::GLOBAL.contains(&flag)
            || dev::GRAMMAR.iter().any(|r| {
                r.once.contains(&flag) || r.repeated.contains(&flag) || r.switches.contains(&flag)
            })
    };
    let skep = readme_settings("skep");
    let dev_rows = readme_settings("skep-dev");
    for (flag, _) in &skep {
        if let Some(flag) = flag {
            assert!(
                SKEP.names_flag(flag),
                "the README tables `{flag}` for skep, a flag its grammar does not take"
            );
        }
    }
    for (flag, _) in &dev_rows {
        if let Some(flag) = flag {
            assert!(
                dev_takes(flag),
                "the README tables `{flag}` for skep-dev, a flag its grammar does not take"
            );
        }
    }
    let row = |rows: &[(Option<String>, Vec<String>)], flag: &str| -> Vec<String> {
        rows.iter()
            .find(|(f, _)| f.as_deref() == Some(flag))
            .map(|(_, cells)| cells.clone())
            .unwrap_or_else(|| panic!("the README tables `{flag}`"))
    };
    for flag in ["--board", "--dir", "--key", "--principal", "--json"] {
        row(&skep, flag);
    }
    for flag in dev::GLOBAL.iter().copied().chain(
        dev::GRAMMAR
            .iter()
            .flat_map(|r| r.once.iter().chain(r.repeated).chain(r.switches).copied()),
    ) {
        row(&dev_rows, flag);
    }
    let default = |rows: &[(Option<String>, Vec<String>)], flag: &str| row(rows, flag)[2].clone();
    assert!(
        default(&skep, "--principal").contains(&format!("at `claim`, `{CLAIM_PRINCIPAL}`")),
        "{:?}",
        default(&skep, "--principal")
    );
    for (flag, figure) in [
        ("--pin", format!("`{}`", dev::DEFAULT_PIN)),
        ("--documents", format!("`{}`", dev::DEFAULT_DOCUMENTS)),
        ("--versions", format!("`{}`", dev::DEFAULT_VERSIONS)),
        ("--drafts", format!("`{}`", dev::DEFAULT_DRAFTS)),
        ("--listen", format!("`{}`", dev::DEFAULT_LISTEN)),
        ("--port", format!("`{}`", dev::DEFAULT_NODE_PORT)),
        ("--principal", format!("at `serve`, `{}`", dev::DEFAULT_PRINCIPAL)),
    ] {
        assert!(
            default(&dev_rows, flag).contains(&figure),
            "the README's `{flag}` default is {figure}: {:?}",
            default(&dev_rows, flag)
        );
    }
    assert!(
        row(&dev_rows, "--secret")[3].contains(&format!("`{}`", dev::SECRET_ALPHABET)),
        "the README names the secret's alphabet"
    );
    assert!(
        row(&dev_rows, "--repo")[1].contains(&format!("`{}`", dev::CORPUS_VARIABLE)),
        "the README names --repo's variable"
    );
}

/// EVERY DEFAULT A HELP STATES IS ITS CONSTANT'S: each figure the two helps
/// print, read with their line breaks collapsed, is the constant the
/// readers answer with — a default moved in one place and not the other
/// fails here.
#[test]
fn every_default_the_helps_state_is_its_constant() {
    let collapsed = |text: &str| text.split_whitespace().collect::<Vec<_>>().join(" ");
    let (help, dev_help) = (collapsed(HELP), collapsed(dev::HELP));
    assert!(
        help.contains(&format!("at claim, the new account's id, {CLAIM_PRINCIPAL} where omitted")),
        "{help}"
    );
    for figure in [
        format!("(default {})", dev::DEFAULT_PIN),
        format!("(default {}, the 10^3 tier", dev::DEFAULT_DOCUMENTS),
        format!("(default {})", dev::DEFAULT_VERSIONS),
        format!("(default {}; at least one)", dev::DEFAULT_DRAFTS),
        format!("(default {})", dev::DEFAULT_LISTEN),
        format!("(default {}; 0 picks a free port", dev::DEFAULT_NODE_PORT),
        format!("at serve, {} where omitted", dev::DEFAULT_PRINCIPAL),
        format!("one or more of {}", dev::SECRET_ALPHABET),
        format!("(env {})", dev::CORPUS_VARIABLE),
    ] {
        assert!(dev_help.contains(&figure), "the dev help states `{figure}`: {dev_help}");
    }
}

/// THE SECRET's ALPHABET: `serve --secret` takes one or more of RFC 3986's
/// unreserved characters — what the page's URL query and its header both
/// carry unchanged — and refuses anything else, a space, a `+`, an `&` or a
/// letter past ASCII, naming the alphabet and never the value; and a port
/// the page is pointed at is never `0`, refused saying why.
#[test]
fn a_secret_is_of_the_url_safe_alphabet_and_a_listen_port_is_one_a_page_names() {
    let secret = |value: &str| {
        let Parsed::CommandLine(c) = dev::parse(argv(&["serve", "--secret", value])).unwrap()
        else {
            panic!()
        };
        c.secret().map(|s| s.map(str::to_string))
    };
    assert_eq!(secret("Ab-9._~").unwrap(), Some("Ab-9._~".to_string()));
    for bad in ["a b", "a+b", "a&b", "a%20b", "é", " ab"] {
        let refused = secret(bad).unwrap_err().0;
        assert!(
            refused.starts_with(&format!(
                "--secret: a secret is one or more of {}",
                dev::SECRET_ALPHABET
            )),
            "`{bad}`: {refused}"
        );
        assert!(!refused.contains(bad.trim()), "the value is never echoed: {refused}");
    }
    let Parsed::CommandLine(c) = dev::parse(argv(&["serve"])).unwrap() else { panic!() };
    assert_eq!(c.secret().unwrap(), None, "absent, the provider generates one");
    let Parsed::CommandLine(c) = dev::parse(argv(&["serve", "--listen", "0"])).unwrap() else {
        panic!()
    };
    assert_eq!(
        c.listen().unwrap_err().0,
        "--listen: '0' is not a port the page can be pointed at: name one (1-65535)"
    );
}

/// Checks that `--unstarted` belongs to `--own` and names its board ahead.
///
/// It is refused without `--own`, read beside it and documented in the dev
/// help; under it a `--port` that names no loopback origin — `0`, a port
/// picked only as the node starts, and `80`, the scheme's default — is
/// refused, the board being named before the node starts, while without it
/// `0` stands.
#[test]
fn unstarted_belongs_to_own_and_its_port_names_the_board_ahead() {
    let line = |a: &[&str]| match dev::parse(argv(a)) {
        Ok(Parsed::CommandLine(c)) => c,
        other => panic!("{a:?} parsed as {other:?}"),
    };
    match dev::parse(argv(&["serve", "--unstarted"])) {
        Err(Usage(text)) => assert_eq!(text, "`--unstarted` belongs to `serve --own` and is refused without `--own`"),
        Ok(parsed) => panic!("parsed: {parsed:?}"),
    }
    let unstarted = line(&["serve", "--own", "--unstarted", "--port", "8650"]);
    assert_eq!((unstarted.unstarted(), unstarted.node_port().unwrap()), (true, 8650));
    assert_eq!(line(&["serve", "--own", "--unstarted"]).node_port().unwrap(), dev::DEFAULT_NODE_PORT);
    for port in ["0", "80"] {
        assert_eq!(
            line(&["serve", "--own", "--unstarted", "--port", port]).node_port().unwrap_err().0,
            format!("--port: '{port}' names no origin, and under --unstarted the board is named before the node starts: name a port from 1 to 65535 other than 80")
        );
    }
    let started = line(&["serve", "--own", "--port", "0"]);
    assert_eq!((started.unstarted(), started.node_port().unwrap()), (false, 0), "without --unstarted, 0 picks a free port");
    assert!(dev::HELP.contains("[--unstarted]"), "the dev help documents it");
}

/// THE SEED READS THE BUDGETS' CORPUS: `--pin`'s default and `--repo`'s
/// variable are `skep-search`'s budgets' own `PIN` and `VAR`, read off that
/// suite's source — a pin or a variable moved in one place and not the
/// other fails here.
#[test]
fn the_seeds_pin_and_variable_are_the_budgets() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../skep-search/tests/it/budgets/corpus.rs");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let literal = |name: &str| -> String {
        let prefix = format!("pub const {name}: &str = \"");
        let line = text
            .lines()
            .find(|l| l.starts_with(&prefix))
            .unwrap_or_else(|| panic!("{} defines {name}", path.display()));
        line[prefix.len()..].split('"').next().expect("a string literal").to_string()
    };
    assert_eq!(literal("PIN"), dev::DEFAULT_PIN);
    assert_eq!(literal("VAR"), dev::CORPUS_VARIABLE);
}

/// Checks that the in-process daemon's default port is the daemon's own.
///
/// `serve --own`'s `--port` defaults to `skepd::DEFAULT_PORT`, so the daemon
/// it runs answers where one started by the local record's recipe does.
/// It is held here, since the default build carries no `skepd`: a port moved
/// in the daemon and not here fails here.
#[test]
fn the_own_daemons_default_port_is_the_daemons() {
    assert_eq!(dev::DEFAULT_NODE_PORT, skepd::DEFAULT_PORT);
}

/// THE VERSION LINE IS AN ANSWER, as the help is: `--version`, as the
/// first argument or as a flag of any command, parses to `Parsed::Version`
/// carrying `<program> <crate version> (<commit>)` — `skep`'s line under
/// its grammar, `skep-dev`'s under the dev grammar — the version
/// `CARGO_PKG_VERSION`'s and the commit `SKEP_GIT_SHA`'s at build time,
/// `unknown` where the build set none, as a developer's own build — this
/// suite's, unless the variable is exported for it — does; what follows
/// the flag is unread and what precedes it is judged, as for `--help`; and
/// both helps name the flag.
#[test]
fn version_is_an_answer_for_both_programs_at_both_sites() {
    let line = |program: &str| {
        format!(
            "{program} {} ({})",
            env!("CARGO_PKG_VERSION"),
            option_env!("SKEP_GIT_SHA").unwrap_or("unknown")
        )
    };
    let version = |parsed: Result<Parsed, Usage>, at: &[&str]| match parsed {
        Ok(Parsed::Version(line)) => line,
        other => panic!("{at:?} parsed as {other:?}, not the version line"),
    };
    for at in [
        &["--version"][..],
        &["--version", "--frob"],
        &["health", "--version"],
        &["claim", "--board", "http://127.0.0.1:8642", "--version", "--frob"],
    ] {
        assert_eq!(version(parse(argv(at)), at), line("skep"), "{at:?}");
    }
    for at in [&["--version"][..], &["seed", "--version"], &["serve", "--version", "--frob"]] {
        match dev::parse(argv(at)) {
            Ok(Parsed::Version(l)) => assert_eq!(l, line("skep-dev"), "{at:?}"),
            other => panic!("{at:?} parsed as {other:?}, not the version line"),
        }
    }
    assert!(
        parse(argv(&["--frob", "--version"])).is_err(),
        "what precedes it is judged: an unknown command"
    );
    assert!(
        parse(argv(&["health", "--frob", "--version"])).is_err(),
        "what precedes it is judged: an unknown flag"
    );
    assert!(
        HELP.contains("\n  --version             this program's version")
            && dev::HELP.contains("\n  --version             this program's version"),
        "both helps name the flag"
    );
}
