use std::path::PathBuf;

use super::*;

/// A scratch directory, removed with the test.
struct Scratch(PathBuf);

impl Scratch {
    /// Returns a fresh scratch directory named for `tag` and this process.
    fn new(tag: &str) -> Scratch {
        let dir = env::temp_dir().join(format!("skep-mcp-main-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("a scratch directory");
        Scratch(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// The T4 check refuses each T4 clause, and no depth or magnitude.
///
/// A leading or trailing zero, adjacent zeros, and a fourth zero component
/// all refuse; depth and magnitude do not.
#[test]
fn the_t4_check_refuses_each_clause_but_no_depth_or_magnitude() {
    for good in ["1", "1.1", "1.0.2", "1.0.1.0.1", "1.0.1.0.1.0.1.1", "1.0.2.0.3.0.3.6.1", "10.20.30"] {
        assert!(is_t4_address(good), "'{good}' is T4-valid");
    }
    for bad in ["", "0", "0.1", "1.0", "1..2", "1.a", " 1", "1.0.0.1", "1.0.1.0.1.0.1.0.2", "1.-2"] {
        assert!(!is_t4_address(bad), "'{bad}' is not T4-valid");
    }
}

/// The T4 check is skep-address's validator read off the digits.
///
/// It is a law, so every string of a family is visited, not a chosen few:
/// each dotted decimal of one to nine components drawn from `0`, `00`, `1`
/// and `10`. Nine components are the fewest in which a fourth zero breaks no
/// other clause; `00` is a zero by its digits, `10` a nonzero ending in one.
#[test]
fn the_t4_check_agrees_with_skep_address_on_every_short_dotted_decimal() {
    use skep_address::{is_t4_valid, Nat, Tumbler};
    let alphabet: [(&str, u32); 4] = [("0", 0), ("00", 0), ("1", 1), ("10", 10)];
    let (mut visited, mut disagreements) = (0usize, Vec::new());
    for depth in 1..=9u32 {
        for mut n in 0..4usize.pow(depth) {
            let (mut digits, mut comps) = (Vec::new(), Vec::new());
            for _ in 0..depth {
                let (text, value) = alphabet[n % 4];
                digits.push(text);
                comps.push(Nat::from(value));
                n /= 4;
            }
            let s = digits.join(".");
            let valid = is_t4_valid(&Tumbler::new(comps).expect("a nonempty tumbler"));
            if is_t4_address(&s) != valid {
                disagreements.push(s);
            }
            visited += 1;
        }
    }
    assert_eq!(visited, 349_524, "the family visited whole");
    assert!(disagreements.is_empty(), "{} strings judged unlike is_t4_valid, first: {:?}", disagreements.len(), &disagreements[..disagreements.len().min(5)]);
}

/// The commons is the document every link type skep-client names sits under.
///
/// `COMMONS_DOCUMENT` is the one value `SKEP_COMMONS` takes, and the format
/// fixes it: each type address skep-client signs and reads — the credential
/// kinds, the grant, the replacement — is an element of its subspace 3.
#[test]
fn the_commons_is_the_document_every_link_type_skep_client_names_sits_under() {
    use skep_client::board::{frames, T_CLAIM, T_ENROLL, T_RETIRE};
    let subspace = format!("{COMMONS_DOCUMENT}.0.3.");
    for ty in [T_ENROLL, T_RETIRE, T_CLAIM, frames::T_GRANT, frames::T_REPLACES] {
        assert!(ty.starts_with(&subspace), "{ty} is an element of {subspace}*");
    }
    assert!(is_t4_address(COMMONS_DOCUMENT), "the commons passes the T4 check it is held to after");
}

/// The build is the crate's version and the build's commit, and names both.
///
/// It is `<crate version> (<commit>)`, the version `CARGO_PKG_VERSION`'s
/// and the commit `SKEP_GIT_SHA`'s at build time, `unknown` where the
/// build set none, which this suite's build never does; the version line is
/// `skep-mcp <build>`; and the usage names the flag.
#[test]
fn the_version_line_names_the_binary_its_version_and_the_build_commit() {
    assert_eq!(build(), format!("{} ({})", env!("CARGO_PKG_VERSION"), option_env!("SKEP_GIT_SHA").unwrap_or("unknown")));
    assert_eq!(version_line(), format!("skep-mcp {}", build()));
    assert!(USAGE.contains("\n  --version            this binary's version"), "{USAGE}");
}

/// A setting names its spelling, holds the flag's value, and says its source.
///
/// Its source is its variable while no flag is given, and its flag once one
/// is, the variable then unread.
#[test]
fn a_setting_names_its_spelling_holds_the_flags_value_and_says_its_source() {
    let mut board = Setting::new(BOARD);
    assert_eq!(board.named(), "--board (or SKEP_BOARD)");
    assert_eq!(board.source(), "SKEP_BOARD", "no flag given: the variable");
    assert_eq!(Setting::new(TOOLS_FILE).named(), "--tools-file");
    board.take(&mut [OsString::from("http://127.0.0.1:8642")].into_iter());
    assert_eq!(board.text().as_deref(), Some("http://127.0.0.1:8642"), "the flag's value, its variable unread");
    assert_eq!(board.source(), "--board", "the flag given: the flag");
}

/// The usage names every setting by its spelling, and the figures it states.
///
/// Each flag with its metavariable and each variable at its line's head,
/// `SKEPD_URL` read no longer, the commons by its one address and the store's
/// wait by its bound: a spelling or a figure changed in one place alone fails
/// here.
#[test]
fn the_usage_names_every_setting_by_its_spelling_and_the_figures_it_states() {
    for (flag, var) in SETTINGS {
        assert!(USAGE.contains(&format!("\n  {flag} <")), "the usage names {flag}: {USAGE}");
        if let Some(var) = var {
            assert!(USAGE.contains(&format!("\n  {var} ")), "the usage names {var}: {USAGE}");
        }
    }
    for said in [
        format!("\n  {COMMONS_VARIABLE}    optional: the commons, {COMMONS_DOCUMENT}, alone"),
        format!("\n  {RETIRED_BOARD_VARIABLE}       no longer read"),
        format!("waits up to {} s", STORE_WAIT.as_secs()),
    ] {
        assert!(USAGE.contains(&said), "the usage says {said:?}: {USAGE}");
    }
}

/// The usage states the exit statuses the suites pin.
///
/// 0 at stdin's end or a closed stdout, 1 a refusal before serving or a
/// stop while serving, 2 a usage error, 101 a panic.
#[test]
fn the_usage_states_the_exit_statuses() {
    for status in ["\nexit status:\n    0  stdin's end", "\n    1  a refusal before serving", "\n    2  a usage error", "\n  101  a panic"] {
        assert!(USAGE.contains(status), "the usage states {status:?}: {USAGE}");
    }
}

/// The usage says how the adapter stops, and what a signal leaves.
///
/// Stdin's end is the clean stop; a signal ends the process with its held
/// bursts on disk, save one the shell kept in memory alone, and its session
/// left at the board; retiring the agent's key stops it for good.
#[test]
fn the_usage_says_how_it_stops_and_what_a_signal_leaves() {
    for said in [
        "\nstop:\n  stdin's end closes the session at the board and saves the index,",
        "A signal ends the process at once,",
        "\n  its held bursts already on disk, save one the shell kept in memory\n  alone (answered unwritable), its session left at the board until",
        "\n  retiring its key (skep retire)\n",
    ] {
        assert!(USAGE.contains(said), "the usage says {said:?}: {USAGE}");
    }
    assert!(!USAGE.contains("other_window"), "the usage names no cause the shell does not answer: {USAGE}");
}

/// The usage says where the log is, and that its reader holds nothing up.
#[test]
fn the_usage_says_where_the_log_is() {
    for said in [
        "\nlog:\n  stderr, every line opening 'skep-mcp: ' and the moment it was said,\n  RFC 3339 UTC to the millisecond, the first naming the version and the\n  process id",
        "never holds the adapter up",
    ] {
        assert!(USAGE.contains(said), "the usage says {said:?}: {USAGE}");
    }
}

/// The README's settings table names each setting as the parse spells it.
///
/// Each setting is one row, its first two cells its flag and its variable as
/// `SETTINGS`, `COMMONS_VARIABLE` and `RETIRED_BOARD_VARIABLE` spell them —
/// `—` where it has none — and the table states the figures the code holds:
/// the commons' one address and the store's wait.
#[test]
fn the_readmes_settings_table_is_the_parses() {
    let readme = fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/README.md")).expect("the crate's README");
    let section = readme.split("\n## Settings\n").nth(1).expect("the README has a Settings section");
    let section = section.split("\n## ").next().unwrap_or(section);
    /// Returns a table row's cells, each trimmed.
    fn cells(line: &str) -> Vec<&str> {
        line.trim_matches('|').split('|').map(str::trim).collect()
    }
    let rows: Vec<Vec<&str>> = section.lines().filter(|line| line.starts_with("| ")).map(cells).filter(|row| row[0] != "setting").collect();
    let cell = |spelled: Option<&str>| spelled.map_or_else(|| "—".to_string(), |s| format!("`{s}`"));
    let variables_alone = [COMMONS_VARIABLE, RETIRED_BOARD_VARIABLE].map(|var| (cell(None), cell(Some(var))));
    for (flag, var) in SETTINGS.map(|(flag, var)| (cell(Some(flag)), cell(var))).into_iter().chain(variables_alone) {
        let found = rows.iter().filter(|cells| cells[0] == flag && cells[1].starts_with(var.as_str())).count();
        assert_eq!(found, 1, "the README's settings hold one row of {flag} and {var}: {rows:?}");
    }
    for figure in [format!("`{COMMONS_DOCUMENT}`"), format!("up to {} s", STORE_WAIT.as_secs())] {
        assert!(section.contains(&figure), "the README's settings state {figure}");
    }
}

/// A store held by one adapter process is refused to a second, naming it.
///
/// The first take holds the store and writes this process's pid; a second,
/// whose wait has run out, is refused naming the store and that pid, and the
/// holder it may be — a predecessor still finishing a call or its clean stop,
/// for as long as the fetch's deadline says, or a second adapter, whose store
/// is its own and never a copy of this one; once the first lets go, the store
/// is free again.
#[test]
fn a_store_held_by_one_adapter_is_refused_to_a_second_naming_it() {
    let scratch = Scratch::new("store-hold");
    let named = Setting::new(DIR).named();
    let held = hold_the_store(&scratch.0, &named, Duration::ZERO).expect("a free store is held");
    let refused = hold_the_store(&scratch.0, &named, Duration::ZERO).expect_err("a held store is refused");
    let holder = format!("--dir (or SKEP_KEYSTORE): '{}' is held by another skep-mcp process (pid {})", scratch.0.display(), std::process::id());
    assert!(refused.starts_with(&holder), "{refused}");
    assert!(refused.contains("a predecessor still finishing a call or its clean stop — a fetch runs up to 10.5 minutes"), "the predecessor it may be: {refused}");
    assert!(refused.contains("never a copy of this one"), "the store a second adapter takes: {refused}");
    drop(held);
    hold_the_store(&scratch.0, &named, Duration::ZERO).expect("the store is free once its holder lets go");
}

/// The start's write probe reads the store and the shell's two under it.
///
/// A fresh store is probed alone, the shell's directories not standing; each
/// that stands is probed too; a probe leaves nothing behind.
#[test]
fn the_write_probe_reads_the_store_and_the_shells_two_under_it() {
    let scratch = Scratch::new("store-writes");
    assert_eq!(store_writes(&scratch.0), std::slice::from_ref(&scratch.0), "a fresh store alone");
    let (index, held) = (SearchDir::new(&scratch.0).root().to_path_buf(), scratch.0.join(HELD_DIR));
    fs::create_dir(&index).expect("the index's root");
    fs::create_dir(&held).expect("the held store");
    assert_eq!(store_writes(&scratch.0), [scratch.0.clone(), index, held], "each of the two that stands");
    for dir in store_writes(&scratch.0) {
        writable(&dir).expect("a directory this process made is one it can write");
    }
    assert_eq!(fs::read_dir(&scratch.0).expect("the store").count(), 2, "the probes leave nothing behind");
}
