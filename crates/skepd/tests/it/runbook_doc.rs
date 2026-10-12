//! `skep/RUNBOOK.md` is tested where it quotes the binary: the lines of the
//! open's report it lists are read at test RUNTIME from the repo root — a
//! changed sentence needs no rebuild — and judged against the words and the
//! class word the binary writes, which the child-process suite (`open.rs`)
//! pins on the stream itself. This pins that the runbook quotes them as
//! written, in the form `wire_doc.rs` pins the wire document.
//!
//! The setup a kept notebook runs under is pinned the same way, read at
//! runtime: §3 step 2's command, §7's synced-folder sentence, and §9's two
//! service units and its Windows question. The units are WORDS here — no
//! test loads one.

use std::path::Path;

use skep_util::notice::Class;

fn runbook_md() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../RUNBOOK.md");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

/// The text between `from` and the first of `until` after it, searched from
/// the first occurrence of `after` (`""` is the top) — the lines KEPT, since
/// a claim here is on the line a quoted sentence stands on, where
/// `wire_doc.rs`'s `prose` collapses them.
fn passage(after: &str, from: &str, until: &[&str]) -> String {
    let text = runbook_md();
    let base = text.find(after).unwrap_or_else(|| panic!("RUNBOOK.md no longer carries {after:?}"));
    let text = &text[base..];
    let start = text.find(from).unwrap_or_else(|| panic!("RUNBOOK.md no longer carries {from:?}"));
    let rest = &text[start + from.len()..];
    let end = until.iter().filter_map(|u| rest.find(u)).min().unwrap_or(rest.len());
    rest[..end].to_string()
}

/// The body of the first fenced block in `text`, its fences' lines dropped,
/// and the text after its closing fence.
fn fenced(text: &str) -> (&str, &str) {
    let open = text.find("```").unwrap_or_else(|| panic!("no fenced block in:\n{text}"));
    let body = &text[open..];
    let body = &body[body.find('\n').expect("the opening fence's line ends") + 1..];
    let close = body.find("```").unwrap_or_else(|| panic!("an unclosed fence in:\n{text}"));
    (&body[..close], &body[close + 3..])
}

/// `text` with every whitespace run collapsed, so a re-wrap of a paragraph
/// moves no pin — `wire_doc.rs`'s `prose`, for a passage already cut.
fn collapsed(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// §9 RUNNING IT AS A SERVICE, the subsection headed `heading`: from it to
/// the next subsection or section.
fn service(heading: &str) -> String {
    passage("\n## 9. Running it as a service", heading, &["\n### ", "\n## "])
}

/// §3 START, STEP 3's LIST — THE OPEN's LINES AS THE BINARY WRITES THEM
/// (`operations.md` §1.1 m3; §4 row 8; CUT 1): the list carries the tail
/// cut's line, `open: journal tail cut (`, after the stray `checkpoint.tmp`'s
/// and before the media limits', where the open says it, with the
/// inventory's `journal.tail_cut` beside it; and each line the binary
/// classes that the list once quoted bare — the stray `checkpoint.tmp`'s and
/// the media limits' under `open:`, the first head's and the cell index's
/// landing under `landing:`, the pruner's refused thread under `failure:` —
/// opens with the class word the door spells, read off the door's own type,
/// so a word spelled another way here fails.
#[test]
fn runbook_lists_the_tail_cut_and_classes_the_opens_lines() {
    let list = passage(
        "\n## 3. Start",
        "the daemon writes them:",
        &["\n4. **Read the one line on stdout**"],
    );
    let at = |phrase: &str| {
        list.find(phrase).unwrap_or_else(|| panic!("step 3's list quotes {phrase:?}:\n{list}"))
    };
    assert!(
        at("checkpoint.tmp found (") < at("open: journal tail cut ("),
        "the tail cut's line follows the stray `checkpoint.tmp`'s"
    );
    assert!(
        at("open: journal tail cut (") < at("media limits:"),
        "the tail cut's line precedes the media limits'"
    );
    assert!(
        list.contains("`journal.tail_cut`"),
        "the tail cut's item names the inventory's figure"
    );
    let classed = |phrase: &str, class: Class| {
        let line = list
            .lines()
            .find(|l| l.contains(phrase))
            .unwrap_or_else(|| panic!("step 3's list quotes {phrase:?}:\n{list}"));
        assert!(
            line.trim_start().starts_with(&format!("{class}: ")),
            "the quoted line opens with `{class}: `, the class the binary writes it under: {line:?}"
        );
    };
    classed("checkpoint.tmp found (", Class::Open);
    classed("journal tail cut (", Class::Open);
    classed("media limits:", Class::Open);
    classed("H.1 written at open", Class::Landing);
    classed("pruner: the OS refused its thread (", Class::Failure);
    classed("cell index rebuilt at open:", Class::Landing);
}

/// §3 START, STEP 3's LEAD — EVERY LINE OF THE OPEN CARRIES A CLASS WORD: the
/// lead names each class the open's lines are written under, read off the
/// door's own type as the list's pin reads them, and no longer says that a
/// few of the open's lines carry none, which stopped being true once the
/// last of them took its class.
#[test]
fn runbook_says_every_line_of_the_open_carries_a_class_word() {
    use skep_util::notice::Moment;

    let lead = collapsed(&passage(
        "\n## 3. Start",
        "3. **Read the open's report**",
        &["the daemon writes them:"],
    ));
    for class in [
        Class::Open,
        Class::Warning(Moment::AtOpen),
        Class::Warning(Moment::AtStart),
        Class::Failure,
        Class::Landing,
    ] {
        assert!(lead.contains(&format!("`{class}:`")), "step 3's lead names `{class}:`: {lead}");
    }
    assert!(
        !lead.contains("carry none"),
        "step 3's lead no longer says some of the open's lines carry no class word: {lead}"
    );
}

/// §3 START's BUILD NOTE — THE `client` FEATURE's BULLET says what the page
/// at `GET /` is: the guest reader (`docs/wire.md` §The other endpoints),
/// read-only — and no longer a page that makes keys and opens signed
/// sessions, which `clients/board.html` never did.
#[test]
fn runbook_says_the_client_feature_serves_the_guest_reader() {
    let bullet = passage("\n## 3. Start", "- `client`, off by default:", &["\n   - `test-hooks`"]);
    assert!(
        bullet.contains("guest reader"),
        "the `client` bullet names the guest reader: {bullet}"
    );
    for stale in ["opens signed sessions", "makes keys"] {
        assert!(!bullet.contains(stale), "the `client` bullet no longer says {stale:?}: {bullet}");
    }
}

/// §3 START, STEP 2 — A KEPT NOTEBOOK STARTS CLOSED (the local-board
/// record's decisions 1 and 2, RULED): the command passes the loopback
/// origin a signed session binds to (AUTH-4.7: configure what the board is
/// actually reachable at) and turns local trust off, the daemon's own
/// Phase A default (AUTH-1.45) left as it is; and the paragraph beneath
/// names the notebook's place in each platform's data directory.
#[test]
fn runbook_starts_a_kept_notebook_with_its_origin_and_local_trust_off() {
    let step = passage("\n## 3. Start", "2. **Run it**", &["\n3. **Read the open's report**"]);
    let (command, beneath) = fenced(&step);
    for flag in ["--origin http://127.0.0.1:8642", "--no-local-trust"] {
        assert!(command.contains(flag), "step 2's command passes {flag}:\n{command}");
    }
    let beneath = collapsed(beneath);
    for place in [
        "`~/Library/Application Support/skep/board/`",
        "`$XDG_DATA_HOME/skep/board/`",
        "`%LOCALAPPDATA%\\skep\\board\\`",
    ] {
        assert!(beneath.contains(place), "the paragraph beneath names {place}: {beneath}");
    }
}

/// §7 BACK UP, STEP 1 — NOTHING OF THE BOARD UNDER A SYNCED FOLDER (the
/// local-board record's decision 7, RULED): the step names the key store
/// and the anchor files beside the data directory, since a synced journal
/// is two daemons on one journal with no lock between them, and a synced
/// key store a copied device key.
#[test]
fn runbook_keeps_the_directory_the_keys_and_the_anchors_out_of_synced_folders() {
    let step = collapsed(&passage(
        "\n## 7. Back up",
        "1. **Take one moment's copy",
        &["\n2. **Prove the copy"],
    ));
    for named in ["synced folder", "the data directory", "the key store", "anchor files"] {
        assert!(step.contains(named), "Back up's first step names {named:?}: {step}");
    }
}

/// §9 RUNNING IT AS A SERVICE — THE TWO UNITS (the local-board record's §5.1
/// and §5.2, pasted whole; decisions 2 and 3, RULED): each runs the daemon
/// as the person with the origin passed and local trust off, under a closed
/// umask. The plist's arguments are read in order off its
/// `ProgramArguments` array, where each flag and its value are strings of
/// their own; the systemd unit's off its `ExecStart` line, and its
/// settings as the lines they are.
#[test]
fn runbook_carries_a_launchd_agent_and_a_systemd_user_unit_closed() {
    let agent = service("### 9.1 macOS");
    let (plist, _) = fenced(&agent);
    let array = plist
        .split("<key>ProgramArguments</key>")
        .nth(1)
        .and_then(|rest| rest.split("</array>").next())
        .unwrap_or_else(|| panic!("the plist carries its ProgramArguments array:\n{plist}"));
    let args: Vec<&str> = array
        .split("<string>")
        .skip(1)
        .map(|s| s.split("</string>").next().expect("a string closes"))
        .collect();
    let args = args.join(" ");
    for arg in [
        "--data-dir /Users/USERNAME/Library/Application Support/skep/board",
        "--origin http://127.0.0.1:8642",
        "--no-local-trust",
    ] {
        assert!(args.contains(arg), "the agent passes {arg}: {args}");
    }
    assert!(plist.contains("<string>io.skep.skepd</string>"), "the agent's label:\n{plist}");
    let umask = plist
        .lines()
        .find(|l| l.contains("<key>Umask</key>"))
        .unwrap_or_else(|| panic!("the agent sets a umask:\n{plist}"));
    assert!(umask.contains("<integer>63</integer>"), "the agent's umask is 0o077, decimal 63: {umask}");

    let linux = service("### 9.2 Linux");
    let (unit, _) = fenced(&linux);
    let exec = unit
        .lines()
        .find(|l| l.starts_with("ExecStart="))
        .unwrap_or_else(|| panic!("the unit carries its ExecStart line:\n{unit}"));
    for arg in ["--data-dir %h/.local/share/skep/board", "--origin http://127.0.0.1:8642", "--no-local-trust"] {
        assert!(exec.contains(arg), "the unit's ExecStart passes {arg}: {exec}");
    }
    for line in ["UMask=0077", "Restart=on-failure", "KillSignal=SIGTERM"] {
        assert!(unit.lines().any(|l| l.trim() == line), "the unit sets {line}:\n{unit}");
    }
}

/// §9.3 WINDOWS — A QUESTION, NO COMMAND (the runbook states only what this
/// build does; the local-board record's §5.3): the daemon does not build
/// for Windows, so the subsection names the platform and what settles it,
/// and gives no unit, no scheduled task and no fenced command.
#[test]
fn runbook_gives_windows_no_command() {
    let windows = service("### 9.3 Windows");
    assert!(windows.contains("Windows"), "§9.3 names the platform: {windows}");
    assert!(!windows.contains("schtasks"), "§9.3 gives no scheduled task: {windows}");
    assert!(!windows.contains("```"), "§9.3 gives no fenced command: {windows}");
}
