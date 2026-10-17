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
//! test loads one. So are the figures the binary's constants supply, read
//! through those constants, §3 step 2's variables, read off the binary's
//! own help, §2's line for the journal damage a history read meets, §1's
//! write refused for a cause but room, and §1 step 8's standing clauses.

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
/// inventory's `journal.tail_cut` beside it, and its second arm — a tail
/// holding intact frames, under `failure:` — after it; the beginning's line,
/// after the recovery's landing it qualifies; the open's two warnings, the
/// skipped base's and the runs passed over below the start point after it,
/// under `warning (at open):`; and each line the binary classes that the
/// list once quoted bare — the stray `checkpoint.tmp`'s and the media
/// limits' under `open:`, the first head's and the cell index's landing
/// under `landing:`, the pruner's refused thread under `failure:` — opens
/// with the class word the door spells, read off the door's own type, so a
/// word spelled another way here fails.
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
    // …and the tail cut's second arm, quoted after the first: a cut that
    // may have taken an acknowledged write is the failure it is.
    classed("of its frames intact on disk", Class::Failure);
    assert!(
        at("open: journal tail cut (") < at("of its frames intact on disk"),
        "the tail cut's two arms, the report's own first"
    );
    // The open's warnings, each under the class the binary writes it with:
    // a skipped base, then the corrupt runs passed over below the start point.
    {
        use skep_util::notice::Moment;
        classed("and was SKIPPED —", Class::Warning(Moment::AtOpen));
        classed("and was PASSED OVER —", Class::Warning(Moment::AtOpen));
    }
    assert!(
        at("and was SKIPPED —") < at("and was PASSED OVER —"),
        "the runs passed over follow the skipped bases, as the open says them"
    );
    // The beginning, quoted with the recovery's landing it follows.
    classed("no journal stood in the data directory:", Class::Open);
    assert!(
        at("open: recovered from ") < at("no journal stood in the data directory:"),
        "the beginning follows the landing it qualifies"
    );
    classed("media limits:", Class::Open);
    // The volume's free space, after the media limits' line that names the
    // floor it is read beside (m4).
    classed("the volume's free space at start:", Class::Open);
    assert!(
        at("media limits:") < at("the volume's free space at start:"),
        "the volume's line follows the floor's"
    );
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
    // Exit 2 is a command line the daemon cannot read, which no restart
    // mends: the unit stops on it, failed, rather than looping.
    for line in [
        "UMask=0077",
        "Restart=on-failure",
        "RestartPreventExitStatus=2",
        "KillSignal=SIGTERM",
    ] {
        assert!(unit.lines().any(|l| l.trim() == line), "the unit sets {line}:\n{unit}");
    }
}

/// THE FIGURES THE CONSTANTS SUPPLY, quoted from them (`operations.md` §2.3
/// F1 and F4; §1.1 row 7): §3 step 2's worker count — the default and the
/// minimum, which moves by itself with the permit pools — and the default
/// per-account limit's share and floor where §1 step 2 and §3 step 3's media
/// line name them, each read here through the library's own constants and
/// never a literal, as the binary's help renders them, so a figure that
/// moves fails here rather than leaving the runbook naming the old one.
/// Beside the worker count, what each worker can hold: one frame body at
/// the frame routes' cap, parsed whole at about twenty times its size, the
/// multiple `skep_core::limits::MAX_REQUEST_BODY`'s own card prices.
#[test]
fn runbook_quotes_the_figures_the_constants_supply() {
    use skep_core::limits::MAX_REQUEST_BODY;
    use skepd::{DEFAULT_LIMIT_FLOOR_BYTES, DEFAULT_LIMIT_SHARE, DEFAULT_WORKERS, MIN_WORKERS};

    /// The JSON tree's multiple over the body it is parsed from.
    ///
    /// `MAX_REQUEST_BODY`'s card gives it: "roughly twenty times its size in
    /// transient heap".
    const TREE_PER_BODY_BYTE: usize = 20;
    let mib = |bytes: usize| bytes / (1024 * 1024);
    let text = collapsed(&runbook_md());
    for figure in [
        format!("request threads. Default {DEFAULT_WORKERS}, minimum {MIN_WORKERS}."),
        format!(
            "Each worker can hold one request body of up to {} MiB on `/op` and `/op-at`",
            mib(MAX_REQUEST_BODY)
        ),
        format!(
            "about {} MiB of transient memory per worker reading a body at the cap",
            mib(TREE_PER_BODY_BYTE * MAX_REQUEST_BODY)
        ),
        format!(
            "the default per-account limit, one part in {DEFAULT_LIMIT_SHARE} of the volume's \
             capacity"
        ),
        format!(
            "(one part in {DEFAULT_LIMIT_SHARE} of the volume's capacity of {{bytes}} bytes, \
             never below {DEFAULT_LIMIT_FLOOR_BYTES} bytes)"
        ),
    ] {
        assert!(text.contains(&figure), "RUNBOOK.md quotes the constants' figure {figure:?}");
    }
}

/// Checks that §3 step 2 names every variable the binary reads.
///
/// The names are the ones the binary's own `--help` prints, which the
/// binary's unit suite holds to the parse's list; and the step says that a
/// `SKEPD_` name the daemon does not read is refused at start, so a reader
/// of the runbook learns that a misspelled variable never passes as unset.
#[test]
fn runbook_names_every_variable_the_daemon_reads_and_refuses_any_other() {
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_skepd"))
        .arg("--help")
        .env_clear()
        .output()
        .expect("run --help");
    assert!(out.status.success(), "--help exits 0: {out:?}");
    let help = String::from_utf8(out.stdout).expect("UTF-8 help");
    let step = passage("\n## 3. Start", "2. **Run it**", &["\n3. **Read the open's report**"]);
    let mut named = 0;
    for (at, _) in help.match_indices("SKEPD_") {
        let rest = &help[at..];
        let end = rest.find(|c: char| !(c.is_ascii_uppercase() || c == '_')).unwrap_or(rest.len());
        let name = &rest[..end];
        if name.len() > "SKEPD_".len() {
            assert!(step.contains(name), "RUNBOOK §3 step 2 names {name}:\n{step}");
            named += 1;
        }
    }
    assert!(named > 0, "the help names its variables: {help}");
    assert!(
        collapsed(&step).contains("A `SKEPD_` variable the daemon does not read is refused at start"),
        "…and the refusal of any other: {step}"
    );
}

/// §2 RESTORE's LEAD AND §1 STEP 8 — THE JOURNAL DAMAGE A HISTORY READ MEETS
/// (RUNBOOK §2): the lead quotes the line the daemon says once, under
/// `failure:`, with its wait for a checkpoint above damage at rest, and the
/// steps it asks before a restart; where no copy holds the file whole, it
/// keeps the daemon serving until a checkpoint lands above the damage, which
/// an open from it passes over (`history.rs` holds the binary to it), and
/// says where an I/O failure is not passed over; and the standing line's
/// list carries its clause by the damage's site, and the kernel's poison by
/// the position its halt line named.
#[test]
fn runbook_says_the_journal_damage_a_history_read_meets_and_its_standing_clause() {
    let lead = passage(
        "\n## 2. Restore",
        "**A history read can find the damage first**",
        &["**Read the refusal before you restore.**"],
    );
    let (line, after) = fenced(&lead);
    let opening = format!("{}: history: journal corrupt at rest;", Class::Failure);
    assert!(
        line.trim_start().starts_with(&opening),
        "the lead quotes the damage's line under its class word: {line}"
    );
    assert!(
        line.contains(
            "where no copy holds that file whole, keep the board serving and do not restart it \
             until the next checkpoint lands"
        ),
        "the quoted line carries the wait for a checkpoint: {line}"
    );
    let after = collapsed(after);
    assert!(after.contains("before a restart, not after it"), "{after}");
    for fact in [
        "Keep the daemon serving until the next checkpoint lands",
        "an open from it passes the damage over, loses nothing",
        "An I/O failure is never passed over in a file the open reads",
    ] {
        assert!(after.contains(fact), "the lead says {fact:?}: {after}");
    }
    let list = passage("\n## 1. The full volume", "8. **Watch between the lines.**", &["\n## 2."]);
    let damage = "a history read found the journal unreadable at position {position}";
    assert!(
        list.lines().any(|l| l.trim() == damage),
        "the standing line's list carries the damage's clause, by its site: {list}"
    );
    assert!(
        list.lines().any(|l| l.trim() == "the kernel is poisoned since position {position}"),
        "the standing line's list carries the poison's clause, by its position: {list}"
    );
}

/// Checks that §1 step 8 says what ends each standing clause.
///
/// The step's fence is the binary's own standing line, every clause in its
/// order (`server/tests.rs` holds the two together); beneath it, the step
/// says what ends each, and that the two states costing every write its
/// testimony while they stand — `commits.log`'s stop and the feed walk's
/// death — are ended by a restart soon.
#[test]
fn runbook_says_what_ends_each_standing_clause() {
    let step = passage(
        "\n## 1. The full volume",
        "8. **Watch between the lines.**",
        &["\n## 2."],
    );
    let (_, after) = fenced(&step);
    let after = collapsed(after);
    for fact in [
        "What ends each:",
        "Restart soon where the file is `commits.log`: every write after its stop is held in \
         memory alone",
        "the feed walk's thread: a restart soon",
        "`503 index_failed` until it",
        "`CLAIMED-PERMISSIVE`: a restart with `--no-local-trust`",
    ] {
        assert!(after.contains(fact), "step 8 says {fact:?}: {after}");
    }
}

/// Checks that §3 step 6 says a `/health` that hangs waits on the volume.
///
/// The probe's `head_time` is read behind the change feed's lock, which a
/// write holds across the attest store's sync, so a device that stops
/// answering mid-sync holds the probe; the step says so, that no line says
/// it, and that a restart does not help while the device does not answer.
#[test]
fn runbook_says_a_health_probe_that_hangs_waits_on_the_volume() {
    let step = collapsed(&passage(
        "\n## 3. Start",
        "6. **Check from outside**",
        &["\n7. **Claim it, the first time.**"],
    ));
    for fact in [
        "A `/health` that does not answer once the open is done points to the volume",
        "behind the change feed's lock",
        "No line says so",
        "A restart does not help while the device does not answer",
    ] {
        assert!(step.contains(fact), "§3 step 6 says {fact:?}: {step}");
    }
}

/// Checks that §1 says a write refused for a cause but room is unsaid.
///
/// Step 1 says such a write is refused `durability` and said by nothing —
/// `volume.rs` holds the binary to it — and names the quota and the device
/// and where the cause is read; step 5 acts on it.
#[test]
fn runbook_says_a_write_refused_for_a_cause_but_room_is_said_by_nothing() {
    let step = collapsed(&passage(
        "\n## 1. The full volume",
        "1. **Tell the two states apart.**",
        &["2. **Make room first.**"],
    ));
    for fact in [
        "A write can be refused for a cause other than room, and then no line says so",
        "`Disk quota exceeded`",
        "`Input/output error`",
        "`writes.halted` stays `false`",
    ] {
        assert!(step.contains(fact), "§1 step 1 says {fact:?}: {step}");
    }
    let acts = collapsed(&passage(
        "\n## 1. The full volume",
        "5. **Then act on the line you saw.**",
        &["6. **Know what the floor keeps meanwhile.**"],
    ));
    assert!(acts.contains("A write refused `durability` and said by nothing"), "{acts}");
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
