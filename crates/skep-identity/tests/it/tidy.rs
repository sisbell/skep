//! THE MODULE MAP, CHECKED: `lib.rs`'s "What lives here" — its one bullet
//! per module, and the three facts it states about how this crate's modules
//! name one another: `state`, the fold, is named by no other module;
//! `entry`, the signed-ops frame, names only `framing`; and `write_types`,
//! the write path's classes, names only `shape`.
//!
//! A module names a sibling by a path from the root: every `crate::…` token
//! in a `src/` file's code, and every `super::…` token that climbs to the
//! root — one that stays inside its own module (`payload`'s inline `sealed`
//! naming `payload`) names no sibling — a brace group's members each read
//! joined to it. A path through the root's re-exports (`crate::IdentityState`)
//! hides the module it reaches, so it is refused: code names an item by its
//! home module. Exempt: comments, doc links included; and tests — a
//! `tests.rs` file, or everything from an inline `mod tests {` on, which is
//! its file's last item (`AGENTS.md`), and that is checked. How deep a line
//! sits in inline modules is read off rustfmt's indentation.
//!
//! Beside the map, the one rule of `lib.rs`'s "Traceability" a test can
//! hold: the signed-ops design record is cited as "the design record", never
//! as "the record" or "its record" alone — read over every comment, not the
//! code.
//!
//! And the bound `AGENTS.md` sets on the tests the map exempts: an inline
//! test module is under 200 lines, counted from its `#[cfg(…)]` line to its
//! closing `}`; at 200 or more it lives in its module's own `tests.rs`.
//!
//! And the crate's outer boundary, which `lib.rs`'s first paragraph states and
//! the compiler holds none of: its dependencies are AUTH-2.1's five, read off
//! the manifest; and `src/`'s code reaches no world but its ctx — no
//! filesystem, network, environment, operating system, process, thread or
//! clock, no `std::sync` item but the one `LazyLock`, no print macro.
//!
//! The module-map, citation, test-module and purity checks look for
//! violations a clean tree does not hold, and on such a tree each passes
//! whether its readers can see or not; so each is held, beside it, to the
//! input those readers exist for, where a reader gone blind fails. The bullet
//! and dependency checks need no such control: on a clean tree their reading
//! is live, every module a bullet and every pinned crate a line they must
//! find.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// The module no other module names: the fold, on top.
const ON_TOP: &str = "state";

/// Each leaf, and the only siblings it names.
const LEAVES: &[(&str, &[&str])] = &[("entry", &["framing"]), ("write_types", &["shape"])];

/// The size, in lines, at which `AGENTS.md` moves an inline unit-test module
/// to its module's own `tests.rs` — counted from the module's `#[cfg(…)]` line
/// to its closing `}`, both included.
const TEST_MODULE_BOUND: usize = 200;

#[test]
fn the_fold_sits_on_top_and_entry_and_write_types_are_leaves() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_files(&src, &mut files);
    files.sort();
    let modules: BTreeSet<String> = files.iter().filter_map(|f| module_of(&src, f)).collect();
    let stated = LEAVES.iter().flat_map(|(leaf, names)| std::iter::once(leaf).chain(names.iter()));
    for module in std::iter::once(&ON_TOP).chain(stated) {
        assert!(
            modules.contains(*module),
            "`{module}` is no module of this crate: update this check and lib.rs's map"
        );
    }
    // (from, to) → where `from` first names `to`.
    let mut edges: BTreeMap<(String, String), String> = BTreeMap::new();
    let mut faults = Vec::new();
    for file in &files {
        let Some(module) = module_of(&src, file) else { continue };
        if file.file_name().is_some_and(|name| name == "tests.rs") {
            continue;
        }
        let text = std::fs::read_to_string(file).unwrap();
        let path = file.strip_prefix(&src).unwrap().display().to_string();
        if let Some(line) = after_test_module(&text) {
            faults.push(format!(
                "src/{path}:{line}: a line after the inline `mod tests` — the test module is \
                 its file's last item, and this check reads a file only up to it"
            ));
        }
        let file_depth = module_depth(&src, file);
        let (code, at) = code_of(&text);
        for (start, named) in named_paths(&code) {
            let (line, inline_depth) = at[start];
            let segments: Vec<&str> = named.split("::").filter(|s| !s.is_empty()).collect();
            let from_root = if segments[0] == "crate" {
                &segments[1..]
            } else {
                let climbs = segments.iter().take_while(|s| **s == "super").count();
                if climbs < inline_depth + file_depth {
                    continue; // inside its own module: names no sibling
                }
                &segments[climbs..]
            };
            match from_root.first() {
                Some(&to) if modules.contains(to) => {
                    if to != module {
                        let key = (module.clone(), to.to_string());
                        edges.entry(key).or_insert(format!("src/{path}:{line}"));
                    }
                }
                Some(_) => faults.push(format!(
                    "src/{path}:{line}: `{named}` goes through the root's re-exports — name it \
                     by its home module"
                )),
                None => {}
            }
        }
    }
    assert!(
        !edges.is_empty(),
        "this check read no path between modules at all: the forms it reads have moved"
    );
    for ((from, to), at) in &edges {
        if to == ON_TOP {
            faults.push(format!("{at}: `{from}` names `{ON_TOP}`, the fold — nothing sits above it"));
        }
        if let Some((_, names)) = LEAVES.iter().find(|(leaf, _)| *leaf == from.as_str()) {
            if !names.contains(&to.as_str()) {
                faults.push(format!("{at}: `{from}` names `{to}` — it names only {names:?}"));
            }
        }
    }
    assert!(faults.is_empty(), "lib.rs's module map does not hold:\n{}", faults.join("\n"));
}

/// The check above looks for edges the tree does not have, and every sibling
/// path `src/` spells is a `use crate::<module>::…` line, whose module its
/// first token names before any brace group — so the path reader's other
/// forms, and the detector of a line after the inline test module, are
/// exercised by nothing there, and on a clean tree the check passes whether
/// they work or not. Held here to what each must yield: a brace group at the
/// ROOT, whose members each name their own module, with a member's nested
/// group and an `as` rename; a `super::` chain; and a stray line after an
/// inline `mod tests`. A reader that stopped expanding the root's groups —
/// reading `crate::` alone, which names no module — would pass every edge
/// spelled that way.
#[test]
fn the_module_map_readers_see_the_forms_src_does_not_spell() {
    let code = "use crate::{key::Fingerprint as Fp,\n    state::{IdentityState, HasIdentity}};\n\
                let deep = super::super::state::X;\n";
    let paths: Vec<String> = named_paths(code).into_iter().map(|(_, path)| path).collect();
    assert_eq!(
        paths,
        [
            "crate::key::Fingerprint",
            "crate::state::IdentityState",
            "crate::state::HasIdentity",
            "super::super::state::X",
        ]
    );
    let tail = "fn a() {}\n#[cfg(test)]\nmod tests {\n    fn t() {}\n}\n";
    assert_eq!(after_test_module(tail), None, "the test module is the last item");
    assert_eq!(after_test_module(&format!("{tail}fn stray() {{}}\n")), Some(6), "a stray line");
}

/// `lib.rs`'s "What lives here" says ONE BULLET PER MODULE, NAMED FIRST —
/// the map's own shape, which the check above takes for granted: every
/// module has exactly one bullet there, opening on its name and a colon;
/// every such bullet names a module; and every file under `src/` is a module
/// `lib.rs` declares, since the compiler never reads a file no `mod` names
/// and no build says so. Two modules under one bullet, one module across
/// two, a module added without its bullet and a bullet a removed module
/// leaves behind are each the map drifting from the code, and each fails
/// here.
#[test]
fn every_module_is_declared_and_has_one_bullet_in_the_root_map() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_files(&src, &mut files);
    let modules: BTreeSet<String> = files.iter().filter_map(|f| module_of(&src, f)).collect();
    let root = std::fs::read_to_string(src.join("lib.rs")).unwrap();
    let declared: BTreeSet<&str> = root.lines().filter_map(declared_module).collect();
    let map = root
        .split("//! ## What lives here")
        .nth(1)
        .and_then(|rest| rest.split("//! ## ").next())
        .expect("lib.rs has a \"What lives here\" section");
    let mut bullets: BTreeMap<&str, usize> = BTreeMap::new();
    for line in map.lines() {
        let Some((name, rest)) = line.strip_prefix("//! * `").and_then(|l| l.split_once('`'))
        else {
            continue;
        };
        if rest.starts_with(':') {
            *bullets.entry(name).or_default() += 1;
        }
    }
    let mut faults = Vec::new();
    for module in &modules {
        if !declared.contains(module.as_str()) {
            faults.push(format!(
                "src/ holds `{module}`, which lib.rs declares no `mod` for: the compiler never \
                 reads it"
            ));
        }
        match bullets.get(module.as_str()).copied().unwrap_or(0) {
            1 => {}
            0 => faults.push(format!("`{module}` has no bullet")),
            n => faults.push(format!("`{module}` has {n} bullets")),
        }
    }
    for name in bullets.keys() {
        if !modules.contains(*name) {
            faults.push(format!(
                "a bullet names `{name}`, which is no module of this crate"
            ));
        }
    }
    assert!(
        faults.is_empty(),
        "lib.rs's \"What lives here\" does not hold:\n{}",
        faults.join("\n")
    );
}

/// `AGENTS.md`'s bound on an inline unit-test module: under 200 lines —
/// counted from its `#[cfg(…)]` line to its closing `}` — it may stay at its
/// file's end; at 200 or more it lives in the module's own `tests.rs`,
/// declared `#[cfg(test)] mod tests;`. The module-map check holds an inline
/// module to its file's END; this holds it to its SIZE, so a module grown past
/// the bound is named here rather than met by a reader paging through it.
#[test]
fn every_inline_test_module_is_under_200_lines() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_files(&src, &mut files);
    files.sort();
    let mut faults = Vec::new();
    for file in &files {
        let text = std::fs::read_to_string(file).unwrap();
        if let Some(len) = oversized_test_module(&text) {
            let path = file.strip_prefix(&src).unwrap().display();
            faults.push(format!(
                "src/{path}: an inline test module of {len} lines — at {TEST_MODULE_BOUND} or \
                 more it lives in the module's own `tests.rs`, declared `#[cfg(test)] mod tests;`"
            ));
        }
    }
    assert!(
        faults.is_empty(),
        "AGENTS.md's test-module bound does not hold:\n{}",
        faults.join("\n")
    );
}

/// The check above looks for a module the tree does not hold, so on a clean
/// tree it passes whether its reader counts or not; held here to a module of
/// each length either side of the bound, and to the declaration of a module
/// that lives in its own file, which is no inline module at all. A reader that
/// counted a line short — from the `mod tests {` line, say — or a line long,
/// or took the bound as `>`, misjudges one of the two lengths.
#[test]
fn the_test_module_reader_counts_as_agents_md_counts() {
    let module = |len: usize| {
        let body = "    fn t() {}\n".repeat(len - 3);
        format!("fn a() {{}}\n#[cfg(test)]\nmod tests {{\n{body}}}\n")
    };
    assert_eq!(oversized_test_module(&module(199)), None, "199 lines stay inline");
    assert_eq!(oversized_test_module(&module(200)), Some(200), "200 lines move out");
    assert_eq!(
        oversized_test_module("fn a() {}\n#[cfg(test)]\nmod tests;\n"),
        None,
        "a module declared into its own file"
    );
}

/// The two test-module checks take the module from one reader,
/// [`inline_test_module`]: the size check counts to its close and the
/// last-item check looks past it, so the two cannot part about which line
/// closes the module. Held here at the layout where a reader of each check's
/// own would part from the other — a `}` carrying a trailing comment, which
/// rustfmt keeps: the size check measures that module, and the last-item check
/// finds nothing after its close until a line is there.
#[test]
fn the_test_module_checks_close_the_module_on_one_line() {
    let body = "    fn t() {}\n".repeat(TEST_MODULE_BOUND - 3);
    let module = format!("fn a() {{}}\n#[cfg(test)]\nmod tests {{\n{body}}} // tests\n");
    assert_eq!(oversized_test_module(&module), Some(TEST_MODULE_BOUND), "measured to its close");
    assert_eq!(after_test_module(&module), None, "nothing after its close");
    let stray = format!("{module}fn stray() {{}}\n");
    assert_eq!(after_test_module(&stray), Some(TEST_MODULE_BOUND + 2), "a line after its close");
}

/// `lib.rs`'s "Traceability" cites the signed-ops design record as "the
/// design record" with its section or ruling, and never as "the record" or
/// "its record" alone: in this crate a record is a credential record
/// (AUTH-1.18), so a bare citation beside an entry, a fingerprint and a label
/// reads as a place inside one. Held over every comment under `src/` and
/// `tests/`, each run of comment lines read as one text, so a citation a
/// reflow splits across two lines is read whole: "the record" or "its
/// record", or either's possessive, before a section sign or a ruling's `D`
/// number is a design-record citation missing its "design".
#[test]
fn the_design_record_is_never_cited_as_the_record_alone() {
    let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    rust_files(&crate_dir.join("src"), &mut files);
    rust_files(&crate_dir.join("tests"), &mut files);
    files.sort();
    let mut faults = Vec::new();
    for file in &files {
        let text = std::fs::read_to_string(file).unwrap();
        let path = file.strip_prefix(crate_dir).unwrap().display();
        for (line, prose) in comment_runs(&text) {
            if let Some(cited) = bare_record_citation(&prose) {
                faults.push(format!(
                    "{path}:{line}: \"{cited}\" — cite a design document as a \"design record\""
                ));
            }
        }
    }
    assert!(faults.is_empty(), "lib.rs's \"Traceability\" does not hold:\n{}", faults.join("\n"));
}

/// The check above looks for a violation the tree does not hold, so on a
/// clean tree it passes whether its two readers can see or not; held here to
/// the input they exist for. `comment_runs` joins a run of comment lines into
/// one text, so a bare citation a reflow split across two lines reads whole,
/// and `bare_record_citation` finds it, after "the" or "its", in either
/// capitalization and with the possessive, while passing the design record's
/// full citation, the phrase in quotes, a phrase whose next word cites
/// nothing, and the phrase inside a longer word. The comment marker is built
/// at runtime, so this file's own scan finds no comment in these lines.
#[test]
fn the_citation_readers_find_a_bare_citation() {
    let marker = "/".repeat(3);
    let text = format!("fn a() {{}}\n{marker} per the\n{marker} record §4.2 (C)\nfn b() {{}}\n");
    let runs = comment_runs(&text);
    assert_eq!(runs, [(2, "per the record §4.2 (C)".to_owned())]);
    assert_eq!(bare_record_citation(&runs[0].1), Some("the record §4.2"));
    assert_eq!(bare_record_citation("as The record's D13 rules"), Some("The record's D13"));
    assert_eq!(bare_record_citation("per its record §3 as ruled"), Some("its record §3"));
    for prose in [
        "the design record §4.2",
        "its design record §3",
        "\"the record\", or",
        "the record value §2",
        "the record's entries",
        "its record's own sig member",
        "breathe record §2",
        "visits record §2",
    ] {
        assert_eq!(bare_record_citation(prose), None, "{prose:?}");
    }
}

/// AUTH-2.1 PINS THE DEPENDENCY SET — `skep-address`, `sha2`, `im`, `serde`
/// and `serde_json`, exactly, as `Cargo.toml`'s card and `lib.rs`'s first
/// paragraph state it — so the crate stays light enough for the engine, M10,
/// checkpoint/replay and any mirror tool to carry, and no signature library
/// reaches the fold (AUTH-2.2: `skep-signature` is the one crate that links
/// them). The compiler holds none of it: a dependency added to the manifest
/// builds, and every other test of the workspace stays green. Read off the
/// manifest's own text: the tables whose headers name dependencies are
/// `[dependencies]` and `[dev-dependencies]` and no other, so none arrives
/// under a target or build table, and `[dependencies]` names the five. Live
/// on a clean tree, as the bullet check is: a reader that found nothing fails.
#[test]
fn the_dependencies_are_auth_2_1s_five() {
    let manifest =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml")).unwrap();
    let (mut table, mut dependency_tables, mut dependencies) =
        ("", BTreeSet::new(), BTreeSet::new());
    for line in manifest.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.starts_with('[') {
            table = line;
            if line.contains("dependencies") {
                dependency_tables.insert(line);
            }
        } else if table == "[dependencies]" {
            dependencies.extend(dependency_named(line));
        }
    }
    assert_eq!(
        dependency_tables,
        BTreeSet::from(["[dependencies]", "[dev-dependencies]"]),
        "Cargo.toml's dependency tables"
    );
    assert_eq!(
        dependencies,
        BTreeSet::from(["im", "serde", "serde_json", "sha2", "skep-address"]),
        "AUTH-2.1's dependency set"
    );
}

/// THE CRATE READS NO WORLD BUT ITS CTX (AUTH-2.1; `lib.rs`'s first paragraph
/// and its purity note): no I/O, no clock, no config, the one `std::sync` item
/// the `LazyLock` behind `key_set`'s empty answer — so the fold answers from
/// the record stream, the ctx and its frozen constants alone (I2, AUTH-2.90).
/// The manifest check cannot see this half: std is no dependency, and
/// `std::time`, `std::fs` and `std::env` compile into any crate. Every path
/// `src/`'s code names under `std::` or `core::` is read, a brace group's
/// members joined to it, and refused where it reaches the world
/// ([`reaches_the_world`]); so is every print macro. The I2 property cannot
/// stand in for this: it re-folds one stream within one run, where a verdict
/// gated on the clock agrees with itself.
#[test]
fn src_reads_no_world_but_its_ctx() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_files(&src, &mut files);
    files.sort();
    let mut faults = Vec::new();
    for file in &files {
        if file.file_name().is_some_and(|name| name == "tests.rs") {
            continue;
        }
        let text = std::fs::read_to_string(file).unwrap();
        let path = file.strip_prefix(&src).unwrap().display().to_string();
        let (code, at) = code_of(&text);
        for (start, named) in paths_from(&code, &["std::", "core::"]) {
            if reaches_the_world(&named) {
                faults.push(format!("src/{path}:{}: `{named}`", at[start].0));
            }
        }
        for call in print_calls(&code) {
            faults.push(format!("src/{path}: `{call}…)` prints"));
        }
    }
    assert!(faults.is_empty(), "the crate reaches past its ctx:\n{}", faults.join("\n"));
}

/// The purity check above looks for paths the tree does not name, so on a
/// clean tree it passes whether its readers can see or not; held here to the
/// forms the world arrives in — a brace group at `std::` with a member's own
/// path, a path spelled in an expression, one spelled from the extern root
/// (`::std::…`), a `std::sync` group holding the `LazyLock` the crate keeps
/// beside an item it does not, and a print macro, read once and never again
/// as the shorter macro its name contains.
#[test]
fn the_purity_readers_see_the_world_in_every_form() {
    let code = "use std::{fs, time::Instant};\nlet home = std::env::var(\"HOME\");\n\
                ::std::process::exit(1);\nuse std::sync::{LazyLock, Mutex};\n\
                eprintln!(\"{home:?}\");\n";
    let named: Vec<String> =
        paths_from(code, &["std::", "core::"]).into_iter().map(|(_, path)| path).collect();
    assert_eq!(
        named,
        [
            "std::fs",
            "std::time::Instant",
            "std::env::var",
            "std::process::exit",
            "std::sync::LazyLock",
            "std::sync::Mutex",
        ]
    );
    let refused: Vec<&str> =
        named.iter().map(String::as_str).filter(|path| reaches_the_world(path)).collect();
    assert_eq!(
        refused,
        [
            "std::fs",
            "std::time::Instant",
            "std::env::var",
            "std::process::exit",
            "std::sync::Mutex",
        ]
    );
    assert_eq!(print_calls(code), ["eprintln!("], "a print macro, read once");
}

/// The crate a line of a dependency table names — the key ahead of its `=`,
/// to its first `.` (`serde_json.workspace = true` names `serde_json`) — or
/// `None` for a line that names none: a blank, or the continuation of an
/// array a key opened above it.
fn dependency_named(line: &str) -> Option<&str> {
    let (key, _) = line.split_once('=')?;
    let name = key.split('.').next()?.trim().trim_matches('"');
    let is_name = |c: char| c.is_ascii_alphanumeric() || c == '-' || c == '_';
    (!name.is_empty() && name.chars().all(is_name)).then_some(name)
}

/// Whether a path `src/` names under `std::` or `core::` reaches past the
/// crate's inputs — the filesystem, the network, the environment, the
/// operating system, a process, a thread or the clock — or holds `std::sync`
/// state beyond the one `LazyLock` the purity note names.
fn reaches_the_world(path: &str) -> bool {
    const WORLD: &[&str] = &["env", "fs", "io", "net", "os", "process", "thread", "time"];
    let module = path.split("::").nth(1).unwrap_or("");
    WORLD.contains(&module) || (module == "sync" && path != "std::sync::LazyLock")
}

/// The print macros `code` calls — writes to the process's own streams —
/// each where its name opens a word, so an `eprintln!` is never read as the
/// `println!` its name contains.
fn print_calls(code: &str) -> Vec<&'static str> {
    let opens_a_word = |at: usize| {
        code[..at].chars().next_back().is_none_or(|c| !(c.is_alphanumeric() || c == '_'))
    };
    ["print!(", "println!(", "eprint!(", "eprintln!(", "dbg!("]
        .into_iter()
        .filter(|call| code.match_indices(call).any(|(at, _)| opens_a_word(at)))
        .collect()
}

/// The module a line of `lib.rs` declares — `mod key;`, with or without a
/// visibility — or `None` for any other line.
fn declared_module(line: &str) -> Option<&str> {
    let item = match line.strip_prefix("pub") {
        Some(rest) => rest.split_once(' ').map_or("", |(_, item)| item),
        None => line,
    };
    item.strip_prefix("mod ")?.strip_suffix(';')
}

/// Every comment in a file as prose, beside the line it begins on: each run
/// of whole-line comments as one text, and each trailing ` //` comment on its
/// own — its words rejoined by single spaces, so a phrase a reflow split
/// across two lines reads as one.
fn comment_runs(text: &str) -> Vec<(usize, String)> {
    let mut runs = Vec::new();
    let mut run: Option<(usize, Vec<&str>)> = None;
    for (i, line) in text.lines().enumerate() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("//") {
            let words = trimmed.trim_start_matches(['/', '!']).split_whitespace();
            run.get_or_insert((i + 1, Vec::new())).1.extend(words);
            continue;
        }
        if let Some((at, words)) = run.take() {
            runs.push((at, words.join(" ")));
        }
        if let Some((_, trailing)) = line.split_once(" //") {
            runs.push((i + 1, trailing.split_whitespace().collect::<Vec<_>>().join(" ")));
        }
    }
    if let Some((at, words)) = run {
        runs.push((at, words.join(" ")));
    }
    runs
}

/// The first citation in `prose` that names a design record as a bare
/// "record" — "the record" or "its record", either capitalization, or the
/// possessive, whose next word opens with a section sign or is a ruling's `D`
/// number — or `None`.
fn bare_record_citation(prose: &str) -> Option<&str> {
    ["the record", "The record", "its record", "Its record"].into_iter().find_map(|phrase| {
        prose.match_indices(phrase).find_map(|(at, _)| {
            let opens_a_word = prose[..at].chars().next_back().is_none_or(|c| !c.is_alphanumeric());
            let rest = &prose[at + phrase.len()..];
            let rest = rest.strip_prefix("'s").unwrap_or(rest);
            let next = rest.strip_prefix(' ')?.split(' ').next()?;
            let numbered = |n: &str| n.starts_with(|c: char| c.is_ascii_digit());
            let cites = next.starts_with('§') || next.strip_prefix('D').is_some_and(numbered);
            (opens_a_word && cites).then(|| &prose[at..prose.len() - rest.len() + 1 + next.len()])
        })
    })
}

/// A file's code as one text, so a brace group may span lines — comment
/// lines dropped (a doc link is no import), a trailing ` //` comment cut,
/// nothing from the inline test module's `mod tests {` on
/// ([`inline_test_module`]) — and, per byte, the line it sits on and how many
/// inline modules enclose it.
fn code_of(text: &str) -> (String, Vec<(usize, usize)>) {
    let lines: Vec<&str> = text.lines().collect();
    let end = inline_test_module(&lines).map_or(lines.len(), |tests| tests.open);
    let (mut code, mut at) = (String::new(), Vec::new());
    // The indentation of each inline module enclosing the current line.
    let mut enclosing: Vec<usize> = Vec::new();
    for (i, &line) in lines[..end].iter().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("//") {
            continue;
        }
        let indent = line.len() - line.trim_start().len();
        if trimmed == "}" && enclosing.last() == Some(&indent) {
            enclosing.pop();
        }
        code.push_str(line.split(" //").next().unwrap_or(line));
        code.push('\n');
        at.resize(code.len(), (i + 1, enclosing.len()));
        if opens_inline_module(trimmed) {
            enclosing.push(indent);
        }
    }
    (code, at)
}

/// Whether a trimmed line opens an inline module (`mod sealed {`, `pub(crate)
/// mod x {`).
fn opens_inline_module(trimmed: &str) -> bool {
    let item = match trimmed.strip_prefix("pub") {
        Some(rest) => rest.split_once(' ').map_or("", |(_, item)| item),
        None => trimmed,
    };
    item.starts_with("mod ") && item.ends_with('{')
}

/// Every path the code names from `crate::` or `super::` — [`paths_from`] as
/// the module map reads it.
fn named_paths(code: &str) -> Vec<(usize, String)> {
    paths_from(code, &["crate::", "super::"])
}

/// Every path the code names from one of `roots`, with the byte it starts at:
/// each token — a maximal run of identifier characters and `:`, read past a
/// leading `::` — and, where one ends at a brace group (`use
/// crate::{key::Fingerprint, keyset::KeySet};`), each member of the group
/// joined to it.
fn paths_from(code: &str, roots: &[&str]) -> Vec<(usize, String)> {
    let is_path = |b: u8| b.is_ascii_alphanumeric() || b == b'_' || b == b':';
    let bytes = code.as_bytes();
    let (mut paths, mut i) = (Vec::new(), 0);
    while i < bytes.len() {
        if !is_path(bytes[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < bytes.len() && is_path(bytes[i]) {
            i += 1;
        }
        let token = code[start..i].trim_start_matches(':');
        if !roots.iter().any(|root| token.starts_with(root)) {
            continue;
        }
        let after = code[i..].trim_start();
        if token.ends_with("::") && after.starts_with('{') {
            let (members, end) = brace_group(code, code.len() - after.len());
            paths.extend(members.into_iter().map(|m| (start, format!("{token}{m}"))));
            i = end;
        } else {
            paths.push((start, token.to_string()));
        }
    }
    paths
}

/// The members of the brace group whose `{` is at byte `open` of `text`,
/// each expanded to a path ([`expand_member`]), and the byte just past its
/// `}`.
fn brace_group(text: &str, open: usize) -> (Vec<String>, usize) {
    let mut depth = 0;
    let mut close = text.len();
    for (j, b) in text.bytes().enumerate().skip(open) {
        match b {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    close = j;
                    break;
                }
            }
            _ => {}
        }
    }
    let inner = &text[open + 1..close];
    let (mut members, mut depth, mut from) = (Vec::new(), 0, 0);
    for (j, c) in inner.char_indices() {
        match c {
            '{' => depth += 1,
            '}' => depth -= 1,
            ',' if depth == 0 => {
                members.extend(expand_member(&inner[from..j]));
                from = j + 1;
            }
            _ => {}
        }
    }
    members.extend(expand_member(&inner[from..]));
    (members, (close + 1).min(text.len()))
}

/// One member of a brace group as the paths it names: `a::b` itself, `a::{b,
/// c}` as `a::b` and `a::c`, `x as y` as `x`, and an empty member — a
/// trailing comma — as none.
fn expand_member(member: &str) -> Vec<String> {
    let member = member.trim();
    match member.find('{') {
        Some(k) => {
            let prefix = member[..k].trim_end();
            brace_group(member, k).0.into_iter().map(|m| format!("{prefix}{m}")).collect()
        }
        None => match member.split(" as ").next().unwrap_or("").trim() {
            "" => Vec::new(),
            path => vec![path.to_string()],
        },
    }
}

/// Where a file's inline unit-test module stands, as line indices from 0, read
/// off rustfmt's layout: `open`, its `mod tests {` line; `first`, the topmost
/// of the attribute lines stacked directly above that — its `#[cfg(…)]` — or
/// `open` where none is; and `close`, the first line after `open` back at
/// column 0 — in a file rustfmt laid out, the module's own `}`, whatever
/// comment trails it — or `None` where the file ends first.
struct InlineTestModule {
    first: usize,
    open: usize,
    close: Option<usize>,
}

/// The file's inline unit-test module, read once for every check that needs
/// it — [`code_of`]'s cut, [`after_test_module`] and [`oversized_test_module`]
/// — so no two of them can part about where it opens or closes. `None` for a
/// file with no inline `mod tests {`: a `mod tests;` declaration is none.
fn inline_test_module(lines: &[&str]) -> Option<InlineTestModule> {
    let open = lines.iter().position(|line| line.trim() == "mod tests {")?;
    let first = (0..open)
        .rev()
        .take_while(|&i| lines[i].trim_start().starts_with("#["))
        .last()
        .unwrap_or(open);
    let close = (open + 1..lines.len()).find(|&i| at_column_zero(lines[i]));
    Some(InlineTestModule { first, open, close })
}

/// Whether a line starts at column 0 — a top-level line, in a file rustfmt
/// laid out; a blank line is none.
fn at_column_zero(line: &str) -> bool {
    line.starts_with(|c: char| !c.is_whitespace())
}

/// The line, numbered from 1, that stands out of place after a file's inline
/// test module ([`inline_test_module`]): the first line back at column 0 after
/// the module's closing `}`, or the module's close itself where that line is
/// no `}` — `None` where nothing follows the module, and for a file with no
/// inline test module.
fn after_test_module(text: &str) -> Option<usize> {
    let lines: Vec<&str> = text.lines().collect();
    let close = inline_test_module(&lines)?.close?;
    let stray = if lines[close].starts_with('}') {
        (close + 1..lines.len()).find(|&i| at_column_zero(lines[i]))?
    } else {
        close
    };
    Some(stray + 1)
}

/// The lines a file's inline test module spans where they reach
/// [`TEST_MODULE_BOUND`] — counted as `AGENTS.md` counts them, from its
/// `#[cfg(…)]` to its closing `}`, both included ([`inline_test_module`]'s
/// `first` and `close`) — and `None` for a module under the bound, for one the
/// file never closes, and for a file with no inline test module.
fn oversized_test_module(text: &str) -> Option<usize> {
    let lines: Vec<&str> = text.lines().collect();
    let module = inline_test_module(&lines)?;
    Some(module.close? - module.first + 1).filter(|&len| len >= TEST_MODULE_BOUND)
}

/// The top-level module a `src/` file belongs to — `src/entry.rs`,
/// `src/entry/mod.rs` and `src/entry/row.rs` alike are `entry` — and `None`
/// for the root, `lib.rs`.
fn module_of(src: &Path, file: &Path) -> Option<String> {
    let first = file.strip_prefix(src).ok()?.iter().next()?.to_string_lossy().into_owned();
    match first.strip_suffix(".rs") {
        Some("lib") => None,
        Some(stem) => Some(stem.to_string()),
        None => Some(first),
    }
}

/// How many modules deep a `src/` file's own module sits: `entry.rs` and
/// `entry/mod.rs` one, `entry/row.rs` two — the `super::`s a file-level path
/// takes to reach the root.
fn module_depth(src: &Path, file: &Path) -> usize {
    let relative = file.strip_prefix(src).unwrap();
    let components = relative.iter().count();
    if relative.file_name().is_some_and(|name| name == "mod.rs") {
        components - 1
    } else {
        components
    }
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}
