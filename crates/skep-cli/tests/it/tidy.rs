//! THE ARRANGEMENT, CHECKED: what `ARCHITECTURE.md` §The command says about
//! where this crate's code lives, read off its own source.
//!
//! THE TREE. Every file under `src/`, and under the test target's
//! `tests/it/`, is a module its parent declares — the compiler never reads
//! a file no `mod` names, and no build says so, so an undeclared command
//! file is a command never built and an undeclared suite a suite never run.
//! The crate has TWO ROOTS ([`ROOTS`]): `src/main.rs`, the `skep` binary's,
//! and `src/dev/main.rs`, the `skep-dev` binary's — a subdirectory holding a
//! `main.rs` is a second binary's tree, rooted there, whose files that root
//! declares. Each root declares its modules in dependency order, each with
//! its map line, a `//` comment directly above it (an attribute line between
//! them, a `#[path]` or a lint allowance, is neither); every `crate::…` path
//! a module's files name in code names that module or one declared above it
//! in that root — never one below, and never an item through the root, which
//! hides the module it reaches. A module the dev root declares by `#[path]`
//! from the `skep` root's files is the same module in both trees, placed by
//! its path. A command file names its parent through `super::`, which is
//! the tree itself and not an edge between modules.
//!
//! NO WRITE PANICS. std's `print!`, `println!`, `eprint!` and `eprintln!`
//! panic on a write their stream refuses — a reader gone, a disk full —
//! and a panic is exit 101, which §2.3 does not have; so none stands under
//! `src/`, and every write is an `io::Write` call whose failure its writer
//! answers.
//!
//! STDOUT CARRIES DATA (§2.4). Every `stdout(` handle under `src/` sits in
//! one of the [`STDOUT_WRITERS`]: `data` and `data_verbatim`, which every
//! command's DATA and the dev binary's one JSON object go through, `--help`'s
//! text among it, and which answer a write stdout refuses with a halt. What
//! reaches stdout is then audited at their call sites alone.
//!
//! STDERR CARRIES TALK, INERT. Every `stderr(` handle under `src/` sits in
//! one of the [`STDERR_WRITERS`]: `write_inert`, which every line and prompt
//! passes — `talk`'s, every statement, prompt heading, command's TALK and
//! halt, and `show`'s, a prompt's text and the sheet's box — rendering it
//! inert (AUTH-5.2's `render_inert`, line by line) before stderr is handed
//! a byte; `clear`, the dismissal's escape, a constant; and
//! `has_terminal`, which writes nothing. Both writers drop a write stderr
//! refuses. So no byte a board, a reply or a file chose reaches the
//! terminal as a command.
//!
//! A PROMPT HOLDS STDIN FOR ONE LINE. Every touch of stdin under `src/` — a
//! `stdin(` handle — sits in one of the [`STDIN_READERS`]: `answer`, the one
//! reader every prompt goes through, locking stdin for its one line alone;
//! `has_terminal`, which reads nothing; the whole reads of a `-`
//! argument, `read_payload`'s and `session --close -`'s; and the dev
//! provider's `watch_stdin`, which reads stdin to its end for the one stop
//! the verb has. So no prompt holds stdin while a payload or a token is
//! read.
//!
//! THE SETTINGS ARE `args.rs`'s (§9 item 21). Every `SKEP_*` variable is
//! named in code in `src/args.rs` alone — `merge`'s `SKEP_MERGE_KIND` and
//! the dev binary's `SKEP_SEARCH_CORPUS` included — so no command and no
//! verb reads a setting around the precedence a flag holds over its
//! variable.
//!
//! EVERY VARIABLE READ IS TABLED. Every variable the source reads at run
//! time — a `SKEP_*` setting, a `std::env::var("…")` or `var_os("…")`, the
//! system temp dir's `TMPDIR` through `temp_dir()` — is a row of the
//! crate's README §Settings, so the source reads no variable an operator
//! cannot find there, its default and where it is read beside it.
//!
//! ONLY `main` ENDS THE PROCESS (§2.3). Every `exit(` and `abort(` under
//! `src/` sits in a root's `main`, which exits with `finish`'s rendering of
//! the command's answer — so no command picks a code of its own, nor ends
//! the run before its stop's block is said.
//!
//! Each scan asserts that it found what it allows — an edge between
//! modules, a write in each writer, a touch in each reader, an end in each
//! `main`, the seven variables in `src/args.rs`, the variables read beside
//! them — or, where it allows nothing, that it reads the forms it refuses,
//! so a scan gone blind fails rather than passing a clean tree. Comments
//! are not code, and neither is anything from an inline `mod tests {` on.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::common::VARIABLES;

/// The two roots under `src/`: the `skep` binary's and the `skep-dev`
/// binary's, each a `[[bin]]` of the manifest.
const ROOTS: &[&str] = &["src/main.rs", "src/dev/main.rs"];

/// The writers that may write to stdout: a file under `src/` and the
/// column-0 function in it.
const STDOUT_WRITERS: &[(&str, &str)] = &[("shared.rs", "data"), ("shared.rs", "data_verbatim")];

/// The functions that may take a stderr handle: a file under `src/` and
/// the column-0 function in it.
const STDERR_WRITERS: &[(&str, &str)] = &[("terminal.rs", "has_terminal"), ("terminal.rs", "write_inert"), ("terminal.rs", "clear")];

/// The functions that may touch stdin: a file under `src/` and the
/// column-0 function in it.
const STDIN_READERS: &[(&str, &str)] = &[("terminal.rs", "has_terminal"), ("terminal.rs", "answer"), ("commands.rs", "read_payload"), ("commands/session.rs", "session"), ("dev/serve.rs", "watch_stdin")];

/// The functions that may end the process: a file under `src/` and the
/// column-0 function in it — each root's `main`.
const EXITERS: &[(&str, &str)] = &[("main.rs", "main"), ("dev/main.rs", "main")];

#[test]
fn every_file_is_declared_and_every_root_declaration_says_what_it_holds() {
    let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut faults = undeclared_files(crate_dir, "src", "main");
    faults.extend(undeclared_files(crate_dir, "tests/it", "main"));
    for root in ROOTS {
        let text = read(&crate_dir.join(root));
        let lines: Vec<&str> = text.lines().collect();
        let mut declared = 0;
        for (i, line) in lines.iter().enumerate() {
            let Some(name) = declared_module(line.trim()) else { continue };
            declared += 1;
            let above = lines[..i].iter().rev().map(|l| l.trim()).find(|l| !l.starts_with("#["));
            if !above.is_some_and(|l| l.starts_with("// ")) {
                faults.push(format!("{root}:{}: `mod {name};` has no map line — a `//` comment directly above it saying what the module holds", i + 1));
            }
        }
        assert!(declared > 1, "{root} declares its modules as `mod name;` lines");
    }
    assert!(faults.is_empty(), "the module tree does not hold:\n{}", faults.join("\n"));
}

#[test]
fn every_module_names_only_itself_and_modules_declared_above_it() {
    let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let src = crate_dir.join("src");
    let (mut faults, mut edges) = (Vec::new(), 0);
    for root in ROOTS {
        let modules = modules_of(&crate_dir.join(root));
        assert!(modules.len() > 1, "{root} declares its modules as `mod name;` lines");
        let rank: HashMap<&str, usize> =
            modules.iter().enumerate().map(|(i, (m, _))| (m.as_str(), i)).collect();
        for (own, (module, file)) in modules.iter().enumerate() {
            let mut files = vec![file.clone()];
            rust_files(&file.with_extension(""), &mut files);
            for file in files {
                let text = read(&file);
                let shown = file.strip_prefix(&src).expect("under src").display().to_string();
                for (n, named) in crate_paths(&text) {
                    match rank.get(named.as_str()) {
                        Some(&r) if r > own => faults.push(format!("src/{shown}:{n}: `crate::{named}` is declared below `{module}` in {root}")),
                        Some(&r) => edges += usize::from(r < own),
                        None => faults.push(format!("src/{shown}:{n}: `crate::{named}` goes through the root {root} — name the item by its home module")),
                    }
                }
            }
        }
    }
    assert!(edges > 0, "this check read no path between modules at all: the forms it reads have moved");
    assert!(
        faults.is_empty(),
        "a module names one declared below it, or an item through the root — move the item, reorder the root, or name the \
         item's home module:\n{}",
        faults.join("\n")
    );
}

#[test]
fn no_stream_is_written_by_a_print_macro() {
    for (sample, prints) in [("    eprintln!(\"{x}\");", true), ("    print!(\"{HELP}\");", true), ("    let _ = writeln!(out, \"{x}\");", false)] {
        assert_eq!(print_macro(sample), prints, "the scan reads the forms it refuses: `{sample}`");
    }
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_files(&src, &mut files);
    assert!(!files.is_empty(), "this check read no file under src/");
    let mut faults = Vec::new();
    for file in &files {
        let text = read(file);
        let shown = file.strip_prefix(&src).expect("under src").display().to_string();
        faults.extend(code_lines(&text).filter(|(_, code)| print_macro(code)).map(|(n, code)| format!("src/{shown}:{n}: `{}`", code.trim())));
    }
    assert!(
        faults.is_empty(),
        "a print macro panics on a write its stream refuses, an exit 101 §2.3 does not have: write DATA through `data` or \
         `data_verbatim` and TALK through `talk`:\n{}",
        faults.join("\n")
    );
}

#[test]
fn stdout_is_written_by_the_two_writers_alone() {
    confined(
        writes_stdout,
        STDOUT_WRITERS,
        "writes to stdout",
        "stdout carries DATA alone (§2.4): write through `data` or `data_verbatim`, and talk through `talk` or the terminal's prompts",
    );
}

#[test]
fn stderr_is_written_inert_by_write_inert_and_clear_alone() {
    confined(
        writes_stderr,
        STDERR_WRITERS,
        "takes a stderr handle",
        "what reaches the terminal is inert: say a line through `talk` and show a prompt or the sheet through `show`, each passing \
         `write_inert`, which renders it by `render_inert`; `clear` alone writes an escape, a constant",
    );
}

#[test]
fn stdin_is_read_by_answer_and_the_dash_arguments_alone() {
    confined(
        touches_stdin,
        STDIN_READERS,
        "touches stdin",
        "every prompt is read through `terminal::answer`, which locks stdin for its one line alone, a `-` argument is read \
         whole by `read_payload` or `session --close -`, and the dev provider's `watch_stdin` reads stdin to its end for its stop",
    );
}

#[test]
fn the_process_is_ended_by_main_alone() {
    let samples = [("    std::process::exit(3);", true), ("        Ok(Parsed::Help) => exit(code),", true), ("    process::abort();", true), ("    talk(h.exit_code());", false)];
    for (sample, ends) in samples {
        assert_eq!(ends_the_process(sample), ends, "the scan reads the forms it refuses: `{sample}`");
    }
    confined(
        ends_the_process,
        EXITERS,
        "ends the process",
        "only a root's `main` ends the process, with `finish`'s rendering of the command's answer (§2.3): answer a `Stop` with `?` instead",
    );
}

/// Asserts that every code line under `src/` that `hits` matches sits in
/// one of `allowed` — a file under `src/` and the column-0 function in it —
/// and that each of `allowed` holds such a line, so a scan gone blind fails
/// rather than passing a clean tree; `does` says what a matched line does,
/// `rule` what a stray one breaks.
fn confined(hits: fn(&str) -> bool, allowed: &[(&str, &str)], does: &str, rule: &str) {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_files(&src, &mut files);
    let (mut faults, mut found) = (Vec::new(), Vec::new());
    for file in &files {
        let text = read(file);
        let shown = file.strip_prefix(&src).expect("under src").display().to_string();
        let mut within: Option<String> = None;
        for (n, code) in code_lines(&text) {
            if let Some(name) = column_0_function(code) {
                within = Some(name);
            } else if code == "}" {
                within = None;
            }
            if !hits(code) {
                continue;
            }
            match within.as_deref() {
                Some(f) if allowed.contains(&(shown.as_str(), f)) => found.push((shown.clone(), f.to_string())),
                _ => faults.push(format!("src/{shown}:{n}: `{}` {does}", code.trim())),
            }
        }
    }
    for (file, f) in allowed {
        assert!(
            found.iter().any(|(fl, fu)| fl == file && fu == f),
            "src/{file}: `{f}` {does} nowhere this scan reads: the function or the forms the scan reads have moved"
        );
    }
    assert!(faults.is_empty(), "{rule}:\n{}", faults.join("\n"));
}

#[test]
fn every_skep_variable_is_named_in_args_alone() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_files(&src, &mut files);
    let (mut faults, mut found) = (Vec::new(), Vec::new());
    for file in &files {
        let text = read(file);
        let shown = file.strip_prefix(&src).expect("under src").display().to_string();
        for (n, code) in code_lines(&text) {
            // A compile-time read — `env!`, `option_env!` — is the BUILD's
            // variable, never a setting the program reads: `SKEP_GIT_SHA`,
            // the commit the version line carries, is no flag's variable.
            if code.contains("env!(") {
                continue;
            }
            for (i, _) in code.match_indices("\"SKEP_") {
                let name: String = code[i + 1..].chars().take_while(|c| c.is_ascii_uppercase() || *c == '_').collect();
                if shown == "args.rs" {
                    found.push(name);
                } else {
                    faults.push(format!("src/{shown}:{n}: `{name}` is a setting — read it in src/args.rs, beside its flag"));
                }
            }
        }
    }
    found.sort();
    found.dedup();
    assert_eq!(found, VARIABLES, "src/args.rs names §9 item 21's five variables, merge's one and the dev binary's one: the scan reads them as `\"SKEP_…\"` literals");
    assert!(faults.is_empty(), "the settings are src/args.rs's (§9 item 21):\n{}", faults.join("\n"));
}

#[test]
fn every_variable_the_source_reads_is_a_row_of_the_readmes_settings() {
    let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let src = crate_dir.join("src");
    let mut files = Vec::new();
    rust_files(&src, &mut files);
    let mut found: Vec<(String, String)> = Vec::new();
    for file in &files {
        let text = read(file);
        let shown = file.strip_prefix(&src).expect("under src").display().to_string();
        for (n, code) in code_lines(&text) {
            // A compile-time read is the build's, tabled beside the table.
            if code.contains("env!(") {
                continue;
            }
            // Each form, and how far past its match the name begins: a
            // `"SKEP_…"` literal just inside its quote, a variable a read
            // names just past the read's opening quote.
            for (needle, skip) in [
                ("\"SKEP_", 1),
                ("env::var(\"", "env::var(\"".len()),
                ("env::var_os(\"", "env::var_os(\"".len()),
            ] {
                for (i, _) in code.match_indices(needle) {
                    let name: String = code[i + skip..]
                        .chars()
                        .take_while(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == '_')
                        .collect();
                    found.push((name, format!("src/{shown}:{n}")));
                }
            }
            if names(code, "temp_dir(") {
                found.push(("TMPDIR".to_string(), format!("src/{shown}:{n}")));
            }
        }
    }
    for name in VARIABLES.iter().chain(&["COMPUTERNAME", "HOSTNAME", "TMPDIR"]) {
        assert!(
            found.iter().any(|(f, _)| f == name),
            "the scan reads `{name}`: the forms it reads have moved"
        );
    }
    let readme = read(&crate_dir.join("README.md"));
    let settings =
        readme.split("\n## Settings\n").nth(1).expect("the README has a Settings section");
    let settings = settings.split("\n## ").next().unwrap_or(settings);
    let rows: Vec<&str> = settings.lines().filter(|l| l.starts_with("| ")).collect();
    assert!(rows.len() > 20, "the scan reads the README's settings tables: {} rows", rows.len());
    let faults: Vec<String> = found
        .iter()
        .filter(|(name, _)| !rows.iter().any(|r| r.contains(&format!("`{name}`"))))
        .map(|(name, at)| format!("{at}: `{name}` is read and is no row of the README's Settings"))
        .collect();
    assert!(faults.is_empty(), "every variable the programs read is tabled, its default and where it is read beside it:\n{}", faults.join("\n"));
}

/// Whether `code` names one of std's print macros, each a whole word: an
/// `eprint!` is never read as the `print!` it ends with.
fn print_macro(code: &str) -> bool {
    ["print!", "println!", "eprint!", "eprintln!"].iter().any(|needle| names(code, needle))
}

/// Whether `code` writes to stdout: a `stdout(` handle, the print macros
/// being refused outright.
fn writes_stdout(code: &str) -> bool {
    names(code, "stdout(")
}

/// Whether `code` writes to stderr: a `stderr(` handle.
fn writes_stderr(code: &str) -> bool {
    names(code, "stderr(")
}

/// Whether `code` touches stdin: a `stdin(` handle.
fn touches_stdin(code: &str) -> bool {
    names(code, "stdin(")
}

/// Whether `code` ends the process: an `exit(` or an `abort(`, bare or
/// through a path — never an `exit_code(`, which names the code and ends
/// nothing.
fn ends_the_process(code: &str) -> bool {
    names(code, "exit(") || names(code, "abort(")
}

/// Whether `code` holds `needle` as a whole word — no identifier character
/// directly before it.
fn names(code: &str, needle: &str) -> bool {
    code.match_indices(needle).any(|(i, _)| !code[..i].ends_with(is_ident_char))
}

/// The function a column-0 `fn` line opens — with or without a visibility —
/// or `None` for any other line.
fn column_0_function(code: &str) -> Option<String> {
    let item = match code.strip_prefix("pub") {
        Some(rest) => rest.split_once(' ').map_or("", |(_, item)| item),
        None => code,
    };
    let rest = item.strip_prefix("fn ")?;
    Some(rest.chars().take_while(|c| is_ident_char(*c)).collect())
}

fn is_ident_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// The module a line declares — `mod key;`, with or without a visibility —
/// or `None` for any other line, an inline `mod x {` included.
fn declared_module(line: &str) -> Option<&str> {
    let item = match line.strip_prefix("pub") {
        Some(rest) => rest.split_once(' ').map_or("", |(_, item)| item),
        None => line,
    };
    item.strip_prefix("mod ")?.strip_suffix(';')
}

/// The modules a root declares, in order, each with the file that holds it:
/// the `#[path = "…"]` attribute directly above a `mod name;` line places
/// it, else `name.rs` beside the root.
fn modules_of(root: &Path) -> Vec<(String, PathBuf)> {
    let dir = root.parent().expect("a root has a directory");
    let text = read(root);
    let mut out = Vec::new();
    let mut placed: Option<PathBuf> = None;
    for line in text.lines() {
        let line = line.trim();
        if let Some(path) =
            line.strip_prefix("#[path = \"").and_then(|rest| rest.strip_suffix("\"]"))
        {
            // Joined lexically — `src/dev/../args.rs` is `src/args.rs` — so
            // the file is named as the tree names it.
            let mut joined = dir.to_path_buf();
            for part in Path::new(path).components() {
                match part {
                    std::path::Component::ParentDir => {
                        joined.pop();
                    }
                    std::path::Component::CurDir => {}
                    other => joined.push(other),
                }
            }
            placed = Some(joined);
            continue;
        }
        if let Some(name) = declared_module(line) {
            let file = placed.take().unwrap_or_else(|| dir.join(format!("{name}.rs")));
            out.push((name.to_string(), file));
        } else if !line.starts_with("#[") {
            placed = None;
        }
    }
    out
}

/// Every file under the crate's `tree` that its parent does not declare, as
/// a fault naming both — the compiler never reads such a file, and no build
/// says so. `root` is the stem of the tree's root file: `main` for `src/`
/// and for the test target's `tests/it/` alike.
fn undeclared_files(crate_dir: &Path, tree: &str, root: &str) -> Vec<String> {
    let dir = crate_dir.join(tree);
    let shown = |path: &Path| path.strip_prefix(crate_dir).expect("under the crate").display().to_string();
    let mut files = Vec::new();
    rust_files(&dir, &mut files);
    let (mut faults, mut held) = (Vec::new(), 0);
    for file in &files {
        let Some((parent, name)) = declared_by(&dir, root, file) else { continue };
        held += 1;
        let parent_text = std::fs::read_to_string(&parent).unwrap_or_default();
        if !parent_text.lines().any(|line| declared_module(line.trim()) == Some(name.as_str())) {
            faults.push(format!("{}: {} declares no `mod {name};` — the compiler never reads this file", shown(file), shown(&parent)));
        }
    }
    assert!(held > 0, "{tree}: this check held no file to its parent — the layout it reads has moved");
    faults
}

/// The file that must declare `file`, and the name it must declare it by, in
/// the tree at `dir` whose root file's stem is `root` — or `None` for the
/// root itself. A file directly in the tree is declared by the root under its
/// stem: `src/main.rs` declares `args` for `src/args.rs`. A file in a
/// subdirectory is declared by the module that directory is named for, `x.rs`
/// beside it or `x/mod.rs` inside it: `src/commands/bind.rs` is `bind` to
/// `src/commands.rs`. A subdirectory holding a `main.rs` is a SECOND
/// BINARY's tree, rooted there: `src/dev/main.rs` is a root the manifest's
/// `[[bin]]` names, and `src/dev/seed.rs` is `seed` to it.
fn declared_by(dir: &Path, root: &str, file: &Path) -> Option<(PathBuf, String)> {
    let relative = file.strip_prefix(dir).ok()?;
    let mut parts: Vec<String> = relative.iter().map(|part| part.to_string_lossy().into_owned()).collect();
    if let Some(first) = parts.first() {
        let sub = dir.join(first);
        if parts.len() > 1 && sub.join("main.rs").is_file() {
            return declared_by(&sub, "main", file);
        }
    }
    let last = parts.pop()?;
    let name = match last.strip_suffix(".rs")? {
        stem if stem == root && parts.is_empty() => return None,
        "mod" => parts.pop()?,
        stem => stem.to_string(),
    };
    let parent = match parts.split_last() {
        None => dir.join(format!("{root}.rs")),
        Some((sub, above)) => {
            let base = above.iter().fold(dir.to_path_buf(), |path, part| path.join(part));
            let flat = base.join(format!("{sub}.rs"));
            if flat.exists() {
                flat
            } else {
                base.join(sub).join("mod.rs")
            }
        }
    };
    Some((parent, name))
}

/// The first segment of every `crate::…` path in code ([`code_lines`]), with
/// its line. A brace group directly after `crate::` would hide the modules
/// its members name, so it is read as a segment of its own and refused.
fn crate_paths(text: &str) -> Vec<(usize, String)> {
    let mut named = Vec::new();
    for (n, code) in code_lines(text) {
        for (i, _) in code.match_indices("crate::") {
            let after = &code[i + "crate::".len()..];
            let segment: String = if after.starts_with('{') { "{…}".to_string() } else { after.chars().take_while(|c| is_ident_char(*c)).collect() };
            named.push((n, segment));
        }
    }
    named
}

/// A file's code lines, numbered from 1: a comment line is not code, a
/// trailing ` //` comment is cut, and nothing from an inline `mod tests {`
/// on is read.
fn code_lines(text: &str) -> impl Iterator<Item = (usize, &str)> {
    text.lines()
        .enumerate()
        .take_while(|(_, line)| line.trim() != "mod tests {")
        .filter(|(_, line)| !line.trim_start().starts_with("//"))
        .map(|(i, line)| (i + 1, line.split(" //").next().unwrap_or(line)))
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// Every `.rs` file under `dir`, recursively, in order; nothing when `dir`
/// is absent.
fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    let mut entries: Vec<PathBuf> = entries.map(|e| e.expect("a readable entry").path()).collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|x| x == "rs") {
            out.push(path);
        }
    }
}
