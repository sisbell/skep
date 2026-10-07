//! THE ARRANGEMENT, CHECKED: what `ARCHITECTURE.md` §The command says about
//! where this crate's code lives, read off its own source.
//!
//! THE TREE. Every file under `src/`, and under the test target's
//! `tests/it/`, is a module its parent declares — the compiler never reads
//! a file no `mod` names, and no build says so, so an undeclared command
//! file is a command never built and an undeclared suite a suite never run.
//! `src/main.rs` declares its modules in dependency order, each with its
//! map line, a `//` comment directly above it; every `crate::…` path a
//! module's files name in code names that module or one declared above it —
//! never one below, and never an item through the root, which hides the
//! module it reaches. A command file names its parent through `super::`,
//! which is the tree itself and not an edge between modules.
//!
//! STDOUT CARRIES DATA (§2.4). Every write to stdout under `src/` — a
//! `print!` or `println!`, or a `stdout(` handle — sits in one of the
//! [`STDOUT_WRITERS`]: `data` and `data_verbatim`, which every command's
//! DATA goes through, and `main`, which prints `--help`. What reaches
//! stdout is then audited at their call sites alone. TALK, the prompts and
//! the halts take `eprint!`, `eprintln!` and `stderr()`, which the scan does
//! not count.
//!
//! A PROMPT HOLDS STDIN FOR ONE LINE. Every touch of stdin under `src/` — a
//! `stdin(` handle — sits in one of the [`STDIN_READERS`]: `answer`, the one
//! reader every prompt goes through, locking stdin for its one line alone;
//! `has_terminal`, which reads nothing; and the whole reads of a `-`
//! argument, `read_payload`'s and `session --close -`'s. So no prompt holds
//! stdin while a payload or a token is read.
//!
//! THE SETTINGS ARE `args.rs`'s (§9 item 21). Every `SKEP_*` variable is
//! named in code in `src/args.rs` alone, so no command reads a setting
//! around the precedence a flag holds over its variable.
//!
//! Each scan asserts that it found what it allows — an edge between
//! modules, a write in each writer, a touch in each reader, the five
//! variables in `src/args.rs` — so a scan gone blind fails rather than
//! passing a clean tree. Comments are not code, and neither is anything
//! from an inline `mod tests {` on.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// The writers that may write to stdout: a file under `src/` and the
/// column-0 function in it.
const STDOUT_WRITERS: &[(&str, &str)] = &[("commands.rs", "data"), ("commands.rs", "data_verbatim"), ("main.rs", "main")];

/// The functions that may touch stdin: a file under `src/` and the
/// column-0 function in it.
const STDIN_READERS: &[(&str, &str)] = &[("terminal.rs", "has_terminal"), ("terminal.rs", "answer"), ("commands.rs", "read_payload"), ("commands/session.rs", "session")];

/// §9 item 21's variables — every one `src/args.rs` reads.
const VARIABLES: &[&str] = &["SKEP_BOARD", "SKEP_KEY", "SKEP_KEYSTORE", "SKEP_PRINCIPAL", "SKEP_SESSION"];

#[test]
fn every_file_is_declared_and_every_root_declaration_says_what_it_holds() {
    let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut faults = undeclared_files(crate_dir, "src", "main");
    faults.extend(undeclared_files(crate_dir, "tests/it", "main"));
    let root = read(&crate_dir.join("src/main.rs"));
    let lines: Vec<&str> = root.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        let Some(name) = declared_module(line.trim()) else { continue };
        let above = lines[..i].iter().rev().map(|l| l.trim()).find(|l| !l.starts_with("#["));
        if !above.is_some_and(|l| l.starts_with("// ")) {
            faults.push(format!("src/main.rs:{}: `mod {name};` has no map line — a `//` comment directly above it saying what the module holds", i + 1));
        }
    }
    assert!(faults.is_empty(), "the module tree does not hold:\n{}", faults.join("\n"));
}

#[test]
fn every_module_names_only_itself_and_modules_declared_above_it() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let root = read(&src.join("main.rs"));
    let order: Vec<&str> = root.lines().filter_map(|l| declared_module(l.trim())).collect();
    assert!(order.len() > 1, "src/main.rs declares its modules as `mod name;` lines");
    let rank: HashMap<&str, usize> = order.iter().enumerate().map(|(i, m)| (*m, i)).collect();
    let (mut faults, mut edges) = (Vec::new(), 0);
    for (own, module) in order.iter().enumerate() {
        let mut files = vec![src.join(format!("{module}.rs"))];
        rust_files(&src.join(module), &mut files);
        for file in files {
            let text = read(&file);
            let shown = file.strip_prefix(&src).expect("under src").display().to_string();
            for (n, named) in crate_paths(&text) {
                match rank.get(named.as_str()) {
                    Some(&r) if r > own => faults.push(format!("src/{shown}:{n}: `crate::{named}` is declared below `{module}`")),
                    Some(&r) => edges += usize::from(r < own),
                    None => faults.push(format!("src/{shown}:{n}: `crate::{named}` goes through the root — name the item by its home module")),
                }
            }
        }
    }
    assert!(edges > 0, "this check read no path between modules at all: the forms it reads have moved");
    assert!(
        faults.is_empty(),
        "a module names one declared below it, or an item through the root — move the item, reorder src/main.rs, or name the \
         item's home module:\n{}",
        faults.join("\n")
    );
}

#[test]
fn stdout_is_written_by_the_three_writers_alone() {
    confined(
        writes_stdout,
        STDOUT_WRITERS,
        "writes to stdout",
        "stdout carries DATA alone (§2.4): write through `data` or `data_verbatim`, and talk through `talk` or the terminal's prompts",
    );
}

#[test]
fn stdin_is_read_by_answer_and_the_dash_arguments_alone() {
    confined(
        touches_stdin,
        STDIN_READERS,
        "touches stdin",
        "every prompt is read through `terminal::answer`, which locks stdin for its one line alone, and a `-` argument is read \
         whole by `read_payload` or `session --close -`",
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
    assert_eq!(found, VARIABLES, "src/args.rs names §9 item 21's five variables: the scan reads them as `\"SKEP_…\"` literals");
    assert!(faults.is_empty(), "the settings are src/args.rs's (§9 item 21):\n{}", faults.join("\n"));
}

/// Whether `code` writes to stdout: a `print!` or `println!` — never the
/// `eprint!` or `eprintln!` it is the tail of — or a `stdout(` handle.
fn writes_stdout(code: &str) -> bool {
    ["print!", "println!", "stdout("].iter().any(|needle| code.match_indices(needle).any(|(i, _)| !code[..i].ends_with(is_ident_char)))
}

/// Whether `code` touches stdin: a `stdin(` handle.
fn touches_stdin(code: &str) -> bool {
    code.match_indices("stdin(").any(|(i, _)| !code[..i].ends_with(is_ident_char))
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
/// `src/commands.rs`.
fn declared_by(dir: &Path, root: &str, file: &Path) -> Option<(PathBuf, String)> {
    let relative = file.strip_prefix(dir).ok()?;
    let mut parts: Vec<String> = relative.iter().map(|part| part.to_string_lossy().into_owned()).collect();
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
