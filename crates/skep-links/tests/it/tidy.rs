//! THE MODULE MAP, CHECKED: `src/lib.rs` declares this crate's modules in
//! dependency order, each with a line saying what it holds and each naming
//! in code only the modules above it, and this is that sentence as tests —
//! together with one rule no compiler error reports: `emit_core` is the one
//! caller of M3's `mint_link`.
//!
//! The tree's shape: every file under `src/`, and under the test target's
//! `tests/it/`, is a module its parent declares — the compiler never reads
//! a file no `mod` names, and no build says so, so an undeclared suite file
//! is a suite that never runs — and every `src/` declaration but a `tests`
//! module carries its map line, a `//` comment directly above it.
//!
//! Every `crate::…` path a module's files name in code — its tests included,
//! comments and doc links not — names that module, one declared above it,
//! or `LinkWorld`, the world bound the root defines. A path through the
//! root's re-exports — this crate's (`crate::MAX_SLOT_SPANS`) or an upstream
//! crate's (`crate::Caller`) — hides the module it reaches, so it is refused:
//! code names an item by its home module. A module's children name their
//! parent through `super::`, which is the tree itself and not an edge between
//! modules. The check counts the paths it reads between modules, so a reader
//! gone blind fails rather than passing a clean tree.
//!
//! The rule is held over every code line under `src/`, tests included, and
//! its scan asserts that it found the one call it allows, inside `emit_core`,
//! so a scan that matches nothing fails rather than passing a clean tree.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// The one item a module may name through `crate::` that is no module: the
/// world bound the root defines rather than re-exports.
const ROOT_ITEM: &str = "LinkWorld";

#[test]
fn every_file_is_declared_and_every_declaration_says_what_it_holds() {
    let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut faults = undeclared_files(crate_dir, "src", "lib");
    faults.extend(undeclared_files(crate_dir, "tests/it", "main"));
    let src = crate_dir.join("src");
    let mut files = Vec::new();
    rust_files(&src, &mut files);
    for file in &files {
        let path = file.strip_prefix(&src).expect("under src").display();
        let text = std::fs::read_to_string(file).expect("a source file is readable");
        let lines: Vec<&str> = text.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            let Some(name) = declared_module(line.trim()) else {
                continue;
            };
            if name == "tests" {
                continue;
            }
            let above = lines[..i]
                .iter()
                .rev()
                .map(|l| l.trim())
                .find(|l| !l.starts_with("#["));
            if !above.is_some_and(|l| l.starts_with("// ")) {
                faults.push(format!(
                    "src/{path}:{}: `mod {name};` has no map line — a `//` comment directly \
                     above it saying what the module holds",
                    i + 1
                ));
            }
        }
    }
    assert!(
        faults.is_empty(),
        "the module tree does not hold:\n{}",
        faults.join("\n")
    );
}

#[test]
fn every_module_names_only_itself_and_modules_declared_above_it() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let lib = std::fs::read_to_string(src.join("lib.rs")).expect("src/lib.rs is readable");
    let order: Vec<&str> = lib
        .lines()
        .filter_map(|l| declared_module(l.trim()))
        .collect();
    assert!(
        order.len() > 1,
        "src/lib.rs declares its modules as `mod name;` lines"
    );
    let rank: HashMap<&str, usize> = order.iter().enumerate().map(|(i, m)| (*m, i)).collect();

    let (mut faults, mut edges) = (Vec::new(), 0);
    for (own_rank, module) in order.iter().enumerate() {
        let mut files = vec![src.join(format!("{module}.rs"))];
        rust_files(&src.join(module), &mut files);
        for file in files {
            let text = std::fs::read_to_string(&file).expect("a module file is readable");
            let shown = file.strip_prefix(&src).expect("under src").display();
            for named in crate_paths(&text) {
                match rank.get(named.as_str()) {
                    Some(&r) if r > own_rank => faults.push(format!(
                        "{shown}: `crate::{named}` is declared below `{module}`"
                    )),
                    Some(&r) => edges += usize::from(r < own_rank),
                    None if named == ROOT_ITEM => {}
                    None => faults.push(format!(
                        "{shown}: `crate::{named}` goes through the root — name the item by its \
                         home module (the one root item a module may name is `{ROOT_ITEM}`)"
                    )),
                }
            }
        }
    }
    assert!(
        edges > 0,
        "this check read no path between modules at all: the forms it reads have moved"
    );
    assert!(
        faults.is_empty(),
        "a module names one declared below it, or an item through the root — move the item, \
         reorder src/lib.rs, or name the item's home module:\n{}",
        faults.join("\n")
    );
}

/// ONE DOOR TO THE MINT: `emit_core`, in `writes.rs`, stages every deposit —
/// it asks whether the home is registered and owned, of the working world,
/// ahead of every gate and every dedup short-circuit — so it is the one place
/// under `src/` that calls M3's `mint_link`. No type keeps it so:
/// `mint_link` is a public method of the namespace slice every write path
/// already holds, so a second call compiles anywhere and mints a link no gate
/// admitted. The scan asserts that it found the one call inside `emit_core`
/// itself, so a scan that matches nothing fails rather than passing a clean
/// tree.
#[test]
fn emit_core_is_the_one_caller_of_mint_link() {
    let mints = scan(|code| calls(code, "mint_link"));
    assert!(
        mints.len() <= 1,
        "only `emit_core` calls `mint_link`; every other deposit goes through it:\n{}",
        render(&mints)
    );
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let writes = std::fs::read_to_string(src.join("writes.rs")).expect("src/writes.rs is readable");
    let body = function_body(&writes, "emit_core");
    assert!(
        body.iter().any(|code| calls(code, "mint_link")),
        "`emit_core` in src/writes.rs calls `mint_link`, so a scan that finds no call \
         there is broken"
    );
}

/// The code lines of the column-0 function `name` in `text`, from its
/// signature to the closing brace in column 0 — empty when `text` declares
/// no such function.
fn function_body<'t>(text: &'t str, name: &str) -> Vec<&'t str> {
    let opener = format!("fn {name}");
    code_lines(text)
        .skip_while(|line| {
            !line
                .strip_prefix(&opener)
                .is_some_and(|rest| rest.starts_with(['<', '(']))
        })
        .take_while(|line| *line != "}")
        .collect()
}

/// Whether `code` calls `function` — the name as a whole identifier, followed
/// directly by its argument list.
fn calls(code: &str, function: &str) -> bool {
    code.match_indices(function).any(|(i, _)| {
        let (before, after) = (&code[..i], &code[i + function.len()..]);
        !before.ends_with(is_ident_char) && after.starts_with('(')
    })
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
/// says so. `root` is the stem of the tree's root file: `lib` for `src/`,
/// `main` for the test target's `tests/it/`.
fn undeclared_files(crate_dir: &Path, tree: &str, root: &str) -> Vec<String> {
    let dir = crate_dir.join(tree);
    let shown = |path: &Path| {
        path.strip_prefix(crate_dir)
            .expect("under the crate")
            .display()
            .to_string()
    };
    let mut files = Vec::new();
    rust_files(&dir, &mut files);
    let (mut faults, mut held) = (Vec::new(), 0);
    for file in &files {
        let Some((parent, name)) = declared_by(&dir, root, file) else {
            continue;
        };
        held += 1;
        let parent_text = std::fs::read_to_string(&parent).unwrap_or_default();
        if !parent_text
            .lines()
            .any(|line| declared_module(line.trim()) == Some(name.as_str()))
        {
            faults.push(format!(
                "{}: {} declares no `mod {name};` — the compiler never reads this file",
                shown(file),
                shown(&parent)
            ));
        }
    }
    assert!(
        held > 0,
        "{tree}: this check held no file to its parent — the layout it reads has moved"
    );
    faults
}

/// The file that must declare `file`, and the name it must declare it by, in
/// the tree at `dir` whose root file's stem is `root` — or `None` for the
/// root itself. A file directly in the tree is declared by the root under its
/// stem: `lib.rs` declares `budget` for `src/budget.rs`, and `main.rs`
/// declares `makelink` for `tests/it/makelink.rs`. A file in a subdirectory is
/// declared by the module that directory is named for, `x.rs` beside it or
/// `x/mod.rs` inside it: `src/writes/emit.rs` is `emit` to `src/writes.rs`.
fn declared_by(dir: &Path, root: &str, file: &Path) -> Option<(PathBuf, String)> {
    let relative = file.strip_prefix(dir).ok()?;
    let mut parts: Vec<String> = relative
        .iter()
        .map(|part| part.to_string_lossy().into_owned())
        .collect();
    let last = parts.pop()?;
    let name = match last.strip_suffix(".rs")? {
        stem if stem == root && parts.is_empty() => return None,
        "mod" => parts.pop()?,
        stem => stem.to_string(),
    };
    let parent = match parts.split_last() {
        None => dir.join(format!("{root}.rs")),
        Some((sub, above)) => {
            let base = above
                .iter()
                .fold(dir.to_path_buf(), |path, part| path.join(part));
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

/// The first segment of every `crate::…` path in code ([`code_lines`]). A
/// brace group directly after `crate::` is refused rather than half-read:
/// this crate names one module per path.
fn crate_paths(text: &str) -> Vec<String> {
    let mut named = Vec::new();
    for code in code_lines(text) {
        for (i, _) in code.match_indices("crate::") {
            let after = &code[i + "crate::".len()..];
            assert!(!after.starts_with('{'), "a `crate::{{…}}` group: {code}");
            let segment: String = after
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            named.push(segment);
        }
    }
    named
}

/// Every code line under `src/` that `pred` holds of, with its file's path
/// relative to `src/`.
fn scan(pred: impl Fn(&str) -> bool) -> Vec<(PathBuf, String)> {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_files(&src, &mut files);
    let mut hits = Vec::new();
    for file in files {
        let text = std::fs::read_to_string(&file).expect("a source file is readable");
        let path = file.strip_prefix(&src).expect("under src").to_path_buf();
        for code in code_lines(&text).filter(|code| pred(code)) {
            hits.push((path.clone(), code.trim().to_string()));
        }
    }
    hits
}

/// The code of `text`, line by line: a comment line is not code, and neither
/// is a line's trailing comment.
fn code_lines(text: &str) -> impl Iterator<Item = &str> {
    text.lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .map(|line| {
            line.split(" //")
                .next()
                .expect("split yields a first piece")
        })
}

/// Scan hits, one line each, for an assertion message.
fn render(hits: &[(PathBuf, String)]) -> String {
    let lines: Vec<String> = hits
        .iter()
        .map(|(file, code)| format!("{}: {code}", file.display()))
        .collect();
    lines.join("\n")
}

/// Every `.rs` file under `dir`, recursively; nothing when `dir` is absent.
fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<PathBuf> = entries
        .map(|e| e.expect("a readable entry").path())
        .collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|x| x == "rs") {
            out.push(path);
        }
    }
}
