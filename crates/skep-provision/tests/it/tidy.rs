//! THE ARRANGEMENT, CHECKED: what `src/main.rs` and `ARCHITECTURE.md` §The
//! provisioning service say about where this crate's code lives and what it
//! depends on, read off its own source and manifest — the compiler holds
//! none of it.
//!
//! THE TREE. Every file under `src/`, and under the test target's
//! `tests/it/`, is a module its parent declares — the compiler never reads a
//! file no `mod` names, and no build says so, so an undeclared file is code
//! never built or a suite never run. `src/main.rs` declares its modules in
//! dependency order, each with its map line, a `//` comment directly above
//! it (an attribute line between them, a `#[cfg(test)]`, is neither); every
//! `crate::…` path a module's files name in code — its fakes' and its
//! suite's among them — names that module or one declared above it, never
//! one below, and never an item through the root, which hides the module it
//! reaches. A module names its parent through `super::`, which is the tree
//! itself and not an edge between modules.
//!
//! THE DOCS. Every file under `src/` opens with its `//!` doc, and every
//! `pub` item and field outside a suite carries a `///` line:
//! `#![deny(missing_docs)]` reaches only what a crate exports, and a binary
//! exports nothing, so this is what holds a module's interface to its docs.
//!
//! THE EDGES. The crate depends on [`DEPENDENCIES`] alone — never `skepd`,
//! `skep-client` or a signer: the sidecar it runs dials the board, and it
//! dials nothing.
//!
//! Each scan asserts that it found what it allows — a file held to its
//! parent, an edge between modules, a documented item, the manifest's
//! dependency table — so a scan gone blind fails rather than passing a clean
//! tree. Comments are not code.

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};

/// The binary's root, the manifest's one `[[bin]]`: it declares every
/// module of the crate.
const ROOT: &str = "src/main.rs";

/// The crate's dependencies: the two skep crates — the record's parse and
/// the HTTP subset — `/health`'s body read, and OS entropy.
const DEPENDENCIES: [&str; 4] = ["getrandom", "serde_json", "skep-http", "skep-identity"];

#[test]
fn every_file_is_declared_and_every_root_declaration_says_what_it_holds() {
    let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut faults = undeclared_files(crate_dir, "src");
    faults.extend(undeclared_files(crate_dir, "tests/it"));
    let text = read(&crate_dir.join(ROOT));
    let lines: Vec<&str> = text.lines().collect();
    let mut declared = 0;
    for (i, line) in lines.iter().enumerate() {
        let Some(name) = declared_module(line.trim()) else { continue };
        declared += 1;
        let above = lines[..i].iter().rev().map(|l| l.trim()).find(|l| !l.starts_with("#["));
        if !above.is_some_and(|l| l.starts_with("// ")) {
            faults.push(format!("{ROOT}:{}: `mod {name};` has no map line — a `//` comment directly above it saying what the module holds", i + 1));
        }
    }
    assert!(declared > 1, "{ROOT} declares its modules as `mod name;` lines");
    assert!(faults.is_empty(), "the module tree does not hold:\n{}", faults.join("\n"));
}

#[test]
fn every_module_names_only_itself_and_modules_declared_above_it() {
    let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let src = crate_dir.join("src");
    let modules = modules_of(&crate_dir.join(ROOT));
    assert!(modules.len() > 1, "{ROOT} declares its modules as `mod name;` lines");
    let rank: HashMap<&str, usize> = modules.iter().enumerate().map(|(i, (m, _))| (m.as_str(), i)).collect();
    let (mut faults, mut edges) = (Vec::new(), 0);
    for (own, (module, file)) in modules.iter().enumerate() {
        let mut files = vec![file.clone()];
        rust_files(&file.with_extension(""), &mut files);
        for file in files {
            let text = read(&file);
            let shown = file.strip_prefix(&src).expect("under src").display().to_string();
            for (n, named) in crate_paths(&text) {
                match rank.get(named.as_str()) {
                    Some(&r) if r > own => faults.push(format!("src/{shown}:{n}: `crate::{named}` is declared below `{module}` in {ROOT}")),
                    Some(&r) => edges += usize::from(r < own),
                    None => faults.push(format!("src/{shown}:{n}: `crate::{named}` goes through the root {ROOT} — name the item by its home module")),
                }
            }
        }
    }
    assert!(edges > 0, "this check read no path between modules at all: the forms it reads have moved");
    assert!(faults.is_empty(), "a module names one declared below it, or an item through the root — move the item, reorder the root, or name the item's home module:\n{}", faults.join("\n"));
}

#[test]
fn every_file_and_every_pub_item_says_what_it_is() {
    let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let shown = |path: &Path| path.strip_prefix(crate_dir).expect("under the crate").display().to_string();
    let mut files = Vec::new();
    rust_files(&crate_dir.join("src"), &mut files);
    let (mut faults, mut documented) = (Vec::new(), 0);
    for file in &files {
        let text = read(file);
        if !text.starts_with("//!") {
            faults.push(format!("{}:1: the file opens with no `//!` doc saying what it holds", shown(file)));
        }
        // A suite's items are its own: no module names them.
        if file.file_name().is_some_and(|name| name == "tests.rs") {
            continue;
        }
        let lines: Vec<&str> = text.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            let item = line.trim();
            // A `pub mod` line's doc is the file it names, held above.
            if !(item.starts_with("pub ") || item.starts_with("pub(")) || declared_module(item).is_some() {
                continue;
            }
            let above = lines[..i].iter().rev().map(|l| l.trim()).find(|l| !l.starts_with("#["));
            if above.is_some_and(|l| l.starts_with("///")) {
                documented += 1;
            } else {
                faults.push(format!("{}:{}: `{item}` has no `///` line directly above it", shown(file), i + 1));
            }
        }
    }
    assert!(documented > 0, "this check read no `pub` item at all: the forms it reads have moved");
    assert!(faults.is_empty(), "a file or a `pub` item says nothing of what it is — in a binary `#![deny(missing_docs)]` reaches neither:\n{}", faults.join("\n"));
}

/// THE EDGES (`ARCHITECTURE.md`'s code map: of the skep crates
/// `skep-identity` and `skep-http` alone, never `skepd` or `skep-client`).
/// The compiler holds none of it: a dependency added to the manifest
/// builds, and every other test of the workspace stays green. Read off the
/// manifest's own text, as skep-registry's
/// `the_dependencies_are_skep_address_and_serde_json` reads its own: no
/// dependency table but `[dependencies]` and `[dev-dependencies]`, so none
/// arrives under a target or build table, and `[dependencies]` names the
/// four.
#[test]
fn the_dependencies_are_the_four() {
    let manifest = read(&Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"));
    let (mut table, mut dependency_tables, mut dependencies) = ("", BTreeSet::new(), BTreeSet::new());
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
    let allowed = BTreeSet::from(["[dependencies]", "[dev-dependencies]"]);
    assert!(dependency_tables.contains("[dependencies]") && dependency_tables.is_subset(&allowed), "Cargo.toml's dependency tables: {dependency_tables:?}");
    assert_eq!(dependencies, BTreeSet::from(DEPENDENCIES), "the crate's four");
}

/// The dependency a manifest line names, where it names one: the key ahead
/// of `=`, cut at its first dot (`serde_json.workspace = true`).
fn dependency_named(line: &str) -> Option<&str> {
    let (key, _) = line.split_once('=')?;
    let name = key.split('.').next()?.trim().trim_matches('"');
    let is_name = |c: char| c.is_ascii_alphanumeric() || c == '-' || c == '_';
    (!name.is_empty() && name.chars().all(is_name)).then_some(name)
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

/// The modules the root declares, in order, each with the file that holds
/// it: `name.rs` beside the root.
fn modules_of(root: &Path) -> Vec<(String, PathBuf)> {
    let dir = root.parent().expect("a root has a directory");
    read(root).lines().filter_map(|line| declared_module(line.trim())).map(|name| (name.to_string(), dir.join(format!("{name}.rs")))).collect()
}

/// Every file under the crate's `tree` that its parent does not declare, as
/// a fault naming both — the compiler never reads such a file, and no build
/// says so. The tree's root is its `main.rs`, for `src/` and for the test
/// target's `tests/it/` alike.
fn undeclared_files(crate_dir: &Path, tree: &str) -> Vec<String> {
    let dir = crate_dir.join(tree);
    let shown = |path: &Path| path.strip_prefix(crate_dir).expect("under the crate").display().to_string();
    let mut files = Vec::new();
    rust_files(&dir, &mut files);
    let (mut faults, mut held) = (Vec::new(), 0);
    for file in &files {
        let Some((parent, name)) = declared_by(&dir, file) else { continue };
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
/// the tree at `dir` — or `None` for the tree's root, its `main.rs`. A file
/// directly in the tree is declared by the root under its stem: `src/main.rs`
/// declares `args` for `src/args.rs`. A file in a subdirectory is declared by
/// the module that directory is named for, `x.rs` beside it or `x/mod.rs`
/// inside it: `src/docker/fake.rs` is `fake` to `src/docker.rs`.
fn declared_by(dir: &Path, file: &Path) -> Option<(PathBuf, String)> {
    let relative = file.strip_prefix(dir).ok()?;
    let mut parts: Vec<String> = relative.iter().map(|part| part.to_string_lossy().into_owned()).collect();
    let last = parts.pop()?;
    let name = match last.strip_suffix(".rs")? {
        "main" if parts.is_empty() => return None,
        "mod" => parts.pop()?,
        stem => stem.to_string(),
    };
    let parent = match parts.split_last() {
        None => dir.join("main.rs"),
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

/// A file's code lines, numbered from 1: a comment line is not code, and a
/// trailing ` //` comment is cut.
fn code_lines(text: &str) -> impl Iterator<Item = (usize, &str)> {
    text.lines().enumerate().filter(|(_, line)| !line.trim_start().starts_with("//")).map(|(i, line)| (i + 1, line.split(" //").next().unwrap_or(line)))
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
