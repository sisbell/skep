//! THE LAYERING, CHECKED: `AGENTS.md`'s "skepd is layered; imports point
//! down", over the six layers `ARCHITECTURE.md` §The daemon draws.
//!
//! Every in-crate module a `src/` file names in code — the leading module
//! segments of each `crate::…`, `super::…` and `self::…` path — lies in
//! that file's own layer or below it. Exempt: a module naming its own
//! children (the tree itself, not an import across layers); comments, doc
//! links included; and tests — a `tests.rs` file, or everything from an
//! inline `mod tests {` on — which may reach whatever they test. An inline
//! test module is its file's last item, where `AGENTS.md` places it, and
//! that is checked too: a line after one is a line this check never reads.
//!
//! Two consequences meet a reader as failures. A module that fits no row of
//! [`LAYERS`] fails until it is placed, and placing it is the decision
//! `ARCHITECTURE.md` records. And code names an in-crate item by its home
//! module (`crate::codec::JsonCodec`), never through the crate root's
//! re-export (`crate::JsonCodec`): the root re-exports items of every
//! layer, so a path through it hides the layer it reaches.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// Module → layer, top (0) to bottom (6). A module takes the layer of its
/// LONGEST matching row, on `::` boundaries: `server::op` is a route by
/// `server`, `server::http` is transport by its own row.
const LAYERS: &[(&str, u8)] = &[
    // 0 — the fuzz harness, above the daemon it drives.
    ("fuzz_support", 0),
    // 1 — the transport.
    ("server::http", 1),
    ("server::listen", 1),
    // 2 — the routes.
    ("server", 2),
    // 3 — the daemon's vocabulary.
    ("server::reply", 3),
    ("server::request", 3),
    ("server::scan", 3),
    // 4 — the session layer.
    ("auth", 4),
    // 5 — the write path.
    ("write_path", 5),
    // 6 — the leaves.
    ("codec", 6),
    ("history", 6),
    ("limits", 6),
    ("notice", 6),
    ("permits", 6),
    ("serial", 6),
];

#[test]
fn every_module_names_only_its_own_layer_and_below() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_files(&src, &mut files);
    files.sort();
    let modules: Vec<String> = files.iter().map(|f| module_of(&src, f)).collect();
    let top: HashSet<&str> = modules.iter().filter_map(|m| m.split("::").next()).collect();
    for (row, _) in LAYERS {
        assert!(
            modules.iter().any(|m| m.as_str() == *row || m.starts_with(&format!("{row}::"))),
            "LAYERS row `{row}` names no module: drop it, and its line in ARCHITECTURE.md"
        );
    }
    let lib = std::fs::read_to_string(src.join("lib.rs")).unwrap();
    let reexported = root_reexports(&lib, &top);
    let mut faults = Vec::new();
    for (file, module) in files.iter().zip(&modules) {
        let name = file.file_name().unwrap().to_str().unwrap();
        if matches!(name, "lib.rs" | "main.rs" | "tests.rs") {
            continue;
        }
        let from = layer(module);
        let text = std::fs::read_to_string(file).unwrap();
        let path = file.strip_prefix(&src).unwrap().display();
        if let Some(n) = after_test_module(&text) {
            faults.push(format!(
                "src/{path}:{n}: a line after the inline `mod tests` — the test module is \
                 its file's last item, and this check reads a file only up to it"
            ));
        }
        for (n, line) in code_lines(&text) {
            for token in path_tokens(line) {
                let at = format!("src/{path}:{n}");
                match resolve(module, token, &top) {
                    Named::Module(target) => {
                        if target.starts_with(&format!("{module}::")) {
                            continue; // a module naming its own child
                        }
                        let to = layer(&target);
                        if to < from {
                            faults.push(format!(
                                "{at}: `{module}` (layer {from}) names `{target}` (layer {to})"
                            ));
                        }
                    }
                    Named::RootItem(item) if reexported.contains(item.as_str()) => {
                        faults.push(format!("{at}: `crate::{item}` — name it by its home module"));
                    }
                    Named::RootItem(_) | Named::Outside => {}
                }
            }
        }
    }
    assert!(faults.is_empty(), "imports point down; these lines do not:\n{}", faults.join("\n"));
}

/// What one path names.
enum Named {
    /// An in-crate module, by its path from the root.
    Module(String),
    /// An item the crate root holds: a re-export, or the root's own.
    RootItem(String),
    /// Something outside this crate.
    Outside,
}

/// One path token as written in `module`, resolved: `crate::` starts at
/// the root, `self::` at `module`, each `super::` one step up; the leading
/// lowercase segments after that name the module. A lowercase item riding
/// along (`codec::obj`) is harmless — layers match by prefix.
fn resolve(module: &str, token: &str, top: &HashSet<&str>) -> Named {
    let mut segments = token.split("::").filter(|s| !s.is_empty()).peekable();
    let mut base: Vec<&str> = match segments.next() {
        Some("crate") => Vec::new(),
        Some("self") => module.split("::").collect(),
        Some("super") => {
            let mut up: Vec<&str> = module.split("::").collect();
            up.pop();
            up
        }
        _ => return Named::Outside,
    };
    while segments.peek() == Some(&"super") {
        segments.next();
        base.pop();
    }
    let rest: Vec<&str> = segments.collect();
    if base.is_empty() {
        match rest.first() {
            None => return Named::Outside,
            Some(first) if !top.contains(first) => return Named::RootItem(first.to_string()),
            Some(_) => {}
        }
    }
    base.extend(rest.iter().take_while(|s| s.starts_with(|c: char| c.is_ascii_lowercase())));
    Named::Module(base.join("::"))
}

/// A code line's path-shaped tokens that start in this crate: maximal runs
/// of identifier characters and `:`, so `use super::{a, b}` yields
/// `super::` and `&crate::codec::X` yields `crate::codec::X`.
fn path_tokens(line: &str) -> impl Iterator<Item = &str> {
    line.split(|c: char| !(c.is_ascii_alphanumeric() || c == '_' || c == ':'))
        .filter(|t| ["crate::", "super::", "self::"].iter().any(|root| t.starts_with(root)))
}

/// A file's code lines, numbered from 1: comment lines dropped (a doc link
/// is no import), a trailing ` //` comment cut, and nothing from an inline
/// `mod tests {` on.
fn code_lines(text: &str) -> impl Iterator<Item = (usize, &str)> {
    text.lines()
        .enumerate()
        .take_while(|(_, line)| line.trim() != "mod tests {")
        .filter(|(_, line)| !line.trim_start().starts_with("//"))
        .map(|(i, line)| (i + 1, line.split(" //").next().unwrap_or(line)))
}

/// The line, numbered from 1, of the first top-level line that follows a
/// file's inline `mod tests {` — `None` where the module's own closing `}`,
/// its first line back at column 0, is the last, and `None` for a file with
/// no inline test module. A column-0 line before that brace is reported
/// too: the module's contents are indented, so it cannot be the module's.
fn after_test_module(text: &str) -> Option<usize> {
    let lines: Vec<&str> = text.lines().collect();
    let start = lines.iter().position(|line| line.trim() == "mod tests {")?;
    let mut top_level =
        (start + 1..lines.len()).filter(|&i| lines[i].starts_with(|c: char| !c.is_whitespace()));
    let first = top_level.next()?;
    let stray = if lines[first] == "}" { top_level.next()? } else { first };
    Some(stray + 1)
}

/// The names the crate root re-exports from its OWN modules (`pub use
/// server::{Daemon, …}`), which code outside the root reaches by their home
/// module. The engine and kernel types it re-exports (`crate::World`) are
/// not among them: those name no layer.
fn root_reexports(lib: &str, top: &HashSet<&str>) -> HashSet<String> {
    let code: String = code_lines(lib).map(|(_, line)| format!("{line}\n")).collect();
    let mut names = HashSet::new();
    for statement in code.split(';') {
        let Some((_, path)) = statement.split_once("pub use ") else { continue };
        let Some((head, items)) = path.trim().split_once("::") else { continue };
        if !top.contains(head) {
            continue;
        }
        for item in items.split(|c: char| matches!(c, '{' | '}' | ',')) {
            let item = item.trim().rsplit("::").next().unwrap_or("");
            if !item.is_empty() {
                names.insert(item.to_string());
            }
        }
    }
    names
}

/// The layer of `module`: its longest matching row's.
fn layer(module: &str) -> u8 {
    LAYERS
        .iter()
        .filter(|(row, _)| module == *row || module.starts_with(&format!("{row}::")))
        .max_by_key(|(row, _)| row.len())
        .map(|&(_, layer)| layer)
        .unwrap_or_else(|| {
            panic!("`{module}` is in no layer: place it in LAYERS and in ARCHITECTURE.md")
        })
}

/// `src/server/op.rs` → `server::op`; `src/write_path/feed.rs` and
/// `src/write_path/feed/mod.rs` alike → `write_path::feed`.
fn module_of(src: &Path, file: &Path) -> String {
    let relative = file.strip_prefix(src).unwrap().with_extension("");
    let mut segments: Vec<String> =
        relative.iter().map(|s| s.to_string_lossy().into_owned()).collect();
    if segments.len() > 1 && segments.last().is_some_and(|s| s == "mod") {
        segments.pop();
    }
    segments.join("::")
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
