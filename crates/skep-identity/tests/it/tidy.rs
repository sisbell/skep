//! THE MODULE MAP, CHECKED: the three facts `lib.rs`'s "What lives here"
//! states about how this crate's modules name one another — `state`, the
//! fold, is named by no other module; `entry`, the signed-ops frame, names
//! only `framing`; and `write_types`, the write path's classes, names only
//! `shape`.
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

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// The module no other module names: the fold, on top.
const ON_TOP: &str = "state";

/// Each leaf, and the only siblings it names.
const LEAVES: &[(&str, &[&str])] = &[("entry", &["framing"]), ("write_types", &["shape"])];

#[test]
fn the_fold_sits_on_top_and_entry_and_write_types_are_leaves() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_files(&src, &mut files);
    files.sort();
    let modules: BTreeSet<String> = files.iter().filter_map(|f| home_of(&src, f)).collect();
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
        let Some(home) = home_of(&src, file) else { continue };
        if file.file_name().is_some_and(|name| name == "tests.rs") {
            continue;
        }
        let text = std::fs::read_to_string(file).unwrap();
        let path = file.strip_prefix(&src).unwrap().display().to_string();
        if let Some(n) = after_test_module(&text) {
            faults.push(format!(
                "src/{path}:{n}: a line after the inline `mod tests` — the test module is its \
                 file's last item, and this check reads a file only up to it"
            ));
        }
        let depth = module_depth(&src, file);
        let (code, at) = code_of(&text);
        for (start, named) in named_paths(&code) {
            let (line, inline_depth) = at[start];
            let segments: Vec<&str> = named.split("::").filter(|s| !s.is_empty()).collect();
            let from_root = if segments[0] == "crate" {
                &segments[1..]
            } else {
                let climbs = segments.iter().take_while(|s| **s == "super").count();
                if climbs < inline_depth + depth {
                    continue; // inside its own module: names no sibling
                }
                &segments[climbs..]
            };
            match from_root.first() {
                Some(&to) if modules.contains(to) => {
                    if to != home {
                        let key = (home.clone(), to.to_string());
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

/// A file's code as one text, so a brace group may span lines — comment
/// lines dropped (a doc link is no import), a trailing ` //` comment cut,
/// nothing from an inline `mod tests {` on — and, per byte, the line it sits
/// on and how many inline modules enclose it.
fn code_of(text: &str) -> (String, Vec<(usize, usize)>) {
    let (mut code, mut at) = (String::new(), Vec::new());
    // The indentation of each inline module open around the current line.
    let mut open: Vec<usize> = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed == "mod tests {" {
            break;
        }
        if trimmed.starts_with("//") {
            continue;
        }
        let indent = line.len() - line.trim_start().len();
        if trimmed == "}" && open.last() == Some(&indent) {
            open.pop();
        }
        code.push_str(line.split(" //").next().unwrap_or(line));
        code.push('\n');
        at.resize(code.len(), (i + 1, open.len()));
        if opens_inline_module(trimmed) {
            open.push(indent);
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

/// Every path the code names from `crate::` or `super::`, with the byte it
/// starts at: each token — a maximal run of identifier characters and `:` —
/// and, where one ends at a brace group (`use crate::{key::Fingerprint,
/// keyset::KeySet};`), each member of the group joined to it.
fn named_paths(code: &str) -> Vec<(usize, String)> {
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
        let token = &code[start..i];
        if !(token.starts_with("crate::") || token.starts_with("super::")) {
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

/// The line, numbered from 1, of the first top-level line that follows a
/// file's inline `mod tests {` — `None` where the module's own closing `}`,
/// its first line back at column 0, is the last, and `None` for a file with
/// no inline test module.
fn after_test_module(text: &str) -> Option<usize> {
    let lines: Vec<&str> = text.lines().collect();
    let start = lines.iter().position(|line| line.trim() == "mod tests {")?;
    let mut top_level =
        (start + 1..lines.len()).filter(|&i| lines[i].starts_with(|c: char| !c.is_whitespace()));
    let first = top_level.next()?;
    let stray = if lines[first] == "}" { top_level.next()? } else { first };
    Some(stray + 1)
}

/// The top-level module a `src/` file belongs to — `src/entry.rs`,
/// `src/entry/mod.rs` and `src/entry/row.rs` alike are `entry` — and `None`
/// for the root, `lib.rs`.
fn home_of(src: &Path, file: &Path) -> Option<String> {
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
