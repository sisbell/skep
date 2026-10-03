//! THE MODULE MAP, CHECKED: `src/lib.rs` declares the crate's modules in
//! dependency order, each with a line saying what it holds, and states the
//! order's rule — each module names only modules above it and the root's own
//! `CoordinationWorld`, test code included. Two checks hold it.
//!
//! The first reads the trees' shape: every file under `src/`, and under the
//! test target's `tests/it/`, is a module its parent declares — the compiler
//! never reads a file no `mod` names, and no build says so — and every `src/`
//! declaration but a `tests` module carries its map line, a `//` comment
//! directly above it (an attribute between the two is allowed). A test-tree
//! parent names its children in its `//!` doc instead.
//!
//! The second reads the order: every path a `src/` file's code spells from
//! the root — every `crate::…` token, and every `super::…` token that climbs
//! to it, a brace group's members each read joined to it — names the file's
//! own module, a module declared above it, or `CoordinationWorld`. A path
//! through the root's re-exports (`crate::Coordinator`) hides the module it
//! reaches, so it is refused: code names an item by its home module. Files
//! under `src/coordinator/` belong to `coordinator`. Exempt: comments, doc
//! links included. Not exempt: tests, inline or in a `tests.rs` — the order
//! holds for test code too, which is why the test-only `fixture` sits above
//! its readers. How deep a line sits in inline modules is read off rustfmt's
//! indentation.
//!
//! The order check looks for violations a clean tree does not hold, so on
//! such a tree it passes whether its readers can see or not; it is held,
//! beside it, to the forms those readers exist for, where a reader gone
//! blind fails.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// The one root item a module may name through `crate::` — the world bound
/// the root defines rather than re-exports.
const ROOT_ITEM: &str = "CoordinationWorld";

#[test]
fn every_file_is_declared_and_every_declaration_says_what_it_holds() {
    let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut faults = undeclared_files(crate_dir, "src", "lib");
    faults.extend(undeclared_files(crate_dir, "tests/it", "main"));
    let src = crate_dir.join("src");
    let mut files = Vec::new();
    rust_files(&src, &mut files);
    files.sort();
    for file in &files {
        let path = file.strip_prefix(&src).unwrap().display().to_string();
        let text = std::fs::read_to_string(file).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            let Some(name) = declared_module(line.trim()) else { continue };
            if name == "tests" {
                continue;
            }
            let above = lines[..i].iter().rev().map(|l| l.trim()).find(|l| !l.starts_with("#["));
            if !above.is_some_and(|l| l.starts_with("// ")) {
                faults.push(format!(
                    "src/{path}:{}: `mod {name};` has no map line — a `//` comment directly above \
                     it saying what the module holds",
                    i + 1
                ));
            }
        }
    }
    assert!(faults.is_empty(), "the module tree does not hold:\n{}", faults.join("\n"));
}

#[test]
fn each_module_names_only_modules_above_it() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let root = std::fs::read_to_string(src.join("lib.rs")).unwrap();
    let order: Vec<&str> = root.lines().filter_map(|line| declared_module(line.trim())).collect();
    assert!(order.len() > 1, "lib.rs declares no module map this check can read");
    let rank = |module: &str| order.iter().position(|m| *m == module);
    let mut files = Vec::new();
    rust_files(&src, &mut files);
    files.sort();
    // (from, to) → where `from` first names `to`.
    let mut edges: BTreeMap<(String, String), String> = BTreeMap::new();
    let mut faults = Vec::new();
    for file in &files {
        let Some(module) = module_of(&src, file) else { continue };
        let text = std::fs::read_to_string(file).unwrap();
        let path = file.strip_prefix(&src).unwrap().display().to_string();
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
                    continue; // inside its own module: names no other
                }
                &segments[climbs..]
            };
            match from_root.first() {
                Some(&to) if rank(to).is_some() => {
                    if to != module {
                        let key = (module.clone(), to.to_string());
                        edges.entry(key).or_insert(format!("src/{path}:{line}"));
                    }
                }
                Some(&ROOT_ITEM) | None => {}
                Some(_) => faults.push(format!(
                    "src/{path}:{line}: `{named}` goes through the root's re-exports — name it \
                     by its home module"
                )),
            }
        }
    }
    assert!(
        !edges.is_empty(),
        "this check read no path between modules at all: the forms it reads have moved"
    );
    for ((from, to), at) in &edges {
        match (rank(from), rank(to)) {
            (Some(f), Some(t)) if t < f => {}
            _ => faults.push(format!(
                "{at}: `{from}` names `{to}`, which lib.rs declares below it — move the item, or \
                 the declaration"
            )),
        }
    }
    assert!(faults.is_empty(), "lib.rs's dependency order does not hold:\n{}", faults.join("\n"));
}

/// The order check looks for edges the tree does not have, and every path
/// `src/` spells between modules is a `use crate::<module>::…` line whose
/// first token names the module before any brace group — so the reader's
/// other forms are exercised by nothing there, and on a clean tree the check
/// passes whether they work or not. Held here to what each must yield: a
/// brace group at the ROOT, whose members each name their own module, with a
/// member's nested group and an `as` rename; a `super::` chain; a comment,
/// doc link or trailing comment naming a module, which names nothing; and a
/// path inside an inline `mod tests`, which is read — test code is held to
/// the order — at one level of inline depth. A reader that stopped expanding
/// the root's groups, or stopped at the test module, would pass every edge
/// spelled that way.
#[test]
fn the_order_readers_see_the_forms_src_does_not_spell() {
    let code = "use crate::{ast::Term as T,\n    value::{Sort, Value}};\n\
                let deep = super::super::check::X;\n";
    let paths: Vec<String> = named_paths(code).into_iter().map(|(_, path)| path).collect();
    assert_eq!(
        paths,
        ["crate::ast::Term", "crate::value::Sort", "crate::value::Value", "super::super::check::X"]
    );
    let text = "use crate::ast::Term; // crate::check::X\n\
                /// [`crate::eval::Y`]\n\
                #[cfg(test)]\n\
                mod tests {\n    use crate::fixture::every_former;\n}\n";
    let (code, at) = code_of(text);
    let read: Vec<(String, usize)> = named_paths(&code)
        .into_iter()
        .map(|(start, path)| (path, at[start].1))
        .collect();
    assert_eq!(
        read,
        [("crate::ast::Term".to_owned(), 0), ("crate::fixture::every_former".to_owned(), 1)]
    );
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
    let shown = |path: &Path| path.strip_prefix(crate_dir).unwrap().display().to_string();
    let mut files = Vec::new();
    rust_files(&dir, &mut files);
    files.sort();
    let (mut faults, mut held) = (Vec::new(), 0);
    for file in &files {
        let Some((parent, name)) = declared_by(&dir, root, file) else { continue };
        held += 1;
        let parent_text = std::fs::read_to_string(&parent).unwrap_or_default();
        if !parent_text.lines().any(|line| declared_module(line.trim()) == Some(name.as_str())) {
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
/// the tree at `dir` whose root file's stem is `root` — in `src/`, `lib.rs`
/// declares `ast` for `ast.rs` and `coordinator.rs` declares `defs` for
/// `coordinator/defs.rs`; in `tests/it/`, `main.rs` declares `pl` for
/// `pl.rs` and `pl.rs` declares `typing` for `pl/typing.rs` — or `None` for
/// the root itself.
fn declared_by(dir: &Path, root: &str, file: &Path) -> Option<(PathBuf, String)> {
    let relative = file.strip_prefix(dir).ok()?;
    let mut parts: Vec<String> =
        relative.iter().map(|part| part.to_string_lossy().into_owned()).collect();
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
            if flat.exists() { flat } else { base.join(sub).join("mod.rs") }
        }
    };
    Some((parent, name))
}

/// A file's code as one text, so a brace group may span lines — comment
/// lines dropped (a doc link is no import), a trailing ` //` comment cut —
/// and, per byte, the line it sits on and how many inline modules enclose it.
/// A test module is code like any other: the order holds for it too.
fn code_of(text: &str) -> (String, Vec<(usize, usize)>) {
    let (mut code, mut at) = (String::new(), Vec::new());
    // The indentation of each inline module open around the current line.
    let mut open: Vec<usize> = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let trimmed = line.trim();
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

/// Whether a trimmed line opens an inline module (`mod tests {`, `pub(crate)
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
/// and, where one ends at a brace group (`use crate::{ast::Term,
/// value::Sort};`), each member of the group joined to it.
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

/// The top-level module a `src/` file belongs to — `src/coordinator.rs`,
/// `src/coordinator/defs.rs` and `src/coordinator/engine.rs` alike are
/// `coordinator` — and `None` for the root, `lib.rs`.
fn module_of(src: &Path, file: &Path) -> Option<String> {
    let first = file.strip_prefix(src).ok()?.iter().next()?.to_string_lossy().into_owned();
    match first.strip_suffix(".rs") {
        Some("lib") => None,
        Some(stem) => Some(stem.to_string()),
        None => Some(first),
    }
}

/// How many modules deep a `src/` file's own module sits: `codec.rs` and
/// `codec/mod.rs` one, `codec/tests.rs` two — the `super::`s a file-level
/// path takes to reach the root.
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
