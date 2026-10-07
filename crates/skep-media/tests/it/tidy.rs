//! THE LAYERING, CHECKED: `AGENTS.md`'s "imports point down", kept by this
//! crate for its own two layers, which `ARCHITECTURE.md` §The media
//! resource draws — THE RESOURCE: the door, the gate, the index, the pruner
//! and the serve, which name one another sideways and the leaves below; over
//! THE LEAVES: the two cells and the limits, which name nothing of the
//! resource. The daemon, the stores, the blob store and `skep-util` are
//! other crates: a path into one is a path outside this crate, which this
//! check reads as it reads any other crate's.
//!
//! Every in-crate module a `src/` file names in code — the leading module
//! segments of each `crate::…`, `super::…` and `self::…` path, a brace
//! group's members each read joined to the path before it — lies in that
//! file's own layer or below it. Exempt: a module naming its own children
//! (the tree itself, not an import across layers); comments, doc links
//! included; and tests — a `tests.rs` file, or everything from an inline
//! `mod tests {` on — which may reach whatever they test. An inline test
//! module is its file's last item, where `AGENTS.md` places it, and that is
//! checked too: a line after one is a line this check never reads.
//!
//! Two consequences meet a reader as failures. A module that fits no row of
//! [`LAYERS`] fails until it is placed, and placing it is the decision
//! `ARCHITECTURE.md` records. And code names an in-crate item by its home
//! module, never through a re-export of the crate root's: the root
//! re-exports items of every layer, so a path through it hides the layer it
//! reaches.
//!
//! Then THE TEST HOOKS, GATED: every item this crate documents as a test
//! hook or a test seam compiles only under the `test-hooks` feature — the
//! second test. And THE SURFACE IS THE DAEMON's NEED: every `pub` item is
//! named in the crate's `README.md`, or is such a hook, `#[doc(hidden)]`
//! under the feature — the third.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// Module → layer, top (0) to bottom (1). A module takes the layer of its
/// LONGEST matching row, on `::` boundaries.
const LAYERS: &[(&str, u8)] = &[
    // 0 — the resource: the door, the gate, the index, the pruner, the serve.
    ("door", 0),
    ("gate", 0),
    ("index", 0),
    ("pruner", 0),
    ("serve", 0),
    // 1 — the leaves: the two cells, and the limits.
    ("blind", 1),
    ("cell", 1),
    ("limits", 1),
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
        if matches!(name, "lib.rs" | "tests.rs") {
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
        let code: Vec<(usize, &str)> = code_lines(&text).collect();
        for (n, named_path) in named_paths(&code) {
            let at = format!("src/{path}:{n}");
            match resolve(module, &named_path, &top) {
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
    assert!(faults.is_empty(), "imports point down; these lines do not:\n{}", faults.join("\n"));
}

/// THE TEST HOOKS, GATED: every item this crate documents as a test hook or
/// a test seam — a doc line opening `TEST HOOK`, `TEST SEAM` or `The test
/// seam` — compiles only under the `test-hooks` feature (or `test`), gated
/// on the item itself or on the `mod` line of the file that holds it.
/// `Cargo.toml`'s `test-hooks` card promises "a build that compiles no test
/// compiles none of it". The gate's `--lib` check proves the library
/// COMPILES without the feature, never that no hook ships in it: a hook
/// whose gate is dropped still compiles, and ships, with every other test
/// green. The root must yield a marker, so a crate whose markers were
/// reworded fails here rather than leaving the check unread.
#[test]
fn every_test_hook_compiles_only_under_test_hooks() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let src = manifest.join("src");
    let mut files = Vec::new();
    rust_files(&src, &mut files);
    files.sort();
    let mut hooks = 0;
    let mut ungated = Vec::new();
    for file in &files {
        let text = std::fs::read_to_string(file).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        let file_gated = declared_under_the_gate(&src, &module_of(&src, file));
        let end = lines.iter().position(|l| l.trim() == "mod tests {").unwrap_or(lines.len());
        for (i, line) in lines[..end].iter().enumerate() {
            let doc = line.trim_start();
            if !(doc.starts_with("/// TEST HOOK")
                || doc.starts_with("/// TEST SEAM")
                || doc.starts_with("/// The test seam"))
            {
                continue;
            }
            hooks += 1;
            let mut j = i;
            while j < lines.len() && lines[j].trim_start().starts_with("///") {
                j += 1;
            }
            let (attributes, item) = attributes_from(&lines, j);
            if !file_gated && !attributes.iter().any(|a| is_gate(a)) {
                ungated.push(format!(
                    "{}:{}: `{}` is documented as a test hook and compiles without `test-hooks`",
                    file.strip_prefix(manifest).unwrap().display(),
                    item + 1,
                    lines.get(item).map_or("", |l| l.trim()),
                ));
            }
        }
    }
    assert!(
        hooks > 0,
        "no test hook found under {}: the markers this check reads have moved",
        src.display()
    );
    assert!(
        ungated.is_empty(),
        "every test hook compiles only under `test-hooks`; these do not:\n{}",
        ungated.join("\n")
    );
}

/// THE SURFACE IS THE DAEMON's NEED (`CONTRIBUTING.md`: "A crate's
/// `README.md` describes its public surface, and a change to that surface
/// keeps it true"): every `pub` item of the library — a module, a type, a
/// function or method, a constant, a static; `pub`, never `pub(crate)` — is
/// named in `README.md` inside a backtick span (by its own name, or as
/// `Type::name`), or is a hook: `#[doc(hidden)]` and gated under
/// `test-hooks` itself, or a method of an `impl` block so gated, whose type
/// is such a hook. A field is its struct's, a test module is read by
/// nothing, and a `pub use` names no item of this crate's own.
#[test]
fn every_pub_item_is_named_in_the_readme_or_is_a_hidden_hook() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let readme = std::fs::read_to_string(manifest.join("README.md")).unwrap();
    // Every identifier inside a backtick span of the README.
    let named: HashSet<String> = readme
        .split('`')
        .skip(1)
        .step_by(2)
        .flat_map(|span| {
            span.split(|c: char| !(c.is_alphanumeric() || c == '_'))
                .filter(|t| !t.is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .collect();
    let src = manifest.join("src");
    let mut files = Vec::new();
    rust_files(&src, &mut files);
    files.sort();
    let (mut items, mut faults) = (0, Vec::new());
    for file in &files {
        if file.file_name().is_some_and(|n| n == "tests.rs") {
            continue;
        }
        let text = std::fs::read_to_string(file).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        let end = lines.iter().position(|l| l.trim() == "mod tests {").unwrap_or(lines.len());
        for (i, line) in lines[..end].iter().enumerate() {
            let Some(rest) = line.trim_start().strip_prefix("pub ") else { continue };
            let mut words = rest.split_whitespace();
            let keyword = words.next().unwrap_or("");
            if !matches!(
                keyword,
                "fn" | "struct" | "enum" | "const" | "static" | "mod" | "type" | "trait"
            ) {
                continue; // a field, or a `pub use`
            }
            let name: String = words
                .next()
                .unwrap_or("")
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            items += 1;
            if named.contains(&name) {
                continue;
            }
            let attributes = attributes_above(&lines, i);
            let hidden = attributes.iter().any(|a| a == "#[doc(hidden)]");
            let gated = attributes.iter().any(|a| is_gate(a));
            if (hidden && gated) || enclosing_impl_is_gated(&lines, i) {
                continue;
            }
            faults.push(format!(
                "{}:{}: `{name}` is `pub`, named nowhere in README.md, and no hidden hook",
                file.strip_prefix(manifest).unwrap().display(),
                i + 1
            ));
        }
    }
    assert!(items > 0, "no `pub` item found under {}", src.display());
    assert!(
        faults.is_empty(),
        "every `pub` item is in the README's surface or a hidden hook; these are neither:\n{}",
        faults.join("\n")
    );
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

/// One path as written in `module` — a token, or a brace group's member
/// joined to the path before it — resolved: `crate::` starts at the root,
/// `self::` at `module`, each `super::` one step up; the leading lowercase
/// segments after that name the module. A lowercase item riding along
/// (`cell::classify`) is harmless — layers match by prefix.
fn resolve(module: &str, named_path: &str, top: &HashSet<&str>) -> Named {
    let mut segments = named_path.split("::").filter(|s| !s.is_empty()).peekable();
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

/// Every in-crate path the code names, with the line it starts on: each
/// `crate::…`, `super::…` and `self::…` token — a maximal run of identifier
/// characters and `:` — and, where one ends at a brace group (`use
/// crate::{gate::MediaGate, cell};`, on one line or across several), each
/// member of the group joined to it, a nested group's likewise.
fn named_paths(code: &[(usize, &str)]) -> Vec<(usize, String)> {
    let mut text = String::new();
    let mut line_of = Vec::new();
    for &(n, line) in code {
        text.push_str(line);
        text.push('\n');
        line_of.resize(text.len(), n);
    }
    let is_path = |b: u8| b.is_ascii_alphanumeric() || b == b'_' || b == b':';
    let bytes = text.as_bytes();
    let mut paths = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if !is_path(bytes[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < bytes.len() && is_path(bytes[i]) {
            i += 1;
        }
        let token = &text[start..i];
        if !["crate::", "super::", "self::"].iter().any(|root| token.starts_with(root)) {
            continue;
        }
        let after = text[i..].trim_start();
        if token.ends_with("::") && after.starts_with('{') {
            let (members, end) = brace_group(&text, text.len() - after.len());
            paths.extend(members.into_iter().map(|m| (line_of[start], format!("{token}{m}"))));
            i = end;
        } else {
            paths.push((line_of[start], token.to_string()));
        }
    }
    paths
}

/// The members of the brace group whose `{` is at byte `open` of `text`, each
/// expanded to a path ([`expand_member`]), and the byte just past its `}`.
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

/// The attributes from `lines[at]` on — each `#[…]`, a multi-line one joined
/// into one — and the index of the line past them: the item they attach to.
fn attributes_from(lines: &[&str], mut at: usize) -> (Vec<String>, usize) {
    let mut attributes = Vec::new();
    while at < lines.len() && lines[at].trim_start().starts_with("#[") {
        let mut attribute = String::new();
        let mut depth = 0i64;
        while at < lines.len() {
            let line = lines[at].trim();
            attribute.push_str(line);
            depth += line.matches('[').count() as i64 - line.matches(']').count() as i64;
            at += 1;
            if depth <= 0 {
                break;
            }
            attribute.push(' ');
        }
        attributes.push(attribute);
    }
    (attributes, at)
}

/// The attributes directly above the item at `lines[item]` — the block
/// walked up to its first `#[` line, a multi-line attribute's continuation
/// lines (which end in `]` and open no attribute of their own) stepped over.
fn attributes_above(lines: &[&str], item: usize) -> Vec<String> {
    let mut start = item;
    while start > 0 {
        let above = lines[start - 1].trim();
        let opens = above.starts_with("#[");
        let continues = above.ends_with(']') && !above.starts_with("//") && !opens;
        if opens || continues {
            start -= 1;
        } else {
            break;
        }
    }
    attributes_from(lines, start).0
}

/// Whether the item at `lines[item]` sits inside an `impl` block whose own
/// attributes carry the gate: the first column-0 line above it is that
/// block's `impl` line, and the attributes above that line are read.
fn enclosing_impl_is_gated(lines: &[&str], item: usize) -> bool {
    if !lines[item].starts_with(char::is_whitespace) {
        return false;
    }
    let Some(head) = (0..item)
        .rev()
        .find(|&k| !lines[k].is_empty() && !lines[k].starts_with(char::is_whitespace))
    else {
        return false;
    };
    lines[head].starts_with("impl") && attributes_above(lines, head).iter().any(|a| is_gate(a))
}

/// Whether the `mod` line declaring `module`, in its parent's file, carries
/// the gate among the attributes directly above it — the whole file then
/// compiles only under it.
fn declared_under_the_gate(src: &Path, module: &str) -> bool {
    let (parent, name) = module.rsplit_once("::").unwrap_or(("", module));
    let parent_file = if parent.is_empty() {
        src.join("lib.rs")
    } else {
        let flat = src.join(format!("{}.rs", parent.replace("::", "/")));
        if flat.exists() {
            flat
        } else {
            src.join(parent.replace("::", "/")).join("mod.rs")
        }
    };
    let Ok(text) = std::fs::read_to_string(parent_file) else { return false };
    let lines: Vec<&str> = text.lines().collect();
    let declaration = format!("mod {name};");
    let Some(at) = lines.iter().position(|l| l.trim().ends_with(&declaration)) else {
        return false;
    };
    lines[..at]
        .iter()
        .rev()
        .take_while(|l| l.trim_start().starts_with("#["))
        .any(|l| is_gate(l.trim()))
}

/// A `cfg` attribute that confines what it gates to test builds: the
/// `test-hooks` feature, or `test` itself.
fn is_gate(attribute: &str) -> bool {
    attribute.starts_with("#[cfg(")
        && !attribute.contains("not(")
        && (attribute.contains(r#"feature = "test-hooks""#) || attribute == "#[cfg(test)]")
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

/// The names the crate root re-exports from its OWN modules (`pub use
/// gate::{…}`), which code outside the root reaches by their home module.
/// The root's own items (`MediaOptions`, `UploadPool`) and another crate's
/// re-exports are not among them: those name no layer.
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

/// `src/gate.rs` → `gate`; `src/gate/tests.rs` → `gate::tests`.
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
