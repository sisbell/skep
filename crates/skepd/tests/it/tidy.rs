//! THE LAYERING, CHECKED: `AGENTS.md`'s "skepd is layered; imports point
//! down", over the six layers `ARCHITECTURE.md` §The daemon draws.
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
//! module (`crate::codec::JsonCodec`), never through the crate root's
//! re-export (`crate::JsonCodec`): the root re-exports items of every
//! layer, so a path through it hides the layer it reaches.
//!
//! And THE TEST HOOKS, GATED: every item documented as a test hook — here,
//! and in `skep-signature` — compiles only under the `test-hooks` feature —
//! the second test below.

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
    ("server::blob_routes", 2),
    // 3 — the daemon's vocabulary.
    ("server::reply", 3),
    ("server::request", 3),
    ("server::scan", 3),
    // 4 — the session layer.
    ("auth", 4),
    // 5 — the write path, and the media door, gate and deposit read beside it.
    ("write_path", 5),
    ("media", 5),
    ("media::deposit_read", 5),
    ("media::gate", 5),
    // 6 — the leaves.
    ("codec", 6),
    ("history", 6),
    ("limits", 6),
    ("media::cell", 6),
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

/// THE TEST HOOKS, GATED: every item this crate documents as a test hook — a
/// doc line opening `TEST HOOK` or `The test seam` — compiles only under the
/// `test-hooks` feature (or `test`), gated on the item itself or on the `mod`
/// line of the file that holds it; and so does every one `skep-signature`
/// documents, whose `src` is read too. `Cargo.toml`'s `test-hooks` card
/// promises "a build that compiles no test compiles none of it"; and the
/// signature libraries' types appear only on hooks no shipped build carries,
/// in `skep-signature` — the one crate that links the signature libraries;
/// skepd calls its verify.
/// The gate's `--lib --bins` check proves the library COMPILES without the
/// feature, never that no hook ships in it: a hook whose gate is dropped
/// still compiles, and ships, with every other test green. Each of the two
/// roots must yield a marker of its own, so a crate whose markers were
/// reworded fails here rather than leaving its half of the check unread.
#[test]
fn every_test_hook_compiles_only_under_test_hooks() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut ungated = Vec::new();
    for src in [manifest.join("src"), manifest.join("../skep-signature/src")] {
        let mut files = Vec::new();
        rust_files(&src, &mut files);
        files.sort();
        let mut hooks = 0;
        for file in &files {
            let text = std::fs::read_to_string(file).unwrap();
            let lines: Vec<&str> = text.lines().collect();
            let file_gated = declared_under_the_gate(&src, &module_of(&src, file));
            let end = lines.iter().position(|l| l.trim() == "mod tests {").unwrap_or(lines.len());
            for (i, line) in lines[..end].iter().enumerate() {
                let doc = line.trim_start();
                if !(doc.starts_with("/// TEST HOOK") || doc.starts_with("/// The test seam")) {
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
                        "{}:{}: `{}` is documented as a test hook and compiles without \
                         `test-hooks`",
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
    }
    assert!(
        ungated.is_empty(),
        "every test hook compiles only under `test-hooks`; these do not:\n{}",
        ungated.join("\n")
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
/// (`codec::obj`) is harmless — layers match by prefix.
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
/// crate::{server::Daemon, codec::obj};`, on one line or across several),
/// each member of the group joined to it, a nested group's likewise. The
/// token alone is not enough there: `crate::` names no module and `super::`
/// only the parent, so a group would hide every module its members name.
fn named_paths(code: &[(usize, &str)]) -> Vec<(usize, String)> {
    // One text, and each byte's line, so a group may span lines.
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

/// Whether the `mod` line declaring `module`, in its parent's file, carries
/// the gate among the attributes directly above it — the whole file then
/// compiles only under it (`server/hooks.rs`, `fuzz_support.rs`).
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
