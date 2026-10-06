//! THE ARRANGEMENT, CHECKED: what `src/ceremony.rs` and `src/person.rs`
//! promise about where code lives, read off the crate's own source.
//!
//! THE CEREMONY'S LAYERS. Every in-crate module a `src/` file names in code
//! — the leading module segments of each `crate::…`, `super::…` and
//! `self::…` path, a brace group's members each read joined to the path
//! before it — keeps `ceremony`'s rule: outside `ceremony/` a file names no
//! ceremony module, the ceremonies standing on top of the crate; inside it a
//! COMPOSITION names no walk, and a WALK names no walk but its own — its
//! child modules (`claim::hosted`, `recover::loss`) naming their parent
//! included. What two walks share is a composition's. Exempt: `ceremony.rs`
//! naming its own children (the tree itself, not an import); comments, doc
//! links included; and tests — a `tests.rs` file, or everything from an
//! inline `mod tests {` on. A module under `ceremony/` in neither row of
//! [`WALKS`] and [`COMPOSITIONS`] fails until it is placed, and placing it
//! is the decision `ARCHITECTURE.md` §The client records.
//!
//! THE SCRIPTED PERSON, GATED: `person::scripted` compiles only under the
//! `test-hooks` feature (or `test`) — the second test below.

use std::path::{Path, PathBuf};

/// The walks, one gesture each.
const WALKS: &[&str] = &["accept", "claim", "enroll", "handoff", "recover", "retire", "rotate"];

/// The compositions every walk runs over.
const COMPOSITIONS: &[&str] =
    &["backup", "deposit", "enumerate", "first_session", "handshake", "import", "payload", "preview", "reads", "trail"];

#[test]
fn a_walk_names_no_other_walk_and_a_composition_names_none() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_files(&src, &mut files);
    files.sort();
    let modules: Vec<String> = files.iter().map(|f| module_of(&src, f)).collect();
    for row in WALKS.iter().chain(COMPOSITIONS) {
        assert!(
            modules.iter().any(|m| *m == format!("ceremony::{row}")),
            "row `{row}` names no module under src/ceremony/: drop it, and its line in ARCHITECTURE.md"
        );
    }
    let mut faults = Vec::new();
    for (file, module) in files.iter().zip(&modules) {
        if file.file_name().is_some_and(|n| n == "tests.rs") {
            continue;
        }
        let path = file.strip_prefix(&src).unwrap().display().to_string();
        let from = place(module);
        match from {
            Place::Root => continue, // the tree itself
            Place::Under(row) if !WALKS.contains(&row) && !COMPOSITIONS.contains(&row) => {
                faults.push(format!(
                    "src/{path}: `{module}` is in neither row: place it among WALKS or COMPOSITIONS, and in ARCHITECTURE.md"
                ));
                continue;
            }
            _ => {}
        }
        let text = std::fs::read_to_string(file).unwrap();
        let code: Vec<(usize, &str)> = code_lines(&text).collect();
        for (n, named_path) in named_paths(&code) {
            let Some(target) = resolve(module, &named_path) else { continue };
            let at = format!("src/{path}:{n}");
            match (from, place(&target)) {
                (_, Place::Outside) => {}
                (Place::Outside, _) => {
                    faults.push(format!("{at}: `{module}` names `{target}` — nothing outside `ceremony` names it"))
                }
                (Place::Under(own), Place::Under(named)) if named != own && WALKS.contains(&named) => {
                    let who = if WALKS.contains(&own) { "a walk names another walk" } else { "a composition names a walk" };
                    faults.push(format!("{at}: `{module}` names `{target}` — {who}"));
                }
                _ => {}
            }
        }
    }
    assert!(faults.is_empty(), "the ceremony's layers; these lines cross them:\n{}", faults.join("\n"));
}

/// THE SCRIPTED PERSON, GATED: `person::scripted`, the test double of the
/// `Person` seam, compiles only under `test-hooks` (or `test`), gated on its
/// `mod` line in `src/person.rs`. `Cargo.toml`'s `test-hooks` card promises
/// a build that compiles no test compiles none of it; the gate's
/// `--features acting` check proves the library COMPILES without the
/// feature, never that the module is not in it — a dropped gate still
/// compiles, and ships, with every other test green.
#[test]
fn the_scripted_person_compiles_only_under_test_hooks() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    assert!(src.join("person/scripted.rs").is_file(), "src/person/scripted.rs: the module this check reads has moved");
    let text = std::fs::read_to_string(src.join("person.rs")).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    let at = lines
        .iter()
        .position(|l| l.trim().ends_with("mod scripted;"))
        .expect("src/person.rs declares `mod scripted;`: the declaration this check reads has moved");
    let gated = lines[..at].iter().rev().take_while(|l| l.trim_start().starts_with("#[")).any(|l| is_gate(l.trim()));
    assert!(gated, "src/person.rs:{}: `{}` compiles without `test-hooks`", at + 1, lines[at].trim());
}

/// Where a module stands against the ceremony.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Place<'a> {
    /// Outside `ceremony`.
    Outside,
    /// `ceremony` itself.
    Root,
    /// Under `ceremony`, in the subtree of this child.
    Under(&'a str),
}

fn place(module: &str) -> Place<'_> {
    match module.strip_prefix("ceremony") {
        Some("") => Place::Root,
        Some(rest) => match rest.strip_prefix("::") {
            Some(rest) => Place::Under(rest.split("::").next().unwrap_or(rest)),
            None => Place::Outside,
        },
        None => Place::Outside,
    }
}

/// One path as written in `module`, resolved to the in-crate module it
/// names: `crate::` starts at the root, `self::` at `module`, each `super::`
/// one step up; the leading lowercase segments after that name the module.
/// A lowercase item riding along (`ceremony::payload::payload_text`) is
/// harmless — a place reads the first segments alone. `None` for a path
/// outside this crate.
fn resolve(module: &str, named_path: &str) -> Option<String> {
    let mut segments = named_path.split("::").filter(|s| !s.is_empty()).peekable();
    let mut base: Vec<&str> = match segments.next() {
        Some("crate") => Vec::new(),
        Some("self") => module.split("::").collect(),
        Some("super") => {
            let mut up: Vec<&str> = module.split("::").collect();
            up.pop();
            up
        }
        _ => return None,
    };
    while segments.peek() == Some(&"super") {
        segments.next();
        base.pop();
    }
    base.extend(segments.take_while(|s| s.starts_with(|c: char| c.is_ascii_lowercase())));
    Some(base.join("::"))
}

/// Every in-crate path the code names, with the line it starts on: each
/// `crate::…`, `super::…` and `self::…` token — a maximal run of identifier
/// characters and `:` — and, where one ends at a brace group (`use
/// crate::ceremony::{deposit::Grade, claim::hosted};`, on one line or across
/// several), each member of the group joined to it, a nested group's
/// likewise. The token alone is not enough there: `crate::` names no module
/// and `super::` only the parent, so a group would hide every module its
/// members name.
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

/// `src/ceremony/claim/hosted.rs` → `ceremony::claim::hosted`;
/// `src/ceremony.rs` → `ceremony`.
fn module_of(src: &Path, file: &Path) -> String {
    let relative = file.strip_prefix(src).unwrap().with_extension("");
    let mut segments: Vec<String> = relative.iter().map(|s| s.to_string_lossy().into_owned()).collect();
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
