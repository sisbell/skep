//! THE ARRANGEMENT, CHECKED: what `src/lib.rs` and `ARCHITECTURE.md` §The
//! shell's core promise about where code lives, read off the crate's own
//! source.
//!
//! THE ORDER. Every in-crate module a `src/` file names in code — the
//! leading module segment of each `crate::…`, `super::…` and `self::…`
//! path, a brace group's members each read joined to the path before it —
//! is declared ABOVE that file's own module in `src/lib.rs`, so the modules
//! stand in the one order the root's map lists them in and no edge between
//! two of them runs upward. A path to an item the root DEFINES
//! (`crate::Talk`) names no module; a path to one the root RE-EXPORTS
//! (`crate::Shell`, brought in by `pub use shell::…`) names the module it is
//! brought from, so a re-export is no way around the order. Exempt:
//! `lib.rs` itself (the tree, not an import);
//! comments, doc links included; and tests — a `tests.rs` file, or
//! everything from an inline `mod tests {` on, which may reach whatever
//! they test. An inline test module is its file's last item, where
//! `AGENTS.md` places it, and that is checked too: a line after one is a
//! line this check never reads. A file under `src/` whose module no `mod`
//! line in `src/lib.rs` declares fails as well — cargo, clippy and every
//! test pass over such a file in silence.
//!
//! THE SURFACE. `src/lib.rs` declares exactly three public modules —
//! `events`, `script` and `shapes`, what a transport reads of the crate
//! beside the root's re-exports — and every other module private, so a
//! module widened by a stray `pub` fails here rather than in the dependent
//! that grew onto it.
//!
//! THE DOOR. `Shell` answers the page's calls through `call`, which logs
//! each, and `fetch`, which streams and its transport logs: every row
//! method is private, so no call is served past the log. Its public methods
//! are listed in [`SHELL_PUBLIC`]: a row method made public fails, and a
//! new public method is a decision that list records. That `call` answers
//! every name of `CALLS` is the compiler's to hold, not this file's: the
//! dispatch matches `src/shell.rs`'s `Call` with one arm per variant, and
//! `CALLS` is spelled from that enum's list.

use std::path::{Path, PathBuf};

/// The public modules: the event names, the script's grammar, the
/// declarations.
const PUBLIC: &[&str] = &["events", "script", "shapes"];

/// `Shell`'s public methods, in their order in `src/shell.rs`: the open,
/// the stream and the log a transport serves, the run's facts, the one
/// door and the stream beside it, the page's two answers, and the stop.
const SHELL_PUBLIC: &[&str] = &[
    "open",
    "bus",
    "subscribe",
    "log",
    "arm_is_script",
    "board_references",
    "set_node_state",
    "check_signed_key",
    "call",
    "fetch",
    "answer",
    "cancel",
    "shutdown",
];

#[test]
fn every_module_names_only_modules_declared_above_it() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let order: Vec<String> = declared(&src).into_iter().map(|(module, _)| module).collect();
    let reexports = reexported(&src);
    let mut files = Vec::new();
    rust_files(&src, &mut files);
    files.sort();
    let mut faults = Vec::new();
    for file in &files {
        let path = file.strip_prefix(&src).unwrap().display().to_string();
        let module = module_of(&src, file);
        if module == "lib" || file.file_name().is_some_and(|n| n == "tests.rs") {
            continue;
        }
        let own = module.split("::").next().unwrap_or(&module);
        let Some(rank) = order.iter().position(|m| m == own) else {
            faults.push(format!("src/{path}: `{own}` is declared by no `mod` line in src/lib.rs: declare it, or delete the file"));
            continue;
        };
        let text = std::fs::read_to_string(file).unwrap();
        if let Some(n) = after_test_module(&text) {
            faults.push(format!("src/{path}:{n}: a line after the inline `mod tests` — the test module is the file's last item"));
        }
        let code: Vec<(usize, &str)> = code_lines(&text).collect();
        for (n, named_path) in named_paths(&code) {
            let Some(target) = resolve(&module, &named_path, &reexports) else { continue };
            let Some(named) = target.split("::").next().filter(|m| !m.is_empty() && *m != own) else { continue };
            match order.iter().position(|m| m == named) {
                Some(r) if r < rank => {}
                Some(_) => faults.push(format!("src/{path}:{n}: `{module}` names `{target}`, which src/lib.rs declares below it")),
                None => faults.push(format!("src/{path}:{n}: `{module}` names `{target}`, which src/lib.rs declares no module for")),
            }
        }
    }
    assert!(faults.is_empty(), "the declaration order of src/lib.rs; these lines cross it:\n{}", faults.join("\n"));
}

#[test]
fn the_public_modules_are_events_script_and_shapes() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let public: Vec<String> = declared(&src).into_iter().filter(|(_, public)| *public).map(|(module, _)| module).collect();
    assert_eq!(
        public, PUBLIC,
        "src/lib.rs's public modules: a module made public is surface a dependent grows onto — re-export the item it needs from the root instead"
    );
}

#[test]
fn the_shell_answers_calls_through_one_door() {
    let text = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/shell.rs")).unwrap();
    let body: Vec<&str> = text
        .lines()
        .skip_while(|line| *line != "impl Shell {")
        .skip(1)
        .take_while(|line| *line != "}")
        .collect();
    assert!(!body.is_empty(), "src/shell.rs holds no `impl Shell {{` block: the block this check reads has moved");
    let public: Vec<&str> = body.iter().filter_map(|line| line.strip_prefix("    pub fn ")?.split(['(', '<']).next()).collect();
    assert_eq!(
        public, SHELL_PUBLIC,
        "`Shell`'s public methods: a call's row reaches the page through `call`, which logs it — keep the row private, or record a new door here"
    );
    assert!(skep_shell::CALLS.contains(&"fetch") && skep_shell::CALLS.iter().filter(|c| SHELL_PUBLIC.contains(c)).eq([&"fetch"]), "of the calls, `fetch` alone is a public method");
}

/// The modules `src/lib.rs` declares, in order, each with whether it is
/// public.
fn declared(src: &Path) -> Vec<(String, bool)> {
    let text = std::fs::read_to_string(src.join("lib.rs")).unwrap();
    let declared: Vec<(String, bool)> = text
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            let (public, rest) = match line.strip_prefix("pub ") {
                Some(rest) => (true, rest),
                None => (false, line),
            };
            let module = rest.strip_prefix("mod ")?.strip_suffix(';')?;
            Some((module.trim().to_string(), public))
        })
        .collect();
    assert!(!declared.is_empty(), "src/lib.rs declares no module: the declarations this check reads have moved");
    declared
}

/// The items `src/lib.rs` re-exports, each with the module it is brought
/// from: `pub use events::{Event, EventBus};` gives `Event` and `EventBus` in
/// `events`, and `use a::B as C;` gives `C` in `a`. A `use` of no module
/// `src/lib.rs` declares (`std::…`) gives nothing.
fn reexported(src: &Path) -> Vec<(String, String)> {
    let declared: Vec<String> = declared(src).into_iter().map(|(module, _)| module).collect();
    let text = std::fs::read_to_string(src.join("lib.rs")).unwrap();
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        let Some(rest) = ["pub use ", "pub(crate) use ", "use "].iter().find_map(|p| line.strip_prefix(p)) else { continue };
        let Some((module, items)) = rest.trim_end_matches(';').split_once("::") else { continue };
        if !declared.iter().any(|m| m == module) {
            continue;
        }
        let items = items.trim_start_matches('{').trim_end_matches('}');
        for item in items.split(',').map(str::trim).filter(|i| !i.is_empty()) {
            let name = item.rsplit(" as ").next().unwrap_or(item).rsplit("::").next().unwrap_or(item);
            out.push((name.trim().to_string(), module.to_string()));
        }
    }
    out
}

/// One path as written in `module`, resolved to the in-crate module path it
/// names: `crate::` starts at the root, `self::` at `module`, each `super::`
/// one step up; the leading lowercase segments after that name the module,
/// and an item the root re-exports (`reexports`) names the module it is
/// brought from. `None` for a path outside this crate.
fn resolve(module: &str, named_path: &str, reexports: &[(String, String)]) -> Option<String> {
    let mut segments = named_path.split("::").filter(|s| !s.is_empty()).peekable();
    let mut base: Vec<&str> = match segments.next() {
        Some("crate") => {
            if let Some((_, from)) = segments.peek().and_then(|item| reexports.iter().find(|(name, _)| name == item)) {
                return Some(from.clone());
            }
            Vec::new()
        }
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
/// crate::refusal::{Name, Refusal};`, on one line or across several), each
/// member of the group joined to it, a nested group's likewise: `crate::`
/// alone names no module, so a group would hide every module its members
/// name.
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

/// One member of a brace group as the paths it names: `a::b` itself,
/// `a::{b, c}` as `a::b` and `a::c`, `x as y` as `x`, and an empty member —
/// a trailing comma — as none.
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
    let mut top_level = (start + 1..lines.len()).filter(|&i| lines[i].starts_with(|c: char| !c.is_whitespace()));
    let first = top_level.next()?;
    let stray = if lines[first] == "}" { top_level.next()? } else { first };
    Some(stray + 1)
}

/// `src/shell/tests.rs` → `shell::tests`; `src/feed.rs` → `feed`.
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
