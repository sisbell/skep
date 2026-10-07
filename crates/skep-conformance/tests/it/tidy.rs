//! THE MODULE MAP, CHECKED: `src/lib.rs` declares this crate's modules in
//! dependency order, each with a line saying what it holds and each naming
//! in code only the modules above it, and this is that sentence as tests.
//!
//! The tree's shape: every file under `src/`, and under the test target's
//! `tests/it/`, is a module its parent declares — the compiler never reads
//! a file no `mod` names, and no build says so, so an undeclared suite file
//! is a suite that never runs — and every `src/` declaration but a `tests`
//! module carries its map line, a `//` comment directly above it.
//!
//! Every `crate::…` path a module's files name in code — its tests included,
//! comments and doc links not — names that module or one declared above it.
//! A path through the root hides the module it reaches, so it is refused:
//! code names an item by its home module (`crate::loader::conformance_dir`).
//! A module's children name their parent through `super::`, which is the
//! tree itself and not an edge between modules. The check counts the paths
//! it reads between modules, so a check gone blind fails rather than passing
//! a clean tree.
//!
//! Four rules no compiler error reports are held the same way. Every
//! request reaches skep through the rig's door, `rig::execute`, which names
//! a panic raised inside skep as skep's, so exactly one code line under
//! `src/` calls `OperationSurface::execute`, and it is in `rig.rs`. Every
//! scenario document is created by `Rig::create_private_document`, so no
//! code line under `src/` but `rig.rs` builds a CREATENEWDOCUMENT request.
//! The play pass changes the golden-side world only through the `Cx`
//! world-change methods, so no code line in `play/` or `runner.rs` mutates
//! the shadow's documents, names or links. And every adaptation tag the
//! code can record is named in `play`'s policy catalogue. Each scan asserts
//! it found the owner's own lines, so a scan that matches nothing fails
//! rather than passing a clean tree.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

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
                    None => faults.push(format!(
                        "{shown}: `crate::{named}` goes through the root — name the item by \
                         its home module"
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

/// Every request reaches skep through `rig::execute`, the one call of
/// `OperationSurface::execute`, which resumes a panic raised inside skep as
/// skep's own (`rig::EnginePanic`). A call made anywhere else would let such
/// a panic report as the harness's — a failure of skep's totality read as a
/// harness bug — so exactly one code line under `src/` calls `.execute(`,
/// and it is in `rig.rs`.
#[test]
fn only_the_rig_door_executes_a_request() {
    let calls = scan(|code| code.contains(".execute("));
    assert!(
        matches!(calls.as_slice(), [(file, _)] if file == Path::new("rig.rs")),
        "exactly one code line, the door in `rig.rs`, calls `OperationSurface::execute`:\n{}",
        render(&calls)
    );
}

/// Every scenario document is minted PRIVATE (PUB-8.16) in the current
/// session's own account, and `Rig::create_private_document` is the one
/// place that says so. A file that built the request itself could name
/// another account or another publication flag, and nothing would refuse it
/// but the goldens drifting: so no file under `src/` but `rig.rs` names
/// `CreateNewDocument`.
#[test]
fn only_the_rig_builds_a_create_new_document() {
    let (rig, elsewhere): (Vec<_>, Vec<_>) = scan(|code| code.contains("CreateNewDocument"))
        .into_iter()
        .partition(|(file, _)| file == Path::new("rig.rs"));
    assert!(
        elsewhere.is_empty(),
        "only `rig.rs` builds a CREATENEWDOCUMENT request; a scenario document is \
         created through `Rig::create_private_document`:\n{}",
        render(&elsewhere)
    );
    assert!(
        !rig.is_empty(),
        "the rig's creator builds the request, so a scan that finds nothing there is broken"
    );
}

/// One rule decides whether a recorded op reaches the shadow — the
/// recording for content, both worlds for a creation — and it lives in the
/// `Cx` world-change methods in `play.rs`. A handler or the runner that
/// edited the shadow's documents, names or links itself could follow skep's
/// answer instead — or name a document no α-image stands behind — and
/// nothing would refuse it but the goldens drifting: so no code line in
/// `play/` or `runner.rs` names a shadow mutation.
#[test]
fn only_the_world_change_methods_change_the_shadow() {
    const MUTATIONS: &[&str] = &[
        "shadow.insert(",
        "shadow.delete(",
        "shadow.pivot(",
        "shadow.swap(",
        "shadow.version(",
        "shadow.create_doc(",
        "shadow.bind_name(",
        "shadow.seat_link(",
        "shadow.record_link(",
        "shadow.last_link =",
        "shadow.arrow_links.insert",
    ];
    let play_pass = |file: &Path| {
        file.starts_with("play") || ["play.rs", "runner.rs"].iter().any(|f| file == Path::new(f))
    };
    let (owner, elsewhere): (Vec<_>, Vec<_>) =
        scan(|code| MUTATIONS.iter().any(|m| code.contains(m)))
            .into_iter()
            .filter(|(file, _)| play_pass(file))
            .partition(|(file, _)| file == Path::new("play.rs"));
    assert!(
        elsewhere.is_empty(),
        "the play pass changes the shadow's documents and links through the `Cx` \
         world-change methods in `play.rs` alone:\n{}",
        render(&elsewhere)
    );
    assert!(
        !owner.is_empty(),
        "the world-change methods mutate the shadow, so a scan that finds nothing there is broken"
    );
}

/// Every adaptation tag the crate can record is named in `play`'s policy
/// catalogue: in the head of one of `play.rs`'s `//!` bullets — the text
/// before its first ` — ` — verbatim, or through a placeholder (a `*`, a
/// `<…>`, or a final `N` / `+N` after its last `:`). The tags are read where
/// the code makes them: each string literal an `adaptations.push(…)` or
/// `adaptations.extend(…)` call holds (a `format!` literal up to its first
/// `{`, which a placeholder must cover), the value of each `&str` constant
/// such a call names, and each literal in the body of a `fn tag` — the
/// grounding enums' tags, which a call records through `.tag()`. A call
/// recording a tag none of these reads, one held in a variable, is refused:
/// its tag is one this check cannot read. A known tag of each kind is
/// asserted found, so a scan gone blind fails rather than passing a clean
/// tree.
#[test]
fn every_adaptation_tag_is_catalogued() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let play = std::fs::read_to_string(src.join("play.rs")).expect("src/play.rs is readable");
    let catalogue = catalogue_entries(&play);
    let (tags, unreadable) = recorded_tags(&src);
    for known in [
        "client-error:no-op",
        "expansion-plan:",
        "text-located:nth-occurrence",
        "position-after-text",
        "allowlist-adjusted:width",
    ] {
        assert!(
            tags.iter().any(|t| t.text == known),
            "the scan found no `{known}`: the forms it reads have moved"
        );
    }
    assert!(
        catalogue.iter().any(|e| e == "open_document:noop"),
        "the catalogue's bullets were not read: the doc's shape has moved"
    );
    assert!(
        unreadable.is_empty(),
        "an adaptation recorded through an expression this check cannot read — record the \
         tag's literal, a `&str` constant, or a `fn tag` result:\n{}",
        unreadable.join("\n")
    );
    let uncatalogued: Vec<String> = tags
        .iter()
        .filter(|t| !catalogue.iter().any(|e| covers(e, t)))
        .map(|t| format!("{}: `{}`", t.file.display(), t.text))
        .collect();
    assert!(
        uncatalogued.is_empty(),
        "an adaptation tag no entry of play.rs's catalogue names — add the entry:\n{}",
        uncatalogued.join("\n")
    );
}

/// One adaptation tag the code can record: the file it is made in, its
/// text, and whether that text is only the fixed head of a `format!`, whose
/// tail the code supplies.
struct Tag {
    file: PathBuf,
    text: String,
    head_only: bool,
}

/// The catalogue's entries: every backticked span in the head of a bullet
/// of `play.rs`'s module doc — the bullet's text up to its first ` — `.
fn catalogue_entries(play: &str) -> Vec<String> {
    let mut bullets: Vec<String> = Vec::new();
    let mut open = false;
    for line in play.lines() {
        let Some(doc) = line.strip_prefix("//!") else {
            continue;
        };
        let doc = doc.strip_prefix(' ').unwrap_or(doc);
        if let Some(head) = doc.strip_prefix("* ") {
            bullets.push(head.to_string());
            open = true;
        } else if let (true, Some(bullet)) = (open && doc.starts_with("  "), bullets.last_mut()) {
            bullet.push(' ');
            bullet.push_str(doc.trim());
        } else {
            open = false;
        }
    }
    bullets
        .iter()
        .flat_map(|b| {
            let head = b.split(" — ").next().unwrap_or(b);
            head.split('`').skip(1).step_by(2).map(str::to_string).collect::<Vec<_>>()
        })
        .collect()
}

/// Does catalogue entry `entry` name `tag`? Verbatim, or through its
/// placeholder — a `*` or `<…>`, or a final `N` / `+N` after its last `:` —
/// when the entry's text before the placeholder begins the tag, and the tag
/// goes on past it (a `format!` head goes on at run time).
fn covers(entry: &str, tag: &Tag) -> bool {
    let fixed = entry.find(['*', '<']).map(|i| &entry[..i]).or_else(|| {
        let (head, last) = entry.rsplit_once(':')?;
        matches!(last, "N" | "+N").then_some(&entry[..=head.len()])
    });
    match fixed {
        None => !tag.head_only && tag.text == entry,
        Some(fixed) => {
            !fixed.is_empty()
                && tag.text.starts_with(fixed)
                && (tag.head_only || tag.text.len() > fixed.len())
        }
    }
}

/// Every adaptation tag `src/`'s shipped code can record (the code before
/// each file's first `#[cfg(test)]` line, `tests.rs` files aside), and, as
/// `file: call` lines, every call recording one this scan cannot read.
fn recorded_tags(src: &Path) -> (Vec<Tag>, Vec<String>) {
    let mut files = Vec::new();
    rust_files(src, &mut files);
    files.retain(|f| f.file_name().is_some_and(|n| n != "tests.rs"));
    let shipped: Vec<(PathBuf, String)> = files
        .iter()
        .map(|f| {
            let text = std::fs::read_to_string(f).expect("a source file is readable");
            let code: Vec<&str> = code_lines(shipped_part(&text)).collect();
            (f.strip_prefix(src).expect("under src").to_path_buf(), code.join("\n"))
        })
        .collect();
    let consts: HashMap<String, String> =
        shipped.iter().flat_map(|(_, code)| str_consts(code)).collect();
    let (mut tags, mut unreadable) = (Vec::new(), Vec::new());
    for (file, code) in &shipped {
        let mut tag = |text: String, head_only: bool| {
            tags.push(Tag { file: file.clone(), text, head_only });
        };
        for call in adaptation_calls(code) {
            let literals = literals(call);
            let named: Vec<&String> = call
                .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .filter_map(|word| consts.get(word))
                .collect();
            let read_elsewhere = call.contains(".tag()") || call.contains(".adaptations");
            if literals.is_empty() && named.is_empty() && !read_elsewhere {
                unreadable.push(format!("{}: {}", file.display(), call.trim()));
            }
            for (text, formatted) in literals {
                if formatted {
                    tag(text.split('{').next().unwrap_or_default().to_string(), true);
                } else {
                    tag(text, false);
                }
            }
            for value in named {
                tag(value.clone(), false);
            }
        }
        for body in tag_fn_bodies(code) {
            for (text, _) in literals(body) {
                tag(text, false);
            }
        }
    }
    (tags, unreadable)
}

/// The part of a source file shipped code lives in: everything before its
/// first `#[cfg(test)]` line.
fn shipped_part(text: &str) -> &str {
    let mut at = 0;
    for line in text.split_inclusive('\n') {
        if line.trim_start().starts_with("#[cfg(test)]") {
            return &text[..at];
        }
        at += line.len();
    }
    text
}

/// The argument text of every `push(…)` or `extend(…)` call on an
/// `adaptations` list in `code`, a method chain split across lines included.
fn adaptation_calls(code: &str) -> Vec<&str> {
    let mut calls = Vec::new();
    for (i, word) in code.match_indices("adaptations") {
        let rest = code[i + word.len()..].trim_start();
        let Some(rest) = rest.strip_prefix('.').map(str::trim_start) else {
            continue;
        };
        let Some(rest) = rest.strip_prefix("push").or_else(|| rest.strip_prefix("extend")) else {
            continue;
        };
        let rest = rest.trim_start();
        if rest.starts_with('(') {
            let open = code.len() - rest.len();
            calls.push(&code[open + 1..closing(code, open)]);
        }
    }
    calls
}

/// The bodies of every `fn tag(` in `code`: the grounding enums' tags.
fn tag_fn_bodies(code: &str) -> Vec<&str> {
    code.match_indices("fn tag(")
        .filter_map(|(i, _)| {
            let open = i + code[i..].find('{')?;
            Some(&code[open + 1..closing(code, open)])
        })
        .collect()
}

/// Every `const NAME: &str = "…";` in `code`: its name and its value.
fn str_consts(code: &str) -> Vec<(String, String)> {
    code.lines()
        .filter_map(|line| {
            let (_, decl) = line.split_once("const ")?;
            let (name, value) = decl.split_once(": &str = \"")?;
            Some((name.trim().to_string(), value.strip_suffix("\";")?.to_string()))
        })
        .collect()
}

/// The string literals in `span`, each with whether a `format!(` opens it.
fn literals(span: &str) -> Vec<(String, bool)> {
    let bytes = span.as_bytes();
    let mut found = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'"' {
            let end = string_end(bytes, i);
            let formatted = span[..i].trim_end().ends_with("format!(");
            found.push((span[i + 1..end].to_string(), formatted));
            i = end;
        }
        i += 1;
    }
    found
}

/// The index of the delimiter closing the `(` or `{` at `open` in `code`,
/// string literals skipped.
fn closing(code: &str, open: usize) -> usize {
    let bytes = code.as_bytes();
    let (opens, closes) = match bytes[open] {
        b'(' => (b'(', b')'),
        b'{' => (b'{', b'}'),
        other => panic!("`{}` opens no delimited span", other as char),
    };
    let (mut depth, mut i) = (0usize, open);
    while i < bytes.len() {
        match bytes[i] {
            b'"' => i = string_end(bytes, i),
            b if b == opens => depth += 1,
            b if b == closes => {
                depth -= 1;
                if depth == 0 {
                    return i;
                }
            }
            _ => {}
        }
        i += 1;
    }
    panic!("a delimiter a source file never closes")
}

/// The index of the `"` closing the string literal that opens at `start`.
fn string_end(bytes: &[u8], start: usize) -> usize {
    let mut i = start + 1;
    while bytes[i] != b'"' {
        i += if bytes[i] == b'\\' { 2 } else { 1 };
    }
    i
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
/// stem: `lib.rs` declares `loader` for `src/loader.rs`, and `main.rs`
/// declares `gate` for `tests/it/gate.rs`. A file in a subdirectory is
/// declared by the module that directory is named for, `x.rs` beside it or
/// `x/mod.rs` inside it: `src/play/find.rs` is `find` to `src/play.rs`.
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
