//! THE MODULE MAP, CHECKED: `src/lib.rs` declares this crate's modules in
//! dependency order, each with a line saying what it holds and each naming
//! in code only the modules above it, and this is that sentence as tests —
//! together with two rules no compiler error reports, one about the reader's
//! predicate and one about a name's suffix.
//!
//! The tree's shape: every file under `src/`, and under the test target's
//! `tests/it/`, is a module its parent declares — the compiler never reads
//! a file no `mod` names, and no build says so, so an undeclared suite file
//! is a suite that never runs — and every `src/` declaration but a `tests`
//! module carries its map line, a `//` comment directly above it.
//!
//! Every `crate::…` path a module's files name in code — its tests included,
//! comments and doc links not — names that module, one declared above it,
//! or `DiscoveryWorld`, the one item the root defines rather than
//! re-exports. A path through the root's re-exports — this crate's
//! (`crate::MAX_IMAGE_RUNS`) or an upstream crate's (`crate::Endset`) — hides
//! the module it reaches, so it is refused: code names an item by its home
//! module. A module's children name their parent through `super::`, which is
//! the tree itself and not an edge between modules. The check counts the
//! paths it reads between modules, so a reader gone blind fails rather than
//! passing a clean tree.
//!
//! The two rules are held over every code line under `src/`, tests included:
//! only `home.rs` projects a home or asks the reader's predicate, and a
//! function ends its name in `_on` exactly when its first parameter is the
//! `&Snapshot` it reads. Each scan also asserts that it found what its rule
//! is about, so a scan that matches nothing fails rather than passing a clean
//! tree.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// The one item a module may name through `crate::` that is no module: the
/// world bound the root defines rather than re-exports.
const ROOT_ITEM: &str = "DiscoveryWorld";

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
                        "{shown}: `crate::{named}` goes through the root's re-exports — name \
                         the item by its home module"
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

/// THE HOME RULE HAS ONE ADDRESS: `home.rs` alone projects a link's home
/// (`document_of`) and alone calls the caller's predicate. Every other file
/// hands `readable` on to `home_readable`, because the predicate answers
/// about a DOCUMENT and, asked of a LINK, admits every link — a fail-open no
/// type catches, `readable` being the plain `&dyn Fn` every read takes. The
/// result-set law holds the reads that exist; this holds every line, so a
/// read added later answers to it too. The scan also asserts that it found
/// `home.rs`'s own sites, so a scan that matches nothing fails rather than
/// passing a clean tree.
#[test]
fn only_home_projects_a_home_or_asks_the_readers_predicate() {
    let (home, elsewhere): (Vec<_>, Vec<_>) = scan(projects_a_home_or_asks_the_reader)
        .into_iter()
        .partition(|(file, _)| file == Path::new("home.rs"));
    assert!(
        elsewhere.is_empty(),
        "only `home.rs` projects a home or asks the reader's predicate; every other \
         file asks through `home_readable`:\n{}",
        render(&elsewhere)
    );
    assert!(
        !home.is_empty(),
        "`home.rs` projects the home and asks the predicate, so a scan that finds \
         nothing there is broken"
    );
}

/// Whether `code` names `document_of`, or calls `readable`, as a whole
/// identifier — `readable` being the name every read gives the caller's
/// predicate.
fn projects_a_home_or_asks_the_reader(code: &str) -> bool {
    [("document_of", false), ("readable", true)]
        .iter()
        .any(|&(word, called)| {
            code.match_indices(word).any(|(i, _)| {
                let (before, after) = (&code[..i], &code[i + word.len()..]);
                !before.ends_with(is_ident_char)
                    && !after.starts_with(is_ident_char)
                    && (!called || after.starts_with('('))
            })
        })
}

/// THE `_on` SUFFIX MARKS A SNAPSHOT: a function under `src/` ends its name
/// in `_on` exactly when its first parameter is the `&Snapshot` it reads —
/// every read, and the region family's private `findlinks_v_set_on` — while a
/// helper over one store, `candidates` or `claims_naming`, carries no suffix.
/// A reader who has learned the suffix reads every call by it, so one
/// exception is one call read wrong. The scan also asserts that it found
/// functions of both kinds, so a reader gone blind to signatures fails rather
/// than passing a clean tree.
#[test]
fn the_on_suffix_marks_exactly_the_functions_over_a_snapshot() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_files(&src, &mut files);
    let (mut faults, mut with_snapshot, mut without_snapshot) = (Vec::new(), 0, 0);
    for file in files {
        let text = std::fs::read_to_string(&file).expect("a source file is readable");
        let shown = file.strip_prefix(&src).expect("under src").display();
        let code: Vec<&str> = code_lines(&text).collect();
        for (name, takes_snapshot) in signatures(&code.join("\n")) {
            if takes_snapshot {
                with_snapshot += 1;
            } else {
                without_snapshot += 1;
            }
            if name.ends_with("_on") != takes_snapshot {
                let wrong = if takes_snapshot {
                    "takes a `&Snapshot` first and does not end in `_on`"
                } else {
                    "ends in `_on` and takes no `&Snapshot` first"
                };
                faults.push(format!("{shown}: `{name}` {wrong}"));
            }
        }
    }
    assert!(
        with_snapshot > 0 && without_snapshot > 0,
        "this check read no signature of one kind: the forms it reads have moved"
    );
    assert!(
        faults.is_empty(),
        "a function ends in `_on` exactly when its first parameter is the `&Snapshot` it \
         reads — name it for what it reads:\n{}",
        faults.join("\n")
    );
}

/// Every function `code` declares — the code of one file, comments stripped —
/// as its name and whether its first parameter is a `&Snapshot`.
fn signatures(code: &str) -> Vec<(String, bool)> {
    let mut found = Vec::new();
    for (i, _) in code.match_indices("fn ") {
        if code[..i].ends_with(is_ident_char) {
            continue; // the tail of an identifier, not the keyword
        }
        let rest = &code[i + "fn ".len()..];
        let name: String = rest.chars().take_while(|&c| is_ident_char(c)).collect();
        let Some(parameters) = after_generics(&rest[name.len()..]).strip_prefix('(') else {
            continue;
        };
        let takes_snapshot = parameters.split_once(':').is_some_and(|(binding, ty)| {
            binding.trim().chars().all(is_ident_char) && ty.trim_start().starts_with("&Snapshot<")
        });
        found.push((name, takes_snapshot));
    }
    found
}

/// What follows the generic list `<…>` at the head of `rest`, or `rest`
/// itself when it opens none. The `>` of a `->`, from an `Fn(…) -> T` bound
/// inside the list, closes nothing.
fn after_generics(rest: &str) -> &str {
    if !rest.starts_with('<') {
        return rest;
    }
    let (mut depth, mut previous) = (0, '<');
    for (i, c) in rest.char_indices() {
        match c {
            '<' => depth += 1,
            '>' if previous != '-' => {
                depth -= 1;
                if depth == 0 {
                    return &rest[i + 1..];
                }
            }
            _ => {}
        }
        previous = c;
    }
    rest
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
/// stem: `lib.rs` declares `sets` for `src/sets.rs`, and `main.rs` declares
/// `region` for `tests/it/region.rs`. A file in a subdirectory is declared by
/// the module that directory is named for, `x.rs` beside it or `x/mod.rs`
/// inside it: `src/x/y.rs` is `y` to `src/x.rs`.
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
