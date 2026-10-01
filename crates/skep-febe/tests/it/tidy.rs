//! THE MODULE ORDER, CHECKED: `src/lib.rs` declares this crate's modules in
//! dependency order, each naming in code only the modules above it, and this
//! is that sentence as a test — together with one of ARCHITECTURE.md's
//! cross-file rules, the half of it no compiler error reports.
//!
//! Every `crate::…` path a module's files name in code — its tests included,
//! comments and doc links not — resolves to that module or to one declared
//! above it. A path through the crate root's re-export (`crate::Stores`) is
//! judged by the module the root re-exports it from (`world`); a root
//! re-export of an upstream crate (`crate::FROM`) names no module here. A
//! module's children name their parent through `super::`, which is the tree
//! itself and not an edge between modules.
//!
//! The rule is held over every code line under `src/`, tests included: only
//! `operation/door.rs` asks the world's own read predicate. The scan also
//! asserts that it found the site the rule allows, so a scan that matches
//! nothing fails rather than passing a clean tree.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[test]
fn every_module_names_only_itself_and_modules_declared_above_it() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let lib = std::fs::read_to_string(src.join("lib.rs")).expect("src/lib.rs is readable");
    let order: Vec<&str> =
        lib.lines().filter_map(|l| l.strip_prefix("mod ")?.strip_suffix(';')).collect();
    assert!(order.len() > 1, "src/lib.rs declares its modules as `mod name;` lines");
    let rank: HashMap<&str, usize> = order.iter().enumerate().map(|(i, m)| (*m, i)).collect();
    let reexport_rank = root_reexports(&lib, &rank);

    let mut faults = Vec::new();
    for (own_rank, module) in order.iter().enumerate() {
        let mut files = vec![src.join(format!("{module}.rs"))];
        rust_files(&src.join(module), &mut files);
        for file in files {
            let text = std::fs::read_to_string(&file).expect("a module file is readable");
            for named in crate_paths(&text) {
                let target =
                    rank.get(named.as_str()).or_else(|| reexport_rank.get(named.as_str()));
                if let Some(&below) = target.filter(|&&r| r > own_rank) {
                    faults.push(format!(
                        "{}: `crate::{named}` reaches `{}`, declared below `{module}`",
                        file.strip_prefix(&src).expect("under src").display(),
                        order[below],
                    ));
                }
            }
        }
    }
    assert!(
        faults.is_empty(),
        "a module names one declared below it — move the item, or reorder src/lib.rs and \
         ARCHITECTURE.md with it:\n{}",
        faults.join("\n")
    );
}

/// ARCHITECTURE.md's first rule, the half the compiler does not keep.
/// `OperationSurface::readable`, where a supplied `ReadPredicate` overrides
/// the world's own predicate, is private to `operation/door.rs`, so no other
/// file can call it by name. The world's own predicate cannot be fenced the
/// same way: `ReadableWorld::readable` is a supertrait method of `FebeWorld`,
/// which bounds every `W` in this crate, so code holding a world asks it with
/// no import — and a read arm that did would answer through the world where a
/// supplied predicate, the historical door's, was meant to answer. So no file
/// but the door asks a `readable` by method call or by path.
#[test]
fn only_the_door_asks_the_worlds_own_predicate() {
    let (door, elsewhere): (Vec<_>, Vec<_>) = scan(asks_readable)
        .into_iter()
        .partition(|(file, _)| file == Path::new("operation/door.rs"));
    assert!(
        elsewhere.is_empty(),
        "only `operation/door.rs` asks the world's own predicate; a read arm answers through \
         its request's, `readable_by`:\n{}",
        render(&elsewhere)
    );
    assert!(!door.is_empty(), "the door asks it, so a scan that finds nothing there is broken");
}

/// The root's `pub use <module>::…;` lines, as re-exported name → the rank
/// of the module it comes from. Upstream re-exports are not modules of this
/// crate and are left out.
fn root_reexports(lib: &str, rank: &HashMap<&str, usize>) -> HashMap<String, usize> {
    let mut reexport_rank = HashMap::new();
    for item in lib.split("pub use ").skip(1) {
        let item = item.split(';').next().expect("a `pub use` ends at `;`");
        let Some((head, rest)) = item.split_once("::") else { continue };
        let Some(&r) = rank.get(head.trim()) else { continue };
        let rest = rest.trim();
        let names = rest.strip_prefix('{').and_then(|g| g.strip_suffix('}')).unwrap_or(rest);
        for name in names.split(',').map(str::trim).filter(|n| !n.is_empty()) {
            reexport_rank.insert(name.to_string(), r);
        }
    }
    reexport_rank
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
            let segment: String =
                after.chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect();
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

/// Whether `code` asks something named exactly `readable` by method call or
/// by path — `.readable(`, `W::readable`, `ReadableWorld::readable` — and not
/// `readable_by`, a local closure called `readable`, or a definition.
fn asks_readable(code: &str) -> bool {
    code.match_indices("readable").any(|(i, word)| {
        let (before, after) = (&code[..i], &code[i + word.len()..]);
        let by_method_or_path = before.ends_with('.') || before.ends_with("::");
        by_method_or_path && !after.starts_with(|c: char| c.is_alphanumeric() || c == '_')
    })
}

/// The code of `text`, line by line: a comment line is not code, and neither
/// is a line's trailing comment.
fn code_lines(text: &str) -> impl Iterator<Item = &str> {
    text.lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .map(|line| line.split(" //").next().expect("split yields a first piece"))
}

/// Scan hits, one line each, for an assertion message.
fn render(hits: &[(PathBuf, String)]) -> String {
    let lines: Vec<String> =
        hits.iter().map(|(file, code)| format!("{}: {code}", file.display())).collect();
    lines.join("\n")
}

/// Every `.rs` file under `dir`, recursively; nothing when `dir` is absent.
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
