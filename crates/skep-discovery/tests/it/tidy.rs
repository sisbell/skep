//! THE MODULE ORDER, CHECKED: `src/lib.rs` declares this crate's modules in
//! dependency order, each naming in code only the modules above it, and this
//! is that sentence as a test — together with the one rule about the reader's
//! predicate that no compiler error reports.
//!
//! Every `crate::…` path a module's files name in code — its tests included,
//! comments and doc links not — resolves to that module or to one declared
//! above it. A path through the crate root's re-export
//! (`crate::MAX_IMAGE_RUNS`) is judged by the module the root re-exports it
//! from (`budget`). A module's children name their parent through `super::`,
//! which is the tree itself and not an edge between modules.
//!
//! The rule is held over every code line under `src/`, tests included: only
//! `home.rs` projects a home or asks the reader's predicate. The scan also
//! asserts that it found the sites the rule allows, so a scan that matches
//! nothing fails rather than passing a clean tree.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[test]
fn every_module_names_only_itself_and_modules_declared_above_it() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let lib = std::fs::read_to_string(src.join("lib.rs")).expect("src/lib.rs is readable");
    let order: Vec<&str> = lib
        .lines()
        .filter_map(|l| l.strip_prefix("mod ")?.strip_suffix(';'))
        .collect();
    assert!(
        order.len() > 1,
        "src/lib.rs declares its modules as `mod name;` lines"
    );
    let rank: HashMap<&str, usize> = order.iter().enumerate().map(|(i, m)| (*m, i)).collect();
    let reexport_rank = root_reexports(&lib, &rank);

    let mut faults = Vec::new();
    for (own_rank, module) in order.iter().enumerate() {
        let mut files = vec![src.join(format!("{module}.rs"))];
        rust_files(&src.join(module), &mut files);
        for file in files {
            let text = std::fs::read_to_string(&file).expect("a module file is readable");
            for named in crate_paths(&text) {
                let target = rank
                    .get(named.as_str())
                    .or_else(|| reexport_rank.get(named.as_str()));
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
        "a module names one declared below it — move the item, or reorder src/lib.rs:\n{}",
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

fn is_ident_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// The root's `pub use <module>::…;` lines, as re-exported name → the rank
/// of the module it comes from. Upstream re-exports are not modules of this
/// crate and are left out.
fn root_reexports(lib: &str, rank: &HashMap<&str, usize>) -> HashMap<String, usize> {
    let mut reexport_rank = HashMap::new();
    for item in lib.split("pub use ").skip(1) {
        let item = item.split(';').next().expect("a `pub use` ends at `;`");
        let Some((head, rest)) = item.split_once("::") else {
            continue;
        };
        let Some(&r) = rank.get(head.trim()) else {
            continue;
        };
        let rest = rest.trim();
        let names = rest
            .strip_prefix('{')
            .and_then(|g| g.strip_suffix('}'))
            .unwrap_or(rest);
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
