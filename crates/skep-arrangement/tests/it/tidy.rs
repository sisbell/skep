//! THE MODULE ORDER, CHECKED: `src/lib.rs` declares this crate's modules in
//! dependency order, each naming in code only the modules above it, and this
//! is that sentence as a test — together with the edges between modules that
//! no path records.
//!
//! Every `crate::…` path a module's files name in code — its tests included,
//! comments and doc links not — resolves to that module or to one declared
//! above it. A path through the crate root's re-export (`crate::Caller`) is
//! judged by the module the root re-exports it from (`ownership`); the root's
//! own items (`crate::HasM5`) and `testutil`, the unit tests' fixtures, are
//! no module of the order. A module's children name their parent through
//! `super::`, which is the tree itself and not an edge between modules.
//!
//! `M5State`'s methods are one namespace across the modules holding an
//! `impl M5State` block — `state.rs`, `reads.rs`, `shot.rs` — so a call from
//! one into a method another defines records no path; the second test reads
//! those edges off the method names instead.

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

/// `M5State`'s methods are one namespace across every module holding an
/// `impl M5State` block, so a call from one into a method another defines
/// records no path. Each such module calls only the methods defined in itself
/// or in a holder declared above it. For the fold, which `state.rs` holds,
/// that is ARCHITECTURE.md's rule: it reaches an arrangement through its own
/// accessors and calls nothing the reads or the address form define, so an
/// edit to either cannot change what replay folds. The holders are found by
/// the order `src/lib.rs` declares, so a fourth joins the check by holding a
/// block. Every `fn` name a holder defines is looked for as a method call
/// (`.name(`) in the code of each holder above it — the holders' own files,
/// not their tests, which read the fold's result through the reads. The scan
/// also asserts that it found the slice, its reads and their names, so a scan
/// that matches nothing fails rather than passing a clean tree.
#[test]
fn each_module_calls_only_m5state_methods_defined_in_itself_or_above_it() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let lib = std::fs::read_to_string(src.join("lib.rs")).expect("src/lib.rs is readable");
    let holders: Vec<(&str, String)> = lib
        .lines()
        .filter_map(|l| l.strip_prefix("mod ")?.strip_suffix(';'))
        .filter_map(|module| {
            let text = std::fs::read_to_string(src.join(format!("{module}.rs"))).ok()?;
            text.contains("impl M5State {").then_some((module, text))
        })
        .collect();
    let order: Vec<&str> = holders.iter().map(|(module, _)| *module).collect();
    assert!(
        order.starts_with(&["state", "reads"]),
        "the slice, then its reads: {order:?}"
    );
    assert!(
        defined_fns(&holders[1].1)
            .iter()
            .any(|name| name == "content_count"),
        "the scan finds the reads `reads.rs` defines"
    );
    let mut faults = Vec::new();
    for (at, (caller, text)) in holders.iter().enumerate() {
        for (definer, below) in &holders[at + 1..] {
            for name in defined_fns(below) {
                let call = format!(".{name}(");
                for code in code_lines(text).filter(|code| code.contains(&call)) {
                    faults.push(format!(
                        "{caller}.rs calls `{name}`, which {definer}.rs defines: {}",
                        code.trim()
                    ));
                }
            }
        }
    }
    assert!(
        faults.is_empty(),
        "a module calls an `M5State` method defined below it — ask its own accessors, or \
         move the method:\n{}",
        faults.join("\n")
    );
}

/// The name of every `fn` the code of `text` defines ([`code_lines`]).
fn defined_fns(text: &str) -> Vec<String> {
    code_lines(text)
        .filter_map(|code| {
            let (_, rest) = code.split_once("fn ")?;
            let name: String =
                rest.chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect();
            (!name.is_empty()).then_some(name)
        })
        .collect()
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

/// The code of `text`, line by line: a comment line is not code, and neither
/// is a line's trailing comment.
fn code_lines(text: &str) -> impl Iterator<Item = &str> {
    text.lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .map(|line| line.split(" //").next().expect("split yields a first piece"))
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
