//! THE MODULE ORDER, CHECKED: `src/lib.rs` declares this crate's modules in
//! dependency order, each naming in code only the modules above it, and this
//! is that sentence as a test.
//!
//! Every `crate::…` path a module's files name in code — its tests included,
//! comments and doc links not — resolves to that module or to one declared
//! above it. A path through the crate root's re-export (`crate::Stores`) is
//! judged by the module the root re-exports it from (`world`); a root
//! re-export of an upstream crate (`crate::FROM`) names no module here. A
//! module's children name their parent through `super::`, which is the tree
//! itself and not an edge between modules.

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

/// The first segment of every `crate::…` path in code. Comment lines are not
/// code, and neither is a line's trailing comment. A brace group directly
/// after `crate::` is refused rather than half-read: this crate names one
/// module per path.
fn crate_paths(text: &str) -> Vec<String> {
    let mut named = Vec::new();
    for line in text.lines() {
        if line.trim_start().starts_with("//") {
            continue;
        }
        let code = line.split(" //").next().expect("split yields a first piece");
        for (i, _) in code.match_indices("crate::") {
            let after = &code[i + "crate::".len()..];
            assert!(!after.starts_with('{'), "a `crate::{{…}}` group: {line}");
            let segment: String =
                after.chars().take_while(|c| c.is_alphanumeric() || *c == '_').collect();
            named.push(segment);
        }
    }
    named
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
