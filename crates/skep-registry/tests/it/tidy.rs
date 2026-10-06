//! The crate's outer boundary, which the compiler holds none of: A LEAF, as
//! `lib.rs`'s A LEAF paragraph, the manifest's description and
//! ARCHITECTURE.md's code map state it.

use std::collections::BTreeSet;
use std::path::Path;

/// A LEAF (`lib.rs`: "it depends on `skep-address` and `serde_json` and on
/// nothing else — no engine, no daemon, no signature library"; the code map:
/// "Of the skep crates it depends only on `skep-address`"), so the daemon's
/// parse and a resolver that links no daemon read one table. The compiler
/// holds none of it: a dependency added to the manifest builds, and every
/// other test of the workspace stays green. Read off the manifest's own
/// text, as skep-identity's `the_dependencies_are_auth_2_1s_five` reads its
/// own: no dependency table but `[dependencies]` and `[dev-dependencies]`,
/// so none arrives under a target or build table, and `[dependencies]` names
/// the two.
#[test]
fn the_dependencies_are_skep_address_and_serde_json() {
    let manifest =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
            .expect("the manifest");
    let (mut table, mut dependency_tables, mut dependencies) =
        ("", BTreeSet::new(), BTreeSet::new());
    for line in manifest.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.starts_with('[') {
            table = line;
            if line.contains("dependencies") {
                dependency_tables.insert(line);
            }
        } else if table == "[dependencies]" {
            dependencies.extend(dependency_named(line));
        }
    }
    let allowed = BTreeSet::from(["[dependencies]", "[dev-dependencies]"]);
    assert!(
        dependency_tables.is_subset(&allowed),
        "Cargo.toml's dependency tables: {dependency_tables:?}"
    );
    assert_eq!(dependencies, BTreeSet::from(["serde_json", "skep-address"]), "the leaf's two");
}

/// The dependency a manifest line names, where it names one: the key ahead
/// of `=`, cut at its first dot (`serde_json.workspace = true`).
fn dependency_named(line: &str) -> Option<&str> {
    let (key, _) = line.split_once('=')?;
    let name = key.split('.').next()?.trim().trim_matches('"');
    let is_name = |c: char| c.is_ascii_alphanumeric() || c == '-' || c == '_';
    (!name.is_empty() && name.chars().all(is_name)).then_some(name)
}
