//! The crate's outer boundary, which the compiler holds none of: AUTH-2.2's
//! "the one crate that links the signature libraries", read off the
//! workspace's resolved graph; the verify-only build a daemon links
//! (AUTH-2.89, I1: "skepd's source has no signing capability"), read off
//! this crate's manifest; the crates each frozen rule runs, read off the
//! lock at the versions its tag froze; and the test hooks, as the one list
//! `src/hooks.rs` keeps names them, read off the source's `TEST HOOK`
//! markers.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// THE ONE CRATE THAT LINKS `ed25519-dalek`, read off the workspace's
/// resolved graph: every package `Cargo.lock` lists as depending on it —
/// dev-dependencies included, since the lock does not tell them apart —
/// is this crate and no other. Other crates' suites reach Ed25519 through
/// this crate's hooks instead (`src/hooks.rs` names them), so a manifest that
/// names the library again lands in the lock and fails here, the way
/// `cargo tree -i ed25519-dalek --workspace` would show it.
#[test]
fn ed25519_dalek_is_linked_by_this_crate_alone() {
    let lock = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../Cargo.lock"))
        .expect("the workspace's Cargo.lock");
    let names_dalek = |line: &str| {
        // A dependency entry is `"name"` or `"name version"` when more
        // than one version of it is resolved.
        let entry = line.trim().trim_end_matches(',').trim_matches('"');
        entry == "ed25519-dalek" || entry.starts_with("ed25519-dalek ")
    };
    let dependents: Vec<&str> = lock
        .split("[[package]]")
        .skip(1)
        .filter(|package| package.lines().any(names_dalek))
        .map(|package| {
            package
                .lines()
                .find_map(|line| line.strip_prefix("name = \"")?.strip_suffix('"'))
                .expect("every package in the lock has a name")
        })
        .collect();
    assert_eq!(
        dependents,
        ["skep-signature"],
        "the packages the lock resolves `ed25519-dalek` for"
    );
}

/// THE VERIFY-ONLY BUILD (AUTH-2.89, I1), read off the manifest's own text
/// as skep-registry's `the_dependencies_are_skep_address_and_serde_json`
/// reads its own: no dependency table but `[dependencies]` and
/// `[dev-dependencies]`, so none arrives under a target or build table; the
/// dependencies every build links are the four the verify reads —
/// skep-identity's syntax and the three signature libraries — by name;
/// every other dependency is the manifest's "OPTIONAL, enabled by `sign`
/// alone — the verify links none of them"; and of them all one is a skep
/// crate, `skep-identity` (the manifest's card, the README, ARCHITECTURE.md's
/// code map). The compiler holds none of it: a signer library made
/// non-optional still builds, and the gate's no-feature check still passes.
#[test]
fn the_verify_only_build_links_the_verifys_four_and_no_signer_library() {
    let manifest =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
            .expect("the manifest");
    let (mut table, mut dependency_tables) = ("", BTreeSet::new());
    let (mut every_build, mut optional, mut sign) =
        (BTreeSet::new(), BTreeSet::new(), BTreeSet::new());
    for line in manifest.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.starts_with('[') {
            table = line;
            if line.contains("dependencies") {
                dependency_tables.insert(line);
            }
        } else if table == "[features]" && line.starts_with("sign = [") {
            sign.extend(line.split('"').filter_map(|item| item.strip_prefix("dep:")));
        } else if table == "[dependencies]" {
            let Some(name) = dependency_named(line) else { continue };
            if line.contains("optional = true") {
                optional.insert(name);
            } else {
                every_build.insert(name);
            }
        }
    }
    let allowed = BTreeSet::from(["[dependencies]", "[dev-dependencies]"]);
    assert!(
        dependency_tables.is_subset(&allowed),
        "Cargo.toml's dependency tables: {dependency_tables:?}"
    );
    assert_eq!(
        every_build,
        BTreeSet::from(["ed25519-dalek", "fn-dsa", "ml-dsa", "skep-identity"]),
        "the dependencies every build links: the verify's four"
    );
    assert!(!sign.is_empty(), "the `sign` feature's line was read");
    assert_eq!(optional, sign, "every other dependency is optional and turned on by `sign` alone");
    let skep: Vec<&str> =
        every_build.iter().chain(&optional).copied().filter(|n| n.starts_with("skep-")).collect();
    assert_eq!(skep, ["skep-identity"], "the one skep crate this crate names");
}

/// THE EXACT PINS REACH THE CODE THEY FREEZE — the manifest's "PINNED
/// EXACTLY … a version bump is a rule change that ships as a NEW tag", read
/// off `Cargo.lock`: every crate a tag's rule runs resolves to the one
/// version its tag froze — `ml-dsa` 0.1.1 under tag 1; under tag 3, `fn-dsa`
/// 0.4.0 and the four crates that ARE its code, `fn-dsa-comm`, `-kgen`,
/// `-sign` and `-vrfy`, which the facade asks for as `0.4`, so that
/// `fn-dsa = "=0.4.0"` holds them at nothing and a `cargo update` moves them
/// within 0.4.x. A move that changes a key or a signature fails a golden;
/// one that changes only what verifies can fail nothing but this.
#[test]
fn every_crate_a_frozen_rule_runs_resolves_to_the_version_it_froze() {
    let lock = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../Cargo.lock"))
        .expect("the workspace's Cargo.lock");
    for (name, frozen) in [
        ("ml-dsa", "0.1.1"),
        ("fn-dsa", "0.4.0"),
        ("fn-dsa-comm", "0.4.0"),
        ("fn-dsa-kgen", "0.4.0"),
        ("fn-dsa-sign", "0.4.0"),
        ("fn-dsa-vrfy", "0.4.0"),
    ] {
        assert_eq!(
            resolved_versions(&lock, name),
            [frozen],
            "`{name}` as the lock resolves it: a tag's rule runs {name} {frozen}, so any other \
             version is a NEW tag, never an edit (`cargo update -p {name} --precise {frozen}` \
             restores the lock)"
        );
    }
}

/// The versions `Cargo.lock` resolves the package `name` at, one per entry.
fn resolved_versions<'l>(lock: &'l str, name: &str) -> Vec<&'l str> {
    let name_line = format!("name = \"{name}\"");
    lock.split("[[package]]")
        .skip(1)
        .filter(|package| package.lines().any(|line| line == name_line))
        .filter_map(|package| {
            package.lines().find_map(|line| line.strip_prefix("version = \"")?.strip_suffix('"'))
        })
        .collect()
}

/// The dependency a manifest line names, where it names one: the key ahead
/// of `=`, cut at its first dot (`sha2.workspace = true`).
fn dependency_named(line: &str) -> Option<&str> {
    let (key, _) = line.split_once('=')?;
    let name = key.split('.').next()?.trim().trim_matches('"');
    let is_name = |c: char| c.is_ascii_alphanumeric() || c == '-' || c == '_';
    (!name.is_empty() && name.chars().all(is_name)).then_some(name)
}

/// THE ONE LIST OF TEST HOOKS: `src/hooks.rs`'s module doc links every item
/// this crate documents as a test hook — a doc line opening `TEST HOOK`, the
/// marker skepd's `every_test_hook_compiles_only_under_test_hooks` reads to
/// hold each one under the gate — and links nothing else. The doc build
/// holds each link to a live item; this holds the list to the markers both
/// ways, so a hook added without its entry, or an entry left for an item no
/// longer marked, fails here — and the crate's other docs point at the list
/// rather than restate it.
#[test]
fn hooks_rs_lists_every_test_hook_and_nothing_else() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_files(&src, &mut files);
    let mut marked = BTreeSet::new();
    for file in &files {
        let text = std::fs::read_to_string(file).expect("a source file");
        let lines: Vec<&str> = text.lines().collect();
        // As skepd's check reads them: a file's markers end where its inline
        // test module begins.
        let end = lines.iter().position(|l| l.trim() == "mod tests {").unwrap_or(lines.len());
        for (i, line) in lines[..end].iter().enumerate() {
            if !line.trim_start().starts_with("/// TEST HOOK") {
                continue;
            }
            let item = lines[i..]
                .iter()
                .map(|l| l.trim_start())
                .find(|l| !l.starts_with("///") && !l.starts_with("#["))
                .expect("a marked doc documents an item");
            let names = names_declared(item);
            assert!(!names.is_empty(), "{}: no name read off `{item}`", file.display());
            marked.extend(names.into_iter().map(String::from));
        }
    }
    assert!(!marked.is_empty(), "no `TEST HOOK` marker under src/: the markers have moved");
    let hooks_rs = std::fs::read_to_string(src.join("hooks.rs")).expect("src/hooks.rs");
    let list: Vec<&str> = hooks_rs.lines().map_while(|l| l.strip_prefix("//!")).collect();
    let listed: BTreeSet<String> = list
        .join(" ")
        .split("[`")
        .skip(1)
        .filter_map(|link| link.split_once("`]"))
        .map(|(target, _)| target.rsplit("::").next().unwrap_or(target).to_string())
        .collect();
    assert_eq!(listed, marked, "src/hooks.rs's list, against the items marked `TEST HOOK`");
}

/// The names one item line declares: each name a `pub use` brings in, or
/// the name after the `fn`, `struct`, `enum`, `trait`, `type` or `const`
/// keyword.
fn names_declared(item: &str) -> Vec<&str> {
    if let Some(path) = item.strip_prefix("pub use ") {
        let path = path.trim_end_matches(';');
        let group = match path.split_once('{') {
            Some((_, group)) => group.trim_end_matches('}'),
            None => path.rsplit("::").next().unwrap_or(path),
        };
        return group.split(',').map(str::trim).filter(|name| !name.is_empty()).collect();
    }
    let mut tokens = item.split_whitespace();
    let keywords = ["fn", "struct", "enum", "trait", "type", "const"];
    let Some(name) = tokens.find(|t| keywords.contains(t)).and_then(|_| tokens.next()) else {
        return Vec::new();
    };
    let end = name.find(|c: char| !(c.is_alphanumeric() || c == '_')).unwrap_or(name.len());
    vec![&name[..end]]
}

/// Every `.rs` file under `dir`, at any depth.
fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("a source directory") {
        let path = entry.expect("a directory entry").path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}
