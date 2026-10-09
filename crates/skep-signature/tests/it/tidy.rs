//! The crate's outer boundary, which the compiler holds none of: AUTH-2.2's
//! "the one crate that links the signature libraries", read off the
//! workspace's resolved graph; and the verify-only build a daemon links
//! (AUTH-2.89, I1: "skepd's source has no signing capability"), read off
//! this crate's manifest.

use std::collections::BTreeSet;
use std::path::Path;

/// THE ONE CRATE THAT LINKS `ed25519-dalek`, read off the workspace's
/// resolved graph: every package `Cargo.lock` lists as depending on it —
/// dev-dependencies included, since the lock does not tell them apart —
/// is this crate and no other. The suites reach the classical pair
/// through `Ed25519SigningKey` and `Ed25519VerifyingKey` instead, so
/// a manifest that names the library again lands in the lock and fails
/// here, the way `cargo tree -i ed25519-dalek --workspace` would show it.
#[test]
fn ed25519_dalek_is_linked_by_this_crate_alone() {
    let lock = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../Cargo.lock"))
        .expect("the workspace's Cargo.lock");
    let names_dalek = |entry: &str| {
        // A dependency entry is `"name"` or `"name version"` when more
        // than one version of it is resolved.
        let entry = entry.trim().trim_end_matches(',').trim_matches('"');
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
    let (mut table, mut tables) = ("", BTreeSet::new());
    let (mut every_build, mut optional, mut sign) =
        (BTreeSet::new(), BTreeSet::new(), BTreeSet::new());
    for line in manifest.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.starts_with('[') {
            table = line;
            if line.contains("dependencies") {
                tables.insert(line);
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
    assert!(tables.is_subset(&allowed), "Cargo.toml's dependency tables: {tables:?}");
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

/// The dependency a manifest line names, where it names one: the key ahead
/// of `=`, cut at its first dot (`sha2.workspace = true`).
fn dependency_named(line: &str) -> Option<&str> {
    let (key, _) = line.split_once('=')?;
    let name = key.split('.').next()?.trim().trim_matches('"');
    let is_name = |c: char| c.is_ascii_alphanumeric() || c == '-' || c == '_';
    (!name.is_empty() && name.chars().all(is_name)).then_some(name)
}
