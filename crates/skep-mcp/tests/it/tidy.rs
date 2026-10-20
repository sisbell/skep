//! The source held to its tables: what `src/` reads, and what the README says.
//!
//! The adapter's settings are tabled once, in the README's Settings; the
//! unit suite holds each row's spelling to the parse's, and this suite holds
//! the source to the table: no variable is read that the table does not name,
//! and none the suite's launches leave set.

use std::fs;
use std::path::{Path, PathBuf};

use crate::common::VARIABLES;

/// Returns every `.rs` file under `dir`, but a unit suite's `tests.rs`.
fn rust_files(dir: &Path, files: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display())).flatten() {
        let path = entry.path();
        if path.is_dir() {
            rust_files(&path, files);
        } else if path.extension().is_some_and(|ext| ext == "rs") && path.file_name().is_some_and(|name| name != "tests.rs") {
            files.push(path);
        }
    }
}

/// Returns a file's code lines, numbered: its `//` lines left out, and the
/// lines from its inline unit suite's `mod tests {` on unread.
///
/// The suite opens at its module, never at the first `#[cfg(test)]`, which
/// marks a test-only item among the code too.
fn code_lines(text: &str) -> impl Iterator<Item = (usize, &str)> {
    text.lines().enumerate().map(|(k, line)| (k + 1, line)).take_while(|(_, line)| line.trim() != "mod tests {").filter(|(_, line)| !line.trim_start().starts_with("//"))
}

/// Every variable the source reads is a row of the README's settings.
///
/// The scan reads `src/` for a `"SKEP_…"` or `"SKEPD_…"` literal and a
/// variable a std read names (`env::var("…")`, `env::var_os("…")`), and for
/// the reads a library makes for this process: `default_store_dir`, `HOME`
/// else `USERPROFILE`, and the shell's open, `HOSTNAME` else `COMPUTERNAME`.
/// A compile-time read (`env!`, `option_env!`) is the build's, tabled beside
/// the table. The `SKEP` variables found are exactly the ones every launch
/// here clears (`VARIABLES`), so no variable the adapter reads reaches a test
/// from the shell that runs it; and each variable found is a row of the
/// README's Settings.
#[test]
fn every_variable_the_source_reads_is_a_row_of_the_readmes_settings() {
    let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let src = crate_dir.join("src");
    let mut files = Vec::new();
    rust_files(&src, &mut files);
    let mut found: Vec<(String, String)> = Vec::new();
    for file in &files {
        let text = fs::read_to_string(file).unwrap_or_else(|e| panic!("{}: {e}", file.display()));
        let shown = file.strip_prefix(&src).expect("under src").display().to_string();
        for (n, code) in code_lines(&text) {
            let at = format!("src/{shown}:{n}");
            if code.contains("env!(") {
                continue;
            }
            for (needle, skip) in [("\"SKEP_", 1), ("\"SKEPD_", 1), ("env::var(\"", "env::var(\"".len()), ("env::var_os(\"", "env::var_os(\"".len())] {
                for (i, _) in code.match_indices(needle) {
                    let name: String = code[i + skip..].chars().take_while(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == '_').collect();
                    found.push((name, at.clone()));
                }
            }
            if code.contains("default_store_dir(") {
                found.extend(["HOME", "USERPROFILE"].map(|name| (name.to_string(), at.clone())));
            }
            if code.contains("Shell::open(") {
                found.extend(["HOSTNAME", "COMPUTERNAME"].map(|name| (name.to_string(), at.clone())));
            }
        }
    }
    let mut skep: Vec<&str> = found.iter().map(|(name, _)| name.as_str()).filter(|name| name.starts_with("SKEP")).collect();
    skep.sort_unstable();
    skep.dedup();
    let mut cleared = VARIABLES.to_vec();
    cleared.sort_unstable();
    assert_eq!(skep, cleared, "the SKEP variables the source reads are the ones every launch here clears");
    for name in ["HOME", "HOSTNAME"] {
        assert!(found.iter().any(|(f, _)| f == name), "the scan reads `{name}`: the forms it reads have moved");
    }
    let readme = fs::read_to_string(crate_dir.join("README.md")).expect("the crate's README");
    let settings = readme.split("\n## Settings\n").nth(1).expect("the README has a Settings section");
    let settings = settings.split("\n## ").next().unwrap_or(settings);
    let rows: Vec<&str> = settings.lines().filter(|line| line.starts_with("| ")).collect();
    let faults: Vec<String> = found
        .iter()
        .filter(|(name, _)| !rows.iter().any(|row| row.contains(&format!("`{name}`"))))
        .map(|(name, at)| format!("{at}: `{name}` is read and is no row of the README's Settings"))
        .collect();
    assert!(faults.is_empty(), "every variable the adapter reads is tabled, its default and where it is read beside it:\n{}", faults.join("\n"));
}
