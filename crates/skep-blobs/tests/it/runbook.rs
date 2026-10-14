//! `RUNBOOK.md` WHERE IT NAMES THIS STORE's FILES, read at test runtime from
//! the workspace root, as skepd's suite reads it where it quotes the
//! daemon's lines: a step that tells an operator which of the blob store's
//! files to remove names each file a store keeps, so a log the store gains
//! or renames fails here until the step that discards it says so.

use std::fs;
use std::path::Path;

use crate::open;

/// The runbook's text from `from` to the first of `until` after it, every
/// whitespace run collapsed, so a re-wrap moves no pin.
fn passage(from: &str, until: &[&str]) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../RUNBOOK.md");
    let text = fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    let start = text.find(from).unwrap_or_else(|| panic!("RUNBOOK.md no longer carries {from:?}"));
    let rest = &text[start..];
    let end = until.iter().filter_map(|u| rest.find(u)).min().unwrap_or(rest.len());
    rest[..end].split_whitespace().collect::<Vec<_>>().join(" ")
}

/// §2 RESTORE, STEP 8 — A COMPROMISE's REMEDIATION DISCARDS EVERY MEDIA
/// STORE BUT THE FILES (`media.md` §Recovery): the step removes each log a
/// store keeps under its root — every file a fresh store makes there, named
/// as it stands under `blobs/` — and each log's compaction twin, and nothing
/// else under `blobs/`, so the deposited files the cells name stay.
#[test]
fn the_compromise_remediation_discards_every_log_the_store_keeps_and_nothing_else() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path().join("blobs");
    drop(open(&root, 0));
    let mut logs: Vec<String> = fs::read_dir(&root)
        .unwrap()
        .map(|entry| entry.unwrap())
        .filter(|entry| entry.file_type().unwrap().is_file())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    logs.sort();
    assert_eq!(logs, ["leases.log", "uploads.log"], "the files a fresh store keeps under its root: its two logs");
    let step = passage("8. **After a compromise", &["\n## 3. Start"]);
    for log in &logs {
        assert!(step.contains(&format!("`blobs/{log}`")), "the step removes blobs/{log}: {step}");
    }
    assert!(step.contains("the `.compact` file beside either"), "and each log's compaction twin: {step}");
    assert!(step.contains("nothing else under `blobs/`"), "and keeps the files: {step}");
}
