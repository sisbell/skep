//! `skep/README.md` is tested where it tells a frontend developer how to run
//! the daemon: the section is read at test RUNTIME from the repo root — a
//! changed sentence needs no rebuild — as `runbook_doc.rs` reads the
//! runbook.

use std::path::Path;

fn readme_md() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../README.md");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

/// The section headed `heading`, from it to the next section or the closing
/// rule, with every whitespace run collapsed — so a re-wrap moves no pin.
fn section(heading: &str) -> String {
    let text = readme_md();
    let start = text.find(heading).unwrap_or_else(|| panic!("README.md no longer carries {heading:?}"));
    let rest = &text[start + heading.len()..];
    let end = ["\n## ", "\n---"].iter().filter_map(|u| rest.find(u)).min().unwrap_or(rest.len());
    rest[..end].split_whitespace().collect::<Vec<_>>().join(" ")
}

/// THE DEVELOPER's RECIPE — A THROWAWAY BOARD, LOCAL TRUST ON AND SAID WHY
/// (the local-board record's §7.3 and decision 2, RULED: the daemon's
/// default kept for a developer's throwaway board, whose dev provider's bare
/// session needs it): the section runs the daemon over `./board`, names
/// `skep-dev serve` as the dev provider, keeps local trust on in a sentence
/// that gives the bare session as its reason, and never passes
/// `--no-local-trust`, the kept notebook's flag (`RUNBOOK.md` §3 step 2).
#[test]
fn readme_runs_a_throwaway_board_for_the_dev_provider_with_local_trust_on() {
    let recipe = section("\n## Running a daemon for frontend development");
    for named in ["--data-dir ./board", "skep-dev serve", "throwaway"] {
        assert!(recipe.contains(named), "the recipe names {named:?}: {recipe}");
    }
    let trust = recipe
        .split(". ")
        .find(|sentence| sentence.to_lowercase().contains("local trust"))
        .unwrap_or_else(|| panic!("the recipe says local trust stays on: {recipe}"));
    assert!(trust.contains("bare session"), "the local-trust sentence gives its reason: {trust}");
    assert!(!recipe.contains("--no-local-trust"), "the throwaway keeps local trust on: {recipe}");
}
