//! `skep/README.md` is tested where it tells a frontend developer how to run
//! the daemon, and where it tells an operator hosting boards how to build
//! and start one: each section is read at test RUNTIME from the repo root —
//! a changed sentence needs no rebuild — as `runbook_doc.rs` reads the
//! runbook. The developer's recipe dials the daemon at its default port,
//! read through its constant; the hosted section names the image's own
//! port, which `skep-provision`'s suite holds to the `Dockerfile`.

use std::path::Path;

use crate::runbook_doc::loopback_ports;

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

/// Checks that the developer's recipe dials the daemon where it listens.
///
/// The recipe runs the daemon with no `--port`, so at `skepd::DEFAULT_PORT`,
/// and every loopback origin the section names is at that port: the
/// daemon's `--origin`, the address it says the daemon listens on, the
/// claim's and the dev provider's `--board`, and the viewer's URL. A default
/// moved in the binary and not here fails here.
#[test]
fn readme_dials_the_developers_daemon_at_its_default_port() {
    let ports = loopback_ports(&section("\n## Running a daemon for frontend development"));
    assert!(!ports.is_empty(), "the recipe dials the daemon");
    assert!(
        ports.iter().all(|p| *p == skepd::DEFAULT_PORT.to_string()),
        "the recipe dials {ports:?}, not the daemon's default {}",
        skepd::DEFAULT_PORT
    );
}

/// Checks that a board hosted without the image is built as the image is.
///
/// The image's daemon is built `--no-default-features` (`operations.md`
/// §3.9 item 8), since the default build's `observe` serves `GET /dump`, a
/// whole-world walk holding no permit, to every guest. The hosted section's
/// paragraph for a host without the image gives the same build and names
/// the end of the open's first line that shows which build runs; and its
/// run paragraph says that a `SKEPD_` name the daemon does not read stops
/// the start, since a run line's `-e` checks no name.
#[test]
fn readme_builds_a_hosts_daemon_as_the_image_does_and_names_the_refused_variable() {
    let hosted = section("\n## Running the hosted image");
    let host = hosted
        .split("**On a host.**")
        .nth(1)
        .and_then(|rest| rest.split("**Rehearsing").next())
        .unwrap_or_else(|| panic!("the hosted section keeps its host paragraph: {hosted}"));
    for named in [
        "`cargo build --release -p skepd --no-default-features`",
        "`built with no optional feature`",
    ] {
        assert!(host.contains(named), "the host paragraph names {named}: {host}");
    }
    assert!(
        hosted.contains("A `SKEPD_` name the daemon does not read stops the start, exit 2"),
        "the run paragraph says an unknown variable stops the start: {hosted}"
    );
}
