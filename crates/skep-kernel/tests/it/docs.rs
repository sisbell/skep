//! THE KERNEL's FIGURES WHERE THE WORKSPACE's DOCS RESTATE THEM, read at test
//! runtime from the workspace root as prose, so a rewrap moves no pin. The
//! segment ceiling, [`MAX_SEGMENT_LEN`], is the one figure of this crate the
//! wire contract and the runbook carry — the media floor reserves one
//! maximal segment beside twice the newest checkpoint — and each
//! restatement is rendered here from the constant, so a ceiling moved with
//! the stamp fails here, in the suite of the crate that moved it, until the
//! sentences say the new figure.

use std::fs;
use std::path::Path;

use skep_kernel::MAX_SEGMENT_LEN;

/// The workspace doc at `relative` (from this crate's manifest), every run of
/// whitespace read as one space.
fn prose(relative: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(relative);
    let text =
        fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// THE SEGMENT CEILING AS THE DOCS SAY IT: `docs/wire.md` §Media in MiB, and
/// `RUNBOOK.md` twice — the floor's own step in MiB, and the open's media
/// line it quotes in bytes — each the figure the constant sets.
#[test]
fn the_docs_restate_the_segment_ceiling_as_the_constant_sets_it() {
    const MIB: u64 = 1024 * 1024;
    assert_eq!(MAX_SEGMENT_LEN % MIB, 0, "the ceiling is whole MiB, as the docs spell it");
    let mib = MAX_SEGMENT_LEN / MIB;
    let wire = prose("../../docs/wire.md");
    let clause = format!("plus one maximal segment ({mib} MiB, the journal's reader ceiling)");
    assert!(wire.contains(&clause), "docs/wire.md §Media does not say: {clause}");
    let runbook = prose("../../RUNBOOK.md");
    for clause in [
        format!("twice the newest checkpoint's size plus {mib} MiB"),
        format!("one maximal segment of {MAX_SEGMENT_LEN} bytes"),
    ] {
        assert!(runbook.contains(&clause), "RUNBOOK.md does not say: {clause}");
    }
}
