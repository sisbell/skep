//! `skep/ARCHITECTURE.md` is tested where it says what a feature adds: the
//! document is read at test RUNTIME from the repo root — a changed sentence
//! needs no rebuild — as `readme_doc.rs` reads the README.

use std::path::Path;

fn architecture_md() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../ARCHITECTURE.md");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

/// THE FEATURES TABLE's `client` ROW says what the page at `GET /` is: the
/// guest reader (`docs/wire.md` §The other endpoints), read-only — and no
/// longer an acting client, which `clients/board.html` never was. The
/// document's other "ACTING client" sentences name the `skep-client`
/// library, which every acting client embeds, and stand.
#[test]
fn architecture_says_the_client_feature_serves_the_guest_reader() {
    let text = architecture_md();
    let start = text
        .find("\n### Features")
        .unwrap_or_else(|| panic!("ARCHITECTURE.md no longer carries its Features table"));
    let features = &text[start..];
    let row = features
        .lines()
        .find(|l| l.starts_with("| `client` |"))
        .unwrap_or_else(|| panic!("the Features table has no `client` row:\n{features}"))
        .to_lowercase();
    assert!(row.contains("guest reader"), "the `client` row names the guest reader: {row}");
    assert!(
        !row.contains("acting client"),
        "the `client` row no longer calls the page an acting client: {row}"
    );
}
