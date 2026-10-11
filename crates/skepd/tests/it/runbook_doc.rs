//! `skep/RUNBOOK.md` is tested where it quotes the binary: the lines of the
//! open's report it lists are read at test RUNTIME from the repo root — a
//! changed sentence needs no rebuild — and judged against the words and the
//! class word the binary writes, which the child-process suite (`open.rs`)
//! pins on the stream itself. This pins that the runbook quotes them as
//! written, in the form `wire_doc.rs` pins the wire document.

use std::path::Path;

use skep_util::notice::Class;

fn runbook_md() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../RUNBOOK.md");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()))
}

/// The text between `from` and the first of `until` after it, searched from
/// the first occurrence of `after` (`""` is the top) — the lines KEPT, since
/// a claim here is on the line a quoted sentence stands on, where
/// `wire_doc.rs`'s `prose` collapses them.
fn passage(after: &str, from: &str, until: &[&str]) -> String {
    let text = runbook_md();
    let base = text.find(after).unwrap_or_else(|| panic!("RUNBOOK.md no longer carries {after:?}"));
    let text = &text[base..];
    let start = text.find(from).unwrap_or_else(|| panic!("RUNBOOK.md no longer carries {from:?}"));
    let rest = &text[start + from.len()..];
    let end = until.iter().filter_map(|u| rest.find(u)).min().unwrap_or(rest.len());
    rest[..end].to_string()
}

/// §3 START, STEP 3's LIST — THE OPEN's LINES AS THE BINARY WRITES THEM
/// (`operations.md` §1.1 m3; §4 row 8; CUT 1): the list carries the tail
/// cut's line, `open: journal tail cut (`, after the stray `checkpoint.tmp`'s
/// and before the media limits', where the open says it, with the
/// inventory's `journal.tail_cut` beside it; and each line the binary
/// classes that the list once quoted bare — the stray `checkpoint.tmp`'s and
/// the media limits' under `open:`, the first head's and the cell index's
/// landing under `landing:`, the pruner's refused thread under `failure:` —
/// opens with the class word the door spells, read off the door's own type,
/// so a word spelled another way here fails.
#[test]
fn runbook_lists_the_tail_cut_and_classes_the_opens_lines() {
    let list = passage(
        "\n## 3. Start",
        "the daemon writes them:",
        &["\n4. **Read the one line on stdout**"],
    );
    let at = |phrase: &str| {
        list.find(phrase).unwrap_or_else(|| panic!("step 3's list quotes {phrase:?}:\n{list}"))
    };
    assert!(
        at("checkpoint.tmp found (") < at("open: journal tail cut ("),
        "the tail cut's line follows the stray `checkpoint.tmp`'s"
    );
    assert!(
        at("open: journal tail cut (") < at("media limits:"),
        "the tail cut's line precedes the media limits'"
    );
    assert!(
        list.contains("`journal.tail_cut`"),
        "the tail cut's item names the inventory's figure"
    );
    let classed = |phrase: &str, class: Class| {
        let line = list
            .lines()
            .find(|l| l.contains(phrase))
            .unwrap_or_else(|| panic!("step 3's list quotes {phrase:?}:\n{list}"));
        assert!(
            line.trim_start().starts_with(&format!("{class}: ")),
            "the quoted line opens with `{class}: `, the class the binary writes it under: {line:?}"
        );
    };
    classed("checkpoint.tmp found (", Class::Open);
    classed("journal tail cut (", Class::Open);
    classed("media limits:", Class::Open);
    classed("H.1 written at open", Class::Landing);
    classed("pruner: the OS refused its thread (", Class::Failure);
    classed("cell index rebuilt at open:", Class::Landing);
}

/// §3 START's BUILD NOTE — THE `client` FEATURE's BULLET says what the page
/// at `GET /` is: the guest reader (`docs/wire.md` §The other endpoints),
/// read-only — and no longer a page that makes keys and opens signed
/// sessions, which `clients/board.html` never did.
#[test]
fn runbook_says_the_client_feature_serves_the_guest_reader() {
    let bullet = passage("\n## 3. Start", "- `client`, off by default:", &["\n   - `test-hooks`"]);
    assert!(
        bullet.contains("guest reader"),
        "the `client` bullet names the guest reader: {bullet}"
    );
    for stale in ["opens signed sessions", "makes keys"] {
        assert!(!bullet.contains(stale), "the `client` bullet no longer says {stale:?}: {bullet}");
    }
}
