use super::*;

/// THE FORMAT REFUSAL's LINE IS THE OPERATOR's: a journal written under
/// another format is refused with the segment found under it, the two stamps
/// and the one remedy a development board has — delete the data directory
/// and start over — in the operator's own terms, and no design document's id
/// rides the line. The remedy is one constant, which the checkpoint's own
/// refusal renders too, so the constant is pinned beside the rendered
/// sentence.
#[test]
fn the_format_refusal_names_the_remedy_and_no_design_id() {
    let refusal = OpenError::ForeignFormat {
        found: *b"SKJ3",
        expected: *b"SKJ4",
        segment: "seg-1.wal".into(),
    }
    .to_string();
    assert!(
        refusal.contains(
            "seg-1.wal opens with the stamp `SKJ3`, this build reads and writes `SKJ4` only"
        ),
        "the segment and the two stamps: {refusal}"
    );
    assert!(
        refusal.ends_with(
            "there is no migration path — every board is a development artifact: delete the \
             data directory and start over"
        ),
        "the remedy, in the operator's terms: {refusal}"
    );
    assert!(!refusal.contains("PUB-"), "a design document's id on the operator's line: {refusal}");
    assert!(!NO_MIGRATION_REMEDY.contains("PUB-"), "the shared remedy: {NO_MIGRATION_REMEDY}");
}

/// EVERY COORDINATE A REFUSAL NAMES IS SPELLED `position N`, the operator's
/// stream's one spelling, so a line naming the damage joins every other line
/// about that position — the open's and the history reads' alike.
#[test]
fn a_refusals_coordinate_is_spelled_as_the_stream_spells_a_position() {
    let open = OpenError::Corruption { at: Seq(41_207), cause: Some("chain break: …".into()) };
    assert_eq!(
        open.to_string(),
        "durable committed data cannot be read; position 41207 names the damage: chain break: …"
    );
    for (refusal, spelled) in [
        (HistoryError::BeyondHead { head: Seq(9) }, "the installed head, position 9"),
        (HistoryError::NotABoundary { nearest: Seq(7) }, "nearest at or below is position 7"),
        (HistoryError::Reclaimed { floor: Some(Seq(8)), cause: None }, "(position 8)"),
        (HistoryError::Corruption { at: Seq(4), cause: None }, "position 4 names the damage"),
    ] {
        let line = refusal.to_string();
        assert!(line.contains(spelled), "{spelled:?} missing from: {line}");
        assert!(!line.contains("coordinate"), "a coordinate spelled otherwise: {line}");
    }
}
