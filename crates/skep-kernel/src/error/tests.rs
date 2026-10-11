use super::*;

/// THE FORMAT REFUSAL's LINE IS THE OPERATOR's: a journal written under
/// another format is refused with the two stamps and the one remedy a
/// development board has — delete the data directory and start over — in
/// the operator's own terms, and no design document's id rides the line.
/// The remedy is one constant, which the checkpoint's own refusal renders
/// too, so the constant is pinned beside the rendered sentence.
#[test]
fn the_format_refusal_names_the_remedy_and_no_design_id() {
    let refusal = OpenError::ForeignFormat { found: *b"SKJ3", expected: *b"SKJ4" }.to_string();
    assert!(
        refusal.contains(
            "its segment opens with the stamp `SKJ3`, this build reads and writes `SKJ4` only"
        ),
        "the two stamps: {refusal}"
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
