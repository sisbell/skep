use serde_json::json;

use super::*;

/// The recording client's crash, in each form the corpus records it — and
/// nothing else: udanax's own refusals stay recorded failures.
#[test]
fn a_client_crash_is_recognized_in_each_recorded_form() {
    let crash = "'XuSession' object has no attribute 'rearrange'";
    let forms = [
        json!({"op": "copy", "result": format!("OPERATION_FAILED: {crash}")}),
        json!({"op": "rearrange", "result": format!("FAILED: {crash}")}),
        json!({"op": "find_documents_containing", "error": crash, "result": []}),
    ];
    for op in &forms {
        assert!(client_side_failure(op).is_some(), "{op}");
    }
    let refused = json!({"op": "open", "error": "request failed (?)"});
    assert_eq!(client_side_failure(&refused), None);
    let failed = json!({"op": "x", "result": "FAILED: out of range"});
    assert_eq!(client_side_failure(&failed), None);
}

/// A recorded array outranks prose: rearrange/double_pivot's three probes
/// read their arrays — the op's one unlisted array included — never
/// `expected`'s sentence; prose alone is still read; two unlisted arrays
/// name no single answer.
#[test]
fn a_recorded_array_outranks_prose() {
    let read = |op: Value| recorded_content(&op, &["doc", "docid"]);
    let answer = |key: &str, text: &str| Some((key.to_string(), vec![text.to_string()]));
    let original = json!({"op": "retrieve", "original": ["ABCDE"]});
    assert_eq!(read(original), answer("original", "ABCDE"));
    let first = json!({"op": "retrieve", "after_first": ["ADEBC"]});
    assert_eq!(read(first), answer("after_first", "ADEBC"));
    let second = json!({
        "op": "retrieve",
        "after_second": ["ABCDE"],
        "expected": "Should match original (ABCDE)",
    });
    assert_eq!(read(second), answer("after_second", "ABCDE"));
    let prose = json!({"op": "retrieve", "expected": "ABCDE"});
    assert_eq!(read(prose), answer("expected", "ABCDE"));
    let two = json!({"op": "retrieve", "source": ["CDEFG"], "dest": ["CDEFG"]});
    assert_eq!(read(two), None);
}

/// The one reading of a vcopy's sources, the corpus extension's single vspec
/// dict included; an op it cannot read says why.
#[test]
fn a_single_vspec_dict_is_a_vcopy_source() {
    let mut shadow = Shadow::new();
    shadow.create_doc("1.1.0.1.0.1", Some("source"));
    shadow.insert("1.1.0.1.0.1", 1, b"hello world");
    let op = json!({
        "op": "vcopy",
        "source": {"docid": "1.1.0.1.0.1", "span": {"start": "1.7", "width": "0.5"}},
    });
    let region = VRegion { sub: 1, ord: 7, width: 5 };
    let source = CopySource { doc: "1.1.0.1.0.1".into(), region };
    assert_eq!(vcopy_sources(&op, &shadow, &mut Vec::new()), Ok(vec![source]));
    assert_eq!(
        vcopy_sources(&json!({"op": "vcopy"}), &shadow, &mut Vec::new()),
        Err("vcopy without specs, span or text".into())
    );
}

/// A vcopy source described at the top of the range grounds as recorded,
/// outside every extent — its end saturating, never overflowing.
#[test]
fn a_described_source_at_the_top_of_the_range_grounds_without_overflow() {
    let mut shadow = Shadow::new();
    shadow.create_doc("1.1.0.1.0.1", Some("source"));
    shadow.insert("1.1.0.1.0.1", 1, b"hello world");
    let op = json!({"op": "vcopy", "from": "1.18446744073709551615 for 0.5"});
    let region = VRegion { sub: 1, ord: u64::MAX, width: 5 };
    let source = CopySource { doc: "1.1.0.1.0.1".into(), region };
    assert_eq!(vcopy_sources(&op, &shadow, &mut Vec::new()), Ok(vec![source]));
}

/// An explicit document reference that resolves to nothing — "version"
/// before any version is made — is never the register; a bare op is, and a
/// reference that resolves becomes it.
#[test]
fn an_explicit_reference_that_resolves_to_nothing_is_never_the_register() {
    const SOURCE: &str = "1.1.0.1.0.1";
    const OTHER: &str = "1.1.0.1.0.2";
    let mut shadow = Shadow::new();
    shadow.create_doc(SOURCE, Some("source"));
    shadow.create_doc(OTHER, Some("other"));
    shadow.set_current(SOURCE);
    let mut aim = |op: Value| aim_doc(&mut shadow, &op, &["doc", "docid"]);
    assert_eq!(aim(json!({"op": "insert", "doc": "ghost"})), DocAim::Unresolved("ghost".into()));
    let version = DocAim::Unresolved("version".into());
    assert_eq!(aim(json!({"op": "insert", "doc": "version"})), version);
    assert_eq!(aim(json!({"op": "insert"})), DocAim::Register(SOURCE.into()));
    assert_eq!(aim(json!({"op": "insert", "doc": "other"})), DocAim::Named(OTHER.into()));
    assert_eq!(aim(json!({"op": "insert"})), DocAim::Register(OTHER.into()));
}

/// Only a zero-width recorded span is dropped — udanax's rendering of
/// emptiness, which contains no address; a span of any width is kept,
/// however deep its width runs.
#[test]
fn only_a_zero_width_recorded_span_is_dropped() {
    let spans = |w: &str| {
        raw_spanset_of(&json!([{"start": "1.1", "width": w}])).map(|(_, spans)| spans)
    };
    let kept = |w: &str| Some(vec![("1.1".to_string(), w.to_string())]);
    assert_eq!(spans("0.0"), Some(Vec::new()));
    assert_eq!(spans("0.1"), kept("0.1"));
    assert_eq!(spans("0.0.1"), kept("0.0.1"));
    let empty = json!("<VSpan in 1.1.0.1.0.1 at 0 for 0>");
    assert_eq!(raw_spanset_of(&empty).map(|(_, spans)| spans), Some(Vec::new()));
}

/// Neither a golden address nor a recording-client repr is document text,
/// wherever it stands in a reply; text that merely looks dotted or
/// bracketed is.
#[test]
fn neither_an_address_nor_a_client_repr_is_document_text() {
    let text = |ss: &[&str]| as_text(&ss.iter().map(|s| s.to_string()).collect::<Vec<_>>());
    assert_eq!(text(&["AB", "CD"]).as_deref(), Some("ABCD"));
    assert_eq!(text(&["<VSpan in 1.1.0.1.0.1 at 0 for 0>"]), None);
    assert_eq!(text(&["<SpecSet []>"]), None);
    assert_eq!(text(&["AB", "1.1.0.1.0.1.0.2.1"]), None);
    assert_eq!(text(&["1.1.0.1.0.1"]), None);
    assert_eq!(text(&["2.5"]).as_deref(), Some("2.5"));
    assert_eq!(text(&["0123456789.1"]).as_deref(), Some("0123456789.1"));
    assert_eq!(text(&["<b>"]).as_deref(), Some("<b>"));
}

/// A meta-named op that carries an observation — a string array under a
/// key no annotation holds, a docs map, a reply-shaped result — is a probe;
/// one that carries none stays meta.
#[test]
fn a_meta_named_op_that_carries_an_observation_is_a_probe() {
    let verb = |op: Value| normalize(op_name(&op), &op);
    assert_eq!(verb(json!({"op": "snapshot", "A_content": ["X"]})), Some(Verb::Observe));
    assert_eq!(verb(json!({"op": "dump_state", "docs": {"A": ["X"]}})), Some(Verb::Observe));
    assert_eq!(verb(json!({"op": "verify", "result": ["X"]})), Some(Verb::Observe));
    let commented = json!({"op": "snapshot", "comment": "before the delete"});
    assert_eq!(verb(commented), Some(Verb::Meta));
    assert_eq!(verb(json!({"op": "summary", "counts": {"links": 2}})), Some(Verb::Meta));
}

/// The stem table reads in order, so a stem that starts with an earlier one
/// would never be reached: none is shadowed, and each reads as its own verb.
#[test]
fn no_verb_stem_is_shadowed_by_an_earlier_one() {
    for (i, (stem, verb)) in STEMS.iter().enumerate() {
        let shadowing = STEMS[..i].iter().find(|(earlier, _)| stem.starts_with(earlier));
        assert_eq!(shadowing, None, "stem `{stem}` is shadowed");
        assert_eq!(normalize(stem, &json!({ "op": stem })), Some(*verb), "stem `{stem}`");
    }
}

/// A description grounds at the occurrence it selects and the range it
/// names: "(second)" is the second occurrence, an occurrence that is not
/// there grounds nowhere, and an explicit range outranks its reminder text.
#[test]
fn a_description_grounds_at_the_occurrence_and_range_it_names() {
    let mut shadow = Shadow::new();
    shadow.create_doc("1.1.0.1.0.1", None);
    shadow.insert("1.1.0.1.0.1", 1, b"the bank by the bank");
    let at = |desc: &str| locate(&shadow, None, desc).map(|l| (l.ord, l.width, l.how));
    assert_eq!(at("bank (second)"), Some((17, 4, Grounding::NthText)));
    assert_eq!(at("bank (first)"), Some((5, 4, Grounding::NthText)));
    assert_eq!(at("bank (third)"), None);
    assert_eq!(at("1.5-1.8"), Some((5, 4, Grounding::Range)));
    assert_eq!(at("by (5-8)"), Some((5, 4, Grounding::Range)));
}

/// An open forks into a version in either spelling the recordings use, and
/// in no other.
#[test]
fn a_conflict_copy_reads_in_either_spelling() {
    let open = |mut op: Value| {
        op["op"] = json!("open_document");
        is_conflict_copy(&op)
    };
    assert!(open(json!({"conflict": "copy"})));
    assert!(open(json!({"copy_mode": "conflict_copy"})));
    assert!(open(json!({"copy": "conflict_copy"})));
    assert!(!open(json!({"mode": "read"})));
    assert!(!open(json!({"conflict": "fail"})));
}

/// A create's recorded addresses, in each shape the corpus records them —
/// an address, a list, an object keyed by the name the op gives its
/// document — and none where the recording kept no address this reads.
#[test]
fn a_create_reads_its_recorded_addresses_in_each_shape() {
    let read = |op: Value| created_addresses(&op);
    let addresses = |ids: &[&str]| Some(ids.iter().map(|id| id.to_string()).collect::<Vec<_>>());
    let one = json!({"op": "create_document", "result": "1.1.0.1.0.1"});
    assert_eq!(read(one), addresses(&["1.1.0.1.0.1"]));
    let list = json!({"op": "create_documents", "results": ["1.1.0.1.0.1", "1.1.0.1.0.2"]});
    assert_eq!(read(list), addresses(&["1.1.0.1.0.1", "1.1.0.1.0.2"]));
    let keyed = json!({"op": "create_doc2_and_copy", "result": {"doc2": "1.1.0.1.0.2"}});
    assert_eq!(read(keyed), addresses(&["1.1.0.1.0.2"]));
    let elsewhere = json!({"op": "create_doc2_and_copy", "result": {"doc3": "1.1.0.1.0.2"}});
    assert_eq!(read(elsewhere), None);
    assert_eq!(read(json!({"op": "create_documents", "count": 3})), None);
}
