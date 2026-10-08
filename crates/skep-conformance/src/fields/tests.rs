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

/// An op refused before it aims reads the document it names in place: the
/// same aim, and the register stays where it stood.
#[test]
fn a_document_read_in_place_moves_no_register() {
    const SOURCE: &str = "1.1.0.1.0.1";
    const OTHER: &str = "1.1.0.1.0.2";
    let mut shadow = Shadow::new();
    shadow.create_doc(SOURCE, Some("source"));
    shadow.create_doc(OTHER, Some("other"));
    let named = json!({"op": "insert_loop", "doc": "source"});
    assert_eq!(doc_aim(&shadow, &named, &["doc", "docid"]), DocAim::Named(SOURCE.into()));
    assert_eq!(shadow.current().as_deref(), Some(OTHER));
    let by_op_name = json!({"op": "insert_doc1"});
    let aimed = doc_aim(&shadow, &by_op_name, &["doc", "docid"]);
    assert_eq!(aimed, DocAim::FromOpName(SOURCE.into()));
    assert_eq!(shadow.current().as_deref(), Some(OTHER));
}

/// A create_link's recorded ids, in each shape the corpus records them — an
/// id, a list, a result object keyed `link` or `link_id`, arrow keys — and
/// none where the recording kept none this reads.
#[test]
fn a_create_link_reads_its_recorded_ids_in_each_shape() {
    const LINK: &str = "1.1.0.1.0.1.0.2.1";
    let read = |op: Value| recorded_links(&op);
    let one = vec![LINK.to_string()];
    assert_eq!(read(json!({"op": "create_link", "result": LINK})), one);
    let two = json!({"op": "create_links", "results": [LINK, "1.1.0.1.0.1.0.2.2"]});
    assert_eq!(read(two).len(), 2);
    let keyed = json!({"op": "makelink_1", "result": {"link": LINK, "links_found": 1}});
    assert_eq!(read(keyed), one);
    let wrapped = json!({"op": "create_link", "result": {"success": true, "link_id": LINK}});
    assert_eq!(read(wrapped), one);
    assert_eq!(read(json!({"op": "create_link", "A->B": LINK})), one);
    let unread = json!({"op": "create_link", "result": {"success": true}});
    assert!(read(unread).is_empty());
    assert!(read(json!({"op": "create_link", "from": "a", "to": "b"})).is_empty());
}

/// A follow's end, read as M7 numbers the ends, in each spelling the corpus
/// uses — the field's word or arrow, else the op's name — and none for a
/// bare follow.
#[test]
fn a_follow_reads_its_end_in_each_spelling() {
    let end = |op: Value| followed_slot(&op);
    assert_eq!(end(json!({"op": "follow_link", "end": "from"})), Some(1));
    assert_eq!(end(json!({"op": "follow_link", "end": "source"})), Some(1));
    assert_eq!(end(json!({"op": "follow_link", "end": "to"})), Some(2));
    assert_eq!(end(json!({"op": "follow_link", "direction": "A->B"})), Some(2));
    assert_eq!(end(json!({"op": "follow_link", "end": "three"})), Some(3));
    assert_eq!(end(json!({"op": "follow_link_target"})), Some(2));
    assert_eq!(end(json!({"op": "follow_link", "end": "elsewhere"})), None);
    assert_eq!(end(json!({"op": "follow_link"})), None);
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

/// A version's source is a reference that resolves — a `doc` naming the new
/// version resolves to nothing, and the register is the source, tagged —
/// and its address is the recorded result, bare or under `version`.
#[test]
fn a_version_reads_its_source_and_its_recorded_address() {
    let mut shadow = Shadow::new();
    shadow.create_doc("1.1.0.1.0.1", Some("source"));
    shadow.create_doc("1.1.0.1.0.2", Some("other"));
    let source = |op: Value| {
        let mut adaptations = Vec::new();
        let src = version_source(&op, &shadow, &mut adaptations);
        (src, adaptations)
    };
    let named = (Some("1.1.0.1.0.1".to_string()), Vec::<String>::new());
    assert_eq!(source(json!({"op": "create_version", "from": "source"})), named);
    assert_eq!(source(json!({"op": "create_version", "doc": "source"})), named);
    let register = (Some("1.1.0.1.0.2".to_string()), vec!["doc-from-register".to_string()]);
    assert_eq!(source(json!({"op": "create_version", "doc": "rearranged"})), register);
    let version =
        |result: Value| version_result(&json!({"op": "create_version", "result": result}));
    assert_eq!(version(json!("1.1.0.1.0.1.1")).as_deref(), Some("1.1.0.1.0.1.1"));
    assert_eq!(version(json!({"version": "1.1.0.1.0.1.2"})).as_deref(), Some("1.1.0.1.0.1.2"));
    assert_eq!(version_result(&json!({"op": "create_version"})), None);
    let named = json!({"op": "create_version", "from": "source", "doc": "draft", "label": "v2"});
    assert_eq!(version_names(&named), ["draft", "v2"]);
}

/// A plural create's documents, in each shape the corpus records: a docs
/// map in id order and a roster in name order, each document under its one
/// name; counted documents under their group's names in each spelling,
/// carrying their texts. Only the counted shape counts, and a count past
/// the budget creates nothing.
#[test]
fn a_plural_create_reads_its_documents_in_each_shape() {
    let created = |op: Value| documents_created(&op).expect("the documents");
    let ids = |c: &CreatedDocuments| c.docs.iter().map(|d| d.id.clone()).collect::<Vec<_>>();
    let id = |s: &str| Some(s.to_string());
    let docs = json!({"B": "1.1.0.1.0.2", "A": "1.1.0.1.0.1"});
    let mapped = created(json!({"op": "create_documents", "docs": docs}));
    assert_eq!(ids(&mapped), [id("1.1.0.1.0.1"), id("1.1.0.1.0.2")]);
    assert_eq!(mapped.docs[0].names, ["A"]);
    assert!(!mapped.counted);
    let rostered = created(json!({"op": "docs", "doc2": "1.1.0.1.0.2", "doc1": "1.1.0.1.0.1"}));
    assert_eq!(ids(&rostered), [id("1.1.0.1.0.1"), id("1.1.0.1.0.2")]);
    assert_eq!(rostered.docs[1].names, ["doc2"]);
    assert!(!rostered.counted);
    let counted = created(json!({
        "op": "create_documents",
        "type": "peripherals",
        "count": 2,
        "results": ["1.1.0.1.0.5"],
        "texts": ["X"],
    }));
    assert!(counted.counted);
    assert_eq!(ids(&counted), [id("1.1.0.1.0.5"), None]);
    assert_eq!(counted.docs[1].names, ["peripherals2", "peripheral2", "peripheral_1"]);
    let texts: Vec<Option<&str>> = counted.docs.iter().map(|d| d.text.as_deref()).collect();
    assert_eq!(texts, [Some("X"), None]);
    assert!(documents_created(&json!({"op": "create_documents", "count": 1u64 << 40})).is_err());
}

/// A create takes its document's name from its `role`, as from a `doc`,
/// `name` or `label` field, or the role its op's name carries — never from
/// an address (versions/version_copies_what names its documents only by
/// role).
#[test]
fn a_create_takes_its_name_from_its_role() {
    let name = |op: Value| create_name_of(&op);
    let role = json!({"op": "create_document", "role": "parent", "result": "1.1.0.1.0.1"});
    assert_eq!(name(role).as_deref(), Some("parent"));
    assert_eq!(name(json!({"op": "create_target"})).as_deref(), Some("target"));
    assert_eq!(name(json!({"op": "create_document", "role": "1.1.0.1.0.1"})), None);
    assert_eq!(name(json!({"op": "create_document"})), None);
}

/// A swap's two region texts name its cuts, the earlier region's first,
/// whichever order the recording lists them in; a region not found, or a
/// list that is no pair, names none.
#[test]
fn a_swap_reads_its_cuts_off_the_regions_it_names() {
    const DOC: &str = "1.1.0.1.0.1";
    let mut shadow = Shadow::new();
    shadow.create_doc(DOC, None);
    shadow.insert(DOC, 1, b"AAA middle BBB");
    let cuts = |regions: Value| {
        let op = json!({"op": "swap", "regions": regions});
        let mut adaptations = Vec::new();
        let cuts = swap_regions(&op, &shadow, DOC, &mut adaptations);
        (cuts, adaptations)
    };
    let found = (Some(vec![1, 4, 12, 15]), vec!["text-located:regions".to_string()]);
    assert_eq!(cuts(json!(["AAA", "BBB"])), found);
    assert_eq!(cuts(json!(["BBB", "AAA"])), found);
    assert_eq!(cuts(json!(["AAA", "CCC"])), (None, Vec::new()));
    assert_eq!(cuts(json!(["AAA"])), (None, Vec::new()));
}
