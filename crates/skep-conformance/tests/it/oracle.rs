//! The oracle held to its own claims: hand-built scenarios played through
//! the real engine and operation surface (`runner::run_scenarios`), each
//! pinning how the harness judges — how op outcomes add up to a scenario's
//! verdict, which agreements it may record, and which references it must
//! refuse rather than re-aim. The golden sweep cannot hold these: no golden
//! is built to fail them, and a harness regression toward a false agreement
//! reads in the ratchet as an improvement.

use std::fs;

use serde_json::{json, Value};

use skep_conformance::allowlist::{self, Allowlist};
use skep_conformance::loader::Scenario;
use skep_conformance::outcome::{ScenarioRecord, Status, Verdict};
use skep_conformance::runner::run_scenarios;

/// Play one hand-built scenario, keyed `oracle/<name>`, under `allow`. The
/// harness itself must not fail on it.
fn play_under(name: &str, operations: Vec<Value>, allow: &Allowlist) -> ScenarioRecord {
    let scenario = Scenario {
        category: "oracle".into(),
        name: name.into(),
        description: String::new(),
        operations,
    };
    let record = run_scenarios(&[scenario], allow).pop().expect("one record per scenario");
    assert_ne!(record.verdict, Verdict::Error, "{:?}", record.error);
    record
}

fn play(name: &str, operations: Vec<Value>) -> ScenarioRecord {
    play_under(name, operations, &Allowlist::default())
}

/// An allowlist of one entry covering `oracle/<name>` — op `op` alone, or
/// every op — loaded from the file format the gate reads.
fn covering(name: &str, op: Option<usize>) -> Allowlist {
    let dir = std::env::temp_dir().join(format!("skep-oracle-{name}-{}", std::process::id()));
    fs::create_dir_all(&dir).expect("a scratch directory");
    let path = dir.join("allowlist.toml");
    let index = op.map(|i| format!("op_index = {i}\n")).unwrap_or_default();
    let entry = format!(
        "[[allow]]\nscenario = \"oracle/{name}\"\n{index}class = \"ruled\"\nrationale = \"r\"\n"
    );
    fs::write(&path, entry).expect("an allowlist");
    let allow = allowlist::load(&path).expect("the allowlist loads");
    fs::remove_dir_all(&dir).expect("the scratch directory is removed");
    allow
}

/// A failure as the recording client records udanax's refusal.
const REFUSED: &str = "request failed (?)";

/// Every op's status, in order.
fn statuses(record: &ScenarioRecord) -> Vec<Status> {
    record.ops.iter().map(|o| o.status).collect()
}

fn create(name: &str, golden: &str) -> Value {
    json!({"op": "create_document", "doc": name, "result": golden})
}

fn insert(doc: &str, text: &str) -> Value {
    json!({"op": "insert", "doc": doc, "text": text})
}

fn retrieve(doc: &str, result: &[&str]) -> Value {
    json!({"op": "retrieve_contents", "doc": doc, "result": result})
}

/// One document holding "A", read back as "B" and then as "C": two
/// disagreements no seed can absorb, since undoing the insert from either
/// probe finds no "A" to remove.
fn two_disagreements() -> Vec<Value> {
    vec![
        create("d", "1.1.0.1.0.1"),
        insert("d", "A"),
        retrieve("d", &["B"]),
        retrieve("d", &["C"]),
    ]
}

/// The control: a scenario every comparison agrees in passes.
#[test]
fn a_scenario_nothing_disagrees_in_passes() {
    let ops = vec![create("d", "1.1.0.1.0.1"), insert("d", "A"), retrieve("d", &["A"])];
    let record = play("agreeing", ops);
    assert_eq!(statuses(&record), [Status::Agreed, Status::NotCompared, Status::Agreed]);
    assert_eq!(record.verdict, Verdict::Pass);
}

/// One disagreement no entry covers keeps its scenario divergent, however
/// many others are covered, and leads the scenario's first finding.
#[test]
fn an_uncovered_disagreement_keeps_its_scenario_divergent() {
    let record = play_under("uncovered", two_disagreements(), &covering("uncovered", Some(2)));
    assert_eq!(record.ops[2].allowlisted.as_deref(), Some("ruled"));
    assert_eq!(record.ops[3].allowlisted, None);
    assert_eq!(record.verdict, Verdict::Divergent);
    let first = record.first_finding.expect("a first finding");
    assert_eq!(first.index, 3, "the uncovered disagreement leads");
}

/// A scenario whose every disagreement an entry covers is allowlisted.
#[test]
fn a_scenario_whose_every_disagreement_is_covered_is_allowlisted() {
    let record = play_under("covered", two_disagreements(), &covering("covered", None));
    assert_eq!(record.verdict, Verdict::Allowlisted);
}

/// An inexpressible op outranks every disagreement, covered or not.
#[test]
fn an_inexpressible_op_outranks_every_disagreement() {
    let mut ops = two_disagreements();
    ops.push(json!({"value": 1}));
    let record = play("outranked", ops);
    assert_eq!(record.ops[4].status, Status::Inexpressible);
    assert_eq!(record.verdict, Verdict::Inexpressible);
}

/// An α-finding makes the op it arose on disagree, owned by the α
/// comparator, its evidence in the note: binding one golden address to a
/// second skep document is a finding, never a silent rebind.
#[test]
fn an_alpha_finding_makes_its_op_disagree() {
    let ops = vec![
        json!({"op": "create_document", "result": "1.1.0.1.0.1"}),
        json!({"op": "create_document", "result": "1.1.0.1.0.2"}),
        json!({"op": "open_document", "doc": "1.1.0.1.0.1", "result": "1.1.0.1.0.2"}),
    ];
    let record = play("double_bind", ops);
    let open = &record.ops[2];
    assert_eq!((open.status, open.comparator), (Status::Disagreed, Some("alpha")));
    let note = open.note.as_deref().unwrap_or_default();
    assert!(note.contains("alpha-double-bind-golden"), "{note}");
    assert_eq!(record.verdict, Verdict::Divergent);
}

/// A version skep refuses to make (a private source, PUB-2.9) is named by
/// no later op: a write, a read and every search naming it are refused
/// (rulings 20, 20a), never re-aimed at another document — and the other
/// document stays exactly as its own recording left it.
#[test]
fn a_refused_version_is_named_by_no_later_op() {
    let ops = vec![
        create("source", "1.1.0.1.0.1"),
        insert("source", "Shared text"),
        create("other", "1.1.0.1.0.2"),
        insert("other", "Other text"),
        json!({"op": "create_version", "from": "source", "result": "1.1.0.1.0.1.1"}),
        insert("version", " (edited)"),
        retrieve("version", &["Shared text (edited)"]),
        json!({"op": "find_links", "from": "version", "result": []}),
        json!({"op": "find_links", "doc": "version", "result": []}),
        json!({"op": "find_links", "search_doc": "version", "result": []}),
        json!({"op": "find_documents", "doc": "version", "result": []}),
        json!({"op": "find_documents", "search_from": "version", "result": []}),
        retrieve("other", &["Other text"]),
    ];
    let record = play("refused_version", ops);
    let refused = &record.ops[4];
    assert_eq!(refused.status, Status::Disagreed, "skep refused the version: {:?}", refused);
    for op in &record.ops[5..12] {
        assert_eq!(op.status, Status::Inexpressible, "op {} `{}`: {:?}", op.index, op.op_name, op);
    }
    assert_eq!(record.ops[12].status, Status::Agreed, "{:?}", record.ops[12]);
}

/// A version skep refuses is never seeded with the answer its own probe
/// expects: no document is minted under its address, so a probe by that
/// address meets a never-bound reference.
#[test]
fn a_refused_version_is_never_seeded_with_its_expected_content() {
    let ops = vec![
        create("source", "1.1.0.1.0.1"),
        insert("source", "AB"),
        json!({"op": "create_version", "from": "source", "result": "1.1.0.1.0.1.1"}),
        retrieve("1.1.0.1.0.1.1", &["XY"]),
    ];
    let record = play("seeded_version", ops);
    assert_eq!(record.ops[2].status, Status::Disagreed, "skep refused the version");
    let probe = &record.ops[3];
    assert_eq!((probe.status, probe.comparator), (Status::Disagreed, Some("alpha")));
    assert!(record.groundings.is_empty(), "{:?}", record.groundings);
}

/// A compare that names no document reads the harness's default: in a
/// scenario that made no version, the first two documents created; after a
/// version the recording made, that version — one skep refused leaves the
/// compare inexpressible, never compared with the original itself.
#[test]
fn a_compare_naming_no_document_aims_at_the_version_the_recording_made() {
    let shares_nothing = json!({"op": "compare_versions", "shared": []});
    let unversioned = vec![
        create("doc1", "1.1.0.1.0.1"),
        insert("doc1", "AAA"),
        create("doc2", "1.1.0.1.0.2"),
        insert("doc2", "BBB"),
        shares_nothing,
    ];
    let record = play("unversioned_compare", unversioned);
    let compare = &record.ops[4];
    assert_eq!(compare.status, Status::Agreed, "{compare:?}");
    assert!(compare.adaptations.iter().any(|a| a == "compare-default:second-document"));

    let whole = json!({"start": "1.1", "width": "0.5"});
    let shares_everything =
        json!({"op": "compare_versions", "shared": [{"source": whole, "dest": whole}]});
    let versioned = vec![
        create("source", "1.1.0.1.0.1"),
        insert("source", "Hello"),
        json!({"op": "create_version", "from": "source", "result": "1.1.0.1.0.1.1"}),
        shares_everything,
    ];
    let record = play("versioned_compare", versioned);
    assert_eq!(record.ops[2].status, Status::Disagreed, "skep refused the version");
    let compare = &record.ops[3];
    assert_eq!(compare.status, Status::Inexpressible, "{compare:?}");
    assert!(!compare.adaptations.iter().any(|a| a == "compare:self"));
}

/// A compare naming a document the shadow cannot ground is never a compare
/// of the other document with itself, which the recorded identity pair
/// would let agree.
#[test]
fn a_compare_naming_an_ungroundable_document_is_never_a_self_compare() {
    let whole = json!({"start": "1.1", "width": "0.5"});
    let ops = vec![
        create("source", "1.1.0.1.0.1"),
        insert("source", "Hello"),
        json!({
            "op": "compare_versions",
            "docs": ["source", "ghost"],
            "shared": [{"a": whole, "b": whole}],
        }),
    ];
    let record = play("ghost_compare", ops);
    let compare = &record.ops[2];
    assert_eq!(compare.status, Status::Inexpressible, "{compare:?}");
    assert!(!compare.adaptations.iter().any(|a| a == "compare:self"));
}

/// The recorded failure of a document never created meets skep's absence
/// as agreement (`joint-absence`); the recorded failure of a document that
/// exists meets skep's answer as a disagreement.
#[test]
fn joint_absence_holds_only_for_a_document_never_created() {
    let failed_probe = |doc: &str| json!({"op": "probe", "doc": doc, "error": REFUSED});
    let ops = vec![
        json!({"op": "create_document", "result": "1.1.0.1.0.1"}),
        failed_probe("1.1.0.1.0.1"),
        failed_probe("1.1.0.1.0.1.7"),
    ];
    let record = play("joint_absence", ops);
    assert_eq!(statuses(&record), [Status::Agreed, Status::Disagreed, Status::Agreed]);
    assert!(record.ops[2].adaptations.iter().any(|a| a == "joint-absence"));
}

/// A recorded refusal of an open is never absorbed into the open no-op:
/// skep has no open layer to refuse with, and the divergence stands.
#[test]
fn a_recorded_refusal_of_an_open_is_never_absorbed_into_the_no_op() {
    let ops = vec![
        create("d", "1.1.0.1.0.1"),
        json!({"op": "open_document", "doc": "d", "mode": "read", "error": REFUSED}),
    ];
    let record = play("refused_open", ops);
    assert_eq!(record.ops[1].status, Status::Disagreed, "{:?}", record.ops[1]);
}

/// A whole-document read asks skep for everything its own extent holds —
/// never only as much as the recording says exists: bytes skep took where
/// udanax refused them disagree, in a document the recording calls empty
/// too.
#[test]
fn a_whole_document_read_sees_what_skep_holds_beyond_the_recording() {
    let refused_insert =
        |doc: &str| json!({"op": "insert", "doc": doc, "text": "XY", "error": REFUSED});
    let ops = vec![
        create("d1", "1.1.0.1.0.1"),
        insert("d1", "AB"),
        refused_insert("d1"),
        retrieve("d1", &["AB"]),
        create("d2", "1.1.0.1.0.2"),
        refused_insert("d2"),
        retrieve("d2", &[]),
    ];
    let record = play("beyond_the_recording", ops);
    use Status::{Agreed, Disagreed, NotCompared};
    let expected = [Agreed, NotCompared, Disagreed, Disagreed, Agreed, Disagreed, Disagreed];
    assert_eq!(statuses(&record), expected);
}

/// A whole-document read narrows to the recording's reply by at most two
/// positions — the script's narrower specset — and no further: a larger
/// shortfall is a world that diverged, and disagrees.
#[test]
fn a_whole_document_read_narrows_by_at_most_two_positions() {
    let ops = vec![
        create("d", "1.1.0.1.0.1"),
        insert("d", "ABCDE"),
        retrieve("d", &["ABC"]),
        retrieve("d", &["AB"]),
    ];
    let record = play("narrowed", ops);
    let narrowed = &record.ops[2];
    assert_eq!(narrowed.status, Status::Agreed, "{narrowed:?}");
    assert!(narrowed.adaptations.iter().any(|a| a == "read-scoped-to-recorded-extent"));
    assert_eq!(record.ops[3].status, Status::Disagreed, "{:?}", record.ops[3]);
}
