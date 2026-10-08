use serde_json::json;

use super::*;

/// A delete is undone only with the bytes it is known to have removed,
/// reinserted at its pinned ordinal; one whose bytes the walk never
/// knew stops the undo instead of handing back the post-delete content
/// as the seed.
#[test]
fn a_delete_is_undone_only_with_the_bytes_it_removed() {
    let known = [Edit::Delete { at: 11, bytes: Some(b"Shared ".to_vec()), explicit: true }];
    let seed = undo_to_initial("B prefix: content", &known);
    assert_eq!(seed.as_deref(), Some(&b"B prefix: Shared content"[..]));
    let unknown = [Edit::Delete { at: 11, bytes: None, explicit: true }];
    assert_eq!(undo_to_initial("B prefix: content", &unknown), None);
}

/// An insert is undone only where its recorded bytes still stand — at
/// the end it appended to, or the ordinal it was placed at; a write the
/// walk could not reproduce stops the undo.
#[test]
fn an_undo_that_does_not_find_the_recorded_bytes_aborts() {
    let appended = [Edit::Insert { at: None, bytes: b"CD".to_vec() }];
    assert_eq!(undo_to_initial("ABCD", &appended).as_deref(), Some(&b"AB"[..]));
    assert_eq!(undo_to_initial("ABXY", &appended), None);
    let placed = [Edit::Insert { at: Some(2), bytes: b"X".to_vec() }];
    assert_eq!(undo_to_initial("AXB", &placed).as_deref(), Some(&b"AB"[..]));
    assert_eq!(undo_to_initial("ABX", &placed), None);
    let longer = [Edit::Insert { at: None, bytes: b"ABCDE".to_vec() }];
    assert_eq!(undo_to_initial("AB", &longer), None);
    assert_eq!(undo_to_initial("AB", &[Edit::Opaque]), None);
}

/// Undoing a pivot or a swap restores the text the shadow rearranged,
/// for every cut set over a six-byte text — the degenerate and
/// out-of-range cuts included, which rearrange nothing either way.
#[test]
fn undoing_a_rearrangement_restores_the_text_for_every_cut_set() {
    const TEXT: &[u8] = b"ABCDEF";
    let undone = |rearrange: &dyn Fn(&mut Shadow), edit: Edit| {
        let mut s = scratch(TEXT);
        rearrange(&mut s);
        undo_to_initial(&s.text_string("x"), &[edit])
    };
    // Every cut in 0..=8: below, inside and past the text's 1..=7.
    for n in 0..9u64.pow(3) {
        let (a, b, c) = (n / 81, n / 9 % 9, n % 9);
        let pivoted = undone(&|s| s.pivot("x", a, b, c), Edit::Pivot { a, b, c });
        assert_eq!(pivoted.as_deref(), Some(TEXT), "pivot {a},{b},{c}");
        for d in 0..=8 {
            let swap = Edit::Swap { s1: a, e1: b, s2: c, e2: d };
            let swapped = undone(&|s| s.swap("x", a, b, c, d), swap);
            assert_eq!(swapped.as_deref(), Some(TEXT), "swap {a},{b},{c},{d}");
        }
    }
}

/// A version is never seeded: its content at creation is its source's,
/// which the recorded create_version provides — however its probe
/// disagrees, no document is minted under its address.
#[test]
fn a_version_is_never_seeded_as_a_document() {
    let ops = [
        json!({"op": "create_document", "doc": "source", "result": "1.1.0.1.0.1"}),
        json!({"op": "insert", "doc": "source", "text": "AB"}),
        json!({"op": "create_version", "from": "source", "result": "1.1.0.1.0.1.1"}),
        json!({"op": "retrieve_contents", "doc": "1.1.0.1.0.1.1", "result": ["XY"]}),
    ];
    let setup = ground(&ops);
    assert!(setup.lead_in.is_empty(), "{:?}", setup.lead_in);
    assert!(setup.groundings.is_empty(), "{:?}", setup.groundings);
}

/// An insert recorded at the last ordinal is held by no text: undoing it
/// abandons the path, never overflowing past the content's end.
#[test]
fn an_insert_recorded_at_the_last_ordinal_undoes_to_nothing() {
    let placed = [Edit::Insert { at: Some(u64::MAX), bytes: b"XY".to_vec() }];
    assert_eq!(undo_to_initial("AB", &placed), None);
}

/// A width at the top of the range, as the corpus's boundary family
/// would record it next.
const TOP_WIDTH: &str = "0.18446744073709551615";

/// A recorded comparison pair at the extremes — a destination ordinal 0,
/// or a width at the top of the range — pins no seed and no cover: the
/// probe holds no such region.
#[test]
fn a_compare_pair_at_the_extremes_seeds_nothing() {
    let pair = |dest_start: &str, width: &str| {
        json!({"a": {"start": dest_start, "width": width}, "b": {"start": "1.1", "width": width}})
    };
    for shared in [pair("1.0", "0.5"), pair("1.2", TOP_WIDTH)] {
        let ops = [
            json!({"op": "create_document", "doc": "target", "result": "1.1.0.1.0.1"}),
            json!({"op": "insert", "doc": "target", "text": "Hello"}),
            json!({"op": "create_document", "doc": "src", "result": "1.1.0.1.0.2"}),
            json!({"op": "retrieve_contents", "doc": "target", "result": ["Hello"]}),
            json!({"op": "compare_versions", "label": "target_vs_src", "shared": [shared]}),
        ];
        let setup = ground(&ops);
        let seeded = setup.groundings.iter().any(|t| t.contains("comparison-seed"));
        assert!(!seeded, "{:?}", setup.groundings);
        let mut shadow = Shadow::new();
        shadow.create_doc("1.1.0.1.0.1", Some("target"));
        shadow.insert("1.1.0.1.0.1", 1, b"Hello");
        shadow.create_doc("1.1.0.1.0.2", Some("src"));
        assert!(cover::cover_from_comparisons(&shadow, "1.1.0.1.0.1", "Hello", &ops).is_none());
    }
}

/// A recorded endset span out of reach — an end past the build budget,
/// or an ordinal 0 — builds no seed, however well a link's text fits it.
#[test]
fn a_recorded_span_out_of_reach_seeds_nothing() {
    const DOC: &str = "1.1.0.1.0.1";
    let seeded = |start: &str, width: &str| {
        let span = json!({"start": start, "width": width});
        let ops = [
            json!({"op": "create_link", "source_text": "Hello"}),
            json!({"op": "retrieve_endsets", "source": [{"docid": DOC, "span": span}]}),
        ];
        endset_anchored_seed(&ops, &Shadow::new(), DOC)
    };
    assert_eq!(seeded("1.3", "0.5").as_deref(), Some(&b"  Hello"[..]), "within reach");
    assert_eq!(seeded("1.1", "0.1099511627776"), None);
    assert_eq!(seeded("1.0", "0.5"), None);
}

/// A recorded pair landing a copy past the build budget's reach from the
/// append position orders filler no comparison could read: no plan
/// builds it, and the copy runs as recorded.
#[test]
fn a_filler_past_the_budget_is_not_built() {
    let five = |start: &str| json!({"start": start, "width": "0.5"});
    let source = json!({"docid": "1.1.0.1.0.1", "span": five("1.1")});
    let ops = [
        json!({"op": "create_document", "doc": "src", "result": "1.1.0.1.0.1"}),
        json!({"op": "insert", "doc": "src", "text": "Hello world"}),
        json!({"op": "create_document", "doc": "dest", "result": "1.1.0.1.0.2"}),
        json!({"op": "vcopy", "source": source, "to": "dest"}),
        json!({
            "op": "compare_versions",
            "label": "dest_vs_src",
            "shared": [{"a": five("1.1099511627776"), "b": five("1.1")}],
        }),
    ];
    let setup = ground(&ops);
    assert!(setup.plans.is_empty(), "{:?}", setup.plans);
}

/// A log's length costs the undo heap, never stack: a hundred thousand
/// appended inserts undo to the empty seed.
#[test]
fn a_long_edit_log_undoes_without_recursion() {
    const N: usize = 100_000;
    let log = vec![Edit::Insert { at: None, bytes: b"A".to_vec() }; N];
    assert_eq!(undo_to_initial(&"A".repeat(N), &log).as_deref(), Some(&b""[..]));
}

/// A log holding a write the walk never knew is refused before any
/// search: forty deletes above it would otherwise try 2^40 placements,
/// each failing at that write.
#[test]
fn a_log_with_an_unknowable_edit_is_refused_before_any_search() {
    let delete = Edit::Delete { at: 1, bytes: Some(b"a".to_vec()), explicit: false };
    let mut log = vec![Edit::Opaque];
    log.extend(vec![delete; 40]);
    assert_eq!(undo_to_initial("x", &log), None);
}

/// A target an implied create made and `vcopy_to_multiple` then builds is
/// minted once — listed once in creation order — and built by plan steps
/// whose edits its log records, so undoing its probed content walks back
/// to the empty document it was made as.
#[test]
fn a_vcopy_target_an_implied_create_made_is_minted_once() {
    const TARGET: &str = "1.1.0.1.0.2";
    let ops = [
        json!({"op": "create_document", "doc": "source", "result": "1.1.0.1.0.1"}),
        json!({"op": "insert", "doc": "source", "text": "Hello"}),
        json!({
            "op": "vcopy_to_multiple",
            "source_span": {"start": "1.1", "width": "0.5"},
            "targets": [{"docid": TARGET, "contents": ["Hello"]}],
        }),
    ];
    let setup = ground(&ops);
    assert_eq!(setup.implied_creates, [TARGET]);
    let sim = Sim::replay(&setup.implied_creates, &BTreeMap::new(), &ops);
    assert_eq!(sim.shadow.created().iter().filter(|d| *d == TARGET).count(), 1);
    assert_eq!(sim.shadow.text_string(TARGET), "Hello");
    assert_eq!(undo_to_initial("Hello", sim.log_for(TARGET)).as_deref(), Some(&b""[..]));
}

/// A document the walk never made stays unmade: an edit of it changes
/// nothing and leaves no log, and a probe of it tests nothing — so no seed
/// is inferred for it, and the lead-in mints no document the scenario never
/// created (here, one under a version's address).
#[test]
fn a_document_the_walk_never_made_is_never_seeded() {
    const UNMADE: &str = "1.1.0.1.0.1.7";
    let ops = [
        json!({"op": "create_document", "doc": "source", "result": "1.1.0.1.0.1"}),
        json!({"op": "insert", "doc": UNMADE, "text": "AB"}),
        json!({"op": "retrieve_contents", "doc": UNMADE, "result": ["XYAB"]}),
    ];
    let setup = ground(&ops);
    assert!(setup.implied_creates.is_empty(), "{:?}", setup.implied_creates);
    assert!(setup.lead_in.is_empty(), "{:?}", setup.lead_in);
    let sim = Sim::replay(&setup.implied_creates, &BTreeMap::new(), &ops);
    assert!(!sim.shadow.knows(UNMADE));
    assert!(sim.log_for(UNMADE).is_empty());
}

/// The walk lands a vcopy where the play pass does: a position marker
/// copies into the first source's document, not the register's, and a
/// destination that resolves to nothing copies nothing, never re-aimed.
#[test]
fn the_walk_lands_a_vcopy_where_the_play_pass_does() {
    const SOURCE: &str = "1.1.0.1.0.1";
    const OTHER: &str = "1.1.0.1.0.2";
    let ops = [
        json!({"op": "create_document", "doc": "source", "result": SOURCE}),
        json!({"op": "insert", "doc": "source", "text": "Hello"}),
        json!({"op": "create_document", "doc": "other", "result": OTHER}),
        json!({"op": "vcopy", "from": "source", "to": "end"}),
        json!({"op": "vcopy", "from": "source", "to": "ghost"}),
    ];
    let sim = Sim::replay(&[], &BTreeMap::new(), &ops);
    assert_eq!(sim.shadow.text_string(SOURCE), "HelloHello");
    assert_eq!(sim.shadow.text_string(OTHER), "");
}

/// The walk swaps the two texts a swap's `regions` name, as the play pass
/// does, never leaving the write unknown.
#[test]
fn the_walk_swaps_the_regions_a_swap_names() {
    const DOC: &str = "1.1.0.1.0.1";
    let ops = [
        json!({"op": "create_document", "doc": "d", "result": DOC}),
        json!({"op": "insert", "doc": "d", "text": "AAA middle BBB"}),
        json!({"op": "swap", "doc": "d", "regions": ["AAA", "BBB"]}),
    ];
    let sim = Sim::replay(&[], &BTreeMap::new(), &ops);
    assert_eq!(sim.shadow.text_string(DOC), "BBB middle AAA");
    let log = sim.log_for(DOC);
    assert!(matches!(log, [.., Edit::Swap { s1: 1, e1: 4, s2: 12, e2: 15 }]), "{log:?}");
}

/// A read moves the register only as its handler does: a find_links or a
/// close_document naming a document leaves it on the document last created,
/// and a content read naming one moves it there — so each doc-less insert
/// after them lands where the play pass lands it.
#[test]
fn a_read_moves_the_register_only_as_its_handler_does() {
    const SOURCE: &str = "1.1.0.1.0.1";
    const OTHER: &str = "1.1.0.1.0.2";
    let ops = [
        json!({"op": "create_document", "doc": "source", "result": SOURCE}),
        json!({"op": "insert", "doc": "source", "text": "AB"}),
        json!({"op": "create_document", "doc": "other", "result": OTHER}),
        json!({"op": "find_links", "doc": "source", "result": []}),
        json!({"op": "close_document", "doc": SOURCE}),
        json!({"op": "insert", "text": "XY"}),
        json!({"op": "retrieve_contents", "doc": "source", "result": ["AB"]}),
        json!({"op": "insert", "text": "CD"}),
    ];
    let sim = Sim::replay(&[], &BTreeMap::new(), &ops);
    assert_eq!(sim.shadow.text_string(OTHER), "XY");
    assert_eq!(sim.shadow.text_string(SOURCE), "ABCD");
}

/// A link homed in a document no op made mints nothing: the walk enters it
/// at no home, as the play pass, finding no α-image there, makes no link.
#[test]
fn a_link_homed_where_no_op_made_a_document_mints_nothing() {
    let ops = [
        json!({"op": "create_document", "result": "1.1.0.1.0.5"}),
        json!({"op": "create_link", "result": "1.1.0.1.0.1.0.2.1"}),
    ];
    let setup = ground(&ops);
    assert!(setup.implied_creates.is_empty(), "{:?}", setup.implied_creates);
    let sim = Sim::replay(&setup.implied_creates, &BTreeMap::new(), &ops);
    assert!(!sim.shadow.knows("1.1.0.1.0.1"));
    assert_eq!(sim.shadow.created(), ["1.1.0.1.0.5"]);
}

/// An op the play pass refuses before it aims moves no register in the walk
/// either — an `insert_loop` with no count, a bare `rearrange` whose cuts
/// name no shape — and the write udanax made in the document it names is
/// one no undo crosses.
#[test]
fn an_op_refused_before_it_aims_moves_no_register() {
    const A: &str = "1.1.0.1.0.1";
    const B: &str = "1.1.0.1.0.2";
    let ops = [
        json!({"op": "create_document", "doc": "a", "result": A}),
        json!({"op": "create_document", "doc": "b", "result": B}),
        json!({"op": "insert_loop", "doc": "a"}),
        json!({"op": "insert", "text": "XY"}),
        json!({"op": "rearrange", "doc": "a", "cuts": [1, 2]}),
        json!({"op": "insert", "text": "Z"}),
    ];
    let sim = Sim::replay(&[], &BTreeMap::new(), &ops);
    assert_eq!(sim.shadow.text_string(B), "XYZ");
    assert_eq!(sim.shadow.text_string(A), "");
    assert!(matches!(sim.log_for(A), [Edit::Opaque, Edit::Opaque]), "{:?}", sim.log_for(A));
}

/// A macro copy the scenario gives no probe to ground builds no plan and
/// copies nothing, never read as one ordinary copy of its text: the play
/// pass, finding no plan, refuses it.
#[test]
fn a_macro_copy_with_no_probe_copies_nothing() {
    const SOURCE: &str = "1.1.0.1.0.1";
    const DEST: &str = "1.1.0.1.0.2";
    let ops = [
        json!({"op": "create_document", "doc": "source", "result": SOURCE}),
        json!({"op": "insert", "doc": "source", "text": "Shared text"}),
        json!({"op": "create_document", "doc": "dest", "result": DEST}),
        json!({"op": "vcopy_all", "from": "source", "to": "dest", "text": "Shared"}),
    ];
    let setup = ground(&ops);
    assert!(setup.plans.is_empty(), "{:?}", setup.plans);
    let sim = Sim::replay(&[], &BTreeMap::new(), &ops);
    assert_eq!(sim.shadow.text_string(DEST), "");
}

/// A macro copy's destination is read in place, as the play pass, which
/// only runs the plan built from it, never aims the op: a macro naming a
/// document moves no register in the walk, and one with no document yet
/// mints none it builds no plan for.
#[test]
fn a_macro_copy_reads_its_destination_in_place() {
    const SOURCE: &str = "1.1.0.1.0.1";
    const OTHER: &str = "1.1.0.1.0.2";
    let ops = [
        json!({"op": "create_document", "doc": "source", "result": SOURCE}),
        json!({"op": "insert", "doc": "source", "text": "Shared text"}),
        json!({"op": "create_document", "doc": "other", "result": OTHER}),
        json!({"op": "vcopy_all", "doc": "source", "to": "ghost", "text": "Shared"}),
        json!({"op": "insert", "text": "XY"}),
    ];
    let sim = Sim::replay(&[], &BTreeMap::new(), &ops);
    assert_eq!(sim.shadow.text_string(OTHER), "XY");
    let minted = [json!({"op": "vcopy_all", "from": ["a"], "text": "Shared"})];
    let sim = Sim::replay(&[], &BTreeMap::new(), &minted);
    assert!(sim.shadow.created().is_empty(), "{:?}", sim.shadow.created());
}
