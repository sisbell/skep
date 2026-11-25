use std::collections::BTreeSet;

use serde_json::json;

use super::*;

/// The most characters a tool's card holds.
///
/// A client cuts a longer description, so a card says what an agent needs
/// first and names the help topic that holds the rest.
const MAX_CARD_CHARS: usize = 1000;

/// The most characters the `help` tool's own card holds.
const MAX_HELP_CARD_CHARS: usize = 400;

/// The most characters the instructions hold, the commons sentence appended.
///
/// A client cuts longer server instructions.
const MAX_INSTRUCTIONS_CHARS: usize = 2000;

/// The tools whose card ends naming its full reference in the help store.
const REFERENCED: [&str; 23] = [
    "create_well_known_document",
    "doc_metadata",
    "set_arrangement",
    "make_link",
    "line_numbers",
    "held",
    "resolve",
    "publication_open",
    "publication_count",
    "publication_confirm",
    "publication_standing",
    "merge_compose",
    "merge_land",
    "merge_undo",
    "merge_withdraw",
    "changes_since",
    "fetch",
    "replace_text",
    "edit_text",
    "move_lines",
    "mark_text",
    "diff_text",
    "restore_text",
];

/// Returns a tool's card: its description, as `tools/list` answers it.
fn card<'c>(catalog: &'c Catalog, name: &str) -> &'c str {
    catalog.tools.iter().find(|t| t["name"] == name).and_then(|t| t["description"].as_str()).unwrap_or_else(|| panic!("the {name} card"))
}

/// Returns a tool's full reference: its help topic where the store holds
/// one, else its card, which then says everything.
fn reference<'c>(catalog: &'c Catalog, name: &str) -> &'c str {
    catalog.help(name).unwrap_or_else(|| card(catalog, name))
}

/// Returns a help topic's text: a rule, by its heading.
fn topic<'c>(catalog: &'c Catalog, heading: &str) -> &'c str {
    catalog.help(heading).unwrap_or_else(|| panic!("the help topic {heading}"))
}

/// The shipped catalog: every wire op and every adapter tool, every entry
/// named, described, and schema'd — `Catalog::load` enforces both no-drift
/// directions, so a clean load IS the no-drift assertion for the embedded
/// file — every entry kept as the file spells it, and the help store's
/// every entry kept in its file order.
#[test]
fn embedded_catalog_matches_dispatch() {
    let catalog = Catalog::load(EMBEDDED).expect("embedded tools.json must validate");
    assert_eq!(catalog.tools.len(), Tool::names().count());
    assert!(!catalog.instructions.is_empty());
    let file: Value = serde_json::from_str(EMBEDDED).expect("embedded parses");
    assert_eq!(Some(&catalog.tools), file["tools"].as_array(), "entries kept verbatim");
    let stored: Vec<(&str, &str)> = file["help"].as_array().expect("the help store").iter().filter_map(|entry| Some((entry["topic"].as_str()?, entry["text"].as_str()?))).collect();
    assert_eq!(catalog.help.iter().map(|(topic, text)| (topic.as_str(), text.as_str())).collect::<Vec<_>>(), stored, "the help store kept verbatim, in file order");
}

/// Direction one: a file entry the dispatch doesn't know refuses to load.
///
/// The refusal names the tool — a ceremony's name among them, which no kind
/// answers, and `publish`, which the shell runs as its `publication` family,
/// whose rows' dotted names are no tool's either.
#[test]
fn unknown_tool_refuses() {
    for stranger in ["frobnicate", "keygen", "claim", "retire", "upload", "restore", "op", "session", "close", "publish", "publication.open"] {
        let mut v: Value = serde_json::from_str(EMBEDDED).expect("embedded parses");
        v["tools"].as_array_mut().expect("tools").push(json!({
            "name": stranger,
            "description": "no tool of the dispatch",
            "inputSchema": {"type": "object"}
        }));
        let err = Catalog::load(&v.to_string()).expect_err("must refuse");
        assert!(err.contains(stranger), "error must name the tool: {err}");
    }
}

/// Direction two: a dispatch tool the file doesn't name refuses to load,
/// naming it — a wire op, a shell call and an apparatus tool alike.
#[test]
fn missing_tool_refuses() {
    for missing in ["insert", "publication_confirm", "search", "changes_since", "fetch", "session_info"] {
        let mut v: Value = serde_json::from_str(EMBEDDED).expect("embedded parses");
        v["tools"].as_array_mut().expect("tools").retain(|t| t["name"] != missing);
        let err = Catalog::load(&v.to_string()).expect_err("must refuse");
        assert!(err.contains(missing), "error must name the tool: {err}");
    }
}

/// Every fault `load` refuses that would otherwise load — a catalog served
/// verbatim to harnesses that may reject a malformed tool list wholesale,
/// and a help store the `help` tool answers from — refuses, naming what is
/// wrong: a help store keyed as an object among them, which would hold no
/// order and keep one of a topic written twice, and a topic that is neither
/// a heading nor a tool, `fetch` respelt as a stranger and `FETCH` as a
/// word of another case.
#[test]
fn every_fault_that_would_load_refuses_by_name() {
    fn refusal(edit: impl FnOnce(&mut Value)) -> String {
        let mut v: Value = serde_json::from_str(EMBEDDED).expect("embedded parses");
        edit(&mut v);
        Catalog::load(&v.to_string()).expect_err("the doctored catalog must refuse")
    }
    fn tool<'a>(v: &'a mut Value, name: &str) -> &'a mut Value {
        let tools = v["tools"].as_array_mut().expect("tools");
        tools.iter_mut().find(|t| t["name"] == name).expect("the named tool")
    }
    fn without(v: &mut Value, name: &str) {
        v["tools"].as_array_mut().expect("tools").retain(|t| t["name"] != name);
    }
    fn entry<'a>(v: &'a mut Value, topic: &str) -> &'a mut Value {
        let help = v["help"].as_array_mut().expect("the help store");
        help.iter_mut().find(|entry| entry["topic"] == topic).expect("the named topic")
    }
    for (err, names) in [
        (refusal(|v| v["version"] = json!(1)), "'version'"),
        (refusal(|v| v["instructions"] = json!("")), "'instructions'"),
        (refusal(|v| v["instructions"] = json!(7)), "missing string field 'instructions'"),
        (refusal(|v| v["commons_instructions"] = json!(["{addr}"])), "missing string field 'commons_instructions'"),
        (refusal(|v| tool(v, "insert")["title"] = json!("Insert")), "'title'"),
        (refusal(|v| tool(v, "insert")["description"] = json!("")), "'description'"),
        (refusal(|v| tool(v, "insert")["inputSchema"] = json!("object")), "'inputSchema'"),
        (refusal(|v| tool(v, "insert")["inputSchema"] = json!({"properties": {}})), "'inputSchema'"),
        (refusal(|v| tool(v, "insert")["inputSchema"]["properties"]["from_"] = json!({"type": "string"})), "'from_'"),
        (
            refusal(|v| {
                let twin = tool(v, "insert").clone();
                v["tools"].as_array_mut().expect("tools").push(twin)
            }),
            "duplicate tool 'insert'",
        ),
        (refusal(|v| without(v, "session_info")), "'session_info'"),
        (refusal(|v| without(v, "help")), "'help'"),
        (
            refusal(|v| {
                v.as_object_mut().expect("root").remove("help");
            }),
            "missing array field 'help'",
        ),
        (refusal(|v| v["help"] = json!({"FETCH": "FETCH. A store keyed by topic."})), "missing array field 'help'"),
        (refusal(|v| v["help"][0] = json!("OVERVIEW")), "help[0]: must be an object"),
        (refusal(|v| entry(v, "FETCH")["title"] = json!("Fetch")), "'title'"),
        (
            refusal(|v| {
                entry(v, "FETCH").as_object_mut().expect("an entry").remove("text");
            }),
            "missing string field 'text'",
        ),
        (refusal(|v| entry(v, "FETCH")["topic"] = json!("")), "'topic' must be nonempty"),
        (refusal(|v| entry(v, "FETCH")["text"] = json!("")), "'text' must be nonempty"),
        (
            refusal(|v| {
                let twin = entry(v, "FETCH").clone();
                v["help"].as_array_mut().expect("the help store").push(twin)
            }),
            "duplicate help topic 'FETCH'",
        ),
        (refusal(|v| entry(v, "FETCH")["topic"] = json!("Fetch")), "help topic 'Fetch'"),
        (refusal(|v| entry(v, "fetch")["topic"] = json!("frobnicate")), "help topic 'frobnicate'"),
    ] {
        assert!(err.contains(names), "the refusal names {names}: {err}");
    }
}

/// One fault at a time, the first found speaking.
///
/// A catalog with an unknown root field, a help store that is no array, a
/// malformed entry, a missing op and a `from_` on an op the dispatch does
/// not rename is refused for the root field; without it, for the help store;
/// with a store that is an array again — its second entry malformed, its
/// first topic written twice — for the entry; without that, for the op;
/// with the op back, for the `from_`; without that, for the help entry; and
/// with the entry mended, for the topic written twice.
#[test]
fn the_first_fault_found_speaks() {
    let mut v: Value = serde_json::from_str(EMBEDDED).expect("embedded parses");
    let insert = v["tools"].as_array().expect("tools").iter().find(|t| t["name"] == "insert").cloned().expect("the insert entry");
    let mut store = v["help"].clone();
    let first = store[0].clone();
    store.as_array_mut().expect("the help store").push(first);
    let text = store[1].as_object_mut().expect("an entry").remove("text").expect("the second entry's text");
    v["version"] = json!(1);
    v["help"] = json!({});
    v["tools"][0]["title"] = json!("Title");
    v["tools"].as_array_mut().expect("tools").retain(|t| t["name"] != "insert");
    let delete = v["tools"].as_array_mut().expect("tools").iter_mut().find(|t| t["name"] == "delete").expect("the delete entry");
    delete["inputSchema"]["properties"]["from_"] = json!({"type": "string"});
    let err = Catalog::load(&v.to_string()).expect_err("five faults");
    assert!(err.contains("'version'"), "the root speaks first: {err}");
    v.as_object_mut().expect("root").remove("version");
    let err = Catalog::load(&v.to_string()).expect_err("four faults");
    assert!(err.contains("missing array field 'help'"), "then the help store: {err}");
    v["help"] = store;
    let err = Catalog::load(&v.to_string()).expect_err("five faults");
    assert!(err.starts_with("tools[0]: ") && err.contains("'title'"), "then the entry: {err}");
    v["tools"][0].as_object_mut().expect("entry").remove("title");
    let err = Catalog::load(&v.to_string()).expect_err("four faults");
    assert!(err.contains("'insert'"), "then the op: {err}");
    v["tools"].as_array_mut().expect("tools").push(insert);
    let err = Catalog::load(&v.to_string()).expect_err("three faults");
    assert!(err.contains("'delete'") && err.contains("'from_'"), "then the from_: {err}");
    let delete = v["tools"].as_array_mut().expect("tools").iter_mut().find(|t| t["name"] == "delete").expect("the delete entry");
    delete["inputSchema"]["properties"].as_object_mut().expect("properties").remove("from_");
    let err = Catalog::load(&v.to_string()).expect_err("two faults");
    assert!(err.starts_with("help[1]: ") && err.contains("'text'"), "then the help entry: {err}");
    v["help"][1]["text"] = text;
    let err = Catalog::load(&v.to_string()).expect_err("one fault");
    assert!(err.contains("duplicate help topic 'OVERVIEW'"), "then the topic: {err}");
}

/// The commons sentence template is catalog data like everything else:
/// absent, or present without its substitution point, refuses to load.
#[test]
fn a_commons_template_absent_or_without_its_placeholder_refuses() {
    let mut v: Value = serde_json::from_str(EMBEDDED).expect("embedded parses");
    v.as_object_mut().expect("root").remove("commons_instructions");
    let err = Catalog::load(&v.to_string()).expect_err("must refuse");
    assert!(err.contains("commons_instructions"), "error names the field: {err}");

    let mut v: Value = serde_json::from_str(EMBEDDED).expect("embedded parses");
    v["commons_instructions"] = json!("a sentence with no substitution point");
    let err = Catalog::load(&v.to_string()).expect_err("must refuse");
    assert!(err.contains("{addr}"), "error names the placeholder: {err}");
}

/// The template is filled in where its placeholder is checked: every
/// `{addr}` takes the address, and the sentence follows a blank line.
#[test]
fn append_commons_fills_every_placeholder() {
    let mut catalog = Catalog { instructions: "Base.".to_string(), commons_instructions: "Commons at {addr}; defines is {addr}.0.3.50.".to_string(), tools: Vec::new(), help: Vec::new() };
    catalog.append_commons("1.0.2.0.71");
    assert_eq!(catalog.instructions, "Base.\n\nCommons at 1.0.2.0.71; defines is 1.0.2.0.71.0.3.50.");
}

/// A wire op's frame makes the name the op and the arguments the frame.
///
/// The name rides as `op` (over any `op` the arguments carry), a top-level
/// `from_` comes back as `from` on the renaming ops and nowhere else —
/// unless a `from` is already there, when both ride — and a nested `from_`
/// is wire shape.
#[test]
fn wire_frame_makes_the_name_the_op_and_the_arguments_the_frame() {
    let frame = |op: &str, args: Value| -> Value {
        let Value::Object(args) = args else { panic!("arguments are an object") };
        wire_frame(op, args)
    };
    for op in ["make_link", "emit", "stage"] {
        assert_eq!(frame(op, json!({"from_": "1.1", "to": [{"from_": "x"}]})), json!({"op": op, "from": "1.1", "to": [{"from_": "x"}]}), "{op} renames its top-level from_");
        assert_eq!(frame(op, json!({"from": "1.1", "from_": "2.2"})), json!({"op": op, "from": "1.1", "from_": "2.2"}), "{op}: both spellings ride — the collision is the daemon's to refuse");
    }
    assert_eq!(frame("insert", json!({"from_": "1.1", "op": "delete"})), json!({"op": "insert", "from_": "1.1"}));
}

/// The dispatch has two kinds of tool, and is counted.
///
/// Fifty-two wire ops — every op of wire.md §Operations but `publish`, the
/// six the first catalog lacked among them, the count by home, the
/// retracted-links read, the landing, the well-known creation and the line
/// read — and twenty-six adapter tools, the `publication` family's four
/// among them, the read of a draft's standing beside them, the `merge`
/// family's four after it and before `session_info`, the two text edits,
/// `replace_text` and `edit_text`, the move of whole lines, `move_lines`,
/// the mark of a draft, `mark_text`, the diff since one, `diff_text`, the
/// restore of a draft's past state, `restore_text`, and `help`, which takes
/// a `topic`; no name twice across the two, each wire op a `Tool::Op` of
/// its own name with no members list, each adapter tool its row's members
/// — `merge_undo`'s those of its row's two forms; and a ceremony, `upload`,
/// `restore`, `op`, `publish` or a row's dotted name no tool at all.
#[test]
fn the_dispatch_has_two_kinds_and_is_counted() {
    let names: Vec<&str> = Tool::names().collect();
    let set: std::collections::BTreeSet<_> = names.iter().collect();
    assert_eq!(set.len(), names.len(), "no name twice");
    assert_eq!(DISPATCH_OPS.len(), 52);
    assert_eq!(names.len(), 78);
    assert_eq!(ADAPTER_TOOLS.len(), 26);
    for (name, tool, members) in [
        ("merge_compose", Tool::MergeCompose, &["doc", "alternative", "draft", "fork", "into"][..]),
        ("merge_land", Tool::MergeLand, &["resolutions", "answers"][..]),
        ("merge_undo", Tool::MergeUndo, &["draft", "withdrawal"][..]),
        ("merge_withdraw", Tool::MergeWithdraw, &["draft"][..]),
    ] {
        assert_eq!(Tool::named(name), Some(tool), "{name} is an adapter tool");
        assert_eq!(Tool::named(name).and_then(Tool::members), Some(members), "{name} takes its row's members");
    }
    let merges: Vec<&str> = names.iter().copied().skip_while(|name| *name != "publication_standing").take(6).collect();
    assert_eq!(
        merges,
        ["publication_standing", "merge_compose", "merge_land", "merge_undo", "merge_withdraw", "session_info"],
        "the merge family's four stand after `publication_standing` and before `session_info`"
    );
    assert_eq!(Tool::named("help"), Some(Tool::Help));
    assert_eq!(Tool::named("help").and_then(Tool::members), Some(&["topic"][..]));
    assert_eq!(Tool::named("replace_text"), Some(Tool::ReplaceText));
    assert_eq!(Tool::named("replace_text").and_then(Tool::members), Some(&["doc", "old", "new"][..]));
    assert_eq!(Tool::named("edit_text"), Some(Tool::EditText));
    assert_eq!(Tool::named("edit_text").and_then(Tool::members), Some(&["doc", "edits"][..]));
    assert_eq!(Tool::named("move_lines"), Some(Tool::MoveLines));
    assert_eq!(Tool::named("move_lines").and_then(Tool::members), Some(&["doc", "first", "last", "before"][..]));
    assert_eq!(Tool::named("mark_text"), Some(Tool::MarkText));
    assert_eq!(Tool::named("mark_text").and_then(Tool::members), Some(&["doc"][..]));
    assert_eq!(Tool::named("diff_text"), Some(Tool::DiffText));
    assert_eq!(Tool::named("diff_text").and_then(Tool::members), Some(&["doc", "since", "stat", "hunk"][..]));
    assert_eq!(Tool::named("restore_text"), Some(Tool::RestoreText));
    assert_eq!(Tool::named("restore_text").and_then(Tool::members), Some(&["draft", "at", "as_of"][..]));
    let order: Vec<&str> = names.iter().copied().skip_while(|name| *name != "move_lines").collect();
    assert_eq!(order, ["move_lines", "mark_text", "diff_text", "restore_text", "help"], "the three stand after `move_lines` and before `help`");
    for added in [
        "effective_owner",
        "key_set",
        "retrieve_i",
        "content_frontier",
        "edition_claims",
        "universal_grants",
        "count_v_by_home",
        "find_links_v_history",
        "set_arrangement",
        "create_well_known_document",
        "line_numbers",
    ] {
        assert_eq!(Tool::named(added), Some(Tool::Op(added)), "{added} is a wire op of the dispatch");
    }
    assert_eq!(Tool::named("insert").and_then(Tool::members), None, "a wire op's arguments pass through unread");
    assert_eq!(Tool::named("search").and_then(Tool::members), Some(&["query", "opts"][..]));
    assert_eq!(Tool::named("session_info").and_then(Tool::members), Some(&[][..]));
    assert_eq!(Tool::named("fetch"), Some(Tool::Fetch));
    assert_eq!(Tool::named("publication_open").and_then(Tool::members), Some(&["draft", "also", "doc", "mint", "claim", "selection", "notes", "readable_drafts", "published"][..]));
    assert_eq!(Tool::named("publication_cancel").and_then(Tool::members), Some(&[][..]));
    assert_eq!(Tool::named("publication_standing").and_then(Tool::members), Some(&["draft", "doc", "also"][..]));
    for not_a_tool in ["keygen", "fingerprint", "claim", "enroll", "bind", "recover", "rotate", "retire", "handoff", "accept", "upload", "restore", "op", "session", "close", "frobnicate"] {
        assert_eq!(Tool::named(not_a_tool), None, "{not_a_tool} is no tool");
    }
    for not_a_tool in ["publish", "publication.open", "merge.compose"] {
        assert_eq!(Tool::named(not_a_tool), None, "{not_a_tool} is no tool: the shell runs a publication and a merge as its call families, each tool named with `_` for `.`");
    }
}

/// The dispatch's door admits a call or refuses it, naming the culprit.
///
/// A name it answers is admitted, a wire op's arguments unread save the one
/// shape skep-shell's `op` row reads as its `/op-at` form, a numeric `at`
/// beside an object `frame`, which alone is refused; a name it does not
/// answer is refused before its arguments are read; a member an adapter
/// tool's row does not take is refused naming the row's own — a
/// `publication_open`'s `base` and a `merge_compose`'s, each a base the
/// shell reads itself, and a `merge_withdraw`'s `doc`, whose draft is
/// `draft`, among them, `merge_compose` admitting each of its three sides,
/// `fork` among them — and a
/// member of its `opts` naming the options — `search`'s withheld `reindex`
/// among them — the row's stranger speaking first; `merge_undo` takes
/// either of its row's forms, no member or `draft` beside `withdrawal`.
#[test]
fn the_dispatchs_door_admits_a_call_or_refuses_it_naming_the_culprit() {
    let args = |v: Value| -> Map<String, Value> {
        let Value::Object(m) = v else { panic!("arguments are an object") };
        m
    };
    assert_eq!(Tool::admit("insert", &args(json!({"stranger": 1}))), Ok(Tool::Op("insert")), "a wire op's arguments pass through unread");
    assert_eq!(Tool::admit("search", &args(json!({"query": "x", "opts": {}}))), Ok(Tool::Search));
    let err = Tool::admit("frobnicate", &args(json!({"stranger": 1}))).expect_err("no tool");
    assert!(err.contains("unknown tool 'frobnicate'"), "the name speaks first: {err}");
    let err = Tool::admit("session_info", &args(json!({"principal": 2}))).expect_err("a stranger");
    assert!(err.contains("session_info takes no arguments") && err.contains("'principal'"), "{err}");
    assert_eq!(Tool::admit("changes_since", &args(json!({"since": 0, "under": "1.0.1"}))), Ok(Tool::ChangesSince), "the narrowing the row takes");
    let err = Tool::admit("changes_since", &args(json!({"since": 0, "undr": "1"}))).expect_err("a stranger");
    assert!(err.contains("'since', 'limit', 'class', 'under'") && err.contains("'undr'"), "{err}");
    let err = Tool::admit("publication_open", &args(json!({"draft": "1.0.1.0.64", "doc": "1.0.1.0.65", "base": "1.0.1.0.65.1"}))).expect_err("a base the shell reads itself");
    assert!(err.contains("publication_open takes") && err.contains("'base'"), "{err}");
    assert_eq!(Tool::admit("publication_open", &args(json!({"draft": "1.0.1.0.64", "doc": "1.0.1.0.65"}))), Ok(Tool::PublicationOpen));
    let err = Tool::admit("doc_metadata", &args(json!({"at": 5, "frame": {"op": "retrieve_v"}}))).expect_err("the /op-at shape");
    assert!(err.contains("'at'") && err.contains("'frame'"), "{err}");
    for plain in [json!({"at": {"subspace": "1", "ordinal": "1"}, "frame": {}}), json!({"at": "5", "frame": {}}), json!({"at": -1, "frame": {}}), json!({"at": 5, "frame": "f"}), json!({"at": 5})] {
        assert_eq!(Tool::admit("insert", &args(plain.clone())), Ok(Tool::Op("insert")), "{plain}: no /op-at shape, so the frame goes to the daemon's parse");
    }
    let err = Tool::admit("places", &args(json!({"opts": {"undr": "1.0.1"}}))).expect_err("an opts stranger");
    assert!(err.contains("'under'") && err.contains("'undr'"), "{err}");
    assert_eq!(Tool::admit("search", &args(json!({"query": "x", "opts": {"limit": 3, "offset": 0}}))), Ok(Tool::Search));
    for reindex in [json!(true), json!(false)] {
        let err = Tool::admit("search", &args(json!({"query": "x", "opts": {"reindex": reindex}}))).expect_err("the withheld refresh");
        assert!(err.contains("'limit', 'offset'") && err.contains("'reindex'"), "{err}");
    }
    let err = Tool::admit("search", &args(json!({"query": "x", "board": "b-1", "opts": {"undr": 1}}))).expect_err("two strangers");
    assert!(err.contains("'board'") && !err.contains("'undr'"), "the row's stranger speaks first: {err}");
    assert_eq!(Tool::admit("move_lines", &args(json!({"doc": "1.0.1.0.64", "first": 2, "last": 3, "before": 1}))), Ok(Tool::MoveLines));
    let err = Tool::admit("move_lines", &args(json!({"doc": "1.0.1.0.64", "from": 2, "before": 1}))).expect_err("a member the row does not take");
    assert!(err.contains("move_lines takes 'doc', 'first', 'last', 'before'") && err.contains("'from'"), "the block's first line is `first`: {err}");
    assert_eq!(Tool::admit("mark_text", &args(json!({"doc": "1.0.1.0.64"}))), Ok(Tool::MarkText));
    let err = Tool::admit("mark_text", &args(json!({"doc": "1.0.1.0.64", "account": "1.0.2"}))).expect_err("the mark is minted in the session's own account");
    assert!(err.contains("mark_text takes 'doc'") && err.contains("'account'"), "{err}");
    assert_eq!(Tool::admit("diff_text", &args(json!({"doc": "1.0.1.0.64", "since": "1.0.1.0.65", "stat": true, "hunk": 2}))), Ok(Tool::DiffText));
    let err = Tool::admit("diff_text", &args(json!({"doc": "1.0.1.0.64", "mark": "1.0.1.0.65"}))).expect_err("a member the row does not take");
    assert!(err.contains("diff_text takes 'doc', 'since', 'stat', 'hunk'") && err.contains("'mark'"), "the document compared with is `since`: {err}");
    assert_eq!(Tool::admit("restore_text", &args(json!({"draft": "1.0.1.0.64", "at": 3, "as_of": 5}))), Ok(Tool::RestoreText));
    let err = Tool::admit("restore_text", &args(json!({"doc": "1.0.1.0.64", "at": 3, "as_of": 5}))).expect_err("a member the row does not take");
    assert!(err.contains("restore_text takes 'draft', 'at', 'as_of'") && err.contains("'doc'"), "the draft restored is `draft`: {err}");
    assert_eq!(Tool::admit("merge_compose", &args(json!({"doc": "1.0.1.0.64", "alternative": "1.0.1.0.64.1.1", "into": "1.0.1.0.65"}))), Ok(Tool::MergeCompose));
    assert_eq!(Tool::admit("merge_compose", &args(json!({"doc": "1.0.1.0.64", "fork": "1.0.1.1.0.66"}))), Ok(Tool::MergeCompose), "the fork side");
    let err = Tool::admit("merge_compose", &args(json!({"doc": "1.0.1.0.64", "fork": "1.0.1.1.0.66", "base": "1.0.1.0.64.1"}))).expect_err("a base the shell reads itself");
    assert!(err.contains("merge_compose takes 'doc', 'alternative', 'draft', 'fork', 'into'") && err.contains("'base'"), "{err}");
    for form in [json!({}), json!({"draft": "1.0.1.0.65", "withdrawal": 7})] {
        assert_eq!(Tool::admit("merge_undo", &args(form.clone())), Ok(Tool::MergeUndo), "{form}: a form of the merge.undo row");
    }
    let err = Tool::admit("merge_withdraw", &args(json!({"doc": "1.0.1.0.65"}))).expect_err("a member the row does not take");
    assert!(err.contains("merge_withdraw takes 'draft'") && err.contains("'doc'"), "the draft withdrawn from is `draft`: {err}");
}

/// The door refuses a member of an `edit_text` pair the shell would ignore.
///
/// A pair's members are skep-shell's `TextEditPair`, held here to the
/// shell's own declaration: a pair carrying another — a `doc` of its own,
/// which the shell would make in the call's draft — is refused -32602
/// naming the pair by its index and the member, the first pair's first
/// speaking; a list that is no list and a pair that is no object pass the
/// door, for the shell to refuse by name (the mutant that reads no pair
/// admits the stranger).
#[test]
fn the_door_refuses_a_member_of_an_edit_text_pair_the_shell_would_ignore() {
    let declared: Vec<&str> = skep_shell::shapes::shape("TextEditPair").expect("skep-shell declares TextEditPair").fields.iter().map(|field| field.name).collect();
    assert_eq!(PAIR_MEMBERS, &declared[..], "the door's pair members are the shell's");
    let args = |v: Value| -> Map<String, Value> {
        let Value::Object(m) = v else { panic!("arguments are an object") };
        m
    };
    let doc = "1.0.1.0.64";
    assert_eq!(Tool::admit("edit_text", &args(json!({"doc": doc, "edits": [{"old": "a", "new": "b"}]}))), Ok(Tool::EditText));
    let err = Tool::admit("edit_text", &args(json!({"doc": doc, "edits": [{"old": "a", "new": "b"}, {"old": "c", "new": "d", "doc": "1.0.1.0.65"}]}))).expect_err("a pair's own doc");
    assert!(err.contains("'old', 'new'") && err.contains("'edits[1].doc'"), "{err}");
    let err = Tool::admit("edit_text", &args(json!({"doc": doc, "edits": [{"old": "a", "new": "b", "z": 1, "y": 2}, {"old": "c", "new": "d", "x": 3}]}))).expect_err("strangers");
    assert!(err.contains("'edits[0]."), "the first pair speaks: {err}");
    for form in [json!({"doc": doc, "edits": "a"}), json!({"doc": doc, "edits": [7, {"old": "a", "new": "b"}]}), json!({"doc": doc})] {
        assert_eq!(Tool::admit("edit_text", &args(form.clone())), Ok(Tool::EditText), "{form}: the shell's to refuse");
    }
    let err = Tool::admit("edit_text", &args(json!({"doc": doc, "edits": [], "old": "a"}))).expect_err("a member the row does not take");
    assert!(err.contains("edit_text takes 'doc', 'edits'") && err.contains("'old'"), "{err}");
}

/// Every adapter tool's schema names exactly the members its row takes.
///
/// The schema is what the agent is told to send and `Tool::admit` refuses
/// -32602 what the row lacks: a schema member the row lacks is a documented
/// argument refused at every call, a row member the schema lacks one no
/// agent is told of. Each schema is closed too, and so is its `opts` schema,
/// which names exactly the options the row's `opts` takes, and stands only
/// where the row takes one.
#[test]
fn each_adapter_tools_schema_names_exactly_the_members_its_row_takes() {
    let catalog = Catalog::load(EMBEDDED).expect("embedded tools.json must validate");
    for (name, tool, members) in ADAPTER_TOOLS {
        let entry = catalog.tools.iter().find(|t| t["name"] == *name).expect("every adapter tool is catalogued");
        let schema = &entry["inputSchema"];
        let named: BTreeSet<&str> = schema["properties"].as_object().expect("a schema's properties").keys().map(String::as_str).collect();
        assert_eq!(named, members.iter().copied().collect::<BTreeSet<&str>>(), "{name}: the schema's members are the row's");
        assert_eq!(schema["additionalProperties"], false, "{name}: the schema is closed");
        let opts = &schema["properties"]["opts"];
        match tool.opts_members() {
            Some(taken) => {
                let named: BTreeSet<&str> = opts["properties"].as_object().expect("the opts schema's properties").keys().map(String::as_str).collect();
                assert_eq!(named, taken.iter().copied().collect::<BTreeSet<&str>>(), "{name}: the opts schema names the row's options");
                assert_eq!(opts["additionalProperties"], false, "{name}: the opts schema is closed");
            }
            None => assert!(opts.is_null(), "{name}: no opts schema where the row takes none"),
        }
    }
}

/// The well-known creation's schema requires its slot and is closed.
///
/// `create_well_known_document` takes the account and the slot, both
/// required, and no other member (wire.md §Namespace): the board refuses a
/// frame without `slot` and one whose `slot` names no well-known slot, so
/// the schema an agent is told to send by requires the member, names the
/// four numbers the namespace's slots carry and no other, and admits no
/// member beside the two — no `published` flag, the slot fixing the
/// document's state. The tool's reference names each slot's document and
/// its state, and the frame the dispatch makes of the arguments carries the
/// slot through as the number sent.
#[test]
fn the_well_known_creations_schema_requires_its_slot_and_refuses_an_unknown_member() {
    let catalog = Catalog::load(EMBEDDED).expect("embedded tools.json must validate");
    let entry = catalog.tools.iter().find(|t| t["name"] == "create_well_known_document").expect("the tool is catalogued");
    let schema = &entry["inputSchema"];
    let required: BTreeSet<&str> = schema["required"].as_array().expect("the required list").iter().filter_map(Value::as_str).collect();
    assert_eq!(required, BTreeSet::from(["account", "slot"]), "the account and the slot are both required");
    let named: BTreeSet<&str> = schema["properties"].as_object().expect("a schema's properties").keys().map(String::as_str).collect();
    assert_eq!(named, required, "the schema names the two members and no other");
    assert_eq!(schema["additionalProperties"], false, "the schema is closed: an unknown member is refused");
    let slot = &schema["properties"]["slot"];
    assert_eq!(slot["type"], "integer", "the slot rides as a number");
    let slots: Vec<u64> = slot["enum"].as_array().expect("the slots the schema admits").iter().filter_map(Value::as_u64).collect();
    assert_eq!(slots, skep_client::address::WELL_KNOWN_SLOTS, "the four well-known slots, and no other number");
    let said_all = reference(&catalog, "create_well_known_document");
    for said in ["slot is REQUIRED", "2 your mailbox", "3 your bio", "4 your public link page", "5 your account's policy document", "always PRIVATE", "already exists", "created it with your home page", "PUBLISHED and EMPTY", "mint_home_first", "committed: false"] {
        assert!(said_all.contains(said), "the reference says `{said}`: {said_all}");
    }
    let args = serde_json::json!({"account": "1.0.1", "slot": 5});
    let frame = wire_frame("create_well_known_document", args.as_object().expect("an object").clone());
    assert_eq!(frame, serde_json::json!({"op": "create_well_known_document", "account": "1.0.1", "slot": 5}));
}

/// The embedded catalog states the adapter's own facts as the code holds them.
///
/// Its schemas spell `from_` on exactly the ops `wire_frame` maps back, and
/// its naming note names each of them; `fetch`'s card, its reference and
/// the FETCH topic name the cap `media` enforces, and the reference the
/// fetch's deadline in words; the `search` card and its query's schema name
/// skep-client's query bound, `changes_since`'s limit the change feed's
/// default page, its reference an entry's members as the shell declares its
/// `FeedUpdate`, each optional where the declaration has it so, and the
/// PUBLISHING topic the staging act as the adapter dispatches it — the
/// `stage` tool, its `from_` — the act whose record the shell reads a
/// draft's base off, with no record of the agent's to write (SP-25): a fact
/// changed in one place alone tells every agent what the adapter then does
/// otherwise.
#[test]
fn the_embedded_catalog_states_the_adapters_own_facts_as_the_code_holds_them() {
    use skep_client::board::DEFAULT_CHANGES_LIMIT;
    use skep_client::search::QUERY_BOUND;
    let catalog = Catalog::load(EMBEDDED).expect("embedded tools.json must validate");
    let spelled: BTreeSet<&str> = catalog.tools.iter().filter(|t| t["inputSchema"]["properties"].get("from_").is_some()).filter_map(|t| t["name"].as_str()).collect();
    assert_eq!(spelled, RENAMES_FROM.iter().copied().collect::<BTreeSet<&str>>(), "the ops whose schema spells from_");
    let note = catalog.instructions().lines().find(|line| line.starts_with("One naming note:")).expect("the instructions' naming note");
    for op in RENAMES_FROM {
        assert!(note.contains(op), "the naming note names {op}: {note}");
    }
    let entry = |name: &str| catalog.tools.iter().find(|t| t["name"] == name).unwrap_or_else(|| panic!("the {name} card"));
    let (cap, mib) = (crate::media::MAX_FETCH_BYTES, crate::media::MAX_FETCH_BYTES / (1024 * 1024));
    let fetch = reference(&catalog, "fetch");
    assert!(fetch.contains(&format!("cap of {mib} MiB ({cap} bytes)")), "the fetch reference names the cap: {fetch}");
    assert!(card(&catalog, "fetch").contains(&format!("cap of {mib} MiB")), "the fetch card names the cap");
    assert!(topic(&catalog, "FETCH").contains(&format!("cap of {mib} MiB")), "the FETCH topic names the cap");
    assert_eq!(crate::media::FETCH_DEADLINE, std::time::Duration::from_secs(10 * 60 + 30), "the deadline the fetch reference names in words");
    assert!(fetch.contains("still unfinished at ten and a half minutes"), "the fetch reference names the deadline: {fetch}");
    let search = entry("search");
    assert!(search["description"].as_str().is_some_and(|d| d.contains(&format!("A query past {QUERY_BOUND} bytes is refused query_too_long"))), "the search card names the query's bound: {search}");
    let query = search["inputSchema"]["properties"]["query"]["description"].as_str().expect("the query's description");
    assert!(query.contains(&format!("at most {QUERY_BOUND} bytes")), "the query's schema names its bound: {query}");
    let limit = entry("changes_since")["inputSchema"]["properties"]["limit"]["description"].as_str().expect("the limit's description");
    assert!(limit.contains(&format!("the board's default, {DEFAULT_CHANGES_LIMIT}, when absent")), "the limit names the default page: {limit}");
    let said = reference(&catalog, "changes_since");
    let members = said.split_once("you may read): {").and_then(|(_, rest)| rest.split_once("}, oldest first")).map(|(members, _)| members).expect("the reference lists an entry's members");
    let mut depth = 0;
    let bare: String = members
        .chars()
        .filter(|c| {
            match c {
                '(' => depth += 1,
                ')' => depth -= 1,
                _ => {}
            }
            depth == 0 && *c != ')'
        })
        .collect();
    let spelled: BTreeSet<(&str, bool)> = bare.split(',').map(str::trim).map(|member| member.strip_suffix('?').map_or((member, true), |member| (member, false))).collect();
    let declared: BTreeSet<(&str, bool)> = skep_shell::shapes::shape("FeedUpdate").expect("the shell declares a feed update").fields.iter().map(|field| (field.name, field.required)).collect();
    assert_eq!(spelled, declared, "the reference's entry is the shell's FeedUpdate: {said}");
    let publishing = topic(&catalog, "PUBLISHING");
    assert!(DISPATCH_OPS.contains(&"stage") && RENAMES_FROM.contains(&"stage"), "the staging act is a tool the adapter dispatches, its from_ renamed");
    assert!(publishing.contains("with stage(from_)"), "the act that records a draft's base is the stage tool: {publishing}");
    assert!(publishing.contains("doc_metadata(draft) answers it as base") && publishing.contains("no record for you to write"), "the board's record, read back, none written: {publishing}");
    assert!(publishing.contains("refused base_unrecorded"), "the refusal a draft with no base meets: {publishing}");
}

/// The `line_numbers` reference states the wire's list cap and its answers.
///
/// Each of its two lists is one wire list, and the "at most {n} entries" its
/// schema states of each is skep-client's `MAX_WIRE_LIST`, the codec's cap
/// as the client holds it (SP-25). The schema is closed and names the
/// frame's three members, `doc` alone required, a position in the form
/// `insert`'s `at` takes, so the frame an agent builds from it is the wire's
/// (SP-24). The tool's reference spells the answer's three members, the
/// `null` a line that names none takes, the `masked` flag and what it means
/// for handing a number on, and each refusal's token; neither it nor the
/// card promises a read of a past position, which the adapter's door
/// refuses for every wire op; and the THE TYPED STATE topic and the
/// `insert` card's `as_of` name the read among those a burst is typed
/// against.
#[test]
fn the_line_numbers_reference_states_the_wires_list_cap_and_the_answers_an_agent_reads() {
    use skep_client::publication::MAX_WIRE_LIST;
    let catalog = Catalog::load(EMBEDDED).expect("embedded tools.json must validate");
    let entry = |name: &str| catalog.tools.iter().find(|t| t["name"] == name).unwrap_or_else(|| panic!("the {name} card"));
    let schema = &entry("line_numbers")["inputSchema"];
    let members: BTreeSet<&str> = schema["properties"].as_object().expect("a schema's properties").keys().map(String::as_str).collect();
    assert_eq!(members, BTreeSet::from(["doc", "lines", "positions"]), "the frame's three members");
    assert_eq!(schema["required"], json!(["doc"]), "the two lists are optional");
    assert_eq!(schema["additionalProperties"], json!(false), "a closed schema");
    for list in ["positions", "lines"] {
        let said = schema["properties"][list]["description"].as_str().expect("a list's description");
        assert!(said.contains(&format!("One wire list, at most {MAX_WIRE_LIST} entries.")), "{list} names the wire's cap: {said}");
        assert!(said.contains("Absent or null = none."), "{list} is optional as the wire has it: {said}");
    }
    let (position, at) = (&schema["properties"]["positions"]["items"], &entry("insert")["inputSchema"]["properties"]["at"]);
    for member in ["type", "properties", "required", "additionalProperties"] {
        assert_eq!(position[member], at[member], "a position's {member} is insert's `at`'s");
    }
    let said_all = reference(&catalog, "line_numbers");
    for said in [
        r#"{"positions": [{"line", "masked"}], "lines": [{"start": {"subspace", "ordinal"}, "masked"} or null], "count": {"n", "masked"}}"#,
        "null stands in the place of a line that names none",
        "masked is true where a run you may not read lies at or before what the number numbers",
        "its line breaks are counted nowhere",
        "hand another reader a position with its as_of, or a permanent address",
        "an atom holds none, whatever its bytes",
        "a document ending in a line break has no empty last line",
        "as it stands at the answer's as_of",
        "doc_not_registered",
        "withheld",
        "not_content_subspace",
        "range_not_present",
        "site.index",
        "too_many_items",
    ] {
        assert!(said_all.contains(said), "the reference says {said:?}: {said_all}");
    }
    for text in [said_all, card(&catalog, "line_numbers")] {
        assert!(!text.contains("op-at") && !text.contains("past position"), "no historical read is promised: {text}");
    }
    let typed = topic(&catalog, "THE TYPED STATE");
    assert!(typed.contains("(retrieve_v, image, retrieve_doc_v_span_set, line_numbers)"), "the topic names the read: {typed}");
    let as_of = entry("insert")["inputSchema"]["properties"]["as_of"]["description"].as_str().expect("insert's as_of");
    assert!(as_of.contains("retrieve_v, image, retrieve_doc_v_span_set or line_numbers"), "insert's as_of names the read: {as_of}");
}

/// A catalog's drift from another counts what an agent is told otherwise.
///
/// A catalog read from the same text drifts nowhere; an entry described
/// otherwise is counted among the catalog's tools; instructions read
/// otherwise — or a commons template — are said, with the entries beside them
/// where any differ; and a help topic is counted where its text reads
/// otherwise or one store alone holds it, over the topics the two hold
/// between them, never folded into the instructions.
#[test]
fn a_catalogs_drift_from_another_counts_what_an_agent_is_told_otherwise() {
    let embedded = Catalog::load(EMBEDDED).expect("embedded tools.json must validate");
    let (tools, topics) = (embedded.tools.len(), embedded.help.len());
    let drift = |edit: &dyn Fn(&mut Value)| {
        let mut v: Value = serde_json::from_str(EMBEDDED).expect("embedded parses");
        edit(&mut v);
        Catalog::load(&v.to_string()).expect("the edited catalog loads").drift_from(&embedded).map(|drift| drift.to_string())
    };
    assert_eq!(drift(&|_| {}), None, "the same text drifts nowhere");
    let fork = |v: &mut Value| v["tools"].as_array_mut().expect("tools").iter_mut().find(|t| t["name"] == "fork").expect("fork")["description"] = json!("Another description.");
    assert_eq!(drift(&fork), Some(format!("1 of its {tools} tools' entries")));
    assert_eq!(drift(&|v| v["commons_instructions"] = json!("Another commons at {addr}.")), Some("its instructions".to_string()));
    let both = |v: &mut Value| {
        fork(v);
        v["instructions"] = json!("Other instructions.");
    };
    assert_eq!(drift(&both), Some(format!("its instructions, and 1 of its {tools} tools' entries")));
    let fetch = |v: &mut Value| v["help"].as_array_mut().expect("the help store").iter_mut().find(|entry| entry["topic"] == "FETCH").expect("FETCH")["text"] = json!("FETCH. Another text.");
    assert_eq!(drift(&fetch), Some(format!("1 of the {topics} help topics")), "a topic read otherwise is the store's, not the instructions'");
    assert_eq!(drift(&|v| v["help"].as_array_mut().expect("the help store").retain(|entry| entry["topic"] != "FETCH")), Some(format!("1 of the {topics} help topics")), "a topic dropped");
    let added = |v: &mut Value| v["help"].as_array_mut().expect("the help store").push(json!({"topic": "rearrange", "text": "The rearrange reference."}));
    assert_eq!(drift(&added), Some(format!("1 of the {} help topics", topics + 1)), "a topic added");
    let all = |v: &mut Value| {
        both(v);
        fetch(v);
    };
    assert_eq!(drift(&all), Some(format!("its instructions, 1 of its {tools} tools' entries, and 1 of the {topics} help topics")));
}

/// Every topic the catalog names is a topic of its help store.
///
/// The instructions, a card or a help topic name a topic by its heading in
/// capitals, in parentheses — `(HELD BURSTS)` — or by the call that reads
/// it, `help("replace_text")`, and every topic so named is one the store
/// holds; each heading's text opens with its heading. A heading renamed in
/// one place alone, or a topic dropped while a text still names it, sends an
/// agent to a topic that is not there.
#[test]
fn every_topic_the_catalog_names_is_a_help_topic() {
    let catalog = Catalog::load(EMBEDDED).expect("embedded tools.json must validate");
    let topics: BTreeSet<&str> = catalog.topics().collect();
    for heading in topics.iter().filter(|held| is_heading(held)) {
        assert!(topic(&catalog, heading).starts_with(&format!("{heading}. ")), "the topic {heading} opens with its heading");
    }
    let texts = std::iter::once(("the instructions", catalog.instructions()))
        .chain(catalog.tools.iter().filter_map(|t| Some((t["name"].as_str()?, t["description"].as_str()?))))
        .chain(catalog.help.iter().map(|(held, text)| (held.as_str(), text.as_str())));
    let (mut headings, mut calls) = (0, 0);
    for (whose, text) in texts {
        for (inner, _) in text.split('(').skip(1).filter_map(|rest| rest.split_once(')')) {
            if is_heading(inner) {
                assert!(topics.contains(inner), "{whose} names the topic {inner}, which the store does not hold: {topics:?}");
                headings += 1;
            }
        }
        for (named, _) in text.split("help(\"").skip(1).filter_map(|rest| rest.split_once("\")")) {
            assert!(topics.contains(named), "{whose} names help(\"{named}\"), which the store does not hold: {topics:?}");
            calls += 1;
        }
    }
    assert!(headings > 0 && calls > 0, "premise: the catalog names a topic both ways");
}

/// Every card and the instructions are short.
///
/// A client cuts a tool's description, and the server instructions, past a
/// length of its own: every card is at most `MAX_CARD_CHARS`, the `help`
/// card at most `MAX_HELP_CARD_CHARS`, and the instructions, the commons
/// sentence appended, at most `MAX_INSTRUCTIONS_CHARS`, so an agent is told
/// the whole of each.
#[test]
fn every_card_and_the_instructions_are_short() {
    let mut catalog = Catalog::load(EMBEDDED).expect("embedded tools.json must validate");
    for name in Tool::names() {
        let said = card(&catalog, name).chars().count();
        let bound = if name == "help" { MAX_HELP_CARD_CHARS } else { MAX_CARD_CHARS };
        assert!(said <= bound, "{name}'s card is {said} characters, past {bound}");
    }
    catalog.append_commons(crate::COMMONS_DOCUMENT);
    let said = catalog.instructions().chars().count();
    assert!(said <= MAX_INSTRUCTIONS_CHARS, "the instructions, the commons sentence appended, are {said} characters, past {MAX_INSTRUCTIONS_CHARS}");
}

/// A card with a reference points to it.
///
/// A tool's topic stands in the help store exactly where its card ends
/// `Full reference: help("<name>").`, so no card points at a topic that is
/// not there and no reference waits unnamed; the tools with a reference are
/// the twenty-three whose whole text an agent needs only when a call goes
/// the way it covers.
#[test]
fn a_card_with_a_reference_points_to_it() {
    let catalog = Catalog::load(EMBEDDED).expect("embedded tools.json must validate");
    for name in Tool::names() {
        let points = card(&catalog, name).ends_with(&format!("Full reference: help(\"{name}\")."));
        assert_eq!(points, catalog.help(name).is_some(), "{name}: the card names its reference exactly where the store holds one");
    }
    let referenced: BTreeSet<&str> = catalog.topics().filter(|held| !is_heading(held)).collect();
    assert_eq!(referenced, BTreeSet::from(REFERENCED), "the tools with a reference");
}

/// Each short card says what an agent needs first.
///
/// Each card holds, itself, the tokens an agent acts on before it reads any
/// reference: the form of the call, the answers that change its next step
/// and the step each asks. Each token but a tool's name is in the tool's
/// reference too, so a word the shell renames, which the reference tests
/// hold to the shell's, cannot stand in a card alone. The figures are
/// rendered from their constants (SP-25): the fetch's cap from
/// `MAX_FETCH_BYTES` and the pairs' from `MAX_WIRE_LIST`. `rearrange`'s
/// card, which is its whole reference, says what three cuts do and then
/// what four do, each with its example over `abcde`, so the two orders
/// cannot trade places.
#[test]
fn each_short_card_says_what_an_agent_needs_first() {
    use skep_client::publication::MAX_WIRE_LIST;
    let catalog = Catalog::load(EMBEDDED).expect("embedded tools.json must validate");
    let mib = format!("{} MiB", crate::media::MAX_FETCH_BYTES / (1024 * 1024));
    let pairs = format!("at most {MAX_WIRE_LIST} pairs");
    let said: [(&str, &[&str]); 24] = [
        ("merge_compose", &["MERGING", "alternative", "draft", "fork", "into", "\"landed\"", "\"reopened\"", "\"merged\"", "EDITING", "merge_land", "base_unknown", "held_lines", "isError"]),
        ("merge_land", &["resolutions", "\"run.part\"", "\"landed\"", "\"restated\"", "supersede_refused", "head_moved", "window_parts_owed", "no_merge", "isError", "not undone"]),
        (
            "merge_undo",
            &[
                "merge_undo(draft, withdrawal)",
                "your own edits included",
                "arrangement_moved",
                "can no longer land",
                "merge_withdraw",
                "no_merge",
                "taken back already",
                "another landing",
                "compose again",
                "nothing_to_undo",
                "held_lines",
                "isError",
            ],
        ),
        ("merge_withdraw", &["KEEPS", "in any session", "merge_undo(draft, withdrawal: position)", "arrangement_moved", "no_merge", "not_owner", "held_lines"]),
        ("replace_text", &["EXACTLY ONCE", "edit_text", "move_lines", "\"replaced\"", "\"refused\"", "not_unique", "\"partial\"", "\"held\"", "isError"]),
        (
            "edit_text",
            &[
                "\"edited\"",
                "\"refused\"",
                "replace_text",
                "isError",
                "edit_text(doc, edits: [{old, new}, …])",
                "EXACTLY ONCE in the draft as the pairs before it leave it",
                "ALL OR NOTHING",
                &pairs,
                "partial and held are isError",
                "read the draft before you edit it again",
            ],
        ),
        (
            "move_lines",
            &[
                "\"moved\"",
                "\"refused\"",
                "edit_text",
                "rearrange",
                "line_numbers",
                "isError",
                "move_lines(doc, first, last?, before?)",
                "both included",
                "made after your last change",
                "The lines move exactly as given",
                "to_first and to_last",
                "no_such_line",
                "arrangement_moved",
            ],
        ),
        (
            "mark_text",
            &[
                "\"marked\"",
                "\"refused\"",
                "diff_text",
                "mark_text(doc)",
                "by identity",
                "to pass as since",
                "the empty document",
                "partial is isError",
                "usable as since, with no marks link",
                "isError",
            ],
        ),
        (
            "diff_text",
            &[
                "\"diffed\"",
                "\"unchanged\"",
                "\"refused\"",
                "mark_text",
                "diff_text(doc, since, stat?, hunk?)",
                "BY IDENTITY",
                "writes nothing",
                "the version",
                "next_hunk",
                "moved here",
                "where moved lines left",
                "shared \"0\": since shares nothing with the draft",
                "arrangement_moved",
                "call again",
                "a publication re-minted pair with since",
            ],
        ),
        (
            "restore_text",
            &[
                "restore_text(draft, at, as_of)",
                "BY IDENTITY",
                "EVERY change made since at",
                "THE TYPED STATE",
                "never session_info's log_position",
                "{draft, at, position, as_of, marker}",
                "restore_text(draft, at: as_of, as_of: position)",
                "arrangement_moved",
                "call again at that read's as_of",
                "not_past",
                "history_reclaimed",
                "not_a_position",
                "held_lines",
                "isError",
            ],
        ),
        ("publication_open", &["mint", "PANEL", "publication_count", "publication_confirm", "publication_cancel", "base_unrecorded"]),
        ("publication_confirm", &["\"acknowledged\"", "\"restated\"", "\"refused\"", "no_panel"]),
        ("publication_count", &["no_panel"]),
        ("publication_standing", &["at_head", "behind", "base_unrecorded"]),
        ("held", &["resolve", "sent"]),
        ("resolve", &["\"drop\"", "\"send\"", "\"kept\": true", "may_have_landed", "landing_unread"]),
        ("changes_since", &["next", "log_position", "history_reclaimed"]),
        ("make_link", &["from_", "addrs", "spans", "empty_type_resolution"]),
        ("create_well_known_document", &["slot", "already", "mint_home_first", "committed: false"]),
        ("set_arrangement", &["WHOLE", "head_moved", "fork_base_moved"]),
        ("line_numbers", &["masked", "range_not_present"]),
        ("doc_metadata", &["base", "withheld", "arranged_at"]),
        ("fetch", &[&mib, "not_a_cell"]),
        ("rearrange", &["THREE", "FOUR", "[b, c) then [a, b)", "[c, d), [b, c), [a, b)", "bad_cut_count", "\"adebc\"", "\"cbade\""]),
    ];
    for (name, tokens) in said {
        let (short, whole) = (card(&catalog, name), reference(&catalog, name));
        for token in tokens {
            assert!(short.contains(token), "{name}'s card says `{token}`: {short}");
            if Tool::named(token).is_none() {
                assert!(whole.contains(token), "{name}'s reference says `{token}` too: {whole}");
            }
        }
    }
    let rearrange = card(&catalog, "rearrange");
    let (three, four) = rearrange.split_once("FOUR").expect("the card says what four cuts do after three");
    assert!(three.contains("THREE") && three.contains("[b, c) then [a, b)") && three.contains("\"adebc\""), "three cuts, their order and their example: {three}");
    assert!(four.contains("[c, d), [b, c), [a, b)") && four.contains("\"cbade\""), "four cuts, their order and their example: {four}");
    assert!(!three.contains("\"cbade\"") && !four.contains("\"adebc\""), "each example beside its own rule: {rearrange}");
}

/// The options the door admits are the ones skep-shell declares, bar `reindex`.
///
/// Each `opts` row of the door's table is held to the shell's own
/// declaration of its options type (`shapes::declarations`) less the option
/// the door withholds, `search`'s `reindex` (`OPTS_MEMBERS`): an option the
/// shell adds or renames fails here before the door refuses it, or admits
/// one the shell would ignore, and the one withheld stays one the shell
/// declares, so the withholding names a refresh the shell still offers.
#[test]
fn the_opts_the_door_admits_are_the_ones_skep_shell_declares_bar_reindex() {
    let declarations = skep_shell::shapes::declarations();
    for (tool, interface, withheld) in [(Tool::Search, "SearchOpts", &["reindex"][..]), (Tool::Places, "PlacesOpts", &[][..])] {
        let head = format!("export interface {interface} {{");
        let body = declarations.split_once(head.as_str()).and_then(|(_, rest)| rest.split_once('}')).map(|(body, _)| body).unwrap_or_else(|| panic!("skep-shell declares {interface}"));
        let declared: BTreeSet<&str> = body.split(';').filter_map(|member| member.split(':').next()).map(|name| name.trim().trim_end_matches('?')).filter(|name| !name.is_empty()).collect();
        let withheld: BTreeSet<&str> = withheld.iter().copied().collect();
        assert!(withheld.is_subset(&declared), "{interface}: the option withheld is one the shell declares: {withheld:?}");
        let taken: BTreeSet<&str> = tool.opts_members().expect("the row takes opts").iter().copied().collect();
        assert_eq!(taken, &declared - &withheld, "{interface}: the door's options are the shell's, bar the one withheld");
    }
}

/// Each adapter tool takes its shell row's members, bar the session and board.
///
/// The door's members, and each schema's `required`, copy skep-shell's call
/// rows, which the shell renders in its declarations (`shapes::declarations`,
/// the `Bridge` interface): a tool that makes a shell call takes exactly the
/// members of its row's session forms together — `merge.undo`'s two, the
/// landing's undo and the withdrawal's, among them; a row with no session
/// form its forms' — save `session` and `board`, which the adapter supplies
/// or does not offer, and requires exactly the ones every such form
/// requires. A guest form, which takes no session, is no form of a tool's:
/// the adapter's calls run under its one session. Each form is read whole,
/// between its braces, since a member's own type may hold a ` | ` (`resolve`'s
/// `act`). Unchecked, a member the shell renamed or dropped would stay
/// admitted here and advertised to every agent, while the shell, which
/// reads no member it does not name, answered the call as though the member
/// had never been sent.
#[test]
fn each_adapter_tool_takes_its_shell_rows_members_bar_the_session_and_board() {
    /// Returns the text inside each top-level brace pair of `text`.
    fn brace_groups(text: &str) -> Vec<&str> {
        let (mut groups, mut depth, mut start) = (Vec::new(), 0usize, 0usize);
        for (i, c) in text.char_indices() {
            match c {
                '{' => {
                    if depth == 0 {
                        start = i + 1;
                    }
                    depth += 1;
                }
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        groups.push(&text[start..i]);
                    }
                }
                _ => {}
            }
        }
        groups
    }
    let declarations = skep_shell::shapes::declarations();
    let catalog = Catalog::load(EMBEDDED).expect("embedded tools.json must validate");
    for (name, tool, members) in ADAPTER_TOOLS {
        // The row `Server::call` sends the tool as; `session_info` takes no
        // argument and copies no row, and `help` reads the catalog alone,
        // sending no row.
        let row = match tool {
            Tool::SessionInfo | Tool::Help => continue,
            Tool::ReplaceText => "text.replace",
            Tool::EditText => "text.edit",
            Tool::MoveLines => "text.move",
            Tool::MarkText => "text.mark",
            Tool::DiffText => "text.diff",
            Tool::RestoreText => "history.restore",
            Tool::ChangesSince => "changes",
            Tool::PublicationOpen => "publication.open",
            Tool::PublicationCount => "publication.count",
            Tool::PublicationConfirm => "publication.confirm",
            Tool::PublicationCancel => "publication.cancel",
            Tool::PublicationStanding => "publication.standing",
            Tool::MergeCompose => "merge.compose",
            Tool::MergeLand => "merge.land",
            Tool::MergeUndo => "merge.undo",
            Tool::MergeWithdraw => "merge.withdraw",
            _ => *name,
        };
        // The declarations quote a dotted row's name, a method of the
        // `Bridge` interface.
        let method = if row.contains('.') { format!("'{row}'") } else { row.to_string() };
        let head = format!("  {method}(args: ");
        let forms = declarations
            .lines()
            .find_map(|line| line.strip_prefix(head.as_str()))
            .and_then(|rest| rest.split_once("): Promise<"))
            .map(|(forms, _)| forms)
            .unwrap_or_else(|| panic!("skep-shell declares the row {row}"));
        // Each form's members, `(member, required)`.
        let forms: Vec<Vec<(&str, bool)>> = brace_groups(forms)
            .into_iter()
            .map(|form| {
                form.split(';')
                    .filter_map(|member| member.split(':').next())
                    .map(str::trim)
                    .filter(|member| !member.is_empty())
                    .map(|member| member.strip_suffix('?').map_or((member, true), |member| (member, false)))
                    .collect()
            })
            .collect();
        assert!(!forms.is_empty(), "the {row} row declares a form");
        let with_session: Vec<&Vec<(&str, bool)>> = forms.iter().filter(|form| form.iter().any(|(member, _)| *member == "session")).collect();
        let read: Vec<&Vec<(&str, bool)>> = if with_session.is_empty() { forms.iter().collect() } else { with_session };
        let declared: BTreeSet<&str> = read.iter().flat_map(|form| form.iter().map(|(member, _)| *member)).filter(|member| *member != "session" && *member != "board").collect();
        let required: BTreeSet<&str> = declared.iter().copied().filter(|member| read.iter().all(|form| form.contains(&(*member, true)))).collect();
        assert_eq!(members.iter().copied().collect::<BTreeSet<&str>>(), declared, "{name}: the door takes the {row} row's members");
        let entry = catalog.tools.iter().find(|t| t["name"] == *name).expect("every adapter tool is catalogued");
        let schema_required: BTreeSet<&str> = entry["inputSchema"]["required"].as_array().map(|r| r.iter().filter_map(Value::as_str).collect()).unwrap_or_default();
        assert_eq!(schema_required, required, "{name}: the schema requires what the {row} row requires");
    }
}

/// Returns a shape skep-shell declares, its fields as a card spells them.
///
/// It is `{a, b?, c: "v", …}`: a field typed by one string literal with its
/// value, an optional one marked `?`, and an open shape ending `, …`.
fn spelled(name: &str) -> String {
    let shape = skep_shell::shapes::shape(name).unwrap_or_else(|| panic!("skep-shell declares {name}"));
    let mut fields: Vec<String> = shape
        .fields
        .iter()
        .map(|field| match field.ty.strip_prefix('\'').and_then(|ty| ty.strip_suffix('\'')).filter(|ty| !ty.contains('\'')) {
            Some(value) => format!("{}: \"{value}\"", field.name),
            None if field.required => field.name.to_string(),
            None => format!("{}?", field.name),
        })
        .collect();
    if shape.open {
        fields.push("…".to_string());
    }
    format!("{{{}}}", fields.join(", "))
}

/// Returns a refusal of the shell's own as a reference spells it.
///
/// It is the refusal's name, then the shape's other members, as
/// `held_lines {doc, held}`: the `kind` and the `name` every one carries
/// stand in its name.
fn spelled_refusal(name: &str) -> String {
    let shape = skep_shell::shapes::shape(name).unwrap_or_else(|| panic!("skep-shell declares {name}"));
    let named =
        shape.fields.iter().find(|field| field.name == "name").and_then(|field| field.ty.strip_prefix('\'')?.strip_suffix('\'')).unwrap_or_else(|| panic!("{name} carries its name as one literal"));
    let members: Vec<String> =
        shape.fields.iter().filter(|field| field.name != "kind" && field.name != "name").map(|field| if field.required { field.name.to_string() } else { format!("{}?", field.name) }).collect();
    format!("{named} {{{}}}", members.join(", "))
}

/// Returns an inline object type's member names, `b?` for an optional `b`.
fn members(object: &str) -> Vec<&str> {
    object.trim_matches(|c| c == '{' || c == '}').split(';').filter_map(|member| member.split(':').next()).map(str::trim).filter(|member| !member.is_empty()).collect()
}

/// Returns the arms of the type alias `name` the declarations hold.
fn alias(declarations: &str, name: &str) -> Vec<String> {
    let head = format!("export type {name} = ");
    let line = declarations.lines().find_map(|line| line.strip_prefix(head.as_str())).unwrap_or_else(|| panic!("skep-shell declares {name}"));
    line.trim_end_matches(';').split('|').map(|arm| arm.trim().to_string()).collect()
}

/// The publication tools' references state the shell's declared shapes.
///
/// Each `publication` tool's reference — its help topic, or its card where
/// the store holds none — spells every arm of the answer the shell
/// declares for its row (`shapes::declarations`) — a shape as `{a, b, c?}`, a
/// field typed by one string literal with its value and an open shape ending
/// `, …`, the empty answer as `{}` — and the open and count references the
/// shapes of the panel's members — a window's parts among them; the open's
/// names each standing the shell's
/// `BaseStanding` spells, its one refusal of a base by the shell's name —
/// `base_unrecorded` with its members and reasons — and its refusal of a
/// re-open passing a member the panel does not hold, `other_panel` as the
/// shell's `OtherPanelRefusal` spells it, with a member left out read as the
/// panel's and the way on (skep #979); neither the open's
/// card nor its reference names `base_superseded`
/// (the shell refuses no standing; a draft begun before version 1 is told
/// `superseded_first`), while the confirm's reference names the library's
/// `base_superseded {first}` arm; the
/// selection's runs, the switches, a destination and an answer are schema'd
/// as the shell's `Run`, `Switches`, `Destination` and `OriginAnswer` spell
/// them (SP-24). A shape the shell changes in one place alone would tell
/// every agent of an answer the shell no longer gives, or ask an argument it
/// no longer takes.
#[test]
fn the_publication_references_state_the_shells_shapes() {
    /// Returns a shape's field names, and those of them it requires.
    fn fields(name: &str) -> (BTreeSet<&'static str>, BTreeSet<&'static str>) {
        let shape = skep_shell::shapes::shape(name).unwrap_or_else(|| panic!("skep-shell declares {name}"));
        (shape.fields.iter().map(|field| field.name).collect(), shape.fields.iter().filter(|field| field.required).map(|field| field.name).collect())
    }
    /// Returns a schema's property names, and those of them it requires.
    fn schema_fields(schema: &Value) -> (BTreeSet<&str>, BTreeSet<&str>) {
        let named = schema["properties"].as_object().expect("a schema's properties").keys().map(String::as_str).collect();
        let required = schema["required"].as_array().map(|required| required.iter().filter_map(Value::as_str).collect()).unwrap_or_default();
        (named, required)
    }
    let declarations = skep_shell::shapes::declarations();
    let alias = |name: &str| alias(&declarations, name);
    let catalog = Catalog::load(EMBEDDED).expect("embedded tools.json must validate");
    let entry = |name: &str| catalog.tools.iter().find(|t| t["name"] == name).unwrap_or_else(|| panic!("the {name} card"));
    for (name, row, nested) in [
        ("publication_open", "publication.open", &["PublicationRow", "TypeFold", "RowFold", "Formatting", "Count", "Price", "Window", "Part", "PartCounts", "Hold"][..]),
        ("publication_count", "publication.count", &["Count"][..]),
        ("publication_confirm", "publication.confirm", &[][..]),
        ("publication_cancel", "publication.cancel", &[][..]),
        ("publication_standing", "publication.standing", &[][..]),
    ] {
        let head = format!("  '{row}'(args: ");
        let line = declarations.lines().find(|line| line.starts_with(head.as_str())).unwrap_or_else(|| panic!("skep-shell declares the row {row}"));
        let answer = line.split_once("Promise<Outcome<").and_then(|(_, rest)| rest.strip_suffix(">>;")).unwrap_or_else(|| panic!("the {row} row's answer: {line}"));
        let said_all = reference(&catalog, name);
        for arm in answer.split(" | ").map(str::trim) {
            let said = match arm {
                "Empty" => "{}".to_string(),
                inline if inline.starts_with('{') => format!("{{{}}}", members(inline).join(", ")),
                shape => spelled(shape),
            };
            assert!(said_all.contains(&said), "the {name} reference spells the {row} row's answer {said}: {said_all}");
        }
        for shape in nested {
            let said = spelled(shape);
            assert!(said_all.contains(&said), "the {name} reference spells {shape} as {said}: {said_all}");
        }
    }
    let count = reference(&catalog, "publication_count");
    assert!(["changed_types", "unchanged_types"].iter().all(|fold| count.contains(fold)), "the count reference names the row's two folds by type: {count}");
    let open = reference(&catalog, "publication_open");
    for standing in alias("BaseStanding") {
        let standing = standing.trim_matches('\'');
        assert!(open.contains(standing), "the open reference names the standing {standing}: {open}");
    }
    let (unrecorded, superseded) = (skep_shell::Name::BASE_UNRECORDED.as_str(), "base_superseded");
    assert!(open.contains(&format!("{unrecorded} {{draft, doc, reason}}")) && ["no_record", "other_chain", "free_standing"].iter().all(|reason| open.contains(reason)), "the open reference names base_unrecorded's members and reasons: {open}");
    for said in [open, card(&catalog, "publication_open")] {
        assert!(!said.contains(superseded), "the open refuses no standing — a draft begun before version 1 is told superseded_first: {said}");
    }
    assert!(open.contains("superseded_first (") && open.contains("beside version 1 as its daughter"), "the open reference tells the fourth standing and where its member lands: {open}");
    let other_panel = spelled_refusal("OtherPanelRefusal");
    assert!(
        open.contains(&format!("is refused {other_panel} (isError), naming the panel's own doc or mint, nothing read and every panel as it stood"))
            && open.contains("one you leave out read as the panel's")
            && open.contains("open it with that doc or mint alone, then publication_cancel it for a fresh panel"),
        "the open reference names the refusal of a re-open in another form by the shell's shape, a member left out the panel's, and the way on: {open}"
    );
    let confirm = reference(&catalog, "publication_confirm");
    assert!(confirm.contains(&format!("{superseded} {{first}}")), "the confirm reference names the library's base_superseded arm: {confirm}");
    assert!(confirm.contains("superseded_first where version 1 was"), "the confirm reference re-states a first draft's standing moved: {confirm}");
    assert!(confirm.contains("or its base did, base then the base as read") && confirm.contains("a base or a standing that moved is the restated outcome"), "the confirm reference says a moved base is re-stated, never a refusal: {confirm}");
    assert!(confirm.contains(&format!("{} {{index}}", skep_shell::Name::SELECTION_NOT_ARRANGED.as_str())), "the confirm reference names the refusal of a selection the draft has wholly left: {confirm}");
    assert!(confirm.contains("kept_place_moved {index, draft, race}"), "the confirm reference names kept_place_moved's members, the draft that moved among them: {confirm}");
    assert!(confirm.contains("each of also — is re-windowed") && confirm.contains("stray_place {index, draft}"), "the confirm reference says every named draft is re-windowed in the one write, and names the own fault's draft: {confirm}");
    // The held-lines gate (client.md §3c.4; skep #849): the confirm
    // reference names the refusal with its members and the agent's act, and
    // the REJECTIONS ARE DATA topic lists it among the shell's own, the
    // restore's and the merge tools' beside the confirm's.
    let held_lines = skep_shell::Name::HELD_LINES.as_str();
    assert!(
        confirm.contains(&format!("holds a line of yours the board has not kept (HELD BURSTS) it is refused {held_lines} {{doc, held}} (isError), nothing sent"))
            && confirm.contains("call held(), resolve each line on that doc, then confirm again"),
        "the confirm reference names the held-lines gate's refusal, its members and the act: {confirm}"
    );
    let rejections = topic(&catalog, "REJECTIONS ARE DATA");
    assert!(rejections.contains(&format!("{held_lines} {{doc, held}} — a publication_confirm over a draft holding lines of yours the board has not kept")), "REJECTIONS ARE DATA names the gate's refusal: {rejections}");
    assert!(
        rejections.contains("the rendering draft or one named also, a restore_text whose draft holds them, or a merge tool over a draft that does"),
        "REJECTIONS ARE DATA names the restore and the merge tools beside the confirm: {rejections}"
    );
    assert!(
        rejections.contains("merge_compose's into or the draft a merge record of yours names, merge_land's draft or draft side, merge_undo's and merge_withdraw's draft — nothing sent: call held(), resolve each line on that doc, then call again"),
        "REJECTIONS ARE DATA names each merge tool's draft the gate asks, and the act: {rejections}"
    );
    let selection = &entry("publication_open")["inputSchema"]["properties"]["selection"]["items"];
    assert_eq!(schema_fields(selection), fields("Run"), "the selection's runs are the shell's Run");
    let answers: BTreeSet<String> = alias("OriginAnswer").iter().map(|arm| arm.trim_matches('\'').to_string()).collect();
    let destination = alias("Destination");
    let literals: BTreeSet<&str> = destination.iter().filter_map(|arm| arm.strip_prefix('\'').and_then(|arm| arm.strip_suffix('\''))).collect();
    let objects: BTreeSet<&str> = destination.iter().filter(|arm| arm.starts_with('{')).flat_map(|arm| members(arm)).collect();
    for name in ["publication_count", "publication_confirm"] {
        let properties = &entry(name)["inputSchema"]["properties"];
        assert_eq!(schema_fields(&properties["switches"]), fields("Switches"), "{name}: the switches are the shell's Switches");
        let arms = properties["switches"]["properties"]["destinations"]["additionalProperties"]["oneOf"].as_array().expect("a destination's arms");
        let spelled_literals: BTreeSet<&str> = arms.iter().filter_map(|arm| arm["enum"].as_array()).flatten().filter_map(Value::as_str).collect();
        let spelled_objects: BTreeSet<&str> = arms.iter().filter_map(|arm| arm["properties"].as_object()).flat_map(|object| object.keys().map(String::as_str)).collect();
        assert_eq!((&spelled_literals, &spelled_objects), (&literals, &objects), "{name}: a destination is the shell's Destination");
        let enumerated: BTreeSet<String> = properties["answers"]["additionalProperties"]["enum"].as_array().expect("the answers' enum").iter().filter_map(Value::as_str).map(str::to_string).collect();
        assert_eq!(enumerated, answers, "{name}: an answer is the shell's OriginAnswer");
    }
}

/// The merge tools' references state the shell's declared shapes.
///
/// Each `merge` tool's reference spells every arm of the answer the shell
/// declares for its row (`shapes::declarations`) as `{a, b, c?}`, as the
/// publication tools' do — `merge_compose`'s report, a gap of it, a
/// stretch a landing replaced and a place the merge kept once,
/// `merge_land`'s landing, re-statement and refusal and a place kept once
/// as its landing names it, `merge_undo`'s answer and
/// the marker in it, `merge_withdraw`'s answer — and names each refusal of
/// the shell's own an agent acts on by its name with its members, as
/// REJECTIONS ARE DATA names `held_lines {doc, held}`: every tool's
/// `held_lines`, and `merge_land`'s `window_parts_owed`, each part in it
/// spelled as the shell's `WindowPart`, and `other_panel`, whose way on it
/// and MERGING say re-opens a held panel in its own form before the cancel,
/// an open in another being refused the same (skep #979); the compose
/// reference names `base_unknown` with every member the shell answers it
/// with, by each reason, at the draft side and at the fork side,
/// `bare_source` naming its `source` for a draft of yours or a fork begun
/// from the bare document while it has no version, with the way on from
/// that draft, and naming its `hop` where the board serves no count of the
/// document's words before version 1, `hop_unrecorded` naming its `hop`,
/// and the fork side's own refusal at its landing, `fork_base_moved`, a
/// fork its owner staged taking the landing at any head, and the arm
/// `line_text_withheld` with its members and the ways past it; it and MERGING
/// say that a fork stands where the board records it — its recorded base,
/// which a landing into it moves, else its source — that a side begun
/// from the document before its first
/// version composes over the document as it stood then, `base` the
/// document itself, and that a draft of the document owner's account given
/// as the fork side is refused `fork_of_owner`, to be given as the draft
/// side. The compose reference and MERGING name every gap kind
/// the shell's `GapKind` spells;
/// `merge_land`'s schema takes `resolutions` as the shell's `MergeChoice`
/// and `answers` as its `OriginAnswer` (SP-24). MERGING says what a merge
/// takes, that a gap is settled by editing the draft — a `moves` gap with
/// spots by moving its words to another side's spot, which the compose
/// reference says beside the gap's `spots` and `merge_land`'s reference and
/// card beside the one choice such a gap takes (CM-I33) — that the landing
/// answers no window part, that the composition lives with the session and
/// that a merge's undo lands only over no change since, the agent's own
/// included (R6 with P3, the undo's `as_of` per surface); PUBLISHING, the
/// OVERVIEW and `set_arrangement`'s card and reference send a merge to the
/// four; and REJECTIONS ARE DATA names them among the calls that may have
/// written before a session's end. A shape the shell changes in one place
/// alone would tell every agent of an answer the shell no longer gives.
#[test]
fn the_merge_references_state_the_shells_shapes() {
    let declarations = skep_shell::shapes::declarations();
    let catalog = Catalog::load(EMBEDDED).expect("embedded tools.json must validate");
    for (name, row, nested, refusals) in [
        ("merge_compose", "merge.compose", &["MergeGap", "ReplacedStretch", "MergeDedup"][..], &["HeldLinesRefusal"][..]),
        ("merge_land", "merge.land", &["WindowPart", "MergeDedup"][..], &["WindowPartsOwedRefusal", "OtherPanelRefusal", "HeldLinesRefusal"][..]),
        ("merge_undo", "merge.undo", &["MergeMarker"][..], &["HeldLinesRefusal"][..]),
        ("merge_withdraw", "merge.withdraw", &[][..], &["HeldLinesRefusal"][..]),
    ] {
        let head = format!("  '{row}'(args: ");
        let line = declarations.lines().find(|line| line.starts_with(head.as_str())).unwrap_or_else(|| panic!("skep-shell declares the row {row}"));
        let answer = line.split_once("Promise<Outcome<").and_then(|(_, rest)| rest.strip_suffix(">>;")).unwrap_or_else(|| panic!("the {row} row's answer: {line}"));
        let said_all = reference(&catalog, name);
        for shape in answer.split(" | ").map(str::trim).chain(nested.iter().copied()) {
            let said = spelled(shape);
            assert!(said_all.contains(&said), "the {name} reference spells {shape} as {said}: {said_all}");
        }
        for shape in refusals {
            let said = spelled_refusal(shape);
            assert!(said_all.contains(&said), "the {name} reference names the refusal {shape} as {said}: {said_all}");
        }
    }
    let merging = topic(&catalog, "MERGING");
    // The way on from `other_panel`: a held panel is re-opened in its own
    // form first, since an open in another is refused the same.
    let own_form = "a held one first opened again in its own form, publication_open with the draft and the doc or mint the refusal names and nothing else";
    for (whose, said) in [("MERGING", merging), ("the merge_land reference", reference(&catalog, "merge_land"))] {
        assert!(said.contains(own_form), "{whose} re-opens a held panel in its own form before the cancel: {said}");
    }
    for kind in alias(&declarations, "GapKind") {
        let kind = kind.trim_matches('\'');
        for (whose, said) in [("merge_compose's reference", reference(&catalog, "merge_compose")), ("MERGING", merging)] {
            assert!(said.contains(kind), "{whose} names the gap kind {kind}: {said}");
        }
    }
    // The schema: `resolutions` the shell's `MergeChoice`, `answers` its
    // `OriginAnswer`.
    let properties = &catalog.tools.iter().find(|t| t["name"] == "merge_land").expect("the merge_land card")["inputSchema"]["properties"];
    let choice = alias(&declarations, "MergeChoice");
    let literals: BTreeSet<&str> = choice.iter().filter_map(|arm| arm.strip_prefix('\'').and_then(|arm| arm.strip_suffix('\''))).collect();
    let objects: BTreeSet<&str> = choice.iter().filter(|arm| arm.starts_with('{')).flat_map(|arm| members(arm)).collect();
    let arms = properties["resolutions"]["additionalProperties"]["oneOf"].as_array().expect("a choice's arms");
    let spelled_literals: BTreeSet<&str> = arms.iter().filter_map(|arm| arm["enum"].as_array()).flatten().filter_map(Value::as_str).collect();
    let spelled_objects: BTreeSet<&str> = arms.iter().filter_map(|arm| arm["properties"].as_object()).flat_map(|object| object.keys().map(String::as_str)).collect();
    assert_eq!((&spelled_literals, &spelled_objects), (&literals, &objects), "a resolution's choice is the shell's MergeChoice");
    let answers: BTreeSet<String> = alias(&declarations, "OriginAnswer").iter().map(|arm| arm.trim_matches('\'').to_string()).collect();
    let enumerated: BTreeSet<String> = properties["answers"]["additionalProperties"]["enum"].as_array().expect("the answers' enum").iter().filter_map(Value::as_str).map(str::to_string).collect();
    assert_eq!(enumerated, answers, "merge_land: an answer is the shell's OriginAnswer");
    // MERGING, and the texts that send a merge to the four.
    for said in [
        "a document never published has nothing to merge",
        "whose recorded base (doc_metadata(draft).base) is doc or a version of doc",
        "whose recorded base (doc_metadata(fork).base), else its source (doc_metadata(fork).source), is doc or a version of doc",
        "a landing into a fork staged so moves its base, and the fork is merged from where it now stands",
        "The base is read off the bases the board recorded, never off an address",
        "composes over doc as it stood before version 1, empty on most documents, base then doc itself",
        "while doc has no version yet it is refused base_unknown with reason bare_source, nothing to merge onto",
        "refused base_unknown, nothing written",
        "a draft of doc's owner's account given as fork is refused base_unknown with reason fork_of_owner — give it as draft",
        "reason hop_unrecorded names the hop",
        "A gap is settled by EDITING THE DRAFT",
        "resolved_by agent",
        "change no words",
        "It answers NO window part for you",
        "The composition lives with this adapter's session",
        "a published merge is not undone",
        "your own edits included",
        "a call — the adapter's own once included — that finds the merge landed in such a draft is refused merge_refused landing_begun {draft, position}, nothing staged or written, never a second landing",
        "compose again naming draft as into, before you write to it, which re-opens it and writes its record; then merge_undo() takes the merge back, or merge_withdraw(draft) takes it out and keeps its words",
        "A draft only staged, the merge never landed in it, is found by its stage row on changes_since(class: \"drafts\")",
        "merge_land publishes into doc, which only its owner can",
    ] {
        assert!(merging.contains(said), "MERGING says {said:?}: {merging}");
    }
    let publishing = topic(&catalog, "PUBLISHING");
    assert!(
        publishing.contains("composes them as count.supersede") && publishing.contains("(MERGING)") && !publishing.contains("to come"),
        "PUBLISHING names the claim the open composes and the merge tools: {publishing}"
    );
    let overview = topic(&catalog, "OVERVIEW");
    assert!(overview.contains("merge_compose, merge_land, merge_undo and merge_withdraw") && overview.contains("(MERGING)"), "the overview names the four among the shell's calls: {overview}");
    for said in [card(&catalog, "set_arrangement"), reference(&catalog, "set_arrangement")] {
        assert!(said.contains("merge_compose") && !said.contains("nothing here composes a merge"), "set_arrangement sends a merge to merge_compose: {said}");
    }
    let rejections = topic(&catalog, "REJECTIONS ARE DATA");
    assert!(
        rejections.contains("save a publication_confirm, which may have sent its request first (PUBLISHING), and the merge tools, merge_compose, merge_land, merge_undo and merge_withdraw, each of which may have written before the end (MERGING)"),
        "REJECTIONS ARE DATA names the merge tools among the calls an end may not have stopped: {rejections}"
    );
    // What a compose made again after a lost answer or a session's end
    // leaves — a landing no record names refused `landing_begun` with no
    // `into`, and recorded by the re-open naming it — and how a draft only
    // staged is found; the base read off the records, `doc` itself for a
    // side begun before the first version; `base_unknown` by each reason,
    // with the way on from a draft begun while no version stands; and a
    // window withheld in the text the line rule reads, refused under its
    // own arm with its members and its ways on (skep #1174).
    let compose = reference(&catalog, "merge_compose");
    for said in [
        "which the adapter makes again itself, once, under the next session — may have left a draft it staged, or landed in, that no merge record names",
        "With into named, the call made again re-opens into, or lands there, and stages nothing more, a re-open writing the record of a landing no merge record names where into still holds the merge",
        "With none named, where the merge landed in such a draft, the call — the adapter's own once included — is refused merge_refused landing_begun {draft, position}, nothing staged or written",
        "name draft as into, before you write to it, to re-open it with its record; then merge_undo() takes the merge back, or merge_withdraw(draft) takes it out and keeps its words",
        "merge_refused {arm, …}, landing_begun {draft, position} among its arms",
        "changes_since(class: \"drafts\") from before the call names such a draft",
        "base the version both sides descend from, read off the bases the board recorded and never off an address — doc itself where a side was begun from doc before its first version",
        "up from the version the side lies under, or from doc's first version for a side begun from doc itself",
        "base_unknown {side, reason, source?, hop?}",
        "reason base_unknown for a draft never staged, one staged from a draft with no recorded base or from another document, or a draft of another account — compose that one as a fork",
        "and for a fork with neither a recorded base nor a source, one the fork op minted, or one whose recorded base, else its source, is neither doc nor a version of it",
        "while a fork its owner staged — one doc_metadata(fork).base names — takes it at any head, its base moving there",
        "a draft of doc's owner's account given as fork is refused base_unknown with reason fork_of_owner — give it as draft",
        "reason fork_of_owner for a document of doc's owner's account given as fork, whose draft is the draft side — give it as draft",
        "reason bare_source, naming source (doc itself), for a draft of yours or a fork, of any account, begun from doc while doc has no version yet — nothing to merge onto: publish that draft, which lands version 1",
        "naming the hop, the version on the side's line published from doc, where the side's own base or source is not doc",
        "reason hop_unrecorded, naming the hop, a version on the side's line the board records no base for, its base never taken from its address",
        "refused merge_refused fork_base_moved {fork, source, head} where its source is not the head",
        "is refused merge_refused {arm: \"side_moved\", side, at, before, after}, isError, nothing landed",
        "the text the merge reads, whatever the dedup, to tell whether two sides' changes meet at a line's edge holds words of a document you may not read, the call is refused merge_refused {arm: \"line_text_withheld\", doc, after, before}, isError, nothing written",
        "after and before the pair's outer anchors as their gaps, or a gap's removed, name them, null at an edge",
        "call again once doc is shared with you or its words are published, since no switch keeps the merge from that read",
        "before and after the side's arranged_at at the two reads, equal where its recorded base moved and its text did not; call again, which reads it as it stands",
        "as_of the one position the composition stands at, where every side that can change held the state it was read in",
        "spots, only on a moves gap of one set of words both sides placed at two places, each side's place {side, after, before}, the default the head's",
        "or, at a moves gap with spots, move the words to another side's spot, then compose again",
        "or text it alone removed with no words of its own in their place",
        "removed, only on a line gap a removal of the other side's meets, each removal {side, after, before}, the side that removed the text and the surviving positions either side of where it stood — the removal stands whatever you choose, the gap's choices placing its words",
    ] {
        assert!(compose.contains(said), "merge_compose's reference says {said:?}: {compose}");
    }
    // A line gap a removal meets names it, and the removal stands whatever
    // the merger chooses (skep #1176).
    let removal = "or text it alone removed with no words of its own in their place, which the gap names in removed and which stands whatever you choose";
    assert!(merging.contains(removal), "MERGING says {removal:?}: {merging}");
    // One set of words two sides placed apart: settled by moving them in
    // the draft, the one choice at it the side the composition took.
    let spots = "A moves gap with spots is one set of words both sides placed, each at a spot of its own, the default the head's";
    assert!(merging.contains(spots), "MERGING says {spots:?}: {merging}");
    let land = reference(&catalog, "merge_land");
    let choice = "at a moves gap with spots the one choice is {order: [side]} or {keep_only: side} naming the side its placed names";
    assert!(land.contains(choice), "merge_land's reference says {choice:?}: {land}");
    let card = properties["resolutions"]["description"].as_str().expect("the resolutions member's description");
    assert!(card.contains("At a moves gap with spots only {order: [side]} or {keep_only: side} naming the side its placed names is taken"), "{card}");
}

/// The catalog tells an agent the edits' figures as the shell holds them.
///
/// Each text edit's reference names the cap on one change's new text and on
/// a draft's size by skep-shell's constants, and `edit_text`'s the wire's
/// list cap on its pairs, which its schema holds too, and each figure of
/// its rows; `move_lines`' reference names the draft's cap and the lines its
/// rows show either side by the same constants, and its schema takes a line
/// as a whole number from 1; `diff_text`'s reference names the cap on the
/// two texts, the plan's bound on their pairs, each figure of its rows and
/// the re-typed threshold by their constants, each row and each note in its
/// form, and that both texts are mapped through the correspondence records
/// the publications left so words a publication re-minted pair with
/// `since`, and its schema takes `stat` as a boolean and `hunk` as a whole
/// number from 1;
/// `mark_text`'s reference names the `marks` type as the client spells it;
/// the instructions send an agent to the three
/// tools, and so do the EDITING TEXT topic, which names the review step
/// too, the mark before the change and the diff after it, and the restore
/// of an earlier state, and the OVERVIEW topic, which names each among the
/// apparatus, the mark, the diff and the restore with them, and
/// `replace_text`'s card and reference,
/// which send whole lines moved to `move_lines`; and every outcome and every
/// cause of the edit's own is spelled
/// in `replace_text`'s reference (SP-25). `edit_text`'s card itself says what
/// an agent needs before it reads the reference — the call's form, the
/// once-only rule, all or nothing, the cap on its pairs and that `partial`
/// and `held` are errors after which the draft is read — and its reference
/// says the rest: every row's form, the take-back's `too_large` and the
/// one-pair tool beside it.
#[test]
fn the_catalog_tells_an_agent_the_edits_figures_as_the_code_holds_them() {
    use skep_client::publication::MAX_WIRE_LIST;
    use skep_shell::{MAX_DRAFT_POSITIONS, MAX_NEW_BYTES, ROWS_CONTEXT_LINES, ROWS_MAX_BYTES, ROWS_MAX_LINE_CHARS, ROWS_MAX_RUN, ROWS_RUN_HEAD, ROWS_RUN_TAIL};
    let catalog = Catalog::load(EMBEDDED).expect("embedded tools.json must validate");
    let entry = |name: &str| catalog.tools.iter().find(|tool| tool["name"] == name).unwrap_or_else(|| panic!("the {name} card"));
    for name in ["replace_text", "edit_text"] {
        let said = reference(&catalog, name);
        assert!(said.contains(&format!("one insert's cap of {MAX_NEW_BYTES} bytes")), "{name}: the reference names the new text's cap: {said}");
        assert!(said.contains(&format!("a draft past {MAX_DRAFT_POSITIONS} content positions")), "{name}: the reference names the draft's cap: {said}");
    }
    let said = reference(&catalog, "replace_text");
    for spelled in [
        "\"replaced\"",
        "\"unchanged\"",
        "\"refused\"",
        "\"partial\"",
        "\"held\"",
        "not_found",
        "not_unique",
        "crosses_atom",
        "published",
        "too_large",
        "unknown_item",
        "arrangement_moved",
        "unread",
        "new_text: {ordinal, width, addr?, at?}",
        "old_text: {ordinal, width}",
    ] {
        assert!(said.contains(spelled), "the reference spells `{spelled}`: {said}");
    }
    let replace = entry("replace_text");
    assert_eq!(replace["inputSchema"]["required"], json!(["doc", "old", "new"]));
    assert_eq!(replace["inputSchema"]["properties"]["old"]["minLength"], 1, "an empty old is refused, and the schema says so");
    let short = card(&catalog, "edit_text");
    for spelled in [
        "edit_text(doc, edits: [{old, new}, …])".to_string(),
        "EXACTLY ONCE in the draft as the pairs before it leave it".to_string(),
        "ALL OR NOTHING".to_string(),
        format!("at most {MAX_WIRE_LIST} pairs"),
        "partial and held are isError".to_string(),
        "read the draft before you edit it again".to_string(),
    ] {
        assert!(short.contains(&spelled), "edit_text's card says `{spelled}`: {short}");
    }
    let said = reference(&catalog, "edit_text");
    for spelled in [
        "\"+N<TAB>line\"".to_string(),
        format!("\" N<TAB>line\" (a space, then N): one of the {ROWS_CONTEXT_LINES} unchanged lines either side"),
        "\"-<TAB>(N bytes removed here)\"".to_string(),
        "\", at the text's end\"".to_string(),
        "\"--\" parts rows whose lines do not touch".to_string(),
        format!("a run of more than {ROWS_MAX_RUN} + rows shows its first {ROWS_RUN_HEAD}, \"+…<TAB>(N more lines)\", its last {ROWS_RUN_TAIL}"),
        format!("a line past {ROWS_MAX_LINE_CHARS} characters ends \"…[+N chars]\""),
        "{hex:…}".to_string(),
        "a value that is no text as {…}".to_string(),
        format!("past {ROWS_MAX_BYTES} bytes the rows end \"(N more changed lines not shown)\""),
        "masked: true".to_string(),
        "stands names each change at its own commit, its new bytes found by addr".to_string(),
    ] {
        assert!(said.contains(&spelled), "edit_text's reference says `{spelled}`: {said}");
    }
    assert!(said.contains("too_large (what: new") && said.contains("or runs, a draft in more runs than one write sets back"), "the reference names the take-back's too_large: {said}");
    assert!(said.contains("replace_text still edits one pair"), "the reference names the one-pair tool: {said}");
    let schema = &entry("edit_text")["inputSchema"];
    assert_eq!(schema["required"], json!(["doc", "edits"]));
    assert_eq!((&schema["properties"]["edits"]["minItems"], &schema["properties"]["edits"]["maxItems"]), (&json!(1), &json!(MAX_WIRE_LIST)), "one pair at least, one wire list at most");
    assert_eq!(schema["properties"]["edits"]["items"]["properties"]["old"]["minLength"], 1, "an empty old is refused, and the schema says so");
    let said = reference(&catalog, "move_lines");
    for spelled in [
        format!("a draft past {MAX_DRAFT_POSITIONS} content positions"),
        "\"+N<TAB>line\"".to_string(),
        format!("\" N<TAB>line\" (a space, then N): one of the {ROWS_CONTEXT_LINES} unchanged lines either side"),
        "\"-<TAB>(lines A–B moved to C–D)\"".to_string(),
        "\"-<TAB>(line A moved to C)\"".to_string(),
        "masked: true".to_string(),
        "which holds one line fewer".to_string(),
        "rearrange itself stays yours for a move that is not whole lines".to_string(),
    ] {
        assert!(said.contains(&spelled), "move_lines' reference says `{spelled}`: {said}");
    }
    let schema = &entry("move_lines")["inputSchema"];
    assert_eq!(schema["required"], json!(["doc", "first"]));
    for line in ["first", "last", "before"] {
        assert_eq!((&schema["properties"][line]["type"], &schema["properties"][line]["minimum"]), (&json!("integer"), &json!(1)), "{line}: a line is a whole number from 1");
    }
    let said = reference(&catalog, "diff_text");
    let pairs = skep_client::text::diff::MAX_PAIRS;
    let kept = skep_client::text::MIN_KEPT_BETWEEN;
    for spelled in [
        format!("a text past {MAX_DRAFT_POSITIONS} content positions"),
        format!("two documents sharing more stretches than {pairs}"),
        "\"@@ -a,b +c,d @@\" heads a hunk".to_string(),
        format!("with the {ROWS_CONTEXT_LINES} unchanged lines either side of its changes"),
        "\" N<TAB>line\" (a space, then N): a line unchanged".to_string(),
        "\"-N<TAB>line\": a line gone, drawn from since and numbered in it".to_string(),
        "\"+N<TAB>line\": a line new".to_string(),
        "\">N<TAB>line\": a line MOVED here, its identity kept".to_string(),
        "\"<<TAB>(lines A–B moved to C–D)\"".to_string(),
        "\"<<TAB>(line A moved to C)\"".to_string(),
        format!("a run of more than {ROWS_MAX_RUN} +, - or > rows shows its first {ROWS_RUN_HEAD}, a row of its own sign such as \"-…<TAB>(N more lines)\", its last {ROWS_RUN_TAIL}"),
        "\"\\ no line break at the end\" follows a last line that has none".to_string(),
        format!("The rows stop after the last whole hunk that fits {ROWS_MAX_BYTES} bytes, next_hunk then naming the hunk to ask next"),
        "\"(N more changed lines not shown)\"".to_string(),
        format!("said for a block of {kept} or more characters that are no whitespace"),
        "{kind: \"moved\", before: [A, B], now: [C, D]}".to_string(),
        "{kind: \"placed_twice\", before, now}".to_string(),
        "{kind: \"retyped\", before, now}".to_string(),
        "{kind: \"moved_within_lines\", bytes}".to_string(),
        "masked: true".to_string(),
        "no_such_hunk".to_string(),
        "since is never read whole".to_string(),
        "words a publication re-minted pair with since, so only real edits show".to_string(),
    ] {
        assert!(said.contains(&spelled), "diff_text's reference says `{spelled}`: {said}");
    }
    let schema = &entry("diff_text")["inputSchema"];
    assert_eq!(schema["required"], json!(["doc", "since"]));
    assert_eq!(schema["properties"]["stat"]["type"], "boolean");
    assert_eq!((&schema["properties"]["hunk"]["type"], &schema["properties"]["hunk"]["minimum"]), (&json!("integer"), &json!(1)), "a hunk is a whole number from 1");
    let said = reference(&catalog, "mark_text");
    for spelled in ["1.1.0.1.0.1.0.3.25", "NO BYTE IS MINTED", "it records no base and no source", "slot_too_large", "mint_home_first", "the link is not sent again"] {
        assert!(said.contains(spelled), "mark_text's reference says `{spelled}`: {said}");
    }
    assert_eq!(skep_client::board::frames::T_MARKS, "1.1.0.1.0.1.0.3.25", "the type the reference names is the client's");
    assert_eq!(entry("mark_text")["inputSchema"]["required"], json!(["doc"]));
    let instructions = catalog.instructions();
    assert!(
        instructions.contains("replace_text (one change)") && instructions.contains("edit_text (several") && instructions.contains("move_lines (lines moved)"),
        "the instructions send an agent to the three tools: {instructions}"
    );
    let editing = topic(&catalog, "EDITING TEXT");
    assert!(
        editing.contains("replace_text(doc, old, new)") && editing.contains("edit_text(doc, edits)") && editing.contains("move_lines(doc, first, last?, before?)"),
        "the topic sends an agent to the three tools: {editing}"
    );
    assert!(
        editing.contains("mark_text(doc) before you change a draft") && editing.contains("diff_text(doc, since) before you hand it on"),
        "the topic names the review step, the mark before the change and the diff after it: {editing}"
    );
    let overview = topic(&catalog, "OVERVIEW");
    assert!(
        overview.contains("replace_text (") && overview.contains("edit_text (") && overview.contains("move_lines (") && overview.contains(": EDITING TEXT)"),
        "the overview names the three among the apparatus: {overview}"
    );
    assert!(overview.contains("mark_text (") && overview.contains("diff_text ("), "the overview names the mark and the diff among the apparatus: {overview}");
    assert!(
        editing.contains("call restore_text(draft, at, as_of): one write, by identity") && overview.contains("restore_text ("),
        "the topic and the overview name the restore among the apparatus: {editing}\n{overview}"
    );
    for (whose, text) in [("EDITING TEXT", editing), ("replace_text's card", card(&catalog, "replace_text")), ("replace_text's reference", reference(&catalog, "replace_text"))] {
        assert!(text.contains("move_lines") && !text.contains("a block moved"), "{whose} sends whole lines moved to move_lines, never to rearrange: {text}");
    }
    assert!(editing.contains("a move that is not whole lines") && reference(&catalog, "replace_text").contains("a move that is not whole lines"), "rearrange stays for a move that is not whole lines");
}

/// `restore_text`'s reference states the shell's answer and the way back.
///
/// It spells the answer the shell declares for the `history.restore` row
/// (`shapes::declarations`, the shape `Restored`) as `{a, b, …}`, and the
/// way back as the call again at the answer's `as_of`, typed at its
/// `position` — a way back typed at `as_of` is refused `not_past`, or
/// writes the restored state over itself; each of the shell's refusals an
/// agent acts on with its members — `not_past` with `current`,
/// `history_reclaimed` with a `floor` that may be null, `not_a_position`
/// with `nearest`, `held_lines {doc, held}` with its act, `not_owner` with
/// `published` — and what a lost answer asks: the same call again, a
/// landed first write refused `arrangement_moved` once the session has
/// ended. Its schema takes `draft` as every document argument is taken,
/// and `at` and `as_of` as whole numbers from 0, all three required
/// (SP-24). A shape the shell changes in one place alone would tell every
/// agent of an answer the shell no longer gives.
#[test]
fn the_restore_reference_states_the_shells_answer_and_the_way_back_typed_at_position() {
    let declarations = skep_shell::shapes::declarations();
    let line = declarations.lines().find(|line| line.starts_with("  'history.restore'(args: ")).expect("skep-shell declares the history.restore row");
    let answer = line.split_once("Promise<Outcome<").and_then(|(_, rest)| rest.strip_suffix(">>;")).unwrap_or_else(|| panic!("the row's answer: {line}"));
    let shape = skep_shell::shapes::shape(answer).unwrap_or_else(|| panic!("skep-shell declares {answer}"));
    assert!(!shape.open && shape.fields.iter().all(|field| field.required), "premise: {answer} is closed, every member required");
    let declared = format!("{{{}}}", shape.fields.iter().map(|field| field.name).collect::<Vec<_>>().join(", "));
    let catalog = Catalog::load(EMBEDDED).expect("embedded tools.json must validate");
    let said = reference(&catalog, "restore_text");
    for (spelled, what) in [
        (format!("Response: {declared}."), "the answer the shell declares"),
        ("The way back is restore_text(draft, at: as_of, as_of: position): the answer's own as_of, typed at its position".to_string(), "the way back, typed at position"),
        ("merge_refused {arm: \"not_past\", draft, at, current}".to_string(), "not_past's members"),
        ("{arm: \"history_reclaimed\", at, floor}".to_string(), "history_reclaimed's members"),
        ("floor the oldest position it still answers, or null where it names none".to_string(), "a floor the board may not name"),
        ("{arm: \"not_a_position\", at, nearest}".to_string(), "not_a_position's members"),
        (
            format!("{} {{doc, held}} where the draft holds lines of yours the board has not kept (HELD BURSTS): call held(), resolve each line on that doc, then call again", skep_shell::Name::HELD_LINES.as_str()),
            "the held-lines gate and its act",
        ),
        ("not_owner {addr, published: true} for a published document".to_string(), "a published document"),
        ("unreachable (isError) may have landed: call again with the same draft, at and as_of".to_string(), "what a lost answer asks"),
        ("After the session has ended, a landed first write is refused arrangement_moved".to_string(), "a landed first write past the session"),
    ] {
        assert!(said.contains(&spelled), "restore_text's reference names {what}, `{spelled}`: {said}");
    }
    let entry = |name: &str| catalog.tools.iter().find(|t| t["name"] == name).unwrap_or_else(|| panic!("the {name} card"));
    let schema = &entry("restore_text")["inputSchema"];
    assert_eq!(schema["required"], json!(["draft", "at", "as_of"]));
    assert_eq!(schema["properties"]["draft"]["pattern"], entry("diff_text")["inputSchema"]["properties"]["doc"]["pattern"], "a draft is an address");
    for position in ["at", "as_of"] {
        assert_eq!((&schema["properties"][position]["type"], &schema["properties"][position]["minimum"]), (&json!("integer"), &json!(0)), "{position}: a position is a whole number from 0");
    }
}

/// The text tools' references state the answers the shell declares.
///
/// They state them bar what the adapter takes off. Each reference —
/// `replace_text`'s of the shell's `text.replace` row,
/// `edit_text`'s of its `text.edit` row, `move_lines`' of its `text.move`
/// row, `mark_text`'s of its `text.mark` row and `diff_text`'s of its
/// `text.diff` row — spells each answer the row
/// declares (`shapes::declarations`) as `{outcome: "…", a, b?, …}`: every
/// member of the shape, `?` where it is optional, a nested value's members
/// in braces beside it, `…` where the shape is open — and no other, save
/// the shell's error member, which the adapter takes off (`EDIT_ERROR`) and
/// no agent sees, and the rows of a landed `text.edit` or `text.move`, and
/// of a `text.diff`, which follow the answer as lines of their own
/// (`EDIT_LINES`, `DIFF_ROWS`); the answers that
/// carry the error member are the `isError` ones, `refused` beside a
/// verdict-less cause and `held`, and an edit's `partial`; a span a
/// reference spells, where its row's answers carry one, is
/// the shell's `TextSpan`; and the reference's `(write: …)` list names each
/// value of its held answer's `write` and no other, a call that holds no
/// line listing none. `edit_text`'s reference
/// spells a change as `TextEditChange`, a change that stands as `TextEditStanding`
/// or `TextEditHalf`, and its schema's pair as `TextEditPair` (SP-24). A
/// shape the shell changes in one place alone would tell every agent of an
/// answer the shell no longer gives, or leave a held line's write unnamed.
#[test]
fn the_text_edit_references_state_the_shells_answers_bar_what_the_adapter_takes_off() {
    /// Returns `text` from its first `{` to the `}` that closes it.
    fn braced(text: &str) -> &str {
        let open = text.find('{').expect("an opening brace");
        let mut depth = 0;
        for (at, c) in text[open..].char_indices() {
            match c {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        return &text[open..=open + at];
                    }
                }
                _ => {}
            }
        }
        panic!("an unclosed brace: {text}")
    }
    /// Returns a braced object's members as a card spells them, each with
    /// whether it is required, and whether it ends `…`.
    fn members(object: &str) -> (BTreeSet<(&str, bool)>, bool) {
        let inner = &object[1..object.len() - 1];
        let (mut pieces, mut depth, mut from) = (Vec::new(), 0, 0);
        for (at, c) in inner.char_indices() {
            match c {
                '{' | '[' => depth += 1,
                '}' | ']' => depth -= 1,
                ',' if depth == 0 => {
                    pieces.push(inner[from..at].trim());
                    from = at + 1;
                }
                _ => {}
            }
        }
        pieces.push(inner[from..].trim());
        let open = pieces.last() == Some(&"…");
        let named = pieces
            .iter()
            .filter(|piece| **piece != "…")
            .map(|piece| piece.split(':').next().unwrap_or(piece).trim())
            .map(|name| name.strip_suffix('?').map_or((name, true), |name| (name, false)))
            .collect();
        (named, open)
    }
    /// Returns a shape's fields as `members` reads a card's, bar `left_out`.
    fn declared<'s>(name: &str, left_out: &[&str]) -> BTreeSet<(&'s str, bool)> {
        let shape = skep_shell::shapes::shape(name).unwrap_or_else(|| panic!("skep-shell declares {name}"));
        shape.fields.iter().filter(|field| !left_out.contains(&field.name)).map(|field| (field.name, field.required)).collect()
    }
    let declarations = skep_shell::shapes::declarations();
    let catalog = Catalog::load(EMBEDDED).expect("embedded tools.json must validate");
    let (edit_error, edit_lines, diff_rows) = (crate::server::EDIT_ERROR, crate::server::EDIT_LINES, crate::server::DIFF_ROWS);
    for (name, row, held, left_out, marked) in [
        ("replace_text", "text.replace", Some("TextHeld"), &[edit_error][..], &["refused", "partial", "held"][..]),
        ("edit_text", "text.edit", Some("TextEditHeld"), &[edit_error, edit_lines][..], &["refused", "partial", "held"][..]),
        ("move_lines", "text.move", Some("TextMoveHeld"), &[edit_error, edit_lines][..], &["refused", "held"][..]),
        ("mark_text", "text.mark", Some("TextMarkHeld"), &[edit_error][..], &["refused", "held", "partial"][..]),
        ("diff_text", "text.diff", None, &[edit_error, diff_rows][..], &["refused"][..]),
    ] {
        let head = format!("  '{row}'(args: ");
        let line = declarations.lines().find(|line| line.starts_with(head.as_str())).unwrap_or_else(|| panic!("skep-shell declares the {row} row"));
        let answers = line.split_once("Promise<Outcome<").and_then(|(_, rest)| rest.strip_suffix(">>;")).unwrap_or_else(|| panic!("the row's answer: {line}"));
        let card = reference(&catalog, name);
        let (mut errors, mut spans) = (BTreeSet::new(), false);
        for answer in answers.split(" | ") {
            let shape = skep_shell::shapes::shape(answer).unwrap_or_else(|| panic!("skep-shell declares {answer}"));
            spans |= shape.fields.iter().any(|field| field.ty.contains("TextSpan") || field.ty.contains("TextEditHalf"));
            let outcome = shape.fields.iter().find(|field| field.name == "outcome").and_then(|field| field.ty.strip_prefix('\'')?.strip_suffix('\'')).unwrap_or_else(|| panic!("{answer} is keyed by its outcome"));
            let head = format!("{{outcome: \"{outcome}\"");
            let at = card.find(&head).unwrap_or_else(|| panic!("{name}: the card spells the {outcome} answer: {card}"));
            assert_eq!(members(braced(&card[at..])), (declared(answer, left_out), shape.open), "{name}: the card spells {answer} as the shell declares it, bar {left_out:?}: {card}");
            if shape.fields.iter().any(|field| field.name == edit_error) {
                errors.insert(outcome);
            }
        }
        assert_eq!(errors, marked.iter().copied().collect::<BTreeSet<&str>>(), "{name}: the answers the shell marks as errors");
        // A reference spells a span only where an answer of its row carries
        // one: a move's answers name no span.
        match card.find("new_text: {").map(|at| members(braced(&card[at..])).0) {
            Some(span) => assert_eq!((spans, span), (true, declared("TextSpan", &[])), "{name}: a span is the shell's TextSpan"),
            None => assert!(!spans, "{name}: the card spells new_text's members"),
        }
        // A call that writes nothing holds no line, and its reference lists
        // no write.
        let Some(held) = held else {
            assert!(!card.contains("(write: "), "{name}: no held answer, no write listed");
            continue;
        };
        let write = skep_shell::shapes::shape(held).and_then(|shape| shape.fields.iter().find(|field| field.name == "write")).unwrap_or_else(|| panic!("skep-shell declares {held}'s write")).ty;
        let writes: BTreeSet<&str> = write.split(" | ").map(|value| value.trim_matches('\'')).collect();
        let listed = card.split_once("(write: ").and_then(|(_, rest)| rest.split_once([')', '—'])).map(|(list, _)| list).unwrap_or_else(|| panic!("{name}: the card lists the writes a held line may be"));
        let spelled: BTreeSet<&str> = listed.split(", ").flat_map(|piece| piece.split(" or ")).map(str::trim).collect();
        assert_eq!(spelled, writes, "{name}: the card names each write a held line may be, as the shell declares them: {listed}");
    }
    let card = catalog.tools.iter().find(|t| t["name"] == "edit_text").expect("the edit_text card");
    let said = reference(&catalog, "edit_text");
    let change = said.find("a change {").map(|at| members(braced(&said[at..])).0).expect("the card spells a change");
    assert_eq!(change, declared("TextEditChange", &[]), "a change is the shell's TextEditChange");
    let stands = said.split_once("stands: [").map(|(_, rest)| rest).expect("the card spells what stands");
    let whole = braced(stands);
    assert_eq!(members(whole).0, declared("TextEditStanding", &[]), "a change that stands whole is the shell's TextEditStanding");
    let in_part = stands[stands.find(whole).expect("the whole change") + whole.len()..].strip_prefix(" or ").map(braced).expect("a change in part beside it");
    assert_eq!(members(in_part).0, declared("TextEditHalf", &[]), "a change in part is the shell's TextEditHalf");
    let pair = &card["inputSchema"]["properties"]["edits"]["items"];
    let named: BTreeSet<(&str, bool)> = pair["properties"]
        .as_object()
        .expect("a pair's properties")
        .keys()
        .map(|key| (key.as_str(), pair["required"].as_array().is_some_and(|required| required.iter().any(|r| r == key))))
        .collect();
    assert_eq!(named, declared("TextEditPair", &[]), "a pair is the shell's TextEditPair");
    assert_eq!(pair["additionalProperties"], false, "a pair's schema is closed");
}

/// The `probe` card names every state the shell's `probe()` answers and its
/// `reason`, read off the shell's own declaration (skep #865), so a state the
/// shell adds is named before an agent meets it.
#[test]
fn the_probe_card_names_the_shells_board_states() {
    let catalog = Catalog::load(EMBEDDED).expect("embedded tools.json must validate");
    let card = reference(&catalog, "probe");
    let fields = skep_shell::shapes::shape("Probe").expect("skep-shell declares Probe").fields;
    let daemon = fields.iter().find(|field| field.name == "daemon").expect("the probe's daemon member").ty;
    for state in daemon.split(" | ").map(|word| word.trim_matches('\'')) {
        assert!(card.contains(state), "the probe card names `{state}`: {card}");
    }
    assert!(fields.iter().any(|field| field.name == "reason" && !field.required) && card.contains("reason?"), "the probe card names the optional `reason`: {card}");
}

/// The `held` reference names `sendable`, an agent's line reading false.
///
/// The reference lists every row member, and an agent reading a moved line's row
/// meets `sendable`: what `resolve` `send` would do, and always false for a
/// burst sent through these tools, which carries no anchors and so never
/// shifts (skep #867). A reference silent on it leaves an agent to guess what the
/// member means, and to send a line it could tell would be held moved again.
#[test]
fn the_held_reference_names_sendable_and_an_agents_line_reading_false() {
    let catalog = Catalog::load(EMBEDDED).expect("embedded tools.json must validate");
    let held = reference(&catalog, "held");
    assert!(
        held.contains("sendable? (on a moved document's first moved line: true where resolve send would shift it into the text as it now stands, false where it would be held moved again, absent where the shell does not know; a burst sent through these tools carries no anchors, so it never shifts and reads false)"),
        "the held reference names sendable: {held}"
    );
    let declared: Vec<&str> = skep_shell::shapes::shape("HeldRow").expect("skep-shell declares a held line").fields.iter().map(|field| field.name).collect();
    assert!(declared.contains(&"sendable"), "`sendable` is a member skep-shell declares for a held line: {declared:?}");
}

/// The `held` reference names `hands`, whose writes moved a document.
///
/// The reference lists every row member, and an agent's `held` is where it learns
/// who moved a document its words wait on: the hands of the move the
/// document stands on now, on each moved line of the document, each key a
/// word skep-shell declares for a hand, `unread` among them where the shell
/// has not read them yet and `unknowable` where no read can (skep #973,
/// #989). A reference silent on them leaves an agent to guess whose change it is
/// placing its words against.
#[test]
fn the_held_reference_names_hands_and_each_key_a_hand_carries() {
    let catalog = Catalog::load(EMBEDDED).expect("embedded tools.json must validate");
    let held = reference(&catalog, "held");
    assert!(
        held.contains("hands? (on each moved line of a moved document: whose writes moved it, each once, for the move the document stands on now — each {key, fingerprint?, label?}"),
        "the held reference names hands: {held}"
    );
    let declarations = skep_shell::shapes::declarations();
    let keys = declarations.lines().find(|line| line.starts_with("export type HandKey")).expect("skep-shell declares a hand's key");
    for key in keys.split('\'').skip(1).step_by(2) {
        assert!(held.contains(&format!("{key} (")), "the held reference names the hand `{key}`: {held}");
    }
    let declared: Vec<&str> = skep_shell::shapes::shape("HeldRow").expect("skep-shell declares a held line").fields.iter().map(|field| field.name).collect();
    assert!(declared.contains(&"hands"), "`hands` is a member skep-shell declares for a held line: {declared:?}");
}

/// The `held` reference names `again` and the hand no read can name.
///
/// An agent's burst carries no anchors, so the board refuses its send again
/// for the change that moved it, and the row then names that change's hands
/// again with `again` beside them; where the board no longer keeps the
/// history, the row names the one hand `unknowable`, which no later list
/// reads (skep #989). A reference silent on `again` leaves an agent to read the
/// same hands as a second change, and one silent on `unknowable` leaves it
/// to list again for hands that never come.
#[test]
fn the_held_reference_names_again_and_the_hand_no_read_can_name() {
    let catalog = Catalog::load(EMBEDDED).expect("embedded tools.json must validate");
    let held = reference(&catalog, "held");
    assert!(
        held.contains("again? (beside hands, true: the board refused the line again with no change since your resolve send, and hands are the changes it named before)"),
        "the held reference names again: {held}"
    );
    assert!(held.contains("or the one hand unknowable (the board no longer keeps the history that would name them, so they can never be read)"), "the held reference names unknowable: {held}");
    let declared = skep_shell::shapes::shape("HeldRow").expect("skep-shell declares a held line").fields;
    assert!(declared.iter().any(|field| field.name == "again" && !field.required), "`again` is an optional member skep-shell declares for a held line: {declared:?}");
}

/// The `held` reference names why a line stands off disk.
///
/// The reference names `unwritable` and `unwritable_class` as skep-shell declares
/// them for a held line, and says what the agent can do with them: a line it
/// lists so is lost if the process ends before the shell writes it (skep
/// #860). A reference silent on them leaves an agent to stop a process holding a
/// write it could have waited for.
#[test]
fn the_held_reference_names_why_a_line_stands_off_disk() {
    let catalog = Catalog::load(EMBEDDED).expect("embedded tools.json must validate");
    let held = reference(&catalog, "held");
    assert!(
        held.contains("unwritable? (the shell could not write this line to disk, and says why: the line stands in memory alone until the shell writes it, trying again on its own, and is lost if the process ends first; absent once it is on disk), unwritable_class? (beside unwritable, always with it: full, read_only or other)"),
        "the held reference names the two members: {held}"
    );
    let declared: Vec<&str> = skep_shell::shapes::shape("HeldRow").expect("skep-shell declares a held line").fields.iter().map(|field| field.name).collect();
    for member in ["unwritable", "unwritable_class"] {
        assert!(declared.contains(&member), "`{member}` is a member skep-shell declares for a held line: {declared:?}");
    }
}

/// The held references name the hand-over and a burst kept in memory alone.
///
/// The `held` reference's causes name the shell's own refused run,
/// `answers_lost`, as skep-shell spells it — why the shell stopped resending
/// and the members of its refusal — a refused run under a code the shell
/// holds no row for, and `head_unreadable`, the write the shell cannot sign
/// while the board's head record will not read, kept on disk and skipped at
/// each probe (skep #725, #727), and `session_died` met at the burst's dial
/// or at the shell's read just after the board refused it
/// `arrangement_moved` (skep #826); the `resolve` reference says what `send` and
/// `drop` do with such a line, that `send` on a moved document records the
/// changes that moved it as seen, so a document moved again names only the
/// changes since (skep #757) and one refused again with no change since names
/// again the changes it named before (skep #989), that `drop` takes a line in
/// any state, a holding one among them — one held on an unreadable head given
/// up for good (skep #726, #983) — while `send` on a holding line and either
/// act on a line the shell is sending are `not_resolvable` (skep #983), and
/// that the drop of a `sent` line, holding or handed back, reads first, keeps
/// a line whose write landed and answers `{"kept": true}`, and is refused
/// `landing_unread` where the read cannot tell (skep #866, #983), and that a
/// drop taking lines that may already be on the board names them in
/// `may_have_landed`, its `Response` naming each member of the answer
/// skep-shell declares for the row (skep #993); HELD BURSTS
/// says a burst answered `unwritable` is lost with the process
/// (skep #733, #700), names the head's hold and the death's, at either of its
/// two points, and says what a drop does; and REJECTIONS ARE DATA names
/// `head_unreadable` among the halts with a garbled answer from the board's
/// head record among its causes (skep #728). A reference that names neither leaves
/// an agent to guess whether a line it holds may have landed, and free to
/// stop a process that holds a write in memory alone; one silent on the moved
/// document's `send` leaves an agent to read a second moved face as the first
/// one again; one silent on the drop of a holding line leaves an agent no way
/// to take back a run of writes the board has not kept, nor to give up one
/// held for a repair that may never come; one that names the death at the
/// dial alone leaves an agent to guess why a burst the board refused stale is
/// held for the next session; one that calls every drop final leaves an
/// agent to write again words the board kept; and one silent on
/// `may_have_landed` leaves an agent to take a discarded line's words for
/// gone and land them twice.
#[test]
fn the_held_references_name_the_shells_hand_over_and_a_burst_kept_in_memory_alone() {
    let catalog = Catalog::load(EMBEDDED).expect("embedded tools.json must validate");
    let lost = skep_shell::Name::ANSWERS_LOST.as_str();
    let unreadable = skep_shell::Name::HEAD_UNREADABLE.as_str();
    let held = reference(&catalog, "held");
    assert!(held.contains(&format!("{lost}: the shell stopped resending: no landing two minutes after the line's first failed send")), "the held reference names the hand-over: {held}");
    assert!(held.contains(&format!("the shell's own for {lost}, {{kind, name, last, elapsed_ms}}")), "the held reference names its refusal's members: {held}");
    assert!(held.contains("a code the shell holds no row for among them, refused at a resend and handed to you at once"), "the held reference names the board's own code handed over: {held}");
    assert!(
        held.contains(&format!("{unreadable} (the board's head record cannot be read — it stands damaged, was served garbled, or a claimed board serves none — so the shell cannot sign the write: held on disk and skipped at each probe until the record reads, or dropped)")),
        "the held reference names the head's hold: {held}"
    );
    let died_at = "at the burst's dial, or at the shell's read just after the board refused it arrangement_moved";
    assert!(
        held.contains(&format!("session_died (this adapter's session ended {died_at} — a board restart among the causes — so the write ran nothing")),
        "the held reference names the death at either point: {held}"
    );
    let resolve = reference(&catalog, "resolve");
    assert!(resolve.contains(&format!("a line that the shell handed back to you ({lost})")), "the resolve reference names the line: {resolve}");
    assert!(resolve.contains("dropped, given up for good") && resolve.contains("is read first and kept where it landed, and otherwise sent again, its two-minute clock started afresh"), "the resolve reference says what each act does: {resolve}");
    let unread = skep_shell::Name::LANDING_UNREAD.as_str();
    assert!(
        resolve.contains(&format!("save a line with sent true, holding or handed back as {lost}, which may have landed after all: its drop reads first, and where its write landed keeps the line, nothing dropped and the lines behind it sent in order, answering {{\"kept\": true}}"))
            && resolve.contains(&format!("where the read cannot tell whether it landed, nothing is dropped and the drop is refused {unread} {{held, why}}"))
            && resolve.contains("a line whose every dial the shell knows never left this device is dropped with no read, whatever its sent says")
            && resolve.ends_with("Response: {}, {\"kept\": true} where a drop kept the line, or {\"may_have_landed\": [<ordinal>, …]} where a drop took lines that may already be on the board."),
        "the resolve reference says a drop of a line that may have landed reads first, may keep it, and names the refusal: {resolve}"
    );
    assert!(
        resolve.contains("A drop that takes lines which may already be on the board — sent true, with no read of the drop's own ruling that out: a refused run's or a moved document's line, or a line behind the one its read found unlanded — answers their ordinals in may_have_landed: they are dropped all the same, and their words may stand, so read the document before writing them again."),
        "the resolve reference says which lines a drop names as perhaps landed: {resolve}"
    );
    // The answer's members, as skep-shell declares the row's result.
    let declarations = skep_shell::shapes::declarations();
    let row = declarations.lines().find(|line| line.starts_with("  resolve(args: ")).expect("skep-shell declares the resolve row");
    let result = row.rsplit_once("Promise<Outcome<{").and_then(|(_, rest)| rest.split_once('}')).map(|(members, _)| members).expect("the row answers an object");
    let members: Vec<&str> = result.split(';').filter_map(|member| member.split(':').next()).map(|name| name.trim().trim_end_matches('?')).filter(|name| !name.is_empty()).collect();
    assert!(!members.is_empty(), "the resolve row answers named members: {row}");
    let response = resolve.rsplit_once("Response: ").map(|(_, response)| response).expect("the resolve reference's Response");
    for member in members {
        assert!(response.contains(&format!("{{\"{member}\": ")), "the resolve reference's Response names `{member}`: {response}");
    }
    assert!(
        resolve.contains("on a moved document, it first records that the changes which moved it have been seen: a document moved again names only the changes since"),
        "the resolve reference says what send records on a moved document: {resolve}"
    );
    assert!(resolve.contains("; one refused again with no change since names again the changes it named before."), "the resolve reference says what a send refused again names: {resolve}");
    let not_resolvable = skep_shell::Name::NOT_RESOLVABLE.as_str();
    assert!(
        resolve.contains(&format!("or one still holding, whatever its cause — {unreadable} among them (the board's head record cannot be read, so the shell cannot sign the write"))
            && resolve.contains(&format!("\"send\" on a line still holding is {not_resolvable}: the shell sends it itself as the board takes it"))
            && resolve.contains(&format!("Either act on a line the shell is sending at that moment is {not_resolvable} until that send ends")),
        "the resolve reference admits the drop on a holding line, the send on none, and neither act on a line being sent: {resolve}"
    );
    let held_bursts = topic(&catalog, "HELD BURSTS");
    assert!(held_bursts.contains("A burst whose held answer carries unwritable — why the shell could not write its line to disk — is kept in memory alone until the shell writes it, and is lost if the process ends first; held() lists it with unwritable beside it until its line is on disk."), "{held_bursts}");
    assert!(
        held_bursts.contains(&format!(
            "\"drop\" discards a line in any state, one still holding among them, and the lines behind it on its document, none of which the shell then sends, save a line with sent true, holding or handed back as {lost}, whose drop reads first: kept where its write landed, nothing discarded and the lines behind it sent (answering {{\"kept\": true}}), and refused {unread} where the read cannot tell, nothing discarded. A drop that discards lines which may already have landed — sent true, refused or moved, or behind the line its read found unlanded — names their ordinals in may_have_landed: discarded all the same, their words perhaps on the board. While the shell is sending a line, either act on it is not_resolvable until that send ends."
        )),
        "HELD BURSTS says what a drop does, the lines it names as perhaps landed, and that no act takes a line being sent: {held_bursts}"
    );
    assert!(
        held_bursts.contains(&format!(
            "its head record unreadable (cause {unreadable}: the shell cannot sign the write until the record reads, keeps the line on disk meanwhile, and skips it at each probe)"
        )),
        "HELD BURSTS names the head's hold: {held_bursts}"
    );
    assert!(held_bursts.contains(&format!("the end of this adapter's session {died_at} (cause session_died: the write ran nothing")), "HELD BURSTS names the death at either point: {held_bursts}");
    let rejections = topic(&catalog, "REJECTIONS ARE DATA");
    assert!(
        rejections.contains(&format!("{unreadable} where the board's head record (H.1), which the attest of a write it signs names, stands and cannot be read — a garbled answer from the board's head record among its causes — or a claimed board serves none")),
        "REJECTIONS ARE DATA names the head's halt and its garbled cause: {rejections}"
    );
}
