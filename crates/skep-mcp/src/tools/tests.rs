use std::collections::BTreeSet;

use serde_json::json;

use super::*;

/// The shipped catalog: every wire op and every adapter tool, every entry
/// named, described, and schema'd — `Catalog::load` enforces both no-drift
/// directions, so a clean load IS the no-drift assertion for the embedded
/// file — and every entry kept as the file spells it.
#[test]
fn embedded_catalog_matches_dispatch() {
    let catalog = Catalog::load(EMBEDDED).expect("embedded tools.json must validate");
    assert_eq!(catalog.tools.len(), Tool::names().count());
    assert!(!catalog.instructions.is_empty());
    let file: Value = serde_json::from_str(EMBEDDED).expect("embedded parses");
    assert_eq!(Some(&catalog.tools), file["tools"].as_array(), "entries kept verbatim");
}

/// Direction one: a file entry the dispatch doesn't know refuses to load,
/// naming the tool — a ceremony's name among them, which no kind answers.
#[test]
fn unknown_tool_refuses() {
    for stranger in ["frobnicate", "keygen", "claim", "retire", "upload", "restore", "op", "session", "close"] {
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
    for missing in ["insert", "publish", "search", "changes_since", "fetch", "session_info"] {
        let mut v: Value = serde_json::from_str(EMBEDDED).expect("embedded parses");
        v["tools"].as_array_mut().expect("tools").retain(|t| t["name"] != missing);
        let err = Catalog::load(&v.to_string()).expect_err("must refuse");
        assert!(err.contains(missing), "error must name the tool: {err}");
    }
}

/// Every fault `load` refuses that would otherwise load — a catalog served
/// verbatim to harnesses that may reject a malformed tool list wholesale —
/// refuses, naming what is wrong.
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
    for (err, names) in [
        (refusal(|v| v["version"] = json!(1)), "'version'"),
        (refusal(|v| v["instructions"] = json!("")), "'instructions'"),
        (refusal(|v| tool(v, "insert")["title"] = json!("Insert")), "'title'"),
        (refusal(|v| tool(v, "insert")["description"] = json!("")), "'description'"),
        (refusal(|v| tool(v, "insert")["inputSchema"] = json!("object")), "'inputSchema'"),
        (
            refusal(|v| {
                let twin = tool(v, "insert").clone();
                v["tools"].as_array_mut().expect("tools").push(twin)
            }),
            "duplicate tool 'insert'",
        ),
        (refusal(|v| without(v, "session_info")), "'session_info'"),
    ] {
        assert!(err.contains(names), "the refusal names {names}: {err}");
    }
}

/// One fault at a time, the first found speaking: a catalog with an
/// unknown root field, a malformed entry and a missing op is refused for
/// the root field; without it, for the entry; without both, for the op.
#[test]
fn the_first_fault_found_speaks() {
    let mut v: Value = serde_json::from_str(EMBEDDED).expect("embedded parses");
    v["version"] = json!(1);
    v["tools"][0]["title"] = json!("Title");
    v["tools"].as_array_mut().expect("tools").retain(|t| t["name"] != "insert");
    let err = Catalog::load(&v.to_string()).expect_err("three faults");
    assert!(err.contains("'version'"), "the root speaks first: {err}");
    v.as_object_mut().expect("root").remove("version");
    let err = Catalog::load(&v.to_string()).expect_err("two faults");
    assert!(err.starts_with("tools[0]: ") && err.contains("'title'"), "then the entry: {err}");
    v["tools"][0].as_object_mut().expect("entry").remove("title");
    let err = Catalog::load(&v.to_string()).expect_err("one fault");
    assert!(err.contains("'insert'"), "then the op: {err}");
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
    let mut catalog = Catalog { instructions: "Base.".to_string(), commons_instructions: "Commons at {addr}; defines is {addr}.0.3.50.".to_string(), tools: Vec::new() };
    catalog.append_commons("1.0.2.0.9");
    assert_eq!(catalog.instructions, "Base.\n\nCommons at 1.0.2.0.9; defines is 1.0.2.0.9.0.3.50.");
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
    for op in ["make_link", "emit"] {
        assert_eq!(frame(op, json!({"from_": "1.1", "to": [{"from_": "x"}]})), json!({"op": op, "from": "1.1", "to": [{"from_": "x"}]}), "{op} renames its top-level from_");
        assert_eq!(frame(op, json!({"from": "1.1", "from_": "2.2"})), json!({"op": op, "from": "1.1", "from_": "2.2"}), "{op}: both spellings ride — the collision is the daemon's to refuse");
    }
    assert_eq!(frame("insert", json!({"from_": "1.1", "op": "delete"})), json!({"op": "insert", "from_": "1.1"}));
}

/// The dispatch's two kinds: forty-seven wire ops — every op of wire.md
/// §Operations, the seven the first catalog lacked among them — and ten
/// adapter tools, no name twice across the two, each wire op a `Tool::Op`
/// of its own name with no members list, each adapter tool its row's
/// members, and a ceremony, `upload`, `restore` or `op` no tool at all.
#[test]
fn the_dispatch_has_two_kinds_and_is_counted() {
    let names: Vec<&str> = Tool::names().collect();
    let set: std::collections::BTreeSet<_> = names.iter().collect();
    assert_eq!(set.len(), names.len(), "no name twice");
    assert_eq!(DISPATCH_OPS.len(), 47);
    assert_eq!(names.len(), 57);
    for added in ["publish", "effective_owner", "key_set", "retrieve_i", "content_frontier", "edition_claims", "universal_grants"] {
        assert_eq!(Tool::named(added), Some(Tool::Op(added)), "{added} is a wire op of the dispatch");
    }
    assert_eq!(Tool::named("insert").and_then(Tool::members), None, "a wire op's arguments pass through unread");
    assert_eq!(Tool::named("search").and_then(Tool::members), Some(&["query", "opts"][..]));
    assert_eq!(Tool::named("session_info").and_then(Tool::members), Some(&[][..]));
    assert_eq!(Tool::named("fetch"), Some(Tool::Fetch));
    for not_a_tool in ["keygen", "fingerprint", "claim", "enroll", "bind", "recover", "rotate", "retire", "handoff", "accept", "upload", "restore", "op", "session", "close", "frobnicate"] {
        assert_eq!(Tool::named(not_a_tool), None, "{not_a_tool} is no tool");
    }
}

/// The dispatch's door admits a call or refuses it, naming the culprit.
///
/// A name it answers is admitted, a wire op's arguments unread; a name it
/// does not answer is refused before its arguments are read, and a member
/// an adapter tool's row does not take is refused naming the row's own.
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
    let err = Tool::admit("changes_since", &args(json!({"since": 0, "under": "1"}))).expect_err("a stranger");
    assert!(err.contains("'since', 'limit'") && err.contains("'under'"), "{err}");
}

/// Every adapter tool's schema names exactly the members its row takes.
///
/// The schema is what the agent is told to send and `Tool::admit` refuses
/// -32602 what the row lacks: a schema member the row lacks is a documented
/// argument refused at every call, a row member the schema lacks one no
/// agent is told of. Each schema is closed too.
#[test]
fn each_adapter_tools_schema_names_exactly_the_members_its_row_takes() {
    let catalog = Catalog::load(EMBEDDED).expect("embedded tools.json must validate");
    for (name, _, members) in ADAPTER_TOOLS {
        let entry = catalog.tools.iter().find(|t| t["name"] == *name).expect("every adapter tool is catalogued");
        let schema = &entry["inputSchema"];
        let named: BTreeSet<&str> = schema["properties"].as_object().expect("a schema's properties").keys().map(String::as_str).collect();
        assert_eq!(named, members.iter().copied().collect::<BTreeSet<&str>>(), "{name}: the schema's members are the row's");
        assert_eq!(schema["additionalProperties"], false, "{name}: the schema is closed");
    }
}
