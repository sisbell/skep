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
    ] {
        assert!(err.contains(names), "the refusal names {names}: {err}");
    }
}

/// One fault at a time, the first found speaking.
///
/// A catalog with an unknown root field, a malformed entry, a missing op and
/// a `from_` on an op the dispatch does not rename is refused for the root
/// field; without it, for the entry; without both, for the op; and with the
/// op back, for the `from_`.
#[test]
fn the_first_fault_found_speaks() {
    let mut v: Value = serde_json::from_str(EMBEDDED).expect("embedded parses");
    let insert = v["tools"].as_array().expect("tools").iter().find(|t| t["name"] == "insert").cloned().expect("the insert entry");
    v["version"] = json!(1);
    v["tools"][0]["title"] = json!("Title");
    v["tools"].as_array_mut().expect("tools").retain(|t| t["name"] != "insert");
    let delete = v["tools"].as_array_mut().expect("tools").iter_mut().find(|t| t["name"] == "delete").expect("the delete entry");
    delete["inputSchema"]["properties"]["from_"] = json!({"type": "string"});
    let err = Catalog::load(&v.to_string()).expect_err("four faults");
    assert!(err.contains("'version'"), "the root speaks first: {err}");
    v.as_object_mut().expect("root").remove("version");
    let err = Catalog::load(&v.to_string()).expect_err("three faults");
    assert!(err.starts_with("tools[0]: ") && err.contains("'title'"), "then the entry: {err}");
    v["tools"][0].as_object_mut().expect("entry").remove("title");
    let err = Catalog::load(&v.to_string()).expect_err("two faults");
    assert!(err.contains("'insert'"), "then the op: {err}");
    v["tools"].as_array_mut().expect("tools").push(insert);
    let err = Catalog::load(&v.to_string()).expect_err("one fault");
    assert!(err.contains("'delete'") && err.contains("'from_'"), "then the from_: {err}");
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

/// The dispatch has two kinds of tool, and is counted.
///
/// Forty-eight wire ops — every op of wire.md §Operations but `publish`, the
/// six the first catalog lacked among them, the count by home and the
/// retracted-links read — and fourteen adapter tools, the `publication`
/// family's four among them; no name twice across the two, each wire op a
/// `Tool::Op` of its own name with no members list, each adapter tool its
/// row's members; and a ceremony, `upload`, `restore`, `op`, `publish` or a
/// row's dotted name no tool at all.
#[test]
fn the_dispatch_has_two_kinds_and_is_counted() {
    let names: Vec<&str> = Tool::names().collect();
    let set: std::collections::BTreeSet<_> = names.iter().collect();
    assert_eq!(set.len(), names.len(), "no name twice");
    assert_eq!(DISPATCH_OPS.len(), 48);
    assert_eq!(names.len(), 62);
    for added in ["effective_owner", "key_set", "retrieve_i", "content_frontier", "edition_claims", "universal_grants", "count_v_by_home", "find_links_v_history"] {
        assert_eq!(Tool::named(added), Some(Tool::Op(added)), "{added} is a wire op of the dispatch");
    }
    assert_eq!(Tool::named("insert").and_then(Tool::members), None, "a wire op's arguments pass through unread");
    assert_eq!(Tool::named("search").and_then(Tool::members), Some(&["query", "opts"][..]));
    assert_eq!(Tool::named("session_info").and_then(Tool::members), Some(&[][..]));
    assert_eq!(Tool::named("fetch"), Some(Tool::Fetch));
    assert_eq!(Tool::named("publication_open").and_then(Tool::members), Some(&["draft", "also", "base", "doc", "mint", "claim", "selection", "notes", "readable_drafts", "published"][..]));
    assert_eq!(Tool::named("publication_cancel").and_then(Tool::members), Some(&[][..]));
    for not_a_tool in ["keygen", "fingerprint", "claim", "enroll", "bind", "recover", "rotate", "retire", "handoff", "accept", "upload", "restore", "op", "session", "close", "frobnicate"] {
        assert_eq!(Tool::named(not_a_tool), None, "{not_a_tool} is no tool");
    }
    for not_a_tool in ["publish", "publication.open"] {
        assert_eq!(Tool::named(not_a_tool), None, "{not_a_tool} is no tool: the shell runs a publication as its call family");
    }
}

/// The dispatch's door admits a call or refuses it, naming the culprit.
///
/// A name it answers is admitted, a wire op's arguments unread save the one
/// shape skep-shell's `op` row reads as its `/op-at` form, a numeric `at`
/// beside an object `frame`, which alone is refused; a name it does not
/// answer is refused before its arguments are read; a member an adapter
/// tool's row does not take is refused naming the row's own, and a member of
/// its `opts` naming the options — `search`'s withheld `reindex` among them —
/// the row's stranger speaking first.
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

/// The embedded catalog states the adapter's own facts as the code holds them.
///
/// Its schemas spell `from_` on exactly the ops `wire_frame` maps back, and
/// its naming note names each of them; its `fetch` card and fetch paragraph
/// name the cap `media` enforces, and the card the fetch's deadline in words;
/// the `search` card and its query's schema name skep-client's query bound,
/// and `changes_since`'s limit the change feed's default page: a fact changed
/// in one place alone tells every agent what the adapter then does otherwise.
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
    let card = entry("fetch")["description"].as_str().expect("the fetch card");
    assert!(card.contains(&format!("cap of {mib} MiB ({cap} bytes)")), "the fetch card names the cap: {card}");
    assert!(catalog.instructions().contains(&format!("cap of {mib} MiB")), "the fetch paragraph names the cap");
    assert_eq!(crate::media::FETCH_DEADLINE, std::time::Duration::from_secs(10 * 60 + 30), "the deadline the fetch card names in words");
    assert!(card.contains("still unfinished at ten and a half minutes"), "the fetch card names the deadline: {card}");
    let search = entry("search");
    assert!(search["description"].as_str().is_some_and(|d| d.contains(&format!("A query past {QUERY_BOUND} bytes is refused query_too_long"))), "the search card names the query's bound: {search}");
    let query = search["inputSchema"]["properties"]["query"]["description"].as_str().expect("the query's description");
    assert!(query.contains(&format!("at most {QUERY_BOUND} bytes")), "the query's schema names its bound: {query}");
    let limit = entry("changes_since")["inputSchema"]["properties"]["limit"]["description"].as_str().expect("the limit's description");
    assert!(limit.contains(&format!("the board's default, {DEFAULT_CHANGES_LIMIT}, when absent")), "the limit names the default page: {limit}");
}

/// A catalog's drift from another counts what an agent is told otherwise.
///
/// A catalog read from the same text drifts nowhere; an entry described
/// otherwise is counted among the catalog's tools; instructions read
/// otherwise — or a commons template — are said, with the entries beside them
/// where any differ.
#[test]
fn a_catalogs_drift_from_another_counts_what_an_agent_is_told_otherwise() {
    let embedded = Catalog::load(EMBEDDED).expect("embedded tools.json must validate");
    let tools = embedded.tools.len();
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
}

/// Every paragraph the catalog sends an agent to opens its instructions.
///
/// A tool's description, or the instructions themselves, name a paragraph by
/// its heading in capitals, in parentheses — `(HELD BURSTS)` or
/// `(FETCH below)` — and every heading so named opens one paragraph of the
/// instructions: a heading renamed in one place alone sends an agent to a
/// paragraph that is not there.
#[test]
fn every_paragraph_the_catalog_names_opens_its_instructions() {
    /// Returns whether `text` is a heading.
    ///
    /// A heading is capitals and spaces, with a capital at each end.
    fn is_heading(text: &str) -> bool {
        text.len() > 1 && text.starts_with(|c: char| c.is_ascii_uppercase()) && text.ends_with(|c: char| c.is_ascii_uppercase()) && text.chars().all(|c| c.is_ascii_uppercase() || c == ' ')
    }
    let catalog = Catalog::load(EMBEDDED).expect("embedded tools.json must validate");
    let headings: BTreeSet<&str> = catalog.instructions().split("\n\n").filter_map(|paragraph| paragraph.split_once(". ")).map(|(head, _)| head).filter(|head| is_heading(head)).collect();
    let texts = std::iter::once(("the instructions", catalog.instructions())).chain(catalog.tools.iter().filter_map(|t| Some((t["name"].as_str()?, t["description"].as_str()?))));
    let mut named = 0;
    for (whose, text) in texts {
        for (inner, _) in text.split('(').skip(1).filter_map(|rest| rest.split_once(')')) {
            let heading = inner.strip_suffix(" below").unwrap_or(inner);
            if is_heading(heading) {
                assert!(headings.contains(heading), "{whose} names the paragraph {heading}, which no paragraph opens: {headings:?}");
                named += 1;
            }
        }
    }
    assert!(named > 0, "premise: the catalog names a paragraph");
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
/// members of its row's session form, the first, save `session` and `board`,
/// which the adapter supplies or does not offer, and requires exactly the
/// ones the row requires. Unchecked, a member the shell renamed or dropped
/// would stay admitted here and advertised to every agent, while the shell,
/// which reads no member it does not name, answered the call as though the
/// member had never been sent.
#[test]
fn each_adapter_tool_takes_its_shell_rows_members_bar_the_session_and_board() {
    let declarations = skep_shell::shapes::declarations();
    let catalog = Catalog::load(EMBEDDED).expect("embedded tools.json must validate");
    for (name, tool, members) in ADAPTER_TOOLS {
        // The row `Server::call` sends the tool as; `session_info` takes no
        // argument, and copies no row.
        let row = match tool {
            Tool::SessionInfo => continue,
            Tool::ChangesSince => "changes",
            Tool::PublicationOpen => "publication.open",
            Tool::PublicationCount => "publication.count",
            Tool::PublicationConfirm => "publication.confirm",
            Tool::PublicationCancel => "publication.cancel",
            _ => *name,
        };
        // The declarations quote a dotted row's name, a method of the
        // `Bridge` interface.
        let method = if row.contains('.') { format!("'{row}'") } else { row.to_string() };
        let head = format!("  {method}(args: {{");
        let form = declarations
            .lines()
            .find_map(|line| line.strip_prefix(head.as_str()))
            .and_then(|rest| rest.split_once('}'))
            .map(|(form, _)| form)
            .unwrap_or_else(|| panic!("skep-shell declares the row {row}"));
        let (mut declared, mut required) = (BTreeSet::new(), BTreeSet::new());
        for member in form.split(';').filter_map(|member| member.split(':').next()).map(str::trim).filter(|member| !member.is_empty()) {
            let (member, optional) = member.strip_suffix('?').map_or((member, false), |member| (member, true));
            if member != "session" && member != "board" {
                declared.insert(member);
                if !optional {
                    required.insert(member);
                }
            }
        }
        assert_eq!(members.iter().copied().collect::<BTreeSet<&str>>(), declared, "{name}: the door takes the {row} row's members");
        let entry = catalog.tools.iter().find(|t| t["name"] == *name).expect("every adapter tool is catalogued");
        let schema_required: BTreeSet<&str> = entry["inputSchema"]["required"].as_array().map(|r| r.iter().filter_map(Value::as_str).collect()).unwrap_or_default();
        assert_eq!(schema_required, required, "{name}: the schema requires what the {row} row requires");
    }
}

/// The publication cards state the shell's declared shapes.
///
/// Each `publication` tool's card spells every arm of the answer the shell
/// declares for its row (`shapes::declarations`) — a shape as `{a, b, c?}`, a
/// field typed by one string literal with its value and an open shape ending
/// `, …`, the empty answer as `{}` — and the open and count cards the shapes
/// of the panel's members; the selection's runs, the switches, a destination
/// and an answer are schema'd as the shell's `Run`, `Switches`, `Destination`
/// and `OriginAnswer` spell them (SP-24). A shape the shell changes in one
/// place alone would tell every agent of an answer the shell no longer gives,
/// or ask an argument it no longer takes.
#[test]
fn the_publication_cards_state_the_shells_shapes() {
    /// Returns a shape's fields as a card spells them.
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
    /// Returns an inline object type's member names, `b?` for an optional `b`.
    fn members(object: &str) -> Vec<&str> {
        object.trim_matches(|c| c == '{' || c == '}').split(';').filter_map(|member| member.split(':').next()).map(str::trim).filter(|member| !member.is_empty()).collect()
    }
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
    let alias = |name: &str| -> Vec<String> {
        let head = format!("export type {name} = ");
        let line = declarations.lines().find_map(|line| line.strip_prefix(head.as_str())).unwrap_or_else(|| panic!("skep-shell declares {name}"));
        line.trim_end_matches(';').split('|').map(|arm| arm.trim().to_string()).collect()
    };
    let catalog = Catalog::load(EMBEDDED).expect("embedded tools.json must validate");
    let entry = |name: &str| catalog.tools.iter().find(|t| t["name"] == name).unwrap_or_else(|| panic!("the {name} card"));
    for (name, row, nested) in [
        ("publication_open", "publication.open", &["PublicationRow", "Formatting", "Count", "Price", "Window", "Hold"][..]),
        ("publication_count", "publication.count", &["Count"][..]),
        ("publication_confirm", "publication.confirm", &[][..]),
        ("publication_cancel", "publication.cancel", &[][..]),
    ] {
        let head = format!("  '{row}'(args: ");
        let line = declarations.lines().find(|line| line.starts_with(head.as_str())).unwrap_or_else(|| panic!("skep-shell declares the row {row}"));
        let answer = line.split_once("Promise<Outcome<").and_then(|(_, rest)| rest.strip_suffix(">>;")).unwrap_or_else(|| panic!("the {row} row's answer: {line}"));
        let card = entry(name)["description"].as_str().expect("a card's description");
        for arm in answer.split(" | ").map(str::trim) {
            let said = match arm {
                "Empty" => "{}".to_string(),
                inline if inline.starts_with('{') => format!("{{{}}}", members(inline).join(", ")),
                shape => spelled(shape),
            };
            assert!(card.contains(&said), "the {name} card spells the {row} row's answer {said}: {card}");
        }
        for shape in nested {
            let said = spelled(shape);
            assert!(card.contains(&said), "the {name} card spells {shape} as {said}: {card}");
        }
    }
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
