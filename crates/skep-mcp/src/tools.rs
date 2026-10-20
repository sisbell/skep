//! The tool catalog: names, descriptions, input schemas, the server
//! `instructions` string, and the `SKEP_COMMONS` sentence template
//! (`commons_instructions`, `{addr}` placeholder) — data, not code. The
//! shipped `tools.json` is embedded at build time and overridable with
//! `--tools-file`. Loading cross-checks the catalog against the dispatch in
//! BOTH directions, so the file and the code cannot drift silently: a file
//! entry the dispatch doesn't know refuses startup, and a dispatch tool the
//! file doesn't name refuses startup. The dispatch has TWO KINDS of tool
//! ([`Tool`]): the WIRE OPS, each spelled as the wire spells it, whose
//! arguments are the frame and which the adapter sends as `op(session,
//! frame)` through the shell; and the ADAPTER's OWN — the shell's calls
//! (`boards`, `health`, `probe`, `search`, `places`, `held`, `resolve`) and
//! the apparatus (`session_info`, `changes_since`, `fetch`) — whose
//! arguments are the bridge's row minus the session and the board the
//! adapter supplies, and whose members the adapter reads by name.
//! `wire_frame` maps a wire op's call onto its frame, and
//! `Catalog::append_commons` fills the commons template in beside the check
//! on its placeholder.

use serde_json::{Map, Value};

/// The shipped catalog (`tools.json` beside `Cargo.toml`).
pub const EMBEDDED: &str = include_str!("../tools.json");

/// The wire operations this adapter maps — every op of wire.md
/// §Operations, each spelled exactly as the wire spells it, since the tool
/// name IS the frame's `op`. No general `op` tool ships: every op has a
/// name here.
const DISPATCH_OPS: &[&str] = &[
    // Namespace.
    "create_new_document",
    "delegate",
    "register_node",
    "fork",
    "next_account_prefix",
    "principal_prefix",
    "effective_owner",
    "doc_metadata",
    // Identity reads.
    "key_set",
    // Arrangement.
    "insert",
    "delete",
    "copy",
    "reinstate",
    "rearrange",
    "version",
    "publish",
    // Links (writes).
    "make_link",
    "emit",
    "nullify",
    "assert_sup",
    "edit_link",
    // Links (raw reads).
    "read_link",
    "follow_link",
    // Content & provenance reads.
    "retrieve_v",
    "retrieve_i",
    "content_frontier",
    "retrieve_doc_v_span",
    "retrieve_doc_v_span_set",
    "show_origin",
    "show_deletions",
    "compare",
    "find_docs_containing",
    // Link discovery reads.
    "image",
    "find_links_v",
    "find_links_ftt",
    "count_v",
    "count_ftt",
    "window_v",
    "window_ftt",
    "retrieve_endsets",
    "project",
    "discoverable_from",
    "delete_orphans",
    "in_claims",
    "out_claims",
    "edition_claims",
    // Grants.
    "universal_grants",
];

/// One tool the dispatch answers: a wire op by its name, or one of the
/// adapter's own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tool {
    /// A wire op: its arguments the frame, sent as `op(session, frame)`.
    Op(&'static str),
    /// `boards()`, the shell's.
    Boards,
    /// `health(board)`, the shell's: the board supplied.
    Health,
    /// `probe()`, the shell's.
    Probe,
    /// `search(session, board, query, opts?)`, the shell's: the session and
    /// the board supplied.
    Search,
    /// `places(session, board, opts?)`, the shell's: the session and the
    /// board supplied.
    Places,
    /// `held(session)`, the shell's: the session supplied.
    Held,
    /// `resolve(session, held, act)`, the shell's: the session supplied.
    Resolve,
    /// The apparatus: this adapter's standing.
    SessionInfo,
    /// `changes(session, since, limit?)`, the shell's, as a pull tool.
    ChangesSince,
    /// `fetch(session, i)`, the shell's streamed call, as a content block.
    Fetch,
}

/// The adapter's own tools: each name, its tool, and the argument members
/// its row takes — the ones the adapter reads; a member outside them is
/// refused before any call.
const ADAPTER_TOOLS: &[(&str, Tool, &[&str])] = &[
    ("boards", Tool::Boards, &[]),
    ("health", Tool::Health, &[]),
    ("probe", Tool::Probe, &[]),
    ("search", Tool::Search, &["query", "opts"]),
    ("places", Tool::Places, &["opts"]),
    ("held", Tool::Held, &[]),
    ("resolve", Tool::Resolve, &["held", "act"]),
    ("session_info", Tool::SessionInfo, &[]),
    ("changes_since", Tool::ChangesSince, &["since", "limit"]),
    ("fetch", Tool::Fetch, &["i"]),
];

impl Tool {
    /// The tool the dispatch answers `name` by, where it answers one.
    pub fn named(name: &str) -> Option<Tool> {
        if let Some(op) = DISPATCH_OPS.iter().find(|op| **op == name) {
            return Some(Tool::Op(op));
        }
        ADAPTER_TOOLS.iter().find(|(n, _, _)| *n == name).map(|(_, tool, _)| *tool)
    }

    /// Every name the dispatch answers, the wire ops first, then the
    /// adapter's own in their table's order.
    fn names() -> impl Iterator<Item = &'static str> {
        DISPATCH_OPS.iter().copied().chain(ADAPTER_TOOLS.iter().map(|(name, _, _)| *name))
    }

    /// The argument members an adapter tool's row takes — the only ones the
    /// adapter reads, so any other is refused by name — or `None` for a wire
    /// op, whose arguments pass through unread as the frame.
    pub fn members(self) -> Option<&'static [&'static str]> {
        match self {
            Tool::Op(_) => None,
            other => ADAPTER_TOOLS.iter().find(|(_, tool, _)| *tool == other).map(|(_, _, members)| *members),
        }
    }
}

/// The ops whose wire `from` argument rides as `from_` in the tool schema
/// (harnesses that turn schemas into function parameters cannot always take
/// `from`); `wire_frame` renames it back — unless the arguments already
/// carry the wire's own `from`, when both ride and the daemon's
/// unknown-field refusal answers: the collision is the strict parse's to
/// refuse, never the relay's to resolve. Only top-level argument names are
/// affected — a `from` nested inside an object value is wire shape,
/// untouched.
const RENAMES_FROM: &[&str] = &["make_link", "emit"];

/// A wire op's frame — the crate's first rule, in one place: the name IS
/// the frame's `op`, the arguments ARE the frame, and on the `RENAMES_FROM`
/// ops a top-level `from_` rides back as `from` where no `from` is already
/// there.
pub fn wire_frame(op: &str, mut args: Map<String, Value>) -> Value {
    if RENAMES_FROM.contains(&op) && !args.contains_key("from") {
        if let Some(v) = args.remove("from_") {
            args.insert("from".to_string(), v);
        }
    }
    args.insert("op".to_string(), Value::String(op.to_string()));
    Value::Object(args)
}

/// The substitution point in `commons_instructions`: `Catalog::load`
/// refuses a template without one, and `Catalog::append_commons` replaces
/// every one.
const ADDR_PLACEHOLDER: &str = "{addr}";

/// The loaded catalog: the server instructions, the commons sentence
/// template, and the tool definitions `tools/list` answers. Its invariant,
/// established by `Catalog::load`: `instructions` is nonempty;
/// `commons_instructions` holds `{addr}`; `tools` is one `check_tool`-valid
/// entry per name of [`Tool::names`] — every wire op and every adapter tool
/// — no name twice, in file order; so every tool `tools/list` names is one
/// `Server::call` runs, and every tool it runs is listed. The fields are
/// private, so outside this module `load` is the one way to build one, and
/// `append_commons`, the one mutation, only appends to `instructions`.
#[derive(Debug)]
pub struct Catalog {
    instructions: String,
    /// The sentence `append_commons` adds to `instructions` when
    /// `SKEP_COMMONS` names the commons; `{addr}` is the substitution point.
    commons_instructions: String,
    /// The catalog's tool definitions in file order, each checked by
    /// `check_tool` and kept as the file spells it: exactly the `tools`
    /// array `tools/list` answers.
    tools: Vec<Value>,
}

impl Catalog {
    /// Parses and validates one catalog, establishing `Catalog`'s invariant
    /// — the no-drift contract, in both directions and over both kinds.
    ///
    /// # Errors
    ///
    /// Every fault is a startup error naming what is wrong — the field, the
    /// entry's index, the tool or the op — one fault at a time, the first
    /// found speaking: the root and its fields, `instructions`,
    /// `commons_instructions`, then each entry by index, then each name in
    /// file order (a duplicate, or one the dispatch doesn't know), then each
    /// dispatch tool the file doesn't name.
    pub fn load(text: &str) -> Result<Catalog, String> {
        let v: Value = serde_json::from_str(text).map_err(|e| format!("not JSON: {e}"))?;
        let Value::Object(mut root) = v else {
            return Err("root must be a JSON object".into());
        };
        for k in root.keys() {
            if k != "instructions" && k != "commons_instructions" && k != "tools" {
                return Err(format!("unknown root field '{k}'"));
            }
        }
        let instructions = root.get("instructions").and_then(Value::as_str).ok_or("missing string field 'instructions'")?.to_string();
        if instructions.is_empty() {
            return Err("'instructions' must be nonempty".into());
        }
        let commons_instructions = root.get("commons_instructions").and_then(Value::as_str).ok_or("missing string field 'commons_instructions'")?.to_string();
        if !commons_instructions.contains(ADDR_PLACEHOLDER) {
            return Err(format!("'commons_instructions' must contain the '{ADDR_PLACEHOLDER}' placeholder"));
        }
        let Some(Value::Array(tools)) = root.remove("tools") else {
            return Err("missing array field 'tools'".into());
        };
        let mut names = Vec::with_capacity(tools.len());
        for (i, t) in tools.iter().enumerate() {
            names.push(check_tool(t).map_err(|e| format!("tools[{i}]: {e}"))?);
        }
        let mut seen = std::collections::BTreeSet::new();
        for name in names {
            if !seen.insert(name) {
                return Err(format!("duplicate tool '{name}'"));
            }
            if Tool::named(name).is_none() {
                return Err(format!("tool '{name}' names neither a wire op the dispatch knows nor an adapter tool"));
            }
        }
        for name in Tool::names() {
            if !seen.contains(name) {
                return Err(format!("dispatch tool '{name}' has no tools-file entry"));
            }
        }
        Ok(Catalog { instructions, commons_instructions, tools })
    }

    /// The server instructions `initialize` answers, the commons sentence
    /// appended when `SKEP_COMMONS` is set.
    pub fn instructions(&self) -> &str {
        &self.instructions
    }

    /// The tool definitions `tools/list` answers: exactly the entries
    /// `Catalog::load` checked, in file order.
    pub fn tools(&self) -> &[Value] {
        &self.tools
    }

    /// Point the instructions at the commons: the commons template with
    /// every `{addr}` replaced by `addr`, appended after a blank line.
    /// `addr` goes in as given: that it is T4-valid is the caller's to have
    /// checked — `main`'s `SKEP_COMMONS` gate — and it is checked nowhere
    /// here.
    pub fn append_commons(&mut self, addr: &str) {
        let sentence = self.commons_instructions.replace(ADDR_PLACEHOLDER, addr);
        self.instructions.push_str("\n\n");
        self.instructions.push_str(&sentence);
    }
}

/// Check one catalog entry — an MCP tool definition: a nonempty string
/// `name` and `description`, an object `inputSchema`, and no other field —
/// and answer its name. A definition's fields are named here and nowhere
/// else in the adapter.
fn check_tool(v: &Value) -> Result<&str, String> {
    let Value::Object(m) = v else {
        return Err("must be an object".into());
    };
    for k in m.keys() {
        if k != "name" && k != "description" && k != "inputSchema" {
            return Err(format!("unknown field '{k}'"));
        }
    }
    let name = m.get("name").and_then(Value::as_str).ok_or("missing string field 'name'")?;
    let description = m.get("description").and_then(Value::as_str).ok_or("missing string field 'description'")?;
    if name.is_empty() || description.is_empty() {
        return Err("'name' and 'description' must be nonempty".into());
    }
    let schema = m.get("inputSchema").ok_or("missing field 'inputSchema'")?;
    if !schema.is_object() {
        return Err("'inputSchema' must be a JSON Schema object".into());
    }
    Ok(name)
}

#[cfg(test)]
mod tests {
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

    /// The first rule, whole: the name rides as `op` (over any `op` the
    /// arguments carry), a top-level `from_` comes back as `from` on the
    /// renaming ops and nowhere else — unless a `from` is already there, when
    /// both ride — and a nested `from_` is wire shape.
    #[test]
    fn wire_frame_is_the_first_rule() {
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
}
