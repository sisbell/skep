//! The tool catalog: names, descriptions, input schemas, the server
//! `instructions` string, and the `SKEP_COMMONS` sentence template
//! (`commons_instructions`, `{addr}` placeholder) — data, not code. The
//! shipped `tools.json` is embedded at build time and overridable with
//! `--tools-file`. Loading cross-checks the catalog against the dispatch
//! table in BOTH directions, so the file and the code cannot drift
//! silently: a file entry the dispatch doesn't know refuses startup, and a
//! dispatch op the file doesn't name refuses startup. `wire_frame` maps a
//! tool call onto its frame from that same table, so the table the catalog
//! is checked against is the one calls are dispatched by; and
//! `Catalog::append_commons` fills the commons template in beside the check
//! on its placeholder.

use serde_json::{Map, Value};

/// The shipped catalog (`tools.json` beside `Cargo.toml`).
pub const EMBEDDED: &str = include_str!("../tools.json");

/// The adapter's one apparatus tool — not a wire op; answered from
/// `principal_prefix` and `GET /health`.
pub const SESSION_INFO: &str = "session_info";

/// The dispatch table: the wire operations this adapter maps — not every op
/// of wire.md §Operations — each spelled exactly as the wire spells it,
/// since the tool name IS the frame's `op`.
const DISPATCH_OPS: &[&str] = &[
    // Namespace.
    "create_new_document",
    "delegate",
    "register_node",
    "fork",
    "next_account_prefix",
    "principal_prefix",
    // Arrangement.
    "insert",
    "delete",
    "copy",
    "rearrange",
    "version",
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
];

/// The ops whose wire `from` argument rides as `from_` in the tool schema
/// (harnesses that turn schemas into function parameters cannot always take
/// `from`); `wire_frame` renames it back. Only top-level argument names are
/// affected — a `from` nested inside an object value is wire shape,
/// untouched.
const RENAMES_FROM: &[&str] = &["make_link", "emit"];

/// A tool call's wire frame — the crate's first rule, in one place: the
/// name IS the frame's `op`, the arguments ARE the frame, and on the
/// `RENAMES_FROM` ops a top-level `from_` rides back as `from`. `None` for
/// a name the dispatch doesn't map: `session_info`, a wire op outside
/// `DISPATCH_OPS`, or no op at all.
pub fn wire_frame(name: &str, mut args: Map<String, Value>) -> Option<Vec<u8>> {
    if !DISPATCH_OPS.contains(&name) {
        return None;
    }
    if RENAMES_FROM.contains(&name) {
        if let Some(v) = args.remove("from_") {
            args.insert("from".to_string(), v);
        }
    }
    args.insert("op".to_string(), Value::String(name.to_string()));
    let frame = serde_json::to_vec(&Value::Object(args))
        .expect("serializing a serde_json::Value cannot fail");
    Some(frame)
}

/// The substitution point in `commons_instructions`: `load` refuses a
/// template without one, and `Catalog::append_commons` replaces every one.
const ADDR_PLACEHOLDER: &str = "{addr}";

/// The loaded catalog: the server instructions, the commons sentence
/// template, and the tool definitions `tools/list` answers.
#[derive(Debug)]
pub struct Catalog {
    pub instructions: String,
    /// The sentence `append_commons` adds to `instructions` when
    /// `SKEP_COMMONS` names the commons; `{addr}` is the substitution point.
    commons_instructions: String,
    /// The catalog's tool definitions in file order, each checked by
    /// `check_tool` and kept as the file spells it: exactly the `tools`
    /// array `tools/list` answers.
    pub tools: Vec<Value>,
}

impl Catalog {
    /// Point the instructions at the commons: the commons template with
    /// every `{addr}` replaced by `addr`, appended after a blank line.
    pub fn append_commons(&mut self, addr: &str) {
        let sentence = self.commons_instructions.replace(ADDR_PLACEHOLDER, addr);
        self.instructions.push_str("\n\n");
        self.instructions.push_str(&sentence);
    }
}

/// Parse and validate one catalog. Every fault is a startup error carrying
/// the offending name — the no-drift contract is enforced here, in both
/// directions.
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
    let instructions = root
        .get("instructions")
        .and_then(Value::as_str)
        .ok_or("missing string field 'instructions'")?
        .to_string();
    if instructions.is_empty() {
        return Err("'instructions' must be nonempty".into());
    }
    let commons_instructions = root
        .get("commons_instructions")
        .and_then(Value::as_str)
        .ok_or("missing string field 'commons_instructions'")?
        .to_string();
    if !commons_instructions.contains(ADDR_PLACEHOLDER) {
        return Err(format!(
            "'commons_instructions' must contain the '{ADDR_PLACEHOLDER}' placeholder"
        ));
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
        if name != SESSION_INFO && !DISPATCH_OPS.contains(&name) {
            return Err(format!("tool '{name}' names an op the dispatch doesn't know"));
        }
    }
    for op in DISPATCH_OPS.iter().copied().chain([SESSION_INFO]) {
        if !seen.contains(op) {
            return Err(format!("dispatch op '{op}' has no tools-file entry"));
        }
    }
    Ok(Catalog { instructions, commons_instructions, tools })
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
    let description = m
        .get("description")
        .and_then(Value::as_str)
        .ok_or("missing string field 'description'")?;
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
    use super::*;
    use serde_json::json;

    /// The shipped catalog: every dispatch op plus `session_info`, every
    /// entry named, described, and schema'd — `load` enforces both no-drift
    /// directions, so a clean load IS the no-drift assertion for the
    /// embedded file — and every entry kept as the file spells it.
    #[test]
    fn embedded_catalog_matches_dispatch() {
        let t = load(EMBEDDED).expect("embedded tools.json must validate");
        assert_eq!(t.tools.len(), DISPATCH_OPS.len() + 1);
        assert!(!t.instructions.is_empty());
        let file: Value = serde_json::from_str(EMBEDDED).expect("embedded parses");
        assert_eq!(Some(&t.tools), file["tools"].as_array(), "entries kept verbatim");
    }

    /// Direction one: a file entry the dispatch doesn't know refuses to
    /// load, naming the tool.
    #[test]
    fn unknown_tool_refuses() {
        let mut v: Value = serde_json::from_str(EMBEDDED).expect("embedded parses");
        v["tools"].as_array_mut().expect("tools").push(json!({
            "name": "frobnicate",
            "description": "no such wire op",
            "inputSchema": {"type": "object"}
        }));
        let err = load(&v.to_string()).expect_err("must refuse");
        assert!(err.contains("frobnicate"), "error must name the tool: {err}");
    }

    /// Direction two: a dispatch op the file doesn't name refuses to load,
    /// naming the op.
    #[test]
    fn missing_op_refuses() {
        let mut v: Value = serde_json::from_str(EMBEDDED).expect("embedded parses");
        v["tools"].as_array_mut().expect("tools").retain(|t| t["name"] != "insert");
        let err = load(&v.to_string()).expect_err("must refuse");
        assert!(err.contains("insert"), "error must name the op: {err}");
    }

    /// The commons sentence template is catalog data like everything else:
    /// absent, or present without its substitution point, refuses to load.
    #[test]
    fn commons_template_refusals() {
        let mut v: Value = serde_json::from_str(EMBEDDED).expect("embedded parses");
        v.as_object_mut().expect("root").remove("commons_instructions");
        let err = load(&v.to_string()).expect_err("must refuse");
        assert!(err.contains("commons_instructions"), "error names the field: {err}");

        let mut v: Value = serde_json::from_str(EMBEDDED).expect("embedded parses");
        v["commons_instructions"] = json!("a sentence with no substitution point");
        let err = load(&v.to_string()).expect_err("must refuse");
        assert!(err.contains("{addr}"), "error names the placeholder: {err}");
    }

    /// The template is filled in where its placeholder is checked: every
    /// `{addr}` takes the address, and the sentence follows a blank line.
    #[test]
    fn append_commons_fills_every_placeholder() {
        let mut t = Catalog {
            instructions: "Base.".to_string(),
            commons_instructions: "Commons at {addr}; defines is {addr}.0.3.50.".to_string(),
            tools: Vec::new(),
        };
        t.append_commons("1.0.2.0.9");
        assert_eq!(t.instructions, "Base.\n\nCommons at 1.0.2.0.9; defines is 1.0.2.0.9.0.3.50.");
    }

    /// The first rule, whole: the name rides as `op` (over any `op` the
    /// arguments carry), a top-level `from_` comes back as `from` on the
    /// renaming ops and nowhere else, a nested `from_` is wire shape, and a
    /// name the dispatch doesn't map has no frame.
    #[test]
    fn wire_frame_is_the_first_rule() {
        let frame = |name: &str, args: Value| -> Option<Value> {
            let Value::Object(args) = args else { panic!("arguments are an object") };
            wire_frame(name, args).map(|f| serde_json::from_slice(&f).expect("a JSON frame"))
        };
        for op in ["make_link", "emit"] {
            assert_eq!(
                frame(op, json!({"from_": "1.1", "to": [{"from_": "x"}]})),
                Some(json!({"op": op, "from": "1.1", "to": [{"from_": "x"}]})),
                "{op} renames its top-level from_"
            );
        }
        assert_eq!(
            frame("insert", json!({"from_": "1.1", "op": "delete"})),
            Some(json!({"op": "insert", "from_": "1.1"}))
        );
        assert_eq!(frame(SESSION_INFO, json!({})), None);
        assert_eq!(frame("frobnicate", json!({})), None);
    }

    /// The dispatch table is distinct, and its size is pinned here and
    /// nowhere else: mapping or dropping a wire op changes this number.
    #[test]
    fn dispatch_ops_are_distinct_and_counted() {
        let set: std::collections::BTreeSet<_> = DISPATCH_OPS.iter().collect();
        assert_eq!(set.len(), DISPATCH_OPS.len());
        assert_eq!(DISPATCH_OPS.len(), 38);
    }
}
