//! The tool catalog: names, descriptions, input schemas, and the server
//! `instructions` string — data, not code. The shipped `tools.json` is
//! embedded at build time and overridable with `--tools-file`. Loading
//! cross-checks the catalog against the dispatch table in BOTH directions,
//! so the file and the code cannot drift silently: a file entry the
//! dispatch doesn't know refuses startup, and a dispatch op the file
//! doesn't name refuses startup.

use serde_json::Value;

/// The shipped catalog (`tools.json` beside `Cargo.toml`).
pub const EMBEDDED: &str = include_str!("../tools.json");

/// The adapter's one apparatus tool — not a wire op; answered from
/// `principal_prefix` and `GET /health`.
pub const SESSION_INFO: &str = "session_info";

/// Every wire operation the dispatch maps, exactly the wire's snake_case
/// op names (wire.md §Operations): the tool name IS the frame's `op`.
pub const WIRE_OPS: &[&str] = &[
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
/// `from`); dispatch renames it back mechanically. Only top-level argument
/// names are affected — a `from` nested inside an object value is wire
/// shape, untouched.
pub const RENAMES_FROM: &[&str] = &["make_link", "emit"];

/// One catalog entry. Order is preserved: `tools/list` answers in file
/// order.
pub struct Tool {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
}

pub struct Tools {
    pub instructions: String,
    pub tools: Vec<Tool>,
}

/// Parse and validate one catalog. Every fault is a startup error carrying
/// the offending name — the no-drift contract is enforced here, in both
/// directions.
pub fn load(text: &str) -> Result<Tools, String> {
    let v: Value = serde_json::from_str(text).map_err(|e| format!("not JSON: {e}"))?;
    let Value::Object(root) = v else {
        return Err("root must be a JSON object".into());
    };
    for k in root.keys() {
        if k != "instructions" && k != "tools" {
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
    let entries =
        root.get("tools").and_then(Value::as_array).ok_or("missing array field 'tools'")?;
    let mut tools = Vec::with_capacity(entries.len());
    for (i, e) in entries.iter().enumerate() {
        tools.push(parse_tool(e).map_err(|e| format!("tools[{i}]: {e}"))?);
    }
    let mut seen = std::collections::BTreeSet::new();
    for t in &tools {
        if !seen.insert(t.name.as_str()) {
            return Err(format!("duplicate tool '{}'", t.name));
        }
        if t.name != SESSION_INFO && !WIRE_OPS.contains(&t.name.as_str()) {
            return Err(format!("tool '{}' names an op the dispatch doesn't know", t.name));
        }
    }
    for op in WIRE_OPS.iter().copied().chain([SESSION_INFO]) {
        if !seen.contains(op) {
            return Err(format!("dispatch op '{op}' has no tools-file entry"));
        }
    }
    Ok(Tools { instructions, tools })
}

fn parse_tool(v: &Value) -> Result<Tool, String> {
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
    Ok(Tool {
        name: name.to_string(),
        description: description.to_string(),
        input_schema: schema.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// The shipped catalog: 38 wire ops + session_info, every entry named,
    /// described, and schema'd — `load` enforces both no-drift directions,
    /// so a clean load IS the no-drift assertion for the embedded file.
    #[test]
    fn embedded_catalog_matches_dispatch() {
        let t = load(EMBEDDED).expect("embedded tools.json must validate");
        assert_eq!(t.tools.len(), WIRE_OPS.len() + 1);
        assert_eq!(t.tools.len(), 39);
        assert!(!t.instructions.is_empty());
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

    #[test]
    fn wire_ops_are_38_and_distinct() {
        let set: std::collections::BTreeSet<_> = WIRE_OPS.iter().collect();
        assert_eq!(set.len(), WIRE_OPS.len());
        assert_eq!(WIRE_OPS.len(), 38);
    }
}
