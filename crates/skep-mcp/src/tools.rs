//! The tool catalog: names, descriptions, input schemas, the server
//! `instructions` string, and the `SKEP_COMMONS` sentence template
//! (`commons_instructions`, `{addr}` placeholder) — data, not code. The
//! shipped `tools.json` is embedded at build time and overridable with
//! `--tools-file`. Loading cross-checks the catalog against the dispatch in
//! BOTH directions, so the file and the code cannot drift silently: a file
//! entry the dispatch doesn't know refuses startup, and a dispatch tool the
//! file doesn't name refuses startup. The dispatch has two kinds of tool
//! ([`Tool`]): the *wire ops*, each spelled as the wire spells it, whose
//! arguments are the frame and which the adapter sends as `op(session, frame)`
//! through the shell; and the *adapter tools* — the shell's calls (`boards`,
//! `health`, `probe`, `search`, `places`, `held`, `resolve`) and the apparatus
//! (`session_info`, `changes_since`, `fetch`) — whose arguments are the
//! bridge's row minus the session and the board, the adapter supplying each
//! where the row requires it, and whose members the adapter reads by name.
//! `Tool::admit` is the dispatch's door, admitting a call or refusing it;
//! `wire_frame` maps a wire op's call onto its frame, and
//! `Catalog::append_commons` fills the commons template in beside the check on
//! its placeholder.

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

/// One tool the dispatch answers: a wire op by its name, or an adapter tool.
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
    /// `search(session, query, opts?)`, the shell's: the session supplied.
    ///
    /// The shell reads a session's search at the session's own board.
    Search,
    /// `places(session, opts?)`, the shell's: the session supplied.
    ///
    /// The shell lists a session's places at the session's own board.
    Places,
    /// `held(session)`, the shell's: the session supplied.
    Held,
    /// `resolve(session, held, act)`, the shell's: the session supplied.
    Resolve,
    /// The apparatus: who this adapter acts as, and its session's facts.
    SessionInfo,
    /// `changes(session, since, limit?)`, the shell's, as a pull tool.
    ChangesSince,
    /// `fetch(session, i)`, the shell's streamed call, as a content block.
    Fetch,
}

/// The adapter tools: each name, its tool, and the argument members
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
    /// Admits the call a `tools/call` names, or refuses it.
    ///
    /// `name` must be one the dispatch answers and, for an adapter tool,
    /// every member of `args` one its row takes — the members the adapter
    /// reads. A wire op's arguments pass through unread as the frame, the
    /// daemon's strict parse their validator.
    ///
    /// # Errors
    ///
    /// The refusal of a call the adapter will not run, which
    /// `Server::respond` answers -32602, in this order: a name the dispatch
    /// does not answer, then a member an adapter tool's row does not take.
    pub fn admit(name: &str, args: &Map<String, Value>) -> Result<Tool, String> {
        let tool = Tool::named(name).ok_or_else(|| format!("unknown tool '{name}'; tools/list names the available tools"))?;
        if let Some(members) = tool.members() {
            if let Some(arg) = args.keys().find(|k| !members.contains(&k.as_str())) {
                return Err(match members {
                    [] => format!("{name} takes no arguments; got '{arg}'"),
                    _ => format!("{name} takes {}; got '{arg}'", members.iter().map(|m| format!("'{m}'")).collect::<Vec<_>>().join(", ")),
                });
            }
        }
        Ok(tool)
    }

    /// The tool the dispatch answers `name` by, where it answers one.
    fn named(name: &str) -> Option<Tool> {
        if let Some(op) = DISPATCH_OPS.iter().find(|op| **op == name) {
            return Some(Tool::Op(op));
        }
        ADAPTER_TOOLS.iter().find(|(n, _, _)| *n == name).map(|(_, tool, _)| *tool)
    }

    /// Every name the dispatch answers, the wire ops first, then the
    /// adapter tools in their table's order.
    fn names() -> impl Iterator<Item = &'static str> {
        DISPATCH_OPS.iter().copied().chain(ADAPTER_TOOLS.iter().map(|(name, _, _)| *name))
    }

    /// The argument members an adapter tool's row takes — the only ones the
    /// adapter reads, so any other is refused by name — or `None` for a wire
    /// op, whose arguments pass through unread as the frame.
    fn members(self) -> Option<&'static [&'static str]> {
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

/// Returns a wire op's frame (*every tool is one call of the shell*).
///
/// The rule's mapping, in one place: the name is the frame's `op`, the
/// arguments are the frame, and on the `RENAMES_FROM` ops a top-level `from_`
/// rides back as `from` where no `from` is already there.
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
mod tests;
