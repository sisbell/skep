//! The tool catalog and the dispatch it is checked against.
//!
//! The catalog is data, not code: names, descriptions, input schemas, the
//! server `instructions` string, the `SKEP_COMMONS` sentence template
//! (`commons_instructions`, `{addr}` placeholder), and the help store
//! (`help`), the text the `help` tool answers by topic: a heading in
//! capitals, which the instructions and the cards name in parentheses, or a
//! tool's name, the whole reference of a tool whose card ends naming it. A
//! client cuts a long description, so the instructions and each card say
//! what an agent needs first, and the store holds the rest, read when a call
//! goes the way it covers. The shipped `tools.json` is embedded at build time
//! and overridable with `--tools-file`. Loading cross-checks the catalog
//! against the dispatch in both directions, so the file and the code cannot
//! drift silently: a file entry the dispatch doesn't know refuses startup, a
//! dispatch tool the file doesn't name refuses startup, and so does a help
//! topic that is neither a heading nor a dispatch tool's name. The dispatch
//! has two kinds of tool ([`Tool`]): the *wire ops*, each spelled as the wire
//! spells it, whose arguments are the frame and which the adapter sends as
//! `op(session, frame)` through the shell — every op of wire.md §Operations
//! but `publish`, which the shell runs as its `publication` call family; and
//! the *adapter tools* — the shell's calls (`boards`, `health`, `probe`,
//! `search`, `places`, `held`, `resolve`, the read of a draft's standing,
//! `publication_standing`, and the `publication` family's four,
//! `publication_open`, `publication_count`, `publication_confirm` and
//! `publication_cancel`) and the apparatus (`session_info`, `changes_since`,
//! `fetch`, the shell's two text edits, `replace_text`, its `text.replace`,
//! and `edit_text`, its several-pair `text.edit`, its move of whole lines,
//! `move_lines`, its `text.move`, its mark of a draft to diff against,
//! `mark_text`, its `text.mark`, its diff of a draft by identity,
//! `diff_text`, its `text.diff`, and `help`, which reads the help store and
//! calls no shell) — whose arguments are the bridge's row
//! minus the session and the board, the adapter supplying each where the row
//! requires it, `help`'s its one `topic`, and whose members the adapter
//! reads by name. A `publication` tool spells its row's `.` as `_`, since an
//! agent runtime takes a tool's name for a function's, whose spelling admits
//! no `.`. `Tool::admit` is the dispatch's door, admitting a call or refusing
//! it; `wire_frame` maps a wire op's call onto its frame, and
//! `Catalog::append_commons` fills the commons template in beside the check on
//! its placeholder.

use std::fmt;

use serde_json::{Map, Value};

/// The shipped catalog (`tools.json` beside `Cargo.toml`).
pub const EMBEDDED: &str = include_str!("../tools.json");

/// The wire operations this adapter maps: every op of wire.md but `publish`.
///
/// They are the ops of wire.md §Operations, each spelled exactly as the wire
/// spells it, since the tool name *is* the frame's `op`. No general `op` tool
/// ships: every op has a name here. `publish` has none, since the shell
/// refuses a `publish` frame through its `op` row (`publish_is_a_call`) and
/// runs a publication itself, composing the one request from the panel it
/// holds: its `publication` family's four rows are adapter tools (`client.md`
/// §4b.1's `op` row).
const DISPATCH_OPS: &[&str] = &[
    // Namespace.
    "create_new_document",
    "delegate",
    "register_node",
    "fork",
    "create_well_known_document",
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
    "set_arrangement",
    "version",
    "stage",
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
    "line_numbers",
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
    "count_v_by_home",
    "find_links_v_history",
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
    /// `publication.open(session, draft, …)`, the shell's.
    ///
    /// The session is supplied; the shell runs a publication's first steps
    /// and holds its panel.
    PublicationOpen,
    /// `publication.count(session, switches?, answers?)`, the shell's.
    ///
    /// The session is supplied.
    PublicationCount,
    /// `publication.confirm(session, switches?, answers?)`, the shell's.
    ///
    /// The session is supplied; the shell composes the one request off the
    /// panel, signs and sends it.
    PublicationConfirm,
    /// `publication.cancel(session)`, the shell's: the session supplied.
    PublicationCancel,
    /// `publication.standing(session, draft, doc, also?)`, the shell's.
    ///
    /// The session is supplied; the shell reads where the draft stands and
    /// holds nothing.
    PublicationStanding,
    /// The apparatus: who this adapter acts as, and its session's facts.
    SessionInfo,
    /// `changes(session, since, limit?, class?, under?)`, the shell's, pulled.
    ChangesSince,
    /// `fetch(session, i)`, the shell's streamed call, as a content block.
    Fetch,
    /// `text.replace(session, doc, old, new)`, the shell's text edit of a
    /// draft: the session supplied.
    ///
    /// The shell marks an answer that is an error by a member of its own,
    /// which the adapter reads for `isError` and takes off.
    ReplaceText,
    /// `text.edit(session, doc, edits)`, the shell's several text edits of a
    /// draft in one call: the session supplied.
    ///
    /// Its answer is rendered as `replace_text`'s, and the lines a landed
    /// call changed, which the shell answers as a member of their own,
    /// follow it one row a line.
    EditText,
    /// `text.move(session, doc, first, last?, before?)`, the shell's.
    ///
    /// It moves whole lines of a draft by identity, the session supplied.
    /// Its answer is rendered as `edit_text`'s, the lines a landed move
    /// shows following it one row a line.
    MoveLines,
    /// `text.mark(session, doc)`, the shell's: the session supplied.
    ///
    /// It makes a private copy of a draft's content by identity, to diff
    /// against later. Its answer is rendered as `replace_text`'s.
    MarkText,
    /// `text.diff(session, doc, since, stat?, hunk?)`, the shell's.
    ///
    /// It tells what changed in a draft since a document that holds its
    /// content by identity, the session supplied, and writes nothing. Its
    /// answer is rendered as `edit_text`'s, the hunks' rows following it one
    /// row a line.
    DiffText,
    /// `help(topic?)`, the catalog's help store read by topic.
    ///
    /// The one tool that calls no shell: it reads the catalog alone
    /// (`Catalog::help`, `Catalog::topics`), so it answers with no session
    /// and no board.
    Help,
}

/// The adapter tools: each name, its tool, and the members its row takes.
///
/// The members are skep-shell's row's, bar the session and the board, which
/// the adapter supplies or does not offer — the suite holds the two equal —
/// save `help`'s `topic`, a member no row has, `help` reading the catalog
/// alone; and they are the only ones the adapter reads: a member outside them
/// is refused before any call.
const ADAPTER_TOOLS: &[(&str, Tool, &[&str])] = &[
    ("boards", Tool::Boards, &[]),
    ("health", Tool::Health, &[]),
    ("probe", Tool::Probe, &[]),
    ("search", Tool::Search, &["query", "opts"]),
    ("places", Tool::Places, &["opts"]),
    ("held", Tool::Held, &[]),
    ("resolve", Tool::Resolve, &["held", "act"]),
    ("publication_open", Tool::PublicationOpen, &["draft", "also", "doc", "mint", "claim", "selection", "notes", "readable_drafts", "published"]),
    ("publication_count", Tool::PublicationCount, &["switches", "answers"]),
    ("publication_confirm", Tool::PublicationConfirm, &["switches", "answers"]),
    ("publication_cancel", Tool::PublicationCancel, &[]),
    ("publication_standing", Tool::PublicationStanding, &["draft", "doc", "also"]),
    ("session_info", Tool::SessionInfo, &[]),
    ("changes_since", Tool::ChangesSince, &["since", "limit", "class", "under"]),
    ("fetch", Tool::Fetch, &["i"]),
    ("replace_text", Tool::ReplaceText, &["doc", "old", "new"]),
    ("edit_text", Tool::EditText, &["doc", "edits"]),
    ("move_lines", Tool::MoveLines, &["doc", "first", "last", "before"]),
    ("mark_text", Tool::MarkText, &["doc"]),
    ("diff_text", Tool::DiffText, &["doc", "since", "stat", "hunk"]),
    ("help", Tool::Help, &["topic"]),
];

/// The options an adapter tool's `opts` takes, where its row takes one.
///
/// They are skep-shell's `SearchOpts` and `PlacesOpts`, the members the
/// catalog's closed `opts` schemas name, bar one the door withholds: `search`'s
/// `reindex`, the index's refresh, which is the person's act (`search.md` §5.5;
/// `client.md` §4b.1). Asked, it re-reads every unit the index holds before the
/// search answers — every published document, whoever published it, and every
/// draft the session reads, each its extent and then its whole text — on the
/// shell's feed thread for the board, while the call waits and this adapter,
/// which answers one call at a time, serves nothing else. No person is at this
/// adapter's seam, and a document's text can steer an agent into asking the
/// refresh on every search. The feed keeps the index current commit by commit
/// and retries a recorded refusal as the index widens; an `unplaced` count,
/// which the refresh alone clears, stands, and the index's state says so. The
/// shell ignores an option it does not read, so the door refuses one outside
/// these, as it refuses a member outside the row.
const OPTS_MEMBERS: &[(Tool, &[&str])] = &[(Tool::Search, &["limit", "offset"]), (Tool::Places, &["under"])];

/// The members each pair of `edit_text`'s `edits` takes.
///
/// They are skep-shell's `TextEditPair`, the members the catalog's closed
/// pair schema names. The shell reads a pair's `old` and `new` alone and
/// ignores any other — a pair's own `doc` would be made in the call's — so
/// the door refuses one outside these, as it refuses a member outside the
/// row; a list that is no list, and a pair that is no object, are the
/// shell's to refuse by name.
const PAIR_MEMBERS: &[&str] = &["old", "new"];

impl Tool {
    /// Admits the call a `tools/call` names, or refuses it.
    ///
    /// `name` must be one the dispatch answers. A wire op's arguments pass
    /// through unread here as the frame — the shell's checks of what it sends
    /// or holds, then the daemon's strict parse, their validators (*every tool
    /// is one call of the shell*) — save one shape: a non-negative integer
    /// `at` beside an object `frame`, which skep-shell's `op` row reads as its
    /// `/op-at` form and would send as another frame. An adapter tool's every
    /// member must be one its row takes, and every member of its `opts` one of
    /// the row's options the door takes (`OPTS_MEMBERS`), and every member of
    /// a pair of `edit_text`'s `edits` one a pair takes (`PAIR_MEMBERS`) —
    /// members the adapter and the shell read.
    ///
    /// # Errors
    ///
    /// The refusal of a call the adapter will not run, which
    /// `Server::respond` answers -32602, in this order:
    ///
    /// 1. a name the dispatch does not answer;
    /// 2. for a wire op, arguments of the `/op-at` shape;
    /// 3. for an adapter tool, a member its row does not take, then a member
    ///    of its `opts` outside `OPTS_MEMBERS`, `search`'s withheld `reindex`
    ///    among them;
    /// 4. for `edit_text`, a member of a pair of its `edits` outside
    ///    `PAIR_MEMBERS`, named with the pair's index, the first pair's
    ///    first speaking.
    pub fn admit(name: &str, args: &Map<String, Value>) -> Result<Tool, String> {
        let tool = Tool::named(name).ok_or_else(|| format!("unknown tool '{name}'; tools/list names the available tools"))?;
        let Some(members) = tool.members() else {
            // The shell sends this shape's inner frame, whatever its op, to
            // the board's history; no wire op takes a top-level `frame`, so
            // the refusal narrows no frame the daemon's parse admits.
            if args.get("at").is_some_and(Value::is_u64) && args.get("frame").is_some_and(Value::is_object) {
                return Err(format!(
                    "{name}'s arguments carry a numeric 'at' beside an object 'frame', which the shell would send as another frame to the board's history: no wire op takes a 'frame', and history reads are not offered here"
                ));
            }
            return Ok(tool);
        };
        if let Some(arg) = args.keys().find(|k| !members.contains(&k.as_str())) {
            return Err(match members {
                [] => format!("{name} takes no arguments; got '{arg}'"),
                _ => format!("{name} takes {}; got '{arg}'", listed(members)),
            });
        }
        if let (Some(Value::Object(opts)), Some(taken)) = (args.get("opts"), tool.opts_members()) {
            if let Some(arg) = opts.keys().find(|k| !taken.contains(&k.as_str())) {
                return Err(format!("{name}'s opts take {}; got '{arg}'", listed(taken)));
            }
        }
        if let (Tool::EditText, Some(Value::Array(edits))) = (tool, args.get("edits")) {
            for (k, pair) in edits.iter().enumerate() {
                if let Some(arg) = pair.as_object().and_then(|pair| pair.keys().find(|key| !PAIR_MEMBERS.contains(&key.as_str()))) {
                    return Err(format!("{name}'s edits take {} in each pair; got 'edits[{k}].{arg}'", listed(PAIR_MEMBERS)));
                }
            }
        }
        Ok(tool)
    }

    /// Returns the tool the dispatch answers `name` by, where it answers one.
    fn named(name: &str) -> Option<Tool> {
        if let Some(op) = DISPATCH_OPS.iter().find(|op| **op == name) {
            return Some(Tool::Op(op));
        }
        ADAPTER_TOOLS.iter().find(|(n, _, _)| *n == name).map(|(_, tool, _)| *tool)
    }

    /// Returns every name the dispatch answers.
    ///
    /// The wire ops come first, then the adapter tools in their table's order.
    fn names() -> impl Iterator<Item = &'static str> {
        DISPATCH_OPS.iter().copied().chain(ADAPTER_TOOLS.iter().map(|(name, _, _)| *name))
    }

    /// Returns the argument members an adapter tool's row takes.
    ///
    /// They are the only ones the adapter reads, so any other is refused by
    /// name; `None` for a wire op, whose arguments pass through unread as the
    /// frame.
    fn members(self) -> Option<&'static [&'static str]> {
        match self {
            Tool::Op(_) => None,
            other => ADAPTER_TOOLS.iter().find(|(_, tool, _)| *tool == other).map(|(_, _, members)| *members),
        }
    }

    /// Returns the options an adapter tool's `opts` takes, where it takes one.
    ///
    /// They are the row's options the door admits (`OPTS_MEMBERS`), so any
    /// other is refused by name; `None` where the tool's row takes no `opts`.
    fn opts_members(self) -> Option<&'static [&'static str]> {
        OPTS_MEMBERS.iter().find(|(tool, _)| *tool == self).map(|(_, members)| *members)
    }
}

/// Returns `members` as a refusal lists them, each quoted, comma-separated.
fn listed(members: &[&str]) -> String {
    members.iter().map(|m| format!("'{m}'")).collect::<Vec<_>>().join(", ")
}

/// The ops whose wire `from` argument rides as `from_` in the tool schema.
///
/// Harnesses that turn schemas into function parameters cannot always take
/// `from`, so the schema spells it `from_` and `wire_frame` renames it back —
/// unless the arguments already carry the wire's own `from`, when both ride
/// and the daemon's unknown-field refusal answers: the collision is the
/// strict parse's to refuse, never the relay's to resolve. Only top-level
/// argument names are affected — a `from` nested inside an object value is
/// wire shape, untouched. `Catalog::load` refuses a schema that spells
/// `from_` on any other tool, an adapter tool's among them; on another op,
/// its agents' `from_` would reach the wire unmapped. `stage`'s one
/// argument, the source staged from, is the wire's `from` too.
const RENAMES_FROM: &[&str] = &["make_link", "emit", "stage"];

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

/// The substitution point in `commons_instructions`.
///
/// `Catalog::load` refuses a template without one, and
/// `Catalog::append_commons` replaces every one.
const ADDR_PLACEHOLDER: &str = "{addr}";

/// The loaded catalog: the instructions, the commons template, the tools,
/// and the help store.
///
/// Its invariant, established by `Catalog::load`: `instructions` is
/// nonempty; `commons_instructions` holds `{addr}`; `tools` is one
/// `check_tool`-valid entry per name of `Tool::names` — every wire op and
/// every adapter tool — no name twice, in file order, a top-level `from_`
/// argument named on the `RENAMES_FROM` ops alone; so every tool `tools/list`
/// names is one `Server::call` runs, every tool it runs is listed, and every
/// `from_` a schema names is one `wire_frame` maps back to the wire's `from`;
/// and `help` is one nonempty text per topic, no topic twice, each a heading
/// (`is_heading`) or a name of `Tool::names`, in file order. The fields are
/// private, so outside this module `load` is the one way to build one, and
/// `append_commons`, the one mutation, only appends to `instructions`.
#[derive(Debug)]
pub struct Catalog {
    instructions: String,
    /// The sentence `append_commons` adds to `instructions`.
    ///
    /// It is added when `SKEP_COMMONS` names the commons; `{addr}` is the
    /// substitution point.
    commons_instructions: String,
    /// The catalog's tool definitions in file order.
    ///
    /// Each is checked by `check_tool` and kept as the file spells it:
    /// exactly the `tools` array `tools/list` answers.
    tools: Vec<Value>,
    /// The help store in file order: each topic, and its text.
    ///
    /// Each is checked by `check_topic`; `help` answers a topic's text, and
    /// `topics` lists them.
    help: Vec<(String, String)>,
}

impl Catalog {
    /// Parses and validates one catalog, establishing `Catalog`'s invariant.
    ///
    /// It is the no-drift contract: the tools' names held to the dispatch in
    /// both directions and over both kinds, the one argument the dispatch
    /// renames held to the ops it renames on, and each help topic held to a
    /// heading or a tool the dispatch answers.
    ///
    /// # Errors
    ///
    /// Every fault is a startup error naming what is wrong — the field, the
    /// entry's index, the tool, the op or the topic — one fault at a time,
    /// the first found speaking, in this order:
    ///
    /// 1. text that is no JSON, a root that is no object, or a root field
    ///    the catalog does not hold;
    /// 2. `instructions` missing or empty, `commons_instructions` missing or
    ///    without `{addr}`, then `tools` missing or no array, then `help`
    ///    missing or no array;
    /// 3. each entry by index, as `check_tool` refuses it;
    /// 4. each name in file order: a duplicate, or one the dispatch doesn't
    ///    know;
    /// 5. each dispatch tool the file doesn't name;
    /// 6. each entry in file order whose schema spells a top-level `from_`
    ///    on any tool but the ops `wire_frame` maps it back on;
    /// 7. each help entry by index, as `check_topic` refuses it;
    /// 8. each help topic in file order: a duplicate, or one that is neither
    ///    a heading nor a tool the dispatch answers.
    pub fn load(text: &str) -> Result<Catalog, String> {
        let v: Value = serde_json::from_str(text).map_err(|e| format!("not JSON: {e}"))?;
        let Value::Object(mut root) = v else {
            return Err("root must be a JSON object".into());
        };
        for k in root.keys() {
            if k != "instructions" && k != "commons_instructions" && k != "tools" && k != "help" {
                return Err(format!("unknown root field '{k}'"));
            }
        }
        let Some(Value::String(instructions)) = root.remove("instructions") else {
            return Err("missing string field 'instructions'".into());
        };
        if instructions.is_empty() {
            return Err("'instructions' must be nonempty".into());
        }
        let Some(Value::String(commons_instructions)) = root.remove("commons_instructions") else {
            return Err("missing string field 'commons_instructions'".into());
        };
        if !commons_instructions.contains(ADDR_PLACEHOLDER) {
            return Err(format!("'commons_instructions' must contain the '{ADDR_PLACEHOLDER}' placeholder"));
        }
        let Some(Value::Array(tools)) = root.remove("tools") else {
            return Err("missing array field 'tools'".into());
        };
        let Some(Value::Array(help)) = root.remove("help") else {
            return Err("missing array field 'help'".into());
        };
        let mut names = Vec::with_capacity(tools.len());
        for (i, t) in tools.iter().enumerate() {
            names.push(check_tool(t).map_err(|e| format!("tools[{i}]: {e}"))?);
        }
        let mut seen = std::collections::BTreeSet::new();
        for &name in &names {
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
        for (t, name) in tools.iter().zip(&names) {
            if t["inputSchema"]["properties"].get("from_").is_some() && !RENAMES_FROM.contains(name) {
                return Err(format!("tool '{name}' names a 'from_' argument, which this adapter maps back to the wire's 'from' on {} alone", listed(RENAMES_FROM)));
            }
        }
        let mut store = Vec::with_capacity(help.len());
        for (i, entry) in help.into_iter().enumerate() {
            store.push(check_topic(entry).map_err(|e| format!("help[{i}]: {e}"))?);
        }
        let mut topics = std::collections::BTreeSet::new();
        for (topic, _) in &store {
            if !topics.insert(topic.as_str()) {
                return Err(format!("duplicate help topic '{topic}'"));
            }
            if !is_heading(topic) && Tool::named(topic).is_none() {
                return Err(format!("help topic '{topic}' is neither a heading (capitals and spaces, a capital at each end) nor a tool the dispatch answers"));
            }
        }
        Ok(Catalog { instructions, commons_instructions, tools, help: store })
    }

    /// Returns the server instructions `initialize` answers.
    ///
    /// The commons sentence is appended when `SKEP_COMMONS` is set.
    pub fn instructions(&self) -> &str {
        &self.instructions
    }

    /// Returns the tool definitions `tools/list` answers.
    ///
    /// They are exactly the entries `Catalog::load` checked, in file order.
    pub fn tools(&self) -> &[Value] {
        &self.tools
    }

    /// Returns the text of the help topic `topic`, where the store holds it.
    ///
    /// A topic is spelled as the store spells it: a heading in capitals, or
    /// a tool's name.
    pub fn help(&self, topic: &str) -> Option<&str> {
        self.help.iter().find(|(held, _)| held == topic).map(|(_, text)| text.as_str())
    }

    /// Returns the help store's topics: the headings, then the tools' names.
    ///
    /// Each kind keeps its file order, so the list an agent reads opens with
    /// the rules and closes with the tools' references.
    pub fn topics(&self) -> impl Iterator<Item = &str> {
        let topics = || self.help.iter().map(|(topic, _)| topic.as_str());
        topics().filter(|topic| is_heading(topic)).chain(topics().filter(|topic| !is_heading(topic)))
    }

    /// Points the instructions at the commons, `addr`.
    ///
    /// The commons template, every `{addr}` replaced by `addr`, is appended
    /// after a blank line. `addr` goes in as given: that it is the commons is
    /// the caller's to have checked — `main`'s `SKEP_COMMONS` gate, which
    /// takes the commons' one address alone — and it is checked nowhere here.
    pub fn append_commons(&mut self, addr: &str) {
        let sentence = self.commons_instructions.replace(ADDR_PLACEHOLDER, addr);
        self.instructions.push_str("\n\n");
        self.instructions.push_str(&sentence);
    }

    /// Returns how this catalog's text differs from `other`'s, where it does.
    ///
    /// Its instructions differ where they, or the commons template, read
    /// otherwise; an entry differs where `other` holds no entry the same,
    /// whole. Two catalogs `load` admitted name the same tools, so the entries
    /// counted are those of a tool the two describe otherwise. Their help
    /// stores may hold different topics, so a help topic differs where the
    /// two read it otherwise, one of them holding it and the other not among
    /// them, counted over the topics either holds.
    pub fn drift_from(&self, other: &Catalog) -> Option<Drift> {
        let instructions = self.instructions != other.instructions || self.commons_instructions != other.commons_instructions;
        let entries = self.tools.iter().filter(|entry| !other.tools.contains(entry)).count();
        let topics: std::collections::BTreeSet<&str> = self.help.iter().chain(&other.help).map(|(topic, _)| topic.as_str()).collect();
        let help = topics.iter().filter(|topic| self.help(topic) != other.help(topic)).count();
        (instructions || entries > 0 || help > 0).then_some(Drift { instructions, entries, tools: self.tools.len(), help, topics: topics.len() })
    }
}

/// How a catalog's text differs from another's.
///
/// It is what `Catalog::drift_from` counts. Its `Display` is the clause a
/// line names the difference by, each part that differs in this order,
/// joined as a list: `its instructions`, `<n> of its <m> tools' entries`,
/// and `<n> of the <m> help topics`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Drift {
    /// Whether the instructions, or the commons template, read otherwise.
    pub instructions: bool,
    /// How many of the tools' entries describe their tool otherwise.
    pub entries: usize,
    /// How many tools the catalog holds.
    pub tools: usize,
    /// How many help topics read otherwise, or stand in one store alone.
    pub help: usize,
    /// How many help topics the two catalogs hold between them.
    pub topics: usize,
}

impl fmt::Display for Drift {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut parts = Vec::with_capacity(3);
        if self.instructions {
            parts.push("its instructions".to_string());
        }
        if self.entries > 0 {
            parts.push(format!("{} of its {} tools' entries", self.entries, self.tools));
        }
        if self.help > 0 {
            parts.push(format!("{} of the {} help topics", self.help, self.topics));
        }
        match parts.split_last() {
            Some((last, [])) => f.write_str(last),
            Some((last, rest)) => write!(f, "{}, and {last}", rest.join(", ")),
            None => Ok(()),
        }
    }
}

/// Checks one catalog entry, an MCP tool definition, and returns its name.
///
/// The definition is a nonempty string `name` and `description`, an
/// `inputSchema` of type `"object"` (MCP 2025-06-18's `Tool.inputSchema`),
/// and no other field. A definition's fields are named here — `inputSchema`
/// in `Catalog::load`'s `from_` check too — and nowhere else in the adapter.
///
/// # Errors
///
/// The first fault found, named: the entry no object, a field no definition
/// has, a missing or empty `name` or `description`, then a missing
/// `inputSchema` or one whose type is not `"object"`.
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
    if schema.get("type").and_then(Value::as_str) != Some("object") {
        return Err("'inputSchema' must be a JSON Schema of type \"object\" (MCP 2025-06-18, Tool.inputSchema)".into());
    }
    Ok(name)
}

/// Checks one help store entry, and returns its topic and its text.
///
/// The entry is a nonempty string `topic` and `text`, and no other field.
/// The store is an array, so its entries keep the file's order and a topic
/// written twice reaches `Catalog::load`'s duplicate check.
///
/// # Errors
///
/// The first fault found, named: the entry no object, a field no entry has,
/// then a missing or empty `topic`, then a missing or empty `text`.
fn check_topic(entry: Value) -> Result<(String, String), String> {
    let Value::Object(mut m) = entry else {
        return Err("must be an object".into());
    };
    if let Some(k) = m.keys().find(|k| *k != "topic" && *k != "text") {
        return Err(format!("unknown field '{k}'"));
    }
    let mut field = |name: &str| match m.remove(name) {
        Some(Value::String(s)) if !s.is_empty() => Ok(s),
        Some(Value::String(_)) => Err(format!("'{name}' must be nonempty")),
        _ => Err(format!("missing string field '{name}'")),
    };
    Ok((field("topic")?, field("text")?))
}

/// Returns whether `text` is a heading.
///
/// A heading is capitals and spaces, with a capital at each end. A help
/// topic is a heading or a tool's name, whose spelling, lowercase with `_`,
/// is never a heading; the instructions and the cards name a heading in
/// parentheses.
fn is_heading(text: &str) -> bool {
    text.len() > 1 && text.starts_with(|c: char| c.is_ascii_uppercase()) && text.ends_with(|c: char| c.is_ascii_uppercase()) && text.chars().all(|c| c.is_ascii_uppercase() || c == ' ')
}

#[cfg(test)]
mod tests;
