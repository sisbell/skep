//! THE DECLARATIONS (S-16 (a), RULED: the page's declarations GENERATED
//! from this crate's Rust types; FP-16: "every value that crosses the
//! bridge has its shape defined on the Rust side and declared for the page
//! from that definition"): [`declarations`] renders one TypeScript
//! declaration file — every call's input and output, every event, the
//! refusal, the `feed` update's shape (a `changes` entry's too) and the
//! index state's ten arms — from
//! THE TABLE below, which is written by hand beside the code that builds
//! each value (`shell`, `feed`, `sessions`, `refusal`, `person`) and PINNED
//! by this module's suite: a sample of each type, built as the code builds
//! it, is round-tripped through `serde_json` and its field names held equal
//! to the table's. No generator crate: the table is the one source, and a
//! field renamed in the table alone, or in the code alone, fails the pin.
//! The calls' argument objects are data beside it (`CALL_ROWS`' members),
//! and the shell's suite sends each optional member a row of one form
//! declares, in a form its type refuses, to the row itself, which must
//! refuse it by name. The event names are rendered from `events::EventName`
//! itself, the type every event carries.

use std::fmt::{self, Write};

use crate::events::EventName;

/// One field of a declared type: its name, its TypeScript type, and
/// whether every value carries it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Field {
    pub name: &'static str,
    pub ty: &'static str,
    pub required: bool,
}

/// A field as the declarations spell it: `name: T`, or `name?: T` where a
/// value may leave it out — an interface's member and a call's argument
/// alike.
impl fmt::Display for Field {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}{}: {}", self.name, if self.required { "" } else { "?" }, self.ty)
    }
}

const fn req(name: &'static str, ty: &'static str) -> Field {
    Field { name, ty, required: true }
}

const fn opt(name: &'static str, ty: &'static str) -> Field {
    Field { name, ty, required: false }
}

/// One declared type: an interface over its fields, with the line of doc
/// the file carries above it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Shape {
    pub name: &'static str,
    /// Whether a value carries members beyond the declared fields — the
    /// arm's own members beside `arm`, the detail beside a shell refusal's
    /// `name` — declared as an index signature, and held by the pin to its
    /// required fields alone.
    pub open: bool,
    pub doc: &'static str,
    pub fields: &'static [Field],
}

/// THE TABLE: every value that crosses the bridge, by the name the file
/// declares it under.
const SHAPES: &[Shape] = &[
    Shape { name: "BoardRow", open: false, doc: "`boards()` — one entry per board in the shell's list; `board` the opaque reference every board-touching call takes", fields: &[req("board", "string"), req("name", "string"), req("origin", "string")] },
    Shape {
        name: "SessionOpened",
        open: false,
        doc: "`session(board, principal)` — the session's opaque reference in the token's place; `writes` whether a write may go out under it: the signed mode's session writes, the bare mode's keyless one reads alone and has every write refused `write_in_bare_session`",
        fields: &[req("session", "string"), req("principal", "number"), req("account", "string | null"), req("writes", "boolean")],
    },
    Shape { name: "Keygen", open: false, doc: "`keygen({label?})` — the device key's fingerprint, its enrollment record, and the outstanding act", fields: &[req("fingerprint", "string"), req("payload", "string"), req("outstanding", "string")] },
    Shape { name: "FingerprintRow", open: false, doc: "`fingerprint({select?, payload?})` — one key of the store, its bindings, the pending state", fields: &[req("fingerprint", "string"), req("label", "string | null"), req("bindings", "string[]"), req("unbound", "boolean"), req("payload", "string | null")] },
    Shape { name: "Claimed", open: false, doc: "`claim(board, opts)` — the three facts and the agent space; the display name held", fields: &[req("account", "string"), req("principal", "number"), req("fingerprint", "string"), req("agent_space", "string | null"), req("display_name", "string | null"), req("warnings", "string[]")] },
    Shape { name: "Facts", open: false, doc: "the three facts of a return leg", fields: &[req("principal", "number"), req("account", "string"), req("origin", "string")] },
    Shape { name: "Enrolled", open: false, doc: "`enroll(board, payload)`", fields: &[req("facts", "Facts"), req("fingerprints", "string[]"), req("reconciled", "boolean"), req("warnings", "string[]")] },
    Shape { name: "Bound", open: false, doc: "`bind(board, facts)` — empty, or the warning an unwritable store returns", fields: &[opt("warning", "string"), opt("warnings", "string[]")] },
    Shape { name: "Recovered", open: false, doc: "`recover(board, opts)`", fields: &[req("facts", "Facts"), req("enrolled", "string[]"), req("retired", "string[]"), req("containment", "boolean"), req("recovery_read", "string[]"), req("warnings", "string[]")] },
    Shape { name: "Rotated", open: false, doc: "`rotate(board, opts)`", fields: &[req("facts", "Facts"), req("old", "string"), req("new", "string"), req("trail", "string"), req("warnings", "string[]")] },
    Shape { name: "HandoffDelegated", open: false, doc: "`handoff(board, {account})` without a payload — beat (a)'s address", fields: &[req("address", "string"), req("principal", "number"), req("already", "boolean")] },
    Shape { name: "Accepted", open: false, doc: "`accept(board, opts)` — the enrollment record for the giver", fields: &[req("payload", "string")] },
    Shape { name: "Health", open: false, doc: "`health(board)` — the `/health` document verbatim and the derived mode", fields: &[req("health", "unknown"), req("mode", "Mode")] },
    Shape { name: "Probe", open: false, doc: "`probe()` — the own node's state", fields: &[req("daemon", "'running' | 'stopped' | 'unreachable'"), req("dialed", "string | null"), req("signed", "string | null")] },
    Shape { name: "SearchAnswer", open: false, doc: "`search(…)` — the hits, the places, the pair's state", fields: &[req("hits", "Hit[]"), req("places", "Place[]"), req("state", "IndexState"), req("total", "number"), req("truncated", "boolean"), req("more_terms", "boolean"), req("fuzzy_bounded", "boolean"), req("positions_bounded", "boolean")] },
    Shape { name: "Hit", open: false, doc: "one hit (search.md §3.1)", fields: &[req("doc", "string"), req("member", "string | null"), req("as_of", "number"), req("span", "SpanText"), req("score", "number"), req("snippet", "Snippet | null"), req("kind", "'edition' | 'draft'"), req("standing", "Standing"), req("occurrences", "number"), req("matched", "Matched[]")] },
    Shape { name: "SpanText", open: false, doc: "a hit's passage: the V-ordinal of its first byte and its width in positions", fields: &[req("start", "number"), req("width", "number")] },
    Shape { name: "Snippet", open: false, doc: "the paragraph window around a hit's span", fields: &[req("text", "string"), req("start", "number"), req("marks", "Mark[]")] },
    Shape { name: "Mark", open: false, doc: "one mark of a snippet", fields: &[req("offset", "number"), req("len", "number"), req("kind", "{ span: true } | { term: string } | { gap: { width: number } }")] },
    Shape { name: "Matched", open: false, doc: "a query word matched by one edit", fields: &[req("word", "string"), req("term", "string")] },
    Shape { name: "Place", open: false, doc: "one document of the document index — an exact address or label match `search` answers, or a document `places` lists", fields: &[req("doc", "string"), req("kind", "'edition' | 'draft'"), req("label", "string | null"), req("standing", "Standing")] },
    Shape {
        name: "PlacesAnswer",
        open: false,
        doc: "`places(…)` — every document of the board's document index at the call's class, in address order, under `opts.under` where given; the counts per account over them; the pair's state",
        fields: &[req("docs", "Place[]"), req("counts", "AccountCount[]"), req("state", "IndexState")],
    },
    Shape { name: "AccountCount", open: false, doc: "how many of a listing's documents lie under one account, the counts in address order", fields: &[req("account", "string"), req("documents", "number")] },
    Shape {
        name: "ChangesAnswer",
        open: false,
        doc: "`changes(session, since, limit?)` — what changed since the position `since` at the session's class: the entries in the `feed` update's shape, oldest first, each `published` or `drafts` by the read that answered it (two reads, the published feed as a guest and the session's drafts supplement under its token, merged by position); `next` the position to ask from next time, past every entry answered and never past one withheld; `head` the board's latest position, read before the page",
        fields: &[req("entries", "FeedUpdate[]"), req("next", "number"), req("head", "number")],
    },
    Shape { name: "RefusedByBoard", open: false, doc: "a refusal: the board's own verdict, verbatim", fields: &[req("kind", "'refused'"), req("name", "string"), req("status", "number"), req("code", "string"), req("detail", "string | null"), req("op", "string | null"), req("body", "unknown")] },
    Shape { name: "HaltFace", open: false, doc: "a refusal: a halt's face under the armed name", fields: &[req("kind", "'halt'"), req("name", "string"), req("state", "string"), req("cause", "string"), req("act", "string")] },
    Shape { name: "BlockedFace", open: false, doc: "a refusal: the block", fields: &[req("kind", "'blocked'"), req("name", "'blocked'"), req("record", "string"), req("named_by", "string"), req("ground", "string | null")] },
    Shape { name: "Unreachable", open: false, doc: "a refusal: the board is not answering", fields: &[req("kind", "'unreachable'"), req("name", "'unreachable'"), req("text", "string")] },
    Shape { name: "ShellRefusal", open: true, doc: "a refusal: the shell's own, its detail beside the name", fields: &[req("kind", "'shell'"), req("name", "string")] },
    Shape { name: "ModeEvent", open: false, doc: "`mode(board, …)` — the pair moved", fields: &[req("board", "string"), req("mode", "Mode"), req("claimant", "string | null"), req("local_trust", "boolean")] },
    Shape { name: "SessionDiedEvent", open: false, doc: "`session-died(session, reason)`", fields: &[req("session", "string"), req("reason", "DeathReason")] },
    Shape { name: "DeathReason", open: true, doc: "the reason a death carries: its `arm`, the trigger it names, and the arm's own members beside it", fields: &[req("arm", "'closed' | 'mode' | 'retired' | 'seeded' | 'blocked' | 'restart' | 'unreachable'")] },
    Shape { name: "DaemonEvent", open: false, doc: "`daemon(board, state)`", fields: &[req("board", "string"), req("state", "'running' | 'stopped' | 'unreachable'")] },
    Shape { name: "FeedEvent", open: false, doc: "`feed(board, update)`", fields: &[req("board", "string"), req("update", "FeedUpdate")] },
    Shape { name: "FeedUpdate", open: false, doc: "the `/changes` row verbatim, with `position` and `class` — THIS CRATE's definition of the update's shape, a `feed` event's `update` and a `changes` entry alike", fields: &[req("position", "number"), req("at", "number"), req("op", "string | null"), req("docs", "string[] | null"), req("class", "'published' | 'drafts'"), opt("session", "string"), opt("key", "string | null"), opt("time", "number | null"), opt("attest", "{ alg: string; sig: string } | null"), opt("new_prefix", "string"), opt("new_id", "number"), opt("link", "string"), opt("placed", "string"), opt("base_extent", "string | null")] },
    Shape { name: "IndexEvent", open: false, doc: "`index(board, session?, state)`", fields: &[req("board", "string"), req("session", "string | null"), req("state", "IndexState")] },
    Shape { name: "IndexState", open: true, doc: "the index's ten arms; the arm's own members beside it", fields: &[req("arm", "'none' | 'building' | 'widening' | 'complete' | 'at_the_floor' | 'resumed_from_the_floor' | 'unplaced' | 'past_the_ceiling' | 'newer_skep' | 'busy'")] },
    Shape { name: "MomentEvent", open: false, doc: "`moment(id, kind, data)` — a PUBLIC moment of a walk; answered by `answer(id, value)` — a string for a `label`, or `null` where its `data.default` names one, the answer then that default; a string for an `ask`; a boolean for a `yes_no` — or declined by `cancel(id)` where `answerable`", fields: &[req("id", "string"), req("kind", "'statement' | 'label' | 'ask' | 'yes_no'"), req("data", "unknown"), req("walk", "string"), req("board", "string | null"), req("answerable", "boolean")] },
    Shape { name: "Answer", open: false, doc: "`answer(id, value)` — `value` of the form its moment's kind takes (`MomentEvent`), else `malformed_args` naming `value`, the moment still waiting; `no_such_moment` where no moment of that id waits", fields: &[req("id", "string"), req("value", "unknown")] },
    Shape { name: "Cancel", open: false, doc: "`cancel(id)`", fields: &[req("id", "string")] },
    Shape {
        name: "HeldAnswer",
        open: false,
        doc: "the `op` answer where the burst's board is HELD (§3c): the shell's own answer, never `ack` — the page takes it as accepted and not acked; `cause` `other_window` where another window holds the board's held text and the burst is held in this one's memory alone, and `unwritable` — why — where the device refused the line or the held file is out of reach, the burst held in memory alone",
        fields: &[req("resp", "'held'"), req("held", "number"), req("cause", "string"), opt("unwritable", "string")],
    },
    Shape {
        name: "HeldRow",
        open: false,
        doc: "`held(session)` — one held burst of the acting principal at the session's board, in resend order (§3c.2): `held` the ordinal, `doc` the draft, `base` the resend's read start, `frame` the page's frame as composed (no attest), `sent` whether the burst may have landed — a dial whose answer was lost (the board's `internal_panic` among them), or a `poisoned` answer (§3c.2), `refusal` the board's verdict for a REFUSED run",
        fields: &[req("held", "number"), req("doc", "string"), req("base", "number"), req("frame", "unknown"), req("cause", "string"), req("sent", "boolean"), req("time", "number"), opt("refusal", "unknown")],
    },
    Shape {
        name: "HeldEvent",
        open: false,
        doc: "`held(board, session, {doc, held, state, cause?})` (§4b.2) — a document's held state as it moves, always under the session it is about (never the guest face, P39); `held` the count of lines still held on the document, `cause` the line's cause — the hold's token while `holding`, the refusal's token while `refused`; emitted at a hold's start, at each line's resolution or drop, and at each state the resend moves the document through — never when a principal's file is read at its session's open, whose lines `held(session)` lists",
        fields: &[req("board", "string"), req("session", "string"), req("doc", "string"), req("held", "number"), req("state", "'holding' | 'sending' | 'kept' | 'refused' | 'moved'"), opt("cause", "string")],
    },
    Shape { name: "Resolve", open: false, doc: "`resolve(session, {held, act})` — the person's act at a REFUSED run's face or a MOVED document's", fields: &[req("session", "string"), req("held", "number"), req("act", "'drop' | 'send'")] },
];

/// One call of the bridge as the file declares it: its name, its argument
/// object — the members of each form it takes, the session form first where
/// it takes the guest form beside it — and its result's type.
#[derive(Debug, Clone, Copy)]
pub(crate) struct CallRow {
    pub(crate) name: &'static str,
    pub(crate) forms: &'static [&'static [Field]],
    pub(crate) result: &'static str,
}

/// THE CALLS, as the bridge spells them — the `Bridge` interface's rows, one
/// per name of [`crate::CALLS`], the dispatch's list, in its order. The
/// suite holds the two lists equal, and every optional member a row of one
/// form declares to the form its row reads it in.
pub(crate) const CALL_ROWS: &[CallRow] = &[
    CallRow { name: "boards", forms: &[&[]], result: "BoardRow[]" },
    CallRow { name: "session", forms: &[&[req("board", "string"), opt("principal", "number")]], result: "SessionOpened" },
    CallRow { name: "close", forms: &[&[req("session", "string")]], result: "Empty" },
    CallRow { name: "keygen", forms: &[&[opt("label", "string")]], result: "Keygen" },
    CallRow { name: "fingerprint", forms: &[&[opt("select", "string"), opt("payload", "boolean")]], result: "FingerprintRow[]" },
    CallRow { name: "claim", forms: &[&[req("board", "string"), opt("principal", "number"), opt("name", "string"), opt("paper", "boolean")]], result: "Claimed" },
    CallRow { name: "enroll", forms: &[&[req("board", "string"), req("payload", "string"), opt("principal", "number")]], result: "Enrolled" },
    CallRow { name: "bind", forms: &[&[req("board", "string"), req("principal", "number"), req("account", "string"), req("origin", "string")]], result: "Bound" },
    CallRow {
        name: "recover",
        forms: &[&[req("board", "string"), opt("principal", "number"), opt("lost", "string[]"), opt("stolen", "boolean"), opt("anchorLost", "boolean")]],
        result: "Recovered",
    },
    CallRow { name: "rotate", forms: &[&[req("board", "string"), opt("principal", "number"), opt("label", "string"), opt("payload", "string")]], result: "Rotated" },
    CallRow { name: "retire", forms: &[&[req("board", "string"), opt("principal", "number"), req("fingerprint", "string")]], result: "Empty" },
    CallRow { name: "handoff", forms: &[&[req("board", "string"), req("account", "string"), opt("payload", "string"), opt("principal", "number")]], result: "HandoffDelegated | Empty" },
    CallRow {
        name: "accept",
        forms: &[&[req("board", "string"), req("address", "string"), opt("label", "string"), opt("paper", "boolean"), opt("noAnchors", "boolean")]],
        result: "Accepted",
    },
    CallRow { name: "health", forms: &[&[req("board", "string")]], result: "Health" },
    CallRow { name: "probe", forms: &[&[]], result: "Probe" },
    CallRow {
        name: "op",
        forms: &[&[req("session", "string"), req("frame", "unknown")], &[req("guest", "true"), opt("board", "string"), opt("origin", "string"), req("frame", "unknown")]],
        result: "unknown",
    },
    CallRow { name: "upload", forms: &[&[req("session", "string"), req("target", "string"), req("path", "string")]], result: "never" },
    CallRow {
        name: "fetch",
        forms: &[&[req("session", "string"), req("i", "string")], &[req("guest", "true"), opt("board", "string"), opt("origin", "string"), req("i", "string")]],
        result: "Uint8Array",
    },
    CallRow { name: "restore", forms: &[&[req("session", "string"), req("i", "string")]], result: "never" },
    CallRow {
        name: "search",
        forms: &[
            &[req("session", "string"), opt("board", "string"), req("query", "string"), opt("opts", "SearchOpts")],
            &[req("guest", "true"), opt("board", "string"), opt("origin", "string"), req("query", "string"), opt("opts", "SearchOpts")],
        ],
        result: "SearchAnswer",
    },
    CallRow {
        name: "places",
        forms: &[&[req("session", "string"), opt("board", "string"), opt("opts", "PlacesOpts")], &[req("guest", "true"), opt("board", "string"), opt("origin", "string"), opt("opts", "PlacesOpts")]],
        result: "PlacesAnswer",
    },
    CallRow { name: "held", forms: &[&[req("session", "string")]], result: "HeldRow[]" },
    CallRow { name: "resolve", forms: &[&[req("session", "string"), req("held", "number"), req("act", "'drop' | 'send'")]], result: "Empty" },
    CallRow { name: "changes", forms: &[&[req("session", "string"), req("since", "number"), opt("limit", "number")]], result: "ChangesAnswer" },
];

/// One form of a call's argument object as the file spells it: `{}` where
/// it carries no member, else `{ m: T; n?: U }`.
fn argument_object(form: &[Field]) -> String {
    if form.is_empty() {
        return "{}".to_string();
    }
    let members: Vec<String> = form.iter().map(Field::to_string).collect();
    format!("{{ {} }}", members.join("; "))
}

/// THE FILE: the preamble, the aliases, every shape, the refusal union,
/// the events, and the bridge's rows.
pub fn declarations() -> String {
    let mut out = String::new();
    out.push_str("// skep-shell — the bridge's declarations (client.md §4b), generated from\n");
    out.push_str("// the crate's tables (`SHAPES` and `CALL_ROWS` in `src/shapes.rs`); every\n");
    out.push_str("// field name of a value the shell answers or emits is pinned by the crate's\n");
    out.push_str("// own suite against the values its code builds, and every optional argument\n");
    out.push_str("// member against the row that reads it.\n\n");
    out.push_str("export type Mode = 'UNCLAIMED' | 'CLAIMED-PERMISSIVE' | 'ENFORCING';\n");
    out.push_str("export type Empty = Record<string, never>;\n");
    out.push_str("export type Standing = 'public' | 'yours_to_read' | { held: { kind: 'named' | 'any_principal'; rung: 'document' | 'account'; issuer: string } };\n");
    out.push_str("export interface SearchOpts { limit?: number; offset?: number; reindex?: boolean }\n");
    out.push_str("export interface PlacesOpts { under?: string }\n");
    out.push_str("export type Refusal = RefusedByBoard | HaltFace | BlockedFace | Unreachable | ShellRefusal;\n");
    out.push_str("export type Outcome<T> = { result: T } | { refused: Refusal };\n");
    let event_names: Vec<String> = EventName::ALL.iter().map(|name| format!("'{name}'")).collect();
    let _ = writeln!(out, "export type EventName = {};\n", event_names.join(" | "));
    for shape in SHAPES {
        let _ = writeln!(out, "/** {} */", shape.doc);
        let _ = writeln!(out, "export interface {} {{", shape.name);
        for f in shape.fields {
            let _ = writeln!(out, "  {f};");
        }
        if shape.open {
            out.push_str("  [member: string]: unknown;\n");
        }
        out.push_str("}\n\n");
    }
    out.push_str("/** The calls (client.md §4b.1, the document index's listing `places`, and the change feed's page `changes`): `POST /bridge/<name>` with the argument object; `{result}` or `{refused}` back. */\n");
    out.push_str("export interface Bridge {\n");
    for row in CALL_ROWS {
        let forms: Vec<String> = row.forms.iter().map(|form| argument_object(form)).collect();
        let _ = writeln!(out, "  {}(args: {}): Promise<Outcome<{}>>;", row.name, forms.join(" | "), row.result);
    }
    out.push_str("  answer(args: Answer): Promise<Outcome<Empty>>;\n");
    out.push_str("  cancel(args: Cancel): Promise<Outcome<Empty>>;\n");
    out.push_str("}\n");
    out
}

/// The shape named `name`, where the table holds one.
pub fn shape(name: &str) -> Option<&'static Shape> {
    SHAPES.iter().find(|s| s.name == name)
}

/// `value` held to the shape `name` declares: an object, every required
/// field present, and — the shape not `open` — no member outside the table.
/// The pin every suite holds a value the crate's code built to.
#[cfg(test)]
pub(crate) fn assert_declared(name: &str, value: &serde_json::Value) {
    let shape = shape(name).unwrap_or_else(|| panic!("`{name}` is declared"));
    let members = value.as_object().unwrap_or_else(|| panic!("a `{name}` is an object: {value}"));
    for field in shape.fields.iter().filter(|f| f.required) {
        assert!(members.contains_key(field.name), "{name}: `{}` is required: {value}", field.name);
    }
    if !shape.open {
        assert!(members.keys().all(|k| shape.fields.iter().any(|f| f.name == k)), "{name}: a member the table does not declare: {value}");
    }
}

#[cfg(test)]
mod tests;
