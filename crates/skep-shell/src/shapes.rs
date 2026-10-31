//! The page's declarations, generated from this crate's Rust types.
//!
//! FP-16 has it: "every value that crosses the bridge has its shape defined
//! on the Rust side and declared for the page from that definition".
//! [`declarations`] renders one TypeScript declaration file — every call's
//! input and output, every event, the refusal, the `feed` update's shape (a
//! `changes` entry's too), the index state's ten arms and the publication
//! family's panel, inputs and outcomes — from the table below, which is
//! written by hand beside the code that builds each value (`shell`,
//! `shell::publication`, `feed`, `sessions`, `refusal`, `person`, `hold`)
//! and pinned by this module's suite: a sample of each type, built as the
//! code builds it,
//! is round-tripped through `serde_json` and its field names held equal to
//! the table's. No generator crate: the table is the one source, and a field
//! renamed in the table alone, or in the code alone, fails the pin. The
//! calls' argument objects are data beside it (`CALL_ROWS`' members), and
//! the shell's suite sends each optional member a row of one form declares,
//! in a form its type refuses, to the row itself, which must refuse it by
//! name. The event names are rendered from `events::EventName` itself, the
//! type every event carries.

use std::fmt::{self, Write};

use crate::events::EventName;

/// One field of a declared type.
///
/// It holds its name, its TypeScript type, and whether every value carries
/// it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Field {
    /// The field's name.
    pub name: &'static str,
    /// The field's TypeScript type.
    pub ty: &'static str,
    /// Whether every value carries the field.
    pub required: bool,
}

/// A field as the declarations spell it: `name: T`, or `name?: T`.
///
/// The second form is a field a value may leave out — an interface's member
/// and a call's argument alike.
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

/// One declared type: an interface over its fields.
///
/// It comes with the line of doc the file carries above it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct Shape {
    /// The name the file declares the type under.
    pub name: &'static str,
    /// Whether a value carries members beyond the declared fields.
    ///
    /// Those are the arm's own members beside `arm`, the detail beside a
    /// shell refusal's `name` — declared as an index signature, and held by
    /// the pin to its required fields alone.
    pub open: bool,
    /// The line of doc the file carries above the type.
    pub doc: &'static str,
    /// The type's fields.
    pub fields: &'static [Field],
}

/// The table of every value that crosses the bridge.
///
/// Each is listed by the name the file declares it under.
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
    Shape {
        name: "RefusedByBoard",
        open: false,
        doc: "a refusal: the board's own verdict, verbatim; `site` the address and the entry the code names (`already_published`'s member, `kept_place_moved`'s `runs` entry, a deposit's entry in its own list), each absent where the code carries none",
        fields: &[req("kind", "'refused'"), req("name", "string"), req("status", "number"), req("code", "string"), req("detail", "string | null"), req("op", "string | null"), req("site", "{ addr?: string; index?: number }"), req("body", "unknown")],
    },
    Shape { name: "HaltFace", open: false, doc: "a refusal: a halt's face under the armed name", fields: &[req("kind", "'halt'"), req("name", "string"), req("state", "string"), req("cause", "string"), req("act", "string")] },
    Shape { name: "BlockedFace", open: false, doc: "a refusal: the block", fields: &[req("kind", "'blocked'"), req("name", "'blocked'"), req("record", "string"), req("named_by", "string"), req("ground", "string | null")] },
    Shape { name: "Unreachable", open: false, doc: "a refusal: the board is not answering", fields: &[req("kind", "'unreachable'"), req("name", "'unreachable'"), req("text", "string")] },
    Shape { name: "ShellRefusal", open: true, doc: "a refusal: the shell's own, its detail beside the name", fields: &[req("kind", "'shell'"), req("name", "string")] },
    Shape { name: "ModeEvent", open: false, doc: "`mode(board, …)` — the pair moved", fields: &[req("board", "string"), req("mode", "Mode"), req("claimant", "string | null"), req("local_trust", "boolean")] },
    Shape { name: "SessionDiedEvent", open: false, doc: "`session-died(session, reason)`", fields: &[req("session", "string"), req("reason", "DeathReason")] },
    Shape { name: "DeathReason", open: true, doc: "the reason a death carries: its `arm`, the trigger it names, and the arm's own members beside it — the `retired` arm's `own` null where the fork on whose key retired it cannot be taken (no record read, a hand the read could not name, or the shell's key store unlisted beside another hand), its `position` the one read whatever the hand (AUTH-5.77's no-hand form)", fields: &[req("arm", "'closed' | 'mode' | 'retired' | 'seeded' | 'blocked' | 'restart' | 'unreachable'")] },
    Shape { name: "DaemonEvent", open: false, doc: "`daemon(board, state)`", fields: &[req("board", "string"), req("state", "'running' | 'stopped' | 'unreachable'")] },
    Shape { name: "FeedEvent", open: false, doc: "`feed(board, update)`", fields: &[req("board", "string"), req("update", "FeedUpdate")] },
    Shape { name: "FeedUpdate", open: false, doc: "the `/changes` row verbatim, with `position` and `class` — THIS CRATE's definition of the update's shape, a `feed` event's `update` and a `changes` entry alike; a `drafts` row goes out once per session of its principal at the board, each event naming its own `session`", fields: &[req("position", "number"), req("at", "number"), req("op", "string | null"), req("docs", "string[] | null"), req("class", "'published' | 'drafts'"), opt("session", "string"), opt("key", "string | null"), opt("time", "number | null"), opt("attest", "{ alg: string; sig: string } | null"), opt("new_prefix", "string"), opt("new_id", "number"), opt("link", "string"), opt("placed", "string"), opt("base_extent", "string | null")] },
    Shape { name: "IndexEvent", open: false, doc: "`index(board, session?, state)` — a face's state where it moved: the guest's, `session` null, or a principal's, once per session of the principal at the board, each event naming its own", fields: &[req("board", "string"), req("session", "string | null"), req("state", "IndexState")] },
    Shape { name: "IndexState", open: true, doc: "the index's ten arms; the arm's own members beside it", fields: &[req("arm", "'none' | 'building' | 'widening' | 'complete' | 'at_the_floor' | 'resumed_from_the_floor' | 'unplaced' | 'past_the_ceiling' | 'newer_skep' | 'busy'")] },
    Shape { name: "MomentEvent", open: false, doc: "`moment(id, kind, data)` — a PUBLIC moment of a walk; answered by `answer(id, value)` — a string for a `label`, or `null` where its `data.default` names one, the answer then that default; a string for an `ask`; a boolean for a `yes_no` — or declined by `cancel(id)` where `answerable`", fields: &[req("id", "string"), req("kind", "'statement' | 'label' | 'ask' | 'yes_no'"), req("data", "unknown"), req("walk", "string"), req("board", "string | null"), req("answerable", "boolean")] },
    Shape { name: "Answer", open: false, doc: "`answer(id, value)` — `value` of the form its moment's kind takes (`MomentEvent`), else `malformed_args` naming `value`, the moment still waiting; `no_such_moment` where no moment of that id waits", fields: &[req("id", "string"), req("value", "unknown")] },
    Shape { name: "Cancel", open: false, doc: "`cancel(id)`", fields: &[req("id", "string")] },
    Shape {
        name: "HeldAnswer",
        open: false,
        doc: "the `op` answer where the burst's board is HELD (§3c): the shell's own answer, never `ack` — the page takes it as accepted and not acked; `cause` the hold's token, and `unwritable` — why — where the device refused the line or the held file is out of reach (another process's lock on the board's held store among the causes: one shell per data directory, §3c.3), the burst held in memory alone",
        fields: &[req("resp", "'held'"), req("held", "number"), req("cause", "string"), opt("unwritable", "string")],
    },
    Shape {
        name: "HeldRow",
        open: false,
        doc: "`held(session)` — one held burst of the acting principal at the session's board, in resend order (§3c.2): `held` the ordinal, `doc` the draft, `base` the resend's read start, `frame` the page's frame as composed (no attest), `sent` whether the burst may have landed — a dial whose answer was lost (the board's `internal_panic` among them), or a `poisoned` answer (§3c.2), `refusal` the verdict for a refused run — the board's, or the shell's `answers_lost` where it handed the person a line whose resends kept losing their answer (§3c.4), its `sent` kept",
        fields: &[req("held", "number"), req("doc", "string"), req("base", "number"), req("frame", "unknown"), req("cause", "string"), req("sent", "boolean"), req("time", "number"), opt("refusal", "unknown")],
    },
    Shape {
        name: "HeldEvent",
        open: false,
        doc: "`held(board, session, {doc, held, state, cause?, hands?})` (§4b.2) — a document's held state as it moves, always under the session it is about (never the guest face, P39); `held` the count of lines still held on the document, `cause` the line's cause — the hold's token while `holding`, the refusal's token while `refused`; `hands` with the `moved` state, EACH HAND ONCE, read off the `under=` rows since `base` the read already holds (§3c.5); emitted at a hold's start, at each line's resolution or drop, and at each state the resend moves the document through — never when a principal's file is read at its session's open, whose lines `held(session)` lists",
        fields: &[req("board", "string"), req("session", "string"), req("doc", "string"), req("held", "number"), req("state", "'holding' | 'sending' | 'kept' | 'refused' | 'moved'"), opt("cause", "string"), opt("hands", "Hand[]")],
    },
    Shape {
        name: "Hand",
        open: false,
        doc: "one hand whose row moved a held document (§3c.5): `own` this store's own key with its fingerprint, `other` another key with its fingerprint and the label the shell's key store holds for it (rendered inert), `bare` an unsigned hand under local trust, `lost` a row whose testimony the board lost — the data of the three forms the moved face draws, the strings `ux/copy.md`'s",
        fields: &[req("key", "HandKey"), opt("fingerprint", "string"), opt("label", "string")],
    },
    Shape { name: "Resolve", open: false, doc: "`resolve(session, {held, act})` — the person's act at a REFUSED run's face or a MOVED document's", fields: &[req("session", "string"), req("held", "number"), req("act", "'drop' | 'send'")] },
    Shape { name: "Run", open: false, doc: "one run of a selection, I-runs in V-order (P51): `width` positions of the document `origin`'s content I-space from the ordinal `i_start`", fields: &[req("origin", "string"), req("i_start", "number"), req("width", "number")] },
    Shape {
        name: "PublicationPanel",
        open: false,
        doc: "`publication.open(session, {draft, also?, base?, doc?, mint?, claim?, selection?, notes?, readable_drafts?, published?})` — THE PANEL: the composition's first steps run by the shell (`enumerate` → `panel` → the price), every member DATA with a code or a kind and never a string a person reads; `draft` the RENDERING draft, `also` the OTHER private drafts of the person's own whose words this publication re-mints as the document's own beside it (the Nelson way — the family: the staging draft and the alternatives made from it, never the notes), each keeping its own records; `base`, for a draft BEHIND the head, the member it was staged from or last re-windowed to, the page's own (the shell reads the head where it is absent) — so the shot lands a daughter under its own base; `rows` the sets in the RULED order — own, notes, private, public by address; `read_with` per published document of the person's whether the edition is read with it now; `count` at the switches' DEFAULT — every private row OFF; `price` the five terms against their caps, as the request would stand with every window kept private; `windows` the own-origin windows the three answers are asked for, the drafts `also` names EXCLUDED; `inherited` per draft `also` names, in its order, THE STATEMENT's count — the passages first written in it (B3-S11 P2 (i)); `hold` where a HELD publication of this draft stood and is re-opened as it stands, with the switches and answers the page last sent it (item 1 (a))",
        fields: &[req("rows", "PublicationRow[]"), req("formatting", "Formatting"), req("read_with", "Record<string, boolean>"), req("count", "Count"), req("price", "Price"), req("windows", "Window[]"), req("inherited", "Inherited[]"), opt("hold", "Hold")],
    },
    Shape {
        name: "PublicationRow",
        open: false,
        doc: "one set of the panel: `home` the set, `kind` own, notes, private or public with whether the edition is read with it, `label` the home's first line (rendered INERT, AUTH-5.2), `links` the row's offered links BY ADDRESS, `types` the fold by type with each type's count and its far documents, `line` the five counts P3's lines are drawn from, `read_through` the private move's share where the row stays OFF",
        fields: &[req("home", "string"), req("kind", "RowKind"), req("label", "string"), req("links", "string[]"), req("types", "TypeFold[]"), req("line", "RowLine"), req("read_through", "number")],
    },
    Shape { name: "TypeFold", open: false, doc: "the links of one type in a row: the type's address, how many of the row's links carry it, each far document they point into in address order", fields: &[req("ty", "string"), req("n", "number"), req("far", "string[]")] },
    Shape {
        name: "RowLine",
        open: false,
        doc: "the five counts of a row's line: ⟨p⟩ links with an end into a private document, ⟨d⟩ links with an end wholly on words of the draft the selection leaves out, ⟨c⟩ links with an end running past the selection's cut, ⟨t⟩ links typed by a private document, ⟨u⟩ revisions of links already published, not offered",
        fields: &[req("p", "number"), req("d", "number"), req("c", "number"), req("t", "number"), req("u", "number")],
    },
    Shape {
        name: "Formatting",
        open: false,
        doc: "the formatting line: `marks` the line's marks by address, `cut` how many run past the selection's cut, `removals` the held removals' job list — the spent and the off-selection dropped, the ⟨r⟩/⟨e⟩ split by `remake`",
        fields: &[req("marks", "string[]"), req("cut", "number"), req("removals", "Removal[]")],
    },
    Shape {
        name: "Removal",
        open: false,
        doc: "one held removal on the job list: `record` the `3.24` record in the draft, `mark` the published mark it names, `mark_value` the mark's value as stored, `on_selection` whether the mark is on the selection's words, `spent` whether a retraction of it already stands, `remake` the formatting-line mark that re-makes it, where one does",
        fields: &[req("record", "string"), req("mark", "string"), req("mark_value", "LinkValue"), req("on_selection", "boolean"), req("spent", "boolean"), req("remake", "string | null")],
    },
    Shape { name: "LinkValue", open: false, doc: "a link's value as stored: the three slots as spans, and the position of the commit that minted it — null where the board serves none", fields: &[req("from", "LinkSpan[]"), req("to", "LinkSpan[]"), req("ty", "LinkSpan[]"), req("at", "number | null")] },
    Shape { name: "LinkSpan", open: false, doc: "one span of a stored slot: its start and its width in their dotted spelling (wire.md §Value encodings)", fields: &[req("start", "string"), req("width", "string")] },
    Shape {
        name: "Count",
        open: false,
        doc: "`publication.count(session, {switches, answers})` — THE COUNT: PUB-3.8's four numbers as DATA (DECISION 5) — ⟨l⟩ the switched-on sets' `links` entries plus the `read_with` entries, ⟨n⟩ the formatting line's marks that re-make nothing, ⟨r⟩ the `retract` entries no re-make covers, ⟨e⟩ the re-makes — `claim` whether the one write carries the edition claim, `read_with` the entries the switches need: each switched-on row's destination other than the member, once, where the edition is not already read with it",
        fields: &[req("l", "number"), req("n", "number"), req("r", "number"), req("e", "number"), req("claim", "boolean"), req("read_with", "string[]")],
    },
    Shape {
        name: "Price",
        open: false,
        doc: "THE PRICE: the five terms against their caps — `lists` the five lists (`runs`, `places`, `links`, `retract`, `read_with`; 4,096 each), `body` the signed body (8 MiB), `values` the distinct draft-native positions (131,072), `reads` the in-lock reads (65,536), `bytes` the staged bytes (64 MiB) — and `over`, each term past its cap with how far: a non-empty `over` is refused `over_cap` at `confirm` BEFORE ANY FRAME (P13); `count` re-runs it over the rows as switched, so the caps are decided at P3 as a set flips",
        fields: &[req("lists", "number[]"), req("body", "number"), req("values", "number"), req("reads", "number"), req("bytes", "number"), req("over", "PriceOver[]")],
    },
    Shape { name: "PriceOver", open: false, doc: "one term of the price past its cap, and by how much", fields: &[req("term", "Term"), req("by", "number")] },
    Shape {
        name: "Window",
        open: false,
        doc: "one own-origin window P2 (i) asks the three answers for: a run of the selection that windows an unpublished draft of the person's own — the drafts `also` names EXCLUDED, their runs re-minted as the document's own words and not windowed (their count is `inherited`) — `run` the run's index in the selection (the key `answers` take), `origin` and `width` the run's own, `owner` the origin's account, `i_start` WHERE IN ⟨origin⟩ THE PASSAGE WAS WRITTEN (the run's first ordinal in ⟨origin⟩'s I-space), `counterpart` where a record of a draft the person reads names the run's words as published, offered FIRST and re-read at every open; NO ANSWER PRE-SELECTED (P50)",
        fields: &[req("run", "number"), req("origin", "string"), req("owner", "string"), req("i_start", "number"), req("width", "number"), opt("counterpart", "Counterpart")],
    },
    Shape {
        name: "Inherited",
        open: false,
        doc: "THE STATEMENT's count for one draft `also` names (B3-S11 P2 (i)'s statement before the act — \"⟨n⟩ passages first written in ⟨D⟩ publish as ⟨E⟩'s own words; ⟨D⟩ keeps a record of where they went\" — the statement itself the page's): `draft` the draft, `passages` ⟨n⟩ — the selection's runs of that origin, consecutive runs of one origin in the selection's V-order counted once; the rendering draft's own words are counted nowhere",
        fields: &[req("draft", "string"), req("passages", "number")],
    },
    Shape {
        name: "Counterpart",
        open: false,
        doc: "the counterpart offered first at a window: `record` the record of `draft`, a draft the person reads, that names the run's words as published — `from` the part of the run it covers, on the run's own chain, `to` the published span that part became",
        fields: &[req("run", "number"), req("draft", "string"), req("record", "string"), req("from", "ISpan"), req("to", "ISpan")],
    },
    Shape { name: "ISpan", open: false, doc: "a content I-span: `chain` the content chain (`document.0.1`), `first` its first ordinal, `width` its positions", fields: &[req("chain", "string"), req("first", "number"), req("width", "number")] },
    Shape { name: "Hold", open: false, doc: "a HELD publication re-opened (item 1 (a)): `since` when the panel was put behind another, in unix milliseconds", fields: &[req("since", "number")] },
    Shape {
        name: "Switches",
        open: false,
        doc: "`publication.count` and `publication.confirm` — the rows' switches: `on` the private rows switched ON by home, `destinations` per switched-on row its `Destination` — the member the shot mints, or another published document of the person's one pick away — the member where unnamed; a home no private row holds, or a set that is no published document of the person's, is refused `malformed_args`",
        fields: &[req("on", "string[]"), opt("destinations", "Record<string, Destination>")],
    },
    Shape {
        name: "Acknowledged",
        open: false,
        doc: "`publication.confirm` — THE ACKNOWLEDGMENT: `member` the member minted (`E.1` of the edition at the mint form), `edition` the edition minted at the mint form, `claim` whether the edition claim rode in the write (the request's own, echoed), `at` the commit's position, `via` how it was reached — `answer` the frame's own ack or the memo of the one re-ask, `twin` `already_published` READ AS THE ACKNOWLEDGMENT (the landed test passed at the member the refusal named), `records`, `walk` and `edition_claim` a lost answer's landed test; the page lands at P5",
        fields: &[req("outcome", "'acknowledged'"), req("member", "string"), req("edition", "string | null"), req("claim", "boolean"), req("at", "number"), req("via", "AckVia")],
    },
    Shape {
        name: "Restated",
        open: false,
        doc: "`publication.confirm` — THE RE-STATEMENT: P4's RE-READ found the draft moved since the panel — `left` links gone or retracted, `superseded` links a claim of the person's superseded since, `came` links arrived, `removals_undone` and `removals_came` the held removals' job list moved, `selection` held runs whose placement changed with where each stands now — NOTHING SENT (PUB-3.108): the page re-renders P2 from it and confirms again; `race` where the re-statement follows the board's `kept_place_moved`, the newest row under the draft since the request's reads and its key",
        fields: &[req("outcome", "'restated'"), req("left", "string[]"), req("superseded", "string[]"), req("came", "string[]"), req("removals_undone", "string[]"), req("removals_came", "string[]"), req("selection", "{ run: number; placement: Placement }[]"), opt("race", "RaceKey")],
    },
    Shape {
        name: "RaceKey",
        open: false,
        doc: "the race's key at a kept place moved: the feed's newest row under the draft since the request's reads — `at` its position, `key` whose write it was (a fingerprint, `bare`; null where lost or a signed entry), `signed` whether the row carries its own attest",
        fields: &[req("at", "number"), req("key", "string | null"), req("signed", "boolean")],
    },
    Shape {
        name: "PublicationRefused",
        open: true,
        doc: "`publication.confirm` — THE REFUSAL: a typed arm with its face's DATA beside `arm` and never a string — the library's `twin {member, missing}`, `kept_place_moved {index, race}` (where the re-read found no difference to re-state), `unowned_draft {draft}`, `not_owner {addr}`, `claim_refused {edition}` (crossing as the board answered it, nothing re-sent), `window_withheld {origin}`, `needs_signed_session`, `no_such_document`, `older_board {detail}`, `head_unreadable` (nothing sent), `session_ended {reason}`, `budget_race {detail}`, `may_already_stand`, `own_fault {fault}`, `other {refusal}` — and the shell's own two BEFORE ANY FRAME: `over_cap {over}` and `inert {inert}`",
        fields: &[req("outcome", "'refused'"), req("arm", "string")],
    },
    Shape {
        name: "PublicationEvent",
        open: true,
        doc: "`publication(board, session, {draft, state, …})` (§4b.2) — THE STATE OF THE ONE REQUEST as it moves: `sent` (the frame left the shell), `acknowledged {member, edition, at}` (the commit stands), `restated` (the re-read found a difference; nothing sent), `refused {arm}` (the arm by name, its data in `confirm`'s answer), `cancelled` (the standing panel dropped by `cancel`), `ended` (the session died with the panel standing or held — gone with it); fired at `confirm`'s send and at its outcome, at `cancel`, and at the session's death",
        fields: &[req("board", "string"), req("session", "string"), req("draft", "string"), req("state", "'sent' | 'acknowledged' | 'restated' | 'refused' | 'cancelled' | 'ended'")],
    },
];

/// One call of the bridge as the file declares it.
///
/// It holds its name, its argument object — the members of each form it
/// takes, the session form first where it takes the guest form beside it —
/// and its result's type.
#[derive(Debug, Clone, Copy)]
pub(crate) struct CallRow {
    pub(crate) name: &'static str,
    pub(crate) forms: &'static [&'static [Field]],
    pub(crate) result: &'static str,
}

/// The calls as the bridge spells them: the `Bridge` interface's rows.
///
/// There is one per name of [`crate::CALLS`], the dispatch's list, in its
/// order. The suite holds the two lists equal, and every optional member a
/// row of one form declares to the form its row reads it in.
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
    CallRow {
        name: "publication.open",
        forms: &[&[
            req("session", "string"),
            req("draft", "string"),
            opt("also", "string[]"),
            opt("base", "string"),
            opt("doc", "string"),
            opt("mint", "string"),
            opt("claim", "boolean"),
            opt("selection", "Run[]"),
            opt("notes", "string[]"),
            opt("readable_drafts", "string[]"),
            opt("published", "string[]"),
        ]],
        result: "PublicationPanel",
    },
    CallRow { name: "publication.count", forms: &[&[req("session", "string"), opt("switches", "Switches"), opt("answers", "Record<string, OriginAnswer>")]], result: "{ count: Count; price: Price }" },
    CallRow { name: "publication.confirm", forms: &[&[req("session", "string"), opt("switches", "Switches"), opt("answers", "Record<string, OriginAnswer>")]], result: "Acknowledged | Restated | PublicationRefused" },
    CallRow { name: "publication.cancel", forms: &[&[req("session", "string")]], result: "Empty" },
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

/// The publication family's closed unions, each a type alias the file
/// declares ahead of the shapes (the crate's enums, spelled as the values
/// the shell answers spell them).
pub const ALIASES: &[&str] = &[
    "export type RowKind = 'own' | 'notes' | 'private' | { public: { read_with: boolean } };",
    "export type Destination = 'member' | { set: string };",
    "export type OriginAnswer = 'publish_first' | 'drop' | 'keep_private' | 'counterpart';",
    "export type Placement = { whole: { ordinal: number } } | { split: [number, number, number][] } | 'absent';",
    "export type Term = 'runs' | 'places' | 'links' | 'retract' | 'read_with' | 'body' | 'values' | 'reads' | 'bytes';",
    "export type AckVia = 'answer' | 'twin' | 'records' | 'walk' | 'edition_claim';",
    "export type Inert = 'unchanged' | { unanswered: number[] } | { publish_first: number[] };",
    "export type Missing = { copy: number } | { retraction: number };",
    "export type HandKey = 'own' | 'other' | 'bare' | 'lost';",
];

/// Returns a call's name as a method of the `Bridge` interface: quoted where
/// it carries a `.`, as the `publication` family's do.
fn method_name(name: &str) -> String {
    if name.contains('.') {
        format!("'{name}'")
    } else {
        name.to_string()
    }
}

/// Returns one form of a call's argument object as the file spells it.
///
/// It is `{}` where it carries no member, else `{ m: T; n?: U }`.
fn argument_object(form: &[Field]) -> String {
    if form.is_empty() {
        return "{}".to_string();
    }
    let members: Vec<String> = form.iter().map(Field::to_string).collect();
    format!("{{ {} }}", members.join("; "))
}

/// Returns the declaration file.
///
/// It holds the preamble, the aliases, every shape, the refusal union, the
/// events, and the bridge's rows.
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
    for alias in ALIASES {
        out.push_str(alias);
        out.push('\n');
    }
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
    out.push_str("/** The calls (client.md §4b.1 — the `publication` family's four among them — the document index's listing `places`, and the change feed's page `changes`): `POST /bridge/<name>` with the argument object; `{result}` or `{refused}` back. */\n");
    out.push_str("export interface Bridge {\n");
    for row in CALL_ROWS {
        let forms: Vec<String> = row.forms.iter().map(|form| argument_object(form)).collect();
        let _ = writeln!(out, "  {}(args: {}): Promise<Outcome<{}>>;", method_name(row.name), forms.join(" | "), row.result);
    }
    out.push_str("  answer(args: Answer): Promise<Outcome<Empty>>;\n");
    out.push_str("  cancel(args: Cancel): Promise<Outcome<Empty>>;\n");
    out.push_str("}\n");
    out
}

/// Returns the shape named `name`, where the table holds one.
pub fn shape(name: &str) -> Option<&'static Shape> {
    SHAPES.iter().find(|s| s.name == name)
}

/// Holds `value` to the shape `name` declares.
///
/// It is an object, every required field present, and — the shape not
/// `open` — no member outside the table: the pin every suite holds a value
/// the crate's code built to.
///
/// # Panics
///
/// Panics where `name` is not declared, `value` is no object, a required
/// field is missing, or — the shape not `open` — a member lies outside the
/// table.
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
