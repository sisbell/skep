//! The page's declarations, generated from this crate's Rust types.
//!
//! FP-16 has it: "every value that crosses the bridge has its shape defined
//! on the Rust side and declared for the page from that definition".
//! [`declarations`] renders one TypeScript declaration file — every call's
//! input and output, every event, the refusal, the `feed` update's shape (a
//! `changes` entry's too), the index state's ten arms, the publication
//! family's panel, inputs and outcomes, the merge family's report and
//! outcomes, and the past state's and the restore's answers with the merge
//! marker each carries — from the table below, which is
//! written by hand beside the code that builds each value (`shell`,
//! `shell::publication`, `shell::merge`, `shell::history`, `feed`,
//! `sessions`, `refusal`, `person`, `hold`)
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
    Shape {
        name: "BoardRow",
        open: false,
        doc: "`boards()` — one entry per board in the shell's list; `board` the opaque reference every board-touching call takes; this machine's notebook absent from the list while the shell holds it unstarted — before `node.start`, the notebook door's act, or `node.restart` has started it, and again once a stop whose `/health` read found it unclaimed has stopped it, `node.stop`'s or a claim's cancel or close (L1)",
        fields: &[req("board", "string"), req("name", "string"), req("origin", "string")],
    },
    Shape {
        name: "SessionOpened",
        open: false,
        doc: "`session(board, principal)` — the session's opaque reference in the token's place; `writes` whether the session itself may write: the signed mode's session writes, the bare mode's keyless one reads alone and has every write refused `write_in_bare_session` — the board's own state can refuse a write beside it: the own node stopped, its writes halted or its write path poisoned (§3c.4), which this answer does not report, or another shell holding its held store (§3c.3), which it reports; `fingerprint` the key the session was opened with, a signed session's, spelled as the `fingerprint()` rows spell it — the page takes the key's label from the row of that fingerprint and never works the key out from the rows' bindings, which cannot tell two keys bound for one principal apart — and `null` for a bare session, which holds none (skep #579); `another_window` present, `true`, only while another shell over the data directory holds the board's held store as the session opens — every write at the board refused `another_window`, nothing held and nothing sent, whatever `writes` says — every later edge of that state an `another-window` event (skep #827); `opened_at` the board's position read before the session opened, where its drafts feed starts — the position a page keeps as its last drafts row's (`draftsAt`) until a row moves it, and reads `changes(session, since, class: 'drafts')` from after the session's end",
        fields: &[req("session", "string"), req("principal", "number"), req("account", "string | null"), req("writes", "boolean"), req("fingerprint", "string | null"), opt("opened_at", "number"), opt("another_window", "true")],
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
    Shape {
        name: "Probe",
        open: false,
        doc: "`probe()` — the state the `daemon` event says of the own node or, where the shell runs none, the first board, taken after the call's own `/health` read: the most severe that holds, `stopped`, `unreachable`, `halted`, `head_unreadable` with its `reason`, else `running`; `node.start`, the notebook door's act, answers it once the node is started, a node already running started no second time; `node.stop` once the node is stopped, a node already stopped asked nothing; and `node.restart` once the node is stopped and started again — the act that clears a halt, a poison or a silence, the start's door asked before anything stops — a stopped notebook's restart its start (L1)",
        fields: &[req("daemon", "'running' | 'stopped' | 'unreachable' | 'halted' | 'head_unreadable'"), opt("reason", "string"), req("dialed", "string | null"), req("signed", "string | null")],
    },
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
        doc: "`changes(session, since, limit?, class?, under?)` and its guest form — what changed since the position `since`: the entries in the `feed` update's shape, oldest first, each `published` or `drafts` by the read that answered it — under a session two reads, the published feed as a guest and the session's drafts supplement under its token, merged by position; with `class: 'drafts'`, the one value the member takes, the drafts supplement's page alone (a page's read, from the session's `opened_at`, of the drafts rows an end cut off before it regained a session); as a guest, `{guest: true, board?, origin?, since, limit?, under?}`, the published feed alone, token-free (no `class`); with `under`, an address of any level in its one spelling — a draft, a document, an account — every read the form makes is the board's `under=` narrowing (PUB-7.31): the rows whose reduced `docs` name a document at or under it, masked as the plain feed is, so a draft the caller may not read answers no row, `next` at the head — one draft's history, a row per change with its `key` or `attest` and its `time` (skep #652), the wire's two residues of lost testimony standing (wire.md §The change feed, Narrowings); `next` the position to ask from next time, past every entry answered and never past one withheld — under `under`, a position of the narrowed feed: asked again with the same `under` it misses no row under the address, and it read no row outside it, so a page keeps it apart from the positions it holds for the whole feed (`feedAt`, `draftsAt`) and never moves those by it; `head` the board's latest position, read before the page, and the floor `history_reclaimed` names the board's, narrowed or not; the shell keeps no position — every form reads from `since`",
        fields: &[req("entries", "FeedUpdate[]"), req("next", "number"), req("head", "number")],
    },
    Shape {
        name: "RefusedByBoard",
        open: false,
        doc: "a refusal: the board's own verdict, verbatim; `site` the fault's place as the wire names it (wire.md §Rejections), each member absent where the code carries none — `addr` the address the code names (`already_published`'s member, `not_owner`'s document, `withheld`'s origin), `index` the entry (`kept_place_moved`'s `runs` entry, a deposit's entry in its own list) and `fault` the span fault beside it, `operand` and `region` a compare input's, `slot` an `edit_link` successor's slot, `as_of` and `current` an `arrangement_moved`'s two states — the one the refused burst was typed against, echoed, and the position the document's arrangement last changed at",
        fields: &[
            req("kind", "'refused'"),
            req("name", "string"),
            req("status", "number"),
            req("code", "string"),
            req("detail", "string | null"),
            req("op", "string | null"),
            req("site", "{ addr?: string; index?: number; operand?: 'first' | 'second'; region?: number; slot?: number; fault?: string; as_of?: number; current?: number }"),
            req("body", "unknown"),
        ],
    },
    Shape { name: "HaltFace", open: false, doc: "a refusal: a halt's face under the armed name", fields: &[req("kind", "'halt'"), req("name", "string"), req("state", "string"), req("cause", "string"), req("act", "string")] },
    Shape { name: "BlockedFace", open: false, doc: "a refusal: the block", fields: &[req("kind", "'blocked'"), req("name", "'blocked'"), req("record", "string"), req("named_by", "string"), req("ground", "string | null")] },
    Shape { name: "Unreachable", open: false, doc: "a refusal: the board is not answering", fields: &[req("kind", "'unreachable'"), req("name", "'unreachable'"), req("text", "string")] },
    Shape {
        name: "HeldLinesRefusal",
        open: false,
        doc: "a refusal: the shell's own `held_lines` (§3c.4, THE HELD-LINES GATE; skep #849, #854) — a whole-draft write (`history.restore`, `merge.land`, `merge.undo`, `merge.withdraw`, `publication.confirm` over the rendering draft or a draft `also` names) refused at the shell's one write door, nothing sent, while `doc`, a draft it writes, holds `held` lines of the acting principal's the board has not kept, in any state (holding, sending, refused, moved, `head_unreadable`, `session_died`); the page draws the slot inert ahead of the act with B3-S13's row rule (\"⟨label⟩ holds words the board has not kept — resolve them where they are marked, then take this\"), and this is that rule's answer for a write that arrives anyway: `held(session)` lists the lines, `resolve` acts on each, the write then goes out; a burst on such a draft is held `behind` the lines, never refused so",
        fields: &[req("kind", "'shell'"), req("name", "'held_lines'"), req("doc", "string"), req("held", "number")],
    },
    Shape {
        name: "WindowPartsOwedRefusal",
        open: false,
        doc: "a refusal: the shell's own `window_parts_owed` (skep #932) — `merge.land`, or an agent's merge tool once one lands, met a window part with no answer: nothing was published, and the landing composes no answer the caller did not give, at any window part. FINAL in meaning and the same for every caller, `skep merge --publish`'s printed refusal composed from the same library data. `parts` every part that needs an answer, `answers` the answers that stand beside them, `misfits` an answer of the shot's that fits nothing or names words another also answers, `left_private` the private sets the shot left out of `merge.land` (each with its count, none at the shot), `defaults` the merge's places left at their defaults (kind, where, as placed). `merge.land` then again with `answers` in the panel's form, each part keyed `⟨run⟩.⟨part⟩`",
        fields: &[req("kind", "'shell'"), req("name", "'window_parts_owed'"), req("parts", "WindowPart[]"), req("answers", "WindowPart[]"), req("misfits", "WindowMisfit[]"), req("left_private", "LeftPrivate[]"), req("defaults", "MergeDefault[]")],
    },
    Shape {
        name: "LandingUnreadRefusal",
        open: false,
        doc: "a refusal: the shell's own `landing_unread` (§3c.4; skep #866, #983) — `resolve(session, {held, act: 'drop'})` under a session that may write, on a line marked `sent` that is holding or handed over as `answers_lost`, reads for the line's landing before it drops anything, since a dial whose answer was lost can commit late and a `poisoned` commit is rebuilt at the board's restart — no read where the shell knows no dial of the line left this device; where that read cannot tell, nothing is dropped and the drop is refused naming `held`, the line, and `why`: `unanswered` the board gave the read no answer, or is not answering the shell, which then makes no read; `unread` the board answered it with no page; `undecided` a row could be the line's landing and the read could not confirm it; `stopped`, `poisoned` or `halted` that hold stands at the board, no read made — the drop is asked again once the board answers and takes writes, and an `undecided` line leaves by `send` where it was handed over, which the board judges by its typed state, and by the probe's resend where it is holding; the page draws the line as still held, never as discarded",
        fields: &[req("kind", "'shell'"), req("name", "'landing_unread'"), req("held", "number"), req("why", "'unanswered' | 'unread' | 'undecided' | 'stopped' | 'poisoned' | 'halted'")],
    },
    Shape {
        name: "NoOwnNodeRefusal",
        open: false,
        doc: "a refusal: the shell's own `no_own_node` (L1) — `node.start`, `node.stop` or `node.restart` at a shell that runs no node on this machine, the verb that opened it having handed it no start and stop of one, as a shell over boards elsewhere hands none; `call` the call refused; nothing is started or stopped, and `boards()` lists what it listed",
        fields: &[req("kind", "'shell'"), req("name", "'no_own_node'"), req("call", "string")],
    },
    Shape {
        name: "OtherPanelRefusal",
        open: false,
        doc: "a refusal: the shell's own `other_panel` (skep #956) — `merge.land` where the family's panel of the draft the composition landed in, standing or held, publishes into another document than the composition's or mints an edition: a shot through it would publish the merge outside the document merged, so nothing is composed or sent, and that panel with every switch and answer the person set, the family's standing panel and the composition stand as they were; `draft` the draft, and exactly one of `doc`, the document the panel publishes into, and `mint`, the account it mints an edition under, as `publication.open` took them; the way on is `publication.cancel` of that panel — a held one re-opened by `publication.open` first — then `merge.land` again, which opens its own panel at the composition's document; confirming that panel instead publishes the draft as a document of its own, and the next `merge.land` is refused `base_unrecorded`",
        fields: &[req("kind", "'shell'"), req("name", "'other_panel'"), req("draft", "string"), opt("doc", "string"), opt("mint", "string")],
    },
    Shape {
        name: "ShellRefusal",
        open: true,
        doc: "a refusal: the shell's own, its detail beside the name (`held_lines`'s declared whole as `HeldLinesRefusal`, `window_parts_owed`'s as `WindowPartsOwedRefusal`, `landing_unread`'s as `LandingUnreadRefusal`, `no_own_node`'s as `NoOwnNodeRefusal`, `other_panel`'s as `OtherPanelRefusal`)",
        fields: &[req("kind", "'shell'"), req("name", "string")],
    },
    Shape { name: "ModeEvent", open: false, doc: "`mode(board, …)` — the pair moved", fields: &[req("board", "string"), req("mode", "Mode"), req("claimant", "string | null"), req("local_trust", "boolean")] },
    Shape { name: "SessionDiedEvent", open: false, doc: "`session-died(session, reason)`", fields: &[req("session", "string"), req("reason", "DeathReason")] },
    Shape {
        name: "DeathReason",
        open: true,
        doc: "the reason a death carries: its `arm`, the trigger it names, and the arm's own members beside it, each declared here and present on its arm alone, `fingerprint` on two — the `restart` arm's `reopened`, with `session` the reference the shell re-opened silently in the dead one's place and `fingerprint` the key that session was opened with where it did (the page takes the key from here as it takes a session's from the `session` answer; skep #579), and `refused` the name of the re-open's refusal where one was tried and refused; the `mode` arm's `mode`, the pair the bare session died at the flip to; the `unreachable` arm's `text`; the `retired` arm's `fingerprint`, the key retired, `own`, `hand`, `position` and `label` — `own` null where the fork on whose key retired it cannot be taken (no record read, a hand the read could not name, or the shell's key store unlisted beside another hand), its `position` the one read whatever the hand (AUTH-5.77's no-hand form); the `seeded` arm's `account`, `as_of` and `writer`; the `blocked` arm's `record` and `ground`; the `closed` arm carries nothing beside",
        fields: &[
            req("arm", "'closed' | 'mode' | 'retired' | 'seeded' | 'blocked' | 'restart' | 'unreachable'"),
            opt("reopened", "boolean"),
            opt("session", "string"),
            opt("refused", "string"),
            opt("mode", "Mode"),
            opt("text", "string"),
            opt("fingerprint", "string"),
            opt("own", "boolean | null"),
            opt("hand", "string | null"),
            opt("position", "number | null"),
            opt("label", "string | null"),
            opt("account", "string"),
            opt("as_of", "number"),
            opt("writer", "string | null"),
            opt("record", "string"),
            opt("ground", "string | null"),
        ],
    },
    Shape {
        name: "DaemonEvent",
        open: false,
        doc: "`daemon(board, state)` — the board's state, the most severe that holds, once per change, never repeated at a tick: `stopped` and `running` as the own node's owner stops and starts it, nothing else said while the stop stands — a notebook the shell starts itself says nothing before `node.start`, `running` at that start and at `node.restart`'s, and `stopped` at `node.stop`, at `node.restart` before its start, and at a claim's cancel or close that stops it unclaimed (L1); else `unreachable` where a `/health` read of the board goes unanswered, the probe's verdict alone, never one request's failure, the commit stream's among them (P37; skep #863); else `halted` where a `/health` read says the board's writes are halted; else `head_unreadable` where the board's head record will not read, `reason` saying why, told before any write meets it (§3c.3; skep #865); else `running`. A board halted whose head record will not read says `halted`, then `head_unreadable` when the halt clears, then `running`",
        fields: &[req("board", "string"), req("state", "'running' | 'stopped' | 'unreachable' | 'halted' | 'head_unreadable'"), opt("reason", "string")],
    },
    Shape { name: "FeedEvent", open: false, doc: "`feed(board, update)`", fields: &[req("board", "string"), req("update", "FeedUpdate")] },
    Shape { name: "FeedUpdate", open: false, doc: "the `/changes` row verbatim, with `position` and `class` — THIS CRATE's definition of the update's shape, a `feed` event's `update` and a `changes` entry alike; a `drafts` row goes out once per session of its principal at the board, each event naming its own `session`", fields: &[req("position", "number"), req("at", "number"), req("op", "string | null"), req("docs", "string[] | null"), req("class", "'published' | 'drafts'"), opt("session", "string"), opt("key", "string | null"), opt("time", "number | null"), opt("attest", "{ alg: string; sig: string } | null"), opt("new_prefix", "string"), opt("new_id", "number"), opt("link", "string"), opt("placed", "string"), opt("base_extent", "string | null"), opt("base", "string | null"), opt("merge", "{ sides: string[]; head: string } | null")] },
    Shape { name: "IndexEvent", open: false, doc: "`index(board, session?, state)` — a face's state where it moved: the guest's, `session` null, or a principal's, once per session of the principal at the board, each event naming its own", fields: &[req("board", "string"), req("session", "string | null"), req("state", "IndexState")] },
    Shape { name: "IndexState", open: true, doc: "the index's ten arms; the arm's own members beside it", fields: &[req("arm", "'none' | 'building' | 'widening' | 'complete' | 'at_the_floor' | 'resumed_from_the_floor' | 'unplaced' | 'past_the_ceiling' | 'newer_skep' | 'busy'")] },
    Shape { name: "MomentEvent", open: false, doc: "`moment(id, kind, data)` — a PUBLIC moment of a walk; answered by `answer(id, value)` — a string for a `label`, or `null` where its `data.default` names one, the answer then that default; a string for an `ask`; a boolean for a `yes_no` — or declined by `cancel(id)` where `answerable`", fields: &[req("id", "string"), req("kind", "'statement' | 'label' | 'ask' | 'yes_no'"), req("data", "unknown"), req("walk", "string"), req("board", "string | null"), req("answerable", "boolean")] },
    Shape { name: "Answer", open: false, doc: "`answer(id, value)` — `value` of the form its moment's kind takes (`MomentEvent`), else `malformed_args` naming `value`, the moment still waiting; `no_such_moment` where no moment of that id waits", fields: &[req("id", "string"), req("value", "unknown")] },
    Shape { name: "Cancel", open: false, doc: "`cancel(id)`", fields: &[req("id", "string")] },
    Shape {
        name: "HeldAnswer",
        open: false,
        doc: "the `op` answer where the burst's board is HELD (§3c): the shell's own answer, never `ack` — the page takes it as accepted and not acked; `cause` the hold's token — the line's own, though a line ahead of it on its document that awaits the person's act keeps that line's state in front on the `held` event (skep #974); `session_died` where the death signal met the burst, at its dial or, the board having refused it as typed against an older state, at the shell's read for its shift or for the hands that moved its document, the session then ended and its `session-died` naming the arm (§3c.4) — and `unwritable` — why — where the device refused the line's copy, or refused a copy the held file still owes an earlier line of the principal's at the board — its first copy, a re-mark or its `done` (the line waits behind it, both written in order once the device takes them) — or refused the held store itself: the held directory or its lock could not be made, the held file could not be read, or an earlier run's lines in it could not be renumbered past this run's — the burst held in memory alone, owed to the file, and written at the first retry the device takes (a board unclaimed or away, or whose head will not read, keeps no line in memory: its lines go to the pending file from the first touch, and another shell's hold on the store refuses the burst `another_window` instead, §3c.3); and `unwritable_class` beside `unwritable`, always with it, the class the page keys its act by, read off the refusal's kind and never its words, which differ by platform (§3c.3's face): `full` a full disk or a spent quota, which space freed on this device ends, the shell's retry then writing the line, `read_only` a read-only volume or a write the shell has no right to make, which no space freed ends, `other` every other kind of I/O refusal — a line waiting behind a refused copy carrying that copy's class unchanged",
        fields: &[req("resp", "'held'"), req("held", "number"), req("cause", "string"), opt("unwritable", "string"), opt("unwritable_class", "'full' | 'read_only' | 'other'")],
    },
    Shape {
        name: "HeldRow",
        open: false,
        doc: "`held(session)` — one held burst of the acting principal at the session's board, in resend order (§3c.2): `held` the ordinal — the line's for the shell's life, naming it until it leaves and no other line after (skep #856) — `doc` the draft, `base` the resend's read start, `frame` the wire frame (no attest) — the page's as composed, or as the shell last shifted it through another writer's change, every position it names moved by one displacement and its `as_of` the state they are true of, its `id` the page's own: a resend dials the line under an `id` the shell draws for it, `shell:` and hex, which never crosses the bridge, and no burst of the page's may carry that prefix (skep #971) — `anchors` the page's, where the burst carried them (the `op` row's member): the identities on either side of the span the frame edits and, for a delete or a rearrange, the I-runs of the units it holds, by which the shell shifts it — an edge naming words the board has not minted yet an `AnchorPiece` until the line it names is kept and the shell places it at the words' address, and the whole member absent once that line left the queue with no address of them known (skep #969) — `sent` whether a dial of the line was attempted since the last read, so it may have landed — a first dial whose answer was lost (the board's `internal_panic` among them), a `poisoned` answer, or any resend, which marks its line before it dials (§3c.2) — kept through a move, and read for its landing before the person's drop drops the line, save where the shell knows no dial of it left this device (`Resolve`; skep #866, #983), `refusal` the verdict for a refused run — the board's, a refusal at a resend under a code the shell's table holds nowhere among them, handed to the person at once, or the shell's `answers_lost` where it handed the person a line no landing of which was found two minutes after its first failed send, whatever the failure (§3c.4): `last` the last failure's token, the held cause or the board's, and `elapsed_ms` the milliseconds since that first failed send — its `sent` kept, a drop of it then reading for its landing first (`Resolve`; skep #866); at a line held `moved` because the board refused it as typed against an older state and the shift could not move it through the change exactly, the board's `arrangement_moved` (`site.as_of` the state it was typed against, `site.current` the document's); at a line held `head_unreadable`, the shell's refusal naming why its signature could not be made, the line holding all the same (SP-14); at a line held `session_died`, the shell's `session_died` refusal once the session's end derives the death, its `reason` the death's arm (§4b.2; the `retired` arm's `own` among its members), the line holding all the same until a session of the principal's that may write stands and resends it (§3c.4); `sendable` on a moved document's first moved line (§3c.5; skep #867): what `resolve(send)` would do now, true where it would shift the line into the text as it now stands, false where it would hold it moved again — always false for a line with no anchors or no span, a burst an agent sent among them — and absent where the shell does not know, the image read having gone unanswered or been refused, and under the keyless session; it never changes what `resolve` does; `hands` on each moved line of a moved document, the lines behind the one the board's verdict rides among them, which the same writes moved (skep #973, #989): the hands whose rows moved it, as the `held` event names them (`Hand`), for the verdict the document stands on now — those this session was told or listed for that verdict, named with no read, else read for this session as the call is made (one `/changes` page for each such document, or two where the board refused its burst again with no row since the person's `send`, none at a board not answering or with the own node stopped), or the one hand `unread` where no page named them, read again by the shell's walk, which then says the `moved` state with them under this session, or the one hand `unknowable` where the board has reclaimed the history the read asks for, which no read can name — never the hands of an earlier move, and absent where they name no hand; `again`, true, beside `hands` where the board refused the burst again with no row since the person's `send`, the hands those the face that `send` acknowledged named (skep #989); the call says no event; `unwritable`, with `unwritable_class` always beside it, as the `op` answer spells them (`HeldAnswer`), while the line stands on no file — in memory alone, the device having refused its copy or a copy owed before it, so a close loses it — and absent once the retry writes it (§3c.3; skep #860); a line parked on the pending file has a copy a close keeps and carries neither, and a line whose `done` the file still owes has left the queue and is on no row",
        fields: &[req("held", "number"), req("doc", "string"), req("base", "number"), req("frame", "unknown"), opt("anchors", "Anchors"), req("cause", "string"), req("sent", "boolean"), req("time", "number"), opt("refusal", "unknown"), opt("sendable", "boolean"), opt("hands", "Hand[]"), opt("again", "true"), opt("unwritable", "string"), opt("unwritable_class", "'full' | 'read_only' | 'other'")],
    },
    Shape {
        name: "Anchors",
        open: false,
        doc: "the identities a burst's edit is placed by (skep #442, #751), sent beside the frame on the `op` row and kept with the held line, never on the wire — the whole within the board's frame cap as compact JSON, anchors past it refused `malformed_args` naming `anchors`: `before` the I-address of the unit just before the span the burst edits, `after` the I-address of the unit just after it — in the tumbler-string form `image` answers an `i_start` in, the run's position added — each `null` at the document's edge, or an `AnchorPiece` naming words of a burst the board has not minted yet, which the shell places at their address once it has (skep #969); an insert, a copy or a reinstate names the units on either side of its `at`, a delete those on either side of its `width` positions from `p`, a rearrange those on either side of its first cut to its last; `span`, for a delete and a rearrange alone, the I-runs of the units between the two, in V order, as the page's `image` read gave them — `start` an I-address, `width` a natural of 1 or more as a decimal string, the widths summing to the span's positions; where the board refuses the burst as typed against an older state, the shell finds `before` and `after` in the document's current image and, where each stands at one place and the units between them are the span's own — none for an insert, a copy or a reinstate, so the two stand adjacent; for a delete or a rearrange its `span`, compared run for run with adjacent runs joined on both sides, so a span another writer cut, filled, emptied and refilled with as many others, or rearranged is not whole — moves every position the frame names by their one displacement and sends it again; else the document is held as moved; a burst sent without anchors, or a delete or a rearrange without its `span`, is held as moved there",
        fields: &[req("before", "string | AnchorPiece | null"), req("after", "string | AnchorPiece | null"), opt("span", "{ start: string; width: string }[]")],
    },
    Shape {
        name: "AnchorPiece",
        open: false,
        doc: "an edge of a burst's `Anchors` naming words the board has not minted yet (skep #969): the unit `offset` positions — counted from 0 as the board seats them, a byte of a string, one per atom — into the words of the insert the session sent on the same document with the envelope `id` `burst`, a string of at most 128 bytes; where that insert stands held, the burst holds `behind` its line, and once that line is kept the shell places the edge at the I-address the insert's words were minted at advanced by `offset` — read off its ack's `addr`, or, where the resend found its landing, off an `image` of its site at the position the landing was confirmed at — the held file's `done` carrying the address; where it is no longer held, the newest insert of that `id` kept on the document among the session's principal's last 64 the shell remembers places the edge at once; else the burst is refused `no_such_burst` `{anchor, burst}`, `anchor` the edge, and `malformed_args` naming `anchors.before` or `anchors.after` where the burst named is no insert or `offset` is not below its positions, nothing held or dialed; a line whose named words left the queue with no address of them known — dropped, or kept where no read found their address — loses its anchors, said in the shell's own window, and is held as moved where the board refuses it as typed against an older state; `burst` names the newest insert of its `id` among the principal's — held under any of its sessions, the one a restart re-opens among them — so a page keeps its ids unique across its reloads and the principal's other pages",
        fields: &[req("burst", "string"), req("offset", "number")],
    },
    Shape {
        name: "BurstPiece",
        open: false,
        doc: "a PIECE of a follower write's end (§3c.6; the `op` row's `after`): an element of a `make_link`'s `from` or `to` in the I-span form `{spans: […]}`, beside its `{start, width}` spans, naming `width` positions of the words of the insert `burst` — the follower's own `after` — from its `offset`, counted from 0 in positions as the board seats them: a byte of a string, one per atom, never characters; resolved at the insert's ack to the I-span `{start: <the ack's I-address advanced by offset>, width: '<width>'}`, so a mark over the words of two bursts is sent as two followers. A FOLLOWER is a `make_link` or a `nullify` sent with `after`, the `id` of a burst its session sent — any of the five kinds, a piece after an insert alone (else `malformed_args` naming the slot, as for a piece past the insert's positions): it waits for that burst's answer and the followers of it before it, then is sent and answered with its own answer where the burst was acked — and at the shell's stop, behind the window, before any session closes; refused `not_followed` `{after, why, cause?}`, nothing written and nothing held, with `why` `burst` and the burst's `cause` — the hold's token, or the refusal's name — where the burst was not acked, `ahead` where a follower of the same burst before it was not acked (a chord's writes are one step), `ack` where the burst's ack names no I-address its pieces resolve against, `stop` where the shell's stop came before the burst's answer; `no_such_burst` `{after}` where no burst of that `id` reached the session's table within a second of the follower; a session that ends under a follower answers it as a call on the ended session",
        fields: &[req("burst", "string"), req("offset", "number"), req("width", "number")],
    },
    Shape {
        name: "HeldEvent",
        open: false,
        doc: "`held(board, session, {doc, held, state, cause?, hands?, again?, landed?})` (§4b.2) — a document's held state as it moves, always under the session it is about (never the guest face, P39); `held` the count of lines still held on the document, `cause` the line's cause — the hold's token while `holding`, the refusal's token while `refused`; while the document's first line awaits the person's act, `refused` or `moved`, every event for the document says that line's state, whatever line it is said for — a burst held behind it, a line kept or told behind it, a landing — the lines behind it changing `held` alone, while the `op` answer names the burst's own cause (`HeldAnswer`; skep #974); `hands` with the `moved` state, EACH HAND ONCE, read off the `under=` rows since the burst's typed state or the person's last `send` on the document, whichever is later (a document moved again after that `send` names only the hands since it; one the board refused again with no row since names again the hands the face that `send` acknowledged named, read from where it read them, with `again`, true, beside them, never no hand — skep #989), for the verdict the document stands on now: a session told, or listed, an earlier move's hands hears the current move's, read for it, never the earlier ones again (skep #973) — the board's refusal of it as typed against an older state (`arrangement_moved`), at its first dial or at a resend, where the shell could not shift the burst through the change exactly (no anchors, a delete or a rearrange without its span, an anchor lost or at two places, the span between them cut or refilled), is the one route to `moved`; a burst it shifts is sent again and lands, no `moved` said; a shift whose live read the board gave no answer to is not tried and says no `moved`, the document `holding` until the board answers; the resend's read judges only whether the line's own write landed (§3c.5); emitted at a hold's start, at each line's resolution or drop, and at each state the resend moves the document through — the one document a resend the board's silence cut back to `holding`, the documents the pass did not reach said nothing (skep #863) — never when a principal's file is read at its session's open, whose lines `held(session)` lists, nor for a line a call enters, shifts and settles within itself, whose ack the `op` answer carries; `landed` on the event that says a line kept after its `op` answered `held` — its ack at a resend, the landing the resend's read found, a drop's read that found it landed — that line's one entry (`LandedLine`), said on that event whatever the event last said, so a keep that leaves the state and count as they stood is said all the same, and never said again: the one place the page learns a resent line's ack (skep #968), and a page that was not listening as it was said learns of the landing as it does with no event, the line gone from `held(session)`, the feed's `drafts` row at the landing's `at`, an `image` read showing the words; `sendable` with the `moved` state, as the document's first moved line's row carries it (`HeldRow`; skep #867), the event sent again, its hands named, where the answer moves to or from true — a row that names the document, a read after an unanswered one, or the first test after a launch, the probe after a session's open — and never for false against absent, the page holding its act inert on both; `unwritable`, with `unwritable_class` always beside it, while a line of the document stands on no file, the refusal it waits behind in the words the `op` answer spells it (`HeldAnswer`), and absent once none does — within one probe of the retry writing the document's lines, the event said again under each session of the principal with its state, cause, hands, `again` and `sendable` as last told — a session told nothing of a document that stands moved, or told another move's hands, hearing it with the hands read for it, or the one hand `unread` or `unknowable` (skep #972, #973, #989) — so the page's face for a line this device could not keep lifts as the copy lands (§3c.3; skep #860)",
        fields: &[req("board", "string"), req("session", "string"), req("doc", "string"), req("held", "number"), req("state", "'holding' | 'sending' | 'kept' | 'refused' | 'moved'"), opt("cause", "string"), opt("hands", "Hand[]"), opt("again", "true"), opt("sendable", "boolean"), opt("unwritable", "string"), opt("unwritable_class", "'full' | 'read_only' | 'other'"), opt("landed", "LandedLine[]")],
    },
    Shape {
        name: "LandedLine",
        open: false,
        doc: "one held line that left the store kept, as the `held` event names it (§4b.2; skep #968): `held` the line's ordinal, the one the `op` call's `held` answer named; `burst` the envelope `id` the page sent on the frame (A-60), absent where it sent none; `at` the position the board took the line at — its ack's `at` (A-62, A-63), or the position the resend's read found its landing at — absent where the read found it under a reclaimed history; `addr` the first I-address an insert's `ack_addr` minted (A-63), absent for the other kinds and for a landing the read found, which no ack names: the page reads the image there for those",
        fields: &[req("held", "number"), opt("burst", "string"), opt("at", "number"), opt("addr", "string")],
    },
    Shape {
        name: "Hand",
        open: false,
        doc: "one hand whose row moved a held document (§3c.5): `own` this store's own key with its fingerprint, `other` another key with its fingerprint and its label rendered inert — the one the shell's key store holds for it, else the one the account's verified credential records give it, another device's key thus named by its enrolled label, and absent where neither names one (skep #869) — `bare` an unsigned hand under local trust, `lost` a row whose testimony the board lost — the data of the three forms the moved face draws, the strings `ux/copy.md`'s; `unread`, the one hand, where no page of the rows named them after a real verdict — the board gave the read no answer or answered it with no page (a refusal), the read met the death signal, or none was made at a board not answering or an own node stopped — the hands not read yet, never `lost`, read again as the shell's walk meets the document, under every session told or listed them so, and the `moved` state said once more with them (skep #863, #972, #973); `unknowable`, the one hand, where the board has reclaimed the history the read asks for (`410 history_reclaimed`): its floor never moves down, so no read can name them and none is made for them again, a later verdict, after the person's `send`, read afresh from its own position (skep #989)",
        fields: &[req("key", "HandKey"), opt("fingerprint", "string"), opt("label", "string")],
    },
    Shape {
        name: "Resolve",
        open: false,
        doc: "`resolve(session, {held, act})` — the person's act on a held line: `send` at a refused run's face or a moved document's, handing the document's waiting lines back to the probe, and refused `not_resolvable` on a line holding, which the probe sends; `drop` on any line, a holding one among them, with every later line of its document; neither act on a line a resend, or a first dial's shift within its call, has out for its dials, refused `not_resolvable` (skep #983); answered `{}`, save a `drop` under a session that may write of a line marked `sent` that is holding or handed over as `answers_lost`, which reads for the line's landing first unless the shell knows no dial of it left this device (§3c.4; skep #866, #983): a landing found keeps the line, nothing dropped, the lines behind it going out in order, answered `{kept: true}`; none that could be its landing drops it, answered `{}`; a read that cannot tell drops nothing, refused `landing_unread` (`LandingUnreadRefusal`); a read the death signal met ends the session, `session_died` — the page takes the outcome from the answer, the `held` event saying `kept` with `held: 0` after a drop as after a keep",
        fields: &[req("session", "string"), req("held", "number"), req("act", "'drop' | 'send'")],
    },
    Shape {
        name: "AnotherWindowEvent",
        open: false,
        doc: "`another-window(board, another_window)` (§3c.3; skep #827, #828, #873) — another shell's hold on the board's held store, at each edge of that state: `true` where a session's open or a probe finds another shell over the data directory holding a lock of the store, the pending directory's or the board's own — every write at the board refused `another_window` from then, nothing held and nothing sent — and `false` where this shell takes the locks, the pending one's and the board's own where a term has read, at a later session's open or at a probe; emitted once at each edge, and never at an open or a probe that finds no change — the `session` answer's `another_window` gives the state as a session opens",
        fields: &[req("board", "string"), req("another_window", "boolean")],
    },
    Shape { name: "Run", open: false, doc: "one run of a selection or of a past state's arrangement (`Past`), I-runs in V-order (P51): `width` positions of the document `origin`'s content I-space from the ordinal `i_start`", fields: &[req("origin", "string"), req("i_start", "number"), req("width", "number")] },
    Shape {
        name: "PublicationStanding",
        open: false,
        doc: "`publication.standing(session, {draft, doc, also?})` — A DRAFT's STANDING READ ALONE (skep #864): where the draft stands against its document, in the members the panel carries, read before the person starts publishing and so with no panel composed, none left standing and none disturbed, no event said and nothing held: `base` the base the board records for the draft in `doc`'s chain, `standing` that base typed against the document's head, `head` where it is `behind` the trunk's newest member, the version the draft's corner names, `left_behind` the drafts of the family its publication leaves behind by address — every draft `also` names, then, where it becomes the head (`at_head`, `first`), every other draft of the person's own whose recorded base is this draft's. It is a read: it asks no write door, so a second window reads it; a session with no key is refused `write_in_bare_session`. A draft the board records no base for in `doc`'s chain is refused `base_unrecorded {draft, doc, reason}`, a `doc` of another chain among them — `other_chain` — as `publication.open` refuses it",
        fields: &[req("base", "string"), req("standing", "BaseStanding"), opt("head", "string"), req("left_behind", "string[]")],
    },
    Shape {
        name: "PublicationPanel",
        open: false,
        doc: "`publication.open(session, {draft, also?, doc?, mint?, claim?, selection?, notes?, readable_drafts?, published?})` — THE PANEL: the composition's first steps run by the shell (`enumerate` → `panel` → the price), every member DATA with a code or a kind and never a string a person reads; `draft` the RENDERING draft, `also` the OTHER private drafts of the person's own whose words this publication re-mints as the document's own beside it (the Nelson way — the family: the staging draft and the alternatives made from it, never the notes), each keeping its own records; the draft's BASE the shell's own read off the board, never the page's — the base the board records for the draft, the version its `stage` copied (the bare document while the chain is empty) or the member its newest publication made — so the shot lands after it, or as its daughter where the trunk has moved past it; a draft the board records no base for is refused `base_unrecorded {draft, doc, reason}` — `reason` `no_record` (minted and never staged), `other_chain` (a base in another document's chain) or `free_standing` (an alternative of a draft with no base) — the one refusal of a base, every standing of a recorded one told; `rows` the sets in the RULED order — own, notes, private, public by address; `read_with` per published document of the person's whether the edition is read with it now; `count` at the switches' DEFAULT — every private row OFF — and every window awaiting its answer, which counts toward nothing; `price` the five terms against their caps, as the request would stand with every window part a record names taken by its counterpart and every other kept private; `windows` the own-origin windows, each in its PARTS with the answers each part admits (B3-S11 P2 (i)), the drafts `also` names EXCLUDED; `parts` what each part's answer brings, the answered row's clause's data; `inherited` per draft `also` names, in its order, THE STATEMENT's count — the passages first written in it (B3-S11 P2 (i)); `merge_records` per named draft whose runs of the selection hold any, in the selection's order, the merge records the publication leaves out — no publication publishes a merge record, so a journal's records stay private and its arrangement keeps them, and a selection of merge records alone is refused `only_merge_records {draft}`; `edition_links` how many of the document's own links lie on the words this publication re-inserts — the ⟨n⟩ of the link-sets design §5.2's line \"⟨n⟩ of ⟨E⟩'s own links on these words stay on this draft's earlier words\", read once at the open, nothing written for them and no answer changing it; `p3_stands` whether P3 stands (E4 1.4): a private row holding a link not unchanged since the recorded base, the formatting line's marks or listed removals, a re-offered original, a public row's link on words this version publishes as new, or `edition_links` above zero — where none stands, P2's own line says the links stayed private; `standing` the base TYPED against the document's head before any act — `at_head`, `behind` (told and never refused: the shot lands the base's daughter, the head unmoved, `head` beside it the trunk's newest member, the version the draft's corner names), `first` (the bare document, its chain empty) or `superseded_first` (the draft was begun from the bare document and version 1 has since been published: told, never refused — the shot lands beside version 1 as its daughter, the head unmoved) — absent at the mint form; `left_behind` the drafts of the family this publication leaves behind, by address: every draft `also` names, then, where it becomes the head (`at_head`, `first`), every other draft of the person's own whose recorded base is this draft's — empty at the mint form; `hold` where a HELD publication of this draft stood and is re-opened as it stands, with the switches and answers the page last sent it (item 1 (a)), its standing typed again",
        fields: &[req("rows", "PublicationRow[]"), req("formatting", "Formatting"), req("read_with", "Record<string, boolean>"), req("count", "Count"), req("price", "Price"), req("windows", "Window[]"), req("parts", "PartCounts[]"), req("inherited", "Inherited[]"), req("merge_records", "MergeRecords[]"), req("edition_links", "number"), req("p3_stands", "boolean"), opt("standing", "BaseStanding"), opt("head", "string"), req("left_behind", "string[]"), opt("hold", "Hold")],
    },
    Shape {
        name: "PublicationRow",
        open: false,
        doc: "one set of the panel: `home` the set, `kind` own, notes, private or public with whether the edition is read with it, `label` the home's first line (rendered INERT, AUTH-5.2), `links` the row's offered links BY ADDRESS, `types` the fold by type with each type's count and its far documents, `line` the five counts P3's lines are drawn from, `read_through` the private move's share where the row stays OFF, `unchanged` the row's links UNCHANGED SINCE THE RECORDED BASE (E4 1.1: made before the version the request's `base` names, every word it touches on the selection held by that version, none new) BY ADDRESS, in `links`' order, `fold` the two counts (E4 1.8) — a private row whose every link is unchanged is drawn compact, one with any changed whole, folded by change; where the base is no version member nothing is unchanged — and `changed_types` and `unchanged_types` the same fold by type as `types` over each side of `fold` alone (E4 1.3): a row folded by change draws its head's type counts and far documents from `changed_types`, not `types`, and the line under it from `unchanged_types`, a far document reached from both sides standing in both",
        fields: &[req("home", "string"), req("kind", "RowKind"), req("label", "string"), req("links", "string[]"), req("types", "TypeFold[]"), req("line", "RowLine"), req("read_through", "number"), req("unchanged", "string[]"), req("fold", "RowFold"), req("changed_types", "TypeFold[]"), req("unchanged_types", "TypeFold[]")],
    },
    Shape { name: "TypeFold", open: false, doc: "the links of one type among those a row's fold by type takes: the type's address, how many of those links carry it, each far document they point into in address order", fields: &[req("ty", "string"), req("n", "number"), req("far", "string[]")] },
    Shape { name: "RowFold", open: false, doc: "a row's links counted by the fold's test (E4 1.8): `unchanged` those unchanged since the recorded base, `changed` the rest", fields: &[req("unchanged", "number"), req("changed", "number")] },
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
        doc: "one held removal on the job list: `record` the `3.24` record in the draft, `mark` the published mark it names, `mark_value` the mark's value as stored, `on_selection` whether the mark is on the selection's words, `spent` whether a retraction of it already stands, `remake` the formatting-line mark that re-makes it, where one does; `original` the person's own original the mark stands for — the `old` of the mark's accept claim, found from the copy — where the mark is of the formatting types and such a claim stands, which the one commit ENDS with the mark through the request's `originals` rider (outside the signed body), null for a mark of another type or one with no original standing; `rest` the original's words no copy ever covered, kept formatted by a fresh mark of its type in the one commit, empty where none",
        fields: &[req("record", "string"), req("mark", "string"), req("mark_value", "LinkValue"), req("on_selection", "boolean"), req("spent", "boolean"), req("remake", "string | null"), req("original", "string | null"), req("rest", "ISpan[]")],
    },
    Shape { name: "LinkValue", open: false, doc: "a link's value as stored: the three slots as spans, and the position of the commit that minted it — null where the board serves none", fields: &[req("from", "LinkSpan[]"), req("to", "LinkSpan[]"), req("ty", "LinkSpan[]"), req("at", "number | null")] },
    Shape { name: "LinkSpan", open: false, doc: "one span of a stored slot: its start and its width in their dotted spelling (wire.md §Value encodings)", fields: &[req("start", "string"), req("width", "string")] },
    Shape {
        name: "Count",
        open: false,
        doc: "`publication.count(session, {switches, answers})` — THE COUNT: PUB-3.8's four numbers as DATA (DECISION 5) — ⟨l⟩ the switched-on sets' `links` entries plus the `read_with` entries, ⟨n⟩ the formatting line's marks that re-make nothing, ⟨r⟩ the `retract` entries no re-make covers, ⟨e⟩ the re-makes — `claim` whether the one write carries the edition claim, `read_with` the entries the switches need: each switched-on row's destination other than the member, once, where the edition is not already read with it; `supersede` THE SUPERSESSION CLAIM the one write carries — the published daughters the draft's merge marker names, each one claim in the commit marking the daughter superseded by the member (the slot's merge form, B3-S11's THE MERGE SCENE) — composed by the shell off the board's marker alone, never session memory, at the open and again at a confirm that finds the draft's base moved or a `merge.land` over a panel read under another marker (`MergeLanded`), and ONLY where the marker's head is the trunk's head as read there: empty at an unmarked draft, at a marked draft behind the head, and at a draft-side merge, whose side is a private draft no public claim supersedes",
        fields: &[req("l", "number"), req("n", "number"), req("r", "number"), req("e", "number"), req("claim", "boolean"), req("read_with", "string[]"), req("supersede", "string[]")],
    },
    Shape {
        name: "Price",
        open: false,
        doc: "THE PRICE: the five terms against their caps — `lists` the six lists (`runs`, `places`, `links`, `retract`, `read_with`, `originals`; 4,096 each), `body` the signed body (8 MiB), `values` the distinct draft-native positions (131,072), `reads` the in-lock reads (65,536), `bytes` the staged bytes (64 MiB) — and `over`, each term past its cap with how far: a non-empty `over` is refused `over_cap` at `confirm` BEFORE ANY FRAME (P13); `count` re-runs it over the rows as switched, so the caps are decided at P3 as a set flips",
        fields: &[req("lists", "number[]"), req("body", "number"), req("values", "number"), req("reads", "number"), req("bytes", "number"), req("over", "PriceOver[]")],
    },
    Shape { name: "PriceOver", open: false, doc: "one term of the price past its cap, and by how much", fields: &[req("term", "Term"), req("by", "number")] },
    Shape {
        name: "Window",
        open: false,
        doc: "one window P2 (i) asks its answers at: a run of the selection that windows an unpublished draft of the person's own or, at a merge, another account's unpublished document (skep #932; a published origin is never asked) — the drafts `also` names EXCLUDED, their runs re-minted as the document's own words and not windowed (their count is `inherited`) — `run` the run's index in the selection, `origin` and `width` the run's own, `owner` the origin's account, `i_start` WHERE IN ⟨origin⟩ THE PASSAGE WAS WRITTEN (the run's first ordinal in ⟨origin⟩'s I-space), `parts` the stretches the draft arranges of it, cut where a record of a draft the person reads names its words as published, each answered on its own and re-read at every open; NO ANSWER PRE-SELECTED (P50), and a window awaiting its answer counts toward nothing",
        fields: &[req("run", "number"), req("origin", "string"), req("owner", "string"), req("i_start", "number"), req("width", "number"), req("parts", "Part[]")],
    },
    Shape {
        name: "Part",
        open: false,
        doc: "one part of a window — the key `answers` take is `⟨run⟩.⟨part⟩` — `from` its words on ⟨origin⟩'s chain, `ordinal` where the draft arranges its first word, `admits` the answers it takes: where a record names its words as published, `record` that record and `to` the published words it names — THE COUNTERPART — and `admits` the counterpart (\"window them from version ⟨j⟩\") and `drop` alone, a placeholder over words anyone reads at the published version being no answer; where none does, `publish_first`, `drop` and `keep_private`, `publish_first` not at another account's words, which are not the person's to publish",
        fields: &[req("part", "number"), req("from", "ISpan"), req("ordinal", "number"), req("admits", "OriginAnswer[]"), opt("record", "string"), opt("to", "ISpan")],
    },
    Shape {
        name: "WindowPart",
        open: false,
        doc: "one window part as the landing names it — a part that needs an answer in `window_parts_owed`, or an answer given in `MergeLanded.answers`: `run` and `part` its key as `publication.confirm` takes it (`⟨run⟩.⟨part⟩`), `words` its first words (`null` where the merger may not read them) and `after` the words it stands after in the merged text (`null` at the start, empty where the words before are not readable), each rendered inert; `ordinal` its first position in the merged text; `origin` its origin, `owner` that origin's owner where it is not the person; `span` its words on the origin's chain; where a record names them as published, `record` the record, `counterpart` the published words it names and `version` ⟨E.j⟩, the member that publishes them; `sides` each published side of the merge whose version shows the part as a placeholder; `admits` the answers it takes; `answer` the answer given, where one stands; `named_since` whether a record named the part only after its answer was given (PUB-3.108)",
        fields: &[req("run", "number"), req("part", "number"), req("words", "string | null"), req("after", "string | null"), req("ordinal", "number"), req("origin", "string"), req("owner", "string | null"), req("span", "ISpan"), req("record", "string | null"), req("counterpart", "ISpan | null"), req("version", "string | null"), req("sides", "string[]"), req("admits", "OriginAnswer[]"), req("answer", "OriginAnswer | null"), req("named_since", "boolean")],
    },
    Shape {
        name: "WindowMisfit",
        open: false,
        doc: "one answer of `skep merge --publish`'s the landing cannot place: `flag` the answer (`window`, `leave_out`, `keep_private`) and `key` its address; with `second`, two answers name the same words; without it, the answer fits nothing here, `published_in` the versions that publish the words of an origin the answer named where a record names all of them",
        fields: &[req("flag", "'window' | 'leave_out' | 'keep_private'"), opt("second", "'window' | 'leave_out' | 'keep_private'"), req("key", "string"), req("published_in", "string[]")],
    },
    Shape { name: "LeftPrivate", open: false, doc: "a private set the landing left out, as `merge.land`'s acknowledgment and refusal name it (`stayed private: ⟨links⟩ links in ⟨set⟩ — your next version offers them again`)", fields: &[req("set", "string"), req("links", "number")] },
    Shape { name: "MergeDefault", open: false, doc: "one of the merge's places left at its default, as the reveal lists them: `id` its gap, `kind`, `after` and `before` its anchors, `placed` as placed", fields: &[req("id", "number"), req("kind", "'order' | 'anchor' | 'corner' | 'cut' | 'collision' | 'moves'"), req("after", "string | null"), req("before", "string | null"), req("placed", "number[] | 'after' | 'before' | 'omitted'")] },
    Shape {
        name: "PartCounts",
        open: false,
        doc: "what one window part's answer brings — the data of the answered row's clause (B3-S11 P2 (i)), the words the page's: the part by `run` and `part`; taken by its counterpart, `marks` the formatting line's marks on the published words, which go out with them, and `links` the private rows' offered links on them, offered next; kept behind a placeholder, `kept_marks` the person's formatting marks on its words, which stay in the draft until a version shows them; zeros at a part left out or awaiting its answer",
        fields: &[req("run", "number"), req("part", "number"), req("marks", "number"), req("links", "number"), req("kept_marks", "number")],
    },
    Shape {
        name: "Inherited",
        open: false,
        doc: "THE STATEMENT's count for one draft `also` names (B3-S11 P2 (i)'s statement before the act — \"⟨n⟩ passages first written in ⟨D⟩ publish as ⟨E⟩'s own words; ⟨D⟩ keeps a record of where they went\" — the statement itself the page's): `draft` the draft, `passages` ⟨n⟩ — the selection's runs of that origin, consecutive runs of one origin in the selection's V-order counted once; the rendering draft's own words are counted nowhere",
        fields: &[req("draft", "string"), req("passages", "number")],
    },
    Shape {
        name: "MergeRecords",
        open: false,
        doc: "the merge records of one named draft the selection holds, which the publication leaves out — the data of \"⟨n⟩ merge records in ⟨label⟩ stay private and are not published with it\" (one: \"1 merge record in ⟨label⟩ stays private and is not published with it\"), the statement the page's: `draft` the draft the records were written in, `n` ⟨n⟩",
        fields: &[req("draft", "string"), req("n", "number")],
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
        doc: "`publication.confirm` — THE ACKNOWLEDGMENT: `member` the member minted (`E.1` of the edition at the mint form), `edition` the edition minted at the mint form, `claim` whether the edition claim rode in the write (the request's own, echoed), `supersede` the daughters the write claimed superseded — the panel's `count.supersede` as sent, less a daughter an active claim of the person's own already named, which the board skips and the request leaves out — `at` the commit's position, `via` how it was reached — `answer` the frame's own ack or the memo of the one re-ask, `twin` `already_published` READ AS THE ACKNOWLEDGMENT (the landed test passed at the member the refusal named), `records`, `walk` and `edition_claim` a lost answer's landed test; the page lands at P5",
        fields: &[req("outcome", "'acknowledged'"), req("member", "string"), req("edition", "string | null"), req("claim", "boolean"), req("supersede", "string[]"), req("at", "number"), req("via", "AckVia")],
    },
    Shape {
        name: "Restated",
        open: false,
        doc: "`publication.confirm` — THE RE-STATEMENT: P4's RE-READ found the draft moved since the panel — `left` links gone or retracted, `superseded` links a claim of the person's superseded since, `came` links arrived, `removals_undone` and `removals_came` the held removals' job list moved, `selection` held runs whose placement changed with where each stands now, `places` the whole places a run standing at more than one since the panel is carried at — or THE DRAFT'S BASE, or its STANDING, moved — NOTHING SENT (PUB-3.108; D4 (b′)): the page re-renders P2 from it and confirms again; `parts` the window parts named, un-named or named by another record since the panel — an origin published meanwhile — each `{run, part, record}` with the record naming it now, null where none does, its answer asked again unless it left the words out; `left_out` where the board refused an entry by its LINEAGE (B3-S11 P4) — its words already carrying its copy (`superseded`), or its original retracted (`retracted`) — the entry by its index, the original, the cause: the original left out of the panel from then on, the re-statement saying what the version now publishes, never the own-bug class alone; `race` where the re-statement follows the board's `kept_place_moved`, the newest row under the draft that refusal named — the rendering draft, or one `also` names — since the request's reads and its key, or a lineage refusal a change of the person's since those reads explains, the newest row under that change's home; `base` where the draft's recorded base differs from the panel's in member or extent — another publication of this draft or a merge landed in it since the panel, which a moved standing need not show (`at_head` both times where the draft itself made the new head) — the base as the re-read read it, present only then: the panel re-composed on it and the claim on the marker as it stands (`Count.supersede`), so the next confirm sends against that base and the request's `base` is the member the panel was tested against; a panel of the whole draft re-takes what the draft now arranges, `selection` then empty, the runs' indices no longer lining up, a draft emptied since keeping the held runs, re-stated absent — a selection the page passed stays held, re-stated over what is left, and a confirm over one the draft has wholly left is refused `selection_not_arranged`, nothing sent; `standing` where the base's standing moved since the panel — a sibling's shot landing while it stood, `at_head` → `behind`, `first` → `superseded_first` for a draft begun from the bare document, whose shot then lands beside version 1 as its daughter, or a newer head while the draft stays `behind` — as the re-read typed it, the panel's own from then on, `head` beside it the trunk's newest member where it is `behind` (a re-read finding the base no longer recorded refuses as the open does, `base_unrecorded`)",
        fields: &[
            req("outcome", "'restated'"),
            req("left", "string[]"),
            req("superseded", "string[]"),
            req("came", "string[]"),
            req("removals_undone", "string[]"),
            req("removals_came", "string[]"),
            req("selection", "{ run: number; placement: Placement }[]"),
            opt("parts", "{ run: number; part: number; record: string | null }[]"),
            opt("left_out", "{ entry: number; original: string; cause: 'superseded' | 'retracted' }[]"),
            opt("race", "RaceKey"),
            opt("base", "string"),
            opt("standing", "BaseStanding"),
            opt("head", "string"),
        ],
    },
    Shape {
        name: "RaceKey",
        open: false,
        doc: "the race's key at a kept place moved: the feed's newest row under the draft the refusal named — the rendering draft, or a draft `also` names, each re-windowed in the one write — since the request's reads — `at` its position, `key` whose write it was (a fingerprint, `bare`; null where lost or a signed entry), `signed` whether the row carries its own attest",
        fields: &[req("at", "number"), req("key", "string | null"), req("signed", "boolean")],
    },
    Shape {
        name: "PublicationRefused",
        open: true,
        doc: "`publication.confirm` — THE REFUSAL: a typed arm with its face's DATA beside `arm` and never a string — the library's `twin {member, missing}`, `kept_place_moved {index, draft, race}` (where the re-read found no difference to re-state: `draft` the draft that no longer holds the entry's words at the place the panel read — the rendering draft, or one `also` names, each re-windowed at its own places in the one write — and `race` whose write moved them, read under that draft), `unowned_draft {draft}`, `not_owner {addr}`, `claim_refused {edition}` (crossing as the board answered it, nothing re-sent), `window_withheld {origin}`, `needs_signed_session`, `no_such_document`, `older_board {detail}`, `head_unreadable` (nothing sent), `session_ended {reason}`, `budget_race {detail}`, `may_already_stand`, `base_superseded {first}` (the board's refusal of a request naming NO base while the document holds its first member, `first` — a shape this shell never sends at the document form, where the request's base is the board's record and a draft begun from the bare document lands beside version 1; carried for the library's raw callers; nothing published), `own_fault {fault}` (the library's own composition at fault, `fault` by its `kind` — `stray_place {index, draft}`, a kept place beside a run of published identity no record names whole, in the draft named; `deposit {code, index, detail}`; `shot {code}`; `attest {detail}`; `budget {detail}`), `other {refusal}` — and the shell's own three BEFORE ANY FRAME: `over_cap {over}`, `inert {inert}` and `head_unreadable {refusal}`, the refusal naming why the signature could not be made (SP-14)",
        fields: &[req("outcome", "'refused'"), req("arm", "string")],
    },
    Shape {
        name: "PublicationEvent",
        open: true,
        doc: "`publication(board, session, {draft, state, …})` (§4b.2) — THE STATE OF THE ONE REQUEST as it moves: `sent` (the frame left the shell), `acknowledged {member, edition, at}` (the commit stands), `restated` (the re-read found a difference; nothing sent), `refused {arm}` (the arm by name, its data in `confirm`'s answer), `cancelled` (the standing panel dropped by `cancel`), `ended` (the session died with the panel standing or held — gone with it); fired at `confirm`'s send and at its outcome, at `cancel`, and at the session's death",
        fields: &[req("board", "string"), req("session", "string"), req("draft", "string"), req("state", "'sent' | 'acknowledged' | 'restated' | 'refused' | 'cancelled' | 'ended'")],
    },
    Shape {
        name: "MergeReport",
        open: false,
        doc: "`merge.compose(session, {doc, alternative, into?})` — or THE DRAFT SIDE, `merge.compose(session, {doc, draft, into?})` — THE REPORT, brief-shaped as the publication panel is, every member DATA and never a string: `outcome` — `landed`, M landed into `into` by ONE `set_arrangement` (the draft named, or a FRESH draft staged from the head first where none is named, `fresh` true where this call staged it — false for a draft named and for a landing of the person's own of the key found standing, nothing staged), typed against the compose's read of the draft, the draft's recorded base re-recorded to the head and the marker set beside it, `position` the write's commit, `head_moved` the trunk's newer head where one stands (LAND AND TELL: the write landed on the head it composed on), `record_link` the merge record's link, homed in the person's private journal beside the record, or null where the record could not be written and the landing stands (`unrecorded` the refusal, for a later `merge.compose` to record); `reopened`, the draft `into` already carrying this merge (its marker naming the side and the head): the report with NOTHING landed, the side read as compose read it — at the marker's position, `position` — and each unsettled gap's state read off the draft as it stands, settled `person` where the draft no longer arranges the gap's default as M placed it (its runs removed whole, or reordered); `merged`, a daughter a supersession claim of the person's own already names: `member` the member that claim names, `claims` the claims standing at the daughter, `record_link` the record of that merge — the person's own, written now where none of theirs named it — and nothing landed; `doc` the trunk, `head` the trunk's head the merge was composed on (the marker's at a re-open), `base` the member both sides descend from, derived, `side` the daughter or the draft composed, `form` which, `sides` the record's sides with the position a draft side was read at, `runs` M with each run's side and family, `gaps` THE GAP REPORT — each gap its kind (`order`, `corner`, `cut`, `collision`, `moves` unsettled; `anchor` settled by the rules), its anchors, the runs placed with their sides, the placement as it stands (the default), `settled` and `resolved_by` (`rule`, `person`, `agent`, `answer:<address>`, or null) — `counts` the run counts, `m` against `cap`, `over_cap` where it passes it (the composition answered, nothing landed, the refusal `over_cap`), `record` the merge record's body as it stands — unlanded at a re-open — and `as_of` the one board position every read was made at",
        fields: &[
            req("outcome", "'landed' | 'reopened' | 'merged'"),
            req("doc", "string"),
            req("head", "string"),
            req("base", "string"),
            req("side", "string"),
            req("form", "'daughter' | 'draft'"),
            req("sides", "MergeSide[]"),
            req("runs", "MergeRun[]"),
            req("gaps", "MergeGap[]"),
            req("counts", "RunCounts"),
            req("cap", "number"),
            req("over_cap", "boolean"),
            req("record", "unknown"),
            req("as_of", "number"),
            opt("into", "string"),
            opt("position", "number"),
            opt("fresh", "boolean"),
            opt("head_moved", "string | null"),
            opt("record_link", "string | null"),
            opt("unrecorded", "Refusal"),
            opt("member", "string"),
            opt("claims", "string[]"),
        ],
    },
    Shape { name: "MergeSide", open: false, doc: "one side of the merge record: `at` the member or the draft, `role` the head, an alternative (a daughter), a draft or a fork, `position` the board position a draft side was read at — null at a member", fields: &[req("at", "string"), req("role", "'head' | 'alternative' | 'draft' | 'fork'"), req("position", "number | null")] },
    Shape {
        name: "MergeRun",
        open: false,
        doc: "one run of M, the merged list, in V-order: `width` positions of `origin`'s content I-space from the ordinal `i_start`, `side` the side that placed it (0 the head, then each side in order) or null for the base's own, `family` the shot's three — `own` the trunk's I-space by reference, `window` another document's, `draft_native` a draft side's fresh text",
        fields: &[req("origin", "string"), req("i_start", "number"), req("width", "number"), req("side", "number | null"), req("family", "'own' | 'window' | 'draft_native'")],
    },
    Shape {
        name: "MergeGap",
        open: false,
        doc: "one gap of the report: `id` the key `merge.land`'s `resolutions` take, `kind`, `after` and `before` the surviving base anchors on either side (null at an edge), `runs` the runs the gap places with the side each came from, `placed` the placement as it stands — the sides' order, `after` or `before` the anchor, or `omitted` — `settled` whether the rules settled it (an `anchor` gap) or the person did (`resolved_by` `person`), `resolved_by` who settled it, or null while it stands unsettled at its default",
        fields: &[req("id", "number"), req("kind", "GapKind"), req("after", "string | null"), req("before", "string | null"), req("runs", "GapRun[]"), req("placed", "GapPlacement"), req("settled", "boolean"), req("resolved_by", "string | null")],
    },
    Shape { name: "GapRun", open: false, doc: "one run a gap places: `side` the side it came from, `i_start` its first I-address, `width` its positions", fields: &[req("side", "number"), req("i_start", "string"), req("width", "number")] },
    Shape { name: "RunCounts", open: false, doc: "the run counts the record keeps (the merge record's decision 17): `a` the head's, `b` the sides', `m` the merged list's, checked against the cap", fields: &[req("a", "number"), req("b", "number"), req("m", "number")] },
    Shape {
        name: "MergeLanded",
        open: false,
        doc: "`merge.land(session, {resolutions?, answers?})` — THE LANDING ON THE TRUNK: the shot through the publication family's one composition and send from the draft the composition landed in — the page's panel of it at the composition's document, standing or held, with the switches and answers the page last sent, or one the shell opens over the whole draft, every private row OFF, under the answers the call names (`Record<string, OriginAnswer>`, keyed `⟨run⟩.⟨part⟩` as `publication.confirm`'s are), the landing composing NO answer the caller did not give at any window part — an unanswered part refuses `window_parts_owed` (`WindowPartsOwedRefusal`), every part named whole, nothing sent — a panel the page read under another merge marker than the draft carries, before the compose or over an earlier merge, FIRST KEYED ON THE DRAFT AS IT STANDS, the claim composed again off the marker, a panel of the whole draft re-taking what the draft arranges and the draft side named `also`, a selection the page passed kept held and any difference re-stated, nothing sent — THE REQUEST CARRYING THE SUPERSESSION CLAIM as the panel composed it, at its open, at a confirm that found the draft's base moved or at that keying (`Count.supersede`), then THE MERGE RECORD, its own write, idempotent by reading first: `member` the member minted, `at` its commit, `via` and `claim` the acknowledgment's, `supersede` the daughters the write claimed superseded (`Acknowledged.supersede`), `daughter` whether the head moved under a shot naming NO daughter — the draft side's — and the member landed as a daughter, reported as a race is and never a silent success, `record` the merge record's link, homed in the person's private journal, null where the member stands and its record could not be written (`unrecorded` the refusal; the next `merge.compose` of the daughter records it), `claims` the supersession claims standing at the daughters whose `new` is the member, `retries` the record's, `answers` each window part's answer as given, `left_private` each private set this landing left out with its count, `defaults` each of the merge's places left at its default; the composition is gone with the landing; the panel's RE-STATEMENT (`Restated`) and its typed REFUSAL (`PublicationRefused`) are the other two shapes — a panel of the whole draft keyed at this call re-stated only where the merge brought a link (`came`) onto a private row left switched on, its `selection` empty and no `parts`, the runs' indices no longer lining up, the next call landing it — the race, `supersede_refused` with `detail` `head_moved` and `head` the trunk's, crossing as the board answered it, NOTHING RE-SENT, the composition gone, to be made again on that head; `no_merge` where nothing is composed; `held_lines` (`HeldLinesRefusal`) where the draft the composition landed in, or a draft the shot names `also`, holds lines of yours the board has not kept, nothing sent; `other_panel` (`OtherPanelRefusal`) where the family's panel of that draft, standing or held, mints an edition or publishes into another document, nothing sent and every panel and the composition as they stood",
        fields: &[req("outcome", "'landed'"), req("member", "string"), req("at", "number"), req("via", "AckVia"), req("claim", "boolean"), req("supersede", "string[]"), req("daughter", "boolean"), req("record", "string | null"), opt("unrecorded", "Refusal"), req("claims", "string[]"), req("retries", "number"), req("answers", "WindowPart[]"), req("left_private", "LeftPrivate[]"), req("defaults", "MergeDefault[]")],
    },
    Shape {
        name: "Undone",
        open: false,
        doc: "`merge.undo(session)` — the landing's one undo step while the session that landed it stands, or with `{draft, withdrawal}` a withdrawal's (below): ONE `set_arrangement` carrying the arrangement the draft held before the landing, its runs mapped through the correspondence records where a publication made its words public since, its old base as the base to record, and the marker the draft carried then put back as it stood — an earlier landing's, or the one its stage copied — or no marker where it carried none (skep #964), typed against this shell's own last acknowledged arrangement write on the draft, or the landing's position — or the latest write that put its marker back, where only a take-back and its undo moved the words since — where that is later (the library's R6 with P3's editor rule: the person's own later changes, taken back first, never refuse it; a write to the draft since by another hand refuses it `arrangement_moved`, nothing wiped); `draft` the draft the merge was taken back out of, `position` the write's commit, `record` the replacing record's link, homed in its private journal (null where no record of the landing stood, or where the one standing is the earlier landing's whose marker came back), `restored` the base restored, address and extent (null where the draft records none), `marker` — the landing's undo alone — the draft's merge marker as the undo left it, the one it put back, or null; the composition is gone with the undo, and where the marker it put back is an earlier landing's whose composition a later landing in the draft set aside, that composition stands again while its session stands, so the next `merge.undo(session)` takes that landing back and `merge.land` publishes it (skep #981); `no_merge` where nothing is composed, `nothing_to_undo {draft, why}` where the merge is not one an undo takes back, `held_lines` (`HeldLinesRefusal`) where the draft holds lines of yours the board has not kept, nothing sent. `merge.undo(session, {draft, withdrawal})` is the withdrawal's undo, `withdrawal` the `position` a `merge.withdraw` answered: ONE `set_arrangement` of the draft's current runs, mapped as the undo's are, its recorded base re-sent unmoved and the marker the withdrawal cleared put back as it stood — its sides, its head and the landing's own `at` — typed as the undo is; the composition the withdrawal took aside in this session stands again, so the next `merge.undo(session)` takes the landing back; `restored` null; `no_merge {draft, withdrawal}` where the position names no withdrawal of the draft, `nothing_to_undo {draft, why}` with `remarked` where the draft carries a merge again or one landed since, `published` with the `version` where the draft was published since, nothing sent",
        fields: &[req("draft", "string"), req("position", "number"), req("record", "string | null"), req("restored", "{ base: string; extent: number } | null"), opt("marker", "MergeMarker | null")],
    },
    Shape {
        name: "Withdrawn",
        open: false,
        doc: "`merge.withdraw(session, {draft})` — THE WITHDRAWAL, in any session: ONE `set_arrangement` of the draft's current runs with its recorded base re-sent unmoved and no `merge`, clearing the marker and keeping the words, typed against the shell's read of the draft; `draft` the draft, `position` the write's commit, `record` the replacing record's link, homed in its private journal (null where no record of the landing stood); `no_merge {draft}` where the draft carries no marker, `not_owner {addr}` where it is another account's or published, `held_lines` (`HeldLinesRefusal`) where the draft holds lines of yours the board has not kept, nothing sent; the composition standing on the draft goes aside, and `merge.undo(session, {draft, withdrawal: position})` puts the merge back (`Undone`)",
        fields: &[req("draft", "string"), req("position", "number"), req("record", "string | null")],
    },
    Shape {
        name: "Past",
        open: false,
        doc: "`history.past(session, {draft, at})` — a past state read, nothing written (B3-S7; skep #853): the reads `history.restore` makes before its write — the draft's `doc_metadata` at the head, its extent and image as of `at` through `/op-at`, the image in parts where the board answers it too large, then the person's correspondence records at the head, one read per chunk of each origin of the person's own the state holds — answered with no write, so the page draws, while the person rests on a past state, what that state brings back and which links the change would orphan (its own `delete_orphans` read over the current text, less the links whose ends `sent` keeps) before \"make this state current\"; it asks no write door, so a bare session and a second window read it and a hold standing at the board stops none of its reads, and it holds, notes and changes nothing, `history.restore` reading again for itself: `draft` the draft, `at` the position read, `as_of` the position the reads were made at — no typed state: `history.restore` stays typed at the page's own state of the draft, and one typed at this `as_of` would write over a change the page never showed — `state` the draft's runs as read at `at`, in V order, for drawing and never for sending: a run a publication has re-minted since is the draft's own words there, which the board's twin fence refuses sent as draft-native (`already_published`); `sent` the same positions in the same order mapped through the records, words published since as the published words they became — what a restore made now would send; `covered` the positions of `state` a record covers, the words that come back as published words; `marker` the draft's merge marker as it stands, which a restore leaves standing, or null; `at` at or past the draft's position refused `merge_refused` with `not_past`, a published document `not_owner` with `published`, and a session the board answered no account for `no_account`",
        fields: &[req("draft", "string"), req("at", "number"), req("as_of", "number"), req("state", "Run[]"), req("sent", "Run[]"), req("covered", "number"), req("marker", "MergeMarker | null")],
    },
    Shape {
        name: "Restored",
        open: false,
        doc: "`history.restore(session, {draft, at, as_of})` — A PAST STATE MADE CURRENT (B3-S7): ONE `set_arrangement` of the draft's runs as read at `at`, mapped through the person's correspondence records so words published since come back as the published words they became, naming no base and no merge — the draft's recorded base and its marker stand — typed against the call's `as_of`, THE TYPED STATE, the page's own state of the draft as its burst frames on it carry it, and refused `arrangement_moved` where the draft's arrangement changed past it, nothing changed; `at` at or past the draft's position refused `merge_refused` with `not_past`; a draft holding lines of yours the board has not kept refused `held_lines` (`HeldLinesRefusal`) before any read, nothing sent — resolve them, then restore: `draft` the draft, `at` the position restored, `position` the write's commit, `as_of` the position the draft stood at as the shell's read found it before the write — the way back, `history.restore` again at `{at: as_of}` typed at `position` — and `marker` the draft's merge marker as it stands, which a restore never takes out, or null",
        fields: &[req("draft", "string"), req("at", "number"), req("position", "number"), req("as_of", "number"), req("marker", "MergeMarker | null")],
    },
    Shape {
        name: "MergeMarker",
        open: false,
        doc: "a draft's merge marker as `doc_metadata` serves it: `sides` the merge's sides by address, `head` the trunk member the merge was composed on, `head_copied` that member's content count as read at the compose, a decimal string, or null where the board serves none, `at` the position of the commit that put the marker on the draft, or null where the board serves none",
        fields: &[req("sides", "string[]"), req("head", "string"), req("head_copied", "string | null"), req("at", "number | null")],
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
    CallRow { name: "node.start", forms: &[&[]], result: "Probe" },
    CallRow { name: "node.stop", forms: &[&[]], result: "Probe" },
    CallRow { name: "node.restart", forms: &[&[]], result: "Probe" },
    CallRow {
        name: "op",
        forms: &[
            &[req("session", "string"), req("frame", "unknown"), opt("anchors", "Anchors"), opt("after", "string")],
            &[req("guest", "true"), opt("board", "string"), opt("origin", "string"), req("frame", "unknown")],
        ],
        result: "unknown",
    },
    CallRow {
        name: "publication.open",
        forms: &[&[
            req("session", "string"),
            req("draft", "string"),
            opt("also", "string[]"),
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
    CallRow {
        name: "publication.count",
        forms: &[&[req("session", "string"), opt("switches", "Switches"), opt("answers", "Record<string, OriginAnswer>")]],
        result: "{ count: Count; price: Price; rows: PublicationRow[]; formatting: Formatting; windows: Window[]; parts: PartCounts[]; edition_links: number; p3_stands: boolean }",
    },
    CallRow { name: "publication.confirm", forms: &[&[req("session", "string"), opt("switches", "Switches"), opt("answers", "Record<string, OriginAnswer>")]], result: "Acknowledged | Restated | PublicationRefused" },
    CallRow { name: "publication.cancel", forms: &[&[req("session", "string")]], result: "Empty" },
    CallRow { name: "publication.standing", forms: &[&[req("session", "string"), req("draft", "string"), req("doc", "string"), opt("also", "string[]")]], result: "PublicationStanding" },
    CallRow { name: "merge.compose", forms: &[&[req("session", "string"), req("doc", "string"), opt("alternative", "string"), opt("draft", "string"), opt("into", "string")]], result: "MergeReport" },
    CallRow { name: "merge.land", forms: &[&[req("session", "string"), opt("resolutions", "Record<string, MergeChoice>"), opt("answers", "Record<string, OriginAnswer>")]], result: "MergeLanded | Restated | PublicationRefused" },
    CallRow { name: "merge.undo", forms: &[&[req("session", "string")], &[req("session", "string"), req("draft", "string"), req("withdrawal", "number")]], result: "Undone" },
    CallRow { name: "merge.withdraw", forms: &[&[req("session", "string"), req("draft", "string")]], result: "Withdrawn" },
    CallRow { name: "history.past", forms: &[&[req("session", "string"), req("draft", "string"), req("at", "number")]], result: "Past" },
    CallRow { name: "history.restore", forms: &[&[req("session", "string"), req("draft", "string"), req("at", "number"), req("as_of", "number")]], result: "Restored" },
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
    CallRow { name: "held.show", forms: &[&[req("session", "string")]], result: "{ shown: boolean }" },
    CallRow { name: "resolve", forms: &[&[req("session", "string"), req("held", "number"), req("act", "'drop' | 'send'")]], result: "{ kept?: true }" },
    CallRow {
        name: "changes",
        forms: &[
            &[req("session", "string"), req("since", "number"), opt("limit", "number"), opt("class", "'drafts'"), opt("under", "string")],
            &[req("guest", "true"), opt("board", "string"), opt("origin", "string"), req("since", "number"), opt("limit", "number"), opt("under", "string")],
        ],
        result: "ChangesAnswer",
    },
];

/// The publication family's closed unions, each a type alias the file
/// declares ahead of the shapes (the crate's enums, spelled as the values
/// the shell answers spell them).
pub const ALIASES: &[&str] = &[
    "export type RowKind = 'own' | 'notes' | 'private' | { public: { read_with: boolean } };",
    "export type Destination = 'member' | { set: string };",
    "export type OriginAnswer = 'publish_first' | 'drop' | 'keep_private' | 'counterpart';",
    "export type Placement = { whole: { ordinal: number } } | { places: number[] } | { split: [number, number, number][] } | 'absent';",
    "export type Term = 'runs' | 'places' | 'links' | 'retract' | 'read_with' | 'body' | 'values' | 'reads' | 'bytes';",
    "export type AckVia = 'answer' | 'twin' | 'records' | 'walk' | 'edition_claim';",
    "export type Inert = 'unchanged' | { unanswered: { run: number; part: number; named: boolean }[] } | { publish_first: { run: number; part: number }[] };",
    "export type Missing = { copy: number } | { retraction: number };",
    "export type HandKey = 'own' | 'other' | 'bare' | 'lost' | 'unread' | 'unknowable';",
    "export type BaseStanding = 'at_head' | 'behind' | 'first' | 'superseded_first';",
    "export type GapKind = 'order' | 'anchor' | 'corner' | 'cut' | 'collision' | 'moves';",
    "export type GapPlacement = number[] | 'after' | 'before' | 'omitted';",
    "export type MergeChoice = 'keep_both' | 'omit' | { order: number[] } | { keep_only: number } | { after: string } | { before: string };",
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
    out.push_str("export type Refusal = RefusedByBoard | HaltFace | BlockedFace | Unreachable | HeldLinesRefusal | WindowPartsOwedRefusal | LandingUnreadRefusal | NoOwnNodeRefusal | OtherPanelRefusal | ShellRefusal;\n");
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
    out.push_str("/** The calls (client.md §4b.1 — the `publication` family's four, the `merge` family's four and `history.restore` among them — this machine's notebook's three acts `node.start`, `node.stop` and `node.restart`, the read of a draft's standing `publication.standing`, the read of a draft's past state `history.past`, the document index's listing `places`, and the change feed's page `changes`): `POST /bridge/<name>` with the argument object; `{result}` or `{refused}` back. */\n");
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
