//! The page's declarations, generated from this crate's Rust types.
//!
//! FP-16 has it: "every value that crosses the bridge has its shape defined
//! on the Rust side and declared for the page from that definition".
//! [`declarations`] renders one TypeScript declaration file — every call's
//! input and output, every event, the refusal, the `feed` update's shape (a
//! `changes` entry's too), the index state's ten arms, the publication
//! family's panel, inputs and outcomes, the merge family's report and
//! outcomes, and the restore's answer with the merge marker it carries —
//! from the table below, which is
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
    Shape { name: "BoardRow", open: false, doc: "`boards()` — one entry per board in the shell's list; `board` the opaque reference every board-touching call takes", fields: &[req("board", "string"), req("name", "string"), req("origin", "string")] },
    Shape {
        name: "SessionOpened",
        open: false,
        doc: "`session(board, principal)` — the session's opaque reference in the token's place; `writes` whether the session itself may write: the signed mode's session writes, the bare mode's keyless one reads alone and has every write refused `write_in_bare_session` — the board's own state can refuse a write beside it: the own node stopped, its writes halted or its write path poisoned (§3c.4), which this answer does not report, or another shell holding its held store (§3c.3), which it reports; `another_window` present, `true`, only while another shell over the data directory holds the board's held store as the session opens — every write at the board refused `another_window`, nothing held and nothing sent, whatever `writes` says — every later edge of that state an `another-window` event (skep #827); `opened_at` the board's position read before the session opened, where its drafts feed starts — the position a page keeps as its last drafts row's (`draftsAt`) until a row moves it, and reads `changes(session, since, class: 'drafts')` from after the session's end",
        fields: &[req("session", "string"), req("principal", "number"), req("account", "string | null"), req("writes", "boolean"), opt("opened_at", "number"), opt("another_window", "true")],
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
        doc: "`changes(session, since, limit?, class?)` and its guest form — what changed since the position `since`: the entries in the `feed` update's shape, oldest first, each `published` or `drafts` by the read that answered it — under a session two reads, the published feed as a guest and the session's drafts supplement under its token, merged by position; with `class: 'drafts'`, the one value the member takes, the drafts supplement's page alone (a page's read, from the session's `opened_at`, of the drafts rows an end cut off before it regained a session); as a guest, `{guest: true, board?, origin?, since, limit?}`, the published feed alone, token-free (no `class`); `next` the position to ask from next time, past every entry answered and never past one withheld; `head` the board's latest position, read before the page; the shell keeps no position — every form reads from `since`",
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
    Shape { name: "ShellRefusal", open: true, doc: "a refusal: the shell's own, its detail beside the name (`held_lines`'s declared whole as `HeldLinesRefusal`)", fields: &[req("kind", "'shell'"), req("name", "string")] },
    Shape { name: "ModeEvent", open: false, doc: "`mode(board, …)` — the pair moved", fields: &[req("board", "string"), req("mode", "Mode"), req("claimant", "string | null"), req("local_trust", "boolean")] },
    Shape { name: "SessionDiedEvent", open: false, doc: "`session-died(session, reason)`", fields: &[req("session", "string"), req("reason", "DeathReason")] },
    Shape {
        name: "DeathReason",
        open: true,
        doc: "the reason a death carries: its `arm`, the trigger it names, and the arm's own members beside it, each declared here and present on its arm alone — the `restart` arm's `reopened`, with `session` the reference the shell re-opened silently in the dead one's place where it did, and `refused` the name of the re-open's refusal where one was tried and refused; the `mode` arm's `mode`, the pair the bare session died at the flip to; the `unreachable` arm's `text`; the `retired` arm's `fingerprint`, `own`, `hand`, `position` and `label` — `own` null where the fork on whose key retired it cannot be taken (no record read, a hand the read could not name, or the shell's key store unlisted beside another hand), its `position` the one read whatever the hand (AUTH-5.77's no-hand form); the `seeded` arm's `account`, `as_of` and `writer`; the `blocked` arm's `record` and `ground`; the `closed` arm carries nothing beside",
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
    Shape { name: "DaemonEvent", open: false, doc: "`daemon(board, state)`", fields: &[req("board", "string"), req("state", "'running' | 'stopped' | 'unreachable'")] },
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
        doc: "the `op` answer where the burst's board is HELD (§3c): the shell's own answer, never `ack` — the page takes it as accepted and not acked; `cause` the hold's token — `session_died` where the death signal met the burst, at its dial or, the board having refused it as typed against an older state, at the shell's read for its shift or for the hands that moved its document, the session then ended and its `session-died` naming the arm (§3c.4) — and `unwritable` — why — where the device refused the line's copy, or refused a copy the held file still owes an earlier line of the principal's at the board — its first copy, a re-mark or its `done` (the line waits behind it, both written in order once the device takes them) — or refused the held store itself: the held directory or its lock could not be made, the held file could not be read, or an earlier run's lines in it could not be renumbered past this run's — the burst held in memory alone, owed to the file, and written at the first retry the device takes (a board unclaimed or away, or whose head will not read, keeps no line in memory: its lines go to the pending file from the first touch, and another shell's hold on the store refuses the burst `another_window` instead, §3c.3); and `unwritable_class` beside `unwritable`, always with it, the class the page keys its act by, read off the refusal's kind and never its words, which differ by platform (§3c.3's face): `full` a full disk or a spent quota, which space freed on this device ends, the shell's retry then writing the line, `read_only` a read-only volume or a write the shell has no right to make, which no space freed ends, `other` every other kind of I/O refusal — a line waiting behind a refused copy carrying that copy's class unchanged",
        fields: &[req("resp", "'held'"), req("held", "number"), req("cause", "string"), opt("unwritable", "string"), opt("unwritable_class", "'full' | 'read_only' | 'other'")],
    },
    Shape {
        name: "HeldRow",
        open: false,
        doc: "`held(session)` — one held burst of the acting principal at the session's board, in resend order (§3c.2): `held` the ordinal — the line's for the shell's life, naming it until it leaves and no other line after (skep #856) — `doc` the draft, `base` the resend's read start, `frame` the wire frame (no attest) — the page's as composed, or as the shell last shifted it through another writer's change, every position it names moved by one displacement and its `as_of` the state they are true of — `anchors` the page's, where the burst carried them (the `op` row's member): the identities on either side of the span the frame edits and, for a delete or a rearrange, the I-runs of the units it holds, by which the shell shifts it, `sent` whether a dial of the line was attempted since the last read, so it may have landed — a first dial whose answer was lost (the board's `internal_panic` among them), a `poisoned` answer, or any resend, which marks its line before it dials (§3c.2) — kept through a move, `refusal` the verdict for a refused run — the board's, a refusal at a resend under a code the shell's table holds nowhere among them, handed to the person at once, or the shell's `answers_lost` where it handed the person a line no landing of which was found two minutes after its first failed send, whatever the failure (§3c.4): `last` the last failure's token, the held cause or the board's, and `elapsed_ms` the milliseconds since that first failed send — its `sent` kept; at a line held `moved` because the board refused it as typed against an older state and the shift could not move it through the change exactly, the board's `arrangement_moved` (`site.as_of` the state it was typed against, `site.current` the document's); at a line held `head_unreadable`, the shell's refusal naming why its signature could not be made, the line holding all the same (SP-14); at a line held `session_died`, the shell's `session_died` refusal once the session's end derives the death, its `reason` the death's arm (§4b.2; the `retired` arm's `own` among its members), the line holding all the same until a session of the principal's that may write stands and resends it (§3c.4)",
        fields: &[req("held", "number"), req("doc", "string"), req("base", "number"), req("frame", "unknown"), opt("anchors", "Anchors"), req("cause", "string"), req("sent", "boolean"), req("time", "number"), opt("refusal", "unknown")],
    },
    Shape {
        name: "Anchors",
        open: false,
        doc: "the identities a burst's edit is placed by (skep #442, #751), sent beside the frame on the `op` row and kept with the held line, never on the wire — the whole within the board's frame cap as compact JSON, anchors past it refused `malformed_args` naming `anchors`: `before` the I-address of the unit just before the span the burst edits, `after` the I-address of the unit just after it — in the tumbler-string form `image` answers an `i_start` in, the run's position added — each `null` at the document's edge; an insert, a copy or a reinstate names the units on either side of its `at`, a delete those on either side of its `width` positions from `p`, a rearrange those on either side of its first cut to its last; `span`, for a delete and a rearrange alone, the I-runs of the units between the two, in V order, as the page's `image` read gave them — `start` an I-address, `width` a natural of 1 or more as a decimal string, the widths summing to the span's positions; where the board refuses the burst as typed against an older state, the shell finds `before` and `after` in the document's current image and, where each stands at one place and the units between them are the span's own — none for an insert, a copy or a reinstate, so the two stand adjacent; for a delete or a rearrange its `span`, compared run for run with adjacent runs joined on both sides, so a span another writer cut, filled, emptied and refilled with as many others, or rearranged is not whole — moves every position the frame names by their one displacement and sends it again; else the document is held as moved; a burst sent without anchors, or a delete or a rearrange without its `span`, is held as moved there",
        fields: &[req("before", "string | null"), req("after", "string | null"), opt("span", "{ start: string; width: string }[]")],
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
        doc: "`held(board, session, {doc, held, state, cause?, hands?})` (§4b.2) — a document's held state as it moves, always under the session it is about (never the guest face, P39); `held` the count of lines still held on the document, `cause` the line's cause — the hold's token while `holding`, the refusal's token while `refused`; `hands` with the `moved` state, EACH HAND ONCE, read off the `under=` rows since the burst's typed state or the person's last `send` on the document, whichever is later (a document moved again after that `send` names only the hands since it) — the board's refusal of it as typed against an older state (`arrangement_moved`), at its first dial or at a resend, where the shell could not shift the burst through the change exactly (no anchors, a delete or a rearrange without its span, an anchor lost or at two places, the span between them cut or refilled), is the one route to `moved`; a burst it shifts is sent again and lands, no `moved` said; the resend's read judges only whether the line's own write landed (§3c.5); emitted at a hold's start, at each line's resolution or drop, and at each state the resend moves the document through — never when a principal's file is read at its session's open, whose lines `held(session)` lists, nor for a line a call enters, shifts and settles within itself",
        fields: &[req("board", "string"), req("session", "string"), req("doc", "string"), req("held", "number"), req("state", "'holding' | 'sending' | 'kept' | 'refused' | 'moved'"), opt("cause", "string"), opt("hands", "Hand[]")],
    },
    Shape {
        name: "Hand",
        open: false,
        doc: "one hand whose row moved a held document (§3c.5): `own` this store's own key with its fingerprint, `other` another key with its fingerprint and the label the shell's key store holds for it (rendered inert), `bare` an unsigned hand under local trust, `lost` a row whose testimony the board lost — the data of the three forms the moved face draws, the strings `ux/copy.md`'s",
        fields: &[req("key", "HandKey"), opt("fingerprint", "string"), opt("label", "string")],
    },
    Shape { name: "Resolve", open: false, doc: "`resolve(session, {held, act})` — the person's act at a REFUSED run's face or a MOVED document's", fields: &[req("session", "string"), req("held", "number"), req("act", "'drop' | 'send'")] },
    Shape {
        name: "AnotherWindowEvent",
        open: false,
        doc: "`another-window(board, another_window)` (§3c.3; skep #827, #828, #873) — another shell's hold on the board's held store, at each edge of that state: `true` where a session's open or a probe finds another shell over the data directory holding a lock of the store, the pending directory's or the board's own — every write at the board refused `another_window` from then, nothing held and nothing sent — and `false` where this shell takes the locks, the pending one's and the board's own where a term has read, at a later session's open or at a probe; emitted once at each edge, and never at an open or a probe that finds no change — the `session` answer's `another_window` gives the state as a session opens",
        fields: &[req("board", "string"), req("another_window", "boolean")],
    },
    Shape { name: "Run", open: false, doc: "one run of a selection, I-runs in V-order (P51): `width` positions of the document `origin`'s content I-space from the ordinal `i_start`", fields: &[req("origin", "string"), req("i_start", "number"), req("width", "number")] },
    Shape {
        name: "PublicationPanel",
        open: false,
        doc: "`publication.open(session, {draft, also?, doc?, mint?, claim?, selection?, notes?, readable_drafts?, published?})` — THE PANEL: the composition's first steps run by the shell (`enumerate` → `panel` → the price), every member DATA with a code or a kind and never a string a person reads; `draft` the RENDERING draft, `also` the OTHER private drafts of the person's own whose words this publication re-mints as the document's own beside it (the Nelson way — the family: the staging draft and the alternatives made from it, never the notes), each keeping its own records; the draft's BASE the shell's own read off the board, never the page's — the base the board records for the draft, the version its `stage` copied (the bare document while the chain is empty) or the member its newest publication made — so the shot lands after it, or as its daughter where the trunk has moved past it; a draft the board records no base for is refused `base_unrecorded {draft, doc, reason}` — `reason` `no_record` (minted and never staged), `other_chain` (a base in another document's chain) or `free_standing` (an alternative of a draft with no base) — the one refusal of a base, every standing of a recorded one told; `rows` the sets in the RULED order — own, notes, private, public by address; `read_with` per published document of the person's whether the edition is read with it now; `count` at the switches' DEFAULT — every private row OFF; `price` the five terms against their caps, as the request would stand with every window kept private; `windows` the own-origin windows the three answers are asked for, the drafts `also` names EXCLUDED; `inherited` per draft `also` names, in its order, THE STATEMENT's count — the passages first written in it (B3-S11 P2 (i)); `standing` the base TYPED against the document's head before any act — `at_head`, `behind` (told and never refused: the shot lands the base's daughter, the head unmoved), `first` (the bare document, its chain empty) or `superseded_first` (the draft was begun from the bare document and version 1 has since been published: told, never refused — the shot lands beside version 1 as its daughter, the head unmoved) — absent at the mint form; `left_behind` the drafts of the family this publication leaves behind, by address: every draft `also` names, then, where it becomes the head (`at_head`, `first`), every other draft of the person's own whose recorded base is this draft's — empty at the mint form; `hold` where a HELD publication of this draft stood and is re-opened as it stands, with the switches and answers the page last sent it (item 1 (a)), its standing typed again",
        fields: &[req("rows", "PublicationRow[]"), req("formatting", "Formatting"), req("read_with", "Record<string, boolean>"), req("count", "Count"), req("price", "Price"), req("windows", "Window[]"), req("inherited", "Inherited[]"), opt("standing", "BaseStanding"), req("left_behind", "string[]"), opt("hold", "Hold")],
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
        doc: "`publication.count(session, {switches, answers})` — THE COUNT: PUB-3.8's four numbers as DATA (DECISION 5) — ⟨l⟩ the switched-on sets' `links` entries plus the `read_with` entries, ⟨n⟩ the formatting line's marks that re-make nothing, ⟨r⟩ the `retract` entries no re-make covers, ⟨e⟩ the re-makes — `claim` whether the one write carries the edition claim, `read_with` the entries the switches need: each switched-on row's destination other than the member, once, where the edition is not already read with it; `supersede` THE SUPERSESSION CLAIM the one write carries — the published daughters the draft's merge marker names, each one claim in the commit marking the daughter superseded by the member (the slot's merge form, B3-S11's THE MERGE SCENE) — composed by the shell at the open off the board's marker alone, never session memory, and ONLY where the marker's head is the trunk's head as read at the open: empty at an unmarked draft, at a marked draft behind the head, and at a draft-side merge, whose side is a private draft no public claim supersedes",
        fields: &[req("l", "number"), req("n", "number"), req("r", "number"), req("e", "number"), req("claim", "boolean"), req("read_with", "string[]"), req("supersede", "string[]")],
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
        doc: "`publication.confirm` — THE ACKNOWLEDGMENT: `member` the member minted (`E.1` of the edition at the mint form), `edition` the edition minted at the mint form, `claim` whether the edition claim rode in the write (the request's own, echoed), `supersede` the daughters the write claimed superseded — the panel's `count.supersede` as sent, less a daughter an active claim of the person's own already named, which the board skips and the request leaves out — `at` the commit's position, `via` how it was reached — `answer` the frame's own ack or the memo of the one re-ask, `twin` `already_published` READ AS THE ACKNOWLEDGMENT (the landed test passed at the member the refusal named), `records`, `walk` and `edition_claim` a lost answer's landed test; the page lands at P5",
        fields: &[req("outcome", "'acknowledged'"), req("member", "string"), req("edition", "string | null"), req("claim", "boolean"), req("supersede", "string[]"), req("at", "number"), req("via", "AckVia")],
    },
    Shape {
        name: "Restated",
        open: false,
        doc: "`publication.confirm` — THE RE-STATEMENT: P4's RE-READ found the draft moved since the panel — `left` links gone or retracted, `superseded` links a claim of the person's superseded since, `came` links arrived, `removals_undone` and `removals_came` the held removals' job list moved, `selection` held runs whose placement changed with where each stands now — or THE BASE's STANDING moved — NOTHING SENT (PUB-3.108): the page re-renders P2 from it and confirms again; `race` where the re-statement follows the board's `kept_place_moved`, the newest row under the draft that refusal named — the rendering draft, or one `also` names — since the request's reads and its key; `standing` where the base's standing moved since the panel — a sibling's shot landing while it stood, `at_head` → `behind`, or `first` → `superseded_first` for a draft begun from the bare document, whose shot then lands beside version 1 as its daughter — as the re-read typed it, the panel's own from then on (a re-read finding the base no longer recorded refuses as the open does, `base_unrecorded`)",
        fields: &[req("outcome", "'restated'"), req("left", "string[]"), req("superseded", "string[]"), req("came", "string[]"), req("removals_undone", "string[]"), req("removals_came", "string[]"), req("selection", "{ run: number; placement: Placement }[]"), opt("race", "RaceKey"), opt("standing", "BaseStanding")],
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
        doc: "`merge.compose(session, {doc, alternative, into?})` — or THE DRAFT SIDE, `merge.compose(session, {doc, draft, into?})` — THE REPORT, brief-shaped as the publication panel is, every member DATA and never a string: `outcome` — `landed`, M landed into `into` by ONE `set_arrangement` (the draft named, or a FRESH draft staged from the head first where none is named, `fresh` true), typed against the compose's read of the draft, the draft's recorded base re-recorded to the head and the marker set beside it, `position` the write's commit, `head_moved` the trunk's newer head where one stands (LAND AND TELL: the write landed on the head it composed on), `record_link` the merge record's public link, or null where the record could not be written and the landing stands (`unrecorded` the refusal, for a later `merge.compose` to record); `reopened`, the draft `into` already carrying this merge (its marker naming the side and the head): the report with NOTHING landed, the side read as compose read it — at the marker's position, `position` — and each unsettled gap's state read off the draft as it stands, settled `person` where the draft no longer arranges the gap's default as M placed it (its runs removed whole, or reordered); `merged`, a daughter a supersession claim of the person's own already names: `member` the member that claim names, `claims` the claims standing at the daughter, `record_link` the record of that merge — written now where none named it — and nothing landed; `doc` the trunk, `head` the trunk's head the merge was composed on (the marker's at a re-open), `base` the member both sides descend from, derived, `side` the daughter or the draft composed, `form` which, `sides` the record's sides with the position a draft side was read at, `runs` M with each run's side and family, `gaps` THE GAP REPORT — each gap its kind (`order`, `corner`, `cut`, `collision`, `moves` unsettled; `anchor` settled by the rules), its anchors, the runs placed with their sides, the placement as it stands (the default), `settled` and `resolved_by` (`rule`, `person`, `agent`, `answer:<address>`, or null) — `counts` the run counts, `m` against `cap`, `over_cap` where it passes it (the composition answered, nothing landed, the refusal `over_cap`), `record` the merge record's body as it stands — unlanded at a re-open — and `as_of` the one board position every read was made at",
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
        doc: "`merge.land(session, {resolutions?})` — THE LANDING ON THE TRUNK: the shot through the publication family's one composition and send from the draft the composition landed in — the panel standing for it, with the switches and answers the page last sent, or one the shell opens over the whole draft, every private row OFF and every window kept private — THE REQUEST CARRYING THE SUPERSESSION CLAIM as the panel composed it at its open (`Count.supersede`), then THE MERGE RECORD, its own write, idempotent by reading first: `member` the member minted, `at` its commit, `via` and `claim` the acknowledgment's, `supersede` the daughters the write claimed superseded (`Acknowledged.supersede`), `daughter` whether the head moved under a shot naming NO daughter — the draft side's — and the member landed as a daughter, reported as a race is and never a silent success, `record` the merge record's public link, null where the member stands and its record could not be written (`unrecorded` the refusal; the next `merge.compose` of the daughter records it), `claims` the supersession claims standing at the daughters whose `new` is the member, `retries` the record's; the composition is gone with the landing; the panel's RE-STATEMENT (`Restated`) and its typed REFUSAL (`PublicationRefused`) are the other two shapes — the race, `supersede_refused` with `detail` `head_moved` and `head` the trunk's, crossing as the board answered it, NOTHING RE-SENT, the composition gone, to be made again on that head; `no_merge` where nothing is composed; `held_lines` (`HeldLinesRefusal`) where the draft the composition landed in, or a draft the shot names `also`, holds lines of yours the board has not kept, nothing sent",
        fields: &[req("outcome", "'landed'"), req("member", "string"), req("at", "number"), req("via", "AckVia"), req("claim", "boolean"), req("supersede", "string[]"), req("daughter", "boolean"), req("record", "string | null"), opt("unrecorded", "Refusal"), req("claims", "string[]"), req("retries", "number")],
    },
    Shape {
        name: "Undone",
        open: false,
        doc: "`merge.undo(session)` — the landing's one undo step while the session that landed it stands: ONE `set_arrangement` carrying the arrangement the draft held before the landing, its runs mapped through the correspondence records where a publication made its words public since, its old base as the base to record, and no marker, typed against this shell's own last acknowledged arrangement write on the draft, or the landing's position where that is later (the library's R6 with P3's editor rule: the person's own later changes, taken back first, never refuse it; a write to the draft since by another hand refuses it `arrangement_moved`, nothing wiped); `draft` the draft the merge was taken back out of, `position` the write's commit, `record` the replacing record's public link (null where no record of the landing stood), `restored` the base restored, address and extent (null where the draft records none); the composition is gone with the undo; `no_merge` where nothing is composed, `nothing_to_undo {draft, why}` where the merge is not one an undo takes back, `held_lines` (`HeldLinesRefusal`) where the draft holds lines of yours the board has not kept, nothing sent",
        fields: &[req("draft", "string"), req("position", "number"), req("record", "string | null"), req("restored", "{ base: string; extent: number } | null")],
    },
    Shape {
        name: "Withdrawn",
        open: false,
        doc: "`merge.withdraw(session, {draft})` — THE WITHDRAWAL, in any session: ONE `set_arrangement` of the draft's current runs with its recorded base re-sent unmoved and no `merge`, clearing the marker and keeping the words, typed against the shell's read of the draft; `draft` the draft, `position` the write's commit, `record` the replacing record's public link (null where no record of the landing stood); `no_merge {draft}` where the draft carries no marker, `not_owner {addr}` where it is another account's or published, `held_lines` (`HeldLinesRefusal`) where the draft holds lines of yours the board has not kept, nothing sent",
        fields: &[req("draft", "string"), req("position", "number"), req("record", "string | null")],
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
    CallRow { name: "publication.count", forms: &[&[req("session", "string"), opt("switches", "Switches"), opt("answers", "Record<string, OriginAnswer>")]], result: "{ count: Count; price: Price }" },
    CallRow { name: "publication.confirm", forms: &[&[req("session", "string"), opt("switches", "Switches"), opt("answers", "Record<string, OriginAnswer>")]], result: "Acknowledged | Restated | PublicationRefused" },
    CallRow { name: "publication.cancel", forms: &[&[req("session", "string")]], result: "Empty" },
    CallRow { name: "merge.compose", forms: &[&[req("session", "string"), req("doc", "string"), opt("alternative", "string"), opt("draft", "string"), opt("into", "string")]], result: "MergeReport" },
    CallRow { name: "merge.land", forms: &[&[req("session", "string"), opt("resolutions", "Record<string, MergeChoice>")]], result: "MergeLanded | Restated | PublicationRefused" },
    CallRow { name: "merge.undo", forms: &[&[req("session", "string")]], result: "Undone" },
    CallRow { name: "merge.withdraw", forms: &[&[req("session", "string"), req("draft", "string")]], result: "Withdrawn" },
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
    CallRow { name: "resolve", forms: &[&[req("session", "string"), req("held", "number"), req("act", "'drop' | 'send'")]], result: "Empty" },
    CallRow {
        name: "changes",
        forms: &[
            &[req("session", "string"), req("since", "number"), opt("limit", "number"), opt("class", "'drafts'")],
            &[req("guest", "true"), opt("board", "string"), opt("origin", "string"), req("since", "number"), opt("limit", "number")],
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
    "export type Placement = { whole: { ordinal: number } } | { split: [number, number, number][] } | 'absent';",
    "export type Term = 'runs' | 'places' | 'links' | 'retract' | 'read_with' | 'body' | 'values' | 'reads' | 'bytes';",
    "export type AckVia = 'answer' | 'twin' | 'records' | 'walk' | 'edition_claim';",
    "export type Inert = 'unchanged' | { unanswered: number[] } | { publish_first: number[] };",
    "export type Missing = { copy: number } | { retraction: number };",
    "export type HandKey = 'own' | 'other' | 'bare' | 'lost';",
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
    out.push_str("export type Refusal = RefusedByBoard | HaltFace | BlockedFace | Unreachable | HeldLinesRefusal | ShellRefusal;\n");
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
    out.push_str("/** The calls (client.md §4b.1 — the `publication` family's four, the `merge` family's four and `history.restore` among them — the document index's listing `places`, and the change feed's page `changes`): `POST /bridge/<name>` with the argument object; `{result}` or `{refused}` back. */\n");
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
