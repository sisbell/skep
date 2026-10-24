# skep-shell

The shell's core, written once: the bridge of `client.md` §4b — "the
contract between the bundled app's shell and its page" — as a library over
`skep-client`, which the dev provider (`skep-dev serve`) serves to a page
over loopback and the desktop shell later wraps, rewriting the transport
alone. Its design is the dev provider record in the skep-ux-design
repository (`_designs/CLIENT/2026-10-10-dev-provider.md`, §2.2) under the
owner's rulings P-1 … P-12; how its modules fit, and the rules that cross
them, are in the workspace's `ARCHITECTURE.md` §The shell's core.

Part of [skep](https://github.com/sisbell/skep), an open-source hypertext substrate in the Project Xanadu lineage.

## What it holds

A transport reaches the crate through its root — `Shell` and what opens
it (`ShellOptions::new`), `Refusal` and its `Name`, `Log` and its
`CallOutcome`, `Event`, its `EventName` and `UnknownEventName`, `Talk`,
`CALLS` — and two public modules, `script` and `shapes`; the rest is
private. The modules, in the order `src/lib.rs` declares them, each naming
only those above it (held by `tests/it/tidy.rs`):

| module | holds |
|---|---|
| `refs` | the reference registry's NAMES: a board reference (`b-…`) and a session reference (`s-…`) minted from OS entropy per process, never a credential, never derived from an origin or a token (§4b.1, THE PIN); and `BoardEntry`, one board under the reference minted for it — the pair the shell, a board's feed thread, its holds and every session at it read whole |
| `log` | `Log`, the call log and the dial log the page's gate reads — sizes, routes and timing, never a token or a body, the latest `MAX_LOG_ENTRIES` kept — and `ShellDialer`, the one `PlainHttp` every board dials through, which dials nothing once the shell's stop stands |
| `events` | `EventBus`: the seven events of §4b.2 as values, each named by an `EventName`, fanned out to every subscriber in order |
| `refusal` | `Refusal`, the one refusal shape the page renders — the board's verdict verbatim, a halt's face, the block, the unreachable board, the shell's own — each named by a constant of `Name`, the one closed list |
| `wire` | the wire's shared facts: the board's frame cap (`MAX_FRAME_BYTES`) and a frame's compact bytes (`json_len`), the tumbler component budget, `document_address`, a document address in its one spelling, and the wire's value forms both ways (`values_of`, `delivered_values`) within the insert's value budget |
| `attest` | `Composer`, the attest a signed session composes for every write of the checked set, every axis from the shell's own reads; the board's other budgets, each held before the work it bounds |
| `held` | the held-burst store (§3c): one append-only file per (board, principal) beside the key store, written and read through `skep_util::file`'s one tail rule — read line by line with P38's faces, a file with no whole header line read as fresh and the next line heading it, each line synced before `op` answers `held` where the last whole line ends, a crash's tail cut off first and answered for the shell to say once (`Torn`), the file removed at compaction and a removal the volume refuses answered (`Settled`) with the store appending on; `HeldQueue`, a principal's queue — its memory, the file its copy — a hold adding none past its frames' bytes or its lines (`MAX_HELD_LINES`), and its file's re-marks within their budget |
| `script` | the dev arm's SCRIPT: the grammar a script file's answers are parsed by, one per line in order |
| `dev_arm` | `DevArm`, the answerer of the SECRET and CONSENT moments (§4b.3): a script's answers in order, or the auto arm, every answer said on TALK and never sent to the page, the NATIVE statements — those naming where key material rests — said there too |
| `person` | `BridgePerson`: the PUBLIC moments as `moment` events answered through `Pending` in their kind's form, the SECRET and CONSENT ones, and the NATIVE statements (`NATIVE_RULES`), sent to the dev arm — or, where the shell was opened with none (`ArmConfig::Refuse`, a client with no person present), the SECRET and CONSENT moments refused here, `person_required` naming the walk, the moment and its class, answered by no arm and no page, and the NATIVE statements said on TALK in the arm's place |
| `sessions` | `Sessions`, the session table: each session's token beside the board it stands at, the two openings — bare, which reads alone (`SessionEntry::may_write`), and signed, which writes too — the attest a session's key signs, a session's end run once whichever caller met the death signal, under the key store the table holds, and a leaving session's drafts supplement released to another of its principal |
| `hold` | `Holds`: the one path of every `/op` under a session that may write (`Holds::send`) — a burst's door (`Burst::admit`) and its hold among it — each answer read through the classification table (`classify`), and the per-(board, principal) queue over `held`'s file; `hold/resend.rs`, the probe and the resend walk, its lines sent in `k` order across the documents under a session of the principal's that may write, never a bare one |
| `feed` | `FeedThreads`, `Feed` and the `Feeder`: per board, the feed thread — the `feed`, `index`, `mode` and `daemon` events, the `search` call and the document index's listing `places`, the held-burst probe on its cadence; and `changes_since`, the one read behind the `changes` call, on the caller's thread |
| `shell` | `Shell`: the boards, the sessions, and one private method per §4b.1 row — per `places`, the document index's listing at the call's class (A-255), and per `changes`, the change feed's page from a position at the session's class — behind `call`, which logs every call — `fetch` public beside it, because it streams, and logging its own; a write under a bare session, and its `resolve(send)`, refused before any dial (`write_in_bare_session`), and the `session` answer's `writes` saying so ahead of any write; `shell/ceremony.rs`, the ten ceremonial rows |
| `shapes` | `declarations()`, the TypeScript declaration file for every value that crosses the bridge, pinned by a round-trip of each type's sample |

## The `feed` update's shape

This crate's definition (S-24 (b)): the `/changes` row VERBATIM — every
member the declared `FeedUpdate` (`shapes`) names beside the three below,
and any later member by the wire's forward rule — plus `position` (the
row's `at`, named once more) and `class` — `published` for a row of the
guest's feed, `drafts` for one of a principal's supplement, the latter with
`session`, the session the event goes to. The event carries `board`, the
reference, beside `update`. A drafts supplement and an index face are a
principal's, not a session's, so a drafts row goes out once per session of
its principal at the board, and an `index` event once per such session,
each naming its own: every tab of a principal hears its drafts and its
face. The published feed starts at the head the board first answers with —
at the thread's start, or at its first `/health` after it, never at 0 for a
board not yet up — and a principal's drafts at the position its first
session opened at, read on through its other sessions and its restart's
re-open: a page re-reads what it shows on open and takes the updates from
there.

## The `changes` call

`changes(session, since, limit?)` → `{entries, next, head}`: what changed
since the position `since`, at the session's class — the catch-up of a
client that comes back to a board, whose `feed` events began at its
connection. It is the board's change feed read TWICE from `since` and
merged by position: the published feed as a guest, token-free, and the
session's drafts supplement under its token (`drafts=true`), so each entry
is a `FeedUpdate` with the `class` the `feed` event gives a row —
`published` or `drafts`, the latter naming the `session` — which one plain
read under the token could not tell apart; a position both reads answer (a
straddle) is answered once, by the rendering naming more documents. The
board's head is read first (`/health`), each read is one page bounded by
`limit` and the wire's page budget (a page past it re-asked at the limit
that fits), and the merged page is cut where either read's `more` stands,
then to `limit`, so no position is skipped: `next` is the position to ask
from next time — past every entry answered, never past one withheld, and
at the head where both reads were complete, so a quiet board's next ask is
the empty page at once. A draft the session may not read never appears:
the gating is the board's. Its refusals: `malformed_args` naming `since`
or `limit`, `session_ended`, the board's own (`history_reclaimed` with its
floor, `malformed_changes`, `feed_rebuilding`), and `session_died`.

## The refusing arm

`ArmConfig::Refuse` is the setting of a client with no person present (an
agent's): every SECRET and CONSENT moment a walk reaches is refused
`person_required` — the refusal naming the `walk`, the `moment` (the
seam's own name for it: `sheet`, `retype`, `destination`, `confirm_typed`,
`import`, `kept_or_placed`), its `class` and, a confirmation's, the `text`
that was asked — answered by no arm and no page, and the walk abandoned
there; `Auto` and `Script` are unchanged. PUBLIC moments still cross to
the page, and a NATIVE statement is said on TALK as the arm would say it.

## Where the library stops at this pin

`upload` and `restore` answer `not_reached`: the media walk (the PUT and
its resume, the create, the cell's insert, the typing link) is the shell's
lane's and `skep-client` holds no media module. `fetch` reaches the
dialer's streamed form — the bytes the daemon checked against the cell —
and runs none of the client-side recovery order. `bind` takes the hop's
landing and compares no genesis whole (the anchor files' pick is a window's).
A `session-died` whose cause is a block is named by the re-open's
`prefix_blocked`; the seeded arm names the account and the set's
`as_of`, not the genesis's position by bisection. No `held` event goes
out at the launch for the documents a principal's held file holds: the
file is read at its session's open, and `held(session)` lists its lines.
The paper path's question whether to destroy an anchor file whose print
passed its re-type names the file and crosses to the page: `skep-client`
classes it PUBLIC, and a question carries no rule the shell could route it
to its own window by, as it routes the NATIVE statements. The faces the
shell carries from `skep-client` name the store's location or a key, anchor
or index file — `no_key`'s arm-4 face, `store_unreadable`'s and
`store_unwritable`'s, a walk's file halt, the index's I/O halt — and cross
to the page as they are, `skep-client`'s to build for the bridge; and
`store_halted` names the held file's path, as §3c.3's face has it against
§4b.3's rule.

No feature, no async runtime, no HTTP crate: std beside the workspace's
crates, as `skep-client`'s rule has it. The transport is not here.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](../../LICENSE-APACHE))
- MIT license ([LICENSE-MIT](../../LICENSE-MIT))

at your option.
