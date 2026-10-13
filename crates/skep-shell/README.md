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
only those above it (`tests/it/tidy.rs` holds the order, the two public
modules, and `Shell`'s one door — `call`, which logs each call, with
`fetch` public beside it):

| module | holds |
|---|---|
| `refs` | the reference registry's NAMES: a board reference (`b-…`) and a session reference (`s-…`) minted from OS entropy per process, never a credential, never derived from an origin or a token (§4b.1, THE PIN) |
| `log` | `Log`, the call log and the dial log the page's gate reads — sizes, routes and timing, never a token or a body, the latest `MAX_LOG_ENTRIES` kept — and `LoggingDialer`, the one `PlainHttp` every board dials through |
| `events` | `EventBus`: the seven events of §4b.2 as values, each named by an `EventName`, fanned out to every subscriber in order |
| `refusal` | `Refusal`, the one refusal shape the page renders — the board's verdict verbatim, a halt's face, the block, the unreachable board, the shell's own — each named by a constant of `Name`, the one closed list |
| `wire` | the wire's shared facts: the board's frame cap (`MAX_FRAME_BYTES`) and a frame's compact bytes (`json_len`), the tumbler component budget, `document_address`, a document address in its one spelling, and the wire's value forms both ways (`values_of`, `delivered_values`) within the insert's value budget |
| `attest` | `Composer`, the attest a signed session composes for every write of the checked set, every axis from the shell's own reads; the board's other budgets, each held before the work it bounds |
| `held` | the held-burst store (§3c): one append-only file per (board, principal) beside the key store, read line by line with P38's faces, each line synced before `op` answers `held`; `HeldQueue`, a principal's queue — its memory, the file its copy |
| `script` | the dev arm's SCRIPT: the grammar a script file's answers are parsed by, one per line in order |
| `dev_arm` | `DevArm`, the answerer of the SECRET and CONSENT moments (§4b.3): a script's answers in order, or the auto arm, every answer said on TALK and never sent to the page |
| `person` | `BridgePerson`: the PUBLIC moments as `moment` events answered through `Pending` in their kind's form, the SECRET and CONSENT ones sent to the dev arm |
| `sessions` | `Sessions`, the session table: each session's token beside the board it stands at, the two openings, the attest a session's key signs, a session's end run once whichever hand met the death signal, under the key store the table holds, and a leaving session's drafts supplement released to another of its principal |
| `hold` | `Holds`: the one path of every `/op` under a session (`Holds::send`) — a burst's door (`Burst::admit`) and its hold among it — each answer read through the classification table (`classify`), and the per-(board, principal) queue over `held`'s file; `hold/resend.rs`, the probe and the resend walk |
| `feed` | `FeedThreads` and `Feed`: per board, the consumer's thread — the `feed`, `index`, `mode` and `daemon` events, the `search` call, the held-burst probe on its cadence |
| `shell` | `Shell`: the boards, the sessions, and one private method per §4b.1 row behind `call`, which logs every call, `fetch` public beside it; `shell/ceremony.rs`, the ten ceremonial rows |
| `shapes` | `declarations()`, the TypeScript declaration file for every value that crosses the bridge, pinned by a round-trip of each type's sample |

## The `feed` update's shape

This crate's definition (S-24 (b)): the `/changes` row's members VERBATIM
(`at`, `op`, `docs`, `key`, `time`, `attest`, `new_prefix`, `new_id`,
`link`, `placed`, `base_extent`, and any later member by the wire's forward
rule), plus `position` (the row's `at`, named once more) and `class` —
`published` for a row of the guest's feed, `drafts` for one of a session's
supplement, the latter with `session`, the reference it was read under. The
event carries `board`, the reference, beside `update`. The published feed
starts at the head the board first answers with — at the thread's start,
or at its first `/health` after it, never at 0 for a board not yet up —
and a session's drafts at the position the session opened at: a page
re-reads what it shows on open and takes the updates from there.

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

No feature, no async runtime, no HTTP crate: std beside the workspace's
crates, as `skep-client`'s rule has it. The transport is not here.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](../../LICENSE-APACHE))
- MIT license ([LICENSE-MIT](../../LICENSE-MIT))

at your option.
