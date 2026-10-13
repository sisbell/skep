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
`CallOutcome`, `Event` and its `EventName`, `Talk`, `CALLS` — and three
public modules, `events`, `script` and `shapes`; the rest is private. The
modules, in the order `src/lib.rs` declares them, each naming only those
above it (`tests/it/tidy.rs` holds both — an item the root re-exports read
as the module it is brought from — and pins `Shell`'s public methods — one
door, `call`, which logs each call, and `fetch` beside it; the compiler
holds `call`'s dispatch to one arm per call, and `CALLS`, the list a
transport admits a call by, is spelled from the same enum):

| module | holds |
|---|---|
| `refs` | the reference registry's NAMES: a board reference (`b-…`) and a session reference (`s-…`) minted from OS entropy per process, never a credential, never derived from an origin or a token (§4b.1, THE PIN) |
| `log` | the call log and the dial log the page's gate reads — every call the page made, its outcome a `CallOutcome`, every dial the shell made, sizes and timing, never a token or a body, each entry numbered by its place in the whole sequence under the one lock that places it, the latest `LOG_ENTRIES` kept, a call of no name the bridge spells kept by the name's length alone — and `LoggingDialer`, the one `PlainHttp` every board dials through and the log's one maker of dial entries |
| `events` | the event stream: `mode`, `session-died`, `daemon`, `feed`, `index`, `moment`, `held`, each a value named by an `EventName` — the closed list §4b.2 spells, parsed from its words and rendered into the declarations — fanned out to every subscriber in order |
| `refusal` | the one refusal shape: `{kind, name, …}` — the board's own verdict verbatim (`refused`), a halt's face under the armed name (`halt`), the block (`blocked`), the unreachable board (`unreachable`), the shell's own (`shell`); every name the shell spells is a constant of `refusal::Name`, the one list of them; a `Halt` converts into its member by `From`, and every refusal is a `std::error::Error` |
| `attest` | the attest a signed session composes for every write of the checked set — the ten kinds that have an entry frame — the frame's every axis from the shell's own reads, a `publish`'s copied runs read back through the origin's arrangement, keeping only the positions the shot copies in — attached as the frame's `attest`; and THE BOARD's BUDGETS the composer, the held store and the hold's door keep as the board keeps them — the board's frame cap, a wire list, an insert's values, an address's components, a slot's spans, a shot's re-inserted values and its body — each asked before the work it bounds, and the document address in its one spelling |
| `held` | the held-burst store (§3c): one append-only file per (board, principal) beside the key store — a header and two line forms (`held`, `done`; a `held` line of a standing ordinal its re-mark), the `flock` on `held/<chain>/lock`, the file read line by line with P38's faces (`v` first, the misplaced file set aside and named, any line it cannot read whole — no UTF-8, a member missing or of another type, an ordinal past the page's, a line past the line bound — halting it) keeping only the standing lines, each line synced before `op` answers `held`, the file removed once every line is done; a principal's queue is its memory, the file its copy — every line enters it whatever the disk did, a queue another window's lock or an unreachable directory keeps in memory alone writes no copy, its frames held to the board's frame cap, and a re-mark that changes nothing writes nothing |
| `script` | the dev arm's SCRIPT: the grammar a script file's answers are parsed by, one per line in order (`confirm yes`, `retype sheet 0`, `destination <path>`, `import neither`, `kept`, `abandon`, …); a typed import's seed is printed by no answer's `Debug` and no refused line's text |
| `dev_arm` | the DEV ARM for the SECRET and CONSENT moments (§4b.3): a script's answers in order, or the auto arm; every answer said on TALK, never sent to the page |
| `person` | the person over the bridge: a `Person` whose PUBLIC moments become `moment(id, kind, data)` events and block until `answer(id, value)` or `cancel(id)`; its SECRET and CONSENT moments go to the dev arm |
| `sessions` | the session table (the token under its reference, the board's position read before the open), the two openings — bare as the principal, signed content-scoped behind AUTH-5.65's pre-check, each refusal under its armed name — the store's key every row that signs looks up, and the attest a session's key signs on its writes, whichever hand sends them; a session's END: one sequence for both hands that meet a death signal, the shell's and the feed's, the entry's `OnceLock` the gate, so a session ends once and the restart arm's re-open is registered whichever hand met it; the arm a `session-died` carries: `closed`, `mode` (a bare session at the flip), `retired` (own or another hand, the hand and position named), `seeded`, `blocked`, `restart` (re-opened silently where a key stands, the new reference named), `unreachable`; and the RELEASE of a leaving session's drafts supplement — one per principal — to another session of its principal standing at the board, narrowed only where none stands |
| `hold` | the held-burst hold (§3c.4, §3c.5): a burst's door, `Burst::admit` — a frame the board takes at no send refused at the act (`frame_too_large`, `malformed_args`, `attest_not_composed`) and never held — and its write path — held without a dial where a hold stands, refused `held_full` where the principal's queue holds its budget, else dialed once and its answer read once through the classification table (what a dial answers → hold / reissue / neither), first dial and resend alike — the per-(board, principal) queue over `held`'s file, each board's under its own lock, its principal's file opened at a session's open, the `base` every acked write sets, and the resend walk — one `/changes` read per document before its first resend, with the three outcomes (send from the head, the in-flight burst kept, the moved document faced), a read the board refuses deciding nothing — driven by the feed worker's probe; the backing of `held(session)` and `resolve(session, {held, act})` |
| `feed` | the feed consumer's thread per board, reached through the board's own handle — a channel, so a call waiting on one board's thread holds nothing another call needs: `search::Consumer` polled on the `/events` commits — coalesced, one read waiting at most, never a read per commit — the `/changes` pages re-read for the `feed` events — a closing session's drafts read once more under its token before its close answers, so its every row precedes its `session-died` — `mode`, `daemon` and `index` as the state moves, and the `search` call answered off the consumer; it also reads `writes.halted` per tick and drives the held-burst PROBE every cadence, measured from the last probe whatever wakes the thread between |
| `shell` | `Shell`: the boards, the sessions, the session mode, and one private method per §4b.1 row behind `call(name, args)`, which dispatches by the bridge's spelling — one arm per call, the compiler holding the match exhaustive — and logs every call; the `op` row hands a burst to the hold's write path, which answers `held` where the board cannot take it, and notes every other write's ack for the hold's `base`; `fetch` public beside it, since it streams and its transport logs it; `answer`, `cancel`; `shutdown`, which dropping a shell runs too; `set_node_state`, the own node's state — the hold's stopped state — which `probe` answers and the `daemon` event announces at its board |
| `shapes` | `declarations()`, the TypeScript declaration file for every value that crosses the bridge, rendered from one table and pinned by a round-trip of each type's sample, its call rows held equal to `CALLS` and its event names rendered from `EventName` |

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
`as_of`, not the genesis's position by bisection.

No feature, no async runtime, no HTTP crate: std beside the workspace's
crates, as `skep-client`'s rule has it. The transport is not here.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](../../LICENSE-APACHE))
- MIT license ([LICENSE-MIT](../../LICENSE-MIT))

at your option.
