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

| module | holds |
|---|---|
| `refs` | the reference registry's NAMES: a board reference (`b-…`) and a session reference (`s-…`) minted from OS entropy per process, never a credential, never derived from an origin or a token (§4b.1, THE PIN) |
| `log` | the call log and the dial log the page's gate reads — every call the page made, every dial the shell made, sizes and timing, never a token or a body — and `LoggingDialer`, the one `PlainHttp` every board dials through |
| `events` | the event stream: `mode`, `session-died`, `daemon`, `feed`, `index`, `moment`, each a value with the name §4b.2 spells, fanned out to every subscriber in order |
| `refusal` | the one refusal shape: `{kind, name, …}` — the board's own verdict verbatim (`refused`), a halt's face under the armed name (`halt`), the block (`blocked`), the unreachable board (`unreachable`), the shell's own (`shell`: `session_ended`, `unknown_board`, `query_too_long`, `write_in_guest_form`, `not_reached`, `abandoned`, …) |
| `script` | the DEV ARM for the SECRET and CONSENT moments (§4b.3): a script file's answers in order (`confirm yes`, `retype sheet 0`, `destination <path>`, `import neither`, `kept`, `abandon`, …), or the auto arm; every answer said on TALK, never sent to the page |
| `person` | the person over the bridge: a `Person` whose PUBLIC moments become `moment(id, kind, data)` events and block until `answer(id, value)` or `cancel(id)`; its SECRET and CONSENT moments go to the dev arm |
| `attest` | the publish-class attest a signed session composes for the ten kinds that have an entry frame — the frame's every axis from the shell's own reads, a `publish`'s copied runs read back through the origin's arrangement — attached as the frame's `attest` |
| `sessions` | the session table (the token under its reference), the two openings — bare as the principal, signed content-scoped behind AUTH-5.65's pre-check with `no_key`, `origin_state`, `retired`, `not_enrolled`, `busy`, `blocked`, `unreachable` — and the arm a `session-died` carries: `closed`, `mode` (a bare session at the flip), `retired` (own or another hand, the hand and position named), `seeded`, `blocked`, `restart` (re-opened silently where a key stands), `unreachable` |
| `feed` | the feed consumer's thread per board: `search::Consumer` polled on each `/events` commit, the `/changes` pages re-read for the `feed` events, `mode`, `daemon` and `index` as the state moves, and the `search` call answered off the consumer |
| `shell` | `Shell`: the boards, the sessions, the session mode, and one method per §4b.1 row (`call(name, args)` dispatches by the bridge's spelling); `answer`, `cancel`; `shutdown` |
| `shapes` | `declarations()`, the TypeScript declaration file for every value that crosses the bridge, rendered from one table and pinned by a round-trip of each type's sample |

## The `feed` update's shape

This crate's definition (S-24 (b)): the `/changes` entry's members VERBATIM
(`at`, `op`, `docs`, `key`, `time`, `attest`, `new_prefix`, `new_id`,
`link`, `placed`, `base_extent`, and any later member by the wire's forward
rule), plus `position` (the entry's `at`, named once more) and `class` —
`published` for a row of the guest's feed, `drafts` for one of a session's
supplement, the latter with `session`, the reference it was read under. The
event carries `board`, the reference, beside `update`. The feed starts at
the head the consumer found when it started: a page re-reads what it shows
on open and takes the updates from there.

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
