# skep

> **skep** *(n.)* — the coiled-straw beehive: the structure a swarm
> builds and inhabits.

The implementation of the Xanadu-derived hypertext system: a permanent,
content-addressed document substrate (addresses, transactions, namespace,
content, arrangements, links, retrieval, query) with a stigmergic
**predicate-coordination** layer built on top, through which agents coordinate
by reading and emitting marks in the shared substrate.

Built in Rust as a Cargo workspace. The module decomposition, per-module
designs, and conformance suites are produced in the reasoning-lattice project
and exported here as they converge.

## Workspace

Twenty-four crates; the boundaries are the architecture. Fourteen domain
crates realize the spec's converged designs (the M1–M10 modules, the
AUTH identity layer, signed ops, the registry and the blob store) and
encode the composition contract's
layering in the dependency graph itself — the
compiler enforces what the design ruled (no store depends on the engine,
type-only edges stay type-only, nothing depends on the engine but a
binary). Beneath them, one support crate; above them, the daemon's media
resource, one assembler, the transport adapters, the verifying registry
resolver, the search index, the client library and the `skep` command;
beside them, the differential-conformance harness.

| crate | role |
|---|---|
| `skep-address` | M1 — tumblers, T4 addresses, span algebra (pure values) |
| `skep-kernel` | M2 — transactions, journal/WAL, checkpoints, recovery |
| `skep-namespace` | M3 — accounts, delegation, baptism, ownership |
| `skep-content` | M4 — the permascroll: write-once address→value map |
| `skep-arrangement` | M5 — document arrangements (V→I), provenance |
| `skep-retrieval` | M6 — content/provenance queries |
| `skep-links` | M7 — permanent typed links, supersession, retraction |
| `skep-discovery` | M8 — link discovery, four-set queries, projection |
| `skep-coordination` | M9 — predicate definitions & coordinator (stateless) |
| `skep-febe` | M10 — the operation surface (`Operation<W>`), codec seam |
| `skep-identity` | AUTH — credential records, key sets, the identity fold (pure) |
| `skep-signature` | signed ops — the hybrid signature: key derivation, signing, verify |
| `skep-registry` | the registry's commons rows and binding/endpoint bodies (pure values) |
| `skep-blobs` | the blob store: deposited files, partial uploads, upload records, leases |
| `skep-util` | the support crate below the daemon and the media crate: the counting permit pool, the operator's notice line, the JSON determinism helpers |
| `skep-media` | the daemon's media resource: the cell's one parser, the media door, the gate over the blob store, the cell index, the pruner, the fetch — generic over the world, no engine |
| `skep-engine` | the one assembler: `World`, genesis, recovery, `world_at` |
| `skepd` | the daemon: HTTP/JSON wire v4, sessions, history, SSE |
| `skep-mcp` | stdio MCP adapter for agent harnesses |
| `skep-resolve` | the verifying registry resolver: a library a client embeds (no engine, no store, never `skepd`) |
| `skep-search` | the search index: a library a client embeds — the document model, the tokenizer, the inverted index with positions (no engine, no store, never `skepd`) |
| `skep-client` | the library every acting client embeds: the dialer, sessions, the key store, signing, the reader's verifier, the claim ceremony |
| `skep-cli` | the `skep` command over `skep-client`: keygen, claim, session, fingerprint, verify, health, bind, and the ceremonies enroll, recover, retire, rotate, handoff, accept |
| `skep-conformance` | differential harness vs. `udanax-green` goldens + ratchet |

Conventions: shared metadata and external-dependency versions live in
`[workspace.package]` / `[workspace.dependencies]` (crates add features,
never different versions); one lockstep version for the family; the
toolchain is pinned in `rust-toolchain.toml` and bumped only with a full
gate run. Release binaries are `skepd` and `skep-mcp`; library crates
publish to crates.io as they stabilize (`skep-address` first). The wire contract clients build against is
`docs/wire.md` — the contract as it stands; versioning begins at the first
release, independent of crate versions. License: MIT OR Apache-2.0 (dual, the Rust convention).
The runbook for running a board — start, stop, restart, upgrade, back up, restore, the full volume — is [RUNBOOK.md](RUNBOOK.md).
See [CONTRIBUTING.md](CONTRIBUTING.md) for the commit convention.

**Keys and the claim.** The client you install IS the board: `skepd` on
your machine is the notebook, and stopping before `skep claim` leaves
nothing behind — no board, no account, no key. Once claimed, every edit to
your notebook, including what you later remove, is kept; its history is
permanent, and it is local: no mirror holds it and this board can never be
made public. The records it holds — your keys, your claim, the grants you
issue — stand as records of their own, so removing the text one names does
not remove it. This notebook is local forever; public work happens in an
org, and that venue is not reachable on any board today — this board can
never become one when they open. The page `skepd` serves is a READER: it
holds no keys, opens no sessions, writes nothing, and does not verify
signatures. A person acts from the `skep` command (`crates/skep-cli`:
`skep keygen` makes the device key, `skep claim` runs the ceremony) or
from the bundled app, whose page acts through the shell's bridge over
`skep-client`. The claim's backup moment writes two anchor FILES by default
— to directories you name, never under the key store — and prints a sheet
only under `--paper`; `skep recover` is the way back in from
a kept file or a print, and no one else holds a reset. The later gestures
are commands too: `skep enroll` adds a device from one already signed in,
`skep retire` and `skep rotate` retire and replace a device key after a
previewed, typed confirmation, `skep recover --anchor-lost` replaces a lost
paper under the surviving one, and `skep handoff` with `skep accept` give a
subdivision to another party.

## Running a daemon for frontend development

Build and run the daemon on loopback against a throwaway board:

```
cargo run -p skepd -- --data-dir ./board --origin http://127.0.0.1:8642
```

The daemon listens on 127.0.0.1:8642 only. The board is UNCLAIMED until you
claim it, and while it is unclaimed anything that can reach the port can take
it: never forward the port before the claim. Claim it from the `skep` command
(`cargo run -p skep-cli --bin skep -- keygen`, then
`claim --board http://127.0.0.1:8642`); the claim writes two anchor files to
directories you name — keep them apart, and never under ~/.skep.

Local trust stays on, the daemon's default, because the dev provider below
opens a bare session as the claimant, which a claimed board admits only while
local trust is on. That lets any loopback party write as any principal, as the
daemon warns at each start once the board is claimed: a cost a throwaway nobody
else reaches can bear.

Your page never posts /session and never holds a session token. The dev
provider, `skep-dev serve`, is a process beside your dev server that opens the
session itself as a loopback peer and carries the page's calls to the daemon:

```
cargo run -p skep-cli --bin skep-dev -- serve --board http://127.0.0.1:8642 \
    --session bare --page-origin http://localhost:5173
```

`--page-origin` is your dev server's origin, the one origin the provider
admits; `crates/skep-cli/README.md` has the rest. Do NOT pass the dev server's
origin to the daemon as `--origin`: a configured origin is permanent on that
board and stays signable after the claim. Bare sessions write drafts and never
publish; to exercise publishing, start the provider with
`--session signed --dir ~/.skep`, which signs with the key that claimed the
board, and the page still holds no token.

To see the daemon's own read-only viewer, build with the `client` feature and
open http://127.0.0.1:8642/; it opens no session. `--allow-preview-keys` is for
the test fixtures only: a preview key enrolled is enrolled for life.

Throw the board away with `rm -rf ./board`. For a notebook you keep, see
[RUNBOOK.md](RUNBOOK.md): Start, step 2, and §9, Running it as a service.

---

*An independent reimplementation derived from the published Xanadu design
(Ted Nelson, *Literary Machines*) and Roger Gregory's `udanax-green`. Not
affiliated with or endorsed by Project Xanadu or Ted Nelson.*
