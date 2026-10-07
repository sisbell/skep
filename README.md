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
| `skep-cli` | the `skep` command over `skep-client`: keygen, claim, session, fingerprint, verify, health, bind |
| `skep-conformance` | differential harness vs. `udanax-green` goldens + ratchet |

Conventions: shared metadata and external-dependency versions live in
`[workspace.package]` / `[workspace.dependencies]` (crates add features,
never different versions); one lockstep version for the family; the
toolchain is pinned in `rust-toolchain.toml` and bumped only with a full
gate run. Release binaries are `skepd` and `skep-mcp`; library crates
publish to crates.io as they stabilize (`skep-address` first). The wire contract clients build against is
`docs/wire.md` — the contract as it stands; versioning begins at the first
release, independent of crate versions. License: MIT OR Apache-2.0 (dual, the Rust convention).
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

---

*An independent reimplementation derived from the published Xanadu design
(Ted Nelson, *Literary Machines*) and Roger Gregory's `udanax-green`. Not
affiliated with or endorsed by Project Xanadu or Ted Nelson.*
