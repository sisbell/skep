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

Fifteen crates; the boundaries are the architecture. Eleven domain
crates realize the spec's converged designs (the M1–M10 modules and
the AUTH identity layer) and encode the composition contract's
layering in the dependency graph itself — the
compiler enforces what the design ruled (no store depends on the engine,
type-only edges stay type-only, nothing depends on the engine but a
binary). Above them, one assembler and the transport adapters; beside
them, the differential-conformance harness.

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
| `skep-engine` | the one assembler: `World`, genesis, recovery, `world_at` |
| `skepd` | the daemon: HTTP/JSON wire v4, sessions, history, SSE |
| `skep-mcp` | stdio MCP adapter for agent harnesses |
| `skep-conformance` | differential harness vs. `udanax-green` goldens + ratchet |

Conventions: shared metadata and external-dependency versions live in
`[workspace.package]` / `[workspace.dependencies]` (crates add features,
never different versions); one lockstep version for the family; the
toolchain is pinned in `rust-toolchain.toml` and bumped only with a full
gate run. Release binaries are `skepd` and `skep-mcp`; library crates
publish to crates.io as they stabilize (`skep-address` first). The wire contract clients build against is
`docs/wire.md` — versioned in its own changelog, independent of crate
versions. License: MIT OR Apache-2.0 (dual, the Rust convention).

---

*An independent reimplementation derived from the published Xanadu design
(Ted Nelson, *Literary Machines*) and Roger Gregory's `udanax-green`. Not
affiliated with or endorsed by Project Xanadu or Ted Nelson.*
