# skep-resolve

The verifying registry resolver: a mirror of the registry board from a
shipped root hint, every binding and endpoint it reads verified under its
home's key set, the verified bindings indexed by prefix, and the walk from
a prefix to its endpoint and key set — or to a named state saying why not.

Part of [skep](https://github.com/sisbell/skep), an open-source hypertext substrate in the Project Xanadu lineage.

## 1. What skep-resolve is

A LIBRARY the frontend, the `skep` command and a node's federation
transport embed. It links no daemon and no engine, speaks the wire as a
guest, and opens no socket to an endpoint: the dial is the caller's. Its
parts, each under the design rule it realizes:

- **The root hint** (`RootHint`, `realm_id`) — the registry root's
  origin(s), the realm id (the fingerprint of the root's GENESIS key set,
  REG-3.39) and the fork point on a forked lineage (REG-3.40), ONE
  overridable config value and never a baked constant (REG-3.2), parsed
  from one line — `https://registry.example realm:<64 hex>` — and from a
  struct. Every resolution the mirror performs is scoped to the hint's
  realm by construction (REG-3.42).
- **The mirror** (`Mirror`) — a `/changes` consumer from the floor
  (REG-3.10: no TTL, no negative cache) that fetches every row's bytes it
  needs — the stored link, the atom at the position the link names, the
  home's credential table AS OF the record's position: the live `key_set`
  where the credential acts the mirror holds prove it the same table,
  `/op-at` otherwise — and keeps a journal copy from genesis under a
  caller-given directory: `feed.jsonl`, the copy of the feed the check
  covers, and `fetched.jsonl`, the mirror's own fetch cache the rebuild
  reads, both begun afresh by a new base, so a cache that outlived its
  feed copy is never read as this mirror's own. A sync that fails leaves
  its rows held, and the next takes them up where it stopped. A key table
  holding a key this build cannot read is no table, never a smaller one.
  The base is from genesis at the root the hint names (REG-3.12); a
  held copy is CHECKED against the source read from genesis and resumed
  only where every held position comes back identical and every held chain
  pair answers the same (REG-3.18); on either, the realm is compared at the
  claim's row against the genesis set the source answers (REG-3.42), and
  no line reaches the copy before it is; a re-pointed hint re-bootstraps
  afresh (REG-3.17); the refusals are named (`Refusal`: a diverged
  frontier, a source behind the mirror, a contradicted chain pair, a realm
  mismatch — REG-3.19). An image that omits, re-orders or replays genuinely
  signed rows fails the check at the first position that differs
  (REG-3.13). An atom un-arranged at the head is recovered by the home's
  chain walk, one version at a time (REG-3.25), its cost counted
  (`WalkStats`). A mirror rebuilt from its copy alone, no board dialed,
  says so (`Opened::Rebuilt`).
- **The verify** (`judge`, `Trial`) — the record grade for registry
  records, client-side (rm-2; REG-1.86 (e)): the body parsed under the
  canonical rule by `skep_registry::parse`, the record frame rebuilt from
  the row's own members, the signer found in the set that opens the home's
  account as of the position, both halves verified. The verdict is one of
  the signed-ops record §3.5's five values (`Verdict`) and stands beside
  every record the index holds; a record not SIGNED is suppressed and
  counted (`Index::suppressed`), never consulted at a resolve.
- **The index** (`Index`) — the position-annotated prefix → binding index
  over the verified bindings (REG-3.21 to REG-3.26), its one writer the
  mirror's gate: a binding from the claimant's doc 1 alone, a record SIGNED
  alone, the rest counted by cause (`Index::suppressed`). Membership is the
  rule's own test: the binding walk on the audit view with the replay
  clause (REG-2.8 to REG-2.11, REG-2.24) — a retraction clears nothing —
  and the endpoint's currency on the active view (REG-1.10, REG-1.11).
- **The walk** (`resolve`, `guest_resolve`) — `1.5` → the binding → the
  account → its key set and current endpoint (REG-3.7 to REG-3.9); a depth
  address resolves to its parent's standing — a parent with a standing,
  never one whose bindings are all inert — and THE HOP NOT MADE
  (REG-3.82). The guest-reading resolve scans every binding's atom with no
  mirror (REG-3.24, REG-3.33), priced (`GuestCost`), its verdicts
  undeterminable here: it folds what it reads, from every home, into a
  ledger of the rules alone and never into an index.
- **The origin checks** (`judge_member`, `walk_members`) — https or a
  self-authenticating origin per member (REG-3.34), the host term met by an
  address and never a name — this resolver's own resolution of a name,
  tested at every address it yields (REG-3.35) — the ordered walk's one
  precedence, and the dial not made for a kind whose transport is not held.
- **The states** (`Resolution`) — every outcome a named visible state
  (REG-3.80): UNREGISTERED, RETIRED-WITH-HISTORY, BOUND-BUT-UNREACHABLE,
  unreachable-by-policy, THE DIAL NOT MADE, THE HOP NOT MADE, BOUND; and
  BOUND-BUT-DISCLAIMED and the live-enforcement face, named for the caller
  to fill after the dial it alone makes. A face naming a bound account
  carries its key set, `None` where this reader could not read it — never
  an empty set in its place. No copy, no rendering.

The HTTP client (`Http`, `Transport`) is a written-out HTTP/1.1 client
over `std::net`, as the MCP adapter's is; it speaks plain `http` alone, so
an `https` root is a transport this build does not hold, refused by name.
The board's typed reads (`Board`) run over any `Transport` — that client,
or a suite's replay of a recording — and count every read by kind
(`Reads`), reported in `Stats`; every value the resolver takes on the
board's word (the head pair, the board term, a link's slots, a key set) is
typed there.

## 2. The crate's suite and its fixture

The suite under `tests/it/` runs against a RECORDED feed,
`tests/fixtures/feed.json` — the wire exchanges a mirror made against a
board the daemon's suite built, two of its deliveries tampered on purpose (one
binding's `sig` zeroed, one body spaced) so the suppress is exercised.
The one command that regenerates it, from the daemon's own suite:

```sh
SKEP_RESOLVE_FIXTURE_WRITE=1 cargo nextest run -p skepd -E 'test(=resolve::the_fixture_board_resolves_live_and_is_recorded_on_demand)'
```

The end-to-end cells and the measurements run in the daemon's suite,
`crates/skepd/tests/it/resolve.rs`, where boards are spawned and
registered.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](../../LICENSE-APACHE))
- MIT license ([LICENSE-MIT](../../LICENSE-MIT))

at your option.
