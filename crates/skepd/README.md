# skepd

The skep daemon: one long-running process owning a board — the
journal, the engine, and the wire.

Part of [skep](https://github.com/sisbell/skep), an open-source hypertext substrate in the Project Xanadu lineage.

- **A hand-written HTTP/1.1 subset** over `std::net` — no server
  framework, no async runtime: the kernel's single applier already
  serializes writes, so worker threads are the whole concurrency
  story, and the commit stream needs flush-at-commit semantics
  pull-based servers cannot give.
- **The wire** — `/op` (execute), `/op-at` (historical reads over
  reconstructed worlds), `/chain` (the commit chain's value at a
  position), `/changes`, `/dump`, `/events` (commit stream),
  `/health`, the session routes `/challenge`, `/session`,
  `/session/close`, and the blob upload's family `/blob/upload` — the
  resumable PUT of a picture's bytes, streamed to the blob store
  ([skep-blobs](../skep-blobs)) one chunk at a time, and the deposit read.
- **The media door, the gate, the index and the pruner** — a picture's
  reference cell is parsed by one parser at every `insert` and `publish`
  and admitted only where its hash is one the caller's own cells already
  name over a whole file, or a deposit of the caller's own under a live
  lease; the gate's three scopes (the own scope — the base plus the
  pending bytes — the venue total, the floor) bound what a deposit may
  take; the cell index — per hash the cells naming it, per account the
  base — is entered at every commit that mints a cell and rebuilt at
  every open on a thread, its three readers (the upload's creation and
  resume, the deposit read) answered `503 index_rebuilding` until the
  walk completes and every other request served meanwhile; the pruner's
  pass removes expired partials and, under the credential lock's
  exclusive arm one file at a time, unlinks the files no cell names and
  no live lease holds, halting on a schema it does not know.
- **Deterministic JSON codec** — key-sorted marshalling so wire bytes
  never depend on map iteration order.
- **Durability is configuration** — fsync policy and checkpoint
  cadence are chosen here, not baked into the kernel.

A library and a binary. The binary runs against a data directory and
serves a board; the library (`Daemon`, `serve`) is the same daemon for
an embedder or a test. Everything it serves is the operation surface
of [skep-febe](../skep-febe) over the world of
[skep-engine](../skep-engine); how its modules are layered is in
[ARCHITECTURE.md](../../ARCHITECTURE.md).

The daemon verifies signatures and makes none: it calls
[skep-signature](../skep-signature)'s verify with that crate's `sign`
feature off, so its build holds no signer and no key. That verify runs
at three doors: the signed session's handshake; the entry signature a
publish-class write carries in its `attest`, checked before the
transaction; and, above the claim, the `sig` a credential record — or a
registry record, the binding and the endpoint of
[skep-registry](../skep-registry) — carries inside its own atom, checked
in the credential or the registry sequence at the record's `make_link`
under the key set that opens the record's home — a record carrying none
is refused at its own `insert`, before it lands. The open runs the
registry's seeding check ahead of every genesis. Build the shipped
binary with `-p skepd` — Cargo unifies features across one invocation,
and a `--workspace` build that compiles the test suites turns the signer
on for everything it builds.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](../../LICENSE-APACHE))
- MIT license ([LICENSE-MIT](../../LICENSE-MIT))

at your option.
