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
  `/health`, and the session routes `/challenge`, `/session`,
  `/session/close`.
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
transaction; and, above the claim, the `sig` a credential record carries
inside its own atom, checked in the credential sequence at the record's
`make_link` under the key set that opens the record's home — a record
carrying none is refused at its own `insert`, before it lands. Build the shipped
binary with `-p skepd` — Cargo unifies features across one invocation,
and a `--workspace` build that compiles the test suites turns the signer
on for everything it builds.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](../../LICENSE-APACHE))
- MIT license ([LICENSE-MIT](../../LICENSE-MIT))

at your option.
