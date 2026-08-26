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
  reconstructed worlds), `/changes`, `/dump`, `/events` (commit
  stream), `/health`.
- **Deterministic JSON codec** — key-sorted marshalling so wire bytes
  never depend on map iteration order.
- **Durability is configuration** — fsync policy and checkpoint
  cadence are chosen here, not baked into the kernel.

A binary crate: run it against a data directory and it serves a
board; everything it serves is the operation surface of
[skep-febe](../skep-febe) over the world of
[skep-engine](../skep-engine).

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](../../LICENSE-APACHE))
- MIT license ([LICENSE-MIT](../../LICENSE-MIT))

at your option.
