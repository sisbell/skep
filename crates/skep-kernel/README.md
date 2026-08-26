# skep-kernel

The transactional heart of skep: a generic write-ahead-journal +
snapshot kernel over an engine-supplied world state.

Part of [skep](https://github.com/sisbell/skep), an open-source hypertext substrate in the Project Xanadu lineage.

- **`WorldState`** — the one trait a world implements: a pure,
  deterministic `apply` folds each journaled record; `rebuild_derived`
  reseeds skip-serialized hints at load.
- **Append-only journal** — CRC-framed records, committed by marker;
  recovery is replay: checkpoint (or genesis) plus every committed
  record reproduces the exact world.
- **Single applier** — one writer critical section (`transact`)
  serializes all mutation; readers take lock-free snapshots
  (atomically installed immutable worlds).
- **Checkpoints** — periodic serialized worlds with a fallback chain
  at load: a checkpoint that fails to resolve steps back to an older
  one, or to genesis, and replays forward.
- **Keyed critical sections** — byte-keyed locks (`LockKey`) let
  logically-independent writes proceed concurrently where the world's
  invariants permit.

The kernel knows nothing about documents, links, or addresses — it is
generic over the world the engine assembles.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](../../LICENSE-APACHE))
- MIT license ([LICENSE-MIT](../../LICENSE-MIT))

at your option.
