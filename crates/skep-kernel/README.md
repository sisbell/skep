# skep-kernel

The transactional heart of skep: a generic write-ahead-journal +
snapshot kernel over an engine-supplied world state.

Part of [skep](https://github.com/sisbell/skep), an open-source hypertext substrate in the Project Xanadu lineage.

- **`WorldState`** — the one trait a world implements: a pure,
  deterministic `apply` folds each journaled record; `rebuild_derived`
  reseeds skip-serialized hints at load.
- **Append-only journal** — CRC-framed records, committed by marker;
  recovery is replay: checkpoint (or genesis) plus every committed
  record reproduces the exact world. Every marker carries a commit-chain
  link over its transaction's records, its per-transaction salt and a
  digest of its signature slot, so a rewrite — a signature stripped or
  altered included — is a chain break at its transaction.
- **Single applier** — one writer critical section (`transact`)
  serializes all mutation; readers take lock-free snapshots
  (atomically installed immutable worlds).
- **Checkpoints** — periodic serialized worlds with a fallback chain
  at load: a checkpoint that fails to resolve steps back to an older
  one, or to genesis, and replays forward. The cadence is tested on
  commit — a count, a byte bound, or either, whichever first — and runs
  inline on the committing thread or, under the deferred form, sets a
  due flag the caller's own thread services (`checkpoint` clears it
  first, then runs; a second crossing with the flag still set runs
  inline as the backstop). The header carries the file's length, the
  figure a floor or a byte bound is sized by, and the kernel removes
  its own `checkpoint.tmp`: a failed write before answering, the open
  one a crash left.
- **Keyed critical sections** — every write names the `LockKey`s it
  would hold. Under the v1 single applier one lock serializes all writes,
  and the keys are the seam a per-key realization will use without
  changing any call shape.

The kernel knows nothing about documents, links, or addresses — it is
generic over the world the engine assembles.

A journal written under an older format stamp is refused by name
(`OpenError::ForeignFormat`), and the remedy is the ruled one: there is
no migration path — every board is a development artifact (PUB-1.2):
delete the data directory and start over.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](../../LICENSE-APACHE))
- MIT license ([LICENSE-MIT](../../LICENSE-MIT))

at your option.
