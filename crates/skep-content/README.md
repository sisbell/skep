# skep-content

The permascroll: skep's append-only, write-once content store.

Part of [skep](https://github.com/sisbell/skep), an open-source hypertext substrate in the Project Xanadu lineage.

- **Address → value** — immutable content values keyed by element
  address in a persistent map ordered by address (structural sharing
  makes snapshots nearly free; the order lets a checkpoint walk the
  whole store without sorting it).
- **Write-once** — a value is stored at a minted address exactly once
  and never mutated; edits happen in the arrangement layer
  ([skep-arrangement](../skep-arrangement)), never by overwriting
  content.
- **`stage_write` / `value_at` / `contains`** — the storage half of
  insertion composites, the value read retrieval answers from, and the
  check other stores consult: is content stored here? Point reads alone,
  but for one enumeration, `iter`, which exists for the daemon's
  cell-index rebuild at open and nothing else.

Content here is raw bytes at addresses; what a document *says* is an
arrangement over these bytes, owned one layer up.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](../../LICENSE-APACHE))
- MIT license ([LICENSE-MIT](../../LICENSE-MIT))

at your option.
