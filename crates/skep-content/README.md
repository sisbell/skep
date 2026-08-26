# skep-content

The permascroll: skep's append-only, write-once content store.

Part of [skep](https://github.com/sisbell/skep), an open-source hypertext substrate in the Project Xanadu lineage.

- **Address → bytes** — immutable content values keyed by element
  address in a persistent map (structural sharing makes snapshots
  nearly free).
- **Write-once** — a minted position is filled exactly once and never
  mutated; edits happen in the arrangement layer
  ([skep-arrangement](../skep-arrangement)), never by overwriting
  content.
- **`stage_write` / `value_at` / `contains`** — the storage half of
  insertion composites, the fold's payload read, and the referential
  gate other stores consult.

Content here is raw bytes at addresses; what a document *says* is an
arrangement over these bytes, owned one layer up.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](../../LICENSE-APACHE))
- MIT license ([LICENSE-MIT](../../LICENSE-MIT))

at your option.
