# skep-coordination

The predicate and coordination layer: a closed, typed language of
predicates over the link store, predicates stored as content, and the
rule machinery over them.

Part of [skep](https://github.com/sisbell/skep), an open-source hypertext substrate in the Project Xanadu lineage.

- **The predicate language** — a closed, typed, read-only algebra over
  the link store's per-type reads; every verdict is decided against one
  pinned snapshot, with one denotation for every caller.
- **Predicates as content** — terms stored as immutable content, then
  registered, versioned and certified as typed links (`pdef`,
  `pd_stable`); a stored predicate is named by its content address.
- **Rules** — trigger→action rules whose actions (a marker deposit, a
  nullify) run as system writes through the link store's gated path,
  with quiescence detection, a fair scheduler and a termination lint.

Deliberately thin: predicates read through the stores' own surfaces,
fires write through their own gated paths — this crate owns
coordination, never storage.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](../../LICENSE-APACHE))
- MIT license ([LICENSE-MIT](../../LICENSE-MIT))

at your option.
