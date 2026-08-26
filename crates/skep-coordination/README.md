# skep-coordination

The predicate and coordination layer: a closed vocabulary of
link-level predicates and the system-rule machinery over them.

Part of [skep](https://github.com/sisbell/skep), an open-source hypertext substrate in the Project Xanadu lineage.

- **The predicate vocabulary** — a small closed set of link/document
  predicates (membership, targeting, kind tests, behavior classes)
  every rule and reader shares; one denotation, no per-caller
  variants.
- **Rule fires** — registered rules whose actions (marker deposits,
  nullifies, content writes) run as system writes through the
  ordinary stores, attributed and journaled like any other act.
- **The catalog** — the engine-assembled registry of definitions the
  layer projects.

Deliberately thin: predicates read through the stores' own surfaces,
fires write through their own gated paths — this crate owns
coordination, never storage.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](../../LICENSE-APACHE))
- MIT license ([LICENSE-MIT](../../LICENSE-MIT))

at your option.
