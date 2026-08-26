# skep-engine

The assembler: one crate that composes skep's stores into the
concrete world the kernel journals.

Part of [skep](https://github.com/sisbell/skep), an open-source hypertext substrate in the Project Xanadu lineage.

- **`World`** — the store slices (namespace, content, arrangement,
  links) as one immutable value implementing the kernel's
  `WorldState`.
- **The central record enum** — one variant per store's record type;
  the engine lifts and folds, but store records stay constructible
  only by their own crates.
- **Accessor impls** — each store's read-seam trait implemented over
  the assembled world, so store crates stay generic.
- **Genesis and recovery order** — the seeded initial world (reserved
  types, roots) and the pinned `rebuild_derived` order.
- **`Engine::open`** — genesis-or-recover in one call; the
  `Stores<World>` factory the operation surface injects.

Everything above the stores and below the wire: the one place a
concrete `World` is named.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](../../LICENSE-APACHE))
- MIT license ([LICENSE-MIT](../../LICENSE-MIT))

at your option.
