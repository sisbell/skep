# skep-engine

The assembler: one crate that composes skep's stores into the
concrete world the kernel journals.

Part of [skep](https://github.com/sisbell/skep), an open-source hypertext substrate in the Project Xanadu lineage.

- **`World`** — the store slices (namespace, content, arrangement,
  links) as one immutable value implementing the kernel's
  `WorldState`, led by a checkpoint format stamp so a base written
  under another layout fails to decode rather than misreading.
- **The central record enum** — one variant per store's record type;
  the engine lifts and folds, but store records stay constructible
  only by their own crates.
- **Accessor impls** — each store's read-seam trait implemented over
  the assembled world, so store crates stay generic.
- **Genesis and recovery order** — the constant initial world (the
  namespace roots and the empty docuverse; the reserved type registry
  is compiled format, not seeded state) and the one stated
  `rebuild_derived` order.
- **The exception set** — the derived membership index over M3's
  publication bit (`World::published`, `World::owner_account`):
  seeded at load, folded on every document-minting record, never
  checkpointed. The daemon's one publication definition.
- **The read predicate and the grant fold** — `World::readable`,
  the one function every read surface answers through
  (published ∨ owner subtree ∨ grant), and the second derived
  index it rests on: a fold over the link store recognizing
  grant-typed records as values, seeded at load, folded on every
  link deposit, never checkpointed. The fold also enumerates the
  change feed's grant keys (`World::universal_grants`,
  `World::issuers_for`), and the stored index M10's any-principal
  discovery read narrows.
- **The edition-claim lookup** — `World::edition_claims`, the
  audit-view lookup over the edition-claim class, composed from the
  link store's own reads and answered unfiltered, for the operation
  surface to filter by home.
- **The commons type pins** — the `types` module: every commons type
  address the engine or the daemon keys on as a value, in one
  prefix-free ledger.
- **`Engine`** — `Engine::open`, genesis-or-recover in one call; the
  M9 `Coordinator` assembly (`Engine::coordinator`); and the
  `Stores<World>` factory the operation surface injects.
- **The world dump** (behind the default-on `dump` feature) — a
  deterministic, byte-comparable rendering of the whole state, the
  crash and conformance harnesses' oracle, and the same rendering
  filtered at a reader's class for the daemon's `/dump`.

Everything above the stores and below the wire: the one place a
concrete `World` is defined.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](../../LICENSE-APACHE))
- MIT license ([LICENSE-MIT](../../LICENSE-MIT))

at your option.
