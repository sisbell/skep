# skep-discovery

Link query and discovery: the read-only surface for finding
links, documents, and structure.

Part of [skep](https://github.com/sisbell/skep), an open-source hypertext substrate in the Project Xanadu lineage.

- **`find_links`** — by endset overlap, by type, from either end;
  results in permanent address order (stable pagination by
  construction).
- **Windows and counts** — bounded slices over large result sets.
- **Orphan preview and lineage** — what a deletion would strand;
  derivation ancestry walks.
- **Pure `*_on` twins** — every read has a form taking an explicit
  snapshot, so callers own the consistency point and can report
  as-of positions.

Presents the link store's matcher — never reimplements it; binds one
snapshot per operation and writes nothing.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](../../LICENSE-APACHE))
- MIT license ([LICENSE-MIT](../../LICENSE-MIT))

at your option.
