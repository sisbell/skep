# skep-retrieval

Content retrieval and comparison: skep's read-only query layer
over documents.

Part of [skep](https://github.com/sisbell/skep), an open-source hypertext substrate in the Project Xanadu lineage.

- **Retrieve** — deliver a document's content (or any span of it) by
  resolving its arrangement against the content store, off one
  pinned snapshot per query.
- **`show_origin`** — pointwise provenance: every delivered position
  answers the document its bytes originated in (transclusion made
  visible).
- **`show_deletions` / `compare`** — what an edition removed;
  shared-content comparison between any two document regions.
- **Discoverability reads** — which documents contain a given
  content region; extents and counts.

Read-only by construction: no transaction, no lock, no write path —
every query binds one immutable snapshot.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](../../LICENSE-APACHE))
- MIT license ([LICENSE-MIT](../../LICENSE-MIT))

at your option.
