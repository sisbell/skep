# skep-retrieval

Content retrieval and comparison: skep's read-only query layer
over documents.

Part of [skep](https://github.com/sisbell/skep), an open-source hypertext substrate in the Project Xanadu lineage.

- **`retrieve_v`** — deliver the content at a list of document V-spans,
  in the order asked: one item per position, a link position as its
  address; `retrieve_v_masked` withholds each run whose origin the
  caller's predicate cannot read.
- **`doc_vspan` / `doc_vspanset`** — a document's extents: its bounding
  span, or one exact span per occupied subspace.
- **`show_origin_v`** — the documents a span's content originated in,
  deduplicated (transclusion made visible).
- **`show_deletions`** — what one document deleted that another still
  holds, both ways.
- **`compare`** — the content two document regions share, as
  address-equal correspondences — never a comparison of bytes.
- **`find_docs_containing`** — the documents that hold some of a
  region's content now; `find_docs_containing_filtered` drops each one
  the caller's predicate cannot read.

Read-only by construction: no transaction, no lock, no write path —
every query pins one immutable snapshot. `retrieve_v`, `compare` and
`find_docs_containing` refuse a request past their published budgets
rather than answer part of it.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](../../LICENSE-APACHE))
- MIT license ([LICENSE-MIT](../../LICENSE-MIT))

at your option.
