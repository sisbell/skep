# skep-discovery

Link query and discovery: the read-only surface for finding the
links that reach a document's content or match a description of
them.

Part of [skep](https://github.com/sisbell/skep), an open-source hypertext substrate in the Project Xanadu lineage.

- **Two ways to find links** — `findlinks_v_on` by content region
  (disjunctive over a link's slots, gated on the document) and
  `findlinks_ftt_on` by four-set descriptor (conjunctive,
  store-wide); results in permanent address order.
- **Windows and counts** — a stateless cursor over the same answer;
  a window bounds what comes back, not what is computed.
- **Orphan preview and lineage** — what a proposed delete would
  strand from a document; the supersession claims naming a link
  (one hop — the walks are the link store's).
- **Answers for a reader** — every link read takes the caller's
  reader predicate and reveals no link homed where that reader
  may not read.
- **Reads over a snapshot you hold** — every read is a free `*_on`
  function over an explicit snapshot and the caller's reader
  predicate, so the caller owns the consistency point and can report
  as-of positions.

Presents the link store's matcher — never reimplements it; reads one
snapshot per operation, the one its caller hands it, and writes nothing.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](../../LICENSE-APACHE))
- MIT license ([LICENSE-MIT](../../LICENSE-MIT))

at your option.
