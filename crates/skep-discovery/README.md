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
  a window pays for the links it returns and the homes it passes, the
  cursor naming the home it resumes in.
- **Reads that pay for what the reader may read** — every read of a
  set of links names the homes its query could meet off the link
  store's directory, asks the reader once per home, and reads only the
  homes it may read, so the links of other people's private documents
  cost it nothing; a descriptor constraining two slots drives from the
  one naming fewer homes; a descriptor naming a home reads that home's
  links by their key range; the claims naming a link are read off the
  coverage index, never by a walk of the supersession class.
- **Orphan preview and lineage** — what a proposed delete would
  strand from a document; the supersession claims naming a link
  (one hop — the walks are the link store's).
- **Answers for a reader** — every link read takes the caller's
  reader predicate and returns no link homed where that reader may
  not read. What a surviving link contributes — its endsets, a
  supersession claim's endpoints — comes back whole, as the
  publication rules require, and may name such a link.
- **Reads over a snapshot you hold** — every read is a free `*_on`
  function over an explicit snapshot, so the caller owns the
  consistency point and can report as-of positions.

Presents the link store's matcher and keeps no index of its own; reads
one snapshot per operation, the one its caller hands it, and writes
nothing.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](../../LICENSE-APACHE))
- MIT license ([LICENSE-MIT](../../LICENSE-MIT))

at your option.
