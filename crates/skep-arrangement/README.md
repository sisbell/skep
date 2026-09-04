# skep-arrangement

Arrangements and editing: the versioned V→I mapping that makes
skep documents editable over immutable content.

Part of [skep](https://github.com/sisbell/skep), an open-source hypertext substrate in the Project Xanadu lineage.

- **The Vstream** — per-document run lists mapping virtual positions
  (what a reader sees) onto immutable content addresses (what is
  stored); every edit is a new arrangement, never a byte change.
- **Editing composites** — insert, copy (transclusion — the copied
  spans keep their origin identity), delete, rearrange; each a
  kernel transaction composing namespace mints and content writes.
- **Versioning** — VERSION forks a document: the fork's arrangement
  starts as a snapshot of the source's content map, the source
  untouched, and the two diverge copy-on-write. An owned fork's
  ancestry is carried by the identity itself, readable by truncation;
  a cross-owner fork's identity is severed from the source's, and what
  records the relationship is provenance.
- **Provenance (R)** — the append-only record of which addresses a
  document has ever contained, including a fork's shared ones. It is
  recorded, not recomputable: an arrangement that no longer holds an
  address cannot tell you it once did, which is what makes deletions
  and "who has ever contained this" answerable at all.
- **`resolve` / `project`** — V→I image and I→V occurrences, the
  reads every query layer builds on.

Rides the kernel for atomicity and recovery; consumes
[skep-address](../skep-address) span algebra throughout.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](../../LICENSE-APACHE))
- MIT license ([LICENSE-MIT](../../LICENSE-MIT))

at your option.
