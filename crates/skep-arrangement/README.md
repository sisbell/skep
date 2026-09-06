# skep-arrangement

Arrangements and editing: the mutable V→I arrangement that makes
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
- **The publish shot** — `publish` appends the next member of a
  published document's version chain, born published, in ONE commit,
  from CLIENT-SUPPLIED I-address runs and never from any draft's
  arrangement at commit: the document's own runs stay by reference,
  the staging draft's are re-minted as fresh identity under the
  document's own I-space, and any other document's stay windows
  behind a per-origin source gate (`Withheld`); the base's post-render
  deposits are carried after them. The trunk advances while the base
  is still its head; otherwise the shot lands as the base's daughter,
  so two shots off one head both commit. A bare published address
  reads as its trunk head, a version address as itself forever, and a
  declared deposit into a chain lands in the head member alone.
- **Write-surface gates** — the four edit ops take a `Caller` and
  admit only the document's effective owner (ω, exact account match;
  `Caller::System` is the in-process automation path, exempt from ω
  alone). A PUBLISHED document refuses every in-place edit
  (`PublishedTarget`, PUB-2.11) except a DECLARED deposit `insert` at
  a fresh position past its arranged content — the one way content
  enters an account's born-published home; `version` refuses a
  private owned source (`PrivateSourceVersionless`, PUB-2.9) and an
  explicit-private member of a published one
  (`PrivateVersionOfPublished`, PUB-2.7). Link seating is outside the
  rule (PUB-2.12).
- **Provenance (R)** — the append-only record of which addresses a
  document has ever contained, including a fork's shared ones. It is
  recorded, not recomputable: an arrangement that no longer holds an
  address cannot tell you it once did, which is what makes deletions
  and "who has ever contained this" answerable at all.
- **`resolve` / `project`** — the I-runs a V-region maps onto, and the
  V-footprint an I-address cover leaves in a document; the reads every
  query layer builds on.

Rides the kernel for atomicity and recovery; consumes
[skep-address](../skep-address) span algebra throughout.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](../../LICENSE-APACHE))
- MIT license ([LICENSE-MIT](../../LICENSE-MIT))

at your option.
