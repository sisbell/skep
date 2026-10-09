# skep-arrangement

Arrangements and editing: the mutable V→I arrangement that makes
skep documents editable over immutable content.

Part of [skep](https://github.com/sisbell/skep), an open-source hypertext substrate in the Project Xanadu lineage.

- **The V-stream** — per-document run lists mapping virtual positions
  (what a reader sees) onto immutable content addresses (what is
  stored); every edit is a new arrangement, never a byte change.
- **Editing composites** — insert, copy (transclusion — the transcluded
  spans keep their origin identity), delete, rearrange; each a
  kernel transaction composing namespace mints and content writes.
- **Versioning** — VERSION forks a document: the fork's arrangement
  starts as a snapshot of the content map the source's readers answer
  from (a bare published source's head), the source untouched, and the
  two diverge copy-on-write. An owned fork's
  ancestry is carried by the identity itself, readable by truncation;
  a cross-owner fork's identity is severed from the source's, and what
  records the relationship is provenance.
- **The publish shot** — `publish` appends the next member of a
  published document's version chain, born published, in ONE commit,
  from CLIENT-SUPPLIED I-address runs and never from any draft's
  arrangement at commit: the document's own runs stay by reference,
  the staging draft's — a document outside the chain — are re-inserted
  as fresh identity under the document's own I-space, and any other
  document's stay windows
  behind a per-origin source gate (`Withheld`); the base's post-render
  deposits are carried after them. The trunk advances while the base
  is still its head; otherwise the shot lands as the base's daughter,
  so two shots off one head both commit. A bare published address
  reads as its trunk head wherever a reader floats — the query layers'
  arrangement reads and `version`'s snapshot — while `copy`'s sources
  and the arrangement's own reads take the address named; a version
  address reads as itself forever, and a declared deposit into a chain
  lands in the head member alone. The shot's placing record
  (`ShotPlace`) journals the member's whole arrangement and the shot's
  two client terms — the count it placed and the base extent its copy
  took — for every member it mints, so a verifier of the member's entry
  signature reads them off the state beside the member's runs, in the
  address form the signature covers (the document's own runs by value,
  windows by address). What the shot re-inserts is answered too —
  `Shot::reinserted_runs` and its count — and `publish` states where
  that fresh identity lands: the last addresses of the document's own
  content chain, which a reader the ack does not tell (the media cell
  index) reads it back from. Everything `publish` checks before it probes an
  address — registration, ownership, the base's shape, the source gate —
  is one query too, `shot_admission`, which a door asks of the world the
  transaction will open on to learn the shot's verdict through its gate.
- **Write-surface gates** — the four edit ops and `publish` take a
  `Caller` and admit only the document's effective owner (ω, exact
  account match; `Caller::System` is the in-process automation path,
  exempt from ω alone). A PUBLISHED document refuses every in-place edit
  (`PublishedTarget`, PUB-2.11) except an `insert` DECLARED under a type
  the deposit class holds (`deposit_class_types` — ENROLL, RETIRE, the
  registry's BINDING and its ENDPOINT today, the four atom-bearing kinds
  whose records the daemon parses) at `n_C + 1` of the arrangement
  `deposit_surface` names (the
  chain's head, or the document's own while it has no member) — the one
  way content enters an account's born-published home; `version` refuses a
  private owned source (`PrivateSourceVersionless`, PUB-2.9) and an
  explicit-private member of a published one
  (`PrivateVersionOfPublished`, PUB-2.7). Link seating is outside the
  rule (PUB-2.12).
- **Provenance (R)** — the append-only record of which addresses a
  document has ever contained, including a fork's shared ones. It is
  recorded, not recomputable: an arrangement that no longer holds an
  address cannot tell you it once did, which is what makes deletions
  and "who has ever contained this" answerable at all.
- **Birth extents** — per trunk, the content count its birth version
  (`birth_version`, the member that opens the chain) was minted with
  (PUB-3.19), unmoved by the deposits that grow the head; noted by the
  fold off the record that mints it — the shot's placing record, or an
  owned `version`'s snapshot (a mint that leaves it empty notes zero,
  which `birth_extent` answers as a zero and not as no birth) — and
  carried by checkpoints, since the arrangement cannot say afterwards
  where the birth ended.
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
