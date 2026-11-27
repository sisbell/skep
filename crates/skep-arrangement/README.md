# skep-arrangement

Arrangements and editing: the mutable V→I arrangement that makes
skep documents editable over immutable content.

Part of [skep](https://github.com/sisbell/skep), an open-source hypertext substrate in the Project Xanadu lineage.

- **The V-stream** — per-document run lists mapping virtual positions
  (what a reader sees) onto immutable content addresses (what is
  stored); every edit is a new arrangement, never a byte change.
- **Editing composites** — insert, copy (transclusion — the transcluded
  spans keep their origin identity), delete, rearrange; each a
  kernel transaction composing namespace mints and content writes — a
  run of single-byte values as one range mint and one stretch, an atom
  as its own mint and write.
- **Versioning** — VERSION forks a document: the fork's arrangement
  starts as a snapshot of the content map the source's readers answer
  from (a bare published source's head), the source untouched, and the
  two diverge copy-on-write. An owned fork's
  ancestry is carried by the identity itself, readable by truncation;
  a cross-owner fork's identity is severed from the source's, and what
  records the relationship is provenance. Every document a snapshot
  mints — a version, a fork or a staged draft — keeps its source and
  the count of it the copy took (`M5State::fork_source`,
  `M5State::fork_source_copied`), the count staying where the copy
  ended however the source grows.
- **The staging act** — `stage` mints a PRIVATE draft of a source in
  the caller's own account, sharing the source's reading surface as
  `version` shares it, and records in the slice's own state where the
  draft began — its base (the member or memberless document copied
  from, or an alternative's inherited base), the extent the copy took,
  measured at the commit, and its source — in ONE commit, so the draft
  stands whole or not at all and no client-written record says where
  it began. The base moves at every publication of the draft itself:
  the shot's placing record names its rendering draft — unless the shot
  sets `keep_base`, as the merge's shot from the head does, leaving the
  draft behind the member it published — and the fold moves the
  draft's base to the member minted (`M5State::draft_base`, which the
  doc-metadata read serves as `base` and `base_copied`). Always
  private, never publish-class, admitted whatever the source's state:
  the sibling draft the version-chain refusals point to.
- **The edit** — `Vstream::edit` (`ops/edit.rs`) makes a list of
  positional changes to ONE draft in ONE commit, staged as ONE record
  (`M5Rec::ContentEdit`). Each change removes a width of positions at a
  place and puts content there: fresh values, minted in the changes'
  order by one range mint a call, through the staging `insert` uses
  (`ops::allocate_values_for_placement`), or runs placed by identity, as
  `reinstate` places them. Every place is a position of the SAME state
  of the draft, the one the call is typed against, so the changes ascend
  and lie apart and none moves another's positions; the gate, the
  published check, the typed state and the draft's content count are
  each read once a call, the changes judged in one walk, and the
  record's fold splices them all into the run-list in one walk
  (`RunList::spliced`, which joins every seam its changes make as the
  one-at-a-time mutators would). The record appends to the provenance
  relation R every run it places — the values an edit mints and the runs
  a landing places alike, nothing for what it removes — and moves the
  draft's arranged-at position to its commit whatever it holds, an empty
  list beside a base included. A call folds the draft's list twice, at
  the record's push and at the transaction's seal, however many changes
  it carries. The wire reaches the one operation under two names: `edit`,
  whose changes mint, and `set_arrangement`, whose changes place runs —
  the name a merge's landing, its take-backs and a restore are sent by.
  A refused change refuses the call, naming its index (`EditError`); a
  list of no change is admitted only beside a base or a merge.
- **The landing's terms** (`ops/set_arrangement.rs`) — an edit may carry
  the three members a merge's landing into a draft rides it with, judged
  and recorded in the same commit beside the edit's record, so the draft
  holds what it was sent and the record of it, or what it held. It is
  the board's half of a
  merge's landing into a draft: the request carries the HEAD the merge
  was composed on at the extent read, which must name a registered
  document and which the store checks against the draft's chain where
  it has one (a draft with no chain has its registration checked alone,
  the extent unchecked) and never against the trunk's current head — a
  version published since lands all the same and the answer names the
  newer head (`head_moved`) — and, where the request names a BASE to
  record, the draft's recorded base moves to it in the same commit,
  carrying the request's MERGE as the marker the draft now carries
  (`DraftBase::merge`: the sides, the head at the extent read, and the
  position the marker was put on the document, stamped by the fold), or
  clearing one. A merge naming a position (`SetMerge::at`) puts back a
  marker the fold stamped on the draft since its base last moved at a
  shot (`DraftBase::stamped`) as it stood, its position kept, so a merge
  taken out and put back stands as it did; any other position is refused
  (`marker_not_restorable`). The marker travels with the base: copied by
  a stage of a marked draft at the stage's own position, cleared by the
  shot that moves the base, untouched by a write that leaves the base
  untouched. A
  document with no recorded base gains none; a FORK whose source is not
  the request's head is refused by name (`fork_base_moved`), its
  recorded source never made false.
- **The substitution** — `stage_substitute` (`ops/substitute.rs`) is the
  identity-checked substitution, a staging body with no operation of its
  own: for each place of a list, the runs a draft must arrange there and
  the runs that take their place. The draft's gate answers first — its
  registration, its owner, `PublishedTarget`. Every place is then checked
  by identity on ONE walk of the draft's run-list
  (`RunList::arranges_each`: the positions hold exactly those runs'
  addresses, in order, whatever the run boundaries on either side), and a
  refusal is the earliest entry's in the order given: a place the draft
  does not hold its runs at, a place overlapping an earlier entry's, an
  entry that came with no pieces (`SubstituteError`). Where every entry
  holds, the places are staged as ONE `M5Rec::ContentEdit` — a change a
  place and a run a piece, never coalesced in the record, so the
  provenance relation gains a span a piece while the run-list holds
  adjacent pieces as one run. A publication stages it once for each draft
  it re-windows at its kept places, so a re-window costs the draft's runs
  and the pieces placed, and one record, however many places it has.
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
  lands in the head member alone. A shot may name its CHANGE in place of
  its whole arrangement: `Shot::stretches` lists the stretches of the
  base its runs replace (`ShotStretch`, held to the request by
  `Shot::stretch_fault`), and the member is the base with them replaced
  — one member under either form. The shot's placing record
  (`ShotPlace`) journals THE RUNS THE SHOT PLACED, never the member's
  arrangement, and the shot's terms — the count it placed, the base it
  was made against, the extent its copy took, its stretch list in
  positions and the depth of the member's chain of bases — for every
  member it mints; the fold builds the member from its base's list with
  every stretch spliced in one walk (`RunList::spliced`), so a shot's
  journal follows its change. A member the shot minted stores no span
  of provenance — its arrangement only grows, so the provenance reads
  take R↾member off the arrangement — and a snapshot (`stage`,
  `version`) appends none either, naming the list it shares. So
  a verifier of the member's entry signature reads the terms off the state
  beside the member's runs at the stretches' images
  (`ShotTerms::images`, `M5State::address_form_of`), the base as the
  shot recorded it and never
  read off the member's address, in the
  address form the signature covers (the document's own runs by value,
  windows by address). What the shot re-inserts is answered too —
  `Shot::reinserted_runs`, its count, and the same runs grouped by the
  named draft whose identity they are (`Shot::reinserted_runs_by_draft`,
  one pass for every draft) — and held to TWO BUDGETS BY ONE COUNT,
  `Shot::reinserted_units`: the distinct positions those runs name,
  arithmetic on the request, against `MAX_REINSERTED_VALUES`; then the
  units they come to — an atom, or a whole run of single bytes within a
  portion the shot mints at one time, two staged records each — counted
  off the drafts' stored pieces against `MAX_REINSERTED_UNITS`, each
  portion split exactly as the commit stages it. The count answers the
  parts it counted and `publish` stages from them, a portion's pieces
  walked once; the composer, the media door and the price ask the same
  count, so the store's refusal and every reader's figure are one
  comparison. `publish` states where
  that fresh identity lands: the last addresses of the document's own
  content chain, which a reader the ack does not tell (the media cell
  index) reads it back from. Everything `publish` checks before it probes an
  address — registration, ownership, the base's shape, the source gate —
  is one query too, `shot_admission`, which a door asks of the world the
  transaction will open on to learn the shot's verdict through its gate.
- **The ownership gate and the publication refusals** — the four edit ops
  and `publish` take a `Caller` and admit only a registered document's
  effective owner (ω, exact account match; `Caller::System` is the
  in-process automation path, exempt from ω alone). A PUBLISHED document
  refuses every in-place edit (`PublishedTarget`, PUB-2.11) except an
  `insert` DECLARED under a type
  the deposit class holds (`deposit_class_types` — ENROLL, RETIRE, the
  registration's six deposit-carrying rows, and the registry's BINDING and
  its ENDPOINT today, the atom-bearing kinds whose records the daemon
  parses, each at its own address) at `n_C + 1` of the arrangement
  `deposit_surface` names (the
  chain's head, or the document's own while it has no member) — the one
  way content enters an account's born-published home; `version` refuses a
  private owned source (`PrivateSourceVersionless`, PUB-2.9) and an
  explicit-private member of a published one
  (`PrivateVersionOfPublished`, PUB-2.7). Link seating is outside the
  rule (PUB-2.12).
- **The stale-edit refusal** — each of the five in-place edits, and the
  edit, names the
  document state it was typed against (`AsOf::Typed`, the position of the
  read its positions came from; `AsOf::Unchecked` for the two in-process
  writers nothing races — the substitution takes no typed state, its check
  by identity being the stricter one). The slice keeps, per document, the position its
  content arrangement last changed at (`M5State::arranged_at`, set by
  every placing, removing, reordering or minting record and never by a
  link seat), and an edit typed below it is refused `ArrangementMoved`
  carrying both positions — behind `PublishedTarget`, ahead of every shape
  check — so a stale edit never lands a position off and never answers
  `OutOfBounds` for positions that were true when it was typed.
- **Provenance (R)** — the append-only provenance relation: which
  addresses a document has ever contained, including a fork's shared
  ones. It is recorded, not recomputable: an arrangement that no longer holds an
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
