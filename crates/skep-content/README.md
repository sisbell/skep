# skep-content

The permascroll: skep's append-only, write-once content store.

Part of [skep](https://github.com/sisbell/skep), an open-source hypertext substrate in the Project Xanadu lineage.

- **Address → value or stretch** — immutable content keyed by element
  address in a persistent map ordered by address (structural sharing
  makes snapshots nearly free; the order lets a checkpoint walk the
  whole store without sorting it, and lets a read find the entry just
  below an address). An entry is one value, or one stretch: a run of
  consecutive single-byte values written by one insert, held under its
  first address, each address inside it still answering by itself.
- **Write-once** — a value or a stretch is stored at minted addresses
  exactly once and never mutated; edits happen in the arrangement layer
  ([skep-arrangement](../skep-arrangement)), never by overwriting
  content.
- **`stage_write` / `stage_stretch` / `value_at` / `contains` /
  `pieces`** — the storage half of insertion composites (one value, or
  one run of bytes), the value read retrieval answers from as a borrowed
  `Piece`, the check other stores consult (is content stored here? —
  coverage, an address inside a stretch counting), and the one run read,
  the pieces of an I-extent. The point queries and the one run read,
  `pieces`; no prefix read; and one enumeration, `iter`, in no promised
  order, for whole-store work over a pinned snapshot such as the cell
  index's walk. Under the `test-hooks` feature, `write` and
  `write_stretch`, the standalone test-only twins of the two stage
  doors.
- **Line breaks, counted once** — a line break is a position whose value
  is the single byte `0x0A`: a byte of a stretch or a one-byte value,
  and nothing else (not `\r`, not U+2028, no byte of a longer value).
  Content never changes, so each entry's line breaks are counted as it
  is written and kept beside the content, in memory: derived from the
  bytes, never journaled or checkpointed, and counted again when a
  checkpoint is decoded. `line_breaks_before` answers the line breaks
  below an address on its chain — a run's are the count before its end
  less the count before its start, two lookups however many entries it
  spans — and `nth_line_break_from` the address of the n-th line break
  at or above an address, a search and never a walk.

Content here is raw bytes at addresses; what a document *says* is an
arrangement over these bytes, owned one layer up.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](../../LICENSE-APACHE))
- MIT license ([LICENSE-MIT](../../LICENSE-MIT))

at your option.
