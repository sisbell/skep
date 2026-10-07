# skep-search

The search index a client embeds: one unit per document version's arranged
content, a tokenizer over UAX #29 word boundaries with the accent,
apostrophe and format-control folds, an inverted index with positions
behind one concrete type, and one versioned file per index with its
dispositions — the reader's own index of a board's text, built from the
reader's own reads of the feed, the substrate staying search-free.

Part of [skep](https://github.com/sisbell/skep), an open-source hypertext substrate in the Project Xanadu lineage.

## 1. What skep-search is

A LIBRARY the frontend's shell embeds beside `skep-client` (the design's
`search.md` §1.2; R9b, ux-FC2 (1), sx-D1). TEXT AND ADDRESSES IN, HITS OUT:
it parses no wire JSON, dials nothing, holds no token, knows no principal
but as the class the embedder passes it, and reads and writes no file but
through the `Read` and `Write` the embedder hands `load` and `save`. Its
parts, each under the design rule it realizes:

- **The document model**, `unit` (§2.1, §2.4) — `Unit`, one document
  version's arranged content, read over its whole content-subspace extent
  and delivered in parts where it holds more than `MAX_DELIVERY_ITEMS`
  positions; the typed delivery `Item`s the crate takes — `Text`, one
  `content` item's bytes or a `hex` run's, and `Gap`, every item that is
  not text (an atom, a withheld run with its origin, a kind the shell does
  not know), each at its start ordinal and width; the parts JOINED in order
  into one unit, adjacent text items becoming one, so a character split at
  a part's edge is rejoined and never a `hex` run; the item table, and the
  binary search over its start ordinals that finds an occurrence's item
  (`Unit::item_at`). `UnitKey`, the bare document address alone, so every
  re-read of a document enters under the same key and replaces; the pinned
  member, the position read at, the kind and the `Class` the unit was read
  at — `Guest`, or `Principal(n)` — riding beside it. A unit's live bytes
  (`Unit::bytes`) are its bytes of text, the ceiling's count. And §2.4's
  head rule, `moved_head`: the trunk head alone per published document — a
  daughter's `publish` row moves no head, an owner's `version` row moves it.
- **The tokenizer**, `token` (§2.3) — UAX #29 word boundaries over each text
  item (`unicode-segmentation`), the segments holding an alphanumeric kept;
  THE FOLD, `fold`: NFD (`unicode-normalization`), then the combining
  diacritical marks, the optional pointing of Arabic and Hebrew and the
  variation selectors dropped (sx-D16 as sr-E1 scopes it, amended by ITEM
  3), the apostrophe variants folded to U+0027, the invisible format
  controls dropped, then `str::to_lowercase` — so `Émile` and `emile` are
  one term, `person's` and `person’s` one term, `कु` and `क्` two. Each
  token keeps its range from the unit's start — the first byte's V-ordinal
  offset and its length, the unfolded segment's — every `Gap` counted at
  its width, a `hex` stretch's bytes at their own ordinals, and the ordinal
  advanced by one across each, so no phrase crosses one. The tokenizer
  `REVISION`: the rule's version and the Unicode version of the two tables,
  17.0, held equal by a test.
- **The index**, `index` (§1.2, §1.4, §5.1) — `Index`, one concrete type of
  ONE CLASS: the sorted term dictionary, the postings — per term, per unit,
  the token ordinals and each occurrence's range (`Occurrence`) — the unit
  records with their per-unit term lists, the tombstones, the live counts
  (units, terms, posting entries, bytes of text) and the dead ones beside
  them, the index's own class and tokenizer revision. The write side:
  `Index::new(class)`; `Index::prepare(unit)`, the unit tokenized and its
  postings built against no index, under no lock, `Prepared` carrying the
  unit's class and live bytes; `merge`, under the write side — THE CLASS
  CHECK, a unit not read at this index's class refused with both classes
  named, THE CEILING, a unit that would carry the index past `CEILING_BYTES`
  refused with the bytes held and the limit named and the unit it would have
  replaced KEPT, and otherwise a held key REPLACED and the replaced unit
  TOMBSTONED, every statistic moving at once; `index(unit)`, their
  composition; `compacted`, the postings rebuilt from this value without the
  tombstoned units, and `install`, ONE SWAP; `compaction_due`, the trigger
  in dead postings past an eighth of the live; `stats`, the live counts with
  the ceiling and `seen`, the units offered past it; `terms`, the live
  dictionary in order. `IndexError` names the two refusals and a failed
  save's writer.
- **The file**, `header`, `file` and `resume` (§5.1, §5.3, §5.4) — ONE
  VERSIONED FILE PER INDEX, loaded whole. `Header`, the typed header the
  embedder composes and `load` hands back: `board` (`Chain`, the 64
  lowercase hex of `H.1`), `floor`, the per-range `RangeRecord`s — `under`,
  `held` as a `ChainAt` pair, the recorded `Refusal`s, the bare-row count,
  a granted range's `Grant {kind, issuer}` — and the newest head's
  `HeadRecord`. The header LINE, one JSON object in the key file's
  conventions, written by `header::encode` and read by `header::parse`, the
  one canonical parser: `v` first — a `v` above 1 faced as a newer skep's
  before any other member is judged — then the line admitted only as its
  own re-encoding, any other spelling `Damaged`, an unknown member refused
  by name; no JSON crate. `Index::save`, the whole index to one writer: the
  line (`kind`, `principal` and `tokenizer` from the `Index` alone), seven
  length-prefixed body sections (the range records, the head's pair,
  `seen`, the sorted dictionary, the unit records with their stored text
  and term lists, the delta-coded postings, the live counts) and a CRC-32C
  trailer over the header line and the body, computed in-crate.
  `Index::load(from, expected)`, the whole file from one reader, in order:
  the line; the class against `expected` — `LoadError::OtherClass`, both
  named, before the body is read; the tokenizer — `NewerTokenizer`, faced,
  the body unread; the body under its trailer — `Damaged`, naming what; an
  older tokenizer revision MIGRATED from the stored text, the result at the
  running revision and tagged by `Index::migrated_from` so the embedder
  saves it. `aside_name`, the aside's spelling
  `<name>.aside.<chain>.<n>`, the shell's rename. `Resume::judge`, the
  resume read's verdict as a pure function over a `ChainAnswer` the shell
  fills: `Equal`, `FromTheFloor`, `Diverged`, `BeyondHead`,
  `DifferentChain`, `Busy`. The crate moves no file and reads no board.

The ceiling (`CEILING_BYTES`, §7.4) is an INTERIM PIN at the records tier's
own size — §7.3's cut re-measured to the byte, 93,075,924 bytes over 3,598
files at the design repository's `b17656e9` — the floor ITEM 2 RULED (d)
fixes, held until lane SR-4 reports M1 and M5 over that tier. Its rules —
one class per index, cut once at `merge`, prepare under no lock and install
by one swap, nothing of the network, the keys or the board, one file in one
spelling read whole, no file moved and no board read — are in its crate
root (`src/lib.rs`) and in the workspace's `ARCHITECTURE.md` §The search
index. It depends on `skep-address` and the two Unicode crates alone: NOT
`skepd`, NOT `skep-client`, NOT `serde_json`.

## 2. What later lanes add

The surface above is `search.md` §1.4 minus the calls below, which the
next lanes land against these names:

- **The query and the answer** (§3; lane SR-3) — `Query::parse`, the one
  grammar; the evaluator (term, prefix expansion over the sorted
  dictionary, phrase by adjacent ordinals, phrase-prefix, the conjunctive
  window, the fuzzy word); `rank`, BM25 over one index or the pair's merged
  statistics; `hit`, `Hit` and `Answer` with the snippet; `Pair`, the two
  indexes by role; `Index::query`; and THE ONE READ over the keys,
  `keys_by_range`, whose order `UnitKey` already sorts in.
- **The budgets, reported** (§7; lane SR-4) — the timing tests over §7.3's
  corpus, the save and load timed among them, and the ceiling's figure
  confirmed or raised.
- **The shell's half** (`client.md` §4e; lane SH) — the feed consumer; the
  directory, the file modes `0600`/`0700`, the lock, the save's rename and
  the moving aside under `aside_name`; the `/health` and `/chain?at` reads
  whose answers `Resume::judge` takes; the save after a migration; the
  triggers, the bridge call and the state event, in `skep-client`.

## 3. The crate's suite

Unit suites sit beside their code: `unit/tests.rs` (the join, the item
table's binary search, the contiguity refusal, the head rule),
`token/tests.rs` (the Unicode version pair, the fold's reach and residue,
the ranges across a gap and a hex stretch), `index/tests.rs` (the postings'
shape, the tombstone and the live counts, compaction and its trigger, the
ceiling's arithmetic at a small ceiling, `seen`), `header/tests.rs` (the
canonical bytes of both kinds, the one spelling both ways, `v` first, every
re-spelling damaged, the unknown member), `file/tests.rs` (the CRC-32C
check value, the codecs, the layout, the round trip and the fixed point,
the trailer over the header line, the newer tokenizer faced with the body
unread, the class before the body, the migration round trip, a damaged body
by section, `seen` and the tombstones across a save, the aside, the
faces), `resume/tests.rs` (one test per arm). The integration suite is one
binary, `tests/it/`: `cases` — §7.2's twenty-two tokenizer cases, each
asserting its tokens and its byte range — `index` — the write side under
the design's fence: the class check, one class per index, the ceiling at
the real constant, replacement, prepare under no lock and install by one
swap under an `RwLock` of the test's own, the join of a document of twice
`MAX_DELIVERY_ITEMS` positions with a character across the parts' edge,
and the range across a `Gap` and a `hex` stretch with the item found by
binary search — `file` — §8.3's file dispositions at the public surface,
one test each, and `load`'s order — and `resume` — the open's judgment over
a loaded header and the wire's answers.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](../../LICENSE-APACHE))
- MIT license ([LICENSE-MIT](../../LICENSE-MIT))

at your option.
