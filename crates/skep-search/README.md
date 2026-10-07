# skep-search

The search index a client embeds: one unit per document version's arranged
content, a tokenizer over UAX #29 word boundaries with the accent,
apostrophe and format-control folds, and an inverted index with positions
behind one concrete type — the reader's own index of a board's text, built
from the reader's own reads of the feed, the substrate staying search-free.

Part of [skep](https://github.com/sisbell/skep), an open-source hypertext substrate in the Project Xanadu lineage.

## 1. What skep-search is

A LIBRARY the frontend's shell embeds beside `skep-client` (the design's
`search.md` §1.2; R9b, ux-FC2 (1), sx-D1). TEXT AND ADDRESSES IN, HITS OUT:
it parses no wire JSON, dials nothing, holds no token, knows no principal
but as the class the embedder passes it, and reads and writes no file of
its own. Its parts, each under the design rule it realizes:

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
  dictionary in order. `IndexError` names the two refusals.

The ceiling (`CEILING_BYTES`, §7.4) is an INTERIM PIN at the records tier's
own size — §7.3's cut re-measured to the byte, 93,075,924 bytes over 3,598
files at the design repository's `b17656e9` — the floor ITEM 2 RULED (d)
fixes, held until lane SR-4 reports M1 and M5 over that tier. Its rules —
one class per index, cut once at `merge`, prepare under no lock and install
by one swap, nothing of the network, the keys or the board — are in its
crate root (`src/lib.rs`) and in the workspace's `ARCHITECTURE.md` §The
search index. It depends on `skep-address` and the two Unicode crates
alone: NOT `skepd`, NOT `skep-client`, NOT `serde_json`.

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
- **The file** (§5.1, §5.4; lane SR-2) — `Index::save` and `Index::load`,
  the typed `Header`, `LoadError` and every disposition, the aside, the
  resume's answers; `seen` and the tombstone set kept in the body.
- **The budgets, reported** (§7; lane SR-4) — the timing tests over §7.3's
  corpus, and the ceiling's figure confirmed or raised.
- **The shell's half** (`client.md` §4e; lane SH) — the feed consumer, the
  directory, the triggers, the bridge call and the state event, in
  `skep-client`.

## 3. The crate's suite

Unit suites sit beside their code: `unit/tests.rs` (the join, the item
table's binary search, the contiguity refusal, the head rule),
`token/tests.rs` (the Unicode version pair, the fold's reach and residue,
the ranges across a gap and a hex stretch), `index/tests.rs` (the postings'
shape, the tombstone and the live counts, compaction and its trigger, the
ceiling's arithmetic at a small ceiling, `seen`). The integration suite is
one binary, `tests/it/`: `cases` — §7.2's twenty-two tokenizer cases, each
asserting its tokens and its byte range — and `index` — the write side
under the design's fence: the class check, one class per index, the
ceiling at the real constant, replacement, prepare under no lock and
install by one swap under an `RwLock` of the test's own, the join of a
document of twice `MAX_DELIVERY_ITEMS` positions with a character across
the parts' edge, and the range across a `Gap` and a `hex` stretch with the
item found by binary search.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](../../LICENSE-APACHE))
- MIT license ([LICENSE-MIT](../../LICENSE-MIT))

at your option.
