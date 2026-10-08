# skep-search

The search index a client embeds: one unit per document version's arranged
content, a tokenizer over UAX #29 word boundaries with the accent,
apostrophe and format-control folds, an inverted index with positions
behind one concrete type, the one grammar and its evaluator over the pair
with every bound a flag, BM25 in its pinned form, the hit with its standing
and snippet, and one versioned file per index with its dispositions — the
reader's own index of a board's text, built from the reader's own reads of
the feed, the substrate staying search-free.

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
  save's writer. And THE ONE READ over the unit keys, `Index::keys_by_range`
  (§1.4; the enumerator RULED (b)): the keys held under a `Prefix` — the
  crate's own type over an account's or a document's address, built on the
  vocabulary's `is_prefix` — one contiguous scan of the key map in the
  address order, its callers the two refreshes and no other, reading
  nothing but the keys.
- **The query**, `query` (§3.2) — `Query::parse`, THE ONE GRAMMAR: a
  `Form::Word`; the string's last word a `Form::Prefix` unless whitespace
  ends the string; a quoted run a `Form::Phrase`, an unclosed quote a
  `Form::PhrasePrefix`; a split chunk the tokenizer cuts to several tokens
  (`PUB-5.115`, `search-free`, `東京都`) an implicit phrase, a phrase-prefix
  at the string's end; several forms a conjunction; no operators. The
  evaluator over the pair: the term lookup; the prefix expansion over the
  sorted dictionary by binary search, the terms taken by document frequency
  descending — the prefix's own term first and always — until the next
  would pass `EXPANSION_BOUND_ENTRIES`, then `more_terms`; the phrase by
  adjacent ordinals, never across a `Gap`; the phrase-prefix over the terms
  that follow the fixed words' occurrences, cut off the stored text, so
  `"the publish s` finds `shot`; the fuzzy word — a complete word of
  `FUZZY_MIN_CHARS` or more that is no term, expanded to the terms within
  one edit counted in characters, at most `FUZZY_WORDS` of them nearest the
  string's end, the rest as typed with `fuzzy_bounded`, the trailing prefix
  never fuzzy, `matched` filled; the conjunction walked rarest first under
  `POSITIONS_BOUND`, every posting consulted counted, a stop answering the
  units reached ranked with `positions_bounded`. The three bounds are
  INTERIM pins, constants whose docs quote §7.1 — the two position bounds
  derived from M2's one-frame pin, the fuzzy words bound its stated three —
  and EACH IS A FLAG on the answer, never a silent cut.
- **The ranking**, `rank` (§3.3) — BM25 with `K1 = 1.2` and `B = 0.75`, the
  idf pinned as written, `ln(1 + (N − df + 0.5)/(df + 0.5))`, positive at
  every df and floored nowhere; `term_score` as written; one score per
  query form — a word one term, a phrase one combined term with its words'
  idf summed, an expansion or a fuzzy word's candidates one combined term
  over the union of their postings — summed in query order; `Statistics`,
  the pair's MERGED statistics, N and the tokens over both members, each
  counted once; `order`, the score descending and ties by document
  address, member and span start.
- **The hit**, `hit` (§3.1, §6) — `Hit` with every member the design names:
  `doc`, `member`, `as_of`, `span` as `Span { start, width }` in V-ordinals
  byte-exact off the postings' ranges, `score`, `snippet`, `kind`,
  `standing` — `Standing::Public`, `YoursToRead`, or `Held { kind, rung,
  issuer }` with `Rung` the range's own shape — `occurrences` and `matched`;
  `Answer` with `hits`, `total` (exact, or a lower bound where a bound was
  met), `truncated`, `more_terms`, `fuzzy_bounded`, `positions_bounded`. The
  `Snippet`: the paragraph window around the span cut from the stored text,
  bounded to `SNIPPET_BOUND` bytes either side and moved inward to a
  character boundary, `start` the V-ordinal of its first position, `marks`
  the `(offset, len, kind)` ranges of the span, of every matched term's
  occurrence — the term named — and of each `Gap` cut out of the text; a
  wide conjunction centred on its rarest word.
- **The pair**, `pair` (§1.4, §5.2) — `Pair { published, supplement,
  ranges, honored }`, the two indexes BY ROLE and the standing's inputs:
  the supplement header's `RangeRecord`s and the `Prefix`es the shell's
  honored set admits — the shell's facts, carried where the shell names
  what it searches, since the index records nothing of ranges; `Held` is
  composed from them by prefix arithmetic, the narrowest departed range's
  cell and issuer, a draft under the subtree's or an honored prefix
  `YoursToRead`, no read made. `Pair::guest` and `Pair::session`;
  `QueryOpts { offset, limit }` with `DEFAULT_LIMIT` 50; and
  `Index::query(pair, &query, &opts) -> Answer`, the one call, evaluated
  from scratch at every keystroke.
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

The INTERIM PINS, each a constant whose doc quotes the design and carries
what the budgets measured of it (§3; lane SR-4, 2026-10-07): the ceiling
(`CEILING_BYTES`, §7.4) at the records tier's own size — §7.3's cut
re-measured to the byte, 93,075,924 bytes over 3,598 files at the design
repository's `b17656e9` — the floor ITEM 2 RULED (d) fixes, where M1's two
ratios hold (the postings 0.73× the text, the file 1.78×) and M5's does not
at any tier (the index loaded whole is 5–7.5× its file resident, the
in-memory shape's ratio and not the tier's), so the figure stands
UNCONFIRMED for the owner's decision with §7.1's remedies named in its doc;
the expansion's bound (`EXPANSION_BOUND_ENTRIES`, `1 << 16` postings
entries) and the positions bound (`POSITIONS_BOUND`, `1 << 16` positions),
each derived from §7.1's M2 pin — one frame, 16 ms, half of it the merge,
at a pessimistic 100 ns an occurrence, the power of two at or below the
80,000 that gives — CONFIRMED at M2: the evaluator merges a position in
47–54 ns and scores a unit in 0.7–0.8 µs, the keystrokes at the bound
reach p99 13.7 ms, so the figure that stands is the one that holds the
frame; the fuzzy words bound (`FUZZY_WORDS`, 3), the fuzzy word's minimum
length (`FUZZY_MIN_CHARS`, 5) and the prefix minimum (`PREFIX_MIN_CHARS`,
1), §7.1's own figures, each reported against the corpus; the snippet's
bound (`SNIPPET_BOUND`, 240 bytes either side), §6's. Its rules —
one class per index, cut once at `merge`, prepare under no lock and install
by one swap, every bound a flag, one score and one order, nothing of the
network, the keys or the board, one file in one spelling read whole, no
file moved and no board read — are in its crate root (`src/lib.rs`) and in
the workspace's `ARCHITECTURE.md` §The search index. It depends on
`skep-address` and the two Unicode crates alone: NOT `skepd`, NOT
`skep-client`, NOT `serde_json`.

## 2. What the next lane adds

The surface above is `search.md` §1.4 whole and §7's budgets are measured
(§3 below); what the one lane left lands against these names:

- **The shell's half** (`client.md` §4e; lane SH) — the feed consumer; the
  directory, the file modes `0600`/`0700`, the lock, the save's rename and
  the moving aside under `aside_name`; the `/health` and `/chain?at` reads
  whose answers `Resume::judge` takes; the save after a migration; the
  triggers, the bridge call that composes the `Pair` from the session's
  indexes, the supplement's header ranges and the honored set and forwards
  the answer's flags, the refreshes that walk `keys_by_range`, the jump's
  landing and the state event, in `skep-client`.

## 3. The crate's suite

Unit suites sit beside their code: `unit/tests.rs` (the join, the item
table's binary search, the contiguity refusal, the head rule),
`token/tests.rs` (the Unicode version pair, the fold's reach and residue,
the ranges across a gap and a hex stretch), `index/tests.rs` (the postings'
shape, the tombstone and the live counts, compaction and its trigger, the
ceiling's arithmetic at a small ceiling, `seen`, the keys under a prefix),
`query/tests.rs` (the grammar's forms, each form's evaluation, the fuzzy
word's edits counted in characters, the three bounds each met at a small
value with its flag, the list's window, determinism and the tie order),
`rank/tests.rs` (the idf's pinned form at every df, the term score by
hand, the merged statistics, the order), `hit/tests.rs` (the rung, the
tightest window, the paragraph window, the character boundary at the
bound, the gap cut out and marked, the wide conjunction, the marks'
order), `pair/tests.rs` (the default opts, the pair by role, the standing
of each case), `header/tests.rs` (the canonical bytes of both kinds, the
one spelling both ways, `v` first, every re-spelling damaged, the unknown
member), `file/tests.rs` (the CRC-32C check value, the codecs, the layout,
the round trip and the fixed point, the trailer over the header line, the
newer tokenizer faced with the body unread, the class before the body, the
migration round trip, a damaged body by section, `seen` and the tombstones
across a save, the aside, the faces), `resume/tests.rs` (one test per
arm). The integration suite is one binary, `tests/it/`: `cases` — §7.2's
twenty-two tokenizer cases, each asserting its tokens and its byte range —
`grammar` — §7.2's two grammar cases with their byte ranges, the
phrase-prefix finding `shot`, the implicit phrase and the conjunctive
window, the fuzzy cases, and each bound met at its REAL constant with its
flag set — `ranking` — §3.3's vectors: the short unit holding the word
over the long unit of completions, the first keystroke's union near zero
and never below, the tie set, the pair's merged statistics counting the
published member once, the same order twice — `hits` — `Held` across a
restart off the range's record with its cell's keys, the second honored
grant, the ancestor's draft, a draft never `Public`, the span's V-ordinals
with the member and `as_of`, and §6's three snippet cases — `separation`
— §2.1's class separation by construction, the investigation §4.10 item
15's vector set — `index` — the write side under the design's fence: the
class check, one class per index, the ceiling at the real constant,
replacement, prepare under no lock and install by one swap under an
`RwLock` of the test's own, the join of a document of twice
`MAX_DELIVERY_ITEMS` positions with a character across the parts' edge,
and the range across a `Gap` and a `hex` stretch with the item found by
binary search — `file` — §8.3's file dispositions at the public surface,
one test each, and `load`'s order — `resume` — the open's judgment over
a loaded header and the wire's answers — and `budgets` — §7's pins, each
MEASURED and REPORTED (§7: "TIMING TESTS THAT REPORT, never assert").

THE BUDGETS (`tests/it/budgets.rs`, with `budgets/corpus.rs`,
`budgets/board.rs` and `budgets/report.rs`): every test of the partition
`#[ignore = "timing test - gate-full only"]`, run by `scripts/gate-full.sh`'s
`full` profile and by hand with `--run-ignored all`. THE CORPUS is §7.3's,
read at run time from the design repository at its pin `b17656e9` through
`git` — the path from the environment variable `SKEP_SEARCH_CORPUS` — and
never committed: the records tier (every tracked file but the `_context.*`
bundles and the image and video files, 3,598 files, 93,075,924 bytes —
asserted, the ceiling's derivation) and the cuts at 10³ and 10⁴ documents
of 1–10 KiB from the tier's `.md` paragraphs under one deterministic rule
(the module doc states it). THE DEV BOARD is skepd in-process over a temp
directory under the system temp dir, claimed as the suites claim theirs;
each cut document is minted as a draft, its text inserted per-byte, and
read back through `retrieve_v` — in parts past `MAX_DELIVERY_ITEMS` — into
the crate's typed items, the round trip asserted byte-exact, so the index
is fed exactly as the shell feeds it; the units a feed delivered are cached
under the temp dir for the other rows, and the rows that need a live board
spawn a fresh one (a fed board is never reopened: the daemon's open of a
board holding thousands of commits replays its history for minutes). THE
ROWS, one test each, each printing
`BUDGET | row | tier | pin | measured | WITHIN or MISSED`: M1's build and
size, M2's keystroke with its named worst cases, the fuzzy query (its
`fuzzy_bounded` asserted), the keystroke under a writer, the two derived
bounds' per-occurrence cost, M3's distinct terms, M4's re-index, M5's
memory (a child process that loads the saved file and nothing else), M6's
`compare` against the daemon, the load, the save and its bytes per hour,
the save path's `/chain?at` beside history readers, the rank row's twenty
queries, the other interim pins, and the ceiling's verdict; M7's tree is
asserted in every gate. Without the corpus every budget test prints one
skip line naming the variable and the pin and passes. `SKEP_SEARCH_TIERS`
restricts a run's tiers (an entry `10^4=10^3` hands a 10⁴ row the 10³ units
for a dry run, the row naming the tier it measured); `SKEP_SEARCH_RECORDS_BOARD`
feeds the records tier through the board too (some forty minutes at the
board's measured rate in a release build — by default that tier enters the
index directly from the corpus and its rows say `records(direct)`). The
rows' numbers are a RELEASE build's: `cargo nextest run --release` — an
unoptimized daemon feeds per-byte text at a tenth of the rate and an
unoptimized index answers a keystroke in ten times the frame, the gate's
weather and not the product's.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](../../LICENSE-APACHE))
- MIT license ([LICENSE-MIT](../../LICENSE-MIT))

at your option.
