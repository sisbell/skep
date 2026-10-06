# Architecture

This document describes how skep is laid out: what each part owns, which
way the dependencies point, and the rules that hold across files. Read it
before changing code you did not write. It says what is true of the code;
the reasons behind the design live in the documents linked at the end.

## Bird's-eye view

skep is a document store in which nothing is ever overwritten. Content is
written once and addressed forever; documents are arrangements of that
content; links connect spans of it. Every change is a transaction appended
to a journal, and the whole state can be rebuilt from the journal.

A client talks to one process, the daemon `skepd`, over HTTP and JSON on
the loopback. A write arrives as an operation; the daemon checks who is
asking and whether they may do it, applies it to the world through one
serialized write path, records it, and announces it. A read is answered
against the current world, or against the world as it stood at an earlier
position in the journal.

## Code map

The workspace is twenty-one crates under `crates/`. Dependencies point
downward in the list below: a crate may depend only on crates listed
above it.

**The foundation**
- `skep-address` — tumblers, addresses and span algebra. Pure values; it
  depends on no other skep crate.
- `skep-registry` — the registry's stable core as values: the twelve
  commons rows the registry allocates (five kinds, seven subtype rows) at
  the addresses commons-map pins, the binding and endpoint bodies under
  one canonical rule, the seeding check's three arms, and the vector set
  every parser of the bodies is held to. Of the skep crates it depends
  only on `skep-address`; it knows no engine, no daemon and no signature
  library. Its rules: §The registry rows and bodies.
- `skep-kernel` — transactions, the journal, checkpoints and recovery. It
  knows nothing of what a transaction means; the world it stores is a
  type parameter the engine supplies. Its modules and rules: §The kernel.
- `skep-blobs` — the blob store (media lane B): the four media stores
  under one root — the files at `blobs/<designation>/<hex>`, the partials,
  the upload records and the lease log — the PUT's fsync order, REPLACE on
  a present hash, the lease's honest-null answer, the pruner's rename
  aside, the logs' runtime compaction on a trigger, the volume's capacity
  read, and the operator's two doors — the read-only inspection and the
  pull's install by the PUT's order. It depends on no other skep crate,
  knows a principal only as an opaque string, holds no lock the daemon's
  write path takes, and reads no limits record. One feature, default off:
  `test-hooks` compiles in the test seam, `store/hooks.rs` — a hold or an
  injected failure at a step of the finish, and the methods only tests
  call. `scripts/gate-full.sh` builds the library and its docs without it.
  Its modules and rules: §The blob store.

**The stores** — each owns one slice of the world and depends only on the
foundation and on the stores above it.
- `skep-namespace` — the name space: it mints every address and builds the
  lock keys the stores take; the entity and principal registries and
  ownership (ω); each document's publication bit. Its modules and rules:
  §The name space.
- `skep-content` — the write-once map from address to value, ordered by
  address so a checkpoint walks it without sorting: point reads, and one
  enumeration of every entry for the daemon's cell-index rebuild at open.
  One feature, default off: `test-hooks`
  compiles in `write`, the test-only twin of `stage_write`, and the
  `skep-kernel` and `skep-namespace` edges only `write` takes. Every debug
  build asserts that each address written is a content element address.
  `scripts/gate-full.sh` checks the library without the feature and runs
  its suite in release.
- `skep-arrangement` — documents as arrangements of content, versions,
  provenance. Its modules and rules: §The arrangement.
- `skep-links` — the link store: `LinkState`, the append-only map from a
  link's address to its value and the hints folded from it; `LinkWriter`,
  whose every deposit passes one gate; the raw and typed reads and the
  matcher `skep-discovery` composes; the type registry, a compiled
  constant. Its modules and rules: §The link store.
- `skep-retrieval` — the content and provenance queries: delivery by
  V-span (RETRIEVEV), a document's extents, the origins of a span
  (SHOWORIGIN), what one document deleted that another still holds
  (SHOWDELETIONS), the shared content of two regions (COMPARE), and the
  documents holding some content now (FINDDOCSCONTAINING). It owns no
  slice and no index and writes nothing; delivery and containment each
  have a door that takes the caller's reader predicate. Its modules and
  rules: §The content queries.
- `skep-discovery` — the link reads: which links reach a document's content
  (the region family) or match a four-set description (the descriptor
  family), counted and paged; projection and discoverability; the
  delete-orphan preview; supersession lineage. It owns no slice and no
  index, and every link read takes the caller's reader predicate. Its
  modules and rules: §The link reads.
- `skep-coordination` — predicate definitions and the coordinator.
- `skep-identity` — credential records, key sets, the identity fold. Pure;
  of the skep crates it depends only on `skep-address`. The engine depends
  on it: `World` seats the fold as its identity slice, stepped at each
  credential deposit's commit and checkpointed with the world (AUTH-2.79).
- `skep-signature` — the hybrid signature's frozen rules: the KDF, keygen
  and signing (behind its `sign` feature), the key and blob layouts, the
  verify. The one crate that links the signature libraries; skepd calls its
  verify. Of the skep crates it depends only on `skep-identity`.

**The surface and the assembler**
- `skep-febe` — the operation surface (`OperationSurface`): one front door
  that dispatches every operation to the stores, and the codec seam a
  transport fills. Its modules and rules: §The operation surface.
- `skep-engine` — the one assembler. It defines `World` from the stores'
  slices and the identity slice, genesis, recovery and reads at a past
  position. Nothing depends
  on it except `skepd`, the conformance harness and — as a dev-dependency,
  for the fixture its hazard, golden and chain suites share —
  `skep-kernel`.

**The programs**
- `skepd` — the daemon (below), and the operator's two tools over a board
  directory — the inventory and the pull — two subcommands of the one
  binary, run with no server.
- `skep-mcp` — a stdio adapter for agent harnesses.
- `skep-resolve` — the verifying registry resolver, a LIBRARY a client
  embeds (the frontend, the `skep` command, a node's federation
  transport): the mirror of the registry board from a shipped root hint
  over its `/changes` feed, the verify of every binding and endpoint under
  its home's key set as of the record's position, the position-annotated
  prefix → binding index, the walk from a prefix to its endpoint and key
  set, and every outcome as a named state. Of the skep crates it depends
  on `skep-address`, `skep-registry`, `skep-identity` and `skep-signature`
  alone — no engine, no store, and never `skepd`, which never depends on
  it (the daemon's own suite takes it as a dev-dependency, where boards
  are spawned). Its modules and rules: §The resolver.
- `skep-client` — the library every ACTING client embeds (the design's
  `client.md`): the one outbound dialer, bare and signed sessions behind
  AUTH-5.65's pre-check, the key store, the signing seam over the hybrid
  key, the reader's verifier over the signature-filtered set, the claim
  ceremony, the compositions every later ceremony runs over, and the
  ceremonies over them — the retirement preview with its reach, the anchor
  import, the device and loss arms of recovery, retirement, rotation with
  its supersession trail, and the handoff door's two walks. Of the
  skep crates it depends on `skep-address`, `skep-identity`,
  `skep-signature` and `skep-resolve` alone — never `skepd`, which does
  not depend on it either (its suite spawns the daemon as a
  dev-dependency). Two features: `acting` (default on) gates everything
  that signs or holds a key; `tls` (default off) the `https://` arm.
- `skep-cli` — the `skep` command over `skep-client`, thirteen commands:
  `keygen`, `claim`, `session`, `fingerprint`, `verify`, `health`, `bind`,
  `enroll`, `recover`, `retire`, `rotate`, `handoff`, `accept`; flag
  parsing by hand, a `Person` over the terminal, stdout data and stderr
  talk.
- `skep-conformance` — a differential harness against `udanax-green`'s
  goldens.

## The kernel, `skep-kernel`

The kernel owns one directory: the journal's segments (`seg-<n>.wal`), the
checkpoints (`checkpoint.<n>`, each written through `checkpoint.tmp` — a
temp file the kernel alone deletes: a failed write removes its own before
answering, and `Kernel::open` removes one a crash left, reporting its size)
and the exclusion lock (`kernel.lock`). One applier lock serializes every
write; a write is appended, fsynced, and only then installed as the root
that lock-free readers load. The checkpoint cadence is tested on commit
under that lock and never by a timer; under its deferred arm a crossing
sets a due flag the caller's own thread services — `Kernel::checkpoint`
clears it first, then runs — and a second crossing with the flag still set
runs the checkpoint inline as the backstop. The world is a type parameter:
the kernel folds records through `WorldState::apply` and never reads them.
Its modules are declared in `src/lib.rs` in dependency order, each with a
line saying what it holds.

Rules that hold across its files:

- **Durable before visible.** `Kernel::transact_attested` hands the
  journal an install closure, and only the journal runs it:
  `JournalWriter::commit_txn` appends, fsyncs, then installs, inside one
  call; the in-memory journal, which has no barrier, installs at the same
  point.
- **A halt cuts nothing.** Every refusal in `Kernel::open` precedes
  `journal::truncate_tail`, recovery's one destructive step.
- **One door to the write state.** `ApplierLock::acquire`, which refuses
  a nested acquisition, is the only way to the sequencer, the journal and
  the cadence; the lock's fields are private to `kernel/applier.rs`.
  `Kernel::checkpoint` never takes it: its own mutex may be taken under
  the applier lock, never the reverse.
- **A scan and its fold share a base.** Scans are reached through
  `replay::Base::scan`, never by a caller supplying `S_load`.
- **One skip rule.** `segment::scanned_above` decides which segments a
  scan reads; the scan walks it and the format probe opens its first.
- **One codec.** Every byte the kernel writes goes through
  `journal::codec`, checkpoint bodies included; `checkpoint.rs` borrows it
  and the directory fsync from `journal`.
- **Mode parity.** `Journal::commit_txn` judges the frame cap and the
  transaction budget above its durability-mode branch, so an in-memory
  kernel refuses what a journaled one refuses.
- **The formats are pinned.** `tests/golden/` holds the bytes the
  fixture's ops must reproduce; a moved byte is a format event and bumps
  the `SKJ` and `SKC` stamps — with one dev-time exception on record: on
  2026-09-29 the chain's preimage gained the signature slot's digest and
  M5's slice its shot terms, and the goldens were regenerated once under
  the unchanged `SKJ4`/`SKC4` by the owner's no-stamp ruling (no served
  board exists; dev boards regenerate).

Its integration suites are one binary, `tests/it/`: `kernel` (the public
surface's claims), `hazard` (dirty crashes, built through the engine),
`golden` (the byte pins) and `chain` (the commit chain's tamper matrix),
over the shared `fixture` and `mutilate`.

## The blob store, `skep-blobs`

`skep-blobs` owns one directory — the daemon hands it `blobs/` inside the
board's data directory — holding the four media stores the media record
names: the files, `<root>/<designation>/<hex>`; the partials,
`<root>/<designation>/.upload-<identifier>`; the upload records,
`<root>/uploads.log`; and the lease log, `<root>/leases.log`. Its modules
are declared in `src/lib.rs` in dependency order, each with a line saying
what it holds, and the crate doc there states the store's guarantees, each
linked to the item that keeps it. `Store` (`store.rs`) is the four opened
as one, and `Stream` beside it an upload open for one request; `Inspection`
the four read as they stand (`Store::inspect`), the operator's inventory's
open, which writes nothing; `Store::install_file` the operator's pull's
install, one file by the PUT's order and nothing else; beneath them,
`store/hooks.rs` is the test seam.

Rules that hold across its files:

- **The PUT's order.** `Stream::finish` is the one path from a partial to
  a file: durable before named, leased before answered, a present name
  REPLACED and the replaced instance's aside unlinked only after the answer
  (`Store::unlink_asides`). A crash leaves at worst a file with no lease,
  a record open retires, or an aside open removes.
- **Three exclusions are the caller's.** One `Store` per root
  (`Store::open`); one stream of an upload at a time, its acts serialized
  (`Store`); and no `unlink_blob` or `remove_aside` while a finish runs
  (`Stream::finish`). The store checks none.
- **The pruner's acts are one method each**, so the daemon's pass holds
  its lock around exactly one, and the lease read inside it is one hash's
  range of the lease map (`LeaseLog`, keyed by the hash first): a pass is
  linear in its files, whatever the count of leases. A file is taken in
  two acts — `Store::rename_aside` under the caller's arm, the aside
  removed after it under none (`Store::remove_aside`) — so the arm is
  never held across the freeing of a file's blocks; `Store::unlink_blob`
  is the one-act form, which the daemon's pass no longer takes.
- **The logs' compaction has a trigger.** `Store::compact_logs_if_past`
  rewrites either log to its current records where its lines have passed
  a multiple of those records and a minimum — both the caller's figures,
  the daemon's pins — under the store's lock on that log's appends alone;
  an append during the rewrite waits and lands in the new file, and a
  stopped log is rewritten whatever its count (`Store::stopped_logs` says
  which has stopped).
- **The capacity is one read with the free space** (`Store::capacity`,
  `Store::free_space`): the same `statvfs`, the total blocks and the
  available ones; what the daemon's default per-account limit and its
  floor are read from.
- **Every name passes one check**, `blobs.rs`'s spellings: a caller's at
  `Store`'s entry points, a log line's at open. No name reaches a path out
  of the root; and a creation names no designation at all, but a
  `HashFunction` the store computes (`Store::create_upload`).
- **A byte is received once it is durable, and a stream is one
  request's** (`Store::resume`, `Stream`): the partial's file closes with
  it.
- **One answer per principal.** `UploadRecords` answers by the asking
  principal; its one lookup by identifier alone serves the pruner's expiry.
- **A record changes only by its holder's acts.** `UploadRecords` makes
  every change an upload record takes — its creation, a byte received, its
  offset set back at open, its retirement — and its write is private to
  `uploads.rs`: `Store` and `partials::reconcile` choose when, never what.
- **Pending bytes are the unplaced deposits and the bytes received**
  (`Store::pending_bytes`); which deposits are unplaced is the caller's
  answer, since the store reads no cell.
- **A torn line is only ever a log's tail** (`jsonl::Log`): a failed
  append is cut back, and a log that cannot cut back, or whose compaction
  failed past its rename, takes no append until a compaction completes.
  The store compacts at its open and at the caller's runtime compaction,
  so a log stopped while the store serves stays stopped until the next
  pass's compaction or the next open reads it afresh (`Store`).
- **Open reconciles and compacts before it answers anything; the
  inspection does neither.** `Store::open` runs each store's act at open —
  the logs' compactions, `partials::reconcile`, `blobs::sweep_asides` —
  and an I/O failure there, as at the size check (`Store::blob_size`), is
  never read as an absence. Its orphan removal keeps to the designations
  this build computes (`HashFunction`); another build's designation
  directory is left, as the pruner leaves it. Before any act, a symbolic
  link, a special file, or a second link to a file the store writes in
  place, at a name it acts on, fails the open
  (`blobs::refuse_links_and_special_files`): nothing is followed or
  written through. `Store::inspect` reads the same four stores as they
  stand — each log's lines read through `Log::read_as_found`, its torn
  tail cut in memory alone — and creates, cuts, renames and syncs nothing,
  so it can run over a backup or beside a serving daemon's store.
- **The pull's install is the PUT's order with no record** —
  `Store::install_file`: the bytes streamed into a temp file named as a
  partial is (so an open that meets it removes it as an orphan), hashed as
  they are copied, fsynced, renamed onto the hash name, the directory and
  the root fsynced; held to an expected hash where one is given, nothing
  installed otherwise; no lease, no record, no lock.
- **A caller's bug is no refusal, nor is the store's own.** `Stream::finish`
  panics on a broken precondition, and `UploadRecords::mark_received` on an
  offset past its record's length; `BlobError` carries only answers.
- **The test seam is a feature.** `test-hooks` (default off) compiles in
  `store/hooks.rs` alone; `scripts/gate-full.sh` builds the library and its
  docs without it.

Its integration suite is one binary, `tests/it/`: `finish` (the PUT's order
under an injected failure at each step, and the finishes run one at a
time), `replace` (REPLACE and its asides), `blobs` (the name check, the
listings, the size check, the floor's and the capacity's reads, the rename
aside, the pull's install), `uploads` (an upload's life while the store
serves, its identifier, and the records' log's runtime compaction),
`reopen` (what open makes of the records and partials a crash or a
restore left, the inspection that touches none of it, and the copy order
a live copy follows) and `lease` (the leases' states, their compaction at
open and by the trigger, and the pending bytes); each module's doc lists
its claims. Five unit suites sit beside their code: `store.rs`'s,
`uploads.rs`'s, `partials/handle.rs`'s, `blobs.rs`'s and `jsonl.rs`'s, the
last in `jsonl/tests.rs`.

## The registry rows and bodies, `skep-registry`

`skep-registry` holds what the registry's two halves — the daemon that
verifies and commits a registry deposit, and a resolver that reads it back
— both read and neither owns. Its modules: `rows.rs` is the one table of
the twelve commons rows the registry allocates — five kinds on the
reserve's ordinals `3.55`–`3.59` of the ghost home document's type
subspace and seven subtype rows nested under their kinds by prefix — each
row with what it is the row of (a kind, or a subtype, whose kind it names)
and the `type` string its body carries, read through one held pin per
row, and answering whether a deposit rides its address by REG-1.18's
test, computed and never stored;
`body.rs` the binding's and the endpoint's bodies — address members typed
as addresses, origins a non-empty list, each kind's `type` string read off
its row — their one parser under the canonical rule, their encoder and the
cap; `check.rs` the seeding check's three arms and the refusal that names
the arm.

Rules that hold across its files:

- **One table, one address apiece.** A row's address is spelled once, in
  `rows.rs`'s table, from the commons type prefix and the row's ordinals;
  the engine's ledger reads the rows through this crate's pins, and the
  daemon's write-path classes read them through the ledger. Shipped code
  spells a row a second time in two places, each held equal to the
  table's: the ledger's own `successor-of`, by the ledger's tests, and the
  insert door's deposit class in `skep-arrangement`, which spells the
  binding `3.55` and the endpoint `3.56`, by the daemon's suite
  (`skepd/tests/it/deposit_class.rs`).
- **The canonical rule is the parser.** `body::parse` answers a record
  only where the bytes are the encoder's re-encoding of what they spell,
  `sig` included; it checks the FORM of every member and never a member's
  admissibility, and a body whose `type` is not the kind the caller names
  is no record of that kind. The vector set under `tests/vectors/` is
  what every parser of the bodies is held to — this crate's, and any
  other a reader of the bodies builds (`skep-resolve` builds none: it
  calls `body::parse`); a parser is never derived from another parser.
- **The check runs on lists.** `seeding_check` takes the registry's rows
  and the foreign rows as lists, so every arm is proved on a list a suite
  builds; the shipped table passes, and the daemon runs the check over
  the whole domain it can see ahead of every genesis.

Its integration suite is one binary, `tests/it/`: `rows` (the table from
outside the crate, and `commons_type`'s panics), `check` (the three arms on
mutated lists, each of the twelve rows' absence among them) and `body` (the
vector set at this parser, the examples' one canonical form, the escape
table at every Unicode scalar value, the admission sentence and the
parse's totality as laws over every one-byte mutant of every admitted
vector, and every law of the parse at once on seeded hostile bodies
several edits from the vectors, met at every refusal the parse answers).

## The resolver, `skep-resolve`

`skep-resolve` is the client's half of the registry: what reads the
board the daemon serves and knows the bindings it read were genuine. It
links no daemon and no engine, speaks the wire as a guest, and opens no
socket to an endpoint — the dial is the caller's. Its modules: `hint.rs`
the root hint (the root's origins and the realm id, `RealmId` — the
genesis fingerprint and, on a forked lineage, the fork point beside it)
parsed from one line or built from its parts, never with no origin;
`http.rs` the written-out
HTTP/1.1 client behind a `Transport` trait; `board.rs` the typed reads
over any transport (`Board`), every read counted by kind;
`mirror.rs` the `/changes` consumer's types and state, the journal copy
and the fetch cache under the caller's directory, and the fold, with three
children — `mirror/base.rs` the base's check, its refusals and the sync,
`mirror/keys.rs` the key set as of a position, `mirror/atoms.rs` a
record's bytes and the chain walk; `verify.rs` the record grade for
registry records, client-side; `index.rs` the ledger of the rules (the
binding walk and the endpoint's currency) and the verified prefix →
binding index behind the mirror's gate; `walk.rs` the resolve, and its
child `walk/guest.rs` the guest-reading resolve that scans with no mirror;
`origin.rs` the scheme and host terms and the ordered walk's one
precedence; `state.rs` the verdict and the faces. The modules are
private: `lib.rs` re-exports the crate's whole surface, one path per name.

Rules that hold across its files:

- **The verdict decides, the registry's reads do not.** `verify::judge`
  is the one place a `sig` is judged, under the set that opens the home's
  account as of the record's position; a record whose verdict is not
  SIGNED enters no index and is counted under that verdict as judged
  (`Cause`, `Index::suppressed`), and the index's write side is the
  crate's own, so a dependent folds nothing into one; the guest-reading
  resolve folds into a `Ledger`, the rules alone, never into an `Index`.
  The body is parsed by `skep_registry::parse`
  alone — this crate derives no parser — and what it admits is not judged
  again: a record's address members are the addresses they name, read at
  any size the canonical rule admits. The library links the verify and
  never the signer — `skep-signature` with no `sign`, which
  `scripts/gate-full.sh` checks by building the library alone.
- **The table as of the position** (`mirror/keys.rs`). A record's key set
  is the one its home's account held at the record's own position — read
  off the live `key_set` only where the credential acts the mirror holds —
  those the credential pass has read, through the last row it read — prove
  none of the account's lies between the position and the live answer's
  `as_of`, off `/op-at` otherwise, and at the reclaim floor only where the
  same proof reaches it; where the table is gone with the journal the
  record is UNDETERMINABLE HERE, never unsigned, a table the walk cannot
  read is `None`, never an empty set, and a table holding a key this build
  cannot read is no table, never a smaller one. The proof reads acts past
  the record's position, so the pull holds every row of a sync before the
  fold takes any, and `fold_pending` records every credential act among
  them — an enroll or retire link naming the account, in any home — before
  it judges any record. A sync that fails leaves its rows held, and the
  next takes them up where it stopped, never asking the board for them
  again.
- **The base is checked, never trusted** (`mirror/base.rs`). A copy under
  the mirror's directory serves only after the source, read from genesis,
  answers every held row identically and every held head pair the same,
  and the realm id's genesis fingerprint is compared at the claim's row on
  every open that holds a board — for the board's own claimant, at the
  board's own genesis act, against the genesis set the source answers
  there: until it is compared the fold reads every link row off the board,
  never the fetch cache, and it honors one claim, a claim row past it
  moving nothing — the copy's header is the copy's word, and the fork point
  is compared by no check; no line reaches the copy before that
  comparison, so a refused base writes no line; a hint of another genesis
  retires the copy and bootstraps afresh; the refusals are named, in the
  order `Mirror::open` states. Only `feed.jsonl` is the checked image,
  every line of it written and read back in `mirror/base.rs` under its
  format stamp, and an offline rebuild, which no source checks, holds its
  rows to the feed's own order; `fetched.jsonl` is this mirror's own
  cache, its format written and read by `Fetched` alone, a value written
  once, a line that does not read — a write a crash cut short — held as
  absent and never run into. A new base begins both files afresh, so a
  cache that outlived its feed copy is never read as this mirror's own.
- **A retraction is the board's own reading** (`board.rs`). A deposit
  leaves the active view where the board's active links of its home, its
  type and its atom no longer answer it (`Board::stands_active`) — the
  org's own `nullify` — and never where a link of the retraction's type is
  found: discovery matches a slot by overlap, and any account's link of
  another class, in its own home, overlaps every address. The mirror asks
  each standing deposit once a pass.
- **The board's shapes are held, not trusted** (`http.rs`, `board.rs`).
  No answer is read past the feed's page budget and its envelope; an `/op`
  answer past it is one no typed read takes; a page that re-serves a row or
  does not advance is refused, a limit the feed names and refuses again is
  refused, a class scan's window that does not move its cursor is refused,
  and a reclaimed read whose floor does not lie past the position asked is
  refused — so no board sizes the client's memory past a page or pages it
  forever, and no floor clause counts acts over an empty interval. A link's slots are read only for a link of a type its reader
  names, its type slot that type's unit span exactly, the daemon's own
  reading of a registry or credential type.
- **The walk reads the index and the board, nothing else.** Every hop is
  the registry board's own journal or the mirror's copy of it; a depth
  address answers its parent prefix's standing — held or retired — and the
  hop not made; no name is tested — the host term is met at the addresses
  this resolver's own resolution yields, through a `NameResolver` a suite
  can hold fixed, an address a translator dials on tested as the IPv4 it
  reaches.

Its integration suite is one binary, `tests/it/`, over a RECORDED feed
(`tests/fixtures/feed.json`, written by the daemon suite's `resolve.rs` on
demand): `index` (the index from the fixture, a missing input's verdict,
the rebuild from the copy and the offline mirror's scope, the realm check,
the head pairs, the re-bootstrap, the root's failover, the copy's two
files, the replay matrix), `walk` (the faces) and `origin` (the terms and
the precedence). The paths no recording reaches — the reclaim floor, the
page budget, the position read, an unclaimed feed, the binding home, a
cache naming another claimant or hiding the genesis act, a second claim,
an address past a machine word, the guest-reading resolve's verdicts, a
forged retraction, a page or a window that does not advance, an answer
past the cap — run in the unit suites over boards they hold fixed. The end-to-end cells and the measurements run in
`crates/skepd/tests/it/resolve.rs`.

## The name space, `skep-namespace`

`skep-namespace` is the one minting authority. Every address a transaction
creates — account, document, version, content, link — comes off one of its
five mints, and every store that mints or writes under a chain
(`skep-arrangement`, which places content and forks versions, and
`skep-links`) holds a lock key M3 built. It also holds who exists, who
owns what (ω, the longest seated prefix) and each document's publication
bit, all in one slice, `M3State`. Node addresses come from provisioning
and are only admitted. Its modules are declared in `src/lib.rs` in
dependency order, each with a line saying what it holds. `state.rs` is the
slice — its types, its journal delta, genesis, the fold and the frontier
arithmetic; beneath it, `state/mint.rs` holds the lock keys and the five
mints (§A) and `state/query.rs` the queries (§C).

Rules that hold across its files:

- **A mint is a query, and its caller commits it.** A mint returns the next
  address with the one `M3Rec::Allocate` that realizes it. The caller takes
  the paired `*_lock_key` for the transaction, mints off that transaction's
  working state, and pushes the record in it before its next mint on the
  chain. That record is the only thing that advances a frontier. A mint
  whose record is dropped hands out the same address again, and nothing
  reports it; a record pushed anywhere else is stale and issues its address
  twice, refused only by a debug build's fold.
- **An account is minted only with its seat.** `delegate` is the only op
  that allocates an account: it stages the account's `M3Rec::Allocate` and
  its principal's `M3Rec::RegisterPrincipal` in one transaction, and genesis
  folds its one account the same way. So a registered account is owned at
  exactly its own prefix, and so is every document in it — the owner
  account `skep-engine` reads by one lookup (`M3State::account_seat`) and
  `skep-febe` and `skepd` read off ω. A second path that allocates an
  account owes the same seat.
- **A namespace has one spelling.** `NsKey`'s fields are private to
  `src/ns.rs`, so every frontier key, and every chain lock key encoded from
  one, is built there. The two registry keys are M3's own, crate-private.
- **No mint lands in the ghost region.** `skep-links` builds its reserved
  type addresses from `ghost_position`, and `src/ghost.rs`'s floor keeps the
  allocator past them on every board.
- **The slice's field order is its checkpoint format.** Fields are appended
  to `M3State`, never inserted.

Its integration suite is one binary, `tests/it/`: one file per surface over
the shared `common` world, and `heap`, the binary's byte-counting
allocator.

## The arrangement, `skep-arrangement`

`skep-arrangement` owns what a document holds: per document a content and a
link run-list (its arrangement), the provenance relation R (every content
address a document has ever held), and two per-member facts — the birth
extent and the shot terms — all in one slice, `M5State`. It is the one place
in the workspace where state is destroyed: `delete` removes positions and
`rearrange` reorders them, in place, and R keeps every address a delete
removed. Its modules are declared in `src/lib.rs` in dependency order, each
with a line saying what it holds; each names in code only the modules above
it, and `tests/it/tidy.rs` checks it. `ops.rs` is the `Vstream` handle and
what its operations share; beneath it, `ops/insert.rs`, `ops/publish.rs`,
`ops/copy.rs`, `ops/delete.rs`, `ops/rearrange.rs` and `ops/version.rs` each
hold one operation's `impl` block. Its `test-hooks` feature (default off)
compiles in `seat_link`, the test-only twin of the link seat;
`scripts/gate-full.sh` checks the library without it.

Rules that hold across its files:

- **One fold.** A committed `M5State` comes only from `apply_m5` over an
  `M5Rec`, and inside this crate only `state.rs` builds one: two of its
  fields are private there. The fold reaches an arrangement through
  `state.rs`'s own `arrangement_of` and calls nothing defined in `reads.rs`
  or `shot.rs`, the other two files holding `M5State`'s methods, so an edit
  to a read or to the address form cannot change what replay folds;
  `tests/it/tidy.rs` checks it.
- **One door for a run.** `Run::new` admits every run not built in this
  crate — the serde shadow and the `LinkSeat` fold go through it — and every
  in-crate literal starts at an address that already is a full element
  position: a resident run's start, an in-crate shift of one, or what M3's
  `mint_content` returned. `runlist::extend_or_push_run` is the one place a
  built run is widened and the one place a placement's runs are accumulated.
- **One allocation step.** Every fresh content address is minted and written
  by `ops::allocate_for_placement`, inside the transaction whose placement
  record places it.
- **The version chain is asked, never spelled.** Every trunk, head,
  publication and surface question in this crate goes through `chain.rs`,
  the one reader of M3's version frontier; the floating readers of
  `skep-retrieval` and `skep-discovery` ask its `reading_surface` rather than
  float by hand.
- **One front door.** Every gated op opens with `ownership::gate_write`.
- **The edition is append-only by the ops.** The fold does not check it;
  `Vstream`'s card lists the ops that keep it, and an op that writes a
  content arrangement joins that list.
- **The slice's shape is its format.** `M5State`'s fields and `M5Rec`'s
  variants are appended, never inserted or reordered: bincode writes fields
  in order and variants by index, and `skep-kernel`'s goldens pin the bytes.

Its integration suite is one binary, `tests/it/`: one file per surface over
the shared `common` world, and `tidy`, which checks the module order and the
first rule.

## The link store, `skep-links`

`skep-links` owns the links: one slice, `LinkState` — the append-only map
from a link's address to its value, and the hints folded from it — and one
writer, `LinkWriter`, whose every deposit passes one gate. Nothing is
updated or removed: a retraction is a link of the `[R]` class, and the
tombstone set is a hint folded from those links. The type registry is a
compiled constant, not state: the five shipped classes over the ghost
tumblers `skep-namespace` reserves, built once per process.

Its modules are declared in `src/lib.rs` in dependency order, each with a
line saying what it holds; each names in code only the modules above it,
and an item by its home module, never through the root's re-exports.
`tests/it/tidy.rs` checks that, and that every file under `src/` and
`tests/it/` is declared. `state.rs` is the slice and the fold; beneath it,
`state/reads.rs` holds the read surface. `writes.rs` is the handle and what
its ops share; beneath it, `writes/makelink.rs`, `writes/emit.rs`,
`writes/nullify.rs` and `writes/supersession.rs` each hold one op family's
`impl` block.

Rules that hold across its files:

- **One door to the mint.** `emit_core`, in `writes.rs`, stages every
  deposit: it asks whether the home is registered and owned, of the
  working world, ahead of every gate and every dedup short-circuit, and it
  is the crate's one caller of M3's `mint_link`. `tests/it/tidy.rs` checks
  the last.
- **One insertion point, one fold.** The map and the hints are private to
  `state.rs` and its `reads` child; `apply_link` is the one insertion and
  asserts the address is fresh, and it and `rebuild_derived` fold through
  the one `fold_hints`.
- **Type identity is a class.** Every comparison of types goes through
  `coverage_class` of a slot, never an `Endset`'s derived equality, and
  `class.rs` is the one place a `CoverageClass` is built.
- **The fences stand on every surface.** The fold recognizes a deposit by
  its type slot's class alone, so each sole-writer class is refused on
  every surface but its writers': `[R]` is written only by `nullify`,
  `[K_sup]` only by `assert_sup` and `editlink`, which both ask its claim
  schema of `LinkState::check_sup_schema`, and `replaces` only by
  `makelink_replacing`.
- **One section decision.** Whether a deposit takes M2's dedup section and
  whether the fold keys it are one predicate,
  `TypeRegistry::is_idempotent`, over one key, `DedupKey::of`.
- **What a write deposits has one statement.** `slot_endset` builds the
  slots a MAKELINK deposits; `emit_tuple`, `retraction_tuple` and
  `supersession_claim` build the tuples of `emit`, `nullify` and the two
  `[K_sup]` writers. Each op builds through its function, and so does
  `skepd`'s entry-frame composer, so the row an attestation covers is the
  link the store deposits.
- **The slice's shape is its format.** Only `links` is serialized, and a
  `Link` decodes through `Link::new`, so a decoded value holds the arity
  floor. Fields and variants are appended, never reordered:
  `skep-kernel`'s golden fixture deposits links, so its pinned bytes cover
  them.

Its integration suite is one binary, `tests/it/`: one file per op family,
per gate that crosses them and per part of the read surface, over the
shared `common` world and the kernels it opens; `carrier`, the contracts
that need no kernel; `recovery`, the hints a checkpoint must rebuild; and
`tidy`, which checks the module map and the first rule.

## The content queries, `skep-retrieval`

`skep-retrieval` holds the seven queries the code map lists, and owns
nothing: no slice, no journal record, no fold, no index. Each is a method
on `Query`, which borrows the one `&Snapshot` its caller pins and holds
nothing else — no `Kernel` — so nothing here writes. The queries compose
`skep-namespace`'s registry, `skep-arrangement`'s reading surface,
resolutions and provenance reads, and, for RETRIEVEV alone,
`skep-content`'s values. Two of them take the caller's reader predicate at
a door of their own: RETRIEVEV's `retrieve_v_masked`, asked of each run's
origin, and FINDDOCSCONTAINING's `find_docs_containing_filtered`, of each
container. `skep-febe`'s dispatch is the one production caller; `skepd`'s
codec and the conformance harness name the request and answer types.

Its modules are declared in `src/lib.rs` in dependency order, each with a
line saying what it holds, and `src/query.rs` declares its six children
the same way, a line each; each module names in code only the modules
above it, and an item by its home module, never through the root's
re-exports. `tests/it/tidy.rs` checks that, and that every file under
`src/` and `tests/it/` is declared. `budget.rs`, `error.rs`, `types.rs`
and `vspan.rs` are what the queries share. `query.rs` is the `Query`
handle and the two projections more than one query asks; beneath it,
`query/retrieve.rs`, `query/extent.rs`, `query/origin.rs`,
`query/deletions.rs`, `query/compare.rs` and `query/find.rs` each hold one
query's `impl` block — `extent.rs` the two extent queries' — and the
helpers no other query uses.

Rules that hold across its files:

- **One file reads values.** Only `query/retrieve.rs` names
  `skep-content`'s store: `HasContent` bounds RETRIEVEV's `impl` block and
  no other, so the other six queries answer from addresses, counts and
  provenance alone. `types.rs` names that crate's `Val`, the item a
  delivery carries, and nothing else of it. `tests/it/tidy.rs` checks that
  no other file names the store.
- **Gate the address named, then ask the surface.** Every query refuses an
  unregistered document before it reads an arrangement — the precondition
  `skep-arrangement`'s `reading_surface` states. RETRIEVEV, the two extent
  queries, SHOWORIGIN and COMPARE then read that function's answer;
  SHOWDELETIONS and FINDDOCSCONTAINING read the address named.
- **The budgets are `budget.rs`'s, and they refuse.** COMPARE's two,
  FINDDOCSCONTAINING's one and RETRIEVEV's delivery budget — and the walk
  budget all three price their spans' run-list walks against, before the
  first walk — are counted by `query/compare.rs`, `query/find.rs` and
  `query/retrieve.rs` through `budget.rs`'s `Count`, which admits exactly a
  budget and refuses a batch that would exceed it before it lands, so no
  producer spells that boundary itself; `error.rs` renders them, and a
  request past one gets its rejection and no partial answer.
  `tests/it/tidy.rs` refuses any other file's code line that names a budget
  beside a comparison — the spelling a hand-written guard takes. Every
  query that resolves a span pulls `skep-arrangement`'s lazy
  `iter_resolve` — the three producers counting each run as it arrives, so
  a request past its budget stops there rather than materializing a
  document's every run, and SHOWORIGIN keeping only each run's origin — and
  FINDDOCSCONTAINING's filter asks `arranges_any` rather than building a
  candidate's footprint; `tidy` refuses any file the eager twins —
  `resolve`, `image`, `project` — which answer the same.
- **The rejections are part of the wire.** `skep-febe`'s `lower.rs` maps
  each variant of the six error enums to a `RejectCode` with no wildcard
  arm, so a new variant fails to compile there. `docs/wire.md` names each
  code and restates the four budgets' values, the walk budget's, and what
  each counts; a change to a variant, or to a number or a count in
  `budget.rs`, changes that document in the same commit. Nothing checks the
  document.

Its integration suite is one binary, `tests/it/`: one file per query
surface over the shared `common` world — `retrieve`, `extent`, `origin`,
`deletions`, `compare` with its refusals in `compare_refusals`, and
`find`; `query`, `head_float` and `traits`, what crosses the queries (the
handle and the gate's precedence, the published-address float, the derive
policy); and `tidy`, which checks the module map, the first rule and the
third.

## The link reads, `skep-discovery`

`skep-discovery` holds the link reads the code map lists, and owns nothing:
no slice, no journal record, no fold, no index. Every read is a free
function over the `&Snapshot` its caller hands it, composed from
`skep-links`' matcher and typed reads, `skep-arrangement`'s reading surface
and run counts, and `skep-namespace`'s registry; every read but `image_on`
also takes the caller's reader predicate. `skep-febe`'s dispatch is its one
production caller.

Its modules are declared in `src/lib.rs` in dependency order, each with a
line saying what it holds; each names in code only the modules above it,
and an item by its home module, never through the root's re-exports.
`tests/it/tidy.rs` checks that, and that every file under `src/` and
`tests/it/` is declared. `budget.rs`, `home.rs`, `types.rs` and `sets.rs`
are what the reads share; `image.rs` is the region resolver every
region-family read chains into the link store's matcher; `region.rs`,
`descriptor.rs`, `pointwise.rs`, `survival.rs` and `lineage.rs` each hold
one family, pair or read.

Rules that hold across its files:

- **The home rule has one address.** Under `src/`, only `home.rs` projects
  a link's home or calls the caller's reader predicate; every other file
  there goes through its `home_of` and `home_readable`. The predicate
  answers about a document, and asked of a link instead of its home it
  admits every link. `tests/it/tidy.rs` checks it.
- **`_on` marks a snapshot.** A function under `src/` ends its name in `_on`
  exactly when its first parameter is the `&Snapshot` it reads; a helper
  over one store carries no suffix. `tests/it/tidy.rs` checks it.
- **A read's cost is part of its interface, outside the crate too.**
  `skepd`'s class-scan pool decides on the crate doc's `## Cost` section
  which of these reads to bound. It links the section by its anchor,
  `skep_discovery#cost`, and restates on its own card — `is_class_scan`, in
  `crates/skepd/src/server/scan.rs` — what each read walks and which walk
  the link store at all. A change to what a read walks, or a new read,
  changes that section and that card in the same commit.
  `tests/it/consumer.rs` checks the section's heading and that it names
  every read the crate publishes; nothing checks what a line says a read
  walks, or skepd's card.

Its integration suite is one binary, `tests/it/`: one file per part of the
read surface over the shared `common` world; `home_rule` and `consumer`,
the laws that cross them; and `tidy`, which checks the module map and the
first two rules.

## The operation surface, `skep-febe`

`skep-febe` is the front door every client operation passes through.
`OperationSurface::execute` takes a parsed request and the caller's
session, hands the operation to the store or query module that owns it,
and answers only after that module returns: an acknowledged write carries
the position it committed at (`at`), a read answer the position of the
snapshot it answered from (`as_of`), and every failure is a typed
`Rejection`, never a silence. It holds no journaled state. Its one
authoritative fact is which principal each session speaks for, kept for
the uptime; its retry memo is a hint. It names no concrete `World`: what it
requires of the engine — the world it reads and the factory it writes
through — is its `world` module, which `skep-engine` implements.

Its modules are declared in `src/lib.rs` in dependency order, each with a
line saying what it holds; each names in code only the modules above it,
and `tests/it/tidy.rs` checks it. `operation.rs` is the lifecycle; beneath
it, `operation/door.rs` holds the readability door and
`operation/dispatch.rs` the two dispatch tables.

Rules that hold across its files:

- **One read predicate per request.** `OperationSurface::readable`, where a
  supplied `ReadPredicate` and the world's own predicate meet, is private
  to `operation/door.rs`. Everything else asks through `readable_by` — a
  request's predicate, bound once off the snapshot it answers from — or
  `visible_to`, the visibility class a write lends its store. The world's
  own `ReadableWorld::readable` is a supertrait method of `FebeWorld`,
  callable wherever a `W` is held, so `tests/it/tidy.rs` checks that only
  `operation/door.rs` asks it.
- **The read/write partition is written in three places** — `Op::is_read`
  and each dispatch table's complement arm — and
  `each_dispatch_table_rejects_exactly_the_other_half` holds them together.
  Every classifying method on `Op` — in `request.rs`, and the door's own in
  `operation/door.rs`, private to it — and on `Response` matches
  exhaustively with no `_` arm, so a new variant is classified everywhere
  before it compiles.
- **Every rejection is classified.** Each one the crate builds goes through
  `Rejection::classified`, which sets its disposition from
  `RejectCode::disposition`; every upstream store error reaches it through
  the `lower` table.
- **The retry memo holds `CommittedAck`s and nothing else** — the one
  shape an acknowledged write's `Response` yields — so no rejection and no
  read answer is ever replayed.

Its integration suite is one binary, `tests/it/`: one file per topic over
the shared `common` world; `reexports`, which checks from outside the crate
that a request is built and a response read through `skep_febe` alone; and
`tidy`, the module order and the check the first rule names.

## The daemon, `skepd`

`skepd` owns three decisions of its own: the session layer's gates (who
may act, and what a credential write may do), the cadence of the published
head, and the media door (whether a value a write carries is a media cell —
a picture's reference cell or a blind document's — by one classification,
the cap bounding the parse and never the classification, and what a write
that would mint one is answered: for a picture, whether its hash is one the
caller's own cells already name, or a deposit of the caller's own; a blind
cell, which the board holds no byte of a file for, is admitted with no
deposit consulted) — with, behind the door, the cell index the base and
the pruner read, and the pruner's pass. It also SERVES media bytes: `GET
/blob?i=` reads a picture's whole file by the I-address of its cell, gated
by M10's read by identity and checked against the cell before the first
byte. And it carries the operator's two tools over a board directory, the
inventory and the pull, run with no server. Everything else it delegates
to the stores through the engine, and the media bytes to `skep-blobs`.

Its modules form six layers. A module names only modules in its own layer
or below it, never above; `crates/skepd/tests/it/tidy.rs` checks it. A
write passes down through them in this order:

```
  HTTP request
       │
       ▼
┌─────────────────────────────────────────────────────────┐
│ 1 TRANSPORT        server/listen.rs   server/http.rs    │
│                    accept · read request · write reply  │
│                    serve the event stream · carry a     │
│                    streaming body in the request · the  │
│                    pruner's cadence, the logs'          │
│                    compaction by its pass · the         │
│                    checkpoint thread: the kernel's      │
│                    deferred trigger serviced, the byte  │
│                    bound and the floor re-read, the     │
│                    feed compacted, a failure said · a   │
│                    replace's deferred unlink after the  │
│                    reply                                │
├─────────────────────────────────────────────────────────┤
│ 2 ROUTES           server.rs (router) · actor.rs        │
│                    session_routes · read_routes · op ·  │
│                    blob_routes                          │
│                    hooks (test-hooks builds only)       │
│                    /op: resolve → check → commit →      │
│                         record → head writer's turn     │
│                    /blob/upload: resolve → setting →    │
│                         readiness → permit → gate (the  │
│                         declared total; at the creation │
│                         the bound and the floor on no   │
│                         length) → stream → finish →     │
│                         answer                          │
│                    /blob?i=: resolve → serve (gate →    │
│                         classify → permit → check) →    │
│                         stream, re-resolved mid-stream  │
│                    the pruner's pass under the arm      │
│   TOOLS            tools.rs                             │
│                    inventory · pull — no server         │
├─────────────────────────────────────────────────────────┤
│ 3 VOCABULARY       server/reply.rs · request.rs ·       │
│                    scan.rs                              │
│                    replies & refusals · the request and │
│                    its streaming body · the class-scan  │
│                    pool                                 │
├─────────────────────────────────────────────────────────┤
│ 4 SESSION LAYER    auth.rs · auth/                      │
│                    sessions · policy · slice readers ·  │
│                    signature check                      │
├─────────────────────────────────────────────────────────┤
│ 5 WRITE PATH       write_path.rs  (one write at a time) │
│                    ├── head.rs      the head writer     │
│                    ├── feed.rs      change feed, indexes│
│                    │                the attest store    │
│                    ├── sidecar.rs   commits.log         │
│                    └── classify.rs  a commit's documents│
│   MEDIA RESOURCE   media.rs · media/door.rs ·           │
│                    media/gate.rs · media/index.rs ·     │
│                    media/pruner.rs · media/serve.rs ·   │
│                    media/deposit_read.rs                │
│                    the upload setting · the media door  │
│                    · the blob store, the limits and     │
│                    their default, the hold, the scopes  │
│                    and the bound, the binding and its   │
│                    window · the cell index: the base,   │
│                    the walk at open, the readiness ·    │
│                    the pruner's pass, its halts, its    │
│                    rename aside and its compaction ·    │
│                    the deposit read · the fetch's       │
│                    composed order, its pool and stream  │
│                    · the upload pool, the fetch's twin  │
├─────────────────────────────────────────────────────────┤
│ 6 LEAVES           codec · history · permits · serial · │
│                    limits · notice · media/cell ·       │
│                    media/blind                          │
└─────────────────────────────────────────────────────────┘
       │
       ▼
  skep-engine  →  the stores  →  skep-kernel (journal)
  skep-blobs   →  blobs/ (the files, partials, records, leases)

  Imports point DOWN or sideways within a layer. Never up.
```

A read skips the write path: a read route goes from the routes to
`history` and the engine. The engine sits below the daemon and knows
nothing of it. A blob upload skips the write path too: the blob route
goes from the routes to the media resource and `skep-blobs`, under a
permit of the upload pool held for the body's whole stream, commits
nothing to the journal, and takes no `Serial`. THE BLOB FETCH
(`GET /blob?i=`) skips it the same way: the route resolves the caller,
runs the serve's composed order (M10's read by identity as the gate, the
classification, a permit of the fetch pool, the whole file checked
against its cell before its first byte), and hands the transport a file
to stream — re-resolving the caller between chunks and cutting the stream
by a reset where the entitlement lapsed. The cell index is entered
by the write path at every commit that mints a cell and read by the
media resource; the pruner's pass runs from the routes under the session
layer's lock, on the transport's cadence. THE TOOLS (`tools.rs`, beside
the routes) run no server at all: the inventory opens the journal through
the engine's open, walks the world into a fresh cell index through the
media resource's walk and reads the store's inspection; the pull reads the
same index or the hash the operator hands it, and writes one file through
the store's install — nothing above their own layer.

1. **The transport** — `server/listen.rs` (sockets, worker threads — the
   default count and the minimum, one more than the four permit pools'
   slots together: the reconstruction, the class scan, the fetch and the
   upload — the
   event streams' loop and budget, the pruner's cadence thread — the pass
   once the cell index is ready and then hourly, the logs' compaction on
   its trigger among its acts — THE CHECKPOINT THREAD — the kernel's
   deferred trigger serviced off the write path's guard: the checkpoint
   every 1024 commits or the byte bound, whichever first, its result on
   the operator stream, a failure said once, and after a landing the byte
   bound and the media floor re-read from the checkpoint's size and the
   change feed's five files compacted to the journal's reclaim floor —
   and, after a blob reply is written, the replaced file's deferred
   unlink) and
   `server/http.rs` (the HTTP bytes: the request reader, the reply
   writer, the event framing — and the streaming arm: for the blob
   upload's two body-carrying methods the reader takes the head alone
   and leaves the body, as a `BodySource` over the connection's socket,
   in the request's own slot for the router to take). It hands each
   request to the router and knows nothing of what a request means.
2. **The routes** — `server.rs` (`Daemon` and the router) and the handler
   files beneath it, each an `impl Daemon` block: `server/actor.rs` (who
   the caller is), `server/session_routes.rs`, `server/read_routes.rs`,
   `server/op.rs`, `server/blob_routes.rs` (the PUT: the path family
   `/blob/upload`, the readiness refusal of the index's three readers,
   the five methods, the pruner's pass as the daemon runs it; and THE
   FETCH `/blob?i=`, beside the family, with its query, its mid-stream
   re-check and its clock), and — in `test-hooks` builds only —
   `server/hooks.rs`. `/op` runs one of the
   three write sequences — the plain (AUTH-3.35), the credential
   (AUTH-3.37) or the registry (the record grade for registry records),
   chosen off the op's own type slot before any lock is taken: resolve
   the caller, run the checks, commit, record, then give the head writer
   its turn. `/blob/upload` resolves the caller, refuses the creation and
   the resume `uploads_closed` on a board launched with `--no-uploads`,
   refuses the creation, the resume and the deposit read
   `index_rebuilding` until the index's walk at open completes, admits
   the creation and the resume under a permit of the upload pool — past
   it `upload_busy`, retry-class, before any body byte — gates the
   declared total and — at the creation, before the partial and the
   record — the standing-uploads bound and the floor on no length,
   streams the body one chunk at a time into the store, each chunk gated,
   and finishes under the credential lock's read arm — the requester
   re-resolved there — never under `Serial`. The router takes the
   streaming body out of the request's slot at the head of every routing.
   `/blob?i=` (with `HEAD`) resolves the caller and runs the serve's
   composed order; an admitted answer is a file the accept loop streams,
   the caller re-resolved between chunks and the stream cut by a reset
   where the entitlement lapsed. Beside the routes, `tools.rs` — THE
   OPERATOR's TOOLS: the inventory over a stopped board or a copy (the
   holes, each account's base and pending bytes, the venue total, the
   standing and expired uploads, the halt marks, a foreign designation
   directory; recording no read, writing nothing under `blobs/`) and the
   pull (a file a committed cell names restored by the store's install,
   no lease and no record; beside a serving daemon held to the inventory's
   hash), the two subcommands `main.rs` parses as a leading verb.
3. **The daemon's vocabulary** — `server/reply.rs` (the reply and every
   transport refusal), `server/request.rs` (the request, the streaming
   body's source and the slot it rides in, and the rules the request's
   headers and query obey), `server/scan.rs` (the class-scan pool): what
   the routes and the transport both speak.
4. **The session layer** — `auth.rs` and the modules under `auth/`.
   Sessions and the signed handshake, the policy checks on every write
   (`auth/policy/`: the plain sequence's admission, the credential
   sequence's precheck with the record grade, the registry sequence's
   admission — `auth/policy/registry.rs`, the record grade for registry
   records, whose trial is the credential grade's own, and the seeding
   check the open runs ahead of every genesis — and the write-path check
   — the entry signature, whose one exempt `insert` is a signed
   credential or registry record into a doc 1), the readers of the World's
   identity slice (the key table is the engine's, read off the head
   snapshot each route already holds; the daemon holds no fold of its own),
   signature verification — `skep-signature` is the one crate that links
   the signature libraries; skepd calls its verify.
5. **The write path** — `write_path.rs`. The single point every write
   passes through, one at a time, and the head writer
   (`write_path/head.rs`, which commits through the write path's own
   door). Beneath it, and reachable only from it:
   - `write_path/feed.rs` — the change feed, and the one compaction of its
     five files to the journal's reclaim floor, run at open and by the
     checkpoint thread after each landing; beneath it,
     `write_path/feed/derived.rs` keeps the feed's derived index files —
     a rewrite that fails past its rename stops its file for the uptime,
     said once — and `write_path/feed/attest.rs` the attest store, the
     marker slot mirrored per attested commit, never compacted;
   - `write_path/sidecar.rs` — `commits.log`, the daemon's record of what
     it committed, for whom, and whether the entry was signed — and, on a
     bare line, the journal's answer for the row's op and terms;
   - `write_path/classify.rs` — which documents a commit touched, and
     which of its op's terms the journal can name for a bare position —
     the one place the feed asks the world anything.

   Beside the write path, at the same layer, THE MEDIA RESOURCE:
   `media.rs` with `media/door.rs` — THE MEDIA DOOR, the one step the
   plain write sequence takes between its admission and the commit for a
   value naming the picture cell's kind: `published_target` at a
   published target whatever the declaration, the shot's owner test
   (`not_owner` naming the draft), and THE BINDING: a cell is admitted
   where its hash is one the principal's own cells already name over a
   file whole at the cell's size (the index's arm, read first once the
   index is ready), or one this principal deposited under its own live
   lease over a whole file; refused `unbound_cell` otherwise,
   `lease_lapsed` where the deposit is gone, and `index_rebuilding`,
   retry-class, where the lease arm alone would refuse while the index's
   walk at open runs. It reads the op's values and, for a shot, the
   staging draft's own runs off the locked snapshot, through M5's and
   M4's public reads, and the index, the lease and the file through the
   gate — which is why it is a step of its own and never a producer of
   the session layer's admission. `media.rs` holds `MediaOptions`, the
   upload setting the routes read and `/health` echoes, and THE UPLOAD
   POOL, the fetch pool's twin — the permit the creation and the resume
   hold for a body's whole stream, counted into the worker minimum beside
   the three other pools. `media/gate.rs` —
   THE GATE: the blob store (`skep-blobs`) opened under `blobs/` in the
   data dir, the limits in force (the daemon's default — one eighth of
   the volume's capacity read once at the open, never below 256 MiB — and
   the install hook the serving layer's channel will call), the hold a
   stream has on its upload, the three scopes a deposit is refused on
   (the own scope — the base plus the pending bytes — the venue total,
   the floor — in that order, the requester's own record first), the
   creation's gate (the standing-uploads bound, the floor on no length),
   THE FLOOR IN FORCE — the larger of the constant 256 MiB and twice the
   newest checkpoint's size plus one maximal segment, read at open off the
   newest checkpoint and set by the checkpoint thread as each lands —
   and the binding's read with its window.
   `media/index.rs` — THE CELL INDEX: per hash the cells naming it, per
   account the distinct hashes its cells name at their size (the base);
   entered by `write_path.rs`'s `record` at every commit that mints a cell
   — a sideways step at this layer — and rebuilt whole at every open on a
   thread over an immutable snapshot of the content store, its entries
   added into the one copy (an entry is idempotent per cell); its
   readiness flag is what the index's three readers consult, and a value
   naming the kind under no pinned schema stands in it as a halt mark.
   `media/pruner.rs` — THE PRUNER's PASS: the expired partials removed off
   the record's expiry and the hold; the halts on a foreign designation
   directory or a halt mark; the unreferenced files renamed aside under
   an exclusive arm the caller hands in (the credential lock's write arm
   — named nowhere here), one file per acquisition, re-reading the index
   and the lease log there, each aside unlinked after under no arm; the
   two logs compacted on their trigger under no arm; and the cadence the
   transport's thread waits on. `media/deposit_read.rs` — the one read of
   a principal's own deposits and uploads, its base the index's number
   and the limit in force echoed beside it, served on the upload's own
   path. `media/serve.rs` — THE FETCH's composed order: the
   shape, M10's read by identity as the gate, the one classification, the
   permit of the fetch pool, the whole file checked against its cell
   before its first byte, the stream's two re-check intervals; what
   `server/blob_routes.rs` runs for `GET /blob?i=` and the transport
   streams.
6. **The leaves** — `codec.rs` with `codec/marshal.rs` (the JSON wire
   format: parse, and marshal), `history.rs` (reading the world at an
   earlier position), `permits.rs` (the counting permit the four bounded
   pools use), `serial.rs` (the write-serialization lock and its guard),
   `limits.rs` (request body caps, the cell's cap, and the blob route's
   bounds — the fetch pool's and the upload pool's counts among them),
   `notice.rs` (the
   operator's log line), `media/cell.rs` (the picture's reference cell:
   its schema, its one parser under the canonical rule, its encoder, its
   designation, and THE ONE CLASSIFICATION of every media kind) and
   `media/blind.rs` (the blind document's cell: the second kind, a
   commitment the board holds no byte of a file for). None of these knows
   anything about the daemon; a leaf imports only leaves.

`lib.rs` declares the daemon's modules in layer order, then the fuzz
harness and the crate's public surface; `main.rs` is the binary — the
daemon's flags, and the two tools' lines, a leading verb parsed before any
flag.
`fuzz_support.rs` (in `test-hooks` builds only) serves the fuzz targets and
the tests: it stands above the transport, and nothing in the daemon
imports it.

### Features

| Feature | Default | Adds | Compiled by the gate |
|---|---|---|---|
| `observe` | on | `GET /dump`, the engine's world dump | every build; OFF in `scripts/gate-full.sh`'s `--no-default-features` checks |
| `client` | off | `GET /`, the embedded board — an ACTING client, so opted into (`Cargo.toml` carries the ruling) | `scripts/gate-full.sh`'s `--features client` check and `--all-features` run |
| `test-hooks` | off | `Daemon`'s `#[doc(hidden)]` test hooks, `fuzz_support`, the `Permit` re-export — nothing in another crate | every test build (the crate's self dev-dependency); `scripts/gate-full.sh` checks the library and binary without it |
| `skep-signature`'s `sign` | off — skepd depends with no feature, so the daemon's build holds no signer | the signer's half: the KDF, keygen from a seed, signing, the signer's OS draw | every test build (the suites' dev-dependencies); `scripts/gate-full.sh` checks the crate without it (the verify-only build a daemon links) and with it |
| `skep-signature`'s `test-hooks` | off | implies `sign`; the fixtures' hooks: the seeded RNG, `sign_with_rng`, the Ed25519 half's signing key, the KDF's half seeds (`derive_half_seeds`), the widths | every test build (its self dev-dependency, and skepd's dev-dependency on it) |

## Rules that hold across files

- **Crate dependencies point down.** The order in the code map is the
  order the compiler enforces between libraries; the dev-dependencies
  pointing back up are `skep-kernel`'s, whose integration suites build
  their shared fixture through `skep-engine` and the stores it assembles,
  and `skepd`'s on `skep-resolve`, whose end-to-end cells and measurements
  run where boards are spawned — the daemon's library never depends on
  the resolver.
- **The client reproduces the daemon's grammars under their rules, never
  its code.** `skep-client` holds its own `Origin::parse`, held to the
  daemon's vector set by a test and never imported from `skepd`; the
  signed origin it frames is the one it dials (AUTH-4.8); every
  `/challenge` it fetches follows the pre-check's two reads (AUTH-5.65);
  `Skepd-Session: closed` has one reader, the board's authenticated
  exchange; a halt names the state, its cause and the one act (AUTH-5.66),
  and a refusal the client's state machine does not arm is surfaced, never
  retried. The person doors — the claim's notebook arm and
  `keygen --anchors` — require a `Person`; the terminal check is the CLI's
  implementation of that seam, never the walk's.
- **Inside `skepd`, imports point down.** A module names only modules in
  its own layer or below it, never above: the transport calls the router,
  and nothing below the router calls the transport; a leaf imports only
  leaves. Code names an in-crate item by its home module, never through
  the crate root's re-exports. `crates/skepd/tests/it/tidy.rs` checks all
  of it.
- **One write path.** Every write to the world goes through
  `write_path`, one at a time. Only the write path records to the feed and
  to `commits.log`.
- **The PUT takes no `Serial`.** A blob upload commits nothing to the
  journal, so the write-serialization lock has nothing to order for it:
  `media/` and `server/blob_routes.rs` never name `serial`. What the
  finish holds — from the rename through the lease's sync — is the
  credential lock's READ arm, the arm the plain write sequence holds
  across the media door, so the door's read of the lease and the finish's
  write of it never interleave with a credential write; the requester is
  re-resolved under it at the rename. The pruner's rename aside holds
  that lock's WRITE arm, one file per acquisition, so the door's check
  and the commit it guards are one interval no removal of a name enters;
  the aside's unlink and the logs' compaction hold no arm of it.
- **The cell index has one lock of its own, taken innermost.** The write
  path enters it under `Serial`, the gate reads it under the credential
  lock's read arm, the pruner under its write arm, the walk at open under
  neither; `media/index.rs`'s lock is held across no other lock, and no
  caller holds it while taking one.
- **The store knows no policy.** `skep-blobs` is handed a root and
  principals as opaque strings; who a principal is, what bounds its bytes,
  the interval an upload and a lease are given, and which lock a finish
  runs under are the daemon's (`media/gate.rs`), never the store's.
- **The cell's parser is the one parser; the door is the one media
  step.** `media/cell.rs`'s `parse` is the daemon's one reading of a
  picture cell's bytes, under the canonical rule (`parse(b)` answers a
  cell only where `b == encode(parse(b))`), and the vector set under
  `crates/skepd/tests/it/fixtures/media/` is what every other parser of
  the cell — the shell's, the browser page's — is held to. `media/door.rs`
  is the one place the daemon acts on that reading: no producer of the
  session layer's admission reads a value's bytes for the cell, and no
  route serves one.
- **The daemon writes only its own files.** The journal and checkpoints
  are the kernel's — its `checkpoint.tmp` included, which the kernel
  removes at open. The daemon's own files are `commits.log` — its
  testimony about what it committed, for whom, and whether the entry was
  signed — the feed's derived index files, projections of that testimony
  and the journal, rebuilt from them on loss — `commits.log` and the four
  compact to the journal's reclaim floor at open and after each checkpoint
  the checkpoint thread lands, the floor moving then and at no other
  moment — and `feed-attest.log`, the attest store: each attested commit's
  marker slot, mirrored at commit from the value the write path admitted,
  rebuilt from the journal above the reclaim floor, and the one daemon
  file that is not a projection — below the floor the checkpoint holds no
  marker, so its line there is the entry signature's only copy at the
  origin, kept and never compacted, its one cut the open's tail check,
  backed up with the board directory as the kernel's own files are. And,
  through `skep-blobs`, the media stores under `blobs/`: the deposited
  files (PRIMARY — neither prunable nor rebuildable beyond the unreferenced
  tail, restored by the exact bytes), the partials, `uploads.log` and
  `leases.log` (honest-null sidecars: a lost record reads as no upload, a
  lost lease as no lease, cured by a re-PUT), backed up with the board
  directory, the journal copied first. It never writes anything about
  the world outside the kernel.
- **The key table is the World's.** The identity slice — every account's
  key set and the board's claim — lives in `World`, stepped by the engine
  at each credential deposit's commit and checkpointed with the world
  (AUTH-2.79–2.88). Nothing rebuilds it from the deposits: the fold's
  verdicts depend on the order the deposits committed in, and the journal
  is the one record of that order. A checkpoint written before the slice
  that holds credential deposits is not a start point; the open steps back
  to one that is, or to genesis while the journal reaches it, and replays.
  So at its FIRST OPEN under a build that writes the slice, a board whose
  journal still reaches genesis replays from genesis — correct, once,
  slower — and a board past genesis-reachability (two retained
  checkpoints of 1,024 commits) refuses to serve until regenerated or
  restored: dev boards regenerate, a served board is the owner's call. A
  slice-less checkpoint with no credential deposit loads as the empty
  table, which is the true one.
- **Nothing is overwritten.** Content, links and journal entries are
  append-only. A removal is a new record, not a deletion.
- **The wire is a contract.** `docs/wire.md` is what clients build
  against. A change to what the daemon answers is a change to that
  document in the same commit.
- **Tests live beside the code they test.** Unit tests are a `tests`
  child module; one of 200 lines or more lives in its own `tests.rs`
  beside the file. Integration tests live in each crate's `tests/it/`, one
  test binary per crate. See `AGENTS.md`.

## Where the reasons live

- `docs/wire.md` — the wire protocol, every route and refusal.
- The module designs (M1–M10), the composition contract and the AUTH, PUB
  and REGISTRY specifications, in the design project — the reasoning
  behind each crate and each rule above.

This file changes when the layout changes: a new crate, a moved module, a
new cross-cutting rule. It does not record history.
