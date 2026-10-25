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
the loopback by default (`--bind` names the address; the hosted image
binds its container's). A write arrives as an operation; the daemon checks who is
asking and whether they may do it, applies it to the world through one
serialized write path, records it, and announces it. A read is answered
against the current world, or against the world as it stood at an earlier
position in the journal.

## Code map

The workspace is twenty-nine crates under `crates/`. Dependencies point
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
- `skep-util` — the support crate below the daemon, the media crate, the
  blob store, the client and the shell: the five utilities two or more
  crates take and none owns — the counting permit pool behind the daemon's
  five bounded pools and, beside it, the edge tracker each bound that
  refuses holds, so its saturation and its clearing are said once per
  episode; the operator's notice line (`skepd: ` on every line; §The
  support crate says why a library spells it); the JSON determinism
  helpers — `obj`, the key-sorting object builder every JSON object the
  daemon emits is built through, `hex_string` and its exact inverse
  `parse_lower_hex` with `hex_nibble`; a setting's source; and the file
  under one tail rule — `file`, the read that hands back a file's lines as
  bytes and classifies its tail, the append written where the last whole
  line ends with a crash's tail first cut off or closed by a mark, or cut
  at the open where the caller asks it there, the whole file written once
  or published by a locked temp and a rename, the temp the module's or the
  caller's `.compact` twin, the bytes a cut drops kept beside the file
  first, the removal that answers what it did, and the sweep of the temps
  a dead run left — which the client's key store, bindings file and anchor
  export, the shell's held-writes file, the dev board's manifest, the
  blob store's two logs and the daemon's commit log and five feed files
  take. It depends on no other skep crate and on
  `serde_json` alone, so it may stand anywhere in the foundation; it
  stands here, above the blob store, because the blob store's two logs
  take its `file` module and a crate takes only what is listed before it —
  it holds no part of the world, and is what the crates that write files
  lean on. No constant lives here: a constant is configuration, not a
  utility. Its rules: §The support crate.
- `skep-blobs` — the blob store (media lane B): the four media stores
  under one root — the files at `blobs/<designation>/<hex>`, the partials,
  the upload records and the lease log — the PUT's fsync order, REPLACE on
  a present hash, the lease's honest-null answer, the pruner's rename
  aside, the logs' runtime compaction on a trigger, the volume's capacity
  read, the open's probe of the volume's hard links, the owner-only modes
  every file is born with, the open's account of what it repaired, found
  and freed, the logs' sizes and their stops' figures, every I/O failure
  named by its file and its act, and the operator's two doors — the
  read-only inspection and the pull's install by the PUT's order. Of the
  skep crates it depends on `skep-util` alone, whose `file` module its two
  logs are read, cut, appended, kept and rewritten through; it knows a
  principal only as an opaque string, holds no lock the daemon's write
  path takes, writes no operator stream, and reads no limits record. One
  feature, default off:
  `test-hooks` compiles in the test seam, `store/hooks.rs` — a hold or an
  injected failure at a step of the finish, and the methods only tests
  call. `scripts/gate-full.sh` builds the library and its docs without it.
  Its modules and rules: §The blob store.
- `skep-corpus` — the prose corpus a dev board is seeded from and the
  search budgets are measured over: a git repository read at one pinned
  commit through `git` alone — the records tier's filter, the paragraphs
  of its `.md` files, and the one deterministic cut into documents of
  1–10 KiB (`cut-v1` over the tier, `cut-v2` over a chosen subtree), each
  document with the paragraphs it was joined from. It depends on no skep
  crate and on nothing but `std` and a `git` child process, so it may
  stand anywhere; it stands here, last of the foundation's leaves, because
  it holds no part of the world — it is what the search budgets suite
  (`skep-search`, a dev-dependency) and the dev binary (`skep-cli`) lean
  on. Its rules: §The corpus crate.
- `skep-http` — the plain HTTP/1.1 subset two programs speak over
  loopback: one request per connection, the head read to its terminator
  and the body to its `Content-Length` under the two caps the caller hands
  in (`Limits`), a `Transfer-Encoding` refused by name, and every answer
  written with `Cache-Control: no-store` and `Connection: close` —
  `read_request` with the `Request` it answers and the `Refused` it
  refuses with, `write_response` and `write_head`. No cap value, no CORS
  header and no event stream lives here: each is its caller's own. It
  depends on no other skep crate and on nothing but `std`, so it may stand
  anywhere; it stands here beside `skep-corpus` because, like it, it holds
  no part of the world — it is what the dev provider
  (`skep-cli`'s `skep-dev serve`) calls today and the provisioning service
  will call next. The daemon's own reader stays the daemon's and calls
  nothing here. Its rule of membership is its crate root's.

**The stores** — each owns one slice of the world and depends only on the
foundation and on the stores above it.
- `skep-namespace` — the name space: it mints every address and builds the
  lock keys the stores take; the entity and principal registries and
  ownership (ω); each document's publication bit. Its modules and rules:
  §The name space.
- `skep-content` — the write-once map from address to value or STRETCH —
  a run of consecutive single-byte values written by one insert, held as
  one entry under its first address — ordered by address so a checkpoint
  walks it without sorting and a read finds the entry at or below an
  address (the predecessor read, `range(..=t).next_back()`, sound across
  the map's leaves): point queries that answer every address inside a
  stretch by its byte, one run read (`pieces`, the maximal pieces of an
  I-extent), and one enumeration of every entry, in no promised order, for
  whole-store work such as the cell index's walk. One feature, default off:
  `test-hooks` compiles in `write` and `write_stretch`, the test-only twins
  of `stage_write` and `stage_stretch`, and the `skep-kernel` and
  `skep-namespace` edges only they take. Every debug build asserts that
  each address written is a content element address.
  `scripts/gate-full.sh` builds the library and its docs without the
  feature and runs its suite in release.
- `skep-arrangement` — documents as arrangements of content, versions,
  provenance. Its modules and rules: §The arrangement.
- `skep-links` — the link store: `LinkState`, the append-only map from a
  link's address to its value and the hints folded from it; `LinkWriter`,
  whose every deposit passes one gate; the raw and typed reads and the
  matcher `skep-discovery` composes, answered from a per-slot coverage
  index; the type registry, a compiled constant. Its modules and rules:
  §The link store.
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
- `skep-identity` — credential records, key sets, the identity fold, and
  the signature-filtered key table a verifying reader keeps beside the fold,
  its signature check handed in by the caller (`table`). Pure; of the skep
  crates it depends only on `skep-address`. The engine depends on it:
  `World` seats the fold as its identity slice, stepped at each credential
  deposit's commit and checkpointed with the world (AUTH-2.79); the client
  and the resolver take the table.
- `skep-signature` — the hybrid signature's frozen rules: the KDF, keygen
  and signing (behind its `sign` feature), the key and blob layouts, the
  verify. The one crate that links the signature libraries; skepd calls its
  verify. Of the skep crates it depends only on `skep-identity`.

**The surface and the assembler**
- `skep-febe` — the operation surface (`OperationSurface`): one front door
  that dispatches every operation to the stores, and the codec seam a
  transport fills. Its modules and rules: §The operation surface.
- `skep-media` — the daemon's media resource (media lane A and lane B's
  policy): the reference cell's one parser and the blind cell, the media
  door, the gate over `skep-blobs` — the limits in force, the hold, the
  three scopes, the deposit's terms, the floor, the binding — the cell
  index and its walk at open, the pruner and its pass, the fetch's composed
  order, the two permit pools, and the
  media limits, each `pub` where another crate reads it. It transports
  nothing: the routes, the replies, the deposit read and the operator's
  tools are the daemon's.
  Generic over the world M10 reads (`skep_febe::FebeWorld`), it depends on
  no engine — the daemon instantiates it at its `World` — and so stands
  here, beside `skep-febe` and above the assembler. One feature, default
  off: `test-hooks` compiles in its test seam, every item of it
  `#[doc(hidden)]`, and forwards `skep-blobs`'s; `scripts/gate-full.sh`
  builds the library and its docs without it. Its modules and rules: §The
  media resource.
- `skep-engine` — the one assembler. It defines `World` from the stores'
  slices and the identity slice, genesis, recovery and reads at a past
  position. Nothing depends
  on it except the daemon's two crates, `skep-core` and `skepd`, the
  conformance harness and — as dev-dependencies — `skep-kernel`, for the
  fixture its hazard, golden and chain suites share, and `skep-media`,
  whose door's and index's unit suites judge generic code against the
  concrete `World`; the as-built list is kept once, in the engine's crate
  doc, and every other place points at it.

**The daemon's core**
- `skep-core` — the daemon's core: the session layer (who may act: the
  origin sets, the handshake, the sessions store, the credential write lock
  and the refusal producers it scopes, the signed-ops check, the readers of
  the World's identity slice), the commits (the one door every write rides
  — commit, record, announce, under one guard — the change feed and its
  five files, the attest store, the published head writer), the wire codec,
  the six bounds it reads and the serialization lock, each `pub` where the
  daemon reads it. It transports nothing: the routes, the replies, the
  history service and the operator's tools are `skepd`'s. It depends on
  the engine — the daemon's two crates are what the Engine Composition
  Contract permits — and on `skep-media` for the cell index the commits
  enter, and so stands here, after the assembler. One feature, default
  off: `test-hooks` compiles in its test seam, every item `#[doc(hidden)]`,
  forwarding nothing; `scripts/gate-full.sh` builds the library and its
  docs without it. Its modules and rules: §The daemon's core.

**The programs**
- `skepd` — the daemon (below), over its core, `skep-core`, and the
  operator's two tools over a board directory — the inventory and the pull
  — two subcommands of the one binary, run with no server.
- `skep-mcp` — a stdio adapter for agent harnesses over the shell's core
  (`skep-shell`): one signed session for the process's life, every wire
  op a tool of its name, the shell's calls, a change pull and a blob
  fetch beside them. One binary: of the skep crates it depends on
  `skep-shell` and `skep-client` — the latter for the types the shell's
  surface names, the inert rendering a key's label and every log line
  take, the plaintext warning its start says, and the places its start
  checks the store against: the search index's directory under it and the
  person's own store — and never `skepd`, which its suite spawns as a
  dev-dependency. No feature, and no TLS: it
  refuses an `https://` board at start and dials plain `http://` alone;
  every test build compiles it with `skep-client`'s `test-hooks` on, so
  `scripts/gate-full.sh` checks the binary as it ships. Its modules and
  the rules that hold across them: its crate doc, `src/main.rs`.
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
- `skep-search` — the search index, a LIBRARY a client embeds (the
  design's `search.md`; R9b's board-wide search is the reader's own index,
  the substrate search-free): the document model — one unit per document
  version's arranged content, delivered in parts and joined, keyed by the
  bare document address — the tokenizer over UAX #29 word boundaries with
  the accent, apostrophe and format-control folds, and the inverted index
  with positions behind one concrete type of one class, with the class
  check and the ceiling made where a unit enters. Of the skep crates it
  depends on `skep-address` alone, and beyond it on the two Unicode crates
  — no engine, no store, and never `skepd`, which never depends on it;
  the shell links it beside `skep-client`. No feature. Its modules and
  rules: §The search index.
- `skep-client` — the library every ACTING client embeds (the design's
  `client.md`): the one outbound dialer, bare and signed sessions behind
  AUTH-5.65's pre-check, the key store, the signing seam over the hybrid
  key, the reader's verifier over the signature-filtered set, the claim
  ceremony, the compositions every later ceremony runs over, and the
  ceremonies over them — the retirement preview with its reach, the anchor
  import, the device and loss arms of recovery, retirement, rotation with
  its supersession trail, and the handoff door's two walks — and, behind
  its `search` feature, the SHELL's HALF of search over `skep-search`: the
  feed consumer, the index directory, the resume, the session's triggers,
  the document index, the state event's arms, the bridge call and the
  jump's landing rule — and, behind its `merge` feature, the `merge`
  module, the pure core of merging two versions of one document: the
  composition over three run lists, the gap report and the counts — and,
  under `acting`, the `share` module: `share`, a draft or an account
  opened to one account; `privash`, a draft opened to every account on
  the board and never a guest (PUB-5.108, Nelson's term); `revoke`; and
  the grants issued, held and privashed read back. Of the
  skep crates it depends on `skep-address`,
  `skep-identity`, `skep-signature`, `skep-resolve` and — optional, behind
  `search` — `skep-search` alone — never `skepd`, which does not depend on
  it either (its suite spawns the daemon as a dev-dependency). Four
  features: `acting` (default on) gates everything that signs or holds a
  key; `tls` (default off) the `https://` arm; `test-hooks` (default off)
  the scripted person a suite drives; `search` (default off, implies
  `acting`) the `search` module. Its modules and rules: §The client.
- `skep-shell` — the SHELL's CORE, written once for the dev provider and
  the desktop shell (the design's `client.md` §4b; the dev provider
  record): the bridge's twenty-four calls — §4b.1's
  twenty-two, the document index's listing and the change feed's page —
  and seven events over
  `skep-client`, the board and session references the page is
  handed in a credential's place, the person seam that forwards PUBLIC
  moments to the page and answers SECRET and CONSENT ones from a dev arm
  — or refuses them, where the run names no arm because no person is
  present —
  the feed thread per board, the attest a signed session composes for the
  checked set, the held-burst store and the hold that resends what a board
  could not take (`client.md` §3c), and the TypeScript declarations of
  every value that crosses the bridge. Of the skep crates it depends on
  `skep-client` with its `search` feature, `skep-identity`, `skep-address`
  and `skep-search` alone — never `skepd`, which it reaches over the wire
  (its suite spawns the daemon as a dev-dependency). No feature, no
  transport: the loopback server is `skep-cli`'s dev verb's, the native
  bridge the shell's. Its modules and rules: §The shell's core.
- `skep-cli` — the `skep` command over `skep-client`, fifteen commands:
  `keygen`, `claim`, `session`, `fingerprint`, `verify`, `health`, `bind`,
  `enroll`, `recover`, `retire`, `rotate`, `handoff`, `accept`,
  `merge`, the one over the library's `merge` feature, which this crate
  alone turns on, and `share`, which shares a draft or an account with
  one account, privashes a draft, revokes a share and lists the grants
  over the library's `share` module; flag
  parsing by hand, a `Person` over the terminal, stdout data and stderr
  talk — and the dev binary `skep-dev`, whose two verbs `seed` a running
  claimed board with a prose corpus (`skep-corpus`) and `serve` the
  shell's core (`skep-shell`) to a page over loopback through the plain
  HTTP/1.1 subset (`skep-http`) — the dev provider — over the same
  plumbing; behind its `dev-hooks` feature, which no shipped
  build enables, `serve --own` links `skepd` with `test-hooks` and runs
  the daemon in-process. Its modules and rules: §The command.
- `skep-provision` — the service behind a hosted board's sign-up, one
  binary: `serve` serves the sign-up page and the claim form over the
  plain HTTP/1.1 subset (`skep-http`), judges the person's record in
  process (`skep-identity`'s `parse_enroll`, the hosted walk's
  preview-kind test, and the hosted genesis's two refusals — every key's
  halves decoding, sixteen keys at most), runs the steps that make a
  board — on a pool of workers, different names at once, the name the
  unit of exclusion — through the host's `docker` command, writes one
  proxy snippet per board and reloads the proxy, the two serial across
  every name, shows the live reply at the post's status URL and mails it
  once the board is live, and at its start sweeps away any board a stop
  left half-made; `invite`
  mints one invite by the owner's hand. Of the skep crates it depends on
  `skep-identity`, `skep-http` and `skep-signature` — its verify alone, no
  `sign`, for the record's all-halves decode — never `skepd` or
  `skep-client`: the sidecar it runs dials the board, and it dials
  nothing. It holds no key. One
  feature, default off: `test-hooks` compiles in its two fakes — the
  scripted Docker runner and the mailer that appends to a file — and the
  two flags that select them, which the crate's self dev-dependency turns
  on for its own suites. Its modules and rules: §The provisioning service.
- `skep-conformance` — a differential harness against `udanax-green`'s
  goldens.

## The kernel, `skep-kernel`

The kernel owns its names in one directory: the journal's segments
(`seg-<n>.wal`), the checkpoints (`checkpoint.<n>`, each written through
`checkpoint.tmp`, a temp file the kernel alone deletes), the exclusion
lock (`kernel.lock`), and the files the open's tail cut keeps
(`seg-<n>.wal.cut-<byte>`, then `….<k>`), which the kernel never reads,
moves, removes or writes over — they are the operator's. Every other name
in that directory it leaves alone, so an embedder keeps files of its own
beside the journal — the daemon keeps its change feed and its blob store
there. The world is a type parameter: the kernel folds records through
`WorldState::apply` and never reads them, handing each the position of
the commit it belongs to, so a world may keep a fact's commit position as
state (D1: a position is a fold input, the clock never is). Its modules
are declared in `src/lib.rs` in dependency order, each with a line saying
what it holds; under `test-hooks` (default off, never in a shipped build)
`src/hooks.rs` is the write-fault seam.

Rules that hold across its files:

- **One door to the write state.** `ApplierLock::acquire`, which refuses
  a nested acquisition, is the only way to the sequencer, the journal and
  the cadence; the lock's fields are private to `kernel/applier.rs`.
  `Kernel::checkpoint` never takes it: its own mutex may be taken under
  the applier lock, never the reverse.
- **A scan and its fold share a base.** Scans are reached through
  `replay::Base::scan` — and, in the mode that collects the committed
  boundaries with their slots and no record, `replay::Base::scan_boundaries`
  — never by a caller supplying `S_load`.
- **One skip rule.** `segment::scanned_above` decides which segments a
  scan reads; the scan walks it and the format probe opens its first.
- **One codec.** Every byte the kernel writes goes through
  `journal::codec`, checkpoint bodies included; `checkpoint.rs` borrows it
  and the directory fsync from `journal`.
- **The formats are pinned.** `tests/golden/` holds the bytes the
  fixture's ops must reproduce; a moved byte is a format event and bumps
  the `SKJ` and `SKC` stamps, and `tests/golden-prestretch/` keeps the one
  committed pre-stretch board, which this build opens from genesis. A
  moved bound the reader holds every journal to — the frame cap, the
  transaction budget, the segment ceiling, the slot's width — is a format
  event too, though it keeps every golden byte, so `src/journal/tests.rs`
  pins those four beside the stamps; the rotation threshold and the
  resynchronization budget are pins a ruling moves under one stamp.

Its integration suites are one binary, `tests/it/`: `kernel`, `hazard`,
`golden`, `chain`, `docs`, `modes` and `tidy`, over the shared `fixture`
and `mutilate`; each module's doc says what it holds.

Its rules of mechanism: SP-1, SP-2, SP-4, SP-7, SP-8, SP-10, SP-13, SP-14,
SP-21, SP-25, SP-28.

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

- **Every name passes one check**, `blobs.rs`'s spellings: a caller's at
  `Store`'s entry points, a log line's at open.
- **A record changes only by its holder's acts.** `UploadRecords` makes
  every change an upload record takes, and its write is private to
  `uploads.rs`: `Store` and `partials::reconcile` choose when, never what.

Its integration suite is one binary, `tests/it/`: `finish`, `replace`,
`blobs`, `uploads`, `reopen`, `lease`, `modes` and `tidy`; each module's
doc lists its claims. Six unit suites sit beside their code: `store.rs`'s,
`uploads.rs`'s, `lease/map.rs`'s, `partials/handle.rs`'s, `blobs.rs`'s and
`jsonl.rs`'s, the last in `jsonl/tests.rs`.

Its rules of mechanism: SP-1, SP-2, SP-3, SP-5, SP-7, SP-8, SP-10, SP-13,
SP-14, SP-18, SP-19, SP-23, SP-28.

## The support crate, `skep-util`

`skep-util` holds the five utilities two or more crates of the workspace
take and none owns — the daemon, the media crate, the blob store, the
client library and the shell's core stand above it. Its modules are
declared in `src/lib.rs`, each with a line saying what it holds, and the
crate doc there states the rule of membership and the program-name
decision: `permits` — the counting permit pool (`Permits`, `Permit`), the
one mechanism behind the daemon's five bounded pools, and beside it the
edge tracker (`EdgeTracker`, `Edge`), the once-per-episode memory of a
bound that refuses, with the one rendering of a pool's two lines
(`PoolEdgeLine`) and the one clock the hold-down is judged against
(`edge_clock_now`); `notice` — the operator's stream, its two doors `emit`
and `emit_lines`, the `drain` at the binary's exits and `set_sink`, the
embedding program's door; `json` — the determinism helpers, `obj`,
`hex_string`, `parse_lower_hex` and `hex_nibble`; `source` — `Source`,
where a setting's value in force came from; `file` — a file one process
writes and reads back after a crash, under the one tail rule: `read_lines`
and the streaming `LineReader`, `Appender` with `cut` and `sync_handle`,
`write_once`, `publish` and `publish_by`, `keep_beside`, `remove`, and
`stale` with `sweep_stale`.

Rules that hold across its files:

- **Membership.** An item lives here if and only if at least two crates
  take it and it has no subject of its own. A constant is configuration,
  not a utility: the limits the two daemon crates share are the media
  crate's own public numbers and the daemon's stay the daemon's, and the
  bound a client file's line keeps is that file's own, so none lives here;
  a helper one crate alone takes lives in that crate.
- **Nothing of skep below it.** The crate names no store and no engine;
  it depends on `serde_json` and `std` alone, so it may stand anywhere in
  the code map's order and any crate may take it.
- **The program's name** is spelled once, in `notice.rs` — in a library,
  by decision: exactly one program writes the operator's stream, and the
  crate doc says why.

Its unit suites sit beside their code: `json/tests.rs`, `notice/tests.rs`
and `file/tests.rs`.

Its rules of mechanism: SP-1, SP-2, SP-3, SP-5, SP-7, SP-9, SP-10, SP-11,
SP-12, SP-14, SP-17, SP-25, SP-26, SP-27.

## The corpus crate, `skep-corpus`

`skep-corpus` holds one rule in one place: THE CUT of a git repository's
prose into documents of 1–10 KiB, read at one pinned commit through `git`
alone — never from the working tree, and nothing of the repository copied
anywhere. Its one module is its crate root, `src/lib.rs`, whose doc states
the rule — the records tier (`in_tier`, `Corpus::tier`, `Corpus::records`),
the cut (`Corpus::cut`, `cut-v1`), the subtree (`Corpus::under`, `cut-v2`)
and the sources (`Corpus::cut_sourced`); its unit suite, `src/tests.rs`,
cuts a repository it builds under the system temp dir.

Rules that hold across its files:

- **The callers name the repository and the pin.** The crate reads no
  environment variable of its own: the search budgets suite reads its
  `SKEP_SEARCH_CORPUS` and the dev binary its `--repo` and `--pin`, and
  each hands the crate a path and a commit.
- **Nothing of skep below it, nothing of the world in it.** The crate
  depends on `std` and a `git` child process alone — no skep crate, no
  feature, no platform call — and copies nothing of a repository into
  this one.
- **One rule, two names.** `cut-v1` over the whole tier is the budgets
  suite's cache key, so its documents never change; a subtree is `cut-v2`,
  another source and another name, and a cache keyed by the rule never
  mixes the two. The 10³ cut at the design repository's pin is pinned by
  the budgets suite — 1,000 documents, 6,258,909 bytes, the smallest
  1,058, the largest 10,237 — so a change to the rule, the cap or the
  targets is a STOP there, not a new number.

Its rules of mechanism: SP-10, SP-14, SP-19.

## The registry rows and bodies, `skep-registry`

`skep-registry` holds what the registry's two halves — the daemon that
verifies and commits a registry deposit, and a resolver that reads it back
— both read and neither owns. Its modules: `rows.rs` is the one table of
the twelve commons rows the registry allocates — five kinds on the
reserve's ordinals `3.55`–`3.59` of the ghost home document's type
subspace and seven subtype rows nested under their kinds by prefix — read
through one held pin per row; `body.rs` the binding's and the endpoint's
bodies, their one parser under the canonical rule, their encoder and the
cap; `check.rs` the seeding check's three arms and the refusal that names
the arm; `vocabulary.rs` the one table of every link type the build names
in the commons, which the daemon's open seeds the registry document from
and a client reads a type's name by.

Rules that hold across its files:

- **One table, one address apiece.** A row's address is spelled once, in
  `rows.rs`'s table, from the commons type prefix and the row's ordinals;
  the engine's ledger reads the rows through this crate's pins, and the
  daemon's write-path classes read them through the ledger. The
  vocabulary's table holds every registry row at `rows.rs`'s address.
- **The canonical rule is the parser.** `body::parse` is the one parser of
  the bodies, and the vector set under `tests/vectors/` is what every
  parser of the bodies is held to — this crate's, and any other a reader
  of the bodies builds (`skep-resolve` builds none: it calls
  `skep_registry::parse`).
- **The check runs on lists.** `seeding_check` takes the registry's rows
  and the foreign rows as lists, and the daemon runs the check over the
  whole domain it can see ahead of every genesis.

Its integration suite is one binary, `tests/it/`: `rows`, `check`, `body`
with its child `body/laws.rs`, and `tidy`. Its unit suites sit inline
beside their code and hold only what that code's privates can show.

Its rules of mechanism: SP-18, SP-25.

## The resolver, `skep-resolve`

`skep-resolve` is the client's half of the registry: what reads the board
the daemon serves and knows the bindings it read were genuine. It links
no daemon and no engine, speaks the wire as a guest, and opens no socket
to an endpoint — the dial is the caller's. Its modules: `hint.rs` the root
hint; `http.rs` the written-out HTTP/1.1 client behind a `Transport`
trait; `board.rs` the typed reads over any transport (`Board`), every
read counted by kind; `mirror.rs` the `/changes` consumer's types and
state, the journal copy and the fetch cache under the caller's directory,
and the fold, with four children — `mirror/base.rs` the base's check, its
refusals and the sync, `mirror/keys.rs` the credential pass that folds
`skep-identity`'s signature-filtered key table from the credential records
the feed names and reads the set that opens an account as of a position
off it, `mirror/atoms.rs` a record's bytes and the chain walk,
`mirror/cache.rs` the fetch cache's format; `verify.rs` the record grade
for registry
records, client-side; `index.rs` the ledger of the rules and the verified
prefix → binding index behind the mirror's gate; `walk.rs` the resolve,
and its child `walk/guest.rs` the guest-reading resolve that scans with no
mirror; `origin.rs` the scheme and host terms and the ordered walk's one
precedence; `state.rs` the verdict and the faces. The modules are
private: `lib.rs` re-exports the crate's whole surface, one path per name.

Rules that hold across its files:

- **The verdict decides, the registry's reads do not.** `verify::judge` is
  the one place a `sig` is judged, and the index's write side is the
  crate's own, so a dependent folds nothing into one; the guest-reading
  resolve folds into a `Ledger`, the rules alone, never into an `Index`.
  The body is parsed by `skep_registry::parse` alone — this crate derives
  no parser. The library links the verify and never the signer —
  `skep-signature` with no `sign`, which `scripts/gate-full.sh` checks by
  building the library alone.
- **Two files, two readers.** Only `feed.jsonl` is the checked image,
  every line of it written and read back in `mirror/base.rs` under its
  format stamp; `fetched.jsonl` is this mirror's own cache, its format
  written and read in `mirror/cache.rs` alone.
- **The walk reads the index and the board, nothing else.** Every hop is
  the registry board's own journal or the mirror's copy of it; no name is
  tested — the host term is met at the addresses this resolver's own
  resolution yields, through a `NameResolver` a suite can hold fixed.

Its integration suite is one binary, `tests/it/`, over a RECORDED feed
(`tests/fixtures/feed.json`, written by the daemon suite's `resolve.rs` on
demand): `index`, `mirror`, `walk` and `origin`. The paths no recording
reaches run in the unit suites, each beside the code it pins, the mirror's
suites sharing the fixtures in `mirror/testing.rs`. The end-to-end cells
and the measurements run in `crates/skepd/tests/it/resolve.rs`.

Its rules of mechanism: SP-2, SP-10, SP-17.

## The search index, `skep-search`

`skep-search` is the reader's own index of a board's text (the design's
`search.md`): R9b's "query → ranked span hits → jump to the position with
structure live — implemented client-side over the /changes feed", the
substrate itself search-free. TEXT AND ADDRESSES IN, HITS OUT — the crate
parses no wire JSON, dials nothing, holds no token, knows no principal but
as the class the embedder passes it, and reads and writes no file but
through the `Read` and `Write` the embedder hands it; the FRONTEND's shell
embeds it beside `skep-client`, and the shell's half — the feed consumer,
the directory, the triggers, the bridge call, the state event — is
`client.md` §4e's, built as `skep-client`'s `search` module behind its
default-off `search` feature (§The client). Its modules are declared in
`src/lib.rs`, each with a line saying what it holds: `unit` — the document
model, `Unit`, `UnitKey` and the typed delivery `Item`s; `token` — the
tokenizer and the `REVISION` the index records; `index` — the inverted
index with positions behind the one concrete type, `Index`, with
`CEILING_BYTES` and the one read over the unit keys, `Index::keys_by_range`
under a `Prefix`; `query` — `Query::parse`, the one grammar, and the
evaluator under its three INTERIM pins, `EXPANSION_BOUND_ENTRIES`,
`POSITIONS_BOUND` and `FUZZY_WORDS`; `rank` — BM25; `hit` — `Hit` and
`Answer`, the contract the UX designs to, with `Span`, `Standing`,
`Matched` and the `Snippet`; `pair` — `Pair`, the two indexes by role,
`QueryOpts` and `Index::query`, the one call; `header` — the file's typed
`Header` and the header line's one canonical writer and parser; `file` —
the body's layout and the CRC-32C trailer, `Index::save` and `Index::load`,
and the aside's spelling `aside_name`; `resume` — the resume read's
answers judged as a pure function, `Resume::judge`.

Rules that hold across its files:

- **Nothing of the network, the keys or the board.** The dependencies are
  `skep-address` and the two Unicode crates, and nothing else — NOT
  `skepd`, NOT `skep-client`, NOT `serde_json`: the file's one JSON line
  is written and read by the crate's own bounded code; no feature, no
  platform call, no target-specific code. The two crates' tables are one
  Unicode version, which the tokenizer revision names and a test holds.
- **The crate moves no file and reads no board.** `save` and `load` take
  the `Write` and `Read` the embedder hands them; the save's rename, the
  aside's rename and the resume's `/chain?at` and `H.k` reads are the
  shell's. The crate spells the aside's name and judges the resume as a
  pure function over values the shell hands in.
- **The embedding is the shell's, and lands in `skep-client`.** The feed
  consumer, the bridge call that composes the pair, the refreshes and the
  jump's landing are `skep-client`'s `search` module (§The client), which
  takes this crate as an optional dependency; this crate gains nothing for
  them. The crate's `README.md` says what remains outside both.

Its unit suites sit beside their code: `unit/tests.rs`, `token/tests.rs`,
`index/tests.rs`, `query/tests.rs`, `rank/tests.rs`, `hit/tests.rs`,
`pair/tests.rs`, `header/tests.rs`, `file/tests.rs` and
`resume/tests.rs`. Its integration suite is one binary, `tests/it/`:
`cases`, `grammar`, `ranking`, `hits`, `separation`, `index`, `file`,
`resume` and `budgets` (the timing tests in the `gate-full only`
partition, with `budgets/corpus.rs`, `budgets/board.rs` and
`budgets/report.rs`); each module's doc says what it holds.

Its rules of mechanism: SP-10, SP-18, SP-23.

## The client, `skep-client`

`skep-client` is what an ACTING client embeds — the `skep` command, the
frontend's shell — to claim a board, open signed sessions, keep its keys
and run the credential ceremonies; with its `acting` feature off it is the
reading half alone, which holds no signer and no key. It links no daemon
and no engine: it speaks the wire as `docs/wire.md` states it and
reproduces the daemon's grammars under their rules. Its modules, bottom-up
— `src/lib.rs`'s doc gives each top-level one a line, `src/ceremony.rs`'s
each ceremony:

- The reading half, in every build. `origin.rs` the canonical origin;
  `address.rs` the address grammar over the wire's dotted spelling;
  `hex.rs` (private) lowercase hex; `dial.rs` the one outbound `Dialer`,
  its plain-HTTP arm and, under `tls`, the `https://` arm, its unit suite
  in `dial/tests.rs`; `halt.rs` the one error family and its exit codes;
  `board.rs` the wire's endpoints over a dialer, `board/frames.rs`, which
  spells every frame the crate sends, and `board/answers.rs`, which
  decodes every read answer it reads — its unit suite in `board/tests.rs`,
  and under `cfg(test)` `board/fake.rs`, the fake board the crate's unit
  suites dial; `derive.rs` the pure derivations over board reads.
- Under `acting`. `sign.rs` the `Signer` seam and the bytes a signer signs;
  `sheet.rs` the key file's one spelling and its refusals, the byline
  `Label`, the `Seed` and the `SeedText`, its unit suite in
  `sheet/tests.rs`; `store.rs` the `FileStore` — key files, the bindings
  file, the lock — and the halts its refusals render as, its unit suite in
  `store/tests.rs`; `person.rs` the `Person` seam, and under `test-hooks`
  `person/scripted.rs`, the scripted person a suite drives;
  `derive/records.rs` the one admitted read of an account's credential
  records, its unit suite in `derive/records/tests.rs`; `verify.rs` the
  reader's verifier — `skep-identity`'s signature-filtered key table built
  over the admitted read, and the entry verdict beside it — its unit suite
  in `verify/tests.rs`; `resolve.rs` the registry walk's `Transport` over a
  dialer; `share.rs` the grant — `share`, `privash` (PUB-5.108), `revoke`,
  the reads `issued`, `held` and `privashed`, and `Ledger::fold` — its unit
  suite in `share/tests.rs` and its daemon suite in `tests/it/share.rs`.
- `ceremony.rs` and `ceremony/`, in two layers. The COMPOSITIONS, each the
  one home of its frames, reads and refusals: `handshake.rs` the session
  open, `deposit.rs` the credential write, `first_session.rs` an account's
  first signed session, `backup.rs` the backup moment, `payload.rs` the
  paste door, `preview.rs` the retirement preview, `enumerate.rs` the head
  invariant's closure and the by-reference cone, `trail.rs` the
  supersession trail, `import.rs` the anchor import, `reads.rs` R0's reads
  and the A4 cell. The WALKS over them, one gesture each: `claim.rs` the
  notebook walk, its hosted arm in `claim/hosted.rs`; `enroll.rs`;
  `recover.rs` the device arm, its loss arm in `recover/loss.rs`;
  `retire.rs`; `rotate.rs`; `handoff.rs` the giver's walk; `accept.rs`
  the recipient's beat.
- Under `search` (default off; the design's `client.md` §4e) — THE SHELL's
  HALF of search over `skep-search`, standing BESIDE the ceremonies and
  naming none: `search.rs` the module and its rules; `search/directory.rs`
  `<data>/index/<chain>/`; `search/consumer.rs` the `Consumer`, one per
  board, and `events`, the `/events` stream as the loop's input;
  `search/places.rs` the document index, a file per part beside its index;
  `search/state.rs` the state event's ten arms as a typed enum;
  `search/bridge.rs` the bridge's two calls, the search and the document
  index's listing; `search/jump.rs` the landing rule over a `compare`
  answer's pairs — its unit suite in `search/tests.rs` over a scripted
  board, its daemon suites in `tests/it/search/`.
- Under `merge` (default off) — MERGING VERSIONS, the editor's act on a
  daughter: `merge.rs` the module and the one rule; `merge/compose.rs` the
  PURE CORE, `compose_runs` over three run lists, `base_of` and `script`;
  `merge/reads.rs` the READS over a board, writing nothing;
  `merge/land.rs` the LANDING and `resume`; `merge/record.rs` the `merge`
  record kind, its currency and `verify`; `merge/journal.rs` the merge
  journal — its unit suite in `merge/tests.rs` over the record's vectors
  and a scripted board, its daemon walk in `tests/it/merge.rs`. Of the
  SURFACES the `skep merge` command is built — `skep-cli`'s
  `commands/merge.rs`, the one embedder that turns the feature on (§The
  command) — and no agent surface is.

Rules that hold across its files:

- **One dialer.** Every request the crate makes goes through a `Dialer`:
  the one a `Board` holds, or the one `resolve.rs`'s transport wraps — and
  a dialer behind a reference, a box or an `Arc` is itself one, so a
  shell's one `Arc<dyn Dialer>` serves both. Every token-bearing request
  but the close rides `Board::authed`, and every read answer is decoded by
  `board/answers.rs`.
- **One home per composition.** Every signed session opens through
  `handshake.rs`, every credential record is written by `deposit.rs`, and
  an account's first signed session runs `first_session.rs`; a walk states
  only what its site adds.
- **The ceremony is layered.** Nothing outside `ceremony/` names it;
  inside, a walk names compositions and never another walk, and a
  composition names no walk. `tests/it/tidy.rs` checks it.
- **The search half has one writer.** The `Consumer` is the one writer of
  a board's index directory — the feeder's `flock` for its life, a second
  process refused as busy.

| Feature | Default | Adds | Compiled by the gate |
|---|---|---|---|
| `acting` | on | `sign`, `sheet`, `store`, `person`, `derive::records`, `verify`, `resolve`, `ceremony`; `skep-signature`'s `sign` | every default build; `scripts/gate-full.sh` checks the library without it (the reading half) and with it alone |
| `tls` | off | the dialer's `https://` arm over rustls and the platform verifier | `skep-cli`'s default build (its dev binary `skep-dev` needs none of it — a dev board is loopback, the dialer's plain arm, for `seed` and for `serve` alike; `serve` takes `search` through `skep-shell` and, under `skep-cli`'s `dev-hooks` alone, the daemon's `test-hooks`); `scripts/gate-full.sh` checks both of `skep-cli`'s binaries without it, and the sidecar image builds `--bin skep` so the dev binary stays out of it |
| `test-hooks` | off | implies `acting`; `person::scripted` | every test build (the crate's self dev-dependency, and `skep-cli`'s dev-dependency); `scripts/gate-full.sh`'s `--features acting` check builds the library without it, and `tests/it/tidy.rs` checks its gate |
| `search` | off | implies `acting`; the `search` module and the optional `skep-search` dependency | every test build of this crate (the self dev-dependency turns it on, so the search suites run under the workspace gate); `scripts/gate-full.sh` checks the library with it alone, and `tests/it/tidy.rs` checks that `pub mod search;` is gated and the feature off by default |

Its integration suite is one binary, `tests/it/`: the walks driven through
the scripted person against a daemon spawned in-process, another hand's
acts re-driven over the wire (`common::wire_*`) and never by a ceremony;
`backup`, the moment with no daemon; `tidy`, the arrangement above and the
two feature gates; `share`; and `search/` (`consumer`, `resume`,
`directory`, `bridge`) over a claimed board whose published text the
attested shot mints. Its unit suites pin what a composition sends and what
it makes of each answer with no daemon, over `board/fake.rs`'s fake board;
the search module's over a scripted board of its own (`search/tests.rs`).

Its rules of mechanism: SP-2, SP-3, SP-7, SP-12, SP-13, SP-14, SP-16,
SP-17, SP-18, SP-20, SP-24, SP-28.

## The shell's core, `skep-shell`

`skep-shell` is the bridge of `client.md` §4b as a library — one method
per call of §4b.1, of the document index's listing `places` (A-255) and of
the change feed's page `changes`, every event of §4b.2 on one stream — and
the three things `skep-client` does not hold and every shell needs,
written once so the dev provider (`skep-dev serve`) and the desktop shell
share them and rewrite the transport alone. A transport reaches it
through the crate root — `Shell` and what opens it, `Refusal` and its
`Name`, `Log` and its `CallOutcome`, `Event`, its `EventName` and
`UnknownEventName`, `Talk`, `CALLS` — and two public modules, `script` and
`shapes`; the rest is private. Its modules, in the order `src/lib.rs`
declares them, each naming only those above it — an item the root
re-exports counted as the module it is brought from (held by
`tests/it/tidy.rs`):

- `refs.rs` the reference registry's NAMES: board and session references
  minted per process, never a credential; `BoardEntry`, one board under
  the reference minted for it.
- `log.rs` `Log`, the call and dial log the page's gate reads, and
  `ShellDialer`, the one `PlainHttp` every board dials through.
- `events.rs` `EventBus`: the seven events as values, each named by an
  `EventName`, fanned out to every subscriber in order.
- `refusal.rs` `Refusal`, the one shape the page renders, each refusal
  with ONE name from `Name`, the closed list of every name the shell spells.
- `wire.rs` the wire's shared facts: the frame cap (`MAX_FRAME_BYTES`) and
  a frame's compact bytes (`json_len`), the tumbler component budget,
  `document_address`, and the value forms both ways (`values_of`,
  `delivered_values`).
- `attest.rs` `Composer`: the entry frame for the ten kinds, every axis
  from the shell's own reads, through `skep-identity`'s builders.
- `held.rs` the HELD-BURST STORE (`client.md` §3c): one append-only file per
  (board, principal); `HeldQueue`, a principal's queue — its memory, the
  file its copy.
- `script.rs` the dev arm's SCRIPT: the grammar a script file's answers are
  parsed by.
- `dev_arm.rs` `DevArm`: the SECRET and CONSENT moments answered from a
  script or by the auto arm.
- `person.rs` `BridgePerson`: the PUBLIC moments as `moment` events, the
  SECRET and CONSENT ones and the NATIVE statements sent to the arm — or
  refused where the run names none (`ArmConfig::Refuse`).
- `sessions.rs` `Sessions`: the token beside the board it stands at, under
  its reference, the two openings, a session's END (`Sessions::end`) and
  the release of its drafts supplement (`Sessions::release`).
- `hold.rs` `Holds`: the one path of every `/op` the shell sends under a
  session (`Holds::send`) — a burst's DOOR (`Burst::admit`) and its hold
  among it — and the per-(board, principal) queue over `held.rs`'s file.
- `hold/resend.rs` THE PROBE (`Holds::probe`) and THE RESEND.
- `feed.rs` `FeedThreads` and `Feed`: per board, the `/events` reader and
  the feed thread, its state the `Feeder`; and `changes_since`, the read
  behind the `changes` call, on the caller's thread.
- `shell.rs` `Shell`: the boards, the sessions, `SessionMode`, `ArmConfig`,
  the private row methods behind `call`, which logs each; `fetch`,
  `answer`, `cancel`, `shutdown`; `ShellOptions` and `set_node_state`.
- `shell/ceremony.rs` the ten ceremonial rows — `keygen`, `fingerprint` and
  the eight walks over `skep_client::ceremony` — `pub(super)` to `call`.
- `shapes.rs` the declarations' table and `declarations()`, pinned by its
  suite.

Rules that hold across its files:

- **One door per call.** Every call reaches its row through `Shell::call`,
  which logs it; the row methods are `shell`'s alone — private, or
  `pub(super)` in `shell/ceremony.rs` — so a transport cannot serve a call
  the log never saw. `Shell::fetch` is the one public row, because it
  streams, and logs its own call. `tests/it/tidy.rs` pins `Shell`'s public
  methods across every `impl Shell` block of `shell.rs` and its non-test
  children, and `CALLS`, the list a transport admits a call by, is spelled
  from the same enum as `call`'s dispatch.
- **One path for every session write.** Every `/op` the shell sends under
  a session, `/op-at`'s aside, goes through `Holds::send`, and its first
  dial and every resend read the answer through `hold.rs`'s one reader;
  `classify` alone bounds the reissues.
- **One composer.** The attest's bodies are `skep-identity`'s builders, the
  daemon's twin, and nothing here spells a row.
- **One list of names.** Every refusal name the shell spells is a constant
  of `refusal::Name`, closed by a private field, so a name spelled anywhere
  else does not compile.

Its suites are unit modules beside the code they test. `shell/tests.rs` and
its children run the shell: `door` the shell alone, with no daemon behind
it; `modes`, `ceremonies`, `boards` and `held` against a daemon spawned
in-process over a temp data dir. `hold/tests.rs` and its children `write`
and `resend` drive the hold over a fake board; the other modules test
themselves over fakes and temp dirs; and `tests/it/tidy.rs` holds the
arrangement — the declaration order, every file under `src/` declared by
its parent's `mod` line, an inline test module as its file's last item,
the two public modules, and `Shell`'s public methods. Each suite's module
doc says what it holds.

Its rules of mechanism: SP-1, SP-2, SP-3, SP-10, SP-11, SP-15, SP-17,
SP-18, SP-19, SP-20, SP-23, SP-24.

## The command, `skep-cli`

`skep-cli` is two binaries over `skep-client` (`client.md` §1.2, §2): the
`skep` command, and beside it the dev binary `skep-dev`. The command
parses the command line, makes the library call — handing a walk the
terminal as its `Person` — and renders the answer, DATA on stdout and TALK
on stderr, with §2.3's exit code. Every ceremony is a library walk; `bind`
and `keygen` sequence the library's compositions themselves, and so carry
their own text. Its modules, in the order `src/main.rs` declares them,
each naming only those above it:

- `args.rs` `Command`, one of the fifteen, the verb `main` dispatches on;
  the grammar — one row per command and the rules its forms hold them to
  (`Form`), beside the flags every command takes (`GLOBAL`) — with `HELP`,
  the text that documents it; and `CommandLine`, one parsed command line
  (`Line<Command>`), its settings each read through `Line::setting`, the
  one place a flag beats its `SKEP_*` variable, with `session_env` the one
  setting no flag carries. Its `dev` module is the dev binary's grammar
  over the same machinery — `DevCommand`, the dev `HELP` and `DevLine`'s
  readers — kept in this file so every `SKEP_*` variable stays its own.
- `terminal.rs` `Terminal`, the `Person` over the terminal: each moment
  written once, in `moment`, against a `Screen` that says its lines and
  reads its answers; `has_terminal`, the person doors' check; `talk`, the
  one writer of a line on stderr, and `show`, each through `write_inert`,
  and `clear`, the dismissal's one escape; `Drawing`, every text it draws,
  which its `drawing` module alone makes (SP-16); and `answer`, the one
  reader every prompt goes through.
- `shared.rs` what both binaries share: DATA's writers (`data` and
  `data_verbatim`), the stops and their exit codes (`Stop`, which `finish`
  renders under a `Program`), `help`, and the plumbing from the flags to a
  board (`board_of`), a store (`store_of`), a principal
  (`principal_or_bound`) and a key (`select_key`, under `Purpose`).
- `commands.rs` what the fifteen commands share among themselves alone:
  the `skep` `Program`'s `finish` and `help`; `require_terminal`, the
  check each `Door` makes; a payload read to its cap (`read_payload`,
  `MAX_PAYLOAD_BYTES`); the anchor boxes' per-run default (`BoxDefault`);
  the three facts' one spelling (`print_facts`); `binding_said`; the
  outstanding-act line `keygen` and `fingerprint` share; and the whole-set
  compare (`held_set`, `compare_genesis`). Beneath it, `commands/<name>.rs`,
  one file per command, each the
  `pub fn <name>(&CommandLine) -> Result<(), Stop>` that `main` dispatches
  to, taking the shared names through `super::`.

The dev binary's root is `src/dev/main.rs`, declared by the manifest's
second `[[bin]]`, `skep-dev`. It declares `args`, `terminal` and `shared`
by `#[path]` from the files above — the same modules, compiled into both
targets — and then its own, in dependency order: `manifest.rs`, the
manifest beside the key store (`<store>-seed/<chain>.jsonl`); `board.rs`,
the frames over the claimant's ONE content-scoped signed session;
`seed.rs`, the run; and `serve.rs`, THE DEV PROVIDER — `skep-dev serve` —
with its modules beneath it: `serve/http.rs`, the provider's own HTTP over
the plain subset `skep-http` serves; `serve/admission.rs`, the check every
request passes before any dial; `serve/node.rs`, the daemon's two modes —
a running board dialed, or under the crate's `dev-hooks` feature the
daemon in-process with its test hooks; and `serve/routes.rs`, the routes
over `skep-shell`'s core. `skep-dev seed` dials a RUNNING board the person
started per `RUNBOOK.md` §3 and claimed with `skep claim`; it never
claims, and it takes none of `tls`, `search` or `test-hooks`. `skep-dev
serve` takes `search` through `skep-shell`, and `test-hooks` through
`skepd` under `dev-hooks` alone — the default build and the sidecar's
`--no-default-features --bin skep` build carry no `skepd`, which
`scripts/gate-full.sh`'s isolation line and `tests/it/serve.rs` hold. The
`[[bin]]` carries `test = false`: the shared modules' unit suites run
once, under `skep`, and the dev binary's own claims are its integration
fences, `tests/it/dev.rs` and `tests/it/serve.rs`.

Rules that hold across its files:

- **A prompt holds stdin for one line.** Every prompt is read through
  `answer`, which locks stdin for that line alone, and the only other
  reads are a `-` argument's, whole, in `read_payload` and
  `session --close -`. `tests/it/tidy.rs` checks it.
- **A person door checks for a terminal first.** The eight doors —
  `claim`'s notebook arm, `keygen --anchors`, `enroll` without `--reply`,
  `recover`, `retire`, `rotate`, `handoff --payload` and `accept` without
  `--reprint` — each call `require_terminal` before anything is generated;
  the check is the CLI's, never a walk's (§2.4).
- **The settings are `args.rs`'s, and every one is tabled.** Every
  `SKEP_*` variable is read there and nowhere else, and every variable the
  source reads at run time is a row of the crate's README §Settings, both
  of which `tests/it/tidy.rs` checks.
- **A command answers `Ok` or a `Stop`.** It names every stop with `?`, and
  `main` — its dispatch one arm per `Command`, which the compiler holds
  exhaustive — exits with `finish`'s rendering of it; no command picks a
  renderer or a code, nor ends the process. `tests/it/tidy.rs` checks that
  only `main` exits.
- **Imports point down.** A module names only the modules `src/main.rs`
  declares above it, and an item by its home module, never through the
  root; a command file names what the commands share through `super::`.
  `tests/it/tidy.rs` checks it, and that every file is declared.

Its integration suite is one binary, `tests/it/`: `cli` and `ceremonies`,
each driving the built `skep` through argv, stdin and stdout against a
daemon spawned in-process; `hostile`, what arrives from outside the
person's trust; `dev`, the dev binary driven against a corpus the suite
builds under the system temp dir; `serve`, the dev provider driven as the
page would drive it over loopback HTTP; and `tidy`, the arrangement above
over both roots, read off the source. `common` holds the spawn, the
canned board and the runs, every setting's variable (`VARIABLES`, the one
list `tidy` holds `src/args.rs` to) and `HOME` cleared from them by the
one `scrub` every suite's runs share; and `tree`, a directory's state, for
the commands that write nothing.

Its rules of mechanism: SP-3, SP-10, SP-11, SP-14, SP-15, SP-17, SP-18,
SP-19, SP-20, SP-25, SP-29.

## The provisioning service, `skep-provision`

`skep-provision` is one binary, the service behind a hosted board's
sign-up (the deployment notes §4, step 1): a plain program on the VM in
the `docker` group, the proxy forwarding the sign-up's domain to it. Its
`serve` verb serves two pages over the plain HTTP/1.1 subset — the
sign-up page and the claim form — judges a post in process before any
`docker` call, and provisions each admitted post on one of a pool of
workers through the host's `docker`; its `invite` verb mints one invite by
the owner's hand. Its modules, in the order `src/main.rs` declares them,
each naming only those above it:

- `scratch.rs`, for the unit suites alone, a scratch directory removed
  when dropped.
- `urlform.rs` the form's body decoded strictly, its values kept as bytes.
- `whole.rs` a kept file changed durably: replaced whole by rename from
  its `<file>.tmp` at the mode its owner names, or removed.
- `process.rs` a child process run to its end: `Exit`, what it answered,
  and `run`, which sets the child's streams.
- `wait.rs` a bounded wait: `Wait`, this many tries this far apart.
- `rates.rs` the rates a line is said at, `skepd`'s shapes: `Edge` and
  `Stretch`.
- `domain.rs` a domain, as `--suffix` takes one, and `Domain`, the one
  value a suffix is taken in as.
- `name.rs` a board's name: its grammar, and `Name::exact`, a name read
  back as this service wrote it.
- `record.rs` the record's admission: the hosted walk's trim,
  `parse_enroll`, the hosted genesis's two refusals and the anchorless fact.
- `mail_address.rs` a mail address by the rule, and `MailAddress`, the one
  value an address is taken in as.
- `invite_code.rs` an invite code and `InviteCode`, the one value a code
  is taken in as.
- `docker.rs` the `Docker` trait — `run`, the one method a runner writes,
  and one named method per call provided over it; `Call`, one call as
  data, and `Call::argv`, every call's argv as a pure function;
  `HostDocker`, the host's `docker`, run by `process::run`; and under
  `test-hooks` `docker/fake.rs`, the scripted fake.
- `sidecar.rs` the sidecar's six DATA lines and its one idempotent line,
  read, and its exit codes mapped.
- `health.rs` the pair off `/health`'s body and its wait, over a `Wait`.
- `caddy.rs` the snippet's text, its write and its removal through
  `whole` at `0644`, whether it stands, the reload, and the routed names
  read off the snippet directory.
- `names.rs` the truth about names — the snippet, the volume, the
  container — the status token, and the labelled volumes sorted against
  the snippets.
- `statedir.rs` the state directory's door and a lock file in it; the
  state files' one writer, `whole`'s replacement at `0600`; and the date
  the two files' lines carry.
- `signups.rs` the sign-up file, capped at 256 KiB.
- `invites.rs` the invite file — mint, look up, spend — under a lock file
  across processes.
- `strings.rs` the strings table: every sentence a person reads, each row
  naming its id.
- `pages.rs` the four pages' HTML and each request's dispatch over
  `skep-http`, each page asking a `Desk`; the two URLs the service hands
  out; and `Accepts` and `Serving`, the accept pair and the pool pair the
  connection threads share.
- `sender.rs` the `Sender` trait, `RelaySender` and the outbox on the
  sender's own thread; `Log` and `Sleep`, the log and the sleep every
  thread of the service is handed — kept here as the first module that
  takes them; under `test-hooks` `sender/fake.rs`.
- `reply.rs` the live reply, one function for the page and the mail.
- `flow.rs` the `Service` — the `Desk` the pages ask, the `Book` of what
  is in flight and of every post's state with its status map
  (`flow/status_map.rs`), the workers' steps, the route lock, the cleanup
  table and the sweep at start.
- `args.rs` the verbs and the flags, every default a named constant, the
  build and `version_line`, the settings the start says, and the usage
  text.

Rules that hold across its files:

- **The command line is the one home of every setting.** The service
  reads no environment variable for one, so the unit's `ExecStart=` holds
  them all; every default is a named constant the usage text renders, and
  the crate's README's flag table is read back against the usage.
  `tests/it/tidy.rs` checks that no file under `src/` reads an
  environment variable but `PATH`.
- **One writer, one runner, one wait.** Every file it keeps is replaced
  whole by rename, or removed, through `whole`, at the mode its owner
  names — the state files `0600`, the snippets `0644`. Every program of
  the host's it runs — `docker` and the mailer — runs through
  `process::run`. Every try it makes again — the `/health` read, the dark
  claim, the mail — is paced by a `Wait`.
- **Every person-facing sentence is in one table**, `strings.rs`, each
  row naming its id, and the live reply is one function, so the page and
  the mail cannot say two things.
- **Imports point down.** A module — its fakes and its suite too — names
  only the modules `src/main.rs` declares above it, and an item by its
  home module, never through the root; and the crate depends on
  `getrandom`, `serde_json`, `skep-http`, `skep-identity` and
  `skep-signature` — its verify alone, no `sign` — and nothing else.
  `tests/it/tidy.rs` checks both, and that every file is declared;
  `scripts/gate-full.sh` checks that the shipped build links no signer.
- **Every `pub` item says what it is.** `#![deny(missing_docs)]` reaches
  only what a crate exports, and a binary exports nothing, so
  `tests/it/tidy.rs` holds every file under `src/` to its `//!` doc and
  every `pub` item and field to its `///` line.

Its integration suite is one binary, `tests/it/`, driving the built
`skep-provision` under `test-hooks` over the two fakes and a temp state
directory; its module doc lists its claims. Beside it, `tests/it/tidy.rs`
reads the arrangement off the source and the manifest: the module order,
the declared files, every `pub` item's doc, the five dependencies, and the
one environment variable read, `PATH`.

Its rules of mechanism: SP-2, SP-7, SP-8, SP-11, SP-15, SP-17, SP-18,
SP-25, SP-28.

## The name space, `skep-namespace`

`skep-namespace` is the one minting authority. Every address a transaction
creates — account, document, version, content, link — comes off one of its
mints, and every store that mints or writes under a chain
(`skep-arrangement`, which places content and forks versions, and
`skep-links`) holds a lock key M3 built. It also holds who exists, who
owns what (ω, the longest seated prefix), each document's publication
bit, and the commit position of every document, member and link it
minted — the position map — all in one slice, `M3State`. Node addresses
come from provisioning and are only admitted. Its modules are declared in
`src/lib.rs` in dependency order, each with a line saying what it holds.
`record.rs` is the journal delta, `M3Rec`, with its field doors and the
identity type it names; `state.rs` is the slice — `M3State`, genesis, the
fold and the frontier arithmetic; beneath it, `state/mint.rs` holds the
lock keys, the mints (§A) and the two peeks, kept beside the mints they
call so the two files depend one way, and `state/query.rs` every other
query (§C). Its `test-hooks` feature (default off) compiles in `M3Rec`'s
test constructors, the one way another crate's suite constructs a record
without decoding one; `scripts/gate-full.sh` runs its doctests — the
`compile_fail` pairs on `M3Rec` that pin the seals a foreign crate meets.

Rules that hold across its files:

- **A namespace has one spelling.** `NsKey`'s fields are private to
  `src/ns.rs`, so every frontier key, and every chain lock key encoded from
  one, is built there. The two registry keys are M3's own, crate-private.
- **Only this crate constructs a record.** `M3Rec` and `RegisterNode` are
  `#[non_exhaustive]`, as `M5Rec`'s and `LinkRec`'s variants are, and the
  payloads of `Allocate` and `RegisterPrincipal` keep their fields
  private, so no other crate builds a record of its own choosing except by
  decoding bytes, and none edits one past its doors.
- **The slice's shape is its format.** `M3State`'s fields, `M3Rec`'s
  variants and the fields of `Allocation` and `Principal` are appended,
  never inserted or reordered; `tests/it/genesis.rs` pins genesis's bytes
  field by field, and `tests/it/recovery.rs` each variant's against a raw
  struct-variant twin.

Its integration suite is one binary, `tests/it/`: one file per surface over
the shared `common` world, and `heap`, the binary's byte-counting
allocator.

Its rules of mechanism: SP-21, SP-28.

## The arrangement, `skep-arrangement`

`skep-arrangement` owns what a document holds: per document a content and a
link run-list (its arrangement), the provenance relation R (every content
address a document has ever held), and three per-member facts — the birth
extent, the shot terms and the fork source — all in one slice, `M5State`.
It is the one place in the workspace where state is destroyed: `delete`
removes positions and `rearrange` reorders them, in place, and R keeps
every address a delete removed. Its modules are declared in `src/lib.rs`
in dependency order, each with a line saying what it holds; each names in
code only the modules above it. `tests/it/tidy.rs` checks that, that every
declaration under `src/` but a `tests` module carries its line, and that
every file under `src/` and `tests/it/` is declared. `run.rs` is the run;
beside it, `run_union.rs` holds the union of a run set's I-extents, in
tumbler order, and `run_list.rs` the run-list, in V-order — two modules
that share no private item. `ops.rs` is the `Vstream` handle and what its
operations share; beneath it, `ops/insert.rs`, `ops/publish.rs`,
`ops/copy.rs`, `ops/reinstate.rs`, `ops/delete.rs`, `ops/rearrange.rs` and
`ops/version.rs` each hold one operation's `impl` block. Its `test-hooks`
feature (default off) compiles in `seat_link`, the test-only twin of the
link seat; `scripts/gate-full.sh` checks the library and its docs without
it, and runs its doctests — the `compile_fail` pairs on `Run` and `M5Rec`
that pin the seals a foreign crate meets.

Rules that hold across its files:

- **One fold.** A committed `M5State` comes only from `apply_m5` over an
  `M5Rec`, and inside this crate only `state.rs` builds one: three of its
  five fields are private there, the arrangement map among them, so every
  other module reaches an arrangement through `state.rs`'s `arrangement_of`
  and the absent-⇒-empty convention it applies. The fold reaches one the
  same way and calls nothing defined in `reads.rs` or `shot.rs`, the other
  two files holding `M5State`'s methods, so an edit to a read or to the
  address form cannot change what replay folds; `tests/it/tidy.rs` checks it.
- **One door for a run.** `Run::new` admits every run not built in this
  crate — the serde shadow and the `LinkSeat` fold go through it — and
  every in-crate literal starts at an address that already is a full
  element position; `Run::admits_start` lists those literals.
  `run_list::extend_or_push_run` is the one place a built run is widened
  and the one place a placement's runs are accumulated.
- **One allocation step.** Every fresh content address is minted and
  written by `ops::allocate_for_placement` or, for a run of single-byte
  values, `ops::allocate_stretch_for_placement`, inside the transaction
  whose placement record places it.
- **The version chain is asked, never spelled.** Every trunk, head,
  publication and surface question in this crate goes through `chain.rs`,
  the one reader of M3's version frontier; the floating readers of
  `skep-retrieval` and `skep-discovery` ask its `reading_surface` rather
  than float by hand.
- **One ownership gate.** Every gated op opens with `ownership::gate_write`:
  registration, then the ω gate. A door ahead of the store asks the same two
  questions through `Caller::passes_ownership_gate`.
- **The slice's shape is its format.** `M5State`'s fields and `M5Rec`'s
  variants are appended, never inserted or reordered. Three checks pin it,
  none alone: `skep-kernel`'s goldens pin the bytes of the records their
  ops reach, `state/tests.rs` pins the shot's record, and `skep-engine`'s
  format-count test pins the slice's field order.

Its integration suite is one binary, `tests/it/`: one file per surface over
the shared `common` world, and `tidy`, which checks the module tree, its
order and the first rule.

Its rules of mechanism: SP-21, SP-28, SP-29.

## The link store, `skep-links`

`skep-links` owns the links: one slice, `LinkState` — the append-only map
from a link's address to its value, and the hints folded from it — and one
writer, `LinkWriter`, whose every deposit passes one gate. The type
registry is a compiled constant, not state: the five shipped classes over
the ghost tumblers `skep-namespace` reserves, built once per process.

Its modules are declared in `src/lib.rs` in dependency order, each with a
line saying what it holds; each names in code only the modules above it,
and an item by its home module, never through the root's re-exports.
`tests/it/tidy.rs` checks that, and that every file under `src/` and
`tests/it/` is declared. `state.rs` is the slice and the fold; beneath it,
`state/reads.rs` holds the read surface and `state/spanfilade.rs` the
coverage index `stab` answers from. `writes.rs` is the handle and what
its ops share; beneath it, `writes/makelink.rs`, `writes/emit.rs`,
`writes/nullify.rs` and `writes/supersession.rs` each hold one op family's
`impl` block.

Rules that hold across its files:

- **One door to the mint.** `emit_core`, in `writes.rs`, stages every
  deposit, and it is the crate's one caller of M3's `mint_link`.
  `tests/it/tidy.rs` checks the last.
- **One insertion point, one fold.** The map and the hints are private to
  `state.rs` and its children; `apply_link` is the one insertion, and it
  and `rebuild_derived` fold through the one `fold_hints`.
- **Type identity is a class.** Every comparison of types goes through
  `coverage_class` of a slot, never an `Endset`'s derived equality, and
  `class.rs` is the one place a `CoverageClass` is built.
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
that need no kernel; `recovery`, the hints a checkpoint must rebuild;
`spanfilade`, the coverage index against a scan of the store; `heap`, the
binary's byte-counting allocator; and `tidy`, which checks the module map
and the first rule.

Its rules of mechanism: SP-21, SP-29.

## The content queries, `skep-retrieval`

`skep-retrieval` holds the seven queries the code map lists, and owns
nothing: no slice, no journal record, no fold, no index. Each is a method
on `Query`, which borrows the one `&Snapshot` its caller pins and holds
nothing else — no `Kernel` — so nothing here writes. The queries compose
`skep-namespace`'s registry, `skep-arrangement`'s reading surface,
resolutions and provenance reads, and, for RETRIEVEV alone,
`skep-content`'s values; two of them take the caller's reader predicate at
a door of their own. `skep-febe`'s dispatch is the one production caller;
`skepd`'s codec and the conformance harness name the request and answer
types.

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
- **The budgets are `budget.rs`'s.** Every count goes through `budget.rs`'s
  `Count`, so no producer spells a boundary itself, and `error.rs` renders
  them; every query that resolves a span pulls `skep-arrangement`'s lazy
  `iter_resolve`. `tests/it/tidy.rs` refuses any other file's code line
  that names a budget beside a comparison, and any file the eager twins —
  `resolve`, `project`.

Its integration suite is one binary, `tests/it/`: one file per query
surface over the shared `common` world — `retrieve`, `extent`, `origin`,
`deletions`, `compare` with its refusals in `compare_refusals`, and
`find`; `query`, `head_float`, `traits` and `walk_budget`, what crosses the
queries; and `tidy`, which checks the module map, the first rule and the
third.

Its rules of mechanism: SP-22, SP-23, SP-24, SP-29.

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
  there goes through its `home_of` and `home_readable`. `tests/it/tidy.rs`
  checks it.
- **`_on` marks a snapshot.** A function under `src/` ends its name in `_on`
  exactly when its first parameter is the `&Snapshot` it reads; a helper
  over one store carries no suffix. `tests/it/tidy.rs` checks it.
- **A read's cost is part of its interface, outside the crate too.**
  `skepd`'s class-scan pool decides on the crate doc's `## Cost` section
  which of these reads to bound. It links the section by its anchor,
  `skep_discovery#cost`, and restates on its own card — `is_class_scan`, in
  `crates/skepd/src/server/scan.rs` — what each read walks. A change to
  what a read walks, or a new read, changes that section and that card in
  the same commit; `tests/it/tidy.rs` checks the section's heading and
  that it names every read the crate publishes.
- **The link store's overlap is restated here.** `skep-links` keeps its
  per-link overlap private, and `addressably_discoverable_from_on` restates
  it over spans' bounds as `SpanBounds::overlaps`, in `src/pointwise.rs`;
  a change to the link store's overlap changes `SpanBounds::overlaps` in
  the same commit.
- **The arrangement's DELETE admission is restated here.**
  `skep-arrangement` keeps private the two tests its DELETE admits a range
  by, and `delete_orphans_on` restates them as one bounds check in
  `DeletePartition::of`, in `src/survival.rs`; a change to DELETE's
  admission changes `DeletePartition::of` in the same commit.

Its integration suite is one binary, `tests/it/`: one file per part of the
read surface over the shared `common` world; `heap`, the binary's
byte-counting allocator; `home_rule`, `head_float` and `consumer`, the laws
that cross them; and `tidy`, which holds every check that reads the crate's
own source: the module map, the first two rules, and the `## Cost` section's
heading and its naming of every read.

Its rules of mechanism: SP-22, SP-23, SP-29.

## The operation surface, `skep-febe`

`skep-febe` is the front door every client operation passes through.
`OperationSurface::execute` takes a parsed request and the caller's
session, hands the operation to the store or query module that owns it,
and answers only after that module returns. It holds no journaled state.
Its one authoritative fact is which principal each session speaks for,
kept for the uptime; its retry memo is a hint. It names no concrete
`World`: what it requires of the engine — the world it reads and the
factory it writes through — is its `world` module, which `skep-engine`
implements.

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
  `visible_to`, the visibility class a write lends its store.
  `tests/it/tidy.rs` checks that only `operation/door.rs` asks the world's
  own `ReadableWorld::readable`.
- **The write path's lowering is a door.** `lower_txn` is public: it is
  the door a caller that drives a store itself — the daemon's head writer —
  lowers its `TxnError` through, so its refusal is the classified rejection
  the front door would have answered.

Its integration suite is one binary, `tests/it/`: one file per topic over
the shared `common` world; `reexports`, which checks from outside the crate
that a request is built and a response read through `skep_febe` alone; and
`tidy`, the module order and the check the first rule names.

Its rules of mechanism: SP-19, SP-22, SP-24, SP-29.

## The media resource, `skep-media`

`skep-media` holds every decision the daemon makes about a media cell — a
picture is a document whose content is ONE REFERENCE CELL — in a crate of
its own beside the daemon's write path: the cell's one parser, the media
door the plain write sequence takes, the gate over `skep-blobs`, the cell
index, the pruner's pass and the fetch's composed order. It is GENERIC
OVER THE WORLD M10 reads (`skep_febe::FebeWorld`, the one bound) and names
no engine: the daemon instantiates its world-reading signatures at its
`World`, and the door's read predicate is `ReadableWorld::readable`'s, the
seam M10 reaches the engine's own through. It transports nothing and takes
no lock of its caller's: the routes, the replies, the deposit read and the
operator's tools are `skepd`'s, and the pruner's exclusive arm is handed
in. Its modules are declared in `src/lib.rs`, each with a line saying what
it holds, and the crate doc there is the tree's charter; its public
surface is its `README.md`'s list, which `tests/it/tidy.rs` holds every
`pub` item to.

`lib.rs` declares the modules and holds `MediaOptions`, the upload setting
the daemon's routes read and `/health` echoes; it names no module in code,
so nothing of the root sits outside the two layers below. `pools.rs` — THE
TWO PERMIT POOLS, the fetch pool and its twin the upload pool. `door.rs` —
THE MEDIA DOOR, the one step the plain write sequence takes between its
admission and the commit for a value naming a media kind, which reads the
op's values off the locked snapshot, through M5's and M4's public reads
and the `ReadableWorld` seam, and the index, the lease and the file
through the gate. `gate.rs` — THE GATE: the blob store opened under
`blobs/` in the data dir — `STORE_DIR`, the one spelling of that
directory's name, which the gate's and the pruner's lines and the daemon's
two tools read — the limits in force, the hold a stream has on its upload,
the three scopes, the floor in force, the deposit's terms and the
inventory's two reads. `index.rs` — THE CELL INDEX: per hash the cells
naming it, per account the base; entered by the daemon's write path at
every commit that mints a cell and rebuilt whole at every open on a
thread. `pruner.rs` — THE PRUNER, one per daemon beside its gate, and its
PASS, under an exclusive arm the caller hands in. `serve.rs` — THE FETCH's
composed order, what the daemon's `server/blob_routes.rs` runs for `GET
/blob?i=` and its transport streams. Beneath them, the leaves: `limits.rs`
— the resource's numbers, each `pub` where another crate reads it;
`cell.rs` — the picture's reference cell: its schema, its one parser under
the canonical rule, its encoder, its designation and THE ONE
CLASSIFICATION of every media kind — with its child `cell/blind.rs`, the
blind document's cell, the second kind, read through that classification
alone.

Its modules form two layers, which `tests/it/tidy.rs` checks as the
daemon's six are checked: THE RESOURCE — `door`, `gate`, `index`, `pools`,
`pruner` and `serve`, which name one another sideways and the leaves below
— over THE LEAVES, `cell` (its child `cell::blind` among it) and `limits`,
which name nothing of the resource.

Rules that hold across its files:

- **Generic over the world; no engine.** Every signature that reads the
  world takes `W: FebeWorld` — the index's entries and walk over
  `Snapshot<W>` and `Kernel<W>`, the fetch's gate over
  `OperationSurface<W>`, the door over `&W` — and the crate's
  `[dependencies]` name no `skep-engine`. Two unit suites open an engine,
  through a dev-dependency: the door's (`door/tests.rs`) and the index's
  walk catch (`index.rs`).
- **The store knows no policy.** `skep-blobs` is handed a root and
  principals as opaque strings; who a principal is, what bounds its bytes,
  the interval an upload and a lease are given and the function a deposit
  is hashed under are the gate's (`gate.rs`), and which lock a finish runs
  under is the daemon's — never the store's. The gate's key for a
  principal is its own spelling: the routes drive the store by it, and the
  inventory reads it back through the gate's two reads, never by a second
  spelling.
- **The door is the one media step.** `door.rs` is the one place the daemon
  acts on the cell's parse: no producer of the session layer's admission
  reads a value's bytes for the cell, and no route serves one.
- **The surface is the daemon's need.** Every `pub` item is one the
  daemon takes, listed in `README.md`, or a hook, `#[doc(hidden)]` under
  `test-hooks`; the parsers, the binding and the gate's rules stay the
  crate's own. `tests/it/tidy.rs` checks it.

Its unit suites sit beside their code: `cell/tests.rs`, `door/tests.rs`
(which opens a real engine), `gate/tests.rs`, and the inline suites of
`cell/blind.rs`, `index.rs` (whose walk-catch test opens one too),
`pools.rs`, `pruner.rs` and `serve.rs`. Its integration suites — the
upload, the fetch, the door and the pruner over a served daemon — are
`skepd`'s (`tests/it`: `blob_routes`, `blob_fetch`, `media`, `pruner`,
`deposit_class`, and `hazard`'s media share), which spawn the daemon they
drive; its own `tests/it/` is `tidy` alone.

Its rules of mechanism: SP-9, SP-11, SP-14, SP-18, SP-22, SP-25, SP-26,
SP-27, SP-28.

## The daemon's core, `skep-core`

`skep-core` holds what the daemon decides about a request between the
socket and the engine, in a crate of its own below `skepd`: who may act on
a board (the session layer), what every write rides and leaves behind (the
commits: the one door, the record, the feed, the published head) and the
wire's JSON grammar (the codec) — the collaborators the daemon composes
behind its router. It transports nothing: the routes, the replies, the
history service, the operator's tools and the process are `skepd`'s. It
depends on the engine — the daemon's two crates are what the Engine
Composition Contract permits, the as-built list kept once in
`skep-engine`'s crate doc — reading the one concrete `World` and driving
the kernel and the stores through `Engine`; and on `skep-media` for the
cell index the commits enter at every commit that mints a cell. Its
modules are declared in `src/lib.rs`, each with a line saying what it
holds; its public surface is its `README.md`'s list, which
`tests/it/tidy.rs` holds every `pub` item to.

Its modules form three layers. A module names only modules in its own
layer or below it, never above; `crates/skep-core/tests/it/tidy.rs` checks
it:

1. **The session layer** — `auth.rs` and the modules under `auth/`.
   Sessions and the signed handshake (`auth/session.rs`), the policy checks
   on every write (`auth/policy/`: the plain sequence's admission in
   `auth/policy/plain.rs`, the credential sequence's precheck with the
   record grade in `auth/policy/credential.rs`, the registry sequence's
   admission and the seeding check the daemon's open runs ahead of every
   genesis in `auth/policy/registry.rs`, the write-path check — the entry
   signature — in `auth/policy/attestation.rs`, over the frame
   `auth/entry.rs` composes, and beside them `auth/policy/upload.rs`, the
   session layer's gate on who may take bytes into the blob store at all),
   the readers of the World's identity slice, signature verification —
   `skep-signature` is the one crate that links the signature libraries;
   the core calls its verify — and the configuration: the
   options and the mode (`auth/options.rs`), the two origin sets
   (`auth/origin.rs`), the node prefix (`auth/prefix.rs`), the
   blocked-prefix list (`auth/blocked.rs`), the credential write lock
   (`auth/lock.rs`), the credential memo (`auth/memo.rs`) and the entropy
   the handshake mints from (`auth/entropy.rs`). It names the commits for
   one thing: the board term, `H.1`'s pair, read off the published head.
2. **The commits** — `commits.rs`. The single point every write passes
   through, one at a time, and the head writer (`commits/head.rs`, which
   commits through the commits' own door), the link-type registry's seed
   (`commits/registry.rs`, which writes through the head writer's helpers
   and the one staging draft they share) and the time writer
   (`commits/time.rs`, which writes through the same helpers and the same
   staging draft). The head writer, the seed and the time writer are the
   only writers under the system account, and the staging draft
   `1.1.0.1.0.3` and the time document `1.1.0.1.0.4` the two documents any
   of them mints. Beneath them, and reachable only from them:
   - `commits/feed.rs` — the change feed over its six files, with
     `commits/feed/window.rs`, the one on-disk read by position below the
     resident window; beneath it, `commits/feed/derived.rs` keeps the
     feed's derived index files, and `commits/feed/attest.rs` the attest
     store;
   - `commits/sidecar.rs` — `commits.log`, the daemon's record of what it
     committed, for whom, and whether the entry was signed;
   - `commits/classify.rs` — which documents a commit touched, and which
     of its op's terms the journal can name for a bare position — the one
     place the feed asks the world anything.

   The cell index is `skep-media`'s (§The media resource), entered by
   `commits.rs`'s `record` at every commit that mints a cell — a sideways
   step at this layer into the crate below.
3. **The leaves** — `codec.rs` with `codec/marshal.rs` (the JSON wire
   format: parse, and marshal — its key-sorting `obj` and the lowercase
   hex pair are `skep-util`'s, taken as every other file takes them),
   `serial.rs` (the write-serialization lock and its guard) and
   `limits.rs` (the bounds the core reads, each `pub` for its reader; the
   daemon's own are `skepd`'s `limits.rs`, the media resource's numbers
   `skep_media::limits`'s). None of these knows anything of the session
   layer or the commits; a leaf imports only leaves — and a leaf in
   another crate is a leaf: `skep-util`'s `permits`, `notice` and `json`.

Rules that hold across its files:

- **One door for commits.** Every write to the world goes through
  `commits`, one at a time. Only the commits record to the feed and to
  `commits.log`.
- **The key table is the World's.** The identity slice — every account's
  key set and the board's claim — lives in `World`, stepped by the engine
  at each credential deposit's commit and checkpointed with the world
  (AUTH-2.79–2.88). Nothing rebuilds it from the deposits: the fold's
  verdicts depend on the order the deposits committed in, and the journal
  is the one record of that order.
- **The guard names the lock.** A function whose contract is "under the
  serialization lock" takes the guard, `SerialGuard`, in its arguments
  (`serial.rs`): the commits' door and the head writer's turn hold it by
  type, as `LockWrite` names the credential lock's exclusive arm — so a
  caller that lacks the lock cannot spell the call.
- **The surface is the daemon's need.** Every `pub` item is one the
  daemon takes, listed in `README.md`, or a hook, `#[doc(hidden)]` under
  `test-hooks`; the producers, the feed's files and the head writer stay
  the crate's own. `tests/it/tidy.rs` checks it.

Its unit suites sit beside their code: `auth/blocked/tests.rs`,
`auth/session/tests.rs` (which opens a real engine), the inline suites of
`auth/policy/*`, `commits/tests.rs` (which opens one too),
`commits/sidecar/tests.rs`, `commits/feed/derived/tests.rs`,
`commits/feed/window/tests.rs` and `codec/tests.rs`. Its integration
suites — the session layer, the commits and the head over a served daemon
— are `skepd`'s (`tests/it`), which spawn the daemon they drive; its own
`tests/it/` is `codec_roundtrip`, the wire grammar's round trips, and
`tidy`.

Its rules of mechanism: SP-1, SP-2, SP-3, SP-5, SP-8, SP-9, SP-11, SP-12,
SP-13, SP-17, SP-19, SP-24, SP-25, SP-26, SP-28.

## The daemon, `skepd`

`skepd` owns three decisions of its own, two of them its core's code
(`skep-core`'s session layer and head writer, run by this daemon): the
session layer's gates (who may act, and what a credential write may do),
the cadence of the published head, and the media door (`skep-media`'s
step, which the daemon's plain write sequence runs) — with, behind the
door, the cell index the base and the pruner read, and the pruner's pass.
It also SERVES media bytes: `GET /blob?i=` reads a picture's whole file by
the I-address of its cell. And it carries the operator's two tools over a
board directory, the inventory and the pull, run with no server.
Everything else it delegates to the stores through the engine, and the
media bytes to `skep-media` and, through its gate, `skep-blobs`. Its
listener binds the address `--bind` (`SKEPD_BIND`) names — `127.0.0.1` by
default, the container's address in the hosted image — and the peer rule
reads the socket, never the bind, so the flag widens who can connect and
nothing of who may act.

Its modules form four layers, and below them its core's three (§The
daemon's core). A module names only modules in its own layer or below it,
never above; `crates/skepd/tests/it/tidy.rs` checks it. A write passes
down through them in this order:

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
│                    deferred trigger serviced, and after │
│                    any landing — its own or a           │
│                    backstop's — the byte bound and the  │
│                    floor re-read off the newest base,   │
│                    the feed's figures, each landing and │
│                    each failure said, and once an hour  │
│                    the standing line while a bad state  │
│                    stands · a replace's deferred unlink │
│                    after the reply, under its own catch │
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
│ 4 LEAVES           history · limits (the daemon's seven)│
│   SKEP-CORE        the daemon's core, a crate of its    │
│                    own below: the session layer · the   │
│                    commits (the door, the feed, the     │
│                    head) · the codec · the bounds · the │
│                    lock (§The daemon's core)            │
│   SKEP-MEDIA       the media resource, a crate of its   │
│                    own beside the commits: the media    │
│                    door · the gate over skep-blobs ·    │
│                    the cell index · the pruner's pass · │
│                    the fetch's composed order · the     │
│                    upload setting and the upload pool   │
│                    (§The media resource)                │
│   SKEP-UTIL        permits · notice · json — the support│
│                    crate below, shared with both        │
└─────────────────────────────────────────────────────────┘
       │
       ▼
  skep-core    →  the session layer, the commits, the codec
                  →  skep-engine, skep-media
  skep-engine  →  the stores  →  skep-kernel (journal)
  skep-media   →  the door, the gate, the index, the pruner, the fetch
                  →  skep-blobs, and the stores through the world it is handed
  skep-blobs   →  blobs/ (the files, partials, records, leases)
  skep-util    →  the permit pool, the notice line, the JSON helpers

  Imports point DOWN or sideways within a layer. Never up.
```

A read skips the write path: a read route goes from the routes to
`history` and the engine. The engine sits below the daemon and knows
nothing of it. A blob upload skips the write path too: the blob route
goes from the routes to the media resource (`skep-media`) and
`skep-blobs`, under a permit of the upload pool held for the body's whole
stream, commits nothing to the journal, and takes no `Serial`. THE BLOB
FETCH (`GET /blob?i=`) skips it the same way: the route resolves the
caller, runs the serve's composed order, and hands the transport a file
to stream. The cell index is entered by the write path at every commit
that mints a cell and read by the media resource; the pruner's pass runs
from the routes under the session layer's lock, on the transport's
cadence. THE OPEN (`server.rs`, `Daemon::open_configured` and the two
doors above it) says its report on the operator stream before anything
is served, its first line the version line. THE TOOLS (`tools.rs`, beside
the routes) run no server at all: the inventory opens the journal through
the engine's open, walks the world into a fresh cell index through the
media resource's walk and reads the store's inspection; the pull reads
the same index or the hash the operator hands it, and writes one file
through the store's install — nothing above their own layer.

1. **The transport** — `server/listen.rs` (sockets — the listener bound
   BEFORE the open, `bind` then `serve_bound`, `serve` the two in
   sequence; the worker threads, their default count and the minimum, one
   more than the five permit pools' slots together; the event streams'
   loop and budget; the pruner's cadence thread; THE CHECKPOINT THREAD,
   the kernel's deferred trigger serviced off the write path's guard; and,
   after a blob reply is written, the replaced file's deferred unlink) and
   `server/http.rs` (the HTTP bytes: the request reader, the reply writer,
   the event framing — and the streaming arm, a `BodySource` over the
   connection's socket the router's private door takes by value). It
   hands each request to the router and knows nothing of what a request
   means. Beside them, at their layer, `server/embed.rs` — THE EMBEDDING
   HELPER, the start a program that is not `skepd` takes to run the daemon
   in its own process: `embed`, the bind, the open and the serve in the
   binary's order, every refusal answered naming its step (`EmbedError`);
   and `Skepd::wait_for_the_index`, the wait for the cell index's walk at
   open on `Daemon::index_is_ready`, the production read. Feature-free:
   the suites' seeded start beside it is a test hook. The binary keeps its
   own sequence — the panic hook, the loose-directory refusal, its exit
   codes — and calls neither.
2. **The routes** — `server.rs` (`Daemon` and the router) and the handler
   files beneath it, each an `impl Daemon` block: `server/actor.rs` (who
   the caller is), `server/session_routes.rs`, `server/read_routes.rs`,
   `server/op.rs`, `server/blob_routes.rs` (the PUT: the path family
   `/blob/upload`, the readiness refusal of the index's three readers,
   the five methods, the pruner's pass as the daemon runs it; and THE
   FETCH `/blob?i=`, beside the family, with its query, its mid-stream
   re-check and its clock), and — in `test-hooks` builds only —
   `server/hooks.rs`. `/op` runs one of the three write sequences — the
   plain (AUTH-3.35), the credential (AUTH-3.37) or the registry (the
   record grade for registry records), chosen off the op's own type slot
   before any lock is taken: take a permit of the write pool, resolve the
   caller, run the checks, commit, record, then give the head writer its
   turn. `/blob/upload` resolves the caller, admits the creation and the
   resume under a permit of the upload pool, gates the declared total,
   streams the body one chunk at a time into the store, each chunk gated,
   and finishes under the credential lock's read arm — never under
   `Serial`. The router takes the streaming body out of the request's
   slot at the head of every routing. `/blob?i=` (with `HEAD`) resolves
   the caller and runs the serve's composed order; an admitted answer is
   a file the accept loop streams. Beside the routes, `tools.rs` — THE
   OPERATOR's TOOLS: the inventory over a stopped board or a copy,
   recording no read and writing nothing under `blobs/`; the pull, a file
   a committed cell names restored by the store's install, no lease and
   no record; the two subcommands `main.rs` parses as a leading verb; and
   `board_stands`, the kernel's own answer whether a journal stands in a
   directory, which the binary asks before it begins a board under
   `--create` and refuses to begin one without.
3. **The daemon's vocabulary** — `server/reply.rs` (the reply and every
   transport refusal), `server/request.rs` (the request, the streaming
   body's source and the slot it rides in, and the rules the request's
   headers and query obey), `server/scan.rs` (the class-scan pool): what
   the routes and the transport both speak.
4. **The leaves** — `history.rs` (reading the world at an earlier
   position) and `limits.rs` (the daemon's own bounds; the ones the core
   reads are `skep_core::limits`'s, and the media resource's own numbers
   `skep-media`'s `limits`, the daemon taking the ones it reads from
   there, each `pub` for it). Neither knows anything about the daemon; a
   leaf imports only leaves — and a leaf in another crate is a leaf: the
   counting permit the five bounded pools use and the operator's log line
   are `skep-util`'s `permits` and `notice`, the support crate below this
   one (§The support crate); the codec and the serialization lock are
   `skep-core`'s, and the two cells `skep-media`'s.

Below the daemon's four layers, its core and its media resource, two
crates the daemon composes with:

- **The session layer** is `skep-core`'s `auth` (§The daemon's core):
  sessions and the signed handshake, the policy checks on every write,
  the readers of the World's identity slice and the signature
  verification. `AuthState` is a field of `Daemon`, opened by `server.rs`
  over the recovered world from the `AuthStart` the open read first — the
  options, and the blocked-prefix list they name, read before the open
  touches the data directory; the routes resolve the caller through it
  and run its checks.
- **The write path** is `skep-core`'s `commits` (§The daemon's core): the
  one door every write passes through, one at a time, the head writer
  behind it, the change feed and its files, the attest store. `Commits`
  is a field of `Daemon`, opened by `server.rs` ahead of the routes and
  driven by `op.rs` — resolve, check, commit, record, then the head
  writer's turn — under the guard `serial_lock` answers; its checkpoint
  signal is what the transport's checkpoint thread waits on.
- **The media resource** is `skep-media`'s (§The media resource), beside
  the commits: the media door, the one step the plain write sequence
  takes between its admission and the commit for a value naming a media
  kind, which reads the index, the lease and the file through the gate —
  why it is a step of its own and never a producer of the session layer's
  admission; the gate the PUT's routes reach as `op.rs` reaches the
  commits; the cell index, entered by the commits' `record` at every
  commit that mints a cell and read by the resource; the pruner's pass,
  run from the routes under the credential lock's write arm; and the
  fetch's composed order, which `server/blob_routes.rs` runs for `GET
  /blob?i=` and the transport streams. The daemon instantiates the crate
  at its `World` and composes with it: `MediaOptions`, the upload setting
  with the source it was set from, rides `Daemon::open_configured`; the
  deposit read is a route helper of `server/blob_routes.rs` over the
  gate's reads; the floor is sized at the open and re-read by the
  checkpoint thread after any landing; and the upload and fetch pools are
  counted into the worker minimum beside the three pools of the daemon's
  own — the reconstruction budget, the class-scan pool and the write pool.

`lib.rs` declares the daemon's modules in layer order, then the fuzz
harness and the crate's public surface; `main.rs` is the binary — the
daemon's flags, and the two tools' lines, a leading verb parsed before any
flag; the process's panic hook, installed first; its own lines, the
refusals before each exit and the serving line on stdout; and the order
bind, open, serve, then `wait`. `fuzz_support.rs` (in `test-hooks` builds
only) serves the fuzz targets and the tests: it stands above the
transport, and nothing in the daemon imports it.

Its rules of mechanism: SP-4, SP-5, SP-7, SP-8, SP-9, SP-10, SP-11, SP-12,
SP-13, SP-14, SP-15, SP-17, SP-19, SP-23, SP-24, SP-25, SP-26, SP-27,
SP-28.

### Features

| Feature | Default | Adds | Compiled by the gate |
|---|---|---|---|
| `observe` | on | `GET /dump`, the engine's world dump | every build; OFF in `scripts/gate-full.sh`'s `--no-default-features` checks |
| `client` | off | `GET /`, the embedded GUEST READER (read-only), so opted into (`Cargo.toml` carries the ruling) | `scripts/gate-full.sh`'s `--features client` check and `--all-features` run |
| `test-hooks` | off | `Daemon`'s `#[doc(hidden)]` test hooks, `fuzz_support`, the `Permit` re-export — and, forwarded, four seams in other crates: `skep-core`'s `test-hooks` (the feed walk's hold, notice and panic arm, the head writer's clock and refusal, the feed's and the attest store's failure arms, the lines said, the checkpoint signal's tick — the surface the daemon's hooks on its core call; it forwards nothing), `skep-media`'s `test-hooks` (the holds, the gate's overrides, the index's report and counts, the pools' `try_hold` the daemon's media hooks call), `skep-blobs`'s (the hazard seam `Daemon::hold_blob_finish_at` is a door to) and `skep-kernel`'s (the write-fault seam: the next checkpoint write, journal append, barrier or repair failing with a named `io::ErrorKind`, or a panic in the checkpoint write, through the kernel's own `#[doc(hidden)]` doors) | every test build (the crate's self dev-dependency); `scripts/gate-full.sh` checks the library and binary without it |
| `skep-signature`'s `sign` | off — skepd depends with no feature, so the daemon's build holds no signer, and skep-provision likewise for the record's decode | the signer's half: the KDF, keygen from a seed, signing, the signer's OS draw | every workspace build (skep-client's default `acting`) and every test build (the suites' dev-dependencies); `scripts/gate-full.sh` checks the crate without it (the verify-only build a daemon links) and with it, and that skep-provision's shipped build resolves it off |
| `skep-signature`'s `test-hooks` | off | implies `sign`; the fixtures' hooks — every item whose doc opens `TEST HOOK`, hidden from the docs, named together in the crate's `src/hooks.rs` | every test build (its self dev-dependency, and skep-core's and skepd's dev-dependencies on it) |

## Rules that hold across files

- **Crate dependencies point down.** The order in the code map is the
  order the compiler enforces between libraries; the dev-dependencies
  pointing back up are `skep-kernel`'s, whose integration suites build
  their shared fixture through `skep-engine` and the stores it assembles,
  `skep-media`'s on `skep-engine`, whose door's and index's unit suites
  open a real engine to judge generic code against the concrete `World` —
  the media crate's library never depends on the engine — `skepd`'s on
  `skep-resolve`, whose end-to-end cells and measurements run where boards
  are spawned — the daemon's library never depends on the resolver — and
  `skep-search`'s on `skepd` and `skep-client`, whose budgets suite writes
  the design's corpus to a dev board through the client's frames and reads
  it back as the shell does, so the index is measured on units that came
  through the wire — the index's library depends on neither (`search.md`
  §1.3, §7.3). `skep-client`'s normal dependency on `skep-search`, behind
  its `search` feature, points DOWN — `skep-search` stands before it in
  the map — while `skep-search`'s dev-dependency on `skep-client` is the
  upward one just named, a dev-cycle Cargo admits: the two libraries never
  depend on each other both ways.
- **The client reproduces the daemon's grammars under their rules, never
  its code.** `skep-client` holds its own `Origin::parse`, never imported
  from `skepd`, held to the daemon's vector set as SP-18 states. Every
  person door (§The command lists them) requires a `Person`; the terminal
  check is the CLI's implementation of that seam, never the walk's.
- **Inside `skepd`, imports point down.** A module names only modules in
  its own layer or below it, never above: the transport calls the router,
  and nothing below the router calls the transport; a leaf imports only
  leaves, `skep-util`'s among them. Code names an in-crate item by its
  home module, never through
  the crate root's re-exports. `crates/skepd/tests/it/tidy.rs` checks all
  of it, `crates/skep-core/tests/it/tidy.rs` the core's three layers and
  `crates/skep-media/tests/it/tidy.rs` the media crate's two layers the
  same way.
- **The PUT takes no `Serial`.** A blob upload commits nothing to the
  journal, so the write-serialization lock has nothing to order for it:
  `skep-media` and `server/blob_routes.rs` never name `serial`. What the
  finish holds — from the rename through the lease's sync — is the
  credential lock's READ arm, the arm the plain write sequence holds
  across the media door, so the door's read of the lease and the finish's
  write of it never interleave with a credential write; the requester is
  re-resolved under it at the rename. The pruner's rename aside holds
  that lock's WRITE arm, one file per acquisition, so the door's check
  and the commit it guards are one interval no removal of a name enters;
  the aside's unlink and the logs' compaction hold no arm of it. The arm
  is the daemon's to hand in: `skep-media`'s pass takes it as a closure
  and names no lock of the daemon's (§The media resource).
- **The daemon writes only its own files.** Everything the board
  creates stands under its data directory, and each file has one owner:
  the journal and the checkpoints are the kernel's, `checkpoint.tmp`
  included; `commits.log`, the feed's derived files and `feed-attest.log`
  are the daemon's own, written by `skep-core`'s `commits` under the
  daemon's directory and lifetime; and the media stores — the deposited
  files, the partials, `uploads.log` and `leases.log` — are `skep-blobs`'s
  under `blobs/`. The board directory is backed up whole, the journal
  copied first. The daemon never writes anything about the world outside
  the kernel. Its rules of mechanism: SP-5, SP-7.
- **Tests live beside the code they test.** Unit tests are a `tests`
  child module; one of 200 lines or more lives in its own `tests.rs`
  beside the file. Integration tests live in each crate's `tests/it/`, one
  test binary per crate. See `AGENTS.md`.

Its rules of mechanism: SP-5, SP-7, SP-18, SP-21, SP-24.

## Where the reasons live

- `docs/wire.md` — the wire protocol, every route and refusal.
- The module designs (M1–M10), the composition contract and the AUTH, PUB
  and REGISTRY specifications, in the design project — the reasoning
  behind each crate and each rule above.

This file changes when the layout changes: a new crate, a moved module, a
new cross-cutting rule. It does not record history. The rules of
mechanism — what every site of a kind must do, and the one component that
does it for all of them — live in `PATTERNS.md`, numbered `SP-n`, each
with the component that holds it and the test that checks it.
