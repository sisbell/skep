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
- `skep-blobs` — the blob store (media lane B): the four media stores
  under one root — the files at `blobs/<designation>/<hex>`, the partials,
  the upload records and the lease log — the PUT's fsync order, REPLACE on
  a present hash, the lease's honest-null answer, the pruner's rename
  aside, the logs' runtime compaction on a trigger, the volume's capacity
  read, the open's probe of the volume's hard links, the owner-only modes
  every file is born with, the open's account of what it repaired, found
  and freed, the logs' sizes and their stops' figures, every I/O failure
  named by its file and its act, and the operator's two doors — the
  read-only inspection and the pull's install by the PUT's order. It
  depends on no other skep crate, knows a principal only as an opaque
  string, holds no lock the daemon's write path takes, writes no operator
  stream, and reads no limits record. One feature, default off:
  `test-hooks` compiles in the test seam, `store/hooks.rs` — a hold or an
  injected failure at a step of the finish, and the methods only tests
  call. `scripts/gate-full.sh` builds the library and its docs without it.
  Its modules and rules: §The blob store.
- `skep-util` — the support crate below the daemon and the media crate:
  the three utilities both take and neither owns — the counting permit
  pool behind the daemon's five bounded pools and, beside it, the edge
  tracker each bound that refuses holds, so its saturation and its
  clearing are said once per episode; the operator's notice line
  (`skepd: ` on every line; §The support crate says why a library spells
  it), and the JSON determinism helpers — `obj`, the key-sorting object
  builder every JSON object the daemon emits is built through,
  `hex_string` and its exact inverse `parse_lower_hex` with `hex_nibble`.
  It depends on no other skep crate and on `serde_json` alone, so it may
  stand anywhere in the foundation; it stands last because it holds no
  part of the world — the crates above it are what a board is made of,
  and this one is what two crates of the daemon's lean on. No constant
  lives here: a constant is configuration, not a utility. Its rules: §The
  support crate.
- `skep-corpus` — the prose corpus a dev board is seeded from and the
  search budgets are measured over: a git repository read at one pinned
  commit through `git` alone — the records tier's filter, the paragraphs
  of its `.md` files, and the one deterministic cut into documents of
  1–10 KiB (`cut-v1` over the tier, `cut-v2` over a chosen subtree), each
  document with the paragraphs it was joined from. It depends on no skep
  crate and on nothing but `std` and a `git` child process, so it may
  stand anywhere; it stands here beside `skep-util` because, like it, it
  holds no part of the world — it is what the search budgets suite
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
  anywhere; it stands here beside `skep-util` and `skep-corpus` because,
  like them, it holds no part of the world — it is what the dev provider
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
  surface names and the inert rendering a key's label and every log line
  take — and never `skepd`, which its suite spawns as a dev-dependency. No
  feature; every test build compiles it with `skep-client`'s `test-hooks`
  on, so `scripts/gate-full.sh` checks the binary as it ships. Its modules
  and the rules that hold across them: its crate doc, `src/main.rs`.
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
  record, ruled P-1 … P-12): the bridge's twenty-four calls — §4b.1's
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
`checkpoint.tmp` — a temp file the kernel alone deletes: a failed write
removes its own before answering, and `Kernel::open` removes one a crash
left, reporting its size), the exclusion lock (`kernel.lock`), and the
files the open's tail cut keeps (`seg-<n>.wal.cut-<byte>`, then `….<k>`):
where the tail holds an intact frame no torn write leaves, every byte the
cut takes is kept there first, durably, and the kernel never reads, moves,
removes or writes over one — they are the operator's. Every other name in
that directory it leaves alone, so an embedder keeps files of its own
beside the journal — the daemon keeps its change feed and its blob store
there. The directory is born `0700` and every file the kernel
makes in it `0600` on unix, through `journal::dir_builder` and
`journal::file_options`, the modes' one home: the mode is set at creation
so the process umask cannot loosen it, and `tests/it/tidy.rs` holds every
other site to those two. One applier lock serializes every
write; a write is appended, fsynced, and only then installed as the root
that lock-free readers load. The checkpoint cadence is tested on commit
under that lock and never by a timer; under its deferred arm a crossing
sets a due flag the caller's own thread services — `Kernel::checkpoint`
clears it first, then runs — and a second crossing with the flag still set
runs the checkpoint inline as the backstop. The world is a type parameter:
the kernel folds records through `WorldState::apply` and never reads them.
Its modules are declared in `src/lib.rs` in dependency order, each with a
line saying what it holds. Under `test-hooks` (default off, never in a
shipped build) `src/hooks.rs` is the write-fault seam: the next checkpoint
write, before or past its rename, or the next journal append, barrier or
repair failing with a named `io::ErrorKind`, or a panic in the checkpoint
write, each arm firing once, armed through `#[doc(hidden)]` doors on
`Kernel` and scoped to that kernel — and the count of the bases that
kernel's history reads have loaded, read through a door of the same
standing; the open's tail keep hooks the same seam at its copy's fsync,
which only the cut's own unit suite arms, the open's seam being made
unarmed with it; the `Step` the write sites hook before is named in every
build, and the hook is a no-op without the feature.

The kernel has no logging seam: it answers facts, and the daemon says them.
A journaled open reports what it found and did as `Recovery` — the start
point, the bases it passed over, the commits it replayed (`replayed`), the
un-acked tail it cut, in bytes (`tail_cut`), with the file and byte the cut
began at (`tail_cut_from`), the intact frames among them no torn write
leaves (`tail_cut_intact`), the files those bytes were kept in before a
byte was cut, where the tail held such a frame (`tail_cut_kept`), and the
position an intact marker in the cut claimed (`tail_cut_claimed`), whether
it `began` a journal where none stood,
and the corrupt runs below the start point it read and passed over
(`runs_passed_over`, with the account of the first); a landing answers the
journal bytes it reclaimed (`Kernel::last_reclaimed_bytes`, `Some(0)` where
it reclaimed nothing) and the checkpoint files its retention removed, each
with its length (`Kernel::last_removed_checkpoints`); the checkpoints
`transact` ran inline on a committing thread are counted and the last one
recorded — the commit that ran it, how long it held that commit's caller,
and how it ended (`Kernel::inline_checkpoints`,
`Kernel::last_inline_checkpoint`); a poisoned kernel says why
(`Kernel::poison_cause`, a panic's words only where the code wrote them);
one checkpoint's header is read by its seq (`Kernel::checkpoint_header`, the
start point's after an open that skipped a newer base); and a checkpoint
that failed after its base landed names which step failed — the directory's
fsync, retention or the journal's reclamation — as `CheckpointError::Landed`
carrying a `LandedStep`, where a failure before the rename stays `Io`; and
the committed boundaries above a position, each with its signature slot, are
answered in one scan from the base at or below it
(`Kernel::boundaries_above`), where `Kernel::attestation_at` answers one
boundary per scan.

Rules that hold across its files:

- **Durable before visible.** `Kernel::transact_attested` hands the
  journal an install closure, and only the journal runs it:
  `JournalWriter::commit_txn` appends, fsyncs, then installs, inside one
  call; the in-memory journal, which has no barrier, installs at the same
  point.
- **A halt cuts nothing.** Every refusal in `Kernel::open` precedes
  `journal::truncate_tail`, recovery's one destructive step — and that
  step keeps before it cuts: where the tail holds an intact frame no torn
  write leaves, every byte it will take is first copied or moved beside
  the journal and synced, and a keep that fails cuts nothing.
- **One door to the write state.** `ApplierLock::acquire`, which refuses
  a nested acquisition, is the only way to the sequencer, the journal and
  the cadence; the lock's fields are private to `kernel/applier.rs`.
  `Kernel::checkpoint` never takes it: its own mutex may be taken under
  the applier lock, never the reverse.
- **A scan and its fold share a base.** Scans are reached through
  `replay::Base::scan` — and, in the mode that collects the committed
  boundaries with their slots and no record, `replay::Base::scan_boundaries`
  — never by a caller supplying `S_load`.
- **Retention keeps the bases that load.** `checkpoint::retain` passes over
  the names the open's `Recovery` lists as skipped when it counts the newest
  `retain_checkpoints` bases to keep, and removes them as excess, so the
  first landing after a skip keeps the base the open loaded from beside the
  new one; the reclamation floor is the oldest base kept, and a base
  `Kernel::checkpoint` writes over a skipped name is counted again.
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
  the `SKJ` and `SKC` stamps — with one dev-time exception on record,
  applied twice: on 2026-09-29 the chain's preimage gained the signature
  slot's digest and M5's slice its shot terms, and on 2026-10-15 a run of
  single-byte values became one range mint and one stretch record where it
  was two records per byte, M4's checkpoint entry a tagged value or
  stretch; each time the goldens were regenerated under the unchanged
  `SKJ4`/`SKC4` by the owner's no-stamp ruling (no served board exists;
  dev boards regenerate — after the second, every development board is
  deleted and re-seeded, whether its open refuses it or opens it from
  genesis), and the first regeneration's artifacts stand under
  `tests/golden-prestretch/` as the one committed pre-stretch board, which
  this build opens from genesis. A moved bound the reader holds
  every journal to — the frame cap, the transaction budget, the segment
  ceiling, the slot's width — is a format event too, though it keeps
  every golden byte, so `src/journal/tests.rs` pins those four beside the
  stamps; the rotation threshold and the resynchronization budget are
  pins a ruling moves under one stamp.

Its integration suites are one binary, `tests/it/`: `kernel` (the public
surface's claims, the write-fault seam's among them — the full volume at a
write, at a checkpoint before and past its rename, and at the repair after
an unwind, and a panic inside the checkpoint write), `hazard` (dirty
crashes, built through the engine), `golden` (the byte pins), `chain`
(the commit chain's tamper matrix), `docs` (the segment ceiling where the
wire contract and the runbook restate it), `modes` (every directory and
file the kernel makes owner-only) and `tidy` (every item documented as a
test hook or the test seam compiles only under `test-hooks`, and every
directory and file the library makes is born through the modes' one
home), over the shared `fixture` and `mutilate`.

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
  (`Store::unlink_asides`) — a failed unlink re-queued at the queue's head,
  its error naming the aside, which the daemon says once and clears with a
  line when a later call empties the queue. A crash leaves at worst a file
  with no lease, a record open retires, or an aside open removes.
- **Three exclusions are the caller's.** One `Store` per root
  (`Store::open`); one stream of an upload at a time, its acts serialized
  (`Store`); and no `unlink_blob` or `remove_aside` while a finish runs
  (`Stream::finish`). The store checks none.
- **The pruner's acts are one method each**, so the daemon's pass holds
  its lock around exactly one, and the lease read inside it is one hash's
  range of the lease map (`LeaseMap`, keyed by the hash first): a pass is
  linear in its files, whatever the count of leases. A file is taken in
  two acts — `Store::rename_aside` under the caller's arm, the aside
  removed after it under none (`Store::remove_aside`) — so the arm is
  never held across the freeing of a file's blocks; `Store::unlink_blob`
  is the one-act form, which the daemon's pass no longer takes. Each
  removal the pass makes answers the bytes its unlink freed — the file's
  length where it took the last name, nothing where another name still
  holds it (`Store::remove_aside`, `Store::expire_upload`) — so the pass's
  line says what it reclaimed.
- **The logs' compaction has a trigger.** `Store::compact_logs_if_past`
  rewrites either log to its current records where its lines have passed
  a multiple of those records and a minimum — both the caller's figures,
  the daemon's pins — the lease log's leases past the horizon at the
  caller's `now_ms` dropped first, as the open drops them (`LeaseLog`),
  under the store's lock on that log's appends alone;
  an append during the rewrite waits and lands in the new file, and a
  stopped log is rewritten whatever its count (`Store::stopped_logs` says
  which has stopped, why, how long it has stood and how many appends it
  has refused — `LogStop`). It answers the size it rewrote each log from,
  and `Store::log_sizes` each log's size, the room its next rewrite needs
  (`LogSize`). A compaction that fails short of its rename takes its twin
  with it (`jsonl::Log::compact`), so a rewrite that met a volume with less
  room than it needs keeps none of that room.
- **The capacity is one read with the free space** (`Store::capacity`,
  `Store::free_space`): the same `statvfs`, the total blocks and the
  available ones — the capacity, what the daemon's default per-account
  limit is a share of, read once at its start; the free space, what the
  floor is held against at every creation and chunk.
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
  answer, since the store reads no cell. A principal's unplaced deposits
  and its live leases (`Store::live_leases_of`) are read off the lease map's
  index by principal (`LeaseMap`), at that principal's own leases' cost:
  the daemon reads the pending bytes once per 64 KiB chunk of each upload,
  and an upload is never its chunks × the board's leases. The map and its
  index change together, by `LeaseMap`'s two acts alone, so the index holds
  the map's keys and no others.
- **A torn line is only ever a log's tail** (`jsonl::Log`): a failed
  append is cut back, and a log that cannot cut back, or whose compaction
  failed past its rename, takes no append until a compaction completes.
  The store compacts at its open and at the caller's runtime compaction,
  so a log stopped while the store serves stays stopped until the next
  pass's compaction or the next open reads it afresh (`Store`). A finish
  meets a stopped log before its first act (`Log::refuse_if_stopped`),
  where its lease's or its retirement's append would meet it past its
  rename, so a stop strands no upload over a partial its rename took: the
  upload stands, to finish once the stop lifts; and a creation the stop
  refuses takes its partial with it. The stop
  keeps its cause — the act that failed and the OS's cause — which every
  refused append names, and counts the appends it refuses, which
  `Store::stopped_logs` answers beside the cause and the stop's age.
- **Every failure names its file and its act.** An I/O error the store
  answers reads `{file}: {act}: {cause}`, its kind the OS's: the file as
  it stands within the data directory, the root's own name first
  (`blobs/leases.log`), never by an absolute path, and a partial by its
  directory alone, its file name an upload's identifier (`blobs::named`,
  `blobs::label`, `blobs::partial_label`). A full volume's cause reads
  `the volume is full ({the OS's text})`, the operator stream's own words
  (`blobs::Cause`), so one search finds every act that failed for room.
- **Every directory and file the store makes is born owner-only**, `0700`
  and `0600`, set at creation whatever the process umask, through one
  builder of each (`blobs::dir_builder`, `blobs::file_options`): a pin,
  which `tests/it/modes.rs` holds every entry the store makes to.
- **Open reconciles and compacts before it answers anything, and answers
  what it did; the inspection does neither, and answers what it found.**
  `Store::open` runs each store's act at open — the logs' compactions,
  `partials::reconcile`, `blobs::sweep_asides` — and an I/O failure there,
  as at the size check (`Store::blob_size`), is never read as an absence.
  What frees room runs before what takes it — the asides swept and the
  partials reconciled before the lease log's rewrite, the hard-link probe
  and the records' rewrite — so an open on a full volume has made the room
  its own repairs make before it asks for any; and every open ends by
  fsyncing the root and then the board's own directory, whose fsync alone
  makes `blobs/`'s own entry durable, the pull's install doing the same.
  Its orphan removal keeps to the designations this build computes
  (`HashFunction`); another build's designation directory is left, as the
  pruner leaves it. The store writes no operator stream, so its open's
  account is its embedder's to say (`Store::opened`, `Opened`): every
  repair by count and the bytes the repairs freed, and what each log's
  reading found (`LogRead`) — a cut
  that took whole lines past its first untrusted one (`TailCut`), which a
  crash never leaves and damage does, lines read as nothing, a store or a
  log found absent and made empty. Before any act, a symbolic link, a
  special file, or a second link to a file the store writes in place, at
  a name it acts on, fails the open, every one found counted in one
  refusal of bounded length — eight clauses named, the partials of one
  directory one clause, the rest counted by kind — with the act for each
  kind (`blobs::refuse_links_and_special_files`): nothing is followed or
  written through. Among the acts that take room, the volume is probed for
  the one capability no other act of the open exercises, a second name for
  a file, which a re-PUT of a file the board holds takes: a volume that
  makes none fails the open with the act that clears it
  (`blobs::probe_hard_link`), where
  it would otherwise serve every new upload and fail every re-PUT, the
  failure telling a file already here from a fresh one. `Store::inspect`
  holds the same names to the walk's rule — and probes nothing, since it
  writes nothing — then reads the four stores as they stand — each
  log's lines read through `Log::read_as_found`, its torn tail cut in
  memory alone, what the reading found answered (`Inspection::logs`) — and
  creates, cuts, renames and syncs nothing, so it can run over a backup or
  beside a serving daemon's store.
- **The pull's install is the PUT's order with no record** —
  `Store::install_file`: the bytes streamed into a temp file named as a
  partial is (so an open that meets it removes it as an orphan), hashed as
  they are copied, fsynced, renamed onto the hash name, the directory, the
  root and the board's own directory fsynced; held to an expected hash
  where one is given; into a
  board's own directory that stands, never one it makes; no lease, no
  record, no lock. A refusal says on which side of the rename it fell:
  `nothing installed: …` before it, `installed at …, but …` past it, the
  file then standing under its hash.
- **A caller's bug is no refusal, nor is the store's own.** `Stream::finish`
  panics on a broken precondition, and `UploadRecords::mark_received` on an
  offset past its record's length; `BlobError` carries only answers.
- **The test seam is a feature.** `test-hooks` (default off) compiles in
  `store/hooks.rs` alone; `scripts/gate-full.sh` builds the library and its
  docs without it.

Its integration suite is one binary, `tests/it/`: `finish` (the PUT's order
under an injected failure at each step, and the finishes run one at a
time), `replace` (REPLACE and its asides, and a failed finish naming the
hash's file alike whether or not it was here), `blobs` (the name check,
the listings, the size check, the floor's and the capacity's reads, the
rename aside, the pull's install and its refusals), `uploads` (an upload's
life while the store serves, its identifier, the records' log's runtime
compaction, and a stopped log's cause), `reopen` (what open makes of the
records and partials a crash or a restore left and the account it answers
of them, its named refusals, the inspection that touches none of it, and
the copy order a live copy follows), `lease` (the leases' states, their
compaction at open and by the trigger, the pending bytes, and what a
principal's reads and the pruner's cost), `modes`
(every directory and file the store makes owner-only) and `tidy` (every
item documented as a test hook or the test seam compiles only under
`test-hooks`); each module's doc lists its claims. Six unit suites sit
beside their code: `store.rs`'s, `uploads.rs`'s, `lease/map.rs`'s,
`partials/handle.rs`'s, `blobs.rs`'s and `jsonl.rs`'s, the last in
`jsonl/tests.rs`.

## The support crate, `skep-util`

`skep-util` holds the three utilities `skepd` and `skep-media` both take
and neither owns, so the media crate's move out of the daemon copies no
helper and the daemon's five pools keep one permit type. Its modules are
declared in `src/lib.rs`, each with a line saying what it holds, and the
crate doc there states the rule of membership and the program-name
decision. `permits` — the counting permit pool (`Permits`, `Permit`): a
try-acquire with no queue and no blocking whose guard returns its slot on
drop, the one mechanism behind the reconstruction budget, the class-scan
pool, the fetch pool, the upload pool and the write pool; a permit is a
slot of the pool that minted it, so no bound can spend another's. Beside
it the edge tracker (`EdgeTracker`, `Edge`): the once-per-episode memory
of a bound that refuses — the first refusal it meets an edge, the first
admission once the condition has stood clear for a hold-down the holder
names the other — which those five pools, the daemon's live-stream
budget, its challenge store and its accept loop each hold, so what each
says on the operator stream is two lines per episode and nothing per
request; the one rendering of a pool's two lines (`PoolEdgeLine`); and
the one clock the hold-down is judged against (`edge_clock_now`), whose
offset the daemon's test seam advances. `notice` — the operator's
stream (`emit` and `emit_lines`, the class word an argument of both and
the two the only doors, so no line goes out without one): one line, or
one notice of several written as one, every line prefixed and the head
carrying its time, each put on a bounded queue that one thread,
`skepd-notice`, writes to stderr in order, the
write's result discarded so a lost log pipe never fails the work the
notice is about and a stalled one never waits it; a line a full queue
cannot take is dropped and counted on the next; `drain` waits the queue
out at the binary's exits while the sink takes lines, and gives up
(`Stalled`) on a sink that has taken none for the caller's bound — the
binary's `DRAIN_STALL` — so a stalled reader costs an exit its last lines
and never the exit. `set_sink` is the embedding program's door: a
sink of its own in stderr's place — the stream made over it at the call,
as the first line would make it — installed before the first line, once;
the stream lives for the process, so a later install is refused
(`StreamAlreadyMade`) and changes nothing. `json` — the determinism
helpers: `obj`, the key-sorting object builder every JSON object the
daemon emits is built through, under which the last pair given wins;
`hex_string`, lowercase hex; `parse_lower_hex` and `hex_nibble`, its
exact inverse at a fixed width, refusing what `hex_string` never writes.

Rules that hold across its files:

- **Membership.** An item lives here if and only if BOTH `skepd` and
  `skep-media` take it AND it has no subject of its own. A constant is
  configuration, not a utility: the limits the two crates share are the
  media crate's own public numbers and the daemon's stay the daemon's, so
  none lives here; a helper one crate alone takes lives in that crate.
- **Nothing of skep below it.** The crate names no store and no engine;
  it depends on `serde_json` and `std` alone, so it may stand anywhere in
  the code map's order and any crate may take it.
- **The program's name.** Every notice line opens `skepd: `, spelled once
  in `notice.rs` — in a library, by decision. The prefix names the
  PROCESS a shared stream attributes a line to, and exactly one program
  writes the operator's stream: the daemon, as the shipped `skepd` binary
  and as the `Skepd` library an embedder or a suite runs in-process under
  the same name; `skep-media` is a component of that process and of no
  other. A name handed in at each call would make the media crate spell
  the daemon's name or be told it, for no line that would read
  differently; a name installed once by the binary's `main` would leave
  every in-process daemon unprefixed. A second program linking this crate
  makes the name a parameter then, and the call sites' shape stays.

Its unit suites sit beside their code: `json/tests.rs` (the sort and the
duplicate-key rule) and `notice/tests.rs` (the line's bytes at a known
instant, pinned as bytes and never through the constant; the civil date at
instants computed by hand; the queue over a sink the test owns — a door
that never waits on it, the bound, the drop and its count, the drain, its
giving up on a sink that takes no line and its patience with one that
takes lines slowly, a parked writer's line).

## The corpus crate, `skep-corpus`

`skep-corpus` holds one rule in one place: THE CUT of a git repository's
prose into documents of 1–10 KiB, read at one pinned commit through `git`
alone — `ls-tree` for the tier, `cat-file --batch` for the bytes — never
from the working tree, and nothing of the repository copied anywhere. Its
one module is its crate root, `src/lib.rs`, whose doc states the rule;
its unit suite, `src/tests.rs`, cuts a repository it builds under the
system temp dir. The records tier (`in_tier`, `Corpus::tier`,
`Corpus::records`): every file tracked at the pin whose basename is not
`_context.*` and whose extension is not an image's or a video's
(`MEDIA_EXTENSIONS`) — the set the search index's ceiling was sized on.
The cut (`Corpus::cut`, `cut-v1`): the tier's `.md` files in `ls-tree`
order, split at blank lines into paragraphs, each capped at
`PARAGRAPH_CAP` on a character boundary, joined in order into documents
whose targets cycle `1 KiB × (1 + 7·i mod 10)` and never pass `CUT_MAX`,
named `cut-NNNNN`; deterministic, and prefix-stable — the first `n`
documents of any cut are the first `n` of every longer one. The subtree
(`Corpus::under`, `cut-v2`): the same rule with the paragraph source
restricted to the `.md` files under one path, the rule's name following
the source. The sources (`Corpus::cut_sourced`): each document with the
paragraphs it was joined from — the file, the byte range, the heading a
paragraph opens — which the dev binary reads to anchor a citation's link,
choose a version's paragraph and send a cited section to the document
holding it.

Rules that hold across its files:

- **The callers name the repository and the pin.** The crate reads no
  environment variable of its own: the search budgets suite reads its
  `SKEP_SEARCH_CORPUS` and the dev binary its `--repo` and `--pin`, and
  each hands the crate a path and a commit. Every `git` it runs starts
  without git's repository-local variables (`GIT_LOCAL_VARIABLES`, git's
  own `--local-env-vars` list less the two that carry configuration), so
  a `GIT_DIR` a hook exported cannot override `-C` and the repository
  read is the one handed in. `Corpus::open` judges the repository
  (`rev-parse --git-dir`, git's refusal an `Error::Git` in its own words)
  and then the pin (`cat-file -e <pin>^{commit}`, `Error::NoCommit`), and
  every read names the pin.
- **Nothing of skep below it, nothing of the world in it.** The crate
  depends on `std` and a `git` child process alone — no skep crate, no
  feature, no platform call — and copies nothing of a repository into
  this one: the budgets suite reads the design repository at its pin at
  run time, and the dev binary whatever checkout it is handed.
- **One rule, two names.** `cut-v1` over the whole tier is the budgets
  suite's cache key, so its documents never change; a subtree is
  `cut-v2`, another source and another name, and a cache keyed by the
  rule never mixes the two. The 10³ cut at the design repository's pin is
  pinned by the budgets suite — 1,000 documents, 6,258,909 bytes, the
  smallest 1,058, the largest 10,237 — so a change to the rule, the cap
  or the targets is a STOP there, not a new number.
- **A shortfall is an `Error`, never a panic.** A `git` that fails, a
  pin that names no commit, a path that is no blob, a source that runs
  out before the documents asked for — each is an `Error` the caller
  renders: the budgets suite skips, the dev binary halts.

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
  calls `skep_registry::parse`); a parser is never derived from another
  parser.
- **The check runs on lists.** `seeding_check` takes the registry's rows
  and the foreign rows as lists, so every arm is proved on a list a suite
  builds; the shipped table passes, and the daemon runs the check over
  the whole domain it can see ahead of every genesis.

Its integration suite is one binary, `tests/it/`: `rows` (commons-map's
table transcribed once and asked every question line by line, the laws the
table holds whatever its lines, and `commons_type`'s panics), `check` (the
three arms on mutated lists, each of the twelve rows' absence among them,
and the row completeness names of any two missing), `body` (the vector set
at this parser, the examples' one canonical form, the cases that pin this
parser alone — a refusal's member, the first stage to fault, the `type`
member read off its kind's row — and the codec's public face at cases a
hand chose), with its child `body/laws.rs` (the escape table at every
Unicode scalar value; the parse's laws, stated once and met on every vector
of the set, on every one-byte mutant of every admitted vector up to 1 KiB
and on seeded hostile bodies several edits from the vectors, at every
refusal the parse answers; and the encoder's law, every body a caller
builds a record up to the cap), and `tidy` (the manifest's two
dependencies, the leaf the code map names). Its unit suites sit inline
beside their code and hold only what that code's privates can show — in
`rows.rs`, the registry range, its ordinal reader and `row_at` against the
type subspace's own prefix; in `body.rs`, the one-spelling reader
`address_of` and the codec's cases built through it.

## The resolver, `skep-resolve`

`skep-resolve` is the client's half of the registry: what reads the
board the daemon serves and knows the bindings it read were genuine. It
links no daemon and no engine, speaks the wire as a guest, and opens no
socket to an endpoint — the dial is the caller's. Its modules: `hint.rs`
the root hint (the root's origins and the realm id, `RealmId` — the
genesis fingerprint and, on a forked lineage, the fork point beside it)
parsed from one line or built from its parts, never with no origin;
`http.rs` the written-out HTTP/1.1 client behind a `Transport` trait;
`board.rs` the typed reads over any transport (`Board`), every read
counted by kind; `mirror.rs` the `/changes` consumer's types and state,
the journal copy and the fetch cache under the caller's directory, and
the fold, with four children — `mirror/base.rs` the base's check, its
refusals and the sync, `mirror/keys.rs` the key set as of a position,
`mirror/atoms.rs` a record's bytes and the chain walk, `mirror/cache.rs`
the fetch cache's format; `verify.rs` the record grade for registry
records, client-side; `index.rs` the ledger of the rules (the binding
walk and the endpoint's currency) and the verified prefix → binding index
behind the mirror's gate; `walk.rs` the resolve, and its child
`walk/guest.rs` the guest-reading resolve that scans with no mirror;
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
  cache, its format written and read in `mirror/cache.rs` alone, a value
  written once, a line that does not read — a write a crash cut short —
  held as absent and never run into, and a record's position and home its
  row's, never a cache line's. A new base begins both files afresh, so a
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
  forever, and no floor clause counts acts over an empty interval. A link's
  slots are read only for a link of a type its reader names, its type slot
  that type's unit span exactly, the daemon's own reading of a registry or
  credential type.
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
the replay matrix), `mirror` (the rebuild from the copy and the offline
mirror's scope, the realm check, the head pairs, the re-bootstrap, the
root's failover, the copy's two files, the hint's line), `walk` (the
faces) and `origin` (the terms and the precedence). The paths no
recording reaches — the reclaim floor, the page budget, the position
read, an unclaimed feed, the binding home, a cache naming another
claimant or hiding the genesis act, a cache line placing a record at
another position or home, a second claim, an address past a machine
word, the guest-reading resolve's verdicts, a forged retraction,
a page or a window that does not advance, an answer past the cap — run in
the unit suites over boards they hold fixed, each beside the code it
pins, the mirror's suites sharing the fixtures in `mirror/testing.rs`.
The end-to-end cells and the measurements run in
`crates/skepd/tests/it/resolve.rs`.

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
default-off `search` feature (lane SH; §The client). Its modules are
declared in `src/lib.rs`, each with a line saying what it holds. `unit` — the document
model (§2.1, §2.4): `Unit`, one document version's arranged content
delivered in parts under `MAX_DELIVERY_ITEMS` and JOINED, adjacent text
items becoming one so a character split at a part's edge is whole again;
the typed delivery `Item`s — `Text`, one `content` item's bytes or a `hex`
run's, and `Gap`, every item that is not text, at its width — and the item
table, searched by start ordinal for an occurrence's item; `UnitKey`, the
bare document address ALONE, so a re-read replaces; the member, the
position, the kind and the `Class` the unit was read at beside it; the
head rule `moved_head`, a daughter's row moving no head and an owner's
`version` row moving it. `token` — the tokenizer (§2.3): UAX #29 word
boundaries, the fold (NFD, the marks sr-E1 scopes as ITEM 3 amended it,
the apostrophe variants, the invisible format controls), lowercasing; each
occurrence's range from the unit's start; the `REVISION` the index
records; the rule over one stretch, `segments`, which the query shares.
`index` — the inverted index with positions (§1.4, §5.1): the
sorted dictionary, the postings with ordinals and ranges, the unit records
with their term lists, the tombstones, the live counts; `Index::new`,
`prepare`, `merge`, `index`, `compacted`, `install`, `compaction_due`,
`stats`, `terms`; `IndexError`'s refusals; `CEILING_BYTES`; and THE ONE
READ over the unit keys, `Index::keys_by_range` under a `Prefix` — the
crate's own type over an account's or a document's address — one scan of
the keys under it, the refreshes' enumerator and nothing else's (RULED
(b)). `query` — `Query::parse`, the one grammar (§3.2): a word, the trailing
prefix, a quoted phrase, an unclosed quote's phrase-prefix, a split chunk's
implicit phrase, the conjunction; the evaluator over the pair — the term
lookup, the prefix expansion over the sorted dictionary by binary search,
the phrase by adjacent ordinals, the phrase-prefix over the terms that
follow the fixed words, the fuzzy word within one edit, the conjunctive
window — under its three INTERIM pins, `EXPANSION_BOUND_ENTRIES`,
`POSITIONS_BOUND` and `FUZZY_WORDS`, each a flag on the answer. `rank` —
BM25 (§3.3): `K1`, `B`, the pinned `idf`, `term_score`, the pair's merged
`Statistics`, the tie `order`. `hit` — `Hit` and `Answer`, the contract the
UX designs to (§3.1, §3.5): `Span`, `Standing` with `Rung`, `Matched`, the
`Snippet` with its `Mark`s (§6), `SNIPPET_BOUND`. `pair` — `Pair`, the two
indexes by role with the standing's inputs — the supplement's header
ranges and the honored set's prefixes — `QueryOpts`, `DEFAULT_LIMIT`, and
`Index::query`, the one call (§1.4, §5.2). `header` — the
file's header (§5.1): the typed `Header` the embedder composes — `board`
(a `Chain`), `floor`, the per-range records with `held` as a `ChainAt`
pair, the refusals, the bare-row count and a granted range's `Grant`, the
newest head's `HeadRecord` — and the header line's one canonical writer
and parser, `encode` and `parse`, `v` first, no JSON crate; `HeaderError`.
`file` — the body's layout and the CRC-32C trailer (§5.1), `Index::save`
and `Index::load` with every disposition as `LoadError`, the migration
from the stored text tagged by `Index::migrated_from`, the aside's
spelling `aside_name` (§5.4). `resume` — the resume read's answers judged
as a pure function, `Resume::judge` over the `ChainAnswer` the shell fills
(§5.4).

Rules that hold across its files:

- **One class per index** (`search.md` §5.2 D7; §4's invariants (i) and
  (ii)). An `Index` carries exactly one `Class` from `new` — `Guest` for a
  published index, `Principal(n)` for `n`'s supplement — and no call
  changes it; `merge` refuses a unit read at any other class, both classes
  named. The published index and a supplement, and one principal's
  supplement and another's, are two values, never one value with a filter
  column.
- **Cut once at `merge`** (§1.4, §7.4). The class check and the ceiling are
  made where a unit enters and nowhere else. Past the ceiling the unit is
  not indexed and nothing changes — a refused replacement leaves the unit
  it would have replaced in place — the refusal names the bytes held and
  the limit with the units beside them, and the offer is counted in
  `seen`. The ceiling counts LIVE bytes of text, what a rebuild would hold;
  its figure is an INTERIM PIN at the records tier's own size (§7.3, §7.4;
  ITEM 2 RULED (d)), confirmed or raised by the budgets lane.
- **Prepare under no lock, install by one swap** (§5.6). `Index::prepare`
  takes no index: the tokenizing and the postings' build run outside
  whatever lock the embedder keeps around the engine, and `merge` takes
  the write side for the merge alone. `compacted` builds the new postings
  from one value under the read side and `install` replaces them by one
  assignment under the write side; the feed thread calls each pair in
  sequence. The crate holds no lock of its own, and every type that
  crosses the embedder's lock is `Send + Sync`, asserted in the library.
- **Every bound is a flag** (§3.2; PATTERNS P29 as sr-P1 amended it). The
  expansion's bound in postings entries, the keystroke's positions bound
  and the fuzzy words bound are INTERIM pins, constants whose docs quote
  §7.1 — the two position bounds derived from M2's one-frame pin, the fuzzy
  words bound its stated three; each stops the work where it is met and
  says so on the `Answer` — `more_terms`, `positions_bounded`,
  `fuzzy_bounded` — and never cuts silently; `total` is then a lower bound
  and `truncated` is set. The budgets lane confirms or moves the figures.
- **One score, one order** (§3.3). BM25's idf in its one pinned form,
  positive at every df; one score per query form over the pair's MERGED
  statistics, each member's units counted once (ITEM 4's cut); a higher
  score the better match; ties by document address, then member, then span
  start. The same pair and query give the same hits in the same order on
  every run, and no hash map's seed decides it.
- **The hit is the contract, the pair names what it searches** (§3.1,
  §1.4, §5.2). A hit carries every member §3.1 names and no file, path,
  directory or other principal's index; a draft's hit is never `Public`;
  `Held` is composed from the range records and the honored prefixes the
  pair carries — the shell's facts, named at the call — by prefix
  arithmetic, no read made. The pair's members are passed by role, the
  guest form's the published index alone.
- **Nothing of the network, the keys or the board** (§1.3). The
  dependencies are `skep-address` and the two Unicode crates, and nothing
  else — NOT `skepd`, NOT `skep-client`, NOT `serde_json`: the file's one
  JSON line is written and read by the crate's own bounded code; no
  feature, no platform call, no target-specific code. The two crates'
  tables are one Unicode version, which the tokenizer revision names and a
  test holds.
- **One file, one spelling, read whole** (§5.1; PATTERNS P35, P38). An
  index is one versioned file, loaded whole. Its header line has the one
  spelling `save` writes and `parse` admits no other — `v` read first, a
  `v` above 1 faced as a newer skep's before any other member is judged —
  and its CRC-32C trailer covers the header line and the body, so nothing
  damaged is loaded as written. `load` judges in one order: the line, the
  class against the one expected, the tokenizer, then the body. The file
  is DERIVED STATE (P22): every refusal is a disposition — a newer `v` or
  tokenizer faced and the file left, another class's file moved aside, an
  older tokenizer migrated from the stored text, a damaged file rebuilt —
  and never a halt.
- **The crate moves no file and reads no board** (§1.2, §5.4). `save` and
  `load` take the `Write` and `Read` the embedder hands them; the save's
  rename, the aside's rename and the resume's `/chain?at` and `H.k` reads
  are the shell's. The crate spells the aside's name and judges the resume
  as a pure function over values the shell hands in; the one read over the
  unit keys reads the keys alone.
- **The budgets report and never gate** (`search.md` §7). Every pin of
  §7.1 is measured by a timing test in the crate's `tests/it/budgets.rs`
  over §7.3's corpus — the design repository at one pin, read through
  `git` at run time and never committed — fed through a dev board's
  `insert` and read back through `retrieve_v`, each row printed as
  `BUDGET | row | tier | pin | measured | WITHIN or MISSED`; a miss is a
  word on the line and fails nothing, the design's "what a miss would
  change" being the owner's decision. The two rows the design asserts
  (M7's tree, the fuzzy row's flag) assert; without the corpus every
  budget test prints one skip line and passes.
- **The embedding is the shell's, and lands in `skep-client`.** The feed
  consumer, the bridge call that composes the pair, the refreshes and the
  jump's landing are `skep-client`'s `search` module (§The client), which
  takes this crate as an optional dependency; this crate gains nothing for
  them. The crate's `README.md` says what remains outside both.

Its unit suites sit beside their code: `unit/tests.rs` (the join, the item
table's binary search, the contiguity refusal, the head rule),
`token/tests.rs` (the Unicode version pair, the fold's reach and its
residue, the ranges across a gap and a hex stretch), `index/tests.rs` (the
postings' shape, the tombstone and the live counts, compaction and its
trigger, the ceiling's arithmetic, `seen`, the keys under a prefix),
`query/tests.rs` (the grammar's forms, each form's evaluation, the fuzzy
edits, the three bounds each met at a small value with its flag, the
window, determinism), `rank/tests.rs` (the pinned idf, the term score, the
merged statistics, the order), `hit/tests.rs` (the rung, the tightest
window, the snippet's cuts, the marks' order), `pair/tests.rs` (the opts,
the pair by role, the standing of each case), `header/tests.rs` (the
canonical bytes, the one spelling both ways, `v` first, every re-spelling,
the unknown member), `file/tests.rs` (the CRC-32C check value, the codecs,
the layout, the round trip, the trailer over the header line, the
dispositions in `load`'s order, the migration round trip, a damaged body by
section) and `resume/tests.rs` (one test per arm). Its integration suite
is one binary, `tests/it/`: `cases` (§7.2's twenty-two tokenizer cases,
each with its byte range), `grammar` (§7.2's two grammar cases with their
byte ranges, §8.3's query items, each bound met at its real constant with
its flag), `ranking` (§3.3's vectors, the merged statistics, determinism),
`hits` (the standing across a restart, the span's V-ordinals, §6's snippet
cases), `separation` (§2.1's class separation by construction), `index`
(the write side under the design's fence: the class check, one class per
index, the ceiling at the real constant, replacement, the lock split under
an `RwLock` of the test's own, the join across the parts' edge, the range
across a `Gap` and a `hex` stretch), `file` (§8.3's file dispositions at
the public surface, one test each), `resume` (the open's judgment over a
loaded header) and `budgets` (§7's pins, each a timing test in the
`gate-full only` partition that reports its row and skips without the
corpus — with `budgets/corpus.rs` reading the design repository at its pin,
`budgets/board.rs` the dev board the units come through, and
`budgets/report.rs` the one row shape).

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
  `address.rs` the address grammar over the wire's dotted spelling (an
  account's parent, first child and doc 1, the document an address lies
  in, the parse, the namespace's principal depth); `hex.rs` (private)
  lowercase hex; `dial.rs` the one outbound `Dialer`, its plain-HTTP arm
  and, under `tls`, the `https://` arm, its unit suite in `dial/tests.rs`;
  `halt.rs` the one error family and its exit codes; `board.rs` the
  wire's endpoints over a dialer, `H.1`'s pair and the one token a refusal
  is dispatched on, `board/frames.rs`, which spells every frame the crate
  sends, and `board/answers.rs`, which decodes every read answer it reads —
  its unit suite in `board/tests.rs`, and under `cfg(test)`
  `board/fake.rs`, the fake board the crate's unit suites dial;
  `derive.rs` the pure derivations over board reads — the mode, the
  pre-check, the walk to the set that opens an account, the key diagnosis,
  the `closed` predicate.
- Under `acting`. `sign.rs` the `Signer` seam and the bytes a signer signs
  (the session payload, a credential record's frame); `sheet.rs` the key
  file's one spelling and its refusals, the byline `Label` and the `Seed`
  every secret is born into; `store.rs` the `FileStore` — key files, the
  bindings file, the lock — and the halts its refusals render as, its unit
  suite in `store/tests.rs`; `person.rs` the `Person` seam,
  and under `test-hooks` `person/scripted.rs`, the scripted person a suite
  drives; `derive/records.rs` the one admitted read of an account's
  credential records, their positions and hands, its unit suite in
  `derive/records/tests.rs`; `verify.rs` the reader's
  verifier over the signature-filtered set, its unit suite in
  `verify/tests.rs`; `resolve.rs` the registry walk's `Transport` over a
  dialer; `share.rs` the grant — `share`, `privash` (PUB-5.108), `revoke`,
  the reads `issued`, `held` and `privashed`, the key's state read before
  every write and the lost answer read back, never re-sent, and
  `Ledger::fold`, the fold's walk over a doc 1's records, pure, its unit
  suite in `share/tests.rs` and its daemon suite in `tests/it/share.rs`.
  Grants are composed by the library and judged by the board, whose rules
  are unchanged: the library writes the record the wire already honours,
  and reads what the board makes of it.
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
  `<data>/index/<chain>/` — the modes, the feeder's `flock`, the save by
  `.tmp` and rename, the aside that never overwrites; `search/consumer.rs`
  the `Consumer` — the open with the aside check and the resume over
  `GET /chain?at` and the `H.k` re-read, the poll (the `/health` pair
  before the drain, one read per changed document per poll in parts, the
  class rule by face, the trunk probe, the straddled draft's pending
  join, the bare rows, the recorded refusals, `held` the fenced pair), the
  cadence's save with its compaction, the triggers `widen`/`narrow`, the
  refresh, the orphan test and the forget, and `events`, the `/events`
  stream as the loop's input; `search/places.rs` the document index's one
  part, a file per part beside its index (P39); `search/state.rs` the
  state event's ten arms as a typed enum and their one composition order;
  `search/bridge.rs` the bridge's two calls — the search, with the
  query's bound, the pair by role, `places` at the call's class with a
  standing at the document grain, and the document index's listing at the
  same class, its counts per account over the documents listed (A-255);
  `search/jump.rs` the landing rule over a `compare` answer's pairs
  — its unit suite in `search/tests.rs` over a scripted board, its
  daemon suites in `tests/it/search/`.
- Under `merge` (default off; the design's merge record,
  `_designs/CLIENT/2026-10-14-reconciling-versions-design.md`) — MERGING
  VERSIONS, the editor's act on a daughter: the base member and the two
  sides read as run lists, the surviving base material walked in order
  with every removal dropped and every addition placed back at the place
  its anchors name, the result one `publish` of the merged list and a
  record beside it. `merge.rs` the module and the one rule;
  `merge/compose.rs` the PURE CORE, `compose_runs` over three run lists
  with the gap report and the counts, `base_of` and the draft's in-place
  `script`; `merge/reads.rs` the READS of the record's §1.3 in order —
  `compose` over a board, a fork side's base read off its `doc_metadata`
  `source` (the member of the document it was born sharing; a bare source
  and a base the caller names for a fork are refused), every `image` and
  `retrieve_v` in parts past its
  budget, each origin the bare document (`origin_of`), the head member's
  feed-walk fallback `head_of`, the refusals — writing nothing;
  `merge/land.rs` the LANDING — the cap before any frame, the one `publish`
  from the head with its signed body through `skep_identity::PublishBody`,
  a daughter reported and never retried, the claim's read, the record and
  its public link, each read first, the draft landing, and `resume`;
  `merge/record.rs` the D13 `merge` kind, its key and currency (newest per
  key, the trunk owner's home first) and `verify`, the testimony
  recomputed with `compare` the oracle of the join; `merge/journal.rs` the
  merge journal, named or the account's default private draft; its unit
  suite in `merge/tests.rs` over the record's vectors and a scripted
  board, its daemon walk in `tests/it/merge.rs`. Of the SURFACES the `skep
  merge` command is built — `skep-cli`'s `commands/merge.rs`, the one
  embedder that turns the feature on (§The command) — and no agent surface
  is: the attendant is not built, and skep-mcp, which embeds `skep-client`
  directly and through `skep-shell`, turns the feature on nowhere, so its
  compose-and-report tool is not either. Neither is the supersession
  claim over version members: the wire's `assert_sup` takes resident
  links alone, so the
  record's public link to the member and the daughter states the
  supersession, and `land` reads `in_claims` without writing one. The one
  rule it keeps: a case is safe when the two sides touched different
  material, a conflict when they touched the same material or the same
  spot; six kinds of gap carry it, and the rules settle one, the anchor.

Rules that hold across its files:

- **One dialer.** Every request the crate makes goes through a `Dialer`:
  the one a `Board` holds, or the one `resolve.rs`'s transport wraps — and
  a dialer behind a reference, a box or an `Arc` is itself one, so a shell's
  one `Arc<dyn Dialer>` serves both.
  Every token-bearing request but the close rides `Board::authed`, which
  answers the death signal as `Authed::Closed` (P28); `Board::session_close`
  reads it on its own `204` as the token already dead (AUTH-4.47). A
  refusal is dispatched on `Rejection::key` alone — the one token wire.md
  §Rejections says a client keys on — and every read answer is decoded by
  `board/answers.rs`.
- **One home per composition.** Every signed session opens through
  `handshake.rs`, its pre-check's reads ahead of the `/challenge`
  (AUTH-5.65), and owns its end: closed, ended by its own commit, or handed
  out — and closed on its drop where a halt took none of the three; an
  imported anchor owns its end the same way, its PLACED copy destroyed at
  the close or on its drop (AUTH-5.54 step 3); every credential record is
  written by `deposit.rs`, which answers the armed arm that stopped it
  (`DepositHalt`) beside its face; an account's first signed session runs
  `first_session.rs`'s two states, and every persist-first `delegate` its
  one form. A walk states only what its site adds.
- **The ceremony is layered.** Nothing outside `ceremony/` names it;
  inside, a walk names compositions and never another walk, and a
  composition names no walk. `tests/it/tidy.rs` checks it.
- **Key material is written once, and no anchor rests in the store.**
  `FileStore::write_once` — `O_CREAT|O_EXCL`, mode `0600` at creation —
  writes every key file and every anchor file; a path inside the store is
  refused as an anchor's destination and as its source (§3.4). The store is
  a stored key's custodian: a lookup answers public facts, and the seed
  leaves the store only as the signer `KeyStore::signer` derives (§3a).
- **No journal.** Every walk resumes by reading the board (P4); the one
  kind of line written ahead of a frame is the persist-first `new_id`
  binding line (§4.3; AUTH-5.20).
- **The search half feeds under one lock and reads at one class per
  index** (`search.md` §4, §5.6). The `Consumer` is the one writer of a
  board's directory — the feeder's `flock` for its life, a second process
  refused as busy — and its mutating calls serialize on one feed mutex,
  while `search`, `places` and `state` read under the read side of the
  one read-write lock around the engines: `prepare` outside it, `merge` under
  the write side, `compacted` under the read side then `install` under the
  write side. The published index is fed by token-free reads alone and a
  supplement by its session's, so the crate's class check never fires; a
  range's `held` advances only behind a whole page, as the `/health` pair
  read before the drain or `GET /chain?at` at a save no drain fenced; no
  read the consumer makes carries a query term, and the bridge call dials
  nothing.

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
two feature gates; `share`, the share, the revoke, the re-share, the
privash and the lost answer over three keyed siblings; and `search/` — the class fence, the two principals'
separation and the events stream (`consumer`), `history_reclaimed` reached
through the daemon's checkpoint seam (`resume`), the orphan walk and the
forget (`directory`), the query crossing nothing and the jump's band
(`bridge`) — over a claimed board whose published text the attested shot
mints. Its unit suites pin what a composition sends and what it makes of
each answer with no daemon, over `board/fake.rs`'s fake board, which
answers each request by the test's own closure and keeps every request it
served; the search module's over a scripted board of its own
(`search/tests.rs`).

## The shell's core, `skep-shell`

`skep-shell` is the bridge of `client.md` §4b as a library — one method
per call of §4b.1, of the document index's listing `places` (A-255) and of
the change feed's page `changes`,
every event of §4b.2 on one stream — and the three things `skep-client`
does not hold and every shell needs, written once so the dev provider
(`skep-dev serve`) and the desktop shell share them and rewrite the
transport alone (the dev provider record §2.2, §6; ruled P-1 (B), P-2
(B1)). A transport reaches it through the crate root — `Shell` and
what opens it, `Refusal` and its `Name`, `Log` and its `CallOutcome`,
`Event`, its `EventName` and `UnknownEventName`, `Talk`, `CALLS` — and two
public modules, `script` and `shapes`; the rest is private. Its modules,
in the order `src/lib.rs` declares them, each naming only those above it —
an item the root re-exports counted as the module it is brought from
(held by `tests/it/tidy.rs`):

- `refs.rs` the reference registry's NAMES: board and session references
  minted from OS entropy per process, never a credential, never derived
  from an origin or a token (THE PIN); `BoardEntry`, one board under the
  reference minted for it.
- `log.rs` `Log`, the call and dial log the page's gate reads — sizes,
  routes and timing, never a token or a body — and `ShellDialer`, the
  one `PlainHttp` every board dials through, so no dial escapes the log,
  and none is made once the shell's stop stands.
- `events.rs` `EventBus`: the seven events as values, each named by an
  `EventName`, fanned out to every subscriber in order.
- `refusal.rs` `Refusal`, the one shape the page renders, each refusal
  with ONE name from `Name`, the closed list of every name the shell spells.
- `wire.rs` the wire's shared facts: the frame cap (`MAX_FRAME_BYTES`) and a
  frame's compact bytes (`json_len`), the tumbler component budget,
  `document_address`, a document address in its one spelling, and the
  value forms both ways (`values_of`, `delivered_values`).
- `attest.rs` `Composer`: the entry frame for the ten kinds, every axis
  from the shell's own reads, through `skep-identity`'s builders; the
  board's other budgets, each held before the work it bounds.
- `held.rs` the HELD-BURST STORE (`client.md` §3c): one append-only file per
  (board, principal), read line by line with P38's faces, each line synced
  before `op` answers `held`; `HeldQueue`, a principal's queue — its
  memory, the file its copy — within its lines' and its re-marks' budgets.
- `script.rs` the dev arm's SCRIPT: the grammar a script file's answers are
  parsed by.
- `dev_arm.rs` `DevArm`: the SECRET and CONSENT moments answered from a
  script or by the auto arm, each answer said on TALK, never sent to the
  page; the NATIVE statements said there too.
- `person.rs` `BridgePerson`: the PUBLIC moments as `moment` events
  answered through `Pending`, the SECRET and CONSENT ones and the NATIVE
  statements (`NATIVE_RULES`: those naming where key material rests) sent
  to the arm — or, where the run names none (`ArmConfig::Refuse`, a client
  with no person present), the SECRET and CONSENT moments refused there,
  `person_required`, reaching no arm and no page, and the NATIVE
  statements said on TALK in the arm's place.
- `sessions.rs` `Sessions`: the token beside the board it stands at, under
  its reference, the two openings — bare, which reads alone
  (`SessionEntry::may_write`), and signed — `SessionEntry::attest`, a
  session's END (`Sessions::end`, under the key store the table holds) and
  the release of its drafts supplement (`Sessions::release`).
- `hold.rs` `Holds`: the one path of every `/op` the shell sends under a
  session (`Holds::send`) — a burst's DOOR (`Burst::admit`) and its hold
  among it — its answers read through `classify`, the one owner of every
  reissue's bound, and the per-(board, principal) queue over `held.rs`'s
  file, each board's hold under its own lock.
- `hold/resend.rs` THE PROBE (`Holds::probe`) and THE RESEND: one
  `/changes` read per document before its first resend, §3c.5's three
  outcomes, the lines then sent in `k` order across the documents under a
  session of the principal's that may write, each through the hold's one
  reader.
- `feed.rs` `FeedThreads` and `Feed`: per board, the `/events` reader and
  the feed thread, its state the `Feeder` — the `feed`, `index`, `mode` and
  `daemon` events, the `search` call and the document index's listing
  `places`, the held-burst probe on its cadence and at every hand-over;
  and `changes_since`, the read behind the `changes` call — the same feed
  from a position a client names, two reads merged by position so each
  entry carries its class — on the caller's thread.
- `shell.rs` `Shell`: the boards, the sessions, `SessionMode`, `ArmConfig`
  (the auto arm, a script, or `Refuse`), the private
  row methods behind `call`, which logs each — a write in the guest form,
  and under a bare session, refused before any dial, the `session` answer's
  `writes` saying which; `fetch`, `answer`,
  `cancel`, `shutdown`; `ShellOptions` and `set_node_state`.
- `shell/ceremony.rs` the ten ceremonial rows — `keygen`, `fingerprint` and
  the eight walks over `skep_client::ceremony` — `pub(super)` to `call`.
- `shapes.rs` the declarations' table and `declarations()`, pinned by its
  suite.

Rules that hold across its files:

- **The page holds no token, no seed and nothing of the SECRET class.**
  The registry's names stand in for the token, the SECRET class stays in
  the arm with the NATIVE statements — each statement whose rule names
  where key material rests (§4b.3, the anchor file's ladder words among
  them) — and the log keeps sizes and routes alone. No answer, event or log
  entry the shell builds itself names a path or the store's location —
  `bind`'s warning carries the binding line and never the bindings file
  (`bind_warning`) — save `store_halted`, whose `path` follows §3c.3's face
  against §4b.3's rule until the owner rules between them. The faces the
  shell carries from `skep-client`, and the paper path's question whether
  to destroy an anchor file, still name the store's location or a key,
  anchor or index file — `skep-client`'s to build for the bridge, and
  listed once, in the crate README's §Where the library stops at this pin.
  The shell's suite reads every answer and event, the refusals it binds,
  and every log entry of its bare walk and its paper claim for the token's
  own text, every seed the walk made and the store's location, and finds
  none; the provider's suite (`skep-cli`'s) reads every answer, event and
  the log for a token-shaped run.
- **The board's verdict is carried verbatim.** A `rejected` document and a
  non-200 are `Refusal::Board` with the body whole — a non-200 read once,
  by `Refusal::board`, and an `/op-at` refusal `skep-client` answers as a
  value rebuilt into its status and error document and carried the same
  way. The shell names a refusal of its own only where the row arms one or
  where it diagnosed the armed name from typed reads — save `accept`,
  whose walk reports its three armed cases in its halt's words alone, read
  by one matcher (`accept_arm`) the suite runs against the real walk — and
  every such name is a constant of `refusal::Name`: the one list, closed
  by a private field, so a name spelled anywhere else does not compile.
- **One door per call.** Every call reaches its row through `Shell::call`,
  which logs it; the row methods are `shell`'s alone — private, or
  `pub(super)` in `shell/ceremony.rs` — so a transport cannot serve a call
  the log never saw. `Shell::fetch` is the one public row, because it
  streams; it logs its own call, the stream's entry written as its body is
  dropped, so a transport logs only the refusals its own seam answers.
  `tests/it/tidy.rs` pins `Shell`'s public methods across every `impl
  Shell` block of `shell.rs` and its non-test children; the compiler holds
  `call`'s dispatch to one arm per call, and `CALLS`, the list a transport
  admits a call by, is spelled from the same enum, so no name is listed
  that the dispatch does not answer.
- **A session ends once.** A death signal is met by two callers that end
  sessions — the shell on a call's thread, at its dial or at a read its
  attest composer made (`Unattested::Died`, no refusal of the composer's),
  and the board's feed thread on its own — and both run `Sessions::end`;
  the resend meets it too and runs no end, leaving its line standing for
  the session the end leaves behind. The entry's `OnceLock` is the gate:
  the caller whose initializer runs derives the reason, registers the
  restart arm's re-open and emits the one `session-died`; a caller that
  comes while it runs waits, answers that reason and does nothing else; a
  caller that panics mid-end leaves the cell unset for the next. A caller
  here is the code that meets the death; a hand stays the corpus's, the
  writer of a record or a row, as a retirement's reason names it. An entry
  leaves the table by that sequence or by `close`, and `Sessions` exposes
  no other removal.
- **A session's rows precede its death.** `close` takes the session out of
  the table, then has the board's feed thread read its drafts to the head
  under its still-standing token (`Feed::closing`, a round-trip to the feed
  thread) before the token closes and `session-died` goes out: every
  subscriber sees one sequence, however far the feed thread trails the
  commits.
- **One board's wait holds no other.** A call reaches a board's feed thread
  through that board's own handle, a channel, and waits on its own reply:
  no lock is held across the wait, so a search queued behind a board that
  is not answering holds back no call at another. The holds keep each
  board's hold under its own lock, so one board's synced appends and file
  reads hold back no burst at another; and a board's commits coalesce into
  one waiting read, so a board committing faster than its feed thread reads
  holds a call queued behind them to one read at most. A board's probe, and
  the resend it lets run, go on that board's feed thread alone —
  `resolve(send)` and `set_node_state(Running)` hand it over — so no caller
  waits on a resend.
- **The board's budgets, kept as the board keeps them.** Every cost the
  shell pays for a page's frame or a board's answer is held, before the
  work it bounds, to the budget the board's own parse, store or composer
  holds the same frame to (`wire.rs`'s and `attest.rs`'s constants, each
  pinned to the board's — by its export where it exports one, by its
  behaviour where it does not): a burst past the frame cap, a list past the
  wire's, an insert
  past its values, a tumbler past its components, a slot past its spans,
  a shot past its re-insert budget or its body, an origin past one
  delivery, and a hold that would carry the held queue past one frame's
  worth. A frame past one is a frame the board refuses whatever it carries;
  no budget of these is one the board does not keep. The held store keeps
  two of its own beside them (`held.rs`): the lines a hold admits
  (`MAX_HELD_LINES`), which bound the resend's walk over every queue its
  holds made, and its file's re-marks (`MAX_HELD_REMARK_BYTES`), which
  bound what a board's answers write to the disk — each argued there from
  the design's outage of hours of typing (§3c.3). Both queue budgets bound
  what a hold ADDS: a reopened queue is read whole, past either where its
  file is past it, and holds nothing more until it drains below them.
- **A burst the board takes at no send is never held.** `Burst::admit` is
  the one door a burst enters the hold by: a frame past the board's frame
  cap as sent or as a signed resend sends it, one naming no document in its
  one spelling, an insert a signed session cannot attest — each refused at
  the act, since its line could be sent and resolved never and would hold
  every later burst of its principal behind it. The held store's writer
  holds no line its reader would halt on.
- **Dropping a shell stops it.** `Shell`'s `Drop` runs `shutdown`, which a
  second time finds nothing left to stop: no feed thread, open session or
  `held/<chain>/` lock outlives the shell, whether or not its owner stopped
  it, and each board's `/events` reader, asked to stop, ends at its next
  read. The stop closes the moment table (`Pending::cancel_all`), so a walk
  that asks the page after it is abandoned at once, its moment never sent;
  then it closes the sessions and stops the feeds (§3c.6's order). A
  session's close a board does not answer is said on TALK, the stop's as
  the page's, its token dying at the board's restart. Once its sessions are
  closed the stop dials nothing (`ShellDialer`), so a board answering
  without end — pages whose `more` never ends — holds no stop past one
  exchange.
- **A principal's supplement follows its standing sessions.** The consumer
  holds one drafts supplement per (board, principal), and two tabs hold two
  sessions of one principal. A session that leaves the table — its end or
  its close — RELEASES the supplement (`Sessions::release`): handed to
  another session of the principal standing at the board, its token
  widened in, and narrowed only where none stands.
- **A bare session writes nothing.** The bare session is the keyless
  session for reading alone (foundations §3.3 state 3, E16 (a′): "no `bare`
  write ever committed by this client"): the `op` row refuses every write
  kind under it, the `/op-at` form's too, and its `resolve(send)` —
  `write_in_bare_session`, before any dial (`SessionEntry::may_write`) —
  as it refuses a write in the guest form; and the resend sends under a
  session of the principal's that may write alone, so a principal with no
  other session keeps its lines held. Its reads, `held(session)` and
  `resolve`'s `drop`, which commits nothing to the board, stand.
- **Attach when in doubt.** Every write of the ten kinds under a session
  that holds a key — the signed mode's — carries the attest the shell
  composed, signed by the key that opened the session; the daemon drops
  one outside the class. A frame the composer cannot sign is never sent.
  One composer, the daemon's twin: the bodies are `skep-identity`'s
  builders, and nothing here spells a row.
- **A moment is answered once, by the party the class names.** `Pending`
  removes an id at its first answer — an answer of the form its moment's
  kind takes (a label box a string, or `null` where the box offers a
  default, the answer then that default; a question a string; a yes-or-no
  a boolean), one of another form refused with the moment still waiting,
  so no walk is handed a value it must coerce; a cancel abandons; a walk
  that ends without its answer is `abandoned` to the page. A SECRET or
  CONSENT moment is the dev arm's — or, under `ArmConfig::Refuse`, where
  no person is present, no one's: refused at the person, the walk ending
  there `person_required`, so nothing is ever confirmed or typed on an
  absent person's behalf.
- **The declarations are pinned.** Every shape in the table has a sample
  the suite round-trips; a required field missing, or a built field
  undeclared on a shape the table does not mark `open`, is red, the
  declared call rows are the dispatch's `CALLS`, every optional argument
  member a row of one form declares is refused by name when sent in a form
  its type refuses, and the declared event names are rendered from
  `EventName`.
- **Persist first.** A `held` answer is a promise the disk already keeps:
  the burst's line is written and synced before `op` answers `held`
  (§3c.3, J1), so a crash after the answer loses nothing of it, and
  `shutdown` writes nothing of the store: a crash between any two steps of
  the stop loses at most the open or in-flight burst, R14's bound. A second
  shell on the same data directory finds the `held/<chain>/` lock held and
  writes nothing — its bursts answer `held` with `cause: other_window`, kept
  in memory alone and resent like any held line; a line whose copy the
  device refused, or whose file is out of reach, stands in the queue the
  same way, its answer saying why as `unwritable`.
- **One path for every session write.** Every `/op` the shell sends under
  a session, `/op-at`'s aside, goes through `Holds::send`, and its first
  dial and every resend read the answer through `hold.rs`'s one reader, so
  they never disagree on what a refusal means: a refusal the table holds
  nowhere is faced at the act and, on a resend, leaves its line standing —
  never `done`; a write the hold never holds faces what a burst's would
  hold; every ack is noted for the base where it is read. `write_busy` and
  a first and second `durability` are reissued within the call, every
  `/op` under a session alike — the page meets the ack or the next
  refusal, never `held` for one of them (§4b.1's `op` row) — and a third
  `durability` holds a burst; `classify` alone bounds them, so every
  reissue moves a write toward its bound.
- **An argument is its row's.** A call's required member absent or of
  another form, and an optional member present in another form, are
  refused `malformed_args` naming it before any dial; absent or `null`, an
  optional member is the row's default. Nothing a page sends is read as
  absent because it was spelled wrong.

Its suites are unit modules beside the code they test. `shell/tests.rs` and
its children run the shell: `door` the shell alone, with no daemon behind
it; `modes` the two session modes, `ceremonies` the ceremonial rows end to
end, `boards` each board's node, wait and stop, and `held` the held-burst
store, against a daemon spawned in-process over a temp data dir.
`hold/tests.rs` and its children `write` and `resend` drive the hold over a
fake board; the other modules test themselves over fakes and temp dirs;
and `tests/it/tidy.rs` holds the arrangement — the declaration order, every
file under `src/` declared by its parent's `mod` line, an inline test
module as its file's last item, the two public modules, and `Shell`'s
public methods. Each suite's module doc says what it holds.

## The command, `skep-cli`

`skep-cli` is two binaries over `skep-client` (`client.md` §1.2, §2): the
`skep` command, and beside it the dev binary `skep-dev`. The command
parses the command line, makes the library call — handing a walk the
terminal as its `Person` — and renders the answer, DATA on stdout and TALK
on stderr, with §2.3's exit code. Every ceremony is a library walk; `bind`
and `keygen` sequence the library's compositions themselves — `bind`
landing the three facts of an enroll hop, a handoff or a hosted signup,
`keygen` the door-side backup moment ahead of the device key's generation
and the payload it prints — and so carry their own text. Its modules, in
the order `src/main.rs` declares them, each naming only those above it:

- `args.rs` `Command`, one of the fifteen, the verb `main` dispatches
  on; the grammar — one row per command, its flags that take one value,
  those that repeat and its switches, and the rules its forms hold them to
  (`Form`), beside the flags every command takes (`GLOBAL`) — with `HELP`,
  the text that documents it; and `CommandLine`, one parsed command line
  (`Line<Command>`), its values lent to the commands that read them, its
  settings each read through `Line::setting`, the one place a flag beats
  its `SKEP_*` variable, with `session_env` the one setting no flag
  carries. Its `dev` module is the dev binary's grammar over the same
  machinery — `DevCommand`, `seed`'s row, the dev `HELP`, and `DevLine`'s
  readers of `--repo` (`SKEP_SEARCH_CORPUS`), `--pin`, `--from`,
  `--documents`, `--versions` and `--drafts` — kept in this file so every
  `SKEP_*` variable stays its own. Every setting the two programs read —
  its flag, its variable, its default, when it is checked and where it is
  read — is tabled in the crate's README §Settings, and each default the
  table and the helps state is a constant here (`CLAIM_PRINCIPAL`, the dev
  `DEFAULT_*`), which `args.rs`'s unit tests hold the table and the helps
  to.
- `terminal.rs` `Terminal`, the `Person` over the terminal: every prompt on
  stderr, the sheet as a ruled box, the dismissal's clear, the anchor
  import's arm asked of the person and never guessed from what was typed —
  each moment written once, in `moment`, against a `Screen` that says its
  lines and reads its answers, which the `Terminal` is over the std streams
  and the module's unit tests over a script; `has_terminal`, the person
  doors' check; `talk`, the one writer of a line on stderr — the prompts'
  headings, every command's TALK and its halt — and `show`, a prompt's
  text and the sheet, each through `write_inert`, which renders its text
  inert before stderr sees it, and `clear`, the dismissal's one escape;
  and `answer`, the one reader every prompt goes through, stdin locked for
  that one line alone — the `Terminal`'s, and those of `bind`, which is no
  person door: its account paste and its landing question.
- `shared.rs` what both binaries share: DATA's writers (`data`, its line
  rendered by `c0_inert`, and `data_verbatim`), the stops and their exit
  codes (`Stop` — a usage refusal, or a member of the halt family — which
  `finish` renders under a `Program`, the name a stop's block opens with
  and the help a usage refusal prints beneath it, and a halt's act beneath
  it where the library's rendering names none — a transport halt's, by
  where its exchange broke, a retry-class `503`'s, and a write refused
  `poisoned` (the restart, room before it at a full volume) or
  `durability` (the room alone, no restart owed) (`act_beside`);
  `help`, `--help`'s DATA), and the plumbing from the flags to a board
  (`board_of`), a store (`store_of`), a principal (`principal_or_bound`,
  §3.5's one-binding test, whose halt names the store and the origins its
  bindings name) and a key (`select_key`, under `Purpose`) — a key file
  refused where a walk takes none (`require_no_key_file`).
- `commands.rs` what the fifteen commands share among themselves alone:
  the `skep` `Program`'s `finish` and `help`; `require_terminal`, the
  check each `Door` makes; a payload read to its cap (`read_payload`,
  `MAX_PAYLOAD_BYTES`); the anchor boxes' per-run default (`BoxDefault`);
  the three facts' one spelling (`print_facts`, the lines `bind` reads
  back from a reply); a landed binding line said as the store reads it
  back, else how to record it by hand (`binding_said`); the
  outstanding-act line `keygen` and `fingerprint` share; and the
  whole-set compare from the held set to its halt (`held_set`,
  `compare_genesis`). Beneath it, `commands/<name>.rs`, one
  file per command, each the
  `pub fn <name>(&CommandLine) -> Result<(), Stop>` that `main`
  dispatches to, taking the shared names through `super::` as it always
  did.

The dev binary's root is `src/dev/main.rs`, declared by the manifest's
second `[[bin]]`, `skep-dev`. It declares `args`, `terminal` and `shared`
by `#[path]` from the files above — the same modules, compiled into both
targets, so a flag beats its variable and a stop renders in one spelling —
and then its own, in dependency order: `manifest.rs`, the manifest beside
the key store (`<store>-seed/<chain>.jsonl`, keyed by `H.1`'s chain, one
JSON line per write by its envelope id, appended after the ack, so a
second run adds nothing and a killed run resumes — making again the one
write it had in flight, which a new session's envelope id does not
recognise, as the stopped run and the resumed one each say, naming its
envelope id — and a torn last line, a stop inside the manifest's own
write, cut away before the resume's first record); `board.rs`, the frames
over the claimant's ONE content-scoped signed session — the staging
draft's mint, the chunked per-byte insert, the attested edition mint, the
shot naming the draft, the attested `make_link` whose V-spec from-end is
resolved through `image` into the spans the daemon stores, the reads, and
the retry of `write_busy`, `durability` and
`attestation_invalid:board_unavailable`, each stall said as it begins and
at most once per ten seconds after; and `seed.rs`, the run — the
inputs as the command finds them, the checks before any write (an
unclaimed board, `writes.halted`, a stranger's claim), the cut through
`skep-corpus`, and the shapes in order: editions, citation links with
ghosts for outside names, rotated second versions with the window on the
first edition's shot, drafts, a keyless second account — ending in one
JSON object; and `serve.rs`, THE DEV PROVIDER — `skep-dev serve` — with
its modules beneath it: `serve/http.rs`, the provider's own HTTP over the
plain subset `skep-http` serves (one request per connection, the head and
the body each under a cap its caller hands in) — the timeouts, the two
caps it reads a request under, the event stream's framing, and the CORS
headers for the one origin and never `*`; `serve/admission.rs`, the check
every request passes before any dial — the peer loopback, `Host` the
listen address, `Origin` the one page origin, the per-run secret in the
`Skep-Provider` header or the event stream's `?provider=` query;
`serve/node.rs`, the daemon's two modes — a running board dialed, or
under the crate's `dev-hooks` feature the daemon in-process with its test
hooks and the fault doors
`/bridge/fault/<door>` reaches; and `serve/routes.rs`, the routes over
`skep-shell`'s core — `POST /bridge/<call>`, `GET /bridge/events`, the two
answers, the log, the shapes, the script seam, the fetch stream. `skep-dev
seed` dials a RUNNING board the person started per `RUNBOOK.md` §3 (with
`--origin`, so a signed session is admitted) and claimed with `skep
claim`; it never claims, and it takes none of `tls`, `search` or
`test-hooks`. `skep-dev serve` takes `search` through `skep-shell`, and
`test-hooks` through `skepd` under `dev-hooks` alone — the default build
and the sidecar's `--no-default-features --bin skep` build carry no
`skepd`, which `scripts/gate-full.sh`'s isolation line and
`tests/it/serve.rs` hold; it stops when its stdin closes, the one clean
stop the verb has, read by `watch_stdin` and said with its cause, the
shell's stop run before the connections are joined so a call parked on a
moment is cancelled and answers — an interrupt ends it with none of that,
as its serving line says — and each refusal it makes itself, the
admission's or a request it cannot read, is
counted, and said on its stderr the first time its kind is met, the stop
saying the counts. The `[[bin]]` carries
`test = false`: the shared modules' unit suites run once, under `skep`,
and the dev binary's own claims are its integration fences,
`tests/it/dev.rs` and `tests/it/serve.rs`.

Rules that hold across its files:

- **stdout carries data, and no write panics.** Only `data` and
  `data_verbatim` write to stdout, `--help`'s text among it, and a write
  stdout refuses is a halt (exit 3) naming the refusal; every prompt,
  warning and halt goes to stderr through `talk` or the terminal's
  `show`, whose `write_inert` drops a write stderr refuses. No std print
  macro — each panics on a write its stream refuses, an exit 101 §2.3 does
  not have — stands in `src/`. `tests/it/tidy.rs` checks it, and
  `tests/it/cli.rs` runs a command whose stdout has no reader, and one
  whose stderr has none.
- **What reaches the terminal is inert on stderr, and C0-free on
  stdout.** Every TALK line and prompt is rendered line by line in
  `write_inert` — every character AUTH-5.2 names, a control character (C0,
  DEL and C1) or a bidi control: `render_inert`'s rendering and the C1
  controls its set leaves out — and the dismissal's clear is the one escape
  written, a constant. A DATA line renders every C0 control, the line
  break among them (`c0_inert`) — a record's encoder escapes exactly those
  (AUTH-2.130 clause 3), so a record passes whole, and DEL, a bidi control
  and a C1 control stand on stdout as a label in it carries them. So a
  control a board, a reply or a file chose acts on no terminal through
  stderr, and through stdout forges no line and opens no 7-bit escape
  sequence. `tests/it/tidy.rs` confines stderr's handles to `write_inert`
  and `clear`, and `tests/it/hostile.rs` runs the binary against boards
  answering 7-bit and 8-bit escapes.
- **What a third party hands in is recognized whole, then used.** A
  payload argument is read no further than one byte past
  `MAX_PAYLOAD_BYTES` — a record at its cap (AUTH-1.18) and its line
  ending — and halts past it; a reply `bind` lands shows as it reads, line
  by line, names each fact as its name and one value, and names a fact
  once, a second value — a line's, a flag's or a variable's — halting
  naming both; a principal is at most `2^53 − 1` (AUTH-6.36), at the flag
  and in a reply. `tests/it/hostile.rs` checks each.
- **A prompt holds stdin for one line.** Every prompt is read through
  `answer`, which locks stdin for that line alone, and the only other
  reads are a `-` argument's, whole, in `read_payload` and
  `session --close -`; so no prompt holds stdin while a payload or a token
  is read. `tests/it/tidy.rs` checks it.
- **A person door checks for a terminal first.** The eight doors —
  `claim`'s notebook arm, `keygen --anchors`, `enroll` without `--reply`,
  `recover`, `retire`, `rotate`, `handoff --payload` and `accept` without
  `--reprint` — each call `require_terminal` before anything is generated
  and, without one, halt (exit 3) naming the moments a person answers at
  that door; the check is the CLI's, never a walk's (§2.4). Every usage
  refusal of its command line — a required flag missing, a setting given
  badly, a key file its walk cannot take — is judged ahead of it, so it
  answers exit 2 whether a terminal stands there or not.
  `tests/it/cli.rs` and `tests/it/ceremonies.rs` run every door without a
  terminal, and `tests/it/ceremonies.rs` runs one under a pseudo-terminal,
  where it opens only with stdin and stderr both a terminal.
- **The settings are `args.rs`'s, and every one is tabled.** Every `SKEP_*`
  variable is read there and nowhere else, and every variable the source
  reads at run time — those and the host name's and the temp dir's — is a
  row of the crate's README §Settings, both of which `tests/it/tidy.rs`
  checks; a session token is never an argv value — `session --close -`
  ends the token in `SKEP_SESSION` where it is set, stdin then unread, else
  the one read from stdin, and says which token it ended where the variable
  answered — which `tests/it/cli.rs` checks.
- **A command answers `Ok` or a `Stop`.** It names every stop with `?`,
  and `main` — its dispatch one arm per `Command`, which the compiler
  holds exhaustive — exits with `finish`'s rendering of it, a command
  line it cannot parse and `--help` included; no command picks a
  renderer or a code, nor ends the process. `commands.rs`'s unit test
  holds each stop to its code, and `tests/it/tidy.rs` checks that only
  `main` exits.
- **A command takes its own flags, in the form that reads them.** A flag
  its row does not name is refused, as is a second value of a flag that
  takes one. A flag that belongs to one form of its command is refused
  outside it, two flags of two forms are refused together, a flag that
  names one value inside a form is refused a second, and the backup
  moment's flags are refused past its two anchors — so no row flag reaches
  a run whose form drops it. The flags §2.2 declares at every command
  (`GLOBAL`, `--json`) are taken at each and read where `HELP` says, as
  §2.2 has `claim` say of `--key`; `accept --reprint` takes the
  `--account` §4c.1's synopsis requires and reads it nowhere. A flag's
  value that is empty, or is itself one of the grammar's flags, is refused
  — what a wrapper's unset variable leaves on its line, which read as
  absent would fall to a default the line never named and read as given
  would name the working directory — where a variable set empty is unset;
  `-` stands. An argument that is not UTF-8 text is refused as a
  variable's value is, never a panic. `args.rs`'s unit tests check it,
  that `HELP` documents every flag a row names, and that every flag `HELP`
  shows parses in its form; `tests/it/cli.rs` runs the binary on an
  argument that is not text and on flags given empty, and
  `tests/it/ceremonies.rs` on flags outside their form.
- **A setting refused is never a setting absent.**
  `CommandLine::principal`, `CommandLine::origin_given`,
  `CommandLine::key_file` and `session_env` answer `Err` for a value given
  badly — a variable whose value is not UTF-8 text among them — and
  `Ok(None)` for one given nowhere; every command returns the `Err` as
  exit 2 before any read, and only the `None` reaches the store's
  one-binding test, its lookup or a prompt. `tests/it/cli.rs` checks it.
- **Imports point down.** A module names only the modules `src/main.rs`
  declares above it, and an item by its home module, never through the
  root; a command file names what the commands share through `super::`.
  `tests/it/tidy.rs` checks it, and that every file is declared.

Its integration suite is one binary, `tests/it/`: `cli`, the first seven
commands and the loop over the hosted claim, and `ceremonies`, the six
ceremony commands and the enroll hop, each driving the built `skep`
through argv, stdin and stdout against a daemon spawned in-process;
`hostile`, what arrives from outside the person's trust — a board's
escapes, a reply saying two things, a payload past its cap, a principal
past the wire's range; `dev`, the dev binary driven against a corpus the
suite builds under the system temp dir — a git repository of a few `.md`
files with cites among them — over a board it spawns and claims: a guest
reads every edition byte-exact, every link resolves at both ends and the
ghost answers `doc_not_registered`, the versions differ as each arm says,
the drafts answer the claimant and are withheld from a guest with the
windowed run withheld to the width, a second run adds nothing, a run cut
short resumes, the refusals halt before any write, the insert frame the
seed shares with the search budgets is one size, and a `--bin skep` build
yields one binary; `serve`, the dev provider driven as the page would
drive it over loopback HTTP with the admission headers — every call of
`client.md` §4b.1 and the document index's listing in the bare mode, its
writes refused before any dial, the events on the stream, the claim's
PUBLIC moments answered and cancelled through the bridge, the admission's
refusals before any dial, the signed mode's attested publish-class write,
the fault doors under `dev-hooks`, the isolation of the shipped builds
from `skepd`, the declarations served, and the conformance of the crate
and the provider over one sequence; and `tidy`, the arrangement above over
both roots, read off the source.
`common` holds the spawn — alone,
or behind a tap that keeps what a client put on the wire — a canned board
that answers whatever bytes a test chose, and the runs, every setting's
variable (`VARIABLES`, the one list `tidy` holds `src/args.rs` to) and
`HOME` cleared from them by the one `scrub` every suite's runs share,
`skep`'s and `skep-dev`'s alike: piped, with stdout or stderr closed, from
a chosen working directory, or under a pseudo-terminal; and `tree`, a
directory's state, for the commands that write nothing.

## The provisioning service, `skep-provision`

`skep-provision` is one binary, the service behind a hosted board's
sign-up (the deployment notes §4, step 1): a plain program on the VM in
the `docker` group, the proxy forwarding the sign-up's domain to it. Its
`serve` verb serves two pages over the plain HTTP/1.1 subset — the
sign-up page, which keeps an email address, and the claim form, which
takes a board's name, the person's record and an invite code — judges a
post in process before any `docker` call, and provisions each admitted
post on one of a pool of workers through the host's `docker`: a fresh
volume, labelled as this service's, the claim run bound to its own
loopback, the sidecar's dark claim in that run's namespace, the serving
run on the bridge, and the `/health` pair read through the sidecar's
`skep health`; then one snippet in the proxy's directory and the proxy
reloaded, the status live, the invite spent and the reply mailed. Its
address bound, and before it serves, it sweeps away every board a stop
left half-made. Its `invite`
verb mints one invite by the owner's hand and prints the invite link
that carries it. Its modules, in the order `src/main.rs` declares them,
each naming only those above it:

- `scratch.rs`, for the unit suites alone, a scratch directory removed
  when dropped.
- `urlform.rs` the form's body decoded strictly — `+` a space, `%XX` the
  byte, a `%` without two hex digits refused, a fourth field refused — its
  values kept as bytes.
- `whole.rs` a kept file changed durably: replaced whole by rename from
  its `<file>.tmp` — made fresh where nothing stands at its name, so the
  write follows no link — at the mode its owner names, set exactly, or
  removed — the directory synced either way, an error from that sync
  coming after the rename or the removal, never before it.
- `process.rs` a child process run to its end: `Exit`, what it answered,
  and `run`, which sets the child's streams — the input on a pipe written
  by a thread of its own, or a null stdin — and reads stdout and stderr
  apart; a feeding thread the OS refuses is the call's error, its child
  ended, never a panic.
- `wait.rs` a bounded wait: `Wait`, this many tries this far apart, and
  the tries paced by it — a sleep before each but the first, never after
  the last — the `/health` read's, the dark claim's and the mail's.
- `rates.rs` the rates a line is said at, `skepd`'s shapes: `Edge`, a
  condition that recurs said once as it starts and once, with its count
  and its span, a hold-down after its last meeting; and `Stretch`, an
  event a stranger drives said at most once a minute, the count of like
  ones riding the next one said.
- `domain.rs` a domain, as `--suffix` takes one — lowercase letters,
  digits, dots and hyphens, its labels non-empty and none beginning or
  ending with a hyphen — its alphabet in words for a refusal to name, and
  `Domain`, the one value a suffix is taken in as.
- `name.rs` a board's name: its grammar, one lowercase label Docker takes
  as a name alone — two bytes at least, none a container's hosts file
  answers, never hex digits alone, which a container command reads as an
  ID's prefix — and the board's host and public origin under the suffix,
  from which every `docker` call, the snippet and the reply are built; and
  `Name::exact`, a name read back as this service wrote it — a snippet's
  stem, a labelled volume — never lowercased.
- `record.rs` the record's admission: the hosted walk's trim,
  `parse_enroll`, the walk's preview-kind test copied, the hosted
  genesis's two refusals copied from skepd's credential precheck — every
  key's halves decoding (`skep-signature`'s `key_decodes`), sixteen entries
  at most — and the anchorless fact.
- `mail_address.rs` a mail address by the rule — one `@` with a side each
  way, at most 254 bytes, ASCII alone, none of RFC 5322's specials but `@`
  and `.` — its words for a refusal to name, and `MailAddress`, the one
  value an address is taken in as.
- `invite_code.rs` an invite code — 1 to 128 of the URL's unreserved
  characters — and `InviteCode`, the one value a code is taken in as.
- `docker.rs` the `Docker` trait — `run`, the one method a runner writes,
  and one named method per call provided over it, the listing of the
  labelled volumes among them; `Call`, one call as data, whole, the dark
  claim's admitted record carried with it, and `Call::argv`, every call's
  argv as a pure function, both runs of the image opening with one
  hardened prefix, the volume's creation carrying the label, and a failed
  run's last lines read before its removal;
  `HostDocker`, the host's `docker`, its `Command` built from that argv
  and run by `process::run`; and under `test-hooks` `docker/fake.rs`, the
  scripted fake, its order strict per name and free across names.
- `sidecar.rs` the sidecar's six DATA lines and its one idempotent line,
  read, and its exit codes mapped.
- `health.rs` the pair off `/health`'s body and its wait, over a `Wait`,
  and the pair said as a body answered it where the wait gave up.
- `caddy.rs` the snippet's text, its write and its removal through
  `whole` at `0644`, whether it stands, the reload, the routed names,
  read off the snippet directory, and the start's probe of its write.
- `names.rs` the truth about names — the snippet, the volume, the
  container — the status token, and the labelled volumes sorted against
  the snippets into half-made, routed and ungrammatical.
- `statedir.rs` the state directory's door — a loose directory refused,
  and one another user owns, a probe telling — and a lock file in it held
  at `0600`; the state files' one writer, `whole`'s replacement at
  `0600`; and the date the two files' lines carry.
- `signups.rs` the sign-up file, capped at 256 KiB, the stretch at its
  cap counted under its own lock, and its fill for the start to say.
- `invites.rs` the invite file — mint, look up, spend — under a lock file
  across processes, and the names its lines are spent under, which the
  sweep holds the boards routed at start against.
- `strings.rs` the strings table: every sentence a person reads, each row
  naming its id.
- `pages.rs` the four pages' HTML and each request's dispatch, by method
  and path, over `skep-http`, the request in and the answer out each under
  a deadline of its own, each page asking a `Desk`; the two URLs the
  service hands out, the invite link and a post's status URL; and
  `Accepts` and `Serving`, the accept pair and the pool pair the
  connection threads share, each an `Edge`.
- `sender.rs` the `Sender` trait, `RelaySender` — the relay client
  `--mailer` names, shelled out to, and whether it can be run, asked at
  start — the message, and the outbox: the
  sender's own thread with its retry, a `Wait`, the hand-over said with
  the mails ahead of it, and the follow-up mail's `From:`, `Reply-To:`
  and subject, held for every board; a refused try said by its exit code
  and that code's `sysexits.h` name; `Log` and `Sleep`, the log and the
  sleep every thread of the service is handed, and the board a thread
  works on, which the panic hook's one line names — kept here as the
  first module that takes them; under `test-hooks` `sender/fake.rs`.
- `reply.rs` the live reply, one function for the page and the mail.
- `flow.rs` the `Service` — the `Desk` the pages ask: a sign-up kept, a
  post admitted, a status read; the `Book` of what is in flight and of
  every post's state, keeping its own rules: the queue, its status map
  (`flow/status_map.rs`) — rebuilt at start from the snippets — and the
  held codes — a post's own among them while it looks at what stands, one
  look per code — what blocks a new post, what admitting, taking, going
  live and failing do; the name as the unit of exclusion, the workers' steps,
  the route lock, the cleanup table and the truth asked what stands after
  it, the sweep at start, and the live reply's inputs gathered in one
  place for the status page and the mail.
- `args.rs` the verbs and the flags, every default a named constant,
  the build and `version_line`, the settings the start says, and the
  usage text.

Rules that hold across its files:

- **It holds no key.** The record it takes is the person's public line,
  parsed by `skep-identity`, whose types cannot carry a private key (I1,
  AUTH-2.89), its keys' halves decoded by `skep-signature`'s verify-only
  build, which holds no signer; and the sidecar it runs signs nothing. What it does hold is
  the Docker socket's reach, through the host's `docker` command; the
  sign-up addresses; and the invite file — the last two in its state
  directory, owner-only and refused at start where other users can read
  it or where another user owns it.
- **The name is the unit of exclusion.** A name is held from its post's
  admission to its live or failed end — the owner's lock per name, an
  entry in the book that no thread waits on — and a second post for a
  name in flight is refused under the book's lock, the very lock that
  admits, so no two posts for one name are ever in flight and the worker
  that takes a post owns its name alone. No mutex is held over a
  provisioning: a pool of worker threads (`--workers`) makes boards for
  different names at once, and posts wait in a queue whose depth is a
  constant, `QUEUE_DEPTH`.
- **A post never waits on a provisioning.** Its checks against what is in
  flight and its admission run under the book's short lock on the status
  map, the queue and the held codes — the admission checking what is in
  flight again, and the invite again, under that lock — and its three
  reads of what stands under its name take no lock at all, four posts' at
  most at once and one per invite code, a fifth answered D-8 with no
  `docker` call; none waits behind a board being made, and a status page
  waits on nothing either.
- **Connections are a pool, and slowness ends.** `--connections` threads
  each take the next connection off the listener, a further one waiting
  in the listener's queue; both pools are made at start, no thread is
  made per connection, and one the OS will not give ends the start,
  exit 1. An `accept` that fails is said once per episode
  across the threads, and its recovery once, `skepd`'s accept pair; the
  pool standing full is said the same way, once as every thread serves
  and once a thread has stood free a hold-down after, with how often it
  filled. A request in and its answer out each have a minute, checked
  between socket calls, so a client that trickles its bytes is cut off
  rather than holding a thread. A panic answering one request costs that
  connection alone, a step or a cleanup that panics fails its post, and a
  send that panics gives up its own mail: no thread either pool or the
  sender made is ever lost to one; and each is said in one line by the
  binary's own hook, the board the thread was on named.
- **A stranger's bytes buy a bounded bill.** A decoded form holds at most
  three fields, so it never holds more bytes than were sent; the sign-up
  file holds at most 256 KiB, past which a sign-up, which needs no
  invite, is refused with no write — the cap said once for its stretch,
  and its end once with the count; and the log is bounded too, through
  `rates`: a refusal no invite bounds is said at most once a minute with
  its count, and a failure met at every request once as it starts and
  once as it ends, so no stranger's flood drops or rotates away the lines
  a board's failure is read from.
- **A start says what it runs, and refuses what would fail later.** Its
  first line is its version; above the serving line it says the settings
  every board is made with and the sign-up file's fill. A state directory
  another user owns, a second `serve` over it, a `--mailer` that cannot be
  run, a snippet directory it cannot write and a port another process
  holds each refuse the start before the sweep, one line naming the cause
  and the act — never a failure met at the first board; and a flag's
  value no board could take — a log size of nothing, an empty path — is
  refused at the parse, exit 2, which the unit never restarts. What the
  start does not check — that the images, the bridge and the proxy's
  container stand, that the relay client is configured — the settings
  line names for the operator to read before a board meets it.
- **The command line is the one home of every setting.** The service
  reads no environment variable for one, so the unit's `ExecStart=` holds
  them all, each read once at start; every default is a named constant
  the usage text renders, and the crate's README's flag table is read
  back against the usage. A setting fixed into each board at its making —
  the image, the bridge, the suffix, the log rotation — reaches the
  boards made after a change alone. The figures the design fixes are
  constants, each carded where it is defined, and no flag sets them.
  `tests/it/tidy.rs` checks that no file under `src/` reads an
  environment variable but `PATH`.
- **Route changes are serial.** One lock, the route lock, is held across
  a route change — a snippet's write and the reload that follows it, and
  where either fails, on across the snippet's removal and the reload that
  undoes it — and nowhere else, so no reload lands between another name's
  snippet and its own, nor loads a snippet whose own route change failed.
- **A stop leaves no name taken for good.** Every volume the service
  creates carries its label, and at `serve`'s start — its address bound and
  its `serve.lock` held, and before it serves — every labelled volume under
  a name of the grammar with no snippet — half-made — is removed by the
  cleanup table's last two rows, the truth asked what stands after; a name
  whose snippet stands is left, a snippet with no labelled volume behind
  it is named and left, a routed board with no invite line spent under it
  is named and left, its invite maybe still issued until the operator
  marks it, and a listing — named on a line of its own before it is made,
  so an Engine that never answers leaves that line the start's last —
  that fails skips the sweep, says what the skip leaves taken, and never
  stops the service; a sweep that listed ends on one line of what it
  listed, cleared and left INCOMPLETE, and the time it took. The
  snippet directory is the list the sweep spares: a start over an emptier
  one removes every labelled board it lacks. Its precondition is the
  operator's: one `serve` per Docker host, for the label is the same on
  every `serve`'s volumes, and a second service would take the first's
  boards for half-made; a second over the same state directory or on the
  same port is refused before its sweep, and one under another of each the
  operator keeps from starting. Its second, no post of this service's in
  flight, its type keeps: it takes the service by `&mut`, so no worker or
  connection thread holds the service while it runs.
- **The argv is the documents'.** Every `docker` call's argv is a pure
  function the unit suite pins token by token, and reads back from
  `scripts/docker-smoke.sh`, `README.md` and `RUNBOOK.md` — the line an
  operator makes a standing board's serving run again by — where those
  spell the line, and from the `Dockerfile` the port and the volume the
  image bakes; the real runner builds its `Command` from that argv and
  nothing else.
  The runner and the fake write one method, `run`, and share every named
  call over it, so each suite that drives the fake drives the mapping the
  host runs.
- **The acts are the command's.** The reply's two acts are `skep claim
  --hosted`'s own act lines with the public origin; the reply's suite
  reads them back from `skep-cli`'s `src/commands/claim.rs`, so an edit
  there is a red test here.
- **One writer, one runner, one wait.** Every file it keeps is replaced
  whole by rename, or removed, through `whole`, at the mode its owner
  names — the state files `0600`, the snippets `0644`. Every program of
  the host's it runs — `docker` and the mailer — runs through
  `process::run`, which sets the child's streams: the input on a pipe of
  its own or a null stdin, never the service's own. Every try it makes
  again — the `/health` read, the dark claim, the mail — is paced by a
  `Wait`, a sleep before each try but the first and never after the last.
- **One door per value.** An address is taken in only as a `MailAddress`,
  an invite code only as an `InviteCode` and the suffix only as a
  `Domain`, each in a module that holds it and its rule alone — as a
  board's name is a `Name` in `name.rs` — so its rule's one constructor is
  the only way to one any other module can write; each is made at the
  door — `args` for the flags, the desk for the claim post's field, the
  sign-up file for its field — so what keeps or carries it — a file's
  line, the snippet, a URL — is handed nothing it cannot carry and checks
  nothing again, and no other string of a code's shape, a status token
  among them, can stand in for a code. The invite file's lines are read
  back as the operator's hand may have left them: a code out of the
  alphabet matches none taken in, and an address reaches the mail's `To:`
  as its line holds it.
- **What stands is the truth about names.** A name is taken iff its
  snippet, its volume or its container stands; no ledger is kept, and
  the log carries the history. A failed step's makings are undone in
  reverse and its status is D-8 — a failed run's last lines logged before
  it is removed, the board's own account of the failure — then the truth
  itself is asked what stands, as it is after each of the sweep's
  removals — never the removals' answers, for a refused `rm -f` may be of
  a run that never stood — and the log says done, or INCOMPLETE naming
  what stands, which refuses re-posts until the operator clears it — a
  volume left with no snippet the next start's sweep's too — or naming the
  look that could not be made by its source, `docker` or the snippet
  directory.
- **The log never carries** the record whole or a key of it, a person's
  address, an invite code or a status token, and the `Debug` of every value
  that holds one — a record, an invite, a message, an address, a code, a
  post, a decoded form, the status map, a status page's reply, a page —
  shows none of them. The sidecar's stderr, which the log keeps whole,
  names each entry of the record by its fingerprint and its label, the
  person's own words, already on the board with the record; and a panic's
  line carries its message only where it is a literal the code wrote,
  never one a request could have formatted.
- **Every person-facing sentence is in one table**, `strings.rs`, each
  row naming its id, and the live reply is one function, its inputs
  gathered in one place, so the page and the mail cannot say two things.
  A row names only slots the place that shows it fills — every page the
  site's two, the suffix and the owner's address — and one shown where a
  slot it names is not filled fails the test that renders it.
- **Two fakes, under `test-hooks` alone.** The scripted Docker runner
  fails a test on a call it did not expect; the mail fake appends what it
  accepts to a file. No shipped build enables the feature, and every test
  build does, through the crate's self dev-dependency; so
  `scripts/gate-full.sh` checks the binary without it (`cargo check -p
  skep-provision --bins`) and runs it: there `--docker-fake` and
  `--mailer-fake` are unknown arguments, exit 2, and the usage names
  neither.
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
`skep-provision` under `test-hooks`: `invite` mints a code; `serve` runs
on an ephemeral loopback port over the two fakes and a temp state
directory; a browser's requests reach the live reply at the status URL,
the snippet written and the one mail sent; every refusal answers as the
strings say; a start again after a stop counts the board live, its status
URL a 404 that says a restart ended it, its spent invite still refused,
and a start after a kill serves; a half-made board is swept before the
serving line; a connection past the pool waits in the listener's queue
until a thread frees, the pool standing full said, and one within it is
answered beside a held one; an `accept` at the open-file limit is said
once however many meet it, the service serving on; the boards
`--workers 2` names are made at once, and no more; the serving line is
the RUNBOOK's, field for field, with mail and without, and above it the
version, first, the settings every board is made with, the sweep's
listing named before it is made and its summary, the RUNBOOK's too; the
sweep's listing, run by the host's runner through a `docker` on `PATH`,
reads nothing of the service's own stdin; a start refused — a second
`serve` over one state directory, a `--mailer` that cannot be run, a
snippet directory that cannot be read or written, a port held, each
before the sweep — or an invite not minted, exits 1 with no DATA line;
and SIGTERM ends the process. Beside it, `tests/it/tidy.rs` reads the
arrangement off the source and the manifest: the module order, the
declared files, every `pub` item's doc, the five dependencies, and the
one environment variable read, `PATH`.

## The name space, `skep-namespace`

`skep-namespace` is the one minting authority. Every address a transaction
creates — account, document, version, content, link — comes off one of its
five mints, and every store that mints or writes under a chain
(`skep-arrangement`, which places content and forks versions, and
`skep-links`) holds a lock key M3 built. It also holds who exists, who
owns what (ω, the longest seated prefix) and each document's publication
bit, all in one slice, `M3State`. Node addresses come from provisioning
and are only admitted. Its modules are declared in `src/lib.rs` in
dependency order, each with a line saying what it holds. `record.rs` is the
journal delta, `M3Rec`, with its two field doors and the identity type it
names; `state.rs` is the slice — `M3State`, genesis, the fold and the
frontier arithmetic; beneath it, `state/mint.rs` holds the lock keys, the
five mints (§A) and the two peeks — `next_account_prefix` and
`next_content_address`, each its chain's mint without the record, kept
beside the mints they call so the two files depend one way — and
`state/query.rs` every other query (§C). Its `test-hooks` feature (default
off) compiles in `M3Rec`'s three test constructors, the one way another
crate's suite constructs a record without decoding one;
`scripts/gate-full.sh` runs its doctests — the `compile_fail` pairs on
`M3Rec` that pin the seals a foreign crate meets.

Rules that hold across its files:

- **A mint is a query, and its caller commits it.** A mint returns the next
  address with the one `M3Rec::Allocate` that realizes it. The caller takes
  the paired `*_lock_key` for the transaction, mints off that transaction's
  working state, and pushes the record in it before its next mint on the
  chain. That record is the only thing that advances a frontier, and the
  caller pushes it exactly as the mint built it: `Allocate`'s payload,
  `Allocation`, keeps its fields private, so no caller rewrites the address
  it carries. A mint whose record is dropped hands out the same address
  again, and nothing reports it; a record pushed anywhere else is stale and
  issues its address twice, refused only by a debug build's fold.
- **An account is minted only with its seat.** `delegate` is the only op
  that allocates an account: it stages the account's `M3Rec::Allocate` and
  its principal's `M3Rec::RegisterPrincipal` in one transaction, and genesis
  folds its one account the same way. So a registered account is owned at
  exactly its own prefix, and so is every document in it — its owner
  account, which `M3State::account_seat` reads by one lookup. The fold
  checks neither half, and only this crate constructs a record, and no
  other edits one past its doors — `M3Rec` and `RegisterNode` are
  `#[non_exhaustive]`, as `M5Rec`'s and `LinkRec`'s variants are, and the
  payloads of `Allocate` and `RegisterPrincipal` keep their fields
  private — so a second path that allocates an account, or seats a
  principal, is one inside it and owes the other half. A record decoded
  from bytes rather than built here owes both halves too, and no door
  checks them.
- **A namespace has one spelling.** `NsKey`'s fields are private to
  `src/ns.rs`, so every frontier key, and every chain lock key encoded from
  one, is built there. The two registry keys are M3's own, crate-private.
- **No mint lands in the ghost region.** `skep-links` builds its reserved
  type addresses from `ghost_position`, and `src/ghost.rs`'s floor keeps the
  allocator past them on every board.
- **Elements come off two chains, and no third.** A document's content
  chain issues `d·0·1·n` and its link chain `d·0·2·n`, both built in
  `src/ns.rs`; no chain is anchored at any other subspace, and
  `M3State::next_in`, where every minted address is computed, refuses to
  issue any other element. Type names are spelled in subspace 3 — the
  commons vocabulary's in the ghost home document's — and rest on it, so a
  third element chain is a format change those names must move ahead of.
- **The slice's shape is its format.** `M3State`'s fields, `M3Rec`'s
  variants and the fields of `Allocation` and `Principal` are appended,
  never inserted or reordered: bincode writes fields in order and variants
  by index, and writes `Allocate` and `RegisterPrincipal` over their
  payloads exactly as it would struct variants carrying those fields.
  `tests/it/genesis.rs` pins genesis's bytes field by field, and
  `tests/it/recovery.rs` each variant's against a raw struct-variant twin.

Its integration suite is one binary, `tests/it/`: one file per surface over
the shared `common` world, and `heap`, the binary's byte-counting
allocator.

## The arrangement, `skep-arrangement`

`skep-arrangement` owns what a document holds: per document a content and a
link run-list (its arrangement), the provenance relation R (every content
address a document has ever held), and three per-member facts — the birth
extent, the shot terms and the fork source, the member or bare document a
`version`-minted document was born sharing, which `doc_metadata` serves as
`source` to every reader of that document — all in one slice, `M5State`. It is the one place
in the workspace where state is destroyed: `delete` removes positions and
`rearrange` reorders them, in place, and R keeps every address a delete
removed. Its modules are declared in `src/lib.rs` in dependency order, each
with a line saying what it holds; each names in code only the modules above
it. `tests/it/tidy.rs` checks that, that every declaration under `src/` but a
`tests` module carries its line, and that every file under `src/` and
`tests/it/` is declared. `run.rs` is the run; beside it, `run_union.rs` holds
the union of a run set's I-extents, in tumbler order, and `run_list.rs` the
run-list, in V-order — two modules that share no private item. `ops.rs` is the
`Vstream` handle and what its operations share; beneath it,
`ops/insert.rs`, `ops/publish.rs`, `ops/copy.rs`, `ops/reinstate.rs`,
`ops/delete.rs`, `ops/rearrange.rs` and `ops/version.rs` each hold one
operation's `impl` block. Its `test-hooks` feature (default off) compiles in `seat_link`, the
test-only twin of the link seat; `scripts/gate-full.sh` checks the library
and its docs without it, and runs its doctests — the `compile_fail` pairs on
`Run` and `M5Rec` that pin the seals a foreign crate meets.

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
  crate — the serde shadow and the `LinkSeat` fold go through it — and every
  in-crate literal starts at an address that already is a full element
  position: another run's start, an in-crate shift of one, or what M3's
  `mint_content` returned; `Run::admits_start` lists those literals.
  `run_list::extend_or_push_run` is the one place a built run is widened and
  the one place a placement's runs are accumulated.
- **One allocation step.** Every fresh content address is minted and written
  by `ops::allocate_for_placement`, inside the transaction whose placement
  record places it.
- **The version chain is asked, never spelled.** Every trunk, head,
  publication and surface question in this crate goes through `chain.rs`,
  the one reader of M3's version frontier; the floating readers of
  `skep-retrieval` and `skep-discovery` ask its `reading_surface` rather than
  float by hand.
- **One ownership gate.** Every gated op opens with `ownership::gate_write`:
  registration, then the ω gate. A door ahead of the store asks the same two
  questions through `Caller::passes_ownership_gate`.
- **The edition is append-only by the ops.** The fold does not check it;
  `Vstream`'s card lists the ops that keep it, and an op that writes a
  content arrangement joins that list.
- **The slice's shape is its format.** `M5State`'s fields and `M5Rec`'s
  variants are appended, never inserted or reordered: bincode writes fields
  in order and variants by index. Three checks pin it, none alone:
  `skep-kernel`'s goldens pin the bytes of the records their ops reach —
  every variant but the shot's `ShotPlace`, since the fixture runs no shot;
  `state/tests.rs`'s `shot_place_folds_as_a_placement_at_one_and_notes_the_terms`
  pins that record's index and fields; and `skep-engine`'s
  `each_slice_serializes_the_fields_the_format_count_names` pins the slice's
  field order, which the goldens cannot see for the two fields they leave
  empty.

Its integration suite is one binary, `tests/it/`: one file per surface over
the shared `common` world, and `tidy`, which checks the module tree, its
order and the first rule.

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
`state/reads.rs` holds the read surface and `state/spanfilade.rs` the
coverage index `stab` answers from. `writes.rs` is the handle and what
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
  `state.rs` and its children; `apply_link` is the one insertion and
  asserts the address is fresh, and it and `rebuild_derived` fold through
  the one `fold_hints`.
- **The index answers what a scan would.** `stab` answers from the
  spanfilade, the per-slot coverage index `fold_hints` files every span
  into, exactly the links a scan of `links` under the one overlap relation
  would — `classify_spans` answering `ProperOverlap`, `Containment` or
  `Equal` — and `match_links` narrows by that relation after its first
  constraint. `tests/it/spanfilade.rs` checks it over every slot, view and
  query of a world holding every span shape a deposit path stores, live and
  after a rebuild.
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
that need no kernel; `recovery`, the hints a checkpoint must rebuild;
`spanfilade`, the coverage index against a scan of the store; `heap`, the
binary's byte-counting allocator; and `tidy`, which checks the module map
and the first rule.

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
  budget all three price their spans' run-list walks against — are counted
  by `query/compare.rs`, `query/find.rs` and `query/retrieve.rs` in two
  passes: what a request names — COMPARE's and FINDDOCSCONTAINING's spans,
  and every span's walk price — before its first span is walked, and what
  it produces — blocks, coverage, items, pairs — as each arrives. Every
  count goes through `budget.rs`'s `Count`, which admits exactly a budget
  and refuses a batch that would exceed it before it lands, so no producer
  spells that boundary itself; `error.rs` renders them, and a request past
  one gets its rejection and no partial answer.
  `tests/it/tidy.rs` refuses any other file's code line that names a budget
  beside a comparison — the spelling a hand-written guard takes. Every
  query that resolves a span pulls `skep-arrangement`'s lazy
  `iter_resolve` — the three producers counting each run as it arrives, so
  a request past its budget stops there rather than materializing a
  document's every run, and SHOWORIGIN keeping only each run's origin — and
  FINDDOCSCONTAINING's filter asks `arranges_any` rather than building a
  candidate's footprint; `tidy` refuses any file the eager twins —
  `resolve`, `project` — which answer the same.
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
`find`; `query`, `head_float`, `traits` and `walk_budget`, what crosses the
queries (the handle and the gate's precedence, the published-address
float, the derive policy, the walk budget's price, its scope and its place
below the gate); and `tidy`, which checks the module map, the first rule
and the third.

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
  `tests/it/tidy.rs` checks the section's heading and that it names every
  read the crate publishes. Of what a line says a read walks, the suite's
  heap pins check only what the heap shows: that the touch test builds
  nothing per pair, and that `image_on`'s run budget and its square, both
  pointwise budgets and the preview's refusal of a `d` whose own runs are
  past the budget each refuse before the work they exist to refuse. Nothing
  checks the rest, or skepd's card.
- **The link store's overlap is restated here.** `skep-links` keeps its
  per-link overlap private — a slot's span meets a query's when they
  properly overlap, one contains the other or they are equal, never when
  they only abut — and `addressably_discoverable_from_on` restates it over
  spans' bounds as `SpanBounds::overlaps`, in `src/pointwise.rs`, so that
  discoverability touches a run by the relation the region family's stab
  does. A change to the link store's overlap changes `SpanBounds::overlaps`
  in the same commit. The unit test beside it holds it to `skep-address`'s
  `classify_spans`, and `tests/it/pointwise.rs` holds discoverability to
  the stab on every relation `classify_spans` draws.
- **The arrangement's DELETE admission is restated here.**
  `skep-arrangement` keeps private the two tests its DELETE admits a range
  by — that the document arranges the range's first position, and that its
  arranged content contains the whole range — and `delete_orphans_on`
  restates them as one bounds check in `DeletePartition::of`, in
  `src/survival.rs`, so that the preview is of the DELETE requested and
  never of a clipped one. A change to DELETE's admission changes
  `DeletePartition::of` in the same commit. `tests/it/survival.rs` holds the
  preview to DELETE's verdict on every request its admission grid draws.

Its integration suite is one binary, `tests/it/`: one file per part of the
read surface over the shared `common` world; `heap`, the binary's
byte-counting allocator; `home_rule`, `head_float` and `consumer`, the laws
that cross them; and `tidy`, which holds every check that reads the crate's
own source: the module map, the first two rules, and the `## Cost` section's
heading and its naming of every read.

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
  the `lower` table. The write path's lowering, `lower_txn`, is public: it
  is the door a caller that drives a store itself — the daemon's head
  writer — lowers its `TxnError` through, so its refusal is the classified
  rejection the front door would have answered and renders as code and
  detail, never as the store error's `Debug`. A `Durability` rejection
  carries the I/O kind in `Rejection::io_kind`, set at `lower_txn` alone,
  read by the daemon's write path and never marshaled — the transport's
  codec reads the wire's five members by name.
- **The retry memo holds `CommittedAck`s and nothing else** — the one
  shape an acknowledged write's `Response` yields — so no rejection and no
  read answer is ever replayed. Its capacity is `OperationSurface::new`'s
  parameter and no default of the crate's: the daemon supplies its own
  pin, carded at its open, and a test the figure it needs.

Its integration suite is one binary, `tests/it/`: one file per topic over
the shared `common` world; `reexports`, which checks from outside the crate
that a request is built and a response read through `skep_febe` alone; and
`tidy`, the module order and the check the first rule names.

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
TWO PERMIT POOLS: the fetch pool, whose permit a fetch's answer holds, and
its twin the upload pool, whose permit the creation and the resume hold
for a body's whole stream, both counted into the daemon's worker minimum
beside its own three pools, each saying its edge pair through the gate's
classed door. `door.rs`
— THE MEDIA DOOR, the one step the plain write sequence takes between its
admission and the commit for a value naming a media kind:
`published_target` at a published target whatever the declaration, the
shot's owner test (`not_owner` naming the draft), and THE BINDING: a
picture's cell is admitted where its hash is one the principal's own cells
already name over a file whole at the cell's size (the index's arm, read
first once the index is ready), or one this principal deposited under its
own live lease over a whole file; refused `unbound_cell` otherwise,
`lease_lapsed` where the deposit is gone, and `index_rebuilding`,
retry-class, where the lease arm alone would refuse while the index's walk
at open runs — and the lease arm's verdict as final once the walk has
FAILED; a blind document's cell is admitted with no store consulted.
It reads the op's values and, for a shot, the staging draft's own runs off
the locked snapshot, through M5's and M4's public reads and the
`ReadableWorld` seam, and the index, the lease and the file through the
gate. `gate.rs` — THE GATE: the blob store opened under `blobs/` in the
data dir — `STORE_DIR`, the one spelling of that directory's name, which
the gate's and the pruner's lines and the daemon's two tools read: a format
name every board holds its deposits under, moved only with a migration —
the limits in force (the daemon's default — one eighth of the
volume's capacity read once at the open, never below 256 MiB — and the
install hook the serving layer's channel will call, compiled under
`test-hooks` until it does, a cap past the route's refused, never
clamped), the hold a stream has on its upload, the three
scopes a deposit is refused on (the own scope — the base plus the pending
bytes — the venue total, the floor — in that order, the requester's own
record first), the creation's gate (the standing-uploads bound, the floor
on no length), THE FLOOR IN FORCE — the larger of the constant 256 MiB and
twice the newest checkpoint's size plus one maximal segment, kept by the
gate from the checkpoint sizes the daemon notes, at open the start point's
(the base that loaded, never a skipped header's claim) and after any
landing, the thread's own or a backstop's, and answered binding or not to
the daemon's standing line by the creation's own test; and the volume's
free space as the floor reads it — the one reading the daemon's open line
and its landing line carry too, and, where the host refuses the read, that
refusal in the store's words, which binds the floor and is never read as a
figure — the refusal said once per binding and its lift once at a
finish — THE DEPOSIT's TERMS, the creation and the finish of an upload
under the principal's key, the deposit's function (the store's for the
schema's designation, the pairing checked at compile time) and the lease
interval in force; the binding's read with its window, and the deposit's
wholeness the deposit read reports by — a file whose size the store cannot
read answered as the deposit gone, never admitted, and said at the
condition's edges by the gate, the unread episode answered to the daemon's
standing line off a fresh read of its file; and THE INVENTORY's two reads,
whose figures the operator's tool reports under the gate's own pending
rule. `index.rs` — THE CELL INDEX:
per hash the cells naming it, per account the distinct hashes its cells
name at their size (the base); entered by the daemon's write path at every
commit that mints a cell and rebuilt whole at every open on a thread — or
at the open, where the OS refuses the thread — over an immutable snapshot
of the content store, its entries added into the one copy (an entry is
idempotent per cell); the walk's death, caught on either by one catch,
marks the index FAILED, a third state beside ready and not-ready, said
once and re-said by the daemon's standing line; its readiness flag is what
the index's three readers consult, and a value naming the kind under no
pinned schema stands in it as a halt mark. `pruner.rs` — THE PRUNER, one
per daemon beside its gate, and its PASS: the
expired partials removed off the record's expiry and the hold; the halts
on a foreign designation directory or a halt mark, or on a read of them
that failed; the unreferenced files renamed aside under an exclusive arm
the caller hands in (the credential lock's write arm — named nowhere
here), one file per acquisition, re-reading the index and the lease log
there, each aside unlinked after under no arm; the two logs compacted on
their trigger under no arm; each step's failure answered beside the
report and every other step run past it — but the unlink, past a failed
read of the halts — and the compaction on every exit, the report's one
line naming each failure ahead of what the pass did; and the cadence the
daemon's transport thread waits on. `serve.rs` — THE
FETCH's composed order: the shape, M10's read by identity as the gate, the
one classification, the permit of the fetch pool, the whole file checked
against its cell before its first byte, the stream's two re-check
intervals; what the daemon's `server/blob_routes.rs` runs for `GET
/blob?i=` and its transport streams. Beneath them, the leaves: `limits.rs`
— the resource's eleven numbers, each `pub` where another crate reads it:
the per-file cap, the two pools' counts, the standing-uploads bound and
the default limit's share and floor, which the daemon reads, and the
compaction trigger and its minimum, which its pruner suite reads; the
fetch's two re-check intervals and the cell's cap are the crate's own.
`cell.rs` — the picture's reference cell: its schema, its one parser under
the canonical rule, its encoder, its designation and the set this build
pins, and THE ONE CLASSIFICATION of every media kind — with its child
`cell/blind.rs`, the blind document's cell: the second kind, a commitment
the board holds no byte of a file for, read through that classification
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
  `OperationSurface<W>` under the record lift M10's own `execute` requires,
  the door over `&W` — and the crate's `[dependencies]` name no
  `skep-engine`; `World::visible_to`, the engine's, is rebuilt here over
  `ReadableWorld::readable`, whose `None` is the guest. Two unit suites
  open an engine, through a dev-dependency: the door's (`door/tests.rs`)
  and the index's walk catch (`index.rs`).
- **The cell index has one lock of its own, taken innermost.** The write
  path enters it under the daemon's `Serial`, the gate reads it under the
  credential lock's read arm, the pruner under its write arm, the walk at
  open under neither; `index.rs`'s lock is held across no other lock, and
  no caller holds it while taking one.
- **The store knows no policy.** `skep-blobs` is handed a root and
  principals as opaque strings; who a principal is, what bounds its bytes,
  the interval an upload and a lease are given and the function a deposit
  is hashed under are the gate's, applied by its own creation and finish
  (`gate.rs`), and which lock a finish runs under is the daemon's — never
  the store's. The gate's key for a principal is its own spelling: the
  routes drive the store by it for the acts that name an upload, and the
  inventory reads it back through the gate's two reads, never by a second
  spelling.
- **The cell's parser is the one parser; the door is the one media
  step.** `cell.rs`'s `parse` is the one reading of a picture cell's
  bytes, under the canonical rule (`parse(b)` answers a cell only where
  `b == encode(parse(b))`), and the vector set under
  `crates/skepd/tests/it/fixtures/media/` is what every other parser of
  the cell — the shell's, the browser page's — is held to. `door.rs` is
  the one place the daemon acts on that reading: no producer of the
  session layer's admission reads a value's bytes for the cell, and no
  route serves one.
- **The lock arm is handed in.** `Pruner::pass` takes the exclusive arm as
  a closure and holds whatever guard it answers for exactly one file; the
  crate names no lock of the daemon's.
- **The surface is the daemon's need.** Every `pub` item is one the
  daemon takes, listed in `README.md`, or a hook, `#[doc(hidden)]` under
  `test-hooks`; the parsers, the binding and the gate's rules stay the
  crate's own. `tests/it/tidy.rs` checks it.
- **The test seam is a feature.** `test-hooks` (default off) compiles in
  the walk and stream holds, the pruner's prune hold, its notice and its
  count, the gate's clock, free-space, floor and limits overrides, the
  index's report and counts
  and the pools' `try_hold`, and forwards `skep-blobs/test-hooks`; the
  daemon's hooks (`server/hooks.rs`) are the doors a suite reaches them
  through, and `scripts/gate-full.sh` builds the library and its docs
  without it.

Its unit suites sit beside their code: `cell/tests.rs`, `door/tests.rs`
(which opens a real engine), `gate/tests.rs`, and the inline suites of
`cell/blind.rs`, `index.rs` (whose walk-catch test opens one too),
`pools.rs`, `pruner.rs` and `serve.rs`. Its integration suites
— the upload, the fetch, the door and the pruner over a served daemon —
are `skepd`'s (`tests/it`: `blob_routes`, `blob_fetch`, `media`, `pruner`,
`deposit_class`, and `hazard`'s media share), which spawn the daemon they
drive; its own `tests/it/` is `tidy` alone.

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
`skep-engine`'s crate doc — reading the one concrete `World` (its identity
slice, the read class of a principal, the publication bit, the genesis
floor) and driving the kernel and the stores through `Engine`; and on
`skep-media` for the cell index the commits enter at every commit that
mints a cell. Its modules are declared in `src/lib.rs`, each with a line
saying what it holds; its public surface is its `README.md`'s list, which
`tests/it/tidy.rs` holds every `pub` item to.

Its modules form three layers. A module names only modules in its own
layer or below it, never above; `crates/skep-core/tests/it/tidy.rs` checks
it:

1. **The session layer** — `auth.rs` and the modules under `auth/`.
   Sessions and the signed handshake (`auth/session.rs`), the policy checks
   on every write (`auth/policy/`: the plain sequence's admission, the
   credential sequence's precheck with the record grade, the registry
   sequence's admission — `auth/policy/registry.rs`, the record grade for
   registry records, whose trial is the credential grade's own, and the
   seeding check the daemon's open runs ahead of every genesis — and the
   write-path check — the entry signature (`auth/policy/attestation.rs`,
   over the frame `auth/entry.rs` composes), whose one exempt `insert` is
   a signed credential or registry record into a doc 1; and beside them
   `auth/policy/upload.rs`, the session layer's gate on who may take bytes
   into the blob store at all), the readers of the World's identity slice
   (the key table is the engine's, read off the head snapshot each route
   already holds; the daemon holds no fold of its own), signature
   verification — `skep-signature` is the one crate that links the
   signature libraries; the core calls its verify — and the
   configuration: the options and the mode (`auth/options.rs`), the two
   origin sets (`auth/origin.rs`), the node prefix (`auth/prefix.rs`), the
   blocked-prefix list (`auth/blocked.rs`), the credential write lock
   (`auth/lock.rs`), the credential memo (`auth/memo.rs`) and the entropy
   the handshake mints from (`auth/entropy.rs`). It names the commits for
   one thing: the board term, `H.1`'s pair, read off the published head.
2. **The commits** — `commits.rs`. The single point every write passes
   through, one at a time — each execute under a catch of the door's own,
   so a write that panics after the kernel committed it is recorded on the
   feed as a classified bare entry with its signature's line, and
   announced, before the panic re-raises to the daemon's handler catch: no
   hole in the feed, nothing halted — and the head writer
   (`commits/head.rs`, which commits through the commits' own door — a
   refused head said ONCE PER CAUSE with the position its head would have
   named and the refusal as the wire renders a rejection, the code and the
   detail through M10's own lowering and never a type name, a memo under
   the writer's state lock holding the last cause said, and cleared by one
   `landing:` line naming the landed position and the first refused one
   when a head next lands). Beneath it, and reachable only from it:
   - `commits/feed.rs` — the change feed, and the one compaction of its
     five files to the journal's reclaim floor, run at open and by the
     daemon's checkpoint thread after any landing, its own or a backstop's,
     its answer naming each file that stood; beneath it,
     `commits/feed/derived.rs` keeps the feed's derived index files — a
     torn tail is cut at open and said with the last trusted position, the
     bytes and that the cut part is re-derived — `commits.log`'s own cut
     part by a walk BEHIND THE LISTENER on a thread of the commits' own,
     reads served and writes admitted meanwhile, `/changes` refusing pages
     into the uncovered region `feed_rebuilding` until ONE rewrite lands
     it; malformed names and unreadable slots are said once per open with
     a count and the first position; a rewrite that fails past its rename
     stops its file for the uptime, said once per uptime — and
     `commits/feed/attest.rs` the attest store, the marker slot mirrored
     per attested commit, never compacted, its missing tail rebuilt at open
     in one scan of the kernel's markers above the store's fence;
   - `commits/sidecar.rs` — `commits.log`, the daemon's record of what it
     committed, for whom, and whether the entry was signed — and, on a
     bare line, the journal's answer for the row's op and terms;
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
   `limits.rs` (the six bounds the core reads: the request-body cap, the
   edge pairs' hold-down and the standing line's cadence, which the daemon
   reads too, the feed walk's progress cadence and the feed's page byte
   budget; the daemon's own seven are `skepd`'s `limits.rs`, the
   media resource's numbers `skep_media::limits`'s, each `pub` for its
   reader). None of these knows anything of the session layer or the
   commits; a leaf imports only leaves — and a leaf in another crate is a
   leaf: `skep-util`'s `permits`, `notice` and `json`.

Rules that hold across its files:

- **One door for commits.** Every write to the world goes through
  `commits`, one at a time. Only the commits record to the feed and to
  `commits.log`.
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
- **The guard names the lock.** A function whose contract is "under the
  serialization lock" takes the guard, `SerialGuard`, in its arguments
  (`serial.rs`): the commits' door and the head writer's turn hold it by
  type, as `LockWrite` names the credential lock's exclusive arm — so a
  caller that lacks the lock cannot spell the call.
- **The surface is the daemon's need.** Every `pub` item is one the
  daemon takes, listed in `README.md`, or a hook, `#[doc(hidden)]` under
  `test-hooks`; the producers, the feed's files and the head writer stay
  the crate's own. `tests/it/tidy.rs` checks it.
- **The test seam is a feature.** `test-hooks` (default off) compiles in
  the feed walk's hold, its notice and its panic arm, the walk's pending
  region and progress cadence, the head writer's clock and its one
  refusal, the feed's and the attest store's failure arms and the attest
  store's sync mark, the lines said and the checkpoint signal's tick, and
  forwards nothing; the daemon's hooks (`server/hooks.rs`) are the doors a
  suite reaches them through, and `scripts/gate-full.sh` builds the
  library and its docs without it.

Its unit suites sit beside their code: `auth/blocked/tests.rs`,
`auth/session/tests.rs` (which opens a real engine), the inline suites of
`auth/policy/*`, `commits/tests.rs` (which opens one too),
`commits/sidecar/tests.rs`, `commits/feed/derived/tests.rs` and
`codec/tests.rs`. Its integration suites — the session layer, the commits
and the head over a served daemon — are `skepd`'s (`tests/it`), which spawn
the daemon they drive; its own `tests/it/` is `codec_roundtrip`, the wire
grammar's round trips, and `tidy`.

## The daemon, `skepd`

`skepd` owns three decisions of its own, two of them its core's code
(`skep-core`'s session layer and head writer, run by this daemon): the
session layer's gates (who may act, and what a credential write may do),
the cadence of the published head, and the media door (`skep-media`'s
step, which the daemon's plain
write sequence runs: whether a value a write carries is a media cell —
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
to the stores through the engine, and the media bytes to `skep-media` and,
through its gate, `skep-blobs`. Its listener binds the address `--bind`
(`SKEPD_BIND`) names — `127.0.0.1` by default, the container's address in
the hosted image — and the peer rule reads the socket, never the bind, so
the flag widens who can connect and nothing of who may act.

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
│                    the feed compacted, each landing and │
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
goes from the routes to the media resource (`skep-media`) and `skep-blobs`, under a
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
layer's lock, on the transport's cadence. THE OPEN (`server.rs`,
`Daemon::open_configured` and the two doors above it) says its report on
the operator stream before anything is served, and its first line is the
version line — the build's version and the three format stamps this build
reads, the kernel's journal and checkpoint stamps and the engine's World
stamp, each a public constant of its crate — ahead of the directory's
line and the recovery's landing. THE TOOLS (`tools.rs`, beside
the routes) run no server at all: the inventory opens the journal through
the engine's open, walks the world into a fresh cell index through the
media resource's walk and reads the store's inspection; the pull reads the
same index or the hash the operator hands it, and writes one file through
the store's install — nothing above their own layer.

1. **The transport** — `server/listen.rs` (sockets — the listener bound
   BEFORE the open, `bind` then `serve_bound`, `serve` the two in sequence,
   so a held port is refused in milliseconds before the kernel's lock is
   taken and a connect during the open waits in the backlog for the first
   worker; `serve_bound` binds the auth port, says the configuration
   warnings and then the open's-report `auth:` line — the mode as AUTH-5.86
   derives it, the local-trust flag with its source, the configured and
   the signed origin sets — then the node prefix and the blocked list,
   before any worker exists — worker threads — the
   default count and the minimum, one more than the five permit pools'
   slots together: the reconstruction, the class scan, the fetch, the
   upload and the write pool (`MAX_CONCURRENT_WRITES`, 4); spawned last,
   after the open, and `wait`, the binary's
   foreground call, returning only when every one has ended, which the
   binary says and exits 1 on — the
   event streams' loop and budget, the pruner's cadence thread — the pass
   once the cell index is ready and then hourly, the logs' compaction on
   its trigger among its acts; its loop under a catch that, on a panic,
   says what the board lost (no pass until a restart) and sets a liveness
   flag the standing line reads — THE CHECKPOINT THREAD — the kernel's
   deferred trigger serviced off the write path's guard: the checkpoint
   every 1024 commits or the byte bound, whichever first, its result on
   the operator stream — a landing's figures, a failure said per attempt
   — and after ANY landing, its own or one the kernel's backstop ran
   inline on a writer (the write path raising the thread's signal where
   the kernel's inline count moved, the thread reading the newest
   checkpoint once on its wake and saying the backstop's line), the byte
   bound and the media floor re-read from that checkpoint's size and the
   change feed's five files compacted to the journal's reclaim floor; its
   wait on the signal TIMED, so that once an hour, while any standing bad
   state stands — the ten, in the order the line says them: the write
   path's halt, the kernel's poison, the journal damage a history read
   met, a stopped feed file, the pruner's thread gone, the feed walk's
   thread gone, the cell index failed, the floor binding, a deposit's
   file the store cannot read, CLAIMED-PERMISSIVE — it says ONE
   `standing:` line naming each with its position or file, and nothing
   on a healthy board; its loop under the
   same catch, which says what is lost with it (every checkpoint the
   backstop's, unsaid; the bound and the floor frozen; the feed's files
   uncompacted and no standing line, until a restart); and the kernel's
   own halt said once, at the write path's door where a write answers
   `poisoned` or at the handler's catch after a panic on a write (a write
   that committed before it panicked already recorded and announced by
   the write path's own catch, so the handler's `500` costs the feed
   nothing), which `GET /health`'s `writes.halted` reads beside the write
   path's halt —
   and, after a blob reply is written, the replaced file's deferred
   unlink, under a catch of its own so a panic there costs the aside and
   never the worker, a failed unlink said ONCE per standing fault by a
   once-flag on the daemon, naming the aside by its name under the data
   directory as the store's error names it, and that it stands for the
   pass or the next open, and cleared by one `landing:`
   line when a later call empties the queue — the family's requests
   writing no line of their own) and
   `server/http.rs` (the HTTP bytes: the request reader, the reply
   writer, the event framing — and the streaming arm: for the blob
   upload's two body-carrying methods the reader takes the head alone
   and hands the body back beside the request, a `BodySource` over the
   connection's socket the router's private door takes by value). It
   hands each request to the router and knows nothing of what a request
   means. Beside them, at their layer, `server/embed.rs` — THE EMBEDDING
   HELPER, the start a program that is not `skepd` takes to run the daemon
   in its own process: `embed`, the bind, the open and the serve in the
   binary's order, the session layer's options taken at the port the bind
   chose so a configured origin can name it, the open retried — twelve
   attempts, 25 ms apart, the listener bound afresh each time — only where
   the journal directory's lock of a daemon just stopped over the same
   directory is not yet re-acquirable, and every other refusal answered at
   once naming its step (`EmbedError`: the bind, the open, the serve); and
   `Skepd::wait_for_the_index`, the wait for the cell index's walk at open
   on `Daemon::index_is_ready`, the production read, a second call so a
   caller can show the board starting while the walk runs (`IndexNotReady`
   past its deadline). Feature-free: the suites' seeded start beside it is
   a test hook. The binary keeps its own sequence — the panic hook, the
   loose-directory refusal, its exit codes — and calls neither.
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
   chosen off the op's own type slot before any lock is taken: take a
   permit of the write pool — before the credential lock and the guard,
   the write refused `write_busy` past it, the head writer's own commits
   taking none — resolve the caller, run the checks, commit, record, then
   give the head writer its turn. `/blob/upload` resolves the caller, refuses the creation and
   the resume `uploads_closed` on a board launched with `--no-uploads`,
   refuses the creation, the resume and the deposit read
   `index_rebuilding` until the index's walk at open completes — or
   `index_failed`, no retry, for the uptime where the walk died — admits
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
   holes, each account's base and pending bytes, the bytes whose key names
   no account, the venue total under the gate's own pending rule, the
   standing and expired uploads, the halt marks, a foreign designation
   directory, and of the journal what the open did to the copy — the
   stray checkpoint removed and the torn tail cut, each in bytes;
   recording no read, writing nothing under `blobs/`; a copy the open
   cannot write refused by name, since the open writes the lock and may
   cut a tail) and the
   pull (a file a committed cell names restored by the store's install,
   no lease and no record; beside a serving daemon held to the inventory's
   hash), the two subcommands `main.rs` parses as a leading verb.
3. **The daemon's vocabulary** — `server/reply.rs` (the reply and every
   transport refusal), `server/request.rs` (the request, the streaming
   body's source and the slot it rides in, and the rules the request's
   headers and query obey), `server/scan.rs` (the class-scan pool): what
   the routes and the transport both speak.
4. **The leaves** — `history.rs` (reading the world at an earlier
   position) and `limits.rs` (the daemon's seven bounds: the small-body
   cap, the change feed's two page-size bounds, and the blob route's
   bounds — the streaming arm's chunk, its two deadlines, the pruner's
   cadence; the six the core reads are `skep_core::limits`'s, three of
   them — the request-body cap, the edge pairs' hold-down and the standing
   line's cadence, the panic hook's rate — read here too,
   and the media resource's own numbers, the two pools' counts among them,
   are `skep-media`'s `limits`, the daemon taking the ones it reads from
   there, each `pub` for it). Neither knows anything about the daemon; a
   leaf imports only leaves — and a leaf in another crate is a leaf: the
   counting permit the five bounded pools use and the operator's log line
   are `skep-util`'s `permits` and `notice`, the support crate below this
   one (§The support crate); the codec and the serialization lock, once
   leaves here, are `skep-core`'s, and the two cells `skep-media`'s.

Below the daemon's four layers, its core and its media resource, two
crates the daemon composes with:

- **The session layer** is `skep-core`'s `auth` (§The daemon's core):
  sessions and the signed handshake, the policy checks on every write —
  the plain sequence's admission, the credential sequence's precheck, the
  registry sequence's admission and the seeding check the open runs ahead
  of every genesis, the write-path check, the upload gate — the readers of
  the World's identity slice and the signature verification. `AuthState`
  is a field of `Daemon`, opened by `server.rs` over the recovered world
  from the `AuthStart` the open read first — the options, and the
  blocked-prefix list they name, read before the open touches the data
  directory; the routes resolve the caller through it and run its checks.
- **The write path** is `skep-core`'s `commits` (§The daemon's core): the
  one door every write passes through, one at a time, the head writer
  behind it, the change feed and its five files, the attest store.
  `Commits` is a field of `Daemon`, opened by `server.rs` ahead of the
  routes and driven by `op.rs` — resolve, check, commit, record, then the
  head writer's turn — under the guard `serial_lock` answers; its
  checkpoint signal is what the transport's checkpoint thread waits on.
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
  with the source it was set from (`skep-util`'s `Source` — the default,
  the flag, the variable, as the binary's parse recorded it), rides
  `Daemon::open_configured`; the setting is echoed on `/health` and the
  open's report names it with its source; the deposit read is a route
  helper of `server/blob_routes.rs` over the gate's reads; the floor is
  sized at the open off the start point's header — the base the open
  loaded, never a skipped header's claim — and re-read by the checkpoint
  thread after any landing, its own or a backstop's; and the upload and
  fetch pools are counted into the worker minimum beside the three pools
  of the daemon's own — the reconstruction budget, the class-scan pool and
  the write pool.

`lib.rs` declares the daemon's modules in layer order, then the fuzz
harness and the crate's public surface; `main.rs` is the binary — the
daemon's flags, and the two tools' lines, a leading verb parsed before any
flag; the process's panic hook, installed first, one prefixed line on the
operator stream for any thread's panic, the payload only where it is a
literal the code wrote; its own lines — the refusals before each exit and
the serving line on stdout — written synchronously with the write's
result discarded, so a lost reader costs the line and never the exit
code; and the order bind, open, serve, then `wait`, whose return is the
workers' end, said and exited 1.
`fuzz_support.rs` (in `test-hooks` builds only) serves the fuzz targets and
the tests: it stands above the transport, and nothing in the daemon
imports it.

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
  its code.** `skep-client` holds its own `Origin::parse`, held to the
  daemon's vector set by a test and never imported from `skepd`; the
  signed origin it frames is the one it dials (AUTH-4.8); every
  `/challenge` it fetches follows the pre-check's two reads (AUTH-5.65);
  `Skepd-Session: closed` has one reader, the board's authenticated
  exchange; a halt names the state, its cause and the one act (AUTH-5.66),
  and a refusal the client's state machine does not arm is surfaced, never
  retried. Every person door (§The command lists them) requires a
  `Person`; the terminal check is the CLI's implementation of that seam,
  never the walk's.
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
- **The daemon writes only its own files.** Every directory and file the
  board creates — the kernel's, the daemon's own and the media stores' —
  is born owner-only on unix, directories `0700` and files `0600`, the
  mode set at creation and the umask irrelevant; and the binary refuses
  to start on a data directory other users of this machine can read,
  naming the directory, the mode found and the `chmod 700` that fixes it,
  repairing nothing. The journal and checkpoints
  are the kernel's — its `checkpoint.tmp` included, which the kernel
  removes at open. The daemon's own files — written by its core's code,
  `skep-core`'s `commits`, and the daemon's files all the same, under the
  daemon's data directory and lifetime — are `commits.log` — its
  testimony about what it committed, for whom, and whether the entry was
  signed — the feed's derived index files, projections of that testimony
  and the journal, rebuilt from them on loss, `commits.log`'s own
  uncovered region walked from the journal behind the listener and landed
  by one rewrite, pages into it refused `feed_rebuilding` meanwhile —
  `commits.log` and the four
  compact to the journal's reclaim floor at open and after each checkpoint
  the checkpoint thread lands, the floor moving then and at no other
  moment — and `feed-attest.log`, the attest store: each attested commit's
  marker slot, mirrored at commit from the value the write path admitted,
  rebuilt from the journal above the reclaim floor in one scan of the
  kernel's markers above the store's fence — a cut at open said with the
  floor and the side it reached, REBUILT where every cut line lies above
  the floor and LOST where the lines between the last trusted position
  and the floor were taken — and the one daemon
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
