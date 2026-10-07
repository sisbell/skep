# skepd

The skep daemon: one long-running process owning a board — the
journal, the engine, and the wire.

Part of [skep](https://github.com/sisbell/skep), an open-source hypertext substrate in the Project Xanadu lineage.

- **A hand-written HTTP/1.1 subset** over `std::net` — no server
  framework, no async runtime: the kernel's single applier already
  serializes writes, so worker threads are the whole concurrency
  story, and the commit stream needs flush-at-commit semantics
  pull-based servers cannot give. Four permit pools bound the surfaces
  that hold a worker long — the reconstruction, the class scan, the
  fetch and the upload — each refusing retry-class past its count, never
  queueing, and the default worker count is sized one above their sum,
  so a daemon whose every pool is saturated still answers.
- **The wire** — `/op` (execute), `/op-at` (historical reads over
  reconstructed worlds), `/chain` (the commit chain's value at a
  position), `/changes`, `/dump`, `/events` (commit stream),
  `/health`, the session routes `/challenge`, `/session`,
  `/session/close`, the blob upload's family `/blob/upload` — the
  resumable PUT of a picture's bytes, streamed to the blob store
  ([skep-blobs](../skep-blobs)) one chunk at a time under a permit pool,
  and the deposit read —
  and `GET /blob?i=` (with `HEAD`), the FETCH: a picture's whole file
  served by the I-address of its cell, gated by the read, checked against
  the cell before the first byte, streamed under a permit pool with the
  requester re-resolved mid-stream.
- **The media resource** is [skep-media](../skep-media)'s, a crate of its
  own beside the write path, whose README lists its surface: the one
  classification of a media cell at every `insert` and `publish`, the media
  door the plain write sequence runs, the gate's three scopes and its
  binding, the cell index entered at every commit that mints a cell and
  rebuilt at every open on a thread, the pruner's pass and the fetch's
  composed order, with a per-account limit ALWAYS in force. The daemon's
  part is the routes and their refusals — the index's three readers (the
  upload's creation and resume, the deposit read) answered `503
  index_rebuilding` until the walk completes and every other request
  served meanwhile, the door answering the same token retry-class where its
  lease arm alone would refuse in that window — the deposit read on the
  upload's own family, the pruner's cadence thread and the credential
  lock's write arm it hands the pass, the floor re-read as each checkpoint
  lands, and the upload pool's and the fetch pool's counts in its worker
  minimum, so a handful of slow uploads never holds every worker.
- **The upload setting and the operator's tools** — `--no-uploads`
  (`SKEPD_UPLOADS=false`) closes the upload family, the creation and the
  resume refused `uploads_closed` before any body byte, echoed on
  `/health` as `media.uploads`; open by default. And two subcommands of
  this binary, run over a board directory with no server: `skepd
  inventory --data-dir <dir> [--no-rehash]` lists the holes — every
  picture cell whose file is absent, of another length or of other
  bytes — each account's base and pending bytes, the bytes whose key names
  no account, and the venue total they all sum to, the standing and
  expired uploads, the halt marks and any foreign
  designation directory, recording no read and writing nothing under
  `blobs/`; `skepd pull --data-dir <dir> [--hash <hex>] <file>` restores
  a file a committed cell names by the PUT's own install order, no lease
  and no record written, beside a serving daemon when held to the
  inventory's hash.
- **Deterministic JSON codec** — key-sorted marshalling so wire bytes
  never depend on map iteration order.
- **Durability is configuration** — fsync policy and checkpoint
  cadence are chosen here, not baked into the kernel: a checkpoint every
  1024 commits or a byte bound — a quarter of the newest checkpoint's
  size, never below 24 MiB, re-read as each lands — whichever first, run
  by the daemon's own checkpoint thread off the write path's guard so no
  write waits for it, a failure said once on the operator stream, and the
  change feed's files compacted to the journal's reclaim floor after each
  landing.

A library and a binary. The binary runs against a data directory and
serves a board; the library (`Daemon`, `serve`) is the same daemon for
an embedder or a test. Everything it serves is the operation surface
of [skep-febe](../skep-febe) over the world of
[skep-engine](../skep-engine); the counting permit its four pools are
built on, the operator's notice line and the codec's key-sorting `obj`
are [skep-util](../skep-util)'s, the support crate below it that the
media crate shares; how its modules are layered is in
[ARCHITECTURE.md](../../ARCHITECTURE.md).

The daemon verifies signatures and makes none: it calls
[skep-signature](../skep-signature)'s verify with that crate's `sign`
feature off, so its build holds no signer and no key. That verify runs
at three doors: the signed session's handshake; the entry signature a
publish-class write carries in its `attest`, checked before the
transaction; and, above the claim, the `sig` a credential record — or a
registry record, the binding and the endpoint of
[skep-registry](../skep-registry) — carries inside its own atom, checked
in the credential or the registry sequence at the record's `make_link`
under the key set that opens the record's home — a record carrying none
is refused at its own `insert`, before it lands. The open runs the
registry's seeding check ahead of every genesis. Build the shipped
binary with `-p skepd` — Cargo unifies features across one invocation,
and a `--workspace` build that compiles the test suites turns the signer
on for everything it builds.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](../../LICENSE-APACHE))
- MIT license ([LICENSE-MIT](../../LICENSE-MIT))

at your option.
