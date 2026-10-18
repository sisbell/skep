# skep-media

The daemon's media resource: a picture is a document whose content is ONE
REFERENCE CELL, and this crate holds every decision the daemon makes about
one — the cell's one parser, the door the plain write sequence takes, the
gate over the blob store, the cell index, the pruner's pass and the fetch's
composed order. It transports nothing: the routes, the replies, the deposit
read and the operator's tools are `skepd`'s, and so is the lock the pruner's
pass is handed. Generic over the world M10 reads (`skep_febe::FebeWorld`),
it names no engine; the daemon instantiates it at its `World`.

Part of [skep](https://github.com/sisbell/skep), an open-source hypertext substrate in the Project Xanadu lineage.

- **The cells**, `cell` — the picture's reference cell: its kind's address
  `KIND`, its hash function's name `DESIGNATION` and the set of the names
  this build pins, `PINNED_DESIGNATIONS`, which the pruner halts outside
  and the operator's inventory reads, the hash's width `HASH_BYTES`, and
  `names_kind_by_prefix`, the cheap test the write path runs ahead of a
  commit. The parser under the canonical rule, the encoder and the one
  classification of every media kind are the crate's own, the blind
  document's cell (`cell::blind`, the module's child) read through them
  alone.
- **The door**, `door` — `media_door(world, op, principal, &gate)`, the one
  step between the session layer's admission and the commit; `MediaRefusal`
  with its `token` and `disposition`, one variant per arm of the armed set.
- **The gate**, `gate` — `MediaGate`: `open_with`; the admission API
  `admit_declared`, `admit_creation`, `admit_bytes` and `claim` (its
  `Hold`), each refusal a `DepositScope` (`token`); THE DEPOSIT's TERMS —
  `create_upload` and `finish_upload`, the creation and the finish under
  the principal's key, `DEPOSIT_FUNCTION` (the store's function for the
  schema's designation, held to it at compile time) and the lease interval
  in force, the finish noting the floor's lift; the reads the routes and
  the deposit read take — `store`, `key`, `now_ms`, `limits` (`Limits`),
  `index`, `index_ready`, `index_failed`, `own_pending`, `deposit_whole`
  (the binding's own reading of a deposit's file, which the deposit read
  reports `lapsed` by), `uploads_open`, `health_object`, `startup_line`;
  the floor — `note_checkpoint`, the daemon's note of the newest
  checkpoint's size, from which the gate keeps the floor in force, `floor`,
  `floor_binding`, the creation's own test the standing line re-says — a
  figure below the floor, or the host's refusal of the read — and
  `free_space`, the host's figure or its refusal in the store's words, which
  the daemon's open line and landing line carry and no reader takes for a
  figure (the binding's refusal is said once, at its first refusal, and its
  lift once, at a finish, by the gate itself); the install's
  refusal, `LimitsRefused` — a record naming a
  per-file cap past the route's refused whole, said once, never clamped —
  compiled with the install under `test-hooks` until the serving layer's
  channel lands; and THE INVENTORY's two reads, `lease_counted`
  (`Counted`) and `upload_counted`, under the gate's own pending rule and
  its own reading of a store key, with `wall_clock_ms`, its reading of the
  clock.
- **The index**, `index` — `CellIndex`: `new`; the entries at commit,
  `enter_insert` and `enter_publish`; the reads `base`, `referenced`,
  `references` (`Reference`), `accounts` and `halts` (`HaltMark`); `walk`
  over a snapshot and `start_walk` on a thread of its own, or at the open
  where the OS refuses the thread, answering a `Rebuild` — or, where the
  walk died on either, marking the index FAILED under one catch, the third
  state beside ready and not-ready, read through the gate's
  `index_failed`.
- **The pruner**, `pruner` — `Pruner` (`new`), one per daemon beside its
  gate, whose `pass(&gate, exclusive)` answers a `PrunePass` — or nothing
  where the index is not ready: its figures and the bytes they freed, the
  halt, each log's size, the compaction half of its line (`compaction`)
  and, where a step failed, the first failure beside them (`PassFailure`,
  naming its `PassStep` and the cause), step (d) — the compaction — having
  run on every exit; `Cadence` (`new`, `wait`, `stop`) and `Wake`, the
  transport's thread's clock and stop.
- **The pools**, `pools` — `FetchPool` (`new`), whose permit a fetch's
  answer holds, and its twin `UploadPool` (`new`, `admit`), whose permit a
  creation or a resume holds for the body's whole stream; each says its
  edge pair through the gate's classed door.
- **The fetch**, `serve` — `fetch` and `gate_admits` over M10's front door;
  `Admitted` (`i`, `size`, `bytes`), `NamedBlob` and `FetchRefusal`;
  `Progress` (`new`, `advance`, `due`, `reset`), the stream's interval
  arithmetic.
- **The limits**, `limits` — the resource's numbers another crate reads,
  each `pub` for that reader: `MAX_BLOB_BYTES`, `MAX_CONCURRENT_FETCHES`,
  `MAX_CONCURRENT_UPLOADS`, `MAX_STANDING_UPLOADS`, `DEFAULT_LIMIT_SHARE`
  and `DEFAULT_LIMIT_FLOOR_BYTES` the daemon's, `COMPACTION_TRIGGER` and
  `COMPACTION_MIN_LINES` its pruner suite's. The fetch's two re-check
  intervals and the cell's cap are the crate's own, read through
  `Progress` and the classification.
- **The root** — `MediaOptions`, the upload setting and, beside it, the
  source it was set from (`skep-util`'s `Source`: the default, the flag,
  the variable), which the daemon's open names.
- **The test seam** (`test-hooks`, default off; every item of it
  `#[doc(hidden)]`) — the walk hold and the walk fault, the stream hold,
  the pruner's prune hold, its notice and its count of passes, the gate's
  clock, free-space, floor and limits overrides and its record of the
  lines it has said, the index's report and counts, the pools'
  `try_hold`; forwards
  `skep-blobs/test-hooks`, the hazard seam the daemon's hooks reach through
  the gate's `store`.

Its modules, each with a line saying what it holds, are declared in
`src/lib.rs`; the rules that hold across its files, in the workspace's
`ARCHITECTURE.md` §The media resource; and `tests/it/tidy.rs` holds its two
layers, every hook to the feature's gate, and every `pub` item to this list.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](../../LICENSE-APACHE))
- MIT license ([LICENSE-MIT](../../LICENSE-MIT))

at your option.
