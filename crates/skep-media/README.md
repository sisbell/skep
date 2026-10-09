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
  `KIND`, its hash function's name `DESIGNATION`, the hash's width
  `HASH_BYTES`, and `names_kind_by_prefix`, the cheap test the write path
  runs ahead of a commit. The parser under the canonical rule, the encoder
  and the one classification of every media kind are the crate's own, the
  blind document's cell (`blind`) read through them alone.
- **The door**, `door` — `media_door(world, op, principal, &gate)`, the one
  step between the session layer's admission and the commit; `MediaRefusal`
  with its `token` and `disposition`, one variant per arm of the armed set.
- **The gate**, `gate` — `MediaGate`: `open_with`; the admission API
  `admit_declared`, `admit_creation`, `admit_bytes` and `claim` (its
  `Hold`), each refusal a `DepositScope` (`token`); the reads the routes
  and the deposit read take — `store`, `key`, `now_ms`, `limits`
  (`Limits`), `index`, `index_ready`, `own_pending`, `uploads_open`,
  `health_object`, `startup_line`; the floor — `floor_in_force`,
  `set_floor`, `floor`, `free_space`; and THE INVENTORY's two reads, `lease_counted`
  (`Counted`) and `upload_counted`, under the gate's own pending rule and
  its own reading of a store key, with `wall_clock_ms`, its reading of the
  clock.
- **The index**, `index` — `CellIndex`: `new`; the entries at commit,
  `enter_insert` and `enter_publish`; the reads `base`, `referenced`,
  `references` (`Reference`), `accounts` and `halts` (`HaltMark`); `walk`
  over a snapshot and `start_walk` on a thread of its own, answering a
  `Rebuild`.
- **The pruner**, `pruner` — `pass(&gate, exclusive)`, answering a
  `PrunePass`; `PINNED_DESIGNATIONS`; `Cadence` (`new`, `wait`, `stop`) and
  `Wake`, the transport's thread's clock and stop.
- **The fetch**, `serve` — `fetch` and `gate_admits` over M10's front door;
  `FetchPool` (`new`); `Admitted` (`i`, `size`, `bytes`), `NamedBlob` and
  `FetchRefusal`; `Progress` (`new`, `advance`, `due`, `reset`), the
  stream's interval arithmetic.
- **The limits**, `limits` — the resource's eleven numbers, four of them
  the daemon's readers take too: `MAX_BLOB_BYTES`, `MAX_CONCURRENT_FETCHES`,
  `MAX_CONCURRENT_UPLOADS`, `MAX_STANDING_UPLOADS`; and seven its own,
  `FETCH_RECHECK_BYTES`, `FETCH_RECHECK_INTERVAL`, `DEFAULT_LIMIT_SHARE`,
  `DEFAULT_LIMIT_FLOOR_BYTES`, `COMPACTION_TRIGGER`, `COMPACTION_MIN_LINES`
  and `MAX_CELL_BYTES`.
- **The root** — `MediaOptions`, the upload setting and, beside it, the
  source it was set from (`skep-util`'s `Source`: the default, the flag,
  the variable), which the daemon's open names; `UploadPool` (`new`,
  `admit`), the fetch pool's twin.
- **The test seam** (`test-hooks`, default off; every item of it
  `#[doc(hidden)]`) — the walk hold, the stream hold, the prune hold and its
  notice, the gate's clock, free-space and limits overrides, the index's
  report and counts, the pools' `try_hold`; forwards `skep-blobs/test-hooks`,
  the hazard seam the daemon's hooks reach through the gate's `store`.

Its modules, each with a line saying what it holds, are declared in
`src/lib.rs`; the rules that hold across its files, in the workspace's
`ARCHITECTURE.md` §The media resource; and `tests/it/tidy.rs` holds its two
layers, every hook to the feature's gate, and every `pub` item to this list.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](../../LICENSE-APACHE))
- MIT license ([LICENSE-MIT](../../LICENSE-MIT))

at your option.
