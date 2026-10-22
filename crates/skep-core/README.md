# skep-core

The daemon's core: who may act on a board, what every write rides and
leaves behind, and the wire's JSON grammar — the collaborators `skepd`
composes behind its router, and nothing of the transport. The routes, the
replies, the history service, the operator's tools and the process are
`skepd`'s, the crate over this one. It depends on the engine — the daemon's
two crates are what the Engine Composition Contract permits, the as-built
list kept in `skep-engine`'s crate doc — on `skep-media` for the cell index
the commits enter, and on `skep-util`.

Part of [skep](https://github.com/sisbell/skep), an open-source hypertext substrate in the Project Xanadu lineage.

- **The session layer**, `auth` — `AuthState` (`open`,
  `reinstall_blocked_at_claim`, `reissue_blocked_prefixes`,
  `blocked_supply_path`, `blocked_supply_absent_line`, `auth_object`,
  `commit_tail`), the daemon's one handle on the layer, opened from an
  `AuthStart` (`read`) — the options, with the blocked-prefix list they
  name read before the daemon's open touches its data directory — and its
  parts: `AuthConfig` (`node_prefix`,
  `node_prefix_line`, `mode`, `auth_line`, `claimed_permissive`,
  `blocked_prefixes`, `bind_port`, `port`) with `Mode` (`of`), the
  challenge store and the sessions store below, `CredentialLock` (`new`,
  `read`, `write`) with its two arms `LockRead` and `LockWrite`, and
  `CredMemo` (`new`, `recall`, `store`, `purge`); the options a daemon is
  built from — `AuthOptions`, `PortAlreadyBound` (`port`), `Origin`
  (`parse`, `as_str`) with `NotCanonical`, `NodePrefix` (`address`) with
  `NotANodePrefix`; the blocked-prefix list `BlockedPrefixes` (`covers`,
  `header`, `issue_is_empty`, `log_lines`), its `BlockedHeader` and the
  reissue's two outcomes `Reissue`; the configuration warnings
  `startup_warnings` (`Warning`); `OsEntropy`, the entropy the handshake
  mints from; `MAX_LIVE_NONCES`, the challenge store's cap the daemon's
  eviction line names; and `key_set_of`, the key-table read.
- **The sessions**, `auth::session` — `Peer` (`of`); `Nonce` (`to_hex`,
  `parse_hex`) and `Challenges` (`new`, `issue`, `burn`, `edge`), the
  store the daemon drains the edge pair of; `Token` (`to_wire`, `parse`),
  `Scope`, `SessionBinding` (`testimony`), `Opened`, `Lookup` and
  `Sessions` (`new`, `open`, `lookup`, `close`); the per-request resolution
  `resolve` answering an `Actor` (`GuestReason`); the handshake —
  `parse_session_body` (`SessionBody`), `handshake` (`HandshakeRefusal`,
  `SessionRejected`) and `CHALLENGE_TTL_MS`.
- **The policy**, `auth::policy` — the three write sequences' admission:
  `plain_admission`; `precheck` with `RecordSig`, `DepositSpans` (`of`,
  `deposit`) and `op_shape_refusal`; `registry_admission` and
  `genesis_seeding_check`; `upload_admission` (`UploadRefusal`, `token`);
  the two classifiers `deposits_credential_link` and
  `deposits_registry_link`; the refusals `CredentialRefusal` and
  `RegistryRefusal` (each `token`, `disposition`) and the attestation's
  causes `AttestFault`.
- **The commits**, `commits` — `Commits`: `open` (a damaged line's cut
  and the lines a file held above the journal's head are kept beside the
  file as `{file}.cut-<byte>` before a byte is cut or dropped, each line
  naming the kept file; the walk run at the open under the same catch as
  its thread), `serial_lock`,
  `serial_figures`, `commit_under`, `take_turn_after_refusal`,
  `write_first_head` (`FirstHead`), `seed_registry` (`Seeded`: the rows
  `written`, the rows that `stood`, the type `refused`) — the link-type
  registry's seed the daemon runs at every open: one named section and one
  `defines` link into `1.1.0.1.0.1` for every type of `skep-registry`'s
  vocabulary the board lacks, as the system principal through the head
  writer's door and its one staging draft, a refusal said once and the
  open going on — `changes` (`ChangesQuery`,
  `ChangesAnswer`, `FeedClass` with `of`), `head_time`, `next_step`
  (`StreamStep`), `announced`, `halted_at`, `say_the_kernels_halt_once`,
  `feed_walk_gone` (`FeedPending` with `is_empty`, what the walk behind the
  listener has yet to land: the region a lost or torn `commits.log` left
  uncovered, and the bare positions a lost `feed-index.log` left unsorted,
  counted as `Unsorted`), `compact_feed_below_reclaim_floor`
  (`FeedCompaction`),
  `stopped_feed_files` (`StoppedFile`), `attest_store_figures`
  (`AttestStoreFigures`), what the never compacted `feed-attest.log` holds
  on disk and in memory, `checkpoint_signal`
  (`CheckpointSignal`: `wait`, `stop`, `is_stopped`, `Woken`), `shutdown`
  and `lines`, the classed door `Lines` (`say`) a line of the daemon's
  goes through to stand in the one record; `write_meta` (`FrameMeta`,
  `attributed`, `WriteMeta`, `Signed`), what the feed will say of a write;
  and `KernelHaltLine` (`at`, `cause`), the kernel's halt line as a
  value.
- **The codec**, `codec` — `JsonCodec` (`marshal_request`, `unparseable`,
  `parse_daemon`, `parse_daemon_value`) answering a `DaemonOp`;
  `to_bytes`, the one marshal door; `op_name`, `check_keys`,
  `key_set_reply`, `credential_refused_reply`, `registry_refused_reply`,
  `wire_address` and `wire_tumbler`.
- **The bounds**, `limits` — `MAX_REQUEST_BODY`, `EDGE_HOLD_DOWN` and
  `STANDING_INTERVAL`, the three the daemon reads too, the last its panic
  hook's rate beside the standing line's cadence;
  `FEED_WALK_PROGRESS_BOUNDARIES`, `FEED_WALK_PROGRESS_INTERVAL` and
  `MAX_CHANGES_PAGE_BYTES`, the core's own.
- **The lock**, `serial` — `SerialGuard`, the write-serialization guard
  the routes hold across the door, and `SerialFigures` (`since`), its
  takes and waits, which the daemon's landing line says.
- **The test seam** (`test-hooks`, default off; every item of it
  `#[doc(hidden)]`) — the feed walk's hold (before its first position, or
  after so many of a lost index's positions sorted), its notice and its
  panic arm, the walk's pending region and pending set, whether it has
  landed, and its progress cadence, the head writer's clock and its one
  refusal, the registry seed's three (a type hidden from a board's seed,
  every type lifted, a refusal of the seed's n-th commit), the feed's and
  the attest store's failure arms and the attest store's sync mark, the
  lines said, the checkpoint signal's tick. Forwards nothing.

Its modules, each with a line saying what it holds, are declared in
`src/lib.rs`; the rules that hold across its files, in the workspace's
`ARCHITECTURE.md` §The daemon's core; and `tests/it/tidy.rs` holds its
three layers, every hook to the feature's gate, and every `pub` item to
this list.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](../../LICENSE-APACHE))
- MIT license ([LICENSE-MIT](../../LICENSE-MIT))

at your option.
