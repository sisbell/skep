# Running a board

This file is how to run a skep board: one `skepd` process serving
one board from one data directory. It is for whoever runs a board,
a self-hosted one included, and it covers the daemon's own acts; it
is not a guide to hosting one, save §10, which runs the service
that makes boards for other people. Every line it quotes is one
this build of `skepd` writes, or in §10 `skep-provision`, and where
the daemon says nothing, this file says so. Most lines on stderr
begin `skepd: ` and the UTC time; the quotes here start after the
time, and a name in braces stands for what the daemon fills in.

## 1. The full volume

This act and the restore come first: done in the wrong order,
either one takes a board down. The volume is the filesystem the
data directory lives on, and the daemon tells two states of it
apart.

1. **Tell the two states apart.**

   *At the floor*, the volume's free space has fallen below the
   floor in force: the room the daemon holds back from deposits so
   that the journal can always write. Uploads are refused
   `507 deposit_refused` with `scope` `floor`, and every other
   write is served. The daemon says so once, at the first refusal:

   ```
   failure: deposits refused at the floor: the volume's free space {free} bytes is below the floor in force {floor}; every write but a deposit serves; the acts: room on the volume, a pass run early
   ```

   When an upload next finishes with the free space back above the
   floor, it says so once more:

   ```
   landing: deposits admitted again: an upload of {bytes} bytes finished with the volume's free space {free} bytes above the floor in force {floor}
   ```

   *Full*, the board's own writes are refused. Any one of these
   says so:

   - A write is refused with the code `durability`. The daemon says
     so once, and again only after a write has landed in between:

     ```
     failure: a write was refused at a full volume at position {position}: no write lands until room is freed on the volume; reads serve; the next write succeeds by itself once room stands, and no restart is owed
     ```

   - A checkpoint fails. It is said at each attempt:

     ```
     failure: checkpoint FAILED (the head stood at position {position} when the run began): the volume is full ({error}); the journal is not reclaimed and holds every commit; the next attempt is at the cadence's next crossing
     ```

   - `feed-attest.log`, which holds each attested commit's
     signature, fails a line. The daemon says so once, then refuses
     every write `poisoned` until a restart; reads serve:

     ```
     failure: feed-attest.log: position {position}'s line is not durable ({error}); every later write is refused until a restart, whose open rebuilds the line from the journal
     ```

   - A change-feed file stops taking lines, and the board serves on
     from what it holds in memory. `{file}` is one of the four index
     files: `feed-index.log`, `feed-offsets.log`, `feed-masked.log`
     or `feed-streams.log`.

     ```
     failure: commits.log append failed at position {position}: {error}; this file takes no further line, so the next open re-derives from {position} as bare entries
     failure: {file} append failed at position {position}: {error}
     failure: commits.log rewrite failed past its rename: {error}; this file takes no further line, so the next open re-derives from its fence as bare entries
     failure: {file} rewrite failed past its rename: {error}; this file takes no further line, so the next open re-derives from its fence
     ```

   - An upload is answered `500 blob_io`, and the pruner's hourly
     line ends with a clause that names `uploads.log` or
     `leases.log`:

     ```
     ; STOPPED: uploads.log takes no append until a compaction completes
     ```

   - The kernel halts its writes. Every write is refused
     `poisoned`, and the daemon says once:

     ```
     failure: the kernel halted its write paths at position {position}: every write is refused poisoned until a restart; reads serve. The cause is one of three the kernel does not report — a commit that could not be rolled back durably, an unwind past the durability barrier, or the sequence order exhausted; check the volume and the device, then restart
     ```

2. **Make room first.** Grow the volume, or free space that
   something other than the board holds. Never delete, move or
   truncate a file in the data directory to make room:

   - the journal's files, `seg-<n>.wal`, `checkpoint.<n>`,
     `checkpoint.tmp` and `kernel.lock`, are the kernel's, and it
     deletes them itself: old checkpoints, and the journal below
     them, as new checkpoints land; a stray `checkpoint.tmp` at
     the next open;
   - below the journal's reclaim floor, `feed-attest.log` holds the
     only copy of each attested commit's signature;
   - the deposited files under `blobs/` are the depositors' own,
     and nothing rebuilds them.

   A pattern such as `feed-*.log` matches `feed-attest.log` too.

3. **At the floor, run the pruner's pass early.** A restart runs
   it, once the open is done and the cell index is rebuilt; after
   that it runs hourly. The pass removes expired partial uploads,
   and deposited files that no cell names and no live lease holds;
   it never touches a placed picture. A restart is how to run the
   pass early, not a way to make room. The pass says what it did:

   ```
   landing: pruner: {n} expired partials removed, {n} files unlinked, {n} kept, {n} asides removed
   ```

   Where that line goes on with `the unlink pass halted: {why}`,
   the pass unlinked no file.

4. **When the volume is full, never restart before there is
   room.** The open writes before it serves. It compacts the blob
   store's two logs where they hold superseded lines, compacts the
   change feed's files where the journal's reclaim floor has passed
   their oldest entries, and writes back, and syncs, any lines
   `feed-attest.log` is missing. If any of these is refused, the
   open stops with exit 1, and a board that was still serving
   reads is down:

   ```
   skepd: change-feed sidecar: {file}: {error}
   skepd: blob store: {error}
   ```

   No figure says how much room the open needs. Each rewrite needs
   room for a second copy of the file it rewrites.

5. **Then act on the line you saw.**

   - `feed-attest.log`'s line: make room, then restart. The open
     writes the missing line back from the journal and syncs it; on
     a volume still full, the open fails.
   - A change-feed file's stop: make room, then restart. The open
     rewrites the file and needs the room to do it.
   - The checkpoint's failure: make room, and nothing more. The
     next attempt comes by itself at the cadence's next crossing:
     after another 1,024 commits, or another quarter of the newest
     checkpoint's size in journal bytes (never less than 24 MiB),
     whichever comes first.
   - The write refused at a full volume: make room. The next write
     succeeds by itself, and no restart is owed.
   - `500 blob_io`, or a log the pruner names `STOPPED`: make room.
     The next hourly pass compacts the log and lifts the stop.
   - The kernel's halt, or writes refused `poisoned` with no
     `feed-attest.log` line: where the volume is full, make room;
     then restart. The halt ends with the process.

6. **Know what the floor keeps meanwhile.** The floor in force is
   the larger of 256 MiB and twice the newest checkpoint's size
   plus 128 MiB, read again as each checkpoint lands. No deposit
   may take the volume below it, so deposits alone never take the
   room the journal needs to reach its next checkpoint. It holds
   back nothing else that fills the volume. The open names the
   floor in force (Start, step 3) but not the free space; each
   checkpoint's landing line names both:

   ```
   landing: checkpoint at position {position} landed ({bytes} bytes) in {ms} ms; {reclaimed}; the cadence's byte bound {bytes}, the media floor in force {floor}, the volume's free space {free}; …
   ```

   `{reclaimed}` reads `{bytes} journal bytes reclaimed` or
   `nothing reclaimed`.

7. **Know what no act clears.** `feed-attest.log` gains a line for
   every attested commit and is never compacted; nothing the daemon
   does shrinks it. Size the volume for the board's signed history.

8. **Watch between the lines.** `GET /health` answers
   `writes.halted` as `true` while either halt stands. And once an
   hour, while any bad state stands, the daemon writes one
   `standing:` line naming each, its clauses joined by `; `. Among
   them:

   ```
   the write path is halted since position {position} (feed-attest.log)
   the kernel is poisoned
   {file} stopped since position {position}
   deposits refused at the floor (free space {free} below the floor in force {floor})
   ```

## 2. Restore

1. **Stop the daemon** (Stop).

2. **Prove the copy** if it was not proved when it was taken:
   `skepd inventory --data-dir <COPY>` (Back up, step 2).

3. **Replace the data directory whole, from that one copy.** Never
   put the journal of one moment beside the `blobs/` or the
   `feed-attest.log` of another. Keep the directory readable by you
   alone: the daemon refuses to start on one that other users can
   read, and names the `chmod 700` that fixes it (Start, step 3).

4. **Start only once all of `blobs/` has landed.** The open
   reconciles the blob store whether or not it then serves: it
   retires every upload record whose partial file has not arrived,
   and removes every partial file whose record has not. It says
   nothing of this.

5. **Read the open's report** (Start, step 3), and look for a cut
   line for `feed-attest.log`. It ends one of two ways. This ending
   owes nothing, since the open rebuilt what it cut:

   ```
   failure: feed-attest.log: trust ends at position {last} (byte {n} of {length}); the {k} bytes after it are cut; every cut line lies above the reclaim floor at position {floor} and is rebuilt from the journal
   ```

   This ending means signatures held nowhere else are gone from the
   file:

   ```
   failure: feed-attest.log: trust ends at position {last} (byte {n} of {length}); the {k} bytes after it are cut; the lines between position {last} and the reclaim floor at position {floor} are LOST unless the board directory's backup is restored
   ```

   Stop the daemon, put back `feed-attest.log` from a copy that
   holds it whole and took it after its journal (Back up, step 1),
   and start again. The same line on a board you did not restore,
   after a disk fault, calls for the same act. A copy with no
   `feed-attest.log` at all opens without a word: the lines above
   the reclaim floor are rebuilt, and those below it are gone.

6. **Put back one deposited file**, a hole the inventory lists,
   with the pull:

   ```
   skepd pull --data-dir <DIR> --hash <HEX> <FILE>
   ```

   With `--hash`, the hex taken from the inventory's `holes`, the
   pull holds the file to that hash, leaves the journal unopened,
   and can run beside a serving daemon. Without `--hash`, the pull
   reads the board's journal, so the board must be stopped. It
   refuses, exit 1, a file no committed cell names (without
   `--hash`) and a file whose bytes are not the hash named:

   ```
   skepd pull: no committed reference cell names {hex}: the pull restores a file a cell already names and deposits nothing
   skepd pull: nothing installed: {error}
   ```

   On success it prints one line, and the daemon serves the file at
   its next fetch:

   ```
   pulled {hex} ({bytes} bytes) into {path}
   ```

   The pull writes no lease, no upload record, no journal entry and
   no line of the daemon's.

7. **Know what an older copy does.** A restore from an older copy
   rewinds the board: later writes take positions it had already
   used. The daemon writes nothing that tells a restored board from
   one that ran on, so whatever holds a position from before the
   restore has to notice for itself. What the daemon offers for it:
   `GET /health` serves `log_position` and `chain_head`, and
   `GET /chain?at={position}` serves the chain's value at a
   position. A `(position, chain)` pair saved before that the board
   now answers differently, or a position past its head
   (`400 beyond_head`), marks the rewind. The verifying resolver's
   mirror (`skep-resolve`) re-reads the board and will not resume a
   copy the board no longer matches; a client that keeps its own
   index of the board may not check.

## 3. Start

1. **Build the binary**, from the workspace root:

   ```
   cargo build --release -p skepd
   ```

   It lands at `target/release/skepd`. The other way to it is the
   prebuilt archive for your platform, which README.md's Prebuilt
   binaries section says how to check. Name `-p skepd` alone in
   that command: Cargo unifies features across one build, and a
   `--workspace` build that compiles the test suites turns the
   signer on for everything it builds, where the daemon's own build
   holds no signer and only verifies. The toolchain is pinned in
   `rust-toolchain.toml` and the dependencies in `Cargo.lock`.
   Three features matter:

   - `observe`, on by default: the `GET /dump` route, a dump of the
     board's world. Build with `--no-default-features` to leave it
     out.
   - `client`, off by default: the guest reader at `GET /`, one
     self-contained page that reads the board and holds no key,
     token or session. It is off so that a hosted image serves no
     page unless you chose to; packaged notebook builds turn it on.
   - `test-hooks`, off: the test suites' hooks. Never build a
     binary you run with it. The one dev exception: `skep-dev serve
     --own`, under skep-cli's `dev-hooks` feature, links a
     `test-hooks` daemon IN-PROCESS for a throwaway board on a dev
     machine, serving nothing to others.

2. **Run it**, for a notebook you keep, with its origin set and
   local trust off:

   ```
   skepd --data-dir <DIR> --origin http://127.0.0.1:8642 --no-local-trust
   ```

   `<DIR>`, or `SKEPD_DATA_DIR`, is the board's directory, the one
   setting the daemon requires. A notebook you keep lives in the
   platform's data directory: on macOS
   `~/Library/Application Support/skep/board/`; on Linux
   `$XDG_DATA_HOME/skep/board/`, by default
   `~/.local/share/skep/board/`; on Windows
   `%LOCALAPPDATA%\skep\board\`, once the daemon builds there
   (Running it as a service, 9.3). Any other path works, outside a
   synced folder (Back up, step 1). One that does not exist is
   created readable by you alone, the directory mode 700 and each
   file 600; one that exists is recovered.

   `--origin` names the origin a signed session binds to, the
   loopback address at the daemon's port (8642 unless `--port`
   names another): once the board is claimed, a signed session is
   accepted from the configured origins alone, and a claimed board
   with none refuses every one. `--no-local-trust` closes the door
   any program on this machine could otherwise walk through as you:
   once the board is claimed, a bare, unsigned session is refused,
   where with local trust on any loopback party may write as any
   principal. Leave local trust on only for a throwaway board you
   develop against, whose dev provider opens a bare session
   (`README.md`, Running a daemon for frontend development), or
   while you run `skep-mcp`, which opens bare sessions only, knowing
   that every program on this machine, and every other user of it,
   can then read your drafts and write as you.

   The other settings follow, these two among them, each with its
   environment variable where it has one; a flag beats its variable.

   - `--port <PORT>` (`SKEPD_PORT`): the TCP port, on the address
     `--bind <ADDR>` (`SKEPD_BIND`) names — 127.0.0.1 by default, the
     only safe value outside a container whose network is the
     boundary (the hosted image: `README.md`, Running the hosted
     image). Default 8642; `0` picks a free port.
   - `--workers <N>` (`SKEPD_WORKERS`): request threads. Default
     16, minimum 15.
   - `--local-trust` or `--no-local-trust`
     (`SKEPD_LOCAL_TRUST=true|false`): whether bare, unsigned
     sessions from this machine are honoured once the board is
     claimed. On by default; a board served to others must pass
     `--no-local-trust`.
   - `--uploads` or `--no-uploads` (`SKEPD_UPLOADS=true|false`):
     the upload family, open by default. Closed, an upload's
     creation and resume are refused `403 upload_refused` with the
     `detail` `uploads_closed`, and everything else serves.
   - `--origin <ORIGIN>` (`SKEPD_ORIGIN`, comma-separated): an
     origin the board answers for, repeatable. Once the board is
     claimed, a signed session is accepted from these alone.
   - `--blocked-prefixes <FILE>` (`SKEPD_BLOCKED_PREFIXES`): the
     blocked-prefix list. It is read at every start, where a file
     that cannot be read, or is not a list, stops the start; and
     read again whenever it is replaced: write the new list beside
     it and rename it over.
   - `--node-prefix <PREFIX>` (`SKEPD_NODE_PREFIX`): the board's
     node prefix, `1.N`. Without it the blocked-prefix list's
     off-board test is off.
   - `--allow-preview-keys`: a development setting, with no
     variable. A served board runs without it.

   `skepd --help` prints the whole text. A command line the daemon
   cannot read is refused with one line and that text, exit 2; for
   instance:

   ```
   skepd: --data-dir (or SKEPD_DATA_DIR) is required
   ```

3. **Read the open's report** on stderr. After the prefix and the
   time, each line opens with a class word: `open:` for the report,
   `warning (at open):` or `warning (at start):`, `failure:`,
   `landing:`. The binary's
   own refusals, written as it exits, carry neither a time nor a
   class word; they are quoted whole, from `skepd:`. In the order
   the daemon writes them:

   1. The port is bound first, at the address `--bind` names,
      127.0.0.1 unless another is given. A port another process
      holds refuses the start at once, exit 1, before anything in
      the data directory is read or written:

      ```
      skepd: bind {address}:{port}: {error}
      ```

   2. A data directory that other users can read is refused,
      exit 1:

      ```
      skepd: the data directory {path} is mode {mode}: other users of this machine can read the board; chmod 700 {path} and start again
      ```

   3. The build's version and the formats this build reads come
      first of the open's own lines:

      ```
      open: version {version}; this build reads journal format SKJ4, checkpoint format SKC4 and world format 0x534b505700000001
      ```

   4. The directory, before anything is read from it:
      `open: data-dir {path}`.

   5. Each retained checkpoint the open passed over:

      ```
      warning (at open): checkpoint.{n} is not a start point and was SKIPPED — {why}; the world was resolved from {base} and replayed forward from there
      ```

   6. The recovery, `{base}` being `checkpoint.{n}` or `genesis`:

      ```
      open: recovered from {base}, {n} commits replayed, in {ms} ms
      ```

      On a large board the open takes a while, and the board
      answers nothing until it is done. This line says how long the
      recovery took.

   7. A checkpoint a crash left half-written, now removed:

      ```
      open: checkpoint.tmp found ({bytes} bytes) and removed: a checkpoint a crash or the journal's own full volume left half-written, no base, its room on the volume reclaimed by the open
      ```

   8. A write caught before its commit was durable, cut from the
      journal's tail. Said only where bytes were cut; an open after
      a clean stop says nothing here:

      ```
      open: journal tail cut ({bytes} bytes): the un-acked tail a crash or a kill left past the last committed marker — a write caught before its commit was durable, never acknowledged — removed by the open; every acknowledged write stands
      ```

      The inventory reports them as `journal.tail_cut` (Stop,
      step 2).

   9. The media limits and the floor in force:

      ```
      open: media limits: no record installed — the daemon's default stands: per-account {bytes} (one part in 8 of the volume's capacity of {bytes} bytes, never below 268435456 bytes), venue total none, lease interval 604800000 ms, per-file cap 67108864; the floor in force {floor} bytes of the volume's free space (never below the constant 268435456 bytes; twice the newest checkpoint's size plus one maximal segment of 134217728 bytes above it, re-read as each checkpoint lands)
      ```

   10. The upload setting, `{source}` being `the default`, the flag
       as typed, or the variable with its value:

       ```
       open: media uploads: open ({source})
       open: media uploads: CLOSED ({source}): the creation and the resume are refused uploads_closed
       ```

   11. Each change-feed file the open had to cut:

       ```
       failure: {file}: trust ends at position {last} (byte {n} of {length}); the {k} bytes after it are cut; {what follows}
       ```

       What follows is, for `commits.log`:
       `the cut part is re-derived as bare entries`; for the four
       index files: `the cut part is re-derived`; and for
       `feed-attest.log`, one of the two endings in Restore,
       step 5. What a file holds that this daemon cannot read is
       said once per open:

       ```
       failure: feed-attest.log: {n} slots this daemon cannot read, the first at position {position}
       failure: {file}: {n} positions carry malformed document names, the first at position {position}
       ```

       Where `commits.log` was lost or torn, the open also starts a
       walk that re-covers it while the board serves (Restart,
       step 3).

   12. On a claimed board whose journal holds no head, the board's
       first head, written now:

       ```
       landing: the board is claimed and its journal held no head: H.1 written at open, naming the committed pair as it stood
       ```

       Where the head writer refuses it, the open goes on and says:

       ```
       failure: head writer: the head at position {position} was refused ({cause}); no head written this cycle
       ```

   13. With the open done, the configuration warnings, each where
       it applies:

       ```
       warning (at start): board is claimed with --local-trust still on: any loopback party may write as any principal (CLAIMED-PERMISSIVE)
       warning (at start): board is claimed with no configured origin: signed_origins is empty and every signed session will be refused
       warning (at start): configured origin {origin} names a loopback host at a port this daemon is not bound to; re-issue the origin for the bound port
       warning (at start): the dev setting --allow-preview-keys is on: the enrollment of a preview key (the tag-3 row, fndsa512-preview-ed25519) is admitted, a genesis included — a served board runs without it; drop the flag and restart
       ```

   14. The board's mode and its origins, `{mode}` being
       `unclaimed`, `CLAIMED-ENFORCING` or `CLAIMED-PERMISSIVE`,
       and an empty list reading `none`:

       ```
       open: auth: {mode} (--local-trust {on|off}, {source}); configured origins {origins}; signed origins {origins}
       ```

   15. The node prefix, or its absence:

       ```
       open: node prefix {prefix} ({source}): egress and assertion config, never journaled; the blocked-prefix list's off-board test runs against it
       open: no --node-prefix: the off-board test is off (every operator account reads as this board's own); a hosted board must supply one
       ```

   16. Where a list was supplied, the blocked-prefix list in force:
       `open: blocked-prefix list (at start, {path}):`, and beneath
       it the count of entries in force and each inert entry.

   17. The worker threads, started last. A worker thread the OS
       refuses stops the start, exit 1:

       ```
       skepd: the OS refused a worker thread at start: {error}; the workers that started are stopped, the port and the data directory released, and nothing serves; retry under a higher thread limit
       ```

       A refused pruner or checkpoint thread is said, and the board
       serves on:

       ```
       failure: pruner: the OS refused its thread ({error}); no pass runs on this daemon's cadence
       failure: checkpoint thread: the OS refused it ({error}); …
       ```

   18. Later, on a thread of its own, the rebuilt cell index:

       ```
       landing: cell index rebuilt at open: {n} values walked, {n} cells, {n} halt marks, {duration} ({duration} past the prefix test)
       ```

       Until then an upload's creation and resume, and the listing
       of one's deposits (`GET /blob/upload`), are answered
       `503 index_rebuilding`; every other request is served. Where
       the rebuild fails, the daemon says so, and those three are
       answered `503 index_failed` until a restart:

       ```
       failure: cell index: the walk failed ({cause}); the upload family and the door's index arm refuse for the uptime; the act: a restart, or the build's fix where it recurs
       ```

       The pruner's first pass follows (The full volume, step 3).

   An open that fails says why on one line and exits 1. A refusal
   from the journal reads `skepd: engine open: {reason}`; a second
   daemon on the same directory, for one, is refused at the
   kernel's lock:

   ```
   skepd: engine open: journal open/recovery I/O failure: {error}
   ```

   Every other refusal names what refused, after the `skepd: `:
   `registry seeding:`, `blob store:`, `change-feed sidecar:` or
   `blocked-prefix list:`.

4. **Read the one line on stdout**, written once the report is
   out. It is the one line that names the port under `--port 0`,
   and the address bound:

   ```
   skepd: serving http://{address}:{port}/ data-dir {path} log-position {position} workers {n}
   ```

5. **Expect a wait, not a refusal, while it opens.** The port is
   bound from the first moment, but nothing answers until the
   workers start, so a connection made during the open waits. A
   health check during a long open meets a hang; the `open:` lines
   on stderr say how far the open has got.

6. **Check from outside** with `GET /health`: `ok` is `true`;
   `log_position` equals the stdout line's; `auth.claimant` is the
   claiming account, or `null` while the board is unclaimed;
   `media.uploads` matches the setting; `writes.halted` is `false`.

## 4. Stop

1. **Send the process a signal.** There is no stop command, and the
   daemon handles no signal, so a signal that ends a process,
   SIGTERM from `kill <pid>` or SIGINT from Ctrl-C at a terminal,
   ends it at once. The daemon says nothing as it stops. The next
   start recovers, and every write the daemon acknowledged is kept.

2. **Know what a stop leaves**, by what was in flight, and what the
   next open does with it:

   - A checkpoint being written leaves `checkpoint.tmp`. The next
     open removes it and says so (Start, step 3). The journal that
     checkpoint would have freed is freed when a later one lands.
   - A change-feed file being rewritten leaves a `.compact` file
     beside it, such as `commits.log.compact`. The next rewrite of
     the file overwrites it. Nothing is said.
   - An upload being finished: the next open reconciles the blob
     store with what the stop left. Nothing is said.
   - The pruner's pass may leave an aside, a `.retired-` file under
     `blobs/`, which the next open removes. Nothing is said.
   - A write caught before its commit was durable is cut from the
     journal's tail at the next open, which says the bytes it cut
     (`journal tail cut ({bytes} bytes): …`); the inventory reports
     them as `journal.tail_cut`.
   - A claim stopped before its first head: the next open writes
     the head and says so (Start, step 3).
   - The walk that re-covers a lost `commits.log` (Restart,
     step 3): the file is left as the open found it, and the next
     open walks again. Writes made during the walk come back as
     bare entries, without their operation or key.

3. **Know how it ends on its own.** The library's orderly stop is
   for programs that embed the daemon; the `skepd` binary never
   runs it. The binary ends by itself only once every worker thread
   has ended. A thread's panic is said on one line; when the last
   worker is gone, the daemon says the second line below and exits
   1:

   ```
   failure: {thread}: a thread panicked at {location}
   failure: every worker thread has ended; the board serves nothing
   ```

## 5. Restart

1. **Stop, then start** (Stop; Start). A restart runs the open's
   housekeeping once: it compacts the change feed's files to the
   journal's reclaim floor and the blob store's logs, and reconciles
   the blob store's partial uploads; once the cell index is rebuilt,
   the pruner's pass runs. That is why a restart is how to run the
   pass early (The full volume, step 3).

2. **Expect the open's cost.** The board answers nothing until the
   open is done. The open loads the newest checkpoint and replays
   the journal above it, so its cost grows with the board, and the
   recovery line says how long that took (Start, step 3). Then the
   cell index is rebuilt on its own thread, and until it is done an
   upload's creation and resume, and the listing of one's deposits,
   are answered `503 index_rebuilding`.

3. **Where `commits.log` was lost or torn**, the open re-covers the
   positions the file no longer holds by walking the journal behind
   the listener: reads are served and writes accepted meanwhile.
   `GET /changes` answers `503 feed_rebuilding` for a page that
   reaches into the positions not yet covered; `/events` is
   untouched. A torn file is cut first, said as a `failure:` line
   (Start, step 3, item 11). The walk then says three things, the
   `progress:` line every 1,000 boundaries or ten seconds, whichever
   comes first:

   ```
   open: commits.log covers to position {covered}; walking {n} boundaries to position {head}
   progress: the walk at position {position} of {head}, {ms} ms in
   landing: {n} walked, {k} of them bare, in {ms} ms
   ```

   Where the walk's thread dies, the positions stay uncovered until
   a restart:

   ```
   failure: the feed walk ended: {cause}; positions ({low}, {head}] stay uncovered — /changes refuses pages into them until a restart, which walks again
   ```

4. **Read the report as at a start.** A restart under a new
   `--node-prefix` moves the blocked-prefix list's off-board test,
   and the list is read again. If the daemon refused a replaced list
   while it ran, the next start refuses too, until a valid list
   stands at the path:

   ```
   failure: blocked-prefix list: reissue REFUSED — {error}; the list in force stands until a restart, and the next start REFUSES until a valid list stands at {path}: an empty "entries" lifts every block, an absent file lifts none
   ```

## 6. Upgrade

1. **Take a copy first** (Back up). It is the one way back.

2. **Build the new binary** (Start, step 1) and start it over the
   same directory. An upgrade is a new binary over the same files,
   and their format stamps decide whether it opens. Its first line
   names the build and the formats this build reads:

   ```
   open: version {version}; this build reads journal format SKJ4, checkpoint format SKC4 and world format 0x534b505700000001
   ```

3. **A journal of another format is refused by name**, newer or
   older, before the journal is scanned or written, exit 1:

   ```
   skepd: engine open: journal is not this build's format: its segment opens with the stamp `{found}`, this build reads and writes `{expected}` only; there is no migration path …
   ```

   The line ends by saying to delete the data directory and start
   over. Nothing of the journal was written, so the binary that
   last served the board still opens it, and the copy from step 1
   stands besides.

4. **A checkpoint the new build cannot use is passed over**, with
   the warning in Start, step 3, item 5, and the open replays from
   an older checkpoint, or from genesis while the journal still
   reaches it: slower, once. Where no checkpoint loads and the
   journal no longer reaches genesis, the open is refused, exit 1;
   restore from a copy, or start over:

   ```
   skepd: engine open: no retained checkpoint loads and genesis is unreachable; the newest refused: {cause}
   ```

5. **Never open a board directory with an older binary than the
   one that last served it.** The change feed's files carry no
   format stamp. An open that meets a line it cannot parse cuts the
   file there and says so, and a cut in `feed-attest.log` below the
   reclaim floor loses signatures held nowhere else. Go back to an
   older binary only with the copy from step 1.

## 7. Back up

1. **Take one moment's copy of the whole data directory.** The
   directory is one unit, backed up and moved together: the
   journal, the change feed's files with `feed-attest.log` among
   them, and `blobs/`. Take the copy one of three ways:

   - a snapshot of the volume;
   - a copy with the daemon stopped;
   - a live copy, in this order: first the journal, the
     `seg-<n>.wal` and `checkpoint.<n>` files; then the daemon's
     own files, `commits.log`, the four `feed-*.log` index files
     and `feed-attest.log`; then `blobs/`, its designation
     directories (`blobs/blake3/`) first, then `blobs/uploads.log`,
     then `blobs/leases.log`.

   The order is what makes a live copy one moment. Every file a
   cell in the copied journal names was on disk before the cell
   committed, so the later copy of `blobs/` holds it, where a
   `blobs/` copied first misses every picture that committed while
   it ran. Within `blobs/` the lease log goes last, because a
   finished upload writes its lease only once its file is in place.
   `feed-attest.log` syncs each line before the next write can
   begin: taken after the journal, it holds a line for every
   position the journal copy holds, where taken before, it can miss
   the only copy of a signature. The four index files are rebuilt
   at the next open whenever they were taken; a position
   `commits.log` lacks comes back as a bare entry, without its
   operation or key.

   A copy taken while a checkpoint lands may hold a
   `checkpoint.tmp`, and a `feed-attest.log` with lines past the
   journal's head. Both are harmless: the copy's open removes the
   first and says so, and drops the second.

   Never keep the data directory, the key store (`~/.skep/`) or the
   claim's anchor files under a synced folder (Dropbox, iCloud
   Drive, OneDrive): sync corrupts journals and copies keys.

2. **Prove the copy with the inventory**, over the copy and never
   over the served directory:

   ```
   skepd inventory --data-dir <COPY>
   ```

   It prints one JSON object: the holes, every picture whose file
   is absent, of the wrong length, or, re-hashed one whole read per
   file, of other bytes (`--no-rehash` checks lengths alone); each
   account's base and pending bytes, the unattributed bytes and the
   venue total they sum to; the standing and expired uploads; the
   halt marks and any foreign designation directory; and under
   `journal`, its `log_position`, `start_point`,
   `skipped_checkpoints`, `tail_cut` and
   `stray_checkpoint_removed`. A served directory is refused at the
   kernel's lock, exit 1:

   ```
   skepd inventory: the journal at {dir} is held by a running daemon: run the inventory over a copy or a stopped board, and pass --hash <hex> from its listing to pull beside the daemon
   ```

   The inventory writes nothing under `blobs/`, but its open does
   to the journal what every open does. It takes the kernel's lock,
   creating `kernel.lock`; it cuts a torn tail, reported as
   `journal.tail_cut` (`0` where nothing was cut); and it removes a
   stray `checkpoint.tmp`, reported as
   `journal.stray_checkpoint_removed` (`null` where none stood). So
   it needs a copy it can write. One it cannot is refused, exit 1:

   ```
   skepd inventory: the copy at {dir} is read-only: the inventory's open writes the kernel's lock and may cut a torn tail; run it over a writable copy
   ```

   A snapshot mounted read-only is proved only once copied to
   storage that can be written. The inventory reads no change-feed
   file, so a copy that lacks `feed-attest.log`, or holds it torn,
   still proves clean (Restore, step 5).

3. **Label the copy.** The daemon writes no line that marks a
   moment to copy at. The nearest is a checkpoint's landing line,
   `landing: checkpoint at position {position} landed (…`, whose
   position serves as a label; the inventory's
   `journal.log_position` is the copy's own position.

## 8. The cold mirror

1. **Begin any mirror before the board first reclaims its
   journal.** A mirror, the verifying resolver's (`skep-resolve`)
   or any client that copies the board's change feed, reads
   `GET /changes` from position 0. Once a checkpoint lands with
   whole journal segments below the oldest checkpoint kept, the
   daemon deletes them; from then on a page from position 0 is
   answered `410 history_reclaimed`, naming as `floor` the oldest
   position the board still serves. A mirror begun from genesis
   meets that refusal at its first page, and the resolver's mirror
   cannot begin anywhere else. The first checkpoint landing line
   that reports `{bytes} journal bytes reclaimed`, where every
   earlier one said `nothing reclaimed`, marks the moment.

2. **After that, no act makes a cold mirror possible.** The daemon
   offers none.

## 9. Running it as a service

A notebook you keep can run under the platform's service manager,
which starts the daemon at login and again after a failure. The two
units below are written from what the daemon does and are untested:
neither has been loaded on a machine, and each names what to
confirm on the first one. What every unit here shares:

- **Your own user.** The daemon runs as you, so the directory is
  yours to copy (Back up, step 1) and `skepd pull` runs over it
  without `sudo`.
- **No secret.** The daemon holds no key, and the unit passes it
  only a path, a port, an origin and local trust off.
- **A closed umask**, `077`, so every file the daemon makes is 600
  under a directory at 700. The daemon sets those modes itself
  (Start, step 2); the umask is a second guard beside them.
- **SIGTERM to stop.** The daemon handles no signal, so SIGTERM
  ends it at once, and the next start recovers (Stop, step 1).
- **A restart on failure, never after a stop.** An exit other than
  0, or a crash, starts the daemon again; a stop through the
  service manager does not. A start the daemon refuses is retried
  at the unit's pace, its refusal written to the log each time.
- **Room for descriptors.** The unit sets the open-file limit to
  1,024; the daemon sizes its 64 live event streams against a
  limit of 256.

### 9.1 macOS: a launchd agent

Save the agent as `~/Library/LaunchAgents/io.skep.skepd.plist`; it
starts at login and runs as you. Put your login name for
`USERNAME`, and the path of the binary you built (Start, step 1)
for `/usr/local/bin/skepd`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>              <string>io.skep.skepd</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/local/bin/skepd</string>
    <string>--data-dir</string>
    <string>/Users/USERNAME/Library/Application Support/skep/board</string>
    <string>--port</string>          <string>8642</string>
    <string>--origin</string>        <string>http://127.0.0.1:8642</string>
    <string>--no-local-trust</string>
  </array>
  <key>WorkingDirectory</key>   <string>/Users/USERNAME/Library/Application Support/skep</string>
  <!-- the umask, decimal: 63 = 0o077, so every file the daemon creates is 0600 under 0700 (UNTESTED: the key's integer encoding) -->
  <key>Umask</key>              <integer>63</integer>
  <key>RunAtLoad</key>          <true/>
  <!-- restart on a non-zero exit (a refused open, every worker gone), not on a clean stop -->
  <key>KeepAlive</key>
  <dict><key>SuccessfulExit</key><false/></dict>
  <key>ThrottleInterval</key>   <integer>10</integer>
  <key>SoftResourceLimits</key>
  <dict><key>NumberOfFiles</key><integer>1024</integer></dict>
  <key>StandardOutPath</key>    <string>/Users/USERNAME/Library/Logs/skepd.out.log</string>
  <key>StandardErrorPath</key>  <string>/Users/USERNAME/Library/Logs/skepd.log</string>
</dict>
</plist>
```

Make its working directory before the first load; the daemon makes
`board/` inside it:

```
mkdir -p -m 700 "$HOME/Library/Application Support/skep"
```

Load the agent, which starts the daemon; restart it; stop it, which
sends SIGTERM and unloads the agent:

```
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/io.skep.skepd.plist
launchctl kickstart -k gui/$(id -u)/io.skep.skepd
launchctl bootout gui/$(id -u)/io.skep.skepd
```

The daemon's stderr goes to `~/Library/Logs/skepd.log`, and its one
stdout line to `~/Library/Logs/skepd.out.log`. The `Umask` integer's
encoding is unverified: after the first start, `ls -l` the directory
and confirm `-rw-------` and `drwx------`.

### 9.2 Linux: a systemd user unit

Save the unit as `~/.config/systemd/user/skepd.service`; it starts
at login and runs as you. Put the path of the binary you built
(Start, step 1) for `/usr/local/bin/skepd`. The unit names
`~/.local/share` as `%h/.local/share`; where `XDG_DATA_HOME` points
elsewhere, change both its paths:

```ini
[Unit]
Description=skepd — this machine's skep notebook (loopback, the bind's default)
After=network.target

[Service]
ExecStart=/usr/local/bin/skepd --data-dir %h/.local/share/skep/board --port 8642 --origin http://127.0.0.1:8642 --no-local-trust
WorkingDirectory=%h/.local/share/skep
# every file the daemon creates is 0600 under 0700
UMask=0077
# a restart on exit 1 (a refused open, every worker gone) and on a crash; not on `systemctl stop` (SIGTERM is a clean stop to systemd)
Restart=on-failure
RestartSec=5
# the daemon handles no signal: SIGTERM ends it at once, the next open recovers
KillSignal=SIGTERM
TimeoutStopSec=10
LimitNOFILE=1024
# the stream carries its own time per line; the journal adds its own
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=default.target
```

Make its working directory before the first start; the daemon makes
`board/` inside it:

```
mkdir -p -m 700 ~/.local/share/skep
```

Enable it, which starts it now and at each login; restart it; stop
it, which sends SIGTERM; follow its log:

```
systemctl --user enable --now skepd
systemctl --user restart skepd
systemctl --user stop skepd
journalctl --user -u skepd -f
```

A user unit runs while you are logged in, and
`loginctl enable-linger $USER` keeps it running with no session
open. Confirm three things on the first machine it runs on, and for
9.1's agent too: a stop during a checkpoint is followed at the next
start by the `checkpoint.tmp` line (Start, step 3, item 7); with 64
`GET /events` streams open, `/health` still answers and the daemon
closes a 65th; and another user of the machine is refused a bare
session on the claimed board, and a read of its files.

A dedicated user is an option on Linux, never the recipe: a system
unit that runs the daemon as a `_skepd` user owning the data
directory, made with
`install -d -m 700 -o _skepd -g _skepd /var/lib/skepd`, keeps the
board's files from every program you run. Its cost: the files are
no longer yours, so a copy of the directory and `skepd pull` run
under `sudo -u _skepd`; and the key store stays yours, so whatever
runs as you still holds your key and still signs as you.

### 9.3 Windows

Windows is a question, and this file gives it no unit. `skepd` does
not build for Windows: the blob store reads the volume's free space
and capacity through `rustix::fs::statvfs`, which `rustix` leaves
out of its Windows build. What settles it: a Windows reading of
those two figures, or a Windows build without the media resource;
then `skepd` built for a Windows target; then, on Windows, a second
daemon refused at the kernel's lock on a directory one already
serves, and a killed daemon's lock taken by the next start.

## 10. Hosting boards for other people: the provisioning service

This section is for an operator hosting boards for other people,
the shape README.md's Running the hosted image describes: one
container per board, behind Caddy. `skep-provision` is the service
behind its sign-up. It serves the sign-up page and the claim form,
judges the record a person pastes, makes the board through the
host's `docker`, writes the board's proxy snippet and reloads Caddy,
then shows the person the live reply and mails it to them. It holds
no key. Its verbs, flags, requests and files are its own README's
(`crates/skep-provision/README.md`); this section is how to run it
on the VM. The unit and the steps below are written from what the
service does and are UNTESTED on a VM: none has run on one, and the
deployment notes' TO TEST list, in the design repository, names
them. The service's lines begin `skep-provision: ` and carry no time
of their own; the journal adds it.

1. **Ready the host.** Before the service's first start:

   - Docker Engine, with its `docker` command and its `docker`
     group, and the bridge the boards and Caddy share, made once:
     `docker network create skep`.
   - The images the service runs, `skep-hosted` and `skep-cli`,
     built as README.md's Running the hosted image says.
   - Caddy, run as the deployment notes' §4a runs it: a container on
     the `skep` bridge publishing 443 alone, its Caddyfile importing
     `/etc/caddy/boards/*.caddy` for the boards, and its `skep.host`
     block forwarding to the service with
     `reverse_proxy <address>:8842`, where `<address>` is the host's
     address on the `skep` bridge, the gateway
     `docker network inspect skep` names. UNTESTED: that Caddy
     reaches the host there.
   - For the mail, OPTIONAL: a relay client, `msmtp` or `sendmail`,
     configured for the service's user with the relay's
     credentials, a second secret on the host beside the socket's
     reach, and the sending domain's SPF, DKIM and DMARC records, so
     a mail lands and is not junked. The service runs the client as
     `<program> -t`, each message on its standard input. Without one
     no mail is sent, and the person reads the reply on their status
     page alone.

2. **Make the service's user**, a system user with no home and no
   login, in the `docker` group (UNTESTED; the forms Debian and
   Ubuntu take):

   ```
   sudo useradd --system --no-create-home --shell /usr/sbin/nologin skep-provision
   sudo usermod -aG docker skep-provision
   ```

   The unit gives the service the group itself
   (`SupplementaryGroups=docker`); the membership gives it to a
   command run as the user by hand, such as
   `sudo -u skep-provision docker volume ls`, which lists what the
   service sees. The group is the Engine's socket, the host's root
   in effect: the user owns the service's two directories and
   nothing else, and runs the service and nothing else.

3. **Make the snippet directory**, which the service writes and
   Caddy reads, the service's user its owner:

   ```
   sudo install -d -m 755 -o skep-provision -g skep-provision /etc/caddy/boards
   ```

   A start that cannot read it is refused, exit 1. The service
   writes each board's snippet there `0644`, whatever its umask,
   because Caddy reads it through its read-only mount of
   `/etc/caddy`.

4. **Install the binary** from the release archive for the VM's
   platform, `x86_64-unknown-linux-gnu` on an x86-64 VM, checked
   first (README.md, Prebuilt binaries):

   ```
   sudo install -m 755 skep-<version>-x86_64-unknown-linux-gnu/skep-provision /usr/local/bin/
   skep-provision --version
   ```

   It answers `skep-provision <version> (<commit>)`, the version and
   the commit every binary in the archive answers.

5. **Install the unit**, `deploy/skep-provision.service` in the
   repository at the release's tag. In the installed copy, put the
   owner's mailbox for `OWNER@EXAMPLE` (the failure page names it,
   and an answer to the mail goes to it) and the mail's sending
   address for `noreply@skep.host`; to run without mail, drop the
   `--mailer` and `--from` lines together. Then load it, start it now
   and at every boot, see its status, and follow its log:

   ```
   sudo install -m 644 deploy/skep-provision.service /etc/systemd/system/
   sudoedit /etc/systemd/system/skep-provision.service
   sudo systemctl daemon-reload
   sudo systemctl enable --now skep-provision
   systemctl status skep-provision
   sudo journalctl -u skep-provision -f
   ```

   It is a system unit, where §9.2's is a user unit, and it keeps
   what every unit in §9 shares with three departures: it runs as
   the service's own user, not yours; it HOLDS A POWER, the `docker`
   group, where the daemon holds none; and systemd makes its state
   directory, `/var/lib/skep-provision`, for the user at `0700`
   (`StateDirectory=`; UNTESTED), the service refusing at start a
   state directory other users can read. It binds `0.0.0.0:8842`,
   every interface, because Caddy runs in a container and cannot
   reach the host's loopback; the VM's firewall admits 443 alone
   (the deployment notes' §6), so the port is reached from the
   bridge and never from outside the VM. UNTESTED: that the Engine's
   unit is `docker.service`, which the unit requires.

   Run ONE SERVICE PER VM. The label on its volumes is the Engine's,
   the same on every `skep-provision serve`'s, and the service tells a
   half-made board by its own snippet directory alone: a second one on
   the Engine — a staging service, or the binary started by hand beside
   the unit, whose sweep runs before it finds the address taken — would
   read this one's boards being made as half-made at its start (step 9)
   and remove them, and under another snippet directory its live boards
   too. Nothing in a volume tells two services apart, so the service
   cannot check this; the operator keeps it.

6. **Read the serving line.** After its sweep (step 9) the service
   binds its address and says one line on stdout; with the unit's
   settings:

   ```
   skep-provision: serving http://0.0.0.0:8842/ state-dir /var/lib/skep-provision boards-dir /etc/caddy/boards suffix skep.host live 0 swept 0 workers 3 connections 16 mail on
   ```

   `live` counts the boards whose snippets it found, `swept` the
   half-made ones it cleared, `workers` the boards it makes at once,
   and `connections` the requests it serves at once, a connection past
   them waiting its turn. Without the mail lines the line ends `mail
   OFF (no --mailer and --from): no follow-up mail is sent`. A refused
   start is one line on stderr and exit 1, naming its cause: a state
   directory other users can read, or one it cannot make or that is no
   directory, a snippet directory it cannot read, an address it cannot
   bind, a thread the machine will not give. The unit retries it every
   five seconds, the refusal written to the journal each time.

7. **Admit a person.** A sign-up is one line in
   `/var/lib/skep-provision/signups`, `<address> <date>`, and sends
   nothing. The owner reads the file and, for each person to admit,
   mints an invite as the service's user, then mails the one line it
   prints by hand:

   ```
   sudo cat /var/lib/skep-provision/signups
   sudo -u skep-provision skep-provision invite --address <address> --state-dir /var/lib/skep-provision
   ```

   The line is the invite link, the claim form's URL carrying the
   code, `https://skep.host/claim?invite=<code>`. Mint as the service's
   user, never as root: each change replaces the invite file whole,
   owner-only and owned by whoever made the change, and a file root
   made is one the service cannot read. Minting while the service
   runs is safe: the two take turns at `invites.lock`. The person
   opens the link on their own device, names the board and
   pastes their record; the service makes the board, and spends the
   invite once the board is live. A failed board leaves the invite
   issued, and the person posts again.

8. **Know what it keeps, and what it never logs.** In the state
   directory, `signups` and `invites`, each born `0600`: one line per
   sign-up, and one per invite, issued or spent with its board's
   name; beside them `invites.lock`, `0600` too, held over each
   rewrite of the invite file. In the snippet directory, one
   `<name>.caddy` per live board, from which each start rebuilds its
   list of live boards. On the Engine, every volume it made, labelled
   `skep.provision=1`. The sign-up address is the one personal datum
   it keeps; how long it is kept is the operator's to decide and say.
   Its log names the board, the step, each call's exit code and the
   sidecar's stderr — which names each entry of the record by its
   fingerprint and its label, the person's own words, already on the
   board with the record — and never carries the record whole or a
   key of it, a person's address, an invite code or a status token.

9. **Know what a stop leaves.** The service handles no signal:
   SIGTERM, which `systemctl stop` sends, ends it at once. Every file
   it keeps is replaced whole by a rename, so a stop tears none. A
   board a stop cuts off before its snippet is written leaves its
   volume, and perhaps a run, under its name with no snippet. At the
   next start, before it listens, the service lists the volumes under
   its label, removes each one with no snippet and any run under its
   name, and counts those it cleared on the serving line as `swept`.
   A board a stop cuts off after its snippet is written stands, routed
   now or at Caddy's next reload, and the next start counts it `live`
   and leaves it. After the sweep's removals, and after a failed
   board's cleanup, the service looks at what stands under the name;
   where something still stands — a removal that itself failed — the
   log line says INCOMPLETE and names it, and the name stays taken
   until the operator clears it: the snippet,
   `sudo rm /etc/caddy/boards/<name>.caddy` and then
   `docker exec caddy caddy reload --config /etc/caddy/Caddyfile`;
   the run, `docker rm -f <name>`; the volume,
   `docker volume rm <name>`. The queue, the status URLs, a mail not
   yet sent and the invite codes its posts hold live in memory and end
   with the process: a status URL from before a stop answers 404, and
   a live board's code the invite file still says issued — its spend
   could not be written, or the stop came between its snippet's write
   and its spend — is admitted again at the next start unless the
   operator has marked it spent; the log names the board
   (`<name>: the invite could not be marked spent`, or
   `<name>: snippet: written` with no `<name>: the invite is spent`
   after it), never the code.

10. **Know what this version does not do.** It serves no TLS of its
    own: Caddy terminates TLS for `skep.host`. It has no rate limit:
    a post must name an issued invite, four posts at most look at
    what stands under their names at once, one per invite, and four at
    most wait for a worker, a fifth told to try again later; a sign-up,
    which needs no invite, is limited by the sign-up file's 256 KiB cap
    alone: past it a sign-up is refused until the owner trims the file. It
    serves sixteen requests at once (`--connections`), each request in
    and each answer out given a minute, so a client that trickles its
    bytes is cut off; one that holds all sixteen keeps everyone else
    waiting, and a limit per client is the proxy's to set. It sends
    no mail without the relay client.

Confirm on the first VM what the unit and these steps assume, beside
the deployment notes' TO TEST list: that the Engine's unit is
`docker.service`; that `SupplementaryGroups=docker` gives the
service the socket, so the sweep's listing logs
`sweep: volumes: exit 0`, and no refusal, before the first serving
line; that systemd makes `/var/lib/skep-provision` `0700` and the
user's; that Caddy reaches the service at the bridge's gateway on
port 8842, and nothing outside the VM reaches that port; the
`useradd` and `usermod` lines on the VM's distribution; and a real
mail landing in an inbox.
