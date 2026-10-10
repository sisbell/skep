# Running a board

This file is how to run a skep board: one `skepd` process serving
one board from one data directory. It is for whoever runs a board,
a self-hosted one included, and it covers the daemon's own acts; it
is not a guide to hosting one. Every line it quotes is one this
build of `skepd` writes, and where the daemon says nothing, this
file says so. Most lines on stderr begin `skepd: ` and the UTC
time; the quotes here start after the time, and a name in braces
stands for what the daemon fills in.

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

   It lands at `target/release/skepd`. Name `-p skepd` alone in
   that command: Cargo unifies features across one build, and a
   `--workspace` build that compiles the test suites turns the
   signer on for everything it builds, where the daemon's own build
   holds no signer and only verifies. The toolchain is pinned in
   `rust-toolchain.toml` and the dependencies in `Cargo.lock`.
   Three features matter:

   - `observe`, on by default: the `GET /dump` route, a dump of the
     board's world. Build with `--no-default-features` to leave it
     out.
   - `client`, off by default: a page at `GET /` that makes keys
     and opens signed sessions at the board's origin. Leave it off
     for any board other people reach; packaged notebook builds
     turn it on.
   - `test-hooks`, off: the test suites' hooks. Never build a
     binary you run with it.

2. **Run it** with the one setting it requires:

   ```
   skepd --data-dir <DIR>
   ```

   `<DIR>`, or `SKEPD_DATA_DIR`, is the board's directory. One that
   does not exist is created readable by you alone, the directory
   mode 700 and each file 600; one that exists is recovered. The
   other settings follow, each with its environment variable where
   it has one; a flag beats its variable.

   - `--port <PORT>` (`SKEPD_PORT`): the TCP port on 127.0.0.1, the
     only address the daemon binds. Default 8642; `0` picks a free
     port.
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
   `landing:`. A few of the open's lines carry none. The binary's
   own refusals, written as it exits, carry neither a time nor a
   class word; they are quoted whole, from `skepd:`. In the order
   the daemon writes them:

   1. The port is bound first. A port another process holds
      refuses the start at once, exit 1, before anything in the
      data directory is read or written:

      ```
      skepd: bind 127.0.0.1:{port}: {error}
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
      checkpoint.tmp found ({bytes} bytes) and removed: a checkpoint a crash or the journal's own full volume left half-written, no base, its room on the volume reclaimed by the open
      ```

   8. The media limits and the floor in force:

      ```
      media limits: no record installed — the daemon's default stands: per-account {bytes} (one part in 8 of the volume's capacity of {bytes} bytes, never below 268435456 bytes), venue total none, lease interval 604800000 ms, per-file cap 67108864; the floor in force {floor} bytes of the volume's free space (never below the constant 268435456 bytes; twice the newest checkpoint's size plus one maximal segment of 134217728 bytes above it, re-read as each checkpoint lands)
      ```

   9. The upload setting, `{source}` being `the default`, the flag
      as typed, or the variable with its value:

      ```
      open: media uploads: open ({source})
      open: media uploads: CLOSED ({source}): the creation and the resume are refused uploads_closed
      ```

   10. Each change-feed file the open had to cut:

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

   11. On a claimed board whose journal holds no head, the board's
       first head, written now:

       ```
       the board is claimed and its journal held no head: H.1 written at open, naming the committed pair as it stood
       ```

       Where the head writer refuses it, the open goes on and says:

       ```
       failure: head writer: the head at position {position} was refused ({cause}); no head written this cycle
       ```

   12. With the open done, the configuration warnings, each where
       it applies:

       ```
       warning (at start): board is claimed with --local-trust still on: any loopback party may write as any principal (CLAIMED-PERMISSIVE)
       warning (at start): board is claimed with no configured origin: signed_origins is empty and every signed session will be refused
       warning (at start): configured origin {origin} names a loopback host at a port this daemon is not bound to; re-issue the origin for the bound port
       warning (at start): the dev setting --allow-preview-keys is on: the enrollment of a preview key (the tag-3 row, fndsa512-preview-ed25519) is admitted, a genesis included — a served board runs without it; drop the flag and restart
       ```

   13. The board's mode and its origins, `{mode}` being
       `unclaimed`, `CLAIMED-ENFORCING` or `CLAIMED-PERMISSIVE`,
       and an empty list reading `none`:

       ```
       open: auth: {mode} (--local-trust {on|off}, {source}); configured origins {origins}; signed origins {origins}
       ```

   14. The node prefix, or its absence:

       ```
       open: node prefix {prefix} ({source}): egress and assertion config, never journaled; the blocked-prefix list's off-board test runs against it
       open: no --node-prefix: the off-board test is off (every operator account reads as this board's own); a hosted board must supply one
       ```

   15. Where a list was supplied, the blocked-prefix list in force:
       `open: blocked-prefix list (at start, {path}):`, and beneath
       it the count of entries in force and each inert entry.

   16. The worker threads, started last. A worker thread the OS
       refuses stops the start, exit 1:

       ```
       skepd: the OS refused a worker thread at start: {error}; the workers that started are stopped, the port and the data directory released, and nothing serves; retry under a higher thread limit
       ```

       A refused pruner or checkpoint thread is said, and the board
       serves on:

       ```
       pruner: the OS refused its thread ({error}); no pass runs on this daemon's cadence
       failure: checkpoint thread: the OS refused it ({error}); …
       ```

   17. Later, on a thread of its own, the rebuilt cell index:

       ```
       cell index rebuilt at open: {n} values walked, {n} cells, {n} halt marks, {duration} ({duration} past the prefix test)
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
   out. It is the one line that names the port under `--port 0`:

   ```
   skepd: serving http://127.0.0.1:{port}/ data-dir {path} log-position {position} workers {n}
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
     journal's tail at the next open. Nothing is said; the
     inventory reports the bytes cut as `journal.tail_cut`.
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
   (Start, step 3, item 10). The walk then says three things, the
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
