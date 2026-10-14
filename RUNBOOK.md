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

   - An upload is answered `500 blob_io`, its detail naming the
     file, the act and the OS's cause, and the pruner's hourly line
     ends with a clause that names `blobs/uploads.log` or
     `blobs/leases.log`, what stopped it, how long ago and how many
     appends it has refused since — each one an upload's creation,
     received bytes, end or finish answered `blob_io`:

     ```
     ; STOPPED: blobs/uploads.log takes no append until a compaction completes — {cause}; stopped {ms} ms, {n} appends refused
     ```

     The cause ends in the OS's own words: `its append failed
     ({error}) and the cut back to its last whole line failed too
     ({error})`, or `its rewrite failed past its rename ({file}:
     {act}: {error}): the rewrite stands at its name`. A full
     volume's `{error}` reads `the volume is full ({the OS's text})`,
     the same words the checkpoint's line uses.

   - The kernel halts its writes. Every write is refused
     `poisoned`, and the daemon says once:

     ```
     failure: the kernel halted its write paths at position {position}: every write is refused poisoned until a restart; reads serve. The cause is one of three the kernel does not report — a commit that could not be rolled back durably, an unwind past the durability barrier, or the sequence order exhausted; check the volume and the device, then restart
     ```

   A volume can be full of files while it holds bytes to spare.
   Every deposited file takes one inode, however few its bytes, and
   the floor holds back bytes alone, so on a volume of many small
   deposits the inodes run out first. The board's writes are then
   refused as *full*, their causes reading `the volume is full (No
   space left on device …)`, while the floor never binds, each
   checkpoint's landing names gigabytes free, and `df -h` agrees;
   `df -i` shows the inodes spent.

2. **Make room first.** Grow the volume, or free space that
   something other than the board holds. Grown room ends the
   floor's refusals at the next upload, which reads the free space
   each time; the default per-account limit, one part in eight of
   the volume's capacity, is read once at start (Start, step 3,
   item 9) and follows a grown volume only at the next start.
   Where the inodes are spent (step 1), only files removed make
   room: grow the volume — an ext4 volume's inodes grow with it —
   or remove files the board does not hold; a large file freed
   elsewhere frees one inode, however many bytes. Never delete,
   move or truncate a file in the data directory to make room:

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
   pass early, not a way to make room. The pass says what it did,
   what it freed, and each of the blob store's two logs' size:

   ```
   landing: pruner: {n} expired partials removed, {n} files unlinked, {n} kept, {n} asides removed, {n} bytes freed; blobs/uploads.log {n} lines ({n} bytes); blobs/leases.log {n} lines ({n} bytes)
   ```

   `{n} bytes freed` is the room the pass made. Where it is `0`
   beside files unlinked, another name still holds those files — a
   hard-link copy of the data directory (`cp -al`, an `rsync
   --link-dest` backup) — and the room comes only once the copy's
   names go: give the copy bytes of its own, or remove it (Back up,
   step 1). Where the line goes on with `the unlink pass halted:
   {why}`, the pass unlinked no file. A log the pass rewrote says
   what it was rewritten from: `— compacted from {n} lines ({n}
   bytes)`.

4. **When the volume is full, never restart before there is
   room.** The open writes before it serves. It compacts the blob
   store's two logs where they hold superseded lines, and proves the
   volume makes hard links by making, and removing, a directory and
   two names under `blobs/` at every open — room is inodes as well
   as bytes; it compacts the change feed's files where the
   journal's reclaim floor has passed their oldest entries, and
   writes back, and syncs, any lines `feed-attest.log` is missing.
   If any of these is refused, the open stops with exit 1, and a
   board that was still serving reads is down:

   ```
   skepd: change-feed sidecar: {file}: {error}
   skepd: blob store: {file}: {act}: {error}
   ```

   The blob store frees what it can before it asks for room — the
   asides a replace or a crash left, the partial uploads that
   expired or that no record names — but no more: a deposited file
   waits for the pruner's pass, which runs only once the open is
   done. Each rewrite needs room for a second copy of the file it
   rewrites. The pruner's last line gives the blob store's two
   logs' sizes (`blobs/uploads.log {n} lines ({n} bytes)`); no line
   gives the change feed's files' sizes.

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
   - `500 blob_io`, or a log the pruner names `STOPPED`: act on the
     words its detail or its cause carries.
     - `the volume is full (No space left on device …)`: make room.
       The upload stands at its last durable point, and the client's
       resume continues it; a finish that met a stopped log was
       refused before it moved anything, and the upload finishes
       once the stop lifts. A stopped log is rewritten whole by the
       next hourly pass, which says so, with how long it stood and
       the appends it refused:
       `; blobs/uploads.log's stop lifted, rewritten whole after {cause}; stopped {ms} ms, {n} appends refused`.
       The pass needs the pruner's thread: where it has ended
       (`pruner thread ended: …`), the stop stands until a restart,
       whose open reads the log afresh.
     - `Read-only file system` or `Input/output error`: the volume
       or its device has failed, and room does not help, since the
       rewrite fails there too. Stop the daemon, repair or replace
       the volume, restoring from a copy where the device lost data
       (Restore), and start again. The open reads each log afresh
       and cuts the line a failed append tore.
     - `no partial stands for this upload`, on a resume: that
       upload's finish failed past its rename — at a directory's
       fsync, or at its lease's append on a full volume — so its
       bytes stand under their hash with no lease, and its partial
       is gone. Neither room nor the pass brings it back: its resume
       answers `blob_io` until the upload is ended, expires, or a
       restart's open retires it. The act is the client's, as the
       detail says: end the upload and PUT its bytes again, which
       leases the file. The re-PUT puts back all there was to lose:
       it is never a case for Restore.
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
   `--hash`), a file whose bytes are not the hash named, and (with
   `--hash`) a `--data-dir` where no directory stands, since it
   makes none:

   ```
   skepd pull: no committed reference cell names {hex}: the pull restores a file a cell already names and deposits nothing
   skepd pull: nothing installed: the file's bytes hash to {hex}, not the {expected} the cell names
   skepd pull: nothing installed: no directory stands at {dir}: the pull installs into a board's own directory and makes none
   ```

   Any other refusal before the install names the file and the act
   that failed, `skepd pull: nothing installed: {file}: {act}:
   {error}`. One past the install says the file now stands under
   its hash and only its durability is owed; run the pull again
   once the volume answers:

   ```
   skepd pull: installed at blobs/blake3/{hex}, but {file}: fsync: {error}: the file stands under its hash and a power loss may yet take it; run the pull again once the volume answers
   ```

   On success it prints one line, and the daemon serves the file at
   its next fetch:

   ```
   pulled {hex} ({bytes} bytes) into {path}
   ```

   The pull writes no lease, no upload record, no journal entry and
   no line of the daemon's, and it holds back no floor. Beside a
   serving daemon, check first that the volume has room for the
   file above the floor in force; each checkpoint's landing line
   names both (The full volume, step 6).

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

8. **After a compromise, discard the blob store's two logs before
   the board serves again.** The deposited files stay; the records
   that bind them go. A lease the compromise planted would let its
   principal place a file that is not theirs — another account's
   picture, published through this board — however many keys are
   rotated since. With the daemon stopped (Stop):

   - prove the files first: `skepd inventory --data-dir <DIR>`
     re-hashes every file a cell names and lists the holes (Back
     up, step 2); a link or a special file planted under `blobs/`
     refuses it, and the open, naming each and the act (Start,
     step 3);
   - remove `blobs/uploads.log` and `blobs/leases.log`, and the
     `.compact` file beside either where one stands — nothing else
     under `blobs/`.

   Then start. The open makes both logs empty, removes every
   partial upload under `blobs/blake3/` and every aside, and says
   nothing of it. The cost: every upload in progress is gone, its
   client's resume answered `404 no_upload`; every deposit not yet
   placed in a cell is no deposit, and the pruner's first pass
   unlinks its file, which its depositor re-PUTs. A placed picture
   keeps its file, since its cell names it. Put back each hole the
   inventory listed with the pull (step 6).

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
   (Running it as a service, 9.3). Any other path works on a
   filesystem that makes hard links — APFS, HFS+, ext4, XFS, btrfs
   and ZFS do; FAT, exFAT and some network shares do not, and the
   daemon refuses to start on one (step 3) — outside a synced
   folder (Back up, step 1). One that does not exist is created
   readable by you alone, the directory mode 700 and each file 600;
   one that exists is recovered.

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

      The capacity it names is read once, here: a volume grown or
      shrunk while the daemon runs moves the default per-account
      limit only at the next start.

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
   `blocked-prefix list:`. The blob store's then names the file, by
   its place in the data directory, and the act that failed, the
   OS's cause last; a partial is named by its directory alone:

   ```
   skepd: blob store: {file}: {act}: {error}
   ```

   Where `blobs/` holds a symbolic link, a special file or a second
   link to a file the store writes in place, the open follows and
   writes through none of them, and its one refusal counts every one
   it found, names up to eight — the partials of one directory as
   one, by the directory — counts the rest by kind, and gives the act
   for each kind at its end, so the line stays whole however many it
   found:

   ```
   skepd: blob store: blobs/ holds {n} entries the blob store never makes, and nothing was followed or written through them: {file} has {n} links; {n} partials in blobs/blake3/ have {n} links; {file} is a symbolic link; …; and {n} more symbolic links. …
   ```

   A second link comes from a hard-link copy (`cp -al`, `ln`, an
   `rsync --link-dest` backup): give the copy bytes of its own
   (`cp -a`), or remove the link. A symbolic link or a special
   file: remove it, and put the store's file back from the board
   directory's copy (Restore). Then start again.

   A volume that makes no hard link refuses the start: a re-PUT of
   a file the board holds gives the file it replaces a second name,
   so the open probes for one before it serves, in a `.link-probe/`
   directory under `blobs/` that it removes again:

   ```
   skepd: blob store: blobs/: link: {error}: the volume under blobs/ makes no second name for a file (a hard link), which a re-PUT of a file the board holds needs; put the data directory on a filesystem that makes hard links — APFS, HFS+, ext4, XFS, btrfs, ZFS; not FAT or exFAT, nor a share that refuses them — and start again
   ```

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

7. **Claim it, the first time.** While `auth.claimant` is `null`,
   any process that can reach the port can claim the board, so claim
   the notebook you keep before anything else runs against it, at a
   terminal, with the `skep` command (`cargo build --release -p
   skep-cli --bin skep`, or the prebuilt archive's):

   ```
   skep keygen
   skep claim --board http://127.0.0.1:8642
   ```

   `skep keygen` makes this device's key in `~/.skep`, asking the
   device's name, a permanent byline. Name the board to `skep claim`
   exactly as step 2's `--origin` names it, character for character:
   the key store keys each binding by the origin as written, so
   `localhost` is another board to it than `127.0.0.1`, and a claimed
   board takes a signed session only at its configured origins. The
   claim asks each of the two anchors its name, offering this
   machine's name and today's date, and a DIRECTORY for its file, with
   no default — an anchor's file is a key's seed, so name two places
   you control, apart, outside `~/.skep` and outside any synced folder
   (Back up, step 1). Then `skep health --board
   http://127.0.0.1:8642` shows `auth.claimant`, the claiming account,
   and says the mode on stderr: `ENFORCING`, with step 2's local trust
   off. `crates/skep-cli/README.md` tables every setting the command
   reads.

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
   - An open stopped while it probes the volume's hard links leaves
     `blobs/.link-probe/` (Start, step 3), which the next open
     removes; until then the inventory lists it among
     `foreign_designations`. Nothing is said.
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
   and their format stamps decide whether it opens; the change
   feed's files and the blob store's two logs carry none (step 5).
   Its first line names the build and the formats this build reads:

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
   reclaim floor loses signatures held nowhere else. The blob
   store's two logs, `blobs/uploads.log` and `blobs/leases.log`,
   carry no stamp either, and an open that meets lines of a shape
   its build does not read — an older build's under a newer binary
   as much as a newer build's under an older one — keeps none of
   them and says nothing. An upload whose record is lost is no
   upload: its partial is removed as an orphan, and its client's
   resume is answered `404 no_upload`. A deposit whose lease is
   lost is no deposit: the pruner takes its file unless a cell
   names it or another live lease holds it, and the cure is the
   depositor's re-PUT. The open's
   compaction then removes the lines for good. Go back to an older
   binary only with the copy from step 1.

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

   A copy holds bytes of its own. Never take it by hard links
   (`cp -al`, an `rsync --link-dest` backup) or by symbolic links
   into another directory: the blob store writes its logs and its
   partials in place, so a second name would carry the board's next
   writes into the copy, and both the open and the inventory refuse
   a `blobs/` that holds one (Start, step 3).

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
   still proves clean (Restore, step 5). It refuses, exit 1, a copy
   whose `blobs/` holds a link or a special file the store never
   makes, counting and naming them as the open's refusal does
   (Start, step 3):

   ```
   skepd inventory: blobs/ holds {n} entries the blob store never makes, and nothing was followed or written through them: {file} has {n} links; … Then try again.
   ```

   It reports nothing of the blob store's two logs themselves: it
   counts the uploads and leases their whole lines hold, so a copy
   whose `uploads.log` or `leases.log` is torn or damaged still
   proves clean, and the copy's open cuts the lines it cannot trust
   and says nothing of it.

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
     built as README.md's Running the hosted image says, from the
     repository at the release's tag — the commit
     `skep-provision --version` names. The service reads the sidecar's
     lines and a board's `/health` as its own build's `skep` and
     `skepd` print them, so the binary and both images are one
     commit: an image from another may answer in lines this binary
     does not read, and every board then fails after its claim run is
     made. An image names its commit,
     `docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' skep-cli`,
     its first twelve characters the binary's, and the binaries in the
     images say the same twelve: `docker run --rm skep-cli skep
     --version` and `docker run --rm skep-hosted --version` each end
     in the `(<commit>)` that `skep-provision --version` ends in. Keep
     both images, and the `:previous` tags step 13 makes, through every
     cleanup of the host: `skep-cli` runs a moment per board, so between
     boards no container uses it, and `docker image prune -a` or
     `docker system prune -a` — the room a full disk tempts — removes
     it, after which every board fails at its dark claim, the sidecar's
     lines naming the image not found, until it is built again; and
     `docker system prune` or `docker container prune` removes every run
     that stands stopped — each board's, after the Engine's restart
     (step 12) — its volume left. Make room on this host with
     `docker builder prune` and `docker image prune` without `-a`, each
     leaving every tagged image and every container, by trimming the
     system's logs, or with a larger disk.
   - Caddy, run as the deployment notes' §4a runs it: a container on
     the `skep` bridge publishing 443 alone, its Caddyfile importing
     `/etc/caddy/boards/*.caddy` for the boards, and its `skep.host`
     block forwarding to the service with
     `reverse_proxy <address>:8842`, where `<address>` is the host's
     address on the `skep` bridge, the gateway
     `docker network inspect skep` names. UNTESTED: that Caddy
     reaches the host there.
   - For the mail, OPTIONAL: a relay client, `msmtp` or `sendmail`,
     installed, and configured once its user stands (step 2): the
     relay's credentials, a second secret on the host beside the
     socket's reach, and the sending domain's SPF, DKIM and DMARC
     records, so a mail lands and is not junked. The service runs the
     client as `<program> -t`, each message on its standard input.
     Without one no mail is sent, and the person reads the reply on
     their status page alone.

   Five of the service's settings are each one half of a pair whose
   other half is set here, and the two change together or not at all,
   never while boards stand: `--listen`'s port and the
   `reverse_proxy <address>:8842` of Caddy's `skep.host` block;
   `--network` and the bridge Caddy's run line joins; `--caddy` and
   Caddy's container's name; `--boards-dir` and the Caddyfile's
   `import /etc/caddy/boards/*.caddy`, through Caddy's mount of
   `/etc/caddy`, where the service's reload reads
   `/etc/caddy/Caddyfile`; `--suffix` and the Caddyfile's two site
   blocks, the DNS wildcard and every `invite`'s `--suffix` (step 7).
   The service reloads Caddy as `docker exec <caddy> caddy reload`
   and routes each board at `<name>:8642` on the bridge: Caddy as a
   container on the bridge is the one shape it runs. Every board's
   route change reloads Caddy's configuration, so change the
   Caddyfile beside itself and prove it before it is the one loaded —
   a Caddyfile that does not load fails each board's reload, and the
   board with it:

   ```
   sudo cp /etc/caddy/Caddyfile /etc/caddy/Caddyfile.new
   sudoedit /etc/caddy/Caddyfile.new
   docker exec caddy caddy validate --adapter caddyfile --config /etc/caddy/Caddyfile.new
   sudo mv /etc/caddy/Caddyfile.new /etc/caddy/Caddyfile
   docker exec caddy caddy reload --config /etc/caddy/Caddyfile
   ```

   UNTESTED: `caddy validate` on the VM's Caddy build.

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

   For the mail, the relay client's configuration where the service's
   user reads it. The user has no home, so the client's system file is
   the one read — msmtp's `/etc/msmtprc` (sendmail's is its own),
   holding the relay's account — owned by root and readable by the
   service's group alone; then prove it as the service's user before
   the service's first start, the mail landing:

   ```
   sudo chown root:skep-provision /etc/msmtprc
   sudo chmod 640 /etc/msmtprc
   printf 'To: <you>\nSubject: test\n\ntest\n' | sudo -u skep-provision /usr/bin/msmtp -t
   ```

   The start proves only that the client can be run, never that it is
   configured, and the client reads its file at every send, so a
   credential's change needs no restart. UNTESTED: that msmtp reads
   `/etc/msmtprc` for a user with no `~/.msmtprc`.

3. **Make the snippet directory**, which the service writes and
   Caddy reads, the service's user its owner:

   ```
   sudo install -d -m 755 -o skep-provision -g skep-provision /etc/caddy/boards
   ```

   A start that cannot read it, or cannot write it, is refused,
   exit 1. The service writes each board's snippet there `0644`,
   whatever its umask, because Caddy reads it through its read-only
   mount of `/etc/caddy`.

   The directory is also the service's list of boards: at every
   start the sweep (step 9) removes each volume under its label with
   no snippet here, its run and the volume both. So a start over an
   emptier directory removes every board it lacks. Never change
   `--boards-dir`, empty the directory, or start the service on a VM
   restored with its volumes but not this directory: restore the
   directory with the volumes (step 14), or write each board's snippet
   again from the deployment notes' §4a template before the first
   start.
   To take a board's route down and keep its volume, stop its run
   (`docker stop <name>`) and leave its snippet — Caddy then answers
   503 for the name — or copy the volume out before removing the
   snippet.

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
   owner's mailbox for `<OWNER-MAILBOX>` (the failure page names it,
   and an answer to the mail goes to it) and the mail's sending
   address for `noreply@skep.host`; to run without mail, drop the
   `--mailer` and `--from` lines together. `<OWNER-MAILBOX>` is no
   address, so a unit installed without it replaced refuses to start,
   naming `--reply-to`. Then load it, start it now and at every boot,
   see its status, and follow its log:

   ```
   sudo install -m 644 deploy/skep-provision.service /etc/systemd/system/
   sudoedit /etc/systemd/system/skep-provision.service
   sudo systemctl daemon-reload
   sudo systemctl enable --now skep-provision
   systemctl status skep-provision
   sudo journalctl -u skep-provision -f
   ```

   Every setting is on the unit's `ExecStart=` and read once, at start
   — the service reads no environment variable for one: to change
   one, `sudoedit` the installed unit, `sudo systemctl daemon-reload`,
   and restart when step 12 allows. A setting fixed into each board at
   its making — the image, the bridge, the suffix, the log rotation —
   reaches the boards made after the restart alone (step 13).

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
   the Engine would read this one's boards being made as half-made at
   its start (step 9) and remove them, and under another snippet
   directory its live boards too. A second `serve` over this one's
   state directory — the binary started by hand beside the unit — is
   refused at its start before its sweep,
   `another serve holds /var/lib/skep-provision/serve.lock`, and so
   is one on its port; one under another state directory and another
   port, a staging service, nothing in a volume tells apart, and the
   operator keeps it.

6. **Read the start.** The service says its version first, then the
   settings every board is made with and the sign-up file's fill,
   binds its address, sweeps (step 9), and says one line on stdout,
   the serving line; with the unit's settings:

   ```
   skep-provision: version <version> (<commit>)
   skep-provision: boards made from image skep-hosted with the sidecar skep-cli, on the bridge skep behind the proxy container caddy, each serving run's log in files of 10m, 5 kept; mail through /usr/bin/msmtp -t from noreply@skep.host; the failure page names <the owner's mailbox>
   skep-provision: the sign-up file holds 0 of its 262144 bytes
   skep-provision: sweep: listing the volumes under the label
   skep-provision: sweep: volumes: exit 0
   skep-provision: sweep: 0 volumes under the label, 0 of them half-made and 0 cleared; in <d> ms
   skep-provision: serving http://0.0.0.0:8842/ state-dir /var/lib/skep-provision boards-dir /etc/caddy/boards suffix skep.host live 0 swept 0 workers 3 connections 16 mail on
   ```

   The version line names the binary an upgrade's restart now runs;
   the settings line, what the serving line leaves out — a wrong
   `--network` or `--caddy` is read there, before a board fails on
   it. The sweep names its listing before it asks the Engine for it,
   so a start whose last line that is, no serving line after it, is an
   Engine that has not answered (step 12). The sweep's last line says
   what it listed and did, and how long the start waited on it
   (step 9). `live` counts the boards whose
   snippets it found, `swept` the half-made ones it cleared, `workers`
   the boards it makes at once, and `connections` the requests it
   serves at once, a connection past them waiting its turn. Without
   the mail lines the settings line
   says `no mail` and the serving line ends
   `mail OFF (no --mailer and --from): no follow-up mail is sent`.
   A refused start is one line on stderr and exit 1, naming its
   cause: a state directory other users can read, one another user
   owns, or one it cannot make or that is no directory; another
   `serve` holding it; a `--mailer` it cannot run; a snippet directory
   it cannot read or write; an address it cannot bind; a thread the
   machine will not give. All but the last are refused before the
   sweep. The unit retries it every five seconds, the refusal written
   to the journal each time. A usage refusal, exit 2 — the unit's
   command line misspelt, its `<OWNER-MAILBOX>` left — is not
   retried: `systemctl status` shows the unit failed and the journal
   the usage text once; mend the line, `daemon-reload`, and start it.

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
   code, `https://skep.host/claim?invite=<code>`. Where the unit's
   `serve` takes `--suffix`, give `invite` the same: the link carries
   it. Mint as the service's user, never as root: each change
   replaces the invite file whole, owner-only and owned by whoever
   made the change, and a file root made is one the service cannot
   read — so a mint by any user but the state directory's owner is
   refused at its door, naming both owners, and nothing in the
   directory is touched. Minting while the service runs is safe: the
   two take turns at `invites.lock`. The person
   opens the link on their own device, names the board and
   pastes their record; the service makes the board, and spends the
   invite once the board is live. A failed board leaves the invite
   issued, and the person posts again.

8. **Know what it keeps, and what it never logs.** In the state
   directory, `signups` and `invites`, each born `0600`: one line per
   sign-up, and one per invite, issued or spent with its board's
   name; beside them `invites.lock`, `0600` too, held over each
   rewrite of the invite file, and `serve.lock`, held by a running
   `serve` for its life. In the snippet directory, one
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
   next start, its address bound and before it serves, the service
   lists the volumes under its label, removes each one with no
   snippet and any run under its name — the snippet directory is the
   list of boards it spares (step 3) — and counts those it cleared on
   the serving line as `swept`. The sweep ends on a line of its own —
   the volumes listed, the half-made among them, those cleared, the
   names it left INCOMPLETE for the operator to clear (below), and the
   time it took:

   ```
   skep-provision: sweep: 3 volumes under the label, 2 of them half-made and 1 cleared; left INCOMPLETE: bob; in 412 ms
   ```

   A snippet that stands with no volume under the label is said and left,
   `<name>: its snippet stands with no volume under the label …`: a
   route to no board, its name taken for good — remove the snippet and
   reload Caddy, as below — or a board made by hand, outside the
   label, which `docker volume inspect <name>` finds. A listing that
   fails skips the sweep, and the line that says so says what it
   leaves: such a board stays taken until a start whose listing
   answers. A board a stop cuts off after its snippet is written
   stands, routed now or at Caddy's next reload, and the next start
   counts it `live`, leaves it, and names it,
   `<name>: routed at start with no invite line spent under it …`,
   until its invite is marked spent (step 11); reload Caddy, as below,
   to route it now. A failed board's cleanup logs what its run said,
   before it removes the run, each line
   `<name>: cleanup: the run said: …`: the board's own daemon's
   account of the failure, kept nowhere else once the run is gone.
   After the sweep's removals, and after a failed board's cleanup, the
   service looks at what stands under the name; where something still
   stands — a removal that itself failed — the log line says
   INCOMPLETE and names it, and the name stays taken until the
   operator clears it: the snippet,
   `sudo rm /etc/caddy/boards/<name>.caddy` and then
   `docker exec caddy caddy reload --config /etc/caddy/Caddyfile`; the
   run, `docker rm -f <name>`; the volume, `docker volume rm <name>` —
   a volume left with no snippet the next start's sweep clears too. A
   verdict `INCOMPLETE — the look at what stands could not be made: …`
   names the look's source, `docker could not run` or the snippet
   directory by its path; once a look can be made, what stands is the
   operator's to clear, as above. The queue, the status URLs, a mail
   not yet sent and the invite codes its posts hold live in memory and
   end with the process: a status URL from before a stop answers 404,
   its page saying a restart most often ends one and what the person
   may do — post again, or, where their name now meets "That name is
   taken", write to the owner, for the board under it may be theirs;
   and a live board's code the invite file still says issued — its
   spend could not be written, or the stop came between its snippet's
   write and its spend — is admitted again at the next start unless
   the operator has marked it spent (step 11); the log names the board
   (`<name>: the invite could not be marked spent`, or
   `<name>: snippet: written` with no `<name>: the invite is spent`
   after it, and at the next start
   `<name>: routed at start with no invite line spent under it …`),
   never the code.

10. **Know what this version does not do.** It serves no TLS of its
    own: Caddy terminates TLS for `skep.host`. It limits no request's
    rate: a post must name an issued invite, four posts at most look at
    what stands under their names at once, one per invite, and four at
    most wait for a worker, a fifth told to try again later; a sign-up,
    which needs no invite, is limited by the sign-up file's 256 KiB cap
    alone: past it a sign-up is refused until the owner trims the file,
    the cap said once and its end once. It serves sixteen requests at
    once (`--connections`), each request in and each answer out given a
    minute, so a client that trickles its bytes is cut off; one that
    holds all sixteen keeps everyone else waiting, and a limit per
    client is the proxy's to set. The log says it, once as the pool
    fills and once a thread has stood free for fifteen seconds after:

    ```
    skep-provision: connections: all 16 threads serving; a connection past them waits in the listener's queue
    skep-provision: connections: a thread free again after all 16 stood serving 3 times, across 2841 ms
    ```

    Its log is bounded too, so a stranger's requests cannot drown the
    lines these steps read: a refusal no invite bounds — a post with no
    code of the code's form, a code the invite file does not hold or
    holds spent, a sign-up with no address — is said at most once a
    minute with the count of like ones since
    (`— <n> more since the last said`); and a failure met at every
    request — the invite file unread, the sign-up file unkept, a look
    at a name not made — once as it starts, naming the file and what
    it refuses, and once as it ends, with the requests it refused. It
    sends no mail without the relay client.

11. **Do by hand what the log asks**, as the service's user and never
    as root: a state file root writes is one the service cannot read,
    and a mint as root is refused at the state directory's door.

    - `<name>: the invite could not be marked spent (…)`, a
      `<name>: snippet: written` with no `<name>: the invite is spent`
      after it, or at a start
      `<name>: routed at start with no invite line spent under it …`:
      mark the invite spent as the service's user — before any
      restart, for the next start admits a post on it until it is
      marked — holding the invite file's lock so the service's own
      rewrite waits, a board going live meanwhile waiting at its spend:

      ```
      sudo -u skep-provision flock /var/lib/skep-provision/invites.lock vi /var/lib/skep-provision/invites
      ```

      rewriting the line `<code> <address> issued <date>` of the
      person who asked for the name as
      `<code> <address> spent <name> <today>`; the log names the
      line's issue date — at the board's admission,
      `<name>: admitted; … its invite issued <date>`, and again at the
      failed spend — never its code or its address. Until it is
      marked, a post naming the code is refused, its line naming the
      board that holds the code:
      `its invite is held by <name>'s board, live, …`.
    - `a sign-up refused: the sign-up file is at its … cap`, said once
      until a sign-up is kept again: trim the file as the service's
      user, `sudo -u skep-provision vi /var/lib/skep-provision/signups`;
      a sign-up made during the edit may be lost. The start says the
      file's fill against its cap, so it is read filling before it is
      full.
    - `<name>: mail: given up …`: write to the person yourself. Their
      address is on the invite file's line spent under the name; the
      reply's facts are `https://<name>.skep.host`, account `1.0.1`,
      principal `1`, and its whole text stands on the post's status
      page until the service stops. Each refused try names the relay
      client's exit code with its `sysexits.h` name where it has one —
      `exit 75 (EX_TEMPFAIL)`, the relay unreachable or deferring;
      `exit 77 (EX_NOPERM)`, refused for the sender;
      `exit 78 (EX_CONFIG)`, the client's own configuration (UNTESTED:
      the codes the VM's client gives) — and never the relay's words,
      which name the recipient. A try by hand as the service's user,
      the one step 2 proves the client by, says why the relay refused:

      ```
      printf 'To: <you>\nSubject: test\n\ntest\n' | sudo -u skep-provision /usr/bin/msmtp -t
      ```

    - `connections: accept failed (Too many open files …)`, said once
      until `connections: accept recovered after <n> failures, …`, with
      the span the failures took, new connections waiting in the
      listener's queue meanwhile: `--connections` past what the unit's
      `LimitNOFILE=` covers, or descriptors leaked; lower the one or
      raise the other, and restart (step 12).

    UNTESTED: that `flock(1)` and the service's lock are one lock (the
    service's is `flock(2)` on Linux); an editor that writes the file
    by a rename leaves it the service's user's, and the service's next
    rewrite of it is `0600` again.

12. **Restart or upgrade knowing what a stop ends.** Restart when no
    board is in flight: every `taken by a worker` in the log has its
    `LIVE` or `FAILED` after it, and every `LIVE` its
    `the invite is spent`. A stop that comes sooner — or that is no
    one's choice: a crash, the Engine's restart, a reboot — leaves each
    board where it was cut. One cut before its `snippet: written` is
    swept at the next start; its person's page answers 404, and they may
    post again. One cut after it stands, routed now or at Caddy's next
    reload, its invite still issued: the next start names it,
    `<name>: routed at start with no invite line spent under it …`, and
    until its invite is marked a post on it is admitted again — its
    person, whose page answers 404 and whose name now meets D-4, may
    post another name and make a second board on one invite. For each
    board the start so names, reload Caddy
    (`docker exec caddy caddy reload --config /etc/caddy/Caddyfile`) and
    mark its invite spent (step 11). A post `admitted` with no
    `taken by a worker` after it waited in the queue, which a stop drops
    too, its page answering 404. A mail with no `sent` or `given up`
    line is dropped. With mail off, every live board's reply stands on
    its status page alone, and a stop ends every status page. The
    start's first line names the version it runs. A board's lines carry
    their times, so a board's length and the queue's are read from them,
    and every step says something at least once a minute — the `/health`
    wait, the longest, says its bound as it begins and what it sees at
    every fifteenth try:

    ```
    skep-provision: alice: taken by a worker 1840 ms after its admission; 2 still waiting
    skep-provision: alice: health: waiting for the pair, at most 60 tries 1000 ms apart
    skep-provision: alice: health: no pair yet at try 15 of 60, 21530 ms into the wait: claimant null, local_trust false
    skep-provision: alice: LIVE at https://alice.skep.host, 48210 ms after a worker took the post
    skep-provision: alice: mail: handed to the sender, 0 ahead of it
    ```

    A board `taken by a worker` with no further line for a minute is a
    `docker` call that has not returned:
    `sudo -u skep-provision docker ps` hangs too; restart the Engine,
    which restarts the service with it (`Requires=`). A start whose last
    line is `sweep: listing the volumes under the label`, with no
    serving line for a minute after it, is the same: a `docker` call
    that has not returned.

    An Engine restart stops every container, and by Docker's
    documentation `--restart on-failure` — the policy every board's
    serving run and Caddy's run carry — restarts none the Engine's own
    restart stopped, nor any after a reboot (UNTESTED). After either,
    start what stands stopped, Caddy first, then each board:

    ```
    docker ps -a --filter status=exited --format '{{.Names}}'
    docker start caddy
    docker start <name>
    ```

    The service's start counts every board whose snippet stands as
    `live`, its run running or not.

    A board `LIVE` with no `the invite is spent` after it for a minute
    waits at the invite file's lock: an editor step 11 opened holds
    it, the board's worker and its mail waiting behind it. Close the
    editor; never restart for it, for a stop there leaves the board
    standing and its invite issued. A hand-over whose count of mails
    ahead climbs from one board to the next is a relay client that has
    not returned, every later mail waiting behind it.

13. **Upgrade the service and its boards together.** The binary and
    the two images are one release, at one commit (step 1).

    - Before: copy each board's volume (§7, a snapshot of the volume),
      and keep the images in service under tags of their own, kept out
      of every prune (step 1), so a board the new image refuses can run
      the old one again:

      ```
      docker tag skep-hosted skep-hosted:previous
      docker tag skep-cli skep-cli:previous
      ```

    - Build both images at the release's tag (step 1) and install the
      binary (step 4). Compare the release's
      `deploy/skep-provision.service` with the installed copy — a
      release's change to the unit reaches the VM only by hand — and
      carry it across, keeping the installed mailbox and sending
      address. Then `sudo systemctl daemon-reload` and restart
      (step 12); the version line names the binary.
    - Boards made from then on run the new image. A board made before
      keeps the image it was made with — Docker's restart restarts
      that container — until its serving run is made again on its own
      volume, by the line the service makes it with, the settings
      line's values in place of these defaults:

      ```
      docker stop <name>
      docker rm <name>
      docker run -d --init --name <name> --read-only --cap-drop ALL --security-opt no-new-privileges --ulimit nofile=1024:1024 --restart on-failure --log-opt max-size=10m --log-opt max-file=5 --network skep -v <name>:/var/lib/skepd -e SKEPD_ORIGIN=https://<name>.skep.host --label host=<name>.skep.host skep-hosted
      ```

      The service's suite holds this line to the one it runs. Between
      the stop and the run the name answers no board, and Caddy routes
      it again once the new run's `/health` answers the pair. A journal
      the new image refuses (§6 step 3) runs `skep-hosted:previous` by
      the same line, its last word that tag; never run the old image
      over a volume the new one has served (§6 step 5).

14. **Back up and restore the host's boards as one moment.** Three
    things make the service's picture of its boards and move together:
    the state directory (`/var/lib/skep-provision`: the invites and
    the sign-ups), `/etc/caddy` (the Caddyfile and the snippet
    directory, the list of boards the sweep spares, step 3), and the
    Engine's volumes under the label (the boards). A snapshot of the
    VM's disk takes them at one moment where they share it (the
    deployment notes' §6); where boards' volumes stand on disks of
    their own, snapshot every disk with the service stopped
    (`sudo systemctl stop skep-provision`).

    Restore all three from one moment, never one alone. A snippet
    directory older than the volumes leaves each board made since with
    a volume and no snippet, which the first start's sweep removes,
    its data with it. An invite file older than the boards says issued
    for codes boards have spent since, which a post spends again on a
    second board — the first start names each such board,
    `<name>: routed at start with no invite line spent under it …`:
    mark each such line spent (step 11), finding it by its issue date
    in the service's log, `journalctl -u skep-provision`:
    `<name>: admitted; … its invite issued <date>`. Before the first
    start after a restore, with the service stopped, set the two lists
    side by side, and write the snippet of each board to keep that has
    a volume and no `<name>.caddy`, from the deployment notes' §4a
    template:

    ```
    sudo -u skep-provision docker volume ls -q --filter label=skep.provision=1
    ls /etc/caddy/boards
    ```

Confirm on the first VM what the unit and these steps assume, beside
the deployment notes' TO TEST list: that the Engine's unit is
`docker.service`; that `SupplementaryGroups=docker` gives the service
the socket, so the sweep's listing logs `sweep: volumes: exit 0`, and
no refusal, before the first serving line; that systemd makes
`/var/lib/skep-provision` `0700` and the user's; that
`RestartPreventExitStatus=2` leaves a usage refusal failed and
unretried; whether a board's serving run and Caddy's run,
`--restart on-failure` both, run again after
`sudo systemctl restart docker` and after a reboot (step 12); that
`docker logs --tail 20 <name>` reads a failed run's lines back under
the Engine's log driver; that Caddy reaches the service at the
bridge's gateway on port 8842, and nothing outside the VM reaches that
port; that the relay client reads its configuration where step 2 puts
it; that a board's busiest hour fills less than its log files hold,
five files of `10m`, so a rotation keeps the hour a standing state is
said again in; the `useradd` and `usermod` lines on the VM's
distribution; and a real mail landing in an inbox.
