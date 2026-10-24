# skep-util

The support crate below the daemon, the media crate, the blob store, the
client and the shell: the five utilities two or more crates of the
workspace take and none owns — a counting permit, the operator's notice
line, the JSON determinism helpers, a setting's source, and the file one
process writes and reads back after a crash under one tail rule.

Part of [skep](https://github.com/sisbell/skep), an open-source hypertext substrate in the Project Xanadu lineage.

- **The permit pool**, `permits` — a counting try-acquire with no queue
  and no blocking, whose guard returns its slot on drop: the one
  mechanism behind the daemon's five bounded pools — the reconstruction
  budget, the class scan, the fetch, the upload and the write. A permit is
  a slot of the pool that minted it, so no bound can spend another's.
- **The notice line**, `notice` — the operator's stream: one line, or one
  notice of several, every line opening `skepd: ` so a shared stream
  attributes it and the head carrying its time, handed to one thread that
  writes them in order so that a failed write never panics the work the
  notice is about and a stalled reader never waits it. `drain` waits the
  queue out at an exit while the sink takes lines, and gives up
  (`Stalled`) on a sink that has taken none for the caller's bound, so a
  stalled reader holds no exit past it. The crate root says why a library
  spells the name.
- **The JSON determinism helpers**, `json` — `obj`, the key-sorting object
  builder every JSON object the daemon emits is built through, under
  which the last pair given wins; `hex_string`, lowercase hex; and
  `parse_lower_hex` with `hex_nibble`, its exact inverse at a fixed
  width, refusing what `hex_string` never writes.
- **A setting's source**, `source` — `Source`, where a setting's value in
  force came from: the default, a flag, a variable — carried beside the
  value so an open's report names each setting's source.
- **The file under the tail rule**, `file` — a file one process writes and
  reads back after a crash, a kill or a refused write: `read_lines` and
  the streaming `LineReader`, which hand back a file's lines as bytes and
  classify its tail (`Tail`); `Appender`, which writes a line and its
  newline in one write where the last whole line ends, a torn tail first
  cut off (`OnTail::Cut`) or closed by a mark (`OnTail::Close`), cuts a
  failed write back — the two failures folded into one error, or kept
  apart for a caller that stops on the second (`append_by_telling`,
  `AppendFailed`) — and cuts the tail at the open where the caller asks it
  there (`cut`); `write_once`, a new file at its name, synced, a failed
  write removed; `publish`, a file put at its name whole or not at all by
  a locked temp, a rename and the directory's sync, and `publish_by`, the
  same through a temp the caller names and a write it streams, each
  failure by its step (`PublishStep`), the file left standing past the
  rename; `keep_beside`, the bytes a cut drops kept beside the file at the
  first free `.cut-<byte>` name (`KeptName`), durably, a half-kept file
  left standing (`KeepStep`); `remove`, answering `Gone` or `Absent` or
  the failure; and `stale` with `sweep_stale`, the temps a dead run left,
  told from a live run's by the lock its writer holds. The client's key
  store, bindings file and anchor export, the shell's held-writes file, the
  dev board's manifest and the blob store's two logs take it; the parse of
  a line, the policy for a whole line that does not read, when to keep and
  when to cut, every word said and the directory's lock stay the caller's.

An item lives here if and only if at least two crates take it and it has
no subject of its own — a constant is configuration, not a utility, and
stays with the crate whose number it is. The crate names no store and no
engine; its one dependency is `serde_json`. Its modules are in its crate
root (`src/lib.rs`); the rules that hold across its files, in the
workspace's `ARCHITECTURE.md` §The support crate.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](../../LICENSE-APACHE))
- MIT license ([LICENSE-MIT](../../LICENSE-MIT))

at your option.
