# skep-util

The support crate below the daemon and the media crate: the three
utilities both take and neither owns — a counting permit, the operator's
notice line, and the JSON determinism helpers.

Part of [skep](https://github.com/sisbell/skep), an open-source hypertext substrate in the Project Xanadu lineage.

- **The permit pool**, `permits` — a counting try-acquire with no queue
  and no blocking, whose guard returns its slot on drop: the one
  mechanism behind the daemon's four bounded pools — the reconstruction
  budget, the class scan, the fetch and the upload. A permit is a slot of
  the pool that minted it, so no bound can spend another's.
- **The notice line**, `notice` — the operator's stream: one line, or one
  notice of several, every line opening `skepd: ` so a shared stream
  attributes it, written so that a failed write never panics the work the
  notice is about. The crate root says why a library spells the name.
- **The JSON determinism helpers**, `json` — `obj`, the key-sorting object
  builder every JSON object the daemon emits is built through, under
  which the last pair given wins; `hex_string`, lowercase hex; and
  `parse_lower_hex` with `hex_nibble`, its exact inverse at a fixed
  width, refusing what `hex_string` never writes.

An item lives here if and only if both `skepd` and `skep-media` take it
and it has no subject of its own — a constant is configuration, not a
utility, and stays with the crate whose number it is. The crate names no
store and no engine; its one dependency is `serde_json`. Its modules are
in its crate root (`src/lib.rs`); the rules that hold across its files,
in the workspace's `ARCHITECTURE.md` §The support crate.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](../../LICENSE-APACHE))
- MIT license ([LICENSE-MIT](../../LICENSE-MIT))

at your option.
