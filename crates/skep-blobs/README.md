# skep-blobs

The blob store: a board's deposited files, the partial transfers on their
way to becoming one, the records of those transfers, and the leases that
bind a deposited file to the principal who deposited it.

Part of [skep](https://github.com/sisbell/skep), an open-source hypertext substrate in the Project Xanadu lineage.

- **The files**, `blobs/<designation>/<hex>` — installed by the PUT's one
  order: hashed as the bytes arrive, fsynced, renamed onto the hash's name,
  the directory fsynced. A hash already present is REPLACED, never a
  no-op, and no answer says whether the file was already here.
- **The partials**, `blobs/<designation>/.upload-<identifier>` — an
  upload's bytes received so far; a byte counts as received only once it
  is durable.
- **The upload records and the lease log**, `blobs/uploads.log` and
  `blobs/leases.log` — append-only JSON lines, tail-checked and compacted
  at open; a lost record reads as no upload, a lost lease as no lease,
  cured by a re-PUT.

The store knows a principal only as an opaque string, takes no lock of its
caller's and reads no limits record: what bounds a principal's bytes is the
daemon's. Its modules, and its guarantees each linked to the item that
keeps it, are in its crate root (`src/lib.rs`); the rules that hold across
its files, in the workspace's `ARCHITECTURE.md` §The blob store.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](../../LICENSE-APACHE))
- MIT license ([LICENSE-MIT](../../LICENSE-MIT))

at your option.
