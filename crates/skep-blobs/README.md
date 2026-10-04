# skep-blobs

The blob store: a board's deposited files, the partial transfers on their
way to becoming one, the records of those transfers, and the leases that
bind a deposited file to the principal who deposited it.

Part of [skep](https://github.com/sisbell/skep), an open-source hypertext substrate in the Project Xanadu lineage.

## 1. What skep-blobs is

One directory — the daemon hands it `blobs/` inside the board's data
directory — holding the four media stores the media record names
(`media.md` §The media stores), each a file class with its own crash
story:

- **The files**, `blobs/<designation>/<hex>` — PRIMARY. A file is
  installed by the PUT's one order: streamed to a temp file in its
  target's own designation directory, hashed as it goes, fsynced,
  renamed onto its hash's name, that directory fsynced — and the root
  where the designation directory is new. Nothing names a file before it
  is durable, directory entry and all. The disposition on a hash already
  present is REPLACE, never a no-op, so a file holding the wrong bytes
  under the right name is repaired by a re-PUT of the right ones; the
  replaced instance is first hard-linked to an aside name
  (`.retired-<hex>-<n>`) so the rename frees nothing, and unlinked by
  the deferred step after the answer (`retire_asides`) — open removes
  any aside a crash leaves; and no answer of the store says whether the
  file was already here, by its bytes or by its time.
- **The pruner's reads** — the designation directories, the files at hex
  names, the asides, whether ANY key holds a live lease on a file
  (`any_live_lease`), the expired uploads and their removal
  (`expired_uploads`, `expire_upload`), the unlink of one file
  (`unlink_blob`) — each one act, so a daemon's pass holds its own lock
  around exactly one; and the pending bytes counted under a predicate
  (`pending_bytes_of`, `pending_total_of`), so a daemon leaves out of a
  key's pending bytes the leases its own cells already count.
- **The partials**, `blobs/<designation>/.upload-<identifier>` — the
  bytes received so far of one standing upload. Fsynced at a grain of
  1 MiB, the record's offset written after each sync, so a byte counts as
  received only once it is durable; cut back to the record's offset before
  a resume appends.
- **The upload records**, `blobs/uploads.log` — one JSON line per change
  of one upload: its identifier (128 bits from the OS, 32 lowercase hex),
  its uploader's opaque key, its designation, its declared length, its
  durable offset, its expiry, and a repair's named cell. Append-only,
  tail-checked at open, compacted at open to each upload's latest line
  with every retired upload dropped; reconciled with the partials both
  ways at open — a partial no record names is removed, a record whose
  partial is gone is retired, and their lengths are set to agree.
- **The lease log**, `blobs/leases.log` — one JSON line per deposit:
  the key, the designation and hex, the size and the expiry fixed at the
  PUT. On PATTERNS P22's honest-null arm: append-only, tail-checked, each
  key's current lease its latest line, compacted at open; a lease lapsed
  past a HORIZON answers as NONE, so LAPSED is exact within the horizon.
  A lost lease reads as no lease, cured by a re-PUT.

The crate knows nothing of who a key is, holds no lock a daemon's write
path takes, and reads no limits record: it answers "is
`<designation>/<hex>` held under a live lease of KEY?", "KEY's own
uploads and deposits", "KEY's pending bytes", and the volume's free
space, and nothing of policy. The ordering a finish needs — the rename
through the lease's sync under the daemon's credential-lock read arm —
is the caller's to hold around `Store::finish`; the crate's own
guarantee is the order of its steps and what each leaves behind on a
crash.

Its `test-hooks` feature (default off) compiles in the test seam,
`src/store/hooks.rs`: the hazard seam — a hold or an injected failure at
a named step of the finish, which the crate's own fsync-order tests and
the daemon's SIGKILL harness drive — and the three methods only a test
calls: `install`, which plants a file under a hash its bytes need not
have, `written` and `asides_pending`. A build without the feature
carries none of it.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](../../LICENSE-APACHE))
- MIT license ([LICENSE-MIT](../../LICENSE-MIT))

at your option.
