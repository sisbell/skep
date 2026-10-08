# skep-febe

The operation surface (FEBE — front end / back end): skep's
command layer, where wire requests become store transactions.

Part of [skep](https://github.com/sisbell/skep), an open-source hypertext substrate in the Project Xanadu lineage.

- **`Op` / `Response`** — the typed enumeration of every operation a
  client can request and every answer it can receive.
- **`OperationSurface::execute`** — total by contract: every input yields a
  `Response`, never a panic; failures are typed rejections with
  fault-site localization.
- **`Rejection::io_kind`** — a durability refusal carries the I/O kind
  behind its code for the daemon to read (a full volume is `StorageFull`);
  it never crosses the wire.
- **`lower_txn`** — the lowering door: a caller that drives a store itself
  lowers the store's `TxnError` into the same classified `Rejection` the
  front door would answer, so its refusal renders as code and detail,
  never as the error's `Debug`.
- **Sessions** — open / close / bootstrap handles, the guest
  (`SessionId::GUEST`), and a per-session retry memo that answers a
  retried write with the acknowledgment it committed, bounded at the
  capacity `OperationSurface::new` is handed — the daemon's own pin, no
  default of the crate's.
- **The codec seam** — marshal/unmarshal is a trait boundary, so
  transports choose their encoding; the operation layer never sees
  bytes.
- **Generic over the world** — reaches stores only through a
  `Stores<W>` factory and names no concrete world: the engine defines
  `World`, and the programs that run the surface — the daemon and the
  conformance harness — name it.

The daemon ([skepd](../skepd)) transports this surface over HTTP;
other transports compose the same crate. How its modules are laid out,
and the rules that hold across them, is in
[ARCHITECTURE.md](../../ARCHITECTURE.md), §The operation surface.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](../../LICENSE-APACHE))
- MIT license ([LICENSE-MIT](../../LICENSE-MIT))

at your option.
