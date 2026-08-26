# skep-febe

The operation surface (FEBE — front end / back end): skep's
command layer, where wire requests become store transactions.

Part of [skep](https://github.com/sisbell/skep), an open-source hypertext substrate in the Project Xanadu lineage.

- **`Op` / `Response`** — the typed enumeration of every operation a
  client can request and every answer it can receive.
- **`Operation::execute`** — total by contract: every input yields a
  `Response`, never a panic; failures are typed rejections with
  fault-site localization.
- **Sessions** — open / close / bootstrap handles and a per-session
  idempotency memo (byte-identical ack replay for retried requests).
- **The codec seam** — marshal/unmarshal is a trait boundary, so
  transports choose their encoding; the operation layer never sees
  bytes.
- **Generic over the world** — reaches stores only through a
  `Stores<W>` factory; only the engine and the daemon ever name a
  concrete world.

The daemon ([skepd](../skepd)) transports this surface over HTTP;
other transports compose the same crate.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](../../LICENSE-APACHE))
- MIT license ([LICENSE-MIT](../../LICENSE-MIT))

at your option.
