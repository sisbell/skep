# skep-identity

The credential model and identity fold of skep's AUTH layer —
pure, deterministic, and standalone.

Part of [skep](https://github.com/sisbell/skep), an open-source hypertext substrate in the Project Xanadu lineage.

- **Credential records** — a byte-exact grammar for enrollment and
  retirement records (Ed25519 public keys, SHA-256 fingerprints,
  anchor flags), with a frozen fault vocabulary.
- **Key sets** — per-account enrolled/retired key state; retired
  fingerprints never re-enter (dispossession resistance is
  structural).
- **The fold** — a deterministic state machine over credential link
  deposits: same records, same order, same table — on the origin, on
  every mirror, forever. Frozen by a conformance corpus.
- **`Values` / `FoldCtx`** — the crate defines its own minimal
  world-fact traits and consumes only
  [skep-address](../skep-address) types: no I/O, no clock, no
  signature verification (verification lives at the session layer),
  no engine dependency.

Pure enough for a mirror or an audit tool to embed directly; the
engine wires it into the world fold.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](../../LICENSE-APACHE))
- MIT license ([LICENSE-MIT](../../LICENSE-MIT))

at your option.
