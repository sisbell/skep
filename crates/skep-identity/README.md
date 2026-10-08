# skep-identity

The credential model and identity fold of skep's AUTH layer —
pure, deterministic, and standalone.

Part of [skep](https://github.com/sisbell/skep), an open-source hypertext substrate in the Project Xanadu lineage.

- **Credential records** — a byte-exact grammar for enrollment and
  retirement records (hybrid post-quantum + Ed25519 public keys,
  SHA-256 fingerprints, anchor flags), with a frozen fault vocabulary.
- **Key sets** — per-account enrolled/retired key state; retired
  fingerprints never re-enter (dispossession resistance is
  structural).
- **The fold** — a deterministic state machine over credential link
  deposits: same records, same order, same table — on the origin, on
  every mirror, forever. Frozen by a conformance corpus.
- **The doc-1 address** — `doc_1_of`, the address of an account's first
  document, computed from the account address alone: the only document
  of an account a credential link is honored in.
  [skep-namespace](../skep-namespace)'s `first_document_address` names
  the same slot; skepd's suite holds the two equal.
- **`Values` / `FoldCtx`** — the crate defines its own minimal
  world-fact traits and consumes only
  [skep-address](../skep-address) types: no I/O, no clock, no
  signature verification (verification lives in
  [skep-signature](../skep-signature), which skepd, the signing client
  and the resolver call),
  no engine dependency.
- **Signed-op declarations** — the bytes a signed write's signature
  covers (the entry frame and its members' encodings), the marker-tag
  table of the two hybrid signature schemes, a hybrid key's two halves,
  and a signature blob's spelling in hex; declarations only — making and
  checking signatures is [skep-signature](../skep-signature)'s.
- **Write-path type classes** — the credential kinds widened by the
  grants and audit-view classes — the registry's binding, takedown
  record and policy link among them, each with its subtype rows by
  prefix — for the daemon's `nullify` refusals; recognition only,
  never fold state.

Pure enough for a mirror or an audit tool to embed directly. The
engine seats the fold as its world's identity slice; skepd, the
signing client ([skep-client](../skep-client)) and the registry
resolver ([skep-resolve](../skep-resolve)) build on its keys, records
and frames, and the `skep` command ([skep-cli](../skep-cli)) on its
keys and records.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](../../LICENSE-APACHE))
- MIT license ([LICENSE-MIT](../../LICENSE-MIT))

at your option.
