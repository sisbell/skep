# skep-signature

The hybrid signature of skep's signed ops — each marker tag's frozen
rules, held once for every signer and every verifier.

Part of [skep](https://github.com/sisbell/skep), an open-source hypertext substrate in the Project Xanadu lineage.

- **Two tags, each one exact rule** — tag 1, ML-DSA-65 + Ed25519 (the
  production pair), and tag 3, the FN-DSA-512 preview + Ed25519. Each
  pinned library's exact version is part of its tag's rule: a change to
  what verifies, or to what a seed derives, is a new tag.
- **The verify** — both halves over the same bytes, either failing
  fails; and the all-halves decode an enrollment's key is checked by.
  Always compiled: this is what a daemon links.
- **The signer, behind `sign`** — the KDF (HKDF-SHA-256, one 32-byte
  seed to both halves, never the raw seed to either), keygen from that
  seed per tag, and signing: the post-quantum signature then the
  Ed25519 one.
- **`test-hooks`** — implies `sign`, and adds the fixtures' seeded
  RNG and the other test-only doors. No shipped signer enables it.
- **Goldens** — per tag, one seed to both public keys, the
  fingerprint and the signatures over fixed entry frames; tag 1
  checked byte for byte against a second FIPS 204 implementation; and
  the keygen-from-seed rule as `docs/wire.md` publishes it — its
  formula, recomputed from RFC 5869 against the KDF, and its two
  vectors, checked against the keys themselves.

The syntax — the tag table, the key layout, the fingerprint, the entry
frame — is [skep-identity](../skep-identity)'s; this crate holds the
arithmetic over it, and names no other skep crate.

skepd depends on this crate with no feature, so the daemon's own build
(`cargo build -p skepd`) holds no signer. Cargo unifies features across
everything one invocation builds: a `--workspace` build turns `sign` on
here — skep-client's default `acting` feature asks for it — and one that
compiles the test suites turns `test-hooks` on too; either reaches the
daemon's binary, so the shipped daemon is built with `-p skepd`.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](../../LICENSE-APACHE))
- MIT license ([LICENSE-MIT](../../LICENSE-MIT))

at your option.
