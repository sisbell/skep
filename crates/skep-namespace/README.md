# skep-namespace

The permanent name space: principal registration, ownership
resolution, and address minting for a Xanadu-style docuverse.

Part of [skep](https://github.com/sisbell/skep), an open-source hypertext substrate in the Project Xanadu lineage.

- **Principal registry** — accounts as tumbler prefixes, delegated
  top-down; registration is permanent (names are never reused).
- **ω (owner resolution)** — longest-registered-prefix ownership: any
  address resolves to the principal whose account prefix contains it.
- **The frontier allocator** — mints fresh document and element
  addresses per (home, subspace) by monotone increment behind a
  structural-validity gate; over-allocation is harmless, reuse is
  impossible by construction.
- **Registration reads** — document/account existence and
  entity-level classification, the universal gates other stores
  consult.
- **Lock-key constructors** — the workspace's one source of
  namespace-keyed critical-section bytes.

State rides the kernel ([skep-kernel](../skep-kernel)) for atomicity,
durability, and recovery; address arithmetic comes from
[skep-address](../skep-address).

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](../../LICENSE-APACHE))
- MIT license ([LICENSE-MIT](../../LICENSE-MIT))

at your option.
