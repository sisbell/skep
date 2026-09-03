# skep-namespace

The permanent name space: principal registration, ownership
resolution, and address minting for a Xanadu-style docuverse.

Part of [skep](https://github.com/sisbell/skep), an open-source hypertext substrate in the Project Xanadu lineage.

- **Principal registry** — principals seated at node or account
  prefixes, delegated top-down; registration is permanent and a
  prefix is never re-seated.
- **ω (effective owner)** — the LONGEST registered prefix covering an
  address, never bare containment: a node operator's prefix contains
  every account delegated beneath it, so several principals contain
  one address and only the longest match owns it.
- **The frontier allocator** — one frontier per chain, keyed by
  `(anchor, generator)`: account, document, version, content and link
  addresses are minted as the next ordinal on the chain their anchor
  names, gap-free and monotone behind M1's structural-validity gate.
  Over-allocation is harmless, and an address is never reused given
  the caller's half — the mint reads the frontier, the record it
  hands back advances it. The five reserved type addresses (the ghost
  tumblers — content positions 1–5 of doc-1 of the registry node's
  operator) are never issued at all: their chain's frontier is
  floored past them as compiled format.
- **Allocation and entity reads** — is-this-allocated over every
  chain, and node/account/document classification over the entity
  registry: the universal gates other stores consult.
- **Lock-key constructors** — the workspace's one source of
  namespace-keyed critical-section bytes, plus the two registry-wide
  keys.

State rides the kernel ([skep-kernel](../skep-kernel)) for atomicity,
durability, and recovery; address arithmetic comes from
[skep-address](../skep-address).

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](../../LICENSE-APACHE))
- MIT license ([LICENSE-MIT](../../LICENSE-MIT))

at your option.
