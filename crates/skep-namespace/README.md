# skep-namespace

The permanent name space: principal registration, ownership
resolution, and address minting for a Xanadu-style docuverse.

Part of [skep](https://github.com/sisbell/skep), an open-source hypertext substrate in the Project Xanadu lineage.

- **Principal registry** — principals seated at node or account
  prefixes, delegated top-down; registration is permanent and a
  prefix is never re-seated.
- **ω (effective owner)** — the principal seated at the LONGEST prefix
  covering an address, never bare containment: the bootstrap
  principal's prefix `[1]` contains every account delegated beneath it,
  so several principals' prefixes contain one address and only the
  longest match owns it.
- **The frontier allocator** — one frontier per chain, keyed by
  `(anchor, generator)`: account, document, version, content and link
  addresses are minted as the next ordinal on the chain their anchor
  names, gap-free and monotone behind M1's structural-validity gate.
  Over-allocation is harmless, and an address is never reused given
  the caller's half — the mint reads the frontier, the record it
  hands back advances it. Two chains publish their frontier as a
  peek — the mint without its record — for a reader: the account
  chain's next delegable prefix, and the content chain's next
  address, whose ordinal is a document's mint count plus one (the
  content-frontier read's answer). The five reserved type addresses
  (the ghost tumblers — content addresses 1–5 of doc 1 of the system
  account `1.1.0.1`, which genesis seeds) are never issued at all:
  their chain's frontier is floored past them as compiled format, so
  on that one document the content frontier is its mint count plus
  six.
- **Allocation and entity reads** — is-this-allocated over every
  chain, M3's own allocation oracle, and node/account/document
  classification over the entity registry, the registration check
  other stores and readers consult.
- **The publication bit** — one bit per document, resolved by the
  minting op and journaled on the document's own allocation record
  at mint; immutable thereafter, there being no publish op.
  `published(doc)` is the engine's one definition of a document's
  publication state; a checkpoint or journal written before the bit
  existed fails to decode rather than defaulting.
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
