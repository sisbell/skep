# skep-namespace

The permanent name space: principal registration, ownership
resolution, and address minting for a Xanadu-style docuverse.

Part of [skep](https://github.com/sisbell/skep), an open-source hypertext substrate in the Project Xanadu lineage.

- **Principal registry** — principals seated at node or account
  prefixes, delegated top-down; registration is permanent and a
  prefix is never re-seated.
- **Ownership** — ω, the effective owner of an address, is the
  principal seated at the LONGEST prefix covering it, never bare
  containment: the bootstrap principal's prefix `[1]` contains every
  account delegated beneath it, so several principals' prefixes contain
  one address and only the longest match owns it. Every ω call walks
  every seat; for a registered document or account, `account_seat`
  answers the same owner by one lookup — the seat at its own account.
- **The frontier allocator** — one frontier per chain, keyed by
  `(anchor, generator)`: account, document, version, content and link
  addresses are minted as the next ordinal on the chain their anchor
  names, gap-free and monotone behind M1's structural-validity gate.
  Elements come off two chains per document, content and link, and no
  third: an element address in any other subspace — subspace 3, where
  type names are spelled — is never minted, and the allocator refuses
  to issue one. Over-allocation is harmless, and an address is never
  reused given the caller's half — the mint reads the frontier, the
  record it hands back advances it. Two chains publish their next
  address as a peek — the mint without its record — for a reader: the
  account chain's next delegable prefix, and the content chain's next
  address, whose ordinal is a document's mint count plus one (the
  content-frontier read's answer). The five reserved type addresses
  (the ghost tumblers — content addresses 1–5 of doc 1 of the system
  account `1.1.0.1`, which genesis seeds) are never issued at all:
  their chain's frontier is floored past them as compiled format, so
  on that one document the content chain's next ordinal is its mint
  count plus six.
- **Entity operations** — the `Namespace` handle's four writes, one
  kernel transaction each: `create_new_document` baptizes an empty
  document under an account its caller owns by ω and resolves the
  publication flag there — an account's first document, flagless, is
  born published, a later flagless one private, and an explicit flag
  is honored as sent; `delegate`, asked by the new account's ω,
  baptizes the next account under a registered node or account and
  seats a new principal there in the same commit, so an account's seat
  is its allocation; `register_node` admits a node address
  provisioning chose, granting no ownership; and `fork` creates a
  document in the caller's own account, as `create_new_document` does.
- **Allocation and entity reads** — is-this-allocated over every
  chain, M3's own allocation oracle, and node/account/document
  classification over the entity registry, the registration check
  other stores and readers consult.
- **The publication bit** — one bit per document, resolved by the
  minting op and journaled on the document's own allocation record
  at mint; immutable thereafter, there being no publication
  transition — publishing mints a new version-chain member born
  published. `published(doc)` is the engine's one definition of a
  document's publication state; a checkpoint or journal written before
  the bit existed fails to decode rather than defaulting.
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
