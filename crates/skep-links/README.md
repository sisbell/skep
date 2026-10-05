# skep-links

The link store: typed, first-class, bidirectional links whose ends are
spans of the address space — the relation layer of the docuverse.

Part of [skep](https://github.com/sisbell/skep), an open-source hypertext substrate in the Project Xanadu lineage.

- **Links as records** — each link has a permanent address in its home
  document, so a link can name another link, and carries three endsets
  (from / to / type), each a span sequence stored exactly as deposited.
  Nothing stored is ever updated or removed.
- **Typed by address** — a type is matched by the addresses its slot
  names, never by their contents, so any address can type a link. Five
  shipped types, at ghost addresses where nothing is ever minted, carry
  the substrate's own meaning; every other type means what the client
  reading it says it means, and no document defines one.
- **Two write surfaces** — `makelink` deposits a link of any type but
  three fenced classes and always mints a fresh one; `emit`, `nullify`
  and `assert_sup` admit only registered types, check each type's
  shape, and answer a duplicate with the earliest incumbent the caller
  can read.
- **Retraction and supersession** — `nullify` deposits a retraction
  link: its target leaves every active view and stays in the audit
  view and in `readlink`. `assert_sup` and `editlink` record what
  replaced a link; the walk follows the chain and stops at a fork
  rather than choosing.
- **Queries** — `readlink`, `followlink`, the typed reads over active
  and audit views, and the overlap matcher
  [skep-discovery](../skep-discovery) presents.

State rides the kernel; span algebra comes from
[skep-address](../skep-address).

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](../../LICENSE-APACHE))
- MIT license ([LICENSE-MIT](../../LICENSE-MIT))

at your option.
