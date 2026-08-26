# skep-links

The link store: typed, first-class, bidirectional links over
span-sets — the relation layer of the docuverse.

Part of [skep](https://github.com/sisbell/skep), an open-source hypertext substrate in the Project Xanadu lineage.

- **Links as records** — each link is homed in a document and carries
  three endsets (from / to / type) as span-sets over the address
  space; links are values in ordinary address space, not metadata.
- **Typed by address** — a link's type is itself a document address,
  so type vocabularies are content and extensible by publication.
- **Emit and dedup** — link creation with a canonical coverage-class
  key: denotationally identical links deduplicate to one identity.
- **Supersession** — asserted successor relations with reserved
  classes; readers can follow "what replaced this".
- **Queries** — `readlink`, `followlink`, stab and match over active
  and audit views (a nullified link is invisible to readers, present
  to auditors).

State rides the kernel; endset algebra comes from
[skep-address](../skep-address).

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](../../LICENSE-APACHE))
- MIT license ([LICENSE-MIT](../../LICENSE-MIT))

at your option.
