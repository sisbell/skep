# skep-arrangement

Arrangements and editing: the versioned V→I mapping that makes
skep documents editable over immutable content.

Part of [skep](https://github.com/sisbell/skep), an open-source hypertext substrate in the Project Xanadu lineage.

- **The Vstream** — per-document run lists mapping virtual positions
  (what a reader sees) onto immutable content addresses (what is
  stored); every edit is a new arrangement, never a byte change.
- **Editing composites** — insert, copy (transclusion — the copied
  spans keep their origin identity), delete, rearrange; each a
  kernel transaction composing namespace mints and content writes.
- **Versioning** — fork and version create documents whose
  arrangements share history with their sources; provenance is
  structural, not recorded metadata.
- **`resolve` / `project`** — V→I image and I→V occurrences, the
  reads every query layer builds on.

Rides the kernel for atomicity and recovery; consumes
[skep-address](../skep-address) span algebra throughout.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](../../LICENSE-APACHE))
- MIT license ([LICENSE-MIT](../../LICENSE-MIT))

at your option.
