# skep-address

The pure, stateless value calculus of a Xanadu-style address space —
the foundation crate of [skep](https://github.com/sisbell/skep), an
open-source hypertext substrate in the Project Xanadu lineage.

It provides, with no I/O, no state, and no dependencies below ℕ
(`num-bigint`):

- **Tumblers** — the transfinite address sequences of Nelson's
  docuverse: arbitrary-precision component chains with a total
  lexicographic order (a prefix sorts before its extensions).
- **Addresses** — validated, classified tumblers (node / account /
  document / element), with field projections and decidable
  containment predicates ("same account", "under document").
- **Position arithmetic** — tumbler addition and subtraction with
  explicit preconditions, sibling/descend increments behind a
  validity gate, and displacement with a guaranteed round trip or a
  refusal.
- **Spans and span-sets** — half-open intervals over the address
  space with an interval algebra (classify, intersect, merge, split,
  difference), normalization to a unique canonical form, and a
  content-addressed canonical key for denotational identity.

Every function is total within its stated preconditions; every
fallible operation returns a typed error naming the violated
condition. The journaled value types (`Tumbler`, `Address`, `Span`,
`SpanSet`, `Level`) implement `serde` serialization.

This crate is the bottom of the skep workspace: everything above it
(stores, engine, daemon) consumes these types; it consumes nothing
of theirs.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](../../LICENSE-APACHE))
- MIT license ([LICENSE-MIT](../../LICENSE-MIT))

at your option.

Unless you explicitly state otherwise, any contribution
intentionally submitted for inclusion in the work by you, as defined
in the Apache-2.0 license, shall be dual licensed as above, without
any additional terms or conditions.
