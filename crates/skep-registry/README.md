# skep-registry

The registry's stable core as values: the twelve commons rows the registry
allocates, the binding and endpoint bodies under one canonical rule, the
seeding check, and the vector set every parser of the bodies is held to.

Part of [skep](https://github.com/sisbell/skep), an open-source hypertext substrate in the Project Xanadu lineage.

## 1. What skep-registry is

The registry is a skep board under the account law: a registrar's console
binds a prefix to a node account by a signed deposit into the registrar's
own doc 1, and an org deposits its endpoint into its node account's doc 1.
What the registry's two halves share — the daemon that verifies and
commits the deposits, and the client's half, the resolver that reads them
back — is this crate:

- **The twelve rows** (`rows`, `Row` with the `RowOf` it is the row of,
  `Kind` and `Subtype` each naming its own row by `row`, `row_at` for the
  row an address is, a held reader per row, `t_binding` … `t_successor_of`,
  and `commons_type`, a commons type address at one or more positive
  ordinals) — five kinds on the reserve's ordinals `3.55`–`3.59` of the
  ghost home document's type subspace and seven subtype rows nested under
  their kinds by prefix, at the addresses commons-map pins (REG-1.14,
  REG-1.15, REG-1.20, REG-1.24): the binding `3.55`, the endpoint `3.56`,
  the takedown record `3.57` with its base reading `3.57.1` and LIFTED
  `3.57.2`, the policy link `3.58` with its own reading `3.58.1`, the
  disavowal `3.58.2`, an expulsion's ground record `3.58.3`, a succession's
  ground record `3.58.4` and the org-chosen succession policy `3.58.5`, and
  `successor-of` `3.59`. Each row is the row of a kind or of a subtype,
  whose kind its subtype names, so a row's kind and subtype cannot disagree;
  it holds the `type` string its body carries where it has one, and answers
  whether a deposit rides its address by REG-1.18's test, computed off the
  kinds' subtype rows and never stored: a kind that reads more than one way
  carries none on its bare ordinal.
- **The two bodies** (`Binding`, `Endpoint`, `Origins`, `Body`, `BodyKind`,
  `parse`, `encode`, `Record`, `ParseRefusal`, and `Member`, each member's
  one name, which the parse and the encoder spell it by and a refusal
  names) — `{"type":"binding","prefix":…}`
  and `{"type":"endpoint","origins":[…]}`, each with `replaces` where a
  later record names the one it replaces and `sig` where signed, under THE
  CANONICAL RULE: `parse(b)` answers a body only where `b ==
  encode(parse(b))`. The parse checks the FORM of every member — `type` the
  kind the caller names, no JSON number anywhere, no member beside the row's
  own, `prefix` and `replaces` addresses in dotted decimal, `origins`
  non-empty, `sig` a string where present — and never a member's
  admissibility, which is the resolver's and the reader's. What it checks,
  the types carry: `prefix` and `replaces` are `Address`es and the origins
  an `Origins`, never empty, so every body a caller builds encodes to a
  record the parse admits, the cap aside. A body past
  `MAX_REGISTRY_RECORD_BYTES` (16 KiB, interim, its `sig` counted inside it;
  the constant's doc says what the cap is priced against) is refused before
  any parse. The other five body-bearing rows, subtype rows all and none a
  kind, stand in the table with their `type` strings and no parser: their
  schemas are pinned where their own rules land (REG-1.86 (h)).
- **The seeding check** (`seeding_check`, `SeedingRefusal`) — three arms over
  the registry's rows and every other commons row a build holds:
  DISJOINTNESS at the subtree grain, COMPLETENESS against the kinds' home,
  and THE COUNT against the registry range's five ordinals (REG-1.28 to
  REG-1.32). A refusal names its arm; the hand that runs it writes nothing.
- **The vector set**, `tests/vectors/records.json` — the admitted and
  refused bodies, one JSON array, with each refused body's cause and each
  admitted body's sig-less canonical projection. Every parser of the two
  bodies runs it in its own gate: this crate's parser here, and any other
  a reader of the bodies builds. A parser is never derived from another
  parser — and the resolver builds none: `skep-resolve` calls `parse`.

Who reads it: the daemon, whose write path parses a registry record at the
atom's `insert` and verifies its `sig` at the deposit's `make_link` under
the set that opens its home, and whose open runs the seeding check ahead of
every genesis; and the resolver, `skep-resolve`, which parses each record
it fetches by this crate's `parse`, folds the registry board's verified
bindings into the prefix → binding index and reads the current endpoint
off the active view.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](../../LICENSE-APACHE))
- MIT license ([LICENSE-MIT](../../LICENSE-MIT))

at your option.
