# skep-registry

The registry's stable core as values: the commons rows the registry
allocates, the bodies the daemon parses and the door's policy document
under one canonical rule, the seeding check, the vocabulary of every link
type the build names, and the vector sets every parser of the bodies is
held to.

Part of [skep](https://github.com/sisbell/skep), an open-source hypertext substrate in the Project Xanadu lineage.

## 1. What skep-registry is

The registry is a skep board under the account law: a registrar's console
binds a prefix to a node account by a signed deposit into the registrar's
own doc 1, and an org deposits its endpoint into its node account's doc 1.
What the registry's two halves share — the daemon that verifies and
commits the deposits, and the client's half, the resolver that reads them
back — is this crate:

- **The rows** (`rows`, `Row` with the `RowOf` it is the row of, `Kind`
  and `Subtype` each naming its own row by `row`, `row_at` for the row an
  address is, a held reader per row, `t_registration` … `t_successor_of`,
  and `commons_type`, a commons type address at one or more positive
  ordinals) — the registry's kinds on the registry range's ordinals,
  `3.54`–`3.59` as the list stands, of the ghost home document's type
  subspace, and their subtype rows nested under them by prefix, at the
  addresses commons-map pins (REG-1.14, REG-1.15, REG-1.20, REG-1.24): the
  registration `3.54` with its request `3.54.1` — a parent row, its kinds
  fresh `3.54.1.1` and board-carries-on `3.54.1.2` beneath it — its reply
  `3.54.2` — a parent row, its answers approved `3.54.2.1`, refused
  `3.54.2.2` and denied `3.54.2.3` beneath it — its vouch `3.54.3` and its
  approval `3.54.4`; the binding `3.55`; the endpoint `3.56`; the takedown
  record `3.57` with its base reading `3.57.1` and LIFTED `3.57.2`; the
  policy link `3.58` with its own reading `3.58.1`, the disavowal `3.58.2`,
  an expulsion's ground record `3.58.3`, a succession's ground record
  `3.58.4` and the org-chosen succession policy `3.58.5`; and
  `successor-of` `3.59`. How many kinds and rows there are is the lists'
  length — `Kind::ALL`, `Subtype::ALL`, `rows()` — and is written as a
  tally nowhere (REG-1.25, REG-1.26). Each row is the row of a kind or of a
  subtype, whose kind its subtype names, so a row's kind and subtype cannot
  disagree; a subtype names its parent row where it stands under one
  (`Subtype::parent`), and a row the row it stands directly beneath
  (`RowOf::above`); a row holds the `type` string its body carries where it
  has one, spells its own ordinal path (`Row::ordinal_path`, `3.54.1.1`),
  and answers whether a deposit rides its address by REG-1.18's test,
  computed off the rows and never stored: a deposit rides a leaf — a kind
  that reads more than one way carries none on its bare ordinal, and a
  parent row none on its own address.
- **The two bodies** (`Binding`, `Endpoint`, `Origins`, `Body`, `BodyKind`,
  `parse`, `encode`, `Record`, `ParseRefusal`, and `Member`, each member's
  one name, which a parse and an encoder spell it by and a refusal
  names) — `{"type":"binding","prefix":…}`
  and `{"type":"endpoint","origins":[…]}`, each with `replaces` where a
  later record names the one it replaces and `sig` where signed, under THE
  CANONICAL RULE: `parse(b)` answers a record only where `b ==
  encode(parse(b))`. The parse checks the FORM of every member — `type` the
  kind the caller names, no JSON number anywhere, no member beside the row's
  own, `prefix` and `replaces` addresses in dotted decimal, `origins`
  non-empty, `sig` a string where present — and never a member's
  admissibility, which is the resolver's and the reader's. What it checks,
  the types carry: `prefix` and `replaces` are `Address`es and the origins
  an `Origins`, never empty, so every body a caller builds encodes to a
  record the parse admits, the cap aside. A body past
  `MAX_REGISTRY_RECORD_BYTES` (16 KiB, a term of the format, its `sig`
  counted inside it; the constant's doc says what the cap is priced
  against) is refused before
  any parse. The other five body-bearing rows of the takedown record and
  the policy link, subtype rows all and none a kind, stand in the table
  with their `type` strings and no parser: their schemas are pinned where
  their own rules land (REG-1.86 (h)).
- **The registration's six bodies** (`RegistrationKind`, `RegistrationBody`
  over `Fresh`, `BoardCarriesOn`, `Approved` with its `ProvisionedBoard`
  and `Disposition`, `Refused` with its `Fault`, `Denied` and `Vouch`,
  `RegistrationRecord`, `parse_registration`, `encode_registration`, a
  request's members as one view, `RequestMembers`, and the forms the types
  carry: `Hex64`, `HexDigits`, `Digits`, `Principal`) — types of their own
  beside `Body` and `BodyKind`, which keep the binding and the endpoint
  alone, parsed and encoded through the same canonical machinery. Each
  body's `type` is its own row's name — `"fresh"` and never `"request"`,
  `"approved"` and never `"reply"` — and its members stand in the order
  REG-1.86 lists them: a request's `door`, `fresh`, `shape`, `node`, `board`
  (the fresh kind alone), `signer` and `signature`, the frame's fields the
  body's members; an approved answer's `prefix`, `node_address`,
  `node_principal`, the board's three members together or not at all,
  `door_origin`, `collection_interval`, `disposition` and `policy`; a
  refused answer's `fault`, one of three; a denied answer's `policy` and
  `clause`; a vouch's `fingerprints` and `replaces`. One number rides them:
  a principal id, a JSON number from `0` to `MAX_EXACT_NUMBER` (`2^53 − 1`);
  every count and interval is a string of decimal digits. The parse checks
  form and never admissibility — a request's `door`, `shape` and
  enrolments are strings, a vouch's fingerprints stand in any order — and
  the cap is per kind: `MAX_REGISTRATION_REQUEST_BYTES` (64 KiB) for a
  request of either kind, `MAX_REGISTRY_RECORD_BYTES` for every other body.
- **The door's policy document** (`AdmissionPolicy` with its `Admission`,
  `parse_policy`, `encode_policy`, `POLICY_TYPE`, and
  `AdmissionPolicy::approval_hand` answering an `ApprovalHand`) — the one
  parser a console, a sign-up page and a guest reader share for the
  document a door publishes (REG-4.131): one object, `type`
  `"admission-policy"`, its members in order, under the canonical rule. It
  is no deposit — it carries no `sig`, and the daemon reads no byte of it —
  and it is capped at `MAX_REGISTRY_RECORD_BYTES`, 16 KiB, as every body
  but a request is: a document past the cap is refused `past_cap` ahead of
  every other stage. A document the parse refuses is no policy — the empty
  document a door holds between its creation and its first words among
  them — and a door with no policy admits no request and writes no
  approval. The approval's hand is read past the
  parse: `"auto"` is honored only where the admission is open and
  otherwise fails closed to the officer's hand, and a value the parser
  does not know opens no approval.
- **The seeding check** (`seeding_check`, `SeedingRefusal`) — three arms
  over the registry's rows and every other commons row a build holds:
  DISJOINTNESS at the subtree grain, COMPLETENESS against the kinds' home
  — a subtype's row sought under the row it stands beneath, its kind's or
  its parent row's — and THE COUNT, each kind on a bare ordinal of its own
  inside the registry range and no two on one (REG-1.28 to REG-1.32). A
  refusal names its arm, and on one the hand that runs the check owes a
  genesis that does not complete: nothing is written.
- **The vocabulary** (`vocabulary`, `Definition` with its `section`,
  `definition_at`, `defines_type`) — every link type this build names in
  the commons, one table in path order: each row's address under the ghost
  home document's type subspace `1.1.0.1.0.1.0.3`, its path, its name (one
  lowercase token — the plan's word, or the code's where the code names a
  type the plan does not), its purpose in a line and the shape of its
  endsets. The credential kinds `3.1`–`3.3`, the core set the seeding plan
  curates (`3.5`–`3.21` with their subtypes, `3.30`, `3.40`–`3.45`), the
  reader-state family `3.46` with `3.46.1` and `3.46.3`–`3.46.5`,
  `replaces` `3.12`, the designations `3.22`, `3.27` and `3.28`,
  `marks` `3.25`, the link a mark of a draft carries, the
  meta-type `defines` `3.50`, the registry's rows named as `rows` names
  them — the registration family's names, purposes and endsets
  commons-map's words — the rail record `3.60`, the steward's
  classification `3.61`, the two media cell kinds `3.88` and `3.89`, the
  grant `3.90` and the consumption marker `3.91`; nothing at an ordinal
  nobody allocated. The daemon writes one section (`Definition::section`:
  the name alone on the first line, then the address, the purpose and the
  endset shape) and one `defines` link per row into the registry document
  `1.1.0.1.0.1` at every open — all of them on a fresh board, the missing
  ones on an upgraded or interrupted one — so a client resolves a type's
  name by one `find_links_ftt` constrained in `to` and `ty` and one read
  of the link's `from` span.
- **The vector sets**, `tests/vectors/` — the admitted and refused bodies
  in one scheme, with each refused body's cause and each admitted body's
  sig-less canonical projection: `records.json` the binding's and the
  endpoint's, `registration.json` the registration's six, `policy.json`
  the door's policy document's, with the hand its reader answers. Every
  parser of the bodies runs them in its own gate: this crate's parsers
  here, and any other a reader of the bodies builds. A parser is never
  derived from another parser — and the resolver builds none:
  `skep-resolve` calls `parse`.

Who reads it: the daemon, whose write path parses a registry record at the
atom's `insert` and verifies its `sig` at the deposit's `make_link` under
the set that opens its home, whose open runs the seeding check ahead of
every genesis and seeds the vocabulary into the registry document after
it; the resolver, `skep-resolve`, which parses each record
it fetches by this crate's `parse`, folds the registry board's verified
bindings into the prefix → binding index and reads the current endpoint
off the active view; and a door's console, its intake scribe and its
sign-up page, which read a registration's records and the door's policy
through the parsers here.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](../../LICENSE-APACHE))
- MIT license ([LICENSE-MIT](../../LICENSE-MIT))

at your option.
