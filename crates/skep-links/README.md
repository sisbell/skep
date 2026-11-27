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
  can read, saying so (`Deposited`): such an answer commits nothing.
- **Retraction and supersession** — `nullify` deposits a retraction
  link: its target leaves every active view and stays in the audit
  view and in `readlink`. `assert_sup` and `editlink` record what
  replaced a link; the walk follows the chain and stops at a fork
  rather than choosing.
- **Queries** — `readlink`, `followlink`, the typed reads over active
  and audit views, a home's links read as one key range of the store,
  and the overlap matcher [skep-discovery](../skep-discovery) presents:
  a coverage index grouped by home, with a directory naming the homes a
  query could meet before any link is touched, so a reader stabs the
  homes it may read and pays nothing for the links of the rest.

- **The publication and its price** — `LinkWriter::publication` stages
  the publish shot with its correspondence records, its deposits and each
  named draft's re-window at its kept places in one transaction, the
  re-window one identity-checked substitution a draft
  ([skep-arrangement](../skep-arrangement)'s `stage_substitute`). The
  commit is priced before any lock is taken (`price_publication_reads`,
  `ReadPrice`): its in-lock reads — the caller's link-holding homes × the
  entries read over them, per re-windowed draft its content runs and the
  pieces placed, a fence stab a re-inserted run — against
  `MAX_PUBLICATION_READS`, and the bytes it would stage, from a
  worst-case table held equal to the kernel's own accounting, against
  the transaction budget — a shot's re-inserted values BY THE UNIT, an
  atom or a whole run of single bytes at `REINSERTED_UNIT_BYTES` and its
  own bytes, the units the ones M5's count answers
  (`Shot::reinserted_units`), so a long run of typed bytes is priced
  near its length. The price carries those units too (`ReadPrice::units`,
  beside `UNIT_BUDGET` and `POSITION_BUDGET`, M5's two re-insert
  budgets), which the store refuses on and the price never does. It is
  taken at the caller's read class: a stray place counts the
  correspondence records the caller may read and no other, in the
  re-window's steps and in the bytes, a shot's units are counted only
  where the class admits every draft it names, a re-windowed draft's
  content runs only where the class admits that draft, and the stored
  type a rest's fresh mark is priced from is read only where the class
  admits the original's home, a link homed elsewhere priced as an
  address where no link stands — a price is answered ahead of the
  store's own judgment of who owns a draft or a link. One function
  prices the daemon's refusal and the price a client asks for before it
  sends.

State rides the kernel; span algebra comes from
[skep-address](../skep-address).

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](../../LICENSE-APACHE))
- MIT license ([LICENSE-MIT](../../LICENSE-MIT))

at your option.
