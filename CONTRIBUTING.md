# Contributing to skep

This file says how a change to skep is written up.

## Commits

Commits follow
[Conventional Commits 1.0.0](https://www.conventionalcommits.org/en/v1.0.0/):
a summary line, a blank line, a body, and footers.

```text
type(scope)!: summary

body

footers
```

- **type** is one of `feat`, `fix`, `refactor`, `perf`, `test`, `docs`,
  `build`, `ci` and `chore`.
- **scope** is the crate the change touches, named without its `skep-`
  prefix (`kernel`, `content`, `blobs`, `registry`), and `skepd` for the
  daemon. A change to several crates names each, comma-separated with no
  space (`skepd,blobs`); a change to no crate has no scope.
- **`!`** after the scope marks a breaking change: one that makes a caller
  of a crate's library change their code, or one that changes a stored or
  wire format. A change to tests, docs or wording alone is never breaking.
  A breaking commit carries a `BREAKING CHANGE:` footer that says what
  broke and what a caller does instead.
- **The summary** is in the imperative ("add", not "adds" or "added"), has
  no trailing period, and says what changed where. The whole first line,
  type and scope included, is at most 72 characters.
- **The body** states the problem first, what was wrong and why it
  mattered, then what the change does. It is written for someone reading
  `git log` who can see the diff, so it never restates the diff: no lists
  of files, functions or tests. Wrapped at 72 columns; the detail lives
  in the body, never in the summary. Each commit is one unit of work.
- **Footers**: `Closes #N` for the issue the change resolves, and
  `Co-authored-by:` as the Attribution section says. No other trailer is
  required.

A plain change:

```text
refactor(coordination): rename local identifiers for clarity

Several local names said nothing about what they held. Two class
lists in the catalog were named unlike their accessors, and three
values in a test were called p1, p2 and p3. They now carry the names
their accessors and the test's own comment use.
```

A breaking change:

```text
fix(coordination)!: mark RegisterError and EvalError non_exhaustive

RegisterError and EvalError will grow, and the crate left both
exhaustive. Each has a refusal foreseen: one for a cap on the distinct
referents a stored body may name, one for a fuel budget on evaluate_def.
Added to an exhaustive enum, either would break every match a caller
wrote; a caller's wildcard arm absorbs it instead. Neither refusal is
added here.

BREAKING CHANGE: an exhaustive match on RegisterError or EvalError
outside the crate no longer compiles; add a wildcard arm.
```

## Attribution

If a model wrote any part of the change, add `Co-authored-by:` naming
the model and its version, as GitHub spells the trailer:
`Co-authored-by: Claude Fable 5.1 <noreply@anthropic.com>`. A change
written by hand carries no such trailer.

## Issues

Features and fixes are tracked as issues on this repository, and a commit
that resolves one carries `Closes #N`. An issue's title is at most 70
characters, plain words, no period, no `type(scope):` prefix. Its body
has exactly this form:

```text
## Problem

<what the code does today and what it costs the person who meets it,
in plain short sentences>

**Where:** <files and identifiers in this repository, in backticks>

## Fix

<what the code will do once fixed — the behaviour, and what stays
unchanged>
```

Where the code needs a decision before it can be fixed, the second
section is `## Design needed` instead — the decision as a question, with
its options and what each costs, no fix chosen — and the issue carries
the `needs-design` label until the decision is made. An issue names
nothing outside this repository: no design document, no rule or decision
id, no person, reviewer, seat or round. Every issue is given one of the
four milestones when it is filed — Now, Next, Before release, Later —
and the label of the crate it touches, spelled as the commit scope is.

## Code and comments

Code keeps to the layering [ARCHITECTURE.md](ARCHITECTURE.md) states under
§Rules that hold across files. The compiler enforces it between crates,
and a crate's `tests/it/tidy.rs`, where it has one, enforces it inside
the crate.

Doc comments cite the design rule the code implements, by id (`AUTH-2.2`,
`PUB-6.30`, `M-I5`). A change that implements or extends a rule carries
the rule's id; the review checks it.

Doc comments follow Rust's conventions (RFC 1574, the API Guidelines'
C-FAILURE, the rustdoc book):

- Every block opens with one summary sentence on one line, then a blank
  line. A function's summary is third person present ("Returns …",
  "Parses …"); a type's or a constant's says what it is. A sentence that
  will not fit the file's width (80 columns) becomes a shorter summary
  with the rest in the next sentence.
- A function that returns `Result` says when it fails under `# Errors`;
  one that can panic, a `debug_assert!` included, says when under
  `# Panics`. A caller's obligation whose breach does not panic is a
  `**Precondition.**` paragraph. Where the order of the checks decides
  which refusal a caller gets, the ordered list sits under `# Errors`.
- Emphasis is markdown, not capitals: a heading inside a block is a bold
  lead, a code item is a code span, stress is a plain word or italics.
  Acronyms and rule ids stay as written.
- A comment states the present. Dates, decision names and history ("no
  longer", "as before") belong in the commit body; the comment keeps the
  rule id. A decision number from a design record other than DOCTRINE
  names its record ("signed-ops D24").
- A comment says what the code does. One that disagrees with the code is
  corrected to the code, and where the comment restated a design rule the
  code does not meet, the commit says so.
- A public doc names a private item in a code span, not a link.
- Every public item, and every field and variant of a public type, has a
  doc. A private item needs none, but a comment it has follows these
  rules, `//` comments included.

A crate's `README.md` describes its public surface, and a change to that
surface keeps it true.

## License

skep is licensed under either the [MIT license](LICENSE-MIT) or the
[Apache License, Version 2.0](LICENSE-APACHE), at the user's option. Unless
you state otherwise, a contribution you submit for inclusion in skep, as
defined in the Apache-2.0 license, is licensed the same way, without any
additional terms or conditions. No contributor agreement and no sign-off
(`Signed-off-by`) is required.
