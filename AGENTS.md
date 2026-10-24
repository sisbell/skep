# Agent instructions for this workspace

## The two files that describe the code

`ARCHITECTURE.md` is the layout: the crates and what each owns, their
modules and which names which, the direction of every dependency, and
the rules of layout that hold across files. It changes only when the
layout changes: a crate added, a module moved, an owner changed, a
layering rule made or lifted. `PATTERNS.md` holds the rules of
mechanism, numbered `SP-n`: what every site of a kind must do and the
one component that does it for all. A module's own behaviour lives in
its `//!` doc. History lives in the commit. Nothing else goes in
`ARCHITECTURE.md`: not how a function works, not a figure, not a dated
aside, not a rule that binds more than one site — that is a pattern.
Before a change, read `PATTERNS.md` and cite the rule it keeps or moves
onto; change a rule there, with the reason in the commit, never work
around it.

## Tests

Unit tests live in the module they test, under `#[cfg(test)] mod tests`.
A test module under 200 lines (counted from the `#[cfg(test)]` line to
the module's closing `}`) may stay inline at the file's end. At 200 lines
or more it lives in the module's own `tests.rs` — `foo/tests.rs` beside
`foo.rs`, or `tests.rs` beside a `mod.rs` — declared
`#[cfg(test)] mod tests;`. Integration tests stay under each crate's
`tests/`.

## skepd

skepd is layered; imports point down. The layers are drawn in
`ARCHITECTURE.md` §The daemon, and `crates/skepd/tests/it/tidy.rs` checks
them; the media resource beside its write path is the crate `skep-media`,
whose two layers — the resource over its two leaf cells — are drawn in
§The media resource and checked by `crates/skep-media/tests/it/tidy.rs`;
the daemon's core is the crate `skep-core`, whose three layers — the
session layer over the commits over the leaves — are drawn in §The
daemon's core and checked by `crates/skep-core/tests/it/tidy.rs`.

## Commits and comments

Commit messages and doc comments follow `CONTRIBUTING.md`: the commit
convention, the body that states the problem first, and the citation of
the design rule a change implements.
