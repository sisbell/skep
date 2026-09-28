# Agent instructions for this workspace

## Tests

Unit tests live in the module they test, under `#[cfg(test)] mod tests`.
A test module under 200 lines (counted from the `#[cfg(test)]` line to
the module's closing `}`) may stay inline at the file's end. At 200 lines
or more it lives in the module's own `tests.rs` — `foo/tests.rs` beside
`foo.rs`, or `tests.rs` beside a `mod.rs` — declared
`#[cfg(test)] mod tests;`. Integration tests stay under each crate's
`tests/`.

## skepd

skepd is layered; imports point down.
