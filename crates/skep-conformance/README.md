# skep-conformance

The conformance harness: plays golden operation scenarios
against the assembled engine and checks every answer.

Part of [skep](https://github.com/sisbell/skep), an open-source hypertext substrate in the Project Xanadu lineage.

- **Golden scenarios** — vendored operation/response files exercised
  end-to-end through the real engine and operation surface, library
  path only (no daemon, no network).
- **The compatibility record** — where wire-visible behavior is
  pinned, a scenario is the pin: conformance failures are findings
  against a change, not noise.

## Running it

`cargo test -p skep-conformance` runs the gate (`tests/it/gate.rs`): it
plays every golden under `conformance/golden/`, writes one record per
scenario to `target/conformance/report.jsonl` and a summary to
`target/conformance/summary.md`, and fails on a verdict
`conformance/ratchet.toml` does not admit (paths from the workspace
root). Rulings on divergences live in
`conformance/adjudication/decisions.md`; `conformance/allowlist.toml` and
the ratchet carry them. What each adaptation tag in the report means:
`src/play.rs`'s module doc. How the crate is laid out, and the rules that
hold across its files: `src/lib.rs`.

A test rig for the workspace — not intended for publication to a
registry.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](../../LICENSE-APACHE))
- MIT license ([LICENSE-MIT](../../LICENSE-MIT))

at your option.
