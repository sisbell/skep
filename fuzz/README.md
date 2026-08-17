# skep-fuzz — the nightly libFuzzer tier

The contract under test is skepd's never-silent boundary: **any bytes in →
exactly one well-formed response out — never a panic, never a hang, never
silence, never a partial write to the socket.**

There are two tiers because the workspace is pinned to stable (1.94.0) and
libFuzzer needs nightly:

- **Tier 1 — in-gate, permanent.** Bounded, seeded `#[test]`s that run in
  every `cargo test` and carry the regression value:
  - `skep/crates/skepd/tests/fuzz_codec.rs` — the JSON codec.
  - `skep/crates/skepd/tests/fuzz_http.rs` — the owned HTTP/1.1 layer.
  - `skep/crates/skepd/tests/fuzz_envelope.rs` — the envelope endpoints.
  - `skep/crates/skep-mcp/tests/fuzz_mcp.rs` — the MCP JSON-RPC line
    protocol (stormed through the real spawned binary).

  Widen any of them with `FUZZ_EXHAUSTIVE=1` (×40 iterations, plus the
  slow-loris read-timeout test that the default budget skips):

  ```
  FUZZ_EXHAUSTIVE=1 cargo test -p skepd --test fuzz_http
  ```

- **Tier 2 — this crate, ad hoc.** Nightly libFuzzer targets. Each is a
  ≤10-line wrapper around the SAME `skepd::fuzz_support` functions tier 1
  exercises, so the code the stable gate cannot compile is trivial by
  construction. **The gate does not build this crate** — it is excluded from
  the workspace (`exclude = ["fuzz"]` in `../Cargo.toml`) and pinned to
  nightly by its own `rust-toolchain.toml`.

## Running tier 2

```
cargo install cargo-fuzz          # once
cd skep/fuzz
cargo +nightly fuzz run codec      # the JSON codec (no daemon)
cargo +nightly fuzz run http       # the HTTP layer (boots one daemon)
cargo +nightly fuzz run envelope   # /session, /op-at, /changes, /dump
```

A crash writes the offending input under `artifacts/<target>/`; reproduce
it with:

```
cargo +nightly fuzz run codec artifacts/codec/crash-<hash>
```

## Targets

| Target     | Wraps (`skepd::fuzz_support`)                    | Oracle |
|------------|-------------------------------------------------|--------|
| `codec`    | `codec_roundtrip_oracle`                         | parse never panics; a parse that succeeds re-marshals to a byte-identical fixpoint; a parse that fails is the Unparseable path. |
| `http`     | `http_raw_exchange` + `check_http_response`      | a non-empty answer is one well-formed HTTP response (status line, headers, universal CORS, `Content-Length`-consistent body); an empty answer is a clean close. |
| `envelope` | `envelope_oracle`                                | the first byte routes to one of the four structured endpoints; the answer is well-formed and any non-2xx `error` name is one wire.md documents. |

## Corpus

`corpus/<target>/` is seeded from wire.md's pinned examples (`codec/`,
`http/`) and routed envelope frames (`envelope/`, first byte selects the
endpoint). libFuzzer grows each corpus as it runs; add any tier-1 hostile
survivor here as its own file. The tier-1 mutation corpus is separate and
self-maintaining: it is harvested live from wire.md's `<!-- wire: … -->`
blocks at test time, so it tracks the wire without a copy step.

## Why there is no `mcp` libFuzzer target

`skep-mcp` is binary-only — it exposes no library seam, and adding one would
be a structural change beyond this round's visibility-only authorization for
its `src/`. Its fuzzing is the tier-1 spawn-storm
(`skep-mcp/tests/fuzz_mcp.rs`), which drives the real process over stdio and
is more faithful than a per-input handler target would be. Widen it the same
way: `FUZZ_EXHAUSTIVE=1 cargo test -p skep-mcp --test fuzz_mcp`.

## Non-goals (this round)

No sanitizer/ASan configuration, no coverage metrics (the oracle is
behavioral, not statistical), and no fixes for anything the fuzzers find —
a finding is reported and its test converted to `#[ignore = "FINDING-n: …"]`
with the assertion intact, per the H3 discipline.
