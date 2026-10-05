#!/usr/bin/env bash
# gate-full — THE GATE OF RECORD. Every test in the workspace, including
# the #[ignore = "timing test - gate-full only"] partition, no fail-fast:
# a partial gate hid seven red targets for three rounds, so round close
# and nightly run THIS script end to end and read every red it reports.
# The `full` profile adds a per-test termination timeout so a hung daemon
# test fails WITH ITS NAME instead of wedging the gate.
set -uo pipefail
cd "$(dirname "$0")/.."

# The shipped build, checked first: skepd's library and binary alone, at
# default features, so `test-hooks` is OFF. The test run below compiles
# skepd with that feature on (the tests that reach its hooks enable it), so
# it cannot show that the daemon compiles without them; this check can, and
# a red here fails the gate before any test runs.
cargo check -p skepd --lib --bins || exit $?

# skep-signature's two builds, neither of which the test run below makes —
# every test build turns its `test-hooks` on: with no feature, the
# verify-only build the daemon links (skepd depends on it so, and its build
# holds no signer); and with `sign`, the signer a shipped client links.
cargo check -p skep-signature || exit $?
cargo check -p skep-signature --features sign || exit $?

# skep-arrangement's library without `test-hooks` — every test build turns
# the feature on (the crate's self dev-dependency, and skep-retrieval's), so
# this is the build that shows the store compiles without `seat_link`,
# whatever the daemon's graph holds.
cargo check -p skep-arrangement --lib || exit $?

# skep-content's library without `test-hooks` — every test build turns it on
# (the crate's self dev-dependency), so this is the build that shows the
# store compiles without `write` and without the two crate edges only it
# takes.
cargo check -p skep-content --lib || exit $?

# …and its suite in release. Every other run here is a debug build, and two
# of M4's behaviors exist only in release: the fold keeping a stored value
# where a debug build panics, and `write` reaching its `.expect` with the
# routing assertion compiled out.
cargo nextest run -p skep-content --release --profile full || exit $?

# skep-blobs' library without `test-hooks` — every test build turns it on
# (the crate's self dev-dependency, and skepd's), so this is the build that
# shows the store compiles without its test seam (`src/store/hooks.rs`).
cargo check -p skep-blobs --lib || exit $?

# skep-blobs' docs as they ship, without `test-hooks`: the intra-doc check
# below builds with `--all-features`, where a shipped doc's link to a
# test-only item resolves; here it does not, so the crate names one by code
# span, never by link.
RUSTDOCFLAGS="-D rustdoc::broken_intra_doc_links" \
    cargo doc -p skep-blobs --lib --no-deps --document-private-items || exit $?

# skep-resolve's library without the signer — every test build turns
# skep-signature's `sign` on (the crate's own dev-dependency, and in the
# workspace's builds skep-mcp's dependency and skepd's dev-dependency), so
# this is the build that shows the verify-only library a client embeds
# compiles with no signer in it.
cargo check -p skep-resolve --lib || exit $?

# skep-client's two halves and the sidecar's binary, none of which the full
# run below makes: the READING half alone (`acting` off — no signer, no
# store, no ceremony: what a daemon embedding the dialer would take), the
# ACTING half explicitly, and the `skep` binary without `tls` (the sidecar
# image's build).
cargo check -p skep-client --lib --no-default-features || exit $?
cargo check -p skep-client --lib --features acting || exit $?
cargo check -p skep-cli --bins --no-default-features || exit $?

# The feature edges the full run below never compiles: `client` is
# default-off, and `observe` is on in every test build. The notebook build
# (`client` on); the build without the dump route (`observe` off), its
# library and binary and then every target; and, with every feature on, the
# tests whose answers turn on `client`.
cargo check -p skepd --lib --bins --features client || exit $?
cargo check -p skepd --lib --bins --no-default-features || exit $?
cargo check -p skepd --all-targets --no-default-features || exit $?
cargo nextest run -p skepd --all-features --profile full \
    -E 'test(/^client::/) | test(/^cors::/) | test(/the_death_signal_rides_exactly_the_documented_routes$/) | test(/the_route_set_agrees_across_preflight_dispatch_and_refusal$/)' \
    || exit $?

# Every intra-doc link in skepd, skep-signature, skep-resolve and skep-blobs
# resolves — a private item's too, and a link resolves only where its module
# could name the target in code, so a narrowing that strands a link fails
# here rather than in a reader's hands.
RUSTDOCFLAGS="-D rustdoc::broken_intra_doc_links" \
    cargo doc -p skepd -p skep-signature -p skep-resolve -p skep-blobs --lib --no-deps --document-private-items --all-features \
    || exit $?

# --run-ignored all re-admits the #[ignore] timing partition. One test is
# excluded BY NAME, not by ignore-ness: hazard G (disk exhaustion) is
# env-gated by its owners (hdiutil, mount rights, macOS only — "run it
# explicitly"), and this gate preserves that ruling. Any FUTURE #[ignore]
# lands in this gate by default — deliberate: an ignore that should not be
# run at round close must be excluded here, visibly.
cargo nextest run --workspace --profile full --run-ignored all \
    -E 'not (package(skepd) & test(=hazard::g_disk_exhaustion_stops_acks_before_durability))'
exit $?
