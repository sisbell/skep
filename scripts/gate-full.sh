#!/usr/bin/env bash
# gate-full — THE GATE OF RECORD. Every test in the workspace, including
# the #[ignore = "timing test - gate-full only"] partition, no fail-fast:
# a partial gate hid seven red targets for three rounds, so round close
# and nightly run THIS script end to end and read every red it reports.
# The `full` profile adds a per-test termination timeout so a hung daemon
# test fails WITH ITS NAME instead of wedging the gate.
set -uo pipefail
cd "$(dirname "$0")/.."

# --run-ignored all re-admits the #[ignore] timing partition. One test is
# excluded BY NAME, not by ignore-ness: hazard G (disk exhaustion) is
# env-gated by its owners (hdiutil, mount rights, macOS only — "run it
# explicitly"), and this gate preserves that ruling. Any FUTURE #[ignore]
# lands in this gate by default — deliberate: an ignore that should not be
# run at round close must be excluded here, visibly.
cargo nextest run --workspace --profile full --run-ignored all \
    -E 'not (package(skepd) & test(=g_disk_exhaustion_stops_acks_before_durability))'
exit $?
