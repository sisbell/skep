#!/usr/bin/env bash
# gate-fast — the seconds-fast inner gate, for review-round ITERATION ONLY.
# Runs the workspace under nextest's default profile, which excludes the
# #[ignore = "timing test - gate-full only"] partition (designed wall-clock
# sleeps: keepalive cadence, transport deadlines). Green here proves
# nothing about the partition — the gate of record is scripts/gate-full.sh.
set -uo pipefail
cd "$(dirname "$0")/.."

cargo nextest run --workspace
code=$?

echo "gate-fast: EXCLUDED the designed-sleep timing tests (#[ignore] partition);"
echo "gate-fast: the gate of record is scripts/gate-full.sh — run it at round close."
exit "$code"
