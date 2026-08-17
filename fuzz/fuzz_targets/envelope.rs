//! Target 3 — the envelope parsers (`/session`, `/op-at`, `/changes`,
//! `/dump`): the first byte routes, the rest is the payload. The oracle
//! (`envelope_oracle`) demands a well-formed response whose error name, on
//! any non-2xx, is one wire.md documents — the same check the tier-1 test
//! runs.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    skepd::fuzz_support::envelope_oracle(skep_fuzz::daemon_port(), data)
        .expect("envelope endpoint answered an undocumented shape");
});
