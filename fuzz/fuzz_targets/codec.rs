//! Target 1 — the JSON codec: arbitrary bytes → `JsonCodec::parse`. The
//! oracle (never panics; a parse that succeeds canonicalizes to a fixpoint;
//! a parse that fails is the Unparseable path) is `codec_roundtrip_oracle`,
//! the same function the in-gate tier-1 test drives.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = skepd::fuzz_support::codec_roundtrip_oracle(data);
});
