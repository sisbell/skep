//! The crate's one source of randomness — the OS, fail-stop — for session
//! tokens, nonces and tag-3 signatures.

use rand_core::{CryptoRng, RngCore};

// ── OS entropy (AUTH-4.13) ───────────────────────────────────────────────

/// The crate's one OS RNG: every draw comes from the OS (`getrandom`), so a
/// token, a nonce or a tag-3 signature's seed is never a function of process
/// state. Implements `rand_core` 0.9's traits, which the declared signatures
/// on the auth surface carry (AUTH-4.19, AUTH-4.23), and — in `hybrid` —
/// 0.6's, which `fn-dsa` 0.4.0 draws through, both over the one `fill_bytes`
/// below.
pub(crate) struct OsEntropy;

impl RngCore for OsEntropy {
    fn next_u32(&mut self) -> u32 {
        rand_core::impls::next_u32_via_fill(self)
    }

    fn next_u64(&mut self) -> u64 {
        rand_core::impls::next_u64_via_fill(self)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        // Fail-stop: a board that cannot draw OS entropy must not mint
        // credentials from anything weaker.
        getrandom::fill(dest).expect("OS entropy unavailable");
    }
}

impl CryptoRng for OsEntropy {}
