//! The crate's one source of randomness, for session tokens and nonces.
//!
//! The source is the OS, fail-stop.

use rand_core::{CryptoRng, RngCore};

// ── OS entropy (AUTH-4.13) ───────────────────────────────────────────────

/// The crate's one OS RNG.
///
/// Every draw comes from the OS (`getrandom`), so a token or a nonce is
/// never a function of process state. It implements `rand_core` 0.9's
/// traits, which the declared signatures on the auth surface carry
/// (AUTH-4.19, AUTH-4.23).
pub struct OsEntropy;

impl RngCore for OsEntropy {
    fn next_u32(&mut self) -> u32 {
        rand_core::impls::next_u32_via_fill(self)
    }

    fn next_u64(&mut self) -> u64 {
        rand_core::impls::next_u64_via_fill(self)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        stop_unless_drawn(getrandom::fill(dest));
    }
}

impl CryptoRng for OsEntropy {}

/// Stops the process where the OS refused its entropy.
///
/// Fail-stop: a board that cannot draw OS entropy must not mint credentials
/// from anything weaker (AUTH-4.13). The panic's payload is a literal, which
/// the binary's panic hook carries on the operator stream; a formatted one
/// the hook drops, leaving a panic at this file and nothing of its cause —
/// a container whose profile refuses `getrandom` would read as a defect.
///
/// # Panics
///
/// Panics where `drawn` is the OS's refusal.
fn stop_unless_drawn(drawn: Result<(), getrandom::Error>) {
    if drawn.is_err() {
        panic!("OS entropy unavailable: no nonce or session token is minted from anything weaker");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Checks that a refused draw stops with a payload the hook carries.
    ///
    /// The binary's panic hook carries a `&'static str` payload alone, so the
    /// refusal's words reach the operator stream only as a literal.
    #[test]
    fn a_refused_draw_stops_with_a_literal_the_hook_carries() {
        stop_unless_drawn(Ok(()));
        let payload = std::panic::catch_unwind(|| {
            stop_unless_drawn(Err(getrandom::Error::UNSUPPORTED));
        })
        .expect_err("a refused draw stops");
        assert_eq!(
            payload.downcast_ref::<&'static str>().copied(),
            Some(
                "OS entropy unavailable: no nonce or session token is minted from anything weaker"
            ),
            "the payload is the literal itself"
        );
    }
}
