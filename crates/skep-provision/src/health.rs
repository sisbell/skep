//! The `/health` read: step 5's guard (AUTH-4.57 (d)).
//!
//! It reads the serving run's body by the sidecar's `skep health` through the
//! runner — chosen by the code, as Q1 (b) leaves the choice open: the CLI
//! prints the body verbatim on stdout, its dial is made inside the
//! bridge where the board's name resolves — the same on the Linux VM and on
//! a Mac, whose host does not reach the bridge — and so this program needs no
//! dialer of its own and no `docker inspect` of an address.
//!
//! **The pair.** It is read with `serde_json` off the body the daemon writes
//! with its keys sorted: `auth.claimant` a claimant (a string, never `null`)
//! and `auth.local_trust == false` — a claimed, enforcing board, the pair as
//! AUTH-4.57 (d) states it. The proxy's own check at every restart, the
//! snippet's `health_body` (`caddy`), is the notes' narrower pattern: the
//! claimant `1.0.1`, the account the dark claim founds. The two agree on
//! every board this flow makes because the dark claim's read has already
//! held the claimant to that account (`sidecar::read`, `sidecar::ACCOUNT`)
//! before this read is made; this read does not hold it again. Every other
//! member is ignored, whatever it holds: the wire's forward rule ("a client
//! must ignore an entry member it does not know"), which `/health`'s
//! readers take as their own, so an eighth member is no failure. A
//! `local_trust: true` is not the pair — under this service it is a failed
//! step, never a reply's clause.
//!
//! **The wait** ([`wait`]). The reads are made over a [`Wait`] —
//! [`HEALTH_WAIT`], the smoke's sixty seconds — a non-zero exit of the
//! sidecar, or a body without the pair, counted as "not yet", each such try
//! handed to the caller as it is answered, for the wait's progress to be
//! said while it runs; it answers at the first pair, and gives up after the
//! bound with what the last try answered — whose pair, where that try
//! exited 0, the log then names as the body answered it ([`pair_said`]), so
//! a claim not on the volume reads apart from local trust on.

use std::io;
use std::num::NonZeroU32;
use std::time::Duration;

use serde_json::Value;

use crate::docker::Docker;
use crate::name::Name;
use crate::process::Exit;
use crate::wait::Wait;

/// The `/health` wait's bound: sixty tries a second apart.
///
/// It is the smoke's own sixty seconds (`scripts/docker-smoke.sh`, the claim
/// run's wait) — each try one `docker run --rm` of the sidecar, so the whole
/// wait runs longer than its sleeps.
pub const HEALTH_WAIT: Wait = Wait { tries: NonZeroU32::new(60).expect("sixty is not zero"), interval: Duration::from_secs(1) };

/// Returns whether a `/health` body answers the pair.
///
/// The pair: `auth.claimant` a string and `auth.local_trust` the boolean
/// `false`; every other member ignored.
fn paired(body: &[u8]) -> bool {
    let Ok(body) = serde_json::from_slice::<Value>(body) else {
        return false;
    };
    let auth = &body["auth"];
    auth["claimant"].is_string() && auth["local_trust"].as_bool() == Some(false)
}

/// Returns the pair as a body answered it, for the log.
///
/// The log names it, for a try that exited 0, on the wait's progress lines
/// and where the wait gave up: `claimant <c>, local_trust <t>`, each the
/// member's JSON — a member absent from the body `absent`, apart from one
/// that is `null` — or `a body that is not JSON`. So a board whose claim is
/// not on its volume (`claimant null`) reads apart from an image built with
/// local trust on (`local_trust true`). `/health` is token-blind, served to
/// every browser: nothing here is withheld.
pub fn pair_said(body: &[u8]) -> String {
    let Ok(body) = serde_json::from_slice::<Value>(body) else {
        return "a body that is not JSON".to_owned();
    };
    let auth = body.get("auth");
    let member = |key: &str| auth.and_then(|auth| auth.get(key)).map_or_else(|| "absent".to_owned(), Value::to_string);
    format!("claimant {}, local_trust {}", member("claimant"), member("local_trust"))
}

/// How a wait ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Waited {
    /// The pair answered, at this try (counted from 1).
    Paired {
        /// The try that answered.
        at: u32,
    },
    /// The bound passed with no pair: what the last try answered.
    GaveUp {
        /// The last try's answer.
        ///
        /// Its exit is spelled for the log by [`Exit::said`].
        last: Exit,
    },
}

/// Waits for the pair: `name`'s `/health` read over `wait`'s tries.
///
/// The tries are paced by `sleep` ([`Wait::paced`]); an exit other than 0, or
/// a body without the pair, is "not yet", handed to `unpaired` with its try's
/// number as it is answered. Given up, it answers what the last try answered.
///
/// # Errors
///
/// A `docker` that cannot be run at all is the error, at once — no try can
/// answer.
pub fn wait(docker: &dyn Docker, name: &Name, wait: Wait, sleep: &dyn Fn(Duration), unpaired: &dyn Fn(u32, &Exit)) -> io::Result<Waited> {
    let mut last = None;
    for at in wait.paced(sleep) {
        let exit = docker.health(name)?;
        if exit.success() && paired(&exit.stdout) {
            return Ok(Waited::Paired { at });
        }
        unpaired(at, &exit);
        last = Some(exit);
    }
    // `Wait::tries` is one or more, so a wait that gives up has made a try,
    // and kept what it answered.
    Ok(Waited::GaveUp { last: last.expect("a wait of one try or more has made a try") })
}

#[cfg(test)]
mod tests;
