//! THE `/health` READ (step 5's guard; AUTH-4.57 (d)): the serving run's
//! body, read by THE SIDECAR's `skep health` through the runner — chosen by
//! the code (Q1 (b) left it to the brief): the CLI prints the body VERBATIM
//! on stdout, its dial is made inside the bridge where the board's name
//! resolves — the same on the Linux VM and on a Mac, whose host does not
//! reach the bridge — and so this program needs no dialer of its own and
//! no `docker inspect` of an address.
//!
//! THE PAIR, read with `serde_json` off the body the daemon writes with its
//! keys sorted: `auth.claimant` a claimant (a string, never `null`) AND
//! `auth.local_trust == false` — a claimed, ENFORCING board, the pair as
//! AUTH-4.57 (d) states it. The proxy's own check at every restart, the
//! snippet's `health_body` (`caddy`), is the notes' narrower pattern: the
//! claimant `1.0.1`, the account the dark claim founds. The two agree on
//! every board this flow makes because the dark claim's read has already
//! held the claimant to that account (`sidecar::read`, `sidecar::ACCOUNT`)
//! before this read is made; this read does not hold it again. Every other
//! member is ignored, whatever it holds: the wire's forward rule ("a client
//! MUST ignore an entry member it does not know"), which `/health`'s
//! readers take as their own, so an eighth member is no failure. A
//! `local_trust: true` is not the pair — under this service it is a failed
//! step, never a reply's clause.
//!
//! THE WAIT ([`wait`]): the reads made over a [`Wait`] — [`HEALTH_WAIT`],
//! the smoke's sixty seconds — a non-zero exit of the sidecar counted as
//! "not yet"; it answers at the first pair, and gives up after the bound
//! with what the last try answered.

use std::io;
use std::num::NonZeroU32;
use std::time::Duration;

use serde_json::Value;

use crate::docker::Docker;
use crate::name::Name;
use crate::process::Exit;
use crate::wait::Wait;

/// THE `/health` WAIT's BOUND: sixty tries a second apart, the smoke's own
/// sixty seconds (`scripts/docker-smoke.sh`, the claim run's wait) — each
/// try one `docker run --rm` of the sidecar, so the whole wait runs longer
/// than its sleeps.
pub const HEALTH_WAIT: Wait = Wait { tries: NonZeroU32::new(60).expect("sixty is not zero"), interval: Duration::from_secs(1) };

/// Whether a `/health` body answers THE PAIR: `auth.claimant` a string and
/// `auth.local_trust` the boolean `false`; every other member ignored.
fn paired(body: &[u8]) -> bool {
    let Ok(body) = serde_json::from_slice::<Value>(body) else {
        return false;
    };
    let auth = &body["auth"];
    auth["claimant"].is_string() && auth["local_trust"].as_bool() == Some(false)
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
        /// The last try's answer, its exit spelled for the log by
        /// [`Exit::said`].
        last: Exit,
    },
}

/// THE WAIT FOR THE PAIR: `name`'s `/health` read over `wait`'s tries,
/// paced by `sleep` ([`Wait::paced`]); an exit other than 0, or a body
/// without the pair, is "not yet". Given up, it answers what the last try
/// answered. A `docker` that cannot be run at all is the error, at once —
/// no try can answer.
pub fn wait(docker: &dyn Docker, name: &Name, wait: Wait, sleep: &dyn Fn(Duration)) -> io::Result<Waited> {
    let mut last = None;
    for at in wait.paced(sleep) {
        let exit = docker.health(name)?;
        if exit.success() && paired(&exit.stdout) {
            return Ok(Waited::Paired { at });
        }
        last = Some(exit);
    }
    // `Wait::tries` is one or more, so a wait that gives up has made a try,
    // and kept what it answered.
    Ok(Waited::GaveUp { last: last.expect("a wait of one try or more has made a try") })
}

#[cfg(test)]
mod tests;
