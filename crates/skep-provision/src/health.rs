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
//! `auth.local_trust == false` — a claimed, ENFORCING board, the condition
//! the proxy's own check holds at every restart. Every other member is
//! ignored, whatever it holds: the wire's forward rule ("a client MUST
//! ignore an entry member it does not know"), which `/health`'s readers take
//! as their own, so an eighth member is no failure. A `local_trust: true`
//! is not the pair — under this service it is a failed step, never a reply's
//! clause.
//!
//! THE WAIT ([`wait`]): a bounded number of tries at a fixed interval
//! ([`Wait`]; the smoke waits sixty seconds), a non-zero exit of the
//! sidecar counted as "not yet"; it answers at the first pair and gives up
//! after the bound. The same [`Wait`] bounds the flow's retry of the dark
//! claim while the claim run's daemon is not yet listening (step 4's exit
//! 4).

use std::io;
use std::num::NonZeroU32;
use std::time::Duration;

use serde_json::Value;

use crate::docker::Docker;
use crate::name::Name;

/// A bounded wait: this many tries, this far apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Wait {
    /// The tries, the first included: one or more, so a wait that gives up
    /// has made a try whose exit it names.
    pub tries: NonZeroU32,
    /// The sleep between two tries.
    pub interval: Duration,
}

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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Waited {
    /// The pair answered, at this try (counted from 1).
    Paired {
        /// The try that answered.
        at: u32,
    },
    /// The bound passed with no pair; the last try's exit code.
    GaveUp {
        /// The tries made — the bound.
        tries: u32,
        /// The last try's exit code, `None` for an end by signal.
        last_code: Option<i32>,
    },
}

/// THE WAIT FOR THE PAIR: up to `wait.tries` reads of `name`'s `/health`,
/// `sleep` between two of them; an exit other than 0, or a body without the
/// pair, is "not yet". A `docker` that cannot be run at all is the error,
/// at once — no try can answer.
pub fn wait(docker: &dyn Docker, name: &Name, wait: Wait, sleep: &dyn Fn(Duration)) -> io::Result<Waited> {
    let mut last_code = None;
    for at in 1..=wait.tries.get() {
        let exit = docker.health(name)?;
        if exit.ok() && paired(&exit.stdout) {
            return Ok(Waited::Paired { at });
        }
        last_code = exit.code;
        if at < wait.tries.get() {
            sleep(wait.interval);
        }
    }
    Ok(Waited::GaveUp { tries: wait.tries.get(), last_code })
}

#[cfg(test)]
mod tests;
