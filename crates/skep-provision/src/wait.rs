//! A bounded wait: the one way this program tries a thing again up to a bound.
//!
//! It is [`Wait`], this many tries this far apart, and [`Wait::paced`], the
//! tries made with a sleep before each but the first and never after the
//! last. Three waits are made of it: the `/health` read's (`health`'s
//! `HEALTH_WAIT`), the dark claim's while the claim run's daemon is not yet
//! listening (`flow`'s `SIDECAR_WAIT`), and the follow-up mail's (`sender`'s
//! `MAIL_WAIT`).

use std::num::NonZeroU32;
use std::time::Duration;

/// A bounded wait: this many tries, this far apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Wait {
    /// The tries, the first included: one or more.
    ///
    /// So a wait that gives up has made a try.
    pub tries: NonZeroU32,
    /// The sleep between two tries.
    pub interval: Duration,
}

impl Wait {
    /// Returns the tries, paced: each try's number, from 1 to [`Wait::tries`].
    ///
    /// A `sleep` of [`Wait::interval`] is made before each but the first — so
    /// a caller that stops at a try sleeps no more, and one that runs them all
    /// has slept between its tries alone, never after the last.
    pub fn paced(self, sleep: &dyn Fn(Duration)) -> impl Iterator<Item = u32> + '_ {
        (1..=self.tries.get()).inspect(move |&at| {
            if at > 1 {
                sleep(self.interval);
            }
        })
    }
}

#[cfg(test)]
mod tests;
