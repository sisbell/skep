//! The rates a line is said at: `skepd`'s three shapes, for this stream.
//!
//! The shapes are `skepd`'s (its `operations.md` §1, the rates), taken for
//! this service's own stream: an event is said once; a condition that recurs
//! is said at its edges ([`Edge`]) — once as it starts and once as it ends,
//! every meeting between counted and said with the end; and an event a
//! stranger drives — a refusal no invite bounds, which comes at a request's
//! rate — is said at most once a stretch ([`Stretch`]), every like one
//! between counted and said with the next.
//!
//! A line said at a request's rate is a flood: past journald's limit on the
//! unit's lines every line the service owes is dropped for the rest of the
//! limit's interval, a board's `FAILED` and its `snippet: written` among
//! them, and below it the flood rotates the journal out from under the lines
//! RUNBOOK §10's acts read. The clock is the caller's: every judgement takes
//! `now`, so a suite judges at the instants it chooses.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// The hold-down an edge's end waits: fifteen seconds.
///
/// It is `skep-core`'s `EDGE_HOLD_DOWN`, the hold-down of `skepd`'s edges —
/// a condition met again within it is the same episode, so one that flaps at
/// exactly the load that meets it is two lines, never two a flap.
pub const HOLD_DOWN: Duration = Duration::from_secs(15);

/// The stretch a stranger's event is said once in: a minute.
///
/// The first of its kind is said whole, each like one within a minute of the
/// last said counted, the count riding the next one said, however late it
/// comes.
pub const STRETCH: Duration = Duration::from_secs(60);

/// A condition's edges.
///
/// It holds the episode standing, where one does, and a flag the clear path
/// reads with no lock.
#[derive(Debug, Default)]
pub struct Edge {
    /// Whether an episode stands.
    ///
    /// It costs one load per [`Edge::passed`] where none does.
    standing: AtomicBool,
    /// The episode standing, where one does.
    episode: Mutex<Option<Episode>>,
}

/// One episode: its meetings, and when its first and its last were met.
#[derive(Debug, Clone, Copy)]
struct Episode {
    met: u64,
    first: Instant,
    last: Instant,
}

/// An episode's end, as its closing line says it.
///
/// It holds the meetings it counted, the first among them, and the span from
/// its first to its last.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ended {
    /// The meetings, the first among them.
    pub met: u64,
    /// From the first meeting to the last.
    pub over: Duration,
}

impl Edge {
    /// Records the condition met at `now`, answering whether it opens one.
    ///
    /// It answers `true` where this opens an episode — its opening line owed
    /// — and `false` inside one, the meeting counted; the hold-down runs from
    /// `now` either way.
    pub fn met(&self, now: Instant) -> bool {
        let mut episode = self.episode.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        match episode.as_mut() {
            Some(standing) => {
                standing.met += 1;
                standing.last = now;
                false
            }
            None => {
                *episode = Some(Episode { met: 1, first: now, last: now });
                self.standing.store(true, Ordering::Release);
                true
            }
        }
    }

    /// Records the condition found clear at `now`, answering an episode's end.
    ///
    /// It answers the episode's end where one stands and its last meeting is
    /// a hold-down past `now` — its closing line owed — and `None` otherwise;
    /// one atomic load where none stands. A `now` before the last meeting
    /// reads as no time passed.
    pub fn passed(&self, now: Instant) -> Option<Ended> {
        if !self.standing.load(Ordering::Acquire) {
            return None;
        }
        let mut episode = self.episode.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let standing = (*episode).filter(|standing| now.saturating_duration_since(standing.last) >= HOLD_DOWN)?;
        *episode = None;
        self.standing.store(false, Ordering::Release);
        Some(Ended { met: standing.met, over: standing.last.saturating_duration_since(standing.first) })
    }
}

impl Ended {
    /// Returns the count as a closing line says it: `1 <one>`, or `<n> <many>`.
    pub fn count(&self, one: &str, many: &str) -> String {
        counted(self.met, one, many)
    }

    /// Returns the span as a closing line says it, after its count.
    ///
    /// It is nothing where one meeting is all it counted, and
    /// `, across <d> ms` where it counted more.
    pub fn across(&self) -> String {
        if self.met > 1 {
            format!(", across {} ms", self.over.as_millis())
        } else {
            String::new()
        }
    }
}

/// A stranger's event, said at most once a [`STRETCH`].
///
/// It holds when its line was last said, and the like events counted unsaid
/// since.
#[derive(Debug, Default)]
pub struct Stretch {
    said: Mutex<Option<Said>>,
}

/// The stretch's last line.
///
/// It holds when it was said, and the like events counted since.
#[derive(Debug, Clone, Copy)]
struct Said {
    at: Instant,
    unsaid: u64,
}

impl Stretch {
    /// Records one event at `now`, answering whether its line is said.
    ///
    /// It answers `Some(n)` where its line is said — `n` the like ones
    /// counted unsaid since the last said — and `None` where a line was said
    /// within the stretch, this one counted.
    fn event(&self, now: Instant) -> Option<u64> {
        let mut said = self.said.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        match said.as_mut() {
            Some(last) if now.saturating_duration_since(last.at) < STRETCH => {
                last.unsaid += 1;
                None
            }
            Some(last) => {
                let unsaid = std::mem::take(&mut last.unsaid);
                last.at = now;
                Some(unsaid)
            }
            None => {
                *said = Some(Said { at: now, unsaid: 0 });
                Some(0)
            }
        }
    }

    /// Records one event at `now`, answering its line where it is said.
    ///
    /// `line` is built then and only then, so a figure it reads is read at
    /// most once a stretch, and after it comes what the stretch says: the
    /// rule where none was counted since the last said, the count where some
    /// were. It answers `None` where the event is counted.
    pub fn said(&self, now: Instant, line: impl FnOnce() -> String) -> Option<String> {
        let unsaid = self.event(now)?;
        let line = line();
        Some(match unsaid {
            0 => format!("{line} — like ones are said at most once a minute, with their count"),
            n => format!("{line} — {n} more since the last said"),
        })
    }
}

/// Returns a count as a line says it: `1 <one>`, or `<n> <many>`.
pub fn counted(n: u64, one: &str, many: &str) -> String {
    if n == 1 {
        format!("1 {one}")
    } else {
        format!("{n} {many}")
    }
}

#[cfg(test)]
mod tests;
