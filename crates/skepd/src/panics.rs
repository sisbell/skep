//! The panic hook's rate: one line per condition, the panics after it counted.
//!
//! The binary's panic hook says a panic on the operator stream at the rate
//! this module holds it to (`operations.md` §1, the rates; §1.1 row 41; SP-11,
//! SP-19). A *condition* is two things together: the panic's site, its
//! `file:line:column` as `skep_util::caught::site_of` spells it, and the
//! route the panicking thread was serving, named in the router's own words
//! ([`RouteName`]). The thread is no part of it, and no byte of a request is.
//! A condition's first panic is said at once; every later one, on any thread,
//! is counted, and the count is said within the standing interval
//! (`skep_core::limits::STANDING_INTERVAL`): on the hourly `standing:` line,
//! which takes every count not yet said ([`take_unsaid_panics`]), on the
//! condition's own next line where no such line has come for an interval
//! ([`AdmittedPanic::repeats`]), and at the binary's exit. A condition quiet
//! for an interval after its count was last said is forgotten, and its next
//! panic is said as a first. So the lines are bounded by the code — its
//! panic sites times the router's route names — whatever a client sends and
//! however many workers or event-stream threads it reaches; a count counts
//! panics, a frame's resends among them, and never frames.
//!
//! **The route.** A worker names the route it serves in a slot of its own
//! thread's ([`serving`]), from the moment its request is read to the end of
//! the connection, and the hook reads the slot at the panic, before the
//! unwind drops the guard that set it. A panic on a thread serving no
//! request — the read itself, the pruner, the checkpoint thread, the two
//! walks, an event stream's own thread, `main` — names none.
//!
//! **The lock rule.** Nothing that can panic runs under the tally's lock: no
//! formatting, no indexing, no `unwrap`, saturating arithmetic alone.
//! `parking_lot`'s lock does not re-enter, so a thread that panicked while
//! holding it would wait on it forever in its own hook. Each door copies out
//! under the lock and renders after releasing it, and no line is emitted
//! under it. The tally's map is a `BTreeMap`, whose `new` is `const` and
//! hashes nothing, so the tally is built at compile time: no first panic
//! builds it inside the hook, and no hash keys are drawn from the OS there —
//! a draw that panics where the OS refuses entropy, the one panic the router
//! raises by design.
//!
//! **The cost.** Per panic, one lock and one lookup in the map — a pass over
//! it, at most `TALLY_KEYS` conditions, where a new condition finds it full;
//! per tick, one lock over at most that many; per request, two short string
//! matches and two writes of a thread-local slot.

use std::cell::Cell;
use std::collections::BTreeMap;
use std::fmt;
use std::marker::PhantomData;
use std::panic::Location;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use skep_core::limits::STANDING_INTERVAL;
use skep_util::caught::site_of;

/// The conditions the tally holds before a new one is counted past it: 1,024.
///
/// It bounds the tally's memory and the tick's pass over it. Only a quiet
/// condition is ever forgotten to make room, so no count is lost to the
/// bound: a new condition that finds the tally full of conditions still in
/// their interval is counted past it, and said with them.
const TALLY_KEYS: usize = 1024;

/// A route a worker was serving, in the router's own words.
///
/// It renders `{method} {path}` — the method and the path as the router
/// spells them, `GET /challenge`, `POST /blob/upload` — or `an unknown route`
/// where the request named a method or a path the router does not serve.
/// Only the router names one, so no byte of a request can become one: a
/// query, a document's address and an upload's identifier never reach a route
/// name (SP-15).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RouteName(Name);

/// What a [`RouteName`] holds: a route the router serves, or none.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum Name {
    /// A method and a path the router dispatches, in its own spelling.
    Known { method: &'static str, path: &'static str },
    /// A method or a path the router does not serve.
    Unknown,
}

impl RouteName {
    /// Returns the route of `method` and `path`, words the router supplies.
    pub(crate) fn known(method: &'static str, path: &'static str) -> RouteName {
        RouteName(Name::Known { method, path })
    }

    /// Returns the route of a request the router does not serve.
    pub(crate) fn unknown() -> RouteName {
        RouteName(Name::Unknown)
    }
}

impl fmt::Display for RouteName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Name::Known { method, path } => write!(f, "{method} {path}"),
            Name::Unknown => f.write_str("an unknown route"),
        }
    }
}

thread_local! {
    /// The route this thread is serving, while a [`Serving`] guard stands.
    static ROUTE: Cell<Option<RouteName>> = const { Cell::new(None) };
}

/// Names `route` as the one this thread serves, until the guard drops.
///
/// The guard puts the route in this thread's slot and, when it drops — on a
/// return or an unwind — puts back what it found, so a nested guard restores
/// the outer one, and an unwind past the connection leaves no stale route for
/// a later panic on the thread to name. Neither the set nor the restore
/// panics: where this thread's locals are torn down, the route goes unnamed.
pub(crate) fn serving(route: RouteName) -> Serving {
    let found = ROUTE.try_with(|slot| slot.replace(Some(route))).ok().flatten();
    Serving { found, _this_thread: PhantomData }
}

/// The guard [`serving`] answers: this thread's route until it drops.
///
/// It is not `Send`, since the slot it restores is the thread's that made it.
#[must_use = "the route is named only while the guard stands: bind it to a name"]
pub(crate) struct Serving {
    /// The route the slot held when the guard was made.
    found: Option<RouteName>,
    /// Keeps the guard on the thread whose slot it restores.
    _this_thread: PhantomData<*const ()>,
}

impl Drop for Serving {
    fn drop(&mut self) {
        let _ = ROUTE.try_with(|slot| slot.set(self.found));
    }
}

/// Returns the route this thread is serving, `None` where it serves none.
fn route_served() -> Option<RouteName> {
    ROUTE.try_with(Cell::get).ok().flatten()
}

/// A condition: the panic's site and the route its thread was serving.
type Condition = (String, Option<RouteName>);

/// One condition's memory: when it was last said, and the panics since.
#[derive(Clone, Copy)]
struct Seen {
    /// When the condition's first panic or its count was last said.
    said_at: Instant,
    /// The panics of the condition counted, and not said, since then.
    since: u64,
}

/// The hook's memory: the conditions it has said and the counts it owes.
///
/// Pure, so its tests run on fixed instants; the process's one is the static
/// `TALLY`, behind [`admit_panic`] and [`take_unsaid_panics`].
struct Tally {
    /// Each condition the hook has said a panic of, by site, then route.
    seen: BTreeMap<Condition, Seen>,
    /// The panics of new conditions counted while the tally was full.
    past_the_bound: u64,
}

impl Tally {
    /// Returns the tally before any panic.
    const fn new() -> Tally {
        Tally { seen: BTreeMap::new(), past_the_bound: 0 }
    }

    /// Answers whether a panic of `condition` is said, at `now`.
    ///
    /// It answers `Some(n)` where it is — the condition's first, or its first
    /// `interval` or more past the condition's last line, `n` the panics
    /// counted since that line, the interval running again from `now` — and
    /// `None` where the panic is counted: inside the interval, or a new
    /// condition that finds the tally full once the quiet ones are forgotten,
    /// counted past the bound.
    fn admit(&mut self, condition: Condition, now: Instant, interval: Duration) -> Option<u64> {
        if let Some(seen) = self.seen.get_mut(&condition) {
            if now.saturating_duration_since(seen.said_at) < interval {
                seen.since = seen.since.saturating_add(1);
                return None;
            }
            let repeats = seen.since;
            *seen = Seen { said_at: now, since: 0 };
            return Some(repeats);
        }
        if self.seen.len() >= TALLY_KEYS {
            self.forget_the_quiet(now, interval);
        }
        if self.seen.len() >= TALLY_KEYS {
            self.past_the_bound = self.past_the_bound.saturating_add(1);
            return None;
        }
        self.seen.insert(condition, Seen { said_at: now, since: 0 });
        Some(0)
    }

    /// Takes every count not yet said, and the count past the bound.
    ///
    /// Each condition with a count is answered with it, in the map's order —
    /// by site, then route — its interval running again from `now`; then the
    /// quiet conditions are forgotten, and the count past the bound is
    /// answered and cleared.
    fn take_unsaid(&mut self, now: Instant, interval: Duration) -> UnsaidPanics {
        let mut counts = Vec::new();
        for ((site, route), seen) in &mut self.seen {
            if seen.since > 0 {
                counts.push(UnsaidCount { site: site.clone(), route: *route, panics: seen.since });
                *seen = Seen { said_at: now, since: 0 };
            }
        }
        self.forget_the_quiet(now, interval);
        UnsaidPanics { counts, past_the_bound: std::mem::take(&mut self.past_the_bound) }
    }

    /// Forgets every quiet condition.
    ///
    /// A condition is quiet when everything it counted has been said and an
    /// interval has passed since with no panic of it. It is the only kind
    /// ever forgotten, so no count is lost.
    fn forget_the_quiet(&mut self, now: Instant, interval: Duration) {
        self.seen.retain(|_, seen| {
            seen.since > 0 || now.saturating_duration_since(seen.said_at) < interval
        });
    }
}

/// The process's one tally, the hook's and the standing line's.
static TALLY: Mutex<Tally> = Mutex::new(Tally::new());

/// Admits a panic at `location` to the hook's line, or counts it.
///
/// The binary's panic hook calls it at every panic, after
/// [`note_site`](crate::note_site), with its info's `location()`; an embedding
/// program's own hook calls it the same way, or no standing line counts its
/// panics. The condition is the site, as the walks' catches spell it, and the
/// route this thread was serving; the instant is now, and the interval is the
/// standing line's (`skep_core::limits::STANDING_INTERVAL`). It answers the
/// panic to say — the condition's first, or its first an interval past its
/// last line — and `None` where the panic is counted. It never panics, and
/// nothing under the tally's lock can, so a hook that calls it never waits on
/// itself.
pub fn admit_panic(location: Option<&Location<'_>>) -> Option<AdmittedPanic> {
    let site = site_of(location);
    let route = route_served();
    let now = Instant::now();
    let condition = (site.clone(), route);
    let repeats = TALLY.lock().admit(condition, now, STANDING_INTERVAL)?;
    Some(AdmittedPanic { site, route, repeats })
}

/// Takes every count the hook made and has not said.
///
/// The standing line takes it at each tick, and the binary at its exit once
/// every worker has ended, so each count is said once and within the
/// interval. Conditions quiet for an interval are forgotten as it takes.
pub fn take_unsaid_panics() -> UnsaidPanics {
    let now = Instant::now();
    TALLY.lock().take_unsaid(now, STANDING_INTERVAL)
}

/// A panic [`admit_panic`] admits to the hook's line.
///
/// It carries the site, the route the thread was serving and the panics of
/// its condition counted since its last line, the three the line says.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmittedPanic {
    site: String,
    route: Option<RouteName>,
    repeats: u64,
}

impl AdmittedPanic {
    /// Returns the panic's site: `file:line:column`, or `an unknown location`.
    pub fn site(&self) -> &str {
        &self.site
    }

    /// Returns the route the panicking thread was serving, where it served one.
    pub fn route(&self) -> Option<RouteName> {
        self.route
    }

    /// Returns the panics of this condition counted since its last line.
    ///
    /// It is zero for a condition's first panic; for a line an interval past
    /// the last, the panics between that no tick took.
    pub fn repeats(&self) -> u64 {
        self.repeats
    }
}

/// The panics the tally counted and has not said: a tick's or the exit's take.
///
/// It renders one clause per condition, by site, then route — `{n} more
/// panics at {site} since its last line`, or `{n} more panics at {site} while
/// serving {route} since its last line` — and then, where any panic was
/// counted while the tally was full, `{n} panics at sites past the hook's
/// memory of {k}`, `{k}` the tally's bound; all joined by `; `. The default is
/// the empty take, which renders nothing.
#[derive(Debug, Default)]
pub struct UnsaidPanics {
    /// The conditions' counts, by site, then route.
    counts: Vec<UnsaidCount>,
    /// The panics counted while the tally was full.
    past_the_bound: u64,
}

/// One condition's count, as a take answers it.
#[derive(Debug)]
struct UnsaidCount {
    site: String,
    route: Option<RouteName>,
    panics: u64,
}

impl UnsaidPanics {
    /// Returns whether the take found no panic to say.
    pub fn is_empty(&self) -> bool {
        self.counts.is_empty() && self.past_the_bound == 0
    }

    /// Returns a take at fixed figures, each `(site, route, panics)` in order.
    ///
    /// Under `cfg(test)` alone, so the standing line's tests render a take
    /// the tally never made.
    #[cfg(test)]
    pub(crate) fn at_figures(
        counts: &[(&str, Option<RouteName>, u64)],
        past_the_bound: u64,
    ) -> UnsaidPanics {
        let counts = counts
            .iter()
            .map(|&(site, route, panics)| UnsaidCount { site: site.to_string(), route, panics })
            .collect();
        UnsaidPanics { counts, past_the_bound }
    }
}

impl fmt::Display for UnsaidPanics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, count) in self.counts.iter().enumerate() {
            if i > 0 {
                f.write_str("; ")?;
            }
            write!(f, "{} more panics at {}", count.panics, count.site)?;
            if let Some(route) = count.route {
                write!(f, " while serving {route}")?;
            }
            f.write_str(" since its last line")?;
        }
        if self.past_the_bound > 0 {
            if !self.counts.is_empty() {
                f.write_str("; ")?;
            }
            write!(
                f,
                "{} panics at sites past the hook's memory of {TALLY_KEYS}",
                self.past_the_bound
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
