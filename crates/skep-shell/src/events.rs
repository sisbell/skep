//! The event stream (`client.md` §4b.2): every event the shell pushes.
//!
//! Each event — `mode`, `session-died`, `daemon`, `feed`, `index`, `moment`,
//! `held`, `publication` — is one value with the name the contract spells,
//! an [`EventName`] of that closed list, fanned out to every subscriber in
//! the order it was emitted: a developer's second tab is a second subscriber
//! (the dev provider record §3.3), and the conformance proof reads the same
//! sequence off a subscriber of its own. A subscriber that went away is
//! dropped at the next emission; nothing is kept for one that has not
//! subscribed yet. Beside the subscribers a WATCHER ([`EventBus::watch`]) is
//! a closure the bus runs on the emitting thread once every subscriber has
//! the event — the shell's own reaction to an event whichever thread emitted
//! it (a session's death met on a board's feed thread ends the publication
//! panels that stood under it, §4b.1's one session rule), a watcher's own
//! emissions following the event it reacted to on the stream.

use std::fmt;
use std::str::FromStr;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};

use serde_json::Value;

/// A watcher: run on the emitting thread after the fan-out.
type Watcher = Arc<dyn Fn(&EventBus, &Event) + Send + Sync>;

/// One event: the name §4b.2 spells and its data.
///
/// The data is shaped as the event's row draws it (`shapes` declares each).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    /// The event's name.
    pub name: EventName,
    /// The event's data, shaped as its row draws it.
    pub data: Value,
}

/// An event's name: one of the eight the contract spells (`client.md` §4b.2).
///
/// [`EventName::as_str`] is its spelling on the stream and in the
/// declarations, which `shapes` renders from [`EventName::ALL`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum EventName {
    /// A board's mode pair moved: `mode`.
    Mode,
    /// A session ended, and the arm its end carried: `session-died`.
    SessionDied,
    /// A board's node started, stopped, or stopped answering: `daemon`.
    Daemon,
    /// A row of a board's change feed: `feed`.
    Feed,
    /// A search index's state moved: `index`.
    Index,
    /// A public moment of a walk: `moment`.
    Moment,
    /// A document's held state as it moves: `held`.
    ///
    /// The state (`client.md` §4b.2; §3c) is `holding`, `sending`, `kept`,
    /// `refused` or `moved`, with the count of lines still held — the moved
    /// state carrying the hands whose rows moved the document (§3c.5).
    /// Emitted at a hold's start, at each line's resolution or drop, and at
    /// each state the resend moves a document through — never when a
    /// principal's file is read at its session's open, whose lines
    /// `held(session)` lists.
    Held,
    /// The state of a publication's one request as it moves: `publication`.
    ///
    /// The state (`client.md` §4b.2) is `sent`, `acknowledged`, `restated`,
    /// `refused`, `cancelled` or `ended`, under the board and the session the
    /// request is about and naming its draft — fired at `publication.confirm`'s
    /// send and at its outcome, at `publication.cancel`, and at the session's
    /// death with a panel standing (the family's one session rule, §4b.1).
    Publication,
}

impl EventName {
    /// Every name, in the contract's order but with `moment` before `held`,
    /// and `publication` last.
    pub const ALL: &'static [EventName] =
        &[EventName::Mode, EventName::SessionDied, EventName::Daemon, EventName::Feed, EventName::Index, EventName::Moment, EventName::Held, EventName::Publication];

    /// Returns the name as the contract spells it.
    pub const fn as_str(self) -> &'static str {
        match self {
            EventName::Mode => "mode",
            EventName::SessionDied => "session-died",
            EventName::Daemon => "daemon",
            EventName::Feed => "feed",
            EventName::Index => "index",
            EventName::Moment => "moment",
            EventName::Held => "held",
            EventName::Publication => "publication",
        }
    }
}

impl fmt::Display for EventName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A name no event of the contract carries: what parsing one answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnknownEventName;

impl fmt::Display for UnknownEventName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("no event of the bridge carries this name")
    }
}

impl std::error::Error for UnknownEventName {}

impl FromStr for EventName {
    type Err = UnknownEventName;

    /// Returns the event the contract spells `s`.
    ///
    /// # Errors
    ///
    /// Returns [`UnknownEventName`] where no event of the contract is
    /// spelled `s`.
    fn from_str(s: &str) -> Result<EventName, UnknownEventName> {
        EventName::ALL.iter().copied().find(|name| name.as_str() == s).ok_or(UnknownEventName)
    }
}

/// The bus: the subscribers, each a channel's sending half, and the watchers.
#[derive(Default)]
pub struct EventBus {
    subscribers: Mutex<Vec<Sender<Event>>>,
    /// The watchers, each run after the fan-out on the emitting thread.
    watchers: Mutex<Vec<Watcher>>,
}

impl fmt::Debug for EventBus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EventBus").field("subscribers", &self.subscribers).finish_non_exhaustive()
    }
}

impl EventBus {
    /// Returns an empty bus.
    pub fn new() -> EventBus {
        EventBus::default()
    }

    /// Returns the receiver of one more subscriber.
    ///
    /// Every event emitted from the call on arrives on the receiver, in
    /// order.
    ///
    /// # Panics
    ///
    /// Panics where the bus's lock is poisoned.
    pub fn subscribe(&self) -> Receiver<Event> {
        let (tx, rx) = channel();
        self.subscribers.lock().expect("the bus's lock").push(tx);
        rx
    }

    /// Registers a watcher: `f` is run with every event emitted from now on.
    ///
    /// It runs on the emitting thread once every subscriber has the event,
    /// outside the bus's locks, so a watcher may emit — its own events follow
    /// the one it reacted to on the stream — and holds a reference to the bus
    /// alone, never an `Arc` of it.
    ///
    /// # Panics
    ///
    /// Panics where the bus's lock is poisoned.
    pub fn watch(&self, f: impl Fn(&EventBus, &Event) + Send + Sync + 'static) {
        self.watchers.lock().expect("the bus's lock").push(Arc::new(f));
    }

    /// Sends `name` with `data` to every subscriber, then to every watcher.
    ///
    /// A subscriber whose receiver is gone is dropped here.
    ///
    /// # Panics
    ///
    /// Panics where the bus's lock is poisoned.
    pub fn emit(&self, name: EventName, data: Value) {
        let event = Event { name, data };
        {
            let mut subscribers = self.subscribers.lock().expect("the bus's lock");
            subscribers.retain(|tx| tx.send(event.clone()).is_ok());
        }
        let watchers: Vec<Watcher> = self.watchers.lock().expect("the bus's lock").clone();
        for watcher in watchers {
            watcher(self, &event);
        }
    }

    /// Returns how many subscribers stand.
    ///
    /// # Panics
    ///
    /// Panics where the bus's lock is poisoned.
    #[cfg(test)]
    fn subscribers(&self) -> usize {
        self.subscribers.lock().expect("the bus's lock").len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::Arc;

    /// Checks that every subscriber sees the sequence in order.
    ///
    /// Two subscribers see one sequence in one order; a dropped receiver is
    /// forgotten at the next emission; a late subscriber sees nothing of the
    /// past.
    #[test]
    fn every_subscriber_sees_the_sequence_in_order() {
        let bus = EventBus::new();
        let a = bus.subscribe();
        let b = bus.subscribe();
        bus.emit(EventName::Feed, json!({"board": "b-1", "update": {"position": 3}}));
        bus.emit(EventName::Mode, json!({"board": "b-1", "mode": "ENFORCING"}));
        let seen = |rx: &Receiver<Event>| -> Vec<EventName> { rx.try_iter().map(|e| e.name).collect() };
        assert_eq!(seen(&a), [EventName::Feed, EventName::Mode]);
        assert_eq!(seen(&b), [EventName::Feed, EventName::Mode]);
        drop(b);
        let late = bus.subscribe();
        bus.emit(EventName::Daemon, json!({"board": "b-1", "state": "running"}));
        assert_eq!(bus.subscribers(), 2, "the dropped receiver is forgotten");
        assert_eq!(seen(&a), [EventName::Daemon]);
        assert_eq!(seen(&late), [EventName::Daemon]);
    }

    /// Checks that every name parses back from its spelling.
    ///
    /// The spelling is the contract's; no two names share one; a spelling of
    /// no event parses to none.
    #[test]
    fn every_name_parses_back_from_its_spelling() {
        let spelled: Vec<&str> = EventName::ALL.iter().map(|name| name.as_str()).collect();
        assert_eq!(spelled, ["mode", "session-died", "daemon", "feed", "index", "moment", "held", "publication"]);
        for &name in EventName::ALL {
            assert_eq!(name.as_str().parse::<EventName>(), Ok(name));
            assert_eq!(name.to_string(), name.as_str());
        }
        assert_eq!("bogus".parse::<EventName>(), Err(UnknownEventName));
        assert_eq!("Held".parse::<EventName>(), Err(UnknownEventName), "the spelling is exact");
    }

    /// Checks that a watcher runs after the fan-out and may emit.
    ///
    /// The watcher sees every event once, after every subscriber has it; an
    /// event it emits in reaction follows the one it reacted to on the
    /// stream, and reaches the watcher too (the mutant that runs watchers
    /// under the subscribers' lock deadlocks on the reaction).
    #[test]
    fn a_watcher_runs_after_the_fan_out_and_may_emit() {
        let bus = EventBus::new();
        let rx = bus.subscribe();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let kept = Arc::clone(&seen);
        bus.watch(move |bus, event| {
            kept.lock().unwrap().push(event.name);
            if event.name == EventName::SessionDied {
                bus.emit(EventName::Publication, json!({"state": "ended"}));
            }
        });
        bus.emit(EventName::SessionDied, json!({"session": "s-1"}));
        let names: Vec<EventName> = rx.try_iter().map(|e| e.name).collect();
        assert_eq!(names, [EventName::SessionDied, EventName::Publication], "the reaction follows the event on the stream");
        assert_eq!(*seen.lock().unwrap(), [EventName::SessionDied, EventName::Publication], "the watcher sees its own reaction too");
    }
}
