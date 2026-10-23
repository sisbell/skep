//! The event stream (`client.md` §4b.2): every event the shell pushes.
//!
//! Each event — `mode`, `session-died`, `daemon`, `feed`, `index`, `moment`,
//! `held` — is one value with the name the contract spells, an
//! [`EventName`] of that closed list, fanned out to every subscriber in the
//! order it was emitted: a developer's second tab is a second subscriber
//! (the dev provider record §3.3), and the conformance proof reads the same
//! sequence off a subscriber of its own. A subscriber that went away is
//! dropped at the next emission; nothing is kept for one that has not
//! subscribed yet.

use std::fmt;
use std::str::FromStr;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Mutex;

use serde_json::Value;

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

/// An event's name: one of the seven the contract spells (`client.md` §4b.2).
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
    /// `refused` or `moved`, with the count of lines still held. Emitted at
    /// a hold's start, at each line's resolution or drop, and at each state
    /// the resend moves a document through — never when a principal's file
    /// is read at its session's open, whose lines `held(session)` lists.
    Held,
}

impl EventName {
    /// Every name, in the contract's order but with `moment` before `held`.
    pub const ALL: &'static [EventName] =
        &[EventName::Mode, EventName::SessionDied, EventName::Daemon, EventName::Feed, EventName::Index, EventName::Moment, EventName::Held];

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

/// The bus: the subscribers, each a channel's sending half.
#[derive(Debug, Default)]
pub struct EventBus {
    subscribers: Mutex<Vec<Sender<Event>>>,
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

    /// Sends `name` with `data` to every subscriber.
    ///
    /// A subscriber whose receiver is gone is dropped here.
    ///
    /// # Panics
    ///
    /// Panics where the bus's lock is poisoned.
    pub fn emit(&self, name: EventName, data: Value) {
        let event = Event { name, data };
        let mut subscribers = self.subscribers.lock().expect("the bus's lock");
        subscribers.retain(|tx| tx.send(event.clone()).is_ok());
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
        assert_eq!(spelled, ["mode", "session-died", "daemon", "feed", "index", "moment", "held"]);
        for &name in EventName::ALL {
            assert_eq!(name.as_str().parse::<EventName>(), Ok(name));
            assert_eq!(name.to_string(), name.as_str());
        }
        assert_eq!("bogus".parse::<EventName>(), Err(UnknownEventName));
        assert_eq!("Held".parse::<EventName>(), Err(UnknownEventName), "the spelling is exact");
    }
}
