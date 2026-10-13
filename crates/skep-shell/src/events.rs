//! THE EVENT STREAM (`client.md` §4b.2): every event the shell pushes —
//! `mode`, `session-died`, `daemon`, `feed`, `index`, `moment`, `held` — as
//! one value with the name the contract spells, an [`EventName`] of that
//! closed list, fanned out to EVERY subscriber in the order it was emitted:
//! a developer's second tab is a second subscriber (the dev provider record
//! §3.3), and the conformance proof reads the same sequence off a subscriber
//! of its own. A subscriber that went away is dropped at the next emission;
//! nothing is kept for one that has not subscribed yet.

use std::fmt;
use std::str::FromStr;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Mutex;

use serde_json::Value;

/// One event: the name §4b.2 spells and its data, shaped as the event's
/// row draws it (`shapes` declares each).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    pub name: EventName,
    pub data: Value,
}

/// An event's NAME: one of the seven the contract spells (`client.md`
/// §4b.2), [`EventName::as_str`] its spelling on the stream and in the
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
    /// A PUBLIC moment of a walk: `moment`.
    Moment,
    /// A document's HELD state as it moves (`client.md` §4b.2; §3c):
    /// `holding`, `sending`, `kept`, `refused` or `moved`, with the count of
    /// lines still held: `held`.
    Held,
}

impl EventName {
    /// Every name, in the order the contract lists them.
    pub const ALL: &'static [EventName] =
        &[EventName::Mode, EventName::SessionDied, EventName::Daemon, EventName::Feed, EventName::Index, EventName::Moment, EventName::Held];

    /// The name as the contract spells it.
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

    /// The event the contract spells `s`.
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
    /// An empty bus.
    pub fn new() -> EventBus {
        EventBus::default()
    }

    /// One more subscriber: every event emitted from now on arrives on the
    /// receiver, in order.
    pub fn subscribe(&self) -> Receiver<Event> {
        let (tx, rx) = channel();
        self.subscribers.lock().expect("the bus's lock").push(tx);
        rx
    }

    /// `name` with `data` to every subscriber; a subscriber whose receiver
    /// is gone is dropped here.
    pub fn emit(&self, name: EventName, data: Value) {
        let event = Event { name, data };
        let mut subscribers = self.subscribers.lock().expect("the bus's lock");
        subscribers.retain(|tx| tx.send(event.clone()).is_ok());
    }

    /// How many subscribers stand.
    #[cfg(test)]
    pub fn subscribers(&self) -> usize {
        self.subscribers.lock().expect("the bus's lock").len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

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

    /// Each name parses back from its spelling, which is the contract's; no
    /// two names share one; a spelling of no event parses to none.
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
