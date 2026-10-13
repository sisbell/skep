//! THE EVENT STREAM (`client.md` §4b.2): every event the shell pushes —
//! `mode`, `session-died`, `daemon`, `feed`, `index`, `moment` — as one
//! value with the name the contract spells, fanned out to EVERY subscriber
//! in the order it was emitted: a developer's second tab is a second
//! subscriber (the dev provider record §3.3), and the conformance proof
//! reads the same sequence off a subscriber of its own. A subscriber that
//! went away is dropped at the next emission; nothing is kept for one that
//! has not subscribed yet.

use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Mutex;

use serde_json::Value;

/// One event: the name §4b.2 spells and its data, shaped as the event's
/// row draws it (`shapes` declares each).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    pub name: &'static str,
    pub data: Value,
}

/// The seven names, as the contract spells them.
pub const MODE: &str = "mode";
pub const SESSION_DIED: &str = "session-died";
pub const DAEMON: &str = "daemon";
pub const FEED: &str = "feed";
pub const INDEX: &str = "index";
pub const MOMENT: &str = "moment";
/// A document's HELD state as it moves (`client.md` §4b.2; §3c): `holding`,
/// `sending`, `kept`, `refused` or `moved`, with the count of lines still held.
pub const HELD: &str = "held";

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
    pub fn emit(&self, name: &'static str, data: Value) {
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
        bus.emit(FEED, json!({"board": "b-1", "update": {"position": 3}}));
        bus.emit(MODE, json!({"board": "b-1", "mode": "ENFORCING"}));
        let seen = |rx: &Receiver<Event>| -> Vec<&'static str> { rx.try_iter().map(|e| e.name).collect() };
        assert_eq!(seen(&a), ["feed", "mode"]);
        assert_eq!(seen(&b), ["feed", "mode"]);
        drop(b);
        let late = bus.subscribe();
        bus.emit(DAEMON, json!({"board": "b-1", "state": "running"}));
        assert_eq!(bus.subscribers(), 2, "the dropped receiver is forgotten");
        assert_eq!(seen(&a), ["daemon"]);
        assert_eq!(seen(&late), ["daemon"]);
    }
}
