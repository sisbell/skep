//! THE PERSON OVER THE BRIDGE (the dev provider record §2.2 (ii);
//! `client.md` §4b.2's `moment`, §4b.3's three classes): a `Person` whose
//! PUBLIC moments — the statements, the boxes, every question over public
//! facts — become `moment(id, kind, data)` events on the bus and BLOCK on a
//! channel the page's `answer(id, value)` or `cancel(id)` fills, and whose
//! SECRET and CONSENT moments go to the dev arm ([`DevArm`]) and never to
//! the page. The trait is synchronous — `label(&mut self, …) -> Result<String,
//! Abandoned>` — so each walk runs on its own thread and the person it
//! holds waits here; a `cancel` answers `Abandoned`, which takes the walk's
//! own abandonment exit, and the shell names the call's refusal
//! `abandoned`. A statement needs no answer and is forwarded as a moment
//! whose `answerable` is false; the page may ignore it.

use std::collections::HashMap;
use std::sync::mpsc::{channel, Sender};
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};
use skep_client::person::{Abandoned, Confirmation, Consent, Destination, HandedPath, Import, Imported, KeptOrPlaced, LabelBox, Person, Public, Question, Retype, Retyped, Secret, Sheet, Statement};

use crate::events::{EventBus, MOMENT};
use crate::refs::moment_id;
use crate::dev_arm::{DevArm, Got};

/// What the page sent for a pending moment.
#[derive(Debug, Clone, PartialEq)]
pub enum Reply {
    /// `answer(id, value)`.
    Answer(Value),
    /// `cancel(id)`.
    Cancel,
}

/// THE PENDING MOMENTS: each waiting walk's channel by the moment's id, so
/// an answer is routed to the walk that asked (the dev provider record
/// §3.3).
#[derive(Debug, Default)]
pub struct Pending {
    waiting: Mutex<HashMap<String, Sender<Reply>>>,
}

impl Pending {
    /// No moment pending.
    pub fn new() -> Pending {
        Pending::default()
    }

    fn register(&self, id: &str) -> std::sync::mpsc::Receiver<Reply> {
        let (tx, rx) = channel();
        self.waiting.lock().expect("the pending lock").insert(id.to_string(), tx);
        rx
    }

    fn deliver(&self, id: &str, reply: Reply) -> bool {
        let tx = self.waiting.lock().expect("the pending lock").remove(id);
        match tx {
            Some(tx) => tx.send(reply).is_ok(),
            None => false,
        }
    }

    /// `answer(id, value)`: `true` where a moment with that id was waiting.
    pub fn answer(&self, id: &str, value: Value) -> bool {
        self.deliver(id, Reply::Answer(value))
    }

    /// `cancel(id)`: `true` where a moment with that id was waiting.
    pub fn cancel(&self, id: &str) -> bool {
        self.deliver(id, Reply::Cancel)
    }

    /// Every pending moment cancelled — the shell's stop.
    pub fn cancel_all(&self) {
        let all: Vec<(String, Sender<Reply>)> = self.waiting.lock().expect("the pending lock").drain().collect();
        for (_, tx) in all {
            let _ = tx.send(Reply::Cancel);
        }
    }

    /// The ids waiting, in no order.
    #[cfg(test)]
    pub fn ids(&self) -> Vec<String> {
        self.waiting.lock().expect("the pending lock").keys().cloned().collect()
    }
}

/// The person a walk is handed: the bus its PUBLIC moments go out on, the
/// pending table their answers come back through, the dev arm the SECRET
/// and CONSENT moments go to, and the walk's name and board reference for
/// the event.
pub struct BridgePerson {
    bus: Arc<EventBus>,
    pending: Arc<Pending>,
    arm: Arc<DevArm>,
    walk: &'static str,
    /// The board reference the walk runs at; none for a walk that touches
    /// no board (`keygen`'s box).
    board_reference: Option<String>,
    /// A moment was cancelled by the page or left by the dev arm: the
    /// walk's halt is the abandonment's.
    pub abandoned: bool,
}

impl BridgePerson {
    /// The person for `walk` at the board `board_reference` names.
    pub fn new(bus: Arc<EventBus>, pending: Arc<Pending>, arm: Arc<DevArm>, walk: &'static str, board_reference: Option<String>) -> BridgePerson {
        BridgePerson { bus, pending, arm, walk, board_reference, abandoned: false }
    }

    /// A PUBLIC moment forwarded: the event, then the wait for the page's
    /// answer where one is owed; a cancel abandons.
    fn moment(&mut self, kind: &str, data: Value, answerable: bool) -> Result<Value, Abandoned> {
        let id = moment_id();
        let rx = answerable.then(|| self.pending.register(&id));
        self.bus.emit(MOMENT, json!({
            "id": id,
            "kind": kind,
            "data": data,
            "walk": self.walk,
            "board": self.board_reference,
            "answerable": answerable,
        }));
        let Some(rx) = rx else { return Ok(Value::Null) };
        match rx.recv() {
            Ok(Reply::Answer(v)) => Ok(v),
            Ok(Reply::Cancel) | Err(_) => {
                self.abandoned = true;
                Err(Abandoned)
            }
        }
    }

    fn got<T>(&mut self, got: Got<T>) -> Result<T, Abandoned> {
        match got {
            Got::Answer(t) => Ok(t),
            Got::Abandoned => {
                self.abandoned = true;
                Err(Abandoned)
            }
        }
    }
}

impl Person for BridgePerson {
    fn say(&mut self, m: Public<Statement>) {
        let _ = self.moment("statement", json!({"rule": m.0.rule, "text": m.0.text}), false);
    }

    fn label(&mut self, m: Public<LabelBox>) -> Result<String, Abandoned> {
        let v = self.moment("label", json!({"title": m.0.title, "statements": m.0.statements, "default": m.0.default}), true)?;
        match v {
            Value::String(s) => Ok(s),
            Value::Null => Ok(m.0.default.unwrap_or_default()),
            other => Ok(other.to_string()),
        }
    }

    fn ask(&mut self, m: Public<Question>) -> Result<String, Abandoned> {
        let v = self.moment("ask", json!({"text": m.0.text}), true)?;
        match v {
            Value::String(s) => Ok(s),
            other => Ok(other.to_string()),
        }
    }

    fn yes_no(&mut self, m: Public<Question>) -> Result<bool, Abandoned> {
        let v = self.moment("yes_no", json!({"text": m.0.text}), true)?;
        Ok(match v {
            Value::Bool(b) => b,
            Value::String(s) => matches!(s.trim().to_ascii_lowercase().as_str(), "y" | "yes" | "true"),
            _ => false,
        })
    }

    fn sheet(&mut self, m: Secret<Sheet>) -> Result<(), Abandoned> {
        self.arm.sheet(m.0.fields);
        Ok(())
    }

    fn dismiss(&mut self) {
        self.arm.dismiss();
    }

    fn retype(&mut self, _m: Secret<Retype>) -> Result<Retyped, Abandoned> {
        let got = self.arm.retype();
        self.got(got)
    }

    fn destination(&mut self, m: Secret<Destination>) -> Result<std::path::PathBuf, Abandoned> {
        let got = self.arm.destination(m.0.which);
        self.got(got)
    }

    fn confirm_typed(&mut self, m: Consent<Confirmation>) -> Result<String, Abandoned> {
        let got = self.arm.confirm(&m.0.text, &m.0.expected);
        self.got(got)
    }

    fn import(&mut self, _m: Secret<Import>) -> Result<Imported, Abandoned> {
        let got = self.arm.import();
        self.got(got)
    }

    fn kept_or_placed(&mut self, m: Secret<HandedPath>) -> Result<KeptOrPlaced, Abandoned> {
        let got = self.arm.kept_or_placed(&m.0.path);
        self.got(got)
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::thread;

    use super::*;

    fn fixture() -> (Arc<EventBus>, Arc<Pending>, Arc<DevArm>) {
        let talk: crate::Talk = Arc::new(|_| {});
        (Arc::new(EventBus::new()), Arc::new(Pending::new()), Arc::new(DevArm::auto(PathBuf::from("/tmp/x"), talk)))
    }

    /// A PUBLIC moment is an event with its id and kind, answered by the
    /// page through the pending table and never by the arm; a statement
    /// needs no answer; a cancel abandons and marks the person.
    #[test]
    fn a_public_moment_waits_for_the_pages_answer_and_a_cancel_abandons() {
        let (bus, pending, arm) = fixture();
        let rx = bus.subscribe();
        let mut person = BridgePerson::new(Arc::clone(&bus), Arc::clone(&pending), arm, "claim", Some("b-1".into()));
        person.say(Public(Statement { rule: "AUTH-5.74", text: "local forever".into() }));
        let statement = rx.recv().unwrap();
        assert_eq!((statement.name, statement.data["kind"].as_str(), statement.data["answerable"].as_bool()), ("moment", Some("statement"), Some(false)));
        assert_eq!(statement.data["board"], "b-1");
        assert!(pending.ids().is_empty(), "a statement waits for nothing");
        let pending_b = Arc::clone(&pending);
        let answerer = thread::spawn(move || {
            let event = rx.recv().unwrap();
            assert_eq!(event.data["kind"], "label");
            assert_eq!(event.data["walk"], "claim");
            let id = event.data["id"].as_str().unwrap().to_string();
            assert!(pending_b.answer(&id, Value::from("phone")));
            assert!(!pending_b.answer(&id, Value::from("again")), "answered once");
            let event = rx.recv().unwrap();
            assert_eq!(event.data["kind"], "yes_no");
            let id = event.data["id"].as_str().unwrap().to_string();
            assert!(pending_b.cancel(&id));
        });
        let label = person.label(Public(LabelBox { title: "name".into(), statements: vec![], default: None })).unwrap();
        assert_eq!(label, "phone");
        assert!(!person.abandoned);
        assert_eq!(person.yes_no(Public(Question { text: "?".into() })), Err(Abandoned));
        assert!(person.abandoned);
        answerer.join().unwrap();
    }

    /// A walk that touches no board names none: its moment's `board` is
    /// `null`, never an empty reference.
    #[test]
    fn a_walk_at_no_board_names_none() {
        let (bus, pending, arm) = fixture();
        let rx = bus.subscribe();
        let mut person = BridgePerson::new(bus, pending, arm, "keygen", None);
        person.say(Public(Statement { rule: "AUTH-5.42", text: "a byline".into() }));
        assert_eq!(rx.recv().unwrap().data["board"], Value::Null);
    }

    /// A SECRET and a CONSENT moment never reach the bus: the arm answers.
    #[test]
    fn secret_and_consent_moments_go_to_the_arm_and_never_to_the_page() {
        let (bus, pending, arm) = fixture();
        let rx = bus.subscribe();
        let mut person = BridgePerson::new(bus, pending, arm, "retire", Some("b-1".into()));
        assert_eq!(person.confirm_typed(Consent(Confirmation { text: "retire?".into(), expected: "abcd".into() })).unwrap(), "abcd");
        assert_eq!(person.retype(Secret(Retype { prompt: "type".into() })).unwrap(), Retyped::Declined);
        assert_eq!(person.import(Secret(Import { prompt: "import".into() })).unwrap(), Imported::Neither);
        assert_eq!(person.kept_or_placed(Secret(HandedPath { path: PathBuf::from("/k"), text: "?".into() })).unwrap(), KeptOrPlaced::Kept);
        assert!(rx.try_recv().is_err(), "no event crossed to the page");
    }

    /// `cancel_all` abandons every waiting walk.
    #[test]
    fn cancel_all_abandons_every_pending_moment() {
        let (bus, pending, arm) = fixture();
        let rx = bus.subscribe();
        let mut person = BridgePerson::new(Arc::clone(&bus), Arc::clone(&pending), arm, "claim", Some("b-1".into()));
        let p = Arc::clone(&pending);
        let t = thread::spawn(move || {
            let _ = rx.recv().unwrap();
            p.cancel_all();
        });
        assert_eq!(person.ask(Public(Question { text: "q".into() })), Err(Abandoned));
        t.join().unwrap();
        assert!(pending.ids().is_empty());
    }
}
