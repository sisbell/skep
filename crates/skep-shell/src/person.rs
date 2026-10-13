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
//! whose `answerable` is false; the page may ignore it. AN ANSWER's FORM is
//! its moment's kind's ([`MomentKind::takes`]): a label box takes a string,
//! or `null` for the box's default; a question a string; a yes-or-no a
//! boolean — asked by [`Pending::answer`], the page's one way in, so a
//! walk never receives a value of another form, and a value of another
//! form leaves its moment waiting.

use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::sync::mpsc::{channel, Sender};
use std::sync::{Arc, Mutex};

use serde_json::{json, Value};
use skep_client::person::{Abandoned, Confirmation, Consent, Destination, HandedPath, Import, Imported, KeptOrPlaced, LabelBox, Person, Public, Question, Retype, Retyped, Secret, Sheet, Statement};

use crate::events::{EventBus, EventName};
use crate::refs::moment_id;
use crate::dev_arm::DevArm;
use crate::refusal::{Name, Refusal};

/// What the page sent for a pending moment.
#[derive(Debug, Clone, PartialEq)]
pub enum Reply {
    /// `answer(id, value)`.
    Answer(Value),
    /// `cancel(id)`.
    Cancel,
}

/// THE PENDING MOMENTS: each waiting walk's channel by the moment's id, with
/// the moment's kind, so an answer is routed to the walk that asked (the dev
/// provider record §3.3) and held to the form that kind takes.
#[derive(Debug, Default)]
pub struct Pending {
    waiting: Mutex<HashMap<String, (MomentKind, Sender<Reply>)>>,
}

impl Pending {
    /// No moment pending.
    pub fn new() -> Pending {
        Pending::default()
    }

    fn register(&self, id: &str, kind: MomentKind) -> std::sync::mpsc::Receiver<Reply> {
        let (tx, rx) = channel();
        self.waiting.lock().expect("the pending lock").insert(id.to_string(), (kind, tx));
        rx
    }

    /// The moment `id` taken out of the table, where it waits and `admits`
    /// its kind; a moment `admits` refuses keeps waiting.
    fn take(&self, id: &str, admits: impl FnOnce(MomentKind) -> Result<(), Refusal>) -> Result<Sender<Reply>, Refusal> {
        match self.waiting.lock().expect("the pending lock").entry(id.to_string()) {
            Entry::Occupied(moment) => {
                admits(moment.get().0)?;
                Ok(moment.remove().1)
            }
            Entry::Vacant(_) => Err(no_such_moment(id)),
        }
    }

    /// `answer(id, value)`: `value` handed to the walk that asked, of the
    /// form its moment's kind takes ([`MomentKind::takes`]) — else
    /// `malformed_args` naming `value` and the form, the moment still
    /// waiting for one; `no_such_moment` where no moment of that id waits.
    pub fn answer(&self, id: &str, value: Value) -> Result<(), Refusal> {
        let tx = self.take(id, |kind| if kind.takes(&value) { Ok(()) } else { Err(Refusal::shell(Name::MALFORMED_ARGS, json!({"what": "value", "takes": kind.form()}))) })?;
        // A walk that ended without its answer dropped its receiver: no
        // moment waits there.
        tx.send(Reply::Answer(value)).map_err(|_| no_such_moment(id))
    }

    /// `cancel(id)`: the walk that asked abandoned at that moment;
    /// `no_such_moment` where no moment of that id waits.
    pub fn cancel(&self, id: &str) -> Result<(), Refusal> {
        let tx = self.take(id, |_| Ok(()))?;
        tx.send(Reply::Cancel).map_err(|_| no_such_moment(id))
    }

    /// Every pending moment cancelled — the shell's stop.
    pub fn cancel_all(&self) {
        let all: Vec<(String, (MomentKind, Sender<Reply>))> = self.waiting.lock().expect("the pending lock").drain().collect();
        for (_, (_, tx)) in all {
            let _ = tx.send(Reply::Cancel);
        }
    }

    /// The ids waiting, in no order.
    #[cfg(test)]
    pub fn ids(&self) -> Vec<String> {
        self.waiting.lock().expect("the pending lock").keys().cloned().collect()
    }
}

/// A PUBLIC moment's kind, as `MomentEvent.kind` spells it: a statement
/// said, or a box or a question the page answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MomentKind {
    Statement,
    Label,
    Ask,
    YesNo,
}

impl MomentKind {
    /// The kind as the event spells it.
    fn as_str(self) -> &'static str {
        match self {
            MomentKind::Statement => "statement",
            MomentKind::Label => "label",
            MomentKind::Ask => "ask",
            MomentKind::YesNo => "yes_no",
        }
    }

    /// Whether the page owes an answer: every kind but a statement.
    fn answerable(self) -> bool {
        self != MomentKind::Statement
    }

    /// Whether `answer` is of the form this kind takes: a label box a
    /// string, or `null` for the box's default; a question a string; a
    /// yes-or-no a boolean. A statement takes none: no answer is owed it.
    fn takes(self, answer: &Value) -> bool {
        match self {
            MomentKind::Statement => false,
            MomentKind::Label => answer.is_string() || answer.is_null(),
            MomentKind::Ask => answer.is_string(),
            MomentKind::YesNo => answer.is_boolean(),
        }
    }

    /// The form this kind takes, as a refused answer names it.
    fn form(self) -> &'static str {
        match self {
            MomentKind::Statement => "no answer",
            MomentKind::Label => "a string, or null for the box's default",
            MomentKind::Ask => "a string",
            MomentKind::YesNo => "a boolean",
        }
    }
}

/// The refusal for an `answer` or a `cancel` no moment waits for.
fn no_such_moment(id: &str) -> Refusal {
    Refusal::shell(Name::NO_SUCH_MOMENT, json!({"id": id}))
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
    /// answer where its kind owes one; a cancel abandons.
    fn moment(&mut self, kind: MomentKind, data: Value) -> Result<Value, Abandoned> {
        let id = moment_id();
        let answerable = kind.answerable();
        let rx = answerable.then(|| self.pending.register(&id, kind));
        self.bus.emit(EventName::Moment, json!({
            "id": id,
            "kind": kind.as_str(),
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

    /// The dev arm's answer passed on, the person marked abandoned where
    /// the arm left the moment.
    fn mark_if_abandoned<T>(&mut self, answer: Result<T, Abandoned>) -> Result<T, Abandoned> {
        answer.inspect_err(|_| self.abandoned = true)
    }
}

impl Person for BridgePerson {
    fn say(&mut self, m: Public<Statement>) {
        let _ = self.moment(MomentKind::Statement, json!({"rule": m.0.rule, "text": m.0.text}));
    }

    fn label(&mut self, m: Public<LabelBox>) -> Result<String, Abandoned> {
        let v = self.moment(MomentKind::Label, json!({"title": m.0.title, "statements": m.0.statements, "default": m.0.default}))?;
        match v {
            Value::String(s) => Ok(s),
            Value::Null => Ok(m.0.default.unwrap_or_default()),
            other => unreachable!("Pending::answer admits a label box's string or null alone, never {other}"),
        }
    }

    fn ask(&mut self, m: Public<Question>) -> Result<String, Abandoned> {
        let v = self.moment(MomentKind::Ask, json!({"text": m.0.text}))?;
        match v {
            Value::String(s) => Ok(s),
            other => unreachable!("Pending::answer admits a question's string alone, never {other}"),
        }
    }

    fn yes_no(&mut self, m: Public<Question>) -> Result<bool, Abandoned> {
        let v = self.moment(MomentKind::YesNo, json!({"text": m.0.text}))?;
        match v {
            Value::Bool(b) => Ok(b),
            other => unreachable!("Pending::answer admits a yes-or-no's boolean alone, never {other}"),
        }
    }

    fn sheet(&mut self, m: Secret<Sheet>) -> Result<(), Abandoned> {
        self.arm.sheet(m.0.fields);
        Ok(())
    }

    fn dismiss(&mut self) {
        self.arm.dismiss();
    }

    fn retype(&mut self, _m: Secret<Retype>) -> Result<Retyped, Abandoned> {
        let answer = self.arm.retype();
        self.mark_if_abandoned(answer)
    }

    fn destination(&mut self, m: Secret<Destination>) -> Result<std::path::PathBuf, Abandoned> {
        let answer = self.arm.destination(m.0.which);
        self.mark_if_abandoned(answer)
    }

    fn confirm_typed(&mut self, m: Consent<Confirmation>) -> Result<String, Abandoned> {
        let answer = self.arm.confirm(&m.0.text, &m.0.expected);
        self.mark_if_abandoned(answer)
    }

    fn import(&mut self, _m: Secret<Import>) -> Result<Imported, Abandoned> {
        let answer = self.arm.import();
        self.mark_if_abandoned(answer)
    }

    fn kept_or_placed(&mut self, m: Secret<HandedPath>) -> Result<KeptOrPlaced, Abandoned> {
        let answer = self.arm.kept_or_placed(&m.0.path);
        self.mark_if_abandoned(answer)
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
        assert_eq!((statement.name, statement.data["kind"].as_str(), statement.data["answerable"].as_bool()), (EventName::Moment, Some("statement"), Some(false)));
        assert_eq!(statement.data["board"], "b-1");
        assert!(pending.ids().is_empty(), "a statement waits for nothing");
        let pending_b = Arc::clone(&pending);
        let answerer = thread::spawn(move || {
            let event = rx.recv().unwrap();
            assert_eq!(event.data["kind"], "label");
            assert_eq!(event.data["walk"], "claim");
            let id = event.data["id"].as_str().unwrap().to_string();
            pending_b.answer(&id, Value::from("phone")).unwrap();
            assert_eq!(pending_b.answer(&id, Value::from("again")).unwrap_err().name(), "no_such_moment", "answered once");
            let event = rx.recv().unwrap();
            assert_eq!(event.data["kind"], "yes_no");
            let id = event.data["id"].as_str().unwrap().to_string();
            pending_b.cancel(&id).unwrap();
        });
        let label = person.label(Public(LabelBox { title: "name".into(), statements: vec![], default: None })).unwrap();
        assert_eq!(label, "phone");
        assert!(!person.abandoned);
        assert_eq!(person.yes_no(Public(Question { text: "?".into() })), Err(Abandoned));
        assert!(person.abandoned);
        answerer.join().unwrap();
    }

    /// AN ANSWER's FORM is its moment's kind's: a label box answered `7`, a
    /// question answered `null` and a yes-or-no answered `"yes"` are each
    /// refused `malformed_args` naming `value`, the moment still waiting;
    /// the right form then delivers — a label box's `null` its default — and
    /// a cancel of no moment answers `no_such_moment`.
    #[test]
    fn an_answer_of_another_form_is_refused_and_the_moment_waits() {
        let (bus, pending, arm) = fixture();
        let rx = bus.subscribe();
        let mut person = BridgePerson::new(Arc::clone(&bus), Arc::clone(&pending), arm, "claim", Some("b-1".into()));
        let page = Arc::clone(&pending);
        let answerer = thread::spawn(move || {
            for (wrong, right) in [(json!(7), Value::Null), (Value::Null, json!("an answer")), (json!("yes"), json!(true))] {
                let id = rx.recv().unwrap().data["id"].as_str().unwrap().to_string();
                let refused = page.answer(&id, wrong).unwrap_err().to_value();
                assert_eq!((refused["name"].as_str(), refused["what"].as_str()), (Some("malformed_args"), Some("value")), "{refused}");
                assert_eq!(page.ids(), std::slice::from_ref(&id), "the moment still waits");
                page.answer(&id, right).unwrap();
            }
        });
        let label = person.label(Public(LabelBox { title: "name".into(), statements: vec![], default: Some("the default".into()) })).unwrap();
        assert_eq!(label, "the default", "a label box's null is its default");
        assert_eq!(person.ask(Public(Question { text: "?".into() })).unwrap(), "an answer");
        assert!(person.yes_no(Public(Question { text: "?".into() })).unwrap());
        answerer.join().unwrap();
        assert_eq!(pending.cancel("m-gone").unwrap_err().name(), "no_such_moment");
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

    /// A moment the dev arm leaves abandons the walk and marks the person,
    /// as a page's cancel does.
    #[test]
    fn a_moment_the_arm_leaves_marks_the_person_abandoned() {
        let talk: crate::Talk = Arc::new(|_| {});
        let arm = Arc::new(DevArm::script(vec![crate::script::Answer::Abandon], talk));
        let mut person = BridgePerson::new(Arc::new(EventBus::new()), Arc::new(Pending::new()), arm, "retire", Some("b-1".into()));
        assert_eq!(person.confirm_typed(Consent(Confirmation { text: "retire?".into(), expected: "abcd".into() })), Err(Abandoned));
        assert!(person.abandoned);
    }

    /// The four kinds are the declared `MomentEvent.kind` union's words,
    /// and a statement alone owes no answer.
    #[test]
    fn the_moment_kinds_are_the_declared_four() {
        let kinds = [MomentKind::Statement, MomentKind::Label, MomentKind::Ask, MomentKind::YesNo];
        let declared = crate::shapes::shape("MomentEvent").unwrap().fields.iter().find(|f| f.name == "kind").unwrap().ty;
        assert_eq!(declared.matches('\'').count(), 2 * kinds.len(), "{declared}");
        for kind in kinds {
            assert!(declared.contains(&format!("'{}'", kind.as_str())), "{declared}");
        }
        assert_eq!(kinds.map(MomentKind::answerable), [false, true, true, true]);
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
