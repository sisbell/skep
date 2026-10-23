//! The person over the bridge.
//!
//! As the dev provider record §2.2 (ii), `client.md` §4b.2's `moment` and
//! §4b.3's three classes draw it, it is a `Person` whose public moments —
//! the statements, the boxes, every question over public facts — become
//! `moment(id, kind, data)` events on the bus and block on a channel the
//! page's `answer(id, value)` or `cancel(id)` fills, and whose secret and
//! consent moments go to the dev arm ([`DevArm`]) and never to the page —
//! or, where the shell was opened with no arm (`ArmConfig::Refuse`: no
//! person is present, an agent's client), reach no arm: each such moment is
//! refused here, answered by nothing, said on `Talk`, and the walk abandoned
//! at it, the call's refusal then `person_required` naming the moment and
//! its class. The trait is synchronous —
//! `label(&mut self, …) -> Result<String, Abandoned>` — so each walk runs on
//! its own thread and the person it holds waits here; a `cancel` answers
//! `Abandoned`, which takes the walk's own abandonment exit, and the person
//! names the walk's halt as the call's refusal — `abandoned`, or
//! `person_required` ([`BridgePerson::walk_refusal`]). A statement needs no
//! answer and is forwarded as a moment whose `answerable` is false; the
//! page may ignore it — save a native one ([`NATIVE_RULES`]), a statement
//! naming where key material rests on disk, which goes to the dev arm — or,
//! with no arm, is said on `Talk` here, the shell's own window's line — and
//! never to the page. An answer's form is its moment's kind's
//! ([`MomentKind::takes`]): a label box takes a string, or `null` where the
//! box offers a default, which the answer then is; a question a string; a
//! yes-or-no a boolean — asked by [`Pending::answer`], the page's one way
//! in, so a walk never receives a value of another form, and a value of
//! another form leaves its moment waiting. The shell's stop closes the
//! table the answers come back through ([`Pending::cancel_all`]): a walk
//! that asks the page after it is abandoned at once, its moment never sent.

use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};

use serde_json::{json, Map, Value};
use skep_client::halt::Halt;
use skep_client::person::{Abandoned, Confirmation, Consent, Destination, HandedPath, Import, Imported, KeptOrPlaced, LabelBox, Person, Public, Question, Retype, Retyped, Secret, Sheet, Statement};

use crate::events::{EventBus, EventName};
use crate::refs::moment_id;
use crate::dev_arm::DevArm;
use crate::refusal::{Name, Refusal};
use crate::Talk;

/// What the page sent for a pending moment.
#[derive(Debug, Clone, PartialEq)]
enum Reply {
    /// `answer(id, value)`.
    Answer(Value),
    /// `cancel(id)`.
    Cancel,
}

/// The pending moments: each waiting walk's channel by the moment's id.
///
/// Each stands with the moment's kind, so an answer is routed to the walk
/// that asked (the dev provider record §3.3) and held to the form that kind
/// takes. The shell's stop closes the table ([`Pending::cancel_all`]): from
/// then on no moment is entered, so no walk waits on a page that will never
/// answer.
#[derive(Debug, Default)]
pub struct Pending {
    table: Mutex<Table>,
}

/// The moments waiting, and whether the stop has closed the table.
///
/// One lock stands over both, so no moment is entered after the stop has
/// drained the table.
#[derive(Debug, Default)]
struct Table {
    waiting: HashMap<String, (MomentKind, Sender<Reply>)>,
    closed: bool,
}

impl Pending {
    /// Returns a table with no moment pending.
    pub fn new() -> Pending {
        Pending::default()
    }

    /// Enters a moment under `id`, its answer to come on the receiver.
    ///
    /// It answers `None` once the stop has closed the table: a moment asked
    /// after it is entered nowhere.
    ///
    /// # Panics
    ///
    /// Panics where the pending lock is poisoned.
    fn register(&self, id: &str, kind: MomentKind) -> Option<Receiver<Reply>> {
        let mut table = self.table.lock().expect("the pending lock");
        if table.closed {
            return None;
        }
        let (tx, rx) = channel();
        table.waiting.insert(id.to_string(), (kind, tx));
        Some(rx)
    }

    /// Takes the moment `id` out of the table, where it waits.
    ///
    /// It is taken where `admits` admits its kind; a moment `admits` refuses
    /// keeps waiting.
    ///
    /// # Errors
    ///
    /// Returns the refusal `admits` makes, and `no_such_moment` where no
    /// moment of that id waits.
    ///
    /// # Panics
    ///
    /// Panics where the pending lock is poisoned.
    fn take(&self, id: &str, admits: impl FnOnce(MomentKind) -> Result<(), Refusal>) -> Result<Sender<Reply>, Refusal> {
        match self.table.lock().expect("the pending lock").waiting.entry(id.to_string()) {
            Entry::Occupied(moment) => {
                admits(moment.get().0)?;
                Ok(moment.remove().1)
            }
            Entry::Vacant(_) => Err(no_such_moment(id)),
        }
    }

    /// Handles `answer(id, value)`: `value` handed to the walk that asked.
    ///
    /// The value is of the form its moment's kind takes
    /// ([`MomentKind::takes`]).
    ///
    /// # Errors
    ///
    /// Returns `malformed_args` naming `value` and the form where `value` is
    /// of another form, the moment still waiting for one; `no_such_moment`
    /// where no moment of that id waits.
    pub fn answer(&self, id: &str, value: Value) -> Result<(), Refusal> {
        let tx = self.take(id, |kind| if kind.takes(&value) { Ok(()) } else { Err(Refusal::shell(Name::MALFORMED_ARGS, json!({"what": "value", "takes": kind.form()}))) })?;
        // A walk that ended without its answer dropped its receiver: no
        // moment waits there.
        tx.send(Reply::Answer(value)).map_err(|_| no_such_moment(id))
    }

    /// Handles `cancel(id)`: the walk that asked abandoned at that moment.
    ///
    /// # Errors
    ///
    /// Returns `no_such_moment` where no moment of that id waits.
    pub fn cancel(&self, id: &str) -> Result<(), Refusal> {
        let tx = self.take(id, |_| Ok(()))?;
        tx.send(Reply::Cancel).map_err(|_| no_such_moment(id))
    }

    /// Cancels every pending moment and closes the table: the shell's stop.
    ///
    /// A moment asked after it is abandoned at once, never entered and never
    /// sent to the page.
    ///
    /// # Panics
    ///
    /// Panics where the pending lock is poisoned.
    pub fn cancel_all(&self) {
        let all: Vec<Sender<Reply>> = {
            let mut table = self.table.lock().expect("the pending lock");
            table.closed = true;
            table.waiting.drain().map(|(_, (_, tx))| tx).collect()
        };
        for tx in all {
            let _ = tx.send(Reply::Cancel);
        }
    }

    /// Returns the ids waiting, in no order.
    ///
    /// # Panics
    ///
    /// Panics where the pending lock is poisoned.
    #[cfg(test)]
    fn ids(&self) -> Vec<String> {
        self.table.lock().expect("the pending lock").waiting.keys().cloned().collect()
    }
}

/// A public moment's kind, as `MomentEvent.kind` spells it.
///
/// It is a statement said, or a box or a question the page answers — a
/// label box beside whether it offers a default, which its form turns on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MomentKind {
    Statement,
    Label { default: bool },
    Ask,
    YesNo,
}

impl MomentKind {
    /// Returns the kind as the event spells it.
    fn as_str(self) -> &'static str {
        match self {
            MomentKind::Statement => "statement",
            MomentKind::Label { .. } => "label",
            MomentKind::Ask => "ask",
            MomentKind::YesNo => "yes_no",
        }
    }

    /// Returns whether the page owes an answer: every kind but a statement.
    fn answerable(self) -> bool {
        self != MomentKind::Statement
    }

    /// Returns whether `answer` is of the form this kind takes.
    ///
    /// A label box takes a string, or `null` where the box offers a default,
    /// which the answer then is; a question a string; a yes-or-no a boolean.
    /// A statement takes none: no answer is owed it.
    fn takes(self, answer: &Value) -> bool {
        match self {
            MomentKind::Statement => false,
            MomentKind::Label { default } => answer.is_string() || (default && answer.is_null()),
            MomentKind::Ask => answer.is_string(),
            MomentKind::YesNo => answer.is_boolean(),
        }
    }

    /// Returns the form this kind takes, as a refused answer names it.
    fn form(self) -> &'static str {
        match self {
            MomentKind::Statement => "no answer",
            MomentKind::Label { default: true } => "a string, or null for the box's default",
            MomentKind::Label { default: false } | MomentKind::Ask => "a string",
            MomentKind::YesNo => "a boolean",
        }
    }
}

/// The rules whose statements are native, the shell's own window's.
///
/// Their statements are never the page's (`client.md` §4b.3: an anchor
/// file's destination is native, "its copy the ladder words" with it, and
/// "a key file's path, the store's location, an anchor file's path or
/// contents: the same"). Each is a rule whose statements name where key
/// material rests, or what was done with it there: AUTH-5.40's ladder words
/// at the anchor file written; AUTH-5.41's line on the print, naming the
/// file kept; §4.1 S3's read-back of an anchor file; AUTH-5.54 step 3's
/// placed copy and kept artifact; §3a's key file written into the store;
/// and §9 item 36's key file a retirement leaves in place. A statement is
/// classed by its rule, the one handle a `Public<Statement>` carries.
const NATIVE_RULES: [&str; 6] = ["AUTH-5.40", "AUTH-5.41", "§4.1 S3", "AUTH-5.54 step 3", "§3a", "§9 item 36"];

/// Returns the refusal for an `answer` or a `cancel` no moment waits for.
fn no_such_moment(id: &str) -> Refusal {
    Refusal::shell(Name::NO_SUCH_MOMENT, json!({"id": id}))
}

/// Why a moment of the walk went unanswered.
///
/// It is what the walk's halt is then named as the call's refusal
/// ([`BridgePerson::walk_refusal`]).
#[derive(Debug, Clone, PartialEq, Eq)]
enum Unanswered {
    /// A moment was cancelled or left: `abandoned`.
    ///
    /// The page or the shell's stop cancelled it, or the dev arm left it.
    Abandoned,
    /// No person is present to answer a secret or consent moment.
    ///
    /// Under `ArmConfig::Refuse` it is `person_required`, naming the moment
    /// by the seam's own name for it, its class, and — a confirmation's — the
    /// text that was asked, public data (`client.md` §4b.3).
    Refused { moment: &'static str, class: &'static str, text: Option<String> },
}

/// Who answers a walk's secret and consent moments, as the shell holds it.
///
/// The shell holds it for the run: the dev arm (`ArmConfig::Auto`,
/// `ArmConfig::Script`), or no one (`ArmConfig::Refuse`) — the person then
/// refuses each such moment, reaching no arm, and says the refusal and the
/// native statements on the `Talk` sink carried here. Its `Debug` leaves out
/// the sink, a closure.
pub enum Answerer {
    /// The dev arm answers.
    Arm(DevArm),
    /// No person is present: every secret and consent moment is refused.
    ///
    /// Each refusal is said on this sink.
    Refuse(Talk),
}

impl std::fmt::Debug for Answerer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Answerer::Arm(arm) => f.debug_tuple("Arm").field(arm).finish(),
            Answerer::Refuse(_) => f.write_str("Refuse"),
        }
    }
}

/// The person a walk is handed.
///
/// It holds the bus its public moments go out on, the pending table their
/// answers come back through, the answerer the secret and consent moments
/// go to — the dev arm, or none, under which they are refused here — and
/// the walk's name and board reference for the event.
#[derive(Debug)]
pub struct BridgePerson {
    bus: Arc<EventBus>,
    pending: Arc<Pending>,
    answerer: Arc<Answerer>,
    walk: &'static str,
    /// The board reference the walk runs at.
    ///
    /// It is none for a walk that touches no board (`keygen`'s box).
    board_reference: Option<String>,
    /// Why a moment went unanswered, where one did.
    ///
    /// It was cancelled by the page or the shell's stop, left by the dev
    /// arm, or refused here with no arm: the walk's halt is that refusal
    /// ([`BridgePerson::walk_refusal`]).
    unanswered: Option<Unanswered>,
}

impl BridgePerson {
    /// Returns the person for `walk` at the board `board_reference` names.
    ///
    /// Its secret and consent moments are `answerer`'s — the dev arm's, or
    /// refused where the run holds none.
    pub fn new(bus: Arc<EventBus>, pending: Arc<Pending>, answerer: Arc<Answerer>, walk: &'static str, board_reference: Option<String>) -> BridgePerson {
        BridgePerson { bus, pending, answerer, walk, board_reference, unanswered: None }
    }

    /// Returns the walk's halt `h` as the call's refusal.
    ///
    /// It is `person_required` where a secret or consent moment of the walk
    /// was refused for want of a person, the abandonment where a moment was
    /// cancelled by the page or the shell's stop or left by the dev arm, else
    /// the family's member — a halt's face under `armed` where the row
    /// diagnosed its armed name.
    pub fn walk_refusal(&self, h: Halt, armed: Option<Name>) -> Refusal {
        match &self.unanswered {
            Some(Unanswered::Refused { moment, class, text }) => {
                let mut detail = Map::new();
                detail.insert("walk".into(), Value::from(self.walk));
                detail.insert("moment".into(), Value::from(*moment));
                detail.insert("class".into(), Value::from(*class));
                if let Some(text) = text {
                    detail.insert("text".into(), Value::from(text.as_str()));
                }
                detail.insert("halt".into(), Value::from(h.to_string()));
                Refusal::shell(Name::PERSON_REQUIRED, Value::Object(detail))
            }
            Some(Unanswered::Abandoned) => Refusal::shell(Name::ABANDONED, json!({"halt": h.to_string()})),
            None => match armed {
                Some(name) => Refusal::of_named(name, h),
                None => Refusal::from(h),
            },
        }
    }

    /// Forwards a public moment to the page as its event.
    ///
    /// The wait for the page's answer follows where its kind owes one.
    ///
    /// # Errors
    ///
    /// Returns [`Abandoned`] for a cancel, and for a moment the stop's
    /// closed table enters no more — abandoned before its event, since no
    /// page will answer it.
    fn moment(&mut self, kind: MomentKind, data: Value) -> Result<Value, Abandoned> {
        let id = moment_id();
        let answerable = kind.answerable();
        let rx = if answerable {
            let Some(rx) = self.pending.register(&id, kind) else {
                self.unanswered = Some(Unanswered::Abandoned);
                return Err(Abandoned);
            };
            Some(rx)
        } else {
            None
        };
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
                self.unanswered = Some(Unanswered::Abandoned);
                Err(Abandoned)
            }
        }
    }

    /// Hands a secret or consent moment to the dev arm, where one stands.
    ///
    /// Its answer is passed on, and the person marked abandoned where the arm
    /// left the moment.
    ///
    /// # Errors
    ///
    /// Returns [`Abandoned`] where the arm left the moment, and where the
    /// shell holds no arm (`ArmConfig::Refuse`): nothing answers it, the
    /// refusal is said on `Talk` naming the moment and its class, and the
    /// walk takes its abandonment exit, the halt then named
    /// `person_required`.
    fn hand<T>(&mut self, moment: &'static str, class: &'static str, text: Option<String>, ask: impl FnOnce(&DevArm) -> Result<T, Abandoned>) -> Result<T, Abandoned> {
        let answerer = Arc::clone(&self.answerer);
        match &*answerer {
            Answerer::Arm(arm) => ask(arm).inspect_err(|_| self.unanswered = Some(Unanswered::Abandoned)),
            Answerer::Refuse(talk) => {
                talk(&format!("person: the {moment} moment ({}) of `{}` is refused — no person is present to answer it, and the walk is abandoned there", class.to_uppercase(), self.walk));
                self.unanswered = Some(Unanswered::Refused { moment, class, text });
                Err(Abandoned)
            }
        }
    }
}

impl Person for BridgePerson {
    fn say(&mut self, m: Public<Statement>) {
        if NATIVE_RULES.contains(&m.0.rule) {
            // The shell's own window's line: the arm's where one stands,
            // said here where none does — never the page's.
            match &*self.answerer {
                Answerer::Arm(arm) => arm.native(&m.0),
                Answerer::Refuse(talk) => talk(&format!("person: {}: {}", m.0.rule, m.0.text)),
            }
            return;
        }
        let _ = self.moment(MomentKind::Statement, json!({"rule": m.0.rule, "text": m.0.text}));
    }

    fn label(&mut self, m: Public<LabelBox>) -> Result<String, Abandoned> {
        let kind = MomentKind::Label { default: m.0.default.is_some() };
        let v = self.moment(kind, json!({"title": m.0.title, "statements": m.0.statements, "default": m.0.default}))?;
        match v {
            Value::String(s) => Ok(s),
            Value::Null => Ok(m.0.default.expect("Pending::answer admits null where the box offers a default alone")),
            other => unreachable!("Pending::answer admits a label box's string, or null where it offers a default, never {other}"),
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
        let fields = m.0.fields;
        self.hand("sheet", "secret", None, |arm| {
            arm.sheet(fields);
            Ok(())
        })
    }

    fn dismiss(&mut self) {
        match &*self.answerer {
            Answerer::Arm(arm) => arm.dismiss(),
            Answerer::Refuse(talk) => talk("person: the sheet is dismissed (nothing was displayed)"),
        }
    }

    fn retype(&mut self, _m: Secret<Retype>) -> Result<Retyped, Abandoned> {
        self.hand("retype", "secret", None, DevArm::retype)
    }

    fn destination(&mut self, m: Secret<Destination>) -> Result<std::path::PathBuf, Abandoned> {
        let which = m.0.which;
        self.hand("destination", "secret", None, |arm| arm.destination(which))
    }

    fn confirm_typed(&mut self, m: Consent<Confirmation>) -> Result<String, Abandoned> {
        let confirmation = m.0;
        self.hand("confirm_typed", "consent", Some(confirmation.text.clone()), |arm| arm.confirm(&confirmation))
    }

    fn import(&mut self, _m: Secret<Import>) -> Result<Imported, Abandoned> {
        self.hand("import", "secret", None, DevArm::import)
    }

    fn kept_or_placed(&mut self, m: Secret<HandedPath>) -> Result<KeptOrPlaced, Abandoned> {
        let path = m.0.path;
        self.hand("kept_or_placed", "secret", None, |arm| arm.kept_or_placed(&path))
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::thread;

    use super::*;

    fn quiet() -> crate::Talk {
        Arc::new(|_| {})
    }

    fn fixture() -> (Arc<EventBus>, Arc<Pending>, Arc<Answerer>) {
        (Arc::new(EventBus::new()), Arc::new(Pending::new()), Arc::new(Answerer::Arm(DevArm::auto(PathBuf::from("/tmp/x"), quiet()))))
    }

    /// A public moment is an event with its id and kind, answered by the
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
        assert!(person.unanswered.is_none());
        assert_eq!(person.yes_no(Public(Question { text: "?".into() })), Err(Abandoned));
        assert_eq!(person.unanswered, Some(Unanswered::Abandoned));
        answerer.join().unwrap();
    }

    /// An answer's form is its moment's kind's: a label box answered `7`, a
    /// question answered `null`, a yes-or-no answered `"yes"` and a box with
    /// no default answered `null` are each refused `malformed_args` naming
    /// `value` and the form, the moment still waiting; the right form then
    /// delivers — a label box's `null` its default — and a cancel of no
    /// moment answers `no_such_moment` (the mutant that admits `null` at
    /// every box turns a box with no default's into an empty byline).
    #[test]
    fn an_answer_of_another_form_is_refused_and_the_moment_waits() {
        let (bus, pending, arm) = fixture();
        let rx = bus.subscribe();
        let mut person = BridgePerson::new(Arc::clone(&bus), Arc::clone(&pending), arm, "claim", Some("b-1".into()));
        let page = Arc::clone(&pending);
        let answerer = thread::spawn(move || {
            let cells = [(json!(7), "a string, or null for the box's default", Value::Null), (Value::Null, "a string", json!("an answer")), (json!("yes"), "a boolean", json!(true)), (Value::Null, "a string", json!("phone"))];
            for (wrong, takes, right) in cells {
                let id = rx.recv().unwrap().data["id"].as_str().unwrap().to_string();
                let refused = page.answer(&id, wrong).unwrap_err().to_value();
                assert_eq!((refused["name"].as_str(), refused["what"].as_str(), refused["takes"].as_str()), (Some("malformed_args"), Some("value"), Some(takes)), "{refused}");
                assert_eq!(page.ids(), std::slice::from_ref(&id), "the moment still waits");
                page.answer(&id, right).unwrap();
            }
        });
        let label = person.label(Public(LabelBox { title: "name".into(), statements: vec![], default: Some("the default".into()) })).unwrap();
        assert_eq!(label, "the default", "a label box's null is its default");
        assert_eq!(person.ask(Public(Question { text: "?".into() })).unwrap(), "an answer");
        assert!(person.yes_no(Public(Question { text: "?".into() })).unwrap());
        assert_eq!(person.label(Public(LabelBox { title: "name".into(), statements: vec![], default: None })).unwrap(), "phone", "a box with no default takes no null");
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

    /// A secret and a consent moment never reach the bus — every one of the
    /// seven, the sheet, its dismissal and an anchor's destination among
    /// them: the arm answers.
    #[test]
    fn secret_and_consent_moments_go_to_the_arm_and_never_to_the_page() {
        let (bus, pending, arm) = fixture();
        let rx = bus.subscribe();
        let mut person = BridgePerson::new(bus, pending, arm, "retire", Some("b-1".into()));
        assert_eq!(person.confirm_typed(Consent(Confirmation { text: "retire?".into(), expected: "abcd".into() })).unwrap(), "abcd");
        assert_eq!(person.retype(Secret(Retype { prompt: "type".into() })).unwrap(), Retyped::Declined);
        assert_eq!(person.import(Secret(Import { prompt: "import".into() })).unwrap(), Imported::Neither);
        assert_eq!(person.kept_or_placed(Secret(HandedPath { path: PathBuf::from("/k"), text: "?".into() })).unwrap(), KeptOrPlaced::Kept);
        let fields = skep_client::sheet::SheetFields { anchor: true, alg: "mldsa65-ed25519".into(), label: None, fingerprint_hex: "ab".repeat(32), fingerprint_grouped: "abab".into(), seed_grouped: "5e5e 5e5e".into(), account: None, principal: None, origin: None };
        person.sheet(Secret(Sheet { fields })).unwrap();
        person.dismiss();
        assert_eq!(person.destination(Secret(Destination { prompt: "where".into(), which: 1 })).unwrap(), PathBuf::from("/tmp/x/anchor-1"));
        assert!(rx.try_recv().is_err(), "no event crossed to the page");
    }

    /// A native statement — one naming where key material rests (§4b.3) — is
    /// said on `Talk` under its rule and never reaches the bus, under each of
    /// the six rules spelled here; a statement of another rule crosses as a
    /// moment (the mutant that drops a rule from `NATIVE_RULES` hands the
    /// page an anchor file's path, or the store's location).
    #[test]
    fn a_native_statement_goes_to_the_arm_and_never_to_the_page() {
        let lines = Arc::new(Mutex::new(Vec::new()));
        let kept = Arc::clone(&lines);
        let talk: crate::Talk = Arc::new(move |l: &str| kept.lock().unwrap().push(l.to_string()));
        let bus = Arc::new(EventBus::new());
        let rx = bus.subscribe();
        let mut person = BridgePerson::new(bus, Arc::new(Pending::new()), Arc::new(Answerer::Arm(DevArm::auto(PathBuf::from("/tmp/x"), talk))), "claim", Some("b-1".into()));
        for rule in ["AUTH-5.40", "AUTH-5.41", "§4.1 S3", "AUTH-5.54 step 3", "§3a", "§9 item 36"] {
            person.say(Public(Statement { rule, text: "anchor file written: /store-anchors/a".into() }));
            assert!(rx.try_recv().is_err(), "{rule}: a native statement crossed to the page");
            assert_eq!(lines.lock().unwrap().last().map(String::as_str), Some(format!("dev arm: {rule}: anchor file written: /store-anchors/a").as_str()), "{rule}");
        }
        person.say(Public(Statement { rule: "AUTH-5.44 (notebook)", text: "keep the anchor files apart".into() }));
        assert_eq!(rx.try_recv().map(|e| e.data["data"]["rule"].clone()), Ok(json!("AUTH-5.44 (notebook)")), "a public statement crosses");
    }

    /// A moment the dev arm leaves abandons the walk and marks the person,
    /// as a page's cancel does.
    #[test]
    fn a_moment_the_arm_leaves_marks_the_person_abandoned() {
        let talk: crate::Talk = Arc::new(|_| {});
        let arm = Arc::new(Answerer::Arm(DevArm::script(vec![crate::script::Answer::Abandon], talk)));
        let mut person = BridgePerson::new(Arc::new(EventBus::new()), Arc::new(Pending::new()), arm, "retire", Some("b-1".into()));
        assert_eq!(person.confirm_typed(Consent(Confirmation { text: "retire?".into(), expected: "abcd".into() })), Err(Abandoned));
        assert_eq!(person.unanswered, Some(Unanswered::Abandoned));
    }

    /// The walk's halt as the call's refusal is the person's to name: before
    /// any moment is cancelled, the halt's face under the row's armed name,
    /// or the halt's own member where the row arms none; once one is, the
    /// abandonment, whatever the row armed.
    #[test]
    fn a_walks_halt_is_the_abandonment_once_a_moment_was_cancelled() {
        let (bus, pending, arm) = fixture();
        let rx = bus.subscribe();
        let mut person = BridgePerson::new(Arc::clone(&bus), Arc::clone(&pending), arm, "accept", Some("b-1".into()));
        let halt = || Halt::face("s", "c", "a");
        assert_eq!(person.walk_refusal(halt(), Some(Name::NOT_DELEGATED)).name(), "not_delegated");
        assert_eq!(person.walk_refusal(halt(), None).name(), "halt");
        let page = Arc::clone(&pending);
        let canceller = thread::spawn(move || page.cancel(rx.recv().unwrap().data["id"].as_str().unwrap()));
        assert_eq!(person.ask(Public(Question { text: "?".into() })), Err(Abandoned));
        canceller.join().unwrap().unwrap();
        assert_eq!(person.walk_refusal(halt(), Some(Name::NOT_DELEGATED)).name(), "abandoned");
    }

    /// The four kinds are the declared `MomentEvent.kind` union's words,
    /// and a statement alone owes no answer.
    #[test]
    fn the_moment_kinds_are_the_declared_four() {
        let kinds = [MomentKind::Statement, MomentKind::Label { default: false }, MomentKind::Ask, MomentKind::YesNo];
        let declared = crate::shapes::shape("MomentEvent").unwrap().fields.iter().find(|f| f.name == "kind").unwrap().ty;
        assert_eq!(declared.matches('\'').count(), 2 * kinds.len(), "{declared}");
        for kind in kinds {
            assert!(declared.contains(&format!("'{}'", kind.as_str())), "{declared}");
        }
        assert_eq!(kinds.map(MomentKind::answerable), [false, true, true, true]);
    }

    /// `cancel_all` abandons every waiting walk and closes the table: a
    /// moment asked after it is abandoned at once, entered nowhere and sent
    /// to no page (the mutant that drains the table and leaves it open
    /// enters the moment and sends it, for no page to answer).
    #[test]
    fn cancel_all_abandons_every_pending_moment_and_closes_the_table() {
        let (bus, pending, arm) = fixture();
        let rx = bus.subscribe();
        let mut person = BridgePerson::new(Arc::clone(&bus), Arc::clone(&pending), arm, "claim", Some("b-1".into()));
        let p = Arc::clone(&pending);
        let t = thread::spawn(move || {
            let _ = rx.recv().unwrap();
            p.cancel_all();
            rx
        });
        assert_eq!(person.ask(Public(Question { text: "q".into() })), Err(Abandoned));
        let rx = t.join().unwrap();
        assert_eq!(person.ask(Public(Question { text: "after the stop".into() })), Err(Abandoned));
        assert!(rx.try_recv().is_err() && pending.ids().is_empty(), "a moment after the stop is entered nowhere and sent to no page");
    }
}
