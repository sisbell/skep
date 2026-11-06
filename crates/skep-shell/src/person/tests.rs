//! The person over the bridge.
//!
//! The suite checks a public moment waiting for the page's answer and a
//! cancel abandoning it; an answer of another form refused, its moment still
//! waiting; a walk at no board naming none; the secret and consent moments
//! going to the arm and never to the page; a native statement said on the
//! arm's line and never on the bus; a moment the arm leaves marking the
//! person abandoned; a walk's halt named as the call's refusal, the
//! abandonment once a moment was cancelled, and none of its arms handing the
//! page the path a face names; the four moment kinds the declared four; and
//! the stop's `cancel_all` abandoning every waiting walk and closing the
//! table.

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

/// A walk's halt crosses as the call's refusal naming no path: a face about
/// a file names it beside its words (`Face::path`, §4b.3), the halt's own
/// member keeping it beside the face, whose value is the three words alone,
/// and the `halt` text of the abandonment and of `person_required` is the
/// block without it (the mutant that renders either detail by the halt's
/// `Display` hands the page the store's location).
#[test]
fn a_walks_halt_crosses_as_its_refusal_naming_no_path() {
    let (bus, pending, arm) = fixture();
    let mut person = BridgePerson::new(bus, pending, arm, "recover", Some("b-1".into()));
    let placed = || Halt::face_at("/a/store", "the key store holds no device key for this walk", "c", "a");
    let own = person.walk_refusal(placed(), None);
    assert!(matches!(&own, Refusal::Halt { face, .. } if face.path.as_deref() == Some(std::path::Path::new("/a/store"))), "{own:?}");
    assert!(!own.to_value().to_string().contains("/a/store"), "{}", own.to_value());
    for unanswered in [Unanswered::Abandoned, Unanswered::Refused { moment: "import", class: "secret", text: None }] {
        person.unanswered = Some(unanswered);
        let v = person.walk_refusal(placed(), None).to_value();
        let text = v["halt"].as_str().unwrap_or_default();
        assert!(text.starts_with("the key store holds no device key for this walk\n  cause: c") && !v.to_string().contains("/a/store"), "{v}");
    }
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
