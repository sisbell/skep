//! THE REGISTRATION REQUEST (REG-4.67, REG-1.86; REG-4.102 to REG-4.104) —
//! no daemon, and no board anywhere: the applicant's own side under the
//! scripted person, over a key store and anchor directories of the test's
//! own. The door identifier judged before anything is asked, generated or
//! written; each enrolment a pair's two anchor-flagged entries and the one
//! device key, each under the label its box fixed; the body parsed under
//! its row with no `sig`, its signature verifying over the frame re-built
//! from its members and failing where any field moves; the kind read off
//! the request — a board that carries on makes the node pair alone, names
//! the store's key and carries no `board` — a fresh freshness value every
//! run; the device key named where the store holds one and never generated
//! beside it; and every refusal ahead of the first box.

use std::collections::BTreeSet;
use std::path::Path;

use skep_client::ceremony::registration::{registration_request, say_request, KeyRole, RegistrationOptions, RegistrationRequest};
use skep_client::person::scripted::{Script, Scripted};
use skep_client::sheet::{group_hex, KeyFile};
use skep_client::store::FileStore;
use skep_identity::{encode_enroll, enrolled_signer, framed, parse_enroll, thread_key, DoorId, Enrollment, Fingerprint, Freshness, PublicKey, REGISTRATION_TAG};
use skep_registry::{parse_registration, ParseRefusal, RegistrationKind, RequestMembers};

use crate::common::{files_in, keygen};

/// A door identifier in its one spelling: the registry's own door.
const DOOR: &str = "realm:9f2a00000000000000000000000000000000000000000000000000000000c41d door:1.1.0.1";

/// The composition's inputs: one destination per anchor under `places`,
/// nothing fixed by a flag.
fn options(board_carries_on: bool, places: &Path) -> RegistrationOptions {
    let anchors = if board_carries_on { 2 } else { 4 };
    RegistrationOptions {
        door: DOOR.into(),
        board_carries_on,
        key_file: None,
        label: None,
        anchor_labels: vec![],
        anchor_out: (0..anchors).map(|i| places.join(i.to_string())).collect(),
        paper: false,
        host_name: "testhost".into(),
        date: "2026-11-16".into(),
    }
}

/// The request composed, or the transcript beside its halt.
fn composed(person: &mut Scripted, store: &FileStore, opts: &RegistrationOptions) -> RegistrationRequest {
    registration_request(person, store, opts).unwrap_or_else(|h| panic!("the registration halted: {h}\n{}", person.transcript.join("\n")))
}

/// The one anchor file under `places/<i>`, parsed.
fn sheet(places: &Path, i: usize) -> KeyFile {
    let files = files_in(&places.join(i.to_string()));
    assert_eq!(files.len(), 1, "one anchor file under destination {i}");
    KeyFile::parse(&std::fs::read(&files[0]).unwrap()).expect("an anchor file")
}

/// A request's members, parsed under its own row, and its enrolments.
struct Parsed {
    door: String,
    fresh: String,
    shape: String,
    node_text: String,
    board_text: Option<String>,
    signer: String,
    signature: String,
    fields: Vec<String>,
    node: Vec<Enrollment>,
    board: Option<Vec<Enrollment>>,
}

fn parsed(kind: RegistrationKind, body: &str) -> Parsed {
    let record = parse_registration(kind, body.as_bytes()).unwrap_or_else(|e| panic!("the body parses under its row: {e:?}"));
    assert_eq!(record.sig, None, "no `sig`: that member is the writing hand's, never the applicant's");
    let m: RequestMembers<'_> = record.body.request().expect("a request's body");
    Parsed {
        door: m.door.to_string(),
        fresh: m.fresh.as_str().to_string(),
        shape: m.shape.to_string(),
        node_text: m.node.to_string(),
        board_text: m.board.map(str::to_string),
        signer: m.signer.as_str().to_string(),
        signature: m.signature.as_str().to_string(),
        fields: m.frame_fields().into_iter().map(str::to_string).collect(),
        node: parse_enroll(m.node.as_bytes()).expect("the node enrolment is a canonical record"),
        board: m.board.map(|b| parse_enroll(b.as_bytes()).expect("the board enrolment is a canonical record")),
    }
}

/// Whether `signature` verifies over the frame built from `fields`, under
/// `key`'s own row.
fn verifies(key: &PublicKey, fields: &[String], signature: &[u8]) -> bool {
    let frame = framed(REGISTRATION_TAG, &fields.iter().map(|f| f.as_bytes()).collect::<Vec<_>>());
    skep_signature::verify(key.sig_alg_row().tag, key, &frame, signature).is_ok()
}

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2) && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)), "lowercase hex, whole bytes");
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

/// FENCE 3 (REG-4.102) — EACH ENROLMENT IS ITS PAIR AND THE ONE
/// DEVICE KEY, AND NOTHING ELSE: on a fresh registration from an empty
/// store, five boxes — the device's, then the org root pair's two and the
/// node pair's two — and the node enrolment parses to exactly the node
/// pair's two anchor-flagged entries and the device key, device-flagged,
/// each under the label its own box fixed; the board enrolment is the org
/// root pair and the same device key. Each rides as `encode_enroll`'s text,
/// no line break; the store holds the one device key the run generated.
/// (The mutant that swaps two labels puts a sheet's name on another key;
/// the one that adds a fourth entry to an enrolment is counted.)
#[test]
fn each_enrolment_is_its_pair_and_the_one_device_key_under_the_labels_their_boxes_fixed() {
    let dir = tempfile::tempdir().unwrap();
    let (store, places) = (FileStore::open(dir.path().join("store")), dir.path().join("sheets"));
    let names = ["root first", "root second", "node first", "node second"];
    let script = std::iter::once("laptop").chain(names).map(|n| Script::Label(n.into())).collect();
    let mut person = Scripted::new(script);
    let request = composed(&mut person, &store, &options(false, &places));
    let asked: Vec<&String> = person.transcript.iter().filter(|l| l.starts_with("PUBLIC label [")).collect();
    assert_eq!(asked.len(), 5, "five name boxes (REG-4.103):\n{}", person.transcript.join("\n"));
    assert!(asked[0].starts_with("PUBLIC label [name this device]"), "the device's box first: {}", asked[0]);
    // The box that fixed each label, by the file it landed in.
    let sheets: Vec<KeyFile> = (0..4).map(|i| sheet(&places, i)).collect();
    for (file, name) in sheets.iter().zip(names) {
        assert_eq!((file.label.as_deref(), file.anchor), (Some(name), true));
    }
    let device = store.device_keys().unwrap();
    assert_eq!(device.len(), 1, "one device key, generated by this run");
    assert_eq!((device[0].label.as_deref(), device[0].fingerprint, request.device.generated), (Some("laptop"), request.device.fingerprint, true));

    let p = parsed(RegistrationKind::Fresh, &request.body);
    let board = p.board.as_ref().expect("a fresh request carries the board root's enrolment");
    let entry = |e: &Enrollment| (Fingerprint::of(&e.key), e.anchor, e.label().map(str::to_string));
    let anchor = |file: &KeyFile| (file.fingerprint, true, file.label.clone());
    let device_entry = (device[0].fingerprint, false, Some("laptop".to_string()));
    assert_eq!(p.node.iter().map(entry).collect::<Vec<_>>(), vec![anchor(&sheets[2]), anchor(&sheets[3]), device_entry.clone()], "the node pair and the device key, and no other");
    assert_eq!(board.iter().map(entry).collect::<Vec<_>>(), vec![anchor(&sheets[0]), anchor(&sheets[1]), device_entry], "the org root pair and the SAME device key, and no other");
    for (enrolment, text) in [(&p.node, &p.node_text), (board, p.board_text.as_ref().unwrap())] {
        assert_eq!(*text, encode_enroll(enrolment), "the member is `encode_enroll`'s own text, as written");
        assert!(!text.contains('\n') && !text.contains('\r'), "no line break");
        assert_eq!(enrolment[2].key, device[0].public);
    }
    // The outcome names the same keys, pair by pair.
    assert_eq!(request.board_pair.iter().map(|a| a.fingerprint).collect::<Vec<_>>(), vec![sheets[0].fingerprint, sheets[1].fingerprint]);
    assert_eq!(request.node_pair.iter().map(|a| a.fingerprint).collect::<Vec<_>>(), vec![sheets[2].fingerprint, sheets[3].fingerprint]);
    assert_eq!(request.keys.iter().map(|k| k.role).collect::<Vec<_>>(), vec![KeyRole::OrgRootAnchor, KeyRole::OrgRootAnchor, KeyRole::NodeAnchor, KeyRole::NodeAnchor, KeyRole::Device]);
    assert!(person.said("[§3a]: key file written: "), "the generated key's custody line");
    assert!(
        person.transcript.iter().position(|l| l.contains("[§3a]: key file written: ")) > person.transcript.iter().position(|l| l.contains("[AUTH-5.44 (create-org)]")),
        "the device key is generated after the moment:\n{}",
        person.transcript.join("\n")
    );
}

/// FENCE 4 (REG-4.67; REG-4.73) — THE BODY VERIFIES OVER THE FRAME
/// RE-BUILT FROM ITS OWN MEMBERS, AND NO FIELD CAN MOVE: the body parses by
/// `parse_registration` under the fresh row with no `sig`; the key
/// `enrolled_signer` answers over its enrolments is the device key; the one
/// signature verifies under it over `framed(skep-registration-v1, [door,
/// fresh, shape, node, board])`, each field the member as written, and
/// fails where any one of the five is altered by a byte, where `board` is
/// left out, and over the body's own bytes; `shape` is the fresh row's
/// ordinal path. And the scannable form prints each key once — the device
/// key once though two enrolments carry it — each label beside its grouped
/// fingerprint: as a set, the thread's key.
#[test]
fn the_body_verifies_over_the_frame_rebuilt_from_its_members_and_no_field_can_move() {
    let dir = tempfile::tempdir().unwrap();
    let (store, places) = (FileStore::open(dir.path().join("store")), dir.path().join("sheets"));
    let mut person = Scripted::new(std::iter::once(Script::Label("laptop".into())).chain(vec![Script::LabelDefault; 4]).collect());
    let request = composed(&mut person, &store, &options(false, &places));
    assert_eq!(request.kind, RegistrationKind::Fresh);
    assert!(!request.body.contains('\n'), "one line");
    assert!(request.body.starts_with("{\"type\":\"fresh\",\"door\":\"") && !request.body.contains("\"sig\":"), "{}", &request.body[..80]);
    assert_eq!(parse_registration(RegistrationKind::BoardCarriesOn, request.body.as_bytes()).map(|_| ()), Err(ParseRefusal::WrongType), "a record under its own row and no other");
    let p = parsed(RegistrationKind::Fresh, &request.body);
    assert_eq!((p.door.as_str(), p.shape.as_str()), (DOOR, "3.54.1.1"));
    assert_eq!(p.shape, RegistrationKind::Fresh.row().ordinal_path(), "the fresh row's own address, by its ordinal path");
    assert_eq!(DoorId::parse(&p.door), Some(request.door.clone()));
    assert_eq!(Freshness::parse(&p.fresh), Some(request.fresh.clone()));
    let board = p.board.clone().expect("the board root's enrolment");
    assert_eq!(p.fields, vec![p.door.clone(), p.fresh.clone(), p.shape.clone(), p.node_text.clone(), p.board_text.clone().unwrap()], "five fields, in the frame's order");
    let signer = Fingerprint::parse_hex(&p.signer).expect("a fingerprint");
    let key = enrolled_signer(&signer, &[&p.node, &board]).expect("every enrolment present enrols the signer").clone();
    assert_eq!((Fingerprint::of(&key), signer), (request.device.fingerprint, request.device.fingerprint), "the signer is the device key");
    let signature = unhex(&p.signature);
    assert!(verifies(&key, &p.fields, &signature), "the one signature, over the frame re-built from the members");
    for (i, name) in ["door", "fresh", "shape", "node", "board"].iter().enumerate() {
        let mut moved = p.fields.clone();
        let mut bytes = std::mem::take(&mut moved[i]).into_bytes();
        let last = bytes.len() - 1;
        bytes[last] = if bytes[last] == b'1' { b'2' } else { b'1' };
        moved[i] = String::from_utf8(bytes).unwrap();
        assert!(!verifies(&key, &moved, &signature), "`{name}` altered by one byte still verifies");
    }
    assert!(!verifies(&key, &p.fields[..4], &signature), "the frame without `board` is another frame");
    assert!(skep_signature::verify(key.sig_alg_row().tag, &key, request.body.as_bytes(), &signature).is_err(), "the signature is over the frame, never the body's bytes");
    for anchors in [&request.board_pair, &request.node_pair] {
        for anchor in anchors.iter() {
            assert!(!verifies(&anchor.public, &p.fields, &signature), "no anchor signed: the one signature is the device key's");
        }
    }

    // The scannable form (AUTH-5.57 step 3), said once the body is handed
    // out: its fingerprints, as a set, are the thread's key.
    let thread = thread_key(p.node.iter().chain(board.iter()));
    assert_eq!(thread.len(), 5, "five keys: the device key counted once");
    assert_eq!(request.thread_key, thread);
    let mut carried = Scripted::new(vec![]);
    say_request(&mut carried, &request);
    let lines: Vec<&String> = carried.transcript.iter().filter(|l| l.starts_with("PUBLIC say [AUTH-5.57 step 3]: ") && l.contains(" — `")).collect();
    assert_eq!(lines.len(), 5, "one line a key:\n{}", carried.transcript.join("\n"));
    let mut printed = BTreeSet::new();
    for (line, k) in lines.iter().zip(&request.keys) {
        let (head, grouped) = line.split_once("\n  ").expect("the label's line, then the grouped fingerprint");
        assert!(head.ends_with(&format!("{} — `{}`", k.named, k.label)), "{head}");
        assert_eq!(grouped.replace("\n  ", "\n"), group_hex(&k.fingerprint.to_hex()), "R42's grouping, beside its label");
        printed.insert(Fingerprint::parse_hex(&grouped.split_whitespace().collect::<String>()).expect("64 hex"));
    }
    assert_eq!(printed, thread.iter().copied().collect::<BTreeSet<_>>(), "the fingerprints the form prints are the thread's key");
    let labels: Vec<Option<&str>> = p.node.iter().chain(board.iter()).map(|e| e.label()).collect();
    assert!(request.keys.iter().all(|k| labels.contains(&Some(k.label.as_str()))), "each label is the one its enrolment carries");
    let keyed = carried.transcript.iter().find(|l| l.contains("[REG-4.78]")).expect("the thread's key, said");
    assert_eq!(keyed.lines().skip(1).map(str::trim).collect::<Vec<_>>(), thread.iter().map(Fingerprint::to_hex).collect::<Vec<_>>(), "ascending, each once");
    let disposition = carried.transcript.last().expect("the disposition, last");
    assert!(disposition.contains(&format!("THIS REQUEST IS FOR ONE DOOR, `{DOOR}`, and serves that door alone")), "{disposition}");
    assert!(disposition.contains("these sheets belong to THIS application") && disposition.contains("destroy them, all four, both pairs, and generate fresh ones for any other door"), "{disposition}");
}

/// FENCE 5 (REG-4.104; REG-4.204) — THE SHAPE READS THE KIND: a registration
/// whose board carries on asks two anchor boxes and no device box, makes two
/// sheets, generates no device key — the store's own is named, and said as
/// unchecked — and its body is the board-carries-on row's: no `board`
/// member, `shape` `3.54.1.2`, a four-field frame that verifies; a fresh one
/// is `shape` `3.54.1.1` with `board` present and five fields (the test
/// above).
#[test]
fn a_board_that_carries_on_makes_the_node_pair_alone_and_names_the_stores_key() {
    let dir = tempfile::tempdir().unwrap();
    let (store, places) = (FileStore::open(dir.path().join("store")), dir.path().join("sheets"));
    let held = keygen(&store, "board laptop");
    let before = files_in(&dir.path().join("store").join("keys"));
    let mut person = Scripted::new(vec![Script::LabelDefault, Script::LabelDefault]);
    let request = composed(&mut person, &store, &options(true, &places));
    let asked: Vec<&String> = person.transcript.iter().filter(|l| l.starts_with("PUBLIC label [")).collect();
    assert_eq!(asked.len(), 2, "two anchor boxes, and the device's box a naming:\n{}", person.transcript.join("\n"));
    assert!(asked.iter().all(|b| b.contains("the node pair's sheet")), "{asked:?}");
    let naming = person.transcript.iter().find(|l| l.contains("THE DEVICE KEY IS NAMED HERE, never generated")).expect("the device key named at its box");
    assert!(naming.contains(&format!("`board laptop`, fingerprint {held}")), "{naming}");
    assert!(naming.contains("TAKEN AS the device key your board's own key set already holds — UNCHECKED: this command reads no board"), "said as unchecked: {naming}");
    assert!(person.transcript.iter().position(|l| l.contains("THE DEVICE KEY IS NAMED HERE")) < person.transcript.iter().position(|l| l.contains("[AUTH-5.54 (a)]")), "at its box, ahead of the moment");
    // No device key generated: the store as it was.
    assert_eq!(files_in(&dir.path().join("store").join("keys")), before, "the key store holds what it held");
    assert_eq!(store.device_keys().unwrap().iter().map(|k| k.fingerprint).collect::<Vec<_>>(), vec![held]);
    assert_eq!((request.device.fingerprint, request.device.generated, request.device.label.as_str()), (held, false, "board laptop"));
    assert!(!person.said("key file written: "), "nothing written into the store");
    // Two sheets.
    assert_eq!(files_in(&places.join("0")).len() + files_in(&places.join("1")).len(), 2);
    assert!(!places.join("2").exists() && request.board_pair.is_empty() && request.node_pair.len() == 2);

    assert_eq!(request.kind, RegistrationKind::BoardCarriesOn);
    assert!(request.body.starts_with("{\"type\":\"board-carries-on\",") && !request.body.contains("\"board\":"), "{}", &request.body[..90]);
    assert_eq!(parse_registration(RegistrationKind::Fresh, request.body.as_bytes()).map(|_| ()), Err(ParseRefusal::WrongType));
    let p = parsed(RegistrationKind::BoardCarriesOn, &request.body);
    assert_eq!((p.shape.as_str(), &p.board, &p.board_text), ("3.54.1.2", &None, &None));
    assert_eq!(p.shape, RegistrationKind::BoardCarriesOn.row().ordinal_path());
    assert_eq!(p.fields, vec![p.door.clone(), p.fresh.clone(), p.shape.clone(), p.node_text.clone()], "four fields: `board` left out of the frame as of the body");
    let key = enrolled_signer(&Fingerprint::parse_hex(&p.signer).unwrap(), &[&p.node]).expect("the node enrolment enrols the signer").clone();
    assert_eq!(Fingerprint::of(&key), held);
    let signature = unhex(&p.signature);
    assert!(verifies(&key, &p.fields, &signature), "the four-field frame verifies");
    let mut five = p.fields.clone();
    five.push(String::new());
    assert!(!verifies(&key, &five, &signature), "and no five-field frame does: an empty `board` is a fifth field");
    let sheets = [sheet(&places, 0), sheet(&places, 1)];
    let entries: Vec<(Fingerprint, bool)> = p.node.iter().map(|e| (Fingerprint::of(&e.key), e.anchor)).collect();
    assert_eq!(entries, vec![(sheets[0].fingerprint, true), (sheets[1].fingerprint, true), (held, false)], "the node pair and the board's device key");
    assert_eq!(request.thread_key.len(), 3);
    let mut carried = Scripted::new(vec![]);
    say_request(&mut carried, &request);
    let disposition = carried.transcript.last().unwrap();
    assert!(disposition.contains("destroy them, the two NODE sheets this run made, and those alone") && disposition.contains("never destroy them for it"), "the org root's own sheets are no paper of this application (REG-4.101): {disposition}");
}

/// FENCE 7 (REG-4.84) — THE FRESHNESS VALUE IS THIS CLIENT'S OWN
/// ENTROPY: two runs from one store, at one door, give two different `fresh`
/// values, each 64 lowercase hex — and so two different signatures over two
/// different frames.
#[test]
fn two_runs_give_two_freshness_values_each_64_lowercase_hex() {
    let dir = tempfile::tempdir().unwrap();
    let store = FileStore::open(dir.path().join("store"));
    keygen(&store, "board laptop");
    let run = |n: usize| {
        let mut person = Scripted::new(vec![Script::LabelDefault, Script::LabelDefault]);
        let request = composed(&mut person, &store, &options(true, &dir.path().join(format!("run-{n}"))));
        let p = parsed(RegistrationKind::BoardCarriesOn, &request.body);
        assert_eq!(p.fresh, request.fresh.as_str());
        (p.fresh, p.signature)
    };
    let (first, second) = (run(1), run(2));
    for fresh in [&first.0, &second.0] {
        assert!(fresh.len() == 64 && fresh.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)), "64 lowercase hex: {fresh}");
        assert!(Freshness::parse(fresh).is_some());
        assert_ne!(*fresh, "0".repeat(64));
    }
    assert_ne!(first.0, second.0, "two runs, two values");
    assert_ne!(first.1, second.1);
}

/// FENCE 10 (REG-4.102, REG-4.104) — A DEVICE KEY THE STORE HOLDS IS
/// NAMED AND NONE IS GENERATED BESIDE IT: a fresh registration over a store
/// holding one device key asks four anchor boxes and no device box, names
/// the key at its box, leaves the store holding exactly that key, and both
/// enrolments carry it. And a registration whose board carries on, over a
/// store holding none, halts before any box: nothing asked, no anchor file,
/// no key.
#[test]
fn a_held_device_key_is_named_and_none_generated_and_none_held_halts_a_board_that_carries_on() {
    let dir = tempfile::tempdir().unwrap();
    let (store, places) = (FileStore::open(dir.path().join("store")), dir.path().join("sheets"));
    let held = keygen(&store, "the one laptop");
    let mut person = Scripted::new(vec![Script::LabelDefault; 4]);
    let request = composed(&mut person, &store, &options(false, &places));
    let asked = person.transcript.iter().filter(|l| l.starts_with("PUBLIC label [")).count();
    assert_eq!(asked, 4, "four anchor boxes and no device box:\n{}", person.transcript.join("\n"));
    assert!(!person.said("name this device"));
    let naming = person.transcript.iter().find(|l| l.contains("THE DEVICE KEY IS NAMED HERE, never generated")).expect("named at its box");
    assert!(naming.contains(&format!("`the one laptop`, fingerprint {held}")) && naming.contains("It goes into BOTH key sets this request founds"), "{naming}");
    assert!(!naming.contains("UNCHECKED"), "a fresh registration takes no board's set on trust: {naming}");
    assert_eq!(store.device_keys().unwrap().iter().map(|k| k.fingerprint).collect::<Vec<_>>(), vec![held], "the store still holds exactly that one key");
    assert!(!request.device.generated && !person.said("key file written: "));
    let p = parsed(RegistrationKind::Fresh, &request.body);
    let board = p.board.expect("the board root's enrolment");
    for enrolment in [&p.node, &board] {
        let devices: Vec<Fingerprint> = enrolment.iter().filter(|e| !e.anchor).map(|e| Fingerprint::of(&e.key)).collect();
        assert_eq!(devices, vec![held], "both enrolments carry the held key, and no other device key");
        assert_eq!(enrolment[2].label(), Some("the one laptop"));
    }
    assert_eq!(p.signer, held.to_hex());

    // The board carries on and the store holds none: before any box.
    let dir = tempfile::tempdir().unwrap();
    let (store, places) = (FileStore::open(dir.path().join("store")), dir.path().join("sheets"));
    let mut opts = options(true, &places);
    opts.anchor_labels = vec!["node a".into(), "node b".into()];
    let mut person = Scripted::new(vec![]);
    let halt = registration_request(&mut person, &store, &opts).expect_err("no device key to name");
    let text = halt.to_string();
    assert!(text.contains("the key store holds no device key, and a registration whose board carries on names one and generates none"), "{text}");
    assert!(text.contains("run this from the store that holds your board's device key"), "{text}");
    assert!(person.transcript.is_empty(), "nothing asked and nothing said: {:?}", person.transcript);
    assert!(!places.exists(), "no anchor file");
    assert!(!dir.path().join("store").exists(), "no key, and no store made");
}

/// REG-4.74; P13 — THE DOOR IS JUDGED FIRST: an identifier `DoorId::parse`
/// refuses — a second space, upper-case hex, a missing term, a term twice,
/// an address not its own rendering — halts naming the one spelling before
/// anything is asked, generated or written, with every label and
/// destination fixed so that a moment run ahead of the judgment would ask
/// nothing and write four files; a forked lineage's identifier is admitted.
#[test]
fn a_door_identifier_that_is_none_halts_before_anything_is_asked_or_written() {
    let realm = "9f2a00000000000000000000000000000000000000000000000000000000c41d";
    let refused = [
        format!("realm:{realm}  door:1.1.0.1"),
        format!("realm:{} door:1.1.0.1", realm.to_uppercase()),
        format!("realm:{realm}"),
        "door:1.1.0.1".to_string(),
        format!("realm:{realm} door:1.1.0.1 door:1.1.0.1"),
        format!("realm:{realm} door:01.1.0.1"),
        format!(" realm:{realm} door:1.1.0.1"),
        format!("realm:{} door:1.1.0.1", &realm[..62]),
        "https://registry.example".to_string(),
    ];
    for door in refused {
        let dir = tempfile::tempdir().unwrap();
        let (store, places) = (FileStore::open(dir.path().join("store")), dir.path().join("sheets"));
        let mut opts = options(false, &places);
        opts.door = door.clone();
        opts.label = Some("laptop".into());
        opts.anchor_labels = ["ra", "rb", "na", "nb"].map(String::from).to_vec();
        let mut person = Scripted::new(vec![]);
        let halt = registration_request(&mut person, &store, &opts).expect_err("no door identifier");
        let text = halt.to_string();
        assert!(text.contains("is not a door identifier") && text.contains("`realm:<64 lowercase hex> door:<address>`"), "`{door}`: {text}");
        assert!(person.transcript.is_empty(), "`{door}`: nothing asked or said: {:?}", person.transcript);
        assert!(!places.exists() && !dir.path().join("store").exists(), "`{door}`: nothing written");
    }
    // A forked lineage's identifier is one, and rides the body as given.
    let dir = tempfile::tempdir().unwrap();
    let store = FileStore::open(dir.path().join("store"));
    keygen(&store, "board laptop");
    let forked = format!("realm:{realm} fork:1.1.0.1.0.7.0.2.3 door:1.1.0.1");
    let mut opts = options(true, &dir.path().join("sheets"));
    opts.door = forked.clone();
    let mut person = Scripted::new(vec![Script::LabelDefault, Script::LabelDefault]);
    let request = composed(&mut person, &store, &opts);
    assert_eq!(parsed(RegistrationKind::BoardCarriesOn, &request.body).door, forked);
    assert!(request.door.fork.is_some());
}

/// The refusals ahead of the first box (P13; REG-4.102; AUTH-5.42): a flag's
/// label outside the domain; more labels than the kind's anchors; `--label`
/// beside a key that is named, on either kind; more than one device key with
/// none named — the selection face, each listed, never a pick — and that
/// same store with one named by its file; and a named key that carries no
/// label. Each asks nothing, writes no anchor file and generates no key.
#[test]
fn every_refusal_of_the_device_key_and_the_labels_comes_ahead_of_the_first_box() {
    let refused = |store: &FileStore, opts: &RegistrationOptions| -> String {
        let keys_before = store.device_keys().unwrap().len();
        let mut person = Scripted::new(vec![]);
        let halt = registration_request(&mut person, store, opts).expect_err("refused");
        assert!(person.transcript.is_empty(), "nothing asked or said: {:?}", person.transcript);
        assert!(opts.anchor_out.iter().all(|p| !p.exists()), "no anchor file");
        assert_eq!(store.device_keys().unwrap().len(), keys_before, "no key generated");
        halt.to_string()
    };
    let dir = tempfile::tempdir().unwrap();
    let places = dir.path().join("sheets");
    let empty = FileStore::open(dir.path().join("empty"));
    // A flag's label outside AUTH-1.24's domain, an anchor's and the device's.
    let mut opts = options(false, &places);
    opts.anchor_labels = vec!["x".repeat(129)];
    assert!(refused(&empty, &opts).contains("an anchor label is refused at the box"));
    let mut opts = options(false, &places);
    opts.label = Some("two\nlines".into());
    assert!(refused(&empty, &opts).contains("the label is refused at the box"));
    // More labels, or more destinations, than the kind's anchors.
    let mut opts = options(true, &places);
    opts.anchor_labels = ["ra", "rb", "na"].map(String::from).to_vec();
    let text = refused(&empty, &opts);
    assert!(text.contains("`--anchor-label` is given 3 times, and this registration makes 2 anchors"), "{text}");
    let mut opts = options(false, &places);
    opts.anchor_out = (0..5).map(|i| places.join(i.to_string())).collect();
    assert!(refused(&empty, &opts).contains("`--anchor-out` is given 5 times, and this registration makes 4 anchors"));

    // `--label` beside a named key: refused, never dropped.
    let one = FileStore::open(dir.path().join("one"));
    let held = keygen(&one, "laptop");
    for board_carries_on in [false, true] {
        let mut opts = options(board_carries_on, &places);
        opts.label = Some("another name".into());
        let text = refused(&one, &opts);
        assert!(text.contains(&format!("`--label` names a device key to generate, and this registration generates none: its device key is `laptop` ({held})")), "{text}");
        assert!(text.contains("run it again without `--label`"), "{text}");
    }

    // More than one device key, none named: the selection face.
    let two = FileStore::open(dir.path().join("two"));
    let (first, second) = (keygen(&two, "laptop"), keygen(&two, "phone"));
    for board_carries_on in [false, true] {
        let text = refused(&two, &options(board_carries_on, &places));
        assert!(text.contains("more than one device key is in this store, and a registration is signed by ONE"), "{text}");
        assert!(text.contains(&format!("{first} laptop")) && text.contains(&format!("{second} phone")), "each listed: {text}");
        assert!(text.contains("name the key with `--key <path>`") && text.contains("never a pick"), "{text}");
    }
    // …and with one named by its file, that key signs and none is generated.
    let mut opts = options(true, &places);
    opts.key_file = Some(two.key_path(&second));
    let mut person = Scripted::new(vec![Script::LabelDefault, Script::LabelDefault]);
    let request = composed(&mut person, &two, &opts);
    assert_eq!((request.device.fingerprint, request.device.generated), (second, false));
    assert_eq!(parsed(RegistrationKind::BoardCarriesOn, &request.body).signer, second.to_hex());
    assert_eq!(two.device_keys().unwrap().len(), 2);

    // A named key that carries no label: faced, never sent.
    let bare = FileStore::open(dir.path().join("bare"));
    let unlabelled = {
        use skep_client::store::KeyStore;
        bare.generate(None).expect("generate").0
    };
    let text = refused(&bare, &options(false, &dir.path().join("bare-sheets")));
    assert!(text.contains(&format!("the device key {unlabelled} carries NO label, and a registration never sends an empty byline")), "{text}");
}

/// A run stopped at its moment says what it leaves (AUTH-5.57 step 2), and
/// the device key, generated after the moment, is not in the store: a
/// destination inside the key store stops a fresh registration from an empty
/// store at its first export — the halt the moment's own, the disposition
/// said ahead of it — with no key generated, so the corrected run stands no
/// second device key beside one.
#[test]
fn a_run_stopped_at_its_moment_says_what_it_leaves_and_generates_no_device_key() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("store");
    let store = FileStore::open(&root);
    let mut opts = options(false, &dir.path().join("sheets"));
    opts.label = Some("laptop".into());
    opts.anchor_out = vec![root.join("a"), root.join("b"), root.join("c"), root.join("d")];
    let mut person = Scripted::new(vec![Script::LabelDefault; 4]);
    let halt = registration_request(&mut person, &store, &opts).expect_err("the moment stops");
    assert!(halt.to_string().contains("lies inside the key store"), "{halt}");
    let left = person.transcript.last().expect("the disposition, said ahead of the halt");
    assert!(left.starts_with("PUBLIC say [AUTH-5.57 step 2]: this registration stops before its request, and nothing was sent anywhere"), "{left}");
    assert!(left.contains("it leaves no board state behind") && left.contains("names no account and opens nothing, ever"), "{left}");
    assert!(left.contains("nothing of this run is in the key store: its device key is generated after the moment"), "{left}");
    assert!(store.device_keys().unwrap().is_empty() && !root.join("keys").exists(), "no device key left behind");
    assert!(!root.join("a").exists(), "and nothing written under the store");
}
