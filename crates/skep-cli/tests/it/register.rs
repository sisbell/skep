//! The twenty-first command through the binary (`skep register`; REG-4.67),
//! and `skep keygen --anchors` unchanged beside it.
//!
//! The composition itself is the library's, fenced under the scripted
//! person in `skep-client`'s `tests/it/registration.rs` and
//! `tests/it/backup.rs`; here, what the command adds, with no daemon
//! anywhere — the command reads no board: its line read ahead of its door,
//! the door refused without a controlling terminal, a door identifier that
//! is none halting before anything is asked or written, and then the runs
//! under a pseudo-terminal — a fresh registration typed as a person types
//! it, from an empty store to the request on stdout, which is verified here
//! as a reader verifies it; a board that carries on, over the store's own
//! key and over a store that holds none; and the hosted signup's door-side
//! form, `skep keygen --anchors`, with its three-key payload, its one-door
//! line and its order as they were.

use std::path::{Path, PathBuf};

use skep_client::sheet::{group_hex, KeyFile};
use skep_client::store::FileStore;
use skep_identity::{enrolled_signer, framed, parse_enroll, thread_key, DoorId, Enrollment, Fingerprint, Freshness, REGISTRATION_TAG};
use skep_registry::{parse_registration, RegistrationKind};

use crate::common::{s, skep, tree};

/// A door identifier in its one spelling.
const DOOR: &str = "realm:9f2a00000000000000000000000000000000000000000000000000000000c41d door:1.1.0.1";

/// The files under `dir`, by path; empty where it does not stand.
fn files_in(dir: &Path) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir).map(|entries| entries.filter_map(Result::ok).map(|e| e.path()).collect()).unwrap_or_default();
    files.sort();
    files
}

/// The one anchor file under `dir`, parsed.
fn sheet(dir: &Path) -> KeyFile {
    let files = files_in(dir);
    assert_eq!(files.len(), 1, "one anchor file under {}", dir.display());
    KeyFile::parse(&std::fs::read(&files[0]).unwrap()).expect("an anchor file")
}

/// A printed request, verified as a reader verifies it (REG-4.95 step 2):
/// one line; a canonical record under `kind`'s row with no `sig`; the door
/// and the freshness value in their forms and `shape` the row's own address;
/// every enrolment enrolling the `signer`; and the one signature verifying
/// over the frame re-built from the members as written. Answers the node
/// enrolment, the board root's where the request carries one, and the
/// signer.
fn verified(kind: RegistrationKind, printed: &str) -> (Vec<Enrollment>, Option<Vec<Enrollment>>, Fingerprint) {
    let line = printed.strip_suffix('\n').expect("the request ends its line");
    assert!(!line.contains('\n') && !line.contains('\r'), "ONE line on standard output");
    let record = parse_registration(kind, line.as_bytes()).unwrap_or_else(|e| panic!("the printed bytes are a canonical record under their row: {e:?}"));
    assert_eq!(record.sig, None, "no `sig`: the writing hand's, never the applicant's");
    let m = record.body.request().expect("a request");
    assert!(DoorId::parse(m.door).is_some() && Freshness::parse(m.fresh.as_str()).is_some());
    assert_eq!(m.shape, kind.row().ordinal_path());
    let node = parse_enroll(m.node.as_bytes()).expect("the node enrolment");
    let board = m.board.map(|b| parse_enroll(b.as_bytes()).expect("the board enrolment"));
    let signer = Fingerprint::parse_hex(m.signer.as_str()).expect("a fingerprint");
    let enrolments: Vec<&[Enrollment]> = std::iter::once(node.as_slice()).chain(board.as_deref()).collect();
    let key = enrolled_signer(&signer, &enrolments).expect("every enrolment present enrols the signer");
    let signature: Vec<u8> = (0..m.signature.as_str().len()).step_by(2).map(|i| u8::from_str_radix(&m.signature.as_str()[i..i + 2], 16).expect("hex")).collect();
    let fields = m.frame_fields();
    let frame = framed(REGISTRATION_TAG, &fields.iter().map(|f| f.as_bytes()).collect::<Vec<_>>());
    assert_eq!(skep_signature::verify(key.sig_alg_row().tag, key, &frame, &signature), Ok(()), "the signature verifies over the frame re-built from the printed members");
    let mut moved = fields.iter().map(|f| f.to_string()).collect::<Vec<_>>();
    moved[1] = "0".repeat(64);
    let other = framed(REGISTRATION_TAG, &moved.iter().map(|f| f.as_bytes()).collect::<Vec<_>>());
    assert!(skep_signature::verify(key.sig_alg_row().tag, key, &other, &signature).is_err(), "and under no other freshness value");
    (node, board, signer)
}

/// THE LINE IS READ AHEAD OF THE DOOR (§2.3's exit 2): `register` without
/// `--door`, with a fifth anchor's label, with a third inside
/// `--existing-board`, and with an `--out` the command does not have, each
/// names what is wrong before any terminal check and before anything is
/// generated; and the help lists the command, its flags and their order.
#[test]
fn registers_line_is_read_ahead_of_its_door_and_the_help_names_it() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("store");
    let base = ["register", "--dir", s(&store)];
    fn joined<'a>(base: &[&'a str], more: &[&'a str]) -> Vec<&'a str> {
        [base, more].concat()
    }
    for (args, refusal) in [
        (joined(&base, &[]), "--door <identifier> is required: the door this request is for, one quoted string as the registry publishes it"),
        (joined(&base, &["--existing-board"]), "--door <identifier> is required"),
        (joined(&base, &["--door", DOOR, "--anchor-label", "1", "--anchor-label", "2", "--anchor-label", "3", "--anchor-label", "4", "--anchor-label", "5"]), "`--anchor-label` is given at most 4 times at `register`"),
        (joined(&base, &["--door", DOOR, "--existing-board", "--anchor-out", "/a", "--anchor-out", "/b", "--anchor-out", "/c"]), "`--anchor-out` is given at most 2 times at `register --existing-board`"),
        (joined(&base, &["--door", DOOR, "--out", "/request.json"]), "unknown argument `--out`"),
        (joined(&base, &["--door", DOOR, "--door", DOOR]), "`--door` is given at most once at `register`"),
    ] {
        let r = skep(&args, &[], None);
        assert_eq!(r.code, 2, "{args:?}: {r:?}");
        assert!(r.err.contains(refusal), "{args:?}: {}", r.err);
        assert!(!r.err.contains("controlling terminal"), "ahead of the door: {}", r.err);
        assert!(r.out.is_empty(), "{}", r.out);
    }
    assert!(!store.exists(), "nothing generated");
    let help = skep(&["--help"], &[], None);
    assert_eq!(help.code, 0);
    assert!(help.out.contains("\n  register     ask a registry for your org's place in it (a person door):"), "{}", help.out);
    assert!(help.out.contains("\n  register: --door <identifier> (one quoted string, as the door"), "{}", help.out);
    assert!(help.out.contains("node a, node b; with --existing-board two, node a and node b)"), "the flags' order: {}", help.out);
}

/// THE DOOR (§2.4): without a controlling terminal `register` is exit 3, a
/// halt's face naming the moments a person answers at this door — the
/// backup moment among them, which this door runs — at both kinds, and
/// nothing is generated: no key, no anchor file.
#[test]
fn register_is_a_person_door_and_refuses_without_a_terminal() {
    let dir = tempfile::tempdir().unwrap();
    let (store, sheets) = (dir.path().join("store"), dir.path().join("sheets"));
    for kind in [&[][..], &["--existing-board"]] {
        let args = [&["register", "--door", DOOR, "--dir", s(&store), "--label", "laptop", "--anchor-out", s(&sheets), "--anchor-out", s(&sheets)][..], kind].concat();
        let r = skep(&args, &[], None);
        assert_eq!(r.code, 3, "{args:?}: {r:?}");
        assert!(r.err.contains("`register` is a person door and requires a controlling terminal"), "{}", r.err);
        assert!(r.err.contains("\n  cause: what a person answers here — the name boxes and the backup moment —"), "the door's own moments: {}", r.err);
        assert!(r.err.contains("\n  act: run it at a terminal"), "{}", r.err);
        assert!(r.out.is_empty(), "{}", r.out);
    }
    assert!(!store.exists() && !sheets.exists(), "nothing generated before the check");
}

/// One run of `register` under a pseudo-terminal, its stdout a file:
/// `flags` after the verb and the store, `typed` the answers a person
/// types. Answers the exit code, stdout, and what the terminal showed.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn at_a_terminal(dir: &Path, store: &Path, flags: &[&str], typed: &str) -> (i32, String, String) {
    use crate::common::{on_a_terminal_typing, shell_word};

    let (out, code) = (dir.join("stdout"), dir.join("code"));
    let _ = std::fs::remove_file(&out);
    let _ = std::fs::remove_file(&code);
    let flags: Vec<String> = flags.iter().map(|f| shell_word(f)).collect();
    let command = format!("{} register --dir {} {} > {}; echo $? > {}", shell_word(env!("CARGO_BIN_EXE_skep")), shell_word(s(store)), flags.join(" "), shell_word(s(&out)), shell_word(s(&code)));
    let seen = on_a_terminal_typing(&command, typed, &code);
    let exit = std::fs::read_to_string(&code).unwrap_or_else(|e| panic!("the run's exit code: {e}: {seen}"));
    (exit.trim().parse().unwrap(), std::fs::read_to_string(&out).unwrap_or_default(), seen)
}

/// FENCE 6 (REG-4.74; P13) — THE DOOR IDENTIFIER IS JUDGED FIRST: at a terminal,
/// with the device's label, all four anchors' labels and all four
/// destinations fixed by flags — so a moment run ahead of the judgment would
/// ask nothing and write every file — an identifier `DoorId::parse` refuses
/// (a second space, upper-case hex, a missing term) halts, exit 3, naming
/// the one spelling: no anchor file under any `--anchor-out`, no key in the
/// store, nothing on stdout.
#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn a_door_identifier_that_is_none_halts_at_a_terminal_before_any_file_or_key() {
    let realm = "9f2a00000000000000000000000000000000000000000000000000000000c41d";
    for (door, what) in [
        (format!("realm:{realm}  door:1.1.0.1"), "a second space"),
        (format!("realm:{} door:1.1.0.1", realm.to_uppercase()), "upper-case hex"),
        (format!("realm:{realm}"), "a missing term"),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let store = dir.path().join("store");
        let places: Vec<PathBuf> = (0..4).map(|i| dir.path().join(format!("place-{i}"))).collect();
        let mut flags = vec!["--door", door.as_str(), "--label", "laptop"];
        for label in ["ra", "rb", "na", "nb"] {
            flags.extend(["--anchor-label", label]);
        }
        for place in &places {
            flags.extend(["--anchor-out", s(place)]);
        }
        let (exit, out, seen) = at_a_terminal(dir.path(), &store, &flags, "");
        assert_eq!(exit, 3, "{what}: {seen}");
        assert!(!seen.contains("requires a controlling terminal"), "past the door: {seen}");
        assert!(seen.contains("is not a door identifier") && seen.contains("`realm:<64 lowercase hex> door:<address>`"), "{what}: the command's refusal of the identifier: {seen}");
        assert!(seen.contains("refused before anything is asked, generated or written"), "{what}: {seen}");
        assert!(!seen.contains("AUTH-5.54") && !seen.contains("anchor file written"), "{what}: no moment ran: {seen}");
        assert!(places.iter().all(|p| !p.exists()), "{what}: no anchor file in any --anchor-out directory");
        assert!(tree(&store).is_empty(), "{what}: no key in the store: {:?}", tree(&store).keys().collect::<Vec<_>>());
        assert!(out.is_empty(), "{what}: nothing printed: {out}");
    }
}

/// FENCE 9 — ONE FRESH REGISTRATION, TYPED AT A TERMINAL, FROM AN EMPTY
/// STORE: the device's box answered, the four anchor boxes taken at their
/// defaults, and the run ends exit 0 with the request the one line on
/// stdout — verified here over the printed bytes as a reader verifies it,
/// its enrolments the two pairs' files and the one device key the store now
/// holds, each under its box's label. Four anchor files stand, one sheet of
/// each pair to a place; the terminal shows each key's label beside its
/// grouped fingerprint, after the request, and the line that the request
/// serves its one door and its sheets belong to this one application
/// (AUTH-5.57 steps 3 and 4).
#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn a_fresh_registration_typed_at_a_terminal_prints_a_request_that_verifies() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("store");
    let (one, two) = (dir.path().join("one"), dir.path().join("two"));
    let places = [one.join("root"), two.join("root"), one.join("node"), two.join("node")];
    let mut flags = vec!["--door", DOOR];
    for place in &places {
        flags.extend(["--anchor-out", s(place)]);
    }
    // The device's box, then the four anchor boxes at their defaults.
    let (exit, out, seen) = at_a_terminal(dir.path(), &store, &flags, "laptop\n\n\n\n\n");
    assert_eq!(exit, 0, "the registration ran to its end:\n{seen}");
    assert!(!seen.contains("requires a controlling terminal"), "{seen}");
    let (node, board, signer) = verified(RegistrationKind::Fresh, &out);
    let board = board.expect("a fresh request carries the board root's enrolment");
    assert!(out.starts_with("{\"type\":\"fresh\",\"door\":\"realm:9f2a") && out.contains("\"shape\":\"3.54.1.1\""), "{}", &out[..120]);

    // The store holds exactly one device key: the one that signed.
    let device = FileStore::open(&store).device_keys().unwrap();
    assert_eq!(device.len(), 1, "one device key");
    assert_eq!((device[0].fingerprint, device[0].label.as_deref()), (signer, Some("laptop")));
    // Four anchor files stand, each the entry its enrolment carries.
    let sheets: Vec<KeyFile> = places.iter().map(|p| sheet(p)).collect();
    let entry = |e: &Enrollment| (Fingerprint::of(&e.key), e.anchor, e.label().map(str::to_string));
    let anchor = |f: &KeyFile| (f.fingerprint, true, f.label.clone());
    let device_entry = (signer, false, Some("laptop".to_string()));
    assert_eq!(board.iter().map(entry).collect::<Vec<_>>(), vec![anchor(&sheets[0]), anchor(&sheets[1]), device_entry.clone()]);
    assert_eq!(node.iter().map(entry).collect::<Vec<_>>(), vec![anchor(&sheets[2]), anchor(&sheets[3]), device_entry]);
    for (file, tail) in sheets.iter().zip(["-org-root-sheet-a", "-org-root-sheet-b", "-node-identity-sheet-a", "-node-identity-sheet-b"]) {
        assert!(file.label.as_deref().is_some_and(|l| l.ends_with(tail)), "the box's default names the pair and the sheet: {:?}", file.label);
    }

    // What the terminal showed: five boxes; the request's place; each key's
    // label beside its grouped fingerprint; the thread's key; the
    // disposition.
    for said in ["name this device", "name the org root pair's sheet a", "name the org root pair's sheet b", "name the node pair's sheet a", "name the node pair's sheet b"] {
        assert!(seen.contains(said), "{said}:\n{seen}");
    }
    for said in ["[AUTH-5.54 (a)]", "(b) FOUR FILES, TWO PLACES YOU CONTROL", "[REG-4.103] THE FILING RULE IS CROSS-PAIR", "[REG-4.103] THE FILING RULE AGAIN", "[AUTH-5.44 (create-org)] keep the anchor files — all four", "[§3a] key file written: "] {
        assert!(seen.contains(said), "{said}:\n{seen}");
    }
    assert!(!seen.contains("are in this one place"), "one sheet of each pair to a place is the rule followed:\n{seen}");
    assert!(seen.contains(&format!("the request is the ONE LINE on standard output, {} bytes", out.len() - 1)), "{seen}");
    let lines = |text: &str| text.replace('\n', "\r\n");
    let keys = [("org root pair, sheet a", &sheets[0]), ("org root pair, sheet b", &sheets[1]), ("node pair, sheet a", &sheets[2]), ("node pair, sheet b", &sheets[3])];
    let mut shown: Vec<(String, String, Fingerprint)> = keys.iter().map(|(named, f)| (named.to_string(), f.label.clone().unwrap(), f.fingerprint)).collect();
    shown.push(("device key, in both key sets".into(), "laptop".into(), signer));
    let request_said = seen.find("the request is the ONE LINE on standard output").expect("said");
    for (named, label, fingerprint) in &shown {
        let block = lines(&format!("[AUTH-5.57 step 3] {named} — `{label}`\n  {}\n", group_hex(&fingerprint.to_hex()).replace('\n', "\n  ")));
        let at = seen.find(&block).unwrap_or_else(|| panic!("`{label}` beside its grouped fingerprint:\n{seen}"));
        assert!(at > request_said, "the scannable form stands under the request");
    }
    let thread = thread_key(node.iter().chain(board.iter()));
    assert_eq!(thread.len(), 5);
    let keyed = lines(&format!("these 5 fingerprints, in this order:\n  {}\n", thread.iter().map(Fingerprint::to_hex).collect::<Vec<_>>().join("\n  ")));
    assert!(seen.contains(&keyed), "the thread's key, ascending:\n{seen}");
    assert!(seen.contains(&format!("[AUTH-5.57 step 4] THIS REQUEST IS FOR ONE DOOR, `{DOOR}`, and serves that door alone")), "{seen}");
    assert!(seen.contains("these sheets belong to THIS application") && seen.contains("destroy them, all four, both pairs, and generate fresh ones for any other door"), "the disposition:\n{seen}");
}

/// FENCES 5 AND 10 THROUGH THE BINARY (REG-4.102, REG-4.104) — THE BOARD THAT
/// CARRIES ON: over a store holding one device key, `register
/// --existing-board` asks two anchor boxes, names that key and says it is
/// taken unchecked, and prints the board-carries-on row's request — no
/// `board` member, `shape` `3.54.1.2`, signed by the store's own key, which
/// stands alone in a store left as it was. A second run from that store, at
/// a fresh registration, names the same key and generates none. And over a
/// store that holds none, `--existing-board` halts before anything is asked
/// or written.
#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn a_board_that_carries_on_names_the_stores_key_and_halts_where_it_holds_none() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("store");
    assert_eq!(skep(&["keygen", "--label", "board laptop", "--dir", s(&store)], &[], None).code, 0);
    let held = FileStore::open(&store).device_keys().unwrap()[0].fingerprint;
    let before = tree(&store);
    let places = [dir.path().join("one"), dir.path().join("two")];
    let (exit, out, seen) = at_a_terminal(dir.path(), &store, &["--door", DOOR, "--existing-board", "--anchor-out", s(&places[0]), "--anchor-out", s(&places[1])], "\n\n");
    assert_eq!(exit, 0, "{seen}");
    let (node, board, signer) = verified(RegistrationKind::BoardCarriesOn, &out);
    assert!(board.is_none() && !out.contains("\"board\":") && out.contains("\"shape\":\"3.54.1.2\""), "{}", &out[..120]);
    assert_eq!(signer, held, "signed by the store's own key");
    assert_eq!(tree(&store), before, "no device key generated: the store as it was");
    let sheets = [sheet(&places[0]), sheet(&places[1])];
    assert_eq!(node.iter().map(|e| (Fingerprint::of(&e.key), e.anchor)).collect::<Vec<_>>(), vec![(sheets[0].fingerprint, true), (sheets[1].fingerprint, true), (held, false)]);
    assert!(seen.contains("THE DEVICE KEY IS NAMED HERE, never generated: `board laptop`") && seen.contains("UNCHECKED: this command reads no board"), "{seen}");
    assert!(!seen.contains("name this device") && !seen.contains("org root pair's sheet"), "two anchor boxes, the node pair's:\n{seen}");
    assert!(seen.contains("the two new sheets go ONE TO EACH PLACE those sheets already occupy"), "the filing copy where the board carries on:\n{seen}");
    assert!(seen.contains("destroy them, the two NODE sheets this run made, and those alone"), "{seen}");

    // A fresh registration from the same store: the held key named, none
    // generated beside it.
    let fresh: Vec<PathBuf> = (0..4).map(|i| dir.path().join(format!("fresh-{i}"))).collect();
    let mut flags = vec!["--door", DOOR];
    for place in &fresh {
        flags.extend(["--anchor-out", s(place)]);
    }
    let (exit, out, seen) = at_a_terminal(dir.path(), &store, &flags, "\n\n\n\n");
    assert_eq!(exit, 0, "{seen}");
    let (node, board, signer) = verified(RegistrationKind::Fresh, &out);
    assert_eq!(signer, held);
    assert_eq!(tree(&store), before, "the store still holds exactly that one key");
    for enrolment in [&node, &board.expect("the board root's enrolment")] {
        assert_eq!(enrolment.iter().filter(|e| !e.anchor).map(|e| Fingerprint::of(&e.key)).collect::<Vec<_>>(), vec![held], "both enrolments carry it");
    }
    assert!(seen.contains("It goes into BOTH key sets this request founds") && !seen.contains("key file written: "), "{seen}");
    // `--label` beside a key that is named is refused, never dropped.
    let (exit, out, seen) = at_a_terminal(dir.path(), &store, &["--door", DOOR, "--existing-board", "--label", "another"], "");
    assert_eq!((exit, out.as_str()), (3, ""), "{seen}");
    assert!(seen.contains("`--label` names a device key to generate, and this registration generates none: its device key is `board laptop`"), "{seen}");

    // A store that holds none: before any box.
    let empty = dir.path().join("empty");
    let nowhere = [dir.path().join("three"), dir.path().join("four")];
    let (exit, out, seen) = at_a_terminal(dir.path(), &empty, &["--door", DOOR, "--existing-board", "--anchor-label", "na", "--anchor-label", "nb", "--anchor-out", s(&nowhere[0]), "--anchor-out", s(&nowhere[1])], "");
    assert_eq!(exit, 3, "{seen}");
    assert!(seen.contains("the key store holds no device key, and a registration whose board carries on names one and generates none"), "{seen}");
    assert!(!seen.contains("AUTH-5.54") && !seen.contains("name the node pair"), "before any box: {seen}");
    assert!(out.is_empty() && tree(&empty).is_empty() && nowhere.iter().all(|p| !p.exists()), "no anchor file, no key");
}

/// FENCE 8 (a pin; AUTH-5.57 step 2, the hosted signup) — `skep keygen
/// --anchors` IS UNCHANGED BESIDE `register`: under a pseudo-terminal, its
/// labels and destinations fixed by flags, the door-side form says the
/// single pair's statements and its own keep-the-papers line, exports two
/// anchors, generates its device key after the moment, and prints the
/// three-key payload — two anchor-flagged entries and the device key — then
/// the fingerprint flat and grouped, with the one-door line naming the
/// hosted signup. Nothing of the registration's node arm is said, and no
/// request is made.
#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn keygen_anchors_keeps_its_three_key_payload_its_one_door_line_and_its_order() {
    use crate::common::{on_a_terminal, shell_word};

    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("store");
    let (a, b, out, code) = (dir.path().join("a"), dir.path().join("b"), dir.path().join("stdout"), dir.path().join("code"));
    let keygen = format!(
        "{} keygen --anchors --label phone --anchor-label 'sheet a' --anchor-label 'sheet b' --anchor-out {} --anchor-out {} --dir {} > {}; echo $? > {}",
        shell_word(env!("CARGO_BIN_EXE_skep")),
        shell_word(s(&a)),
        shell_word(s(&b)),
        shell_word(s(&store)),
        shell_word(s(&out)),
        shell_word(s(&code))
    );
    let seen = on_a_terminal(&keygen);
    let exit = std::fs::read_to_string(&code).unwrap_or_else(|e| panic!("the run's exit code: {e}: {seen}"));
    assert_eq!(exit.trim(), "0", "{seen}");
    let printed = std::fs::read_to_string(&out).unwrap();
    let lines: Vec<&str> = printed.lines().collect();
    assert_eq!(lines.len(), 4, "the payload, then the fingerprint flat and grouped on two lines: {lines:?}");
    // The three-key payload: the pair, anchor-flagged, then the device key.
    let entries = parse_enroll(lines[0].as_bytes()).expect("a canonical enrollment record");
    let (sheet_a, sheet_b) = (sheet(&a), sheet(&b));
    let device = FileStore::open(&store).device_keys().unwrap();
    assert_eq!(device.len(), 1);
    assert_eq!(
        entries.iter().map(|e| (Fingerprint::of(&e.key), e.anchor, e.label())).collect::<Vec<_>>(),
        vec![(sheet_a.fingerprint, true, Some("sheet a")), (sheet_b.fingerprint, true, Some("sheet b")), (device[0].fingerprint, false, Some("phone"))],
        "three keys: the two anchors and the device key"
    );
    assert_eq!(lines[1], device[0].fingerprint.to_hex());
    assert_eq!(format!("{}\n{}", lines[2], lines[3]), group_hex(&device[0].fingerprint.to_hex()));
    assert!(lines[0].starts_with("{\"type\":\"skep-enroll\",") && !printed.contains("\"door\"") && !printed.contains("\"shape\""), "an enrollment record, and no request");
    // Its own copy: one pair, the hosted signup's one door.
    for said in [
        "(b) TWO FILES, TWO PLACES YOU CONTROL: the pair is two files",
        "[AUTH-5.42] anchor a is named `sheet a`: this names the SHEET and never where you keep it; public forever and uncorrectable\r\n",
        "[AUTH-5.42] anchor b is named `sheet b`",
        "[AUTH-5.44 (create-org)] keep the anchor files — if you lose every device you have signed in on, they are the only way back in",
        "this three-key payload serves ONE door, the hosted signup — never the enroll hop",
    ] {
        assert!(seen.contains(said), "{said}:\n{seen}");
    }
    for unsaid in ["REG-4.103", "CROSS-PAIR", "org root", "node pair", "skep register", "THE REQUEST", "THIS REQUEST IS FOR ONE DOOR"] {
        assert!(!seen.contains(unsaid), "nothing of the registration's arm: `{unsaid}`:\n{seen}");
    }
    assert_eq!(seen.matches("[AUTH-5.40] anchor file written: ").count(), 2, "two exports:\n{seen}");
    // Its order: the device key is generated after the moment.
    let (keep, custody, one_door) = (seen.find("[AUTH-5.44 (create-org)]").unwrap(), seen.find("key file written: ").expect("the custody line"), seen.find("this three-key payload serves ONE door").unwrap());
    assert!(keep < custody && custody < one_door, "the moment, then the device key, then the payload's line:\n{seen}");
}
