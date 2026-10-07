//! `skep keygen` (`client.md` §2.2): one DEVICE key generated into the
//! store, its byline fixed at the box — AUTH-5.42's statements, AUTH-1.24's
//! domain — and the custody line written beside its path; `--payload`
//! prints its enrollment record, and `--anchors`, a person door, runs the
//! door-side backup moment for the hosted signup's three-key payload
//! (AUTH-5.57 step 2). With `bind`, one of the two commands that sequence
//! the library's compositions themselves rather than calling a walk — the
//! store's `generate`, its lookup, `backup_moment` at the door side,
//! `encode_enroll` — and so the carrier of this form's own text: the box's
//! statements by venue, the custody line, the abandonment's disposition and
//! the one-door line.

use std::path::{Path, PathBuf};

use skep_client::ceremony::backup::{backup_moment, BackupOptions, Venue};
use skep_client::halt::Halt;
use skep_client::person::{LabelBox, Person, Public, Statement};
use skep_client::sheet::{group_hex, Label};
use skep_client::store::{KeySelector, KeyStore, Purpose};
use skep_identity::{encode_enroll, Enrollment};

use super::{data, halt, host_name_and_date, no_terminal, store_of, talk, usage, OUTSTANDING_ACT};
use crate::args::Command;
use crate::terminal::{has_terminal, Terminal};

/// AUTH-5.42's statements, rendered whenever a label is fixed — prompt or
/// flag alike (§2.2 `keygen`), keyed to the venue.
fn device_box_statements(door_side: bool) -> Vec<String> {
    let venue = if door_side {
        "it rides onto a public thread, approved or denied; and not every write under this byline is yours — the party that operates the board you join can write as you there, visibly and permanently, which every copy that checks signatures will show was not you"
    } else {
        "at this notebook it is readable by anything on the machine"
    };
    vec![
        "This name is permanent and cannot be edited: fixing a typo costs a keypair.".to_string(),
        "It is a byline: this name appears beside every write you make with this key, forever.".to_string(),
        "It holds the DEVICE's name — never your own and never your organisation's; a display name is a separate, changeable label.".to_string(),
        venue.to_string(),
    ]
}

/// The key file's custody line beside its path (§3a, RULED; §9 items 4, 5,
/// 38: the ladder alone until the store-location spike answers).
fn custody_line(path: &Path) -> String {
    format!(
        "key file written: {} — the seed rests in this file and the filesystem's modes are its whole protection (0600 under 0700): a \
         same-user process reads it and a disk image carries it; your anchors, where the account this key joins holds them, are what \
         its loss recovers from (`skep recover`); an account founded from this key's own one-key record holds none, and there the one \
         way back is the enroll hop from another signed-in device",
        path.display()
    )
}

pub fn keygen(c: &Command) -> i32 {
    let store = match store_of(c) {
        Ok(s) => s,
        Err(u) => return usage(u),
    };
    let anchors = c.switch("--anchors");
    if anchors && !has_terminal() {
        return no_terminal("keygen --anchors");
    }
    let mut person = Terminal::new();
    // The device-name box: `--label`, or asked; the statements whenever a
    // label is fixed; the domain test at the box (P13).
    let label = match c.value("--label", None) {
        Some(text) => match Label::new(&text) {
            Ok(l) => {
                for s in device_box_statements(anchors) {
                    person.say(Public(Statement { rule: "AUTH-5.42", text: s }));
                }
                l
            }
            Err(fault) => return halt(Halt::face(format!("the label is refused at the box: {fault}"), "AUTH-1.24's domain: non-empty, no line break, at most 128 bytes of UTF-8", "pass a label inside the domain")),
        },
        None => {
            loop {
                let text = match person.label(Public(LabelBox { title: "name this device".into(), statements: device_box_statements(anchors), default: None })) {
                    Ok(t) => t,
                    Err(_) => return halt(Halt::face("no device name was given", "the box was abandoned", "run `skep keygen --label <name>`, or answer the box")),
                };
                match Label::new(&text) {
                    Ok(l) => break l,
                    Err(fault) => person.say(Public(Statement { rule: "AUTH-1.24", text: format!("that name is refused at the box: {fault}") })),
                }
            }
        }
    };
    let id = match store.generate(Some(label.clone())) {
        Ok(id) => id,
        Err(e) => return halt(e.into()),
    };
    let path = store.key_path(&id.0);
    let key = match store.select(&KeySelector::Path(&path), Purpose::Read) {
        Ok(k) => k,
        Err(e) => return halt(e.into()),
    };
    talk(custody_line(&path));
    let mut entries = Vec::new();
    if anchors {
        // THE DOOR-SIDE FORM (AUTH-5.57 step 2): the backup moment for an
        // anchor pair with no board, statement (a) carrying the operator
        // sentence unconditionally; then the three-key payload for the
        // hosted signup.
        let labels: Vec<Label> = match c.all("--anchor-label").iter().map(|l| Label::new(l)).collect::<Result<Vec<_>, _>>() {
            Ok(ls) => ls,
            Err(fault) => return halt(Halt::face(format!("an anchor label is refused at the box: {fault}"), "AUTH-1.24's domain", "pass labels inside the domain")),
        };
        let (host_name, date) = host_name_and_date();
        let opts = BackupOptions {
            labels,
            destinations: c.all("--anchor-out").into_iter().map(PathBuf::from).collect(),
            paper: c.switch("--paper"),
            store: Some(store.root().to_path_buf()),
            host_name,
            date,
        };
        let outcome = match backup_moment(&mut person, &Venue::DoorSide, &opts) {
            Ok(o) => o,
            Err(h) => {
                talk("this form delegates nothing and leaves no board state behind: any anchor file written names no account and opens nothing, ever — destroy it, or keep it plainly marked dead and never beside a live pair");
                return halt(h);
            }
        };
        for a in &outcome.anchors {
            entries.push(Enrollment::new(a.public.clone(), true, Some(a.label.as_str().to_string())).expect("a label the box admitted"));
        }
    }
    entries.push(Enrollment::new(key.public.clone(), false, Some(label.as_str().to_string())).expect("a label the box admitted"));
    if c.switch("--payload") || anchors {
        // The record FIRST (§2.2): one canonical JSON object.
        data(encode_enroll(&entries));
        if anchors {
            talk("this three-key payload serves ONE door, the hosted signup — never the enroll hop, whose `skep enroll` refuses every anchor-flagged entry at the paste");
        } else {
            // A key this command made was never made at `skep accept`, so the
            // handoff recipient's clause is `fingerprint`'s alone.
            talk(format!("this key is not enrolled anywhere yet. {OUTSTANDING_ACT} Where no board has been claimed from this store at all: `skep claim`."));
        }
    }
    // The fingerprint LAST, flat and grouped — never the bare public key.
    data(key.fingerprint.to_hex());
    data(group_hex(&key.fingerprint.to_hex()));
    0
}
