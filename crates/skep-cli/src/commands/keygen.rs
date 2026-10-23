//! `skep keygen` (`client.md` §2.2): one device key generated into the store.
//!
//! Its byline is fixed at the box — AUTH-5.42's statements, AUTH-1.24's
//! domain — and the custody line written beside its path; `--payload`
//! prints its enrollment record, and `--anchors`, a person door, runs the
//! door-side backup moment for the hosted signup's three-key payload
//! (AUTH-5.57 step 2). With `bind`, one of the two ceremonies that sequence
//! the library's compositions themselves rather than calling a walk — the
//! store's `generate`, its lookup, `backup_moment` at the door side,
//! `encode_enroll` — and so the carrier of this form's own text: the box's
//! statements by venue, the custody line, the abandonment's disposition,
//! and the one-door line.
//!
//! **The order.** The device-name box, then at the door side the backup
//! moment, then the device key's generation — so a moment stopped short
//! leaves no unbound device key in the store for the next run's to stand
//! beside, where §3.5 arm 3's "exactly one device key" would select none.
//! A generation the store cannot write leaves nothing of the key behind
//! (§3.7), and its halt is the store's own.

use std::path::{Path, PathBuf};

use skep_client::ceremony::backup::{backup_moment, BackupOptions, Venue};
use skep_client::halt::Halt;
use skep_client::person::{LabelBox, Person, Public, Statement};
use skep_client::sheet::{group_hex, Label};
use skep_client::store::{KeySelector, Purpose};
use skep_identity::{encode_enroll, Enrollment};

use super::{data, host_name_and_date, record_refused, require_terminal, store_of, talk, BoxDefault, Door, Stop, OUTSTANDING_ACT};
use crate::args::CommandLine;
use crate::terminal::Terminal;

/// Returns AUTH-5.42's statements, rendered whenever a label is fixed.
///
/// They are rendered at the prompt or the flag alike (§2.2 `keygen`), the
/// last of them the consequence at this venue, keyed off the form: at the
/// notebook its reader class, at the door-side form the public thread the
/// byline rides onto.
fn device_box_statements(door_side: bool) -> Vec<String> {
    let consequence = if door_side {
        "it rides onto a public thread, approved or denied; and not every write under this byline is yours — the party that operates the board you join can write as you there, visibly and permanently, which every copy that checks signatures will show was not you"
    } else {
        "at this notebook it is readable by anything on the machine"
    };
    vec![
        "This name is permanent and cannot be edited: fixing a typo costs a keypair.".to_string(),
        "It is a byline: this name appears beside every write you make with this key, forever.".to_string(),
        "It holds the DEVICE's name — never your own and never your organisation's; a display name is a separate, changeable label.".to_string(),
        consequence.to_string(),
    ]
}

/// Returns the key file's custody line beside its path.
///
/// The custody is §3a's (§9 items 4, 5, 38: the ladder alone until the
/// store-location spike answers).
fn custody_line(path: &Path) -> String {
    format!(
        "key file written: {} — the seed rests in this file and the filesystem's modes are its whole protection (0600 under 0700): a \
         same-user process reads it and a disk image carries it; your anchors, where the account this key joins holds them, are what \
         its loss recovers from (`skep recover`); an account founded from this key's own one-key record holds none, and there the one \
         way back is the enroll hop from another signed-in device",
        path.display()
    )
}

/// What a door-side form stopped short of its payload's print leaves behind.
///
/// It leaves no board state (AUTH-5.57 step 2) — the form delegates nothing
/// — and anchor files that name no account and open nothing. It is said
/// ahead of each halt that stops the form between the moment's start and
/// the device key standing in the store: the moment's own, an anchor's
/// label the record refuses, the generation's.
const ABANDONED: &str = "this form delegates nothing and leaves no board state behind: any anchor file written names no account and \
     opens nothing, ever — destroy it, or keep it plainly marked dead and never beside a live pair";

/// [`ABANDONED`]'s key-store clause, true of a stop before the generation.
///
/// The generation is the device key's, which follows the moment (the
/// module's order).
const NOTHING_STORED: &str = "and nothing of this form is in the key store: its device key is generated after the moment";

pub fn keygen(c: &CommandLine) -> Result<(), Stop> {
    let store = store_of(c)?;
    // `--anchors`: the door-side form (§2.2), a person door.
    let door_side = c.switch("--anchors");
    if door_side {
        require_terminal(Door { form: "keygen --anchors", moments: "the door-side backup moment" })?;
    }
    // Every label a flag fixes is judged at its box before anything is
    // asked or generated (§2.2; P13): the anchors' here — given only with
    // `--anchors`, the grammar's rule — and the device's below.
    let anchor_labels: Vec<Label> = c
        .values("--anchor-label")
        .iter()
        .map(|l| Label::new(l))
        .collect::<Result<_, _>>()
        .map_err(|fault| Halt::face(format!("an anchor label is refused at the box: {fault}"), "AUTH-1.24's domain", "pass labels inside the domain"))?;
    let mut person = Terminal;
    // The device-name box: `--label`, or asked; the statements whenever a
    // label is fixed; the domain test at the box (P13).
    let label = match c.value("--label") {
        Some(text) => {
            let label = Label::new(text).map_err(|fault| Halt::face(format!("the label is refused at the box: {fault}"), "AUTH-1.24's domain: non-empty, no line break, at most 128 bytes of UTF-8", "pass a label inside the domain"))?;
            for s in device_box_statements(door_side) {
                person.say(Public(Statement { rule: "AUTH-5.42", text: s }));
            }
            label
        }
        None => loop {
            let text = person
                .label(Public(LabelBox { title: "name this device".into(), statements: device_box_statements(door_side), default: None }))
                .map_err(|_| Halt::face("no device name was given", "the box was abandoned", "run `skep keygen --label <name>`, or answer the box"))?;
            match Label::new(&text) {
                Ok(l) => break l,
                Err(fault) => person.say(Public(Statement { rule: "AUTH-1.24", text: format!("that name is refused at the box: {fault}") })),
            }
        },
    };
    let mut entries = Vec::new();
    if door_side {
        // The door-side form (AUTH-5.57 step 2): the backup moment for an
        // anchor pair with no board, statement (a) carrying the operator
        // sentence unconditionally — ahead of the device key's generation
        // (the module's order); then the three-key payload for the hosted
        // signup.
        let BoxDefault { host_name, date } = host_name_and_date();
        let opts = BackupOptions {
            labels: anchor_labels,
            destinations: c.values("--anchor-out").iter().map(PathBuf::from).collect(),
            paper: c.switch("--paper"),
            store: Some(store.root().to_path_buf()),
            host_name,
            date,
        };
        // A stopped moment's disposition, said ahead of its halt.
        let abandoned = || talk(format!("{ABANDONED}; {NOTHING_STORED}"));
        let outcome = backup_moment(&mut person, &Venue::DoorSide, &opts).inspect_err(|_| abandoned())?;
        for a in &outcome.anchors {
            entries.push(Enrollment::new(a.public.clone(), true, Some(a.label.as_str().to_string())).map_err(record_refused).inspect_err(|_| abandoned())?);
        }
    }
    let generated = store.generate_and_sweep(Some(label.clone())).inspect_err(|_| {
        // The moment's anchors stand written: their disposition, beside the
        // generation's halt, which says the store holds nothing of its key.
        if door_side {
            talk(ABANDONED);
        }
    })?;
    // The sweep's names, said: a temp a killed generation left held a seed
    // nobody's key was made of (§3.7), and one the volume keeps still does.
    for swept in &generated.swept {
        talk(format!("removed an unfinished key file {}, left by a generation that did not complete", swept.display()));
    }
    for (left, e) in &generated.unswept {
        talk(format!("an unfinished key file could not be removed ({e}) and stands: {}", left.display()));
    }
    let id = generated.id;
    let path = store.key_path(&id.0);
    let key = store.select(&KeySelector::Path(&path), Purpose::Read)?;
    talk(custody_line(&path));
    entries.push(Enrollment::new(key.public.clone(), false, Some(label.as_str().to_string())).map_err(record_refused)?);
    if c.switch("--payload") || door_side {
        // The record first (§2.2): one canonical JSON object.
        data(encode_enroll(&entries))?;
        if door_side {
            talk("this three-key payload serves ONE door, the hosted signup — never the enroll hop, whose `skep enroll` refuses every anchor-flagged entry at the paste");
        } else {
            // A key this command made was never made at `skep accept`, so the
            // handoff recipient's clause is `fingerprint`'s alone.
            talk(format!("this key is not enrolled anywhere yet. {OUTSTANDING_ACT} Where no board has been claimed from this store at all: `skep claim`."));
        }
    }
    // The fingerprint last, flat and grouped — never the bare public key —
    // each line its own data line.
    data(key.fingerprint.to_hex())?;
    for line in group_hex(&key.fingerprint.to_hex()).lines() {
        data(line)?;
    }
    Ok(())
}
