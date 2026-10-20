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
//! the one-door line, and a generation's refusal.
//!
//! **The order.** The device-name box, then at the door side the backup
//! moment, then the device key's generation — so a moment stopped short
//! leaves no unbound device key in the store for the next run's to stand
//! beside, where §3.5 arm 3's "exactly one device key" would select none;
//! and a generation the store could not write names the volume's room and
//! the file its failed write left behind ([`generation_refused`]), which
//! every later listing of the store would otherwise halt on, or select
//! beside the next run's.

use std::io;
use std::path::{Path, PathBuf};

use skep_client::ceremony::backup::{backup_moment, BackupOptions, Venue};
use skep_client::halt::Halt;
use skep_client::person::{LabelBox, Person, Public, Statement};
use skep_client::sheet::{group_hex, Label};
use skep_client::store::{FileStore, KeySelector, KeyStore, Purpose, StoreError};
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

/// Returns the halt a generation the store could not write comes to.
///
/// It names the write's own cause beside the volume's room, never the
/// "missing, unreadable or mis-pathed" face a lookup's read meets
/// (`StoreError::Io`'s conversion). Where the file this run created stands
/// — its write cut short at a full volume or a file-size limit, or written
/// whole and its sync refused, as a filesystem that allocates late answers
/// at a full volume — it is named as the one to remove, since no line
/// printed its key and no board knows it: a partial file stops every later
/// `skep` command that lists the store (`FileStore::list` refuses a store
/// holding a file that does not parse), and a whole one stands beside the
/// next run's as a second device key, where §3.5 arm 3's "exactly one"
/// selects none. A file an `O_EXCL` open met standing is no file of this
/// run's, and is never named.
fn generation_refused(e: StoreError, store: &FileStore) -> Halt {
    match e {
        StoreError::Io { path, error } => {
            let created = error.kind() != io::ErrorKind::AlreadyExists && path.is_file();
            let remnant = match (created, created && store.load(&path).is_ok()) {
                (false, _) => String::new(),
                (true, false) => format!(
                    "; then remove {}, the partial file this run left — no line printed its key and no board knows it, and every later \
                     `skep` command that lists this store halts on it",
                    path.display()
                ),
                (true, true) => format!(
                    "; then remove {}, the key file this run wrote and never printed — no board knows its key, and left in place it \
                     stands beside the next run's as a second device key, where a lookup selects none",
                    path.display()
                ),
            };
            Halt::face(
                format!("the key store could not write {}: {error}", path.display()),
                "the generation's write failed — at a full volume, the volume's room — and nothing was printed",
                format!("free room on the volume holding {}{remnant}; then run `skep keygen` again", store.root().display()),
            )
        }
        other => other.into(),
    }
}

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
    let id = store.generate(Some(label.clone())).map_err(|e| generation_refused(e, &store)).inspect_err(|_| {
        // The moment's anchors stand written: their disposition, beside the
        // generation's halt, which names what the store holds.
        if door_side {
            talk(ABANDONED);
        }
    })?;
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
