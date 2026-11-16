//! `skep register`, the twenty-first command: a registration request
//! (REG-4.67).
//!
//! It is an applicant's own side of a registration, the library's
//! composition (`skep_client::ceremony::registration`) with the terminal as
//! its `Person`: on the applicant's own device, with no board and no
//! account, it makes the keys a registry's door asks for and prints the
//! request that carries them, signed once by this store's device key. It
//! reads no board, opens no connection and writes nothing to any board;
//! what takes the request to the door — a sign-up page, a sponsor — is no
//! part of it.
//!
//! `--door <identifier>` is required and names the one door the request is
//! framed for (REG-4.74). It is judged for its form alone, ahead of
//! everything the run asks, generates or writes: whether a door answers to
//! it is that door's own check. A request is a fresh registration's — the
//! org's own root pair and its node pair, four anchor sheets — unless
//! `--existing-board` says the org's board carries on: then it is the node
//! pair alone, two sheets, the org root's pair being the one that board
//! already has (REG-4.104, REG-4.204). `--anchor-label`, `--anchor-out` and
//! `--paper` are the backup moment's, as `keygen --anchors` takes them, four
//! of each at most in the order org root a, org root b, node a, node b, and
//! two, node a and node b, with `--existing-board`.
//!
//! One device key serves every board (REG-4.102), so the device key is
//! this store's own where it holds one — named at its box, none generated
//! beside it — or the file `--key` (or `SKEP_KEY`) names; more than one
//! with none named is a halt listing them, never a pick. A fresh
//! registration over a store that holds none generates one, under
//! `--label` or the box's answer, after the sheets are verified. With
//! `--existing-board` none is ever generated: the key is taken as the one
//! the board's own set holds and said as unchecked, and a store that holds
//! none halts before anything is asked. `--label` beside a key that is
//! named is refused, never dropped.
//!
//! A person door: the name boxes and the backup moment are read at the
//! terminal. Stdout carries the request, one line of canonical JSON with no
//! `sig` — that member is the hand's that deposits it — to pipe, copy or
//! redirect whole. Stderr carries the walk's statements, and after the
//! request each key's label beside its fingerprint in the grouped form, the
//! thread's key, and the line that the request serves its one door and its
//! sheets belong to this one application (AUTH-5.57 steps 3 and 4). A run
//! that stops short says what it leaves behind.

use std::path::PathBuf;

use skep_client::ceremony::registration::{registration_request, say_request, RegistrationOptions};

use super::{data, host_name_and_date, require_terminal, store_of, talk, BoxDefault, Door, Stop};
use crate::args::{CommandLine, Usage};
use crate::terminal::Terminal;

pub fn register(c: &CommandLine) -> Result<(), Stop> {
    let store = store_of(c)?;
    let key_file = c.key_file()?;
    // The line's own judgment, ahead of the door: which door is required.
    let Some(door) = c.value("--door") else {
        return Err(Usage(
            "--door <identifier> is required: the door this request is for, one quoted string as the registry publishes it — `realm:<64 lowercase hex> door:<address>`".into(),
        )
        .into());
    };
    require_terminal(Door { form: "register", moments: "the name boxes and the backup moment" })?;
    let BoxDefault { host_name, date } = host_name_and_date();
    let opts = RegistrationOptions {
        door: door.to_string(),
        board_carries_on: c.switch("--existing-board"),
        key_file,
        label: c.value("--label").map(str::to_owned),
        anchor_labels: c.values("--anchor-label").to_vec(),
        anchor_out: c.values("--anchor-out").iter().map(PathBuf::from).collect(),
        paper: c.switch("--paper"),
        host_name,
        date,
    };
    let mut person = Terminal;
    let request = registration_request(&mut person, &store, &opts)?;
    // The request first, one line on stdout; what is carried beside it is
    // said after, so it stands under the block.
    data(&request.body).inspect_err(|_| {
        talk(format!(
            "the request was composed and NOT handed out: stdout refused it, and nothing was sent anywhere. The sheets this run wrote \
             name no account and open nothing, ever — destroy them, or keep them plainly marked dead and never beside a live pair; {}. \
             Run it again with stdout at a terminal or a file: it makes fresh sheets and a fresh request",
            if request.device.generated {
                "the device key this run generated stands in the key store, and the next run names it and generates none"
            } else {
                "the key store is as it was"
            }
        ));
    })?;
    talk(format!(
        "the request is the ONE LINE on standard output, {} bytes: pipe it, copy it or redirect it to a file, and hand it to the door whole",
        request.body.len()
    ));
    say_request(&mut person, &request);
    Ok(())
}
