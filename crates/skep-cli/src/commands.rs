//! THE THIRTEEN COMMANDS, each exactly as `client.md` §2.2 writes it — one
//! file per command beneath this one, each a `pub fn` that `main`
//! dispatches to and that answers `Ok` or the [`Stop`] it came to, every
//! walk a library call — and what they share AMONG THEMSELVES ALONE,
//! private here and so visible to each of them: `require_terminal`, the
//! person doors' check, whose refusal is a halt naming the [`Door`]'s own
//! moments; a payload read to its cap ([`MAX_PAYLOAD_BYTES`]); the anchor
//! boxes' per-run default ([`BoxDefault`]); the three facts' one spelling
//! (`print_facts`); the outstanding-act line `keygen` and `fingerprint`
//! share (`OUTSTANDING_ACT`); and the whole-set compare, from the held set
//! to its halt (`held_set`, `compare_genesis`). What the dev binary shares
//! with them — the two streams, the stops and their exit codes, the
//! plumbing from the flags to a board, a store, a principal and a key —
//! is `shared.rs`'s, taken here and handed down to the command files — the
//! one spelling of a key on an operator's line (`key_named`) and the one
//! bound on a third party's text a halt echoes (`clipped`) among it;
//! `finish` and `help` are the `skep` [`Program`]'s own.

mod accept;
mod bind;
mod claim;
mod enroll;
mod fingerprint;
mod handoff;
mod health;
mod keygen;
mod recover;
mod retire;
mod rotate;
mod session;
mod verify;

pub use accept::accept;
pub use bind::bind;
pub use claim::claim;
pub use enroll::enroll;
pub use fingerprint::fingerprint;
pub use handoff::handoff;
pub use health::health;
pub use keygen::keygen;
pub use recover::recover;
pub use retire::retire;
pub use rotate::rotate;
pub use session::session;
pub use verify::verify;

use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use skep_client::board::Board;
use skep_client::derive::records::{compare_whole_set, credential_records, Difference, Held};
use skep_client::derive::Walk;
use skep_client::halt::Halt;
use skep_client::sheet::{render_inert, Facts};
use skep_client::store::{FileStore, KeyFacts, KeySelector, Purpose};
use skep_identity::{Fingerprint, LabelError, PublicKey, MAX_RECORD_BYTES};

use crate::args::HELP;
use crate::shared::{
    self, board_of, clipped, data, data_verbatim, key_named, principal_or_bound,
    require_no_key_file, select_key, store_of, Program, Stop,
};
use crate::terminal::{has_terminal, talk};

/// The `skep` program: its name, which every stop's block opens with, and
/// the help a usage refusal prints beneath it.
const SKEP: Program = Program { name: "skep", help: HELP };

/// A command's outcome finished under the `skep` program (`shared::finish`):
/// a stop's one block said on stderr, and the exit code answered — 0, or
/// the stop's.
pub fn finish(outcome: Result<(), Stop>) -> i32 {
    shared::finish(SKEP, outcome)
}

/// `--help`: `HELP` on stdout, the DATA the run asked for.
pub fn help() -> Result<(), Stop> {
    shared::help(SKEP)
}

/// A person door (§2.4; `ARCHITECTURE.md` §The command lists the eight):
/// its `form`, as a command line spells it, and the `moments` a person
/// answers there, in §2.4's and §6's words — each named, so neither stands
/// in the other's place.
#[derive(Clone, Copy, Debug)]
struct Door {
    form: &'static str,
    moments: &'static str,
}

/// A person door's check (§2.4: the CLI's, never a walk's), made before
/// anything is generated: a controlling terminal, or the halt naming
/// `door`'s moments.
fn require_terminal(door: Door) -> Result<(), Halt> {
    if has_terminal() {
        Ok(())
    } else {
        Err(no_terminal(door))
    }
}

/// A person door reached without a controlling terminal: HALT AND SURFACE,
/// §2.3's missing-TTY member, its face naming the moments a person answers
/// at that door (§2.4; §6 "The terminal") — the backup moment only where it
/// runs.
fn no_terminal(door: Door) -> Halt {
    Halt::face(
        format!("`{}` is a person door and requires a controlling terminal", door.form),
        format!(
            "what a person answers here — {} — is read at the terminal, and stdin and stderr are not both a terminal: a \
             wrapper that captured one and fed the other would answer it with no person (§2.4)",
            door.moments
        ),
        "run it at a terminal; a script that must drive this walk drives the library's scripted Person in-process",
    )
}

/// The most bytes a payload argument carries: one record at its cap
/// (`MAX_RECORD_BYTES`, AUTH-1.18) and the line ending it is printed with,
/// `\r\n` at most — a reply's three facts and the hosted reply's six lines
/// sit far inside it. Past it the argument is no payload, and
/// [`read_payload`] reads no further than the byte past it: no argument —
/// a customer's payload at the sidecar, a file that never ends — sizes
/// this run's memory, where a read to its end grows with whatever it is fed
/// before the record's own cap is ever consulted.
const MAX_PAYLOAD_BYTES: usize = MAX_RECORD_BYTES + 2;

/// A payload argument's bytes: a file, or `-` for stdin, read no further
/// than one byte past [`MAX_PAYLOAD_BYTES`] — and past the cap, a halt
/// naming it.
fn read_payload(arg: &str) -> Result<Vec<u8>, Halt> {
    let limit = MAX_PAYLOAD_BYTES as u64 + 1;
    let mut bytes = Vec::new();
    if arg == "-" {
        io::stdin().take(limit).read_to_end(&mut bytes).map_err(|e| Halt::face("the payload could not be read from stdin", e.to_string(), "pipe the payload in"))?;
    } else {
        File::open(arg).and_then(|file| file.take(limit).read_to_end(&mut bytes)).map_err(|e| {
            Halt::face(format!("the payload file {arg} could not be read: {e}"), "AUTH-5.67: a mis-pathed file is a halt naming the path, never a fallback", "check the path")
        })?;
    }
    if bytes.len() > MAX_PAYLOAD_BYTES {
        let at = if arg == "-" { "stdin" } else { arg };
        return Err(Halt::face(
            format!("the payload at {at} runs past {MAX_PAYLOAD_BYTES} bytes and is read no further"),
            format!("a payload is one enrollment record of at most {MAX_RECORD_BYTES} bytes (AUTH-1.18) and its line ending, or a reply's few lines: past the cap it is neither"),
            "pass the record or the reply as it was printed, and nothing beside it",
        ));
    }
    Ok(bytes)
}

/// A label the enrollment record refuses (AUTH-1.25): one `Label::new`
/// admitted and `Enrollment::new` does not — AUTH-1.24's domain spelled
/// twice, by `skep-client` and by `skep-identity`, and the two standing
/// apart. A halt naming the label's fault, never a panic, whose exit 101
/// §2.3 does not have.
fn record_refused(e: LabelError) -> Halt {
    Halt::face(
        format!("the label is refused by the enrollment record: {e}"),
        "AUTH-1.25: the record admits a label inside AUTH-1.24's domain alone, and a key's label is fixed in its file",
        "generate a key named inside the domain (`skep keygen --label <name>`)",
    )
}

/// The anchor boxes' per-run default (§4.2 step 2), which becomes a
/// permanent byline: the machine's host name and today's date, each named,
/// so neither lands in the other's place.
#[derive(Debug)]
struct BoxDefault {
    host_name: String,
    date: String,
}

/// This run's [`BoxDefault`]: the machine's host name and today's date in
/// UTC. The name is the first source's name ([`host_name_of`]) that is not
/// empty, on §6's three platforms: `COMPUTERNAME` (Windows), `HOSTNAME`
/// (where a shell exports it), `/etc/hostname` (Linux), then the `hostname`
/// command's output (macOS) — `this-machine` where none answers. So the
/// name is never empty, never holds a dot and is lowercase.
fn host_name_and_date() -> BoxDefault {
    let host_name = std::env::var("COMPUTERNAME")
        .ok()
        .and_then(host_name_of)
        .or_else(|| std::env::var("HOSTNAME").ok().and_then(host_name_of))
        .or_else(|| std::fs::read_to_string("/etc/hostname").ok().and_then(host_name_of))
        .or_else(|| std::process::Command::new("hostname").output().ok().and_then(|out| String::from_utf8(out.stdout).ok()).and_then(host_name_of))
        .unwrap_or_else(|| "this-machine".to_string());
    let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    BoxDefault { host_name, date: civil_date(secs) }
}

/// A host-name source's name: its first line, trimmed, cut at its first dot
/// and lowercased — `None` where that leaves nothing, a source of `.local`
/// as much as an empty one, so the next source is asked.
fn host_name_of(text: String) -> Option<String> {
    let line = text.lines().next().unwrap_or_default().trim();
    let name = line.split_once('.').map_or(line, |(name, _)| name).to_lowercase();
    Some(name).filter(|name| !name.is_empty())
}

/// `yyyy-mm-dd` from unix seconds (Howard Hinnant's civil-from-days).
fn civil_date(secs: u64) -> String {
    let z = (secs / 86400) as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

/// The three facts, DATA on stdout — their one spelling, every command's
/// that prints them, in the lines `bind`'s `facts_of` reads back from a
/// reply (`account …`, `principal …`, `origin …`).
fn print_facts(f: &Facts) -> Result<(), Halt> {
    data(format!("account {}", f.account))?;
    data(format!("principal {}", f.principal))?;
    data(format!("origin {}", f.origin))
}

/// The outstanding act of a key enrolled nowhere — AUTH-5.32's pending state
/// named, CONDITIONED on the walk because one payload serves two (§2.2): the
/// line `keygen --payload` prints at exit, and the one `fingerprint` carries
/// beside every UNBOUND key, "the same conditioned outstanding-act line".
/// Each site adds the clauses its own state makes true.
const OUTSTANDING_ACT: &str = "Where it ADDS a device: take this payload to a device already signed in, run `skep enroll` there, and bring its three \
     facts back to `skep bind` here. Where it REPLACES a machine: `skep rotate --payload` there instead, then `skep bind` here.";

/// What this device HOLDS for the whole-set compare (AUTH-4.58's
/// detection): the entries of the record `record_arg` names — the
/// `--payload` argument, a file or `-`, naming the RECORD this device
/// printed, `verify`'s; never `bind`'s, whose payload is the reply — and
/// each `anchors` file's public members beside `device`, the store's key;
/// `None` where neither is given.
fn held_set(store: &FileStore, record_arg: Option<&str>, anchors: &[String], device: &KeyFacts) -> Result<Option<Vec<Held>>, Halt> {
    if record_arg.is_none() && anchors.is_empty() {
        return Ok(None);
    }
    let mut held = Vec::new();
    if let Some(arg) = record_arg {
        let bytes = read_payload(arg)?;
        let text = std::str::from_utf8(&bytes).map_err(|_| Halt::face("the payload is not UTF-8", "a canonical record is UTF-8 text", "re-take the payload"))?.trim();
        let entries = skep_identity::parse_enroll(text.as_bytes()).map_err(|e| Halt::face("the payload is not a canonical enrollment record", e.to_string(), "re-take it from the device that printed it"))?;
        for entry in entries {
            held.push(Held { fingerprint: Fingerprint::of(&entry.key), anchor: entry.anchor, label: entry.label().map(str::to_string) });
        }
    }
    if !anchors.is_empty() {
        for path in anchors {
            // The file's PUBLIC facts and nothing else — the lookup hands out
            // no seed; no session, nothing written.
            let artifact = store.select(&KeySelector::Path(Path::new(path)), Purpose::Read)?;
            held.push(Held { fingerprint: artifact.fingerprint, anchor: artifact.anchor, label: artifact.label });
        }
        held.push(held_device(device));
    }
    Ok(Some(held))
}

/// The store's device key as the compare holds it — the whole of what is
/// held where another hand wrote the first set around this key alone: a
/// handoff's DECLINE arm, which prints no papers (§2.2 `bind`), or a hosted
/// one-key signup.
fn held_device(device: &KeyFacts) -> Held {
    Held { fingerprint: device.fingerprint, anchor: false, label: device.label.clone() }
}

/// THE WHOLE-SET COMPARE, run and faced (AUTH-4.58's detection; P25) — at
/// `verify` and at `bind`, which "halts as at `verify`" (§2.2): the genesis
/// record of the set `walk` reached, entry for entry against `held`; each
/// LATER act one line of TALK (P27); any difference a halt in AUTH-5.53's
/// terms naming that set's account, its act the acts by cell (§2.2
/// `verify`; AUTH-4.56) and then `site_clause`, the site's own last clause;
/// a set with no genesis record a halt.
fn compare_genesis(board: &Board, walk: &Walk, own: &[(Fingerprint, PublicKey)], held: &[Held], site_clause: &str) -> Result<(), Halt> {
    let records = credential_records(board, &walk.set_account, own)?;
    let Some(whole) = compare_whole_set(&records, &walk.set, held) else {
        return Err(Halt::face(
            "the account has no genesis record to compare against",
            "the admitted read found no enrollment record naming the account",
            "this is a board fault, or the account is not the one the facts name",
        ));
    };
    if !whole.differences.is_empty() {
        return Err(Halt::face(
            format!("this account is NOT yours to keep as it stands (AUTH-5.53): the genesis record of {} differs from what you hold", walk.set_account),
            difference_lines(&whole.differences).join("\n  "),
            format!(
                "the acts by cell: a planted DEVICE key is retired from this device's own session; a planted ANCHOR only under an anchor of \
                 your own that survived; the state is PERMANENT where the flags did not — {site_clause}"
            ),
        ));
    }
    for act in &whole.later {
        talk(later_line(act));
    }
    Ok(())
}

/// The whole-set compare's differences, one line each in AUTH-5.53's terms —
/// the cause [`compare_genesis`]'s halt gives.
fn difference_lines(diffs: &[Difference]) -> Vec<String> {
    diffs
        .iter()
        .map(|d| match d {
            Difference::Added { fingerprint, anchor, label } => format!(
                "a key you did not send stands in the genesis: {fingerprint} anchor={anchor} label={} — {}",
                label.as_deref().map(render_inert).unwrap_or_else(|| "(none)".into()),
                if *anchor { "an anchor planted: the remedy is your OWN anchor where the flags survived (AUTH-4.56), and the state is PERMANENT where they did not" } else { "a device key planted: retire it from this device's own session (`skep retire --fingerprint <prefix>`)" }
            ),
            Difference::Missing { fingerprint, anchor, label } => format!(
                "a key you sent is missing from the genesis: {fingerprint} anchor={anchor} label={}",
                label.as_deref().map(render_inert).unwrap_or_else(|| "(none)".into())
            ),
            Difference::FlagFlipped { fingerprint, held_anchor, genesis_anchor } => {
                format!("the anchor flag is flipped on {fingerprint}: you sent anchor={held_anchor}, the genesis holds anchor={genesis_anchor}")
            }
        })
        .collect()
}

/// A later act the compare reads off the current set beyond the genesis
/// record, one line of TALK [`compare_genesis`] says.
fn later_line(act: &Held) -> String {
    format!("later act: {} anchor={} label={}", act.fingerprint, act.anchor, act.label.as_deref().map(render_inert).unwrap_or_else(|| "(none)".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `retire`'s door, as `commands/retire.rs` names it.
    const RETIRE: Door = Door { form: "retire", moments: "the preview's typed confirmation" };

    #[test]
    fn the_host_name_is_a_sources_first_line_cut_and_lowercased() {
        assert_eq!(host_name_of("Notebook.local\nsecond\n".into()).as_deref(), Some("notebook"));
        assert_eq!(host_name_of(" Notebook \n".into()).as_deref(), Some("notebook"));
        assert_eq!(host_name_of(".local\n".into()), None, "a name the cut leaves empty answers nothing, and the next source is asked");
        assert_eq!(host_name_of("  \n".into()), None, "an empty source answers nothing, and the next is asked");
        assert_eq!(host_name_of(String::new()), None);
        let BoxDefault { host_name: host, date } = host_name_and_date();
        assert!(!host.is_empty() && !host.contains('.') && host == host.to_lowercase(), "{host}");
        assert_eq!(civil_date(0), "1970-01-01");
        assert_eq!(date.len(), "yyyy-mm-dd".len(), "{date}");
    }

    /// `civil_date` names every day as the Gregorian calendar counts it —
    /// the date a permanent byline's default carries (§4.2 step 2) — checked
    /// over 100 000 days from the epoch, to 2243 (2000's leap day, and 2100's
    /// and 2200's skipped), at each day's first and last second, against a
    /// calendar counted day by day.
    #[test]
    fn civil_date_names_every_day_as_the_gregorian_calendar_counts_it() {
        let (mut y, mut m, mut d) = (1970u32, 1u32, 1u32);
        for day in 0..100_000u64 {
            let want = format!("{y:04}-{m:02}-{d:02}");
            assert_eq!(civil_date(day * 86_400), want, "the first second of day {day}");
            assert_eq!(civil_date(day * 86_400 + 86_399), want, "the last second of day {day}");
            let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
            let length = [31, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][m as usize - 1];
            d += 1;
            if d > length {
                (d, m) = (1, m + 1);
                if m > 12 {
                    (m, y) = (1, y + 1);
                }
            }
        }
        assert_eq!((y, m, d), (2243, 10, 17), "the count reached past 2200: day 100 000 is 2243-10-17");
    }

    /// The commands' own stops answer §2.3's code from the one renderer: a
    /// person door without a terminal a halt of the family, 3, and a label
    /// the record refuses a halt, 3 — beside the stops `shared.rs` holds to
    /// their codes.
    #[test]
    fn the_commands_own_stops_finish_with_their_exit_codes() {
        assert_eq!(finish(Ok(())), 0);
        assert_eq!(finish(Err(no_terminal(RETIRE).into())), 3);
        assert_eq!(finish(Err(record_refused(LabelError::Newline).into())), 3);
    }

    /// The person door's refusal is a halt's face — the state, its cause,
    /// the one act — naming the moments a person answers at that door, and
    /// the backup moment only where the door runs one.
    #[test]
    fn a_person_door_without_a_terminal_is_a_halt_naming_its_own_moments() {
        let Halt::Halt(face) = no_terminal(RETIRE) else { panic!("a HALT AND SURFACE member") };
        assert_eq!(face.state, "`retire` is a person door and requires a controlling terminal");
        assert!(face.cause.contains("what a person answers here — the preview's typed confirmation —"), "{}", face.cause);
        assert!(!face.cause.contains("backup moment"), "retire runs no backup moment: {}", face.cause);
        assert!(face.act.contains("scripted Person in-process"), "{}", face.act);
    }
}
