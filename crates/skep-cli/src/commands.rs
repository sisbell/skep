//! THE THIRTEEN COMMANDS, each exactly as `client.md` §2.2 writes it — one
//! file per command beneath this one, each a `pub fn` that `main`
//! dispatches to, every walk a library call — and what they share, private
//! here and so visible to each of them: the two streams, stdout DATA
//! (`data`, `data_verbatim`) and stderr TALK (`talk`) (§2.4); the refusals
//! and §2.3's exit codes (`halt`, `usage`, `no_terminal`), `usage` public
//! for `main`'s refusal of a command line it cannot parse; the plumbing from
//! the flags to a board, a store, a payload, a principal and a key; the
//! three facts' one spelling (`facts`); the outstanding-act line `keygen`
//! and `fingerprint` share (`OUTSTANDING_ACT`); and the whole-set compare's
//! held set and lines.
//! A halt is one block on stderr: the state, its cause, the one act
//! (AUTH-5.66; AUTH-5.67's key-file cell naming the path and the state).
//! THE PERSON DOORS — `claim`'s notebook arm, `keygen --anchors`, `enroll`'s
//! comparison, `recover`, `retire`, `rotate`, `handoff` with `--payload`,
//! `accept` without `--reprint` — refuse without a controlling terminal
//! through the CLI's `Person` (§2.4: the CLI's check, never the walk's).

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

use std::io::{self, Read, Write};
use std::path::Path;

use skep_client::board::Board;
use skep_client::derive::records::{Difference, Held};
use skep_client::derive::Mode;
use skep_client::dial::PlainHttp;
use skep_client::halt::Halt;
use skep_client::sheet::{render_inert, Facts};
use skep_client::store::{arm4_face, FileStore, KeyFacts, KeySelector, Purpose, StoreError};
use skep_identity::Fingerprint;

use crate::args::{Command, Usage, HELP};

/// DATA, to stdout.
fn data(line: impl AsRef<str>) {
    println!("{}", line.as_ref());
}

/// DATA, to stdout, as the bytes it came in — a body the CLI passes through
/// untouched (`health`'s, AUTH-5.86) — ended by a newline where it has none.
fn data_verbatim(body: &[u8]) {
    let mut out = io::stdout().lock();
    let _ = out.write_all(body);
    if !body.ends_with(b"\n") {
        let _ = out.write_all(b"\n");
    }
    let _ = out.flush();
}

/// TALK, to stderr.
fn talk(line: impl AsRef<str>) {
    eprintln!("{}", line.as_ref());
}

/// A halt rendered as its one block, its exit code answered.
fn halt(h: Halt) -> i32 {
    talk(format!("skep: {h}"));
    h.exit_code()
}

/// A usage refusal rendered with the help beneath it (§2.3's exit 2) — a
/// command's, and `main`'s for a command line it cannot parse.
pub fn usage(u: Usage) -> i32 {
    talk(format!("skep: {}\n\n{HELP}", u.0));
    2
}

/// The missing-TTY face (§2.4; §2.3's exit 3).
fn no_terminal(door: &str) -> i32 {
    talk(format!(
        "skep: `{door}` is a person door and requires a controlling terminal — it reads its prompts from the terminal and refuses \
         without one, so a wrapper over stderr and stdin cannot satisfy the backup moment with no paper and no person. A script \
         that must drive this walk drives the library's scripted Person in-process."
    ));
    3
}

fn board_of(c: &Command) -> Result<Board, Usage> {
    let origin = c.board()?;
    Ok(Board::new(origin, PlainHttp::new()))
}

fn store_of(c: &Command) -> Result<FileStore, Usage> {
    Ok(FileStore::open(c.dir()?))
}

/// A payload argument: a file, or `-` for stdin.
fn read_payload(arg: &str) -> Result<Vec<u8>, Halt> {
    if arg == "-" {
        let mut buf = Vec::new();
        io::stdin().read_to_end(&mut buf).map_err(|e| Halt::face("the payload could not be read from stdin", e.to_string(), "pipe the payload in"))?;
        return Ok(buf);
    }
    std::fs::read(arg).map_err(|e| Halt::face(format!("the payload file {arg} could not be read: {e}"), "AUTH-5.67: a mis-pathed file is a halt naming the path, never a fallback", "check the path"))
}

/// The principal: the one `given` — `Command::principal`'s answer, its
/// refusal already returned as exit 2 by the caller, before any read — else
/// the board's one binding in the store (§3.5's one-binding test).
fn principal_or_bound(given: Option<u64>, store: &FileStore, board: &Board) -> Result<u64, Halt> {
    if let Some(p) = given {
        return Ok(p);
    }
    let ps = store.principals_at(board.dialed())?;
    match ps.as_slice() {
        [one] => Ok(*one),
        [] => Err(Halt::face("no principal", "--principal (or SKEP_PRINCIPAL) is absent and the store holds no binding for this board", "pass --principal")),
        _ => Err(Halt::face("no principal", "--principal is absent and the store holds bindings for several principals at this board", "pass --principal")),
    }
}

/// The store's key for this board and principal (§3.5's lookup, `--key`
/// first), its public facts judged for `purpose` — an anchor file refused
/// where the key signs and read where it does not (§2.2's selection test;
/// P11) — its signer the store's (`KeyStore::signer`); the arm-4 face forked
/// on the claimant.
fn select_key(c: &Command, store: &FileStore, board: &Board, principal: u64, purpose: Purpose) -> Result<KeyFacts, Halt> {
    let sel = match c.key() {
        Some(path) => store.select(&KeySelector::Path(&path), purpose),
        None => store.select(&KeySelector::Board { origin: board.dialed(), principal: Some(principal) }, purpose),
    };
    match sel {
        Ok(key) => Ok(key),
        Err(StoreError::NoSelection { keys }) => Err(arm4_face(store, &keys, Mode::of(&board.health()?))),
        Err(e) => Err(e.into()),
    }
}

/// The machine's host name and today's date in UTC — the anchor boxes'
/// per-run default (§4.2 step 2), which becomes a permanent byline. The name
/// is the first that answers on §6's three platforms: `COMPUTERNAME`
/// (Windows), `HOSTNAME` (where a shell exports it), `/etc/hostname` (Linux),
/// then the `hostname` command's first line (macOS) — cut at its first dot
/// and lowercased, `this-machine` where none answers.
fn host_name_and_date() -> (String, String) {
    let host_name = std::env::var("COMPUTERNAME")
        .ok()
        .and_then(first_line)
        .or_else(|| std::env::var("HOSTNAME").ok().and_then(first_line))
        .or_else(|| std::fs::read_to_string("/etc/hostname").ok().and_then(first_line))
        .or_else(|| std::process::Command::new("hostname").output().ok().and_then(|out| String::from_utf8(out.stdout).ok()).and_then(first_line))
        .unwrap_or_else(|| "this-machine".to_string());
    let host_name = host_name.split('.').next().unwrap_or("this-machine").to_lowercase();
    let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    (host_name, civil_date(secs))
}

/// A host-name source's first line, trimmed; `None` where it is empty.
fn first_line(text: String) -> Option<String> {
    Some(text.lines().next().unwrap_or("").trim().to_string()).filter(|h| !h.is_empty())
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
fn facts(f: &Facts) {
    data(format!("account {}", f.account));
    data(format!("principal {}", f.principal));
    data(format!("origin {}", f.origin));
}

/// The outstanding act of a key enrolled nowhere — AUTH-5.32's pending state
/// named, CONDITIONED on the walk because one payload serves two (§2.2): the
/// line `keygen --payload` prints at exit, and the one `fingerprint` carries
/// beside every UNBOUND key, "the same conditioned outstanding-act line".
/// Each site adds the clauses its own state makes true.
const OUTSTANDING_ACT: &str = "Where it ADDS a device: take this payload to a device already signed in, run `skep enroll` there, and bring its three \
     facts back to `skep bind` here. Where it REPLACES a machine: `skep rotate --payload` there instead, then `skep bind` here.";

/// What this device HOLDS for the whole-set compare (AUTH-4.58's
/// detection): `record`'s entries — a `--payload` argument holding the
/// RECORD this device printed, `verify`'s; never `bind`'s, whose payload is
/// the reply — and each `anchors` file's public members beside `device`,
/// the store's key; `None` where neither is given.
fn held_set(store: &FileStore, record: Option<&str>, anchors: &[String], device: &KeyFacts) -> Result<Option<Vec<Held>>, Halt> {
    if record.is_none() && anchors.is_empty() {
        return Ok(None);
    }
    let mut held = Vec::new();
    if let Some(arg) = record {
        let bytes = read_payload(arg)?;
        let text = std::str::from_utf8(&bytes).map_err(|_| Halt::face("the payload is not UTF-8", "a canonical record is UTF-8 text", "re-take the payload"))?.trim();
        let entries = skep_identity::parse_enroll(text.as_bytes()).map_err(|e| Halt::face("the payload is not a canonical enrollment record", e.to_string(), "re-take it from the device that printed it"))?;
        for e in entries {
            held.push(Held { fingerprint: Fingerprint::of(&e.key), anchor: e.anchor, label: e.label().map(str::to_string) });
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

/// The whole-set compare's differences, one line each in AUTH-5.53's terms —
/// the face `verify` and `bind` halt with alike.
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
/// record, one line of TALK at `verify` and `bind` alike.
fn later_line(l: &Held) -> String {
    format!("later act: {} anchor={} label={}", l.fingerprint, l.anchor, l.label.as_deref().map(render_inert).unwrap_or_else(|| "(none)".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_host_name_is_a_sources_first_line_cut_and_lowercased() {
        assert_eq!(first_line("notebook.local\nsecond\n".into()).as_deref(), Some("notebook.local"));
        assert_eq!(first_line("  \n".into()), None, "an empty source answers nothing, and the next is asked");
        assert_eq!(first_line(String::new()), None);
        let (host, date) = host_name_and_date();
        assert!(!host.is_empty() && !host.contains('.') && host == host.to_lowercase(), "{host}");
        assert_eq!(civil_date(0), "1970-01-01");
        assert_eq!(date.len(), "yyyy-mm-dd".len(), "{date}");
    }
}
