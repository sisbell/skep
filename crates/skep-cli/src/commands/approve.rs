//! `skep approve`, the twenty-third command: a request approved
//! (REG-4.108; REG-4.123 steps 1 to 3).
//!
//! It is the approval's hand at a registry's door, the library's console
//! (`skep_client::ceremony::console`), in the two forms the door's policy
//! names by its `approval` term.
//!
//! **`skep approve <request>`** is an officer's: `<request>` is the
//! request's link address, as `skep review` prints it. The approval's check
//! is run again on it. Where it passes, the officer is shown the request's
//! keys and types the first 8 hex of its device key's fingerprint, and the
//! approval is written whole and in order: the org's node account and its
//! first key record, the approval link, the binding with its read-back, the
//! approved answer. Where it fails, the request is answered refused, with
//! its fault, and nothing else is written. A person door: the confirmation
//! is read at the terminal. Stdout carries what was written — `approved
//! <request>`, then `prefix`, `account`, `principal` and `answer` lines; or
//! `refused <request>`, then `fault` and `answer` — and stderr each act as
//! it is made. A run that stopped part way is resumed by running it again.
//! Where another console of the registrar's answered the request, or keyed
//! its account first, while this one ran, no answer is sent, a prefix this
//! run bound is retired, stderr says which, and stdout carries `yielded
//! <request>` (REG-4.86).
//!
//! **`skep approve --auto`** is the unattended hand: it takes no request,
//! and answers the whole queue — approving what passes, refusing what
//! fails, never denying. It runs in the foreground until it is stopped,
//! reading the queue every [`QUEUE_INTERVAL`]; it needs no terminal, so it
//! runs in a container, its key the registrar's labeled device key
//! (`--key`, `SKEP_KEY`, or the store's own lookup) and its key store the
//! folder it is handed (`--dir`, `SKEP_KEYSTORE`). It refuses to start
//! unless the policy standing is open admission approved by `auto`, and
//! stops, saying why, when a later version withdraws that. It catches
//! SIGINT and SIGTERM itself — a container's first process is given no
//! default handling — and each only sets a flag the loop reads between two
//! requests: an act under way runs to its end, and the process then ends
//! with exit 0. A kill inside an act is safe: every act resumes by
//! reading. Stdout carries one line an act, `approved <request> <prefix>
//! <account> <principal> <answer>`, `refused <request> <fault> <answer>`
//! or `yielded <request>`; stderr each act as it is made. A board that does
//! not answer is said and tried again at the next pass; any other halt ends
//! the run.
//!
//! The principal is the one the board seats at its claimant, the door's own
//! account, where `--principal` is omitted. A line with neither a request
//! nor `--auto`, or a request that is no address, is a usage refusal, exit
//! 2, before any socket opens.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use skep_client::board::{Board, Scope};
use skep_client::ceremony::console::{self, auto_round, read_queue, unattended_withheld, Console, Door, Hand, Outcome};
use skep_client::ceremony::handshake::{handshake, Site};
use skep_client::dial::{plaintext_non_loopback_warning, Dialer};
use skep_client::halt::Halt;
use skep_client::resolve::mirror_dialer;
use skep_client::store::{KeySelector, KeyStore, Purpose};

use super::{board_of, clipped, data, key_named, registrar_principal, require_terminal, select_key, store_of, talk, Door as PersonDoor, Stop};
use crate::args::{CommandLine, Usage};
use crate::terminal::Terminal;

/// How long the unattended hand waits between two reads of the queue.
const QUEUE_INTERVAL: Duration = Duration::from_secs(10);

/// How often the wait between two reads looks at the stop flag.
const STOP_POLL: Duration = Duration::from_millis(100);

pub fn approve(c: &CommandLine) -> Result<(), Stop> {
    let board = board_of(c)?;
    let store = store_of(c)?;
    let given = c.principal()?;
    let key_file = c.key_file()?;
    let auto = c.switch("--auto");
    // The line's own judgment, ahead of the door and of any socket.
    let request = match (c.operand(), auto) {
        (Some(request), _) if !skep_client::address::is_address_text(request) => {
            return Err(Usage(format!("<request>: '{}' is not an address — a request is named by its link address, as `skep review` prints it", clipped(request))).into());
        }
        (Some(request), _) => Some(request),
        (None, true) => None,
        (None, false) => {
            return Err(Usage("a request is required: `skep approve <request>`, the request's link address as `skep review` prints it — or `skep approve --auto`, the unattended hand".into()).into());
        }
    };
    if !auto {
        require_terminal(PersonDoor { form: "approve <request>", moments: "the comparison of the request's keys and its typed confirmation" })?;
    }
    if let Some(w) = plaintext_non_loopback_warning(board.dialed()) {
        talk(w);
    }
    let principal = registrar_principal(&board, given)?;
    let key = select_key(key_file.as_deref(), &store, &board, principal, Purpose::Sign)?;
    let signer = store.signer(&KeySelector::Path(&key.path))?;
    let dialer: Arc<dyn Dialer> = Arc::new(mirror_dialer());
    let hand = if auto { Hand::Unattended } else { Hand::Officer };
    let console = Console { board: &board, store: &store, signer: &*signer, principal, hand, dialer };
    talk(format!("acting as principal {principal}, the registrar's, with key {}", key_named(&key)));
    match request {
        Some(request) => {
            let outcome = console::approve(&console, &mut Terminal, request)?;
            said(&outcome, false)
        }
        None => unattended(&board, &console),
    }
}

/// Prints one outcome as data: an officer's in lines, the unattended
/// hand's as one line.
///
/// # Errors
///
/// A write stdout refuses is a halt.
fn said(outcome: &Outcome, one_line: bool) -> Result<(), Stop> {
    match outcome {
        Outcome::Approved(a) if one_line => data(format!("approved {} {} {} {} {}", a.request, a.prefix, a.node_address, a.node_principal, a.answer))?,
        Outcome::Refused(r) if one_line => data(format!("refused {} {} {}", r.request, r.fault.as_str(), r.answer))?,
        // Another console's request: this run sent no answer, and the walk
        // said why.
        Outcome::Yielded(y) => data(format!("yielded {}", y.request))?,
        Outcome::Approved(a) => {
            talk(format!(
                "the registration is written whole: the binding {} and the answer {} cite the policy version {}, and the applicant collects it within {} seconds by opening its node account's first signed session and depositing its endpoint",
                a.binding, a.answer, a.policy, a.collection_interval
            ));
            data(format!("approved {}", a.request))?;
            data(format!("prefix {}", a.prefix))?;
            data(format!("account {}", a.node_address))?;
            data(format!("principal {}", a.node_principal))?;
            data(format!("answer {}", a.answer))?;
        }
        Outcome::Refused(r) => {
            data(format!("refused {}", r.request))?;
            data(format!("fault {}", r.fault.as_str()))?;
            data(format!("answer {}", r.answer))?;
        }
    }
    Ok(())
}

/// Runs the unattended hand until it is stopped.
///
/// # Errors
///
/// Before the first pass: the reads' halts; a policy that does not open
/// the unattended hand; and a key that opens no session as the registrar.
/// Then a policy version that withdraws the hand, and any halt of a pass
/// but a board that did not answer, which is said and tried again.
fn unattended(board: &Board, console: &Console<'_>) -> Result<(), Stop> {
    // It refuses to start unless the policy opens it, and unless its key
    // opens the registrar's session.
    let door = Door::read(board, console.dialer.clone())?;
    if let Some(why) = unattended_withheld(&read_queue(board, None, &door)?) {
        return Err(withheld("does not start", &why).into());
    }
    handshake(board, Scope::Content, console.signer, console.principal, Site::Console)?.close()?;
    // The two signals only set a flag: the loop reads it between two
    // requests, and between two reads of the queue.
    let stop = Arc::new(AtomicBool::new(false));
    for signal in [signal_hook::consts::SIGTERM, signal_hook::consts::SIGINT] {
        signal_hook::flag::register(signal, Arc::clone(&stop)).map_err(|e| {
            Halt::face(
                "the unattended hand could not take its stop signals, and does not start",
                format!("registering a handler for signal {signal} failed: {e}"),
                "this is a fault of this build or its platform; nothing was written",
            )
        })?;
    }
    let stopping = || stop.load(Ordering::SeqCst);
    talk(format!(
        "the unattended hand is watching the door `{}`: it reads the queue every {} seconds, approves what passes the approval's check and refuses what fails it, \
         and denies nothing. Stop it with SIGINT or SIGTERM: an act under way runs to its end first, and a kill inside one is safe — every act resumes by reading",
        door.id,
        QUEUE_INTERVAL.as_secs()
    ));
    while !stopping() {
        match auto_round(console, &mut Terminal, &stopping) {
            Ok(round) => {
                for act in &round.acts {
                    said(act, true)?;
                }
                if let Some(why) = round.withheld {
                    return Err(withheld("stops", &why).into());
                }
                if round.stopped {
                    break;
                }
            }
            Err(Halt::Dial(e)) => talk(format!("the board did not answer ({e}); nothing is assumed written, and the queue is read again in {} seconds", QUEUE_INTERVAL.as_secs())),
            Err(halt) => return Err(halt.into()),
        }
        let mut waited = Duration::ZERO;
        while waited < QUEUE_INTERVAL && !stopping() {
            std::thread::sleep(STOP_POLL);
            waited += STOP_POLL;
        }
    }
    talk("the unattended hand is stopped, between two requests: nothing is left half done");
    Ok(())
}

/// Returns the halt the unattended hand comes to where the policy does not
/// open it.
fn withheld(does: &str, why: &str) -> Halt {
    Halt::face(
        format!("the unattended hand {does}: {why}"),
        "`skep approve --auto` approves only at a door whose policy is open admission approved by `auto` (REG-4.108); under every other policy the approval is an officer's",
        "publish the policy the door means (`skep set-policy <file>`), or approve by hand: `skep approve <request>`; nothing was written",
    )
}
