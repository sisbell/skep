//! The three answers, and the approval's write list (REG-4.85, REG-4.90,
//! REG-4.99; REG-4.123 steps 1 to 3).
//!
//! Every answer is a registration record in the binding-writing account's
//! own doc 1 whose `to` is the request's link, written through the one
//! registry-record composition. [`approve`] runs the framing re-check's
//! verdict into one of two: the approval — the mint, the binding with its
//! read-back, the approved answer, in the parent module's order — or the
//! refused answer, the fault its one member, and no `delegate`, no genesis
//! and no binding. [`deny`] writes the denied answer, citing a clause of
//! the policy version standing.
//!
//! Every judgment a read can make comes before the first write: that a
//! policy stands and what it opens, that the address names a request on
//! this door's queue with no answer on its thread, that the console's
//! account is the door's, that a denial's clause exists. An officer is
//! asked once, by the request's device-key fingerprint, before anything is
//! written; the unattended hand is asked nothing.

use skep_address::Address;
use skep_identity::Fingerprint;
use skep_registry::{t_approval, t_registration, Admission, Approved, ApprovalHand, Denied, Digits, Disposition, Fault, Principal, Refused, RegistrationBody, RegistrationKind};

use super::queue::{Queue, Request, Thread, Verdict};
use super::{no_policy, say, Console, Door, Hand, FIRST_ROOT_PREFIX, ROOT_TIER};
use crate::address::{document_of, parent_account, parse_address};
use crate::board::{Board, KeySetAnswer, Scope, T_ENROLL};
use crate::ceremony::deposit::{deposit, Deposit, DepositHalt, DepositKind, DepositOutcome};
use crate::ceremony::first_session::{delegate_persisted, Delegated};
use crate::ceremony::handshake::{handshake, handshake_prechecked, Session, Site};
use crate::ceremony::policy::Standing;
use crate::ceremony::registry_record::{
    binding_history, deposit_answer, deposit_binding, holder_of, link_approval, link_order, links_homed, links_to, next_prefix, one_address, registration_at, stored_link, AnswerDeposit, Atoms,
    BindingDeposit,
};
use crate::derive::{origin_arm, principal_of, walk_to_set, KeyDiagnosis, Mode, PreCheck};
use crate::halt::Halt;
use crate::person::{Confirmation, Consent, Person};
use crate::resolve::guest_resolve;
use crate::sheet::{group_hex, render_inert};
use crate::sign::{fresh_bytes, fresh_principal_id};
use crate::store::{Binding, KeyStore};

/// The most passes of bind-then-read-back one approval makes (REG-2.17).
///
/// Each pass that loses takes the next prefix, and a console loses only
/// where another's binding for that prefix already stands: this many in a
/// row is a fault, never a race.
const MAX_BINDING_PASSES: usize = 8;

/// An approval, as written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Approval {
    /// The request approved, by its link's address.
    pub request: String,
    /// The prefix bound, as the approved answer names it once.
    pub prefix: String,
    /// The node account minted.
    pub node_address: String,
    /// The node account's principal.
    pub node_principal: u64,
    /// The genesis link: the node account's first key record.
    pub genesis: String,
    /// The approval link, from the genesis to the request.
    pub approval: String,
    /// The binding's link.
    pub binding: String,
    /// The approved answer's link.
    pub answer: String,
    /// The policy version the answer cites.
    pub policy: String,
    /// The collection interval the answer copies from that version.
    pub collection_interval: String,
}

/// A refusal, as written: the failed re-check's answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Refusal {
    /// The request refused, by its link's address.
    pub request: String,
    /// The fault the answer states.
    pub fault: Fault,
    /// What the check found, in this console's words.
    pub why: String,
    /// The refused answer's link.
    pub answer: String,
}

/// A denial, as written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Denial {
    /// The request denied, by its link's address.
    pub request: String,
    /// The policy version cited.
    pub policy: String,
    /// The clause cited: its position in that version's `grounds`, from 1.
    pub clause: u64,
    /// The clause's words, as the version states them.
    pub ground: String,
    /// The denied answer's link.
    pub answer: String,
}

/// A request this run left to another console (REG-4.86).
///
/// Two consoles of one registrar may take one request in the same interval
/// — an officer's and the unattended hand's. The registration is the first
/// genesis by journal order naming the request's node keys, and a request
/// has one answer: the run that finds another's ahead of its own sends
/// none, and retires the binding it wrote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Yielded {
    /// The request, by its link's address.
    pub request: String,
    /// The account the registration is, where another console's genesis
    /// stands first; `None` where the thread was answered without one.
    pub account: Option<String>,
    /// The answer standing on the thread, where one stands.
    pub answer: Option<String>,
    /// The targetless binding this run wrote to retire its own, where it
    /// had bound a prefix to an account that is not the registration's.
    pub retired: Option<String>,
    /// What this run read, in this console's words.
    pub why: String,
}

/// What the approval's hand did with a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The request passed the re-check and is approved.
    Approved(Approval),
    /// The request failed the re-check and is refused.
    Refused(Refusal),
    /// Another console answered the request, or holds its registration:
    /// this run sent no answer.
    Yielded(Yielded),
}

/// Returns a per-run token: every write of one run carries it in its id.
fn run_token() -> String {
    crate::hex::encode(&fresh_bytes(8))
}

/// Returns the thread of the request `link` names, where it can be answered.
///
/// # Errors
///
/// An address that names no request on this door's queue, and a request
/// already answered: each a halt, before any write.
fn open_thread<'q>(queue: &'q Queue, door: &Door, link: &str) -> Result<&'q Thread, Halt> {
    let Some(thread) = queue.thread(link) else {
        return Err(Halt::face(
            format!("`{}` names no request at this door", render_inert(link)),
            format!(
                "a request is named by its link's address, as `skep review` prints it: a link typed a request's row whose `to` is this door's account, {}, \
                 written on a home the door's policy admitted at the request's own position (REG-4.78) — and no such link stands at that address",
                door.account
            ),
            "run `skep review` and copy the address beside the request; nothing was written",
        ));
    };
    if let Some(answer) = thread.answers.first() {
        let row = match &answer.body {
            RegistrationBody::Approved(_) => "approved",
            RegistrationBody::Refused(_) => "refused",
            RegistrationBody::Denied(_) => "denied",
            _ => "answered",
        };
        return Err(Halt::face(
            format!("the request {link} is already {row}"),
            format!("the answer {} stands on its thread, and a request is answered once: a correction is a further act of its own (REG-1.43)", answer.link),
            "nothing was written; `skep review` lists it where it stands",
        ));
    }
    Ok(thread)
}

/// Opens the console's own signed session, and holds it to the door.
///
/// # Errors
///
/// The handshake's halts; and a session whose account is not the door's
/// binding-writing account, closed and faced before any write.
fn own_session<'b>(console: &Console<'b>, door: &Door, scope: Scope) -> Result<Session<'b>, Halt> {
    let session = handshake(console.board, scope, console.signer, console.principal, Site::Console)?;
    if session.account() != door.account {
        let account = session.account().to_string();
        let _ = session.close();
        return Err(Halt::face(
            format!("principal {} acts as {account}, which does not write this board's bindings", console.principal),
            format!("the door's binding-writing account is the board's claimant, {}, and every answer and binding is written from its own signed session (REG-2.4; REG-4.108)", door.account),
            "run it with the registrar's own principal (`--principal`), or leave the principal out: it is read off the board; nothing was written",
        ));
    }
    Ok(session)
}

/// Asks an officer for the one typed confirmation of an act.
///
/// The row is the request's device-key fingerprint, its first eight hex:
/// the key the applicant's own client holds, which the officer compares
/// out of band before answering for it. A request past the shape was never
/// parsed and names no key this console read: its row is the act's own
/// word. `act` is the verb and `done` its participle, as the faces say
/// them.
///
/// # Errors
///
/// A decline, a wrong row and an abandoned prompt, each a halt naming that
/// nothing was written.
fn consent(person: &mut dyn Person, request: &Request, act: &str, done: &str, statement: String) -> Result<(), Halt> {
    let fingerprint = Fingerprint::parse_hex(&request.signer).map(|fp| fp.to_hex());
    let (text, expected, row) = match &fingerprint {
        Some(fingerprint) => (
            format!(
                "{statement}\n  the request's device key: {}\n  to {act} this request, type the first 8 hex of that fingerprint; or `no`",
                group_hex(fingerprint).replace('\n', "\n                            ")
            ),
            fingerprint.chars().take(8).collect::<String>(),
            "the first 8 hex of the request's device-key fingerprint",
        ),
        None => (format!("{statement}\n  this request was never parsed, and names no key this console read\n  to {act} it, type `{act}`; or `no`"), act.to_string(), "the act's own word"),
    };
    let answer = person
        .confirm_typed(Consent(Confirmation { text, expected: expected.clone() }))
        .map_err(|_| Halt::face(format!("the request was not {done}: the confirmation was abandoned"), "no answer was typed", "nothing was written; run it again to answer"))?;
    if answer.trim().eq_ignore_ascii_case(&expected) {
        return Ok(());
    }
    Err(Halt::face(
        format!("the request was not {done}: the confirmation was declined"),
        format!("the typed answer was not `{expected}`, {row}"),
        "nothing was written; run it again where you mean to answer it",
    ))
}

/// Says the request's keys, each beside its label, for the comparison.
fn say_keys(person: &mut dyn Person, request: &Request) {
    for key in &request.keys {
        say(
            person,
            "AUTH-5.57 step 4",
            format!(
                "{} — `{}`\n  {}",
                key.named,
                if key.label.is_empty() { "(no label)".to_string() } else { render_inert(&key.label) },
                group_hex(&key.fingerprint.to_hex()).replace('\n', "\n  ")
            ),
        );
    }
}

/// Answers the request at `request` as the approval's hand does.
///
/// It reads the door and its queue, then runs the request's verdict: where
/// the re-check passes, the approval, whole and in order; where it fails,
/// the refused answer and nothing else. An officer is asked for one typed
/// confirmation before the first write; the unattended hand is not.
///
/// # Errors
///
/// Before any write: the reads' halts; a door with no policy standing; a
/// door that is not open admission, naming its mode; a policy naming no
/// hand this console knows, or — for the unattended hand — not the `auto`
/// hand; an address naming no request on this door's queue; a request
/// already answered; a console whose account is not the door's; and the
/// confirmation declined. Then each write's own halts, each naming what
/// stands and that running it again resumes by reading.
pub fn approve(console: &Console<'_>, person: &mut dyn Person, request: &str) -> Result<Outcome, Halt> {
    let door = Door::read(console.board, console.dialer.clone())?;
    let queue = super::read_queue(console.board, None, &door)?;
    answer(console, person, &door, &queue, request)
}

/// Runs [`approve`] over a door and a queue the caller already read.
///
/// # Errors
///
/// [`approve`]'s, past the reads.
pub(super) fn answer(console: &Console<'_>, person: &mut dyn Person, door: &Door, queue: &Queue, request: &str) -> Result<Outcome, Halt> {
    let standing = queue.policy.standing().map_err(|no| no_policy(&no))?;
    if standing.policy.admission != Admission::Open {
        return Err(Halt::face(
            format!("this door's admission is `{}`, and `skep approve` approves at an open door alone", standing.policy.admission.as_str()),
            format!(
                "the policy standing, {}, is not open admission: an invitation-only door takes its approvals by sponsorship and an n-vouches door by counted \
                 vouches, and this build performs neither",
                standing.version.address
            ),
            "`skep review` and `skep deny` work at every admission mode; nothing was written",
        ));
    }
    let hand = standing.policy.approval_hand();
    let opened = match (console.hand, hand) {
        (_, None) => false,
        (Hand::Officer, Some(_)) => true,
        (Hand::Unattended, Some(named)) => named == ApprovalHand::Unattended,
    };
    if !opened {
        return Err(Halt::face(
            match console.hand {
                Hand::Unattended => "the policy standing does not open the unattended hand".to_string(),
                Hand::Officer => "the policy standing opens no approval".to_string(),
            },
            format!(
                "{} names `approval` `{}`: `officer` is an officer's signed session, `auto` the unattended console under open admission, and any other value opens no \
                 approval at all (REG-4.108)",
                standing.version.address,
                render_inert(&standing.policy.approval)
            ),
            "publish the policy the door means (`skep set-policy <file>`); nothing was written",
        ));
    }
    let thread = open_thread(queue, door, request)?;
    match &thread.request.verdict {
        Verdict::Fails { fault, why } => {
            say(
                person,
                "REG-4.85",
                format!(
                    "the request {} FAILS the approval's check: {why}. It is answered REFUSED, `{}` — a fact about the payload, never a judgment of the person — \
                     and no account is made, no key written and no prefix bound.",
                    thread.request.link,
                    fault.as_str()
                ),
            );
            let session = own_session(console, door, Scope::Content)?;
            let written = refuse(console, person, &session, door, &thread.request, *fault, why);
            let _ = session.close();
            written
        }
        Verdict::Passes => {
            if console.hand == Hand::Officer {
                say(
                    person,
                    "REG-4.123",
                    format!(
                        "APPROVING the request {} makes, in this order: a node account on this board and its first key record — the request's node enrolment, \
                         verbatim; the binding of the next prefix to that account; and the approved answer on the request's thread, naming the prefix once, the \
                         account and its principal. Each is PERMANENT and PUBLIC, written under your key as the registrar's. Its {} keys follow: compare them \
                         with the applicant, out of band, before you answer.",
                        thread.request.link,
                        thread.request.keys.len()
                    ),
                );
                say_keys(person, &thread.request);
                consent(person, &thread.request, "approve", "approved", format!("approve the request {}?", thread.request.link))?;
            }
            let session = own_session(console, door, Scope::Full)?;
            let written = run_approval(console, person, &session, door, thread, &standing);
            let _ = session.close();
            written
        }
    }
}

/// An answer standing on a request's thread, as a read just made finds it.
struct Answered {
    /// The answer's link.
    link: String,
    /// The node account an approved answer names; `None` at a refused or a
    /// denied one.
    approves: Option<String>,
}

/// Returns the first answer on `request`'s thread, read now.
///
/// It is the read made before every answer is written: the registration
/// records homed in the door account's own doc 1 whose `to` is the
/// request's link and whose row is an answer's (REG-4.79), the first by
/// journal order. A request is answered once, and the queue a run began
/// from may be older than another console's answer.
///
/// # Errors
///
/// The reads' errors.
fn answer_standing(board: &Board, door: &Door, request: &str) -> Result<Option<Answered>, Halt> {
    let mut links = links_to(board, None, &t_registration().to_string(), request)?;
    links.retain(|link| document_of(link).as_deref() == Some(door.home.as_str()));
    links.sort_by_key(|link| link_order(link));
    links.dedup();
    let mut atoms = Atoms::new(board, None);
    for link in links {
        let Some(entry) = registration_at(board, None, &mut atoms, &link)? else { continue };
        if one_address(&entry.stored.value.to) != Some(request) || !matches!(entry.kind, RegistrationKind::Approved | RegistrationKind::Refused | RegistrationKind::Denied) {
            continue;
        }
        let approves = match entry.record {
            Ok(record) => match record.body {
                RegistrationBody::Approved(approved) => Some(approved.node_address.to_string()),
                _ => None,
            },
            Err(_) => None,
        };
        return Ok(Some(Answered { link, approves }));
    }
    Ok(None)
}

/// Returns the approval link from `genesis` to `request`, where one stands.
///
/// It is the read made before the approval link is written: the links of
/// the approval row homed in the door account's own doc 1, from exactly
/// that genesis to exactly that request.
///
/// # Errors
///
/// The reads' errors.
fn approval_link_from(board: &Board, door: &Door, genesis: &str, request: &str) -> Result<Option<String>, Halt> {
    let row = t_approval().to_string();
    let mut links = links_to(board, None, &row, request)?;
    links.retain(|link| document_of(link).as_deref() == Some(door.home.as_str()));
    links.sort_by_key(|link| link_order(link));
    links.dedup();
    for link in links {
        let Some(stored) = stored_link(board, None, &link)? else { continue };
        if stored.value.typed_exactly(&row) && one_address(&stored.value.to) == Some(request) && one_address(&stored.value.from) == Some(genesis) {
            return Ok(Some(link));
        }
    }
    Ok(None)
}

/// Writes the refused answer on a request's thread (REG-4.85).
///
/// The thread is read again first: where another console answered the
/// request since this run's queue was read, no second answer is written.
///
/// # Errors
///
/// The reads' errors and the deposit's halts.
fn refuse(console: &Console<'_>, person: &mut dyn Person, session: &Session<'_>, door: &Door, request: &Request, fault: Fault, why: &str) -> Result<Outcome, Halt> {
    if let Some(standing) = answer_standing(console.board, door, &request.link)? {
        return Ok(Outcome::Yielded(yielded(person, request, standing.approves, Some(standing.link), None)));
    }
    let body = RegistrationBody::Refused(Refused { fault });
    let id = format!("console.{}.refused", run_token());
    let done = deposit_answer(console.board, session.token(), &AnswerDeposit { home: &door.home, request: &request.link, body: &body, hand: console.signer, id: &id })?;
    Ok(Outcome::Refused(Refusal { request: request.link.clone(), fault, why: why.to_string(), answer: done.link }))
}

/// Says a yield, and answers it.
///
/// `account` is the registration's account where another console's genesis
/// stands first, `answer` the answer standing on the thread, and `retired`
/// the targetless binding this run wrote to retire its own.
fn yielded(person: &mut dyn Person, request: &Request, account: Option<String>, answer: Option<String>, retired: Option<String>) -> Yielded {
    let why = match (&answer, &account) {
        (Some(answer), _) => format!("the answer {answer} stands on its thread: another console of this registrar's answered it while this one ran, and a request is answered once"),
        (None, Some(account)) => format!(
            "another console of this registrar's keyed {account} for this request first: the first key record by journal order naming a request's node keys is its registration (REG-4.86), and that console answers it"
        ),
        (None, None) => "another console of this registrar's holds this request".to_string(),
    };
    let retiring = match &retired {
        Some(link) => format!(" The prefix this run bound is retired by {link}, never to be named again, and the account this run made stands unbound"),
        None => String::new(),
    };
    say(person, "REG-4.86", format!("the request {} is LEFT to the other console, and no answer is sent: {why}.{retiring}", request.link));
    Yielded { request: request.link.clone(), account, answer, retired, why }
}

/// Denies the request at `request`, citing clause `clause` (REG-4.99).
///
/// The denied answer cites the policy version standing at the denial by
/// its address, and the ground by its position in that version's `grounds`,
/// counted from 1. It is an officer's act alone, at every admission mode,
/// and runs no re-check: a denial is the registrar's judgment under a
/// published clause, never a fact about the payload. The officer is asked
/// once before the write.
///
/// # Errors
///
/// Before any write: a hand that is not an officer's; the reads' halts; a
/// door with no policy standing, which has no ground to cite; a clause
/// that is zero or past the version's `grounds`; an address naming no
/// request on this door's queue; a request already answered, or one whose
/// approval has begun; a console whose account is not the door's; and the
/// confirmation declined. Then the deposit's halts.
pub fn deny(console: &Console<'_>, person: &mut dyn Person, request: &str, clause: u64) -> Result<Denial, Halt> {
    if console.hand != Hand::Officer {
        return Err(Halt::face(
            "a denial is an officer's alone",
            "the denied answer is the registrar's judgment under a published clause, written from an officer's signed session at every admission policy; the unattended hand approves and refuses, and never denies (REG-4.99)",
            "nothing was written",
        ));
    }
    let door = Door::read(console.board, console.dialer.clone())?;
    let queue = super::read_queue(console.board, None, &door)?;
    let standing = queue.policy.standing().map_err(|no| no_policy(&no))?;
    let grounds = &standing.policy.grounds;
    let Some(ground) = clause.checked_sub(1).and_then(|index| usize::try_from(index).ok()).and_then(|index| grounds.get(index)) else {
        return Err(Halt::face(
            format!("the policy standing has no clause {clause}"),
            format!(
                "{} states {} ground{}, cited by position from 1 (REG-4.99): a denial cites a clause the door published, and none stands at {clause}",
                standing.version.address,
                grounds.len(),
                if grounds.len() == 1 { "" } else { "s" }
            ),
            "name a clause the policy states, or publish the ground first (`skep set-policy <file>`); nothing was written",
        ));
    };
    let thread = open_thread(&queue, &door, request)?;
    if let Some(approval) = &thread.approval {
        return Err(Halt::face(
            format!("the request {request} has an approval under way, and is not denied"),
            format!("the approval link {} ties an account already made to it: a run of `skep approve` stopped before its answer", approval.link),
            format!("finish it — `skep approve {request}` resumes by reading; nothing was written"),
        ));
    }
    say(
        person,
        "REG-4.99",
        format!(
            "DENYING the request {request} writes one answer on its thread, PERMANENT and PUBLIC: a citation of clause {clause} of the policy version {} — \
             `{}` — and nothing about the applicant. A denial binds this request and never the party: a fresh request under fresh keys is a new one.",
            standing.version.address,
            render_inert(ground)
        ),
    );
    consent(person, &thread.request, "deny", "denied", format!("deny the request {request} under clause {clause}?"))?;
    let digits = Digits::new(clause.to_string()).ok_or_else(|| Halt::face("the clause cannot be spelled", "a position is decimal digits", "this is a fault in this client; nothing was written"))?;
    let policy = policy_address(&standing)?;
    let body = RegistrationBody::Denied(Denied { policy, clause: digits });
    let session = own_session(console, &door, Scope::Content)?;
    // The thread, read again now: the confirmation may have stood a while,
    // and a request is answered once.
    let written = match still_open(console.board, &door, &thread.request.link) {
        Ok(()) => {
            let id = format!("console.{}.denied", run_token());
            deposit_answer(console.board, session.token(), &AnswerDeposit { home: &door.home, request: &thread.request.link, body: &body, hand: console.signer, id: &id })
        }
        Err(halt) => Err(halt),
    };
    let _ = session.close();
    let done = written?;
    Ok(Denial { request: thread.request.link.clone(), policy: standing.version.address.clone(), clause, ground: ground.clone(), answer: done.link })
}

/// Checks, by a read made now, that a request can still be denied.
///
/// # Errors
///
/// An answer written on the thread, or an approval begun for the request,
/// since this run's queue was read: a halt, before the write; and the
/// reads' errors.
fn still_open(board: &Board, door: &Door, request: &str) -> Result<(), Halt> {
    if let Some(standing) = answer_standing(board, door, request)? {
        return Err(Halt::face(
            format!("the request {request} was answered while this denial waited, and is not denied"),
            format!("the answer {} stands on its thread — another console of this registrar's wrote it — and a request is answered once", standing.link),
            "nothing was written; `skep review` lists the request where it stands",
        ));
    }
    let row = t_approval().to_string();
    let mut begun = links_to(board, None, &row, request)?;
    begun.retain(|link| document_of(link).as_deref() == Some(door.home.as_str()));
    for link in begun {
        let Some(stored) = stored_link(board, None, &link)? else { continue };
        if stored.value.typed_exactly(&row) && one_address(&stored.value.to) == Some(request) {
            return Err(Halt::face(
                format!("an approval of the request {request} began while this denial waited, and it is not denied"),
                format!("the approval link {link} ties an account already made to it: another console of this registrar's is approving it"),
                "nothing was written; `skep review` lists the request where it stands",
            ));
        }
    }
    Ok(())
}

/// Returns the address of the policy version standing, as a body cites it.
fn policy_address(standing: &Standing<'_>) -> Result<Address, Halt> {
    parse_address(&standing.version.address).ok_or_else(|| Halt::face("the policy version's address cannot be spelled", standing.version.address.clone(), "this is a fault in the board; nothing was written"))
}

/// Returns the key records homed in the registrar's doc 1, in journal order.
///
/// Each is an enroll link's address beside the account it names: the
/// genesis registry of every node account this door admits (REG-4.86). The
/// read is the windowed search over the home and the enroll type, drained,
/// a guest's — the home is published — and each link is read back for its
/// stored type and its one target.
///
/// # Errors
///
/// The reads' errors.
fn key_records(board: &Board, door: &Door) -> Result<Vec<(String, String)>, Halt> {
    let mut links = links_homed(board, None, &door.home, T_ENROLL)?;
    links.sort_by_key(|link| link_order(link));
    links.dedup();
    let mut records = Vec::new();
    for link in links {
        let Some(stored) = stored_link(board, None, &link)? else { continue };
        if !stored.value.typed_exactly(T_ENROLL) {
            continue;
        }
        if let Some(subject) = one_address(&stored.value.to) {
            records.push((link, subject.to_string()));
        }
    }
    Ok(records)
}

/// Returns the account a genesis in the registrar's doc 1 names for these
/// fingerprints.
///
/// It is REG-4.86's read, made before every mint and again in the
/// read-back's pass: the genesis registry — the registrar's own doc 1 — is
/// read for a genesis naming the request's node fingerprints, the whole
/// set. Each top-level account a key record there names is asked for its
/// set, in journal order, and the first whose set holds every one of them
/// is the registration: its genesis link, and the account.
///
/// # Errors
///
/// The reads' errors.
fn standing_genesis(board: &Board, door: &Door, fingerprints: &[Fingerprint]) -> Result<Option<(String, String)>, Halt> {
    if fingerprints.is_empty() {
        return Ok(None);
    }
    let mut seen: Vec<String> = Vec::new();
    for (link, subject) in key_records(board, door)? {
        if subject == door.account || parent_account(&subject).is_some() || seen.contains(&subject) {
            continue;
        }
        seen.push(subject.clone());
        let KeySetAnswer::Set(set) = board.key_set(&subject)? else { continue };
        if fingerprints.iter().all(|fp| set.enrolled(fp).is_some() || set.retired(fp).is_some()) {
            return Ok(Some((link, subject)));
        }
    }
    Ok(None)
}

/// Returns the genesis link the registrar's doc 1 holds for `account`.
///
/// # Errors
///
/// The reads' errors.
fn genesis_link_of(board: &Board, door: &Door, account: &str) -> Result<Option<String>, Halt> {
    Ok(key_records(board, door)?.into_iter().find(|(_, subject)| subject == account).map(|(link, _)| link))
}

/// An account an earlier run of this store delegated for a node account.
enum Pending {
    /// The `delegate` committed and the account holds no key: resumed.
    Delegated { account: String },
    /// The `new_id` was persisted and its `delegate` never landed.
    Unsent { account: String, principal: u64 },
}

/// Returns what this store's persist-first lines say of the node tier.
///
/// A line is a cache and never a source (REG-4.109): each top-level line
/// at this board other than the door's own is read back by
/// `principal_prefix` and the account's set. One whose `delegate` committed
/// at its address, the account holding no key, is an approval stopped
/// between its `delegate` and its genesis — the account the next mint
/// takes, so no second is delegated. A store whose bindings cannot be read
/// answers none.
///
/// # Errors
///
/// The reads' errors.
fn pending_account(console: &Console<'_>, door: &Door, node: &str) -> Result<Option<Pending>, Halt> {
    let board = console.board;
    let top_level = format!("{node}.0.");
    let mut unsent = None;
    let mut seen: Vec<String> = Vec::new();
    for binding in console.store.all_bindings().unwrap_or_default().into_iter().rev() {
        let Binding::Enrollment { origin, principal, account, .. } = binding else { continue };
        if origin != *board.dialed() || account == door.account || parent_account(&account).is_some() || !account.starts_with(&top_level) || seen.contains(&account) {
            continue;
        }
        seen.push(account.clone());
        match board.principal_prefix(principal)? {
            Some(seated) if seated == account => {
                if matches!(board.key_set(&account)?, KeySetAnswer::Set(set) if set.is_empty()) {
                    return Ok(Some(Pending::Delegated { account }));
                }
            }
            None if unsent.is_none() => unsent = Some(Pending::Unsent { account, principal }),
            _ => {}
        }
    }
    Ok(unsent)
}

/// Opens the session that mints top-level accounts, by reference.
///
/// It is the session of the principal seated at the board's own node —
/// principal 0, whose subject is the claimant's set (REG-4.110) — opened
/// with the console's key, which stands in that set. The pre-check's reads
/// are made here: the key is judged against the set that opens the door
/// account, the one the board authenticates this principal against.
///
/// # Errors
///
/// The reads' errors; an origin the board does not sign for; a board that
/// seats no principal at its node; the key's face where it is not
/// enrolled; and the handshake's halts.
fn minting_session<'b>(console: &Console<'b>, door: &Door) -> Result<(Session<'b>, String), Halt> {
    let board = console.board;
    let health = board.health()?;
    origin_arm(board.signed(), &health)?;
    let Some(node) = board.principal_prefix(0)? else {
        return Err(Halt::face(
            "this board seats no principal at its own node",
            "`principal_prefix(0)` answered null: the accounts a registrar admits are minted from that principal's session (REG-4.110)",
            "this is a fault in the board; nothing was written",
        ));
    };
    let walk = walk_to_set(board, &door.account)?;
    let diagnosis = KeyDiagnosis::of(&walk.set, &console.signer.fingerprint());
    let pre = PreCheck { mode: Mode::of(&health), health, principal: 0, account: node.clone(), walk, diagnosis };
    Ok((handshake_prechecked(board, Scope::Content, console.signer, &pre, Site::Console)?, node))
}

/// Mints the node account: the `delegate`, persisted first (REG-4.123
/// step 1; REG-4.109).
///
/// An account an earlier run delegated and never keyed is taken where this
/// store names one. Otherwise the board's next top-level address is
/// delegated from the minting session under a fresh `new_id`, written to
/// the store before the frame is sent: a store that cannot record it stops
/// the approval before anything is delegated.
///
/// # Errors
///
/// The reads' errors; the minting session's; a board that names no next
/// account; a store that cannot record the `new_id`; an address another
/// session took while this ran; and `delegate_persisted`'s halts.
fn mint_account(console: &Console<'_>, person: &mut dyn Person, door: &Door, run: &str) -> Result<String, Halt> {
    let board = console.board;
    let (zero, node) = minting_session(console, door)?;
    let outcome = (|| -> Result<String, Halt> {
        let pending = pending_account(console, door, &node)?;
        if let Some(Pending::Delegated { account }) = &pending {
            say(person, "REG-4.109", format!("resuming at {account}: an earlier run delegated it and wrote no key record — found by reading, and no second account is delegated"));
            return Ok(account.clone());
        }
        let Some(address) = board.next_account_prefix(&node)?.filter(|address| parent_account(address).is_none()) else {
            return Err(Halt::face(
                format!("the board names no next account under {node}"),
                "`next_account_prefix` answered no top-level address: this is a fault in the board",
                "nothing was written",
            ));
        };
        let key = console.signer.fingerprint();
        let new_id = match pending {
            Some(Pending::Unsent { account, principal }) if account == address => principal,
            _ => {
                // On disk before the `delegate` is sent (REG-4.109).
                let fresh = fresh_principal_id();
                console.store.bind(&Binding::Enrollment { origin: board.dialed().clone(), principal: fresh, account: address.clone(), fingerprint: key }).map_err(|unappended| {
                    Halt::face(
                        "the console's store could not record the new account's id, and no account is delegated",
                        unappended.to_string(),
                        "an approval's `new_id` is on disk before its `delegate` is sent, so a stopped run resumes by reading (REG-4.109): make the key store writable and run it again; nothing was written",
                    )
                })?;
                fresh
            }
        };
        let mut warnings = Vec::new();
        let id = format!("console.{run}.delegate");
        match delegate_persisted(board, &zero, Some(console.store), Some(new_id), &address, &key, &id, &mut warnings)? {
            Delegated::Committed { .. } => {
                say(person, "REG-4.123", format!("{address} is delegated: the node account, a permanent address on this board, holding no key yet"));
                Ok(address)
            }
            Delegated::Seated(_) | Delegated::NotAuthorized => Err(Halt::face(
                format!("{address} was taken while this approval ran: another session delegated it first"),
                "the `delegate` answered `not_authorized` at an address that is no longer the board's next — another console of this registrar's, under a key of the same set",
                "nothing of this approval was written there; run it again: it reads the board's next address afresh",
            )),
        }
    })();
    let _ = zero.close();
    outcome
}

/// Runs the approval's write list, in order (the parent module's doc).
///
/// # Errors
///
/// Each step's halts, each naming what stands; running the approval again
/// resumes by reading.
fn run_approval(console: &Console<'_>, person: &mut dyn Person, session: &Session<'_>, door: &Door, thread: &Thread, standing: &Standing<'_>) -> Result<Outcome, Halt> {
    let board = console.board;
    let request = &thread.request;
    let run = run_token();
    let resume = "run `skep approve` with this request again: it resumes by reading, and makes no second account, binding or answer";

    // 1 — the mint. Before it, always, the genesis registry is read for a
    // genesis naming this request's node fingerprints (REG-4.86).
    let found = standing_genesis(board, door, &request.node_fingerprints)?;
    let (genesis, account) = match found {
        Some((genesis, account)) => {
            say(person, "REG-4.86", format!("resuming at {account}: its first key record, {genesis}, already names this request's node keys — found by reading, and nothing is minted again"));
            (genesis, account)
        }
        None => {
            let account = mint_account(console, person, door, &run)?;
            let id = format!("console.{run}.genesis");
            let deposited = deposit(board, session.token(), &Deposit { home: &door.home, subject: &account, kind: DepositKind::EnrollVerbatim(request.node.clone()), hand: Some(console.signer), id: &id });
            let genesis = match deposited {
                Ok(DepositOutcome::Deposited { link, .. }) => link,
                Ok(DepositOutcome::Committed { reason }) => {
                    say(person, "AUTH-5.17", format!("the node account's first key record stands: {reason}"));
                    genesis_link_of(board, door, &account)?.ok_or_else(|| Halt::face(format!("the first key record of {account} stands and its link was not found"), format!("no enroll link in {} names it", door.home), resume))?
                }
                Err(DepositHalt::NotGenesisRegistry(h)) => {
                    return Err(Halt::face(
                        format!("{account} was given its first keys by another hand, and they are not this request's"),
                        h.to_string(),
                        "another console of this registrar's keyed the account this run delegated; run it again: it delegates afresh. Nothing of this request was written at that account",
                    ))
                }
                Err(other) => {
                    let h = Halt::from(other);
                    return Err(Halt::face(format!("the node account {account} is delegated and its first key record was not written: {h}"), "the approval stopped between its `delegate` and its genesis", resume));
                }
            };
            say(person, "REG-4.95 step 2", format!("the first key record of {account} is written in {}: the request's node enrolment, verbatim, under this console's hand", door.home));
            (genesis, account)
        }
    };
    // With the genesis, the approval link, from the genesis to the request:
    // read first, so a resumed run writes no second.
    let approval = match approval_link_from(board, door, &genesis, &request.link)? {
        Some(link) => link,
        None => {
            let id = format!("console.{run}.approval");
            link_approval(board, session.token(), session.account(), &door.home, &genesis, &request.link, console.signer, &id)?.link
        }
    };
    #[cfg(feature = "test-hooks")]
    super::hooks::hold_after_the_mint();

    // 2 — the binding, then the read-back, until the read-back finds the
    // account at the prefix bound (REG-2.16).
    let account_address = parse_address(&account).ok_or_else(|| Halt::face("the node account's address cannot be spelled", account.clone(), "this is a fault in the board"))?;
    let mut bound: Option<(Address, String)> = None;
    for pass in 0..MAX_BINDING_PASSES {
        let history = binding_history(board, Some(session.token()), &door.home)?;
        // A binding an earlier pass or an earlier run wrote that holds.
        let held = history.iter().rev().find(|binding| binding.account.as_deref() == Some(account.as_str()) && holder_of(&history, &binding.prefix).is_some_and(|current| current.link == binding.link));
        let (prefix, link) = match held {
            Some(binding) => (parse_address(&binding.prefix).ok_or_else(|| Halt::face("the bound prefix cannot be spelled", binding.prefix.clone(), "this is a fault in this client"))?, binding.link.clone()),
            None => {
                let Some(prefix) = next_prefix(&history, ROOT_TIER, FIRST_ROOT_PREFIX) else {
                    return Err(Halt::face("no next prefix can be derived", "the bindings name a prefix at the top of the count", resume));
                };
                let id = format!("console.{run}.binding.{pass}");
                let done = deposit_binding(board, session.token(), &BindingDeposit { home: &door.home, prefix: &prefix, account: Some(&account), replaces: None, hand: console.signer, id: &id })?;
                (prefix, done.link)
            }
        };
        let holder = resolved_holder(console, &prefix, resume)?.and_then(|(_, holder)| holder);
        if holder.as_ref() == Some(&account_address) {
            bound = Some((prefix, link));
            break;
        }
        say(
            person,
            "REG-2.16",
            format!("the read-back of {prefix} finds {}, not {account}: another binding of that prefix stood first, and the next prefix is taken", holder.map(|a| a.to_string()).unwrap_or_else(|| "no holder".to_string())),
        );
    }
    let Some((prefix, binding)) = bound else {
        return Err(Halt::face(
            format!("{MAX_BINDING_PASSES} bindings in a row did not read back as {account}'s"),
            "each pass binds the next prefix and reads its resolved holder back (REG-2.16); a console loses a pass only to another's binding of the same prefix",
            resume,
        ));
    };
    say(person, "REG-2.16", format!("{prefix} is bound to {account}, and reads back so"));
    // The same pass reads for a genesis at these fingerprints: the first by
    // journal order is the registration, and a console that finds another's
    // ahead of its own sends no answer and retires the binding it wrote
    // (REG-4.86; REG-4.95 step 4).
    if let Some((_, first)) = standing_genesis(board, door, &request.node_fingerprints)?.filter(|(_, first)| *first != account) {
        let retired = retire_binding(console, session, door, &prefix, &account_address, &run, resume)?;
        return Ok(Outcome::Yielded(yielded(person, request, Some(first), None, retired)));
    }

    // 3 — the reply: the approved answer, the node account's pair alone.
    // The thread is read again first: a request has one answer.
    if let Some(answered) = answer_standing(board, door, &request.link)? {
        // An approval of this very account is the registration's own
        // answer, and its binding stands; any other answer leaves this
        // run's binding grounding nothing, and it is retired.
        let retired = match answered.approves.as_deref() == Some(account.as_str()) {
            true => None,
            false => retire_binding(console, session, door, &prefix, &account_address, &run, resume)?,
        };
        return Ok(Outcome::Yielded(yielded(person, request, answered.approves, Some(answered.link), retired)));
    }
    let Some(node_principal) = principal_of(board, &account)?.and_then(Principal::new) else {
        return Err(Halt::face(format!("the board answers no principal for {account}"), "`effective_owner` names no seat at the node account, or one past the range an answer carries", resume));
    };
    let body = RegistrationBody::Approved(Approved {
        prefix: prefix.clone(),
        node_address: account_address,
        node_principal,
        board: None,
        door_origin: None,
        collection_interval: standing.policy.collection_interval.clone(),
        disposition: Disposition::Retirement,
        policy: policy_address(standing)?,
    });
    let id = format!("console.{run}.approved");
    let done = deposit_answer(board, session.token(), &AnswerDeposit { home: &door.home, request: &request.link, body: &body, hand: console.signer, id: &id })?;
    say(person, "REG-4.90", format!("the request {} is APPROVED: the answer {} names the prefix {prefix}, the account {account} and its principal {}", request.link, done.link, node_principal.get()));
    Ok(Outcome::Approved(Approval {
        request: request.link.clone(),
        prefix: prefix.to_string(),
        node_address: account,
        node_principal: node_principal.get(),
        genesis,
        approval,
        binding,
        answer: done.link,
        policy: standing.version.address.clone(),
        collection_interval: standing.policy.collection_interval.as_str().to_string(),
    }))
}

/// Reads `prefix`'s resolved holder back, through the resolver's own walk.
///
/// It is the read-back's read (REG-2.16): the binding current at the
/// prefix as a guest's resolution finds it — its link, and the account it
/// binds the prefix to, `None` where it is retired. `None` where no binding
/// stands at the prefix.
///
/// # Errors
///
/// A walk the registry board refuses or cannot answer, faced as a read-back
/// that did not answer, naming `resume`.
fn resolved_holder(console: &Console<'_>, prefix: &Address, resume: &'static str) -> Result<Option<(String, Option<Address>)>, Halt> {
    let (resolution, _) = guest_resolve(console.dialer.clone(), console.board.dialed(), prefix)
        .map_err(|e| Halt::face(format!("the binding of {prefix} is written and its read-back did not answer: {e}"), "the approval reads the prefix's resolved holder back before it replies (REG-2.16)", resume))?;
    Ok(resolution.standing().map(|standing| (standing.current.link.to_string(), standing.current.record.account.clone())))
}

/// Retires this run's binding of `prefix` to `account` (REG-2.21).
///
/// A retirement is a targetless binding naming, in `replaces`, the binding
/// current at the prefix. The pass is the read-back's for a later record
/// (REG-2.16): the prefix's current binding is read, the retirement is
/// written only while that binding still holds the prefix for `account`,
/// naming it, and the read is made again — so a retirement another hand
/// wrote first leaves nothing owed. Returns the last retirement this run
/// wrote, `None` where it wrote none.
///
/// # Errors
///
/// The read-back's halts and the deposit's; and a prefix that still reads
/// back as `account`'s after every pass, faced as a fault.
fn retire_binding(console: &Console<'_>, session: &Session<'_>, door: &Door, prefix: &Address, account: &Address, run: &str, resume: &'static str) -> Result<Option<String>, Halt> {
    let mut written = None;
    for pass in 0..MAX_BINDING_PASSES {
        let Some((current, Some(holder))) = resolved_holder(console, prefix, resume)? else { return Ok(written) };
        if holder != *account {
            return Ok(written);
        }
        let id = format!("console.{run}.retire.{pass}");
        let done = deposit_binding(console.board, session.token(), &BindingDeposit { home: &door.home, prefix, account: None, replaces: Some(&current), hand: console.signer, id: &id })?;
        written = Some(done.link);
    }
    Err(Halt::face(
        format!("{prefix} still reads back as {account}'s after {MAX_BINDING_PASSES} retirements"),
        "each pass names the binding current at the prefix and reads the prefix back (REG-2.16); a retirement is inert only where another record replaced that binding first",
        resume,
    ))
}
