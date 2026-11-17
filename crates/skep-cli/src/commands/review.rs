//! `skep review`, the twenty-second command: the requests at a registry's
//! door (REG-4.78; REG-4.81).
//!
//! It is the registrar's read of its own queue, the library's
//! (`skep_client::ceremony::console::read_queue`): the requests an admitted
//! home wrote at this door, each judged by the approval's check and set
//! beside its thread. Every record it reads is published, so it reads as a
//! guest — no key, no session — holds no state of its own between runs, and
//! writes nothing: `--board` names the registry's board and no other setting
//! is read.
//!
//! Stdout carries three blocks, each headed by its name and its count:
//! `WAITING`, the requests no answer stands for; `APPROVED AND NOT
//! COLLECTED`, the approved requests whose node account has no doc 1 yet;
//! and `CLOSED`, the refused, the denied and the approved and collected.
//! Each request is one line — its link address, the name `skep approve` and
//! `skep deny` take; its kind, `fresh` or `board-carries-on`; its time, as
//! the board testifies it, in UTC; where it stands — the check's verdict
//! with its fault, or its answer; and `no name given`, the applicant's
//! optional name being none this build reads — then each of its keys, its
//! label beside its fingerprint in the grouped form, for the comparison with
//! the applicant out of band.
//!
//! Stderr carries the door's identifier, the string a request is framed
//! for; the policy standing, or that the door has none and so lists nothing;
//! a record of a request's type that is no request, where an admitted home
//! holds one; and the two commands that answer a waiting request. No person
//! door: the command runs without a terminal.

use std::sync::Arc;

use skep_client::ceremony::console::{read_queue, Door, Queue, State, Thread, Verdict};
use skep_client::dial::Dialer;
use skep_client::resolve::mirror_dialer;
use skep_client::sheet::{group_hex, render_inert};
use skep_registry::{ApprovalHand, RegistrationBody, RegistrationKind};

use super::{board_of, civil_date, data, talk, Stop};
use crate::args::CommandLine;

pub fn review(c: &CommandLine) -> Result<(), Stop> {
    let board = board_of(c)?;
    let dialer: Arc<dyn Dialer> = Arc::new(mirror_dialer());
    let door = Door::read(&board, dialer)?;
    let queue = read_queue(&board, None, &door)?;
    talk(format!("this door: `{}` — the identifier a request to it is framed for (REG-4.74); its account on this board is {}", door.id, door.account));
    match queue.policy.standing() {
        Ok(standing) => {
            let hand = match standing.policy.approval_hand() {
                Some(ApprovalHand::Officer) => "an officer's hand",
                Some(ApprovalHand::Unattended) => "the unattended hand, or an officer's",
                None => "no hand: no approval is written under it",
            };
            let intake: Vec<String> = standing.policy.intake.iter().map(ToString::to_string).collect();
            talk(format!(
                "the policy standing: {} — `{}` admission, approved by `{}` ({hand}); requests are read from {}; {} ground{} a denial can cite",
                standing.version.address,
                standing.policy.admission.as_str(),
                render_inert(&standing.policy.approval),
                if intake.is_empty() { "no home: its `intake` names none".to_string() } else { intake.join(", ") },
                standing.policy.grounds.len(),
                if standing.policy.grounds.len() == 1 { "" } else { "s" }
            ));
        }
        Err(no) => talk(format!(
            "{no}. A door with no policy is shut: no request is admitted, so none is listed, and no approval or denial is written (REG-4.139). Publish the \
             door's policy with `skep set-policy <file>`"
        )),
    }
    for passed in &queue.passed_over {
        talk(format!("not a request, and not listed: {} — {} (REG-4.78)", passed.link, passed.why));
    }
    block("WAITING", &queue, State::Waiting)?;
    block("APPROVED AND NOT COLLECTED", &queue, State::ApprovedNotCollected)?;
    block("CLOSED", &queue, State::Closed)?;
    if queue.waiting().next().is_some() {
        talk("to answer a waiting request: `skep approve <its address>`, or `skep deny <its address> --clause <n>`; compare its keys with the applicant, out of band, before you approve");
    }
    Ok(())
}

/// Prints one block: its heading and count, then each request in it.
///
/// # Errors
///
/// A write stdout refuses is a halt.
fn block(name: &str, queue: &Queue, state: State) -> Result<(), Stop> {
    let threads: Vec<&Thread> = queue.threads.iter().filter(|thread| thread.state == state).collect();
    data(format!("{name} ({})", threads.len()))?;
    for thread in threads {
        let request = &thread.request;
        let kind = match request.kind {
            RegistrationKind::BoardCarriesOn => "board-carries-on",
            _ => "fresh",
        };
        let time = request.time.map(utc_time).unwrap_or_else(|| "time unknown".to_string());
        data(format!("{}  {kind}  {time}  {}  no name given", request.link, standing(thread)))?;
        for key in &request.keys {
            let label = if key.label.is_empty() { "(no label)".to_string() } else { format!("`{}`", render_inert(&key.label)) };
            data(format!("    {} — {label}", key.named))?;
            for line in group_hex(&key.fingerprint.to_hex()).lines() {
                data(format!("      {line}"))?;
            }
        }
    }
    Ok(())
}

/// Returns where a request stands, as its line says it.
///
/// A waiting request's is the approval check's verdict, with its fault
/// where it fails and a begun approval where one stands; an answered one's
/// is its answer.
fn standing(thread: &Thread) -> String {
    let answered = thread.answers.first().map(|answer| match &answer.body {
        RegistrationBody::Approved(approved) => {
            let collected = if thread.state == State::Closed { "approved and collected" } else { "approved" };
            format!("{collected}: prefix {}, account {}, principal {}", approved.prefix, approved.node_address, approved.node_principal.get())
        }
        RegistrationBody::Refused(refused) => format!("refused: {}", refused.fault.as_str()),
        RegistrationBody::Denied(denied) => format!("denied: clause {} of {}", denied.clause.as_str(), denied.policy),
        _ => "answered".to_string(),
    });
    if let Some(answered) = answered {
        return answered;
    }
    let verdict = match &thread.request.verdict {
        Verdict::Passes => "passes".to_string(),
        Verdict::Fails { fault, why } => format!("fails: {} ({why})", fault.as_str()),
    };
    match &thread.approval {
        Some(_) => format!("{verdict}; an approval is begun and not finished — `skep approve {}` resumes it", thread.request.link),
        None => verdict,
    }
}

/// Returns a time the board testifies, as a line says it: UTC, to the
/// second.
///
/// `millis` is milliseconds since the epoch, as a read's `time` carries it.
fn utc_time(millis: u64) -> String {
    let secs = millis / 1000;
    let of_day = secs % 86_400;
    format!("{} {:02}:{:02}:{:02}Z", civil_date(secs), of_day / 3600, of_day % 3600 / 60, of_day % 60)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Checks that a time is said in UTC to the second, its day the
    /// calendar's: the epoch, a leap day's last second, and an afternoon —
    /// the milliseconds past the second dropped, never rounded up.
    #[test]
    fn a_time_is_said_in_utc_to_the_second() {
        assert_eq!(utc_time(0), "1970-01-01 00:00:00Z");
        assert_eq!(utc_time(1_709_251_199_999), "2024-02-29 23:59:59Z");
        assert_eq!(utc_time(1_794_837_731_000), "2026-11-16 14:02:11Z");
    }
}
