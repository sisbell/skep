//! The merge journal (the merge record's §4, "Its home"; decision 7).
//!
//! It is the document a merge record's atom is appended to — any number per
//! account, the caller's to name — and the default where none is named: the
//! journal the account's first record went to, found by the account's own
//! links of the kind from its doc 1 and named by the first record's link, or
//! a private draft minted on first use with
//! `create_new_document{published: false}`. The atom goes in as a plain
//! insert, so a journal takes it only as a draft the account owns; the
//! library never changes a journal's flag, and checks a journal named
//! before an act's first write (the `land` module's doc; P13).

use serde_json::Value;
use skep_address::Address;

use crate::address::{doc_1_of, document_of, parse_address};
use crate::board::{acked_addr, answers, frames, Answer, Board, Rejection};
use crate::halt::Halt;

use super::land::Merger;
use super::reads::{session_ended, OnEnd, Refusal};

/// Returns the journal a merge record goes to (decision 7).
///
/// It is `journal` where the caller names one; else the account's default —
/// the journal the first link of `kind` homed in the merger's doc 1 points
/// into, found by `find_links_ftt` over `ty` and `home` (no class scan), or
/// a fresh private draft minted into the account where no such link stands.
///
/// # Errors
///
/// A transport halt, a board refusal of the find, of a link's read or of the
/// mint, verbatim, and a mint's acknowledgment with no address this client
/// can parse or an answer of a shape this client does not know, faced — each
/// [`Refusal::Halt`]; the death signal under the merger's token,
/// [`Refusal::SessionEnded`], the call made again on a new session.
pub fn of(
    board: &Board,
    merger: &Merger<'_>,
    kind: &Address,
    journal: Option<Address>,
) -> Result<Address, Refusal> {
    found(board, merger, kind, journal, OnEnd::Rerun)
}

/// Returns the journal a merge record goes to, as [`of`] does, for an act
/// whose session's end leaves `on_end` — the record step of the act it
/// writes the record of.
///
/// # Errors
///
/// As [`of`]'s, the death signal faced for that act.
pub(super) fn found(
    board: &Board,
    merger: &Merger<'_>,
    kind: &Address,
    journal: Option<Address>,
    on_end: OnEnd,
) -> Result<Address, Refusal> {
    if let Some(journal) = journal {
        return Ok(journal);
    }
    let account = merger.account;
    let home = doc_1_of(account);
    let v = read(
        board.op(Some(merger.token), &frames::find_links_ftt_home(&kind.to_string(), &home))?,
        "finding the merge journal",
        on_end,
    )?;
    let mut links: Vec<Address> =
        answers::addrs(&v).iter().filter_map(|a| parse_address(a)).collect();
    links.sort_by_key(super::reads::comps);
    for link in &links {
        let lv = read(
            board.op(Some(merger.token), &frames::read_link(&link.to_string()))?,
            "reading a record's link",
            on_end,
        )?;
        if let Some(journal) =
            answers::link_from(&lv).and_then(document_of).and_then(|j| parse_address(&j))
        {
            return Ok(journal);
        }
    }
    let id = format!("merge.journal:{account}");
    let v = document(
        board.op(Some(merger.token), &frames::create_document(account, false, Some(&id)))?,
        "minting the merge journal",
        on_end,
    )?;
    if let Some(addr) = acked_addr(&v) {
        return parse_address(addr).ok_or_else(|| shape("the mint answered no address", &v).into());
    }
    match Rejection::of(&v) {
        Some(r) => Err(r.refused(&v).into()),
        None => Err(shape("the mint answered a shape this client does not know", &v).into()),
    }
}

/// Returns the response document of an exchange under the merger's token.
///
/// # Errors
///
/// The death signal, [`Refusal::SessionEnded`] naming the step `during`
/// names, faced for `on_end`.
fn document(answer: Answer, during: &str, on_end: OnEnd) -> Result<Value, Refusal> {
    match answer {
        Answer::Closed => Err(session_ended(during, on_end)),
        Answer::Document(v) => Ok(v),
    }
}

/// Returns a read's document.
///
/// # Errors
///
/// The death signal, as [`document`]'s; a rejection, the board's refusal.
fn read(answer: Answer, during: &str, on_end: OnEnd) -> Result<Value, Refusal> {
    let v = document(answer, during, on_end)?;
    match Rejection::of(&v) {
        Some(r) => Err(r.refused(&v).into()),
        None => Ok(v),
    }
}

fn shape(state: &str, v: &Value) -> Halt {
    Halt::face(
        state,
        crate::halt::clipped(&v.to_string(), 200).to_string(),
        "this board is not speaking the wire this client expects",
    )
}
