//! The merge journal (the merge record's §4, "Its HOME"; decision 7): the
//! document a merge record's atom is appended to — any number per account,
//! the caller's to name — and the default where none is named: ONE PRIVATE
//! DRAFT per account, found by the account's own links of the kind from its
//! doc 1 and named by the first record's link, or MINTED on first use with
//! `create_new_document{published: false}`. Public or private is the
//! journal document's own flag; the library never changes it.

use serde_json::Value;
use skep_address::Address;

use crate::address::{doc_1_of, document_of, parse_address};
use crate::board::{acked_addr, answers, frames, Answer, Board, Rejection};
use crate::halt::Halt;

use super::land::Merger;

/// Returns the journal a merge record goes to: `journal` where the caller
/// names one; else the account's default — the journal the first link of
/// `kind` homed in the merger's doc 1 points into, found by
/// `find_links_ftt` over `ty` and `home` (no class scan), or a fresh private
/// draft minted into the account where no such link stands (decision 7).
///
/// # Errors
///
/// The death signal under the merger's token; a board refusal of the find or
/// the mint, verbatim; an acknowledgment without an address, faced.
pub fn of(
    board: &Board,
    merger: &Merger<'_>,
    kind: &Address,
    journal: Option<Address>,
) -> Result<Address, Halt> {
    if let Some(journal) = journal {
        return Ok(journal);
    }
    let account = merger.account;
    let home = doc_1_of(account);
    let v = read(
        board.op(Some(merger.token), &frames::find_links_ftt_home(&kind.to_string(), &home))?,
        "finding the merge journal",
    )?;
    let mut links: Vec<Address> =
        answers::addrs(&v).iter().filter_map(|a| parse_address(a)).collect();
    links.sort_by_key(super::reads::comps);
    for link in &links {
        let lv = read(
            board.op(Some(merger.token), &frames::read_link(&link.to_string()))?,
            "reading a record's link",
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
    )?;
    if let Some(addr) = acked_addr(&v) {
        return parse_address(addr).ok_or_else(|| shape("the mint answered no address", &v));
    }
    match Rejection::of(&v) {
        Some(r) => Err(r.refused(&v)),
        None => Err(shape("the mint answered a shape this client does not know", &v)),
    }
}

/// The response document of an exchange under the merger's token, the death
/// signal faced.
fn document(answer: Answer, during: &str) -> Result<Value, Halt> {
    match answer {
        Answer::Closed => Err(Halt::face(
            format!("the session ended while {during}"),
            "the board answered `Skepd-Session: closed` (wire.md §Sessions)",
            "open a session again and run the merge again: every step resumes by reading",
        )),
        Answer::Document(v) => Ok(v),
    }
}

/// A read's document, a rejection the board's refusal.
fn read(answer: Answer, during: &str) -> Result<Value, Halt> {
    let v = document(answer, during)?;
    match Rejection::of(&v) {
        Some(r) => Err(r.refused(&v)),
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
