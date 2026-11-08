//! The merge journal (the merge record's §4, "Its home"; decision 7).
//!
//! It is the document a merge record's atom is appended to — any number per
//! account, the caller's to name — and a merge record is kept only in a
//! private document: the atom goes in as a plain insert, which a published
//! document refuses, so a journal is a private draft the account owns and
//! no record is written into a published document. A journal the caller
//! names is checked before an act's first write (the `land` module's doc;
//! P13), a published one refused [`Refusal::PublishedJournal`]; [`check`] is
//! that check alone. The default, where none is named, is the journal the
//! account's first record went to — found by the account's own links of the
//! kind from its doc 1, each candidate's `doc_metadata` read and taken only
//! where it is a private draft of the account's — or a private draft minted
//! on first use with `create_new_document{published: false}`. The library
//! never changes a journal's flag.

use serde_json::Value;
use skep_address::Address;

use crate::address::{doc_1_of, document_of, parse_address};
use crate::board::{acked_addr, answers, frames, Answer, Board, Rejection};
use crate::halt::Halt;

use super::land::{Merger, Writer};
use super::reads::{session_ended, OnEnd, Reader, Refusal};

/// Returns the journal a merge record goes to (decision 7).
///
/// It is `journal` where the caller names one; else the account's default —
/// the journal the first link of `kind` homed in the merger's doc 1 points
/// into, found by `find_links_ftt` over `ty` and `home` (no class scan),
/// where its `doc_metadata` names a private draft of the account's — a
/// journal published, another account's, withheld or unregistered is passed
/// over for the next link's — or a fresh private draft minted into the
/// account where no such journal stands.
///
/// # Errors
///
/// A transport halt, a board refusal of the find, of a link's read, of a
/// journal's `doc_metadata` but `withheld` and `doc_not_registered`, or of
/// the mint, verbatim, and a mint's acknowledgment with no address this
/// client can parse or an answer of a shape this client does not know,
/// faced — each [`Refusal::Halt`]; the death signal under the merger's
/// token, [`Refusal::SessionEnded`], the call made again on a new session.
pub fn of(
    board: &Board,
    merger: &Merger<'_>,
    kind: &Address,
    journal: Option<Address>,
) -> Result<Address, Refusal> {
    found(board, merger, kind, journal, OnEnd::Rerun)
}

/// Checks a journal the caller names as an act checks it before its first
/// write (P13; the `land` module's doc).
///
/// It is that check alone, writing nothing: one `doc_metadata` of `journal`
/// at the head, judged as a landing judges it, for a caller that says
/// before it lands whether the journal can take the merge's record.
///
/// # Errors
///
/// As the landing's check, nothing sent: a journal this merger may not
/// read, one this board does not register or another account's, as
/// [`Refusal::Halt`] naming the journal and the check it fails; a merger's
/// account this client cannot spell, as the library's own fault; a
/// published one of the merger's own, [`Refusal::PublishedJournal`]; the
/// read's other refusals and halts; the death signal under the merger's
/// token, [`Refusal::SessionEnded`], the call made again on a new session.
pub fn check(board: &Board, merger: &Merger<'_>, journal: &Address) -> Result<(), Refusal> {
    Writer::new(board, *merger, OnEnd::Rerun).check_journal(Some(journal), "the merge cannot land")
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
    // Each candidate read once: a journal passed over is not read again for
    // the next record's link into it.
    let reader = Reader::new(board, Some(merger.token), on_end);
    let own = parse_address(account);
    let mut passed: Vec<Address> = Vec::new();
    for link in &links {
        let lv = read(
            board.op(Some(merger.token), &frames::read_link(&link.to_string()))?,
            "reading a record's link",
            on_end,
        )?;
        let Some(journal) =
            answers::link_from(&lv).and_then(document_of).and_then(|j| parse_address(&j))
        else {
            continue;
        };
        if passed.contains(&journal) {
            continue;
        }
        match reader.metadata(&journal, None) {
            Ok(meta) if !meta.published && own.is_some() && parse_address(&meta.owner) == own => {
                return Ok(journal)
            }
            Ok(_) | Err(Refusal::Unreadable(_) | Refusal::NoSuchDocument(_)) => {
                passed.push(journal)
            }
            Err(e) => return Err(e),
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
