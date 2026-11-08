//! The merge journal (the merge record's §4, "Its home"; decision 7).
//!
//! It is the document a merge record's atom is appended to and the record's
//! link is homed in, beside it — any number per account, the caller's to
//! name — and a merge record is kept only in a private document: the atom
//! goes in as a plain insert, which a published document refuses, so a
//! journal is a private draft the account owns, the record and its link
//! hidden with it, and no record is written into a published document. A
//! journal the caller names is checked before an act's first write (the
//! `land` module's doc; P13), a published one refused
//! [`Refusal::PublishedJournal`]; [`check`] is that check alone. The default,
//! where none is named, is the journal the account's first record went to —
//! found by the account's own links of the kind, homed in the journals that
//! hold their records, each candidate's `doc_metadata` read and taken only
//! where it is a private draft of the account's — or a private draft minted
//! on first use with `create_new_document{published: false}`. The library
//! never changes a journal's flag.
//!
//! **The find is a class scan.** The account's links of the kind are read by
//! one `find_links_ftt` over `ty` and `home` the account, the read the
//! client's design names for a caller with no index (A-47), and a `home`
//! naming an account walks every home under it: the board admits it under
//! its class-scan permits and refuses it `scan_busy` while every one is in
//! use (wire.md §Link discovery reads). The find is reissued then, under the
//! publication's backoff and bound (`SCAN_BUSY_REISSUES`, the link-sets
//! design §5.7), nothing written between; past the bound it is answered as
//! the board's refusal, which an act's record step faces as the act standing
//! with its record unwritten.

use std::thread;
use std::time::Duration;

use serde_json::Value;
use skep_address::Address;

use crate::address::{document_of, parse_address};
use crate::board::{acked_addr, answers, frames, Answer, Board, Rejection};
use crate::halt::{Halt, Refused};
use crate::publication::{is_busy, owned_by, SCAN_BUSY_REISSUES};

use super::land::{Merger, Writer};
use super::reads::{comps, session_ended, OnEnd, Reader, Refusal};

/// Returns the journal a merge record goes to (decision 7).
///
/// It is `journal` where the caller names one; else the account's default —
/// the journal the account's first record went to: of the documents of the
/// account's own that home a link of `kind`, found by `find_links_ftt` over
/// `ty` and `home` the account, each read by its earliest such link, a
/// document whose link's `from` lies outside it or whose type is not
/// exactly `kind` is no journal, and the rest are taken in the order their
/// earliest links were minted, the first whose `doc_metadata` names a
/// private draft of the account's — a journal published, another
/// account's, withheld or unregistered is passed over — or a fresh private
/// draft minted into the account where no such journal stands.
///
/// # Errors
///
/// A transport halt, a board refusal of the find — `scan_busy` past the
/// bounded reissues among them (the module's doc) — of a link's read, of a
/// journal's `doc_metadata` but `withheld` and `doc_not_registered`, or of
/// the mint, verbatim, and a link's read or a mint's acknowledgment this
/// client cannot read, faced — each [`Refusal::Halt`]; the death signal
/// under the merger's token, [`Refusal::SessionEnded`], the call made again
/// on a new session.
pub fn of(
    board: &Board,
    merger: &Merger<'_>,
    kind: &Address,
    journal: Option<Address>,
) -> Result<Address, Refusal> {
    found(board, merger, kind, journal, OnEnd::Rerun).map_err(|e| match e {
        Unfound::Busy(r) => Refusal::Halt(Halt::Refused(r)),
        Unfound::Other(r) => r,
    })
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

/// Why the account's journal was not found.
pub(super) enum Unfound {
    /// The board refused the find `scan_busy` on its first send and on each
    /// of its bounded reissues: the last refusal, nothing written.
    Busy(Refused),
    /// Every other refusal of the find, a link's read, a `doc_metadata` or
    /// the mint, as itself.
    Other(Refusal),
}

impl From<Refusal> for Unfound {
    fn from(r: Refusal) -> Unfound {
        Unfound::Other(r)
    }
}

impl From<Halt> for Unfound {
    fn from(h: Halt) -> Unfound {
        Unfound::Other(Refusal::Halt(h))
    }
}

/// Returns the journal a merge record goes to, as [`of`] does, for an act
/// whose session's end leaves `on_end` — the record step of the act it
/// writes the record of.
///
/// # Errors
///
/// The find refused `scan_busy` past the bounded reissues, [`Unfound::Busy`]
/// with nothing written; every other error of [`of`]'s, the death signal
/// faced for that act, [`Unfound::Other`].
pub(super) fn found(
    board: &Board,
    merger: &Merger<'_>,
    kind: &Address,
    journal: Option<Address>,
    on_end: OnEnd,
) -> Result<Address, Unfound> {
    if let Some(journal) = journal {
        return Ok(journal);
    }
    let account = merger.account;
    let kind_text = kind.to_string();
    let v = find(board, merger, &frames::find_links_ftt_home(&kind_text, account), on_end)?;
    // Each home of the account's own, by its earliest link of the kind: a
    // link's ordinal within its home is the order it was minted in. A
    // sub-account's home is another account's, never read.
    let mut earliest: Vec<(String, Address)> = Vec::new();
    for link in answers::addrs(&v).into_iter().filter(|l| owned_by(l, account)) {
        let (Some(home), Some(link)) = (document_of(link), parse_address(link)) else { continue };
        match earliest.iter_mut().find(|(h, _)| *h == home) {
            Some((_, first)) if comps(&link) < comps(first) => *first = link,
            Some(_) => {}
            None => earliest.push((home, link)),
        }
    }
    // A home is a journal where its earliest link is a record's: its `from`
    // inside the home, its type exactly the kind. The journals in the order
    // those links were minted — a link the board serves no position for is
    // one a build before the position map minted, so the older — the
    // address breaking a tie.
    let mut journals: Vec<(Option<u64>, Address)> = Vec::new();
    for (home, link) in &earliest {
        let lv = read(
            board.op(Some(merger.token), &frames::read_link(&link.to_string()))?,
            "reading a record's link",
            on_end,
        )?;
        let Some(value) = answers::link_value(&lv) else {
            return Err(
                shape("a record's link answered a shape this client does not know", &lv).into()
            );
        };
        let Some(value) = value.filter(|value| value.typed_exactly(&kind_text)) else { continue };
        let from = value.from.first().and_then(|span| document_of(&span.start));
        let Some(journal) = from.filter(|from| from == home).and_then(|j| parse_address(&j)) else {
            continue;
        };
        journals.push((value.at, journal));
    }
    journals.sort_by(|(a, x), (b, y)| a.cmp(b).then_with(|| comps(x).cmp(&comps(y))));
    let reader = Reader::new(board, Some(merger.token), on_end);
    let own = parse_address(account);
    for (_, journal) in journals {
        match reader.metadata(&journal, None) {
            Ok(meta) if !meta.published && own.is_some() && parse_address(&meta.owner) == own => {
                return Ok(journal)
            }
            Ok(_) | Err(Refusal::Unreadable(_) | Refusal::NoSuchDocument(_)) => {}
            Err(e) => return Err(e.into()),
        }
    }
    let id = format!("merge.journal:{account}");
    let v = document(
        board.op(Some(merger.token), &frames::create_document(account, false, Some(&id)))?,
        "minting the merge journal",
        on_end,
    )?;
    if let Some(addr) = acked_addr(&v) {
        return parse_address(addr)
            .ok_or_else(|| Unfound::from(shape("the mint answered no address", &v)));
    }
    match Rejection::of(&v) {
        Some(r) => Err(r.refused(&v).into()),
        None => Err(shape("the mint answered a shape this client does not know", &v).into()),
    }
}

/// Returns the find's document: `frame`, the account's links of the kind,
/// sent again while the board refuses it busy (the module's doc).
///
/// Each reissue waits 20 ms more than the last, nothing written between.
///
/// # Errors
///
/// The board's busy refusal on the first send and on each of the
/// [`SCAN_BUSY_REISSUES`] reissues, [`Unfound::Busy`]; the death signal and
/// a rejection, as [`read`]'s; every other halt of the send.
fn find(
    board: &Board,
    merger: &Merger<'_>,
    frame: &Value,
    on_end: OnEnd,
) -> Result<Value, Unfound> {
    let mut reissued = 0;
    loop {
        match board.op(Some(merger.token), frame) {
            Err(Halt::Refused(r)) if is_busy(&r.code) => {
                if reissued == SCAN_BUSY_REISSUES {
                    return Err(Unfound::Busy(r));
                }
                reissued += 1;
                thread::sleep(Duration::from_millis(20 * u64::from(reissued)));
            }
            answer => return Ok(read(answer?, "finding the merge journal", on_end)?),
        }
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
