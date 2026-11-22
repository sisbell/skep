//! The publication's correspondence records, read and mapped through.
//!
//! [`records_of`] reads the records of the person's own origins among a
//! state's runs, [`owners_records`] every origin's in its owner's account,
//! and [`mapped`] maps a state through them, so words a publication made
//! public come back as the published words they became (the `reads`
//! module's doc).

use serde_json::Value;
use skep_address::Address;

use crate::address::parse_address;
use crate::board::{answers, frames};
use crate::merge::compose::Run;
use crate::publication::enumerate::MAX_WIRE_LIST;
use crate::publication::{self, home_of_link, owned_by};

use super::addresses::account_of;
use super::reader::{shape, Reader};
use super::refusal::Refusal;

// ── the correspondence records ────────────────────────────────────────────

/// Reads the correspondence records of `account`'s own origins, at the head.
///
/// The origins are those among `state`'s runs. It is the read a write of a
/// past state makes before it is sent — the restore's (the `history`
/// module) and the undo's (the `undo` module) — and the shot's read of its
/// twins (the `windows` module): [`records_held_to`] over each distinct
/// origin `account` owns exactly, every record held to `account`. An origin
/// of another account's is not read, and its words stay as read.
///
/// # Errors
///
/// [`records_held_to`]'s.
pub(crate) fn records_of(
    reader: &Reader<'_>,
    account: &str,
    state: &[Run],
) -> Result<Vec<publication::Record>, Refusal> {
    records_held_to(reader, state, |origin| {
        owned_by(&origin.to_string(), account).then(|| account.to_string())
    })
}

/// Reads every origin's correspondence records, each in its owner's account.
///
/// The origins are those among `state`'s runs, and the reads are made at
/// the head. It is the read a comparison by identity maps its texts
/// through — the diff's (`history::records`). A text can hold another
/// account's draft's words by identity, a mark of the draft or a copy from
/// it, and only that draft's owner's own shot re-mints them and homes a
/// record for them in the draft (wire.md §The publish shot and head-float:
/// every named draft the caller's own; the correspondence records), so each
/// origin's records are read in its owner's account, as a publication reads
/// a window's (the link-sets design §5.5; `publication::parts`'s
/// `window_records`): [`records_held_to`] over every distinct origin, each
/// held to the account it lies in. The board answers a reader only the
/// links homed where it may read (wire.md §The read predicate), so an
/// origin the reader may not read yields no record, and its words stay as
/// read.
///
/// # Errors
///
/// [`records_held_to`]'s.
pub(crate) fn owners_records(
    reader: &Reader<'_>,
    state: &[Run],
) -> Result<Vec<publication::Record>, Refusal> {
    records_held_to(reader, state, account_of)
}

/// Reads each origin's correspondence records, held to `held_to`'s account.
///
/// It is the one loop of [`records_of`] and [`owners_records`], over the
/// origins among `state`'s runs, at the head. Each distinct origin is taken
/// in run order, and `held_to` names the account its records are held to,
/// or none, which leaves it unread. One four-set read per chunk of each
/// taken origin's spans — `{home: [the origin], from: [the spans], ty: [the
/// correspondence class]}`, the twin fence's own read — each hit judged off
/// its address (the owned-home test: a hit homed in no document of that
/// account's exactly is never read), read once, and kept by `Record::of` as
/// a record of that account's. The reads are made at the head and never at
/// the state's position, since a record minted after the state must be
/// seen.
///
/// # Errors
///
/// The reads' refusals: `withheld` on an origin as [`Refusal::Unreadable`],
/// `doc_not_registered` as [`Refusal::NoSuchDocument`], an answer of
/// another shape faced, the reader's other errors.
fn records_held_to(
    reader: &Reader<'_>,
    state: &[Run],
    held_to: impl Fn(&Address) -> Option<String>,
) -> Result<Vec<publication::Record>, Refusal> {
    let subtype =
        frames::unit_span(frames::T_CORRESPONDENCE).as_array().cloned().unwrap_or_default();
    let mut distinct: Vec<&Address> = Vec::new();
    for run in state {
        if !distinct.contains(&&run.origin) {
            distinct.push(&run.origin);
        }
    }
    let mut records: Vec<publication::Record> = Vec::new();
    for (origin, account) in distinct.into_iter().filter_map(|o| Some((o, held_to(o)?))) {
        let text = origin.to_string();
        let home = frames::unit_span(&text).as_array().cloned().unwrap_or_default();
        let spans: Vec<Value> = state
            .iter()
            .filter(|r| r.origin == *origin)
            .map(|r| frames::i_span(&format!("{text}.0.1.{}", r.i_start), r.width))
            .collect();
        for chunk in spans.chunks(MAX_WIRE_LIST) {
            let query = frames::find_links_four(
                frames::Slot::Spans(&home),
                frames::Slot::Spans(chunk),
                frames::Slot::Any,
                frames::Slot::Spans(&subtype),
            );
            let v = reader.answered(origin, &query, None)?;
            if v["resp"].as_str() != Some("addrs") {
                return Err(shape("find_links_ftt", &v).into());
            }
            let hits: Vec<String> = answers::addrs(&v).into_iter().map(str::to_string).collect();
            for hit in hits {
                if records.iter().any(|r| r.link.to_string() == hit) {
                    continue;
                }
                if !home_of_link(&hit).is_some_and(|h| owned_by(h, &account)) {
                    continue;
                }
                let lv = reader.answered(origin, &frames::read_link(&hit), None)?;
                let Some(value) =
                    answers::link_value(&lv).ok_or_else(|| shape("read_link", &lv))?
                else {
                    continue;
                };
                if let Some(record) = publication::Record::of(&hit, &value, &account) {
                    records.push(record);
                }
            }
        }
    }
    Ok(records)
}

/// Maps `state` through `records`: the runs a write of it sends.
///
/// Each run is walked from its first ordinal; the piece a record covers —
/// the first record covering the ordinal — is mapped by `Record::map` onto
/// the published span it became, its origin the document the record's `to`
/// lies in; the piece no record covers is kept as read; I-adjacent pieces
/// of one origin are merged. The order is the state's. A run of an origin
/// no record names passes through unchanged, as does a piece whose mapped
/// span this client cannot spell.
pub fn mapped(state: &[Run], records: &[publication::Record]) -> Vec<Run> {
    let mut out: Vec<Run> = Vec::new();
    let mut push = |run: Run| match out.last_mut() {
        Some(last) if last.origin == run.origin && last.reach() == run.i_start => {
            last.width += run.width
        }
        _ => out.push(run),
    };
    for run in state {
        let chain = format!("{}.0.1", run.origin);
        let mut cursor = run.i_start;
        while cursor < run.reach() {
            let covering =
                records.iter().find(|r| r.from.overlap(&chain, cursor, cursor + 1).is_some());
            let end = match covering {
                Some(r) => r.from.reach().min(run.reach()),
                None => records
                    .iter()
                    .filter_map(|r| {
                        (r.from.chain == chain && r.from.first > cursor).then_some(r.from.first)
                    })
                    .min()
                    .unwrap_or(run.reach())
                    .min(run.reach()),
            };
            let width = end - cursor;
            let piece = covering
                .and_then(|r| r.map(&chain, cursor, end))
                .and_then(|to| Some(Run::new(parse_address(&to.document()?)?, to.first, width)))
                .unwrap_or_else(|| Run::new(run.origin.clone(), cursor, width));
            push(piece);
            cursor = end;
        }
    }
    out
}
