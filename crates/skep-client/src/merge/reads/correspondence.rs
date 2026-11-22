//! The publication's correspondence records, read and mapped through.
//!
//! [`records_of`] reads the records of the person's own origins among a
//! state's runs, and [`owners_records`] every origin's in its owner's
//! account. [`mapped_image`] maps an image through them at its own
//! spelling, each run keyed by its I-address prefix: the words a
//! publication made public come back as the published span they became on
//! the trunk's chain, and a run minted under a member's chain stays under
//! that chain. It is the mapping of every write of a state the board held —
//! the restore's (the `history` module) and the take-backs' (the `undo`
//! module) — and of a comparison by identity, the diff's. [`mapped`] is
//! the same walk over the core's runs, each origin the trunk, which no
//! write sends.

use serde_json::Value;
use skep_address::Address;

use crate::address::parse_address;
use crate::board::{answers, frames, Image};
use crate::halt::Halt;
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

/// Returns `image` mapped through `records`, each run at its own spelling.
///
/// It is what a write of a state the board held sends, and what a
/// comparison by identity across a publication compares. Each run is walked
/// from its first I-address on its own chain, the run's prefix: the piece
/// the first record covering an I-address covers, up to that record's end
/// or the run's, is mapped onto the span the record's `to` names at the same
/// offset; the piece no record covers, up to the next record's start on the
/// chain or the run's end, is kept as read; consecutive pieces I-adjacent on
/// one chain are merged; and the ordinals are tiled again from 1. A run
/// minted under a member's chain is keyed by that chain, never its trunk's,
/// so it is mapped, kept and compared as itself. An image no record touches
/// comes back with the same identities at the same positions, a run a part
/// boundary cut one run again.
///
/// # Errors
///
/// A record that maps a piece past the largest ordinal is the board's
/// fault, faced, and nothing is mapped (SP-19).
pub fn mapped_image(image: &Image, records: &[publication::Record]) -> Result<Image, Halt> {
    let past_the_range = || {
        Halt::face(
            "a correspondence record maps words past the largest ordinal",
            "the record's published span, at the offset of a piece it covers, passes the range of an I-address",
            "this is a board fault; nothing was compared or written",
        )
    };
    let mut pieces: Vec<(String, u64, u64)> = Vec::with_capacity(image.runs().len());
    for run in image.runs() {
        let mut into = 0u64;
        while into < run.width {
            // The run's I-addresses lie within `u64` (the image's invariant).
            let (at, left) = (run.first + into, run.width - into);
            let covering = records.iter().find(|r| {
                r.from.chain == run.prefix && r.from.first <= at && at - r.from.first < r.from.width
            });
            let (prefix, first, width) = match covering {
                Some(record) => {
                    let offset = at - record.from.first;
                    let first = record.to.first.checked_add(offset).ok_or_else(past_the_range)?;
                    (&record.to.chain, first, (record.from.width - offset).min(left))
                }
                None => {
                    let next = records
                        .iter()
                        .filter(|r| r.from.chain == run.prefix && r.from.first > at)
                        .map(|r| r.from.first - at)
                        .min();
                    (&run.prefix, at, next.map_or(left, |next| next.min(left)))
                }
            };
            match pieces.last_mut() {
                Some((last, start, positions))
                    if last == prefix && start.checked_add(*positions) == Some(first) =>
                {
                    *positions += width
                }
                _ => pieces.push((prefix.clone(), first, width)),
            }
            into += width;
        }
    }
    // A mapped piece's last I-address past `u64` is refused here.
    Image::tiled(pieces).ok_or_else(past_the_range)
}

/// Maps `state`, a state as the core's runs, through `records`.
///
/// It is [`mapped_image`]'s walk over runs whose origin is the trunk, for
/// drawing a state: a member's own words stand in it as the trunk's
/// positions of the same ordinals, so no write sends it. Each run is walked
/// from its first ordinal; the piece a record covers — the first record
/// covering the ordinal — is mapped by `Record::map` onto the published
/// span it became, its origin the document the record's `to` lies in; the
/// piece no record covers is kept as read; I-adjacent pieces of one origin
/// are merged. The order is the state's. A run of an origin no record names
/// passes through unchanged, as does a piece whose mapped span this client
/// cannot spell.
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
