//! The join's oracle and the first difference of two run lists.
//!
//! [`check_join`] holds the core's join against the board's `compare` (the
//! merge record's §1.3 step 4); [`first_difference`] finds where a member's
//! or a draft's runs leave the list a merge composed, a draft side's fresh
//! runs matched by their width in the document's own I-space, and
//! [`first_word_difference`] where a member's words at those runs leave the
//! draft side's own.

use serde_json::Value;
use skep_address::Address;

use crate::board::{answers, frames, Rejection};
use crate::halt::Halt;
use crate::merge::compose::Run;

use super::inputs::Family;
use super::reader::{shape, Imaged, Reader};
use super::readings::{values_of, Readings};
use super::refusal::Refusal;

/// Returns the first V-ordinal, counted from 1, at which two lists differ.
///
/// The lists are the `actual` runs — a member's over its placed positions,
/// or a draft's whole — and the `expected` list the merge composed — `None`
/// where they agree. A
/// draft side's fresh runs are re-minted by the shot under `doc`'s own
/// I-space, consecutively, so an expected `DraftNative` run matches any
/// stretch of `doc`'s positions of its width in its place, whatever their
/// ordinals.
pub(in crate::merge) fn first_difference(
    expected: &[(Run, Family)],
    actual: &[Run],
    doc: &Address,
) -> Option<u64> {
    let mut cursor = 1u64;
    let (mut i, mut j, mut off_i, mut off_j) = (0usize, 0usize, 0u64, 0u64);
    while i < expected.len() && j < actual.len() {
        let (e, fam) = &expected[i];
        let a = &actual[j];
        let stretch = (e.width - off_i).min(a.width - off_j);
        let same_origin =
            if *fam == Family::DraftNative { a.origin == *doc } else { a.origin == e.origin };
        let same_start = *fam == Family::DraftNative || e.i_start + off_i == a.i_start + off_j;
        if !(same_origin && same_start) {
            return Some(cursor);
        }
        cursor += stretch;
        off_i += stretch;
        off_j += stretch;
        if off_i == e.width {
            i += 1;
            off_i = 0;
        }
        if off_j == a.width {
            j += 1;
            off_j = 0;
        }
    }
    (i < expected.len() || j < actual.len()).then_some(cursor)
}

/// Returns the first V-ordinal, counted from 1, at which `member` holds
/// other words than the draft side's words a shot re-mints there.
///
/// `native` names each draft-native run of the list a merge composed: the
/// V-ordinal of `member` it lands at, the side its words are read through
/// and the run they are read as. [`first_difference`] matches such a run by
/// its width alone, the shot giving the words new addresses, so the words
/// decide: the member's at those ordinals ([`Reader::values_by_ordinal`])
/// and the run's own through the side that holds them ([`values_of`]), both
/// read at the head and compared position by position. Values confirm here
/// what the addresses cannot; they never stand for identity (D6). `None`
/// where every word agrees, and where `native` is empty, nothing read.
///
/// # Errors
///
/// The two reads' refusals, each as itself (SP-14).
pub(in crate::merge) fn first_word_difference(
    reader: &Reader<'_>,
    doc: &Address,
    maps: &[Imaged],
    member: &Address,
    native: &[(u64, Option<usize>, &Run)],
) -> Result<Option<u64>, Refusal> {
    if native.is_empty() {
        return Ok(None);
    }
    let spans: Vec<(u64, u64)> = native.iter().map(|(at, _, run)| (*at, run.width)).collect();
    let held = reader.values_by_ordinal(member, &spans)?;
    let through: Vec<(Option<usize>, &Run)> =
        native.iter().map(|(_, side, run)| (*side, *run)).collect();
    let own = values_of(reader, doc, maps, &through)?;
    for (((at, _, _), held), own) in native.iter().zip(held).zip(own) {
        let differs = held.iter().zip(&own).position(|(h, o)| h != o);
        let short = (held.len() != own.len()).then(|| held.len().min(own.len()));
        if let Some(k) = differs.or(short) {
            return Ok(Some(at + k as u64));
        }
    }
    Ok(None)
}

// ── the oracle of the join ────────────────────────────────────────────────

/// Checks the client's join against the daemon's `compare`.
///
/// It is the merge record's §1.3 step 4: one `compare` of the base's whole
/// content against every side's — the second operand a region per side —
/// asked in parts past its budgets (`too_many_blocks`, `too_many_pairs`:
/// the sides asked one at a time, then the larger operand halved and
/// re-asked), and for each side the base positions the pairs name as shared
/// must be exactly the base positions that side's image holds. A base that
/// is the document's own arrangement is compared as its image was read,
/// its region carrying `own` (PUB-2.66); a base of no positions shares
/// none, and nothing is asked.
///
/// # Errors
///
/// A disagreement is this library's own fault — the core's join reproduces
/// the daemon's equi-join on I-address — faced; the reads' refusals.
pub(in crate::merge) fn check_join(reader: &Reader<'_>, readings: &Readings) -> Result<(), Refusal> {
    let base = &readings.base_image;
    // The oracle at the one position a verification reads every image at.
    let at = Some(readings.at);
    let regions: Vec<(Address, u64, u64)> =
        readings.maps.iter().map(|m| (m.doc.clone(), 1, m.extent)).collect();
    let mut pairs = Vec::new();
    compare_parts(reader, base, 1, base.extent, &regions, at, &mut pairs)?;
    for m in &readings.maps {
        let doc = m.doc.to_string();
        let mut oracle: Vec<(u64, u64)> =
            pairs.iter().filter(|p| p.d2 == doc).map(|p| (p.u1, p.width)).collect();
        let mut join: Vec<(u64, u64)> = Vec::new();
        for b in &base.runs {
            for s in m.runs.iter().filter(|s| s.prefix == b.prefix) {
                let lo = b.first.max(s.first);
                let hi = (b.first + b.width).min(s.first + s.width);
                if lo < hi {
                    join.push((b.ordinal + (lo - b.first), hi - lo));
                }
            }
        }
        if coalesced(&mut oracle) != coalesced(&mut join) {
            return Err(Halt::face(
                format!("the client's join over {} and {} disagrees with the board's `compare`", base.doc, m.doc),
                format!("compare: {oracle:?}; the images' intersection: {join:?}"),
                "this is this client's fault — its reproduction of the daemon's equi-join; nothing was written",
            )
            .into());
        }
    }
    Ok(())
}

/// Sorts `(start, width)` ranges and merges those that touch.
fn coalesced(ranges: &mut Vec<(u64, u64)>) -> Vec<(u64, u64)> {
    ranges.sort_unstable();
    let mut out: Vec<(u64, u64)> = Vec::new();
    for &(start, width) in ranges.iter() {
        if let Some(last) = out.last_mut() {
            if last.0 + last.1 >= start {
                last.1 = (start + width).max(last.0 + last.1) - last.0;
                continue;
            }
        }
        out.push((start, width));
    }
    out
}

/// Asks one `compare` of the base region against the side regions.
///
/// The base region is `base`'s positions `from ..`, `width` of them,
/// carrying `own` where `base` is the document's own arrangement. On a
/// budget refusal it asks the sides one at a time, then halves the larger
/// operand, until each part answers.
///
/// # Errors
///
/// A refusal other than a budget's, mapped by [`Reader::refuse`] as a read
/// of several documents — a `withheld` or `doc_not_registered` naming the
/// region's document the board refused, the base's or a side's, and one
/// naming no document this client parses the board's refusal verbatim,
/// never the base (SP-18); a budget refusal down to one position each,
/// faced; an answer that is no `compare` answer, faced; [`Reader::read`]'s
/// errors.
fn compare_parts(
    reader: &Reader<'_>,
    base: &Imaged,
    from: u64,
    width: u64,
    sides: &[(Address, u64, u64)],
    at: Option<u64>,
    out: &mut Vec<answers::Correspondence>,
) -> Result<(), Refusal> {
    if width == 0 || sides.iter().all(|(_, _, w)| *w == 0) {
        return Ok(());
    }
    let text = base.doc.to_string();
    let rho1 = [if base.own {
        frames::region_own(&text, from, width)
    } else {
        frames::region(&text, from, width)
    }];
    let rho2: Vec<Value> = sides
        .iter()
        .filter(|(_, _, w)| *w > 0)
        .map(|(d, f, w)| frames::region(&d.to_string(), *f, *w))
        .collect();
    let v = reader.read(&frames::compare(&rho1, &rho2), at)?;
    if let Some(r) = Rejection::of(&v) {
        if !matches!(r.key(), "too_many_blocks" | "too_many_pairs") {
            // A read of the base and every side: the one the board names,
            // or its refusal.
            return Err(reader.refuse(None, &r, &v));
        }
        if sides.len() > 1 {
            for side in sides {
                compare_parts(reader, base, from, width, std::slice::from_ref(side), at, out)?;
            }
            return Ok(());
        }
        let (side, sf, sw) = &sides[0];
        if width >= *sw && width > 1 {
            let left = width / 2;
            compare_parts(reader, base, from, left, sides, at, out)?;
            return compare_parts(reader, base, from + left, width - left, sides, at, out);
        }
        if *sw > 1 {
            let left = sw / 2;
            compare_parts(reader, base, from, width, &[(side.clone(), *sf, left)], at, out)?;
            return compare_parts(
                reader,
                base,
                from,
                width,
                &[(side.clone(), sf + left, sw - left)],
                at,
                out,
            );
        }
        return Err(Halt::face(
            format!("`compare` refuses {} against {side} down to one position", base.doc),
            format!("{}: the board's compare budget refuses operands of one position", r.token()),
            "this board is not speaking the wire this client expects; nothing was written",
        )
        .into());
    }
    let pairs = answers::compare_pairs(&v).ok_or_else(|| shape("compare", &v))?;
    out.extend(pairs);
    Ok(())
}
