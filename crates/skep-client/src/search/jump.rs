//! The jump's landing rule (`search.md` §3.4).
//!
//! The rule: "the span is re-projected at the jump, never per keystroke.
//! The index answers the hit at `(member, as_of, span)` and the leap, where
//! `member` is not the head the page holds, makes one `compare` read —
//! `rho1` the band the leap's viewport will show at `member` around the
//! hit's span … never a range cut to the span; `rho2` the head's content
//! extent — and the page places the span among the answered pairs". The
//! page composes the operand and the shell makes the read
//! (`frames::compare`); this module holds the one landing rule over the
//! band's pairs as a pure function, [`land`]: "the page first selects the
//! pairs whose `u1` runs overlap the span, then lands where they place the
//! passage — at the head position of the pair covering the hit span's first
//! byte — of several, the first in the head's order — and, where that byte
//! is cut from the head, at the first pair in the head's order; where the
//! pairs carry the whole span onto one contiguous head span, in order, the
//! passage is carried whole and the landing says nothing; where they carry
//! part of it, the landing is a stated partial state … and where they carry
//! none, (43)" — [`Landing::Absent`], the pinned member with foundations'
//! face. Where the board refuses the re-projection on its budgets —
//! `too_many_blocks`, `too_many_pairs`, `image_too_large`, each permanent —
//! "the leap lands on the hit's own span at the pinned member … with no
//! read": [`Landing::Pinned`], which [`landing_of`] answers off the refusal.
//! A scan of the answered pairs, bounded by `MAX_COMPARE_PAIRS`, and no read.
//! The faces are the UX's; this module names the states.

use serde_json::Value;
use skep_search::Span;

use crate::board::{answers, Rejection};

pub use crate::board::answers::Correspondence;

/// Where the leap lands (`search.md` §3.4).
///
/// Where it lands at a head position, the position is in content ordinals of
/// the head's document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Landing {
    /// The pairs carry the whole span onto one contiguous head span, in order.
    ///
    /// The passage is carried whole; the landing says nothing.
    Carried {
        /// The head position of the span's first byte.
        at: u64,
    },
    /// The pairs carry part of the span: a stated partial state.
    ///
    /// Part of the passage is no longer in the head's text.
    Partial {
        /// The head position of the span's first byte.
        ///
        /// Where that byte is cut, it is the head position of the first pair
        /// in the head's order.
        at: u64,
    },
    /// The pairs carry none of the span.
    ///
    /// It is foundations' (43), the pinned member the landing.
    Absent,
    /// The board refused the re-projection on its budgets.
    ///
    /// The landing is the hit's own span at the pinned member, with no read;
    /// the face a third one, the passage's place in the current text not
    /// found.
    Pinned,
}

/// Returns the landing under the one landing rule over the band's pairs.
///
/// `span` is the hit's span at `member` in V-ordinals, `pairs` the
/// `compare` answer's — each a shared run at `u1` in the member and `u2` in
/// the head. Pure; no read. The ordinals are the board's word, so every sum
/// saturates at the top of the range rather than wrap: no conforming answer
/// reaches it, and a hostile one lands at its edge.
pub fn land(span: Span, pairs: &[Correspondence]) -> Landing {
    let end = span.start.saturating_add(span.width);
    let mut overlapping: Vec<&Correspondence> = pairs
        .iter()
        .filter(|p| p.width > 0 && p.u1 < end && p.u1.saturating_add(p.width) > span.start)
        .collect();
    if overlapping.is_empty() {
        return Landing::Absent;
    }
    // The pair covering the span's first byte — of several, the first in
    // the head's order — else the first pair in the head's order.
    let at = match overlapping.iter().filter(|p| p.u1 <= span.start).min_by_key(|p| p.u2) {
        Some(p) => p.u2.saturating_add(span.start - p.u1),
        None => overlapping.iter().min_by_key(|p| p.u2).map(|p| p.u2).unwrap_or(0),
    };
    // Whole and contiguous, in order: walk the pairs by their member start,
    // each clipped to what the pairs before it did not already carry, and
    // require no gap in the member and one contiguous run in the head.
    overlapping.sort_by_key(|p| (p.u1, p.u2));
    let mut cursor = span.start;
    let mut head_cursor: Option<u64> = None;
    let mut whole = true;
    for p in &overlapping {
        if cursor >= end {
            break;
        }
        if p.u1 > cursor {
            whole = false;
            break;
        }
        let clipped_start = p.u1.max(cursor);
        let clipped_end = p.u1.saturating_add(p.width).min(end);
        if clipped_end <= clipped_start {
            continue;
        }
        let head_at = p.u2.saturating_add(clipped_start - p.u1);
        if head_cursor.is_some_and(|h| h != head_at) {
            whole = false;
            break;
        }
        head_cursor = Some(head_at.saturating_add(clipped_end - clipped_start));
        cursor = clipped_end;
    }
    if whole && cursor >= end {
        Landing::Carried { at }
    } else {
        Landing::Partial { at }
    }
}

/// Returns the landing off a `compare` answer.
///
/// The pairs go under [`land`]; one of the three budget refusals —
/// `too_many_blocks`, `too_many_pairs`, `image_too_large` — is
/// [`Landing::Pinned`]; any other document is `None`, the refusal the
/// caller's to face (a `withheld` at the jump is PUB-5.115's departure
/// face, the page's).
pub fn landing_of(answer: &Value, span: Span) -> Option<Landing> {
    if let Some(rejection) = Rejection::of(answer) {
        return matches!(rejection.key(), "too_many_blocks" | "too_many_pairs" | "image_too_large")
            .then_some(Landing::Pinned);
    }
    answers::compare_pairs(answer).map(|pairs| land(span, &pairs))
}
