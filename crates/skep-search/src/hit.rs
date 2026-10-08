//! THE HIT (`search.md` §3.1) — THE CONTRACT THE UX DESIGNS TO (§3.5: "the
//! box, the results and the jump's face are designed to §3.1's hit, §3.2's
//! forms and §3.4's jump — never to the index"). [`Hit`] carries every member
//! §3.1 names, by the design's names: `doc`, the bare document address, which
//! floats (R20); `member`, the pinned member an edition was read at or the
//! draft's own address, absent for a published document without a member;
//! `as_of`, the board position of the read; `span`, the matched passage at
//! `member`/`as_of` in V-ordinals, BYTE-EXACT off the postings' ranges (§2.3,
//! §5.1; fact 11), the first occurrence or a conjunction's tightest window
//! (§3.2); `score`, BM25 over the pair's merged statistics (§3.3); `snippet`,
//! the paragraph window around the span cut from the stored text (§6);
//! `kind`, edition or draft; `standing`; `occurrences`, how many matches the
//! unit holds; and `matched`, each query word corrected by one edit and the
//! term it matched (§3.2 D15) — "what the UX renders as 'matching
//! transclusion'". A hit IS a V-spec (`{doc, span}`) plus a version and a
//! position, what R9d's later `make_link` would name (fact 3) and what the
//! LEAP lands by (§3.4, the shell's). No member of a hit names a file, a
//! path, a principal's directory or another principal's index.
//!
//! [`Standing`] says what `kind` cannot (§3.1): `Public` where every reader
//! reads the span — the published member's edition; `YoursToRead` where this
//! class admits the span and the guest does not — a draft's, so a draft's hit
//! is never `Public`; `Held` where the unit's document lies under a header
//! range the honored set no longer admits (§4's REVOCATION), carrying the
//! CELL of PUB-5.115's KIND × RUNG split and the issuer the departure face
//! names — `kind` and `issuer` off the range's grant record, the `rung` the
//! range's own shape (a document's prefix or an account's; `header`'s
//! `RangeRecord`). The composition is the pair's (`Pair::standing`): the
//! crate sets `Public` and `YoursToRead` from the member of the pair the unit
//! came from, and `Held` by prefix arithmetic over the shell's three inputs,
//! which the pair carries — the supplement header's ranges, the honored set,
//! and the subtree's own and ancestors' ranges, which carry no grant and are
//! never `Held`; no read is made.
//!
//! [`Answer`] is the list with its six members (§3.1): `total` the matching
//! units — EXACT where every candidate was scored, else a LOWER BOUND (§3.2's
//! bounded expansion and positions bound); `truncated` where more units match
//! than `offset + hits.len()` holds, whether or not `total` counts them;
//! `more_terms`, `fuzzy_bounded` and `positions_bounded`, each true exactly
//! where its bound was met (§3.2) — EVERY BOUND IS A FLAG, never a silent cut
//! (PATTERNS P29 as sr-P1 amended it).
//!
//! THE SNIPPET (§6; §3.1's `{ text, start, marks }`) is a RENDERING AND NEVER
//! A COPY SOURCE (§3.1): "a paragraph window around the span — the text
//! between the nearest two blank-line or paragraph breaks, bounded to an
//! INTERIM 240 bytes either side, each bound moved inward to the nearest
//! CHARACTER boundary; a `Gap` inside the window cut out of `text` and
//! carried as a `gap` mark at its offset, the page rendering it (the UX's),
//! an invalid byte of a `hex` stretch (§2.2) the same; a conjunction's window
//! wider than the bound centred on its RAREST matched word (the highest idf),
//! the others marked where they fall inside" — `start` the V-ordinal of the
//! window's first position, `marks` the `(offset, len, kind)` byte ranges
//! inside `text` of the span, of every occurrence of a matched term and of
//! each `Gap`, off the same ranges the postings hold, "so the page marks what
//! matched without parsing". A term mark names the term it marks, so a wide
//! conjunction's window says which of the query's terms fell inside it and,
//! by their absence, which it dropped.

use std::cmp::Ordering;

use skep_address::{Address, Level};

use crate::header::GrantKind;
use crate::unit::{Item, Kind, Unit};

/// THE SNIPPET's BOUND (§6; §7.1's INTERIM pin): "bounded to an INTERIM 240
/// bytes either side" of the span — or of the rarest matched word, where a
/// conjunction's span is wider than this.
pub const SNIPPET_BOUND: u64 = 240;

/// The matched passage (§3.1): `{ start: V-position (subspace 1, ordinal),
/// width: natural }` — `start` the V-ordinal of its first byte, `width` its
/// bytes through the last matched token's end, both read off the postings'
/// ranges from the unit's start (fact 11: a byte offset inside a `content`
/// item IS a V-ordinal offset).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Span {
    /// The V-ordinal of the passage's first byte.
    pub start: u64,
    /// The passage's width in positions.
    pub width: u64,
}

/// The RUNG of PUB-5.115's KIND × RUNG split (§3.1; R90): a grant by DOCUMENT
/// or by ACCOUNT — "the rung is the range's own shape", read off the prefix
/// the widening named as `under=`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Rung {
    /// The range is a document's prefix: all its versions, one `under=`.
    Document,
    /// The range is an account's prefix.
    Account,
}

impl Rung {
    /// The rung a range's shape yields: a document's prefix — or a position
    /// under one — the Document rung, an account's or the node's the Account
    /// rung, the coarser.
    pub fn of(under: &Address) -> Rung {
        match under.level() {
            Level::Document | Level::Element => Rung::Document,
            Level::Node | Level::Account => Rung::Account,
        }
    }
}

/// The hit's STANDING (§3.1), what `kind` cannot say.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Standing {
    /// Every reader reads the span: the published member's edition.
    Public,
    /// This class admits the span and the guest does not: a draft's, under a
    /// range the session's subtree or an honored grant still admits — or a
    /// grant dead with its issuer, "announced by nothing" (R90), which never
    /// leaves the honored set.
    YoursToRead,
    /// The unit's document lies under a header range the honored set no
    /// longer admits (§4's REVOCATION), under no prefix another grant or the
    /// subtree admits: the departed grant's cell and issuer, composed from
    /// the range's own record, "where several departed grants cover the
    /// span, the narrowest prefix's".
    Held {
        /// Named, or any-principal: the grant's kind.
        kind: GrantKind,
        /// By document or by account: the range's own shape.
        rung: Rung,
        /// The grant's issuer, whom the departure face names.
        issuer: Address,
    },
}

/// One correction (§3.1's `matched`; §3.2 D15): a query word matched by ONE
/// EDIT, as typed, and the term it matched.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Matched {
    /// The word as the person typed it.
    pub word: String,
    /// The dictionary term within one edit of it that the unit holds.
    pub term: String,
}

/// What a mark marks (§6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MarkKind {
    /// The hit's span, clipped to the window.
    Span,
    /// One occurrence of a matched term, the term named.
    Term {
        /// The dictionary term the occurrence matched.
        term: String,
    },
    /// A `Gap` cut out of the text — an atom, a withheld run, an unknown
    /// item, or one invalid byte of a `hex` stretch — at its width in
    /// positions; its `len` in the text is zero.
    Gap {
        /// The positions the gap occupies inside the window.
        width: u64,
    },
}

/// One `(offset, len, kind)` byte range inside a snippet's text (§3.1, §6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mark {
    /// The first byte's offset inside `text`.
    pub offset: usize,
    /// The marked bytes; zero for a gap, which the text does not hold.
    pub len: usize,
    /// What is marked.
    pub kind: MarkKind,
}

/// The paragraph window around the span, cut from the stored text (§6;
/// §3.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snippet {
    /// The window's text, the gaps cut out of it: valid UTF-8, never split
    /// inside a character.
    pub text: String,
    /// The V-ordinal of the window's first position — its first byte, or the
    /// gap the mark at offset zero names where the window opens on one.
    pub start: u64,
    /// The span, every occurrence of a matched term and every gap inside the
    /// window, by offset.
    pub marks: Vec<Mark>,
}

/// THE HIT (§3.1), every member by the design's name.
#[derive(Debug, Clone, PartialEq)]
pub struct Hit {
    /// The bare document address — the chain's prefix; floats (R20).
    pub doc: Address,
    /// The PINNED member the unit was read at (an edition's), or the draft's
    /// own address; absent for a published document without a member, read
    /// at its one address (§2.1).
    pub member: Option<Address>,
    /// The board position the unit's read was made at — the last part's.
    pub as_of: u64,
    /// The matched passage at `member`/`as_of`, byte-exact.
    pub span: Span,
    /// BM25 over the pair's merged statistics, one score per query form
    /// summed; a HIGHER score the better match (§3.3).
    pub score: f64,
    /// The paragraph window around the span; absent where no text is stored.
    pub snippet: Option<Snippet>,
    /// Edition or draft.
    pub kind: Kind,
    /// What `kind` cannot say: who reads the span.
    pub standing: Standing,
    /// How many matches this unit holds — every occurrence of the query's
    /// forms, each a mark the snippet would carry; `span` is the first, or
    /// the tightest window.
    pub occurrences: usize,
    /// Each query word matched by one edit and the term it matched; empty
    /// for an exact match.
    pub matched: Vec<Matched>,
}

/// THE ANSWER (§3.1): the hits `opts` bounds and the five facts about them.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Answer {
    /// The hits from `offset`, at most `limit`, in §3.3's order.
    pub hits: Vec<Hit>,
    /// The matching units — EXACT where every candidate was scored, else a
    /// LOWER BOUND: where the expansion met its bound or the evaluation
    /// stopped at its positions bound.
    pub total: usize,
    /// Whether more units match than `offset + hits.len()` holds — the list
    /// cut by `limit`, or the evaluation stopped with candidates left —
    /// whether or not `total` counts them.
    pub truncated: bool,
    /// Whether an expansion — a prefix's, a phrase-prefix's or a fuzzy word's
    /// candidates — met its bound in postings entries (§3.2).
    pub more_terms: bool,
    /// Whether a complete word of the query was matched as typed because the
    /// fuzzy bound left it unexpanded (§3.2).
    pub fuzzy_bounded: bool,
    /// Whether the keystroke's whole evaluation stopped at its positions
    /// bound, the hits ranked among the units reached (§3.2).
    pub positions_bounded: bool,
}

/// A token the snippet marks: its range from the unit's start and the term
/// it matched.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Marked<'a> {
    pub(crate) offset: u64,
    pub(crate) len: u32,
    pub(crate) term: &'a str,
}

/// THE TIGHTEST WINDOW (§3.2's conjunction: "ranked by BM25 with the TIGHTEST
/// WINDOW holding one occurrence of each as the hit's span"): over one
/// match list per form, each a `(start, end)` in offsets from the unit's
/// start and sorted by start, the window of least width holding one match of
/// every form — of equal widths the earliest — as `(start, end, the chosen
/// match per form)`. `None` where some form has no match. For one form the
/// window is its first match.
pub(crate) fn tightest(forms: &[Vec<(u64, u64)>]) -> Option<(u64, u64, Vec<usize>)> {
    if forms.is_empty() || forms.iter().any(Vec::is_empty) {
        return None;
    }
    // Per form, the least end over the matches from an index on: the match
    // with the least end among those starting at or after a left edge.
    let suffix_min: Vec<Vec<(u64, usize)>> = forms
        .iter()
        .map(|list| {
            let mut out = vec![(0u64, 0usize); list.len()];
            let mut best: Option<(u64, usize)> = None;
            for (i, &(_, end)) in list.iter().enumerate().rev() {
                best = match best {
                    Some((e, j)) if e <= end => Some((e, j)),
                    _ => Some((end, i)),
                };
                out[i] = best.expect("set above");
            }
            out
        })
        .collect();
    let mut best: Option<(u64, u64, Vec<usize>)> = None;
    for (f, list) in forms.iter().enumerate() {
        for (i, &(start, end)) in list.iter().enumerate() {
            let mut window_end = end;
            let mut chosen = vec![0usize; forms.len()];
            chosen[f] = i;
            let mut whole = true;
            for (g, other) in forms.iter().enumerate() {
                if g == f {
                    continue;
                }
                let k = other.partition_point(|&(s, _)| s < start);
                if k == other.len() {
                    whole = false;
                    break;
                }
                let (e, j) = suffix_min[g][k];
                chosen[g] = j;
                window_end = window_end.max(e);
            }
            if !whole {
                continue;
            }
            let better = match &best {
                None => true,
                Some((s, e, _)) => {
                    let (width, best_width) = (window_end - start, e - s);
                    width < best_width || (width == best_width && start < *s)
                }
            };
            if better {
                best = Some((start, window_end, chosen));
            }
        }
    }
    best
}

/// THE SNIPPET's CUT (§6), over the unit's stored text: the window around
/// the span — or around `focus`, the rarest matched word's occurrence, where
/// the span is wider than the bound — narrowed to the nearest paragraph
/// breaks, bounded to [`SNIPPET_BOUND`] positions either side, each bound
/// moved inward to a character boundary; the window's text with every gap
/// and invalid byte cut out and marked, the span and each marked token
/// placed inside it. Offsets in `span` are V-ordinals; `focus` and `marked`
/// are offsets from the unit's start.
pub(crate) fn snippet(
    unit: &Unit,
    span: Span,
    focus: (u64, u64),
    marked: &[Marked<'_>],
) -> Snippet {
    let base = unit.start();
    let extent = unit.positions();
    let span_lo = span.start - base;
    let span_hi = span_lo + span.width;
    let (centre_lo, centre_hi) =
        if span.width > SNIPPET_BOUND { focus } else { (span_lo, span_hi) };
    let mut lo = centre_lo.saturating_sub(SNIPPET_BOUND);
    let mut hi = centre_hi.saturating_add(SNIPPET_BOUND).min(extent);
    if let Some(after) = last_break_before(unit, lo, centre_lo) {
        lo = after;
    }
    if let Some(at) = first_break_after(unit, centre_hi, hi) {
        hi = at;
    }
    lo = boundary_forward(unit, lo, centre_lo);
    hi = boundary_back(unit, hi, centre_hi);

    let mut text = String::new();
    let mut marks = Vec::new();
    // The valid stretches rendered: `(from, to)` in offsets, and the text
    // offset `from` landed at.
    let mut stretches: Vec<(u64, u64, usize)> = Vec::new();
    for item in unit.items() {
        let from = item.start() - base;
        let to = from + item.width();
        if to <= lo || from >= hi {
            continue;
        }
        let (a, b) = (from.max(lo), to.min(hi));
        match item {
            Item::Gap { .. } => {
                marks.push(Mark {
                    offset: text.len(),
                    len: 0,
                    kind: MarkKind::Gap { width: b - a },
                });
            }
            Item::Text { bytes, .. } => {
                let slice = &bytes[(a - from) as usize..(b - from) as usize];
                let mut at = a;
                for chunk in slice.utf8_chunks() {
                    let valid = chunk.valid();
                    if !valid.is_empty() {
                        stretches.push((at, at + valid.len() as u64, text.len()));
                        text.push_str(valid);
                        at += valid.len() as u64;
                    }
                    for _ in chunk.invalid() {
                        marks.push(Mark {
                            offset: text.len(),
                            len: 0,
                            kind: MarkKind::Gap { width: 1 },
                        });
                        at += 1;
                    }
                }
            }
        }
    }
    let to_text = |position: u64| -> usize {
        for &(from, to, at) in &stretches {
            if position < from {
                return at;
            }
            if position <= to {
                return at + (position - from) as usize;
            }
        }
        text.len()
    };
    let (a, b) = (to_text(span_lo.clamp(lo, hi)), to_text(span_hi.clamp(lo, hi)));
    marks.push(Mark { offset: a, len: b - a, kind: MarkKind::Span });
    for token in marked {
        let (s, e) = (token.offset, token.offset + u64::from(token.len));
        if e <= lo || s >= hi {
            continue;
        }
        let (a, b) = (to_text(s.max(lo)), to_text(e.min(hi)));
        if b > a {
            marks.push(Mark {
                offset: a,
                len: b - a,
                kind: MarkKind::Term { term: token.term.to_string() },
            });
        }
    }
    marks.sort_by(mark_order);
    Snippet { text, start: base + lo, marks }
}

/// The marks' order: by offset, then a gap — which sits before the text at
/// its offset, having been cut out there — before the span before a term,
/// then by length and the term's spelling — one order on every run.
fn mark_order(a: &Mark, b: &Mark) -> Ordering {
    fn rank(kind: &MarkKind) -> (u8, &str) {
        match kind {
            MarkKind::Gap { .. } => (0, ""),
            MarkKind::Span => (1, ""),
            MarkKind::Term { term } => (2, term.as_str()),
        }
    }
    let (ra, rb) = (rank(&a.kind), rank(&b.kind));
    a.offset.cmp(&b.offset).then(ra.0.cmp(&rb.0)).then(a.len.cmp(&b.len)).then(ra.1.cmp(rb.1))
}

/// The paragraph breaks inside `bytes`, each as `(start, end)`: a BLANK LINE
/// — a line feed, horizontal whitespace or carriage returns, and a second
/// line feed — or U+2029 PARAGRAPH SEPARATOR. A lone line feed is a soft
/// wrap, not a break: the project's own prose is hard-wrapped.
fn breaks(bytes: &[u8]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\n' {
            let mut j = i + 1;
            while j < bytes.len() && matches!(bytes[j], b' ' | b'\t' | b'\r') {
                j += 1;
            }
            if j < bytes.len() && bytes[j] == b'\n' {
                out.push((i, j + 1));
                i = j + 1;
                continue;
            }
        } else if bytes[i] == 0xE2
            && bytes.get(i + 1) == Some(&0x80)
            && bytes.get(i + 2) == Some(&0xA9)
        {
            out.push((i, i + 3));
            i += 3;
            continue;
        }
        i += 1;
    }
    out
}

/// The text items overlapping the offsets `[lo, hi)`, each as the overlap's
/// start offset and its bytes.
fn text_within(unit: &Unit, lo: u64, hi: u64) -> impl Iterator<Item = (u64, &[u8])> {
    let base = unit.start();
    unit.items().iter().filter_map(move |item| match item {
        Item::Text { start, bytes } => {
            let from = start - base;
            let to = from + bytes.len() as u64;
            if to <= lo || from >= hi {
                return None;
            }
            let (a, b) = (from.max(lo), to.min(hi));
            Some((a, &bytes[(a - from) as usize..(b - from) as usize]))
        }
        Item::Gap { .. } => None,
    })
}

/// The offset after the last paragraph break inside `[lo, until)`.
fn last_break_before(unit: &Unit, lo: u64, until: u64) -> Option<u64> {
    let mut found = None;
    for (at, bytes) in text_within(unit, lo, until) {
        if let Some(&(_, end)) = breaks(bytes).last() {
            found = Some(at + end as u64);
        }
    }
    found
}

/// The offset of the first paragraph break inside `[from, hi)`.
fn first_break_after(unit: &Unit, from: u64, hi: u64) -> Option<u64> {
    text_within(unit, from, hi)
        .find_map(|(at, bytes)| breaks(bytes).first().map(|&(start, _)| at + start as u64))
}

fn is_continuation(byte: u8) -> bool {
    byte & 0xC0 == 0x80
}

/// The text item holding the offset, as its start offset and its bytes.
fn text_at(unit: &Unit, offset: u64) -> Option<(u64, &[u8])> {
    match &unit.items()[unit.item_at(offset)?] {
        Item::Text { start, bytes } => Some((start - unit.start(), bytes)),
        Item::Gap { .. } => None,
    }
}

/// `lo` moved forward to a character boundary where it falls inside a text
/// item, never past `limit`.
fn boundary_forward(unit: &Unit, mut lo: u64, limit: u64) -> u64 {
    if let Some((from, bytes)) = text_at(unit, lo) {
        while lo < limit && lo > from && is_continuation(bytes[(lo - from) as usize]) {
            lo += 1;
        }
    }
    lo
}

/// `hi` moved back to a character boundary where the byte at it continues a
/// character begun before it, never below `limit`.
fn boundary_back(unit: &Unit, mut hi: u64, limit: u64) -> u64 {
    if let Some((from, bytes)) = text_at(unit, hi) {
        while hi > limit && hi > from && is_continuation(bytes[(hi - from) as usize]) {
            hi -= 1;
        }
    }
    hi
}

#[cfg(test)]
mod tests;
