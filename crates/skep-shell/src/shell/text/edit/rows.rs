//! The rows of `text.edit`'s answer: the lines the call changed (skep #1080).
//!
//! An `edited` answer names each change by byte counts and addresses; the
//! rows show the lines themselves, numbered, so a caller sees its edit
//! without reading the draft back. They are drawn from the text the call
//! already holds — the draft's one read with every pair applied in memory
//! (`Text::splice`), which is the draft exactly as the call's last write left
//! it, each write typed against the one before — and no read is made for
//! them. The module is a function of that text and of where each of its
//! positions came from: it writes nothing and reads no board.
//!
//! **The pieces** ([`Pieces`]). As the plan splices the text pair by pair, it
//! splices the pieces in step: each run of the text's positions is either a
//! run the draft held when it was read, by its position then, or bytes the
//! call inserted. The bytes a pair's minimal changes leave standing keep
//! their pieces — an earlier pair's insert stays one — and every byte a
//! change removes of the draft as read is kept by its position, as the
//! pair's own `old` spells it.
//!
//! **The stretches.** The stretches are read off the pieces of the text as
//! the call leaves it, so a change shifts every one after it: bytes the call
//! inserted side by side, and a removal touching them, are one stretch,
//! whichever pairs made them.
//!
//! **The lines.** Lines are counted as `line_numbers` counts them (wire.md
//! §Content & provenance reads): a line break is the byte 0x0A; a value that
//! is no text — an atom, a withheld run — holds none; line 1 starts at
//! position 1 and line N one position past line break N − 1; and a text that
//! ends in a line break has no empty last line.
//!
//! **The slide.** A stretch that only inserts or only removes leaves the same
//! text told one byte back, where the byte before it is text equal to its
//! last byte, and one byte on, where the byte after it is text equal to its
//! first. One that starts no line is moved, one byte at a time, back to the
//! first line start it reaches, else on to the first it reaches; where
//! neither reaches one it stays, and it is never moved into or against
//! another stretch.
//!
//! **The rows.** Each line holding a byte the call inserted is `+N<TAB>line`,
//! and the [`ROWS_CONTEXT_LINES`] lines either side of it ` N<TAB>line`. A
//! removal of whole lines — one from a line start that ends with a line
//! break or at the text's end, or one that starts with a line break and
//! ends before the next line break, or at the text's end having taken more
//! than that break — is the row `-<TAB>(N bytes removed here)` between the
//! lines that now meet, `, at the text's end` before its `)` where it is
//! there, with the lines either side of it; any other removal marks the line
//! its two sides now meet on `+N`.
//! Rows whose lines do not touch are parted by `--`. A run of more than
//! [`ROWS_MAX_RUN`] `+` rows in a row shows its first [`ROWS_RUN_HEAD`], then
//! `+…<TAB>(N more lines)`, then its last [`ROWS_RUN_TAIL`]. A row shows its
//! line without the line break; past [`ROWS_MAX_LINE_CHARS`] characters — a
//! character being a UTF-8 character, a byte that is no UTF-8, or a value
//! that is no text — it is cut, `…[+N chars]` counting the rest; bytes that
//! are no UTF-8 are `{hex:…}`, each run of them one, and each value that is
//! no text is `{…}`. The rows stop before the first that would take them
//! past [`ROWS_MAX_BYTES`], a last row `(N more changed lines not shown)`
//! counting the `+` and `-` rows left. `masked` is set beside them where a
//! withheld run stands on or before a line they show: its line breaks are
//! counted nowhere, so every number past it is the caller's own view.
//!
//! **The cost** (SP-23). The pieces are spliced as the text is: each pair's
//! splice walks the pieces once and moves those after it, as `Text::splice`
//! walks and moves the bytes, so the plan's cost keeps its order. The rows
//! are one walk of the text numbering the stretches' lines and one more
//! drawing the lines they show; a slide reads at most the line it moves in,
//! and each removed byte it reads is a lookup among the runs removed.

use std::fmt::Write as _;
use std::ops::{Range, RangeInclusive};

use skep_client::text::Change;

use super::super::Text;

/// The unchanged lines the rows show either side of a change.
pub const ROWS_CONTEXT_LINES: usize = 2;

/// The most `+` rows in a row a run shows whole.
///
/// A longer run shows its first [`ROWS_RUN_HEAD`] and its last
/// [`ROWS_RUN_TAIL`], with one row between them counting the rest.
pub const ROWS_MAX_RUN: usize = 16;

/// The `+` rows a run past [`ROWS_MAX_RUN`] shows from its start.
pub const ROWS_RUN_HEAD: usize = 6;

/// The `+` rows a run past [`ROWS_MAX_RUN`] shows at its end.
pub const ROWS_RUN_TAIL: usize = 3;

/// The most characters of its line a row shows.
pub const ROWS_MAX_LINE_CHARS: usize = 2000;

/// The most bytes the rows take, bar the row that counts what they leave out.
pub const ROWS_MAX_BYTES: usize = 40_000;

/// A run of the text's positions, and where it came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Piece {
    /// Positions the draft held when it was read.
    Kept {
        /// The position the first of them held as read.
        from: u64,
        /// How many.
        len: u64,
    },
    /// Bytes the call inserted.
    New {
        /// How many.
        len: u64,
    },
}

impl Piece {
    /// Returns how many positions the piece is.
    fn len(self) -> u64 {
        match self {
            Piece::Kept { len, .. } | Piece::New { len } => len,
        }
    }

    /// Returns the piece's positions from `start` to `end` into it.
    fn part(self, start: u64, end: u64) -> Piece {
        match self {
            Piece::Kept { from, .. } => Piece::Kept { from: from + start, len: end - start },
            Piece::New { .. } => Piece::New { len: end - start },
        }
    }

    /// Returns the one piece `self` and `next`, side by side, make, where they
    /// make one.
    fn joined(self, next: Piece) -> Option<Piece> {
        match (self, next) {
            (Piece::New { len }, Piece::New { len: more }) => Some(Piece::New { len: len + more }),
            (Piece::Kept { from, len }, Piece::Kept { from: then, len: more }) if from + len == then => Some(Piece::Kept { from, len: len + more }),
            _ => None,
        }
    }
}

/// Pushes `piece` onto `pieces`, joined to the last where the two are one.
///
/// A piece of no positions is no piece, and is not pushed.
fn push(pieces: &mut Vec<Piece>, piece: Piece) {
    if piece.len() == 0 {
        return;
    }
    match pieces.last_mut() {
        Some(last) => match last.joined(piece) {
            Some(joined) => *last = joined,
            None => pieces.push(piece),
        },
        None => pieces.push(piece),
    }
}

/// A walk through pieces by positions, counted from the first piece's start.
struct Walk<'p> {
    /// The pieces walked.
    pieces: &'p [Piece],
    /// The piece the walk stands in.
    k: usize,
    /// How far into that piece.
    into: u64,
    /// How far from the first piece's start.
    at: u64,
}

impl Walk<'_> {
    /// Walks on to `to`, handing `each` the part of every piece it passes
    /// and where that part starts.
    ///
    /// A walk past the pieces' end stops at it.
    fn to(&mut self, to: u64, mut each: impl FnMut(Piece, u64)) {
        while self.at < to {
            let Some(&piece) = self.pieces.get(self.k) else { return };
            let take = (piece.len() - self.into).min(to - self.at);
            each(piece.part(self.into, self.into + take), self.at);
            self.at += take;
            self.into += take;
            if self.into == piece.len() {
                self.k += 1;
                self.into = 0;
            }
        }
    }
}

/// Where each position of the text the call leaves came from.
///
/// Its invariant, kept by [`Pieces::splice`], the one way it changes: the
/// pieces' lengths sum to the text's positions, none is empty, and no two
/// side by side make one; each removed run is of positions no piece keeps,
/// and no position is in two.
#[derive(Debug)]
pub(super) struct Pieces<'a> {
    /// The pieces, in the text's order.
    pieces: Vec<Piece>,
    /// The runs of bytes the call removed of the draft as read.
    ///
    /// Each is the position its first byte held as read, and its bytes as
    /// the `old` of the pair that removed them spells them.
    removed: Vec<(u64, &'a [u8])>,
    /// How many positions the draft held as read.
    read: u64,
}

impl<'a> Pieces<'a> {
    /// Returns the pieces of a draft read whole, `read` positions of it.
    pub(super) fn of(read: u64) -> Pieces<'a> {
        let mut pieces = Vec::new();
        push(&mut pieces, Piece::Kept { from: 1, len: read });
        Pieces { pieces, removed: Vec::new(), read }
    }

    /// Splices the pieces as a pair's text is spliced.
    ///
    /// `old`, standing at the position `found`, is made into its pair's new
    /// text by `changes`, its minimal changes: the bytes between two changes
    /// keep their pieces, each change's new bytes are a piece the call
    /// inserted, and each byte a change removes that the draft held as read
    /// is kept by its position.
    ///
    /// **Precondition.** `old` stands at `found` in the text the pieces are
    /// of, as a `Found::Once` of it says, and `changes` are
    /// `minimal_changes(old, …)`'s.
    pub(super) fn splice(&mut self, found: u64, old: &'a str, changes: &[Change]) {
        let first = self.cut(found);
        let last = self.cut(found.saturating_add(old.len() as u64));
        let taken: Vec<Piece> = self.pieces.drain(first..last).collect();
        let mut walk = Walk { pieces: &taken, k: 0, into: 0, at: 0 };
        let mut put = Vec::with_capacity(taken.len() + 2 * changes.len());
        for change in changes {
            walk.to(change.old.start as u64, |piece, _| push(&mut put, piece));
            walk.to(change.old.end as u64, |piece, at| {
                if let Piece::Kept { from, len } = piece {
                    if let Some(bytes) = usize::try_from(at).ok().zip(usize::try_from(at + len).ok()).and_then(|(start, end)| old.as_bytes().get(start..end)) {
                        self.removed.push((from, bytes));
                    }
                }
            });
            push(&mut put, Piece::New { len: change.new.len() as u64 });
        }
        walk.to(old.len() as u64, |piece, _| push(&mut put, piece));
        let after = first + put.len();
        self.pieces.splice(first..first, put);
        self.join(after);
        self.join(first);
    }

    /// Returns the index of the piece that starts at `position`.
    ///
    /// The piece that holds `position` and does not start there is cut in
    /// two first; a position past every piece is the index past them.
    fn cut(&mut self, position: u64) -> usize {
        let mut start = 1;
        for k in 0..self.pieces.len() {
            let piece = self.pieces[k];
            if position <= start {
                return k;
            }
            if position < start + piece.len() {
                let into = position - start;
                self.pieces[k] = piece.part(0, into);
                self.pieces.insert(k + 1, piece.part(into, piece.len()));
                return k + 1;
            }
            start += piece.len();
        }
        self.pieces.len()
    }

    /// Joins the pieces either side of the seam before the piece `k`, where
    /// the two make one.
    fn join(&mut self, k: usize) {
        let Some(before) = k.checked_sub(1) else { return };
        if let Some(joined) = self.pieces.get(before).zip(self.pieces.get(k)).and_then(|(one, next)| one.joined(*next)) {
            self.pieces[before] = joined;
            self.pieces.remove(k);
        }
    }

    /// Returns the call's stretches of changes, in the text's order.
    ///
    /// A stretch is a run of inserted bytes, the removal touching it, or a
    /// removal alone: positions the draft held as read that no piece keeps,
    /// between two that pieces do.
    fn changed(&self) -> Vec<Changed> {
        let (mut all, mut open, mut kept_to, mut at) = (Vec::new(), None::<Changed>, 1, 1);
        for piece in &self.pieces {
            match *piece {
                Piece::New { len } => {
                    let stretch = open.get_or_insert(Changed { new: at..at, gone: kept_to..kept_to });
                    stretch.new.end = at + len;
                }
                Piece::Kept { from, len } => {
                    if from > kept_to {
                        open.get_or_insert(Changed { new: at..at, gone: kept_to..kept_to }).gone = kept_to..from;
                    }
                    all.extend(open.take());
                    kept_to = from + len;
                }
            }
            at += piece.len();
        }
        if kept_to <= self.read {
            open.get_or_insert(Changed { new: at..at, gone: kept_to..kept_to }).gone = kept_to..self.read + 1;
        }
        all.extend(open);
        all
    }
}

/// One stretch of the call's changes in the text it leaves.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Changed {
    /// The positions of the bytes it inserted.
    ///
    /// Where it inserted none, it is empty at the place its removal left.
    new: Range<u64>,
    /// The positions it removed, as the draft held them when read.
    ///
    /// Empty where it removed none.
    gone: Range<u64>,
}

/// The runs of bytes the call removed, ascending by position as read.
struct Removed<'r> {
    /// Each run: the position its first byte held as read, and its bytes.
    runs: &'r [(u64, &'r [u8])],
}

impl Removed<'_> {
    /// Returns the byte the draft held at `position` as read, where the call
    /// removed it.
    fn byte(&self, position: u64) -> Option<u8> {
        let k = self.runs.partition_point(|(from, _)| *from <= position).checked_sub(1)?;
        let (from, bytes) = self.runs.get(k)?;
        usize::try_from(position - from).ok().and_then(|into| bytes.get(into)).copied()
    }
}

/// The text as the call leaves it, read by position.
#[derive(Debug, Clone, Copy)]
struct Draft<'t> {
    /// The text.
    text: &'t Text,
}

impl Draft<'_> {
    /// Returns the byte of text at `position`, none where a value that is no
    /// text, or nothing, stands.
    fn byte(self, position: u64) -> Option<u8> {
        let stretches = &self.text.stretches;
        let k = stretches.partition_point(|stretch| stretch.ordinal <= position).checked_sub(1)?;
        let stretch = stretches.get(k)?;
        let into = usize::try_from(position - stretch.ordinal).ok().filter(|into| *into < stretch.len)?;
        self.text.bytes.get(stretch.at + into).copied()
    }

    /// Returns whether a line starts at `position`: the first position, or
    /// one past a line break.
    fn starts_line(self, position: u64) -> bool {
        position <= 1 || self.byte(position - 1) == Some(b'\n')
    }

    /// Returns the position past the text's last.
    fn end(self) -> u64 {
        self.text.positions() + 1
    }
}

/// What a stretch shows, placed.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Mark {
    /// Bytes the call inserted, at these positions: each line holding one
    /// is a `+` row.
    Inserted(Range<u64>),
    /// A removal that took no whole line: the line its sides meet on, at
    /// this place, is a `+` row.
    Within(u64),
    /// A removal of whole lines: a `-` row where its sides meet.
    Lines {
        /// The place its sides meet.
        at: u64,
        /// Whether a line starts at the place; else the place ends one.
        starts: bool,
        /// How many bytes it removed.
        bytes: u64,
    },
}

/// Returns the positions inserted bytes are told at, slid.
///
/// Bytes at `new` that start no line are moved back, one at a time, while
/// the byte before them is text equal to their last, to the first line
/// start that reaches; else on, while the byte after them is text equal to
/// their first, to the first line start that reaches; else they stay. The
/// move keeps them clear of the stretch before, which ends at `floor`, and
/// the one after, which starts at `ceiling`.
fn slid(draft: Draft<'_>, new: Range<u64>, floor: u64, ceiling: u64) -> Range<u64> {
    let (start, end) = (new.start, new.end);
    if draft.starts_line(start) {
        return new;
    }
    let mut back = 0;
    while start - back > floor + 1 && draft.byte(start - back - 1).is_some_and(|before| draft.byte(end - back - 1) == Some(before)) {
        back += 1;
        if draft.starts_line(start - back) {
            return start - back..end - back;
        }
    }
    let mut on = 0;
    while end + on + 1 < ceiling && draft.byte(end + on).is_some_and(|after| draft.byte(start + on) == Some(after)) {
        on += 1;
        if draft.starts_line(start + on) {
            return start + on..end + on;
        }
    }
    new
}

/// Returns how a removal is told, slid and placed.
///
/// Its sides meet at `at`, and it removed the positions `gone` as read,
/// whose bytes `removed` holds. It is slid as inserted bytes are ([`slid`]):
/// told one byte back where the text before `at` ends in the removed bytes'
/// last, one on where the text after `at` starts with their first. Placed,
/// it took whole lines where a line starts at its place and its last byte
/// is a line break or the place is the text's end; and where its first byte
/// is a line break and either a line break stands at its place or the place
/// is the text's end and it removed more than that break.
fn removal(draft: Draft<'_>, removed: &Removed<'_>, at: u64, gone: Range<u64>, floor: u64, ceiling: u64) -> Mark {
    let width = gone.end - gone.start;
    let byte = |k: u64| removed.byte(gone.start + k);
    // The text before the place, then the removed bytes; and the removed
    // bytes, then the text after the place.
    let behind = |i: u64| if i < at { draft.byte(i) } else { byte(i - at) };
    let ahead = |j: u64| if j < width { byte(j) } else { draft.byte(at + j - width) };
    let (mut place, mut first, mut last) = (at, byte(0), byte(width - 1));
    'slide: {
        if draft.starts_line(at) {
            break 'slide;
        }
        let mut back = 0;
        while at - back > floor + 1 && draft.byte(at - back - 1).is_some_and(|before| behind(at - back - 1 + width) == Some(before)) {
            back += 1;
            if draft.starts_line(at - back) {
                (place, first, last) = (at - back, behind(at - back), behind(at - back + width - 1));
                break 'slide;
            }
        }
        let mut on = 0;
        while at + on + 1 < ceiling && draft.byte(at + on).is_some_and(|after| ahead(on) == Some(after)) {
            on += 1;
            if draft.starts_line(at + on) {
                (place, first, last) = (at + on, ahead(on), ahead(on + width - 1));
                break 'slide;
            }
        }
    }
    let end = place == draft.end();
    let starts = draft.starts_line(place);
    let whole = (starts && (last == Some(b'\n') || end)) || (first == Some(b'\n') && (draft.byte(place) == Some(b'\n') || (end && width > 1)));
    if whole {
        Mark::Lines { at: place, starts, bytes: width }
    } else {
        Mark::Within(place)
    }
}

/// Returns how each stretch is told, slid and placed, in the text's order.
fn marks(draft: Draft<'_>, removed: &Removed<'_>, stretches: &[Changed]) -> Vec<Mark> {
    let mut marks = Vec::with_capacity(stretches.len());
    let mut floor = 0;
    for (k, stretch) in stretches.iter().enumerate() {
        let ceiling = stretches.get(k + 1).map_or(u64::MAX, |next| next.new.start);
        let mark = match (stretch.new.is_empty(), stretch.gone.is_empty()) {
            (false, true) => Mark::Inserted(slid(draft, stretch.new.clone(), floor, ceiling)),
            (true, false) => removal(draft, removed, stretch.new.start, stretch.gone.clone(), floor, ceiling),
            _ => Mark::Inserted(stretch.new.clone()),
        };
        floor = match &mark {
            Mark::Inserted(new) => new.end,
            Mark::Within(at) | Mark::Lines { at, .. } => *at,
        };
        marks.push(mark);
    }
    marks
}

/// The line numbers of positions asked in ascending order, by one walk.
struct Numbering<'t> {
    /// The text.
    text: &'t Text,
    /// The stretch of text the walk stands in.
    k: usize,
    /// The first position not yet counted.
    counted_to: u64,
    /// The line breaks counted.
    breaks: u64,
}

impl<'t> Numbering<'t> {
    /// Returns a numbering of `text` from its first position.
    fn of(text: &'t Text) -> Numbering<'t> {
        Numbering { text, k: 0, counted_to: 1, breaks: 0 }
    }

    /// Returns the line `position` is on: one past the line breaks before it.
    ///
    /// A position asked before one asked already is numbered as that one.
    fn line(&mut self, position: u64) -> u64 {
        while let Some(stretch) = self.text.stretches.get(self.k) {
            let past = stretch.ordinal + stretch.len as u64;
            let (from, to) = (self.counted_to.max(stretch.ordinal), past.min(position));
            if from < to {
                let (start, end) = (stretch.at + (from - stretch.ordinal) as usize, stretch.at + (to - stretch.ordinal) as usize);
                self.breaks += self.text.bytes.get(start..end).unwrap_or_default().iter().filter(|byte| **byte == b'\n').count() as u64;
            }
            if past > position {
                break;
            }
            self.k += 1;
        }
        self.counted_to = self.counted_to.max(position);
        self.breaks + 1
    }
}

/// A `-` row: where whole lines went.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Gone {
    /// The line the row follows; 0 where it stands before the first.
    after: u64,
    /// How many bytes went.
    bytes: u64,
    /// Whether they went at the text's end.
    at_end: bool,
}

/// One row the rows are to show.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Spec {
    /// A line, `+` where it holds a change.
    Line {
        /// Its number.
        number: u64,
        /// Whether it holds a change.
        changed: bool,
    },
    /// The `+` rows a long run leaves out.
    More {
        /// How many.
        lines: u64,
        /// The number of the last of them.
        through: u64,
    },
    /// A `-` row.
    Gone(Gone),
    /// The `--` between rows whose lines do not touch.
    Parted,
}

/// What the rows show: the `+` lines, the `-` rows, and the text's lines.
#[derive(Debug)]
struct Shown {
    /// The `+` lines, as runs of numbers, ascending, no two touching.
    changed: Vec<RangeInclusive<u64>>,
    /// The `-` rows, ascending.
    gone: Vec<Gone>,
    /// How many lines the text holds.
    lines: u64,
    /// The line the first withheld run stands on, where one stands.
    withheld: Option<u64>,
}

impl Shown {
    /// Returns what the rows show of `text`, its stretches told as `marks`.
    fn of(draft: Draft<'_>, marks: &[Mark]) -> Shown {
        let text = draft.text;
        let mut numbering = Numbering::of(text);
        let (mut changed, mut gone): (Vec<RangeInclusive<u64>>, Vec<Gone>) = (Vec::new(), Vec::new());
        let mut add = |run: RangeInclusive<u64>| match changed.last_mut() {
            Some(last) if *run.start() <= last.end() + 1 => *last = *last.start()..=(*run.end()).max(*last.end()),
            _ => changed.push(run),
        };
        for mark in marks {
            match mark {
                Mark::Inserted(new) if !new.is_empty() => {
                    let first = numbering.line(new.start);
                    add(first..=numbering.line(new.end - 1));
                }
                Mark::Within(at) => {
                    let line = numbering.line(*at);
                    add(line..=line);
                }
                Mark::Lines { at, starts, bytes } => {
                    let line = numbering.line(*at);
                    gone.push(Gone { after: if *starts { line - 1 } else { line }, bytes: *bytes, at_end: *at == draft.end() });
                }
                Mark::Inserted(_) => {}
            }
        }
        let breaks = text.bytes.iter().filter(|byte| **byte == b'\n').count() as u64;
        let positions = text.positions();
        let lines = breaks + u64::from(positions > 0 && draft.byte(positions) != Some(b'\n'));
        let withheld = text.gaps.iter().find(|gap| gap.kind == "withheld").map(|gap| Numbering::of(text).line(gap.ordinal));
        Shown { changed, gone, lines, withheld }
    }

    /// Returns the rows to show, in order.
    ///
    /// The lines shown are the [`ROWS_CONTEXT_LINES`] either side of each run
    /// of `+` lines and of each `-` row; lines shown that touch are one
    /// group, and `--` parts two groups.
    fn specs(&self) -> Vec<Spec> {
        let context = ROWS_CONTEXT_LINES as u64;
        let mut spans: Vec<(u64, u64)> = self.changed.iter().map(|run| (run.start().saturating_sub(context).max(1), (run.end() + context).min(self.lines))).collect();
        spans.extend(self.gone.iter().map(|row| ((row.after + 1).saturating_sub(context).max(1), (row.after + context).min(self.lines))));
        spans.retain(|(low, high)| low <= high);
        spans.sort_unstable();
        let mut groups: Vec<(u64, u64)> = Vec::new();
        for (low, high) in spans {
            match groups.last_mut() {
                Some(last) if low <= last.1 + 1 => last.1 = last.1.max(high),
                _ => groups.push((low, high)),
            }
        }
        let (mut specs, mut gone, mut changed) = (Vec::new(), self.gone.iter().peekable(), self.changed.iter().peekable());
        for (k, (low, high)) in groups.into_iter().enumerate() {
            if k > 0 {
                specs.push(Spec::Parted);
            }
            let mut line = low;
            while line <= high {
                while let Some(row) = gone.next_if(|row| row.after < line) {
                    specs.push(Spec::Gone(row.clone()));
                }
                while changed.next_if(|run| *run.end() < line).is_some() {}
                let Some(run) = changed.peek().filter(|run| run.contains(&line)) else {
                    specs.push(Spec::Line { number: line, changed: false });
                    line += 1;
                    continue;
                };
                // A run of `+` rows ends at its last line, or at a `-` row.
                let last = gone.peek().map_or(*run.end(), |row| row.after.min(*run.end()));
                let count = last - line + 1;
                if count > ROWS_MAX_RUN as u64 {
                    let (head, tail) = (ROWS_RUN_HEAD as u64, ROWS_RUN_TAIL as u64);
                    specs.extend((line..line + head).map(|number| Spec::Line { number, changed: true }));
                    specs.push(Spec::More { lines: count - head - tail, through: last - tail });
                    specs.extend((last + 1 - tail..=last).map(|number| Spec::Line { number, changed: true }));
                } else {
                    specs.extend((line..=last).map(|number| Spec::Line { number, changed: true }));
                }
                line = last + 1;
            }
            while let Some(row) = gone.next_if(|row| row.after <= high) {
                specs.push(Spec::Gone(row.clone()));
            }
        }
        specs.extend(gone.cloned().map(Spec::Gone));
        specs
    }

    /// Returns the rows, drawn from `text`, and whether a withheld run
    /// stands on or before a line they show.
    fn drawn(&self, text: &Text) -> Rows {
        let total = self.changed.iter().map(|run| run.end() - run.start() + 1).sum::<u64>() + self.gone.len() as u64;
        let mut walk = LineWalk::of(text);
        let (mut lines, mut used, mut told, mut reach) = (Vec::new(), 0, 0, 0);
        for spec in self.specs() {
            let (row, changes, line) = match spec {
                Spec::Line { number, changed } => (format!("{}{number}\t{}", if changed { '+' } else { ' ' }, walk.line(number)), u64::from(changed), number),
                Spec::More { lines: more, through } => (format!("+…\t({more} more lines)"), more, through),
                Spec::Gone(Gone { after, bytes, at_end }) => (format!("-\t({bytes} bytes removed here{})", if at_end { ", at the text's end" } else { "" }), 1, after),
                Spec::Parted => ("--".to_string(), 0, reach),
            };
            if used + row.len() > ROWS_MAX_BYTES {
                lines.push(format!("({} more changed lines not shown)", total.saturating_sub(told)));
                break;
            }
            (used, told, reach) = (used + row.len(), told + changes, reach.max(line));
            lines.push(row);
        }
        Rows { lines, masked: self.withheld.is_some_and(|line| line <= reach) }
    }
}

/// One value of the text a row draws.
#[derive(Debug, Clone, Copy)]
enum Part<'t> {
    /// Bytes of text, no line break among them.
    Bytes(&'t [u8]),
    /// A value that is no text.
    Gap,
}

/// One run of the text's values, in order.
#[derive(Debug, Clone, Copy)]
enum Segment {
    /// A stretch of text: where its bytes start, and how many.
    Text {
        /// Where its bytes start in the text's bytes.
        at: usize,
        /// How many.
        len: usize,
    },
    /// A value that is no text.
    Gap,
}

/// A walk of the text line by line, the lines asked in ascending order.
struct LineWalk<'t> {
    /// The text's bytes.
    bytes: &'t [u8],
    /// The text's values, in order.
    segments: Vec<Segment>,
    /// The segment the walk stands in.
    k: usize,
    /// How far into that segment.
    into: usize,
    /// The line the walk stands at the start of.
    number: u64,
}

impl<'t> LineWalk<'t> {
    /// Returns a walk of `text` from its first line.
    fn of(text: &'t Text) -> LineWalk<'t> {
        let mut segments = Vec::with_capacity(text.stretches.len() + text.gaps.len());
        let (mut stretches, mut gaps) = (text.stretches.iter().peekable(), text.gaps.iter().peekable());
        loop {
            match (stretches.peek(), gaps.peek()) {
                (Some(stretch), Some(gap)) if gap.ordinal < stretch.ordinal => {
                    segments.push(Segment::Gap);
                    gaps.next();
                }
                (Some(stretch), _) => {
                    segments.push(Segment::Text { at: stretch.at, len: stretch.len });
                    stretches.next();
                }
                (None, Some(_)) => {
                    segments.push(Segment::Gap);
                    gaps.next();
                }
                (None, None) => break,
            }
        }
        LineWalk { bytes: &text.bytes, segments, k: 0, into: 0, number: 1 }
    }

    /// Walks past the line it stands at, handing `each` its values, the line
    /// break left out.
    fn pass(&mut self, mut each: impl FnMut(Part<'t>)) {
        while let Some(&segment) = self.segments.get(self.k) {
            match segment {
                Segment::Gap => {
                    each(Part::Gap);
                    self.k += 1;
                }
                Segment::Text { at, len } => {
                    let rest = self.bytes.get(at + self.into..at + len).unwrap_or_default();
                    match rest.iter().position(|byte| *byte == b'\n') {
                        Some(cut) => {
                            each(Part::Bytes(&rest[..cut]));
                            self.into += cut + 1;
                            if self.into == len {
                                (self.k, self.into) = (self.k + 1, 0);
                            }
                            self.number += 1;
                            return;
                        }
                        None => {
                            each(Part::Bytes(rest));
                            (self.k, self.into) = (self.k + 1, 0);
                        }
                    }
                }
            }
        }
        self.number += 1;
    }

    /// Returns the line `number` as a row shows it.
    fn line(&mut self, number: u64) -> String {
        while self.number < number {
            self.pass(|_| {});
        }
        let mut drawing = Drawing::default();
        self.pass(|part| drawing.part(part));
        drawing.done()
    }
}

/// A line drawn as a row shows it.
#[derive(Debug, Default)]
struct Drawing {
    /// The line as drawn so far.
    out: String,
    /// The characters drawn.
    drawn: usize,
    /// The characters past the cut.
    past: u64,
    /// The bytes that are no UTF-8 waiting to be drawn, as hex.
    hex: String,
}

impl Drawing {
    /// Draws one value of the line.
    fn part(&mut self, part: Part<'_>) {
        match part {
            Part::Gap => self.unit(None),
            Part::Bytes(bytes) => {
                for chunk in bytes.utf8_chunks() {
                    for c in chunk.valid().chars() {
                        self.unit(Some(Ok(c)));
                    }
                    for byte in chunk.invalid() {
                        self.unit(Some(Err(*byte)));
                    }
                }
            }
        }
    }

    /// Draws one character: a UTF-8 character, a byte that is none, or
    /// (`None`) a value that is no text.
    fn unit(&mut self, unit: Option<Result<char, u8>>) {
        if self.drawn == ROWS_MAX_LINE_CHARS {
            self.past += 1;
            return;
        }
        self.drawn += 1;
        match unit {
            Some(Err(byte)) => {
                let _ = write!(self.hex, "{byte:02x}");
            }
            Some(Ok(c)) => {
                self.flush();
                self.out.push(c);
            }
            None => {
                self.flush();
                self.out.push_str("{…}");
            }
        }
    }

    /// Draws the bytes waiting as one `{hex:…}`.
    fn flush(&mut self) {
        if !self.hex.is_empty() {
            let _ = write!(self.out, "{{hex:{}}}", self.hex);
            self.hex.clear();
        }
    }

    /// Returns the line drawn, `…[+N chars]` where it was cut.
    fn done(mut self) -> String {
        self.flush();
        if self.past > 0 {
            let _ = write!(self.out, "…[+{} chars]", self.past);
        }
        self.out
    }
}

/// The rows of a call that landed, and whether a withheld run numbers them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Rows {
    /// The rows, in the text's order.
    pub(super) lines: Vec<String>,
    /// Whether a withheld run stands on or before a line they show.
    pub(super) masked: bool,
}

/// Returns the rows of `text`, the text the call leaves, whose positions
/// came from `pieces`.
pub(super) fn rows(text: &Text, pieces: &Pieces<'_>) -> Rows {
    let draft = Draft { text };
    let mut runs = pieces.removed.clone();
    runs.sort_unstable_by_key(|(from, _)| *from);
    let marks = marks(draft, &Removed { runs: &runs }, &pieces.changed());
    Shown::of(draft, &marks).drawn(text)
}

#[cfg(test)]
mod tests;
