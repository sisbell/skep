//! `text.move`: whole lines of a draft moved by identity (skep #1085).
//!
//! A caller moves a block of text — a function to sit beside its relatives,
//! a paragraph up a document — and names it by lines:
//! `text.move(session, {doc, first, last?, before?})`, the `text` family's
//! third call, moves the lines `first` to `last`, both included, to stand
//! before the line `before`, or at the text's end where `before` is absent
//! or one past the last line. No byte is minted: the move is one
//! `rearrange`, the board's own move by identity, so every byte keeps the
//! address it had and every link on it follows, where lines removed and
//! typed again are minted anew and leave every link behind. The module makes
//! the call out of the parent's own pieces — its read, its one write and the
//! line it settles, under the session the call stands under — and adds the
//! cuts.
//!
//! **The lines** (`rows::Lines`). The draft's text is read once, as
//! `text.replace` reads it, and its lines are counted as `line_numbers`
//! counts them: a line break is the byte 0x0A, a value that is no text holds
//! none, and a text that ends in a line break has no empty last line. A
//! `first` or a `last` past the last line, and a `before` past one beyond
//! it, is the call's refusal, `no_such_line`, with nothing written (SP-8); a
//! `before` at the block's own edges — `first`, or one past `last` — moves
//! nothing, and the call answers `unchanged`.
//!
//! **The cuts** ([`place`]). With `s` the position line `first` starts at,
//! `e` the one line `last + 1` starts at and `p` the one line `before`
//! starts at — each one past the text's last position where its line is one
//! past the last — a move up (`p < s`) sends the three cuts `[p, s, e]` and
//! a move down (`p > e`) `[s, e, p]`: the block and the stretch it crosses
//! change places, each a run of whole lines. Where the text ends in no line
//! break and the move would set its last line before another — the block
//! holding the last line moved up, or a block moved down to the end — three
//! cuts would join two lines, so four are sent, which leave one line break
//! standing between the two regions they exchange: `[p, s − 1, s, e]` up,
//! the break before the block, and `[s, e − 1, e, p]` down, the block's own
//! last. Every line then stays whole, and the text ends as it did. Where the
//! first of those four regions would be empty — the stretch crossed up is
//! one empty line, or the block moved down is — the three cuts are sent
//! after all: the empty line's break then ends the text, which holds one
//! line fewer. A cut stands at a line's start or on a line break, so none
//! falls inside a value that is no text, and each such value moves with its
//! line.
//!
//! **The write.** One `rearrange`, typed against the read's position: a
//! draft that changed since is refused `arrangement_moved` by the board,
//! with nothing written. Its line, where the shell holds it, is settled as
//! `text.replace` settles one (`settle`): dropped, the board's verdict read
//! off it first, so the call answers `refused` with nothing standing and
//! nothing queued; found landed, the move landed, its commit unnamed; and
//! where the shell would not drop it, the call answers `held`, an error
//! naming it.
//!
//! **The answer.** One JSON object keyed by `outcome`, as `text.replace`'s
//! is: `moved`, `unchanged`, `refused` and `held` (`shapes`' `TextMoved`,
//! `TextMoveUnchanged`, `TextRefused`, `TextMoveHeld`). `moved` names the
//! lines as asked and where they now stand, the cuts sent and the commit,
//! and carries the rows (`rows::moved`): the moved lines numbered where they
//! stand, the lines either side of them, and one row where they left —
//! drawn from the call's own text with the cuts applied in memory
//! (`Text::rearranged`), no read made for them. The rows number the text as
//! the move leaves it: where it holds one line fewer, the row where the
//! lines left follows the text's last line at most, and a moved empty line
//! that is now the text's last line break is no line and has no row.
//!
//! **The cost** (SP-23). One read of the draft, as every text call makes;
//! one walk of its text counting the lines and one finding the three starts;
//! one write; and the rows, which tell the text once in its new order and
//! walk it as `text.edit`'s rows walk theirs.

use serde_json::{json, Value};
use skep_client::address::is_address_text;
use skep_client::board::frames;

use super::super::optional;
use super::rows::{moved as moved_rows, Lines, Rows};
use super::{held, read_draft, refused, refused_write, settle, write, Answer, Calls, Read, Settled, Text, Wrote};
use crate::refusal::Refusal;

/// What the call is asked: the draft, the lines to move, and where to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Asked<'a> {
    /// The draft, an address in its one spelling.
    doc: &'a str,
    /// The block's first line, from 1.
    first: u64,
    /// The block's last line: `first`, or a line past it.
    last: u64,
    /// The line the block is to stand before, outside the block.
    ///
    /// The text's end where the call names none.
    before: Option<u64>,
}

impl<'a> Asked<'a> {
    /// Reads `text.move`'s members off `args`, each in its form.
    ///
    /// A line is a whole number from 1; `last` absent is `first`, the one
    /// line, and `before` absent the text's end, a `null` read as absent.
    ///
    /// # Errors
    ///
    /// `malformed_args` naming the first member that fails, in this order:
    ///
    /// 1. `doc` where it is no address in its one spelling;
    /// 2. `first` where it is no line;
    /// 3. `last`, then `before`, where it is present and no line;
    /// 4. `last` where it is before `first`;
    /// 5. `before` where it is inside the block: past `first`, and at or
    ///    before `last`.
    pub(super) fn read(args: &'a Value) -> Result<Asked<'a>, Refusal> {
        let line = |member: &Value| member.as_u64().filter(|line| *line >= 1);
        let doc = args["doc"].as_str().filter(|doc| is_address_text(doc)).ok_or_else(|| Refusal::malformed("doc"))?;
        let first = line(&args["first"]).ok_or_else(|| Refusal::malformed("first"))?;
        let last = optional(args, "last", line)?.unwrap_or(first);
        let before = optional(args, "before", line)?;
        if last < first {
            return Err(Refusal::malformed("last"));
        }
        if before.is_some_and(|before| first < before && before <= last) {
            return Err(Refusal::malformed("before"));
        }
        Ok(Asked { doc, first, last, before })
    }
}

/// A move, placed in the text as read.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Placed {
    /// The cuts the one `rearrange` sends: three, or four.
    cuts: Vec<u64>,
    /// The lines the block stands at once the move lands: first and last.
    to: (u64, u64),
    /// The line the place the block left follows.
    ///
    /// It is numbered in a text of as many lines as the one read.
    after: u64,
}

/// Where a move asked stands against the text as read.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Placing {
    /// A member names a line the text does not hold.
    NoSuchLine {
        /// The member: `first`, `last` or `before`.
        what: &'static str,
        /// The line it names.
        line: u64,
        /// How many lines the text holds.
        count: u64,
    },
    /// The block stands before that line already.
    Unchanged,
    /// The move, and its cuts.
    Move(Placed),
}

/// Places the move `asked` in `text`, the draft's text as read.
///
/// The block must be lines of the text and `before` a line of it or one past
/// its last: the first of `first`, `last` and `before` that is not is
/// answered [`Placing::NoSuchLine`]. A `before` at the block's own edges is
/// [`Placing::Unchanged`]. Any other move is placed by the module doc's *The
/// cuts*: the cuts, the lines the block comes to stand at, and the line the
/// place it left follows.
fn place(text: &Text, asked: &Asked<'_>) -> Placing {
    let Asked { first, last, before, .. } = *asked;
    let lines = Lines::of(text);
    let count = lines.count();
    let before = before.unwrap_or(count + 1);
    // A line from 1 to one past the count starts somewhere, and no other.
    let [s, e, p] = lines.starts([first, last.saturating_add(1), before]);
    let no_such = |what, line| Placing::NoSuchLine { what, line, count };
    let Some(s) = s.filter(|_| first <= count) else { return no_such("first", first) };
    let Some(e) = e else { return no_such("last", last) };
    let Some(p) = p else { return no_such("before", before) };
    if before == first || before == last + 1 {
        return Placing::Unchanged;
    }
    // The text's last line, where no line break closes it, is whole only at
    // the text's end: four cuts keep a line break between it and the line a
    // move would set after it.
    let (end, open, block) = (text.positions() + 1, !lines.closed(), last - first + 1);
    Placing::Move(if before < first {
        let cuts = if e == end && open && p < s - 1 { vec![p, s - 1, s, e] } else { vec![p, s, e] };
        Placed { cuts, to: (before, before + block - 1), after: last }
    } else {
        let cuts = if p == end && open && s < e - 1 { vec![s, e - 1, e, p] } else { vec![s, e, p] };
        Placed { cuts, to: (before - block, before - 1), after: first - 1 }
    })
}

/// Returns the answer of a move that landed.
///
/// `at` is the `rearrange`'s commit, absent where the shell's read found the
/// write landed, its own answer lost; `rows` are the rows of the text as the
/// move leaves it.
fn moved(asked: &Asked<'_>, placed: &Placed, at: Option<u64>, rows: Rows) -> Answer {
    let Rows { lines, masked } = rows;
    let cuts: Vec<String> = placed.cuts.iter().map(u64::to_string).collect();
    let mut value = json!({"outcome": "moved", "doc": asked.doc, "first": asked.first, "last": asked.last, "to_first": placed.to.0, "to_last": placed.to.1, "cuts": cuts, "lines": lines});
    if let Some(at) = at {
        value["at"] = Value::from(at);
    }
    if masked {
        value["masked"] = Value::Bool(true);
    }
    Answer::data(value)
}

/// Makes the move `asked` through `calls`.
///
/// In order: the draft's text is read, a published document refused before
/// any of its text is (`read_draft`); the move is placed in it ([`place`]),
/// a line the text does not hold refused and a move of nothing answered
/// `unchanged`; and the one `rearrange` is written, typed against the read,
/// a move that lands answered with the rows of the text as it leaves it
/// (`rows::moved`). Nothing is written before every refusal a read alone
/// decides (SP-8).
///
/// # Errors
///
/// The board's verdict on a read, or the shell's refusal of it; and the
/// `op` row's refusal of the write, nothing written. Every other outcome is
/// an [`Answer`].
pub(super) fn move_lines(calls: &impl Calls, asked: &Asked<'_>) -> Result<Answer, Refusal> {
    let doc = asked.doc;
    let Read { text, as_of } = match read_draft(calls, doc)? {
        Ok(read) => read,
        Err(answer) => return Ok(answer),
    };
    let placed = match place(&text, asked) {
        Placing::Move(placed) => placed,
        Placing::Unchanged => return Ok(Answer::data(json!({"outcome": "unchanged", "doc": doc, "as_of": as_of}))),
        Placing::NoSuchLine { what, line, count } => return Ok(refused(doc, "no_such_line", json!({"what": what, "line": line, "count": count}))),
    };
    let at = match write(calls, frames::rearrange(doc, &placed.cuts, as_of, None))? {
        Wrote::Acked(ack) => ack["at"].as_u64(),
        Wrote::Held(line) => match settle(calls, line) {
            Settled::Landed => None,
            Settled::Dropped { cause, verdict } => return Ok(refused_write(doc, &cause, verdict)),
            Settled::Standing(line) => return Ok(held(doc, &line, "rearrange", Value::Null)),
        },
    };
    let rows = moved_rows(&text.rearranged(&placed.cuts), (asked.first, asked.last), placed.to, placed.after);
    Ok(moved(asked, &placed, at, rows))
}

#[cfg(test)]
mod tests;
