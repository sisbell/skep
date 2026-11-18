//! The minimal changes that make one text into another (skep #1079).
//!
//! A caller that changes a text hands over a stretch of it twice, as it
//! stands and as it is to read. Written back whole — even cut to what the
//! two share at either end — that re-types everything between the first
//! byte that differs and the last, and the bytes standing unchanged between
//! two changes lose their identity. [`minimal_changes`] finds the changes
//! themselves, in order and apart, so a caller writes those alone and every
//! byte between two of them keeps the address it had. The module is a
//! function of two texts: it reads no board and holds no key, and stands in
//! every build.
//!
//! **The match.** The texts are matched by lines first — a line is its
//! bytes through its `\n`, a last line that has none among them — and a
//! line that stands in both is unchanged. Each run of lines that changed on
//! both sides is matched again by words: a word is a run of word characters
//! (`char::is_alphanumeric`, or `_`), a run of whitespace
//! (`char::is_whitespace`), or one other character. Either match is
//! Python's `difflib.SequenceMatcher` with no junk heuristic, written here
//! by hand: the longest block the two sequences share — of several, the one
//! standing earliest in the old sequence, then earliest in the new — and
//! the same again in what stands before it and after it (`unmatched`).
//!
//! **The bound** ([`MAX_MATCH_PRODUCT`]). A match walks, for each block it
//! finds, at most as many places as the two sequences' lengths multiply
//! to. Two sequences whose lengths multiply past the bound are not
//! matched: they are one changed run. Lines past it still meet the match by
//! words, under the same bound, so a text of many blank lines beside one of
//! few is split by its words.
//!
//! **The join** ([`MIN_KEPT_BETWEEN`]). What stands between two changes is
//! kept only where it is worth a change of its own: a stretch holding fewer
//! than the bound's characters that are no whitespace — a blank line, a
//! lone brace, `, ` — is written again with the changes either side of it,
//! which are then one.
//!
//! **The trim** ([`shared`]). Each change is cut to what differs: what its
//! old and its new bytes share at either end is left standing, whole
//! characters. A change the trim leaves nothing of is no change.

use std::collections::HashMap;
use std::hash::Hash;
use std::ops::Range;

/// The fewest characters that are no whitespace a kept stretch holds.
///
/// A stretch between two changes that holds fewer is written again with
/// them, the two then one change (the module doc's *The join*).
pub const MIN_KEPT_BETWEEN: usize = 8;

/// The greatest product of two sequences' lengths a match is made over.
///
/// Two sequences of lines, or of words, whose lengths multiply past it are
/// one changed run (the module doc's *The bound*).
pub const MAX_MATCH_PRODUCT: usize = 1_000_000;

/// One change: bytes of the old text, and the new text's in their place.
///
/// Each range is in bytes of its own text and ends on character boundaries
/// of it; at least one of the two holds a byte.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    /// The bytes of the old text the change removes.
    ///
    /// None where it only inserts.
    pub old: Range<usize>,
    /// The bytes of the new text the change inserts.
    ///
    /// None where it only removes.
    pub new: Range<usize>,
}

/// Returns the minimal changes that make `old` into `new`.
///
/// They ascend in both texts and lie apart: between two of them stands a
/// stretch of at least [`MIN_KEPT_BETWEEN`] characters that are no
/// whitespace, the same bytes in each text. The bytes of `old` outside
/// every change's `old` are, in order, the bytes of `new` outside every
/// change's `new`, so making each change makes `new`. None where the two
/// are the same text.
pub fn minimal_changes(old: &str, new: &str) -> Vec<Change> {
    if old == new {
        return Vec::new();
    }
    let (old_lines, new_lines) = (Pieces::lines(old), Pieces::lines(new));
    let mut raw: Vec<Change> = Vec::new();
    for (was, now) in unmatched(&old_lines.pieces, &new_lines.pieces) {
        let lines = Change { old: old_lines.bytes(&was), new: new_lines.bytes(&now) };
        if was.is_empty() || now.is_empty() {
            raw.push(lines);
            continue;
        }
        // Lines that changed on both sides: matched again by their words.
        let (old_words, new_words) = (Pieces::words(&old[lines.old.clone()]), Pieces::words(&new[lines.new.clone()]));
        for (was, now) in unmatched(&old_words.pieces, &new_words.pieces) {
            let (was, now) = (old_words.bytes(&was), new_words.bytes(&now));
            raw.push(Change { old: lines.old.start + was.start..lines.old.start + was.end, new: lines.new.start + now.start..lines.new.start + now.end });
        }
    }
    let mut joined: Vec<Change> = Vec::new();
    for change in raw {
        match joined.last_mut() {
            Some(last) if old[last.old.end..change.old.start].chars().filter(|c| !c.is_whitespace()).take(MIN_KEPT_BETWEEN).count() < MIN_KEPT_BETWEEN => {
                last.old.end = change.old.end;
                last.new.end = change.new.end;
            }
            _ => joined.push(change),
        }
    }
    joined.into_iter().filter_map(|change| trimmed(old, new, change)).collect()
}

/// Returns `change` cut to what differs, none where nothing does.
///
/// What its bytes of `old` and its bytes of `new` share at either end is
/// left out of it ([`shared`]).
fn trimmed(old: &str, new: &str, change: Change) -> Option<Change> {
    let (lead, tail) = shared(&old[change.old.clone()], &new[change.new.clone()]);
    let trimmed = Change { old: change.old.start + lead..change.old.end - tail, new: change.new.start + lead..change.new.end - tail };
    (!trimmed.old.is_empty() || !trimmed.new.is_empty()).then_some(trimmed)
}

/// Returns how many bytes `old` and `new` share at their start and their end.
///
/// The start is the longest they share cut back to a character boundary,
/// and the end the longest the rest of each shares, cut forward to one: a
/// character the two texts spell differently in its last byte, or its
/// first, is replaced whole, never split between kept bytes and new ones.
/// The two never overlap, so `lead + tail` is at most the shorter text's
/// length, and each is a character boundary of both texts: the bytes before
/// `lead` are the same valid text in each, and so are the bytes of the
/// tail.
pub fn shared(old: &str, new: &str) -> (usize, usize) {
    let (old_bytes, new_bytes) = (old.as_bytes(), new.as_bytes());
    let mut lead = old_bytes.iter().zip(new_bytes).take_while(|(a, b)| a == b).count();
    while !old.is_char_boundary(lead) {
        lead -= 1;
    }
    let mut tail = old_bytes[lead..].iter().rev().zip(new_bytes[lead..].iter().rev()).take_while(|(a, b)| a == b).count();
    while !old.is_char_boundary(old.len() - tail) {
        tail -= 1;
    }
    (lead, tail)
}

/// A text cut into consecutive pieces: its lines, or its words.
struct Pieces<'t> {
    /// The pieces, in order: together they are the text.
    pieces: Vec<&'t str>,
    /// The byte each piece begins at, and the text's length last.
    starts: Vec<usize>,
}

impl<'t> Pieces<'t> {
    /// Returns `text` cut at each of `starts`, ascending from 0.
    fn cut(text: &'t str, mut starts: Vec<usize>) -> Pieces<'t> {
        starts.push(text.len());
        let pieces = starts.windows(2).map(|ends| &text[ends[0]..ends[1]]).collect();
        Pieces { pieces, starts }
    }

    /// Returns `text` cut into its lines.
    ///
    /// A line is its bytes through its `\n`; a last line that has none is a
    /// line too, and an empty text has no line.
    fn lines(text: &'t str) -> Pieces<'t> {
        let mut at = 0;
        let starts = text
            .split_inclusive('\n')
            .map(|line| {
                at += line.len();
                at - line.len()
            })
            .collect();
        Pieces::cut(text, starts)
    }

    /// Returns `text` cut into its words.
    ///
    /// A word is a run of word characters, a run of whitespace, or one
    /// other character ([`Class`]).
    fn words(text: &'t str) -> Pieces<'t> {
        let (mut starts, mut last) = (Vec::new(), None);
        for (at, c) in text.char_indices() {
            let class = Class::of(c);
            if class == Class::Other || last != Some(class) {
                starts.push(at);
            }
            last = Some(class);
        }
        Pieces::cut(text, starts)
    }

    /// Returns the bytes the pieces `pieces` take up in the text.
    fn bytes(&self, pieces: &Range<usize>) -> Range<usize> {
        self.starts[pieces.start]..self.starts[pieces.end]
    }
}

/// What a character is to the cut into words.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Class {
    /// A word character: `char::is_alphanumeric`, or `_`.
    Word,
    /// Whitespace: `char::is_whitespace`.
    Space,
    /// Any other character, a word of its own.
    Other,
}

impl Class {
    /// Returns the class of `c`.
    fn of(c: char) -> Class {
        if c.is_alphanumeric() || c == '_' {
            Class::Word
        } else if c.is_whitespace() {
            Class::Space
        } else {
            Class::Other
        }
    }
}

/// Returns the runs of `a` and `b` that no block the two share covers.
///
/// Each is a run of `a` beside the run of `b` that stands in its place,
/// one of the two possibly empty, ascending in both; the elements between
/// two runs are a block the sequences share ([`matching_blocks`]). Two
/// sequences whose lengths multiply past [`MAX_MATCH_PRODUCT`] are one run,
/// each whole.
fn unmatched<T: Eq + Hash>(a: &[T], b: &[T]) -> Vec<(Range<usize>, Range<usize>)> {
    if a.len().saturating_mul(b.len()) > MAX_MATCH_PRODUCT {
        return vec![(0..a.len(), 0..b.len())];
    }
    let (mut runs, mut i, mut j) = (Vec::new(), 0, 0);
    for (in_a, in_b, size) in matching_blocks(a, b).into_iter().chain([(a.len(), b.len(), 0)]) {
        if i < in_a || j < in_b {
            runs.push((i..in_a, j..in_b));
        }
        (i, j) = (in_a + size, in_b + size);
    }
    runs
}

/// Returns the blocks `a` and `b` share, ascending.
///
/// Each is its first element in `a`, its first in `b`, and its length. The
/// longest block the two share is found ([`longest_match`]), then the
/// longest in what stands before it in both and in what stands after it in
/// both, until a stretch shares none: `difflib.SequenceMatcher`'s
/// `get_matching_blocks` with no junk, the stretches still to match kept in
/// a list, never on the stack.
fn matching_blocks<T: Eq + Hash>(a: &[T], b: &[T]) -> Vec<(usize, usize, usize)> {
    // Where each element of `b` stands in `b`, ascending, and so where each
    // element of `a` stands there.
    let (mut first, mut places): (HashMap<&T, usize>, Vec<Vec<usize>>) = (HashMap::new(), Vec::new());
    for (j, element) in b.iter().enumerate() {
        let id = *first.entry(element).or_insert(places.len());
        if id == places.len() {
            places.push(Vec::new());
        }
        places[id].push(j);
    }
    let stands: Vec<&[usize]> = a.iter().map(|element| first.get(element).map_or(&[][..], |&id| places[id].as_slice())).collect();
    let mut rows = (vec![0; b.len() + 1], vec![0; b.len() + 1]);
    let (mut blocks, mut queue) = (Vec::new(), vec![(0..a.len(), 0..b.len())]);
    while let Some((in_a, in_b)) = queue.pop() {
        let (i, j, size) = longest_match(&stands, in_a.clone(), in_b.clone(), &mut rows);
        if size > 0 {
            blocks.push((i, j, size));
            if in_a.start < i && in_b.start < j {
                queue.push((in_a.start..i, in_b.start..j));
            }
            if i + size < in_a.end && j + size < in_b.end {
                queue.push((i + size..in_a.end, j + size..in_b.end));
            }
        }
    }
    blocks.sort_unstable();
    blocks
}

/// Returns the longest block two stretches share.
///
/// They are the stretch `in_a` of one sequence and the stretch `in_b` of
/// another, and the block is its first element in each and its length, 0
/// where they share no element. `places[i]` is where element `i` of the
/// first sequence stands in the second, ascending. Of several longest
/// blocks it is the one standing earliest in the first sequence, and of
/// those the earliest in the second (`difflib`'s `find_longest_match`).
///
/// `rows` is the match's scratch, two rows of the second sequence's length
/// and one, all zero as the call finds them and as it leaves them:
/// `rows.0[j + 1]` holds the length of the block ending at the element
/// before the one being read and at `j`.
fn longest_match(places: &[&[usize]], in_a: Range<usize>, in_b: Range<usize>, rows: &mut (Vec<usize>, Vec<usize>)) -> (usize, usize, usize) {
    let (before, here) = (&mut rows.0, &mut rows.1);
    let (mut best_i, mut best_j, mut best) = (in_a.start, in_b.start, 0);
    let within = |places: &'_ [usize]| -> Range<usize> { places.partition_point(|&j| j < in_b.start)..places.partition_point(|&j| j < in_b.end) };
    let mut last: &[usize] = &[];
    for i in in_a {
        let read = &places[i][within(places[i])];
        for &j in read {
            let size = before[j] + 1;
            here[j + 1] = size;
            if size > best {
                (best_i, best_j, best) = (i + 1 - size, j + 1 - size, size);
            }
        }
        for &j in last {
            before[j + 1] = 0;
        }
        std::mem::swap(before, here);
        last = read;
    }
    for &j in last {
        before[j + 1] = 0;
    }
    (best_i, best_j, best)
}

#[cfg(test)]
mod tests;
